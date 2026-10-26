/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 88d: the composer's readiness and the send gate answer the strict policy
 * with one computation between them, not two.
 *
 * The two surfaces are `getEncryptionKeyMeta()` — what the composer and the Key
 * Assistant show — and `getValidKeysForRecipient()` — what a send consults. They
 * read different databases: readiness from this build's acceptance row, the gate
 * from `_strictLevelFor()`, which asks GnuPG. Under
 * `mail.openpgp.require_trusted_keys` nothing kept the two answers in step, and
 * the disagreement only ever ran one way:
 *
 *   - a key GnuPG fully trusts, whose acceptance row says `unverified`, read as
 *     `undecided` — the composer told the user the recipient had no usable key
 *     while the gate would have accepted the send;
 *   - the other direction does not exist. `_strictLevelFor()` falls back to the
 *     store's answer when GnuPG has nothing better to say, so a stored
 *     `verified` passes the gate whether or not gpg agrees. That is asserted
 *     here rather than assumed, because an earlier draft of the plan item
 *     claimed the direction both ways and the measurement says otherwise.
 *
 * The first task is therefore the defect and the second is the measurement that
 * corrects the claim. Item 91's per-message override is written against the
 * readiness vocabulary, which is why this comes before the override reaches the
 * send: an override that relaxes `undecided` relaxes a state that, on this key,
 * did not mean what it said.
 */

"use strict";

const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { PgpSqliteDb2 } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/sqliteDb.sys.mjs"
);
const { GPGME } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/GPGME.sys.mjs"
);
const { GnuPGAgent } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/gnupgAgent.sys.mjs"
);
const { OpenPgpValidity } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/constants.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { Subprocess } = ChromeUtils.importESModule(
  "resource://gre/modules/Subprocess.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";
const STRICT_PREF = "mail.openpgp.require_trusted_keys";

// The key GnuPG holds, and the one every disagreement is measured on.
const GNUPG_ADDRESS = "alice@openpgp.example";
const GNUPG_SECRET = "alice@openpgp.example-0xf231550c4f47e38e-secret.asc";
const GNUPG_FPR = "EB85BB5FA33A75E15E944E63F231550C4F47E38E";
const GNUPG_KEY_ID = "F231550C4F47E38E";

// The key only this build holds, for the store's own answers.
const STORE_ADDRESS = "bob@openpgp.example";
const STORE_FPR = "D1A66E1A23B182C9980F788CFBFCC82A015E7330";
const STORE_KEY_ID = "FBFCC82A015E7330";

let gpgPath = null;
let gnupgHome = null;
let externalAvailable = false;

/**
 * @param {string[]} args
 * @returns {Promise<string>}
 */
async function runGpg(args) {
  const process = await Subprocess.call({
    command: gpgPath,
    arguments: ["--batch", "--no-tty", "--yes", ...args],
    environment: { GNUPGHOME: gnupgHome.path },
    environmentAppend: true,
    stdout: "pipe",
    stderr: "pipe",
  });
  const stdout = await process.stdout.readString();
  await process.stderr.readString();
  await process.wait();
  return stdout;
}

/**
 * What the composer and the Key Assistant would show for one key.
 *
 * @param {string} address
 * @param {string} fpr
 * @returns {Promise<?string>} the readiness value, or null if the key is absent.
 */
async function readinessFor(address, fpr) {
  EnigmailKeyRing.clearCache();
  EnigmailKeyRing.clearGnuPgKeyCache();
  const meta = (await EnigmailKeyRing.getEncryptionKeyMeta(address)).find(
    m => m.keyObj?.fpr == fpr
  );
  return meta ? meta.readiness : null;
}

/**
 * What the send path would do with the same key.
 *
 * @param {string} address
 * @param {string} keyId
 * @returns {Promise<boolean>}
 */
async function gateAccepts(address, keyId) {
  EnigmailKeyRing.clearCache();
  EnigmailKeyRing.clearGnuPgKeyCache();
  const offered = await EnigmailKeyRing.getValidKeysForRecipient(address, {});
  return offered.includes(keyId);
}

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();

  // A key only this build holds, accepted as "unverified" -- usable under the
  // permissive policy and not trusted under the strict one.
  await OpenPGPTestUtils.importPublicKey(
    null,
    do_get_file(`${keyDir}/bob@openpgp.example-0xfbfcc82a015e7330-pub.asc`)
  );
  await PgpSqliteDb2.updateAcceptance(STORE_FPR, [STORE_ADDRESS], "unverified");
  registerCleanupFunction(() => PgpSqliteDb2.deleteAcceptance(STORE_FPR));

  Services.prefs.setBoolPref(STRICT_PREF, false);
  registerCleanupFunction(() => {
    Services.prefs.clearUserPref(STRICT_PREF);
    Services.prefs.clearUserPref("mail.openpgp.allow_external_gnupg");
    Services.prefs.clearUserPref("mail.openpgp.fetch_pubkeys_from_gnupg");
  });

  try {
    gpgPath = await Subprocess.pathSearch("gpg");
  } catch (ex) {
    info("No gpg executable found; the GnuPG half cannot be measured.");
  }
  if (gpgPath) {
    gnupgHome = do_get_tempdir();
    gnupgHome.append("gnupg-item88d");
    gnupgHome.createUnique(Ci.nsIFile.DIRECTORY_TYPE, 0o700);
    const previousHome = Services.env.exists("GNUPGHOME")
      ? Services.env.get("GNUPGHOME")
      : "";
    Services.env.set("GNUPGHOME", gnupgHome.path);
    registerCleanupFunction(async () => {
      try {
        const gpgconfPath = await Subprocess.pathSearch("gpgconf");
        const process = await Subprocess.call({
          command: gpgconfPath,
          arguments: ["--kill", "all"],
          environment: { GNUPGHOME: gnupgHome.path },
          environmentAppend: true,
          stderr: "pipe",
        });
        await process.stderr.readString();
        await process.wait();
      } catch (ex) {
        info(`Could not stop gpg-agent: ${ex.message}`);
      }
      Services.env.set("GNUPGHOME", previousHome);
      gnupgHome.remove(true);
    });

    const imported = await runGpg([
      "--import",
      do_get_file(`${keyDir}/${GNUPG_SECRET}`).path,
    ]);
    externalAvailable = imported !== null && GPGME.init();
    Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
    Services.prefs.setBoolPref("mail.openpgp.fetch_pubkeys_from_gnupg", true);
  }
});

/**
 * The defect, in the one direction it exists.
 *
 * GnuPG is asked to trust the key and it does; the store's row still says
 * "unverified", because that is what importing a GnuPG-held key writes and
 * nothing has asked the user about it. The gate accepts the key. Readiness used
 * to call it `undecided` and the composer told the user the recipient had no
 * usable key.
 */
add_task(async function readinessAgreesWhenGnuPGTrustsTheKey() {
  if (!externalAvailable) {
    info("SKIPPED: no external GnuPG on this machine.");
    Assert.ok(true, "skipped");
    return;
  }

  Services.prefs.setBoolPref(STRICT_PREF, true);
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  Services.prefs.setBoolPref("mail.openpgp.fetch_pubkeys_from_gnupg", true);

  const set = await GnuPGAgent.setOwnerTrust(
    GNUPG_FPR,
    OpenPgpValidity.ULTIMATE
  );
  Assert.ok(set.ok, `owner trust was written to gpg: ${set.output}`);
  registerCleanupFunction(async () => {
    await GnuPGAgent.setOwnerTrust(GNUPG_FPR, OpenPgpValidity.NEVER);
    EnigmailKeyRing.clearCache();
    EnigmailKeyRing.clearGnuPgKeyCache();
  });

  const accepted = await gateAccepts(GNUPG_ADDRESS, GNUPG_KEY_ID);
  const readiness = await readinessFor(GNUPG_ADDRESS, GNUPG_FPR);
  info(`FINDING gpg-trusted: gate=${accepted} readiness=${readiness}`);

  Assert.ok(accepted, "the strict gate accepts a key gpg fully trusts");
  Assert.equal(
    readiness,
    "accepted",
    "and the composer's readiness agrees with it rather than calling the " +
      "key undecided"
  );
});

/**
 * The direction an earlier draft of Item 88d claimed, measured and corrected.
 *
 * A stored `verified` passes the gate even when gpg's ownertrust for the key is
 * NEVER, because `_strictLevelFor()` falls back to the store's answer. So the
 * gate's accepted set is a superset of readiness's: there is no key the gate
 * refuses and readiness calls accepted, and the fix for the other direction
 * cannot create one.
 */
add_task(async function theStoreStillSatisfiesTheGate() {
  if (!externalAvailable) {
    info("SKIPPED: no external GnuPG on this machine.");
    Assert.ok(true, "skipped");
    return;
  }

  Services.prefs.setBoolPref(STRICT_PREF, true);
  await PgpSqliteDb2.updateAcceptance(GNUPG_FPR, [GNUPG_ADDRESS], "verified");
  registerCleanupFunction(() => PgpSqliteDb2.deleteAcceptance(GNUPG_FPR));
  const withdrawn = await GnuPGAgent.setOwnerTrust(
    GNUPG_FPR,
    OpenPgpValidity.NEVER
  );
  Assert.ok(withdrawn.ok, `ownertrust withdrawn: ${withdrawn.output}`);

  const accepted = await gateAccepts(GNUPG_ADDRESS, GNUPG_KEY_ID);
  const readiness = await readinessFor(GNUPG_ADDRESS, GNUPG_FPR);
  info(
    `FINDING store-verified/gpg-never: gate=${accepted} readiness=${readiness}`
  );

  Assert.ok(
    accepted,
    "a stored verified satisfies the gate even when gpg's ownertrust is NEVER"
  );
  Assert.equal(
    readiness,
    "accepted",
    "and readiness reports the same answer, so the second direction of the " +
      "claimed disagreement does not exist"
  );
});

/**
 * The control: the permissive policy's answers must not move.
 *
 * Readiness for a permissive build comes from the store and is what it always
 * was. A change that relaxed the strict policy by relaxing both would be a
 * behaviour change nobody asked for.
 */
add_task(async function permissiveAnswersDidNotMove() {
  Services.prefs.setBoolPref(STRICT_PREF, false);
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", false);
  Services.prefs.setBoolPref("mail.openpgp.fetch_pubkeys_from_gnupg", false);

  Assert.equal(
    await readinessFor(STORE_ADDRESS, STORE_FPR),
    "accepted",
    "permissive: an unverified key is accepted, as before"
  );

  await PgpSqliteDb2.updateAcceptance(STORE_FPR, [STORE_ADDRESS], "verified");
  registerCleanupFunction(() =>
    PgpSqliteDb2.updateAcceptance(STORE_FPR, [STORE_ADDRESS], "unverified")
  );
  Assert.equal(
    await readinessFor(STORE_ADDRESS, STORE_FPR),
    "accepted",
    "permissive: a verified key is accepted, as before"
  );

  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  Services.prefs.setBoolPref("mail.openpgp.fetch_pubkeys_from_gnupg", true);
});

/**
 * The strict policy still reports a rejection as a rejection.
 *
 * `NEVER` is numerically above `UNDEFINED` in GnuPG's vocabulary, so a route
 * that sorted by number would call a rejected key usable. The gate answers by
 * exact value and the readiness switch must too -- this is the ordering trap
 * reaching the new computation rather than a new hazard.
 */
add_task(async function aRejectedKeyStillReadsRejected() {
  Services.prefs.setBoolPref(STRICT_PREF, true);
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", false);
  Services.prefs.setBoolPref("mail.openpgp.fetch_pubkeys_from_gnupg", false);
  await PgpSqliteDb2.updateAcceptance(STORE_FPR, [STORE_ADDRESS], "rejected");
  registerCleanupFunction(() =>
    PgpSqliteDb2.updateAcceptance(STORE_FPR, [STORE_ADDRESS], "unverified")
  );

  const readiness = await readinessFor(STORE_ADDRESS, STORE_FPR);
  info(`FINDING rejected under strict: readiness=${readiness}`);
  Assert.equal(readiness, "rejected", "a rejected key reads as rejected");

  await PgpSqliteDb2.updateAcceptance(STORE_FPR, [STORE_ADDRESS], "unverified");
  Assert.equal(
    await readinessFor(STORE_ADDRESS, STORE_FPR),
    "undecided",
    "and an unjudged key reads as undecided under strict, as before"
  );
});
