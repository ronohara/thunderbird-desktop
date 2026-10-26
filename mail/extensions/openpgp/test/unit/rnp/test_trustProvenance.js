/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 88b: one vocabulary, two sources, each labelled.
 *
 * Design 13.6: *"for a GnuPG key the value is GnuPG's computed answer, displayed
 * as such; for an internal key it is the user's declaration. One vocabulary, two
 * sources, each labelled."* This file checks the labelling half.
 *
 * **The value deliberately does not move here.** `_getAcceptanceLevelForEmail()`
 * returns `{ level, source }` and `level` is what it always was, so that this
 * step cannot change a send and can be verified on its own. Item 88c is the
 * change that lets the source decide the value; this one only establishes that
 * the build knows which source it is talking about.
 *
 * **The case that matters is the third one: the fallback.** `getOwnerTrust()`
 * answers `null` when gpg is unavailable or does not hold the key, and `null`
 * must mean *ask the store*, not *no trust*. A build that read absence as
 * `UNKNOWN` would refuse every recipient for a user with no external ring while
 * the strict policy was on -- a refusal caused by nothing the user did, on keys
 * they had never been asked to judge. That is the assertion a build which got
 * the rule backwards fails, and the other two pass it.
 *
 * Three keys, because the three sources are three different situations:
 *   - Bob, secret key in GnuPG only      -> "gnupg"
 *   - Carol, public key in the profile   -> "store"
 *   - Bob again, external ring switched off -> "store", and still a usable value
 */

"use strict";

const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { GPGME } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/GPGME.sys.mjs"
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

// Held by GnuPG, and not imported into the profile: the external arm.
const BOB_SECRET = "bob@openpgp.example-0xfbfcc82a015e7330-secret.asc";
const BOB_FPR = "D1A66E1A23B182C9980F788CFBFCC82A015E7330";
const BOB_ADDRESS = "bob@openpgp.example";

// Imported into the profile only: the store's answer, and the user's own.
const CAROL_PUBLIC = "carol@example.com-0x3099ff1238852b9f-pub.asc";
const CAROL_FPR = "B8F2F6F4BD3AD3F82DC446833099FF1238852B9F";
const CAROL_ADDRESS = "carol@example.com";

var gpgPath = null;
var gnupgHome = null;
var available = false;

/**
 * @param {string[]} args
 * @returns {Promise<{exitCode: integer, stdout: string, stderr: string}>}
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
  const stderr = await process.stderr.readString();
  const { exitCode } = await process.wait();
  return { exitCode, stdout, stderr };
}

/**
 * The level and source for one address on one key.
 *
 * The key object is taken from `getCandidateKeysForEmail()` rather than from
 * `getKeyById()`, because that is the list the gate itself walks: a key GnuPG
 * holds is deliberately **not** in the profile ring (Item 8's guard refuses to
 * import one), so the only place its key object exists is the candidate list
 * that merges the external ring in.
 *
 * @param {string} fpr - Primary fingerprint, either case.
 * @param {string} address
 * @returns {Promise<{level: integer, source: string}>}
 */
async function provenance(fpr, address) {
  const wanted = fpr.replace(/^0x/i, "").toUpperCase();
  const candidates = await EnigmailKeyRing.getCandidateKeysForEmail(address);
  const keyObj = candidates.find(k => k.fpr.toUpperCase() == wanted);
  Assert.ok(
    keyObj,
    `${fpr} is among the candidate keys for ${address} ` +
      `(got ${candidates.map(k => k.fpr).join(", ")})`
  );

  const details = {};
  const level = await EnigmailKeyRing.isValidKeyForRecipient(
    keyObj,
    address,
    false,
    details
  );
  info(
    `FINDING ${address}: level=${level} source=${JSON.stringify(details.source)}`
  );
  return { level, source: details.source, keyObj };
}

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();

  // Carol is in the profile and nowhere else, which is what makes her the
  // store's case rather than gpg's.
  await OpenPGPTestUtils.importPublicKey(
    null,
    do_get_file(`${keyDir}/${CAROL_PUBLIC}`)
  );
  EnigmailKeyRing.clearCache();

  try {
    gpgPath = await Subprocess.pathSearch("gpg");
  } catch (ex) {
    info("No gpg executable found; the external arm cannot be exercised.");
    return;
  }

  gnupgHome = do_get_tempdir();
  gnupgHome.append("gnupg-trust-provenance");
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
    do_get_file(`${keyDir}/${BOB_SECRET}`).path,
  ]);
  if (imported.exitCode) {
    info(`gpg could not import Bob's key: ${imported.stderr}`);
    return;
  }

  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  registerCleanupFunction(() => {
    Services.prefs.clearUserPref("mail.openpgp.allow_external_gnupg");
  });

  if (!GPGME.init()) {
    info("No usable gpgme library found.");
    return;
  }
  available = true;
});

/**
 * A key GnuPG holds is answered by GnuPG, and says so.
 */
add_task(async function aGnuPGKeyIsSourcedFromGnuPG() {
  if (!available) {
    info("SKIPPED: external GnuPG is not available on this machine.");
    Assert.ok(true, "skipped");
    return;
  }

  const { level, source, keyObj } = await provenance(BOB_FPR, BOB_ADDRESS);
  Assert.equal(source, "gnupg", "a key GnuPG holds is sourced from GnuPG");
  Assert.equal(
    level,
    await EnigmailKeyRing.getKeyAcceptanceLevelForEmail(keyObj, BOB_ADDRESS),
    "and the level is still the store's answer -- this step labels, it does not switch"
  );
});

/**
 * A key only the profile holds is the user's own declaration, and says so.
 */
add_task(async function aProfileKeyIsSourcedFromTheStore() {
  const { source } = await provenance(CAROL_FPR, CAROL_ADDRESS);
  Assert.equal(
    source,
    "store",
    "a key GnuPG does not hold is answered by this build's store"
  );
});

/**
 * The fallback: with the external ring switched off, a GnuPG-held key is still
 * answered -- by the store, and with a usable value.
 *
 * This is the assertion a build that read `null` as `UNKNOWN` fails. It would
 * report `source: "gnupg"` with a level of 0, or refuse outright; either way the
 * user loses a recipient they had before, for a reason they cannot see.
 */
add_task(async function theExternalRingOffFallsBackRatherThanRefusing() {
  if (!available) {
    info("SKIPPED: external GnuPG is not available on this machine.");
    Assert.ok(true, "skipped");
    return;
  }

  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", false);
  try {
    const { level, source } = await provenance(BOB_FPR, BOB_ADDRESS);
    Assert.equal(
      source,
      "store",
      "with the external ring off, the store answers"
    );
    Assert.notEqual(
      level,
      OpenPgpValidity.UNKNOWN,
      "and the answer is a real value, not the absence of one"
    );
    Assert.ok(
      OpenPgpValidity.UNKNOWN !== level || source === "store",
      "absence from GnuPG never becomes a refusal"
    );
  } finally {
    Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  }
});

/**
 * A key with its secret half in the profile is the user's own declaration,
 * whichever engine also knows about it.
 */
add_task(async function aPersonalKeyIsAlwaysTheStoresAnswer() {
  const alice = "alice@openpgp.example-0xf231550c4f47e38e-secret.asc";
  const aliceFpr = "EB85BB5FA33A75E15E944E63F231550C4F47E38E";

  await OpenPGPTestUtils.importPrivateKey(
    null,
    do_get_file(`${keyDir}/${alice}`),
    OpenPGPTestUtils.ACCEPTANCE_PERSONAL
  );
  EnigmailKeyRing.clearCache();

  const { level, source } = await provenance(aliceFpr, "alice@openpgp.example");
  Assert.equal(
    source,
    "store",
    "marking a key personal is a statement this build makes, not one gpg computes"
  );
  Assert.equal(level, OpenPgpValidity.ULTIMATE, "and it is ultimately trusted");
});
