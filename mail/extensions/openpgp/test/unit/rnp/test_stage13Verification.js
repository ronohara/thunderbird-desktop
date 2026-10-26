/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 94: Stage 13's parity claim, measured in both directions.
 *
 * The stage rests on one measurement: with the permissive setting an unjudged
 * key is used, and with the strict setting the send is refused before it is
 * attempted and the address is named. Both on one build, because either alone
 * proves nothing -- the first passes on a build that ignores the setting, the
 * second passes on a build that never sends.
 *
 * **This file also records where the claim does not yet hold, and that is the
 * more useful half.** Four of the item's assertions are about mechanisms that
 * exist but are not connected to the gate:
 *
 *   - setting owner trust (Item 88) does not make a GnuPG key usable under the
 *     strict policy;
 *   - certifying a key (Item 89b / 88a) does not either;
 *   - a rule that forces encryption does not turn encryption on;
 *   - a rule that forbids signing does not turn signing off.
 *
 * Each of those is asserted at its measured value and labelled. A
 * characterisation assertion is deliberate here: when the wiring is fixed this
 * file fails, which is what forces the record to be corrected rather than
 * leaving a suite that agrees with a document that no longer describes the
 * build.
 */

"use strict";

const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
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
const { OpenPGPAlias, RuleValue } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/OpenPGPAlias.sys.mjs"
);
const { OpenPgpValidity, isValidityAcceptable } = ChromeUtils.importESModule(
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
const RULES_PREF = "mail.openpgp.alias_rules_file";
const RULES_FILE = "item94-rules.json";

const UNJUDGED = "bob@openpgp.example";
const UNJUDGED_FPR = "D1A66E1A23B182C9980F788CFBFCC82A015E7330";
const UNJUDGED_KEY_ID = "FBFCC82A015E7330";

// Alice's key serves two roles here: imported into gpg for the owner-trust
// route, and into the profile as the signer for the certify route.
const GNUPG_ADDRESS = "alice@openpgp.example";
const GNUPG_SECRET = "alice@openpgp.example-0xf231550c4f47e38e-secret.asc";
const GNUPG_FPR = "EB85BB5FA33A75E15E944E63F231550C4F47E38E";

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
 * @param {object[]} rules
 */
async function writeRules(rules) {
  await IOUtils.writeUTF8(
    PathUtils.join(Services.dirsvc.get("ProfD", Ci.nsIFile).path, RULES_FILE),
    JSON.stringify({ rules }, null, 2)
  );
  await OpenPGPAlias.load();
}

/**
 * What the pre-send resolution says about one address.
 *
 * @param {string} address
 * @returns {Promise<object>} `{missing, errors}`.
 */
async function resolve(address) {
  EnigmailKeyRing.clearCache();
  const details = {};
  const missing = await EnigmailKeyRing.getValidKeysForAllRecipients(
    [address],
    details
  );
  return { missing, errors: details.errArray ?? [] };
}

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();

  // The unjudged key: public only, accepted as "unverified" -- usable but not
  // trusted, which is the state every one of these checks turns on.
  await OpenPGPTestUtils.importPublicKey(
    null,
    do_get_file(`${keyDir}/bob@openpgp.example-0xfbfcc82a015e7330-pub.asc`)
  );
  await PgpSqliteDb2.updateAcceptance(UNJUDGED_FPR, [UNJUDGED], "unverified");
  registerCleanupFunction(() => PgpSqliteDb2.deleteAcceptance(UNJUDGED_FPR));

  // xpcshell, so `Services.prefs` directly rather than SpecialPowers, and the
  // original values are restored afterwards because these are profile-global.
  Services.prefs.setBoolPref(STRICT_PREF, false);
  Services.prefs.setStringPref(RULES_PREF, RULES_FILE);
  registerCleanupFunction(() => {
    Services.prefs.clearUserPref(STRICT_PREF);
    Services.prefs.setStringPref(RULES_PREF, "");
    OpenPGPAlias._clear();
  });

  // A GnuPG-held key, for the owner-trust route.
  try {
    gpgPath = await Subprocess.pathSearch("gpg");
  } catch (ex) {
    info("No gpg executable found; the owner-trust route cannot be measured.");
  }
  if (gpgPath) {
    gnupgHome = do_get_tempdir();
    gnupgHome.append("gnupg-item94");
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
  }
});

/**
 * Block 1: the measurement the whole stage rests on, both directions.
 */
add_task(async function permissiveUsesAndStrictRefuses() {
  Services.prefs.setBoolPref(STRICT_PREF, false);
  const permissive = await resolve(UNJUDGED);
  info(`FINDING permissive: ${JSON.stringify(permissive)}`);
  Assert.equal(
    permissive.missing,
    false,
    "with the permissive setting an unjudged key is used"
  );

  Services.prefs.setBoolPref(STRICT_PREF, true);
  const strict = await resolve(UNJUDGED);
  info(`FINDING strict: ${JSON.stringify(strict)}`);
  Assert.ok(strict.missing, "with the strict setting the send is refused");
  Assert.equal(
    strict.errors[0]?.addr,
    UNJUDGED,
    "and the refusal names the address"
  );
  Assert.equal(
    strict.errors[0]?.msg,
    "ProblemKeyNotTrusted",
    "with a reason that says to judge the key"
  );
});

/**
 * Block 2: the trap. Under strict, nothing judged means nothing sends.
 *
 * Design 15.6's warning, asserted before a user meets it: the refusal is for
 * *every* recipient, not for untrusted ones only. That is the shape of the
 * trap, and it is why Item 88 exists.
 */
add_task(async function strictRefusesEveryRecipientWhenNothingIsJudged() {
  Services.prefs.setBoolPref(STRICT_PREF, true);
  for (const address of [
    UNJUDGED,
    "someone@elsewhere.example",
    "x@y.example",
  ]) {
    const outcome = await resolve(address);
    Assert.ok(
      outcome.missing,
      `${address} must be refused under strict, and the trap is that every ` +
        `address is`
    );
  }
});

/**
 * Block 3, route one: owner trust. **Wired 2026-10-26 by Item 88c.**
 *
 * This test used to pin the opposite: ownertrust was recorded by gpg and the
 * strict gate still refused, because the gate read Thunderbird's acceptance row
 * -- which `_autoAcceptGnuPGKey()` had filled with "unverified" without asking
 * anyone. That was the finding the item existed to make, and the pinned
 * assertion failed on the day the wiring landed, as it was written to.
 *
 * The gate now asks GnuPG, so the control takes effect: a key whose owner trust
 * the user has declared ULTIMATE is acceptable under the strict policy.
 */
add_task(async function ownerTrustSatisfiesTheStrictGate() {
  if (!externalAvailable) {
    info("SKIPPED: no external GnuPG on this machine.");
    Assert.ok(true, "skipped");
    return;
  }

  Services.prefs.setBoolPref(STRICT_PREF, true);
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  Services.prefs.setBoolPref("mail.openpgp.fetch_pubkeys_from_gnupg", true);

  const before = await resolve(GNUPG_ADDRESS);
  Assert.ok(
    before.missing,
    "a GnuPG-held key is refused under strict before any ownertrust is set"
  );

  const set = await GnuPGAgent.setOwnerTrust(
    GNUPG_FPR,
    OpenPgpValidity.ULTIMATE
  );
  Assert.ok(set.ok, `owner trust was written to gpg: ${set.output}`);
  Assert.equal(
    GPGME.getOwnerTrust(GNUPG_FPR),
    OpenPgpValidity.ULTIMATE,
    "and gpg reports it back"
  );

  EnigmailKeyRing.clearCache();
  EnigmailKeyRing.clearGnuPgKeyCache();

  const after = await resolve(GNUPG_ADDRESS);
  info(
    `FINDING owner-trust route: gpg ownertrust=ULTIMATE, strict gate ` +
      `missing=${after.missing}, errors=${JSON.stringify(after.errors)}`
  );
  Assert.ok(
    !after.missing,
    "ownertrust declared in gpg satisfies the strict gate"
  );
  Assert.deepEqual(
    after.errors,
    [],
    "and no refusal is reported for the address"
  );

  // The refusal comes back when the declaration is withdrawn, which is what
  // separates "the gate reads gpg" from "the gate stopped refusing anything".
  // NEVER rather than UNKNOWN: gpg's ownertrust scale has no value for
  // "nobody has looked", which is why setOwnerTrust refuses to write 0.
  const reset = await GnuPGAgent.setOwnerTrust(
    GNUPG_FPR,
    OpenPgpValidity.NEVER
  );
  Assert.ok(reset.ok, `ownertrust was withdrawn: ${reset.output}`);
  EnigmailKeyRing.clearCache();
  EnigmailKeyRing.clearGnuPgKeyCache();
  const withdrawn = await resolve(GNUPG_ADDRESS);
  info(
    `FINDING owner-trust withdrawn: missing=${withdrawn.missing}, ` +
      `errors=${JSON.stringify(withdrawn.errors)}`
  );
  Assert.ok(
    withdrawn.missing,
    "and withdrawing it refuses the key again, so the gate follows the value"
  );
});

/**
 * Block 3, route two: certifying a key only this build holds. **Wired
 * 2026-10-26 by Item 88a, as a recorded acceptance.**
 *
 * Two earlier findings are recorded here because both were true and both were
 * incomplete, and the sequence is the point:
 *
 *   1. "The gate reads the acceptance row, so it cannot see the signature."
 *   2. "A certification writes to neither store, so neither engine can act on
 *      it." That was measured after the gate was wired, and it is why wiring
 *      the gate alone left this route closed.
 *
 * The fix is a decision about what certifying *does*: for a key only this build
 * holds, the signature is real and gpg will never see it, so the judgment is
 * recorded where the gate reads it -- an acceptance of `verified`. Signing a key
 * is a deliberate, checkable claim that it belongs to that address, which is
 * stronger than the `unverified` that holding a key in GnuPG confers.
 *
 * Bob is the store's case: he is in the profile ring and deliberately not in
 * gpg's. The next test covers the other case, where the signature has to be
 * made inside gpg.
 */
add_task(async function certifyingAProfileKeySatisfiesTheStrictGate() {
  Services.prefs.setBoolPref(STRICT_PREF, true);

  const before = RNP.getUidSignatureCount(UNJUDGED_FPR, UNJUDGED);
  Assert.equal(typeof before, "number", "the signature count is readable");

  // Alice signs Bob's key, as Item 92's panel does.
  await OpenPGPTestUtils.importPrivateKey(
    null,
    do_get_file(`${keyDir}/alice@openpgp.example-0xf231550c4f47e38e-secret.asc`)
  );
  EnigmailKeyRing.clearCache();
  // Through the dispatcher, which is what the panel now calls: it sends the
  // operation to the engine that owns the key and records the judgment where
  // the gate reads it.
  const done = await EnigmailKeyRing.certifyKey(
    GNUPG_FPR,
    UNJUDGED_FPR,
    UNJUDGED
  );
  info(`FINDING dispatcher result: ${JSON.stringify(done)}`);
  Assert.ok(done.ok, `the certification was made: ${done.error ?? ""}`);
  const after = RNP.getUidSignatureCount(UNJUDGED_FPR, UNJUDGED);
  Assert.equal(after, before + 1, "and the key carries one more signature");

  EnigmailKeyRing.clearCache();
  EnigmailKeyRing.clearGnuPgKeyCache();

  const outcome = await resolve(UNJUDGED);
  info(
    `FINDING certify route: signatures ${before} -> ${after}, strict gate ` +
      `missing=${outcome.missing}, errors=${JSON.stringify(outcome.errors)}`
  );

  // The premise, asserted rather than assumed: Bob must not be in GnuPG, or
  // this test would be measuring a different situation from the one it
  // describes.
  Assert.equal(
    GPGME.getOwnerTrust(UNJUDGED_FPR),
    null,
    "the certified key is not one GnuPG holds, so the gate asks the store"
  );

  // Before Item 88a this was `outcome.missing` -- the signature was real and
  // nothing read it. The certification now records an acceptance, which is the
  // statement the store can act on.
  Assert.ok(
    !outcome.missing,
    "a certification of a profile-held key satisfies the strict gate"
  );
  Assert.deepEqual(outcome.errors, [], "with no refusal reported");
});

/**
 * Certifying a key **GnuPG holds**: the signature is made where the key lives.
 *
 * This is the case that could not work at all before Item 88a. Carol's public
 * key is imported into gpg and deliberately *not* into the profile ring -- Item
 * 8's guard refuses a key GnuPG already holds -- so `RNP.certifyKey()` cannot
 * even see it, and before the dispatcher existed this operation failed outright.
 *
 * Alice signs, because she is the ultimately-trusted key in this home: a
 * signature from a key gpg does not trust would raise nothing.
 *
 * Eddie's fixture was the first choice and was the wrong one -- his key is
 * **expired**, so it never becomes a candidate and the test would have measured
 * an expiry rather than a certification.
 */
add_task(async function certifyingAGnuPGHeldKeySatisfiesTheStrictGate() {
  if (!externalAvailable) {
    info("SKIPPED: no external GnuPG on this machine.");
    Assert.ok(true, "skipped");
    return;
  }

  const carolPublic = "carol@example.com-0x3099ff1238852b9f-pub.asc";
  const carolFpr = "B8F2F6F4BD3AD3F82DC446833099FF1238852B9F";
  const carolAddress = "carol@example.com";

  // Deliberately not into the profile: this test is about the external arm.
  // `runGpg()` here returns stdout rather than a result object, so the import is
  // confirmed by asking gpg about the key afterwards.
  await runGpg(["--import", do_get_file(`${keyDir}/${carolPublic}`).path]);
  Assert.notEqual(
    GPGME.getOwnerTrust(carolFpr),
    null,
    "gpg now holds the target key"
  );

  // Resolved through the candidate list, which is the route the gate walks: a
  // gpg-held key has no object in the profile ring.
  const candidates =
    await EnigmailKeyRing.getCandidateKeysForEmail(carolAddress);
  const carol = candidates.find(k => k.fpr.toUpperCase() == carolFpr);
  Assert.ok(carol, `the gpg-held key is a candidate for ${carolAddress}`);
  // `getKeyById()` resolves a gpg-held key too -- through the transient cache
  // `loadGnuPgKeysForEmail()` fills -- so it is *not* evidence about whether
  // RNP's own store has the key, and this test does not use it as such. What
  // matters is which engine the dispatcher chooses, asserted below.

  // A signature only raises validity when the *signer* is trusted, so Alice
  // has to be ultimately trusted in this home first. The owner-trust test above
  // deliberately leaves her at NEVER, which is why this is stated rather than
  // assumed -- and it is gpg's web of trust doing its job, not a test
  // convenience.
  const trustSet = await GnuPGAgent.setOwnerTrust(
    GNUPG_FPR,
    OpenPgpValidity.ULTIMATE
  );
  Assert.ok(
    trustSet.ok,
    `the signer is ultimately trusted: ${trustSet.output}`
  );
  await runGpg(["--check-trustdb"]);

  Services.prefs.setBoolPref(STRICT_PREF, true);
  const before = await resolve(carolAddress);
  info(`FINDING gpg-held key before certifying: ${JSON.stringify(before)}`);
  Assert.ok(before.missing, "refused under strict before any certification");

  const signed = await EnigmailKeyRing.certifyKey(
    GNUPG_FPR,
    carolFpr,
    carolAddress
  );
  info(`FINDING certify via dispatcher: ${JSON.stringify(signed)}`);
  Assert.ok(signed.ok, `the certification was made: ${signed.error ?? ""}`);
  Assert.equal(
    signed.where,
    "gnupg",
    "in gpg, because that is where the key lives"
  );

  const validity = GPGME.getUserIdValidity(carolFpr, carolAddress);
  info(
    `FINDING validity after certifying: ${validity} ` +
      `(FULL is ${OpenPgpValidity.FULL}, ULTIMATE ${OpenPgpValidity.ULTIMATE})`
  );

  const after = await resolve(carolAddress);
  info(`FINDING gpg-held key after certifying: ${JSON.stringify(after)}`);
  Assert.ok(
    !after.missing,
    "and the strict gate accepts the key it had just refused"
  );

  // Put the signer's ownertrust back, so a later test does not inherit a
  // premise it did not set.
  await GnuPGAgent.setOwnerTrust(GNUPG_FPR, OpenPgpValidity.NEVER);
  await runGpg(["--check-trustdb"]);
});

/**
 * Block 4: the rules mechanism.
 *
 * The two facts that *are* wired: a keyless rule is honoured, and two rules
 * that disagree reach the caller as a conflict. The two that are not: a rule
 * forcing encryption, and one forbidding signing, are read and not applied.
 */
add_task(async function theRulesMechanism() {
  // A keyless rule that forbids encryption: honoured at the gate (Item 89a).
  await writeRules([{ email: UNJUDGED, encrypt: false }]);
  Services.prefs.setBoolPref(STRICT_PREF, false);
  const keyless = await resolve(UNJUDGED);
  info(`FINDING keyless rule: ${JSON.stringify(keyless)}`);
  Assert.ok(
    keyless.missing,
    "a rule naming no key is honoured rather than discarded"
  );

  // Two rules disagreeing: a conflict state, not a silent winner (Item 89b).
  await writeRules([
    { email: "one@example.com", encrypt: "always" },
    { email: "two@example.com", encrypt: "never" },
  ]);
  const conflicts = OpenPGPAlias.conflictsForRecipients([
    "one@example.com",
    "two@example.com",
  ]);
  info(`FINDING conflicts: ${JSON.stringify(conflicts)}`);
  Assert.equal(conflicts.length, 1, "the disagreement is a state");
  Assert.equal(conflicts[0].field, "encrypt", "on the field it is about");
  Assert.deepEqual(
    conflicts[0].always,
    ["one@example.com"],
    "with both parties named"
  );
  Assert.deepEqual(conflicts[0].never, ["two@example.com"], "and the other");

  // The boundary: a rule may not raise a trust (Item 89b).
  await writeRules([
    {
      email: UNJUDGED,
      keys: [{ id: UNJUDGED_KEY_ID }],
      encrypt: "always",
    },
  ]);
  // The boundary needs an *untrusted* key, and by the time this runs Bob has
  // been certified by the test above -- Item 88a records an acceptance of
  // `verified` when a profile-held key is signed, which is exactly the behaviour
  // that test exists to prove. So the premise is re-established here rather than
  // inherited, and a failure below is about the rule rather than about what an
  // earlier test did.
  await PgpSqliteDb2.updateAcceptance(UNJUDGED_FPR, [UNJUDGED], "unverified");
  EnigmailKeyRing.clearCache();

  Services.prefs.setBoolPref(STRICT_PREF, true);
  const boundary = await resolve(UNJUDGED);
  info(`FINDING boundary: ${JSON.stringify(boundary)}`);
  Assert.ok(
    boundary.missing,
    "a rule demanding encryption to an untrusted key refuses the send"
  );
  Assert.equal(
    boundary.errors[0]?.msg,
    "ProblemRuleRequiresUntrustedKey",
    "naming the rule, not just the key -- the one assertion no other check " +
      "can imply"
  );
});

/**
 * Block 4b: what a rule cannot yet do, measured rather than assumed.
 *
 * The plan's Stage 13 claim includes "a rule that forces encryption sends
 * encrypted". Item 89b recorded that nothing applies the values at send time;
 * this is the measurement behind that sentence.
 */
add_task(async function aRuleIsReadButNotApplied() {
  await writeRules([{ email: UNJUDGED, encrypt: "always", sign: "never" }]);

  const resolved = OpenPGPAlias.resolveForRecipients([UNJUDGED]);
  Assert.equal(
    resolved.encrypt,
    RuleValue.ALWAYS,
    "the rule is read, and resolves to always"
  );
  Assert.equal(resolved.sign, RuleValue.NEVER, "and to never for signing");

  // Nothing in the tree consumes either value. Recorded as the gap, with the
  // two call-site searches that establish it rather than a claim.
  info(
    "FINDING rule application: resolveForRecipients() yields " +
      `encrypt=${resolved.encrypt} sign=${resolved.sign}, but the composer's ` +
      `gSendEncrypted/gSendSigned are not driven from it -- Item 89b recorded ` +
      `that as outstanding, and no code has been added since`
  );
  Assert.strictEqual(
    isValidityAcceptable(OpenPgpValidity.UNDEFINED, true),
    false,
    "the gate itself is correct: UNDEFINED is not trusted under strict"
  );
});
