/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 67: verify that nothing is decided silently.
 *
 * Three checks, each written so it can fail. Two of them run:
 *
 *   - check 3, a revoked key carrying an old "verified" acceptance, passes:
 *     the key is refused before the label is consulted.
 *   - check 1, two acceptable keys for one address with neither preferred,
 *     does NOT pass. The lookup returns both, which is Item 27's work and is
 *     right; but the composer never surfaces the choice and the send path
 *     resolves it by itself. The task below is a characterisation of that
 *     behaviour, labelled as such, and it must be inverted when the fix lands.
 *
 * Check 2 -- one key held by GnuPG and one by the internal store -- could not
 * be exercised: the transient GnuPG key path returned no keys for the address
 * in this harness, with `mail.openpgp.allow_external_gnupg` set and an explicit
 * `loadGnuPgKeysForEmail()`, so "the ask happens once" could not be observed.
 * That is recorded as not run rather than assumed either way.
 *
 * The claim under test throughout is design 13.6's: the engine asks rather than
 * decides. Where it decides, the useful output of the check is the name of the
 * function that decides.
 */

"use strict";

const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { OpenPGPMasterpass } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/masterpass.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { PgpSqliteDb2 } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/sqliteDb.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { Subprocess } = ChromeUtils.importESModule(
  "resource://gre/modules/Subprocess.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";

var gpgPath = null;
var gnupgHome = null;

/**
 * @param {string[]} args
 * @returns {Promise<{exitCode: integer, stdout: string, stderr: string}>}
 */
async function runGpg(args) {
  const process = await Subprocess.call({
    command: gpgPath,
    arguments: [
      "--batch",
      "--no-tty",
      "--yes",
      "--pinentry-mode",
      "loopback",
      ...args,
    ],
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

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();

  try {
    gpgPath = await Subprocess.pathSearch("gpg");
  } catch (ex) {
    info("No gpg executable found; check 2 will be skipped.");
    return;
  }

  // A throwaway home, and a pinentry that does not exist so a command that
  // would ask a human fails instead -- and never puts a dialog on a screen.
  gnupgHome = do_get_tempdir();
  gnupgHome.append("gnupg-nothing-silent");
  gnupgHome.createUnique(Ci.nsIFile.DIRECTORY_TYPE, 0o700);
  await IOUtils.writeUTF8(
    PathUtils.join(gnupgHome.path, "gpg-agent.conf"),
    "pinentry-program /nonexistent/item67-no-pinentry\n"
  );

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
});

/**
 * The fingerprint of the key the internal send path would use for an address.
 *
 * This is the function that decides, so a check about silence has to look at
 * it: `findKeyByEmail(email, true)` walks librnp's identifiers, prefers a
 * "verified" key over an "unverified" one, and returns the first that
 * qualifies. Nothing in its signature takes a preferred key.
 *
 * @param {string} email
 * @returns {Promise<?string>} The fingerprint, or null.
 */
async function keyTheSendPathWouldUse(email) {
  // The handle is not destroyed: `RNPLib` is module-private, and the tests
  // that already call this function (`test_secretKeys.js`) leave theirs to the
  // test process for the same reason.
  const handle = await RNP.findKeyByEmail(`<${email}>`, true);
  if (!handle || handle.isNull()) {
    return null;
  }
  return RNP.getFingerprintFromHandle(handle);
}

// ---------------------------------------------------------------- check 3

/**
 * A revoked key carrying an old "verified" acceptance is refused, and refused
 * before the label is read.
 *
 * This is the one place design 13.6 says the internal engine is already
 * stronger than a naive trust label, so the check is that the work in this
 * stage has not regressed it: a sticky "verified" must not outlive a
 * revocation.
 */
add_task(async function check3_revokedKeyIsRefusedBeforeItsLabel() {
  await OpenPGPTestUtils.importPublicKey(
    null,
    do_get_file(`${keyDir}/carol@pgp.icu-0xEF2FD01608AFD744-revoked-secret.asc`)
  );
  EnigmailKeyRing.clearCache();

  const key = EnigmailKeyRing.getKeyById("0xEF2FD01608AFD744");
  Assert.ok(key, "the revoked fixture key is in the keyring");
  Assert.equal(key.keyTrust, "r", "and the keyring reports it as revoked");

  // The old judgment, written as though the key were still good. This is the
  // state a user is in when a key they verified is revoked later.
  await PgpSqliteDb2.updateAcceptance(key.fpr, ["carol@pgp.icu"], "verified");

  const stored = await PgpSqliteDb2.getFingerprintAcceptance(null, key.fpr);
  Assert.equal(
    stored,
    "verified",
    "the stale judgment really is stored, so the check is not vacuous"
  );

  const level = await EnigmailKeyRing.isValidKeyForRecipient(
    key,
    "carol@pgp.icu",
    false
  );
  Assert.less(
    level,
    0,
    `a revoked key must be refused whatever its label, got level ${level}`
  );

  // The refusal is structural, not a filter applied later: the key does not
  // appear in the list the composer builds, so no UI can offer it.
  const usable = await EnigmailKeyRing.getValidKeysForRecipient(
    "carol@pgp.icu",
    {}
  );
  Assert.ok(
    !usable.includes(key.keyId),
    `the revoked key must not be offered, got ${JSON.stringify(usable)}`
  );

  // And the send path does not resolve to it either.
  const wouldUse = await keyTheSendPathWouldUse("carol@pgp.icu");
  Assert.notEqual(
    wouldUse,
    key.fpr,
    "the send path must not select a revoked key"
  );
});

// ---------------------------------------------------------------- check 1

/**
 * Two acceptable keys for one address, neither preferred.
 *
 * THE CLAIM IS NOT MET, and this task records what happens instead. Design
 * 13.6 requires the composer to ask; it does not ask, and nothing in the send
 * path carries an answer from the user. The two halves:
 *
 *   - the lookup is right: `getValidKeysForRecipient` returns BOTH keys, which
 *     is Item 27's work and must not be undone;
 *   - the resolution is silent: `findKeyByEmail(email, true)` picks one, on
 *     its own rule, with no input from the user.
 *
 * So the defect is not the lookup. It is that the answer the lookup produces
 * has nowhere to go, and the send path asks a different question of a
 * different function.
 *
 * WHEN THE FIX LANDS THIS TASK MUST BE INVERTED: it should then assert that
 * the two-key case is surfaced and that the user's answer is what the send
 * path reads. Leaving it as it is would mean the fix passes unnoticed.
 */
add_task(async function check1_twoAcceptableKeysAreResolvedSilently() {
  const addr = "carol@example.com";

  // A correspondent's key from a fixture, and a generated key for the same
  // address. Two distinct keys, both usable for encryption, both acceptable.
  await OpenPGPTestUtils.importPublicKey(
    null,
    do_get_file(`${keyDir}/carol@example.com-0x3099ff1238852b9f-pub.asc`)
  );
  const pass = await OpenPGPMasterpass.retrieveOpenPGPPassword();
  const keyId = await RNP.genKey(
    "Carol Internal <carol@example.com>",
    "ECC",
    0,
    0,
    pass
  );
  EnigmailKeyRing.clearCache();

  const fromRing = EnigmailKeyRing.getKeyById("0x3099ff1238852b9f");
  const generated = EnigmailKeyRing.getKeyById(keyId);
  Assert.ok(fromRing, "the fixture key is present");
  Assert.ok(generated, "the generated key is present");
  Assert.notEqual(fromRing.fpr, generated.fpr, "and they are different keys");

  // Both acceptable, neither preferred: the acceptance for each is the highest
  // a correspondent key can carry, and the generated key is personal.
  await PgpSqliteDb2.updateAcceptance(fromRing.fpr, [addr], "verified");
  await PgpSqliteDb2.acceptAsPersonalKey(generated.fpr);

  // Half one: the lookup produces every usable key and states no preference.
  const usable = await EnigmailKeyRing.getValidKeysForRecipient(addr, {});
  Assert.equal(
    usable.length,
    2,
    `both keys must be returned, got ${JSON.stringify(usable)}`
  );

  const metas = await EnigmailKeyRing.getEncryptionKeyMeta(addr);
  const acceptedMetas = metas.filter(k => k.readiness == "accepted");
  Assert.equal(
    acceptedMetas.length,
    2,
    "and the composer's own view reports both as accepted, not one as better"
  );

  // Half two, and this is the finding. The composer's criterion for asking is
  // "no key is accepted" -- `checkRecipientKeys()` in MsgComposeCommands.js
  // pushes an address onto its problem list only when this fails. Two accepted
  // keys therefore meet the criterion for "nothing to ask about".
  const anyAccepted = metas.some(k => k.readiness == "accepted");
  Assert.ok(
    anyAccepted,
    "the composer's condition for needing to ask is not met"
  );
  info(
    "FINDING, check 1: two acceptable keys for one address do not make the " +
      "composer ask. MsgComposeCommands.js checkRecipientKeys() reports only " +
      "addresses with NO accepted key, so an address with two is silent."
  );

  // And the resolution happens anyway, in a function the user never sees.
  const chosen = await keyTheSendPathWouldUse(addr);
  Assert.ok(chosen, "the send path resolves to a key on its own");
  Assert.ok(
    [fromRing.fpr, generated.fpr]
      .map(f => f.toUpperCase())
      .includes(chosen.toUpperCase()),
    `and it is one of the two, got ${chosen}`
  );
  info(
    `FINDING, check 1: RNP.findKeyByEmail("<${addr}>", true) selected ` +
      `${chosen} with no input from the user. That is the ranking Item 27 ` +
      `removed from the lookup, surviving in the encryption path.`
  );

  // The contrast, stated so the finding cannot be read as "the lookup ranks":
  // the lookup returns two and the selection returns one, from different
  // functions.
  Assert.notEqual(
    usable.length,
    1,
    "the lookup itself must not narrow the candidate list"
  );
});

// ---------------------------------------------------------------- check 2

/**
 * Check 2 could not be exercised, and this task records why rather than
 * leaving the gap silent.
 *
 * The case is one key held by GnuPG and one by the internal store, both for
 * the same address, asserting that a single ask covers both. Reaching it needs
 * a transient GnuPG key, and in this harness the transient path returned no
 * keys for the address even with `mail.openpgp.allow_external_gnupg` set, a
 * throwaway `GNUPGHOME` populated by `gpg --quick-generate-key`, and an
 * explicit `loadGnuPgKeysForEmail()`. Two setups were tried; neither produced a
 * transient key, so nothing about the ask-once behaviour can be said either way.
 *
 * What can be said is what makes a single ask possible: the candidate list
 * de-duplicates by fingerprint, with the GnuPG revision surviving. That rule is
 * asserted in the other direction by Item 14's tests.
 */
add_task(async function check2_oneAskNotTwoWithDifferentAnswers() {
  if (!gpgPath) {
    info("SKIPPED: no gpg executable; the external arm cannot be exercised.");
    Assert.ok(true, "skipped");
    return;
  }

  const addr = "both@example.com";

  // One key in GnuPG, one in this profile's ring, for the same address. That is
  // the shape the check is about: two stores that could each answer, and the
  // question is whether the caller has to ask twice and reconcile.
  // A parameter file rather than `--quick-generate-key`: in batch mode even the
  // quick form wants a passphrase, and this key needs none. `%no-protection` is
  // the mechanism, and it is what Item 88a's test uses for the same reason.
  const params = PathUtils.join(gnupgHome.path, "both-external.params");
  await IOUtils.writeUTF8(
    params,
    [
      "Key-Type: eddsa",
      "Key-Curve: ed25519",
      // cert and sign on the primary, plus an encryption subkey. My first
      // version asked for a signing-only key, and `getEncryptionKeyMeta()`
      // correctly skipped it -- a key that cannot encrypt is not an answer to
      // "which key encrypts to this address". The filter was right and the
      // fixture was wrong.
      "Key-Usage: sign,cert",
      "Subkey-Type: ecdh",
      "Subkey-Curve: cv25519",
      "Subkey-Usage: encrypt",
      "Name-Real: Both External",
      `Name-Email: ${addr}`,
      "Expire-Date: 0",
      "%no-protection",
      "%commit",
      "",
    ].join("\n")
  );
  const generated = await runGpg(["--gen-key", params]);
  Assert.equal(
    generated.exitCode,
    0,
    `gpg generated the external key: ${generated.stderr.trim()}`
  );

  // The internal key has to be for the *same* address, or the two are not
  // answers to one question. Generated rather than a fixture, because every
  // fixture's address is fixed and none of them collides with a key gpg holds.
  const pass = await OpenPGPMasterpass.retrieveOpenPGPPassword();
  const internalId = await RNP.genKey(
    `Both Internal <${addr}>`,
    "ECC",
    0,
    0,
    pass
  );
  EnigmailKeyRing.clearCache();
  const internal = EnigmailKeyRing.getKeyById(internalId);
  Assert.ok(internal, "the internal key is present");
  await PgpSqliteDb2.acceptAsPersonalKey(internal.fpr);

  // The external ring must be reachable for this test, which is the premise the
  // earlier run could not establish.
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  Services.prefs.setBoolPref("mail.openpgp.fetch_pubkeys_from_gnupg", true);
  registerCleanupFunction(() => {
    Services.prefs.clearUserPref("mail.openpgp.allow_external_gnupg");
    Services.prefs.clearUserPref("mail.openpgp.fetch_pubkeys_from_gnupg");
  });

  EnigmailKeyRing.clearGnuPgKeyCache();
  const loaded = await EnigmailKeyRing.loadGnuPgKeysForEmail(addr);
  Assert.ok(loaded, "the external ring was consulted for this address");

  // **The assertion the check exists for: one lookup, both answers.** A caller
  // asks the ring once per address and gets every key that could encrypt to it,
  // from both stores -- rather than asking each store separately and having to
  // reconcile two lists itself, which is where "twice with different answers"
  // would come from.
  const metas = await EnigmailKeyRing.getEncryptionKeyMeta(addr);
  info(
    `FINDING check 2: ${metas.length} key metadata records for ${addr}: ` +
      `${JSON.stringify(metas.map(m => m.keyObj?.fpr ?? m.readiness))}`
  );
  Assert.equal(
    metas.length,
    2,
    `one ask returns both keys, got ${metas.length}`
  );

  // The metas are address-filtered; `getCandidateKeysForEmail()` is **not** --
  // it returns the whole ring plus the transient keys, and the narrowing
  // happens here in `getEncryptionKeyMeta()`. That surprised me while writing
  // this: the name reads like a per-address lookup and it is a per-address
  // *superset*. Asserting on the candidates would therefore have measured the
  // ring's size rather than this address's answers, so the checks below are on
  // the metas.
  const internalMeta = metas.find(
    m => m.keyObj?.fpr.toUpperCase() == internal.fpr.toUpperCase()
  );
  Assert.ok(internalMeta, "the internal key is one of the two answers");
  const fromGnuPG = metas.filter(m => m.gnupgKey);
  Assert.equal(
    fromGnuPG.length,
    1,
    `exactly one answer came from GnuPG, got ${fromGnuPG.length}`
  );
  Assert.notEqual(
    fromGnuPG[0].keyObj.fpr.toUpperCase(),
    internal.fpr.toUpperCase(),
    "and it is a different key from the internal one"
  );
});
