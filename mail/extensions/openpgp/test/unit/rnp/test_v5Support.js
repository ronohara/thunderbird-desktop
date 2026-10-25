/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 75: v5 keys are accepted, and the decision is made on the key's version
 * rather than on the length of its fingerprint.
 *
 * The item's verification requirement is end to end, "because the current
 * failure is silent: import a real v5 key, assert it appears in the key list,
 * that its acceptance can be recorded, and that getKeyById resolves it -- then
 * send and receive with it." That is what this file does.
 *
 * The fixtures are v5 Ed25519 keys, copied from librnp's own test data
 * (`src/tests/data/test_stream_key_load/`) so that a `mach vendor` refresh
 * cannot take them away. They carry a supported algorithm, which the existing
 * `alice-v5-pub.asc` does not -- that one is Ed448, and librnp has no Ed448
 * algorithm at all (`repgp_def.h` has `PGP_PKA_DILITHIUM5_ED448` commented out
 * and there is no `PGP_PKA_ED448`), so it fails to parse before any Thunderbird
 * guard is reached and cannot demonstrate v5 support either way.
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
const { EnigmailConstants } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/constants.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";

/** The v5 key's fingerprint, 32 bytes. Asserted below rather than trusted. */
const V5_FPR =
  "817F60336BB9D133B59F1B91FDEBE36796C1B2F47907BAB49A7EB981DC719DC0";

/**
 * @param {string} name - Fixture file name, without the extension.
 * @returns {Promise<string>} Its contents.
 */
async function readFixture(name) {
  const file = do_get_file(`${keyDir}/${name}.asc`);
  Assert.ok(file.exists(), `fixture ${name}.asc should exist`);
  return IOUtils.readUTF8(file.path);
}

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();
});

/**
 * The fixture is what it is claimed to be: a v5 key, with a supported
 * algorithm, carrying a 64-hex fingerprint.
 *
 * Asserted first so that every task below rests on a fact rather than on a
 * filename.
 */
add_task(async function theFixtureIsAV5Key() {
  const text = await readFixture("v5-ecc-25519-pub");
  const result = await RNP.importPubkeyBlockAutoAcceptImpl(null, text, null);
  Assert.equal(result.exitCode, 0, "the v5 public key should import");

  EnigmailKeyRing.clearCache();
  const key = EnigmailKeyRing.getKeyById(V5_FPR);
  Assert.ok(key, "the v5 key should be in the keyring");
  Assert.equal(key.version, 5, "and its version should be 5");
  Assert.equal(key.fpr.length, 64, "with a 32-byte fingerprint");
});

/**
 * The key appears in the key list -- the item's first check, and the thing that
 * silently did not happen before: the key was refused and vanished.
 */
add_task(async function theKeyAppearsInTheKeyList() {
  EnigmailKeyRing.clearCache();
  const keys = EnigmailKeyRing.getAllKeys(null, null).keyList;
  const found = keys.find(k => k.fpr == V5_FPR);
  Assert.ok(
    found,
    `the v5 key should be listed; the list holds ${keys.length} key(s)`
  );
  Assert.equal(found.version, 5, "and should still report version 5");
});

/**
 * Its acceptance can be recorded, which is the guard that would have refused a
 * v5 key even after a successful import.
 */
add_task(async function acceptanceCanBeRecorded() {
  await PgpSqliteDb2.updateAcceptance(V5_FPR, ["v5@example.net"], "verified");
  registerCleanupFunction(() => PgpSqliteDb2.deleteAcceptance(V5_FPR));

  const stored = await PgpSqliteDb2.getFingerprintAcceptance(null, V5_FPR);
  Assert.equal(stored, "verified", "a v5 fingerprint must be storable");
});

/**
 * And getKeyById resolves it, which is the locator guard.
 */
add_task(async function getKeyByIdResolvesTheV5Fingerprint() {
  EnigmailKeyRing.clearCache();
  const key = EnigmailKeyRing.getKeyById(V5_FPR);
  Assert.ok(key, "getKeyById should resolve a 64-hex fingerprint");
  Assert.equal(key.fpr, V5_FPR, "and return the key asked for");

  // Lower case too, because a stored fingerprint may be either.
  EnigmailKeyRing.clearCache();
  const lower = EnigmailKeyRing.getKeyById(V5_FPR.toLowerCase());
  Assert.ok(lower, "and should be case-insensitive like any other fingerprint");
});

/**
 * The item's last check: send and receive with it.
 *
 * Done at the RNP level rather than through a compose window, because what the
 * item is about is whether the crypto path handles the key -- and the silent
 * failure it describes is the key not being found, not a UI problem. The secret
 * key is imported so the same key signs, encrypts and then decrypts.
 */
add_task(async function sendAndReceiveWithTheV5Key() {
  const secText = await readFixture("v5-ecc-25519-sec");
  const imported = await RNP.importSecKeyBlockImpl(
    null,
    // The fixture is passphrase-protected, with the passphrase librnp's own
    // tests use for their secret-key data -- read from `support.cpp`, not
    // guessed. Returning "" would be treated as a cancel, and asking for a real
    // prompt in xpcshell hangs the file with no error.
    () => "password",
    false,
    secText
  );
  Assert.equal(imported.exitCode, 0, "the v5 secret key should import");

  EnigmailKeyRing.clearCache();
  const key = EnigmailKeyRing.getKeyById(V5_FPR);
  Assert.ok(key, "the secret key should be in the keyring");
  Assert.ok(key.secretAvailable, "and its secret material should be available");

  await PgpSqliteDb2.acceptAsPersonalKey(V5_FPR);

  const sourceText = "A message signed and encrypted with a v5 key.";

  // Encrypted to the sender, not to an address. The fixture's user ID is
  // "v5_25519" with no email part, so there is no address that resolves to this
  // key -- and `encryptToSender` reaches it by fingerprint, which is what the
  // round trip needs to exercise.
  Assert.ok(
    !/@/.test(key.userId),
    `the fixture user ID carries no address, got "${key.userId}"`
  );

  const encryptResult = {};
  const encrypted = await RNP.encryptAndOrSign(
    sourceText,
    {
      aliasKeys: new Map(),
      armor: true,
      bcc: [],
      encrypt: true,
      encryptToSender: true,
      sender: `0x${V5_FPR}`,
      senderKeyIsExternal: false,
      sigTypeClear: false,
      sigTypeDetached: false,
      sign: true,
      signatureHash: "SHA256",
      to: [],
    },
    encryptResult
  );
  Assert.ok(encrypted, "the message should be encrypted");
  Assert.ok(!encryptResult.exitCode, "and encrypting should not fail");

  const { exitCode, decryptedData } = await RNP.decrypt(encrypted, {
    fromAddr: key.userId,
    maxOutputLength: encrypted.length * 100,
    noOutput: false,
    uiFlags: EnigmailConstants.UI_PGP_MIME,
    verifyOnly: false,
    msgDate: null,
  });
  Assert.ok(!exitCode, "and decrypting should not fail");
  Assert.equal(
    decryptedData,
    sourceText,
    "the round trip must return the original text"
  );
});

/**
 * A length that is not a fingerprint is still refused. The widening is three
 * accepted lengths, not "anything goes".
 */
add_task(async function aNonFingerprintLengthIsStillRefused() {
  // Asserted on the read path, which is where the guard lives: the write path
  // stores whatever it is given, and `getFingerprintAcceptance` is what refuses
  // to interpret a length that cannot be a fingerprint. Checking the write path
  // would have asserted a guard that does not exist.
  for (const bad of ["0".repeat(10), "0".repeat(50), "0".repeat(80)]) {
    let refused = false;
    try {
      await PgpSqliteDb2.getFingerprintAcceptance(null, bad);
    } catch (ex) {
      refused = true;
    }
    Assert.ok(refused, `a ${bad.length}-hex value must be refused on read`);
  }

  // And the three real lengths are all accepted, which is the widening itself.
  for (const good of [32, 40, 64]) {
    const fpr = "0".repeat(good);
    const value = await PgpSqliteDb2.getFingerprintAcceptance(null, fpr);
    Assert.ok(
      value === null || value === undefined || typeof value == "string",
      `a ${good}-hex value must be readable rather than refused`
    );
  }
});

/**
 * The import guard decides on the version. Asserted on the source, because the
 * only v6 fixture in the tree cannot be parsed by either GnuPG or librnp -- so
 * a v6 key is refused by the parser before the guard is reached, and a runtime
 * assertion here would be testing the parser instead.
 */
add_task(async function theImportGuardUsesTheVersion() {
  const source = await fetch(
    "chrome://openpgp/content/modules/RNP.sys.mjs"
  ).then(r => r.text());

  Assert.ok(
    /MAX_SUPPORTED_VERSION = 5/.test(source),
    "the guard should name the highest supported version"
  );
  Assert.ok(
    /k\.version > MAX_SUPPORTED_VERSION/.test(source),
    "and compare the key's version against it"
  );
  Assert.ok(
    !/k\.fpr\.length > 40/.test(source),
    "the fingerprint-length heuristic must be gone, not merely bypassed"
  );

  info(
    "the v6 fixtures (pgp-v6-pub.asc, pgp-v6-sec.asc) are unparseable by both " +
      "GnuPG 2.4.4 and the vendored librnp, so v6 refusal is the parser's, not " +
      "this guard's. The guard exists for a v6 key the library does understand, " +
      "which needs ENABLE_CRYPTO_REFRESH and the Botan 3 backend."
  );
});
