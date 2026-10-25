/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 99's account half: adopting an imported key for an identity.
 *
 * Split from `test_autocryptImport.js` because xpcshell has no account-manager
 * server types -- `createIncomingServer` throws `NS_ERROR_NOT_AVAILABLE` there,
 * so nothing past that line runs. The classification, unwrapping and the
 * preference rule are all in the xpcshell file; what needs an account is here.
 *
 * The list of what adoption means comes from Enigmail, because the
 * specification states only the goal. Each item on it is asserted, because
 * each is something a user notices the absence of: a key imported but not
 * attached to the identity leaves them still unable to write encrypted mail,
 * and one imported but not marked personal reads as untrusted in the composer.
 */

"use strict";

const { AutocryptSetup } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/autocryptSetup.sys.mjs"
);
const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { PgpSqliteDb2 } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/sqliteDb.sys.mjs"
);
const { OpenPGPAlias } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/OpenPGPAlias.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);

const ALICE_SECRET_WITH_PP =
  "data/keys/alice@openpgp.example-0xf231550c4f47e38e-secret-with-pp.asc";
const ALICE_FPR = "EB85BB5FA33A75E15E944E63F231550C4F47E38E";
const ALICE_ADDRESS = "alice@openpgp.example";

let account;
let identity;

add_setup(async function () {
  requestLongerTimeout(2);

  account = MailServices.accounts.createAccount();
  account.incomingServer = MailServices.accounts.createIncomingServer(
    "item99import",
    "import.example",
    "pop3"
  );
  identity = MailServices.accounts.createIdentity();
  identity.email = ALICE_ADDRESS;
  account.addIdentity(identity);
  registerCleanupFunction(() =>
    MailServices.accounts.removeAccount(account, true)
  );

  await OpenPGPTestUtils.initOpenPGP();
  EnigmailKeyRing.clearCache();

  await SpecialPowers.pushPrefEnv({
    set: [["mail.openpgp.alias_rules_file", "browser-item99-rules.json"]],
  });
  registerCleanupFunction(() => OpenPGPAlias._clear());
});

/**
 * A key block produced the way a setup message produces one.
 *
 * The builder is used rather than a fixture, so what is adopted is the same
 * shape a receiver gets from Item 98 -- including the armour headers, which is
 * where the preference lives.
 *
 * @returns {Promise<string>} The armoured secret key, decrypted from a message.
 */
async function keyBlockFromAMessage() {
  // Alice's key, protected, imported so it can be exported again.
  await OpenPGPTestUtils.importPrivateKey(
    window,
    new FileUtils.File(getTestFilePath(ALICE_SECRET_WITH_PP)),
    OpenPGPTestUtils.ACCEPTANCE_PERSONAL,
    "alice-passphrase",
    true
  );
  EnigmailKeyRing.clearCache();

  const keyBlock = RNP.exportSecretKeyForTransfer(ALICE_FPR, "mutual");
  Assert.ok(keyBlock, "the key exports");

  const message = AutocryptSetup.buildMessage({
    address: ALICE_ADDRESS,
    setupCode: "1234-5678-9012-3456-7890-1234-5678-9012-3456",
    keyBlock,
    preferEncrypt: "mutual",
  });
  const boundary = /boundary="([^"]+)"/.exec(message)[1];
  const marker = /^Autocrypt-Setup-Message:.*$/m.exec(message)[0];
  const classified = AutocryptSetup.classify(
    `${marker}\r\n${message.split(`--${boundary}`)[2]}`
  );
  const unwrapped = await AutocryptSetup.unwrap(
    classified.armour,
    "1234-5678-9012-3456-7890-1234-5678-9012-3456"
  );
  Assert.equal(unwrapped.state, "ok", "the message yields a key block");
  return unwrapped.keyBlock;
}

/**
 * Adopting the key: the identity names it, it is personal, and the rule is
 * written.
 *
 * Each part is the answer to "what does import mean" that the specification
 * leaves to the implementation.
 */
add_task(async function adoptingSetsTheIdentity() {
  const keyBlock = await keyBlockFromAMessage();

  const result = await AutocryptSetup.adopt({
    keyBlock,
    address: ALICE_ADDRESS,
    preferEncrypt: "mutual",
    identity,
    // The key inside the block is protected by its own passphrase, which is a
    // different secret from the setup code that opened the message. Supplying
    // it here is what a real import does with the prompt's answer; leaving it
    // out means an empty callback and an import that fails later at signing,
    // which is how the first version of this timed out.
    passphraseCallback: () => "alice-passphrase",
  });
  info(`FINDING adopt: ${JSON.stringify(result)}`);
  Assert.ok(result.ok, `the key was adopted: ${result.error ?? ""}`);
  Assert.equal(
    result.fingerprint.toUpperCase(),
    ALICE_FPR,
    "the expected key was imported"
  );

  const key = EnigmailKeyRing.getKeyById(`0x${ALICE_FPR}`);
  Assert.ok(key, "the key is in the ring");
  Assert.equal(
    identity.getUnicharAttribute("openpgp_key_id"),
    key.keyId,
    "and the identity names it, which is what makes it usable for sending"
  );

  Assert.ok(
    await PgpSqliteDb2.isAcceptedAsPersonalKey(key.fpr),
    "it is marked as the user's own, so the composer offers it"
  );

  // The preference, as a rule -- the D17 boundary: behaviour belongs there.
  const rule = OpenPGPAlias.getRuleForEmail(ALICE_ADDRESS);
  info(`FINDING rule: ${JSON.stringify(rule)}`);
  Assert.ok(rule, "a rule carries the preference");
  Assert.equal(rule.encrypt, 2, "encrypt always, for mutual");
  Assert.deepEqual(rule.keys, [{ fingerprint: ALICE_FPR }], "naming the key");
});

/**
 * And the key is usable: it can decrypt, which is what the identity needs.
 *
 * Asserting the attributes could pass while the key itself was unusable -- a
 * public-only import, a revoked key, a fingerprint mismatch -- so the check is
 * an operation. Decryption is used rather than signing because `encryptAndOrSign`
 * takes a shape of arguments that this test would be guessing at, and the
 * property under test is that the secret material arrived intact.
 */
add_task(async function theAdoptedKeyHasItsSecretMaterial() {
  const key = EnigmailKeyRing.getKeyById(`0x${ALICE_FPR}`);
  Assert.ok(key?.secretAvailable, "the adopted key has its secret part");
  Assert.ok(
    key.subKeys.some(sub => sub.secretAvailable),
    "and at least one secret subkey, which is what a message is encrypted to"
  );

  // The key the identity names is the key that was imported, not merely one
  // with a matching address: a mismatch here would make every message
  // undecryptable with no visible cause.
  Assert.equal(
    identity.getUnicharAttribute("openpgp_key_id"),
    key.keyId,
    "and the identity names that key"
  );
});
