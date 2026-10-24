/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 62: name the subkey, and report the one used.
 *
 * Since Item 60 a generated key has a signing subkey, and since Item 61 a
 * second one can be added. That makes the selection a decision rather than a
 * detail: the engine picks the newest usable signing subkey, and a user who
 * rotated a subkey has no way to see that the new one is the one in use --
 * or to say otherwise. These tests are about both halves: honouring a named
 * subkey, and reporting the one that actually signed.
 *
 * The refusal is tested as hard as the selection, because it is the part that
 * protects the user. Substituting a different signing key when the named one
 * is unusable is the failure mode this mechanism exists to prevent.
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
const { EnigmailEncryption } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/encryption.sys.mjs"
);
const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);
const { EnigmailConstants } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/constants.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";

const DAY = 24 * 60 * 60;

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();

  await OpenPGPTestUtils.importPublicKey(
    null,
    do_get_file(`${keyDir}/alice@openpgp.example-0xf231550c4f47e38e-pub.asc`)
  );
});

/**
 * Generate a key the internal engine holds, and accept it as personal so the
 * send path will use it.
 *
 * @param {string} userId
 * @returns {Promise<object>} The EnigmailKey, reloaded from the keyring.
 */
async function generateSender(userId) {
  const pass = await OpenPGPMasterpass.retrieveOpenPGPPassword();
  const keyId = await RNP.genKey(userId, "ECC", 0, 0, pass);
  Assert.ok(keyId, `genKey() should return a key ID for ${userId}`);

  EnigmailKeyRing.clearCache();
  const key = EnigmailKeyRing.getKeyById(keyId);
  Assert.ok(key, "the generated key is in the keyring");
  await PgpSqliteDb2.updateAcceptance(key.fpr, null, "personal");
  return key;
}

/**
 * Sign and encrypt a short message from the given key to Alice.
 *
 * @param {string} senderFpr - Fingerprint of the sender's primary key.
 * @param {string} [signingSubkeyFpr] - A named signing subkey, if any.
 * @param {object} resultStatus - Out parameter, filled by RNP.
 * @returns {Promise<string>} The signed and encrypted message.
 */
async function signFrom(senderFpr, signingSubkeyFpr, resultStatus) {
  const encryptArgs = {
    aliasKeys: new Map(),
    armor: true,
    bcc: [],
    encrypt: true,
    encryptToSender: false,
    sender: `0x${senderFpr}`,
    senderKeyIsExternal: false,
    sigTypeClear: false,
    sigTypeDetached: false,
    sign: true,
    signatureHash: "SHA256",
    signingSubkeyFpr: signingSubkeyFpr || "",
    to: ["<alice@openpgp.example>"],
  };

  return RNP.encryptAndOrSign("the message body", encryptArgs, resultStatus);
}

/**
 * @param {object} key - An EnigmailKey.
 * @returns {object[]} Subkeys that can sign.
 */
function signingSubkeys(key) {
  return key.subKeys.filter(sk => sk.keyUseFor.includes("s"));
}

/**
 * With nothing named, the newest usable signing subkey signs -- and the
 * subkey is reported rather than the primary, which is the whole point:
 * `gpg --list-packets` names the subkey, and before this the answer was
 * recovered only by guessing.
 */
add_task(async function testAutomaticSelectionIsReported() {
  const key = await generateSender("Auto Signer <auto@example.com>");
  const signers = signingSubkeys(key);
  Assert.equal(signers.length, 1, "the generated key has one signing subkey");

  const resultStatus = {};
  const encrypted = await signFrom(key.fpr, null, resultStatus);
  Assert.ok(encrypted, "the message was signed and encrypted");
  Assert.ok(!resultStatus.exitCode, "the send exited ok");

  Assert.equal(
    resultStatus.senderSigningKeyFpr,
    signers[0].fpr,
    "the signing subkey is reported, not the primary"
  );
  Assert.notEqual(
    resultStatus.senderSigningKeyFpr,
    key.fpr,
    "the certificate key did not sign"
  );
  Assert.equal(
    resultStatus.senderSigningSubkeyNamed,
    "",
    "nothing was named, so nothing is reported as named"
  );
});

/**
 * A named subkey is the one used, even when it is not the newest -- which is
 * the whole difference between this and the automatic rule.
 */
add_task(async function testNamedSubkeyIsUsed() {
  const key = await generateSender("Named Signer <named@example.com>");
  const originalSigner = signingSubkeys(key)[0];

  // Give the key a second signing subkey, so "newest" and "named" disagree.
  const added = await RNP.addSubkey(key.fpr, {
    usage: "sign",
    expirySeconds: 365 * DAY,
  });
  Assert.ok(added, "a second signing subkey was added");

  EnigmailKeyRing.clearCache();
  const withTwo = EnigmailKeyRing.getKeyById(key.keyId);
  const signers = signingSubkeys(withTwo);
  Assert.equal(signers.length, 2, "the key now has two signing subkeys");

  // Name the older one. Automatic selection would take the newer one, so a
  // passing assertion here cannot be the automatic rule in disguise.
  const resultStatus = {};
  const encrypted = await signFrom(
    withTwo.fpr,
    originalSigner.fpr,
    resultStatus
  );
  Assert.ok(
    encrypted,
    "the message was signed and encrypted with the named key"
  );
  Assert.ok(!resultStatus.exitCode, "the send exited ok");

  Assert.equal(
    resultStatus.senderSigningKeyFpr,
    originalSigner.fpr,
    "the named subkey signed, not the newest one"
  );
  Assert.equal(
    resultStatus.senderSigningSubkeyNamed,
    originalSigner.fpr,
    "the message records which subkey was named"
  );
});

/**
 * The named choice reaches the send path. This is the glue that could fail
 * silently -- an attribute written but never read would leave every test above
 * passing while the user's choice did nothing.
 */
add_task(async function testIdentityAttributeReachesTheSendPath() {
  const key = await generateSender("Chosen Signer <chosen@example.com>");
  const signer = signingSubkeys(key)[0];

  const account = MailServices.accounts.createAccount();
  const identity = MailServices.accounts.createIdentity();
  identity.email = "chosen@example.com";
  identity.setUnicharAttribute("openpgp_key_id", key.fpr);
  identity.setUnicharAttribute("openpgp_signing_subkey", signer.fpr);
  account.addIdentity(identity);

  try {
    // By address, which is what the composer passes.
    Assert.equal(
      EnigmailEncryption.namedSigningSubkeyFor("chosen@example.com"),
      signer.fpr,
      "the identity's named subkey is found from the sender address"
    );
    // And by key id, which is what the composer passes when the identity is
    // configured with a key rather than an address.
    Assert.equal(
      EnigmailEncryption.namedSigningSubkeyFor(`0x${key.fpr}`),
      signer.fpr,
      "and from the sender's key id"
    );

    // The argument the send path builds carries it, which is the link that
    // makes the choice take effect.
    const args = EnigmailEncryption.getCryptParams(
      "chosen@example.com",
      "<alice@openpgp.example>",
      "",
      "SHA256",
      EnigmailConstants.SEND_SIGNED | EnigmailConstants.SEND_ENCRYPTED,
      0,
      { value: "" }
    );
    Assert.ok(args, "getCryptParams() built the arguments");
    Assert.equal(
      args.signingSubkeyFpr,
      signer.fpr,
      "the chosen subkey is carried into the send arguments"
    );

    // An identity with no choice is unaffected: the automatic rule still
    // applies, which is what keeps this change inert for existing profiles.
    identity.setUnicharAttribute("openpgp_signing_subkey", "");
    Assert.equal(
      EnigmailEncryption.namedSigningSubkeyFor("chosen@example.com"),
      "",
      "clearing the choice returns to automatic selection"
    );
  } finally {
    MailServices.accounts.removeAccount(account, true);
  }
});

/**
 * A named subkey that cannot be used stops the send. It is not replaced.
 */
add_task(async function testUnusableNamedSubkeyRefuses() {
  const key = await generateSender("Refusing Signer <refuse@example.com>");

  const bogus = "0".repeat(40);
  await Assert.rejects(
    signFrom(key.fpr, bogus, {}),
    /refusing rather than signing with a different key/,
    "a name that matches no subkey must stop the send"
  );

  // And the same for a real fingerprint that is not a signing subkey: the
  // encryption subkey exists, so this is not a missing-key case.
  const encryptionSubkey = key.subKeys.find(sk => sk.keyUseFor.includes("e"));
  Assert.ok(encryptionSubkey, "the key has an encryption subkey");
  await Assert.rejects(
    signFrom(key.fpr, encryptionSubkey.fpr, {}),
    /refusing rather than signing with a different key/,
    "naming a subkey that cannot sign must stop the send"
  );
});
