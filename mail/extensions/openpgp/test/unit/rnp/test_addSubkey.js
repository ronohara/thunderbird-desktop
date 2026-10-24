/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 61: a general add-subkey path, and expiry per subkey.
 *
 * Item 60 gives a generated key the structure GnuPG generates -- a certify-only
 * primary with a signing subkey and an encryption subkey -- but that structure
 * was created once and never renewed. Rotation needs two things, and these
 * tests are about both: adding a subkey to a live key (which RNP refused for a
 * certify-only primary before Item 60's patch), and giving the new subkey its
 * own expiration so the old one can be retired later rather than at the same
 * moment.
 *
 * The property under test is not "a subkey appears". It is that the key
 * survives the operation with its identity intact: the primary keeps its
 * fingerprint, its certification ability and its passphrase, and the subkeys
 * that were already there keep the usage and expiry they had.
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
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";

const DAY = 24 * 60 * 60;

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();
});

/**
 * Reads a key back out of the keyring, bypassing the cache.
 *
 * @param {string} keyId
 * @returns {object} The EnigmailKey object.
 */
function reloadKey(keyId) {
  EnigmailKeyRing.clearCache();
  const key = EnigmailKeyRing.getKeyById(keyId);
  Assert.ok(key, `key ${keyId} is in the keyring`);
  return key;
}

/**
 * @param {object} key An EnigmailKey.
 * @param {string} usageChar "s" or "e".
 * @returns {object[]} Subkeys carrying that usage.
 */
function subkeysWithUsage(key, usageChar) {
  return key.subKeys.filter(sk => sk.keyUseFor.includes(usageChar));
}

async function generateKey(userId, keyType) {
  const pass = await OpenPGPMasterpass.retrieveOpenPGPPassword();
  const keyId = await RNP.genKey(userId, keyType, 0, 0, pass);
  Assert.ok(keyId, `genKey() should return a key ID for ${userId}`);
  return keyId;
}

/**
 * A signing subkey can be added to a generated key, and nothing that was
 * already there changes.
 */
add_task(async function testAddSigningSubkey() {
  const keyId = await generateKey("Signer <signer@example.com>", "ECC");
  const before = reloadKey(keyId);

  Assert.equal(before.subKeys.length, 2, "the key starts with two subkeys");
  const primaryFpr = before.fpr;
  const originalSigning = subkeysWithUsage(before, "s")[0].fpr;
  Assert.ok(originalSigning, "there is a signing subkey to begin with");

  const added = await RNP.addSubkey(primaryFpr, {
    usage: "sign",
    expirySeconds: 100 * DAY,
  });
  Assert.ok(added, "addSubkey() should add a signing subkey");

  const after = reloadKey(keyId);

  // The identity is untouched: same fingerprint, still certifying, still not
  // signing. If any of this moved, rotation would have replaced the key rather
  // than renewed part of it.
  Assert.equal(after.fpr, primaryFpr, "the primary fingerprint is unchanged");
  Assert.ok(
    after.keyUseFor.includes("c"),
    `the primary still certifies, usage "${after.keyUseFor}"`
  );
  Assert.ok(
    !after.keyUseFor.includes("s"),
    `the primary still must not sign, usage "${after.keyUseFor}"`
  );

  Assert.equal(after.subKeys.length, 3, "the key now has three subkeys");
  Assert.equal(
    subkeysWithUsage(after, "s").length,
    2,
    "two subkeys can sign, the old one and the new one"
  );

  const newSigning = subkeysWithUsage(after, "s").find(
    sk => sk.fpr != originalSigning
  );
  Assert.ok(newSigning, "the new signing subkey is present");
  Assert.ok(
    !newSigning.keyUseFor.includes("e"),
    `the new signing subkey cannot encrypt, usage "${newSigning.keyUseFor}"`
  );
  Assert.equal(
    after.subKeys.find(sk => sk.fpr == originalSigning).keyUseFor,
    before.subKeys.find(sk => sk.fpr == originalSigning).keyUseFor,
    "the subkey that was already there keeps its usage"
  );
});

/**
 * An encryption subkey can be added to the same key, so one unmodified key
 * ends up carrying both kinds of replacement.
 */
add_task(async function testAddEncryptionSubkey() {
  const keyId = await generateKey("Encryptor <encryptor@example.com>", "ECC");
  const before = reloadKey(keyId);
  const primaryFpr = before.fpr;

  const added = await RNP.addSubkey(primaryFpr, {
    usage: "encrypt",
    expirySeconds: 200 * DAY,
  });
  Assert.ok(added, "addSubkey() should add an encryption subkey");

  const after = reloadKey(keyId);
  Assert.equal(after.fpr, primaryFpr, "the primary fingerprint is unchanged");
  Assert.equal(after.subKeys.length, 3, "the key now has three subkeys");
  Assert.equal(
    subkeysWithUsage(after, "e").length,
    2,
    "two subkeys can encrypt"
  );

  const newEncrypting = subkeysWithUsage(after, "e").find(
    sk => !before.subKeys.some(old => old.fpr == sk.fpr)
  );
  Assert.ok(newEncrypting, "the new encryption subkey is present");
  Assert.ok(
    !newEncrypting.keyUseFor.includes("s"),
    `the new encryption subkey cannot sign, usage "${newEncrypting.keyUseFor}"`
  );
});

/**
 * The point of the item: each subkey carries its own expiration.
 *
 * This is what makes rotation staggered rather than simultaneous. The old
 * signing subkey here never expires (the generated key was made that way), so
 * if the new subkey inherited anything rather than taking the value it was
 * given, the two would be indistinguishable.
 */
add_task(async function testExpiryIsPerSubkey() {
  const keyId = await generateKey("Rotator <rotator@example.com>", "ECC");
  const before = reloadKey(keyId);
  const primaryFpr = before.fpr;
  const oldSigning = subkeysWithUsage(before, "s")[0];

  const expirySeconds = 100 * DAY;
  const added = await RNP.addSubkey(primaryFpr, {
    usage: "sign",
    expirySeconds,
  });
  Assert.ok(added, "addSubkey() should add a signing subkey");

  const after = reloadKey(keyId);
  const newSigning = subkeysWithUsage(after, "s").find(
    sk => sk.fpr != oldSigning.fpr
  );
  Assert.ok(newSigning, "the new signing subkey is present");

  Assert.equal(
    oldSigning.expiryTime,
    0,
    "the subkey that was already there still never expires"
  );
  Assert.notEqual(
    newSigning.expiryTime,
    0,
    "the new subkey expires, rather than inheriting 'never'"
  );

  // Its expiry is measured from its own creation, which is the PGP rule, so
  // the expectation is built the same way rather than from "now".
  const expected = newSigning.keyCreated + expirySeconds;
  Assert.equal(
    newSigning.expiryTime,
    expected,
    `the new subkey expires ${expirySeconds / DAY} days after it was created`
  );

  // And the difference between the two is the whole staggering, so assert it
  // is a real interval and not accidental equality.
  Assert.greater(
    newSigning.expiryTime - oldSigning.expiryTime,
    10 * DAY,
    "the two signing subkeys expire at clearly different times"
  );
});

/**
 * An RSA primary yields RSA subkeys at the primary's own size.
 */
add_task(async function testRsaPrimary() {
  const keyId = await generateKey("RsaUser <rsa@example.com>", "RSA");
  const before = reloadKey(keyId);
  const primaryFpr = before.fpr;

  const added = await RNP.addSubkey(primaryFpr, {
    usage: "sign",
    expirySeconds: 0,
  });
  Assert.ok(added, "addSubkey() should add a signing subkey to an RSA key");

  const after = reloadKey(keyId);
  const newSigning = subkeysWithUsage(after, "s").find(
    sk => !before.subKeys.some(old => old.fpr == sk.fpr)
  );
  Assert.ok(newSigning, "the new signing subkey is present");
  Assert.equal(
    newSigning.algoSym,
    "RSA",
    `the new subkey is RSA, got "${newSigning.algoSym}"`
  );
  Assert.equal(
    newSigning.keySize,
    before.keySize,
    "the new subkey uses the primary's key size"
  );
  Assert.ok(
    !newSigning.keyUseFor.includes("e"),
    `it cannot encrypt, usage "${newSigning.keyUseFor}"`
  );
});

/**
 * The refusals. A public key cannot sign a binding for a new subkey, and an
 * unknown fingerprint is not an error -- the UI asks about keys it may not
 * hold, and false is the answer that keeps the button hidden.
 */
add_task(async function testRefusals() {
  await OpenPGPTestUtils.importPublicKey(
    null,
    do_get_file(`${keyDir}/alice@openpgp.example-0xf231550c4f47e38e-pub.asc`)
  );

  EnigmailKeyRing.clearCache();
  const publicKey = EnigmailKeyRing.getKeyById("0xF231550C4F47E38E");
  Assert.ok(publicKey, "the public key is in the keyring");

  Assert.equal(
    RNP.canAddSubkeyByFpr(publicKey.fpr),
    false,
    "a public key cannot gain a subkey"
  );

  const added = await RNP.addSubkey(publicKey.fpr, {
    usage: "sign",
    expirySeconds: 0,
  });
  Assert.equal(added, false, "addSubkey() refuses a key without its secret");

  Assert.equal(
    RNP.canAddSubkeyByFpr("0".repeat(40)),
    false,
    "an unknown fingerprint is refused rather than throwing"
  );
  Assert.equal(
    await RNP.addSubkey("0".repeat(40), { usage: "sign", expirySeconds: 0 }),
    false,
    "addSubkey() refuses an unknown fingerprint rather than throwing"
  );

  const keyId = await generateKey("ArgCheck <args@example.com>", "ECC");
  const key = reloadKey(keyId);

  await Assert.rejects(
    RNP.addSubkey(key.fpr, { usage: "certify", expirySeconds: 0 }),
    /invalid subkey usage/,
    "an unsupported usage is a programming error, not a silent false"
  );
  await Assert.rejects(
    RNP.addSubkey(key.fpr, { usage: "sign", expirySeconds: -1 }),
    /invalid expirySeconds/,
    "a negative expiry is a programming error"
  );
  await Assert.rejects(
    RNP.addSubkey(key.fpr, { usage: "sign", expirySeconds: 1.5 }),
    /invalid expirySeconds/,
    "a fractional expiry is a programming error"
  );

  // Nothing was added by any of the refused calls.
  EnigmailKeyRing.clearCache();
  const unchanged = EnigmailKeyRing.getKeyById(keyId);
  Assert.equal(
    unchanged.subKeys.length,
    2,
    "the refusals left the key's structure alone"
  );
});
