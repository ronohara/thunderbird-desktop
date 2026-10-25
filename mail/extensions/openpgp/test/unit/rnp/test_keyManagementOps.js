/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 70: operations that were already bound and had no way to be reached.
 *
 * Subkey revocation worked end to end in `revokeKey()` but was offered only on
 * whole keys, and `rnp_uid_remove` was reachable only from a public-export
 * helper. Neither needed new library work; both needed a path.
 *
 * The property under test throughout is *scope*: revoking a subkey must leave
 * the primary and its sibling subkey alone, and removing a user ID must leave
 * the others in place. Both are irreversible, so the tests assert the
 * collateral as carefully as the effect.
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

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();
});

/**
 * @param {string} userId
 * @returns {Promise<object>} A generated key, from the keyring.
 */
async function generateKey(userId) {
  const pass = await OpenPGPMasterpass.retrieveOpenPGPPassword();
  const keyId = await RNP.genKey(userId, "ECC", 0, 0, pass);
  Assert.ok(keyId, `genKey() produced a key for ${userId}`);
  EnigmailKeyRing.clearCache();
  return EnigmailKeyRing.getKeyById(keyId);
}

/**
 * @param {string} fpr
 * @returns {object} The key, re-read so a change is visible.
 */
function reload(fpr) {
  EnigmailKeyRing.clearCache();
  return EnigmailKeyRing.getKeyById(fpr);
}

/**
 * Whether a key or subkey is revoked, read from its primary's listing.
 *
 * A subkey is not addressable through `getKeyById()` in the way a primary is,
 * so its state is read from the parent that carries it -- which is also how the
 * UI sees it, and therefore the right thing to assert.
 *
 * @param {string} primaryFpr
 * @param {?string} subkeyFpr - Null to ask about the primary itself.
 * @returns {boolean}
 */
function isRevoked(primaryFpr, subkeyFpr = null) {
  const primary = reload(primaryFpr);
  Assert.ok(primary, `key ${primaryFpr} should still be in the keyring`);
  if (!subkeyFpr) {
    return primary.keyTrust == "r";
  }
  const subkey = primary.subKeys.find(sk => sk.fpr == subkeyFpr);
  Assert.ok(subkey, `subkey ${subkeyFpr} should still be listed`);
  return subkey.keyTrust == "r";
}

/**
 * Revoking one subkey leaves the primary and its sibling alone.
 *
 * That is the whole of Item 70's first half: the Key Manager could revoke a
 * key, and revoking a subkey meant revoking everything or using GnuPG.
 */
add_task(async function revokingASubkeyLeavesTheRestAlone() {
  const key = await generateKey("Subkey Owner <subkey@example.com>");
  const signing = key.subKeys.find(sk => sk.keyUseFor.includes("s"));
  const encrypting = key.subKeys.find(sk => sk.keyUseFor.includes("e"));
  Assert.ok(signing && encrypting, "the key has a signing and an encrypting subkey");

  const revoked = await RNP.revokeSubkey(signing.fpr);
  Assert.ok(revoked, "revokeSubkey() should succeed");

  Assert.ok(
    isRevoked(key.fpr, signing.fpr),
    "the chosen subkey must be revoked"
  );

  // The collateral. A revocation that took the whole key with it would pass
  // the assertion above and fail the user completely.
  Assert.notEqual(
    reload(key.fpr).keyTrust,
    "r",
    "the primary key must not be revoked"
  );
  Assert.ok(
    !isRevoked(key.fpr, encrypting.fpr),
    "and the other subkey must not be revoked"
  );
});

/**
 * The guard against using it on a primary key.
 *
 * `revokeSubkey()` is called from a list where row 0 is the primary, so a
 * mis-indexed selection is a realistic mistake and would revoke the whole key.
 */
add_task(async function revokingAPrimaryThroughTheSubkeyPathIsRefused() {
  const key = await generateKey("Not A Subkey <notasubkey@example.com>");

  Assert.equal(
    await RNP.revokeSubkey(key.fpr),
    false,
    "a primary fingerprint must be refused rather than revoked"
  );
  Assert.notEqual(
    reload(key.fpr).keyTrust,
    "r",
    "and the key must still be intact"
  );
});

/**
 * Removing a user ID removes that one and leaves the rest.
 */
add_task(async function removingAUserIdLeavesTheOthersAlone() {
  const key = await generateKey("Keep <keep@example.com>");
  await RNP.addUserId(key.fpr, "Drop <drop@example.com>");

  const before = reload(key.fpr);
  Assert.equal(
    before.userIds.filter(uid => uid.type === "uid").length,
    2,
    "two user IDs to begin with"
  );

  const removed = await RNP.removeUserId(key.fpr, "drop@example.com");
  Assert.ok(removed, "removeUserId() should succeed");

  const after = reload(key.fpr);
  const ids = after.userIds.filter(uid => uid.type === "uid").map(u => u.userId);
  Assert.equal(ids.length, 1, "one user ID should remain");
  Assert.ok(
    ids[0].includes("keep@example.com"),
    `and it should be the one not removed, got ${JSON.stringify(ids)}`
  );
});

/**
 * A user ID that is not there is refused rather than silently doing nothing,
 * and the key must be left exactly as it was.
 */
add_task(async function removingAnAbsentUserIdChangesNothing() {
  const key = await generateKey("Intact <intact@example.com>");

  Assert.equal(
    await RNP.removeUserId(key.fpr, "absent@example.com"),
    false,
    "an absent user ID is refused"
  );
  Assert.equal(
    reload(key.fpr).userIds.filter(uid => uid.type === "uid").length,
    1,
    "and nothing was removed"
  );

  // And an unknown key is refused rather than throwing.
  Assert.equal(
    await RNP.removeUserId("0".repeat(40), "x@example.com"),
    false,
    "an unknown key is refused"
  );
});
