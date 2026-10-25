/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 69: adding a user ID, and changing which one is primary.
 *
 * The item's own words for why this matters: "a second address cannot
 * currently be added to a key from inside Thunderbird at all". These tests
 * assert that it can now, and — the item's own verification requirement —
 * *"that adding a user ID re-signs the key correctly"*, because an unsigned
 * new user ID is worse than no user ID.
 *
 * "Signed correctly" is checked from the outside: a user ID only appears in a
 * key's listing if it carries a self-certification, so counting the user IDs
 * the keyring reports after the add is what proves the binding was signed and
 * saved rather than merely created.
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

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();
});

/**
 * @param {string} userId
 * @returns {Promise<object>} The generated key, from the keyring.
 */
async function generateKey(userId) {
  const pass = await OpenPGPMasterpass.retrieveOpenPGPPassword();
  const keyId = await RNP.genKey(userId, "ECC", 0, 0, pass);
  Assert.ok(keyId, `genKey() produced a key for ${userId}`);
  EnigmailKeyRing.clearCache();
  const key = EnigmailKeyRing.getKeyById(keyId);
  Assert.ok(key, "the generated key is in the keyring");
  return key;
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
 * The user ID strings a key carries.
 *
 * @param {object} key
 * @returns {string[]}
 */
function userIdsOf(key) {
  return key.userIds.filter(uid => uid.type === "uid").map(uid => uid.userId);
}

/**
 * The item's central claim: a second address can be added, and the binding is
 * signed.
 *
 * The signature is what makes it real. `rnp_key_add_uid` signs in the same
 * call, and a user ID without a self-certification would either not be listed
 * or not be usable -- so the assertion is on the key as re-read from the
 * keyring, not on the call's return value.
 */
add_task(async function aSecondUserIdCanBeAdded() {
  const key = await generateKey("First <first@example.com>");

  const before = userIdsOf(reload(key.fpr));
  Assert.equal(before.length, 1, "the key starts with one user ID");

  const added = await RNP.addUserId(key.fpr, "Second <second@example.com>");
  Assert.ok(added, "addUserId() should succeed");

  const after = userIdsOf(reload(key.fpr));
  Assert.equal(after.length, 2, "the key now carries two user IDs");
  Assert.ok(
    after.some(uid => uid.includes("second@example.com")),
    `the new address must be there, got ${JSON.stringify(after)}`
  );
  Assert.ok(
    after.some(uid => uid.includes("first@example.com")),
    "and the original must still be there"
  );
});

/**
 * `makePrimary` asks for the new user ID to become the key's primary one in
 * the same call, which is the behaviour `rnp_key_add_uid` exists to provide.
 */
add_task(async function aNewUserIdCanBeMadePrimary() {
  const key = await generateKey("Original <original@example.com>");

  const added = await RNP.addUserId(
    key.fpr,
    "Preferred <preferred@example.com>",
    { makePrimary: true }
  );
  Assert.ok(added, "addUserId() with makePrimary should succeed");

  const reread = reload(key.fpr);
  Assert.ok(
    reread.userId.includes("preferred@example.com"),
    `the new user ID should be primary, key reports "${reread.userId}"`
  );
});

/**
 * Changing the primary user ID afterwards.
 *
 * The sequence is create an editable certification, set the flag, sign it --
 * and a caller that stopped after setting the flag would see success and no
 * change. Asserted through the key's reported primary, which only moves if the
 * signature was applied.
 */
add_task(async function thePrimaryUserIdCanBeChanged() {
  const key = await generateKey("Stays <stays@example.com>");
  await RNP.addUserId(key.fpr, "Moves <moves@example.com>");
  Assert.ok(
    reload(key.fpr).userId.includes("stays@example.com"),
    "the original is primary before the change"
  );

  const changed = await RNP.setPrimaryUserId(
    key.fpr,
    "Moves <moves@example.com>"
  );
  Assert.ok(changed, "setPrimaryUserId() should succeed");

  Assert.ok(
    reload(key.fpr).userId.includes("moves@example.com"),
    "the chosen user ID should now be primary"
  );
});

/**
 * A user ID is matched by address as well as by its whole text, because
 * callers commonly have one and not the other.
 */
add_task(async function aUserIdIsFoundByItsAddress() {
  const key = await generateKey("Addressed <addressed@example.com>");
  await RNP.addUserId(key.fpr, "Other <other@example.com>");

  const ok = await RNP.setPrimaryUserId(key.fpr, "other@example.com");
  Assert.ok(ok, "an address alone should identify the user ID to change");
  Assert.ok(
    reload(key.fpr).userId.includes("other@example.com"),
    "and the change should have been applied to it"
  );
});

/**
 * The refusals. A malformed user ID is refused before anything is signed,
 * because the library would accept almost any string and the result would
 * match no address at all.
 */
add_task(async function malformedUserIdsAreRefused() {
  const key = await generateKey("Refusing <refusing@example.com>");

  for (const bad of ["no address here", "Name <not-an-address>", "  "]) {
    await Assert.rejects(
      RNP.addUserId(key.fpr, bad),
      /invalid user ID/,
      `"${bad}" should be refused rather than written`
    );
  }

  Assert.equal(
    userIdsOf(reload(key.fpr)).length,
    1,
    "and the refusals must not have added anything"
  );

  // A key this profile has no secret material for cannot sign a binding.
  const exported = reload(key.fpr);
  Assert.ok(exported, "the key is present for the next check");
  await PgpSqliteDb2.acceptAsPersonalKey(key.fpr);
  Assert.ok(
    !(await RNP.addUserId("0".repeat(40), "X <x@example.com>")),
    "an unknown key is refused rather than throwing"
  );
});
