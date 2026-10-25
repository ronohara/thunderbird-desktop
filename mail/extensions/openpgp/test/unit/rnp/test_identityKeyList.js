/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 65: an ordered key list per identity, with a visible preference.
 *
 * The claim under test is that the order the user sets is the order the engine
 * reads, and that a key which cannot be used is passed over rather than
 * promoted or substituted. Two properties matter more than the rest:
 *
 *   - an existing `openpgp_key_id` survives as a one-element list, because a
 *     migration that dropped it would take away the key a profile is using;
 *   - `openpgp_key_id` keeps naming the first entry, so the two dozen readers
 *     that know about only one key keep being right.
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
const {
  getKeyList,
  setKeyList,
  firstUsableKey,
  usableKeys,
  isUsableForKey,
  moveKey,
  addKey,
  removeKey,
  LIST_ATTR,
  PRIMARY_ATTR,
} = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/identityKeys.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();
});

/**
 * @param {string} email
 * @returns {nsIMsgIdentity} A fresh identity, removed with the account.
 */
function makeIdentity(email) {
  const account = MailServices.accounts.createAccount();
  const identity = MailServices.accounts.createIdentity();
  identity.email = email;
  account.addIdentity(identity);
  return identity;
}

/**
 * Generates a key the internal engine holds and accepts it as personal.
 *
 * @param {string} userId
 * @returns {Promise<object>} The EnigmailKey.
 */
async function generateKey(userId) {
  const pass = await OpenPGPMasterpass.retrieveOpenPGPPassword();
  const keyId = await RNP.genKey(userId, "ECC", 0, 0, pass);
  Assert.ok(keyId, `genKey() should return a key ID for ${userId}`);
  EnigmailKeyRing.clearCache();
  const key = EnigmailKeyRing.getKeyById(keyId);
  Assert.ok(key, "the generated key is in the keyring");
  return key;
}

/**
 * An identity with no key at all reports an empty list rather than a list
 * holding an empty string, so a caller can test `length` and mean it.
 */
add_task(async function testEmptyIdentityHasNoKeys() {
  const identity = makeIdentity("none@example.com");
  Assert.deepEqual(getKeyList(identity), [], "no keys, and no placeholder");

  Assert.equal(
    firstUsableKey(identity, "sign"),
    null,
    "there is no key to select"
  );
});

/**
 * The migration: an identity that predates the list keeps its key.
 */
add_task(async function testLegacyKeyBecomesAOneElementList() {
  const key = await generateKey("Legacy <legacy@example.com>");
  const identity = makeIdentity("legacy@example.com");

  // The old world: only the single attribute, holding a key ID.
  identity.setUnicharAttribute(PRIMARY_ATTR, key.keyId);
  Assert.equal(
    identity.getUnicharAttribute(LIST_ATTR),
    "",
    "the list attribute is unset, as it is on an existing profile"
  );

  const list = getKeyList(identity);
  Assert.equal(list.length, 1, "the legacy key becomes a one-element list");
  Assert.equal(
    list[0],
    key.fpr.toUpperCase(),
    "and it is resolved to a fingerprint, so the two forms agree"
  );

  // Reading must not write: a preference changed by opening a composer would
  // be a surprise, and a profile that is only read should stay untouched.
  Assert.equal(
    identity.getUnicharAttribute(LIST_ATTR),
    "",
    "reading the list does not write one"
  );
});

/**
 * Both attributes, kept in step. This is what lets every existing reader of
 * `openpgp_key_id` keep working.
 */
add_task(async function testThePrimaryAttributeFollowsTheList() {
  const first = await generateKey("First <first@example.com>");
  const second = await generateKey("Second <second@example.com>");
  const identity = makeIdentity("order@example.com");

  setKeyList(identity, [first.fpr, second.fpr]);
  Assert.deepEqual(
    getKeyList(identity),
    [first.fpr.toUpperCase(), second.fpr.toUpperCase()],
    "the list is stored in the order given"
  );
  Assert.equal(
    identity.getUnicharAttribute(PRIMARY_ATTR),
    first.keyId.toUpperCase(),
    "openpgp_key_id names the first entry"
  );

  // Reordering rewrites it, because the first entry is what "the identity's
  // key" means everywhere else.
  setKeyList(identity, [second.fpr, first.fpr]);
  Assert.equal(
    identity.getUnicharAttribute(PRIMARY_ATTR),
    second.keyId.toUpperCase(),
    "openpgp_key_id follows the new first entry"
  );

  // And clearing the list clears the single attribute with it, rather than
  // leaving the identity naming a key its list no longer holds.
  setKeyList(identity, []);
  Assert.equal(
    identity.getUnicharAttribute(LIST_ATTR),
    "",
    "the list is empty"
  );
  Assert.equal(
    identity.getUnicharAttribute(PRIMARY_ATTR),
    "",
    "and openpgp_key_id is cleared too"
  );
});

/**
 * The selection rule: first entry wins, and the order is the user's.
 */
add_task(async function testFirstEntryWins() {
  const alpha = await generateKey("Alpha <alpha@example.com>");
  const beta = await generateKey("Beta <beta@example.com>");
  const identity = makeIdentity("pick@example.com");

  setKeyList(identity, [alpha.fpr, beta.fpr]);
  Assert.equal(
    firstUsableKey(identity, "sign").fpr,
    alpha.fpr,
    "the first entry signs"
  );

  setKeyList(identity, [beta.fpr, alpha.fpr]);
  Assert.equal(
    firstUsableKey(identity, "sign").fpr,
    beta.fpr,
    "and swapping the order swaps the signer"
  );

  // Both are usable, so the choice is purely the order. An engine that ranked
  // by creation time would answer the same here by accident, so this asserts
  // the list order is what did it: the newer key is second in the first case.
  const newer = alpha.keyCreated > beta.keyCreated ? alpha : beta;
  const older = newer === alpha ? beta : alpha;
  setKeyList(identity, [older.fpr, newer.fpr]);
  Assert.equal(
    firstUsableKey(identity, "sign").fpr,
    older.fpr,
    "an older key listed first still signs; nothing ranks by age"
  );
});

/**
 * An entry that cannot be used is passed over -- and passing over is not
 * ranking: the remaining entries keep the user's order.
 */
add_task(async function testUnusableEntriesArePassedOver() {
  const good = await generateKey("Good <good@example.com>");
  const other = await generateKey("Other <other@example.com>");
  const identity = makeIdentity("skip@example.com");

  // An entry that names no key at all: a fingerprint that was deleted, or one
  // belonging to another profile.
  setKeyList(identity, ["0".repeat(40), good.fpr, other.fpr]);
  Assert.equal(
    firstUsableKey(identity, "sign").fpr,
    good.fpr,
    "a missing key is skipped rather than returned"
  );

  Assert.deepEqual(
    usableKeys(identity, "sign").map(k => k.fpr),
    [good.fpr, other.fpr],
    "the usable set keeps the user's order once the missing entry is gone"
  );

  // A public-only key has no secret material, so it cannot sign. This is the
  // case a chooser listing everything would offer and the send would refuse.
  const publicOnly = EnigmailKeyRing.getKeyById("0xF231550C4F47E38E");
  if (publicOnly) {
    Assert.equal(
      isUsableForKey(publicOnly, "sign"),
      false,
      "a key without secret material cannot sign"
    );
  }
});

/**
 * Moving, adding and removing, all of which have to preserve uniqueness.
 */
add_task(async function testOrderEditing() {
  const one = await generateKey("One <one@example.com>");
  const two = await generateKey("Two <two@example.com>");
  const identity = makeIdentity("edit@example.com");

  setKeyList(identity, [one.fpr, two.fpr]);

  Assert.ok(moveKey(identity, two.fpr, -1), "moving up succeeds");
  Assert.deepEqual(
    getKeyList(identity),
    [two.fpr.toUpperCase(), one.fpr.toUpperCase()],
    "the order changed"
  );

  Assert.equal(
    moveKey(identity, two.fpr, -1),
    false,
    "moving the first entry up does nothing"
  );
  Assert.deepEqual(
    getKeyList(identity),
    [two.fpr.toUpperCase(), one.fpr.toUpperCase()],
    "and leaves the order alone"
  );

  // Adding appends: adding a key is not a statement that it should be
  // preferred, and a list that reordered itself would make the preference
  // unreliable. The key is removed first so that the add is a real transition
  // rather than a no-op dressed as one.
  Assert.ok(removeKey(identity, one.fpr), "a listed key is removed");
  Assert.deepEqual(
    getKeyList(identity),
    [two.fpr.toUpperCase()],
    "leaving the other one in place"
  );

  Assert.ok(addKey(identity, one.fpr), "the key is added back");
  Assert.deepEqual(
    getKeyList(identity),
    [two.fpr.toUpperCase(), one.fpr.toUpperCase()],
    "and it is appended, not promoted to the front"
  );
  Assert.equal(
    addKey(identity, one.fpr),
    false,
    "adding a key that is already there does nothing"
  );

  // Duplicates are collapsed, so an order cannot be made ambiguous by a
  // repeated entry.
  setKeyList(identity, [one.fpr, one.fpr, two.fpr]);
  Assert.deepEqual(
    getKeyList(identity),
    [one.fpr.toUpperCase(), two.fpr.toUpperCase()],
    "a repeated entry is stored once"
  );

  Assert.ok(removeKey(identity, one.fpr), "a listed key is removed");
  Assert.deepEqual(
    getKeyList(identity),
    [two.fpr.toUpperCase()],
    "and the rest keep their order"
  );
  Assert.equal(
    removeKey(identity, one.fpr),
    false,
    "removing a key that is not listed does nothing"
  );

  // Removing the first entry promotes the next one, in both attributes.
  Assert.equal(
    identity.getUnicharAttribute(PRIMARY_ATTR),
    two.keyId.toUpperCase(),
    "openpgp_key_id follows the promotion"
  );
});

/**
 * Key IDs and fingerprints are accepted interchangeably, because every
 * existing writer of `openpgp_key_id` deals in key IDs and this is the
 * compatibility seam they pass through.
 */
add_task(async function testKeyIdsAreResolved() {
  const key = await generateKey("Ids <ids@example.com>");
  const identity = makeIdentity("ids@example.com");

  setKeyList(identity, [key.keyId]);
  Assert.deepEqual(
    getKeyList(identity),
    [key.fpr.toUpperCase()],
    "a key ID is stored as the fingerprint it names"
  );

  // A comma-separated value is accepted too, so a hand-edited preference does
  // not have to know which separator the code chose.
  identity.setUnicharAttribute(LIST_ATTR, `${key.fpr.toLowerCase()}, `);
  Assert.deepEqual(
    getKeyList(identity),
    [key.fpr.toUpperCase()],
    "a comma-separated preference parses"
  );
});
