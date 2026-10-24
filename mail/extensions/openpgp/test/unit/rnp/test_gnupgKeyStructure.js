/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 60: a generated key has the structure GnuPG generates -- a
 * certify-only primary with a signing subkey and an encryption subkey.
 *
 * The point of the structure, and therefore of these tests: the primary is the
 * identity, and every signature happens on a subkey that can be rotated or
 * revoked without replacing that identity. A primary that can sign has to be
 * present, and vulnerable, for every signature.
 *
 * `keyUseFor` is what these tests read: a string of lowercase letters built in
 * RNP.sys.mjs from `rnp_key_allows_usage` for encrypt, sign, certify and
 * authenticate. "c" is certify only; "sc" is a primary that also signs.
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
 * Reads a generated key back out of the keyring.
 *
 * @param {string} keyId
 * @returns {object} The EnigmailKey object.
 */
function structureOf(keyId) {
  EnigmailKeyRing.clearCache();
  const key = EnigmailKeyRing.getKeyById(keyId);
  Assert.ok(key, `key ${keyId} is in the keyring`);
  return key;
}

/**
 * Asserts the GnuPG structure on a generated key.
 *
 * @param {object} key An EnigmailKey.
 * @param {string} label For failure messages.
 */
function assertGnupgStructure(key, label) {
  Assert.equal(
    key.subKeys.length,
    2,
    `${label}: expected a signing and an encryption subkey, ` +
      `found ${key.subKeys.length}`
  );

  const signing = key.subKeys.filter(sk => sk.keyUseFor.includes("s"));
  const encrypting = key.subKeys.filter(sk => sk.keyUseFor.includes("e"));

  Assert.equal(signing.length, 1, `${label}: exactly one subkey signs`);
  Assert.equal(encrypting.length, 1, `${label}: exactly one subkey encrypts`);

  // The substance of the item. If this fails, the structure is cosmetic and
  // the certificate key is still in the path of every signature.
  Assert.ok(
    !key.keyUseFor.includes("s"),
    `${label}: the primary must not sign; its usage is "${key.keyUseFor}"`
  );
  Assert.ok(
    key.keyUseFor.includes("c"),
    `${label}: the primary must certify; its usage is "${key.keyUseFor}"`
  );
}

add_task(async function test_ecc_key_has_gnupg_structure() {
  const pass = await OpenPGPMasterpass.retrieveOpenPGPPassword();
  const keyId = await RNP.genKey(
    "Structure ECC <structure-ecc@example.invalid>",
    "ECC",
    0,
    0,
    pass
  );
  Assert.ok(keyId, "genKey returned a key id");
  assertGnupgStructure(structureOf(keyId), "ECC");
});

add_task(async function test_rsa_key_has_gnupg_structure() {
  // The RSA path assigns its key types in a separate branch, so it is checked
  // rather than inferred from the ECC case.
  const pass = await OpenPGPMasterpass.retrieveOpenPGPPassword();
  const keyId = await RNP.genKey(
    "Structure RSA <structure-rsa@example.invalid>",
    "RSA",
    2048,
    0,
    pass
  );
  Assert.ok(keyId, "genKey returned a key id");
  assertGnupgStructure(structureOf(keyId), "RSA");
});

add_task(async function test_the_signing_subkey_is_the_one_selected() {
  // The structure is only worth having if signing selects the subkey.
  // `getSuitableSubkey(primary, "sign")` prefers a subkey and falls back to a
  // primary that can sign -- so with a certify-only primary there is no
  // fallback, and this asserts the precondition selection depends on.
  const pass = await OpenPGPMasterpass.retrieveOpenPGPPassword();
  const keyId = await RNP.genKey(
    "Structure Signing <structure-sign@example.invalid>",
    "ECC",
    0,
    0,
    pass
  );
  const key = structureOf(keyId);

  const sub = key.subKeys.find(sk => sk.keyUseFor.includes("s"));
  Assert.ok(sub, "there is a signing subkey");
  Assert.ok(sub.keyId, "it has an id, so selection has something to pick");
  Assert.ok(
    !key.keyUseFor.includes("s"),
    "and the primary offers no competing signing candidate"
  );
});

add_task(async function test_expiry_still_applies_to_both() {
  // The structure changed; expiry behaviour did not. Per-subkey expiry is a
  // separate capability (design 12.7) and is not part of this item.
  const pass = await OpenPGPMasterpass.retrieveOpenPGPPassword();
  const keyId = await RNP.genKey(
    "Structure Expiry <structure-expiry@example.invalid>",
    "ECC",
    0,
    30,
    pass
  );
  const key = structureOf(keyId);

  const now = Math.floor(Date.now() / 1000);
  const thirtyDays = 30 * 24 * 60 * 60;

  Assert.greater(key.expiryTime, now, "the primary expires in the future");
  Assert.less(
    Math.abs(key.expiryTime - (now + thirtyDays)),
    300,
    "and it is thirty days out, to within five minutes"
  );

  for (const sk of key.subKeys) {
    Assert.greater(sk.expiryTime, now, "each subkey expires in the future too");
    Assert.less(
      Math.abs(sk.expiryTime - key.expiryTime),
      300,
      "with the same expiry as the primary, as before this change"
    );
  }
});
