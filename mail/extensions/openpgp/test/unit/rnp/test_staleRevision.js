/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Stage 3's verification: a stale copy in the profile ring must not decide a
 * key's expiry, its user IDs, or anything else GnuPG knows better.
 *
 * On 18 October the profile held a copy of the user's own key that was correct
 * in fingerprint and wrong in revision -- an older self-signature, without the
 * later one that removed the expiry. Thunderbird reported the key as expired;
 * GnuPG reported no expiry, because `getKeyById()` consulted the ring index
 * first. These tests plant that shape.
 *
 * Both revisions are real keys, built or supplied as packets, never marker
 * objects: the earlier tests in this directory (test_keyPrecedence.js) prove
 * the ordering with stand-ins, and this file proves it with the thing itself.
 */

"use strict";

const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { EnigmailKeyObj } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyObj.sys.mjs"
);
const { GPGME } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/GPGME.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";
const REV_KEY_ID = "D4ED849BCD779DFC";
const REV_BEFORE = "D4ED849BCD779DFC-before-new-identity.asc";
const REV_AFTER = "D4ED849BCD779DFC-after-new-identity.asc";

let gOriginalInit;

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();
  gOriginalInit = GPGME.init;
});

/** Clear the caches, the transient set, and the pref this file touches. */
async function cleanup() {
  GPGME.init = gOriginalInit;
  EnigmailKeyRing.clearCache();
  EnigmailKeyRing.clearGnuPgKeyCache?.();
  EnigmailKeyRing.gnuPgKeys.clear();
  EnigmailKeyRing.gnuPgKeyIds.clear();
  EnigmailKeyRing.gnuPgLoadedFor.clear();
  if (Services.prefs.prefHasUserValue("mail.openpgp.allow_external_gnupg")) {
    Services.prefs.clearUserPref("mail.openpgp.allow_external_gnupg");
  }
}

/**
 * Read a fixture.
 *
 * @param {string} name - File under the shared key fixtures.
 * @returns {Promise<string>} Its contents.
 */
async function readFixture(name) {
  const data = await IOUtils.read(do_get_file(`${keyDir}/${name}`).path);
  return new TextDecoder().decode(data);
}

/**
 * Import a public block into the profile ring, bypassing the guards.
 *
 * The guards are Item 8 and Item 10's subject; here the planted copy is the
 * point of the test, so the pref that makes them consult GnuPG is switched off
 * and the import proceeds as it would on a machine with no GnuPG.
 *
 * @param {string} block - Armored key block.
 * @returns {Promise<void>}
 */
async function importIntoRing(block) {
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", false);
  await EnigmailKeyRing.importKeyAsync(null, false, block, false, "", {}, null);
  EnigmailKeyRing.clearCache();
}

/**
 * Install a key block in the transient cache as GnuPG's answer.
 *
 * @param {string} block - Armored key block.
 * @returns {Promise<EnigmailKeyObj>} The transient key object.
 */
async function installTransient(block) {
  const parsed = await RNP.getKeyListFromKeyBlockImpl(block);
  const keyObj = new EnigmailKeyObj(parsed[0]);
  EnigmailKeyRing.gnuPgKeys.set(keyObj.fpr.toUpperCase(), keyObj);
  EnigmailKeyRing.gnuPgKeyIds.set(
    keyObj.keyId.toUpperCase(),
    keyObj.fpr.toUpperCase()
  );
  return keyObj;
}

add_task(async function stale_revision_does_not_supply_user_ids() {
  const before = await readFixture(REV_BEFORE);
  const after = await readFixture(REV_AFTER);

  // The older revision carries one user ID, the newer one two. That is the
  // 18 October shape in miniature: same fingerprint, different content.
  await importIntoRing(before);
  const ringKey = EnigmailKeyRing.getKeyById(REV_KEY_ID);
  Assert.ok(ringKey, "the older revision is in the profile ring");
  Assert.equal(ringKey.userIds.length, 1, "and it carries one user ID");

  const transient = await installTransient(after);
  Assert.equal(transient.userIds.length, 2, "the newer revision carries two");

  try {
    const resolved = EnigmailKeyRing.getKeyById(REV_KEY_ID);
    Assert.equal(
      resolved.userIds.length,
      2,
      "the reported user IDs are GnuPG's, not the planted copy's"
    );
  } finally {
    await cleanup();
  }
});

add_task(async function stale_revision_does_not_supply_the_expiry() {
  const userId = "Stage Three Test <stage3@example.com>";
  const keyId = await RNP.genKey(userId, "ECC", 0, 30, "");
  Assert.ok(keyId, "a test key should be generated");

  EnigmailKeyRing.clearCache();
  const fresh = EnigmailKeyRing.getKeyById(keyId);
  Assert.ok(fresh, "the generated key should be in the ring");
  const fpr = fresh.fpr;
  const expiryShort = fresh.expiryTime;
  Assert.greater(expiryShort, 0, "the key should have a near expiry");

  // The earlier revision: a 30-day expiry, captured as packets.
  // The export needs the "0x" form: exportPublicKeyBlock() silently returns an
  // empty string for a bare fingerprint, because the handle lookup inside it
  // wants the prefixed id. Found by a probe, left in the test as a comment so
  // the next reader does not learn it the same way.
  const oldBlock = RNP.exportPublicKeyBlock("0x" + fpr);
  Assert.ok(oldBlock, "the earlier revision should export");

  // The later revision: the same key with the expiry pushed out, which is a
  // new self-signature and therefore a different revision of one certificate.
  await RNP._changeExpirationDate([fpr], 1000 * 86400);
  EnigmailKeyRing.clearCache();
  const extended = EnigmailKeyRing.getKeyById(keyId);
  const expiryLong = extended.expiryTime;
  Assert.notEqual(
    expiryLong,
    expiryShort,
    "the two revisions must differ in expiry, or this proves nothing"
  );

  // Same prefix requirement as above: exportPublicKeyBlock() silently returns
  // an empty string for a bare fingerprint, because the handle lookup wants
  // the "0x" form.
  const newBlock = RNP.exportPublicKeyBlock("0x" + fpr);
  Assert.ok(newBlock, "the later revision should export");

  try {
    // Plant the older revision: remove the key, then import the earlier
    // packets. The ring now answers "expires in 30 days".
    await RNP.deleteKey(fpr, false);
    EnigmailKeyRing.clearCache();
    await importIntoRing(oldBlock);

    const planted = EnigmailKeyRing.getKeyById(keyId);
    Assert.ok(planted, "the older revision should be back in the ring");
    Assert.equal(
      planted.expiryTime,
      expiryShort,
      "the planted copy carries the near expiry, which is the stale answer"
    );

    // GnuPG's answer: the later revision, with the extended expiry.
    const transient = await installTransient(newBlock);
    Assert.equal(
      transient.expiryTime,
      expiryLong,
      "the transient revision carries the extended expiry"
    );

    // The assertion the item exists for.
    const resolved = EnigmailKeyRing.getKeyById(keyId);
    Assert.equal(
      resolved.expiryTime,
      expiryLong,
      "the reported expiry is GnuPG's, not the planted copy's"
    );
    Assert.notEqual(
      resolved.expiryTime,
      expiryShort,
      "and the stale expiry is not what a user would see"
    );
  } finally {
    EnigmailKeyRing.clearCache();
    const leftover = EnigmailKeyRing.getKeyById(keyId);
    if (leftover) {
      await RNP.deleteKey(leftover.fpr, leftover.secretAvailable);
    }
    await cleanup();
  }
});
