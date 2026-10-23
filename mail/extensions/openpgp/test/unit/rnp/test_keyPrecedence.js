/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Precedence: for a fingerprint the external GnuPG keyring holds, GnuPG's
 * revision is the answer and a copy in the profile ring is not consulted.
 *
 * The defect this pins is the 18 October one. The profile held a copy of the
 * user's own key that was correct in fingerprint and wrong in revision -- the
 * 2018 self-signature, a subkey binding GnuPG no longer had, and without the
 * 2021 self-signature that removed the expiry. Because `getKeyById()`
 * consulted the profile index first, Thunderbird reported the key as expired
 * while GnuPG reported no expiry.
 *
 * Both directions are asserted. A rule that always prefers GnuPG would pass a
 * test that only planted a stale copy; it would also break every key GnuPG
 * does not hold.
 */

"use strict";

const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { GPGME } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/GPGME.sys.mjs"
);
const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { EnigmailKeyObj } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyObj.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";
const KEY_ID = "F231550C4F47E38E";
const SECRET_FILE = "alice@openpgp.example-0xf231550c4f47e38e-secret.asc";

let gOriginalInit;
let gOriginalGetPublicKeysForId;
let gOriginalGetPublicKeysForEmail;

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();

  gOriginalInit = GPGME.init;
  gOriginalGetPublicKeysForId = GPGME.getPublicKeysForId;
  gOriginalGetPublicKeysForEmail = GPGME.getPublicKeysForEmail;
});

/** Restore the GnuPG boundary and drop the profile copy. */
async function cleanup() {
  GPGME.init = gOriginalInit;
  GPGME.getPublicKeysForId = gOriginalGetPublicKeysForId;
  GPGME.getPublicKeysForEmail = gOriginalGetPublicKeysForEmail;

  EnigmailKeyRing.clearCache();
  const keyObj = EnigmailKeyRing.getKeyById(KEY_ID);
  if (keyObj?.secretAvailable) {
    await RNP.deleteKey(keyObj.fpr, true);
  }
  EnigmailKeyRing.clearCache();

  if (Services.prefs.prefHasUserValue("mail.openpgp.allow_external_gnupg")) {
    Services.prefs.clearUserPref("mail.openpgp.allow_external_gnupg");
  }
}

add_task(async function gnupg_revision_wins_over_a_ring_copy() {
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);

  // A profile copy first, which is the state that caused the false expiry.
  await OpenPGPTestUtils.importPrivateKey(
    null,
    do_get_file(`${keyDir}/${SECRET_FILE}`)
  );
  EnigmailKeyRing.clearCache();
  const ringKey = EnigmailKeyRing.getKeyById(KEY_ID);
  Assert.ok(ringKey, "the profile copy should be present to begin with");
  Assert.ok(ringKey.secretAvailable, "and it is a secret key");

  // The transient key for the same fingerprint, distinguished by a marker the
  // ring object cannot have. Only one of the two can be returned.
  const transient = new EnigmailKeyObj({
    fpr: ringKey.fpr,
    keyId: KEY_ID,
    userIds: ringKey.userIds,
    keyCreated: ringKey.keyCreated,
    expiryTime: 0,
  });
  transient.marker = "from-gnupg";
  EnigmailKeyRing.gnuPgKeys.set(ringKey.fpr.toUpperCase(), transient);
  EnigmailKeyRing.gnuPgKeyIds.set(KEY_ID, ringKey.fpr.toUpperCase());

  try {
    const resolved = EnigmailKeyRing.getKeyById(KEY_ID);
    Assert.equal(
      resolved?.marker,
      "from-gnupg",
      "getKeyById() must return the GnuPG revision, not the ring copy"
    );

    // And by fingerprint rather than key id, since callers use both.
    const byFpr = EnigmailKeyRing.getKeyById(ringKey.fpr);
    Assert.equal(
      byFpr?.marker,
      "from-gnupg",
      "the same applies when the lookup uses a fingerprint"
    );
  } finally {
    EnigmailKeyRing.gnuPgKeys.delete(ringKey.fpr.toUpperCase());
    await cleanup();
  }
});

add_task(async function ring_copy_still_wins_when_gnupg_lacks_the_key() {
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);

  await OpenPGPTestUtils.importPrivateKey(
    null,
    do_get_file(`${keyDir}/${SECRET_FILE}`)
  );
  EnigmailKeyRing.clearCache();

  try {
    const ringKey = EnigmailKeyRing.getKeyById(KEY_ID);
    Assert.ok(
      ringKey,
      "with nothing in the transient cache the ring answer is returned"
    );
    Assert.equal(
      ringKey.marker,
      undefined,
      "and it is the ring object, not a transient one"
    );
  } finally {
    await cleanup();
  }
});

/**
 * Build a stand-in key object.
 *
 * The merge only reads `fpr`, so a plain object is enough and keeps the test
 * about the merge rather than about key parsing.
 *
 * @param {string} fpr - Fingerprint.
 * @param {string} marker - Label identifying which source it came from.
 * @returns {object} A minimal key object.
 */
function fakeKey(fpr, marker) {
  return {
    fpr,
    keyId: fpr.slice(-16),
    marker,
    userIds: [],
    subKeys: [],
    expiryTime: 0,
    keyCreated: 1,
  };
}

const FPR_SHARED = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const FPR_RING_ONLY = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const FPR_GNUPG_ONLY = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

/**
 * Run getCandidateKeysForEmail() against fixed inputs.
 *
 * @param {object[]} ringKeys - What the profile ring holds.
 * @param {object[]} gnuPgKeys - What the transient cache holds.
 * @returns {Promise<object[]>} The merged candidate list.
 */
async function mergedCandidates(ringKeys, gnuPgKeys) {
  const originalLoad = EnigmailKeyRing.loadGnuPgKeysForEmail;
  const originalAll = EnigmailKeyRing.getAllKeys;
  const originalForEmail = EnigmailKeyRing.getGnuPgKeysForEmail;
  EnigmailKeyRing.loadGnuPgKeysForEmail = async () => true;
  EnigmailKeyRing.getAllKeys = () => ({ keyList: ringKeys });
  EnigmailKeyRing.getGnuPgKeysForEmail = () => gnuPgKeys;
  try {
    return await EnigmailKeyRing.getCandidateKeysForEmail("a@example.com");
  } finally {
    EnigmailKeyRing.loadGnuPgKeysForEmail = originalLoad;
    EnigmailKeyRing.getAllKeys = originalAll;
    EnigmailKeyRing.getGnuPgKeysForEmail = originalForEmail;
  }
}

/**
 * The merge keeps every key exactly once.
 *
 * The three cases are in one task because the failure this guards against is a
 * merge that drops a whole class of key rather than one that mishandles an
 * individual fingerprint: a rule that returns only the GnuPG set, or only the
 * shared ones, must fail here.
 */
add_task(async function merge_keeps_every_key_exactly_once() {
  const merged = await mergedCandidates(
    [fakeKey(FPR_SHARED, "ring"), fakeKey(FPR_RING_ONLY, "ring")],
    [fakeKey(FPR_SHARED, "gnupg"), fakeKey(FPR_GNUPG_ONLY, "gnupg")]
  );

  Assert.equal(merged.length, 3, "three distinct fingerprints, three entries");

  const byFpr = new Map(merged.map(k => [k.fpr, k]));
  Assert.equal(byFpr.size, 3, "no fingerprint appears twice");
  Assert.equal(
    byFpr.get(FPR_SHARED).marker,
    "gnupg",
    "the shared fingerprint carries GnuPG's revision"
  );
  Assert.equal(
    byFpr.get(FPR_RING_ONLY).marker,
    "ring",
    "a key GnuPG does not hold still comes from the ring"
  );
  Assert.equal(
    byFpr.get(FPR_GNUPG_ONLY).marker,
    "gnupg",
    "and a key only GnuPG holds is not lost"
  );
});

/**
 * Distinct keys keep their relative order.
 *
 * getValidKeyForRecipient() returns the first acceptable key it finds, so the
 * order of this list decides which key signs. Precedence for a shared
 * fingerprint must not become a general reordering: a ring-only key has to stay
 * ahead of the transient set, exactly as it did before this change.
 */
add_task(async function distinct_keys_keep_their_order() {
  const merged = await mergedCandidates(
    [fakeKey(FPR_RING_ONLY, "ring")],
    [fakeKey(FPR_GNUPG_ONLY, "gnupg")]
  );

  Assert.equal(merged.length, 2, "both keys are present");
  Assert.equal(
    merged[0].marker,
    "ring",
    "the ring key comes first, as it did before the precedence change"
  );
  Assert.equal(merged[1].marker, "gnupg", "and the transient key follows it");
});

add_task(async function merged_candidates_keep_gnupgs_revision() {
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  Services.prefs.setBoolPref("mail.openpgp.fetch_pubkeys_from_gnupg", true);

  await OpenPGPTestUtils.importPrivateKey(
    null,
    do_get_file(`${keyDir}/${SECRET_FILE}`)
  );
  EnigmailKeyRing.clearCache();
  const ringKey = EnigmailKeyRing.getKeyById(KEY_ID);
  Assert.ok(ringKey, "the profile copy should be present");

  const transient = new EnigmailKeyObj({
    fpr: ringKey.fpr,
    keyId: KEY_ID,
    userIds: ringKey.userIds,
    keyCreated: ringKey.keyCreated,
    expiryTime: 0,
  });
  transient.marker = "from-gnupg";

  const originalLoad = EnigmailKeyRing.loadGnuPgKeysForEmail;
  const originalForEmail = EnigmailKeyRing.getGnuPgKeysForEmail;
  EnigmailKeyRing.loadGnuPgKeysForEmail = async () => true;
  EnigmailKeyRing.getGnuPgKeysForEmail = () => [transient];

  try {
    const candidates = await EnigmailKeyRing.getCandidateKeysForEmail(
      "alice@openpgp.example"
    );

    const matching = candidates.filter(
      k => k.fpr.toUpperCase() == ringKey.fpr.toUpperCase()
    );
    Assert.equal(
      matching.length,
      1,
      "one answer per fingerprint, not two competing revisions"
    );
    Assert.equal(
      matching[0].marker,
      "from-gnupg",
      "and the answer is GnuPG's revision rather than the copy"
    );
  } finally {
    EnigmailKeyRing.loadGnuPgKeysForEmail = originalLoad;
    EnigmailKeyRing.getGnuPgKeysForEmail = originalForEmail;
    Services.prefs.clearUserPref("mail.openpgp.fetch_pubkeys_from_gnupg");
    await cleanup();
  }
});
