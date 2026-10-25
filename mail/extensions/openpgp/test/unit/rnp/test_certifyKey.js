/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 92: certify another party's key, which is what Item 88a was blocked on.
 *
 * Item 88's owner trust and this are different operations and the difference is
 * the point: a certification is a signature others can check, it is what gpg's
 * computed validity counts, and it survives being exported. Owner trust asserts
 * locally and grants the key authority to validate others. A keyring where
 * everything is ultimately trusted and nothing is signed has validity that
 * evaporates on a new machine.
 *
 * **Item 88a was recorded as Blocked because "there is no binding" for
 * certifying.** That was true when it was written and stopped being true when
 * Item 69 bound `rnp_key_certification_create` and `rnp_key_signature_sign` to
 * support user IDs on the user's own key. This file is the check that the
 * operation works when the signer and the target are different keys, which is
 * the case those bindings had not been used for.
 *
 * The observation is the signature count on the target's user ID: a
 * certification adds exactly one, so a count that rises by one -- and stays
 * risen after an export and a re-parse -- is the difference between a
 * certification that exists and one that only existed in memory.
 */

"use strict";

const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";

// Alice signs; Bob's key is the one certified. Two keys, because the whole
// question is what happens when the signer is not the target.
const ALICE_SECRET = "alice@openpgp.example-0xf231550c4f47e38e-secret.asc";
const ALICE_FPR = "EB85BB5FA33A75E15E944E63F231550C4F47E38E";
const BOB_PUBLIC = "bob@openpgp.example-0xfbfcc82a015e7330-pub.asc";
const BOB_FPR = "D1A66E1A23B182C9980F788CFBFCC82A015E7330";
const BOB_ADDRESS = "bob@openpgp.example";

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();

  await OpenPGPTestUtils.importPrivateKey(
    null,
    do_get_file(`${keyDir}/${ALICE_SECRET}`)
  );
  await OpenPGPTestUtils.importPublicKey(
    null,
    do_get_file(`${keyDir}/${BOB_PUBLIC}`)
  );
  EnigmailKeyRing.clearCache();

  Assert.ok(
    EnigmailKeyRing.getKeyById(`0x${ALICE_FPR}`)?.secretAvailable,
    "Alice's key is in the profile and has its secret part"
  );
  Assert.ok(
    EnigmailKeyRing.getKeyById(`0x${BOB_FPR}`),
    "Bob's key is in the profile"
  );
});

/**
 * Certifying adds exactly one signature to the target's user ID.
 *
 * Read through the engine rather than through a Thunderbird cache, because the
 * claim is about what the keyring holds.
 */
let exportLengthBefore = 0;

add_task(async function certifyingAddsOneSignature() {
  // Captured before the certification, so the export check has a baseline: a
  // block that grew has a packet in it that was not there.
  exportLengthBefore = RNP.getMultiplePublicKeys(
    [`0x${BOB_FPR}`],
    null,
    null
  ).length;
  Assert.greater(exportLengthBefore, 0, "the key exports before certifying");

  const before = RNP.getUidSignatureCount(BOB_FPR, BOB_ADDRESS);
  Assert.equal(typeof before, "number", "the before-count is readable");

  const done = await RNP.certifyKey(ALICE_FPR, BOB_FPR, BOB_ADDRESS);
  Assert.ok(done, "the certification was made and saved");

  EnigmailKeyRing.clearCache();
  const after = RNP.getUidSignatureCount(BOB_FPR, BOB_ADDRESS);
  info(`FINDING signature count: before=${before} after=${after}`);
  Assert.equal(
    after,
    before + 1,
    `exactly one certification was added, got ${before} then ${after}`
  );
});

/**
 * And it is exportable: the certification is in the key, not in a session.
 *
 * Measured as a block that grew. A certification is one more signature packet,
 * so an exported block with the certification in it is longer than the same
 * block without -- and the length is compared rather than the content, because
 * an armored block's length is exact and its bytes are not stable across
 * exports (creation timestamps, ordering).
 */
add_task(async function theCertificationIsExportable() {
  const block = RNP.getMultiplePublicKeys([`0x${BOB_FPR}`], null, null);
  Assert.ok(block.length, "the key exports after certifying");

  info(
    `FINDING export length: before=${exportLengthBefore} after=${block.length}`
  );
  Assert.greater(
    block.length,
    exportLengthBefore,
    "the exported block grew, so the certification is in the key rather than " +
      "in a cache"
  );
  Assert.ok(
    block.includes("BEGIN PGP PUBLIC KEY BLOCK"),
    "and it is still one armored public key"
  );
});

/**
 * The signer and the target must be different keys.
 *
 * A self-certification goes through `_editSelfCertification`, which is a
 * different operation with different rules; routing it here as well would be
 * two ways to change the same thing.
 */
add_task(async function aKeyCannotCertifyItselfThroughThisPath() {
  Assert.equal(
    await RNP.certifyKey(ALICE_FPR, ALICE_FPR, "alice@openpgp.example"),
    false,
    "the same fingerprint for signer and target is refused"
  );
});

/**
 * A signer whose secret is not in the profile is refused rather than throwing.
 */
add_task(async function aSignerWithoutASecretIsRefused() {
  Assert.equal(
    await RNP.certifyKey(BOB_FPR, ALICE_FPR, "alice@openpgp.example"),
    false,
    "Bob's key has no secret part here, so it cannot sign a certification"
  );
});
