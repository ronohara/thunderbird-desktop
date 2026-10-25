/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 27: a recipient with several keys resolves to all of them.
 *
 * The function this replaces returned one key chosen by a ranking -- a fully
 * or ultimately trusted key won immediately, otherwise the highest acceptance
 * level won, and a tie went to whichever came first. Two things were wrong with
 * that, and only the first is visible in a passing test: the ranking made a
 * choice on the user's behalf, and it made it invisibly.
 *
 * The acceptance levels and the candidate list are stubbed here on purpose.
 * The subject is the selection rule, not the database or the keyring: feeding
 * acceptance values in directly is the only way to say "these two keys are
 * acceptable and this one is better" without a fixture in which one key's
 * acceptance has to be raised above another's. The real path is covered by
 * test_recipientChecks.js, test_alias.js and test_keyPrecedence.js, which run
 * against actual keys and the actual database.
 *
 * The task that matters is testLowerListedKeyIsNotDisplaced: on the old code
 * it fails, because the better-acceptance key wins from any position.
 */

"use strict";

const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);

const ADDR = "recipient@example.com";
const OTHER_ADDR = "nobody@example.com";

// Acceptance values as the code under test receives them: 3 personal,
// 2 verified, 1 unverified, 0 undecided, -1 rejected.
const PERSONAL = 3;
// The GnuPG validity values, not the old Thunderbird numbers. These stubbed the
// real function's return, so they have to speak the vocabulary it now returns --
// with the old numbers, VERIFIED = 2 is NEVER and a "verified" key would be
// refused.
const { OpenPgpValidity } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/constants.sys.mjs"
);
const VERIFIED = OpenPgpValidity.FULL;
const UNVERIFIED = OpenPgpValidity.UNDEFINED;
const UNDECIDED = OpenPgpValidity.UNKNOWN;
const REJECTED = OpenPgpValidity.NEVER;

let gOriginalCandidates;
let gOriginalIsValid;

/**
 * Replace the candidate list and the acceptance lookup for one task.
 *
 * The candidates belong to `address` only. Returning them for every address
 * would make the "no key for this address" case unreachable, which is how the
 * first version of this test passed a wrong answer.
 *
 * @param {object[]} candidates - Key objects, in the order the resolver sees.
 * @param {Map<string, integer>} acceptance - keyId -> acceptance level.
 * @param {string} [address] - The address those candidates belong to.
 */
function stubSelection(candidates, acceptance, address = ADDR) {
  EnigmailKeyRing.getCandidateKeysForEmail = async emailAddr =>
    emailAddr.toLowerCase() == address.toLowerCase() ? candidates : [];
  EnigmailKeyRing.isValidKeyForRecipient = async keyObj =>
    acceptance.get(keyObj.keyId) ?? REJECTED;
}

/** Put the real functions back, so one task cannot leak into the next. */
function restoreSelection() {
  EnigmailKeyRing.getCandidateKeysForEmail = gOriginalCandidates;
  EnigmailKeyRing.isValidKeyForRecipient = gOriginalIsValid;
}

/**
 * A key object with only what the resolver reads.
 *
 * @param {string} keyId - Key ID.
 * @returns {object} A minimal key object.
 */
function key(keyId) {
  return { keyId, fpr: `FPR-${keyId}` };
}

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();

  gOriginalCandidates = EnigmailKeyRing.getCandidateKeysForEmail;
  gOriginalIsValid = EnigmailKeyRing.isValidKeyForRecipient;

  registerCleanupFunction(restoreSelection);
});

/**
 * Two acceptable keys for one address are both returned, in candidate order.
 */
add_task(async function bothAcceptableKeysAreReturned() {
  stubSelection(
    [key("AAAAAAAA11111111"), key("BBBBBBBB22222222")],
    new Map([
      ["AAAAAAAA11111111", VERIFIED],
      ["BBBBBBBB22222222", UNVERIFIED],
    ])
  );

  const found = await EnigmailKeyRing.getValidKeysForRecipient(ADDR);

  Assert.deepEqual(
    found,
    ["AAAAAAAA11111111", "BBBBBBBB22222222"],
    "both keys should be returned, in the order the candidate list gave them"
  );
  restoreSelection();
});

/**
 * The ranking is gone: a better-acceptance key lower in the list does not
 * displace the one above it.
 *
 * This is the task that fails on the old implementation, which returned the
 * verified key from whatever position it occupied.
 */
add_task(async function lowerListedKeyIsNotDisplaced() {
  stubSelection(
    [key("AAAAAAAA11111111"), key("BBBBBBBB22222222")],
    new Map([
      ["AAAAAAAA11111111", UNVERIFIED],
      ["BBBBBBBB22222222", PERSONAL],
    ])
  );

  const found = await EnigmailKeyRing.getValidKeysForRecipient(ADDR);

  Assert.deepEqual(
    found,
    ["AAAAAAAA11111111", "BBBBBBBB22222222"],
    "a later key with better acceptance must not be moved ahead of an earlier acceptable one"
  );

  const single = await EnigmailKeyRing.getValidKeyForRecipient(ADDR);
  Assert.equal(
    single,
    "AAAAAAAA11111111",
    "the single-key answer is the first acceptable key, not the best-ranked one"
  );
  restoreSelection();
});

/**
 * The acceptability threshold is unchanged: rejected and undecided keys are
 * still excluded, and the rest come back in order.
 */
add_task(async function unacceptableKeysStayExcluded() {
  stubSelection(
    [
      key("REJECTED00000000"),
      key("UNDECIDED0000000"),
      key("UNVERIFIED000000"),
      key("VERIFIED00000000"),
    ],
    new Map([
      ["REJECTED00000000", REJECTED],
      ["UNDECIDED0000000", UNDECIDED],
      ["UNVERIFIED000000", UNVERIFIED],
      ["VERIFIED00000000", VERIFIED],
    ])
  );

  const found = await EnigmailKeyRing.getValidKeysForRecipient(ADDR);

  Assert.deepEqual(
    found,
    ["UNVERIFIED000000", "VERIFIED00000000"],
    "only keys at or above unverified should be returned, in candidate order"
  );
  restoreSelection();
});

/**
 * A repeated key in the candidate list is reported once.
 */
add_task(async function repeatedKeyIsReportedOnce() {
  stubSelection(
    [key("AAAAAAAA11111111"), key("AAAAAAAA11111111")],
    new Map([["AAAAAAAA11111111", VERIFIED]])
  );

  const found = await EnigmailKeyRing.getValidKeysForRecipient(ADDR);

  Assert.deepEqual(
    found,
    ["AAAAAAAA11111111"],
    "the same key twice in the candidate list should resolve to one entry"
  );
  restoreSelection();
});

/**
 * The per-address detail reports every key, and an address with none is still
 * reported as missing.
 */
add_task(async function allRecipientsReportsEveryKeyPerAddress() {
  stubSelection(
    [key("AAAAAAAA11111111"), key("BBBBBBBB22222222")],
    new Map([
      ["AAAAAAAA11111111", VERIFIED],
      ["BBBBBBBB22222222", UNVERIFIED],
    ])
  );

  const details = {};
  const missing = await EnigmailKeyRing.getValidKeysForAllRecipients(
    [ADDR, OTHER_ADDR],
    details
  );

  Assert.equal(missing, true, "the address with no candidate key is missing");
  Assert.deepEqual(
    details.keysByAddr[ADDR],
    ["AAAAAAAA11111111", "BBBBBBBB22222222"],
    "both of the first address's keys should be reported"
  );
  Assert.equal(
    details.keysByAddr[OTHER_ADDR],
    undefined,
    "an address with no usable key has no entry"
  );
  Assert.equal(
    details.errArray.length,
    1,
    "only the address without a key is reported as an error"
  );
  Assert.equal(
    details.errArray[0].addr,
    OTHER_ADDR,
    "and the error names that address"
  );
  restoreSelection();
});

/**
 * An address that does have keys is not reported as missing.
 */
add_task(async function recipientWithKeysIsNotMissing() {
  stubSelection(
    [key("AAAAAAAA11111111")],
    new Map([["AAAAAAAA11111111", VERIFIED]])
  );

  const details = {};
  const missing = await EnigmailKeyRing.getValidKeysForAllRecipients(
    [ADDR],
    details
  );

  Assert.equal(missing, false, "an address with a usable key is not missing");
  Assert.deepEqual(
    details.keysByAddr[ADDR],
    ["AAAAAAAA11111111"],
    "its key is reported"
  );
  Assert.equal(details.errArray.length, 0, "and no error is recorded");
  restoreSelection();
});
