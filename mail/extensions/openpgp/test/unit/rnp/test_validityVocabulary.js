/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 77 / D13: GnuPG's six validity values, and the gate that must not treat
 * them as an order.
 *
 * The item is explicit about why the gate comes first: GnuPG's values are *not*
 * ordered by trustworthiness. NEVER is 2 and UNDEFINED is 1, so the old test
 * `if (acceptanceLevel < 1) continue` would admit a rejected key once the
 * numbers changed. These tests are written to fail on that old comparison --
 * the strongest of them asserts a rejected key is refused, which the threshold
 * version got wrong by exactly one step.
 */

"use strict";

const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
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
const { OpenPgpValidity, isValidityUsable } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/constants.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";

/**
 * @returns {object} The GnuPG validity values keyed by name, for readable
 *   failure messages.
 */
function vocabulary() {
  return {
    UNKNOWN: OpenPgpValidity.UNKNOWN,
    UNDEFINED: OpenPgpValidity.UNDEFINED,
    NEVER: OpenPgpValidity.NEVER,
    MARGINAL: OpenPgpValidity.MARGINAL,
    FULL: OpenPgpValidity.FULL,
    ULTIMATE: OpenPgpValidity.ULTIMATE,
  };
}

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();

  // The vocabulary reaches keyRing.sys.mjs through a lazy getter. A getter
  // resolving to `undefined` is a failure this tree has met four times and it
  // fails silently, so the values are asserted to be reachable through the
  // module that uses them -- by making it answer a call that needs them.
  Assert.equal(
    EnigmailKeyRing.getAcceptanceStringFromAcceptanceLevel(4),
    "verified",
    "the vocabulary must be reachable through keyRing.sys.mjs, not merely " +
      "importable in this test"
  );
});

/**
 * The vocabulary is GnuPG's, in GnuPG's numbering, and it is not monotonic.
 *
 * The non-monotonicity is asserted rather than described, because it is the
 * fact the whole item turns on: a reader who assumes these are ordered will
 * write a threshold and be wrong.
 */
add_task(async function theVocabularyIsGnuPGsAndIsNotOrdered() {
  const v = vocabulary();
  Assert.deepEqual(
    v,
    {
      UNKNOWN: 0,
      UNDEFINED: 1,
      NEVER: 2,
      MARGINAL: 3,
      FULL: 4,
      ULTIMATE: 5,
    },
    "the values must match GnuPG's own numbering"
  );

  Assert.greater(
    v.NEVER,
    v.UNDEFINED,
    "NEVER sits above UNDEFINED, so these values are not an order"
  );
  Assert.less(
    v.NEVER,
    v.MARGINAL,
    "and a rejection is numerically below partial trust -- which is why a " +
      "threshold test cannot express any of this"
  );
});

/**
 * `isValidityUsable()` is an explicit set, and the set excludes both NEVER and
 * UNKNOWN.
 *
 * This is the assertion that fails on the old code: under the old vocabulary,
 * `level < 1` excluded rejection (-1) and undecided (0). Under the new numbers
 * the same expression admits NEVER (2) and FULL (4) and excludes nothing else --
 * so a rejected key becomes usable, silently.
 */
add_task(async function theGateAdmitsTheRightValues() {
  const v = vocabulary();

  for (const usable of [v.UNDEFINED, v.MARGINAL, v.FULL, v.ULTIMATE]) {
    Assert.ok(
      isValidityUsable(usable),
      `value ${usable} should permit use of the key`
    );
  }

  for (const refused of [v.UNKNOWN, v.NEVER]) {
    Assert.ok(
      !isValidityUsable(refused),
      `value ${refused} must NOT permit use of the key`
    );
  }

  // The hard-invalid sentinel is not a validity value and must not be usable.
  Assert.ok(
    !isValidityUsable(OpenPgpValidity.INVALID),
    "INVALID must not permit use of the key"
  );
});

/**
 * And the same claim through the real path: a rejected key is refused for a
 * recipient.
 *
 * The item asks for this specifically -- "write the test that proves a NEVER key
 * is refused before changing the vocabulary, so the test can fail on the old
 * code and pass on the new". It is here, and it is the test that would have
 * caught a threshold.
 */
add_task(async function aRejectedKeyIsRefusedForARecipient() {
  await OpenPGPTestUtils.importPublicKey(
    null,
    do_get_file(`${keyDir}/alice@openpgp.example-0xf231550c4f47e38e-pub.asc`)
  );
  EnigmailKeyRing.clearCache();

  const key = EnigmailKeyRing.getKeyById("0xF231550C4F47E38E");
  Assert.ok(key, "the fixture key is in the keyring");

  const email = "alice@openpgp.example";

  // Accepted first, so the refusal below is a change of state rather than a
  // key that was never usable.
  await PgpSqliteDb2.updateAcceptance(key.fpr, [email], "verified");
  EnigmailKeyRing.clearCache();
  const acceptedLevel = await EnigmailKeyRing.isValidKeyForRecipient(
    EnigmailKeyRing.getKeyById("0xF231550C4F47E38E"),
    email,
    false
  );
  Assert.equal(
    acceptedLevel,
    OpenPgpValidity.FULL,
    `a verified key should report FULL, got ${acceptedLevel}`
  );
  Assert.ok(isValidityUsable(acceptedLevel), "and should be usable");

  // Now rejected, with the address passed as the UI passes it.
  //
  // `null` here does NOT work, and the way it fails is worth recording:
  // `updateAcceptance()` writes no `acceptance_email` rows for any decision when
  // the array is null, and `getAcceptance()` only reports a decision when the
  // address is among those rows. So a null array stores the rejection and
  // reports nothing -- the gate then answers UNKNOWN, and the key is refused for
  // the wrong reason. A test passing `null` would have "proved" the refusal
  // while never exercising the NEVER path at all.
  await PgpSqliteDb2.updateAcceptance(key.fpr, [email], "rejected");
  EnigmailKeyRing.clearCache();
  const rejectedLevel = await EnigmailKeyRing.isValidKeyForRecipient(
    EnigmailKeyRing.getKeyById("0xF231550C4F47E38E"),
    email,
    false
  );
  Assert.equal(
    rejectedLevel,
    OpenPgpValidity.NEVER,
    `a rejected key should report NEVER, got ${rejectedLevel}`
  );
  Assert.ok(
    !isValidityUsable(rejectedLevel),
    "and must be refused -- this is the assertion a threshold gets wrong, " +
      `because NEVER is ${OpenPgpValidity.NEVER} and a '< 1' test admits it`
  );

  // And the refusal holds at the list the send path actually uses. This is the
  // assertion that separates the two implementations: `getValidKeysForRecipient`
  // asks the same question and filters on the same value, so with a threshold it
  // would return the rejected key here.
  const usable = await EnigmailKeyRing.getValidKeysForRecipient(email, {});
  Assert.ok(
    !usable.includes(key.keyId),
    `a rejected key must not appear in the usable list, got ` +
      `${JSON.stringify(usable)}`
  );

  registerCleanupFunction(() => PgpSqliteDb2.deleteAcceptance(key.fpr));
});

/**
 * The decision words are unchanged, so profile data needs no migration.
 *
 * The item maps the strings onto GnuPG's numbers; it does not change what is
 * stored. Asserted through the one function where the two meet.
 */
add_task(async function theStoredWordsAreUnchanged() {
  const cases = [
    [OpenPgpValidity.ULTIMATE, "personal"],
    [OpenPgpValidity.FULL, "verified"],
    [OpenPgpValidity.UNDEFINED, "unverified"],
    [OpenPgpValidity.NEVER, "rejected"],
    [OpenPgpValidity.UNKNOWN, "undecided"],
  ];
  for (const [level, word] of cases) {
    Assert.equal(
      EnigmailKeyRing.getAcceptanceStringFromAcceptanceLevel(level),
      word,
      `validity ${level} should still be stored as "${word}"`
    );
  }

  // MARGINAL has no stored word: only GnuPG's computation produces it, and it
  // is never written by Thunderbird. Falling through to "undecided" is the
  // honest answer, and asserting it records that the gap is deliberate.
  Assert.equal(
    EnigmailKeyRing.getAcceptanceStringFromAcceptanceLevel(
      OpenPgpValidity.MARGINAL
    ),
    "undecided",
    "MARGINAL has no Thunderbird-stored equivalent"
  );
});
