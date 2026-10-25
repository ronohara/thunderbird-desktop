/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 87: the key-acceptance choice, and the gate that honours it.
 *
 * Enigmail let the user say whether a recipient's key had to be *trusted* or
 * merely *usable*, and defaulted to usable. This build hard-coded the usable
 * answer, so the setting was the gap and the default was already right.
 *
 * Both answers are exercised on the same key, because a setting that can only
 * be read in one direction is indistinguishable from a hard-coded value. The
 * key is `unverified`: usable, not trusted. That is the exact state the two
 * answers disagree about, so it is the only state worth testing.
 *
 * Two other values are pinned down as well, and they are the ones a reader is
 * most likely to guess wrong:
 *
 *   - `MARGINAL` is usable but *not* trusted. It is a web-of-trust level GnuPG
 *     computes from other people's signatures; a user who asked for their own
 *     judgment has not given it.
 *   - `ULTIMATE` is trusted. It is what a key gets when the user holds both
 *     halves, which is a stronger statement than FULL rather than a weaker one.
 */

"use strict";

const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { PgpSqliteDb2 } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/sqliteDb.sys.mjs"
);
const {
  OpenPgpValidity,
  isValidityUsable,
  isValidityTrusted,
  isValidityAcceptable,
} = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/constants.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);

// A public key fixture. A key generated here would be the user's own, and
// `_getAcceptanceLevelForEmail()` answers ULTIMATE for a personal key whatever
// its acceptance says -- so it could never be the "usable but not trusted"
// case these checks turn on.
const ADDRESS = "bob@openpgp.example";
const KEY_DIR = "../../../../../test/browser/openpgp/data/keys";
const PUBLIC_KEY_FILE = "bob@openpgp.example-0xfbfcc82a015e7330-pub.asc";
const PREF = "mail.openpgp.require_trusted_keys";

/**
 * @returns {Promise<object>} The fixture key, imported public-only.
 */
async function importPublicKey() {
  await OpenPGPTestUtils.importPublicKey(
    null,
    do_get_file(`${KEY_DIR}/${PUBLIC_KEY_FILE}`)
  );
  EnigmailKeyRing.clearCache();
  const key = EnigmailKeyRing.getKeyById("0xFBFCC82A015E7330");
  Assert.ok(key, "the fixture key is in the ring");
  Assert.ok(
    !key.secretAvailable,
    "public-only, so its level comes from acceptance rather than ownership"
  );
  return key;
}

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();
  // No external GnuPG: the candidate list must contain exactly the fixture,
  // or a key from the machine's own keyring could satisfy the lookup and the
  // test would pass for a reason it did not set up.
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", false);
  Services.prefs.setBoolPref("mail.openpgp.fetch_pubkeys_from_gnupg", false);
});

/**
 * The two predicates, stated as the sets they are.
 *
 * Written out rather than derived, so a change to either is a visible change
 * to a test rather than a silent consequence of tidying one of them.
 */
add_task(async function theTwoPredicatesAreDistinct() {
  const usable = [
    OpenPgpValidity.UNDEFINED,
    OpenPgpValidity.MARGINAL,
    OpenPgpValidity.FULL,
    OpenPgpValidity.ULTIMATE,
  ];
  const trusted = [OpenPgpValidity.FULL, OpenPgpValidity.ULTIMATE];

  for (const level of [
    OpenPgpValidity.UNKNOWN,
    OpenPgpValidity.UNDEFINED,
    OpenPgpValidity.NEVER,
    OpenPgpValidity.MARGINAL,
    OpenPgpValidity.FULL,
    OpenPgpValidity.ULTIMATE,
    OpenPgpValidity.INVALID,
  ]) {
    Assert.equal(
      isValidityUsable(level),
      usable.includes(level),
      `isValidityUsable(${level})`
    );
    Assert.equal(
      isValidityTrusted(level),
      trusted.includes(level),
      `isValidityTrusted(${level})`
    );
    Assert.equal(
      isValidityAcceptable(level, false),
      usable.includes(level),
      `the permissive policy is the usable set, at ${level}`
    );
    Assert.equal(
      isValidityAcceptable(level, true),
      trusted.includes(level),
      `the strict policy is the trusted set, at ${level}`
    );
  }
});

/**
 * The setting reaches the selection path.
 *
 * One key, `unverified`, asked for twice: offered under the default and
 * refused under the strict setting, with the reason the composer reports.
 */
add_task(async function theSettingChangesWhichKeysAreOffered() {
  const key = await importPublicKey();
  registerCleanupFunction(() => PgpSqliteDb2.deleteAcceptance(key.fpr));
  await PgpSqliteDb2.updateAcceptance(key.fpr, [ADDRESS], "unverified");

  // The default. Asserted rather than assumed, because a pref that defaulted
  // to strict would refuse every correspondent out of the box.
  Services.prefs.clearUserPref(PREF);
  Assert.ok(
    !EnigmailKeyRing.requiresTrustedKeys(),
    "the default policy is permissive"
  );

  EnigmailKeyRing.clearCache();
  let details = {};
  let offered = await EnigmailKeyRing.getValidKeysForRecipient(
    ADDRESS,
    details
  );
  Assert.deepEqual(
    offered,
    [key.keyId],
    "an unverified key is offered while the policy is permissive"
  );

  // The strict answer.
  Services.prefs.setBoolPref(PREF, true);
  registerCleanupFunction(() => Services.prefs.clearUserPref(PREF));

  EnigmailKeyRing.clearCache();
  details = {};
  offered = await EnigmailKeyRing.getValidKeysForRecipient(ADDRESS, details);
  Assert.deepEqual(
    offered,
    [],
    "and is refused once the policy requires trust"
  );
  Assert.equal(
    details.msg,
    "ProblemKeyNotTrusted",
    "with the reason that says to judge the key, not to find one"
  );
});

/**
 * Accepting the key as verified satisfies the strict policy.
 *
 * This is the loop the setting depends on: a refusal the user can act on. If
 * judging the key did not change the answer, the strict setting would be a
 * dead end and the dialog offering to fix it would be lying.
 */
add_task(async function judgingTheKeySatisfiesTheStrictPolicy() {
  const key = await importPublicKey();
  registerCleanupFunction(() => PgpSqliteDb2.deleteAcceptance(key.fpr));

  Services.prefs.setBoolPref(PREF, true);
  registerCleanupFunction(() => Services.prefs.clearUserPref(PREF));

  await PgpSqliteDb2.updateAcceptance(key.fpr, [ADDRESS], "unverified");
  EnigmailKeyRing.clearCache();
  Assert.deepEqual(
    await EnigmailKeyRing.getValidKeysForRecipient(ADDRESS, {}),
    [],
    "unverified is refused under the strict policy"
  );

  await PgpSqliteDb2.updateAcceptance(key.fpr, [ADDRESS], "verified");
  EnigmailKeyRing.clearCache();
  const offered = await EnigmailKeyRing.getValidKeysForRecipient(ADDRESS, {});
  Assert.ok(
    offered.includes(key.keyId),
    `accepting it as verified must make it usable, got ${JSON.stringify(offered)}`
  );
});

/**
 * And the Key Assistant must agree with the gate.
 *
 * Reporting the key as accepted while the send path refuses it would have the
 * assistant say the recipient is fine and the send then fail on the same key.
 * Under the strict policy an `unverified` key reads as undecided instead, so
 * the assistant offers the action that actually fixes it.
 */
add_task(async function theAssistantReadinessAgreesWithTheGate() {
  const key = await importPublicKey();
  registerCleanupFunction(() => PgpSqliteDb2.deleteAcceptance(key.fpr));
  await PgpSqliteDb2.updateAcceptance(key.fpr, [ADDRESS], "unverified");

  Services.prefs.clearUserPref(PREF);
  EnigmailKeyRing.clearCache();
  let meta = (await EnigmailKeyRing.getEncryptionKeyMeta(ADDRESS)).find(
    m => m.keyObj?.fpr == key.fpr
  );
  Assert.equal(
    meta?.readiness,
    "accepted",
    "permissive: an unverified key is reported as accepted"
  );

  Services.prefs.setBoolPref(PREF, true);
  registerCleanupFunction(() => Services.prefs.clearUserPref(PREF));
  EnigmailKeyRing.clearCache();
  meta = (await EnigmailKeyRing.getEncryptionKeyMeta(ADDRESS)).find(
    m => m.keyObj?.fpr == key.fpr
  );
  info(`FINDING strict readiness: ${JSON.stringify(meta?.readiness)}`);
  Assert.equal(
    meta?.readiness,
    "undecided",
    "strict: it reads as undecided, so the assistant offers to resolve it"
  );
});
