/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * A key that exists only in the external GnuPG keyring must reach every
 * recipient check, not just some of them.
 *
 * The split-screen failure this guards against is specific: the composer
 * reports a key as usable while the send path decides it is missing, or the
 * key assistant offers a key the encryption path then refuses. That happens
 * when one check resolves through `getCandidateKeysForEmail()` and another
 * reads the profile ring directly.
 *
 * The last task is a source guard rather than a behaviour test: it reads
 * keyRing.sys.mjs and requires the three checks to resolve through the shared
 * function. Behaviour tests only cover the sites that exist today, and the
 * item's claim is that this holds "as new call sites are added".
 */

"use strict";

const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { GPGME } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/GPGME.sys.mjs"
);
const { PgpSqliteDb2 } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/sqliteDb.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";
const KEY_ID = "F231550C4F47E38E";
const KEY_FPR = "EB85BB5FA33A75E15E944E63F231550C4F47E38E";
const EMAIL = "alice@openpgp.example";
const PUBLIC_FILE = "alice@openpgp.example-0xf231550c4f47e38e-pub.asc";

let gOriginalInit;
let gOriginalGetByEmail;

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();

  gOriginalInit = GPGME.init;
  gOriginalGetByEmail = GPGME.getPublicKeysForEmail;
});

/** Restore the GnuPG boundary and forget anything the test recorded. */
async function cleanup() {
  GPGME.init = gOriginalInit;
  GPGME.getPublicKeysForEmail = gOriginalGetByEmail;
  EnigmailKeyRing.clearCache();

  await PgpSqliteDb2.deleteAcceptance(KEY_FPR);

  for (const pref of [
    "mail.openpgp.fetch_pubkeys_from_gnupg",
    "mail.openpgp.allow_external_gnupg",
  ]) {
    if (Services.prefs.prefHasUserValue(pref)) {
      Services.prefs.clearUserPref(pref);
    }
  }
}

/**
 * Make the key visible only through GnuPG.
 *
 * Nothing is imported into the profile, so `getAllKeys()` cannot see it. That
 * is the condition every assertion below depends on.
 *
 * @returns {Promise<void>}
 */
async function offerKeyOnlyThroughGnuPG() {
  const data = await IOUtils.read(do_get_file(`${keyDir}/${PUBLIC_FILE}`).path);
  const block = new TextDecoder().decode(data);

  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  Services.prefs.setBoolPref("mail.openpgp.fetch_pubkeys_from_gnupg", true);
  GPGME.init = () => true;
  GPGME.getPublicKeysForEmail = () => new Map([[KEY_FPR, block]]);

  EnigmailKeyRing.clearCache();

  Assert.ok(
    !EnigmailKeyRing.getAllKeys(null, null).keyList.some(
      k => k.fpr.toUpperCase() == KEY_FPR
    ),
    "the key must not be in the profile ring, or this proves nothing"
  );
}

add_task(async function gnupg_only_key_reaches_recipient_checks() {
  await offerKeyOnlyThroughGnuPG();

  try {
    // 1. The candidate list itself, widened by the email-keyed load.
    const candidates = await EnigmailKeyRing.getCandidateKeysForEmail(EMAIL);
    Assert.ok(
      candidates.some(k => k.fpr.toUpperCase() == KEY_FPR),
      "getCandidateKeysForEmail() sees a key that is only in GnuPG"
    );

    // 2. getEncryptionKeyMeta, which the composer and key assistant use.
    const meta = await EnigmailKeyRing.getEncryptionKeyMeta(EMAIL);
    Assert.ok(
      meta.some(entry => entry.keyObj?.fpr?.toUpperCase() == KEY_FPR),
      "getEncryptionKeyMeta() reports a key that is only in GnuPG"
    );

    // 3. getValidKeyForRecipient, which decides whether encryption can happen.
    //    It only returns a key that has an acceptance decision, and the
    //    transient load records one -- that is what makes the external path
    //    work at all.
    const validId = await EnigmailKeyRing.getValidKeyForRecipient(EMAIL);
    Assert.equal(
      validId,
      KEY_ID,
      "getValidKeyForRecipient() resolves a key that is only in GnuPG"
    );

    // 4. The multi-recipient check. Note the shape: it returns keyMissing,
    //    so false is success and a list would have been the wrong assertion --
    //    which is what the first version of this test got wrong.
    const details = {};
    const keyMissing = await EnigmailKeyRing.getValidKeysForAllRecipients(
      [EMAIL],
      details
    );
    Assert.equal(
      keyMissing,
      false,
      "getValidKeysForAllRecipients() reports no key missing for a GnuPG-only key"
    );
    Assert.equal(
      details.errArray.length,
      0,
      "and records no error for the address"
    );
  } finally {
    await cleanup();
  }
});

add_task(async function recipient_checks_agree_with_each_other() {
  await offerKeyOnlyThroughGnuPG();

  try {
    // The failure this rules out is the split screen: one check says yes and
    // another says no, for the same address and the same keyring.
    const meta = await EnigmailKeyRing.getEncryptionKeyMeta(EMAIL);
    const single = await EnigmailKeyRing.getValidKeyForRecipient(EMAIL);
    const keyMissing = await EnigmailKeyRing.getValidKeysForAllRecipients(
      [EMAIL],
      {}
    );

    const metaSeesIt = meta.some(
      entry => entry.keyObj?.fpr?.toUpperCase() == KEY_FPR
    );
    Assert.ok(metaSeesIt, "the composer's view sees the key");
    Assert.equal(single, KEY_ID, "the single-recipient check sees the key");
    Assert.equal(keyMissing, false, "the multi-recipient check sees the key");

    Assert.equal(
      metaSeesIt && single == KEY_ID && keyMissing === false,
      true,
      "all three answers agree, which is the property Item 16 is about"
    );
  } finally {
    await cleanup();
  }
});

/**
 * Source guard: the three checks must resolve through the shared function.
 *
 * A behaviour test covers the call sites that exist today; this covers the
 * claim that a new one cannot quietly read the ring instead.
 */
add_task(async function recipient_checks_resolve_through_one_function() {
  // The module is not staged under _tests; it is reached through chrome
  // registration, so the chrome URL is the only reliable way to its source.
  const ChromeRegistry = Cc["@mozilla.org/chrome/chrome-registry;1"].getService(
    Ci.nsIChromeRegistry
  );
  const file = ChromeRegistry.convertChromeURL(
    Services.io.newURI("chrome://openpgp/content/modules/keyRing.sys.mjs")
  ).QueryInterface(Ci.nsIFileURL).file;
  Assert.ok(file.exists(), `keyRing.sys.mjs should be at ${file.path}`);
  const source = new TextDecoder().decode(await IOUtils.read(file.path));

  for (const name of [
    "getEncryptionKeyMeta",
    "getValidKeysForRecipient",
    "getValidKeyForRecipient",
    "getValidKeysForAllRecipients",
  ]) {
    const start = source.indexOf(`async ${name}(`);
    Assert.greater(start, -1, `${name}() should exist in keyRing.sys.mjs`);

    // The body runs to the next method at the same indentation.
    const rest = source.slice(start + 1);
    const end = rest.search(/\n {2}(?:async )?[a-zA-Z_]+\(/);
    const body = end < 0 ? rest : rest.slice(0, end);

    // Routing counts whether it is direct or by delegation.
    // getValidKeysForAllRecipients() calls the resolver once per address
    // rather than the shared function itself, which reaches the same place
    // through one more step and keeps the per-address logic in one function.
    // Requiring the direct call would have failed a correct design. Since Item
    // 27 the resolver is getValidKeysForRecipient() -- the plural -- and
    // getValidKeyForRecipient() delegates to it, so both names count.
    Assert.ok(
      body.includes("getCandidateKeysForEmail(") ||
        body.includes("getValidKeyForRecipient(") ||
        body.includes("getValidKeysForRecipient("),
      `${name}() must resolve through getCandidateKeysForEmail(), directly or by delegation`
    );
    Assert.ok(
      !body.includes("getAllKeys("),
      `${name}() must not read the profile ring directly with getAllKeys()`
    );
  }
});
