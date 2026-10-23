/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests for the import guard: a secret key that the external GnuPG keyring
 * holds must not acquire a second copy in the profile.
 *
 * The GnuPG boundary is stubbed rather than exercised. What is under test is
 * the decision the guard makes, not the keyring's contents, and a real gpg
 * would make the result depend on whatever happens to be in ~/.gnupg on the
 * machine that runs the test.
 *
 * Two routes are covered because they do different things with the same file.
 * `importKeyAsync()` parses a block and imports its public parts, so it can
 * put a public copy in the profile ring. `importSecKeyFromFile()` is the route
 * that writes secret material, unprotecting the key and re-protecting it with
 * the automatic passphrase -- the downgrade design 1.5 measured.
 */

"use strict";

const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { GPGME } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/GPGME.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";
const KEY_ID = "F231550C4F47E38E";
const SECRET_FILE = "alice@openpgp.example-0xf231550c4f47e38e-secret.asc";
const PUBLIC_FILE = "alice@openpgp.example-0xf231550c4f47e38e-pub.asc";

let gOriginalInit;
let gOriginalHasSecretKey;

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();

  gOriginalInit = GPGME.init;
  gOriginalHasSecretKey = GPGME.hasSecretKey;
});

/**
 * Stub the GnuPG boundary.
 *
 * @param {boolean|Function} held - What hasSecretKey() should answer.
 * @param {object} counter - Object whose `lookups` property is incremented.
 */
function stubGnuPG(held, counter) {
  GPGME.init = () => true;
  GPGME.hasSecretKey = () => {
    counter.lookups++;
    return typeof held == "function" ? held() : held;
  };
}

/** Restore the module and the pref between tasks. */
async function restoreGnuPG() {
  GPGME.init = gOriginalInit;
  GPGME.hasSecretKey = gOriginalHasSecretKey;
  if (Services.prefs.prefHasUserValue("mail.openpgp.allow_external_gnupg")) {
    Services.prefs.clearUserPref("mail.openpgp.allow_external_gnupg");
  }
  EnigmailKeyRing.clearCache();
}

/**
 * Read a fixture as a string.
 *
 * @param {string} name - File name under the shared key fixtures.
 * @returns {Promise<string>} The file's contents.
 */
async function readKeyFixture(name) {
  const data = await IOUtils.read(do_get_file(`${keyDir}/${name}`).path);
  return new TextDecoder().decode(data);
}

/** Remove the fixture key from the profile ring, if it is there. */
async function removeFixtureKey() {
  EnigmailKeyRing.clearCache();
  const keyObj = EnigmailKeyRing.getKeyById(KEY_ID);
  if (keyObj) {
    await RNP.deleteKey(keyObj.fpr, keyObj.secretAvailable);
    EnigmailKeyRing.clearCache();
  }
}

add_task(async function importKeyAsync_refuses_when_gnupg_holds_it() {
  const block = await readKeyFixture(SECRET_FILE);
  const counter = { lookups: 0 };
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  stubGnuPG(true, counter);

  try {
    const before = EnigmailKeyRing.getAllKeys(null, null).keyList.length;
    const errorMsgObj = {};
    const exitCode = await EnigmailKeyRing.importKeyAsync(
      null,
      false,
      block,
      false,
      "",
      errorMsgObj,
      null
    );

    Assert.equal(exitCode, 0, "a refusal should be shaped like success");
    Assert.ok(!errorMsgObj.value, "a refusal should not set an error message");
    Assert.greater(counter.lookups, 0, "the guard should have asked GnuPG");

    const after = EnigmailKeyRing.getAllKeys(null, null).keyList.length;
    Assert.equal(
      after,
      before,
      "nothing at all should be added to the profile ring, not even the public part"
    );
  } finally {
    await restoreGnuPG();
  }
});

add_task(async function importKeyAsync_permits_a_key_gnupg_lacks() {
  const block = await readKeyFixture(SECRET_FILE);
  const counter = { lookups: 0 };
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  stubGnuPG(false, counter);

  try {
    const errorMsgObj = {};
    const exitCode = await EnigmailKeyRing.importKeyAsync(
      null,
      false,
      block,
      false,
      "",
      errorMsgObj,
      null
    );

    Assert.equal(exitCode, 0, "the import should succeed");
    Assert.greater(counter.lookups, 0, "the guard should have asked GnuPG");

    EnigmailKeyRing.clearCache();
    const keyObj = EnigmailKeyRing.getKeyById(KEY_ID);
    Assert.ok(keyObj, "the key should be in the ring after a permitted import");
    Assert.ok(
      !keyObj.secretAvailable,
      "importKeyAsync imports public parts only, so no secret copy is made here"
    );
  } finally {
    await removeFixtureKey();
    await restoreGnuPG();
  }
});

add_task(async function public_block_costs_no_lookup() {
  const block = await readKeyFixture(PUBLIC_FILE);
  const counter = { lookups: 0 };
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  stubGnuPG(true, counter);

  try {
    const errorMsgObj = {};
    const exitCode = await EnigmailKeyRing.importKeyAsync(
      null,
      false,
      block,
      false,
      "",
      errorMsgObj,
      null
    );

    Assert.equal(exitCode, 0, "a public key import should succeed");
    Assert.equal(
      counter.lookups,
      0,
      "an armored public block must not reach GnuPG at all"
    );

    EnigmailKeyRing.clearCache();
    Assert.ok(
      EnigmailKeyRing.getKeyById(KEY_ID),
      "the public key should be in the ring"
    );
  } finally {
    await removeFixtureKey();
    await restoreGnuPG();
  }
});

add_task(async function importSecKeyFromFile_refuses_when_gnupg_holds_it() {
  const counter = { lookups: 0 };
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  stubGnuPG(true, counter);

  try {
    const errorMsgObj = {};
    const importedKeysObj = {};
    const exitCode = await EnigmailKeyRing.importSecKeyFromFile(
      null,
      () => "",
      false,
      do_get_file(`${keyDir}/${SECRET_FILE}`),
      errorMsgObj,
      importedKeysObj
    );

    Assert.equal(exitCode, 0, "a refusal should be shaped like success");
    Assert.equal(
      importedKeysObj.keys.length,
      0,
      "no key should be reported as imported"
    );

    EnigmailKeyRing.clearCache();
    const keyObj = EnigmailKeyRing.getKeyById(KEY_ID);
    Assert.ok(
      !keyObj || !keyObj.secretAvailable,
      "the secret key must not exist in the profile after the refusal"
    );
  } finally {
    await restoreGnuPG();
  }
});

add_task(async function importSecKeyFromFile_permits_a_key_gnupg_lacks() {
  const counter = { lookups: 0 };
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  stubGnuPG(false, counter);

  try {
    const errorMsgObj = {};
    const importedKeysObj = {};
    const exitCode = await EnigmailKeyRing.importSecKeyFromFile(
      null,
      () => "",
      false,
      do_get_file(`${keyDir}/${SECRET_FILE}`),
      errorMsgObj,
      importedKeysObj
    );

    Assert.equal(exitCode, 0, "the import should succeed");
    Assert.greater(
      importedKeysObj.keys.length,
      0,
      "the imported key should be reported"
    );

    EnigmailKeyRing.clearCache();
    const keyObj = EnigmailKeyRing.getKeyById(KEY_ID);
    Assert.ok(
      keyObj?.secretAvailable,
      "this route does write the secret key when the guard permits it"
    );
  } finally {
    await removeFixtureKey();
    await restoreGnuPG();
  }
});

add_task(async function guard_defers_to_the_pref() {
  const counter = { lookups: 0 };
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", false);
  stubGnuPG(true, counter);

  try {
    const errorMsgObj = {};
    const importedKeysObj = {};
    const exitCode = await EnigmailKeyRing.importSecKeyFromFile(
      null,
      () => "",
      false,
      do_get_file(`${keyDir}/${SECRET_FILE}`),
      errorMsgObj,
      importedKeysObj
    );

    Assert.equal(exitCode, 0, "the import should succeed with the pref off");
    Assert.equal(
      counter.lookups,
      0,
      "the guard must not consult GnuPG when the external path is off"
    );

    EnigmailKeyRing.clearCache();
    const keyObj = EnigmailKeyRing.getKeyById(KEY_ID);
    Assert.ok(
      keyObj?.secretAvailable,
      "with the external path off the secret key is imported, by decision"
    );
  } finally {
    await removeFixtureKey();
    await restoreGnuPG();
  }
});
