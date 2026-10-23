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
let gOriginalHasPublicKey;

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();

  gOriginalInit = GPGME.init;
  gOriginalHasSecretKey = GPGME.hasSecretKey;
  gOriginalHasPublicKey = GPGME.hasPublicKey;
});

/**
 * Stub the GnuPG boundary.
 *
 * @param {boolean|Function} held - What hasSecretKey() should answer.
 * @param {object} counter - Tallies the calls, in `lookups` and `publicLookups`.
 * @param {object} [options] - What the stub should answer.
 * @param {boolean} [options.readable] - Whether GPGME.init() succeeds.
 * @param {boolean} [options.publicHeld] - What hasPublicKey() answers; defaults
 *   to the same answer as hasSecretKey().
 */
function stubGnuPG(held, counter, { readable = true, publicHeld } = {}) {
  GPGME.init = () => readable;
  GPGME.hasSecretKey = () => {
    counter.lookups++;
    return typeof held == "function" ? held() : held;
  };
  GPGME.hasPublicKey = () => {
    counter.publicLookups = (counter.publicLookups ?? 0) + 1;
    return publicHeld === undefined ? held : publicHeld;
  };
}

/** Restore the module and the pref between tasks. */
async function restoreGnuPG() {
  GPGME.init = gOriginalInit;
  GPGME.hasSecretKey = gOriginalHasSecretKey;
  GPGME.hasPublicKey = gOriginalHasPublicKey;
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

add_task(async function public_block_does_no_secret_key_lookup() {
  const block = await readKeyFixture(PUBLIC_FILE);
  const counter = { lookups: 0 };
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  Services.prefs.setBoolPref("mail.openpgp.fetch_pubkeys_from_gnupg", true);
  // Item 10 needs one public lookup per public import, so it cannot be zero.
  // What is still true, and is what this task pins: the secret-key listing is
  // never reached for a public block. The asymmetry is what makes a secret
  // import cost more than a public one.
  stubGnuPG(true, counter, { publicHeld: false });

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
      "an armored public block must not trigger a secret-key lookup"
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

add_task(async function importSecKeyFromFile_refuses_a_key_gnupg_lacks() {
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

    Assert.equal(
      exitCode,
      1,
      "with the external path in use, a key GnuPG lacks is an error rather than a refusal"
    );
    Assert.ok(
      errorMsgObj.value,
      "the error should carry a message the wizard can show"
    );
    Assert.equal(
      importedKeysObj.keys.length,
      0,
      "no key should be reported as imported"
    );

    EnigmailKeyRing.clearCache();
    const keyObj = EnigmailKeyRing.getKeyById(KEY_ID);
    Assert.ok(
      !keyObj || !keyObj.secretAvailable,
      "and nothing is written to the profile store"
    );
  } finally {
    await restoreGnuPG();
  }
});

add_task(async function importSecKeyFromFile_permits_without_gnupg() {
  const counter = { lookups: 0 };
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  // The pref is on but GnuPG cannot load: the case of a machine with no gpg.
  // There is no destination in GnuPG, so refusing would strand the user.
  stubGnuPG(false, counter, { readable: false });

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

    Assert.equal(exitCode, 0, "the import should succeed when GnuPG is absent");
    Assert.greater(
      importedKeysObj.keys.length,
      0,
      "the imported key should be reported"
    );

    EnigmailKeyRing.clearCache();
    const keyObj = EnigmailKeyRing.getKeyById(KEY_ID);
    Assert.ok(
      keyObj?.secretAvailable,
      "with no GnuPG to hold the key, the internal store takes it"
    );
  } finally {
    await removeFixtureKey();
    await restoreGnuPG();
  }
});

add_task(async function public_key_gnupg_holds_is_not_persisted() {
  const block = await readKeyFixture(PUBLIC_FILE);
  const counter = { lookups: 0 };
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  Services.prefs.setBoolPref("mail.openpgp.fetch_pubkeys_from_gnupg", true);
  stubGnuPG(true, counter, { publicHeld: true });

  // The transient load this guard performs reads the key back out of GnuPG.
  const originalGetById = GPGME.getPublicKeysForId;
  GPGME.getPublicKeysForId = () => new Map();

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

    Assert.equal(exitCode, 0, "the refusal is shaped like success");
    Assert.ok(!errorMsgObj.value, "and carries no error message");
    Assert.greater(
      counter.publicLookups ?? 0,
      0,
      "the guard should have asked GnuPG for the public key"
    );

    const after = EnigmailKeyRing.getAllKeys(null, null).keyList.length;
    Assert.equal(
      after,
      before,
      "a public key GnuPG holds is not written to the profile"
    );
  } finally {
    GPGME.getPublicKeysForId = originalGetById;
    await restoreGnuPG();
  }
});

add_task(async function public_key_gnupg_lacks_is_persisted() {
  const block = await readKeyFixture(PUBLIC_FILE);
  const counter = { lookups: 0 };
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  Services.prefs.setBoolPref("mail.openpgp.fetch_pubkeys_from_gnupg", true);
  stubGnuPG(false, counter, { publicHeld: false });

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
    EnigmailKeyRing.clearCache();
    Assert.ok(
      EnigmailKeyRing.getKeyById(KEY_ID),
      "a public key GnuPG lacks is still persisted, which is what makes it usable"
    );
  } finally {
    await removeFixtureKey();
    await restoreGnuPG();
  }
});

add_task(
  async function public_key_is_persisted_when_the_transient_path_is_off() {
    const block = await readKeyFixture(PUBLIC_FILE);
    const counter = { lookups: 0 };
    // The pref that fills the transient cache is off, so refusing to persist
    // would leave the key reachable from nowhere.
    Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
    Services.prefs.setBoolPref("mail.openpgp.fetch_pubkeys_from_gnupg", false);
    stubGnuPG(true, counter, { publicHeld: true });

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
      EnigmailKeyRing.clearCache();
      Assert.ok(
        EnigmailKeyRing.getKeyById(KEY_ID),
        "with no transient path the key is persisted rather than lost"
      );
    } finally {
      await removeFixtureKey();
      await restoreGnuPG();
    }
  }
);

add_task(async function import_is_permitted_with_the_pref_off() {
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
