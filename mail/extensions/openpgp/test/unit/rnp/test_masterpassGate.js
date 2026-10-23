/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * The automatic OpenPGP passphrase file is created only when it has something
 * to protect.
 *
 * A profile with no internal key used to carry
 * `encrypted-openpgp-passphrase.txt` anyway -- a small envelope over a locally
 * generated secret protecting nothing -- because `RNP.once()` called
 * `ensurePasswordIsCached()` unconditionally at startup. Deleting the file was
 * pointless without gating the creation, because the next start recreated it.
 *
 * Both halves are asserted, and the second is what makes the first mean
 * anything: the file must not appear with no keys, and it must still appear
 * once a key exists. A gate that never creates the file would break every
 * internal key, and only the second test would notice.
 */

"use strict";

const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { OpenPGPMasterpass } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/masterpass.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);

/** The passphrase file this file is about. */
function passPath() {
  return OpenPGPMasterpass.getPassPath();
}

/** Whether the passphrase file exists. */
function passFileExists() {
  return passPath().exists();
}

/** Remove the passphrase file and forget the cached copy. */
async function clearPassphrase() {
  if (passFileExists()) {
    await IOUtils.remove(passPath().path, { ignoreAbsent: true });
  }
  OpenPGPMasterpass.cachedPassword = null;
  OpenPGPMasterpass._initDone = false;
}

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();
});

add_task(async function no_keys_means_no_passphrase_file() {
  EnigmailKeyRing.clearCache();
  Assert.equal(
    RNP.getProtectedKeysCount().reduce((a, b) => a + b, 0),
    0,
    "the profile should hold no secret keys for this to be the case it tests"
  );

  await clearPassphrase();
  Assert.ok(!passFileExists(), "starting from no file");

  // The startup path, with nothing to protect.
  await RNP.once();

  // The file is created on demand rather than at startup, so give a delayed
  // write the chance to land before concluding it did not happen. A negative
  // check that reads too early passes vacuously.
  await new Promise(resolve => do_timeout(400, resolve));

  Assert.ok(
    !passFileExists(),
    "startup must not create the passphrase file when there is no key to protect"
  );
});

add_task(async function a_key_makes_the_file_appear() {
  EnigmailKeyRing.clearCache();
  await clearPassphrase();
  Assert.ok(!passFileExists(), "starting from no file again");

  // The order the wizard uses, which matters: it asks for the automatic
  // password *before* generating, and passes it to genKey(). So the file
  // exists before the key does, and the gate cannot leave a key unprotected by
  // appearing too late.
  const password = await OpenPGPMasterpass.retrieveOpenPGPPassword();
  Assert.ok(password, "the automatic password should be available on demand");
  Assert.ok(
    passFileExists(),
    "asking for the password creates the file, which is the lazy path working"
  );

  const keyId = await RNP.genKey(
    "Gate Test <gate@example.com>",
    "ECC",
    0,
    30,
    password
  );
  Assert.ok(keyId, "a test key should be generated");

  const [protectedKeys, unprotectedKeys] = RNP.getProtectedKeysCount();
  Assert.greater(
    protectedKeys + unprotectedKeys,
    0,
    "the generated key should be a secret key in the store"
  );
  Assert.equal(
    unprotectedKeys,
    0,
    "and it should be protected, because it was given the automatic password"
  );

  // Clean up the key, and the file it caused.
  await RNP.saveKeyRings();
  EnigmailKeyRing.clearCache();
  const keyObj = EnigmailKeyRing.getKeyById(keyId);
  if (keyObj) {
    await RNP.deleteKey(keyObj.fpr, true);
  }
  await clearPassphrase();
  EnigmailKeyRing.clearCache();
});
