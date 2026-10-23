/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Stage 4's verification: the internal key store, in the four states the plan
 * names, each asserted on the files rather than on the key list.
 *
 * The states are cumulative and run in order, because the third depends on
 * what the second set up:
 *
 * 1. A fresh profile with no internal key -- no passphrase file at startup.
 * 2. With an internal key -- the passphrase file exists, and so does
 *    secring.gpg, both with real content.
 * 3. Delete the key and both files, then start again -- nothing of substance
 *    comes back.
 * 4. The round trip -- the key the migration puts into GnuPG is protected by
 *    the passphrase the export used, and the import prompted for nothing.
 *
 * States 1 and 2 overlap the tests written for Items 18 and 19, deliberately:
 * this file is the one pass the stage is verified by, and a verification that
 * leans on other files' assertions cannot say what it checked. What it adds is
 * the part those could not cover -- file sizes, the secring, the restart, and
 * protection measured on the migration's own output rather than on a block the
 * test exported itself.
 */

"use strict";

const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { GnuPGAgent } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/gnupgAgent.sys.mjs"
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

const keyDir = "../../../../../test/browser/openpgp/data/keys";
const SECRET_FILE = "alice@openpgp.example-0xf231550c4f47e38e-secret.asc";
const KEY_FPR = "EB85BB5FA33A75E15E944E63F231550C4F47E38E";
const NEW_PASS = "stage-four-passphrase-2026";

/** @returns {nsIFile} The passphrase file. */
function passFile() {
  return OpenPGPMasterpass.getPassPath();
}

/** @returns {nsIFile} The secret keyring file. */
function secRingFile() {
  return OpenPGPMasterpass.getSecretKeyRingFile();
}

/**
 * Size of a file, or -1 when it does not exist.
 *
 * Size rather than presence is what distinguishes a real file from F49's
 * 0-byte stub: `saveKeyRing` writes an empty array when the key count is zero,
 * so a stub is evidence that something wrote, not that a key came back.
 *
 * @param {nsIFile} file - The file to measure.
 * @returns {integer} Bytes, or -1.
 */
function fileSize(file) {
  return file.exists() ? file.fileSize : -1;
}

/** Remove both files and forget the cached passphrase. */
async function clearStoreFiles() {
  for (const file of [passFile(), secRingFile()]) {
    if (file.exists()) {
      await IOUtils.remove(file.path, { ignoreAbsent: true });
    }
  }
  OpenPGPMasterpass.cachedPassword = null;
  OpenPGPMasterpass._initDone = false;
}

/** Remove the fixture key from the profile ring. */
async function removeKey() {
  EnigmailKeyRing.clearCache();
  const keyObj = EnigmailKeyRing.getKeyById(KEY_FPR);
  if (keyObj) {
    await RNP.deleteKey(keyObj.fpr, keyObj.secretAvailable);
  }
  EnigmailKeyRing.clearCache();
}

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();
  await removeKey();
  await clearStoreFiles();
});

/**
 * State 1: no internal key, so no passphrase file after startup.
 *
 * Asserted on absence rather than on size: a 0-byte file here would mean
 * something created it for no reason, which is the defect Item 18 fixed.
 */
add_task(async function state1_fresh_profile_has_no_passphrase_file() {
  EnigmailKeyRing.clearCache();
  Assert.equal(
    RNP.getProtectedKeysCount().reduce((a, b) => a + b, 0),
    0,
    "the profile must hold no secret key for this state to be the one tested"
  );

  await clearStoreFiles();
  await RNP.once();

  // A negative check that reads too early passes vacuously, so let a delayed
  // write land before concluding nothing was written.
  await new Promise(resolve => do_timeout(400, resolve));

  Assert.equal(
    fileSize(passFile()),
    -1,
    "startup must not create the passphrase file when there is nothing to protect"
  );
});

/**
 * State 2: with an internal key, both files exist and both have content.
 *
 * The size assertions are the point. F49 records that an empty key count makes
 * `saveKeyRing` write a 0-byte file, so presence alone proves nothing.
 */
add_task(async function state2_internal_key_gives_real_files() {
  await OpenPGPTestUtils.importPrivateKey(
    null,
    do_get_file(`${keyDir}/${SECRET_FILE}`)
  );
  await RNP.saveKeyRings();
  EnigmailKeyRing.clearCache();

  const [protectedKeys, unprotectedKeys] = RNP.getProtectedKeysCount();
  Assert.greater(
    protectedKeys + unprotectedKeys,
    0,
    "the imported key should be a secret key in the store"
  );

  Assert.greater(
    fileSize(passFile()),
    0,
    "the passphrase file must exist and carry content, not be a 0-byte stub"
  );
  Assert.greater(
    fileSize(secRingFile()),
    0,
    "secring.gpg must exist and carry the key, not be a 0-byte stub"
  );
});

/**
 * State 3: delete the key and both files, then start again -- nothing of
 * substance returns.
 *
 * A 0-byte stub is tolerated and named, because F49 says a keyring write with
 * no keys produces one; what must not appear is a file with content, which
 * would mean the key was restored from somewhere.
 */
add_task(async function state3_deleting_both_does_not_restore_anything() {
  await removeKey();
  await clearStoreFiles();

  Assert.equal(fileSize(passFile()), -1, "starting from no passphrase file");
  Assert.equal(fileSize(secRingFile()), -1, "and no secret keyring");

  // The startup path again, as a restart would run it.
  await RNP.once();
  await new Promise(resolve => do_timeout(400, resolve));

  Assert.equal(
    fileSize(passFile()),
    -1,
    "a restart must not recreate the passphrase file once the key is gone"
  );
  Assert.lessOrEqual(
    fileSize(secRingFile()),
    0,
    "and must not recreate secring.gpg with content; a 0-byte stub is F49's " +
      "empty-count write and not the key coming back"
  );
  Assert.equal(
    RNP.getProtectedKeysCount().reduce((a, b) => a + b, 0),
    0,
    "and no secret key may be present after the restart"
  );
});

/**
 * State 4: the round trip, measured on the migration's own output.
 *
 * Item 20's test checked protection on a block it exported itself with
 * `backupSecretKeys()`, so planting a defect in the migration could not reach
 * it -- and when one was planted, the suite still passed. This one takes the
 * key as the migration left it in a throwaway keyring, so the block under test
 * is the one the product produced.
 */
add_task(
  async function state4_the_migrated_key_is_protected_and_needed_no_prompt() {
    const home = Services.dirsvc.get("ProfD", Ci.nsIFile);
    home.append("gnupg-stage4");
    await IOUtils.makeDirectory(home.path, { ignoreExisting: true });
    await IOUtils.setPermissions(home.path, 0o700);

    const previousHome = Services.env.get("GNUPGHOME");
    Services.env.set("GNUPGHOME", home.path);

    try {
      // Re-import the key, since state 3 removed it.
      await OpenPGPTestUtils.importPrivateKey(
        null,
        do_get_file(`${keyDir}/${SECRET_FILE}`)
      );
      await RNP.saveKeyRings();
      EnigmailKeyRing.clearCache();

      const result = await RNP.migrateSecretKeyToGnuPG(KEY_FPR, NEW_PASS);
      Assert.ok(result.ok, `the migration should succeed: ${result.detail}`);
      Assert.equal(
        result.stage,
        "offer-delete",
        "and stop at offering the deletion"
      );

      // The import ran under --batch, which cannot prompt. Its success is
      // therefore the assertion that no passphrase was asked for: a protected
      // key whose passphrase had to be supplied would have failed there.
      Assert.equal(
        await GnuPGAgent.hasSecretKey(KEY_FPR),
        true,
        "the key reached the keyring through an import that could not prompt"
      );

      // Protected with the passphrase the caller chose, asked of gpg directly.
      const withEmpty = await GnuPGAgent._run("gpg", [
        "--batch",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        "",
        "--export-secret-keys",
      ]);
      Assert.ok(
        !withEmpty.ok,
        "an empty passphrase must not export the migrated key, or it was migrated unprotected"
      );

      const withReal = await GnuPGAgent._run("gpg", [
        "--batch",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        NEW_PASS,
        "--export-secret-keys",
      ]);
      Assert.ok(
        withReal.ok,
        "the passphrase chosen for the export must open it"
      );
    } finally {
      Services.env.set("GNUPGHOME", previousHome ?? "");
      if (home.exists()) {
        await IOUtils.remove(home.path, { recursive: true });
      }
      await removeKey();
      await clearStoreFiles();
    }
  }
);
