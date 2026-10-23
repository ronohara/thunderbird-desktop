/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 22: Thunderbird never asks for a GnuPG key's passphrase.
 *
 * When a key lives in the external keyring, gpg-agent asks through pinentry
 * and Thunderbird must not see the passphrase. The dangerous shape is a prompt
 * raised by Thunderbird for such a key, because that prompt is what makes
 * "unprotect with the passphrase the user just typed" possible -- and that is
 * how a key safe in ~/.gnupg acquires a second, recoverable copy in the
 * profile.
 *
 * The guard lives where the prompt would be raised, not at the call sites, so
 * this test drives the unlock tracker directly: whatever future code reaches
 * it, the prompt cannot happen.
 *
 * Both directions are asserted. A refusal that fired for every key would leave
 * internal keys unusable, and only the second task would notice.
 */

"use strict";

const { RNP, RnpPrivateKeyUnlockTracker } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { GPGME } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/GPGME.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";
// Alice's key, protected with a user-chosen passphrase, so the tracker has
// something real to fail to unlock.
const SECRET_FILE =
  "alice@openpgp.example-0xf231550c4f47e38e-secret-with-pp.asc";
const KEY_FPR = "EB85BB5FA33A75E15E944E63F231550C4F47E38E";

let gOriginalInit;
let gOriginalHasSecretKey;

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();

  gOriginalInit = GPGME.init;
  gOriginalHasSecretKey = GPGME.hasSecretKey;

  // Import keeping the user's own passphrase, so the key is locked.
  // Keep Alice's own passphrase: the signature is
  // (parent, file, acceptance, passphrase, keepPassphrase), and passing null
  // for the passphrase with keepPassphrase true would take the
  // unprotect-with-automatic-passphrase path instead of keeping the key locked.
  await OpenPGPTestUtils.importPrivateKey(
    null,
    do_get_file(`${keyDir}/${SECRET_FILE}`),
    OpenPGPTestUtils.ACCEPTANCE_PERSONAL,
    "alice-passphrase",
    true
  );
  EnigmailKeyRing.clearCache();
});

/**
 * Restore the GnuPG boundary.
 *
 * The fixture key deliberately outlives this: both tasks need it, and deleting
 * it between them caused the second to build a tracker for a key that was
 * gone. Removal happens once, in the cleanup registered at the end.
 */
function restoreBoundary() {
  GPGME.init = gOriginalInit;
  GPGME.hasSecretKey = gOriginalHasSecretKey;
}

/**
 * A tracker for the fixture key, configured to prompt.
 *
 * @param {object} record - Receives `calls`, the number of prompts raised.
 * @returns {RnpPrivateKeyUnlockTracker} The tracker.
 */
function promptingTracker(record) {
  // The same constructor the existing tracker tests use; it resolves the
  // handle against the loaded keyring rather than needing an ffi by hand.
  const tracker = RnpPrivateKeyUnlockTracker.constructFromFingerprint(KEY_FPR);
  tracker.setAllowPromptingUserForPassword(true);
  tracker.setRememberUnlockPassword(true);
  tracker.setPassphraseCallback(() => {
    record.calls++;
    return "alice-passphrase";
  });
  return tracker;
}

add_task(async function a_gnupg_held_key_is_never_prompted_for() {
  GPGME.init = () => true;
  GPGME.hasSecretKey = () => true;

  const record = { calls: 0 };
  const tracker = promptingTracker(record);

  try {
    await tracker.unlock();

    Assert.equal(
      record.calls,
      0,
      "Thunderbird must not prompt for the passphrase of a key GnuPG holds"
    );
    Assert.ok(
      !tracker.isUnlocked(),
      "and the key must stay locked, because no passphrase was obtained"
    );
  } finally {
    tracker.forget();
    restoreBoundary();
  }
});

add_task(async function an_internal_key_is_still_prompted_for() {
  // The control: the same tracker, the same callback, with GnuPG not holding
  // the key. If this did not prompt, the test above would pass for the wrong
  // reason -- a guard that refused everything.
  GPGME.init = () => true;
  GPGME.hasSecretKey = () => false;

  const record = { calls: 0 };
  const tracker = promptingTracker(record);

  try {
    await tracker.unlock();

    Assert.equal(
      record.calls,
      1,
      "a key that lives only in the profile must still be prompted for"
    );
    Assert.ok(
      tracker.isUnlocked(),
      "and the passphrase supplied must unlock it"
    );
  } finally {
    tracker.forget();
    restoreBoundary();
  }
});

/**
 * The import path a passphrase callback serves cannot run for a GnuPG-held key
 * even when the import guard is bypassed.
 *
 * This is Item 23's assertion. `importSecKeyFromFile()` normally refuses such a
 * key before librnp sees it, and the unlock tracker refuses to prompt for one --
 * but both are guards in front of the line that wires the callback up. A new
 * route, or a reordered guard, would reach that line without them. So the
 * binding is checked where the callback is attached, and this task proves it by
 * calling the lower-level import directly, which is what a new route would
 * effectively do.
 *
 * Bob's key is used because no other task in this file imports it, so the
 * "not already present" path is the one exercised.
 */
add_task(async function the_import_cannot_attach_a_prompt_for_a_gnupg_key() {
  const block = new TextDecoder().decode(
    await IOUtils.read(
      do_get_file(
        `${keyDir}/bob@openpgp.example-0xfbfcc82a015e7330-secret-with-pp.asc`
      ).path
    )
  );

  GPGME.init = () => true;
  GPGME.hasSecretKey = () => true;

  const prompted = { calls: 0 };
  const promptWhenAsked = (win, promptString, resultFlags) => {
    prompted.calls++;
    // Cancel at once: the unlock loop repeats until it is cancelled or the
    // passphrase works, and Bob's passphrase is not known here.
    resultFlags.canceled = true;
    return "";
  };

  try {
    await RNP.importSecKeyBlockImpl(null, promptWhenAsked, true, block);

    Assert.equal(
      prompted.calls,
      0,
      "the import must not attach a passphrase prompt for a key GnuPG holds, " +
        "even when reached without the guard above it"
    );
  } finally {
    restoreBoundary();
    EnigmailKeyRing.clearCache();
    // Bob's key must not have been persisted either.
    for (const keyId of ["FBFCC82A015E7330"]) {
      const keyObj = EnigmailKeyRing.getKeyById(keyId);
      if (keyObj) {
        await RNP.deleteKey(keyObj.fpr, keyObj.secretAvailable);
      }
    }
    EnigmailKeyRing.clearCache();
  }
});

/**
 * The control for the task above: with GnuPG not holding the key, the same
 * direct import does ask, so the refusal is not a blanket one.
 */
add_task(async function the_import_still_asks_when_gnupg_lacks_the_key() {
  const block = new TextDecoder().decode(
    await IOUtils.read(
      do_get_file(
        `${keyDir}/bob@openpgp.example-0xfbfcc82a015e7330-secret-with-pp.asc`
      ).path
    )
  );

  GPGME.init = () => true;
  GPGME.hasSecretKey = () => false;

  const prompted = { calls: 0 };
  const promptWhenAsked = (win, promptString, resultFlags) => {
    prompted.calls++;
    resultFlags.canceled = true;
    return "";
  };

  try {
    await RNP.importSecKeyBlockImpl(null, promptWhenAsked, true, block);
    Assert.greater(
      prompted.calls,
      0,
      "an internal key whose passphrase is needed must still be asked about"
    );
  } finally {
    restoreBoundary();
    EnigmailKeyRing.clearCache();
    const keyObj = EnigmailKeyRing.getKeyById("FBFCC82A015E7330");
    if (keyObj) {
      await RNP.deleteKey(keyObj.fpr, keyObj.secretAvailable);
    }
    EnigmailKeyRing.clearCache();
  }
});

registerCleanupFunction(async function () {
  restoreBoundary();
  EnigmailKeyRing.clearCache();
  const keyObj = EnigmailKeyRing.getKeyById(KEY_FPR);
  if (keyObj) {
    await RNP.deleteKey(keyObj.fpr, keyObj.secretAvailable);
  }
  EnigmailKeyRing.clearCache();
});
