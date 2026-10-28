/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import { AppConstants } from "resource://gre/modules/AppConstants.sys.mjs";
// Imported directly rather than through a lazy getter: from this chrome://
// module, defineESModuleGetters on this resource:/// module resolves to
// undefined, while a direct import works. Verified in xpcshell with a probe.
import { requirePrimaryPassword } from "resource:///modules/PrimaryPassword.sys.mjs";

const lazy = {};
ChromeUtils.defineESModuleGetters(lazy, {
  EnigmailConstants: "chrome://openpgp/content/modules/constants.sys.mjs",
  EnigmailFuncs: "chrome://openpgp/content/modules/funcs.sys.mjs",
  GPGME: "chrome://openpgp/content/modules/GPGME.sys.mjs",
  GnuPGAgent: "chrome://openpgp/content/modules/gnupgAgent.sys.mjs",
  MailStringUtils: "resource:///modules/MailStringUtils.sys.mjs",
  OpenPGPMasterpass: "chrome://openpgp/content/modules/masterpass.sys.mjs",
  PgpSqliteDb2: "chrome://openpgp/content/modules/sqliteDb.sys.mjs",
  RNPLibLoader: "chrome://openpgp/content/modules/RNPLib.sys.mjs",
  ctypes: "resource://gre/modules/ctypes.sys.mjs",
});
ChromeUtils.defineLazyGetter(lazy, "log", () => {
  return console.createInstance({
    prefix: "openpgp",
    maxLogLevel: "Warn",
    maxLogLevelPref: "openpgp.loglevel",
  });
});

var l10n = new Localization(["messenger/openpgp/openpgp.ftl"]);

const RNP_PHOTO_USERID_ID = "(photo)"; // string is hardcoded inside RNP

// The only post-quantum encryption algorithm we support.
const PQC_ENCRYPTION_ALGO = "ML-KEM-768+X25519";

var RNPLib;

/**
 * Opens a prompt, asking the user to enter passphrase for given key id.

 * @param {?nsIWindow} win - Parent window, may be null
 * @param {string} promptString - This message will be shown to the user
 * @param {object} resultFlags - Attribute .canceled is set to true
 *   if the user clicked cancel, other it's set to false.
 * @returns {string} - The passphrase the user entered
 */
function passphrasePromptCallback(win, promptString, resultFlags) {
  const password = { value: "" };
  if (!Services.prompt.promptPassword(win, "", promptString, password)) {
    resultFlags.canceled = true;
    return "";
  }

  resultFlags.canceled = false;
  return password.value;
}

/**
 * Helper class to track resources related to a private/secret key,
 * holding the key handle obtained from RNP, and offering services
 * related to that key and its handle, including releasing the handle
 * when done. Tracking a null handle is allowed.
 */
export class RnpPrivateKeyUnlockTracker {
  #rnpKeyHandle = null;
  #wasUnlocked = false;
  #allowPromptingUserForPassword = false;
  #allowAutoUnlockWithCachedPasswords = false;
  #passwordCache = null;
  #fingerprint = "";
  #passphraseCallback = null;
  #rememberUnlockPasswordForUnprotect = false;
  #unlockPassword = null;
  #isLocked = true;
  #secretMaterialAvailable = false;
  #allowRelockToCapturePassword = false;

  /**
   * Initialize this object as a tracker for the private key identified
   * by the given fingerprint. The fingerprint will be looked up in an
   * RNP space (FFI) and the resulting handle will be tracked. The
   * default FFI is used for performing the lookup, unless a specific
   * FFI is given. If no key can be found, the object is initialized
   * with a null handle. If a handle was found, the handle and any
   * additional resources can be freed by calling the object's release()
   * method.
   *
   * @param {string} fingerprint - the fingerprint of a key to look up.
   * @param {rnp_ffi_t} ffi - An optional specific FFI.
   * @returns {RnpPrivateKeyUnlockTracker} - a new instance, which was
   *   either initialized with a found key handle, or with null-
   */
  static constructFromFingerprint(fingerprint, ffi = RNPLib.ffi) {
    if (fingerprint.startsWith("0x")) {
      throw new Error("fingerprint must not start with 0x");
    }

    const handle = RNP.getKeyHandleByKeyIdOrFingerprint(
      ffi,
      `0x${fingerprint}`
    );

    return new RnpPrivateKeyUnlockTracker(handle);
  }

  /**
   * Construct this object as a tracker for the private key referenced
   * by the given handle. The object may also be initialized
   * with null, if no key was found. A valid handle and any additional
   * resources can be freed by calling the object's release() method.
   *
   * @param {?rnp_key_handle_t} handle - the handle of a RNP key, or null
   */
  constructor(handle) {
    if (this.#rnpKeyHandle) {
      throw new Error("Instance already initialized");
    }
    if (!handle) {
      return;
    }
    this.#rnpKeyHandle = handle;

    if (!this.available()) {
      // Not a private key. We tolerate this use to enable automatic
      // handle releasing, for code that sometimes needs to track a
      // secret key, and sometimes only a public key.
      // The only functionality that is allowed on such a key is to
      // call the .available() and the .release() methods.
      this.#isLocked = false;
    } else {
      this.#secretMaterialAvailable = true;
      const is_locked = new lazy.ctypes.bool();
      if (RNPLib.rnp_key_is_locked(this.#rnpKeyHandle, is_locked.address())) {
        throw new Error("rnp_key_is_locked failed");
      }
      this.#isLocked = is_locked.value;
    }

    if (!this.#fingerprint) {
      const fingerprint = new lazy.ctypes.char.ptr();
      if (
        RNPLib.rnp_key_get_fprint(this.#rnpKeyHandle, fingerprint.address())
      ) {
        throw new Error("rnp_key_get_fprint failed");
      }
      this.#fingerprint = fingerprint.readString();
      RNPLib.rnp_buffer_destroy(fingerprint);
    }
  }

  /**
   * @param {Function} cb - Override the callback function that this
   *   object will call to obtain the passphrase to unlock the private
   *   key for tracked key handle, if the object needs to unlock
   *   the key and prompting the user is allowed.
   *   If no alternative callback is set, the global
   *   passphrasePromptCallback function will be used.
   */
  setPassphraseCallback(cb) {
    this.#passphraseCallback = cb;
  }

  /**
   * Allow or forbid prompting the user for a passphrase.
   *
   * @param {boolean} isAllowed - True if allowed, false if forbidden
   */
  setAllowPromptingUserForPassword(isAllowed) {
    this.#allowPromptingUserForPassword = isAllowed;
  }

  /**
   * Allow or forbid automatically using passphrases from a configured
   * cache of passphrase, if it's necessary to obtain a passphrase
   * for unlocking.
   *
   * @param {boolean} isAllowed - True if allowed, false if forbidden
   */
  setAllowAutoUnlockWithCachedPasswords(isAllowed) {
    this.#allowAutoUnlockWithCachedPasswords = isAllowed;
  }

  /**
   * Allow or forbid this object to remember the passphrase that was
   * successfully used to to unlock it. This is necessary when intending
   * to subsequently call the unprotect() function to remove the key's
   * passphrase protection. Care should be taken that a tracker object
   * with a remembered passphrase is held in memory only for a short
   * amount of time, and should be released as soon as a task has
   * completed.
   *
   * @param {boolean} isAllowed - True if allowed, false if forbidden
   */
  setRememberUnlockPassword(isAllowed) {
    this.#rememberUnlockPasswordForUnprotect = isAllowed;
  }

  /**
   * Allow this object to lock the tracked key, if it is found already
   * unlocked, so that unlock() can learn the passphrase that protects
   * it. Without this, a key that other code has already unlocked cannot
   * report its passphrase, because this object never saw it, and
   * getUnlockPassword() returns null.
   * Only useful in combination with setRememberUnlockPassword(true).
   * The key is left unlocked when this object is released, because the
   * code that unlocked it may still be relying on that.
   *
   * @param {boolean} isAllowed - True if allowed, false if forbidden
   */
  setAllowRelockToCapturePassword(isAllowed) {
    this.#allowRelockToCapturePassword = isAllowed;
  }

  /**
   * Registers a reference to shared object that implements an optional
   * password cache. Will be used to look up passwords if
   * #allowAutoUnlockWithCachedPasswords is set to true. Will be used
   * to store additional passwords that are found to unlock a key.
   *
   * @param cacheObj
   */
  setPasswordCache(cacheObj) {
    this.#passwordCache = cacheObj;
  }

  /**
   * Completely remove the encryption layer that protects the private
   * key. Requires that setRememberUnlockPassword(true) was already
   * called on this object, prior to unlocking the key, because this
   * code requires that the unlock/unprotect passphrase has been cached
   * in this object already, and that the tracked key has already been
   * unlocked.
   */
  unprotect() {
    if (!this.#rnpKeyHandle) {
      return;
    }

    const is_protected = new lazy.ctypes.bool();
    if (
      RNPLib.rnp_key_is_protected(this.#rnpKeyHandle, is_protected.address())
    ) {
      throw new Error("rnp_key_is_protected failed");
    }
    if (!is_protected.value) {
      return;
    }

    if (!this.#wasUnlocked || !this.#rememberUnlockPasswordForUnprotect) {
      // This precondition ensures we have the correct password cached.
      throw new Error("Key should have been unlocked already.");
    }

    if (RNPLib.rnp_key_unprotect(this.#rnpKeyHandle, this.#unlockPassword)) {
      throw new Error(`Failed to unprotect private key ${this.#fingerprint}`);
    }
  }

  /**
   * Attempt to unlock the tracked key with the given passphrase,
   * can also be used with the empty string, which will unlock the key
   * if no passphrase is set.
   *
   * @param {string} pass - try to unlock the key using this passphrase
   */
  unlockWithPassword(pass) {
    if (!this.#rnpKeyHandle || !this.#isLocked) {
      return;
    }
    this.#wasUnlocked = false;

    if (!RNPLib.rnp_key_unlock(this.#rnpKeyHandle, pass)) {
      this.#noteUnlocked(pass, false);
    }
  }

  /**
   * Attempt to unlock the tracked key, using the allowed unlock
   * mechanisms that have been configured/allowed for this tracker,
   * which must been configured as desired prior to calling this function.
   * Attempts will potentially be made to unlock using the automatic
   * passphrase, or using password available in the password cache,
   * or by prompting the user for a password, repeatedly prompting
   * until the user enters the correct password or cancels.
   * When prompting the user for a passphrase, and the key is a subkey,
   * it might be necessary to lookup the primary key. A RNP FFI handle
   * is necessary for that potential lookup.
   * Unless a ffi parameter is provided, the default ffi is used.
   *
   * @param {rnp_ffi_t} ffi - An optional specific FFI.
   */
  async unlock(ffi = RNPLib.ffi) {
    if (!this.#rnpKeyHandle) {
      return;
    }

    // If the key is already unlocked, we never saw the passphrase, so we
    // cannot remember it. Lock the key first, to obtain the passphrase
    // below. Remember that we found it unlocked, so that release() will
    // leave it unlocked for whichever code unlocked it.
    let foundUnlocked = false;
    if (
      !this.#isLocked &&
      this.#secretMaterialAvailable &&
      this.#allowRelockToCapturePassword &&
      this.#rememberUnlockPasswordForUnprotect &&
      this.#unlockPassword === null
    ) {
      RNPLib.rnp_key_lock(this.#rnpKeyHandle);
      this.#isLocked = true;
      foundUnlocked = true;
    }

    if (!this.#isLocked) {
      return;
    }
    this.#wasUnlocked = false;
    const autoPassword = await lazy.OpenPGPMasterpass.retrieveOpenPGPPassword();

    if (!RNPLib.rnp_key_unlock(this.#rnpKeyHandle, autoPassword)) {
      this.#noteUnlocked(autoPassword, foundUnlocked);
      return;
    }

    if (this.#allowAutoUnlockWithCachedPasswords && this.#passwordCache) {
      for (const pw of this.#passwordCache.passwords) {
        if (!RNPLib.rnp_key_unlock(this.#rnpKeyHandle, pw)) {
          this.#noteUnlocked(pw, foundUnlocked);
          return;
        }
      }
    }

    if (!this.#allowPromptingUserForPassword) {
      if (foundUnlocked) {
        // Restore the state we found, we couldn't obtain the passphrase.
        RNPLib.rnp_key_unlock(this.#rnpKeyHandle, autoPassword);
      }
      return;
    }

    // No path asks for a GnuPG passphrase.
    //
    // For a key whose protection lives in the external keyring, gpg-agent asks
    // through pinentry when the key is used, and Thunderbird must never see
    // that passphrase. A prompt raised here would be Thunderbird asking for a
    // GnuPG key's passphrase, which is the thing this stage exists to prevent:
    // it is what makes "unprotect with the passphrase the user just typed"
    // possible, and that is how a key safe in ~/.gnupg acquires a second,
    // recoverable copy in the profile.
    //
    // This is a mechanism rather than a rule about call sites. The check sits
    // where the prompt would be raised, so any future caller that routes a
    // GnuPG-held key here still cannot prompt -- the item asks for that
    // explicitly, because the call graph will change and a convention would
    // not survive it.
    //
    // It refuses rather than throws, on purpose. Decryption reaches this code
    // with prompting allowed, and a throw would abort the decryption instead
    // of letting librnp report "cannot decrypt" -- which is what makes the
    // caller fall through to gpg, where the key actually lives and where no
    // prompt is needed. The downgrade path is still closed: unprotect()
    // requires a remembered password, so refusing to capture one makes it
    // throw its own precondition error before anything is written.
    if (this.#fingerprint && lazy.GPGME.init()) {
      const held = lazy.GPGME.hasSecretKey(this.#fingerprint);
      if (held) {
        lazy.log.warn(
          `Not prompting for the passphrase of ${this.#fingerprint}: the ` +
            `external GnuPG keyring holds this key, and its passphrase is ` +
            `gpg-agent's to ask for, never Thunderbird's.`
        );
        if (foundUnlocked) {
          // Restore the state we found, as the non-prompting branch above does.
          RNPLib.rnp_key_unlock(this.#rnpKeyHandle, autoPassword);
        }
        return;
      }
    }

    const promptString = await RNP.getPassphrasePrompt(this.#rnpKeyHandle, ffi);
    while (true) {
      const userFlags = { canceled: false };
      let pass;
      if (this.#passphraseCallback) {
        pass = this.#passphraseCallback(null, promptString, userFlags);
      } else {
        pass = passphrasePromptCallback(null, promptString, userFlags);
      }
      if (userFlags.canceled) {
        return;
      }

      if (!RNPLib.rnp_key_unlock(this.#rnpKeyHandle, pass)) {
        this.#noteUnlocked(pass, foundUnlocked);

        if (this.#passwordCache) {
          this.#passwordCache.passwords.push(pass);
        }
        return;
      }
    }
  }

  /**
   * Record that the tracked key was unlocked using the given passphrase.
   *
   * @param {string} pass - The passphrase that unlocked the key.
   * @param {boolean} foundUnlocked - True if this object had found the
   *   key already unlocked and locked it only to learn the passphrase.
   *   In that case release() must not lock the key again.
   */
  #noteUnlocked(pass, foundUnlocked) {
    this.#isLocked = false;
    this.#wasUnlocked = !foundUnlocked;
    if (this.#rememberUnlockPasswordForUnprotect) {
      this.#unlockPassword = pass;
    }
  }

  /**
   * Check that this tracker has a reference to a private key.
   *
   * @returns {boolean} - true if the tracked key is a secret/private
   */
  isSecret() {
    return (
      this.#rnpKeyHandle &&
      RNPLib.getSecretAvailableFromHandle(this.#rnpKeyHandle)
    );
  }

  /**
   * Check that this tracker has a reference to a valid private key.
   * The check will fail e.g. for offline secret keys, where a
   * primary key is marked as being a secret key, but not having
   * the raw key data available. (In that scenario, the raw key data
   * for subkeys is usually available.)
   *
   * @returns {boolean} - true if the tracked key is a secret/private
   *   key with its key material available.
   */
  available() {
    return (
      this.#rnpKeyHandle &&
      RNPLib.getSecretAvailableFromHandle(this.#rnpKeyHandle) &&
      RNPLib.isSecretKeyMaterialAvailable(this.#rnpKeyHandle)
    );
  }

  /**
   * Obtain the raw RNP key handle managed by this tracker.
   * The returned handle may be temporarily used by the caller,
   * but the caller must not destroy the handle. The returned handle
   * will become invalid as soon as the release() function is called
   * on this tracker object.
   *
   * @returns {rnp_key_handle_t} - the handle of the tracked private key
   *   or null, if no key is tracked by this tracker.
   */
  getHandle() {
    return this.#rnpKeyHandle;
  }

  /**
   * @returns {string} - key fingerprint of the tracked key, or the
   *   empty string.
   */
  getFingerprint() {
    return this.#fingerprint;
  }

  /**
   * A key without secret key material available cannot be unlocked, and
   * cannot be used for operations that require the secret key. Such a
   * key is tracked as not locked, to allow automatic handle releasing,
   * so the locked flag alone isn't sufficient to answer this question.
   *
   * @returns {boolean} - true if the tracked key is a private key with
   *   its key material available, and is currently unlocked.
   */
  isUnlocked() {
    return this.#secretMaterialAvailable && !this.#isLocked;
  }

  /**
   * @returns {string} - the password that was previously used to
   *   unlock the secret key, if a call to setRememberUnlockPassword
   *   allowed remembering it.
   *   May return null if the password isn't available.
   */
  getUnlockPassword() {
    if (!this.#rnpKeyHandle) {
      return null;
    }

    return this.#unlockPassword;
  }

  /**
   * Protect the key with the automatic passphrase mechanism, that is,
   * using the classic mechanism that uses an automatically generated
   * passphrase, which is either unprotected, or protected by the
   * primary password.
   * Requires that the key is unlocked already.
   */
  async setAutoPassphrase() {
    if (!this.#rnpKeyHandle) {
      return;
    }

    const autoPassword = await lazy.OpenPGPMasterpass.retrieveOpenPGPPassword();
    if (
      RNPLib.rnp_key_protect(
        this.#rnpKeyHandle,
        autoPassword,
        null,
        null,
        null,
        0
      )
    ) {
      throw new Error(`rnp_key_protect failed for ${this.#fingerprint}`);
    }
  }

  /**
   * Protect the key with the given passphrase.
   * Requires that the key is unlocked already.
   *
   * @param {string} pass - protect the key with this passphrase
   */
  setPassphrase(pass) {
    if (!this.#rnpKeyHandle) {
      return;
    }

    if (RNPLib.rnp_key_protect(this.#rnpKeyHandle, pass, null, null, null, 0)) {
      throw new Error(`rnp_key_protect failed for ${this.#fingerprint}`);
    }
  }

  /**
   * If this tracker object has unlocked the secret key, switch it to
   * backed to the locked state.
   */
  lockIfUnlocked() {
    if (!this.#rnpKeyHandle) {
      return;
    }

    if (!this.#isLocked && this.#wasUnlocked) {
      RNPLib.rnp_key_lock(this.#rnpKeyHandle);
      this.#isLocked = true;
      this.#wasUnlocked = false;
    }
  }

  /**
   * Drop the reference to the underlying key handle and other sensitive
   * data, without destroying the key handle. This can be used if other
   * code will handle the cleanup.
   */
  forget() {
    this.#rnpKeyHandle = null;
    this.#unlockPassword = null;
  }

  /**
   * Release all data managed by this tracker, if necessary locking the
   * tracked private key, forgetting the remembered unlock password,
   * and destroying the handle.
   * Note that data passed on to a password cache isn't released.
   */
  release() {
    if (!this.#rnpKeyHandle) {
      return;
    }

    this.lockIfUnlocked();
    RNPLib.rnp_key_handle_destroy(this.#rnpKeyHandle);
    this.forget();
  }
}

// The revocation strings are not localized, because the revocation certificate
// will be published to others who may not know the native language of the user.
const revocationFilePrefix1 =
  "This is a revocation certificate for the OpenPGP key:";
const revocationFilePrefix2 = `
A revocation certificate is kind of a "kill switch" to publicly
declare that a key shall no longer be used.  It is not possible
to retract such a revocation certificate once it has been published.

Use it to revoke this key in case of a secret key compromise, or loss of
the secret key, or loss of passphrase of the secret key.

To avoid an accidental use of this file, a colon has been inserted
before the 5 dashes below.  Remove this colon with a text editor
before importing and publishing this revocation certificate.

:`;

/**
 * Object to hold result status of decryption/verification.
 */
export class DecryptVerifyResult {
  /** @type {string} */
  decryptedData = "";
  /** @type {integer} */
  exitCode = -1;
  /** @type {integer} */
  statusFlags = 0;
  /** @type {integer} */
  extStatusFlags = 0;
  /** @type {string} */
  userId = "";
  /** @type {string} */
  keyId = "";
  /** @type {object} */
  sigDetails = { sigDate: null };
  /** @type {object} */
  encToDetails = { myRecipKey: {}, allRecipKeys: [] };
  /**
   * Which engine produced `decryptedData`, when it is not this one.
   *
   * `null` means librnp decrypted it, which is the ordinary case. `"gnupg"`
   * means the fall-through at the end of `decryptArray()` handed the work to
   * GPGME and its result came back. The value is a fact about *decryption* and
   * nothing else: signature verification is always librnp, whatever keyring
   * the signing key lives in, so a message verified here may well be signed by
   * a key that lives in GnuPG.
   *
   * Deliberately not a key id. Which key was used is a separate question that
   * `gpgme_op_decrypt_result` does not answer directly, which is why the
   * existing TODO beside the fall-through leaves it open; this field does not
   * need it.
   *
   * @type {?string}
   */
  decryptionEngine = null;
}

export var RNP = {
  hasRan: false,
  libLoaded: false,
  async once() {
    this.hasRan = true;
    try {
      RNPLib = lazy.RNPLibLoader.init();
      if (!RNPLib || !RNPLib.loaded) {
        return;
      }
      if (await RNPLib.init()) {
        //this.initUiOps();
        RNP.libLoaded = true;
        this.warnAboutProblematicKeys();
      }

      // Only start the automatic-passphrase machinery when there is at least
      // one secret key for it to protect.
      //
      // It used to run unconditionally, and the consequence was visible to any
      // user who looked: a profile with no OpenPGP key at all still carried
      // encrypted-openpgp-passphrase.txt, a 136-byte envelope over a locally
      // generated secret protecting nothing. The file is created on first need
      // by retrieveOpenPGPPassword(), which every path that actually protects
      // a key already calls, so nothing is lost by waiting -- and the file's
      // absence then means what it looks like.
      //
      // The keyring has been loaded by RNPLib.init() at this point, so this
      // count is real rather than zero-by-not-yet-read.
      const [protectedKeys, unprotectedKeys] = this.getProtectedKeysCount();
      if (protectedKeys || unprotectedKeys) {
        await lazy.OpenPGPMasterpass.ensurePasswordIsCached();
      }
    } catch (e) {
      lazy.log.warn("Loading RNP FAILED!", e);
    }
  },

  /**
   * Warn the user about existing secret keys with unsupported feature
   * flags, which were imported in the past, when we weren't yet able
   * to strip those flags. We haven't yet implemented a way to
   * automatically fix them, because fixing them requires
   * unlocking, and we shouldn't introduce code that prompts
   * the user to unlock keys unexpectedly.
   */
  warnAboutProblematicKeys() {
    const iter = new RNPLib.rnp_identifier_iterator_t();
    const grip = new lazy.ctypes.char.ptr();

    if (
      RNPLib.rnp_identifier_iterator_create(RNPLib.ffi, iter.address(), "grip")
    ) {
      throw new Error("rnp_identifier_iterator_create failed");
    }

    while (
      !RNPLib.rnp_identifier_iterator_next(iter, grip.address()) &&
      !grip.isNull()
    ) {
      const handle = new RNPLib.rnp_key_handle_t();
      if (RNPLib.rnp_locate_key(RNPLib.ffi, "grip", grip, handle.address())) {
        throw new Error("rnp_locate_key failed");
      }

      if (this.getSecretAvailableFromHandle(handle)) {
        const is_subkey = new lazy.ctypes.bool();
        if (RNPLib.rnp_key_is_sub(handle, is_subkey.address())) {
          throw new Error("rnp_key_is_sub failed");
        }
        if (!is_subkey.value) {
          if (this.keyHasUnsupportedFeatures(handle)) {
            const fp = this.getFingerprintFromHandle(handle);
            lazy.log.warn(
              `OpenPGP secret key with fingerprint ${fp} advertises unsupported features.`
            );
          }
        }
      }

      RNPLib.rnp_key_handle_destroy(handle);
    }

    RNPLib.rnp_identifier_iterator_destroy(iter);
  },

  getRNPLibStatus() {
    return RNPLib.getRNPLibStatus();
  },

  /**
   * The live library wrapper, for a caller that has to drive librnp directly.
   *
   * `RNPLibLoader.init()` returns a *new* wrapper with a null `ffi` each time
   * it is called -- the loaded library is shared, but the handle belongs to
   * the instance that called `init()`. So a test that reaches for the loader
   * gets an object it cannot use, and the only way to the ffi this build is
   * actually using is through here.
   *
   * Read-only, and for diagnostics and tests rather than for the send path:
   * `ffi` is null until `init()` has completed, which this does not force.
   *
   * @returns {?object} The wrapper, or null before initialisation.
   */
  getRNPLib() {
    return RNPLib ?? null;
  },

  async init() {
    if (!this.hasRan) {
      await this.once();
    }

    return RNP.libLoaded;
  },

  isAllowedPublicKeyAlgo(algo) {
    // see rnp/src/lib/rnp.cpp pubkey_alg_map
    switch (algo) {
      case "SM2":
        return false;

      default:
        return true;
    }
  },

  /**
   * returns {integer} - the raw value of the key's creation date
   *
   * @param handle
   */
  getKeyCreatedValueFromHandle(handle) {
    const key_creation = new lazy.ctypes.uint32_t();
    if (RNPLib.rnp_key_get_creation(handle, key_creation.address())) {
      throw new Error("rnp_key_get_creation failed");
    }
    return key_creation.value;
  },

  /**
   * @param {rnp_key_handle_t} handle - RNP key handle.
   * @returns {string} - The key's algorithm, e.g. "EDDSA" or "ECDH".
   */
  getAlgoFromHandle(handle) {
    const algo = new lazy.ctypes.char.ptr();
    if (RNPLib.rnp_key_get_alg(handle, algo.address())) {
      throw new Error("rnp_key_get_alg failed");
    }
    const algoStr = algo.readString();
    RNPLib.rnp_buffer_destroy(algo);
    return algoStr;
  },

  addKeyAttributes(handle, meta, keyObj, is_subkey, forListing) {
    const algo = new lazy.ctypes.char.ptr();
    const bits = new lazy.ctypes.uint32_t();
    const key_expiration = new lazy.ctypes.uint32_t();
    const allowed = new lazy.ctypes.bool();

    keyObj.secretAvailable = this.getSecretAvailableFromHandle(handle);

    if (keyObj.secretAvailable) {
      keyObj.secretMaterial = RNPLib.isSecretKeyMaterialAvailable(handle);
    } else {
      keyObj.secretMaterial = false;
    }

    if (is_subkey) {
      keyObj.type = "sub";
    } else {
      keyObj.type = "pub";
    }

    keyObj.keyId = this.getKeyIDFromHandle(handle);
    if (forListing) {
      keyObj.id = keyObj.keyId;
    }

    keyObj.fpr = this.getFingerprintFromHandle(handle);

    const version = new lazy.ctypes.uint32_t();
    if (RNPLib.rnp_key_get_version(handle, version.address())) {
      throw new Error("rnp_key_get_version failed");
    }
    keyObj.version = version.value;

    if (RNPLib.rnp_key_get_alg(handle, algo.address())) {
      throw new Error("rnp_key_get_alg failed");
    }
    keyObj.algoSym = algo.readString();
    RNPLib.rnp_buffer_destroy(algo);

    if (RNPLib.rnp_key_get_bits(handle, bits.address())) {
      throw new Error("rnp_key_get_bits failed");
    }
    keyObj.keySize = bits.value;

    keyObj.keyCreated = this.getKeyCreatedValueFromHandle(handle);
    keyObj.created = new Services.intl.DateTimeFormat().format(
      new Date(keyObj.keyCreated * 1000)
    );

    if (RNPLib.rnp_key_get_expiration(handle, key_expiration.address())) {
      throw new Error("rnp_key_get_expiration failed");
    }
    if (key_expiration.value > 0) {
      keyObj.expiryTime = keyObj.keyCreated + key_expiration.value;
    } else {
      keyObj.expiryTime = 0;
    }
    keyObj.expiry = keyObj.expiryTime
      ? new Services.intl.DateTimeFormat().format(
          new Date(keyObj.expiryTime * 1000)
        )
      : "";
    keyObj.keyUseFor = "";

    if (!this.isAllowedPublicKeyAlgo(keyObj.algoSym)) {
      return;
    }

    const key_revoked = new lazy.ctypes.bool();
    if (RNPLib.rnp_key_is_revoked(handle, key_revoked.address())) {
      throw new Error("rnp_key_is_revoked failed");
    }

    if (key_revoked.value) {
      keyObj.keyTrust = "r";
      if (forListing) {
        keyObj.revoke = true;
      }
    } else if (this.isExpiredTime(keyObj.expiryTime)) {
      keyObj.keyTrust = "e";
    } else if (keyObj.secretAvailable) {
      keyObj.keyTrust = "u";
    } else {
      keyObj.keyTrust = "o";
    }

    if (RNPLib.rnp_key_allows_usage(handle, "encrypt", allowed.address())) {
      throw new Error("rnp_key_allows_usage failed");
    }
    if (allowed.value) {
      keyObj.keyUseFor += "e";
      meta.e = true;
    }
    if (RNPLib.rnp_key_allows_usage(handle, "sign", allowed.address())) {
      throw new Error("rnp_key_allows_usage failed");
    }
    if (allowed.value) {
      keyObj.keyUseFor += "s";
      meta.s = true;
    }
    if (RNPLib.rnp_key_allows_usage(handle, "certify", allowed.address())) {
      throw new Error("rnp_key_allows_usage failed");
    }
    if (allowed.value) {
      keyObj.keyUseFor += "c";
      meta.c = true;
    }
    if (
      RNPLib.rnp_key_allows_usage(handle, "authenticate", allowed.address())
    ) {
      throw new Error("rnp_key_allows_usage failed");
    }
    if (allowed.value) {
      keyObj.keyUseFor += "a";
      meta.a = true;
    }
  },

  async getKeys(onlyKeys = null) {
    return this.getKeysFromFFI(RNPLib.ffi, false, onlyKeys, false);
  },

  async getSecretKeys(onlyKeys = null) {
    return this.getKeysFromFFI(RNPLib.ffi, false, onlyKeys, true);
  },

  getProtectedKeysCount() {
    return RNPLib.getProtectedKeysCount();
  },

  async protectUnprotectedKeys() {
    return RNPLib.protectUnprotectedKeys();
  },

  /**
   * This function inspects the keys contained in the RNP space "ffi",
   * and returns objects of type KeyObj that describe the keys.
   *
   * Some consumers want a different listing of keys, and expect
   * slightly different attribute names.
   * If forListing is true, we'll set those additional attributes.
   * If onlyKeys is given: only returns keys in that array.
   *
   * @param {rnp_ffi_t} ffi - RNP library handle to key storage area
   * @param {boolean} forListing - Request additional attributes
   *   in the returned objects, for backwards compatibility.
   * @param {?string[]} onlyKeys - An array of key IDs or fingerprints.
   *   If non-null, only the given elements will be returned.
   *   If null, all elements are returned.
   * @param {boolean} onlySecret - If true, only information for
   *   available secret keys is returned.
   * @param {boolean} withPubKey - If true, an additional attribute
   *   "pubKey" will be added to each returned KeyObj, which will
   *   contain an ascii armor copy of the public key.
   * @returns {KeyObj[]} an array of KeyObj objects that describe the
   *   available keys.
   */
  async getKeysFromFFI(
    ffi,
    forListing,
    onlyKeys = null,
    onlySecret = false,
    withPubKey = false
  ) {
    if (!!onlyKeys && onlySecret) {
      throw new Error(
        "filtering by both white list and only secret keys isn't supported"
      );
    }

    const keys = [];

    if (onlyKeys) {
      for (const id of onlyKeys) {
        const handle = await this.getKeyHandleByIdentifier(ffi, id);
        if (!handle || handle.isNull()) {
          continue;
        }

        const keyObj = {};
        try {
          // Skip if it is a sub key, it will be processed together with primary key later.
          const ok = this.getKeyInfoFromHandle(
            ffi,
            handle,
            keyObj,
            false,
            forListing,
            false
          );
          if (!ok) {
            continue;
          }
        } catch (ex) {
          lazy.log.warn(`Get key info from handle FAILED for 0x${id}`, ex);
          continue;
        } finally {
          RNPLib.rnp_key_handle_destroy(handle);
        }

        if (keyObj) {
          if (withPubKey) {
            const pubKey = await this.getPublicKey("0x" + keyObj.id, ffi);
            if (pubKey) {
              keyObj.pubKey = pubKey;
            }
          }
          keys.push(keyObj);
        }
      }
    } else {
      const iter = new RNPLib.rnp_identifier_iterator_t();
      const grip = new lazy.ctypes.char.ptr();

      const rv = RNPLib.rnp_identifier_iterator_create(
        ffi,
        iter.address(),
        "grip"
      );
      if (rv) {
        return null;
      }

      while (!RNPLib.rnp_identifier_iterator_next(iter, grip.address())) {
        if (grip.isNull()) {
          break;
        }

        const handle = new RNPLib.rnp_key_handle_t();

        if (RNPLib.rnp_locate_key(ffi, "grip", grip, handle.address())) {
          throw new Error("rnp_locate_key failed");
        }

        const keyObj = {};
        try {
          if (RNP.isBadKey(handle, null, ffi)) {
            continue;
          }

          // Skip if it is a sub key, it will be processed together with primary key later.
          if (
            !this.getKeyInfoFromHandle(
              ffi,
              handle,
              keyObj,
              false,
              forListing,
              onlySecret
            )
          ) {
            continue;
          }
        } catch (ex) {
          const id = RNP.getKeyIDFromHandle(handle);
          lazy.log.warn(`Get key info from handle FAILED for 0x${id}`, ex);
          continue;
        } finally {
          RNPLib.rnp_key_handle_destroy(handle);
        }

        if (keyObj) {
          if (withPubKey) {
            const pubKey = await this.getPublicKey("0x" + keyObj.id, ffi);
            if (pubKey) {
              keyObj.pubKey = pubKey;
            }
          }
          keys.push(keyObj);
        }
      }
      RNPLib.rnp_identifier_iterator_destroy(iter);
    }
    return keys;
  },

  getFingerprintFromHandle(handle) {
    const fingerprint = new lazy.ctypes.char.ptr();
    if (RNPLib.rnp_key_get_fprint(handle, fingerprint.address())) {
      throw new Error("rnp_key_get_fprint failed");
    }
    const result = fingerprint.readString();
    RNPLib.rnp_buffer_destroy(fingerprint);
    return result;
  },

  getKeyIDFromHandle(handle) {
    const ctypes_key_id = new lazy.ctypes.char.ptr();
    if (RNPLib.rnp_key_get_keyid(handle, ctypes_key_id.address())) {
      throw new Error("rnp_key_get_keyid failed");
    }
    const result = ctypes_key_id.readString();
    RNPLib.rnp_buffer_destroy(ctypes_key_id);
    return result;
  },

  getSecretAvailableFromHandle(handle) {
    return RNPLib.getSecretAvailableFromHandle(handle);
  },

  // We already know sub_handle is a subkey
  getPrimaryKeyHandleFromSub(ffi, sub_handle) {
    const newHandle = new RNPLib.rnp_key_handle_t();
    // test my expectation is correct
    if (!newHandle.isNull()) {
      throw new Error("unexpected, new handle isn't null");
    }
    const primary_grip = new lazy.ctypes.char.ptr();
    if (RNPLib.rnp_key_get_primary_grip(sub_handle, primary_grip.address())) {
      throw new Error("rnp_key_get_primary_grip failed");
    }
    if (primary_grip.isNull()) {
      return newHandle;
    }
    if (RNPLib.rnp_locate_key(ffi, "grip", primary_grip, newHandle.address())) {
      throw new Error("rnp_locate_key failed");
    }
    return newHandle;
  },

  // We don't know if handle is a subkey. If it's not, return null handle
  getPrimaryKeyHandleIfSub(ffi, handle) {
    const is_subkey = new lazy.ctypes.bool();
    if (RNPLib.rnp_key_is_sub(handle, is_subkey.address())) {
      throw new Error("rnp_key_is_sub failed");
    }
    if (!is_subkey.value) {
      const nullHandle = new RNPLib.rnp_key_handle_t();
      // test my expectation is correct
      if (!nullHandle.isNull()) {
        throw new Error("unexpected, new handle isn't null");
      }
      return nullHandle;
    }
    return this.getPrimaryKeyHandleFromSub(ffi, handle);
  },

  /**
   * Creation time of the newest self-signature on a key.
   *
   * A key's revision is its signatures, not its fingerprint. Two copies of one
   * key can agree on the fingerprint and disagree about expiry, user IDs or
   * capabilities, because one was taken before the owner last changed them --
   * which is the 18 October shape exactly. The newest self-signature is what
   * separates the revisions, and comparing it between two stores is how a
   * stale copy is told from a current one.
   *
   * A self-signature is one whose signer is the key itself: the key ID is the
   * low 64 bits of the fingerprint, for every version this build accepts.
   * Signatures from other people are certifications, and a newer third-party
   * signature does not make the key a newer revision of itself, so they are
   * skipped.
   *
   * Returns 0 rather than throwing when a signature cannot be read. A caller
   * comparing two times must treat 0 as "unknown" and say nothing, because a
   * failure to measure must never be reported as evidence that a copy is old.
   *
   * @param {object} ffi - The librnp FFI holding the key.
   * @param {string} fpr - Fingerprint, with or without "0x".
   * @returns {number} Seconds since the epoch, or 0 when it cannot be read.
   */
  newestSelfSignatureTime(ffi, fpr) {
    const bare = String(fpr || "").replace(/^0x/i, "");
    if (!bare) {
      return 0;
    }
    const selfKeyId = bare.slice(-16).toUpperCase();

    const handle = this.getKeyHandleByKeyIdOrFingerprint(ffi, "0x" + bare);
    if (!handle || handle.isNull()) {
      return 0;
    }

    let newest = 0;
    const consider = sigHandle => {
      const sigId = new lazy.ctypes.char.ptr();
      if (RNPLib.rnp_signature_get_keyid(sigHandle, sigId.address())) {
        return;
      }
      const signer = sigId.isNull() ? "" : sigId.readString().toUpperCase();
      if (!sigId.isNull()) {
        RNPLib.rnp_buffer_destroy(sigId);
      }
      if (signer != selfKeyId && !selfKeyId.endsWith(signer)) {
        // Not a self-signature: a certification by somebody else says nothing
        // about which revision of the key this is.
        return;
      }
      const creation = new lazy.ctypes.uint32_t();
      if (RNPLib.rnp_signature_get_creation(sigHandle, creation.address())) {
        return;
      }
      if (creation.value > newest) {
        newest = creation.value;
      }
    };

    try {
      // Signatures attached to the key itself: direct-key and revocations.
      const keySigCount = new lazy.ctypes.size_t();
      if (!RNPLib.rnp_key_get_signature_count(handle, keySigCount.address())) {
        for (let i = 0; i < keySigCount.value; i++) {
          const sigHandle = new RNPLib.rnp_signature_handle_t();
          if (
            !RNPLib.rnp_key_get_signature_at(handle, i, sigHandle.address())
          ) {
            consider(sigHandle);
            RNPLib.rnp_signature_handle_destroy(sigHandle);
          }
        }
      }

      // And the ones that matter most in practice: each user ID carries its
      // own self-signature, which is where an expiry change is recorded.
      const uidCount = new lazy.ctypes.size_t();
      if (!RNPLib.rnp_key_get_uid_count(handle, uidCount.address())) {
        for (let u = 0; u < uidCount.value; u++) {
          const uidHandle = new RNPLib.rnp_uid_handle_t();
          if (
            RNPLib.rnp_key_get_uid_handle_at(handle, u, uidHandle.address())
          ) {
            continue;
          }
          // The uid variants, not the key ones. rnp_key_get_signature_count
          // and rnp_uid_get_signature_count are different entry points taking
          // different handles, and most keys carry no direct-key signature at
          // all: their self-signatures live on the user IDs. Using the key
          // function here returned zero for every key, which read as "no
          // revision" rather than as an error -- found by the test asserting
          // the fixture really is stale rather than trusting the comparison.
          const uidSigCount = new lazy.ctypes.size_t();
          if (
            !RNPLib.rnp_uid_get_signature_count(
              uidHandle,
              uidSigCount.address()
            )
          ) {
            for (let i = 0; i < uidSigCount.value; i++) {
              const sigHandle = new RNPLib.rnp_signature_handle_t();
              if (
                RNPLib.rnp_uid_get_signature_at(
                  uidHandle,
                  i,
                  sigHandle.address()
                )
              ) {
                continue;
              }
              consider(sigHandle);
              RNPLib.rnp_signature_handle_destroy(sigHandle);
            }
          }
          RNPLib.rnp_uid_handle_destroy(uidHandle);
        }
      }
    } finally {
      RNPLib.rnp_key_handle_destroy(handle);
    }

    return newest;
  },

  /**
   * The same measurement, for a key in the profile store.
   *
   * A convenience rather than a second implementation: callers outside this
   * module have no handle on the librnp FFI, and passing one around would
   * spread that detail for no benefit.
   *
   * @param {string} fpr - Fingerprint, with or without "0x".
   * @returns {number} Seconds since the epoch, or 0 when it cannot be read.
   */
  newestSelfSignatureTimeInProfile(fpr) {
    try {
      return this.newestSelfSignatureTime(RNPLib.ffi, fpr);
    } catch (ex) {
      lazy.log.warn("Reading a key's newest self-signature failed", ex);
      return 0;
    }
  },

  /**
   * The same measurement, for a key that is not in the profile store.
   *
   * Used to ask what revision GnuPG holds without importing it: the block is
   * parsed into a throwaway FFI, measured, and the FFI destroyed. Nothing is
   * written to either store, which is the property Item 10 exists to protect.
   *
   * @param {string} keyBlockStr - Armored public key block.
   * @param {string} fpr - Fingerprint of the key to measure.
   * @returns {number} Seconds since the epoch, or 0.
   */
  newestSelfSignatureTimeForKeyBlock(keyBlockStr, fpr) {
    if (!keyBlockStr) {
      return 0;
    }
    const tempFFI = RNPLib.prepare_ffi();
    if (!tempFFI) {
      return 0;
    }
    let time = 0;
    try {
      // importToFFI returns 0 on success.
      if (this.importToFFI(tempFFI, keyBlockStr, true, false) === 0) {
        time = this.newestSelfSignatureTime(tempFFI, fpr);
      }
    } finally {
      RNPLib.rnp_ffi_destroy(tempFFI);
    }
    return time;
  },

  hasKeyWeakSelfSignature(selfId, handle) {
    const sig_count = new lazy.ctypes.size_t();
    if (RNPLib.rnp_key_get_signature_count(handle, sig_count.address())) {
      throw new Error("rnp_key_get_signature_count failed");
    }

    let hasWeak = false;
    for (let i = 0; !hasWeak && i < sig_count.value; i++) {
      const sig_handle = new RNPLib.rnp_signature_handle_t();

      if (RNPLib.rnp_key_get_signature_at(handle, i, sig_handle.address())) {
        throw new Error("rnp_key_get_signature_at failed");
      }

      hasWeak = RNP.isWeakSelfSignature(selfId, sig_handle);
      RNPLib.rnp_signature_handle_destroy(sig_handle);
    }
    return hasWeak;
  },

  getSelfSigFeatures(selfId, handle) {
    let allFeatures = 0;

    const sig_count = new lazy.ctypes.size_t();
    if (RNPLib.rnp_key_get_signature_count(handle, sig_count.address())) {
      throw new Error("rnp_key_get_signature_count failed");
    }

    for (let i = 0; i < sig_count.value; i++) {
      const sig_handle = new RNPLib.rnp_signature_handle_t();

      if (RNPLib.rnp_key_get_signature_at(handle, i, sig_handle.address())) {
        throw new Error("rnp_key_get_signature_at failed");
      }

      const sig_id_str = new lazy.ctypes.char.ptr();
      if (RNPLib.rnp_signature_get_keyid(sig_handle, sig_id_str.address())) {
        throw new Error("rnp_signature_get_keyid failed");
      }

      const sigId = sig_id_str.readString();
      RNPLib.rnp_buffer_destroy(sig_id_str);

      // Is it a self-signature?
      if (sigId == selfId) {
        const features = new lazy.ctypes.uint32_t();
        if (RNPLib.rnp_signature_get_features(sig_handle, features.address())) {
          throw new Error("rnp_signature_get_features failed");
        }

        allFeatures |= features.value;
      }

      RNPLib.rnp_signature_handle_destroy(sig_handle);
    }
    return allFeatures;
  },

  isWeakSelfSignature(selfId, sig_handle) {
    const sig_id_str = new lazy.ctypes.char.ptr();
    if (RNPLib.rnp_signature_get_keyid(sig_handle, sig_id_str.address())) {
      throw new Error("rnp_signature_get_keyid failed");
    }

    const sigId = sig_id_str.readString();
    RNPLib.rnp_buffer_destroy(sig_id_str);

    // Is it a self-signature?
    if (sigId != selfId) {
      return false;
    }

    const creation = new lazy.ctypes.uint32_t();
    if (RNPLib.rnp_signature_get_creation(sig_handle, creation.address())) {
      throw new Error("rnp_signature_get_creation failed");
    }

    const hash_str = new lazy.ctypes.char.ptr();
    if (RNPLib.rnp_signature_get_hash_alg(sig_handle, hash_str.address())) {
      throw new Error("rnp_signature_get_hash_alg failed");
    }

    const creation64 = new lazy.ctypes.uint64_t();
    creation64.value = creation.value;

    const level = new lazy.ctypes.uint32_t();

    if (
      RNPLib.rnp_get_security_rule(
        RNPLib.ffi,
        RNPLib.RNP_FEATURE_HASH_ALG,
        hash_str,
        creation64,
        null,
        null,
        level.address()
      )
    ) {
      throw new Error("rnp_get_security_rule failed");
    }

    RNPLib.rnp_buffer_destroy(hash_str);
    return level.value < RNPLib.RNP_SECURITY_DEFAULT;
  },

  /**
   * @param {rnp_ffi_t} ffi
   * @param {rnp_key_handle_t} handle
   * @param {KeyObj} keyObj
   * @param {boolean} usePrimaryIfSubkey
   * @param {boolean} forListing
   * @param {boolean} onlyIfSecret
   * @returns {boolean} false if handle refers to subkey and should be ignored
   */
  getKeyInfoFromHandle(
    ffi,
    handle,
    keyObj,
    usePrimaryIfSubkey,
    forListing,
    onlyIfSecret
  ) {
    keyObj.ownerTrust = null;
    keyObj.userId = null;
    keyObj.userIds = [];
    keyObj.subKeys = [];
    keyObj.photoAvailable = false;
    keyObj.hasIgnoredAttributes = false;

    const is_subkey = new lazy.ctypes.bool();
    const sub_count = new lazy.ctypes.size_t();
    const uid_count = new lazy.ctypes.size_t();

    if (RNPLib.rnp_key_is_sub(handle, is_subkey.address())) {
      throw new Error("rnp_key_is_sub failed");
    }
    if (is_subkey.value) {
      if (!usePrimaryIfSubkey) {
        return false;
      }
      let rv = false;
      const newHandle = this.getPrimaryKeyHandleFromSub(ffi, handle);
      if (!newHandle.isNull()) {
        // recursively call ourselves to get primary key info
        rv = this.getKeyInfoFromHandle(
          ffi,
          newHandle,
          keyObj,
          false,
          forListing,
          onlyIfSecret
        );
        RNPLib.rnp_key_handle_destroy(newHandle);
      }
      return rv;
    }

    if (onlyIfSecret) {
      const have_secret = new lazy.ctypes.bool();
      if (RNPLib.rnp_key_have_secret(handle, have_secret.address())) {
        throw new Error("rnp_key_have_secret failed");
      }
      if (!have_secret.value) {
        return false;
      }
    }

    const meta = {
      a: false,
      s: false,
      c: false,
      e: false,
    };
    this.addKeyAttributes(handle, meta, keyObj, false, forListing);

    let hasAnySecretKey = keyObj.secretAvailable;

    // The remaining actions are done for primary keys, only.
    if (!is_subkey.value) {
      if (RNPLib.rnp_key_get_uid_count(handle, uid_count.address())) {
        throw new Error("rnp_key_get_uid_count failed");
      }
      let firstValidUid = null;
      for (let i = 0; i < uid_count.value; i++) {
        const uid_handle = new RNPLib.rnp_uid_handle_t();

        if (RNPLib.rnp_key_get_uid_handle_at(handle, i, uid_handle.address())) {
          throw new Error("rnp_key_get_uid_handle_at failed");
        }

        const uid_str = new lazy.ctypes.char.ptr();
        if (RNPLib.rnp_key_get_uid_at(handle, i, uid_str.address())) {
          throw new Error("rnp_key_get_uid_at failed");
        }
        const userIdStr = uid_str.readStringReplaceMalformed();
        RNPLib.rnp_buffer_destroy(uid_str);

        // Never allow revoked user IDs
        let uidOkToUse = !this.isRevokedUid(uid_handle);
        let ignoreReason = uidOkToUse ? null : "it is revoked";
        if (uidOkToUse) {
          // Usually, we don't allow user IDs reported as not valid
          uidOkToUse = !this.isBadUid(uid_handle);
          if (!uidOkToUse) {
            ignoreReason = "rnp_uid_is_valid reports it as invalid";
          }

          const { hasGoodSignature, hasWeakSignature } =
            this.getUidSignatureQuality(keyObj.keyId, uid_handle, userIdStr);

          if (hasWeakSignature) {
            keyObj.hasIgnoredAttributes = true;
          }

          if (!uidOkToUse && keyObj.keyTrust == "e") {
            // However, a user might be not valid, because it has
            // expired. If the primary key has expired, we should show
            // some user ID, even if all user IDs have expired,
            // otherwise the user cannot see any text description.
            // We allow showing user IDs with a good self-signature.
            uidOkToUse = hasGoodSignature;
            if (uidOkToUse) {
              ignoreReason = null;
            } else {
              ignoreReason += ", and it has no good self signature";
            }
          }
        }

        if (!uidOkToUse) {
          lazy.log.debug(
            `Ignoring user ID ${i} (${userIdStr}) of key ${keyObj.fpr}, because ${ignoreReason}.`
          );
        }

        if (uidOkToUse) {
          if (userIdStr !== RNP_PHOTO_USERID_ID) {
            if (!firstValidUid) {
              firstValidUid = userIdStr;
            }

            if (!keyObj.userId && this.isPrimaryUid(uid_handle)) {
              keyObj.userId = userIdStr;
            }

            const uidObj = {};
            uidObj.userId = userIdStr;
            uidObj.type = "uid";
            uidObj.keyTrust = keyObj.keyTrust;
            uidObj.uidFpr = "??fpr??";

            uidObj.features = this.getUidFeatures(keyObj.keyId, uid_handle);

            keyObj.userIds.push(uidObj);
          }
        }

        RNPLib.rnp_uid_handle_destroy(uid_handle);
      }

      if (!keyObj.userId && firstValidUid) {
        // No user ID marked as primary, so let's use the first valid.
        keyObj.userId = firstValidUid;
      }

      if (!keyObj.userId) {
        lazy.log.debug(
          `Key ${keyObj.fpr} has no usable user ID, it will be shown without a description.`
        );
        keyObj.userId = "?";
      }

      if (forListing) {
        keyObj.name = keyObj.userId;
      }

      if (RNPLib.rnp_key_get_subkey_count(handle, sub_count.address())) {
        throw new Error("rnp_key_get_subkey_count failed");
      }
      for (let i = 0; i < sub_count.value; i++) {
        const sub_handle = new RNPLib.rnp_key_handle_t();
        if (RNPLib.rnp_key_get_subkey_at(handle, i, sub_handle.address())) {
          throw new Error("rnp_key_get_subkey_at failed");
        }

        if (RNP.hasKeyWeakSelfSignature(keyObj.keyId, sub_handle)) {
          keyObj.hasIgnoredAttributes = true;
        }

        if (!RNP.isBadKey(sub_handle, handle, null)) {
          const subKeyObj = {};
          this.addKeyAttributes(sub_handle, meta, subKeyObj, true, forListing);
          keyObj.subKeys.push(subKeyObj);
          hasAnySecretKey = hasAnySecretKey || subKeyObj.secretAvailable;
        }

        RNPLib.rnp_key_handle_destroy(sub_handle);
      }

      let haveNonExpiringEncryptionKey = false;
      let haveNonExpiringSigningKey = false;

      let effectiveEncryptionExpiry = keyObj.expiry;
      let effectiveSigningExpiry = keyObj.expiry;
      let effectiveEncryptionExpiryTime = keyObj.expiryTime;
      let effectiveSigningExpiryTime = keyObj.expiryTime;

      if (keyObj.keyUseFor.match(/e/) && !keyObj.expiryTime) {
        haveNonExpiringEncryptionKey = true;
      }

      if (keyObj.keyUseFor.match(/s/) && !keyObj.expiryTime) {
        haveNonExpiringSigningKey = true;
      }

      let mostFutureEncExpiryTime = 0;
      let mostFutureSigExpiryTime = 0;
      let mostFutureEncExpiry = "";
      let mostFutureSigExpiry = "";

      for (const aSub of keyObj.subKeys) {
        if (aSub.keyTrust == "r") {
          continue;
        }

        // Expiring subkeys may shorten the effective expiry,
        // unless the primary key is non-expiring and can be used
        // for a purpose.
        // Subkeys cannot extend the expiry beyond the primary key's.

        // Strategy: If we don't have a non-expiring usable primary key,
        // then find the usable subkey that has the most future
        // expiration date. Stop searching is a non-expiring subkey
        // is found. Then compare with primary key expiry.

        if (!haveNonExpiringEncryptionKey && aSub.keyUseFor.match(/e/)) {
          if (!aSub.expiryTime) {
            haveNonExpiringEncryptionKey = true;
          } else if (!mostFutureEncExpiryTime) {
            mostFutureEncExpiryTime = aSub.expiryTime;
            mostFutureEncExpiry = aSub.expiry;
          } else if (aSub.expiryTime > mostFutureEncExpiryTime) {
            mostFutureEncExpiryTime = aSub.expiryTime;
            mostFutureEncExpiry = aSub.expiry;
          }
        }

        // We only need to calculate the effective signing expiration
        // if it's about a personal key (we require both signing and
        // encryption capability).
        if (
          hasAnySecretKey &&
          !haveNonExpiringSigningKey &&
          aSub.keyUseFor.match(/s/)
        ) {
          if (!aSub.expiryTime) {
            haveNonExpiringSigningKey = true;
          } else if (!mostFutureSigExpiryTime) {
            mostFutureSigExpiryTime = aSub.expiryTime;
            mostFutureSigExpiry = aSub.expiry;
          } else if (aSub.expiryTime > mostFutureEncExpiryTime) {
            mostFutureSigExpiryTime = aSub.expiryTime;
            mostFutureSigExpiry = aSub.expiry;
          }
        }
      }

      if (
        !haveNonExpiringEncryptionKey &&
        mostFutureEncExpiryTime &&
        (!keyObj.expiryTime || mostFutureEncExpiryTime < keyObj.expiryTime)
      ) {
        effectiveEncryptionExpiryTime = mostFutureEncExpiryTime;
        effectiveEncryptionExpiry = mostFutureEncExpiry;
      }

      if (
        !haveNonExpiringSigningKey &&
        mostFutureSigExpiryTime &&
        (!keyObj.expiryTime || mostFutureSigExpiryTime < keyObj.expiryTime)
      ) {
        effectiveSigningExpiryTime = mostFutureSigExpiryTime;
        effectiveSigningExpiry = mostFutureSigExpiry;
      }

      if (!hasAnySecretKey) {
        keyObj.effectiveExpiryTime = effectiveEncryptionExpiryTime;
        keyObj.effectiveExpiry = effectiveEncryptionExpiry;
      } else {
        let effectiveSignOrEncExpiry = "";
        let effectiveSignOrEncExpiryTime = 0;

        if (!effectiveEncryptionExpiryTime) {
          if (effectiveSigningExpiryTime) {
            effectiveSignOrEncExpiryTime = effectiveSigningExpiryTime;
            effectiveSignOrEncExpiry = effectiveSigningExpiry;
          }
        } else if (!effectiveSigningExpiryTime) {
          effectiveSignOrEncExpiryTime = effectiveEncryptionExpiryTime;
          effectiveSignOrEncExpiry = effectiveEncryptionExpiry;
        } else if (effectiveSigningExpiryTime < effectiveEncryptionExpiryTime) {
          effectiveSignOrEncExpiryTime = effectiveSigningExpiryTime;
          effectiveSignOrEncExpiry = effectiveSigningExpiry;
        } else {
          effectiveSignOrEncExpiryTime = effectiveEncryptionExpiryTime;
          effectiveSignOrEncExpiry = effectiveEncryptionExpiry;
        }

        keyObj.effectiveExpiryTime = effectiveSignOrEncExpiryTime;
        keyObj.effectiveExpiry = effectiveSignOrEncExpiry;
      }

      if (meta.s) {
        keyObj.keyUseFor += "S";
      }
      if (meta.a) {
        keyObj.keyUseFor += "A";
      }
      if (meta.c) {
        keyObj.keyUseFor += "C";
      }
      if (meta.e) {
        keyObj.keyUseFor += "E";
      }

      if (RNP.hasKeyWeakSelfSignature(keyObj.keyId, handle)) {
        keyObj.hasIgnoredAttributes = true;
      }

      keyObj.features = this.getSelfSigFeatures(keyObj.keyId, handle);
    }

    return true;
  },

  /*
  // We don't need these functions currently, but it's helpful
  // information that I'd like to keep around as documentation.

  isUInt64WithinBounds(val) {
    // JS integers are limited to 53 bits precision.
    // Numbers smaller than 2^53 -1 are safe to use.
    // (For comparison, that's 8192 TB or 8388608 GB).
    const num53BitsMinus1 = ctypes.UInt64("0x1fffffffffffff");
    return ctypes.UInt64.compare(val, num53BitsMinus1) < 0;
  },

  isUInt64Max(val) {
    // 2^64-1, 18446744073709551615
    const max = ctypes.UInt64("0xffffffffffffffff");
    return ctypes.UInt64.compare(val, max) == 0;
  },
  */

  isBadKey(handle, knownPrimaryKey, knownContextFFI) {
    const validTill64 = new lazy.ctypes.uint64_t();
    if (RNPLib.rnp_key_valid_till64(handle, validTill64.address())) {
      throw new Error("rnp_key_valid_till64 failed");
    }

    // For the purpose of this function, we define bad as: there isn't
    // any valid self-signature on the key, and thus the key should
    // be completely avoided.
    // In this scenario, zero is returned. In other words,
    // if a non-zero value is returned, we know the key isn't completely
    // bad according to our definition.

    // ctypes.uint64_t().value is of type ctypes.UInt64

    if (
      lazy.ctypes.UInt64.compare(validTill64.value, lazy.ctypes.UInt64("0")) > 0
    ) {
      return false;
    }

    // If zero was returned, it could potentially have been revoked.
    // If it was revoked, we don't treat is as generally bad,
    // to allow importing it and to consume the revocation information.
    // If the key was not revoked, then treat it as a bad key.
    const key_revoked = new lazy.ctypes.bool();
    if (RNPLib.rnp_key_is_revoked(handle, key_revoked.address())) {
      throw new Error("rnp_key_is_revoked failed");
    }

    if (!key_revoked.value) {
      // Also check if the primary key was revoked. If the primary key
      // is revoked, the subkey is considered revoked, too.
      if (knownPrimaryKey) {
        if (RNPLib.rnp_key_is_revoked(knownPrimaryKey, key_revoked.address())) {
          throw new Error("rnp_key_is_revoked failed");
        }
      } else if (knownContextFFI) {
        const primaryHandle = this.getPrimaryKeyHandleIfSub(
          knownContextFFI,
          handle
        );
        if (!primaryHandle.isNull()) {
          if (RNPLib.rnp_key_is_revoked(primaryHandle, key_revoked.address())) {
            throw new Error("rnp_key_is_revoked failed");
          }
          RNPLib.rnp_key_handle_destroy(primaryHandle);
        }
      }
    }

    return !key_revoked.value;
  },

  isPrimaryUid(uid_handle) {
    const is_primary = new lazy.ctypes.bool();

    if (RNPLib.rnp_uid_is_primary(uid_handle, is_primary.address())) {
      throw new Error("rnp_uid_is_primary failed");
    }

    return is_primary.value;
  },

  getUidFeatures(self_key_id, uid_handle) {
    let allFeatures = 0;

    const sig_count = new lazy.ctypes.size_t();
    if (RNPLib.rnp_uid_get_signature_count(uid_handle, sig_count.address())) {
      throw new Error("rnp_uid_get_signature_count failed");
    }

    for (let i = 0; i < sig_count.value; i++) {
      const sig_handle = new RNPLib.rnp_signature_handle_t();

      if (
        RNPLib.rnp_uid_get_signature_at(uid_handle, i, sig_handle.address())
      ) {
        throw new Error("rnp_uid_get_signature_at failed");
      }

      const sig_id_str = new lazy.ctypes.char.ptr();
      if (RNPLib.rnp_signature_get_keyid(sig_handle, sig_id_str.address())) {
        throw new Error("rnp_signature_get_keyid failed");
      }

      if (sig_id_str.readString() == self_key_id) {
        const features = new lazy.ctypes.uint32_t();
        if (RNPLib.rnp_signature_get_features(sig_handle, features.address())) {
          throw new Error("rnp_signature_get_features failed");
        }

        allFeatures |= features.value;
      }

      RNPLib.rnp_buffer_destroy(sig_id_str);
      RNPLib.rnp_signature_handle_destroy(sig_handle);
    }

    return allFeatures;
  },

  /**
   * @param {string} self_key_id - Key ID of the key that owns the user ID.
   * @param {rnp_uid_handle_t} uid_handle
   * @param {string} [userIdStr] - User ID string, used for debug logging only.
   * @returns {object} quality - Result of the check.
   * @property {boolean} quality.hasGoodSignature - A good signature was found.
   * @property {boolean} quality.hasWeakSignature - Only a weak signature was found.
   */
  getUidSignatureQuality(self_key_id, uid_handle, userIdStr = "") {
    let hasGoodSignature = false;
    let hasWeakSignature = false;

    const sig_count = new lazy.ctypes.size_t();
    if (RNPLib.rnp_uid_get_signature_count(uid_handle, sig_count.address())) {
      throw new Error("rnp_uid_get_signature_count failed");
    }

    for (let i = 0; i < sig_count.value; i++) {
      const sig_handle = new RNPLib.rnp_signature_handle_t();

      if (
        RNPLib.rnp_uid_get_signature_at(uid_handle, i, sig_handle.address())
      ) {
        throw new Error("rnp_uid_get_signature_at failed");
      }

      const sig_id_str = new lazy.ctypes.char.ptr();
      if (RNPLib.rnp_signature_get_keyid(sig_handle, sig_id_str.address())) {
        throw new Error("rnp_signature_get_keyid failed");
      }

      if (sig_id_str.readString() == self_key_id) {
        if (!hasGoodSignature) {
          const sig_validity = RNPLib.rnp_signature_is_valid(sig_handle, 0);
          hasGoodSignature =
            sig_validity == RNPLib.RNP_SUCCESS ||
            sig_validity == RNPLib.RNP_ERROR_SIGNATURE_EXPIRED;

          if (!hasGoodSignature) {
            lazy.log.debug(
              `Bad self signature ${i} on user ID (${userIdStr}) of key ${self_key_id}, rnp_signature_is_valid status ${sig_validity}.`
            );
          }
        }

        if (!hasWeakSignature) {
          hasWeakSignature = RNP.isWeakSelfSignature(self_key_id, sig_handle);
        }
      }

      RNPLib.rnp_buffer_destroy(sig_id_str);
      RNPLib.rnp_signature_handle_destroy(sig_handle);
    }

    return {
      hasGoodSignature,
      hasWeakSignature,
    };
  },

  /**
   * Get revocation reason for a key.
   *
   * @param {string} keyId
   * @returns {object} revocationReason - Textual explanation for revocation.
   * @property {?string} revocationReason.code - One of "no", "superseded",
   *   "compromised", "retired", or null. See revocation_code_map.
   * @property {?string} revocationReason.reason - Human-readable reason.
   * @see https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.31
   */
  getKeyRevocationReasonByKeyId(keyId) {
    const key_handle = this.getKeyHandleByKeyIdOrFingerprint(RNPLib.ffi, keyId);
    if (key_handle?.isNull()) {
      return { code: null, reason: null };
    }
    const reason = this.getKeyRevocationReasonByKeyHandle(key_handle);
    RNPLib.rnp_key_handle_destroy(key_handle);
    return reason;
  },

  /**
   * Get revocation reason for a key.
   *
   * @param {rnp_key_handle_t} key_handle
   * @returns {?object} revocationReason - Textual explanation for revocation.
   * @property {"no"|"superseded"|"compromised"|"retired"|null} revocationReason.code
   *   Code. See revocation_code_map.
   * @property {?string} revocationReason.reason - Human-readable reason.
   * @see https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.31
   */
  getKeyRevocationReasonByKeyHandle(key_handle) {
    const sig_handle = new RNPLib.rnp_signature_handle_t();
    if (
      RNPLib.rnp_key_get_revocation_signature(key_handle, sig_handle.address())
    ) {
      throw new Error("rnp_key_get_revocation_signature failed");
    }
    if (sig_handle.isNull()) {
      return { code: null, reason: null };
    }

    const codePtr = new lazy.ctypes.char.ptr();
    const reasonPtr = new lazy.ctypes.char.ptr();
    if (
      RNPLib.rnp_signature_get_revocation_reason(
        sig_handle,
        codePtr.address(),
        reasonPtr.address()
      )
    ) {
      throw new Error("rnp_signature_get_revocation_reason failed");
    }
    const code = !codePtr.isNull() ? codePtr.readString() : null;
    const reason = !reasonPtr.isNull() ? reasonPtr.readString() : null;

    RNPLib.rnp_buffer_destroy(codePtr);
    RNPLib.rnp_buffer_destroy(reasonPtr);
    RNPLib.rnp_signature_handle_destroy(sig_handle);

    return { code, reason };
  },

  isBadUid(uid_handle) {
    const is_valid = new lazy.ctypes.bool();

    if (RNPLib.rnp_uid_is_valid(uid_handle, is_valid.address())) {
      throw new Error("rnp_uid_is_valid failed");
    }

    return !is_valid.value;
  },

  isRevokedUid(uid_handle) {
    const is_revoked = new lazy.ctypes.bool();

    if (RNPLib.rnp_uid_is_revoked(uid_handle, is_revoked.address())) {
      throw new Error("rnp_uid_is_revoked failed");
    }

    return is_revoked.value;
  },

  /* unused
  getKeySignatures(keyId, ignoreUnknownUid) {
    const handle = this.getKeyHandleByKeyIdOrFingerprint(
      RNPLib.ffi,
      "0x" + keyId
    );
    if (handle.isNull()) {
      return null;
    }

    const mainKeyObj = {};
    this.getKeyInfoFromHandle(
      RNPLib.ffi,
      handle,
      mainKeyObj,
      false,
      true,
      false
    );

    const result = RNP._getSignatures(mainKeyObj, handle, ignoreUnknownUid);
    RNPLib.rnp_key_handle_destroy(handle);
    return result;
  },
  */

  getKeyObjSignatures(keyObj, ignoreUnknownUid) {
    const handle = this.getKeyHandleByKeyIdOrFingerprint(
      RNPLib.ffi,
      "0x" + keyObj.keyId
    );
    if (handle.isNull()) {
      return null;
    }

    const result = RNP._getSignatures(keyObj, handle, ignoreUnknownUid);
    RNPLib.rnp_key_handle_destroy(handle);
    return result;
  },

  _getSignatures(keyObj, handle, ignoreUnknownUid) {
    const rList = [];

    try {
      const uid_count = new lazy.ctypes.size_t();
      if (RNPLib.rnp_key_get_uid_count(handle, uid_count.address())) {
        throw new Error("rnp_key_get_uid_count failed");
      }
      let outputIndex = 0;
      for (let i = 0; i < uid_count.value; i++) {
        const uid_handle = new RNPLib.rnp_uid_handle_t();

        if (RNPLib.rnp_key_get_uid_handle_at(handle, i, uid_handle.address())) {
          throw new Error("rnp_key_get_uid_handle_at failed");
        }

        if (!this.isBadUid(uid_handle) && !this.isRevokedUid(uid_handle)) {
          const uid_str = new lazy.ctypes.char.ptr();
          if (RNPLib.rnp_key_get_uid_at(handle, i, uid_str.address())) {
            throw new Error("rnp_key_get_uid_at failed");
          }
          const userIdStr = uid_str.readStringReplaceMalformed();
          RNPLib.rnp_buffer_destroy(uid_str);

          if (userIdStr !== RNP_PHOTO_USERID_ID) {
            const id = outputIndex;
            ++outputIndex;

            let subList = {};

            subList = {};
            subList.keyCreated = keyObj.keyCreated;
            subList.created = keyObj.created;
            subList.fpr = keyObj.fpr;
            subList.keyId = keyObj.keyId;

            subList.userId = userIdStr;
            subList.sigList = [];

            const sig_count = new lazy.ctypes.size_t();
            if (
              RNPLib.rnp_uid_get_signature_count(
                uid_handle,
                sig_count.address()
              )
            ) {
              throw new Error("rnp_uid_get_signature_count failed");
            }
            for (let j = 0; j < sig_count.value; j++) {
              const sigObj = {};

              const sig_handle = new RNPLib.rnp_signature_handle_t();
              if (
                RNPLib.rnp_uid_get_signature_at(
                  uid_handle,
                  j,
                  sig_handle.address()
                )
              ) {
                throw new Error("rnp_uid_get_signature_at failed");
              }

              const creation = new lazy.ctypes.uint32_t();
              if (
                RNPLib.rnp_signature_get_creation(
                  sig_handle,
                  creation.address()
                )
              ) {
                throw new Error("rnp_signature_get_creation failed");
              }
              sigObj.keyCreated = creation.value;
              sigObj.created = new Services.intl.DateTimeFormat().format(
                new Date(sigObj.keyCreated * 1000)
              );
              sigObj.sigType = "?";

              const sig_id_str = new lazy.ctypes.char.ptr();
              if (
                RNPLib.rnp_signature_get_keyid(sig_handle, sig_id_str.address())
              ) {
                throw new Error("rnp_signature_get_keyid failed");
              }

              const sigIdStr = sig_id_str.readString();
              sigObj.signerKeyId = sigIdStr;
              RNPLib.rnp_buffer_destroy(sig_id_str);

              const signerHandle = new RNPLib.rnp_key_handle_t();

              if (
                RNPLib.rnp_signature_get_signer(
                  sig_handle,
                  signerHandle.address()
                )
              ) {
                throw new Error("rnp_signature_get_signer failed");
              }

              if (
                signerHandle.isNull() ||
                this.isBadKey(signerHandle, null, RNPLib.ffi)
              ) {
                if (!ignoreUnknownUid) {
                  sigObj.userId = "?";
                  sigObj.sigKnown = false;
                  subList.sigList.push(sigObj);
                }
              } else {
                const signer_uid_str = new lazy.ctypes.char.ptr();
                if (
                  RNPLib.rnp_key_get_primary_uid(
                    signerHandle,
                    signer_uid_str.address()
                  )
                ) {
                  throw new Error("rnp_key_get_primary_uid failed");
                }
                sigObj.userId = signer_uid_str.readStringReplaceMalformed();
                RNPLib.rnp_buffer_destroy(signer_uid_str);
                sigObj.sigKnown = true;
                subList.sigList.push(sigObj);
                RNPLib.rnp_key_handle_destroy(signerHandle);
              }
              RNPLib.rnp_signature_handle_destroy(sig_handle);
            }
            rList[id] = subList;
          }
        }

        RNPLib.rnp_uid_handle_destroy(uid_handle);
      }
    } catch (ex) {
      lazy.log.warn(`Getting signatures for 0x{keyObj.keyId} FAILED!`, ex);
    }
    return rList;
  },

  policyForbidsAlg() {
    // TODO: implement policy
    // Currently, all algorithms are allowed
    return false;
  },

  getKeyIdsFromRecipHandle(recip_handle, resultRecipAndPrimary) {
    resultRecipAndPrimary.keyId = "";
    resultRecipAndPrimary.primaryKeyId = "";

    const c_key_id = new lazy.ctypes.char.ptr();
    if (RNPLib.rnp_recipient_get_keyid(recip_handle, c_key_id.address())) {
      throw new Error("rnp_recipient_get_keyid failed");
    }
    const recip_key_id = c_key_id.readString();
    resultRecipAndPrimary.keyId = recip_key_id;
    RNPLib.rnp_buffer_destroy(c_key_id);

    const recip_key_handle = this.getKeyHandleByKeyIdOrFingerprint(
      RNPLib.ffi,
      "0x" + recip_key_id
    );
    if (!recip_key_handle.isNull()) {
      const primary_signer_handle = this.getPrimaryKeyHandleIfSub(
        RNPLib.ffi,
        recip_key_handle
      );
      if (!primary_signer_handle.isNull()) {
        resultRecipAndPrimary.primaryKeyId = this.getKeyIDFromHandle(
          primary_signer_handle
        );
        RNPLib.rnp_key_handle_destroy(primary_signer_handle);
      }
      RNPLib.rnp_key_handle_destroy(recip_key_handle);
    }
  },

  /**
   * Decrypts/Decodes an OpenPGP message, verify signatures, and
   * return associated meta data.
   *
   * @param {string} encrypted_string - A string of bytes containing
   *   the encrypted message.
   * @param {object} options - Various pieces of information that are
   *   necessary for correctly processing the encrypted message.
   * @param {boolean} alreadyDecrypted - Usually callers should set this
   *   flag to false, to request both decryption and full decoding of
   *   all available meta data. Value True is intended to allow
   *   recursive calling of this function. Value True means, a previous
   *   action has already processed the outer encryption layer, only,
   *   (include querying of encryption strength and the list keys that
   *   are known to be able to decrypt the message), but processing of
   *   the inner payload has not yet been done, such as decompression
   *   and verification of the inner signature.
   *   If the value is set to True, then meta data related to
   *   the encryption layer is read from the "options" parameter and
   *   copied over to the result object.
   * @returns {DecryptVerifyResult} - Various flags that contain the decrypted
   *    data and related meta data.
   */
  async decrypt(encrypted_string, options, alreadyDecrypted = false) {
    const arr = encrypted_string.split("").map(e => e.charCodeAt());
    const encrypted_array = lazy.ctypes.uint8_t.array()(arr);
    return this.decryptArray(encrypted_array, options, alreadyDecrypted);
  },

  /**
   * Decrypts/Decodes an OpenPGP message, verify signatures, and
   * return associated meta data.
   *
   * @param {string} encrypted_array - An array of bytes that contains
   *   the encrypted message.
   * @param {object} options - See description of the same parameter
   *   of function decrypt().
   * @param {boolean} alreadyDecrypted - See description of the same
   *   parameter of function decrypt().
   * @returns {DecryptVerifyResult}
   */
  async decryptArray(encrypted_array, options, alreadyDecrypted = false) {
    const result = new DecryptVerifyResult();

    if (alreadyDecrypted) {
      result.encToDetails = options.encToDetails;
    }

    // Allow compressed encrypted messages, max factor 1200, up to 100 MiB.
    const max_decrypted_message_size = 100 * 1024 * 1024;
    const max_out = Math.min(
      encrypted_array.length * 1200,
      max_decrypted_message_size
    );

    const collected_fingerprints = [];
    const remembered_passwords = new Map();

    function collect_key_info_password_cb(ffi, app_ctx, key) {
      const fingerprint = new lazy.ctypes.char.ptr();
      if (!RNPLib.rnp_key_get_fprint(key, fingerprint.address())) {
        collected_fingerprints.push(fingerprint.readString());
      }

      RNPLib.rnp_buffer_destroy(fingerprint);
      return false;
    }

    function use_remembered_password_cb(
      ffi,
      app_ctx,
      key,
      pgp_context,
      buf,
      buf_len
    ) {
      const fingerprint = new lazy.ctypes.char.ptr();
      if (RNPLib.rnp_key_get_fprint(key, fingerprint.address())) {
        return false;
      }
      const fpr = fingerprint.readString();
      RNPLib.rnp_buffer_destroy(fingerprint);

      const pw = remembered_passwords.get(fpr);
      const passCTypes = lazy.ctypes.char.array()(pw); // UTF-8

      if (buf_len < passCTypes.length) {
        return false;
      }

      const char_array = lazy.ctypes.cast(
        buf,
        lazy.ctypes.char.array(buf_len).ptr
      ).contents;

      for (let i = 0; i < passCTypes.length; i++) {
        char_array[i] = passCTypes[i];
      }
      char_array[passCTypes.length] = 0;
      return true;
    }

    let tryAgain;
    let isFirstTry = true;

    let verify_op;
    let input_from_memory;
    let output_to_memory;

    // We don't know which secret key RNP wants to use for decryption.
    // We make an initial attempt to ask RNP to decrypt, in which we set
    // "collect_key_info_password_cb" as the password callback function.
    // If RNP needs to unlock a key to decrypt, we will remember the
    // key that needs to be unlocked in "collect_key_info_password_cb",
    // but will give no password to RNP, which will cause RNP to fail
    // the decryption operation.
    // After returning from rnp_op_verify_execute (which performs the
    // decryption or decryption attempt), we'll learn whether encryption
    // worked, then we can continue immediately.
    // Or, we'll learn that RNP needs to unlock a key. In this
    // scenario, we'll interact with the user to learn the password
    // that's required to unlock the key. We'll prompt the user, and if
    // the user enters the correct password, we'll remember that
    // password temporarily, and try the decryption operation again.
    // During this second attempt to decrypt, we'll provide
    // "use_remembered_password_cb" as the password callback function.
    // When RNP attempts to decrypt and calls use_remembered_password_cb,
    // we'll pass along the password to RNP, which can then
    // unlock the key and decrypt the message.
    // We use this approach, because we cannot easily prompt the user
    // from within the password callback itself.
    // (We're starting from JavaScript code, we're calling RNP C code,
    // which then calls back into a JavaScript callback, and from there
    // we would have to execute async code, but the RNP code that
    // calls back into JavaScript isn't able to handle that. To avoid
    // having to spin a nested event loop for simulating a synchronous
    // call, we're using the approach described above.)

    do {
      tryAgain = false;

      input_from_memory = new RNPLib.rnp_input_t();
      RNPLib.rnp_input_from_memory(
        input_from_memory.address(),
        encrypted_array,
        encrypted_array.length,
        false
      );

      output_to_memory = new RNPLib.rnp_output_t();
      RNPLib.rnp_output_to_memory(output_to_memory.address(), max_out);

      verify_op = new RNPLib.rnp_op_verify_t();
      RNPLib.rnp_op_verify_create(
        verify_op.address(),
        RNPLib.ffi,
        input_from_memory,
        output_to_memory
      );

      // Use a local variable for the temporary wrapper object,
      // to ensure the JS engine will keep the object alive during
      // the call to rnp_op_verify_execute.
      let callbackKeepAlive = RNPLib.rnp_password_cb_t(
        isFirstTry ? collect_key_info_password_cb : use_remembered_password_cb,
        this, // this value used while executing callback
        false // callback return value if exception is thrown
      );

      // If a message is encrypted to a hidden recipients, RNP will call
      // the callback with each available secret key that has a matching
      // type and might potentially work for decrypting. We collect the
      // list of fingerprints, and must unlock all of them.
      RNPLib.rnp_op_verify_set_flags(
        verify_op,
        RNPLib.RNP_VERIFY_ALLOW_HIDDEN_RECIPIENT
      );

      RNPLib.rnp_ffi_set_pass_provider(RNPLib.ffi, callbackKeepAlive, null);
      result.exitCode = RNPLib.rnp_op_verify_execute(verify_op);

      // This call resets the callback reference kept by RNP, which
      // means we can clean up callbackKeepAlive and allow the
      // referenced object to be cleaned up.
      RNPLib.setDefaultPasswordCB();
      callbackKeepAlive = null;

      if (isFirstTry && result.exitCode != 0 && collected_fingerprints.length) {
        for (const fp of collected_fingerprints) {
          const key_handle = this.getKeyHandleByKeyIdOrFingerprint(
            RNPLib.ffi,
            "0x" + fp
          );
          if (
            !key_handle.isNull() &&
            RNPLib.getSecretAvailableFromHandle(key_handle) &&
            RNPLib.isSecretKeyMaterialAvailable(key_handle)
          ) {
            const decryptKey = new RnpPrivateKeyUnlockTracker(key_handle);
            if (decryptKey.available()) {
              decryptKey.setAllowPromptingUserForPassword(true);
              decryptKey.setRememberUnlockPassword(true);
              await decryptKey.unlock();
            }

            if (decryptKey.isUnlocked()) {
              tryAgain = true;
              const pw = decryptKey.getUnlockPassword();
              remembered_passwords.set(fp, pw);

              RNPLib.rnp_input_destroy(input_from_memory);
              input_from_memory = null;
              RNPLib.rnp_output_destroy(output_to_memory);
              output_to_memory = null;
              RNPLib.rnp_op_verify_destroy(verify_op);
              verify_op = null;
            }

            // We don't create the tracker in all scenarios,
            // so we'll release key_handle manually.
            decryptKey.lockIfUnlocked();
            decryptKey.forget();
          }
          RNPLib.rnp_key_handle_destroy(key_handle);
        }
      }

      isFirstTry = false;
    } while (tryAgain);

    let rnpCannotDecrypt = false;
    let queryAllEncryptionRecipients = false;
    let stillUndecidedIfSignatureIsBad = false;

    let useDecodedData;
    let processSignature;
    switch (result.exitCode) {
      case RNPLib.RNP_SUCCESS:
        useDecodedData = true;
        processSignature = true;
        break;
      case RNPLib.RNP_ERROR_SIGNATURE_INVALID:
        // Either the signing key is unavailable, or the signature is
        // indeed bad. Must check signature status below.
        stillUndecidedIfSignatureIsBad = true;
        useDecodedData = true;
        processSignature = true;
        break;
      case RNPLib.RNP_ERROR_SIGNATURE_EXPIRED:
        useDecodedData = true;
        processSignature = false;
        result.statusFlags |= lazy.EnigmailConstants.EXPIRED_SIGNATURE;
        break;
      case RNPLib.RNP_ERROR_DECRYPT_FAILED:
        rnpCannotDecrypt = true;
        useDecodedData = false;
        processSignature = false;
        queryAllEncryptionRecipients = true;
        result.statusFlags |= lazy.EnigmailConstants.DECRYPTION_FAILED;
        break;
      case RNPLib.RNP_ERROR_NO_SUITABLE_KEY:
        rnpCannotDecrypt = true;
        useDecodedData = false;
        processSignature = false;
        queryAllEncryptionRecipients = true;
        result.statusFlags |=
          lazy.EnigmailConstants.DECRYPTION_FAILED |
          lazy.EnigmailConstants.NO_SECKEY;
        break;
      case RNPLib.RNP_ERROR_BAD_FORMAT:
        queryAllEncryptionRecipients = true;
        if (Services.prefs.getBoolPref("mail.openpgp.allow_external_gnupg")) {
          // Same handling as RNP_ERROR_DECRYPT_FAILED, to allow
          // handling of some corrupt messages, see bug 1898832.
          rnpCannotDecrypt = true;
          useDecodedData = false;
          processSignature = false;
          result.statusFlags |= lazy.EnigmailConstants.DECRYPTION_FAILED;
          break;
        }
      // else: fall through to default processing
      default:
        useDecodedData = false;
        processSignature = false;
        lazy.log.warn(
          "rnp_op_verify_execute returned unexpected: " + result.exitCode
        );
        break;
    }

    if (useDecodedData && alreadyDecrypted) {
      result.statusFlags |= lazy.EnigmailConstants.DECRYPTION_OKAY;
    } else if (useDecodedData && !alreadyDecrypted) {
      const prot_mode_str = new lazy.ctypes.char.ptr();
      const prot_cipher_str = new lazy.ctypes.char.ptr();
      const prot_is_valid = new lazy.ctypes.bool();

      if (
        RNPLib.rnp_op_verify_get_protection_info(
          verify_op,
          prot_mode_str.address(),
          prot_cipher_str.address(),
          prot_is_valid.address()
        )
      ) {
        throw new Error("rnp_op_verify_get_protection_info failed");
      }
      const mode = prot_mode_str.readString();
      const cipher = prot_cipher_str.readString();
      const validIntegrityProtection = prot_is_valid.value;

      lazy.log.debug(`Decryption mode=${mode}, cipher=${cipher}`);
      if (mode != "none") {
        if (!validIntegrityProtection) {
          useDecodedData = false;
          result.statusFlags |=
            lazy.EnigmailConstants.MISSING_MDC |
            lazy.EnigmailConstants.DECRYPTION_FAILED;
        } else if (cipher == "null" || this.policyForbidsAlg(cipher)) {
          // don't indicate decryption, because a non-protecting or insecure cipher was used
          result.statusFlags |= lazy.EnigmailConstants.UNKNOWN_ALGO;
        } else {
          queryAllEncryptionRecipients = true;

          const recip_handle = new RNPLib.rnp_recipient_handle_t();
          let rv = RNPLib.rnp_op_verify_get_used_recipient(
            verify_op,
            recip_handle.address()
          );
          if (rv) {
            throw new Error("rnp_op_verify_get_used_recipient failed");
          }

          const c_alg = new lazy.ctypes.char.ptr();
          rv = RNPLib.rnp_recipient_get_alg(recip_handle, c_alg.address());
          if (rv) {
            throw new Error("rnp_recipient_get_alg failed");
          }

          if (this.policyForbidsAlg(c_alg.readString())) {
            result.statusFlags |= lazy.EnigmailConstants.UNKNOWN_ALGO;
          } else {
            this.getKeyIdsFromRecipHandle(
              recip_handle,
              result.encToDetails.myRecipKey
            );
            result.statusFlags |= lazy.EnigmailConstants.DECRYPTION_OKAY;
            result.extStatusFlags |=
              lazy.EnigmailConstants.EXT_INTEGRITY_PROTECTED;
          }
        }
      }
    }

    if (queryAllEncryptionRecipients) {
      const all_recip_count = new lazy.ctypes.size_t();
      if (
        RNPLib.rnp_op_verify_get_recipient_count(
          verify_op,
          all_recip_count.address()
        )
      ) {
        throw new Error("rnp_op_verify_get_recipient_count failed");
      }
      if (all_recip_count.value > 1) {
        for (let recip_i = 0; recip_i < all_recip_count.value; recip_i++) {
          const other_recip_handle = new RNPLib.rnp_recipient_handle_t();
          if (
            RNPLib.rnp_op_verify_get_recipient_at(
              verify_op,
              recip_i,
              other_recip_handle.address()
            )
          ) {
            throw new Error("rnp_op_verify_get_recipient_at failed");
          }
          const encTo = {};
          this.getKeyIdsFromRecipHandle(other_recip_handle, encTo);
          result.encToDetails.allRecipKeys.push(encTo);
        }
      }
    }

    if (useDecodedData) {
      const result_buf = new lazy.ctypes.uint8_t.ptr();
      const result_len = new lazy.ctypes.size_t();
      const rv = RNPLib.rnp_output_memory_get_buf(
        output_to_memory,
        result_buf.address(),
        result_len.address(),
        false
      );

      // result_len is of type UInt64, I don't know of a better way
      // to convert it to an integer.
      const b_len = parseInt(result_len.value.toString());

      if (!rv) {
        // type casting the pointer type to an array type allows us to
        // access the elements by index.
        const uint8_array = lazy.ctypes.cast(
          result_buf,
          lazy.ctypes.uint8_t.array(result_len.value).ptr
        ).contents;

        let str = "";
        for (let i = 0; i < b_len; i++) {
          str += String.fromCharCode(uint8_array[i]);
        }

        result.decryptedData = str;
      }

      if (processSignature) {
        // ignore "no signature" result, that's ok
        await this.getVerifyDetails(
          RNPLib.ffi,
          options.fromAddr,
          options.msgDate,
          verify_op,
          result
        );

        if (
          (result.statusFlags &
            (lazy.EnigmailConstants.GOOD_SIGNATURE |
              lazy.EnigmailConstants.UNCERTAIN_SIGNATURE |
              lazy.EnigmailConstants.EXPIRED_SIGNATURE |
              lazy.EnigmailConstants.BAD_SIGNATURE)) !=
          0
        ) {
          // A decision was already made.
          stillUndecidedIfSignatureIsBad = false;
        }
      }
    }

    if (stillUndecidedIfSignatureIsBad) {
      // We didn't find more details above, so conclude it's bad.
      result.statusFlags |= lazy.EnigmailConstants.BAD_SIGNATURE;
    }

    RNPLib.rnp_input_destroy(input_from_memory);
    RNPLib.rnp_output_destroy(output_to_memory);
    RNPLib.rnp_op_verify_destroy(verify_op);

    if (
      rnpCannotDecrypt &&
      !alreadyDecrypted &&
      Services.prefs.getBoolPref("mail.openpgp.allow_external_gnupg") &&
      lazy.GPGME.allDependenciesLoaded()
    ) {
      // failure processing with RNP, attempt decryption with GPGME
      const r2 = await lazy.GPGME.decryptArray(
        encrypted_array,
        this.enArmorCDataMessage.bind(this)
      );
      if (r2 && !r2.exitCode && r2.decryptedData) {
        // TODO: obtain info which key ID was used for decryption
        //       and set result.decryptKey*
        //       It isn't obvious how to do that with GPGME, because
        //       gpgme_op_decrypt_result provides the list of all the
        //       encryption keys, only.

        // The result may still contain wrapping like compression,
        // and optional signature data. Recursively call ourselves
        // to perform the remaining processing.
        options.encToDetails = result.encToDetails;

        // Handle badly encoded messages, see bugs 1898832 and 1906903.
        const deArmored = this.deArmorString(r2.decryptedData);
        const isDeArmoredStillAsciiArmored = this.isASCIIArmored(deArmored);

        let retval2;
        if (isDeArmoredStillAsciiArmored) {
          retval2 = await RNP.decryptArray(deArmored, options, true);
        } else {
          retval2 = await RNP.decrypt(r2.decryptedData, options, true);
        }

        // The recursive call decrypts what GPGME already unwrapped -- it
        // finishes the job rather than doing it -- so the engine that produced
        // the plaintext is GnuPG. Marked on the result that is returned, which
        // is the one whose status flags reach the header.
        retval2.decryptionEngine = "gnupg";

        return retval2;
      }
    }

    if (!result.decryptedData) {
      const inmem = new RNPLib.rnp_input_t();
      RNPLib.rnp_input_from_memory(
        inmem.address(),
        encrypted_array,
        encrypted_array.length,
        false
      );

      const outmem = new RNPLib.rnp_output_t();
      RNPLib.rnp_output_to_memory(outmem.address(), max_out);

      let rv = RNPLib.rnp_dump_packets_to_output(inmem, outmem, 0);
      if (!rv) {
        const result_buf = new lazy.ctypes.uint8_t.ptr();
        const result_len = new lazy.ctypes.size_t();
        rv = RNPLib.rnp_output_memory_get_buf(
          outmem,
          result_buf.address(),
          result_len.address(),
          false
        );

        if (!rv) {
          // type casting the pointer type to an array type allows us to
          // access the elements by index.
          const uint8_array = lazy.ctypes.cast(
            result_buf,
            lazy.ctypes.uint8_t.array(result_len.value).ptr
          ).contents;

          result.packetDump = lazy.MailStringUtils.uint8ArrayToByteString(
            uint8_array.readTypedArray()
          );
        }
      }

      RNPLib.rnp_input_destroy(inmem);
      RNPLib.rnp_output_destroy(outmem);
    }

    return result;
  },

  async getVerifyDetails(ffi, fromAddr, msgDate, verify_op, result) {
    if (!fromAddr) {
      // We cannot correctly verify without knowing the fromAddr.
      // This scenario is reached when quoting an encrypted MIME part.
      return false;
    }

    const sig_count = new lazy.ctypes.size_t();
    if (
      RNPLib.rnp_op_verify_get_signature_count(verify_op, sig_count.address())
    ) {
      throw new Error("rnp_op_verify_get_signature_count failed");
    }

    // TODO: How should handle (sig_count.value > 1) ?
    if (sig_count.value == 0) {
      // !sig_count.value didn't work, === also doesn't work
      return false;
    }

    const sig = new RNPLib.rnp_op_verify_signature_t();
    if (RNPLib.rnp_op_verify_get_signature_at(verify_op, 0, sig.address())) {
      throw new Error("rnp_op_verify_get_signature_at failed");
    }

    const sig_handle = new RNPLib.rnp_signature_handle_t();
    const sig_get_handle_status = RNPLib.rnp_op_verify_signature_get_handle(
      sig,
      sig_handle.address()
    );
    if (sig_get_handle_status) {
      result.exitCode = -1;
      result.statusFlags |= lazy.EnigmailConstants.BAD_SIGNATURE;
      lazy.log.warn(
        `Verify signature FAILED; rnp_op_verify_signature_get_handle returned ${sig_get_handle_status}`
      );
      return false;
    }

    const sig_id_str = new lazy.ctypes.char.ptr();
    if (RNPLib.rnp_signature_get_keyid(sig_handle, sig_id_str.address())) {
      throw new Error("rnp_signature_get_keyid failed");
    }
    result.keyId = sig_id_str.readString();
    RNPLib.rnp_buffer_destroy(sig_id_str);
    RNPLib.rnp_signature_handle_destroy(sig_handle);

    const sig_status = RNPLib.rnp_op_verify_signature_get_status(sig);
    if (sig_status != RNPLib.RNP_SUCCESS && !result.exitCode) {
      /* Don't allow a good exit code. Keep existing bad code. */
      result.exitCode = -1;
    }

    let query_signer = true;

    switch (sig_status) {
      case RNPLib.RNP_SUCCESS:
        result.statusFlags |= lazy.EnigmailConstants.GOOD_SIGNATURE;
        break;
      case RNPLib.RNP_ERROR_KEY_NOT_FOUND:
        result.statusFlags |=
          lazy.EnigmailConstants.UNCERTAIN_SIGNATURE |
          lazy.EnigmailConstants.NO_PUBKEY;
        query_signer = false;
        break;
      case RNPLib.RNP_ERROR_SIGNATURE_EXPIRED:
        result.statusFlags |= lazy.EnigmailConstants.EXPIRED_SIGNATURE;
        break;
      case RNPLib.RNP_ERROR_SIGNATURE_INVALID:
        result.statusFlags |= lazy.EnigmailConstants.BAD_SIGNATURE;
        break;
      default:
        result.statusFlags |= lazy.EnigmailConstants.BAD_SIGNATURE;
        query_signer = false;
        break;
    }

    if (msgDate && result.statusFlags & lazy.EnigmailConstants.GOOD_SIGNATURE) {
      const created = new lazy.ctypes.uint32_t();
      const expires = new lazy.ctypes.uint32_t(); //relative

      if (
        RNPLib.rnp_op_verify_signature_get_times(
          sig,
          created.address(),
          expires.address()
        )
      ) {
        throw new Error("rnp_op_verify_signature_get_times failed");
      }

      result.sigDetails.sigDate = new Date(created.value * 1000);

      let timeDelta;
      if (result.sigDetails.sigDate > msgDate) {
        timeDelta = result.sigDetails.sigDate - msgDate;
      } else {
        timeDelta = msgDate - result.sigDetails.sigDate;
      }

      if (timeDelta > 1000 * 60 * 60 * 1) {
        result.statusFlags &= ~lazy.EnigmailConstants.GOOD_SIGNATURE;
        result.statusFlags |= lazy.EnigmailConstants.MSG_SIG_INVALID;
        result.extStatusFlags |=
          lazy.EnigmailConstants.EXT_SIGNING_TIME_MISMATCH;
      }
    }

    const signer_key = new RNPLib.rnp_key_handle_t();
    let have_signer_key = false;
    let use_signer_key = false;

    if (query_signer) {
      if (RNPLib.rnp_op_verify_signature_get_key(sig, signer_key.address())) {
        // If sig_status isn't RNP_ERROR_KEY_NOT_FOUND then we must
        // be able to obtain the signer key.
        throw new Error("rnp_op_verify_signature_get_key");
      }

      have_signer_key = true;
      use_signer_key = !this.isBadKey(signer_key, null, RNPLib.ffi);
    }

    if (use_signer_key) {
      const keyInfo = {};
      const ok = this.getKeyInfoFromHandle(
        ffi,
        signer_key,
        keyInfo,
        true,
        false,
        false
      );
      if (!ok) {
        throw new Error("getKeyInfoFromHandle failed");
      }

      let fromMatchesAnyUid = false;
      const fromLower = fromAddr ? fromAddr.toLowerCase() : "";

      for (const uid of keyInfo.userIds) {
        if (uid.type !== "uid") {
          continue;
        }

        if (
          lazy.EnigmailFuncs.getEmailFromUserID(uid.userId).toLowerCase() ===
          fromLower
        ) {
          fromMatchesAnyUid = true;
          break;
        }
      }

      let useUndecided = true;

      if (keyInfo.secretAvailable) {
        const isPersonal = await lazy.PgpSqliteDb2.isAcceptedAsPersonalKey(
          keyInfo.fpr
        );
        if (isPersonal && fromMatchesAnyUid) {
          result.extStatusFlags |= lazy.EnigmailConstants.EXT_SELF_IDENTITY;
          useUndecided = false;
        } else {
          result.statusFlags |= lazy.EnigmailConstants.INVALID_RECIPIENT;
          useUndecided = true;
        }
      } else if (result.statusFlags & lazy.EnigmailConstants.GOOD_SIGNATURE) {
        if (!fromMatchesAnyUid) {
          /* At the time the user had accepted the key,
           * a different set of email addresses might have been
           * contained inside the key. In the meantime, we might
           * have refreshed the key, a email addresses
           * might have been removed or revoked.
           * If the current from was removed/revoked, we'd still
           * get an acceptance match, but the from is no longer found
           * in the key's UID list. That should get "undecided".
           */
          result.statusFlags |= lazy.EnigmailConstants.INVALID_RECIPIENT;
          useUndecided = true;
        } else {
          const acceptanceResult = {};
          try {
            await lazy.PgpSqliteDb2.getAcceptance(
              keyInfo.fpr,
              fromLower,
              acceptanceResult
            );
          } catch (ex) {
            lazy.log.warn("Get acceptance FAILED!", ex);
          }

          // unverified key acceptance means, we consider the signature OK,
          //   but it's not a trusted identity.
          // unverified signature means, we cannot decide if the signature
          //   is ok.

          if (
            "emailDecided" in acceptanceResult &&
            acceptanceResult.emailDecided &&
            "fingerprintAcceptance" in acceptanceResult &&
            acceptanceResult.fingerprintAcceptance.length &&
            acceptanceResult.fingerprintAcceptance != "undecided"
          ) {
            if (acceptanceResult.fingerprintAcceptance == "rejected") {
              result.statusFlags &= ~lazy.EnigmailConstants.GOOD_SIGNATURE;
              result.statusFlags |=
                lazy.EnigmailConstants.BAD_SIGNATURE |
                lazy.EnigmailConstants.INVALID_RECIPIENT;
              useUndecided = false;
            } else if (acceptanceResult.fingerprintAcceptance == "verified") {
              result.statusFlags |= lazy.EnigmailConstants.TRUSTED_IDENTITY;
              useUndecided = false;
            } else if (acceptanceResult.fingerprintAcceptance == "unverified") {
              useUndecided = false;
            }
          }
        }
      }

      if (useUndecided) {
        result.statusFlags &= ~lazy.EnigmailConstants.GOOD_SIGNATURE;
        result.statusFlags |= lazy.EnigmailConstants.UNCERTAIN_SIGNATURE;
      }
    }

    if (have_signer_key) {
      RNPLib.rnp_key_handle_destroy(signer_key);
    }

    return true;
  },

  /**
   * Verify signature of data.
   *
   * @param {string} data - The (allegedly) signed data.
   * @param {string} mimeSignatureData - The signature.
   * @param {?string} fromAddr - Email address.
   * @param {?Date} msgDate - Date.
   * @returns {DecryptVerifyResult} containing verification status details.
   */
  async verifyDetached(data, mimeSignatureData, fromAddr, msgDate) {
    const result = new DecryptVerifyResult();

    const sig_arr = mimeSignatureData.split("").map(e => e.charCodeAt());
    const sig_array = lazy.ctypes.uint8_t.array()(sig_arr);

    const input_sig = new RNPLib.rnp_input_t();
    RNPLib.rnp_input_from_memory(
      input_sig.address(),
      sig_array,
      sig_array.length,
      false
    );

    const input_from_memory = new RNPLib.rnp_input_t();

    const arr = data.split("").map(e => e.charCodeAt());
    const data_array = lazy.ctypes.uint8_t.array()(arr);

    RNPLib.rnp_input_from_memory(
      input_from_memory.address(),
      data_array,
      data_array.length,
      false
    );

    const verify_op = new RNPLib.rnp_op_verify_t();
    if (
      RNPLib.rnp_op_verify_detached_create(
        verify_op.address(),
        RNPLib.ffi,
        input_from_memory,
        input_sig
      )
    ) {
      throw new Error("rnp_op_verify_detached_create failed");
    }

    result.exitCode = RNPLib.rnp_op_verify_execute(verify_op);

    const haveSignature = await this.getVerifyDetails(
      RNPLib.ffi,
      fromAddr,
      msgDate,
      verify_op,
      result
    );
    if (!haveSignature) {
      if (!result.exitCode) {
        /* Don't allow a good exit code. Keep existing bad code. */
        result.exitCode = -1;
      }
      result.statusFlags |= lazy.EnigmailConstants.BAD_SIGNATURE;
    }

    RNPLib.rnp_input_destroy(input_from_memory);
    RNPLib.rnp_input_destroy(input_sig);
    RNPLib.rnp_op_verify_destroy(verify_op);

    return result;
  },

  async genKey(userId, keyType, keyBits, expiryDays, passphrase) {
    let newKeyId = "";
    let newKeyFingerprint = "";

    let primaryKeyType;
    let primaryKeyBits = 0;
    let subKeyType;
    let subKeyBits = 0;
    const primaryKeyCurve = null;
    let subKeyCurve = null;
    // The signing subkey's algorithm, separate from the primary's because the
    // primary no longer signs. Its curve is left to the library, exactly as the
    // primary's is -- naming it fails, and the default for eddsa is Ed25519.
    let signingKeyType;
    const signingKeyCurve = null;
    let expireSeconds = 0;

    if (keyType == "RSA") {
      primaryKeyType = subKeyType = signingKeyType = "rsa";
      primaryKeyBits = subKeyBits = keyBits;
    } else if (keyType == "ECC") {
      primaryKeyType = "eddsa";
      signingKeyType = "eddsa";
      subKeyType = "ecdh";
      subKeyCurve = "Curve25519";
    } else {
      return null;
    }

    if (expiryDays != 0) {
      expireSeconds = expiryDays * 24 * 60 * 60;
    }

    const genOp = new RNPLib.rnp_op_generate_t();
    if (
      RNPLib.rnp_op_generate_create(genOp.address(), RNPLib.ffi, primaryKeyType)
    ) {
      throw new Error("rnp_op_generate_create primary failed");
    }

    if (RNPLib.rnp_op_generate_set_userid(genOp, userId)) {
      throw new Error("rnp_op_generate_set_userid failed");
    }

    // Certify-only primary, as `gpg --quick-generate-key … cert` produces.
    // Signing and encryption go to subkeys, so the certificate key is not in
    // the path of every signature and a subkey can be rotated without
    // replacing the identity.
    //
    // clear_usage first, then add: `add_usage` *adds* to the algorithm's
    // defaults rather than replacing them, so adding "certify" to an eddsa
    // primary would leave it able to sign as well. Measured: without the
    // clear, the primary reports "sc".
    if (RNPLib.rnp_op_generate_clear_usage(genOp)) {
      throw new Error("rnp_op_generate_clear_usage primary failed");
    }
    if (RNPLib.rnp_op_generate_add_usage(genOp, "certify")) {
      throw new Error("rnp_op_generate_add_usage certify failed");
    }

    if (passphrase != null && passphrase.length) {
      if (RNPLib.rnp_op_generate_set_protection_password(genOp, passphrase)) {
        throw new Error("rnp_op_generate_set_protection_password failed");
      }
    }

    if (primaryKeyBits != 0) {
      if (RNPLib.rnp_op_generate_set_bits(genOp, primaryKeyBits)) {
        throw new Error("rnp_op_generate_set_bits primary failed");
      }
    }

    if (primaryKeyCurve != null) {
      if (RNPLib.rnp_op_generate_set_curve(genOp, primaryKeyCurve)) {
        throw new Error("rnp_op_generate_set_curve primary failed");
      }
    }

    if (RNPLib.rnp_op_generate_set_expiration(genOp, expireSeconds)) {
      throw new Error("rnp_op_generate_set_expiration primary failed");
    }

    if (RNPLib.rnp_op_generate_execute(genOp)) {
      throw new Error("rnp_op_generate_execute primary failed");
    }

    const primaryKey = new RNPLib.rnp_key_handle_t();
    if (RNPLib.rnp_op_generate_get_key(genOp, primaryKey.address())) {
      throw new Error("rnp_op_generate_get_key primary failed");
    }

    RNPLib.rnp_op_generate_destroy(genOp);

    newKeyFingerprint = this.getFingerprintFromHandle(primaryKey);
    newKeyId = this.getKeyIDFromHandle(primaryKey);

    // Signing subkey, then the encryption one below. Two subkeys is what GnuPG
    // produces for a certify-only primary; this block is the one that did not
    // exist before, because the primary used to do the signing.
    //
    // The op slot is reused exactly as the encryption block reuses it:
    // rnp_op_generate_destroy releases the op and rnp_op_generate_subkey_create
    // writes a fresh one into the same slot. A restructure that gave each
    // subkey its own rnp_key_handle crashed inside rnp's allocator -- SIGSEGV
    // in arena_dalloc from rnp_op_generate_destroy -- so the existing shape is
    // kept deliberately.
    if (
      RNPLib.rnp_op_generate_subkey_create(
        genOp.address(),
        RNPLib.ffi,
        primaryKey,
        signingKeyType
      )
    ) {
      throw new Error("rnp_op_generate_subkey_create signing failed");
    }

    // Cleared first for the same reason as the primary: add_usage adds to the
    // algorithm's defaults, and an RSA subkey's defaults include encryption --
    // so without the clear, the signing subkey reports "se" and a key-generation
    // test cannot tell which subkey is meant to do what.
    if (RNPLib.rnp_op_generate_clear_usage(genOp)) {
      throw new Error("rnp_op_generate_clear_usage signing failed");
    }
    if (RNPLib.rnp_op_generate_add_usage(genOp, "sign")) {
      throw new Error("rnp_op_generate_add_usage sign failed");
    }

    if (passphrase != null && passphrase.length) {
      if (RNPLib.rnp_op_generate_set_protection_password(genOp, passphrase)) {
        throw new Error("rnp_op_generate_set_protection_password failed");
      }
    }

    if (subKeyBits != 0) {
      if (RNPLib.rnp_op_generate_set_bits(genOp, subKeyBits)) {
        throw new Error("rnp_op_generate_set_bits signing failed");
      }
    }

    if (signingKeyCurve != null) {
      if (RNPLib.rnp_op_generate_set_curve(genOp, signingKeyCurve)) {
        throw new Error("rnp_op_generate_set_curve signing failed");
      }
    }

    if (RNPLib.rnp_op_generate_set_expiration(genOp, expireSeconds)) {
      throw new Error("rnp_op_generate_set_expiration signing failed");
    }

    let signingUnlocked = false;
    try {
      if (passphrase != null && passphrase.length) {
        if (RNPLib.rnp_key_unlock(primaryKey, passphrase)) {
          throw new Error("rnp_key_unlock failed");
        }
        signingUnlocked = true;
      }

      if (RNPLib.rnp_op_generate_execute(genOp)) {
        throw new Error("rnp_op_generate_execute signing failed");
      }
    } finally {
      if (signingUnlocked) {
        RNPLib.rnp_key_lock(primaryKey);
      }
    }

    RNPLib.rnp_op_generate_destroy(genOp);

    if (
      RNPLib.rnp_op_generate_subkey_create(
        genOp.address(),
        RNPLib.ffi,
        primaryKey,
        subKeyType
      )
    ) {
      throw new Error("rnp_op_generate_subkey_create primary failed");
    }

    // And the same again, so the encryption subkey is encryption-only. An RSA
    // key's default capabilities include signing, and a subkey silently able to
    // sign is not the structure this produces.
    if (RNPLib.rnp_op_generate_clear_usage(genOp)) {
      throw new Error("rnp_op_generate_clear_usage encryption failed");
    }
    if (RNPLib.rnp_op_generate_add_usage(genOp, "encrypt")) {
      throw new Error("rnp_op_generate_add_usage encrypt failed");
    }

    if (passphrase != null && passphrase.length) {
      if (RNPLib.rnp_op_generate_set_protection_password(genOp, passphrase)) {
        throw new Error("rnp_op_generate_set_protection_password failed");
      }
    }

    if (subKeyBits != 0) {
      if (RNPLib.rnp_op_generate_set_bits(genOp, subKeyBits)) {
        throw new Error("rnp_op_generate_set_bits sub failed");
      }
    }

    if (subKeyCurve != null) {
      if (RNPLib.rnp_op_generate_set_curve(genOp, subKeyCurve)) {
        throw new Error("rnp_op_generate_set_curve sub failed");
      }
    }

    if (RNPLib.rnp_op_generate_set_expiration(genOp, expireSeconds)) {
      throw new Error("rnp_op_generate_set_expiration sub failed");
    }

    let unlocked = false;
    try {
      if (passphrase != null && passphrase.length) {
        if (RNPLib.rnp_key_unlock(primaryKey, passphrase)) {
          throw new Error("rnp_key_unlock failed");
        }
        unlocked = true;
      }

      if (RNPLib.rnp_op_generate_execute(genOp)) {
        throw new Error("rnp_op_generate_execute sub failed");
      }
    } finally {
      if (unlocked) {
        RNPLib.rnp_key_lock(primaryKey);
      }
    }

    RNPLib.rnp_op_generate_destroy(genOp);
    RNPLib.rnp_key_handle_destroy(primaryKey);

    await lazy.PgpSqliteDb2.acceptAsPersonalKey(newKeyFingerprint);

    return newKeyId;
  },

  async saveKeyRings() {
    RNPLib.saveKeys();
    Services.obs.notifyObservers(null, "openpgp-key-change");
  },

  importToFFI(ffi, keyBlockStr, usePublic, useSecret) {
    if (usePublic && useSecret) {
      throw new Error("Cannot import public and secret keys at the same time");
    }
    const permissive = !useSecret; // permissive only for public keys

    const input_from_memory = new RNPLib.rnp_input_t();

    if (!keyBlockStr) {
      throw new Error("no keyBlockStr parameter in importToFFI");
    }

    // Input might be either plain text or binary data.
    // If the input is binary, do not modify it.
    // If the input contains characters with a multi-byte char code value,
    // we know the input doesn't consist of binary 8-bit values. Rather,
    // it contains text with multi-byte characters. The only scenario
    // in which we can tolerate those are comment lines, which we can
    // filter out.

    // Remove comment lines.
    const input = keyBlockStr.includes("-----BEGIN PGP ")
      ? keyBlockStr.replace(/^Comment:.*(\r?\n|\r)/gm, "")
      : keyBlockStr;
    const arr = lazy.MailStringUtils.byteStringToUint8Array(input);
    if (arr.some(c => c > 255)) {
      // Not 8-bit data.
      throw new Error(`Multi-byte string input: ${input}`);
    }
    const key_array = lazy.ctypes.uint8_t.array()(arr);

    if (
      RNPLib.rnp_input_from_memory(
        input_from_memory.address(),
        key_array,
        key_array.length,
        false
      )
    ) {
      throw new Error("rnp_input_from_memory failed");
    }

    const jsonInfo = new lazy.ctypes.char.ptr();

    let flags = 0;
    if (usePublic) {
      flags |= RNPLib.RNP_LOAD_SAVE_PUBLIC_KEYS;
    }
    if (useSecret) {
      flags |= RNPLib.RNP_LOAD_SAVE_SECRET_KEYS;
    }

    if (permissive) {
      flags |= RNPLib.RNP_LOAD_SAVE_PERMISSIVE;
    }

    let rv = RNPLib.rnp_import_keys(
      ffi,
      input_from_memory,
      flags,
      jsonInfo.address()
    );
    if (rv) {
      lazy.log.warn(`rnp_import_keys FAILED; rv=${rv}`);
    } else {
      const info = JSON.parse(jsonInfo.readString());
      if (!("keys" in info) || !info.keys.length) {
        lazy.log.warn("rnp_import_keys found no supported keys");
        rv = -1;
      }
    }

    // TODO: parse jsonInfo and return a list of keys,
    // as seen in keyRing.importKeyAsync.
    // (should prevent the incorrect popup "no keys imported".)

    RNPLib.rnp_buffer_destroy(jsonInfo);
    RNPLib.rnp_input_destroy(input_from_memory);

    return rv;
  },

  maxImportKeyBlockSize: 5000000,

  async getOnePubKeyFromKeyBlock(keyBlockStr, fpr) {
    if (!keyBlockStr) {
      throw new Error(`Invalid parameter; keyblock: ${keyBlockStr}`);
    }

    if (keyBlockStr.length > RNP.maxImportKeyBlockSize) {
      throw new Error("rejecting big keyblock");
    }

    const tempFFI = RNPLib.prepare_ffi();
    if (!tempFFI) {
      throw new Error("Couldn't initialize librnp.");
    }

    let pubKey;
    if (!this.importToFFI(tempFFI, keyBlockStr, true, false)) {
      pubKey = await this.getPublicKey("0x" + fpr, tempFFI);
    }

    RNPLib.rnp_ffi_destroy(tempFFI);
    return pubKey;
  },

  async getKeyListFromKeyBlockImpl(
    keyBlockStr,
    pubkey = true,
    seckey = false,
    withPubKey = false
  ) {
    if (!keyBlockStr) {
      throw new Error(`Invalid parameter; keyblock: ${keyBlockStr}`);
    }

    if (keyBlockStr.length > RNP.maxImportKeyBlockSize) {
      throw new Error("rejecting big keyblock");
    }

    const tempFFI = RNPLib.prepare_ffi();
    if (!tempFFI) {
      throw new Error("Couldn't initialize librnp.");
    }

    let keyList = null;
    if (!this.importToFFI(tempFFI, keyBlockStr, pubkey, seckey)) {
      keyList = await this.getKeysFromFFI(
        tempFFI,
        true,
        null,
        false,
        withPubKey
      );
    }

    RNPLib.rnp_ffi_destroy(tempFFI);
    return keyList;
  },

  /**
   * Take two or more ASCII armored key blocks and import them into memory,
   * and return the merged public key for the given fingerprint.
   * (Other keys included in the key blocks are ignored.)
   * The intention is to use it to combine keys obtained from different places,
   * possibly with updated/different expiration date and userIds etc. to
   * a canonical representation of them.
   *
   * @param {string} fingerprint - Key fingerprint.
   * @param {...string} keyBlocks - Key blocks.
   * @returns {string} the resulting public key of the blocks
   */
  async mergePublicKeyBlocks(fingerprint, ...keyBlocks) {
    if (keyBlocks.some(b => b.length > RNP.maxImportKeyBlockSize)) {
      throw new Error("keyBlock too big");
    }

    const tempFFI = RNPLib.prepare_ffi();
    if (!tempFFI) {
      throw new Error("Couldn't initialize librnp.");
    }

    try {
      for (const block of new Set(keyBlocks)) {
        if (this.importToFFI(tempFFI, block, true, false)) {
          throw new Error("Merging public keys failed");
        }
      }
      return await this.getPublicKey(`0x${fingerprint}`, tempFFI);
    } finally {
      RNPLib.rnp_ffi_destroy(tempFFI);
    }
  },

  async importRevImpl(data) {
    if (!data || typeof data != "string") {
      throw new Error("invalid data parameter");
    }

    const arr = data.split("").map(e => e.charCodeAt());
    var key_array = lazy.ctypes.uint8_t.array()(arr);

    const input_from_memory = new RNPLib.rnp_input_t();
    if (
      RNPLib.rnp_input_from_memory(
        input_from_memory.address(),
        key_array,
        key_array.length,
        false
      )
    ) {
      throw new Error("rnp_input_from_memory failed");
    }

    const jsonInfo = new lazy.ctypes.char.ptr();

    const flags = 0;
    const rv = RNPLib.rnp_import_signatures(
      RNPLib.ffi,
      input_from_memory,
      flags,
      jsonInfo.address()
    );
    if (rv) {
      lazy.log.warn(`rnp_import_signatures FAILED; rv=${rv}`);
    }

    // TODO: parse jsonInfo

    RNPLib.rnp_buffer_destroy(jsonInfo);
    RNPLib.rnp_input_destroy(input_from_memory);
    await this.saveKeyRings();

    return rv;
  },

  async importSecKeyBlockImpl(
    win,
    passCB,
    keepPassphrases,
    keyBlockStr,
    limitedFPRs = []
  ) {
    return this._importKeyBlockWithAutoAccept(
      win,
      passCB,
      keepPassphrases,
      keyBlockStr,
      false,
      true,
      null,
      limitedFPRs
    );
  },

  async importPubkeyBlockAutoAcceptImpl(
    win,
    keyBlockStr,
    acceptance,
    limitedFPRs = []
  ) {
    return this._importKeyBlockWithAutoAccept(
      win,
      null,
      false,
      keyBlockStr,
      true,
      false,
      acceptance,
      limitedFPRs
    );
  },

  /**
   * Import either a public key or a secret key.
   * Importing both at the same time isn't supported by this API.
   *
   * @param {?nsIWindow} win - Parent window, may be null
   * @param {Function} passCB - a callback function that will be called if the user needs
   *   to enter a passphrase to unlock a secret key. See passphrasePromptCallback
   *   for the function signature.
   * @param {boolean} keepPassphrases - controls which passphrase will
   *   be used to protect imported secret keys. If true, the existing
   *   passphrase will be kept. If false, (of if currently there's no
   *   passphrase set), passphrase protection will be changed to use
   *   our automatic passphrase (to allow automatic protection by
   *   primary password, whether's it's currently enabled or not).
   * @param {string} keyBlockStr - An block of OpenPGP key data. See
   *   implementation of function importToFFI for allowed contents.
   *   TODO: Write better documentation for this parameter.
   * @param {boolean} pubkey - If true, import the public keys found in
   *   keyBlockStr.
   * @param {boolean} seckey - If true, import the secret keys found in
   *   keyBlockStr.
   * @param {string} acceptance - The key acceptance level that should
   *   be assigned to imported public keys.
   *   TODO: Write better documentation for the allowed values.
   * @param {string[]} limitedFPRs - This is a filtering parameter.
   *   If the array is empty, all keys will be imported.
   *   If the array contains at least one entry, a key will be imported
   *   only if its fingerprint (of the primary key) is listed in this
   *   array.
   */
  async _importKeyBlockWithAutoAccept(
    win,
    passCB,
    keepPassphrases,
    keyBlockStr,
    pubkey,
    seckey,
    acceptance,
    limitedFPRs = []
  ) {
    if (keyBlockStr.length > RNP.maxImportKeyBlockSize) {
      throw new Error("rejecting big keyblock");
    }
    if (pubkey && seckey) {
      throw new Error("Cannot import public and secret keys at the same time");
    }
    // A secret key in the internal store is protected by the SDR key, which
    // without a Primary Password is stretched once -- so importing one while
    // there is no password hands the user a private key that anyone with the
    // profile can read. Refuse here rather than warning, because a warning is
    // dismissible and this is not.
    //
    // `requirePrimaryPassword()` opens the change-password dialog itself and
    // reports whether the user complied, which is what D7 requires: the
    // refusal has to carry the route forward. **It asks whether a password
    // exists, not merely whether the enterprise policy requires one** -- Item
    // 53's stronger reading, chosen by the user on 2026-10-27, because
    // `enforcePrimaryPassword()` returns true immediately on every ordinary
    // profile and so protected nobody.
    //
    // **The window is what keeps this from refusing the whole test suite.** A
    // user-initiated import always has one; tests and programmatic imports pass
    // null, and `requirePrimaryPassword()` refuses without a window rather than
    // passing silently. So a null-window import is refused here, deliberately,
    // and tests that import secret keys are expected to set a Primary Password
    // first -- which is the behaviour this requirement is about.
    if (seckey && !requirePrimaryPassword(win)) {
      const refused = {};
      refused.exitCode = 0;
      refused.importedKeys = [];
      refused.errorMsg = "";
      refused.fingerprintsWithUnsupportedFeatures = [];
      return refused;
    }

    const permissive = !seckey; // permissive only for public keys

    /*
     * Import strategy:
     * - import file into a temporary space, in-memory only (ffi)
     * - if we failed to decrypt the secret keys, return null
     * - set the password of secret keys that don't have one yet
     * - get the key listing of all keys from the temporary space,
     *   which is want we want to return as the import report
     * - export all keys from the temporary space, and import them
     *   into our permanent space.
     */
    const userFlags = { canceled: false };

    const result = {};
    result.exitCode = -1;
    result.importedKeys = [];
    result.errorMsg = "";
    result.fingerprintsWithUnsupportedFeatures = [];

    const tempFFI = RNPLib.prepare_ffi();
    if (!tempFFI) {
      throw new Error("Couldn't initialize librnp.");
    }

    // TODO: check result
    if (this.importToFFI(tempFFI, keyBlockStr, pubkey, seckey)) {
      result.errorMsg = "RNP.importToFFI failed";
      RNPLib.rnp_ffi_destroy(tempFFI);
      return result;
    }

    const keys = await this.getKeysFromFFI(tempFFI, true);
    const pwCache = {
      passwords: [],
    };

    // Abort if we see keys that we don't support -- decided on the key's
    // version, not on the length of its fingerprint.
    //
    // The length was a proxy, and it was a wrong one in both directions. It
    // refused v5, whose fingerprint is 32 bytes: librnp handles v5
    // unconditionally (`Fingerprint::size_valid` accepts 16, 20 and 32), so the
    // refusal was Thunderbird's own and forced a v5 user to generate a v4 key
    // instead -- with a SHA-1 fingerprint where v5 uses SHA-256. And it would
    // have *accepted* a v6 key if one had a 40-character fingerprint, which it
    // does not, but the guard was asking about the representation rather than
    // about the thing that matters.
    //
    // v5 is accepted. v6 is still refused, and for a different reason:
    // librnp needs ENABLE_CRYPTO_REFRESH (the Botan 3 backend) for it, and
    // `third_party/rnp/moz.build` does not set it -- so a v6 key would parse
    // and then fail unpredictably rather than being refused cleanly.
    //
    // The comment that stood here asked for exactly this and was left as a TODO;
    // `rnp_key_get_version` was already bound, and `addKeyAttributes()` already
    // stores the result on the key object.
    const MAX_SUPPORTED_VERSION = 5;
    for (const k of keys) {
      if (k.version > MAX_SUPPORTED_VERSION) {
        RNPLib.rnp_ffi_destroy(tempFFI);
        lazy.log.warn(
          `Cannot import OpenPGP key with fingerprint ${k.fpr}: version ` +
            `${k.version} is newer than the supported ${MAX_SUPPORTED_VERSION}.`
        );
        result.errorMsg = `Found unsupported key: ${k.fpr}`;
        return result;
      }
    }

    // Prior to importing, ensure the user is able to unlock all keys

    // If anything goes wrong during our attempt to unlock keys,
    // we don't want to keep key material remain unprotected in memory,
    // that's why we remember the trackers, including the respective
    // unlock passphrase, temporarily in memory, and we'll minimize
    // the period of time during which the key remains unprotected.
    const secretKeyTrackers = new Map();
    let unableToUnlockId = null;

    for (const k of keys) {
      const fprStr = "0x" + k.fpr;
      if (limitedFPRs.length && !limitedFPRs.includes(fprStr)) {
        continue;
      }

      let impKey = await this.getKeyHandleByIdentifier(tempFFI, fprStr);
      if (impKey.isNull()) {
        throw new Error("cannot get key handle for imported key: " + k.fpr);
      }

      if (!k.secretAvailable) {
        RNPLib.rnp_key_handle_destroy(impKey);
        impKey = null;
      } else {
        const primaryKey = new RnpPrivateKeyUnlockTracker(impKey);
        impKey = null;

        if (this.keyObjHasUnsupportedFeatures(k)) {
          lazy.log.warn(
            `OpenPGP secret key with fingerprint ${k.fpr} advertises unsupported features.`
          );
          // This function shouldn't bring up the warning.
          // Let the caller do it.
          result.fingerprintsWithUnsupportedFeatures.push(k.fpr);
        }

        // Don't attempt to unlock secret keys that are unavailable.
        if (primaryKey.available()) {
          // Is it unprotected?
          primaryKey.unlockWithPassword("");
          if (primaryKey.isUnlocked()) {
            // yes, it's unprotected (empty passphrase)
            await primaryKey.setAutoPassphrase();
          } else {
            // try to unlock with the recently entered passwords,
            // or ask the user, if allowed
            primaryKey.setPasswordCache(pwCache);
            primaryKey.setAllowAutoUnlockWithCachedPasswords(true);

            // Item 23: bound the remaining prompt site.
            //
            // A passphrase callback is legitimate here. A user with an internal
            // key protected by their own passphrase must still be able to
            // unlock it, and that passphrase belongs to Thunderbird's store and
            // was typed for this purpose. What is not legitimate is the same
            // callback running for a key whose protection lives in the external
            // keyring: gpg-agent asks for that passphrase through pinentry, and
            // Thunderbird must never see it -- a prompt here is what makes
            // unprotect-with-the-typed-passphrase possible.
            //
            // This is a bound independent of the two that already exist. The
            // import is refused earlier for a GnuPG-held key, and the unlock
            // tracker refuses to prompt for one; both are correct, and both are
            // guards in front of *this* line. If either is ever reordered, or a
            // new route reaches this code without them, the callback would
            // still be wired up and would still ask. So the callback is not
            // handed over for such a key at all.
            //
            // Checked here rather than at the call sites because this is the
            // one place every secret-key import passes through with a callback
            // in hand, and the item asks for the assertion to hold whatever the
            // call graph does next.
            let mayPromptForThisKey = !!passCB;
            if (mayPromptForThisKey) {
              const fprToCheck = primaryKey.getFingerprint();
              if (
                fprToCheck &&
                lazy.GPGME.init() &&
                lazy.GPGME.hasSecretKey(fprToCheck)
              ) {
                lazy.log.error(
                  `Refusing to attach a passphrase prompt for ${fprToCheck}: ` +
                    `the external GnuPG keyring holds this key, so its ` +
                    `passphrase is gpg-agent's to ask for. This should not be ` +
                    `reachable; the import guard should have refused earlier.`
                );
                mayPromptForThisKey = false;
              }
            }

            primaryKey.setAllowPromptingUserForPassword(mayPromptForThisKey);
            primaryKey.setPassphraseCallback(
              mayPromptForThisKey ? passCB : null
            );
            primaryKey.setRememberUnlockPassword(true);
            await primaryKey.unlock(tempFFI);
            if (!primaryKey.isUnlocked()) {
              userFlags.canceled = true;
              unableToUnlockId = RNP.getKeyIDFromHandle(primaryKey.getHandle());
            } else {
              secretKeyTrackers.set(fprStr, primaryKey);
            }
          }
        }

        if (!userFlags.canceled) {
          const sub_count = new lazy.ctypes.size_t();
          if (
            RNPLib.rnp_key_get_subkey_count(
              primaryKey.getHandle(),
              sub_count.address()
            )
          ) {
            throw new Error("rnp_key_get_subkey_count failed");
          }

          for (let i = 0; i < sub_count.value && !userFlags.canceled; i++) {
            let sub_handle = new RNPLib.rnp_key_handle_t();
            if (
              RNPLib.rnp_key_get_subkey_at(
                primaryKey.getHandle(),
                i,
                sub_handle.address()
              )
            ) {
              throw new Error("rnp_key_get_subkey_at failed");
            }

            const subTracker = new RnpPrivateKeyUnlockTracker(sub_handle);
            sub_handle = null;

            if (subTracker.available()) {
              // Is it unprotected?
              subTracker.unlockWithPassword("");
              if (subTracker.isUnlocked()) {
                // yes, it's unprotected (empty passphrase)
                await subTracker.setAutoPassphrase();
              } else {
                // try to unlock with the recently entered passwords,
                // or ask the user, if allowed
                subTracker.setPasswordCache(pwCache);
                subTracker.setAllowAutoUnlockWithCachedPasswords(true);
                subTracker.setAllowPromptingUserForPassword(!!passCB);
                subTracker.setPassphraseCallback(passCB);
                subTracker.setRememberUnlockPassword(true);
                await subTracker.unlock(tempFFI);
                if (!subTracker.isUnlocked()) {
                  userFlags.canceled = true;
                  unableToUnlockId = RNP.getKeyIDFromHandle(
                    subTracker.getHandle()
                  );
                  break;
                } else {
                  secretKeyTrackers.set(
                    this.getFingerprintFromHandle(subTracker.getHandle()),
                    subTracker
                  );
                }
              }
            }
          }
        }
      }

      if (userFlags.canceled) {
        break;
      }
    }

    if (unableToUnlockId) {
      result.errorMsg = "Cannot unlock key " + unableToUnlockId;
    }

    if (!userFlags.canceled) {
      for (const k of keys) {
        const fprStr = "0x" + k.fpr;
        if (limitedFPRs.length && !limitedFPRs.includes(fprStr)) {
          continue;
        }

        // We allow importing, if any of the following is true
        // - it contains a secret key
        // - it contains at least one user ID
        // - it is an update for an existing key (possibly new validity/revocation)

        if (!k.userIds.length && !k.secretAvailable) {
          const existingKey = await this.getKeyHandleByIdentifier(
            RNPLib.ffi,
            "0x" + k.fpr
          );
          if (existingKey.isNull()) {
            continue;
          }
          RNPLib.rnp_key_handle_destroy(existingKey);
        }

        let impKeyPub;
        const impKeySecTracker = secretKeyTrackers.get(fprStr);
        if (!impKeySecTracker) {
          impKeyPub = await this.getKeyHandleByIdentifier(tempFFI, fprStr);
        }

        if (!keepPassphrases) {
          // It's possible that the primary key doesn't come with a
          // secret key (only public key of primary key was imported).
          // In that scenario, we must still process subkeys that come
          // with a secret key.

          if (impKeySecTracker) {
            impKeySecTracker.unprotect();
            await impKeySecTracker.setAutoPassphrase();
          }

          const sub_count = new lazy.ctypes.size_t();
          if (
            RNPLib.rnp_key_get_subkey_count(
              impKeySecTracker ? impKeySecTracker.getHandle() : impKeyPub,
              sub_count.address()
            )
          ) {
            throw new Error("rnp_key_get_subkey_count failed");
          }

          for (let i = 0; i < sub_count.value; i++) {
            const sub_handle = new RNPLib.rnp_key_handle_t();
            if (
              RNPLib.rnp_key_get_subkey_at(
                impKeySecTracker ? impKeySecTracker.getHandle() : impKeyPub,
                i,
                sub_handle.address()
              )
            ) {
              throw new Error("rnp_key_get_subkey_at failed");
            }

            const subTracker = secretKeyTrackers.get(
              this.getFingerprintFromHandle(sub_handle)
            );
            if (!subTracker) {
              // There is no secret key material for this subkey available,
              // that's why no tracker was created, we can skip it.
              continue;
            }
            subTracker.unprotect();
            await subTracker.setAutoPassphrase();
          }
        }

        let exportFlags =
          RNPLib.RNP_KEY_EXPORT_ARMORED | RNPLib.RNP_KEY_EXPORT_SUBKEYS;

        if (pubkey) {
          exportFlags |= RNPLib.RNP_KEY_EXPORT_PUBLIC;
        }
        if (seckey) {
          exportFlags |= RNPLib.RNP_KEY_EXPORT_SECRET;
        }

        const output_to_memory = new RNPLib.rnp_output_t();
        if (RNPLib.rnp_output_to_memory(output_to_memory.address(), 0)) {
          throw new Error("rnp_output_to_memory failed");
        }

        if (
          RNPLib.rnp_key_export(
            impKeySecTracker ? impKeySecTracker.getHandle() : impKeyPub,
            output_to_memory,
            exportFlags
          )
        ) {
          throw new Error("rnp_key_export failed");
        }

        if (impKeyPub) {
          RNPLib.rnp_key_handle_destroy(impKeyPub);
          impKeyPub = null;
        }

        const result_buf = new lazy.ctypes.uint8_t.ptr();
        const result_len = new lazy.ctypes.size_t();
        if (
          RNPLib.rnp_output_memory_get_buf(
            output_to_memory,
            result_buf.address(),
            result_len.address(),
            false
          )
        ) {
          throw new Error("rnp_output_memory_get_buf failed");
        }

        const input_from_memory = new RNPLib.rnp_input_t();

        if (
          RNPLib.rnp_input_from_memory(
            input_from_memory.address(),
            result_buf,
            result_len,
            false
          )
        ) {
          throw new Error("rnp_input_from_memory failed");
        }

        let importFlags = 0;
        if (pubkey) {
          importFlags |= RNPLib.RNP_LOAD_SAVE_PUBLIC_KEYS;
        }
        if (seckey) {
          importFlags |= RNPLib.RNP_LOAD_SAVE_SECRET_KEYS;
        }
        if (permissive) {
          importFlags |= RNPLib.RNP_LOAD_SAVE_PERMISSIVE;
        }

        if (
          RNPLib.rnp_import_keys(
            RNPLib.ffi,
            input_from_memory,
            importFlags,
            null
          )
        ) {
          throw new Error("rnp_import_keys failed");
        }

        result.importedKeys.push("0x" + k.id);

        RNPLib.rnp_input_destroy(input_from_memory);
        RNPLib.rnp_output_destroy(output_to_memory);

        // For acceptance "undecided", we don't store it, because that's
        // the default if no value is stored.
        const actionableAcceptances = ["rejected", "unverified", "verified"];

        if (
          pubkey &&
          !k.secretAvailable &&
          actionableAcceptances.includes(acceptance)
        ) {
          // For each imported public key, if its current acceptance is
          // undecided, we update its acceptance for the associated email
          // addresses to the passed acceptance value.
          // We also update the acceptance for all the email addresses
          // associated to a key if both the current acceptance for that key
          // and the passed acceptance value are unverified.
          // If the acceptance is rejected or verified, we keep it is as is.

          const currentAcceptance =
            await lazy.PgpSqliteDb2.getFingerprintAcceptance(null, k.fpr);

          if (
            !currentAcceptance ||
            currentAcceptance == "undecided" ||
            (currentAcceptance == "unverified" && acceptance == "unverified")
          ) {
            // Currently undecided or unverified, allowed to update.
            const allEmails = [];

            for (const uid of k.userIds) {
              if (uid.type != "uid") {
                continue;
              }

              const uidEmail = lazy.EnigmailFuncs.getEmailFromUserID(
                uid.userId
              );
              if (uidEmail) {
                allEmails.push(uidEmail);
              }
            }
            await lazy.PgpSqliteDb2.updateAcceptance(
              k.fpr,
              allEmails,
              acceptance
            );
          }
        }
      }

      result.exitCode = 0;
      await this.saveKeyRings();
    }

    for (const valTracker of secretKeyTrackers.values()) {
      valTracker.release();
    }

    RNPLib.rnp_ffi_destroy(tempFFI);
    return result;
  },

  /**
   * Delete the given key.
   *
   * @param {string} keyFingerprint - Fingerprint.
   * @param {boolean} deleteSecret - Whether to delete secret key as well.
   */
  async deleteKey(keyFingerprint, deleteSecret) {
    const handle = new RNPLib.rnp_key_handle_t();
    if (
      RNPLib.rnp_locate_key(
        RNPLib.ffi,
        "fingerprint",
        keyFingerprint,
        handle.address()
      )
    ) {
      throw new Error(`rnp_locate_key failed for ${keyFingerprint}`);
    }

    let flags = RNPLib.RNP_KEY_REMOVE_PUBLIC | RNPLib.RNP_KEY_REMOVE_SUBKEYS;
    if (deleteSecret) {
      flags |= RNPLib.RNP_KEY_REMOVE_SECRET;
    }

    if (RNPLib.rnp_key_remove(handle, flags)) {
      throw new Error(`rnp_key_remove failed; deleteSecret=${deleteSecret}`);
    }

    RNPLib.rnp_key_handle_destroy(handle);
    await this.saveKeyRings();
  },

  /**
   * Revoke the given key.
   *
   * @param {string} keyFingerprint - Fingerprint.
   */
  async revokeKey(keyFingerprint) {
    await this._revoke(keyFingerprint, null, null);
  },

  /**
   * Revoke one subkey, leaving the primary key and its other subkeys alone.
   *
   * Item 70. `revokeKey()` already worked on any handle -- the tracker resolves
   * a subkey fingerprint without forcing the primary, and `rnp_key_revoke`
   * acts on whatever handle it is given -- so there is no new library work
   * here, only a way to reach it. What the UI previously offered was "revoke"
   * on a whole key, which is a much larger act than retiring one subkey.
   *
   * The authorising secret key is the primary's: a subkey revocation is signed
   * by the key that made the subkey, and `rnp_key_revoke` finds it. So the
   * subkey's own secret material is not required, only the primary's.
   *
   * @param {string} subkeyFpr - Fingerprint of the subkey to revoke.
   * @param {?string} code - RFC 4880 reason code: "no", "superseded",
   *   "compromised" or "retired". Null means "no reason given".
   * @param {?string} reason - Free text, or null.
   * @returns {Promise<boolean>} true if the subkey is now revoked.
   */
  async revokeSubkey(subkeyFpr, code = null, reason = null) {
    return this._revoke(subkeyFpr, code, reason, true);
  },

  /**
   * The one revoke path, for a key or a subkey.
   *
   * @param {string} fingerprint - Of the key or subkey.
   * @param {?string} code - Reason code, or null.
   * @param {?string} reason - Free text, or null.
   * @param {boolean} [mustBeSubkey=false] - Refuse a primary key's fingerprint.
   * @returns {Promise<boolean>} true if the revocation was applied.
   */
  async _revoke(fingerprint, code, reason, mustBeSubkey = false) {
    // Checked before the tracker is built: constructing one for a fingerprint
    // that is not in the ring throws from `available()` rather than reporting
    // absence. The same guard as `addUserId()` for the same reason.
    if (!this._keyIsInTheRing(fingerprint)) {
      return false;
    }

    const tracker =
      RnpPrivateKeyUnlockTracker.constructFromFingerprint(fingerprint);
    if (!tracker.available()) {
      return false;
    }

    if (mustBeSubkey) {
      // Checked before anything is revoked: calling this with a primary's
      // fingerprint would revoke the whole key, which is a different and much
      // larger operation than the caller asked for. The guard lives here
      // rather than in the UI because the UI's row index is not evidence.
      const sub = new lazy.ctypes.bool();
      if (RNPLib.rnp_key_is_sub(tracker.getHandle(), sub.address())) {
        tracker.release();
        throw new Error("rnp_key_is_sub failed");
      }
      if (!sub.value) {
        tracker.release();
        return false;
      }
    }

    // The signature that authorises a subkey revocation is made by the
    // *primary* key, which `rnp_key_revoke` finds for itself in the keyring --
    // but only if that key is unlocked. Unlocking the subkey alone is not
    // enough, and the failure is a bare RNP error with no clue why.
    const trackers = [tracker];
    const handle = tracker.getHandle();
    const is_sub = new lazy.ctypes.bool();
    if (RNPLib.rnp_key_is_sub(handle, is_sub.address())) {
      tracker.release();
      throw new Error("rnp_key_is_sub failed");
    }
    if (is_sub.value) {
      const primary = this.getPrimaryKeyHandleFromSub(RNPLib.ffi, handle);
      if (!primary) {
        tracker.release();
        return false;
      }
      const primaryTracker = new RnpPrivateKeyUnlockTracker(primary);
      trackers.push(primaryTracker);
    }

    for (const t of trackers) {
      t.setAllowPromptingUserForPassword(true);
      t.setAllowAutoUnlockWithCachedPasswords(true);
      await t.unlock();
      if (!t.isUnlocked()) {
        for (const other of trackers) {
          other.release();
        }
        return false;
      }
    }

    const revokeResult = RNPLib.rnp_key_revoke(handle, 0, null, code, reason);
    for (const t of trackers) {
      t.release();
    }
    if (revokeResult) {
      throw new Error(`rnp_key_revoke failed for fingerprint=${fingerprint}`);
    }
    await this.saveKeyRings();
    return true;
  },

  /**
   * Remove a user ID from a key.
   *
   * Item 70. `rnp_uid_remove` was bound but reached only inside
   * `export_pubkey_strip_sigs_uids`, a public-export helper, so key management
   * could not use it. This is the key-management path: the user ID is removed
   * from the real key, and the change is saved.
   *
   * Not reversible by re-adding: the self-certification is gone, so anything
   * that recorded this address against the key no longer sees it. The UI
   * confirms first.
   *
   * @param {string} primaryFpr - Fingerprint of the key to edit.
   * @param {string} userId - The user ID to remove, matched by its address as
   *   well as by its whole text.
   * @returns {Promise<boolean>} true if it was removed.
   */
  async removeUserId(primaryFpr, userId) {
    if (!this._keyIsInTheRing(primaryFpr)) {
      return false;
    }

    const tracker =
      RnpPrivateKeyUnlockTracker.constructFromFingerprint(primaryFpr);
    if (!tracker.available()) {
      return false;
    }

    tracker.setAllowPromptingUserForPassword(true);
    tracker.setAllowAutoUnlockWithCachedPasswords(true);
    await tracker.unlock();
    if (!tracker.isUnlocked()) {
      tracker.release();
      return false;
    }

    let uidHandle = null;
    try {
      uidHandle = this._findUidHandle(tracker.getHandle(), userId);
      if (!uidHandle) {
        return false;
      }
      if (RNPLib.rnp_uid_remove(tracker.getHandle(), uidHandle)) {
        throw new Error("rnp_uid_remove failed");
      }
    } finally {
      if (uidHandle) {
        RNPLib.rnp_uid_handle_destroy(uidHandle);
      }
      tracker.release();
    }

    await this.saveKeyRings();
    return true;
  },

  _getKeyHandleByKeyIdOrFingerprint(ffi, id, findPrimary) {
    if (!id.startsWith("0x")) {
      throw new Error(`id should be 0x prefixed; got id ${id}`);
    }
    // remove 0x
    id = id.substring(2);

    let type = null;
    if (id.length == 16) {
      type = "keyid";
    } else if (id.length == 40 || id.length == 32 || id.length == 64) {
      // 16, 20 and 32 bytes: v4, v3 and v5. Folded into the same branch rather
      // than given separate ones, because the length is only being used to tell
      // a key ID from a fingerprint here -- which version it is belongs to the
      // import guard, where it is asked of the key itself.
      type = "fingerprint";
    } else {
      throw new Error("key/fingerprint identifier of unexpected length: " + id);
    }

    let key = new RNPLib.rnp_key_handle_t();
    if (RNPLib.rnp_locate_key(ffi, type, id, key.address())) {
      throw new Error("rnp_locate_key failed, " + type + ", " + id);
    }

    if (!key.isNull() && findPrimary) {
      const is_subkey = new lazy.ctypes.bool();
      if (RNPLib.rnp_key_is_sub(key, is_subkey.address())) {
        throw new Error("rnp_key_is_sub failed");
      }
      if (is_subkey.value) {
        const primaryKey = this.getPrimaryKeyHandleFromSub(ffi, key);
        RNPLib.rnp_key_handle_destroy(key);
        key = primaryKey;
      }
    }

    if (!key.isNull() && this.isBadKey(key, null, ffi)) {
      RNPLib.rnp_key_handle_destroy(key);
      key = new RNPLib.rnp_key_handle_t();
    }

    return key;
  },

  getPrimaryKeyHandleByKeyIdOrFingerprint(ffi, id) {
    return this._getKeyHandleByKeyIdOrFingerprint(ffi, id, true);
  },

  getKeyHandleByKeyIdOrFingerprint(ffi, id) {
    return this._getKeyHandleByKeyIdOrFingerprint(ffi, id, false);
  },

  async getKeyHandleByIdentifier(ffi, id) {
    let key = null;

    if (id.startsWith("<")) {
      //throw new Error("search by email address not yet implemented: " + id);
      if (!id.endsWith(">")) {
        throw new Error(
          "if search identifier starts with < then it must end with > : " + id
        );
      }
      key = await this.findKeyByEmail(id);
    } else {
      key = this.getKeyHandleByKeyIdOrFingerprint(ffi, id);
    }
    return key;
  },

  /**
   * Test if the key's usage attributes allow the given usage, based on
   * the public key material only, without requiring that the secret key
   * material is available locally.
   *
   * @param {rnp_key_handle_t} key - RNP key handle.
   * @param {string} usage - The usage to test for, e.g. "sign".
   * @returns {boolean} true if the key allows the given usage
   */
  keyAllowsUsage(key, usage) {
    const allowed = new lazy.ctypes.bool();
    if (RNPLib.rnp_key_allows_usage(key, usage, allowed.address())) {
      throw new Error("rnp_key_allows_usage failed");
    }
    return allowed.value;
  },

  /**
   * Test if the key can be used for the given usage. For signing, the
   * secret key material must also be available locally.
   *
   * @param {rnp_key_handle_t} key - RNP key handle.
   * @param {string} usage - The usage to test for, e.g. "sign".
   * @returns {boolean} true if the key can be used for the given usage
   */
  isKeyUsableFor(key, usage) {
    if (!this.keyAllowsUsage(key, usage)) {
      return false;
    }

    if (usage != "sign") {
      return true;
    }

    return (
      RNPLib.getSecretAvailableFromHandle(key) &&
      RNPLib.isSecretKeyMaterialAvailable(key)
    );
  },

  /**
   * Find the key ID of a signing key related to the given key handle,
   * based on the public key usage attributes only. This is used for
   * externally managed secret keys, for which only the public key is
   * available locally. Prefer the most recently created signing subkey.
   * If no suitable subkey exists, return the ID of the primary key (if
   * it allows signing), or null.
   *
   * @param {rnp_key_handle_t} primary - RNP key handle.
   * @returns {?string} key ID of a suitable signing key, or null
   */
  findSuitableSigningKeyID(primary) {
    if (!primary || primary.isNull()) {
      return null;
    }
    const sub_handle = this.getSuitableSubkey(primary, "sign", true);
    if (sub_handle) {
      const signingKeyID = this.getKeyIDFromHandle(sub_handle);
      RNPLib.rnp_key_handle_destroy(sub_handle);
      return signingKeyID;
    }
    if (this.keyAllowsUsage(primary, "sign")) {
      return this.getKeyIDFromHandle(primary);
    }
    return null;
  },

  /**
   * Find the subkey to use for a purpose.
   *
   * Called with no `preferredFpr` this is the automatic rule: the newest
   * usable subkey, which is what GnuPG does when no key is named.
   *
   * @param {rnp_key_handle_t} primary - RNP key handle of the primary key.
   * @param {string} usage - "sign" or "encrypt".
   * @param {boolean} [publicKeyUsageOnly=false] - Test the public usage
   *   attributes only, for externally managed keys.
   * @param {?string} [preferredFpr=null] - Fingerprint of the subkey the user
   *   named, or null to choose automatically. A named subkey that is absent or
   *   unusable yields null, never a substitute: refusing is the caller's
   *   decision, but a silent substitution would sign with a key the identity
   *   does not name, which is the failure this whole mechanism exists to stop.
   * @returns {?rnp_key_handle_t} A handle the caller must destroy, or null.
   */
  getSuitableSubkey(
    primary,
    usage,
    publicKeyUsageOnly = false,
    preferredFpr = null
  ) {
    const sub_count = new lazy.ctypes.size_t();
    if (RNPLib.rnp_key_get_subkey_count(primary, sub_count.address())) {
      throw new Error("rnp_key_get_subkey_count failed");
    }

    // For compatibility with GnuPG, when encrypting to a single subkey,
    // encrypt to the most recently created subkey. (Bug 1665281)
    let newest_created = null;
    let newest_handle = null;

    for (let i = 0; i < sub_count.value; i++) {
      let sub_handle = new RNPLib.rnp_key_handle_t();
      if (RNPLib.rnp_key_get_subkey_at(primary, i, sub_handle.address())) {
        throw new Error("rnp_key_get_subkey_at failed");
      }

      // A subkey named by the user is the only candidate. It still has to
      // pass every check below, so naming one cannot make an unusable subkey
      // usable -- it can only stop another being chosen in its place.
      if (preferredFpr) {
        const fpr = this.getFingerprintFromHandle(sub_handle);
        if (fpr.toUpperCase() != preferredFpr.toUpperCase()) {
          RNPLib.rnp_key_handle_destroy(sub_handle);
          continue;
        }
      }
      let skip =
        this.isBadKey(sub_handle, primary, null) ||
        this.isKeyExpired(sub_handle);
      if (!skip) {
        const key_revoked = new lazy.ctypes.bool();
        if (RNPLib.rnp_key_is_revoked(sub_handle, key_revoked.address())) {
          throw new Error("rnp_key_is_revoked failed");
        }
        if (key_revoked.value) {
          skip = true;
        }
      }
      if (!skip) {
        const usable = publicKeyUsageOnly
          ? this.keyAllowsUsage(sub_handle, usage)
          : this.isKeyUsableFor(sub_handle, usage);
        if (!usable) {
          skip = true;
        }
      }

      if (!skip) {
        const created = this.getKeyCreatedValueFromHandle(sub_handle);
        // A PQC subkey is usually added to an existing key, and may
        // have been created in the same second as another subkey.
        // Prefer the PQC subkey in that case, don't rely on the order
        // in which RNP happens to report the subkeys.
        const better =
          created > newest_created ||
          (created == newest_created &&
            this.getAlgoFromHandle(sub_handle) == PQC_ENCRYPTION_ALGO);
        if (!newest_handle || better) {
          if (newest_handle) {
            RNPLib.rnp_key_handle_destroy(newest_handle);
          }
          newest_handle = sub_handle;
          sub_handle = null;
          newest_created = created;
        }
      }

      if (sub_handle) {
        RNPLib.rnp_key_handle_destroy(sub_handle);
      }
    }

    return newest_handle;
  },

  /**
   * Get a minimal Autocrypt-compatible public key, for the given key
   * that exactly matches the given userId.
   *
   * @param {rnp_key_handle_t} key - RNP key handle.
   * @param {string} userId - The userID to include.
   * @returns {string} The encoded key, or the empty string on failure.
   */
  getSuitableEncryptKeyAsAutocrypt(key, userId) {
    // Prefer usable subkeys, because they are always newer
    // (or same age) as primary key.

    const use_sub = this.getSuitableSubkey(key, "encrypt");
    if (!use_sub && !this.isKeyUsableFor(key, "encrypt")) {
      return "";
    }

    const result = this.getAutocryptKeyB64ByHandle(key, use_sub, userId);

    if (use_sub) {
      RNPLib.rnp_key_handle_destroy(use_sub);
    }
    return result;
  },

  addSuitableEncryptKey(key, op) {
    // Prefer usable subkeys, because they are always newer
    // (or same age) as primary key.

    const use_sub = this.getSuitableSubkey(key, "encrypt");
    if (!use_sub && !this.isKeyUsableFor(key, "encrypt")) {
      throw new Error("no suitable subkey found for encrypt");
    }

    if (
      RNPLib.rnp_op_encrypt_add_recipient(op, use_sub != null ? use_sub : key)
    ) {
      throw new Error("rnp_op_encrypt_add_recipient sender failed");
    }
    if (use_sub) {
      RNPLib.rnp_key_handle_destroy(use_sub);
    }
  },

  addAliasKeys(aliasKeys, op) {
    for (const ak of aliasKeys) {
      const key = this.getKeyHandleByKeyIdOrFingerprint(RNPLib.ffi, "0x" + ak);
      if (!key || key.isNull()) {
        lazy.log.warn(`Couldn't find key used by alias rule ${ak}`);
        return false;
      }
      this.addSuitableEncryptKey(key, op);
      RNPLib.rnp_key_handle_destroy(key);
    }
    return true;
  },

  /**
   * Get a minimal Autocrypt-compatible public key, for the given email
   * address.
   *
   * @param {string} email - Use a userID with this email address.
   * @returns {string} The encoded key, or the empty string on failure.
   */
  async getRecipientAutocryptKeyForEmail(email) {
    email = email.toLowerCase();

    const key = await this.findKeyByEmail("<" + email + ">", true);
    if (!key || key.isNull()) {
      return "";
    }

    const keyInfo = {};
    const ok = this.getKeyInfoFromHandle(
      RNPLib.ffi,
      key,
      keyInfo,
      false,
      false,
      false
    );
    if (!ok) {
      throw new Error("getKeyInfoFromHandle failed");
    }

    let result = "";
    const userId = keyInfo.userIds.find(
      uid =>
        uid.type == "uid" &&
        lazy.EnigmailFuncs.getEmailFromUserID(uid.userId).toLowerCase() == email
    );
    if (userId) {
      result = this.getSuitableEncryptKeyAsAutocrypt(key, userId.userId);
    }
    RNPLib.rnp_key_handle_destroy(key);
    return result;
  },

  /**
   * Add every acceptable recipient key for one address (Item 27a).
   *
   * **The internal arm now behaves as the external one already does.** The
   * GnuPG path adds every fingerprint `getPublicKeysForEmail()` returns; this
   * adds every key `findAllKeysByEmail()` returns, so a recipient with two live
   * keys is encrypted to both rather than to whichever the old ranking preferred.
   * That is what makes a key rotation work without a window in which the old key
   * is gone and the new one is not yet used.
   *
   * **The filter is GnuPG's, plus the user's rejection.** Eligibility follows
   * gpg's own rule as far as an internal-storage key can — not revoked, not
   * expired, not disabled, and carrying the address on a usable user ID — and
   * `findAllKeysByEmail()` excludes an address the user has rejected, because
   * rejection is a statement only this build can make.
   *
   * @param {string} email - The recipient address.
   * @param {rnp_op_encrypt_t} op
   * @returns {Promise<integer>} How many keys were added; 0 means the address has
   *   no usable key and the caller must refuse.
   */
  async addEncryptionKeysForEmail(email, op) {
    const found = await this.findAllKeysByEmail(email, true);
    let added = 0;
    try {
      for (const { handle } of found) {
        this.addSuitableEncryptKey(handle, op);
        added++;
      }
    } finally {
      for (const { handle } of found) {
        RNPLib.rnp_key_handle_destroy(handle);
      }
    }
    return added;
  },

  async addEncryptionKeyForEmail(email, op) {
    return (await this.addEncryptionKeysForEmail(email, op)) > 0;
  },

  getEmailWithoutBrackets(email) {
    if (email.startsWith("<") && email.endsWith(">")) {
      return email.substring(1, email.length - 1);
    }
    return email;
  },

  /**
   * Test if the given array appears to contain an OpenPGP ASCII Armored
   * data block. This is done by checking the initial bytes of the array
   * contain the -----BEGIN string. This check should be sufficient to
   * distinguish it from a data block that contains a binary encoding
   * of OpenPGP data packets.
   *
   * @param {TypedArray} typedArray - It's assumed this parameter
   *   was created by obtaining a memory buffer from js-ctypes, casting
   *   it to ctypes.uint8_t.array, and calling readTypedArray().
   * @returns {boolean} - Returns true if the block looks ASCII armored
   */
  isASCIIArmored(typedArray) {
    const armorBegin = "-----BEGIN";
    return lazy.MailStringUtils.uint8ArrayToByteString(
      typedArray.slice(0, armorBegin.length)
    ).startsWith(armorBegin);
  },

  /**
   * Resolve the encryption recipients for the external GnuPG path.
   *
   * Each entry carries the fingerprint and, so that GPGME can import it when
   * GnuPG does not hold the key, the ASCII armored public key. Alias rules
   * take precedence over a lookup by address, as they do on the RNP path.
   *
   * @param {object} args - The encryption parameters.
   * @returns {?object[]} { fpr, keyBlock } per recipient, or null when a
   *   recipient has no usable key.
   */
  /**
   * Record what GnuPG actually used, for display only.
   *
   * Delegation costs the caller its certainty: when gpg picks the key, the
   * caller can no longer assume which one ran, and a user cannot verify a
   * choice they cannot see. These fields are the answer to "what handled
   * this", written where the composer and the message header can read them.
   *
   * Recorded after the engine call rather than before, because the result
   * object is reset at the start of every signing and encryption attempt --
   * a value written before it would be wiped by the call it describes.
   *
   * @param {object} resultStatus - Out parameter of encryptAndOrSign.
   * @param {object} used - { signingKey, recipients }, either may be absent.
   */
  /**
   * An error message that carries gpg's own reason.
   *
   * Item 28 bound gpgme_strerror so the reason exists at all; an error that
   * says only "GPGME.signDetached failed" throws that away again. Kept as a
   * helper rather than inline so the call sites stay one line and the
   * surrounding function's complexity does not creep up.
   *
   * @param {string} what - Operation name, for the leading part.
   * @param {object} resultStatus - The operation's out parameter.
   * @returns {string} The message.
   */
  async gpgmeFailure(what, resultStatus) {
    // A cancellation is not a failure and must not be worded as one. Design
    // 5.7 asks for "Signing was cancelled" distinct from a failure, and the
    // measurement behind that is GPG_ERR_CANCELED (99) from
    // GPG_ERR_SOURCE_PINENTRY (5), which before Item 36 arrived looking
    // exactly like a failure.
    //
    // The async form of the lookup, because every caller is async and
    // formatValueSync throws "Can't use formatValueSync when state is async"
    // -- the failure the first version of this produced, which is worth
    // recording: it turned a cancellation into a localisation error.
    if (resultStatus?.cancelled) {
      return l10n.formatValue("key-error-signing-cancelled");
    }
    const reason = resultStatus?.errorMsg;
    return reason ? `${what} failed: ${reason}` : `${what} failed`;
  },

  recordEngineReadBack(resultStatus, used) {
    if (!resultStatus || typeof resultStatus != "object") {
      return;
    }

    if (used.signingKey) {
      resultStatus.externalSigningKeyFpr = used.signingKey.fpr;
      resultStatus.externalSigningKeySource = used.signingKey.source;
    }

    if (used.recipients) {
      resultStatus.externalRecipientFprs = used.recipients.map(r => r.fpr);
    }
  },

  async getGnuPgEncryptionRecipients(args) {
    const recipients = [];
    const seen = new Set();

    const addFingerprint = (fpr, keyBlock = "") => {
      const normalized = fpr.toUpperCase();
      if (seen.has(normalized)) {
        return;
      }
      seen.add(normalized);
      recipients.push({ fpr: normalized, keyBlock });
    };

    const addKeyId = id => {
      const fromGnuPG = lazy.GPGME.getPublicKeysForId(id.replace(/^0x/i, ""));
      if (fromGnuPG.size) {
        for (const [gpgFpr, block] of fromGnuPG) {
          addFingerprint(gpgFpr, block);
        }
        return true;
      }
      const key = this.getKeyHandleByKeyIdOrFingerprint(RNPLib.ffi, id);
      if (!key || key.isNull()) {
        return false;
      }
      const fpr = this.getFingerprintFromHandle(key);
      RNPLib.rnp_key_handle_destroy(key);
      if (!fpr) {
        return false;
      }
      addFingerprint(fpr, this.exportPublicKeyBlock(fpr));
      return true;
    };

    for (const rcpList of [args.to, args.bcc]) {
      for (let rcpEmail of rcpList) {
        rcpEmail = rcpEmail.toLowerCase();
        const aliasKeys = args.aliasKeys.get(
          this.getEmailWithoutBrackets(rcpEmail)
        );
        if (aliasKeys) {
          for (const ak of aliasKeys) {
            if (!addKeyId("0x" + ak)) {
              lazy.log.warn(`Couldn't find key used by alias rule ${ak}`);
              return null;
            }
          }
          continue;
        }

        // Look in GnuPG first: on this path the recipient's key normally
        // lives there, and only a key that exists solely in the profile ring
        // needs the RNP store and an export.
        const fromGnuPG = lazy.GPGME.getPublicKeysForEmail(
          this.getEmailWithoutBrackets(rcpEmail)
        );
        if (fromGnuPG.size) {
          for (const [gpgFpr, block] of fromGnuPG) {
            addFingerprint(gpgFpr, block);
          }
          continue;
        }

        const key = await this.findKeyByEmail(rcpEmail, true);
        if (!key || key.isNull()) {
          lazy.log.warn(`No key found for recipient ${rcpEmail}`);
          return null;
        }
        const fpr = this.getFingerprintFromHandle(key);
        RNPLib.rnp_key_handle_destroy(key);
        if (!fpr) {
          return null;
        }
        addFingerprint(fpr, this.exportPublicKeyBlock(fpr));
      }
    }

    if (args.encryptToSender && args.sender) {
      let added = false;

      // The identity names its key by id, not by address: `getSenderUserId()`
      // returns "0x" + keyId so that error messages name the configured key.
      // An id has to be resolved through the same lookup the recipients use,
      // which asks GnuPG first -- on this path the key normally lives there,
      // and the RNP store is empty by design.
      //
      // This used to go straight to `getKeyHandleByIdentifier()`, which for an
      // id is the RNP store only. With no key in the profile ring the lookup
      // returned nothing, the sender was silently left out of the recipient
      // list, and the copy saved to Sent was encrypted to the correspondents
      // alone -- readable by them and by nobody else. A draft has no other
      // recipient, so there the same omission produced no recipients at all
      // and the save failed outright.
      if (/^0x[0-9a-f]+$/i.test(args.sender)) {
        added = addKeyId(args.sender);
      } else {
        const senderEmail = this.getEmailWithoutBrackets(
          args.sender.toLowerCase()
        );
        if (senderEmail.includes("@")) {
          const fromGnuPG = lazy.GPGME.getPublicKeysForEmail(senderEmail);
          for (const [gpgFpr, block] of fromGnuPG) {
            addFingerprint(gpgFpr, block);
            added = true;
          }
        }
        if (!added) {
          const senderKey = await this.getKeyHandleByIdentifier(
            RNPLib.ffi,
            args.sender
          );
          if (senderKey && !senderKey.isNull()) {
            const fpr = this.getFingerprintFromHandle(senderKey);
            RNPLib.rnp_key_handle_destroy(senderKey);
            if (fpr) {
              addFingerprint(fpr, this.exportPublicKeyBlock(fpr));
              added = true;
            }
          }
        }
      }

      if (!added) {
        // Never silent. A message the sender cannot read back is not the
        // message they asked to send, so the caller turns this into a refusal
        // rather than encrypting to everybody except its author.
        args.senderKeyUnavailable = true;
        lazy.log.warn(
          `Cannot encrypt to the sender's own key ${args.sender}: no usable ` +
            `key was found in GnuPG or in the profile.`
        );
      }
    }

    return recipients;
  },

  /**
   * ASCII armored public key block for a fingerprint, taken from the
   * profile's keyring, for import into GnuPG.
   *
   * @param {string} fpr - Fingerprint of the key.
   * @returns {string} The key block, or "" when it cannot be exported.
   */
  exportPublicKeyBlock(fpr) {
    try {
      return this.getMultiplePublicKeys([fpr], null, null);
    } catch (ex) {
      lazy.log.warn(`Exporting public key ${fpr} for GnuPG failed`, ex);
      return "";
    }
  },

  /**
   * Encrypt, and optionally sign, entirely through GnuPG. Used when the
   * sender's key is the external GnuPG key, so that no part of the operation
   * runs through RNP.
   *
   * @param {string} plaintext - The data to encrypt.
   * @param {object} args - The encryption parameters.
   * @param {object} resultStatus - Out parameter receiving exitCode and
   *   statusFlags.
   * @returns {?string} The encrypted data, or null on failure.
   */
  async encryptWithGnuPG(plaintext, args, resultStatus) {
    if (!lazy.GPGME.allDependenciesLoaded()) {
      // Design 5.7's first condition, in the user's words rather than a
      // developer's. External identities fail and do not fall back to the
      // internal engine: falling back would sign with a different key than the
      // identity names, which is the class of silent substitution this whole
      // design exists to stop.
      resultStatus.exitCode = -1;
      resultStatus.errorMsg = l10n.formatValueSync(
        "key-error-gnupg-unavailable"
      );
      return null;
    }
    if (args.sigTypeClear) {
      throw new Error(
        "unexpected signing request with external GnuPG key configuration"
      );
    }

    const recipients = await this.getGnuPgEncryptionRecipients(args);
    if (!recipients) {
      resultStatus.statusFlags |= lazy.EnigmailConstants.INVALID_RECIPIENT;
      // A numeric exit code, so the caller reports a failure instead of
      // "FAILED: undefined".
      resultStatus.exitCode = -1;
      resultStatus.errorMsg = "Could not find a usable key for every recipient";
      return null;
    }

    if (args.senderKeyUnavailable) {
      // Encrypting to everyone except the author produces a message the author
      // cannot read back, and the Sent copy is the only record of what was
      // sent. Refused, with the reason, rather than sent and discovered later.
      // The draft path reaches this too -- there the author is the only
      // recipient, so a silent omission left the save with no recipients at
      // all and it failed with a message that named nothing.
      resultStatus.statusFlags |= lazy.EnigmailConstants.INVALID_RECIPIENT;
      resultStatus.exitCode = -1;
      // `formatValue`, not `formatValueSync`: this function is async, and the
      // synchronous form throws "Can't use formatValueSync when state is async"
      // rather than returning a message. The same mistake was made once before
      // in this file, recorded against Item 36's row.
      resultStatus.errorMsg = await l10n.formatValue(
        "cannot-encrypt-to-own-key",
        {
          key: args.sender,
        }
      );
      return null;
    }

    let signingKey = null;
    if (args.sign) {
      // The sender's key may exist only in GnuPG, in which case RNP holds no
      // handle for it. Ask GnuPG which of its keys should sign, and keep the
      // answer so it can be reported back.
      signingKey = await lazy.GPGME.resolveSigningKeyForIdentity(
        args.sender.replace(/^0x/, "")
      );
      if (!signingKey) {
        throw new Error(
          "no suitable signing key found for external GnuPG key " + args.sender
        );
      }
      args.externalSenderSigningKeyID = signingKey.keyId;
    }

    const result = await lazy.GPGME.encrypt(
      plaintext,
      args,
      resultStatus,
      recipients,
      signingKey?.keyId ?? null
    );
    this.recordEngineReadBack(resultStatus, { signingKey, recipients });

    // Item 28: a refusal must name whom it is about. gpg's wording says what
    // went wrong and not which address it was for, which is ambiguous the
    // moment a message has more than one recipient -- so the addresses are
    // added here, where the send knows them.
    if (!result && resultStatus.errorMsg) {
      const addresses = [...(args.to || []), ...(args.bcc || [])]
        .map(r => this.getEmailWithoutBrackets(String(r).toLowerCase()).trim())
        .filter(a => a.includes("@"));
      if (addresses.length) {
        resultStatus.errorMsg = `${resultStatus.errorMsg} (recipients: ${addresses.join(
          ", "
        )})`;
      }
    }
    return result;
  },

  async encryptAndOrSign(plaintext, args, resultStatus) {
    let signedInner;

    if (args.encrypt && args.senderKeyIsExternal) {
      return this.encryptWithGnuPG(plaintext, args, resultStatus);
    }

    if (args.sign && args.senderKeyIsExternal) {
      if (!lazy.GPGME.allDependenciesLoaded()) {
        resultStatus.exitCode = -1;
        resultStatus.errorMsg = l10n.formatValueSync(
          "key-error-gnupg-unavailable"
        );
        return null;
      }
      if (args.sigTypeClear) {
        throw new Error(
          "unexpected signing request with external GnuPG key configuration"
        );
      }

      // The sender's key may exist only in GnuPG, where RNP has no handle for
      // it. Ask GnuPG which of its keys should sign, the same way the
      // encrypt path does.
      const signingKey = await lazy.GPGME.resolveSigningKeyForIdentity(
        args.sender.replace(/^0x/, "")
      );
      if (!signingKey) {
        throw new Error(
          "no suitable signing key found for external GnuPG key " + args.sender
        );
      }
      args.externalSenderSigningKeyID = signingKey.keyId;

      if (args.encrypt) {
        // If we are asked to encrypt and sign at the same time, it
        // means we're asked to produce the combined OpenPGP encoding.
        // We ask GPG to produce a regular signature, and will then
        // combine it with the encryption produced by RNP.
        const orgEncrypt = args.encrypt;
        args.encrypt = false;
        signedInner = await lazy.GPGME.sign(plaintext, args, resultStatus);
        if (!signedInner) {
          throw new Error(await this.gpgmeFailure("GPGME.sign", resultStatus));
        }
        this.recordEngineReadBack(resultStatus, { signingKey });
        // Despite our request to produce binary data, GPGME.sign might
        // have produce ASCII armored encoding, e.g. if the user has
        // a configuration file that enables it.
        if (this.isASCIIArmored(signedInner)) {
          signedInner = this.deArmorTypedArray(signedInner);
        }
        args.encrypt = orgEncrypt;
      } else {
        // We aren't asked to encrypt, but sign only. That means the
        // caller needs the detached signature, either for MIME
        // mime encoding with separate signature part, or for the nested
        // approach with separate signing and encryption layers.
        const signResult = await lazy.GPGME.signDetached(
          plaintext,
          args,
          resultStatus
        );
        // After the call, because signDetached resets resultStatus.
        this.recordEngineReadBack(resultStatus, { signingKey });
        if (!signResult) {
          throw new Error(
            await this.gpgmeFailure("GPGME.signDetached", resultStatus)
          );
        }
        return signResult;
      }
    }

    resultStatus.exitCode = -1;
    resultStatus.statusFlags = 0;
    resultStatus.statusMsg = "";
    resultStatus.errorMsg = "";

    let data_array;
    if (args.sign && args.senderKeyIsExternal) {
      data_array = lazy.ctypes.uint8_t.array()(signedInner);
    } else {
      const arr = plaintext.split("").map(e => e.charCodeAt());
      data_array = lazy.ctypes.uint8_t.array()(arr);
    }

    const input = new RNPLib.rnp_input_t();
    if (
      RNPLib.rnp_input_from_memory(
        input.address(),
        data_array,
        data_array.length,
        false
      )
    ) {
      throw new Error("rnp_input_from_memory failed");
    }

    const output = new RNPLib.rnp_output_t();
    if (RNPLib.rnp_output_to_memory(output.address(), 0)) {
      throw new Error("rnp_output_to_memory failed");
    }

    let op;
    if (args.encrypt) {
      op = new RNPLib.rnp_op_encrypt_t();
      if (
        RNPLib.rnp_op_encrypt_create(op.address(), RNPLib.ffi, input, output)
      ) {
        throw new Error("rnp_op_encrypt_create failed");
      }
      if (RNPLib.usingExperimental) {
        // If a recipient has both an ECC and a PQC encryption subkey,
        // encrypt to the PQC one.
        if (RNPLib.rnp_op_encrypt_prefer_pqc_enc_subkey(op)) {
          throw new Error("rnp_op_encrypt_prefer_pqc_enc_subkey failed");
        }
      }
    } else if (args.sign && !args.senderKeyIsExternal) {
      op = new RNPLib.rnp_op_sign_t();
      if (args.sigTypeClear) {
        if (
          RNPLib.rnp_op_sign_cleartext_create(
            op.address(),
            RNPLib.ffi,
            input,
            output
          )
        ) {
          throw new Error("rnp_op_sign_cleartext_create failed");
        }
      } else if (args.sigTypeDetached) {
        if (
          RNPLib.rnp_op_sign_detached_create(
            op.address(),
            RNPLib.ffi,
            input,
            output
          )
        ) {
          throw new Error("rnp_op_sign_detached_create failed");
        }
      } else {
        throw new Error(
          "not yet implemented scenario: signing, neither clear nor encrypt, without encryption"
        );
      }
    } else {
      throw new Error("invalid parameters, neither encrypt nor sign");
    }

    let senderKeyTracker = null;
    let subKeyTracker = null;

    try {
      if ((args.sign && !args.senderKeyIsExternal) || args.encryptToSender) {
        {
          // Use a temporary scope to ensure the senderKey variable
          // cannot be accessed later on.
          const senderKey = await this.getKeyHandleByIdentifier(
            RNPLib.ffi,
            args.sender
          );
          if (!senderKey || senderKey.isNull()) {
            return null;
          }

          senderKeyTracker = new RnpPrivateKeyUnlockTracker(senderKey);
          senderKeyTracker.setAllowPromptingUserForPassword(true);
          senderKeyTracker.setAllowAutoUnlockWithCachedPasswords(true);
        }

        // Manually configured external key overrides the check for
        // a valid personal key.
        if (!args.senderKeyIsExternal) {
          if (!senderKeyTracker.isSecret()) {
            throw new Error(
              `configured sender key ${args.sender} isn't available`
            );
          }
          if (
            !(await lazy.PgpSqliteDb2.isAcceptedAsPersonalKey(
              senderKeyTracker.getFingerprint()
            ))
          ) {
            throw new Error(
              `configured sender key ${args.sender} isn't accepted as a personal key`
            );
          }
        }

        if (args.encryptToSender) {
          this.addSuitableEncryptKey(senderKeyTracker.getHandle(), op);
        }

        if (args.sign && !args.senderKeyIsExternal) {
          let signingKeyTrackerReference = senderKeyTracker;

          // Prefer usable subkeys, because they are always newer
          // (or same age) as primary key -- unless the user has named one.
          const namedSubkeyFpr = args.signingSubkeyFpr || null;
          const usableSubKeyHandle = this.getSuitableSubkey(
            senderKeyTracker.getHandle(),
            "sign",
            false,
            namedSubkeyFpr
          );

          // A named subkey that cannot be used is refused, not replaced.
          // Falling back would sign with a key the identity does not name,
          // and the user would have no way to tell -- which is the class of
          // silent substitution the external path already refuses to do.
          if (!usableSubKeyHandle && namedSubkeyFpr) {
            throw new Error(
              `the signing subkey configured for this identity ` +
                `(${namedSubkeyFpr}) is missing, expired, revoked or not ` +
                `a signing subkey; refusing rather than signing with a ` +
                `different key`
            );
          }

          if (
            !usableSubKeyHandle &&
            !this.isKeyUsableFor(senderKeyTracker.getHandle(), "sign")
          ) {
            throw new Error("no suitable (sub)key found for sign");
          }
          if (usableSubKeyHandle) {
            subKeyTracker = new RnpPrivateKeyUnlockTracker(usableSubKeyHandle);
            subKeyTracker.setAllowPromptingUserForPassword(true);
            subKeyTracker.setAllowAutoUnlockWithCachedPasswords(true);
            if (subKeyTracker.available()) {
              signingKeyTrackerReference = subKeyTracker;
            }
          }

          await signingKeyTrackerReference.unlock();
          if (!signingKeyTrackerReference.isUnlocked()) {
            throw new Error("failed to unlock the signing key");
          }

          // Report what actually signed, the way `gpg --list-packets` does.
          // Without this a rotated subkey is indistinguishable from the one
          // it replaced, so the rotation is invisible to the user who asked
          // for it. This is the subkey when one was used and the primary's
          // fingerprint when the primary signed, which is itself the answer
          // to "why is my new subkey not being used?".
          if (resultStatus && typeof resultStatus == "object") {
            resultStatus.senderSigningKeyFpr =
              signingKeyTrackerReference.getFingerprint();
            resultStatus.senderSigningSubkeyNamed = namedSubkeyFpr || "";
          }

          if (args.encrypt) {
            if (
              RNPLib.rnp_op_encrypt_add_signature(
                op,
                signingKeyTrackerReference.getHandle(),
                null
              )
            ) {
              throw new Error("rnp_op_encrypt_add_signature failed");
            }
          } else if (
            RNPLib.rnp_op_sign_add_signature(
              op,
              signingKeyTrackerReference.getHandle(),
              null
            )
          ) {
            throw new Error("rnp_op_sign_add_signature failed");
          }
          // This was just a reference, no ownership.
          signingKeyTrackerReference = null;
        }
      }

      if (args.encrypt) {
        // If we have an alias definition, it will be used, and the usual
        // lookup by email address will be skipped. Earlier code should
        // have already checked that alias keys are available and usable
        // for encryption, so we fail if a problem is found.

        for (const rcpList of [args.to, args.bcc]) {
          for (let rcpEmail of rcpList) {
            rcpEmail = rcpEmail.toLowerCase();
            const aliasKeys = args.aliasKeys.get(
              this.getEmailWithoutBrackets(rcpEmail)
            );
            if (aliasKeys) {
              if (!this.addAliasKeys(aliasKeys, op)) {
                resultStatus.statusFlags |=
                  lazy.EnigmailConstants.INVALID_RECIPIENT;
                return null;
              }
            } else if (!(await this.addEncryptionKeysForEmail(rcpEmail, op))) {
              // Zero keys means no usable key for this address; the count is
              // what the plural form answers, and zero is the refusal.
              resultStatus.statusFlags |=
                lazy.EnigmailConstants.INVALID_RECIPIENT;
              return null;
            }
          }
        }

        if (AppConstants.MOZ_UPDATE_CHANNEL != "release") {
          const debugKey = Services.prefs.getStringPref(
            "mail.openpgp.debug.extra_encryption_key"
          );
          if (debugKey) {
            const handle = this.getKeyHandleByKeyIdOrFingerprint(
              RNPLib.ffi,
              debugKey
            );
            if (!handle.isNull()) {
              this.addSuitableEncryptKey(handle, op);
              RNPLib.rnp_key_handle_destroy(handle);
            }
          }
        }

        // Don't use AEAD as long as RNP uses v5 packets which aren't
        // widely compatible with other clients.
        if (RNPLib.rnp_op_encrypt_set_aead(op, "NONE")) {
          throw new Error("rnp_op_encrypt_set_aead failed");
        }

        if (RNPLib.rnp_op_encrypt_set_cipher(op, "AES256")) {
          throw new Error("rnp_op_encrypt_set_cipher failed");
        }

        // TODO, map args.signatureHash string to RNP and call
        //       rnp_op_encrypt_set_hash
        if (RNPLib.rnp_op_encrypt_set_hash(op, "SHA256")) {
          throw new Error("rnp_op_encrypt_set_hash failed");
        }

        if (RNPLib.rnp_op_encrypt_set_armor(op, args.armor)) {
          throw new Error("rnp_op_encrypt_set_armor failed");
        }

        if (args.sign && args.senderKeyIsExternal) {
          if (RNPLib.rnp_op_encrypt_set_flags(op, RNPLib.RNP_ENCRYPT_NOWRAP)) {
            throw new Error("rnp_op_encrypt_set_flags failed");
          }
        }

        const rv = RNPLib.rnp_op_encrypt_execute(op);
        if (rv) {
          throw new Error("rnp_op_encrypt_execute failed: " + rv);
        }
        RNPLib.rnp_op_encrypt_destroy(op);
      } else if (args.sign && !args.senderKeyIsExternal) {
        if (RNPLib.rnp_op_sign_set_hash(op, "SHA256")) {
          throw new Error("rnp_op_sign_set_hash failed");
        }
        // TODO, map args.signatureHash string to RNP and call
        //       rnp_op_encrypt_set_hash

        if (RNPLib.rnp_op_sign_set_armor(op, args.armor)) {
          throw new Error("rnp_op_sign_set_armor failed");
        }

        if (RNPLib.rnp_op_sign_execute(op)) {
          throw new Error("rnp_op_sign_execute failed");
        }
        RNPLib.rnp_op_sign_destroy(op);
      }
    } finally {
      if (subKeyTracker) {
        subKeyTracker.release();
      }
      if (senderKeyTracker) {
        senderKeyTracker.release();
      }
    }

    RNPLib.rnp_input_destroy(input);

    let result = null;

    const result_buf = new lazy.ctypes.uint8_t.ptr();
    const result_len = new lazy.ctypes.size_t();
    if (
      !RNPLib.rnp_output_memory_get_buf(
        output,
        result_buf.address(),
        result_len.address(),
        false
      )
    ) {
      const char_array = lazy.ctypes.cast(
        result_buf,
        lazy.ctypes.char.array(result_len.value).ptr
      ).contents;

      result = char_array.readString();
    }

    RNPLib.rnp_output_destroy(output);

    resultStatus.exitCode = 0;

    if (args.encrypt) {
      resultStatus.statusFlags |= lazy.EnigmailConstants.END_ENCRYPTION;
    }

    if (args.sign) {
      resultStatus.statusFlags |= lazy.EnigmailConstants.SIG_CREATED;
    }

    return result;
  },

  /**
   * Export an identity's key as a Transferable Secret Key (RFC 9580 10.2).
   *
   * A public-key packet sequence with the Secret-Key and Secret-Subkey packets
   * added, armoured, carrying the Autocrypt preference in an armour header,
   * and cut at the armour's first end delimiter -- "trailing data after the
   * first ASCII-armor ending delimiter MUST be stripped" is the specification's
   * own clause, and it is the kind that is skipped until another
   * implementation rejects the message.
   *
   * **This does not touch the stored key's protection, and the difference from
   * the import path is deliberate.** The import path calls `unprotect()` and
   * `setAutoPassphrase()` on each secret subkey before re-exporting, which is
   * correct there: it is mid-import, the key is being replaced, and a
   * passphrase the user typed once should not have to be typed again. Reusing
   * that sequence here would leave the user's own key unprotected in their
   * profile -- a security regression wearing the clothes of a convenience.
   *
   * So the export is a plain `rnp_key_export` with the secret flag and no
   * unlock. What comes out carries whatever protection the key already had, and
   * the key in the profile is untouched because nothing about it was written.
   * The test asserts this the only way that means anything: by trying to unlock
   * the key afterwards with no passphrase and requiring that it fails.
   *
   * @param {string} fpr - Primary key fingerprint of the identity's own key.
   * @param {"mutual"|"nopreference"} preferEncrypt - The account's Autocrypt
   *   preference. The two legal values, per the specification; anything else is
   *   refused rather than passed through, because a receiver that does not
   *   recognise a value treats it as absent and the sender would never know.
   * @returns {?string} The armoured TSK, or null when the key is not present
   *   or has no secret material.
   */
  exportSecretKeyForTransfer(fpr, preferEncrypt) {
    if (preferEncrypt != "mutual" && preferEncrypt != "nopreference") {
      throw new Error(
        `Autocrypt-Prefer-Encrypt must be "mutual" or "nopreference", not ` +
          `${JSON.stringify(preferEncrypt)}`
      );
    }

    const handle = this.getKeyHandleByKeyIdOrFingerprint(
      RNPLib.ffi,
      "0x" + String(fpr).replace(/^0x/i, "")
    );
    if (!handle || handle.isNull()) {
      return null;
    }

    const output = new RNPLib.rnp_output_t();
    let armoured = null;
    try {
      // Asked of the library rather than of a key object: whether there is
      // secret material is librnp's fact, and a caller may hand this a
      // fingerprint whose key object has not been read into the ring.
      const haveSecret = new lazy.ctypes.bool();
      if (RNPLib.rnp_key_have_secret(handle, haveSecret.address())) {
        throw new Error("rnp_key_have_secret failed");
      }
      if (!haveSecret.value) {
        return null;
      }

      if (RNPLib.rnp_output_to_memory(output.address(), 0)) {
        throw new Error("rnp_output_to_memory failed");
      }
      // No unlock, no auto passphrase: see the comment above.
      if (
        RNPLib.rnp_key_export(
          handle,
          output,
          RNPLib.RNP_KEY_EXPORT_ARMORED |
            RNPLib.RNP_KEY_EXPORT_SUBKEYS |
            RNPLib.RNP_KEY_EXPORT_SECRET
        )
      ) {
        throw new Error("rnp_key_export failed");
      }

      const result_buf = new lazy.ctypes.uint8_t.ptr();
      const result_len = new lazy.ctypes.size_t();
      if (
        RNPLib.rnp_output_memory_get_buf(
          output,
          result_buf.address(),
          result_len.address(),
          false
        )
      ) {
        throw new Error("rnp_output_memory_get_buf failed");
      }
      armoured = lazy.ctypes
        .cast(result_buf, lazy.ctypes.char.array(result_len.value).ptr)
        .contents.readString();
    } finally {
      RNPLib.rnp_output_destroy(output);
      RNPLib.rnp_key_handle_destroy(handle);
    }

    return armoured
      ? this._prepareTransferKeyBlock(armoured, preferEncrypt)
      : null;
  },

  /**
   * Put an exported key block into the shape a setup message needs.
   *
   * Two steps, both from the specification rather than from taste: the
   * Autocrypt preference goes in an armour header immediately after the BEGIN
   * line -- where Enigmail put it, and Enigmail is the deployed implementation
   * the specification describes -- and everything from the first end delimiter
   * onwards is discarded.
   *
   * Split out so it can be tested without a key, because the stripping is the
   * clause most likely to be got wrong and least likely to be noticed.
   *
   * @param {string} armoured
   * @param {string} preferEncrypt
   * @returns {string}
   */
  _prepareTransferKeyBlock(armoured, preferEncrypt) {
    const normalised = armoured.replace(/\r\n/g, "\n");

    const endMarker = normalised.indexOf("-----END PGP ");
    let body = endMarker >= 0 ? normalised.slice(0, endMarker) : normalised;
    if (endMarker >= 0) {
      // The end line has no trailing newline after the slice; put one back so
      // the block still ends as a block.
      body += normalised.slice(endMarker).split("\n")[0] + "\n";
    }

    const lines = body.split("\n");
    const begin = lines[0];
    if (!begin?.startsWith("-----BEGIN PGP ")) {
      return body;
    }

    // Armour headers live between the BEGIN line and the blank line that
    // separates them from the body, and RFC 4880 requires that blank line.
    //
    // Dropping it is the mistake this function made first time round: the
    // output then read `BEGIN`, header, base64 with no separation, and gpg
    // rejected the first base64 line as `invalid armor header`. The message
    // still looked like a key block to a human, which is exactly the kind of
    // defect an assertion on shape alone does not catch -- hence the test
    // checks the blank line and gpg parses the result.
    const firstBlank = lines.findIndex((l, i) => i > 0 && l === "");
    const existingHeaders = firstBlank < 0 ? [] : lines.slice(1, firstBlank);
    const bodyLines =
      firstBlank < 0 ? lines.slice(1) : lines.slice(firstBlank + 1);

    const header = `Autocrypt-Prefer-Encrypt: ${preferEncrypt}`;
    return [begin, header, ...existingHeaders, "", ...bodyLines].join("\n");
  },

  /**
   * Decrypt a message that is encrypted to a passphrase (Item 99).
   *
   * The other half of Item 95's `encryptWithPassword()`, and the thing Item 95a
   * measured as possible but not yet wired: librnp hands a symmetric request to
   * the installed pass provider with a **NULL key handle**, and every existing
   * callback here dereferences that handle and gives up. This installs a
   * provider that answers the keyless request and refuses every other one.
   *
   * **Refusing the other one is the security-relevant half.** The setup code is
   * 119 bits the user wrote on paper; a provider that answered *any* request
   * with it would offer that code as a passphrase for whatever secret key the
   * message happened to be encrypted to, turning a backup file into a way to
   * get a key's passphrase tried for it. So a request carrying a key handle
   * returns false and the ordinary path is untouched.
   *
   * The provider is installed only for this call and replaced immediately
   * afterwards, so nothing else in the application can observe it.
   *
   * @param {string} armoured - The ASCII-armored message.
   * @param {string} passphrase - The setup code.
   * @param {object} [options] - As `decryptArray()`.
   * @returns {Promise<object>} `{exitCode, decryptedData}`, as `decrypt()`
   *   returns.
   */
  async decryptWithPassword(armoured, passphrase, options = {}) {
    if (!passphrase) {
      throw new Error("a passphrase is required for symmetric decryption");
    }

    const defaultOptions = {
      fromAddr: "",
      maxOutputLength: armoured.length * 100,
      noOutput: false,
      uiFlags: 0,
      verifyOnly: false,
      msgDate: null,
      ...options,
    };

    const arr = armoured.split("").map(c => c.charCodeAt());
    const data = lazy.ctypes.uint8_t.array()(arr);

    const input = new RNPLib.rnp_input_t();
    if (RNPLib.rnp_input_from_memory(input.address(), data, arr.length, true)) {
      throw new Error("rnp_input_from_memory failed");
    }

    const output = new RNPLib.rnp_output_t();
    if (RNPLib.rnp_output_to_memory(output.address(), 0)) {
      RNPLib.rnp_input_destroy(input);
      throw new Error("rnp_output_to_memory failed");
    }

    const op = new RNPLib.rnp_op_verify_t();
    if (RNPLib.rnp_op_verify_create(op.address(), RNPLib.ffi, input, output)) {
      RNPLib.rnp_input_destroy(input);
      RNPLib.rnp_output_destroy(output);
      throw new Error("rnp_op_verify_create failed");
    }

    const passphraseBytes = lazy.ctypes.char.array()(passphrase);
    const callback = RNPLib.rnp_password_cb_t(
      (ffi, appCtx, key, context, buf, bufLen) => {
        // A key handle means "unlock this secret key", which is not what a
        // setup code is for. See the comment above.
        if (!key.isNull()) {
          return false;
        }
        if (bufLen < passphraseBytes.length) {
          return false;
        }
        const dest = lazy.ctypes.cast(
          buf,
          lazy.ctypes.char.array(bufLen).ptr
        ).contents;
        for (let i = 0; i < passphraseBytes.length; i++) {
          dest[i] = passphraseBytes[i];
        }
        dest[passphraseBytes.length] = 0;
        return true;
      },
      null,
      false
    );

    let exitCode;
    let decryptedData = "";
    try {
      RNPLib.rnp_ffi_set_pass_provider(RNPLib.ffi, callback, null);
      exitCode = RNPLib.rnp_op_verify_execute(op);

      // Read the buffer **before** the handles are destroyed. The output object
      // owns the memory; reading it afterwards returns an empty string and an
      // exit code of 0 -- a success that looks like a wrong code, which is how
      // the first version of this failed.
      const resultBuf = new lazy.ctypes.uint8_t.ptr();
      const resultLen = new lazy.ctypes.size_t();
      if (
        !RNPLib.rnp_output_memory_get_buf(
          output,
          resultBuf.address(),
          resultLen.address(),
          false
        )
      ) {
        decryptedData = lazy.ctypes
          .cast(resultBuf, lazy.ctypes.char.array(resultLen.value).ptr)
          .contents.readString();
      }
    } finally {
      // Back to the ordinary callbacks whatever happened, so a failure here
      // cannot leave the application answering every prompt with this code.
      RNPLib.setDefaultPasswordCB();
      RNPLib.rnp_op_verify_destroy(op);
      RNPLib.rnp_input_destroy(input);
      RNPLib.rnp_output_destroy(output);
    }

    return { exitCode, decryptedData, ...defaultOptions };
  },

  /**
   * Encrypt data to a passphrase, producing an SKESK packet (Item 95).
   *
   * RFC 9580 5.3's symmetric-key encrypted session key, and the one operation
   * that makes a password-carrying message possible at all. Its consumer is
   * the Autocrypt setup message (D19), but the operation is general: given a
   * passphrase and some bytes, produce a message only that passphrase opens.
   *
   * **The S2K parameters are passed explicitly, not defaulted.** RFC 9580
   * requires AES-128 or AES-256 for the session key and a salted, iterated
   * S2K for turning the passphrase into a key. rnp would accept `NULL` for
   * both and choose for itself; the choice would then be a value nobody in
   * this project made, and if it were AES-192 the message would be one this
   * build produced and another implementation refused. So the cipher is
   * named, the hash is named, and the iteration count is stated as a count
   * rather than as "whatever rnp thinks".
   *
   * The iteration count is the same order as the primary-password floor: the
   * threat is identical -- an attacker with the ciphertext guessing offline --
   * so it takes the same reasoning. It is not the same number, because the
   * setup code is 36 digits of entropy a user has to read out and retype,
   * which is a different budget from a passphrase they chose.
   *
   * @param {string} plaintext - Bytes to encrypt, as a byte string.
   * @param {string} passphrase - The symmetric passphrase.
   * @param {object} [options]
   * @param {"AES128"|"AES256"} [options.cipher="AES256"] - RFC 9580 permits
   *   these two; anything else is refused rather than passed to rnp, because
   *   the library would accept more than the specification allows.
   * @param {string} [options.s2kHash="SHA256"] - Hash for the S2K.
   * @param {integer} [options.iterations=S2K_ITERATIONS] - Stated explicitly.
   * @returns {string} The encrypted message, ASCII armored.
   */
  encryptWithPassword(plaintext, passphrase, options = {}) {
    const cipher = options.cipher ?? "AES256";
    const s2kHash = options.s2kHash ?? "SHA256";
    const iterations = options.iterations ?? this.S2K_ITERATIONS;

    // RFC 9580 5.3 requires one of these two; refusing here rather than
    // relying on rnp keeps the conformance rule in one place and testable
    // without producing a message.
    if (cipher != "AES128" && cipher != "AES256") {
      throw new Error(
        `RFC 9580 permits AES-128 or AES-256 for a symmetric session key, ` +
          `not ${cipher}`
      );
    }
    if (!passphrase) {
      throw new Error("a passphrase is required for symmetric encryption");
    }

    const arr = plaintext.split("").map(e => e.charCodeAt());
    const data_array = lazy.ctypes.uint8_t.array()(arr);
    const input = new RNPLib.rnp_input_t();
    if (
      RNPLib.rnp_input_from_memory(
        input.address(),
        data_array,
        data_array.length,
        false
      )
    ) {
      throw new Error("rnp_input_from_memory failed");
    }

    const output = new RNPLib.rnp_output_t();
    if (RNPLib.rnp_output_to_memory(output.address(), 0)) {
      RNPLib.rnp_input_destroy(input);
      throw new Error("rnp_output_to_memory failed");
    }

    const op = new RNPLib.rnp_op_encrypt_t();
    let result = null;
    try {
      if (
        RNPLib.rnp_op_encrypt_create(op.address(), RNPLib.ffi, input, output)
      ) {
        throw new Error("rnp_op_encrypt_create failed");
      }
      // The S2K cipher argument is the cipher used to wrap the session key,
      // which is what the specification constrains; the same value is set as
      // the message cipher so the two cannot disagree.
      if (
        RNPLib.rnp_op_encrypt_add_password(
          op,
          passphrase,
          s2kHash,
          iterations,
          cipher
        )
      ) {
        throw new Error("rnp_op_encrypt_add_password failed");
      }
      if (RNPLib.rnp_op_encrypt_set_cipher(op, cipher)) {
        throw new Error("rnp_op_encrypt_set_cipher failed");
      }
      if (RNPLib.rnp_op_encrypt_set_armor(op, true)) {
        throw new Error("rnp_op_encrypt_set_armor failed");
      }
      if (RNPLib.rnp_op_encrypt_execute(op)) {
        throw new Error("rnp_op_encrypt_execute failed");
      }

      const result_buf = new lazy.ctypes.uint8_t.ptr();
      const result_len = new lazy.ctypes.size_t();
      if (
        !RNPLib.rnp_output_memory_get_buf(
          output,
          result_buf.address(),
          result_len.address(),
          false
        )
      ) {
        const char_array = lazy.ctypes.cast(
          result_buf,
          lazy.ctypes.char.array(result_len.value).ptr
        ).contents;
        result = char_array.readString();
      }
    } finally {
      RNPLib.rnp_op_encrypt_destroy(op);
      RNPLib.rnp_input_destroy(input);
      RNPLib.rnp_output_destroy(output);
    }

    if (!result) {
      throw new Error("symmetric encryption produced no output");
    }
    return result;
  },

  /**
   * S2K iteration count for password encryption, stated rather than defaulted.
   *
   * Matches the order the primary-password floor uses, for the same threat: an
   * attacker holding the ciphertext guessing offline. Not the same figure --
   * see `encryptWithPassword()`.
   */
  S2K_ITERATIONS: 4194304,

  /**
   * @param {number} expiryTime - Time to check, in seconds from the epoch.
   * @returns {boolean} - true if the given time is after now.
   */
  isExpiredTime(expiryTime) {
    if (!expiryTime) {
      return false;
    }
    const nowSeconds = Math.floor(Date.now() / 1000);
    return nowSeconds > expiryTime;
  },

  isKeyExpired(handle) {
    const expiration = new lazy.ctypes.uint32_t();
    if (RNPLib.rnp_key_get_expiration(handle, expiration.address())) {
      throw new Error("rnp_key_get_expiration failed");
    }
    if (!expiration.value) {
      return false;
    }

    const created = this.getKeyCreatedValueFromHandle(handle);
    const expirationSeconds = created + expiration.value;
    return this.isExpiredTime(expirationSeconds);
  },

  /**
   * Find key by email.
   *
   * @param {string} id - Email, surrounded by angle brackets.
   * @param {boolean} [onlyIfAcceptableAsRecipientKey=false] - Require matching
   *   key to be acceptable as recipient key.
   * @returns {Promise<ctypes.voidptr_t>} key handle of matching key.
   */
  /**
   * Every key in the RNP store that may be used for one address.
   *
   * **The multi-key answer Item 27a needs, and the single-key one expressed in
   * terms of it.** `findKeyByEmail()` below has asked this question since the
   * beginning and taken the first acceptable key, preferring a personal or
   * verified one; that preference is a *ranking of a list*, so the list is what
   * is produced here and the choice is made from it. The equivalence is exact:
   * the old loop stopped at the first personal-or-verified key and kept the
   * first unverified as a fallback, which is what picking from an ordered
   * collection gives.
   *
   * **`strong` is the ordering the old loop used**, kept as a flag rather than
   * re-derived: a personal key, or one the user has verified, wins over a key
   * that is merely acceptable. Nothing else distinguishes the entries.
   *
   * **Rejection is the boundary this function owns.** An address whose
   * acceptance is `rejected` is not a recipient address at all, and a key with
   * no decision is not one either — those are the user's statements, and gpg has
   * no vocabulary for them. Everything else follows GnuPG's own eligibility rule
   * as closely as an internal-storage key can: not revoked, not expired when the
   * caller excludes expired keys, and carrying a usable user ID.
   *
   * Callers own the returned handles and must destroy each with
   * `rnp_key_handle_destroy()`.
   *
   * @param {string} id - A bracketed address, e.g. `"<alice@example.com>"`.
   * @param {boolean} [onlyIfAcceptableAsRecipientKey=false] - Apply the
   *   acceptance rules, rather than returning any key carrying the address.
   * @returns {Promise<Array<{handle: rnp_key_handle_t, strong: boolean}>>} In
   *   iterator order, which is the order the old loop saw them in.
   */
  async findAllKeysByEmail(id, onlyIfAcceptableAsRecipientKey = false) {
    if (!id.startsWith("<") || !id.endsWith(">") || id.includes(" ")) {
      throw new Error(`Invalid argument; id=${id}`);
    }

    const emailWithoutBrackets = id.substring(1, id.length - 1);
    const found = [];

    const iter = new RNPLib.rnp_identifier_iterator_t();
    const grip = new lazy.ctypes.char.ptr();

    if (
      RNPLib.rnp_identifier_iterator_create(RNPLib.ffi, iter.address(), "grip")
    ) {
      throw new Error("rnp_identifier_iterator_create failed");
    }

    try {
      while (!RNPLib.rnp_identifier_iterator_next(iter, grip.address())) {
        if (grip.isNull()) {
          break;
        }

        let keep = false;
        const handle = new RNPLib.rnp_key_handle_t();

        try {
          const is_subkey = new lazy.ctypes.bool();
          const uid_count = new lazy.ctypes.size_t();

          if (
            RNPLib.rnp_locate_key(RNPLib.ffi, "grip", grip, handle.address())
          ) {
            throw new Error("rnp_locate_key failed");
          }
          keep = true;
          if (RNPLib.rnp_key_is_sub(handle, is_subkey.address())) {
            throw new Error("rnp_key_is_sub failed");
          }
          if (is_subkey.value) {
            continue;
          }
          if (this.isBadKey(handle, null, RNPLib.ffi)) {
            continue;
          }

          const keyObj = {};
          if (
            !this.getKeyInfoFromHandle(
              RNPLib.ffi,
              handle,
              keyObj,
              false,
              true,
              false
            )
          ) {
            continue;
          }

          if (
            keyObj.keyTrust == "r" ||
            keyObj.keyTrust == "e" ||
            (onlyIfAcceptableAsRecipientKey &&
              this.isExpiredTime(keyObj.effectiveExpiryTime))
          ) {
            continue;
          }

          if (RNPLib.rnp_key_get_uid_count(handle, uid_count.address())) {
            throw new Error("rnp_key_get_uid_count failed");
          }

          let foundUid = false;
          let strong = false;

          for (let i = 0; i < uid_count.value && !foundUid; i++) {
            const uid_handle = new RNPLib.rnp_uid_handle_t();

            if (
              RNPLib.rnp_key_get_uid_handle_at(handle, i, uid_handle.address())
            ) {
              throw new Error("rnp_key_get_uid_handle_at failed");
            }

            try {
              if (this.isBadUid(uid_handle) || this.isRevokedUid(uid_handle)) {
                continue;
              }

              const uid_str = new lazy.ctypes.char.ptr();
              if (RNPLib.rnp_key_get_uid_at(handle, i, uid_str.address())) {
                throw new Error("rnp_key_get_uid_at failed");
              }

              const userId = uid_str.readStringReplaceMalformed();
              RNPLib.rnp_buffer_destroy(uid_str);

              if (
                lazy.EnigmailFuncs.getEmailFromUserID(userId).toLowerCase() !=
                emailWithoutBrackets
              ) {
                continue;
              }

              if (!onlyIfAcceptableAsRecipientKey) {
                foundUid = true;
                strong = true;
                continue;
              }

              // A key is acceptable as a recipient key either:
              //  - without secret material, when the user has decided on it and
              //    the decision is not "rejected"; or
              //  - with secret material, when it is marked as personal.
              const have_secret = new lazy.ctypes.bool();
              if (RNPLib.rnp_key_have_secret(handle, have_secret.address())) {
                throw new Error("rnp_key_have_secret failed");
              }

              const fingerprint = new lazy.ctypes.char.ptr();
              if (RNPLib.rnp_key_get_fprint(handle, fingerprint.address())) {
                throw new Error("rnp_key_get_fprint failed");
              }
              const fpr = fingerprint.readString();
              RNPLib.rnp_buffer_destroy(fingerprint);

              if (have_secret.value) {
                if (await lazy.PgpSqliteDb2.isAcceptedAsPersonalKey(fpr)) {
                  foundUid = true;
                  strong = true;
                }
                continue;
              }

              const acceptanceResult = {};
              try {
                await lazy.PgpSqliteDb2.getAcceptance(
                  fpr,
                  emailWithoutBrackets,
                  acceptanceResult
                );
              } catch (ex) {
                lazy.log.warn("Get acceptance FAILED!", ex);
              }

              if (!acceptanceResult.emailDecided) {
                continue;
              }
              // `rejected` is the user saying not to use this key, and gpg has
              // no vocabulary for it -- so it is excluded here rather than left
              // to a later filter. `undecided` is not a decision either.
              if (acceptanceResult.fingerprintAcceptance == "unverified") {
                foundUid = true;
                strong = false;
              } else if (acceptanceResult.fingerprintAcceptance == "verified") {
                foundUid = true;
                strong = true;
              }
            } finally {
              RNPLib.rnp_uid_handle_destroy(uid_handle);
            }
          }

          if (foundUid) {
            found.push({ handle, strong });
            keep = false;
          }
        } catch (ex) {
          lazy.log.warn(`Finding keys by email=${id} FAILED`, ex);
        } finally {
          if (keep) {
            RNPLib.rnp_key_handle_destroy(handle);
          }
        }
      }
    } finally {
      RNPLib.rnp_identifier_iterator_destroy(iter);
    }

    return found;
  },

  /**
   * The single key `findKeyByEmail()` has always returned, chosen from the list
   * `findAllKeysByEmail()` produces.
   *
   * **Kept as an equivalence rather than rewritten.** The old loop preferred a
   * personal-or-verified key and fell back to the first unverified one; that is
   * a choice over an ordered list, so it is expressed as one. The handles not
   * chosen are destroyed here, because the caller owns only what it is given.
   *
   * @param {string} id - A bracketed address.
   * @param {boolean} [onlyIfAcceptableAsRecipientKey=false]
   * @returns {Promise<?rnp_key_handle_t>} The chosen handle, or null.
   */
  async findKeyByEmail(id, onlyIfAcceptableAsRecipientKey = false) {
    const found = await this.findAllKeysByEmail(
      id,
      onlyIfAcceptableAsRecipientKey
    );
    if (!found.length) {
      return null;
    }

    // The first strong entry, else the first entry. That is what the old loop
    // produced: it stopped at the first personal-or-verified key, and kept the
    // first unverified one only when no strong key appeared.
    const chosen = found.find(entry => entry.strong) ?? found[0];
    for (const entry of found) {
      if (entry.handle !== chosen.handle) {
        RNPLib.rnp_key_handle_destroy(entry.handle);
      }
    }
    return chosen.handle;
  },

  async getPublicKey(id, store = RNPLib.ffi) {
    let result = "";
    const key = await this.getKeyHandleByIdentifier(store, id);

    if (key.isNull()) {
      return result;
    }

    const flags =
      RNPLib.RNP_KEY_EXPORT_ARMORED |
      RNPLib.RNP_KEY_EXPORT_PUBLIC |
      RNPLib.RNP_KEY_EXPORT_SUBKEYS;

    const output_to_memory = new RNPLib.rnp_output_t();
    RNPLib.rnp_output_to_memory(output_to_memory.address(), 0);

    if (RNPLib.rnp_key_export(key, output_to_memory, flags)) {
      throw new Error("rnp_key_export failed");
    }

    const result_buf = new lazy.ctypes.uint8_t.ptr();
    const result_len = new lazy.ctypes.size_t();
    const exitCode = RNPLib.rnp_output_memory_get_buf(
      output_to_memory,
      result_buf.address(),
      result_len.address(),
      false
    );

    if (!exitCode) {
      const char_array = lazy.ctypes.cast(
        result_buf,
        lazy.ctypes.char.array(result_len.value).ptr
      ).contents;

      result = char_array.readString();
    }

    RNPLib.rnp_output_destroy(output_to_memory);
    RNPLib.rnp_key_handle_destroy(key);
    return result;
  },

  /**
   * Exports a public key, strips all signatures added by others,
   * and optionally also strips user IDs. Self-signatures are kept.
   * The given key handle will not be modified. The input key will be
   * copied to a temporary area, only the temporary copy will be
   * modified. The result key will be streamed to the given output.
   *
   * @param {rnp_key_handle_t} expKey - RNP key handle
   * @param {boolean} keepUserIDs - if true keep users IDs
   * @param {rnp_output_t} out_binary - output stream handle
   */
  export_pubkey_strip_sigs_uids(expKey, keepUserIDs, out_binary) {
    const expKeyId = this.getKeyIDFromHandle(expKey);

    const tempFFI = RNPLib.prepare_ffi();
    if (!tempFFI) {
      throw new Error("Couldn't initialize librnp.");
    }

    try {
      const exportFlags =
        RNPLib.RNP_KEY_EXPORT_SUBKEYS | RNPLib.RNP_KEY_EXPORT_PUBLIC;
      const importFlags = RNPLib.RNP_LOAD_SAVE_PUBLIC_KEYS;

      const output_to_memory = new RNPLib.rnp_output_t();
      if (RNPLib.rnp_output_to_memory(output_to_memory.address(), 0)) {
        throw new Error("rnp_output_to_memory failed");
      }

      if (RNPLib.rnp_key_export(expKey, output_to_memory, exportFlags)) {
        throw new Error("rnp_key_export failed");
      }

      const result_buf = new lazy.ctypes.uint8_t.ptr();
      const result_len = new lazy.ctypes.size_t();
      if (
        RNPLib.rnp_output_memory_get_buf(
          output_to_memory,
          result_buf.address(),
          result_len.address(),
          false
        )
      ) {
        throw new Error("rnp_output_memory_get_buf failed");
      }

      const input_from_memory = new RNPLib.rnp_input_t();

      if (
        RNPLib.rnp_input_from_memory(
          input_from_memory.address(),
          result_buf,
          result_len,
          false
        )
      ) {
        throw new Error("rnp_input_from_memory failed");
      }

      if (
        RNPLib.rnp_import_keys(tempFFI, input_from_memory, importFlags, null)
      ) {
        throw new Error("rnp_import_keys failed");
      }

      const tempKey = this.getKeyHandleByKeyIdOrFingerprint(
        tempFFI,
        "0x" + expKeyId
      );

      // Strip

      if (!keepUserIDs) {
        const uid_count = new lazy.ctypes.size_t();
        if (RNPLib.rnp_key_get_uid_count(tempKey, uid_count.address())) {
          throw new Error("rnp_key_get_uid_count failed");
        }
        for (let i = uid_count.value; i > 0; i--) {
          const uid_handle = new RNPLib.rnp_uid_handle_t();
          if (
            RNPLib.rnp_key_get_uid_handle_at(
              tempKey,
              i - 1,
              uid_handle.address()
            )
          ) {
            throw new Error("rnp_key_get_uid_handle_at failed");
          }
          if (RNPLib.rnp_uid_remove(tempKey, uid_handle)) {
            throw new Error("rnp_uid_remove failed");
          }
          RNPLib.rnp_uid_handle_destroy(uid_handle);
        }
      }

      if (
        RNPLib.rnp_key_remove_signatures(
          tempKey,
          RNPLib.RNP_KEY_SIGNATURE_NON_SELF_SIG,
          null,
          null
        )
      ) {
        throw new Error("rnp_key_remove_signatures failed");
      }

      if (RNPLib.rnp_key_export(tempKey, out_binary, exportFlags)) {
        throw new Error("rnp_key_export failed");
      }
      RNPLib.rnp_key_handle_destroy(tempKey);

      RNPLib.rnp_input_destroy(input_from_memory);
      RNPLib.rnp_output_destroy(output_to_memory);
    } finally {
      RNPLib.rnp_ffi_destroy(tempFFI);
    }
  },

  /**
   * Export one or multiple public keys.
   *
   * @param {string[]} idArrayFull - an array of key IDs or fingerprints
   *   that should be exported as full keys including all attributes.
   * @param {string[]} idArrayReduced - an array of key IDs or
   *   fingerprints that should be exported with all self-signatures,
   *   but without signatures from others.
   * @param {string[]} idArrayMinimal - an array of key IDs or
   *   fingerprints that should be exported as minimized keys.
   * @returns {string} - An ascii armored key block containing all
   *   requested (available) keys.
   */
  getMultiplePublicKeys(idArrayFull, idArrayReduced, idArrayMinimal) {
    const out_final = new RNPLib.rnp_output_t();
    RNPLib.rnp_output_to_memory(out_final.address(), 0);

    const out_binary = new RNPLib.rnp_output_t();
    let rv;
    if (
      (rv = RNPLib.rnp_output_to_armor(
        out_final,
        out_binary.address(),
        "public key"
      ))
    ) {
      throw new Error("rnp_output_to_armor failed:" + rv);
    }

    if ((rv = RNPLib.rnp_output_armor_set_line_length(out_binary, 64))) {
      throw new Error("rnp_output_armor_set_line_length failed:" + rv);
    }

    const flags = RNPLib.RNP_KEY_EXPORT_PUBLIC | RNPLib.RNP_KEY_EXPORT_SUBKEYS;

    if (idArrayFull) {
      for (const id of idArrayFull) {
        const key = this.getKeyHandleByKeyIdOrFingerprint(RNPLib.ffi, id);
        if (key.isNull()) {
          continue;
        }

        if (RNPLib.rnp_key_export(key, out_binary, flags)) {
          throw new Error("rnp_key_export failed");
        }

        RNPLib.rnp_key_handle_destroy(key);
      }
    }

    if (idArrayReduced) {
      for (const id of idArrayReduced) {
        const key = this.getPrimaryKeyHandleByKeyIdOrFingerprint(
          RNPLib.ffi,
          id
        );
        if (key.isNull()) {
          continue;
        }

        this.export_pubkey_strip_sigs_uids(key, true, out_binary);

        RNPLib.rnp_key_handle_destroy(key);
      }
    }

    if (idArrayMinimal) {
      for (const id of idArrayMinimal) {
        const key = this.getPrimaryKeyHandleByKeyIdOrFingerprint(
          RNPLib.ffi,
          id
        );
        if (key.isNull()) {
          continue;
        }

        this.export_pubkey_strip_sigs_uids(key, false, out_binary);

        RNPLib.rnp_key_handle_destroy(key);
      }
    }

    if ((rv = RNPLib.rnp_output_finish(out_binary))) {
      throw new Error("rnp_output_finish failed: " + rv);
    }

    const result_buf = new lazy.ctypes.uint8_t.ptr();
    const result_len = new lazy.ctypes.size_t();
    const exitCode = RNPLib.rnp_output_memory_get_buf(
      out_final,
      result_buf.address(),
      result_len.address(),
      false
    );

    let result = "";
    if (!exitCode) {
      const char_array = lazy.ctypes.cast(
        result_buf,
        lazy.ctypes.char.array(result_len.value).ptr
      ).contents;
      result = char_array.readString();
    }

    RNPLib.rnp_output_destroy(out_binary);
    RNPLib.rnp_output_destroy(out_final);

    return result;
  },

  /**
   * The RNP library may store keys in a format that isn't compatible
   * with GnuPG, see bug 1713621 for an example where this happened.
   *
   * This function modifies the input key to make it compatible.
   *
   * The caller must ensure that the key is unprotected when calling
   * this function, and must apply the desired protection afterwards.
   *
   * @param {rnp_key_handle_t} tempKey - The key handle to modify in place.
   */
  ensureECCSubkeyIsGnuPGCompatible(tempKey) {
    const algo = new lazy.ctypes.char.ptr();
    if (RNPLib.rnp_key_get_alg(tempKey, algo.address())) {
      throw new Error("rnp_key_get_alg failed");
    }
    const algoStr = algo.readString();
    RNPLib.rnp_buffer_destroy(algo);

    if (algoStr.toLowerCase() != "ecdh") {
      return;
    }

    const curve = new lazy.ctypes.char.ptr();
    if (RNPLib.rnp_key_get_curve(tempKey, curve.address())) {
      throw new Error("rnp_key_get_curve failed");
    }
    const curveStr = curve.readString();
    RNPLib.rnp_buffer_destroy(curve);

    if (curveStr.toLowerCase() != "curve25519") {
      return;
    }

    const tweak_status = new lazy.ctypes.bool();
    let rc = RNPLib.rnp_key_25519_bits_tweaked(tempKey, tweak_status.address());
    if (rc) {
      throw new Error("rnp_key_25519_bits_tweaked failed: " + rc);
    }

    // If it's not tweaked yet, then tweak to make it compatible.
    if (!tweak_status.value) {
      rc = RNPLib.rnp_key_25519_bits_tweak(tempKey);
      if (rc) {
        throw new Error("rnp_key_25519_bits_tweak failed: " + rc);
      }
    }
  },

  /**
   * Move a secret key out of this profile and into the external GnuPG keyring.
   *
   * The sequence, and each step is there for a reason:
   *
   * 1. Export the key re-protected with `newPassphrase`, never unprotected.
   *    An unprotected export is the intermediate state the design exists to
   *    avoid, even for a few seconds in memory -- so the caller chooses a real
   *    passphrase and the exported block is never readable without one.
   * 2. Import it into GnuPG.
   * 3. Ask GnuPG whether it now holds the secret for that fingerprint. The
   *    import's exit status is not enough: it reports what it did, not what the
   *    keyring contains afterwards, and step 4 is destructive.
   * 4. Only then offer to delete. This method does not delete: it returns what
   *    it found so the caller can ask the user, which is the item's rule.
   *
   * @param {string} fpr - Fingerprint of the key to move.
   * @param {string} newPassphrase - Passphrase the exported key is protected
   *   with. Must not be empty.
   * @returns {Promise<object>} { ok, stage, detail, fpr } where stage names the
   *   step that stopped, if one did.
   */
  async migrateSecretKeyToGnuPG(fpr, newPassphrase) {
    if (!fpr) {
      return { ok: false, stage: "export", detail: "no fingerprint", fpr };
    }
    if (!newPassphrase) {
      // Item 20 is explicit: an unprotected export is the state this design
      // exists to avoid, so this is a refusal rather than a default.
      return { ok: false, stage: "export", detail: "no passphrase", fpr };
    }
    let keyBlock;
    try {
      keyBlock = await this.backupSecretKeys([fpr], newPassphrase);
    } catch (ex) {
      return { ok: false, stage: "export", detail: String(ex), fpr };
    }
    if (!keyBlock) {
      return {
        ok: false,
        stage: "export",
        detail: "the key could not be unlocked for export",
        fpr,
      };
    }

    const imported = await lazy.GnuPGAgent.importKeyBlock(keyBlock);
    if (!imported.ok) {
      return { ok: false, stage: "import", detail: imported.output, fpr };
    }

    if (!(await lazy.GnuPGAgent.hasSecretKey(fpr))) {
      return {
        ok: false,
        stage: "verify",
        detail: "gpg did not report the key after importing it",
        fpr,
      };
    }

    // Deliberately not deleting. The caller asks the user, and that is the
    // item's central rule: the move is offered, never taken.
    return {
      ok: true,
      stage: "offer-delete",
      detail: "the key is in GnuPG; the internal copy may now be removed",
      fpr,
    };
  },

  async backupSecretKeys(fprs, backupPassword) {
    if (!fprs.length) {
      throw new Error("invalid fprs parameter");
    }

    /*
     * Strategy:
     * - copy keys to a temporary space, in-memory only (ffi)
     * - if we failed to decrypt the secret keys, return null
     * - change the password of all secret keys in the temporary space
     * - export from the temporary space
     */

    const out_final = new RNPLib.rnp_output_t();
    RNPLib.rnp_output_to_memory(out_final.address(), 0);

    const out_binary = new RNPLib.rnp_output_t();
    let rv;
    if (
      (rv = RNPLib.rnp_output_to_armor(
        out_final,
        out_binary.address(),
        "secret key"
      ))
    ) {
      throw new Error("rnp_output_to_armor failed:" + rv);
    }

    const tempFFI = RNPLib.prepare_ffi();
    if (!tempFFI) {
      throw new Error("Couldn't initialize librnp.");
    }

    let unlockFailed = false;
    try {
      const exportFlags =
        RNPLib.RNP_KEY_EXPORT_SUBKEYS | RNPLib.RNP_KEY_EXPORT_SECRET;
      const importFlags =
        RNPLib.RNP_LOAD_SAVE_PUBLIC_KEYS | RNPLib.RNP_LOAD_SAVE_SECRET_KEYS;

      const pwCache = {
        passwords: [],
      };

      for (const fpr of fprs) {
        const fprStr = fpr;
        let expKey = await this.getKeyHandleByIdentifier(
          RNPLib.ffi,
          "0x" + fprStr
        );

        let output_to_memory = new RNPLib.rnp_output_t();
        if (RNPLib.rnp_output_to_memory(output_to_memory.address(), 0)) {
          throw new Error("rnp_output_to_memory failed");
        }

        if (RNPLib.rnp_key_export(expKey, output_to_memory, exportFlags)) {
          throw new Error("rnp_key_export failed");
        }
        RNPLib.rnp_key_handle_destroy(expKey);
        expKey = null;

        let result_buf = new lazy.ctypes.uint8_t.ptr();
        const result_len = new lazy.ctypes.size_t();
        if (
          RNPLib.rnp_output_memory_get_buf(
            output_to_memory,
            result_buf.address(),
            result_len.address(),
            false
          )
        ) {
          throw new Error("rnp_output_memory_get_buf failed");
        }

        let input_from_memory = new RNPLib.rnp_input_t();
        if (
          RNPLib.rnp_input_from_memory(
            input_from_memory.address(),
            result_buf,
            result_len,
            false
          )
        ) {
          throw new Error("rnp_input_from_memory failed");
        }

        if (
          RNPLib.rnp_import_keys(tempFFI, input_from_memory, importFlags, null)
        ) {
          throw new Error("rnp_import_keys failed");
        }

        RNPLib.rnp_input_destroy(input_from_memory);
        RNPLib.rnp_output_destroy(output_to_memory);
        input_from_memory = null;
        output_to_memory = null;
        result_buf = null;

        const tracker = RnpPrivateKeyUnlockTracker.constructFromFingerprint(
          fprStr,
          tempFFI
        );
        if (!tracker.available()) {
          tracker.release();
          continue;
        }

        tracker.setAllowPromptingUserForPassword(true);
        tracker.setAllowAutoUnlockWithCachedPasswords(true);
        tracker.setPasswordCache(pwCache);
        tracker.setRememberUnlockPassword(true);

        await tracker.unlock();
        if (!tracker.isUnlocked()) {
          unlockFailed = true;
          tracker.release();
          break;
        }

        tracker.unprotect();
        tracker.setPassphrase(backupPassword);

        const sub_count = new lazy.ctypes.size_t();
        if (
          RNPLib.rnp_key_get_subkey_count(
            tracker.getHandle(),
            sub_count.address()
          )
        ) {
          throw new Error("rnp_key_get_subkey_count failed");
        }
        for (let i = 0; i < sub_count.value; i++) {
          const sub_handle = new RNPLib.rnp_key_handle_t();
          if (
            RNPLib.rnp_key_get_subkey_at(
              tracker.getHandle(),
              i,
              sub_handle.address()
            )
          ) {
            throw new Error("rnp_key_get_subkey_at failed");
          }

          const subTracker = new RnpPrivateKeyUnlockTracker(sub_handle);
          if (subTracker.available()) {
            subTracker.setAllowPromptingUserForPassword(true);
            subTracker.setAllowAutoUnlockWithCachedPasswords(true);
            subTracker.setPasswordCache(pwCache);
            subTracker.setRememberUnlockPassword(true);

            await subTracker.unlock();
            if (!subTracker.isUnlocked()) {
              unlockFailed = true;
            } else {
              subTracker.unprotect();
              this.ensureECCSubkeyIsGnuPGCompatible(subTracker.getHandle());
              subTracker.setPassphrase(backupPassword);
            }
          }
          subTracker.release();
          if (unlockFailed) {
            break;
          }
        }

        if (
          !unlockFailed &&
          RNPLib.rnp_key_export(tracker.getHandle(), out_binary, exportFlags)
        ) {
          throw new Error("rnp_key_export failed");
        }

        tracker.release();
        if (unlockFailed) {
          break;
        }
      }
    } finally {
      RNPLib.rnp_ffi_destroy(tempFFI);
    }

    let result = "";
    if (!unlockFailed) {
      if ((rv = RNPLib.rnp_output_finish(out_binary))) {
        throw new Error("rnp_output_finish failed: " + rv);
      }

      const result_buf = new lazy.ctypes.uint8_t.ptr();
      const result_len = new lazy.ctypes.size_t();
      const exitCode = RNPLib.rnp_output_memory_get_buf(
        out_final,
        result_buf.address(),
        result_len.address(),
        false
      );

      if (!exitCode) {
        const char_array = lazy.ctypes.cast(
          result_buf,
          lazy.ctypes.char.array(result_len.value).ptr
        ).contents;
        result = char_array.readString();
      }
    }

    RNPLib.rnp_output_destroy(out_binary);
    RNPLib.rnp_output_destroy(out_final);

    return result;
  },

  /**
   * Generate a revocation statement for the secret key with the given
   * ID. The function must also unlock the secret key.
   *
   * @param {string} id - The ID of a primary key.
   * @param {?string} pass - The password that can be used to unlock the
   *   primary key. If parameter is set to null, then this function
   *   will prompt the user to enter the password.
   * @param {bool} addEnglishInformation - Add english language text to
   *   the revocation file, that explains what the file contains.
   * @returns {string} - The ASCII armored revocation statement.
   */
  async unlockAndGetNewRevocation(id, pass, addEnglishInformation = true) {
    const key = await this.getKeyHandleByIdentifier(RNPLib.ffi, id);
    if (key.isNull()) {
      return "";
    }
    const tracker = new RnpPrivateKeyUnlockTracker(key);

    if (pass) {
      tracker.setAllowPromptingUserForPassword(false);
      tracker.setAllowAutoUnlockWithCachedPasswords(false);
      tracker.unlockWithPassword(pass);
    } else {
      tracker.setAllowPromptingUserForPassword(true);
      tracker.setAllowAutoUnlockWithCachedPasswords(true);
      await tracker.unlock();
    }

    if (!tracker.isUnlocked()) {
      tracker.release();
      throw new Error(`Couldn't unlock key ${id}`);
    }

    const out_final = new RNPLib.rnp_output_t();
    RNPLib.rnp_output_to_memory(out_final.address(), 0);

    const out_binary = new RNPLib.rnp_output_t();
    let rv;
    if (
      (rv = RNPLib.rnp_output_to_armor(
        out_final,
        out_binary.address(),
        "public key"
      ))
    ) {
      throw new Error("rnp_output_to_armor failed:" + rv);
    }

    if (
      (rv = RNPLib.rnp_key_export_revocation(
        key,
        out_binary,
        0,
        null,
        null,
        null
      ))
    ) {
      throw new Error("rnp_key_export_revocation failed: " + rv);
    }

    if ((rv = RNPLib.rnp_output_finish(out_binary))) {
      throw new Error("rnp_output_finish failed: " + rv);
    }

    const result_buf = new lazy.ctypes.uint8_t.ptr();
    const result_len = new lazy.ctypes.size_t();
    const exitCode = RNPLib.rnp_output_memory_get_buf(
      out_final,
      result_buf.address(),
      result_len.address(),
      false
    );

    let result = "";
    if (!exitCode) {
      const char_array = lazy.ctypes.cast(
        result_buf,
        lazy.ctypes.char.array(result_len.value).ptr
      ).contents;
      result = char_array.readString();
    }

    RNPLib.rnp_output_destroy(out_binary);
    RNPLib.rnp_output_destroy(out_final);
    tracker.release();

    if (!addEnglishInformation) {
      return result;
    }

    return (
      revocationFilePrefix1 +
      "\n\n" +
      id +
      "\n" +
      revocationFilePrefix2 +
      result
    );
  },

  enArmorString(input, type) {
    const arr = input.split("").map(e => e.charCodeAt());
    const input_array = lazy.ctypes.uint8_t.array()(arr);

    return this.enArmorCData(input_array, input_array.length, type);
  },

  enArmorCDataMessage(buf, len) {
    return this.enArmorCData(buf, len, "message");
  },

  enArmorCData(buf, len, type) {
    const input_array = lazy.ctypes.cast(buf, lazy.ctypes.uint8_t.array(len));

    const input_from_memory = new RNPLib.rnp_input_t();
    RNPLib.rnp_input_from_memory(
      input_from_memory.address(),
      input_array,
      len,
      false
    );

    const max_out = len * 2 + 150; // extra bytes for head/tail/hash lines

    const output_to_memory = new RNPLib.rnp_output_t();
    RNPLib.rnp_output_to_memory(output_to_memory.address(), max_out);

    if (RNPLib.rnp_enarmor(input_from_memory, output_to_memory, type)) {
      throw new Error("rnp_enarmor failed");
    }

    let result = "";
    const result_buf = new lazy.ctypes.uint8_t.ptr();
    const result_len = new lazy.ctypes.size_t();
    if (
      !RNPLib.rnp_output_memory_get_buf(
        output_to_memory,
        result_buf.address(),
        result_len.address(),
        false
      )
    ) {
      const char_array = lazy.ctypes.cast(
        result_buf,
        lazy.ctypes.char.array(result_len.value).ptr
      ).contents;

      result = char_array.readString();
    }

    RNPLib.rnp_input_destroy(input_from_memory);
    RNPLib.rnp_output_destroy(output_to_memory);

    return result;
  },

  /**
   * Removes ASCII armor layer from the input.
   *
   * @param {TypedArray} input_array - An array of bytes containing
   *   an OpenPGP message in ASCII armored data format.
   * @returns {object} - A typed array with the result bytes.
   */
  deArmorTypedArray(input_array) {
    const input_from_memory = new RNPLib.rnp_input_t();
    RNPLib.rnp_input_from_memory(
      input_from_memory.address(),
      input_array,
      input_array.length,
      false
    );
    const max_out = input_array.length * 2 + 150; // extra bytes for head/tail/hash lines

    const output_to_memory = new RNPLib.rnp_output_t();
    RNPLib.rnp_output_to_memory(output_to_memory.address(), max_out);

    if (RNPLib.rnp_dearmor(input_from_memory, output_to_memory)) {
      throw new Error("rnp_dearmor failed");
    }

    let result = null;

    const result_buf = new lazy.ctypes.uint8_t.ptr();
    const result_len = new lazy.ctypes.size_t();
    if (
      !RNPLib.rnp_output_memory_get_buf(
        output_to_memory,
        result_buf.address(),
        result_len.address(),
        false
      )
    ) {
      // type casting the pointer type to an array type allows us to
      // access the elements by index.
      const uint8_array = lazy.ctypes.cast(
        result_buf,
        lazy.ctypes.uint8_t.array(result_len.value).ptr
      ).contents;

      result = uint8_array.readTypedArray();
    }

    RNPLib.rnp_input_destroy(input_from_memory);
    RNPLib.rnp_output_destroy(output_to_memory);

    return result;
  },

  /**
   * Removes ASCII armor layer from the input.
   *
   * @param {string} str - A string of bytes that contains OpenPGP
   *   ASCII armored data.
   * @returns {object} - A typed array with the result bytes.
   */
  deArmorString(str) {
    const array = lazy.MailStringUtils.byteStringToUint8Array(str);
    return this.deArmorTypedArray(array);
  },

  /**
   * Change the key expiration date.
   *
   * @param {KeyObj} primaryKey - Primary key.
   * @param {?KeyObj} subKey - Key to change if not the primary key (simpleMode false)
   * @param {?Date} date - The expiration date. null for "does not expire".
   * @param {boolean} [simpleMode=true] - Set to false to edit expiration of
   *   a parcular subkey only.
   * @returns {boolean} true if the key expiration was changed.
   */
  async changeKeyExpiration(primaryKey, subKey, date, simpleMode = true) {
    const keyToEdit = simpleMode ? primaryKey : subKey;

    // We must always unlock the primary key, that's the one that will
    // be used to sign/allow the change.
    let fingerprintsToUnlock;
    let fingerprintsToEdit;

    if (simpleMode) {
      fingerprintsToUnlock = [primaryKey.fpr, primaryKey.subKeys[0].fpr];
      fingerprintsToEdit = [primaryKey.fpr, primaryKey.subKeys[0].fpr];
    } else {
      // When not editing the primary key, also unlock the subkey to edit.
      fingerprintsToUnlock = [primaryKey.fpr];
      if (keyToEdit.fpr != primaryKey.fpr) {
        fingerprintsToUnlock.push(keyToEdit.fpr);
      }
      fingerprintsToEdit = [keyToEdit.fpr];
    }

    // Key Expiration Time - this is the number of seconds after the key
    // creation time that the key expires.
    const expirationTime = date
      ? Math.ceil(date.getTime() / 1000) - keyToEdit.keyCreated
      : 0;

    const pwCache = {
      passwords: [],
    };
    const keyTrackers = [];
    try {
      for (const fp of fingerprintsToUnlock) {
        const tracker = RnpPrivateKeyUnlockTracker.constructFromFingerprint(fp);
        keyTrackers.push(tracker);
        if (!tracker.available()) {
          // The secret key material isn't available locally, we cannot
          // sign the changed expiration date.
          return false;
        }
        tracker.setAllowPromptingUserForPassword(true);
        tracker.setAllowAutoUnlockWithCachedPasswords(true);
        tracker.setPasswordCache(pwCache);
        await tracker.unlock();
        if (!tracker.isUnlocked()) {
          // Unlock failed.
          return false;
        }
      }
      await RNP._changeExpirationDate(fingerprintsToEdit, expirationTime);
    } finally {
      for (const t of keyTrackers) {
        t.release();
      }
    }
    return true;
  },

  /**
   * Will change the expiration date of all given keys to newExpiry.
   * fingerprintArray is an array, containing fingerprints, both
   * primary key fingerprints and subkey fingerprints are allowed.
   * The function assumes that all involved keys have already been
   * unlocked. We shouldn't rely on password callbacks for unlocking,
   * as it would be confusing if only some keys are changed.
   *
   * @param {string[]} fingerprintArray - Fingerprints.
   * @param {integer} newExpiry - New expiration time in seconds (since key creation).
   */
  async _changeExpirationDate(fingerprintArray, newExpiry) {
    for (const fingerprint of fingerprintArray) {
      const handle = this.getKeyHandleByKeyIdOrFingerprint(
        RNPLib.ffi,
        "0x" + fingerprint
      );

      if (handle.isNull()) {
        continue;
      }

      if (RNPLib.rnp_key_set_expiration(handle, newExpiry)) {
        throw new Error(`rnp_key_set_expiration failed for ${fingerprint}`);
      }
      RNPLib.rnp_key_handle_destroy(handle);
    }

    await this.saveKeyRings();
    return true;
  },

  /**
   * Like canGenerateV4PQCEncryptionSubkey, but for a fingerprint.
   * Returns false, rather than throwing, if the key cannot be found.
   *
   * @param {string} fpr - Fingerprint of a primary key, without "0x".
   * @returns {boolean} - true if a PQC encryption subkey may be added
   */
  canGenerateV4PQCEncryptionSubkeyByFpr(fpr) {
    const handle = this.getKeyHandleByKeyIdOrFingerprint(
      RNPLib.ffi,
      `0x${fpr}`
    );
    if (!handle || handle.isNull()) {
      return false;
    }
    try {
      return this.canGenerateV4PQCEncryptionSubkey(handle);
    } finally {
      RNPLib.rnp_key_handle_destroy(handle);
    }
  },

  /**
   * Test whether a v4 post-quantum encryption subkey may be added to the
   * given primary key. This is the only place that defines the policy,
   * both the UI and addV4PQCEncryptionSubkey() must use it.
   *
   * @param {rnp_key_handle_t} primaryHandle - Handle of a primary key.
   * @returns {boolean} - true if a PQC encryption subkey may be added
   */
  canGenerateV4PQCEncryptionSubkey(primaryHandle) {
    // Generating an ML-KEM subkey requires the experimental library.
    if (!RNPLib.usingExperimental) {
      return false;
    }

    // Everything that applies to adding any subkey at all: secret material
    // present, primary not revoked, primary not expired.
    if (!this.canAddSubkey(primaryHandle)) {
      return false;
    }

    const version = new lazy.ctypes.uint32_t();
    if (RNPLib.rnp_key_get_version(primaryHandle, version.address())) {
      throw new Error("rnp_key_get_version failed");
    }
    if (version.value != 4) {
      lazy.log.warn("primary key is not v4");
      return false;
    }

    // Require a classic ECC signing primary key, reject RSA/DSA/Elgamal.
    const primaryAlgo = this.getAlgoFromHandle(primaryHandle);
    if (!["ECDSA", "EDDSA", "ED25519"].includes(primaryAlgo)) {
      lazy.log.warn(`unsupported primary key algorithm ${primaryAlgo}`);
      return false;
    }

    // While this is a test feature, require an opt-in email address,
    // with a local part ending in either "+pqc-test" or "-pqc-test",
    // e.g. "alice-pqc-test@example.com".
    if (!this._haveTestPqcUserId(primaryHandle)) {
      lazy.log.warn("no pqc-test user ID");
      return false;
    }

    let havePQC = false;
    let haveEccEncryptionSubkey = false;
    const subCount = new lazy.ctypes.size_t();
    if (RNPLib.rnp_key_get_subkey_count(primaryHandle, subCount.address())) {
      throw new Error("rnp_key_get_subkey_count failed");
    }
    for (let i = 0; i < subCount.value; i++) {
      const subHandle = new RNPLib.rnp_key_handle_t();
      if (RNPLib.rnp_key_get_subkey_at(primaryHandle, i, subHandle.address())) {
        throw new Error("rnp_key_get_subkey_at failed");
      }
      const subAlgo = this.getAlgoFromHandle(subHandle);
      RNPLib.rnp_key_handle_destroy(subHandle);

      if (subAlgo == PQC_ENCRYPTION_ALGO) {
        havePQC = true;
      } else if (["ECDH", "X25519"].includes(subAlgo)) {
        haveEccEncryptionSubkey = true;
      }
    }

    if (havePQC) {
      lazy.log.warn("key already has a pqc subkey");
      return false;
    }
    if (!haveEccEncryptionSubkey) {
      lazy.log.warn("no supported ECC encryption subkey");
      return false;
    }

    return true;
  },

  /**
   * @param {rnp_key_handle_t} handle - RNP key handle.
   * @returns {boolean} - true if the key has a user ID whose email
   *   address opts in to the PQC test feature.
   */
  _haveTestPqcUserId(handle) {
    const count = new lazy.ctypes.size_t();
    if (RNPLib.rnp_key_get_uid_count(handle, count.address())) {
      throw new Error("rnp_key_get_uid_count failed");
    }

    for (let i = 0; i < count.value; i++) {
      const uid = new lazy.ctypes.char.ptr();
      if (RNPLib.rnp_key_get_uid_at(handle, i, uid.address())) {
        throw new Error("rnp_key_get_uid_at failed");
      }
      const uidStr = uid.readString();
      RNPLib.rnp_buffer_destroy(uid);

      let email;
      try {
        email = lazy.EnigmailFuncs.getEmailFromUserID(uidStr);
      } catch (e) {
        continue;
      }
      if (!email) {
        continue;
      }
      const at = email.lastIndexOf("@");
      if (at > 0 && /[+-]pqc-test$/i.test(email.slice(0, at))) {
        return true;
      }
    }
    return false;
  },

  /**
   * Test whether any subkey may be added to the given primary key, ignoring
   * which kind of subkey is wanted. This is the policy shared by every
   * add-subkey path; both the UI and the RNP methods must use it.
   *
   * @param {rnp_key_handle_t} primaryHandle - Handle of a primary key.
   * @returns {boolean} - true if a subkey may be added
   */
  canAddSubkey(primaryHandle) {
    // A handle for a key that is not in the ring is not null, it is invalid,
    // and asking it for secret material throws rather than answering. Checked
    // here because every caller reaches this with a handle it did not
    // necessarily obtain from a successful lookup.
    if (!primaryHandle || primaryHandle.isNull()) {
      return false;
    }

    // The secret key material of the primary key is required, because
    // the new subkey must be bound to the primary key by a signature.
    if (
      !RNPLib.getSecretAvailableFromHandle(primaryHandle) ||
      !RNPLib.isSecretKeyMaterialAvailable(primaryHandle)
    ) {
      lazy.log.warn("secret key material not available");
      return false;
    }

    const isRevoked = new lazy.ctypes.bool();
    if (RNPLib.rnp_key_is_revoked(primaryHandle, isRevoked.address())) {
      throw new Error("rnp_key_is_revoked failed");
    }
    if (isRevoked.value) {
      lazy.log.warn("primary key is revoked");
      return false;
    }

    // An expired primary key would produce an unusable subkey, and we
    // couldn't derive an expiration date for the new subkey either.
    const expiration = new lazy.ctypes.uint32_t();
    if (RNPLib.rnp_key_get_expiration(primaryHandle, expiration.address())) {
      throw new Error("rnp_key_get_expiration failed");
    }
    if (expiration.value) {
      const created = this.getKeyCreatedValueFromHandle(primaryHandle);
      if (created + expiration.value <= Math.floor(Date.now() / 1000)) {
        lazy.log.warn("primary key is expired");
        return false;
      }
    }

    return true;
  },

  /**
   * Like canAddSubkey, but for a fingerprint.
   * Returns false, rather than throwing, if the key cannot be found.
   *
   * @param {string} fpr - Fingerprint of a primary key, without "0x".
   * @returns {boolean} - true if a subkey may be added
   */
  canAddSubkeyByFpr(fpr) {
    const handle = this.getKeyHandleByKeyIdOrFingerprint(
      RNPLib.ffi,
      `0x${fpr}`
    );
    if (!handle || handle.isNull()) {
      return false;
    }
    try {
      return this.canAddSubkey(handle);
    } finally {
      RNPLib.rnp_key_handle_destroy(handle);
    }
  },

  /**
   * Choose the algorithm for a new subkey from the primary key's own, so a
   * replaced subkey is the same kind as the one it replaces. The curve for a
   * signing key is left unset, because the library's default for eddsa is
   * Ed25519 and naming it fails.
   *
   * @param {rnp_key_handle_t} primaryHandle - Handle of a primary key.
   * @param {string} usage - "sign" or "encrypt".
   * @returns {?object} - { algo, bits, curve }, or null if unsupported.
   */
  _subkeySpecForPrimary(primaryHandle, usage) {
    const primaryAlgo = this.getAlgoFromHandle(primaryHandle);

    switch (primaryAlgo) {
      case "RSA": {
        // Same size as the primary: a smaller subkey would weaken the key as
        // a whole, and a larger one buys nothing the primary does not have.
        const bits = new lazy.ctypes.uint32_t();
        if (RNPLib.rnp_key_get_bits(primaryHandle, bits.address())) {
          throw new Error("rnp_key_get_bits failed");
        }
        return { algo: "rsa", bits: bits.value, curve: null };
      }

      case "EDDSA":
      case "ED25519":
        return usage == "sign"
          ? { algo: "eddsa", bits: 0, curve: null }
          : { algo: "ecdh", bits: 0, curve: "Curve25519" };

      case "ECDSA": {
        // Keep the curve the primary already uses, so the key stays one
        // coherent algorithm family rather than a mixture.
        const curve = new lazy.ctypes.char.ptr();
        if (RNPLib.rnp_key_get_curve(primaryHandle, curve.address())) {
          throw new Error("rnp_key_get_curve failed");
        }
        const curveStr = curve.readString();
        RNPLib.rnp_buffer_destroy(curve);
        return {
          algo: usage == "sign" ? "ecdsa" : "ecdh",
          bits: 0,
          curve: curveStr,
        };
      }

      default:
        lazy.log.warn(`cannot add a subkey to a ${primaryAlgo} primary key`);
        return null;
    }
  },

  /**
   * Generate a subkey and bind it to the primary key. The caller has already
   * decided that this is allowed; this method does the work and saves it.
   *
   * The primary key is unlocked on demand, which may prompt the user for a
   * passphrase. The new subkey is protected with the same passphrase.
   *
   * @param {string} primaryFpr - Fingerprint of the primary key.
   * @param {object} spec - What to generate.
   * @param {string} spec.usage - "sign" or "encrypt".
   * @param {string} spec.algo - The RNP algorithm name.
   * @param {integer} spec.bits - Bits, or 0 to leave the default.
   * @param {?string} spec.curve - Curve, or null to leave the default.
   * @param {integer} spec.expirySeconds - Seconds until expiry, 0 for never.
   * @returns {Promise<boolean>} - true if a subkey was added.
   */
  async _generateSubkey(
    primaryFpr,
    { usage, algo, bits, curve, expirySeconds }
  ) {
    const tracker =
      RnpPrivateKeyUnlockTracker.constructFromFingerprint(primaryFpr);
    try {
      if (!tracker.available()) {
        return false;
      }

      tracker.setAllowPromptingUserForPassword(true);
      tracker.setAllowAutoUnlockWithCachedPasswords(true);
      tracker.setPasswordCache({ passwords: [] });
      tracker.setRememberUnlockPassword(true);
      // We must learn the passphrase, to protect the new subkey with it.
      tracker.setAllowRelockToCapturePassword(true);
      await tracker.unlock();
      if (!tracker.isUnlocked()) {
        return false;
      }

      const passphrase = tracker.getUnlockPassword();
      if (passphrase === null) {
        throw new Error(
          `cannot determine the passphrase protecting key ${primaryFpr}`
        );
      }

      const genOp = new RNPLib.rnp_op_generate_t();
      if (
        RNPLib.rnp_op_generate_subkey_create(
          genOp.address(),
          RNPLib.ffi,
          tracker.getHandle(),
          algo
        )
      ) {
        throw new Error("rnp_op_generate_subkey_create failed");
      }
      try {
        // Clear before adding. add_usage extends the algorithm's defaults
        // rather than replacing them, so an RSA signing subkey would
        // otherwise be able to encrypt as well, and nothing downstream could
        // tell which subkey was meant to do what.
        if (RNPLib.rnp_op_generate_clear_usage(genOp)) {
          throw new Error("rnp_op_generate_clear_usage failed");
        }
        if (RNPLib.rnp_op_generate_add_usage(genOp, usage)) {
          throw new Error("rnp_op_generate_add_usage failed");
        }
        if (bits && RNPLib.rnp_op_generate_set_bits(genOp, bits)) {
          throw new Error("rnp_op_generate_set_bits failed");
        }
        if (curve && RNPLib.rnp_op_generate_set_curve(genOp, curve)) {
          throw new Error("rnp_op_generate_set_curve failed");
        }
        if (RNPLib.rnp_op_generate_set_protection_password(genOp, passphrase)) {
          throw new Error("rnp_op_generate_set_protection_password failed");
        }
        if (RNPLib.rnp_op_generate_set_expiration(genOp, expirySeconds)) {
          throw new Error("rnp_op_generate_set_expiration failed");
        }
        if (RNPLib.rnp_op_generate_execute(genOp)) {
          throw new Error("rnp_op_generate_execute failed");
        }
      } finally {
        RNPLib.rnp_op_generate_destroy(genOp);
      }
    } finally {
      tracker.release();
    }

    await this.saveKeyRings();
    return true;
  },

  /**
   * Add a signing or encryption subkey to an existing primary key, so that a
   * subkey can be replaced while the certificate and the trust placed in it
   * survive. This is what makes rotation possible at all: without it, the
   * structure Item 60 produces is created once and never renewed.
   *
   * The new subkey is added alongside the existing ones, not in place of one.
   * Rotation is the pair of operations -- add the new subkey, let the old one
   * expire -- and staggering the two expirations is what keeps a key usable
   * throughout, so the expiry is the caller's to choose (see Item 62 for
   * making the choice visible).
   *
   * @param {string} primaryFpr - Fingerprint of the primary key.
   * @param {object} options
   * @param {string} options.usage - "sign" or "encrypt".
   * @param {integer} options.expirySeconds - Seconds until the new subkey
   *   expires, or 0 if it should never expire.
   * @returns {Promise<boolean>} - true if a subkey was added, false if the
   *   preconditions weren't met.
   */
  async addSubkey(primaryFpr, { usage, expirySeconds }) {
    if (usage != "sign" && usage != "encrypt") {
      throw new Error(`invalid subkey usage ${usage}`);
    }
    if (!Number.isInteger(expirySeconds) || expirySeconds < 0) {
      throw new Error(`invalid expirySeconds ${expirySeconds}`);
    }

    const handle = this.getKeyHandleByKeyIdOrFingerprint(
      RNPLib.ffi,
      `0x${primaryFpr}`
    );
    if (!handle || handle.isNull()) {
      return false;
    }

    let spec;
    try {
      if (!this.canAddSubkey(handle)) {
        return false;
      }
      spec = this._subkeySpecForPrimary(handle, usage);
    } finally {
      RNPLib.rnp_key_handle_destroy(handle);
    }

    if (!spec) {
      return false;
    }

    return this._generateSubkey(primaryFpr, {
      usage,
      ...spec,
      expirySeconds,
    });
  },

  /**
   * Add a user ID to a primary key, signing the binding.
   *
   * Item 69. Until this existed a second address could not be added to a key
   * from inside Thunderbird at all: the only way was to generate a new key or
   * to use GnuPG.
   *
   * `rnp_key_add_uid` signs the binding itself, which is the point rather than
   * a convenience. A user ID with no self-certification is a string attached
   * to a key; no other client accepts it, and the key's own validity does not
   * extend to it. The wrapper therefore does not offer an unsigned variant.
   *
   * @param {string} primaryFpr - Fingerprint of the primary key.
   * @param {string} userId - The user ID, conventionally "Name <address>".
   * @param {object} [options]
   * @param {integer} [options.expirySeconds=0] - Seconds until the user ID
   *   expires, measured from the key's creation. 0 for never.
   * @param {boolean} [options.makePrimary=false] - Ask for this user ID to
   *   become the primary one.
   * @returns {Promise<boolean>} true if the user ID was added.
   */
  async addUserId(primaryFpr, userId, options = {}) {
    const expirySeconds = options.expirySeconds ?? 0;
    if (!Number.isInteger(expirySeconds) || expirySeconds < 0) {
      throw new Error(`invalid expirySeconds ${expirySeconds}`);
    }
    const trimmed = String(userId ?? "").trim();
    // RNP would accept almost any string; the check is here because a user ID
    // that is not "Name <address>" is accepted by the library and then matches
    // no address at all, which is worse than refusing it.
    if (!/^[^<>]+<[^<>@\s]+@[^<>@\s]+>$/.test(trimmed)) {
      throw new Error(`invalid user ID: ${trimmed}`);
    }

    // Checked before the tracker is built, because constructing one for a
    // fingerprint that is not in the ring throws from `available()` rather
    // than reporting absence.
    if (!this._keyIsInTheRing(primaryFpr)) {
      return false;
    }
    if (!this.canAddSubkeyByFpr(primaryFpr)) {
      return false;
    }

    const tracker =
      RnpPrivateKeyUnlockTracker.constructFromFingerprint(primaryFpr);
    try {
      if (!tracker.available()) {
        return false;
      }
      if (!this.canAddSubkey(tracker.getHandle())) {
        // Same precondition as adding a subkey: the primary must hold its
        // secret material and be neither revoked nor expired, because the
        // binding has to be signed by it.
        return false;
      }

      tracker.setAllowPromptingUserForPassword(true);
      tracker.setAllowAutoUnlockWithCachedPasswords(true);
      tracker.setPasswordCache({ passwords: [] });
      await tracker.unlock();
      if (!tracker.isUnlocked()) {
        return false;
      }

      // key_flags is 0: RFC 4880 s5.2.3.21 treats that as "no statement", so
      // adding a user ID leaves the key's usages exactly as they were.
      if (
        RNPLib.rnp_key_add_uid(
          tracker.getHandle(),
          trimmed,
          "SHA256",
          expirySeconds,
          0,
          !!options.makePrimary
        )
      ) {
        throw new Error("rnp_key_add_uid failed");
      }
    } finally {
      tracker.release();
    }

    await this.saveKeyRings();
    return true;
  },

  /**
   * Make one of a key's user IDs the primary one.
   *
   * The change is a self-certification: RNP gives an editable certification,
   * this sets the flag on it, and signing applies it. Nothing on disk changes
   * until the sign, which is why the three steps are one method rather than
   * three the caller could forget to finish.
   *
   * @param {string} primaryFpr - Fingerprint of the primary key.
   * @param {string} userId - The user ID to make primary.
   * @returns {Promise<boolean>} true if it was changed.
   */
  async setPrimaryUserId(primaryFpr, userId) {
    return this._editSelfCertification(
      primaryFpr,
      userId,
      "rnp_key_signature_set_primary_uid",
      sig => RNPLib.rnp_key_signature_set_primary_uid(sig, true)
    );
  },

  /**
   * Change which usages a key allows.
   *
   * RNP does not check that the flags suit the key's algorithm -- an
   * encryption-only key can be marked for signing, and the result is a key
   * that fails when used rather than when changed. The caller is responsible
   * for offering only what makes sense, which is why the UI presents the
   * key's current usages rather than a free choice.
   *
   * @param {string} primaryFpr - Fingerprint of the primary key.
   * @param {string} userId - The user ID whose certification carries the flags.
   * @param {integer} flags - RFC 4880 key-usage bit field.
   * @returns {Promise<boolean>} true if it was changed.
   */
  async setKeyFlags(primaryFpr, userId, flags) {
    if (!Number.isInteger(flags) || flags <= 0 || flags > 0x0f) {
      throw new Error(`invalid key flags ${flags}`);
    }
    return this._editSelfCertification(
      primaryFpr,
      userId,
      "rnp_key_signature_set_key_flags",
      sig => RNPLib.rnp_key_signature_set_key_flags(sig, flags)
    );
  },

  /**
   * Runs one of the `rnp_key_signature_set_*` edits over a user ID's
   * certification, signs it, and saves.
   *
   * Shared by the two callers so the create-sign-save sequence exists once. A
   * setter that was applied but never signed would look successful and leave
   * the key unchanged, which is the failure mode this shape prevents.
   *
   * @param {string} primaryFpr - Fingerprint of the primary key.
   * @param {string} userId - The user ID whose certification to edit.
   * @param {string} what - Name of the edit, for the error message.
   * @param {Function} apply - Receives the signature handle and returns the
   *   RNP result code for the edit.
   * @returns {Promise<boolean>} true if the edit was applied and saved.
   */
  async _editSelfCertification(primaryFpr, userId, what, apply) {
    // Checked before the tracker is built, because constructing one for a
    // fingerprint that is not in the ring throws from `available()` rather
    // than reporting absence.
    if (!this._keyIsInTheRing(primaryFpr)) {
      return false;
    }
    if (!this.canAddSubkeyByFpr(primaryFpr)) {
      return false;
    }

    const tracker =
      RnpPrivateKeyUnlockTracker.constructFromFingerprint(primaryFpr);
    try {
      if (!tracker.available()) {
        return false;
      }
      if (!this.canAddSubkey(tracker.getHandle())) {
        return false;
      }

      tracker.setAllowPromptingUserForPassword(true);
      tracker.setAllowAutoUnlockWithCachedPasswords(true);
      tracker.setPasswordCache({ passwords: [] });
      await tracker.unlock();
      if (!tracker.isUnlocked()) {
        return false;
      }

      const uidHandle = this._findUidHandle(tracker.getHandle(), userId);
      if (!uidHandle) {
        return false;
      }

      const sig = new RNPLib.rnp_signature_handle_t();
      try {
        // The third argument is the certification *type*, not a hash, and it
        // has to be a null pointer -- not an empty string -- for the library
        // to choose. RNP tests `!type` first, and a JS "" becomes a pointer to
        // a NUL byte rather than NULL, so the lookup that follows rejects it.
        // Both mistakes were made here before this comment existed.
        if (
          RNPLib.rnp_key_certification_create(
            tracker.getHandle(),
            uidHandle,
            null,
            sig.address()
          )
        ) {
          throw new Error("rnp_key_certification_create failed");
        }
        if (apply(sig)) {
          throw new Error(`${what} failed`);
        }
        if (RNPLib.rnp_key_signature_sign(sig)) {
          throw new Error("rnp_key_signature_sign failed");
        }
      } finally {
        RNPLib.rnp_signature_handle_destroy(sig);
        RNPLib.rnp_uid_handle_destroy(uidHandle);
      }
    } finally {
      tracker.release();
    }

    await this.saveKeyRings();
    return true;
  },

  /**
   * Certify another party's key with one of the user's own (D18(b), Item 92).
   *
   * The operation Enigmail called "sign key", and the one that makes strict
   * mode useful rather than merely quiet: it produces a certification that
   * gpg's computed validity counts, and that survives being exported to
   * another machine. Item 88's owner trust does neither -- it asserts
   * locally and grants authority to validate others.
   *
   * **The signer and the target are different keys.** `_editSelfCertification`
   * certifies a user ID of the key that holds it, which is right for making a
   * user ID primary on your own key; this takes the signer separately, and the
   * library supports that directly -- `rnp_key_certification_create(signer,
   * uid, ...)` where the uid belongs to the target.
   *
   * The certification type is left to the library, which picks GENERIC for a
   * key that is not your own. Naming POSITIVE would claim a stronger statement
   * than "I have checked this is the right key", and RNP's own documentation
   * says GENERIC is what certifying another key uses.
   *
   * @param {string} signerFpr - The user's key, which must have its secret.
   * @param {string} targetFpr - The key being certified.
   * @param {string} userId - Which user ID of the target to certify.
   * @returns {Promise<boolean>} true if the certification was made and saved.
   */
  async certifyKey(signerFpr, targetFpr, userId) {
    if (!signerFpr || !targetFpr) {
      return false;
    }
    // A key cannot meaningfully certify itself through this path; the self
    // case is `_editSelfCertification`, and routing it here would create a
    // second, subtly different way to do the same thing.
    if (signerFpr.toUpperCase() == targetFpr.toUpperCase()) {
      return false;
    }
    if (!this._keyIsInTheRing(signerFpr)) {
      return false;
    }

    const tracker =
      RnpPrivateKeyUnlockTracker.constructFromFingerprint(signerFpr);
    let targetKey = null;
    try {
      if (!tracker.available()) {
        return false;
      }
      tracker.setAllowPromptingUserForPassword(true);
      tracker.setAllowAutoUnlockWithCachedPasswords(true);
      tracker.setPasswordCache({ passwords: [] });
      await tracker.unlock();
      if (!tracker.isUnlocked()) {
        return false;
      }

      // A handle on the key being certified, from the ring rather than from
      // the tracker: the tracker's handle is the signer. The public entry
      // point is the one that takes a `0x`-prefixed identifier and returns a
      // primary-key handle.
      targetKey = this.getKeyHandleByKeyIdOrFingerprint(
        RNPLib.ffi,
        "0x" + targetFpr.replace(/^0x/i, "")
      );
      if (!targetKey) {
        return false;
      }

      const uidHandle = this._findUidHandle(targetKey, userId);
      if (!uidHandle) {
        return false;
      }

      const sig = new RNPLib.rnp_signature_handle_t();
      try {
        // Null, not "": see the comment in `_editSelfCertification` -- an
        // empty JS string becomes a pointer to a NUL byte, which RNP does not
        // read as "choose for me".
        if (
          RNPLib.rnp_key_certification_create(
            tracker.getHandle(),
            uidHandle,
            null,
            sig.address()
          )
        ) {
          throw new Error("rnp_key_certification_create failed");
        }
        if (RNPLib.rnp_key_signature_sign(sig)) {
          throw new Error("rnp_key_signature_sign failed");
        }
      } finally {
        RNPLib.rnp_signature_handle_destroy(sig);
        RNPLib.rnp_uid_handle_destroy(uidHandle);
      }
    } finally {
      if (targetKey) {
        RNPLib.rnp_key_handle_destroy(targetKey);
      }
      tracker.release();
    }

    await this.saveKeyRings();
    return true;
  },

  /**
   * How many signatures one of a key's user IDs carries.
   *
   * A certification adds exactly one, so this is how a caller observes that
   * one was made -- and, after re-reading an exported block, that it is
   * exportable rather than merely in memory. The engine has no API for "is
   * this key valid", because validity is a client-side computation over the
   * signatures; the signature count is the fact underneath it.
   *
   * @param {string} fpr - Primary key fingerprint.
   * @param {string} userId - Which user ID, matched as `_findUidHandle` does.
   * @returns {?integer} The count, or null when the key or user ID is absent.
   */
  getUidSignatureCount(fpr, userId) {
    if (!fpr || !this._keyIsInTheRing(fpr)) {
      return null;
    }
    const handle = this.getKeyHandleByKeyIdOrFingerprint(
      RNPLib.ffi,
      "0x" + fpr.replace(/^0x/i, "")
    );
    if (!handle || handle.isNull()) {
      return null;
    }
    let uidHandle = null;
    try {
      uidHandle = this._findUidHandle(handle, userId);
      if (!uidHandle) {
        return null;
      }
      const count = new lazy.ctypes.size_t();
      if (RNPLib.rnp_uid_get_signature_count(uidHandle, count.address())) {
        throw new Error("rnp_uid_get_signature_count failed");
      }
      // `size_t` reads back as a ctypes object rather than a primitive;
      // returning it un-converted makes every caller's arithmetic silently
      // stringify, which is how a count of 2 can compare unequal to 2.
      return Number(count.value);
    } finally {
      if (uidHandle) {
        RNPLib.rnp_uid_handle_destroy(uidHandle);
      }
      RNPLib.rnp_key_handle_destroy(handle);
    }
  },

  /**
   * Finds a user ID's handle by its text.
   *
   * Compared on the address rather than the whole string: "Name <a@b>" and
   * "a@b" are the same user ID to every reader that matters, and a caller
   * working from an address should not have to reproduce the name.
   *
   * @param {rnp_key_handle_t} keyHandle
   * @param {string} userId
   * @returns {?rnp_uid_handle_t} The handle, which the caller must destroy.
   */
  _findUidHandle(keyHandle, userId) {
    const wanted = String(userId ?? "")
      .trim()
      .toLowerCase();
    if (!wanted) {
      return null;
    }

    const count = new lazy.ctypes.size_t();
    if (RNPLib.rnp_key_get_uid_count(keyHandle, count.address())) {
      throw new Error("rnp_key_get_uid_count failed");
    }

    // The text is read through `rnp_key_get_uid_at`, which takes the key and
    // an index; `rnp_uid_get_data` would be the direct route but is not bound,
    // and binding it for this would be a sixth binding for no gain.
    for (let i = 0; i < count.value; i++) {
      const text = new lazy.ctypes.char.ptr();
      if (RNPLib.rnp_key_get_uid_at(keyHandle, i, text.address())) {
        throw new Error("rnp_key_get_uid_at failed");
      }
      const text_ = text.readStringReplaceMalformed().trim().toLowerCase();
      RNPLib.rnp_buffer_destroy(text);

      if (
        text_ != wanted &&
        this._emailOfUid(text_) != this._emailOfUid(wanted)
      ) {
        continue;
      }

      const uid = new RNPLib.rnp_uid_handle_t();
      if (RNPLib.rnp_key_get_uid_handle_at(keyHandle, i, uid.address())) {
        throw new Error("rnp_key_get_uid_handle_at failed");
      }
      return uid;
    }
    return null;
  },

  /**
   * Whether a fingerprint names a key this FFI can see.
   *
   * Exists because building an unlock tracker for an absent fingerprint
   * throws rather than reporting absence, so every path that takes a
   * fingerprint from a caller has to ask this first.
   *
   * @param {string} fpr
   * @returns {boolean}
   */
  _keyIsInTheRing(fpr) {
    const handle = this.getKeyHandleByKeyIdOrFingerprint(
      RNPLib.ffi,
      `0x${fpr}`
    );
    if (!handle || handle.isNull()) {
      return false;
    }
    RNPLib.rnp_key_handle_destroy(handle);
    return true;
  },

  /**
   * The address inside a user ID, or the string itself when there is none.
   *
   * `getEmailWithoutBrackets` handles "<a@b>" but not "Name <a@b>", which is
   * the common form, so it is not enough for matching a user ID against an
   * address.
   *
   * @param {string} userId
   * @returns {string}
   */
  _emailOfUid(userId) {
    const parsed = lazy.EnigmailFuncs.getEmailFromUserID(userId);
    return (parsed || userId).trim().toLowerCase();
  },

  /**
   * Add a v4 post-quantum (ML-KEM-768+X25519) encryption subkey to the
   * given primary key. The primary key is unlocked on demand, which may
   * prompt the user for a passphrase. The new subkey is protected with
   * the same passphrase that protects the primary key.
   *
   * @param {string} primaryFpr - Fingerprint of the primary key.
   * @param {integer} expirySeconds - Seconds until the new subkey
   *   expires, or 0 if it should never expire.
   * @returns {Promise<boolean>} - true if a subkey was added, false if
   *   the preconditions weren't met or the user cancelled.
   */
  async addV4PQCEncryptionSubkey(primaryFpr, expirySeconds) {
    if (!Number.isInteger(expirySeconds) || expirySeconds < 0) {
      throw new Error(`invalid expirySeconds ${expirySeconds}`);
    }

    // The PQC policy is stricter than the general one: it also requires the
    // experimental library, a v4 ECC primary and an opted-in test address.
    if (!this.canGenerateV4PQCEncryptionSubkeyByFpr(primaryFpr)) {
      return false;
    }

    return this._generateSubkey(primaryFpr, {
      usage: "encrypt",
      algo: PQC_ENCRYPTION_ALGO,
      bits: 0,
      curve: null,
      expirySeconds,
    });
  },

  /**
   * Get a minimal Autocrypt-compatible key for the given key handles.
   * If subkey is given, it must refer to an existing encryption subkey.
   * This is a wrapper around RNP function rnp_key_export_autocrypt.
   *
   * @param {rnp_key_handle_t} primHandle - The handle of a primary key.
   * @param {?rnp_key_handle_t} subHandle - The handle of an encryption subkey or null.
   * @param {string} userId - The userID to include.
   * @returns {string} The encoded key, or the empty string on failure.
   */
  getAutocryptKeyB64ByHandle(primHandle, subHandle, userId) {
    if (!primHandle || primHandle.isNull()) {
      // A key held only in GnuPG has no handle here. An Autocrypt header is
      // optional metadata, so this must not abort the send.
      return "";
    }

    const output_to_memory = new RNPLib.rnp_output_t();
    if (RNPLib.rnp_output_to_memory(output_to_memory.address(), 0)) {
      throw new Error("rnp_output_to_memory failed");
    }

    let result = "";

    if (
      RNPLib.rnp_key_export_autocrypt(
        primHandle,
        subHandle,
        userId,
        output_to_memory,
        0
      )
    ) {
      lazy.log.warn("rnp_key_export_autocrypt FAILED");
    } else {
      const result_buf = new lazy.ctypes.uint8_t.ptr();
      const result_len = new lazy.ctypes.size_t();
      const rv = RNPLib.rnp_output_memory_get_buf(
        output_to_memory,
        result_buf.address(),
        result_len.address(),
        false
      );

      if (!rv) {
        // result_len is of type UInt64, I don't know of a better way
        // to convert it to an integer.
        const b_len = parseInt(result_len.value.toString());

        // type casting the pointer type to an array type allows us to
        // access the elements by index.
        const uint8_array = lazy.ctypes.cast(
          result_buf,
          lazy.ctypes.uint8_t.array(result_len.value).ptr
        ).contents;

        let str = "";
        for (let i = 0; i < b_len; i++) {
          str += String.fromCharCode(uint8_array[i]);
        }

        result = btoa(str);
      }
    }

    RNPLib.rnp_output_destroy(output_to_memory);

    return result;
  },

  /**
   * Minimal Autocrypt key for a key that exists only as an armored block, such
   * as one read from the external GnuPG keyring.
   *
   * Parsed into a temporary FFI context that is destroyed before returning, so
   * the persistent keyring is untouched.
   *
   * @param {string} keyBlock - ASCII armored public key block.
   * @param {string} keyId - Key id or fingerprint of the primary key.
   * @param {string} uidString - The user ID to include.
   * @returns {string} The base64 encoded key, or the empty string on failure.
   */
  getAutocryptKeyB64FromBlock(keyBlock, keyId, uidString) {
    if (!keyBlock) {
      return "";
    }
    const tempFFI = RNPLib.prepare_ffi();
    if (!tempFFI) {
      return "";
    }
    try {
      if (this.importToFFI(tempFFI, keyBlock, true, false)) {
        return "";
      }
      const primHandle = this.getKeyHandleByKeyIdOrFingerprint(tempFFI, keyId);
      if (!primHandle || primHandle.isNull()) {
        return "";
      }
      const result = this.getSuitableEncryptKeyAsAutocrypt(
        primHandle,
        uidString
      );
      RNPLib.rnp_key_handle_destroy(primHandle);
      return result;
    } catch (ex) {
      lazy.log.warn(
        `Autocrypt export from a key block failed for ${keyId}`,
        ex
      );
      return "";
    } finally {
      RNPLib.rnp_ffi_destroy(tempFFI);
    }
  },

  /**
   * Get a minimal Autocrypt-compatible key for the given key ID.
   * If subKeyId is given, it must refer to an existing encryption subkey.
   * This is a wrapper around RNP function rnp_key_export_autocrypt.
   *
   * @param {string} primaryKeyId - The ID of a primary key.
   * @param {?string} subKeyId - The ID of an encryption subkey or null.
   * @param {string} uidString - The userID to include.
   * @returns {string} The encoded key, or the empty string on failure.
   */
  getAutocryptKeyB64(primaryKeyId, subKeyId, uidString) {
    let subHandle = null;

    if (subKeyId) {
      subHandle = this.getKeyHandleByKeyIdOrFingerprint(RNPLib.ffi, subKeyId);
      if (subHandle.isNull()) {
        // Although subKeyId is optional, if it's given, it must be valid.
        return "";
      }
    }

    const primHandle = this.getKeyHandleByKeyIdOrFingerprint(
      RNPLib.ffi,
      primaryKeyId
    );

    const result = this.getAutocryptKeyB64ByHandle(
      primHandle,
      subHandle,
      uidString
    );

    if (!primHandle.isNull()) {
      RNPLib.rnp_key_handle_destroy(primHandle);
    }
    if (subHandle) {
      RNPLib.rnp_key_handle_destroy(subHandle);
    }
    return result;
  },

  /**
   * Helper function to produce the string that will be shown to the
   * user, when the user is asked to unlock a key. If the key is a
   * subkey, it might help to user to identify the respective key by
   * also mentioning the key ID of the primary key, so both IDs are
   * shown when prompting to unlock a subkey.
   * Parameter nonDefaultFFI is required, if the prompt is related to
   * a key that isn't (yet) stored in the global storage, for example
   * a key that is being prepared for import or export in a temporary
   * ffi space.
   *
   * @param {rnp_key_handle_t} handle - produce a passphrase prompt
   *   string based on the properties of this key.
   * @param {rnp_ffi_t} ffi - the RNP FFI that relates the handle
   * @returns {string} - a string that asks the user to enter the
   *   passphrase for the given string parameter, including details
   *   that allow the user to identify the key.
   */
  async getPassphrasePrompt(handle, ffi) {
    const parentOfHandle = this.getPrimaryKeyHandleIfSub(ffi, handle);
    const useThisHandle = !parentOfHandle.isNull() ? parentOfHandle : handle;

    const keyObj = {};
    if (
      !this.getKeyInfoFromHandle(ffi, useThisHandle, keyObj, false, true, true)
    ) {
      return "";
    }

    const mainKeyId = keyObj.keyId;
    let subKeyId;
    if (!parentOfHandle.isNull()) {
      subKeyId = this.getKeyIDFromHandle(handle);
    }

    if (subKeyId) {
      return l10n.formatValue("passphrase-prompt2-sub", {
        subkey: subKeyId,
        key: mainKeyId,
        date: keyObj.created,
        username_and_email: keyObj.userId,
      });
    }
    return l10n.formatValue("passphrase-prompt2", {
      key: mainKeyId,
      date: keyObj.created,
      username_and_email: keyObj.userId,
    });
  },

  getSupportedFeatureFlags() {
    // Update this bitmask whenever additional features are supported.
    return RNPLib.PGP_KEY_FEATURE_MDC;
  },

  /**
   * @param {EnigmailKeyObj} keyObj - The key to check.
   * @returns {boolean} true if unsupported features (version, algorithms) are advertised by this key
   */
  keyObjHasUnsupportedFeatures(keyObj) {
    let foundFeatures = 0;
    if (keyObj.features) {
      foundFeatures |= keyObj.features;
    }

    for (let i = 0; i < keyObj.userIds.length; i++) {
      const uid = keyObj.userIds[i];
      if (uid.type === "uid" && uid.features) {
        foundFeatures |= uid.features;
      }
    }

    const ourSupportedFeatures = this.getSupportedFeatureFlags();

    // Remove our supported feature flags from bitmask.
    const unsupportedFeatures = (foundFeatures &= ~ourSupportedFeatures);

    return unsupportedFeatures != 0;
  },

  /**
   * @param {?rnp_key_handle_t} handle - the handle of a RNP key
   * @returns {boolean} true if unsupported features (version, algorithms) are advertised by this key
   */
  keyHasUnsupportedFeatures(handle) {
    const selfId = this.getKeyIDFromHandle(handle);

    let foundFeatures = this.getSelfSigFeatures(selfId, handle);

    const uid_count = new lazy.ctypes.size_t();
    if (RNPLib.rnp_key_get_uid_count(handle, uid_count.address())) {
      throw new Error("rnp_key_get_uid_count failed");
    }
    for (let i = 0; i < uid_count.value; i++) {
      const uid_handle = new RNPLib.rnp_uid_handle_t();

      if (RNPLib.rnp_key_get_uid_handle_at(handle, i, uid_handle.address())) {
        throw new Error("rnp_key_get_uid_handle_at failed");
      }

      if (!this.isRevokedUid(uid_handle)) {
        const uid_str = new lazy.ctypes.char.ptr();
        if (RNPLib.rnp_key_get_uid_at(handle, i, uid_str.address())) {
          throw new Error("rnp_key_get_uid_at failed");
        }
        const userIdStr = uid_str.readStringReplaceMalformed();
        RNPLib.rnp_buffer_destroy(uid_str);

        if (userIdStr !== RNP_PHOTO_USERID_ID) {
          foundFeatures |= this.getUidFeatures(selfId, uid_handle);
        }
      }

      RNPLib.rnp_uid_handle_destroy(uid_handle);
    }

    const ourSupportedFeatures = this.getSupportedFeatureFlags();

    // Remove our supported feature flags from bitmask.
    const unsupportedFeatures = (foundFeatures &= ~ourSupportedFeatures);

    return unsupportedFeatures != 0;
  },

  /**
   * Verify an attachment.
   *
   * @param {string} dataPath - The data to verify.
   * @param {string} signaturePath - The signature data.
   * @returns {boolean} true if verification succeeded.
   */
  async verifyAttachment(dataPath, signaturePath) {
    const data = lazy.MailStringUtils.uint8ArrayToByteString(
      await IOUtils.read(dataPath)
    );
    const signature = lazy.MailStringUtils.uint8ArrayToByteString(
      await IOUtils.read(signaturePath)
    );
    return !(await this.verifyDetached(data, signature)).exitCode;
  },
};
