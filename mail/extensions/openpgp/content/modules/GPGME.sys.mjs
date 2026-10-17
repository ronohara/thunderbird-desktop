/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const lazy = {};
ChromeUtils.defineESModuleGetters(lazy, {
  EnigmailConstants: "chrome://openpgp/content/modules/constants.sys.mjs",
  GPGMELibLoader: "chrome://openpgp/content/modules/GPGMELib.sys.mjs",
  ctypes: "resource://gre/modules/ctypes.sys.mjs",
});

var GPGMELib;

export var GPGME = {
  hasRan: false,
  libLoaded: false,
  once() {
    this.hasRan = true;
    try {
      GPGMELib = lazy.GPGMELibLoader.init();
      if (!GPGMELib) {
        return;
      }
      if (GPGMELib && GPGMELib.init()) {
        GPGME.libLoaded = true;
      }
    } catch (e) {
      console.warn("Init GPGME FAILED", e);
    }
  },

  init() {
    if (!this.hasRan) {
      this.once();
    }

    return GPGME.libLoaded;
  },

  allDependenciesLoaded() {
    return GPGME.libLoaded;
  },

  /**
   * High level interface to retrieve public keys from GnuPG that
   * contain a user ID that matches the given email address.
   *
   * @param {string} email - The email address to search for.
   *
   * @returns {Map} - a Map that contains ASCII armored key blocks
   *   indexed by fingerprint.
   */
  getPublicKeysForEmail(email) {
    function keyFilterFunction(key) {
      if (
        key.contents.bitfield & GPGMELib.gpgme_key_t_revoked ||
        key.contents.bitfield & GPGMELib.gpgme_key_t_expired ||
        key.contents.bitfield & GPGMELib.gpgme_key_t_disabled ||
        key.contents.bitfield & GPGMELib.gpgme_key_t_invalid ||
        !(key.contents.bitfield & GPGMELib.gpgme_key_t_can_encrypt)
      ) {
        return false;
      }

      let matchesEmail = false;
      let nextUid = key.contents.uids;
      while (nextUid && !nextUid.isNull()) {
        const uidEmail = nextUid.contents.email.readString();
        // Variable email is provided by the outer scope.
        if (uidEmail == email) {
          matchesEmail = true;
          break;
        }
        nextUid = nextUid.contents.next;
      }
      return matchesEmail;
    }

    return GPGMELib.exportKeys(email, false, keyFilterFunction);
  },

  /**
   * Fingerprints of keys in the external GnuPG keyring that hold a secret key
   * for the given email address. Only the fingerprints are retrieved; no
   * secret key material is exported.
   *
   * Expired keys are included, because callers decide what to do about
   * expiry; revoked, disabled and invalid keys are not.
   *
   * @param {string} [email] - The email address to search for. Omit to list
   *   every secret key in the keyring.
   *
   * @returns {string[]} - Fingerprints of matching secret keys.
   */
  getSecretKeysForEmail(email) {
    const wanted = email ? email.toLowerCase() : null;

    function keyFilterFunction(key) {
      if (
        key.contents.bitfield & GPGMELib.gpgme_key_t_revoked ||
        key.contents.bitfield & GPGMELib.gpgme_key_t_disabled ||
        key.contents.bitfield & GPGMELib.gpgme_key_t_invalid
      ) {
        return false;
      }

      if (!wanted) {
        return true;
      }

      let nextUid = key.contents.uids;
      while (nextUid && !nextUid.isNull()) {
        if (nextUid.contents.email.readString().toLowerCase() == wanted) {
          return true;
        }
        nextUid = nextUid.contents.next;
      }
      return false;
    }

    return GPGMELib.listKeys(email ?? "", true, keyFilterFunction);
  },

  /**
   * Fingerprints of secret keys in GnuPG that match the given address, or all
   * of them when no address is given.
   *
   * @param {string} [email] - The email address to match.
   * @returns {string[]} Fingerprints.
   */
  getSecretKeyFingerprintsForEmail(email) {
    return this.getSecretKeysForEmail(email).map(key => key.fpr);
  },

  async decrypt(encrypted_string, enArmorCB) {
    const arr = encrypted_string.split("").map(e => e.charCodeAt());
    const encrypted_array = lazy.ctypes.uint8_t.array()(arr);
    return this.decryptArray(encrypted_array, enArmorCB);
  },

  async decryptArray(encrypted_array, enArmorCB) {
    const result = {};
    result.decryptedData = "";

    const tmp_array = lazy.ctypes.cast(
      encrypted_array,
      lazy.ctypes.char.array(encrypted_array.length)
    );

    const data_ciphertext = new GPGMELib.gpgme_data_t();
    if (
      GPGMELib.gpgme_data_new_from_mem(
        data_ciphertext.address(),
        tmp_array,
        tmp_array.length,
        0
      )
    ) {
      throw new Error("gpgme_data_new_from_mem failed");
    }

    const data_plain = new GPGMELib.gpgme_data_t();
    if (GPGMELib.gpgme_data_new(data_plain.address())) {
      throw new Error("gpgme_data_new failed");
    }

    const c1 = new GPGMELib.gpgme_ctx_t();
    if (GPGMELib.gpgme_new(c1.address())) {
      throw new Error("gpgme_new failed");
    }

    GPGMELib.gpgme_set_armor(c1, 1);

    result.exitCode = GPGMELib.gpgme_op_decrypt_ext(
      c1,
      GPGMELib.GPGME_DECRYPT_UNWRAP,
      data_ciphertext,
      data_plain
    );

    if (GPGMELib.gpgme_data_release(data_ciphertext)) {
      throw new Error("gpgme_data_release failed");
    }

    const result_len = new lazy.ctypes.size_t();
    const result_buf = GPGMELib.gpgme_data_release_and_get_mem(
      data_plain,
      result_len.address()
    );

    if (!result_buf.isNull()) {
      const unwrapped = lazy.ctypes.cast(
        result_buf,
        lazy.ctypes.char.array(result_len.value).ptr
      ).contents;

      // The result of decrypt(GPGME_DECRYPT_UNWRAP) is an OpenPGP message.
      // Because old versions of GPGME (e.g. 1.12.0) may return the
      // results as a binary encoding (despite gpgme_set_armor),
      // we check if the result looks like an armored message.
      // If it doesn't we apply armoring ourselves.

      const armor_head = "-----BEGIN PGP MESSAGE-----";

      const head_of_array = lazy.ctypes.cast(
        result_buf,
        lazy.ctypes.char.array(armor_head.length).ptr
      ).contents;

      let isArmored = false;

      try {
        // If this is binary, which usually isn't a valid UTF-8
        // encoding, it will throw an error.
        const head_of_array_string = head_of_array.readString();
        if (head_of_array_string == armor_head) {
          isArmored = true;
        }
      } catch (ex) {}

      if (isArmored) {
        result.decryptedData = unwrapped.readString();
      } else {
        result.decryptedData = enArmorCB(unwrapped, result_len.value);
      }

      GPGMELib.gpgme_free(result_buf);
    }

    GPGMELib.gpgme_release(c1);

    return result;
  },

  /**
   * Obtain a key handle from GnuPG, importing the public key first when GnuPG
   * does not hold it yet. GnuPG can only encrypt to keys in its own keyring, so
   * a recipient known only to Thunderbird's store has to be copied in.
   *
   * @param {object} ctx - An initialized gpgme context.
   * @param {object} recipient - The key to obtain.
   * @param {string} recipient.fpr - Fingerprint or key id to look up.
   * @param {string} [recipient.keyBlock] - ASCII armored public key to
   *   import when GnuPG does not already hold the key.
   * @returns {?object} The gpgme_key_t handle, or null.
   */
  _getKeyHandle(ctx, { fpr, keyBlock }) {
    const keyHandle = new GPGMELib.gpgme_key_t();
    if (!GPGMELib.gpgme_get_key(ctx, fpr, keyHandle.address(), 0)) {
      return keyHandle;
    }

    if (!keyBlock) {
      return null;
    }

    const data = new GPGMELib.gpgme_data_t();
    const tmp_array = lazy.ctypes.char.array()(keyBlock);
    if (
      GPGMELib.gpgme_data_new_from_mem(
        data.address(),
        tmp_array,
        tmp_array.length - 1,
        1
      )
    ) {
      return null;
    }

    const importResult = GPGMELib.gpgme_op_import(ctx, data);
    GPGMELib.gpgme_data_release(data);
    if (importResult) {
      return null;
    }

    if (!GPGMELib.gpgme_get_key(ctx, fpr, keyHandle.address(), 0)) {
      return keyHandle;
    }
    return null;
  },

  /**
   * Encrypt, and optionally sign, through GnuPG.
   *
   * @param {string} plaintext - The data to encrypt.
   * @param {object} args - The encryption parameters, as built by
   *   EnigmailEncryption.getCryptParams.
   * @param {object} resultStatus - Out parameter receiving exitCode and
   *   statusFlags.
   * @param {object[]} recipients - The keys to encrypt to.
   * @param {string} recipients[].fpr - Fingerprint or key id of the recipient.
   * @param {string} [recipients[].keyBlock] - ASCII armored public key,
   *   imported when GnuPG does not hold the key.
   * @param {string} [signingKeyId] - Key id or fingerprint to sign with.
   *   Required when args.sign is set.
   * @returns {?string} The encrypted data, or null on failure.
   */
  async encrypt(plaintext, args, resultStatus, recipients, signingKeyId) {
    resultStatus.exitCode = -1;
    resultStatus.statusFlags = 0;
    resultStatus.statusMsg = "";
    resultStatus.errorMsg = "";

    if (!args.encrypt) {
      throw new Error("invalid encrypt parameters");
    }
    if (!plaintext) {
      throw new Error("cannot encrypt empty data");
    }
    if (!recipients || !recipients.length) {
      throw new Error("no recipients for encryption");
    }

    const ctx = new GPGMELib.gpgme_ctx_t();
    if (GPGMELib.gpgme_new(ctx.address())) {
      throw new Error("gpgme_new failed");
    }
    GPGMELib.gpgme_set_armor(ctx, args.armor ? 1 : 0);

    const keyHandles = [];
    let result = null;

    try {
      for (const rcp of recipients) {
        const keyHandle = this._getKeyHandle(ctx, rcp);
        if (!keyHandle) {
          return null;
        }
        keyHandles.push(keyHandle);
      }

      const keyArray = GPGMELib.gpgme_key_t.array(keyHandles.length + 1)();
      for (let i = 0; i < keyHandles.length; i++) {
        keyArray[i] = keyHandles[i];
      }
      keyArray[keyHandles.length] = new GPGMELib.gpgme_key_t();

      if (args.sign) {
        if (!signingKeyId) {
          throw new Error("missing signing key for encrypted and signed data");
        }
        const signerHandle = this._getKeyHandle(ctx, { fpr: signingKeyId });
        if (!signerHandle) {
          return null;
        }
        keyHandles.push(signerHandle);
        GPGMELib.gpgme_set_textmode(ctx, 1);
        if (GPGMELib.gpgme_signers_add(ctx, signerHandle)) {
          return null;
        }
      }

      const tmp_array = lazy.ctypes.char.array()(plaintext);
      const data_plaintext = new GPGMELib.gpgme_data_t();
      if (
        GPGMELib.gpgme_data_new_from_mem(
          data_plaintext.address(),
          tmp_array,
          tmp_array.length - 1,
          0
        )
      ) {
        return null;
      }

      const data_ciphertext = new GPGMELib.gpgme_data_t();
      if (GPGMELib.gpgme_data_new(data_ciphertext.address())) {
        GPGMELib.gpgme_data_release(data_plaintext);
        return null;
      }

      const flags = GPGMELib.GPGME_ENCRYPT_ALWAYS_TRUST;
      const exitCode = args.sign
        ? GPGMELib.gpgme_op_encrypt_sign(
            ctx,
            keyArray,
            flags,
            data_plaintext,
            data_ciphertext
          )
        : GPGMELib.gpgme_op_encrypt(
            ctx,
            keyArray,
            flags,
            data_plaintext,
            data_ciphertext
          );

      GPGMELib.gpgme_data_release(data_plaintext);

      if (exitCode != GPGMELib.GPG_ERR_NO_ERROR) {
        GPGMELib.gpgme_data_release(data_ciphertext);
        return null;
      }

      const result_len = new lazy.ctypes.size_t();
      const result_buf = GPGMELib.gpgme_data_release_and_get_mem(
        data_ciphertext,
        result_len.address()
      );

      if (!result_buf.isNull()) {
        // The output is armored text or raw OpenPGP packets. Deciding which
        // by the bytes rather than by the requested flag also covers a
        // gpg.conf that forces armor.
        const armorHead = "-----BEGIN PGP MESSAGE-----";
        let isArmored = false;
        try {
          const head = lazy.ctypes.cast(
            result_buf,
            lazy.ctypes.char.array(armorHead.length).ptr
          ).contents;
          isArmored = head.readString() == armorHead;
        } catch (ex) {}

        if (isArmored) {
          const unwrapped = lazy.ctypes.cast(
            result_buf,
            lazy.ctypes.char.array(result_len.value).ptr
          ).contents;
          result = unwrapped.readString();
        } else {
          const unwrapped = lazy.ctypes.cast(
            result_buf,
            lazy.ctypes.uint8_t.array(result_len.value).ptr
          ).contents;
          result = unwrapped.readTypedArray();
        }
        GPGMELib.gpgme_free(result_buf);
      }

      if (result) {
        resultStatus.exitCode = 0;
        resultStatus.statusFlags |= lazy.EnigmailConstants.END_ENCRYPTION;
        if (args.sign) {
          resultStatus.statusFlags |= lazy.EnigmailConstants.SIG_CREATED;
        }
      }
    } finally {
      for (const keyHandle of keyHandles) {
        GPGMELib.gpgme_key_release(keyHandle);
      }
      GPGMELib.gpgme_release(ctx);
    }

    return result;
  },

  async signDetached(plaintext, args, resultStatus) {
    resultStatus.exitCode = -1;
    resultStatus.statusFlags = 0;
    resultStatus.statusMsg = "";
    resultStatus.errorMsg = "";

    if (args.encrypt || !args.sign || !args.sigTypeDetached) {
      throw new Error("invalid encrypt/sign parameters");
    }
    if (!plaintext) {
      throw new Error("cannot sign empty data");
    }

    let result = null;
    const keyId = args.externalSenderSigningKeyID
      .replace(/^0x/, "")
      .toUpperCase();

    const ctx = new GPGMELib.gpgme_ctx_t();
    if (GPGMELib.gpgme_new(ctx.address())) {
      throw new Error("gpgme_new failed");
    }
    GPGMELib.gpgme_set_armor(ctx, 1);
    GPGMELib.gpgme_set_textmode(ctx, 1);
    const keyHandle = new GPGMELib.gpgme_key_t();
    if (!GPGMELib.gpgme_get_key(ctx, keyId, keyHandle.address(), 1)) {
      if (!GPGMELib.gpgme_signers_add(ctx, keyHandle)) {
        var tmp_array = lazy.ctypes.char.array()(plaintext);
        const data_plaintext = new GPGMELib.gpgme_data_t();

        // The tmp_array will have one additional byte to store the
        // trailing null character, we don't want to sign it, thus -1.
        if (
          !GPGMELib.gpgme_data_new_from_mem(
            data_plaintext.address(),
            tmp_array,
            tmp_array.length - 1,
            0
          )
        ) {
          const data_signed = new GPGMELib.gpgme_data_t();
          if (!GPGMELib.gpgme_data_new(data_signed.address())) {
            const exitCode = GPGMELib.gpgme_op_sign(
              ctx,
              data_plaintext,
              data_signed,
              GPGMELib.GPGME_SIG_MODE_DETACH
            );
            if (exitCode != GPGMELib.GPG_ERR_NO_ERROR) {
              GPGMELib.gpgme_data_release(data_signed);
            } else {
              const result_len = new lazy.ctypes.size_t();
              const result_buf = GPGMELib.gpgme_data_release_and_get_mem(
                data_signed,
                result_len.address()
              );
              if (!result_buf.isNull()) {
                const unwrapped = lazy.ctypes.cast(
                  result_buf,
                  lazy.ctypes.char.array(result_len.value).ptr
                ).contents;
                result = unwrapped.readString();
                resultStatus.exitCode = 0;
                resultStatus.statusFlags |= lazy.EnigmailConstants.SIG_CREATED;
                GPGMELib.gpgme_free(result_buf);
              }
            }
          }
        }
      }
      GPGMELib.gpgme_key_release(keyHandle);
    }
    GPGMELib.gpgme_release(ctx);
    return result;
  },

  async sign(plaintext, args, resultStatus) {
    resultStatus.exitCode = -1;
    resultStatus.statusFlags = 0;
    resultStatus.statusMsg = "";
    resultStatus.errorMsg = "";

    if (args.encrypt || !args.sign) {
      throw new Error("invalid encrypt/sign parameters");
    }
    if (!plaintext) {
      throw new Error("cannot sign empty data");
    }

    let result = null;
    const keyId = args.externalSenderSigningKeyID
      .replace(/^0x/, "")
      .toUpperCase();

    const ctx = new GPGMELib.gpgme_ctx_t();
    if (GPGMELib.gpgme_new(ctx.address())) {
      throw new Error("gpgme_new failed");
    }
    GPGMELib.gpgme_set_armor(ctx, 0);
    const keyHandle = new GPGMELib.gpgme_key_t();
    if (!GPGMELib.gpgme_get_key(ctx, keyId, keyHandle.address(), 1)) {
      if (!GPGMELib.gpgme_signers_add(ctx, keyHandle)) {
        var tmp_array = lazy.ctypes.char.array()(plaintext);
        const data_plaintext = new GPGMELib.gpgme_data_t();

        // The tmp_array will have one additional byte to store the
        // trailing null character, we don't want to sign it, thus -1.
        if (
          !GPGMELib.gpgme_data_new_from_mem(
            data_plaintext.address(),
            tmp_array,
            tmp_array.length - 1,
            0
          )
        ) {
          const data_signed = new GPGMELib.gpgme_data_t();
          if (!GPGMELib.gpgme_data_new(data_signed.address())) {
            const exitCode = GPGMELib.gpgme_op_sign(
              ctx,
              data_plaintext,
              data_signed,
              GPGMELib.GPGME_SIG_MODE_NORMAL
            );
            if (exitCode != GPGMELib.GPG_ERR_NO_ERROR) {
              GPGMELib.gpgme_data_release(data_signed);
            } else {
              const result_len = new lazy.ctypes.size_t();
              const result_buf = GPGMELib.gpgme_data_release_and_get_mem(
                data_signed,
                result_len.address()
              );
              if (!result_buf.isNull()) {
                const unwrapped = lazy.ctypes.cast(
                  result_buf,
                  lazy.ctypes.uint8_t.array(result_len.value).ptr
                ).contents;

                result = unwrapped.readTypedArray();
                resultStatus.exitCode = 0;
                resultStatus.statusFlags |= lazy.EnigmailConstants.SIG_CREATED;
                GPGMELib.gpgme_free(result_buf);
              }
            }
          }
        }
      }
      GPGMELib.gpgme_key_release(keyHandle);
    }
    GPGMELib.gpgme_release(ctx);
    return result;
  },
};
