/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const lazy = {};
ChromeUtils.defineESModuleGetters(lazy, {
  EnigmailConstants: "chrome://openpgp/content/modules/constants.sys.mjs",
  GPGMELibLoader: "chrome://openpgp/content/modules/GPGMELib.sys.mjs",
  GnuPGAgent: "chrome://openpgp/content/modules/gnupgAgent.sys.mjs",
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
   * gpgme's own wording for an error code.
   *
   * gpgme returns a packed number, and a number tells a user nothing. The
   * string behind it does: "No pinentry" names the missing thing, and
   * "Unusable public key" names the key problem. Item 24 measured that the
   * code was being dropped entirely on every failure path, so a failed send
   * arrived as an unexplained failure. This is the function that turns it back
   * into something a person can act on.
   *
   * Never throws: a failure to describe a failure must not replace it, so an
   * unusable library falls back to the number.
   *
   * @param {number} code - gpgme_error_t as returned by an operation.
   * @returns {string} The reason, or the numeric code when it cannot be read.
   */
  strerror(code) {
    const numeric = Number(code);
    if (!numeric) {
      return "";
    }
    try {
      if (!GPGME.init() || !GPGMELib.gpgme_strerror) {
        return `gpgme error ${numeric}`;
      }
      const text = GPGMELib.gpgme_strerror(numeric);
      const reason = text?.isNull?.() ? "" : text.readString();
      return reason || `gpgme error ${numeric}`;
    } catch (ex) {
      return `gpgme error ${numeric}`;
    }
  },

  /**
   * Whether a gpgme error is the user cancelling a passphrase prompt.
   *
   * A cancellation is not a failure, and the design requires the two to be
   * distinguishable: "Signing was cancelled" is the message, and the send is
   * aborted with the message kept rather than reported as broken. Before this,
   * a cancellation and a failure arrived as the same thing -- an unexplained
   * failure -- so the distinction was unreachable.
   *
   * gpgme packs a source in the high byte, and a cancellation can come from
   * either the agent or pinentry depending on which of them handled the
   * refusal, so any source carrying GPG_ERR_CANCELED counts.
   *
   * @param {number} code - A packed gpgme error.
   * @returns {boolean} True when the user cancelled.
   */
  isCancellation(code) {
    if (!code || !GPGMELib) {
      return false;
    }
    const errCode = Number(code) & GPGMELib.GPG_ERR_CODE_MASK;
    return errCode == GPGMELib.GPG_ERR_CANCELED;
  },

  /**
   * Record a gpgme failure where the caller will see it.
   *
   * Both the number and the words, because the number is what a bug report
   * needs and the words are what the user needs.
   *
   * @param {object} resultStatus - Out parameter of the calling operation.
   * @param {number} code - gpgme_error_t.
   */
  recordGpgmeFailure(resultStatus, code) {
    if (!resultStatus) {
      return;
    }
    resultStatus.exitCode = Number(code) || -1;
    resultStatus.errorMsg = this.strerror(code);
    // A cancellation is recorded as well as returned, so a caller that inspects
    // the status object rather than catching an error can still tell the two
    // apart. Design 5.7 requires a cancelled prompt to abort the send with the
    // message kept, which is a different action from reporting a failure.
    if (this.isCancellation(code)) {
      resultStatus.cancelled = true;
    }
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
   * Whether the external GnuPG keyring holds a *secret* key for a fingerprint.
   *
   * The distinction between this and "GnuPG knows this key" is the whole of
   * its purpose: `gpgme_op_keylist_start` with `secret_only` unset returns a
   * key whose public half is present and whose secret half may be nowhere but
   * in the file a caller is about to import. Answering that as "held" would
   * refuse an import the user actually needs.
   *
   * A listing rather than an export: no key material is read, and the listing
   * stops at the first match, so this is cheap enough to call on every import.
   * Subkeys are matched too, because a block may carry a secret subkey whose
   * primary key is held elsewhere.
   *
   * @param {string} fingerprint - Fingerprint of the primary key or a subkey.
   * @returns {boolean} True if GnuPG holds the secret for that fingerprint.
   */
  hasSecretKey(fingerprint) {
    if (!fingerprint) {
      return false;
    }
    const wanted = fingerprint.replace(/^0x/i, "").toUpperCase();
    if (!this.init()) {
      return false;
    }
    try {
      const keys = GPGMELib.listKeys(wanted, true);
      return keys.some(
        key =>
          key.fpr.toUpperCase() == wanted ||
          key.subkeys?.some(sub => sub.fpr && sub.fpr.toUpperCase() == wanted)
      );
    } catch (ex) {
      console.warn(`Checking GnuPG for the secret key ${wanted} failed`, ex);
      return false;
    }
  },

  /**
   * Whether the external GnuPG keyring holds a public key for a fingerprint.
   *
   * The public counterpart of hasSecretKey(), and the same shape: a listing
   * with no key material read, matching subkeys as well as the primary.
   *
   * @param {string} fingerprint - Fingerprint of the primary key or a subkey.
   * @returns {boolean} True if GnuPG holds the key.
   */
  hasPublicKey(fingerprint) {
    if (!fingerprint) {
      return false;
    }
    const wanted = fingerprint.replace(/^0x/i, "").toUpperCase();
    if (!this.init()) {
      return false;
    }
    try {
      const keys = GPGMELib.listKeys(wanted, false);
      return keys.some(
        key =>
          key.fpr.toUpperCase() == wanted ||
          key.subkeys?.some(sub => sub.fpr && sub.fpr.toUpperCase() == wanted)
      );
    } catch (ex) {
      console.warn(`Checking GnuPG for the key ${wanted} failed`, ex);
      return false;
    }
  },

  /**
   * Public keys from GnuPG matching an identifier, without filtering by user
   * ID. Needed when the caller has a key id rather than an address.
   *
   * @param {string} id - Key id or fingerprint.
   * @returns {Map} Fingerprint -> ASCII armored public key block.
   */
  getPublicKeysForId(id) {
    if (!id) {
      return new Map();
    }
    return GPGMELib.exportKeys(id, false);
  },

  /**
   * Ask GnuPG which key should sign, and report what it said.
   *
   * Thunderbird does not rank keys here. The identity is handed to gpg, and
   * the answer is assembled from gpg's own listing: the order it prints, the
   * states it reports, and the key it has been configured to prefer.
   *
   * Three of gpg's rules are applied, and each one is sourced rather than
   * reinterpreted:
   *
   * - **`--default-key`.** When gpg has a default key configured and that key
   *   belongs to this identity, it wins. This is the one rule `--local-user`
   *   does not express, because an explicit `-u` overrides it -- measured, and
   *   the reason it is applied here instead.
   * - **gpg's key order.** Otherwise the first usable key gpg lists for the
   *   identity is used, which is what `--local-user <identity>` resolves to.
   * - **gpg's key state.** Revoked, expired, invalid and disabled keys are
   *   excluded, from gpg's own validity and capability fields.
   *
   * **And one of gpg's rules is deliberately not followed.** Measured on gpg
   * 2.4.4: `--local-user <identity>` still signs with a key that has been
   * disabled. Delegating that answer literally would mean sending with a key
   * the user has retired, so disabled stays excluded here.
   *
   * The signing subkey is still chosen by us rather than by gpg, because
   * gpgme cannot pick one: handing it a primary key id that cannot sign makes
   * `gpgme_op_sign` fail (bug 2026356). That is a gpgme limitation, not a
   * preference, and it is why this function returns a subkey key id whenever
   * the key has a usable signing subkey.
   *
   * @param {string} identity - The sender's address, or a key id/fingerprint.
   * @returns {Promise<?object>} { keyId, fpr, source } where source is
   *   "default-key" or "gnupg-order", or null when gpg holds no usable key.
   */
  async resolveSigningKeyForIdentity(identity) {
    const raw = String(identity ?? "").trim();
    if (!raw) {
      return null;
    }

    const isKeyId = /^(0x)?[0-9a-f]{8,64}$/i.test(raw);
    const pattern = isKeyId ? `0x${raw.replace(/^0x/i, "")}` : raw;

    let keys;
    let defaultKey = "";
    try {
      keys = await lazy.GnuPGAgent.listSecretKeys(pattern);
      if (!isKeyId) {
        defaultKey = await lazy.GnuPGAgent.configuredDefaultKey();
      }
    } catch (ex) {
      console.warn("Asking GnuPG for its key selection failed", ex);
      return null;
    }

    const usable = key =>
      !/^[redi]/.test(key.validity || "") &&
      !(key.capabilities || "").includes("D");
    const canSign = key => /[sS]/.test(key.capabilities || "");

    const identityMatches = key => {
      if (isKeyId) {
        const wanted = raw.replace(/^0x/i, "").toUpperCase();
        const fpr = (key.fpr || "").toUpperCase();
        return (
          fpr.endsWith(wanted) ||
          (key.keyId || "").toUpperCase().endsWith(wanted) ||
          key.subkeys.some(
            sub =>
              (sub.fpr || "").toUpperCase().endsWith(wanted) ||
              (sub.keyId || "").toUpperCase().endsWith(wanted)
          )
        );
      }
      const wanted = this.emailFromIdentity(raw);
      return key.uids.some(uid => uid.email && uid.email == wanted);
    };

    const candidates = keys.filter(key => usable(key) && identityMatches(key));

    const preferred = defaultKey
      ? candidates.find(key => this.keyMatchesIdentifier(key, defaultKey))
      : null;
    if (preferred && (canSign(preferred) || this.signingSubkey(preferred))) {
      return this.signingKeyRecord(preferred, "default-key");
    }

    const first = candidates.find(
      key => canSign(key) || this.signingSubkey(key)
    );
    if (!first) {
      return null;
    }
    return this.signingKeyRecord(first, "gnupg-order");
  },

  /**
   * The address part of an identity string.
   *
   * @param {string} identity - An address, or "Name <address>".
   * @returns {string} The address in lower case.
   */
  emailFromIdentity(identity) {
    const match = /<([^<>]+)>/.exec(identity);
    return (match ? match[1] : identity).trim().toLowerCase();
  },

  /**
   * Whether a key record from gpg's listing is the one an identifier names.
   *
   * The identifier arrives from gpg.conf, where it may be a fingerprint, a
   * key id, an address, or "Name <address>". Only the forms that name a key
   * uniquely are accepted: a match on a short suffix or on an address is
   * enough, since that is all `--default-key` needs.
   *
   * @param {object} key - A record from GnuPGAgent.listSecretKeys().
   * @param {string} identifier - The configured identifier.
   * @returns {boolean} True when the identifier names this key.
   */
  keyMatchesIdentifier(key, identifier) {
    const wanted = identifier.trim();
    if (!wanted) {
      return false;
    }

    // Only a value that is entirely hexadecimal can name a key by id;
    // stripping the 0x prefix must not touch a fingerprint that starts with 0.
    const stripped = wanted.replace(/^0x/i, "");
    if (/^[0-9a-f]{8,64}$/i.test(stripped)) {
      const compact = stripped.toUpperCase();
      return (
        (key.fpr || "").toUpperCase().endsWith(compact) ||
        (key.keyId || "").toUpperCase().endsWith(compact)
      );
    }

    const email = this.emailFromIdentity(wanted);
    if (email.includes("@")) {
      return key.uids.some(uid => uid.email == email);
    }
    return key.uids.some(uid => uid.uid == wanted);
  },

  /**
   * The usable signing subkey of a key, when it has one.
   *
   * @param {object} key - A record from GnuPGAgent.listSecretKeys().
   * @returns {?object} The subkey record, or null.
   */
  signingSubkey(key) {
    return (
      key.subkeys.find(
        sub =>
          /[sS]/.test(sub.capabilities || "") &&
          !(sub.capabilities || "").includes("D") &&
          !/^[redi]/.test(sub.validity || "")
      ) || null
    );
  },

  /**
   * Build the answer for a chosen key, preferring the signing subkey.
   *
   * @param {object} key - A record from GnuPGAgent.listSecretKeys().
   * @param {string} source - Which of gpg's rules chose it.
   * @returns {object} { keyId, fpr, source }.
   */
  signingKeyRecord(key, source) {
    const sub = this.signingSubkey(key);
    if (sub) {
      return { keyId: sub.keyId, fpr: sub.fpr || key.fpr, source };
    }
    return { keyId: key.keyId, fpr: key.fpr, source };
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
   * @param {boolean} [secret] - Request the secret key, which signing needs.
   * @returns {?object} The gpgme_key_t handle, or null.
   */
  _getKeyHandle(ctx, { fpr, keyBlock }, secret = false) {
    const secretFlag = secret ? 1 : 0;
    const keyHandle = new GPGMELib.gpgme_key_t();
    if (!GPGMELib.gpgme_get_key(ctx, fpr, keyHandle.address(), secretFlag)) {
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

    if (!GPGMELib.gpgme_get_key(ctx, fpr, keyHandle.address(), secretFlag)) {
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
        const signerHandle = this._getKeyHandle(
          ctx,
          { fpr: signingKeyId },
          true
        );
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
        // Before Item 28 this returned null and the code was lost, so a
        // failed encryption reached the composer as an unexplained failure.
        this.recordGpgmeFailure(resultStatus, exitCode);
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
              this.recordGpgmeFailure(resultStatus, exitCode);
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
              this.recordGpgmeFailure(resultStatus, exitCode);
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
