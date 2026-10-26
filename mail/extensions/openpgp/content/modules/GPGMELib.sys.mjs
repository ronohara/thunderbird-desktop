/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import { ctypes } from "resource://gre/modules/ctypes.sys.mjs";

var log = console.createInstance({
  prefix: "openpgp",
  maxLogLevel: "Warn",
  maxLogLevelPref: "openpgp.loglevel",
});

var abi = ctypes.default_abi;

// Default library paths to look for on macOS
const ADDITIONAL_LIB_PATHS = [
  "/usr/local/lib",
  "/opt/local/lib",
  "/opt/homebrew/lib",
];

// Open libgpgme. Determine the path to the chrome directory and look for it
// there first. If not, fallback to searching the standard locations.
var libgpgme, libgpgmePath;

function tryLoadGPGME(name, suffix) {
  const filename = ctypes.libraryName(name) + suffix;
  const binPath = Services.dirsvc.get("XpcomLib", Ci.nsIFile).path;
  const binDir = PathUtils.parent(binPath);
  libgpgmePath = PathUtils.join(binDir, filename);

  let loaded = null;
  try {
    loaded = ctypes.open(libgpgmePath);
  } catch (e) {}

  if (loaded) {
    log.debug(`Loaded GPGME from ${libgpgmePath}`);
    return loaded;
  }

  try {
    // look in system's standard library locations
    libgpgmePath = filename;
    loaded = ctypes.open(libgpgmePath);
  } catch (e) {}

  if (loaded) {
    log.debug(`Loaded GPGME from ${libgpgmePath}`);
    return loaded;
  }

  if (Services.appinfo.OS !== "WINNT") {
    // try specific additional directories
    for (const tryPath of ADDITIONAL_LIB_PATHS) {
      try {
        libgpgmePath = tryPath + "/" + filename;
        loaded = ctypes.open(libgpgmePath);
        if (loaded) {
          log.debug(`Loaded GPGME from ${libgpgmePath}`);
          break;
        }
      } catch (e) {}
    }
  }

  return loaded;
}

function loadExternalGPGMELib() {
  if (libgpgme) {
    throw new Error("Internal error, trying to load GPGME again");
  }

  let optionalGPGMEVersion = Services.prefs.getStringPref(
    "mail.openpgp.load_untested_gpgme_version"
  );

  // Only allow characters expected in version numbers,
  // which will disallow things like path separators.
  if (optionalGPGMEVersion && !/^[A-Za-z0-9]+$/.test(optionalGPGMEVersion)) {
    log.debug(`Ignoring invalid value in load_untested_gpgme_version`);
    optionalGPGMEVersion = "";
  }

  const libsToTry = [];
  libsToTry.push(["libgpgme6-11", ""]);
  libsToTry.push(["libgpgme-11", ""]);

  if (Services.appinfo.OS === "WINNT") {
    if (optionalGPGMEVersion) {
      libsToTry.push(["libgpgme-" + optionalGPGMEVersion, ""]);
      libsToTry.push(["gpgme-" + optionalGPGMEVersion, ""]);
    }

    libsToTry.push(["libgpgme6-11", ""]);
    libsToTry.push(["libgpgme-45", ""]);
    libsToTry.push(["gpgme-45", ""]);
    libsToTry.push(["libgpgme-11", ""]);
    libsToTry.push(["gpgme-11", ""]);
  }

  if (optionalGPGMEVersion) {
    libsToTry.push(["gpgme", "." + optionalGPGMEVersion]);
    libsToTry.push(["gpgme." + optionalGPGMEVersion, ""]);
  }

  libsToTry.push(["gpgme", ""]);
  libsToTry.push(["gpgme", ".45"]);
  libsToTry.push(["gpgme.45", ""]);
  libsToTry.push(["gpgme", ".11"]);
  libsToTry.push(["gpgme.11", ""]);

  for (const [name, suffix] of libsToTry) {
    libgpgme = tryLoadGPGME(name, suffix);
    if (libgpgme) {
      break;
    }
  }

  return !!libgpgme;
}

export var GPGMELibLoader = {
  init() {
    if (!loadExternalGPGMELib()) {
      return null;
    }
    if (libgpgme) {
      enableGPGMELibJS();
    }
    return GPGMELib;
  },
};

const gpgme_error_t = ctypes.unsigned_int;
const gpgme_ctx_t = ctypes.void_t.ptr;
const gpgme_data_t = ctypes.void_t.ptr;
const gpgme_validity_t = ctypes.int;
const gpgme_keylist_mode_t = ctypes.unsigned_int;
const gpgme_protocol_t = ctypes.int;
const gpgme_pubkey_algo_t = ctypes.int;
const gpgme_sig_notation_flags_t = ctypes.unsigned_int;
const gpgme_export_mode_t = ctypes.unsigned_int;
const gpgme_decrypt_flags_t = ctypes.unsigned_int;
const gpgme_data_encoding_t = ctypes.unsigned_int;
const gpgme_sig_mode_t = ctypes.int; // it's an enum, risk of wrong type.
const gpgme_encrypt_flags_t = ctypes.unsigned_int;

const _gpgme_subkey = ctypes.StructType("_gpgme_subkey");
_gpgme_subkey.define([
  { next: _gpgme_subkey.ptr },
  { bitfield: ctypes.unsigned_int },
  { pubkey_algo: gpgme_pubkey_algo_t },
  { length: ctypes.unsigned_int },
  { keyid: ctypes.char.ptr },
  { _keyid: ctypes.char.array(17) },
  { fpr: ctypes.char.ptr },
  { timestamp: ctypes.long },
  { expires: ctypes.long },
  { card_number: ctypes.char.ptr },
  { curve: ctypes.char.ptr },
  { keygrip: ctypes.char.ptr },
]);
const gpgme_subkey_t = _gpgme_subkey.ptr;

const _gpgme_sig_notation = ctypes.StructType("_gpgme_sig_notation");
_gpgme_sig_notation.define([
  { next: _gpgme_sig_notation.ptr },
  { name: ctypes.char.ptr },
  { value: ctypes.char.ptr },
  { name_len: ctypes.int },
  { value_len: ctypes.int },
  { flags: gpgme_sig_notation_flags_t },
  { bitfield: ctypes.unsigned_int },
]);
const gpgme_sig_notation_t = _gpgme_sig_notation.ptr;

const _gpgme_key_sig = ctypes.StructType("_gpgme_key_sig");
_gpgme_key_sig.define([
  { next: _gpgme_key_sig.ptr },
  { bitfield: ctypes.unsigned_int },
  { pubkey_algo: gpgme_pubkey_algo_t },
  { keyid: ctypes.char.ptr },
  { _keyid: ctypes.char.array(17) },
  { timestamp: ctypes.long },
  { expires: ctypes.long },
  { status: gpgme_error_t },
  { class_: ctypes.unsigned_int },
  { uid: ctypes.char.ptr },
  { name: ctypes.char.ptr },
  { email: ctypes.char.ptr },
  { comment: ctypes.char.ptr },
  { sig_class: ctypes.unsigned_int },
  { notations: gpgme_sig_notation_t },
  { last_notation: gpgme_sig_notation_t },
]);
const gpgme_key_sig_t = _gpgme_key_sig.ptr;

const _gpgme_tofu_info = ctypes.StructType("_gpgme_tofu_info");
_gpgme_tofu_info.define([
  { next: _gpgme_tofu_info.ptr },
  { bitfield: ctypes.unsigned_int },
  { signcount: ctypes.unsigned_short },
  { encrcount: ctypes.unsigned_short },
  { signfirst: ctypes.unsigned_short },
  { signlast: ctypes.unsigned_short },
  { encrfirst: ctypes.unsigned_short },
  { encrlast: ctypes.unsigned_short },
  { description: ctypes.char.ptr },
]);
const gpgme_tofu_info_t = _gpgme_tofu_info.ptr;

const _gpgme_user_id = ctypes.StructType("_gpgme_user_id");
_gpgme_user_id.define([
  { next: _gpgme_user_id.ptr },
  { bitfield: ctypes.unsigned_int },
  { validity: gpgme_validity_t },
  { uid: ctypes.char.ptr },
  { name: ctypes.char.ptr },
  { email: ctypes.char.ptr },
  { comment: ctypes.char.ptr },
  { signatures: gpgme_key_sig_t },
  { _last_keysig: gpgme_key_sig_t },
  { address: ctypes.char.ptr },
  { tofu: gpgme_tofu_info_t },
  { last_update: ctypes.unsigned_long },
]);
const gpgme_user_id_t = _gpgme_user_id.ptr;

const _gpgme_key = ctypes.StructType("gpgme_key_t", [
  { _refs: ctypes.unsigned_int },
  { bitfield: ctypes.unsigned_int },
  { protocol: gpgme_protocol_t },
  { issuer_serial: ctypes.char.ptr },
  { issuer_name: ctypes.char.ptr },
  { chain_id: ctypes.char.ptr },
  { owner_trust: gpgme_validity_t },
  { subkeys: gpgme_subkey_t },
  { uids: gpgme_user_id_t },
  { _last_subkey: gpgme_subkey_t },
  { _last_uid: gpgme_user_id_t },
  { keylist_mode: gpgme_keylist_mode_t },
  { fpr: ctypes.char.ptr },
  { last_update: ctypes.unsigned_long },
]);
const gpgme_key_t = _gpgme_key.ptr;

var GPGMELib;

function enableGPGMELibJS() {
  // this must be delayed until after "libgpgme" is initialized

  GPGMELib = {
    path: libgpgmePath,

    init() {
      // GPGME 1.9.0 released 2017-03-28 is the first version that
      // supports GPGME_DECRYPT_UNWRAP, requiring >= gpg 2.1.12
      const version = this.gpgme_check_version("1.9.0").readString();

      const gpgExe = Services.prefs.getStringPref(
        "mail.openpgp.alternative_gpg_path"
      );
      if (!gpgExe) {
        // Use the normal gpg executable.
        return true;
      }

      const extResult = this.gpgme_set_engine_info(
        this.GPGME_PROTOCOL_OpenPGP,
        gpgExe,
        null
      );
      const success = extResult === this.GPG_ERR_NO_ERROR;
      if (success) {
        log.debug(`Using external OpenPGP engine; v${version}: ${gpgExe}`);
      } else {
        log.error(
          `Could not use external OpenPGP engine; v${version}: ${gpgExe} - ${extResult}`
        );
      }
      return success;
    },

    /**
     * Export key blocks from GnuPG that match the given parameters.
     *
     * @param {string} pattern - A pattern given to GnuPG for listing keys.
     * @param {boolean} secret - If true, retrieve secret keys.
     *   If false, retrieve public keys.
     * @param {Function} keyFilterFunction - An optional test function that
     *   will be called for each candidate key that GnuPG lists for the
     *   given pattern. Allows the caller to decide whether a candidate
     *   key is wanted or not. Function will be called with a
     *   {gpgme_key_t} parameter, the candidate key returned by GPGME.
     *
     * @returns {Map} - a Map that contains ASCII armored key blocks
     *   indexed by fingerprint.
     */
    exportKeys(pattern, secret = false, keyFilterFunction = undefined) {
      const resultMap = new Map();
      const allFingerprints = [];

      const c1 = new gpgme_ctx_t();
      if (this.gpgme_new(c1.address())) {
        throw new Error("gpgme_new failed");
      }

      if (this.gpgme_op_keylist_start(c1, pattern, secret ? 1 : 0)) {
        throw new Error("gpgme_op_keylist_start failed");
      }

      do {
        const key = new gpgme_key_t();
        const rv = this.gpgme_op_keylist_next(c1, key.address());
        if (rv & GPGMELib.GPG_ERR_EOF) {
          break;
        } else if (rv) {
          throw new Error("gpgme_op_keylist_next failed: " + rv);
        }

        if (key.contents.protocol == GPGMELib.GPGME_PROTOCOL_OpenPGP) {
          if (!keyFilterFunction || keyFilterFunction(key)) {
            const fpr = key.contents.fpr.readString();
            allFingerprints.push(fpr);
          }
        }
        this.gpgme_key_release(key);
        // eslint-disable-next-line no-constant-condition
      } while (true);

      if (this.gpgme_op_keylist_end(c1)) {
        throw new Error("gpgme_op_keylist_end failed");
      }

      this.gpgme_release(c1);

      for (const aFpr of allFingerprints) {
        const c2 = new gpgme_ctx_t();
        if (this.gpgme_new(c2.address())) {
          throw new Error("gpgme_new failed");
        }

        this.gpgme_set_armor(c2, 1);

        const data = new gpgme_data_t();
        let rv = this.gpgme_data_new(data.address());
        if (rv) {
          throw new Error("gpgme_op_keylist_next gpgme_data_new: " + rv);
        }

        rv = this.gpgme_op_export(
          c2,
          aFpr,
          secret ? GPGMELib.GPGME_EXPORT_MODE_SECRET : 0,
          data
        );
        if (rv) {
          throw new Error("gpgme_op_export gpgme_data_new: " + rv);
        }

        const result_len = new ctypes.size_t();
        const result_buf = this.gpgme_data_release_and_get_mem(
          data,
          result_len.address()
        );

        const keyData = ctypes.cast(
          result_buf,
          ctypes.char.array(result_len.value).ptr
        ).contents;

        resultMap.set(aFpr, keyData.readString());

        this.gpgme_free(result_buf);
        this.gpgme_release(c2);
      }
      return resultMap;
    },

    /**
     * List keys matching the given parameters, without exporting any key
     * material: only the fingerprint and the user IDs of each key.
     *
     * @param {string} pattern - A pattern given to GnuPG for listing keys.
     * @param {boolean} secret - If true, list secret keys instead of public
     *   keys.
     * @param {Function} keyFilterFunction - An optional test function called
     *   for each candidate key. Called with a {gpgme_key_t} parameter.
     *
     * @returns {object[]} - { fpr, emails, ownerTrust, uids } for each matching
     *   key. `emails` is the plain address list; `uids` carries each address
     *   with the validity gpg computed for it, which is a different answer from
     *   `ownerTrust`: declared versus computed.
     */
    listKeys(pattern, secret = false, keyFilterFunction = undefined) {
      const keys = [];

      const c1 = new gpgme_ctx_t();
      if (this.gpgme_new(c1.address())) {
        throw new Error("gpgme_new failed");
      }

      if (this.gpgme_op_keylist_start(c1, pattern, secret ? 1 : 0)) {
        throw new Error("gpgme_op_keylist_start failed");
      }

      do {
        const key = new gpgme_key_t();
        const rv = this.gpgme_op_keylist_next(c1, key.address());
        if (rv & GPGMELib.GPG_ERR_EOF) {
          break;
        } else if (rv) {
          throw new Error("gpgme_op_keylist_next failed: " + rv);
        }

        if (key.contents.protocol == GPGMELib.GPGME_PROTOCOL_OpenPGP) {
          if (!keyFilterFunction || keyFilterFunction(key)) {
            const emails = [];
            // Per user ID, alongside `emails` rather than replacing it. The two
            // are the same list of addresses, and only this one carries what
            // gpg computed about each: `validity` is the number a certification
            // moves, and it is what the strict gate asks for (Item 88c).
            //
            // A parallel array rather than a richer `emails`, because four
            // consumers read `emails` as a list of strings and a change there
            // would reach all of them for nothing.
            const uids = [];
            let nextUid = key.contents.uids;
            while (nextUid && !nextUid.isNull()) {
              const uidEmail = nextUid.contents.email;
              if (!uidEmail.isNull()) {
                const email = uidEmail.readString().toLowerCase();
                emails.push(email);
                uids.push({ email, validity: nextUid.contents.validity });
              }
              nextUid = nextUid.contents.next;
            }
            const subkeys = [];
            let nextSub = key.contents.subkeys;
            while (nextSub && !nextSub.isNull()) {
              const subFpr = nextSub.contents.fpr;
              subkeys.push({
                fpr: subFpr.isNull() ? "" : subFpr.readString().toUpperCase(),
                keyid: nextSub.contents.keyid.readString().toUpperCase(),
                bitfield: nextSub.contents.bitfield,
              });
              nextSub = nextSub.contents.next;
            }
            const fpr = key.contents.fpr.readString().toUpperCase();
            keys.push({
              fpr,
              // The low-order 64 bits of a v4 fingerprint, which is the key id.
              keyid: fpr.slice(-16),
              emails,
              bitfield: key.contents.bitfield,
              subkeys,
              // What the user has declared about this key, as opposed to what
              // its signatures prove. gpgme's validity values are the same six
              // numbers as `OpenPgpValidity`, so nothing has to be translated
              // between the two vocabularies -- which is why Item 88 can drive
              // gpg's own database instead of keeping a second copy of trust.
              ownerTrust: key.contents.owner_trust,
              uids,
            });
          }
        }
        this.gpgme_key_release(key);
        // eslint-disable-next-line no-constant-condition
      } while (true);

      if (this.gpgme_op_keylist_end(c1)) {
        throw new Error("gpgme_op_keylist_end failed");
      }

      this.gpgme_release(c1);
      return keys;
    },

    /**
     * Certify a key in GnuPG's own keyring (Item 88a).
     *
     * **Why this belongs here rather than in this build's ring.** gpg computes a
     * key's validity from the signatures *it* can see. A certification made
     * against a key that only this build holds is therefore invisible to the
     * engine that decides whether the key is good enough to encrypt to -- which
     * is why Item 88c could wire the gate and still leave certification with no
     * effect. Signing where the key lives needs no export, no import and no
     * trust-database nudge: gpg updates its own trust database as part of the
     * operation.
     *
     * `userid` is the address or the full user-ID string to certify, and an
     * empty value certifies every user ID, which is what gpg's own `--quick-sign-key`
     * does by default. Named rather than implied, because certifying every ID
     * on a key that carries several is a bigger statement than the caller may
     * intend.
     *
     * @param {string} signerFpr - Fingerprint of the key that signs.
     * @param {string} targetFpr - Fingerprint of the key being certified.
     * @param {string} [userid=""] - The user ID to certify; empty means all.
     * @returns {{ok: boolean, error?: integer}}
     */
    signKey(signerFpr, targetFpr, userid = "") {
      const signer = signerFpr.replace(/^0x/i, "").toUpperCase();
      const target = targetFpr.replace(/^0x/i, "").toUpperCase();
      if (!signer || !target) {
        return { ok: false };
      }

      const ctx = new gpgme_ctx_t();
      if (this.gpgme_new(ctx.address())) {
        throw new Error("gpgme_new failed");
      }

      let signerKey = null;
      let targetKey = null;
      try {
        signerKey = this._keyForFingerprint(signer);
        if (!signerKey) {
          // The signer has to be in gpg's own keyring for this to be gpg's
          // decision rather than ours; refusing is the honest answer.
          return { ok: false };
        }
        const added = this.gpgme_signers_add(ctx, signerKey);
        if (added) {
          return { ok: false, error: added };
        }

        targetKey = this._keyForFingerprint(target);
        if (!targetKey) {
          return { ok: false };
        }

        // gpg matches the user ID **exactly**, and an address is not a user ID:
        // the string on Carol's key is "Carol <carol@example.com>", so asking
        // for "carol@example.com" answers "No user ID". The address a caller
        // works from is therefore resolved to the string the key actually
        // carries, and an address that matches nothing certifies every ID --
        // which is what gpg's own `--quick-sign-key` does when given no uid.
        const uidText = this._uidFor(targetKey, userid);

        // expire 0: a certification that never expires, which is what the
        // internal path also produces and what a user signing a key expects.
        // flags 0: gpg's defaults, as `--quick-sign-key` uses.
        //
        // A NULL pointer, not an empty string, is how gpgme is told "every user
        // ID": an empty C string is a uid that matches nothing. Passing "" is
        // what produced "No user ID" on the first run of this.
        const rv = this.gpgme_op_keysign(
          ctx,
          targetKey,
          uidText ? ctypes.char.array()(uidText) : ctypes.char.ptr(),
          0,
          0
        );
        return rv ? { ok: false, error: rv } : { ok: true };
      } finally {
        if (targetKey) {
          this.gpgme_key_release(targetKey);
        }
        if (signerKey) {
          this.gpgme_key_release(signerKey);
        }
        this.gpgme_signers_clear(ctx);
        this.gpgme_release(ctx);
      }
    },

    /**
     * The user-ID string on a key that a caller's `userid` refers to, or null
     * for "every user ID".
     *
     * gpg compares user IDs exactly, so an address has to be translated into
     * the string the key carries. An exact match wins; otherwise the first user
     * ID containing the address as its `email` wins; otherwise null.
     *
     * @param {gpgme_key_t} keyHandle
     * @param {string} userid
     * @returns {?string}
     */
    _uidFor(keyHandle, userid) {
      const wanted = (userid ?? "").trim();
      if (!wanted) {
        return null;
      }
      const wantedLower = wanted.toLowerCase();
      let firstByAddress = null;
      let uid = keyHandle.contents.uids;
      while (uid && !uid.isNull()) {
        const text = uid.contents.uid.isNull()
          ? ""
          : uid.contents.uid.readString();
        const email = uid.contents.email.isNull()
          ? ""
          : uid.contents.email.readString().toLowerCase();
        if (text == wanted) {
          return text;
        }
        if (!firstByAddress && email && email == wantedLower) {
          firstByAddress = text;
        }
        uid = uid.contents.next;
      }
      return firstByAddress;
    },

    /**
     * A released-by-the-caller gpgme key handle for one fingerprint, or null.
     *
     * Picked by fingerprint from a listing rather than taken as the only result:
     * the pattern is a search, so it can match a subkey or a user ID containing
     * the string.
     *
     * @param {string} fpr - Upper-case primary fingerprint.
     * @returns {?gpgme_key_t}
     */
    _keyForFingerprint(fpr) {
      const ctx = new gpgme_ctx_t();
      if (this.gpgme_new(ctx.address())) {
        throw new Error("gpgme_new failed");
      }
      try {
        if (this.gpgme_op_keylist_start(ctx, fpr, 0)) {
          return null;
        }
        while (true) {
          const key = new gpgme_key_t();
          const rv = this.gpgme_op_keylist_next(ctx, key.address());
          if (rv & GPGMELib.GPG_ERR_EOF) {
            return null;
          }
          if (rv) {
            return null;
          }
          const got = key.contents.fpr.isNull()
            ? ""
            : key.contents.fpr.readString().toUpperCase();
          if (got == fpr) {
            return key;
          }
          this.gpgme_key_release(key);
        }
      } finally {
        this.gpgme_op_keylist_end(ctx);
        this.gpgme_release(ctx);
      }
    },

    gpgme_check_version: libgpgme.declare(
      "gpgme_check_version",
      abi,
      ctypes.char.ptr,
      ctypes.char.ptr
    ),

    gpgme_set_engine_info: libgpgme.declare(
      "gpgme_set_engine_info",
      abi,
      gpgme_error_t,
      gpgme_protocol_t,
      ctypes.char.ptr,
      ctypes.char.ptr
    ),

    gpgme_new: libgpgme.declare("gpgme_new", abi, gpgme_error_t, gpgme_ctx_t),

    gpgme_release: libgpgme.declare(
      "gpgme_release",
      abi,
      ctypes.void_t,
      gpgme_ctx_t
    ),

    gpgme_key_release: libgpgme.declare(
      "gpgme_key_release",
      abi,
      ctypes.void_t,
      gpgme_key_t
    ),

    gpgme_op_keylist_start: libgpgme.declare(
      "gpgme_op_keylist_start",
      abi,
      gpgme_error_t,
      gpgme_ctx_t,
      ctypes.char.ptr,
      ctypes.int
    ),

    gpgme_op_keylist_next: libgpgme.declare(
      "gpgme_op_keylist_next",
      abi,
      gpgme_error_t,
      gpgme_ctx_t,
      gpgme_key_t.ptr
    ),

    gpgme_op_keylist_end: libgpgme.declare(
      "gpgme_op_keylist_end",
      abi,
      gpgme_error_t,
      gpgme_ctx_t
    ),

    // Certifying a key that GnuPG holds (Item 88a). Declared here because gpg
    // computes validity from the signatures in *its* keyring: a signature made
    // against a key that only this build holds is invisible to it, so the
    // operation has to happen where the key lives.
    //
    // `gpgme_op_keysign(ctx, key, userid, expire, flags)` returns
    // `gpgme_error_t`, and `gpgme_signers_add` supplies the key that signs.
    // Both are in the shipped library -- measured with `nm -D` against
    // libgpgme.so.11, GPGME_1.1 -- which is the same finding as Item 95: the
    // symbol was there and only the declaration was missing.
    gpgme_op_keysign: libgpgme.declare(
      "gpgme_op_keysign",
      abi,
      gpgme_error_t,
      gpgme_ctx_t,
      // `gpgme_key_t` is already a pointer; the struct is `_gpgme_key`, so the
      // bare `gpgme_key_t` is the parameter type gpgme expects here.
      gpgme_key_t,
      ctypes.char.ptr,
      ctypes.unsigned_long,
      ctypes.unsigned_int
    ),

    // `gpgme_signers_add` already exists further down this table -- it was
    // bound for Item 88's ownertrust work -- so only `gpgme_signers_clear` is
    // new here. A duplicate key in this object literal is a lint error, and it
    // was my first version's mistake.
    gpgme_signers_clear: libgpgme.declare(
      "gpgme_signers_clear",
      abi,
      ctypes.void_t,
      gpgme_ctx_t
    ),

    gpgme_op_export: libgpgme.declare(
      "gpgme_op_export",
      abi,
      gpgme_error_t,
      gpgme_ctx_t,
      ctypes.char.ptr,
      gpgme_export_mode_t,
      gpgme_data_t
    ),

    gpgme_set_armor: libgpgme.declare(
      "gpgme_set_armor",
      abi,
      ctypes.void_t,
      gpgme_ctx_t,
      ctypes.int
    ),

    gpgme_data_new: libgpgme.declare(
      "gpgme_data_new",
      abi,
      gpgme_error_t,
      gpgme_data_t.ptr
    ),

    gpgme_data_release: libgpgme.declare(
      "gpgme_data_release",
      abi,
      ctypes.void_t,
      gpgme_data_t
    ),

    gpgme_data_release_and_get_mem: libgpgme.declare(
      "gpgme_data_release_and_get_mem",
      abi,
      ctypes.char.ptr,
      gpgme_data_t,
      ctypes.size_t.ptr
    ),

    gpgme_free: libgpgme.declare(
      "gpgme_free",
      abi,
      ctypes.void_t,
      ctypes.void_t.ptr
    ),

    gpgme_op_decrypt_ext: libgpgme.declare(
      "gpgme_op_decrypt_ext",
      abi,
      gpgme_error_t,
      gpgme_ctx_t,
      gpgme_decrypt_flags_t,
      gpgme_data_t,
      gpgme_data_t
    ),

    gpgme_data_new_from_mem: libgpgme.declare(
      "gpgme_data_new_from_mem",
      abi,
      gpgme_error_t,
      gpgme_data_t.ptr,
      ctypes.char.ptr,
      ctypes.size_t,
      ctypes.int
    ),

    gpgme_data_read: libgpgme.declare(
      "gpgme_data_read",
      abi,
      ctypes.ssize_t,
      gpgme_data_t,
      ctypes.void_t.ptr,
      ctypes.size_t
    ),

    gpgme_data_rewind: libgpgme.declare(
      "gpgme_data_rewind",
      abi,
      gpgme_error_t,
      gpgme_data_t
    ),

    gpgme_data_get_encoding: libgpgme.declare(
      "gpgme_data_get_encoding",
      abi,
      gpgme_data_encoding_t,
      gpgme_data_t
    ),

    gpgme_data_set_encoding: libgpgme.declare(
      "gpgme_data_set_encoding",
      abi,
      gpgme_error_t,
      gpgme_data_t,
      gpgme_data_encoding_t
    ),

    // Text for an error code, as gpgme words it. Returns a static string, so
    // there is nothing to free. Bound because a bare numeric code is not
    // something a user can act on: "No pinentry" says what to fix, and 85 does
    // not. Item 24 measured that the code itself was being discarded entirely.
    gpgme_strerror: libgpgme.declare(
      "gpgme_strerror",
      abi,
      ctypes.char.ptr,
      gpgme_error_t
    ),

    gpgme_op_sign: libgpgme.declare(
      "gpgme_op_sign",
      abi,
      gpgme_error_t,
      gpgme_ctx_t,
      gpgme_data_t,
      gpgme_data_t,
      gpgme_sig_mode_t
    ),

    gpgme_op_encrypt: libgpgme.declare(
      "gpgme_op_encrypt",
      abi,
      gpgme_error_t,
      gpgme_ctx_t,
      gpgme_key_t.ptr,
      gpgme_encrypt_flags_t,
      gpgme_data_t,
      gpgme_data_t
    ),

    gpgme_op_encrypt_sign: libgpgme.declare(
      "gpgme_op_encrypt_sign",
      abi,
      gpgme_error_t,
      gpgme_ctx_t,
      gpgme_key_t.ptr,
      gpgme_encrypt_flags_t,
      gpgme_data_t,
      gpgme_data_t
    ),

    gpgme_op_import: libgpgme.declare(
      "gpgme_op_import",
      abi,
      gpgme_error_t,
      gpgme_ctx_t,
      gpgme_data_t
    ),

    gpgme_signers_add: libgpgme.declare(
      "gpgme_signers_add",
      abi,
      gpgme_error_t,
      gpgme_ctx_t,
      gpgme_key_t
    ),

    gpgme_get_key: libgpgme.declare(
      "gpgme_get_key",
      abi,
      gpgme_error_t,
      gpgme_ctx_t,
      ctypes.char.ptr,
      gpgme_key_t.ptr,
      ctypes.int
    ),

    gpgme_set_textmode: libgpgme.declare(
      "gpgme_set_textmode",
      abi,
      ctypes.void_t,
      gpgme_ctx_t,
      ctypes.int
    ),

    gpgme_error_t,
    gpgme_ctx_t,
    gpgme_data_t,
    gpgme_validity_t,
    gpgme_keylist_mode_t,
    gpgme_pubkey_algo_t,
    gpgme_sig_notation_flags_t,
    gpgme_export_mode_t,
    gpgme_decrypt_flags_t,
    gpgme_data_encoding_t,

    gpgme_protocol_t,
    gpgme_subkey_t,
    gpgme_sig_notation_t,
    gpgme_key_sig_t,
    gpgme_tofu_info_t,
    gpgme_user_id_t,
    gpgme_key_t,

    GPG_ERR_NO_ERROR: 0x00000000,
    GPG_ERR_EOF: 16383,

    // gpgme packs a source in the high byte and an error code in the low 24
    // bits. Both numbers are needed: the code says what happened, the source
    // says where. Measured on gpgme 1.18 with gpg 2.4.4, cancelling at the
    // pinentry returns code 99 (GPG_ERR_CANCELED) from source 5
    // (GPG_ERR_SOURCE_PINENTRY), packed as 83886179.
    //
    // The distinction matters because the design requires a cancelled prompt to
    // be reported as a cancellation and not as a failure: before this the two
    // arrived identical, and "Signing was cancelled" was unreachable.
    GPG_ERR_SOURCE_SHIFT: 24,
    GPG_ERR_CODE_MASK: 0xffffff,
    GPG_ERR_SOURCE_UNKNOWN: 0,
    GPG_ERR_SOURCE_GPGME: 1,
    GPG_ERR_SOURCE_GPG: 2,
    GPG_ERR_SOURCE_GPGSM: 3,
    GPG_ERR_SOURCE_GPGAGENT: 4,
    GPG_ERR_SOURCE_PINENTRY: 5,
    GPG_ERR_CANCELED: 99,
    GPGME_PROTOCOL_OpenPGP: 0,
    GPGME_EXPORT_MODE_SECRET: 16,
    GPGME_DECRYPT_UNWRAP: 128,
    GPGME_DATA_ENCODING_ARMOR: 3,
    GPGME_SIG_MODE_DETACH: 1,
    GPGME_SIG_MODE_NORMAL: 0,
    GPGME_ENCRYPT_ALWAYS_TRUST: 1,
    GPGME_ENCRYPT_NO_COMPRESS: 16,

    // Order verified against gpgme 1.18 behaviour: an ed25519 primary that can
    // sign and certify and holds a secret reports 224 (32 + 64 + 128), and a
    // cv25519 encryption subkey holding a secret reports 144 (16 + 128).
    gpgme_key_t_revoked: 1,
    gpgme_key_t_expired: 2,
    gpgme_key_t_disabled: 4,
    gpgme_key_t_invalid: 8,
    gpgme_key_t_can_encrypt: 16,
    gpgme_key_t_can_sign: 32,
    gpgme_key_t_can_certify: 64,
    gpgme_key_t_has_secret: 128,
    gpgme_subkey_can_sign: 32,
  };
}
