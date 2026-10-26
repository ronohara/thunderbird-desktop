/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

import { MailStringUtils } from "resource:///modules/MailStringUtils.sys.mjs";
// The constants *namespace*, imported directly rather than through the
// `defineESModuleGetters` block below: as a lazy getter this resolved to
// undefined and every validity comparison threw. Fifth occurrence of that
// failure in this tree, and the reachability assertion in
// test_validityVocabulary.js is what caught it.
import * as OpenPgpConstants from "chrome://openpgp/content/modules/constants.sys.mjs";

const lazy = {};
ChromeUtils.defineESModuleGetters(lazy, {
  CollectedKeysDB: "chrome://openpgp/content/modules/CollectedKeysDB.sys.mjs",
  OpenPGPAlias: "chrome://openpgp/content/modules/OpenPGPAlias.sys.mjs",
  EnigmailArmor: "chrome://openpgp/content/modules/armor.sys.mjs",
  EnigmailFuncs: "chrome://openpgp/content/modules/funcs.sys.mjs",
  EnigmailTrust: "chrome://openpgp/content/modules/trust.sys.mjs",
  EnigmailDialog: "chrome://openpgp/content/modules/dialog.sys.mjs",
  EnigmailWindows: "chrome://openpgp/content/modules/windows.sys.mjs",
  GPGME: "chrome://openpgp/content/modules/GPGME.sys.mjs",
  EnigmailKeyObj: "chrome://openpgp/content/modules/keyObj.sys.mjs",
  PgpSqliteDb2: "chrome://openpgp/content/modules/sqliteDb.sys.mjs",
  RNP: "chrome://openpgp/content/modules/RNP.sys.mjs",
});
ChromeUtils.defineLazyGetter(lazy, "log", () => {
  return console.createInstance({
    prefix: "openpgp",
    maxLogLevel: "Warn",
    maxLogLevelPref: "openpgp.loglevel",
  });
});
ChromeUtils.defineLazyGetter(lazy, "l10n", () => {
  return new Localization(["messenger/openpgp/openpgp.ftl"]);
});

import { openLinkExternally } from "resource:///modules/LinkHelper.sys.mjs";

/**
 * @typedef KeyList
 * @property {EnigmailKeyObj[]} keyList - The keys, in the order they were loaded.
 * @property {object[]} keySortList - Used for quickly sorting the keys.
 * @property {string} keySortList[].userId - User ID in lower case.
 * @property {string} keySortList[].keyId - Key ID.
 * @property {integer} keySortList[].keyNum - Index of the key in keyList.
 */

/** @type {KeyList} */
let gKeyListObj = null;
let gKeyIndex = new Map();
let gSubkeyIndex = new Map();
let gLoadingKeys = false;

export var EnigmailKeyRing = {
  _initialized: false,

  init() {
    if (this._initialized) {
      return;
    }
    this._initialized = true;
    this.clearCache();
  },

  /**
   * Get the complete list of all public keys, optionally sorted by a column.
   *
   * @param {?window} win - Parent window for displaying error messages.
   * @param {string} sortColumn - The column name for sorting. One of:
   *   userid, keyid, keyidshort, fpr, keytype, validity, trust, created, expiry.
   * @param {1|-1} sortDirection - Sort direction: 1 = ascending / -1 = descending.
   * @returns {KeyList} The key list and its sort index. See {KeyList}.
   */
  getAllKeys(win, sortColumn, sortDirection) {
    if (!gKeyListObj) {
      // Nothing has populated the cache yet; start from an empty one rather
      // than dereferencing null. Callers may reach this before any UI has.
      this.clearCache();
    }
    if (gKeyListObj.keySortList.length === 0) {
      loadKeyList(win, sortColumn, sortDirection);
    } else if (sortColumn) {
      gKeyListObj.keySortList.sort(
        getSortFunction(sortColumn.toLowerCase(), gKeyListObj, sortDirection)
      );
    }
    return gKeyListObj;
  },

  /**
   * Get 1st key object that matches a given key ID or subkey ID.
   *
   * @param {string} keyId - Key ID with 16 characters (preferred) or 8 characters),
   *  or fingerprint (40 or 32 characters). Optionally preceded with "0x".
   * @param {boolean} [noLoadKeys=false] - Do not try to load the key list first.
   * @returns {?EnigmailKeyObj}
   */
  getKeyById(keyId, noLoadKeys = false) {
    if (!keyId) {
      return null;
    }

    if (keyId.search(/^0x/) === 0) {
      keyId = keyId.substr(2);
    }
    keyId = keyId.toUpperCase();

    if (!noLoadKeys || this.getCacheEmpty()) {
      this.getAllKeys(); // ensure keylist is loaded;
    }

    // GnuPG first, and the ring second, for a key GnuPG holds.
    //
    // The reverse order is what produced the 18 October false expiry: the
    // profile held a copy that was correct in fingerprint and wrong in
    // revision, and because the ring index was consulted first, Thunderbird
    // reported the 2018 self-signature as current while GnuPG reported none.
    // A stale copy must not be able to outrank the live key, and the only way
    // to guarantee that is to stop asking it first.
    //
    // This is a precedence rule, not a merge. Two revisions of one certificate
    // are not combined; GnuPG's is used and the copy is dead weight that Stage
    // 7 offers to remove.
    const fromGnuPG = this.getGnuPgKeyById(keyId);
    if (fromGnuPG) {
      return fromGnuPG;
    }

    let keyObj = gKeyIndex.get(keyId);

    if (keyObj === undefined) {
      keyObj = gSubkeyIndex.get(keyId);
    }

    return keyObj === undefined ? null : keyObj;
  },

  isSubkeyId(keyId) {
    if (!keyId) {
      throw new Error("keyId parameter not set");
    }

    keyId = keyId.replace(/^0x/, "").toUpperCase();

    const keyObj = gSubkeyIndex.get(keyId);

    return keyObj !== undefined;
  },

  /**
   * Get all key objects that match a given email address.
   *
   * @param {string} email - An email address to match against all UIDs
   *   of the keys. An empty string will return no result.
   * @param {boolean} [onlyValidUid=true] - If true (default), invalid (e.g. revoked)
   *   UIDs are not matched.
   * @param {boolean} [allowExpired=false] - If true, expired keys are matched.
   * @returns {EnigmailKeyObj[]} the found keys.
   */
  getKeysByEmail(email, onlyValidUid = true, allowExpired = false) {
    const res = [];
    if (!email) {
      return res;
    }

    this.getAllKeys(); // ensure keylist is loaded;
    email = email.toLowerCase();

    for (const key of gKeyListObj.keyList) {
      if (!allowExpired && key.keyTrust == "e") {
        continue;
      }

      for (const userId of key.userIds) {
        if (userId.type !== "uid") {
          continue;
        }

        // Skip test if it's expired. If expired isn't allowed, we
        // already skipped it above.
        if (
          onlyValidUid &&
          userId.keyTrust != "e" &&
          lazy.EnigmailTrust.isInvalid(userId.keyTrust)
        ) {
          continue;
        }

        if (
          lazy.EnigmailFuncs.getEmailFromUserID(userId.userId).toLowerCase() ===
          email
        ) {
          res.push(key);
          break;
        }
      }
    }
    return res;
  },

  emailAddressesWithSecretKey: null,

  /**
   * Keys that exist only in the external GnuPG keyring, parsed from the
   * armored public blocks GnuPG exports.
   *
   * Nothing here is ever written to the profile: RNP.getKeyListFromKeyBlockImpl
   * imports into a temporary FFI context that it destroys before returning.
   * The parsed key objects are kept in memory for the session so that lookups
   * do not re-parse on every keystroke, and so that the synchronous
   * getKeyById() can find them.
   *
   * Keyed by fingerprint. Never holds secret material, because GnuPG is never
   * asked for any.
   */
  gnuPgKeys: new Map(),

  /**
   * Key id (16 hex characters) -> fingerprint, so getKeyById() can resolve a
   * key id to a transient key without scanning.
   */
  gnuPgKeyIds: new Map(),

  /**
   * Fingerprint -> ASCII armored public key block, for the transient keys.
   * Needed where a key's material is required rather than its parsed form,
   * for example the Autocrypt header.
   */
  gnuPgKeyBlocks: new Map(),

  /**
   * Addresses whose GnuPG keys have already been parsed this session.
   */
  gnuPgLoadedFor: new Set(),
  /** Whether the whole keyring has been read by `loadAllGnuPgKeys()`. */
  gnuPgKeyringLoaded: false,

  /**
   * Parse the external GnuPG keys for an address into the session cache.
   *
   * @param {string} emailAddr - Address to look up.
   * @returns {boolean} whether the lookup ran (not whether it found anything).
   */
  async loadGnuPgKeysForEmail(emailAddr) {
    if (
      !emailAddr ||
      !emailAddr.includes("@") ||
      !Services.prefs.getBoolPref("mail.openpgp.allow_external_gnupg") ||
      !Services.prefs.getBoolPref("mail.openpgp.fetch_pubkeys_from_gnupg")
    ) {
      return false;
    }

    const key = emailAddr.toLowerCase();
    if (this.gnuPgLoadedFor.has(key)) {
      return true;
    }
    if (!lazy.GPGME.init()) {
      return false;
    }

    // Marked before parsing: the map is consulted by getKeyById(), and a
    // re-entrant lookup during parsing must not loop.
    this.gnuPgLoadedFor.add(key);

    let keysFromGnuPGMap;
    try {
      keysFromGnuPGMap = lazy.GPGME.getPublicKeysForEmail(emailAddr);
    } catch (ex) {
      lazy.log.warn(`Reading GnuPG keys for ${emailAddr} failed`, ex);
      return true;
    }

    for (const [fpr, keyBlock] of keysFromGnuPGMap) {
      const normalized = fpr.toUpperCase();
      if (this.gnuPgKeys.has(normalized)) {
        continue;
      }
      let parsed;
      try {
        // A temporary FFI context: destroyed inside the call, so this key is
        // never added to RNP's own store.
        parsed = await lazy.RNP.getKeyListFromKeyBlockImpl(keyBlock);
      } catch (ex) {
        lazy.log.warn(`Parsing the GnuPG key ${fpr} failed`, ex);
        continue;
      }
      if (!parsed?.length) {
        continue;
      }
      const keyObj = new lazy.EnigmailKeyObj(parsed[0]);
      this.gnuPgKeys.set(normalized, keyObj);
      this.gnuPgKeyBlocks.set(normalized, keyBlock);
      for (const id of [keyObj.keyId, keyObj.fpr]) {
        if (id) {
          this.gnuPgKeyIds.set(id.toUpperCase(), normalized);
        }
      }
      for (const sub of keyObj.subKeys) {
        if (sub.keyId) {
          this.gnuPgKeyIds.set(sub.keyId.toUpperCase(), normalized);
        }
      }
      await this._autoAcceptGnuPGKey(keyObj);
    }
    return true;
  },

  /**
   * Record an acceptance decision for a key that came from the user's GnuPG
   * keyring.
   *
   * Thunderbird refuses to encrypt to a key until it holds an acceptance
   * decision for it. With the external GnuPG backend the keyring itself is the
   * trust store: the user put the key there, or their own gpg decided it was
   * genuine. So the same trust basis applies, and a key found there is
   * accepted as "unverified" — not "verified", which would claim a
   * fingerprint checked in person.
   *
   * An existing decision is never overridden, so an explicit rejection stands.
   *
   * @param {EnigmailKeyObj} keyObj - The transient key.
   */
  async _autoAcceptGnuPGKey(keyObj) {
    const existing = await lazy.PgpSqliteDb2.getFingerprintAcceptance(
      null,
      keyObj.fpr
    );
    if (existing) {
      // "" means undecided-but-present; anything else is a user decision.
      return;
    }
    const emails = keyObj.userIds
      .filter(uid => uid.type == "uid")
      .map(uid => lazy.EnigmailFuncs.getEmailFromUserID(uid.userId))
      .filter(email => email?.includes("@"));
    if (!emails.length) {
      return;
    }
    try {
      await lazy.PgpSqliteDb2.updateAcceptance(
        keyObj.fpr,
        emails,
        "unverified"
      );
    } catch (ex) {
      lazy.log.warn(`Recording acceptance for ${keyObj.fpr} failed`, ex);
    }
  },

  /**
   * Parse the external GnuPG key for a key id or fingerprint into the session
   * cache. Used when the caller has an identifier rather than an address, for
   * example the identity's configured OpenPGP key id.
   *
   * @param {string} keyId - Key id or fingerprint.
   */
  async loadGnuPgKeyById(keyId) {
    if (!keyId) {
      return;
    }
    if (!Services.prefs.getBoolPref("mail.openpgp.allow_external_gnupg")) {
      return;
    }
    if (this.getGnuPgKeyById(keyId)) {
      return;
    }
    if (!lazy.GPGME.init()) {
      return;
    }

    let keys;
    try {
      keys = lazy.GPGME.getPublicKeysForId(keyId.replace(/^0x/i, ""));
    } catch (ex) {
      lazy.log.warn(`Reading the GnuPG key ${keyId} failed`, ex);
      return;
    }

    for (const [fpr, keyBlock] of keys) {
      const normalized = fpr.toUpperCase();
      if (this.gnuPgKeys.has(normalized)) {
        continue;
      }
      let parsed;
      try {
        parsed = await lazy.RNP.getKeyListFromKeyBlockImpl(keyBlock);
      } catch (ex) {
        lazy.log.warn(`Parsing the GnuPG key ${fpr} failed`, ex);
        continue;
      }
      if (!parsed?.length) {
        continue;
      }
      const keyObj = new lazy.EnigmailKeyObj(parsed[0]);
      this.gnuPgKeys.set(normalized, keyObj);
      for (const id of [keyObj.keyId, keyObj.fpr]) {
        if (id) {
          this.gnuPgKeyIds.set(id.toUpperCase(), normalized);
        }
      }
      for (const sub of keyObj.subKeys) {
        if (sub.keyId) {
          this.gnuPgKeyIds.set(sub.keyId.toUpperCase(), normalized);
        }
      }
    }
  },

  /**
   * Keys to consider for an address: the profile ring plus the transient
   * GnuPG keys.
   *
   * Every recipient check has to use this rather than getAllKeys(). Missing a
   * path here produces a split where one screen reports the key as usable and
   * the next step refuses to send.
   *
   * @param {string} emailAddr - Address whose GnuPG keys should be included.
   * @returns {EnigmailKeyObj[]} Candidate keys, de-duplicated by fingerprint.
   */
  async getCandidateKeysForEmail(emailAddr) {
    await this.loadGnuPgKeysForEmail(emailAddr);

    // For a shared fingerprint the GnuPG revision is the one that survives.
    // Pushing the ring keys first and skipping a transient key whose
    // fingerprint was already present did the opposite: the *copy* was kept
    // and the live key discarded, which is Item 14's defect one level up, in
    // the list every recipient check reads.
    //
    // The de-duplication itself stays. The point is one answer per
    // fingerprint, and that answer should be GnuPG's.
    const fromGnuPG = new Map();
    for (const keyObj of this.getGnuPgKeysForEmail(emailAddr)) {
      fromGnuPG.set(keyObj.fpr.toUpperCase(), keyObj);
    }

    const keys = [];
    for (const keyObj of this.getAllKeys(null, null).keyList) {
      const fpr = keyObj.fpr.toUpperCase();
      if (fromGnuPG.has(fpr)) {
        continue;
      }
      keys.push(keyObj);
    }
    keys.push(...fromGnuPG.values());
    return keys;
  },

  /**
   * Parse every key in the GnuPG keyring into the transient cache.
   *
   * The whole-keyring counterpart of `loadGnuPgKeysForEmail()`, which needs an
   * address and is therefore no use to a dialog that lists keys. Guarded by a
   * flag rather than by `gnuPgLoadedFor`, because that set is keyed by
   * address; `clearGnuPgKeyCache()` resets both.
   *
   * Nothing is imported: each block is parsed in a temporary FFI context and
   * the key object is kept for the session, which is the same treatment a
   * per-address lookup gives.
   *
   * @returns {Promise<boolean>} whether the keyring was read.
   */
  async loadAllGnuPgKeys() {
    if (
      !Services.prefs.getBoolPref("mail.openpgp.allow_external_gnupg") ||
      !Services.prefs.getBoolPref("mail.openpgp.fetch_pubkeys_from_gnupg")
    ) {
      return false;
    }
    if (this.gnuPgKeyringLoaded) {
      return true;
    }
    if (!lazy.GPGME.init()) {
      return false;
    }
    this.gnuPgKeyringLoaded = true;

    let blocks;
    try {
      blocks = lazy.GPGME.getPublicKeysForKeyring();
    } catch (ex) {
      lazy.log.warn("Reading the GnuPG keyring failed", ex);
      return true;
    }

    for (const [fpr, keyBlock] of blocks) {
      const normalized = fpr.toUpperCase();
      if (this.gnuPgKeys.has(normalized)) {
        continue;
      }
      let parsed;
      try {
        parsed = await lazy.RNP.getKeyListFromKeyBlockImpl(keyBlock);
      } catch (ex) {
        lazy.log.warn(`Parsing the GnuPG key ${fpr} failed`, ex);
        continue;
      }
      if (!parsed?.length) {
        continue;
      }
      const keyObj = new lazy.EnigmailKeyObj(parsed[0]);
      this.gnuPgKeys.set(normalized, keyObj);
      this.gnuPgKeyBlocks.set(normalized, keyBlock);
      for (const id of [keyObj.keyId, keyObj.fpr]) {
        if (id) {
          this.gnuPgKeyIds.set(id.toUpperCase(), normalized);
        }
      }
      for (const sub of keyObj.subKeys) {
        if (sub.keyId) {
          this.gnuPgKeyIds.set(sub.keyId.toUpperCase(), normalized);
        }
      }
    }
    return true;
  },

  /**
   * Whether GnuPG is where this key lives, rather than the profile.
   *
   * The manager asks before offering an operation whose target is the profile
   * ring -- deleting, backing up, changing a passphrase -- because the key on
   * screen is GnuPG's public copy and those operations would either fail
   * quietly or act on something else.
   *
   * @param {EnigmailKeyObj|string} key - A key object, or a key id or
   *   fingerprint.
   * @returns {boolean}
   */
  isExternalKey(key) {
    const id = typeof key == "string" ? key : key?.keyId;
    return !!this.getGnuPgKeyById(id);
  },

  /**
   * The whole key list as the Key Manager shows it: the profile ring, plus
   * every key GnuPG holds.
   *
   * Kept separate from `getAllKeys()` on purpose. That one returns the global
   * ring cache, which dozens of callers read -- the composer's key assistant,
   * the settings pages, every recipient lookup -- and merging external keys
   * into it would put GnuPG's keys into all of them. The manager is the one
   * dialog whose job is to show where keys live, so it is the one that asks.
   *
   * A fingerprint in both stores appears once, as GnuPG's revision, which is
   * the same precedence `getKeyById()` applies and for the same reason: a
   * stale profile copy must not outrank the live key.
   *
   * @param {?window} win - Parent window, for the ring's own loading path.
   * @param {string} sortColumn - See `getAllKeys()`.
   * @param {1|-1} sortDirection - Sort direction.
   * @returns {Promise<object>} `{keyList, keySortList}`, the same shape
   *   `getAllKeys()` returns.
   */
  async getManagerKeyList(win, sortColumn, sortDirection) {
    // The ring first: it sets the global cache up, and its loader is
    // synchronous against that cache.
    this.getAllKeys(win, sortColumn, sortDirection);
    const ringKeys = gKeyListObj.keyList;

    await this.loadAllGnuPgKeys();

    const byFpr = new Map();
    for (const keyObj of ringKeys) {
      byFpr.set(keyObj.fpr.toUpperCase(), keyObj);
    }
    for (const [fpr, keyObj] of this.gnuPgKeys) {
      byFpr.set(fpr, keyObj);
    }

    const keyList = [...byFpr.values()];
    const keySortList = keyList.map((keyObj, i) => ({
      userId: keyObj.userId ? keyObj.userId.toLowerCase() : "",
      keyId: keyObj.keyId,
      fpr: keyObj.fpr,
      keyNum: i,
    }));

    // The sort functions index into `keyList` by `keyNum`, so the object this
    // is given only has to hold the list.
    const column = typeof sortColumn == "string" ? sortColumn : "userid";
    keySortList.sort(
      getSortFunction(column.toLowerCase(), { keyList }, sortDirection)
    );

    return { keyList, keySortList };
  },

  /**
   * Transient keys from the cache that match an address.
   *
   * @param {string} emailAddr - Address to look up.
   * @returns {EnigmailKeyObj[]} Matching keys, possibly empty.
   */
  getGnuPgKeysForEmail(emailAddr) {
    const wanted = emailAddr?.toLowerCase();
    if (!wanted) {
      return [];
    }
    const res = [];
    for (const key of this.gnuPgKeys.values()) {
      if (
        key.userIds?.some(
          uid =>
            uid.type == "uid" &&
            lazy.EnigmailFuncs.getEmailFromUserID(uid.userId).toLowerCase() ==
              wanted
        )
      ) {
        res.push(key);
      }
    }
    return res;
  },

  /**
   * Look a transient GnuPG key up by key id or fingerprint.
   *
   * @param {string} keyId - Key id or fingerprint, optionally 0x-prefixed.
   * @returns {?EnigmailKeyObj}
   */
  getGnuPgKeyById(keyId) {
    if (!keyId) {
      return null;
    }
    const id = keyId.replace(/^0x/i, "").toUpperCase();
    const fpr =
      this.gnuPgKeyIds.get(id) ?? (this.gnuPgKeys.has(id) ? id : null);
    return fpr ? (this.gnuPgKeys.get(fpr) ?? null) : null;
  },

  /**
   * Where GnuPG keeps the keyring this profile is reading.
   *
   * For display only: the Key Assistant names the source of a key, and "GnuPG
   * keyring" alone does not say which one when someone runs several. Never
   * used to open anything.
   *
   * @returns {string} The directory, or the string a user recognizes when
   *   `GNUPGHOME` is unset.
   */
  getGnuPgKeyringPath() {
    if (Services.env.exists("GNUPGHOME")) {
      return Services.env.get("GNUPGHOME");
    }
    // gpg's own default. Named rather than resolved: reading the home
    // directory of the process to form a guess would be worse than saying
    // what gpg itself would use.
    return "~/.gnupg";
  },

  /**
   * Drop the transient cache, so the next lookup re-reads GnuPG.
   */
  clearGnuPgKeyCache() {
    this.gnuPgKeys.clear();
    this.gnuPgKeyIds.clear();
    this.gnuPgKeyBlocks.clear();
    this.gnuPgLoadedFor.clear();
    this.gnuPgKeyringLoaded = false;
  },

  /**
   * Fingerprints of keys in the external GnuPG keyring that hold a secret key.
   *
   * @param {string} [emailAddr] - Restrict to keys with a matching user ID.
   * @returns {?Set<string>} uppercase fingerprints, or null when external
   *   GnuPG is not in use or unreadable.
   */
  _getGnuPgSecretFingerprints(emailAddr) {
    if (!Services.prefs.getBoolPref("mail.openpgp.allow_external_gnupg")) {
      return null;
    }
    if (!lazy.GPGME.init()) {
      return null;
    }
    try {
      const fprs = lazy.GPGME.getSecretKeyFingerprintsForEmail(emailAddr);
      return new Set(fprs.map(fpr => fpr.toUpperCase()));
    } catch (ex) {
      lazy.log.warn("Reading secret keys from GnuPG failed", ex);
      return null;
    }
  },

  async _populateEmailHasSecretKeyCache() {
    this.getAllKeys(); // ensure keylist is loaded;
    const gnuPgSecretFprs = this._getGnuPgSecretFingerprints();
    const emailAddressesWithSecretKey = new Set();

    // Addresses covered by a secret key in GnuPG, whether or not the public
    // part has been imported into the profile ring yet.
    if (
      Services.prefs.getBoolPref("mail.openpgp.allow_external_gnupg") &&
      lazy.GPGME.init()
    ) {
      try {
        for (const key of lazy.GPGME.getSecretKeysForEmail()) {
          for (const email of key.emails) {
            emailAddressesWithSecretKey.add(email);
          }
        }
      } catch (ex) {
        lazy.log.warn("Reading secret keys from GnuPG failed", ex);
      }
    }
    for (const key of gKeyListObj.keyList) {
      const secretInGnuPG = gnuPgSecretFprs?.has(key.fpr.toUpperCase());
      if (!key.secretAvailable && !secretInGnuPG) {
        continue;
      }
      const isPersonal =
        secretInGnuPG ||
        (await lazy.PgpSqliteDb2.isAcceptedAsPersonalKey(key.fpr));
      if (!isPersonal) {
        continue;
      }
      for (const userId of key.userIds) {
        if (userId.type !== "uid") {
          continue;
        }
        if (lazy.EnigmailTrust.isInvalid(userId.keyTrust)) {
          continue;
        }
        emailAddressesWithSecretKey.add(
          lazy.EnigmailFuncs.getEmailFromUserID(userId.userId).toLowerCase()
        );
      }
    }
    this.emailAddressesWithSecretKey = emailAddressesWithSecretKey;
  },

  /**
   * This API uses a cache. It helps when making lookups from multiple
   * places, during a longer transaction.
   * Currently, the cache isn't refreshed automatically.
   * this.emailAddressesWithSecretKey should be set to null when keys have
   * changed and the cache needs to be refreshed.
   *
   * @param {string} emailAddr
   */
  async hasSecretKeyForEmail(emailAddr) {
    if (!this.emailAddressesWithSecretKey) {
      await this._populateEmailHasSecretKeyCache();
    }
    return this.emailAddressesWithSecretKey.has(emailAddr);
  },

  /**
   * Specialized function that takes into account the specifics of email
   * addresses in UIDs.
   *
   * @param {string} emailAddr - Email address to search for without any
   *   angulars or names.
   * @returns {?EnigmailKeyObj} with the found key, or null if no key found.
   */
  async getSecretKeyByEmail(emailAddr) {
    const result = {};
    await this.getAllSecretKeysByEmail(emailAddr, result, true);
    return result.best;
  },

  async getAllSecretKeysByEmail(emailAddr, result, allowExpired) {
    await this.loadGnuPgKeysForEmail(emailAddr);
    const keyList = this.getKeysByEmail(emailAddr, true, true);

    // Keys that exist only in GnuPG are held transiently, never imported, so
    // they are not in the ring and have to be added explicitly.
    for (const key of this.getGnuPgKeysForEmail(emailAddr)) {
      if (!keyList.some(k => k.fpr.toUpperCase() == key.fpr.toUpperCase())) {
        keyList.push(key);
      }
    }

    // A key whose secret material lives in the external GnuPG keyring is a
    // secret key for this address even though only its public part is known.
    const gnuPgSecretFprs = this._getGnuPgSecretFingerprints(emailAddr);

    result.all = [];
    result.best = null;

    var nowDate = new Date();
    var nowSecondsSinceEpoch = nowDate.valueOf() / 1000;
    let bestIsExpired = false;

    for (const key of keyList) {
      const secretInGnuPG = gnuPgSecretFprs?.has(key.fpr.toUpperCase());
      if (!key.secretAvailable && !secretInGnuPG) {
        continue;
      }
      const isPersonal =
        secretInGnuPG ||
        (await lazy.PgpSqliteDb2.isAcceptedAsPersonalKey(key.fpr));
      if (!isPersonal) {
        continue;
      }
      // For a key whose secret material lives in GnuPG, RNP reports the key
      // as unusable for signing, because it cannot see that secret. Judge
      // such a key by its public part instead: rejected keys were dropped
      // above, and expiry is handled below.
      const usable = secretInGnuPG
        ? key.keyTrust != "r"
        : key.getEncryptionValidity(true, "ignoreExpired").keyValid &&
          key.getSigningValidity("ignoreExpired").keyValid;

      if (usable) {
        const thisIsExpired =
          key.expiryTime != 0 && key.expiryTime < nowSecondsSinceEpoch;
        if (!allowExpired && thisIsExpired) {
          continue;
        }
        result.all.push(key);
        if (!result.best) {
          result.best = key;
          bestIsExpired = thisIsExpired;
        } else if (
          result.best.algoSym === key.algoSym &&
          result.best.keySize === key.keySize
        ) {
          if (!key.expiryTime || key.expiryTime > result.best.expiryTime) {
            result.best = key;
          }
        } else if (bestIsExpired && !thisIsExpired) {
          if (
            result.best.algoSym.search(/^(DSA|RSA)$/) < 0 &&
            key.algoSym.search(/^(DSA|RSA)$/) === 0
          ) {
            // prefer RSA or DSA over ECC (long-term: change this once ECC keys are widely supported)
            result.best = key;
            bestIsExpired = thisIsExpired;
          } else if (
            key.getVirtualKeySize() > result.best.getVirtualKeySize()
          ) {
            result.best = key;
            bestIsExpired = thisIsExpired;
          }
        }
      }
    }
  },

  /**
   * Get a list of keys for a given set of (sub-) key IDs.
   *
   * @param {string[]|string} keyIdList - Key IDs, or
   *   string, with space-separated list of key IDs.
   */
  getKeyListById(keyIdList) {
    let keyArr;
    if (typeof keyIdList === "string") {
      keyArr = keyIdList.split(/ +/);
    } else {
      keyArr = keyIdList;
    }

    const ret = [];
    for (const i in keyArr) {
      const r = this.getKeyById(keyArr[i]);
      if (r) {
        ret.push(r);
      }
    }

    return ret;
  },

  /**
   * @param {nsIFile} file - ASCII armored file containing the revocation.
   */
  async importRevFromFile(file) {
    const contents = await IOUtils.readUTF8(file.path);

    const beginIndexObj = {};
    const endIndexObj = {};
    const blockType = lazy.EnigmailArmor.locateArmoredBlock(
      contents,
      0,
      "",
      beginIndexObj,
      endIndexObj,
      {}
    );
    if (!blockType) {
      return;
    }

    if (blockType.search(/^(PUBLIC|PRIVATE) KEY BLOCK$/) !== 0) {
      return;
    }

    const pgpBlock = contents.substr(
      beginIndexObj.value,
      endIndexObj.value - beginIndexObj.value + 1
    );

    const res = await lazy.RNP.importRevImpl(pgpBlock);
    if (res.exitCode) {
      return;
    }

    EnigmailKeyRing.clearCache();
    lazy.EnigmailWindows.keyManReloadKeys();
  },

  /**
   * Import a secret key from the given file.
   *
   * @param {window} win - parent window
   * @param {Function} passCB - a callback function that will be called if the user needs
   *   to enter a passphrase to unlock a secret key. See passphrasePromptCallback
   *   for the function signature.
   * @param {boolean} keepPassphrases - Whether to keep passphrases.
   * @param {nsIFile} inputFile - ASCII armored file containing the revocation.
   * @param {object} errorMsgObj - errorMsgObj.value will contain an error
   *   message in case of failures
   * @param {object} importedKeysObj - importedKeysObj.value will contain
   *   an array of the FPRs imported.
   */
  async importSecKeyFromFile(
    win,
    passCB,
    keepPassphrases,
    inputFile,
    errorMsgObj,
    importedKeysObj
  ) {
    const data = await IOUtils.read(inputFile.path);
    const contents = MailStringUtils.uint8ArrayToByteString(data);

    // This is the route that writes secret material, and the one where the
    // damage design 1.5 measured happens: without this check librnp would
    // unprotect the key and re-protect it with the automatic passphrase, so a
    // key safe in ~/.gnupg would acquire a second, recoverable copy here.
    // Refused before librnp is asked to parse anything, and shaped like
    // success so the wizard reports "no keys imported" rather than an error.
    const heldFpr = await this.gnupgHeldSecretFingerprint(contents);
    if (heldFpr) {
      this._logRefusedSecretImport(heldFpr);
      if (importedKeysObj) {
        importedKeysObj.keys = [];
      }
      return 0;
    }

    // The mirror of the check above, and deliberately not the same shape. Here
    // GnuPG is working but does not hold this key, so the external path is the
    // one in use and this build has no route that writes a secret key into the
    // keyring. Copying it into the profile instead would put the key in the
    // store the user is trying to leave, so the answer is an explicit error:
    // a user who selected a secret keyfile asked for something this build does
    // not do, and silence would be worse than refusal.
    if (this.externalGnuPGUsable()) {
      lazy.log.warn(
        "Refusing to import a secret key into the profile: the external " +
          "GnuPG path is in use and this key is not in the keyring"
      );
      errorMsgObj.value = await lazy.l10n.formatValue(
        "import-secret-key-belongs-in-gnupg"
      );
      if (importedKeysObj) {
        importedKeysObj.keys = [];
      }
      return 1;
    }

    let res;

    let failed = true;

    try {
      res = await lazy.RNP.importSecKeyBlockImpl(
        win,
        passCB,
        keepPassphrases,
        contents
      );
      failed =
        !res || res.exitCode || !res.importedKeys || !res.importedKeys.length;
    } catch (ex) {
      Services.prompt.alert(win, null, ex);
    }

    if (failed) {
      Services.prompt.alert(
        win,
        null,
        await lazy.l10n.formatValue("import-keys-failed")
      );
    }

    if (!res || !res.importedKeys) {
      errorMsgObj.value = res.errorMsg ? res.errorMsg : "";
      return 1;
    }

    if (importedKeysObj) {
      importedKeysObj.keys = res.importedKeys;
    }
    if (res.importedKeys.length) {
      EnigmailKeyRing.updateKeys(res.importedKeys);
    }
    EnigmailKeyRing.clearCache();

    if (res.fingerprintsWithUnsupportedFeatures.length) {
      const fingerprints = res.fingerprintsWithUnsupportedFeatures.join(", ");

      const [info, title, help] = await lazy.l10n.formatValues([
        {
          id: "imported-secret-with-unsupported-features",
          args: {
            fingerprints,
          },
        },
        { id: "import-key-file" },
        { id: "help-button" },
      ]);

      const buttonPressed = Services.prompt.confirmEx(
        win,
        title,
        info,
        Services.prompt.BUTTON_TITLE_IS_STRING * Services.prompt.BUTTON_POS_0 +
          Services.prompt.BUTTON_TITLE_OK * Services.prompt.BUTTON_POS_1 +
          Services.prompt.BUTTON_POS_1_DEFAULT,
        help,
        null,
        null,
        null,
        {}
      );
      if (buttonPressed == 0) {
        openLinkExternally(
          "https://support.mozilla.org/kb/openpgp-secret-keys-with-unsupported-feature-flags"
        );
      }
    }

    if (res.exitCode) {
      errorMsgObj.value = res.errorMsg || "";
    }
    return res.exitCode;
  },

  /**
   * Empty the key cache, such that it will get loaded next time it is accessed.
   */
  clearCache() {
    this.emailAddressesWithSecretKey = null;
    this.clearGnuPgKeyCache();

    // Deliberately not clearGnuPGCheckCache(). Importing a public key ends in
    // saveKeyRings(), which notifies "openpgp-key-change", which lands here.
    // Clearing the "already checked" set too would make the next check import
    // again and notify again, in a loop that redraws the composer's key
    // banner and the key assistant without end.

    gKeyListObj = {
      keyList: [],
      keySortList: [],
    };

    gKeyIndex = new Map();
    gSubkeyIndex = new Map();
  },

  /**
   * Check if the cache is empty.
   *
   * @returns {boolean} true if cache is empty.
   */
  getCacheEmpty() {
    return !gKeyIndex.size;
  },

  /**
   * Get a list of UserIds for a given key.
   * Only the Only UIDs with highest trust level are returned.
   *
   * @param {string} keyId - Key ID, optionally preceded with 0x.
   *
   * @returns {string[]} a list of user IDs.
   */
  getValidUids(keyId) {
    const keyObj = this.getKeyById(keyId);
    if (keyObj) {
      return this.getValidUidsFromKeyObj(keyObj);
    }
    return [];
  },

  getValidUidsFromKeyObj(keyObj) {
    let r = [];
    if (keyObj) {
      const TRUSTLEVELS_SORTED = lazy.EnigmailTrust.trustLevelsSorted();
      let hideInvalidUid = true;
      let maxTrustLevel = TRUSTLEVELS_SORTED.indexOf(keyObj.keyTrust);

      if (lazy.EnigmailTrust.isInvalid(keyObj.keyTrust)) {
        // pub key not valid (anymore)-> display all UID's
        hideInvalidUid = false;
      }

      for (const i in keyObj.userIds) {
        if (keyObj.userIds[i].type !== "uat") {
          if (hideInvalidUid) {
            const thisTrust = TRUSTLEVELS_SORTED.indexOf(
              keyObj.userIds[i].keyTrust
            );
            if (thisTrust > maxTrustLevel) {
              r = [keyObj.userIds[i].userId];
              maxTrustLevel = thisTrust;
            } else if (thisTrust === maxTrustLevel) {
              r.push(keyObj.userIds[i].userId);
            }
            // else do not add uid
          } else if (
            !lazy.EnigmailTrust.isInvalid(keyObj.userIds[i].keyTrust) ||
            !hideInvalidUid
          ) {
            // UID valid  OR  key not valid, but invalid keys allowed
            r.push(keyObj.userIds[i].userId);
          }
        }
      }
    }

    return r;
  },

  /**
   * Export public key(s) to a file.
   *
   * @param {string[]} idArrayFull - array of key IDs or fingerprints
   *   to export (full keys).
   * @param {string[]} idArrayReduced - array of key IDs or fingerprints
   *   to export (reduced keys, non-self signatures stripped).
   * @param {string[]} idArrayMinimal - array of key IDs or fingerprints
   *   to export (minimal keys, user IDs and non-self signatures stripped).
   * @param {string|nsIFile|null} outputFile - output file name or Object.
   * @param {object} exitCodeObj - o.value will contain exit code
   * @param {object} errorMsgObj - o.value will contain error message
   * @returns {string}  the key block data if outputFile is null; "" if a file
   *   is written.
   */
  async extractPublicKeys(
    idArrayFull,
    idArrayReduced,
    idArrayMinimal,
    outputFile,
    exitCodeObj,
    errorMsgObj
  ) {
    // At least one array must have valid input
    if (
      (!idArrayFull || !Array.isArray(idArrayFull) || !idArrayFull.length) &&
      (!idArrayReduced ||
        !Array.isArray(idArrayReduced) ||
        !idArrayReduced.length) &&
      (!idArrayMinimal ||
        !Array.isArray(idArrayMinimal) ||
        !idArrayMinimal.length)
    ) {
      throw new Error("invalid parameter given to EnigmailKeyRing.extractKey");
    }

    exitCodeObj.value = -1;

    const keyBlock = lazy.RNP.getMultiplePublicKeys(
      idArrayFull,
      idArrayReduced,
      idArrayMinimal
    );
    if (!keyBlock) {
      errorMsgObj.value = await lazy.l10n.formatValue("fail-key-extract");
      return "";
    }

    exitCodeObj.value = 0;
    if (outputFile) {
      return IOUtils.writeUTF8(outputFile.path, keyBlock)
        .then(() => {
          return "";
        })
        .catch(async () => {
          exitCodeObj.value = -1;
          errorMsgObj.value = await lazy.l10n.formatValue("file-write-failed", {
            output: outputFile.path,
          });
          return null;
        });
    }
    return keyBlock;
  },

  async promptKeyExport2AsciiFilename(window, title, defaultFilename) {
    const fp = Cc["@mozilla.org/filepicker;1"].createInstance(Ci.nsIFilePicker);
    fp.init(window.browsingContext, title, Ci.nsIFilePicker.modeSave);
    fp.defaultString = defaultFilename;
    fp.defaultExtension = "*.asc";
    fp.appendFilter(await lazy.l10n.formatValue("ascii-armor-file"), "*.asc");
    fp.appendFilters(Ci.nsIFilePicker.filterAll);
    const rv = await new Promise(resolve => fp.open(resolve));
    if (rv != Ci.nsIFilePicker.returnOK || !fp.file) {
      return null;
    }
    return fp.file;
  },

  async exportPublicKeysInteractive(window, defaultFileName, keyIdArray) {
    const outFile = await EnigmailKeyRing.promptKeyExport2AsciiFilename(
      window,
      await lazy.l10n.formatValue("export-to-file"),
      defaultFileName
    );
    if (!outFile) {
      return;
    }

    var exitCodeObj = {};
    var errorMsgObj = {};

    await EnigmailKeyRing.extractPublicKeys(
      keyIdArray, // full
      null,
      null,
      outFile,
      exitCodeObj,
      errorMsgObj
    );
    if (exitCodeObj.value !== 0) {
      Services.prompt.alert(
        window,
        null,
        await lazy.l10n.formatValue("save-keys-failed")
      );
      return;
    }
    Services.prompt.alert(
      window,
      null,
      await lazy.l10n.formatValue("save-keys-ok")
    );
  },

  async backupSecretKeysInteractive(window, defaultFileName, fprArray) {
    const outFile = await EnigmailKeyRing.promptKeyExport2AsciiFilename(
      window,
      await lazy.l10n.formatValue("export-keypair-to-file"),
      defaultFileName
    );

    if (!outFile) {
      return;
    }

    window.openDialog(
      "chrome://openpgp/content/ui/backupKeyPassword.xhtml",
      "",
      "dialog,modal,centerscreen,resizable",
      {
        okCallback: EnigmailKeyRing.exportSecretKey,
        file: outFile,
        fprArray,
      }
    );
  },

  /**
   * Export the secret key after a successful password setup.
   *
   * @param {string} password - The declared password to protect the keys.
   * @param {string[]} fprArray - The array of fingerprint of the selected keys.
   * @param {object} file - The file where the keys should be saved.
   * @param {boolean} [confirmed=false] - If the password was properly typed
   *   in the prompt.
   */
  async exportSecretKey(password, fprArray, file, confirmed = false) {
    // Interrupt in case this method has been called directly without confirming
    // the input password through the password prompt.
    if (!confirmed) {
      return;
    }

    const backupKeyBlock = await lazy.RNP.backupSecretKeys(fprArray, password);
    if (!backupKeyBlock) {
      Services.prompt.alert(
        null,
        await lazy.l10n.formatValue("save-keys-failed")
      );
      return;
    }

    await IOUtils.writeUTF8(file.path, backupKeyBlock)
      .then(async () => {
        Services.prompt.alert(
          null,
          null,
          await lazy.l10n.formatValue("save-keys-ok")
        );
      })
      .catch(async () => {
        Services.prompt.alert(
          null,
          null,
          await lazy.l10n.formatValue("file-write-failed", {
            output: file.path,
          })
        );
      });
  },

  /**
   * Import public key from provided key data.
   *
   * @param {window} parent
   * @param {boolean} askToConfirm - If true, display confirmation dialog.
   * @param {string} keyBlock - Data containing key.
   * @param {boolean} isBinary - Whether the key is binary.
   * @param {string}  keyId - Key ID expected to import (no meaning).
   * @param {object} errorMsgObj - Error object. object.value will contain
   *   error message from GnuPG
   * @param {object} [importedKeysObj] - Imported keys object. object.value
   *    will contain an array of the FPRs imported.
   * @param {boolean} [minimizeKey=false] - Minimize key for importing.
   * @param {string[]} [limitedUids] - Restrict importing the key(s) to a given
   *   set of UIDs.
   * @param {string} [acceptance] - Acceptance for the keys to import,
   *   which are new, or still have acceptance "undecided".
   * @returns {integer} an exit code:
   *   - code 0:  success
   *   - code > 0: error
   *   - code == -1: Cancelled by user
   */
  /**
   * Fingerprint of a secret key in `keyBlock` that the external GnuPG keyring
   * also holds, or null when there is nothing to refuse.
   *
   * Two questions in one place, because both callers need the same answer and
   * a second copy of this logic is a second place to get it wrong. First,
   * whether the block carries secret material at all -- parsed with librnp's
   * secret-only flag, so a public block in the same call answers no without a
   * keyring lookup. Second, whether GnuPG holds the secret for each one, which
   * `GPGME.hasSecretKey()` answers with a listing.
   *
   * **Gated on `allow_external_gnupg`, and that is the whole gate.** Item 8's
   * decision is that the pref governs: with the external path switched off the
   * guard does not consult GnuPG, and a secret key may be imported into the
   * internal store, because that user has chosen the store. What protects them
   * instead is the Primary Password refusal at the point a key is created.
   *
   * @param {string} keyBlock - Armored or binary key data.
   * @returns {Promise<?string>} Uppercase fingerprint, or null.
   */
  async gnupgHeldSecretFingerprint(keyBlock) {
    if (!keyBlock) {
      return null;
    }
    if (!Services.prefs.getBoolPref("mail.openpgp.allow_external_gnupg")) {
      return null;
    }
    if (!lazy.GPGME.init()) {
      return null;
    }

    let secretKeys;
    try {
      secretKeys = await lazy.RNP.getKeyListFromKeyBlockImpl(
        keyBlock,
        false,
        true
      );
    } catch (ex) {
      lazy.log.warn("Checking a key block for secret keys failed", ex);
      return null;
    }
    if (!secretKeys?.length) {
      return null;
    }

    for (const key of secretKeys) {
      if (key.fpr && lazy.GPGME.hasSecretKey(key.fpr)) {
        return key.fpr.toUpperCase();
      }
    }
    return null;
  },

  /**
   * Whether the external GnuPG path is switched on *and* actually working.
   *
   * The pref alone is not enough to refuse an import. It defaults to true in
   * this fork, including on a machine with no GnuPG installed, where
   * `GPGME.init()` fails because the library cannot be loaded. Refusing there
   * would leave a user with no destination at all -- GnuPG cannot take the key
   * because it is not there, and Thunderbird is not allowed to -- which is the
   * one outcome D6 rules out by making the no-GnuPG user a supported user.
   *
   * So this is the condition for treating GnuPG as the owner of secret keys,
   * and `allow_external_gnupg` alone is not.
   *
   * @returns {boolean} True if the external path is enabled and GnuPG loads.
   */
  externalGnuPGUsable() {
    return (
      Services.prefs.getBoolPref("mail.openpgp.allow_external_gnupg") &&
      lazy.GPGME.init()
    );
  },

  /**
   * Fingerprint of a public key in `keyBlock` that the external GnuPG keyring
   * also holds, or null when there is nothing to leave alone.
   *
   * Item 10's rule: a public key GnuPG holds is not written to the profile.
   * The live key in the keyring is the authority, so a copy in the profile
   * cannot outrank it later, and the 18 October stale revision has no
   * mechanism left to recur.
   *
   * **Gated on the transient path being live, not merely on the pref.** A key
   * that is neither written to the profile nor reachable through the transient
   * cache would be lost, and the cache is filled by loadGnuPgKeysForEmail(),
   * which needs `allow_external_gnupg` *and* `fetch_pubkeys_from_gnupg` and a
   * working GPGME. Those three together are this guard's condition, so the
   * refusal only happens where the key is still obtainable.
   *
   * @param {string} keyBlock - Armored or binary key data.
   * @returns {Promise<?string>} Uppercase fingerprint, or null.
   */
  async gnupgHeldPublicFingerprint(keyBlock) {
    if (!keyBlock) {
      return null;
    }
    if (
      !Services.prefs.getBoolPref("mail.openpgp.allow_external_gnupg") ||
      !Services.prefs.getBoolPref("mail.openpgp.fetch_pubkeys_from_gnupg") ||
      !lazy.GPGME.init()
    ) {
      return null;
    }

    let publicKeys;
    try {
      publicKeys = await lazy.RNP.getKeyListFromKeyBlockImpl(keyBlock);
    } catch (ex) {
      lazy.log.warn("Checking a key block for public keys failed", ex);
      return null;
    }
    if (!publicKeys?.length) {
      return null;
    }
    // A block that carries secret material is Item 8 and Item 9's business,
    // not this item's. Refusing it here would block importing a secret key
    // whose public part happens to be in the keyring, which is a legitimate
    // import when GnuPG lacks the secret.
    if (publicKeys.some(key => key.secretAvailable)) {
      return null;
    }

    for (const key of publicKeys) {
      if (key.fpr && lazy.GPGME.hasPublicKey(key.fpr)) {
        return key.fpr.toUpperCase();
      }
    }
    return null;
  },

  /**
   * Log a refusal in the one form that identifies which route reached it.
   *
   * The caller is the only thing that says which of the nine import sites was
   * used, and it is not otherwise recoverable from the message path.
   *
   * @param {string} fingerprint - The key that was refused.
   */
  _logRefusedSecretImport(fingerprint) {
    const caller =
      new Error().stack
        ?.split("\n")
        .slice(2, 4)
        .map(line => line.trim().replace(/^at\s+/, ""))
        .join(" <- ") || "unknown";
    lazy.log.warn(
      `Refusing to import secret key ${fingerprint}: the external GnuPG ` +
        `keyring holds it, so this would be a second copy (reached from ${caller})`
    );
  },

  async importKeyAsync(
    parent,
    askToConfirm,
    keyBlock,
    isBinary,
    keyId, // ignored
    errorMsgObj,
    importedKeysObj,
    minimizeKey = false,
    limitedUids = [],
    acceptance = null
  ) {
    var pgpBlock;
    let armoredType = null;
    if (!isBinary) {
      const beginIndexObj = {};
      const endIndexObj = {};
      const blockType = lazy.EnigmailArmor.locateArmoredBlock(
        keyBlock,
        0,
        "",
        beginIndexObj,
        endIndexObj,
        {}
      );
      if (!blockType) {
        errorMsgObj.value = await lazy.l10n.formatValue("no-pgp-block");
        return 1;
      }

      if (blockType.search(/^(PUBLIC|PRIVATE) KEY BLOCK$/) !== 0) {
        errorMsgObj.value = await lazy.l10n.formatValue("not-first-block");
        return 1;
      }

      armoredType = blockType;
      pgpBlock = keyBlock.substr(
        beginIndexObj.value,
        endIndexObj.value - beginIndexObj.value + 1
      );
    }

    // A secret key that GnuPG already holds must not acquire a second copy
    // here, which is the compromise design 1.5 describes and the reason this
    // guard exists. Checked only when the block could carry secret material:
    // an armored public block cannot, so the common import path pays nothing.
    // A binary block is always checked, because its type is not readable
    // without parsing.
    const mayCarrySecret = isBinary || armoredType === "PRIVATE KEY BLOCK";
    if (mayCarrySecret) {
      const heldFpr = await this.gnupgHeldSecretFingerprint(
        isBinary ? keyBlock : pgpBlock
      );
      if (heldFpr) {
        this._logRefusedSecretImport(heldFpr);
        // Success-shaped on purpose. Every caller of this function treats a
        // non-zero exit as a failure it should report, and none of them did
        // anything wrong by reaching a path this build deliberately declines
        // to take. See the callout in the plan's Stage 2 for the trade.
        return 0;
      }
    }

    // A public key GnuPG holds is not written to the profile. The copy is
    // redundant while the keyring has it, and a redundant copy is what let the
    // 18 October stale revision outrank the live key. The transient key is
    // loaded explicitly so the caller can still resolve it by fingerprint --
    // and it is only refused at all when the transient path is live, which is
    // what stops this from losing the key instead of leaving it in place.
    const isArmoredSecretBlock = armoredType === "PRIVATE KEY BLOCK";
    if (!isArmoredSecretBlock) {
      const heldPublicFpr = await this.gnupgHeldPublicFingerprint(
        isBinary ? keyBlock : pgpBlock
      );
      if (heldPublicFpr) {
        if (importedKeysObj) {
          importedKeysObj.value = [];
        }
        await this.loadGnuPgKeyById(heldPublicFpr);
        lazy.log.debug(
          `Not persisting public key ${heldPublicFpr}: GnuPG holds it`
        );
        return 0;
      }
    }

    if (askToConfirm) {
      if (
        Services.prompt.confirmEx(
          parent,
          null,
          await lazy.l10n.formatValue("import-key-confirm"),
          Services.prompt.STD_OK_CANCEL_BUTTONS,
          await lazy.l10n.formatValue("key-man-button-import"),
          null,
          null,
          null,
          {}
        )
      ) {
        errorMsgObj.value = await lazy.l10n.formatValue("fail-cancel");
        return -1;
      }
    }

    if (minimizeKey) {
      throw new Error("importKeyAsync with minimizeKey not implemented");
    }

    let result = undefined;
    const blockParam = isBinary ? keyBlock : pgpBlock;

    // TODO: The filtering might not work, because the underlying
    // implementation wants to filter by fingerprint, but the filter
    // input is apparently user IDs? Really?
    result = await lazy.RNP.importPubkeyBlockAutoAcceptImpl(
      parent,
      blockParam,
      acceptance,
      limitedUids
    );

    const failed =
      !result ||
      result.exitCode ||
      !result.importedKeys ||
      !result.importedKeys.length;
    if (failed) {
      if (askToConfirm) {
        // if !askToConfirm the caller is responsible to inform the user
        Services.prompt.alert(
          parent,
          null,
          await lazy.l10n.formatValue("import-keys-failed")
        );
      }
    }

    if (!result) {
      result = {};
      result.exitCode = -1;
    } else if (result.importedKeys) {
      if (importedKeysObj) {
        importedKeysObj.value = result.importedKeys;
      }
      if (result.importedKeys.length) {
        EnigmailKeyRing.updateKeys(result.importedKeys);
      }
    }

    EnigmailKeyRing.clearCache();
    return result.exitCode;
  },

  async importKeyDataWithConfirmation(
    window,
    preview,
    keyData,
    isBinary,
    limitedUids = []
  ) {
    if (preview.length) {
      const acceptance = lazy.EnigmailDialog.confirmPubkeyImport(
        window,
        preview
      );
      if (!acceptance) {
        return false;
      }
      const errorMsgObj = {};
      try {
        const exitStatus = await EnigmailKeyRing.importKeyAsync(
          window,
          false,
          keyData,
          isBinary,
          "",
          errorMsgObj,
          null,
          false,
          limitedUids,
          acceptance
        );

        if (exitStatus === 0) {
          const keyList = preview.map(a => a.id);
          lazy.EnigmailDialog.keyImportDlg(window, keyList);
          return true;
        }
      } catch (ex) {
        lazy.log.warn("Importing key FAILED.", ex);
      }
      lazy.l10n.formatValue("fail-key-import").then(value => {
        Services.prompt.alert(window, null, value + "\n" + errorMsgObj.value);
      });
    } else {
      lazy.l10n.formatValue("no-key-found2").then(value => {
        Services.prompt.alert(window, null, value);
      });
    }
    return false;
  },

  async importKeyArrayWithConfirmation(
    window,
    keyArray,
    isBinary,
    limitedUids = []
  ) {
    let somethingWasImported = false;
    if (keyArray.length) {
      const acceptance = lazy.EnigmailDialog.confirmPubkeyImport(
        window,
        keyArray
      );
      if (acceptance) {
        const importedKeys = [];
        let allErrors = "";
        for (const key of keyArray) {
          let exitStatus;
          const errorMsgObj = {};
          try {
            exitStatus = await EnigmailKeyRing.importKeyAsync(
              window,
              false,
              key.pubKey,
              isBinary,
              "",
              errorMsgObj,
              null,
              false,
              limitedUids,
              acceptance
            );
          } catch (ex) {
            lazy.log.warn("Importing key FAILED!", ex);
          }

          if (exitStatus === 0) {
            importedKeys.push(key.id);
          } else {
            allErrors += "\n" + errorMsgObj.value;
          }
        }

        if (importedKeys.length) {
          lazy.EnigmailDialog.keyImportDlg(window, importedKeys);
          somethingWasImported = true;
        } else {
          lazy.l10n.formatValue("fail-key-import").then(value => {
            Services.prompt.alert(window, null, value + allErrors);
          });
        }
      }
    } else {
      lazy.l10n.formatValue("no-key-found2").then(value => {
        Services.prompt.alert(window, null, value);
      });
    }
    return somethingWasImported;
  },

  async importKeyDataSilent(window, keyData, isBinary, onlyFingerprint = "") {
    const errorMsgObj = {};
    let exitStatus = -1;
    try {
      exitStatus = await EnigmailKeyRing.importKeyAsync(
        window,
        false,
        keyData,
        isBinary,
        "",
        errorMsgObj,
        undefined,
        false,
        onlyFingerprint ? [onlyFingerprint] : []
      );
      this.clearCache();
    } catch (ex) {
      lazy.log.warn("Importing key FAILED!", ex);
    }
    return exitStatus === 0;
  },

  /**
   * @param {EnigmailKeyObj} keyObj
   * @returns {boolean} true if the key is valid for encryption.
   */
  isValidForEncryption(keyObj) {
    return this._getValidityLevelIgnoringAcceptance(keyObj, null, false) == 0;
  },

  /**
   * @param {EnigmailKeyObj} keyObj
   * @param {string} emailAddr - Email address.
   * @param {boolean} allowExpired - Whether to allow expired keys.
   * @returns {integer} an acceptance level from -1 to 3. Or -2 for
   *   "doesn't match email" or "not usable"
   */
  /**
   * Whether keys must be trusted rather than merely usable.
   *
   * Item 87's setting. Enigmail asked the same question and defaulted to
   * "usable"; the default here is the same and the strict answer is opt-in,
   * because a strict default in a build whose users have never signed anybody
   * would refuse every correspondent.
   *
   * Read rather than cached: a preference change must take effect on the next
   * send, and the cost is one pref lookup per recipient.
   *
   * @returns {boolean}
   */
  requiresTrustedKeys() {
    return Services.prefs.getBoolPref(
      "mail.openpgp.require_trusted_keys",
      false
    );
  },

  async isValidKeyForRecipient(keyObj, emailAddr, allowExpired, details) {
    if (!emailAddr) {
      return OpenPgpConstants.OpenPgpValidity.INVALID;
    }
    const level = this._getValidityLevelIgnoringAcceptance(
      keyObj,
      emailAddr,
      allowExpired
    );
    if (level < 0) {
      return level;
    }
    const answer = await this._getAcceptanceLevelForEmail(keyObj, emailAddr);
    if (details) {
      // Provenance reaches a caller only when it asks for it. See
      // `_getAcceptanceLevelForEmail()`: the value is the same either way today,
      // and Item 88c is the change that makes the source matter.
      details.source = answer.source;
    }
    return answer.level;
  },

  /**
   * This function checks that given key is not expired, not revoked,
   * and that a (related) encryption (sub-)key is available.
   * If an email address is provided by the caller, the function
   * also requires that a matching user id is available.
   *
   * @param {EnigmailKeyObj} keyObj - The key to check.
   * @param {string} [emailAddr] - Email address.
   * @param {boolean} allowExpired - Whether an expired key may still count.
   * @returns {integer} the validity level, negative for invalid,
   *   0 if no problem were found (neutral).
   */
  _getValidityLevelIgnoringAcceptance(keyObj, emailAddr, allowExpired) {
    if (keyObj.keyTrust == "r") {
      return OpenPgpConstants.OpenPgpValidity.INVALID;
    }

    if (keyObj.keyTrust == "e" && !allowExpired) {
      return OpenPgpConstants.OpenPgpValidity.INVALID;
    }

    if (emailAddr) {
      let uidMatch = false;
      for (const uid of keyObj.userIds) {
        if (uid.type !== "uid") {
          continue;
        }

        if (
          lazy.EnigmailFuncs.getEmailFromUserID(uid.userId).toLowerCase() ===
          emailAddr
        ) {
          uidMatch = true;
          break;
        }
      }
      if (!uidMatch) {
        return OpenPgpConstants.OpenPgpValidity.INVALID;
      }
    }

    // key valid for encryption?
    if (!keyObj.keyUseFor.includes("E")) {
      return OpenPgpConstants.OpenPgpValidity.INVALID;
    }

    // Ensure we have at least one key usable for encryption
    // that is not expired/revoked.

    // We already checked above, the primary key is not revoked/expired
    let foundGoodEnc = keyObj.keyUseFor.match(/e/);
    if (!foundGoodEnc) {
      for (const aSub of keyObj.subKeys) {
        if (aSub.keyTrust == "r") {
          continue;
        }
        if (aSub.keyTrust == "e" && !allowExpired) {
          continue;
        }
        if (aSub.keyUseFor.match(/e/)) {
          foundGoodEnc = true;
          break;
        }
      }
    }

    if (!foundGoodEnc) {
      return OpenPgpConstants.OpenPgpValidity.INVALID;
    }

    return 0; // no problem found
  },

  /**
   * What this build believes about a key for an address, and where that came
   * from.
   *
   * **Two sources, one vocabulary.** Design 13.6: "for a GnuPG key the value is
   * GnuPG's computed answer, displayed as such; for an internal key it is the
   * user's declaration. One vocabulary, two sources, each labelled." This is the
   * labelling. `level` is unchanged from before -- still the value the store
   * holds -- and `source` says which engine *would* answer for this key.
   *
   * **Why the value does not move yet.** The step is deliberately separable: no
   * send can behave differently because of it, so it can be verified alone and
   * cannot break an existing test. Item 88c is the change that makes the source
   * decide the value.
   *
   * **The rule that matters, and it is about `null`.** `GPGME.getOwnerTrust()`
   * answers `null` when GnuPG is uninitialised, does not hold the key, or has no
   * record of it -- a third answer, distinct from `UNKNOWN`, which is 0 and is a
   * real value. `null` therefore means *ask the store*, never *refuse*. Read the
   * other way, every user of the internal engine who has asked for strict trust
   * would lose the ability to send the moment the external ring went quiet,
   * which is why the fallback is the point of this function rather than a detail
   * of it.
   *
   * A key whose secret half is in this profile is the user's own declaration in
   * every case: `getKeyAcceptanceLevelForEmail()` refuses to answer for one, and
   * marking it personal is a statement this build makes about the user's key
   * rather than one gpg computes.
   *
   * @param {EnigmailKeyObj} keyObj
   * @param {string} emailAddr
   * @returns {Promise<{level: integer, source: "gnupg"|"store"}>}
   */
  async _getAcceptanceLevelForEmail(keyObj, emailAddr) {
    let level;
    if (keyObj.secretAvailable) {
      const isPersonal = await lazy.PgpSqliteDb2.isAcceptedAsPersonalKey(
        keyObj.fpr
      );
      if (isPersonal) {
        level = OpenPgpConstants.OpenPgpValidity.ULTIMATE;
      } else {
        // A private key that is not accepted as personal is refused. Expressed
        // as NEVER rather than as a negative, because this is a trust decision
        // and belongs in the same vocabulary as the rest.
        level = OpenPgpConstants.OpenPgpValidity.NEVER;
      }
    } else {
      level = await this.getKeyAcceptanceLevelForEmail(keyObj, emailAddr);
    }

    return { level, source: this._trustSourceFor(keyObj) };
  },

  /**
   * Which engine would answer the trust question for a key: `"gnupg"` or
   * `"store"`.
   *
   * Asked of gpg only when the build is configured to use it and gpg actually
   * has a record. Anything else -- including a key whose secret half is here --
   * is the store's, because that is where the user's declaration lives.
   *
   * A read, not a query: `getOwnerTrust()` lists one key and reads a field off
   * the record it already has, and returns `null` rather than throwing when gpg
   * is unavailable. That is why this needs no try/catch of its own.
   *
   * @param {EnigmailKeyObj} keyObj
   * @returns {"gnupg"|"store"}
   */
  _trustSourceFor(keyObj) {
    if (keyObj.secretAvailable) {
      return "store";
    }
    if (
      !Services.prefs.getBoolPref("mail.openpgp.allow_external_gnupg", false)
    ) {
      return "store";
    }
    return lazy.GPGME.getOwnerTrust(keyObj.fpr) === null ? "store" : "gnupg";
  },

  /**
   * The level the strict policy judges a key by, asked of GnuPG where GnuPG has
   * an answer.
   *
   * **Why this exists, and what it is not.** `isValidKeyForRecipient()` answers
   * from this build's acceptance store, which for a key GnuPG holds was filled
   * with `unverified` by `_autoAcceptGnuPGKey()` without asking anyone -- so the
   * strict policy was judging such a key by a value no human chose. Under the
   * strict policy the question is put to GnuPG instead, which is the decision
   * recorded in design 13.6 and in Item 88c.
   *
   * **Two GnuPG answers, and one of them is not enough.** Measured 2026-10-26
   * against gpg 2.4.4:
   *
   *   - declaring ownertrust **ULTIMATE** raises the key's validity to `u`;
   *   - declaring ownertrust **FULL** leaves validity where it was -- `-` for a
   *     key nobody has signed;
   *   - a certification from an ultimately-trusted key raises validity to `f`.
   *
   * So Item 88c's own argument -- that owner trust and certification are two
   * inputs to one result -- holds only for ULTIMATE. `FULL` means "I trust this
   * person to introduce others", which is not the same statement as "this key is
   * sound", and gpg is right not to treat it as one. Accepting **either** answer
   * is therefore deliberate: both are GnuPG's own databases, neither is ours, and
   * a user who has said "fully trusted" in the Key Manager has said something
   * that must count.
   *
   * **The permissive policy never reaches here.** It keeps the store's answer, so
   * a key whose validity gpg has not computed stays usable -- which is the point
   * of permissive, and would have been broken by switching the value globally.
   *
   * @param {EnigmailKeyObj} keyObj
   * @param {string} emailAddr
   * @param {boolean} allowExpired
   * @returns {Promise<integer>} The level to judge by: a trusted value from
   *   GnuPG when it has one, otherwise the store's answer unchanged.
   */
  async _strictLevelFor(keyObj, emailAddr, allowExpired) {
    const storeLevel = await this.isValidKeyForRecipient(
      keyObj,
      emailAddr,
      allowExpired
    );
    // A hard invalid -- revoked, expired, no encryption subkey, no matching
    // user ID -- is not a trust question and GnuPG is not asked about it.
    if (storeLevel === OpenPgpConstants.OpenPgpValidity.INVALID) {
      return storeLevel;
    }
    if (this._trustSourceFor(keyObj) != "gnupg") {
      return storeLevel;
    }

    // What gpg computed, first: a certification is the statement the strict
    // policy is really asking for, and an ultimately-trusted key carries it as
    // ULTIMATE.
    const validity = lazy.GPGME.getUserIdValidity(keyObj.fpr, emailAddr);
    if (OpenPgpConstants.isValidityTrusted(validity)) {
      return validity;
    }
    // What the user declared, second. Not redundant: ownertrust FULL does not
    // raise validity, and refusing a key the user marked fully trusted would be
    // this build second-guessing a statement made in its own interface.
    const ownerTrust = lazy.GPGME.getOwnerTrust(keyObj.fpr);
    if (OpenPgpConstants.isValidityTrusted(ownerTrust)) {
      return ownerTrust;
    }
    return storeLevel;
  },

  /**
   * Every valid encryption key for one recipient, in candidate order.
   *
   * This used to be one key chosen by a ranking -- a fully or ultimately
   * trusted key won immediately, otherwise the highest acceptance level won,
   * and a tie went to whichever was encountered first. That ranking is gone.
   * Several keys for one address is what rotation looks like, and a layer that
   * collapses them to one makes a choice the user cannot see and cannot
   * override.
   *
   * **What is kept is the acceptability threshold, not the ranking.** A key
   * must still reach "unverified" (level 1) to be usable at all; rejected and
   * undecided keys are excluded exactly as before. The change is that every
   * key which clears the bar is returned, and none is preferred over another.
   *
   * **This is the resolution layer only.** It answers "which keys could this
   * address be encrypted to". It does not decide which one a send uses: the
   * encryption path resolves its own key, and for the internal engine that
   * choice is made in RNP's `findKeyByEmail()`. That gap is recorded in Item
   * 27's row rather than hidden here.
   *
   * @param {string} emailAddr - Email address.
   * @param {object} [details] - If not null, receives msg="ProblemNoKey" when
   *   the address has no usable key at all.
   * @param {object} [options]
   * @param {boolean} [options.trustKeysForThisMessage] - The composer's
   *   per-message override (Item 91). Admits a key whose only failing is trust,
   *   which under the strict policy is `UNKNOWN`, `UNDEFINED` or `MARGINAL`.
   *   `NEVER` and `INVALID` stay refused: see `isValidityUnjudged()`.
   * @returns {Promise<string[]>} Key IDs (without leading "0x"), candidate
   *   order preserved, no duplicates.
   */
  async getValidKeysForRecipient(emailAddr, details, options) {
    const found = [];
    if (!emailAddr) {
      return found;
    }
    emailAddr = emailAddr.toLowerCase();

    const requireTrust = this.requiresTrustedKeys();
    // Only meaningful where trust is required. Under the permissive policy the
    // override would be relaxing a question that was never asked, and Item 91
    // does not even offer the control there.
    const relaxTrust = requireTrust && !!options?.trustKeysForThisMessage;

    // Item 88f: what was refused, and why, so a caller can say it. Only the
    // candidates that failed *for trust* are collected -- a key with no
    // encryption subkey is not something an override can help, so naming it in
    // a "trust" message would offer an action that cannot work.
    const refusedForTrust = [];

    const seen = new Set();
    const keyList = await this.getCandidateKeysForEmail(emailAddr);

    for (const keyObj of keyList) {
      // Under the strict policy the level is asked of GnuPG rather than of this
      // build's acceptance row; under the permissive policy it is the row, as
      // before. Item 88c: one question for the policy that asks for judgment,
      // and no change at all for the policy that does not.
      const acceptanceLevel = requireTrust
        ? await this._strictLevelFor(keyObj, emailAddr, false)
        : await this.isValidKeyForRecipient(keyObj, emailAddr, false);

      // An explicit test of the acceptable values, not a threshold.
      //
      // This used to read `if (acceptanceLevel < 1)`, which worked only because
      // rejection was -1 and everything else counted upward. In GnuPG's
      // vocabulary NEVER is 2 and UNDEFINED is 1, so the same comparison would
      // admit a rejected key -- the ordering temptation is exactly what Item 77
      // warns about.
      //
      // `INVALID` is negative and distinct from the six values: it means the key
      // is unusable for the address (revoked, expired, no encryption subkey, no
      // matching user ID), which is not a trust judgment at all.
      if (
        !OpenPgpConstants.isValidityAcceptable(acceptanceLevel, requireTrust) &&
        !(relaxTrust && OpenPgpConstants.isValidityUnjudged(acceptanceLevel))
      ) {
        if (
          requireTrust &&
          !relaxTrust &&
          OpenPgpConstants.isValidityUnjudged(acceptanceLevel)
        ) {
          refusedForTrust.push({ keyId: keyObj.keyId, fpr: keyObj.fpr });
        }
        continue;
      }
      if (seen.has(keyObj.keyId)) {
        continue;
      }
      seen.add(keyObj.keyId);
      found.push(keyObj.keyId);
    }

    if (!found.length) {
      if (details) {
        // Two different answers, because they ask the user to do different
        // things. "No key" means find one; "not trusted" means judge the one
        // you already have, which the Key Details and Key Manager dialogs can
        // now do. Reporting the second as the first sends a user looking for
        // a key when the key is on their screen.
        //
        // The test is whether a key was actually refused for trust, not whether
        // the strict policy is on. Item 88c keyed this on the policy alone,
        // which told a user with no key at all that their key was not trusted --
        // found by Item 88f's control task, which addresses one recipient who
        // has no key anywhere.
        details.msg = refusedForTrust.length
          ? "ProblemKeyNotTrusted"
          : "ProblemNoKey";
        // Only where the reason is trust: an empty array here would say the
        // address has keys the user could judge, which for "no key" is untrue.
        if (refusedForTrust.length) {
          details.trustRefused = refusedForTrust;
        }
      }
      lazy.log.debug(
        `Found no valid encryption key with enough trust level for ${emailAddr}`
      );
    }
    return found;
  },

  /**
   * The first valid key for an address, with no ranking applied.
   *
   * Kept for callers that can use only one key. "First" means first in the
   * candidate list, which is what the previous ranking also returned for two
   * equally acceptable keys -- the difference is that a lower-listed key no
   * longer displaces a higher-listed one by having better acceptance.
   *
   * @param {string} emailAddr - Email address.
   * @param {object} details - If not null returns error in details.msg.
   * @returns {?string} The first valid key ID (without leading "0x") or null.
   */
  async getValidKeyForRecipient(emailAddr, details) {
    const keys = await this.getValidKeysForRecipient(emailAddr, details);
    return keys.length ? keys[0] : null;
  },

  /**
   * The decision word for a validity value.
   *
   * The strings are what get stored, and they are unchanged by Item 77: the
   * user's judgment is "verified" or "rejected", not a number, and the numbers
   * are GnuPG's vocabulary laid underneath. So this is the only place the two
   * meet, and existing profile data needs no migration for the vocabulary
   * change.
   *
   * @param {integer} level - One of `OpenPgpValidity`.
   * @returns {string} The stored decision word.
   */
  getAcceptanceStringFromAcceptanceLevel(level) {
    switch (level) {
      case OpenPgpConstants.OpenPgpValidity.ULTIMATE:
        return "personal";
      case OpenPgpConstants.OpenPgpValidity.FULL:
        return "verified";
      case OpenPgpConstants.OpenPgpValidity.UNDEFINED:
        return "unverified";
      case OpenPgpConstants.OpenPgpValidity.NEVER:
        return "rejected";
      case OpenPgpConstants.OpenPgpValidity.UNKNOWN:
      default:
        return "undecided";
    }
  },

  /**
   * Certify another party's key, wherever that key lives (Item 88a).
   *
   * **The engine has to be the one that owns the key**, because validity is what
   * gpg computes from the signatures it can see. For a key GnuPG holds the
   * signature is made there, by `GPGME.signKey()`, and gpg's own validity moves
   * as a result. For a key only this build holds, `RNP.certifyKey()` signs it in
   * the profile ring and the signature never reaches gpg -- so the statement is
   * recorded where the strict gate actually reads it, as an acceptance decision
   * of `verified`.
   *
   * **Why `verified` rather than `unverified`.** Signing a key is a deliberate,
   * checkable statement that this key belongs to that address, which is a
   * stronger thing than "I will use it anyway". `_autoAcceptGnuPGKey()` records
   * `unverified` for a key the user merely happens to hold, and conflating the
   * two would make the weaker act grant the stronger status.
   *
   * **An existing rejection is never overridden.** A user who has rejected a key
   * has said not to use it, and a certification is about identity rather than
   * about permission; silently turning a rejection into acceptance would be the
   * kind of quiet reversal this build avoids elsewhere.
   *
   * @param {string} signerFpr - The user's key.
   * @param {string} targetFpr - The key being certified.
   * @param {string} userId - The target's user ID, or its address.
   * @returns {Promise<{ok: boolean, where: "gnupg"|"store", error?: string}>}
   */
  async certifyKey(signerFpr, targetFpr, userId) {
    if (!signerFpr || !targetFpr) {
      return { ok: false, where: "store", error: "missing fingerprint" };
    }
    const target = targetFpr.replace(/^0x/i, "").toUpperCase();

    // Asked of gpg first, because that is the answer that makes the signature
    // count. `getOwnerTrust()` returns null when gpg does not hold the key,
    // which is the same discrimination Item 88b relies on.
    if (
      Services.prefs.getBoolPref("mail.openpgp.allow_external_gnupg", false) &&
      lazy.GPGME.getOwnerTrust(target) !== null
    ) {
      const result = lazy.GPGME.signKey(signerFpr, target, userId ?? "");
      if (!result.ok) {
        return { ok: false, where: "gnupg", error: result.output };
      }
      // gpg's validity is a computed field, but `gpgme_op_keysign` updates the
      // trust database as part of the operation -- measured, unlike a
      // certification made outside gpg. Nothing to nudge here.
      this.clearCache();
      this.clearGnuPgKeyCache();
      return { ok: true, where: "gnupg" };
    }

    const signed = await lazy.RNP.certifyKey(signerFpr, target, userId);
    if (!signed) {
      return { ok: false, where: "store", error: "the signature failed" };
    }

    // The signature is real and gpg cannot see it, so the judgment has to be
    // written where the gate reads it.
    const email = lazy.EnigmailFuncs.getEmailFromUserID(userId) || userId;
    if (email?.includes("@")) {
      try {
        const existing = {};
        await lazy.PgpSqliteDb2.getAcceptance(target, email, existing);
        const decided =
          existing.fingerprintAcceptance == "rejected" ||
          existing.fingerprintAcceptance == "verified";
        if (!decided) {
          await lazy.PgpSqliteDb2.updateAcceptance(target, [email], "verified");
        }
      } catch (ex) {
        lazy.log.warn(
          `Recording acceptance after certifying ${target} failed`,
          ex
        );
      }
    }

    this.clearCache();
    return { ok: true, where: "store" };
  },

  async getKeyAcceptanceLevelForEmail(keyObj, email) {
    if (keyObj.secretAvailable) {
      throw new Error(
        `Should not get acceptance. ${keyObj.fpr} is a private key.`
      );
    }

    let acceptanceLevel = OpenPgpConstants.OpenPgpValidity.UNKNOWN;

    const acceptanceResult = {};
    try {
      await lazy.PgpSqliteDb2.getAcceptance(
        keyObj.fpr,
        email,
        acceptanceResult
      );
    } catch (ex) {
      lazy.log.warn("Get acceptance FAILED!", ex);
      return null;
    }

    if (acceptanceResult.fingerprintAcceptance == "rejected") {
      // rejecting is always global for all email addresses
      return OpenPgpConstants.OpenPgpValidity.NEVER;
    }

    if (acceptanceResult.emailDecided) {
      switch (acceptanceResult.fingerprintAcceptance) {
        case "verified":
          acceptanceLevel = OpenPgpConstants.OpenPgpValidity.FULL;
          break;
        case "unverified":
          acceptanceLevel = OpenPgpConstants.OpenPgpValidity.UNDEFINED;
          break;
        default:
        case "undecided":
          acceptanceLevel = OpenPgpConstants.OpenPgpValidity.UNKNOWN;
          break;
      }
    }
    return acceptanceLevel;
  },

  async getKeyAcceptanceForEmail(keyObj, email) {
    const acceptanceResult = {};

    try {
      await lazy.PgpSqliteDb2.getAcceptance(
        keyObj.fpr,
        email,
        acceptanceResult
      );
    } catch (ex) {
      lazy.log.warn("Get acceptance FAILED!", ex);
      return null;
    }

    if (acceptanceResult.fingerprintAcceptance == "rejected") {
      // rejecting is always global for all email addresses
      return acceptanceResult.fingerprintAcceptance;
    }

    if (acceptanceResult.emailDecided) {
      switch (acceptanceResult.fingerprintAcceptance) {
        case "verified":
        case "unverified":
        case "undecided":
          return acceptanceResult.fingerprintAcceptance;
      }
    }

    return "undecided";
  },

  /**
   * Determine the keys for a set of given addresses.
   *
   * Every usable key per address is collected, not one. A recipient with two
   * live keys -- what rotation looks like -- is reported as having two, so a
   * caller can show which keys exist instead of being handed a choice already
   * made on its behalf.
   *
   * @param {string[]} addresses - Email addresses
   * @param {object} details - Holds details for invalid keys.
   * @param {object} details.errArray
   * @param {object} details.errArray.addr - Email addresses.
   * @param {object} details.errArray.msg - Related error.
   * @param {object} details.keysByAddr - Filled in with address -> string[]
   *   of usable key IDs. Absent from errArray means at least one key.
   * @param {object} [options] - Forwarded to the per-address resolver. Item
   *   88e: `trustKeysForThisMessage` is the composer's per-message override,
   *   and it also applies to a rule that demands encryption, which is the same
   *   trust question asked by a different route.
   * @returns {boolean} true if at least one address has no usable key.
   */
  async getValidKeysForAllRecipients(addresses, details, options) {
    if (!addresses) {
      return null;
    }
    // check whether each address is or has a key:
    let keyMissing = false;
    if (details) {
      details.errArray = [];
      details.keysByAddr = {};
      // Item 88f: every address whose refusal was about trust, with the keys
      // that were refused, so the composer can name them and offer the
      // per-message decision. Absent means no such address, which is different
      // from an empty list of them.
      details.trustRefused = [];
    }
    for (let i = 0; i < addresses.length; i++) {
      let addr = addresses[i];
      if (!addr) {
        continue;
      }
      // try to find current address in key list:
      var errMsg = null;
      addr = addr.toLowerCase();
      if (!addr.includes("@")) {
        throw new Error(
          "getValidKeysForAllRecipients unexpected lookup for non-email addr: " +
            addr
        );
      }

      const aliasKeyList = this.getAliasKeyList(addr);
      if (aliasKeyList) {
        // An empty list is a rule that names no key -- "never encrypt to this
        // address" -- not an absence of a rule. The loop below does nothing
        // for it, so without this branch the address would fall through as
        // satisfied: a rule saying "do not" would read as "fine".
        if (!aliasKeyList.length) {
          keyMissing = true;
          if (details) {
            details.errArray.push({ addr, msg: "ProblemNoKey" });
          }
          lazy.log.debug(`Alias rule for ${addr} names no key.`);
          continue;
        }

        for (const entry of aliasKeyList) {
          let foundError = true;

          let key;
          if ("fingerprint" in entry) {
            key = this.getKeyById(entry.fingerprint);
          } else if ("id" in entry) {
            key = this.getKeyById(entry.id);
          }
          if (key && this.isValidForEncryption(key)) {
            const acceptanceResult =
              await lazy.PgpSqliteDb2.getFingerprintAcceptance(null, key.fpr);
            // If we don't have acceptance info for the key yet,
            // or, we have it and it isn't rejected,
            // then we accept the key for using it in alias definitions.
            if (!acceptanceResult || acceptanceResult != "rejected") {
              foundError = false;
            }

            // A rule may require encryption; it may not make a key
            // acceptable. Where a rule demands encryption and the key it
            // names is below the trust threshold, the send is refused here
            // -- before it is attempted -- and the refusal names the address
            // *and both facts*: that a rule asked for this, and that the key
            // is not trusted. Enigmail had no equivalent because its rules
            // carried no key.
            //
            // Only the `always` answer is treated this way. `maybe` is a rule
            // saying "encrypt if you can", which an untrusted key can honour
            // under the permissive policy; refusing on it would make a
            // permissive default unusable.
            if (!foundError && lazy.OpenPGPAlias.requiresEncryption(addr)) {
              // Inherently a strict question -- a rule demanding encryption asks
              // whether the key is good enough for it -- so it goes through the
              // same GnuPG consultation the strict policy uses. Before this, a
              // rule's own requirement was judged by the acceptance row while
              // the policy beside it was judged by nothing at all.
              const level = await this._strictLevelFor(key, addr, false);
              const trusted =
                OpenPgpConstants.isValidityTrusted(level) ||
                (this.requiresTrustedKeys() &&
                  options?.trustKeysForThisMessage &&
                  OpenPgpConstants.isValidityUnjudged(level));
              if (!trusted) {
                foundError = true;
                keyMissing = true;
                if (details) {
                  // One refusal with a reason that can be acted on, rather
                  // than this beside the generic "alias problem": two errors
                  // saying different things about one address is how a user
                  // learns to ignore both.
                  details.errArray.push({
                    addr,
                    msg: "ProblemRuleRequiresUntrustedKey",
                  });
                  // The same trust question the policy asks, so the same
                  // per-message answer reaches it (Items 88e and 88f).
                  if (
                    !options?.trustKeysForThisMessage &&
                    OpenPgpConstants.isValidityUnjudged(level)
                  ) {
                    details.trustRefused.push({
                      addr,
                      keyId: key.keyId,
                      fpr: key.fpr,
                    });
                  }
                }
                lazy.log.warn(
                  `Rule requires encryption to ${addr}, but ${key.fpr} is ` +
                    `not trusted.`
                );
              }
            }
          }

          if (foundError) {
            keyMissing = true;
            if (
              details &&
              !details.errArray.some(
                e =>
                  e.addr == addr && e.msg == "ProblemRuleRequiresUntrustedKey"
              )
            ) {
              const detEl = {};
              detEl.addr = addr;
              detEl.msg = "alias problem";
              details.errArray.push(detEl);
            }
            lazy.log.warn(`Alias key for ${addr} missing/unusable.`);
          }
        }

        // skip the lookup for direct matching keys by email
        continue;
      }

      // try email match:
      var addrErrDetails = {};
      const foundKeyIds = await this.getValidKeysForRecipient(
        addr,
        addrErrDetails,
        options
      );
      if (details && addrErrDetails.msg) {
        errMsg = addrErrDetails.msg;
      }
      if (details && addrErrDetails.trustRefused) {
        for (const refused of addrErrDetails.trustRefused) {
          details.trustRefused.push({ addr, ...refused });
        }
      }
      if (details && foundKeyIds.length) {
        details.keysByAddr[addr] = foundKeyIds;
      }
      if (!foundKeyIds.length) {
        // no key for this address found
        keyMissing = true;
        if (details) {
          if (!errMsg) {
            errMsg = "ProblemNoKey";
          }
          var detailsElem = {};
          detailsElem.addr = addr;
          detailsElem.msg = errMsg;
          details.errArray.push(detailsElem);
        }
        lazy.log.warn(`No single valid key for ${addr}`);
      }
    }
    return keyMissing;
  },

  /**
   * If the given email address has an alias definition, return its
   * list of key identifiers.
   *
   * The function will prefer a match to an exact email alias.
   * If no email alias could be found, the function will search for
   * an alias rule that matches the domain.
   *
   * @param {string} email - The email address to look up
   * @returns {object[]} - An array with alias key identifiers found for the
   *  input, or null if no alias matches the address.
   */
  getAliasKeyList(email) {
    const ekl = lazy.OpenPGPAlias.getEmailAliasKeyList(email);
    if (ekl) {
      return ekl;
    }
    return lazy.OpenPGPAlias.getDomainAliasKeyList(email);
  },

  /**
   * Return the fingerprint of each usable alias key for the given
   * email address.
   *
   * @param {string[]} keyList - Array of key identifiers
   * @returns {string[]} An array with fingerprints of all alias keys,
   *   or an empty array on failure.
   */
  getAliasKeys(keyList) {
    const keys = [];

    for (const entry of keyList) {
      let key;
      let lookupId;
      if ("fingerprint" in entry) {
        lookupId = entry.fingerprint;
        key = this.getKeyById(entry.fingerprint);
      } else if ("id" in entry) {
        lookupId = entry.id;
        key = this.getKeyById(entry.id);
      }
      if (key && this.isValidForEncryption(key)) {
        keys.push(key.fpr);
      } else {
        const reason = key ? "not usable" : "missing";
        lazy.log.warn(`Alias key for ${lookupId} ${reason}`);
        return [];
      }
    }
    return keys;
  },

  /**
   * Rebuild the quick access search indexes after the key list was loaded
   */
  rebuildKeyIndex() {
    gKeyIndex = new Map();
    gSubkeyIndex = new Map();

    for (const i in gKeyListObj.keyList) {
      const k = gKeyListObj.keyList[i];
      gKeyIndex.set(k.keyId, k);
      gKeyIndex.set(k.fpr, k);
      gKeyIndex.set(k.keyId.substr(-8, 8), k);

      // add subkeys
      for (const j in k.subKeys) {
        gSubkeyIndex.set(k.subKeys[j].keyId, k);
      }
    }
  },

  /**
   * Update specific keys in the key cache. If the key objects don't exist yet,
   * they will be created
   *
   * @param {string[]} keys - Key IDs or fingerprints.
   */
  updateKeys(keys) {
    const uniqueKeys = [...new Set(keys)]; // make key IDs unique

    deleteKeysFromCache(uniqueKeys);

    if (gKeyListObj.keyList.length) {
      loadKeyList(null, null, 1, uniqueKeys);
    } else {
      loadKeyList(null, null, 1);
    }

    lazy.EnigmailWindows.keyManReloadKeys();
  },

  /**
   * Fingerprints of revoked personal keys for an address, including keys that
   * live only in the external GnuPG keyring.
   *
   * The transient set is included because a revoked key is exactly the case
   * where its absence is worst: the caller attaches these revocation
   * certificates to a message so recipients learn the key is dead, and a
   * revoked personal key held by GnuPG used to be invisible here -- the ring
   * was read directly. Found by Item 16's sweep, which is why this is async:
   * the transient cache has to be loaded before it can be read.
   *
   * @param {string} email - Address to match.
   * @returns {Promise<string[]>} Fingerprints, each prefixed with "0x".
   */
  async findRevokedPersonalKeysByEmail(email) {
    const res = [];
    if (email === "") {
      return res;
    }
    email = email.toLowerCase();
    await this.loadGnuPgKeysForEmail(email);

    const candidates = [
      ...this.getKeysByEmail(email, true, true),
      ...this.getGnuPgKeysForEmail(email),
    ];
    const seen = new Set();
    const unique = [];
    for (const k of candidates) {
      const fpr = k.fpr.toUpperCase();
      if (seen.has(fpr)) {
        continue;
      }
      seen.add(fpr);
      unique.push(k);
    }

    for (const k of unique) {
      if (k.keyTrust != "r") {
        continue;
      }
      let hasAdditionalEmail = false;
      let isMatch = false;

      for (const userId of k.userIds) {
        if (userId.type !== "uid") {
          continue;
        }

        const emailInUid = lazy.EnigmailFuncs.getEmailFromUserID(
          userId.userId
        ).toLowerCase();
        if (emailInUid == email) {
          isMatch = true;
        } else {
          // For privacy reasons, exclude revoked keys that point to
          // other email addresses.
          hasAdditionalEmail = true;
          break;
        }
      }

      if (isMatch && !hasAdditionalEmail) {
        res.push("0x" + k.fpr);
      }
    }
    return res;
  },

  /**
   * @param {string} email
   */
  async getRecipientAutocryptKeyForEmail(email) {
    // Forward to RNP, to avoid that other modules depend on RNP
    return lazy.RNP.getRecipientAutocryptKeyForEmail(email);
  },

  /**
   * @param {string} keyId
   * @param {string} email
   */
  getAutocryptKey(keyId, email) {
    const keyObj = this.getKeyById(keyId);
    if (
      !keyObj ||
      !keyObj.subKeys.length ||
      !keyObj.userIds.length ||
      !keyObj.keyUseFor.includes("s")
    ) {
      return null;
    }
    const uid = keyObj.getUserIdWithEmail(email);
    if (!uid) {
      return null;
    }

    // A key that lives only in GnuPG has no handle in RNP's store, so export
    // it from the block that was read from GnuPG instead.
    const gnuPgKey = this.getGnuPgKeyById(keyId);
    if (gnuPgKey) {
      return lazy.RNP.getAutocryptKeyB64FromBlock(
        this.gnuPgKeyBlocks.get(gnuPgKey.fpr.toUpperCase()) ?? "",
        keyId,
        uid.userId
      );
    }

    return lazy.RNP.getAutocryptKeyB64(keyId, null, uid.userId);
  },

  alreadyCheckedGnuPG: new Set(),

  /**
   * Forget which addresses have been checked against GnuPG, so the next key
   * listing queries the external keyring again. Needed because the keyring is
   * not watched for changes: a key added with gpg stays invisible otherwise
   * until the application restarts.
   */
  clearGnuPGCheckCache() {
    this.alreadyCheckedGnuPG.clear();
  },

  /**
   * @typedef {object} EncryptionKeyMeta
   * @property {string} readiness - one of
   *   "accepted", "expiredAccepted",
   *   "otherAccepted", "expiredOtherAccepted",
   *   "undecided", "expiredUndecided",
   *   "rejected", "expiredRejected",
   *   "collected", "rejectedPersonal", "revoked", "alias"
   *
   *   The meaning of "otherAccepted" is: the key is undecided for this
   *   email address, but accepted for at least on other address.
   *
   * @property {KeyObj} keyObj -
   *   undefined if an alias
   * @property {CollectedKey} collectedKey -
   *   undefined if not a collected key or an alias
   */

  /**
   * Obtain information on the availability of recipient keys
   * for the given email address, and the status of the keys.
   *
   * No key details are returned for alias keys.
   *
   * If readiness is "collected" it's an unexpired key that hasn't
   * been imported into permanent storage (keyring) yet.
   *
   * @param {string} email - Email address.
   *
   * @returns {EncryptionKeyMeta[]} meta information for an encryption key.
   *
   *   Callers can filter it keys according to needs, like
   *
   *   let meta = getEncryptionKeyMeta("foo@example.com");
   *   let readyToUse = meta.filter(k => k.readiness == "accepted" || k.readiness == "alias");
   *   let hasAlias = meta.filter(k => k.readiness == "alias");
   *   let accepted = meta.filter(k => k.readiness == "accepted");
   *   let expiredAccepted = meta.filter(k => k.readiness == "expiredAccepted");
   *   let unaccepted = meta.filter(k => k.readiness == "undecided" || k.readiness == "rejected" );
   *   let expiredUnaccepted = meta.filter(k => k.readiness == "expiredUndecided" || k.readiness == "expiredRejected");
   *   let unacceptedNotYetImported = meta.filter(k => k.readiness == "collected");
   *   let invalidKeys = meta.some(k => k.readiness == "revoked" || k.readiness == "rejectedPersonal" || );
   *
   *   let keyReadiness = meta.groupBy(({readiness}) => readiness);
   */
  async getEncryptionKeyMeta(email) {
    email = email.toLowerCase();

    // The composer and the key assistant both come through here, and both
    // previously saw only the profile ring, so a key that exists only in
    // GnuPG was reported as "available but not accepted" — the collected
    // entry — while the accepted decision written for it was never consulted.
    await this.loadGnuPgKeysForEmail(email);

    const result = [];

    result.hasAliasRule = lazy.OpenPGPAlias.hasAliasDefinition(email);
    if (result.hasAliasRule) {
      const keyMeta = {};
      keyMeta.readiness = "alias";
      result.push(keyMeta);
      return result;
    }

    const fingerprintsInKeyring = new Set();

    // Keys from the profile ring, plus the transient ones from GnuPG. The
    // latter are public-only, so they take the acceptance path below rather
    // than the personal-key path.
    const candidateKeys = await this.getCandidateKeysForEmail(email);
    for (const keyObj of candidateKeys) {
      if (this.getGnuPgKeyById(keyObj.keyId)) {
        // Track transient keys, so the collected-key block below treats them
        // as present and does not add a second, unaccepted entry for them.
        fingerprintsInKeyring.add(keyObj.fpr);
      }
    }

    for (const keyObj of candidateKeys) {
      const keyMeta = {};
      keyMeta.keyObj = keyObj;

      // Where this key came from, when it came from GnuPG.
      //
      // The Key Assistant asks the user to judge a key it found, and an answer
      // that omits the source is incomplete: for a key GnuPG holds there is no
      // collected-key record to name it, so the origin line said nothing at
      // all. `openpgp-key-assistant-key-collected-gnupg` has existed as a
      // localized string with no producer; this is its producer.
      //
      // Deliberately not `collectedKey`. That field carries a `pubKey` which
      // the assistant imports on the user's behalf -- and a key GnuPG holds is
      // already present, so it must never be imported. Under Item 10 it is not
      // written to the profile either, which means this source is the *only*
      // one for such a key rather than an additional one.
      if (this.getGnuPgKeyById(keyObj.keyId)) {
        keyMeta.gnupgKey = {
          sources: [{ type: "gnupg", description: this.getGnuPgKeyringPath() }],
        };
      }

      let uidMatch = false;
      for (const uid of keyObj.userIds) {
        if (uid.type !== "uid") {
          continue;
        }
        // key valid for encryption?
        if (!keyObj.keyUseFor.includes("E")) {
          continue;
        }

        if (
          lazy.EnigmailFuncs.getEmailFromUserID(uid.userId).toLowerCase() ===
          email
        ) {
          uidMatch = true;
          break;
        }
      }
      if (!uidMatch) {
        continue;
      }
      fingerprintsInKeyring.add(keyObj.fpr);

      if (keyObj.keyTrust == "r") {
        keyMeta.readiness = "revoked";
        result.push(keyMeta);
        continue;
      }
      let isExpired = keyObj.keyTrust == "e";

      // Ensure we have at least one primary key or subkey usable for
      // encryption that is not expired/revoked.
      // We already checked above, the primary key is not revoked.
      // If the primary key is good for encryption, we don't need to
      // check subkeys.
      if (!keyObj.keyUseFor.match(/e/)) {
        let hasExpiredSubkey = false;
        let hasRevokedSubkey = false;
        let hasUsableSubkey = false;

        for (const aSub of keyObj.subKeys) {
          if (!aSub.keyUseFor.match(/e/)) {
            continue;
          }
          if (aSub.keyTrust == "e") {
            hasExpiredSubkey = true;
          } else if (aSub.keyTrust == "r") {
            hasRevokedSubkey = true;
          } else {
            hasUsableSubkey = true;
          }
        }

        if (!hasUsableSubkey) {
          if (hasExpiredSubkey) {
            isExpired = true;
          } else if (hasRevokedSubkey) {
            keyMeta.readiness = "revoked";
            result.push(keyMeta);
            continue;
          }
        }
      }

      if (keyObj.secretAvailable) {
        const isPersonal = await lazy.PgpSqliteDb2.isAcceptedAsPersonalKey(
          keyObj.fpr
        );
        if (isPersonal) {
          keyMeta.readiness = "accepted";
        } else {
          // We don't allow encrypting to rejected secret/personal keys.
          keyMeta.readiness = "rejectedPersonal";
          result.push(keyMeta);
          continue;
        }
      } else {
        // Item 88d: under the strict policy, readiness asks the gate's own
        // question, so the composer's view and a send cannot disagree about one
        // key. `allowExpired` is true because the `expired*` readiness values
        // report expiry separately; false would collapse them into INVALID.
        const acceptanceLevel = this.requiresTrustedKeys()
          ? await this._strictLevelFor(keyObj, email, true)
          : await this.getKeyAcceptanceLevelForEmail(keyObj, email);
        // Named values, not raw numbers. This switch used to read `case 1: case
        // 2:` for accepted and `case -1:` for rejected -- which under GnuPG's
        // numbering would make NEVER (2) "accepted" and leave rejection
        // unreachable. The readiness vocabulary is derived from these values
        // rather than stored, which is why changing the values without this
        // change produced a rejected key shown as accepted; the failure was
        // Item 67's test noticing, not a silent one.
        const { OpenPgpValidity } = OpenPgpConstants;
        switch (acceptanceLevel) {
          // ULTIMATE reaches here only from GnuPG: a personal key is answered
          // above, and the acceptance store has no value for it.
          case OpenPgpValidity.UNDEFINED:
          case OpenPgpValidity.FULL:
          case OpenPgpValidity.ULTIMATE: {
            // Under the strict policy an `UNDEFINED` key is not accepted,
            // because the send gate will refuse it. Reporting it as accepted
            // here would have the Key Assistant say the recipient is fine and
            // the send then fail on the same key -- two surfaces disagreeing
            // about one fact, which is the failure this stage keeps meeting.
            // It reads as undecided instead, so the assistant offers to
            // resolve it and accepting it as verified makes it FULL.
            const accepted = OpenPgpConstants.isValidityAcceptable(
              acceptanceLevel,
              this.requiresTrustedKeys()
            );
            if (accepted) {
              keyMeta.readiness = isExpired ? "expiredAccepted" : "accepted";
            } else {
              keyMeta.readiness = isExpired ? "expiredUndecided" : "undecided";
            }
            break;
          }
          case OpenPgpValidity.NEVER:
            keyMeta.readiness = isExpired ? "expiredRejected" : "rejected";
            break;
          case OpenPgpValidity.UNKNOWN:
          default: {
            const other = await lazy.PgpSqliteDb2.getFingerprintAcceptance(
              null,
              keyObj.fpr
            );
            if (other == "verified" || other == "unverified") {
              // If the check for the email returned undecided, but
              // overall the key is marked as accepted, it means that
              // the key is only accepted for another email address.
              keyMeta.readiness = isExpired
                ? "expiredOtherAccepted"
                : "otherAccepted";
            } else {
              keyMeta.readiness = isExpired ? "expiredUndecided" : "undecided";
            }
            break;
          }
        }
      }
      result.push(keyMeta);
    }

    // GnuPG keys are read above, by loadGnuPgKeysForEmail(), and held
    // transiently. There is deliberately nothing here that imports them: the
    // whole point of the external backend is that Thunderbird's own keyring is
    // never used for them.

    const collDB = await lazy.CollectedKeysDB.getInstance();
    const coll = await collDB.findKeysForEmail(email);
    for (const c of coll) {
      const k = await lazy.RNP.getKeyListFromKeyBlockImpl(c.pubKey);
      if (!k) {
        continue;
      }
      if (k.length != 1) {
        // Past code could have store key blocks that contained
        // multiple entries. Ignore and delete.
        collDB.deleteKey(k[0].fpr);
        continue;
      }

      let deleteFromCollected = false;

      if (fingerprintsInKeyring.has(k[0].fpr)) {
        deleteFromCollected = true;
      } else {
        const trust = k[0].keyTrust;
        if (trust == "r" || trust == "e") {
          deleteFromCollected = true;
        }
      }

      if (!deleteFromCollected) {
        // Ensure we have at least one primary key or subkey usable for
        // encryption that is not expired/revoked.
        // If the primary key is good for encryption, we don't need to
        // check subkeys.

        if (!k[0].keyUseFor.match(/e/)) {
          let hasUsableSubkey = false;

          for (const aSub of k[0].subKeys) {
            if (!aSub.keyUseFor.match(/e/)) {
              continue;
            }
            if (aSub.keyTrust != "e" && aSub.keyTrust != "r") {
              hasUsableSubkey = true;
              break;
            }
          }

          if (!hasUsableSubkey) {
            deleteFromCollected = true;
          }
        }
      }

      if (deleteFromCollected) {
        collDB.deleteKey(k[0].fpr);
        continue;
      }

      const keyMeta = {};
      keyMeta.readiness = "collected";
      keyMeta.keyObj = k[0];
      keyMeta.collectedKey = c;

      result.push(keyMeta);
    }

    return result;
  },
}; //  EnigmailKeyRing

/************************ INTERNAL FUNCTIONS ************************/

function sortByUserId(keyListObj, sortDirection) {
  return function (a, b) {
    return a.userId < b.userId ? -sortDirection : sortDirection;
  };
}

const sortFunctions = {
  keyid(keyListObj, sortDirection) {
    return function (a, b) {
      return a.keyId < b.keyId ? -sortDirection : sortDirection;
    };
  },

  keyidshort(keyListObj, sortDirection) {
    return function (a, b) {
      return a.keyId.substr(-8, 8) < b.keyId.substr(-8, 8)
        ? -sortDirection
        : sortDirection;
    };
  },

  fpr(keyListObj, sortDirection) {
    return function (a, b) {
      return keyListObj.keyList[a.keyNum].fpr < keyListObj.keyList[b.keyNum].fpr
        ? -sortDirection
        : sortDirection;
    };
  },

  keytype(keyListObj, sortDirection) {
    return function (a, b) {
      return keyListObj.keyList[a.keyNum].secretAvailable <
        keyListObj.keyList[b.keyNum].secretAvailable
        ? -sortDirection
        : sortDirection;
    };
  },

  validity(keyListObj, sortDirection) {
    return function (a, b) {
      return lazy.EnigmailTrust.trustLevelsSorted().indexOf(
        lazy.EnigmailTrust.getTrustCode(keyListObj.keyList[a.keyNum])
      ) <
        lazy.EnigmailTrust.trustLevelsSorted().indexOf(
          lazy.EnigmailTrust.getTrustCode(keyListObj.keyList[b.keyNum])
        )
        ? -sortDirection
        : sortDirection;
    };
  },

  trust(keyListObj, sortDirection) {
    return function (a, b) {
      return lazy.EnigmailTrust.trustLevelsSorted().indexOf(
        keyListObj.keyList[a.keyNum].ownerTrust
      ) <
        lazy.EnigmailTrust.trustLevelsSorted().indexOf(
          keyListObj.keyList[b.keyNum].ownerTrust
        )
        ? -sortDirection
        : sortDirection;
    };
  },

  created(keyListObj, sortDirection) {
    return function (a, b) {
      return keyListObj.keyList[a.keyNum].keyCreated <
        keyListObj.keyList[b.keyNum].keyCreated
        ? -sortDirection
        : sortDirection;
    };
  },

  expiry(keyListObj, sortDirection) {
    return function (a, b) {
      return keyListObj.keyList[a.keyNum].expiryTime <
        keyListObj.keyList[b.keyNum].expiryTime
        ? -sortDirection
        : sortDirection;
    };
  },
};

function getSortFunction(type, keyListObj, sortDirection) {
  return (sortFunctions[type] || sortByUserId)(keyListObj, sortDirection);
}

/**
 * Load the key list into memory and return it sorted by a specified column.
 *
 * @param {?window} win - Parent window for displaying error messages.
 * @param {string} sortColumn - The column name for sorting. One of:
 *   userid, keyid, keyidshort, fpr, keytype, validity, trust, created, expiry.
 * @param {1|-1} sortDirection - Sort direction: 1 = ascending / -1 = descending.
 * @param {?string[]} onlyKeys - Only (re-)load these key IDs.
 */
function loadKeyList(win, sortColumn, sortDirection, onlyKeys = null) {
  if (gLoadingKeys) {
    waitForKeyList();
    return;
  }
  gLoadingKeys = true;

  lazy.RNP.getKeys(onlyKeys)
    .then(keyList => {
      createAndSortKeyList(
        keyList,
        sortColumn,
        sortDirection,
        onlyKeys === null
      );
      gLoadingKeys = false;
    })
    .catch(e => {
      lazy.log.warn("Loading keylist FAILED.", e);
      gLoadingKeys = false;
    });
  waitForKeyList();
}

/**
 * Update the global key sort-list (quick index to keys).
 */
function updateSortList() {
  gKeyListObj.keySortList = [];
  for (let i = 0; i < gKeyListObj.keyList.length; i++) {
    const keyObj = gKeyListObj.keyList[i];
    gKeyListObj.keySortList.push({
      userId: keyObj.userId ? keyObj.userId.toLowerCase() : "",
      keyId: keyObj.keyId,
      fpr: keyObj.fpr,
      keyNum: i,
    });
  }
}

/**
 * Delete a set of keys from the key cache. Does not rebuild key indexes.
 * Not found keys are skipped.
 *
 * @param {string[]} keyList - Key IDs (or fpr) to delete.
 * @returns {EnigmailKeyObj[]} the deleted key objects.
 */

function deleteKeysFromCache(keyList) {
  const deleted = [];
  const foundKeys = [];
  for (const keyId of keyList) {
    const k = EnigmailKeyRing.getKeyById(keyId, true);
    if (k) {
      foundKeys.push(k);
    }
  }

  for (const k of foundKeys) {
    let foundIndex = -1;
    for (let i = 0; i < gKeyListObj.keyList.length; i++) {
      if (gKeyListObj.keyList[i].fpr == k.fpr) {
        foundIndex = i;
        break;
      }
    }
    if (foundIndex >= 0) {
      gKeyListObj.keyList.splice(foundIndex, 1);
      deleted.push(k);
    }
  }

  return deleted;
}

function createAndSortKeyList(
  keyList,
  sortColumn,
  sortDirection,
  resetKeyCache
) {
  if (typeof sortColumn !== "string") {
    sortColumn = "userid";
  }
  if (!sortDirection) {
    sortDirection = 1;
  }

  if (!("keyList" in gKeyListObj) || resetKeyCache) {
    gKeyListObj.keyList = [];
    gKeyListObj.keySortList = [];
  }

  gKeyListObj.keyList = gKeyListObj.keyList.concat(
    keyList.map(k => new lazy.EnigmailKeyObj(k))
  );

  // update the quick index for sorting keys
  updateSortList();

  // create a hash-index on key ID (8 and 16 characters and fingerprint)
  // in a single array

  EnigmailKeyRing.rebuildKeyIndex();

  gKeyListObj.keySortList.sort(
    getSortFunction(sortColumn.toLowerCase(), gKeyListObj, sortDirection)
  );
}

function waitForKeyList() {
  const mainThread = Services.tm.mainThread;
  while (gLoadingKeys) {
    mainThread.processNextEvent(true);
  }
}
