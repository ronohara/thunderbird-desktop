/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * An identity's OpenPGP keys, as an ordered list.
 *
 * Why a list: an identity used to name exactly one key, in `openpgp_key_id`.
 * That is enough to say *which* key but not which to prefer, so when an
 * identity holds several live keys the choice is made by whatever order the
 * keyring happens to return them in -- invisible, and unchoosable. D12 chose
 * the ordered list: the user states a preference, and the engine reads the
 * first entry that can actually be used rather than computing a preference of
 * its own.
 *
 * Why `openpgp_key_id` is still written: it is read in about two dozen places
 * -- the account settings page, the key wizard, the extension API, the draft
 * flags -- and changing them all in one step would be a larger change than the
 * feature. So the list is authoritative and `openpgp_key_id` is kept equal to
 * the first entry's key ID, which is what every existing reader means by "the
 * identity's key". A reader that knows only about one key therefore keeps
 * working and keeps being right, and only the code that has to distinguish
 * among several consults the list.
 *
 * A key ID is not a fingerprint, and the two are not interchangeable here:
 * `openpgp_key_id` holds a 16-hex-digit key ID because that is what the
 * settings page compares against, while the list holds full fingerprints
 * because two keys can share a key ID and the preference must not be
 * ambiguous.
 */

const lazy = {};

ChromeUtils.defineESModuleGetters(lazy, {
  EnigmailKeyRing: "chrome://openpgp/content/modules/keyRing.sys.mjs",
});

/** The attribute holding the ordered list, newline-separated fingerprints. */
export const LIST_ATTR = "openpgp_key_list";

/**
 * The attribute holding the single key the rest of the application reads.
 * Always the first entry of the list; never written on its own by this module.
 */
export const PRIMARY_ATTR = "openpgp_key_id";

/**
 * Normalises a fingerprint or key ID: trimmed, upper case, no `0x`.
 *
 * @param {string} value
 * @returns {string}
 */
function normalise(value) {
  return String(value ?? "")
    .trim()
    .replace(/^0x/i, "")
    .toUpperCase();
}

/**
 * Parses the stored list.
 *
 * Both `\n` and `,` are accepted as separators, because the attribute is a
 * preference and a hand-edited prefs.js is a legitimate way to set it.
 *
 * @param {string} raw
 * @returns {string[]}
 */
function parseList(raw) {
  return String(raw ?? "")
    .split(/[\n,]/)
    .map(normalise)
    .filter(Boolean);
}

/**
 * The fingerprints the identity has, in the user's order.
 *
 * An identity that predates the list returns its single `openpgp_key_id`
 * resolved to a fingerprint, which is the migration: the old value is read
 * rather than discarded, and nothing is written during a read. The list is
 * written the first time the order is changed, and until then the two agree by
 * construction.
 *
 * @param {nsIMsgIdentity} identity
 * @returns {string[]} Fingerprints, most preferred first. Empty when the
 *   identity has no key.
 */
export function getKeyList(identity) {
  const stored = parseList(identity.getUnicharAttribute(LIST_ATTR));
  if (stored.length) {
    return stored;
  }

  const single = normalise(identity.getUnicharAttribute(PRIMARY_ATTR));
  if (!single) {
    return [];
  }
  // Resolve to a fingerprint where the key is known, so the two forms agree
  // and a later comparison is not between a key ID and a fingerprint. A key
  // that is not in the keyring keeps its key ID: dropping it would silently
  // forget the identity's key, which is a worse answer than an entry that
  // resolves to nothing.
  const key = lazy.EnigmailKeyRing.getKeyById(single);
  return [key ? normalise(key.fpr) : single];
}

/**
 * Stores the list, and keeps `openpgp_key_id` equal to its first entry.
 *
 * Duplicates are removed, keeping the first occurrence, because a preference
 * that lists one key twice would make the order meaningless without making the
 * intent any clearer.
 *
 * @param {nsIMsgIdentity} identity
 * @param {string[]} fingerprints - Fingerprints, most preferred first.
 */
export function setKeyList(identity, fingerprints) {
  const seen = new Set();
  const list = [];
  for (const fpr of fingerprints.map(fingerprintOf)) {
    if (fpr && !seen.has(fpr)) {
      seen.add(fpr);
      list.push(fpr);
    }
  }

  identity.setUnicharAttribute(LIST_ATTR, list.join("\n"));
  identity.setUnicharAttribute(
    PRIMARY_ATTR,
    list.length ? keyIdOf(list[0]) : ""
  );
}

/**
 * The key ID for a fingerprint, or the fingerprint itself when the key is not
 * in the ring. `openpgp_key_id` holds a key ID, so a fingerprint written there
 * would still resolve but would stop matching the settings page's comparison.
 *
 * @param {string} fpr
 * @returns {string}
 */
function keyIdOf(fpr) {
  const key = lazy.EnigmailKeyRing.getKeyById(fpr);
  return key ? key.keyId.toUpperCase() : fpr;
}

/**
 * A fingerprint for whatever the caller has -- a fingerprint or a key ID.
 *
 * The list stores fingerprints because a key ID is not unique in principle,
 * but every existing writer of `openpgp_key_id` deals in key IDs, so this is
 * what lets those sites call `setKeyList()` without a conversion of their own.
 * A key that is not in the ring keeps the value it was given.
 *
 * @param {string} value
 * @returns {string}
 */
function fingerprintOf(value) {
  const normalised = normalise(value);
  if (!normalised) {
    return "";
  }
  const key = lazy.EnigmailKeyRing.getKeyById(normalised);
  return key ? normalise(key.fpr) : normalised;
}

/**
 * Whether one key -- a primary or a subkey -- can perform the usage itself.
 *
 * The conditions are the ones the send path already applies: not revoked, not
 * expired, carries the usage, and has its secret material available locally.
 *
 * @param {object} key - An EnigmailKey or an entry of `key.subKeys`.
 * @param {string} usage - "sign" or "encrypt".
 * @returns {boolean}
 */
function canPerform(key, usage) {
  if (!key || key.keyTrust == "r" || key.keyTrust == "e") {
    return false;
  }
  if (!key.secretAvailable) {
    return false;
  }
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (key.expiryTime && key.expiryTime <= nowSeconds) {
    return false;
  }
  return key.keyUseFor.includes(usage == "sign" ? "s" : "e");
}

/**
 * Whether a key can be used to sign or to encrypt, for this identity.
 *
 * Asked of the *key*, not of its primary part, and that distinction is the
 * whole reason this function exists rather than a flag test. Since Item 60 a
 * generated key is a certify-only primary with a signing subkey, so asking
 * whether the primary carries the sign flag answers "no" for exactly the
 * structure this fork now produces -- and a selection rule built on that would
 * skip every key it generated. What matters is whether the key can perform the
 * usage with some part of itself, which is what the send path does when it
 * prefers a subkey and falls back to the primary.
 *
 * A subkey's secret material is what counts for a subkey; a profile exported
 * with `gpg --export-secret-subkeys` has no primary secret and can still sign.
 *
 * @param {object} key - An EnigmailKey.
 * @param {string} usage - "sign" or "encrypt".
 * @returns {boolean}
 */
export function isUsableForKey(key, usage) {
  if (!key) {
    return false;
  }
  if (canPerform(key, usage)) {
    return true;
  }
  return (key.subKeys || []).some(sk => canPerform(sk, usage));
}

/**
 * The first entry of the list that can be used, which is the whole of the
 * selection rule.
 *
 * The order is the user's, so it is read rather than recomputed: an earlier
 * entry always wins over a later one, and an entry that cannot be used is
 * passed over rather than promoted. Skipping is not a ranking -- it answers
 * "can this key be used", not "which key is better" -- and that distinction is
 * what D12's "ask, don't decide" requires.
 *
 * @param {nsIMsgIdentity} identity
 * @param {string} usage - "sign" or "encrypt".
 * @returns {?object} The key, or null when none in the list can be used.
 */
export function firstUsableKey(identity, usage) {
  for (const fpr of getKeyList(identity)) {
    const key = lazy.EnigmailKeyRing.getKeyById(fpr);
    if (isUsableForKey(key, usage)) {
      return key;
    }
  }
  return null;
}

/**
 * @param {nsIMsgIdentity} identity
 * @param {string} usage - "sign" or "encrypt".
 * @returns {object[]} Keys in the list that can be used, in the user's order.
 *   What a chooser should list: the same set the engine will choose from.
 */
export function usableKeys(identity, usage) {
  const result = [];
  for (const fpr of getKeyList(identity)) {
    const key = lazy.EnigmailKeyRing.getKeyById(fpr);
    if (isUsableForKey(key, usage)) {
      result.push(key);
    }
  }
  return result;
}

/**
 * Moves an entry within the list.
 *
 * A move that would fall off either end is a no-op rather than an error: the
 * buttons that call this are disabled at the ends, and a drag that overshoots
 * should do nothing rather than throw.
 *
 * @param {nsIMsgIdentity} identity
 * @param {string} fpr - The entry to move.
 * @param {number} delta - Negative to move earlier, positive to move later.
 * @returns {boolean} true if the order changed.
 */
export function moveKey(identity, fpr, delta) {
  const list = getKeyList(identity);
  const from = list.indexOf(normalise(fpr));
  const to = from + delta;
  if (from < 0 || to < 0 || to >= list.length) {
    return false;
  }
  const [moved] = list.splice(from, 1);
  list.splice(to, 0, moved);
  setKeyList(identity, list);
  return true;
}

/**
 * Adds a key to the end of the list, or leaves the list alone if it is there.
 *
 * Appending rather than prepending is deliberate: adding a key is not a
 * statement that it should be preferred, and a list whose order changes when
 * an unrelated key is added would make the preference unreliable.
 *
 * @param {nsIMsgIdentity} identity
 * @param {string} fpr
 * @returns {boolean} true if the key was added.
 */
export function addKey(identity, fpr) {
  const list = getKeyList(identity);
  const normalised = normalise(fpr);
  if (!normalised || list.includes(normalised)) {
    return false;
  }
  setKeyList(identity, [...list, normalised]);
  return true;
}

/**
 * Removes a key from the list.
 *
 * @param {nsIMsgIdentity} identity
 * @param {string} fpr
 * @returns {boolean} true if the key was present and is now gone.
 */
export function removeKey(identity, fpr) {
  const list = getKeyList(identity);
  const normalised = normalise(fpr);
  if (!list.includes(normalised)) {
    return false;
  }
  setKeyList(
    identity,
    list.filter(f => f != normalised)
  );
  return true;
}
