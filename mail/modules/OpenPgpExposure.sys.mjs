/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * When to tell a user that their secret material sits in an unprotected
 * profile, and in whose words.
 *
 * Design 12.5 splits the audience three ways, and the split is the point:
 *
 *   internal-key      a secret OpenPGP key lives in this profile, so the
 *                     automatic passphrase -- and therefore the key -- is what
 *                     the SDR key protects. Strongest wording.
 *   credentials-only  no internal OpenPGP key, but saved mail passwords or TLS
 *                     client certificates. The same SDR key and the same weak
 *                     derivation, so the notice must name *those*, not
 *                     OpenPGP: telling a GnuPG-only user their GnuPG key is at
 *                     risk would be false.
 *   nothing           silence. Nagging here is how the notice trains itself to
 *                     be ignored on the profiles that need it.
 *
 * Dismissal expires, because a permanent dismissal is how the warning
 * disappears on the profiles that most need it. "Not now" re-arms at the next
 * start; "do not ask again" returns after a stated interval.
 *
 * This module is the decision only. It reads no UI and touches no element, so
 * the rules can be tested without a window.
 */

/**
 * How long "do not ask again" lasts. Thirty days is the design's first value:
 * long enough not to nag, short enough that a profile which never fixed the
 * problem hears about it again.
 */
export const SNOOZE_MS = 30 * 24 * 60 * 60 * 1000;

/** Preference: ISO timestamp of the last "do not ask again", or "". */
export const ACK_PREF = "mail.openpgp.exposure.acknowledged";

/** Preference: true when the user chose "not now" in this session. */
export const NOT_NOW_PREF = "mail.openpgp.exposure.notNow";

/** The three audiences, in the order design 12.5 lists them. */
export const Population = {
  InternalKey: "internal-key",
  CredentialsOnly: "credentials-only",
  Nothing: "nothing",
};

/**
 * Describes what is at risk in a profile.
 *
 * @param {object} input
 * @param {number} [input.secretKeys] Secret keys in the profile ring that
 *   GnuPG does not also hold. A key both stores hold is not internal.
 * @param {number} [input.savedLogins] Saved logins, which the SDR protects.
 * @param {number} [input.clientCerts] TLS client certificates, likewise.
 * @param {boolean} [input.hasPrimaryPassword] Whether one is set. It changes
 *   the wording and never the population: design 1.2 shows a weak derivation
 *   under a password is still weak, so "has a password" is not "safe".
 * @returns {{population: string, secretKeys: number, hasPrimaryPassword: boolean}}
 */
export function assess({
  secretKeys = 0,
  savedLogins = 0,
  clientCerts = 0,
  hasPrimaryPassword = false,
}) {
  if (secretKeys > 0) {
    return {
      population: Population.InternalKey,
      secretKeys,
      hasPrimaryPassword,
    };
  }
  if (savedLogins > 0 || clientCerts > 0) {
    return {
      population: Population.CredentialsOnly,
      secretKeys: 0,
      hasPrimaryPassword,
    };
  }
  return {
    population: Population.Nothing,
    secretKeys: 0,
    hasPrimaryPassword,
  };
}

/**
 * Whether the notice should appear now.
 *
 * Order matters: "nothing to protect" is checked before any dismissal, so a
 * profile that has been cleaned up never sees a notice about it, and the
 * "not now" state is checked before the acknowledgement because it is the
 * shorter-lived of the two.
 *
 * @param {object} input
 * @param {object} input.assessment From `assess()`.
 * @param {boolean} [input.notNow] The user deferred in this session.
 * @param {string} [input.acknowledgedAt] ISO timestamp of the last "do not
 *   ask again", or "".
 * @param {number} [input.now] Milliseconds since the epoch.
 * @param {number} [input.snoozeMs]
 * @returns {{show: boolean, reason: string, population: string}}
 */
export function shouldShow({
  assessment,
  notNow = false,
  acknowledgedAt = "",
  now = Date.now(),
  snoozeMs = SNOOZE_MS,
}) {
  const population = assessment?.population ?? Population.Nothing;

  if (population === Population.Nothing) {
    return { show: false, reason: "nothing-to-protect", population };
  }
  if (notNow) {
    return { show: false, reason: "deferred-this-session", population };
  }
  if (acknowledgedAt) {
    const at = Date.parse(acknowledgedAt);
    if (Number.isFinite(at) && now - at < snoozeMs) {
      return { show: false, reason: "acknowledged", population };
    }
    if (!Number.isFinite(at)) {
      // An unparseable timestamp is treated as expired rather than as a
      // permanent silence: a corrupted preference must not hide the notice
      // forever on the profile that needs it.
      return { show: true, reason: "acknowledgement-unreadable", population };
    }
    return { show: true, reason: "acknowledgement-expired", population };
  }
  return { show: true, reason: "no-dismissal", population };
}
