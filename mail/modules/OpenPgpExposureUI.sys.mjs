/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * The OpenPGP exposure notice: where it appears and what it says.
 *
 * `OpenPgpExposure.sys.mjs` decides *whether* a profile should be told that its
 * secret store is weaker than a GnuPG keyring; this module is the half that
 * counts what a profile actually holds and puts a banner in front of the user.
 * The split matters: the decision is pure and fully tested without a window,
 * and everything here is the part that needs one.
 *
 * Two placements, one message. The thread pane because that is where a user
 * starts their day, and the message pane because that is where they read. The
 * same banner appears in whichever is on screen rather than in both, so a
 * profile that has been told is not told twice at once.
 *
 * What this notice is not: a nag that cannot be dismissed, or one that returns
 * without being asked. "Not now" defers it for the session; "do not ask again"
 * records a timestamp and the notice returns after the snooze, because a
 * profile that has since acquired an internal key is a different situation and
 * silence would be wrong.
 */

import * as OpenPgpExposure from "resource:///modules/OpenPgpExposure.sys.mjs";

const lazy = {};

ChromeUtils.defineESModuleGetters(lazy, {
  EnigmailKeyRing: "chrome://openpgp/content/modules/keyRing.sys.mjs",
});

const l10n = new Localization(["messenger/openpgp/openpgp.ftl"], true);

/** The notification value, so a second call replaces rather than duplicates. */
const NOTIFICATION_VALUE = "openpgp-exposure";

/**
 * Counts the OpenPGP secret keys this profile holds that GnuPG does not.
 *
 * A key both stores hold is not an internal key: the risk being described is
 * the secret material living only in the profile's own store. Keys without
 * secret material are irrelevant here and are skipped.
 *
 * @returns {Promise<number>}
 */
export async function countInternalSecretKeys() {
  let keys;
  try {
    keys = lazy.EnigmailKeyRing.getAllKeys(null, null).keyList;
  } catch (ex) {
    // No OpenPGP at all, or a ring that could not be read. Either way there is
    // nothing this notice could say that would be true.
    console.warn("OpenPGP exposure: could not read the keyring", ex);
    return 0;
  }
  return keys.filter(key => key.secretAvailable && !key.gnuPgKeys?.has).length;
}

/**
 * Counts saved logins, which the profile's secret store protects.
 *
 * Asynchronous because the login manager's API is: `countLogins` was removed in
 * favour of `countLoginsAsync`. Calling the old name threw, the catch below
 * swallowed it, and every profile was reported as having no saved logins --
 * which is the "nothing to protect" population, whose notice is correctly
 * silent. Found by noticing the notice never appeared for a profile that had a
 * login added to it.
 *
 * @returns {Promise<number>} The count, or 0 when the manager cannot answer.
 */
async function countSavedLogins() {
  try {
    return await Services.logins.countLoginsAsync("", "", null);
  } catch (ex) {
    console.warn("OpenPGP exposure: could not count saved logins", ex);
    return 0;
  }
}

/**
 * Gathers everything the assessment needs.
 *
 * @returns {object} Arguments for `OpenPgpExposure.assess()`.
 */
export async function surveyProfile() {
  let savedLogins = 0;
  let clientCerts = 0;
  let hasPrimaryPassword = false;
  try {
    savedLogins = await countSavedLogins();
    hasPrimaryPassword = Cc[
      "@mozilla.org/security/internalkeytoken;1"
    ].createInstance(Ci.nsIPKCS11Token).hasPassword;
    const certDb = Cc["@mozilla.org/security/x509certdb;1"].getService(
      Ci.nsIX509CertDB
    );
    clientCerts = certDb.getCerts().filter(cert => cert.isValid()).length;
  } catch (ex) {
    console.warn("OpenPGP exposure: could not survey the profile", ex);
  }
  return { savedLogins, clientCerts, hasPrimaryPassword };
}

/**
 * Works out whether to show the notice, doing the async parts first.
 *
 * @returns {Promise<{show: boolean, reason: string, population: string,
 *   secretKeys: number, hasPrimaryPassword: boolean}>}
 */
export async function decide() {
  const survey = await surveyProfile();
  const secretKeys = await countInternalSecretKeys();
  const assessment = OpenPgpExposure.assess({ ...survey, secretKeys });

  const prefs = Services.prefs;
  return {
    ...OpenPgpExposure.shouldShow({
      assessment,
      notNow: prefs.getBoolPref(OpenPgpExposure.NOT_NOW_PREF, false),
      acknowledgedAt: prefs.getStringPref(OpenPgpExposure.ACK_PREF, ""),
    }),
    secretKeys,
    hasPrimaryPassword: assessment.hasPrimaryPassword,
  };
}

/**
 * The strings and button the notice needs, chosen for its population.
 *
 * @param {object} decision From `decide()`.
 * @returns {{label: object, buttons: object[]}}
 */
async function contentFor(decision) {
  const internal =
    decision.population === OpenPgpExposure.Population.InternalKey;
  const buttonLabels = await l10n.formatValues([
    { id: "openpgp-exposure-not-now" },
    { id: "openpgp-exposure-dismiss" },
  ]);

  return {
    label: {
      "l10n-id": internal
        ? "openpgp-exposure-internal-key"
        : "openpgp-exposure-credentials",
      "l10n-args": { keys: decision.secretKeys },
    },
    buttons: [
      {
        label: buttonLabels[0],
        callback() {
          Services.prefs.setBoolPref(OpenPgpExposure.NOT_NOW_PREF, true);
          return false;
        },
      },
      {
        label: buttonLabels[1],
        callback() {
          Services.prefs.setStringPref(
            OpenPgpExposure.ACK_PREF,
            new Date().toISOString()
          );
          return false;
        },
      },
    ],
  };
}

/**
 * Puts the notice into the given notification box, or removes it.
 *
 * Idempotent by value: called twice, the second call replaces the first rather
 * than stacking. Called when the answer is "do not show", it removes anything
 * already there -- which is what makes the notice disappear when a user
 * upgrades to a GnuPG keyring mid-session.
 *
 * @param {MozElements.NotificationBox} box
 * @returns {Promise<boolean>} true if the notice is showing.
 */
export async function refreshNotice(box) {
  if (!box) {
    return false;
  }
  const decision = await decide();
  if (!decision.show) {
    const existing = box.getNotificationWithValue(NOTIFICATION_VALUE);
    if (existing) {
      existing.close();
    }
    return false;
  }

  const { label, buttons } = await contentFor(decision);
  await box.appendNotification(
    NOTIFICATION_VALUE,
    { label, priority: box.PRIORITY_INFO_MEDIUM },
    buttons
  );
  return true;
}

/** The notification value, exposed so tests can find what this made. */
export const EXPOSURE_NOTIFICATION = NOTIFICATION_VALUE;
