/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/** The dialog that sets a Primary Password. */
const CHANGEMP_URL = "chrome://mozapps/content/preferences/changemp.xhtml";

/** A token instance, read fresh because `hasPassword` changes. */
function keyToken() {
  return Cc["@mozilla.org/security/internalkeytoken;1"].createInstance(
    Ci.nsIPKCS11Token
  );
}

/**
 * Enforces the PrimaryPassword enterprise policy before saving a credential.
 *
 * When the policy is active, a primary password must protect the login store.
 * If none is set the user is prompted to create one.
 *
 * Note that this returns `true` immediately when the policy is not active,
 * which is the ordinary case for every non-enterprise profile. It therefore
 * enforces a *policy*, not the presence of a password. Code that needs a
 * password regardless of policy must not use this function.
 *
 * @param {nsIWindow} [win] Parent for the dialog. Defaults to the most recent
 *   window, which is what every pre-existing caller gets.
 * @returns {boolean} true if saving may proceed, false if the user declined.
 */
export function enforcePrimaryPassword(win = null) {
  if (Services.policies.isAllowed("removeMasterPassword")) {
    return true;
  }
  if (keyToken().hasPassword) {
    return true;
  }
  const parent = win ?? Services.wm.getMostRecentWindow(null);
  if (!parent) {
    // No window means no dialog, and D7 requires a refusal to carry a route
    // forward. Rather than refuse with nowhere to go, report that the
    // requirement is unmet and let the caller decide; the caller's own error
    // is then the only thing the user sees, which is why every real caller
    // passes a window.
    return false;
  }
  parent.openDialog(CHANGEMP_URL, "", "centerscreen,chrome,modal,titlebar");
  return keyToken().hasPassword;
}
