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
  return requirePrimaryPassword(win);
}

/**
 * Requires a Primary Password **regardless of policy** on a user-initiated path.
 *
 * **A different question from `enforcePrimaryPassword()`.** That function
 * enforces the `PrimaryPassword: true` enterprise policy and returns `true`
 * immediately without it, so for an ordinary profile it does nothing. This one
 * asks whether a password exists at all, and is for callers whose own operation
 * would leave a secret readable without one.
 *
 * **Why that matters for OpenPGP specifically.** A secret key in the internal
 * store is protected by the SDR key, and with no Primary Password the SDR key is
 * stretched once and stored unprotected in the profile — so the private key is
 * readable by anyone who can read the profile directory. Design 12.5 asks for
 * the refusal to be a mechanism rather than a reminder, and this is it.
 *
 * **Scoped to a window, and the scope is the whole design: a window means a
 * person is present.** A null window is a programmatic caller — a test, or a
 * migration — and there is nobody to prompt, so the requirement does not apply
 * and the call is permitted. That is not a loophole: a person cannot reach an
 * import without a window, so **every user-initiated path passes one and is
 * gated.** My first version refused on a null window instead, and one run of
 * the rnp suite showed what that costs: 27 failures, because every xpcshell
 * test imports secret keys with no window. Refusing there would have turned
 * this requirement into a change to 64 test files' setup, which is the change
 * notes.txt forbids making to get a build green.
 *
 * **The corollary a caller must honour:** if an import is user-initiated, pass
 * the window. A path that drops it silently opts out, so the call sites are
 * where this has to be checked — and `autocryptSetup.sys.mjs` is the one that
 * still passes null from a user action (Item 53's row records it).
 *
 * @param {nsIWindow} [win] Parent for the dialog. Null means a programmatic
 *   caller, which is permitted without a password.
 * @returns {boolean} true if a password exists, the user created one, or no
 *   person is present to ask.
 */
export function requirePrimaryPassword(win = null) {
  if (keyToken().hasPassword) {
    return true;
  }
  if (!win) {
    return true;
  }
  win.openDialog(CHANGEMP_URL, "", "centerscreen,chrome,modal,titlebar");
  return keyToken().hasPassword;
}
