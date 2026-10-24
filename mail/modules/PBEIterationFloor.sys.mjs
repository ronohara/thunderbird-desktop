/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Raises the NSS key-database derivation floor from a preference.
 *
 * NSS derives the key protecting key4.db with PBKDF2-HMAC-SHA256 and, for a
 * database that has a Primary Password, uses `NSS_MP_PBE_ITERATION_COUNT` --
 * a compiled-in 10,000 -- as the iteration count. That constant is not
 * adjustable through an API, but softoken reads two environment variables
 * around it on every call to `getPBEIterationCount()`
 * (security/nss/lib/softoken/sftkpwd.c):
 *
 *   NSS_MIN_MP_PBE_ITERATION_COUNT  raises the floor
 *   NSS_MAX_MP_PBE_ITERATION_COUNT  caps it (the test harness uses this)
 *
 * So the count can be raised without patching NSS, provided the variable is
 * in the environment before the first password-based operation on the
 * database.
 *
 * A preference rather than a line in the launcher, and the reasons are in
 * design 12.3: a desktop-entry `env` line is invisible to the user, absent
 * when the binary is run directly, and overridable by anything that launches
 * the application -- including an attacker, which matters because this value
 * governs the protection being relied on. A preference can be locked by
 * policy, and the derived state can be reported in the same place the user
 * reads whether a Primary Password is set.
 */

const ENV_VAR = "NSS_MIN_MP_PBE_ITERATION_COUNT";

/**
 * The preference holding the floor. Named for what it does rather than for
 * the derivation function: an administrator reading a policy file should not
 * need to know what PBKDF2 stands for.
 *
 * A value of 0 or less means "leave NSS's own minimum alone", which is the
 * default. Nothing here chooses the shipped value -- that is a separate
 * decision (design 12.1, plan Item 74), recorded once so the number cannot
 * drift between code and document.
 */
export const PREF = "mail.e2ee.primary_password_min_iteration_count";

/**
 * Applies the preference to the environment.
 *
 * Called once, from MailGlue's app-startup handler. That is the earliest
 * point at which both of the following are true, and both are required:
 *
 *   - user preferences are loaded (nsAppRunner.cpp finishes
 *     FinishInitializingUserPrefs() before the app-startup category is
 *     created), so a value set in prefs.js or by policy is visible; and
 *   - NSS has not been initialised. Thunderbird forces NSS up early in
 *     nsXREDirProvider::DoStartup() when
 *     security.prompt_for_master_password_on_startup is set, and DoStartup
 *     runs after the app-startup category.
 *
 * Getting this wrong is silent: an export after NSS_Init has no effect until
 * the next start, because softoken has already derived the key.
 *
 * A preference that is set overrides an inherited environment variable, so a
 * locked policy cannot be defeated by whatever launched the application. When
 * the preference is not set, an inherited variable is left in place: someone
 * who exported it deliberately keeps it.
 *
 * @param {nsIPrefBranch} [prefs] Branch to read, for tests. Defaults to the
 *   root branch.
 * @param {nsIEnvironment} [env] Environment to write, for tests. Defaults to
 *   the process environment.
 * @returns {{applied: boolean, value: number, previous: string|null}}
 *   `applied` is false when the preference asks for nothing; `value` is the
 *   floor that is now in force; `previous` is what the variable held before,
 *   either null or a string, so a caller can report a change.
 */
export function applyPBEIterationFloor(prefs, env) {
  prefs ??= Services.prefs;
  env ??= Services.env;

  const previous = env.exists(ENV_VAR) ? env.get(ENV_VAR) : null;
  const value = prefs.getIntPref(PREF, 0);

  if (!Number.isFinite(value) || value <= 0) {
    // Nothing asked for. If something in the environment already sets a
    // floor, report it, because that is the number actually in force and a
    // reader of the derived state should not be told otherwise.
    const inherited = previous ? Number.parseInt(previous, 10) : 0;
    return {
      applied: false,
      value: Number.isFinite(inherited) ? inherited : 0,
      previous,
    };
  }

  env.set(ENV_VAR, String(value));

  if (previous && previous !== String(value)) {
    console.warn(
      `PBE iteration floor: ${ENV_VAR} was "${previous}", overridden by ` +
        `${PREF}=${value}`
    );
  }

  return { applied: true, value, previous };
}

/**
 * Reads back the floor that softoken will use, from the environment rather
 * than from the preference, so a caller reports what is in force instead of
 * what was requested. This is the value Item 52 reads alongside the count
 * stored in the database.
 *
 * @returns {number} The floor, or 0 when nothing sets one.
 */
export function currentPBEIterationFloor() {
  const env = Services.env;
  if (!env.exists(ENV_VAR)) {
    return 0;
  }
  const value = Number.parseInt(env.get(ENV_VAR), 10);
  return Number.isFinite(value) && value > 0 ? value : 0;
}
