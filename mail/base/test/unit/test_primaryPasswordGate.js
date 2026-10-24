/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

// Tests for the contract the OpenPGP key paths rely on when they call
// `enforcePrimaryPassword()`. The policy-active branch opens a modal dialog
// and belongs to a browser test; what is checked here is the default branch,
// which decides whether this helper does anything at all for an ordinary
// profile.

const { enforcePrimaryPassword } = ChromeUtils.importESModule(
  "resource:///modules/PrimaryPassword.sys.mjs"
);

/**
 * A window that fails the test if anything tries to open a dialog in it.
 *
 * @returns {object} A stand-in with an `openDialog` that throws.
 */
function windowThatMustNotPrompt() {
  return {
    openDialog() {
      throw new Error(
        "enforcePrimaryPassword() opened a dialog when no PrimaryPassword " +
          "policy is active. That branch would hang any headless caller and " +
          "breaks the browser tests that generate keys without a password."
      );
    },
  };
}

add_task(async function test_permits_without_the_policy() {
  // The ordinary case: no `PrimaryPassword: true` enterprise policy. The
  // helper returns true without looking at the token and without prompting,
  // which is what makes it safe to call from the key paths on every profile.
  Assert.ok(
    Services.policies.isAllowed("removeMasterPassword"),
    "this test assumes no PrimaryPassword policy is active"
  );
  Assert.equal(
    enforcePrimaryPassword(windowThatMustNotPrompt()),
    true,
    "without the policy the helper must permit, not prompt"
  );
});

add_task(async function test_accepts_an_explicit_parent_window() {
  // The import path passes the window it already has, rather than relying on
  // "most recent window". With the policy inactive it must still permit.
  const win = windowThatMustNotPrompt();
  Assert.equal(enforcePrimaryPassword(win), true);
  Assert.equal(
    enforcePrimaryPassword(null),
    true,
    "a null parent is permitted"
  );
});

add_task(async function test_is_idempotent() {
  // Both key paths may call it; a second call must not change anything.
  const win = windowThatMustNotPrompt();
  Assert.equal(enforcePrimaryPassword(win), true);
  Assert.equal(enforcePrimaryPassword(win), true);
});
