/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 73 / D7: a refusal must carry a route forward.
 *
 * The claim is narrow and testable: when the `PrimaryPassword` enterprise policy
 * is active and no password is set, the OpenPGP paths that write secret material
 * refuse, and the refusal opens the dialog that fixes it. Verified by refusing,
 * cancelling and completing — not by reading the code.
 *
 * Scoped to the gate's contract rather than to the key wizard.
 * `browser_keyWizard.js` is excluded on Linux and headless (bug 1806870), so the
 * wizard cannot be driven here; what can be driven is the function both key
 * paths call, through the real changemp dialog. That is what the item's sentence
 * is about — "the change-password dialog opens from the refusal" — and the call
 * sites are asserted separately so a path that stopped calling the gate fails
 * rather than passing quietly.
 *
 * Every wait here is bounded. The first version of this test hung for 47
 * seconds because the policy was never activated, the gate returned true
 * without opening anything, and an unbounded wait on the dialog had nothing to
 * wait for.
 */

"use strict";

const { enforcePrimaryPassword } = ChromeUtils.importESModule(
  "resource:///modules/PrimaryPassword.sys.mjs"
);
const { LoginTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/LoginTestUtils.sys.mjs"
);
const { EnterprisePolicyTesting } = ChromeUtils.importESModule(
  "resource://testing-common/EnterprisePolicyTesting.sys.mjs"
);

// The exact URL `PrimaryPassword.sys.mjs` opens. Dropping `/preferences/` here
// was a 7-minute hang: the dialog opened under the real URL, the observer never
// matched it, and nothing answered the modal. Copied from the module rather than
// typed from memory, and asserted against it below so it cannot drift again.
const CHANGEMP_URL = "chrome://mozapps/content/preferences/changemp.xhtml";
const POLICIES = { policies: { PrimaryPassword: true } };
const STEP_TIMEOUT_MS = 15000;

/**
 * @returns {nsIPKCS11Token} The internal key token, read fresh.
 */
function keyToken() {
  return Cc["@mozilla.org/security/internalkeytoken;1"].createInstance(
    Ci.nsIPKCS11Token
  );
}

/**
 * Fails a promise after a fixed time, with a reason rather than a timeout.
 *
 * @param {Promise} promise
 * @param {string} message - What did not happen.
 * @returns {Promise} The original value, or a rejection carrying `message`.
 */
function bounded(promise, message) {
  let timer;
  const expiry = new Promise((_, reject) => {
    // eslint-disable-next-line mozilla/no-arbitrary-setTimeout
    timer = setTimeout(() => reject(new Error(message)), STEP_TIMEOUT_MS);
  });
  return Promise.race([promise, expiry]).finally(() => clearTimeout(timer));
}

/**
 * Calls the gate and answers the dialog it opens.
 *
 * `promiseAlertDialogOpen` is the only form that works here: the gate opens its
 * dialog modally, so it does not return until the dialog closes, which means
 * nothing on the calling stack can answer it. The observer runs inside the
 * nested event loop, and that is where the answering happens.
 *
 * **What the bound below can and cannot do.** `enforcePrimaryPassword()` is
 * synchronous, so the `await` on `dialogShown` is downstream of it: if the
 * dialog opens and nothing answers it, the bound never runs. It catches the
 * other failure -- the gate returning without opening anything, which leaves a
 * promise that would otherwise wait forever -- and that is the one it can catch.
 * A modal that opens and is never answered is bounded only by the harness, which
 * is why the URL above is copied from the product rather than trusted.
 *
 * @param {string|function(Window):Promise} answer - A button name, or a callback
 *   receiving the dialog window.
 * @returns {Promise<boolean>} What `enforcePrimaryPassword()` returned.
 */
async function enforceAndAnswer(answer) {
  // `options` is the *third* argument of promiseAlertDialogOpen. Passing a
  // callback first made it the button name instead: `getButton(fn)` returned
  // null, `element.click()` threw inside the observer, the modal was never
  // answered, and the whole run hung. A name string takes the first-argument
  // form; a callback must go in the options object.
  const dialogShown =
    typeof answer == "function"
      ? BrowserTestUtils.promiseAlertDialogOpen(null, CHANGEMP_URL, {
          callback: answer,
        })
      : BrowserTestUtils.promiseAlertDialogOpen(answer, CHANGEMP_URL);
  const result = enforcePrimaryPassword(window);
  await bounded(
    dialogShown,
    "enforcePrimaryPassword() did not open the change-password dialog"
  );
  return result;
}

/**
 * Types into a field of the change-password dialog.
 *
 * @param {Window} win - The dialog.
 * @param {string} id - Field id.
 * @param {string} value
 */
async function typeInto(win, id, value) {
  const field = win.document.getElementById(id);
  EventUtils.synthesizeMouseAtCenter(field, {}, win);
  EventUtils.sendString(value, win);
  await new Promise(resolve => win.requestAnimationFrame(resolve));
  Assert.equal(field.value, value, `the ${id} field should hold the value`);
}

add_setup(async function () {
  await EnterprisePolicyTesting.setupPolicyEngineWithJson(POLICIES);
  registerCleanupFunction(async () => {
    await EnterprisePolicyTesting.setupPolicyEngineWithJson({ policies: {} });
    await LoginTestUtils.primaryPassword.disable();
  });
});

/**
 * The test's idea of the dialog URL must be the product's.
 *
 * A mismatch does not fail loudly -- it hangs, because the modal opens under one
 * URL and the observer waits for another. Asserting it costs one `fetch` and
 * turns that hang into a named failure.
 */
add_task(async function theDialogUrlMatchesTheProduct() {
  const source = await fetch(
    "resource:///modules/PrimaryPassword.sys.mjs"
  ).then(r => r.text());
  const match = source.match(/const CHANGEMP_URL = "([^"]+)"/);
  Assert.ok(match, "PrimaryPassword.sys.mjs should declare CHANGEMP_URL");
  Assert.equal(
    CHANGEMP_URL,
    match[1],
    "this test must watch the same URL the product opens"
  );
});

/**
 * The refusal opens the dialog that fixes it, and cancelling refuses.
 *
 * This is the whole of D7: refusing without a route leaves the user with an
 * error and no way forward. Cancelling is what distinguishes "opened" from
 * "opened and then enforced nothing".
 */
add_task(async function refusingOpensTheDialogAndCancelRefuses() {
  Assert.ok(
    !keyToken().hasPassword,
    "the profile starts with no Primary Password"
  );
  Assert.ok(
    !Services.policies.isAllowed("removeMasterPassword"),
    "and the PrimaryPassword policy is active"
  );

  const result = await enforceAndAnswer("cancel");

  Assert.equal(
    result,
    false,
    "cancelling must refuse, so the caller does not write secret material"
  );
  Assert.ok(
    !keyToken().hasPassword,
    "with no password set as a result of cancelling"
  );
});

/**
 * Completing the dialog lets the original action proceed.
 *
 * The route has to *work*, not merely exist: a dialog that could be completed
 * while the gate kept refusing would be a dead end with extra steps.
 */
add_task(async function completingTheDialogAllowsTheAction() {
  const strong = "Tandem-Whistle-Bramble-Quiver-Magnet9!";

  const result = await enforceAndAnswer(async dialogWindow => {
    // Waits on the *button*, not only the fields: `getButton("accept")` returns
    // null until the dialog has finished constructing itself, and clicking a
    // null throws inside the observer -- which kills the answer and hangs the
    // modal. Waiting on what is about to be used is the cheap version.
    await TestUtils.waitForCondition(
      () =>
        dialogWindow.document.getElementById("pw1") &&
        dialogWindow.document.getElementById("changemp")?.getButton("accept"),
      "the change-password dialog should be fully constructed"
    );
    await typeInto(dialogWindow, "pw1", strong);
    await typeInto(dialogWindow, "pw2", strong);

    // A successful change opens a *second* modal, "Password Change Succeeded",
    // before the change-password dialog closes. Nothing after the click runs
    // until that alert is dismissed, so the click below would block forever and
    // `enforcePrimaryPassword()` would never return. Arranged here, from inside
    // the outer observer, because that is the only place running in the nested
    // loop while the alert is up.
    //
    // The same alert is handled the same way in browser_primaryPasswordPolicy.js;
    // it cost a run there too.
    // `promiseAlertDialogOpen`, not `promiseAlertDialog`. The latter clicks the
    // button from the observer and *then* waits for the window to close, which
    // is fragile when the click destroys it -- the same shape that hung an
    // earlier version of this file. Clicking from the observer and not waiting
    // for the close is all that is needed: the outer dialog closing is the
    // signal that everything finished.
    const succeeded = BrowserTestUtils.promiseAlertDialogOpen(
      "accept",
      "chrome://global/content/commonDialog.xhtml"
    );
    dialogWindow.document
      .getElementById("changemp")
      .getButton("accept")
      .click();
    await bounded(
      succeeded,
      "the success alert was never dismissed, so the change did not complete"
    );
  });

  Assert.ok(
    keyToken().hasPassword,
    "accepting should have set the Primary Password"
  );
  Assert.equal(
    result,
    true,
    "and the original action should be allowed to proceed"
  );
});

/**
 * With a password already set the gate does not interrupt.
 *
 * A dialog on every key operation would be worse than the gap it closed, so the
 * "already satisfied" branch is asserted rather than assumed. No dialog is
 * arranged, so one opening would fail the suite rather than pass quietly.
 */
add_task(async function anExistingPasswordIsNotPromptedForAgain() {
  Assert.ok(
    keyToken().hasPassword,
    "a password is in force from the last task"
  );

  Assert.equal(
    enforcePrimaryPassword(window),
    true,
    "a profile that already satisfies the policy must not be prompted"
  );
});

/**
 * And both key paths are asserted to call the gate.
 *
 * Read from the product source rather than by driving the wizard, which is
 * excluded on this platform. A path that stopped calling the gate is the
 * failure this item exists to prevent, so the count is asserted rather than the
 * presence of a single call.
 */
add_task(async function bothKeyPathsCallTheGate() {
  const response = await fetch("chrome://openpgp/content/ui/keyWizard.js");
  const source = await response.text();

  // Counts *calls*, not mentions. A plain `/enforcePrimaryPassword\(/g` matched
  // the word in a comment above the import-path call as well, which failed this
  // assertion at 3 == 2 while the code was correct. Comments end at the newline,
  // so requiring the name to be the first thing on its statement is enough to
  // exclude them.
  const calls =
    source.match(/^\s*if \(!enforcePrimaryPassword\(window\)\)/gm) ?? [];
  Assert.equal(
    calls.length,
    2,
    `key generation and secret-key import must both call the gate, found ` +
      `${calls.length} call(s)`
  );
  Assert.ok(
    source.includes("openPgpImportStart"),
    "and the import path is still the one this item added the call to"
  );
});
