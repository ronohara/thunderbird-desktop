/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 61 in the UI: the structure tab offers adding a signing subkey and an
 * encryption subkey, and doing so leaves the key's identity alone.
 *
 * The unit test (test_addSubkey.js) covers RNP.addSubkey() itself. This one
 * exists because that is not the same claim: the buttons have to be offered
 * for a key that can take a subkey, hidden for one that cannot, and the click
 * has to reach the RNP path and come back with the dialog showing the new
 * subkey. A button that is wired to nothing passes a unit test.
 *
 * Every wait in this file is bounded. A hang is the worst failure a browser
 * test can have: it costs the harness's whole 370-second budget for the file
 * and reports nothing about which step stopped. Ten seconds is far longer
 * than any of these steps needs and far shorter than that budget.
 */

"use strict";

const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { EnigmailWindows } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/windows.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);

const KEY_DETAILS_URL = "chrome://openpgp/content/ui/keyDetailsDlg.xhtml";

const ALICE_KEY_ID = "0xf231550c4f47e38e";

/** Longest any single step here may take, in milliseconds. */
const STEP_TIMEOUT_MS = 10000;

function keyFile(name) {
  return new FileUtils.File(getTestFilePath(`data/keys/${name}`));
}

/**
 * Fails a promise after a fixed time, with the reason rather than a timeout.
 *
 * `TestUtils.waitForCondition` already gives up after about five seconds, so
 * only the event-based waits need this. The point is that a wrong selector
 * or a prompt that never opens reports which step it was, instead of leaving
 * the harness to kill the file minutes later with no message.
 *
 * @param {Promise} promise - The wait to bound.
 * @param {string} message - What did not happen.
 * @returns {Promise} The original value, or a rejection carrying `message`.
 */
function bounded(promise, message) {
  let timer;
  const expiry = new Promise((_, reject) => {
    // The rule against arbitrary delays exists to stop tests papering over
    // races with a sleep. This is the opposite use: a deliberate ceiling on a
    // wait that has no timeout of its own, so that the failure is a message
    // naming the step rather than a harness kill minutes later.
    // eslint-disable-next-line mozilla/no-arbitrary-setTimeout
    timer = setTimeout(() => reject(new Error(message)), STEP_TIMEOUT_MS);
  });
  return Promise.race([promise, expiry]).finally(() => clearTimeout(timer));
}

/**
 * Open the key details dialog and run the given function inside it. The
 * dialog is modal, so everything has to happen in the callback.
 *
 * @param {string} keyId - A key in the keyring.
 * @param {function(Window):Promise} checks - Receives the dialog window, not
 *   its document: `EventUtils.synthesizeMouseAtCenter` takes a window as its
 *   third argument, and passing a document there is silently wrong -- the
 *   click is not delivered, the prompt never opens, and the test waits.
 */
async function withKeyDetails(keyId, checks) {
  const onDialogLoaded = async function (dialogWindow) {
    // Closed in a finally that covers everything, including the wait below:
    // the dialog is modal, so any throw on this path leaves the whole harness
    // blocked rather than merely failing one task.
    try {
      await TestUtils.waitForCondition(
        () => dialogWindow.document.getElementById("keyId")?.value,
        "the key details should have loaded"
      );
      await checks(dialogWindow);
    } finally {
      dialogWindow.close();
    }
  };

  const dialogPromise = BrowserTestUtils.promiseAlertDialog(
    null,
    KEY_DETAILS_URL,
    { callback: onDialogLoaded }
  );
  // Returns only after the dialog has been closed.
  await EnigmailWindows.openKeyDetails(window, keyId, false);
  await dialogPromise;
}

/**
 * @param {Document} doc
 */
function selectStructureTab(doc) {
  doc.getElementById("mainTabs").selectedTab =
    doc.getElementById("structureTab");
}

/**
 * @param {Document} doc
 * @returns {integer} Rows currently shown in the subkey list.
 */
function subkeyRowCount(doc) {
  return doc.getElementById("subkeyList").view.rowCount;
}

/**
 * Click an add-subkey button and accept its confirmation.
 *
 * The button name is passed *into* `promiseAlertDialogOpen()` rather than the
 * window being clicked afterwards, and that is not a style choice -- it is the
 * difference between working and deadlocking.
 *
 * `addSubkey()` calls `Services.prompt.confirm()` synchronously in its click
 * handler, before any await, so `synthesizeMouseAtCenter` below enters a
 * nested event loop and does not return until the dialog is answered. Any code
 * in *this* function placed after the click therefore cannot run: it is queued
 * behind a call that is waiting for it. A bound written after the click is
 * decoration -- observed, when a ten-second timeout failed to fire while the
 * main thread slept for five minutes in `openPromptSync`.
 *
 * `promiseAlertDialogOpen(name)` clicks the button from inside its own
 * `common-dialog-loaded` observer (BrowserTestUtils.sys.mjs:2905), which runs
 * in the nested loop. That is what lets the click return. Same reason
 * `browser_messageFilters.js` passes a callback for its delete confirmation.
 *
 * @param {Window} win - The dialog window.
 * @param {string} buttonId
 */
async function clickAndAccept(win, buttonId) {
  const button = win.document.getElementById(buttonId);
  Assert.ok(button, `the ${buttonId} button exists`);
  Assert.ok(!button.hidden, `the ${buttonId} button is visible`);

  // "accept" is the confirmation's affirmative button. Answered from inside
  // the observer, so the click below can return.
  const promptPromise = BrowserTestUtils.promiseAlertDialogOpen("accept");
  EventUtils.synthesizeMouseAtCenter(button, {}, win);
  await bounded(
    promptPromise,
    `the confirmation for ${buttonId} was opened but never closed`
  );
}

add_setup(async function () {
  await OpenPGPTestUtils.importPrivateKey(
    window,
    keyFile("alice@openpgp.example-0xf231550c4f47e38e-secret.asc")
  );
});

/**
 * A key whose secret material is present offers both buttons, and only on the
 * structure tab -- they act on the list of subkeys shown there.
 */
add_task(async function testButtonsAreOfferedOnTheStructureTab() {
  await withKeyDetails(ALICE_KEY_ID, async win => {
    const doc = win.document;
    selectStructureTab(doc);

    const signing = doc.getElementById("addSigningSubkeyButton");
    const encryption = doc.getElementById("addEncryptionSubkeyButton");
    Assert.ok(!signing.hidden, "the add-signing-subkey button is shown");
    Assert.ok(!encryption.hidden, "the add-encryption-subkey button is shown");

    // Switching away hides them, because they would act on a list that is no
    // longer on screen. Asserted by waiting for the outcome, not for the
    // "select" event: a wait on the event hangs if the tab id is wrong, where
    // a wait on the outcome fails with a message.
    doc.getElementById("mainTabs").selectedTab =
      doc.getElementById("acceptanceTab");
    await TestUtils.waitForCondition(
      () => signing.hidden,
      "the signing button should be hidden once another tab is selected"
    );
    Assert.ok(signing.hidden, "the signing button is hidden on another tab");
    Assert.ok(
      encryption.hidden,
      "the encryption button is hidden on another tab"
    );
  });
});

/**
 * Clicking the button adds a subkey, and the dialog shows it without being
 * reopened: the refresh after the change is part of what the button has to do.
 */
add_task(async function testAddSigningSubkeyFromTheDialog() {
  // The Structure tab lists the primary as its first row, so its row count is
  // subkeys + 1 (SubkeyListView sets `rowCount = subKeys.length + 1`). Rows
  // and subkeys are therefore different quantities, and comparing one to the
  // other is what made this test fail while the feature worked.
  let rowsBefore = 0;
  const before = new Set();

  await withKeyDetails(ALICE_KEY_ID, async win => {
    const doc = win.document;
    selectStructureTab(doc);

    rowsBefore = subkeyRowCount(doc);
    Assert.greater(rowsBefore, 1, "the key has a subkey to begin with");

    // The fixtures' fingerprints, captured inside the dialog so the comparison
    // afterwards is "what was added" rather than "what looks new".
    for (const sk of EnigmailKeyRing.getKeyById(ALICE_KEY_ID).subKeys) {
      before.add(sk.fpr);
    }

    await clickAndAccept(win, "addSigningSubkeyButton");

    await TestUtils.waitForCondition(
      () => subkeyRowCount(doc) == rowsBefore + 1,
      `the subkey list should gain a row, ${rowsBefore} -> ${rowsBefore + 1}`
    );

    // The key itself must still be the same key. A subkey that arrives by
    // replacing the primary would leave the user with a new identity.
    Assert.equal(
      doc.getElementById("keyId").value,
      "F231550C4F47E38E",
      "the primary key is unchanged"
    );
  });

  // And it persisted, rather than only looking right in the open dialog.
  EnigmailKeyRing.clearCache();
  const key = EnigmailKeyRing.getKeyById(ALICE_KEY_ID);
  Assert.ok(key, "the key is still in the keyring");

  // What was added, by fingerprint. Alice's fixture has one encryption subkey
  // and no signing subkey, which is what makes "the new one signs" a real
  // assertion rather than a restatement of what was already there.
  const added = key.subKeys.filter(sk => !before.has(sk.fpr));
  Assert.equal(added.length, 1, "exactly one subkey was added");

  Assert.equal(
    added[0].keyUseFor,
    "s",
    `the added subkey signs and does nothing else, usage "${added[0].keyUseFor}"`
  );
  Assert.equal(
    added[0].keyTrust,
    "u",
    "and it is usable rather than revoked or expired"
  );
});

/**
 * A public key offers neither button. This is the refusal that matters most
 * in the UI: the operation needs the primary key's secret material, and
 * offering a button that can only fail is worse than not offering it.
 */
add_task(async function testPublicKeyOffersNoButtons() {
  await OpenPGPTestUtils.importPublicKey(
    window,
    keyFile("bob@openpgp.example-0xfbfcc82a015e7330-pub.asc")
  );

  await withKeyDetails("0xfbfcc82a015e7330", async win => {
    const doc = win.document;
    selectStructureTab(doc);
    Assert.ok(
      doc.getElementById("addSigningSubkeyButton").hidden,
      "a public key is not offered a signing subkey"
    );
    Assert.ok(
      doc.getElementById("addEncryptionSubkeyButton").hidden,
      "a public key is not offered an encryption subkey"
    );
  });
});
