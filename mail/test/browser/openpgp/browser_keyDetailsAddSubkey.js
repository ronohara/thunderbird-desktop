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
 */

"use strict";

const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { EnigmailWindows } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/windows.sys.mjs"
);

const KEY_DETAILS_URL = "chrome://openpgp/content/ui/keyDetailsDlg.xhtml";

const ALICE_KEY_ID = "0xf231550c4f47e38e";

function keyFile(name) {
  return new FileUtils.File(getTestFilePath(`data/keys/${name}`));
}

/**
 * Open the key details dialog and run the given function inside it. The
 * dialog is modal, so everything has to happen in the callback.
 *
 * @param {string} keyId - A key in the keyring.
 * @param {function(Document):Promise} checks - Receives the dialog document.
 */
async function withKeyDetails(keyId, checks) {
  const onDialogLoaded = async function (dialogWindow) {
    await TestUtils.waitForCondition(
      () => dialogWindow.document.getElementById("keyId").value,
      "the key details should have loaded"
    );
    await checks(dialogWindow.document);
    dialogWindow.close();
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

function selectStructureTab(doc) {
  doc.getElementById("mainTabs").selectedTab = doc.getElementById("structureTab");
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
 * @param {Document} doc - The dialog document.
 * @param {string} buttonId
 */
async function clickAndAccept(doc, buttonId) {
  const promptPromise = BrowserTestUtils.promiseAlertDialogOpen();
  EventUtils.synthesizeMouseAtCenter(
    doc.getElementById(buttonId),
    {},
    doc
  );
  const promptWindow = await promptPromise;
  promptWindow.document.querySelector("dialog").getButton("accept").click();
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
  await withKeyDetails(ALICE_KEY_ID, async doc => {
    selectStructureTab(doc);

    const signing = doc.getElementById("addSigningSubkeyButton");
    const encryption = doc.getElementById("addEncryptionSubkeyButton");
    Assert.ok(!signing.hidden, "the add-signing-subkey button is shown");
    Assert.ok(!encryption.hidden, "the add-encryption-subkey button is shown");

    // Switching away hides them, because they would act on a list that is no
    // longer on screen.
    doc.getElementById("mainTabs").selectedTab = doc.getElementById("introTab");
    doc.getElementById("mainTabPanel").doCommand();
    Assert.ok(signing.hidden, "the signing button is hidden on another tab");
    Assert.ok(encryption.hidden, "the encryption button is hidden on another tab");
  });
});

/**
 * Clicking the button adds a subkey, and the dialog shows it without being
 * reopened: the refresh after the change is part of what the button has to do.
 */
add_task(async function testAddSigningSubkeyFromTheDialog() {
  let before = 0;

  await withKeyDetails(ALICE_KEY_ID, async doc => {
    selectStructureTab(doc);
    before = subkeyRowCount(doc);
    Assert.ok(before > 0, "the key has subkeys to begin with");

    await clickAndAccept(doc, "addSigningSubkeyButton");

    await TestUtils.waitForCondition(
      () => subkeyRowCount(doc) == before + 1,
      `the subkey list should gain a row, ${before} -> ${before + 1}`
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
  Assert.equal(key.subKeys.length, before + 1, "the subkey was saved");

  const signing = key.subKeys.filter(sk => sk.keyUseFor.includes("s"));
  Assert.greater(signing.length, 1, "there is more than one signing subkey");
  for (const sk of signing) {
    Assert.ok(
      !sk.keyUseFor.includes("e"),
      `a signing subkey must not also encrypt, usage "${sk.keyUseFor}"`
    );
  }
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

  await withKeyDetails("0xfbfcc82a015e7330", async doc => {
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
