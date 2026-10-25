/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests for the creation or import of an OpenPGP key.
 */

"use strict";

const {
  click_account_tree_row,
  get_account_tree_row,
  promise_account_tree_load,
} = ChromeUtils.importESModule(
  "resource://testing-common/mail/AccountManagerHelpers.sys.mjs"
);
var { open_content_tab_with_url } = ChromeUtils.importESModule(
  "resource://testing-common/mail/ContentTabHelpers.sys.mjs"
);
const { wait_for_frame_load } = ChromeUtils.importESModule(
  "resource://testing-common/mail/WindowHelpers.sys.mjs"
);
const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);
const { MockFilePicker } = ChromeUtils.importESModule(
  "resource://testing-common/MockFilePicker.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);

var gAccount;
var gIdentity;
var gTab;
var tabDocument;
var tabWindow;

/**
 * Set up the base account and identity.
 */
add_setup(async function () {
  gAccount = MailServices.accounts.createAccount();
  gAccount.incomingServer = MailServices.accounts.createIncomingServer(
    "alice",
    "openpgp.example",
    "pop3"
  );
  gIdentity = MailServices.accounts.createIdentity();
  gIdentity.email = "alice@openpgp.example";
  gIdentity.fullName = "Alice";
  gAccount.addIdentity(gIdentity);

  await SpecialPowers.pushPrefEnv({
    set: [["mail.openpgp.allow_external_gnupg", true]],
  });

  gTab = await open_content_tab_with_url("about:accountsettings");
  await promise_account_tree_load(gTab);

  // Open the End-to-End Encryption page.
  const accountRow = get_account_tree_row(gAccount.key, "am-e2e.xhtml", gTab);
  await click_account_tree_row(gTab, accountRow);

  const iframe =
    gTab.browser.contentWindow.document.getElementById("contentFrame");

  tabDocument = iframe.contentDocument;
  tabWindow = iframe.contentDocument.documentGlobal;
});

/**
 * Test that we don't have any initial OpenPGP key configured in the
 * End-to-End Encryption page.
 */
add_task(async function check_clean_keylist() {
  // The OpenPGP Key List container should not be visible.
  Assert.equal(
    tabDocument.getElementById("openPgpKeyList").hidden,
    true,
    "The openPgpKeyList container shouldn't be visible"
  );

  // The OpenPGP Key List radiogroup should only have 1 item (the None).
  Assert.equal(
    tabDocument.getElementById("openPgpKeyListRadio").itemCount,
    1,
    "The OpenPGP Key List radiogroup should only have 1 item"
  );

  // The "None" radio item should be currently selected.
  Assert.equal(
    tabDocument.getElementById("openPgpNone").selected,
    true,
    "The openPgpNone radio option is currently selected"
  );
});

/**
 * Test that stepping forward and back always leaves exactly one section of the
 * wizard visible. See bug 2069581.
 */
/**
 * Test that a new identity whose key is already in GnuPG starts on the external
 * path, and that the internal choices stay on screen beside it.
 *
 * The GnuPG boundary is stubbed rather than exercised: what this asserts is the
 * wizard's choice, not the keyring's contents. The key itself is real, so the
 * code path that picks it walks the same listing the product uses.
 */
add_task(async function preselect_gnupg_key_for_new_identity() {
  const { GPGME } = ChromeUtils.importESModule(
    "chrome://openpgp/content/modules/GPGME.sys.mjs"
  );

  // A key the listing returns, held (per the stub below) by GnuPG.
  const ChromeRegistry = Cc["@mozilla.org/chrome/chrome-registry;1"].getService(
    Ci.nsIChromeRegistry
  );
  const chromeUrl = Services.io.newURI(
    getRootDirectory(gTestPath) +
      "data/keys/alice@openpgp.example-0xf231550c4f47e38e-secret.asc"
  );
  const secretFile = ChromeRegistry.convertChromeURL(chromeUrl).QueryInterface(
    Ci.nsIFileURL
  ).file;
  const importedKeyIds = await OpenPGPTestUtils.importPrivateKey(
    window,
    secretFile
  );
  Assert.ok(importedKeyIds.length, "the fixture key should be imported");
  // Kept as returned: getKeyById() strips a lowercase "0x" only, so the id has
  // to stay in the form the helper produced.
  const keyId = importedKeyIds[0];
  const keyFpr = EnigmailKeyRing.getKeyById(keyId).fpr.toUpperCase();

  // An identity with no key of its own is the case the offer exists for.
  const previousKeyId = gIdentity.getUnicharAttribute("openpgp_key_id");
  gIdentity.setUnicharAttribute("openpgp_key_id", "");
  gIdentity.setUnicharAttribute("last_entered_external_gnupg_key_id", "");

  const originalInit = GPGME.init;
  const originalGetFprs = GPGME.getSecretKeyFingerprintsForEmail;
  GPGME.init = () => true;
  GPGME.getSecretKeyFingerprintsForEmail = () => [keyFpr];
  registerCleanupFunction(() => {
    GPGME.init = originalInit;
    GPGME.getSecretKeyFingerprintsForEmail = originalGetFprs;
  });

  let dialog;
  try {
    const button = tabDocument.getElementById("addOpenPgpButton");
    EventUtils.synthesizeMouseAtCenter(button, {}, tabWindow);

    const wizard = await wait_for_frame_load(
      gTab.browser.contentWindow.gSubDialog._topDialog._frame,
      "chrome://openpgp/content/ui/keyWizard.xhtml"
    );
    const doc = wizard.document;
    dialog = doc.documentElement.querySelector("dialog");

    const choices = doc.getElementById("openPgpKeyChoices");
    Assert.equal(choices.value, "2", "the GnuPG choice should be preselected");

    // The internal engine stays offered, not removed and not hidden.
    Assert.ok(
      !doc.getElementById("createOpenPgp").hidden,
      "the create choice should still be visible"
    );
    Assert.ok(
      !doc.getElementById("importOpenPgp").hidden,
      "the import choice should still be visible"
    );

    // Continuing fills in the key that was found, so no typing is needed.
    const externalView = doc.getElementById("wizardExternalKey");
    dialog.acceptDialog();
    await TestUtils.waitForCondition(
      () => wizard.getComputedStyle(externalView).opacity == 1,
      "Timeout waiting for the #wizardExternalKey to appear"
    );

    Assert.equal(
      doc.getElementById("externalKey").value.toUpperCase(),
      `0X${keyId.replace(/^0x/i, "").toUpperCase()}`,
      "the key field should hold the key that was found"
    );
    Assert.ok(
      !doc.querySelector("dialog").getButton("accept").disabled,
      "the Continue button should be enabled"
    );
  } finally {
    GPGME.init = originalInit;
    GPGME.getSecretKeyFingerprintsForEmail = originalGetFprs;
    dialog?.cancelDialog();
    await OpenPGPTestUtils.removeKeyById(keyId.toLowerCase(), true);
    gIdentity.setUnicharAttribute("openpgp_key_id", previousKeyId);
    // The settings page cached the list this test changed; refresh it so the
    // next task starts from the state it expects.
    await tabWindow.reloadOpenPgpUI();
  }
});

/**
 * Test the settings description when the external path is switched off but a
 * GnuPG keyring holds a key for the identity.
 *
 * The wording matters because the old sentence -- "doesn't have a personal
 * OpenPGP key" -- was untrue in this state, and was the one that sent people to
 * the internal engine. The GnuPG boundary is stubbed, since what is under test
 * is the branch rather than the keyring's contents.
 */
add_task(async function description_reports_unused_gnupg_key() {
  const { GPGME } = ChromeUtils.importESModule(
    "chrome://openpgp/content/modules/GPGME.sys.mjs"
  );
  const description = tabDocument.getElementById("openPgpDescription");

  const originalInit = GPGME.init;
  const originalGetFprs = GPGME.getSecretKeyFingerprintsForEmail;

  await SpecialPowers.pushPrefEnv({
    set: [["mail.openpgp.allow_external_gnupg", false]],
  });
  try {
    // No readable keyring: the plain "no key" sentence is still correct.
    GPGME.init = () => false;
    await tabWindow.reloadOpenPgpUI();
    Assert.equal(
      description.dataset.l10nId,
      "openpgp-description-no-key",
      "with no keyring, the description should say there is no key"
    );

    // A keyring holding a key, with the switch off: say so instead.
    GPGME.init = () => true;
    GPGME.getSecretKeyFingerprintsForEmail = () => ["0".repeat(40)];
    await tabWindow.reloadOpenPgpUI();
    Assert.equal(
      description.dataset.l10nId,
      "openpgp-description-gnupg-not-used",
      "with a keyring holding a key and the switch off, the description should say so"
    );
  } finally {
    GPGME.init = originalInit;
    GPGME.getSecretKeyFingerprintsForEmail = originalGetFprs;
    await SpecialPowers.popPrefEnv();
    await tabWindow.reloadOpenPgpUI();
  }
});

add_task(async function switch_sections() {
  // Leave no dialog behind, a stuck one would fail every following task.
  let dialog;
  try {
    // Open the key wizard from the "Add Key" button.
    const button = tabDocument.getElementById("addOpenPgpButton");
    EventUtils.synthesizeMouseAtCenter(button, {}, tabWindow);

    const wizard = await wait_for_frame_load(
      gTab.browser.contentWindow.gSubDialog._topDialog._frame,
      "chrome://openpgp/content/ui/keyWizard.xhtml"
    );
    const doc = wizard.document;
    dialog = doc.documentElement.querySelector("dialog");

    const startView = doc.getElementById("wizardStart");
    const keyGenView = doc.getElementById("wizardCreateKey");

    // Suppress the transition so that no transitionend is fired. The section
    // switching must not depend on it.
    startView.style.transition = "none";

    // Accept the dialog since the first option should be automatically
    // selected.
    dialog.acceptDialog();
    await TestUtils.waitForCondition(
      () => wizard.getComputedStyle(keyGenView).opacity == 1,
      "Timeout waiting for the #wizardCreateKey to appear"
    );
    Assert.ok(startView.hidden, "the start section should be hidden");
    Assert.greater(
      keyGenView.getBoundingClientRect().height,
      0,
      "the create key section should have a height"
    );

    // Return to the first screen.
    dialog.getButton("extra1").click();
    await TestUtils.waitForCondition(
      () => wizard.getComputedStyle(startView).opacity == 1,
      "Timeout waiting for the #wizardStart to reappear"
    );
    Assert.ok(keyGenView.hidden, "the create key section should be hidden");
    Assert.greater(
      startView.getBoundingClientRect().height,
      0,
      "the start section should have a height"
    );
  } finally {
    dialog?.cancelDialog();
  }
});

/**
 * Test that an identity without a name only warns, and that the secret key
 * protection section stays hidden while the pref is off. See bug 2069581.
 */
add_task(async function missing_identity_name() {
  gIdentity.fullName = "";

  // Leave no dialog behind, and restore the name, a nameless identity would
  // fail every following task.
  let dialog;
  try {
    // Open the key wizard from the "Add Key" button.
    const button = tabDocument.getElementById("addOpenPgpButton");
    EventUtils.synthesizeMouseAtCenter(button, {}, tabWindow);

    const wizard = await wait_for_frame_load(
      gTab.browser.contentWindow.gSubDialog._topDialog._frame,
      "chrome://openpgp/content/ui/keyWizard.xhtml"
    );
    const doc = wizard.document;
    dialog = doc.documentElement.querySelector("dialog");

    const keyGenView = doc.getElementById("wizardCreateKey");

    // Accept the dialog since the first option should be automatically
    // selected.
    dialog.acceptDialog();
    await TestUtils.waitForCondition(
      () => wizard.getComputedStyle(keyGenView).opacity == 1,
      "Timeout waiting for the #wizardCreateKey to appear"
    );

    Assert.ok(
      doc.getElementById("keygenPassphraseSection").hidden,
      "the secret key protection section should be hidden"
    );

    await TestUtils.waitForCondition(
      () => !doc.getElementById("openPgpWarning").collapsed,
      "Timeout waiting for the missing name warning to appear"
    );
    Assert.equal(
      doc.getElementById("openPgpWarningDescription").dataset.l10nId,
      "openpgp-keygen-missing-username",
      "the warning should be about the missing name"
    );
    Assert.ok(
      !dialog.getButton("accept").disabled,
      "the Generate key button should still be enabled"
    );
  } finally {
    dialog?.cancelDialog();
    gIdentity.fullName = "Alice";
  }
});

/**
 * Generate a new OpenPGP Key.
 */
add_task(async function generate_new_key() {
  // Open the key wizard from the "Add Key" button.
  const button = tabDocument.getElementById("addOpenPgpButton");
  EventUtils.synthesizeMouseAtCenter(button, {}, tabWindow);

  const wizard = await wait_for_frame_load(
    gTab.browser.contentWindow.gSubDialog._topDialog._frame,
    "chrome://openpgp/content/ui/keyWizard.xhtml"
  );
  const doc = wizard.document;
  const dialog = doc.documentElement.querySelector("dialog");

  const keyGenView = doc.getElementById("wizardCreateKey");

  // Accept the dialog since the first option should be automatically selected.
  dialog.acceptDialog();
  await TestUtils.waitForCondition(
    () => wizard.getComputedStyle(keyGenView).opacity == 1,
    "Timeout waiting for the #wizardCreateKey to appear"
  );

  // Change the expiration.
  EventUtils.synthesizeMouseAtCenter(
    doc.getElementById("keygenDoesNotExpire"),
    {},
    dialog.documentGlobal
  );

  const wizardOverlay = doc.getElementById("wizardOverlay");

  // Move to the next screen.
  dialog.acceptDialog();
  await TestUtils.waitForCondition(
    () => wizard.getComputedStyle(wizardOverlay).opacity == 1,
    "Timeout waiting for the #wizardOverlay to appear"
  );

  // Store the wait event here before the SubDialog is destroyed and we can't
  // access it anymore.
  const frameWinUnload = BrowserTestUtils.waitForEvent(
    gTab.browser.contentWindow.gSubDialog._topDialog._frame.contentWindow,
    "unload",
    true
  );

  // Confirm the generation of the new key.
  const confirmButton = doc.getElementById("openPgpKeygenConfirmButton");
  EventUtils.synthesizeMouseAtCenter(confirmButton, {}, dialog.documentGlobal);

  // Wait for the subdialog to close.
  info("Waiting for subdialog unload");
  await frameWinUnload;

  // The key wizard should automatically assign the newly generated key to the
  // selected identity and close the dialog.
  //
  // The wait is on the **radiogroup**, not on the identity attribute. The
  // attribute is set synchronously by `useOpenPGPKey()`, and the list is
  // rebuilt afterwards by an async `reloadOpenPgpUI()` -- so waiting for the
  // attribute returns while the list still holds only "None", and the
  // assertions below then read a pane that has not caught up. That is one race
  // producing both `itemCount 1 == 2` and `openPgpNone selected`: they were
  // never two defects.
  const radiogroup = tabDocument.getElementById("openPgpKeyListRadio");
  await TestUtils.waitForCondition(
    () => radiogroup.itemCount == 2,
    "Timeout waiting for the key list to be rebuilt with the new key"
  );

  const createdKeyId = gIdentity.getUnicharAttribute("openpgp_key_id");
  Assert.ok(createdKeyId, "identity should have key");

  // The OpenPGP Key List radiogroup should have 2 items (None, and a key).
  Assert.equal(
    radiogroup.itemCount,
    2,
    "The OpenPGP Key List radiogroup should have 2 items"
  );

  // The "None" radio item should NOT be selected.
  Assert.equal(
    tabDocument.getElementById("openPgpNone").selected,
    false,
    "The openPgpNone radio option should not be selected"
  );

  await OpenPGPTestUtils.removeKeyById(createdKeyId, true);
});

/**
 * Import an OpenPGP secret key from file.
 */
add_task(async function import_secret_key() {
  // Importing a secret key into the profile is refused while the external
  // GnuPG path is in use (Item 9 in the plan): the key belongs in the keyring,
  // and this build has no route that writes there. The suite enables that pref
  // for the external-key tasks, so it is switched off here to exercise the
  // internal store, which is the only route that can import a secret key.
  await SpecialPowers.pushPrefEnv({
    set: [["mail.openpgp.allow_external_gnupg", false]],
  });

  // Open the key wizard from the "Add Key" button.
  const button = tabDocument.getElementById("addOpenPgpButton");
  EventUtils.synthesizeMouseAtCenter(button, {}, tabWindow);

  const wizard = await wait_for_frame_load(
    gTab.browser.contentWindow.gSubDialog._topDialog._frame,
    "chrome://openpgp/content/ui/keyWizard.xhtml"
  );
  const doc = wizard.document;
  const dialog = doc.documentElement.querySelector("dialog");

  // Change the selection to import a key.
  EventUtils.synthesizeMouseAtCenter(
    doc.getElementById("importOpenPgp"),
    {},
    dialog.documentGlobal
  );

  const importView = doc.getElementById("wizardImportKey");

  // Accept the dialog to move to the next screen.
  dialog.acceptDialog();
  await TestUtils.waitForCondition(
    () => wizard.getComputedStyle(importView).opacity == 1,
    "Timeout waiting for the #wizardImportKey to appear"
  );

  const ChromeRegistry = Cc["@mozilla.org/chrome/chrome-registry;1"].getService(
    Ci.nsIChromeRegistry
  );
  const chromeUrl = Services.io.newURI(
    getRootDirectory(gTestPath) +
      "data/keys/alice@openpgp.example-0xf231550c4f47e38e-secret.asc"
  );
  const importedKeyId = "0xf231550c4f47e38e";
  const fileUrl = ChromeRegistry.convertChromeURL(chromeUrl);
  const file = fileUrl.QueryInterface(Ci.nsIFileURL).file;

  MockFilePicker.init(window.browsingContext);
  MockFilePicker.setFiles([file]);
  MockFilePicker.returnValue = MockFilePicker.returnOK;

  const importButton = doc
    .getElementById("importKeyIntro")
    .querySelector("button");
  EventUtils.synthesizeMouseAtCenter(importButton, {}, dialog.documentGlobal);

  // The container with the listed keys to import should be visible.
  await TestUtils.waitForCondition(
    () => !doc.getElementById("importKeyListContainer").collapsed,
    "Timeout waiting for the #importKeyListContainer to appear"
  );

  const keyList = doc.getElementById("importKeyList");

  // The dialog should display 1 key ready to be imported.
  Assert.equal(
    keyList.childNodes.length,
    1,
    "Only 1 fetched key is listed in the #importKeyList container"
  );

  // Be sure the listed private key is checked to be used as personal key.
  Assert.equal(
    keyList.querySelector("checkbox").checked,
    true,
    "The imported key is marked to be used as personal key"
  );

  // Accept the dialog to move to the next screen.
  dialog.acceptDialog();
  await TestUtils.waitForCondition(
    () => !doc.getElementById("importKeyListSuccess").collapsed,
    "Timeout waiting for the #importKeyListSuccess to appear"
  );

  const keyListRecap = doc.getElementById("importKeyListRecap");

  // The dialog should display 1 key ready to be imported.
  Assert.equal(
    keyListRecap.childNodes.length,
    1,
    "Only 1 imported key is listed in the #importKeyListRecap container"
  );

  const keyListRadio = tabDocument.getElementById("openPgpKeyListRadio");
  const listItemCount = keyListRadio.itemCount + 1;

  // Accept the dialog to close it.
  dialog.acceptDialog();

  await TestUtils.waitForCondition(
    () => keyListRadio.itemCount == listItemCount,
    "Timeout waiting for the #importKeyListSuccess to appear"
  );

  Assert.equal(
    keyListRadio.itemCount,
    listItemCount,
    "should list the expected keys"
  );

  // The previously configured OpenPGP key should still be selected.
  Assert.equal(
    keyListRadio.selectedIndex,
    1,
    "The previously generated secret key is still selected"
  );

  await OpenPGPTestUtils.removeKeyById(importedKeyId, true);
  // Remove all the previously generated radio options, except the first.
  while (keyListRadio.lastChild.id != "openPgpOptionNone") {
    keyListRadio.removeChild(keyListRadio.lastChild);
  }

  await SpecialPowers.popPrefEnv();
});

/**
 * Setting an external key that GnuPG holds must not put a copy in the profile.
 *
 * This is the path Item 12 removed an import from: completing the external
 * section used to import the key's public part into the profile ring. The key
 * is now loaded into the transient cache instead, so the wizard completes and
 * nothing is written.
 */
add_task(async function external_key_is_not_copied_into_the_profile() {
  const { GPGME } = ChromeUtils.importESModule(
    "chrome://openpgp/content/modules/GPGME.sys.mjs"
  );

  const ChromeRegistry = Cc["@mozilla.org/chrome/chrome-registry;1"].getService(
    Ci.nsIChromeRegistry
  );
  const chromeUrl = Services.io.newURI(
    getRootDirectory(gTestPath) +
      "data/keys/alice@openpgp.example-0xf231550c4f47e38e-pub.asc"
  );
  const pubFile = ChromeRegistry.convertChromeURL(chromeUrl).QueryInterface(
    Ci.nsIFileURL
  ).file;
  const keyBlock = new TextDecoder().decode(await IOUtils.read(pubFile.path));

  const EXTERNAL_KEY_ID = "F231550C4F47E38E";
  const EXTERNAL_FPR = "EB85BB5FA33A75E15E944E63F231550C4F47E38E";

  const originalInit = GPGME.init;
  const originalByEmail = GPGME.getPublicKeysForEmail;
  const originalById = GPGME.getPublicKeysForId;
  GPGME.init = () => true;
  // GnuPG reports the key as held, which is the case that used to be imported.
  GPGME.getPublicKeysForEmail = () => new Map([[EXTERNAL_FPR, keyBlock]]);
  GPGME.getPublicKeysForId = () => new Map([[EXTERNAL_FPR, keyBlock]]);

  gIdentity.setUnicharAttribute("openpgp_key_id", "");
  gIdentity.setUnicharAttribute("last_entered_external_gnupg_key_id", "");

  let dialog;
  try {
    EnigmailKeyRing.clearCache();
    Assert.ok(
      !EnigmailKeyRing.getAllKeys(null, null).keyList.some(
        k => k.fpr.toUpperCase() == EXTERNAL_FPR
      ),
      "the fixture key should not be in the profile ring to begin with"
    );

    const button = tabDocument.getElementById("addOpenPgpButton");
    EventUtils.synthesizeMouseAtCenter(button, {}, tabWindow);

    const wizard = await wait_for_frame_load(
      gTab.browser.contentWindow.gSubDialog._topDialog._frame,
      "chrome://openpgp/content/ui/keyWizard.xhtml"
    );
    const doc = wizard.document;
    dialog = doc.documentElement.querySelector("dialog");

    // Choose the external path and enter the key id.
    EventUtils.synthesizeMouseAtCenter(
      doc.getElementById("externalOpenPgp"),
      {},
      dialog.documentGlobal
    );
    const externalView = doc.getElementById("wizardExternalKey");
    dialog.acceptDialog();
    await TestUtils.waitForCondition(
      () => wizard.getComputedStyle(externalView).opacity == 1,
      "Timeout waiting for the #wizardExternalKey section"
    );

    const keyInput = doc.getElementById("externalKey");
    keyInput.focus();
    EventUtils.sendString(EXTERNAL_KEY_ID, wizard);

    dialog.acceptDialog();

    // The wizard closes itself through okExternalCallback; waiting on a window
    // is wrong here because this is a subdialog frame, so the observable
    // effect is the identity attribute it sets.
    await TestUtils.waitForCondition(
      () => gIdentity.getUnicharAttribute("openpgp_key_id"),
      "Timeout waiting for the external key to be set on the identity"
    );

    Assert.equal(
      gIdentity.getUnicharAttribute("openpgp_key_id"),
      EXTERNAL_KEY_ID,
      "the wizard should complete and record the external key id"
    );
    Assert.ok(
      gIdentity.getBoolAttribute("is_gnupg_key_id"),
      "and mark the identity as using an external key"
    );

    EnigmailKeyRing.clearCache();
    const inRing = EnigmailKeyRing.getAllKeys(null, null).keyList.some(
      k => k.fpr.toUpperCase() == EXTERNAL_FPR
    );
    Assert.ok(
      !inRing,
      "nothing should be written to the profile ring for a key GnuPG holds"
    );
  } finally {
    GPGME.init = originalInit;
    GPGME.getPublicKeysForEmail = originalByEmail;
    GPGME.getPublicKeysForId = originalById;
    dialog?.cancelDialog();
    // Clearing the identity attributes is not enough: the settings page keeps
    // its own gKeyId, so the key would still be listed for the next task and
    // that task's baseline item count would be wrong. useOpenPGPKey() is the
    // sanctioned way to change it -- the file says so -- and it also clears
    // is_gnupg_key_id.
    tabWindow.useOpenPGPKey("");
    gIdentity.setUnicharAttribute("last_entered_external_gnupg_key_id", "");
    EnigmailKeyRing.clearCache();
    await tabWindow.reloadOpenPgpUI();
  }
});

/**
 * Manually set and external GnuPG key.
 */
add_task(async function add_external_key() {
  // Open the key wizard from the "Add Key" button.
  const button = tabDocument.getElementById("addOpenPgpButton");
  EventUtils.synthesizeMouseAtCenter(button, {}, tabWindow);

  const wizard = await wait_for_frame_load(
    gTab.browser.contentWindow.gSubDialog._topDialog._frame,
    "chrome://openpgp/content/ui/keyWizard.xhtml"
  );
  const doc = wizard.document;
  const dialog = doc.documentElement.querySelector("dialog");

  // Change the selection to import a key.
  EventUtils.synthesizeMouseAtCenter(
    doc.getElementById("externalOpenPgp"),
    {},
    dialog.documentGlobal
  );

  const externalView = doc.getElementById("wizardExternalKey");

  // Accept the dialog to move to the next screen.
  dialog.acceptDialog();
  await TestUtils.waitForCondition(
    () => wizard.getComputedStyle(externalView).opacity == 1,
    "Timeout waiting for the #wizardExternalKey to appear"
  );

  doc.getElementById("externalKey").focus();

  const EXTERNAL_GNUP_KEY = "f231550c4f47e38e".toUpperCase();

  EventUtils.sendString(EXTERNAL_GNUP_KEY, wizard);

  dialog.acceptDialog(); // Press "Continue"

  // Must provide the public key.
  const ChromeRegistry = Cc["@mozilla.org/chrome/chrome-registry;1"].getService(
    Ci.nsIChromeRegistry
  );
  const chromeUrl = Services.io.newURI(
    getRootDirectory(gTestPath) +
      "data/keys/alice@openpgp.example-0xf231550c4f47e38e-pub.asc"
  );
  const fileUrl = ChromeRegistry.convertChromeURL(chromeUrl);
  const file = fileUrl.QueryInterface(Ci.nsIFileURL).file;

  MockFilePicker.init(window.browsingContext);
  MockFilePicker.setFiles([file]);
  MockFilePicker.returnValue = MockFilePicker.returnOK;

  const keyListRadio = tabDocument.getElementById("openPgpKeyListRadio");
  const listItemCount = keyListRadio.itemCount + 1;

  const importButton = doc.getElementById("importPublicKeyButton");
  EventUtils.synthesizeMouseAtCenter(importButton, {}, dialog.documentGlobal);

  // The container with the listed keys to import should be visible.
  await TestUtils.waitForCondition(
    () => !dialog.getButton("accept").disabled,
    "Timeout waiting for the Continue to appear"
  );

  await TestUtils.waitForCondition(
    () => keyListRadio.itemCount == listItemCount,
    "Waiting for the newly imported key to be listed"
  );

  Assert.equal(
    keyListRadio.itemCount,
    listItemCount,
    "should list the expected keys"
  );

  // The first key should currently be selected.
  Assert.equal(
    keyListRadio.selectedIndex,
    1,
    "The external key is selected and listed at first position"
  );

  // Confirm that the currently listed key is correct.
  Assert.equal(
    gIdentity.getUnicharAttribute("openpgp_key_id"),
    EXTERNAL_GNUP_KEY,
    "The external key was properly set for the current identity"
  );

  await OpenPGPTestUtils.removeKeyById(EXTERNAL_GNUP_KEY, false);
  await SpecialPowers.popPrefEnv();
});

/**
 * Test that the "Go Back" button does not appear when the Key Wizard is opened
 * from the key manager.
 */
add_task(async function check_for_go_back_button() {
  const keyManagerPromise = BrowserTestUtils.domWindowOpened(
    null,
    async win => {
      await BrowserTestUtils.waitForEvent(win, "load");
      return (
        win.document.documentURI ===
        "chrome://openpgp/content/ui/enigmailKeyManager.xhtml"
      );
    }
  );
  // Open the key manager from the "OpenPGP Key Manager" button.
  const openPGPKeyManagerButton = tabDocument.getElementById(
    "openOpenPGPKeyManagerButton"
  );
  // The button sits below the fold on a small test window, and a synthesized
  // click at its centre then lands outside the viewport: no error, no command,
  // and the window never opens. Scroll it into view first.
  openPGPKeyManagerButton.scrollIntoView({ block: "center" });
  EventUtils.synthesizeMouseAtCenter(openPGPKeyManagerButton, {}, tabWindow);

  const kmWindow = await keyManagerPromise;

  const dialogPromise = BrowserTestUtils.promiseAlertDialog(
    null,
    "chrome://openpgp/content/ui/keyWizard.xhtml",
    {
      callback(win) {
        const doc = win.document;
        const dialog = doc.querySelector("dialog");
        const goBackButton = dialog.getButton("extra1");

        // The "Go Back" button should not be visible.
        Assert.equal(
          goBackButton.hidden,
          true,
          "The Go Back button should not be visible."
        );

        doc.querySelector("dialog").getButton("cancel").click();
      },
    }
  );
  // Open the key wizard from the "New Key Pair" menu option.
  kmWindow.document.getElementById("genKey").click();

  await dialogPromise;

  kmWindow.close();
});

registerCleanupFunction(async function () {
  document.getElementById("tabmail").closeTab(gTab);
  gTab = null;
  tabDocument = null;
  tabWindow = null;

  MailServices.accounts.removeAccount(gAccount, true);
  gAccount = null;
});
