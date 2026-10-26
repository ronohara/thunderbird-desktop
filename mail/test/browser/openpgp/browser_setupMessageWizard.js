/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Items 99 and 99a, the half that lives in the Key Wizard.
 *
 * Both rows were Partial for the same reason and it was not the code: the
 * entry points existed and nothing pressed them, because `browser_keyWizard.js`
 * is excluded on Linux and in headless runs by bug 1806870. **That exclusion is
 * still there and this file carries the same one** — it is a tree-wide harness
 * judgement about which browser tests are reliable in that configuration, not a
 * property of this dialog. Given an explicit path, the wizard runs here, which
 * is how this file was driven.
 *
 * What is asserted, and what is deliberately stubbed:
 *
 *   - **Real**: the message. A setup message built by Item 98's own builder,
 *     from a key exported by Item 96's own export, so what the wizard classifies
 *     and unwraps is the shape a receiver actually gets.
 *   - **Real**: the two controls, their visibility, the status line, and the
 *     consequences of pressing them — the identity ending up naming the imported
 *     key.
 *   - **Stubbed**: `AutocryptSetup.findSetupMessages()`, because what this file
 *     is about is the wiring and not the scan. The scan is measured against real
 *     folders with real Junk, Trash, Local Folders and NNTP beside them in
 *     `test_autocryptSetupScan.js`, 21/21. Substituting its answer here is the
 *     same seam `browser_keyWizard.js` uses to stub GPGME, and the stub is
 *     installed on the module the dialog itself calls, so the call being made is
 *     the real one.
 *   - **Stubbed**: `Services.prompt.promptPassword`, because a synchronous modal
 *     prompt has nobody to answer it in a test run and would take the harness's
 *     whole budget to say so.
 */

"use strict";

const { AutocryptSetup } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/autocryptSetup.sys.mjs"
);
const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { PgpSqliteDb2 } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/sqliteDb.sys.mjs"
);
const { OpenPGPAlias } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/OpenPGPAlias.sys.mjs"
);
const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
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
var { wait_for_frame_load } = ChromeUtils.importESModule(
  "resource://testing-common/mail/WindowHelpers.sys.mjs"
);

const ALICE_SECRET =
  "data/keys/alice@openpgp.example-0xf231550c4f47e38e-secret.asc";
const ALICE_FPR = "EB85BB5FA33A75E15E944E63F231550C4F47E38E";
const ALICE_ADDRESS = "alice@openpgp.example";
const SETUP_CODE = "1234-5678-9012-3456-7890-1234-5678-9012-3456";
const FOLDER_NAME = "Saved Messages";

let gAccount;
let gIdentity;
let gTab;
let tabDocument;
let tabWindow;

// The message every task imports, built in setup.
let gMessage = null;

// What the stubbed scan answers, and how many times it was asked.
let gScanCalls = 0;

/**
 * Run a task with a Primary Password present, and remove it afterwards.
 *
 * `adopt()` passes the wizard's window to the import gate (Item 53), and the
 * gate opens the change-password dialog when no password is set — correct for a
 * user, and a deadlock in a test with nobody to answer it. Set through the token
 * so these tasks test the wizard rather than the password dialog, and removed in
 * a `finally` so a failed assertion does not leave a password behind.
 *
 * @param {function(): Promise<void>} body
 */
async function withPrimaryPassword(body) {
  const token = Cc["@mozilla.org/security/internalkeytoken;1"].createInstance(
    Ci.nsIPKCS11Token
  );
  const hadPassword = token.hasPassword;
  if (!hadPassword) {
    await token.changePassword("", "item99-wizard-passphrase");
  }
  try {
    await body();
  } finally {
    if (!hadPassword) {
      const after = Cc[
        "@mozilla.org/security/internalkeytoken;1"
      ].createInstance(Ci.nsIPKCS11Token);
      if (after.hasPassword) {
        after.changePassword("item99-wizard-passphrase", "");
      }
    }
  }
}

/**
 * Build the setup message the wizard will be offered.
 *
 * The key is exported by Item 96's own path and the message by Item 98's, so the
 * wizard's classifier meets the real format rather than a hand-written one.
 *
 * @returns {Promise<string>} The message, CRLF-terminated.
 */
async function buildSetupMessage() {
  await OpenPGPTestUtils.importPrivateKey(
    window,
    new FileUtils.File(getTestFilePath(ALICE_SECRET))
  );
  EnigmailKeyRing.clearCache();

  const keyBlock = RNP.exportSecretKeyForTransfer(ALICE_FPR, "mutual");
  Assert.ok(keyBlock, "the key exports for transfer");

  return AutocryptSetup.buildMessage({
    address: ALICE_ADDRESS,
    setupCode: SETUP_CODE,
    keyBlock,
    preferEncrypt: "mutual",
  });
}

/**
 * Open the Key Wizard at its import section.
 *
 * @returns {Promise<{wizard: Window, doc: Document, dialog: Element}>}
 */
async function openImportSection() {
  EnigmailKeyRing.clearCache();
  await promise_account_tree_load(gTab);
  const accountRow = get_account_tree_row(gAccount.key, "am-e2e.xhtml", gTab);
  await click_account_tree_row(gTab, accountRow);

  const iframe =
    gTab.browser.contentWindow.document.getElementById("contentFrame");
  tabDocument = iframe.contentDocument;
  tabWindow = iframe.contentDocument.documentGlobal;

  EventUtils.synthesizeMouseAtCenter(
    tabDocument.getElementById("addOpenPgpButton"),
    {},
    tabWindow
  );

  const wizard = await wait_for_frame_load(
    gTab.browser.contentWindow.gSubDialog._topDialog._frame,
    "chrome://openpgp/content/ui/keyWizard.xhtml"
  );
  const doc = wizard.document;
  const dialog = doc.documentElement.querySelector("dialog");

  EventUtils.synthesizeMouseAtCenter(
    doc.getElementById("importOpenPgp"),
    {},
    dialog.documentGlobal
  );
  dialog.acceptDialog();

  await TestUtils.waitForCondition(
    () =>
      wizard.getComputedStyle(doc.getElementById("wizardImportKey")).opacity ==
      1,
    "Timeout waiting for the import section to appear"
  );
  return { wizard, doc, dialog };
}

add_setup(async function () {
  requestLongerTimeout(2);

  gAccount = MailServices.accounts.createAccount();
  gAccount.incomingServer = MailServices.accounts.createIncomingServer(
    "alice-item99",
    "openpgp.example",
    "pop3"
  );
  gIdentity = MailServices.accounts.createIdentity();
  gIdentity.email = ALICE_ADDRESS;
  gIdentity.fullName = "Alice";
  gAccount.addIdentity(gIdentity);

  await SpecialPowers.pushPrefEnv({
    set: [
      ["mail.openpgp.alias_rules_file", "browser-item99-wizard-rules.json"],
    ],
  });
  await OpenPGPTestUtils.initOpenPGP();

  gMessage = await buildSetupMessage();

  gTab = await open_content_tab_with_url("about:accountsettings");
  await promise_account_tree_load(gTab);

  // The scan is stubbed for every task; the counter is what proves the dialog
  // asked rather than merely having a result to show.
  const realFind = AutocryptSetup.findSetupMessages;
  AutocryptSetup.findSetupMessages = async () => {
    gScanCalls++;
    return [
      {
        // The wizard reads the folder's name into its status line, which is
        // Item 99a's claim, so the object only has to carry one.
        folder: { name: FOLDER_NAME, localizedName: FOLDER_NAME },
        hdr: { date: Date.now() / 1000 },
        messageURI: "stub://setup-message",
        source: gMessage,
      },
    ];
  };

  registerCleanupFunction(() => {
    AutocryptSetup.findSetupMessages = realFind;
    OpenPGPAlias._clear();
    MailServices.accounts.removeAccount(gAccount, true);
  });
});

/**
 * Item 99a: opening the import section asks for a scan, and a hit is offered.
 *
 * The section's own opening is the trigger the item specifies — "runs at setup
 * ... never on launch" — so this asserts the scan happened without anything
 * being pressed.
 */
add_task(async function openingTheSectionRunsTheScan() {
  const { doc, dialog } = await openImportSection();
  try {
    await TestUtils.waitForCondition(
      () => gScanCalls > 0,
      "Timeout waiting for the scan to be asked for"
    );
    const status = doc.getElementById("setupMessageScanStatus");
    await TestUtils.waitForCondition(
      () => !status.hidden && status.textContent.includes(FOLDER_NAME),
      "Timeout waiting for the status line to name the folder"
    );
    info(
      `FINDING scan-on-open: calls=${gScanCalls} status=${JSON.stringify(status.textContent)}`
    );
    Assert.greaterOrEqual(
      gScanCalls,
      1,
      "opening the section asked for a scan, without anything being pressed"
    );
  } finally {
    dialog.cancelDialog();
  }
});

/**
 * Item 99a and Item 99 together: the hit reveals the import button, and the
 * search control asks again.
 */
add_task(async function aHitRevealsTheButtonAndTheControlRescans() {
  const { doc, dialog } = await openImportSection();
  try {
    const offer = doc.getElementById("importSetupMessageButton");
    await TestUtils.waitForCondition(
      () => !offer.hidden,
      "Timeout waiting for the import button to be offered"
    );

    const before = gScanCalls;
    EventUtils.synthesizeMouseAtCenter(
      doc.getElementById("searchSetupMessageButton"),
      {},
      dialog.documentGlobal
    );
    await TestUtils.waitForCondition(
      () => gScanCalls > before,
      "Timeout waiting for the search control to ask again"
    );
    info(`FINDING rescan: before=${before} after=${gScanCalls}`);
    Assert.equal(
      gScanCalls,
      before + 1,
      "the search control asked for exactly one more scan"
    );
    Assert.ok(
      !offer.hidden,
      "and the hit is offered again rather than withdrawn"
    );
  } finally {
    dialog.cancelDialog();
  }
});

/**
 * Item 99: the button imports.
 *
 * The code prompt is stubbed because it is synchronous and modal; everything
 * after it is real — the classifier, the unwrapping, and `adopt()`, whose
 * consequences are what the identity ends up holding.
 */
add_task(async function theButtonImportsTheOfferedMessage() {
  await withPrimaryPassword(async () => {
    // The whole service is replaced rather than one method: `Services.prompt`
    // is an XPCOM proxy whose properties are read-only, which the first version
    // of this found by throwing. Replacing the object is what alertTestUtils.js
    // does, for the same reason.
    const realPrompt = Services.prompt;
    const answered = [];
    Services.prompt = {
      promptPassword(_parent, _title, _text, password) {
        answered.push(password);
        password.value = SETUP_CODE;
        return true;
      },
      alert() {},
      QueryInterface: ChromeUtils.generateQI(["nsIPromptService"]),
    };
    registerCleanupFunction(() => {
      Services.prompt = realPrompt;
    });

    const { doc, dialog } = await openImportSection();
    const wizardWindow = doc.defaultView ?? doc.documentGlobal;

    const offer = doc.getElementById("importSetupMessageButton");
    await TestUtils.waitForCondition(
      () => !offer.hidden,
      "Timeout waiting for the import button to be offered"
    );

    const closed = BrowserTestUtils.waitForEvent(
      wizardWindow,
      "unload",
      true,
      () => true
    ).catch(() => {});

    EventUtils.synthesizeMouseAtCenter(offer, {}, dialog.documentGlobal);

    // The wizard closes itself on a successful adoption, which is the dialog's
    // own report that it worked.
    await TestUtils.waitForCondition(
      () => EnigmailKeyRing.getKeyById(`0x${ALICE_FPR}`),
      "Timeout waiting for the imported key to appear in the ring",
      100,
      100
    );
    await closed;

    const key = EnigmailKeyRing.getKeyById(`0x${ALICE_FPR}`);
    Assert.ok(key, "the key the message carried is in the ring");
    Assert.equal(
      gIdentity.getUnicharAttribute("openpgp_key_id"),
      key.keyId,
      "and the identity names it, so the wizard's entry did what adoption does"
    );
    Assert.ok(
      await PgpSqliteDb2.isAcceptedAsPersonalKey(key.fpr),
      "and it is marked as the user's own key"
    );
    info(
      `FINDING wizard import: key=${key.keyId} ` +
        `identity=${gIdentity.getUnicharAttribute("openpgp_key_id")}`
    );
  });
});
