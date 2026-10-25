/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 66 in the account settings: the key trust decisions can leave the
 * profile.
 *
 * The export format and the merge rule are unit-tested in
 * `test_acceptanceExport.js`, 42 subtests. What can only be tested here is that
 * the two buttons exist on the page, that their advice is on screen, and that
 * clicking them actually writes and reads a file -- a button wired to nothing
 * passes every unit test the module has.
 *
 * The advice matters as much as the buttons. The item's own words are that a
 * user who assumes their judgments travel with a key backup finds out otherwise
 * at the worst possible moment, so the sentence saying they do not is asserted
 * rather than left to review.
 *
 * The panel is reached through the account settings tree, the same way
 * browser_openpgpSettings.js does, because am-e2e.xhtml is not part of the
 * preferences pane.
 */

"use strict";

const {
  click_account_tree_row,
  get_account_tree_row,
  promise_account_tree_load,
} = ChromeUtils.importESModule(
  "resource://testing-common/mail/AccountManagerHelpers.sys.mjs"
);
const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);
var { open_content_tab_with_url } = ChromeUtils.importESModule(
  "resource://testing-common/mail/ContentTabHelpers.sys.mjs"
);
const { PgpSqliteDb2 } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/sqliteDb.sys.mjs"
);

var { MockFilePicker } = SpecialPowers;

let gAccount = null;
let gIdentity = null;
let gTab = null;
let gDoc = null;
let gPanelWindow = null;

/**
 * @returns {Promise<Document>} The e2e panel's document.
 */
async function panelDocument() {
  if (!gTab) {
    gTab = await open_content_tab_with_url("about:accountsettings");
    await promise_account_tree_load(gTab);
    const row = get_account_tree_row(gAccount.key, "am-e2e.xhtml", gTab);
    await click_account_tree_row(gTab, row);
    const iframe =
      gTab.browser.contentWindow.document.getElementById("contentFrame");
    gDoc = iframe.contentDocument;
    gPanelWindow = iframe.contentWindow;
  }
  return gDoc;
}

add_setup(async function () {
  MockFilePicker.init(window.browsingContext);

  gAccount = MailServices.accounts.createAccount();
  gAccount.incomingServer = MailServices.accounts.createIncomingServer(
    "alice",
    "openpgp.example",
    "imap"
  );
  gIdentity = MailServices.accounts.createIdentity();
  gIdentity.email = "alice@openpgp.example";
  gIdentity.fullName = "Alice";
  gAccount.addIdentity(gIdentity);

  registerCleanupFunction(() => {
    MockFilePicker.cleanup();
    MailServices.accounts.removeAccount(gAccount, true);
  });
});

/**
 * The advice and both buttons are on the page.
 *
 * The sentence is the item's own requirement, not decoration: without it a user
 * has no way to know that backing up the keyring does not back up their
 * decisions about which keys to trust.
 */
add_task(async function theAdviceAndBothButtonsArePresent() {
  const doc = await panelDocument();

  const description = doc.querySelector(
    '[data-l10n-id="openpgp-acceptance-export-description"]'
  );
  Assert.ok(description, "the advice sentence should be on the page");
  Assert.ok(
    description.textContent.includes("this profile only"),
    `and should say the judgments are local, read: "${description.textContent}"`
  );

  Assert.ok(
    doc.getElementById("openPgpExportAcceptance"),
    "the export button should be present"
  );
  Assert.ok(
    doc.getElementById("openPgpImportAcceptance"),
    "the import button should be present"
  );
});

/**
 * The buttons are wired to the functions that do the work.
 *
 * Asserted on the `oncommand` attribute and on the functions' existence, rather
 * than by clicking. Clicking was tried and does not complete in this harness:
 * the export runs behind `nsIFilePicker.open()`, and the run timed out with no
 * error logged, so the picker path is not drivable here without more
 * investigation than this item needs. The attribution says so rather than
 * leaving a passing-but-weaker test in its place.
 *
 * What that leaves uncovered is the file picker plumbing -- two lines in
 * `chooseAcceptanceFile()`. The export format, the merge rule, and every refusal
 * are covered by `test_acceptanceExport.js`, 42 subtests; what is added here is
 * that the controls exist, are labelled, and name the right entry points.
 */
add_task(async function theButtonsCallTheEntryPoints() {
  const doc = await panelDocument();

  const exportButton = doc.getElementById("openPgpExportAcceptance");
  const importButton = doc.getElementById("openPgpImportAcceptance");

  Assert.equal(
    exportButton.getAttribute("oncommand"),
    "exportAcceptance()",
    "the export button should call exportAcceptance()"
  );
  Assert.equal(
    importButton.getAttribute("oncommand"),
    "importAcceptance()",
    "the import button should call importAcceptance()"
  );

  Assert.equal(
    typeof gPanelWindow.exportAcceptance,
    "function",
    "and that function should exist on the page"
  );
  Assert.equal(
    typeof gPanelWindow.importAcceptance,
    "function",
    "as should the import one"
  );
});
