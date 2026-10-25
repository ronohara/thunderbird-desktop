/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 81: the mark appears where the question "which engine?" is asked, and
 * nowhere it is not.
 *
 * Two places, each for its own reason:
 *
 *   - the message security panel heading, because that panel explains the
 *     header badge and the two must agree. It used to append "- OpenPGP" for
 *     either engine;
 *   - the account settings key list, per key rather than once for the page,
 *     because an identity can hold one key in each store and a page-level
 *     badge would have to be wrong about one of them.
 *
 * The Key Manager is deliberately *not* one of them: its list is built from the
 * profile ring alone, so a key that lives only in the keyring does not appear
 * at all. Marking rows there would decorate the internal keys and stay silent
 * about the external ones. Sourcing those keys is Item 81a.
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
const {
  get_about_message,
  get_special_folder,
  be_in_folder,
  select_click_row,
  wait_for_message_display_completion,
  press_delete,
} = ChromeUtils.importESModule(
  "resource://testing-common/mail/FolderDisplayHelpers.sys.mjs"
);
const { PromiseTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mailnews/PromiseTestUtils.sys.mjs"
);

var gAccount;
var gIdentity;
var gInbox;

add_setup(async function () {
  requestLongerTimeout(2);

  gAccount = MailServices.accounts.createAccount();
  gAccount.incomingServer = MailServices.accounts.createIncomingServer(
    "mark",
    "mark.example",
    "pop3"
  );
  gIdentity = MailServices.accounts.createIdentity();
  gIdentity.email = "mark@mark.example";
  gAccount.addIdentity(gIdentity);
  registerCleanupFunction(() =>
    MailServices.accounts.removeAccount(gAccount, true)
  );

  await SpecialPowers.pushPrefEnv({
    set: [["mail.openpgp.allow_external_gnupg", true]],
  });

  gInbox = await get_special_folder(Ci.nsMsgFolderFlags.Inbox, true);
  await be_in_folder(gInbox);
});

/**
 * The panel heading names the engine the badge names.
 *
 * The engine comes from `getMessageEngine()`, which is the same source the
 * badge reads -- so this asserts the agreement the item asks for rather than
 * two values that happen to match.
 */
add_task(async function thePanelHeadingFollowsTheEngine() {
  const openPgpFile = new FileUtils.File(
    getTestFilePath(
      "data/eml/signed-by-0xfbfcc82a015e7330-encrypted-to-0xf231550c4f47e38e.eml"
    )
  );
  const copyListener = new PromiseTestUtils.PromiseCopyListener();
  MailServices.copy.copyFileMessage(
    openPgpFile,
    gInbox,
    null,
    false,
    0,
    "",
    copyListener,
    null
  );
  await copyListener.promise;

  await select_click_row(-1);
  await wait_for_message_display_completion(window);

  const aboutMessage = get_about_message(window);
  const doc = aboutMessage.document;
  const hdrView = aboutMessage.Enigmail.hdrView;
  const techLabel = doc.getElementById("techLabel");
  const mark = doc.getElementById("securityTechMark");

  // A message with no recorded engine: the heading is what it always was.
  hdrView.msgDecryptionEngine = null;
  await aboutMessage.Enigmail.msg.loadOpenPgpMessageSecurityInfo();
  Assert.equal(
    techLabel.textContent,
    "- OpenPGP",
    "with no engine recorded the heading says OpenPGP"
  );
  Assert.ok(mark.hidden, "and shows no mark");
  Assert.ok(!mark.hasAttribute("src"), "with no source left behind");

  // The same message, with the engine recorded as GnuPG.
  hdrView.msgDecryptionEngine = "gnupg";
  await aboutMessage.Enigmail.msg.loadOpenPgpMessageSecurityInfo();

  info(`FINDING: the heading reads "${techLabel.textContent}"`);
  Assert.equal(
    techLabel.textContent,
    "- GnuPG",
    "and says GnuPG when the engine is GnuPG"
  );
  Assert.ok(!mark.hidden, "with the mark shown");
  Assert.equal(
    mark.getAttribute("src"),
    "chrome://branding/content/gnupg-wing.svg",
    "pointing at the branding asset"
  );
  Assert.equal(
    hdrView.getMessageEngine(),
    "gnupg",
    "which is the same answer the header badge gets"
  );

  // Decoded, not merely referenced: a broken image beside the heading would be
  // worse than none.
  await TestUtils.waitForCondition(
    () => mark.complete && mark.naturalWidth > 0,
    "the mark to load and decode"
  );

  registerCleanupFunction(() => {
    hdrView.msgDecryptionEngine = null;
  });

  await select_click_row(-1);
  await press_delete();
});

/**
 * In account settings the mark sits beside the key it is true of.
 *
 * The external key's row carries the "External GnuPG Key" pill already; the
 * mark is added beside it rather than replacing it, and no other row gets one.
 */
add_task(async function theExternalKeyRowCarriesTheMark() {
  gIdentity.setBoolAttribute("is_gnupg_key_id", true);
  gIdentity.setUnicharAttribute("last_entered_external_gnupg_key_id", "0xDEAD");
  registerCleanupFunction(() => {
    gIdentity.setBoolAttribute("is_gnupg_key_id", false);
    gIdentity.setUnicharAttribute("last_entered_external_gnupg_key_id", "");
  });

  const tab = await open_content_tab_with_url("about:accountsettings");
  await promise_account_tree_load(tab);
  const row = get_account_tree_row(gAccount.key, "am-e2e.xhtml", tab);
  await click_account_tree_row(tab, row);

  const iframe =
    tab.browser.contentWindow.document.getElementById("contentFrame");
  const doc = iframe.contentDocument;

  // Rebuild the list, which is what draws the rows.
  await iframe.contentDocument.documentGlobal.reloadOpenPgpUI();

  const radio = doc.getElementById("openPgpKeyListRadio");
  // Selected by the pill rather than by id: the row id is built from the
  // configured key id including its "0x" prefix.
  const pill = radio.querySelector(".external-pill");
  info(`FINDING: rows=${radio.children.length} pill=${pill ? "yes" : "no"}`);
  Assert.ok(pill, "the external key has a row carrying the pill");
  const externalRow = pill.closest(".content-blocking-category");
  Assert.ok(externalRow, "and the pill sits inside that key's row");

  const mark = externalRow.querySelector(".openpgp-source-mark");
  info(`FINDING: external row carries ${mark ? "a" : "no"} mark`);
  Assert.ok(mark, "and now a provenance mark beside it");
  Assert.equal(
    mark.getAttribute("src"),
    "chrome://branding/content/gnupg-wing.svg",
    "from the branding directory"
  );

  // The mark is per key: no other row in the list carries one.
  const marks = radio.querySelectorAll(".openpgp-source-mark");
  Assert.equal(
    marks.length,
    1,
    `exactly one row is marked, got ${marks.length}`
  );

  // A content tab in the 3-pane's tabmail, not a gBrowser tab.
  document.getElementById("tabmail").closeTab(tab);
});
