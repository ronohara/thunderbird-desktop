/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 82: verify Stage 12, and that the identifiers did not move.
 *
 * Stage 12 added a provenance cue in four places. This runs the claims
 * together, on one build, because the failure that matters is not "the cue is
 * wrong" but "the cue is right in one place and wrong in the next".
 *
 * Three things are checked:
 *
 *   1. **All three badge states on one build** -- GnuPG, internal, and
 *      neither. A cue that appears for everything is caught as surely as one
 *      that never appears, and only running all three distinguishes them.
 *   2. **The security panel still routes by `tech`,** which is the identifier
 *      that must not change. `msgSecurityPane.js` dispatches on it.
 *   3. **The identifiers 14.3 protects are still what they were** -- asserted
 *      at runtime rather than by grepping source, because a label change that
 *      quietly renamed one would pass every visible test and break an add-on.
 *
 * What this file does *not* do: it does not decrypt anything through GnuPG.
 * Recording which engine decrypted a message is Item 79a's, and it is verified
 * against real gpg in `test_decryptionEngine.js`. Here the recorded fact is
 * set, because this item is about what the interface does with it.
 *
 * The 16px legibility judgement is measured rather than rendered -- see the
 * plan row for the numbers and for what is left to the user's eye.
 */

"use strict";

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
const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);

const KEY_DIR = "data/keys/";
const ALICE_SECRET = "alice@openpgp.example-0xf231550c4f47e38e-secret.asc";
const BOB_PUBLIC = "bob@openpgp.example-0xfbfcc82a015e7330-pub.asc";
const BOB_SECRET_REL = "bob@openpgp.example-0xfbfcc82a015e7330-secret.asc";

/** Encrypted and signed: the badge has both icons, so it is fully populated. */
const MSG_ENCRYPTED_SIGNED =
  "data/eml/signed-by-0xfbfcc82a015e7330-encrypted-to-0xf231550c4f47e38e.eml";
/** Neither encrypted nor signed: no badge at all. */
const MSG_PLAIN = "data/eml/unsigned-unencrypted-from-bob-to-alice.eml";

var account;
var inbox;

/**
 * @param {string} path - Relative to this test's directory.
 * @returns {nsIFile}
 */
function fixture(path) {
  return new FileUtils.File(getTestFilePath(path));
}

/**
 * Puts a fixture in the inbox and selects it.
 *
 * @param {string} path - Relative to this test's directory.
 * @returns {Promise<object>} The about:message window.
 */
async function openMessage(path) {
  const copyListener = new PromiseTestUtils.PromiseCopyListener();
  MailServices.copy.copyFileMessage(
    fixture(path),
    inbox,
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
  return get_about_message(window);
}

/**
 * Deletes the message on show, so the next `select_click_row(-1)` is the one
 * just copied rather than the previous fixture.
 */
async function removeMessage() {
  await select_click_row(-1);
  await press_delete();
}

/**
 * Re-renders the badge from the view's current state.
 *
 * `loadOpenPgpMessageSecurityInfo()` fills the security panel; the badge is
 * drawn by `updateVisibleSecurityStatus()`, which the overlay calls on every
 * status update. Both are driven here so the two are read from one state.
 *
 * @param {object} aboutMessage - The about:message window.
 * @param {string} expectedLabel - What the badge must end up saying.
 */
async function refresh(aboutMessage, expectedLabel) {
  aboutMessage.Enigmail.hdrView.updateVisibleSecurityStatus();
  await aboutMessage.Enigmail.msg.loadOpenPgpMessageSecurityInfo();
  // The label is set through Fluent, so it lands a turn later -- and waiting
  // for "some text" is not enough, because the previous message's label is
  // still there and truthy. Wait for the value this state should produce.
  await TestUtils.waitForCondition(
    () =>
      aboutMessage.document.querySelector("#encryptionTechBtn .crypto-label")
        ?.textContent == expectedLabel,
    `the badge to say ${expectedLabel}`
  );
}

/**
 * The badge as the user sees it.
 *
 * @param {Document} doc
 * @returns {object}
 */
function readBadge(doc) {
  const box = doc.getElementById("cryptoBox");
  const mark = doc.getElementById("gnupgWingIcon");
  return {
    shown: !box.hidden,
    label: doc.querySelector("#encryptionTechBtn .crypto-label")?.textContent,
    tech: box.getAttribute("tech"),
    engine: box.getAttribute("engine"),
    markShown: !mark.hidden,
    markSrc: mark.getAttribute("src"),
  };
}

add_setup(async function () {
  requestLongerTimeout(3);

  account = MailServices.accounts.createAccount();
  account.incomingServer = MailServices.accounts.createIncomingServer(
    "stage12",
    "stage12.example",
    "pop3"
  );
  const identity = MailServices.accounts.createIdentity();
  identity.email = "stage12@stage12.example";
  account.addIdentity(identity);
  registerCleanupFunction(() =>
    MailServices.accounts.removeAccount(account, true)
  );

  await OpenPGPTestUtils.initOpenPGP();
  await OpenPGPTestUtils.importPrivateKey(
    window,
    fixture(KEY_DIR + ALICE_SECRET)
  );
  await OpenPGPTestUtils.importPublicKey(window, fixture(KEY_DIR + BOB_PUBLIC));

  inbox = await get_special_folder(Ci.nsMsgFolderFlags.Inbox, true);
  await be_in_folder(inbox);
});

/**
 * The three states, in one build.
 *
 * This is the check Item 79a exists to make possible: before it recorded which
 * engine decrypted a message, there was no fact to assert on, and the badge
 * would silently have been the internal one for every message a user read.
 */
add_task(async function threeBadgeStates() {
  // 1. Neither encrypted nor signed: nothing is shown at all.
  let aboutMessage = await openMessage(MSG_PLAIN);
  let badge = readBadge(aboutMessage.document);
  info(`FINDING state "neither": ${JSON.stringify(badge)}`);
  Assert.ok(!badge.shown, "a plain message shows no badge");
  Assert.equal(badge.label, "", "and no label");
  await removeMessage();

  // 2. Encrypted by the internal engine: the present badge.
  aboutMessage = await openMessage(MSG_ENCRYPTED_SIGNED);
  const hdrView = aboutMessage.Enigmail.hdrView;
  registerCleanupFunction(() => hdrView.reset());

  hdrView.msgDecryptionEngine = null;
  await refresh(aboutMessage, "OpenPGP");
  badge = readBadge(aboutMessage.document);
  info(`FINDING state "internal": ${JSON.stringify(badge)}`);
  Assert.ok(badge.shown, "an encrypted message shows the badge");
  Assert.equal(badge.label, "OpenPGP", "which says OpenPGP");
  Assert.ok(!badge.markShown, "with no mark");
  Assert.ok(!badge.engine, "and no engine claimed");
  Assert.equal(
    badge.tech,
    "OpenPGP",
    "while tech is still the technology, not the engine"
  );

  // 3. The same message, decrypted by GnuPG: mark and word.
  hdrView.msgDecryptionEngine = "gnupg";
  await refresh(aboutMessage, "GnuPG");
  badge = readBadge(aboutMessage.document);
  info(`FINDING state "gnupg": ${JSON.stringify(badge)}`);
  Assert.ok(badge.shown, "the badge is still shown");
  Assert.equal(badge.label, "GnuPG", "and now says GnuPG");
  Assert.ok(badge.markShown, "with the wing");
  Assert.equal(
    badge.markSrc,
    "chrome://branding/content/gnupg-wing.svg",
    "from the branding directory"
  );
  Assert.equal(
    badge.tech,
    "OpenPGP",
    "and tech is unchanged, because the panel dispatches on it"
  );

  // The mark at the size the header actually uses, measured in the header
  // rather than read from the file's own attributes.
  //
  // 20px since 2026-10-27: this item measured the drawing at 16px and found no
  // row of it carrying a feather gap, which is what makes it read as a leaf
  // rather than a wing; one gap returns at 20px. The assertion remains exact.
  const wing = aboutMessage.document.getElementById("gnupgWingIcon");
  await TestUtils.waitForCondition(
    () => wing.complete && wing.naturalWidth > 0,
    "the wing to load and decode"
  );
  const rect = wing.getBoundingClientRect();
  info(`FINDING the mark occupies ${rect.width}x${rect.height}px`);
  Assert.equal(Math.round(rect.width), 20, "the mark renders at 20px");
  Assert.equal(Math.round(rect.height), 20, "and is square");

  await removeMessage();
});

/**
 * A signed-only message keeps the present badge, and the signature is still
 * reported correctly.
 *
 * The point is that verification is librnp's in every configuration, so a
 * signature is not evidence of GnuPG provenance. The badge must not imply it,
 * and the panel must still say what the signature is.
 */
add_task(async function aSignatureIsNotProvenance() {
  const aboutMessage = await openMessage("data/eml/alice-signed.eml");
  const hdrView = aboutMessage.Enigmail.hdrView;
  registerCleanupFunction(() => hdrView.reset());
  hdrView.msgDecryptionEngine = null;
  await refresh(aboutMessage, "OpenPGP");

  const badge = readBadge(aboutMessage.document);
  info(`FINDING state "signed only": ${JSON.stringify(badge)}`);
  Assert.ok(badge.shown, "a signed message shows the badge");
  Assert.equal(badge.label, "OpenPGP", "which stays OpenPGP");
  Assert.ok(!badge.markShown, "and no provenance mark is claimed");

  info(
    `FINDING signature state: ${
      ["ok", "unknown", "unverified", "mismatch"].find(s =>
        OpenPGPTestUtils.hasSignedIconState(aboutMessage.document, s)
      ) ?? "none"
    }`
  );
  Assert.ok(
    OpenPGPTestUtils.hasSignedIconState(aboutMessage.document, "verified") ||
      OpenPGPTestUtils.hasSignedIconState(aboutMessage.document, "unverified"),
    "while the signature itself is still reported, not silently dropped"
  );

  await removeMessage();
});

/**
 * The security panel still opens the OpenPGP pane for a GnuPG-handled message.
 *
 * `msgSecurityPane.js` dispatches on the `tech` attribute. If the label change
 * had been made by rewriting `tech` to "GnuPG", a GnuPG message would have
 * fallen through to the S/MIME branch and the panel would have contradicted
 * the badge. This asserts the routing, not the label.
 */
add_task(async function thePanelRoutesOnTechNotTheLabel() {
  const aboutMessage = await openMessage(MSG_ENCRYPTED_SIGNED);
  const hdrView = aboutMessage.Enigmail.hdrView;
  registerCleanupFunction(() => hdrView.reset());
  hdrView.msgDecryptionEngine = "gnupg";
  await refresh(aboutMessage, "GnuPG");

  const doc = aboutMessage.document;
  const popupshown = BrowserTestUtils.waitForEvent(
    doc.getElementById("messageSecurityPanel"),
    "popupshown"
  );
  aboutMessage.showMessageReadSecurityInfo();
  await popupshown;

  // The OpenPGP pane, not the S/MIME one: the S/MIME branch shows a
  // certificate section, and the OpenPGP branch populates the signature label
  // with one of its own strings.
  Assert.equal(
    doc.getElementById("cryptoBox").getAttribute("tech"),
    "OpenPGP",
    "the panel dispatched on tech, which is still OpenPGP"
  );
  Assert.ok(
    doc.getElementById("encryptionCert").collapsed,
    "so the S/MIME certificate section is collapsed"
  );
  Assert.ok(
    doc.getElementById("signatureLabel").textContent.includes("Signature"),
    `and the OpenPGP signature label is populated, got ` +
      `"${doc.getElementById("signatureLabel").textContent}"`
  );
  Assert.equal(
    doc.getElementById("techLabel").textContent,
    "- GnuPG",
    "while the heading beside it names the engine"
  );

  doc.getElementById("messageSecurityPanel").hidePopup();
  await removeMessage();
});

/**
 * An identity holding one key in each store: both are listed, and they are
 * told apart.
 *
 * The sharpest form of the item's third check, and the reason 14.5 asks for
 * the mark per key rather than once for the page. A page-level badge would
 * have to be wrong about one of these two rows.
 */
add_task(async function anIdentityWithAKeyInEachStore() {
  const {
    click_account_tree_row,
    get_account_tree_row,
    promise_account_tree_load,
  } = ChromeUtils.importESModule(
    "resource://testing-common/mail/AccountManagerHelpers.sys.mjs"
  );
  const { open_content_tab_with_url } = ChromeUtils.importESModule(
    "resource://testing-common/mail/ContentTabHelpers.sys.mjs"
  );

  const both = MailServices.accounts.createAccount();
  both.incomingServer = MailServices.accounts.createIncomingServer(
    "bothstores",
    "bothstores.example",
    "pop3"
  );
  const identity = MailServices.accounts.createIdentity();
  identity.email = "bothstores@bothstores.example";
  both.addIdentity(identity);
  registerCleanupFunction(() =>
    MailServices.accounts.removeAccount(both, true)
  );

  // An internal key for this identity.
  const keyId = await OpenPGPTestUtils.importPrivateKey(
    window,
    fixture(KEY_DIR + BOB_SECRET_REL)
  );
  Assert.ok(keyId, "the profile holds a key");

  // And an external one configured on the same identity.
  identity.setBoolAttribute("is_gnupg_key_id", true);
  identity.setUnicharAttribute("last_entered_external_gnupg_key_id", "0xBEEF");
  registerCleanupFunction(() => {
    identity.setBoolAttribute("is_gnupg_key_id", false);
    identity.setUnicharAttribute("last_entered_external_gnupg_key_id", "");
  });

  const tab = await open_content_tab_with_url("about:accountsettings");
  await promise_account_tree_load(tab);
  await click_account_tree_row(
    tab,
    get_account_tree_row(both.key, "am-e2e.xhtml", tab)
  );

  const frame =
    tab.browser.contentWindow.document.getElementById("contentFrame");
  const doc = frame.contentDocument;
  await frame.contentDocument.documentGlobal.reloadOpenPgpUI();

  const radio = doc.getElementById("openPgpKeyListRadio");
  const pills = radio.querySelectorAll(".external-pill");
  const marks = radio.querySelectorAll(".openpgp-source-mark");

  info(
    `FINDING both stores: rows=${radio.children.length} ` +
      `pills=${pills.length} marks=${marks.length}`
  );
  Assert.equal(pills.length, 1, "the external key has its own row, once");
  Assert.equal(
    marks.length,
    1,
    "and exactly one row is marked, so the two stores are told apart"
  );
  Assert.ok(
    pills[0].closest(".content-blocking-category").contains(marks[0]),
    "the mark is on the external key's row, not on the internal one"
  );

  document.getElementById("tabmail").closeTab(tab);
});
