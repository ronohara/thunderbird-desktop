/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 79: the header badge names the engine that handled the message.
 *
 * The badge is composed, as it has always been: a label and the two status
 * icons, built by setMessageCryptoBox(). This adds one element to that row --
 * GnuPG's wing -- and lets the label follow the engine rather than always
 * saying OpenPGP.
 *
 * Two facts are kept apart, deliberately:
 *
 *   - `tech`, the OpenPGP/S-MIME distinction, stays on the `tech` attribute
 *     because that is what the security panel dispatches on and what CSS
 *     styles. It does not change.
 *   - `engine` is a new, separate attribute. It is set only when the profile
 *     records which engine ran.
 *
 * Which engine ran is a fact that exists for a message the user *sent*
 * (`is_gnupg_key_id` on the identity that sent it) and does not exist for a
 * received message, where it would have to be recorded at decryption time.
 * That is Item 79a, and until it lands a received message keeps the badge it
 * has always had rather than claiming an engine nobody wrote down. So these
 * checks cover the composition and the sent-message rule, not the received
 * case.
 *
 * Every wait here is bounded. A wrong selector should cost a named failure in
 * a few seconds, not the harness's whole budget.
 */

"use strict";

const {
  create_folder,
  get_about_message,
  get_special_folder,
  be_in_folder,
  select_click_row,
  wait_for_message_display_completion,
} = ChromeUtils.importESModule(
  "resource://testing-common/mail/FolderDisplayHelpers.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { PromiseTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mailnews/PromiseTestUtils.sys.mjs"
);
const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);

/**
 * Waits for a condition without letting a mistake hang the harness.
 *
 * @param {Function} condition
 * @param {string} what - Named in the failure, so a stall says what it wanted.
 */
async function waitFor(condition, what) {
  await TestUtils.waitForCondition(condition, `waiting for ${what}`, 100, 50);
}

var account;
var identity;
var inbox;

add_setup(async function () {
  account = MailServices.accounts.createAccount();
  account.incomingServer = MailServices.accounts.createIncomingServer(
    "badge",
    "badge.example",
    "pop3"
  );
  identity = MailServices.accounts.createIdentity();
  identity.email = "badge@badge.example";
  account.addIdentity(identity);
  // The engine fact this badge reads. Set through the same attribute the key
  // wizard sets, so the test exercises the real switch rather than a copy.
  identity.setBoolAttribute("is_gnupg_key_id", true);

  inbox = await get_special_folder(Ci.nsMsgFolderFlags.Inbox, true);
  await be_in_folder(inbox);
});

/**
 * The badge for a message the internal engine handled is unchanged.
 *
 * This is the regression guard for the whole item: adding a mark and a
 * condition to the label must leave every existing badge exactly as it was.
 */
add_task(async function thePresentBadgeIsUnchanged() {
  const openPgpFile = new FileUtils.File(
    getTestFilePath(
      "data/eml/signed-by-0xfbfcc82a015e7330-encrypted-to-0xf231550c4f47e38e.eml"
    )
  );
  const copyListener = new PromiseTestUtils.PromiseCopyListener();
  MailServices.copy.copyFileMessage(
    openPgpFile,
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

  const aboutMessage = get_about_message(window);
  const doc = aboutMessage.document;
  const label = doc.querySelector("#encryptionTechBtn .crypto-label");
  const mark = doc.getElementById("gnupgWingIcon");
  const box = doc.getElementById("cryptoBox");

  // The message is in the inbox, so no engine is recorded and the badge is the
  // one it has always been.
  Assert.equal(
    aboutMessage.Enigmail.hdrView.getMessageEngine(),
    null,
    "a received message has no recorded engine"
  );
  Assert.equal(
    box.getAttribute("tech"),
    "OpenPGP",
    "the technology is OpenPGP"
  );
  Assert.ok(!box.hasAttribute("engine"), "and no engine is claimed on the box");
  Assert.ok(mark.hidden, "the wing is not shown");
  Assert.equal(label.textContent, "OpenPGP", "and the label is unchanged");
});

/**
 * With the engine known to be GnuPG, the row gains the wing and the label
 * names GnuPG -- the composition the item asks for.
 *
 * Called on the live header with an explicit engine, because that is the one
 * input a received message cannot supply yet. The rendering path is the real
 * one: this is the function the OpenPGP overlay calls on every status update.
 */
add_task(async function theWingAndTheLabelFollowTheEngine() {
  const aboutMessage = get_about_message(window);
  const doc = aboutMessage.document;
  const label = doc.querySelector("#encryptionTechBtn .crypto-label");
  const mark = doc.getElementById("gnupgWingIcon");
  const box = doc.getElementById("cryptoBox");

  aboutMessage.setMessageCryptoBox(
    "OpenPGP",
    "ok",
    "verified",
    false,
    null,
    "gnupg"
  );

  Assert.equal(
    box.getAttribute("tech"),
    "OpenPGP",
    "the technology is unchanged"
  );
  Assert.equal(
    box.getAttribute("engine"),
    "gnupg",
    "and the engine is recorded on its own attribute"
  );
  Assert.ok(!mark.hidden, "the wing is shown");
  Assert.equal(
    mark.getAttribute("src"),
    "chrome://branding/content/gnupg-wing.svg",
    "pointing at the branding asset"
  );
  // Decoded, not merely referenced: a broken image in the header would be
  // worse than no mark, so the check is that the file loaded.
  await waitFor(
    () => mark.complete && mark.naturalWidth > 0,
    "the wing to load and decode"
  );

  // The size the design asks for, measured in the real header rather than
  // inferred from the file's own attributes: a stretched flex item would still
  // "show the wing" while being the wrong size.
  //
  // 20 rather than 16, decided 2026-10-27. Item 82 measured the drawing at the
  // size it is displayed and found that at 16px no row of it carries a gap
  // between the wing's feathers -- it reads as a solid leaf -- while one gap
  // returns at 20px. The assertion stays an exact size on both dimensions; what
  // moved is the value, because the design decision moved.
  const rect = mark.getBoundingClientRect();
  Assert.equal(Math.round(rect.width), 20, "the mark is 20px wide");
  Assert.equal(Math.round(rect.height), 20, "and 20px tall");

  // The label is localized, so it arrives asynchronously.
  await waitFor(() => label.textContent == "GnuPG", "the label to say GnuPG");
  Assert.equal(
    doc.getElementById("cryptoBox").getAttribute("tech"),
    "OpenPGP",
    "the technology did not change with the label"
  );
  Assert.ok(
    OpenPGPTestUtils.hasEncryptedIconState(doc, "ok"),
    "the encrypted icon is untouched"
  );
  Assert.ok(
    OpenPGPTestUtils.hasSignedIconState(doc, "verified"),
    "and so is the signed icon"
  );
});

/**
 * Going back to a message with no recorded engine clears both the mark and
 * the engine attribute -- the badge must not keep a stale claim.
 */
add_task(async function theBadgeForgetsTheEngine() {
  const aboutMessage = get_about_message(window);
  const doc = aboutMessage.document;

  aboutMessage.setMessageCryptoBox("OpenPGP", "ok", "verified", false, null);

  const label = doc.querySelector("#encryptionTechBtn .crypto-label");
  const mark = doc.getElementById("gnupgWingIcon");
  Assert.ok(mark.hidden, "the wing is hidden again");
  Assert.ok(!mark.hasAttribute("src"), "and its source is cleared");
  Assert.ok(
    !doc.getElementById("cryptoBox").hasAttribute("engine"),
    "no engine is claimed"
  );
  await waitFor(() => label.textContent == "OpenPGP", "the label to reset");
});

/**
 * The loop from decryption to the header, closed.
 *
 * Item 79a sets `decryptionEngine` on the result when GnuPG produced the
 * plaintext, `mimeDecrypt` carries it in the `extraDetails` JSON, and
 * `updatePgpStatus()` reads it into the view. That last step is what this
 * checks: fed the details a GnuPG decryption would produce, the badge must name
 * GnuPG -- and fed the details an internal decryption produces, it must not.
 *
 * The decryption branch itself is tested where it can be exercised against real
 * gpg, in `test_decryptionEngine.js`. This is the half that needs a window.
 */
add_task(async function theDecryptionEngineReachesTheBadge() {
  const aboutMessage = get_about_message(window);
  const doc = aboutMessage.document;
  const hdrView = aboutMessage.Enigmail.hdrView;
  const OpenPGP = aboutMessage.EnigmailConstants;

  registerCleanupFunction(() => hdrView.reset());

  const args = extraDetails => [
    0,
    OpenPGP.GOOD_SIGNATURE | OpenPGP.DECRYPTION_OKAY,
    0,
    "",
    "",
    { sigDate: null },
    "",
    "",
    JSON.stringify(extraDetails),
    "1",
  ];

  // What the external path produces.
  hdrView.updatePgpStatus(...args({ decryptionEngine: "gnupg" }));
  Assert.equal(
    hdrView.msgDecryptionEngine,
    "gnupg",
    "the engine recorded at decryption is read into the view"
  );
  Assert.equal(
    hdrView.getMessageEngine(),
    "gnupg",
    "and that is what the badge asks for"
  );
  await waitFor(
    () =>
      doc.querySelector("#encryptionTechBtn .crypto-label")?.textContent ==
      "GnuPG",
    "the badge to name GnuPG"
  );
  Assert.ok(
    !doc.getElementById("gnupgWingIcon").hidden,
    "with the wing beside it"
  );

  // What the internal path produces: no field, or null.
  hdrView.reset();
  hdrView.updatePgpStatus(...args({ decryptionEngine: null }));
  Assert.equal(
    hdrView.msgDecryptionEngine,
    null,
    "an internal decryption records no engine"
  );
  await waitFor(
    () =>
      doc.querySelector("#encryptionTechBtn .crypto-label")?.textContent ==
      "OpenPGP",
    "the badge to say OpenPGP again"
  );
  Assert.ok(doc.getElementById("gnupgWingIcon").hidden, "and the wing is gone");
});

/**
 * How much the two badges actually differ in width.
 *
 * Design 14.4 asks for both badges to be the same width so the header does not
 * shift between engines. Nothing enforces that in CSS: the label is real text
 * in the header's own font, and the drawing's 107-unit geometry was measured
 * with a different one. So this records the difference instead of pretending
 * it is zero, and Item 82 judges whether it matters on a real header.
 */
add_task(async function theTwoBadgesAreNotTheSameWidth() {
  const aboutMessage = get_about_message(window);
  const doc = aboutMessage.document;
  const label = doc.querySelector("#encryptionTechBtn .crypto-label");
  const button = doc.getElementById("encryptionTechBtn");

  aboutMessage.setMessageCryptoBox(
    "OpenPGP",
    "ok",
    "verified",
    false,
    null,
    "gnupg"
  );
  await waitFor(() => label.textContent == "GnuPG", "the GnuPG label");
  const withWing = button.getBoundingClientRect().width;

  aboutMessage.setMessageCryptoBox("OpenPGP", "ok", "verified", false, null);
  await waitFor(() => label.textContent == "OpenPGP", "the OpenPGP label");
  const withoutWing = button.getBoundingClientRect().width;

  info(
    `FINDING: the GnuPG badge is ${withWing.toFixed(1)}px wide and the OpenPGP ` +
      `badge ${withoutWing.toFixed(1)}px, so the header content shifts by ` +
      `${Math.abs(withWing - withoutWing).toFixed(1)}px between them. 14.4 asks ` +
      `for equal widths; nothing enforces it.`
  );
  Assert.ok(withWing > 0 && withoutWing > 0, "both badges were measured");
});

/**
 * The sent-message rule, against a real Sent folder.
 *
 * The engine is read from the identity that authored the message, so the whole
 * question is which identity matches the From address -- and the answer must
 * not be the default identity when nothing matches. `getIdentityForHeader()`
 * would answer exactly that way, which is why this uses a strict match and why
 * the second half of this check exists.
 */
add_task(async function onlyASentMessageFromOurIdentityNamesAnEngine() {
  // Built rather than looked up: `get_special_folder()` has no name for
  // SentMail and would call createLocalSubfolder(undefined).
  const sent = create_folder("Sent", [Ci.nsMsgFolderFlags.SentMail]);
  const hdrView = get_about_message(window).Enigmail.hdrView;

  Assert.equal(
    hdrView.getMessageEngine({ author: identity.email }, sent),
    "gnupg",
    "a message this identity sent was handled by GnuPG"
  );

  Assert.equal(
    hdrView.getMessageEngine({ author: "stranger@example.net" }, sent),
    null,
    "a sender that matches no identity is not attributed to GnuPG, even " +
      "though a GnuPG identity exists as the default"
  );

  Assert.equal(
    hdrView.getMessageEngine({ author: identity.email }, inbox),
    null,
    "and the same author is not attributed from a folder that is not Sent"
  );

  Assert.equal(
    hdrView.getMessageEngine({ author: identity.email }, null),
    null,
    "with no folder there is no message to attribute"
  );
});
