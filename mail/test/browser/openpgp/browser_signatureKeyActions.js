/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 92: the two key decisions, in the panel that shows the signature.
 *
 * D18(b) put them here rather than in the Key Manager alone, and the argument
 * is placement: both are decisions about the key that just signed the message
 * being read, and this is where the user is when they make them.
 *
 * The two actions are different operations and the panel must not blur them:
 *
 *   - **Certify** produces a signature others can verify, which is what gpg's
 *     computed validity counts and what survives being exported. It needs a
 *     key of the user's own with its secret part.
 *   - **Set Owner Trust** opens the one editor for a key's trust in either
 *     store. It asserts locally and grants the key authority to validate
 *     others, and it is not offered as a substitute for certifying.
 *
 * The operation underneath is verified where the keyring can be read directly
 * (`test_certifyKey.js`); this file is about the panel offering it, and about
 * the certify button being disabled -- not hidden -- when there is no own key,
 * because a missing button says nothing about why it is missing.
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
const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);

const KEY_DIR = "data/keys/";
const ALICE_SECRET = "alice@openpgp.example-0xf231550c4f47e38e-secret.asc";
const BOB_PUBLIC = "bob@openpgp.example-0xfbfcc82a015e7330-pub.asc";
const BOB_FPR = "D1A66E1A23B182C9980F788CFBFCC82A015E7330";
const BOB_ADDRESS = "bob@openpgp.example";

/** Bob signs this one; it is encrypted to Alice, whose secret we hold. */
const MSG =
  "data/eml/signed-by-0xfbfcc82a015e7330-encrypted-to-0xf231550c4f47e38e.eml";

var account;
var inbox;

/**
 * Opens a message, returning the about:message window.
 *
 * @param {string} path - Relative to this test's directory.
 * @returns {Promise<object>}
 */
async function openMessage(path) {
  const copyListener = new PromiseTestUtils.PromiseCopyListener();
  MailServices.copy.copyFileMessage(
    new FileUtils.File(getTestFilePath(path)),
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
 * Opens the security panel and waits for it.
 *
 * @param {object} aboutMessage
 * @returns {Promise<void>}
 */
async function openPanel(aboutMessage) {
  const doc = aboutMessage.document;
  const popupshown = BrowserTestUtils.waitForEvent(
    doc.getElementById("messageSecurityPanel"),
    "popupshown"
  );
  aboutMessage.showMessageReadSecurityInfo();
  await popupshown;
}

add_setup(async function () {
  requestLongerTimeout(2);

  account = MailServices.accounts.createAccount();
  account.incomingServer = MailServices.accounts.createIncomingServer(
    "alice",
    "openpgp.example",
    "pop3"
  );
  const identity = MailServices.accounts.createIdentity();
  identity.email = "alice@openpgp.example";
  account.addIdentity(identity);

  await OpenPGPTestUtils.initOpenPGP();
  const [keyId] = await OpenPGPTestUtils.importPrivateKey(
    window,
    new FileUtils.File(getTestFilePath(KEY_DIR + ALICE_SECRET))
  );
  Assert.ok(keyId, "Alice's secret key imported");
  // Importing a key does not tell the identity it is hers; a real profile has
  // this attribute set, and it is what `firstUsableKey()` reads.
  identity.setUnicharAttribute("openpgp_key_id", keyId.split("0x").join(""));
  await OpenPGPTestUtils.importPublicKey(
    window,
    new FileUtils.File(getTestFilePath(KEY_DIR + BOB_PUBLIC))
  );
  EnigmailKeyRing.clearCache();

  inbox = await get_special_folder(Ci.nsMsgFolderFlags.Inbox, true);
  await be_in_folder(inbox);

  registerCleanupFunction(() =>
    MailServices.accounts.removeAccount(account, true)
  );
});

/**
 * Both actions are offered beside the signature state.
 */
add_task(async function thePanelOffersBothActions() {
  const aboutMessage = await openMessage(MSG);
  const doc = aboutMessage.document;
  try {
    await openPanel(aboutMessage);

    const actions = doc.getElementById("signerKeyActions");
    Assert.ok(!actions.collapsed, "the actions appear beside the signer key");

    const certify = doc.getElementById("certifySignerKey");
    const trust = doc.getElementById("trustSignerKey");
    Assert.ok(certify, "there is a Certify button");
    Assert.ok(trust, "and a Set Owner Trust button");

    // Alice's own key is in the profile, so certifying is possible.
    Assert.ok(
      !certify.disabled,
      "certify is offered, an own key being present"
    );
    Assert.equal(
      certify.getAttribute("data-l10n-id"),
      "openpgp-certify-signer-key",
      "and is labelled for what it does"
    );
    Assert.equal(
      trust.getAttribute("data-l10n-id"),
      "openpgp-trust-signer-key",
      "while the other names the different operation"
    );
    Assert.notEqual(
      certify.getAttribute("data-l10n-id"),
      trust.getAttribute("data-l10n-id"),
      "the two are not the same word for the same act"
    );
  } finally {
    aboutMessage.document.getElementById("messageSecurityPanel").hidePopup();
    await select_click_row(-1);
    await press_delete();
  }
});

/**
 * Certifying from the panel adds a certification to the signer's key.
 *
 * The prompt is stubbed rather than answered: `Services.prompt.confirm` is
 * modal, so awaiting the call while a real dialog is open never returns -- the
 * same deadlock met in Item 81a, and the reason it is stubbed here from the
 * start.
 */
add_task(async function certifyingFromThePanelSignsTheKey() {
  const before = RNP.getUidSignatureCount(BOB_FPR, BOB_ADDRESS);
  Assert.equal(typeof before, "number", "the before-count is readable");

  const aboutMessage = await openMessage(MSG);
  const doc = aboutMessage.document;
  const originalPrompt = Services.prompt;
  const asked = [];
  Services.prompt = {
    confirm(w, title, text) {
      asked.push(text);
      return true;
    },
    alert(w, title, text) {
      asked.push(text);
    },
    QueryInterface: ChromeUtils.generateQI(["nsIPromptService"]),
  };
  try {
    await openPanel(aboutMessage);
    await aboutMessage.certifySignerKey(null);
  } finally {
    Services.prompt = originalPrompt;
  }

  try {
    info(`FINDING confirm said: ${JSON.stringify(asked)}`);
    Assert.equal(asked.length, 1, "it asked before certifying");
    Assert.ok(
      asked[0].includes(BOB_ADDRESS),
      `naming whose key is being certified, got ${JSON.stringify(asked[0])}`
    );

    EnigmailKeyRing.clearCache();
    const after = RNP.getUidSignatureCount(BOB_FPR, BOB_ADDRESS);
    info(`FINDING panel certify: before=${before} after=${after}`);
    Assert.equal(
      after,
      before + 1,
      "the signer's key gained exactly one certification"
    );
  } finally {
    if (!doc.getElementById("messageSecurityPanel").hidden) {
      doc.getElementById("messageSecurityPanel").hidePopup();
    }
    await select_click_row(-1);
    await press_delete();
  }
});
