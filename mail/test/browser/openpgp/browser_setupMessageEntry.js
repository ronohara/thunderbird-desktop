/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 98 in the window: the entry point exists, and it is reachable.
 *
 * The message's structure is verified in `test_autocryptSetup.js`, where it can
 * be read packet by packet. This is about the two properties the compose path
 * adds and nothing else does:
 *
 *   - **the action exists and is user-initiated.** It is a menu item in the Key
 *     Manager's file menu; nothing calls it. The specification states creation
 *     as a MUST be user-initiated, and a menu entry is the shape of that: it
 *     cannot happen without a click.
 *   - **it refuses rather than producing a message it cannot complete.** With
 *     no key of one's own there is nothing to transfer, and the answer must be
 *     an explanation rather than a compose window holding an empty file.
 *
 * Deliberately not driven here: the setup-code dialog. It is modal, and the
 * flow through it is covered by `browser_setupCodeDialog.js` -- opening it from
 * this test would block the harness waiting for a click nobody can make.
 */

"use strict";

const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);

const ALICE_SECRET =
  "data/keys/alice@openpgp.example-0xf231550c4f47e38e-secret.asc";
const ALICE_FPR = "EB85BB5FA33A75E15E944E63F231550C4F47E38E";

let account;

/**
 * Opens the Key Manager and waits for its list.
 *
 * @returns {Promise<Window>}
 */
async function openKeyManager() {
  const win = Services.ww.openWindow(
    null,
    "chrome://openpgp/content/ui/enigmailKeyManager.xhtml",
    "_blank",
    "chrome,dialog,centerscreen,resizable",
    null
  );
  await BrowserTestUtils.waitForEvent(win, "load");
  await TestUtils.waitForCondition(
    () => win.gKeyListView?.rowCount >= 0,
    "the manager to load its list"
  );
  return win;
}

add_setup(async function () {
  requestLongerTimeout(2);

  account = MailServices.accounts.createAccount();
  account.incomingServer = MailServices.accounts.createIncomingServer(
    "item98",
    "item98.example",
    "pop3"
  );
  const identity = MailServices.accounts.createIdentity();
  identity.email = "item98@item98.example";
  account.addIdentity(identity);
  registerCleanupFunction(() =>
    MailServices.accounts.removeAccount(account, true)
  );

  await OpenPGPTestUtils.initOpenPGP();
  EnigmailKeyRing.clearCache();
});

/**
 * The action is in the menu, and nothing else calls it.
 */
add_task(async function theActionIsAUserInitiatedMenuEntry() {
  const win = await openKeyManager();
  try {
    const item = win.document.getElementById("createSetupMessage");
    Assert.ok(item, "the menu entry exists");
    Assert.equal(
      item.getAttribute("data-l10n-id"),
      "openpgp-key-man-create-setup-message",
      "and is labelled"
    );
    Assert.equal(
      item.getAttribute("oncommand"),
      "createAutocryptSetupMessage()",
      "calling the function this item adds"
    );
    Assert.equal(
      typeof win.createAutocryptSetupMessage,
      "function",
      "which exists on the window"
    );
  } finally {
    win.close();
  }
});

/**
 * With no key of its own, it explains rather than proceeding.
 *
 * Without Alice's key imported, the identity has nothing to transfer. The
 * assertion is on the alert, and on no compose window appearing: a compose
 * window holding an empty attachment would be worse than a refusal.
 */
add_task(async function withoutAKeyItExplainsAndStops() {
  EnigmailKeyRing.clearCache();
  const win = await openKeyManager();
  const originalPrompt = Services.prompt;
  const alerts = [];
  Services.prompt = {
    alert(w, title, text) {
      alerts.push(text);
    },
    QueryInterface: ChromeUtils.generateQI(["nsIPromptService"]),
  };
  try {
    await win.createAutocryptSetupMessage();
  } finally {
    Services.prompt = originalPrompt;
    win.close();
  }

  info(`FINDING refusal: ${JSON.stringify(alerts)}`);
  Assert.equal(alerts.length, 1, "it said why rather than doing nothing");
  Assert.ok(
    alerts[0].includes("no OpenPGP key"),
    `and named the reason, got ${JSON.stringify(alerts[0])}`
  );
});

/**
 * With a key, the dialog is what comes next.
 *
 * Asserted by stubbing the code dialog rather than opening it: the real one is
 * modal, and this file's question is whether the compose path *reaches* it with
 * a key in hand, not what the dialog does once open.
 */
add_task(async function withAKeyTheDialogIsOpened() {
  const [id] = await OpenPGPTestUtils.importPrivateKey(
    window,
    new FileUtils.File(getTestFilePath(ALICE_SECRET))
  );
  Assert.ok(id, "the key imported");
  // The identity has to know the key is hers; importing does not say so.
  account.defaultIdentity.setUnicharAttribute(
    "openpgp_key_id",
    id.split("0x").join("")
  );
  EnigmailKeyRing.clearCache();

  const win = await openKeyManager();
  let dialogOpened = 0;
  const originalOpenDialog = win.openDialog;
  win.openDialog = (...args) => {
    dialogOpened++;
    // Does not open anything: the first argument is the dialog's URL, and the
    // call is recorded rather than performed.
    Assert.ok(
      String(args[0]).endsWith("setupCodeDialog.xhtml"),
      `the setup code dialog is what opens next, got ${args[0]}`
    );
  };
  const originalPrompt = Services.prompt;
  Services.prompt = {
    alert(w, t, text) {
      Assert.ok(false, `no alert expected with a key present: ${text}`);
    },
    QueryInterface: ChromeUtils.generateQI(["nsIPromptService"]),
  };
  try {
    await win.createAutocryptSetupMessage();
  } finally {
    Services.prompt = originalPrompt;
    win.openDialog = originalOpenDialog;
    win.close();
  }

  info(`FINDING dialog opened ${dialogOpened} time(s)`);
  Assert.equal(dialogOpened, 1, "with a key, the code dialog opens once");
});
