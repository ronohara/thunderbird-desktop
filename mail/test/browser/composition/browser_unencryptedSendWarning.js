/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 90: warn me when a message is about to go out unencrypted.
 *
 * Enigmail's "confirm before sending" had five values; this carries the one
 * that is useful, as a plain on/off. The three checks are the three states the
 * notification can be in, and the middle one is the reason the item exists:
 *
 *   - the pref is off, so nothing is said;
 *   - the pref is on and the message is in the clear, so it says so and names
 *     the cause;
 *   - the message becomes encrypted, so the warning goes away -- a stale
 *     warning would be telling the user something untrue.
 *
 * A fourth check pins the decision not to double-speak: when encryption is
 * possible and the user has not touched the toggle, the existing "encryption
 * is possible" reminder already says it, with a one-click fix.
 */

"use strict";

var { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);
var { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
var { be_in_folder } = ChromeUtils.importESModule(
  "resource://testing-common/mail/FolderDisplayHelpers.sys.mjs"
);
var { close_compose_window, open_compose_new_mail, setup_msg_contents } =
  ChromeUtils.importESModule(
    "resource://testing-common/mail/ComposeHelpers.sys.mjs"
  );

const PREF = "mail.e2ee.warn_on_unencrypted_send";
const NOTIFICATION = "unencryptedSendWarning";

let bobAcct;

/**
 * @param {Window} win - The composer.
 * @returns {Promise<void>} Resolves when a status check has completed.
 */
function waitCheckEncryptionStateDone(win) {
  return BrowserTestUtils.waitForEvent(
    win.document,
    "encryption-state-checked"
  );
}

/**
 * @param {Window} win - The composer.
 * @returns {?object} The warning, if it is showing.
 */
function warning(win) {
  return win.gComposeNotification.getNotificationWithValue(NOTIFICATION);
}

add_setup(async function () {
  bobAcct = MailServices.accounts.createAccount();
  bobAcct.incomingServer = MailServices.accounts.createIncomingServer(
    "bob",
    "openpgp.example",
    "imap"
  );

  const bobIdentity = MailServices.accounts.createIdentity();
  bobIdentity.email = "bob@openpgp.example";
  bobAcct.addIdentity(bobIdentity);

  // Bob's own key, so encryption is *possible* for his identity. The tests
  // then choose whether that matters by addressing somebody with a key or
  // without one.
  const [id] = await OpenPGPTestUtils.importPrivateKey(
    window,
    new FileUtils.File(
      getTestFilePath(
        "../openpgp/data/keys/bob@openpgp.example-0xfbfcc82a015e7330-secret.asc"
      )
    )
  );
  Assert.ok(id, "private key id received");
  bobIdentity.setUnicharAttribute("openpgp_key_id", id.split("0x").join(""));

  await SpecialPowers.pushPrefEnv({ set: [[PREF, false]] });
  await be_in_folder(bobAcct.incomingServer.rootFolder);

  registerCleanupFunction(() => {
    MailServices.accounts.removeIncomingServer(bobAcct.incomingServer, true);
    MailServices.accounts.removeAccount(bobAcct, true);
  });
});

/**
 * With the pref off, an unencrypted message says nothing.
 *
 * The default, and the reason the item says "when the user asks to be warned":
 * a warning nobody asked for is noise.
 */
add_task(async function silentWhenTheUserDidNotAsk() {
  await SpecialPowers.pushPrefEnv({ set: [[PREF, false]] });

  const cwc = await open_compose_new_mail();
  try {
    const done = waitCheckEncryptionStateDone(cwc);
    await setup_msg_contents(
      cwc,
      "stranger@example.org",
      "No warning wanted",
      "Body."
    );
    await done;

    Assert.ok(!cwc.gSendEncrypted, "the message is not encrypted");
    Assert.equal(
      warning(cwc),
      null,
      "and no warning is shown, because none was asked for"
    );
  } finally {
    await close_compose_window(cwc);
  }
});

/**
 * With the pref on and no key for the recipient, the warning appears and names
 * the address.
 *
 * This is the case the existing "encryption is possible" reminder cannot
 * cover, because for this recipient encryption is not possible.
 */
add_task(async function warnsAndNamesTheRecipientWithNoKey() {
  await SpecialPowers.pushPrefEnv({ set: [[PREF, true]] });

  const cwc = await open_compose_new_mail();
  try {
    const done = waitCheckEncryptionStateDone(cwc);
    await setup_msg_contents(
      cwc,
      "nokey@example.org",
      "Will be in the clear",
      "Body."
    );
    await done;

    await TestUtils.waitForCondition(
      () => warning(cwc),
      "the unencrypted-send warning should appear"
    );

    // `notification-message` is the element that carries the localized text;
    // read it rather than a class name guessed from the widget.
    const messageEl = cwc.document.querySelector(
      `notification-message[value="${NOTIFICATION}"]`
    );
    Assert.ok(messageEl, "the notification has a message element");

    // The text lives inside the element's shadow root: `appendNotification()`
    // puts an l10n span into `moz-message-bar`'s `.message`, and translates the
    // fragment afterwards. Reading the light DOM finds an empty element, which
    // is what the first version of this test did.
    Assert.ok(messageEl.shadowRoot, "the message element has a shadow root");

    // The label is translated asynchronously. Waiting for text rather than
    // reading once separates a race from a string that never resolved -- and
    // if it never resolves, the timeout names what was missing.
    await TestUtils.waitForCondition(
      () => messageEl.shadowRoot.textContent.trim(),
      `the warning to be translated, l10n-id=${messageEl.getAttribute("data-l10n-id")}`
    );
    const label = messageEl.shadowRoot.textContent;
    info(`FINDING warning label: ${JSON.stringify(label)}`);
    Assert.ok(
      label?.includes("unencrypted"),
      `the warning says the message is unencrypted, got "${label}"`
    );
    Assert.ok(
      label?.includes("nokey@example.org"),
      `and names the recipient with no key, got "${label}"`
    );
  } finally {
    await close_compose_window(cwc);
  }
});

/**
 * Encrypting the message clears the warning.
 *
 * A warning that stayed after encryption was turned on would be telling the
 * user something untrue, which is worse than not warning at all.
 */
add_task(async function theWarningGoesWhenEncryptionComesOn() {
  await SpecialPowers.pushPrefEnv({ set: [[PREF, true]] });

  const cwc = await open_compose_new_mail();
  try {
    const done = waitCheckEncryptionStateDone(cwc);
    await setup_msg_contents(
      cwc,
      "nokey@example.org",
      "Then encrypted",
      "Body."
    );
    await done;

    await TestUtils.waitForCondition(
      () => warning(cwc),
      "the warning should appear first"
    );

    // Bob writing to himself: his own key is usable, so encryption can be
    // turned on and the warning has to go.
    const encrypted = waitCheckEncryptionStateDone(cwc);
    await OpenPGPTestUtils.toggleMessageEncryption(cwc);
    await encrypted;
    Assert.ok(cwc.gSendEncrypted, "encryption is now on");

    await TestUtils.waitForCondition(
      () => !warning(cwc),
      "and the warning is gone"
    );
  } finally {
    await close_compose_window(cwc);
  }
});

/**
 * The boundary of this notification: it does not double-speak.
 *
 * When encryption is possible for every recipient and the user has not touched
 * the toggle, the existing reminder offers to turn it on. A second
 * notification about the same fact -- one of which is fixable in a click --
 * would be worse than the reminder alone.
 */
add_task(async function quietWhenTheReminderAlreadySpeaks() {
  await SpecialPowers.pushPrefEnv({ set: [[PREF, true]] });

  const cwc = await open_compose_new_mail();
  try {
    const done = waitCheckEncryptionStateDone(cwc);
    // Bob to himself: encryption is possible, and untouched.
    await setup_msg_contents(cwc, "bob@openpgp.example", "Possible", "Body.");
    await done;

    Assert.ok(!cwc.gSendEncrypted, "encryption is off");
    Assert.ok(
      cwc.gComposeNotification.getNotificationWithValue("enableNotification"),
      "and the existing reminder is the one speaking"
    );
    Assert.equal(warning(cwc), null, "so the unencrypted warning stays quiet");
  } finally {
    await close_compose_window(cwc);
  }
});
