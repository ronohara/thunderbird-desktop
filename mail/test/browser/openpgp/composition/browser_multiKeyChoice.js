/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 67's check 1: when a recipient has more than one acceptable key, the
 * composer **tells the user a choice exists and leaves the choosing to them.**
 *
 * The requirement in the user's words: *"tell the user a choice exists. And let
 * them make that choice — it is not something the code decides."*
 *
 * Two things make this a statement about the build rather than about a string:
 *
 *   1. **Before Item 27a the code decided**, by ranking. It no longer does: a
 *      send encrypts to every accepted key, so the composer is not hiding a
 *      choice it made. What was left is that it showed a recipient with two keys
 *      exactly as it showed one — nothing decided, and nothing said.
 *   2. **This must not become a warning.** A message encrypted to both keys is
 *      correct, and during a rotation it is the only way to reach a reader who
 *      has not yet switched. So the control matters as much as the claim: the
 *      send button stays enabled, because the notice is information.
 *
 * The narrowing mechanism already exists and is deliberately not rebuilt: a rule
 * for the address names the keys and `getAliasKeyList()` confines the send path
 * to them, which is why the section's button opens the rules editor rather than
 * inventing a chooser.
 */

"use strict";

const { PgpSqliteDb2 } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/sqliteDb.sys.mjs"
);
const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { OpenPGPMasterpass } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/masterpass.sys.mjs"
);
const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);
// Destructured imports rather than import-globals, matching the neighbouring
// composition tests: these helpers are ES modules and the harness does not
// inject them into this file's scope.
const { close_compose_window, open_compose_new_mail } =
  ChromeUtils.importESModule(
    "resource://testing-common/mail/ComposeHelpers.sys.mjs"
  );

const MANY = "two-keys@openpgp.example";
const ONE = "one-key@openpgp.example";
const NONE = "no-key@openpgp.example";

let gAccount = null;

/**
 * Generates a personalised key the internal engine holds.
 *
 * @param {string} userId
 * @returns {Promise<object>} The EnigmailKey.
 */
async function generatePersonalKey(userId) {
  const pass = await OpenPGPMasterpass.retrieveOpenPGPPassword();
  const keyId = await RNP.genKey(userId, "ECC", 0, 0, pass);
  Assert.ok(keyId, `genKey() produced a key for ${userId}`);
  EnigmailKeyRing.clearCache();
  const key = EnigmailKeyRing.getKeyById(keyId);
  Assert.ok(key, `the key for ${userId} is in the ring`);
  await PgpSqliteDb2.acceptAsPersonalKey(key.fpr);
  EnigmailKeyRing.clearCache();
  return EnigmailKeyRing.getKeyById(keyId);
}

/**
 * Open the key assistant for a given recipient list.
 *
 * `show()` is the composer's own entry point and takes the recipients, so
 * calling it with a list means the test covers the same path a user reaches.
 * The wait is for the *rendered* content, not for the panel to open: `show()`
 * does not await its own async build, which is the flake Item 65's test records.
 *
 * @param {string[]} recipients
 * @returns {Promise<{win: Window, doc: Document}>}
 */
async function openAssistantFor(recipients) {
  const win = await open_compose_new_mail();
  const doc = win.document;
  win.gKeyAssistant.show(recipients, false);
  await TestUtils.waitForCondition(
    () => doc.getElementById("keyAssistant")?.open,
    "the key assistant should open"
  );
  await TestUtils.waitForCondition(
    () =>
      !doc.getElementById("keyAssistantValid").hidden ||
      !doc.getElementById("keyAssistantIssues").hidden,
    "the main view should be built",
    100,
    50
  );
  return { win, doc };
}

add_setup(async function () {
  requestLongerTimeout(5);

  gAccount = MailServices.accounts.createAccount();
  gAccount.incomingServer = MailServices.accounts.createIncomingServer(
    "u67c1",
    "openpgp.example",
    "imap"
  );
  const identity = MailServices.accounts.createIdentity();
  identity.email = "sender-67c1@openpgp.example";
  gAccount.addIdentity(identity);

  await generatePersonalKey(`Two Keys One <${MANY}>`);
  await generatePersonalKey(`Two Keys Two <${MANY}>`);
  await generatePersonalKey(`Only One <${ONE}>`);

  registerCleanupFunction(async () => {
    MailServices.accounts.removeAccount(gAccount, true);
  });
});

/**
 * The claim: a recipient with two accepted keys is called out, by name and with
 * a count, and the message stays sendable.
 */
add_task(async function aRecipientWithTwoKeysIsCalledOut() {
  const { win, doc } = await openAssistantFor([MANY]);
  try {
    const section = doc.getElementById("keyAssistantMultiKey");

    // `buildMultiKeyNotice()` runs at the end of `buildMainView()`, which is
    // async and unawaited by `show()` — so the wait is for the rendered state.
    await TestUtils.waitForCondition(
      () => !section.hidden,
      "the multi-key section should appear",
      100,
      50
    );

    const text = section.textContent;
    info(`FINDING multi-key section: ${JSON.stringify(text.trim())}`);

    Assert.ok(
      text.includes(MANY),
      `the notice names the recipient, read: "${text.trim()}"`
    );
    // Two keys, so the entry and the header both speak in the plural. Asserted
    // on the number rather than on the wording, so a copy change does not break
    // the test while a count that stopped being reported does.
    Assert.ok(
      /\b2\b/.test(text),
      `and says how many keys there are, read: "${text.trim()}"`
    );

    // The whole point: information, not a warning.
    Assert.ok(
      !doc.getElementById("sendEncryptedButton").disabled,
      "the send button stays enabled -- a second key is not a problem to fix"
    );
    Assert.ok(
      doc.getElementById("keyAssistantIssues").hidden,
      "and it is not listed among the issues"
    );

    // The route to choosing, which already existed and was not rebuilt.
    const button = doc.getElementById("multiKeyRulesButton");
    Assert.ok(button, "a control offers the place where a key can be chosen");
    Assert.ok(!button.hidden, "and it is visible");
  } finally {
    await close_compose_window(win);
  }
});

/**
 * The control: a recipient with one key shows nothing, and so does a mixed list
 * beyond the one address that has a choice.
 *
 * Without this the test above passes on a build that shows the notice for every
 * recipient — which would train the user to ignore it, the opposite of informing
 * them.
 */
add_task(async function oneKeySaysNothing() {
  const { win, doc } = await openAssistantFor([ONE]);
  try {
    await TestUtils.waitForCondition(
      () => !doc.getElementById("keyAssistantValid").hidden,
      "the main view should be built",
      100,
      50
    );
    Assert.ok(
      doc.getElementById("keyAssistantMultiKey").hidden,
      "a recipient with one accepted key produces no notice"
    );
  } finally {
    await close_compose_window(win);
  }
});

/**
 * A mixed list names only the address that has a choice.
 */
add_task(async function onlyTheAmbiguousAddressIsNamed() {
  const { win, doc } = await openAssistantFor([MANY, ONE]);
  try {
    const section = doc.getElementById("keyAssistantMultiKey");
    await TestUtils.waitForCondition(
      () => !section.hidden,
      "the multi-key section should appear for the ambiguous address",
      100,
      50
    );

    const text = section.textContent;
    info(`FINDING mixed list: ${JSON.stringify(text.trim())}`);
    Assert.ok(text.includes(MANY), "the ambiguous address is named");
    Assert.ok(
      !text.includes(ONE),
      `and the unambiguous one is not, read: "${text.trim()}"`
    );
  } finally {
    await close_compose_window(win);
  }
});
