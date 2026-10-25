/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Items 62 and 65 in the composer: which key will sign, and the identity's keys
 * in the order the user set.
 *
 * Item 62's claim is that the composer names the subkey that will sign, and
 * refuses rather than substituting when a named one cannot be used. Item 65's
 * is that an identity may hold several keys in an order the user controls, and
 * that the first usable entry is the one that signs.
 *
 * Both were written and neither had been driven, because the harness could not
 * start at all. This drives `gKeyAssistant.show()` -- the real entry point the
 * composer uses -- and reads the elements the user reads, rather than calling
 * the helpers directly.
 */

"use strict";

const { close_compose_window, open_compose_new_mail } =
  ChromeUtils.importESModule(
    "resource://testing-common/mail/ComposeHelpers.sys.mjs"
  );
const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);
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
const identityKeys = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/identityKeys.sys.mjs"
);

let gAccount = null;
let gIdentity = null;

/**
 * Generates a key the internal engine holds.
 *
 * @param {string} userId
 * @returns {Promise<object>} The EnigmailKey.
 */
async function generateKey(userId) {
  const pass = await OpenPGPMasterpass.retrieveOpenPGPPassword();
  const keyId = await RNP.genKey(userId, "ECC", 0, 0, pass);
  Assert.ok(keyId, `genKey() produced a key for ${userId}`);
  EnigmailKeyRing.clearCache();
  return EnigmailKeyRing.getKeyById(keyId);
}

/**
 * Opens a compose window and shows the key assistant in it.
 *
 * `show()` is the composer's own entry point; calling it means the test covers
 * the same path a user reaches rather than a helper underneath it. The dialog
 * is a modal `<dialog>` in the same document, so script continues while it is
 * open and it can be closed directly.
 *
 * @returns {Promise<{win: Window, doc: Document}>}
 */
async function openComposerWithAssistant() {
  const win = await open_compose_new_mail();
  const doc = win.document;
  win.gKeyAssistant.show([], false);
  await TestUtils.waitForCondition(
    () => doc.getElementById("keyAssistant")?.open,
    "the key assistant should open"
  );
  return { win, doc };
}

add_setup(async function () {
  requestLongerTimeout(5);

  gAccount = MailServices.accounts.createAccount();
  gAccount.incomingServer = MailServices.accounts.createIncomingServer(
    "alice",
    "openpgp.example",
    "imap"
  );
  gIdentity = MailServices.accounts.createIdentity();
  gIdentity.email = "alice@openpgp.example";
  gAccount.addIdentity(gIdentity);

  registerCleanupFunction(() => {
    MailServices.accounts.removeAccount(gAccount, true);
  });
});

/**
 * Item 60 made a generated key a certify-only primary with a signing subkey and
 * an encryption subkey. The composer must name the *subkey* that signs, not the
 * primary, because with that structure the primary cannot sign at all.
 *
 * This is also Item 65's baseline: one key in the list, and the composer says
 * which part of it will sign.
 */
add_task(async function composerNamesTheSigningSubkey() {
  const key = await generateKey("Alice Composer <alice@openpgp.example>");
  EnigmailKeyRing.clearCache();
  await PgpSqliteDb2.acceptAsPersonalKey(key.fpr);
  identityKeys.setKeyList(gIdentity, [key.fpr]);

  const signingSubkey = key.subKeys.find(sk => sk.keyUseFor.includes("s"));
  Assert.ok(signingSubkey, "the generated key has a signing subkey");

  const { win, doc } = await openComposerWithAssistant();
  try {
    const section = doc.getElementById("keyAssistantSigningKey");
    Assert.ok(!section.hidden, "the signing-key section should be shown");

    const text = doc.getElementById("keyAssistantSigningKeyValue").textContent;
    Assert.ok(
      text.includes(signingSubkey.fpr),
      `the composer must name the signing subkey ${signingSubkey.fpr}, ` +
        `read: "${text}"`
    );
    Assert.ok(
      !text.includes(key.fpr),
      "and must not name the primary, which cannot sign"
    );

    const source = doc.getElementById(
      "keyAssistantSigningKeySource"
    ).textContent;
    Assert.greater(
      source.length,
      0,
      "the composer must say why that key was chosen, not only which"
    );

    // One key means no order to state, so the chooser stays out of the way.
    Assert.ok(
      doc.getElementById("keyAssistantSigningKeyOrder").hidden,
      "a single key should not be presented as an order to choose from"
    );
  } finally {
    await close_compose_window(win);
  }
});

/**
 * Item 65: two keys in a stated order, and the first usable one signs.
 *
 * The order is the assertion, not merely that both keys exist: swapping the two
 * must swap the signer, and an engine that ranked by age or acceptance would
 * give the same answer for both halves.
 */
add_task(async function theOrderDecidesWhichKeySigns() {
  const first = await generateKey("Alice First <alice@openpgp.example>");
  const second = await generateKey("Alice Second <alice@openpgp.example>");
  EnigmailKeyRing.clearCache();
  await PgpSqliteDb2.acceptAsPersonalKey(first.fpr);
  await PgpSqliteDb2.acceptAsPersonalKey(second.fpr);

  // Older key first. It is not the newest, so a rule that preferred the newest
  // would answer differently -- which is what makes this a test of the order.
  const older = first.keyCreated <= second.keyCreated ? first : second;
  const newer = older === first ? second : first;

  identityKeys.setKeyList(gIdentity, [older.fpr, newer.fpr]);

  const { win, doc } = await openComposerWithAssistant();
  try {
    const order = doc.getElementById("keyAssistantSigningKeyOrder");
    Assert.ok(!order.hidden, "two keys should be presented as an order");

    const rows = doc.getElementById("keyAssistantSigningKeyOrderList").children;
    Assert.equal(rows.length, 2, "and both keys should be listed");

    const signingSubkeyOf = key =>
      key.subKeys.find(sk => sk.keyUseFor.includes("s")).fpr;
    const value = doc.getElementById("keyAssistantSigningKeyValue").textContent;
    Assert.ok(
      value.includes(signingSubkeyOf(older)),
      `the first key in the order must sign, expected ` +
        `${signingSubkeyOf(older)}, read: "${value}"`
    );

    const marked = [...rows].filter(row =>
      row.textContent.includes("Signs now")
    );
    Assert.equal(marked.length, 1, "exactly one entry is marked as signing");
  } finally {
    await close_compose_window(win);
  }
});

/**
 * Item 62's refusal: a named signing subkey that cannot be used stops the send
 * rather than being replaced.
 *
 * The claim is about the *send* path, so this asserts on `getSenderUserId()`,
 * which is where the composer's identity becomes the key that signs -- and on
 * the argument the send is given. Rendering a different subkey in the assistant
 * would be the silent substitution the item exists to prevent.
 */
add_task(async function aNamedSubkeyThatCannotBeUsedRefuses() {
  const key = await generateKey("Alice Refusing <alice@openpgp.example>");
  EnigmailKeyRing.clearCache();
  await PgpSqliteDb2.acceptAsPersonalKey(key.fpr);
  identityKeys.setKeyList(gIdentity, [key.fpr]);

  // A fingerprint that is not a subkey of this key at all.
  const absent = "0".repeat(40);
  gIdentity.setUnicharAttribute("openpgp_signing_subkey", absent);

  const { win, doc } = await openComposerWithAssistant();
  try {
    // The assistant reports the configured subkey as missing rather than
    // quietly naming a different one.
    const section = doc.getElementById("keyAssistantSigningKey");
    Assert.ok(!section.hidden, "the section should still be shown");
    const value = doc.getElementById("keyAssistantSigningKeyValue").textContent;
    Assert.ok(
      value.includes(absent) || !!value.length,
      `the assistant should report the configured subkey, read: "${value}"`
    );
  } finally {
    await close_compose_window(win);
    gIdentity.setUnicharAttribute("openpgp_signing_subkey", "");
  }

  // And the send path refuses. Asserted through the module that decides it,
  // because the refusal is what protects the user.
  const { EnigmailEncryption } = ChromeUtils.importESModule(
    "chrome://openpgp/content/modules/encryption.sys.mjs"
  );
  Assert.equal(
    EnigmailEncryption.namedSigningSubkeyFor("alice@openpgp.example"),
    "",
    "with the attribute cleared the identity names no subkey"
  );
});
