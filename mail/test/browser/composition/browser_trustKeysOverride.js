/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 91: one message may override the strict key policy.
 *
 * Enigmail's "trust the keys of all recipients", which relaxes the
 * key-acceptance question for the message being composed. Two things it must
 * be, and both are asserted here:
 *
 *   - **scoped to the message.** It disappears with the window; it is not a
 *     preference and it is not remembered.
 *   - **not a trust decision.** Nothing about the keyring changes when it is
 *     used. If it wrote, it would be Item 88 under another name, and the user
 *     would learn that a button in the composer marks a key trusted forever.
 *
 * The key used throughout is `unverified` -- usable, not trusted. That is the
 * exact state the override exists for: a key the user has not got round to
 * judging, and a message they want out now. A `rejected` key is deliberately
 * not covered: a rejection is a decision the user made, and the override
 * relaxes the absence of a decision rather than overturning one.
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
var { PgpSqliteDb2 } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/sqliteDb.sys.mjs"
);
var { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);

const STRICT_PREF = "mail.openpgp.require_trusted_keys";
const RECIPIENT = "bob@openpgp.example";
const BOB_KEY_ID = "FBFCC82A015E7330";
const BOB_FPR = "D1A66E1A23B182C9980F788CFBFCC82A015E7330";

let aliceAcct;

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

add_setup(async function () {
  requestLongerTimeout(2);

  aliceAcct = MailServices.accounts.createAccount();
  aliceAcct.incomingServer = MailServices.accounts.createIncomingServer(
    "alice",
    "openpgp.example",
    "imap"
  );
  const identity = MailServices.accounts.createIdentity();
  identity.email = "alice@openpgp.example";
  aliceAcct.addIdentity(identity);

  // Alice's own secret key, so the identity can encrypt at all.
  const [id] = await OpenPGPTestUtils.importPrivateKey(
    window,
    new FileUtils.File(
      getTestFilePath(
        "../openpgp/data/keys/alice@openpgp.example-0xf231550c4f47e38e-secret.asc"
      )
    )
  );
  Assert.ok(id, "private key id received");
  identity.setUnicharAttribute("openpgp_key_id", id.split("0x").join(""));

  // Bob's public key, accepted but not trusted: the state the override is for.
  await OpenPGPTestUtils.importPublicKey(
    window,
    new FileUtils.File(
      getTestFilePath(
        "../openpgp/data/keys/bob@openpgp.example-0xfbfcc82a015e7330-pub.asc"
      )
    )
  );
  await PgpSqliteDb2.updateAcceptance(BOB_FPR, [RECIPIENT], "unverified");
  registerCleanupFunction(() => PgpSqliteDb2.deleteAcceptance(BOB_FPR));

  await SpecialPowers.pushPrefEnv({ set: [[STRICT_PREF, true]] });
  await be_in_folder(aliceAcct.incomingServer.rootFolder);

  registerCleanupFunction(() => {
    MailServices.accounts.removeIncomingServer(aliceAcct.incomingServer, true);
    MailServices.accounts.removeAccount(aliceAcct, true);
  });
});

/**
 * The menu entry is offered only when there is a strict policy to relax.
 */
add_task(async function theControlAppearsOnlyForTheStrictPolicy() {
  const cwc = await open_compose_new_mail();
  try {
    cwc.setSecuritySettings("_Toolbar");
    const item = cwc.document.getElementById("menu_trustKeys_Toolbar");
    Assert.ok(item, "the menu entry exists");
    Assert.ok(!item.hidden, "and is shown, because the strict policy is on");
  } finally {
    await close_compose_window(cwc);
  }

  await SpecialPowers.pushPrefEnv({ set: [[STRICT_PREF, false]] });
  const cwc2 = await open_compose_new_mail();
  try {
    cwc2.setSecuritySettings("_Toolbar");
    Assert.ok(
      cwc2.document.getElementById("menu_trustKeys_Toolbar").hidden,
      "and hidden under the permissive policy, where it would relax nothing"
    );
  } finally {
    await close_compose_window(cwc2);
    await SpecialPowers.pushPrefEnv({ set: [[STRICT_PREF, true]] });
  }
});

/**
 * The override makes an unjudged key usable for this message.
 *
 * Under the strict policy Bob's `unverified` key is refused; with the override
 * on it is accepted. Read from `gEmailsWithMissingKeys`, which is what the
 * composer's own readiness decision is built from.
 */
add_task(async function theOverrideAcceptsAnUnjudgedKey() {
  const cwc = await open_compose_new_mail();
  try {
    cwc.gSendEncrypted = true;
    let done = waitCheckEncryptionStateDone(cwc);
    await setup_msg_contents(cwc, RECIPIENT, "Override", "Body.");
    await done;

    Assert.ok(
      cwc.gEmailsWithMissingKeys.includes(RECIPIENT),
      "without the override the unjudged key is refused"
    );

    // Turn it on the way the menu does.
    done = waitCheckEncryptionStateDone(cwc);
    cwc.onEncryptionChoice("trustkeys");
    await done;

    info(
      `FINDING override: missing=${JSON.stringify(cwc.gEmailsWithMissingKeys)} ` +
        `flag=${cwc.gTrustKeysForThisMessage}`
    );
    Assert.ok(cwc.gTrustKeysForThisMessage, "the flag is set for this message");
    Assert.ok(
      !cwc.gEmailsWithMissingKeys.includes(RECIPIENT),
      "and the recipient no longer counts as having no usable key"
    );
  } finally {
    await close_compose_window(cwc);
  }
});

/**
 * It writes nothing about the key.
 *
 * The acceptance value is the same before and after, which is the whole of the
 * claim that this is not a trust decision. Read from the database rather than
 * from a cache, so the assertion is about what persisted.
 */
add_task(async function theOverrideWritesNothing() {
  const before = await PgpSqliteDb2.getFingerprintAcceptance(null, BOB_FPR);

  const cwc = await open_compose_new_mail();
  try {
    const done = waitCheckEncryptionStateDone(cwc);
    cwc.onEncryptionChoice("trustkeys");
    await done;
    Assert.ok(cwc.gTrustKeysForThisMessage, "the override was used");
  } finally {
    await close_compose_window(cwc);
  }

  EnigmailKeyRing.clearCache();
  const after = await PgpSqliteDb2.getFingerprintAcceptance(null, BOB_FPR);
  info(`FINDING acceptance before=${before} after=${after}`);
  Assert.equal(after, before, "the key's acceptance is unchanged");
  Assert.equal(
    after,
    "unverified",
    "still the value the user set, not one the composer invented"
  );
});

/**
 * And it does not outlive the message.
 *
 * A new composer starts with the policy intact -- the override is per message,
 * so a user who relaxed it once must not find themself relaxed forever.
 */
add_task(async function theOverrideDoesNotOutliveTheMessage() {
  const first = await open_compose_new_mail();
  const done = waitCheckEncryptionStateDone(first);
  first.onEncryptionChoice("trustkeys");
  await done;
  Assert.ok(first.gTrustKeysForThisMessage, "the override was on");
  await close_compose_window(first);

  const second = await open_compose_new_mail();
  try {
    Assert.ok(
      !second.gTrustKeysForThisMessage,
      "a new message starts with the strict policy intact"
    );
  } finally {
    await close_compose_window(second);
  }
});
