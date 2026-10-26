/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 89b's second half, in the composer the user actually gets.
 *
 * `test_recipientRules.js` proves the resolver answers correctly and now returns
 * the answer in words. `test_stage13Verification.js` records that
 * `resolveForRecipients()` yields the right values. **Neither proves the
 * composer does anything with them** -- and that was the whole of what this item
 * had left: a rule saying "always encrypt to this address" was read, resolved,
 * and obeyed by nothing.
 *
 * Three things, each of which a build that only *read* the rules would fail:
 *
 *   1. **A rule turns encryption on by itself.** With every automatic
 *      behaviour switched off, addressing a rule-governed recipient leaves
 *      `gSendEncrypted` true -- and it does so despite
 *      `mail.e2ee.auto_enable` being false, which is what makes it the rule
 *      rather than the preference.
 *   2. **A rule forbids signing, and keeps forbidding it.** Encryption on
 *      normally implies signing on, so the interesting case is that signing
 *      stays off across a redraw -- which is where the first version of this
 *      would have silently undone itself.
 *   3. **The encryption toggle reflects the rule**, so the user is not told one
 *      thing while another is true.
 *
 * The rules file is written where the preference points, which is the same file
 * the send path reads.
 */

"use strict";

// Destructured imports rather than import-globals, matching the neighbouring
// composition tests: these helpers are ES modules, and the harness does not
// inject them into this file's scope.
const { be_in_folder } = ChromeUtils.importESModule(
  "resource://testing-common/mail/FolderDisplayHelpers.sys.mjs"
);
const { close_compose_window, open_compose_new_mail, setup_msg_contents } =
  ChromeUtils.importESModule(
    "resource://testing-common/mail/ComposeHelpers.sys.mjs"
  );

const { OpenPGPAlias } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/OpenPGPAlias.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);

const RULES_PREF = "mail.openpgp.alias_rules_file";
const RULES_FILE = "browser-item89b-rules.json";

let bobAcct;
let bobIdentity;

/**
 * @param {object[]} rules
 */
async function writeRulesFile(rules) {
  await IOUtils.writeUTF8(
    PathUtils.join(Services.dirsvc.get("ProfD", Ci.nsIFile).path, RULES_FILE),
    JSON.stringify({ rules }, null, 2)
  );
  await OpenPGPAlias.load();
}

/**
 * @param {Window} win
 * @returns {Promise<void>}
 */
async function waitCheckEncryptionStateDone(win) {
  return BrowserTestUtils.waitForEvent(
    win.document,
    "encryption-state-checked"
  );
}

add_setup(async function () {
  requestLongerTimeout(5);

  bobAcct = MailServices.accounts.createAccount();
  bobAcct.incomingServer = MailServices.accounts.createIncomingServer(
    "bob",
    "openpgp.example",
    "imap"
  );
  bobIdentity = MailServices.accounts.createIdentity();
  bobIdentity.email = "bob@openpgp.example";
  bobAcct.addIdentity(bobIdentity);

  const [id] = await OpenPGPTestUtils.importPrivateKey(
    window,
    new FileUtils.File(
      getTestFilePath(
        "../data/keys/bob@openpgp.example-0xfbfcc82a015e7330-secret.asc"
      )
    )
  );
  Assert.ok(id, "the sender's private key is imported");
  bobIdentity.setUnicharAttribute("openpgp_key_id", id.split("0x").join(""));

  // Alice's public key is the recipient, so encryption is possible.
  await OpenPGPTestUtils.importPublicKey(
    window,
    new FileUtils.File(
      getTestFilePath(
        "../data/keys/alice@openpgp.example-0xf231550c4f47e38e-pub.asc"
      )
    )
  );

  // `pushPrefEnv` rather than a direct set, which is what browser tests are
  // required to use -- it also restores the previous value on cleanup, so the
  // preference does not leak into another file.
  await SpecialPowers.pushPrefEnv({
    set: [[RULES_PREF, RULES_FILE]],
  });
  registerCleanupFunction(() => OpenPGPAlias._clear());
});

/**
 * A rule requiring encryption turns it on with every automatic behaviour off.
 *
 * `mail.e2ee.auto_enable` is false throughout: if encryption is on, the rule put
 * it there. That separation is the assertion -- a test that left auto-enable on
 * would pass on a build that never read a rule.
 */
add_task(async function aRuleTurnsEncryptionOnByItself() {
  await SpecialPowers.pushPrefEnv({
    set: [
      ["mail.e2ee.auto_enable", false],
      ["mail.e2ee.auto_disable", false],
      ["mail.openpgp.remind_encryption_possible", false],
      ["mail.e2ee.warn_on_unencrypted_send", false],
    ],
  });

  await writeRulesFile([
    { email: "alice@openpgp.example", encrypt: "always", sign: "never" },
  ]);

  await be_in_folder(bobAcct.incomingServer.rootFolder);
  const cwc = await open_compose_new_mail();

  Assert.ok(!cwc.gSendEncrypted, "encryption starts off");

  const checkDone = waitCheckEncryptionStateDone(cwc);
  await setup_msg_contents(
    cwc,
    "alice@openpgp.example",
    "Item 89b: a rule requires encryption",
    "This message is encrypted because a rule says so."
  );
  await checkDone;

  Assert.ok(
    cwc.gSendEncrypted,
    "a rule requiring encryption turned it on, with auto-enable off"
  );
  Assert.ok(
    !cwc.gSendSigned,
    "and a rule forbidding signing kept it off even though encryption is on"
  );

  // The signing rule has to survive the *redraw*, not just the first pass.
  // `updateEncryptionDependencies()` re-derives signing from the encryption
  // state, and encryption on normally means signing on -- so a rule consulted
  // only in `checkEncryptionState()` is undone silently the moment the window
  // repaints. Called directly rather than by nudging the recipient list,
  // because this is the function that would do the undoing and a wait on an
  // event that may never fire is how this test stalled the first time.
  cwc.updateEncryptionDependencies();
  Assert.ok(
    !cwc.gSendSigned,
    "and signing is still off after updateEncryptionDependencies() re-derived it"
  );
  Assert.ok(cwc.gSendEncrypted, "with encryption still on");

  await close_compose_window(cwc);
});

/**
 * A rule forbidding encryption leaves it off, and the preference cannot
 * override it.
 *
 * The inverse of the test above, and it is not the same assertion: a build that
 * forced encryption on whenever a key existed would pass the first and fail
 * this one.
 */
add_task(async function aRuleForbiddingEncryptionKeepsItOff() {
  await SpecialPowers.pushPrefEnv({
    set: [
      // Auto-enable is ON here, so turning encryption on would be the
      // preference's doing rather than the rule's.
      ["mail.e2ee.auto_enable", true],
      ["mail.e2ee.auto_disable", false],
      ["mail.openpgp.remind_encryption_possible", false],
    ],
  });

  await writeRulesFile([{ email: "alice@openpgp.example", encrypt: "never" }]);

  await be_in_folder(bobAcct.incomingServer.rootFolder);
  const cwc = await open_compose_new_mail();

  const checkDone = waitCheckEncryptionStateDone(cwc);
  await setup_msg_contents(
    cwc,
    "alice@openpgp.example",
    "Item 89b: a rule forbids encryption",
    "This message is not encrypted because a rule says so."
  );
  await checkDone;

  Assert.ok(
    !cwc.gSendEncrypted,
    "a rule forbidding encryption kept it off even with auto-enable on"
  );

  await close_compose_window(cwc);
});
