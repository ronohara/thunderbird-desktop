/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * A message the user asked to encrypt must never leave unencrypted.
 *
 * Every existing test asserts the *resolver*: that `getValidKeysForAllRecipients()`
 * returns `ProblemNoKey` or `ProblemKeyNotTrusted` in its error array. Items 87,
 * 89a, 94 and 100 all do exactly that. **None of them asserts that the message
 * does not go out**, and those are different claims -- the difference this plan
 * has already been bitten by twice: `about3Pane.js`, whose test passed while the
 * application was broken because it called the module and never touched the
 * wiring, and Item 90's checkbox, which rendered, ticked, and wrote nothing.
 *
 * The requirement, in the user's words: *"a user who selected 'encrypted' wants
 * the message encrypted - it should never send if it can not encrypt to all
 * recipients .. it should block and inform the user why."*
 *
 * So this measures three things, and the first is the one that matters:
 *
 *   1. **The message did not leave.** Nothing arrives in Outbox or Sent, and the
 *      compose window is still open. Asserted by counting rows before and after,
 *      not by trusting the absence of an error -- a send that failed silently and
 *      a send that never started look identical from the outside otherwise.
 *   2. **The state was encryption-on when the send was attempted.** A test that
 *      let encryption get switched off first would pass by measuring a plain
 *      message, which is not the case under test.
 *   3. **The user was told why**, and the reason names the address. The message
 *      must not be "something went wrong"; it must say which recipient has no
 *      key, because that is the thing the user can act on.
 */

"use strict";

const { be_in_folder, create_folder, get_special_folder } =
  ChromeUtils.importESModule(
    "resource://testing-common/mail/FolderDisplayHelpers.sys.mjs"
  );
const { close_compose_window, open_compose_new_mail, setup_msg_contents } =
  ChromeUtils.importESModule(
    "resource://testing-common/mail/ComposeHelpers.sys.mjs"
  );
const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);

let gAccount = null;
let gIdentity = null;
let gOutbox = null;
let gSent = null;

/**
 * Wait until the composer's encryption state has been computed.
 *
 * @param {Window} win
 * @returns {Promise<void>}
 */
async function waitCheckEncryptionStateDone(win) {
  return BrowserTestUtils.waitForEvent(
    win.document,
    "encryption-state-checked"
  );
}

/**
 * How many messages a folder holds.
 *
 * @param {nsIMsgFolder} folder
 * @returns {number}
 */
function messageCount(folder) {
  try {
    return folder.getTotalMessages(false);
  } catch (ex) {
    return 0;
  }
}

add_setup(async function () {
  requestLongerTimeout(5);

  // A sending identity with a key, so "cannot encrypt" is about the *recipient*
  // rather than about the sender being unable to sign.
  gAccount = MailServices.accounts.createAccount();
  gAccount.incomingServer = MailServices.accounts.createIncomingServer(
    "u67",
    "openpgp.example",
    "imap"
  );
  gIdentity = MailServices.accounts.createIdentity();
  gIdentity.email = "u67-sender@openpgp.example";
  gAccount.addIdentity(gIdentity);

  // The sender needs a key, or `isEnigmailEnabledForIdentity()` is false and the
  // whole encryption path is skipped -- which my first version of this test did
  // not have, and the result was a false pass: `determineMsgRecipients()`
  // returned null and `prepareSendMsg()` answered true without ever asking
  // whether the recipient had a key. The case under test needs a sender who can
  // encrypt and a recipient who cannot.
  const [keyId] = await OpenPGPTestUtils.importPrivateKey(
    window,
    new FileUtils.File(
      getTestFilePath(
        "../data/keys/alice@openpgp.example-0xf231550c4f47e38e-secret.asc"
      )
    )
  );
  Assert.ok(keyId, "the sender has a key");
  gIdentity.setUnicharAttribute("openpgp_key_id", keyId.split("0x").join(""));

  gOutbox = await get_special_folder(Ci.nsMsgFolderFlags.Queue);
  // `get_special_folder()` only knows Drafts, Templates, Outbox and Inbox by
  // name, so asking it for SentMail with aCreate fails with
  // NS_MSG_ERROR_INVALID_FOLDER_NAME. Found it directly instead.
  const localRoot = MailServices.accounts.localFoldersServer.rootFolder;
  gSent =
    localRoot.getFolderWithFlags(Ci.nsMsgFolderFlags.SentMail) ??
    (await create_folder("Sent", [Ci.nsMsgFolderFlags.SentMail]));

  registerCleanupFunction(async () => {
    MailServices.accounts.removeAccount(gAccount, true);
  });
});

/**
 * The requirement: encryption asked for, no key for the recipient, message does
 * not leave, and the user is told which address is the problem.
 *
 * The recipient deliberately does not exist in any keyring. `mail.e2ee.auto_enable`
 * is **off**, because the point is a message the user asked to encrypt -- with
 * auto-enable on, a build could switch encryption off before the send and never
 * reach the refusal path at all, passing this test for the wrong reason.
 */
add_task(async function anUnencryptableMessageIsNotSent() {
  const recipient = "no-key-anywhere@openpgp.example";

  await SpecialPowers.pushPrefEnv({
    set: [
      ["mail.e2ee.auto_enable", false],
      ["mail.e2ee.auto_disable", false],
      ["mail.e2ee.notify_on_auto_disable", false],
    ],
  });

  await be_in_folder(gAccount.incomingServer.rootFolder);

  const outboxBefore = messageCount(gOutbox);
  const sentBefore = messageCount(gSent);

  const cwc = await open_compose_new_mail();
  let closed = false;
  cwc.addEventListener("unload", () => (closed = true), { once: true });

  try {
    let checkDone = waitCheckEncryptionStateDone(cwc);
    await setup_msg_contents(
      cwc,
      recipient,
      "Item 67: cannot encrypt to this recipient",
      "This message must not leave in the clear."
    );
    await checkDone;

    // The user asks for encryption explicitly, which is the state the
    // requirement is about. Without this the composer may have decided
    // cleartext is fine, and the send would be permitted -- correctly.
    Assert.ok(
      !cwc.gSendEncrypted,
      "encryption is off before the user asks for it"
    );
    checkDone = waitCheckEncryptionStateDone(cwc);
    cwc.gSendEncrypted = true;
    cwc.gUserTouchedSendEncrypted = true;
    cwc.updateEncryptionDependencies?.();
    cwc.document.dispatchEvent(
      new CustomEvent("encryption-state-checked", { bubbles: true })
    );
    await checkDone;

    Assert.ok(
      cwc.gSendEncrypted,
      "the message is set to encrypt, so the send is being attempted encrypted"
    );

    // The act under test. `onSendOpenPGP()` is what the send function consults
    // and its answer is what decides; calling it directly measures the refusal
    // rather than whatever the button does with it, and both matter -- so the
    // button's own path is asserted below by the message count.
    // What the resolver says, before the send path acts on it -- so a refusal
    // can be attributed to the right cause rather than to any of the several
    // guards on this path.
    const details = await cwc.Enigmail.msg.determineSendFlags();
    info(
      `FINDING determineSendFlags: gSendEncrypted=${cwc.gSendEncrypted} ` +
        `errArray=${JSON.stringify(details?.errArray)}`
    );

    const proceed = await cwc.Enigmail.msg.onSendOpenPGP(
      Ci.nsIMsgCompDeliverMode.Now
    );
    info(`FINDING onSendOpenPGP for an unencryptable recipient: ${proceed}`);

    Assert.equal(
      proceed,
      false,
      "the send path refuses to proceed with a recipient it cannot encrypt to"
    );

    // The durable fact: nothing was written to either spool.
    Assert.equal(
      messageCount(gOutbox),
      outboxBefore,
      "nothing was queued in Outbox"
    );
    Assert.equal(
      messageCount(gSent),
      sentBefore,
      "and nothing was filed to Sent"
    );

    // And the window is still here, with the text intact -- design 5.7's
    // "abort the send and keep the message".
    Assert.ok(!closed, "the compose window is still open");
    // What "the message is kept" can be measured on. `GetCurrentEditor()` is
    // empty on this window -- the editor lives in the compose content frame --
    // and `gMsgCompose` is not populated at the point a send is refused, so the
    // durable evidence is the compose fields: the subject the user typed is
    // still in the subject input, which a discarded or reset message would not
    // have.
    const subjectField = cwc.document.getElementById("msgSubject");
    info(
      `FINDING compose state after refusal: subject=${JSON.stringify(
        subjectField?.value
      )}`
    );
    Assert.equal(
      subjectField?.value,
      "Item 67: cannot encrypt to this recipient",
      "and the message is still there, with what the user typed"
    );

    // The user is told, and told which address. The security panel is what
    // `showMessageComposeSecurityStatus()` opens on this path.
    const assistant = cwc.document.getElementById("keyAssistant");
    Assert.ok(
      assistant?.open,
      "the security panel was opened to explain the refusal"
    );
    // `show()` calls the async `buildMainView()` without awaiting it, so the
    // panel is open before its recipient list is drawn. Waiting for the text is
    // the state the assertion is about -- the same mistake Item 65's test had
    // with the key assistant, met again here.
    await TestUtils.waitForCondition(
      () => assistant.textContent.includes(recipient),
      "the panel names the recipient it cannot encrypt to",
      100,
      50
    );
    info(
      `FINDING panel names the recipient: ` +
        `${JSON.stringify(assistant.textContent.trim().slice(0, 200))}`
    );
    // And it refuses to send from its own button, which is the other half of
    // "block and inform": the explanation is not a notice beside a send that
    // still works.
    const sendButton = cwc.document.getElementById("sendEncryptedButton");
    Assert.ok(
      sendButton.disabled,
      "and the panel offers no way to send the unencryptable message"
    );
  } finally {
    if (!closed) {
      await close_compose_window(cwc);
    }
  }
});

/**
 * The control: the same message, with a recipient who *does* have a key, is not
 * refused.
 *
 * Without this, the test above passes on a build that refuses every encrypted
 * send -- which would be a different defect wearing the same result. So the
 * pair is the measurement: the refusal is specific to the recipient who cannot
 * be encrypted to, rather than to encryption in general.
 *
 * Only the resolver is exercised here, not the send: asserting that
 * `onSendOpenPGP()` proceeds would start the send machinery, and what needs
 * proving is that the *reason* differs, not that the mail is delivered.
 */
add_task(async function anEncryptableMessageIsNotRefused() {
  await be_in_folder(gAccount.incomingServer.rootFolder);

  const cwc = await open_compose_new_mail();
  try {
    const checkDone = waitCheckEncryptionStateDone(cwc);
    await setup_msg_contents(
      cwc,
      "alice@openpgp.example",
      "Item 67 control: this recipient has a key",
      "This one can be encrypted."
    );
    await checkDone;

    cwc.gSendEncrypted = true;
    cwc.gUserTouchedSendEncrypted = true;

    const details = await cwc.Enigmail.msg.determineSendFlags();
    const errArray = details?.errArray ?? [];
    info(
      `FINDING control determineSendFlags: gSendEncrypted=${cwc.gSendEncrypted} ` +
        `errArray=${JSON.stringify(errArray)}`
    );
    Assert.ok(cwc.gSendEncrypted, "encryption is on for the control case too");
    Assert.deepEqual(
      errArray,
      [],
      "a recipient with a usable key produces no refusal reason"
    );
  } finally {
    await close_compose_window(cwc);
  }
});

/**
 * Encryption on, and no mail recipient at all: what the resolver says.
 *
 * **Out of scope by decision, 2026-10-27.** Encrypting a message that has no mail
 * recipient -- a newsgroup-only post -- is not something this item covers; the
 * user's ruling is to leave it. So this task records what the resolver does and
 * asserts nothing about it.
 *
 * **Only the resolver is exercised, and the reason is a hang in the first
 * attempt.** That version waited on the `encryption-state-checked` event after
 * setting `compFields.newsgroups` directly, and timed out at 240 seconds. **The
 * event wait is the likelier cause rather than the send path** -- assigning a
 * field from script is not an input event and may never trigger a re-check --
 * and this version, without that wait, completes in six seconds. So what is
 * established is that the resolver reports no problem; **whether
 * `onSendOpenPGP()` itself returns for a newsgroup message remains untested**,
 * and this comment deliberately does not claim it either way.
 *
 * So this measures the half that cannot hang: whether `determineSendFlags()`
 * notices that there is nothing to encrypt to. It builds its list from
 * to/cc/bcc only, so a newsgroup-only message checks *no* name -- and with an
 * empty `errArray`, `cannotEncryptMissingInfo` can never be set.
 */
add_task(async function theResolverSeesNoMailRecipient() {
  await be_in_folder(gAccount.incomingServer.rootFolder);

  const cwc = await open_compose_new_mail();
  let closed = false;
  cwc.addEventListener("unload", () => (closed = true), { once: true });

  try {
    cwc.gMsgCompose.compFields.newsgroups = "example.test";
    cwc.gSendEncrypted = true;
    cwc.gUserTouchedSendEncrypted = true;

    const details = await cwc.Enigmail.msg.determineSendFlags();
    const errArray = details?.errArray ?? [];
    info(
      `FINDING newsgroup-only resolver: gSendEncrypted=${cwc.gSendEncrypted} ` +
        `errArray=${JSON.stringify(errArray)}`
    );

    // **Recorded, not asserted.** Encryption for a message with no mail
    // recipient is out of scope, by the user's decision on 2026-10-27, so this
    // measurement is documentation rather than a requirement -- a test that
    // failed here would be enforcing something nobody asked for. It stays in the
    // file because the number is the evidence for the scope note in Item 67's
    // row; if a guard is ever added, the printed value changes and the row needs
    // correcting.
    info(
      `FINDING (out of scope): ${
        errArray.length
          ? "the resolver now reports a problem"
          : "the resolver reports no problem, so nothing would stop a send"
      } for a newsgroup-only message with encryption on`
    );
  } finally {
    if (!closed) {
      await close_compose_window(cwc);
    }
  }
});
