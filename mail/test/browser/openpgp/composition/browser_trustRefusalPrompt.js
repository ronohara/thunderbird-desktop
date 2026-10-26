/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 88f: when trust is the only thing missing, the refusal says so and
 * offers the per-message decision.
 *
 * Items 88d and 88e made the gate answerable; this is the surface that lets a
 * user find the answer. What it replaces, in the order the faults hurt:
 *
 *   - every refusal produced the same dialog whatever the reason, so a user
 *     whose key merely needed judging was told to obtain and accept a key;
 *   - the only action offered was to accept the key, which writes a lasting
 *     decision at the moment a message is trying to leave -- the exact reflex
 *     the per-message override exists to avoid;
 *   - and the assistant's own send button stayed visible and disabled, offering
 *     a control whose only job was to say no.
 *
 * The control below is the reason the section is specific: a recipient with no
 * key at all must still get the ordinary refusal, with no trust section. Without
 * it, a build that showed the section for every refusal would pass the first
 * task.
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

const STRICT_PREF = "mail.openpgp.require_trusted_keys";
const UNJUDGED = "bob@openpgp.example";
const UNJUDGED_KEY_ID = "FBFCC82A015E7330";
const UNJUDGED_FPR = "D1A66E1A23B182C9980F788CFBFCC82A015E7330";
const NO_KEY = "no-key-anywhere@openpgp.example";

let gAccount;

/**
 * Wait for the composer's encryption state to be recomputed.
 *
 * Bounded: an event that never fires would otherwise stall the harness for its
 * whole budget and say nothing about where it stopped.
 *
 * @param {Window} win
 * @returns {Promise<void>}
 */
function waitCheckEncryptionStateDone(win) {
  return Promise.race([
    BrowserTestUtils.waitForEvent(win.document, "encryption-state-checked"),
    new Promise((resolve, reject) => {
      // eslint-disable-next-line mozilla/no-arbitrary-setTimeout
      setTimeout(
        () => reject(new Error("encryption-state-checked never fired")),
        10000
      );
    }),
  ]);
}

/**
 * Open a composer addressed to one recipient, with encryption on, and attempt
 * the send so the refusal path runs.
 *
 * @param {string} recipient
 * @returns {Promise<{cwc: Window, proceeded: boolean}>} The composer, which the
 *   caller must close, and whether the send path agreed to proceed.
 */
async function attemptEncryptedSend(recipient) {
  await be_in_folder(gAccount.incomingServer.rootFolder);
  const cwc = await open_compose_new_mail();
  try {
    let checkDone = waitCheckEncryptionStateDone(cwc);
    await setup_msg_contents(cwc, recipient, "Item 88f", "Body.");
    await checkDone;

    checkDone = waitCheckEncryptionStateDone(cwc);
    cwc.gSendEncrypted = true;
    cwc.gUserTouchedSendEncrypted = true;
    cwc.updateEncryptionDependencies?.();
    cwc.document.dispatchEvent(
      new CustomEvent("encryption-state-checked", { bubbles: true })
    );
    await checkDone;

    // Called first, and not only for its answer: `determineSendFlags()` is what
    // fills `gMsgCompose.compFields` from the recipient pills when the body is
    // ready, and `prepareSendMsg()` throws "No recipients specified!" without
    // it. The working reference (`browser_encryptRefusal.js`) does the same and
    // for the same reason, which is what this test learned by failing.
    const details = await cwc.Enigmail.msg.determineSendFlags();
    info(`FINDING refusal details: ${JSON.stringify(details.errArray)}`);

    const proceeded = await cwc.Enigmail.msg.onSendOpenPGP(
      Ci.nsIMsgCompDeliverMode.Now
    );
    return { cwc, proceeded, details };
  } catch (ex) {
    await close_compose_window(cwc);
    throw ex;
  }
}

add_setup(async function () {
  requestLongerTimeout(5);

  gAccount = MailServices.accounts.createAccount();
  gAccount.incomingServer = MailServices.accounts.createIncomingServer(
    "u88f",
    "openpgp.example",
    "imap"
  );
  const identity = MailServices.accounts.createIdentity();
  identity.email = "u88f-sender@openpgp.example";
  gAccount.addIdentity(identity);

  // The sender needs a key, or the encryption path is skipped and the refusal
  // never happens -- the false pass browser_encryptRefusal.js records.
  const [keyId] = await OpenPGPTestUtils.importPrivateKey(
    window,
    new FileUtils.File(
      getTestFilePath(
        "../data/keys/alice@openpgp.example-0xf231550c4f47e38e-secret.asc"
      )
    )
  );
  Assert.ok(keyId, "the sender has a key");
  identity.setUnicharAttribute("openpgp_key_id", keyId.split("0x").join(""));

  // Bob: present, usable, and not trusted. The state the section is for.
  await OpenPGPTestUtils.importPublicKey(
    window,
    new FileUtils.File(
      getTestFilePath(
        "../data/keys/bob@openpgp.example-0xfbfcc82a015e7330-pub.asc"
      )
    )
  );
  await PgpSqliteDb2.updateAcceptance(UNJUDGED_FPR, [UNJUDGED], "unverified");
  registerCleanupFunction(() => PgpSqliteDb2.deleteAcceptance(UNJUDGED_FPR));

  await SpecialPowers.pushPrefEnv({
    set: [
      [STRICT_PREF, true],
      ["mail.e2ee.auto_enable", false],
      ["mail.e2ee.auto_disable", false],
      ["mail.e2ee.notify_on_auto_disable", false],
    ],
  });

  registerCleanupFunction(() => {
    MailServices.accounts.removeAccount(gAccount, true);
  });
});

/**
 * The item: the refusal names the address and the key, and offers the decision.
 */
add_task(async function theRefusalNamesTheKeyAndOffersTheDecision() {
  const { cwc, proceeded } = await attemptEncryptedSend(UNJUDGED);
  try {
    Assert.equal(proceeded, false, "the strict policy refused the send");

    const doc = cwc.document;
    await TestUtils.waitForCondition(
      () => {
        const section = doc.getElementById("keyAssistantTrustRefusal");
        return section && !section.hidden;
      },
      "the trust section appeared",
      100,
      50
    );

    Assert.ok(
      doc.getElementById("keyAssistant").open,
      "the assistant was opened to explain it"
    );

    const text = doc.getElementById("keyAssistantTrustRefusal").textContent;
    info(`FINDING trust section: ${JSON.stringify(text.trim())}`);
    Assert.ok(text.includes(UNJUDGED), "the section names the address");
    Assert.ok(
      text.includes(UNJUDGED_FPR),
      "and the fingerprint of the key that was refused"
    );

    // The section's button is the send button for this case, so the ordinary
    // one is not left beside it as a control that can only say no.
    Assert.ok(
      doc.getElementById("sendEncryptedButton").hidden,
      "the ordinary send button is not offered beside the answer"
    );

    // And the issues section's "obtain and accept a key" instruction is gone,
    // because this section has just explained that the key is present.
    Assert.ok(
      doc.getElementById("keyAssistantIssues").hidden,
      "the issues section does not contradict the trust section"
    );
  } finally {
    await close_compose_window(cwc);
  }
});

/**
 * The control: a recipient with no key at all gets the ordinary refusal and no
 * trust section.
 *
 * This is the task that fails if the reason is not threaded through, or if the
 * section is shown whenever there is any refusal.
 */
add_task(async function anAddressWithNoKeyGetsNoTrustSection() {
  const { cwc, proceeded, details } = await attemptEncryptedSend(NO_KEY);
  try {
    Assert.equal(proceeded, false, "the send is refused for want of a key");
    Assert.deepEqual(
      details.errArray.map(e => e.msg),
      ["ProblemNoKey"],
      "and the reason says there is no key, not that a key is untrusted"
    );

    const doc = cwc.document;
    await TestUtils.waitForCondition(
      () => doc.getElementById("keyAssistant")?.open,
      "the assistant opened",
      100,
      50
    );
    await TestUtils.waitForCondition(
      () =>
        doc.getElementById("keyAssistantIssues").textContent.includes(NO_KEY),
      "the panel names the address it cannot encrypt to",
      100,
      50
    );

    Assert.ok(
      doc.getElementById("keyAssistantTrustRefusal").hidden,
      "no trust section: this refusal is about a missing key, not an unjudged one"
    );
    Assert.ok(
      !doc.getElementById("keyAssistantIssues").hidden,
      "and the ordinary issues section is what explains it"
    );
  } finally {
    await close_compose_window(cwc);
  }
});

/**
 * The decision: the section's button turns the per-message override on, asks
 * for the send again, and the gate that refused a moment earlier now admits the
 * key.
 *
 * `goDoCommand` is replaced with a recorder, so the assertion is about what the
 * button decided rather than about a message actually leaving. The send path
 * itself is measured in `browser_encryptRefusal.js` and, for the override's
 * reach into it, by `test_trustOverrideGate.js`.
 */
add_task(async function theDecisionSendsAndWritesNothing() {
  const { cwc } = await attemptEncryptedSend(UNJUDGED);
  try {
    const doc = cwc.document;
    await TestUtils.waitForCondition(
      () => !doc.getElementById("keyAssistantTrustRefusal").hidden,
      "the trust section appeared",
      100,
      50
    );

    let commanded = null;
    cwc.goDoCommand = command => {
      commanded = command;
    };

    Assert.ok(
      !cwc.gTrustKeysForThisMessage,
      "the override is off before the user decides"
    );

    doc.getElementById("trustKeysForThisMessageButton").click();

    Assert.equal(
      commanded,
      "cmd_sendWithCheck",
      "the button asks for the send again rather than closing silently"
    );
    Assert.ok(
      cwc.gTrustKeysForThisMessage,
      "and turns the per-message override on"
    );

    // The gate the refusal came from now admits the key -- so the retry is not
    // a request to attempt the same refusal twice.
    const details = await cwc.Enigmail.msg.determineSendFlags();
    info(`FINDING after the decision: ${JSON.stringify(details.errArray)}`);
    Assert.deepEqual(
      details.errArray,
      [],
      "the same check that refused now passes, so the retried send can go ahead"
    );

    // Still not a trust decision: nothing was written.
    const stored = await PgpSqliteDb2.getFingerprintAcceptance(
      null,
      UNJUDGED_FPR
    );
    Assert.equal(
      stored,
      "unverified",
      "the key's acceptance is unchanged, so the override is per message"
    );
  } finally {
    await close_compose_window(cwc);
  }
});
