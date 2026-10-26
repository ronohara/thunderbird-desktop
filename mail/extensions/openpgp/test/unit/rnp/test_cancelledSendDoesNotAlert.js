/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 36, condition 4, the composer's half: **a cancelled send must not alert.**
 *
 * Design 5.7 asks for a cancellation to abort the send, keep the message, and be
 * distinguishable from a failure. Item 36's module half made it distinguishable
 * — `resultStatus.cancelled` is set and `gpgmeFailure()` words it as a
 * cancellation — and asserts that with a real pinentry refusing GETPIN.
 *
 * What that left undone was the composer: `encryptMessageStart()` alerted on
 * *any* non-zero exit, so a user who pressed Cancel was then shown a modal
 * telling them they had cancelled. The alert is the only user-facing report on
 * that path, because `mimeEncrypt.sys.mjs` turns the non-zero exit into a bare
 * throw with nothing else to say.
 *
 * **What this file covers, and what it deliberately does not.** The dependency
 * is stubbed here: `RNP.encryptAndOrSign` is replaced with one that sets the
 * result the module half produces. That is the right seam, because the two
 * halves are already separately proven —
 * `test_externalGnuPGPinentry.js` drives a *real* cancellation through a
 * pinentry stub and asserts `resultStatus.cancelled` is set (25/25). This file
 * takes that result as given and asks the question the composer owns: **does it
 * alert?**
 *
 * The control is the point. A test asserting "no alert" passes on a build that
 * never alerts about anything, so the same call is made with `cancelled` false
 * and must alert. Two outcomes, one variable.
 */

"use strict";

const { EnigmailEncryption } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/encryption.sys.mjs"
);
const { EnigmailConstants } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/constants.sys.mjs"
);
const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);

/**
 * Run `fn` with `Services.prompt` replaced by a recorder.
 *
 * `Services.prompt` is assignable, which is how `alertTestUtils.js` installs its
 * own mock; this does the same thing for one call and restores it afterwards,
 * including on throw.
 *
 * @param {Function} fn - Receives the array of recorded alerts.
 * @returns {*} Whatever `fn` returns.
 */
function withRecordingPrompt(fn) {
  const original = Services.prompt;
  const alerts = [];
  const mock = {
    QueryInterface: ChromeUtils.generateQI(["nsIPromptService"]),
    alert(window, title, text) {
      alerts.push({ title, text });
    },
    // Anything else reaching the prompt is a surprise on this path, and saying
    // so is better than silently returning a default that would look like
    // "the user chose OK".
    confirm() {
      throw new Error("unexpected confirm() on the send path");
    },
    prompt() {
      throw new Error("unexpected prompt() on the send path");
    },
  };
  Services.prompt = mock;
  try {
    return fn(alerts);
  } finally {
    Services.prompt = original;
  }
}

/**
 * Call `encryptMessageStart()` once with a stubbed crypto layer.
 *
 * Synchronous on purpose: `encryptMessageStart` itself is synchronous -- it
 * uses `EnigmailFuncs.sync()` to wait on the asynchronous crypto call -- so a
 * promise here would only add a shape to unpack.
 *
 * @param {object} options
 * @param {boolean} options.cancelled - What the crypto layer reports.
 * @returns {{returns: integer, alerts: object[]}}
 */
function startSendWith({ cancelled }) {
  const original = RNP.encryptAndOrSign;
  RNP.encryptAndOrSign = async (plaintext, args, resultStatus) => {
    resultStatus.exitCode = cancelled ? 83886179 : 67108949;
    resultStatus.statusFlags = 0;
    resultStatus.cancelled = cancelled;
    resultStatus.errorMsg = cancelled
      ? "Signing was cancelled. The message has not been sent and is still here."
      : "No pinentry was available.";
    resultStatus.blockSeparation = false;
    resultStatus.missingRecipients = [];
    return null;
  };

  try {
    return withRecordingPrompt(alerts => {
      const listener = {
        getInputForCrypto() {
          return "Item 36: a cancelled send must not alert.\r\n";
        },
        addCryptoOutput() {},
      };
      const returns = EnigmailEncryption.encryptMessageStart(
        0, // win: only ever passed to alert, which the recorder owns
        0, // uiFlags
        "sender@openpgp.example",
        "recipient@openpgp.example",
        "", // bcc
        null, // hashAlgorithm
        EnigmailConstants.SEND_ENCRYPTED |
          EnigmailConstants.SEND_SIGNED |
          EnigmailConstants.SEND_PGP_MIME,
        listener,
        {}, // statusFlagsObj
        { value: "" } // errorMsgObj
      );
      return { returns, alerts };
    });
  } finally {
    RNP.encryptAndOrSign = original;
  }
}

add_setup(async function () {
  do_get_profile();
});

/**
 * The claim: a cancellation reports nothing, and the send still stops.
 *
 * Both halves matter. An implementation that suppressed the alert *and* the
 * failure would look identical from the alert count alone, so the non-zero
 * return is asserted in the same task — that is what keeps the message from
 * being sent.
 */
add_task(async function aCancelledSendDoesNotAlert() {
  const { returns, alerts } = startSendWith({ cancelled: true });
  info(
    `FINDING cancelled: returns=${returns} alerts=${JSON.stringify(alerts)}`
  );

  Assert.deepEqual(
    alerts,
    [],
    "a cancelled send raises no alert -- the user is not told they cancelled"
  );
  Assert.notEqual(
    returns,
    0,
    "and the send still reports failure, so the message is not sent"
  );
});

/**
 * The control: the same call, not cancelled, **does** alert.
 *
 * Without this the test above passes on a build that never reports anything on
 * this path at all — which would be a worse defect than the one being fixed.
 * The recorder is proven to record by this task, so the empty array above means
 * "nothing was raised" rather than "nothing was watched".
 */
add_task(async function aFailedSendStillAlerts() {
  const { returns, alerts } = startSendWith({ cancelled: false });
  info(
    `FINDING not-cancelled: returns=${returns} ` +
      `alerts=${JSON.stringify(alerts.map(a => a.text))}`
  );

  Assert.equal(alerts.length, 1, "a genuine failure raises exactly one alert");
  Assert.ok(
    alerts[0].text.includes("No pinentry"),
    `and the alert carries the reason, got: "${alerts[0].text}"`
  );
  Assert.ok(
    !alerts[0].text.toLowerCase().includes("cancel"),
    "and it does not describe the failure as a cancellation"
  );
  Assert.notEqual(returns, 0, "the send is still refused");
});
