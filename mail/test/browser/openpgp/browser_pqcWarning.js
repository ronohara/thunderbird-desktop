/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 76a: the PQC subkey button carries the interoperability cost, not just
 * a note that generation is slow.
 *
 * **Why the warning exists at all.** PQC arrived in GnuPG 2.5 and was never
 * backported, so a PQC subkey is usable only by software that supports it.
 * Measured 2026-10-27 rather than assumed: gpg 2.4.4 and 2.3.8 both report
 * `Pubkey: RSA, ELG, DSA, ECDH, ECDSA, EDDSA` — no PQC algorithm at all. They
 * import a key carrying a PQC subkey and can still *send* to it, because they
 * skip the subkey and use the older one. What they cannot do is read a message
 * encrypted **to** it: the packet arrives as algorithm 35, and the secret
 * subkey does not even import. So the cost is one-directional and easy to miss,
 * which is exactly why it has to be said at the button.
 *
 * **This file drives the button**, because a string that exists and a string
 * that reaches the user are different claims, and this plan has been bitten by
 * the difference more than once.
 *
 * The confirmation is answered by replacing `Services.prompt` wholesale rather
 * than by answering a real dialog: `confirm()` is called synchronously inside
 * the click handler, so a real one puts the click into a nested event loop and
 * nothing after it runs. Replacing the service is what `alertTestUtils.js`
 * does, and assigning a single method throws, because the service is an XPCOM
 * proxy.
 */

"use strict";

const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { EnigmailWindows } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/windows.sys.mjs"
);
const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { OpenPGPMasterpass } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/masterpass.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);

const KEY_DETAILS_URL = "chrome://openpgp/content/ui/keyDetailsDlg.xhtml";

/** The address policy: `canGenerateV4PQCEncryptionSubkey()` needs this suffix. */
const PQC_ADDRESS = "alice-pqc-test@example.com";

let gKeyId = null;

/**
 * Open the key details dialog and run the given function inside it.
 *
 * @param {string} keyId - A key in the keyring.
 * @param {function(Window):Promise} checks - Receives the dialog window.
 */
async function withKeyDetails(keyId, checks) {
  const onDialogLoaded = async function (dialogWindow) {
    try {
      await TestUtils.waitForCondition(
        () => dialogWindow.document.getElementById("keyId")?.value,
        "the key details should have loaded"
      );
      await checks(dialogWindow);
    } finally {
      dialogWindow.close();
    }
  };

  const dialogPromise = BrowserTestUtils.promiseAlertDialog(
    null,
    KEY_DETAILS_URL,
    { callback: onDialogLoaded }
  );
  await EnigmailWindows.openKeyDetails(window, keyId, false);
  await dialogPromise;
}

add_setup(async function () {
  requestLongerTimeout(2);
  await OpenPGPTestUtils.initOpenPGP();

  // A key the PQC policy admits: a v4 ECC primary, an encryption subkey to sit
  // beside the new one, and a user ID ending in `-pqc-test`.
  const pass = await OpenPGPMasterpass.retrieveOpenPGPPassword();
  gKeyId = await RNP.genKey(`Alice PQC <${PQC_ADDRESS}>`, "ECC", 0, 0, pass);
  Assert.ok(gKeyId, "a PQC-eligible key was generated");
  EnigmailKeyRing.clearCache();
});

/**
 * The warning reaches the user, and declining it adds nothing.
 *
 * Both halves matter: a warning that appears but does not gate is a notice
 * beside an action that still happens, and the item asks for a warning
 * *before* generation.
 */
add_task(async function theWarningNamesTheCompatibilityCost() {
  const key = EnigmailKeyRing.getKeyById(gKeyId);
  Assert.ok(key, "the key is in the ring");
  Assert.ok(
    RNP.canGenerateV4PQCEncryptionSubkeyByFpr(key.fpr),
    "and the PQC policy admits it, or this test proves nothing"
  );

  const subkeysBefore = key.subKeys.length;

  const realPrompt = Services.prompt;
  const asked = [];
  Services.prompt = {
    confirm(_parent, _title, text) {
      asked.push(text);
      return false; // decline: this task is about the warning, not the result
    },
    alert() {},
    QueryInterface: ChromeUtils.generateQI(["nsIPromptService"]),
  };

  try {
    await withKeyDetails(`0x${key.keyId}`, async win => {
      const doc = win.document;

      // Wait for the dialog's own async init before touching the tab. It reads
      // the key, works out `gCanAddPQCSubkey`, and only then refreshes the
      // add-subkey buttons -- so selecting the tab earlier than that gets the
      // selection overwritten and the button stays hidden. The subkey list
      // having rows is the observable sign that the key has been read.
      await TestUtils.waitForCondition(
        () => doc.getElementById("subkeyList")?.view?.rowCount > 0,
        "the dialog finished reading the key"
      );

      doc.getElementById("mainTabs").selectedTab =
        doc.getElementById("structureTab");

      const button = doc.getElementById("addPQCSubkeyButton");
      Assert.ok(button, "the PQC button exists");
      await TestUtils.waitForCondition(
        () => !button.hidden,
        "the PQC button is offered for this key"
      );

      // No nested event loop: the stub answers synchronously.
      EventUtils.synthesizeMouseAtCenter(button, {}, win);

      await TestUtils.waitForCondition(
        () => asked.length > 0,
        "the button asked for confirmation"
      );
    });
  } finally {
    Services.prompt = realPrompt;
  }

  Assert.equal(asked.length, 1, "the button asked exactly once");
  const text = asked[0];
  info(`FINDING the PQC confirmation says: ${JSON.stringify(text)}`);

  Assert.ok(/PQC/.test(text), "the warning names PQC");
  Assert.ok(
    /2\.4/.test(text),
    "and names the version that cannot use the subkey, so the warning is " +
      "actionable rather than vague"
  );
  Assert.ok(
    /cannot read/i.test(text),
    "and states the consequence rather than only the incompatibility"
  );

  // Declining leaves the key alone, which is what "before generation" means.
  EnigmailKeyRing.clearCache();
  const after = EnigmailKeyRing.getKeyById(gKeyId);
  Assert.equal(
    after.subKeys.length,
    subkeysBefore,
    "declining the warning generates nothing"
  );
});
