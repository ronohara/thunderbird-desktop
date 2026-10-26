/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Functions related to the msgSecurityPane.inc.xhtml file, used in the message
 * header to display S/MIME and OpenPGP encryption and signature info.
 */

/* import-globals-from ../../../mailnews/extensions/smime/msgReadSMIMEOverlay.js */
/* import-globals-from ../../extensions/openpgp/content/ui/enigmailMessengerOverlay.js */
/* import-globals-from aboutMessage.js */

var { XPCOMUtils } = ChromeUtils.importESModule(
  "resource://gre/modules/XPCOMUtils.sys.mjs"
);

ChromeUtils.defineESModuleGetters(this, {
  EnigmailConstants: "chrome://openpgp/content/modules/constants.sys.mjs",
  EnigmailFuncs: "chrome://openpgp/content/modules/funcs.sys.mjs",
  EnigmailKeyRing: "chrome://openpgp/content/modules/keyRing.sys.mjs",
  EnigmailWindows: "chrome://openpgp/content/modules/windows.sys.mjs",
  MailUtils: "resource:///modules/MailUtils.sys.mjs",
});

var identityKeys = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/identityKeys.sys.mjs"
);

/**
 * Reveal message security popup panel with updated OpenPGP or S/MIME info.
 */
function showMessageReadSecurityInfo() {
  // Interrupt if no message is selected or no encryption technology was used.
  if (!gMessage || document.getElementById("cryptoBox").hidden) {
    return;
  }

  // OpenPGP.
  if (document.getElementById("cryptoBox").getAttribute("tech") === "OpenPGP") {
    Enigmail.msg.loadOpenPgpMessageSecurityInfo();
    showMessageSecurityPanel();
    return;
  }

  // S/MIME.
  if (gSignatureStatus === Ci.nsICMSMessageErrors.VERIFY_NOT_YET_ATTEMPTED) {
    showImapSignatureUnknown();
    return;
  }

  loadSmimeMessageSecurityInfo();
  showMessageSecurityPanel();
}

/**
 * Reveal the popup panel with the populated message security info.
 */
function showMessageSecurityPanel() {
  document
    .getElementById("messageSecurityPanel")
    .openPopup(
      document.getElementById("encryptionTechBtn"),
      "bottomright topright",
      0,
      0,
      false
    );
}

/**
 * Reset all values and clear the text of the message security popup panel.
 */
function onMessageSecurityPopupHidden() {
  // Hide the UI elements.
  document.getElementById("signatureHeader").collapsed = true;
  document.getElementById("encryptionHeader").collapsed = true;
  document.getElementById("signatureCert").collapsed = true;
  document.getElementById("signatureKey").collapsed = true;
  document.getElementById("viewSignatureKey").collapsed = true;
  document.getElementById("signerKeyActions").collapsed = true;
  document.getElementById("encryptionKey").collapsed = true;
  document.getElementById("encryptionCert").collapsed = true;
  document.getElementById("viewEncryptionKey").collapsed = true;
  document.getElementById("otherEncryptionKeys").collapsed = true;

  const keyList = document.getElementById("otherEncryptionKeysList");
  // Clear any possible existing key previously appended to the DOM.
  for (const node of keyList.children) {
    keyList.removeChild(node);
  }
}

async function viewSignatureKey(popupToHide) {
  if (popupToHide) {
    popupToHide.hidePopup();
  }

  // If the signature acceptance was edited, reload the current message.
  if (
    await EnigmailWindows.openKeyDetails(
      window,
      Enigmail.hdrView.msgSignatureKeyId,
      false
    )
  ) {
    ReloadMessage();
  }
}

/**
 * The signer's key as an object, or null.
 *
 * @returns {?EnigmailKeyObj}
 */
function signerKey() {
  const keyId = Enigmail.hdrView?.msgSignatureKeyId;
  if (!keyId) {
    return null;
  }
  EnigmailKeyRing.clearCache();
  return EnigmailKeyRing.getKeyById(keyId);
}

/**
 * The current identity's own key, which is what certifies another key.
 *
 * An identity can hold several; this takes the first usable for signing, which
 * is the same rule the composer uses when it names the signer.
 *
 * @returns {?EnigmailKeyObj}
 */
function ownSigningKey() {
  // The identity the message belongs to first, which is the right answer when
  // the message is in an account's own folder.
  if (gMessage) {
    const [identity] = MailUtils.getIdentityForHeader(gMessage);
    const key = identity ? identityKeys.firstUsableKey(identity, "sign") : null;
    if (key) {
      return key;
    }
  }

  // Then any identity that has one. A message can sit somewhere no identity
  // claims -- Local Folders, an imported archive, a folder in an account whose
  // identity has no key -- and the question the panel is asking is whether the
  // user has a key to certify with at all. Which key it is, is named in the
  // confirmation before anything is signed, so a fallback is visible rather
  // than silent.
  for (const candidate of MailServices.accounts.allIdentities) {
    const key = identityKeys.firstUsableKey(candidate, "sign");
    if (key) {
      return key;
    }
  }
  return null;
}

/**
 * Certify the key that signed this message (D18(b), Item 92).
 *
 * The operation Enigmail called "sign key": it produces a certification others
 * can verify, which is what gpg's computed validity counts and what survives
 * being exported. It is not owner trust, and the panel offers both so the
 * difference is visible rather than hidden behind one word.
 */
async function certifySignerKey(popupToHide) {
  const signer = signerKey();
  const own = ownSigningKey();

  if (!signer || !own) {
    Services.prompt.alert(
      window,
      null,
      await document.l10n.formatValue("openpgp-certify-no-own-key")
    );
    return;
  }

  const confirmed = Services.prompt.confirm(
    window,
    null,
    await document.l10n.formatValue("openpgp-certify-confirm", {
      signer: signer.userId,
      own: own.userId,
    })
  );
  if (!confirmed) {
    return;
  }

  // The address of the signer's user ID, because that is what a certification
  // is about: the claim that this key belongs to that person.
  const userId =
    EnigmailFuncs.getEmailFromUserID(signer.userId) || signer.userId;
  // Through the dispatcher rather than straight to RNP: for a key GnuPG holds,
  // signing it in this build's ring produces a signature gpg never sees, and
  // the strict policy judges by what gpg computed. `certifyKey()` sends each
  // key to the engine that owns it and records the judgment where the gate
  // reads it (Item 88a).
  const done = await EnigmailKeyRing.certifyKey(own.fpr, signer.fpr, userId);

  if (!done.ok) {
    console.warn(`Certifying ${signer.fpr} failed: ${done.error ?? ""}`);
    Services.prompt.alert(
      window,
      null,
      await document.l10n.formatValue("openpgp-certify-failed")
    );
    return;
  }

  if (popupToHide) {
    popupToHide.hidePopup();
  }
  EnigmailKeyRing.clearCache();
  ReloadMessage();
}

/**
 * Set owner trust on the key that signed this message.
 *
 * Item 88's operation, in the place D18(b) puts it. It asserts locally and
 * grants the key authority to validate others, and it is deliberately not
 * offered as a substitute for certifying: a keyring where everything is
 * ultimately trusted and nothing is signed has validity that evaporates on a
 * new machine.
 */
function trustSignerKey(popupToHide) {
  if (popupToHide) {
    popupToHide.hidePopup();
  }
  // Key Details is the one editor for a key's trust in both stores, so the
  // panel routes there rather than growing a second editor beside it.
  EnigmailWindows.openKeyDetails(
    window,
    Enigmail.hdrView.msgSignatureKeyId,
    false
  ).then(refresh => {
    if (refresh) {
      ReloadMessage();
    }
  });
}

function viewEncryptionKey(popupToHide) {
  if (popupToHide) {
    popupToHide.hidePopup();
  }

  EnigmailWindows.openKeyDetails(
    window,
    Enigmail.hdrView.msgEncryptionKeyId.keyId,
    false
  );
}
