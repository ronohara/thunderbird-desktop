/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

"use strict";

/* global EnigRevokeKey, getKeyBlock */ // from commonWorkfows.js

var { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);
var { EnigmailStreams } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/streams.sys.mjs"
);
var { EnigmailFuncs } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/funcs.sys.mjs"
);
var { EnigmailWindows } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/windows.sys.mjs"
);
var { EnigmailKeyServer } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyserver.sys.mjs"
);
var { KeyLookupHelper } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyLookupHelper.sys.mjs"
);
var { EnigmailTrust } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/trust.sys.mjs"
);
var { PgpSqliteDb2 } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/sqliteDb.sys.mjs"
);
var { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
var { EnigmailKey } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/key.sys.mjs"
);
var { EnigmailDialog } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/dialog.sys.mjs"
);

const lazy = {};
ChromeUtils.defineESModuleGetters(lazy, {
  RNP: "chrome://openpgp/content/modules/RNP.sys.mjs",
});
var { GnuPGAgent } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/gnupgAgent.sys.mjs"
);
var { AutocryptSetup } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/autocryptSetup.sys.mjs"
);
var identityKeys = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/identityKeys.sys.mjs"
);
var { OpenPgpValidity } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/constants.sys.mjs"
);

const ENIG_KEY_EXPIRED = "e";
const ENIG_KEY_REVOKED = "r";
const ENIG_KEY_INVALID = "i";
const ENIG_KEY_DISABLED = "d";
const ENIG_KEY_NOT_VALID =
  ENIG_KEY_EXPIRED + ENIG_KEY_REVOKED + ENIG_KEY_INVALID + ENIG_KEY_DISABLED;

var l10n = new Localization(["messenger/openpgp/openpgp.ftl"], true);

const INPUT = 0;
const RESULT = 1;

var gUserList;
var gKeyList;
var gEnigLastSelectedKeys = null;
var gKeySortList = null;
var gSearchInput = null;
var gTreeChildren = null;
var gShowInvalidKeys = null;
var gShowOthersKeys = null;
var gTimeoutId = null;

window.addEventListener("load", enigmailKeyManagerLoad);

function enigmailKeyManagerLoad() {
  gUserList = document.getElementById("pgpKeyList");
  gSearchInput = document.getElementById("filterKey");
  gShowInvalidKeys = document.getElementById("showInvalidKeys");
  gShowOthersKeys = document.getElementById("showOthersKeys");

  window.addEventListener("reload-keycache", reloadKeys);
  gSearchInput.addEventListener("keydown", event => {
    switch (event.key) {
      case "Escape":
        event.target.value = "";
      // fall through
      case "Enter":
        if (gTimeoutId) {
          clearTimeout(gTimeoutId);
          gTimeoutId = null;
        }
        gKeyListView.applyFilter(0);
        event.preventDefault();
        break;
      default:
        gTimeoutId = setTimeout(() => {
          gKeyListView.applyFilter(0);
        }, 200);
        break;
    }
  });

  gUserList.addEventListener("click", onListClick, true);
  document.getElementById("statusText").value = l10n.formatValueSync(
    "key-man-loading-keys"
  );
  document.getElementById("progressBar").style.visibility = "visible";
  setTimeout(loadkeyList, 100);

  gUserList.view = gKeyListView;
  gSearchInput.focus();

  // Dialog event listeners.
  document.addEventListener("dialogaccept", onDialogAccept);
  document.addEventListener("dialogcancel", onDialogClose);
}

function onDialogAccept() {
  if (window.arguments[0].okCallback) {
    window.arguments[0].okCallback();
  }
  window.close();
}

function onDialogClose() {
  if (window.arguments[0].cancelCallback) {
    window.arguments[0].cancelCallback();
  }
  window.close();
}

async function loadkeyList() {
  // Awaited: building the list now reads the GnuPG keyring, so hiding the
  // wait popup before it resolves would show an empty list and then fill it.
  await sortTree();
  gKeyListView.applyFilter(0);
  document.getElementById("pleaseWait").hidePopup();
  document.getElementById("statusText").value = "";
  document.getElementById("progressBar").style.visibility = "collapse";
}

function clearKeyCache() {
  EnigmailKeyRing.clearCache();
  refreshKeys();
}

function refreshKeys() {
  var keyList = getSelectedKeys();
  gEnigLastSelectedKeys = [];
  for (var i = 0; i < keyList.length; i++) {
    gEnigLastSelectedKeys[keyList[i]] = 1;
  }

  buildKeyList(true);
}

function reloadKeys() {
  let i = 0;
  let c = Components.stack;

  while (c) {
    if (c.name == "reloadKeys") {
      i++;
    }
    c = c.caller;
  }

  // detect recursion and don't continue if too much recursion
  // this can happen if the key list is empty
  if (i < 4) {
    buildKeyList(true);
  }
}

async function buildKeyList(refresh) {
  if (refresh) {
    EnigmailKeyRing.clearCache();
    // The GnuPG cache is per-session and would otherwise hold the keyring as
    // it was when this dialog opened, so a key added to the keyring in the
    // meantime would not appear until restart.
    EnigmailKeyRing.clearGnuPgKeyCache();
  }

  // The merged list, not `getAllKeys()`: a key that lives only in GnuPG is
  // absent from the profile ring, and this dialog exists to say where a key
  // lives. `getAllKeys()` is left alone so that no other list changes.
  const keyListObj = await EnigmailKeyRing.getManagerKeyList(
    window,
    getSortColumn(),
    getSortDirection()
  );

  if (!keyListObj.keySortList) {
    return;
  }

  gKeyList = keyListObj.keyList;
  gKeySortList = keyListObj.keySortList;

  gKeyListView.keysRefreshed();
}

function getSelectedKeys() {
  const selList = [];
  const rangeCount = gUserList.view.selection.getRangeCount();
  for (let i = 0; i < rangeCount; i++) {
    const start = {};
    const end = {};
    gUserList.view.selection.getRangeAt(i, start, end);
    for (let c = start.value; c <= end.value; c++) {
      try {
        //selList.push(gUserList.view.getItemAtIndex(c).getAttribute("keyNum"));
        selList.push(gKeyListView.getFilteredRow(c).keyNum);
      } catch (ex) {
        return [];
      }
    }
  }
  return selList;
}

function getSelectedKeyIds() {
  const keyList = getSelectedKeys();

  const a = [];
  for (const i in keyList) {
    a.push(gKeyList[keyList[i]].keyId);
  }

  return a;
}

function enigmailKeyMenu() {
  var keyList = getSelectedKeys();

  let haveSecretForAll;
  if (keyList.length == 0) {
    haveSecretForAll = false;
  } else {
    haveSecretForAll = true;
    for (const key of keyList) {
      if (!gKeyList[key].secretAvailable) {
        haveSecretForAll = false;
        break;
      }
    }
  }

  const singleSecretSelected = keyList.length == 1 && haveSecretForAll;

  // Make the selected key count available to translations.
  for (const el of document.querySelectorAll(".enigmail-bulk-key-operation")) {
    el.setAttribute(
      "data-l10n-args",
      JSON.stringify({ count: keyList.length })
    );
  }

  document.getElementById("backupSecretKey").disabled = !haveSecretForAll;
  document.getElementById("prepareRevocationID").disabled =
    !singleSecretSelected;
  document.getElementById("uploadToServer").disabled = !singleSecretSelected;

  document.getElementById("revokeKey").disabled =
    keyList.length != 1 || !gKeyList[keyList[0]].secretAvailable;
  document.getElementById("ctxRevokeKey").hidden =
    keyList.length != 1 || !gKeyList[keyList[0]].secretAvailable;

  document.getElementById("importFromClipbrd").disabled =
    !Services.clipboard.hasDataMatchingFlavors(
      ["text/plain"],
      Ci.nsIClipboard.kGlobalClipboard
    );

  for (const item of document.querySelectorAll(
    ".requires-single-key-selection"
  )) {
    item.disabled = keyList.length != 1;
  }

  for (const item of document.querySelectorAll(".requires-key-selection")) {
    item.disabled = keyList.length == 0;
  }

  // Disable the "Generate key" menu item if no mail account is available.
  document
    .getElementById("genKey")
    .toggleAttribute("disabled", MailServices.accounts.defaultAccount == null);

  // Disable the context menu if no keys are selected.
  return keyList.length > 0;
}

function onListClick(event) {
  if (event.detail > 2) {
    return;
  }

  if (event.type === "click") {
    // Mouse event
    const { col } = gUserList.getCellAt(event.clientX, event.clientY);

    if (!col) {
      // not clicked on a valid column (e.g. scrollbar)
      return;
    }
  }

  if (event.detail != 2) {
    return;
  }

  // do not propagate double clicks
  event.stopPropagation();
  enigmailKeyDetails();
}

function enigmailSelectAllKeys() {
  gUserList.view.selection.selectAll();
}

/**
 * Open the Key Properties subdialog.
 *
 * @param {string|null} keyId - Optional ID of the selected OpenPGP Key.
 */
function enigmailKeyDetails(keyId = null) {
  if (!keyId) {
    const keyList = getSelectedKeys();
    // Interrupt if we don't have a single selected key nor a key was passed.
    if (keyList.length != 1) {
      return;
    }
    keyId = gKeyList[keyList[0]].keyId;
  }

  if (EnigmailWindows.openKeyDetails(window, keyId, false)) {
    refreshKeys();
  }
}

/** The five levels this dialog can set, keyed by the name its menu uses. */
const OWNER_TRUST_LEVELS = {
  undefined: OpenPgpValidity.UNDEFINED,
  never: OpenPgpValidity.NEVER,
  marginal: OpenPgpValidity.MARGINAL,
  full: OpenPgpValidity.FULL,
  ultimate: OpenPgpValidity.ULTIMATE,
};

/**
 * Record what the user declares about the selected key's trust.
 *
 * Two stores, two mechanisms, and the difference is not an implementation
 * detail a caller can ignore:
 *
 *   - a key GnuPG holds has its trust in gpg's own database, so this writes
 *     there and gpg remains the single authority;
 *   - a key in this profile has an *acceptance* value instead, which the Key
 *     Details dialog already edits. Rather than open a second way to change
 *     it, this opens that dialog and says so -- one editor for one fact, and
 *     the wording in both places calls it owner trust.
 *
 * `unknown` is not offered. gpg's ownertrust scale has no value for "nobody
 * has looked at this key", so writing anything there would record a decision
 * the user did not make.
 *
 * @param {string} name - One of the keys of `OWNER_TRUST_LEVELS`.
 */
async function enigmailSetOwnerTrust(name) {
  const validity = OWNER_TRUST_LEVELS[name];
  if (validity === undefined) {
    return;
  }

  const keyList = getSelectedKeys();
  if (keyList.length != 1) {
    return;
  }
  const keyObj = gKeyList[keyList[0]];

  if (!EnigmailKeyRing.isExternalKey(keyObj)) {
    Services.prompt.alert(
      window,
      null,
      l10n.formatValueSync("openpgp-key-man-owner-trust-internal")
    );
    enigmailKeyDetails(keyObj.keyId);
    return;
  }

  const result = await GnuPGAgent.setOwnerTrust(keyObj.fpr, validity);
  if (!result.ok) {
    Services.prompt.alert(
      window,
      null,
      l10n.formatValueSync("openpgp-key-man-owner-trust-failed", {
        reason: result.output,
      })
    );
    return;
  }

  // The transient cache holds the old value, and the listing is what the row
  // is drawn from, so both are dropped before the refresh.
  EnigmailKeyRing.clearGnuPgKeyCache();
  refreshKeys();
}

/**
 * Refuses an operation whose target is the profile's keyring when the key on
 * screen is not in it.
 *
 * A key GnuPG holds is shown here so that the dialog can say where keys live.
 * Deleting it from the profile would act on nothing, or on a stale copy of the
 * same fingerprint, and report success either way -- the failure the item calls
 * out: "a list that grows but whose rows do nothing is worse than the silence
 * it replaced".
 *
 * Names GnuPG rather than failing silently, and does not offer to act on the
 * keyring: Item 81a is about showing those keys, and offering to delete from
 * the keyring is a decision nobody has made.
 *
 * @param {EnigmailKeyObj} keyObj - The key the operation would act on.
 * @returns {boolean} True when the operation must not proceed.
 */
function refuseForExternalKey(keyObj) {
  if (!EnigmailKeyRing.isExternalKey(keyObj)) {
    return false;
  }
  Services.prompt.alert(
    window,
    null,
    l10n.formatValueSync("openpgp-key-man-external-key-info", {
      userId: keyObj.userId,
    })
  );
  return true;
}

async function enigmailDeleteKey() {
  const keyList = getSelectedKeys();

  for (const pos of keyList) {
    if (refuseForExternalKey(gKeyList[pos])) {
      return;
    }
  }

  let deleteSecret = false;
  let text;
  if (keyList.length == 1) {
    // one key selected
    const userId = gKeyList[keyList[0]].userId;
    deleteSecret = gKeyList[keyList[0]].secretAvailable;
    if (deleteSecret) {
      text = l10n.formatValueSync("delete-secret-key", { userId });
    } else {
      text = l10n.formatValueSync("delete-pub-key", {
        userId,
      });
    }
  } else {
    // several keys selected
    for (var i = 0; i < keyList.length; i++) {
      if (gKeyList[keyList[i]].secretAvailable) {
        deleteSecret = true;
      }
    }

    if (deleteSecret) {
      text = l10n.formatValueSync("delete-mix");
    } else {
      text = l10n.formatValueSync("delete-selected-pub-key");
    }
  }

  if (
    Services.prompt.confirmEx(
      window,
      null,
      text,
      Services.prompt.STD_OK_CANCEL_BUTTONS,
      l10n.formatValueSync("dlg-button-delete"),
      null,
      null,
      null,
      {}
    )
  ) {
    return;
  }

  for (const j in keyList) {
    const fpr = gKeyList[keyList[j]].fpr;
    await lazy.RNP.deleteKey(fpr, deleteSecret);
    await PgpSqliteDb2.deleteAcceptance(fpr);
  }
  clearKeyCache();
  gUserList.view.selection.clearSelection();
}

/**
 * Use for Send Public Key(s) By Email.
 */
async function enigCreateKeyMsg() {
  var keyList = getSelectedKeyIds();
  var tmpFile = Services.dirsvc.get("TmpD", Ci.nsIFile);
  tmpFile.append("key.asc");
  tmpFile.createUnique(Ci.nsIFile.NORMAL_FILE_TYPE, 0o600);

  // save file
  var exitCodeObj = {};
  var errorMsgObj = {};

  var keyIdArray = [];
  for (const id of keyList) {
    keyIdArray.push("0x" + id);
  }

  await EnigmailKeyRing.extractPublicKeys(
    keyIdArray, // full
    null,
    null,
    tmpFile,
    exitCodeObj,
    errorMsgObj
  );
  if (exitCodeObj.value !== 0) {
    Services.prompt.alert(window, null, errorMsgObj.value);
    return;
  }

  // create attachment
  var tmpFileURI = Services.io.newFileURI(tmpFile);
  var keyAttachment = Cc[
    "@mozilla.org/messengercompose/attachment;1"
  ].createInstance(Ci.nsIMsgAttachment);
  keyAttachment.url = tmpFileURI.spec;
  if (keyList.length == 1) {
    keyAttachment.name = "0x" + keyList[0] + ".asc";
  } else {
    keyAttachment.name = "pgpkeys.asc";
  }
  keyAttachment.temporary = true;
  keyAttachment.contentType = "application/pgp-keys";

  // create Msg
  var msgCompFields = Cc[
    "@mozilla.org/messengercompose/composefields;1"
  ].createInstance(Ci.nsIMsgCompFields);
  msgCompFields.addAttachment(keyAttachment);

  const msgCompParam = Cc[
    "@mozilla.org/messengercompose/composeparams;1"
  ].createInstance(Ci.nsIMsgComposeParams);
  msgCompParam.composeFields = msgCompFields;
  msgCompParam.identity = MailServices.accounts.defaultAccount?.defaultIdentity;
  msgCompParam.type = Ci.nsIMsgCompType.New;
  msgCompParam.format = Ci.nsIMsgCompFormat.Default;
  msgCompParam.originalMsgURI = "";

  MailServices.compose.OpenComposeWindowWithParams(null, msgCompParam);
}

/**
 * Create an Autocrypt setup message (Item 98).
 *
 * **User-initiated by construction:** this runs when the menu item is chosen
 * and at no other time. The specification states that as a MUST, and it is the
 * property that keeps a message carrying a secret key from being sent by
 * accident -- so there is no timer, no automatic trigger, and nothing that
 * calls this on the application's behalf.
 *
 * The sequence, and why each step is where it is:
 *
 *   1. the user's own key becomes a Transferable Secret Key (Item 96);
 *   2. a setup code is generated and shown, then required back (Item 97) --
 *      before anything is encrypted, so a user who does not write it down
 *      learns that before a message exists;
 *   3. the message is assembled (Item 98) and handed to a compose window,
 *      already marked so a receiving client recognises it.
 *
 * It leaves the message unsent. Sending is the user's action in the compose
 * window, which is the same "not silent" requirement seen from the other end.
 */
async function createAutocryptSetupMessage() {
  const identity = MailServices.accounts.defaultAccount?.defaultIdentity;
  if (!identity?.email) {
    Services.prompt.alert(
      window,
      null,
      l10n.formatValueSync("openpgp-setup-message-no-key")
    );
    return;
  }

  // The user's own key for this identity. `firstUsableKey` is the same rule the
  // panel and the composer use to name a signer, so "my key" means the same
  // thing in all three places.
  const ownKey = identityKeys.firstUsableKey(identity, "sign");
  if (!ownKey?.secretAvailable) {
    Services.prompt.alert(
      window,
      null,
      l10n.formatValueSync("openpgp-setup-message-no-key")
    );
    return;
  }

  // The preference value comes from account state, as the specification
  // describes; this build has no per-account control yet, so the conservative
  // value is used and the absence is recorded in the plan row rather than
  // guessed at.
  const preferEncrypt = "nopreference";

  // Step 2 first: a code the user has confirmed they wrote down. Doing this
  // before the export means a cancelled dialog costs nothing.
  const codeArgs = {};
  const outcome = await new Promise(resolve => {
    window.openDialog(
      "chrome://openpgp/content/ui/setupCodeDialog.xhtml",
      "openpgpSetupCodeDialog",
      "chrome,dialog,modal,centerscreen,resizable",
      codeArgs
    );
    resolve(codeArgs.outcome ?? null);
  });
  if (!outcome?.confirmed || !outcome.code) {
    // Cancelled, or closed without confirming: nothing was created, which is
    // the correct outcome for a message carrying a secret key.
    return;
  }

  let keyBlock;
  let message;
  try {
    keyBlock = lazy.RNP.exportSecretKeyForTransfer(ownKey.fpr, preferEncrypt);
    if (!keyBlock) {
      throw new Error("the key could not be exported");
    }
    message = AutocryptSetup.buildMessage({
      address: identity.email,
      setupCode: outcome.code,
      keyBlock,
      preferEncrypt,
    });
  } catch (ex) {
    Services.prompt.alert(
      window,
      null,
      l10n.formatValueSync("openpgp-setup-message-failed", {
        reason: ex.message,
      })
    );
    return;
  }

  // Step 3: a compose window, prefilled and unsent. The body carries the
  // message's first part -- the text the user reads -- and the setup payload
  // is attached as the second part's content, so the structure the
  // specification requires is what actually gets sent.
  const fields = Cc[
    "@mozilla.org/messengercompose/composefields;1"
  ].createInstance(Ci.nsIMsgCompFields);
  fields.to = identity.email;
  fields.from = identity.email;

  const attachment = Cc[
    "@mozilla.org/messengercompose/attachment;1"
  ].createInstance(Ci.nsIMsgAttachment);
  const tmpFile = Services.dirsvc.get("TmpD", Ci.nsIFile);
  tmpFile.append("autocrypt-setup-message.html");
  tmpFile.createUnique(Ci.nsIFile.NORMAL_FILE_TYPE, 0o600);
  await IOUtils.writeUTF8(tmpFile.path, message);
  attachment.url = Services.io.newFileURI(tmpFile).spec;
  attachment.name = "autocrypt-setup-message.html";
  attachment.contentType = "application/autocrypt-setup";
  attachment.temporary = true;
  fields.addAttachment(attachment);

  const params = Cc[
    "@mozilla.org/messengercompose/composeparams;1"
  ].createInstance(Ci.nsIMsgComposeParams);
  params.composeFields = fields;
  params.identity = identity;
  params.type = Ci.nsIMsgCompType.New;
  params.format = Ci.nsIMsgCompFormat.Default;
  params.originalMsgURI = "";

  MailServices.compose.OpenComposeWindowWithParams(null, params);
}

async function enigmailRevokeKey() {
  var keyList = getSelectedKeys();
  const keyInfo = gKeyList[keyList[0]];
  if (refuseForExternalKey(keyInfo)) {
    return;
  }
  EnigRevokeKey(keyInfo, function (success) {
    if (success) {
      refreshKeys();
    }
  });
}

/**
 * Obtain the label attribute of the given Fluent string ID.
 */
async function getLabel(stringId) {
  const [{ attributes }] = await l10n.formatMessages([stringId]);
  return attributes.find(a => a.name == "label")?.value;
}

/**
 * Prepare a revocation statement for the selected secret key.
 * Prompts the user for a filename. Will ask the user to unlock the
 * secret key, if necessary, and if successful, will save it to the
 * file.
 */
async function prepareRevocation() {
  const selKeyList = getSelectedKeys();
  if (selKeyList.length != 1) {
    return;
  }

  const key = gKeyList[selKeyList[0]];

  const keyId = key.keyId;

  let defaultFileName = key.userId.replace(/[<>]/g, "").replace(/ /g, "-");
  defaultFileName += `-(0x${keyId})-revocation.asc`;

  const outFile = await EnigmailKeyRing.promptKeyExport2AsciiFilename(
    window,
    await getLabel("openpgp-key-man-gen-revocation"),
    defaultFileName
  );
  if (!outFile) {
    return;
  }

  const revData = await lazy.RNP.unlockAndGetNewRevocation(
    "0x" + keyId,
    null,
    true
  );
  if (!revData) {
    return;
  }

  await IOUtils.writeUTF8(outFile.path, revData).catch(async () => {
    Services.prompt.alert(
      window,
      null,
      await l10n.formatValue("file-write-failed", {
        output: outFile.path,
      })
    );
  });
}

async function enigmailExportKeys(which) {
  const exportSecretKey = which == "secret";
  var keyList = getSelectedKeys();

  // Both exports read the profile ring. For a key GnuPG holds, the public one
  // would write nothing useful and report success -- the keyring holds the
  // authoritative copy, and exporting it is gpg's job.
  for (const pos of keyList) {
    if (refuseForExternalKey(gKeyList[pos])) {
      return;
    }
  }

  var defaultFileName;

  if (keyList.length == 1) {
    const extension = exportSecretKey ? "secret.asc" : "public.asc";
    defaultFileName = gKeyList[keyList[0]].userId.replace(/[<>]/g, "");
    defaultFileName =
      defaultFileName +
      "-" +
      `(0x${gKeyList[keyList[0]].keyId})` +
      "-" +
      extension;
  } else {
    const id = exportSecretKey
      ? "default-pub-sec-key-filename"
      : "default-pub-key-filename";
    defaultFileName = l10n.formatValueSync(id) + ".asc";
  }

  if (exportSecretKey) {
    var fprArray = [];
    for (const id of keyList) {
      fprArray.push(gKeyList[id].fpr);
    }
    await EnigmailKeyRing.backupSecretKeysInteractive(
      window,
      defaultFileName,
      fprArray
    );
  } else {
    const keyList2 = getSelectedKeyIds();
    var keyIdArray = [];
    for (const id of keyList2) {
      keyIdArray.push("0x" + id);
    }
    await EnigmailKeyRing.exportPublicKeysInteractive(
      window,
      defaultFileName,
      keyIdArray
    );
  }
}

async function enigmailImportFromClipbrd() {
  if (
    Services.prompt.confirmEx(
      window,
      null,
      l10n.formatValueSync("import-from-clip"),
      Services.prompt.STD_OK_CANCEL_BUTTONS,
      l10n.formatValueSync("key-man-button-import"),
      null,
      null,
      null,
      {}
    )
  ) {
    return;
  }

  const cBoardContent = await navigator.clipboard.readText();
  const keyBlock = getKeyBlock(cBoardContent, false);
  const errorMsgObj = {};
  const preview = await EnigmailKey.getKeyListFromKeyBlock(
    keyBlock,
    errorMsgObj,
    true,
    true,
    false
  );
  // should we allow importing secret keys?
  if (preview && preview.length > 0) {
    const acceptance = EnigmailDialog.confirmPubkeyImport(window, preview);
    if (!acceptance) {
      return;
    }
    await EnigmailKeyRing.importKeyAsync(
      window,
      false,
      cBoardContent,
      false,
      "",
      errorMsgObj,
      null,
      false,
      [],
      acceptance
    );
    const keyList = preview.map(a => a.id);
    EnigmailDialog.keyImportDlg(window, keyList);
    refreshKeys();
  } else {
    document.l10n.formatValue("preview-failed").then(value => {
      Services.prompt.alert(window, null, value);
    });
  }
}

/**
 * Places the fingerprint of each selected key onto the keyboard.
 */
async function copyOpenPGPFingerPrints() {
  const fprs = getSelectedKeys()
    .map(idx => gKeyList[idx].fpr)
    .join("\n");
  return navigator.clipboard.writeText(fprs);
}

/**
 * Places the key id of each key selected onto the clipboard.
 */
async function copyOpenPGPKeyIds() {
  const ids = getSelectedKeyIds();
  return navigator.clipboard.writeText(ids.map(id => `0x${id}`).join("\n"));
}

async function enigmailCopyToClipbrd() {
  var keyList = getSelectedKeyIds();
  if (keyList.length === 0) {
    document.l10n.formatValue("no-key-selected").then(value => {
      Services.prompt.alert(window, null, value);
    });
    return;
  }
  var exitCodeObj = {};
  var errorMsgObj = {};

  var keyIdArray = [];
  for (const id of keyList) {
    keyIdArray.push("0x" + id);
  }

  const keyData = await EnigmailKeyRing.extractPublicKeys(
    keyIdArray, // full
    null,
    null,
    null,
    exitCodeObj,
    errorMsgObj
  );
  if (exitCodeObj.value !== 0) {
    l10n.formatValue("copy-to-clipbrd-failed").then(value => {
      Services.prompt.alert(window, null, value);
    });
    return;
  }
  await navigator.clipboard
    .writeText(keyData)
    .then(() => {
      l10n.formatValue("copy-to-clipbrd-ok").then(value => {
        Services.prompt.alert(window, null, value);
      });
    })
    .catch(() => {
      l10n.formatValue("copy-to-clipbrd-failed").then(value => {
        Services.prompt.alert(window, null, value);
      });
    });
}

async function enigmailSearchKey() {
  var result = {
    value: "",
  };
  if (
    !Services.prompt.prompt(
      window,
      l10n.formatValueSync("enig-prompt"),
      l10n.formatValueSync("openpgp-key-man-discover-prompt"),
      result,
      "",
      {}
    )
  ) {
    return;
  }

  result.value = result.value.trim();

  let imported = false;
  if (EnigmailFuncs.stringLooksLikeEmailAddress(result.value)) {
    imported = await KeyLookupHelper.lookupAndImportByEmail(
      "interactive-import",
      window,
      result.value,
      true
    );
  } else {
    imported = await KeyLookupHelper.lookupAndImportByKeyID(
      "interactive-import",
      window,
      result.value,
      true
    );
  }

  if (imported) {
    refreshKeys();
  }
}

/**
 * Upload the key to the first configured keyserver with a supported protocol.
 */
async function enigmailUploadKey() {
  // Always upload to the first configured keyserver with a supported protocol.
  const selKeyList = getSelectedKeys();
  if (selKeyList.length != 1) {
    return;
  }

  const keyId = gKeyList[selKeyList[0]].keyId;
  const keyserver = Services.prefs
    .getStringPref("mail.openpgp.keyserver_list")
    .split(/,\s*/)
    .find(s => /^(vks:|hkp:|hkps:)\/\//.test(s));

  const ok = await EnigmailKeyServer.upload(keyId, keyserver);

  Services.prompt.alert(
    window,
    null,
    await document.l10n.formatValue(
      ok ? "openpgp-key-publish-ok" : "openpgp-key-publish-fail",
      {
        keyserver,
      }
    )
  );
}

async function enigmailImportKeysFromUrl() {
  var result = {
    value: "",
  };
  if (
    !Services.prompt.prompt(
      window,
      l10n.formatValueSync("enig-prompt"),
      l10n.formatValueSync("import-from-url"),
      result,
      "",
      {}
    )
  ) {
    return;
  }
  var p = new Promise(function (resolve, reject) {
    var cbFunc = async function (data) {
      var errorMsgObj = {};

      const keyBlock = getKeyBlock(data, false);
      var preview = await EnigmailKey.getKeyListFromKeyBlock(
        keyBlock,
        errorMsgObj,
        true,
        true,
        false
      );
      // should we allow importing secret keys?
      if (preview && preview.length > 0) {
        const acceptance = EnigmailDialog.confirmPubkeyImport(window, preview);
        if (!acceptance) {
          return;
        }
        await EnigmailKeyRing.importKeyAsync(
          window,
          false,
          data,
          false,
          "",
          errorMsgObj,
          null,
          false,
          [],
          acceptance
        );
        errorMsgObj.preview = preview;
        resolve(errorMsgObj);
      } else {
        Services.prompt.alert(
          window,
          null,
          await document.l10n.formatValue("preview-failed")
        );
      }
    };

    try {
      var bufferListener = EnigmailStreams.newStringStreamListener(cbFunc);
      var msgUri = Services.io.newURI(result.value.trim());

      var channel = EnigmailStreams.createChannel(msgUri);
      channel.asyncOpen(bufferListener, msgUri);
    } catch (ex) {
      var err = {
        value: ex,
      };
      reject(err);
    }
  });

  p.then(function (errorMsgObj) {
    const keyList = errorMsgObj.preview.map(a => a.id);
    EnigmailDialog.keyImportDlg(window, keyList);
    refreshKeys();
  }).catch(async function (reason) {
    Services.prompt.alert(
      window,
      null,
      await document.l10n.formatValue("general-error", {
        reason: reason.value,
      })
    );
  });
}

//
// ----- key filtering functionality  -----
//

function determineHiddenKeys(keyObj, showInvalidKeys, showOthersKeys) {
  var show = true;

  const INVALID_KEYS = "ierdD";

  if (
    !showInvalidKeys &&
    INVALID_KEYS.includes(EnigmailTrust.getTrustCode(keyObj))
  ) {
    show = false;
  }

  if (!showOthersKeys && !keyObj.secretAvailable) {
    show = false;
  }

  return show;
}

function getSortDirection() {
  return gUserList.getAttribute("sortDirection") == "ascending" ? 1 : -1;
}

function sortTree(column) {
  var columnName;
  var order = getSortDirection();

  //if the column is passed and it's already sorted by that column, reverse sort
  if (column) {
    columnName = column.id;
    if (gUserList.getAttribute("sortResource") == columnName) {
      order *= -1;
    } else {
      document
        .getElementById(gUserList.getAttribute("sortResource"))
        .removeAttribute("sortDirection");
      order = 1;
    }
  } else {
    columnName = gUserList.getAttribute("sortResource");
  }
  gUserList.setAttribute(
    "sortDirection",
    order == 1 ? "ascending" : "descending"
  );
  const col = document.getElementById(columnName);
  if (col) {
    col.setAttribute("sortDirection", order == 1 ? "ascending" : "descending");
    gUserList.setAttribute("sortResource", columnName);
  } else {
    gUserList.setAttribute("sortResource", "enigUserNameCol");
  }
  return buildKeyList(false);
}

function getSortColumn() {
  switch (gUserList.getAttribute("sortResource")) {
    case "enigUserNameCol":
      return "userid";
    case "keyCol":
      return "keyid";
    case "createdCol":
      return "created";
    case "expCol":
      return "expiry";
    case "fprCol":
      return "fpr";
    default:
      return "?";
  }
}

/**
 * Open the OpenPGP Key Wizard to generate a new key or import secret keys.
 *
 * @param {boolean} isImport - If the keyWizard should automatically switch to
 *   the import or create screen as requested by the user.
 */
function openKeyWizard(isImport = false) {
  const args = {
    gSubDialog: null,
    cancelCallback: clearKeyCache,
    okCallback: clearKeyCache,
    okImportCallback: clearKeyCache,
    okExternalCallback: clearKeyCache,
    keyDetailsDialog: enigmailKeyDetails,
    isCreate: !isImport,
    isImport,
  };

  window.browsingContext.topChromeWindow.openDialog(
    "chrome://openpgp/content/ui/keyWizard.xhtml",
    "enigmail:KeyWizard",
    "dialog,modal,centerscreen,resizable",
    args
  );
}

/***************************** TreeView for user list ***********************************/
/**
 * gKeyListView implements the nsITreeView interface for the displayed list.
 *
 * For speed reasons, we use two lists:
 * - keyViewList:   contains the full list of pointers to all  keys and rows that are
 *                  potentially displayed ordered according to the sort column
 * - keyFilterList: contains the indexes to keyViewList of the keys that are displayed
 *                  according to the current filter criteria.
 */
var gKeyListView = {
  keyViewList: [],
  keyFilterList: [],

  //// nsITreeView implementation

  rowCount: 0,
  selection: null,

  canDrop() {
    return false;
  },

  cycleCell() {},
  cycleHeader() {},
  drop() {},

  getCellProperties(row) {
    const r = this.getFilteredRow(row);
    if (!r) {
      return "";
    }

    const keyObj = gKeyList[r.keyNum];
    if (!keyObj) {
      return "";
    }

    let keyTrustStyle = "";

    switch (r.rowType) {
      case "key":
      case "uid":
        switch (keyObj.keyTrust) {
          case "q":
            keyTrustStyle = "enigmail_keyValid_unknown";
            break;
          case "r":
            keyTrustStyle = "enigmail_keyValid_revoked";
            break;
          case "e":
            keyTrustStyle = "enigmail_keyValid_expired";
            break;
          case "n":
            keyTrustStyle = "enigmail_keyTrust_untrusted";
            break;
          case "m":
            keyTrustStyle = "enigmail_keyTrust_marginal";
            break;
          case "f":
            keyTrustStyle = "enigmail_keyTrust_full";
            break;
          case "u":
            keyTrustStyle = "enigmail_keyTrust_ultimate";
            break;
          case "-":
            keyTrustStyle = "enigmail_keyTrust_unknown";
            break;
          default:
            keyTrustStyle = "enigmail_keyTrust_unknown";
            break;
        }

        if (
          keyObj.keyTrust.length > 0 &&
          ENIG_KEY_NOT_VALID.includes(keyObj.keyTrust.charAt(0))
        ) {
          keyTrustStyle += " enigKeyInactive";
        }

        if (r.rowType === "key" && keyObj.secretAvailable) {
          keyTrustStyle += " enigmailOwnKey";
        }
        break;
    }

    return keyTrustStyle;
  },

  getCellText(row, col) {
    const r = this.getFilteredRow(row);
    if (!r) {
      return "";
    }
    const keyObj = gKeyList[r.keyNum];
    if (!keyObj) {
      return "???";
    }

    switch (r.rowType) {
      case "key":
        switch (col.id) {
          case "enigUserNameCol":
            return keyObj.userId;
          case "keyCol":
            return `0x${keyObj.keyId}`;
          case "createdCol":
            return keyObj.created;
          case "expCol":
            return keyObj.effectiveExpiry;
          case "fprCol":
            return keyObj.fprFormatted;
        }
        break;
      case "uid":
        switch (col.id) {
          case "enigUserNameCol":
            return keyObj.userIds[r.uidNum].userId;
        }
        break;
    }

    return "";
  },
  getCellValue() {
    return "";
  },
  getColumnProperties() {
    return "";
  },

  getImageSrc(row, col) {
    const r = this.getFilteredRow(row);
    if (!r || r.rowType != "key") {
      return null;
    }
    const keyObj = gKeyList[r.keyNum];
    if (!keyObj || col?.id != "enigUserNameCol") {
      return null;
    }

    // The provenance mark for a key GnuPG holds. Per row, not once for the
    // page: an identity can hold one key in each store, so a header-level
    // badge would have to be wrong about one of them.
    //
    // The same asset the message badge uses, so the dialog and the header name
    // the engine the same way. Branding-scoped, so another branding has no
    // wing -- the image then simply fails to load and the row keeps its text,
    // which is why nothing depends on this returning a value.
    return EnigmailKeyRing.isExternalKey(keyObj)
      ? "chrome://branding/content/gnupg-wing.svg"
      : null;
  },

  /**
   * indentation level for rows
   */
  getLevel(row) {
    const r = this.getFilteredRow(row);
    if (!r) {
      return 0;
    }

    switch (r.rowType) {
      case "key":
        return 0;
      case "uid":
        return 1;
    }

    return 0;
  },

  getParentIndex() {
    return -1;
  },
  getProgressMode() {},

  getRowProperties() {
    return "";
  },
  hasNextSibling() {
    return false;
  },
  isContainer(row) {
    const r = this.getFilteredRow(row);
    if (!r) {
      return false;
    }
    switch (r.rowType) {
      case "key":
        return true;
    }

    return false;
  },
  isContainerEmpty(row) {
    const r = this.getFilteredRow(row);
    if (!r) {
      return true;
    }
    switch (r.rowType) {
      case "key":
        return !r.hasSubUID;
    }
    return true;
  },
  isContainerOpen(row) {
    return this.getFilteredRow(row).isOpen;
  },
  isEditable() {
    return false;
  },
  isSelectable() {
    return true;
  },
  isSeparator() {
    return false;
  },
  isSorted() {
    return false;
  },
  performAction() {},
  performActionOnCell() {},
  performActionOnRow() {},
  selectionChanged() {},
  // void setCellText(in long row, in nsITreeColumn col, in AString value);
  // void setCellValue(in long row, in nsITreeColumn col, in AString value);
  setTree(treebox) {
    this.treebox = treebox;
  },

  toggleOpenState(row) {
    const r = this.getFilteredRow(row);
    if (!r) {
      return;
    }
    const realRow = this.keyFilterList[row];
    switch (r.rowType) {
      case "key":
        if (r.isOpen) {
          let i = 0;
          while (
            this.getFilteredRow(row + 1 + i) &&
            this.getFilteredRow(row + 1 + i).keyNum === r.keyNum
          ) {
            ++i;
          }

          this.keyViewList.splice(realRow + 1, i);
          r.isOpen = false;
          this.applyFilter(row);
        } else {
          this.appendUids("uid", r.keyNum, realRow, this.keyViewList[row]);

          r.isOpen = true;
          this.applyFilter(row);
        }
        break;
    }
  },

  /**
   * Add UIDs for a given key to key view
   *
   * @param {string} uidType - One of uid (user ID), uat (photo).
   * @param {integer} keyNum -Index of key in gKeyList.
   * @param {integer} realRow - Index of row in keyViewList (i.e. without filter)
   * @returns {integer} the number of UIDs added.
   */
  appendUids(uidType, keyNum, realRow, parentRow) {
    const keyObj = gKeyList[keyNum];
    let uidAdded = 0;

    for (let i = 0; i < keyObj.userIds.length; i++) {
      if (keyObj.userIds[i].type === uidType) {
        if (keyObj.userIds[i].userId == keyObj.userId) {
          continue;
        }
        ++uidAdded;
        this.keyViewList.splice(realRow + uidAdded, 0, {
          rowType: uidType,
          keyNum,
          parent: parentRow,
          uidNum: i,
        });
      }
    }

    return uidAdded;
  },

  /**
   * Reload key list entirely.
   */
  keysRefreshed() {
    this.keyViewList = [];
    this.keyFilterList = [];
    for (let i = 0; i < gKeySortList.length; i++) {
      this.keyViewList.push({
        row: i,
        rowType: "key",
        fpr: gKeySortList[i].fpr,
        keyNum: gKeySortList[i].keyNum,
        isOpen: false,
        hasSubUID: gKeyList[gKeySortList[i].keyNum].userIds.length > 1,
      });
    }

    this.applyFilter(0);
    const oldRowCount = this.rowCount;
    this.rowCount = this.keyViewList.length;
    gUserList.rowCountChanged(0, this.rowCount - oldRowCount);
  },

  /**
   * If no search term is entered, decide which keys to display.
   *
   * @returns {?integer[]} array of keyNums (= display some keys)
   *   or null (= display ALL keys).
   */
  showOrHideAllKeys() {
    var showInvalidKeys = gShowInvalidKeys.hasAttribute("checked");
    var showOthersKeys = gShowOthersKeys.hasAttribute("checked");

    document.getElementById("nothingFound").hidePopup();

    if (showInvalidKeys && showOthersKeys) {
      return null;
    }

    const keyShowList = [];
    for (let i = 0; i < gKeyList.length; i++) {
      if (determineHiddenKeys(gKeyList[i], showInvalidKeys, showOthersKeys)) {
        keyShowList.push(i);
      }
    }

    return keyShowList;
  },

  /**
   * Search for keys that match filter criteria.
   *
   * @returns {?integer[]} array of keyNums (= display some keys)
   *   or null (= display ALL keys).
   */
  getFilteredKeys() {
    let searchTxt = gSearchInput.value;

    if (!searchTxt || searchTxt.length === 0) {
      return this.showOrHideAllKeys();
    }

    if (!gKeyList) {
      return [];
    }
    const showInvalidKeys = gShowInvalidKeys.hasAttribute("checked");
    const showOthersKeys = gShowOthersKeys.hasAttribute("checked");

    // skip leading 0x in case we search for a key:
    if (searchTxt.length > 2 && searchTxt.substr(0, 2).toLowerCase() == "0x") {
      searchTxt = searchTxt.substr(2);
    }

    searchTxt = searchTxt.toLowerCase();
    searchTxt = searchTxt.replace(/^(\s*)(.*)/, "$2").replace(/\s+$/, ""); // trim spaces

    // check if we search for a full fingerprint (with optional spaces every 4 letters)
    var fpr = null;
    if (searchTxt.length == 49) {
      // possible fingerprint with spaces?
      if (
        searchTxt.search(/^[0-9a-f ]*$/) >= 0 &&
        searchTxt[4] == " " &&
        searchTxt[9] == " " &&
        searchTxt[14] == " " &&
        searchTxt[19] == " " &&
        searchTxt[24] == " " &&
        searchTxt[29] == " " &&
        searchTxt[34] == " " &&
        searchTxt[39] == " " &&
        searchTxt[44] == " "
      ) {
        fpr = searchTxt.replace(/ /g, "");
      }
    } else if (searchTxt.length == 40) {
      // possible fingerprint without spaces
      if (searchTxt.search(/^[0-9a-f ]*$/) >= 0) {
        fpr = searchTxt;
      }
    }

    const keyShowList = [];

    for (let i = 0; i < gKeyList.length; i++) {
      const keyObj = gKeyList[i];
      let uid = keyObj.userId;
      let showKey = false;

      // does a user ID (partially) match?
      for (let idx = 0; idx < keyObj.userIds.length; idx++) {
        uid = keyObj.userIds[idx].userId;
        if (uid.toLowerCase().includes(searchTxt)) {
          showKey = true;
        }
      }

      // does the full fingerprint (without spaces) match?
      // - no partial match check because this is special for the collapsed spaces inside the fingerprint
      if (showKey === false && fpr && keyObj.fpr.toLowerCase() == fpr) {
        showKey = true;
      }
      // does the fingerprint (partially) match?
      if (showKey === false && keyObj.fpr.toLowerCase().includes(searchTxt)) {
        showKey = true;
      }
      // does a sub key of (partially) match?
      if (showKey === false) {
        for (
          let subKeyIdx = 0;
          subKeyIdx < keyObj.subKeys.length;
          subKeyIdx++
        ) {
          const subkey = keyObj.subKeys[subKeyIdx].keyId;
          if (subkey.toLowerCase().includes(searchTxt)) {
            showKey = true;
          }
        }
      }
      // take option to show invalid/untrusted... keys into account
      if (
        showKey &&
        determineHiddenKeys(keyObj, showInvalidKeys, showOthersKeys)
      ) {
        keyShowList.push(i);
      }
    }

    return keyShowList;
  },

  /**
   * Trigger re-displaying the list of keys and apply a filter.
   *
   * @param {integer} selectedRow - The row that is currently selected or
   *   clicked on.
   */
  applyFilter(selectedRow) {
    const keyDisplayList = this.getFilteredKeys();

    this.keyFilterList = [];
    if (keyDisplayList === null) {
      for (let i = 0; i < this.keyViewList.length; i++) {
        this.keyFilterList.push(i);
      }

      this.adjustRowCount(this.keyViewList.length, selectedRow);
    } else {
      for (let i = 0; i < this.keyViewList.length; i++) {
        if (keyDisplayList.includes(this.keyViewList[i].keyNum)) {
          this.keyFilterList.push(i);
        }
      }

      this.adjustRowCount(this.keyFilterList.length, selectedRow);
    }
  },

  /**
   * Re-calculate the row count and instruct the view to update.
   */
  adjustRowCount(newRowCount, selectedRow) {
    if (this.rowCount === newRowCount) {
      gUserList.invalidate();
      return;
    }

    const delta = newRowCount - this.rowCount;
    this.rowCount = newRowCount;
    gUserList.rowCountChanged(selectedRow, delta);
  },

  /**
   * Determine the row object from the a filtered row number
   *
   * @param {integer} row - Row number of displayed (=filtered) list.
   * @returns {?object} keyViewList entry of corresponding row.
   */
  getFilteredRow(row) {
    const r = this.keyFilterList[row];
    if (r !== undefined) {
      return this.keyViewList[r];
    }
    return null;
  },

  treebox: null,
};
