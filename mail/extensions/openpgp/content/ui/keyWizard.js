/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

var { AutocryptSetup } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/autocryptSetup.sys.mjs"
);
/**
 * A synchronous Localization instance of this dialog's own.
 *
 * `document.l10n` is asynchronous and `formatValueSync()` throws on it once its
 * state is async; this file reports import failures synchronously, so it needs
 * values now rather than later.
 */
var l10n = new Localization(["messenger/openpgp/openpgp.ftl"], true);
var { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);
var { AppConstants } = ChromeUtils.importESModule(
  "resource://gre/modules/AppConstants.sys.mjs"
);
var { OpenPGPMasterpass } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/masterpass.sys.mjs"
);
var { requirePrimaryPassword } = ChromeUtils.importESModule(
  "resource:///modules/PrimaryPassword.sys.mjs"
);
var { EnigmailKey } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/key.sys.mjs"
);
var { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
var { setKeyList } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/identityKeys.sys.mjs"
);
var { EnigmailWindows } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/windows.sys.mjs"
);
var { PgpSqliteDb2 } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/sqliteDb.sys.mjs"
);
var { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
var { GPGME } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/GPGME.sys.mjs"
);

ChromeUtils.defineESModuleGetters(this, {
  LoginHelper: "resource://gre/modules/LoginHelper.sys.mjs",
});

// UI variables.
var gIdentity;
var gIdentityList;
var gSubDialog;
var kDialog;
var kCurrentSection = "start";
var kGenerating = false;
var kButtonLabel;

// OpenPGP variables.
var gKeygenRequest;
var gAllData = "";
var gGeneratedKey = null;
var gFiles;

/**
 * The scan's result for this dialog, or null before it has run (Item 99a).
 *
 * Held rather than re-run so that moving between the wizard's sections does not
 * read the user's mail again; the button beside the result forces a fresh pass.
 *
 * @type {?Array<{folder: nsIMsgFolder, hdr: nsIMsgDBHdr, messageURI: string,
 *   source: string}>}
 */
var gSetupMessageHits = null;

/**
 * The `application/autocrypt-setup` payload the scan offered, ready for
 * `importSetupMessage()`. Null when nothing has been offered, which is what
 * keeps the offered button from acting on a message nobody found.
 *
 * @type {?string}
 */
var gOfferedSetupMessage = null;

/** Guard so a second press while the walk is running does not start another. */
var gSetupMessageScanRunning = false;

/**
 * The GnuPG key the wizard offers, when the identity it was opened for has one
 * in the external keyring and has not chosen a key itself.
 *
 * Set on init by preselectGnuPGKeyIfAvailable(), consumed by
 * wizardExternalKey() when it fills in the key field. Null when there is
 * nothing to offer, which is the ordinary case for most identities.
 *
 * The identity key it was found for is part of the value rather than implied:
 * the menulist in the wizard can change the identity, and a suggestion that
 * belonged to the previous one must not be applied to the new one.
 *
 * @type {?{ identityKey: string, keyId: string }}
 */
var gSuggestedGnuPgKey = null;

const DEFAULT_FILE_PERMS = 0o600;

var syncl10n = new Localization(["messenger/openpgp/keyWizard.ftl"], true);

window.addEventListener("load", initKeyWiz);

document.addEventListener("dialogaccept", wizardContinue);
document.addEventListener("dialogextra1", goBack);
document.addEventListener("dialogcancel", onClose);

/**
 * Initialize the keyWizard dialog.
 */
async function initKeyWiz() {
  gSubDialog = window.arguments[0].gSubDialog;
  gIdentity = window.arguments[0].identity || null;
  gIdentityList = document.getElementById("userIdentity");

  kDialog = document.querySelector("dialog");

  await initIdentity();

  // Show the GnuPG radio selection if the pref is enabled.
  if (Services.prefs.getBoolPref("mail.openpgp.allow_external_gnupg")) {
    document.getElementById("externalOpenPgp").hidden = false;
    document.getElementById("externalKey").addEventListener("input", event => {
      kDialog.getButton("accept").disabled = !event.target.checkValidity();
    });

    // A key already in GnuPG makes the external path the default choice. This
    // runs after the radio is shown so the selection is made on a visible
    // control, and before the isCreate/isImport shortcuts below, which set the
    // radio themselves when the dialog was opened for one of those purposes.
    await preselectGnuPGKeyIfAvailable();
  }

  // After the dialog is visible, disable the event listeners causing it to
  // close when clicking on the overlay or hitting the Esc key, and remove the
  // close button from the header. This is necessary to control the escape
  // point and prevent the accidental dismiss of the dialog during important
  // processes, like the generation or importing of a key.
  setTimeout(() => {
    // Check if the attribute is not null. This can be removed after the full
    // conversion of the Key Manager into a SubDialog in Bug 1652537.
    if (gSubDialog?._topDialog) {
      gSubDialog._topDialog._removeDialogEventListeners();
      gSubDialog._topDialog._closeButton?.remove();
      resizeWindow();
    }
  }, 150);

  // Switch directly to the create screen if requested by the user.
  if (window.arguments[0].isCreate) {
    document.getElementById("openPgpKeyChoices").value = 0;
    switchSection(true);
    return;
  }

  // Switch directly to the import screen if requested by the user.
  if (window.arguments[0].isImport) {
    document.getElementById("openPgpKeyChoices").value = 1;

    // Disable the "Continue" button so the user can't accidentally click on it.
    // See bug 1689980.
    kDialog.getButton("accept").disabled = true;

    switchSection(true);
  }
}

function onProtectionChange() {
  const pw1Element = document.getElementById("passwordInput");
  const pw2Element = document.getElementById("passwordConfirm");

  const pw1 = pw1Element.value;
  const pw2 = pw2Element.value;

  const inputDisabled = document.getElementById(
    "keygenAutoProtection"
  ).selected;
  pw1Element.disabled = inputDisabled;
  pw2Element.disabled = inputDisabled;

  const buttonEnabled = inputDisabled || (!inputDisabled && pw1 == pw2 && pw1);
  const ok = kDialog.getButton("accept");
  ok.disabled = !buttonEnabled;
}

/**
 * Populate the identity menulist with all the valid and available identities
 * and autoselect the current identity if available.
 */
async function initIdentity() {
  const identityListPopup = document.getElementById("userIdentityPopup");

  for (const identity of MailServices.accounts.allIdentities) {
    // Skip invalid and non-email identities.
    if (!identity.valid || !identity.email) {
      continue;
    }

    // Interrupt if no server was defined for this identity.
    const servers = MailServices.accounts.getServersForIdentity(identity);
    if (servers.length == 0) {
      continue;
    }

    const item = document.createXULElement("menuitem");
    item.setAttribute(
      "label",
      `${identity.identityName} - ${servers[0].prettyName}`
    );
    item.setAttribute("class", "identity-popup-item");
    item.setAttribute("accountname", servers[0].prettyName);
    item.setAttribute("identitykey", identity.key);
    item.setAttribute("email", identity.email);

    identityListPopup.appendChild(item);

    if (gIdentity && gIdentity.key == identity.key) {
      gIdentityList.selectedItem = item;
    }
  }

  // If not identity was originally passed during the creation of this dialog,
  // select the first available value.
  if (!gIdentity) {
    gIdentityList.selectedIndex = 0;
  }

  await setIdentity();
}

/**
 * Preselect the GnuPG path when the keyring holds a key for this identity.
 *
 * A new identity with a key already in GnuPG should start on the external
 * path, because that is the key its owner already trusts and the one this build
 * exists to use. The other two choices stay on screen and stay selectable: the
 * internal engine is offered, never assumed, and the asymmetry between the two
 * is deliberate. An identity that already has a key configured is left alone
 * entirely -- which key signs is a decision the user has made, and opening the
 * wizard again is not a reason to revisit it.
 *
 * The selected key is the same one the account settings offer (Item 2): the
 * newest non-expired key GnuPG holds for the address. Expired keys are skipped
 * because a preselected key that cannot sign would fail at the first send,
 * which is the worst moment to discover it.
 *
 * Nothing here writes to the identity. The choice becomes real only when the
 * user continues through the external section and the dialog is accepted, so
 * cancelling the wizard leaves the identity exactly as it was.
 *
 * @returns {Promise<void>}
 */
async function preselectGnuPGKeyIfAvailable() {
  gSuggestedGnuPgKey = null;

  if (!Services.prefs.getBoolPref("mail.openpgp.allow_external_gnupg")) {
    return;
  }
  if (!gIdentity?.email) {
    return;
  }
  // An identity that already uses a key keeps it. The wizard is not a place to
  // change which key signs by accident.
  if (gIdentity.getUnicharAttribute("openpgp_key_id")) {
    return;
  }
  if (!GPGME.init()) {
    return;
  }

  let gnuPgFprs;
  try {
    gnuPgFprs = GPGME.getSecretKeyFingerprintsForEmail(gIdentity.email);
  } catch (ex) {
    console.warn("Reading secret keys from GnuPG failed", ex);
    return;
  }
  if (!gnuPgFprs.length) {
    return;
  }
  const heldByGnuPg = new Set(gnuPgFprs.map(fpr => fpr.toUpperCase()));

  const result = {};
  await EnigmailKeyRing.getAllSecretKeysByEmail(gIdentity.email, result, true);

  const nowSecondsSinceEpoch = Date.now() / 1000;
  const offered = result.all
    .filter(
      key =>
        heldByGnuPg.has(key.fpr.toUpperCase()) &&
        (!key.expiryTime || key.expiryTime > nowSecondsSinceEpoch)
    )
    .sort((a, b) => b.keyCreated - a.keyCreated);
  if (!offered.length) {
    return;
  }

  // Key id rather than fingerprint, for the same reason as in the account
  // settings: the field, the identity attributes and the key list all speak in
  // key ids, and getKeyById() resolves either.
  gSuggestedGnuPgKey = {
    identityKey: gIdentity.key,
    keyId: offered[0].keyId.toUpperCase(),
  };

  const choices = document.getElementById("openPgpKeyChoices");
  choices.value = 2;
}

/**
 * Update the currently used identity to reflect the user selection from the
 * identity menulist.
 */
async function setIdentity() {
  if (gIdentityList.selectedItem) {
    gIdentity = MailServices.accounts.getIdentity(
      gIdentityList.selectedItem.getAttribute("identitykey")
    );

    document.l10n.setAttributes(
      document.documentElement,
      "key-wizard-dialog-window",
      {
        identity: gIdentity.email,
      }
    );
  }
}

/**
 * Intercept the dialogaccept command to implement a wizard like setup workflow.
 *
 * @param {Event} event - The DOM Event.
 */
function wizardContinue(event) {
  event.preventDefault();

  // Pretty impossible scenario but just in case if no radio button is
  // currently selected, bail out.
  if (!document.getElementById("openPgpKeyChoices").value) {
    return;
  }

  // Trigger an action based on the currently visible section.
  if (kCurrentSection != "start") {
    wizardNextStep();
    return;
  }

  // Disable the `Continue` button.
  kDialog.getButton("accept").disabled = true;

  switchSection(false);
}

/**
 * Show the section matching the current radiogroup selection.
 *
 * @param {boolean} isKeyManager - If the wizard was opened from the Key
 *   Manager, which doesn't offer the `Go Back` step.
 */
function switchSection(isKeyManager = false) {
  // Save the current label of the accept button in order to restore it later.
  kButtonLabel = kDialog.getButton("accept").label;

  // Update the UI based on the radiogroup selection.
  switch (document.getElementById("openPgpKeyChoices").value) {
    case "0":
      wizardCreateKey();
      break;

    case "1":
      wizardImportKey();
      break;

    case "2":
      wizardExternalKey();
      document.getElementById("externalKey").focus();
      break;
  }

  if (!isKeyManager) {
    kDialog.getButton("extra1").hidden = false;
  }
  resizeWindow();
}

/**
 * Handle the next step of the wizard based on the currently visible section.
 */
async function wizardNextStep() {
  switch (kCurrentSection) {
    case "create":
      await openPgpKeygenStart();
      break;

    case "import":
      await openPgpImportStart();
      break;

    case "importComplete":
      openPgpImportComplete();
      break;

    case "external":
      await openPgpExternalComplete();
      break;
  }
}

/**
 * Go back to the initial view of the wizard.
 */
function goBack() {
  // Hide the `Go Back` button.
  kDialog.getButton("extra1").hidden = true;

  // Enable the `Continue` button.
  kDialog.getButton("accept").disabled = false;

  kDialog.getButton("accept").label = kButtonLabel;
  kDialog.getButton("accept").classList.remove("primary");

  // Reset the import section.
  clearImportWarningNotifications();
  document.getElementById("importKeyIntro").hidden = false;
  document.getElementById("importKeyListContainer").collapsed = true;

  // Reset section key.
  kCurrentSection = "start";

  revealSection("wizardStart");
}

/**
 * Create a new inline notification to append to the import warning container.
 *
 * @param {string} [containerId="openPgpImportWarning"] - Id of the container
 *   to add the warning to.
 * @returns {XULElement} - The description element inside the notification.
 */
async function addImportWarningNotification(
  containerId = "openPgpImportWarning"
) {
  const notification = document.createXULElement("hbox");
  notification.classList.add(
    "inline-notification-container",
    "error-container"
  );

  const wrapper = document.createXULElement("hbox");
  wrapper.classList.add("inline-notification-wrapper", "align-center");

  const image = document.createElement("img");
  image.classList.add("notification-image");
  image.setAttribute("src", "chrome://global/skin/icons/warning.svg");
  image.setAttribute("alt", "");

  const description = document.createXULElement("description");

  wrapper.appendChild(image);
  wrapper.appendChild(description);

  notification.appendChild(wrapper);

  const container = document.getElementById(containerId);
  container.appendChild(notification);

  // Show the notification container.
  container.removeAttribute("hidden");

  return description;
}

/**
 * Remove all inline errors from the notification area of the import section.
 *
 * @param {string} [containerId="openPgpImportWarning"] - Id of the container
 *   to remove the warning from.
 */
function clearImportWarningNotifications(containerId = "openPgpImportWarning") {
  const container = document.getElementById(containerId);

  // Remove any existing notification.
  for (const notification of container.querySelectorAll(
    ".inline-notification-container"
  )) {
    notification.remove();
  }

  // Hide the entire notification container.
  container.hidden = true;
}

/**
 * Show the Key Creation section.
 */
async function wizardCreateKey() {
  kCurrentSection = "create";
  revealSection("wizardCreateKey");

  kDialog.getButton("accept").label = await document.l10n.formatValue(
    "openpgp-keygen-button"
  );
  kDialog.getButton("accept").classList.add("primary");

  const sepPassphraseEnabled = Services.prefs.getBoolPref(
    "mail.openpgp.passphrases.enabled"
  );
  document.getElementById("keygenPassphraseSection").hidden =
    !sepPassphraseEnabled;

  if (sepPassphraseEnabled) {
    const usingPP = LoginHelper.isPrimaryPasswordSet();
    const autoProt = document.getElementById("keygenAutoProtection");

    document.l10n.setAttributes(
      autoProt,
      usingPP
        ? "radio-keygen-protect-primary-pass"
        : "radio-keygen-no-protection"
    );

    autoProt.toggleAttribute("selected", true);
    document
      .getElementById("keygenPassphraseProtection")
      .removeAttribute("selected");
  }

  // This also handles enable/disabling the accept/ok button.
  onProtectionChange();

  if (!gIdentity.fullName) {
    document.getElementById("openPgpWarning").collapsed = false;
    document.l10n.setAttributes(
      document.getElementById("openPgpWarningDescription"),
      "openpgp-keygen-missing-username"
    );
  }

  resizeWindow();
}

/**
 * Show the Key Import section.
 */
function wizardImportKey() {
  kCurrentSection = "import";
  revealSection("wizardImportKey");

  const sepPassphraseEnabled = Services.prefs.getBoolPref(
    "mail.openpgp.passphrases.enabled"
  );
  const keepPassphrasesItem = document.getElementById(
    "openPgpKeygenKeepPassphrases"
  );
  keepPassphrasesItem.hidden = !sepPassphraseEnabled;
  keepPassphrasesItem.checked = false;

  // Item 99a: the "at setup" half of the scan. Opening this section is a
  // user-initiated path, which is the condition the item sets; the second half
  // is the button beside the result. Nothing here runs on launch.
  scanForSetupMessage();
}

/**
 * Show the Key Setup via external smartcard section.
 */
async function wizardExternalKey() {
  kCurrentSection = "external";
  revealSection("wizardExternalKey");
  kDialog.getButton("accept").classList.add("primary");

  const keyInput = document.getElementById("externalKey");

  // is_gnupg_key_id alone does not mean a key is configured. The account
  // settings write it as "openpgp_key_id equals last_entered_external_gnupg_key_id",
  // which is true for an identity with no key at all, because both are empty.
  // Testing it without a key id would treat that identity as already set up and
  // leave the field blank, so the key id is what decides here.
  const configuredKey = gIdentity.getBoolAttribute("is_gnupg_key_id")
    ? gIdentity.getUnicharAttribute("last_entered_external_gnupg_key_id")
    : "";

  // If the user is already using an external GnuPG key, populate the input,
  // show the warning description, and enable the primary button.
  if (configuredKey) {
    keyInput.value = `0x${configuredKey}`;
    document.getElementById("openPgpExternalWarning").collapsed = false;
    kDialog.getButton("accept").disabled = !keyInput.checkValidity();
  } else if (gSuggestedGnuPgKey?.identityKey == gIdentity.key) {
    // A key was found for this identity before the wizard opened. Fill it in so
    // continuing needs no typing, and show the same warning the configured
    // case shows, because this is the same situation from the user's side.
    // The field stays editable: the suggestion is a starting point, not a
    // commitment, and the user may type a different key.
    keyInput.value = `0x${gSuggestedGnuPgKey.keyId}`;
    document.getElementById("openPgpExternalWarning").collapsed = false;
    kDialog.getButton("accept").disabled = !keyInput.checkValidity();
  } else {
    document.getElementById("openPgpExternalWarning").collapsed = true;
    kDialog.getButton("accept").disabled = true;
  }
}

/**
 * Reveal a section of the wizard and hide all the others.
 *
 * @param {string} id - The id of the section to reveal. It can also be a
 *   subsection nested inside one of the wizard sections.
 */
function revealSection(id) {
  const section = document.getElementById(id);
  for (const other of document.querySelectorAll(
    ".wizard-section:not(.overlay)"
  )) {
    if (other != section && !other.contains(section)) {
      other.hidden = true;
    }
  }
  section.hidden = false;
  resizeWindow();
}

/**
 * Enable or disable the elements based on the radiogroup selection.
 *
 * @param {Event} event - The DOM event triggered on change.
 */
function onExpirationChange(event) {
  document.getElementById("expireInput").disabled = event.target.value != 0;
  document.getElementById("timeScale").disabled = event.target.value != 0;

  validateExpiration();
}

/**
 * Enable or disable the #keySize input field based on the current selection of
 * the #keyType radio group.
 *
 * @param {Event} event - The DOM Event.
 */
function onKeyTypeChange(event) {
  document.getElementById("keySize").disabled = event.target.value == "ECC";
}

/**
 * Intercept the cancel event to prevent accidental closing if the generation of
 * a key is currently in progress.
 *
 * @param {Event} event - The DOM event.
 */
function onClose(event) {
  // A close refused because a key operation is in progress must not run the
  // cancel callback: doing so rebuilt the Key Manager's whole list for a window
  // that stayed open, which is work with no changed data behind it.
  if (kGenerating) {
    event.preventDefault();
    return;
  }

  window.arguments[0].cancelCallback();
}

/**
 * Validate the expiration time of a newly generated key when the user changes
 * values. Disable the "Generate Key" button and show an alert if the selected
 * value is less than 1 day or more than 100 years.
 */
async function validateExpiration() {
  // If the key doesn't have an expiration date, hide the warning message and
  // enable the "Generate Key" button.
  if (document.getElementById("openPgpKeygeExpiry").value == 1) {
    document.getElementById("openPgpWarning").collapsed = true;
    kDialog.getButton("accept").disabled = false;
    return;
  }

  // Calculate the selected expiration date.
  const expiryTime =
    Number(document.getElementById("expireInput").value) *
    Number(document.getElementById("timeScale").value);

  // If the expiration date exceeds 100 years.
  if (expiryTime > 36500) {
    document.getElementById("openPgpWarning").collapsed = false;
    document.l10n.setAttributes(
      document.getElementById("openPgpWarningDescription"),
      "openpgp-keygen-long-expiry"
    );
    kDialog.getButton("accept").disabled = true;
    resizeWindow();
    return;
  }

  // If the expiration date is shorter than 1 day.
  if (expiryTime <= 0) {
    document.getElementById("openPgpWarning").collapsed = false;
    document.l10n.setAttributes(
      document.getElementById("openPgpWarningDescription"),
      "openpgp-keygen-short-expiry"
    );
    kDialog.getButton("accept").disabled = true;
    resizeWindow();
    return;
  }

  // If the previous conditions are false, hide the warning message and
  // enable the "Generate Key" button since the expiration date is valid.
  document.getElementById("openPgpWarning").collapsed = true;
  kDialog.getButton("accept").disabled = false;
}

/**
 * Resize the dialog to account for the newly visible sections.
 */
function resizeWindow() {
  // Check if the attribute is not null. This can be removed after the full
  // conversion of the Key Manager into a SubDialog in Bug 1652537.
  if (gSubDialog?._topDialog) {
    gSubDialog._topDialog.resizeVertically();
    return;
  }

  window.sizeToContent();
}

/**
 * Start the generation of a new OpenPGP Key.
 */
async function openPgpKeygenStart() {
  const openPgpWarning = document.getElementById("openPgpWarning");
  const openPgpWarningText = document.getElementById(
    "openPgpWarningDescription"
  );
  openPgpWarning.collapsed = true;

  // If a key generation request is already pending, warn the user and
  // don't proceed.
  if (gKeygenRequest) {
    const req = gKeygenRequest.QueryInterface(Ci.nsIRequest);

    if (req.isPending()) {
      openPgpWarning.collapsed = false;
      document.l10n.setAttributes(openPgpWarningText, "openpgp-keygen-ongoing");
      return;
    }
  }

  // Reset global variables to be sure.
  gGeneratedKey = null;
  gAllData = "";

  // Show wizard overlay before the start of the generation process. This is
  // necessary because the generation happens synchronously and blocks the UI.
  // We need to show the overlay before it, otherwise it would flash and freeze.
  // This should be moved after the Services.prompt.confirmEx() method
  // once Bug 1617444 is implemented.
  const overlay = document.getElementById("wizardOverlay");
  overlay.hidden = false;

  // Ask for confirmation before triggering the generation of a new key.
  document.l10n.setAttributes(
    document.getElementById("wizardOverlayQuestion"),
    "openpgp-key-confirm",
    {
      identity: `${gIdentity.fullName} <b>"${gIdentity.email}"</b>`,
    }
  );

  document.l10n.setAttributes(
    document.getElementById("wizardOverlayTitle"),
    "openpgp-keygen-progress-title"
  );
}

async function openPgpKeygenConfirm() {
  const openPgpWarning = document.getElementById("openPgpWarning");
  const openPgpWarningText = document.getElementById(
    "openPgpWarningDescription"
  );

  // A key generated here is protected by the SDR key, and without a Primary
  // Password that key is stretched once -- so the private key is readable by
  // anyone who can open the profile. The helper opens the change-password
  // dialog and reports whether the user complied, which is the route forward
  // D7 requires; refusing silently would block the action with nowhere to go.
  //
  // Item 53, on the user's decision of 2026-10-27: this is the stronger
  // reading design 12.5 asks for -- refuse whenever there is no password,
  // policy or not. A secret key in the internal store is protected by the SDR
  // key, and without a Primary Password that key is stretched once and stored
  // unprotected in the profile, so the private key is readable by anyone who
  // can read the profile directory. `enforcePrimaryPassword()` would return
  // true immediately on an ordinary profile, which is why it is not used here.
  if (!requirePrimaryPassword(window)) {
    openPgpWarning.collapsed = false;
    document.l10n.setAttributes(
      openPgpWarningText,
      "openpgp-keygen-error-primary-password"
    );
    return;
  }

  document.getElementById("openPgpKeygenConfirm").collapsed = true;
  document.getElementById("openPgpKeygenProcess").removeAttribute("collapsed");

  openPgpWarning.collapsed = true;

  kGenerating = true;

  let password;
  let newId = null;

  const sepPassphraseEnabled = Services.prefs.getBoolPref(
    "mail.openpgp.passphrases.enabled"
  );

  if (
    !sepPassphraseEnabled ||
    document.getElementById("keygenAutoProtection").selected
  ) {
    password = await OpenPGPMasterpass.retrieveOpenPGPPassword();
  } else {
    password = document.getElementById("passwordInput").value;
  }
  newId = await RNP.genKey(
    `${gIdentity.fullName} <${gIdentity.email}>`,
    document.getElementById("keyType").value,
    Number(document.getElementById("keySize").value),
    document.getElementById("openPgpKeygeExpiry").value == 1
      ? 0
      : Number(document.getElementById("expireInput").value) *
          Number(document.getElementById("timeScale").value),
    password
  );
  await RNP.saveKeyRings();

  gGeneratedKey = newId;

  EnigmailWindows.keyManReloadKeys();

  gKeygenRequest = null;
  kGenerating = false;

  // For whatever reason, the key wasn't generated. Show an error message and
  // hide the processing overlay.
  if (!gGeneratedKey) {
    openPgpWarning.collapsed = false;
    document.l10n.setAttributes(
      openPgpWarningText,
      "openpgp-keygen-error-failed"
    );
    closeOverlay();

    throw new Error("key generation failed");
  }

  Services.prefs.savePrefFile(null);

  // Hide wizard overlay at the end of the generation process.
  closeOverlay();
  EnigmailKeyRing.clearCache();

  const rev = await RNP.unlockAndGetNewRevocation(
    `0x${gGeneratedKey}`,
    password,
    true
  );
  if (!rev) {
    openPgpWarning.collapsed = false;
    document.l10n.setAttributes(
      openPgpWarningText,
      "openpgp-keygen-error-revocation",
      {
        key: gGeneratedKey,
      }
    );
    closeOverlay();

    throw new Error("failed to obtain revocation for key " + gGeneratedKey);
  }

  const revFile = Services.dirsvc.get("ProfD", Ci.nsIFile);
  revFile.append(`0x${gGeneratedKey}_rev.asc`);

  // Create a revokation cert in the Thunderbird profile directory.
  await IOUtils.writeUTF8(revFile.path, rev);

  // Key successfully created. Close the dialog and show a confirmation message.
  // Assigning the key to an identity is the responsibility of the caller,
  // so we pass back what we created.
  window.arguments[0].okCallback(gGeneratedKey);
  window.close();
}

/**
 * Cancel the keygen process, ask for confirmation before proceeding.
 */
async function openPgpKeygenCancel() {
  const [abortTitle, abortText] = await document.l10n.formatValues([
    { id: "openpgp-keygen-abort-title" },
    { id: "openpgp-keygen-abort" },
  ]);

  if (
    kGenerating &&
    Services.prompt.confirmEx(
      window,
      abortTitle,
      abortText,
      Services.prompt.STD_YES_NO_BUTTONS,
      "",
      "",
      "",
      "",
      {}
    ) != 0
  ) {
    return;
  }

  closeOverlay();
  gKeygenRequest.kill(false);
  kGenerating = false;
}

/**
 * Close the processing wizard overlay.
 */
function closeOverlay() {
  document.getElementById("openPgpKeygenConfirm").removeAttribute("collapsed");
  document.getElementById("openPgpKeygenProcess").collapsed = true;

  hideOverlay(document.getElementById("wizardOverlay"));
}

/**
 * Hide a wizard overlay.
 *
 * @param {Element} overlay - The overlay to hide.
 */
function hideOverlay(overlay) {
  overlay.hidden = true;
  resizeWindow();
}

async function importSecretKey() {
  // Reset the array of selected files.
  gFiles = [];

  const [importTitle, importType] = await document.l10n.formatValues([
    { id: "import-key-file" },
    { id: "gnupg-file" },
  ]);

  const fp = Cc["@mozilla.org/filepicker;1"].createInstance(Ci.nsIFilePicker);
  fp.init(
    window.browsingContext,
    importTitle,
    Ci.nsIFilePicker.modeOpenMultiple
  );
  fp.defaultExtension = "*.asc";
  fp.appendFilter(importType, "*.asc;*.gpg;*.pgp");
  fp.appendFilters(Ci.nsIFilePicker.filterAll);
  const rv = await new Promise(resolve => fp.open(resolve));
  if (rv != Ci.nsIFilePicker.returnOK || !fp.files) {
    return;
  }

  // Clear and hide the warning notification section.
  clearImportWarningNotifications();

  // Clear the key list from any previously listed key.
  const keyList = document.getElementById("importKeyList");
  while (keyList.lastChild) {
    keyList.lastChild.remove();
  }

  let keyCount = 0;
  for (const file of fp.files) {
    // Skip the file and show a warning message if larger than 5MB.
    if (file.fileSize > 5000000) {
      document.l10n.setAttributes(
        await addImportWarningNotification(),
        "import-error-file-size"
      );
      continue;
    }

    const errorMsgObj = {};
    // Fetch the list of all the available keys inside the selected file.
    const importKeys = await EnigmailKey.getKeyListFromKeyFile(
      file,
      errorMsgObj,
      false,
      true
    );

    // Skip the file and show a warning message if the import failed.
    if (!importKeys || !importKeys.length || errorMsgObj.value) {
      document.l10n.setAttributes(
        await addImportWarningNotification(),
        "import-error-failed",
        {
          error: errorMsgObj.value,
        }
      );
      continue;
    }

    await appendFetchedKeys(importKeys);
    keyCount += importKeys.length;

    // Add the current file to the list of valid files to import.
    gFiles.push(file);
  }

  // Update the list count recap and show the container.
  document.l10n.setAttributes(
    document.getElementById("keyListCount"),
    "openpgp-import-key-list-amount-2",
    {
      count: keyCount,
    }
  );

  document.getElementById("importKeyListContainer").collapsed = !keyCount;

  // Hide the intro section and enable the import of keys only if we have valid
  // keys currently listed.
  if (keyCount) {
    document.getElementById("importKeyIntro").hidden = true;
    kDialog.getButton("accept").disabled = false;
    kDialog.getButton("accept").classList.add("primary");
  }

  resizeWindow();
}

/**
 * Populate the key list in the import dialog with all the valid keys fetched
 * from a single file.
 *
 * @param {string[]} importKeys - The array of keys fetched from a single file.
 */
async function appendFetchedKeys(importKeys) {
  const keyList = document.getElementById("importKeyList");

  // List all the keys fetched from the file.
  for (const key of importKeys) {
    const container = document.createXULElement("hbox");
    container.classList.add("key-import-row", "selected");

    const titleContainer = document.createXULElement("vbox");

    const id = document.createXULElement("label");
    id.classList.add("openpgp-key-id");
    id.value = `0x${key.id}`;

    const name = document.createXULElement("label");
    name.classList.add("openpgp-key-name");
    name.value = key.name;

    titleContainer.appendChild(id);
    titleContainer.appendChild(name);

    // Allow users to treat imported keys as "Personal".
    const checkbox = document.createXULElement("checkbox");
    checkbox.setAttribute("id", `${key.id}-set-personal`);
    document.l10n.setAttributes(checkbox, "import-key-personal-checkbox");
    checkbox.checked = true;

    container.appendChild(titleContainer);
    container.appendChild(checkbox);

    keyList.appendChild(container);
  }
}

async function openPgpImportStart() {
  if (!gFiles.length) {
    return;
  }

  // Item 73 / D7: the same refusal-with-a-route the key-generation path makes.
  // A secret key imported here is protected by the SDR key, and without a
  // Primary Password that key is stretched once, so the private key is readable
  // by anyone who can open the profile. requirePrimaryPassword() opens the
  // change-password dialog and reports whether the user complied, so the route
  // forward is the refusal rather than a dead end -- and unlike
  // enforcePrimaryPassword() it does not return early on a profile with no
  // enterprise policy, which is the whole point of Item 53's stronger reading.
  //
  // Before this, the import path had no check at all -- it wrote secret
  // material whatever the policy said, which is the asymmetry Item 53's own
  // audit named and this item closes.
  if (!requirePrimaryPassword(window)) {
    document.l10n.setAttributes(
      await addImportWarningNotification(),
      "openpgp-import-error-primary-password"
    );
    // The files stay selected and the list stays populated, so the user can
    // set a password and press Continue again rather than re-picking them.
    return;
  }

  kGenerating = true;

  // Show the overlay.
  const overlay = document.getElementById("wizardImportOverlay");
  overlay.hidden = false;

  // Clear and hide the warning notification section.
  clearImportWarningNotifications();

  // Clear the list of any previously imported keys from the DOM.
  const keyList = document.getElementById("importKeyListRecap");
  while (keyList.lastChild) {
    keyList.lastChild.remove();
  }

  let keyCount = 0;
  for (const file of gFiles) {
    const resultKeys = {};
    const errorMsgObj = {};

    // keepPassphrases false is the classic behavior.
    let keepPassphrases = false;

    // If the pref is on, we allow the user to decide what to do.
    const allowSeparatePassphrases = Services.prefs.getBoolPref(
      "mail.openpgp.passphrases.enabled"
    );
    if (allowSeparatePassphrases) {
      keepPassphrases = document.getElementById(
        "openPgpKeygenKeepPassphrases"
      ).checked;
    }

    const exitCode = await EnigmailKeyRing.importSecKeyFromFile(
      window,
      passphrasePromptCallback,
      keepPassphrases,
      file,
      errorMsgObj,
      resultKeys
    );

    // Skip this file if something went wrong.
    if (exitCode !== 0) {
      document.l10n.setAttributes(
        await addImportWarningNotification(),
        "openpgp-import-keys-failed",
        {
          // We must at least provide an empty string to avoid
          // a crash in the Rust Fluent code.
          error: errorMsgObj.value ? errorMsgObj.value : "",
        }
      );
      continue;
    }

    await appendImportedKeys(resultKeys);
    keyCount += resultKeys.keys.length;
  }

  // Hide the previous key list container and title.
  document.getElementById("importKeyListContainer").collapsed = keyCount;
  document.getElementById("importKeyTitle").hidden = keyCount;

  // Show the successful final screen only if at least one key was imported.
  if (keyCount) {
    // Update the dialog buttons for the final stage.
    kDialog.getButton("extra1").hidden = true;
    kDialog.getButton("cancel").hidden = true;

    // Update the `Continue` button.
    document.l10n.setAttributes(
      kDialog.getButton("accept"),
      "openpgp-keygen-import-complete"
    );
    kCurrentSection = "importComplete";

    // Show the recently built key list.
    document.getElementById("importKeyListSuccess").collapsed = false;
  }

  // Hide the loading overlay.
  hideOverlay(overlay);

  kGenerating = false;
}

/**
 * Look for a setup message in the user's mail and offer it (Item 99a).
 *
 * Two entry points, one function: opening the import section asks for a scan
 * once, and the button beside the result asks for a fresh one. The distinction
 * matters because the scan reads the headers of the user's mail -- repeating it
 * every time the wizard switches sections would read mail the user did not ask
 * to have read again.
 *
 * Nothing is imported here. A hit is put in `gOfferedSetupMessage` and the
 * button that leads to Item 99's flow is revealed; the user decides whether to
 * press it.
 *
 * @param {boolean} [rescan=false] - Scan again even if this dialog already has
 *   a result.
 */
async function scanForSetupMessage(rescan = false) {
  if (gSetupMessageScanRunning) {
    return;
  }
  if (gSetupMessageHits && !rescan) {
    presentSetupMessageHits();
    return;
  }

  const status = document.getElementById("setupMessageScanStatus");
  const scanButton = document.getElementById("searchSetupMessageButton");

  gSetupMessageScanRunning = true;
  status.hidden = false;
  document.l10n.setAttributes(status, "openpgp-setup-message-scan-running");
  scanButton.disabled = true;
  resizeWindow();

  try {
    gSetupMessageHits = await AutocryptSetup.findSetupMessages();
  } catch (ex) {
    // The scan walks what it can and reports per folder; reaching here means
    // the walk itself failed, which is a different statement from "nothing was
    // found" and is said as such. A `null` result also means the next visit to
    // this section tries again rather than showing a stale answer.
    console.warn("Autocrypt setup: the scan failed", ex);
    gSetupMessageHits = null;
    document.l10n.setAttributes(status, "openpgp-setup-message-scan-failed");
    return;
  } finally {
    gSetupMessageScanRunning = false;
    scanButton.disabled = false;
    resizeWindow();
  }

  presentSetupMessageHits();
}

/**
 * Show what the scan found, or say that it found nothing.
 *
 * The newest hit is the one offered: several old backups can sit in a mailbox,
 * and the recent one is the one whose key is still the user's.
 */
function presentSetupMessageHits() {
  const status = document.getElementById("setupMessageScanStatus");
  const offerButton = document.getElementById("importSetupMessageButton");
  const hits = gSetupMessageHits ?? [];

  if (!hits.length) {
    gOfferedSetupMessage = null;
    offerButton.hidden = true;
    document.l10n.setAttributes(status, "openpgp-setup-message-scan-none", {
      days: Math.round(AutocryptSetup.MAX_AGE_SECONDS / 86400),
    });
    status.hidden = false;
    resizeWindow();
    return;
  }

  const newest = hits[0];
  gOfferedSetupMessage = newest.source;
  document.l10n.setAttributes(status, "openpgp-setup-message-scan-found", {
    folder: newest.folder.localizedName || newest.folder.name,
  });
  status.hidden = false;
  offerButton.hidden = false;
  resizeWindow();
}

/**
 * Import a key from an Autocrypt setup message (Item 99).
 *
 * The flow the specification describes: the message is detected, its structure
 * validated, the code requested, and the payload adopted. The three cases have
 * different behaviour and are kept apart, because conflating them produces the
 * worst outcomes -- a `v2` message offered as `v1`, or a broken message offered
 * with a prompt that cannot succeed.
 *
 * @param {string} [mimePartText] - The message, or its
 *   `application/autocrypt-setup` part. `classify()` reads whichever it is
 *   given: the scan hands over the whole message it streamed, and a caller with
 *   a detached part hands over the part. When absent, this is a no-op: the
 *   button is only shown once a message has been found, so there is nothing to
 *   guess at.
 */
async function importSetupMessage(mimePartText) {
  if (!mimePartText) {
    return;
  }

  const classified = AutocryptSetup.classify(mimePartText);
  if (classified.state == "notASetupMessage") {
    // Ignored entirely, and silently: a format this build does not know must
    // not produce a dialog here, or every future version would.
    return;
  }
  if (classified.state == "malformed") {
    Services.prompt.alert(
      window,
      null,
      l10n.formatValueSync("openpgp-setup-message-malformed", {
        reason: classified.reason ?? "",
      })
    );
    return;
  }

  // The code, requested after the message has been accepted rather than
  // before: a user should not be asked for a code for a message that turns out
  // to be unusable.
  const code = { value: "" };
  const ok = Services.prompt.promptPassword(
    window,
    l10n.formatValueSync("openpgp-setup-code-title"),
    l10n.formatValueSync("openpgp-setup-code-reentry-intro"),
    code,
    null,
    { value: false }
  );
  if (!ok) {
    return;
  }

  const unwrapped = await AutocryptSetup.unwrap(classified.armour, code.value);
  if (unwrapped.state == "wrongCode") {
    // A different fact from a damaged message: the code authenticates as well
    // as decrypts, so this says the code was wrong, not the file.
    Services.prompt.alert(
      window,
      null,
      l10n.formatValueSync("openpgp-setup-message-wrong-code")
    );
    return;
  }
  if (unwrapped.state != "ok") {
    Services.prompt.alert(
      window,
      null,
      l10n.formatValueSync("openpgp-setup-message-malformed", {
        reason: unwrapped.reason ?? "",
      })
    );
    return;
  }

  const preferEncrypt = AutocryptSetup.preferenceOf(unwrapped.keyBlock);
  const result = await AutocryptSetup.adopt({
    keyBlock: unwrapped.keyBlock,
    address: gIdentity.email,
    preferEncrypt,
    identity: gIdentity,
    // Item 53: this is a user-initiated import, so the gate must see a window.
    win: window,
  });
  if (!result.ok) {
    Services.prompt.alert(
      window,
      null,
      l10n.formatValueSync("openpgp-setup-message-failed", {
        reason: result.error ?? "",
      })
    );
    return;
  }

  kGenerating = false;
  window.close();
}

/**
 * Populate the key list in the import dialog with all the valid keys imported
 * from a single file.
 *
 * @param {string[]} resultKeys - The array of keys imported from a single file.
 */
async function appendImportedKeys(resultKeys) {
  const keyList = document.getElementById("importKeyListRecap");

  for (let keyId of resultKeys.keys) {
    if (keyId.search(/^0x/) === 0) {
      keyId = keyId.substr(2).toUpperCase();
    }

    const key = EnigmailKeyRing.getKeyById(keyId);

    if (key && key.fpr) {
      // If the checkbox was checked, update the acceptance of the key.
      // Awaited: this function is already async, and the marker it writes is
      // what makes the imported key usable.
      if (document.getElementById(`${key.keyId}-set-personal`).checked) {
        await PgpSqliteDb2.acceptAsPersonalKey(key.fpr);
      }

      const container = document.createXULElement("hbox");
      container.classList.add("key-import-row");

      // Start key info section.
      const grid = document.createXULElement("hbox");
      grid.classList.add("extra-information-label");

      // Key identity.
      const identityLabel = document.createXULElement("label");
      identityLabel.classList.add("extra-information-label-type");
      document.l10n.setAttributes(
        identityLabel,
        "openpgp-import-identity-label"
      );

      const identityValue = document.createXULElement("label");
      identityValue.value = key.userId;

      grid.appendChild(identityLabel);
      grid.appendChild(identityValue);

      // Key fingerprint.
      const fingerprintLabel = document.createXULElement("label");
      document.l10n.setAttributes(
        fingerprintLabel,
        "openpgp-import-fingerprint-label"
      );
      fingerprintLabel.classList.add("extra-information-label-type");

      const fingerprintInput = document.createXULElement("label");
      fingerprintInput.value = EnigmailKey.formatFpr(key.fpr);

      grid.appendChild(fingerprintLabel);
      grid.appendChild(fingerprintInput);

      // Key creation date.
      const createdLabel = document.createXULElement("label");
      document.l10n.setAttributes(createdLabel, "openpgp-import-created-label");
      createdLabel.classList.add("extra-information-label-type");

      const createdValue = document.createXULElement("label");
      createdValue.value = key.created;

      grid.appendChild(createdLabel);
      grid.appendChild(createdValue);

      // Key bits.
      const bitsLabel = document.createXULElement("label");
      bitsLabel.classList.add("extra-information-label-type");
      document.l10n.setAttributes(bitsLabel, "openpgp-import-bits-label");

      const bitsValue = document.createXULElement("label");
      bitsValue.value = key.keySize;

      grid.appendChild(bitsLabel);
      grid.appendChild(bitsValue);
      // End key info section.

      const info = document.createXULElement("button");
      info.classList.add("openpgp-image-btn", "openpgp-props-btn");
      document.l10n.setAttributes(info, "openpgp-import-key-props");
      info.addEventListener("command", () => {
        window.arguments[0].keyDetailsDialog(key.keyId);
      });

      container.appendChild(grid);
      container.appendChild(info);

      keyList.appendChild(container);
    }
  }
}

function openPgpImportComplete() {
  window.arguments[0].okImportCallback();
  window.close();
}

/**
 * Opens a prompt asking the user to enter the passphrase for a given key id.
 *
 * @param {window} win - The current window.
 * @param {string} promptString - The ID of the imported key.
 * @param {object} resultFlags - Keep track of the cancelled action.
 *
 * @returns {string} The entered passphrase or empty.
 */
function passphrasePromptCallback(win, promptString, resultFlags) {
  const passphrase = { value: "" };

  // We need to fetch these strings synchronously in order to properly work with
  // the RNP key import method, which is not async.
  const title = syncl10n.formatValueSync("openpgp-passphrase-prompt-title");

  const prompt = Services.prompt.promptPassword(
    win,
    title,
    promptString,
    passphrase,
    null,
    {}
  );

  if (!prompt) {
    hideOverlay(document.getElementById("wizardImportOverlay"));
    kGenerating = false;
  }

  resultFlags.canceled = !prompt;
  return !prompt ? "" : passphrase.value;
}

/**
 * Return the normalized key from input that may be the full fingerprint.
 *
 * @returns {string} the key id.
 */
function normalizeKeyInput(key) {
  key = key.replace(/^0x/, "").replaceAll(" ", "").toUpperCase();
  if (key.length == 40 || key.length == 64) {
    // Got the full fingerprint; use key part.
    // See https://openpgp.dev/book/glossary.html#term-Key-ID
    // - For OpenPGP v4 keys, the Key ID consists of the low-order
    //   (rightmost) 64 bits of their OpenPGP Fingerprint.
    // - For OpenPGP v5/v6 keys, the Key ID consists of the high-order
    //   (leftmost) 64 bits of their OpenPGP Fingerprint.
    key = key.length === 40 ? key.substring(24) : key.substring(0, 16);
  }
  return key;
}

/**
 * Return the full fingerprint if the input was one, otherwise an empty string.
 *
 * @param {string} key - Raw value of the key id field.
 * @returns {string} The uppercase fingerprint, or "".
 */
function fingerprintFromInput(key) {
  const cleaned = key.replace(/^0x/i, "").replaceAll(" ", "").toUpperCase();
  return cleaned.length == 40 || cleaned.length == 64 ? cleaned : "";
}

/**
 * Look the entered key up in the external GnuPG keyring.
 *
 * @param {string} keyId - Normalized key id from the input.
 * @param {string} fingerprint - Full fingerprint from the input, or "".
 * @returns {object} With a status of "disabled", "unavailable",
 *   "not-found" or "found"; the latter also carries the fingerprint and
 *   the ASCII armored public key block.
 */
function findKeyInGnuPG(keyId, fingerprint) {
  if (!Services.prefs.getBoolPref("mail.openpgp.allow_external_gnupg")) {
    return { status: "disabled" };
  }
  if (!GPGME.init()) {
    return { status: "unavailable" };
  }

  let keysFromGnuPGMap;
  try {
    keysFromGnuPGMap = GPGME.getPublicKeysForEmail(gIdentity.email);
  } catch (ex) {
    console.warn("Looking up the key in GnuPG failed", ex);
    return { status: "unavailable" };
  }

  for (const fpr of keysFromGnuPGMap.keys()) {
    // Accept both a full fingerprint and a key id, per normalizeKeyInput().
    if (
      (fingerprint && fpr.toUpperCase() == fingerprint) ||
      normalizeKeyInput(fpr) == keyId
    ) {
      // Only the fingerprint is returned. The armored block used to travel
      // with it so the caller could import it into the profile; that import is
      // gone, and the caller now loads the key transiently by fingerprint.
      return { status: "found", fingerprint: fpr };
    }
  }
  return { status: "not-found" };
}

/**
 * Save the GnuPG Key for the current identity and trigger a callback.
 */
async function openPgpExternalComplete() {
  const acceptButton = kDialog.getButton("accept");

  const inputValue = document.getElementById("externalKey").value;
  const keyId = normalizeKeyInput(inputValue);
  const fingerprint = fingerprintFromInput(inputValue);

  // Check if we have the public key for that, and if not, ask GnuPG.
  let keyObj = EnigmailKeyRing.getKeyById(keyId);
  let gnuPgLookup;

  if (!keyObj?.getUserIdWithEmail(gIdentity.email)) {
    gnuPgLookup = findKeyInGnuPG(keyId, fingerprint);
    if (gnuPgLookup.status == "found") {
      // The key exists only in GnuPG, so it is made reachable through the
      // transient cache rather than copied into the profile. Nothing is
      // written: getKeyById() resolves a transient key by fingerprint, which
      // is what signing and the own-key usability check need, and Item 10
      // refuses to persist a key GnuPG holds for exactly this reason.
      //
      // loadGnuPgKeyById() rather than a profile import also covers the case
      // where `fetch_pubkeys_from_gnupg` is off: that pref gates the
      // address-keyed discovery, not a lookup by fingerprint, so the key is
      // still reachable and the wizard still completes.
      acceptButton.disabled = true;
      await EnigmailKeyRing.loadGnuPgKeyById(gnuPgLookup.fingerprint);
      keyObj = EnigmailKeyRing.getKeyById(keyId);
    }
  }

  if (!keyObj?.getUserIdWithEmail(gIdentity.email)) {
    document.getElementById("wizardExternalKeyProvideKeyId").hidden = true;
    acceptButton.disabled = true;

    const gnupgUnavailable = gnuPgLookup?.status == "unavailable";
    document.l10n.setAttributes(
      document.getElementById("openpgpImportOwnPublicKey"),
      gnupgUnavailable
        ? "openpgp-import-own-key-gnupg-unavailable"
        : "openpgp-import-own-key-description",
      { keyId: `0x${keyId}` }
    );
    revealSection("openpgpImportOwnKey");
    return;
  }

  gIdentity.setBoolAttribute("is_gnupg_key_id", true);
  // Item 65: the ordered list is authoritative and `openpgp_key_id` follows its
  // first entry. The wizard is naming the identity's key, so the list becomes
  // that one key -- set through the list rather than beside it, or the two
  // would disagree the moment the user reordered anything.
  setKeyList(gIdentity, [keyId]);

  window.arguments[0].okExternalCallback(keyId);
  window.close();
}

/**
 * Open key picker, and try to import the public key.
 * On success, complete the external key setup.
 */
async function importPublicKey() {
  clearImportWarningNotifications("openPgpImportPublicKeyWarning");
  const [importTitle, importType] = await document.l10n.formatValues([
    { id: "import-key-file" },
    { id: "gnupg-file" },
  ]);

  const fp = Cc["@mozilla.org/filepicker;1"].createInstance(Ci.nsIFilePicker);
  fp.init(window.browsingContext, importTitle, Ci.nsIFilePicker.modeOpen);
  fp.defaultExtension = "*.asc";
  fp.appendFilter(importType, "*.asc;*.gpg;*.pgp");
  fp.appendFilters(Ci.nsIFilePicker.filterAll);
  const rv = await new Promise(resolve => fp.open(resolve));
  if (rv != Ci.nsIFilePicker.returnOK || !fp.file) {
    return;
  }

  const keyId = normalizeKeyInput(document.getElementById("externalKey").value);

  const errorMsgObj = {};
  // Fetch the list of all the available keys inside the selected file.
  const importKeys = await EnigmailKey.getKeyListFromKeyFile(
    fp.file,
    errorMsgObj,
    true,
    false,
    true
  );
  const key = importKeys?.find(k => k.id.toUpperCase() == keyId);
  // Show a warning message if the import failed.
  if (!key) {
    document.l10n.setAttributes(
      await addImportWarningNotification("openPgpImportPublicKeyWarning"),
      "openpgp-import-keyid-failed",
      {
        keyId: `0x${keyId}`,
      }
    );
    return;
  }

  await EnigmailKeyRing.importKeyDataSilent(null, key.pubKey, false);

  kDialog.getButton("accept").disabled = false;
  await openPgpExternalComplete();
}
