/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* global MozElements */
/* import-globals-from ../../../../components/compose/content/MsgComposeCommands.js */
/* import-globals-from commonWorkflows.js */
/* globals goDoCommand */ // From globalOverlay.js

"use strict";

var { XPCOMUtils } = ChromeUtils.importESModule(
  "resource://gre/modules/XPCOMUtils.sys.mjs"
);

ChromeUtils.defineESModuleGetters(this, {
  EnigmailKeyRing: "chrome://openpgp/content/modules/keyRing.sys.mjs",
  GPGME: "chrome://openpgp/content/modules/GPGME.sys.mjs",
  KeyLookupHelper: "chrome://openpgp/content/modules/keyLookupHelper.sys.mjs",
  firstUsableKey: "chrome://openpgp/content/modules/identityKeys.sys.mjs",
  getKeyList: "chrome://openpgp/content/modules/identityKeys.sys.mjs",
  moveKey: "chrome://openpgp/content/modules/identityKeys.sys.mjs",
  OpenPGPAlias: "chrome://openpgp/content/modules/OpenPGPAlias.sys.mjs",
  PgpSqliteDb2: "chrome://openpgp/content/modules/sqliteDb.sys.mjs",
  // FIXME: using this creates a conflict with another file where this symbol
  // was imported with ChromeUtils instead of defined as lazy getter.
  // EnigmailWindows: "chrome://openpgp/content/modules/windows.sys.mjs",
});
var { EnigmailWindows } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/windows.sys.mjs"
);
// Imported directly rather than through defineESModuleGetters above. A lazy
// getter for this name made the whole script fail to load in the composer --
// gKeyAssistant came out undefined and every caller threw -- which the FIXME
// above records as a known conflict between the two import styles. Nothing
// else in this window defines the name, so the direct import is the working
// form rather than a workaround for a collision.
var { GnuPGAgent } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/gnupgAgent.sys.mjs"
);

window.addEventListener("load", () => {
  gKeyAssistant.onLoad();
});
window.addEventListener("unload", () => {
  gKeyAssistant.onUnload();
});

var gKeyAssistant = {
  dialog: null,
  recipients: [],
  currentRecip: null,

  /*
   * Variable ignoreExternal should be set to true whenever a
   * keyAsssistant window is open that cannot tolerate changes to
   * the keyAsssistant's own variables, that track the current user
   * interaction.
   *
   * While the key assistant is showing, it takes care to update the
   * elements on screen, based on the expected changes. Usually,
   * it will perform a refresh after a current action is completed.
   *
   * Without this protection, you'd get data races and side effects like
   * email addresses being shown twice, and worse.
   */
  ignoreExternal: false,

  /**
   * Initialize the main notification box for the account setup process.
   */
  get notificationBox() {
    if (!this._notificationBox) {
      this._notificationBox = new MozElements.NotificationBox(element => {
        element.setAttribute("notificationside", "bottom");
        document.getElementById("modalDialogNotification").append(element);
      });
    }
    return this._notificationBox;
  },

  onLoad() {
    this.dialog = document.getElementById("keyAssistant");

    this._setupEventListeners();
  },

  _setupEventListeners() {
    document
      .getElementById("disableEncryptionButton")
      .addEventListener("click", () => {
        gSendEncrypted = false;
        gUserTouchedSendEncrypted = true;
        checkEncryptionState();
        this.close();
      });
    document
      .getElementById("sendEncryptedButton")
      .addEventListener("click", () => {
        goDoCommand("cmd_sendWithCheck");
        this.close();
      });
    document
      .getElementById("toggleRecipientsButton")
      .addEventListener("click", () => {
        this.toggleRecipientsList();
      });

    this.dialog.addEventListener("close", () => {
      this.close();
    });
  },

  async close() {
    await checkEncryptionState();
    this.dialog.close();
  },

  onUnload() {
    this.recipients = [];
  },

  setMainDisableButton() {
    document.getElementById("disableEncryptionButton").hidden =
      !gSendEncrypted || (this.usableKeys && !this.problematicKeys);
  },

  /**
   * Open the key assistant modal dialog.
   *
   * @param {string[]} recipients - An array of strings containing all currently
   *   written recipients.
   * @param {boolean} isSending - If the key assistant was triggered during a
   *   sending attempt.
   */
  show(recipients, isSending) {
    this.recipients = recipients;
    this.buildMainView();
    this.resetViews();

    document.getElementById("sendEncryptedButton").hidden = !isSending;
    this.setMainDisableButton();
    this.dialog.showModal();
  },

  resetViews() {
    this.notificationBox.removeAllNotifications();
    this.dialog.removeAttribute("style");

    for (const view of document.querySelectorAll(".dialog-body-view")) {
      view.hidden = true;
    }

    document.getElementById("mainButtons").hidden = false;
    document.getElementById("mainView").hidden = false;
  },

  changeView(view, context) {
    this.resetViews();

    this.dialog.setAttribute(
      "style",
      `min-height: ${this.dialog.getBoundingClientRect().height}px`
    );

    document.getElementById("mainView").hidden = true;
    document.getElementById(`${view}View`).hidden = false;

    switch (view) {
      case "discover":
        this.hideMainButtons();
        this.initOnlineDiscovery(context);
        break;

      case "resolve":
        this.hideMainButtons();
        break;

      default:
        break;
    }
  },

  hideMainButtons() {
    document.getElementById("mainButtons").hidden = true;
  },

  usableKeys: 0,
  problematicKeys: 0,

  /**
   * Name the key that will sign, before the message is sent.
   *
   * With either engine the choice must be visible: a user cannot verify a
   * decision they cannot see. For the external keyring the choice is GnuPG's
   * -- it applies the configured default key, or falls back to the first
   * usable key in its own order -- and it is reported rather than assumed.
   *
   * For a key the internal engine holds, the choice is ours, and since
   * Item 60 a generated key has two subkeys, so the interesting question is
   * no longer which key but which subkey. The engine prefers the newest usable
   * signing subkey and only falls back to the primary if no subkey can sign;
   * that rule is what this line reports, and the chooser beneath it is the
   * named choice -- the equivalent of GnuPG's --local-user / --default-key.
   */
  async fillSigningKey() {
    const section = document.getElementById("keyAssistantSigningKey");
    const value = document.getElementById("keyAssistantSigningKeyValue");
    const source = document.getElementById("keyAssistantSigningKeySource");
    section.hidden = true;
    this.hideSigningSubkeyChoice();
    // Hidden with the rest: an identity that has switched to the external
    // keyring must not keep showing the internal key list from before, which
    // would describe a choice the engine is no longer making.
    this.hideIdentityKeyOrder();

    const identity = gCurrentIdentity;
    if (!identity?.email) {
      return;
    }

    const useExternalKeyring =
      GPGME.init() &&
      Services.prefs.getBoolPref("mail.openpgp.allow_external_gnupg") &&
      identity.getBoolAttribute("is_gnupg_key_id");

    if (!useExternalKeyring) {
      await this.fillInternalSigningKey(identity, value, source, section);
      return;
    }

    let chosen = null;
    try {
      chosen = await GPGME.resolveSigningKeyForIdentity(identity.email);
    } catch (ex) {
      console.warn("Resolving the signing key for display failed", ex);
      return;
    }
    if (!chosen?.fpr) {
      return;
    }

    document.l10n.setAttributes(
      value,
      "openpgp-key-assistant-signing-key-value",
      {
        fingerprint: chosen.fpr,
      }
    );
    document.l10n.setAttributes(
      source,
      chosen.source == "default-key"
        ? "openpgp-key-assistant-signing-key-source-default"
        : "openpgp-key-assistant-signing-key-source-gnupg-order"
    );

    await this.fillPassphraseCacheNote();

    section.hidden = false;
  },

  /**
   * Report the subkey the internal engine will sign with, and offer the
   * named choice.
   *
   * @param {nsIMsgIdentity} identity - The composer's identity.
   * @param {Element} value - Element naming the key.
   * @param {Element} source - Element explaining the choice.
   * @param {Element} section - The whole section.
   */
  async fillInternalSigningKey(identity, value, source, section) {
    // The engine reads the identity's ordered key list, so the line has to
    // report what that rule produces rather than what `openpgp_key_id` says:
    // with two keys those are the same only while the first one is usable.
    const key = firstUsableKey(identity, "sign");
    if (!key) {
      this.fillIdentityKeyOrder(identity);
      return;
    }

    // Offered whenever the identity holds more than one key, because that is
    // when the order is a preference rather than a restatement of the only
    // answer available.
    this.fillIdentityKeyOrder(identity);

    // A revoked or expired subkey cannot sign, so it is not a candidate.
    // Listing one would offer a choice that fails at send time.
    const nowSeconds = Math.floor(Date.now() / 1000);
    const usableSigners = key.subKeys.filter(
      sk =>
        sk.keyUseFor.includes("s") &&
        !/r/i.test(sk.keyTrust) &&
        (!sk.expiryTime || sk.expiryTime > nowSeconds)
    );

    const named = identity.getUnicharAttribute("openpgp_signing_subkey");
    let signer = null;
    let sourceId;

    if (named) {
      // Named but unusable still reports the name: the send will refuse, and
      // showing a different subkey here would say the opposite.
      signer =
        key.subKeys.find(sk => sk.fpr.toUpperCase() == named.toUpperCase()) ||
        null;
      sourceId = "openpgp-key-assistant-signing-key-source-named";
      if (!signer) {
        document.l10n.setAttributes(
          value,
          "openpgp-key-assistant-signing-subkey-missing",
          {
            fingerprint: named,
          }
        );
        document.l10n.setAttributes(source, sourceId);
        // The chooser is still offered, so the setting can be repaired from
        // here rather than leaving the user with a refusal and no way out.
        if (usableSigners.length) {
          this.fillSigningSubkeyChoice(identity, usableSigners, "");
        }
        section.hidden = false;
        return;
      }
    } else if (usableSigners.length) {
      signer = usableSigners.reduce((a, b) =>
        b.keyCreated >= a.keyCreated ? b : a
      );
      sourceId = "openpgp-key-assistant-signing-key-source-newest-subkey";
    } else if (key.keyUseFor.includes("s")) {
      signer = key;
      sourceId = "openpgp-key-assistant-signing-key-source-primary";
    } else {
      return;
    }

    document.l10n.setAttributes(
      value,
      "openpgp-key-assistant-signing-key-value",
      {
        fingerprint: signer.fpr,
      }
    );
    document.l10n.setAttributes(source, sourceId);

    this.fillSigningSubkeyChoice(identity, usableSigners, named);

    // No passphrase-cache note here: that note describes gpg-agent's cache,
    // and an internal key is unlocked through the primary password instead.
    section.hidden = false;
  },

  /**
   * Offer the signing subkeys of the identity's key, so one can be named.
   *
   * "Automatic" is the default and is what every profile had before this
   * existed. A named subkey is stored on the identity, so it applies to every
   * message this identity sends rather than to this one draft.
   *
   * @param {nsIMsgIdentity} identity - The composer's identity.
   * @param {object[]} signers - Usable signing subkeys.
   * @param {string} named - The currently named fingerprint, or "".
   */
  fillSigningSubkeyChoice(identity, signers, named) {
    const chooser = document.getElementById("keyAssistantSigningSubkeyChoice");
    const label = document.getElementById(
      "keyAssistantSigningSubkeyChoiceLabel"
    );
    chooser.replaceChildren();

    if (!signers.length) {
      this.hideSigningSubkeyChoice();
      return;
    }

    const automatic = document.createElement("option");
    automatic.value = "";
    document.l10n.setAttributes(
      automatic,
      "openpgp-key-assistant-signing-subkey-automatic"
    );
    chooser.appendChild(automatic);

    let selected = 0;
    for (const sk of signers) {
      const option = document.createElement("option");
      option.value = sk.fpr;
      document.l10n.setAttributes(
        option,
        "openpgp-key-assistant-signing-subkey-item",
        { keyId: sk.keyId, created: sk.created }
      );
      if (named && sk.fpr.toUpperCase() == named.toUpperCase()) {
        selected = chooser.children.length;
      }
      chooser.appendChild(option);
    }
    chooser.selectedIndex = selected;

    chooser.onchange = () => {
      identity.setUnicharAttribute("openpgp_signing_subkey", chooser.value);
      // Redraw, so the line above names the subkey just chosen.
      this.fillSigningKey();
    };

    chooser.hidden = false;
    label.hidden = false;
  },

  /**
   * Show the identity's keys in order, so the preference is visible where it
   * is used and can be changed without leaving the composer.
   *
   * Only shown when there is more than one key: an identity with one key has
   * no order to state, and a list of one would be a control that can only
   * displease. The first usable entry is marked, because that is the rule the
   * engine applies -- marking the first entry instead would claim a preference
   * the user does not get when that key has expired.
   *
   * @param {nsIMsgIdentity} identity - The composer's identity.
   */
  fillIdentityKeyOrder(identity) {
    const section = document.getElementById("keyAssistantSigningKeyOrder");
    const list = document.getElementById("keyAssistantSigningKeyOrderList");
    if (!section || !list) {
      return;
    }
    list.replaceChildren();

    const keys = getKeyList(identity);
    if (keys.length < 2) {
      section.hidden = true;
      return;
    }

    const chosen = firstUsableKey(identity, "sign");
    for (const [index, fpr] of keys.entries()) {
      const key = EnigmailKeyRing.getKeyById(fpr);
      const item = document.createElement("li");
      item.className = "key-assistant-key-order-item";

      const label = document.createElement("span");
      label.textContent = key ? `${key.keyId} — ${key.created}` : fpr;
      item.appendChild(label);

      if (chosen && chosen.fpr.toUpperCase() == fpr.toUpperCase()) {
        const badge = document.createElement("span");
        badge.className = "tip-caption";
        document.l10n.setAttributes(
          badge,
          "openpgp-key-assistant-signing-key-order-active"
        );
        item.appendChild(badge);
      }

      // Arrows rather than drag: a drag cannot be operated from a keyboard,
      // and this dialog already asks the user to make a decision by reading.
      const up = document.createElement("button");
      document.l10n.setAttributes(
        up,
        "openpgp-key-assistant-signing-key-order-move-up"
      );
      up.disabled = index == 0;
      up.addEventListener("click", () => {
        moveKey(identity, fpr, -1);
        this.fillSigningKey();
      });
      item.appendChild(up);

      const down = document.createElement("button");
      document.l10n.setAttributes(
        down,
        "openpgp-key-assistant-signing-key-order-move-down"
      );
      down.disabled = index == keys.length - 1;
      down.addEventListener("click", () => {
        moveKey(identity, fpr, 1);
        this.fillSigningKey();
      });
      item.appendChild(down);

      list.appendChild(item);
    }

    section.hidden = false;
  },

  hideIdentityKeyOrder() {
    const section = document.getElementById("keyAssistantSigningKeyOrder");
    if (section) {
      section.hidden = true;
    }
  },

  hideSigningSubkeyChoice() {
    const chooser = document.getElementById("keyAssistantSigningSubkeyChoice");
    const label = document.getElementById(
      "keyAssistantSigningSubkeyChoiceLabel"
    );
    if (chooser) {
      chooser.hidden = true;
    }
    if (label) {
      label.hidden = true;
    }
  },

  /**
   * Say how long gpg-agent will keep the passphrase after signing.
   *
   * A user who signs twice sees a pinentry the first time and none the second,
   * and the obvious reading of that is that the second signature did not
   * prompt because it was not needed. It was needed; the agent remembered it.
   * Saying so, with the durations read from the agent's own configuration,
   * turns a mystery into a stated property -- and names the menu item that
   * clears it.
   *
   * **Two numbers, not one, and the difference is the honest part.** The idle
   * timer resets on every use, so the maximum is what bounds the exposure, and
   * a message quoting only the first would understate it.
   *
   * **The residual risk is stated rather than implied.** While the agent holds
   * the passphrase, any program running as the same user can use the key
   * without being asked. That is how gpg-agent works; this build does not fix
   * it and must not read as though it does.
   *
   * Silent when the agent cannot be asked. A duration invented here would be
   * the number a user relied on, which is worse than no number at all.
   */
  async fillPassphraseCacheNote() {
    const note = document.getElementById("keyAssistantSigningKeyCache");
    if (!note) {
      return;
    }
    note.hidden = true;

    let timeouts = null;
    try {
      timeouts = await GnuPGAgent.cacheTimeouts();
    } catch (ex) {
      console.warn("Reading gpg-agent's cache timeouts failed", ex);
      return;
    }
    if (!timeouts?.maximum) {
      return;
    }

    document.l10n.setAttributes(
      note,
      "openpgp-key-assistant-passphrase-cached",
      {
        idle: Math.round(timeouts.idle / 60),
        maximum: Math.round(timeouts.maximum / 60),
      }
    );
    note.hidden = false;
  },

  /**
   * Populate the main view of the key assistant with the list of recipients and
   * its keys, separating the recipients that have issues from those without
   * issues.
   */
  async buildMainView() {
    await this.fillSigningKey();

    // Restore empty UI state.
    document.getElementById("keyAssistantIssues").hidden = true;
    document.getElementById("keysListIssues").replaceChildren();
    document.getElementById("keyAssistantValid").hidden = true;
    document.getElementById("keysListValid").replaceChildren();

    this.usableKeys = 0;
    this.problematicKeys = 0;

    for (const addr of this.recipients) {
      // Fetch all keys for the current recipient.
      const keyMetas = await EnigmailKeyRing.getEncryptionKeyMeta(addr);
      if (keyMetas.some(k => k.readiness == "alias")) {
        const aliasKeyList = EnigmailKeyRing.getAliasKeyList(addr);
        const aliasKeys = EnigmailKeyRing.getAliasKeys(aliasKeyList);
        if (!aliasKeys.length) {
          // failure, at least one alias key is unusable/unavailable

          const descriptionDiv = document.createElement("div");
          document.l10n.setAttributes(
            descriptionDiv,
            "openpgp-compose-alias-status-error"
          );

          this.addToProblematicList(addr, descriptionDiv, null);
          this.problematicKeys++;
        } else {
          const aliasText = document.createElement("div");
          document.l10n.setAttributes(
            aliasText,
            "openpgp-compose-alias-status-direct",
            { count: aliasKeys.length }
          );

          this.addToReadyList(addr, aliasText);
          this.usableKeys++;
        }
      } else {
        // not alias

        const acceptedKeys = keyMetas.filter(k => k.readiness == "accepted");
        if (acceptedKeys.length) {
          const button = document.createElement("button");
          document.l10n.setAttributes(
            button,
            "openpgp-key-assistant-view-key-button"
          );
          button.addEventListener("click", () => {
            gKeyAssistant.viewKeyFromOverview(addr, acceptedKeys[0]);
          });

          this.addToReadyList(addr, button);
          this.usableKeys++;
        } else {
          const descriptionDiv = document.createElement("div");

          const canOfferResolving = keyMetas.some(
            k =>
              k.readiness == "collected" ||
              k.readiness == "expiredAccepted" ||
              k.readiness == "expiredUndecided" ||
              k.readiness == "expiredOtherAccepted" ||
              k.readiness == "undecided" ||
              k.readiness == "otherAccepted" ||
              k.readiness == "expiredRejected" ||
              k.readiness == "rejected"
          );

          let button = null;
          if (canOfferResolving) {
            this.fillKeysStatus(descriptionDiv, keyMetas);

            button = document.createElement("button");
            document.l10n.setAttributes(
              button,
              "openpgp-key-assistant-issue-resolve-button"
            );
            button.addEventListener("click", () => {
              this.buildResolveView(addr, keyMetas);
            });
          } else {
            document.l10n.setAttributes(
              descriptionDiv,
              "openpgp-key-assistant-no-key-available"
            );
          }

          this.addToProblematicList(addr, descriptionDiv, button);
          this.problematicKeys++;
        }
      }
    }

    document.getElementById("keyAssistantIssues").hidden =
      !this.problematicKeys;
    document.l10n.setAttributes(
      document.getElementById("keyAssistantIssuesDescription"),
      "openpgp-key-assistant-recipients-issue-description",
      { count: this.problematicKeys }
    );

    document.getElementById("keyAssistantValid").hidden = !this.usableKeys;

    if (!this.problematicKeys && this.usableKeys) {
      document.l10n.setAttributes(
        document.getElementById("keyAssistantValidDescription"),
        "openpgp-key-assistant-recipients-description-no-issues"
      );
      document.getElementById("toggleRecipientsButton").click();
    } else {
      document.l10n.setAttributes(
        document.getElementById("keyAssistantValidDescription"),
        "openpgp-key-assistant-recipients-description",
        { count: this.usableKeys }
      );
    }

    document.getElementById("sendEncryptedButton").disabled =
      this.problematicKeys || !this.usableKeys;
    this.setMainDisableButton();
  },

  isAccepted(acc) {
    return (
      acc.emailDecided &&
      (acc.fingerprintAcceptance == "verified" ||
        acc.fingerprintAcceptance == "unverified")
    );
  },

  async viewKeyFromResolve(keyMeta) {
    const oldAccept = {};
    await PgpSqliteDb2.getAcceptance(
      keyMeta.keyObj.fpr,
      this.currentRecip,
      oldAccept
    );

    this.ignoreExternal = true;
    await this._viewKey(keyMeta);
    this.ignoreExternal = false;

    // If the key is not yet accepted, then we want to automatically
    // close the email-resolve view, if the user accepts the key
    // while viewing the key details.
    const autoCloseOnAccept = !this.isAccepted(oldAccept);

    const newAccept = {};
    await PgpSqliteDb2.getAcceptance(
      keyMeta.keyObj.fpr,
      this.currentRecip,
      newAccept
    );

    if (autoCloseOnAccept && this.isAccepted(newAccept)) {
      this.resetViews();
      this.buildMainView();
    } else {
      // While viewing the key, the user could have triggered a refresh,
      // which could have changed the validity of the key.
      const keyMetas = await EnigmailKeyRing.getEncryptionKeyMeta(
        this.currentRecip
      );
      this.buildResolveView(this.currentRecip, keyMetas);
    }
  },

  async viewKeyFromOverview(recip, keyMeta) {
    this.ignoreExternal = true;
    await this._viewKey(keyMeta);
    this.ignoreExternal = false;

    // While viewing the key, the user could have triggered a refresh,
    // which could have changed the validity of the key.
    // In theory it would be sufficient to refresh the main view
    // for the single email address.
    await checkEncryptionState("openpgp-key-assistant-refresh");
    this.buildMainView();
  },

  async _viewKey(keyMeta) {
    const exists = EnigmailKeyRing.getKeyById(keyMeta.keyObj.keyId);

    if (!exists) {
      if (keyMeta.readiness != "collected") {
        return;
      }
      await EnigmailKeyRing.importKeyDataSilent(
        window,
        keyMeta.collectedKey.pubKey,
        true
      );
    }

    EnigmailWindows.openKeyDetails(window, keyMeta.keyObj.keyId, false);
  },

  addToReadyList(recipient, detailElement) {
    const list = document.getElementById("keysListValid");
    const row = document.createElement("li");
    row.classList.add("key-row");

    const info = document.createElement("div");
    info.classList.add("key-info");
    const title = document.createElement("b");
    title.textContent = recipient;

    info.appendChild(title);
    row.append(info, detailElement);
    list.appendChild(row);
  },

  fillKeysStatus(element, keyMetas) {
    const unaccepted = keyMetas.filter(
      k =>
        k.readiness == "undecided" ||
        k.readiness == "rejected" ||
        k.readiness == "otherAccepted"
    );
    const collected = keyMetas.filter(k => k.readiness == "collected");

    // Multiple keys available.
    if (unaccepted.length + collected.length > 1) {
      document.l10n.setAttributes(
        element,
        "openpgp-key-assistant-multiple-keys"
      );
      // TODO: add note to be careful?
      return;
    }

    // Not expired but not accepted keys.
    if (unaccepted.length) {
      document.l10n.setAttributes(
        element,
        "openpgp-key-assistant-key-unaccepted",
        {
          count: unaccepted.length,
        }
      );
      if (unaccepted.length == 1) {
        element.before("0x" + unaccepted[0].keyObj.keyId);
      }
      return;
    }

    const expiredAccepted = keyMetas.filter(
      k => k.readiness == "expiredAccepted"
    );

    // Key accepted but expired.
    if (expiredAccepted.length) {
      if (expiredAccepted.length == 1) {
        document.l10n.setAttributes(
          element,
          "openpgp-key-assistant-key-accepted-expired",
          {
            date: expiredAccepted[0].keyObj.effectiveExpiry,
          }
        );
        element.before("0x" + expiredAccepted[0].keyObj.keyId);
      } else {
        document.l10n.setAttributes(
          element,
          "openpgp-key-assistant-keys-accepted-expired"
        );
      }
      return;
    }

    const expiredUnaccepted = keyMetas.filter(
      k =>
        k.readiness == "expiredUndecided" ||
        k.readiness == "expiredRejected" ||
        k.readiness == "expiredOtherAccepted"
    );

    // Key not accepted and expired.
    if (expiredUnaccepted.length) {
      if (expiredUnaccepted.length == 1) {
        document.l10n.setAttributes(
          element,
          "openpgp-key-assistant-key-unaccepted-expired-one",
          {
            date: expiredUnaccepted[0].keyObj.effectiveExpiry,
          }
        );
        element.before("0x" + expiredUnaccepted[0].keyObj.keyId);
      } else {
        document.l10n.setAttributes(
          element,
          "openpgp-key-assistant-key-unaccepted-expired-many"
        );
      }
      return;
    }

    const unacceptedNotYetImported = keyMetas.filter(
      k => k.readiness == "collected"
    );

    if (unacceptedNotYetImported.length) {
      document.l10n.setAttributes(
        element,
        "openpgp-key-assistant-keys-has-collected",
        {
          count: unacceptedNotYetImported.length,
        }
      );
      if (unacceptedNotYetImported.length == 1) {
        element.before("0x" + unacceptedNotYetImported[0].keyObj.keyId);
      }
      return;
    }

    // We found nothing, so let's return a default message.
    document.l10n.setAttributes(
      element,
      "openpgp-key-assistant-no-key-available"
    );
  },

  addToProblematicList(recipient, descriptionDiv, resolveButton) {
    const list = document.getElementById("keysListIssues");
    const row = document.createElement("li");
    row.classList.add("key-row");

    const info = document.createElement("div");
    info.classList.add("key-info");
    const title = document.createElement("b");
    title.textContent = recipient;
    info.append(title, descriptionDiv);

    if (resolveButton) {
      row.append(info, resolveButton);
    } else {
      row.appendChild(info);
    }

    list.appendChild(row);
  },

  fillKeyOriginAndStatus(element, keyMeta) {
    // The key was collected from somewhere.
    if (keyMeta.collectedKey) {
      const sourceSpan = document.createElement("span");
      document.l10n.setAttributes(
        sourceSpan,
        "openpgp-key-assistant-key-source",
        {
          count: keyMeta.collectedKey.sources.length,
        }
      );
      element.append(sourceSpan, ": ");
      const linkSpan = document.createElement("span");
      linkSpan.classList.add("comma-separated");

      const sourceLinks = keyMeta.collectedKey.sources.map(source => {
        source.type = source.type.toLowerCase(); // Earlier "WKD" was "wkd".
        const a = document.createElement("a");
        if (source.uri) {
          a.href = source.uri;
          a.title = source.uri;
        }
        if (source.description) {
          if (a.title) {
            a.title += " - ";
          }
          a.title += source.description;
        }
        const span = document.createElement("span");
        // openpgp-key-assistant-key-collected-attachment
        // openpgp-key-assistant-key-collected-autocrypt
        // openpgp-key-assistant-key-collected-keyserver
        // openpgp-key-assistant-key-collected-wkd
        document.l10n.setAttributes(
          span,
          `openpgp-key-assistant-key-collected-${source.type}`
        );
        a.appendChild(span);
        return a;
      });
      linkSpan.append(...sourceLinks);
      element.appendChild(linkSpan);
      return;
    }

    // The key was rejected.
    if (keyMeta.readiness == "rejected") {
      document.l10n.setAttributes(
        element,
        "openpgp-key-assistant-key-rejected"
      );
      return;
    }

    // Key is expired.
    if (
      keyMeta.readiness == "expiredAccepted" ||
      keyMeta.readiness == "expiredUndecided" ||
      keyMeta.readiness == "expiredOtherAccepted" ||
      keyMeta.readiness == "expiredRejected"
    ) {
      document.l10n.setAttributes(
        element,
        "openpgp-key-assistant-this-key-accepted-expired",
        {
          date: keyMeta.keyObj.effectiveExpiry,
        }
      );
      return;
    }

    if (keyMeta.readiness == "otherAccepted") {
      // Was the key already accepted for another email address?
      document.l10n.setAttributes(
        element,
        "openpgp-key-assistant-key-accepted-other",
        {
          date: keyMeta.keyObj.effectiveExpiry,
        }
      );
    }
  },

  async buildResolveView(recipient, keyMetas) {
    this.currentRecip = recipient;
    document.getElementById("resolveViewAcceptKey").disabled = true;

    const unaccepted = keyMetas.filter(
      k =>
        k.readiness == "undecided" ||
        k.readiness == "rejected" ||
        k.readiness == "otherAccepted"
    );
    const collected = keyMetas.filter(k => k.readiness == "collected");
    const expiredAccepted = keyMetas.filter(
      k => k.readiness == "expiredAccepted"
    );
    const expiredUnaccepted = keyMetas.filter(
      k =>
        k.readiness == "expiredUndecided" ||
        k.readiness == "expiredRejected" ||
        k.readiness == "expiredOtherAccepted"
    );

    this.usableKeys = unaccepted.length + collected.length;
    const problematicKeys = expiredAccepted.length + expiredUnaccepted.length;
    const numKeys = this.usableKeys + problematicKeys;

    document.l10n.setAttributes(
      document.getElementById("resolveViewTitle"),
      "openpgp-key-assistant-resolve-title",
      {
        recipient,
        numKeys,
      }
    );

    document.l10n.setAttributes(
      document.getElementById("resolveViewExpiredDescription"),
      "openpgp-key-assistant-invalid-title",
      { numKeys }
    );

    document.getElementById("resolveViewValid").hidden = !this.usableKeys;
    const usableList = document.getElementById("resolveValidKeysList");
    usableList.replaceChildren();

    function createKeyRow(keyMeta, isValid) {
      const row = document.createElement("li");
      const label = document.createElement("label");
      label.classList.add("flex-center");

      const input = document.createElement("input");
      input.type = "radio";
      input.name = isValid ? "valid-key" : "invalid-key";
      input.value = keyMeta.keyObj.keyId;
      input.disabled = !isValid;

      if (isValid) {
        input.addEventListener("change", () => {
          document.getElementById("resolveViewAcceptKey").disabled = false;
        });
      }
      label.appendChild(input);

      const keyId = document.createElement("b");
      keyId.textContent = "0x" + keyMeta.keyObj.keyId;

      const creationTime = document.createElement("time");
      creationTime.setAttribute(
        "datetime",
        new Date(keyMeta.keyObj.keyCreated * 1000).toISOString()
      );
      document.l10n.setAttributes(
        creationTime,
        "openpgp-key-assistant-key-created",
        { date: keyMeta.keyObj.created }
      );
      label.append(keyId, " - ", creationTime);
      row.appendChild(label);

      const fingerprint = document.createElement("div");
      fingerprint.classList.add("key-info-block");
      const fpDesc = document.createElement("span");
      const fpLink = document.createElement("a");
      fpLink.href = "#";
      fpLink.textContent = EnigmailKey.formatFpr(keyMeta.keyObj.fpr);
      fpLink.addEventListener("click", event => {
        event.preventDefault();
        gKeyAssistant.viewKeyFromResolve(keyMeta);
      });
      document.l10n.setAttributes(
        fpDesc,
        "openpgp-key-assistant-key-fingerprint"
      );
      fingerprint.append(fpDesc, ": ", fpLink);
      row.appendChild(fingerprint);

      const info = document.createElement("div");
      info.classList.add("key-info-block");
      row.append(info);

      gKeyAssistant.fillKeyOriginAndStatus(info, keyMeta);
      return row;
    }

    for (const meta of unaccepted) {
      usableList.appendChild(createKeyRow(meta, true));
    }

    for (const meta of collected) {
      usableList.appendChild(createKeyRow(meta, true));
    }

    document.getElementById("resolveViewInvalid").hidden = !problematicKeys;
    const problematicList = document.getElementById("resolveInvalidKeysList");
    problematicList.replaceChildren();

    for (const meta of expiredAccepted) {
      problematicList.appendChild(createKeyRow(meta, false));
    }
    for (const meta of expiredUnaccepted) {
      problematicList.appendChild(createKeyRow(meta, false));
    }

    document.getElementById("resolveViewAcceptKey").onclick = () => {
      this.acceptSelectedKey(recipient, keyMetas);
    };
    this.changeView("resolve");
  },

  async acceptSelectedKey(recipient, keyMetas) {
    const selectedKey = document.querySelector(
      'input[name="valid-key"]:checked'
    )?.value;
    if (!selectedKey) {
      // The accept button was enabled but nothing was selected.
      return;
    }
    let fingerprint;

    this.ignoreExternal = true;

    const existingKey = EnigmailKeyRing.getKeyById(selectedKey);
    if (existingKey) {
      fingerprint = existingKey.fpr;
    } else {
      const unacceptedNotYetImported = keyMetas.filter(
        k => k.readiness == "collected"
      );

      for (const keyMeta of unacceptedNotYetImported) {
        if (keyMeta.keyObj.keyId != selectedKey) {
          continue;
        }
        await EnigmailKeyRing.importKeyDataSilent(
          window,
          keyMeta.collectedKey.pubKey,
          true
        );
        fingerprint = keyMeta.keyObj.fpr;
      }
    }

    if (!fingerprint) {
      throw new Error(`Key not found for id=${selectedKey}`);
    }

    await PgpSqliteDb2.addAcceptedEmail(fingerprint, recipient).catch(
      console.error
    );

    // Trigger the UI refresh of the compose window.
    await checkEncryptionState("openpgp-key-assistant-refresh");

    this.ignoreExternal = false;
    this.resetViews();
    this.buildMainView();
  },

  async initOnlineDiscovery(context) {
    const container = document.getElementById("discoveryOutput");
    container.replaceChildren();

    function write(recipient) {
      const p = document.createElement("p");
      const span = document.createElement("span");
      document.l10n.setAttributes(span, "openpgp-key-assistant-discover-keys", {
        recipient,
      });
      const span2 = document.createElement("span");
      span2.classList.add("loading-inline");
      p.append(span, " ", span2);
      container.appendChild(p);
    }

    let gotNewData = false; // XXX: not used for anything atm

    // Checking gotNewData isn't really sufficient, because the discovery could
    // find an update for an existing key, which was expired, and is now valid
    // again. Let's always rebuild for now.

    if (context == "overview") {
      this.ignoreExternal = true;
      for (const email of this.recipients) {
        if (OpenPGPAlias.hasAliasDefinition(email)) {
          continue;
        }
        write(email);
        const rv = await KeyLookupHelper.fullOnlineDiscovery(
          "silent-collection",
          window,
          email,
          null
        );
        gotNewData = gotNewData || rv;
      }

      // Wait a sec before closing the view, so the user has time to see what
      // happened.
      await new Promise(resolve => setTimeout(resolve, 1000));

      this.resetViews();
      this.buildMainView();

      // Online discovery and key collection triggered key change
      // notifications. We must allow those notifications arrive while
      // ignoreExternal is still true.
      // Use settimeout to reset ignoreExternal to false afterwards.
      setTimeout(function () {
        this.ignoreExternal = false;
      });
      return;
    }

    // We should never arrive here for an email address that has an
    // alias rule, because for those we don't want to perform online
    // discovery.

    if (OpenPGPAlias.hasAliasDefinition(this.currentRecip)) {
      throw new Error(`${this.currentRecip} has an alias rule`);
    }

    write(this.currentRecip);

    this.ignoreExternal = true;
    gotNewData = await KeyLookupHelper.fullOnlineDiscovery(
      "silent-collection",
      window,
      this.currentRecip,
      null
    );
    // Online discovery and key collection triggered key change
    // notifications. We must allow those notifications arrive while
    // ignoreExternal is still true.
    // Use settimeout to reset ignoreExternal to false afterwards.
    setTimeout(function () {
      this.ignoreExternal = false;
    });

    // If the recipient now has a usable previously accepted key, go back to
    // the main view and show a successful notification.
    const keyMetas = await EnigmailKeyRing.getEncryptionKeyMeta(
      this.currentRecip
    );

    if (keyMetas.some(k => k.readiness == "accepted")) {
      // Trigger the UI refresh of the compose window.
      await checkEncryptionState("openpgp-key-assistant-refresh");

      // Wait a sec before closing the view, so the user has time to see what
      // happened.
      await new Promise(resolve => setTimeout(resolve, 1000));
      this.resetViews();
      this.buildMainView();

      let notification =
        this.notificationBox.getNotificationWithValue("acceptedKeyUpdated");

      // If a notification already exists, simply update the message.
      if (notification) {
        document.l10n.setAttributes(
          notification.messageText,
          "openpgp-key-assistant-expired-key-update",
          {
            recipient: this.currentRecip,
          }
        );
        return;
      }

      notification = await this.notificationBox.appendNotification(
        "acceptedKeyUpdated",
        {
          label: {
            "l10n-id": "openpgp-key-assistant-expired-key-update",
            "l10n-args": { recipient: this.currentRecip },
          },
          priority: this.notificationBox.PRIORITY_INFO_HIGH,
        },
        null
      );
      notification.setAttribute("type", "success");
      return;
    }

    this.buildResolveView(this.currentRecip, keyMetas);
    gKeyAssistant.changeView("resolve");
  },

  toggleRecipientsList() {
    const list = document.getElementById("keysListValid");
    list.hidden = !list.hidden;

    document.l10n.setAttributes(
      document.getElementById("toggleRecipientsButton"),
      list.hidden
        ? "openpgp-key-assistant-recipients-show-button"
        : "openpgp-key-assistant-recipients-hide-button"
    );
  },

  async importFromFile(context) {
    await EnigmailCommon_importObjectFromFile("pub");
    if (context == "overview") {
      this.buildMainView();
    } else {
      this.buildResolveView(
        this.currentRecip,
        await EnigmailKeyRing.getEncryptionKeyMeta(this.currentRecip)
      );
    }
  },

  onExternalKeyChange() {
    if (!this.dialog || !this.dialog.open) {
      return;
    }

    if (this.ignoreExternal) {
      return;
    }

    // Refresh the "overview", which will potentially close a currently
    // shown "resolve" view.
    this.resetViews();
    this.buildMainView();
  },
};
