/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 89: the editor for per-recipient rules.
 *
 * The format is `mail.openpgp.alias_rules_file`'s JSON, and this dialog is a
 * view of that file rather than a store beside it -- so what is shown is what
 * the send path reads, and there is one place recipient policy is written
 * down.
 *
 * What it can say, and what it deliberately cannot:
 *
 *   - a rule maps a recipient to keys, and may require or forbid encryption,
 *     signing and PGP/MIME;
 *   - a rule may **not** make a key acceptable. Trust is Item 87's and Item
 *     88's, and a rules file that grew a trust field would be a second trust
 *     store -- the boundary design 15.4 draws.
 *
 * Three settings with three states each: on, off, or "the rule says nothing".
 * The distinction matters and is why they are checkboxes over a companion
 * `unset` flag rather than plain checkboxes: a rule that forbids encryption
 * and a rule that does not mention it are different statements, and a dialog
 * that could not express the second would silently convert every rule it
 * saved into a policy.
 *
 * Reading is lenient and writing is strict. `readRulesForEditing()` returns
 * the entries exactly as the file holds them, including ones the send path
 * ignores, because a rule the user wrote and the build discarded is the first
 * thing they need to see. Saving validates what it writes, because a file the
 * build cannot read is worse than no rule at all.
 */

"use strict";

var { OpenPGPAlias, RuleValue } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/OpenPGPAlias.sys.mjs"
);

/**
 * A synchronous Localization instance, separate from the document's.
 *
 * `document.l10n` is asynchronous, so `formatValueSync` throws on it while its
 * state is async -- which it is as soon as the document starts loading its own
 * bundles. This dialog needs synchronous values because it renders rows in a
 * loop and reports validation failures inline; the same pattern the Key
 * Manager uses, and for the same reason.
 */
var l10n = new Localization(["messenger/openpgp/openpgp.ftl"], true);

/** The rules as last read from the file. Entries are kept verbatim. */
let gRules = [];
/** Index being edited, or -1 when adding. */
let gEditing = -1;
/** Set when the file could not be read; saving is refused while it is. */
let gReadError = null;

window.addEventListener("DOMContentLoaded", onLoad);

async function onLoad() {
  document.getElementById("rulesAdd").addEventListener("command", addRule);
  await reload();
}

/**
 * Re-reads the file and repaints the list.
 */
async function reload() {
  const { rules, error } = await OpenPGPAlias.readRulesForEditing();
  gRules = rules;
  gReadError = error;

  const errorBox = document.getElementById("rulesError");
  errorBox.collapsed = !error;
  if (error) {
    document.getElementById("rulesErrorText").textContent = error;
  }

  renderList();
  updateButtons();
}

/**
 * @param {?boolean} value
 * @returns {string} The localized word for a tri-state setting.
 */
function describe(value) {
  if (value === RuleValue.ALWAYS) {
    return l10n.formatValueSync("openpgp-rules-yes");
  }
  if (value === RuleValue.NEVER) {
    return l10n.formatValueSync("openpgp-rules-no");
  }
  if (value === RuleValue.MAYBE) {
    return l10n.formatValueSync("openpgp-rules-maybe");
  }
  return l10n.formatValueSync("openpgp-rules-unchanged");
}

/**
 * @param {object} rule - One entry from the file.
 * @returns {string} What identifies the rule to a reader.
 */
function recipientLabel(rule) {
  if (typeof rule.email == "string") {
    return rule.email;
  }
  if (typeof rule.domain == "string") {
    return `@${rule.domain}`;
  }
  // A rule with neither is one the loader ignores. It is still shown, because
  // a rule the user wrote and the build discarded is what they came to see.
  return l10n.formatValueSync("openpgp-rules-unidentified");
}

function renderList() {
  const list = document.getElementById("rulesList");
  // Keep the header, drop the rows.
  for (const item of [...list.querySelectorAll("listitem")]) {
    item.remove();
  }

  const doc = list.ownerDocument;
  gRules.forEach((rule, index) => {
    const item = doc.createXULElement("listitem");
    item.setAttribute("data-index", index);
    // The list shows the file's own entries, which hold the words; `describe()`
    // speaks values, so each one goes through the module's single mapping
    // rather than a second one kept here. Two mappings would drift, and the
    // drift would show as a rule that reads correctly in one place and not the
    // other.
    for (const text of [
      recipientLabel(rule),
      describe(OpenPGPAlias._normalizeValue(rule.encrypt)),
      describe(OpenPGPAlias._normalizeValue(rule.sign)),
      describe(OpenPGPAlias._normalizeValue(rule.pgpMime)),
    ]) {
      const cell = doc.createXULElement("listcell");
      cell.setAttribute("label", text);
      item.appendChild(cell);
    }
    list.appendChild(item);
  });
}

function updateButtons() {
  const hasSelection = document.getElementById("rulesList").selectedIndex >= 0;
  document.getElementById("rulesEdit").disabled = !hasSelection;
  document.getElementById("rulesRemove").disabled = !hasSelection;
}

function onRuleSelected() {
  updateButtons();
}

function addRule() {
  gEditing = -1;
  document.getElementById("ruleFormTitle").textContent = l10n.formatValueSync(
    "openpgp-rules-form-add-title"
  );
  document.getElementById("ruleEmail").value = "";
  document.getElementById("ruleKeys").value = "";
  setTriState("ruleEncrypt", null);
  setTriState("ruleSign", null);
  setTriState("rulePgpMime", null);
  document.getElementById("ruleForm").collapsed = false;
  document.getElementById("ruleEmail").focus();
}

function editRule() {
  const index = document.getElementById("rulesList").selectedIndex;
  const rule = gRules[index];
  if (!rule) {
    return;
  }
  gEditing = index;
  document.getElementById("ruleFormTitle").textContent = l10n.formatValueSync(
    "openpgp-rules-form-edit-title",
    {
      recipient: recipientLabel(rule),
    }
  );

  const isDomain =
    typeof rule.email != "string" && typeof rule.domain == "string";
  document.getElementById("ruleEmail").value = isDomain
    ? `@${rule.domain}`
    : (rule.email ?? "");

  const keys = Array.isArray(rule.keys) ? rule.keys : [];
  document.getElementById("ruleKeys").value = keys
    .map(entry => entry.fingerprint ?? entry.id ?? "")
    .filter(Boolean)
    .join("\n");

  setTriState("ruleEncrypt", triValue(rule.encrypt));
  setTriState("ruleSign", triValue(rule.sign));
  setTriState("rulePgpMime", triValue(rule.pgpMime));

  document.getElementById("ruleForm").collapsed = false;
}

/**
 * @param {*} value - Whatever the file held.
 * @returns {?boolean} A boolean, or null when the field said nothing.
 */
function triValue(value) {
  return typeof value == "number" ? value : null;
}

/**
 * Sets one of the three-state settings.
 *
 * @param {string} id - The menulist.
 * @param {?boolean} value - true, false, or null for "says nothing".
 */
function setTriState(id, value) {
  const list = document.getElementById(id);
  let wanted = "unset";
  if (value === RuleValue.ALWAYS) {
    wanted = "yes";
  } else if (value === RuleValue.NEVER) {
    wanted = "no";
  } else if (value === RuleValue.MAYBE) {
    wanted = "maybe";
  }
  list.value = wanted;
}

/**
 * @param {string} id - The menulist.
 * @returns {?boolean}
 */
function getTriState(id) {
  const value = document.getElementById(id).value;
  if (value == "yes") {
    return RuleValue.ALWAYS;
  }
  if (value == "no") {
    return RuleValue.NEVER;
  }
  if (value == "maybe") {
    return RuleValue.MAYBE;
  }
  return null;
}

function cancelRule() {
  document.getElementById("ruleForm").collapsed = true;
  gEditing = -1;
}

/**
 * Validates and stores the rule being edited, then writes the file.
 *
 * A rule may name no key (Item 89a): "never encrypt to this address" is a
 * complete rule carried by its settings alone. The dialog used to refuse that,
 * which is why the one rule a cautious user most wants could not be written
 * here.
 */
async function saveRule() {
  const raw = document.getElementById("ruleEmail").value.trim();
  const keyText = document.getElementById("ruleKeys").value.trim();

  if (!raw) {
    report("openpgp-rules-error-recipient-required");
    return;
  }
  // A rule may name no key. "Never encrypt to this address" is the rule a
  // cautious user most wants, and it is carried entirely by the settings; the
  // absence of a key is not an incomplete rule but a complete one of a
  // different kind.

  const isDomain = raw.startsWith("@");
  const recipient = isDomain ? raw.slice(1).toLowerCase() : raw.toLowerCase();
  if (isDomain ? recipient.includes("@") : !recipient.includes("@")) {
    report(
      isDomain
        ? "openpgp-rules-error-domain-invalid"
        : "openpgp-rules-error-email-invalid"
    );
    return;
  }

  const keys = keyText
    .split(/[\s,]+/)
    .filter(Boolean)
    .map(entry => {
      const cleaned = entry.replace(/^0x/i, "");
      // A fingerprint is 32, 40 or 64 hex digits; anything shorter is a key
      // id, which this format also accepts.
      return cleaned.length > 16
        ? { fingerprint: cleaned.toUpperCase() }
        : { id: cleaned.toUpperCase() };
    });

  const rule = { [isDomain ? "domain" : "email"]: recipient, keys };
  const encrypt = getTriState("ruleEncrypt");
  const sign = getTriState("ruleSign");
  const pgpMime = getTriState("rulePgpMime");
  // Absent rather than null: a field the rule does not mention is a field the
  // file should not mention either, so a later reader cannot mistake an
  // explicit false for the default.
  // Words in the file, per Item 89b: it is a format users are expected to
  // edit by hand, and `"always"` survives a round trip through a text editor
  // where `2` invites a guess.
  const asWord = value => {
    if (value === RuleValue.ALWAYS) {
      return "always";
    }
    if (value === RuleValue.NEVER) {
      return "never";
    }
    if (value === RuleValue.MAYBE) {
      return "maybe";
    }
    return null;
  };
  const encryptWord = asWord(encrypt);
  const signWord = asWord(sign);
  const pgpMimeWord = asWord(pgpMime);
  if (encryptWord !== null) {
    rule.encrypt = encryptWord;
  }
  if (signWord !== null) {
    rule.sign = signWord;
  }
  if (pgpMimeWord !== null) {
    rule.pgpMime = pgpMimeWord;
  }

  // One rule per recipient: a duplicate key in the file is ignored by the
  // loader, so writing one would look like it had taken effect and not.
  const clash = gRules.findIndex((existing, index) => {
    if (index == gEditing) {
      return false;
    }
    const value =
      typeof existing.email == "string" ? existing.email : existing.domain;
    const otherIsDomain = typeof existing.email != "string";
    return (
      typeof value == "string" &&
      value.toLowerCase() == recipient &&
      otherIsDomain == isDomain
    );
  });
  if (clash != -1) {
    report("openpgp-rules-error-duplicate", { recipient: raw });
    return;
  }

  if (gEditing == -1) {
    gRules.push(rule);
  } else {
    gRules[gEditing] = rule;
  }

  await persist();
}

/**
 * Asks before removing, because the file has no undo.
 */
async function removeRule() {
  const index = document.getElementById("rulesList").selectedIndex;
  const rule = gRules[index];
  if (!rule) {
    return;
  }

  const confirmed = Services.prompt.confirm(
    window,
    null,
    l10n.formatValueSync("openpgp-rules-confirm-remove", {
      recipient: recipientLabel(rule),
    })
  );
  if (!confirmed) {
    return;
  }

  gRules.splice(index, 1);
  await persist();
}

/**
 * Writes the rules and reports failure rather than assuming success.
 */
async function persist() {
  if (gReadError) {
    // Saving now would overwrite a file this dialog could not read, which is
    // the one way an editor loses data the user never saw.
    report("openpgp-rules-error-read-failed");
    return;
  }

  const result = await OpenPGPAlias.writeRules(gRules);
  if (!result.ok) {
    report("openpgp-rules-error-write-failed", { error: result.error });
    return;
  }

  document.getElementById("ruleForm").collapsed = true;
  gEditing = -1;
  await reload();
}

/**
 * @param {string} l10nId
 * @param {object} [args]
 */
function report(l10nId, args) {
  const text = args
    ? l10n.formatValueSync(l10nId, args)
    : l10n.formatValueSync(l10nId);
  Services.prompt.alert(window, null, text);
}
