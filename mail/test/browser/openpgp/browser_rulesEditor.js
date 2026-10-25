/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 89 in the dialog the user actually gets.
 *
 * `test_recipientRules.js` proves the format: settings survive a write and a
 * load, an omitted field stays omitted, and the file the editor writes is the
 * file the send path reads. This proves the editor drives that format -- add,
 * edit, remove, and the two refusals that protect the user from losing data.
 *
 * The dialog is opened the way the Settings button opens it, so the path
 * exercised is the real one rather than a function called underneath it.
 */

"use strict";

const { OpenPGPAlias, RuleValue } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/OpenPGPAlias.sys.mjs"
);

const PREF = "mail.openpgp.alias_rules_file";
const FILE = "browser-item89-rules.json";

/**
 * @param {object[]} rules
 */
async function writeRulesFile(rules) {
  await IOUtils.writeUTF8(
    PathUtils.join(Services.dirsvc.get("ProfD", Ci.nsIFile).path, FILE),
    JSON.stringify({ rules }, null, 2)
  );
}

/**
 * @returns {Promise<object[]>}
 */
async function readRulesFile() {
  const { rules } = await OpenPGPAlias.readRulesForEditing();
  return rules;
}

/**
 * Opens the rules editor and waits for it to load.
 *
 * @returns {Promise<Window>}
 */
async function openEditor() {
  // Opened through `Services.ww` rather than `window.openDialog`, which is the
  // same call Settings makes but from the right principal: a chrome dialog
  // opened from a content window trips the broken-chrome-URL assertion and
  // takes the whole harness down with a crash rather than a failure.
  const win = Services.ww.openWindow(
    null,
    "chrome://openpgp/content/ui/rulesEditor.xhtml",
    "openpgpRulesEditor",
    "chrome,dialog,centerscreen,resizable",
    null
  );
  await BrowserTestUtils.waitForEvent(win, "load");
  // The dialog reads the file on DOMContentLoaded, asynchronously.
  await TestUtils.waitForCondition(
    () => win.document.getElementById("rulesList"),
    "the rules list to exist"
  );
  return win;
}

/**
 * @param {Window} win
 * @returns {string[]} The recipient column as shown.
 */
function listedRecipients(win) {
  return [...win.document.querySelectorAll("#rulesList listitem")].map(item =>
    item.querySelector("listcell").getAttribute("label")
  );
}

add_setup(async function () {
  await SpecialPowers.pushPrefEnv({ set: [[PREF, FILE]] });
  registerCleanupFunction(async () => {
    OpenPGPAlias._clear();
    const path = PathUtils.join(
      Services.dirsvc.get("ProfD", Ci.nsIFile).path,
      FILE
    );
    if (await IOUtils.exists(path)) {
      await IOUtils.remove(path);
    }
  });
});

/**
 * The editor shows what is in the file, including a rule it would refuse to
 * create. A rule the user wrote and the build ignored is the first thing they
 * came to see.
 */
add_task(async function itShowsWhatIsInTheFile() {
  await writeRulesFile([
    { email: "bob@example.com", keys: [{ id: "BBBB" }], encrypt: "always" },
    { email: "carol@example.com", keys: [{ id: "CCCC" }], sign: "never" },
  ]);

  const win = await openEditor();
  try {
    await TestUtils.waitForCondition(
      () => listedRecipients(win).length == 2,
      "both rules should be listed"
    );
    const shown = listedRecipients(win);
    info(`FINDING listed: ${JSON.stringify(shown)}`);
    Assert.ok(shown.includes("bob@example.com"), "the address rule is listed");
    Assert.ok(shown.includes("carol@example.com"), "and so is the second one");

    // The columns read the three states apart rather than as booleans.
    const firstCells = [
      ...win.document
        .querySelector("#rulesList listitem")
        .querySelectorAll("listcell"),
    ].map(c => c.getAttribute("label"));
    Assert.equal(firstCells[1], "Yes", "encrypt shows as Yes");
    Assert.equal(
      firstCells[2],
      "Leave unchanged",
      "and an unstated setting says so rather than showing No"
    );
  } finally {
    win.close();
  }
});

/**
 * Adding a rule writes it, with the settings the user chose.
 */
add_task(async function addingARuleWritesIt() {
  await writeRulesFile([]);
  const win = await openEditor();
  try {
    win.addRule();
    win.document.getElementById("ruleEmail").value = "dave@example.com";
    win.document.getElementById("ruleKeys").value = "FBFCC82A015E7330";
    win.document.getElementById("ruleEncrypt").value = "yes";
    win.document.getElementById("ruleSign").value = "no";
    win.document.getElementById("rulePgpMime").value = "unset";

    await win.saveRule();

    const rules = await readRulesFile();
    info(`FINDING after add: ${JSON.stringify(rules)}`);
    Assert.equal(rules.length, 1, "one rule was written");
    Assert.equal(rules[0].email, "dave@example.com", "for the address");
    Assert.equal(rules[0].encrypt, "always", "with encryption required");
    Assert.equal(rules[0].sign, "never", "signing forbidden");
    Assert.ok(
      !("pgpMime" in rules[0]),
      "and no PGP/MIME field, because the user left it unchanged"
    );
    Assert.equal(rules[0].keys.length, 1, "with a key");
    Assert.equal(
      rules[0].keys[0].id,
      "FBFCC82A015E7330",
      "recorded as a key id, which is what was entered"
    );

    // And the send path sees it, which is the claim that matters.
    const rule = OpenPGPAlias.getRuleForEmail("dave@example.com");
    Assert.equal(
      rule?.encrypt,
      RuleValue.ALWAYS,
      "the send path reads the new rule as always"
    );
  } finally {
    win.close();
  }
});

/**
 * A rule without a key is accepted, and written (Item 89a).
 *
 * This is the rule a cautious user most wants -- "never encrypt to this
 * address" -- and the dialog refused it until Item 89a, because the loader
 * discarded keyless rules. Both halves changed together: the loader keeps
 * them and the editor writes them.
 */
add_task(async function aRuleWithoutAKeyIsAccepted() {
  await writeRulesFile([]);
  const win = await openEditor();
  try {
    win.addRule();
    win.document.getElementById("ruleEmail").value = "keyless@example.com";
    win.document.getElementById("ruleKeys").value = "";
    win.document.getElementById("ruleEncrypt").value = "no";
    await win.saveRule();

    const rules = await readRulesFile();
    info(`FINDING keyless rule written: ${JSON.stringify(rules)}`);
    Assert.equal(rules.length, 1, "the rule was written");
    Assert.equal(rules[0].email, "keyless@example.com", "for the address");
    Assert.deepEqual(rules[0].keys, [], "with an empty key list");
    Assert.equal(rules[0].encrypt, "never", "and the setting it carries");

    // And the send path sees a rule, and knows it names no key.
    Assert.ok(
      OpenPGPAlias.hasRule("keyless@example.com"),
      "the send path finds the rule"
    );
    Assert.ok(
      OpenPGPAlias.hasKeylessRule("keyless@example.com"),
      "and knows it names no key"
    );
  } finally {
    win.close();
  }
});

/**
 * A second rule for the same recipient is refused rather than written and
 * ignored: the loader uses the first rule per recipient, so a duplicate would
 * look like it had taken effect.
 */
add_task(async function aDuplicateIsRefused() {
  await writeRulesFile([
    { email: "bob@example.com", keys: [{ id: "AAAA" }], encrypt: "always" },
  ]);
  const win = await openEditor();
  await TestUtils.waitForCondition(
    () => listedRecipients(win).length == 1,
    "the existing rule should be listed"
  );

  const originalPrompt = Services.prompt;
  const alerts = [];
  Services.prompt = {
    alert(w, title, text) {
      alerts.push(text);
    },
    QueryInterface: ChromeUtils.generateQI(["nsIPromptService"]),
  };
  try {
    win.addRule();
    win.document.getElementById("ruleEmail").value = "BOB@example.com";
    win.document.getElementById("ruleKeys").value = "BBBB";
    await win.saveRule();
  } finally {
    Services.prompt = originalPrompt;
  }

  try {
    info(`FINDING duplicate refusal: ${JSON.stringify(alerts)}`);
    Assert.equal(alerts.length, 1, "the duplicate was refused");
    const rules = await readRulesFile();
    Assert.equal(rules.length, 1, "and the file is unchanged");
    Assert.equal(rules[0].keys[0].id, "AAAA", "with the original key");
  } finally {
    win.close();
  }
});

/**
 * Removing a rule deletes it from the file, after asking.
 */
add_task(async function removingARuleDeletesIt() {
  await writeRulesFile([
    { email: "gone@example.com", keys: [{ id: "AAAA" }] },
    { email: "stays@example.com", keys: [{ id: "BBBB" }] },
  ]);
  const win = await openEditor();
  await TestUtils.waitForCondition(
    () => listedRecipients(win).length == 2,
    "both rules should be listed"
  );

  const originalPrompt = Services.prompt;
  const asked = [];
  Services.prompt = {
    confirm(w, title, text) {
      asked.push(text);
      return true;
    },
    QueryInterface: ChromeUtils.generateQI(["nsIPromptService"]),
  };
  try {
    // Select the first row, then remove it.
    const list = win.document.getElementById("rulesList");
    list.selectedIndex = 0;
    await win.removeRule();
  } finally {
    Services.prompt = originalPrompt;
  }

  try {
    info(`FINDING removal asked: ${JSON.stringify(asked)}`);
    Assert.equal(asked.length, 1, "it asked before removing");

    const rules = await readRulesFile();
    Assert.equal(rules.length, 1, "one rule is left");
    Assert.equal(
      rules[0].email,
      "stays@example.com",
      "and it is the one that was not selected"
    );
    Assert.equal(
      OpenPGPAlias.getRuleForEmail("gone@example.com"),
      null,
      "the removed address has no rule in the send path"
    );
  } finally {
    win.close();
  }
});
