/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 88 in the two dialogs that name the concept.
 *
 * The Key Manager gains a Set Owner Trust submenu. For a key GnuPG holds the
 * write goes to gpg's own trust database; for a key in this profile it opens
 * the acceptance editor, because that is where this build stores the same
 * fact and a second way to change it would be a second mechanism.
 *
 * The write itself is verified against gpg in `test_ownerTrust.js`, where the
 * value can be read out of gpg's own listing. This file is about the routing
 * and about the two dialogs agreeing on what the setting is called.
 */

"use strict";

const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { Subprocess } = ChromeUtils.importESModule(
  "resource://gre/modules/Subprocess.sys.mjs"
);
const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);

const KEY_DIR = "data/keys/";
const EXTERNAL_KEY_ID = "F231550C4F47E38E";
const EXTERNAL_SECRET = "alice@openpgp.example-0xf231550c4f47e38e-secret.asc";
const INTERNAL_KEY_ID = "FBFCC82A015E7330";
const INTERNAL_SECRET = "bob@openpgp.example-0xfbfcc82a015e7330-secret.asc";

let gpgPath = null;
let gnupgHome = null;
let externalAvailable = false;

/**
 * @param {string[]} args
 * @returns {Promise<string>} stdout+stderr.
 */
async function runGpg(args) {
  const process = await Subprocess.call({
    command: gpgPath,
    arguments: ["--batch", "--no-tty", "--yes", ...args],
    environment: { GNUPGHOME: gnupgHome.path },
    environmentAppend: true,
    stdout: "pipe",
    stderr: "pipe",
  });
  const stdout = await process.stdout.readString();
  const stderr = await process.stderr.readString();
  await process.wait();
  return stdout + stderr;
}

/**
 * The ownertrust letter gpg records for a key, from its own listing.
 *
 * @param {string} keyId
 * @returns {Promise<string>}
 */
async function gpgOwnertrust(keyId) {
  const out = await runGpg(["--with-colons", "--list-keys", `0x${keyId}`]);
  for (const line of out.split("\n")) {
    const f = line.split(":");
    if (f[0] === "pub") {
      return f[8] ?? "";
    }
  }
  return "";
}

/**
 * Opens the Key Manager and waits for its list.
 *
 * @returns {Promise<Window>}
 */
async function openKeyManager() {
  const win = Services.ww.openWindow(
    null,
    "chrome://openpgp/content/ui/enigmailKeyManager.xhtml",
    "_blank",
    "chrome,dialog,centerscreen,resizable",
    null
  );
  await BrowserTestUtils.waitForEvent(win, "load");
  await TestUtils.waitForCondition(
    () => win.gKeyListView?.rowCount > 0,
    "the manager should populate its list"
  );
  return win;
}

/**
 * Selects the row for a key id.
 *
 * @param {Window} win - The Key Manager window.
 * @param {string} keyId
 * @returns {boolean} Whether the row was found and selected.
 */
function selectKey(win, keyId) {
  const view = win.gKeyListView;
  for (let i = 0; i < view.rowCount; i++) {
    const r = view.getFilteredRow(i);
    if (r?.rowType != "key") {
      continue;
    }
    if (win.gKeyList[r.keyNum].keyId.toUpperCase() != keyId.toUpperCase()) {
      continue;
    }
    win.gUserList.view.selection.select(i);
    return true;
  }
  return false;
}

add_setup(async function () {
  requestLongerTimeout(3);

  const account = MailServices.accounts.createAccount();
  account.incomingServer = MailServices.accounts.createIncomingServer(
    "trust",
    "trust.example",
    "pop3"
  );
  const identity = MailServices.accounts.createIdentity();
  identity.email = "trust@trust.example";
  account.addIdentity(identity);
  registerCleanupFunction(() =>
    MailServices.accounts.removeAccount(account, true)
  );

  await SpecialPowers.pushPrefEnv({
    set: [
      ["mail.openpgp.allow_external_gnupg", true],
      ["mail.openpgp.fetch_pubkeys_from_gnupg", true],
    ],
  });

  // The menu entry is markup, so it is asserted whether or not gpg exists.
  const win = await openKeyManager();
  try {
    const menu = win.document.getElementById("ctxOwnerTrust");
    Assert.ok(menu, "the context menu carries a Set Owner Trust entry");
    // The popup is looked up in the document, not as `menu.children`: Fluent
    // replaces an element's children when it applies a message with a value,
    // which is why the menu's own message is attribute-only. This query would
    // catch a regression to a value message, because the popup would vanish.
    const popup = win.document.getElementById("ctxOwnerTrustPopup");
    Assert.ok(popup, "the entry has a popup");
    const items = popup.querySelectorAll("menuitem");
    info(`FINDING menu: items=${items.length}`);
    Assert.equal(items.length, 5, "with the five levels gpg can store");
    Assert.equal(
      menu.querySelectorAll(
        'menuitem[data-l10n-id="openpgp-key-man-owner-trust-unknown"]'
      ).length,
      0,
      "and none for unknown, which gpg's ownertrust scale cannot express"
    );
  } finally {
    win.close();
  }

  try {
    gpgPath = await Subprocess.pathSearch("gpg");
  } catch (ex) {
    info("No gpg executable found; the write cannot be exercised here.");
    return;
  }

  gnupgHome = Services.dirsvc.get("ProfD", Ci.nsIFile);
  gnupgHome.append("gnupg-ownertrust-ui");
  gnupgHome.createUnique(Ci.nsIFile.DIRECTORY_TYPE, 0o700);
  const previousHome = Services.env.exists("GNUPGHOME")
    ? Services.env.get("GNUPGHOME")
    : "";
  Services.env.set("GNUPGHOME", gnupgHome.path);
  registerCleanupFunction(async () => {
    try {
      const gpgconfPath = await Subprocess.pathSearch("gpgconf");
      const process = await Subprocess.call({
        command: gpgconfPath,
        arguments: ["--kill", "all"],
        environment: { GNUPGHOME: gnupgHome.path },
        environmentAppend: true,
        stderr: "pipe",
      });
      await process.stderr.readString();
      await process.wait();
    } catch (ex) {
      info(`Could not stop gpg-agent: ${ex.message}`);
    }
    Services.env.set("GNUPGHOME", previousHome);
    gnupgHome.remove(true);
  });

  await runGpg([
    "--import",
    new FileUtils.File(getTestFilePath(`${KEY_DIR}/${EXTERNAL_SECRET}`)).path,
  ]);
  externalAvailable = true;
});

/**
 * Choosing a level for a key GnuPG holds writes to gpg's trust database.
 *
 * The value is read back out of gpg's own listing rather than from Thunderbird,
 * because the claim is that gpg is the authority -- asking our own cache would
 * pass even if the two agreed on something gpg had never stored.
 */
add_task(async function choosingALevelWritesToGpg() {
  if (!externalAvailable) {
    info("SKIPPED: no external GnuPG on this machine.");
    return;
  }

  EnigmailKeyRing.clearCache();
  EnigmailKeyRing.clearGnuPgKeyCache();

  const win = await openKeyManager();
  try {
    Assert.ok(
      selectKey(win, EXTERNAL_KEY_ID),
      "the keyring-only key has a row to select"
    );

    await win.enigmailSetOwnerTrust("full");
    const letters = ["q", "n", "m", "f", "u"];
    // The write is asynchronous and the row refresh follows it.
    await TestUtils.waitForCondition(
      async () => {
        const letter = await gpgOwnertrust(EXTERNAL_KEY_ID);
        return letter === "f";
      },
      "gpg to record full trust",
      100,
      60
    );
    info(
      `FINDING after choosing "full": gpg records ` +
        `"${await gpgOwnertrust(EXTERNAL_KEY_ID)}"`
    );
    Assert.ok(
      letters.includes(await gpgOwnertrust(EXTERNAL_KEY_ID)),
      "and the value is one of gpg's own levels"
    );

    await win.enigmailSetOwnerTrust("never");
    await TestUtils.waitForCondition(
      async () => (await gpgOwnertrust(EXTERNAL_KEY_ID)) === "n",
      "gpg to record never trust",
      100,
      60
    );
  } finally {
    win.close();
  }
});

/**
 * Choosing a level for a key in this profile points at the acceptance editor
 * rather than opening a second way to change the same fact.
 */
add_task(async function anInternalKeyRoutesToTheAcceptanceEditor() {
  await OpenPGPTestUtils.importPrivateKey(
    window,
    new FileUtils.File(getTestFilePath(`${KEY_DIR}/${INTERNAL_SECRET}`))
  );
  EnigmailKeyRing.clearCache();
  EnigmailKeyRing.clearGnuPgKeyCache();

  const win = await openKeyManager();
  const originalPrompt = Services.prompt;
  const alerts = [];
  Services.prompt = {
    alert(w, title, text) {
      alerts.push(text);
    },
    QueryInterface: ChromeUtils.generateQI(["nsIPromptService"]),
  };
  // Key Details is modal, so the call is stubbed rather than allowed to open a
  // window that would block this task until the test budget ran out.
  const opened = [];
  const originalDetails = win.enigmailKeyDetails;
  win.enigmailKeyDetails = keyId => {
    opened.push(keyId);
  };

  try {
    Assert.ok(selectKey(win, INTERNAL_KEY_ID), "the profile key has a row");

    await win.enigmailSetOwnerTrust("full");

    info(`FINDING internal routing: opened=${JSON.stringify(opened)}`);
    Assert.equal(opened.length, 1, "it opened the acceptance editor");
    Assert.equal(
      opened[0].toUpperCase(),
      INTERNAL_KEY_ID,
      "for the key that was selected"
    );
    Assert.equal(alerts.length, 1, "and said why it was routing there");
    Assert.ok(
      alerts[0].includes("acceptance"),
      `naming the setting the two dialogs share, got ${JSON.stringify(alerts[0])}`
    );
  } finally {
    Services.prompt = originalPrompt;
    win.enigmailKeyDetails = originalDetails;
    win.close();
  }
});
