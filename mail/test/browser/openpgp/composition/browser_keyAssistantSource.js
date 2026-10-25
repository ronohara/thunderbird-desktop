/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 80 in the window the user actually sees.
 *
 * `openpgp-key-assistant-key-collected-gnupg` existed as a localized string
 * with no producer. The module test (`test_keyOriginSource.js`) checks that a
 * candidate key GnuPG holds now carries a `gnupg` source; this checks that the
 * Key Assistant *says* it, which is the claim the item makes.
 *
 * Two cases, because an origin that appeared for everything would be as
 * misleading as one that never appeared:
 *
 *   - a key only GnuPG holds  -> "GnuPG keyring", and the note saying it is
 *     the only copy rather than one of several;
 *   - a key collected from an attachment -> "email attachment", and not GnuPG.
 *
 * The collected record is stored through `CollectedKeysDB.storeKey()` here,
 * and not in the module test, because that method dispatches its change event
 * on the most recent `mail:3pane` window -- which exists in a browser test and
 * does not in xpcshell.
 */

"use strict";

const { close_compose_window, open_compose_new_mail } =
  ChromeUtils.importESModule(
    "resource://testing-common/mail/ComposeHelpers.sys.mjs"
  );
const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);
const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { CollectedKeysDB } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/CollectedKeysDB.sys.mjs"
);
const { Subprocess } = ChromeUtils.importESModule(
  "resource://gre/modules/Subprocess.sys.mjs"
);

const keyDir = "../data/keys";

const GNUPG_ADDRESS = "alice@openpgp.example";
const GNUPG_SECRET_FILE = "alice@openpgp.example-0xf231550c4f47e38e-secret.asc";
const ATTACHMENT_ADDRESS = "bob@openpgp.example";
const ATTACHMENT_PUBLIC_FILE = "bob@openpgp.example-0xfbfcc82a015e7330-pub.asc";

let gpgPath = null;
let gnupgHome = null;
let externalAvailable = false;

/**
 * @param {string[]} args
 * @returns {Promise<{exitCode: integer, stdout: string, stderr: string}>}
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
  const { exitCode } = await process.wait();
  return { exitCode, stdout, stderr };
}

/**
 * Opens a compose window and asks the key assistant about one recipient.
 *
 * `show()` is the composer's own entry point, so this follows the path a user
 * reaches rather than a helper beneath it.
 *
 * @param {string} address
 * @returns {Promise<{win: Window, doc: Document}>}
 */
async function askAbout(address) {
  const win = await open_compose_new_mail();
  const doc = win.document;
  win.gKeyAssistant.show([address], false);
  await TestUtils.waitForCondition(
    () => doc.getElementById("keyAssistant")?.open,
    "the key assistant should open"
  );
  return { win, doc };
}

add_setup(async function () {
  requestLongerTimeout(3);

  const account = MailServices.accounts.createAccount();
  account.incomingServer = MailServices.accounts.createIncomingServer(
    "origin",
    "origin.example",
    "imap"
  );
  const identity = MailServices.accounts.createIdentity();
  identity.email = "origin@origin.example";
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

  try {
    gpgPath = await Subprocess.pathSearch("gpg");
  } catch (ex) {
    info("No gpg executable found; the GnuPG origin cannot be shown here.");
    return;
  }

  // `do_get_tempdir()` is xpcshell-only; a browser test writes beside the
  // profile, which is its own throwaway directory.
  gnupgHome = Services.dirsvc.get("ProfD", Ci.nsIFile);
  gnupgHome.append("gnupg-origin-ui");
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

  const { exitCode, stderr } = await runGpg([
    "--import",
    new FileUtils.File(getTestFilePath(`${keyDir}/${GNUPG_SECRET_FILE}`)).path,
  ]);
  if (exitCode) {
    info(`gpg could not import the fixture key: ${stderr}`);
    return;
  }
  externalAvailable = true;
});

/**
 * The assistant names GnuPG, and says that is the only copy.
 */
add_task(async function theAssistantNamesGnuPG() {
  if (!externalAvailable) {
    info("SKIPPED: no external GnuPG on this machine.");
    return;
  }

  EnigmailKeyRing.clearGnuPgKeyCache();
  const { win, doc } = await askAbout(GNUPG_ADDRESS);
  try {
    const list = doc.getElementById("keysListValid");
    await TestUtils.waitForCondition(
      () => list.textContent.includes("GnuPG"),
      "the assistant should name GnuPG"
    );

    const text = list.textContent;
    info(
      `FINDING: the assistant says "${text}" across ` +
        `${list.querySelectorAll(".key-row").length} row(s)`
    );
    Assert.ok(
      text.includes("GnuPG keyring"),
      `the source string finally has a producer, got "${text}"`
    );
    Assert.ok(
      text.includes("the only copy"),
      "and says it is the only copy, because Item 10 means there is no " +
        "second one in the profile"
    );
  } finally {
    await close_compose_window(win);
  }
});

/**
 * A key collected from an attachment is attributed to the attachment, and the
 * word GnuPG does not appear -- the negative half of the claim.
 */
add_task(async function aCollectedKeyIsNotCalledGnuPG() {
  const pubKey = await IOUtils.readUTF8(
    new FileUtils.File(getTestFilePath(`${keyDir}/${ATTACHMENT_PUBLIC_FILE}`))
      .path
  );
  const keys = await RNP.getKeyListFromKeyBlockImpl(pubKey);
  Assert.equal(keys.length, 1, "the fixture is a single key");

  const collDB = await CollectedKeysDB.getInstance();
  registerCleanupFunction(() => collDB.deleteKey(keys[0].fpr));
  await collDB.storeKey(
    await collDB.mergeExisting(keys[0], pubKey, {
      uri: "mid:item80@example",
      type: "attachment",
      description: "bob.asc",
    })
  );

  EnigmailKeyRing.clearCache();
  const { win, doc } = await askAbout(ATTACHMENT_ADDRESS);
  try {
    // A collected key has not been accepted, so the main view reports it as an
    // issue and offers "Resolve…". The origin is drawn in the resolve view --
    // which is the view a user reaches when asking what to do about a key, and
    // therefore the honest place to read the answer.
    const issues = doc.getElementById("keysListIssues");
    await TestUtils.waitForCondition(
      () => issues.querySelector("button"),
      "the assistant should offer to resolve the collected key"
    );
    issues.querySelector("button").click();

    const list = doc.getElementById("resolveValidKeysList");
    await TestUtils.waitForCondition(
      () => doc.getElementById("resolveView").hidden === false,
      "the resolve view should open"
    );
    await TestUtils.waitForCondition(
      () => list.textContent.includes("attachment"),
      "the assistant should name the attachment"
    );

    const text = list.textContent;
    info(`FINDING: the resolve view says "${text}"`);
    Assert.ok(
      text.includes("email attachment"),
      `the collected source is named, got "${text}"`
    );
    Assert.ok(
      !text.includes("GnuPG"),
      "and GnuPG is not claimed for a key it does not hold"
    );
  } finally {
    await close_compose_window(win);
  }
});
