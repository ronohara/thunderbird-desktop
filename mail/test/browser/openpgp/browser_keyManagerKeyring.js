/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 81a: the Key Manager shows the keys that live only in GnuPG.
 *
 * The dialog a user opens to find out where a key lives could not show the
 * keys that live outside the profile: `loadKeyList()` was built from
 * `RNP.getKeys()` alone, so a key held by GnuPG was absent from the list
 * entirely. The mechanism to find those keys already existed for the composer
 * and the assistant (per address); this adds the whole-keyring variant and the
 * manager's use of it.
 *
 * Three claims, and the third is the one the item says matters most -- "a list
 * that grows but whose rows do nothing is worse than the silence it replaced":
 *
 *   - the row is present;
 *   - it is marked external;
 *   - an operation that would act on the profile refuses, and says why.
 *
 * The profile holds no key for the fixture, so a row for it can only have come
 * from GnuPG. The negative half is a second test: a key the profile *does*
 * hold must not be marked, or the mark would mean nothing.
 */

"use strict";

const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
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

const keyDir = "data/keys";
const EXTERNAL_SECRET_FILE =
  "alice@openpgp.example-0xf231550c4f47e38e-secret.asc";
const EXTERNAL_KEY_ID = "F231550C4F47E38E";

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
 * The rows the manager is showing, as `{keyId, marked}`.
 *
 * Read through the view the dialog itself uses, so the answer is what the user
 * sees rather than what the module holds.
 *
 * @param {Window} win - The Key Manager window.
 * @returns {object[]}
 */
function managerRows(win) {
  const view = win.gKeyListView;
  const rows = [];
  for (let i = 0; i < view.rowCount; i++) {
    const r = view.getFilteredRow(i);
    if (r?.rowType != "key") {
      continue;
    }
    const keyObj = win.gKeyList[r.keyNum];
    rows.push({
      keyId: keyObj.keyId.toUpperCase(),
      marked: !!view.getImageSrc(i, { id: "enigUserNameCol" }),
    });
  }
  return rows;
}

add_setup(async function () {
  requestLongerTimeout(3);

  const account = MailServices.accounts.createAccount();
  account.incomingServer = MailServices.accounts.createIncomingServer(
    "manager",
    "manager.example",
    "pop3"
  );
  const identity = MailServices.accounts.createIdentity();
  identity.email = "manager@manager.example";
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

  // True whether or not gpg is installed, and the precondition the whole file
  // rests on: if the profile already held this key, a row for it would prove
  // nothing about the keyring. Asserted before the gpg guard so the file has a
  // real check even where gpg is absent.
  EnigmailKeyRing.clearCache();
  Assert.equal(
    EnigmailKeyRing.getKeyById(EXTERNAL_KEY_ID),
    null,
    "the profile holds no key for the fixture"
  );

  try {
    gpgPath = await Subprocess.pathSearch("gpg");
  } catch (ex) {
    info("No gpg executable found; the keyring cannot be listed here.");
    return;
  }

  gnupgHome = Services.dirsvc.get("ProfD", Ci.nsIFile);
  gnupgHome.append("gnupg-manager");
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
    new FileUtils.File(getTestFilePath(`${keyDir}/${EXTERNAL_SECRET_FILE}`))
      .path,
  ]);
  if (exitCode) {
    info(`gpg could not import the fixture key: ${stderr}`);
    return;
  }

  externalAvailable = true;
});

/**
 * A key only GnuPG holds appears in the manager, marked, and its
 * profile-scoped operations are refused rather than failing silently.
 */
add_task(async function theManagerShowsAndMarksAKeyringOnlyKey() {
  if (!externalAvailable) {
    info("SKIPPED: no external GnuPG on this machine.");
    return;
  }

  EnigmailKeyRing.clearCache();
  EnigmailKeyRing.clearGnuPgKeyCache();

  const win = Services.ww.openWindow(
    null,
    "chrome://openpgp/content/ui/enigmailKeyManager.xhtml",
    "_blank",
    "chrome,dialog,centerscreen,resizable",
    null
  );
  await BrowserTestUtils.waitForEvent(win, "load");
  registerCleanupFunction(() => {
    if (!win.closed) {
      win.close();
    }
  });

  await TestUtils.waitForCondition(
    () => win.gKeyListView?.rowCount > 0,
    "the manager should populate its list"
  );

  const rows = managerRows(win);
  info(`FINDING: the manager shows ${JSON.stringify(rows)}`);

  const external = rows.find(r => r.keyId == EXTERNAL_KEY_ID);
  Assert.ok(
    external,
    "the keyring's key is in the list at all, which it was not"
  );
  Assert.ok(external.marked, "and it is marked as coming from elsewhere");

  // The refusal: selecting it and asking to delete must not reach the ring.
  const view = win.gKeyListView;
  let rowIndex = -1;
  for (let i = 0; i < view.rowCount; i++) {
    const r = view.getFilteredRow(i);
    if (
      r?.rowType == "key" &&
      win.gKeyList[r.keyNum].keyId == EXTERNAL_KEY_ID
    ) {
      rowIndex = i;
      break;
    }
  }
  Assert.greaterOrEqual(rowIndex, 0, "the row has a view index");
  win.gUserList.view.selection.select(rowIndex);

  // The prompt is stubbed rather than answered. `Services.prompt.alert` is
  // modal and blocks the thread it runs on, so awaiting the delete while a
  // real dialog is open can never return -- measured: it hung for the whole
  // test budget. A stub records the refusal and lets the call finish.
  const originalPrompt = Services.prompt;
  const alerts = [];
  Services.prompt = {
    alert(w, title, text) {
      alerts.push(text);
    },
    QueryInterface: ChromeUtils.generateQI(["nsIPromptService"]),
  };
  try {
    await win.enigmailDeleteKey();
  } finally {
    Services.prompt = originalPrompt;
  }

  info(`FINDING: refusal said ${JSON.stringify(alerts)}`);
  Assert.equal(alerts.length, 1, "the delete refused rather than proceeding");
  Assert.ok(
    alerts[0].includes("GnuPG"),
    `and named GnuPG as the reason, got ${JSON.stringify(alerts[0])}`
  );

  // Nothing was deleted, and nothing was written to the profile either.
  //
  // Asserted against the profile ring rather than `getKeyById()`, which
  // deliberately answers with GnuPG's copy for a fingerprint GnuPG holds --
  // so asking it here would have reported the key as present and meant
  // nothing about the profile.
  const ringFprs = EnigmailKeyRing.getAllKeys().keyList.map(k =>
    k.fpr.toUpperCase()
  );
  Assert.ok(
    !ringFprs.includes("EB85BB5FA33A75E15E944E63F231550C4F47E38E"),
    "the refused delete left the profile untouched"
  );
  Assert.ok(
    EnigmailKeyRing.isExternalKey(EXTERNAL_KEY_ID),
    "and the key is still GnuPG's, not a profile copy"
  );

  win.close();
});

/**
 * The negative half: a key the profile holds is not marked.
 */
add_task(async function aProfileKeyIsNotMarked() {
  if (!externalAvailable) {
    info("SKIPPED: no external GnuPG on this machine.");
    return;
  }

  // A private key imported into the profile, which GnuPG does not hold.
  await OpenPGPTestUtils.importPrivateKey(
    window,
    new FileUtils.File(
      getTestFilePath(
        `${keyDir}/bob@openpgp.example-0xfbfcc82a015e7330-secret.asc`
      )
    )
  );
  EnigmailKeyRing.clearCache();
  EnigmailKeyRing.clearGnuPgKeyCache();

  const win = Services.ww.openWindow(
    null,
    "chrome://openpgp/content/ui/enigmailKeyManager.xhtml",
    "_blank",
    "chrome,dialog,centerscreen,resizable",
    null
  );
  await BrowserTestUtils.waitForEvent(win, "load");
  registerCleanupFunction(() => {
    if (!win.closed) {
      win.close();
    }
  });

  await TestUtils.waitForCondition(
    () => win.gKeyListView?.rowCount > 0,
    "the manager should populate its list"
  );

  const rows = managerRows(win);
  info(`FINDING: the manager shows ${JSON.stringify(rows)}`);
  const profile = rows.find(r => r.keyId == "FBFCC82A015E7330");
  Assert.ok(profile, "the profile's key is listed");
  Assert.ok(
    !profile.marked,
    "and is not marked, because GnuPG is not where it lives"
  );

  win.close();
});
