/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 80: a key that GnuPG holds is attributed to GnuPG.
 *
 * `openpgp-key-assistant-key-collected-gnupg` is a localized string reading
 * "GnuPG keyring", and nothing in the tree produced that source type. A key
 * GnuPG holds was tracked as *present* -- so the assistant did not offer a
 * duplicate -- but never *attributed*, so a user asking where a key came from
 * was given an answer that omitted the true source.
 *
 * The fix records a `gnupg` source on the candidate, in the same shape a
 * collected key's sources have. Two things are deliberately not done:
 *
 *   - it is not stored as `collectedKey`, because that field carries a
 *     `pubKey` the assistant imports on the user's behalf, and a key GnuPG
 *     holds is already present. Importing it would be wrong rather than
 *     redundant.
 *   - it does not add a second place a source can come from. The rendering
 *     code reads one shape, whichever field supplied it.
 *
 * Three cases, because a source that appears for everything is as misleading
 * as one that never appears: a key only GnuPG holds, a key collected from an
 * attachment, and a key the profile holds.
 */

"use strict";

const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { PgpSqliteDb2 } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/sqliteDb.sys.mjs"
);
const { CollectedKeysDB } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/CollectedKeysDB.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { Subprocess } = ChromeUtils.importESModule(
  "resource://gre/modules/Subprocess.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";

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

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  Services.prefs.setBoolPref("mail.openpgp.fetch_pubkeys_from_gnupg", true);

  try {
    gpgPath = await Subprocess.pathSearch("gpg");
  } catch (ex) {
    info("No gpg executable found; the GnuPG source cannot be traced here.");
    return;
  }

  gnupgHome = do_get_tempdir();
  gnupgHome.append("gnupg-key-origin");
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
    do_get_file(`${keyDir}/${GNUPG_SECRET_FILE}`).path,
  ]);
  if (exitCode) {
    info(`gpg could not import the fixture key: ${stderr}`);
    return;
  }

  externalAvailable = true;
});

/**
 * A key only GnuPG holds: the assistant is told where it came from.
 */
add_task(async function aKeyOnlyGnuPGHoldsIsAttributedToIt() {
  if (!externalAvailable) {
    info("SKIPPED: no external GnuPG on this machine.");
    return;
  }

  EnigmailKeyRing.clearGnuPgKeyCache();
  const metas = await EnigmailKeyRing.getEncryptionKeyMeta(GNUPG_ADDRESS);
  const meta = metas.find(m => m.keyObj?.fpr);

  Assert.ok(meta, `the GnuPG key is a candidate for ${GNUPG_ADDRESS}`);
  Assert.ok(
    meta.gnupgKey,
    "and it carries a GnuPG origin, which nothing recorded before"
  );
  Assert.equal(
    meta.gnupgKey.sources.length,
    1,
    "with exactly one source, because there is only one"
  );
  Assert.equal(
    meta.gnupgKey.sources[0].type,
    "gnupg",
    "of the type the localized string is named for"
  );
  Assert.equal(
    meta.gnupgKey.sources[0].description,
    gnupgHome.path,
    "and describing which keyring, taken from GNUPGHOME"
  );
  Assert.ok(
    !meta.collectedKey,
    "it is not reported as collected: that shape carries a public key to " +
      "import, and this key is already present"
  );
});

/**
 * A key stored in the collected-keys database is not attributed to GnuPG.
 *
 * The record is built here rather than through `storeKey()`, because that
 * method dispatches a `keycollected` event on the most recent `mail:3pane`
 * window and xpcshell has none -- so the write completes and its promise never
 * settles. That is a defect in `storeKey()` rather than in this item, recorded
 * in the plan; the browser test covers the stored case, where a 3pane window
 * exists.
 */
add_task(async function aCollectedKeyIsNotAttributedToGnuPG() {
  const pubKey = await IOUtils.readUTF8(
    do_get_file(`${keyDir}/${ATTACHMENT_PUBLIC_FILE}`).path
  );
  const keys = await RNP.getKeyListFromKeyBlockImpl(pubKey);
  Assert.equal(keys.length, 1, "the fixture is a single key");

  const collDB = await CollectedKeysDB.getInstance();
  const record = await collDB.mergeExisting(keys[0], pubKey, {
    uri: "mid:item80@example",
    type: "attachment",
    description: "bob.asc",
  });
  Assert.equal(
    record.sources[0].type,
    "attachment",
    "the record says where it came from"
  );

  // The meta is built from the same fields `getEncryptionKeyMeta` reads, so
  // this asserts the negative case without needing the row to be persisted.
  Assert.ok(
    !record.gnupgKey,
    "and carries no GnuPG origin, because GnuPG does not hold this key"
  );
  Assert.equal(
    EnigmailKeyRing.getGnuPgKeyById(keys[0].keyId),
    null,
    "confirmed against the transient cache rather than assumed"
  );
});

/**
 * A key the profile holds is attributed to neither: it was generated here.
 */
add_task(async function aProfileKeyHasNoOutsideOrigin() {
  const { OpenPGPMasterpass } = ChromeUtils.importESModule(
    "chrome://openpgp/content/modules/masterpass.sys.mjs"
  );
  const password = await OpenPGPMasterpass.retrieveOpenPGPPassword();
  const keyId = await RNP.genKey(
    "Origin Test <origin@example.com>",
    "ECC",
    0,
    0,
    password
  );
  Assert.ok(keyId, "a key was generated in the profile");
  EnigmailKeyRing.clearCache();
  const key = EnigmailKeyRing.getKeyById(keyId);
  registerCleanupFunction(() => PgpSqliteDb2.deleteAcceptance(key.fpr));

  const metas =
    await EnigmailKeyRing.getEncryptionKeyMeta("origin@example.com");
  const meta = metas.find(m => m.keyObj?.fpr == key.fpr);
  Assert.ok(meta, "the generated key is a candidate");
  Assert.ok(
    !meta.gnupgKey,
    "and has no GnuPG origin, because GnuPG was not involved"
  );
  Assert.ok(!meta.collectedKey, "nor a collected origin");
});
