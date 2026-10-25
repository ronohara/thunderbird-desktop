/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 100: Stage 14 verified, including interoperation with an implementation
 * that is not this one.
 *
 * The item's own ordering is the file's: the round trip is the floor, and
 * interoperation is what proves conformity.
 *
 *   - **The floor.** A message is encrypted to a key, the key is destroyed (the
 *     device that was lost), and the setup message restores it -- asserted on
 *     the message that could not be read a moment earlier, not on the keyring
 *     entry alone. An xpcshell process has one profile, so the empty state is
 *     reached by deleting the key material; what matters is that the store
 *     genuinely holds nothing and genuinely cannot read the mail.
 *   - **Both interoperation directions, because the failure modes differ.** A
 *     message we write but others cannot read is a conformance bug in the
 *     writer; a message others write that we refuse is a conformance bug in the
 *     reader. The outside implementation is GnuPG. In the write direction it
 *     does not merely parse our message -- it imports the key from it and then
 *     encrypts and decrypts with that key, which is use rather than inspection.
 *     In the read direction the payload, its symmetric encryption and the
 *     secret key all come from GnuPG; this build only classifies, decrypts and
 *     adopts.
 *   - **The clauses, parsed.** The header set, the two parts in order, the
 *     packet sequence, the cipher, the code's shape, and the code's absence
 *     from the message.
 *   - **The negative cases**, including the one the specification requires and
 *     no earlier item tested: trailing data after the armour's end delimiter
 *     must be stripped, not rejected.
 *   - **The two decisions of 2026-10-24**: no ownertrust write reaches GnuPG
 *     during an adoption, and the scan finds a recent message outside the Inbox
 *     while importing nothing.
 *   - **The security property the stage exists to be trusted for**: building a
 *     backup from a protected key leaves the stored key protected and locked.
 *
 * What is *not* here, and cannot be: pressing the wizard's two buttons. That
 * remains unwitnessed for the reason Items 99 and 99a record -- `browser_keyWizard.js`
 * is excluded on Linux by bug 1806870 -- and the item says so rather than
 * counting a module-level call as a button press.
 */

"use strict";

const { AutocryptSetup } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/autocryptSetup.sys.mjs"
);
const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { SetupCode } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/setupCode.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { PgpSqliteDb2 } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/sqliteDb.sys.mjs"
);
const { OpenPGPAlias } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/OpenPGPAlias.sys.mjs"
);
const { EnigmailConstants } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/constants.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);
const { Subprocess } = ChromeUtils.importESModule(
  "resource://gre/modules/Subprocess.sys.mjs"
);
const { ctypes } = ChromeUtils.importESModule(
  "resource://gre/modules/ctypes.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";

const ALICE_FPR = "EB85BB5FA33A75E15E944E63F231550C4F47E38E";
const ALICE_ADDRESS = "alice@openpgp.example";
const ALICE_SECRET = "alice@openpgp.example-0xf231550c4f47e38e-secret.asc";
const ALICE_SECRET_WITH_PP =
  "alice@openpgp.example-0xf231550c4f47e38e-secret-with-pp.asc";

const BOB_FPR = "D1A66E1A23B182C9980F788CFBFCC82A015E7330";
const BOB_ADDRESS = "bob@openpgp.example";
const BOB_SECRET = "bob@openpgp.example-0xfbfcc82a015e7330-secret.asc";

const CODE = "1234-5678-9012-3456-7890-1234-5678-9012-3456";
const RULES_PREF = "mail.openpgp.alias_rules_file";
const RULES_FILE = "item100-rules.json";
const DAY = 86400;

var gpgPath = null;
var tempDir = null;

/** The message Stage 14 produced, kept for the clause checks that follow. */
var gMessage = null;

/**
 * The message built from the *protected* key, which is what a user's backup
 * actually carries: the export does not unprotect anything (Item 96), so the
 * key inside keeps its own passphrase.
 */
var gProtectedMessage = null;

/** A message encrypted to Alice while her key was present. */
var gCiphertext = null;

/** The code in its canonical nine-group form, used by more than one check. */
const CANONICAL_CODE = SetupCode.format(CODE);

/** gpg's ownertrust for Carol, read before and after the adoption. */
var gCarolFpr = null;
var gOwnertrustBefore = null;

/**
 * Run gpg against the throwaway home.
 *
 * `pinentry-mode loopback` and a `pinentry-program` that does not exist are
 * both deliberate: a gpg command that would otherwise wait for a human must
 * fail instead, and on this machine a waiting gpg-agent puts a dialog on the
 * user's screen.
 *
 * @param {string[]} args
 * @returns {Promise<{exitCode: number, stdout: string, stderr: string}>}
 */
async function runGpg(args) {
  const process = await Subprocess.call({
    command: gpgPath,
    arguments: [
      "--batch",
      "--no-tty",
      "--yes",
      "--no-symkey-cache",
      "--pinentry-mode",
      "loopback",
      ...args,
    ],
    environment: { GNUPGHOME: tempDir.path },
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
 * @param {string} message
 * @returns {string} The armoured block out of a setup message.
 */
function armourOf(message) {
  const start = message.indexOf("-----BEGIN PGP MESSAGE-----");
  const end = message.indexOf("-----END PGP MESSAGE-----");
  Assert.greater(start, -1, "the message contains an armoured block");
  Assert.greater(end, start, "which is terminated");
  return message.slice(start, end + "-----END PGP MESSAGE-----".length) + "\n";
}

/**
 * @param {string} message
 * @returns {string[]} The MIME parts, excluding the opening boundary line.
 */
function partsOf(message) {
  const boundary = /boundary="([^"]+)"/.exec(message)?.[1];
  Assert.ok(boundary, "the message names a boundary");
  return message
    .split(`--${boundary}`)
    .slice(1)
    .map(part => part.replace(/^--\r?\n?$/, ""));
}

/**
 * @param {string} address
 * @param {string} text
 * @returns {Promise<string>} An armoured message encrypted to the address.
 */
async function encryptTo(address, text) {
  const result = {};
  const encrypted = await RNP.encryptAndOrSign(
    text,
    {
      aliasKeys: new Map(),
      armor: true,
      bcc: [],
      encrypt: true,
      encryptToSender: false,
      sender: `0x${ALICE_FPR}`,
      senderKeyIsExternal: false,
      sigTypeClear: false,
      sigTypeDetached: false,
      sign: false,
      signatureHash: "SHA256",
      to: [`<${address}>`],
    },
    result
  );
  Assert.equal(result.exitCode, 0, `encryption succeeded: ${result.errorMsg}`);
  return encrypted;
}

/**
 * @param {number} length
 * @returns {object} Options for `RNP.decrypt()`.
 */
function decryptOptions(length) {
  return {
    fromAddr: BOB_ADDRESS,
    maxOutputLength: length * 100,
    noOutput: false,
    uiFlags: EnigmailConstants.UI_PGP_MIME,
    verifyOnly: false,
    msgDate: null,
  };
}

/**
 * Whether the library considers a stored key protected and locked.
 *
 * Asked of librnp through a handle on the live ffi, because the claim is about
 * what is on disk rather than about a cached key object.
 *
 * @param {string} fpr
 * @returns {{protected: boolean, locked: boolean}}
 */
function protectionState(fpr) {
  const lib = RNP.getRNPLib();
  const handle = RNP.getKeyHandleByKeyIdOrFingerprint(lib.ffi, `0x${fpr}`);
  Assert.ok(handle && !handle.isNull(), "the key has a handle");

  const isProtected = new ctypes.bool();
  const isLocked = new ctypes.bool();
  try {
    Assert.equal(
      lib.rnp_key_is_protected(handle, isProtected.address()),
      0,
      "rnp_key_is_protected succeeded"
    );
    Assert.equal(
      lib.rnp_key_is_locked(handle, isLocked.address()),
      0,
      "rnp_key_is_locked succeeded"
    );
    return { protected: isProtected.value, locked: isLocked.value };
  } finally {
    lib.rnp_key_handle_destroy(handle);
  }
}

/**
 * The ownertrust gpg itself reports, from its own listing.
 *
 * A `pub` line's ownertrust letter is field 8: `u` ultimate, `f` full, `m`
 * marginal, `n` never, `-` unknown. Read from gpg rather than through GPGME,
 * because the claim is that *gpg's database* was not written to.
 *
 * @param {string} fpr
 * @returns {Promise<string>}
 */
async function gpgOwnertrust(fpr) {
  const { stdout } = await runGpg(["--with-colons", "--list-keys", `0x${fpr}`]);
  for (const line of stdout.split("\n")) {
    const fields = line.split(":");
    if (fields[0] === "pub") {
      return fields[8] ?? "";
    }
  }
  return "";
}

/**
 * Declare an ownertrust value in gpg's trust database.
 *
 * gpg's own value scale: 2 unknown, 3 never, 4 marginal, 5 full, 6 ultimate.
 * Used to move a key *off* the value gpg gives a key it generated itself --
 * ultimate -- so that an adoption writing ultimate would be visible as a change
 * rather than as agreement.
 *
 * @param {string} fpr
 * @param {number} level
 */
async function setGpgOwnertrust(fpr, level) {
  const path = PathUtils.join(tempDir.path, "ownertrust.txt");
  await IOUtils.writeUTF8(path, `${fpr}:${level}:\n`);
  const { exitCode, stderr } = await runGpg(["--import-ownertrust", path]);
  Assert.equal(exitCode, 0, `gpg accepts an ownertrust declaration: ${stderr}`);
  // gpg caches the trust database; a rebuild makes the new value readable.
  await runGpg(["--check-trustdb"]);
}

/**
 * The named subfolder, created if it is not already there.
 *
 * A new POP3 account arrives with some folders already made, so creating
 * unconditionally fails with NS_MSG_FOLDER_EXISTS.
 *
 * @param {nsIMsgLocalMailFolder} root
 * @param {string} name
 * @returns {nsIMsgFolder}
 */
function ensureFolder(root, name) {
  return root.containsChildNamed(name)
    ? root.getChildNamed(name)
    : root.createLocalSubfolder(name);
}

/**
 * The identity an adoption is recorded against.
 *
 * @param {string} address
 * @returns {nsIMsgIdentity}
 */
function identityFor(address) {
  const account = MailServices.accounts.createAccount();
  const identity = MailServices.accounts.createIdentity();
  identity.email = address;
  account.addIdentity(identity);
  return identity;
}

/**
 * Build a setup message carrying a key GnuPG exported.
 *
 * The payload is GnuPG's own transferable secret key, and GnuPG encrypts it --
 * so nothing in the message's cryptographic content was produced by this build.
 * The envelope is assembled here because that is the part an outside
 * implementation's envelope would provide, and the item's read direction is
 * about whether we accept the substance.
 *
 * @param {string} fpr - The key to export from GnuPG.
 * @param {string} address
 * @returns {Promise<string>}
 */
async function buildFromGnuPG(fpr, address) {
  const exported = await runGpg([
    "--armor",
    "--export-secret-keys",
    `0x${fpr}`,
  ]);
  Assert.equal(
    exported.exitCode,
    0,
    `gpg exports the secret key: ${exported.stderr.trim()}`
  );
  Assert.ok(
    exported.stdout.includes("BEGIN PGP PRIVATE KEY BLOCK"),
    "and what it exports is a secret key block"
  );

  // Enigmail's armour-header spelling, inside the payload where the
  // specification puts it. GnuPG knows nothing of Autocrypt, so this is the one
  // part of the payload the test writes -- and `preferenceOf()` is what reads it
  // back.
  const withHeader = exported.stdout.replace(
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----\nAutocrypt-Prefer-Encrypt: mutual"
  );

  const tskPath = PathUtils.join(tempDir.path, "gnupg-tsk.asc");
  const payloadPath = PathUtils.join(tempDir.path, "gnupg-payload.asc");
  await IOUtils.writeUTF8(tskPath, withHeader);

  const encrypted = await runGpg([
    "--armor",
    "--symmetric",
    "--cipher-algo",
    "AES256",
    "--passphrase",
    CODE,
    "-o",
    payloadPath,
    tskPath,
  ]);
  Assert.equal(
    encrypted.exitCode,
    0,
    `gpg encrypts the payload: ${encrypted.stderr.trim()}`
  );
  const armour = (await IOUtils.readUTF8(payloadPath)).trimEnd();
  Assert.ok(
    armour.includes("BEGIN PGP MESSAGE"),
    "and the result is an armoured message"
  );

  const boundary = "gnupg-produced-boundary";
  return [
    `To: ${address}`,
    `From: ${address}`,
    "Autocrypt-Setup-Message: v1",
    "Subject: Autocrypt Setup Message",
    "MIME-Version: 1.0",
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    "",
    `--${boundary}`,
    "Content-Type: text/plain; charset=utf-8",
    "",
    "This message contains your OpenPGP key.",
    "",
    `--${boundary}`,
    "Content-Type: application/autocrypt-setup",
    "",
    armour,
    "",
    `--${boundary}--`,
    "",
  ].join("\r\n");
}

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();

  Services.prefs.setStringPref(RULES_PREF, RULES_FILE);
  registerCleanupFunction(() => {
    Services.prefs.setStringPref(RULES_PREF, "");
    OpenPGPAlias._clear();
  });

  try {
    gpgPath = await Subprocess.pathSearch("gpg");
  } catch (ex) {
    info("No gpg executable found; the interoperation checks need one.");
  }

  tempDir = do_get_tempdir();
  tempDir.append("item100");
  tempDir.createUnique(Ci.nsIFile.DIRECTORY_TYPE, 0o700);
  await IOUtils.writeUTF8(
    PathUtils.join(tempDir.path, "gpg-agent.conf"),
    "pinentry-program /nonexistent/item100-no-pinentry\n"
  );

  registerCleanupFunction(async () => {
    if (!gpgPath) {
      return;
    }
    // Killed through gpgconf with this home set, so the agent this test started
    // does not outlive it -- and never a dialog on anyone's screen.
    try {
      const gpgconfPath = await Subprocess.pathSearch("gpgconf");
      const process = await Subprocess.call({
        command: gpgconfPath,
        arguments: ["--kill", "all"],
        environment: { GNUPGHOME: tempDir.path },
        environmentAppend: true,
        stderr: "pipe",
      });
      await process.stderr.readString();
      await process.wait();
    } catch (ex) {
      info(`Could not stop gpg-agent: ${ex.message}`);
    }
    tempDir.remove(true);
  });
});

/**
 * The security check the stage exists to be trusted for.
 *
 * A backup is an export of the user's secret key, and the hazard is that the
 * export path leaves the copy in the profile unprotected. Asserted before and
 * after, and behaviourally as well as by flag: an unlock with an empty
 * passphrase must fail afterwards, which a build that had stripped the
 * passphrase would not.
 *
 * Run before the round trip because the round trip needs Alice's key
 * unprotected, and one fingerprint can only be in one protection state.
 */
add_task(async function theStoredKeyStaysProtectedAfterABackup() {
  await OpenPGPTestUtils.importPrivateKey(
    null,
    do_get_file(`${keyDir}/${ALICE_SECRET_WITH_PP}`),
    OpenPGPTestUtils.ACCEPTANCE_PERSONAL,
    "alice-passphrase",
    true
  );
  EnigmailKeyRing.clearCache();

  const before = protectionState(ALICE_FPR);
  info(`FINDING protection before: ${JSON.stringify(before)}`);
  Assert.ok(before.protected, "the fixture key is protected to begin with");
  Assert.ok(
    before.locked,
    "and locked, so it is not usable without its own passphrase"
  );

  // The whole creation path, not only the export: a message built from the
  // protected key is what a user's backup actually is.
  const keyBlock = RNP.exportSecretKeyForTransfer(ALICE_FPR, "mutual");
  Assert.ok(keyBlock, "the key exports for the message");
  gProtectedMessage = AutocryptSetup.buildMessage({
    address: ALICE_ADDRESS,
    setupCode: CODE,
    keyBlock,
    preferEncrypt: "mutual",
  });
  Assert.ok(
    gProtectedMessage.includes("BEGIN PGP MESSAGE"),
    "and a message is built"
  );

  const after = protectionState(ALICE_FPR);
  info(`FINDING protection after: ${JSON.stringify(after)}`);
  Assert.equal(
    after.protected,
    before.protected,
    "the stored key is still protected after the export and the message"
  );
  Assert.equal(after.locked, before.locked, "and still locked");

  const lib = RNP.getRNPLib();
  const handle = RNP.getKeyHandleByKeyIdOrFingerprint(
    lib.ffi,
    `0x${ALICE_FPR}`
  );
  try {
    const rc = lib.rnp_key_unlock(handle, "");
    info(`FINDING unlock with an empty passphrase: rc=${rc}`);
    Assert.notEqual(
      rc,
      0,
      "unlocking with an empty passphrase fails, so the key still has one"
    );
  } finally {
    lib.rnp_key_handle_destroy(handle);
  }

  // The round trip needs the unprotected variant of the same key.
  await OpenPGPTestUtils.removeKeyById(ALICE_FPR, true);
  EnigmailKeyRing.clearCache();
  Assert.equal(
    EnigmailKeyRing.getKeyById(`0x${ALICE_FPR}`),
    null,
    "the protected copy is gone, so the round trip starts clean"
  );
});

/**
 * The floor: a device that lost its key gets it back, and the proof is the mail
 * it could not read.
 */
add_task(async function aSetupMessageRestoresAKeyOnADeviceThatLostIt() {
  await OpenPGPTestUtils.importPrivateKey(
    null,
    do_get_file(`${keyDir}/${ALICE_SECRET}`),
    OpenPGPTestUtils.ACCEPTANCE_PERSONAL
  );
  EnigmailKeyRing.clearCache();
  Assert.ok(
    EnigmailKeyRing.getKeyById(`0x${ALICE_FPR}`)?.secretAvailable,
    "the key is in the profile"
  );

  // Mail that only this key can read.
  const plaintext = "Stage 14 round trip\r\n";
  gCiphertext = await encryptTo(ALICE_ADDRESS, plaintext);
  Assert.ok(
    gCiphertext?.includes("BEGIN PGP MESSAGE"),
    "a message is encrypted to it"
  );
  let read = await RNP.decrypt(gCiphertext, decryptOptions(gCiphertext.length));
  Assert.equal(
    read.exitCode,
    0,
    "and the profile reads it while the key is present"
  );

  // The backup, made while the device still has the key.
  const keyBlock = RNP.exportSecretKeyForTransfer(ALICE_FPR, "mutual");
  gMessage = AutocryptSetup.buildMessage({
    address: ALICE_ADDRESS,
    setupCode: CODE,
    keyBlock,
    preferEncrypt: "mutual",
  });

  // The device is lost: nothing of the key remains, and the mail is unreadable.
  await OpenPGPTestUtils.removeKeyById(ALICE_FPR, true);
  EnigmailKeyRing.clearCache();
  Assert.equal(
    EnigmailKeyRing.getKeyById(`0x${ALICE_FPR}`),
    null,
    "the profile holds no key for the address"
  );
  read = await RNP.decrypt(gCiphertext, decryptOptions(gCiphertext.length));
  info(`FINDING decrypt without the key: exitCode=${read.exitCode}`);
  Assert.notEqual(
    read.exitCode,
    0,
    "and cannot read the mail that was encrypted to it"
  );

  // The setup message, treated exactly as a receiving client treats one.
  const classified = AutocryptSetup.classify(gMessage);
  Assert.equal(classified.state, "ok", "the message is recognised");
  const unwrapped = await AutocryptSetup.unwrap(classified.armour, CODE);
  Assert.equal(unwrapped.state, "ok", "and the code opens it");

  const adopted = await AutocryptSetup.adopt({
    keyBlock: unwrapped.keyBlock,
    address: ALICE_ADDRESS,
    preferEncrypt: AutocryptSetup.preferenceOf(unwrapped.keyBlock),
    identity: identityFor(ALICE_ADDRESS),
  });
  info(
    `FINDING adopt: ok=${adopted.ok} error=${adopted.error ?? ""} ` +
      `fpr=${adopted.fingerprint ?? ""}`
  );
  Assert.ok(adopted.ok, `the key is adopted: ${adopted.error ?? ""}`);
  Assert.equal(
    adopted.fingerprint,
    ALICE_FPR,
    "and the fingerprint that came back is the one the message carried"
  );

  // The mail that was unreadable a moment ago.
  read = await RNP.decrypt(gCiphertext, decryptOptions(gCiphertext.length));
  info(`FINDING decrypt after adoption: exitCode=${read.exitCode}`);
  Assert.equal(read.exitCode, 0, "the same message is readable now");
  Assert.ok(
    read.decryptedData.includes(plaintext.trim()),
    "and the plaintext is the one that was encrypted"
  );

  Assert.ok(
    await PgpSqliteDb2.isAcceptedAsPersonalKey(ALICE_FPR),
    "the adopted key carries the marker the composer reads"
  );
});

/**
 * Write-direction interoperation: GnuPG uses the key our message carries.
 *
 * Parsing would only show the message is well formed. Importing the key into a
 * keyring this build does not own and then encrypting and decrypting with it
 * shows the message is *sufficient* -- which is the failure mode the item names,
 * a message we can read but others cannot.
 */
add_task(async function gnuPGUsesTheKeyOurMessageCarries() {
  if (!gpgPath) {
    info("SKIPPED: no gpg executable.");
    Assert.ok(true, "skipped");
    return;
  }

  // Built from the protected key, because that is the message a user's backup
  // is, and because a key with an empty passphrase cannot be unlocked
  // non-interactively by gpg at all -- it answers "No passphrase given" to an
  // empty one. That is a property of gpg's command line, not of the message:
  // the import below succeeds for both fixtures.
  Assert.ok(gProtectedMessage, "the protected-key message exists");
  const armourPath = PathUtils.join(tempDir.path, "our-message.asc");
  await IOUtils.writeUTF8(armourPath, armourOf(gProtectedMessage));

  // gpg, not this build, decrypts it -- with nothing but the code.
  const decrypted = await runGpg([
    "--passphrase",
    CODE,
    "--decrypt",
    armourPath,
  ]);
  Assert.equal(
    decrypted.exitCode,
    0,
    `gpg decrypts our message: ${decrypted.stderr.trim()}`
  );
  Assert.ok(
    decrypted.stdout.includes("BEGIN PGP PRIVATE KEY BLOCK"),
    "and gets a secret key block out of it"
  );

  const tskPath = PathUtils.join(tempDir.path, "from-our-message.asc");
  await IOUtils.writeUTF8(tskPath, decrypted.stdout);

  const imported = await runGpg(["--import", tskPath]);
  Assert.equal(
    imported.exitCode,
    0,
    `gpg imports the key from our message: ${imported.stderr.trim()}`
  );
  const listed = await runGpg(["--with-colons", "--list-secret-keys"]);
  Assert.ok(
    listed.stdout.includes(ALICE_FPR),
    "gpg now holds the secret key the message carried"
  );

  // Use, not presence: encrypt to the key in gpg and read it back in gpg.
  const plaintext = "Stage 14 interoperation\r\n";
  const inPath = PathUtils.join(tempDir.path, "interop-plain.txt");
  const outPath = PathUtils.join(tempDir.path, "interop-cipher.asc");
  await IOUtils.writeUTF8(inPath, plaintext);
  const encrypted = await runGpg([
    "--armor",
    "--trust-model",
    "always",
    "--recipient",
    `0x${ALICE_FPR}`,
    "--output",
    outPath,
    "--encrypt",
    inPath,
  ]);
  Assert.equal(
    encrypted.exitCode,
    0,
    `gpg encrypts to the imported key: ${encrypted.stderr.trim()}`
  );

  // The passphrase is the key's own, carried inside the message: the export
  // does not unprotect (Item 96), so the user's passphrase is what opens it.
  // That is the point -- a backup that arrived without its passphrase would be
  // a worse message, not a better one.
  const roundTripped = await runGpg([
    "--passphrase",
    "alice-passphrase",
    "--decrypt",
    outPath,
  ]);
  Assert.equal(
    roundTripped.exitCode,
    0,
    `and decrypts it: ${roundTripped.stderr.trim()}`
  );
  Assert.ok(
    roundTripped.stdout.includes(plaintext.trim()),
    "with the plaintext that went in"
  );
});

/**
 * Read-direction interoperation: a message GnuPG produced, imported here.
 *
 * Carol is a key this profile has never held, so the import is unambiguous --
 * the key arrives with the message and nowhere else. GnuPG exports the key and
 * encrypts it with the code; the envelope is the only part the test assembles.
 */
add_task(async function aMessageGnuPGProducedImportsHere() {
  if (!gpgPath) {
    info("SKIPPED: no gpg executable.");
    Assert.ok(true, "skipped");
    return;
  }

  // Carol's key is generated *inside* GnuPG, so nothing about it came from a
  // fixture this repository provides -- and it is generated without protection
  // because gpg will not export a protected key in batch mode without a
  // passphrase nobody here has.
  const paramsPath = PathUtils.join(tempDir.path, "carol.params");
  await IOUtils.writeUTF8(
    paramsPath,
    [
      "Key-Type: RSA",
      "Key-Length: 2048",
      "Name-Real: Carol Stage14",
      "Name-Email: carol@example.com",
      "Expire-Date: 0",
      "%no-protection",
      "%commit",
      "",
    ].join("\n")
  );
  const generated = await runGpg(["--gen-key", paramsPath]);
  Assert.equal(
    generated.exitCode,
    0,
    `gpg generates Carol's key: ${generated.stderr.trim()}`
  );

  // Listed by address rather than with no pattern. A full listing of this home
  // came back carrying only the first key while a by-address lookup found the
  // second -- a transport quirk of reading gpg's listing through a pipe in this
  // harness, not a fact about gpg, which lists both when run from a shell. What
  // the test needs is one fingerprint, and the narrower query returns it
  // deterministically.
  const listed = await runGpg([
    "--with-colons",
    "--list-secret-keys",
    "carol@example.com",
  ]);
  // The first `fpr` record of an address query is the primary key's, and the
  // address filter is what makes it Carol's rather than Alice's -- both live in
  // this home by now.
  gCarolFpr = listed.stdout
    .split("\n")
    .find(line => line.startsWith("fpr:"))
    ?.split(":")[9];
  Assert.ok(gCarolFpr, `Carol's fingerprint is known to gpg: ${gCarolFpr}`);
  info(`FINDING Carol's fingerprint from gpg: ${gCarolFpr}`);

  // gpg trusts a key it generated itself, so the value is moved to *never*
  // first. An adoption that wrote ultimate would then show as a change, where
  // against gpg's own default it would agree either way.
  await setGpgOwnertrust(gCarolFpr, 3);
  const declared = await gpgOwnertrust(gCarolFpr);
  info(`FINDING gpg ownertrust after declaring never: "${declared}"`);
  Assert.equal(declared, "n", "gpg holds the declaration this test made");

  Assert.equal(
    EnigmailKeyRing.getKeyById(`0x${gCarolFpr}`),
    null,
    "the profile holds no key for her"
  );

  const message = await buildFromGnuPG(gCarolFpr, "carol@example.com");
  const classified = AutocryptSetup.classify(message);
  info(`FINDING classify of a GnuPG message: ${classified.state}`);
  Assert.equal(classified.state, "ok", "the message is recognised");

  const unwrapped = await AutocryptSetup.unwrap(classified.armour, CODE);
  Assert.equal(unwrapped.state, "ok", "and opened by the code");

  const adopted = await AutocryptSetup.adopt({
    keyBlock: unwrapped.keyBlock,
    address: "carol@example.com",
    preferEncrypt: AutocryptSetup.preferenceOf(unwrapped.keyBlock),
    identity: identityFor("carol@example.com"),
  });
  info(
    `FINDING adopt of a GnuPG message: ok=${adopted.ok} ` +
      `error=${adopted.error ?? ""}`
  );
  Assert.ok(adopted.ok, `the key is adopted: ${adopted.error ?? ""}`);

  const key = EnigmailKeyRing.getKeyById(`0x${gCarolFpr}`);
  Assert.ok(key?.secretAvailable, "and the secret key is in the profile");
  Assert.ok(
    await PgpSqliteDb2.isAcceptedAsPersonalKey(gCarolFpr),
    "marked as the user's own, which is what the composer reads"
  );
});

/**
 * The ownertrust decision, measured where a write would land.
 *
 * Item 94 established that this build *can* write owner trust, and Item 99
 * decided an adoption must not. So the check is not "the value is unchanged in
 * a build that cannot write it" -- the pref that lets a write reach GnuPG is on,
 * and gpg's own database is read afterwards. A build that dropped the decision
 * would move the letter.
 *
 * Read from gpg's own listing rather than through GPGME, because the claim is
 * about gpg's database and asking the same interface that wrote it would agree
 * with itself.
 */
add_task(async function adoptionWritesNoOwnerTrust() {
  if (!gpgPath || !gCarolFpr) {
    info("SKIPPED: no gpg executable, or no key to check.");
    Assert.ok(true, "skipped");
    return;
  }

  // Before: the adoption in the previous task made no write, and this reads the
  // value afterwards -- with the pref that would let a write reach GnuPG.
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  registerCleanupFunction(() => {
    Services.prefs.clearUserPref("mail.openpgp.allow_external_gnupg");
  });

  gOwnertrustBefore = await gpgOwnertrust(gCarolFpr);
  info(`FINDING gpg ownertrust after adoption: "${gOwnertrustBefore}"`);
  Assert.equal(
    gOwnertrustBefore,
    "n",
    "gpg still holds the test's own declaration, so no write was attempted"
  );

  // And a second adoption through the same path does not change it either:
  // the assertion is about the path, not about one lucky run.
  const message = await buildFromGnuPG(gCarolFpr, "carol@example.com");
  const { armour } = AutocryptSetup.classify(message);
  const unwrapped = await AutocryptSetup.unwrap(armour, CODE);
  Assert.equal(unwrapped.state, "ok", "the code opens it a second time");
  const adopted = await AutocryptSetup.adopt({
    keyBlock: unwrapped.keyBlock,
    address: "carol@example.com",
    preferEncrypt: AutocryptSetup.preferenceOf(unwrapped.keyBlock),
    identity: identityFor("carol@example.com"),
  });
  Assert.ok(adopted.ok, `the repeat adoption succeeds: ${adopted.error ?? ""}`);

  const after = await gpgOwnertrust(gCarolFpr);
  info(`FINDING gpg ownertrust after a second adoption: "${after}"`);
  Assert.equal(after, "n", "and gpg's ownertrust is still untouched");
});

/**
 * The clauses, parsed rather than eyeballed.
 *
 * One task for the whole conformance list, because the item states it as one
 * claim: the message this build writes meets the MUSTs. The packet checks need
 * gpg and say so when it is absent; the rest never do.
 */
add_task(async function theMessageMeetsEachRequiredClause() {
  Assert.ok(gMessage, "the round trip produced a message");

  // To and From are the user's own address.
  Assert.ok(
    new RegExp(`^To: ${ALICE_ADDRESS}\r$`, "m").test(gMessage),
    "To: is the account address"
  );
  Assert.ok(
    new RegExp(`^From: ${ALICE_ADDRESS}\r$`, "m").test(gMessage),
    "From: is the account address"
  );

  // The marker, and the multipart shape with the parts in order.
  Assert.ok(
    /^Autocrypt-Setup-Message: v1\r$/m.test(gMessage),
    "the v1 marker is present"
  );
  Assert.ok(
    /^Content-Type: multipart\/mixed;/m.test(gMessage),
    "the message is multipart/mixed"
  );
  const parts = partsOf(gMessage);
  info(`FINDING part count: ${parts.length}`);
  Assert.equal(parts.length, 3, "two parts and the close");
  Assert.ok(
    /Content-Type: text\/plain/.test(parts[0] ?? ""),
    "the human-readable part comes first"
  );
  Assert.ok(
    /Content-Type: application\/autocrypt-setup/.test(parts[1] ?? ""),
    "and the setup payload second"
  );

  // The code's shape, and its absence from the message.
  const canonical = SetupCode.format(CODE);
  Assert.equal(canonical, CODE, "the code is already canonical");
  const groups = canonical.split("-");
  Assert.equal(groups.length, 9, "nine groups");
  Assert.ok(
    groups.every(group => /^\d{4}$/.test(group)),
    "of four digits each, so thirty-six digits in all"
  );
  if (!gpgPath) {
    info("SKIPPED: no gpg executable; the packet checks need one.");
    return;
  }

  // The packets, parsed. `gpg --list-packets` reports the SKESK's cipher, which
  // is the cipher the SEIPD uses.
  const armourPath = PathUtils.join(tempDir.path, "clauses.asc");
  await IOUtils.writeUTF8(armourPath, armourOf(gMessage));
  const { stdout } = await runGpg([
    "--passphrase",
    CODE,
    "--list-packets",
    armourPath,
  ]);
  const tags = [...stdout.matchAll(/tag=(\d+)/g)].map(match =>
    Number(match[1])
  );
  info(`FINDING packet tags: ${JSON.stringify(tags)}`);
  Assert.equal(tags[0], 3, "the first packet is an SKESK");
  Assert.equal(tags[1], 18, "the second is a SEIPD");
  Assert.ok(
    !tags.includes(1),
    "there is no PKESK: the message is opened by the code, not by a key"
  );
  Assert.ok(
    !tags.includes(8),
    "and no compression packet, which the specification excludes"
  );

  const cipher = Number(/cipher (\d+)/.exec(stdout)?.[1]);
  info(`FINDING SKESK cipher: ${cipher}`);
  Assert.ok(
    cipher == 7 || cipher == 9,
    `the cipher is AES-128 or AES-256 (gpg reports ${cipher})`
  );
});

/**
 * The negative cases, in one place.
 *
 * Each is a different required behaviour: a wrong code must not read as damage,
 * a version this build does not know must be ignored rather than partly parsed,
 * and a broken body must be reported rather than offered.
 */
add_task(async function theMessagesThisBuildMustRefuse() {
  const wrong = await AutocryptSetup.unwrap(
    armourOf(gMessage),
    "9999-9999-9999-9999-9999-9999-9999-9999-9999"
  );
  Assert.equal(wrong.state, "wrongCode", "a wrong code is a wrong code");

  const future = gMessage.replace(
    "Autocrypt-Setup-Message: v1",
    "Autocrypt-Setup-Message: v2"
  );
  const futureClassification = AutocryptSetup.classify(future);
  info(`FINDING v2 classification: ${JSON.stringify(futureClassification)}`);
  Assert.equal(
    futureClassification.state,
    "notASetupMessage",
    "a v2 message is ignored entirely"
  );

  const brokenBody = gMessage.replace("-----BEGIN PGP MESSAGE-----", "");
  const brokenClassification = AutocryptSetup.classify(brokenBody);
  info(`FINDING broken body: ${JSON.stringify(brokenClassification)}`);
  Assert.equal(
    brokenClassification.state,
    "malformed",
    "a v1 header with no armour is reported as malformed"
  );
});

/**
 * Trailing data after the armour's end delimiter is stripped, not rejected.
 *
 * The specification requires a reader to strip what follows the end delimiter,
 * because implementations differ in what they append there. No earlier item
 * tested it, so it is asserted here rather than assumed from the builder's
 * shape.
 */
add_task(async function trailingDataAfterTheArmourEndStillImports() {
  const withTrailing = gMessage.replace(
    "-----END PGP MESSAGE-----",
    "-----END PGP MESSAGE-----\r\n\r\nTrailing text a reader must ignore.\r\n"
  );
  Assert.notEqual(withTrailing, gMessage, "the message really was altered");

  const classified = AutocryptSetup.classify(withTrailing);
  info(`FINDING classification with trailing data: ${classified.state}`);
  Assert.equal(
    classified.state,
    "ok",
    "trailing data after the end delimiter does not make the message malformed"
  );
  Assert.ok(
    !classified.armour.includes("Trailing text"),
    "and the armour handed on stops at the end delimiter"
  );

  const unwrapped = await AutocryptSetup.unwrap(classified.armour, CODE);
  Assert.equal(
    unwrapped.state,
    "ok",
    "the code still opens it, so the message is usable rather than merely parseable"
  );
  Assert.ok(
    unwrapped.keyBlock.includes("BEGIN PGP PRIVATE KEY BLOCK"),
    "and the key comes out whole"
  );
});

/**
 * The scan decision: find it, and import nothing.
 *
 * The freshness bound and the folder skips are asserted here as the stage's
 * claim; the scan's own file has the per-folder detail. What only this file
 * asserts is the last sentence of the item -- *a hit opens the wizard rather
 * than importing* -- measured as the key the message carries still being absent
 * from the profile after the scan found the message.
 */
add_task(async function theScanFindsItAndImportsNothing() {
  // Bob's key is used for the message and deliberately not kept in the profile:
  // the export is the only point at which it is there.
  await OpenPGPTestUtils.importPrivateKey(
    null,
    do_get_file(`${keyDir}/${BOB_SECRET}`),
    OpenPGPTestUtils.ACCEPTANCE_PERSONAL
  );
  EnigmailKeyRing.clearCache();
  const keyBlock = RNP.exportSecretKeyForTransfer(BOB_FPR, "mutual");
  Assert.ok(keyBlock, "Bob's key exports");
  const bobMessage = AutocryptSetup.buildMessage({
    address: BOB_ADDRESS,
    setupCode: CODE,
    keyBlock,
    preferEncrypt: "mutual",
  });

  await OpenPGPTestUtils.removeKeyById(BOB_FPR, true);
  EnigmailKeyRing.clearCache();
  Assert.equal(
    EnigmailKeyRing.getKeyById(`0x${BOB_FPR}`),
    null,
    "the profile holds no key for the address before the scan"
  );

  // A POP3 account, with the folders the item names beside a normal one.
  const server = MailServices.accounts.createIncomingServer(
    "item100",
    "stage14.example",
    "pop3"
  );
  const account = MailServices.accounts.createAccount();
  server.valid = false;
  account.incomingServer = server;
  server.valid = true;
  const root = server.rootMsgFolder.QueryInterface(Ci.nsIMsgLocalMailFolder);
  const archive = ensureFolder(root, "Archive");
  const junk = ensureFolder(root, "Junk");
  junk.setFlag(Ci.nsMsgFolderFlags.Junk);
  const trash = ensureFolder(root, "Trash");
  trash.setFlag(Ci.nsMsgFolderFlags.Trash);

  // The same message with a date inside and outside the window. The old one is
  // added first so it carries the lower key: reverse enumeration meets the
  // fresh one and then must stop.
  const now = Math.floor(Date.now() / 1000);
  // The builder writes no Date header -- a compose window adds one when the
  // message is sent -- so the date is inserted rather than replaced, and the
  // stored header is what the scan's window is measured against.
  const aged = (text, seconds) => {
    const date = `Date: ${new Date(seconds * 1000).toUTCString()}`;
    if (/^Date: /m.test(text)) {
      return text.replace(/^Date: [^\r\n]*/m, date);
    }
    return text.replace(
      /^From: [^\r\n]*\r?\n/m,
      match => `${match}${date}\r\n`
    );
  };
  archive
    .QueryInterface(Ci.nsIMsgLocalMailFolder)
    .addMessage(aged(bobMessage, now - 45 * DAY));
  archive
    .QueryInterface(Ci.nsIMsgLocalMailFolder)
    .addMessage(aged(bobMessage, now - 2 * DAY));
  junk
    .QueryInterface(Ci.nsIMsgLocalMailFolder)
    .addMessage(aged(bobMessage, now - 1 * DAY));
  trash
    .QueryInterface(Ci.nsIMsgLocalMailFolder)
    .addMessage(aged(bobMessage, now - 1 * DAY));

  const hits = await AutocryptSetup.findSetupMessages();
  info(
    `FINDING scan hits: ${hits.length} in ` +
      `${[...new Set(hits.map(hit => hit.folder.name))].join(", ")}`
  );
  Assert.equal(hits.length, 1, "exactly one message is found");
  Assert.equal(
    hits[0].folder.URI,
    archive.URI,
    "in the archive, so not the Inbox"
  );
  Assert.greater(
    hits[0].hdr.dateInSeconds,
    now - 30 * DAY,
    "and it is the recent one, so the window excluded the old copy"
  );
  Assert.ok(
    !hits.some(
      hit => hit.folder.URI == junk.URI || hit.folder.URI == trash.URI
    ),
    "Junk and Trash were not searched"
  );
  // The item's last sentence: the scan found the message and imported nothing.
  Assert.equal(
    EnigmailKeyRing.getKeyById(`0x${BOB_FPR}`),
    null,
    "the scan imported nothing: the key is still absent from the profile"
  );
  Assert.ok(
    !(await PgpSqliteDb2.isAcceptedAsPersonalKey(BOB_FPR)),
    "and wrote no acceptance for it"
  );
});

/**
 * The clause this build does not meet, kept as its own task so that a run
 * reports every other conformance result before this one fails.
 *
 * Autocrypt Level 1, Setup Code: *"It MUST NOT be included in the cleartext of
 * the Autocrypt Setup Message, or otherwise transmitted over e-mail."*
 *
 * The message this build writes prints the whole code in its human-readable
 * part -- `autocrypt-setup-body` interpolates `$code` -- so a copy of the
 * message is a copy of the passphrase that protects the key. Item 98 chose that
 * deliberately, for a good reason wrongly answered: the human part must explain
 * the message, and the specification explicitly permits the first two digits in
 * the *text* for exactly that purpose, but not the remaining thirty-four.
 *
 * The test is written to the specification rather than to the build, so it
 * fails until the builder stops printing the code. That is the finding this
 * item exists to produce, and Item 98's row records the proposed correction.
 */
add_task(async function theCodeIsNotInTheMessage() {
  Assert.ok(gMessage, "the round trip produced a message");

  info(
    `FINDING code in message: ${
      gMessage.includes(CANONICAL_CODE) ? "present" : "absent"
    }; prefix ${
      gMessage.includes(CANONICAL_CODE.slice(0, 2)) ? "present" : "absent"
    }`
  );

  Assert.ok(
    !gMessage.includes(CANONICAL_CODE),
    "the setup code must not appear in the message, so that a copy of the " +
      "message is not also a copy of the passphrase (Autocrypt Level 1, " +
      "Setup Code, MUST NOT)"
  );
  Assert.ok(
    !gMessage.includes(CANONICAL_CODE.replace(/-/g, "")),
    "nor the thirty-six digits without their dashes"
  );
  // The appearance the specification does allow: the first two digits, so that a
  // user can tell this backup from another before typing anything. In the
  // cleartext that is the descriptive text; `Passphrase-Begin` says the same
  // thing inside the armour, where it is unreadable until the code has been
  // entered, which is why the text carries it too -- and why this check looks at
  // the message rather than at the header.
  Assert.ok(
    gMessage.includes(CANONICAL_CODE.slice(0, 2)),
    "the two-digit prefix does appear, which the specification permits so that " +
      "messages can be told apart"
  );
  Assert.ok(
    !gMessage.includes(`Passphrase-Begin: ${CANONICAL_CODE.slice(0, 2)}`),
    "and it is not a Passphrase-Begin header in the clear: the armour headers " +
      "sit inside the encrypted payload"
  );
});
