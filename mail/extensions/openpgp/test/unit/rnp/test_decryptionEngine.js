/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 79a: record which engine decrypted a message.
 *
 * Decryption is not routed by engine; it is tried in one and falls through to
 * the other. `RNP.decryptArray()` runs librnp first, and only when librnp
 * cannot decrypt -- and the external pref is on and GPGME has loaded -- does it
 * hand the work to `GPGME.decryptArray()` and recurse on the result. That
 * branch used to record nothing about having succeeded, which is why the
 * header had no engine to name for a received message.
 *
 * The flag added is one bit -- *did GnuPG produce this plaintext* -- and not
 * the key id. Which key was used is the separate question the TODO beside that
 * branch leaves open, and conflating the two would turn one bit into an
 * investigation.
 *
 * Both directions are checked, because a flag that is always set is as useless
 * as one that never is:
 *
 *   - GnuPG holds the only copy of the secret key  -> `decryptionEngine` is
 *     `"gnupg"`, and the plaintext is real rather than empty;
 *   - the profile holds it and GnuPG does not      -> the field is null, and
 *     librnp did the work.
 *
 * Signature verification is deliberately out of scope: `mimeVerify.sys.mjs`
 * has no GPGME reference, so every signature is verified by librnp whatever
 * keyring the key lives in.
 */

"use strict";

const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { GPGME } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/GPGME.sys.mjs"
);
const { EnigmailConstants } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/constants.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { Subprocess } = ChromeUtils.importESModule(
  "resource://gre/modules/Subprocess.sys.mjs"
);
const { MailStringUtils } = ChromeUtils.importESModule(
  "resource:///modules/MailStringUtils.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";

const BOB_SECRET_FILE = "bob@openpgp.example-0xfbfcc82a015e7330-secret.asc";
const BOB_EMAIL = "bob@openpgp.example";
const BOB_PRIMARY_ID = "FBFCC82A015E7330";

const PLAINTEXT = "Item 79a: which engine produced this?\n";

let gpgPath = null;
let gnupgHome = null;
let externalAvailable = false;

/**
 * @param {string[]} args
 * @returns {Promise<{exitCode: integer, stdout: string, stderr: string}>}
 */
async function runGpg(args, stdin) {
  const process = await Subprocess.call({
    command: gpgPath,
    arguments: ["--batch", "--no-tty", "--yes", ...args],
    environment: { GNUPGHOME: gnupgHome.path },
    environmentAppend: true,
    stdin: stdin ? "pipe" : "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
  if (stdin) {
    process.stdin.write(stdin);
    process.stdin.close();
  }
  const stdout = await process.stdout.readString();
  const stderr = await process.stderr.readString();
  const { exitCode } = await process.wait();
  return { exitCode, stdout, stderr };
}

/**
 * @param {string} filename - In the shared key fixture directory.
 * @returns {nsIFile} The fixture.
 */
function keyFile(filename) {
  return do_get_file(`${keyDir}/${filename}`);
}

/**
 * Encrypts with gpg, so the ciphertext is independent of the profile.
 *
 * Binary rather than armored, because that is the form `mimeDecrypt` hands to
 * `RNP.decryptArray()`: the MIME layer has already decoded the transfer
 * encoding, so `rnp_input_from_memory` is given `armored = false`.
 *
 * @param {string} text
 * @returns {Promise<string>} A byte string, one char per byte.
 */
async function gpgEncrypt(text) {
  const plainPath = PathUtils.join(gnupgHome.path, "plain.txt");
  const cipherPath = PathUtils.join(gnupgHome.path, "cipher.bin");
  await IOUtils.writeUTF8(plainPath, text);

  const { exitCode, stderr } = await runGpg([
    "--encrypt",
    "--recipient",
    BOB_EMAIL,
    "--output",
    cipherPath,
    plainPath,
  ]);
  Assert.equal(exitCode, 0, `gpg should encrypt, stderr: ${stderr}`);

  const bytes = await IOUtils.read(cipherPath);
  return MailStringUtils.uint8ArrayToByteString(bytes);
}

/**
 * @param {integer} len
 * @returns {object} Options for `RNP.decrypt`.
 */
function decryptOptions(len) {
  return {
    fromAddr: "alice@openpgp.example",
    maxOutputLength: len * 100,
    noOutput: false,
    uiFlags: EnigmailConstants.UI_PGP_MIME,
    verifyOnly: false,
    msgDate: null,
  };
}

/**
 * Lists fingerprints gpg holds secret keys for.
 *
 * @returns {Promise<string[]>}
 */
async function gpgSecretFingerprints() {
  const { stdout } = await runGpg(["--with-colons", "--list-secret-keys"]);
  return stdout
    .split("\n")
    .filter(line => line.startsWith("fpr:"))
    .map(line => line.split(":")[9]);
}

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);

  try {
    gpgPath = await Subprocess.pathSearch("gpg");
  } catch (ex) {
    info("No gpg executable found; the external engine cannot be traced here.");
    return;
  }

  gnupgHome = do_get_tempdir();
  gnupgHome.append("gnupg-decryption-engine");
  gnupgHome.createUnique(Ci.nsIFile.DIRECTORY_TYPE, 0o700);

  const previousHome = Services.env.exists("GNUPGHOME")
    ? Services.env.get("GNUPGHOME")
    : "";
  Services.env.set("GNUPGHOME", gnupgHome.path);
  registerCleanupFunction(async () => {
    // Killed through gpgconf with this home set, so the agent it started does
    // not outlive the test -- and never a dialog on anyone's screen.
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

  // A passphrase would mean a pinentry, and a pinentry is a dialog. This home
  // is a temporary directory owned by the test, and the key is deleted with
  // it, so an unprotected key is the safe choice as well as the quiet one.
  await IOUtils.writeUTF8(
    PathUtils.join(gnupgHome.path, "gpg.conf"),
    "compliance rfc4880\n"
  );

  const { exitCode, stderr } = await runGpg([
    "--import",
    keyFile(BOB_SECRET_FILE).path,
  ]);
  if (exitCode) {
    info(`gpg could not import the fixture key: ${stderr}`);
    return;
  }

  // Without this, gpg refuses to encrypt to a key it has no reason to trust:
  // "There is no assurance this key belongs to the named user". Ownertrust is
  // a property of this throwaway home, not of the fixture.
  const bobFpr = (await gpgSecretFingerprints())[0];
  const trust = await runGpg(
    ["--import-ownertrust", "/dev/stdin"],
    `${bobFpr}:6:\n`
  );
  if (trust.exitCode) {
    info(`gpg could not set ownertrust: ${trust.stderr}`);
    return;
  }

  if (!GPGME.init()) {
    info("No usable gpgme library found; the external engine cannot be used.");
    return;
  }

  externalAvailable = true;
});

/**
 * The ciphertext both directions decrypt, made once so that the second check
 * really is the same message rather than a similar one.
 */
let ciphertext = null;

/**
 * A key only GnuPG holds: the plaintext comes from the fall-through, and the
 * result says so.
 */
add_task(async function gnuPGDecryptionIsRecorded() {
  if (!externalAvailable) {
    info("SKIPPED: external GnuPG is not available on this machine.");
    return;
  }

  // Nothing is imported into the profile, deliberately. It must not be able to
  // decrypt, or librnp answers first and the branch under test is never
  // reached -- and a public key cannot be added anyway while GnuPG holds it,
  // which is the behaviour Item 81a records rather than a defect here.
  Assert.greaterOrEqual(
    (await gpgSecretFingerprints()).length,
    1,
    "gpg holds the secret key"
  );
  Assert.equal(
    EnigmailKeyRing.getKeyById(BOB_PRIMARY_ID),
    null,
    "and the profile holds no key for it"
  );

  ciphertext = await gpgEncrypt(PLAINTEXT);
  const result = await RNP.decrypt(
    ciphertext,
    decryptOptions(ciphertext.length)
  );

  info(
    `FINDING: external decryption exitCode=${result.exitCode} ` +
      `engine=${JSON.stringify(result.decryptionEngine)}`
  );
  Assert.equal(result.exitCode, 0, "librnp cannot, and GnuPG succeeds");
  Assert.ok(
    result.decryptedData.includes(PLAINTEXT.trim()),
    "the plaintext is the one that was encrypted"
  );
  Assert.equal(
    result.decryptionEngine,
    "gnupg",
    "and the result records that GnuPG produced it"
  );
});

/**
 * The same message with the key moved into the profile: librnp decrypts, and
 * the field stays empty. Without this half, a flag that is always set would
 * pass.
 */
add_task(async function librnpDecryptionIsNotAttributedToGnuPG() {
  if (!externalAvailable) {
    info("SKIPPED: external GnuPG is not available on this machine.");
    return;
  }
  Assert.ok(ciphertext, "the first check produced the ciphertext");

  // Take the key away from GnuPG first: while GnuPG holds it, the profile
  // declines to import it, and this check would be about that instead.
  const bobFpr = (await gpgSecretFingerprints())[0];
  Assert.ok(bobFpr, "gpg listed a secret key to remove");
  const { exitCode, stderr } = await runGpg([
    "--delete-secret-and-public-key",
    bobFpr,
  ]);
  Assert.equal(exitCode, 0, `gpg should delete the key, stderr: ${stderr}`);
  Assert.deepEqual(
    await gpgSecretFingerprints(),
    [],
    "gpg holds no secret key now"
  );

  const [keyId] = await OpenPGPTestUtils.importPrivateKey(
    null,
    keyFile(BOB_SECRET_FILE)
  );
  Assert.ok(keyId, "the profile holds the secret key now");
  EnigmailKeyRing.clearCache();

  const result = await RNP.decrypt(
    ciphertext,
    decryptOptions(ciphertext.length)
  );

  info(
    `FINDING: internal decryption exitCode=${result.exitCode} ` +
      `engine=${JSON.stringify(result.decryptionEngine)}`
  );
  Assert.equal(result.exitCode, 0, "librnp decrypts it");
  Assert.ok(
    result.decryptedData.includes(PLAINTEXT.trim()),
    "with the same plaintext"
  );
  Assert.equal(
    result.decryptionEngine,
    null,
    "and claims no engine, because none but librnp was involved"
  );
});
