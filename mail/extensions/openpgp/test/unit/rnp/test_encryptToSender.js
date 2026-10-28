/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * The sender must be able to read their own copy.
 *
 * **The defect this covers, and why it was invisible.** The identity names its
 * key by id, not by address: `getSenderUserId()` returns `"0x" + keyId` so that
 * error messages name the key the user configured. The encrypt-to-self step
 * then looked that identifier up in the RNP store only. In this variant the
 * profile ring is empty by design -- GnuPG is the keyring -- so the lookup
 * found nothing, the sender was silently left out of the recipient list, and
 * the copy saved to Sent was encrypted to the correspondents alone.
 *
 * Two symptoms, one cause:
 *
 *   - a sent message could not be read back from Sent ("the secret key that is
 *     required to decrypt this message is not available"), because no key slot
 *     for the sender existed in the ciphertext;
 *   - saving a draft failed outright, because a draft has no other recipient --
 *     with the sender omitted there was nobody to encrypt to.
 *
 * **The shape that matters is the one in this file:** sender's key in GnuPG,
 * named by key id, recipients' keys also reachable. Every existing test that
 * sets `encryptToSender` passes a fingerprint of a *profile-held* key, which is
 * the configuration that always worked, so none of them could see this.
 *
 * The assertion is a decryption, not a count: whether gpg can read the message
 * back with the sender's secret key. A recipient list can look right and still
 * omit the sender, which is exactly what happened.
 */

"use strict";

const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { GPGME } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/GPGME.sys.mjs"
);
const { OpenPgpValidity } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/constants.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { Subprocess } = ChromeUtils.importESModule(
  "resource://gre/modules/Subprocess.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";

// The sender: secret half lives in GnuPG, never in the profile ring.
const SENDER_SECRET = "alice@openpgp.example-0xf231550c4f47e38e-secret.asc";
const SENDER_FPR = "EB85BB5FA33A75E15E944E63F231550C4F47E38E";
const SENDER_KEY_ID = "F231550C4F47E38E";

// The correspondent: public key only, in the profile ring.
const RECIPIENT_PUB = "bob@openpgp.example-0xfbfcc82a015e7330-pub.asc";
const RECIPIENT_ADDRESS = "bob@openpgp.example";

const PLAINTEXT = "A message that must be readable from Sent afterwards.";

let gpgPath = null;
let gnupgHome = null;
let ready = false;

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
 * Encrypt the way the composer does, with the sender named by key id.
 *
 * @param {string} senderIdentifier - What the identity names, e.g. "0xF231…".
 * @returns {Promise<{ciphertext: ?string, result: object}>}
 */
async function encryptToRecipient(senderIdentifier) {
  const args = {
    aliasKeys: new Map(),
    armor: true,
    bcc: [],
    encrypt: true,
    encryptToSender: true,
    sender: senderIdentifier,
    senderKeyIsExternal: true,
    sigTypeClear: false,
    sigTypeDetached: false,
    sign: false,
    signatureHash: "SHA256",
    to: [`<${RECIPIENT_ADDRESS}>`],
  };
  const result = {};
  const ciphertext = await RNP.encryptAndOrSign(PLAINTEXT, args, result);
  return { ciphertext, result };
}

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();

  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  Services.prefs.setBoolPref("mail.openpgp.fetch_pubkeys_from_gnupg", true);
  registerCleanupFunction(() => {
    Services.prefs.clearUserPref("mail.openpgp.allow_external_gnupg");
    Services.prefs.clearUserPref("mail.openpgp.fetch_pubkeys_from_gnupg");
  });

  try {
    gpgPath = await Subprocess.pathSearch("gpg");
  } catch (ex) {
    info(
      "No gpg executable found; this file cannot measure the external path."
    );
  }
  if (!gpgPath) {
    return;
  }

  gnupgHome = do_get_tempdir();
  gnupgHome.append("gnupg-item103");
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

  // Both keys go into GnuPG and neither into the profile ring, which is what
  // this variant looks like: GnuPG is the keyring and the ring is empty.
  const imported = await runGpg([
    "--import",
    do_get_file(`${keyDir}/${SENDER_SECRET}`).path,
    do_get_file(`${keyDir}/${RECIPIENT_PUB}`).path,
  ]);
  ready = imported.exitCode === 0 && GPGME.init();

  // The sender's public key must be discoverable by id in gpg, which is the
  // lookup the defect skipped.
  if (ready) {
    const byId = GPGME.getPublicKeysForId(`0x${SENDER_KEY_ID}`);
    info(`SENDER keys found in GnuPG by id: ${byId.size}`);
    Assert.greater(
      byId.size,
      0,
      "the sender's key is reachable in GnuPG by key id, so the lookup this " +
        "test exercises has something to find"
    );
  }

  // The recipient must be reachable the same way, or the test would fail for a
  // reason other than the one it is about.
  if (ready) {
    const recipients = GPGME.getPublicKeysForEmail(RECIPIENT_ADDRESS);
    info(`RECIPIENT keys found in GnuPG: ${recipients.size}`);
    Assert.greater(recipients.size, 0, "the recipient is reachable in GnuPG");
  }
});

/**
 * The defect: the ciphertext must contain a key slot for the sender.
 *
 * Asserted by decryption, because that is the consequence the user meets. A
 * recipient list that looks correct can still omit the sender, which is exactly
 * what happened here.
 */
add_task(async function theSentCopyCanBeReadBackByItsAuthor() {
  if (!ready) {
    info("SKIPPED: no external GnuPG available.");
    Assert.ok(true, "skipped");
    return;
  }

  EnigmailKeyRing.clearCache();
  EnigmailKeyRing.clearGnuPgKeyCache();

  const { ciphertext, result } = await encryptToRecipient(`0x${SENDER_KEY_ID}`);
  info(
    `FINDING encrypt: exitCode=${result.exitCode} err=${
      result.errorMsg ?? "(none)"
    } senderKeyUnavailable=${!!result.senderKeyUnavailable}`
  );
  Assert.ok(ciphertext, `the message should be encrypted: ${result.errorMsg}`);
  Assert.ok(!result.exitCode, "and encrypting should not fail");

  // Write it where gpg can read it, then decrypt with the sender's secret key.
  const path = PathUtils.join(
    Services.dirsvc.get("ProfD", Ci.nsIFile).path,
    "item103-ciphertext.asc"
  );
  await IOUtils.writeUTF8(path, ciphertext);
  registerCleanupFunction(() => IOUtils.remove(path, { ignoreAbsent: true }));

  const decrypted = await runGpg([
    "--pinentry-mode",
    "loopback",
    "--passphrase",
    "",
    "--decrypt",
    path,
  ]);
  info(
    `FINDING decrypt with the sender's own key: exit=${decrypted.exitCode} ` +
      `out=${JSON.stringify(decrypted.stdout.slice(0, 60))}`
  );
  Assert.equal(
    decrypted.exitCode,
    0,
    "the sender can decrypt the message they just sent"
  );
  Assert.equal(
    decrypted.stdout,
    PLAINTEXT,
    "and gets the original text back, which is what reading it from Sent does"
  );
});

/**
 * The draft case, which failed differently and for the same reason.
 *
 * A draft is encrypted to the author alone: the compose overlay sets
 * `SEND_ENCRYPT_TO_SELF` and leaves the recipient list empty. So when the
 * author's key could not be resolved there was nobody at all to encrypt to, the
 * encryption produced nothing, and saving failed with a generic "Unable to save
 * your message as a draft" that named no cause.
 */
add_task(async function aDraftCanBeReadBackAfterSaving() {
  if (!ready) {
    info("SKIPPED: no external GnuPG available.");
    Assert.ok(true, "skipped");
    return;
  }

  EnigmailKeyRing.clearCache();
  EnigmailKeyRing.clearGnuPgKeyCache();

  const args = {
    aliasKeys: new Map(),
    armor: true,
    bcc: [],
    encrypt: true,
    encryptToSender: true,
    sender: `0x${SENDER_KEY_ID}`,
    senderKeyIsExternal: true,
    sigTypeClear: false,
    sigTypeDetached: false,
    sign: false,
    signatureHash: "SHA256",
    // A draft has no recipients -- the author is the only one.
    to: [],
  };
  const result = {};
  const ciphertext = await RNP.encryptAndOrSign(PLAINTEXT, args, result);
  info(
    `FINDING draft: encrypted=${!!ciphertext} exitCode=${result.exitCode} ` +
      `err=${JSON.stringify(result.errorMsg ?? "")}`
  );
  Assert.ok(
    ciphertext,
    `a draft with the author as its only recipient should encrypt: ${
      result.errorMsg ?? ""
    }`
  );

  const path = PathUtils.join(
    Services.dirsvc.get("ProfD", Ci.nsIFile).path,
    "item103-draft.asc"
  );
  await IOUtils.writeUTF8(path, ciphertext);
  registerCleanupFunction(() => IOUtils.remove(path, { ignoreAbsent: true }));

  const decrypted = await runGpg([
    "--pinentry-mode",
    "loopback",
    "--passphrase",
    "",
    "--decrypt",
    path,
  ]);
  info(`FINDING draft decrypt: exit=${decrypted.exitCode}`);
  Assert.equal(
    decrypted.exitCode,
    0,
    "and the author can read the draft back, which is what reopening it does"
  );
  Assert.equal(decrypted.stdout, PLAINTEXT, "with the original text intact");
});

/**
 * The refusal: if the sender's key cannot be used, nothing is sent.
 *
 * Before this, the message went out with the sender omitted and the failure was
 * discovered later, from the Sent folder. A message its author cannot read back
 * is not the message they asked to send.
 */
add_task(async function anUnusableSenderKeyRefusesTheSend() {
  if (!ready) {
    info("SKIPPED: no external GnuPG available.");
    Assert.ok(true, "skipped");
    return;
  }

  // A key id that is in neither store.
  const { ciphertext, result } = await encryptToRecipient("0x0000000000000000");
  info(
    `FINDING refused: ciphertext=${ciphertext === null} exitCode=${
      result.exitCode
    } err=${JSON.stringify(result.errorMsg ?? "")}`
  );
  Assert.equal(ciphertext, null, "no ciphertext is produced");
  Assert.ok(result.exitCode, "and the operation reports failure");
  Assert.ok(
    /could not be used to encrypt a copy for you/.test(result.errorMsg ?? ""),
    `the refusal names the reason, got: ${result.errorMsg}`
  );
});
