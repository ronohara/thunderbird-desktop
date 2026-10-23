/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Which key signs, when GnuPG is allowed to answer.
 *
 * The point of these tasks is that Thunderbird stops ranking keys and applies
 * GnuPG's own rules instead: the key configured as `default-key` when it
 * belongs to the identity, otherwise the first usable key in gpg's own order.
 * The fixture is two keys for one address, which is what key rotation looks
 * like, and it is the case where a ranking invented by the caller shows.
 *
 * The keys are generated without a passphrase, so no prompt can ever be
 * needed. The agent is additionally pointed at a pinentry that does not
 * exist, so that a prompt would fail rather than appear on screen.
 */

"use strict";

const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { GPGME } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/GPGME.sys.mjs"
);
const { GnuPGAgent } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/gnupgAgent.sys.mjs"
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

const IDENTITY = "alice@example.com";
const FIRST_UID = `Alice One <${IDENTITY}>`;
const SECOND_UID = `Alice Two <${IDENTITY}>`;
const OTHER_UID = "Carol <carol@example.com>";

const PLAINTEXT = "Key selection delegation test.";

let gpgPath = null;
let gpgconfPath = null;
let gnupgHome = null;
let externalGnuPGReady = false;

// Fingerprints of the two keys that share the identity, in generation order,
// which is the order gpg lists them in.
let firstFpr = "";
let secondFpr = "";
let otherFpr = "";

/**
 * Read a pipe to the end.
 *
 * `readString()` without a length reads only the first chunk, so a helper
 * built on it silently truncates anything gpg writes in more than one write.
 * Key listings fit in one chunk and status output does not, so the difference
 * only shows up on the runs that matter.
 *
 * @param {object} stream - A Subprocess input pipe.
 * @returns {Promise<string>} Everything the stream produced.
 */
async function readAll(stream) {
  const decoder = new TextDecoder();
  let text = "";
  if (!stream) {
    return text;
  }
  for (;;) {
    const buffer = await stream.read();
    if (!buffer || buffer.byteLength === 0) {
      return text;
    }
    text += decoder.decode(buffer, { stream: true });
  }
}

/**
 * Run gpg against our temporary GnuPG home.
 *
 * @param {string[]} args - Command line arguments.
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
  const [stdout, stderr] = await Promise.all([
    readAll(process.stdout),
    readAll(process.stderr),
  ]);
  const { exitCode } = await process.wait();
  return { exitCode, stdout, stderr };
}

/**
 * Stop the agent for our temporary home, so the next gpg run reads the
 * configuration just written.
 */
async function killGnuPGAgent() {
  if (!gpgconfPath) {
    return;
  }
  const process = await Subprocess.call({
    command: gpgconfPath,
    arguments: ["--kill", "all"],
    environment: { GNUPGHOME: gnupgHome.path },
    environmentAppend: true,
    stdout: "pipe",
    stderr: "pipe",
  });
  await Promise.all([readAll(process.stdout), readAll(process.stderr)]);
  await process.wait();
}

/**
 * Generate a signing key with no passphrase.
 *
 * Unprotected on purpose: a test that signs must not be able to ask a human
 * for anything.
 *
 * @param {string} uid - User id for the new key.
 */
async function generateKey(uid) {
  const { exitCode, stderr } = await runGpg([
    "--passphrase",
    "",
    "--quick-generate-key",
    uid,
    "ed25519",
    "sign",
    "0",
  ]);
  Assert.equal(exitCode, 0, `gpg should generate a key for ${uid}: ${stderr}`);
}

/**
 * Fingerprint of the key carrying a user id, read straight from gpg.
 *
 * Read here rather than through the module under test, so a defect in the
 * parser cannot also decide what the fixture looks like.
 *
 * @param {string} uid - User id to look up.
 * @returns {Promise<string>} The fingerprint.
 */
async function fingerprintForUid(uid) {
  const { stdout } = await runGpg([
    "--with-colons",
    "--fingerprint",
    "--list-secret-keys",
    uid,
  ]);
  const lines = stdout.split("\n");
  const secIndex = lines.findIndex(line => line.startsWith("sec:"));
  Assert.notEqual(secIndex, -1, `gpg should list a key for ${uid}`);
  const fprLine = lines.slice(secIndex).find(line => line.startsWith("fpr:"));
  Assert.ok(fprLine, `gpg should print a fingerprint for ${uid}`);
  return fprLine.split(":")[9];
}

/**
 * Set, or clear, `default-key` in gpg's own configuration.
 *
 * @param {string} [value] - Fingerprint to make the default key.
 */
async function setDefaultKey(value) {
  const text = value ? `default-key ${value}\n` : "";
  await IOUtils.writeUTF8(PathUtils.join(gnupgHome.path, "gpg.conf"), text);
  await killGnuPGAgent();
}

/**
 * @param {string} sender - Identity for the signing request.
 * @returns {object} arguments for RNP.encryptAndOrSign
 */
function detachedSignArgs(sender) {
  return {
    aliasKeys: new Map(),
    armor: true,
    bcc: [],
    encrypt: false,
    encryptToSender: false,
    sender,
    senderKeyIsExternal: true,
    sigTypeClear: false,
    sigTypeDetached: true,
    sign: true,
    signatureHash: "SHA256",
    to: [],
  };
}

add_setup(async function () {
  do_get_profile();

  await OpenPGPTestUtils.initOpenPGP();

  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);

  try {
    gpgPath = await Subprocess.pathSearch("gpg");
    gpgconfPath = await Subprocess.pathSearch("gpgconf");
  } catch (ex) {
    info("No gpg executable found");
    return;
  }

  gnupgHome = do_get_tempdir();
  gnupgHome.append("gnupg-selection");
  gnupgHome.createUnique(Ci.nsIFile.DIRECTORY_TYPE, 0o700);

  const previousHome = Services.env.exists("GNUPGHOME")
    ? Services.env.get("GNUPGHOME")
    : "";
  Services.env.set("GNUPGHOME", gnupgHome.path);
  registerCleanupFunction(async function () {
    await killGnuPGAgent();
    Services.env.set("GNUPGHOME", previousHome);
    gnupgHome.remove(true);
  });

  // A pinentry that cannot open anything. Nothing here needs one, and if
  // that ever changes the run must fail rather than wait for a human.
  await IOUtils.writeUTF8(
    PathUtils.join(gnupgHome.path, "gpg-agent.conf"),
    "pinentry-program /nonexistent-pinentry-item26\n"
  );

  if (!GPGME.init()) {
    info("No usable gpgme library found");
    return;
  }

  await generateKey(FIRST_UID);
  await generateKey(SECOND_UID);
  await generateKey(OTHER_UID);

  firstFpr = await fingerprintForUid(FIRST_UID);
  secondFpr = await fingerprintForUid(SECOND_UID);
  otherFpr = await fingerprintForUid(OTHER_UID);

  Assert.notEqual(firstFpr, secondFpr, "the fixture needs two distinct keys");

  // The public halves are deliberately not imported into the profile ring.
  // The import guard refuses a key GnuPG already holds -- which is the point
  // of Item 8 -- so the signature produced here is verified by gpg instead,
  // against the keyring that really holds the key. That is the stronger
  // check anyway: gpg's own VALIDSIG line names the signing key, and the
  // test can compare it with what Thunderbird reports having used.

  externalGnuPGReady = true;
});

/**
 * With nothing configured, gpg's own order decides: the first key it lists
 * for the identity.
 */
add_task(
  { skip_if: () => !externalGnuPGReady },
  async function testGnuPGOrderDecidesByDefault() {
    await setDefaultKey();

    const selected = await GPGME.resolveSigningKeyForIdentity(IDENTITY);

    Assert.ok(selected, "a key should be found for the identity");
    Assert.equal(
      selected.source,
      "gnupg-order",
      "with no default-key configured, gpg's order is the rule that applies"
    );
    Assert.equal(
      selected.fpr,
      firstFpr,
      "the first key gpg lists for the identity should be used"
    );
  }
);

/**
 * A configured `default-key` belonging to the identity wins over gpg's order.
 *
 * This is the task that fails on the old selection, which had no notion of
 * the configured preference and returned the first key regardless.
 */
add_task(
  { skip_if: () => !externalGnuPGReady },
  async function testConfiguredDefaultKeyWins() {
    await setDefaultKey(secondFpr);

    const selected = await GPGME.resolveSigningKeyForIdentity(IDENTITY);

    Assert.ok(selected, "a key should be found for the identity");
    Assert.equal(
      selected.source,
      "default-key",
      "the configured default key should be the rule that applies"
    );
    Assert.equal(
      selected.fpr,
      secondFpr,
      "the key the user configured for signing should be the one used"
    );
  }
);

/**
 * A default key belonging to somebody else is not applied to this identity.
 *
 * Without this task, the previous one would pass on a resolver that simply
 * trusted `default-key` for any sender, which would sign as the wrong person.
 */
add_task(
  { skip_if: () => !externalGnuPGReady },
  async function testDefaultKeyForAnotherIdentityIsIgnored() {
    await setDefaultKey(otherFpr);

    const selected = await GPGME.resolveSigningKeyForIdentity(IDENTITY);

    Assert.ok(selected, "a key should be found for the identity");
    Assert.equal(
      selected.source,
      "gnupg-order",
      "a default key for another identity must not be applied to this one"
    );
    Assert.equal(
      selected.fpr,
      firstFpr,
      "the identity's own first key should still be the one used"
    );
  }
);

/**
 * What gpg used is reported back, so the choice can be shown to the user.
 */
add_task(
  { skip_if: () => !externalGnuPGReady },
  async function testSigningReportsTheKeyGnuPGUsed() {
    await setDefaultKey(secondFpr);

    const args = detachedSignArgs(IDENTITY);
    const resultStatus = {};
    const signature = await RNP.encryptAndOrSign(PLAINTEXT, args, resultStatus);

    Assert.equal(resultStatus.exitCode, 0, "signing should succeed");
    Assert.ok(
      resultStatus.statusFlags & EnigmailConstants.SIG_CREATED,
      "a signature should have been created"
    );
    Assert.equal(
      resultStatus.externalSigningKeyFpr,
      secondFpr,
      "the key gpg used should be reported, not the key we guessed"
    );
    Assert.equal(
      resultStatus.externalSigningKeySource,
      "default-key",
      "the reason for the choice should be reported too"
    );

    // The report is only worth having if the signature really came from that
    // key. gpg verifies it against the keyring that holds the key, and its
    // VALIDSIG line names the key that made the signature.
    const plaintextFile = gnupgHome.clone();
    plaintextFile.append("signed.txt");
    // Exactly the signed bytes: no trailing newline. GPGME signs in text
    // mode, so a newline added here would be part of the data being verified
    // and the signature would read as bad.
    await IOUtils.writeUTF8(plaintextFile.path, PLAINTEXT);
    const signatureFile = gnupgHome.clone();
    signatureFile.append("signed.asc");
    await IOUtils.writeUTF8(signatureFile.path, signature);

    const verified = await runGpg([
      "--status-fd",
      "1",
      "--verify",
      signatureFile.path,
      plaintextFile.path,
    ]);
    Assert.equal(
      verified.exitCode,
      0,
      `gpg should verify the signature it just made: ${verified.stderr}`
    );
    const validSig = verified.stdout
      .split("\n")
      .find(line => line.startsWith("[GNUPG:] VALIDSIG"));
    Assert.ok(validSig, "gpg should name the key that made the signature");
    Assert.equal(
      validSig.split(" ")[2],
      resultStatus.externalSigningKeyFpr,
      "the key gpg verified with should be the key Thunderbird reported"
    );
  }
);

/**
 * Asking gpg for its key list returns what gpg actually holds, including the
 * state gpg reports for each key.
 */
add_task(
  { skip_if: () => !externalGnuPGReady },
  async function testListingMirrorsGnuPG() {
    const keys = await GnuPGAgent.listSecretKeys(IDENTITY);

    Assert.equal(
      keys.length,
      2,
      "gpg should list both keys that carry this identity"
    );
    Assert.deepEqual(
      keys.map(key => key.fpr),
      [firstFpr, secondFpr],
      "the listing should preserve gpg's order and fingerprints"
    );
    for (const key of keys) {
      Assert.ok(key.keyId, "each key should carry its key id");
      Assert.ok(
        key.uids.some(uid => uid.email == IDENTITY),
        "each key should carry the identity's address"
      );
      Assert.ok(
        /[sS]/.test(key.capabilities),
        "each key should be reported as able to sign"
      );
      Assert.ok(
        !key.capabilities.includes("D"),
        "neither key should be reported as disabled"
      );
    }
  }
);
