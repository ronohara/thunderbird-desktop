/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * External GnuPG signing when no passphrase can be obtained.
 *
 * The passphrase of a key that GnuPG holds belongs to gpg-agent, not to
 * Thunderbird. Thunderbird must neither ask for it nor wait for it. This
 * test removes every way for the agent to obtain one and asserts that
 * signing fails promptly instead of raising a prompt, then supplies a
 * non-interactive pinentry and asserts that the same request succeeds.
 *
 * Both halves are needed. The first proves that no prompt of ours exists;
 * the second proves that the refusal is about the passphrase and not about
 * signing being broken for this key.
 *
 * The second half needs a pinentry that never touches a desktop, so the
 * test writes its own. A pinentry is the Assuan server, so it speaks
 * first and then answers GETPIN; a stub that waits for a greeting instead
 * deadlocks the agent until it gives up.
 *
 * A gpg executable and a loadable gpgme library are required. If either is
 * missing, the tasks are skipped.
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

const keyDir = "../../../../../test/browser/openpgp/data/keys";

// Bob's primary key can sign and its secret key is protected by a
// passphrase, so every signing attempt has to unlock it first.
const BOB_PRIMARY_ID = "FBFCC82A015E7330";
const BOB_EMAIL = "bob@openpgp.example";
const BOB_PROTECTED_SECRET_FILE =
  "bob@openpgp.example-0xfbfcc82a015e7330-secret-with-pp.asc";
const BOB_PUBLIC_FILE = "bob@openpgp.example-0xfbfcc82a015e7330-pub.asc";
const BOB_PASSPHRASE = "bob-passphrase";

// Keep this on a single line, GPGME signs detached signatures in text
// mode, which canonicalizes line endings.
const PLAINTEXT = "External GnuPG pinentry test.";

let gpgPath = null;
let gpgconfPath = null;
let gnupgHome = null;
let externalGnuPGReady = false;

/**
 * Run the external gpg executable against our temporary GnuPG home.
 *
 * @param {string[]} args - Command line arguments.
 * @returns {Promise<{exitCode: integer, stderr: string}>}
 */
async function runGpg(args) {
  const process = await Subprocess.call({
    command: gpgPath,
    arguments: ["--batch", "--no-tty", "--yes", "--rfc4880", ...args],
    environment: { GNUPGHOME: gnupgHome.path },
    environmentAppend: true,
    stderr: "pipe",
  });
  const stderr = await process.stderr.readString();
  const { exitCode } = await process.wait();
  return { exitCode, stderr };
}

/**
 * Stop gpg-agent for our temporary GnuPG home, so the next gpg invocation
 * starts one that reads the configuration we just wrote. Also stops it at
 * the end of the test, otherwise it outlives the run.
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
    stderr: "pipe",
  });
  await process.stderr.readString();
  await process.wait();
}

/**
 * Point gpg-agent at a pinentry, and restart it so the setting takes
 * effect.
 *
 * @param {string} pinentryPath - Path of the pinentry to use. A path that
 *   does not exist is how the "no passphrase available" case is set up:
 *   gpg-agent then has nowhere to ask, and fails immediately.
 */
async function setPinentry(pinentryPath) {
  await IOUtils.writeUTF8(
    PathUtils.join(gnupgHome.path, "gpg-agent.conf"),
    `pinentry-program ${pinentryPath}\nno-allow-external-cache\n`
  );
  await killGnuPGAgent();
}

/**
 * Write a pinentry that is guaranteed not to open a window.
 *
 * It answers Assuan the way pinentry does: it is the server, so it sends
 * its OK greeting before reading anything, answers GETPIN with the
 * passphrase, and acknowledges every other command.
 *
 * @returns {Promise<string>} Path of the executable stub.
 */
async function writeNonInteractivePinentry() {
  const path = PathUtils.join(gnupgHome.path, "pinentry-noninteractive.sh");
  await IOUtils.writeUTF8(
    path,
    [
      "#!/bin/sh",
      "# Non-interactive pinentry for tests: no window, no terminal.",
      "printf 'OK non-interactive test pinentry\\n'",
      "while IFS= read -r line; do",
      '  case "${line%% *}" in',
      `    GETPIN) printf 'D ${BOB_PASSPHRASE}\\nOK\\n' ;;`,
      "    BYE)    printf 'OK closing connection\\n'; exit 0 ;;",
      "    *)      printf 'OK\\n' ;;",
      "  esac",
      "done",
      "",
    ].join("\n")
  );
  await IOUtils.setPermissions(path, 0o700);
  return path;
}

/**
 * @param {string} sender - Key ID of the sender, prefixed with 0x.
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

/*
 * There is deliberately no watchdog timer here. If gpg-agent manages to
 * raise a prompt, the call blocks until somebody answers it, and the
 * xpcshell harness fails the task on its own timeout rather than letting
 * the run pass. A timer of our own would be a second, arbitrary bound on
 * top of that, and this directory's lint rules reject one.
 */

add_setup(async function () {
  do_get_profile();

  await OpenPGPTestUtils.initOpenPGP();

  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);

  // Only the public key goes into our own ring, which is all Thunderbird
  // would have for a key that GnuPG manages. It is what the detached
  // signature is verified against.
  await OpenPGPTestUtils.importPublicKey(
    null,
    do_get_file(`${keyDir}/${BOB_PUBLIC_FILE}`)
  );

  try {
    gpgPath = await Subprocess.pathSearch("gpg");
    gpgconfPath = await Subprocess.pathSearch("gpgconf");
  } catch (ex) {
    info("No gpg executable found");
    return;
  }
  info(`Using gpg executable ${gpgPath}`);

  // Not the profile directory, the path of the gpg-agent socket below
  // it must stay short enough for a unix domain socket.
  gnupgHome = do_get_tempdir();
  gnupgHome.append("gnupg-pinentry");
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

  // The digest must be pinned, otherwise the digest that gpg picks
  // depends on its version and on the key's preferences, and RNP
  // rejects a SHA-1 signature.
  await IOUtils.writeUTF8(
    PathUtils.join(gnupgHome.path, "gpg.conf"),
    "compliance rfc4880\ndigest-algo SHA256\n"
  );

  if (!GPGME.init()) {
    info("No usable gpgme library found");
    return;
  }

  const { exitCode, stderr } = await runGpg([
    "--import",
    do_get_file(`${keyDir}/${BOB_PROTECTED_SECRET_FILE}`).path,
  ]);
  Assert.equal(
    exitCode,
    0,
    `gpg should import the protected secret key, got: ${stderr}`
  );

  externalGnuPGReady = true;
});

/**
 * With no pinentry to ask, the passphrase cannot be obtained. Signing must
 * fail rather than wait, and the failure must come from gpg-agent.
 */
add_task(
  { skip_if: () => !externalGnuPGReady },
  async function testSigningWithoutPinentryFails() {
    await setPinentry("/nonexistent-pinentry-item24");

    // The same operation through gpg directly, to establish what the
    // refusal is. This is the cause the signing attempt has to be failing
    // for, and it is a property of the agent rather than of our call.
    const plaintextPath = PathUtils.join(gnupgHome.path, "direct.txt");
    await IOUtils.writeUTF8(plaintextPath, `${PLAINTEXT}\n`);
    const direct = await runGpg([
      "--local-user",
      BOB_PRIMARY_ID,
      "--detach-sign",
      "--output",
      PathUtils.join(gnupgHome.path, "direct.sig"),
      plaintextPath,
    ]);
    Assert.notEqual(
      direct.exitCode,
      0,
      "gpg should not be able to sign without a usable pinentry"
    );
    Assert.ok(
      direct.stderr.includes("No pinentry"),
      `gpg should report that it has nowhere to ask, got: ${direct.stderr}`
    );

    const args = detachedSignArgs(`0x${BOB_PRIMARY_ID}`);
    const resultStatus = {};

    // The interesting part is that this rejects at all. A prompt of ours
    // would have to come from a passphrase callback, and the external
    // signing path never installs one: it hands the request to gpg-agent
    // and waits for the answer. The wait is what fails here.
    //
    // Until Item 28 this message could not be asserted on: GPGME.signDetached()
    // dropped gpgme's return code, so the caller saw an unexplained failure.
    // The code and gpg's own wording are now recorded, which is why the reason
    // is asserted below rather than printed and ignored.
    let error = null;
    try {
      await RNP.encryptAndOrSign(PLAINTEXT, args, resultStatus);
    } catch (ex) {
      error = ex;
    }

    Assert.ok(
      error,
      "signing with no usable pinentry must fail instead of returning a signature"
    );
    info(`signing failed with: ${error.message}`);
    Assert.equal(
      resultStatus.statusFlags & EnigmailConstants.SIG_CREATED,
      0,
      "no signature should have been created"
    );

    // Item 28: the reason reaches the caller. gpg itself reported "No pinentry"
    // here, and a message that says only "signDetached failed" would throw away
    // the one piece of information that tells a user what to fix.
    Assert.ok(
      resultStatus.errorMsg,
      "the failure must carry gpg's own reason, not just a code"
    );
    Assert.ok(
      /pinentry/i.test(resultStatus.errorMsg),
      `the reason should name the missing pinentry, got: ${resultStatus.errorMsg}`
    );
    Assert.equal(
      typeof resultStatus.exitCode,
      "number",
      "a numeric exit code should be reported, not the -1 placeholder"
    );
    Assert.notEqual(
      resultStatus.exitCode,
      0,
      "the code should record a failure"
    );
    Assert.ok(
      error.message.includes(resultStatus.errorMsg),
      "the thrown error should carry the same reason as resultStatus"
    );
  }
);

/**
 * With a pinentry available the same request succeeds, and the passphrase
 * is supplied by gpg-agent. Thunderbird contributes no prompt of its own,
 * which is what the first task relies on.
 */
add_task(
  { skip_if: () => !externalGnuPGReady },
  async function testSigningWithNonInteractivePinentrySucceeds() {
    const pinentryPath = await writeNonInteractivePinentry();
    await setPinentry(pinentryPath);

    const args = detachedSignArgs(`0x${BOB_PRIMARY_ID}`);
    const resultStatus = {};
    const signature = await RNP.encryptAndOrSign(PLAINTEXT, args, resultStatus);

    Assert.equal(
      resultStatus.exitCode,
      0,
      "signing should report success to the caller"
    );
    Assert.ok(
      resultStatus.statusFlags & EnigmailConstants.SIG_CREATED,
      "a signature should have been created"
    );
    Assert.ok(
      signature.startsWith("-----BEGIN PGP SIGNATURE-----"),
      "result should be an armored detached signature"
    );

    const verified = await RNP.verifyDetached(
      PLAINTEXT,
      signature,
      BOB_EMAIL,
      null
    );
    Assert.equal(verified.exitCode, 0, "verification should succeed");
    Assert.ok(
      verified.statusFlags & EnigmailConstants.GOOD_SIGNATURE,
      "signature should be good"
    );
    Assert.equal(
      verified.keyId,
      BOB_PRIMARY_ID,
      "signature should have been made by the protected primary key"
    );
  }
);
