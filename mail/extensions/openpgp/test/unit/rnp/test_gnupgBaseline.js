/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 76: prove the declared GnuPG baseline of 2.3.
 *
 * The baseline was decided on 2026-10-23 so that v5 compatibility is on the
 * supported side of the line: 2.3.0 introduced "Support v5 keys and
 * signatures". A floor nobody runs is a claim, not a guarantee, so this runs the
 * four send paths against a real gpg and records what it found.
 *
 * **What this file does and does not establish, and the difference is the
 * point.** It runs every path against the gpg that is installed on the build
 * machine, records that version, and asserts the baseline is met.
 *
 * **Run against 2.3.8 on 2026-10-27, so the sentence this comment used to make
 * is now wrong and is corrected rather than left.** It said a 2.3 run was
 * impossible here: no released GnuPG generates v5 keys, the distro ships 2.4.4
 * only, and building 2.3 needs several `-dev` packages installed system-wide.
 * The last part is true and it is not an obstacle -- it is a one-off build, not
 * a per-run cost. 2.3.8 was built from source in a throwaway VM and this file
 * ran there: 27/27, with the same v5 import and the same 64-hex fingerprint
 * 2.4.4 gives. So the baseline is measured at the version it declares, not only
 * above it.
 *
 * **Pin the engine with `mail.openpgp.alternative_gpg_path` when doing that,
 * and do not rely on `PATH`.** Two different callers are involved: the version
 * probe below runs `gpg` from `PATH`, while every crypto operation goes through
 * libgpgme, which resolves its engine separately. Prefixing `PATH` makes the
 * probe report 2.3 while libgpgme may still use the distro's 2.4 -- a run that
 * reads as a 2.3 measurement and is not one. The pref is the explicit route,
 * and it can be proved honoured: pointed at a path that does not exist, the
 * suite fails at `GPGME.signDetached`.
 *
 * The version is still printed on every run, so a run against another version
 * remains self-evident.
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

/** The declared floor, from the plan. */
const BASELINE_MAJOR = 2;
const BASELINE_MINOR = 3;

const BOB_SECRET_FILE = "bob@openpgp.example-0xfbfcc82a015e7330-secret.asc";
const BOB_PRIMARY_ID = "FBFCC82A015E7330";
const BOB_EMAIL = "bob@openpgp.example";
const SIGNING_KEY_FILE = "sign-subkey-only-secret.asc";
const SIGNING_KEY_EMAIL = "sign-subkey-only@openpgp.example";

const PLAINTEXT = "Item 76 baseline run.";

let gpgPath = null;
let gnupgHome = null;
let gpgVersion = null;
let ready = false;

/**
 * Run the external gpg against our temporary home.
 *
 * @param {string[]} args
 * @returns {Promise<{exitCode: integer, stdout: string, stderr: string}>}
 */
async function runGpg(args) {
  const process = await Subprocess.call({
    command: gpgPath,
    arguments: ["--batch", "--no-tty", "--yes", "--rfc4880", ...args],
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
 * @returns {Promise<{major: integer, minor: integer, raw: string}>} The gpg
 *   version, parsed from `gpg --version`.
 */
async function readGpgVersion() {
  const process = await Subprocess.call({
    command: gpgPath,
    arguments: ["--version"],
    stdout: "pipe",
    stderr: "pipe",
  });
  const stdout = await process.stdout.readString();
  await process.stderr.readString();
  await process.wait();

  const match = stdout.match(/gpg \(GnuPG\)\s+(\d+)\.(\d+)(?:\.(\d+))?/);
  Assert.ok(match, `gpg --version should name its version, got: ${stdout}`);
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    raw: match[0].replace(/^gpg \(GnuPG\)\s+/, ""),
  };
}

/**
 * Stops the gpg-agent started for our temporary home.
 */
async function killGnuPGAgent() {
  let gpgconfPath;
  try {
    gpgconfPath = await Subprocess.pathSearch("gpgconf");
  } catch (ex) {
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
 * @param {object} overrides
 * @returns {object} Arguments for RNP.encryptAndOrSign, signed externally.
 */
function sendArgs(overrides) {
  return {
    aliasKeys: new Map(),
    armor: true,
    bcc: [],
    encrypt: false,
    encryptToSender: false,
    sender: `0x${BOB_PRIMARY_ID}`,
    senderKeyIsExternal: true,
    sigTypeClear: false,
    sigTypeDetached: false,
    sign: false,
    signatureHash: "SHA256",
    to: [],
    ...overrides,
  };
}

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);

  try {
    gpgPath = await Subprocess.pathSearch("gpg");
  } catch (ex) {
    info("No gpg executable found; the baseline cannot be checked here.");
    return;
  }

  gnupgHome = do_get_tempdir();
  gnupgHome.append("gnupg-baseline");
  gnupgHome.createUnique(Ci.nsIFile.DIRECTORY_TYPE, 0o700);

  const previousHome = Services.env.exists("GNUPGHOME")
    ? Services.env.get("GNUPGHOME")
    : "";
  Services.env.set("GNUPGHOME", gnupgHome.path);
  registerCleanupFunction(async () => {
    await killGnuPGAgent();
    Services.env.set("GNUPGHOME", previousHome);
    gnupgHome.remove(true);
  });

  // Pinned, so the digest does not depend on the gpg version or the key's
  // preferences -- RNP rejects a SHA-1 signature and the failure would read as a
  // compatibility problem.
  await IOUtils.writeUTF8(
    PathUtils.join(gnupgHome.path, "gpg.conf"),
    "compliance rfc4880\ndigest-algo SHA256\n"
  );

  if (!GPGME.init()) {
    info("No usable gpgme library found; the baseline cannot be checked here.");
    return;
  }

  gpgVersion = await readGpgVersion();
  info(`BASELINE running against gpg ${gpgVersion.raw}`);

  for (const name of [BOB_SECRET_FILE, SIGNING_KEY_FILE]) {
    const { exitCode, stderr } = await runGpg([
      "--import",
      do_get_file(`${keyDir}/${name}`).path,
    ]);
    Assert.equal(exitCode, 0, `gpg should import ${name}, got: ${stderr}`);
  }

  // The recipient's public key goes into our own keyring, because encryption
  // resolves recipients there even when signing is delegated to gpg.
  // Bob's secret key, as browser-side external tests do: it supplies both the
  // public key for encrypting to him and the material for decrypting the
  // results below. `importPublicKey` reported "no key imported" here because
  // this key is already present by the time it runs.
  await OpenPGPTestUtils.importPrivateKey(
    null,
    do_get_file(`${keyDir}/${BOB_SECRET_FILE}`)
  );

  ready = true;
});

/**
 * The version this run is actually against, and whether it meets the declared
 * floor.
 *
 * First, because every task below is a statement about *this* version and the
 * result would be misread otherwise.
 */
add_task(
  { skip_if: () => !ready },
  async function theRunRecordsItsGnuPGVersion() {
    Assert.ok(gpgVersion, "the gpg version must have been read");

    const meets =
      gpgVersion.major > BASELINE_MAJOR ||
      (gpgVersion.major == BASELINE_MAJOR &&
        gpgVersion.minor >= BASELINE_MINOR);

    info(
      `BASELINE declared floor ${BASELINE_MAJOR}.${BASELINE_MINOR}; ` +
        `ran against ${gpgVersion.raw}; ` +
        `${meets ? "meets" : "does NOT meet"} the floor.`
    );

    Assert.ok(
      meets,
      `the gpg in use (${gpgVersion.raw}) must be at least ` +
        `${BASELINE_MAJOR}.${BASELINE_MINOR}`
    );
  }
);

/**
 * Path 1 of 4: sign only, detached.
 */
add_task({ skip_if: () => !ready }, async function pathOneSignOnly() {
  const args = sendArgs({ sign: true, sigTypeDetached: true });
  const status = {};
  const signature = await RNP.encryptAndOrSign(PLAINTEXT, args, status);

  Assert.equal(status.exitCode, 0, "signing should succeed");
  Assert.ok(
    status.statusFlags & EnigmailConstants.SIG_CREATED,
    "a signature should have been created"
  );
  Assert.ok(
    signature.startsWith("-----BEGIN PGP SIGNATURE-----"),
    "the result should be an armored detached signature"
  );
});

/**
 * Path 2 of 4: encrypted only. Signing is not requested, so gpg is not
 * involved and the encryption is ours -- which is the point of the path: it
 * must work with an externally held *sender* key without needing one.
 */
add_task({ skip_if: () => !ready }, async function pathTwoEncryptedOnly() {
  const args = sendArgs({ encrypt: true, to: [`<${BOB_EMAIL}>`] });
  const status = {};
  const encrypted = await RNP.encryptAndOrSign(PLAINTEXT, args, status);

  Assert.equal(status.exitCode, 0, "encrypting should succeed");
  Assert.ok(
    encrypted.startsWith("-----BEGIN PGP MESSAGE-----"),
    "the result should be an armored message"
  );

  const { exitCode, decryptedData } = await RNP.decrypt(encrypted, {
    fromAddr: BOB_EMAIL,
    maxOutputLength: encrypted.length * 100,
    noOutput: false,
    uiFlags: EnigmailConstants.UI_PGP_MIME,
    verifyOnly: false,
    msgDate: null,
  });
  Assert.ok(!exitCode, "and the message should decrypt");
  Assert.equal(decryptedData, PLAINTEXT, "returning the original text");
});

/**
 * Path 3 of 4: encrypted and signed -- encryption by us, the signature by gpg.
 */
add_task(
  { skip_if: () => !ready },
  async function pathThreeEncryptedAndSigned() {
    const args = sendArgs({
      encrypt: true,
      sign: true,
      to: [`<${BOB_EMAIL}>`],
    });
    const status = {};
    const message = await RNP.encryptAndOrSign(PLAINTEXT, args, status);

    Assert.equal(status.exitCode, 0, "encrypting and signing should succeed");
    Assert.ok(
      status.statusFlags & EnigmailConstants.SIG_CREATED,
      "the external gpg should have produced a signature"
    );
    Assert.ok(
      message.startsWith("-----BEGIN PGP MESSAGE-----"),
      "the result should be an armored message"
    );

    const { exitCode, decryptedData } = await RNP.decrypt(message, {
      fromAddr: BOB_EMAIL,
      maxOutputLength: message.length * 100,
      noOutput: false,
      uiFlags: EnigmailConstants.UI_PGP_MIME,
      verifyOnly: false,
      msgDate: null,
    });
    Assert.ok(!exitCode, "and the message should decrypt");
    Assert.equal(decryptedData, PLAINTEXT, "returning the original text");
  }
);

/**
 * Path 4 of 4: plain. No signing and no encryption.
 *
 * Asserted as a refusal rather than as a pass-through, because that is what the
 * code does: `encryptAndOrSign()` throws "invalid parameters, neither encrypt
 * nor sign" and a plain send never reaches it. That guard is what keeps an
 * uncrypted message out of the crypto path entirely, and asserting it is the
 * useful claim -- the alternative, calling the function and expecting quiet
 * success, would be inventing a contract it does not have.
 */
add_task({ skip_if: () => !ready }, async function pathFourPlain() {
  const args = sendArgs({});
  const status = {};

  await Assert.rejects(
    RNP.encryptAndOrSign(PLAINTEXT, args, status),
    /neither encrypt nor sign/,
    "an uncrypted send must be refused rather than silently attempted"
  );
  Assert.strictEqual(
    status.externalSenderSigningKeyID,
    undefined,
    "and nothing should have been delegated to gpg"
  );
});

/**
 * Key selection: the signing key is chosen from the external keyring, which is
 * the item's "plus key selection".
 */
add_task(
  { skip_if: () => !ready },
  async function keySelectionUsesTheExternalKeyring() {
    const args = sendArgs({ sign: true, sigTypeDetached: true });
    const status = {};
    await RNP.encryptAndOrSign(PLAINTEXT, args, status);

    Assert.equal(status.exitCode, 0, "signing should succeed");
    Assert.equal(
      args.externalSenderSigningKeyID,
      BOB_PRIMARY_ID,
      "the signing key should be reported as the one gpg chose"
    );

    // And the delegation path can answer a recipient query from the external
    // keyring -- the "key selection" half of the item, asked of the module that
    // does the delegating rather than of our own keyring.
    // It returns a Map of armored key blocks indexed by fingerprint, not an
    // array -- asserted on the type it actually has rather than the one I
    // expected.
    const candidates = GPGME.getPublicKeysForEmail(BOB_EMAIL);
    info(
      `BASELINE recipient query returned ${Object.prototype.toString.call(
        candidates
      )} with size ${candidates?.size}`
    );
    Assert.ok(
      candidates,
      "the external keyring should answer a recipient query"
    );
    Assert.greater(
      candidates.size,
      0,
      `and should find a key for ${BOB_EMAIL}, found ${candidates.size}`
    );
  }
);

/**
 * v5 import, which is the whole reason the baseline is 2.3: a v5 key has to be
 * usable by the gpg we depend on. Asserted against gpg itself rather than
 * against Thunderbird, because this is the interop claim.
 */
add_task(
  { skip_if: () => !ready },
  async function aV5KeyIsAcceptedByTheExternalGnuPG() {
    const v5Path = do_get_file(`${keyDir}/v5-ecc-25519-pub.asc`).path;
    const { exitCode, stderr } = await runGpg(["--import", v5Path]);
    Assert.equal(
      exitCode,
      0,
      `gpg ${gpgVersion.raw} should import a v5 key, got: ${stderr}`
    );

    const listed = await runGpg(["--with-colons", "--list-keys"]);
    Assert.equal(listed.exitCode, 0, "gpg should list its keys");

    // A v5 fingerprint is 32 bytes; the colons format prints it in field 10.
    const fprs = listed.stdout
      .split("\n")
      .filter(line => line.startsWith("fpr:"))
      .map(line => line.split(":")[9]);
    Assert.ok(
      fprs.some(fpr => fpr?.length == 64),
      `gpg should report a 64-hex fingerprint for the v5 key, saw ` +
        `${JSON.stringify(fprs.map(f => f?.length))}`
    );

    info(
      `BASELINE gpg ${gpgVersion.raw} imported and listed the v5 key, ` +
        `confirming the reason the floor is 2.3.`
    );
  }
);
