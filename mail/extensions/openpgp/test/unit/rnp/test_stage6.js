/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Stage 6's verification: the key model, measured against a real GnuPG.
 *
 * Four of the five cases design 1.1 names are exercised here, on generated
 * keys in a throwaway keyring, with no passphrase anywhere so that no prompt
 * can be needed. The fifth -- a smartcard-held key -- cannot be tested without
 * the hardware, and that is stated in the task that stands in for it rather
 * than quietly omitted.
 *
 * The claim under test throughout is that Thunderbird asks GnuPG and accepts
 * the answer: a retired key is never used, a rotation to a signing subkey is
 * followed, and an address with several keys is encrypted to all of them.
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
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
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

const PLAINTEXT = "Stage six verification.";

let gpgPath = null;
let gpgconfPath = null;
let gnupgHome = null;
let ready = false;

/**
 * Read a pipe to the end.
 *
 * `readString()` without a length returns one chunk, which silently truncates
 * anything gpg writes in more than one write.
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
 * Run gpg against the throwaway keyring.
 *
 * @param {string[]} args - Arguments.
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

/** Stop the agent for the throwaway keyring. */
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
 * Generate a secret key with no passphrase.
 *
 * @param {string} uid - User id.
 * @param {string} algo - Primary algorithm, for example "ed25519".
 * @param {string} usage - Primary usage, for example "sign".
 * @param {string} [subAlgo] - Subkey algorithm, when a subkey is wanted.
 * @param {string} [subUsage] - Subkey usage.
 * @returns {Promise<string>} The primary fingerprint.
 */
async function generateKey(uid, algo, usage, subAlgo, subUsage) {
  // The fingerprint comes from gpg's own status output, not from re-listing
  // after the fact. Listing straight after a generation was racy: the same
  // run passed alone and failed in the directory run, and a test whose fixture
  // depends on a flush timing is a flake waiting to be blamed on the code.
  let { exitCode, stdout, stderr } = await runGpg([
    "--status-fd",
    "1",
    "--passphrase",
    "",
    "--quick-generate-key",
    uid,
    algo,
    usage,
    "0",
  ]);
  Assert.equal(exitCode, 0, `gpg should generate ${uid}: ${stderr}`);

  const created = /\[GNUPG:\] KEY_CREATED \S+ ([0-9A-F]{40})/.exec(stdout);
  const fpr = created ? created[1] : null;
  Assert.ok(fpr, `gpg should report the new key for ${uid}: ${stdout}`);

  // KEY_CREATED is emitted before gpg's keyring write is necessarily complete,
  // so a listing immediately afterwards can miss the key. Measured 2026-10-24:
  // the identity generated here resolved to null in a directory run while the
  // same task passed alone, which is the signature of this and not of a defect
  // in the resolver. Wait, bounded, until gpg lists what it says it created.
  let listed = false;
  for (let attempt = 0; attempt < 20 && !listed; attempt++) {
    listed = (await listKeys(uid)).some(k => k.fpr == fpr);
    if (!listed) {
      await new Promise(resolve => do_timeout(25, resolve));
    }
  }
  Assert.ok(listed, `gpg should list the key it just created for ${uid}`);

  let subFpr = "";
  if (subAlgo) {
    // The subkey's fingerprint also comes from gpg's status output rather than
    // from re-listing. The listing version passed alone and failed in the
    // directory run with "the generated key should be listed", which is the
    // same race the primary's fingerprint was taken from KEY_CREATED to avoid.
    let subOut;
    ({
      exitCode,
      stdout: subOut,
      stderr,
    } = await runGpg([
      "--status-fd",
      "1",
      "--passphrase",
      "",
      "--quick-add-key",
      fpr,
      subAlgo,
      subUsage,
      "0",
    ]));
    Assert.equal(exitCode, 0, `gpg should add a ${subUsage} subkey: ${stderr}`);
    const subCreated = /\[GNUPG:\] KEY_CREATED \S+ ([0-9A-F]{40})/.exec(subOut);
    subFpr = subCreated ? subCreated[1] : "";
    Assert.ok(subFpr, `gpg should report the new subkey: ${subOut}`);
  }
  return { fpr, subFpr };
}

/**
 * gpg's own listing for a pattern, parsed far enough for these tasks.
 *
 * @param {string} pattern - Address, key id or fingerprint.
 * @returns {Promise<object[]>} One record per key, with its subkeys.
 */
async function listKeys(pattern) {
  const keys = await GnuPGAgent.listSecretKeys(pattern);
  return keys;
}

/**
 * Disable a key in GnuPG, which is how a user retires one without revoking it.
 *
 * @param {string} fpr - Primary fingerprint.
 */
async function disableKey(fpr) {
  const process = await Subprocess.call({
    command: gpgPath,
    arguments: [
      "--batch",
      "--yes",
      "--command-fd",
      "0",
      "--status-fd",
      "2",
      "--edit-key",
      fpr,
    ],
    environment: { GNUPGHOME: gnupgHome.path },
    environmentAppend: true,
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
  });
  await process.stdin.write("disable\nsave\n");
  await process.stdin.close();
  await Promise.all([readAll(process.stdout), readAll(process.stderr)]);
  await process.wait();
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
  gnupgHome.append("gnupg-stage6");
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

  // Nowhere for a passphrase prompt to go. Nothing here needs one, and if that
  // ever changes the run must fail rather than wait for a human.
  await IOUtils.writeUTF8(
    PathUtils.join(gnupgHome.path, "gpg-agent.conf"),
    "pinentry-program /nonexistent-pinentry-stage6\n"
  );

  if (!GPGME.init()) {
    info("No usable gpgme library found");
    return;
  }

  ready = true;
});

/**
 * Two acceptable keys for one address, one of them disabled: the disabled one
 * is never chosen, and the choice is reported.
 *
 * This is the first case design 1.1 names, and the reporting half is what Item
 * 28 added: the fingerprint and the rule that chose it reach the caller, which
 * is what the composer displays.
 */
add_task({ skip_if: () => !ready }, async function disabledKeyIsNeverChosen() {
  const { fpr: liveFpr } = await generateKey(
    "Alice <alice@openpgp.example>",
    "ed25519",
    "sign"
  );
  const { fpr: retiredFpr } = await generateKey(
    "Alice <alice@openpgp.example>",
    "ed25519",
    "sign"
  );
  await disableKey(retiredFpr);

  // Confirm the fixture really is disabled, from gpg's own listing, so a
  // passing test cannot mean "the disable silently did nothing".
  const keys = await listKeys("Alice <alice@openpgp.example>");
  const retired = keys.find(k => k.fpr == retiredFpr);
  Assert.ok(retired, "the retired key should still be listed");
  Assert.ok(
    retired.capabilities.includes("D"),
    `gpg should report ${retiredFpr} as disabled, got ${retired.capabilities}`
  );

  const chosen = await GPGME.resolveSigningKeyForIdentity(
    "alice@openpgp.example"
  );
  Assert.ok(chosen, "a signing key should be resolved");
  Assert.equal(
    chosen.fpr,
    liveFpr,
    "the live key should be chosen, not the retired one"
  );
  Assert.ok(
    ["default-key", "gnupg-order"].includes(chosen.source),
    `the rule that chose it should be reported, got ${chosen.source}`
  );
});

/**
 * A retired key cannot be selected at all.
 *
 * With every key for the address disabled there is nothing to choose, and the
 * answer is null rather than a key the user has retired. The control is the
 * second address, which is untouched -- without it this task would pass on a
 * resolver that refused everything.
 */
add_task(
  { skip_if: () => !ready },
  async function retiredKeyCannotBeSelected() {
    const { fpr: onlyFpr } = await generateKey(
      "Bob <bob@openpgp.example>",
      "ed25519",
      "sign"
    );
    await disableKey(onlyFpr);

    const refused = await GPGME.resolveSigningKeyForIdentity(
      "Bob <bob@openpgp.example>"
    );
    Assert.equal(
      refused,
      null,
      "a key that has been retired must not be selected"
    );

    // The control: an untouched identity still resolves.
    const { fpr: other } = await generateKey(
      "Carol <carol@openpgp.example>",
      "ed25519",
      "sign"
    );
    const allowed = await GPGME.resolveSigningKeyForIdentity(
      "Carol <carol@openpgp.example>"
    );
    Assert.ok(allowed, "an identity with a live key should still resolve");
    Assert.equal(allowed.fpr, other, "and it is the live key that is used");
  }
);

/**
 * A rotation to a signing subkey is followed.
 *
 * The resolver prefers a signing subkey over a primary that could also sign,
 * because that is where a rotation puts the signing capability. Asserted as an
 * inequality against the primary as well, so a change that started returning
 * the primary would fail here rather than pass quietly.
 */
add_task({ skip_if: () => !ready }, async function signingSubkeyIsFollowed() {
  const { fpr: primaryFpr, subFpr } = await generateKey(
    "Dave <dave@openpgp.example>",
    "ed25519",
    "sign",
    "ed25519",
    "sign"
  );

  const chosen = await GPGME.resolveSigningKeyForIdentity(
    "Dave <dave@openpgp.example>"
  );
  Assert.ok(chosen, "a signing key should be resolved");
  Assert.equal(
    chosen.fpr,
    subFpr,
    "the signing subkey should be used, not the primary"
  );
  Assert.notEqual(
    chosen.fpr,
    primaryFpr,
    "following the rotation means not returning the primary"
  );
});

/**
 * Several keys for one address are all encrypted to.
 *
 * Read out of the ciphertext's own packets: one PKESK per recipient key, which
 * is the only place the answer actually lives. A caller that believed the
 * message went to both, while the ciphertext named one, would pass a test that
 * only counted recipients.
 */
add_task(
  { skip_if: () => !ready },
  async function everyRecipientKeyIsEncryptedTo() {
    const { fpr: firstFpr } = await generateKey(
      "Erin <erin@openpgp.example>",
      "ed25519",
      "sign",
      "cv25519",
      "encr"
    );
    const { fpr: secondFpr } = await generateKey(
      "Erin <erin@openpgp.example>",
      "ed25519",
      "sign",
      "cv25519",
      "encr"
    );

    const args = {
      aliasKeys: new Map(),
      armor: true,
      bcc: [],
      encrypt: true,
      encryptToSender: false,
      sender: "",
      // Routes the send down the external path, which is the one whose
      // recipient resolution this task is about. With a false flag the call
      // goes to the internal engine, which cannot see a GnuPG-only recipient
      // key at all, and the task would fail for a reason unrelated to the
      // claim.
      senderKeyIsExternal: true,
      sigTypeClear: false,
      sigTypeDetached: false,
      sign: false,
      signatureHash: "SHA256",
      to: ["<erin@openpgp.example>"],
    };
    const resultStatus = {};
    const ciphertext = await RNP.encryptAndOrSign(
      PLAINTEXT,
      args,
      resultStatus
    );
    Assert.equal(resultStatus.exitCode, 0, "encryption should succeed");
    Assert.ok(ciphertext, "ciphertext should be produced");

    const cipherFile = gnupgHome.clone();
    cipherFile.append("stage6.asc");
    await IOUtils.writeUTF8(cipherFile.path, ciphertext);

    const { exitCode, stdout } = await runGpg([
      "--list-packets",
      cipherFile.path,
    ]);
    Assert.equal(exitCode, 0, "gpg should read the ciphertext's packets");

    // ":pubkey enc packet: version 3, algo 18, keyid ABCDEF0123456789"
    const keyIds = [...stdout.matchAll(/keyid ([0-9A-Fa-f]{16})/g)].map(m =>
      m[1].toUpperCase()
    );

    // The packets name the key that actually encrypts, which is the
    // encryption subkey -- not the primary fingerprint. Comparing against the
    // primary was the first version of this assertion and it failed on a
    // correct result.
    const encryptedWith = new Map();
    for (const fpr of [firstFpr, secondFpr]) {
      const key = (await listKeys("erin@openpgp.example")).find(
        k => k.fpr == fpr
      );
      Assert.ok(key, `the key ${fpr} should be listed`);
      const sub = key.subkeys.find(candidate =>
        /[eE]/.test(candidate.capabilities)
      );
      Assert.ok(sub, `the key ${fpr} should carry an encryption subkey`);
      encryptedWith.set(sub.keyId.toUpperCase(), fpr);
    }

    for (const [keyId, fpr] of encryptedWith) {
      Assert.ok(
        keyIds.includes(keyId),
        `the ciphertext should name the encryption subkey ${keyId} of ${fpr}, got ${keyIds}`
      );
    }
    Assert.equal(
      keyIds.length,
      encryptedWith.size,
      `the ciphertext should name exactly the two recipient subkeys, got ${keyIds}`
    );
  }
);

/**
 * A key visible only to GnuPG resolves and signs -- the structural case a
 * smartcard key is an instance of.
 *
 * **What this does not test, stated rather than implied:** a real smartcard.
 * That needs the hardware, and the item says so. What a smartcard key shares
 * with this case is the property that matters to the code: the secret material
 * is not in the profile ring and RNP cannot see it, so everything has to work
 * through gpg. A generated key that is never imported into the ring has that
 * property, and nothing else about a card does.
 */
add_task(
  { skip_if: () => !ready },
  async function gnupgOnlyKeyIsNotVisibleToRNP() {
    const { fpr: fpr } = await generateKey(
      "Frank <frank@openpgp.example>",
      "ed25519",
      "sign"
    );

    EnigmailKeyRing.clearCache();
    Assert.ok(
      !EnigmailKeyRing.getKeyById(fpr),
      "the profile ring should not hold this key, which is the point"
    );

    const chosen = await GPGME.resolveSigningKeyForIdentity(
      "Frank <frank@openpgp.example>"
    );
    Assert.ok(chosen, "a key GnuPG holds should still resolve");
    Assert.equal(chosen.fpr, fpr, "and it is that key");

    const args = {
      aliasKeys: new Map(),
      armor: true,
      bcc: [],
      encrypt: false,
      encryptToSender: false,
      sender: "Frank <frank@openpgp.example>",
      senderKeyIsExternal: true,
      sigTypeClear: false,
      sigTypeDetached: true,
      sign: true,
      signatureHash: "SHA256",
      to: [],
    };
    const resultStatus = {};
    const signature = await RNP.encryptAndOrSign(PLAINTEXT, args, resultStatus);
    Assert.equal(
      resultStatus.exitCode,
      0,
      `signing through gpg alone should succeed: ${resultStatus.errorMsg}`
    );
    Assert.ok(
      resultStatus.statusFlags & EnigmailConstants.SIG_CREATED,
      "a signature should have been created"
    );
    Assert.ok(
      signature.startsWith("-----BEGIN PGP SIGNATURE-----"),
      "the result should be an armored detached signature"
    );
  }
);
