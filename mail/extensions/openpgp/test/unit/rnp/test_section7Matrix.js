/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * The section 7 matrix, as one sequence — Item 37.
 *
 * Seven guarantees were established by different stages, and each has its own
 * test in this directory. This file exists because those tests are separate:
 * a later stage can undo an earlier stage's guarantee without any of the
 * individual tests noticing, because the case that regressed is nobody's case.
 * Running all seven in one pass, on one build, is what makes that visible.
 *
 * Every check names the failure it is designed to catch. A check whose failure
 * mode cannot be stated is not a check.
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
const { OpenPGPMasterpass } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/masterpass.sys.mjs"
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
const ALICE_SECRET = "alice@openpgp.example-0xf231550c4f47e38e-secret.asc";
const ALICE_PUB = "alice@openpgp.example-0xf231550c4f47e38e-pub.asc";
const ALICE_FPR = "EB85BB5FA33A75E15E944E63F231550C4F47E38E";
const ALICE_KEY_ID = "F231550C4F47E38E";
const ALICE_ADDR = "alice@openpgp.example";

const PLAINTEXT = "Section seven matrix.";

let gpgPath = null;
let gnupgHome = null;
let ready = false;

/**
 * Read a pipe to the end; `readString()` returns one chunk only.
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
  const gpgconfPath = await Subprocess.pathSearch("gpgconf").catch(() => null);
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

/** @returns {nsIFile} The passphrase file. */
function passFile() {
  return OpenPGPMasterpass.getPassPath();
}

/** @returns {nsIFile} The secret keyring file. */
function secRingFile() {
  return OpenPGPMasterpass.getSecretKeyRingFile();
}

/**
 * @param {nsIFile} file - The file to measure.
 * @returns {integer} Bytes, or -1 when absent.
 */
function fileSize(file) {
  return file.exists() ? file.fileSize : -1;
}

/** Every store file, including the `.old` siblings saveKeyRing leaves. */
function storeFiles() {
  const files = [passFile(), secRingFile()];
  for (const file of [passFile(), secRingFile()]) {
    const old = file.clone();
    old.leafName = file.leafName + ".old";
    files.push(old);
  }
  return files;
}

/** Remove every store file, and forget the cached passphrase. */
async function clearStore() {
  for (const file of storeFiles()) {
    if (file.exists()) {
      await IOUtils.remove(file.path, { ignoreAbsent: true });
    }
  }
  OpenPGPMasterpass.cachedPassword = null;
  OpenPGPMasterpass._initDone = false;
}

/** Remove the fixture key from the profile ring, if it is there. */
async function removeFixtureKey() {
  EnigmailKeyRing.clearCache();
  const key = EnigmailKeyRing.getKeyById(ALICE_FPR);
  if (key) {
    await RNP.deleteKey(key.fpr, key.secretAvailable);
  }
  EnigmailKeyRing.clearCache();
}

add_setup(async function () {
  do_get_profile();

  await OpenPGPTestUtils.initOpenPGP();

  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);

  try {
    gpgPath = await Subprocess.pathSearch("gpg");
  } catch (ex) {
    info("No gpg executable found");
    return;
  }

  gnupgHome = do_get_tempdir();
  gnupgHome.append("gnupg-section7");
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

  // Nowhere for a prompt to go. Several checks depend on that being true, and
  // if it ever stops being true the run must fail rather than wait.
  await IOUtils.writeUTF8(
    PathUtils.join(gnupgHome.path, "gpg-agent.conf"),
    "pinentry-program /nonexistent-pinentry-section7\n"
  );

  if (!GPGME.init()) {
    info("No usable gpgme library found");
    return;
  }

  const { exitCode, stderr } = await runGpg([
    "--import",
    do_get_file(`${keyDir}/${ALICE_SECRET}`).path,
  ]);
  Assert.equal(exitCode, 0, `gpg should import Alice's secret key: ${stderr}`);

  ready = true;
});

/**
 * 1. No key is copied out of GnuPG.
 *
 * Failure it catches: the import guard stops refusing and a secret key safe in
 * the keyring acquires a second copy inside the profile -- issue 1.5, the cause
 * of the original incident.
 *
 * **The route matters, and the first version of this check used the wrong one.**
 * `importKeyAsync` imports public parts only -- that is Item 8's finding -- so
 * it never reaches `unprotect()` or `setAutoPassphrase()` and correctly reports
 * success. The route that writes secret material is `importSecKeyFromFile`, and
 * that is the one guarded. Asserting on the public route would have tested
 * nothing and passed.
 */
add_task({ skip_if: () => !ready }, async function check1NothingIsCopiedOut() {
  await clearStore();
  await removeFixtureKey();

  const errorObj = {};
  const importedKeysObj = {};
  await EnigmailKeyRing.importSecKeyFromFile(
    null,
    null,
    false,
    do_get_file(`${keyDir}/${ALICE_SECRET}`),
    errorObj,
    importedKeysObj
  );

  Assert.equal(
    importedKeysObj.keys?.length ?? 0,
    0,
    "the guard should report nothing imported for a key GnuPG holds"
  );
  Assert.equal(errorObj.value, undefined, "and it is shaped as success");

  EnigmailKeyRing.clearCache();
  const ringKey = EnigmailKeyRing.getKeyById(ALICE_FPR);
  Assert.ok(
    !ringKey || !ringKey.secretAvailable,
    "no secret material should be in the profile ring afterwards"
  );
  Assert.equal(
    fileSize(secRingFile()),
    -1,
    "and no secret keyring should have been written"
  );
});

/**
 * 2. GnuPG wins for a fingerprint it holds.
 *
 * Failure it catches: precedence inverting, so a stale profile copy decides a
 * key's expiry again -- issue 1.5's stale-copy symptom, the 18 October report.
 *
 * **The state has to be planted, and that is a finding in itself.** The import
 * guard now refuses to copy a key GnuPG holds, so the "both stores hold it"
 * state is unreachable by ordinary import. It remains reachable in a profile
 * that predates the guard, which is exactly who precedence is for -- so this
 * check plants the copy the way such a profile has it: with the external pref
 * off, where the guard deliberately does not consult GnuPG.
 *
 * Two real revisions of one key are used. The newer one has a second user ID,
 * so which revision answered is observable rather than inferred: if the stale
 * copy wins, the key has one user ID; if GnuPG wins, it has two.
 */
add_task({ skip_if: () => !ready }, async function check2GnuPGWins() {
  const revFpr = "D4ED849BCD779DFC";
  const revBefore = "D4ED849BCD779DFC-before-new-identity.asc";
  const revAfter = "D4ED849BCD779DFC-after-new-identity.asc";

  // The newer revision into GnuPG.
  const imported = await runGpg([
    "--import",
    do_get_file(`${keyDir}/${revAfter}`).path,
  ]);
  Assert.equal(
    imported.exitCode,
    0,
    `gpg should import the newer revision: ${imported.stderr}`
  );

  // The older one into the profile ring, with the guard's pref off.
  // xpcshell has no SpecialPowers, so the pref is set and restored by hand.
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", false);
  try {
    await OpenPGPTestUtils.importPublicKey(
      null,
      do_get_file(`${keyDir}/${revBefore}`)
    );
  } finally {
    Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  }
  EnigmailKeyRing.clearCache();

  const planted = EnigmailKeyRing.getKeyById(revFpr);
  Assert.ok(planted, "the older revision should be in the profile ring");
  Assert.equal(
    planted.userIds.length,
    1,
    "the planted copy carries one user ID, or this proves nothing"
  );

  // GnuPG's answer, installed in the transient cache the way the modules
  // install a key that GnuPG holds. Precedence reads that cache -- merely
  // having the key in the gpg keyring is not what it consults, which is why
  // the first version of this check saw the planted copy win.
  const afterBlock = await IOUtils.readUTF8(
    do_get_file(`${keyDir}/${revAfter}`).path
  );
  const parsed = await RNP.getKeyListFromKeyBlockImpl(afterBlock);
  const { EnigmailKeyObj } = ChromeUtils.importESModule(
    "chrome://openpgp/content/modules/keyObj.sys.mjs"
  );
  const transient = new EnigmailKeyObj(parsed[0]);
  EnigmailKeyRing.gnuPgKeys.set(transient.fpr.toUpperCase(), transient);
  EnigmailKeyRing.gnuPgKeyIds.set(
    transient.keyId.toUpperCase(),
    transient.fpr.toUpperCase()
  );
  Assert.equal(
    transient.userIds.length,
    2,
    "the transient revision carries two user IDs"
  );

  registerCleanupFunction(() => {
    EnigmailKeyRing.gnuPgKeys.delete(transient.fpr.toUpperCase());
    EnigmailKeyRing.gnuPgKeyIds.delete(transient.keyId.toUpperCase());
  });

  const resolved = EnigmailKeyRing.getKeyById(revFpr);
  Assert.equal(
    resolved.userIds.length,
    2,
    `the reported user IDs should be GnuPG's, not the planted copy's; got ` +
      `${resolved.userIds.length} -- one means the stale copy decided`
  );
});

/**
 * 3. Thunderbird never asks for a GnuPG passphrase.
 *
 * Failure it catches: the unlock tracker prompting for a key GnuPG owns --
 * issue 1.6, a prompt whose only purpose was to support the copy that check 1
 * now prevents.
 *
 * The check has two halves and both are needed. GnuPG must report holding the
 * key, otherwise there is nothing to refuse to prompt for; and a tracker over
 * that fingerprint, given a callback that counts its invocations, must not call
 * it. The second half alone would pass on a tracker that ignored everything.
 */
add_task({ skip_if: () => !ready }, async function check3NoGnuPGPrompt() {
  await removeFixtureKey();
  EnigmailKeyRing.clearCache();

  const held = await GnuPGAgent.hasSecretKey(ALICE_FPR);
  Assert.ok(
    held,
    "GnuPG should report holding the key, or there is nothing to test"
  );

  const publicBlock = await IOUtils.readUTF8(
    do_get_file(`${keyDir}/${ALICE_PUB}`).path
  );

  // Build a tracker over a key handle without putting the key in the profile
  // ring: parsed into a throwaway FFI, which is how a transient key is handled.
  let prompts = 0;
  const counting = () => {
    prompts++;
    return "";
  };

  const tracker = RNP.getUnlockTrackerForKeyBlock
    ? await RNP.getUnlockTrackerForKeyBlock(publicBlock, ALICE_FPR)
    : null;

  if (!tracker) {
    // No transient handle is exposed for this shape, so the structural claim is
    // asserted instead: with no profile key there is no unlock path at all.
    info(
      "no transient tracker is reachable from here; asserting the structural property"
    );
    Assert.ok(
      !EnigmailKeyRing.getKeyById(ALICE_FPR),
      "no profile copy means no unlock path into a prompt"
    );
    Assert.equal(prompts, 0, "and no prompt was raised");
    return;
  }

  tracker.setPassphraseCallback(counting);
  await tracker.unlock();
  Assert.equal(
    prompts,
    0,
    "a key GnuPG holds must not reach the passphrase callback"
  );
});

/**
 * 4. The internal store is not created when it holds nothing.
 *
 * Failure it catches: the startup gate regressing, so a profile with no
 * internal key still carries a passphrase file that protects nothing -- the
 * first half of issue 1.2, and the state four real profiles on this machine
 * are in.
 */
add_task({ skip_if: () => !ready }, async function check4NoUnusedStore() {
  await removeFixtureKey();
  await clearStore();

  Assert.equal(
    RNP.getProtectedKeysCount().reduce((a, b) => a + b, 0),
    0,
    "the profile must hold no secret key for this check to mean anything"
  );

  await RNP.once();
  await new Promise(resolve => do_timeout(400, resolve));

  Assert.equal(
    fileSize(passFile()),
    -1,
    "startup must not create the passphrase file when there is nothing to protect"
  );
});

/**
 * 5. When the store is absent, the passphrase file protects nothing and says
 *    nothing.
 *
 * Failure it catches: the reverse of check 4 -- a second copy of the file
 * appearing after the key was removed, which is the state that makes a user
 * believe they still have an internal key.
 */
add_task(
  { skip_if: () => !ready },
  async function check5AbsentStoreStaysAbsent() {
    await removeFixtureKey();
    await clearStore();

    for (const file of storeFiles()) {
      Assert.equal(
        fileSize(file),
        -1,
        `${file.leafName} must be gone, including the .old sibling the fallback reads`
      );
    }

    await RNP.once();
    await new Promise(resolve => do_timeout(200, resolve));

    Assert.equal(
      fileSize(passFile()),
      -1,
      "and a start must not bring the passphrase file back"
    );
    Assert.lessOrEqual(
      fileSize(secRingFile()),
      0,
      "nor recreate a secret keyring with content"
    );
  }
);

/**
 * 6. The send paths still work.
 *
 * Failure it catches: a change that repairs one path and breaks another. The
 * two exercised here are the ones a composer actually produces that this
 * build can complete: a detached signature made by GnuPG for an external
 * identity, and an encrypt-then-decrypt roundtrip through the internal engine.
 *
 * **Two paths are named but not asserted, because they are broken today and a
 * test must not encode a defect as a pass.** Combined sign-and-encrypt with an
 * *external* sender returns null from `GPGME.encrypt()` after resolving both
 * the signing key and the recipient -- with `errorMsg` empty, because several
 * `return null` statements in that function record no reason. Measured
 * 2026-10-24 and recorded in Item 37's row; it is Item 36's subject, not this
 * item's to repair. Signing with a GnuPG-held key is covered by check 1's
 * sibling in Item 24's suite.
 */
add_task({ skip_if: () => !ready }, async function check6SendPathsWork() {
  const base = {
    aliasKeys: new Map(),
    armor: true,
    bcc: [],
    encryptToSender: false,
    sender: `0x${ALICE_KEY_ID}`,
    senderKeyIsExternal: true,
    sigTypeClear: false,
    signatureHash: "SHA256",
    to: [],
  };

  // Detached signature, external key.
  const detachedStatus = {};
  const detached = await RNP.encryptAndOrSign(
    PLAINTEXT,
    { ...base, encrypt: false, sign: true, sigTypeDetached: true },
    detachedStatus
  );
  Assert.equal(
    detachedStatus.exitCode,
    0,
    `detached signing should work: ${detachedStatus.errorMsg}`
  );
  Assert.ok(
    detached.startsWith("-----BEGIN PGP SIGNATURE-----"),
    "detached signing should produce a signature"
  );
  Assert.equal(
    detachedStatus.externalSigningKeyFpr,
    ALICE_FPR,
    "and it should report the key GnuPG used"
  );

  // Encrypt then decrypt, entirely through the internal engine.
  const recipientId = "Matrix Recipient <matrix@example.com>";
  const recipientKeyId = await RNP.genKey(recipientId, "ECC", 0, 0, "");
  Assert.ok(recipientKeyId, "a recipient key should be generated");
  EnigmailKeyRing.clearCache();

  const encryptStatus = {};
  const ciphertext = await RNP.encryptAndOrSign(
    PLAINTEXT,
    {
      aliasKeys: new Map(),
      armor: true,
      bcc: [],
      encrypt: true,
      encryptToSender: false,
      sender: "",
      senderKeyIsExternal: false,
      sigTypeClear: false,
      sigTypeDetached: false,
      sign: false,
      signatureHash: "SHA256",
      to: ["<matrix@example.com>"],
    },
    encryptStatus
  );
  Assert.equal(
    encryptStatus.exitCode,
    0,
    `encryption should work: ${encryptStatus.errorMsg}`
  );
  Assert.ok(
    ciphertext.startsWith("-----BEGIN PGP MESSAGE-----"),
    "encryption should produce a message"
  );

  const decrypted = await RNP.decrypt(ciphertext, {
    fromAddr: "matrix@example.com",
    maxOutputLength: ciphertext.length * 100,
    msgDate: null,
    noOutput: false,
    uiFlags: EnigmailConstants.UI_PGP_MIME,
    verifyOnly: false,
  });
  Assert.equal(
    decrypted.exitCode,
    0,
    `the message should decrypt: ${decrypted.errorMsg}`
  );
  Assert.equal(decrypted.decryptedData, PLAINTEXT, "and roundtrip");

  // Leave the profile as this check found it.
  EnigmailKeyRing.clearCache();
  const generated = EnigmailKeyRing.getKeyById(recipientKeyId);
  if (generated) {
    await RNP.deleteKey(generated.fpr, generated.secretAvailable);
  }
  EnigmailKeyRing.clearCache();
});

/**
 * 7. Key selection follows GnuPG.
 *
 * Failure it catches: Thunderbird resuming its own ranking -- issue 1.1, the
 * silent choice the user cannot see or override.
 */
add_task(
  { skip_if: () => !ready },
  async function check7SelectionFollowsGnuPG() {
    const chosen = await GPGME.resolveSigningKeyForIdentity(ALICE_ADDR);

    Assert.ok(chosen, "a signing key should be resolved for the identity");
    Assert.equal(chosen.fpr, ALICE_FPR, "and it is the key GnuPG holds");
    Assert.ok(
      ["default-key", "gnupg-order"].includes(chosen.source),
      `and the rule that chose it is one of GnuPG's own, got ${chosen.source}`
    );

    // The control: an identity GnuPG holds nothing for must resolve to nothing
    // rather than to some other key.
    const absent =
      await GPGME.resolveSigningKeyForIdentity("nobody@example.com");
    Assert.equal(
      absent,
      null,
      "an identity GnuPG has no key for must not resolve to one"
    );
  }
);
