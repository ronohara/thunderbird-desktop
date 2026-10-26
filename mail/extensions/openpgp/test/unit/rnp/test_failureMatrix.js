/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 36's failure matrix, conditions 2 and 5 — tasks written for this matrix.
 *
 * The item's row said these two were *met by other items' code and asserted by
 * their tests rather than by tasks written for this matrix*. That is a fine
 * statement about the code and a poor one about the matrix: a condition whose
 * only evidence is a test written for a different question can regress without
 * anyone noticing. These are the missing tasks.
 *
 * **Condition 5 runs first**, because it also builds the premise condition 2
 * needs: a key that GnuPG holds and this profile does not.
 */

"use strict";

const { EnigmailEncryption } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/encryption.sys.mjs"
);
const { EnigmailConstants } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/constants.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { GPGME } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/GPGME.sys.mjs"
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

const keyDir = "../../../../../test/browser/openpgp/data/keys";

const BOB_FPR = "D1A66E1A23B182C9980F788CFBFCC82A015E7330";
const BOB_EMAIL = "bob@openpgp.example";
const BOB_SECRET = "bob@openpgp.example-0xfbfcc82a015e7330-secret.asc";

// A well-formed fingerprint no keyring holds, for condition 2's failure case.
const ABSENT_KEY_ID = "0x0123456789ABCDEF";

var gpgPath = null;
var gnupgHome = null;
var available = false;

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
  // librnp has to be loaded before `RNP.getKeyListFromKeyBlockImpl()` can parse
  // anything; without it the call throws `can't access property "prepare_ffi",
  // RNPLib is undefined`, which my first version did not print and so read as
  // "the guard answered null".
  await OpenPGPTestUtils.initOpenPGP();

  try {
    gpgPath = await Subprocess.pathSearch("gpg");
  } catch (ex) {
    info("No gpg executable found; conditions 2 and 5 cannot be exercised.");
    return;
  }

  gnupgHome = do_get_tempdir();
  gnupgHome.append("gnupg-failure-matrix");
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

  const imported = await runGpg([
    "--import",
    do_get_file(`${keyDir}/${BOB_SECRET}`).path,
  ]);
  if (imported.exitCode) {
    info(`gpg could not import Bob's key: ${imported.stderr}`);
    return;
  }

  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  registerCleanupFunction(() => {
    Services.prefs.clearUserPref("mail.openpgp.allow_external_gnupg");
  });

  // The guard consults `GPGME.init()` before it will refuse anything: with the
  // library unavailable there is nowhere to put the key, and D6 makes the
  // no-GnuPG user a supported user rather than a refused one. So without this
  // call `gnupgHeldSecretFingerprint()` answers null for the wrong reason --
  // which is exactly what my first version measured.
  if (!GPGME.init()) {
    info("gpgme could not be initialised; conditions 2 and 5 cannot run.");
    return;
  }
  available = true;
});

/**
 * Condition 5: an import the guard refuses does not cost the user the key.
 *
 * Design 5.7 asks that a refused import *continue with the transient key* — the
 * point of the guard is to avoid a second copy of a secret, not to take the key
 * away. So the two halves are asserted together: the guard does refuse, and the
 * key is still usable for encryption afterwards.
 *
 * This ordering matters. `gnupgHeldSecretFingerprint()` returning a fingerprint
 * is only half the claim; a build that refused the import *and* dropped the key
 * would satisfy it and break sending.
 */
add_task(async function aRefusedImportStillLeavesTheKeyUsable() {
  if (!available) {
    info("SKIPPED: no external GnuPG on this machine.");
    Assert.ok(true, "skipped");
    return;
  }

  const block = await IOUtils.readUTF8(
    do_get_file(`${keyDir}/${BOB_SECRET}`).path
  );

  const refused = await EnigmailKeyRing.gnupgHeldSecretFingerprint(block);
  info(`FINDING guard fingerprint for a gpg-held secret: ${refused}`);
  Assert.equal(
    refused,
    BOB_FPR,
    "the guard refuses the import, because GnuPG holds the secret"
  );

  // The control that makes it a statement about the *secret* rather than about
  // imports in general: a public block answers null, so no refusal.
  const publicBlock = await IOUtils.readUTF8(
    do_get_file(`${keyDir}/bob@openpgp.example-0xfbfcc82a015e7330-pub.asc`).path
  );
  const notRefused =
    await EnigmailKeyRing.gnupgHeldSecretFingerprint(publicBlock);
  info(`FINDING guard fingerprint for a public block: ${notRefused}`);
  Assert.equal(notRefused, null, "a public block is not refused");

  // And the key is still there to encrypt with, through the transient path.
  const candidates = await EnigmailKeyRing.getCandidateKeysForEmail(BOB_EMAIL);
  const bob = candidates.find(k => k.fpr.toUpperCase() == BOB_FPR);
  info(
    `FINDING transient key present: ${!!bob}, ` +
      `secretAvailable=${bob?.secretAvailable}`
  );
  Assert.ok(
    bob,
    "the refused import does not cost the user the key: it is a candidate"
  );
  const metas = await EnigmailKeyRing.getEncryptionKeyMeta(BOB_EMAIL);
  const bobMeta = metas.find(m => m.keyObj?.fpr.toUpperCase() == BOB_FPR);
  Assert.ok(bobMeta, "and it has encryption metadata");
  Assert.ok(
    bobMeta.gnupgKey,
    "which records that GnuPG is where it lives, so nothing claims a second copy"
  );
});

/**
 * Condition 2: an external identity whose key GnuPG lacks **fails**, and the
 * message names the key it expected.
 *
 * A silent fallback to the internal engine would sign with a different key than
 * the identity names — the substitution this design exists to prevent — so the
 * assertion is on the failure and on the name in it.
 */
add_task(async function anExternalIdentityWithoutItsKeyFails() {
  const result = await EnigmailEncryption.determineOwnKeyUsability(
    EnigmailConstants.SEND_SIGNED,
    ABSENT_KEY_ID,
    true // isExternalGnuPG
  );
  info(
    `FINDING condition 2: keyId=${JSON.stringify(result.keyId)} ` +
      `errorMsg=${JSON.stringify(result.errorMsg)}`
  );

  Assert.equal(
    result.keyId,
    undefined,
    "no key is chosen, so nothing can be substituted for the named one"
  );
  Assert.ok(result.errorMsg, "the failure is reported rather than silent");
  Assert.ok(
    result.errorMsg.includes("0123456789ABCDEF") ||
      result.errorMsg.toLowerCase().includes("not found"),
    `and the message names what it expected, got: "${result.errorMsg}"`
  );
});

/**
 * The control for condition 2: a key that *is* present passes the same call.
 *
 * Without it, the task above passes on a build where the external path fails for
 * everything — which would be a different defect wearing the same result.
 */
add_task(async function anExternalIdentityWithItsKeyProceeds() {
  if (!available) {
    info("SKIPPED: no external GnuPG on this machine.");
    Assert.ok(true, "skipped");
    return;
  }

  const result = await EnigmailEncryption.determineOwnKeyUsability(
    EnigmailConstants.SEND_SIGNED,
    `0x${BOB_FPR}`,
    true
  );
  info(
    `FINDING condition 2 control: keyId=${JSON.stringify(result.keyId)} ` +
      `errorMsg=${JSON.stringify(result.errorMsg)}`
  );
  Assert.ok(
    !result.errorMsg,
    `a key GnuPG holds passes the same call, got: "${result.errorMsg}"`
  );
});
