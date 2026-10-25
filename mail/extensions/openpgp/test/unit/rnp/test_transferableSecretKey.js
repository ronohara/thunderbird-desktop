/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 96: export an identity's key as a Transferable Secret Key.
 *
 * RFC 9580 10.2 defines the container -- public-key packets with Secret-Key
 * and Secret-Subkey packets added -- and the Autocrypt specification adds what
 * has to be around it. Four claims, in the order their absence would hurt:
 *
 *   - **the stored key's protection is unchanged**, which is the one the item
 *     says to verify and the one a careless reuse of the import path would
 *     break. `importToFFI`'s neighbourhood calls `unprotect()` and
 *     `setAutoPassphrase()` before re-exporting, because it is mid-import and
 *     the key is being replaced; doing that here would leave the user's own key
 *     readable without a passphrase, in their profile, permanently;
 *   - the export is a **secret** key block, not a public one;
 *   - it carries **Autocrypt-Prefer-Encrypt** with one of the two legal values;
 *   - it is **cut at the first end delimiter**, which the specification
 *     requires and which nothing else in the build would notice.
 *
 * The fixture is protected with a user-chosen passphrase, because an
 * unprotected key cannot fail the first check: `rnp_key_is_protected` would be
 * false before and after, and the test would pass on a build that had stripped
 * the passphrase.
 */

"use strict";

const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { RNPLibLoader } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNPLib.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { ctypes } = ChromeUtils.importESModule(
  "resource://gre/modules/ctypes.sys.mjs"
);
const { Subprocess } = ChromeUtils.importESModule(
  "resource://gre/modules/Subprocess.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";
const ALICE_SECRET_WITH_PP =
  "alice@openpgp.example-0xf231550c4f47e38e-secret-with-pp.asc";
const ALICE_FPR = "EB85BB5FA33A75E15E944E63F231550C4F47E38E";
const ALICE_KEY_ID = "F231550C4F47E38E";

/**
 * Whether the library considers the stored key protected and locked.
 *
 * Asked of librnp through a handle on the live ffi, because the claim is about
 * what is on disk rather than about a cached key object.
 *
 * @returns {{protected: boolean, locked: boolean}}
 */
function protectionState() {
  const lib = RNP.getRNPLib();
  const handle = RNP.getKeyHandleByKeyIdOrFingerprint(
    lib.ffi,
    "0x" + ALICE_FPR
  );
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

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();

  // Alice's key, protected with her own passphrase, imported with that
  // passphrase kept -- so the key in the profile is locked, which is the state
  // the export must not disturb.
  // The third argument is the *acceptance* value, the fourth the passphrase,
  // and the fifth says to keep the user's own passphrase rather than replacing
  // it with the automatic one. Passing the passphrase third is what made the
  // first version of this file hang: the key was imported unreadable, and the
  // export below then asked the pass provider for a passphrase, which in a
  // test has nobody to answer it.
  await OpenPGPTestUtils.importPrivateKey(
    null,
    do_get_file(`${keyDir}/${ALICE_SECRET_WITH_PP}`),
    OpenPGPTestUtils.ACCEPTANCE_PERSONAL,
    "alice-passphrase",
    true
  );
  EnigmailKeyRing.clearCache();
  Assert.ok(
    EnigmailKeyRing.getKeyById(`0x${ALICE_FPR}`)?.secretAvailable,
    "the protected secret key is in the profile"
  );
});

/**
 * The claim the item asks to be verified: protection unchanged.
 *
 * Checked before and after, and by attempting an unlock with no passphrase
 * afterwards -- because `rnp_key_is_protected` reads a flag, and a flag is not
 * the same as the behaviour the flag describes.
 */
add_task(async function theStoredKeyStaysProtected() {
  const before = protectionState();
  info(`FINDING protection before: ${JSON.stringify(before)}`);
  Assert.ok(before.protected, "the fixture key is protected to begin with");

  const armoured = RNP.exportSecretKeyForTransfer(ALICE_FPR, "mutual");
  Assert.ok(armoured, "the export produced a key block");

  const after = protectionState();
  info(`FINDING protection after: ${JSON.stringify(after)}`);
  Assert.equal(
    after.protected,
    before.protected,
    "the stored key is still protected after the export"
  );
  Assert.equal(
    after.locked,
    before.locked,
    "and still locked, so nothing unlocked it in passing"
  );

  // The behavioural half: an attempt to unlock with an empty passphrase must
  // fail. A build that had stripped the passphrase would succeed here.
  const lib = RNP.getRNPLib();
  const handle = RNP.getKeyHandleByKeyIdOrFingerprint(
    lib.ffi,
    "0x" + ALICE_FPR
  );
  try {
    const rc = lib.rnp_key_unlock(handle, "");
    info(`FINDING unlock with empty passphrase: rc=${rc}`);
    Assert.notEqual(
      rc,
      0,
      "unlocking with an empty passphrase fails, so the key still has one"
    );
  } finally {
    lib.rnp_key_handle_destroy(handle);
  }
});

/**
 * The block is a secret key block, not a public one, and it is armoured.
 */
add_task(async function theExportIsASecretArmoredBlock() {
  const block = RNP.exportSecretKeyForTransfer(ALICE_FPR, "mutual");
  Assert.ok(
    block.includes("BEGIN PGP PRIVATE KEY BLOCK"),
    "an armoured transferable secret key"
  );
  Assert.ok(
    !block.includes("BEGIN PGP PUBLIC KEY BLOCK"),
    "not a public key block"
  );
  // The subkeys travel with it: a TSK without its encryption subkey could not
  // decrypt anything sent to the identity.
  const parsed = await RNP.getKeyListFromKeyBlockImpl(block, false, true);
  Assert.equal(parsed.length, 1, "the block holds one key");
  Assert.ok(
    parsed[0].subKeys.length,
    "with its subkeys, which is what makes it transferable"
  );
});

/**
 * The Autocrypt preference reaches the armour header, where a receiver reads it.
 */
add_task(async function thePreferenceIsInTheArmorHeader() {
  for (const value of ["mutual", "nopreference"]) {
    const block = RNP.exportSecretKeyForTransfer(ALICE_FPR, value);
    const lines = block.split("\n");
    Assert.ok(
      lines[0].startsWith("-----BEGIN PGP PRIVATE KEY BLOCK"),
      "the block begins with the armour line"
    );
    Assert.equal(
      lines[1],
      `Autocrypt-Prefer-Encrypt: ${value}`,
      "and the preference is the line immediately after it, inside the armour"
    );
    // The header region ends at a **blank line**, which RFC 4880 requires and
    // which the first version of this helper dropped -- producing `BEGIN`,
    // header, base64 with no separation. gpg then rejected the first base64
    // line as "invalid armor header", while the block still looked correct to a
    // reader. So the assertion is that the blank line is there and that the
    // preference is above it, not merely that the preference is present.
    const firstBlank = lines.indexOf("");
    info(
      `FINDING armor headers: ` +
        `${JSON.stringify(lines.slice(0, firstBlank + 1))}`
    );
    Assert.greater(firstBlank, 1, "there is a header region ending in a blank");
    Assert.equal(
      lines[firstBlank],
      "",
      "the header region ends with a blank line"
    );
    Assert.ok(
      lines.slice(0, firstBlank).includes(`Autocrypt-Prefer-Encrypt: ${value}`),
      "and the preference is inside the header region"
    );
    Assert.ok(
      lines[firstBlank + 1]?.length && !lines[firstBlank + 1].includes(":"),
      "with the base64 body starting after the blank line, not a header"
    );
  }
});

/**
 * A value the specification does not define is refused rather than passed on.
 *
 * A receiver that does not recognise a value treats it as absent, so writing an
 * invented one would silently lose the user's preference and neither side would
 * report anything.
 */
add_task(async function anUndefinedPreferenceIsRefused() {
  for (const bad of ["", "Mutual", "yes", "nopreference "]) {
    let threw = false;
    try {
      RNP.exportSecretKeyForTransfer(ALICE_FPR, bad);
    } catch (ex) {
      threw = true;
    }
    Assert.ok(threw, `${JSON.stringify(bad)} is refused`);
  }
});

/**
 * Trailing data after the first end delimiter is stripped.
 *
 * The specification says MUST, and the clause exists because a block with
 * material after the end line is one that some implementations refuse. Tested
 * on the helper directly, so the assertion is about the stripping rather than
 * about whether librnp happened to emit trailing bytes this time.
 */
add_task(async function trailingDataIsStripped() {
  const block = RNP.exportSecretKeyForTransfer(ALICE_FPR, "mutual");
  const withTrailing =
    block +
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\njunk\n-----END PGP PUBLIC KEY BLOCK-----\n";

  const prepared = RNP._prepareTransferKeyBlock(withTrailing, "mutual");
  const endCount =
    prepared.split("-----END PGP PRIVATE KEY BLOCK-----").length - 1;
  info(
    `FINDING stripping: ends=${endCount} ` +
      `containsTrailing=${prepared.includes("junk")}`
  );
  Assert.equal(endCount, 1, "exactly one end delimiter survives");
  Assert.ok(
    !prepared.includes("junk"),
    "and nothing after it does: the second block is gone"
  );
  Assert.ok(
    prepared.trimEnd().endsWith("-----END PGP PRIVATE KEY BLOCK-----"),
    "the block ends at its own end delimiter"
  );
});

/**
 * And another implementation parses it.
 *
 * The claim is about a format meant to be read elsewhere, so the check that
 * means anything is gpg's. This is the one that caught the missing blank line
 * between the armour headers and the body: every shape assertion above passed
 * while gpg called the first base64 line an invalid header.
 */
add_task(async function gpgParsesTheExportedBlock() {
  let gpgPath;
  try {
    gpgPath = await Subprocess.pathSearch("gpg");
  } catch (ex) {
    info("SKIPPED: no gpg executable.");
    Assert.ok(true, "skipped");
    return;
  }

  const block = RNP.exportSecretKeyForTransfer(ALICE_FPR, "mutual");
  const dir = do_get_tempdir();
  dir.append("item96");
  dir.createUnique(Ci.nsIFile.DIRECTORY_TYPE, 0o700);
  const path = PathUtils.join(dir.path, "tsk.asc");
  await IOUtils.writeUTF8(path, block);

  const process = await Subprocess.call({
    command: gpgPath,
    arguments: [
      "--batch",
      "--no-tty",
      "--pinentry-mode",
      "loopback",
      "--passphrase",
      "alice-passphrase",
      "--list-packets",
      path,
    ],
    environment: { GNUPGHOME: dir.path },
    environmentAppend: true,
    stdout: "pipe",
    stderr: "pipe",
  });
  const stdout = await process.stdout.readString();
  const stderr = await process.stderr.readString();
  const { exitCode } = await process.wait();
  dir.remove(true);

  info(`FINDING gpg: exit=${exitCode} stderr=${JSON.stringify(stderr.trim())}`);
  Assert.equal(
    stderr.includes("invalid armor header"),
    false,
    "gpg accepts every armour header, including the one added here"
  );
  Assert.equal(exitCode, 0, `gpg reads the key block: ${stderr.trim()}`);
  Assert.ok(
    stdout.includes("secret key packet"),
    "and it sees secret key material, so this is a transferable secret key"
  );
  Assert.ok(
    stdout.includes("secret sub key packet"),
    "with its secret subkeys"
  );
});
