/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 95: a message can be encrypted to a passphrase.
 *
 * `rnp_op_encrypt_add_password` was the one member of its family missing from
 * the bindings, so no SKESK packet could be created and a password-carrying
 * message could not exist. The library exported the symbol all along -- both
 * shipped libraries define it -- which is what turned the row from Blocked
 * into work.
 *
 * **Why gpg is in these checks.** The item's own concern is that a default
 * "would be a conformance defect nobody would notice until another
 * implementation refused the message". So the message this build produces is
 * handed to `gpg --list-packets`, which reports the cipher and the S2K the
 * way an independent implementation reads them, and then to `gpg --decrypt`
 * with the passphrase. An assertion against our own reader would agree with a
 * defect in both directions.
 *
 * Three things are checked, and the third is the one that would otherwise
 * never be noticed:
 *
 *   - the message decrypts with the passphrase, in another implementation;
 *   - the SKESK carries AES-128 or AES-256, as RFC 9580 5.3 requires;
 *   - the S2K is the salted, iterated kind, with an iteration count that is
 *     this build's stated figure rather than whatever rnp would have chosen.
 */

"use strict";

const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { RNPLibLoader } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNPLib.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { Subprocess } = ChromeUtils.importESModule(
  "resource://gre/modules/Subprocess.sys.mjs"
);

const PLAINTEXT = "Item 95: encrypted to a passphrase.\n";
const PASSPHRASE = "item95-passphrase";

let gpgPath = null;
let tempDir = null;

/**
 * @param {string[]} args
 * @param {Uint8Array} [stdinBytes]
 * @returns {Promise<{exitCode: integer, stdout: string, stderr: string}>}
 */
async function runGpg(args, stdinBytes) {
  const process = await Subprocess.call({
    command: gpgPath,
    // `--pinentry-mode loopback` with an explicit passphrase is what stops a
    // prompt: `--list-packets` unlocks the session key to describe the
    // contents, and without this it asks, which on a desktop means a dialog.
    arguments: [
      "--batch",
      "--no-tty",
      "--yes",
      "--no-symkey-cache",
      "--pinentry-mode",
      "loopback",
      ...args,
    ],
    stdin: stdinBytes ? "pipe" : "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
  if (stdinBytes) {
    process.stdin.write(stdinBytes);
    await process.stdin.close();
  }
  const stdout = await process.stdout.readString();
  const stderr = await process.stderr.readString();
  const { exitCode } = await process.wait();
  return { exitCode, stdout, stderr };
}

/**
 * The bytes of an armored message, for handing to a child process.
 *
 * @param {string} text
 * @returns {Uint8Array}
 */
function bytes(text) {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) {
    out[i] = text.charCodeAt(i) & 0xff;
  }
  return out;
}

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();

  try {
    gpgPath = await Subprocess.pathSearch("gpg");
  } catch (ex) {
    info("No gpg executable found; the conformance check needs one.");
  }

  tempDir = do_get_tempdir();
  tempDir.append("item95");
  tempDir.createUnique(Ci.nsIFile.DIRECTORY_TYPE, 0o700);

  // A throwaway home, and a pinentry that cannot exist.
  //
  // Both are load-bearing. Without the first, gpg reads the user's own keyring
  // and starts its agent there. Without the second, a command that decides it
  // needs a passphrase **puts a dialog on the user's screen** and leaves this
  // test blocked behind it -- which is what the first run of this file did:
  // `gpg --list-packets` on a symmetric message asks to unlock the session key,
  // found no configured pinentry here, fell back to the desktop one, and a
  // window appeared for the user while the harness waited out its budget.
  //
  // Pointing `pinentry-program` at a path that does not exist makes gpg fail
  // immediately and predictably instead.
  const gnupgHome = tempDir.clone();
  gnupgHome.append("gnupg");
  gnupgHome.createUnique(Ci.nsIFile.DIRECTORY_TYPE, 0o700);
  await IOUtils.writeUTF8(
    PathUtils.join(gnupgHome.path, "gpg-agent.conf"),
    "pinentry-program /nonexistent/item95-no-pinentry\n"
  );
  const previousHome = Services.env.exists("GNUPGHOME")
    ? Services.env.get("GNUPGHOME")
    : "";
  Services.env.set("GNUPGHOME", gnupgHome.path);

  registerCleanupFunction(async () => {
    // Killed with gpgconf under this home, so the agent this test started does
    // not outlive it and no dialog survives the run.
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
    tempDir.remove(true);
  });
});

/**
 * The binding exists on the library this build loaded.
 *
 * Cheap, and it is the check the row asked for as its first action: whether
 * the function is there at all. It was recorded as Blocked because nobody
 * looked.
 */
add_task(async function theLibraryExportsTheCall() {
  const lib = RNPLibLoader.init();
  Assert.ok(lib?.loaded, "librnp loaded");
  Assert.equal(
    typeof lib.rnp_op_encrypt_add_password,
    "function",
    "rnp_op_encrypt_add_password is bound, which the row had recorded as a " +
      "missing declaration and a possible library upgrade"
  );
});

/**
 * A message encrypted to a passphrase, decrypted by gpg.
 *
 * The claim is not "our reader accepts our writer" but "another implementation
 * does", which is the only version of the claim that can fail when the format
 * is wrong.
 */
add_task(async function gpgDecryptsWhatWeProduce() {
  if (!gpgPath) {
    info("SKIPPED: no gpg executable.");
    Assert.ok(true, "skipped");
    return;
  }

  const encrypted = RNP.encryptWithPassword(PLAINTEXT, PASSPHRASE, {
    cipher: "AES256",
  });
  Assert.ok(
    encrypted.includes("BEGIN PGP MESSAGE"),
    "the output is one armored message"
  );

  const { exitCode, stdout, stderr } = await runGpg(
    ["--pinentry-mode", "loopback", "--passphrase", PASSPHRASE, "--decrypt"],
    bytes(encrypted)
  );
  info(`FINDING gpg decrypt exit=${exitCode}`);
  Assert.equal(exitCode, 0, `gpg decrypts it: ${stderr}`);
  Assert.ok(
    stdout.includes(PLAINTEXT.trim()),
    `and returns the plaintext, got ${JSON.stringify(stdout.slice(0, 120))}`
  );
});

/**
 * The packet gpg reports carries the cipher RFC 9580 permits and the S2K this
 * build states.
 *
 * Read from `gpg --list-packets`, which prints the SKESK's own fields. This is
 * the check the item exists for: a default cipher of AES-192 would pass every
 * decrypt test above and be a conformance defect.
 */
add_task(async function theSkeskIsConformant() {
  if (!gpgPath) {
    info("SKIPPED: no gpg executable.");
    Assert.ok(true, "skipped");
    return;
  }

  const encrypted = RNP.encryptWithPassword(PLAINTEXT, PASSPHRASE, {
    cipher: "AES256",
  });

  const cipherPath = PathUtils.join(tempDir.path, "msg.asc");
  await IOUtils.writeUTF8(cipherPath, encrypted);

  const { exitCode, stdout, stderr } = await runGpg([
    "--passphrase",
    PASSPHRASE,
    "--list-packets",
    cipherPath,
  ]);
  Assert.equal(exitCode, 0, `gpg lists the packets: ${stderr.trim()}`);

  // :symkey enc packet: version 4, cipher 9, s2k 3, hash 8
  // cipher 7 = AES128, 8 = AES192, 9 = AES256; s2k 3 = iterated+salted.
  const skesk = stdout.split("\n").find(l => l.includes("symkey enc packet"));
  info(`FINDING SKESK: ${skesk}`);
  Assert.ok(skesk, "the message carries an SKESK packet");

  const cipher = Number(/cipher (\d+)/.exec(skesk)?.[1]);
  Assert.ok(
    cipher == 7 || cipher == 9,
    `RFC 9580 5.3 permits AES-128 (7) or AES-256 (9); the packet says ` +
      `${cipher}${cipher == 8 ? ", which is AES-192 and not permitted" : ""}`
  );

  const s2k = Number(/s2k (\d+)/.exec(skesk)?.[1]);
  Assert.equal(
    s2k,
    3,
    "the S2K is iterated and salted (type 3), as the specification requires, " +
      "rather than a simple or salted-only derivation"
  );
});

/**
 * The cipher is chosen by the caller, and a value the specification forbids is
 * refused here rather than passed to rnp.
 *
 * rnp accepts more ciphers than RFC 9580 allows. Leaving the choice to it, or
 * forwarding whatever a future caller asked for, would put the conformance
 * rule somewhere nobody tests.
 */
add_task(async function aCipherTheRfcForbidsIsRefused() {
  Assert.throws(
    () => RNP.encryptWithPassword(PLAINTEXT, PASSPHRASE, { cipher: "AES192" }),
    /AES-128 or AES-256/,
    "AES-192 is refused before rnp sees it"
  );

  // And the permitted pair both work, so the guard is not simply refusing.
  const aes128 = RNP.encryptWithPassword(PLAINTEXT, PASSPHRASE, {
    cipher: "AES128",
  });
  Assert.ok(aes128.includes("BEGIN PGP MESSAGE"), "AES-128 produces a message");
});

/**
 * The iteration count is this build's figure, not rnp's default.
 *
 * `gpg --list-packets` prints the encoded count as a number when it decodes
 * the S2K; what is asserted here is that a caller-specified count reaches the
 * packet, by comparing two messages made with visibly different counts.
 */
add_task(async function theIterationCountIsOurs() {
  if (!gpgPath) {
    info("SKIPPED: no gpg executable.");
    Assert.ok(true, "skipped");
    return;
  }

  const low = RNP.encryptWithPassword(PLAINTEXT, PASSPHRASE, {
    cipher: "AES256",
    iterations: 1024,
  });
  const high = RNP.encryptWithPassword(PLAINTEXT, PASSPHRASE, {
    cipher: "AES256",
    iterations: 4194304,
  });

  const lowPath = PathUtils.join(tempDir.path, "low.asc");
  const highPath = PathUtils.join(tempDir.path, "high.asc");
  await IOUtils.writeUTF8(lowPath, low);
  await IOUtils.writeUTF8(highPath, high);

  const lowOut = (
    await runGpg(["--passphrase", PASSPHRASE, "--list-packets", lowPath])
  ).stdout;
  const highOut = (
    await runGpg(["--passphrase", PASSPHRASE, "--list-packets", highPath])
  ).stdout;

  // gpg prints the S2K's salt and count on the line *after* the packet
  // header, so the block has to be read as two lines:
  //   :symkey enc packet: version 4, cipher 9, aead 0, s2k 3, hash 8
  //       salt 00ED4F80B911CA2C, count 65011712 (255)
  // Reading only the header line finds no count at all, which is how the first
  // version of this check compared 0 against 0 and failed for a reason that
  // had nothing to do with the iteration count.
  const countOf = text => {
    const lines = text.split("\n");
    const header = lines.findIndex(l => l.includes("symkey enc packet"));
    if (header < 0) {
      return 0;
    }
    const countLine = lines[header + 1] ?? "";
    return Number(/count (\d+)/.exec(countLine)?.[1] ?? 0);
  };

  info(
    `FINDING S2K counts: low=${countOf(lowOut)} high=${countOf(highOut)} ` +
      `(the default when unstated is ${RNP.S2K_ITERATIONS})`
  );
  Assert.greater(
    countOf(highOut),
    countOf(lowOut),
    "a larger iteration count reaches the packet, so the figure is the " +
      "caller's rather than rnp's default in both cases"
  );
});
