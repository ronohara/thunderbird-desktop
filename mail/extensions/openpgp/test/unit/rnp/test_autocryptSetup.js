/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 98: the message's structure, checked against gpg's reading of it.
 *
 * Every clause is a MUST somewhere, so each one gets an assertion rather than
 * a comment:
 *
 *   - `To:` and `From:` are both the user's address;
 *   - `Autocrypt-Setup-Message: v1` marks it;
 *   - `multipart/mixed`, human part first, `application/autocrypt-setup`
 *     second;
 *   - **exactly two OpenPGP packets inside the armour: SKESK then SEIPD** --
 *     read from gpg's own `--list-packets`, because "exactly two" is a claim
 *     about a format another implementation has to parse;
 *   - the armour carries `Passphrase-Format: numeric9x4` and a
 *     `Passphrase-Begin` matching the code's first two digits;
 *   - the code opens it, which is the property the whole thing exists for.
 */

"use strict";

const { AutocryptSetup } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/autocryptSetup.sys.mjs"
);
const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { SetupCode } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/setupCode.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { Subprocess } = ChromeUtils.importESModule(
  "resource://gre/modules/Subprocess.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";
const ALICE_SECRET_WITH_PP =
  "alice@openpgp.example-0xf231550c4f47e38e-secret-with-pp.asc";
const ALICE_FPR = "EB85BB5FA33A75E15E944E63F231550C4F47E38E";
const ALICE_ADDRESS = "alice@openpgp.example";
const CODE = "1234-5678-9012-3456-7890-1234-5678-9012-3456";

let gpgPath = null;
let tempDir = null;

/**
 * @param {string[]} args
 * @returns {Promise<{exitCode: integer, stdout: string, stderr: string}>}
 */
async function runGpg(args) {
  const process = await Subprocess.call({
    command: gpgPath,
    arguments: [
      "--batch",
      "--no-tty",
      "--yes",
      "--no-symkey-cache",
      "--pinentry-mode",
      "loopback",
      ...args,
    ],
    environment: { GNUPGHOME: tempDir.path },
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
 * The armoured block out of the message's second part.
 *
 * Deliberately naive: the reader in a receiving client also has to find the
 * block among other text, and the specification requires a reader to ignore
 * what surrounds it.
 *
 * @param {string} message
 * @returns {string}
 */
function armourOf(message) {
  const start = message.indexOf("-----BEGIN PGP MESSAGE-----");
  const end = message.indexOf("-----END PGP MESSAGE-----");
  Assert.greater(start, -1, "the message contains an armoured block");
  Assert.greater(end, start, "which is terminated");
  return message.slice(start, end + "-----END PGP MESSAGE-----".length) + "\n";
}

/**
 * @returns {Promise<string>} A built message.
 */
async function buildMessage() {
  const keyBlock = RNP.exportSecretKeyForTransfer(ALICE_FPR, "mutual");
  Assert.ok(keyBlock, "the key exports");
  return AutocryptSetup.buildMessage({
    address: ALICE_ADDRESS,
    setupCode: CODE,
    keyBlock,
    preferEncrypt: "mutual",
  });
}

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();

  // Alice's key, protected and kept protected: the TSK the message carries is
  // the one she has, passphrase and all.
  await OpenPGPTestUtils.importPrivateKey(
    null,
    do_get_file(`${keyDir}/${ALICE_SECRET_WITH_PP}`),
    OpenPGPTestUtils.ACCEPTANCE_PERSONAL,
    "alice-passphrase",
    true
  );

  try {
    gpgPath = await Subprocess.pathSearch("gpg");
  } catch (ex) {
    info("No gpg executable found; the packet checks need one.");
  }

  tempDir = do_get_tempdir();
  tempDir.append("item98");
  tempDir.createUnique(Ci.nsIFile.DIRECTORY_TYPE, 0o700);
  await IOUtils.writeUTF8(
    PathUtils.join(tempDir.path, "gpg-agent.conf"),
    "pinentry-program /nonexistent/item98-no-pinentry\n"
  );

  registerCleanupFunction(async () => {
    try {
      const gpgconfPath = await Subprocess.pathSearch("gpgconf");
      const process = await Subprocess.call({
        command: gpgconfPath,
        arguments: ["--kill", "all"],
        environment: { GNUPGHOME: tempDir.path },
        environmentAppend: true,
        stderr: "pipe",
      });
      await process.stderr.readString();
      await process.wait();
    } catch (ex) {
      info(`Could not stop gpg-agent: ${ex.message}`);
    }
    tempDir.remove(true);
  });
});

/**
 * The headers both specifications require.
 */
add_task(async function theHeadersAreTheOnesSpecified() {
  const message = await buildMessage();
  const head = message.split("\r\n\r\n")[0];

  const header = name =>
    head
      .split("\r\n")
      .find(l => l.toLowerCase().startsWith(`${name.toLowerCase()}:`));

  Assert.equal(
    header("To"),
    `To: ${ALICE_ADDRESS}`,
    "To is the user's own address"
  );
  Assert.equal(
    header("From"),
    `From: ${ALICE_ADDRESS}`,
    "and so is From: the message is not addressed to anybody else"
  );
  Assert.equal(
    header("Autocrypt-Setup-Message"),
    "Autocrypt-Setup-Message: v1",
    "the marker header, which is how a receiver recognises the message"
  );

  const contentType = header("Content-Type");
  info(`FINDING headers: ${JSON.stringify(head.split("\r\n"))}`);
  Assert.ok(
    /multipart\/mixed;\s*boundary="/.test(contentType),
    `multipart/mixed with a quoted boundary, got ${contentType}`
  );
  Assert.ok(
    /^Subject: \S/m.test(head),
    "and a subject, because a subjectless message is one a client may hide"
  );
});

/**
 * Both parts, in the order the specification gives, with the boundary closing.
 */
add_task(async function thePartsAreInOrder() {
  const message = await buildMessage();

  const boundary = /boundary="([^"]+)"/.exec(message)[1];
  const parts = message.split(`--${boundary}`);

  // Split on the delimiter: element 0 is the headers, then part one, part two,
  // and the closing `--` with its trailing CRLF.
  Assert.equal(parts.length, 4, `two parts and a close, got ${parts.length}`);

  Assert.ok(
    parts[1].includes("Content-Type: text/plain"),
    "the first part is plain text, which every client can display"
  );
  Assert.ok(
    parts[1].includes(CODE),
    "and it carries the code, so the user can read it from the message"
  );
  Assert.ok(
    parts[2].includes("Content-Type: application/autocrypt-setup"),
    "the second part is the setup payload"
  );
  Assert.ok(
    parts[2].includes("BEGIN PGP MESSAGE"),
    "with the armoured block inside it"
  );
  Assert.strictEqual(
    parts[3].trim(),
    "--",
    "and the multipart is closed, not left open"
  );
});

/**
 * The armour headers Enigmail supplies and the specification describes.
 */
add_task(async function theArmorHeadersArePresent() {
  if (!gpgPath) {
    info("SKIPPED: no gpg executable.");
    Assert.ok(true, "skipped");
    return;
  }

  // The headers are on the **inner** block -- the armoured key, which is what
  // the code encrypts -- so they are only visible after decrypting. Looking at
  // the outer `BEGIN PGP MESSAGE`, which is the SKESK and SEIPD, finds none of
  // them, which is how the first version of this check failed.
  const message = await buildMessage();
  const path = PathUtils.join(tempDir.path, "inner.asc");
  await IOUtils.writeUTF8(path, armourOf(message));
  const { exitCode, stdout } = await runGpg([
    "--passphrase",
    CODE,
    "--decrypt",
    path,
  ]);
  Assert.equal(exitCode, 0, "the inner block is readable with the code");

  const lines = stdout.replace(/\r\n/g, "\n").split("\n");

  Assert.ok(
    lines.includes("Passphrase-Format: numeric9x4"),
    "the passphrase format header, spelled as Enigmail spelled it"
  );
  Assert.ok(
    lines.includes("Passphrase-Begin: 12"),
    `and the first two digits of the code, got ${JSON.stringify(
      lines.slice(0, 6)
    )}`
  );
  Assert.ok(
    lines.includes("Autocrypt-Prefer-Encrypt: mutual"),
    "and the preference, from the caller"
  );

  // The blank line that separates headers from body, which Item 96's defect
  // taught is not optional.
  const firstBlank = lines.findIndex((l, i) => i > 0 && l === "");
  Assert.greater(firstBlank, 1, "there is a header region");
  Assert.equal(lines[firstBlank], "", "ending in a blank line");
});

/**
 * Exactly two packets, SKESK then SEIPD.
 *
 * The specification fixes this so a reader does not have to guess. Read from
 * gpg: tag 3 is the symmetric-key session key packet, tag 18 is the
 * symetrically-encrypted and integrity-protected data packet. A compression
 * packet (tag 8) or a literal packet (tag 11) at top level would mean the
 * structure is wrong even though the message still decrypts.
 */
add_task(async function thePacketsAreSkeskThenSeipd() {
  if (!gpgPath) {
    info("SKIPPED: no gpg executable.");
    Assert.ok(true, "skipped");
    return;
  }

  const message = await buildMessage();
  const path = PathUtils.join(tempDir.path, "setup.asc");
  await IOUtils.writeUTF8(path, armourOf(message));

  // With the passphrase, so gpg can describe the SEIPD as well as the SKESK.
  // It then also lists the literal packet it finds *inside* the SEIPD, which is
  // why the sequence reads `3, 18, 11`: two packets belonging to the message,
  // and one belonging to what the message contains. Without the passphrase only
  // the SKESK can be described, so the check would be unable to see the second.
  //
  // What the specification fixes is the container: an SKESK followed by a
  // SEIPD, with no compression packet in between. So the assertions are on the
  // first two tags and on the absence of tag 8, not on the total -- a total of
  // two would be an assertion about gpg's output rather than about the message.
  const { stdout } = await runGpg([
    "--passphrase",
    CODE,
    "--list-packets",
    path,
  ]);
  const tags = [...stdout.matchAll(/tag=(\d+)/g)].map(m => Number(m[1]));
  info(`FINDING packet tags: ${JSON.stringify(tags)}`);

  Assert.greaterOrEqual(tags.length, 2, `at least the container, got ${tags}`);
  Assert.equal(tags[0], 3, "the first packet is an SKESK (tag 3)");
  Assert.equal(tags[1], 18, "the second is a SEIPD (tag 18)");
  Assert.ok(
    !tags.includes(8),
    "and there is no compression packet, which the specification excludes: " +
      "the key travels uncompressed inside the encrypted data"
  );
  Assert.ok(
    tags.slice(2).every(t => t == 11),
    `anything after the container is literal data inside it, got ${tags}`
  );
});

/**
 * The code opens the message, and what comes out is the key block.
 *
 * The end-to-end property: a user who wrote down the code and carried the
 * message to another machine can get their key back.
 */
add_task(async function theCodeOpensTheMessage() {
  if (!gpgPath) {
    info("SKIPPED: no gpg executable.");
    Assert.ok(true, "skipped");
    return;
  }

  const message = await buildMessage();
  const path = PathUtils.join(tempDir.path, "open.asc");
  await IOUtils.writeUTF8(path, armourOf(message));

  const { exitCode, stdout, stderr } = await runGpg([
    "--passphrase",
    CODE,
    "--decrypt",
    path,
  ]);
  info(`FINDING decrypt: exit=${exitCode}`);
  Assert.equal(exitCode, 0, `the code opens it: ${stderr.trim()}`);
  Assert.ok(
    stdout.includes("BEGIN PGP PRIVATE KEY BLOCK"),
    "and what comes out is an armoured secret key"
  );
  Assert.ok(
    stdout.includes("Autocrypt-Prefer-Encrypt: mutual"),
    "carrying the preference for the receiving side to record"
  );
});

/**
 * A wrong code does not.
 *
 * The negative half, without which the check above would pass on a message
 * encrypted to nothing in particular.
 */
add_task(async function aWrongCodeDoesNotOpenIt() {
  if (!gpgPath) {
    info("SKIPPED: no gpg executable.");
    Assert.ok(true, "skipped");
    return;
  }

  const message = await buildMessage();
  const path = PathUtils.join(tempDir.path, "wrong.asc");
  await IOUtils.writeUTF8(path, armourOf(message));

  const { exitCode, stdout } = await runGpg([
    "--passphrase",
    "9999-9999-9999-9999-9999-9999-9999-9999-9999",
    "--decrypt",
    path,
  ]);
  Assert.notEqual(exitCode, 0, "a wrong code fails");
  Assert.ok(
    !stdout.includes("BEGIN PGP PRIVATE KEY BLOCK"),
    "and no key comes out"
  );
});

/**
 * What the builder refuses, and why each refusal matters.
 */
add_task(async function theBuilderRefusesWhatItCannotBuild() {
  const keyBlock = RNP.exportSecretKeyForTransfer(ALICE_FPR, "mutual");

  for (const [label, options] of [
    ["an address that is not one", { address: "nobody" }],
    ["no address", { address: "" }],
    ["an undefined preference", { preferEncrypt: "yes" }],
    ["no preference", { preferEncrypt: undefined }],
    ["a short code", { setupCode: "1234" }],
    [
      "a public key block",
      { keyBlock: "-----BEGIN PGP PUBLIC KEY BLOCK-----" },
    ],
    ["no key block", { keyBlock: "" }],
  ]) {
    let threw = false;
    try {
      AutocryptSetup.buildMessage({
        address: ALICE_ADDRESS,
        setupCode: CODE,
        keyBlock,
        preferEncrypt: "mutual",
        ...options,
      });
    } catch (ex) {
      threw = true;
    }
    Assert.ok(threw, `${label} is refused rather than producing a bad message`);
  }
});

/**
 * The code in the message and the code the user was shown are the same code.
 *
 * Trivial-looking and worth having: the message's human part states the code,
 * and a mismatch between the text and what the armour is encrypted with would
 * produce a message that looks right and cannot be opened.
 */
add_task(async function theStatedCodeIsTheEncryptingCode() {
  if (!gpgPath) {
    info("SKIPPED: no gpg executable.");
    Assert.ok(true, "skipped");
    return;
  }

  const message = await buildMessage();
  const stated = SetupCode.format(
    message.split("Your setup code is: ")[1].split(/\s/)[0]
  );
  Assert.equal(stated, CODE, "the message states the code that encrypts it");

  const path = PathUtils.join(tempDir.path, "stated.asc");
  await IOUtils.writeUTF8(path, armourOf(message));
  const { exitCode } = await runGpg([
    "--passphrase",
    stated,
    "--decrypt",
    path,
  ]);
  Assert.equal(exitCode, 0, "and that code opens it");
});
