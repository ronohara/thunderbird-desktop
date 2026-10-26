/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 77a: read gpg's per-user-ID validity, so that certification has a number
 * that moves.
 *
 * gpgme reports two different things about a key and this file is about the
 * second of them:
 *
 *   - `owner_trust` is what the user *declared* -- Item 88 writes it;
 *   - `validity`, per user ID, is what gpg *computed* from the certifications
 *     it can see -- and it is what changes when a key is signed.
 *
 * Item 88a and Item 92 produce certifications, so a gate that could only read
 * owner trust could not see their effect. That is why this read exists, and why
 * it is its own step: it changes no behaviour, so it can be verified alone.
 *
 * **The test has to make gpg change its mind, not merely read a number.**
 * Asserting a shape -- that a field exists and holds an integer -- would pass
 * on an implementation that returned a constant, or one wired to owner trust
 * under the wrong name. So the key is signed between two readings and the
 * number must rise. That is the only assertion that distinguishes reading
 * validity from reading something that looks like it.
 *
 * **And null is a third answer.** A key GnuPG does not hold, or an address the
 * key does not carry, returns null rather than 0. `UNKNOWN` is 0 and is a
 * real value; conflating the two is the bug Item 88b exists to prevent, and it
 * is asserted here so the distinction is settled at the source.
 */

"use strict";

const { GPGME } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/GPGME.sys.mjs"
);
const { OpenPgpValidity } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/constants.sys.mjs"
);
const { Subprocess } = ChromeUtils.importESModule(
  "resource://gre/modules/Subprocess.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";

// Alice signs; Bob's key is the one whose validity moves. Two keys, because the
// whole question is what happens to one when the other vouches for it.
const ALICE_SECRET = "alice@openpgp.example-0xf231550c4f47e38e-secret.asc";
const ALICE_FPR = "EB85BB5FA33A75E15E944E63F231550C4F47E38E";
const BOB_PUBLIC = "bob@openpgp.example-0xfbfcc82a015e7330-pub.asc";
const BOB_FPR = "D1A66E1A23B182C9980F788CFBFCC82A015E7330";
const BOB_ADDRESS = "bob@openpgp.example";

// A well-formed fingerprint GnuPG will never hold, for the null case.
const ABSENT_FPR = "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEE";

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
    arguments: [
      "--batch",
      "--no-tty",
      "--yes",
      "--no-symkey-cache",
      "--pinentry-mode",
      "loopback",
      ...args,
    ],
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
 * The validity gpgme reports for one address on one key, named.
 *
 * @param {?integer} level
 * @returns {string}
 */
function name(level) {
  const names = {
    [OpenPgpValidity.UNKNOWN]: "UNKNOWN",
    [OpenPgpValidity.UNDEFINED]: "UNDEFINED",
    [OpenPgpValidity.NEVER]: "NEVER",
    [OpenPgpValidity.MARGINAL]: "MARGINAL",
    [OpenPgpValidity.FULL]: "FULL",
    [OpenPgpValidity.ULTIMATE]: "ULTIMATE",
  };
  if (level === null) {
    return "null";
  }
  return names[level] ?? `unmapped(${level})`;
}

add_setup(async function () {
  do_get_profile();

  try {
    gpgPath = await Subprocess.pathSearch("gpg");
  } catch (ex) {
    info("No gpg executable found; validity cannot be read here.");
    return;
  }

  gnupgHome = do_get_tempdir();
  gnupgHome.append("gnupg-uid-validity");
  gnupgHome.createUnique(Ci.nsIFile.DIRECTORY_TYPE, 0o700);

  // A pinentry that does not exist, so a command that would ask a human fails
  // instead -- and never puts a dialog on someone's screen.
  await IOUtils.writeUTF8(
    PathUtils.join(gnupgHome.path, "gpg-agent.conf"),
    "pinentry-program /nonexistent/item77a-no-pinentry\n"
  );

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

  // Alice's secret key signs; Bob's public key is the target.
  for (const file of [ALICE_SECRET, BOB_PUBLIC]) {
    const { exitCode, stderr } = await runGpg([
      "--import",
      do_get_file(`${keyDir}/${file}`).path,
    ]);
    if (exitCode) {
      info(`gpg could not import ${file}: ${stderr}`);
      return;
    }
  }

  // Alice's signature only counts towards Bob's validity if gpg trusts her, so
  // her ownertrust is declared ultimate. Without this the certification below
  // would leave Bob at UNDEFINED and the test would fail for a reason that is
  // about gpg's web of trust rather than about the reader.
  const trustFile = PathUtils.join(gnupgHome.path, "ownertrust.txt");
  await IOUtils.writeUTF8(trustFile, `${ALICE_FPR}:6:\n`);
  const trust = await runGpg(["--import-ownertrust", trustFile]);
  if (trust.exitCode) {
    info(`gpg could not declare ownertrust: ${trust.stderr}`);
    return;
  }
  await runGpg(["--check-trustdb"]);

  if (!GPGME.init()) {
    info("No usable gpgme library found.");
    return;
  }
  available = true;
});

/**
 * The value is read, and it is gpg's.
 */
add_task(async function theValidityIsReadFromGnuPG() {
  if (!available) {
    info("SKIPPED: external GnuPG is not available on this machine.");
    Assert.ok(true, "skipped");
    return;
  }

  const before = GPGME.getUserIdValidity(BOB_FPR, BOB_ADDRESS);
  info(`FINDING validity of Bob before signing: ${name(before)} (${before})`);

  Assert.notEqual(before, null, "gpg holds the key and the address");
  Assert.equal(
    typeof before,
    "number",
    "and answers with one of the six validity values"
  );
  Assert.ok(
    !(before === OpenPgpValidity.FULL || before === OpenPgpValidity.ULTIMATE),
    `nobody has vouched for Bob yet, so he is not fully valid (${name(before)})`
  );

  // The listing that carries it, so the read is traceable to the field it comes
  // from rather than to a second implementation of the same idea.
  // Through the accessor, because `GPGMELibLoader.init()` throws on a second
  // call: the library is loaded once for the process, and GPGME.init() has
  // already done it. The instance GPGME is using is the one that matters.
  const lib = GPGME.getGPGMELib();
  Assert.ok(lib, "the loaded gpgme wrapper is reachable");
  const listed = lib.listKeys(BOB_FPR, false);
  const record = listed.find(k => k.fpr == BOB_FPR);
  Assert.ok(record, "listKeys() returned the key");
  Assert.ok(Array.isArray(record.uids), "with a per-user-ID list");
  Assert.ok(
    record.uids.some(u => u.email == BOB_ADDRESS),
    "carrying the address this test reads"
  );
  Assert.equal(
    record.uids.find(u => u.email == BOB_ADDRESS).validity,
    before,
    "and the value is the one listKeys() carries, not a separate lookup"
  );
  // The plain address list is untouched, because four consumers read it.
  Assert.ok(
    record.emails.includes(BOB_ADDRESS),
    "emails still holds the address as a plain string"
  );
});

/**
 * The number moves when the key is certified -- the assertion that tells a real
 * reader from one returning a constant.
 */
add_task(async function signingTheKeyRaisesItsValidity() {
  if (!available) {
    info("SKIPPED: external GnuPG is not available on this machine.");
    Assert.ok(true, "skipped");
    return;
  }

  const before = GPGME.getUserIdValidity(BOB_FPR, BOB_ADDRESS);
  Assert.notEqual(before, null, "there is a reading to compare against");

  const signed = await runGpg([
    "--local-user",
    ALICE_FPR,
    "--quick-sign-key",
    BOB_FPR,
  ]);
  info(`FINDING gpg --quick-sign-key: exit=${signed.exitCode}`);
  Assert.equal(
    signed.exitCode,
    0,
    `Alice's key certifies Bob's: ${signed.stderr.trim()}`
  );

  // Validity is a computed field, so gpg has to rebuild its trust database
  // before the signature affects it. This is the freshness property Item 88c
  // records as a risk; doing it explicitly here is what keeps that risk visible
  // rather than rediscovered later.
  await runGpg(["--check-trustdb"]);

  const after = GPGME.getUserIdValidity(BOB_FPR, BOB_ADDRESS);
  info(
    `FINDING validity of Bob after signing: ${name(after)} (${after}), ` +
      `was ${name(before)} (${before})`
  );

  Assert.notEqual(after, null, "the reading survives the change");
  Assert.greater(
    after,
    before,
    `the certification raised validity from ${name(before)} to ${name(after)}`
  );
  Assert.ok(
    after === OpenPgpValidity.FULL ||
      after === OpenPgpValidity.ULTIMATE ||
      after === OpenPgpValidity.MARGINAL,
    `and it reached a value a trusted signature produces (${name(after)})`
  );
});

/**
 * Absence is null, not zero.
 *
 * The distinction the gate depends on: a key GnuPG does not hold has no
 * validity to report, and reading that as `UNKNOWN` would make an internal
 * profile's keys look unjudged to a gate that should have asked the store.
 */
add_task(async function absenceIsNullAndNotUnknown() {
  if (!available) {
    info("SKIPPED: external GnuPG is not available on this machine.");
    Assert.ok(true, "skipped");
    return;
  }

  const absent = GPGME.getUserIdValidity(ABSENT_FPR, BOB_ADDRESS);
  info(`FINDING validity of a key gpg does not hold: ${name(absent)}`);
  Assert.equal(absent, null, "a key gpg does not hold has no validity here");

  const wrongAddress = GPGME.getUserIdValidity(BOB_FPR, "nobody@example.com");
  info(
    `FINDING validity of an address the key does not carry: ${name(wrongAddress)}`
  );
  Assert.equal(
    wrongAddress,
    null,
    "an address the key does not carry is not UNKNOWN, it is absent"
  );

  const noArguments = GPGME.getUserIdValidity("", "");
  Assert.equal(noArguments, null, "and an empty request answers nothing");
});
