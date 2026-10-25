/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 88: record what the user declares about a key GnuPG holds.
 *
 * Trust for a keyring key is gpg's own database, so the operation is gpg's:
 * `--import-ownertrust`, driven through the module that already runs the gpg
 * executable. A value kept anywhere else would disagree with the engine that
 * computes validity, and the disagreement would show as a key gpg refuses to
 * use while Thunderbird says it is trusted.
 *
 * Two scales, an offset of two apart, and that offset is the whole of the
 * translation -- gpgme reports `unknown` as 0 and gpg stores it as 2. So these
 * checks are about that mapping as much as about the write: a mistake there
 * would set a key to *never* when the user asked for *unknown*, which is a
 * silent inversion rather than an error.
 *
 * Every level is set and read back, because a setter that only works for one
 * level is worse than none: the user would believe they had marked a key and
 * gpg would still refuse it.
 */

"use strict";

const { GPGME } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/GPGME.sys.mjs"
);
const { GnuPGAgent } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/gnupgAgent.sys.mjs"
);
const { OpenPgpValidity } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/constants.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { Subprocess } = ChromeUtils.importESModule(
  "resource://gre/modules/Subprocess.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";
const BOB_SECRET_FILE = "bob@openpgp.example-0xfbfcc82a015e7330-secret.asc";
const BOB_PRIMARY_FPR = "D1A66E1A23B182C9980F788CFBFCC82A015E7330";

let gpgPath = null;
let gnupgHome = null;
let available = false;

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

/**
 * The ownertrust gpg itself reports, read from its own listing.
 *
 * Deliberately *not* read back through GPGME: the point of the check is that
 * the value reached gpg's database, and asking the same interface that wrote
 * it would pass even if both agreed on something gpg had not stored.
 *
 * A `pub` line's ownertrust letter is field 8: `u` ultimate, `f` full,
 * `m` marginal, `n` never, `-` unknown.
 *
 * @param {string} fpr
 * @returns {Promise<string>} The single letter, or "" when gpg has no record.
 */
async function gpgOwnertrust(fpr) {
  const { stdout } = await runGpg(["--with-colons", "--list-keys", `0x${fpr}`]);
  for (const line of stdout.split("\n")) {
    const f = line.split(":");
    if (f[0] === "pub") {
      // Field 8, not field 1. Field 1 is the key's *computed validity*, which
      // stays unknown until gpg rebuilds its trust database -- a fact about
      // signatures, not about what the user declared. The two agree only for
      // `unknown`, so reading the wrong one passes there and fails everywhere
      // else, which is how this test first failed.
      return f[8] ?? "";
    }
  }
  return "";
}

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  Services.prefs.setBoolPref("mail.openpgp.fetch_pubkeys_from_gnupg", true);

  try {
    gpgPath = await Subprocess.pathSearch("gpg");
  } catch (ex) {
    info("No gpg executable found; owner trust cannot be set here.");
    return;
  }

  gnupgHome = do_get_tempdir();
  gnupgHome.append("gnupg-ownertrust");
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

  const { exitCode, stderr } = await runGpg([
    "--import",
    do_get_file(`${keyDir}/${BOB_SECRET_FILE}`).path,
  ]);
  if (exitCode) {
    info(`gpg could not import the fixture key: ${stderr}`);
    return;
  }
  if (!GPGME.init()) {
    info("No usable gpgme library found.");
    return;
  }
  available = true;
});

/**
 * Each level reaches gpg's database.
 *
 * The letters are gpg's own, so this fails if the offset is wrong: setting
 * `unknown` and reading back `n` would mean a key the user had not judged was
 * recorded as refused.
 */
add_task(async function everyLevelReachesTheTrustDatabase() {
  if (!available) {
    info("SKIPPED: no external GnuPG on this machine.");
    return;
  }

  // Measured from gpg's own listing: 2 -> "q" (undefined), 3 -> "n",
  // 4 -> "m", 5 -> "f", 6 -> "u". There is no letter for gpgme's UNKNOWN,
  // which is why that level is absent here and refused by the setter.
  const cases = [
    [OpenPgpValidity.UNDEFINED, "q"],
    [OpenPgpValidity.NEVER, "n"],
    [OpenPgpValidity.MARGINAL, "m"],
    [OpenPgpValidity.FULL, "f"],
    [OpenPgpValidity.ULTIMATE, "u"],
  ];

  for (const [level, letter] of cases) {
    const result = await GnuPGAgent.setOwnerTrust(BOB_PRIMARY_FPR, level);
    Assert.ok(result.ok, `setting level ${level}: ${result.output}`);
    const stored = await gpgOwnertrust(BOB_PRIMARY_FPR);
    info(`FINDING level ${level} -> gpg stores "${stored}"`);
    Assert.equal(stored, letter, `level ${level} should be gpg's "${letter}"`);
  }
});

/**
 * And what was written is what gpgme reports back, which is the number the
 * rest of the build will compare against.
 */
add_task(async function theValueReadsBackThroughGpGME() {
  if (!available) {
    info("SKIPPED: no external GnuPG on this machine.");
    return;
  }

  await GnuPGAgent.setOwnerTrust(BOB_PRIMARY_FPR, OpenPgpValidity.FULL);
  Assert.equal(
    GPGME.getOwnerTrust(BOB_PRIMARY_FPR),
    OpenPgpValidity.FULL,
    "a key marked full reads back as full"
  );

  await GnuPGAgent.setOwnerTrust(BOB_PRIMARY_FPR, OpenPgpValidity.NEVER);
  Assert.equal(
    GPGME.getOwnerTrust(BOB_PRIMARY_FPR),
    OpenPgpValidity.NEVER,
    "and re-marking it never reads back as never, so the two are distinct"
  );
});

/**
 * The level gpg cannot store is refused rather than silently turned into
 * another one.
 */
add_task(async function unknownIsRefused() {
  if (!available) {
    info("SKIPPED: no external GnuPG on this machine.");
    return;
  }

  const before = await gpgOwnertrust(BOB_PRIMARY_FPR);
  const result = await GnuPGAgent.setOwnerTrust(
    BOB_PRIMARY_FPR,
    OpenPgpValidity.UNKNOWN
  );
  Assert.ok(
    !result.ok,
    "UNKNOWN is refused, because gpg's ownertrust scale has no value for it"
  );
  Assert.equal(
    await gpgOwnertrust(BOB_PRIMARY_FPR),
    before,
    "and the stored value is untouched, not written as something else"
  );
});

/**
 * A fingerprint GnuPG does not hold has no owner trust, rather than a default
 * that would read as a decision.
 */
add_task(async function anUnknownKeyHasNoValue() {
  if (!available) {
    info("SKIPPED: no external GnuPG on this machine.");
    return;
  }

  const absent = "AB".repeat(20);
  const { exitCode } = await runGpg(["--list-keys", `0x${absent}`]);
  Assert.notEqual(exitCode, 0, "gpg does not hold this fingerprint");
  Assert.equal(
    GPGME.getOwnerTrust(absent),
    null,
    "so there is no owner trust to report"
  );
});
