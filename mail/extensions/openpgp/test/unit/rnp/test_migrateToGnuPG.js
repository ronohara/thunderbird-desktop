/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 20: a key stored inside Thunderbird can be moved into GnuPG, and the
 * move is offered rather than taken.
 *
 * This is the only test in the directory that runs a real `gpg`, against a
 * throwaway GNUPGHOME, because the claim is about what GnuPG ends up holding.
 * Stubbing the boundary here would test the stub.
 *
 * The sequence is asserted stage by stage, including the two refusals: an
 * unprotected export must not happen at all, and the deletion must not happen
 * without the caller asking. Those are the item's rules, not incidental
 * behaviour.
 */

"use strict";

const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { GnuPGAgent } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/gnupgAgent.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";
const SECRET_FILE = "alice@openpgp.example-0xf231550c4f47e38e-secret.asc";
const KEY_FPR = "EB85BB5FA33A75E15E944E63F231550C4F47E38E";
const NEW_PASS = "migration-test-passphrase-2026";

let gGnuPgHome;
let gOriginalEnv;

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();

  // A private GNUPGHOME, so the test cannot see or disturb the user's keyring
  // and is not affected by whatever is in it.
  gGnuPgHome = Services.dirsvc.get("ProfD", Ci.nsIFile);
  gGnuPgHome.append("gnupg-test-home");
  await IOUtils.makeDirectory(gGnuPgHome.path, { ignoreExisting: true });
  await IOUtils.setPermissions(gGnuPgHome.path, 0o700);

  gOriginalEnv = Services.env.get("GNUPGHOME");
  Services.env.set("GNUPGHOME", gGnuPgHome.path);
});

add_task(async function gpg_is_available_to_the_test() {
  // If gpg is missing, every assertion below would pass for the wrong reason.
  const probe = await GnuPGAgent._run("gpg", ["--version"]);
  Assert.ok(probe.ok, "gpg must be available for this test to mean anything");
});

add_task(
  async function a_key_gpg_already_holds_is_not_reported_as_migrated_first() {
    // The empty keyring answers no, which is the precondition of the next task.
    Assert.equal(
      await GnuPGAgent.hasSecretKey(KEY_FPR),
      false,
      "the throwaway keyring starts empty"
    );
  }
);

add_task(async function the_sequence_moves_the_key_and_offers_deletion() {
  await OpenPGPTestUtils.importPrivateKey(
    null,
    do_get_file(`${keyDir}/${SECRET_FILE}`)
  );
  EnigmailKeyRing.clearCache();
  Assert.ok(
    EnigmailKeyRing.getKeyById(KEY_FPR),
    "the key should be in the profile to begin with"
  );

  const result = await RNP.migrateSecretKeyToGnuPG(KEY_FPR, NEW_PASS);
  Assert.ok(result.ok, `the migration should succeed: ${result.detail}`);
  Assert.equal(
    result.stage,
    "offer-delete",
    "and it should stop at offering the deletion, not performing it"
  );

  // GnuPG now holds the secret.
  Assert.equal(
    await GnuPGAgent.hasSecretKey(KEY_FPR),
    true,
    "gpg should report the secret key after the import"
  );

  // And the internal copy is still there: the move is offered, never taken.
  EnigmailKeyRing.clearCache();
  const stillHere = EnigmailKeyRing.getKeyById(KEY_FPR);
  Assert.ok(
    stillHere?.secretAvailable,
    "the internal copy must still exist, because deleting is the user's decision"
  );
});

/**
 * The export is protected with the passphrase the caller chose.
 *
 * Item 20's rule is that an unprotected export must never happen, even briefly.
 * The way to prove it is not to look at the block but to make GnuPG open it:
 * import the export into a second throwaway keyring and ask for the secret
 * back, once with no passphrase and once with the one that was chosen.
 *
 * A key that is protected refuses the empty passphrase and accepts the real
 * one. If the export had been a passthrough of the unprotected original, both
 * would succeed -- which is the defect this task exists to catch.
 */
add_task(async function the_export_is_protected_with_the_chosen_passphrase() {
  const exported = await RNP.backupSecretKeys([KEY_FPR], NEW_PASS);
  Assert.ok(exported, "the key should export");

  // A second, empty keyring for the check.
  const secondHome = Services.dirsvc.get("ProfD", Ci.nsIFile);
  secondHome.append("gnupg-protection-check");
  await IOUtils.makeDirectory(secondHome.path, { ignoreExisting: true });
  await IOUtils.setPermissions(secondHome.path, 0o700);

  const firstHome = Services.env.get("GNUPGHOME");
  Services.env.set("GNUPGHOME", secondHome.path);
  try {
    const imported = await GnuPGAgent.importKeyBlock(exported);
    Assert.ok(
      imported.ok,
      "the exported block should import into a fresh keyring"
    );

    const withEmpty = await GnuPGAgent._run("gpg", [
      "--batch",
      "--pinentry-mode",
      "loopback",
      "--passphrase",
      "",
      "--export-secret-keys",
    ]);
    Assert.ok(
      !withEmpty.ok,
      "an empty passphrase must not unlock the exported key, or it was exported unprotected"
    );

    const withReal = await GnuPGAgent._run("gpg", [
      "--batch",
      "--pinentry-mode",
      "loopback",
      "--passphrase",
      NEW_PASS,
      "--export-secret-keys",
    ]);
    Assert.ok(
      withReal.ok,
      "the passphrase the caller chose must unlock it, so the protection is theirs"
    );
  } finally {
    Services.env.set("GNUPGHOME", firstHome);
    if (secondHome.exists()) {
      await IOUtils.remove(secondHome.path, { recursive: true });
    }
  }
});

add_task(async function an_unprotected_export_is_refused() {
  const result = await RNP.migrateSecretKeyToGnuPG(KEY_FPR, "");
  Assert.equal(result.ok, false, "an empty passphrase must be refused");
  Assert.equal(
    result.stage,
    "export",
    "and refused before anything is exported or imported"
  );
  Assert.equal(
    await GnuPGAgent.hasSecretKey(KEY_FPR),
    true,
    "the keyring is unchanged by the refusal"
  );
});

registerCleanupFunction(async function () {
  EnigmailKeyRing.clearCache();
  const keyObj = EnigmailKeyRing.getKeyById(KEY_FPR);
  if (keyObj) {
    await RNP.deleteKey(keyObj.fpr, keyObj.secretAvailable);
  }
  EnigmailKeyRing.clearCache();

  if (gOriginalEnv === null || gOriginalEnv === undefined) {
    Services.env.set("GNUPGHOME", "");
  } else {
    Services.env.set("GNUPGHOME", gOriginalEnv);
  }
  if (gGnuPgHome?.exists()) {
    await IOUtils.remove(gGnuPgHome.path, { recursive: true });
  }
});
