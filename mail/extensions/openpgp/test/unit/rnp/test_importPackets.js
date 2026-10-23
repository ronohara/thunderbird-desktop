/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Stage 2's verification, at the level the claim is made at: what is actually
 * in the profile ring after each import route runs.
 *
 * Every import route funnels through `importKeyAsync()`, which is the finding
 * this stage was built on (Item 7: nine call sites in seven files, not the
 * three wrappers). So the routes are exercised where they converge rather than
 * through their user interfaces, and the assertion is made on the ring file's
 * packet headers rather than on the key list -- a key that is present but
 * hidden from the list would still be a copy.
 *
 * Secret material is packet tag 5 (secret key) or tag 7 (secret subkey),
 * RFC 4880 section 4.3. A public copy is not a secret copy and is not what
 * this file refuses; that distinction is Item 8 versus Item 9.
 */

"use strict";

const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { GPGME } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/GPGME.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";
const KEY_ID = "F231550C4F47E38E";
const KEY_FPR = "EB85BB5FA33A75E15E944E63F231550C4F47E38E";
const SECRET_FILE = "alice@openpgp.example-0xf231550c4f47e38e-secret.asc";
const PUBLIC_FILE = "alice@openpgp.example-0xf231550c4f47e38e-pub.asc";

const TAG_SECRET_KEY = 5;
const TAG_SECRET_SUBKEY = 7;

let gOriginalInit;
let gOriginalHasSecret;
let gOriginalHasPublic;
let gBaselineSecretPackets = 0;

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();

  gOriginalInit = GPGME.init;
  gOriginalHasSecret = GPGME.hasSecretKey;
  gOriginalHasPublic = GPGME.hasPublicKey;

  // Other suites share this profile, so the baseline is measured rather than
  // assumed to be empty. The final check compares against it.
  gBaselineSecretPackets = await countSecretPackets();
});

/**
 * Tags of every packet in an OpenPGP byte stream.
 *
 * Written out rather than shelled out to `gpg --list-packets`, so the check
 * does not depend on an external binary and runs in the same process as the
 * code under test.
 *
 * Supports the new and old header formats. Partial body lengths are not
 * supported: a keyring file written by librnp does not use them, and returning
 * an error is better than silently miscounting.
 *
 * @param {Uint8Array} bytes - The file's contents.
 * @returns {{tags: integer[], error: ?string}} Packet tags, and what stopped
 *   the scan if anything did.
 */
function packetTags(bytes) {
  const tags = [];
  let i = 0;
  while (i < bytes.length) {
    const b = bytes[i];
    if (!(b & 0x80)) {
      return { tags, error: `not a packet header at ${i}` };
    }
    let tag;
    let len;
    if (b & 0x40) {
      tag = b & 0x3f;
      const lt = bytes[i + 1];
      if (lt === undefined) {
        return { tags, error: "truncated length" };
      }
      if (lt < 192) {
        len = lt;
        i += 2;
      } else if (lt < 224) {
        len = ((lt - 192) << 8) + bytes[i + 2] + 192;
        i += 3;
      } else if (lt === 255) {
        len =
          (bytes[i + 2] << 24) |
          (bytes[i + 3] << 16) |
          (bytes[i + 4] << 8) |
          bytes[i + 5];
        i += 6;
      } else {
        return { tags, error: "partial body length" };
      }
    } else {
      tag = (b >> 2) & 0x0f;
      const lt = b & 0x03;
      if (lt === 0) {
        len = bytes[i + 1];
        i += 2;
      } else if (lt === 1) {
        len = (bytes[i + 1] << 8) | bytes[i + 2];
        i += 3;
      } else if (lt === 2) {
        len =
          (bytes[i + 1] << 24) |
          (bytes[i + 2] << 16) |
          (bytes[i + 3] << 8) |
          bytes[i + 4];
        i += 5;
      } else {
        return { tags, error: "indeterminate length" };
      }
    }
    tags.push(tag);
    i += len;
  }
  return { tags, error: null };
}

/**
 * Packet tags in a keyring file, or an empty list when the file is absent.
 *
 * An absent file is the correct state for a profile that has stored nothing,
 * so it is not an error.
 *
 * @param {string} name - "pubring.gpg" or "secring.gpg".
 * @returns {Promise<{tags: integer[], error: ?string}>} As packetTags().
 */
async function ringTags(name) {
  const file = Services.dirsvc.get("ProfD", Ci.nsIFile);
  file.append(name);
  if (!file.exists()) {
    return { tags: [], error: null };
  }
  const bytes = await IOUtils.read(file.path);
  return packetTags(bytes);
}

/** Secret-key and secret-subkey packets anywhere in the profile ring. */
async function countSecretPackets() {
  let count = 0;
  for (const name of ["pubring.gpg", "secring.gpg"]) {
    const { tags } = await ringTags(name);
    count += tags.filter(
      t => t === TAG_SECRET_KEY || t === TAG_SECRET_SUBKEY
    ).length;
  }
  return count;
}

/**
 * Wait for the ring files to stop changing.
 *
 * librnp writes the keyring asynchronously, so a scan taken immediately after
 * an import or a delete can see the previous state. Every assertion here reads
 * the file, so both directions have to wait: a negative check that runs too
 * early passes vacuously, which is worse than a failure.
 *
 * @param {Function} settled - Called with a snapshot; returns true when the
 *   expected state has arrived.
 * @param {string} what - Description, for the timeout message.
 */
async function waitForRing(settled, what) {
  const deadline = Date.now() + 5000;
  let last = null;
  while (Date.now() < deadline) {
    last = {
      pub: (await ringTags("pubring.gpg")).tags,
      secrets: await countSecretPackets(),
    };
    if (settled(last)) {
      return last;
    }
    await new Promise(resolve => do_timeout(50, resolve));
  }
  throw new Error(
    `Timeout waiting for ${what}; last snapshot: ${JSON.stringify(last)}`
  );
}

/**
 * Stub the GnuPG boundary.
 *
 * @param {object} answer - What to report.
 * @param {boolean} [answer.readable] - Whether GPGME.init() succeeds.
 * @param {boolean} [answer.held] - Whether GnuPG holds the key.
 */
function stubGnuPG({ readable = true, held = false } = {}) {
  GPGME.init = () => readable;
  GPGME.hasSecretKey = () => held;
  GPGME.hasPublicKey = () => held;
}

/** Restore the module boundary. */
function restoreGnuPG() {
  GPGME.init = gOriginalInit;
  GPGME.hasSecretKey = gOriginalHasSecret;
  GPGME.hasPublicKey = gOriginalHasPublic;
}

/**
 * Read a fixture as a string.
 *
 * @param {string} name - File name under the shared key fixtures.
 * @returns {Promise<string>} The file's contents.
 */
async function readKeyFixture(name) {
  const data = await IOUtils.read(do_get_file(`${keyDir}/${name}`).path);
  return new TextDecoder().decode(data);
}

/** Remove the fixture key from the profile ring, if it is there. */
async function removeFixtureKey() {
  EnigmailKeyRing.clearCache();
  const keyObj = EnigmailKeyRing.getKeyById(KEY_ID);
  if (keyObj) {
    await RNP.deleteKey(keyObj.fpr, keyObj.secretAvailable);
    EnigmailKeyRing.clearCache();
  }
  // The ring file is rewritten asynchronously, so a scan taken immediately
  // after the delete can still see the packets. Wait for the file to settle
  // rather than assuming the delete is visible.
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    if (EnigmailKeyRing.getKeyById(KEY_ID) === null) {
      const { tags } = await ringTags("pubring.gpg");
      if (!tags.length) {
        break;
      }
    }
    await new Promise(resolve => do_timeout(50, resolve));
  }
}

/**
 * The scanner itself must be able to see a secret key, or every assertion
 * below it passes for the wrong reason.
 *
 * A control that cannot fail on the defect is worse than no control, so this
 * plants the state the later checks forbid and requires the scanner to find it.
 */
add_task(async function scanner_sees_a_secret_key() {
  const before = await countSecretPackets();

  const importedIds = await OpenPGPTestUtils.importPrivateKey(
    null,
    do_get_file(`${keyDir}/${SECRET_FILE}`)
  );
  Assert.ok(importedIds.length, "the secret fixture should import");

  const after = (
    await waitForRing(snap => snap.secrets > before, "the imported secret key")
  ).secrets;
  Assert.greater(
    after,
    before,
    "the packet scanner must find secret-key packets when a secret key is present"
  );

  await removeFixtureKey();
  Assert.equal(
    await countSecretPackets(),
    before,
    "and the count must fall again when the key is removed"
  );
});

/**
 * A secret block whose key GnuPG holds writes no packet at all.
 *
 * This is the route the wizard uses, and the one where the damage design 1.5
 * measured happens.
 */
add_task(async function held_secret_block_writes_nothing() {
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  stubGnuPG({ held: true });

  try {
    const pubBefore = await ringTags("pubring.gpg");
    const secBefore = await ringTags("secring.gpg");

    const errorMsgObj = {};
    await EnigmailKeyRing.importSecKeyFromFile(
      null,
      () => "",
      false,
      do_get_file(`${keyDir}/${SECRET_FILE}`),
      errorMsgObj,
      {}
    );

    // Give a late write time to land before reading, so "nothing added" is a
    // fact rather than a race with the keyring's asynchronous save.
    await new Promise(resolve => do_timeout(400, resolve));
    const pubAfter = await ringTags("pubring.gpg");
    const secAfter = await ringTags("secring.gpg");

    Assert.equal(
      pubAfter.tags.length,
      pubBefore.tags.length,
      "no public packet is added for a secret key GnuPG holds"
    );
    Assert.equal(
      secAfter.tags.length,
      secBefore.tags.length,
      "and no secret packet either"
    );
  } finally {
    await restoreGnuPG();
    if (Services.prefs.prefHasUserValue("mail.openpgp.allow_external_gnupg")) {
      Services.prefs.clearUserPref("mail.openpgp.allow_external_gnupg");
    }
  }
});

/**
 * A held public block adds no packet, and the ring still resolves the key.
 *
 * Both halves matter: "nothing written" is only correct while the transient
 * path can still answer a lookup.
 */
add_task(
  async function held_public_block_writes_nothing_but_stays_resolvable() {
    Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
    Services.prefs.setBoolPref("mail.openpgp.fetch_pubkeys_from_gnupg", true);
    stubGnuPG({ held: true });

    const block = await readKeyFixture(PUBLIC_FILE);
    const originalGetById = GPGME.getPublicKeysForId;
    const originalGetByEmail = GPGME.getPublicKeysForEmail;
    GPGME.getPublicKeysForId = () => new Map([[KEY_FPR, block]]);
    GPGME.getPublicKeysForEmail = () => new Map([[KEY_FPR, block]]);

    try {
      const before = await ringTags("pubring.gpg");

      const errorMsgObj = {};
      await EnigmailKeyRing.importKeyAsync(
        null,
        false,
        block,
        false,
        "",
        errorMsgObj,
        null
      );

      await new Promise(resolve => do_timeout(400, resolve));
      const after = await ringTags("pubring.gpg");
      Assert.equal(
        after.tags.length,
        before.tags.length,
        "a public key GnuPG holds is not written to the profile ring"
      );

      // Asserted before any cache clear: clearCache() drops the transient
      // cache by design (it calls clearGnuPgKeyCache), so the promise Item 10
      // makes is that the caller can resolve the key now, not that it survives
      // an invalidation.
      Assert.ok(
        EnigmailKeyRing.getKeyById(KEY_ID),
        "but the key is still resolvable, through the transient cache"
      );

      // And an invalidation drops it, which is the documented behaviour rather
      // than a defect: the address-keyed load repopulates it on the next lookup.
      EnigmailKeyRing.clearCache();
      Assert.ok(
        !EnigmailKeyRing.getKeyById(KEY_ID),
        "clearing the cache drops transient keys, which is why the guard loads eagerly"
      );
    } finally {
      GPGME.getPublicKeysForId = originalGetById;
      GPGME.getPublicKeysForEmail = originalGetByEmail;
      await restoreGnuPG();
      Services.prefs.clearUserPref("mail.openpgp.fetch_pubkeys_from_gnupg");
      Services.prefs.clearUserPref("mail.openpgp.allow_external_gnupg");
    }
  }
);

/**
 * A public key GnuPG does not hold is written, and what is written carries no
 * secret packet.
 *
 * This is the send-path control: the guard must not have stopped an ordinary
 * correspondent's key from being imported.
 */
add_task(async function unheld_public_block_is_written_without_secrets() {
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  Services.prefs.setBoolPref("mail.openpgp.fetch_pubkeys_from_gnupg", true);
  stubGnuPG({ held: false });

  const block = await readKeyFixture(PUBLIC_FILE);

  try {
    const before = await ringTags("pubring.gpg");
    const secretsBefore = await countSecretPackets();

    const errorMsgObj = {};
    await EnigmailKeyRing.importKeyAsync(
      null,
      false,
      block,
      false,
      "",
      errorMsgObj,
      null
    );

    // The keyring file is written asynchronously, so reading it here can see
    // the state before the import landed. This assertion is positive, so the
    // race showed up as an intermittent failure rather than as a false pass --
    // which is the luckier direction, and still a defect in the test. Waited
    // for properly, as the other files in this directory do.
    const settled = await waitForRing(
      snap => snap.pub.length > before.tags.length,
      "the imported public key to land in pubring.gpg"
    );
    const after = { tags: settled.pub };
    Assert.greater(
      after.tags.length,
      before.tags.length,
      "a public key GnuPG does not hold is still imported"
    );
    Assert.equal(
      await countSecretPackets(),
      secretsBefore,
      "and importing it adds no secret-key packet"
    );

    EnigmailKeyRing.clearCache();
    Assert.ok(
      EnigmailKeyRing.getKeyById(KEY_ID),
      "the key is resolvable afterwards, which is what encryption needs"
    );
  } finally {
    await removeFixtureKey();
    await restoreGnuPG();
    Services.prefs.clearUserPref("mail.openpgp.fetch_pubkeys_from_gnupg");
    Services.prefs.clearUserPref("mail.openpgp.allow_external_gnupg");
  }
});

/**
 * With no usable GnuPG a secret key is imported, and that is the one case
 * where a secret packet is legitimately present.
 *
 * Stated as a positive assertion rather than left implicit, because Item 9's
 * refusal is only correct if this route still works.
 */
add_task(async function secret_block_imports_when_no_gnupg() {
  Services.prefs.setBoolPref("mail.openpgp.allow_external_gnupg", true);
  stubGnuPG({ readable: false, held: false });

  try {
    const before = await countSecretPackets();

    const importedKeysObj = {};
    const errorMsgObj = {};
    await EnigmailKeyRing.importSecKeyFromFile(
      null,
      () => "",
      false,
      do_get_file(`${keyDir}/${SECRET_FILE}`),
      errorMsgObj,
      importedKeysObj
    );

    const settled = await waitForRing(
      snap => snap.secrets > before,
      "the secret key to appear in the ring"
    );
    Assert.greater(
      settled.secrets,
      before,
      "with no GnuPG the internal store takes the secret key, and the packets show it"
    );
  } finally {
    await removeFixtureKey();
    await restoreGnuPG();
    Services.prefs.clearUserPref("mail.openpgp.allow_external_gnupg");
  }
});

/**
 * The ring ends where it started.
 *
 * Measured against the baseline taken in setup rather than against zero,
 * because other suites in this directory share the profile and may leave keys
 * of their own. What this asserts is that nothing this file did left a secret
 * packet behind, which is the claim the stage makes.
 */
add_task(async function ring_returns_to_its_baseline() {
  await removeFixtureKey();
  EnigmailKeyRing.clearCache();

  Assert.equal(
    await countSecretPackets(),
    gBaselineSecretPackets,
    "this file must leave no secret-key packet behind"
  );
});
