/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 78: Stage 11 as one sequence.
 *
 * Items 62 to 77 were each verified on their own. This runs the five claims
 * together, in one file and one process, so that a later change cannot undo an
 * earlier one without the sequence noticing.
 *
 * The ordering is deliberate and is the item's own: the gate is checked first,
 * because everything after it depends on selection being right, and a wrong
 * gate makes every later result meaningless rather than merely wrong.
 *
 * What this adds over the individual files is not more assertions about each
 * area -- it is the *interaction*. Item 77's vocabulary change, for instance,
 * broke the readiness switch in the composer's own view of a key, and that was
 * found only because an existing test happened to look there. This file looks at
 * the seam on purpose.
 */

"use strict";

const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { PgpSqliteDb2 } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/sqliteDb.sys.mjs"
);
const { EnigmailConstants, OpenPgpValidity, isValidityUsable } =
  ChromeUtils.importESModule(
    "chrome://openpgp/content/modules/constants.sys.mjs"
  );
const identityKeys = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/identityKeys.sys.mjs"
);
const acceptanceExport = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/acceptanceExport.sys.mjs"
);
const { OpenPGPMasterpass } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/masterpass.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";

/** A v5 Ed25519 key: 32-byte fingerprint, a supported algorithm. */
const V5_FPR =
  "817F60336BB9D133B59F1B91FDEBE36796C1B2F47907BAB49A7EB981DC719DC0";

const ADDRESS = "stage11@example.com";

/**
 * @param {string} userId
 * @returns {Promise<object>} A generated key, from the keyring.
 */
async function generateKey(userId) {
  const pass = await OpenPGPMasterpass.retrieveOpenPGPPassword();
  const keyId = await RNP.genKey(userId, "ECC", 0, 0, pass);
  Assert.ok(keyId, `genKey() produced a key for ${userId}`);
  EnigmailKeyRing.clearCache();
  return EnigmailKeyRing.getKeyById(keyId);
}

/**
 * @param {string} fpr
 * @returns {object} The key, re-read so a change is visible.
 */
function reload(fpr) {
  EnigmailKeyRing.clearCache();
  return EnigmailKeyRing.getKeyById(fpr);
}

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();
});

/**
 * CHECK 1, first because everything after it depends on it.
 *
 * A rejected key is refused before its label is consulted, and the refusal
 * tests specific values rather than a threshold.
 *
 * The second half is the one that matters: Item 77's own warning is that a
 * threshold gate admits the key the user set aside, because NEVER is 2 and
 * UNDEFINED is 1. Asserted here against the function, and against the constant
 * that would be used to build such a threshold.
 */
add_task(async function check1_aRejectedKeyIsRefusedBeforeItsLabel() {
  await OpenPGPTestUtils.importPublicKey(
    null,
    do_get_file(`${keyDir}/alice@openpgp.example-0xf231550c4f47e38e-pub.asc`)
  );
  EnigmailKeyRing.clearCache();

  const key = EnigmailKeyRing.getKeyById("0xF231550C4F47E38E");
  Assert.ok(key, "the fixture key is in the keyring");
  const email = "alice@openpgp.example";

  await PgpSqliteDb2.updateAcceptance(key.fpr, [email], "rejected");
  registerCleanupFunction(() => PgpSqliteDb2.deleteAcceptance(key.fpr));

  const level = await EnigmailKeyRing.isValidKeyForRecipient(
    reload(key.fpr),
    email,
    false
  );
  Assert.equal(
    level,
    OpenPgpValidity.NEVER,
    `a rejected key reports NEVER, got ${level}`
  );
  Assert.ok(!isValidityUsable(level), "and the predicate refuses it");

  // The trap, stated as an assertion: a threshold at UNDEFINED would admit it,
  // because NEVER is numerically higher.
  Assert.greaterOrEqual(
    level,
    OpenPgpValidity.UNDEFINED,
    "NEVER is numerically at or above UNDEFINED -- which is exactly why a " +
      "threshold test cannot express this and must not be written"
  );

  // And the list the send path uses refuses it, which is the behavioural half.
  const usable = await EnigmailKeyRing.getValidKeysForRecipient(email, {});
  Assert.ok(
    !usable.includes(key.keyId),
    `a rejected key must not be offered, got ${JSON.stringify(usable)}`
  );
});

/**
 * CHECK 2: a v5 key survives the whole path.
 *
 * Import, acceptance, resolution by fingerprint, and a round trip -- in one
 * sequence, because the failure the item describes is that the key "vanishes
 * silently" partway through.
 */
add_task(async function check2_aV5KeySurvivesTheWholePath() {
  const pub = await IOUtils.readUTF8(
    do_get_file(`${keyDir}/v5-ecc-25519-pub.asc`).path
  );
  const imported = await RNP.importPubkeyBlockAutoAcceptImpl(null, pub, null);
  Assert.equal(imported.exitCode, 0, "the v5 key imports");

  // Cleared after the import: the keyring caches its list, so a lookup straight
  // after an import answers from the snapshot taken before it. This is the
  // "vanishes silently" failure in miniature -- the key was there and the
  // lookup said otherwise.
  EnigmailKeyRing.clearCache();
  const key = EnigmailKeyRing.getKeyById(V5_FPR);
  Assert.ok(key, "and resolves by its 64-hex fingerprint");
  Assert.equal(key.version, 5, "as a v5 key");

  await PgpSqliteDb2.updateAcceptance(V5_FPR, ["v5@example.net"], "verified");
  registerCleanupFunction(() => PgpSqliteDb2.deleteAcceptance(V5_FPR));
  Assert.equal(
    await PgpSqliteDb2.getFingerprintAcceptance(null, V5_FPR),
    "verified",
    "its acceptance is recorded against the v5 fingerprint"
  );

  // The secret half, so the round trip uses the same key.
  const sec = await IOUtils.readUTF8(
    do_get_file(`${keyDir}/v5-ecc-25519-sec.asc`).path
  );
  const secImported = await RNP.importSecKeyBlockImpl(
    null,
    // The fixture's passphrase, as librnp's own tests use it.
    () => "password",
    false,
    sec
  );
  Assert.equal(secImported.exitCode, 0, "the v5 secret key imports");
  await PgpSqliteDb2.acceptAsPersonalKey(V5_FPR);

  const sourceText = "Stage 11, check 2.";
  const encrypted = await RNP.encryptAndOrSign(
    sourceText,
    {
      aliasKeys: new Map(),
      armor: true,
      bcc: [],
      encrypt: true,
      encryptToSender: true,
      sender: `0x${V5_FPR}`,
      senderKeyIsExternal: false,
      sigTypeClear: false,
      sigTypeDetached: false,
      sign: true,
      signatureHash: "SHA256",
      to: [],
    },
    {}
  );
  Assert.ok(encrypted, "a v5 key can send");

  const { exitCode, decryptedData } = await RNP.decrypt(encrypted, {
    fromAddr: reload(V5_FPR).userId,
    maxOutputLength: encrypted.length * 100,
    noOutput: false,
    uiFlags: EnigmailConstants.UI_PGP_MIME,
    verifyOnly: false,
    msgDate: null,
  });
  Assert.ok(!exitCode, "and receive");
  Assert.equal(decryptedData, sourceText, "returning what was sent");
});

/**
 * CHECK 3: an ordered key list survives a cleared cache, and the entry that
 * will sign is the one the order names.
 *
 * The cache clear is the substantive part: the list is read from identity
 * attributes, and a cache that answered from memory would pass this while the
 * stored order was wrong.
 */
add_task(async function check3_theOrderedListSurvivesACacheClear() {
  const account = MailServices.accounts.createAccount();
  const identity = MailServices.accounts.createIdentity();
  identity.email = ADDRESS;
  account.addIdentity(identity);
  registerCleanupFunction(() =>
    MailServices.accounts.removeAccount(account, true)
  );

  const first = await generateKey("Stage Eleven First <stage11@example.com>");
  const second = await generateKey("Stage Eleven Second <stage11@example.com>");
  EnigmailKeyRing.clearCache();

  identityKeys.setKeyList(identity, [second.fpr, first.fpr]);
  EnigmailKeyRing.clearCache();

  // Re-read the identity through the account manager, as a reloaded profile
  // would, rather than reusing the object in hand.
  const reloaded = MailServices.accounts.allIdentities.find(
    i => i.email == ADDRESS
  );
  Assert.deepEqual(
    identityKeys.getKeyList(reloaded),
    [second.fpr.toUpperCase(), first.fpr.toUpperCase()],
    "the stored order survives and is read back in order"
  );

  const chosen = identityKeys.firstUsableKey(reloaded, "sign");
  Assert.equal(
    chosen.fpr,
    second.fpr,
    "and the first usable entry is the one that would sign"
  );
});

/**
 * CHECK 4: the acceptance export and import agree across two "profiles".
 *
 * One profile writes, the other reads. Simulated by exporting to a string,
 * deleting the judgment, and importing it back -- which is the whole of what
 * happens between two machines, and the only part that can be wrong here.
 */
add_task(async function check4_theExportCarriesAJudgmentBetweenProfiles() {
  const fpr = "78".repeat(20);
  await PgpSqliteDb2.updateAcceptance(fpr, ["carried@example.com"], "verified");
  registerCleanupFunction(() => PgpSqliteDb2.deleteAcceptance(fpr));

  const json = await acceptanceExport.exportAcceptanceToJSON();
  const parsed = JSON.parse(json);
  Assert.ok(
    parsed.decisions.some(d => d.fpr == fpr && d.decision == "verified"),
    "the export carries the judgment"
  );

  // The receiving profile: no judgment, then the import.
  await PgpSqliteDb2.deleteAcceptance(fpr);
  // `""`, not `null` -- the delete leaves an empty string, which is falsy and
  // is what every caller tests. Asserted as "no decision" rather than against a
  // particular empty value.
  Assert.ok(
    !(await PgpSqliteDb2.getFingerprintAcceptance(null, fpr)),
    "the judgment is gone before the import"
  );

  const result = await acceptanceExport.importAcceptanceFromJSON(json);
  Assert.equal(result.errors.length, 0, "the import reports no errors");
  Assert.equal(
    await PgpSqliteDb2.getFingerprintAcceptance(null, fpr),
    "verified",
    "and the judgment is visible on the other side"
  );
});

/**
 * CHECK 5: nothing is decided silently.
 *
 * Two acceptable keys for one address produce a list of two, not a choice, and
 * the composer's own view reports both as accepted rather than marking one
 * better. This is the seam Item 77's change crossed: the readiness switch
 * compared raw numbers, and a vocabulary change made a rejected key read as
 * accepted.
 *
 * The address is this check's own. An earlier check leaves two personal keys
 * for ADDRESS in the same profile, and counting keys for ADDRESS was satisfied
 * by those rather than by the pair created here -- a false pass that the first
 * draft of this file did not notice.
 *
 * The two defects this check found are now fixed, and its findings are
 * assertions of the fixed behaviour: the marker is readable the moment
 * `genKey()` returns, and accepting a key for an address no longer unmarks it
 * as the user's own.
 */
add_task(async function check5_twoAcceptableKeysAreNotCollapsedToOne() {
  const address = "stage11-check5@example.com";
  const keyA = await generateKey(`Stage Eleven A <${address}>`);
  const keyB = await generateKey(`Stage Eleven B <${address}>`);
  EnigmailKeyRing.clearCache();

  // Straight after generation, with no intervening read. `genKey()` awaits
  // `acceptAsPersonalKey()`, which returns its write's promise; it used to
  // await a call that had already resolved, so the first read here returned
  // "" and the key a caller had just made looked unmarked.
  for (const k of [keyA, keyB]) {
    Assert.ok(
      await PgpSqliteDb2.isAcceptedAsPersonalKey(k.fpr),
      `${k.fpr} is personal the instant genKey() returns`
    );
  }

  const usable = await EnigmailKeyRing.getValidKeysForRecipient(address, {});
  Assert.deepEqual(
    usable.slice().sort(),
    [keyA.keyId, keyB.keyId].sort(),
    `both keys, and nothing else, must be offered for ${address}`
  );

  const metas = await EnigmailKeyRing.getEncryptionKeyMeta(address);
  const accepted = metas.filter(k => k.readiness == "accepted");
  Assert.deepEqual(
    accepted.map(m => m.keyObj.fpr).sort(),
    [keyA.fpr, keyB.fpr].sort(),
    `the composer must accept both keys, got ` +
      `${JSON.stringify(metas.map(m => [m.keyObj?.fpr, m.readiness]))}`
  );
  Assert.ok(
    !metas.some(k => k.readiness == "rejected"),
    "neither key may be reported as rejected"
  );

  // And accepting a key for an address -- what the key manager and the import
  // both do -- leaves it the user's own.
  //
  // It used to unmark it: the marker was a `decision` value in the one row per
  // fingerprint, and `updateAcceptance()` replaced that row with "verified".
  // The composer then reported the user's own key as `rejectedPersonal` and
  // stopped offering it. The marker has its own table now, so the two facts
  // coexist and the key stays usable.
  await PgpSqliteDb2.updateAcceptance(keyA.fpr, [address], "verified");
  EnigmailKeyRing.clearCache();

  Assert.ok(
    await PgpSqliteDb2.isAcceptedAsPersonalKey(keyA.fpr),
    `${keyA.fpr} is still personal after being accepted for ${address}`
  );
  const offeredAfter = await EnigmailKeyRing.getValidKeysForRecipient(
    address,
    {}
  );
  Assert.deepEqual(
    offeredAfter.slice().sort(),
    [keyA.keyId, keyB.keyId].sort(),
    `both keys must still be offered, got ${JSON.stringify(offeredAfter)}`
  );
  const keyAAfter = (await EnigmailKeyRing.getEncryptionKeyMeta(address)).find(
    m => m.keyObj?.fpr == keyA.fpr
  );
  Assert.equal(
    keyAAfter?.readiness,
    "accepted",
    `the composer must still accept ${keyA.fpr}`
  );

  registerCleanupFunction(() => PgpSqliteDb2.deleteAcceptance(keyA.fpr));
});
