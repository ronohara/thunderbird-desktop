/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 66: carrying the user's acceptance judgments between profiles.
 *
 * The judgments live in the profile's own store and had no export, so a lost
 * profile lost them. These tests are about three properties, in order of how
 * much damage their absence would do:
 *
 *   - a round trip is lossless, so an export taken before a migration restores
 *     exactly what was there;
 *   - an import never removes a local judgment, because the failure mode of a
 *     trust store is losing trust the user granted, and a merge that deleted
 *     rows would do it silently;
 *   - a malformed file is refused or reported, never partly believed.
 *
 * This file runs with `run-sequentially = true`, and the reason is the subject
 * rather than convenience: the acceptance store is profile-global, and the
 * xpcshell harness gives parallel test files the same profile. Another file
 * writing a judgment mid-run makes these assertions read a value no test in
 * *this* file ever wrote, which was observed exactly that way -- passing alone
 * and failing in the suite, with a different task failing on each run. The
 * store is shared state, so the test that asserts on it must not run beside
 * another test that writes it.
 */

"use strict";

const { PgpSqliteDb2 } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/sqliteDb.sys.mjs"
);
const {
  buildExport,
  exportAcceptanceToJSON,
  importAcceptance,
  importAcceptanceFromJSON,
  validateExport,
  readAcceptance,
  FORMAT_KIND,
  FORMAT_VERSION,
  DECISIONS,
} = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/acceptanceExport.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();
});

/**
 * @param {string} fpr
 * @returns {Promise<void>} Resolves when the judgment is gone.
 */
async function forget(fpr) {
  await PgpSqliteDb2.deleteAcceptance(fpr);
}

/**
 * A fingerprint this file owns.
 *
 * Synthetic rather than generated, deliberately. These tests are about the
 * store's export and merge, not about keys, and generating one couples them to
 * a profile-global database that other test files in the suite also write:
 * `RNP.genKey()` records the new key as personal, and that write was observed
 * landing between this file's own write and its read, turning an assertion
 * green or red depending on timing. A fingerprint nothing else touches removes
 * the coupling at its source.
 *
 * @param {number} n - Distinguishes the fingerprints within this file.
 * @returns {{fpr: string, keyId: string}}
 */
function syntheticKey(n) {
  const hex = "0123456789abcdef"[n % 16];
  const fpr = hex.repeat(40);
  return { fpr, keyId: fpr.slice(-16).toUpperCase() };
}

/**
 * @param {string} fpr
 * @returns {Promise<?object>} The stored judgment, or null.
 */
async function entryFor(fpr) {
  const all = await readAcceptance();
  return all.find(e => e.fpr == fpr.toLowerCase()) ?? null;
}

/**
 * A round trip restores exactly what was exported.
 */
add_task(async function testRoundTrip() {
  const key = syntheticKey(1);
  await PgpSqliteDb2.updateAcceptance(
    key.fpr,
    ["export1@example.com"],
    "verified"
  );

  const before = await entryFor(key.fpr);
  Assert.ok(before, "the judgment is stored");
  Assert.equal(before.decision, "verified", "with its decision");
  Assert.deepEqual(before.emails, ["export1@example.com"], "and its address");

  const json = await exportAcceptanceToJSON();
  const parsed = JSON.parse(json);
  Assert.equal(parsed.kind, FORMAT_KIND, "the file names its own kind");
  Assert.equal(parsed.version, FORMAT_VERSION, "and its version");
  Assert.ok(parsed.exportedAt, "and when it was taken");

  // Wipe, then restore.
  await forget(key.fpr);
  Assert.equal(await entryFor(key.fpr), null, "the judgment is gone");

  const result = await importAcceptanceFromJSON(json);
  Assert.equal(result.added, 1, "one judgment restored");
  Assert.equal(result.errors.length, 0, "with no errors");

  const after = await entryFor(key.fpr);
  Assert.equal(after.decision, "verified", "the decision came back");
  Assert.deepEqual(after.emails, ["export1@example.com"], "and the address");
});

/**
 * The merge rule, which is the design decision this module makes.
 */
add_task(async function testMergeNeverRemoves() {
  const kept = syntheticKey(2);
  const incoming = syntheticKey(3);

  await PgpSqliteDb2.updateAcceptance(
    kept.fpr,
    ["kept@example.com"],
    "verified"
  );
  await PgpSqliteDb2.updateAcceptance(
    incoming.fpr,
    ["incoming@example.com"],
    "unverified"
  );
  const exported = await buildExport();

  // The local machine now knows only about `kept`, with a different decision.
  await forget(incoming.fpr);
  await PgpSqliteDb2.updateAcceptance(
    kept.fpr,
    ["kept@example.com"],
    "unverified"
  );

  // Keep-local: the conflict is counted and the local value survives.
  const keptResult = await importAcceptance(exported, {
    onConflict: "keep-local",
  });
  Assert.equal(keptResult.conflicts, 1, "one conflict, reported");
  Assert.equal(keptResult.added, 1, "the absent judgment is added");
  Assert.equal(
    (await entryFor(kept.fpr)).decision,
    "unverified",
    "the local judgment is not replaced"
  );

  // Take-imported: the same file, the other rule.
  const tookResult = await importAcceptance(exported, {
    onConflict: "take-imported",
  });
  Assert.equal(tookResult.replaced, 1, "one judgment replaced");
  Assert.equal(
    (await entryFor(kept.fpr)).decision,
    "verified",
    "the imported judgment won because the caller asked for it"
  );

  // And in neither case was anything deleted: a judgment the file does not
  // mention is untouched by importing it.
  Assert.ok(
    await entryFor(incoming.fpr),
    "a judgment present locally and absent from the file survives"
  );
});

/**
 * An identical decision still merges the addresses, because the address list
 * is what decides whether a key is usable for a given sender.
 */
add_task(async function testIdenticalDecisionMergesAddresses() {
  const key = syntheticKey(4);
  await PgpSqliteDb2.updateAcceptance(
    key.fpr,
    ["first@example.com"],
    "verified"
  );

  const exported = {
    kind: FORMAT_KIND,
    version: FORMAT_VERSION,
    exportedAt: new Date().toISOString(),
    count: 1,
    decisions: [
      {
        fpr: key.fpr,
        decision: "verified",
        emails: ["first@example.com", "second@example.com"],
      },
    ],
  };

  await importAcceptance(exported);
  const after = await entryFor(key.fpr);
  Assert.equal(after.decision, "verified", "the decision is unchanged");
  Assert.deepEqual(
    after.emails.sort(),
    ["first@example.com", "second@example.com"],
    "and the address the local store lacked was added"
  );
});

/**
 * Validation: a wrong file, a wrong version, and a partly bad one.
 */
add_task(async function testValidation() {
  Assert.ok(validateExport(null).error, "null is refused");
  Assert.ok(validateExport([]).error, "an array is refused");
  Assert.ok(
    validateExport({ kind: "something-else", version: 1 }).error,
    "a file of another kind is refused"
  );
  Assert.ok(
    validateExport({ kind: FORMAT_KIND, version: 99, decisions: [] }).error,
    "an unknown version is refused rather than guessed at"
  );
  Assert.ok(
    validateExport({ kind: FORMAT_KIND, version: FORMAT_VERSION }).error,
    "a document with no decisions array is refused"
  );

  const good = "0".repeat(40);
  const partly = validateExport({
    kind: FORMAT_KIND,
    version: FORMAT_VERSION,
    decisions: [
      { fpr: good, decision: "verified", emails: ["a@example.com"] },
      { fpr: "not-a-fingerprint", decision: "verified", emails: [] },
      { fpr: good, decision: "undecided", emails: [] },
      { fpr: good, decision: "TRUST_ME", emails: [] },
      { decision: "verified" },
    ],
  });
  Assert.equal(partly.entries.length, 1, "the good entry is kept");
  Assert.equal(partly.skipped, 4, "and every bad one is counted");
  Assert.equal(partly.error, null, "the file as a whole is still usable");

  // `undecided` is not storable -- it is the absence of a row -- so a file that
  // names it is describing something the store cannot represent.
  Assert.equal(
    DECISIONS.includes("undecided"),
    false,
    "undecided is not an exportable decision"
  );
});

/**
 * A file that is not JSON at all is refused with a message, not an exception
 * from the parser leaking to the caller.
 */
add_task(async function testNonJSONIsRefused() {
  let message = "";
  try {
    await importAcceptanceFromJSON("this is not json");
  } catch (ex) {
    message = ex.message;
  }
  Assert.ok(
    message.includes("not valid JSON"),
    `the refusal names the reason, got "${message}"`
  );
});

/**
 * A judgment for a key this profile does not hold is stored rather than
 * dropped, which is what makes an export taken before the keyring is copied
 * worth anything.
 */
add_task(async function testUnknownKeyIsStored() {
  const absentFpr = "0123456789abcdef".repeat(2) + "01234567";
  const exported = {
    kind: FORMAT_KIND,
    version: FORMAT_VERSION,
    exportedAt: new Date().toISOString(),
    count: 1,
    decisions: [
      { fpr: absentFpr, decision: "verified", emails: ["future@example.com"] },
    ],
  };

  const result = await importAcceptance(exported);
  Assert.equal(result.added, 1, "the judgment is stored");

  const stored = await entryFor(absentFpr);
  Assert.ok(stored, "even though the profile holds no such key");
  Assert.equal(stored.decision, "verified", "with its decision");
  await forget(absentFpr);
});

/**
 * A rejected key keeps no address rows, which is the store's own rule and must
 * survive a round trip.
 */
add_task(async function testRejectedCarriesNoAddresses() {
  const key = syntheticKey(5);
  await PgpSqliteDb2.updateAcceptance(
    key.fpr,
    ["rejected@example.com"],
    "rejected"
  );

  const stored = await entryFor(key.fpr);
  Assert.equal(stored.decision, "rejected", "the rejection is stored");
  Assert.deepEqual(
    stored.emails,
    [],
    "and rejection is global for the fingerprint, with no address rows"
  );

  const json = await exportAcceptanceToJSON();
  await forget(key.fpr);
  await importAcceptanceFromJSON(json);

  const after = await entryFor(key.fpr);
  Assert.equal(
    after.decision,
    "rejected",
    "the rejection survives the round trip"
  );
  Assert.deepEqual(after.emails, [], "and is still global");
  await forget(key.fpr);
});
