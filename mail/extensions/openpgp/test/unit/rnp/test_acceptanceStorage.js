/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * The acceptance store holds two different facts about a key, and they used to
 * share one row.
 *
 * `acceptance_decision` is one row per fingerprint, and it held both "this key
 * is mine" (`personal`) and "this is what I think of it for these addresses"
 * (`verified`, `unverified`, `rejected`). Because `updateAcceptance()` replaces
 * that row wholesale, writing either fact destroyed the other: accepting a key
 * for an address unmarked it as the user's own, and marking it as the user's
 * own discarded the address judgment. Item 78 found both shapes while making
 * its sequence precise; this file is about the storage they came from.
 *
 * The marker now lives in `personal_key`, so the collision is impossible
 * rather than remembered at each call site. These checks are in the order of
 * how much damage their absence would do:
 *
 *   - the two facts coexist, whichever one is written second;
 *   - a rejection outranks the marker without destroying it;
 *   - clearing the marker keeps the judgment, and clearing everything clears
 *     everything;
 *   - a profile written before the split is migrated on open;
 *   - an export carries the marker, and an import cannot turn it into a
 *     judgment.
 *
 * This file runs with `run-sequentially = true` for the same reason
 * `test_acceptanceExport.js` does: the store is profile-global, and the
 * xpcshell harness gives parallel files the same profile.
 */

"use strict";

const { PgpSqliteDb2 } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/sqliteDb.sys.mjs"
);
const { buildExport, importAcceptance, readAcceptance } =
  ChromeUtils.importESModule(
    "chrome://openpgp/content/modules/acceptanceExport.sys.mjs"
  );
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);

const EMAIL = "storage@example.com";

/**
 * A fingerprint of a legal length for the store, which validates on read.
 *
 * @param {string} seed - Two hex digits; repeated to 40.
 * @returns {string}
 */
function fpr(seed) {
  return seed.repeat(20);
}

/**
 * Removes everything this file wrote for a fingerprint.
 *
 * @param {string} fingerprint
 */
function cleanup(fingerprint) {
  registerCleanupFunction(() => PgpSqliteDb2.deleteAcceptance(fingerprint));
}

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();
});

/**
 * The defect, in its first direction: a judgment written over the marker.
 */
add_task(async function markerSurvivesAnAddressJudgment() {
  const key = fpr("a1");
  cleanup(key);

  await PgpSqliteDb2.acceptAsPersonalKey(key);
  Assert.ok(
    await PgpSqliteDb2.isAcceptedAsPersonalKey(key),
    "the key is marked as the user's own"
  );

  // Exactly what the key manager and the import do.
  await PgpSqliteDb2.updateAcceptance(key, [EMAIL], "verified");

  Assert.ok(
    await PgpSqliteDb2.isAcceptedAsPersonalKey(key),
    "and it is still the user's own after being accepted for an address"
  );
  Assert.equal(
    await PgpSqliteDb2.getFingerprintAcceptance(null, key),
    "verified",
    "with the address judgment recorded separately"
  );
  const acceptance = {};
  await PgpSqliteDb2.getAcceptance(key, EMAIL, acceptance);
  Assert.ok(
    acceptance.emailDecided && acceptance.fingerprintAcceptance == "verified",
    `and the address is decided, got ${JSON.stringify(acceptance)}`
  );
});

/**
 * And in the other direction: the marker written over a judgment. This is the
 * one that used to discard the user's decision about the key's user IDs.
 */
add_task(async function judgmentSurvivesTheMarker() {
  const key = fpr("b2");
  cleanup(key);

  await PgpSqliteDb2.updateAcceptance(key, [EMAIL], "unverified");
  await PgpSqliteDb2.acceptAsPersonalKey(key);

  Assert.equal(
    await PgpSqliteDb2.getFingerprintAcceptance(null, key),
    "unverified",
    "marking a key as the user's own leaves its judgment alone"
  );
  const acceptance = {};
  await PgpSqliteDb2.getAcceptance(key, EMAIL, acceptance);
  Assert.ok(acceptance.emailDecided, "and leaves the address it covered");
});

/**
 * A rejection outranks the marker, and does not delete it.
 *
 * Rejecting a key means never encrypt to it, and that is global for the
 * fingerprint; a key can be both the user's own and rejected, and in that state
 * it is not usable. Checking the rejection where the marker is read is what
 * keeps all of the callers correct. The marker itself survives, so lifting the
 * rejection restores the key rather than requiring it to be marked again.
 */
add_task(async function aRejectionOutranksTheMarker() {
  const key = fpr("c3");
  cleanup(key);

  await PgpSqliteDb2.acceptAsPersonalKey(key);
  await PgpSqliteDb2.updateAcceptance(key, null, "rejected");
  Assert.ok(
    !(await PgpSqliteDb2.isAcceptedAsPersonalKey(key)),
    "a rejected key is not usable, even though it is the user's own"
  );

  await PgpSqliteDb2.updateAcceptance(key, [EMAIL], "verified");
  Assert.ok(
    await PgpSqliteDb2.isAcceptedAsPersonalKey(key),
    "and lifting the rejection restores it without remarking it"
  );
});

/**
 * Two deletes, deliberately different in scope.
 */
add_task(async function clearingTheMarkerKeepsTheJudgment() {
  const key = fpr("d4");
  cleanup(key);

  await PgpSqliteDb2.acceptAsPersonalKey(key);
  await PgpSqliteDb2.updateAcceptance(key, [EMAIL], "verified");

  await PgpSqliteDb2.deletePersonalKeyAcceptance(key);
  Assert.ok(
    !(await PgpSqliteDb2.isAcceptedAsPersonalKey(key)),
    "the marker is gone"
  );
  Assert.equal(
    await PgpSqliteDb2.getFingerprintAcceptance(null, key),
    "verified",
    "and the judgment the user made about the key is untouched"
  );

  await PgpSqliteDb2.acceptAsPersonalKey(key);
  await PgpSqliteDb2.deleteAcceptance(key);
  Assert.ok(
    !(await PgpSqliteDb2.isAcceptedAsPersonalKey(key)),
    "deleting the key's records clears the marker too"
  );
  Assert.equal(
    await PgpSqliteDb2.getFingerprintAcceptance(null, key),
    "",
    "and every judgment with it"
  );
});

/**
 * A profile written before the split.
 *
 * Simulated the only way that is honest: put the old shape back in the database
 * -- drop the new table and write the marker as a `decision` value -- then open
 * the profile again as the application does at startup.
 */
add_task(async function anOlderProfileIsMigratedOnOpen() {
  const key = fpr("e5");
  const judged = fpr("f6");
  cleanup(key);
  cleanup(judged);

  const conn = await PgpSqliteDb2.openDatabase();
  await conn.execute("drop table personal_key");
  await conn.execute(
    "insert into acceptance_decision values (:fpr, 'personal')",
    { fpr: key }
  );
  await conn.execute(
    "insert into acceptance_decision values (:fpr, 'verified')",
    { fpr: judged }
  );
  await conn.execute("insert into acceptance_email values (:fpr, :email)", {
    fpr: judged,
    email: EMAIL,
  });
  await conn.close();

  await PgpSqliteDb2.checkDatabaseStructure();

  Assert.ok(
    await PgpSqliteDb2.isAcceptedAsPersonalKey(key),
    "the old marker was carried into the new table"
  );
  Assert.equal(
    await PgpSqliteDb2.getFingerprintAcceptance(null, key),
    "",
    "and removed from the table that now holds judgments only"
  );
  Assert.equal(
    await PgpSqliteDb2.getFingerprintAcceptance(null, judged),
    "verified",
    "a real judgment is left exactly where it was"
  );
  const acceptance = {};
  await PgpSqliteDb2.getAcceptance(judged, EMAIL, acceptance);
  Assert.ok(acceptance.emailDecided, "with its address intact");

  // Running it again must do nothing: the table exists, so the move is not
  // repeated and the judgment above is not disturbed.
  await PgpSqliteDb2.checkDatabaseStructure();
  Assert.equal(
    await PgpSqliteDb2.getFingerprintAcceptance(null, judged),
    "verified",
    "and a second open changes nothing"
  );
});

/**
 * The export carries the marker, so moving a profile does not lose it.
 */
add_task(async function theExportCarriesTheMarker() {
  const key = fpr("17");
  cleanup(key);

  await PgpSqliteDb2.acceptAsPersonalKey(key);

  const exported = await readAcceptance();
  const entry = exported.find(e => e.fpr == key);
  Assert.ok(entry, "the marker reaches the export");
  Assert.equal(
    entry.decision,
    "personal",
    "under the word the format already carried"
  );
  Assert.ok(entry.personal, "and with the field the split added");

  const document = await buildExport();
  Assert.ok(
    document.decisions.some(d => d.fpr == key && d.decision == "personal"),
    "which survives into the document that is written to a file"
  );
});

/**
 * The defect as an import can still reach it, which is the path a profile move
 * takes: a file that says "verified for this address" about a key this profile
 * holds as its own.
 *
 * Before the split this wrote one row and the key stopped being the user's own.
 * Now the marker is a fact the file cannot overwrite, and the two coexist.
 */
add_task(async function anImportCannotUnmarkAPersonalKey() {
  const key = fpr("28");
  cleanup(key);

  await PgpSqliteDb2.acceptAsPersonalKey(key);

  const result = await importAcceptance({
    kind: "thunderbird-openpgp-acceptance",
    version: 1,
    decisions: [{ fpr: key, decision: "verified", emails: [EMAIL] }],
  });

  Assert.equal(result.errors.length, 0, "the import reports no errors");
  Assert.equal(
    result.conflicts,
    0,
    "and a marker is not a conflicting judgment, so nothing is refused"
  );
  Assert.ok(
    await PgpSqliteDb2.isAcceptedAsPersonalKey(key),
    "the key is still the user's own"
  );
  Assert.equal(
    await PgpSqliteDb2.getFingerprintAcceptance(null, key),
    "verified",
    "and the imported judgment is recorded"
  );
});

/**
 * And the reverse: a marker arriving for a key that already has a judgment.
 */
add_task(async function anImportOfAMarkerKeepsTheJudgment() {
  const key = fpr("39");
  cleanup(key);

  await PgpSqliteDb2.updateAcceptance(key, [EMAIL], "verified");

  const result = await importAcceptance({
    kind: "thunderbird-openpgp-acceptance",
    version: 1,
    decisions: [{ fpr: key, decision: "personal", emails: [] }],
  });

  Assert.equal(result.errors.length, 0, "the import reports no errors");
  Assert.ok(
    await PgpSqliteDb2.isAcceptedAsPersonalKey(key),
    "the imported marker is set"
  );
  Assert.equal(
    await PgpSqliteDb2.getFingerprintAcceptance(null, key),
    "verified",
    "and the judgment the key already had is still there"
  );
});
