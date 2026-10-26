/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 88e: the send gate honours the per-message override.
 *
 * `gTrustKeysForThisMessage` (Item 91) is written by the composer's encryption
 * menus and read in one place -- `checkRecipientKeys()`, which builds the
 * composer's readiness state. The send does not consult it: `determineSendFlags()`
 * calls `getValidKeysForAllRecipients()`, which asks the strict question from
 * scratch. So a message composed with the override ticked was refused by the
 * same gate the menu had just said was relaxed.
 *
 * **What the override admits, and what it does not.** Only the levels that mean
 * nobody has judged the key -- `UNKNOWN`, `UNDEFINED`, `MARGINAL`. `NEVER` is a
 * decision the user already made, and `INVALID` is not a trust question at all;
 * neither is admitted with the flag, which is the boundary Item 91 states as "it
 * relaxes the absence of a decision, not a decision". The two tasks that check
 * that boundary exist because an override that admitted everything would pass
 * the task above it.
 *
 * **Nothing is written.** The override is a statement about one message. The
 * acceptance row is re-read after an overridden resolution, at the database
 * rather than at the flag.
 */

"use strict";

const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { PgpSqliteDb2 } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/sqliteDb.sys.mjs"
);
const { OpenPGPAlias } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/OpenPGPAlias.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { EnigmailFuncs } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/funcs.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";
const STRICT_PREF = "mail.openpgp.require_trusted_keys";
const RULES_PREF = "mail.openpgp.alias_rules_file";
const RULES_FILE = "item88e-rules.json";

const UNJUDGED = "bob@openpgp.example";
const UNJUDGED_FPR = "D1A66E1A23B182C9980F788CFBFCC82A015E7330";
const UNJUDGED_KEY_ID = "FBFCC82A015E7330";

const NO_ENC_SUBKEY = "expired-enc-subkey@example.org";

// Filled in by the setup: a key imported and never given an acceptance row, so
// its level is UNKNOWN rather than UNDEFINED.
let undecidedAddress = null;

/**
 * Resolve one address the way the send does.
 *
 * @param {string} address
 * @param {object} [options] - Forwarded to the resolver; the third argument is
 *   the one Item 88e added.
 * @returns {Promise<{missing: boolean, errors: object[], keys: object}>}
 */
async function resolve(address, options) {
  EnigmailKeyRing.clearCache();
  EnigmailKeyRing.clearGnuPgKeyCache();
  const details = {};
  const missing = await EnigmailKeyRing.getValidKeysForAllRecipients(
    [address],
    details,
    options
  );
  return {
    missing,
    errors: details.errArray ?? [],
    keys: details.keysByAddr ?? {},
  };
}

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();

  await OpenPGPTestUtils.importPublicKey(
    null,
    do_get_file(`${keyDir}/bob@openpgp.example-0xfbfcc82a015e7330-pub.asc`)
  );
  await PgpSqliteDb2.updateAcceptance(UNJUDGED_FPR, [UNJUDGED], "unverified");
  registerCleanupFunction(() => PgpSqliteDb2.deleteAcceptance(UNJUDGED_FPR));

  // A key with no acceptance row at all. Imported directly rather than through
  // importPublicKey(), which writes "verified" and would make the last task
  // measure a decision instead of an absence.
  const ids = await OpenPGPTestUtils.importKey(
    null,
    do_get_file(`${keyDir}/carol@example.com-0x3099ff1238852b9f-pub.asc`),
    false
  );
  Assert.equal(ids.length, 1, "the undecided fixture imported");
  const undecided = EnigmailKeyRing.getKeyById(ids[0]);
  undecidedAddress = EnigmailFuncs.getEmailFromUserID(
    undecided.userId
  ).toLowerCase();
  Assert.ok(undecidedAddress, "and it carries an address");
  registerCleanupFunction(() => PgpSqliteDb2.deleteAcceptance(undecided.fpr));

  Services.prefs.setBoolPref(STRICT_PREF, true);
  Services.prefs.setStringPref(RULES_PREF, RULES_FILE);
  registerCleanupFunction(async () => {
    Services.prefs.clearUserPref(STRICT_PREF);
    Services.prefs.setStringPref(RULES_PREF, "");
    OpenPGPAlias._clear();
    const path = PathUtils.join(
      Services.dirsvc.get("ProfD", Ci.nsIFile).path,
      RULES_FILE
    );
    if (await IOUtils.exists(path)) {
      await IOUtils.remove(path);
    }
  });
});

/**
 * Write the rules file the preference names, and load it.
 *
 * @param {object[]} rules
 */
async function writeRules(rules) {
  await IOUtils.writeUTF8(
    PathUtils.join(Services.dirsvc.get("ProfD", Ci.nsIFile).path, RULES_FILE),
    JSON.stringify({ rules }, null, 2)
  );
  await OpenPGPAlias.load();
}

/**
 * The control, and it is the state a user is in before Item 88e: strict on, no
 * override, an unjudged key refused with the reason that names trust.
 */
add_task(async function withoutTheOverrideItIsRefused() {
  const result = await resolve(UNJUDGED);
  info(`FINDING no override: ${JSON.stringify(result)}`);
  Assert.ok(
    result.missing,
    "an unjudged key is refused under the strict policy"
  );
  Assert.deepEqual(
    result.errors.map(e => e.msg),
    ["ProblemKeyNotTrusted"],
    "and the refusal says trust rather than 'no key', which is the reason a " +
      "prompt can act on"
  );
});

/**
 * The item itself: the same call, with the per-message override on.
 */
add_task(async function withTheOverrideItIsAccepted() {
  const result = await resolve(UNJUDGED, { trustKeysForThisMessage: true });
  info(`FINDING with override: ${JSON.stringify(result)}`);
  Assert.ok(
    !result.missing,
    "the per-message override admits a key whose only failing is trust"
  );
  Assert.deepEqual(result.errors, [], "and no refusal is reported");
  Assert.ok(
    result.keys[UNJUDGED]?.includes(UNJUDGED_KEY_ID),
    `the key is what the send would use, got ${JSON.stringify(result.keys)}`
  );
});

/**
 * The boundary, first half: `NEVER` is a decision and the override cannot
 * overturn it.
 */
add_task(async function aRejectedKeyIsRefusedEvenWithTheOverride() {
  await PgpSqliteDb2.updateAcceptance(UNJUDGED_FPR, [UNJUDGED], "rejected");
  registerCleanupFunction(() =>
    PgpSqliteDb2.updateAcceptance(UNJUDGED_FPR, [UNJUDGED], "unverified")
  );

  const result = await resolve(UNJUDGED, { trustKeysForThisMessage: true });
  info(`FINDING rejected with override: ${JSON.stringify(result)}`);
  Assert.ok(
    result.missing,
    "a key the user rejected is still refused with the override on"
  );

  await PgpSqliteDb2.updateAcceptance(UNJUDGED_FPR, [UNJUDGED], "unverified");
});

/**
 * The boundary, second half: `INVALID` is not a trust judgment, so there is
 * nothing for the override to relax. The fixture is accepted as verified and
 * still refused, because its only encryption subkey has expired -- which makes
 * it the case where a level-based fix that forgot the negative value would
 * wrongly succeed.
 */
add_task(async function anUnusableKeyIsRefusedEvenWithTheOverride() {
  const ids = await OpenPGPTestUtils.importKey(
    null,
    do_get_file(`${keyDir}/expired-enc-subkey.pub.asc`),
    false
  );
  Assert.equal(ids.length, 1, "the expired-subkey fixture imported");
  await OpenPGPTestUtils.updateKeyIdAcceptance(
    ids,
    OpenPGPTestUtils.ACCEPTANCE_VERIFIED
  );

  const result = await resolve(NO_ENC_SUBKEY, {
    trustKeysForThisMessage: true,
  });
  info(`FINDING no encryption subkey with override: ${JSON.stringify(result)}`);
  Assert.ok(
    result.missing,
    "a key with no usable encryption subkey is refused whatever the override"
  );
});

/**
 * The override writes nothing. Read at the database, after a resolution that
 * only succeeded because of it.
 */
add_task(async function theOverrideWritesNothing() {
  await resolve(UNJUDGED, { trustKeysForThisMessage: true });
  EnigmailKeyRing.clearCache();
  const stored = await PgpSqliteDb2.getFingerprintAcceptance(
    null,
    UNJUDGED_FPR
  );
  Assert.equal(
    stored,
    "unverified",
    "the acceptance row is unchanged, so the override is per message and not a " +
      "trust decision"
  );
});

/**
 * The permissive control: the override must not widen a policy that never asked
 * the question. Under the permissive policy a key nobody has judged is refused
 * -- permissive tolerates use, not silence -- and it stays refused with the
 * flag, because the flag only means something where trust is required.
 */
add_task(async function permissiveIsUnchangedByTheOverride() {
  Services.prefs.setBoolPref(STRICT_PREF, false);
  registerCleanupFunction(() => Services.prefs.setBoolPref(STRICT_PREF, true));

  const plain = await resolve(undecidedAddress);
  const overridden = await resolve(undecidedAddress, {
    trustKeysForThisMessage: true,
  });
  info(`FINDING permissive: ${JSON.stringify({ plain, overridden })}`);

  Assert.equal(
    plain.missing,
    true,
    "permissive: a key nobody has judged is not usable, as before"
  );
  Assert.equal(
    overridden.missing,
    true,
    "and the override does not widen the permissive policy"
  );
});

/**
 * The override also reaches a rule that demands encryption.
 *
 * A rule naming a key and saying "always encrypt" asks the same trust question
 * by a different route -- `ProblemRuleRequiresUntrustedKey` -- and refusing
 * there while admitting the same key one line earlier would leave the
 * per-message override meaning "trust this key, unless a rule is also
 * involved". Strict only: under the permissive policy the control is not
 * offered and the rule keeps its own answer.
 */
add_task(async function theOverrideReachesARuleDemandingEncryption() {
  Services.prefs.setBoolPref(STRICT_PREF, true);
  await PgpSqliteDb2.updateAcceptance(UNJUDGED_FPR, [UNJUDGED], "unverified");

  await writeRules([
    {
      email: UNJUDGED,
      keys: [{ id: UNJUDGED_KEY_ID }],
      encrypt: "always",
    },
  ]);

  const refused = await resolve(UNJUDGED);
  info(`FINDING rule, no override: ${JSON.stringify(refused)}`);
  Assert.ok(
    refused.missing,
    "a rule demanding encryption to an untrusted key refuses the send"
  );
  Assert.deepEqual(
    refused.errors.map(e => e.msg),
    ["ProblemRuleRequiresUntrustedKey"],
    "and names the rule as the cause"
  );

  const admitted = await resolve(UNJUDGED, { trustKeysForThisMessage: true });
  info(`FINDING rule, with override: ${JSON.stringify(admitted)}`);
  Assert.ok(
    !admitted.missing,
    "the per-message override answers the rule's trust question too"
  );

  await writeRules([]);
});
