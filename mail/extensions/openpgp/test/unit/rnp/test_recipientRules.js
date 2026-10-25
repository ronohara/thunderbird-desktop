/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 89: the rule format, and the file the editor writes.
 *
 * The reader has existed since the alias feature; what it could not say was
 * "encrypt to this person" or "do not sign to them". This adds those three
 * settings to the format and keeps the whole rule rather than only its keys,
 * so a value written by the editor survives the next load.
 *
 * Three properties, in the order their absence would hurt:
 *
 *   - a rule's settings survive a write and a load, because a setting the
 *     build silently forgets is worse than one it never offered;
 *   - a field the rule does not mention stays unmentioned, because "no" and
 *     "not stated" are different answers and a boolean format would collapse
 *     them;
 *   - the file stays the only store, so what the editor wrote is what the
 *     send path reads -- no second copy to drift.
 *
 * Item 89b is what several rules for several recipients add up to. This file
 * only asserts one recipient's statement, which is the layer under it.
 */

"use strict";

const { OpenPGPAlias } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/OpenPGPAlias.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { RuleValue } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/OpenPGPAlias.sys.mjs"
);

const PREF = "mail.openpgp.alias_rules_file";
const FILE = "item89-rules.json";

/**
 * @param {object[]} rules
 * @returns {Promise<void>} Writes the file the preference names.
 */
async function writeRulesFile(rules) {
  const path = PathUtils.join(
    Services.dirsvc.get("ProfD", Ci.nsIFile).path,
    FILE
  );
  await IOUtils.writeUTF8(path, JSON.stringify({ rules }, null, 2));
}

/**
 * @param {object[]} rules
 * @returns {Promise<object>} The rule the module reports for an address.
 */
async function loadAndAsk(rules, address) {
  await writeRulesFile(rules);
  await OpenPGPAlias.load();
  return OpenPGPAlias.getRuleForEmail(address);
}

add_setup(async function () {
  do_get_profile();
  // Needed by the last check, which puts a key in the ring to prove that a
  // keyless rule beats a normal lookup that would otherwise succeed.
  await OpenPGPTestUtils.initOpenPGP();
  Services.prefs.setStringPref(PREF, FILE);
  registerCleanupFunction(async () => {
    Services.prefs.setStringPref(PREF, "");
    OpenPGPAlias._clear();
    const path = PathUtils.join(
      Services.dirsvc.get("ProfD", Ci.nsIFile).path,
      FILE
    );
    if (await IOUtils.exists(path)) {
      await IOUtils.remove(path);
    }
  });
});

/**
 * The settings reach the lookup, which is what "the format can say something
 * worth saying" means.
 */
add_task(async function settingsSurviveTheLoad() {
  const rule = await loadAndAsk(
    [
      {
        email: "Bob@Example.com",
        keys: [{ id: "FBFCC82A015E7330" }],
        encrypt: true,
        sign: false,
        pgpMime: true,
      },
    ],
    "bob@example.com"
  );

  Assert.ok(rule, "the rule is found for the address, case-insensitively");
  Assert.equal(rule.matchedBy, "email", "matched by address");
  Assert.equal(rule.encrypt, RuleValue.ALWAYS, "encrypt survives as always");
  Assert.equal(
    rule.sign,
    RuleValue.NEVER,
    "a never survives as never, not as absent"
  );
  Assert.equal(rule.pgpMime, RuleValue.ALWAYS, "PGP/MIME survives");
  Assert.deepEqual(
    rule.keys,
    [{ id: "FBFCC82A015E7330" }],
    "and the keys are still there, in the shape the loader reads"
  );
});

/**
 * A field the rule does not mention stays unmentioned.
 *
 * This is the distinction the whole format turns on: `sign: false` forbids
 * signing, an absent `sign` says nothing. A reader that reported `false` for
 * both would turn every rule ever written into a policy about signing.
 */
add_task(async function anOmittedFieldIsNotAFalse() {
  const rule = await loadAndAsk(
    [{ email: "only@example.com", keys: [{ id: "FBFCC82A015E7330" }] }],
    "only@example.com"
  );

  info(
    `FINDING omitted fields: sign=${JSON.stringify(rule.sign)} ` +
      `encrypt=${JSON.stringify(rule.encrypt)}`
  );
  Assert.equal(rule.encrypt, null, "encrypt is null, not never");
  Assert.equal(rule.sign, null, "sign is null, not never");
  Assert.equal(rule.pgpMime, null, "PGP/MIME is null, not never");
});

/**
 * A value that is not a boolean is treated as absent rather than as a policy.
 *
 * The file can be hand-edited, and `"encrypt": "yes"` in JSON is a string.
 * Reading that as true would apply a policy the user did not write; reading it
 * as absent is the only answer that cannot invent one.
 */
add_task(async function aMalformedValueIsTreatedAsAbsent() {
  const rule = await loadAndAsk(
    [
      {
        email: "typo@example.com",
        keys: [{ id: "FBFCC82A015E7330" }],
        encrypt: "yes",
        sign: 1,
      },
    ],
    "typo@example.com"
  );

  Assert.equal(rule.encrypt, null, "a word it does not know is not a value");
  Assert.equal(rule.sign, null, "and neither is a number");
});

/**
 * An address rule wins over a domain rule for the same recipient.
 *
 * The narrower statement is the one the user made about that person.
 */
add_task(async function theAddressRuleWins() {
  const emailRule = await loadAndAsk(
    [
      { domain: "example.com", keys: [{ id: "AAAA" }], encrypt: true },
      { email: "bob@example.com", keys: [{ id: "BBBB" }], encrypt: false },
    ],
    "bob@example.com"
  );
  Assert.equal(emailRule.matchedBy, "email", "the address rule is used");
  Assert.equal(emailRule.encrypt, RuleValue.NEVER, "with its own setting");
  Assert.deepEqual(emailRule.keys, [{ id: "BBBB" }], "and its own key");

  const domainRule = await loadAndAsk(
    [
      { domain: "example.com", keys: [{ id: "AAAA" }], encrypt: true },
      { email: "bob@example.com", keys: [{ id: "BBBB" }], encrypt: false },
    ],
    "carol@example.com"
  );
  Assert.equal(domainRule.matchedBy, "domain", "another recipient falls back");
  Assert.equal(
    domainRule.encrypt,
    RuleValue.ALWAYS,
    "to the domain rule's setting"
  );
});

/**
 * Nothing is reported for an address no rule covers, rather than a default
 * that would read as a policy.
 */
add_task(async function anUncoveredAddressHasNoRule() {
  const rule = await loadAndAsk(
    [{ email: "someone@example.com", keys: [{ id: "AAAA" }], encrypt: true }],
    "nobody@elsewhere.example"
  );
  Assert.equal(rule, null, "no rule, not a rule with null settings");
});

/**
 * The round trip: what the editor writes is what the send path reads.
 *
 * Written through `writeRules()` -- the editor's own path -- rather than by
 * placing a file, so this covers the serialisation as well as the parse.
 */
add_task(async function writeThenReadAgrees() {
  const written = [
    {
      email: "round@example.com",
      keys: [{ fingerprint: "AB".repeat(20) }],
      encrypt: true,
      sign: true,
    },
    {
      domain: "corp.example",
      keys: [{ id: "CCCCCCCCCCCCCCCC" }],
      pgpMime: false,
    },
  ];

  const result = await OpenPGPAlias.writeRules(written);
  Assert.ok(result.ok, `writeRules() should succeed: ${result.error}`);

  const reread = await OpenPGPAlias.readRulesForEditing();
  Assert.equal(reread.error, null, "and re-read without an error");
  Assert.equal(reread.rules.length, 2, "with both rules present");
  Assert.equal(
    reread.rules[0].encrypt,
    true,
    "the settings are on disk, not only in memory"
  );
  Assert.equal(reread.rules[1].pgpMime, false, "including the false one");
  Assert.ok(
    !("encrypt" in reread.rules[1]),
    "and a field that was not set is not in the file at all"
  );

  const rule = OpenPGPAlias.getRuleForEmail("round@example.com");
  Assert.equal(
    rule.encrypt,
    RuleValue.ALWAYS,
    "and the send path sees the same value"
  );
  Assert.equal(
    rule.sign,
    RuleValue.ALWAYS,
    "for every setting that was written"
  );
});

/**
 * A missing file is the first-run case, not an error.
 *
 * The preference defaults to empty and the file does not exist until the first
 * save; an editor that reported that as a failure would show a warning to
 * every new profile.
 */
add_task(async function aMissingFileIsNotAnError() {
  const rule = await loadAndAsk([], "whatever@example.com");
  Assert.equal(rule, null, "no rules, no rule");

  // Remove the file and read again.
  const path = PathUtils.join(
    Services.dirsvc.get("ProfD", Ci.nsIFile).path,
    FILE
  );
  if (await IOUtils.exists(path)) {
    await IOUtils.remove(path);
  }
  const reread = await OpenPGPAlias.readRulesForEditing();
  Assert.equal(reread.error, null, "a missing file reports no error");
  Assert.deepEqual(reread.rules, [], "and no rules");
});

/**
 * A rule may name no key, and must still be found (Item 89a).
 *
 * This is the substantive part of the item: the lookup used to answer with a
 * key list or null, so "rule present, no key" and "no rule" were the same
 * answer. A rule saying "never encrypt to this address" is exactly that case,
 * and reading it as "no rule" would make it do nothing at all.
 */
add_task(async function aKeylessRuleIsFoundAndDistinguishable() {
  const rule = await loadAndAsk(
    [{ email: "never@example.com", encrypt: false }],
    "never@example.com"
  );

  Assert.ok(rule, "the keyless rule is found");
  Assert.deepEqual(rule.keys, [], "with an empty key list, not an absent one");
  Assert.equal(rule.encrypt, RuleValue.NEVER, "and its setting intact");

  Assert.ok(
    OpenPGPAlias.hasRule("never@example.com"),
    "hasRule() answers true for it"
  );
  Assert.ok(
    OpenPGPAlias.hasKeylessRule("never@example.com"),
    "and hasKeylessRule() says it names no key"
  );
  // `hasAliasDefinition()` tests membership of the rule maps, not the key
  // list, so it reports a keyless rule too -- and rightly: an address with a
  // rule should not be looked up online for a key its owner has refused.
  // Asserted rather than assumed, because the opposite was the natural guess.
  Assert.ok(
    OpenPGPAlias.hasAliasDefinition("never@example.com"),
    "hasAliasDefinition() reports it as well, since it asks the rule maps"
  );

  Assert.ok(
    !OpenPGPAlias.hasRule("nobody@elsewhere.example"),
    "and an address with no rule is still plainly false"
  );
});

/**
 * The key accessors still answer null for no rule and an empty list for a
 * keyless one, which is the distinction the send path reads.
 */
add_task(async function theKeyAccessorsKeepTheDistinction() {
  await writeRulesFile([{ email: "keyless@example.com", sign: true }]);
  await OpenPGPAlias.load();

  Assert.deepEqual(
    OpenPGPAlias.getEmailAliasKeyList("keyless@example.com"),
    [],
    "a keyless rule reports an empty list"
  );
  Assert.equal(
    OpenPGPAlias.getEmailAliasKeyList("other@example.com"),
    null,
    "and an address with no rule reports null"
  );
});

/**
 * A keyed rule still works, and still beats a keyless domain rule.
 */
add_task(async function aKeyedRuleStillWorks() {
  const rule = await loadAndAsk(
    [
      { domain: "example.com", encrypt: false },
      { email: "bob@example.com", keys: [{ id: "BBBB" }], encrypt: true },
    ],
    "bob@example.com"
  );
  Assert.equal(rule.matchedBy, "email", "the address rule is used");
  Assert.deepEqual(rule.keys, [{ id: "BBBB" }], "with its key");
  Assert.equal(rule.encrypt, RuleValue.ALWAYS, "and its setting");

  const domainRule = OpenPGPAlias.getRuleForEmail("carol@example.com");
  Assert.equal(domainRule.matchedBy, "domain", "another address falls back");
  Assert.deepEqual(
    domainRule.keys,
    [],
    "to the keyless domain rule, whose empty key list is real"
  );
});

/**
 * A malformed `keys` element is still refused, because it is a typo rather
 * than an absence.
 */
add_task(async function aMalformedKeysElementIsStillRefused() {
  const rule = await loadAndAsk(
    [{ email: "malformed@example.com", keys: "FBFCC82A015E7330" }],
    "malformed@example.com"
  );
  Assert.equal(
    rule,
    null,
    "a string where a list belongs is not read as a key list or as no keys"
  );
});

/**
 * A rule that names neither keys nor settings is still ignored (Item 89a's
 * boundary).
 *
 * Between "a keyless rule is a real rule" and "a bare entry changes nothing"
 * there is a line, and this is it: the existing alias tests assert that a rule
 * with a missing or empty `keys` entry and nothing else falls through to the
 * normal lookup and finds the address's key. Keeping that is what stops this
 * item from turning every stub entry in an existing file into a refusal.
 */
add_task(async function aRuleThatSaysNothingIsStillIgnored() {
  const rule = await loadAndAsk(
    [{ email: "bare@example.com", keys: [] }],
    "bare@example.com"
  );
  Assert.equal(rule, null, "a bare entry is not a rule");

  const noKeysElement = await loadAndAsk(
    [{ email: "bare@example.com" }],
    "bare@example.com"
  );
  Assert.equal(noKeysElement, null, "and neither is one with no keys element");
});

/**
 * And a keyless rule reaches the send path as unsatisfied, not as fine.
 *
 * This is the half that would have failed silently. With an empty key list the
 * loop over the rule's keys does nothing, so without an explicit branch the
 * address would have been treated as having a usable key -- a rule saying
 * "never encrypt to this address" would have read as "this one is fine".
 */
add_task(async function aKeylessRuleMarksTheRecipientAsUnsatisfied() {
  const { EnigmailKeyRing } = ChromeUtils.importESModule(
    "chrome://openpgp/content/modules/keyRing.sys.mjs"
  );

  // The fixture key is in the ring, so the address *would* be satisfiable by a
  // normal lookup if the rule were ignored.
  await OpenPGPTestUtils.importPublicKey(
    null,
    do_get_file(
      "../../../../../test/browser/openpgp/data/keys/bob@openpgp.example-0xfbfcc82a015e7330-pub.asc"
    )
  );
  EnigmailKeyRing.clearCache();

  await writeRulesFile([{ email: "bob@openpgp.example", encrypt: false }]);
  await OpenPGPAlias.load();

  const details = {};
  const missing = await EnigmailKeyRing.getValidKeysForAllRecipients(
    ["bob@openpgp.example"],
    details
  );
  info(
    `FINDING keyless rule at the send path: missing=${missing} ` +
      `errs=${JSON.stringify(details.errArray)}`
  );
  Assert.ok(
    missing,
    "the address is reported as missing a key, because the rule forbids " +
      "encrypting to it"
  );
  Assert.equal(details.errArray.length, 1, "with one error for that address");
  Assert.equal(
    details.errArray[0].addr,
    "bob@openpgp.example",
    "naming the address the rule applies to"
  );
});

/**
 * Three values per field, and the words are what the file holds (Item 89b).
 */
add_task(async function theFileKeepsWordsAndTheReaderMapsThem() {
  const rule = await loadAndAsk(
    [
      {
        email: "words@example.com",
        keys: [{ id: "AAAA" }],
        encrypt: "always",
        sign: "never",
        pgpMime: "maybe",
      },
    ],
    "words@example.com"
  );

  Assert.equal(rule.encrypt, RuleValue.ALWAYS, "always maps to ALWAYS");
  Assert.equal(rule.sign, RuleValue.NEVER, "never maps to NEVER");
  Assert.equal(rule.pgpMime, RuleValue.MAYBE, "maybe maps to MAYBE");

  // The file is legible, which is why it stores words.
  const raw = JSON.parse(
    await IOUtils.readUTF8(
      PathUtils.join(Services.dirsvc.get("ProfD", Ci.nsIFile).path, FILE)
    )
  );
  Assert.equal(raw.rules[0].encrypt, "always", "the file says always, not 2");
});

/**
 * A boolean still reads as the value it meant, because this build's own
 * editor wrote booleans before this item.
 */
add_task(async function booleansFromTheEarlierFormatStillRead() {
  const rule = await loadAndAsk(
    [
      {
        email: "old@example.com",
        keys: [{ id: "AAAA" }],
        encrypt: true,
        sign: false,
      },
    ],
    "old@example.com"
  );
  Assert.equal(rule.encrypt, RuleValue.ALWAYS, "true was always");
  Assert.equal(rule.sign, RuleValue.NEVER, "false was never");
});

/**
 * Several recipients, and the combining rule Enigmail used.
 *
 * A boolean would have to pick a winner here, and whichever it picked would be
 * a policy applied to a recipient the user did not intend.
 */
add_task(async function conflictingRulesAreNotResolved() {
  await writeRulesFile([
    { email: "always@example.com", encrypt: "always" },
    { email: "never@example.com", encrypt: "never" },
    { email: "maybe@example.com", encrypt: "maybe" },
  ]);
  await OpenPGPAlias.load();

  // never + maybe = never: a silence beside a decision is not a contradiction.
  const neverAndMaybe = OpenPGPAlias.resolveForRecipients([
    "never@example.com",
    "maybe@example.com",
  ]);
  Assert.equal(neverAndMaybe.encrypt, RuleValue.NEVER, "never beats maybe");

  // always + maybe = always.
  const alwaysAndMaybe = OpenPGPAlias.resolveForRecipients([
    "always@example.com",
    "maybe@example.com",
  ]);
  Assert.equal(alwaysAndMaybe.encrypt, RuleValue.ALWAYS, "always beats maybe");

  // always + never = conflict, and the parties are named.
  const both = OpenPGPAlias.resolveForRecipients([
    "always@example.com",
    "never@example.com",
  ]);
  Assert.equal(both.encrypt, RuleValue.CONFLICT, "always and never conflict");

  const conflicts = OpenPGPAlias.conflictsForRecipients([
    "always@example.com",
    "never@example.com",
  ]);
  info(`FINDING conflicts: ${JSON.stringify(conflicts)}`);
  Assert.equal(conflicts.length, 1, "one field conflicts");
  Assert.equal(conflicts[0].field, "encrypt", "encryption");
  Assert.deepEqual(
    conflicts[0].always,
    ["always@example.com"],
    "naming who asked for it"
  );
  Assert.deepEqual(
    conflicts[0].never,
    ["never@example.com"],
    "and who refused"
  );

  // A single recipient never conflicts with itself.
  Assert.deepEqual(
    OpenPGPAlias.conflictsForRecipients(["always@example.com"]),
    [],
    "one recipient, no disagreement"
  );
});

/**
 * The boundary: a rule may require encryption, and may not make a key
 * acceptable (Item 89b, design 15.7).
 *
 * The key here is in the ring and usable, and it is not trusted. A rule saying
 * "always encrypt" to it must refuse the send and name *both* facts, rather
 * than either encrypting to an untrusted key or reporting the address as
 * simply missing a key.
 */
add_task(async function aRuleCannotRaiseATrust() {
  const { EnigmailKeyRing } = ChromeUtils.importESModule(
    "chrome://openpgp/content/modules/keyRing.sys.mjs"
  );
  const { PgpSqliteDb2 } = ChromeUtils.importESModule(
    "chrome://openpgp/content/modules/sqliteDb.sys.mjs"
  );

  const key = EnigmailKeyRing.getKeyById("0xFBFCC82A015E7330");
  Assert.ok(key, "the fixture key is in the ring");
  registerCleanupFunction(() => PgpSqliteDb2.deleteAcceptance(key.fpr));

  // Usable, and not trusted.
  await PgpSqliteDb2.updateAcceptance(
    key.fpr,
    ["bob@openpgp.example"],
    "unverified"
  );
  EnigmailKeyRing.clearCache();

  // First without a rule: the alias lookup is not involved, so the key is
  // found by the normal path.
  await writeRulesFile([]);
  await OpenPGPAlias.load();
  let details = {};
  let missing = await EnigmailKeyRing.getValidKeysForAllRecipients(
    ["bob@openpgp.example"],
    details
  );
  Assert.equal(missing, false, "without a rule, an unverified key is usable");

  // Now with a rule demanding encryption.
  await writeRulesFile([
    {
      email: "bob@openpgp.example",
      keys: [{ id: "FBFCC82A015E7330" }],
      encrypt: "always",
    },
  ]);
  await OpenPGPAlias.load();

  details = {};
  missing = await EnigmailKeyRing.getValidKeysForAllRecipients(
    ["bob@openpgp.example"],
    details
  );
  info(
    `FINDING rule-vs-trust: missing=${missing} errs=${JSON.stringify(details.errArray)}`
  );
  Assert.ok(
    missing,
    "a rule requiring encryption to an untrusted key refuses the send"
  );
  Assert.equal(
    details.errArray[0]?.msg,
    "ProblemRuleRequiresUntrustedKey",
    "with a reason that names the rule as the cause"
  );

  // And the rule is satisfied once the key is trusted, which is what makes
  // the refusal actionable rather than a dead end.
  await PgpSqliteDb2.updateAcceptance(
    key.fpr,
    ["bob@openpgp.example"],
    "verified"
  );
  EnigmailKeyRing.clearCache();
  details = {};
  missing = await EnigmailKeyRing.getValidKeysForAllRecipients(
    ["bob@openpgp.example"],
    details
  );
  Assert.equal(missing, false, "a trusted key satisfies the rule");
});
