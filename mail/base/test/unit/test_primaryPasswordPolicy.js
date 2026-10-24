/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

const { TIERS, RULES, resolveTier, failingRules, unenforcedRules } =
  ChromeUtils.importESModule(
    "resource://gre/modules/PrimaryPasswordPolicy.sys.mjs"
  );

add_task(async function test_tier_table_matches_the_shared_vocabulary() {
  // The names and arithmetic are workbench-development's, deliberately, so one
  // password-strength vocabulary exists across both projects. If these numbers
  // drift, a policy written for one project means something else in the other.
  Assert.deepEqual(
    {
      minLength: TIERS.low.minLength,
      classes:
        TIERS.low.requireUppercase ||
        TIERS.low.requireLowercase ||
        TIERS.low.requireDigit ||
        TIERS.low.requireSpecial,
      minStrength: TIERS.low.minStrength,
    },
    { minLength: 6, classes: false, minStrength: 0 },
    "low is 6 characters, no classes, score 0"
  );
  Assert.deepEqual(
    {
      minLength: TIERS.medium.minLength,
      upper: TIERS.medium.requireUppercase,
      lower: TIERS.medium.requireLowercase,
      digit: TIERS.medium.requireDigit,
      special: TIERS.medium.requireSpecial,
      minStrength: TIERS.medium.minStrength,
    },
    {
      minLength: 8,
      upper: true,
      lower: true,
      digit: true,
      special: false,
      minStrength: 2,
    },
    "medium is 8, upper+lower+digit, score 2"
  );
  Assert.deepEqual(
    {
      minLength: TIERS.high.minLength,
      upper: TIERS.high.requireUppercase,
      lower: TIERS.high.requireLowercase,
      digit: TIERS.high.requireDigit,
      special: TIERS.high.requireSpecial,
      minStrength: TIERS.high.minStrength,
    },
    {
      minLength: 10,
      upper: true,
      lower: true,
      digit: true,
      special: true,
      minStrength: 3,
    },
    "high is 10, all four classes, score 3"
  );
});

add_task(async function test_resolves_by_name() {
  for (const name of ["low", "medium", "high"]) {
    const r = resolveTier(name);
    Assert.equal(r.name, name);
    Assert.ok(!r.unknownTier, `${name} is a known tier`);
    Assert.deepEqual(r.rules, TIERS[name]);
  }
});

add_task(async function test_custom_overrides_only_what_it_names() {
  const r = resolveTier("custom", { minLength: 14, requireDigit: true });
  Assert.equal(r.name, "custom");
  Assert.equal(r.rules.minLength, 14);
  Assert.equal(r.rules.requireDigit, true);
  Assert.equal(
    r.rules.requireSpecial,
    TIERS.custom.requireSpecial,
    "fields the policy does not name keep the custom defaults"
  );
});

add_task(async function test_unknown_tier_falls_back_to_low_not_high() {
  // A misspelling in a policy file must not lock every user out of changing a
  // password. Falling back to the strictest tier would do exactly that, and it
  // would do it silently.
  const r = resolveTier("hgih");
  Assert.equal(r.name, "low");
  Assert.equal(r.requested, "hgih");
  Assert.ok(r.unknownTier, "the caller can tell that the name was not known");
  // "shortpw" is 7 characters: over low's 6, and with no class requirements
  // to fail. ("short" is 5 and would fail min-length -- the fallback is
  // permissive, not exempt.)
  Assert.deepEqual(failingRules("shortpw", r.rules), [], "a typo must not block");
});

add_task(async function test_empty_tier_means_no_policy() {
  const r = resolveTier("");
  Assert.equal(r.name, "low");
  Assert.ok(!r.unknownTier, "no policy is not the same as a bad policy name");
});

add_task(async function test_high_tier_rejects_and_accepts() {
  const { rules } = resolveTier("high");
  Assert.deepEqual(
    failingRules("abc", rules),
    ["min-length", "uppercase", "digit", "special"],
    "every failure is named, in order"
  );
  Assert.deepEqual(
    failingRules("Abcdefgh1!", rules),
    [],
    "ten characters with all four classes passes"
  );
  Assert.deepEqual(
    failingRules("abcdefghij1", rules),
    ["uppercase", "special"],
    "a long password with no capital or symbol still fails"
  );
});

add_task(async function test_empty_password_is_never_judged() {
  // Clearing the Primary Password is a deliberate action the dialog's own
  // rules govern. Applying a length minimum to "" would make the password
  // impossible to remove.
  const { rules } = resolveTier("high");
  Assert.deepEqual(failingRules("", rules), []);
});

add_task(async function test_strength_is_reported_but_never_fatal() {
  // This is the lockout this module must not have. There is no strength
  // estimator in the tree, so a tier asking for a score would reject every
  // password if the score were treated as a failure -- including correct
  // ones, making the Primary Password impossible to set.
  const { rules } = resolveTier("high");
  Assert.deepEqual(unenforcedRules(rules), ["strength"], "the gap is reported");
  Assert.deepEqual(
    failingRules("Abcdefgh1!", rules),
    [],
    "and it is not a reason to refuse a password that satisfies the rest"
  );
  Assert.ok(
    !RULES.includes("strength-unchecked"),
    "no rule name that would always fail"
  );
});

add_task(async function test_low_tier_has_nothing_unenforced() {
  const { rules } = resolveTier("low");
  Assert.deepEqual(unenforcedRules(rules), [], "score 0 asks for nothing");
});
