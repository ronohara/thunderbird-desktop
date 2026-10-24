/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

const { TIERS, RULES, resolveTier, failingRules, estimateScore } =
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
  Assert.deepEqual(
    failingRules("shortpw", r.rules),
    [],
    "a typo must not block"
  );
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
    ["min-length", "uppercase", "digit", "special", "strength"],
    "every failure is named, in order -- strength included, since Item 56 " +
      "vendored the estimator and a three-letter password fails that too"
  );
  Assert.deepEqual(
    failingRules("Abcdefgh1!", rules),
    [],
    "ten characters with all four classes passes"
  );
  Assert.deepEqual(
    failingRules("abcdefghij1", rules),
    ["uppercase", "special", "strength"],
    "a long password with no capital or symbol still fails, and so does its " +
      "score -- eleven characters of lowercase and a digit is a guessable shape"
  );
});

add_task(async function test_empty_password_is_never_judged() {
  // Clearing the Primary Password is a deliberate action the dialog's own
  // rules govern. Applying a length minimum to "" would make the password
  // impossible to remove.
  const { rules } = resolveTier("high");
  Assert.deepEqual(failingRules("", rules), []);
});

add_task(async function test_the_estimator_is_available() {
  // Item 56 vendored zxcvbn, so the strength minimum is now enforceable. If
  // this fails, the tier's score requirement is being ignored and the policy
  // is back to length-and-classes alone.
  const { score, error } = estimateScore("correcthorsebatterystaple");
  Assert.equal(error, null, "the estimator ran");
  Assert.ok(Number.isInteger(score), `a score came back: ${score}`);
});

add_task(async function test_password1_is_rejected_by_the_high_tier() {
  // The example the design cites as the reason a length-and-classes rule is
  // not enough. "Password1!" is ten characters with all four classes, so it
  // satisfies every non-strength rule -- and zxcvbn scores it 1.
  const { rules } = resolveTier("high");
  const lengthAndClasses = { ...rules, minStrength: 0 };
  Assert.deepEqual(
    failingRules("Password1!", lengthAndClasses),
    [],
    "without a score requirement it passes, which is the gap Item 56 closes"
  );
  Assert.deepEqual(
    failingRules("Password1!", rules),
    ["strength"],
    "with the estimator it is refused"
  );
});

add_task(
  async function test_a_good_passphrase_is_rejected_by_the_class_rules() {
    // A finding rather than a test of what I hoped: "correcthorsebatterystaple"
    // scores 4 -- the best possible -- and the `high` tier still refuses it,
    // because it demands an uppercase letter, a digit and a symbol, and the
    // passphrase has none.
    //
    // Design 12.6 already says an estimator is advisory and that "a long
    // passphrase of random words scores well and is a good choice". This is that
    // sentence with a number attached, and it is worth knowing before the tier
    // is settled: as configured, this build tells a user their excellent
    // passphrase is unacceptable. Whether the class rules should yield to a high
    // score is a policy decision, not an implementation one.
    const { rules } = resolveTier("high");
    Assert.deepEqual(
      failingRules("correcthorsebatterystaple", rules),
      ["uppercase", "digit", "special"],
      "a strong passphrase fails the class requirements"
    );
    Assert.greaterOrEqual(
      estimateScore("correcthorsebatterystaple").score,
      rules.minStrength,
      "and it satisfies the score requirement, so the two rules disagree"
    );
  }
);

add_task(async function test_a_passphrase_that_satisfies_both_passes() {
  const { rules } = resolveTier("high");
  Assert.deepEqual(
    failingRules("Correct-Horse-Battery-Staple-9", rules),
    [],
    "a passphrase with a capital, a digit and a symbol passes both"
  );
});

add_task(async function test_an_estimator_failure_is_not_a_pass() {
  // A requirement that cannot be checked has not been met. Silently accepting
  // would tell the user their password cleared a bar nobody measured.
  const { rules } = resolveTier("high");
  const broken = () => ({ score: null, error: "boom" });
  Assert.ok(
    failingRules("Abcdefgh1!", rules, broken).includes("strength"),
    "an estimator that cannot answer must not pass the password"
  );
  const garbage = () => ({ score: 99, error: null });
  Assert.ok(
    failingRules("Abcdefgh1!", rules, garbage).includes("strength"),
    "an out-of-range score is not a pass either"
  );
});

add_task(async function test_low_tier_never_calls_the_estimator() {
  // Score 0 asks for nothing, so the estimator must not run at all -- the
  // dialog evaluates on every keystroke and a 800 KB estimator per keypress
  // would be felt.
  const { rules } = resolveTier("low");
  let called = false;
  const spy = () => {
    called = true;
    return { score: 0, error: null };
  };
  Assert.deepEqual(failingRules("abc", rules, spy), ["min-length"]);
  Assert.equal(called, false, "no score required, so none is computed");
});

add_task(async function test_the_meter_and_the_gate_share_one_score() {
  // Item 57's requirement, as far as it is checkable without a window: the
  // meter value the dialog shows is derived from the score the gate compares
  // against, so the two cannot be computed from different things.
  //
  // The dialog maps the score onto 0-100 in four bands. The relationship that
  // matters is that a password the gate refuses can no longer *display* as
  // perfect -- which is exactly what the old heuristic did with Password1!:
  // 65 of 100 on the meter, accepted by the button.
  const { rules } = resolveTier("high");
  const meter = score => (Number.isInteger(score) ? score * 25 : 0);

  const refused = "Password1!";
  const { score } = estimateScore(refused);
  Assert.greater(failingRules(refused, rules).length, 0, "the gate refuses it");
  Assert.less(
    meter(score),
    100,
    "and the meter cannot show it as perfect, because both read this score"
  );

  // The score is 1, so the bar sits at 25 -- the same number the gate used.
  Assert.equal(score, 1);
  Assert.equal(meter(score), 25);
});

add_task(async function test_a_password_can_pass_while_the_meter_is_not_full() {
  // Worth stating so nobody "fixes" it later: the meter is the score and the
  // gate is the policy floor, so a password scoring exactly the minimum is
  // accepted at 75 of 100. Sharing one computation does not mean sharing one
  // threshold, and pretending otherwise would make the bar meaningless.
  const { rules } = resolveTier("high");
  Assert.equal(rules.minStrength, 3);

  // Measured, not guessed: zxcvbn scores this exactly 3, and it has all four
  // character classes, so it clears the length and class rules too.
  const accepted = "Abcdefgh1!";
  Assert.equal(estimateScore(accepted).score, 3, "exactly the floor");
  Assert.deepEqual(failingRules(accepted, rules), [], "so the gate accepts it");
  Assert.equal(3 * 25, 75, "and the bar reads 75, not 100");
});

add_task(async function test_every_rule_name_is_reachable() {
  // The dialog maps rule names to wording; a name that can be produced but not
  // described would render as a raw identifier in the UI.
  const { rules } = resolveTier("high");
  const produced = new Set(failingRules("a", { ...rules, minStrength: 1 }));
  for (const name of produced) {
    Assert.ok(RULES.includes(name), `${name} is a declared rule`);
  }
  Assert.ok(RULES.includes("strength"), "strength is a declared rule");
});
