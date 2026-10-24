/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

// The module reads and writes the process environment, so nothing here needs
// a profile; do_get_profile() is called by the head file regardless.

const { applyPBEIterationFloor, currentPBEIterationFloor, PREF } =
  ChromeUtils.importESModule("resource:///modules/PBEIterationFloor.sys.mjs");

const ENV_VAR = "NSS_MIN_MP_PBE_ITERATION_COUNT";

/** A stand-in for nsIPrefBranch that answers one integer. */
function fakePrefs(value) {
  return {
    getIntPref(name, _fallback) {
      Assert.equal(name, PREF, "the module reads the documented preference");
      return value;
    },
  };
}

/** A stand-in for nsIEnvironment holding one variable. */
function fakeEnv(initial = null) {
  const values = new Map();
  if (initial !== null) {
    values.set(ENV_VAR, initial);
  }
  return {
    exists(name) {
      return values.has(name);
    },
    get(name) {
      return values.get(name) ?? "";
    },
    set(name, value) {
      values.set(name, String(value));
    },
    _values: values,
  };
}

add_task(async function test_pref_and_env_var_names() {
  // Both names are part of the contract: the preference is what an
  // administrator sets, and the variable is what softoken reads.
  // security/nss/lib/softoken/sftkpwd.c: getPBEIterationCount() calls
  // getenv("NSS_MIN_MP_PBE_ITERATION_COUNT").
  Assert.equal(PREF, "mail.e2ee.primary_password_min_iteration_count");
  Assert.equal(ENV_VAR, "NSS_MIN_MP_PBE_ITERATION_COUNT");
});

add_task(async function test_zero_leaves_nss_alone() {
  const env = fakeEnv();
  const result = applyPBEIterationFloor(fakePrefs(0), env);
  Assert.equal(result.applied, false, "0 means no floor is imposed");
  Assert.equal(result.value, 0);
  Assert.ok(
    !env.exists(ENV_VAR),
    "the variable must not be set when the preference asks for nothing, " +
      "or NSS would lose its own minimum in favour of a lower one"
  );
});

add_task(async function test_negative_is_treated_as_zero() {
  const env = fakeEnv();
  const result = applyPBEIterationFloor(fakePrefs(-5), env);
  Assert.equal(result.applied, false);
  Assert.ok(!env.exists(ENV_VAR));
});

add_task(async function test_positive_sets_the_variable() {
  const env = fakeEnv();
  const result = applyPBEIterationFloor(fakePrefs(1010000), env);
  Assert.equal(result.applied, true);
  Assert.equal(result.value, 1010000);
  Assert.equal(
    env.get(ENV_VAR),
    "1010000",
    "softoken parses this with atoi, so it must be a plain integer"
  );
});

add_task(async function test_pref_overrides_an_inherited_variable() {
  // The design's argument for a preference over a launcher line is that a
  // locked policy cannot be defeated by whatever launched the application.
  // That only holds if a set preference wins over an inherited variable.
  const env = fakeEnv("10000");
  const result = applyPBEIterationFloor(fakePrefs(1010000), env);
  Assert.equal(result.applied, true);
  Assert.equal(result.previous, "10000", "the previous value is reported");
  Assert.equal(env.get(ENV_VAR), "1010000", "the preference wins");
});

add_task(async function test_inherited_variable_survives_an_unset_pref() {
  // The other half of the rule: someone who exported the variable
  // deliberately keeps it when the preference says nothing.
  const env = fakeEnv("840000");
  const result = applyPBEIterationFloor(fakePrefs(0), env);
  Assert.equal(result.applied, false);
  Assert.equal(
    result.value,
    840000,
    "the floor in force is reported, not the preference value"
  );
  Assert.equal(env.get(ENV_VAR), "840000", "left untouched");
});

add_task(async function test_current_floor_reads_the_environment() {
  // currentPBEIterationFloor() exists so a report can state what softoken
  // will actually use. It reads the environment, not the preference, so it
  // cannot disagree with NSS.
  const env = Services.env;
  const saved = env.exists(ENV_VAR) ? env.get(ENV_VAR) : null;
  try {
    if (saved === null) {
      env.set(ENV_VAR, "");
    }
    env.set(ENV_VAR, "1010000");
    Assert.equal(currentPBEIterationFloor(), 1010000);

    env.set(ENV_VAR, "not-a-number");
    Assert.equal(
      currentPBEIterationFloor(),
      0,
      "an unparseable value means no floor, not NaN"
    );

    env.set(ENV_VAR, "0");
    Assert.equal(currentPBEIterationFloor(), 0, "0 is not a floor");
  } finally {
    if (saved === null) {
      env.set(ENV_VAR, "");
    } else {
      env.set(ENV_VAR, saved);
    }
  }
});
