/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

const { assess, shouldShow, Population, SNOOZE_MS, ACK_PREF, NOT_NOW_PREF } =
  ChromeUtils.importESModule("resource:///modules/OpenPgpExposure.sys.mjs");

const HOUR = 60 * 60 * 1000;

add_task(async function test_three_populations() {
  // Design 12.5's split, and the reason the message has to differ: telling a
  // GnuPG-only user that their *OpenPGP key* is at risk would be false, and
  // telling a user with nothing stored that anything is at risk is noise.
  Assert.equal(
    assess({ secretKeys: 1 }).population,
    Population.InternalKey,
    "a secret key in the profile is the strongest case"
  );
  Assert.equal(
    assess({ secretKeys: 0, savedLogins: 3 }).population,
    Population.CredentialsOnly,
    "saved logins alone are the credentials population"
  );
  Assert.equal(
    assess({ secretKeys: 0, clientCerts: 1 }).population,
    Population.CredentialsOnly,
    "a client certificate counts the same as a saved login"
  );
  Assert.equal(
    assess({}).population,
    Population.Nothing,
    "nothing stored is the population that must stay silent"
  );
});

add_task(async function test_a_primary_password_does_not_change_population() {
  // Item 19's condition, kept: a user who set a Primary Password has been told
  // the problem is handled, and design 1.2 shows the derivation is weak
  // regardless. The population is about where the secret sits, not about
  // whether a password exists.
  const withPw = assess({ secretKeys: 2, hasPrimaryPassword: true });
  Assert.equal(withPw.population, Population.InternalKey);
  Assert.equal(withPw.hasPrimaryPassword, true);
});

add_task(async function test_silent_when_nothing_to_protect() {
  // Checked before any dismissal state, so a cleaned-up profile never sees a
  // notice about material it no longer has.
  const r = shouldShow({
    assessment: assess({}),
    notNow: false,
    acknowledgedAt: "",
  });
  Assert.equal(r.show, false);
  Assert.equal(r.reason, "nothing-to-protect");
});

add_task(async function test_shown_by_default() {
  const r = shouldShow({ assessment: assess({ secretKeys: 1 }) });
  Assert.equal(r.show, true);
  Assert.equal(r.reason, "no-dismissal");
});

add_task(async function test_not_now_holds_for_the_session() {
  const r = shouldShow({
    assessment: assess({ secretKeys: 1 }),
    notNow: true,
  });
  Assert.equal(r.show, false);
  Assert.equal(r.reason, "deferred-this-session");
});

add_task(async function test_acknowledgement_expires() {
  const now = Date.parse("2026-10-24T12:00:00Z");

  // A day later: still snoozed.
  let r = shouldShow({
    assessment: assess({ secretKeys: 1 }),
    acknowledgedAt: new Date(now - 24 * HOUR).toISOString(),
    now,
  });
  Assert.equal(r.show, false);
  Assert.equal(r.reason, "acknowledged");

  // Twenty-nine days later: still snoozed, just.
  r = shouldShow({
    assessment: assess({ secretKeys: 1 }),
    acknowledgedAt: new Date(now - 29 * 24 * HOUR).toISOString(),
    now,
  });
  Assert.equal(r.show, false);

  // Thirty-one days later: back.
  r = shouldShow({
    assessment: assess({ secretKeys: 1 }),
    acknowledgedAt: new Date(now - 31 * 24 * HOUR).toISOString(),
    now,
  });
  Assert.equal(
    r.show,
    true,
    "a dismissal that never expires hides the notice forever"
  );
  Assert.equal(r.reason, "acknowledgement-expired");
});

add_task(async function test_unreadable_acknowledgement_does_not_silence_it() {
  // A corrupted preference must not hide the notice permanently. Erring
  // towards showing is the safe direction here: the cost is one notice, the
  // cost of the other direction is a user who never learns.
  const r = shouldShow({
    assessment: assess({ secretKeys: 1 }),
    acknowledgedAt: "not-a-date",
  });
  Assert.equal(r.show, true);
  Assert.equal(r.reason, "acknowledgement-unreadable");
});

add_task(async function test_the_notice_never_blocks_sending() {
  // Design 12.5's fourth rule, expressed as a property of this module: it
  // answers "should a notice be shown" and returns nothing a caller could
  // reasonably use to refuse an action. Asserted on the shape of the result,
  // because the rule is about what callers can do with it.
  const r = shouldShow({ assessment: assess({ secretKeys: 1 }) });
  Assert.deepEqual(
    Object.keys(r).sort(),
    ["population", "reason", "show"],
    "no field that reads as a verdict on the user's mail"
  );
  Assert.equal(typeof r.show, "boolean");
});

add_task(async function test_pref_names_are_stable() {
  // A renamed preference silently resets every user's dismissal, which is the
  // failure mode the expiry rule exists to avoid.
  Assert.equal(ACK_PREF, "mail.openpgp.exposure.acknowledged");
  Assert.equal(NOT_NOW_PREF, "mail.openpgp.exposure.notNow");
  Assert.equal(SNOOZE_MS, 30 * 24 * 60 * 60 * 1000);
});
