/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 54's nag, and Item 64 row 5: the notice follows the population, stays
 * silent when it should, and re-arms after a dismissal expires.
 *
 * The decision itself is unit-tested in `test_openPgpExposure.js`. What can
 * only be tested here is that the banner actually appears in the 3-pane and
 * that its buttons do what they say -- a decision function that nothing calls
 * passes every unit test it has.
 *
 * The three populations are exercised by controlling what the profile holds,
 * not by stubbing the assessment: a stubbed assessment would prove the banner
 * renders and nothing about whether the profile is read correctly.
 */

"use strict";

// Namespaces, not destructured members. Both modules export individual
// functions and constants and no member named after the module, so
// `{ OpenPgpExposure }` would be undefined -- the same mistake that made
// changemp.js's policy reads throw.
const OpenPgpExposureUI = ChromeUtils.importESModule(
  "resource:///modules/OpenPgpExposureUI.sys.mjs"
);
const OpenPgpExposure = ChromeUtils.importESModule(
  "resource:///modules/OpenPgpExposure.sys.mjs"
);

const EXPOSURE_NOTIFICATION = OpenPgpExposureUI.EXPOSURE_NOTIFICATION;

const ACK_PREF = OpenPgpExposure.ACK_PREF;
const NOT_NOW_PREF = OpenPgpExposure.NOT_NOW_PREF;

/**
 * The notice currently showing in the 3-pane, if any.
 *
 * @returns {?Element}
 */
function findNotice() {
  // The 3-pane is its own document, reached through tabmail. Looking in the
  // test's window found nothing, which read as "the notice never appeared".
  const box = document
    .getElementById("tabmail")
    ?.currentAbout3Pane?.document.getElementById("threadPaneNotificationBox");
  if (!box) {
    return null;
  }
  return box.querySelector(
    `notification-message[value="${EXPOSURE_NOTIFICATION}"]`
  );
}

/**
 * Waits for the notice to be present, which is asynchronous because the
 * profile survey and the keyring read are.
 *
 * @returns {Promise<Element>} The notice.
 */
async function waitForNotice() {
  await TestUtils.waitForCondition(
    () => findNotice(),
    "the exposure notice should appear"
  );
  return findNotice();
}

/**
 * @returns {Promise<void>} Resolves once the notice is gone.
 */
async function waitForNoNotice() {
  await TestUtils.waitForCondition(
    () => !findNotice(),
    "the exposure notice should not be showing"
  );
}

/**
 * The profile this test runs in has saved logins, which is the
 * credentials-only population. Nothing in the harness gives it an internal
 * OpenPGP key, and creating one would be a larger fixture than the assertion
 * needs -- so the internal-key population is exercised through the assessment
 * rather than through the banner. Said here rather than left implicit.
 */
add_setup(async function () {
  // A saved login is what puts this profile in the credentials-only
  // population. Without one the harness profile has nothing to protect and the
  // notice correctly stays silent -- which is a test of the silence, not of the
  // notice. Added here so the population under test is the populated one.
  const login = Cc["@mozilla.org/login-manager/loginInfo;1"].createInstance(
    Ci.nsILoginInfo
  );
  login.init(
    "https://example.com",
    "https://example.com",
    null,
    "exposure-test",
    "not-a-real-password",
    "",
    ""
  );
  await Services.logins.addLoginAsync(login);
  registerCleanupFunction(async () => {
    await Services.logins.removeAllLoginsAsync();
  });

  await SpecialPowers.pushPrefEnv({
    set: [
      [ACK_PREF, ""],
      [NOT_NOW_PREF, false],
    ],
  });
  // The 3-pane is already open in this harness and its notice was evaluated
  // before the prefs above were set. Re-running the evaluation is enough, and
  // cheaper and less disruptive than opening another tab -- which also left an
  // unexpected tab behind for the harness's end-of-run check.
  const about3Pane = document.getElementById("tabmail").currentAbout3Pane;
  const container = about3Pane.document.getElementById(
    "threadPaneNotificationBox"
  );
  await OpenPgpExposureUI.refreshNotice(
    new about3Pane.MozElements.NotificationBox(element =>
      container.append(element)
    )
  );
});

/**
 * The notice appears for a profile that has something to protect, and it is the
 * credentials wording rather than the key wording -- saying "your secret keys"
 * to a profile with none would be alarming about the wrong thing.
 */
add_task(async function noticeAppearsForCredentialsOnly() {
  const survey = await OpenPgpExposureUI.surveyProfile();
  Assert.greater(
    survey.savedLogins,
    0,
    "the test profile should have saved logins to protect"
  );

  const decision = await OpenPgpExposureUI.decide();
  Assert.equal(
    decision.population,
    OpenPgpExposure.Population.CredentialsOnly,
    "the test profile is the credentials-only population"
  );

  const notice = await waitForNotice();
  Assert.ok(notice, "the notice should be showing");
  // The rendered text, not the attribute: the notification element carries the
  // localized message in its shadow content, and reading `data-l10n-id` off the
  // host returns null. The text is also the better assertion -- it is what the
  // user reads.
  const text = notice.messageText.textContent;
  Assert.ok(
    text.includes("saves passwords"),
    `the notice should use the credentials wording, read: "${text}"`
  );
  Assert.ok(
    !text.includes("secret key"),
    "and must not claim there are secret keys when there are none"
  );
});

/**
 * "Not now" hides it for the session and records that it did.
 */
add_task(async function notNowDefersForTheSession() {
  const notice = await waitForNotice();
  const notNow = notice.querySelector(".notification-button");
  Assert.ok(notNow, "the notice must offer a 'not now' button");

  notNow.click();
  await waitForNoNotice();

  Assert.ok(
    Services.prefs.getBoolPref(NOT_NOW_PREF, false),
    "the deferral must be recorded, not merely enacted"
  );

  // And a fresh evaluation agrees with what the user saw.
  const decision = await OpenPgpExposureUI.decide();
  Assert.equal(
    decision.reason,
    "deferred-this-session",
    "and the decision should say why it is silent"
  );
});

/**
 * A recorded acknowledgement silences it, and an expired one brings it back.
 * This is the re-arming half of Item 64 row 5.
 */
add_task(async function acknowledgementExpiresAndReArms() {
  await SpecialPowers.pushPrefEnv({
    set: [
      [ACK_PREF, new Date().toISOString()],
      [NOT_NOW_PREF, false],
    ],
  });

  const fresh = await OpenPgpExposureUI.decide();
  Assert.equal(
    fresh.show,
    false,
    "a fresh acknowledgement must silence the notice"
  );
  Assert.equal(fresh.reason, "acknowledged", "and say that it did");

  // Older than the snooze window. Written as a prefs push rather than by
  // waiting a month.
  const longAgo = new Date(Date.now() - 400 * 24 * 60 * 60 * 1000);
  await SpecialPowers.pushPrefEnv({
    set: [[ACK_PREF, longAgo.toISOString()]],
  });

  const expired = await OpenPgpExposureUI.decide();
  Assert.equal(
    expired.show,
    true,
    "an expired acknowledgement must let the notice return"
  );
  Assert.equal(
    expired.reason,
    "acknowledgement-expired",
    "and say that it expired rather than that nothing was ever set"
  );
});

/**
 * A profile with nothing to protect is never told about it. This is the
 * population that makes the notice noise if it is wrong, and the reason the
 * check is ordered first in `shouldShow()`.
 */
add_task(async function nothingToProtectIsSilent() {
  const assessment = OpenPgpExposure.assess({
    secretKeys: 0,
    savedLogins: 0,
    clientCerts: 0,
  });
  Assert.equal(
    assessment.population,
    OpenPgpExposure.Population.Nothing,
    "an empty profile is the nothing population"
  );

  const decision = OpenPgpExposure.shouldShow({
    assessment,
    notNow: false,
    acknowledgedAt: "",
  });
  Assert.equal(decision.show, false, "and is never told anything");
  Assert.equal(
    decision.reason,
    "nothing-to-protect",
    "and the reason is that there is nothing to protect"
  );
});

/**
 * A profile with an internal key gets the key wording, and the count is the
 * number of keys rather than a boolean.
 */
add_task(async function internalKeyGetsItsOwnWording() {
  const assessment = OpenPgpExposure.assess({
    secretKeys: 3,
    savedLogins: 12,
    clientCerts: 0,
  });
  Assert.equal(
    assessment.population,
    OpenPgpExposure.Population.InternalKey,
    "keys dominate credentials: the more serious population wins"
  );
  Assert.equal(
    assessment.secretKeys,
    3,
    "and the count is carried through, not flattened to a flag"
  );
});
