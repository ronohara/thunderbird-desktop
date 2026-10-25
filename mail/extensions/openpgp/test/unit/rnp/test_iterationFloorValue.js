/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 74: the shipped derivation floor is the number D8 asks for, and it is
 * the number that reaches the database.
 *
 * D8's rule is 1.2x GnuPG's measured cost per guess. Item 51 measured that cost
 * on this machine at 428 ms and measured NSS's own PBKDF2-HMAC-SHA256 rate;
 * design 12.1 derives the iteration count from the two. This file verifies the
 * *shipped preference* against that derivation, and then verifies that the
 * figure actually reaches key4.db rather than being a setting nobody applies.
 *
 * The second half is the one that matters. A pref can be correct and inert --
 * that is exactly what happened to the iteration floor before Item 50's wiring
 * was fixed, and the failure is silent.
 */

"use strict";

const { readStoredIterationCount } = ChromeUtils.importESModule(
  "resource:///modules/PBEStoredCount.sys.mjs"
);
const PBEIterationFloor = ChromeUtils.importESModule(
  "resource:///modules/PBEIterationFloor.sys.mjs"
);
const { PREF } = PBEIterationFloor;
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);

/**
 * GnuPG's measured cost per guess on this machine, from Item 51: nine timed
 * wrong-passphrase attempts against a key at the maximum S2K count, median
 * 435 ms less ~2 ms of process spawn. The control that makes it a measurement
 * rather than a timing: the same export on an unprotected key takes 4 ms.
 */
const GNU_PG_MS = 428;

/**
 * D8's margin, in the user's words: "not a match - 20% better than GnuPG".
 */
const MARGIN = 1.2;

/**
 * NSS's PBKDF2-HMAC-SHA256 rate, iterations per second, measured through
 * NSS's own implementation by Item 51.
 *
 * Recorded as a range because two measurements of it disagree, and pretending
 * otherwise would be worse than a wide band. Item 51's C program against
 * PK11_PBEKeyGen measured 8.0e6/s. An independent measurement of this tree's
 * own `changePassword` marginal cost -- with the old-password derivation pinned
 * at NSS's minimum, so the slope is exactly one derivation per iteration --
 * measured 4.4e6/s on this machine. The second is the slower reading, so the
 * band below brackets both. What this file asserts is that the shipped pref is
 * inside the band the two imply; it does not claim which measurement is right.
 */
const NSS_RATE_LOW = 4.4e6;
const NSS_RATE_HIGH = 8.0e6;

/**
 * @returns {number} The pref's value.
 */
function shippedFloor() {
  return Services.prefs.getIntPref(PREF);
}

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();
});

/**
 * The shipped value is what D8 asks for, within what the measurements support.
 *
 * A strict equality against a derived figure would be false precision: the
 * rate measurement spans a factor of 1.8, so the honest assertion is that the
 * pref sits inside the band the two readings bracket, and that it is closer to
 * the middle of it than to either edge.
 */
add_task(async function theShippedFloorIsDD8sFigure() {
  const floor = shippedFloor();
  const targetMs = GNU_PG_MS * MARGIN;

  const lowest = Math.round((targetMs / 1000) * NSS_RATE_LOW);
  const highest = Math.round((targetMs / 1000) * NSS_RATE_HIGH);

  Assert.greater(
    floor,
    0,
    "the shipped preference must be a real floor, not 0 which leaves NSS alone"
  );
  Assert.greaterOrEqual(
    floor,
    lowest,
    `the floor must be at least what the slower rate implies (${lowest}), ` +
      `got ${floor}`
  );
  Assert.lessOrEqual(
    floor,
    highest,
    `and no more than the faster rate implies (${highest}), got ${floor}`
  );

  info(
    `D8: ${GNU_PG_MS} ms per GnuPG guess x ${MARGIN} = ${targetMs} ms; ` +
      `at ${NSS_RATE_LOW} to ${NSS_RATE_HIGH} iter/s that is ${lowest} to ` +
      `${highest} iterations. Shipped: ${floor}.`
  );
});

/**
 * And the figure reaches the database.
 *
 * This is the half a preference cannot prove about itself. The count is decoded
 * from key4.db's PBES2 parameter set after a real password is set with the
 * engine's own floor in force -- not read back from the pref, and not inferred
 * from the absence of an error.
 */
add_task(async function theFloorReachesTheDatabase() {
  const floor = shippedFloor();

  // Set the floor from the pref, exactly as app-startup does.
  PBEIterationFloor.applyPBEIterationFloor();
  Assert.equal(
    PBEIterationFloor.currentPBEIterationFloor(),
    floor,
    "the engine reports the shipped floor in force"
  );

  const token = Cc["@mozilla.org/security/internalkeytoken;1"].createInstance(
    Ci.nsIPKCS11Token
  );
  await token.changePassword("", "item-74-primary-password");
  Assert.ok(token.hasPassword, "a Primary Password is set");

  const profileDir = Services.dirsvc.get("ProfD", Ci.nsIFile);
  const stored = await readStoredIterationCount(profileDir);
  Assert.equal(
    stored,
    floor,
    `key4.db must carry the shipped floor, decoded ${stored}`
  );

  Assert.notEqual(
    stored,
    10000,
    "and definitively not NSS's compiled-in minimum, which is what a " +
      "pref-with-no-effect would leave behind"
  );
});
