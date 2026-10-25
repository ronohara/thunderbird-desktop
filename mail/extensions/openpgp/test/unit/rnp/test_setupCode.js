/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 97, the code itself: format, uniformity, and the re-entry check.
 *
 * The format is the specification's, not a choice: 36 digits in nine groups of
 * four, dashes included in the passphrase string. What is worth *testing*
 * rather than asserting in prose is that the digits are uniform -- the code is
 * the only thing standing between a copied setup message and its contents, so
 * a generator that quietly produces fewer than 119 bits is a security defect
 * that looks exactly like a working one.
 *
 * The uniformity check is a chi-square over 200,000 digits. Rejection sampling
 * (as here) passes it; `byte % 10` over the full byte range -- which is what
 * Enigmail did -- also passes it, because Enigmail's bias is about a tenth of a
 * bit over the whole code and far below this test's resolution. That is why the
 * generator's own comment records the departure rather than this file claiming
 * to have caught it: the honest statement is that the bias is removed because
 * removing it is free, not because a test here would have found it.
 */

"use strict";

const { SetupCode } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/setupCode.sys.mjs"
);

/**
 * Chi-square statistic for a uniform-over-ten expectation.
 *
 * @param {integer[]} counts - Length 10.
 * @returns {number}
 */
function chiSquare(counts) {
  const total = counts.reduce((a, b) => a + b, 0);
  const expected = total / 10;
  return counts.reduce(
    (sum, observed) => sum + (observed - expected) ** 2 / expected,
    0
  );
}

/**
 * The format the specification fixes, and the reasons it gives for fixing it.
 */
add_task(async function theFormatIsTheSpecifiedOne() {
  const code = SetupCode.generate();

  Assert.equal(
    code.length,
    44,
    "36 digits and 8 dashes, which is 44 characters in the dashed form"
  );
  Assert.ok(
    /^\d{4}(-\d{4}){8}$/.test(code),
    `nine groups of four digits joined by dashes, got ${code}`
  );
  Assert.equal(SetupCode.digitsOf(code).length, 36, "36 digits of entropy");

  // The nominal figure the design states. log2(10^36) = 119.6.
  const bits = 36 * Math.log2(10);
  Assert.ok(
    bits > 119 && bits < 120,
    `the code carries about ${bits.toFixed(1)} bits, matching the design's 119`
  );
});

/**
 * Every digit is equally likely.
 *
 * 200,000 digits: at nine degrees of freedom the 99.9th percentile of the
 * chi-square distribution is 27.88, so a threshold of 30 fails roughly once in
 * ten thousand runs on a correct generator -- low enough that a flake is not a
 * practical worry, high enough that a badly biased one fails every time.
 */
add_task(async function theDigitsAreUniform() {
  const counts = new Array(10).fill(0);
  const samples = 20000;
  for (let i = 0; i < samples; i++) {
    const code = SetupCode.generate();
    for (const ch of SetupCode.digitsOf(code)) {
      counts[Number(ch)]++;
    }
  }

  const total = counts.reduce((a, b) => a + b, 0);
  Assert.equal(total, samples * 36, "every digit of every code was counted");

  const statistic = chiSquare(counts);
  info(
    `FINDING uniformity: counts=${JSON.stringify(counts)} ` +
      `chi2=${statistic.toFixed(2)} (threshold 30 at 9 d.f.)`
  );
  Assert.less(
    statistic,
    30,
    "the digits are uniform, so the code carries the bits it is claimed to"
  );

  // And no digit is wildly over-represented, which a chi-square can hide when
  // one bucket is short and another long in compensating amounts.
  const expected = total / 10;
  for (let d = 0; d < 10; d++) {
    Assert.less(
      Math.abs(counts[d] - expected) / expected,
      0.05,
      `digit ${d} is within 5% of its expected count`
    );
  }
});

/**
 * Two codes are different codes.
 *
 * A generator that returned a constant would pass a format check and produce a
 * message anyone who had seen one setup message could open.
 */
add_task(async function codesDiffer() {
  const seen = new Set();
  for (let i = 0; i < 1000; i++) {
    seen.add(SetupCode.generate());
  }
  Assert.equal(seen.size, 1000, "a thousand generated codes are all distinct");
});

/**
 * The re-entry check, including the shapes a user actually types.
 */
add_task(async function theReentryCheckAcceptsWhatAPersonTypes() {
  const code = "1234-5678-9012-3456-7890-1234-5678-9012-3456";

  Assert.ok(SetupCode.matches(code, code), "the code as displayed matches");

  // The same digits without the dashes, which is how many people will type it.
  const noDashes = "123456789012345678901234567890123456";
  Assert.ok(
    SetupCode.matches(noDashes, code),
    "the digits alone match the dashed form"
  );

  // Spaces, as a phone keyboard or a copy-paste may introduce.
  Assert.ok(
    SetupCode.matches("1234 5678 9012 3456 7890 1234 5678 9012 3456", code),
    "spaces instead of dashes match"
  );

  // One wrong digit, which is the case the check exists for.
  Assert.ok(
    !SetupCode.matches("1234-5678-9012-3456-7890-1234-5678-9012-3457", code),
    "a single wrong digit fails"
  );

  // Length problems.
  Assert.ok(
    !SetupCode.matches("1234-5678", code),
    "a partial entry fails rather than matching a prefix"
  );
  Assert.ok(!SetupCode.matches("", code), "an empty entry fails");
  Assert.ok(!SetupCode.matches(null, code), "and so does nothing at all");
});

/**
 * A transposition is not the same code.
 *
 * Worth its own check because a naive implementation that sorts or reformats
 * carelessly can make a reordering invisible.
 */
add_task(async function orderMatters() {
  const a = "1111-2222-3333-4444-5555-6666-7777-8888-9999";
  const b = "9999-8888-7777-6666-5555-4444-3333-2222-1111";
  Assert.ok(
    !SetupCode.matches(a, b),
    "the same digits in another order differ"
  );
});

/**
 * The canonical form is rebuilt from digits, so what is encrypted is always
 * dashed even when the caller started from a bare string.
 */
add_task(async function theCanonicalFormIsAlwaysDashed() {
  const digits = "123456789012345678901234567890123456";
  Assert.equal(
    SetupCode.format(digits),
    "1234-5678-9012-3456-7890-1234-5678-9012-3456",
    "36 digits become the dashed form"
  );
  Assert.equal(
    SetupCode.format("1234-5678-9012-3456-7890-1234-5678-9012-3456"),
    "1234-5678-9012-3456-7890-1234-5678-9012-3456",
    "and an already-dashed code is unchanged"
  );
  Assert.equal(
    SetupCode.format("1234"),
    null,
    "anything short of 36 digits has no canonical form"
  );
});
