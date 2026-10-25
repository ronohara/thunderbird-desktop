/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * The Autocrypt setup code: generation, formatting and re-entry (Item 97).
 *
 * The specification fixes the format rather than only the length, and gives
 * its reasons: 36 characters in nine groups of four is unambiguous,
 * pronounceable, script-independent, enterable on a phone and comfortable in
 * short-term memory. The dashes are part of the passphrase string -- they are
 * what the code is encrypted with, not decoration applied for display.
 *
 * **The code is generated here and never transmitted.** The specification says
 * so twice; the whole message depends on it, because the setup code is the only
 * thing standing between the message and anyone who receives a copy of it.
 *
 * **One deliberate departure from the reference implementation.** Enigmail
 * generated each digit as `byte % 10` over a uniformly random byte
 * (`autocrypt.jsm:993`), which is modulo bias: 256 is not a multiple of 10, so
 * digits 0-5 come up 26 times in 256 and 6-9 come up 25. The skew is small --
 * about a tenth of a bit over the whole code -- and it is also free to remove,
 * which is why it is removed here rather than copied. Rejection sampling costs
 * a few discarded bytes and makes every digit exactly uniform.
 */

/** Nine groups of four: the specification's `numeric9x4`. */
const GROUPS = 9;
const GROUP_LENGTH = 4;
const DIGIT_COUNT = GROUPS * GROUP_LENGTH;

/** 250 is the largest multiple of 10 a byte can hold; above it, redraw. */
const UNBIASED_LIMIT = 250;

export const SetupCode = {
  GROUPS,
  GROUP_LENGTH,
  DIGIT_COUNT,

  /**
   * One uniformly random digit, 0-9.
   *
   * Rejection sampling rather than `% 10`: bytes 250-255 are discarded so that
   * 0-249 divides evenly into ten buckets of 25. A modulo over the full byte
   * range would make the first six digits a fraction more likely, which is a
   * bias in the one value the whole message's confidentiality rests on.
   *
   * `crypto.getRandomValues` is the platform CSPRNG, the same one
   * `masterpass.sys.mjs` uses for the profile password.
   *
   * @returns {integer} 0-9, uniform.
   */
  randomDigit() {
    // A fixed buffer would work too; a fresh one per call keeps this function
    // free of hidden state, and the cost is a three-byte allocation.
    const candidate = new Uint8Array(1);
    for (;;) {
      crypto.getRandomValues(candidate);
      if (candidate[0] < UNBIASED_LIMIT) {
        return candidate[0] % 10;
      }
      // Loop: a value above the limit carries leftover bias, so it is dropped
      // rather than folded in.
    }
  },

  /**
   * A new setup code, in its canonical dashed form.
   *
   * @returns {string} `dddd-dddd-dddd-dddd-dddd-dddd-dddd-dddd-dddd`.
   */
  generate() {
    const groups = [];
    for (let g = 0; g < GROUPS; g++) {
      let group = "";
      for (let d = 0; d < GROUP_LENGTH; d++) {
        group += String(this.randomDigit());
      }
      groups.push(group);
    }
    return groups.join("-");
  },

  /**
   * The digits of a typed code, ignoring everything that is not a digit.
   *
   * Only the digits carry entropy, and a user retyping a code may or may not
   * reproduce the dashes -- some will copy them, some will type the 36 digits
   * straight through, and a phone keyboard may insert spaces. All three are the
   * same code, so the comparison is made on the digits and the canonical form
   * is rebuilt from them.
   *
   * @param {string} input
   * @returns {?string} 36 digits, or null when that is not what was typed.
   */
  digitsOf(input) {
    if (typeof input != "string") {
      return null;
    }
    const digits = input.replace(/\D/g, "");
    return digits.length == DIGIT_COUNT ? digits : null;
  },

  /**
   * Put 36 digits back into the canonical dashed form.
   *
   * @param {string} digits
   * @returns {?string} The dashed code, or null when not exactly 36 digits.
   */
  format(digits) {
    const only = this.digitsOf(digits);
    if (!only) {
      return null;
    }
    const groups = [];
    for (let g = 0; g < GROUPS; g++) {
      groups.push(only.slice(g * GROUP_LENGTH, (g + 1) * GROUP_LENGTH));
    }
    return groups.join("-");
  },

  /**
   * Whether a typed code matches the one that was shown.
   *
   * This is the check the specification recommends in place of a timer, and
   * the reason it is worth the annoyance is in its own words: it "ensures that
   * the code was actually written down and the Autocrypt Setup Message is not
   * rendered useless". A thirty-second delay establishes nothing -- it can be
   * waited out while reading the code off the screen.
   *
   * Comparison is on digits, so a user who types the dashes and one who does
   * not both succeed; a user who mistypes a digit fails.
   *
   * @param {string} typed - What the user entered.
   * @param {string} expected - The code that was displayed.
   * @returns {boolean}
   */
  matches(typed, expected) {
    const a = this.digitsOf(typed);
    const b = this.digitsOf(expected);
    if (!a || !b) {
      return false;
    }
    // Compared as digits rather than by rebuilding both into the canonical
    // form, because rebuilding would make a *wrong* six-digit prefix followed
    // by the right remainder indistinguishable from a transposition. Digits
    // are what carry the secret; the dashes are a rendering of them.
    if (a.length != b.length) {
      return false;
    }
    // Constant-time-ish: the whole comparison runs for any same-length input,
    // so the timing does not reveal where a mismatch is. The threat model here
    // is a user retyping a code, not an attacker with a stopwatch, but the cost
    // of writing it this way is nil.
    let different = 0;
    for (let i = 0; i < a.length; i++) {
      different |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return different == 0;
  },
};
