/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Utilities for keeping log messages readable.
 */

const DEFAULT_MAX_LENGTH = 500;

/**
 * Shorten a value for inclusion in a log message.
 *
 * Calendar data is routinely large — a whole ICS file, or a malformed MIME
 * part that has been base64-decoded — and a parse error quotes the offending
 * line. Logging the payload in full therefore dumps megabytes into the console
 * and journald for a single failure. A bounded preview keeps the message
 * diagnosable without that, since the beginning of the data is what identifies
 * it and the length says how much was dropped.
 *
 * @param {*} value - The value to shorten; converted to a string.
 * @param {number} [maxLength] - Maximum number of characters to keep.
 * @returns {string} The value, truncated with an ellipsis and its total length.
 */
export function previewForLog(value, maxLength = DEFAULT_MAX_LENGTH) {
  const text = String(value ?? "");
  if (text.length <= maxLength) {
    return text;
  }
  return `${text.slice(0, maxLength)}… [${text.length} characters]`;
}
