/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 97: show the setup code once, then require it back.
 *
 * The specification's recommendation, and the one place this build deliberately
 * does not follow Enigmail: the reference implementation disabled its Next
 * button for thirty seconds (`autocryptInitiateBackup.js`,
 * `delayedEnableNext`), which can be waited out while reading the code off the
 * screen and establishes nothing. Requiring the code to be typed back is the
 * check the specification describes as "a recommended defense against worse
 * annoyance: it ensures that the code was actually written down and the
 * Autocrypt Setup Message is not rendered useless".
 *
 * Two views rather than a wizard: the code, then the re-entry. The code is
 * hidden before the second appears and is never restored, so the second view
 * cannot be completed by reading the first.
 */

"use strict";

var { SetupCode } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/setupCode.sys.mjs"
);

/**
 * A Localization instance of this dialog's own.
 *
 * `document.l10n` is asynchronous, and `formatValueSync()` throws on it once
 * its state is async. The same reason the Key Manager and the rules editor keep
 * their own.
 */
var l10n = new Localization(["messenger/openpgp/openpgp.ftl"], true);

/** The code this dialog is asking the user to write down. */
var gSetupCode = "";

/**
 * The result of a successful re-entry.
 *
 * Also written into `window.arguments[0]` when that is an object, which is how
 * `openDialog` returns a value; this copy exists for a caller that opened the
 * dialog with `Services.ww.openWindow`, where no object can be handed back.
 */
var gOutcome = null;

window.addEventListener("DOMContentLoaded", onLoad);

function onLoad() {
  // Given by the opener, or generated here: a caller that already has a code
  // must be able to pass it, because the same code encrypts the message.
  //
  // Two shapes, because two openers exist: a plain object from `openDialog`
  // (what the message window will use), and a bare string from
  // `Services.ww.openWindow` -- which cannot carry an object through at all,
  // as its argument arrives as a wrapper with nothing but `QueryInterface` on
  // it. Accepting both keeps either route from silently generating a
  // *different* code than the one the message was encrypted with.
  const args = window.arguments?.[0];
  let carried = null;
  if (typeof args == "string") {
    carried = args;
  } else if (typeof args?.code == "string") {
    carried = args.code;
  } else if (typeof args?.getPropertyAsAString == "function") {
    // `Services.ww.openWindow` cannot carry a plain object; it takes an
    // `nsISupports`, and a property bag is the carrier that works.
    try {
      carried = args.getPropertyAsAString("code") || null;
    } catch (ex) {
      // The property is absent, which is the generate-a-code case.
      carried = null;
    }
  }
  gSetupCode = carried ?? SetupCode.generate();

  document.getElementById("codeDisplay").textContent = gSetupCode;
  document.getElementById("reentryError").hidden = true;
  document.getElementById("reentryView").hidden = true;
}

/**
 * Hides the code and switches to the re-entry view.
 *
 * Removing the text rather than collapsing the view: a collapsed element is
 * still in the document and can be read, and the point of moving on is that the
 * code is no longer on screen.
 */
function showReentry() {
  document.getElementById("codeDisplay").textContent = "";
  document.getElementById("displayView").hidden = true;
  document.getElementById("reentryView").hidden = false;
  document.getElementById("reentryInput").focus();
}

/**
 * Compares the typed code with the one that was shown.
 *
 * Success closes the dialog with the canonical dashed code as its result, which
 * is what the message is encrypted with. Failure says so and leaves the
 * dialog open, because a user who mistyped one digit should be able to try
 * again without regenerating anything.
 */
function checkReentry() {
  const typed = document.getElementById("reentryInput").value;
  const error = document.getElementById("reentryError");

  if (!SetupCode.matches(typed, gSetupCode)) {
    // One message for every kind of mismatch. A more specific one -- "that is
    // 35 digits" -- would help a little and would also confirm which part of a
    // guessed code was right.
    error.textContent = l10n.formatValueSync(
      "openpgp-setup-code-reentry-mismatch"
    );
    error.hidden = false;
    document.getElementById("reentryInput").focus();
    return;
  }

  const outcome = { confirmed: true, code: SetupCode.format(typed) };

  // Readable from the window by any opener, including one that used
  // `Services.ww.openWindow` and so cannot receive a value back at all.
  gOutcome = outcome;

  // Written to `window.arguments[0]` only when that is a plain object, which is
  // the shape `openDialog` delivers and the shape the production caller will
  // use. A property bag is a native wrapper and assigning a property to it
  // throws `NS_ERROR_XPC_CANT_MODIFY_PROP_ON_WN` -- after the re-entry had
  // already succeeded, which is why the first version of this failed on the
  // one test where everything else had worked.
  const args = window.arguments?.[0];
  const isPlainObject =
    args &&
    typeof args == "object" &&
    typeof args.setPropertyAsAString != "function";
  if (isPlainObject) {
    args.outcome = outcome;
  }

  window.close();
}
