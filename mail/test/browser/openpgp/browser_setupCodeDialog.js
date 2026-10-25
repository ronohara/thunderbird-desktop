/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 97 in the dialog: display once, hide, require it back.
 *
 * The module's generator and comparison are verified in `test_setupCode.js`.
 * This is about the two properties the dialog itself has to have:
 *
 *   - **the code is gone before the re-entry appears.** A collapsed view is
 *     still in the document and can be read; the display's text is cleared, so
 *     the second view cannot be completed by looking at the first. That is the
 *     whole difference between this and Enigmail's thirty-second timer, which
 *     could be waited out while the code stayed on screen.
 *   - **a wrong code does not close the dialog.** A user who mistypes a digit
 *     must be able to try again; a dialog that closed on a mismatch would
 *     leave them with a message they cannot open.
 */

"use strict";

const { SetupCode } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/setupCode.sys.mjs"
);

const CODE = "1234-5678-9012-3456-7890-1234-5678-9012-3456";

/**
 * Opens the dialog with a known code.
 *
 * `Services.ww.openWindow` with a **bare string**, which is the one route that
 * both carries something through and returns immediately. Three shapes were
 * tried before this one:
 *
 *   - `openWindow` with an object: the dialog receives a wrapper with nothing
 *     but `QueryInterface` on it, so the code arrived undefined and the dialog
 *     quietly generated its own;
 *   - `openDialog` from the chrome window: synchronous whenever the `dialog`
 *     feature is present, so the opener blocked and the test could never type
 *     into the dialog it had just asked for;
 *   - `openDialog` without that feature: still blocked, from the message
 *     window's principal.
 *
 * A string passes, and the dialog accepts it deliberately -- it takes either a
 * plain object from `openDialog` (what the production caller will use) or a
 * string, so neither route can silently generate a different code than the one
 * the message was encrypted with.
 *
 * @returns {Promise<Window>}
 */
async function openDialog(code) {
  // A property bag, created through XPCOM rather than constructed: the plain
  // object literal does not implement `setProperty`, which is why the earlier
  // attempt failed. `openWindow` requires an `nsISupports` argument and this is
  // the carrier it accepts.
  const args = Cc["@mozilla.org/hash-property-bag;1"].createInstance(
    Ci.nsIWritablePropertyBag2
  );
  if (code) {
    args.setPropertyAsAString("code", code);
  }

  const win = Services.ww.openWindow(
    null,
    "chrome://openpgp/content/ui/setupCodeDialog.xhtml",
    "openpgpSetupCodeDialog",
    "chrome,dialog,centerscreen,resizable",
    args
  );
  await BrowserTestUtils.waitForEvent(win, "load");
  return win;
}

/**
 * The code is displayed in the canonical form the module generates.
 */
add_task(async function theCodeIsShown() {
  const win = await openDialog(CODE);
  try {
    const shown = win.document.getElementById("codeDisplay").textContent;
    info(`FINDING displayed: ${JSON.stringify(shown)}`);
    Assert.equal(shown, CODE, "the code is shown exactly as given");
    Assert.ok(
      /^\d{4}(-\d{4}){8}$/.test(shown),
      "in nine groups of four digits"
    );
    Assert.equal(
      !win.document.getElementById("reentryView").hidden,
      false,
      "and the re-entry view is not shown yet"
    );
  } finally {
    win.close();
  }
});

/**
 * The code leaves the document before re-entry is asked for.
 *
 * Asserted on `textContent`, not on visibility: an element that is merely
 * collapsed or hidden is still readable, and the point of hiding is that the
 * code cannot be copied from it.
 */
add_task(async function theCodeIsGoneBeforeReentry() {
  const win = await openDialog(CODE);
  try {
    win.showReentry();

    Assert.equal(
      win.document.getElementById("codeDisplay").textContent,
      "",
      "the displayed code has been removed, not merely hidden"
    );
    Assert.ok(
      win.document.getElementById("displayView").hidden,
      "the display view is gone"
    );
    Assert.ok(
      !win.document.getElementById("reentryView").hidden,
      "and the re-entry view is showing"
    );

    // Belt and braces: nowhere in the document's text is the code still
    // available, which catches a copy left in a label or an attribute value
    // that a later refactor might add.
    Assert.equal(
      win.document.body.textContent.includes("1234-5678"),
      false,
      "the code does not appear anywhere in the dialog's text"
    );
  } finally {
    win.close();
  }
});

/**
 * A wrong code is refused, with a message, and the dialog stays open.
 */
add_task(async function aWrongCodeIsRefused() {
  const win = await openDialog(CODE);
  try {
    win.showReentry();
    win.document.getElementById("reentryInput").value =
      "1234-5678-9012-3456-7890-1234-5678-9012-3457";
    win.checkReentry();

    const error = win.document.getElementById("reentryError");
    info(`FINDING wrong code: error=${JSON.stringify(error.textContent)}`);
    Assert.ok(!error.hidden, "the mismatch is reported");
    Assert.ok(error.textContent.length, "with a message");
    Assert.equal(
      win.gOutcome?.confirmed,
      null,
      "no outcome is recorded, so the opener cannot mistake it for success"
    );
    Assert.ok(!win.closed, "and the dialog is still open to try again");
  } finally {
    if (!win.closed) {
      win.close();
    }
  }
});

/**
 * The right code, typed without dashes, is accepted and returns the canonical
 * form.
 *
 * The dashes are part of the passphrase string, so what comes back has to be
 * the dashed code even when the user typed the digits straight through.
 */
add_task(async function theRightCodeIsAccepted() {
  const win = await openDialog(CODE);
  // Polled rather than `BrowserTestUtils.windowClosed`, which waits on an
  // event this dialog's close does not raise; the awaited promise timed out
  // with the dialog already gone.
  try {
    win.showReentry();
    win.document.getElementById("reentryInput").value =
      "123456789012345678901234567890123456";
    win.checkReentry();
    await TestUtils.waitForCondition(
      () => win.closed,
      "the dialog to close after a matching code"
    );

    info(
      `FINDING outcome: confirmed=${win.gOutcome?.confirmed} ` +
        `code=${JSON.stringify(win.gOutcome?.code)}`
    );
    Assert.ok(win.gOutcome?.confirmed, "the re-entry was accepted");
    Assert.equal(
      win.gOutcome?.code,
      CODE,
      "and the canonical dashed form is returned, not the digits as typed"
    );
  } finally {
    if (!win.closed) {
      win.close();
    }
  }
});

/**
 * A generated code, when none is supplied, is the specified format.
 *
 * The dialog usually has a code from the caller, because the same one encrypts
 * the message; this is the fallback path, and it must not produce something the
 * specification does not describe.
 */
add_task(async function withoutACodeItGeneratesOne() {
  const win = await openDialog(null);
  try {
    await TestUtils.waitForCondition(
      () => win.document.getElementById("codeDisplay").textContent,
      "a code to be generated"
    );
    const shown = win.document.getElementById("codeDisplay").textContent;
    info(`FINDING generated: ${JSON.stringify(shown)}`);
    Assert.equal(
      SetupCode.digitsOf(shown)?.length,
      36,
      `36 digits were generated, got ${shown}`
    );
    Assert.equal(
      shown,
      SetupCode.format(shown),
      "and it is already in the canonical form"
    );
  } finally {
    win.close();
  }
});
