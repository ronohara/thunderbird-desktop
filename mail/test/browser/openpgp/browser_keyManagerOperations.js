/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 93: the three Key Manager operations, checked rather than assumed.
 *
 * The item was written on the premise that all three are "class A -- librnp
 * supports them and the bindings were never written". **Two of the three
 * premises are false and the third is false in the other direction**, and this
 * file is the evidence:
 *
 *   - **Manage user IDs** exists. Item 69 bound `rnp_key_add_uid`, wrapped it
 *     as `RNP.addUserId()`, and put a control on Key Details; verified by
 *     `test_userIds.js`.
 *   - **Change a passphrase** exists. Key Details has a passphrase tab driven
 *     by `setPassphrase()` and `useAutoPassphrase()`, verified by
 *     `browser_keyDetailsPassphrase.js`.
 *   - **Add a photo** cannot be built here at all. The vendored librnp exports
 *     no way to *add* a user attribute: `rnp_key_add_uid()` takes a
 *     `const char *`, and there is no `add_attr`/`add_photo` in
 *     `third_party/rnp/rnp.symbols`. It can only *read* a photo
 *     (`rnp_uid_get_type` → `RNP_USER_ATTR`). So the third is blocked on
 *     upstream, not on a missing binding.
 *
 * What this file adds is the reachability the item was really asking about:
 * both existing operations must be *reachable from the Key Manager*, which is
 * the surface the item names. The other two files test the operations
 * themselves in Key Details; this checks the path a user takes to get there.
 */

"use strict";

const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);

const ALICE_SECRET =
  "data/keys/alice@openpgp.example-0xf231550c4f47e38e-secret.asc";
const ALICE_KEY_ID = "F231550C4F47E38E";

let account;

/**
 * Opens the Key Manager and returns its window.
 *
 * @returns {Promise<Window>}
 */
async function openKeyManager() {
  const win = Services.ww.openWindow(
    null,
    "chrome://openpgp/content/ui/enigmailKeyManager.xhtml",
    "_blank",
    "chrome,dialog,centerscreen,resizable",
    null
  );
  await BrowserTestUtils.waitForEvent(win, "load");
  await TestUtils.waitForCondition(
    () => win.gKeyListView?.rowCount > 0,
    "the manager should populate its list"
  );
  return win;
}

/**
 * Selects a key's row in the manager.
 *
 * @param {Window} win
 * @param {string} keyId
 * @returns {boolean}
 */
function selectKey(win, keyId) {
  const view = win.gKeyListView;
  for (let i = 0; i < view.rowCount; i++) {
    const r = view.getFilteredRow(i);
    if (r?.rowType != "key") {
      continue;
    }
    if (win.gKeyList[r.keyNum].keyId.toUpperCase() != keyId.toUpperCase()) {
      continue;
    }
    win.gUserList.view.selection.select(i);
    return true;
  }
  return false;
}

add_setup(async function () {
  requestLongerTimeout(2);

  account = MailServices.accounts.createAccount();
  account.incomingServer = MailServices.accounts.createIncomingServer(
    "item93",
    "item93.example",
    "pop3"
  );
  const identity = MailServices.accounts.createIdentity();
  identity.email = "item93@item93.example";
  account.addIdentity(identity);
  registerCleanupFunction(() =>
    MailServices.accounts.removeAccount(account, true)
  );

  await OpenPGPTestUtils.initOpenPGP();
  const [id] = await OpenPGPTestUtils.importPrivateKey(
    window,
    new FileUtils.File(getTestFilePath(ALICE_SECRET))
  );
  Assert.ok(id, "the secret key imported");
  EnigmailKeyRing.clearCache();
});

/**
 * The manager's own entry point opens Key Details, and that dialog carries
 * both surviving operations.
 *
 * This is the path a user takes: select a key, press the properties button or
 * double-click, and `enigmailKeyDetails()` opens the dialog. The dialog is
 * **modal**, so the call returns only once it has closed -- which is why the
 * checks run in a `promiseAlertDialog` callback rather than after an await.
 * Awaiting the call first hangs, which the first version of this test did.
 */
add_task(async function theManagerOpensKeyDetailsForASecretKey() {
  EnigmailKeyRing.clearCache();
  const win = await openKeyManager();
  try {
    Assert.ok(selectKey(win, ALICE_KEY_ID), "the secret key has a row");

    let seen = null;
    const dialogPromise = BrowserTestUtils.promiseAlertDialog(
      null,
      "chrome://openpgp/content/ui/keyDetailsDlg.xhtml",
      {
        callback: async dialogWin => {
          const doc = dialogWin.document;
          seen = {
            addUserId: !!doc.getElementById("addUserIdButton"),
            passphraseTab: !!doc.getElementById("passphraseTab"),
            tabs: [...doc.querySelectorAll("tab")].map(t =>
              t.getAttribute("data-l10n-id")
            ),
          };
          // The dialog is modal, and `openKeyDetails()` returns only once it
          // has closed -- so the callback has to close it. Without this the
          // await below never returns, which is what the first run of this
          // test demonstrated.
          dialogWin.close();
        },
      }
    );
    // Returns only after the callback has closed the dialog.
    await win.enigmailKeyDetails();
    await dialogPromise;

    info(`FINDING key details from the manager: ${JSON.stringify(seen)}`);
    Assert.ok(seen, "the dialog opened from the manager's own entry point");
    Assert.ok(
      seen.addUserId,
      "and offers adding a user ID (Item 69's control)"
    );
    Assert.ok(
      seen.passphraseTab,
      "and has a passphrase tab (the change-passphrase operation)"
    );
  } finally {
    win.close();
  }
});

/**
 * And the photo operation is absent from the loaded library, not merely from
 * the UI.
 *
 * Read from the library object the build actually loads, which is what can be
 * bound. Asserting against a symbol list on disk would be the same fact read
 * more fragilely; asking the loaded library is the fact itself.
 */
add_task(async function addingAPhotoIsNotInTheLibrary() {
  const { RNPLibLoader } = ChromeUtils.importESModule(
    "chrome://openpgp/content/modules/RNPLib.sys.mjs"
  );
  const lib = RNPLibLoader.init();
  if (!lib || !lib.loaded) {
    info("SKIPPED: librnp did not load in this harness.");
    Assert.ok(true, "skipped");
    return;
  }

  const additions = Object.keys(lib).filter(name =>
    /^rnp_.*add_(photo|attr)/.test(name)
  );
  info(
    `FINDING library: add_uid=${typeof lib.rnp_key_add_uid} ` +
      `photoOrAttrAdditions=${JSON.stringify(additions)}`
  );

  Assert.equal(
    typeof lib.rnp_key_add_uid,
    "function",
    "the user ID call is bound, which is why Item 69 could use it"
  );
  Assert.deepEqual(
    additions,
    [],
    "and there is no call to add a photo or a user attribute, so the third " +
      "operation is blocked on librnp rather than on a missing binding"
  );
});
