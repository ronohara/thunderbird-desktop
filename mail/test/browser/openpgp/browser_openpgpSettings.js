/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Tests the three states the OpenPGP settings description can report, and the
 * first-use offer of a GnuPG key.
 *
 * Both live in am-e2e.js, which is a classic chrome script rather than a
 * module, so this drives the loaded page and calls the functions directly. That
 * keeps the harness independent of the dialogs the page would otherwise open,
 * and it is the reason the checks run headless: what is asserted is which
 * message is chosen and what is recorded on the identity, not what a prompt
 * looks like.
 *
 * Deliberately a separate file from browser_keyWizard.js, which the manifest
 * excludes on Linux and in headless runs (bug 1806870) -- Stage 1's verification
 * would otherwise never run in CI.
 */

"use strict";

const {
  click_account_tree_row,
  get_account_tree_row,
  promise_account_tree_load,
} = ChromeUtils.importESModule(
  "resource://testing-common/mail/AccountManagerHelpers.sys.mjs"
);
const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);
var { open_content_tab_with_url } = ChromeUtils.importESModule(
  "resource://testing-common/mail/ContentTabHelpers.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { GPGME } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/GPGME.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);

const KEY_ID = "F231550C4F47E38E";
const SECRET_FILE =
  "data/keys/alice@openpgp.example-0xf231550c4f47e38e-secret.asc";

var gAccount;
var gIdentity;
var gTab;
var tabDocument;
var tabWindow;

var gOriginalInit;
var gOriginalGetFprs;

/**
 * Replace the GnuPG boundary with answers the test controls.
 *
 * @param {object} [options] - What the stub should answer.
 * @param {boolean} [options.readable] - Whether the keyring can be read.
 * @param {string[]} [options.fingerprints] - Fingerprints it holds.
 */
function stubGnuPG({ readable = true, fingerprints = [] } = {}) {
  GPGME.init = () => readable;
  GPGME.getSecretKeyFingerprintsForEmail = () => fingerprints;
}

/** Restore the GnuPG boundary and drop anything the test left on the identity. */
function restoreGnuPG() {
  GPGME.init = gOriginalInit;
  GPGME.getSecretKeyFingerprintsForEmail = gOriginalGetFprs;
}

/**
 * Capture the prompts the page raises, and answer with a chosen button.
 *
 * @param {object} answers - `button` (index to return), `checkbox` (value to
 *   leave in the object the page passes for the checkbox), `calls` (array the
 *   invocations are recorded into).
 */
function stubPrompt(answers) {
  Services.prompt = {
    confirmEx(
      window,
      title,
      text,
      flags,
      b0,
      b1,
      b2,
      checkboxLabel,
      checkboxObj
    ) {
      answers.calls.push({ text, b0, b1, checkboxLabel });
      if (checkboxObj) {
        checkboxObj.value = answers.checkbox;
      }
      return answers.button;
    },
    alert() {},
    QueryInterface: ChromeUtils.generateQI(["nsIPromptService"]),
  };
}

/**
 * A file under this test's data directory.
 *
 * Browser tests have no do_get_file(), so the chrome URL is resolved the way
 * the rest of the suite does it.
 *
 * @param {string} name - Path relative to the test directory.
 * @returns {nsIFile} The file.
 */
function getTestFile(name) {
  const ChromeRegistry = Cc["@mozilla.org/chrome/chrome-registry;1"].getService(
    Ci.nsIChromeRegistry
  );
  const chromeUrl = Services.io.newURI(getRootDirectory(gTestPath) + name);
  return ChromeRegistry.convertChromeURL(chromeUrl).QueryInterface(
    Ci.nsIFileURL
  ).file;
}

/**
 * Put the real prompt service back.
 *
 * @param {nsIPromptService} original - The service to restore.
 */
function restorePrompt(original) {
  Services.prompt = original;
}

add_setup(async function () {
  gOriginalInit = GPGME.init;
  gOriginalGetFprs = GPGME.getSecretKeyFingerprintsForEmail;

  gAccount = MailServices.accounts.createAccount();
  gAccount.incomingServer = MailServices.accounts.createIncomingServer(
    "alice",
    "openpgp.example",
    "pop3"
  );
  gIdentity = MailServices.accounts.createIdentity();
  gIdentity.email = "alice@openpgp.example";
  gIdentity.fullName = "Alice";
  gAccount.addIdentity(gIdentity);

  await SpecialPowers.pushPrefEnv({
    set: [["mail.openpgp.allow_external_gnupg", true]],
  });

  gTab = await open_content_tab_with_url("about:accountsettings");
  await promise_account_tree_load(gTab);

  const accountRow = get_account_tree_row(gAccount.key, "am-e2e.xhtml", gTab);
  await click_account_tree_row(gTab, accountRow);

  const iframe =
    gTab.browser.contentWindow.document.getElementById("contentFrame");
  tabDocument = iframe.contentDocument;
  tabWindow = iframe.contentDocument.documentGlobal;

  // The functions under test are globals of the loaded page.
  Assert.equal(
    typeof tabWindow.setOpenPgpDescription,
    "function",
    "the page should expose setOpenPgpDescription()"
  );
  Assert.equal(
    typeof tabWindow.offerGnuPGKeyIfFirstUse,
    "function",
    "the page should expose offerGnuPGKeyIfFirstUse()"
  );
});

/**
 * The description distinguishes all three states.
 */
add_task(async function description_has_three_states() {
  const description = tabDocument.getElementById("openPgpDescription");

  // A key of this identity's own: the count sentence.
  await tabWindow.setOpenPgpDescription(2);
  Assert.equal(
    description.dataset.l10nId,
    "openpgp-description-has-keys",
    "with personal keys the count sentence is used"
  );

  // None of its own, and no readable keyring.
  stubGnuPG({ readable: false });
  await tabWindow.setOpenPgpDescription(0);
  Assert.equal(
    description.dataset.l10nId,
    "openpgp-description-no-key",
    "with no keyring the page says there is no key"
  );

  // None of its own, but the keyring holds one: the sentence Item 4 added.
  stubGnuPG({ fingerprints: [KEY_ID] });
  await tabWindow.setOpenPgpDescription(0);
  Assert.equal(
    description.dataset.l10nId,
    "openpgp-description-gnupg-not-used",
    "a keyring holding a key is reported as present and unused, not as absent"
  );

  restoreGnuPG();
});

/**
 * countPersonalKeys() counts a configured external key once, and not at all
 * while the external path is switched off.
 */
add_task(async function configured_key_is_counted_once() {
  const keyObj = { keyId: KEY_ID };
  gIdentity.setUnicharAttribute("last_entered_external_gnupg_key_id", KEY_ID);

  Assert.equal(
    tabWindow.countPersonalKeys({ all: [] }, KEY_ID),
    1,
    "a configured external key counts once when the ring has none"
  );
  Assert.equal(
    tabWindow.countPersonalKeys({ all: [keyObj] }, KEY_ID),
    1,
    "the same key is not counted twice when the ring also holds it"
  );

  await SpecialPowers.pushPrefEnv({
    set: [["mail.openpgp.allow_external_gnupg", false]],
  });
  Assert.equal(
    tabWindow.configuredExternalKeyId(),
    "",
    "with the external path off no key is considered configured"
  );
  Assert.equal(
    tabWindow.countPersonalKeys(
      { all: [] },
      tabWindow.configuredExternalKeyId()
    ),
    0,
    "so the count is zero, which is what the description will report"
  );
  await SpecialPowers.popPrefEnv();

  gIdentity.setUnicharAttribute("last_entered_external_gnupg_key_id", "");
});

/**
 * A first-use offer is made, and accepting it records the key.
 */
add_task(async function offer_accept_records_the_key() {
  await OpenPGPTestUtils.importPrivateKey(window, getTestFile(SECRET_FILE));
  const keyObj = EnigmailKeyRing.getKeyById(KEY_ID);
  Assert.ok(keyObj, "the fixture key should be importable");

  const originalPrompt = Services.prompt;
  const answers = { button: 0, checkbox: false, calls: [] };
  stubPrompt(answers);
  stubGnuPG({ fingerprints: [keyObj.fpr] });

  gIdentity.setUnicharAttribute("openpgp_key_id", "");
  gIdentity.setUnicharAttribute("last_entered_external_gnupg_key_id", "");
  gIdentity.setBoolAttribute("openpgp_gnupg_offer_answered", false);

  try {
    const changed = await tabWindow.offerGnuPGKeyIfFirstUse({
      all: [keyObj],
    });

    Assert.ok(changed, "accepting the offer should report a change");
    Assert.equal(answers.calls.length, 1, "exactly one prompt is raised");
    Assert.ok(
      answers.calls[0].b0 && answers.calls[0].b1,
      "both answers are named, so the internal engine is a choice rather than an absence"
    );
    Assert.equal(
      gIdentity.getUnicharAttribute("openpgp_key_id"),
      KEY_ID,
      "the accepted key is recorded on the identity"
    );
    Assert.equal(
      gIdentity.getUnicharAttribute("last_entered_external_gnupg_key_id"),
      KEY_ID,
      "and recorded as the external key, so is_gnupg_key_id resolves"
    );
    Assert.ok(
      gIdentity.getBoolAttribute("openpgp_gnupg_offer_answered"),
      "accepting is a permanent answer"
    );
  } finally {
    restorePrompt(originalPrompt);
    restoreGnuPG();
    await OpenPGPTestUtils.removeKeyById(KEY_ID.toLowerCase(), true);
    gIdentity.setUnicharAttribute("openpgp_key_id", "");
    gIdentity.setUnicharAttribute("last_entered_external_gnupg_key_id", "");
    gIdentity.setBoolAttribute("openpgp_gnupg_offer_answered", false);
  }
});

/**
 * Declining without the checkbox asks again next time; with it, never.
 */
add_task(async function offer_declined_is_remembered_only_when_asked() {
  await OpenPGPTestUtils.importPrivateKey(window, getTestFile(SECRET_FILE));
  const keyObj = EnigmailKeyRing.getKeyById(KEY_ID);

  const originalPrompt = Services.prompt;

  gIdentity.setUnicharAttribute("openpgp_key_id", "");
  gIdentity.setUnicharAttribute("last_entered_external_gnupg_key_id", "");
  gIdentity.setBoolAttribute("openpgp_gnupg_offer_answered", false);
  stubGnuPG({ fingerprints: [keyObj.fpr] });

  try {
    // Dismissed: no checkbox, so the offer must return.
    const dismiss = { button: 1, checkbox: false, calls: [] };
    stubPrompt(dismiss);
    Assert.ok(
      !(await tabWindow.offerGnuPGKeyIfFirstUse({ all: [keyObj] })),
      "declining should not change the identity"
    );
    Assert.equal(
      gIdentity.getUnicharAttribute("openpgp_key_id"),
      "",
      "declining leaves the identity with no key configured"
    );
    Assert.ok(
      !gIdentity.getBoolAttribute("openpgp_gnupg_offer_answered"),
      "a dismissal is not read as a permanent answer"
    );

    // Declined with the checkbox: recorded, so the offer does not return.
    const permanent = { button: 1, checkbox: true, calls: [] };
    stubPrompt(permanent);
    Assert.ok(
      !(await tabWindow.offerGnuPGKeyIfFirstUse({ all: [keyObj] })),
      "the second refusal also changes nothing"
    );
    Assert.ok(
      gIdentity.getBoolAttribute("openpgp_gnupg_offer_answered"),
      "ticking the box records a permanent answer"
    );

    // And with that recorded, no prompt is raised at all.
    const after = { button: 0, checkbox: false, calls: [] };
    stubPrompt(after);
    await tabWindow.offerGnuPGKeyIfFirstUse({ all: [keyObj] });
    Assert.equal(
      after.calls.length,
      0,
      "an answered offer is not raised again"
    );
  } finally {
    restorePrompt(originalPrompt);
    restoreGnuPG();
    await OpenPGPTestUtils.removeKeyById(KEY_ID.toLowerCase(), true);
    gIdentity.setUnicharAttribute("openpgp_key_id", "");
    gIdentity.setUnicharAttribute("last_entered_external_gnupg_key_id", "");
    gIdentity.setBoolAttribute("openpgp_gnupg_offer_answered", false);
  }
});

/**
 * The offer stays silent where it should: no keyring, no key for the address,
 * the external path off, or a key already configured.
 */
add_task(async function offer_is_suppressed_where_it_should_be() {
  const originalPrompt = Services.prompt;
  gIdentity.setUnicharAttribute("openpgp_key_id", "");
  gIdentity.setUnicharAttribute("last_entered_external_gnupg_key_id", "");
  gIdentity.setBoolAttribute("openpgp_gnupg_offer_answered", false);

  try {
    const fakeKey = {
      keyId: KEY_ID,
      fpr: KEY_ID,
      expiryTime: 0,
      keyCreated: 1,
    };

    // No readable keyring.
    let answers = { button: 0, checkbox: false, calls: [] };
    stubPrompt(answers);
    stubGnuPG({ readable: false });
    Assert.ok(
      !(await tabWindow.offerGnuPGKeyIfFirstUse({ all: [fakeKey] })),
      "no readable keyring means no offer"
    );
    Assert.equal(answers.calls.length, 0, "and no prompt");

    // A readable keyring holding nothing for this address.
    answers = { button: 0, checkbox: false, calls: [] };
    stubPrompt(answers);
    stubGnuPG({ fingerprints: [] });
    Assert.ok(
      !(await tabWindow.offerGnuPGKeyIfFirstUse({ all: [fakeKey] })),
      "no key for the address means no offer"
    );
    Assert.equal(answers.calls.length, 0, "and no prompt");
    Assert.ok(
      !gIdentity.getBoolAttribute("openpgp_gnupg_offer_answered"),
      "and nothing is recorded, so a key added later can still be offered"
    );

    // The external path switched off.
    answers = { button: 0, checkbox: false, calls: [] };
    stubPrompt(answers);
    stubGnuPG({ fingerprints: [KEY_ID] });
    await SpecialPowers.pushPrefEnv({
      set: [["mail.openpgp.allow_external_gnupg", false]],
    });
    Assert.ok(
      !(await tabWindow.offerGnuPGKeyIfFirstUse({ all: [fakeKey] })),
      "with the external path off there is no keyring to be offered"
    );
    Assert.equal(answers.calls.length, 0, "and no prompt");
    await SpecialPowers.popPrefEnv();

    // A key already configured: the question has been answered by choosing.
    gIdentity.setUnicharAttribute("openpgp_key_id", KEY_ID);
    answers = { button: 1, checkbox: false, calls: [] };
    stubPrompt(answers);
    Assert.ok(
      !(await tabWindow.offerGnuPGKeyIfFirstUse({ all: [fakeKey] })),
      "an identity that already has a key is never moved"
    );
    Assert.equal(answers.calls.length, 0, "and is not asked");
    Assert.equal(
      gIdentity.getUnicharAttribute("openpgp_key_id"),
      KEY_ID,
      "its configured key id is unchanged"
    );
  } finally {
    restorePrompt(originalPrompt);
    restoreGnuPG();
    gIdentity.setUnicharAttribute("openpgp_key_id", "");
    gIdentity.setUnicharAttribute("last_entered_external_gnupg_key_id", "");
    gIdentity.setBoolAttribute("openpgp_gnupg_offer_answered", false);
  }
});

/**
 * The offer is reached from page initialisation, not only when called by hand.
 *
 * The tests above drive offerGnuPGKeyIfFirstUse() directly, which proves the
 * decision but not the wiring. This one runs the real entry point and asserts
 * that the prompt arrives through it.
 *
 * Runs last: initOpenPgpSettings() adds a listener to the key list each time it
 * is called, so calling it here rather than before the other tests keeps the
 * page in the state they expect.
 */
add_task(async function offer_is_reached_from_page_init() {
  await OpenPGPTestUtils.importPrivateKey(window, getTestFile(SECRET_FILE));
  const keyObj = EnigmailKeyRing.getKeyById(KEY_ID);
  Assert.ok(keyObj, "the fixture key should be importable");

  const originalPrompt = Services.prompt;
  const answers = { button: 1, checkbox: false, calls: [] };
  stubPrompt(answers);
  stubGnuPG({ fingerprints: [keyObj.fpr] });

  gIdentity.setUnicharAttribute("openpgp_key_id", "");
  gIdentity.setUnicharAttribute("last_entered_external_gnupg_key_id", "");
  gIdentity.setBoolAttribute("openpgp_gnupg_offer_answered", false);

  try {
    await tabWindow.initOpenPgpSettings();

    Assert.equal(
      answers.calls.length,
      1,
      "initialising the settings page should raise the offer exactly once"
    );
  } finally {
    restorePrompt(originalPrompt);
    restoreGnuPG();
    await OpenPGPTestUtils.removeKeyById(KEY_ID.toLowerCase(), true);
    gIdentity.setUnicharAttribute("openpgp_key_id", "");
    gIdentity.setUnicharAttribute("last_entered_external_gnupg_key_id", "");
    gIdentity.setBoolAttribute("openpgp_gnupg_offer_answered", false);
  }
});

registerCleanupFunction(async function () {
  restoreGnuPG();
  document.getElementById("tabmail").closeTab(gTab);
  gTab = null;
  tabDocument = null;
  tabWindow = null;

  MailServices.accounts.removeAccount(gAccount, true);
  gAccount = null;
});
