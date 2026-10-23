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
const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);

const KEY_ID = "F231550C4F47E38E";

// Two genuine revisions of one key, the pair Item 17 uses for the precedence
// rule: identical fingerprint, different self-signatures.
const REV_KEY_ID = "D4ED849BCD779DFC";
const REV_BEFORE = "D4ED849BCD779DFC-before-new-identity.asc";
const REV_AFTER = "D4ED849BCD779DFC-after-new-identity.asc";
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
 * Read a fixture as text.
 *
 * @param {string} name - Path relative to this test's data directory.
 * @returns {Promise<string>} The file's contents.
 */
async function readFixtureText(name) {
  const data = await IOUtils.read(getTestFile(name).path);
  return new TextDecoder().decode(data);
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

/**
 * The internal-key notice follows the presence of a secret key in the profile,
 * not the Primary Password.
 *
 * That distinction is the item: a user who has set a Primary Password has been
 * told the exposure is handled, and the design shows it is not. So the notice
 * must stay while the key is there, and must not appear merely because no
 * password is set.
 */
add_task(async function internal_key_notice_follows_the_key_not_the_password() {
  const notice = tabDocument.getElementById("openPgpInternalKeyNotice");
  const description = tabDocument.getElementById(
    "openPgpInternalKeyNoticeDescription"
  );

  // No secret key in the profile: silent.
  EnigmailKeyRing.clearCache();
  await tabWindow.reloadOpenPgpUI();
  Assert.equal(
    notice.collapsed,
    true,
    "with no internal secret key the notice is collapsed"
  );

  // Import a secret key: the notice appears.
  await OpenPGPTestUtils.importPrivateKey(window, getTestFile(SECRET_FILE));
  await tabWindow.reloadOpenPgpUI();

  Assert.equal(
    notice.collapsed,
    false,
    "with a secret key in the profile the notice is shown"
  );
  Assert.equal(
    description.dataset.l10nId,
    "openpgp-internal-key-notice",
    "and it uses the notice string, with the count argument"
  );

  // The Primary Password is not the condition. Its state is unchanged by this
  // test, and the notice appeared and disappeared with the key alone.
  const token = Cc["@mozilla.org/security/internalkeytoken;1"].createInstance(
    Ci.nsIPKCS11Token
  );
  Assert.equal(
    token.hasPassword,
    false,
    "the harness runs without a Primary Password, so the notice above cannot " +
      "have been caused by one"
  );

  // Remove the key: silent again.
  await OpenPGPTestUtils.removeKeyById(KEY_ID.toLowerCase(), true);
  EnigmailKeyRing.clearCache();
  await tabWindow.reloadOpenPgpUI();

  Assert.equal(
    notice.collapsed,
    true,
    "removing the key collapses the notice again"
  );
});

/**
 * Source guard: the notice's condition must not consult the Primary Password.
 *
 * This exists because the behaviour test cannot distinguish the two conditions
 * in a harness that runs without a Primary Password -- planting the wrong
 * condition there passes, since `hasPassword` is false and the two expressions
 * coincide. Which is exactly the bug being guarded against: the notice would
 * disappear for a user who set a password, on the reasoning that the password
 * solved the exposure. It does not.
 */
add_task(async function notice_does_not_consult_the_primary_password() {
  const ChromeRegistry = Cc["@mozilla.org/chrome/chrome-registry;1"].getService(
    Ci.nsIChromeRegistry
  );
  const file = ChromeRegistry.convertChromeURL(
    Services.io.newURI("chrome://messenger/content/am-e2e.js")
  ).QueryInterface(Ci.nsIFileURL).file;
  const source = new TextDecoder().decode(await IOUtils.read(file.path));

  const start = source.indexOf("function updateInternalKeyNotice(");
  Assert.greater(start, -1, "updateInternalKeyNotice() should exist");

  // The body runs to the next top-level function.
  const rest = source.slice(start + 1);
  const end = rest.search(/\n(?:async )?function /);
  const body = end < 0 ? rest : rest.slice(0, end);

  Assert.ok(
    !body.includes("hasPassword"),
    "the notice must not be conditioned on the Primary Password"
  );
  Assert.ok(
    !body.includes("internalkeytoken"),
    "and must not reach for the token to decide whether to show itself"
  );
  Assert.ok(
    body.includes("secretAvailable"),
    "its condition should be the presence of a secret key in the profile"
  );
});

/**
 * Item 31: a copy of a GnuPG key in this profile is reported, and the four
 * files are named.
 *
 * The notice exists because removing only pubring.gpg looks like it worked and
 * does not: RNPLib.loadWithFallback reads <path>.old when the main file fails,
 * so the key returns at the next start (corrections-F50). A test that only
 * asserted the notice appears would pass a message naming one file, which is
 * the defect the item is about -- so the four names are asserted from the
 * Fluent message itself rather than from the description node.
 */
add_task(async function duplicate_key_notice_names_four_files() {
  const notice = tabDocument.getElementById("openPgpDuplicateKeyNotice");

  // The key this profile holds, which GnuPG will be told it also holds.
  await OpenPGPTestUtils.importPrivateKey(null, getTestFile(SECRET_FILE));
  EnigmailKeyRing.clearCache();
  const ringKey = EnigmailKeyRing.getKeyById(KEY_ID);
  Assert.ok(ringKey, "the fixture key should be in the profile ring");
  Assert.ok(ringKey.secretAvailable, "and it should carry its secret half");

  stubGnuPG({ fingerprints: [ringKey.fpr] });
  const duplicates = tabWindow.updateDuplicateKeyNotice();

  Assert.equal(duplicates.size, 1, "one key should be reported as a duplicate");
  Assert.equal(
    notice.collapsed,
    false,
    "the notice should be shown when a duplicate exists"
  );
  Assert.equal(
    tabDocument.getElementById("openPgpDuplicateKeyNoticeDescription").dataset
      .l10nId,
    "openpgp-duplicate-key-notice",
    "the duplicate message should be selected"
  );

  // The requirement the item turns on: four files, not one.
  const text = await tabWindow.document.l10n.formatValue(
    "openpgp-duplicate-key-notice",
    { count: 1 }
  );
  for (const name of [
    "pubring.gpg",
    "pubring.gpg.old",
    "secring.gpg",
    "secring.gpg.old",
  ]) {
    Assert.ok(
      text.includes(name),
      `the message must name ${name}, or removing the copy looks like it failed`
    );
  }

  // It offers rather than acts: the control opens the Key Manager.
  Assert.equal(
    tabDocument.getElementById("openPgpDuplicateKeyNoticeManage").dataset
      .l10nId,
    "openpgp-duplicate-key-notice-manage",
    "the notice should offer a route to the removal, not perform it"
  );
});

/**
 * The control: no duplicate, no notice.
 *
 * Without this task the previous one would pass on a notice that showed itself
 * unconditionally, which is the failure mode a single-state test cannot see.
 */
add_task(async function notice_hidden_when_no_duplicate() {
  const notice = tabDocument.getElementById("openPgpDuplicateKeyNotice");

  // A readable keyring that holds something else.
  stubGnuPG({ fingerprints: ["F".repeat(40)] });
  let duplicates = tabWindow.updateDuplicateKeyNotice();
  Assert.equal(duplicates.size, 0, "an unrelated keyring key is not a copy");
  Assert.equal(notice.collapsed, true, "and the notice stays collapsed");

  // No keyring at all.
  stubGnuPG({ readable: false });
  duplicates = tabWindow.updateDuplicateKeyNotice();
  Assert.equal(
    duplicates.size,
    0,
    "with no readable keyring there is nothing to compare against"
  );
  Assert.equal(notice.collapsed, true, "so no notice");
});

/**
 * The notice is gated on the external path, like every other GnuPG query here.
 *
 * With the pref off there is no keyring in use, so a "copy" claim would be an
 * answer invented rather than observed -- the same rule Item 19's condition
 * follows.
 */
add_task(async function notice_gated_on_the_external_pref() {
  const notice = tabDocument.getElementById("openPgpDuplicateKeyNotice");
  const ringKey = EnigmailKeyRing.getKeyById(KEY_ID);
  stubGnuPG({ fingerprints: [ringKey.fpr] });

  await SpecialPowers.pushPrefEnv({
    set: [["mail.openpgp.allow_external_gnupg", false]],
  });
  const duplicates = tabWindow.updateDuplicateKeyNotice();
  Assert.equal(
    duplicates.size,
    0,
    "with the external path off nothing is compared and nothing is claimed"
  );
  Assert.equal(notice.collapsed, true, "and the notice is not shown");

  await SpecialPowers.popPrefEnv();

  // Restored, the same fixture reports the copy again.
  const restored = tabWindow.updateDuplicateKeyNotice();
  Assert.equal(
    restored.size,
    1,
    "with the path back on, the duplicate is reported again"
  );
});

/**
 * Item 32: a copy whose revision is older than GnuPG's is reported as stale.
 *
 * Two genuine revisions of one key are used, the same pair Item 17 built for
 * the precedence rule: same fingerprint, different self-signatures. The older
 * one goes into the profile ring and the newer one is what GnuPG answers with,
 * which is the 18 October shape rather than a marker object standing in for it.
 *
 * The stale message is a different message from Item 31's, because it says a
 * different thing: not "a copy exists" but "the copy is out of date".
 */
add_task(async function stale_copy_is_reported_as_stale() {
  const before = await readFixtureText("data/keys/" + REV_BEFORE);
  const after = await readFixtureText("data/keys/" + REV_AFTER);

  // The older revision into the profile ring, with the guard's pref off so the
  // planted copy is possible at all -- the guards are Item 8 and Item 10's
  // subject, and here the copy is the point.
  await SpecialPowers.pushPrefEnv({
    set: [["mail.openpgp.allow_external_gnupg", false]],
  });
  await EnigmailKeyRing.importKeyAsync(
    null,
    false,
    before,
    false,
    "",
    {},
    null
  );
  EnigmailKeyRing.clearCache();

  const ringKey = EnigmailKeyRing.getKeyById(REV_KEY_ID);
  Assert.ok(ringKey, "the older revision should be in the profile ring");

  // The measurements the notice will make, taken here so a wrong answer is
  // attributable rather than hidden behind the notice.
  const ringTime = RNP.newestSelfSignatureTimeInProfile(ringKey.fpr);
  const gnuPgTime = RNP.newestSelfSignatureTimeForKeyBlock(after, ringKey.fpr);
  Assert.greater(ringTime, 0, "the profile copy's newest self-signature reads");
  Assert.greater(gnuPgTime, 0, "and so does GnuPG's revision's");
  Assert.less(
    ringTime,
    gnuPgTime,
    "the fixture must be stale, or this task proves nothing"
  );

  // Now the notice, with GnuPG answering as it would if it held the newer one.
  await SpecialPowers.popPrefEnv();
  stubGnuPG({ fingerprints: [ringKey.fpr] });
  const gOriginalExport = GPGME.getPublicKeysForId;
  GPGME.getPublicKeysForId = () =>
    new Map([[ringKey.fpr.toUpperCase(), after]]);
  try {
    const duplicates = tabWindow.updateDuplicateKeyNotice();
    Assert.equal(duplicates.size, 1, "the copy is still a duplicate");

    Assert.equal(
      tabDocument.getElementById("openPgpDuplicateKeyNoticeDescription").dataset
        .l10nId,
      "openpgp-stale-key-copy-notice",
      "a stale copy earns the stronger message, not the plain one"
    );
  } finally {
    GPGME.getPublicKeysForId = gOriginalExport;
    restoreGnuPG();
  }
});

/**
 * The control: a copy whose revision matches GnuPG's is not called stale.
 *
 * Without this, the task above would pass on a check that called every
 * duplicate stale -- which is the failure mode of a comparison that never
 * evaluates to "not stale".
 */
add_task(async function current_copy_is_not_called_stale() {
  const after = await readFixtureText("data/keys/" + REV_AFTER);

  // Actually replace the ring copy with the newer revision, so the two stores
  // agree. The first version of this task only re-read the fixture and then
  // asserted "not stale" against a ring that still held the older one -- it
  // failed, correctly, and the failure is why the copy is now replaced.
  EnigmailKeyRing.clearCache();
  const stale = EnigmailKeyRing.getKeyById(REV_KEY_ID);
  Assert.ok(stale, "the older revision should still be present to replace");
  await RNP.deleteKey(stale.fpr, false);
  await SpecialPowers.pushPrefEnv({
    set: [["mail.openpgp.allow_external_gnupg", false]],
  });
  await EnigmailKeyRing.importKeyAsync(null, false, after, false, "", {}, null);
  await SpecialPowers.popPrefEnv();
  EnigmailKeyRing.clearCache();

  const ringKey = EnigmailKeyRing.getKeyById(REV_KEY_ID);
  Assert.ok(ringKey, "the newer revision should now be in the ring");

  stubGnuPG({ fingerprints: [ringKey.fpr] });
  const gOriginalExport = GPGME.getPublicKeysForId;
  GPGME.getPublicKeysForId = () =>
    new Map([[ringKey.fpr.toUpperCase(), after]]);
  try {
    tabWindow.updateDuplicateKeyNotice();
    Assert.equal(
      tabDocument.getElementById("openPgpDuplicateKeyNoticeDescription").dataset
        .l10nId,
      "openpgp-duplicate-key-notice",
      "a copy that is current earns the plain duplicate message"
    );
  } finally {
    GPGME.getPublicKeysForId = gOriginalExport;
    restoreGnuPG();
  }
});

/**
 * Item 35, Stage 7's verification: three profile states, three answers.
 *
 * Each state is built deliberately and both notices are read together, so a
 * notice that fires on a state it does not describe is as visible as one that
 * fails to fire. Reading one notice at a time cannot see that, which is why the
 * earlier tests -- each about a single notice -- passed while two of them could
 * show at once.
 *
 *   state 1  a copy of a key GnuPG also holds, secret half present
 *            -> the duplicate message, and the internal-store message silent
 *   state 2  a key that exists only in the profile
 *            -> the internal-store message, and no duplicate message
 *   state 3  no secret key in the profile at all
 *            -> both silent
 *
 * **The stale variant of state 1 has no fixture and is verified elsewhere.**
 * The two-revision pair Item 17 built is public-only, so a key with a secret
 * half cannot be given two revisions here. Whether the stale message is the one
 * selected is Item 32's own test, `stale_copy_is_reported_as_stale`, which uses
 * that pair; what this task adds is that a *secret* copy does not make the
 * internal-store notice speak as well.
 */

const ALICE_PUB = "data/keys/alice@openpgp.example-0xf231550c4f47e38e-pub.asc";

/** Read both notices at once. */
function readNotices() {
  const internal = tabDocument.getElementById("openPgpInternalKeyNotice");
  const duplicate = tabDocument.getElementById("openPgpDuplicateKeyNotice");
  const id = name => tabDocument.getElementById(name)?.dataset.l10nId || null;
  return {
    internalShown: !internal.collapsed,
    internalMessage: id("openPgpInternalKeyNoticeDescription"),
    duplicateShown: !duplicate.collapsed,
    duplicateMessage: id("openPgpDuplicateKeyNoticeDescription"),
  };
}

/** Remove every key from the profile ring, so a state starts from nothing. */
async function clearProfileRing() {
  EnigmailKeyRing.clearCache();
  for (const key of EnigmailKeyRing.getAllKeys(null, null).keyList.slice()) {
    // secretAvailable, not true: rnp_key_remove refuses to remove a secret
    // that is not there, so the flag has to describe the key.
    await RNP.deleteKey(key.fpr, key.secretAvailable);
  }
  EnigmailKeyRing.clearCache();
  await tabWindow.reloadOpenPgpUI();
}

/**
 * Put a key with a secret half into the profile ring.
 *
 * The guard's pref is turned off for the import because a secret key is what
 * this state needs; the guards themselves are Items 8 and 10's subject, and
 * here the copy is the point.
 *
 * @returns {Promise<object>} The ring key.
 */
async function importSecretIntoRing() {
  await SpecialPowers.pushPrefEnv({
    set: [["mail.openpgp.allow_external_gnupg", false]],
  });
  await OpenPGPTestUtils.importPrivateKey(window, getTestFile(SECRET_FILE));
  await SpecialPowers.popPrefEnv();
  EnigmailKeyRing.clearCache();

  const ringKey = EnigmailKeyRing.getKeyById(KEY_ID);
  Assert.ok(ringKey, "the fixture should be in the ring");
  Assert.ok(
    ringKey.secretAvailable,
    "and it must carry its secret half, or the internal notice cannot fire"
  );
  return ringKey;
}

/**
 * State 1: the profile holds a copy of a key GnuPG also holds.
 *
 * The duplicate notice speaks, and the internal-store notice must stay quiet.
 * It must stay quiet because its advice -- "moving the key to GnuPG removes
 * that exposure" -- cannot be followed for a key GnuPG already holds, and it
 * contradicts the other notice's "delete the four files". Two notices with
 * incompatible remedies are worse than one.
 */
add_task(async function state1_copy_of_held_key_speaks_once() {
  await clearProfileRing();
  const ringKey = await importSecretIntoRing();
  const publicBlock = await readFixtureText(ALICE_PUB);

  await SpecialPowers.pushPrefEnv({
    set: [["mail.openpgp.allow_external_gnupg", true]],
  });
  stubGnuPG({ fingerprints: [ringKey.fpr] });
  const gOriginalExport = GPGME.getPublicKeysForId;
  GPGME.getPublicKeysForId = () =>
    new Map([[ringKey.fpr.toUpperCase(), publicBlock]]);
  try {
    await tabWindow.reloadOpenPgpUI();
    const notices = readNotices();

    Assert.equal(
      notices.duplicateShown,
      true,
      "the duplicate notice should be shown for a copy GnuPG also holds"
    );
    Assert.equal(
      notices.duplicateMessage,
      "openpgp-duplicate-key-notice",
      "and it should carry the duplicate message: the revisions agree"
    );
    Assert.equal(
      notices.internalShown,
      false,
      "the internal-store notice must stay silent, because its remedy is already true"
    );
  } finally {
    GPGME.getPublicKeysForId = gOriginalExport;
    restoreGnuPG();
    await SpecialPowers.popPrefEnv();
  }
});

/**
 * State 2: the key exists only in the profile.
 *
 * This is the state Item 19's notice is about -- a key stored inside
 * Thunderbird with no keyring behind it -- so it fires, and the duplicate
 * notice has nothing to say because there is no duplicate.
 */
add_task(async function state2_profile_only_key_speaks_once() {
  await clearProfileRing();
  await importSecretIntoRing();

  // GnuPG holds something else entirely, so this key is not a copy of anything.
  await SpecialPowers.pushPrefEnv({
    set: [["mail.openpgp.allow_external_gnupg", true]],
  });
  stubGnuPG({ fingerprints: ["A".repeat(40)] });
  try {
    await tabWindow.reloadOpenPgpUI();
    const notices = readNotices();

    Assert.equal(
      notices.internalShown,
      true,
      "a key that exists only in the profile is what the internal notice is for"
    );
    Assert.equal(
      notices.internalMessage,
      "openpgp-internal-key-notice",
      "and it carries the internal-store message"
    );
    Assert.equal(
      notices.duplicateShown,
      false,
      "with no duplicate there is nothing for the duplicate notice to report"
    );
  } finally {
    restoreGnuPG();
    await SpecialPowers.popPrefEnv();
  }
});

/**
 * State 3: no secret key in the profile.
 *
 * The control for the two above, and the one that catches a notice which shows
 * itself regardless of state.
 */
add_task(async function state3_no_copy_says_nothing() {
  await clearProfileRing();

  await SpecialPowers.pushPrefEnv({
    set: [["mail.openpgp.allow_external_gnupg", true]],
  });
  stubGnuPG({ fingerprints: ["B".repeat(40)] });
  try {
    await tabWindow.reloadOpenPgpUI();
    const notices = readNotices();

    Assert.equal(notices.internalShown, false, "no key, no internal notice");
    Assert.equal(notices.duplicateShown, false, "no copy, no duplicate notice");
  } finally {
    restoreGnuPG();
    await SpecialPowers.popPrefEnv();
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
