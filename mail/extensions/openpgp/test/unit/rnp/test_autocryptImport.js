/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 99: detect, validate and import.
 *
 * The item's centre is that the three cases have *different required
 * behaviour*, and conflating them produces the worst outcomes:
 *
 *   - a header whose value is not `v1` is **ignored entirely**, silently,
 *     because a format this build does not know must not produce a dialog here;
 *   - a `v1` header with a broken structure is **reported and not offered**,
 *     which is information rather than a code prompt that cannot succeed;
 *   - a good one is offered, the code requested, the payload adopted.
 *
 * Plus the two behaviours Enigmail had that the specification does not
 * describe, and whose absence a user notices at once: a **wrong code is not a
 * corrupt message**, and a message this session created is not offered back.
 *
 * The round trip here is against the builder from Item 98, so what is imported
 * is what this build produces -- byte for byte the shape a receiver sees.
 */

"use strict";

const { AutocryptSetup } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/autocryptSetup.sys.mjs"
);
const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { OpenPGPAlias } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/OpenPGPAlias.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";
const ALICE_SECRET_WITH_PP =
  "alice@openpgp.example-0xf231550c4f47e38e-secret-with-pp.asc";
const ALICE_FPR = "EB85BB5FA33A75E15E944E63F231550C4F47E38E";
const ALICE_ADDRESS = "alice@openpgp.example";
const CODE = "1234-5678-9012-3456-7890-1234-5678-9012-3456";
const RULES_PREF = "mail.openpgp.alias_rules_file";
const RULES_FILE = "item99-rules.json";

/**
 * Wraps a built message in the MIME part a receiver sees.
 *
 * The builder produces the whole message; a receiving client hands the second
 * part to `classify()`, so that is what these checks feed it.
 *
 * @param {string} message - From `buildMessage()`.
 * @returns {string} The `application/autocrypt-setup` part's text.
 */
function setupPartOf(message) {
  const boundary = /boundary="([^"]+)"/.exec(message)[1];
  const parts = message.split(`--${boundary}`);
  // Header, human part, setup part, close. The marker header lives on the
  // message, so it is carried into the part for the classifier to see.
  const marker = /^Autocrypt-Setup-Message:.*$/m.exec(message)[0];
  return `${marker}\r\n${parts[2]}`;
}

/**
 * @returns {Promise<string>} A complete setup message.
 */
async function buildMessage(preferEncrypt = "mutual") {
  const keyBlock = RNP.exportSecretKeyForTransfer(ALICE_FPR, preferEncrypt);
  Assert.ok(keyBlock, "the key exports");
  return AutocryptSetup.buildMessage({
    address: ALICE_ADDRESS,
    setupCode: CODE,
    keyBlock,
    preferEncrypt,
  });
}

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();

  await OpenPGPTestUtils.importPrivateKey(
    null,
    do_get_file(`${keyDir}/${ALICE_SECRET_WITH_PP}`),
    OpenPGPTestUtils.ACCEPTANCE_PERSONAL,
    "alice-passphrase",
    true
  );
  EnigmailKeyRing.clearCache();

  Services.prefs.setStringPref(RULES_PREF, RULES_FILE);
  registerCleanupFunction(() => {
    Services.prefs.setStringPref(RULES_PREF, "");
    OpenPGPAlias._clear();
  });
});

/**
 * Case one: a message that is not a setup message is not offered.
 *
 * Including the version case, which is the one that matters for the future:
 * a `v2` message arriving at this build must be ignored silently, not reported
 * and not offered.
 */
add_task(async function anythingThatIsNotV1IsIgnored() {
  const message = await buildMessage();
  const part = setupPartOf(message);

  const cases = [
    ["no marker at all", part.replace(/^Autocrypt-Setup-Message:.*\r\n/m, "")],
    [
      "version 2",
      part.replace(
        "Autocrypt-Setup-Message: v1",
        "Autocrypt-Setup-Message: v2"
      ),
    ],
    [
      "a word",
      part.replace(
        "Autocrypt-Setup-Message: v1",
        "Autocrypt-Setup-Message: yes"
      ),
    ],
    ["empty", ""],
  ];

  for (const [label, input] of cases) {
    const result = AutocryptSetup.classify(input);
    info(`FINDING not-a-setup [${label}]: ${JSON.stringify(result)}`);
    Assert.equal(
      result.state,
      "notASetupMessage",
      `${label} is ignored rather than offered`
    );
  }
});

/**
 * Case two: a v1 header with a broken structure is reported, not offered.
 *
 * The distinction the item insists on: the user is told the message is broken,
 * which is true and useful, rather than being led to a code prompt whose only
 * outcome is failure.
 */
add_task(async function aBrokenV1MessageIsReportedNotOffered() {
  const message = await buildMessage();
  const part = setupPartOf(message);

  const cases = [
    [
      "no armoured block",
      part.replace(
        /-----BEGIN PGP MESSAGE-----[\s\S]*-----END PGP MESSAGE-----/,
        ""
      ),
    ],
    ["a truncated block", part.replace("-----END PGP MESSAGE-----", "")],
    [
      "the wrong content type",
      part.replace(
        /Content-Type: application\/autocrypt-setup/i,
        "Content-Type: text/plain"
      ),
    ],
  ];

  for (const [label, input] of cases) {
    const result = AutocryptSetup.classify(input);
    info(`FINDING malformed [${label}]: ${JSON.stringify(result)}`);
    Assert.equal(result.state, "malformed", `${label} is reported as broken`);
    Assert.ok(result.reason, "with a reason for the report");
  }
});

/**
 * Case three: a good message classifies, unwraps, and yields the key.
 */
add_task(async function aGoodMessageIsOfferedAndOpensWithTheCode() {
  const message = await buildMessage();
  const classified = AutocryptSetup.classify(setupPartOf(message));
  info(`FINDING classify ok: state=${classified.state}`);
  Assert.equal(classified.state, "ok", "a well-formed v1 message is offered");
  Assert.ok(classified.armour, "with its armoured block located");

  const unwrapped = await AutocryptSetup.unwrap(classified.armour, CODE);
  info(
    `FINDING unwrap: state=${unwrapped.state} ` +
      `hasKey=${!!unwrapped.keyBlock}`
  );
  Assert.equal(unwrapped.state, "ok", "the code opens it");
  Assert.ok(
    unwrapped.keyBlock.includes("BEGIN PGP PRIVATE KEY BLOCK"),
    "and what comes out is a secret key block"
  );
  Assert.equal(
    AutocryptSetup.preferenceOf(unwrapped.keyBlock),
    "mutual",
    "whose armour carries the preference the sender stated"
  );
});

/**
 * A wrong code is a wrong code, not a corrupt message.
 *
 * The code authenticates as well as decrypts, so these are different facts.
 * Telling a user their message is damaged when they mistyped a digit sends them
 * looking for another copy of something they already have.
 */
add_task(async function aWrongCodeIsNotACorruptMessage() {
  const message = await buildMessage();
  const { armour } = AutocryptSetup.classify(setupPartOf(message));

  const unwrapped = await AutocryptSetup.unwrap(
    armour,
    "9999-9999-9999-9999-9999-9999-9999-9999-9999"
  );
  info(`FINDING wrong code: state=${unwrapped.state} ${unwrapped.reason}`);
  Assert.equal(
    unwrapped.state,
    "wrongCode",
    "a wrong code is reported as a wrong code"
  );
  Assert.notEqual(
    unwrapped.state,
    "malformed",
    "and not as damage to the message"
  );

  // And a code of the wrong shape is also a wrong code -- the user typed
  // something that is not a code, which is not the message's fault either.
  const shortCode = await AutocryptSetup.unwrap(armour, "1234");
  Assert.equal(shortCode.state, "wrongCode", "a short entry is a wrong code");
});

/**
 * A message that decrypts into something other than a key is malformed.
 *
 * The code was right, so the failure is structural: this is the case that
 * must not be offered, and it is distinguishable from a wrong code only
 * *after* decrypting.
 */
add_task(async function apayloadThatIsNotAKeyIsMalformed() {
  const notAKey = RNP.encryptWithPassword("not a key at all\n", CODE, {
    cipher: "AES256",
  });
  const unwrapped = await AutocryptSetup.unwrap(notAKey, CODE);
  info(`FINDING not-a-key: ${JSON.stringify(unwrapped)}`);
  Assert.equal(
    unwrapped.state,
    "malformed",
    "a payload that is not a secret key is malformed, not a wrong code"
  );
});

/**
 * The preference is read from the armour, defaulting conservatively.
 */
add_task(async function thePreferenceIsReadOrDefaulted() {
  for (const value of ["mutual", "nopreference"]) {
    const message = await buildMessage(value);
    const { armour } = AutocryptSetup.classify(setupPartOf(message));
    const { keyBlock } = await AutocryptSetup.unwrap(armour, CODE);
    Assert.equal(
      AutocryptSetup.preferenceOf(keyBlock),
      value,
      `${value} is read back from the armour`
    );
  }

  // A block that says nothing, and one that says something undefined, both
  // mean the default -- which is what a receiver is required to do.
  Assert.equal(
    AutocryptSetup.preferenceOf("-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nx\n"),
    "nopreference",
    "an absent preference is the default"
  );
  Assert.equal(
    AutocryptSetup.preferenceOf(
      "-----BEGIN PGP PRIVATE KEY BLOCK-----\nAutocrypt-Prefer-Encrypt: sometimes\n\nx\n"
    ),
    "nopreference",
    "and an undefined value falls back to it rather than being passed on"
  );
});

/**
 * A message this session created is not offered back.
 */
add_task(async function aselfCreatedMessageIsNotOffered() {
  const created = ["<msg-1@example>", "<msg-2@example>"];

  Assert.ok(
    AutocryptSetup.isSelfCreated("<msg-1@example>", created),
    "an id from this session is recognised"
  );
  Assert.ok(
    !AutocryptSetup.isSelfCreated("<other@example>", created),
    "an unknown id is not"
  );
  Assert.ok(
    !AutocryptSetup.isSelfCreated("<msg-1@example>", []),
    "and with nothing recorded, nothing is self-created"
  );
});

/**
 * The preference rule on its own, which needs no account.
 *
 * Adoption's account half is in `browser_autocryptImport.js`: xpcshell has no
 * account manager server types, so `createIncomingServer` throws
 * `NS_ERROR_NOT_AVAILABLE` and nothing past it runs. What can be tested here is
 * the rule, and the rule is the part that meets D17's boundary.
 */
add_task(async function thePreferenceRuleIsWritten() {
  const address = "rule-target@example.com";
  await AutocryptSetup.recordPreferenceRule(address, "mutual", ALICE_FPR);

  const rule = OpenPGPAlias.getRuleForEmail(address);
  info(`FINDING rule: ${JSON.stringify(rule)}`);
  Assert.ok(rule, "a rule was written for the address");
  Assert.equal(rule.encrypt, 2, "encrypt is always, for mutual");
  Assert.equal(rule.sign, 2, "and so is sign");
  Assert.deepEqual(
    rule.keys,
    [{ fingerprint: ALICE_FPR }],
    "naming the imported key"
  );

  // Rewritten rather than duplicated: one rule per address, and the loader
  // uses the first, so a second would be silently ignored.
  await AutocryptSetup.recordPreferenceRule(address, "nopreference", ALICE_FPR);
  const rules = (await OpenPGPAlias.readRulesForEditing()).rules.filter(
    r => r.email == address
  );
  Assert.equal(rules.length, 1, "the rule was replaced, not duplicated");
  Assert.equal(
    OpenPGPAlias.getRuleForEmail(address).encrypt,
    0,
    "and now says never"
  );
});

/**
 * `nopreference` writes a refusal, not an absence.
 *
 * "Do not encrypt" is a statement the send path can act on; leaving the rule
 * out would read as no opinion and fall back to a default.
 */
add_task(async function nopreferenceWritesARefusal() {
  const address = "refuse@example.com";
  await AutocryptSetup.recordPreferenceRule(address, "nopreference", ALICE_FPR);

  const rule = OpenPGPAlias.getRuleForEmail(address);
  info(`FINDING nopreference rule: ${JSON.stringify(rule)}`);
  Assert.ok(rule, "a rule exists rather than none");
  Assert.equal(rule.encrypt, 0, "encrypt is never");
  Assert.equal(rule.sign, 0, "and sign is never");
});
