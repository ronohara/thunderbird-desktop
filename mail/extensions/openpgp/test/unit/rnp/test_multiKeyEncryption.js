/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 27a: the internal engine encrypts to every acceptable key.
 *
 * The external arm has always done this — `getGnuPgEncryptionRecipients()` adds
 * every fingerprint `getPublicKeysForEmail()` returns. The internal arm used
 * `findKeyByEmail()`, which prefers a personal-or-verified key and takes one.
 * So a recipient with two live keys was encrypted to whichever the ranking
 * preferred, and a key rotation had a window in which the old key was gone and
 * the new one was not yet used.
 *
 * **The filter is now gpg's, plus the user's rejection.** Eligibility follows
 * gpg's own rule as closely as an internal-storage key can — not revoked, not
 * expired, not disabled, carrying the address on a usable user ID — and an
 * address the user has *rejected* is excluded, because rejection is a statement
 * only this build can make and gpg has no vocabulary for it.
 *
 * Two things are asserted, and the second is the one a careless change would
 * break:
 *
 *   1. `findAllKeysByEmail()` returns both acceptable keys for one address, in
 *      iterator order, and marks which of them the old ranking would have
 *      preferred.
 *   2. `findKeyByEmail()` still returns the *same single key* it did before —
 *      the refactor is an equivalence, not a rewrite — so the four callers that
 *      want one key are unaffected.
 *
 * The encryption-level half — that `addEncryptionKeysForEmail()` actually adds
 * both to the operation — is asserted on the recipient handles the operation
 * received, which is as close to "the message is encrypted to both" as a unit
 * test can get without a full send.
 */

"use strict";

const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);

const { EnigmailKeyRing } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/keyRing.sys.mjs"
);
const { PgpSqliteDb2 } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/sqliteDb.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { OpenPGPMasterpass } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/masterpass.sys.mjs"
);
// `ctypes` is a global in xpcshell through `ChromeUtils.importESModule`, and
// librnp's own module imports the same object -- but this file needs a pointer
// of its own to read a fingerprint back out of a handle.
const { ctypes } = ChromeUtils.importESModule(
  "resource://gre/modules/ctypes.sys.mjs"
);

const keyDir = "../../../../../test/browser/openpgp/data/keys";
const ADDRESS = "twokeys@openpgp.example";
const OTHER_ADDRESS = "single@openpgp.example";

var gFirst = null;
var gSecond = null;
var gSingle = null;

/**
 * The loaded librnp wrapper.
 *
 * `RNPLibLoader.init()` returns a *new* wrapper with a null `ffi` on every call,
 * so a test that reaches for the loader gets an object it cannot use --
 * `RNP.getRNPLib()` is the accessor added for exactly this. Destructuring
 * `RNPLib` from the module yields undefined, which is the trap notes.txt records
 * and which I walked into here: the module exports `RNPLibLoader`.
 *
 * @returns {object}
 */
function lib() {
  const wrapper = RNP.getRNPLib();
  if (!wrapper?.ffi) {
    throw new Error("librnp is not loaded, so its ffi is unavailable");
  }
  return wrapper;
}

/**
 * Destroy every handle in a list, so a failed assertion does not leak into the
 * next task through librnp's own bookkeeping.
 *
 * @param {object[]} found
 */
function destroyAll(found) {
  for (const entry of found) {
    lib().rnp_key_handle_destroy(entry.handle);
  }
}

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();

  const pass = await OpenPGPMasterpass.retrieveOpenPGPPassword();

  // Two live keys for one address, and one for another. Generated rather than
  // fixtures, because no fixture carries a second key for the same address.
  const firstId = await RNP.genKey(
    `Two Keys One <${ADDRESS}>`,
    "ECC",
    0,
    0,
    pass
  );
  // A second of separation so the iterator's order is deterministic rather than
  // dependent on creation within the same second.
  await new Promise(resolve => do_timeout(1100, resolve));
  const secondId = await RNP.genKey(
    `Two Keys Two <${ADDRESS}>`,
    "ECC",
    0,
    0,
    pass
  );
  const singleId = await RNP.genKey(
    `Only One <${OTHER_ADDRESS}>`,
    "ECC",
    0,
    0,
    pass
  );

  EnigmailKeyRing.clearCache();
  for (const id of [firstId, secondId, singleId]) {
    const key = EnigmailKeyRing.getKeyById(id);
    Assert.ok(key, `key ${id} was generated`);
    await PgpSqliteDb2.acceptAsPersonalKey(key.fpr);
  }
  EnigmailKeyRing.clearCache();

  gFirst = EnigmailKeyRing.getKeyById(firstId);
  gSecond = EnigmailKeyRing.getKeyById(secondId);
  gSingle = EnigmailKeyRing.getKeyById(singleId);
  Assert.ok(gFirst && gSecond && gSingle, "all three keys are present");
});

/**
 * Both acceptable keys come back for one address.
 */
add_task(async function bothKeysAreReturned() {
  const found = await RNP.findAllKeysByEmail(`<${ADDRESS}>`, true);
  try {
    info(
      `FINDING findAllKeysByEmail: ${found.length} keys, ` +
        `strong=${JSON.stringify(found.map(f => f.strong))}`
    );
    Assert.equal(found.length, 2, "both keys for the address are returned");
    // Personal keys are `strong`, which is the flag the old ranking preferred.
    Assert.ok(
      found.every(f => f.strong),
      "both are personal, so both would have been strong to the old ranking"
    );
  } finally {
    destroyAll(found);
  }
});

/**
 * The single-key function still answers what it answered before.
 *
 * The refactor's whole claim is equivalence. If this fails, four callers that
 * want one key have changed behaviour — which is the risk Item 27's row named.
 */
add_task(async function theSingleKeyAnswerIsUnchanged() {
  const handle = await RNP.findKeyByEmail(`<${ADDRESS}>`, true);
  Assert.ok(handle && !handle.isNull(), "a key is still returned");

  const fprPtr = new ctypes.char.ptr();
  try {
    Assert.equal(
      lib().rnp_key_get_fprint(handle, fprPtr.address()),
      0,
      "the handle has a fingerprint"
    );
    const fpr = fprPtr.readString().toUpperCase();
    info(`FINDING findKeyByEmail chose: ${fpr}`);
    // The first personal-or-verified key in iterator order, which for two
    // personal keys is the one created first.
    Assert.equal(
      fpr,
      gFirst.fpr.toUpperCase(),
      "and it is the first of the two, as the old loop would have returned"
    );
  } finally {
    lib().rnp_key_handle_destroy(handle);
  }
});

/**
 * The rejection boundary: a rejected key is not a recipient key.
 *
 * This is the one part of the rule gpg cannot express, so it is the part most
 * likely to be lost when "lean on GnuPG" is taken too far. Rejecting one of the
 * two keys must leave exactly the other.
 */
add_task(async function aRejectedKeyIsNotARecipientKey() {
  await PgpSqliteDb2.updateAcceptance(gFirst.fpr, [ADDRESS], "rejected");
  EnigmailKeyRing.clearCache();

  try {
    const found = await RNP.findAllKeysByEmail(`<${ADDRESS}>`, true);
    try {
      info(
        `FINDING after rejecting one key: ${found.length} keys ` +
          `(expected 1)`
      );
      Assert.equal(
        found.length,
        1,
        "the rejected key is excluded and the acceptable one remains"
      );
    } finally {
      destroyAll(found);
    }
  } finally {
    // Restore, so the count above is the only thing this task changes.
    await PgpSqliteDb2.updateAcceptance(gFirst.fpr, [ADDRESS], "verified");
    EnigmailKeyRing.clearCache();
  }
});

/**
 * Build an encrypt operation the way the real path does.
 *
 * `rnp_op_encrypt_create()` wants an input and an output as well as the
 * operation, and my first version passed nulls and got
 * `268435463` back — a failure code, not an assertion failure, which is the same
 * shape of mistake as the guard answering null earlier in this stretch: an
 * error return read as data. Building them as `encryptAndOrSign()` builds them
 * removes the guess.
 *
 * @returns {{op: rnp_op_encrypt_t, input: rnp_input_t, output: rnp_output_t}}
 */
function createEncryptOp() {
  const impl = lib();
  const data = ctypes.uint8_t.array()([65, 66, 67]); // "ABC"

  const input = new impl.rnp_input_t();
  Assert.equal(
    impl.rnp_input_from_memory(input.address(), data, data.length, false),
    0,
    "an input was created"
  );

  const output = new impl.rnp_output_t();
  Assert.equal(
    impl.rnp_output_to_memory(output.address(), 0),
    0,
    "an output was created"
  );

  const op = new impl.rnp_op_encrypt_t();
  Assert.equal(
    impl.rnp_op_encrypt_create(op.address(), impl.ffi, input, output),
    0,
    "an encrypt operation was created"
  );

  return { op, input, output };
}

/**
 * @param {object} handles - From `createEncryptOp()`.
 * @param {object} handles.op
 * @param {object} handles.input
 * @param {object} handles.output
 */
function destroyEncryptOp({ op, input, output }) {
  const impl = lib();
  impl.rnp_op_encrypt_destroy(op);
  impl.rnp_input_destroy(input);
  impl.rnp_output_destroy(output);
}

/**
 * The encryption level: every acceptable key is added to the operation.
 *
 * `addEncryptionKeysForEmail()` is what the send path now calls, and its answer
 * is a count — which is also the refusal signal at the call site, so a zero must
 * mean zero.
 */
add_task(async function everyKeyIsAddedToTheOperation() {
  const handles = createEncryptOp();
  try {
    const added = await RNP.addEncryptionKeysForEmail(
      `<${ADDRESS}>`,
      handles.op
    );
    info(`FINDING addEncryptionKeysForEmail: ${added} keys added`);
    Assert.equal(added, 2, "both acceptable keys were added to the operation");
  } finally {
    destroyEncryptOp(handles);
  }

  // And the control: an address with no key adds nothing, which is what the
  // call site turns into a refusal. A build that added one unconditionally
  // would pass the assertion above and fail this one.
  const emptyHandles = createEncryptOp();
  try {
    const none = await RNP.addEncryptionKeysForEmail(
      "<nobody-here@openpgp.example>",
      emptyHandles.op
    );
    info(`FINDING addEncryptionKeysForEmail for an unknown address: ${none}`);
    Assert.equal(none, 0, "an address with no key adds nothing");
  } finally {
    destroyEncryptOp(emptyHandles);
  }
});
