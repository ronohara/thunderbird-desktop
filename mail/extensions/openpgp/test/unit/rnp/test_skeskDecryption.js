/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 95a: can an SKESK be decrypted at all, as things stand?
 *
 * The item exists because the reading that says importing a symmetric message
 * is nearly free is an *inference*: `rnp_decrypt` is bound and a pass provider
 * is already installed, so a passphrase "may" reach an SKESK through it. The
 * item's own words are that **it may not** -- "a pass provider written for a
 * protected secret key is not necessarily consulted for a symmetric session
 * key, and the two paths are different in librnp". This file settles it.
 *
 * **The answer, and it is more precise than yes or no.** librnp *does* consult
 * the provider for a symmetric message -- the header documents the callback
 * context as `"decrypt (symmetric)"` and says the key handle is "the key, if
 * any", which for an SKESK is none. But **both of Thunderbird's callbacks
 * dereference that handle before doing anything else**:
 *
 *   - the default `password_cb()` logs "called unexpectedly" and returns false;
 *   - `collect_key_info_password_cb()` calls `rnp_key_get_fprint(key, ...)`
 *     and gives up when it fails, which is exactly what happens on a NULL key;
 *   - `use_remembered_password_cb()` does the same, and only ever has the
 *     passwords collected by the first.
 *
 * So the existing entry point refuses, and cannot do otherwise: it has no path
 * for a passphrase that does not belong to a key. The two checks below are the
 * two halves of that sentence, run separately because they support different
 * conclusions -- the first says what the entry point does today, the second
 * says whether the library can do it at all, which is what decides whether the
 * import needs a new binding.
 *
 * The fixture is a 232-byte armored message this repository now carries
 * (`data/skesk-aes256.asc`), made once by `gpg --symmetric --cipher-algo
 * AES256` with the passphrase below. It is committed rather than generated at
 * test time so that this file tests librnp rather than whether gpg is
 * installed.
 */

"use strict";

const { RNP } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/RNP.sys.mjs"
);
const { OpenPGPTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/mail/OpenPGPTestUtils.sys.mjs"
);
const { ctypes } = ChromeUtils.importESModule(
  "resource://gre/modules/ctypes.sys.mjs"
);

const FIXTURE = "data/skesk-aes256.asc";
const PASSPHRASE = "item95a-passphrase";
const PLAINTEXT = "Item 95a: can librnp open a symmetric message?";

/**
 * The pass-provider signature, from `rnp_password_cb` in `rnp.h`.
 *
 * Rebuilt here rather than imported because `RNPLib.sys.mjs` keeps the type
 * module-private, and building it in the test is part of what is being
 * established: whether librnp will call a callback with this shape for a
 * symmetric message.
 *
 * @returns {object} A ctypes function pointer type.
 */
function passwordCallbackType() {
  return ctypes.FunctionType(ctypes.default_abi, ctypes.bool, [
    ctypes.void_t.ptr, // rnp_ffi_t
    ctypes.void_t.ptr, // app_ctx
    ctypes.void_t.ptr, // rnp_key_handle_t, or NULL for a symmetric message
    ctypes.char.ptr, // pgp_context
    ctypes.char.ptr, // buf to write the password into
    ctypes.size_t, // buf_len
  ]).ptr;
}

/**
 * Writes a NUL-terminated string into one of C's buffers.
 *
 * @param {object} buf - `char.ptr` the library passed in.
 * @param {integer} bufLen - Its capacity.
 * @param {string} text
 * @returns {boolean} false when it does not fit.
 */
function writeToBuf(buf, bufLen, text) {
  const bytes = ctypes.char.array()(text);
  if (bufLen < bytes.length) {
    return false;
  }
  const chars = ctypes.cast(buf, ctypes.char.array(bufLen).ptr).contents;
  for (let i = 0; i < bytes.length; i++) {
    chars[i] = bytes[i];
  }
  chars[bytes.length] = 0;
  return true;
}

add_setup(async function () {
  do_get_profile();
  await OpenPGPTestUtils.initOpenPGP();

  // A prompt raised from inside a pass callback would put a dialog on the
  // user's screen. Nothing in this file should ever reach one; if it does, the
  // test says so rather than hanging or waiting for a window that is nobody's
  // to answer.
  const originalPrompt = Services.prompt;
  Services.prompt = {
    promptPassword() {
      Assert.ok(
        false,
        "a passphrase prompt was raised; nothing here should ask"
      );
      return false;
    },
    alert(w, t, text) {
      Assert.ok(false, `an alert was raised: ${text}`);
    },
    QueryInterface: ChromeUtils.generateQI(["nsIPromptService"]),
  };
  registerCleanupFunction(() => {
    Services.prompt = originalPrompt;
  });
});

/**
 * Half one: the entry point refuses, and the fixture is not the reason.
 *
 * `RNP.decrypt()` is what every consumer calls. On a symmetric message it
 * cannot succeed, and the failure has to be attributed correctly -- a message
 * that could not be *parsed* would look identical from the outside.
 */
add_task(async function theEntryPointCannotDecryptASkesk() {
  const armoured = await IOUtils.readUTF8(do_get_file(FIXTURE).path);
  const options = {
    fromAddr: "someone@example.com",
    maxOutputLength: armoured.length * 100,
    noOutput: false,
    uiFlags: 0,
    verifyOnly: false,
    msgDate: null,
  };

  let result;
  try {
    result = await RNP.decrypt(armoured, options);
    info(
      `FINDING entry point: exitCode=${result.exitCode} ` +
        `plaintext=${JSON.stringify(result.decryptedData.slice(0, 80))}`
    );
  } catch (ex) {
    info(`FINDING entry point threw: ${ex.message}`);
    Assert.ok(true, "the entry point does not decrypt it");
    return;
  }

  Assert.ok(
    result.exitCode != 0 || !result.decryptedData.length,
    "RNP.decrypt() does not open a symmetric message today"
  );
  Assert.ok(
    !result.decryptedData.includes(PLAINTEXT),
    "and no plaintext comes out of it"
  );
});

/**
 * Half two: the library can, given a callback that handles a keyless request.
 *
 * This is the decisive half. It drives librnp with the same operations
 * `decryptArray()` uses, except that the provider answers for a symmetric
 * message instead of demanding a key handle. If this works, no new binding is
 * needed for the import -- the work is a callback, not a function.
 *
 * The handle plumbing follows `decryptArray()` line for line: every one of
 * these types is an opaque pointer, so `ctypes.void_t.ptr()` stands in for the
 * module-private `rnp_input_t`, `rnp_output_t` and `rnp_op_verify_t`, and
 * `.address()` is what the C API takes for a pointer-to-handle.
 */
add_task(async function theLibraryCanWithASymmetricCapableProvider() {
  // The live wrapper, not a fresh one: `RNPLibLoader.init()` builds a new
  // object with a null `ffi` on every call, so reaching for it gives an
  // instance that cannot talk to the library this build already opened.
  const RNPLib = RNP.getRNPLib();
  Assert.ok(RNPLib?.loaded, "librnp loaded");
  Assert.ok(!RNPLib.ffi.isNull(), "and its ffi is the live one");

  const armoured = await IOUtils.readUTF8(do_get_file(FIXTURE).path);
  const arr = armoured.split("").map(c => c.charCodeAt(0) & 0xff);
  const data = ctypes.uint8_t.array()(arr);

  const seen = [];
  const callback = passwordCallbackType()(
    (ffi, appCtx, key, context, buf, bufLen) => {
      const ctx = context.isNull() ? "" : context.readString();
      // `key` is documented as "the key, if any". Recording whether it is null
      // is the whole question: a callback written for secret keys assumes it
      // is not, and that assumption is what makes the present entry point
      // refuse.
      seen.push({ context: ctx, keyIsNull: key.isNull() });
      return writeToBuf(buf, bufLen, PASSPHRASE);
    },
    null,
    false
  );
  Assert.ok(callback, "the callback type could be constructed");

  // `new`, not a call: these are pointer *instances* whose `.address()` is the
  // storage the library writes the handle into. A bare `ctypes.void_t.ptr()`
  // is a null pointer with nowhere to put anything, which is why the first
  // version of this task failed at `rnp_op_verify_create`.
  // `armored = true`: the fixture is ASCII-armored, and `rnp_input_from_memory`
  // is told so. Passing `false` is what `decryptArray()` does, because its
  // caller hands it bytes the MIME layer has already decoded; a test starting
  // from a file has the armor still on.
  const input = new ctypes.void_t.ptr();
  if (RNPLib.rnp_input_from_memory(input.address(), data, arr.length, true)) {
    throw new Error("rnp_input_from_memory failed");
  }

  const output = new ctypes.void_t.ptr();
  if (RNPLib.rnp_output_to_memory(output.address(), 0)) {
    throw new Error("rnp_output_to_memory failed");
  }

  const verifyOp = new ctypes.void_t.ptr();
  const createRc = RNPLib.rnp_op_verify_create(
    verifyOp.address(),
    RNPLib.ffi,
    input,
    output
  );
  info(
    `FINDING create: rc=${createRc} inputNull=${input.isNull()} ` +
      `outputNull=${output.isNull()} ffiNull=${RNPLib.ffi.isNull()}`
  );
  if (createRc) {
    throw new Error(`rnp_op_verify_create failed: ${createRc}`);
  }

  let exitCode;
  try {
    RNPLib.rnp_ffi_set_pass_provider(RNPLib.ffi, callback, null);
    exitCode = RNPLib.rnp_op_verify_execute(verifyOp);
  } finally {
    // Resets the callback reference RNP keeps, which is also what lets the
    // wrapper be collected.
    RNPLib.setDefaultPasswordCB();
  }

  let plaintext = "";
  const resultBuf = new ctypes.uint8_t.ptr();
  const resultLen = new ctypes.size_t();
  if (
    !RNPLib.rnp_output_memory_get_buf(
      output,
      resultBuf.address(),
      resultLen.address(),
      false
    )
  ) {
    plaintext = ctypes
      .cast(resultBuf, ctypes.char.array(resultLen.value).ptr)
      .contents.readString();
  }

  info(
    `FINDING library: exitCode=${exitCode} seen=${JSON.stringify(seen)} ` +
      `plaintext=${JSON.stringify(plaintext.slice(0, 80))}`
  );

  RNPLib.rnp_op_verify_destroy(verifyOp);
  RNPLib.rnp_input_destroy(input);
  RNPLib.rnp_output_destroy(output);

  Assert.ok(
    seen.length,
    "librnp consulted the provider, so the symmetric path does use it"
  );
  Assert.equal(seen[0].context, "decrypt (symmetric)", "with that context");
  Assert.ok(seen[0].keyIsNull, "and with no key handle, which is the point");
  Assert.equal(exitCode, 0, "and the message decrypted");
  Assert.ok(
    plaintext.includes(PLAINTEXT),
    `the plaintext is the one that was encrypted, got ${JSON.stringify(
      plaintext.slice(0, 80)
    )}`
  );
});
