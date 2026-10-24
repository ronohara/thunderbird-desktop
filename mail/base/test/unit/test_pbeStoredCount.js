/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

const {
  decodeIterationCount,
  readStoredIterationCount,
  reportStoredCount,
  Status,
} = ChromeUtils.importESModule("resource:///modules/PBEStoredCount.sys.mjs");

do_get_profile();

/**
 * Builds the PBES2 parameter set NSS writes into key4.db's `metaData` row for
 * id `password`, so the decoder is exercised against the real shape rather
 * than against a guess.
 *
 * @param {number} iterations
 * @param {object} [opts]
 * @param {boolean} [opts.keyLength] Include the optional keyLength INTEGER.
 * @param {boolean} [opts.prf] Include the optional prf SEQUENCE.
 * @param {number} [opts.saltLen] Salt length in bytes.
 */
function buildPBES2Der(iterations, opts = {}) {
  const saltLen = opts.saltLen ?? 32;
  const salt = new Uint8Array(saltLen);
  for (let i = 0; i < saltLen; i++) {
    salt[i] = (i * 7 + 3) & 0xff;
  }

  const int = n => {
    // Minimal two-or-three byte encoding, the widths NSS actually emits.
    if (n < 0x100) {
      return [0x02, 0x02, (n >> 8) & 0xff, n & 0xff];
    }
    return [0x02, 0x03, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
  };
  const seq = body => {
    const len = body.length;
    if (len < 0x80) {
      return [0x30, len, ...body];
    }
    if (len < 0x100) {
      return [0x30, 0x81, len, ...body];
    }
    return [0x30, 0x82, (len >> 8) & 0xff, len & 0xff, ...body];
  };
  const octet = bytes => [0x04, bytes.length, ...bytes];

  const PBKDF2 = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c,
  ];
  const PBES2 = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d,
  ];
  const HMAC_SHA256 = [
    0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09,
  ];

  const kdfParams = [...octet(salt), ...int(iterations)];
  if (opts.keyLength) {
    kdfParams.push(...int(32));
  }
  if (opts.prf) {
    kdfParams.push(...seq(HMAC_SHA256));
  }

  const kdf = seq([...PBKDF2, ...seq(kdfParams)]);
  const encScheme = seq(HMAC_SHA256); // stands in for the cipher algid
  const params = seq([...kdf, ...encScheme]);
  return new Uint8Array(seq([...PBES2, ...params]));
}

/**
 * Creates a key4.db-shaped file with one `password` metadata row.
 *
 * @param {nsIFile} dir Directory to create the file in.
 * @param {Uint8Array} derBytes The parameter set to store.
 * @returns {nsIFile} The file written.
 */
function writeFakeKey4Db(dir, derBytes) {
  const file = dir.clone();
  file.append("key4.db");
  if (file.exists()) {
    file.remove(false);
  }
  let step = "open database";
  let conn;
  try {
    conn = Services.storage.openDatabase(file);
    step = "create table";
    conn.executeSimpleSQL(
      "CREATE TABLE metaData (id TEXT PRIMARY KEY, item1 BLOB, item2 BLOB)"
    );
    step = "insert row";
    // SQLite's x'..' literal writes the BLOB directly, so neither the test
    // nor the reader needs mozIStorage's blob binding.
    const hex = Array.from(derBytes, b => b.toString(16).padStart(2, "0")).join(
      ""
    );
    conn.executeSimpleSQL(
      `INSERT INTO metaData (id, item1, item2) ` +
        `VALUES ('password', NULL, x'${hex}')`
    );
  } catch (ex) {
    throw new Error(`writeFakeKey4Db failed at "${step}": ${ex}`);
  } finally {
    conn?.close();
  }
  return file;
}

function tempDir(name) {
  const d = Services.dirsvc.get("ProfD", Ci.nsIFile).clone();
  d.append(name);
  if (!d.exists()) {
    d.create(Ci.nsIFile.DIRECTORY_TYPE, 0o700);
  }
  return d;
}

// --------------------------------------------------------------- the decoder

add_task(async function test_decodes_typical_counts() {
  for (const n of [1, 10000, 1010000, 840000, 4194304]) {
    Assert.equal(decodeIterationCount(buildPBES2Der(n)), n, `round-trips ${n}`);
  }
});

add_task(async function test_decodes_the_shape_nss_actually_writes() {
  // The exact bytes from a real key4.db written by NSS at the default count,
  // captured on 2026-10-24. If the decoder stops handling this, it has been
  // changed in a way that will silently report nothing.
  // Concatenated with explicit "+": adjacent string literals are separate
  // statements in JavaScript, unlike C or Python, so without the operators
  // only the first line would be assigned.
  const hex =
    "308182306e06092a864886f70d01050d3061304206092a864886f70d01050c30" +
    "350420cc69fe59a8775acc297058ee3214864c10e336c77f5c4ab39e4b5c49ee" +
    "96246c02022710020120300a06082a864886f70d0209301b0609608648016503" +
    "04012a040e0cc3d886970ca33168e33ca0e4e00410771e827dd14ac9b35b1007" +
    "5c71b6a0a0";
  const der = Uint8Array.from(hex.match(/../g).map(b => parseInt(b, 16)));
  Assert.equal(decodeIterationCount(der), 10000);
});

add_task(async function test_decodes_an_upgraded_database() {
  // A real key4.db after the floor was applied at a writable login: the same
  // NSS encoder, at 1,010,000 rather than the default. This is the state the
  // item exists to detect, so it is pinned rather than synthesised.
  const hex =
    "308183306f06092a864886f70d01050d3062304306092a864886f70d01050c30" +
    "360420590e0e24cf1c438dd5cf98b848e771c4fd77b85e60ed14f1dc224077a1" +
    "f0d0b302030f6950020120300a06082a864886f70d0209301b06096086480165" +
    "0304012a040ef5dd4393f9d9397d4e078eb57e4604105362cd43f6b0426a01fc" +
    "0935f454002e";
  const der = Uint8Array.from(hex.match(/../g).map(b => parseInt(b, 16)));
  Assert.equal(decodeIterationCount(der), 1010000);
});

add_task(async function test_tolerates_optional_fields_absent() {
  Assert.equal(
    decodeIterationCount(
      buildPBES2Der(500000, { keyLength: false, prf: false })
    ),
    500000,
    "keyLength and prf are optional in PKCS#5 and must not be assumed"
  );
  Assert.equal(
    decodeIterationCount(buildPBES2Der(500000, { keyLength: true, prf: true })),
    500000
  );
});

add_task(async function test_tolerates_a_different_salt_length() {
  // The count is located from the PBKDF2 OID, not from a fixed offset, so a
  // salt that is not 32 bytes must still decode.
  for (const saltLen of [8, 16, 32, 48, 64]) {
    Assert.equal(
      decodeIterationCount(buildPBES2Der(123456, { saltLen })),
      123456,
      `salt length ${saltLen}`
    );
  }
});

add_task(async function test_returns_null_rather_than_guessing() {
  Assert.equal(decodeIterationCount(null), null);
  Assert.equal(decodeIterationCount(new Uint8Array(0)), null);
  Assert.equal(decodeIterationCount(new Uint8Array([1, 2, 3])), null);
  Assert.equal(
    decodeIterationCount(new Uint8Array(64).fill(0xaa)),
    null,
    "random bytes must not produce a number out of nowhere"
  );
  // A PBKDF2 OID with nothing valid after it must not throw.
  Assert.equal(
    decodeIterationCount(
      Uint8Array.from([
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c,
      ])
    ),
    null
  );
});

// ---------------------------------------------------------------- the reader

add_task(async function test_reads_a_count_out_of_a_database() {
  const dir = tempDir("pbe-read");
  writeFakeKey4Db(dir, buildPBES2Der(1010000));
  Assert.equal(await readStoredIterationCount(dir), 1010000);
});

add_task(async function test_missing_database_is_null_not_an_error() {
  const dir = tempDir("pbe-missing");
  const f = dir.clone();
  f.append("key4.db");
  if (f.exists()) {
    f.remove(false);
  }
  Assert.equal(await readStoredIterationCount(dir), null);
});

add_task(async function test_unrecognisable_blob_is_null() {
  const dir = tempDir("pbe-garbage");
  writeFakeKey4Db(dir, new Uint8Array([0xff, 0x00, 0x13, 0x37]));
  Assert.equal(await readStoredIterationCount(dir), null);
});

// ------------------------------------------------------------- the reporting

add_task(async function test_reports_at_floor() {
  const dir = tempDir("pbe-at");
  writeFakeKey4Db(dir, buildPBES2Der(1010000));
  const r = await reportStoredCount(dir, 1010000);
  Assert.equal(r.status, Status.AtFloor);
  Assert.equal(r.stored, 1010000);
  Assert.equal(r.floor, 1010000);
});

add_task(async function test_reports_below_floor() {
  // The whole point of the item: an upgrade that failed leaves this state
  // looking exactly like success, unless something reads the count back.
  const dir = tempDir("pbe-below");
  writeFakeKey4Db(dir, buildPBES2Der(10000));
  const r = await reportStoredCount(dir, 1010000);
  Assert.equal(r.status, Status.BelowFloor);
  Assert.equal(r.stored, 10000);
});

add_task(async function test_a_count_of_one_means_no_password() {
  const dir = tempDir("pbe-nopass");
  writeFakeKey4Db(dir, buildPBES2Der(1));
  const r = await reportStoredCount(dir, 1010000);
  Assert.equal(
    r.status,
    Status.NoPassword,
    "NSS writes 1 when there is no password, and a floor cannot apply; " +
      "reporting below-floor there would be a false alarm on every default profile"
  );
});

add_task(async function test_unknown_when_there_is_nothing_to_read() {
  const dir = tempDir("pbe-unknown");
  const f = dir.clone();
  f.append("key4.db");
  if (f.exists()) {
    f.remove(false);
  }
  const r = await reportStoredCount(dir, 1010000);
  Assert.equal(r.status, Status.Unknown);
  Assert.equal(r.stored, null);
});

add_task(async function test_no_floor_means_nothing_to_compare() {
  const dir = tempDir("pbe-nofloor");
  writeFakeKey4Db(dir, buildPBES2Der(10000));
  const r = await reportStoredCount(dir, 0);
  Assert.equal(
    r.status,
    Status.AtFloor,
    "with no floor in force the stored count cannot be below it"
  );
});
