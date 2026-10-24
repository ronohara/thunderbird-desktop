/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Reads the iteration count actually stored in a key database.
 *
 * Why this exists: NSS re-encrypts a database at login when its stored count
 * is below the minimum, and that upgrade is best-effort -- a failure is
 * swallowed (`PORT_SetError(0)` in `sftkdb_finishPasswordCheck`, with the
 * comment that login already succeeded). A profile that failed to upgrade
 * therefore looks exactly like one that succeeded. The only way to tell a
 * working floor from a silent one is to decode the count back out and report
 * it, rather than inferring success from the absence of an error.
 *
 * The count is readable without a password. It lives in the PBES2 parameter
 * set NSS stores in key4.db's `metaData` table under the id `password`, in
 * plaintext, because NSS has to know the count before it can derive anything.
 */

/**
 * Converts an even-length hex string to bytes.
 *
 * @param {string} hex
 * @returns {Uint8Array}
 */
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

/**
 * Reads one DER type-length-value triple.
 *
 * @param {Uint8Array} der
 * @param {number} offset
 * @returns {{tag: number, start: number, valueStart: number, end: number}}
 *   `start` is the offset of the tag byte, `valueStart` of the first content
 *   byte, `end` one past the last content byte.
 */
function readTLV(der, offset) {
  if (offset + 2 > der.length) {
    throw new Error("truncated DER: no room for tag and length");
  }
  const tag = der[offset];
  let p = offset + 1;
  let len = der[p++];

  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) {
      throw new Error(`unsupported DER length form: ${n} bytes`);
    }
    len = 0;
    for (let i = 0; i < n; i++) {
      len = (len << 8) | der[p++];
    }
  }
  const valueStart = p;
  const end = p + len;
  if (end > der.length) {
    throw new Error("truncated DER: length runs past the buffer");
  }
  return { tag, start: offset, valueStart, end };
}

/** Reads a DER INTEGER's value as a JS number. */
function readInteger(der, offset) {
  const { tag, valueStart, end } = readTLV(der, offset);
  if (tag !== 0x02) {
    throw new Error(`expected INTEGER (0x02), found 0x${tag.toString(16)}`);
  }
  let v = 0;
  for (let i = valueStart; i < end; i++) {
    v = v * 256 + der[i];
  }
  return { value: v, end };
}

/** The OID 1.2.840.113549.1.5.12 -- PBKDF2. */
const PBKDF2_OID = [
  0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c,
];

function oidAt(der, offset) {
  for (let i = 0; i < PBKDF2_OID.length; i++) {
    if (der[offset + i] !== PBKDF2_OID[i]) {
      return false;
    }
  }
  return true;
}

/**
 * Decodes the PBKDF2 iteration count from the PBES2 parameter set that NSS
 * stores in `metaData`'s `password` row.
 *
 * The shape is fixed by PKCS#5 and by `sftkdb_encodeCipherText`:
 *
 *   SEQUENCE                                 -- PBES2 AlgorithmIdentifier
 *     SEQUENCE
 *       OID  1.2.840.113549.1.5.13           -- PBES2
 *       SEQUENCE                             -- params
 *         SEQUENCE                           -- KDF AlgorithmIdentifier
 *           OID  1.2.840.113549.1.5.12       -- PBKDF2
 *           SEQUENCE
 *             OCTET STRING   salt
 *             INTEGER        iterationCount   <-- the value wanted
 *             INTEGER        keyLength        (optional)
 *             SEQUENCE       prf              (optional)
 *         ...
 *
 * Rather than assume positions, the PBKDF2 OID is located and the SEQUENCE
 * that follows it is read; its second child is the iteration count. That
 * tolerates the optional keyLength and prf being absent, and tolerates NSS
 * changing the surrounding encryption parameters.
 *
 * @param {Uint8Array} der
 * @returns {number|null} The iteration count, or null if this is not a
 *   PBES2/PBKDF2 parameter set.
 */
export function decodeIterationCount(der) {
  if (!der || der.length < 8) {
    return null;
  }

  // Locate the PBKDF2 OID rather than walking a fixed path: everything before
  // it is the outer SEQUENCE, the PBES2 OID and the params SEQUENCE, whose
  // lengths vary with the salt and with the cipher chosen.
  let oidOffset = -1;
  for (let i = 0; i + PBKDF2_OID.length <= der.length; i++) {
    if (oidAt(der, i)) {
      oidOffset = i;
      break;
    }
  }
  if (oidOffset < 0) {
    return null;
  }

  try {
    // The KDF SEQUENCE begins immediately after the OID.
    const kdf = readTLV(der, oidOffset + PBKDF2_OID.length);
    if (kdf.tag !== 0x30) {
      return null;
    }
    // First child is the salt OCTET STRING; the count follows it.
    const salt = readTLV(der, kdf.valueStart);
    if (salt.tag !== 0x04) {
      return null;
    }
    return readInteger(der, salt.end).value;
  } catch {
    return null;
  }
}

/** State a report can carry, so a caller does not have to interpret numbers. */
export const Status = {
  /** The stored count meets or exceeds the floor in force. */
  AtFloor: "at-floor",
  /** The stored count is below the floor: the upgrade did not happen. */
  BelowFloor: "below-floor",
  /** The database has no password, so there is no stretch to raise. */
  NoPassword: "no-password",
  /** The database could not be read, or held no recognisable parameter set. */
  Unknown: "unknown",
};

/**
 * Reads the iteration count stored in a key4.db, without a password.
 *
 * Opened read-only and closed in a `finally`: this must not be the reason a
 * profile cannot be opened elsewhere, and a monitoring read has no business
 * taking a write lock on the key database.
 *
 * @param {nsIFile} profileDir
 * @returns {Promise<number|null>} The stored count, or null when the file is
 *   missing or holds no password parameter set.
 */
export async function readStoredIterationCount(profileDir) {
  const dbFile = profileDir.clone();
  dbFile.append("key4.db");
  if (!dbFile.exists()) {
    return null;
  }

  let conn = null;
  try {
    conn = Services.storage.openDatabase(dbFile);
    // Read the column as hex rather than as a blob. mozIStorageStatement's
    // getBlob takes out-parameters in its IDL and has no in-tree JS caller to
    // copy, so the hex form avoids that binding question entirely; SQLite's
    // hex() is exact for a BLOB and the value is 133 bytes.
    const stmt = conn.createStatement(
      "SELECT hex(item2) FROM metaData WHERE id = 'password'"
    );
    try {
      if (!stmt.executeStep()) {
        return null;
      }
      const hex = stmt.getString(0);
      if (!hex) {
        return null;
      }
      return decodeIterationCount(hexToBytes(hex));
    } finally {
      stmt.finalize();
    }
  } catch (ex) {
    console.error("PBE stored count: could not read key4.db", ex);
    return null;
  } finally {
    try {
      conn?.close();
    } catch {
      // A close failure is not worth reporting over the result already read.
    }
  }
}

/**
 * Reads the stored count and says what it means relative to the floor in
 * force. This is the reporting half: it exists so a caller states a fact
 * rather than inferring one from silence.
 *
 * @param {nsIFile} profileDir
 * @param {number} floor The minimum NSS will apply, from
 *   `currentPBEIterationFloor()`.
 * @returns {Promise<{status: string, stored: number|null, floor: number}>}
 */
export async function reportStoredCount(profileDir, floor) {
  const stored = await readStoredIterationCount(profileDir);
  if (stored === null) {
    return { status: Status.Unknown, stored, floor };
  }
  // An empty password is stored as a count of 1: NSS deliberately skips the
  // stretch entirely, so a floor cannot apply and its absence is not a fault.
  if (stored <= 1) {
    return { status: Status.NoPassword, stored, floor };
  }
  if (floor > 0 && stored < floor) {
    return { status: Status.BelowFloor, stored, floor };
  }
  return { status: Status.AtFloor, stored, floor };
}
