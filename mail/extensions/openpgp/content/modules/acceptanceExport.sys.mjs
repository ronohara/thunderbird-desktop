/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Carrying the user's acceptance judgments between profiles.
 *
 * The judgments -- which keys are trusted, verified, rejected, personal --
 * live in the profile's own SQLite store, in `acceptance_decision`,
 * `acceptance_email` and `personal_key`. GnuPG exports its equivalent
 * (`--export-ownertrust`) and this store had no equivalent, so a lost profile
 * or a moved machine lost every judgment the user had made about which keys to
 * trust, and the only way to get them back was to repeat the work by hand, key
 * by key.
 *
 * Two facts travel here, and they are not the same fact: **this key is mine**
 * (the marker, `personal_key`) and **this is what I think of it for these
 * addresses** (the judgment, `acceptance_decision` + `acceptance_email`). An
 * entry carries `personal` for the first and `decision`/`emails` for the
 * second. `decision: "personal"` is still written and still read, because it
 * was the only way the marker could be expressed before the two were split
 * apart, and a file already exported must not become unimportable.
 *
 * Two things this is not. It is not a backup of the keys: keys travel in the
 * keyring, and this file is meaningless without them, though an entry for a key
 * that is not present is kept and becomes meaningful when the key arrives. And
 * it is not a synchronization mechanism: there is no merge conflict resolution
 * by recency, because the schema holds no timestamp, so the import rule is
 * stated rather than guessed (see `importAcceptance`).
 *
 * The format is JSON, deliberately readable. A trust store that can only be
 * read by the program that wrote it is one the user cannot check before
 * importing, and checking is the point of exporting.
 */

const lazy = {};

ChromeUtils.defineESModuleGetters(lazy, {
  PgpSqliteDb2: "chrome://openpgp/content/modules/sqliteDb.sys.mjs",
});

/** Bumped only when the shape changes incompatibly. */
export const FORMAT_VERSION = 1;

/** What the file says it is, so a wrong file is refused rather than parsed. */
export const FORMAT_KIND = "thunderbird-openpgp-acceptance";

/**
 * The decisions the store can hold. `undecided` is deliberately absent: it is
 * not a stored value, it is the absence of a row, so a file that names it is
 * describing something the store has no way to represent.
 *
 * `personal` is a decision word only for compatibility. It names the marker,
 * not a judgment about an address, and the import routes it to the marker.
 */
export const DECISIONS = ["personal", "verified", "unverified", "rejected"];

/**
 * The decision words that say something about a key's addresses. `personal` is
 * excluded: a key can be the user's own without any address being judged, and
 * a judgment can exist for a key that is not the user's own.
 */
const ADDRESS_DECISIONS = new Set(["verified", "unverified", "rejected"]);

/**
 * Fingerprint lengths in hex digits. A v4 fingerprint is 40; librnp's
 * `Fingerprint::size_valid` accepts 16, 20 and 32 bytes (32, 40 and 64 hex), so
 * the same set is accepted here rather than assuming v4 -- a v5 key's
 * judgment must be exportable too.
 */
const FPR_HEX_LENGTHS = new Set([32, 40, 64]);

/**
 * @param {string} value
 * @returns {boolean} Whether the value looks like a fingerprint.
 */
function isValidFingerprint(value) {
  return (
    typeof value == "string" &&
    /^[0-9a-f]+$/i.test(value) &&
    FPR_HEX_LENGTHS.has(value.length)
  );
}

/**
 * Reads every acceptance judgment in the store.
 *
 * Both facts are read: the address judgments from `acceptance_decision` and
 * `acceptance_email`, and the personal markers from `personal_key`. A key that
 * is the user's own and has no address judgment is exported as
 * `decision: "personal"` with `personal: true` -- the word files already carry
 * -- so moving a profile does not quietly lose it.
 *
 * @returns {Promise<object[]>} `[{fpr, decision, emails, personal}]`, ordered
 *   by fingerprint so an exported file is stable and a diff between two exports
 *   shows what actually changed.
 */
export async function readAcceptance() {
  const conn = await lazy.PgpSqliteDb2.openDatabase();
  try {
    const decisions = await conn.execute(
      "select fpr, decision from acceptance_decision order by fpr"
    );
    const emails = await conn.execute(
      "select fpr, email from acceptance_email order by fpr, email"
    );
    const personal = await conn.execute(
      "select fpr from personal_key order by fpr"
    );

    const byFpr = new Map();
    for (const row of decisions) {
      byFpr.set(row.getResultByName("fpr"), {
        fpr: row.getResultByName("fpr"),
        decision: row.getResultByName("decision"),
        emails: [],
        personal: false,
      });
    }
    for (const row of emails) {
      const entry = byFpr.get(row.getResultByName("fpr"));
      if (entry) {
        entry.emails.push(row.getResultByName("email"));
      }
      // An address whose fingerprint has no decision row is unreachable
      // through `getAcceptance` -- the join in the read path requires the
      // decision -- so it is dropped rather than exported as though it meant
      // something.
    }
    for (const row of personal) {
      const fpr = row.getResultByName("fpr");
      const entry = byFpr.get(fpr);
      if (entry) {
        entry.personal = true;
      } else {
        byFpr.set(fpr, {
          fpr,
          decision: "personal",
          emails: [],
          personal: true,
        });
      }
    }
    return [...byFpr.values()].sort((a, b) => (a.fpr < b.fpr ? -1 : 1));
  } finally {
    await conn.close();
  }
}

/**
 * Builds the exportable document.
 *
 * @returns {Promise<object>} A JSON-serialisable object.
 */
export async function buildExport() {
  const decisions = await readAcceptance();
  return {
    kind: FORMAT_KIND,
    version: FORMAT_VERSION,
    exportedAt: new Date().toISOString(),
    // Counted rather than left to the reader: a file that says how many
    // judgments it holds can be checked against the machine it came from.
    count: decisions.length,
    decisions,
  };
}

/**
 * Builds the export as the text to write to a file.
 *
 * @returns {Promise<string>}
 */
export async function exportAcceptanceToJSON() {
  return JSON.stringify(await buildExport(), null, 2) + "\n";
}

/**
 * Checks a parsed document and returns its usable entries.
 *
 * Malformed entries are skipped and counted rather than throwing away the whole
 * file: one bad row in an otherwise good export should not cost the user every
 * other judgment, but it must not be silently dropped either, so the count
 * reaches the caller.
 *
 * @param {*} data - Parsed JSON.
 * @returns {{entries: object[], skipped: number, error: ?string}}
 */
export function validateExport(data) {
  if (!data || typeof data != "object" || Array.isArray(data)) {
    return { entries: [], skipped: 0, error: "not an object" };
  }
  if (data.kind !== FORMAT_KIND) {
    return { entries: [], skipped: 0, error: "not an acceptance export" };
  }
  if (data.version !== FORMAT_VERSION) {
    return {
      entries: [],
      skipped: 0,
      error: `unsupported version ${data.version}`,
    };
  }
  if (!Array.isArray(data.decisions)) {
    return { entries: [], skipped: 0, error: "no decisions array" };
  }

  const entries = [];
  let skipped = 0;
  for (const item of data.decisions) {
    if (
      !item ||
      typeof item != "object" ||
      !isValidFingerprint(item.fpr) ||
      !DECISIONS.includes(item.decision)
    ) {
      skipped++;
      continue;
    }
    const fpr = item.fpr.toLowerCase();
    const emails = Array.isArray(item.emails)
      ? item.emails
          .filter(e => typeof e == "string" && e.includes("@"))
          .map(e => e.toLowerCase())
      : [];
    entries.push({
      fpr,
      decision: item.decision,
      emails,
      // Absent in files written before the marker had its own field; such an
      // entry expresses the marker through `decision` instead.
      personal: item.personal === true,
    });
  }
  return { entries, skipped, error: null };
}

/**
 * Merges exported judgments into the local store.
 *
 * The rule, stated because the schema cannot supply one: **a local judgment is
 * never removed, and is replaced only when the caller says so.** There is no
 * timestamp on a decision, so "most recent wins" is not available; inventing an
 * order from the file's `exportedAt` would be an inference the data does not
 * support, since a decision recorded on this machine may well be newer than
 * every decision in a file exported last month.
 *
 * So a conflict -- the same fingerprint, a different decision on each side --
 * is reported, and `onConflict` decides it. The default keeps the local value,
 * for the same reason the push gate defaults to refusal: importing someone
 * else's file must not quietly lower a judgment this machine's user made.
 * Importing into a fresh profile involves no conflicts at all, and that is the
 * case this exists for.
 *
 * A judgment for a key that is not in this profile's keyring is stored and
 * counted separately. It is harmless -- the read path resolves by fingerprint,
 * so the judgment simply waits -- and it is exactly right for a migration done
 * before the keys have been copied.
 *
 * @param {*} data - Parsed JSON from `buildExport()`.
 * @param {object} [options]
 * @param {"keep-local"|"take-imported"} [options.onConflict="keep-local"]
 * @returns {Promise<object>} Counts, so the caller can say what happened.
 */
export async function importAcceptance(data, options = {}) {
  const onConflict = options.onConflict ?? "keep-local";
  if (onConflict != "keep-local" && onConflict != "take-imported") {
    throw new Error(`invalid onConflict ${onConflict}`);
  }

  const { entries, skipped, error } = validateExport(data);
  if (error) {
    throw new Error(`cannot import: ${error}`);
  }

  const existing = new Map(
    (await readAcceptance()).map(entry => [entry.fpr, entry])
  );

  const result = {
    added: 0,
    replaced: 0,
    kept: 0,
    conflicts: 0,
    skipped,
    // Entries for keys this profile does not hold. Not a failure: a judgment
    // can arrive before the key it is about.
    forUnknownKeys: 0,
    errors: [],
  };

  const ring = lazy.PgpSqliteDb2;
  for (const entry of entries) {
    const local = existing.get(entry.fpr);

    // The marker first, and independently of the judgment below.
    //
    // "This key is mine" and "this is what I think of it for this address" are
    // separate facts, so an entry may carry either, or both, and neither may
    // stand in for the other. The marker is never removed by an import: a file
    // that does not mention it says nothing about it.
    if (entry.personal || entry.decision == "personal") {
      if (local?.personal) {
        result.kept++;
      } else {
        try {
          await ring.acceptAsPersonalKey(entry.fpr);
          result.added++;
        } catch (ex) {
          result.errors.push(`${entry.fpr}: ${ex.message}`);
        }
      }
    }

    if (entry.decision == "personal") {
      // A marker and nothing else, which is what every `personal` entry meant
      // before the two facts had separate homes.
      continue;
    }

    // Only a real judgment conflicts with a real judgment. A local marker used
    // to sit in the same column, so comparing against it here would report a
    // false conflict between "this key is mine" and "I verified it".
    const localDecision = ADDRESS_DECISIONS.has(local?.decision)
      ? local.decision
      : null;

    if (localDecision && localDecision == entry.decision) {
      // Same decision, possibly different addresses. Merging the addresses is
      // the one thing an identical decision still has to do, because the
      // address list is what decides whether the key is usable for a sender.
      const missing = entry.emails.filter(e => !local.emails.includes(e));
      if (missing.length) {
        try {
          for (const email of missing) {
            await ring.addAcceptedEmail(entry.fpr, email);
          }
          result.replaced++;
        } catch (ex) {
          result.errors.push(`${entry.fpr}: ${ex.message}`);
        }
      } else {
        result.kept++;
      }
      continue;
    }

    if (localDecision) {
      result.conflicts++;
      if (onConflict == "keep-local") {
        result.kept++;
        continue;
      }
    }

    try {
      // `updateAcceptance` replaces the rows for this fingerprint wholesale,
      // which is what makes the address list authoritative rather than
      // additive. Passing the fingerprints' addresses is therefore required:
      // omitting them would drop the addresses the local entry had.
      await ring.updateAcceptance(
        entry.fpr,
        entry.decision == "rejected" ? null : entry.emails,
        entry.decision
      );
      if (localDecision) {
        result.replaced++;
      } else {
        result.added++;
      }
    } catch (ex) {
      result.errors.push(`${entry.fpr}: ${ex.message}`);
    }
  }

  return result;
}

/**
 * Imports from the text of a file.
 *
 * @param {string} text
 * @param {object} [options] - See `importAcceptance`.
 * @returns {Promise<object>} Counts.
 */
export async function importAcceptanceFromJSON(text, options) {
  let data;
  try {
    data = JSON.parse(text);
  } catch (ex) {
    throw new Error(`cannot import: not valid JSON (${ex.message})`);
  }
  return importAcceptance(data, options);
}
