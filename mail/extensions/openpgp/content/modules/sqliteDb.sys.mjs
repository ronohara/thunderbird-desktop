/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 * Module that provides generic functions for the OpenPGP SQLite database.
 */
const lazy = {};
ChromeUtils.defineESModuleGetters(lazy, {
  EnigmailKeyRing: "chrome://openpgp/content/modules/keyRing.sys.mjs",
  Sqlite: "resource://gre/modules/Sqlite.sys.mjs",
  setTimeout: "resource://gre/modules/Timer.sys.mjs",
});
ChromeUtils.defineLazyGetter(lazy, "log", () => {
  return console.createInstance({
    prefix: "openpgp",
    maxLogLevel: "Warn",
    maxLogLevelPref: "openpgp.loglevel",
  });
});

export var PgpSqliteDb2 = {
  /** @returns {Promise<OpenedConnection>} */
  openDatabase() {
    return new Promise((resolve, reject) => {
      openDatabaseConn(
        "openpgp.sqlite",
        resolve,
        reject,
        100,
        Date.now() + 10000
      );
    });
  },

  /**
   * Check database structure is ok.
   *
   * @throws {Error} if the structure is not ok.
   */
  async checkDatabaseStructure() {
    let conn;
    try {
      conn = await this.openDatabase();
      await checkAcceptanceTable(conn);
      await conn.close();
    } catch (ex) {
      lazy.log.error("Check db structure FAILED.", ex);
      if (conn) {
        await conn.close();
      }
      throw ex;
    }
  },

  accCacheFingerprint: "",
  accCacheValue: "",
  accCacheEmails: null,

  /**
   * @param {Promise<OpenedConnection>} conn
   * @param {string} fingerprint
   */
  async getFingerprintAcceptance(conn, fingerprint) {
    // 40 is for modern fingerprints, 32 for older fingerprints.
    // 16, 20 and 32 bytes: v3, v4 and v5. The acceptance table stores the
    // fingerprint as text and has no length constraint, so widening this costs
    // nothing on disk -- it refused v5 before the key could reach it.
    if (
      fingerprint.length != 40 &&
      fingerprint.length != 32 &&
      fingerprint.length != 64
    ) {
      throw new Error(`Invalid fingerprint: ${fingerprint}`);
    }

    fingerprint = fingerprint.toLowerCase();
    if (fingerprint == this.accCacheFingerprint) {
      return this.accCacheValue;
    }

    let myConn = false;
    let rv = "";

    try {
      if (!conn) {
        myConn = true;
        conn = await this.openDatabase();
      }

      await conn
        .execute("select decision from acceptance_decision where fpr = :fpr", {
          fpr: fingerprint,
        })
        .then(result => {
          if (result.length) {
            rv = result[0].getResultByName("decision");
          }
        });
    } catch (ex) {
      console.warn(ex);
    }

    if (myConn && conn) {
      await conn.close();
    }
    return rv;
  },

  /**
   * Check if the given email has a positively accepted key.
   *
   * @param {string} email
   * @returns {boolean} true if it has an accepted key.
   */
  async hasAnyPositivelyAcceptedKeyForEmail(email) {
    email = email.toLowerCase();
    let count = 0;

    let conn;
    try {
      conn = await this.openDatabase();

      const result = await conn.execute(
        "select count(decision) as hits from acceptance_email" +
          " inner join acceptance_decision on" +
          " acceptance_decision.fpr = acceptance_email.fpr" +
          " where (decision = 'verified' or decision = 'unverified')" +
          " and lower(email) = :email",
        { email }
      );
      if (result.length) {
        count = result[0].getResultByName("hits");
      }
      await conn.close();
    } catch (ex) {
      if (conn) {
        await conn.close();
      }
      throw ex;
    }

    if (!count) {
      return Boolean(await lazy.EnigmailKeyRing.getSecretKeyByEmail(email));
    }
    return true;
  },

  /**
   * Get acceptance for the specified fingerprint + email combination.
   *
   * @param {string} fingerprint
   * @param {string} email
   * @param {object} rv - Out object.
   * FIXME: use return value instead.
   */
  async getAcceptance(fingerprint, email, rv) {
    fingerprint = fingerprint.toLowerCase();
    email = email.toLowerCase();

    rv.emailDecided = false;
    rv.fingerprintAcceptance = "";

    if (fingerprint == this.accCacheFingerprint) {
      if (
        this.accCacheValue.length &&
        this.accCacheValue != "undecided" &&
        this.accCacheEmails &&
        this.accCacheEmails.has(email)
      ) {
        rv.emailDecided = true;
        rv.fingerprintAcceptance = this.accCacheValue;
      }
      return;
    }

    let conn;
    try {
      conn = await this.openDatabase();

      rv.fingerprintAcceptance = await this.getFingerprintAcceptance(
        conn,
        fingerprint
      );

      if (rv.fingerprintAcceptance) {
        await conn
          .execute(
            "select count(*) from acceptance_email where fpr = :fpr and email = :email",
            {
              fpr: fingerprint,
              email,
            }
          )
          .then(result => {
            if (result.length) {
              const count = result[0].getResultByName("count(*)");
              rv.emailDecided = count > 0;
            }
          });
      }
      await conn.close();
    } catch (ex) {
      if (conn) {
        await conn.close();
      }
      throw ex;
    }
  },

  /**
   * @param {OpenedConnection} conn - Connection.
   * @param {string} fingerprint - Fingerprint; must be lowercase already.
   */
  async _deleteAcceptanceNoTransaction(conn, fingerprint) {
    const delObj = { fpr: fingerprint };
    await conn.execute(
      "delete from acceptance_decision where fpr = :fpr",
      delObj
    );
    await conn.execute("delete from acceptance_email where fpr = :fpr", delObj);
    // Deliberately not `personal_key`. This helper is shared with
    // `updateAcceptance()`, which replaces a fingerprint's *judgment* and must
    // leave the marker alone -- a key stays the user's own however often its
    // addresses are judged. The wholesale delete adds the marker itself.
  },

  /**
   * Delete acceptance for the given fingerprint.
   *
   * @param {string} fingerprint
   */
  async deleteAcceptance(fingerprint) {
    fingerprint = fingerprint.toLowerCase();
    this.accCacheFingerprint = fingerprint;
    this.accCacheValue = "";
    this.accCacheEmails = null;
    let conn;
    try {
      conn = await this.openDatabase();
      await conn.execute("begin transaction");
      await this._deleteAcceptanceNoTransaction(conn, fingerprint);
      // Everything the store knows about the fingerprint, which is what a
      // caller deleting a key means. Clearing only the marker has its own
      // method, `deletePersonalKeyAcceptance()`.
      await conn.execute("delete from personal_key where fpr = :fpr", {
        fpr: fingerprint,
      });
      await conn.execute("commit transaction");
      await conn.close();
      Services.obs.notifyObservers(null, "openpgp-acceptance-change");
    } catch (ex) {
      if (conn) {
        await conn.close();
      }
      throw ex;
    }
  },

  /**
   * Convenience function that will add one accepted email address,
   * either to an already accepted key, or as unverified to an undecided
   * key. It is an error to call this API for a rejected key, or for
   * an already accepted email address.
   *
   * @param {string} fingerprint
   * @param {string} email
   */
  async addAcceptedEmail(fingerprint, email) {
    fingerprint = fingerprint.toLowerCase();
    email = email.toLowerCase();
    let conn;
    try {
      conn = await this.openDatabase();

      const fingerprintAcceptance = await this.getFingerprintAcceptance(
        conn,
        fingerprint
      );

      let fprAlreadyAccepted = false;

      switch (fingerprintAcceptance) {
        case "undecided":
        case "":
        case undefined:
          break;

        case "unverified":
        case "verified":
          fprAlreadyAccepted = true;
          break;

        default:
          throw new Error(
            "invalid use of addAcceptedEmail() with existing acceptance " +
              fingerprintAcceptance
          );
      }

      this.accCacheFingerprint = "";
      this.accCacheValue = "";
      this.accCacheEmails = null;

      if (!fprAlreadyAccepted) {
        await conn.execute("begin transaction");
        // start fresh, clean up old potential email decisions
        this._deleteAcceptanceNoTransaction(conn, fingerprint);

        await conn.execute(
          "insert into acceptance_decision values (:fpr, :decision)",
          {
            fpr: fingerprint,
            decision: "unverified",
          }
        );
      } else {
        await conn
          .execute(
            "select count(*) from acceptance_email where fpr = :fpr and email = :email",
            {
              fpr: fingerprint,
              email,
            }
          )
          .then(result => {
            if (result.length && result[0].getResultByName("count(*)") > 0) {
              throw new Error(
                `${email} already has acceptance for ${fingerprint}`
              );
            }
          });

        await conn.execute("begin transaction");
      }

      await conn.execute("insert into acceptance_email values (:fpr, :email)", {
        fpr: fingerprint,
        email,
      });

      await conn.execute("commit transaction");
      await conn.close();
      Services.obs.notifyObservers(null, "openpgp-acceptance-change");
    } catch (ex) {
      if (conn) {
        await conn.close();
      }
      throw ex;
    }
  },

  async updateAcceptance(fingerprint, emailArray, decision) {
    fingerprint = fingerprint.toLowerCase();

    if (decision == "personal") {
      // "Personal" is not a judgment about an address, so it is routed to the
      // marker rather than stored here.
      //
      // This is how every caller marked a key as its own before the marker had
      // its own table -- the shared test helper's `importPrivateKey()` still
      // defaults to it -- and ignoring the word here would leave those keys
      // unmarked while reporting success. The address list is not used: a
      // marker says nothing about which addresses a key is judged for, and
      // writing it must not replace a judgment the user already made.
      await this.acceptAsPersonalKey(fingerprint);
      return;
    }

    let conn;
    try {
      const uniqueEmails = new Set();
      if (decision !== "undecided") {
        if (emailArray) {
          for (let email of emailArray) {
            if (!email) {
              continue;
            }
            email = email.toLowerCase();
            if (uniqueEmails.has(email)) {
              continue;
            }
            uniqueEmails.add(email);
          }
        }
      }

      this.accCacheFingerprint = fingerprint;
      this.accCacheValue = decision;
      this.accCacheEmails = uniqueEmails;

      conn = await this.openDatabase();
      await conn.execute("begin transaction");
      await this._deleteAcceptanceNoTransaction(conn, fingerprint);

      if (decision !== "undecided") {
        const decisionObj = {
          fpr: fingerprint,
          decision,
        };
        await conn.execute(
          "insert into acceptance_decision values (:fpr, :decision)",
          decisionObj
        );

        // Rejection is global for a fingerprint, don't need to
        // store email address records.

        if (decision !== "rejected") {
          // A key might contain multiple user IDs with the same email
          // address. We add each email only once.
          for (const email of uniqueEmails) {
            await conn.execute(
              "insert into acceptance_email values (:fpr, :email)",
              {
                fpr: fingerprint,
                email,
              }
            );
          }
        }
      }
      await conn.execute("commit transaction");
      await conn.close();
      Services.obs.notifyObservers(null, "openpgp-acceptance-change");
    } catch (ex) {
      if (conn) {
        await conn.close();
      }
      throw ex;
    }
  },

  /**
   * Mark a key as the user's own.
   *
   * The promise is returned, not merely awaited inside: without that, an
   * `await` on this call resolved before the write had begun, so a caller saw
   * a success for a write that had not happened and would never report its
   * failure. `RNP.genKey()` awaits this, and a key whose marker did not commit
   * can never be used for encryption.
   *
   * The marker lives in its own table. It used to be a `decision` value, in the
   * one row per fingerprint that also holds the trust judgment for a key's
   * addresses -- so accepting a key for an address deleted that row and wrote
   * `verified` in its place, and the key stopped being the user's own. Two
   * facts, one row; now two tables, and the collision cannot happen.
   *
   * @param {string} fingerprint
   * @returns {Promise<void>} Resolves once the write has committed.
   */
  async acceptAsPersonalKey(fingerprint) {
    fingerprint = fingerprint.toLowerCase();
    let conn;
    try {
      conn = await this.openDatabase();
      await conn.execute("insert or ignore into personal_key values (:fpr)", {
        fpr: fingerprint,
      });
      await conn.close();
      Services.obs.notifyObservers(null, "openpgp-acceptance-change");
    } catch (ex) {
      if (conn) {
        await conn.close();
      }
      throw ex;
    }
  },

  /**
   * Drop the marker that says a key is the user's own.
   *
   * Only the marker. This used to call `deleteAcceptance()`, which also removed
   * the trust judgment and its addresses -- so unticking "personal" silently
   * discarded a judgment the user had made about that key's user IDs.
   *
   * @param {string} fingerprint
   * @returns {Promise<void>} Resolves once the delete has committed.
   */
  async deletePersonalKeyAcceptance(fingerprint) {
    fingerprint = fingerprint.toLowerCase();
    let conn;
    try {
      conn = await this.openDatabase();
      await conn.execute("delete from personal_key where fpr = :fpr", {
        fpr: fingerprint,
      });
      await conn.close();
      Services.obs.notifyObservers(null, "openpgp-acceptance-change");
    } catch (ex) {
      if (conn) {
        await conn.close();
      }
      throw ex;
    }
  },

  /**
   * Whether the user has marked this key as their own.
   *
   * A rejection outranks the marker. Rejecting a key means never encrypt to
   * it, and that decision is global for the fingerprint; a key can be both the
   * user's own and rejected, and in that state it is not usable. Checking here
   * rather than at the eight call sites is what keeps them all correct, and it
   * restores an invariant the old one-row schema could not hold: rejecting a
   * key used to be silently undone by marking it personal.
   *
   * @param {string} fingerprint
   * @returns {Promise<boolean>}
   */
  async isAcceptedAsPersonalKey(fingerprint) {
    fingerprint = fingerprint.toLowerCase();
    const decision = await this.getFingerprintAcceptance(null, fingerprint);
    if (decision == "rejected") {
      return false;
    }
    let conn;
    try {
      conn = await this.openDatabase();
      const rows = await conn.execute(
        "select count(*) as hits from personal_key where fpr = :fpr",
        { fpr: fingerprint }
      );
      const hits = rows.length ? rows[0].getResultByName("hits") : 0;
      await conn.close();
      return hits > 0;
    } catch (ex) {
      if (conn) {
        await conn.close();
      }
      throw ex;
    }
  },
};

/**
 * Use a promise to open the OpenPGP database.
 *
 * It's possible that there will be an NS_ERROR_STORAGE_BUSY
 * so we're willing to retry for a little while.
 *
 * @param {string} filename - Path of the sqlite database.
 * @param {Function} resolve - Function to call when promise succeeds.
 * @param {Function} reject - Function to call when promise fails.
 * @param {integer} waitms - Number of milliseconds to wait before trying again
 *   in case of NS_ERROR_STORAGE_BUSY.
 * @param {integer} maxtime - Unix epoch (in milliseconds) of the point at
 *   which we should give up.
 */
function openDatabaseConn(filename, resolve, reject, waitms, maxtime) {
  lazy.Sqlite.openConnection({
    path: filename,
    sharedMemoryCache: false,
  })
    .then(connection => {
      resolve(connection);
    })
    .catch(error => {
      const now = Date.now();
      if (now > maxtime) {
        reject(error);
        return;
      }
      lazy.setTimeout(function () {
        openDatabaseConn(filename, resolve, reject, waitms, maxtime);
      }, waitms);
    });
}

/** @param {OpenedConnection} connection */
async function checkAcceptanceTable(connection) {
  const exists = await connection.tableExists("acceptance_email");
  const exists2 = await connection.tableExists("acceptance_decision");
  if (!exists || !exists2) {
    await createAcceptanceTable(connection);
  }
  await ensurePersonalKeyTable(connection);
}

/**
 * Adds `personal_key` to a profile that predates it, and moves the markers
 * that used to be stored as a decision.
 *
 * The move is a copy then a delete, in one transaction: until the new table
 * exists a `personal` decision is how a key was marked as the user's own, and
 * afterwards that word in `acceptance_decision` means nothing. Running it
 * twice is harmless -- the insert is `or ignore`, and the second run finds no
 * `personal` rows to move.
 *
 * @param {OpenedConnection} connection
 */
async function ensurePersonalKeyTable(connection) {
  if (await connection.tableExists("personal_key")) {
    return;
  }
  await createPersonalKeyTable(connection);
  await connection.execute("begin transaction");
  try {
    await connection.execute(
      "insert or ignore into personal_key (fpr)" +
        " select fpr from acceptance_decision where decision = 'personal'"
    );
    await connection.execute(
      "delete from acceptance_decision where decision = 'personal'"
    );
    await connection.execute("commit transaction");
  } catch (ex) {
    await connection.execute("rollback transaction");
    throw ex;
  }
}

/** @param {OpenedConnection} connection */
async function createPersonalKeyTable(connection) {
  await connection.execute(
    "create table personal_key (fpr text not null, unique(fpr));"
  );
  await connection.execute(
    "create unique index personal_key_i1 on personal_key(fpr);"
  );
}

/** @param {OpenedConnection} connection */
async function createAcceptanceTable(connection) {
  await connection.execute(
    "create table acceptance_email (" +
      "fpr text not null, " +
      "email text not null, " +
      "unique(fpr, email));"
  );

  await connection.execute(
    "create table acceptance_decision (" +
      "fpr text not null, " +
      "decision text not null, " +
      "unique(fpr));"
  );

  await connection.execute(
    "create unique index acceptance_email_i1 on acceptance_email(fpr, email);"
  );

  await connection.execute(
    "create unique index acceptance__decision_i1 on acceptance_decision(fpr);"
  );

  await createPersonalKeyTable(connection);
}
