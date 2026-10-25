/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Clearing the GnuPG passphrase cache.
 *
 * When a key in the external GnuPG keyring is used, the passphrase is never
 * seen by Thunderbird: gpg asks pinentry through gpg-agent, and the unlocked
 * passphrase is held in the agent's memory for as long as its cache settings
 * allow (default-cache-ttl and max-cache-ttl in gpg-agent.conf). Thunderbird
 * therefore has nothing of its own to forget, and the only way to drop that
 * cache is to tell the agent to.
 *
 * Enigmail's "forget passphrase" did the same thing with RELOADAGENT; this
 * module uses the two mechanisms gpg provides for the purpose and reports
 * which one it used, because "nothing happened" is not distinguishable from
 * "it worked" by looking at the UI afterwards.
 */

const lazy = {};

ChromeUtils.defineESModuleGetters(lazy, {
  Subprocess: "resource://gre/modules/Subprocess.sys.mjs",
});

export var GnuPGAgent = {
  /**
   * Run one gpg helper and return { ok, output }.
   *
   * Both streams must be piped explicitly, and both must be read the way
   * `InputPipe` actually behaves. `Subprocess.call` defaults `stderr` to
   * "ignore", so an option that is not named is not a pipe and there is nothing
   * to read; and `read()` resolves to an ArrayBuffer, so a loop written against
   * `{value}` reads nothing even when the pipe exists. Both faults were present
   * in the first version of this method, and together they made every query
   * return an empty string that looked like a property of xpcshell.
   *
   * @param {string} command - Executable name, looked up on PATH.
   * @param {string[]} args - Arguments.
   * @param {string} [stdin] - Text to write to the child's standard input.
   *   Omitted means the child gets none, which is what every read-only query
   *   wants: a gpg that decides to prompt must not find a pipe to prompt on.
   * @returns {Promise<object>} { ok, output } where output is stdout+stderr.
   */
  async _run(command, args, stdin) {
    let path;
    try {
      path = await lazy.Subprocess.pathSearch(command);
    } catch (ex) {
      return { ok: false, output: `${command} not found` };
    }

    // GNUPGHOME is forwarded explicitly. libgpgme resolves the keyring from
    // the process environment, and a child spawned here does not necessarily
    // see an environment this process changed after startup -- under
    // xpcshell it does not, so every query silently read the wrong keyring.
    // Forwarding it keeps the gpg executable and gpgme answering about the
    // same keyring, which is the only way their answers can be compared.
    const environment = { environmentAppend: true };
    if (Services.env.exists("GNUPGHOME")) {
      environment.environment = { GNUPGHOME: Services.env.get("GNUPGHOME") };
    }

    try {
      const proc = await lazy.Subprocess.call({
        command: path,
        arguments: args,
        stdin: stdin === undefined ? "ignore" : "pipe",
        stdout: "pipe",
        stderr: "pipe",
        environment: environment.environment,
        environmentAppend: environment.environmentAppend,
      });

      if (stdin !== undefined) {
        proc.stdin.write(stdin);
        await proc.stdin.close();
      }

      let output = "";
      const decoder = new TextDecoder();
      // `InputPipe.read()` resolves to an ArrayBuffer and an empty one at end
      // of file -- it does not resolve to `{value}`. The first version of this
      // loop read `chunk.value` and therefore never appended anything, which
      // is why every query here returned no output at all and why that was
      // misread as an xpcshell limitation.
      const read = async stream => {
        if (!stream) {
          return;
        }
        for (;;) {
          const buffer = await stream.read();
          if (!buffer || buffer.byteLength === 0) {
            return;
          }
          output += decoder.decode(buffer, { stream: true });
        }
      };
      await Promise.all([read(proc.stdout), read(proc.stderr)]);
      const { exitCode } = await proc.wait();
      return { ok: exitCode === 0, output: output.trim() };
    } catch (ex) {
      return { ok: false, output: String(ex) };
    }
  },

  /**
   * Record what the user declares about a key GnuPG holds.
   *
   * Trust for a keyring key is gpg's own database, so this drives gpg rather
   * than keeping a second copy: a value stored anywhere else would disagree
   * with the engine that actually computes validity, and the disagreement
   * would show as a key gpg refuses to use while Thunderbird says it is
   * trusted.
   *
   * `gpg --import-ownertrust` takes lines of `fingerprint:level:` on a scale
   * that starts one above gpgme's: it has `undefined` at 2, `never` at 3,
   * `marginal` at 4, `full` at 5 and `ultimate` at 6. gpgme reports the same
   * states as 1 to 5, with an extra `unknown` at 0.
   *
   * **The offset is one, not two, and gpgme's 0 has no equivalent on the
   * write side.** `--import-ownertrust` cannot express "unknown" -- an absent
   * entry is what that means -- so `OpenPgpValidity.UNKNOWN` is refused here
   * rather than written as `undefined`. They are not the same state: one is a
   * key nobody has looked at, the other is a key the user deliberately left
   * undecided, and writing the second when the user asked for the first would
   * record a decision they did not make.
   *
   * Both numbers were measured rather than taken from documentation: setting
   * each value and reading gpg's own listing back gives `q`, `n`, `m`, `f`
   * and `u` for 2 to 6.
   *
   * @param {string} fingerprint - Primary key fingerprint.
   * @param {integer} validity - One of `OpenPgpValidity`.
   * @returns {Promise<object>} { ok, output }. `ok` false means gpg refused;
   *   the caller must report that rather than assume the write landed.
   */
  async setOwnerTrust(fingerprint, validity) {
    const fpr = String(fingerprint || "")
      .replace(/^0x/i, "")
      .toUpperCase();
    if (!fpr) {
      return { ok: false, output: "no fingerprint" };
    }

    // gpgme's UNDEFINED is 1 and gpg's import scale starts at 2, so every
    // level that exists is written one higher. UNKNOWN (0) is absent on
    // purpose: gpg has no ownertrust value for "nobody has looked at this".
    const GPG_OWNERTRUST_OFFSET = 1;
    const settable = new Set([1, 2, 3, 4, 5]);
    if (!settable.has(validity)) {
      return {
        ok: false,
        output:
          `owner trust ${validity} cannot be written: gpg's ownertrust ` +
          `scale has no value for it`,
      };
    }

    const record = `${fpr}:${validity + GPG_OWNERTRUST_OFFSET}:\n`;
    const result = await this._run(
      "gpg",
      ["--batch", "--no-tty", "--yes", "--import-ownertrust"],
      record
    );
    return { ok: result.ok, output: result.output };
  },

  /**
   * Import a key block into the external GnuPG keyring.
   *
   * Used by the migration in Item 20, and deliberately the only write this
   * module performs. `gpg --import` is used rather than GPGME's importer for a
   * reason that matters to the caller: its exit status distinguishes "the key
   * is now there" from "nothing changed", and the migration has to know which
   * before it offers to delete anything.
   *
   * @param {string} keyBlock - ASCII armored key block, already protected.
   * @returns {Promise<object>} { ok, output }.
   */
  async importKeyBlock(keyBlock) {
    let tmpPath;
    try {
      // gpg reads stdin happily, but Subprocess here cannot write to it while
      // also draining stdout without a deadlock risk on large blocks, so the
      // block goes through a temporary file in the profile directory.
      const dir = Services.dirsvc.get("ProfD", Ci.nsIFile);
      dir.append("openpgp-migration");
      await IOUtils.makeDirectory(dir.path, { ignoreExisting: true });
      const file = dir.clone();
      file.append("import.asc");
      await IOUtils.writeUTF8(file.path, keyBlock);
      tmpPath = file.path;

      return await this._run("gpg", ["--batch", "--import", tmpPath]);
    } finally {
      if (tmpPath) {
        await IOUtils.remove(tmpPath, { ignoreAbsent: true });
      }
    }
  },

  /**
   * Whether GnuPG holds a secret key for a fingerprint.
   *
   * Asks gpg rather than trusting the import's exit status alone: an import
   * can succeed while the key it carried was already present, and the
   * migration's next step is destructive.
   *
   * **Decided on gpg's exit status, not by parsing its output.** `gpg
   * --list-secret-keys <fpr>` exits 0 when the key is there and 2 when it is
   * not -- measured, not assumed -- and that answer does not depend on this
   * module reading a stream. It first parsed the colon listing and every query
   * reported "not held"; that was blamed on xpcshell and was not xpcshell. `_run`
   * was asking for no pipes and reading the pipe's answer as though it were a
   * `{value}` object, so there was no output to parse anywhere. The exit status
   * is kept as the narrower thing to depend on, and both capture faults are
   * fixed in `_run` because the colon listing is what other callers need.
   *
   * @param {string} fingerprint - Fingerprint, with or without "0x".
   * @returns {Promise<boolean>} True if the secret key is in the keyring.
   */
  async hasSecretKey(fingerprint) {
    const wanted = fingerprint.replace(/^0x/i, "").toUpperCase();
    if (!wanted) {
      return false;
    }
    const result = await this._run("gpg", [
      "--batch",
      "--list-secret-keys",
      wanted,
    ]);
    return result.ok;
  },

  /**
   * Read the value of an option from gpg's own configuration.
   *
   * `gpgconf --list-options gpg` prints one line per option, colon separated,
   * with the configured value last. Reading it here means a preference the
   * user set in gpg.conf is applied by us instead of being overwritten by our
   * own idea of which key should be used.
   *
   * @param {string} name - Option name, for example "default-key".
   * @returns {Promise<string>} The configured value, or "" when unset.
   */
  async configuredOption(name) {
    const result = await this._run("gpgconf", ["--list-options", "gpg"]);
    if (!result.ok) {
      return "";
    }
    for (const line of result.output.split("\n")) {
      if (!line.startsWith(`${name}:`)) {
        continue;
      }
      // The value is the last field and is quoted when it is non-empty.
      const fields = line.split(":");
      const value = fields[fields.length - 1] ?? "";
      return value.replace(/^"|"$/g, "");
    }
    return "";
  },

  /**
   * Read one option from gpg-agent's own configuration.
   *
   * A separate call from `configuredOption`, which reads gpg's file: the cache
   * timeouts live in the agent's, and the two are different programs with
   * different option sets. Same output shape, so the parsing is shared.
   *
   * @param {string} name - Option name, for example "default-cache-ttl".
   * @returns {Promise<string>} The configured value, or "" when unset.
   */
  async configuredAgentOption(name) {
    const result = await this._run("gpgconf", ["--list-options", "gpg-agent"]);
    if (!result.ok) {
      return "";
    }
    for (const line of result.output.split("\n")) {
      if (!line.startsWith(`${name}:`)) {
        continue;
      }
      const fields = line.split(":");
      return (fields[fields.length - 1] ?? "").replace(/^"|"$/g, "");
    }
    return "";
  },

  /**
   * How long gpg-agent keeps a passphrase, in seconds.
   *
   * Read from the agent rather than assumed, because these are per-machine
   * settings and a user who has changed them should be told their own numbers.
   * The distinction between the two is the point of reporting both: the timer
   * resets on each use until the maximum is reached, so a passphrase can sit
   * in memory for far longer than the first figure suggests.
   *
   * Returns nulls when the agent cannot be asked. A caller must then say
   * nothing rather than inventing a duration -- a wrong number here would be
   * worse than no number, because it is the number a user would rely on.
   *
   * @returns {Promise<{idle: ?number, maximum: ?number}>} Seconds, or nulls.
   */
  async cacheTimeouts() {
    const toSeconds = value => {
      const n = Number.parseInt(value, 10);
      return Number.isFinite(n) && n > 0 ? n : null;
    };
    const [idle, maximum] = await Promise.all([
      this.configuredAgentOption("default-cache-ttl"),
      this.configuredAgentOption("max-cache-ttl"),
    ]);
    return { idle: toSeconds(idle), maximum: toSeconds(maximum) };
  },

  /**
   * The key gpg has been configured to sign with, when the user has set one.
   *
   * @returns {Promise<string>} The `default-key` value, or "".
   */
  async configuredDefaultKey() {
    return this.configuredOption("default-key");
  },

  /**
   * Ask gpg which secret keys it holds for a pattern, in gpg's own order.
   *
   * The order is the answer, not an implementation detail: `--local-user`
   * resolves an identity to the first match in exactly this listing, so a
   * caller that keeps this order is applying gpg's rule instead of inventing
   * one. Every state that decides usability (revoked, expired, invalid,
   * disabled) is read from the same output rather than being judged here.
   *
   * The capability string carries the disabled marker: gpg appends `D` to it
   * for a disabled key (`scESC` becomes `scESCD`), measured on gpg 2.4.4, and
   * the validity field is left untouched by disabling -- so the flag is the
   * only place that state appears.
   *
   * @param {string} pattern - An email address, key id, fingerprint, or user id.
   * @returns {Promise<object[]>} One record per key: { keyId, fpr, validity,
   *   capabilities, uids: [{ validity, uid, email }], subkeys: [{ keyId, fpr,
   *   capabilities, validity }] }. Empty when gpg has none or cannot be run.
   */
  async listSecretKeys(pattern) {
    const args = ["--batch", "--with-colons", "--list-secret-keys"];
    if (pattern) {
      args.push(pattern);
    }
    const result = await this._run("gpg", args);
    // gpg exits 2 when the pattern matches nothing, which is an answer and
    // not a failure, so the output is parsed either way.
    return this._parseSecretKeyListing(result.output);
  },

  /**
   * Turn `gpg --with-colons --list-secret-keys` output into key records.
   *
   * @param {string} output - The colon listing.
   * @returns {object[]} Key records, in the order gpg printed them.
   */
  _parseSecretKeyListing(output) {
    const keys = [];
    let current = null;

    for (const line of String(output || "").split("\n")) {
      if (!line) {
        continue;
      }
      const f = line.split(":");
      const type = f[0];

      if (type == "sec") {
        current = {
          keyId: f[4] || "",
          fpr: "",
          validity: f[1] || "",
          capabilities: f[11] || "",
          uids: [],
          subkeys: [],
        };
        keys.push(current);
        continue;
      }
      if (!current) {
        continue;
      }

      if (type == "fpr") {
        const fpr = f[9] || "";
        if (!current.fpr) {
          current.fpr = fpr;
        } else if (current.subkeys.length) {
          current.subkeys[current.subkeys.length - 1].fpr = fpr;
        }
      } else if (type == "ssb") {
        current.subkeys.push({
          keyId: f[4] || "",
          fpr: "",
          validity: f[1] || "",
          capabilities: f[11] || "",
        });
      } else if (type == "uid") {
        const uid = this._unescapeColonField(f[9] || "");
        current.uids.push({
          validity: f[1] || "",
          uid,
          email: this._emailFromUid(uid),
        });
      }
    }

    return keys;
  },

  /**
   * Undo the escapes gpg applies to field text in a colon listing.
   *
   * @param {string} text - A field from the listing.
   * @returns {string} The text as gpg holds it.
   */
  _unescapeColonField(text) {
    return text
      .replace(/\\x3a/gi, ":")
      .replace(/\\e/g, "\\")
      .replace(/\\n/g, "\n");
  },

  /**
   * The address in a user id, when the user id carries one.
   *
   * @param {string} uid - A user id, for example "Name <name@example.com>".
   * @returns {string} The address in lower case, or "".
   */
  _emailFromUid(uid) {
    const match = /<([^<>]+)>\s*$/.exec(uid);
    return match ? match[1].trim().toLowerCase() : "";
  },

  /**
   * Drop every passphrase gpg-agent has cached.
   *
   * `gpgconf --kill gpg-agent` is tried first: it terminates the agent, which
   * discards the cache outright rather than relying on the agent to honour a
   * reload request. The agent is restarted automatically the next time gpg
   * needs it, so nothing is left broken. If gpgconf is unavailable, the
   * RELOADAGENT request is sent instead.
   *
   * @returns {Promise<object>} { ok, method, detail } describing what was done.
   */
  async forgetCachedPassphrases() {
    const killed = await this._run("gpgconf", ["--kill", "gpg-agent"]);
    if (killed.ok) {
      return { ok: true, method: "gpgconf", detail: killed.output };
    }

    const reloaded = await this._run("gpg-connect-agent", [
      "RELOADAGENT",
      "/bye",
    ]);
    if (reloaded.ok) {
      return { ok: true, method: "gpg-connect-agent", detail: reloaded.output };
    }

    return {
      ok: false,
      method: "none",
      detail: killed.output || reloaded.output,
    };
  },
};
