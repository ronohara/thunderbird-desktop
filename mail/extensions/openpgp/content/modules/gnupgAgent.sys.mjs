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
   * @param {string} command - Executable name, looked up on PATH.
   * @param {string[]} args - Arguments.
   * @returns {Promise<object>} { ok, output } where output is stdout+stderr.
   */
  async _run(command, args) {
    let path;
    try {
      path = await lazy.Subprocess.pathSearch(command);
    } catch (ex) {
      return { ok: false, output: `${command} not found` };
    }

    try {
      const proc = await lazy.Subprocess.call({
        command: path,
        arguments: args,
      });

      let output = "";
      const decoder = new TextDecoder();
      const read = async stream => {
        if (!stream) {
          return;
        }
        let chunk;
        while ((chunk = await stream.read()) && chunk.value) {
          output += decoder.decode(chunk.value, { stream: true });
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
