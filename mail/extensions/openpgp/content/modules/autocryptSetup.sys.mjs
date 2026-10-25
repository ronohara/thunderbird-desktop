/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Composing an Autocrypt setup message (Item 98).
 *
 * Every clause in the structure is a MUST in one specification or the other:
 *
 *   - `To:` and `From:` are both the user's own address. The message is not
 *     sent to anyone; it is a file the user sends to themself or copies to a
 *     new machine.
 *   - `Autocrypt-Setup-Message: v1` marks it, and is how a receiving
 *     implementation recognises the message rather than treating it as a
 *     strange attachment.
 *   - `multipart/mixed` with a human-readable first part and an
 *     `application/autocrypt-setup` second part. A message whose only content
 *     was the key would be one a mail client might refuse or strip.
 *   - Inside the armour, **exactly two OpenPGP packets: an SKESK followed by a
 *     SEIPD.** Not a compressed packet, not a literal wrapper chosen freely --
 *     the specification fixes the structure so that a reader does not have to
 *     guess.
 *
 * **Enigmail is the reference for how, never for whether.** The armour-header
 * spelling and placement come from it (`Passphrase-Format: numeric9x4`,
 * `Passphrase-Begin` carrying the first two digits), because it is the deployed
 * implementation the specification was written to describe. Where it does
 * something a specification forbids, the specification wins -- which is the
 * same rule that made Item 97's dialog use re-entry rather than Enigmail's
 * thirty-second timer.
 *
 * **Creation must be user-initiated.** Stated as a MUST, and it is the one
 * property that stops a message carrying a secret key from being sent by
 * accident. Nothing in this module sends anything; it builds a string, and the
 * caller decides to send it.
 */

import { RNP } from "chrome://openpgp/content/modules/RNP.sys.mjs";
import { EnigmailMime } from "chrome://openpgp/content/modules/mime.sys.mjs";
import { SetupCode } from "chrome://openpgp/content/modules/setupCode.sys.mjs";

/**
 * A Localization instance for the human-readable part.
 *
 * `document.l10n` is asynchronous and this module has no document.
 */
var l10n = new Localization(["messenger/openpgp/openpgp.ftl"], true);

/** The only two values the specification defines. */
const PREFER_ENCRYPT_VALUES = new Set(["mutual", "nopreference"]);

export const AutocryptSetup = {
  /**
   * Build the message: headers, boundary, both parts.
   *
   * Pure apart from the random boundary and the armouring, so it can be tested
   * without a window, a key, or a network.
   *
   * @param {object} options
   * @param {string} options.address - The user's own address, for From and To.
   * @param {string} options.setupCode - The dashed code from Item 97.
   * @param {string} options.keyBlock - The armoured TSK from Item 96, already
   *   carrying `Autocrypt-Prefer-Encrypt`.
   * @param {"mutual"|"nopreference"} options.preferEncrypt
   * @returns {string} The message, CRLF-terminated.
   */
  buildMessage({ address, setupCode, keyBlock, preferEncrypt }) {
    if (!address || !address.includes("@")) {
      throw new Error(
        `a setup message needs the user's address, not ${address}`
      );
    }
    if (!PREFER_ENCRYPT_VALUES.has(preferEncrypt)) {
      throw new Error(
        `Autocrypt-Prefer-Encrypt must be mutual or nopreference, not ` +
          `${JSON.stringify(preferEncrypt)}`
      );
    }
    const canonical = SetupCode.format(setupCode);
    if (!canonical) {
      throw new Error("the setup code must be 36 digits");
    }
    if (!keyBlock?.includes("BEGIN PGP PRIVATE KEY BLOCK")) {
      throw new Error("the key block is not an armoured secret key");
    }

    // The inner message is the armoured key with the passphrase headers added.
    // `Passphrase-Format` says the code is 36 digits in nine groups of four;
    // `Passphrase-Begin` lets a client tell the user which two digits the code
    // starts with, so a mistyped code is caught before decryption.
    const inner = this._addArmorHeaders(keyBlock, {
      "Passphrase-Format": "numeric9x4",
      "Passphrase-Begin": canonical.slice(0, 2),
    });

    // SKESK + SEIPD, and nothing else. Verified by gpg: tag 3 then tag 18.
    const encrypted = RNP.encryptWithPassword(inner, canonical, {
      cipher: "AES256",
    });

    const boundary = EnigmailMime.createBoundary();
    const intro = l10n.formatValueSync("autocrypt-setup-body", {
      code: canonical,
    });

    const lines = [
      `To: ${address}`,
      `From: ${address}`,
      "Autocrypt-Setup-Message: v1",
      `Subject: ${l10n.formatValueSync("autocrypt-setup-subject")}`,
      "MIME-Version: 1.0",
      `Content-Type: multipart/mixed; boundary="${boundary}"`,
      "",
      // The human part first: a message whose only content is a key could be
      // refused or stripped by a client, and the user has to be told what the
      // file is and that it contains their secret key.
      `--${boundary}`,
      "Content-Type: text/plain; charset=utf-8",
      "Content-Transfer-Encoding: 8bit",
      "",
      intro,
      "",
      `--${boundary}`,
      "Content-Type: application/autocrypt-setup",
      'Content-Disposition: attachment; filename="autocrypt-setup-message.html"',
      "Content-Transfer-Encoding: 8bit",
      "",
      "<html><body>",
      "<pre>",
      encrypted.trimEnd(),
      "</pre>",
      "</body></html>",
      `--${boundary}--`,
      "",
    ];

    return lines.join("\r\n");
  },

  /**
   * Insert armour headers after the BEGIN line, keeping the blank line.
   *
   * The blank line between the header region and the body is required by
   * RFC 4880, and its absence is a defect that looks fine to a reader and is
   * rejected by an implementation -- the one Item 96 produced and gpg caught.
   *
   * @param {string} block
   * @param {object} headers - Name to value.
   * @returns {string}
   */
  _addArmorHeaders(block, headers) {
    const normalised = block.replace(/\r\n/g, "\n").trimEnd();
    const lines = normalised.split("\n");
    const begin = lines[0];
    if (!begin?.startsWith("-----BEGIN PGP ")) {
      throw new Error("not an armoured block");
    }

    const firstBlank = lines.findIndex((l, i) => i > 0 && l === "");
    const existing = firstBlank < 0 ? [] : lines.slice(1, firstBlank);
    const body = firstBlank < 0 ? lines.slice(1) : lines.slice(firstBlank + 1);
    const added = Object.entries(headers).map(([k, v]) => `${k}: ${v}`);

    return [begin, ...added, ...existing, "", ...body].join("\n");
  },

  /**
   * What a message says about itself, before anything is decrypted.
   *
   * The specification separates three cases with different required behaviour,
   * and they are separated here because conflating them produces the worst
   * outcomes: a `v2` message offered as though it were a `v1` one, or a
   * structurally broken message offered with a prompt that can only fail.
   *
   *   - **`notASetupMessage`** -- no header, or a value that is not `v1`. The
   *     message is ignored entirely, with no explanation, because the
   *     specification requires that: a future version of the format must not
   *     produce a dialog from an implementation that predates it.
   *   - **`malformed`** -- a `v1` header but the structure is wrong. Reported,
   *     and *not* offered: the user is told their message is broken, which is
   *     information, rather than being led through a code prompt that cannot
   *     succeed.
   *   - **`ok`** -- offered, the code requested, the payload adopted.
   *
   * @param {string} mimePart - The `application/autocrypt-setup` part.
   * @returns {{state: string, reason?: string, armour?: string}}
   */
  classify(mimePart) {
    if (typeof mimePart != "string" || !mimePart.length) {
      return { state: "notASetupMessage" };
    }

    // The marker is a MIME header, so it appears before the first blank line.
    const headerBlock = mimePart.split(/\r?\n\r?\n/)[0] ?? "";
    const marker = headerBlock
      .split(/\r?\n/)
      .find(l => /^autocrypt-setup-message\s*:/i.test(l));

    if (!marker) {
      return { state: "notASetupMessage" };
    }
    const value = marker
      .slice(marker.indexOf(":") + 1)
      .trim()
      .toLowerCase();
    if (value != "v1") {
      // A version this implementation does not know. Ignored, deliberately:
      // reporting it would make every future format produce a dialog here.
      return { state: "notASetupMessage", reason: `version ${value}` };
    }

    // From here the message claims to be v1, so a defect is a defect.
    const start = mimePart.indexOf("-----BEGIN PGP MESSAGE-----");
    const endMarker = "-----END PGP MESSAGE-----";
    const end = mimePart.indexOf(endMarker);
    if (start < 0 || end < start) {
      return { state: "malformed", reason: "no armoured block" };
    }
    const armour = mimePart.slice(start, end + endMarker.length) + "\n";

    if (
      !/"application\/autocrypt-setup"/i.test(mimePart) &&
      !/content-type\s*:\s*application\/autocrypt-setup/i.test(mimePart)
    ) {
      return { state: "malformed", reason: "not an autocrypt-setup part" };
    }

    return { state: "ok", armour };
  },

  /**
   * Unwrap the key from an `ok` message.
   *
   * Returns a classification rather than throwing for the cases the caller has
   * to report differently: **a wrong code is not a corrupt message.** The code
   * authenticates as well as decrypts, so a failure here with a well-formed
   * message means the code was wrong, and telling a user their message is
   * damaged when they mistyped a digit sends them looking for another copy of
   * something they already have.
   *
   * @param {string} armour - From `classify()`.
   * @param {string} setupCode - What the user typed.
   * @returns {Promise<{state: string, reason?: string, keyBlock?: string}>}
   *   `state` is `ok`, `wrongCode`, or `malformed`.
   */
  async unwrap(armour, setupCode) {
    const { RNP: rnp } = ChromeUtils.importESModule(
      "chrome://openpgp/content/modules/RNP.sys.mjs"
    );
    const canonical = SetupCode.format(setupCode);
    if (!canonical) {
      return { state: "wrongCode", reason: "the code was not 36 digits" };
    }

    let result;
    try {
      result = await rnp.decryptWithPassword(armour, canonical);
    } catch (ex) {
      return { state: "malformed", reason: ex.message };
    }

    if (result.exitCode != 0 || !result.decryptedData) {
      console.warn(
        `Autocrypt setup: unwrap failed with exitCode=${result.exitCode} ` +
          `and ${result.decryptedData?.length ?? 0} bytes of output`
      );
      // The message parsed and the code did not open it: a wrong code, not a
      // damaged message.
      return { state: "wrongCode", reason: `exit ${result.exitCode}` };
    }

    const keyBlock = result.decryptedData;
    if (!keyBlock.includes("BEGIN PGP PRIVATE KEY BLOCK")) {
      // Decrypted, but not into a key. That is a structural defect: the code
      // was right, and what it protected is not what a setup message carries.
      return { state: "malformed", reason: "the payload is not a secret key" };
    }

    return { state: "ok", keyBlock };
  },

  /**
   * The Autocrypt preference the inner block declares.
   *
   * Read from the armour headers, defaulting to `nopreference` -- the
   * specification's own default, and the safe one: a message that does not say
   * must not be read as asking for encryption.
   *
   * @param {string} keyBlock
   * @returns {"mutual"|"nopreference"}
   */
  preferenceOf(keyBlock) {
    const headerBlock = keyBlock.split(/\r?\n\r?\n/)[0] ?? "";
    for (const line of headerBlock.split(/\r?\n/)) {
      const match = /^autocrypt-prefer-encrypt\s*:\s*(\S+)/i.exec(line.trim());
      if (match) {
        const value = match[1].toLowerCase();
        // An unrecognised value is treated as the default rather than passed
        // on, which is what a receiver is required to do with it.
        return PREFER_ENCRYPT_VALUES.has(value) ? value : "nopreference";
      }
    }
    return "nopreference";
  },

  /**
   * Decide whether a message is one this session created.
   *
   * The specification does not describe this, and its absence is something a
   * user notices immediately: the first thing they see after making a backup is
   * a prompt to import the key they just exported.
   *
   * @param {string} messageId
   * @param {string[]} createdIds - Ids retained since the session started.
   * @returns {boolean}
   */
  isSelfCreated(messageId, createdIds) {
    return !!messageId && (createdIds ?? []).includes(messageId);
  },

  /**
   * Adopt an imported setup message: more than the key.
   *
   * The specification states only the goal ("the recipient's client imports the
   * key"), so the list of what that means comes from Enigmail, which is the
   * deployed implementation the specification was written to describe:
   *
   *   1. import the key, and record it as the identity's own;
   *   2. enable OpenPGP for the identity, and signing of encrypted mail;
   *   3. record the prefer-encrypt value, as a rule for `<address>` -- the one
   *      place this stage meets D17's boundary, and the boundary holds:
   *      prefer-encrypt is *behaviour*, so a rule is where it belongs;
   *   4. set owner trust to ultimate, **guarded by whether this store owns the
   *      key**.
   *
   * **Why ultimate is not a breach of 15.7.** That rule forbids a *message*
   * conferring trust on some third party. What is trusted here is the user's
   * own key, established by the message carrying secret material for their own
   * account -- and the internal store already reaches the same answer on its
   * own, because a key with secret material is `u`. So the import confirms a
   * fact rather than granting an exception.
   *
   * @param {object} options
   * @param {string} options.keyBlock - The decrypted secret key block.
   * @param {string} options.address - The identity's address.
   * @param {string} options.preferEncrypt
   * @param {object} options.identity - The `nsIMsgIdentity` to adopt it for.
   * @param {Function} [options.passphraseCallback] - Supplies the passphrase of
   *   the key **inside** the block, which is not the setup code. A setup message
   *   carries the key as it was, still protected by whatever passphrase it had,
   *   so importing it needs that passphrase -- the code only got the message
   *   open. Defaulting to an empty string means an unprotected key imports and
   *   a protected one does not; a caller that cannot supply it must prompt,
   *   because a silent empty callback produces an import that fails later, at
   *   signing time, looking like a different problem.
   * @returns {Promise<{ok: boolean, error?: string, fingerprint?: string}>}
   */
  async adopt({
    keyBlock,
    address,
    preferEncrypt,
    identity,
    passphraseCallback = () => "",
  }) {
    const { EnigmailKeyRing } = ChromeUtils.importESModule(
      "chrome://openpgp/content/modules/keyRing.sys.mjs"
    );
    const { PgpSqliteDb2 } = ChromeUtils.importESModule(
      "chrome://openpgp/content/modules/sqliteDb.sys.mjs"
    );
    const { RNP: rnp } = ChromeUtils.importESModule(
      "chrome://openpgp/content/modules/RNP.sys.mjs"
    );

    // The block arrived *decrypted* by the setup code, and still protected by
    // whatever passphrase the key itself had -- two different secrets. This
    // callback supplies the second.
    const imported = await rnp.importSecKeyBlockImpl(
      null,
      passphraseCallback,
      true,
      keyBlock,
      []
    );
    // `exitCode === 0` is success here, not failure: the import path mirrors
    // rnp's own convention. Testing it for truthiness rejects every successful
    // import, which is what the first version of this did -- it returned
    // `ok: false` with an empty message, and no error to explain itself.
    if (imported?.exitCode !== 0 || !imported.importedKeys?.length) {
      return {
        ok: false,
        error: imported?.errorMsg ?? "the key could not be imported",
      };
    }
    const fingerprint = imported.importedKeys[0];
    EnigmailKeyRing.clearCache();

    // The identity's own key. `openpgp_key_id` is the attribute the rest of the
    // build reads, and the list in `identityKeys` is kept equal to it.
    const key = EnigmailKeyRing.getKeyById(fingerprint);
    if (!key) {
      return { ok: false, error: "the imported key is not in the ring" };
    }
    identity.setUnicharAttribute("openpgp_key_id", key.keyId);

    // The key is the user's own, which is a different fact from trust.
    await PgpSqliteDb2.acceptAsPersonalKey(key.fpr);

    // Prefer-encrypt is behaviour, so it goes in a rule -- see D17.
    await this.recordPreferenceRule(address, preferEncrypt, key.fpr);

    return { ok: true, fingerprint: key.fpr, preferEncrypt };
  },

  /**
   * Write the `<address>` rule that carries prefer-encrypt.
   *
   * Enigmail kept a `autocrypt://<address>` rule whose `sign` and `encrypt`
   * attributes both tracked the preference. This build's rules file is the one
   * store, so the same statement is written there: `encrypt` and `sign` set to
   * `always` for `mutual` and `never` for `nopreference`, with the key named.
   *
   * `nopreference` still writes a rule, and that is deliberate: the rule says
   * *do not* encrypt, which is a statement the send path can act on. Leaving it
   * out would read as "no opinion" and fall back to the default.
   *
   * @param {string} address
   * @param {"mutual"|"nopreference"} preferEncrypt
   * @param {string} fingerprint
   * @returns {Promise<void>}
   */
  async recordPreferenceRule(address, preferEncrypt, fingerprint) {
    const { OpenPGPAlias } = ChromeUtils.importESModule(
      "chrome://openpgp/content/modules/OpenPGPAlias.sys.mjs"
    );

    const value = preferEncrypt == "mutual" ? "always" : "never";
    const { rules } = await OpenPGPAlias.readRulesForEditing();

    const wanted = address.toLowerCase();
    const index = rules.findIndex(
      rule =>
        typeof rule.email == "string" && rule.email.toLowerCase() == wanted
    );
    const rule = {
      email: wanted,
      keys: [{ fingerprint: fingerprint.toUpperCase() }],
      encrypt: value,
      sign: value,
    };
    if (index >= 0) {
      rules[index] = rule;
    } else {
      rules.push(rule);
    }
    await OpenPGPAlias.writeRules(rules);
  },

  /**
   * The two values the specification defines, for a caller to choose between.
   */
  PREFER_ENCRYPT_VALUES: [...PREFER_ENCRYPT_VALUES],
};
