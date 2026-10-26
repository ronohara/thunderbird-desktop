/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * The Thunderbird OpenPGP Alias Keys feature is used for sending an encrypted
 * email using a public key that does not contain (or does not match) the email
 * address of a message recipient.
 *
 * For example, a correspondent might ask you to use a particular public key for
 * sending them encrypted email, but that public key doesn't contain their email
 * address.
 *
 * Another example is a company that might have published a single public key
 * for sending encrypted email to any employee of the company, and the public
 * key doesn't contain any email address. When receiving an email that was
 * encrypted with that key, the company might then decrypt the email, and then
 * forward the decrypted email to the intended recipient. While this isn't
 * complete End-To-End Encryption, at least the email will be encrypted while
 * passing through the public Internet, until it arrives at the company's email server.
 *
 * Usually, Thunderbird refuses to use a key with a mismatching email address.
 * By using the Alias Keys Feature, you can override Thunderbird's usual checks,
 * and tell Thunderbird to use a public key anyway.
 */

const lazy = {};
ChromeUtils.defineLazyGetter(lazy, "log", () => {
  return console.createInstance({
    prefix: "openpgp",
    maxLogLevel: "Warn",
    maxLogLevelPref: "openpgp.loglevel",
  });
});
/**
 * The three answers a rule can give for one setting, plus the state that
 * means two rules disagreed.
 *
 * These are not booleans, and the difference is the point of Item 89b: a
 * message has several recipients, two rules can contradict each other, and a
 * design that reduced each field to true or false would have to pick a winner.
 * Whichever it picked would be a policy applied to somebody the user did not
 * intend, so the contradiction is carried instead of resolved.
 *
 * The numbers match Enigmail's, whose `combineFlagValues()` resolved them the
 * same way -- 0 never, 1 maybe, 2 always, 3 conflict -- and the file keeps the
 * *words*, so a hand-edited file stays legible.
 */
export const RuleValue = {
  NEVER: 0,
  MAYBE: 1,
  ALWAYS: 2,
  CONFLICT: 3,
};

/** The words the file uses, and the value each maps to. */
const RULE_WORDS = new Map([
  ["never", RuleValue.NEVER],
  ["maybe", RuleValue.MAYBE],
  ["always", RuleValue.ALWAYS],
]);

export var OpenPGPAlias = {
  _aliasDomains: null,
  _aliasEmails: null,

  _loaded() {
    return this._aliasDomains && this._aliasEmails;
  },

  async load() {
    const path = Services.prefs.getStringPref(
      "mail.openpgp.alias_rules_file",
      ""
    );

    if (!path) {
      this._clear();
      return;
    }

    try {
      await this._loadFromFile(path);
    } catch (e) {
      lazy.log.warn(`Loading alias_rules_file from ${path} FAILED!`, e);
    }
  },

  _clear() {
    this._aliasDomains = new Map();
    this._aliasEmails = new Map();
  },

  _hasExpectedKeysStructure(keys) {
    try {
      for (const entry of keys) {
        if (!("id" in entry) && !("fingerprint" in entry)) {
          return false;
        }
      }
      // all entries passed the test
      return true;
    } catch (ex) {
      return false;
    }
  },

  /**
   * The file the rules live in, or the one they will live in once saved.
   *
   * The preference is empty by default -- the feature shipped with no file --
   * so an editor has to be able to answer "where would a new one go" without
   * guessing at read time. The answer is a fixed name in the profile, and the
   * preference is set to it on the first save. A fixed name rather than a file
   * picker: the user is editing recipient policy, not choosing where to put a
   * document, and a supplied path would let the two diverge.
   *
   * @returns {string} A filename inside the profile, or the configured
   *   `file://` URL when the preference holds one.
   */
  getRulesFile() {
    const configured = Services.prefs.getStringPref(
      "mail.openpgp.alias_rules_file",
      ""
    );
    return configured || "openpgp-rules.json";
  },

  /**
   * Resolve the rules file to a file:// URL.
   *
   * Same rule `_loadFromFile()` applies, kept in one place so the editor and
   * the loader cannot disagree about which file they mean.
   *
   * @param {string} src - From `getRulesFile()`.
   * @returns {string} A file:// URL.
   */
  _rulesFileURL(src) {
    if (src.startsWith("file://")) {
      return src;
    }
    if (src.includes("/") || src.includes("\\")) {
      throw new Error(`Invalid alias rules src: ${src}`);
    }
    const spec = PathUtils.join(
      Services.dirsvc.get("ProfD", Ci.nsIFile).path,
      src
    );
    return PathUtils.toFileURI(spec);
  },

  /**
   * Read the rules exactly as the file holds them, for an editor.
   *
   * Distinct from `load()` on purpose. `load()` builds the lookup maps and
   * silently drops what it cannot use, which is right for the send path and
   * wrong for an editor: a rule the user wrote and the build ignored is
   * precisely what they need to see. So this returns the entries as they are,
   * and reports why the file could not be read rather than logging it.
   *
   * @returns {Promise<object>} `{rules, error}`. `rules` is empty when the
   *   file does not exist yet, which is the normal first-run case and not an
   *   error.
   */
  async readRulesForEditing() {
    const src = this.getRulesFile();
    let url;
    try {
      url = this._rulesFileURL(src);
    } catch (ex) {
      return { rules: [], error: ex.message };
    }

    let jsonData;
    try {
      const response = await fetch(url);
      jsonData = await response.json();
    } catch (ex) {
      // A missing file is the first-run case. Anything else is reported.
      const exists = await IOUtils.exists(
        Services.io.newURI(url).QueryInterface(Ci.nsIFileURL).file.path
      );
      return exists
        ? { rules: [], error: `could not read ${src}: ${ex.message}` }
        : { rules: [], error: null };
    }

    return {
      rules: Array.isArray(jsonData.rules) ? jsonData.rules : [],
      error: null,
    };
  },

  /**
   * Write the rules back, and make the preference point at the file.
   *
   * The file stays the only store: this replaces its `rules` array rather than
   * merging into anything, so what the editor shows is what the send path
   * reads next time.
   *
   * @param {object[]} rules - Entries as they should be written.
   * @returns {Promise<object>} `{ok, error}`.
   */
  async writeRules(rules) {
    const src = this.getRulesFile();
    let path;
    try {
      path = Services.io
        .newURI(this._rulesFileURL(src))
        .QueryInterface(Ci.nsIFileURL).file.path;
    } catch (ex) {
      return { ok: false, error: ex.message };
    }

    try {
      await IOUtils.writeUTF8(path, JSON.stringify({ rules }, null, 2) + "\n");
    } catch (ex) {
      return { ok: false, error: `could not write ${src}: ${ex.message}` };
    }

    // Point the preference at the file the first time, so the loader and the
    // editor cannot end up using different names.
    if (!Services.prefs.getStringPref("mail.openpgp.alias_rules_file", "")) {
      Services.prefs.setStringPref("mail.openpgp.alias_rules_file", src);
    }

    await this.load();
    return { ok: true, error: null };
  },

  /**
   * Load alias rules from file.
   *
   * @param {string} src - Filename of json file in profile, or file:// URL.
   */
  async _loadFromFile(src) {
    this._clear();

    let jsonData;
    if (src.startsWith("file://")) {
      const response = await fetch(src);
      jsonData = await response.json();
    } else if (src.includes("/") || src.includes("\\")) {
      throw new Error(`Invalid alias rules src: ${src}`);
    } else {
      const spec = PathUtils.join(
        Services.dirsvc.get("ProfD", Ci.nsIFile).path,
        src
      );
      const response = await fetch(PathUtils.toFileURI(spec));
      jsonData = await response.json();
    }
    if (!("rules" in jsonData)) {
      throw new Error(
        "alias file contains invalid JSON data, no rules element found"
      );
    }
    const aliasRules = jsonData.rules;

    for (const entry of aliasRules) {
      // A rule may name no key. "Never encrypt to this address" is the rule a
      // cautious user most wants, and it needs no key at all; the settings it
      // carries are the whole of it. Only a malformed `keys` element is a
      // reason to skip -- a non-empty string, or an object, is a typo rather
      // than an absence, and reading it as a key list would fail later and
      // further away.
      if (
        "keys" in entry &&
        entry.keys !== null &&
        !Array.isArray(entry.keys)
      ) {
        lazy.log.warn("Ignoring alias rule with a malformed keys element");
        continue;
      }
      // A rule with no keys is a rule only if it says something. A bare entry
      // naming an address and nothing else -- no keys, no settings -- changes
      // nothing, and an existing test asserts exactly that: such an address
      // falls through to the normal lookup and finds its key. A keyless rule
      // that carries a setting is different: "never encrypt to this address"
      // is carried entirely by its settings, and is the reason Item 89a
      // exists.
      const normalized = this._normalizeRule(entry);
      const saysNothing =
        !normalized.keys.length &&
        normalized.encrypt === null &&
        normalized.sign === null &&
        normalized.pgpMime === null;
      if (saysNothing) {
        lazy.log.warn("Ignoring alias rule with neither keys nor settings");
        continue;
      }
      if ("email" in entry && "domain" in entry) {
        lazy.log.warn("Ignoring invalid alias rule with both email and domain");
        continue;
      }
      // Ignore duplicate rules, only use first rule per key.
      // Require email address contains @, and domain doesn't contain @.
      if ("email" in entry) {
        const email = entry.email.toLowerCase();
        if (!email.includes("@")) {
          lazy.log.warn("Ignoring invalid email alias rule: " + email);
          continue;
        }
        if (this._aliasEmails.get(email)) {
          lazy.log.warn("Ignoring duplicate email alias rule: " + email);
          continue;
        }
        if (
          normalized.keys.length &&
          !this._hasExpectedKeysStructure(normalized.keys)
        ) {
          lazy.log.warn(
            "Ignoring alias rule with invalid key entries for email " + email
          );
          continue;
        }
        this._aliasEmails.set(email, this._normalizeRule(entry));
      } else if ("domain" in entry) {
        const domain = entry.domain.toLowerCase();
        if (domain.includes("@")) {
          lazy.log.warn("Ignoring invalid domain alias rule: " + domain);
          continue;
        }
        if (this._aliasDomains.get(domain)) {
          lazy.log.warn("Ignoring duplicate domain alias rule: " + domain);
          continue;
        }
        if (
          normalized.keys.length &&
          !this._hasExpectedKeysStructure(normalized.keys)
        ) {
          lazy.log.warn(
            "Ignoring alias rule with invalid key entries for domain " + domain
          );
          continue;
        }
        this._aliasDomains.set(domain, this._normalizeRule(entry));
      } else {
        lazy.log.warn(
          "Ignoring invalid alias rule without domain and without email"
        );
      }
    }
  },

  getDomainAliasKeyList(email) {
    return this.getDomainRule(email)?.keys ?? null;
  },

  getEmailAliasKeyList(email) {
    if (!this._loaded()) {
      return null;
    }
    return this._aliasEmails.get(email.toLowerCase())?.keys ?? null;
  },

  /**
   * Whether the address is governed by a rule, whether or not it names a key.
   *
   * Named for what it means. `hasAliasDefinition()` answers this too -- it
   * tests membership of the rule maps, not the presence of keys, which was
   * checked rather than assumed after a test disproved the opposite -- so a
   * keyless rule counts there as well, now that one is stored at all. What
   * that method cannot say is *whether the rule names a key*, which is what
   * `hasKeylessRule()` adds and what the send path needs.
   *
   * @param {string} email
   * @returns {boolean}
   */
  hasRule(email) {
    return this.getRuleForEmail(email) != null;
  },

  /**
   * Whether a rule *requires* encryption to this address.
   *
   * `always` only. `maybe` is a rule saying "encrypt if you can", and treating
   * it as a requirement would refuse sends the user's permissive policy
   * allows. A caller asking this is asking about a demand, not a hope.
   *
   * Exposed as a method rather than leaving callers to compare against
   * `RuleValue`: the constant is a separate module export, and reaching for it
   * through a namespace binding has been the cause of more silent `undefined`
   * in this tree than any other mistake.
   *
   * @param {string} email
   * @returns {boolean}
   */
  requiresEncryption(email) {
    return this.getRuleForEmail(email)?.encrypt === RuleValue.ALWAYS;
  },

  /**
   * What the rules decide about one field, across several addressees.
   *
   * **The question the composer actually asks.** `resolveForRecipients()` answers
   * in `RuleValue` numbers, and a composer caller that compares them has to know
   * what `2` means -- which is the mistake this file already records twice, so
   * the translation lives here rather than at the call site.
   *
   * Returns a decision only when the rules agree on one. A conflict is not a
   * decision: it reaches the pre-send refusal as `ProblemRuleConflict`, and the
   * composer must not pick a winner out of it any more than the resolver may.
   * A `maybe` is not a decision either -- it means "if you can", which is what
   * the automatic behaviour already does.
   *
   * @param {string[]} addresses
   * @param {"encrypt"|"sign"} field
   * @returns {?"always"|"never"} `null` when nothing is decided.
   */
  decidedValueFor(addresses, field) {
    if (field != "encrypt" && field != "sign") {
      return null;
    }
    const resolved = this.resolveForRecipients(addresses ?? []);
    if (resolved[field] === RuleValue.ALWAYS) {
      return "always";
    }
    if (resolved[field] === RuleValue.NEVER) {
      return "never";
    }
    return null;
  },

  /**
   * Whether the address is governed by a rule that names no key.
   *
   * @param {string} email
   * @returns {boolean}
   */
  hasKeylessRule(email) {
    const rule = this.getRuleForEmail(email);
    return rule != null && rule.keys.length == 0;
  },

  /**
   * The whole rule for an address, email rule first and domain rule second.
   *
   * Email rules win over domain rules because that is how they are looked up
   * everywhere else in this module, and because a rule for one correspondent
   * is a narrower statement than a rule for their employer.
   *
   * The three settings are `true`, `false` or `null` -- null meaning the rule
   * says nothing about that field. Item 89b decides what several such values,
   * from several recipients, add up to; this only reports one recipient's
   * statement.
   *
   * @param {string} email
   * @returns {?object} `{keys, encrypt, sign, pgpMime, matchedBy}` where
   *   `matchedBy` is "email" or "domain", or null when no rule applies.
   */
  getRuleForEmail(email) {
    if (!this._loaded() || !email) {
      return null;
    }

    const wanted = email.toLowerCase();
    const byEmail = this._aliasEmails.get(wanted);
    if (byEmail) {
      return { ...byEmail, matchedBy: "email" };
    }

    const domain = this.getDomainRule(wanted);
    return domain ? { ...domain, matchedBy: "domain" } : null;
  },

  /**
   * @param {string} email
   * @returns {?object} The rule for the address's domain, if there is one.
   */
  getDomainRule(email) {
    if (!this._loaded()) {
      return null;
    }
    const lastAt = email.lastIndexOf("@");
    if (lastAt == -1) {
      return null;
    }
    const domain = email.substr(lastAt + 1);
    if (!domain) {
      return null;
    }
    return this._aliasDomains.get(domain.toLowerCase()) ?? null;
  },

  /**
   * Copy the fields this module understands out of a file entry.
   *
   * The three settings are stored as `true`, `false` or `null` rather than as
   * whatever the file happened to contain, so a caller does not have to
   * distinguish "absent" from "false" at every read. A value that is neither a
   * boolean nor absent is treated as absent: a typo in a hand-edited file must
   * not read as a policy the user did not set.
   *
   * @param {object} entry - One rule from the file.
   * @returns {object} `{keys, encrypt, sign, pgpMime}`.
   */
  _normalizeRule(entry) {
    return {
      // Always an array, so a caller never has to distinguish an absent list
      // from an empty one: "this rule names no key" is `keys.length === 0`,
      // and the rule is still present and findable.
      keys: Array.isArray(entry.keys) ? entry.keys : [],
      encrypt: this._normalizeValue(entry.encrypt),
      sign: this._normalizeValue(entry.sign),
      pgpMime: this._normalizeValue(entry.pgpMime),
    };
  },

  /**
   * One setting, as one of the three values or null for "says nothing".
   *
   * The words are what the format documents, and a boolean is accepted because
   * this build's own editor wrote booleans before this item: `true` meant
   * always and `false` meant never, so reading them that way keeps a file
   * written a version ago meaning what its author intended. Anything else is
   * null -- a typo must not become a policy.
   *
   * @param {*} value - Whatever the file held.
   * @returns {?integer} A `RuleValue`, or null.
   */
  _normalizeValue(value) {
    if (typeof value == "string") {
      return RULE_WORDS.get(value.toLowerCase()) ?? null;
    }
    if (value === true) {
      return RuleValue.ALWAYS;
    }
    if (value === false) {
      return RuleValue.NEVER;
    }
    return null;
  },

  /**
   * Combine two answers for the same field, keeping disagreement as a state.
   *
   * Enigmail's rule, kept because it is the right one: a contradiction between
   * never and always is not resolved either way, it becomes a conflict the
   * caller has to report; never beats maybe and always beats maybe, because
   * those are not contradictions but a silence beside a decision.
   *
   * @param {?integer} current - The value so far, or null for none yet.
   * @param {?integer} incoming - The value to fold in, or null.
   * @returns {?integer} The combined value, or null when neither said anything.
   */
  combineValues(current, incoming) {
    if (current === null || current === undefined) {
      return incoming ?? null;
    }
    if (incoming === null || incoming === undefined) {
      return current;
    }
    if (current === RuleValue.CONFLICT || incoming === RuleValue.CONFLICT) {
      return RuleValue.CONFLICT;
    }
    if (
      (current === RuleValue.NEVER && incoming === RuleValue.ALWAYS) ||
      (current === RuleValue.ALWAYS && incoming === RuleValue.NEVER)
    ) {
      return RuleValue.CONFLICT;
    }
    if (current === RuleValue.NEVER || incoming === RuleValue.NEVER) {
      return RuleValue.NEVER;
    }
    if (current === RuleValue.ALWAYS || incoming === RuleValue.ALWAYS) {
      return RuleValue.ALWAYS;
    }
    return RuleValue.MAYBE;
  },

  /**
   * Resolve the rules that apply to every recipient of one message.
   *
   * Per field, and per field's *sources*: which addresses asked for what, so a
   * caller can name the two that disagreed rather than reporting a bare
   * conflict. That is what makes the composer able to say something useful
   * instead of picking a winner.
   *
   * @param {string[]} addresses
   * @returns {object} `{encrypt, sign, pgpMime, byValue}` where each field is
   *   a `RuleValue` or null, and `byValue[field]` maps each value that
   *   contributed to the addresses that asked for it.
   */
  resolveForRecipients(addresses) {
    const result = { encrypt: null, sign: null, pgpMime: null, byValue: {} };
    for (const field of ["encrypt", "sign", "pgpMime"]) {
      result.byValue[field] = new Map();
    }

    for (const address of addresses ?? []) {
      const rule = this.getRuleForEmail(address);
      if (!rule) {
        continue;
      }
      for (const field of ["encrypt", "sign", "pgpMime"]) {
        const value = rule[field];
        if (value === null) {
          continue;
        }
        result[field] = this.combineValues(result[field], value);
        if (!result.byValue[field].has(value)) {
          result.byValue[field].set(value, []);
        }
        result.byValue[field].get(value).push(address);
      }
    }
    return result;
  },

  /**
   * The fields on which the rules for these recipients contradict each other.
   *
   * The question a caller actually has. Asking it here rather than comparing
   * against `RuleValue` at the call site keeps the constant out of every
   * caller's reach -- and out of the `undefined`-through-a-namespace failure
   * that this tree has produced repeatedly.
   *
   * @param {string[]} addresses
   * @returns {object[]} `[{field, always, never}]`, empty when nothing
   *   conflicts. Each entry names the addresses on both sides, because
   *   "these two disagree" is the only useful report.
   */
  conflictsForRecipients(addresses) {
    const resolved = this.resolveForRecipients(addresses);
    const conflicts = [];
    for (const field of ["encrypt", "sign", "pgpMime"]) {
      if (resolved[field] !== RuleValue.CONFLICT) {
        continue;
      }
      const parties = this.conflictParties(resolved, field);
      conflicts.push({ field, ...parties });
    }
    return conflicts;
  },

  /**
   * The addresses behind a conflict on one field.
   *
   * @param {object} resolved - From `resolveForRecipients()`.
   * @param {string} field - "encrypt", "sign" or "pgpMime".
   * @returns {object} `{always: string[], never: string[]}`, either possibly
   *   empty. Reported rather than resolved: the two sets are the two things
   *   the user must choose between.
   */
  conflictParties(resolved, field) {
    const byValue = resolved?.byValue?.[field];
    return {
      always: byValue?.get(RuleValue.ALWAYS) ?? [],
      never: byValue?.get(RuleValue.NEVER) ?? [],
    };
  },

  hasAliasDefinition(email) {
    if (!this._loaded()) {
      return false;
    }
    email = email.toLowerCase();
    const hasEmail = this._aliasEmails.has(email);
    if (hasEmail) {
      return true;
    }

    const lastAt = email.lastIndexOf("@");
    if (lastAt == -1) {
      return false;
    }

    const domain = email.substr(lastAt + 1);
    if (!domain) {
      return false;
    }

    return this._aliasDomains.has(domain);
  },
};
