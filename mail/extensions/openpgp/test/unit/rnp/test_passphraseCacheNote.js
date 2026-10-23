/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 33: how long gpg-agent keeps a passphrase, read from the agent.
 *
 * The number is what a user will rely on, so the two ways it can be wrong are
 * both tested: a duration invented when the agent cannot be asked, and a
 * duration misread from the agent's own output. The second is the likelier of
 * the two -- the option listing is colon-separated with the current value last,
 * and reading the wrong field yields a plausible number rather than an error.
 *
 * What this does not test, stated rather than implied: the sentence shown in
 * the key assistant. That needs a live composer with a GnuPG-held identity,
 * which is the same gap Item 28 records for the signing-key line.
 */

"use strict";

const { GnuPGAgent } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/gnupgAgent.sys.mjs"
);
const { Subprocess } = ChromeUtils.importESModule(
  "resource://gre/modules/Subprocess.sys.mjs"
);

let gRealRun = null;
let gHaveGpgconf = false;

add_setup(async function () {
  gRealRun = GnuPGAgent._run;
  try {
    await Subprocess.pathSearch("gpgconf");
    gHaveGpgconf = true;
  } catch (ex) {
    info("No gpgconf executable found; the real-agent task will be skipped");
  }
});

/** Put the real runner back. */
function restoreRun() {
  GnuPGAgent._run = gRealRun;
}

/**
 * Answer gpgconf with a fixed listing.
 *
 * @param {string[]} lines - Lines the stub returns.
 */
function stubListing(lines) {
  GnuPGAgent._run = async (command, args) => ({
    ok: command == "gpgconf" && args.includes("gpg-agent"),
    output: lines.join("\n"),
  });
}

/**
 * The durations the agent really has configured.
 *
 * Both are asserted as positive integers rather than as fixed values: they are
 * per-machine settings, and pinning 1200 here would make the test fail on a
 * machine whose owner changed them -- while asserting the exact number this
 * machine has would not be a test of anything.
 */
add_task(
  { skip_if: () => !gHaveGpgconf },
  async function readsTheAgentsOwnTimeouts() {
    const timeouts = await GnuPGAgent.cacheTimeouts();

    Assert.ok(timeouts, "a result should be returned");
    Assert.ok(
      Number.isInteger(timeouts.idle) && timeouts.idle > 0,
      `the idle timeout should be a positive number of seconds, got ${timeouts.idle}`
    );
    Assert.ok(
      Number.isInteger(timeouts.maximum) && timeouts.maximum > 0,
      `the maximum should be a positive number of seconds, got ${timeouts.maximum}`
    );
    Assert.greaterOrEqual(
      timeouts.maximum,
      timeouts.idle,
      "the maximum cannot be shorter than the idle timeout on a real agent"
    );
  }
);

/**
 * The current value is the last field, not the default.
 *
 * This is the misread that matters: the listing carries a default in field 8
 * and the configured value in field 10, so a parser taking the wrong one
 * returns a number that looks right and is not the one in force.
 */
add_task(async function readsTheLastFieldNotTheDefault() {
  stubListing([
    // name:flags:level:description:type:alt:argname:default:default-arg:value
    "default-cache-ttl:24:0:expire cached PINs after N seconds:3:3:N:600::1200",
    "max-cache-ttl:24:2:set maximum PIN cache lifetime to N seconds:3:3:N:7200::12000",
  ]);

  const timeouts = await GnuPGAgent.cacheTimeouts();

  Assert.equal(timeouts.idle, 1200, "the configured value, not the default");
  Assert.equal(
    timeouts.maximum,
    12000,
    "and the same for the maximum, whose default differs from its value"
  );
  restoreRun();
});

/**
 * A changed setting is reported as changed.
 *
 * Without this the task above could pass on a parser that returned constants.
 */
add_task(async function readsAChangedSetting() {
  stubListing([
    "default-cache-ttl:24:0:expire cached PINs after N seconds:3:3:N:600::60",
    "max-cache-ttl:24:2:set maximum PIN cache lifetime to N seconds:3:3:N:7200::300",
  ]);

  const timeouts = await GnuPGAgent.cacheTimeouts();

  Assert.equal(timeouts.idle, 60, "a shorter idle timeout is reported as set");
  Assert.equal(timeouts.maximum, 300, "and so is a shorter maximum");
  restoreRun();
});

/**
 * No agent, no number.
 *
 * The code's own rule, and the reason this task exists: a duration invented
 * here would be the number a user relied on, which is worse than silence.
 */
add_task(async function noAnswerMeansNoNumber() {
  GnuPGAgent._run = async () => ({ ok: false, output: "gpgconf not found" });

  const timeouts = await GnuPGAgent.cacheTimeouts();

  Assert.equal(timeouts.idle, null, "no idle timeout is invented");
  Assert.equal(timeouts.maximum, null, "no maximum is invented");
  restoreRun();
});

/**
 * A garbled answer means no number, not a zero.
 *
 * Zero would be worse than null: it reads as "the passphrase is not kept",
 * which is the opposite of the truth and would make the note understate the
 * exposure rather than stay silent.
 */
add_task(async function garbledAnswerMeansNoNumber() {
  stubListing([
    "default-cache-ttl:24:0:expire cached PINs after N seconds:3:3:N:600::none",
    "max-cache-ttl:24:2:set maximum PIN cache lifetime to N seconds:3:3:N:7200::",
  ]);

  const timeouts = await GnuPGAgent.cacheTimeouts();

  Assert.equal(timeouts.idle, null, "a non-numeric value is not a duration");
  Assert.equal(timeouts.maximum, null, "and an empty one is not zero");
  restoreRun();
});

/**
 * A missing option is null rather than a throw.
 *
 * The caller shows nothing in that case, so one absent option must not take
 * the whole signing-key section down with it.
 */
add_task(async function missingOptionIsNull() {
  stubListing(["some-other-option:0:0:unrelated:0:0::0::0"]);

  const timeouts = await GnuPGAgent.cacheTimeouts();

  Assert.equal(timeouts.idle, null, "an absent idle option is null");
  Assert.equal(timeouts.maximum, null, "an absent maximum option is null");
  restoreRun();
});

registerCleanupFunction(() => {
  restoreRun();
});
