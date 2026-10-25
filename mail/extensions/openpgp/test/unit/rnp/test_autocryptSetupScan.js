/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Item 99a: finding the setup message in the mailbox.
 *
 * The item copies Enigmail's shape, and each part of it is asserted here rather
 * than assumed:
 *
 *   - it finds a message **in a folder that is not the Inbox**, newest-first;
 *   - it **stops at thirty days** -- asserted by widening the window and
 *     finding the same message, so the bound and not the header check is what
 *     excluded it;
 *   - it **skips Junk, Trash, NNTP and Local Folders**, with a real folder of
 *     each kind instead of a mocked list;
 *   - a folder that **cannot be opened does not stop the walk**;
 *   - a message whose marker is not `v1` is **invisible**, so a future format
 *     does not arrive as an offer here;
 *   - and the reason all of it streams headers: **the database does not store
 *     the marker.** That is the fact the scan's cost follows from, so it is
 *     asserted rather than described.
 *
 * What is *not* asserted, because it is not this item: the message is not
 * imported. The scan hands over the source and Item 99's flow takes it from
 * there; `classify()` is asserted only to show that what the scan returns is
 * what the next step expects.
 */

"use strict";

const { AutocryptSetup } = ChromeUtils.importESModule(
  "chrome://openpgp/content/modules/autocryptSetup.sys.mjs"
);
const { MailServices } = ChromeUtils.importESModule(
  "resource:///modules/MailServices.sys.mjs"
);

const DAY = 86400;

var gRoot;
var gArchive;
var gJunk;
var gTrash;
var gLocalInbox;
var gNewsRoot;
var gCounter = 0;

/**
 * @param {number} days - How long ago the message is dated.
 * @returns {number} Seconds since the epoch.
 */
function daysAgo(days) {
  return Math.floor(Date.now() / 1000) - days * DAY;
}

/**
 * A message that carries the marker, and the structure a receiver expects.
 *
 * The armour is not a real message -- nothing here decrypts anything -- but the
 * `application/autocrypt-setup` part and the BEGIN/END lines are what
 * `classify()` looks for, so a hit from the scan can be passed to Item 99's
 * flow unchanged. That is the seam this test crosses.
 *
 * @param {object} options
 * @param {number} options.date - Seconds since the epoch.
 * @param {?string} [options.marker] - The header's value; null omits it.
 * @returns {string}
 */
function makeMessage({ date, marker = "v1" }) {
  gCounter++;
  const lines = [
    "From: alice@example.com",
    "To: alice@example.com",
    "Subject: Autocrypt Setup Message",
    `Date: ${new Date(date * 1000).toUTCString()}`,
    `Message-ID: <setup-${gCounter}@example.com>`,
  ];
  if (marker) {
    lines.push(`Autocrypt-Setup-Message: ${marker}`);
  }
  lines.push(
    "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="setup-boundary"',
    "",
    "--setup-boundary",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "This message contains your OpenPGP key.",
    "",
    "--setup-boundary",
    "Content-Type: application/autocrypt-setup",
    "",
    "-----BEGIN PGP MESSAGE-----",
    "",
    "c2V0dXAtbWVzc2FnZQ==",
    "-----END PGP MESSAGE-----",
    "",
    "--setup-boundary--",
    ""
  );
  return lines.join("\r\n");
}

/**
 * The named subfolder, created if it is not already there.
 *
 * A POP3 account arrives with some of these folders already made -- Inbox for
 * certain -- so creating unconditionally fails with NS_MSG_FOLDER_EXISTS.
 *
 * @param {nsIMsgLocalMailFolder} root
 * @param {string} name
 * @returns {nsIMsgFolder}
 */
function ensureFolder(root, name) {
  return root.containsChildNamed(name)
    ? root.getChildNamed(name)
    : root.createLocalSubfolder(name);
}

/**
 * Append a message to a folder and return its header.
 *
 * @param {nsIMsgFolder} folder
 * @param {string} text
 * @returns {nsIMsgDBHdr}
 */
function addMessage(folder, text) {
  folder.QueryInterface(Ci.nsIMsgLocalMailFolder).addMessage(text);
  return [...folder.messages].at(-1);
}

add_setup(async function () {
  do_get_profile();

  // A real POP3 account, not Local Folders. The scan skips the Local Folders
  // account, so a message seeded only there could not prove anything -- and
  // that is exactly the rule under test.
  const server = MailServices.accounts.createIncomingServer(
    "scanner",
    "scan.example",
    "pop3"
  );
  const account = MailServices.accounts.createAccount();
  server.valid = false;
  account.incomingServer = server;
  server.valid = true;

  gRoot = server.rootMsgFolder.QueryInterface(Ci.nsIMsgLocalMailFolder);
  ensureFolder(gRoot, "Inbox").setFlag(Ci.nsMsgFolderFlags.Inbox);
  gArchive = ensureFolder(gRoot, "Archive");
  gJunk = ensureFolder(gRoot, "Junk");
  gJunk.setFlag(Ci.nsMsgFolderFlags.Junk);
  gTrash = ensureFolder(gRoot, "Trash");
  gTrash.setFlag(Ci.nsMsgFolderFlags.Trash);

  // Local Folders, which the item's list excludes.
  const localAccount = MailServices.accounts.createLocalMailAccount();
  const localRoot = localAccount.incomingServer.rootMsgFolder.QueryInterface(
    Ci.nsIMsgLocalMailFolder
  );
  gLocalInbox = ensureFolder(localRoot, "Inbox");
  gLocalInbox.setFlag(Ci.nsMsgFolderFlags.Mail);

  // And a news server, which has folders but no mail.
  const newsServer = MailServices.accounts.createIncomingServer(
    "reader",
    "news.example",
    "nntp"
  );
  const newsAccount = MailServices.accounts.createAccount();
  newsServer.valid = false;
  newsAccount.incomingServer = newsServer;
  newsServer.valid = true;
  gNewsRoot = newsServer.rootMsgFolder;
});

/**
 * The fact the scan's cost follows from, and the item's own case: a message
 * found in a folder that is not the Inbox.
 */
add_task(async function findsItInAFolderThatIsNotTheInbox() {
  const hdr = addMessage(gArchive, makeMessage({ date: daysAgo(2) }));

  Assert.equal(
    hdr.getStringProperty("autocrypt-setup-message"),
    "",
    "the message database does not store the marker, so it cannot be searched for"
  );

  const hits = await AutocryptSetup.findSetupMessages();
  Assert.equal(hits.length, 1, "the archive message is found");
  Assert.equal(
    hits[0].folder.URI,
    gArchive.URI,
    "and it is found in the folder that is not the Inbox"
  );
  Assert.equal(hits[0].hdr.messageKey, hdr.messageKey, "it is that message");
  Assert.ok(
    hits[0].source.includes("Autocrypt-Setup-Message: v1"),
    "the whole message came back, not only the headers the scan read first"
  );
  Assert.equal(
    AutocryptSetup.classify(hits[0].source).state,
    "ok",
    "and what the scan hands over is what Item 99's flow expects"
  );
});

/**
 * The skip list, asserted against real folders of each kind.
 *
 * A reason rather than a boolean is what makes this possible: "not found" and
 * "not looked at" are different answers, and only the second is the item's
 * requirement.
 */
add_task(async function theSkippedFoldersAreTheItemsOwnList() {
  Assert.equal(AutocryptSetup.skipReason(gJunk), "junk", "Junk is skipped");
  Assert.equal(AutocryptSetup.skipReason(gTrash), "trash", "Trash is skipped");
  Assert.equal(
    AutocryptSetup.skipReason(gLocalInbox),
    "local-folders",
    "Local Folders is skipped"
  );
  Assert.equal(AutocryptSetup.skipReason(gNewsRoot), "nntp", "NNTP is skipped");
  Assert.equal(
    AutocryptSetup.skipReason(gArchive),
    null,
    "an ordinary folder is scanned"
  );
});

/**
 * And the same folders are skipped by a walk, not merely by the predicate.
 */
add_task(async function junkTrashAndLocalFoldersAreNotWalked() {
  addMessage(gJunk, makeMessage({ date: daysAgo(1) }));
  addMessage(gTrash, makeMessage({ date: daysAgo(1) }));
  addMessage(gLocalInbox, makeMessage({ date: daysAgo(1) }));

  const hits = await AutocryptSetup.findSetupMessages();
  Assert.equal(hits.length, 1, "only the archive message is found");
  Assert.equal(
    hits[0].folder.URI,
    gArchive.URI,
    "the copies in Junk, Trash and Local Folders are not offered"
  );
});

/**
 * The thirty-day bound, isolated.
 *
 * The old message is added first so it carries the lower key: reverse
 * enumeration reaches the fresh one and then the old one, which is what makes
 * the stop observable at all. Widening the window finds both, so the bound and
 * not the header check is what excluded the old one.
 */
add_task(async function stopsAtThirtyDays() {
  Assert.equal(
    AutocryptSetup.MAX_AGE_SECONDS,
    2592000,
    "the bound is Enigmail's number, in seconds"
  );

  const bounded = ensureFolder(gRoot, "Bounded");
  addMessage(bounded, makeMessage({ date: daysAgo(45) }));
  addMessage(bounded, makeMessage({ date: daysAgo(2) }));

  const hits = await AutocryptSetup.findSetupMessages();
  const within = hits.filter(hit => hit.folder.URI == bounded.URI);
  Assert.equal(within.length, 1, "one message inside the window is found");
  Assert.greater(
    within[0].hdr.dateInSeconds,
    daysAgo(30),
    "and it is the recent one, not the 45-day-old copy"
  );

  const widened = await AutocryptSetup.findSetupMessages({
    maxAgeSeconds: 60 * DAY,
  });
  const all = widened.filter(hit => hit.folder.URI == bounded.URI);
  Assert.equal(
    all.length,
    2,
    "with the window widened the same folder yields both, so the bound is what excluded the old one"
  );
});

/**
 * A message from a format this build does not know is invisible to the scan.
 *
 * The same rule `classify()` applies, applied at the earlier point: a `v2`
 * message must not arrive as an offer at all, or every future version of the
 * format would produce a prompt from a build that predates it.
 */
add_task(async function aFutureFormatIsNotOffered() {
  const future = ensureFolder(gRoot, "Future");
  addMessage(future, makeMessage({ date: daysAgo(1), marker: "v2" }));

  const hits = await AutocryptSetup.findSetupMessages();
  Assert.equal(
    hits.filter(hit => hit.folder.URI == future.URI).length,
    0,
    "a v2 message is not found, and is not reported either"
  );
});

/**
 * A folder that cannot be opened is skipped, and the walk continues.
 *
 * The break is real rather than simulated: the folder's message store is
 * replaced by a directory, so opening its database fails the way a damaged
 * store does. The item requires this because a broken index in one account must
 * not stop the scan finding a hit in another -- which is what the final
 * assertion checks.
 */
add_task(async function aFolderThatCannotBeOpenedDoesNotStopTheWalk() {
  const broken = ensureFolder(gRoot, "Broken");
  addMessage(broken, makeMessage({ date: daysAgo(1) }));

  const summary = broken.summaryFile;
  broken.msgDatabase.forceClosed();
  broken.msgDatabase = null;
  summary.remove(false);
  await IOUtils.makeDirectory(summary.path);

  // The premise, asserted rather than assumed. The item's requirement is about
  // a folder that *fails* to open, which is the exception path; a folder whose
  // database merely comes back null would pass through a different branch and
  // the tolerance below would not be exercised at all.
  let outcome;
  try {
    outcome = broken.msgDatabase ? "opened" : "returned null";
  } catch (ex) {
    outcome = `threw: ${ex.message}`;
  }
  info(`FINDING the broken folder's database: ${outcome}`);
  Assert.ok(
    outcome.startsWith("threw"),
    `opening the broken folder fails, so the tolerance is exercised (${outcome})`
  );

  let threw = false;
  let hits;
  try {
    hits = await AutocryptSetup.findSetupMessages();
  } catch (ex) {
    threw = true;
    info(`FINDING the walk threw: ${ex.message}`);
  }

  Assert.ok(!threw, "one unreadable folder does not fail the whole scan");
  Assert.ok(
    hits.some(hit => hit.folder.URI == gArchive.URI),
    "and the message in the readable folder is still found"
  );
});
