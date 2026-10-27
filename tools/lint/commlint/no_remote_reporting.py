# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Fail if any remote-reporting send path has come back.

Coldfork removes the network side of telemetry, crash reporting and update
checks by neutering each send primitive in place, and the prefs that would
otherwise re-enable them are left as build-time no-ops. That removal only holds
if nothing puts the code back, and the thing that would put it back is a
vendoring or an upstream merge: the files are all outside `comm/`, so they are
exactly the files such an operation rewrites.

This module is the guard. It asserts a distinctive signature at each site -- the
guard's own comment and the code that follows it -- so a file that has been
replaced wholesale fails here instead of quietly resuming uploads.

Two callers use the same table:

  * `mach vendor` runs it after any vendoring, so a revert is caught in the
    same command that caused it;
  * `commlint` runs it like any other linter, which is what catches the case
    where a file is restored by a pull or a merge without vendoring at all.

Each entry is (path, signature). The signature is the first line of the comment
that documents the guard plus the statement that does the work, so editing the
guard without updating this table is itself a failure -- deliberately, because
the alternative is a check that silently stops checking.
"""

import os

# The marker every guard carries. Cheap to grep, stable under formatting.
MARKER = "COLDFORK-NO-NET"

# (path relative to topsrcdir, list of signatures that must all be present)
SITES = [
    (
        "toolkit/components/telemetry/app/TelemetrySend.sys.mjs",
        [
            "COLDFORK-NO-NET: Coldfork never submits telemetry.",
            'this._log.trace("submitPing - COLDFORK-NO-NET: submission disabled, dropping ping");',
            "COLDFORK-NO-NET: reachable without going through submitPing",
            'this._log.trace("_doPing - COLDFORK-NO-NET: submission disabled");',
            "COLDFORK-NO-NET: pingsender is a separate binary",
            'this._log.trace("runPingSender - COLDFORK-NO-NET: pingsender disabled");',
        ],
    ),
    (
        "toolkit/components/glean/src/init/viaduct_uploader.rs",
        [
            "COLDFORK-NO-NET: Coldfork never uploads Glean pings.",
            'log::info!("COLDFORK-NO-NET: FOG ping upload disabled, discarding ping");',
        ],
    ),
    (
        "toolkit/crashreporter/CrashSubmit.sys.mjs",
        [
            "COLDFORK-NO-NET: Coldfork never submits crash reports.",
        ],
    ),
    (
        "toolkit/crashreporter/client/app/src/glean.rs",
        [
            "COLDFORK-NO-NET: the crash client is a separate process",
            'log::info!("COLDFORK-NO-NET: crash client glean upload disabled");',
        ],
    ),
    (
        "toolkit/crashreporter/client/app/src/net/report.rs",
        [
            "COLDFORK-NO-NET: Coldfork never uploads a crash report.",
            'log::info!("COLDFORK-NO-NET: crash report upload disabled");',
        ],
    ),
    (
        "toolkit/mozapps/update/UpdateService.sys.mjs",
        [
            "COLDFORK-NO-NET: Coldfork never checks for updates.",
            "COLDFORK-NO-NET: update check disabled",
        ],
    ),
]

# The pref default, which lives in comm and is a statement rather than a barrier.
PREF_SITE = (
    "comm/mail/app/profile/all-thunderbird.js",
    'pref("datareporting.healthreport.uploadEnabled", false);',
)


def check(root):
    """Return a list of failures as (path, message).

    Each failure is one site whose signature is gone. The messages name the
    site rather than the line, because after a vendoring the line number is
    whatever the new file happens to have.
    """
    failures = []

    for rel_path, signatures in SITES:
        abs_path = os.path.join(root, rel_path)
        try:
            with open(abs_path, encoding="utf-8") as fh:
                text = fh.read()
        except FileNotFoundError:
            failures.append((rel_path, "file is gone; the guard went with it"))
            continue
        for sig in signatures:
            if sig not in text:
                failures.append(
                    (
                        rel_path,
                        f"guard missing: {sig.splitlines()[0]!r} "
                        f"({MARKER} removal has been reverted or rewritten)",
                    )
                )

    rel_path, sig = PREF_SITE
    abs_path = os.path.join(root, rel_path)
    try:
        with open(abs_path, encoding="utf-8") as fh:
            text = fh.read()
        if sig not in text:
            failures.append((rel_path, f"pref default is not off: expected {sig}"))
    except FileNotFoundError:
        failures.append((rel_path, "file is gone"))

    return failures


def lint(files, config, **lintargs):
    """mozlint entry point, for `commlint` and CI.

    `files` is ignored: this is a whole-tree property, not a per-file one, and
    the mozlint `global` type invokes it once.

    Results are `Issue` objects rather than plain dicts -- mozlint reads
    `.level` off them, and a dict fails with "'dict' object has no attribute
    'level'".
    """
    from mozlint import result

    root = lintargs["root"]
    issues = []
    for rel_path, message in check(root):
        issues.append(
            result.from_config(
                config,
                path=os.path.join(root, rel_path),
                lineno=1,
                column=1,
                message=message,
                level="error",
            )
        )
    return issues
