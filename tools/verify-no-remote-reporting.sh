#!/bin/bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Standalone check for Coldfork's telemetry / crash-report / update removal.
#
# Run it after anything that can rewrite toolkit/ or third_party/ -- a
# vendoring, an upstream merge, a rebase -- or whenever you want to know
# whether the removal is still in place. Exit 0 means every guard is present;
# non-zero names each site whose guard is gone.
#
# The signatures live in comm/tools/lint/commlint/no_remote_reporting.py, so
# this script and `commlint` cannot drift apart.

set -u

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
module="$root/comm/tools/lint/commlint/no_remote_reporting.py"

if [ ! -f "$module" ]; then
    echo "FAIL: cannot find $module" >&2
    exit 2
fi

exec python3 - "$root" "$module" <<'PY'
import importlib.util
import sys

root, module_path = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("no_remote_reporting", module_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

failures = mod.check(root)
if not failures:
    print(f"OK: all {len(mod.SITES) + 1} guards present; no remote reporting path is live.")
    sys.exit(0)

print(f"FAIL: {len(failures)} regression(s) in the remote-reporting removal:\n")
for path, message in failures:
    print(f"  {path}\n      {message}")
print(
    "\nSomething restored a send path. If this followed a vendoring, re-apply the\n"
    "guard; the diff you need is the COLDFORK-NO-NET block in the file named above."
)
sys.exit(1)
PY
