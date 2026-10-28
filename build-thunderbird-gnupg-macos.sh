#!/bin/bash
#
# build-thunderbird-gnupg-macos.sh
#
# Full (non-artifact) macOS build of Thunderbird GnuPG from the checkout at
# /Users/rono/Documents/firefox, then a .dmg if one can be made.
#
# Run this at the console, not over ssh. A build spends a long time fetching
# toolchains and compiling; a dropped ssh session takes the process group with
# it, so a run started remotely does not survive the connection. Started here,
# the only thing that stops it is the machine.
#
# It is safe to re-run. Nothing is deleted between runs: configure reuses the
# downloaded toolchains, and make picks up where an interrupted build stopped.
# After a failure, run it again and it continues.
#
# Phases
#   0  preflight   check the checkout, the branding, python and disk
#   1  bootstrap   ./mach bootstrap --application-choice "Firefox for Desktop"
#                  (skipped with --skip-bootstrap; nothing here needs root)
#   2  mozconfig   ensure the lines that make this the GnuPG variant, and
#                  MOZ_PKG_FORMAT=DMG so the package step writes a .dmg
#   3  build       ./mach build
#   4  package     ./mach package  ->  Thunderbird GnuPG.app  +  .dmg
#   5  dmg         report the .dmg produced by phase 4
#   6  verify      read the identity back out of the built application
#
# Exit status is non-zero when the build fails, when a requested artifact
# (.app, or the .dmg) is missing, or when the built application does not carry
# the GnuPG identity. A run that says "warning" and exits 0 would be worse than
# a failure: it would let a wrong or missing artifact pass as a finished build.
#
# WHY THE MOZCONFIG IS CHECKED, NOT JUST ASSUMED
# Without --enable-project=comm/mail this tree builds Firefox. Without
# --enable-gnupg the profile is the shared "Thunderbird" one rather than
# ThunderbirdGnuPG. Both failures produce a build that looks fine, so the
# script reads the values back out of the finished application rather than
# trusting that the flags took effect.
#
# WHAT A macOS PACKAGE CONTAINS
# Left alone, a developer build on macOS gets MOZ_PKG_FORMAT=TAR
# (toolkit/moz.configure: if toolkit == cocoa and developer_options and not
# automation, return "TAR"), so `mach package` writes the .app bundle and a
# .tar of it. This script asks for DMG instead, and the same step then writes
# the .dmg directly.
#
# The other route -- `mach repackage dmg` on the .tar -- does not work on a
# macOS host, and fails only after the whole build has succeeded. It resolves
# every tool through bootstrap_toolchain(), which fetches Linux-built
# toolchains; there is no macOS build of hfsplus/newfs_hfs, so it stops with
# "MKFSHFS tool not found". `mach package` with DMG prefers the configure-time
# tools instead (make_dmg.py: buildconfig.substs.get("MKFSHFS") or
# bootstrap_toolchain(...)), and on macOS MKFSHFS is the host's
# /sbin/newfs_hfs. So the DMG is made in phase 4, not phase 5.
#
# Log: $SRC/artifacts/build-thunderbird-macos.log
#
# Options
#   --skip-bootstrap   omit phase 1
#   --no-dmg           stop after packaging; do not make a .dmg
#   --jobs N           pass -jN to mach build
#   -h, --help         this text

set -euo pipefail

SRC="${THUNDERBIRD_SRC:-$HOME/Documents/firefox}"
LOG_DIR="$SRC/artifacts"
LOG="$LOG_DIR/build-thunderbird-macos.log"
MOZCONFIG="$SRC/mozconfig"

DO_BOOTSTRAP=1
DO_DMG=1
DMG_OUT=""
JOBS=""

say()  { printf '\n=== %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '    ! %s\n' "$*" >&2; }
die()  { printf '\n!! %s\n\n' "$*" >&2; exit 1; }

# Print the leading comment block, however long it grows. The line range used
# to be hardcoded to '2,57'; adding a line to the header silently truncated help.
usage() { awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; }

FAIL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-bootstrap) DO_BOOTSTRAP=0 ;;
    --no-dmg)         DO_DMG=0 ;;
    --jobs)           shift; [ $# -gt 0 ] || die "--jobs needs a number"; JOBS="$1" ;;
    -h|--help)        usage; exit 0 ;;
    *)                die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

START_EPOCH=$(date +%s)

# ---------------------------------------------------------------- phase 0
say "Phase 0 - preflight"

# Homebrew refuses to run as root, and root's PATH has no /opt/homebrew/bin, so
# a build started with sudo fails in a confusing way rather than an obvious one.
[ "$(id -u)" -ne 0 ] || die "run this as your own user, not with sudo or as root"

[ -d "$SRC" ]                          || die "checkout not found: $SRC"
[ -x "$SRC/mach" ]                     || die "no executable ./mach in $SRC"
[ -d "$SRC/comm/mail" ]                || die "comm/mail is missing from $SRC"
[ -d "$SRC/comm/mail/branding/gnupg" ] || die "comm has no branding/gnupg - pull the fork's comm first"
grep -q "enable-gnupg" "$SRC/comm/mail/moz.configure" \
  || die "comm/mail/moz.configure has no --enable-gnupg - pull the fork's comm first"

cd "$SRC"

info "checkout:   $SRC"
if git -C "$SRC" rev-parse --git-dir >/dev/null 2>&1; then
  info "gecko HEAD: $(git -C "$SRC" -c safe.directory="$SRC" log -1 --format='%h %s' 2>/dev/null || echo unknown)"
fi
if git -C "$SRC/comm" rev-parse --git-dir >/dev/null 2>&1; then
  info "comm HEAD:  $(git -C "$SRC/comm" -c safe.directory="$SRC/comm" log -1 --format='%h %s' 2>/dev/null || echo unknown)"
fi

# Ensure the interpreter this script needs is the one mach will find. A login
# shell already has /usr/local/bin first, but a script started from a bare
# shell may not, and mach aborts on Python 3.9 with a message that looks like
# a mach bug rather than a PATH problem.
#
# /usr/local/bin comes first because that is where the python3 symlink lives
# (see the note on the interpreter below); /opt/homebrew/bin is the fallback.
# Putting Homebrew first would select python3.15, which mach warns is above
# its highest known-working version.
export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"
PY="$(command -v python3 || true)"
[ -n "$PY" ] || die "no python3 on PATH"
PYVER="$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
info "python:     $PY ($PYVER)"
case "$PYVER" in
  3.9|3.8|3.7|3.6) die "python $PYVER is too old for mach (needs 3.10+).

  Point python3 at a supported interpreter machine-wide with
      sudo ln -sfn /opt/homebrew/bin/python3.13 /usr/local/bin/python3
  then run this script again." ;;
  3.10|3.11|3.12|3.13|3.14) : ;;
  *) warn "python $PYVER is above the highest version mach lists as known-working (3.14); 3.13 is the safe choice" ;;
esac

CORES="$(sysctl -n hw.ncpu 2>/dev/null || echo 4)"
info "cores:      $CORES"

# One build ID for the whole run, so that every artifact agrees about which
# build it is.
#
# Without this, the two halves of one build disagree. buildid.h is declared with
# FORCE (Makefile.in:22), so build/variables.py:buildid_header() rewrites it on
# every make pass, stamping datetime.now() when MOZ_BUILD_DATE is unset. A build
# passes through it twice -- before XUL links, and again near the end -- so the
# binary keeps the first stamp and application.ini records the second. Measured
# here on a full, clean build: XUL carried 20261028105546 while buildid.h and
# application.ini read 20261028111533.
#
# The mismatch is invisible until someone compares the two, and then it is
# actively misleading: the About dialog reports the later value while the binary
# holds the earlier one, and neither names the build a user is running.
#
# MOZ_BUILD_DATE is Mozilla's own mechanism for this -- buildid_header() prefers
# it over the clock and rejects anything that is not 14 digits. One value here
# reaches every pass, so buildid.h, buildid.cpp and application.ini are the same
# number for the life of the run.
export MOZ_BUILD_DATE="${MOZ_BUILD_DATE:-$(date +%Y%m%d%H%M%S)}"
info "build id:   $MOZ_BUILD_DATE (pinned for the whole run)"

FREE_GB="$(df -g "$SRC" 2>/dev/null | awk 'NR==2 {print $4}')"
if [ -n "$FREE_GB" ] && [ "$FREE_GB" -lt 40 ]; then
  warn "only ${FREE_GB}GB free at $SRC; a full build wants about 40GB"
fi

if [ "$(uname -m)" = "arm64" ]; then
  info "arch:       arm64 (configure derives the objdir, obj-aarch64-apple-darwin<sdk>)"
else
  info "arch:       $(uname -m)"
fi

# The Gecko and comm checkouts each carry a vendored Rust tree, and the build
# vendors from comm's (comm/python/rocbuild: VENDORED_DIRECTORY =
# comm/third_party/rust). A git dependency that Gecko's Cargo.toml names at a
# version comm no longer vendors has no replacement, so cargo tries the network
# and --frozen refuses it. The build dies at
# config/.deps/cbindgen-metadata.json.stub with
#   "can't checkout from 'https://github.com/mozilla/neqo': you are in the
#    offline mode (--frozen)"
# which names neither checkout and reads like a toolchain fault. Checked here
# instead, where the fix can be stated.
VENDOR_G="$(sed -n 's/^version = "\(.*\)"/\1/p' "$SRC/third_party/rust/neqo-bin/Cargo.toml" 2>/dev/null | head -1)"
VENDOR_C="$(sed -n 's/^version = "\(.*\)"/\1/p' "$SRC/comm/third_party/rust/neqo-bin/Cargo.toml" 2>/dev/null | head -1)"
WANT_NEQO="$(grep -oE 'tag = "v[0-9.]+"' "$SRC/netwerk/test/http3server/Cargo.toml" 2>/dev/null | head -1 | grep -oE '[0-9.]+')"
info "neqo:       gecko vendors ${VENDOR_G:-?}, comm vendors ${VENDOR_C:-?}, http3server wants ${WANT_NEQO:-?}"
if [ -n "$WANT_NEQO" ] && [ -n "$VENDOR_C" ] && [ "$WANT_NEQO" != "$VENDOR_C" ]; then
  die "the Gecko checkout is older than comm, so the build cannot resolve neqo.

    Gecko's netwerk/test/http3server/Cargo.toml asks for neqo v$WANT_NEQO,
    but comm vendors neqo $VENDOR_C and the build takes its vendored sources
    from comm. There is no replacement for v$WANT_NEQO, so cargo tries to
    fetch it and fails under --frozen.

  Bring the Gecko checkout to the revision this comm was built against, for
  example:

      git -C $SRC fetch origin
      git -C $SRC checkout e77c5131fd07ddab0731efab207539f5ae3a00ce

  then run this script again. Nothing has been changed by this run."
fi

if [ "$DO_BOOTSTRAP" -eq 1 ]; then
  info "bootstrap:  yes (use --skip-bootstrap once it has been done)"
else
  info "bootstrap:  skipped (--skip-bootstrap)"
fi

# Rotate the log instead of truncating it. The header promises this script can
# be re-run to continue an interrupted build, and after a failure the previous
# log is the only record of what went wrong. Done here, before phase 1, so it
# happens whether or not bootstrap is skipped.
mkdir -p "$LOG_DIR"
if [ -f "$LOG" ]; then
  mv -f -- "$LOG" "$LOG.prev"
  info "previous log kept as: $LOG.prev"
fi

# ---------------------------------------------------------------- phase 1
say "Phase 1 - bootstrap"

if [ "$DO_BOOTSTRAP" -eq 0 ]; then
  info "skipped"
else
  info "installs Homebrew formulas and fetches toolchains; may prompt to install"
  info "the Xcode command line tools. Nothing here needs root or sudo."

  # bootstrap compares the mozconfig's project against --application-choice,
  # sees a mismatch, and answers its own "overwrite the config?" prompt with yes
  # when it is not interactive -- replacing the mozconfig with a Firefox one.
  # Observed in this script's first run: "Selecting Y because context is not
  # interactive. Your requested configuration has been written to". Move ours
  # aside so bootstrap never sees it, and restore it afterwards.
  MOZCONFIG_ASIDE="$MOZCONFIG.bootstrap-aside"
  restore_mozconfig() {
    if [ -e "$MOZCONFIG_ASIDE" ]; then
      mv -f -- "$MOZCONFIG_ASIDE" "$MOZCONFIG"
      info "restored your mozconfig"
    fi
  }
  trap restore_mozconfig EXIT

  if [ -f "$MOZCONFIG" ]; then
    mv -- "$MOZCONFIG" "$MOZCONFIG_ASIDE"
    info "moved the mozconfig aside so bootstrap cannot overwrite it"
  fi

  set +e
  ./mach --no-interactive bootstrap --application-choice "Firefox for Desktop" 2>&1 | tee -a "$LOG"
  boot_status=${PIPESTATUS[0]}
  set -e

  restore_mozconfig
  trap - EXIT

  [ "$boot_status" -eq 0 ] || die "bootstrap failed (exit $boot_status); see $LOG"
fi

# ---------------------------------------------------------------- phase 2
say "Phase 2 - mozconfig"

WANT_PROJECT='ac_add_options --enable-project=comm/mail'
WANT_GNUPG='ac_add_options --enable-gnupg'
WANT_REMOTING='export MOZ_APP_REMOTINGNAME=thunderbird-gnupg'

# MOZ_PKG_FORMAT decides what `mach package` writes. Left alone, a developer
# build on macOS gets TAR (toolkit/moz.configure): the .app bundle and a .tar
# of it. Asking for DMG makes `mach package` produce the .dmg itself.
#
# That matters because the other route -- `mach repackage dmg` on the .tar --
# does not work on a macOS host. It resolves its three tools with
# bootstrap_toolchain(), which fetches the Linux-built toolchains, and there is
# no macOS build of hfsplus/newfs_hfs, so it stops with "MKFSHFS tool not
# found" after the whole build has succeeded. `mach package` with DMG, by
# contrast, prefers the configure-time tools (make_dmg.py:
# `buildconfig.substs.get("MKFSHFS") or bootstrap_toolchain(...)`), and on
# macOS MKFSHFS is the host's /sbin/newfs_hfs.
WANT_PKGFMT='export MOZ_PKG_FORMAT=DMG'

# A mozconfig that predates this run may name a different project. bootstrap
# writes one when none exists (non-interactively that is
# `ac_add_options --with-ccache=sccache`), and an older one could carry a
# browser line. Two project lines make configure fail, and a browser line on
# its own silently builds Firefox instead of Thunderbird. Take ownership of
# that line here, before the file is written or appended to: a freshly written
# file is already correct and must not be stripped and re-added for no reason.
if [ -f "$MOZCONFIG" ] && grep -qE '^[[:space:]]*(ac_add_options[[:space:]]+)?--enable-(project|application)=' "$MOZCONFIG"; then
  info "removing existing project/application line(s) so comm/mail is unambiguous"
  grep -vE '^[[:space:]]*(ac_add_options[[:space:]]+)?--enable-(project|application)=' "$MOZCONFIG" > "$MOZCONFIG.tmp"
  mv -f -- "$MOZCONFIG.tmp" "$MOZCONFIG"
fi

if [ ! -f "$MOZCONFIG" ]; then
  info "no mozconfig; writing one"
  {
    printf '%s\n' "$WANT_PROJECT"
    printf '%s\n' "$WANT_GNUPG"
    printf '%s\n' "$WANT_REMOTING"
    if [ "$DO_DMG" -eq 1 ]; then
      printf '%s\n' "$WANT_PKGFMT"
    fi
  } > "$MOZCONFIG"
else
  info "existing mozconfig kept; checking the lines that matter"
fi

# Append only what is missing, so an edited mozconfig is not overwritten.
for line in "$WANT_PROJECT" "$WANT_GNUPG" "$WANT_REMOTING"; do
  if grep -qxF -- "$line" "$MOZCONFIG"; then
    info "already set:  $line"
  elif grep -qF -- "${line#*=}" "$MOZCONFIG"; then
    info "present:      $line"
  else
    info "adding:       $line"
    printf '%s\n' "$line" >> "$MOZCONFIG"
  fi
done

# The package format is managed both ways, because a stale DMG line would make
# --no-dmg lie: `mach package` would still write a .dmg.
if [ "$DO_DMG" -eq 1 ]; then
  if grep -qxF -- "$WANT_PKGFMT" "$MOZCONFIG"; then
    info "already set:  $WANT_PKGFMT"
  else
    info "adding:       $WANT_PKGFMT"
    printf '%s\n' "$WANT_PKGFMT" >> "$MOZCONFIG"
  fi
else
  if grep -q '^export MOZ_PKG_FORMAT=' "$MOZCONFIG"; then
    info "removing the MOZ_PKG_FORMAT line, so --no-dmg really writes no .dmg"
    grep -v '^export MOZ_PKG_FORMAT=' "$MOZCONFIG" > "$MOZCONFIG.tmp"
    mv -f -- "$MOZCONFIG.tmp" "$MOZCONFIG"
  fi
fi

info "contents:"
sed 's/^/      /' "$MOZCONFIG"

# ---------------------------------------------------------------- phase 3
say "Phase 3 - build (full, non-artifact)"

mkdir -p "$LOG_DIR"
[ -f "$LOG" ] || : > "$LOG"
info "this takes a long time (tens of minutes, longer on a first run)"
info "logging to: $LOG"

set +e
./mach build ${JOBS:+-j$JOBS} 2>&1 | tee -a "$LOG"
status=${PIPESTATUS[0]}
set -e

if [ "$status" -ne 0 ]; then
  printf '\n!! build failed (exit %s)\n\n' "$status"
  tail -40 "$LOG" 2>/dev/null | sed 's/^/    /' || true
  exit "$status"
fi

# ---------------------------------------------------------------- phase 4
say "Phase 4 - package"

set +e
./mach package 2>&1 | tee -a "$LOG"
pkg_status=${PIPESTATUS[0]}
set -e
[ "$pkg_status" -eq 0 ] || warn "mach package exited $pkg_status; the .app may still have been produced"

APP="$(find "$SRC" -maxdepth 3 -name '*.app' -path '*/dist/*' -type d 2>/dev/null | head -1)"
if [ -z "$APP" ]; then
  APP="$(find "$SRC" -maxdepth 4 -name 'Thunderbird GnuPG.app' -type d 2>/dev/null | head -1)"
fi
if [ -n "$APP" ]; then
  info "app bundle: $APP"
else
  warn "no .app found under $SRC (look in obj-*/dist)"
  FAIL=1
fi

# ---------------------------------------------------------------- phase 5
say "Phase 5 - dmg"

if [ "$DO_DMG" -eq 0 ]; then
  info "skipped (--no-dmg)"
else
  DMG_IN="$(find "$SRC" -maxdepth 3 -name '*.dmg' -path '*/dist/*' 2>/dev/null | head -1)"

  if [ -n "$DMG_IN" ]; then
    DMG_OUT="$DMG_IN"
    info "produced by mach package: $DMG_IN"
  else
    # Not expected now that MOZ_PKG_FORMAT=DMG drives the package step. If it
    # does happen, say why the obvious remedy does not work here, because the
    # failure it produces ("MKFSHFS tool not found") names no cause.
    warn "no .dmg in dist"
    warn "mach repackage dmg will not help on macOS: it bootstraps"
    warn "hfsplus/newfs_hfs, which is only built for Linux. Check that the"
    warn "mozconfig line '$WANT_PKGFMT' is present, then re-run."
    FAIL=1
  fi
fi

# ---------------------------------------------------------------- phase 6
say "Phase 6 - verify what was built"

# depth 4: <src>/<objdir>/dist/bin/application.ini -- objdir and dist and bin
# are three levels, so maxdepth 3 misses the file and the identity check that
# follows silently does nothing.
INI="$(find "$SRC" -maxdepth 4 -name application.ini -path '*/dist/bin/*' 2>/dev/null | head -1)"
if [ -n "$INI" ]; then
  info "application.ini: $INI"
  grep -E '^(Name|RemotingName|CodeName|Profile|BuildID)=' "$INI" | sed 's/^/      /'
else
  warn "no dist/bin/application.ini found"
fi

if [ -n "$APP" ] && [ -f "$APP/Contents/Info.plist" ]; then
  info "Info.plist:"
  for key in CFBundleName CFBundleIdentifier CFBundleExecutable; do
    val="$(/usr/libexec/PlistBuddy -c "Print :$key" "$APP/Contents/Info.plist" 2>/dev/null || echo '(absent)')"
    printf '      %-22s %s\n' "$key" "$val" | sed 's/^      //'
  done
fi

ELAPSED=$(( $(date +%s) - START_EPOCH ))
printf '\n=== Result\n'
printf '    build exit: %s\n' "$status"
printf '    elapsed:    %dm%02ds\n' $((ELAPSED / 60)) $((ELAPSED % 60))
printf '    log:        %s\n' "$LOG"
if [ -n "$APP" ]; then
  printf '    app:        %s\n' "$APP"
fi
if [ -n "${DMG_OUT:-}" ]; then
  printf '    dmg:        %s\n' "$DMG_OUT"
fi

# The three identity values are what make this the variant rather than a
# Thunderbird Daily build with a different icon. State plainly whether they
# came out right, because a wrong one is otherwise invisible until launch.
if [ -n "$INI" ]; then
  code="$(grep '^CodeName=' "$INI" | cut -d= -f2-)"
  prof="$(grep '^Profile=' "$INI" | cut -d= -f2-)"
  if [ "$code" = "Thunderbird GnuPG" ] && [ "$prof" = "ThunderbirdGnuPG" ]; then
    printf '\n    branding and profile are correct for the variant\n'
  else
    printf '\n    ! unexpected identity: CodeName=%s Profile=%s\n' "$code" "$prof"
    printf '    ! expected Thunderbird GnuPG / ThunderbirdGnuPG\n'
    FAIL=1
  fi
fi

printf '\n    run it with:   open "%s"\n' "${APP:-$SRC/obj-*/dist/Thunderbird GnuPG.app}"
printf '    exit:       %s\n\n' "$FAIL"

# A missing artifact or a wrong identity is a failure even though the compile
# succeeded, so the last word from this script is the honest one.
exit "$FAIL"
