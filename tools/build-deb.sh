#!/usr/bin/env bash
#
# build-deb.sh — full Thunderbird (comm/mail) build, packaged as a .deb.
#
# Run it by hand, from anywhere:
#
#   comm/tools/build-deb.sh                  # full build, package, copy to $HOME
#   comm/tools/build-deb.sh --skip-build     # reuse the build, rebuild the .deb
#   comm/tools/build-deb.sh --jobs 8         # pass -j8 to mach build
#   comm/tools/build-deb.sh --dry-run        # report what would happen
#
# Phases
#   0  preflight   the gecko checkout, mozconfig, objdir and host tools
#   1  build       ./mach build            (full, not artifact mode)
#   2  package     ./mach package          -> obj-*/dist/<package_name>.tar.xz
#   3  stage       unpack that tarball into a dpkg tree, and add the parts the
#                  tarball does not carry: the launcher symlink, the .desktop
#                  entry and the hicolor icons
#   4  package deb dpkg-deb --build        -> <name>_<version>_<arch>.deb
#   5  copy        the .deb to $DEST (default: $HOME)
#
# Deliberately NOT done here
#   - bootstrap and mozconfig writing. build-thunderbird.sh in ~/Documents/Sentuny
#     owns those; this script assumes a checkout that already builds and checks
#     the mozconfig selects comm/mail rather than rewriting it.
#   - The translation pipeline. That belongs to the workbench product, not to
#     Thunderbird, and nothing here touches a database.
#
# The .deb installs under /usr/lib/<package>, links /usr/bin/<package>, and uses
# a package name that is not "thunderbird", so it installs beside a distribution
# Thunderbird without replacing it.
#
# Exit codes: 0 built and copied; non-zero at the phase that failed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GECKO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BRANDING_DIR="$GECKO_ROOT/comm/mail/branding/gnupg"

# Package identity. The name must not be "thunderbird": this build is a distinct
# product and has to install beside the distribution package.
PKG_NAME="${PKG_NAME:-thunderbird-gnupg}"
# Assigned in two steps rather than with ${MAINTAINER:-...}: an apostrophe inside
# a ${var:-word} default breaks bash's parser even when the whole thing is in
# double quotes. The name has one, so the default cannot live there.
if [ -z "${MAINTAINER:-}" ]; then
  MAINTAINER="Ron O'Hara <rono@sentuny.com>"
fi
DESCRIPTION="Thunderbird with GnuPG as the authoritative OpenPGP engine"
HOMEPAGE="${HOMEPAGE:-https://sentuny.com}"

DEST="${DEST:-$HOME}"

# A complete package has 72 entries, not thousands: the chrome lives inside
# omni.ja as a single archive member, so the count is small and stable. Measured
# against the 21 Oct known-good package (72) and the interrupted fragment (15).
# The floor rejects a fragment without asserting an exact count.
MIN_PKG_ENTRIES="${MIN_PKG_ENTRIES:-50}"

JOBS=""
SKIP_BUILD=0
SKIP_PACKAGE=0
DRY_RUN=0
COPY=1
VERSION_SUFFIX=""

# ---------------------------------------------------------------- arguments
usage() {
  sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  cat <<'EOF'

Options
  --skip-build          reuse the existing build; do not run ./mach build
  --skip-package        reuse the existing dist tarball; imply --skip-build
  --jobs N              pass -jN to ./mach build
  --dest DIR            copy the .deb here (default: $HOME)
  --no-copy             build the .deb but do not copy it anywhere
  --version-suffix S    append +S to the Debian version (e.g. a revision)
  --dry-run             print the phases and change nothing
  -h, --help            this text

Environment
  PKG_NAME, MAINTAINER, HOMEPAGE, DEST   overrides for the values above
  EPOCH                                  Debian epoch (default: 1)
  THUNDERBIRD_SRC                        the gecko checkout (default: this tree's root)
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-build)     SKIP_BUILD=1 ;;
    --skip-package)   SKIP_PACKAGE=1; SKIP_BUILD=1 ;;
    --jobs)           JOBS="${2:?--jobs needs a number}"; shift ;;
    --dest)           DEST="${2:?--dest needs a directory}"; shift ;;
    --no-copy)        COPY=0 ;;
    --version-suffix) VERSION_SUFFIX="${2:?--version-suffix needs a value}"; shift ;;
    --dry-run)        DRY_RUN=1 ;;
    -h|--help)        usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [ -n "${THUNDERBIRD_SRC:-}" ]; then
  GECKO_ROOT="$THUNDERBIRD_SRC"
  BRANDING_DIR="$GECKO_ROOT/comm/mail/branding/gnupg"
fi

say()  { printf '\n=== %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
die()  { printf '\n!! %s\n' "$*" >&2; exit 1; }

START_EPOCH=$(date +%s)

# ---------------------------------------------------------------- phase 0
say "Phase 0 - preflight"

[ -x "$GECKO_ROOT/mach" ] || die "no mach at $GECKO_ROOT/mach (set THUNDERBIRD_SRC)"
info "gecko checkout: $GECKO_ROOT"

[ -f "$GECKO_ROOT/mozconfig" ] ||
  die "no mozconfig at $GECKO_ROOT/mozconfig; this script does not write one"
if ! grep -q -- '--enable-project=comm/mail' "$GECKO_ROOT/mozconfig"; then
  die "the mozconfig does not select comm/mail; refusing to build the wrong product"
fi
info "mozconfig selects comm/mail"

command -v dpkg-deb >/dev/null || die "dpkg-deb not found (install dpkg-dev)"
info "dpkg-deb: $(dpkg-deb --version | head -1)"

for tool in tar xz; do
  command -v "$tool" >/dev/null || die "$tool not found"
done
info "tar and xz present"

[ -d "$BRANDING_DIR" ] || die "branding icons not found at $BRANDING_DIR"
info "branding: $BRANDING_DIR"

# The objdir is discovered rather than assumed: a checkout can have more than
# one, and guessing would package a stale one.
find_objdir() {
  local d newest="" newest_time=0
  for d in "$GECKO_ROOT"/obj-*/; do
    [ -d "$d/dist" ] || continue
    local t
    t=$(stat -c %Y "$d/dist" 2>/dev/null || echo 0)
    if [ "$t" -gt "$newest_time" ]; then newest="$d"; newest_time="$t"; fi
  done
  [ -n "$newest" ] && printf '%s' "${newest%/}"
}
OBJDIR="$(find_objdir)"
[ -n "$OBJDIR" ] || die "no obj-*/dist under $GECKO_ROOT; run ./mach build first"
info "objdir: $OBJDIR"

if [ "$DRY_RUN" -eq 1 ]; then
  say "Dry run"
  info "would $([ "$SKIP_BUILD" -eq 1 ] && echo 'skip' || echo 'run') build, $([ "$SKIP_PACKAGE" -eq 1 ] && echo 'skip' || echo 'run') package, stage and build a .deb"
  info "would copy the .deb to: $([ "$COPY" -eq 1 ] && echo "$DEST" || echo '(no copy)')"
  exit 0
fi

# ---------------------------------------------------------------- phase 1
if [ "$SKIP_BUILD" -eq 1 ]; then
  say "Phase 1 - build (skipped)"
else
  say "Phase 1 - build (full, non-artifact)"
  info "this takes a long time; output is your terminal only"
  ( cd "$GECKO_ROOT" && ./mach build ${JOBS:+-j"$JOBS"} )
fi

# ---------------------------------------------------------------- phase 2
if [ "$SKIP_PACKAGE" -eq 1 ]; then
  say "Phase 2 - package (skipped)"
else
  say "Phase 2 - package"
  ( cd "$GECKO_ROOT" && ./mach package )
fi

PKG_FILE="$OBJDIR/dist/package_name.txt"
[ -f "$PKG_FILE" ] || die "no $PKG_FILE; ./mach package did not run"
TARBALL_NAME="$(head -1 "$PKG_FILE")"
TARBALL="$OBJDIR/dist/$TARBALL_NAME"

# One temporary directory for the whole run, removed on exit. Created here
# because the integrity check below writes into it.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tb-deb.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
[ -f "$TARBALL" ] || die "tarball missing: $TARBALL"
info "tarball: $TARBALL"
info "size:    $(du -h "$TARBALL" | cut -f1)"

# A tarball can exist and still be a fragment: `mach package` writes it as it
# works, so a build that is interrupted - or a run whose output was killed -
# leaves a small valid-looking archive behind. Item: a 15 MB, 15-entry tarball
# with no libxul.so would otherwise be packaged into a 15 MB .deb that installs
# and does nothing.
# The listing is taken with tar's own status captured rather than inherited: a
# truncated archive makes tar exit 2, and under `set -o pipefail` that becomes
# the script's exit before any message is printed - the failure would be silent.
# A bad archive is a finding to report, not a reason to die quietly.
TAR_LISTING="$WORK/tarball-listing.txt"
set +e
tar -tJf "$TARBALL" > "$TAR_LISTING" 2> "$WORK/tarball.err"
TAR_STATUS=$?
set -e
TAR_ENTRIES=$(wc -l < "$TAR_LISTING")

info "entries: $TAR_ENTRIES"

[ "$TAR_STATUS" -eq 0 ] ||
  die "the tarball cannot be read whole (tar exit $TAR_STATUS: $(head -1 "$WORK/tarball.err")); it is a partial or truncated package. Remove it and re-run ./mach package."

[ "$TAR_ENTRIES" -ge "$MIN_PKG_ENTRIES" ] ||
  die "the tarball has only $TAR_ENTRIES entries (expected >= $MIN_PKG_ENTRIES); it is a partial package. Remove it and re-run ./mach package."

grep -q '/libxul\.so$' "$TAR_LISTING" ||
  die "the tarball has no libxul.so; it is not a complete package. Remove it and re-run ./mach package."

say "Unpacking"
mkdir -p "$WORK/unpack"
tar -xJf "$TARBALL" -C "$WORK/unpack"
APP_DIR_NAME="$(find "$WORK/unpack" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | head -1)"
[ -n "$APP_DIR_NAME" ] || die "the tarball has no top-level directory"
UNPACKED="$WORK/unpack/$APP_DIR_NAME"
info "app directory: $APP_DIR_NAME"

APP_INI="$UNPACKED/application.ini"
[ -f "$APP_INI" ] || die "no application.ini in $UNPACKED"
APP_VERSION="$(sed -n 's/^Version=//p' "$APP_INI" | head -1)"
BUILD_ID="$(sed -n 's/^BuildID=//p' "$APP_INI" | head -1)"
[ -n "$APP_VERSION" ] || die "no Version in application.ini"
info "version:  $APP_VERSION (build $BUILD_ID)"

# Versioning. Epoch 1 for continuity with the package already on the machine:
# without it this build sorts BELOW the installed 1:160.0a1~… and apt reports a
# downgrade.
#
# The BuildID follows a "+", not a "~". "~" exists to sort a pre-release BELOW
# its release, which is upstream's convention and not this product's: these are
# successive builds of one product, so a later timestamp must sort later. The
# effect of "~" here was that a build without a BuildID outranked every dated
# build made before it.
DEB_VERSION="${EPOCH:-1}:${APP_VERSION}"
[ -n "$BUILD_ID" ] && DEB_VERSION="${DEB_VERSION}+${BUILD_ID}"
[ -n "$VERSION_SUFFIX" ] && DEB_VERSION="${DEB_VERSION}+${VERSION_SUFFIX}"
ARCH="$(dpkg --print-architecture)"

# ---------------------------------------------------------------- phase 3
say "Phase 3 - stage"

STAGE="$WORK/stage"
INSTALL_DIR="$STAGE/usr/lib/$PKG_NAME"
mkdir -p "$INSTALL_DIR" "$STAGE/usr/bin" "$STAGE/usr/share/applications" \
         "$STAGE/DEBIAN"

cp -a "$UNPACKED/." "$INSTALL_DIR/"

# The launcher: the tarball's own wrapper, reached through /usr/bin so the
# desktop entry and a terminal command both find it.
BIN_NAME="$PKG_NAME"
[ -e "$INSTALL_DIR/$BIN_NAME" ] || die "no $BIN_NAME launcher in the app directory"
ln -s "/usr/lib/$PKG_NAME/$BIN_NAME" "$STAGE/usr/bin/$BIN_NAME"

# Desktop entry. The tarball ships none, so this is the one place it exists.
cat > "$STAGE/usr/share/applications/$PKG_NAME.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=Thunderbird GnuPG
GenericName=Mail Client
Comment=$DESCRIPTION
Exec=/usr/bin/$BIN_NAME %u
Icon=$PKG_NAME
Terminal=false
Categories=Network;Email;GTK;
MimeType=message/rfc822;x-scheme-handler/mailto;
StartupNotify=true
StartupWMClass=$BIN_NAME
DESKTOP

# hicolor icons from the variant's branding.
ICON_SIZES="16 22 24 32 48 64 128 256"
for size in $ICON_SIZES; do
  src="$BRANDING_DIR/default${size}.png"
  [ -f "$src" ] || die "missing branding icon: $src"
  dir="$STAGE/usr/share/icons/hicolor/${size}x${size}/apps"
  mkdir -p "$dir"
  cp "$src" "$dir/$PKG_NAME.png"
done
info "icons: $ICON_SIZES"

# Installed-Size is in KiB, as dpkg expects.
INSTALLED_KIB=$(du -sk --exclude=DEBIAN "$STAGE" | cut -f1)

# Dependencies: ask dpkg-shlibdeps rather than hand-writing a list, so a library
# the build starts linking is not silently omitted.
DEPS=""
if command -v dpkg-shlibdeps >/dev/null; then
  SHLIB_DIR="$WORK/shlibdeps"
  mkdir -p "$SHLIB_DIR/debian"
  cat > "$SHLIB_DIR/debian/control" <<CTRL
Source: $PKG_NAME
Section: mail
Priority: optional
Maintainer: $MAINTAINER
Standards-Version: 4.6.0

Package: $PKG_NAME
Architecture: any
Depends: \${shlibs:Depends}
Description: placeholder
CTRL
  # The launcher links only libc/libstdc++; the engine is libxul.so, and every
  # system library the product actually needs is reached through it. Analysing
  # the launcher alone reported three dependencies and left GTK out, which would
  # install and then fail to start. -l lets shlibdeps resolve the libraries the
  # build ships inside the app directory instead of warning about them.
  set +e
  DEPS="$( cd "$SHLIB_DIR" && dpkg-shlibdeps -l"$INSTALL_DIR" -O \
             "$INSTALL_DIR/$BIN_NAME-bin" \
             "$INSTALL_DIR/libxul.so" 2>/dev/null |
           sed -n 's/^shlibs:Depends=//p' )"
  set -e
fi
if [ -z "$DEPS" ]; then
  DEPS="libc6, libgcc-s1, libstdc++6, libgtk-3-0, libgdk-3-0, libglib2.0-0, libpango-1.0-0, libcairo2, libgdk-pixbuf-2.0-0, libatk1.0-0, libdbus-1-3, libx11-6, libxcb1, libxcomposite1, libxdamage1, libxfixes3, libxrandr2, libnspr4, libnss3, libasound2, libfontconfig1, libfreetype6, libgcrypt20"
  info "dpkg-shlibdeps did not answer; using the fallback dependency list"
else
  info "depends: $DEPS"
fi

cat > "$STAGE/DEBIAN/control" <<CONTROL
Package: $PKG_NAME
Version: $DEB_VERSION
Section: mail
Priority: optional
Architecture: $ARCH
Maintainer: $MAINTAINER
Installed-Size: $INSTALLED_KIB
Depends: $DEPS
Homepage: $HOMEPAGE
Description: $DESCRIPTION
 A Thunderbird build in which GnuPG is the authoritative OpenPGP engine and the
 internal implementation is kept only as a constrained fallback.
CONTROL

# Refresh the caches only if the tools are present; never fail an install for it.
cat > "$STAGE/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database -q /usr/share/applications || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -q -t /usr/share/icons/hicolor || true
fi
exit 0
POSTINST
chmod 0755 "$STAGE/DEBIAN/postinst"

# ---------------------------------------------------------------- phase 4
say "Phase 4 - build the .deb"

# The filename omits the epoch, as Debian's own packages do: the epoch belongs
# in the control file, and a colon is legal in a control field but awkward in a
# path. `dpkg -I` still reports the full version.
DEB_FILE="${PKG_NAME}_${DEB_VERSION#*:}_${ARCH}.deb"
OUT="$WORK/$DEB_FILE"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT"

info "deb:  $OUT"
info "size: $(du -h "$OUT" | cut -f1)"

# ---------------------------------------------------------------- phase 5
if [ "$COPY" -eq 1 ]; then
  say "Phase 5 - copy"
  mkdir -p "$DEST"
  cp -- "$OUT" "$DEST/"
  info "copied to: $DEST/$DEB_FILE"
else
  info "not copied (--no-copy); the .deb is in a temporary directory and is about to be removed"
  # Keep it reachable when the caller asked for no copy.
  KEEP="$(pwd)/$DEB_FILE"
  cp -- "$OUT" "$KEEP"
  info "kept at:   $KEEP"
fi

ELAPSED=$(( $(date +%s) - START_EPOCH ))
printf '\n=== Result\n'
printf '    deb:      %s\n' "$DEB_FILE"
printf '    version:  %s\n' "$DEB_VERSION"
printf '    elapsed:  %dm%02ds\n' $((ELAPSED / 60)) $((ELAPSED % 60))
if [ "$COPY" -eq 1 ]; then
  printf '    location: %s/%s\n' "$DEST" "$DEB_FILE"
fi
printf '    install:  sudo apt install ./%s\n\n' "$DEB_FILE"
