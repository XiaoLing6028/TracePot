#!/usr/bin/env bash
# Builds the TracePot AppImage for x86_64 from a clean build directory.
#
#   packaging/appimage/build-appimage.sh
#
# Result: build/appimage/TracePot-<version>-x86_64.AppImage (+ .sha256)
#
# Build requirements: the regular build dependencies (see README.md), Qt 6 Wayland client
# plugins (Debian/Ubuntu: qt6-wayland, Fedora: qt6-qtwayland), rsvg-convert (Debian/Ubuntu:
# librsvg2-bin, Fedora: librsvg2-tools), curl and sha256sum. The packaging tools below are
# downloaded once into build/appimage-tools and verified against pinned SHA-256 checksums.
# No FUSE is needed to build: the tools run with APPIMAGE_EXTRACT_AND_RUN=1.
#
# Environment:
#   QMAKE              qmake of the Qt 6 installation to bundle (default: qmake6 from PATH)
#   SOURCE_DATE_EPOCH  timestamp for the files in the image (default: time of the last commit)

set -euo pipefail

readonly LINUXDEPLOY_VERSION=1-alpha-20251107-1
readonly LINUXDEPLOY_SHA256=c20cd71e3a4e3b80c3483cef793cda3f4e990aca14014d23c544ca3ce1270b4d
readonly LINUXDEPLOY_QT_VERSION=1-alpha-20250213-1
readonly LINUXDEPLOY_QT_SHA256=15106be885c1c48a021198e7e1e9a48ce9d02a86dd0a1848f00bdbf3c1c92724
readonly APPIMAGETOOL_VERSION=1.9.1
readonly APPIMAGETOOL_SHA256=ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0
readonly RUNTIME_VERSION=20251108
readonly RUNTIME_SHA256=2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d

export ARCH=x86_64
SOURCE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
readonly ARCH SOURCE_DIR
readonly WORK_DIR=$SOURCE_DIR/build/appimage
readonly TOOLS_DIR=$SOURCE_DIR/build/appimage-tools
readonly APPDIR=$WORK_DIR/AppDir

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

require() {
    command -v "$1" >/dev/null 2>&1 || die "$1 is required${2:+ ($2)}"
}

# Downloads a pinned file once and verifies its checksum on every run.
fetch() {
    local url=$1 sha256=$2 dest=$TOOLS_DIR/$3
    if [[ -f $dest ]] && echo "$sha256  $dest" | sha256sum --check --status; then
        return
    fi
    echo "Downloading $url"
    curl --fail --location --retry 3 --silent --show-error --output "$dest.part" "$url"
    echo "$sha256  $dest.part" | sha256sum --check --status || {
        rm -f "$dest.part"
        die "checksum mismatch for $url"
    }
    chmod +x "$dest.part"
    mv "$dest.part" "$dest"
}

is_elf() {
    [[ $(od -An -tx1 -N4 "$1" 2>/dev/null | tr -d ' \n') == 7f454c46 ]]
}

[[ $(uname -m) == "$ARCH" ]] || die "the AppImage must be built on $ARCH (this machine is $(uname -m))"
require cmake
require curl
require sha256sum
require rsvg-convert "Debian/Ubuntu: librsvg2-bin, Fedora: librsvg2-tools"
require ldd
require readelf

QMAKE=${QMAKE:-$(command -v qmake6 || true)}
[[ -n $QMAKE && -x $QMAKE ]] || die "Qt 6 qmake not found; set QMAKE=/path/to/qt6/bin/qmake"
[[ $("$QMAKE" -query QT_VERSION) == 6.* ]] || die "$QMAKE does not belong to Qt 6"
export QMAKE

if [[ -z ${SOURCE_DATE_EPOCH:-} ]] && git -C "$SOURCE_DIR" rev-parse --git-dir >/dev/null 2>&1; then
    SOURCE_DATE_EPOCH=$(git -C "$SOURCE_DIR" log -1 --format=%ct)
fi
[[ -n ${SOURCE_DATE_EPOCH:-} ]] && export SOURCE_DATE_EPOCH

log "Fetching packaging tools"
mkdir -p "$TOOLS_DIR"
fetch "https://github.com/linuxdeploy/linuxdeploy/releases/download/$LINUXDEPLOY_VERSION/linuxdeploy-$ARCH.AppImage" \
    "$LINUXDEPLOY_SHA256" "linuxdeploy-$ARCH.AppImage"
fetch "https://github.com/linuxdeploy/linuxdeploy-plugin-qt/releases/download/$LINUXDEPLOY_QT_VERSION/linuxdeploy-plugin-qt-$ARCH.AppImage" \
    "$LINUXDEPLOY_QT_SHA256" "linuxdeploy-plugin-qt-$ARCH.AppImage"
fetch "https://github.com/AppImage/appimagetool/releases/download/$APPIMAGETOOL_VERSION/appimagetool-$ARCH.AppImage" \
    "$APPIMAGETOOL_SHA256" "appimagetool-$ARCH.AppImage"
fetch "https://github.com/AppImage/type2-runtime/releases/download/$RUNTIME_VERSION/runtime-$ARCH" \
    "$RUNTIME_SHA256" "runtime-$ARCH"
# The tools are AppImages themselves; extracting them on the fly avoids needing FUSE.
export APPIMAGE_EXTRACT_AND_RUN=1
export PATH=$TOOLS_DIR:$PATH

log "Building TracePot in a clean build directory"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
generator=()
command -v ninja >/dev/null 2>&1 && generator=(-G Ninja)
cmake -S "$SOURCE_DIR" -B "$WORK_DIR/cmake" "${generator[@]}" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DBUILD_TESTING=OFF \
    -DTRACEPOT_BUILD_GUI=ON
cmake --build "$WORK_DIR/cmake" --parallel
DESTDIR=$APPDIR cmake --install "$WORK_DIR/cmake"

version=$("$APPDIR/usr/bin/tracepot" version | awk '{print $2}')
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] || die "cannot determine the TracePot version (got '$version')"
readonly OUTPUT=$WORK_DIR/TracePot-$version-$ARCH.AppImage

# A PNG icon for .DirIcon and desktop integration tools; the SVG is installed by CMake.
icon_png=$APPDIR/usr/share/icons/hicolor/256x256/apps/tracepot.png
mkdir -p "$(dirname "$icon_png")"
rsvg-convert --width 256 --height 256 "$SOURCE_DIR/data/tracepot.svg" --output "$icon_png"

log "Bundling libraries and Qt plugins"
# tracepot-limits only needs libc and libstdc++ (taken from the host); passing it with --executable
# would copy it into usr/bin, so it stays in usr/libexec/tracepot where TracePot looks for it.
# Wayland: the platform plugins alone cannot open windows. In this plugin version the
# "waylandcompositor" module is what deploys the client-side shell integration (xdg-shell),
# decoration and graphics integration plugins; it does not bundle the compositor library.
# offscreen allows headless use.
EXTRA_PLATFORM_PLUGINS="libqwayland-egl.so;libqwayland-generic.so;libqoffscreen.so" \
EXTRA_QT_MODULES="waylandcompositor" \
    "$TOOLS_DIR/linuxdeploy-$ARCH.AppImage" \
    --appdir "$APPDIR" \
    --desktop-file "$APPDIR/usr/share/applications/tracepot.desktop" \
    --icon-file "$icon_png" \
    --custom-apprun "$SOURCE_DIR/packaging/appimage/AppRun" \
    --plugin qt

# .DirIcon is what file managers and thumbnailers show; it should be the PNG.
rm -f "$APPDIR/tracepot.svg" "$APPDIR/tracepot.png" "$APPDIR/.DirIcon"
ln -s usr/share/icons/hicolor/256x256/apps/tracepot.png "$APPDIR/tracepot.png"
ln -s tracepot.png "$APPDIR/.DirIcon"

log "Checking the AppDir"
[[ -x $APPDIR/usr/libexec/tracepot/tracepot-limits ]] || die "tracepot-limits helper missing"
for plugin in platforms/libqxcb.so platforms/libqwayland-generic.so wayland-shell-integration/libxdg-shell.so; do
    [[ -f $APPDIR/usr/plugins/$plugin ]] || die "Qt plugin $plugin missing (are the Qt 6 Wayland plugins installed?)"
done
problems=0
while IFS= read -r -d '' file; do
    is_elf "$file" || continue
    missing=$(ldd "$file" 2>&1 | grep 'not found' || true)
    if [[ -n $missing ]]; then
        printf 'unresolved dependency in %s:\n%s\n' "${file#"$APPDIR"/}" "$missing" >&2
        problems=1
    fi
    rpath=$(readelf -d "$file" | sed -nE 's/.*\((RPATH|RUNPATH)\).*\[(.*)\]$/\2/p')
    IFS=: read -ra entries <<<"$rpath"
    for entry in "${entries[@]}"; do
        if [[ $entry != "\$ORIGIN"* ]]; then
            printf 'non-relocatable RPATH entry %s in %s\n' "$entry" "${file#"$APPDIR"/}" >&2
            problems=1
        fi
    done
done < <(find "$APPDIR/usr" -type f -print0)
((problems == 0)) || die "the AppDir is not self-contained"

log "Creating $OUTPUT"
VERSION=$version "$TOOLS_DIR/appimagetool-$ARCH.AppImage" \
    --runtime-file "$TOOLS_DIR/runtime-$ARCH" \
    --no-appstream \
    "$APPDIR" "$OUTPUT"
chmod 0755 "$OUTPUT"
(cd "$WORK_DIR" && sha256sum "$(basename "$OUTPUT")" >"$(basename "$OUTPUT").sha256")

log "Done"
echo "AppImage: ${OUTPUT#"$SOURCE_DIR"/}"
echo "Size:     $(stat -c %s "$OUTPUT") bytes"
echo "SHA-256:  $(cut -d ' ' -f 1 "$OUTPUT.sha256")"
