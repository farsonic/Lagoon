#!/bin/sh
# Lagoon - assemble the Amiga distribution package (make package).
#
#   tools/mkpackage.sh [BUILDDIR [OUTDIR [VERSION]]]
#
# Defaults: build/amiga, build, 0.2. Builds OUTDIR/package/Lagoon/ (+ .info):
#
#   Install_Lagoon(.info)    Installer script and its icon
#   ReadMe(.info)            short instructions
#   Lagoon.readme            Aminet readme
#   C/Lagoon                 the command
#   L/lagoon-handler         the file system handler
#   Prefs/LagoonPrefs(.info) the share list editor
#   Catalogs/<lang>/         locale catalogs (tools/mkcatalog.py, from every
#                            src/amiga/*/catalogs/*.cd and its .ct files);
#                            <lang> is the .ct name in ASCII (francais):
#                            Install_Lagoon copies them to LOCALE:Catalogs/
#                            under the language names (fran\347ais)
#   Docs/(.info)             README.md, LICENSE and docs/*.md but DESIGN.md
#                            (each with an icon)
#
# and from it OUTDIR/lagoon-VERSION.lha (with "LHa for UNIX" lha or jlha;
# LHA=... picks one; a .zip otherwise), OUTDIR/lagoon-VERSION.readme and an
# 880 KB OUTDIR/lagoon-VERSION.adf (with amitools' xdftool, if installed).
# Finally the package is checked for certificates and private keys.
# ALLOW_MISSING=1 packages even when C:Lagoon or lagoon-handler are not built
# (for testing the package flow only).
# Adapted from Riptide's tools/mkpackage.sh (same author, GPL-2.0-only).
# SPDX-License-Identifier: GPL-2.0-only
set -eu
top=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${1:-$top/build/amiga}
OUT=${2:-$top/build}
VERSION=${3:-0.2}
PYTHON=${PYTHON:-python3}
mkicon="$PYTHON $top/tools/mkicon.py"
trash=$OUT/.trash
mkdir -p "$OUT" "$trash"

# move an old file/dir out of the way (we never delete with rm -rf)
aside() {
	[ -e "$1" ] || return 0
	mv "$1" "$trash/$(basename "$1").$(date +%s).$$"
}

missing=0
for f in Lagoon lagoon-handler LagoonPrefs; do
	if [ ! -f "$BUILD/$f" ]; then
		echo "mkpackage: $BUILD/$f is missing (make amiga)" >&2
		missing=1
	fi
done
[ $missing -eq 0 ] || [ "${ALLOW_MISSING:-}" = 1 ] || exit 1
[ -f "$BUILD/LagoonPrefs" ] || exit 1

stage=$OUT/package
pkg=$stage/Lagoon
aside "$stage"
mkdir -p "$pkg/C" "$pkg/L" "$pkg/Prefs" "$pkg/Docs" "$pkg/Catalogs"

# programs
[ -f "$BUILD/Lagoon" ] && cp "$BUILD/Lagoon" "$pkg/C/Lagoon" && chmod 755 "$pkg/C/Lagoon"
[ -f "$BUILD/lagoon-handler" ] && cp "$BUILD/lagoon-handler" "$pkg/L/lagoon-handler"
cp "$BUILD/LagoonPrefs" "$pkg/Prefs/LagoonPrefs"
chmod 755 "$pkg/Prefs/LagoonPrefs"

# catalogs: build/amiga/catalogs/<lang>/<name>.catalog
cats=$BUILD/catalogs
aside "$cats"
mkdir -p "$cats"
for cd in "$top"/src/amiga/*/catalogs/*.cd; do
	[ -f "$cd" ] || continue
	name=$(basename "$cd" .cd)
	dir=$(dirname "$cd")
	$PYTHON "$top/tools/mkcatalog.py" check "$cd" "$dir"/*.ct
	for ct in "$dir"/*.ct; do
		[ -f "$ct" ] || continue
		lang=$(basename "$ct" .ct)
		mkdir -p "$cats/$lang"
		$PYTHON "$top/tools/mkcatalog.py" catalog "$cd" "$ct" "$cats/$lang/$name.catalog"
	done
done
cp -R "$cats/." "$pkg/Catalogs/"

# installer, readmes
cp "$top/install/Install_Lagoon" "$pkg/Install_Lagoon"
sed "s/@VERSION@/$VERSION/g" "$top/install/ReadMe" > "$pkg/ReadMe"
sed "s/@VERSION@/$VERSION/g" "$top/install/Lagoon.readme" > "$pkg/Lagoon.readme"

# documentation (Markdown reads fine as text in MultiView)
docs="README.md LICENSE"
for f in "$top"/docs/*.md; do
	case "$f" in */DESIGN.md) ;; *) docs="$docs docs/$(basename "$f")" ;; esac
done
for f in $docs; do
	[ -f "$top/$f" ] && cp "$top/$f" "$pkg/Docs/"
done

# icons
$mkicon drawer  "$stage/Lagoon.info" --image drawer --window 60,40,420,140
$mkicon project "$pkg/Install_Lagoon.info" --image install --tool Installer --stack 20000 --pos 20,10 \
	--tooltype APPNAME=Lagoon --tooltype MINUSER=NOVICE --tooltype DEFUSER=NOVICE
$mkicon project "$pkg/ReadMe.info" --image doc --tool SYS:Utilities/MultiView --pos 150,10
$mkicon drawer  "$pkg/Docs.info" --image docs --window 80,60,420,120 --pos 230,10
$mkicon drawer  "$pkg/Prefs.info" --image drawer --window 90,70,300,90 --pos 310,10
$mkicon tool    "$pkg/Prefs/LagoonPrefs.info" --image prefs --stack 32768 --pos 20,10
x=10 y=8
for f in "$pkg"/Docs/*; do
	case "$f" in *.info) continue ;; esac
	$mkicon project "$f.info" --image doc --tool SYS:Utilities/MultiView --pos $x,$y
	x=$((x + 130))
	[ $x -gt 300 ] && x=10 y=$((y + 45))
done

# stable time stamps inside the archives
find "$stage" -exec touch -d "@${SOURCE_DATE_EPOCH:-$(git -C "$top" log -1 --format=%ct 2>/dev/null || date +%s)}" {} +

# nothing secret may ship: certificates, keys
bad=$(find "$stage" \( -iname '*.crt' -o -iname '*.pem' -o -iname '*.key' -o -iname '*.p12' -o -iname 'id_rsa*' \) -print)
if [ -n "$bad" ] || grep -rlE "BEGIN (CERTIFICATE|[A-Z ]*PRIVATE KEY)" "$stage" >/dev/null 2>&1; then
	echo "mkpackage: certificates or keys in the package: $bad $(grep -rlE 'BEGIN (CERTIFICATE|[A-Z ]*PRIVATE KEY)' "$stage")" >&2
	exit 1
fi

name=lagoon-$VERSION
for f in "$OUT/$name.lha" "$OUT/$name.zip" "$OUT/$name.adf"; do aside "$f"; done
cp "$pkg/Lagoon.readme" "$OUT/$name.readme"

# ---- LHA ----
lha_kind() {
	# "LHa for UNIX" (can write) vs lhasa's lha (extract only); jlha
	case "$1" in
	*jlha*) command -v "$1" >/dev/null 2>&1 && echo jlha ;;
	*) command -v "$1" >/dev/null 2>&1 && "$1" --version 2>&1 | grep -q "LHa for UNIX" && echo lha ;;
	esac
}
kind=
if [ -n "${LHA:-}" ]; then
	kind=$(lha_kind "$LHA" || true)
	[ -n "$kind" ] || { echo "mkpackage: LHA=$LHA cannot write archives" >&2; exit 1; }
else
	for c in lha jlha; do
		kind=$(lha_kind "$c" || true)
		[ -n "$kind" ] && { LHA=$c; break; }
	done
fi
abs_out=$(cd "$OUT" && pwd)
case "$kind" in
lha)
	(cd "$stage" && "$LHA" -aq2o5 "$abs_out/$name.lha" Lagoon.info Lagoon >/dev/null)
	echo "mkpackage: $OUT/$name.lha" ;;
jlha)
	(cd "$stage" && "$LHA" a2o5q "$abs_out/$name.lha" Lagoon.info $(find Lagoon -type f | LC_ALL=C sort) >/dev/null 2>&1)
	echo "mkpackage: $OUT/$name.lha (jlha)" ;;
*)
	echo "mkpackage: no LHA archiver that can write archives (lha or jlha); making a zip" >&2
	(cd "$stage" && zip -qrX "$abs_out/$name.zip" Lagoon.info Lagoon)
	echo "mkpackage: $OUT/$name.zip" ;;
esac

# ---- ADF ----
if command -v xdftool >/dev/null 2>&1; then
	adf=$OUT/$name.adf
	xdftool "$adf" create + format "Lagoon" ffs >/dev/null
	xdftool "$adf" write "$stage/Lagoon.info" >/dev/null
	if xdftool "$adf" write "$pkg" >/dev/null 2>&1; then
		echo "mkpackage: $adf"
	else
		echo "mkpackage: the package does not fit on an 880 KB floppy; no ADF" >&2
		aside "$adf"
	fi
else
	echo "mkpackage: xdftool (amitools) not found; no ADF" >&2
fi
[ $missing -eq 0 ] || echo "mkpackage: WARNING: incomplete package (ALLOW_MISSING=1)" >&2
