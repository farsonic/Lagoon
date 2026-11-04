#!/bin/sh
# Lagoon - check the .info files of the Amiga package (after Riptide's
# tests/amiga/check_icons.sh, same author): every icon is parsed back with
# tools/mkicon.py dump (magic, version, image sizes, default tool,
# tooltypes, drawer data, no trailing bytes), and the tools and drawers
# have the expected types.
#
#   tests/amiga/check_icons.sh [PACKAGEDIR]     (default build/package)
# SPDX-License-Identifier: GPL-2.0-only
set -u
PKG=${1:-build/package}
here=$(cd "$(dirname "$0")/../.." && pwd)
fails=0
n=0
for f in $(find "$PKG" -name '*.info' | sort); do
	if out=$(python3 "$here/tools/mkicon.py" dump "$f" 2>&1); then
		n=$((n + 1))
		t=$(echo "$out" | sed -n 's/^type *//p')
		case "$f" in
		*/LagoonPrefs.info) [ "$t" = TOOL ] || { echo "FAIL $f: type $t, expected TOOL"; fails=$((fails + 1)); }
			echo "$out" | grep -q '^stack *32768' || { echo "FAIL $f: stack"; fails=$((fails + 1)); } ;;
		*/Lagoon.info|*/Docs.info|*/Prefs.info) [ "$t" = DRAWER ] || { echo "FAIL $f: type $t"; fails=$((fails + 1)); } ;;
		*/Install_Lagoon.info) echo "$out" | grep -q '^default_tool *Installer' || { echo "FAIL $f: tool"; fails=$((fails + 1)); } ;;
		*) [ "$t" = PROJECT ] || { echo "FAIL $f: type $t"; fails=$((fails + 1)); } ;;
		esac
	else
		echo "FAIL $f does not parse: $out"; fails=$((fails + 1))
	fi
done
[ $n -gt 0 ] || { echo "SKIP: no .info files in $PKG (make package)"; exit 77; }
[ $fails -eq 0 ] && echo "ok   $n icons parse" && exit 0
exit 1
