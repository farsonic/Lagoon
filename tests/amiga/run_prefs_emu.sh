#!/bin/sh
# Lagoon - LagoonPrefs on the emulated A1200 (tests/amiga/run_emu.sh), driven
# with the keyboard through xdotool on the harness's Xvfb display: main
# window, share editor (existing and new share, password shown as '*'),
# network browser against tests/servers/mdns/responder.py and a private nmbd
# on the host side of the veth, Save; then ENVARC:/ENV: lagoon.conf are
# checked. Screenshots go to OUTDIR (default: a temporary directory).
#
#   tests/amiga/run_prefs_emu.sh [OUTDIR] [pal|ntsc] [LANGUAGE]
#
# LANGUAGE (e.g. deutsch) starts LagoonPrefs with LANGUAGE=..., using the
# catalogs from build/amiga/catalogs (tools/mkpackage.sh builds them).
# Needs root, xdotool, ImageMagick, python3; nmbd is optional.
# SPDX-License-Identifier: GPL-2.0-only
set -u
here=$(cd "$(dirname "$0")" && pwd)
top=$(cd "$here/../.." && pwd)
S=${TMPDIR:-/tmp}
out=${1:-$(mktemp -d "$S/lagoon-prefs-emu.XXXXXX")}
mode=${2:-pal}
lang=${3:-}
mkdir -p "$out"
out=$(cd "$out" && pwd)
export DISPLAY=:97
ptr="python3 $here/fsuae_pointer.py"
[ -f "$top/build/amiga/LagoonPrefs" ] || { echo "SKIP: build/amiga/LagoonPrefs not built"; exit 77; }
command -v xdotool >/dev/null 2>&1 || { echo "SKIP: no xdotool"; exit 77; }

extra=$(mktemp -d "$S/lagoon-prefs-dh0.XXXXXX")
mkdir -p "$extra/ENVARC/Lagoon" "$extra/ENV/Lagoon" "$extra/C"
cat > "$extra/ENVARC/Lagoon/lagoon.conf" <<'CONF'
# Lagoon shares (emulator test)
share name="NAS" url="smb://nas.local/Public" user="bob" automount=yes
share name="iMac" url="afp://imac.local/Macintosh%20HD/Users/bob" user="bob" readonly=yes
share name="Linux" url="nfs://192.168.78.1/srv/lagoon?uid=1000&gid=1000"
option loglevel=1 colour=blue
CONF
cp "$extra/ENVARC/Lagoon/lagoon.conf" "$extra/ENV/Lagoon/"
if [ -d "$top/build/amiga/catalogs" ]; then
	cp -r "$top/build/amiga/catalogs" "$extra/C/Catalogs"
fi
cmds=$extra/cmds
largs=""
[ -n "$lang" ] && largs="LANGUAGE=$lang"
# the ROM's Assign fails in the harness: assign with a helper first
VBCC=${VBCC:-/opt/amiga/vbcc}
PATH=$VBCC/bin:$PATH VBCC=$VBCC "$VBCC/bin/vc" +aos68k -O2 -I/opt/amiga/ndk/Include_H -o "$extra/C/tassign" \
	"$here/tassign.c" -lamiga || { echo "FAIL: cannot build tassign"; exit 1; }
{
	echo "as1|DH0:C/tassign ENV DH0:ENV"
	echo "as2|DH0:C/tassign ENVARC DH0:ENVARC"
	echo "as3|DH0:C/tassign T DH0:T"
	echo "prefs|DH0:C/LagoonPrefs $largs DEBUG"
} > "$cmds"
# FS-UAE turns the cursor keys into a joystick unless told otherwise
fx="joystick_port_1 = none"
[ "$mode" = ntsc ] && fx="$fx
ntsc_mode = 1"

mkdir -p "$out/emu"
TMPDIR=$out/emu LAGOON_DH0_EXTRA=$extra FSUAE_EXTRA="$fx" "$here/run_emu.sh" "$cmds" 240 "$top/build/amiga/LagoonPrefs" > "$out/run_emu.log" 2>&1 &
epid=$!

# run_emu.sh serializes runs: wait until OUR emulator runs (other runs use
# the same display and veth), then start the mDNS responder and nmbd on it
t=0
while [ $t -lt 1800 ] && ! pgrep -f "fs-uae $out/emu/lagoon-emu" >/dev/null; do
	kill -0 $epid 2>/dev/null || { echo "FAIL: run_emu.sh ended early"; cat "$out/run_emu.log"; exit 1; }
	sleep 1
	t=$((t + 1))
done
python3 "$top/tests/servers/mdns/responder.py" --mcast 192.168.78.1 --addr 192.168.78.1 > "$out/responder.log" 2>&1 &
rpid=$!
nbdir=$(mktemp -d "$S/lagoon-prefs-nb.XXXXXX")
nbpid=
if command -v nmbd >/dev/null 2>&1; then
	mkdir -p "$nbdir/nmbd"
	cat > "$nbdir/smb.conf" <<CONF
[global]
netbios name = OLDNAS
workgroup = HOME
interfaces = lgbr1
bind interfaces only = yes
lock directory = $nbdir
state directory = $nbdir
cache directory = $nbdir
private dir = $nbdir
pid directory = $nbdir
ncalrpc dir = $nbdir
log file = $nbdir/log.nmbd
nmbd:socket dir = $nbdir/nmbd
CONF
	nmbd -F --debug-stdout -d 3 --no-process-group -s "$nbdir/smb.conf" > "$out/nmbd.log" 2>&1 &
	nbpid=$!
fi
cleanup() {
	[ -n "$rpid" ] && kill $rpid 2>/dev/null
	[ -n "$nbpid" ] && kill $nbpid 2>/dev/null
	rpid= nbpid=
}
trap cleanup EXIT

fails=0
fail() { echo "FAIL $*"; fails=$((fails + 1)); }
# never type into another run's emulator (the display is shared, runs queue)
mine() {
	pgrep -f "fs-uae $out/emu/lagoon-emu" >/dev/null && return 0
	echo "FAIL: our emulator is gone (LagoonPrefs quit early?)"
	exit 1
}
key() { for k in "$@"; do mine; xdotool key "$k"; sleep 0.4; done; }
typ() { mine; xdotool type --delay 120 "$1"; sleep 0.3; }
shot() { mine; $ptr stable 2 90 >/dev/null || fail "screen did not settle before $1"; $ptr shot "$out/$1.png"; }

# boot + Riptide + window; click into it so it has the keyboard
sleep 25
mine
$ptr stable 2 90 >/dev/null
mine
$ptr click 560 270 >/dev/null
if [ -n "$lang" ]; then
	# a translation: main window and editor (Return/Esc work in every language)
	shot 01-main-$lang
	key Down Return
	shot 02-editor-$lang
	key Escape
	sleep 1
	key Down Down Return
	shot 03-editor-nfs-$lang
	key Escape
	sleep 1
	key Escape
else
	shot 01-main
	key Down
	shot 02-main-selected
	key e
	shot 03-editor-smb
	key Escape
	sleep 1
	key Down Down
	key e
	shot 03b-editor-nfs
	key Escape
	sleep 1
	# a new share by hand
	key a
	sleep 2
	key v
	typ 192.168.78.1
	key Return h
	typ Music
	key Return e
	typ alice
	key Return w
	typ lagoon-test-pw
	key Return
	key u
	shot 04-editor-new
	key o
	sleep 1
	shot 05-main-added
	# browse: mDNS + NetBIOS take ~5 s
	key b
	sleep 8
	shot 06-browse
	key Down Down
	shot 06b-browse-selected
	key Return
	sleep 3
	shot 07-editor-from-browse
	key Escape
	sleep 1
	key s
fi
t=0
while [ $t -lt 60 ] && kill -0 $epid 2>/dev/null; do sleep 1; t=$((t + 1)); done
wait $epid
work=$(sed -n 's/.*work dir \(.*\)$/\1/p' "$out/run_emu.log")
cleanup
[ -n "$work" ] || { fail "no emulator work dir"; cat "$out/run_emu.log"; exit 1; }
conf=$work/dh0/ENVARC/Lagoon/lagoon.conf
cp "$conf" "$out/lagoon.conf" 2>/dev/null
if [ -n "$lang" ]; then
	cmp -s "$conf" "$extra/ENVARC/Lagoon/lagoon.conf" || fail "Cancel changed lagoon.conf"
	echo "output: $out (emulator work dir $work)"
	[ $fails -eq 0 ] && echo "ok   LagoonPrefs on the emulator ($mode, $lang)"
	exit $fails
fi
grep -q 'name="Music" url="smb://192.168.78.1/Music" user="alice" pass="~' "$conf" || fail "new share not saved: $(cat "$conf")"
grep -q 'lagoon-test-pw' "$conf" && fail "password in clear text"
grep -q 'colour="blue"' "$conf" || fail "unknown option lost"
grep -q 'name="Linux" url="nfs://192.168.78.1/srv/lagoon?uid=1000&gid=1000"' "$conf" || fail "NFS share changed"
cmp -s "$conf" "$work/dh0/ENV/Lagoon/lagoon.conf" || fail "ENV: and ENVARC: differ"
[ -f "$conf.bak" ] || fail "no lagoon.conf.bak"
grep -q "query from 192.168.78.2" "$out/responder.log" || fail "no mDNS query from the Amiga"
echo "output: $out (emulator work dir $work)"
[ $fails -eq 0 ] && echo "ok   LagoonPrefs on the emulator ($mode${lang:+, $lang})"
exit $fails
