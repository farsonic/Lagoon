#!/bin/sh
# Lagoon - sharing Amiga folders, on the emulated A1200 (tests/amiga/run_emu.sh):
# LagoonPrefs' Sharing window driven with the keyboard (xdotool): a guest
# folder and a password folder, a user with a password, Start at boot, Start
# server; then smbclient (and impacket, if $LAGOON_PY has it) on this host
# use the Amiga's shares: list, get, put, mkdir, rename, delete, every
# dialect with signing, wrong password and guest refusals, NetBIOS node
# status and an mDNS answer; then Stop server, OK, Save, and lagoon.conf is
# checked (export lines, an NT hash, never the password). Screenshots go to
# OUTDIR (default: a temporary directory).
#
#   tests/amiga/run_share_emu.sh [OUTDIR]
#
# Needs root, xdotool, ImageMagick, python3, smbclient; build/amiga/ built.
# SPDX-License-Identifier: GPL-2.0-only
set -u
here=$(cd "$(dirname "$0")" && pwd)
top=$(cd "$here/../.." && pwd)
S=${TMPDIR:-/tmp}
out=${1:-$(mktemp -d "$S/lagoon-share-emu.XXXXXX")}
mkdir -p "$out"
out=$(cd "$out" && pwd)
export DISPLAY=:97
ptr="python3 $here/fsuae_pointer.py"
A=192.168.78.2
PW='Corr3ct-Horse'
for f in LagoonPrefs Lagoon; do [ -f "$top/build/amiga/$f" ] || { echo "SKIP: build/amiga/$f not built"; exit 77; }; done
command -v xdotool >/dev/null 2>&1 || { echo "SKIP: no xdotool"; exit 77; }
command -v smbclient >/dev/null 2>&1 || { echo "SKIP: no smbclient"; exit 77; }

extra=$(mktemp -d "$S/lagoon-share-dh0.XXXXXX")
mkdir -p "$extra/ENVARC/Lagoon" "$extra/ENV/Lagoon" "$extra/Pub" "$extra/Priv" "$extra/S"
echo "hello from the emulated Amiga" > "$extra/Pub/hello.txt"
cat > "$extra/ENVARC/Lagoon/lagoon.conf" <<'CONF'
# Lagoon shares (emulator test)
share name="NAS" url="smb://nas.local/Public" user="bob" automount=no
CONF
cp "$extra/ENVARC/Lagoon/lagoon.conf" "$extra/ENV/Lagoon/"
# the server's log, once LagoonPrefs starts it
cmds=$extra/cmds
VBCC=${VBCC:-/opt/amiga/vbcc}
PATH=$VBCC/bin:$PATH VBCC=$VBCC "$VBCC/bin/vc" +aos68k -O2 -I/opt/amiga/ndk/Include_H -o "$extra/C_tassign" \
	"$here/tassign.c" -lamiga || { echo "FAIL: cannot build tassign"; exit 1; }
mkdir -p "$extra/C"
mv "$extra/C_tassign" "$extra/C/tassign"
{
	echo "as1|DH0:C/tassign ENV DH0:ENV"
	echo "as2|DH0:C/tassign ENVARC DH0:ENVARC"
	echo "as3|DH0:C/tassign T DH0:T"
	echo "prefs|DH0:C/LagoonPrefs DEBUG"
	echo "after|DH0:C/Lagoon SHARE"
} > "$cmds"
fx="joystick_port_1 = none"
mkdir -p "$out/emu"
TMPDIR=$out/emu LAGOON_DH0_EXTRA=$extra FSUAE_EXTRA="$fx" "$here/run_emu.sh" "$cmds" 420 \
	"$top/build/amiga/LagoonPrefs" "$top/build/amiga/Lagoon" > "$out/run_emu.log" 2>&1 &
epid=$!
t=0
while [ $t -lt 1800 ] && ! pgrep -f "fs-uae $out/emu/lagoon-emu" >/dev/null; do
	kill -0 $epid 2>/dev/null || { echo "FAIL: run_emu.sh ended early"; cat "$out/run_emu.log"; exit 1; }
	sleep 1
	t=$((t + 1))
done

fails=0
fail() { echo "FAIL $*"; fails=$((fails + 1)); }
ok() { echo "ok   $*"; }
mine() {
	pgrep -f "fs-uae $out/emu/lagoon-emu" >/dev/null && return 0
	echo "FAIL: our emulator is gone (LagoonPrefs quit early?)"
	exit 1
}
key() { for k in "$@"; do mine; xdotool key "$k"; sleep 0.5; done; }
typ() { mine; xdotool type --delay 120 "$1"; sleep 0.3; }
shot() { mine; $ptr stable 2 90 >/dev/null || fail "screen did not settle before $1"; $ptr shot "$out/$1.png"; }

sleep 25
mine
$ptr stable 2 90 >/dev/null
$ptr click 560 270 >/dev/null
shot 01-main
key h
sleep 2
shot 02-sharing-empty
# a guest folder: Add, name, folder, guests
key a
sleep 2
typ Public
key Return f
typ DH0:Pub
key Return m
typ "Amiga files"
key Return g
shot 03-folder-guest
key o
sleep 2
# a password folder for bob: OK warns that nobody can use it yet
key a
sleep 2
typ Private
key Return f
typ DH0:Priv
key Return u
typ bob
key Return
shot 04-folder-private
key o
sleep 2
shot 04b-nobody-warning
key super+v
sleep 1
# the user
key s
sleep 2
key a
sleep 2
typ bob
key Return w
typ "$PW"
key Return f
typ "$PW"
key Return
shot 05-user-new
key o
sleep 1
shot 06-users
key o
sleep 1
key b
shot 07-sharing
# Start server: it reads ENV:, which Start writes
key t
sleep 12
shot 08-running

SC="timeout 120 smbclient -p 445"
o=$out/smb.out
if $SC -N -L //$A > "$o" 2>&1 && grep -q "Public *Disk *Amiga files" "$o" && grep -q "Private *Disk" "$o"; then ok "share list from the Amiga"; else fail "share list"; cat "$o"; fi
head -c 200000 /dev/urandom > "$out/big.bin"
rm -f "$out/big.got"
if $SC -N //$A/Public -c "get hello.txt $out/hello.got; put $out/big.bin big.bin; mkdir New; rename big.bin New/m.bin; get New/m.bin $out/big.got; del New/m.bin; rmdir New" > "$o" 2>&1 &&
   cmp -s "$out/big.bin" "$out/big.got" && grep -q "emulated Amiga" "$out/hello.got"; then
	ok "guest share: get, put 200 KB, mkdir, rename, get back identical, delete, rmdir"
else fail "guest share"; cat "$o"; fi
for p in SMB2_02 SMB2_10 SMB3_00 SMB3_02 SMB3_11; do
	rm -f "$out/x.got"
	if $SC -U "bob%$PW" -m $p --option="client signing=required" //$A/Private -c "put $out/hello.got h.txt; get h.txt $out/x.got; del h.txt" > "$o" 2>&1 &&
	   cmp -s "$out/hello.got" "$out/x.got"; then ok "bob, $p, signed"; else fail "bob $p"; cat "$o"; fi
done
$SC -U 'bob%wrong' //$A/Private -c ls > "$o" 2>&1; grep -q LOGON_FAILURE "$o" && ok "wrong password refused" || { fail "wrong password"; cat "$o"; }
$SC -N //$A/Private -c ls > "$o" 2>&1; grep -q ACCESS_DENIED "$o" && ok "guest refused on Private" || { fail "guest on Private"; cat "$o"; }
nmblookup -A $A > "$o" 2>&1; grep -q "<20>" "$o" && ok "NetBIOS node status: $(grep '<20>' "$o" | awk '{print $1}')" || { fail "NetBIOS"; cat "$o"; }
python3 -I - "$A" > "$o" 2>&1 <<'PY'
import socket, struct, sys
q = struct.pack(">HHHHHH", 0x4242, 0, 1, 0, 0, 0)
for l in "_smb._tcp.local".split("."):
    q += bytes([len(l)]) + l.encode()
q += b"\0" + struct.pack(">HH", 12, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(q, (sys.argv[1], 5353))
d, a = s.recvfrom(1500)
print("answers", struct.unpack(">H", d[6:8])[0], "additional", struct.unpack(">H", d[10:12])[0])
PY
grep -q "answers 1 additional 3" "$o" && ok "mDNS _smb._tcp answer" || { fail "mDNS"; cat "$o"; }
# speed (unsigned 2.1 and signed 3.1.1), 512 KB each way
head -c 524288 /dev/urandom > "$out/512k.bin"
for p in "SMB2_10" "SMB3_11 --option=client\ signing=required"; do
	t0=$(date +%s.%N)
	eval $SC -U "bob%$PW" -m $p //$A/Private -c "\"put $out/512k.bin s.bin\"" > "$o" 2>&1
	t1=$(date +%s.%N)
	eval $SC -U "bob%$PW" -m $p //$A/Private -c "\"get s.bin $out/512k.got; del s.bin\"" >> "$o" 2>&1
	t2=$(date +%s.%N)
	cmp -s "$out/512k.bin" "$out/512k.got" || fail "512 KB copy ($p)"
	echo "speed ${p%% *}: put $(awk "BEGIN { printf \"%.0f\", 512 / ($t1 - $t0) }") KB/s, get $(awk "BEGIN { printf \"%.0f\", 512 / ($t2 - $t1) }") KB/s (logon included)"
done
PY=${LAGOON_PY:-}
[ -z "$PY" ] && [ -x /tmp/claude-0/lagoon-smb/venv/bin/python ] && PY=/tmp/claude-0/lagoon-smb/venv/bin/python
if [ -n "$PY" ]; then
	"$PY" -I - "$A" "$PW" > "$o" 2>&1 <<'PY'
import io, sys
from impacket.smbconnection import SMBConnection
c = SMBConnection("AMIGA", sys.argv[1], sess_port=445)
c.login("bob", sys.argv[2])
c.putFile("Private", "imp.txt", io.BytesIO(b"impacket was here").read)
b = io.BytesIO(); c.getFile("Private", "imp.txt", b.write)
assert b.getvalue() == b"impacket was here"
c.deleteFile("Private", "imp.txt")
print("impacket ok")
PY
	grep -q "impacket ok" "$o" && ok "impacket put/get/delete" || { fail "impacket"; cat "$o"; }
fi
# Stop server, OK, Save
key t
sleep 5
shot 09-stopped
key o
sleep 1
shot 10-main
key s
t=0
while [ $t -lt 90 ] && kill -0 $epid 2>/dev/null; do sleep 1; t=$((t + 1)); done
wait $epid
work=$(sed -n 's/.*work dir \(.*\)$/\1/p' "$out/run_emu.log")
[ -n "$work" ] || { fail "no emulator work dir"; cat "$out/run_emu.log"; exit 1; }
conf=$work/dh0/ENVARC/Lagoon/lagoon.conf
cp "$conf" "$out/lagoon.conf" 2>/dev/null
grep -q 'export name="Public" path="DH0:Pub" comment="Amiga files" readonly=no guest=yes' "$conf" && ok "Public saved" || fail "Public not saved: $(cat "$conf")"
grep -q 'export name="Private" path="DH0:Priv" readonly=no guest=no users="bob"' "$conf" && ok "Private saved" || fail "Private not saved"
grep -q 'user name="bob" nthash="[0-9a-f]\{32\}"' "$conf" && ok "user saved as an NT hash" || fail "user not saved"
grep -q "$PW" "$conf" && fail "the password is in lagoon.conf"
grep -q 'autostart=yes' "$conf" && ok "Start at boot saved" || fail "autostart not saved"
grep -q 'share name="NAS"' "$conf" || fail "the share list lost its share"
cat "$work/dh0/out/after"
echo "output: $out (emulator work dir $work)"
[ $fails -eq 0 ] && echo "ok   sharing on the emulator"
exit $fails
