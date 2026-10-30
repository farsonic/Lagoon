#!/bin/sh
# Lagoon - run commands on an emulated A1200 (FS-UAE with Riptide's uaenet
# libpcap patch, AROS ROM) networked to this host over a veth pair, with
# Riptide as the TCP/IP stack. Servers you start on the host (bound to
# 0.0.0.0 or $BR_NET.1) are reachable from the Amiga at $BR_NET.1.
#
#   tests/amiga/run_emu.sh CMDS [TIMEOUT] [FILE...]
#
# CMDS is a file of "NAME|AmigaDOS command" lines; each runs from the
# startup-sequence with its output in DH0:out/NAME (stderr too). FILEs are
# copied into DH0:C (Riptide, rtcheck and ping are added from RIPTIDE_BUILD).
# DH0: is a host directory: put test data in $LAGOON_DH0_EXTRA (a directory
# copied to DH0:) if you need it. Results: the work directory is printed at
# the end; outputs are in WORK/dh0/out/. Exit 0 if every command ran.
#
# Environment: BR_IF/BR_PEER/BR_NET (default lgbr0/lgbr1/192.168.78),
# FSUAE_PCAP (patched fs-uae), RIPTIDE_BUILD, FSUAE_EXTRA (more config
# lines, e.g. "cpu = 68040"), LAGOON_EMU_LOCK (runs are serialized with
# flock on it; default /tmp/lagoon-emu.lock), KEEP_SCREEN=1 saves a
# screenshot WORK/screen.png just before stopping (needs xwd/convert or
# python3 + Xlib-free fallback via import).
# Needs root (veth + packet capture).
# SPDX-License-Identifier: GPL-2.0-only
set -u
CMDS=${1:?usage: run_emu.sh CMDS [TIMEOUT] [FILE...]}
TIMEOUT=${2:-300}
[ $# -ge 2 ] && shift 2 || shift $#
BR_IF=${BR_IF:-lgbr0}
BR_PEER=${BR_PEER:-lgbr1}
BR_NET=${BR_NET:-192.168.78}
FSUAE_PCAP=${FSUAE_PCAP:-/tmp/claude-0/fs-uae-riptide/fs-uae-3.2.35/fs-uae}
RIPTIDE_BUILD=${RIPTIDE_BUILD:-/home/user/farsonic/riptide/build/amiga}
LOCK=${LAGOON_EMU_LOCK:-/tmp/lagoon-emu.lock}
[ -x "$FSUAE_PCAP" ] || { echo "SKIP: no patched fs-uae at $FSUAE_PCAP (riptide/tools/fs-uae/build-fs-uae.sh)"; exit 77; }
[ "$(id -u)" = 0 ] || { echo "SKIP: needs root"; exit 77; }
for f in Riptide rtcheck ping; do [ -f "$RIPTIDE_BUILD/$f" ] || { echo "SKIP: $RIPTIDE_BUILD/$f missing"; exit 77; }; done

work=$(mktemp -d "${TMPDIR:-/tmp}/lagoon-emu.XXXXXX")
dh0=$work/dh0
mkdir -p "$dh0/C" "$dh0/S" "$dh0/L" "$dh0/out" "$dh0/T" "$dh0/ENV" "$dh0/ENVARC"
for f in Riptide rtcheck ping; do cp "$RIPTIDE_BUILD/$f" "$dh0/C/"; done
# AmigaDOS commands from the AROS m68k system (the ROM has none: no Assign,
# Copy, List ...); AROS_C overrides the source directory
AROS_C=${AROS_C:-/tmp/claude-0/-home-user/3a066da9-8230-5cea-817a-b3782336c61e/scratchpad/arossys/C}
for c in Assign Copy Date List Dir MakeDir Rename Delete Protect Filenote SetDate Info Type Execute \
	Echo Wait Run Version Avail Touch Mount Status Path Stack Setenv Getenv Set Unset Join Search \
	Break Lock Relabel Which Why Fault Eval If Else EndIf Skip Lab Ask Resident; do
	[ -f "$AROS_C/$c" ] && cp "$AROS_C/$c" "$dh0/C/"
done
for f in "$@"; do cp "$f" "$dh0/C/"; done
[ -n "${LAGOON_DH0_EXTRA:-}" ] && cp -r "$LAGOON_DH0_EXTRA"/. "$dh0/"
cat > "$dh0/S/riptide.conf" <<CONF
hostname lagoon-test
loglevel 1
interface eth0 device=uaenet.device unit=2
ifconfig eth0 $BR_NET.2/24 up
route add default $BR_NET.1
CONF
{
	echo "FailAt 30"
	echo "Stack 32768"
	echo "DH0:C/Path DH0:C ADD"
	echo "Assign T: DH0:T"
	echo "Assign ENV: DH0:ENV"
	echo "Assign ENVARC: DH0:ENVARC"
	echo "Assign L: DH0:L ADD"
	echo "DH0:C/rtcheck START=\"DH0:C/Riptide >DH0:out/riptide.log CONFIG=DH0:S/riptide.conf\" NOCHECK >DH0:out/start"
	echo "DH0:C/ping -c 2 -q $BR_NET.1 >DH0:out/ping"
	tr -d '\r' < "$CMDS" | while IFS='|' read -r name cmd; do
		case "$name" in ''|'#'*) continue;; esac
		echo "$cmd >DH0:out/$name"
	done
	echo "Echo done >DH0:out/zz_done"
} > "$dh0/S/Startup-Sequence"
cat > "$work/test.fs-uae" <<CFG
[fs-uae]
amiga_model = A1200
fast_memory = 8192
hard_drive_0 = $dh0
hard_drive_0_label = DH0
sound_card = none
floppy_drive_count = 0
automatic_input_grab = 0
video_sync = off
uae_sana2 = 1
uaenet_pcap = $BR_IF
base_dir = $work/fsuae
${FSUAE_EXTRA:-}
CFG

exec 9>"$LOCK"
flock 9
ip link del $BR_IF 2>/dev/null
ip link add $BR_IF type veth peer name $BR_PEER || { echo "SKIP: cannot create veth"; exit 77; }
ip link set $BR_IF up
ip link set $BR_PEER up
ip addr add $BR_NET.1/24 dev $BR_PEER
if command -v ethtool >/dev/null 2>&1; then
	for d in $BR_IF $BR_PEER; do ethtool -K $d tso off gso off gro off tx off rx off >/dev/null 2>&1; done
fi
disp=:97
Xvfb $disp -screen 0 1024x768x24 >/dev/null 2>&1 9>&- &
xpid=$!
sleep 1
start=$(date +%s)
DISPLAY=$disp SDL_AUDIODRIVER=dummy setsid "$FSUAE_PCAP" "$work/test.fs-uae" >"$work/fs-uae.log" 2>&1 9>&- &
upid=$!
t=0
while [ $t -lt "$TIMEOUT" ] && [ ! -f "$dh0/out/zz_done" ]; do
	kill -0 $upid 2>/dev/null || break
	sleep 1
	t=$((t + 1))
done
sleep 1
if [ "${KEEP_SCREEN:-}" = 1 ]; then
	DISPLAY=$disp import -window root "$work/screen.png" 2>/dev/null ||
		DISPLAY=$disp xwd -root -silent 2>/dev/null | convert xwd:- "$work/screen.png" 2>/dev/null
fi
kill $upid 2>/dev/null; wait $upid 2>/dev/null
kill $xpid 2>/dev/null; wait $xpid 2>/dev/null
ip link del $BR_IF 2>/dev/null
for f in "$dh0"/out/*; do [ -f "$f" ] && tr -d '\r' < "$f" > "$f.tmp" && mv "$f.tmp" "$f"; done
echo "---- emulator ran $(( $(date +%s) - start )) s; work dir $work"
[ -f "$dh0/out/zz_done" ] && exit 0
echo "run_emu: timed out or emulator stopped (see $work/fs-uae.log, $dh0/out/)"
exit 1
