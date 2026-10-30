#!/bin/sh
# Lagoon - a private Samba nmbd for tests/t_netbios.c.
#
#   nmbd.sh start DIR    veth lgnb0 (192.168.99.1/24) + nmbd answering as
#                        LAGOONNB in workgroup LAGOONWG; prints "ready"
#                        once it answers a node status request
#   nmbd.sh stop DIR     stops nmbd, removes the veth pair
#
# nmbd always uses UDP port 137 and ignores loopback, hence the veth pair.
# Needs root and nmbd/nmblookup; exits 77 (skip) without them.
# SPDX-License-Identifier: GPL-2.0-only
set -u
cmd=${1:?start|stop}
d=${2:?DIR}
IF=${LAGOON_NB_IF:-lgnb0}
case "$cmd" in
start)
	[ "$(id -u)" = 0 ] || exit 77
	command -v nmbd >/dev/null 2>&1 && command -v nmblookup >/dev/null 2>&1 || exit 77
	mkdir -p "$d/nmbd"
	ip link del "$IF" 2>/dev/null
	ip link add "$IF" type veth peer name "${IF%0}1" || exit 77
	ip addr add 192.168.99.1/24 brd + dev "$IF"
	ip link set "$IF" up
	ip link set "${IF%0}1" up
	cat > "$d/smb.conf" <<CONF
[global]
netbios name = LAGOONNB
workgroup = LAGOONWG
interfaces = $IF
lock directory = $d
state directory = $d
cache directory = $d
private dir = $d
pid directory = $d
ncalrpc dir = $d
log file = $d/log.nmbd
nmbd:socket dir = $d/nmbd
CONF
	nmbd -D -s "$d/smb.conf" || exit 77
	t=0
	while [ $t -lt 30 ]; do
		if nmblookup -s "$d/smb.conf" -A 192.168.99.1 2>/dev/null | grep -q 'LAGOONNB *<20>'; then
			echo ready
			exit 0
		fi
		sleep 1
		t=$((t + 1))
	done
	echo "nmbd did not come up" >&2
	exit 1
	;;
stop)
	[ -f "$d/nmbd.pid" ] && kill "$(cat "$d/nmbd.pid")" 2>/dev/null
	ip link del "$IF" 2>/dev/null
	exit 0
	;;
esac
exit 2
