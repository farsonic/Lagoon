#!/bin/sh
# Lagoon - start/stop the NFSv3 test server (nfs-ganesha, FSAL VFS).
#   ganesha.sh start DIR [PORT [MNTPORT]]   -> exit 0 when serving, 77 if it cannot run
#   ganesha.sh stop DIR                     (KEEP_RPCBIND=1: leave rpcbind running)
# ganesha registers with the portmapper and refuses to start without one:
# rpcbind is started if nothing listens on port 111 (and stopped again by
# "stop" if we started it). DIR gets export/, ro/, recov/, the config and logs.
# Needs root (FSAL VFS uses open_by_handle_at).
# SPDX-License-Identifier: GPL-2.0-only
set -u
here=$(cd "$(dirname "$0")" && pwd)
cmd=${1:?start|stop}
dir=${2:?dir}
port=${3:-20490}
mntport=${4:-$((port + 1))}
listening() { ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$1\$"; }
case "$cmd" in
start)
	command -v ganesha.nfsd >/dev/null 2>&1 || { echo "no ganesha.nfsd"; exit 77; }
	[ "$(id -u)" = 0 ] || { echo "ganesha needs root"; exit 77; }
	mkdir -p "$dir/export" "$dir/ro" "$dir/recov"
	if ! listening 111; then
		command -v rpcbind >/dev/null 2>&1 || { echo "no rpcbind"; exit 77; }
		mkdir -p /run/rpcbind
		rpcbind -w || { echo "rpcbind failed"; exit 77; }
		sleep 1
		pgrep -x rpcbind > "$dir/rpcbind.started"
	fi
	sed -e "s|@DIR@|$dir|g" -e "s|@PORT@|$port|" -e "s|@MNTPORT@|$mntport|" \
	    -e "s|@NLMPORT@|$((port + 2))|" -e "s|@RQPORT@|$((port + 3))|" \
	    "$here/ganesha.conf.in" > "$dir/ganesha.conf"
	ganesha.nfsd -f "$dir/ganesha.conf" -L "$dir/ganesha.log" -p "$dir/ganesha.pid" -N NIV_EVENT
	i=0
	while [ $i -lt 40 ]; do
		listening "$port" && listening "$mntport" && { sleep 1; exit 0; }
		sleep 0.25; i=$((i + 1))
	done
	echo "ganesha did not start (see $dir/ganesha.log)"
	[ -f "$dir/ganesha.pid" ] && kill "$(cat "$dir/ganesha.pid")" 2>/dev/null
	exit 77
	;;
stop)
	if [ -f "$dir/ganesha.pid" ]; then
		pid=$(cat "$dir/ganesha.pid")
		kill "$pid" 2>/dev/null
		i=0
		while kill -0 "$pid" 2>/dev/null && [ $i -lt 40 ]; do sleep 0.25; i=$((i + 1)); done
		kill -9 "$pid" 2>/dev/null
		[ -f "$dir/ganesha.pid" ] && mv "$dir/ganesha.pid" "$dir/ganesha.pid.old"
	fi
	if [ -f "$dir/rpcbind.started" ] && [ -z "${KEEP_RPCBIND:-}" ]; then
		kill "$(cat "$dir/rpcbind.started")" 2>/dev/null
		mv "$dir/rpcbind.started" "$dir/rpcbind.stopped"
	fi
	exit 0
	;;
esac
exit 2
