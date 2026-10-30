#!/bin/bash
# Lagoon AFP tests - run Netatalk 3's afpd from a
# private configuration in a temp directory, as root, in the foreground.
#   netatalk.sh start DIR [PORT] [LISTEN]   -> exit 0 when it answers, 77 if unavailable
#   netatalk.sh stop DIR
# Creates the local test users "lagoon" (password "lagoon-test-pw") and
# "lagoon8" (password "lagoon-t", for the 8-byte clear text login) (no home,
# shell /bin/sh because afpd refuses users without a valid shell) if needed:
# the DHX2 and clear text logins check it with PAM against /etc/shadow.
# Volumes: lagoon (DIR/vol, writable by everyone so guest works too),
# readonly (DIR/ro), secret (DIR/secret, volume password "lagoonpw").
# SPDX-License-Identifier: GPL-2.0-only
set -u
cmd=${1:?start|stop}
dir=${2:?dir}
port=${3:-5480}
listen=${4:-127.0.0.1}
here=$(cd "$(dirname "$0")" && pwd)
case "$cmd" in
start)
	command -v netatalk >/dev/null 2>&1 || { echo "netatalk not installed"; exit 77; }
	[ "$(id -u)" = 0 ] || { echo "needs root"; exit 77; }
	if ! id lagoon >/dev/null 2>&1; then
		useradd -M -s /bin/sh -c "Lagoon test user" lagoon || exit 77
	fi
	echo 'lagoon:lagoon-test-pw' | chpasswd || exit 77
	# "Cleartxt Passwrd" carries 8 password bytes at most: a second user
	# with an 8-character password for that test
	if ! id lagoon8 >/dev/null 2>&1; then
		useradd -M -s /bin/sh -c "Lagoon test user (clear text)" lagoon8 || exit 77
	fi
	echo 'lagoon8:lagoon-t' | chpasswd || exit 77
	# afpd runs as the logged-in user: the volumes must not be below a
	# private (0700) directory such as the scratchpad, hence a /tmp dir
	mkdir -p "$dir/vol" "$dir/ro" "$dir/secret" "$dir/db"
	chmod 777 "$dir/vol" "$dir/secret"
	chmod 755 "$dir/ro" "$dir"
	echo "read-only volume" > "$dir/ro/readme.txt"
	sed -e "s|@DIR@|$dir|g" -e "s|@PORT@|$port|g" -e "s|@LISTEN@|$listen|g" \
	    -e "s|@LOGLEVEL@|${AFP_LOGLEVEL:-info}|g" -e "s|@TICKLE@|${AFP_TICKLE:-10}|g" \
	    "$here/afp.conf.in" > "$dir/afp.conf"
	# afpd alone, without the netatalk supervisor: cnid_metad (the "dbd"
	# CNID scheme) exits when it cannot raise RLIMIT_NOFILE to 65535, which
	# containers often forbid, so the volumes use the daemon-less "tdb"
	# scheme ("last" would make them read-only)
	afpd -d -F "$dir/afp.conf" > "$dir/netatalk.out" 2>&1 &
	echo $! > "$dir/netatalk.pid"
	i=0
	while [ $i -lt 50 ]; do
		if (exec 3<>/dev/tcp/$listen/$port) 2>/dev/null; then exit 0; fi
		sleep 0.2
		i=$((i + 1))
	done
	echo "netatalk did not start:"; cat "$dir/netatalk.out"; tail -20 "$dir/afpd.log" 2>/dev/null
	"$0" stop "$dir"
	exit 77
	;;
stop)
	if [ -f "$dir/netatalk.pid" ]; then
		pid=$(cat "$dir/netatalk.pid")
		kill "$pid" 2>/dev/null
		i=0
		while kill -0 "$pid" 2>/dev/null && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
		kill -9 "$pid" 2>/dev/null
		mv "$dir/netatalk.pid" "$dir/netatalk.pid.old"
	fi
	# afpd children / cnid daemons started from this config
	pkill -f "$dir/afp.conf" 2>/dev/null
	exit 0
	;;
esac
