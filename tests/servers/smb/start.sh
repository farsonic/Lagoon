#!/bin/sh
# Lagoon - start a private smbd for the SMB tests.
#   tests/servers/smb/start.sh DIR PORT [IFACES] [SIGNING]
# DIR is a fresh directory (config, passdb, shares); IFACES defaults to
# 127.0.0.1, SIGNING (server signing) to "auto". Login: lagoon /
# lagoon-test-pw (needs a Unix user "lagoon"; otherwise the login is mapped
# to "nobody" with a username map). Exit 77 if smbd cannot run.
# SPDX-License-Identifier: GPL-2.0-only
set -u
DIR=${1:?usage: start.sh DIR PORT [IFACES] [SIGNING]}
PORT=${2:?port}
IFACES=${3:-127.0.0.1}
SIGNING=${4:-auto}
HERE=$(cd "$(dirname "$0")" && pwd)
command -v smbd >/dev/null 2>&1 || { echo "no smbd"; exit 77; }
command -v pdbedit >/dev/null 2>&1 || { echo "no pdbedit"; exit 77; }
[ "$(id -u)" = 0 ] || { echo "smbd needs root"; exit 77; }
mkdir -p "$DIR/private" "$DIR/lock" "$DIR/state" "$DIR/cache" "$DIR/run" "$DIR/ncalrpc" \
	"$DIR/plain" "$DIR/readonly" "$DIR/encrypted" "$DIR/fruit" "$DIR/guest"
chmod 755 "$DIR"
UNIXUSER=lagoon
MAP=""
if ! id lagoon >/dev/null 2>&1; then
	UNIXUSER=nobody
	echo "nobody = lagoon" > "$DIR/usermap"
	MAP="username map = $DIR/usermap"
fi
sed -e "s|@DIR@|$DIR|g" -e "s|@PORT@|$PORT|g" -e "s|@IFACES@|$IFACES|g" \
	-e "s|@SIGNING@|$SIGNING|g" -e "s|@MAP@|$MAP|g" "$HERE/smb.conf.in" > "$DIR/smb.conf"
printf 'lagoon-test-pw\nlagoon-test-pw\n' | pdbedit -s "$DIR/smb.conf" -a -t -u $UNIXUSER >/dev/null 2>&1 ||
	{ echo "pdbedit failed"; exit 77; }
echo "read only file" > "$DIR/readonly/hello.txt"
smbd -s "$DIR/smb.conf" -D || { echo "smbd failed"; exit 77; }
i=0
while [ $i -lt 50 ]; do
	[ -f "$DIR/run/smbd.pid" ] && exit 0
	sleep 0.1
	i=$((i + 1))
done
echo "smbd did not start (see $DIR/log.smbd)"
exit 77
