#!/bin/sh
# Lagoon - stop the smbd started by start.sh DIR (and its RPC helpers).
# SPDX-License-Identifier: GPL-2.0-only
DIR=${1:?usage: stop.sh DIR}
for p in smbd samba-dcerpcd; do
	[ -f "$DIR/run/$p.pid" ] && kill "$(cat "$DIR/run/$p.pid")" 2>/dev/null
done
# children (rpcd_*, per-connection smbd) that still use this config
pkill -f -- "$DIR/smb.conf" 2>/dev/null
exit 0
