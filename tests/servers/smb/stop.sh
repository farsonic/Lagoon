#!/bin/sh
# Lagoon - stop the smbd started by start.sh DIR (and its RPC helpers).
# SPDX-License-Identifier: GPL-2.0-only
DIR=${1:?usage: stop.sh DIR}
for p in smbd samba-dcerpcd; do
	[ -f "$DIR/run/$p.pid" ] && kill "$(cat "$DIR/run/$p.pid")" 2>/dev/null
done
# RPC workers started for this config
pkill -f -- "^/usr/libexec/samba/[a-z_-]+ --configfile=$DIR/smb.conf" 2>/dev/null
exit 0
