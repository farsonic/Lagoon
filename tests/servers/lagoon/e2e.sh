#!/bin/sh
# Lagoon - end-to-end test of the SMB server (build/host/lnsrv) with real
# clients: smbclient (Samba) for every dialect with and without signing,
# and impacket when $LAGOON_PY (a python with impacket) is given or
# /tmp/claude-0/lagoon-smb/venv exists. A guest share, a password share and
# a read-only share in a private temp dir; made-up users and passwords.
#   tests/servers/lagoon/e2e.sh   (from the repository root)
# Exit 0 = passed, 1 = failed, 77 = smbclient not installed.
# SPDX-License-Identifier: GPL-2.0-only
cd "$(dirname "$0")/../../.." || exit 1
command -v smbclient >/dev/null 2>&1 || { echo "e2e: smbclient not installed: skipped"; exit 77; }
[ -x build/host/lnsrv ] || { echo "e2e: build/host/lnsrv missing (make)"; exit 1; }
D=$(mktemp -d /tmp/lagoon-e2e.XXXXXX) || exit 1
PORT=$((24000 + $$ % 8000))
mkdir -p "$D/pub" "$D/priv" "$D/ro" "$D/work"
echo "hello from the Amiga" > "$D/pub/hello.txt"
echo "read only" > "$D/ro/keep.txt"
head -c 1048576 /dev/urandom > "$D/work/big.bin"
fail=0; n=0
ok()  { n=$((n + 1)); echo "e2e: ok   $1"; }
bad() { n=$((n + 1)); fail=$((fail + 1)); echo "e2e: FAIL $1"; [ -n "$2" ] && sed 's/^/      /' "$2" | tail -8; }
build/host/lnsrv -p $PORT -n E2EAMIGA -v 1 \
	-s "Public=$D/pub,guest" -s "Private=$D/priv,users=bob" -s "Archive=$D/ro,ro,guest" \
	-u 'bob:Corr3ct-Horse' -u 'alice:another one' > "$D/server.log" 2>&1 &
SP=$!
trap 'kill $SP 2>/dev/null; wait $SP 2>/dev/null' EXIT
i=0; while [ $i -lt 50 ] && ! grep -q "serving" "$D/server.log"; do sleep 0.1; i=$((i + 1)); done
SC="timeout 60 smbclient -p $PORT"
out="$D/out"

# share list, anonymous
if $SC -N -L //127.0.0.1 > "$out" 2>&1 && grep -q "Public *Disk" "$out" && grep -q "Private *Disk" "$out"; then ok "share list (-L, anonymous)"; else bad "share list" "$out"; fi

# guest share: list, get, put, mkdir, rename, delete
if $SC -N //127.0.0.1/Public -c "ls; get hello.txt $D/work/hello.got; put $D/work/big.bin big.bin; mkdir New; rename big.bin New/moved.bin; ls New/*; get New/moved.bin $D/work/big.got" > "$out" 2>&1 \
   && cmp -s "$D/work/big.bin" "$D/work/big.got" && cmp -s "$D/pub/hello.txt" "$D/work/hello.got" && [ -f "$D/pub/New/moved.bin" ]; then
	ok "guest: ls, get, put 1 MB, mkdir, rename, get back (byte-identical)"
else bad "guest share" "$out"; fi
if $SC -N //127.0.0.1/Public -c "del New/moved.bin; rmdir New; ls" > "$out" 2>&1 && [ ! -e "$D/pub/New" ]; then ok "guest: delete, rmdir"; else bad "guest delete" "$out"; fi

# password share, every dialect, signing required by the client
for p in SMB2_02 SMB2_10 SMB3_00 SMB3_02 SMB3_11; do
	rm -f "$D/work/big.got"
	if $SC -U 'bob%Corr3ct-Horse' -m $p --option="client signing=required" //127.0.0.1/Private \
	       -c "put $D/work/big.bin b.bin; mkdir d; rename b.bin d/c.bin; get d/c.bin $D/work/big.got; del d/c.bin; rmdir d; ls" > "$out" 2>&1 \
	   && cmp -s "$D/work/big.bin" "$D/work/big.got" && [ ! -e "$D/priv/d" ]; then
		ok "bob, $p, signed: put/mkdir/rename/get/del/rmdir"
	else bad "bob $p signed" "$out"; fi
done

# refusals
if $SC -U 'bob%wrong password' //127.0.0.1/Private -c ls > "$out" 2>&1; then bad "wrong password accepted" "$out"
elif grep -q LOGON_FAILURE "$out"; then ok "wrong password: LOGON_FAILURE"; else bad "wrong password: unexpected error" "$out"; fi
if $SC -N //127.0.0.1/Private -c ls > "$out" 2>&1; then bad "guest on the password share accepted" "$out"
elif grep -q ACCESS_DENIED "$out"; then ok "guest on the password share: ACCESS_DENIED"; else bad "guest on Private: unexpected" "$out"; fi
if $SC -U 'alice%another one' //127.0.0.1/Private -c ls > "$out" 2>&1; then bad "alice (not in users=) accepted" "$out"
elif grep -q ACCESS_DENIED "$out"; then ok "user not listed for the share: ACCESS_DENIED"; else bad "alice: unexpected" "$out"; fi
$SC -N //127.0.0.1/Archive -c "put $D/work/hello.got x.txt; del keep.txt; mkdir z" > "$out" 2>&1
if [ -f "$D/ro/keep.txt" ] && [ ! -e "$D/ro/x.txt" ] && [ ! -e "$D/ro/z" ] && grep -q ACCESS_DENIED "$out"; then ok "read-only share refuses put, del, mkdir"; else bad "read-only share" "$out"; fi
if $SC -N //127.0.0.1/Archive -c "get keep.txt $D/work/keep.got" > "$out" 2>&1 && cmp -s "$D/ro/keep.txt" "$D/work/keep.got"; then ok "read-only share: get"; else bad "read-only get" "$out"; fi

# impacket
PY=${LAGOON_PY:-}
[ -z "$PY" ] && [ -x /tmp/claude-0/lagoon-smb/venv/bin/python ] && PY=/tmp/claude-0/lagoon-smb/venv/bin/python
if [ -n "$PY" ] && "$PY" -c "import impacket" 2>/dev/null; then
	if "$PY" -I tests/servers/lagoon/impacket_test.py 127.0.0.1 $PORT "$D" > "$out" 2>&1; then
		sed 's/^/e2e: /' "$out" | grep "ok  "
		ok "impacket ($(grep -c '^ok' "$out") checks)"
	else bad "impacket" "$out"; fi
else
	echo "e2e: impacket not available: skipped (LAGOON_PY=python-with-impacket)"
fi

if grep -q "ERROR: AddressSanitizer\|runtime error" "$D/server.log"; then bad "sanitizer report in the server log" "$D/server.log"; fi
kill $SP 2>/dev/null; wait $SP 2>/dev/null; trap - EXIT
echo "e2e: $n checks, $fail failed"
# leave the temp dir only when something failed (moved aside, not deleted, otherwise)
if [ $fail -eq 0 ]; then find "$D" -type f -delete; find "$D" -depth -type d -empty -delete; else echo "e2e: files kept in $D"; fi
[ $fail -eq 0 ]
