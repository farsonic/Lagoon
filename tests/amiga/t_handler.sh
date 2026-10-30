#!/bin/sh
# Lagoon - lagoon-handler + C:Lagoon on the emulated A1200 (run_emu.sh),
# against the in-memory backend (mem://, no server needed) and, with
# SMB_URL set (e.g. smb://lagoon:lagoon-test-pw@192.168.78.1/lagoon), a
# real server too.
#
#   tests/amiga/t_handler.sh            (needs root, like run_emu.sh)
#
# AmigaDOS commands (List, Dir, MakeDir ...) are not in the AROS ROM: they
# are taken from an AROS m68k system directory, $AROS_C (its C: drawer),
# at test time only. Exit 0 = all checks passed, 77 = skipped.
# SPDX-License-Identifier: GPL-2.0-only
set -u
cd "$(dirname "$0")/../.." || exit 1
S=${TMPDIR:-/tmp}
AROS_C=${AROS_C:-/tmp/claude-0/-home-user/3a066da9-8230-5cea-817a-b3782336c61e/scratchpad/arossys/C}
for f in build/amiga/lagoon-handler build/amiga/Lagoon; do
	[ -f "$f" ] || { echo "SKIP: $f missing (make amiga)"; exit 77; }
done
[ -d "$AROS_C" ] || { echo "SKIP: no AROS C: drawer at $AROS_C (set AROS_C)"; exit 77; }

x=$(mktemp -d "$S/t_handler.XXXXXX")
mkdir -p "$x/dh0/L" "$x/dh0/C" "$x/dh0/ENV/Lagoon" "$x/dh0/data"
cp build/amiga/lagoon-handler "$x/dh0/L/"
for c in List Dir Copy MakeDir Rename Delete Protect Filenote SetDate Info Type Execute Relabel Wait Version Avail; do
	[ -f "$AROS_C/$c" ] && cp "$AROS_C/$c" "$x/dh0/C/"
done
head -c 1048576 /dev/urandom > "$x/dh0/data/big.bin"
printf 'small file\n' > "$x/dh0/data/small.txt"
printf 'Echo "second script ran"\n' > "$x/dh0/data/script"
cat > "$x/dh0/ENV/Lagoon/lagoon.conf" <<'EOF'
# Lagoon handler test shares
share name="MEM" url="mem://test/vol?seed=1&many=300" volume="MemVol"
share name="AUTO" url="mem://test/auto?seed=1" automount=yes
option loglevel=1
EOF
SMB_URL=${SMB_URL:-}
cmds=$x/cmds
cat > "$cmds" <<'EOF'
a01_mount|Lagoon MOUNT MEM
a02_mountdup|Lagoon MOUNT MEM
a03_list|List MEM:
a04_dirall|Dir MEM: ALL
a05_info|Info MEM:
a06_copyin|Copy DH0:data/big.bin MEM:big.bin
a07_copyout|Copy MEM:big.bin DH0:out/big.back
a08_mkdir|MakeDir MEM:NewDir
a09_copy2|Copy DH0:data/small.txt MEM:NewDir/small.txt
a10_rename|Rename MEM:NewDir/small.txt MEM:NewDir/renamed.txt
a11_delne|Delete MEM:NewDir
a12_protect|Protect MEM:NewDir/renamed.txt rwe
a13_delprot|Delete MEM:NewDir/renamed.txt
a14_protect2|Protect MEM:NewDir/renamed.txt +d
a15_filenote|Filenote MEM:NewDir/renamed.txt "hello note"
a16_setdate|SetDate MEM:NewDir/renamed.txt 01-Jan-20 12:00:00
a17_listnd|List MEM:NewDir
a18_type|Type MEM:ReadMe.txt
a19_typecase|Type mem:README.TXT
a20_exec|Execute MEM:script
a21_copyscript|Copy DH0:data/script MEM:s2
a22_exec2|Execute MEM:s2
a23_escaped|Type "MEM:a%3Ab.txt"
a24_renamecase|Rename MEM:ReadMe.txt MEM:README.TXT
a25_listcase|List MEM: PAT=readme#?
a26_delall|Delete MEM:NewDir ALL
a27_notfound|List MEM:nothere
a28_exists|MakeDir MEM:Dir1
a29_many|Dir MEM:Many
a30_relabel|Relabel MEM: NewLabel
a31_info2|Info MEM:
a32_status|Lagoon STATUS
a33_llist|Lagoon LIST
a34_test|Lagoon TEST MEM
a35_testbad|Lagoon TEST mem://test/x?pass=right PASSWORD wrong
a36_shares|Lagoon SHARES mem://test
a37_cd|CD MEM:Dir1
a38_inuse|Lagoon UNMOUNT MEM:
a39_cdback|CD DH0:
a40_unmount|Lagoon UNMOUNT MEM:
a41_gone|Lagoon STATUS MEM:
b01_ro|Lagoon MOUNT mem://test/ro?seed=1 AS RO: READONLY
b02_rowrite|Copy DH0:data/small.txt RO:x
b03_rolist|List RO:ReadMe.txt
b04_rodel|Delete RO:ReadMe.txt
b05_rounmount|Lagoon UNMOUNT RO:
b06_badauth|Lagoon MOUNT mem://test/auth?pass=secret AS BAD: PASSWORD wrong
b07_badgone|Lagoon STATUS BAD:
b08_goodauth|Lagoon MOUNT mem://test/auth?pass=secret AS GOOD: PASSWORD secret
b09_goodlist|List GOOD:
b10_goodun|Lagoon UNMOUNT GOOD:
b11_url|Lagoon MOUNT mem://test/adhoc?seed=1
b12_urllist|List LGN0:ReadMe.txt
b13_urlun|Lagoon UNMOUNT LGN0:
c01_drop|Lagoon MOUNT mem://test/drop?seed=1&dropevery=20 AS DROP:
c02_dropin|Copy DH0:data/big.bin DROP:big
c03_dropout|Copy DROP:big DH0:out/drop.back
c04_droplist|List DROP:
c05_dropstat|Lagoon STATUS DROP:
c06_dropun|Lagoon UNMOUNT DROP:
c07_down|Lagoon MOUNT mem://test/down?seed=1&dropevery=12&refuse=1000000 AS DOWN:
c08_downlist|List DOWN:
c09_downlist2|List DOWN:
c10_downstat|Lagoon STATUS DOWN:
d01_mountall|Lagoon MOUNTALL WAIT 10
d02_autolist|List AUTO:Dir1
d03_mountall2|Lagoon MOUNTALL
d04_list|Lagoon LIST
d05_un|Lagoon UNMOUNT AUTO:
EOF
if [ -n "$SMB_URL" ]; then
	cat >> "$cmds" <<EOF
s01_mount|Lagoon MOUNT $SMB_URL AS SMB:
s02_info|Info SMB:
s03_copyin|Copy DH0:data/big.bin SMB:lagoon-big.bin
s04_copyout|Copy SMB:lagoon-big.bin DH0:out/smb.back
s05_mkdir|MakeDir SMB:lagoon-dir
s06_copy|Copy DH0:data/small.txt SMB:lagoon-dir/small.txt
s07_rename|Rename SMB:lagoon-dir/small.txt SMB:lagoon-dir/Renamed.txt
s08_delne|Delete SMB:lagoon-dir
s09_note|Filenote SMB:lagoon-dir/Renamed.txt "smb note"
s10_date|SetDate SMB:lagoon-dir/Renamed.txt 01-Jan-20 12:00:00
s11_list|List SMB:lagoon-dir
s12_case|Type SMB:LAGOON-DIR/renamed.TXT
s13_dirall|Dir SMB: ALL
s14_status|Lagoon STATUS SMB:
s15_del|Delete SMB:lagoon-dir ALL
s16_del2|Delete SMB:lagoon-big.bin
s17_un|Lagoon UNMOUNT SMB:
EOF
fi
LAGOON_DH0_EXTRA=$x/dh0 tests/amiga/run_emu.sh "$cmds" "${EMU_TIMEOUT:-400}" build/amiga/Lagoon > "$x/emu.log" 2>&1
rc=$?
work=$(sed -n 's/.*work dir \([^ ]*\).*/\1/p' "$x/emu.log" | tail -1)
[ $rc = 77 ] && { cat "$x/emu.log"; exit 77; }
[ -n "$work" ] || { cat "$x/emu.log"; echo "FAIL: emulator did not run"; exit 1; }
o=$work/dh0/out
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $*"; }
has() {   # has FILE REGEX [description]
	if grep -qiE "$2" "$o/$1" 2>/dev/null; then ok; else bad "$1: no /$2/ in: $(tr '\n' '|' < "$o/$1" 2>/dev/null | cut -c1-300)"; fi
}
hasnt() {
	if grep -qiE "$2" "$o/$1" 2>/dev/null; then bad "$1: unexpected /$2/ in: $(tr '\n' '|' < "$o/$1" | cut -c1-300)"; else ok; fi
}
same() {
	if cmp -s "$1" "$2"; then ok; else bad "$1 differs from $2"; fi
}
count() {   # count FILE REGEX N
	n=$(grep -ciE "$2" "$o/$1" 2>/dev/null)
	if [ "${n:-0}" -eq "$3" ]; then ok; else bad "$1: $n lines match /$2/, expected $3"; fi
}

has a01_mount "Mounted MEM as MEM:"
has a02_mountdup "already mounted"
has a03_list "ReadMe.txt"
has a03_list "Dir1 +Dir"
has a03_list "a%3Ab.txt"
has a03_list "~[0-9A-F]{4}"
has a03_list "script .*s"
has a04_dirall "deep.txt"
has a05_info "MemVol"
same "$x/dh0/data/big.bin" "$o/big.back"
hasnt a06_copyin "error|fail"
has a11_delne "not empty"
has a13_delprot "protected"
has a17_listnd "renamed.txt"
has a17_listnd "hello note"
has a17_listnd "01-Jan-20"
has a18_type "Hello from the Lagoon mem backend"
has a19_typecase "Hello from the Lagoon mem backend"
has a20_exec "script from the share ran"
has a22_exec2 "second script ran"
has a23_escaped "colon"
has a25_listcase "README.TXT"
hasnt a26_delall "error|not"
has a27_notfound "not found|object not"
has a28_exists "exists"
count a29_many "file0" 300
has a31_info2 "NewLabel"
has a32_status "MEM: volume NewLabel"
has a32_status "In-memory test file system"
has a33_llist "MEM +-? *MEM:"
has a33_llist "AUTO +auto"
has a34_test "Test OK"
has a35_testbad "logon failed"
has a36_shares "vol"
has a38_inuse "in use"
has a40_unmount "Unmounted MEM:"
has a41_gone "no such device"
has b01_ro "Mounted"
has b02_rowrite "write.protected|protected"
has b03_rolist "ReadMe.txt"
has b04_rodel "protected"
has b05_rounmount "Unmounted"
has b06_badauth "logon failed"
has b07_badgone "no such device"
has b08_goodauth "Mounted"
has b09_goodlist "ReadMe.txt"
has b10_goodun "Unmounted"
has b11_url "as LGN0:"
has b12_urllist "ReadMe.txt"
has b13_urlun "Unmounted"
same "$x/dh0/data/big.bin" "$o/drop.back"
has c04_droplist "big"
has c05_dropstat "online"
if grep -qE "[1-9][0-9]* reconnects" "$o/c05_dropstat"; then ok; else bad "c05_dropstat: no reconnects"; fi
has c06_dropun "Unmounted"
has c08_downlist "no disk|not mounted|disk"
has c10_downstat "OFFLINE"
has d01_mountall "Mounted AUTO as AUTO:"
has d02_autolist "sub"
hasnt d03_mountall2 "cannot"
has d04_list "AUTO +auto +AUTO:"
has d05_un "Unmounted"
if [ -n "$SMB_URL" ]; then
	has s01_mount "Mounted"
	same "$x/dh0/data/big.bin" "$o/smb.back"
	has s08_delne "not empty"
	has s11_list "Renamed.txt"
	has s11_list "smb note|Renamed"
	has s11_list "01-Jan-20"
	has s12_case "small file"
	has s13_dirall "lagoon-dir"
	has s14_status "online"
	has s17_un "Unmounted"
fi
echo "t_handler: $pass checks passed, $fail failed (outputs in $o)"
[ $fail = 0 ]
