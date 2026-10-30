#!/bin/sh
# Lagoon - lagoon-handler + C:Lagoon on the emulated A1200 (run_emu.sh),
# against the in-memory backend (mem://, no server needed) and, with
# SMB_URL set (e.g. smb://lagoon:lagoon-test-pw@192.168.78.1/lagoon), a
# real server too.
#
#   tests/amiga/t_handler.sh            (needs root, like run_emu.sh)
#
# The AROS ROM has no Assign/List/Info...: tests/amiga/t_handler_assign.c
# and t_handler_tool.c (built here) fill in, and Dir, Copy, MakeDir ... are
# taken from an AROS m68k system's C: drawer, $AROS_C, at test time only.
# Exit 0 = all checks passed, 77 = skipped. Binary results are written to
# DH0:data/ (run_emu.sh strips CRs from everything in DH0:out/).
# URLs with "=" must be quoted for ReadArgs.
# SPDX-License-Identifier: GPL-2.0-only
set -u
cd "$(dirname "$0")/../.." || exit 1
S=${TMPDIR:-/tmp}
AROS_C=${AROS_C:-/tmp/claude-0/-home-user/3a066da9-8230-5cea-817a-b3782336c61e/scratchpad/arossys/C}
VBCC=${VBCC:-/opt/amiga/vbcc}
NDK=${NDK:-/opt/amiga/ndk/Include_H}
for f in build/amiga/lagoon-handler build/amiga/Lagoon; do
	[ -f "$f" ] || { echo "SKIP: $f missing (make amiga)"; exit 77; }
done
[ -d "$AROS_C" ] || { echo "SKIP: no AROS C: drawer at $AROS_C (set AROS_C)"; exit 77; }

x=$(mktemp -d "$S/t_handler.XXXXXX")
mkdir -p "$x/dh0/L" "$x/dh0/C" "$x/dh0/ENV/Lagoon" "$x/dh0/data"
cp build/amiga/lagoon-handler "$x/dh0/L/"
for t in t_handler_assign t_handler_tool; do
	PATH=$VBCC/bin:$PATH VBCC=$VBCC vc +aos68k -c99 -O2 -cpu=68020 -I"$NDK" \
		-o "$x/dh0/C/$t" tests/amiga/$t.c -lamiga || { echo "FAIL: cannot build $t"; exit 1; }
done
# (List and Info from that AROS system do not run on the 2015 AROS ROM)
for c in Dir Copy MakeDir Rename Delete Protect Filenote Type Relabel; do
	[ -f "$AROS_C/$c" ] && cp "$AROS_C/$c" "$x/dh0/C/"
done
head -c 1048576 /dev/urandom > "$x/dh0/data/big.bin"
printf 'small file\n' > "$x/dh0/data/small.txt"
printf 'Echo "second script ran"\n' > "$x/dh0/data/script"
cat > "$x/dh0/ENV/Lagoon/lagoon.conf" <<'CONF'
# Lagoon handler test shares
share name="MEM" url="mem://test/vol?seed=1&many=300" volume="MemVol"
share name="AUTO" url="mem://test/auto?seed=1" automount=yes
option loglevel=1
CONF
SMB_URL=${SMB_URL:-}
cmds=$x/cmds
cat > "$cmds" <<'CMDS'
as1|t_handler_assign T: DH0:T
as2|t_handler_assign ENV: DH0:ENV
as3|t_handler_assign ENVARC: DH0:ENVARC
as4|t_handler_assign L: DH0:L ADD
a01_mount|Lagoon MOUNT MEM
a02_mountdup|Lagoon MOUNT MEM
a03_ls|t_handler_tool ls MEM:
a04_exall|t_handler_tool exall MEM:
a04_exallp|t_handler_tool exall MEM: #?.txt
a04_dirall|Dir MEM: ALL
a05_info|t_handler_tool info MEM:
a05_names|t_handler_tool names MEM:
a06_copyin|Copy DH0:data/big.bin MEM:big.bin
a07_copyout|Copy MEM:big.bin DH0:data/big.back
a08_mkdir|MakeDir MEM:NewDir
a09_copy2|Copy DH0:data/small.txt MEM:NewDir/small.txt
a10_rename|Rename MEM:NewDir/small.txt MEM:NewDir/renamed.txt
a11_delne|Delete MEM:NewDir
a12_protect|Protect MEM:NewDir/renamed.txt rwe
a13_delprot|Delete MEM:NewDir/renamed.txt
a14_protect2|Protect MEM:NewDir/renamed.txt +d
a15_filenote|Filenote MEM:NewDir/renamed.txt "hello note"
a16_setdate|t_handler_tool setdate MEM:NewDir/renamed.txt
a17_lsnd|t_handler_tool ls MEM:NewDir
a18_type|Type MEM:ReadMe.txt
a19_typecase|Type mem:README.TXT
a21_copyscript|Copy DH0:data/script MEM:s2
a22_exec2|Execute MEM:s2
a22_prog|Copy DH0:C/t_handler_tool MEM:tool
a22_runprog|MEM:tool info MEM:
a23_escaped|Type "MEM:a%3Ab.txt"
a23_long|Type MEM:abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx~50DE
a24_renamecase|Rename MEM:ReadMe.txt MEM:README.TXT
a25_lscase|t_handler_tool exall MEM: readme#?
a26_delall|Delete MEM:NewDir ALL
a27_notfound|Type MEM:nothere
a28_exists|MakeDir MEM:Dir1
a29_many|t_handler_tool exall MEM:Many
a29_manyls|t_handler_tool ls MEM:Many
a30_seek|t_handler_tool seek MEM:seek.bin
a30_locks|t_handler_tool locks MEM:seek.bin
a30_fh|t_handler_tool fh MEM:fh.txt
a31_relabel|Relabel MEM: NewLabel
a31_info2|t_handler_tool info MEM:
a32_status|Lagoon STATUS
a33_llist|Lagoon LIST
a34_test|Lagoon TEST MEM
a35_testbad|Lagoon TEST "mem://test/x?pass=right" PASSWORD wrong
a36_shares|Lagoon SHARES mem://test
a37_cd|CD MEM:Dir1
a38_inuse|Lagoon UNMOUNT MEM:
a39_cdback|CD DH0:
a40_unmount|Lagoon UNMOUNT MEM:
a41_gone|Lagoon STATUS MEM:
b01_ro|Lagoon MOUNT "mem://test/ro?seed=1" AS RO: READONLY
b02_rowrite|Copy DH0:data/small.txt RO:x
b03_roinfo|t_handler_tool info RO:
b04_rodel|Delete RO:ReadMe.txt
b05_rounmount|Lagoon UNMOUNT RO:
b06_badauth|Lagoon MOUNT "mem://test/auth?pass=secret" AS BAD: PASSWORD wrong
b07_badgone|Lagoon STATUS BAD:
b08_goodauth|Lagoon MOUNT "mem://user:secret@test/auth?pass=secret" AS GOOD:
b09_goodtype|Type GOOD:ReadMe.txt
b09_goodstat|Lagoon STATUS GOOD:
b10_goodun|Lagoon UNMOUNT GOOD:
b11_url|Lagoon MOUNT "mem://test/adhoc?seed=1"
b12_urltype|Type" LGN0:ReadMe.txt
b13_urlun|Lagoon UNMOUNT LGN0:
c01_drop|Lagoon MOUNT "mem://test/drop?seed=1&dropevery=20" AS DROP:
c02_dropin|Copy DH0:data/big.bin DROP:big
c03_dropout|Copy DROP:big DH0:data/drop.back
c04_dropls|t_handler_tool ls DROP:
c05_dropstat|Lagoon STATUS DROP:
c06_dropun|Lagoon UNMOUNT DROP:
c07_down|Lagoon MOUNT "mem://test/down?seed=1&dropevery=12&refuse=1000000" AS DOWN:
c08_downls|t_handler_tool ls DOWN:
c09_downls2|t_handler_tool ls DOWN:
c10_downstat|Lagoon STATUS DOWN:
d01_mountall|Lagoon MOUNTALL WAIT 10
d02_autols|t_handler_tool ls AUTO:Dir1
d03_mountall2|Lagoon MOUNTALL
d04_list|Lagoon LIST
d05_un|Lagoon UNMOUNT AUTO:
CMDS
if [ -n "$SMB_URL" ]; then
	cat >> "$cmds" <<CMDS
s01_mount|Lagoon MOUNT "$SMB_URL" AS SMB:
s02_info|t_handler_tool info SMB:
s03_copyin|Copy DH0:data/big.bin SMB:lagoon-big.bin
s04_copyout|Copy SMB:lagoon-big.bin DH0:data/smb.back
s05_mkdir|MakeDir SMB:lagoon-dir
s06_copy|Copy DH0:data/small.txt SMB:lagoon-dir/small.txt
s07_rename|Rename SMB:lagoon-dir/small.txt SMB:lagoon-dir/Renamed.txt
s08_delne|Delete SMB:lagoon-dir
s09_note|Filenote SMB:lagoon-dir/Renamed.txt "smb note"
s10_date|t_handler_tool setdate SMB:lagoon-dir/Renamed.txt
s11_ls|t_handler_tool ls SMB:lagoon-dir
s12_case|Type SMB:LAGOON-DIR/renamed.TXT
s13_dirall|Dir SMB: ALL
s13_exall|t_handler_tool exall SMB:
s13_seek|t_handler_tool seek SMB:lagoon-dir/seek.bin
s13_locks|t_handler_tool locks SMB:lagoon-dir/seek.bin
s13_fh|t_handler_tool fh SMB:lagoon-dir/fh.txt
s14_status|Lagoon STATUS SMB:
s15_del|Delete SMB:lagoon-dir ALL
s16_del2|Delete SMB:lagoon-big.bin
s17_un|Lagoon UNMOUNT SMB:
CMDS
fi
LAGOON_DH0_EXTRA=$x/dh0 tests/amiga/run_emu.sh "$cmds" "${EMU_TIMEOUT:-400}" build/amiga/Lagoon > "$x/emu.log" 2>&1
rc=$?
work=$(sed -n 's/.*work dir \([^ ;]*\).*/\1/p' "$x/emu.log" | tail -1)
[ $rc = 77 ] && { cat "$x/emu.log"; exit 77; }
[ -n "$work" ] || { cat "$x/emu.log"; echo "FAIL: emulator did not run"; exit 1; }
[ $rc = 0 ] || echo "WARNING: the emulator run did not finish (see $work)"
o=$work/dh0/out
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $*"; }
has() {   # has FILE REGEX
	if grep -qiE -- "$2" "$o/$1" 2>/dev/null; then ok; else bad "$1: no /$2/ in: $(tr '\n' '|' < "$o/$1" 2>/dev/null | cut -c1-300)"; fi
}
hasnt() {
	if grep -qiE -- "$2" "$o/$1" 2>/dev/null; then bad "$1: unexpected /$2/ in: $(tr '\n' '|' < "$o/$1" | cut -c1-300)"; else ok; fi
}
same() {
	if cmp -s "$1" "$2"; then ok; else bad "$1 differs from $2"; fi
}
count() {   # count FILE REGEX N
	n=$(grep -ciE -- "$2" "$o/$1" 2>/dev/null)
	if [ "${n:-0}" -eq "$3" ]; then ok; else bad "$1: $n lines match /$2/, expected $3"; fi
}

has a01_mount "Mounted MEM as MEM:"
has a02_mountdup "already mounted"
has a03_ls "examine MemVol type=1"
has a03_ls "ent ReadMe.txt\|file\|35\|----rwed"
has a03_ls "ent Dir1\|dir"
has a03_ls "ent a%3Ab.txt"
has a03_ls "ent abcdefghij.*~[0-9A-F]{4}\|file\|10"
has a03_ls "ent script\|file\|33\|-s--rwed"
has a03_ls "ent Many\|dir"
has a03_ls "end 232 count=8"
has a04_exall "exall count=8"
count a04_exallp "^ed .*\.txt\|" 4
has a04_dirall "deep.txt"
has a05_info "info volume=MemVol blocks=65536 used=[0-9]+ bpb=1024 type=444f5300 state=82"
has a05_names "MEM:dir1/SUB/ -> MemVol:Dir1/sub"
has a05_names "MEM:Dir1/sub// -> MemVol:Dir1$"
has a05_names "MEM:Dir1/sub///ReadMe.txt -> MemVol:ReadMe.txt"
has a05_names "MEM:DIR1//mixedcase.txt -> MemVol:MixedCase.TXT"
has a05_names "MEM:nothere -> error 205"
has a05_names "MEM:ReadMe.txt/x -> error 212"
has a05_names "^name / -> MemVol:Dir1"
has a05_names "^name //ReadMe.txt -> MemVol:ReadMe.txt"
has a05_names "^name deep.txt -> MemVol:Dir1/sub/deep.txt"
same "$x/dh0/data/big.bin" "$work/dh0/data/big.back"
hasnt a06_copyin "error|fail"
has a11_delne "not empty"
has a13_delprot "protected"
has a17_lsnd "ent renamed.txt\|file\|11\|----rwed\|2020-01-01 12:00\|hello note"
has a18_type "Hello from the Lagoon mem backend"
has a19_typecase "Hello from the Lagoon mem backend"
hasnt a22_exec2 "error|not found|can.t"
has a22_runprog "info volume=MemVol"
has a23_escaped "colon"
has a23_long "long name"
has a25_lscase "ed README.TXT"
hasnt a26_delall "error|not deleted"
has a27_notfound "not found|object not"
has a28_exists "exists"
has a29_many "exall count=300 calls=[2-9]"
has a29_manyls "end 232 count=300"
has a30_seek "seek past end=-1 err=219"
has a30_seek "read 10 012abc6789"
has a30_seek "setsize=4"
has a30_seek "pos after setsize=4"
has a30_seek "read 4 012a"
has a30_locks "shared while excl: fail err=202"
has a30_locks "open while excl: fail err=202"
has a30_locks "delete while locked: fail err=202"
has a30_locks "duplock excl: fail"
has a30_locks "two shared: ok ok same=0"
has a30_locks "newfile while shared: fail err=202"
has a30_locks "lock while newfile: fail err=202"
has a30_fh "namefromfh: MemVol:fh.txt"
has a30_fh "examinefh: fh.txt size=5"
has a30_fh "parentoffh: MemVol:"
has a30_fh "changemode lock excl: ok"
has a30_fh "read 5 hello"
has a31_info2 "info volume=NewLabel"
has a32_status "MEM: volume NewLabel"
has a32_status "In-memory test file system"
has a33_llist "MEM +MEM:"
has a33_llist "AUTO +auto"
has a34_test "Test OK"
has a35_testbad "logon failed"
has a36_shares "vol"
has a38_inuse "in use"
has a40_unmount "Unmounted MEM:"
has a41_gone "no such device"
has b01_ro "Mounted"
has b02_rowrite "write.protected|protected"
has b03_roinfo "state=80"
has b04_rodel "protected"
has b05_rounmount "Unmounted"
has b06_badauth "logon failed"
has b07_badgone "no such device"
has b08_goodauth "Mounted"
has b09_goodtype "Hello from"
hasnt b09_goodstat "user:secret"
has b10_goodun "Unmounted"
has b11_url "as LGN0:"
has b12_urltype "Hello from"
has b13_urlun "Unmounted"
same "$x/dh0/data/big.bin" "$work/dh0/data/drop.back"
has c04_dropls "ent big\|file\|1048576"
has c05_dropstat "online"
if grep -qE "[1-9][0-9]* reconnects" "$o/c05_dropstat" 2>/dev/null; then ok; else bad "c05_dropstat: no reconnects"; fi
has c06_dropun "Unmounted"
has c09_downls2 "no disk|not mounted|226"
has c10_downstat "OFFLINE"
has d01_mountall "Mounted AUTO as AUTO:"
has d02_autols "ent sub\|dir"
hasnt d03_mountall2 "cannot"
has d04_list "AUTO +auto +AUTO:"
has d05_un "Unmounted"
if [ -n "$SMB_URL" ]; then
	has s01_mount "Mounted"
	has s02_info "info volume="
	same "$x/dh0/data/big.bin" "$work/dh0/data/smb.back"
	has s08_delne "not empty"
	has s11_ls "ent Renamed.txt\|file\|11"
	has s11_ls "2020-01-01 12:00"
	has s12_case "small file"
	has s13_dirall "lagoon-dir"
	has s13_seek "read 4 012a"
	has s13_locks "lock while newfile: fail err=202"
	has s13_fh "read 5 hello"
	has s14_status "online"
	has s17_un "Unmounted"
fi
echo "t_handler: $pass checks passed, $fail failed (outputs in $o)"
[ $fail = 0 ]
