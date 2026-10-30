#!/bin/sh
# Lagoon - run every native test in build/host (exit 77 = skipped).
cd "$(dirname "$0")/.." || exit 1
fail=0
for t in build/host/t_*; do
	[ -x "$t" ] || continue
	"$t"; r=$?
	if [ $r -eq 77 ]; then :; elif [ $r -ne 0 ]; then echo "FAIL $t"; fail=1; fi
done
[ $fail -eq 0 ] && echo "all tests passed"
exit $fail
