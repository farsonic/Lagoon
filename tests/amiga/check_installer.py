#!/usr/bin/env python3
# Lagoon - static check of an Amiga Installer script (install/Install_Lagoon):
# balanced parentheses and strings, every function is an Installer V43
# function or a procedure the script defines, every #variable is set (or is
# a procedure argument) somewhere, the quoted options of copyfiles/startup
# etc. are known. It does not run the script (InstallerLG would).
#
#   tests/amiga/check_installer.py install/Install_Lagoon
# SPDX-License-Identifier: GPL-2.0-only
import re
import sys

FUNCS = set("""
abort about all and append askbool askchoice askdir askdisk askfile asknumber
askoptions askstring assigns bitand bitnot bitor bitxor cat choices command
complete compression confirm copyfiles copylib database debug default delay
delete delopts dest disk earlier execute exists exit expandpath files fileonly
font foreach getassign getdevice getdiskspace getenv getsize getsum getversion
help iconinfo if in infos makeassign makedir message newname newpath nofail
noposition noreq not onerror optional or override pathonly patmatch pattern
procedure prompt protect quiet range rename resident retrace rexx run safe
select set setenv settings sizeof source startup strlen substr swing symbolset
symbolval tackon textfile tooltype transcript trap until user welcome while
working closemedia effect openwbobject setmedia showmedia showwbobject
""".split()) | {"=", "<>", "<", ">", "<=", ">=", "+", "-", "*", "/", "shiftleft", "shiftright", "xor"}


def tokens(text):
    i, n, line = 0, len(text), 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif c in " \t\r":
            i += 1
        elif c == ";":
            while i < n and text[i] != "\n":
                i += 1
        elif c in "()":
            yield c, c, line
            i += 1
        elif c in "\"'":
            j, s = i + 1, ""
            while j < n and text[j] != c:
                if text[j] == "\\" and j + 1 < n:
                    s += text[j:j + 2]
                    j += 2
                    continue
                if text[j] == "\n":
                    line += 1
                s += text[j]
                j += 1
            if j >= n:
                raise SyntaxError("line %d: unterminated string" % line)
            yield "str", s, line
            i = j + 1
        else:
            j = i
            while j < n and text[j] not in " \t\r\n();\"'":
                j += 1
            yield "atom", text[i:j], line
            i = j


def parse(text):
    stack, top = [], []
    cur = top
    for kind, val, line in tokens(text):
        if kind == "(":
            new = []
            cur.append((new, line))
            stack.append(cur)
            cur = new
        elif kind == ")":
            if not stack:
                raise SyntaxError("line %d: unbalanced ')'" % line)
            cur = stack.pop()
        else:
            cur.append(((kind, val), line))
    if stack:
        raise SyntaxError("unbalanced '(' at end of file")
    return top


def main(path):
    text = open(path, encoding="latin-1").read()
    try:
        tree = parse(text)
    except SyntaxError as e:
        print("FAIL %s: %s" % (path, e))
        return 1
    procs, setvars, used, problems = set(), set(), [], []

    def walk(node):
        items = node
        if not items:
            return
        head, hline = items[0]
        if isinstance(head, tuple) and head[0] == "atom":
            name = head[1]
            if name.lower() == "procedure" and len(items) > 1:
                procs.add(items[1][0][1])
                for a, _ in items[2:]:
                    if isinstance(a, tuple) and a[1].startswith("#"):
                        setvars.add(a[1])
            if name.lower() == "set":
                for k in range(1, len(items), 2):
                    a = items[k][0]
                    if isinstance(a, tuple):
                        setvars.add(a[1])
            used.append((name, hline))
        elif isinstance(head, tuple) and head[0] == "str":
            pass                          # ("%s" args): formatted string
        for item, line in items:
            if isinstance(item, list):
                walk(item)
            elif item[0] == "atom" and item[1].startswith("#"):
                refs.append((item[1], line))

    refs = []
    for item, _ in tree:
        if isinstance(item, list):
            walk(item)
    for name, line in used:
        if name.lower() not in FUNCS and name not in procs and not name.startswith("#"):
            problems.append("line %d: unknown function %s" % (line, name))
    for v, line in refs:
        if v not in setvars:
            problems.append("line %d: %s is never set" % (line, v))
    for p in problems:
        print("FAIL %s: %s" % (path, p))
    if not problems:
        print("ok   %s: %d calls, %d procedures, %d variables" % (path, len(used), len(procs), len(setvars)))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "install/Install_Lagoon"))
