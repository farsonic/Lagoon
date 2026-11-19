#!/usr/bin/env python3
# Lagoon - the SMB server (build/host/lnsrv, started by e2e.sh) driven by
# impacket: share list, guest and password logons on each dialect impacket
# offers, list/put/get/mkdir/rename/delete, and refusals (wrong password,
# guest on the password share, writes to the read-only share).
#   impacket_test.py HOST PORT DIR      (DIR = e2e.sh's temp dir)
# SPDX-License-Identifier: GPL-2.0-only
import io
import os
import sys

from impacket.smbconnection import SMBConnection, SessionError
from impacket import smb3structs as s3

host, port, d = sys.argv[1], int(sys.argv[2]), sys.argv[3]
fails = 0


def check(cond, what):
    global fails
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        fails += 1


def conn(dialect=None):
    return SMBConnection("E2EAMIGA", host, sess_port=port, preferredDialect=dialect)


def put(c, share, name, data):
    c.putFile(share, name, io.BytesIO(data).read)


def get(c, share, name):
    b = io.BytesIO()
    c.getFile(share, name, b.write)
    return b.getvalue()


data = os.urandom(300000)
dialects = [("2.0.2", s3.SMB2_DIALECT_002), ("2.1", s3.SMB2_DIALECT_21), ("3.0", s3.SMB2_DIALECT_30),
            ("3.1.1", s3.SMB2_DIALECT_311), ("default", None)]   # impacket cannot ask for 3.0.2 alone

# guest
c = conn()
c.login("", "")
names = [x["shi1_netname"][:-1] for x in c.listShares()]
check("Public" in names and "Private" in names and "IPC$" in names, "share list as guest: %s" % names)
files = [f.get_longname() for f in c.listPath("Public", "*")]
check("hello.txt" in files, "guest: list Public")
check(get(c, "Public", "hello.txt") == b"hello from the Amiga\n", "guest: get hello.txt")
put(c, "Public", "imp.bin", data)
check(get(c, "Public", "imp.bin") == data, "guest: put/get 300 KB")
c.deleteFile("Public", "imp.bin")
check(not os.path.exists(os.path.join(d, "pub", "imp.bin")), "guest: delete")
c.logoff()

for label, dia in dialects:
    try:
        c = conn(dia)
        c.login("bob", "Corr3ct-Horse")
        c.createDirectory("Private", "dir")
        put(c, "Private", "dir\\f.bin", data)
        c.rename("Private", "dir\\f.bin", "dir\\g.bin")
        ok = get(c, "Private", "dir\\g.bin") == data
        listed = [f.get_longname() for f in c.listPath("Private", "dir\\*")]
        c.deleteFile("Private", "dir\\g.bin")
        c.deleteDirectory("Private", "dir")
        gone = not os.path.exists(os.path.join(d, "priv", "dir"))
        check(ok and "g.bin" in listed and gone, "bob, %s: mkdir/put/rename/get/list/delete/rmdir" % label)
        c.logoff()
    except Exception as e:  # noqa: BLE001 - report and go on
        check(False, "bob, %s: %r" % (label, e))

try:
    c = conn()
    c.login("bob", "not it")
    check(False, "wrong password accepted")
except SessionError as e:
    check("LOGON_FAILURE" in str(e), "wrong password refused (%s)" % e.getErrorString()[0])

c = conn()
c.login("", "")
try:
    c.listPath("Private", "*")
    check(False, "guest reached Private")
except SessionError as e:
    check("ACCESS_DENIED" in str(e), "guest on Private: ACCESS_DENIED")
try:
    put(c, "Archive", "x.txt", b"x")
    check(False, "write to the read-only share accepted")
except SessionError as e:
    check("ACCESS_DENIED" in str(e), "read-only share refuses a put")
check(get(c, "Archive", "keep.txt") == b"read only\n", "read-only share: get")

# NT hash logon (pass the hash): the server only knows hashes anyway
from impacket.ntlm import compute_nthash  # noqa: E402
c = conn()
c.login("bob", "", nthash=compute_nthash("Corr3ct-Horse").hex())
check(len(c.listPath("Private", "*")) >= 2, "logon with the NT hash")

sys.exit(1 if fails else 0)
