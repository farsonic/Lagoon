#!/usr/bin/env python3
# Lagoon - a tiny mDNS/DNS-SD responder for the discovery tests. It
# publishes fake file services (no real servers behind them):
#
#   "Lagoon Test SMB"  _smb._tcp         port 445
#   "Lagoon Test AFP"  _afpovertcp._tcp  port 548
#   "Lagoon Test NFS"  _nfs._tcp         port 2049  TXT path=/srv/lagoon
#   lagoontest.local   A  --addr (default 127.0.0.1)
#
#   responder.py [--bind ADDR] [--port N] [--mcast IFADDR] [--addr A]
#                [--no-additional] [--count N]
#
# Default: unicast on 127.0.0.1, any port (tests point ln_mdns_set_server at it).
# --mcast IFADDR joins 224.0.0.251 on that interface and listens on 5353
# (emulator test). Answers go to the sender's address and port (RFC 6762 6.7
# legacy unicast; queries from 5353 are answered by unicast too). With
# --no-additional, PTR answers carry no SRV/TXT/A (tests follow-up queries).
# Writes "ready PORT" to stdout when listening; --count N exits after N queries.
# SPDX-License-Identifier: GPL-2.0-only
import argparse
import socket
import struct
import sys

SERVICES = [
    ("Lagoon Test SMB", "_smb._tcp", 445, [b"model=Lagoon"]),
    ("Lagoon Test AFP", "_afpovertcp._tcp", 548, []),
    ("Lagoon Test NFS", "_nfs._tcp", 2049, [b"path=/srv/lagoon"]),
]
HOST = "lagoontest.local"


def name(labels):
    out = b""
    for l in labels:
        b = l.encode()
        out += bytes([len(b)]) + b
    return out + b"\0"


def split(n):
    return [x for x in n.split(".") if x]


def read_name(pkt, off):
    labels, jumped, end = [], False, off
    while True:
        l = pkt[off]
        if l & 0xC0 == 0xC0:
            if not jumped:
                end = off + 2
            off = ((l & 0x3F) << 8) | pkt[off + 1]
            jumped = True
            continue
        off += 1
        if l == 0:
            break
        labels.append(pkt[off:off + l].decode("utf-8", "replace"))
        off += l
    return labels, (end if jumped else off)


def rr(labels, rtype, rdata, ttl=120, flush=True):
    cls = 0x8001 if flush else 0x0001
    return name(labels) + struct.pack(">HHIH", rtype, cls, ttl, len(rdata)) + rdata


def ptr(svc):
    inst, typ, port, txt = svc
    return rr(split(typ) + ["local"], 12, name([inst] + split(typ) + ["local"]), flush=False)


def srv(svc):
    inst, typ, port, txt = svc
    return rr([inst] + split(typ) + ["local"], 33, struct.pack(">HHH", 0, 0, port) + name(split(HOST)))


def txtrr(svc):
    inst, typ, port, txt = svc
    data = b"".join(bytes([len(t)]) + t for t in txt) or b"\0"
    return rr([inst] + split(typ) + ["local"], 16, data)


def arec(addr):
    return rr(split(HOST), 1, socket.inet_aton(addr))


def answer(q, addr, additional):
    """answers, extra records for one question (labels, type)"""
    labels, qtype = q
    low = [l.lower() for l in labels]
    ans, add = [], []
    for svc in SERVICES:
        inst, typ, port, txt = svc
        tl = split(typ.lower()) + ["local"]
        if low == tl and qtype in (12, 255):
            ans.append(ptr(svc))
            if additional:
                add += [srv(svc), txtrr(svc), arec(addr)]
        elif low == ["_services", "_dns-sd", "_udp", "local"] and qtype in (12, 255):
            ans.append(rr(labels, 12, name(split(typ) + ["local"]), flush=False))
        elif low == [inst.lower()] + tl:
            if qtype in (33, 255):
                ans.append(srv(svc))
                if additional:
                    add.append(arec(addr))
            if qtype in (16, 255):
                ans.append(txtrr(svc))
    if low == split(HOST.lower()) and qtype in (1, 255):
        ans.append(arec(addr))
    return ans, add


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--mcast")
    ap.add_argument("--addr", default="127.0.0.1")
    ap.add_argument("--no-additional", action="store_true")
    ap.add_argument("--count", type=int, default=0)
    a = ap.parse_args()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if a.mcast:
        s.bind(("0.0.0.0", 5353))
        mreq = socket.inet_aton("224.0.0.251") + socket.inet_aton(a.mcast)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(a.mcast))
    else:
        s.bind((a.bind, a.port))
    print("ready %d" % s.getsockname()[1], flush=True)
    n = 0
    while True:
        pkt, src = s.recvfrom(9000)
        if len(pkt) < 12:
            continue
        qid, flags, qd = struct.unpack(">HHH", pkt[:6])
        if flags & 0x8000:
            continue
        off, qs, qraw = 12, [], b""
        try:
            for _ in range(qd):
                start = off
                labels, off = read_name(pkt, off)
                qtype, qcls = struct.unpack(">HH", pkt[off:off + 4])
                off += 4
                qs.append((labels, qtype))
                qraw += name(labels) + struct.pack(">HH", qtype, qcls & 0x7FFF)
        except (IndexError, struct.error):
            continue
        ans, add = [], []
        for q in qs:
            x, y = answer(q, a.addr, not a.no_additional)
            ans += x
            add += [r for r in y if r not in add]
        sys.stdout.write("query from %s:%d: %s\n" % (src[0], src[1], ["%s/%d" % (".".join(l), t) for l, t in qs]))
        sys.stdout.flush()
        if ans:
            legacy = src[1] != 5353
            hdr = struct.pack(">HHHHHH", qid if legacy else 0, 0x8400, qd if legacy else 0, len(ans), 0, len(add))
            s.sendto(hdr + (qraw if legacy else b"") + b"".join(ans) + b"".join(add), src)
        n += 1
        if a.count and n >= a.count:
            break


if __name__ == "__main__":
    main()
