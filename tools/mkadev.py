#!/usr/bin/env python3
"""Pack Lagoon EtherTalk: an AppleTalk connection file (type 'adev') for the classic Mac OS.

    mkadev.py --riptide ../riptide adev.bin atlk.elf -o "build/mac/Lagoon EtherTalk.bin"

The file holds the 'adev' resource (adev.S, flat code), the 'atlk' (ethertalk.c and its glue,
linked at 0: the image, then riptide tools/mac_elf.py's relocation table, which the first call
applies in place), the 'ICN#' -4032 that System 7.1's Network control panel loads from every
connection file (without it the panel skips the file), and a Finder bundle. Both code resources
carry the same ID, the low byte of the parameter RAM long that names the connection; the 1988
connections reference wants the 'atlk' in the system heap and both locked. Copy the result to an
HFS volume with `hcopy -m`, into the System Folder's Extensions folder.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse, os, struct, sys

ap = argparse.ArgumentParser()
ap.add_argument('--riptide', default=os.path.join(os.path.dirname(__file__), '..', '..', 'riptide'))
ap.add_argument('adev'); ap.add_argument('atlk_elf'); ap.add_argument('-o', required=True)
ap.add_argument('--id', type=int, default=168)
a = ap.parse_args()
sys.path.insert(0, os.path.join(a.riptide, 'tools'))
from mac_rsrc import ResourceFork, macbinary
from mac_elf import build_image

CREATOR = b'LGNE'          # Lagoon's EtherTalk (the application is 'LAGN')
SYSHEAP, LOCKED = 0x40, 0x10

# a 32 x 32 icon: an Ethernet plug on its cable, with a wave for Lagoon
ICON = """
................................
................................
..........############..........
..........#..........#..........
..........#.#.#.#.#..#..........
..........#.#.#.#.#..#..........
..........#..........#..........
........################........
........#..............#........
........#..............#........
........#..............#........
........#..............#........
........#..............#........
........#..............#........
........#..............#........
........################........
..........#..........#..........
...........#........#...........
............########............
..............####..............
..............####..............
..............####..............
..............####..............
..............####..............
....##........####........##....
...#..#.......####.......#..#...
..#....#......####......#....#..
.#......#.....####.....#......#.
#........#....####....#........#
..........#...####...#..........
...........###....###...........
................................
"""
rows = [r for r in ICON.strip('\n').split('\n')]
assert len(rows) == 32 and all(len(r) == 32 for r in rows)
def bits(rows):
    out = b''
    for r in rows:
        v = 0
        for c in r: v = v << 1 | (c == '#')
        out += struct.pack('>I', v)
    return out
icon = bits(rows)
# the mask: each row filled between its outermost pixels, so the plug reads as solid
mask_rows = []
for r in rows:
    if '#' in r:
        l, h = r.index('#'), r.rindex('#')
        mask_rows.append('.' * l + '#' * (h - l + 1) + '.' * (31 - h))
    else:
        mask_rows.append('.' * 32)
icn = icon + bits(mask_rows)

adev = open(a.adev, 'rb').read()
img, nrel, end = build_image(a.atlk_elf)
rf = ResourceFork()
rf.add(b'adev', a.id, adev, attrs=LOCKED)
rf.add(b'atlk', a.id, img, attrs=SYSHEAP | LOCKED)
rf.add(b'ICN#', -4032, icn)
rf.add(b'ICN#', 128, icn)
rf.add(CREATOR, 0, b'\x10Lagoon EtherTalk')
rf.add(b'FREF', 128, b'adev' + struct.pack('>H', 0) + b'\0')
rf.add(b'BNDL', 128, CREATOR + struct.pack('>HH', 0, 1) +
       b'ICN#' + struct.pack('>HHH', 0, 0, 128) + b'FREF' + struct.pack('>HHH', 0, 0, 128))
def pstr(t): return bytes([len(t)]) + t
vers = struct.pack('>BBBBH', 0x00, 0x10, 0x20, 0x01, 0) + pstr(b'0.1d1') + pstr(b'0.1d1, Lagoon EtherTalk (AppleTalk on Ethernet)')
rf.add(b'vers', 1, vers)
open(a.o, 'wb').write(macbinary('Lagoon EtherTalk', b'adev', CREATOR, b'', rf.build(), finder_flags=0x2000))
print(f"{a.o}: adev {len(adev)} bytes, atlk {len(img)} bytes with {nrel} relocations")
