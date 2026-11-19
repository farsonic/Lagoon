# Lagoon status

## 0.2 (not released yet): sharing Amiga folders

The SMB server ([server.md](server.md)): `Lagoon SHARE/USER/SERVE`,
LagoonPrefs' Sharing window, the Installer's `Lagoon SERVE AUTO` line.

- Native (Linux, ASan/UBSan): `t_smbsrv` (670 checks: MS-NLMP NTLMv2
  vectors, lagoon.conf, NetBIOS/mDNS answers read back with Lagoon's own
  discovery code, raw protocol units with compounds, then Lagoon's SMB
  client against the server on 2.0.2/2.1/3.0/3.0.2/3.1.1, CMAC and GMAC,
  signing required, guest, wrong passwords, read-only, share lists) and
  `t_smbsrv_clients` (smbclient 4.19 on every dialect with signing
  required; impacket on 2.0.2/2.1/3.0/3.1.1 and an NT-hash logon).
- Emulated A1200 (68020, AROS ROM, Riptide 0.14), `tests/amiga/run_share_emu.sh`:
  the Sharing window driven by keyboard (folders, guests, a user, Start
  at boot, Start/Stop server, Save), then from the host: share list, guest
  and password shares, smbclient on every dialect with signing, impacket,
  wrong password and guest refusals, `nmblookup -A`, an mDNS query; the
  saved lagoon.conf holds the NT hash, never the password.
- Speed on the emulated A1200 (512 KB with smbclient, logon included):
  SMB 2.1 unsigned ~325 KB/s to the Amiga, ~150-185 KB/s from it; SMB 3.1.1
  signed (GMAC) ~85 KB/s to, ~75 KB/s from.
- Not tested yet: Windows Explorer, macOS Finder, mount.cifs, GNOME/KDE,
  real hardware, other stacks. Not done: encryption, WS-Discovery (Windows'
  Network folder), CHANGE_NOTIFY, oplocks/leases, enforced byte-range
  locks, named streams, ACLs.

# Lagoon 0.1 status

## Tested
- Native (Linux, ASan/UBSan): 12 test programs, ~6900 checks, against real
  Samba 4.19 (13 SMB dialect/signing/encryption variants, vfs_fruit as macOS),
  Netatalk 3.1.18 (AFP guest/DHX2/clear text) and nfs-ganesha 4.3 (NFSv3).
- Emulated A1200 (68020, 14 MHz, AROS ROM, FS-UAE with Riptide's uaenet patch,
  Riptide 0.14): lagoon-handler + C:Lagoon with SMB (signing mandatory), AFP
  and NFS: copies byte-identical, directory ops, locks, reconnect, offline mode;
  LagoonPrefs on PAL and NTSC screens (browse, list shares, test, mount).

## 68020 speed (1 MB, emulated A1200)
| SMB unsigned 3.0.2 | SMB 3.1.1 signed (GMAC) | SMB encrypted (GCM) | AFP read/write | NFS read/write |
|---|---|---|---|---|
| ~360 KB/s | ~90 KB/s | ~38 KB/s | ~450/240 KB/s | ~300/180 KB/s |

## Known limits / not yet done
- Install_Lagoon has only been checked statically (no Installer in the test
  emulator): run it once on a real Amiga or under InstallerLG before release.
- Catalogs (de/fr/es/it) were checked by tools/mkcatalog.py, not on screen.
- 68030/040/060 not measured (the emulator setup hangs in Riptide's first ping with those CPUs).
- Not tested on real hardware or on other stacks (Roadshow, Miami, AmiTCP).
- SMB: no SMB1, Kerberos, DFS, compounding, durable handles; no file notes.
- AFP: data fork only (no resource forks), no AFP 2.x/AppleTalk.
- NFS: v3 over TCP only, AUTH_SYS only, no locking.
- Handler: no notifications, links or record locks (ERROR_ACTION_NOT_KNOWN).
- Each program links all three backends (~170 KB of code each).
