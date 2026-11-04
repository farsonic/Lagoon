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
