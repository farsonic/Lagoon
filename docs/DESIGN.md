# Lagoon design

Lagoon mounts network shares as AmigaDOS volumes on AmigaOS 3.x (68020+),
over any bsdsocket.library stack, and shares Amiga folders over SMB 2/3 (the
server, [server.md](server.md)); it is developed and tested on Riptide.

| Protocol | Servers | Backend |
|---|---|---|
| SMB 2.0.2 to 3.1.1 | Windows, macOS (its file sharing is SMB), Samba, every NAS | `src/core/smb` |
| AFP 3.x over DSI | older Macs (OS X 10.x, AFP-only Time Capsules), Netatalk | `src/core/afp` |
| NFS v3 over TCP | Linux/BSD/Unix servers, NAS | `src/core/nfs` |

## Pieces

```
src/core/          portable C99 (gcc on Linux for tests, vbcc for the Amiga)
  ln_types.h       u8..u64, byte packing (ln_le32, ln_put_be16 ...), string helpers
  ln_err.h         LN_E* codes, ln_strerror
  ln_sys.h         alloc, time, random, logging, Ctrl-C  (src/host, src/amiga)
  ln_net.h         TCP/UDP sockets                        (src/host, src/amiga)
  ln_vfs.h         THE backend interface (LnOps) + registry + path helpers
  ln_url.h         smb:// afp:// nfs:// URLs
  ln_charset.h     UTF-8/UTF-16, NFC/NFD, remote name <-> Amiga name
  ln_conf.h        ENVARC:Lagoon/lagoon.conf (share list)
  ln_hash.h        MD4, MD5, SHA-256, SHA-512, HMAC      (crypto/hash.c)
  crypto/          ciphers (AES, CMAC, CCM, GCM, RC4 for SMB; bignum/CAST-128 for AFP)
  smb/ afp/ nfs/   the backends, each exporting `const LnOps ln_<scheme>_ops`
  ln_srv.h, srv/   the SMB2 server: connections, NTLMSSP, files, srvsvc,
                   NetBIOS/mDNS answers, the network loop; shares are LnOps
src/host/          POSIX sys + net (native tests, lncli), fs_posix.c (a host
                   directory as an LnOps backend, for the server's tests)
src/amiga/         sys_amiga.c, net_amiga.c (bsdsocket), fs_dos.c (an Amiga
                   folder as an LnOps backend, for the server), then:
  handler/         L:lagoon-handler, the DOS file system handler (one process per mount)
  cmd/             C:Lagoon  (MOUNT, UNMOUNT, LIST, MOUNTALL, STATUS ...;
                   SHARE, USER, SERVE run the server: cmd/serve.c)
  prefs/           SYS:Prefs/LagoonPrefs (GadTools share editor, network
                   browser, Sharing window: prefs/sharing.c)
tests/             t_*.c native unit/integration tests, lncli.c, servers/, amiga/run_emu.sh
install/           Install_Lagoon (Installer script), icons, ReadMe
```

## Rules for all code

- C99 that vbcc accepts: no anonymous structs/unions, no VLAs, no floating
  point, no `%.*s` with precision 0 tricks (use ln_snprintf, which is ours and
  behaves the same everywhere). `long long` is fine.
- The core never calls the OS: only ln_sys.h / ln_net.h. Memory via
  ln_alloc/ln_free (zeroed). Keep stack use small (handler stack is 16 KB):
  big buffers go on the heap.
- Big-endian host on the Amiga: always use the ln_le*/ln_be* helpers for wire
  data, never cast structs onto packets.
- Every backend function returns LN_OK/counts or a negative LN_E*. Lost
  connections return LN_ECONNRESET; `reconnect()` restores the session.
- Secrets: wipe password copies with ln_wipe when done.
- Comments: say what and why, briefly, like the existing files. SPDX header
  `GPL-2.0-only` on every file.
- Tests: native tests are `tests/t_<name>.c` (picked up by wildcard; exit 77
  = skipped, e.g. no server). Server-backed tests start their own server
  from `tests/servers/<proto>/` on a high port in a temp dir and stop it.
  The Makefile builds the core with ASan/UBSan; keep it warning-free with
  -Wall -Wextra.
- Amiga check: `make amiga` builds `build/amiga/lncli`;
  `tests/amiga/run_emu.sh CMDS 300 build/amiga/lncli` runs it on an emulated
  A1200 with Riptide, against servers on this host at 192.168.78.1.

## Backend interface (ln_vfs.h)

Paths are UTF-8 NFC relative to the share root ("" = root, "a/b.txt").
Backends handle their wire encodings (UTF-16LE for SMB, decomposed UTF-8 for
AFP, raw bytes for NFS, treated as UTF-8). Times are Unix UTC seconds.
`readdir` never returns "." or "..". `rename` must not overwrite. `remove`
deletes files and empty directories. `max_io` tells the handler how big its
read/write requests should be. `list_shares` serves the prefs Browse button.

## Server (src/core/srv)

The same `LnOps` interface runs the other way: every shared folder is an
LnOps file system (`fs_dos.c` on the Amiga, `fs_posix.c` or `mem` in the
tests), and the server turns SMB2 requests into LnOps calls. An
`LnSrvConn` takes whole SMB messages and returns the reply, so the protocol
is tested without sockets; `ln_srv_serve()` is one task with a
WaitSelect/poll loop over the listeners, the NetBIOS and mDNS sockets and
up to 16 clients. Signing reuses the client's key derivation
(`smb_derive_keys`, `smb_sign_msg` on an `SmbConn` that only holds keys).
Users are NT hashes from lagoon.conf. Details: [server.md](server.md).

## Handler (src/amiga/handler)

One handler process per mounted share, started by DOS from a DeviceNode
built by `Lagoon MOUNT` (dn_Handler = L:lagoon-handler, dn_Startup = the share
name in lagoon.conf). It converts packets (LOCATE_OBJECT, EXAMINE_*, FIND*,
READ/WRITE/SEEK, DELETE, RENAME, CREATE_DIR, SET_DATE/PROTECT/COMMENT,
INFO/DISK_INFO, PARENT, COPY_DIR, SAME_LOCK, *_FH, SET_FILE_SIZE, EXAMINE_ALL,
CHANGE_MODE, IS_FILESYSTEM, DIE ...) into LnOps calls, maps names with
ln_name_to_amiga/from_amiga, keeps a small attribute/directory cache, read-
ahead and write-behind buffers, sends keep-alives (ops->ping), reconnects
after network loss, and shows a volume on Workbench.

## Configuration

`ENVARC:Lagoon/lagoon.conf` (format in ln_conf.h), copied to `ENV:Lagoon/`
on boot. LagoonPrefs edits it; `Lagoon MOUNTALL` in S:User-Startup (after the
TCP/IP stack starts) mounts the shares marked automount, and
`Lagoon SERVE AUTO` starts the server when sharing is switched on. The
server's lines (`server`, `export`, `user`) live in the same file.

## Licence

GPL-2.0-only (same as Riptide).
