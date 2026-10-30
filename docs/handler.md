# L:lagoon-handler

The handler is the AmigaDOS file system that turns a Lagoon backend (SMB,
AFP, NFS, or the in-memory test backend) into a DOS volume. There is one
handler process per mounted share.

Sources: `src/amiga/handler/` (`entry.c`, `handler.c`: the DOS side;
`hcore.c`/`hcore.h`: the portable file system logic), `src/amiga/mount.c`
(building the DeviceNode, shared with C:Lagoon and LagoonPrefs),
`src/core/mem/mem_ops.c` (test backend). Tests: `tests/t_hcore.c` (native,
hcore + mem backend under ASan/UBSan), `tests/amiga/t_handler.sh` (the real
handler and C:Lagoon on the emulated A1200).

## Start-up

`Lagoon MOUNT` (or `ln_amiga_mount()`) adds a DeviceNode with

| field | value |
|---|---|
| `dn_Handler` | `L:lagoon-handler` |
| `dn_GlobalVec` | -1 (C handler: DOS puts the startup packet in `pr_MsgPort`) |
| `dn_StackSize` | 16384 |
| `dn_Priority` | 5 |
| `dn_Startup` | BSTR: a share name from lagoon.conf, or `&` + hex address of an `LnMountInfo` |

and calls `DeviceProc()` on it, so DOS loads and starts the handler at
once. The handler

1. reads `ENV:Lagoon/lagoon.conf` (fallback `ENVARC:`) for the log level,
   and the share when `dn_Startup` is a name (this is what a DOSDriver
   with `Startup = "NAS"` uses); with `&address` it takes the share from
   the `LnMountInfo` that C:Lagoon filled in (ad-hoc URLs, `USER`,
   `PASSWORD`, `READONLY`, `VOLUME` overrides),
2. opens bsdsocket.library (`ln_net_init`); without a TCP/IP stack the
   startup fails with "no TCP/IP stack running",
3. mounts with `ln_vfs_mount_url(url, credentials)`,
4. on failure writes the LN error code into `LnMountInfo.error` (so
   C:Lagoon can print `ln_strerror()`, e.g. "logon failed (user name or
   password)"), replies the startup packet with `DOSFALSE` and a DOS error
   (table below), and exits; C:Lagoon then removes the device again,
5. on success sets `dn_Task`, replies `DOSTRUE`, and only then adds the
   volume node (DOS may hold the DOS list while it waits for the reply)
   and sends an `IECLASS_DISKINSERTED` input event so Workbench shows the
   icon.

Volume name: the share's `volume=` label, else the share name, else the
device name (`:` and `/` become `_`). Volume date: the mount time.

**Disk type.** The volume node and `ACTION_INFO` report `ID_DOS_DISK`
('DOS\0'). A private type such as 'LGN\0' would be more honest, but
Workbench, DiskInfo and many programs only treat volumes with one of the
known DOS types as ordinary disks (icons, free space, drag and drop).
`ACTION_FORMAT`, `ACTION_SERIALIZE_DISK` etc. are refused with
`ERROR_ACTION_NOT_KNOWN`, so nothing can try to format a share.

## Packets

| packet | notes |
|---|---|
| `LOCATE_OBJECT`, `FREE_LOCK`, `COPY_DIR`, `PARENT`, `SAME_LOCK` | shared/exclusive locks per object |
| `EXAMINE_OBJECT`, `EXAMINE_NEXT` | ExNext iterates over a snapshot of the directory taken at the first call (`fib_DiskKey` = index), so it is stable while files are added/deleted |
| `EXAMINE_ALL`, `EXAMINE_ALL_END` | `ED_NAME`..`ED_OWNER`, `eac_MatchString` (`MatchPatternNoCase`) and `eac_MatchFunc`; `eac_LastKey` = index into the same snapshot; other types: `ERROR_BAD_NUMBER` |
| `FINDINPUT`, `FINDOUTPUT`, `FINDUPDATE`, `READ`, `WRITE`, `SEEK`, `END`, `SET_FILE_SIZE` | see I/O |
| `FH_FROM_LOCK`, `COPY_DIR_FH`, `PARENT_FH`, `EXAMINE_FH`, `CHANGE_MODE` | |
| `DELETE_OBJECT`, `RENAME_OBJECT`, `CREATE_DIR` | CreateDir returns an exclusive lock, as FFS does |
| `SET_PROTECT`, `SET_COMMENT`, `SET_DATE` | passed to the backend's `setattr` |
| `INFO`, `DISK_INFO` | sizes from `statfs` (cached 5 s), block size scaled so the block count fits 31 bits |
| `CURRENT_VOLUME`, `IS_FILESYSTEM`, `FLUSH`, `INHIBIT` (no-op) | |
| `RENAME_DISK` | renames the local volume label only (Relabel); the server is not changed |
| `WRITE_PROTECT` | local read-only switch (with pass key), like `Lock DRIVE ON` |
| `DIE` | unmounts if no locks or files are open, else `ERROR_OBJECT_IN_USE` |
| `LOCK_RECORD`, `FREE_RECORD`, notification, links, `SET_OWNER`, anything else | `ERROR_ACTION_NOT_KNOWN` |
| `ACTION_LAGOON_STATUS` (`0x4C470001`) | private: fills an `LnStatus` for `Lagoon STATUS` (mount.h) |

### Lock semantics

Locks and open files are tracked by remote path (compared case-insensitively,
since that is what an Amiga name means):

- an exclusive lock (`ACCESS_WRITE`) conflicts with any other lock or open
  file on the object, a shared lock conflicts with an exclusive one:
  `ERROR_OBJECT_IN_USE`;
- `MODE_NEWFILE` takes an exclusive lock, `MODE_OLDFILE` and
  `MODE_READWRITE` shared ones (as in FFS, `MODE_OLDFILE` may also write;
  if the server refuses write access the file is opened read-only and
  writes fail with `ERROR_WRITE_PROTECTED`);
- `DupLock` of an exclusive lock fails; `DupLockFromFH` always gives a
  shared lock, even on a `MODE_NEWFILE` file, so that `NameFromFH()` works;
- deleting an object that is locked or open: `ERROR_OBJECT_IN_USE`;
- renaming a locked/open object is allowed; its locks and handles (and
  those of everything below a renamed directory) follow the new name.
  Renaming a directory into itself gives `ERROR_OBJECT_IN_USE`, onto an
  existing object `ERROR_OBJECT_EXISTS`; a rename that only changes the
  case of a name works on case-sensitive and case-insensitive servers;
- `ACTION_DIE` (and Ctrl-C sent to the handler) only unmounts when nothing
  is locked or open.

## Names

- Packet names are BSTRs; `DEV:`/`VOL:` prefixes are stripped (a colon
  means "from the root"), `/` at the start or after another `/` means
  parent, a trailing `/` is ignored. A second colon, `.`/`..` as a name to
  create, or a name longer than 107 bytes to create:
  `ERROR_INVALID_COMPONENT_NAME`.
- Remote names (UTF-8) are shown with `ln_name_to_amiga()`: ISO-8859-1
  where possible, everything else (and `:`, `/`, `%`) as `%XX` escapes of
  the UTF-8 bytes, which `ln_name_from_amiga()` undoes when you type them.
- Matching is case-insensitive (Latin-1 rules, like DOS) also on
  case-sensitive servers (NFS, Samba with `case sensitive = yes`): a name is
  first tried as typed (one `stat`); if that fails the directory listing is
  searched (exact display name, then the exact remote name, then
  case-insensitively). When a fresh listing is in the cache it is used
  directly, which also gives the server's real spelling.
- **Long names.** A FileInfoBlock holds 107 bytes. Names whose Amiga form
  is longer are cut to 102 bytes (never inside a `%XX`) plus `~` and four
  hex digits of a hash of the remote name, e.g.
  `abcdefghij...uvwx~50DE`. The shortened name can be used to open,
  delete or rename the file. Two remote names that are the same name to the
  Amiga (`Foo` and `foo` on a case-sensitive server, or two long names with
  the same prefix) are kept apart the same way: the second one is listed as
  `foo~1A2B`. Nothing is skipped (names over 1023 bytes are skipped with a
  log line; no real server sends those).
- Comments: UTF-8 on the server, Latin-1 in `fib_Comment` (79 bytes);
  characters outside Latin-1 become `?`.

## Attributes

- Protection: `LnStat.prot` (`LN_P_*`, bit set = allowed) becomes the
  FIB bits with RWED inverted; A, P and S map directly. The server's
  hidden flag has no Amiga bit; `SetProtection` keeps it. The H (hold) bit
  and the group/other bits are not used.
- Dates: Unix UTC on the server, local time on the Amiga, with the offset
  from locale.library (`ln_tz_minutes()`, read at start-up).
- `fib_Size` is clamped to 2 GB - 1 (DOS file positions are 32-bit signed);
  `fib_NumBlocks` uses the block size reported in `ACTION_INFO`.
- `fib_OwnerUID`/`GID` (and `ED_OWNER`) come from the server's uid/gid
  when it has them.

## I/O and caching (tuned for a 68020)

- `max_io` comes from the backend (clamped to 512 B .. 1 MB). Each open
  file has one buffer of `min(max_io, 64 KB)`, used either for
  read-ahead (small reads are served from it) or write-behind (small
  sequential writes are coalesced into one `max_io`-sized request).
  Requests at least as large as the buffer go straight to the backend,
  split into `max_io` pieces.
- Write-behind data is flushed before any read, seek-to-end, size change,
  Examine of the same object, rename, `setattr`, close, `ACTION_FLUSH`,
  and after 1 s without requests (the timer). A delayed write that fails
  (disk full, connection gone for good) is reported by the next `Write`,
  `Read` or by `Close`.
- Reads through one handle see unflushed writes of another handle on the
  same file (they are flushed first), and writes drop other handles'
  read-ahead.
- Directory listings (4) and attributes (16) are cached for 3 s; every
  change the handler makes invalidates the affected entries (the object,
  its parent's listing, everything below a renamed/deleted directory).
  Changes made by other clients show up after at most 3 s.
- `statfs` is cached for 5 s.

## Keep-alive, reconnect, offline

- A timer.device request wakes the handler every 10 s (every 1 s while
  write-behind data is waiting); after 60 s without server traffic it
  calls `ops->ping()`.
- When a backend call returns `LN_ECONNRESET`, the handler calls
  `ops->reconnect()` with back-off (0.5, 1, 2, 4, 8, 8 ... s, up to 30 s,
  Ctrl-C stops it) and retries the call (up to three times). Open files
  whose handles did not survive (`LN_ESTALE`) are reopened by path
  (without create/truncate) and the call is retried.
- If the server stays away, the handler marks itself offline: requests
  fail at once with `ERROR_NO_DISK` ("No disk present"), and every 10 s one
  request tries a single reconnect. The volume stays mounted, locks and
  file handles stay valid, and work continues when the server is back.
  `Lagoon STATUS` shows `OFFLINE`.

## Errors

The one mapping table (`doserr()` in handler.c):

| LN code | DOS error |
|---|---|
| `LN_ENOENT`, `LN_ESTALE` | `ERROR_OBJECT_NOT_FOUND` |
| `LN_EEXIST` | `ERROR_OBJECT_EXISTS` |
| `LN_ENOTDIR`, `LN_EISDIR` | `ERROR_OBJECT_WRONG_TYPE` |
| `LN_ENOTEMPTY` | `ERROR_DIRECTORY_NOT_EMPTY` |
| `LN_EACCES` | `ERROR_READ_PROTECTED` (reads, opening, locking), `ERROR_DELETE_PROTECTED` (delete), else `ERROR_WRITE_PROTECTED` |
| `LN_EROFS` | `ERROR_DISK_WRITE_PROTECTED` |
| `LN_ENOSPC` | `ERROR_DISK_FULL` |
| `LN_EINUSE` | `ERROR_OBJECT_IN_USE` |
| `LN_EINVAL`, `LN_ENAMETOOLONG` | `ERROR_INVALID_COMPONENT_NAME` (`SEEK`/`SET_FILE_SIZE`: `ERROR_SEEK_ERROR`) |
| `LN_ENOMEM` | `ERROR_NO_FREE_STORE` |
| `LN_ENOTSUP` | `ERROR_ACTION_NOT_KNOWN` |
| `LN_EAUTH` | `ERROR_READ_PROTECTED` |
| `LN_EBREAK` | `ERROR_BREAK` |
| `LN_ENOSHARE` | `ERROR_DEVICE_NOT_MOUNTED` at start-up, else `ERROR_OBJECT_NOT_FOUND` |
| `LN_ETIMEDOUT`, `LN_ECONNREFUSED`, `LN_ECONNRESET`, `LN_EHOSTUNREACH`, `LN_ENOHOST`, `LN_ENONET` | `ERROR_NO_DISK` |
| `LN_EIO`, `LN_EPROTO`, `LN_ECRYPTO`, others | `ERROR_NOT_A_DOS_DISK` |

C:Lagoon prints the LN text (`ln_strerror`) for start-up failures, which
is more precise than the DOS code.

## Logging

With `option loglevel=1` (or 2, 3) in lagoon.conf the handler appends to
`T:lagoon-<share>.log` (level 1: mounts, reconnects, failures; 2: also
keep-alives and backend debug output; 3: packet dumps from the backends).
With level 0 nothing is written.

## Memory and robustness

- The handler is linked with `-nostdlib` and its own entry (`entry.c`,
  which must stay first); it opens dos/utility/timer/input itself and uses
  only vc.lib functions that need no initialisation. Big buffers are on the
  heap (stack 16 KB). Packet names are copied into fixed 256-byte buffers.
- Locks carry a magic number and our port; foreign or stale locks give
  `ERROR_INVALID_LOCK`, unknown file handles `ERROR_OBJECT_WRONG_TYPE`.
- On `DIE`: flushes and closes everything, unmounts, closes bsdsocket,
  removes the volume, clears `dn_Task`, replies the packets still queued
  with `ERROR_DEVICE_NOT_MOUNTED`, and replies the DIE packet under
  `Forbid()` so the code is not unloaded before the process has gone.
  `Lagoon UNMOUNT` then removes the DeviceNode and frees its seglist,
  BSTRs and mount record.
- The seglist belongs to the DeviceNode: do not make lagoon-handler
  resident. If a device is used again after its handler quit (without
  UNMOUNT), DOS restarts the handler from the same seglist; all state is
  re-initialised at start-up.

## Testing with the mem backend

`mem://host/share?options` keeps a file tree in memory (see the header of
`src/core/mem/mem_ops.c`): `seed=1` creates sample files (mixed case, a
name with `:`, a non-Latin-1 name, a 134-byte name, a script, nested
directories), `many=N` a big directory, `ro=1`, `size=N` (disk full),
`casefold=1`, `pass=X` (logon failure), `dropevery=N` (every Nth call loses
the connection until `reconnect()`), `refuse=K` (K failed reconnects),
`stale=1` (open files do not survive a reconnect).

    make test                       # t_hcore: 3000+ checks
    tests/amiga/t_handler.sh        # emulator, as root; SMB_URL=... adds a Samba run
