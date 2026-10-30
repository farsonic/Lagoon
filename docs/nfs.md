# NFS v3 backend

`src/core/nfs/` mounts NFS version 3 exports from Linux, BSD and Unix
servers and NAS boxes (anything with an NFSv3 server: knfsd, nfs-ganesha,
FreeBSD/NetBSD/OpenBSD nfsd, Synology, QNAP, TrueNAS, macOS `nfsd` ...).
It is written from the specifications: RFC 1813 (NFSv3 and MOUNT v3),
RFC 5531 (ONC RPC), RFC 1833 (portmapper) and RFC 4506 (XDR).

| File | What |
|---|---|
| `nfs_rpc.h/.c` | XDR, RPC over TCP (record marking, XIDs, AUTH_SYS, reply/reject parsing, reconnect + retransmit), portmapper GETPORT, status/attribute mapping |
| `nfs_ops.c` | `ln_nfs_ops`: MOUNT (MNT/UMNT/EXPORT) and the NFSv3 procedures |

## URL

    nfs://host[:nfsport]/export/path[?option&option...]

Examples:

    nfs://nas.local/volume1/amiga
    nfs://192.168.1.10/srv/data/games?uid=1000&gid=1000
    nfs://10.0.0.5:2049/export?mountport=20048&secure=no

The path after the host is the export *plus* an optional directory inside
it: Lagoon tries `MNT` on the whole path, then on shorter prefixes, and
looks the rest up inside the export it got (so `nfs://nas/srv/data/games`
works whether the server exports `/srv/data` or `/srv/data/games`).

Options:

| Option | Default | Meaning |
|---|---|---|
| `uid=`, `gid=` | 65534, 65534 | the Unix identity sent in AUTH_SYS ("nobody" by default). Use your account's numbers on the server to own your files. |
| `gids=a,b,c` | none | supplementary groups (up to 16) |
| `mountport=` | portmapper | MOUNT service port: with it and an explicit NFS port in the URL the portmapper (111) is not needed |
| `pmapport=` | 111 | portmapper port |
| `secure=no` | yes | do not bind a reserved local port (<1024) |
| `sync=yes` | no | FILE_SYNC writes instead of UNSTABLE + COMMIT |
| `maxio=` | 32768 | largest READ/WRITE (1024..65536); further capped by the server's FSINFO rtmax/wtmax |
| `timeout=` | 30 | seconds to wait for a reply before reconnecting and retransmitting |
| `ro` | no | refuse all changes locally; the volume shows as read-only |
| `access=no` | yes | do not ask the server (ACCESS) for permissions in `stat`; derive them from the mode bits |
| `fmode=`, `dmode=` | 0644, 0755 | octal modes for new files and directories |

User name and password in the URL are ignored: NFSv3 with AUTH_SYS has no
login, the server trusts the uid/gid the client sends.

## What the server must allow

- **The Amiga's address in the export list.** Linux `/etc/exports`:
  `/srv/amiga 192.168.1.0/24(rw,sync,no_subtree_check)`; on a NAS, add an
  NFS permission rule for the Amiga's IP (Synology: Shared Folder > Edit >
  NFS Permissions; QNAP: Shared Folder > Edit Shared Folder Permission > NFS
  host access).
- **TCP.** Lagoon speaks NFS over TCP only (every current server has it).
- **NFS version 3** must be enabled (some NAS boxes default to v4 only).
- **Ports.** Lagoon binds a reserved local port (1023 downwards) for MOUNT
  and NFS, which satisfies servers that insist on "secure" ports (Linux
  `secure`, the default; BSD `-resvport`). If your stack does not allow it
  the backend falls back to an ordinary port; then the server needs
  `insecure` (Linux exports option) or "Allow connections from
  non-privileged ports" (Synology/QNAP checkbox).
- **The portmapper (TCP 111)** to find MOUNT and NFS, unless you give the
  ports (`nfs://host:2049/path?mountport=N`). Firewalls must pass 111, 2049
  and the mountd port (fixed on most NAS boxes; on Linux set it in
  `/etc/nfs.conf` `[mountd] port=`).
- **Identity.** The server maps the uid/gid you send. With root squashing
  (the default everywhere) `uid=0` becomes nobody; use your own uid, or
  `all_squash,anonuid=1000,anongid=1000` on the export to map every client to
  one account. AUTH_SYS only: Kerberos (sec=krb5*) exports cannot be mounted.

## Behaviour

- **Paths and names** are passed as raw bytes and treated as UTF-8;
  `ln_name_to_amiga` turns them into Amiga names. `readdir` uses
  READDIRPLUS (names and attributes in one go) and falls back to READDIR +
  LOOKUP on servers that answer NOTSUPP.
- **Attributes**: type, size, mtime; `ctime` (creation) is the mtime, NFS has
  no birth time. `mode`, `uid`, `gid` and `fileid` are filled in.
  Protection bits: `stat`/`fstat` ask the server (ACCESS), so they are right
  even with root squashing and ACLs; `readdir` derives them from the mode bits
  against the uid/gid/gids in use (owner, group or other bits; everything for
  uid 0). R = read, W = modify (D follows W), E = execute (search for
  directories). Files are never hidden (dot files are ordinary files).
- **Setting attributes**: SetDate sets the mtime, SetProtection maps R/W/E to
  the owner's r/w/x bits (group and other bits are left alone), a full Unix
  mode can be set with `LN_SET_MODE`. File comments are not supported.
- **Creating files**: GUARDED create (EXCLUSIVE with a verifier for
  `LN_O_EXCL`, followed by SETATTR of the mode as RFC 1813 asks); opening an
  existing file with `LN_O_TRUNC` sets its size to 0. `rename` refuses to
  replace an existing object (LN_EEXIST) - it looks the target up first; a
  pure case change on a case-insensitive server is allowed. `remove` uses
  REMOVE or RMDIR depending on the object's type.
- **Writes** are UNSTABLE, and a copy of uncommitted data (up to 128 KB per
  file) is kept until COMMIT, which happens when that much has piled up and
  on flush/close. If the server's write verifier changes (it restarted and
  may have lost cached data) the kept data is written again with FILE_SYNC.
  `sync=yes` makes every WRITE stable instead.
- **Symbolic links** show up as links (LN_T_LINK, size = target length) in
  `stat` and `readdir`. When resolving a path Lagoon follows relative links
  in any component, and `open`/`opendir` also follow a link in the last
  component, so linked files and directories work. Absolute link targets are
  followed only when they point inside the mounted export path; links that
  leave the share (`/etc/passwd`, `../..` above the share root) fail with
  "object not found". Lagoon never creates links.
- **Directory handle cache**: handles of the 16 most recently used
  directories are kept by path, so most operations cost one LOOKUP plus the
  operation. Removing or renaming a directory drops its entries.
- **Stale handles** (NFS3ERR_STALE / BADHANDLE): the cache is flushed and the
  path looked up again (MNT again if the share root itself went stale); open
  files are found again by their path and the call is retried.
- **NFS3ERR_JUKEBOX** (file being recalled from offline storage) is retried
  up to 10 times with growing delays (0.5 s, 1 s, ... about 27 s in all),
  then reported as "object in use".
- **Lost connections**: a call that times out or loses its connection is
  sent again once on a new connection with the same XID (the server's
  duplicate request cache answers non-idempotent calls it already did).
  If that fails the call returns LN_ECONNRESET and the handler calls
  `reconnect()`, which reconnects, MNTs again and keeps every open file:
  NFS file handles survive server reboots.
- **statfs**: FSSTAT; free space is what is available to the user (`abytes`).
  The volume name is the last component of the URL path.
- **list_shares**: MOUNT EXPORT; the comment lists the allowed client groups.
- **ping**: the NFS NULL procedure.

Error mapping (nfsstat3 -> LN_E*): PERM, ACCES -> EACCES; NOENT, NXIO,
NODEV -> ENOENT; EXIST -> EEXIST; NOTDIR -> ENOTDIR; ISDIR -> EISDIR;
NOTEMPTY -> ENOTEMPTY; ROFS -> EROFS; NOSPC, DQUOT, FBIG -> ENOSPC;
NAMETOOLONG -> ENAMETOOLONG; STALE, BADHANDLE -> ESTALE (after one retry by
path); NOTSUPP, BADTYPE -> ENOTSUP; JUKEBOX -> EINUSE (after retries);
others -> EIO. RPC rejections: AUTH_ERROR -> EAUTH (logged, e.g. "too weak"
when the server wants a reserved port), PROG_UNAVAIL/MISMATCH -> ENOTSUP.
MNT on a path the server does not export -> ENOSHARE (checked against the
EXPORT list, as servers answer "access denied" for unknown paths too).

## Limits

- NFSv3 over TCP only; no NFSv2, no NFSv4, no UDP.
- AUTH_SYS only (no Kerberos), so security is the server's export rules.
- No locking (NLM): two clients writing the same file are not coordinated.
- Names longer than the Amiga's 107-byte limit are handled by the handler's
  name mapping; NFS names over 255 bytes are skipped.
- No SYMLINK/LINK/MKNOD; device files, FIFOs and sockets appear as files.
- I/O requests are at most 32 KB by default (good for the 68k's memory and
  latency; raise with `maxio=` on fast machines).

## Tests

- `tests/t_nfs_unit.c`: XDR encoding/decoding, AUTH_SYS, call framing,
  record marking (fragments, oversize, truncation), reply parsing (accepted,
  XID mismatch, PROG_UNAVAIL/MISMATCH, GARBAGE_ARGS, SYSTEM_ERR, AUTH_ERROR,
  RPC_MISMATCH), fattr3/wcc decoding, permission and status mapping.
- `tests/t_nfs_server.c`: starts **nfs-ganesha** 4.3 (FSAL VFS, NFSv3/TCP
  only, NFS port 20490, MOUNT port 20491, an RW export without root squash
  and an RO export with it) via `tests/servers/nfs/ganesha.sh`, which also
  starts `rpcbind` when nothing listens on port 111 (ganesha refuses to run
  without a portmapper) and stops it again. Needs root (exit 77 otherwise).
  It exercises every LnOps call: mounts via the portmapper and with explicit
  ports (no portmapper), 1.5 MB transfers byte-compared through the backend
  and on the server's disk, odd-sized writes, EXCL/TRUNC/CREATE opens,
  truncate, 300-entry directories (several READDIRPLUS batches), UTF-8 names,
  symlinks (relative, absolute, in the middle of a path, pointing outside),
  rename rules, setattr (mtime/mode/protection/size), remove rules, errors
  (ENOENT, EEXIST, ENOTDIR, EISDIR, ENOTEMPTY, EACCES as nobody, EROFS),
  sub-directory URLs, statfs, list_shares, reconnect with open files, and a
  server restart with uncommitted writes (verifier change -> resend) and a
  replaced directory (stale handle -> lookup by path).
- Amiga: `build/amiga/lncli` on the emulated A1200 (Riptide) against the same
  ganesha on 192.168.78.1 (see the results in the commit log / report).
