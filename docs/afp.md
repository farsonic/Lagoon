# AFP backend

`src/core/afp/` implements `const LnOps ln_afp_ops` (scheme `afp`, port 548):
AFP 3.x over DSI/TCP, for the Apple file servers that do not speak SMB well
or at all:

- Mac OS X 10.x "Personal File Sharing" / Mac OS X Server (AFP 3.1-3.3),
- AFP-only Time Capsules and AirPort Disks (AirPort base station firmware),
- Netatalk 2.x and 3.x on Linux, BSD and NAS boxes (AFP 3.1-3.4).

Modern macOS (11 and later) shares over SMB: use `smb://` for those. AppleTalk
(DDP/ASP) and AFP 2.x servers (Mac OS 9, AppleShare IP before 6) are not
supported: Lagoon needs AFP 3's UTF-8 names and 64-bit sizes.

Written from Apple's *Apple Filing Protocol Programming Guide / AFP Reference*
(AFP 3.x) and its DSI description; no code from other implementations.

## URL

    afp://[user[:password]@]host[:port]/volume[/path][?option=value&...]

No user = guest login ("No User Authent"). `path` mounts a directory inside
the volume. Options:

| option | meaning |
|---|---|
| `uam=guest\|cleartext\|dhcast128\|dhx2` | force a login method (default: best offered) |
| `cleartext=yes` | allow "Cleartxt Passwrd" (password sent unencrypted, 8 characters at most) |
| `volpass=secret` | volume password (8 characters at most) |
| `showall=yes` | also list `.AppleDouble`, `.AppleDB`, `.AppleDesktop` (hidden by default) |
| `comments=no\|yes\|all` | Finder comments: off / in `stat`/`fstat` (default) / also in directory listings (one extra request per entry) |
| `timeout=seconds` | reply timeout, default 30 |
| `maxio=bytes` | largest read/write request (default 128 KB, at most the server's request quantum) |

## Files

| file | what |
|---|---|
| `afp/afp_int.h` | internal header: DSI framing, AFP command codes, bitmaps, `kFP*` errors, packing/parsing helpers, login math |
| `afp/afp_dsi.c` | DSI transport (sessions, tickles, attentions), request builder, FPGetSrvrInfo and parameter parsers, dates, error mapping |
| `afp/afp_uam.c` | DHX2 / DHCAST128 client math (keys, nonces, CAST-128 CBC) |
| `afp/afp_ops.c` | the LnOps: login, volumes, files, directories, attributes, comments, reconnect |
| `afp/afp_crypto.h` | `ln_bn_modexp`, `ln_bn_cmp`, CAST-128 API |
| `crypto/bignum.c` | Montgomery modular exponentiation (32-bit limbs, 4-bit window, 68020 `mulu.l` inner loop for vbcc) |
| `crypto/cast128.c` | CAST-128 / CAST5 (RFC 2144) with CBC |

## Protocol notes

**DSI.** 16-byte header (flags, command, request ID, error code / write
offset, length, reserved). A session starts with DSIOpenSession (we offer an
attention quantum of 1 KB; the server tells its request quantum, which caps
our writes). Before that, FPGetSrvrInfo runs as DSIGetStatus on its own short
connection (servers close it after the reply): it gives the machine type,
server name (the UTF-8 one when offered), flags, AFP versions and UAMs. We
pick AFP3.4 > 3.3 > 3.2 > 3.1 > AFPX03.

While waiting for a reply the transport handles server requests: DSITickle
(answered with our own tickle when we have been silent for 20 s),
DSIAttention (acknowledged; shutdown/message bits logged, `ping()` reports a
pending shutdown) and DSICloseSession (connection closed, `LN_ECONNRESET`).
Servers drop clients they have not heard from (Netatalk: `tickleval` x
`timeout`, 2 minutes by default): `ping()`, which the handler calls every
~60 s when idle, drains pending tickles/attentions, sends a DSITickle and
makes one cheap FPGetVolParms round trip.

**Logins.** FPLoginExt with a UTF-8 user name (FPLogin as fallback for
servers without it), then FPLoginCont as the method needs:

- *DHX2*: the server sends ID, g, the prime length and p (Netatalk: a fresh
  1024-bit prime per login), and Mb. We answer Ma = g^Ra mod p and
  CAST-128-CBC(K, clientNonce) with K = MD5(Mb^Ra mod p), IV "LWallace";
  the server returns (IV "CJalbert") clientNonce+1 and its serverNonce, which
  proves it knows K; we send serverNonce+1 and the password padded to 256
  bytes. The exponent Ra is 160 bits for primes up to 1024 bits (224 up to
  2048, else 256): twice the strength of the group, per NIST SP 800-57.
- *DHCAST128*: fixed 128-bit prime and g = 7, K is the shared secret itself,
  the first reply carries Mb and CAST(K, serverNonce || 16 zero bytes),
  the password is padded to 64 bytes. Weak (128-bit DH); used only when the
  server has no DHX2.
- *Cleartxt Passwrd*: only when offered **and** `cleartext=yes`; 8 bytes.
- *No User Authent*: guest, when no user name is given.

Preference: DHX2, DHCAST128, then clear text. Failures give `LN_EAUTH`.

**Names and paths.** Every object is addressed from the volume root
(directory ID 2) with a full pathname of type 3 (kFPUTF8Name: 4-byte text
encoding hint, 2-byte length, components separated by NUL bytes). Lagoon's
NFC paths are converted with `ln_utf8_nfd` on the way out and names in
replies with `ln_utf8_nfc`, so "Café" round-trips whether the server stores
it decomposed (HFS+) or composed (Netatalk on Linux). This avoids a
directory-ID cache and survives reconnects unchanged.

**Calls used.** FPGetSrvrParms (`list_shares`), FPOpenVol (+ volume
password) / FPGetVolParms (extended bytes free/total, block size;
`statfs`) / FPCloseVol, FPGetFileDirParms, FPEnumerateExt2 (paged by index,
256 entries or 64 KB per request; FPEnumerateExt on AFP 3.0), FPOpenFork
(data fork) / FPReadExt / FPWriteExt (DSIWrite) / FPFlushFork /
FPGetForkParms / FPSetForkParms (truncate, extended length) / FPCloseFork,
FPCreateFile (soft create, so `LN_O_EXCL` maps directly; `LN_O_CREATE`
ignores "exists"), FPCreateDir, FPDelete, FPMoveAndRename, FPSetFileDirParms,
FPOpenDT / FPGetComment / FPAddComment / FPRemoveComment / FPCloseDT,
FPLogout.

**Attributes.** `LnStat` from the parameters: dates (AFP epoch 2000-01-01,
signed), 64-bit data fork length, node ID as `fileid`, UNIX privileges when
the volume has them (`mode`, `uid`, `gid`; the "user access" byte clears
`LN_P_READ` / `LN_P_WRITE`, files without any x bit lose `LN_P_EXEC`).
Attribute mapping both ways:

| AFP attribute | Lagoon |
|---|---|
| Invisible | `LN_P_HIDDEN` |
| WriteInhibit (files) | no `LN_P_WRITE` |
| DeleteInhibit, RenameInhibit | no `LN_P_DELETE` (both are set together) |

`setattr`: `LN_SET_MTIME` (ModDate), `LN_SET_PROT` (attributes via the
SetClear bit, cleared then set), `LN_SET_MODE` (UNIX privileges, keeps uid/
gid; `LN_ENOTSUP` without them), `LN_SET_SIZE` (opens the data fork and sets
its length), `LN_SET_COMMENT` (Finder comment, 199 bytes at most; empty =
remove).

**Finder comments** hold Amiga file notes. They are sent and read as UTF-8
bytes (classic Mac clients would show non-ASCII as Mac Roman). Best effort:
if FPOpenDT or FPGetComment is not supported comments are simply empty.

**Resource forks are ignored**: only data forks are opened, created and
listed; a Mac file's resource fork and Finder info stay untouched on the
server (copying such a file with Lagoon loses its resource fork).

**Rename** never overwrites: the target is checked first (`LN_EEXIST`),
except when it is the same object (a case-only rename on a case-insensitive
volume).

**Deny modes**: none are requested. After a network loss the server may keep
the old session (and its forks) until its tickle timeout, and a deny mode
would then stop the reconnect from reopening the file.

**Errors** (`afp_err`): ObjectNotFound/DirNotFound/ItemNotFound ->
`LN_ENOENT`, AccessDenied -> `LN_EACCES`, ObjectExists -> `LN_EEXIST`,
DirNotEmpty -> `LN_ENOTEMPTY`, VolLocked -> `LN_EROFS`, DiskFull/
QuotaExceeded -> `LN_ENOSPC`, UserNotAuth/BadUAM -> `LN_EAUTH`, ParamErr ->
`LN_EINVAL`, ObjectLocked/DenyConflict/FileBusy -> `LN_EINUSE`,
ObjectTypeErr -> `LN_ENOTDIR` (`LN_EISDIR` when opening a directory),
CallNotSupported -> `LN_ENOTSUP`, SessClosed/ServerGoingDown ->
`LN_ECONNRESET`, others `LN_EIO`. Where ObjectLocked means "write/delete/
rename inhibited" (open for writing, delete, rename, set parameters) it is
`LN_EACCES`, which the handler shows as "protected". A file used as a
directory in a path gives `LN_ENOENT` (Netatalk answers ParamErr).

**Reconnect.** `reconnect()` drops the socket, runs FPGetSrvrInfo, a new DSI
session and the login again, reopens the volume and then every open fork by
its path (with the same access mode); a file that cannot be reopened returns
`LN_ESTALE` afterwards. Directory listings continue by index. Reconnect
tokens (FPGetSessionToken / FPDisconnectOldSession) are not used.

## Tests

- `tests/t_afp_unit.c`: DSI header packing, request builder (NFD paths with
  NUL separators, Pascal strings, padding, overflow), AFP dates, error
  mapping, FPGetSrvrInfo parsing of a real Netatalk 3.1.18 reply, parameter
  parsing (files, directories, UTF-8 names, UNIX privileges), CAST-128 RFC
  2144 vectors (128/80/40-bit keys; the B.2 maintenance test with 10 000
  iterations, all 1 000 000 with `T_AFP_FULL=1`), CBC, modexp (1024-bit
  Oakley group 2, 2^521-1, small and degenerate cases), and complete DHX2
  and DHCAST128 exchanges computed independently with Python
  (`tests/servers/afp/gen_vectors.py`, Python integers + the `cryptography`
  package's CAST5).
- `tests/t_afp_netatalk.c`: starts Netatalk 3's `afpd` (as root) from
  `tests/servers/afp/afp.conf.in` via `tests/servers/afp/netatalk.sh` on
  127.0.0.1:5481 with volumes in a fresh `/tmp/lagoon-afp.XXXXXX`, and runs
  every LnOps call: `list_shares` (guest and user), guest / DHX2 / clear text
  logins, wrong password, unknown volume, volume password (none, wrong,
  right), read-only volume (`LN_EROFS`), 3 MB transfers in odd-sized pieces
  byte-compared with the file on disk, reads across EOF, create/exclusive/
  truncate, holes, `truncate`/`fstat`/`LN_SET_SIZE`, error codes, Unicode
  names (NFC <-> NFD, a name created in NFD on the Linux side), rename rules,
  mtime, UNIX mode, hidden/delete/write protection, Finder comments on files
  and directories, a 700-entry directory (three pages) with `.AppleDouble`
  hidden, a kill of the server's session processes followed by
  `reconnect()` with an open file reopened, the server dropping a silent
  client while `ping()` keeps another alive (tickleval 2 s), a DSIAttention
  (SIGUSR1 = shutdown notice) acknowledged, and a mount below a
  subdirectory. The tree is moved to `$S/trash` (or `/tmp/lagoon/trash`)
  afterwards, never deleted.

  Notes on the server setup: `afpd` runs alone (no `netatalk` supervisor)
  because `cnid_metad` exits when it cannot raise `RLIMIT_NOFILE` to 65535,
  which containers forbid; the volumes use the daemon-less `tdb` CNID scheme
  (`last` would make them read-only). The volumes live in `/tmp` because
  afpd switches to the logged-in user, who cannot enter a 0700 scratch
  directory. The script creates two local users with fake passwords:
  `lagoon` / `lagoon-test-pw` (DHX2, checked with PAM against /etc/shadow)
  and `lagoon8` / `lagoon-t` (clear text carries 8 bytes at most), both
  without a home and with shell /bin/sh (afpd refuses users without a valid
  shell). Netatalk 3 does not offer DHCAST128 by default, so that method is
  covered by the unit test only.

## On the Amiga

`build/amiga/lncli` on the emulated A1200 (68020, 14 MHz, Riptide) against
Netatalk 3.1.18 on 192.168.78.1:548 (`tests/amiga/run_emu.sh`): guest and
DHX2 logins, `ls`, `df`, `shares`, `cat`, `mkdir`, `put`/`get` of 2 MB
random files (byte-identical on the host, both directions, guest and DHX2),
rename to a UTF-8 name, `touch`, `stat`, wrong password (`logon failed`),
`rm` of a non-empty directory (`directory not empty`).

Measured (emulated A1200, 68020 at 14 MHz, 8 MB fast RAM, Riptide over uaenet):

- DHX2 login: 5.2 s, of which 5.0 s are the two 1024-bit modular
  exponentiations (the first version, with 256-bit exponents and plain
  CIOS Montgomery multiplication, took 12.3 s; now 160-bit exponent,
  dedicated squaring, no memmove, `mulu.l` inner loop). Faster CPUs scale
  accordingly (a 68030/50 MHz should be near 1.5 s). Guest login: 20 ms.
- Throughput with `lncli` (128 KB requests): read 450 KB/s, write
  240 KB/s, the same for guest and DHX2 (AFP has no per-packet crypto).

## Not done / limits

- Resource forks, Finder info (type/creator), extended attributes, ACLs,
  byte-range locks, FPCatSearch, Spotlight, server messages
  (FPGetSrvrMsg), password changes, reconnect tokens, Kerberos (GSS) and
  the older "Randnum"/"2-Way Randnum" UAMs.
- AFP 2.x servers and AppleTalk transport.
- Directory listings by index can skip or repeat entries if the directory
  changes while it is being listed (as with every index-based protocol).
