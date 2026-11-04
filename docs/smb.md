# SMB 2/3 backend

`src/core/smb` implements `const LnOps ln_smb_ops` (`smb://`, also
`cifs://`): a client for Windows 10/11 and Server, macOS file sharing,
Samba and NAS boxes. It is written from the Microsoft specifications
(MS-SMB2, MS-NLMP, MS-SPNG / RFC 4178, MS-SRVS, C706 DCE/RPC) and uses
only `ln_net.h` / `ln_sys.h`, so the same code runs natively (tests) and on
the Amiga (vbcc, 68020).

| File | What |
|---|---|
| `smb_conn.c` | TCP 445 with 4-byte session framing, NEGOTIATE (3.1.1 contexts, preauth SHA-512), credits and message ids, signing, encryption, key derivation |
| `smb_auth.c` | SESSION_SETUP: SPNEGO + NTLMSSP (NTLMv2, MsvAvTimestamp, MIC, RC4 key exchange, mechListMIC), anonymous and guest logons |
| `smb_ops.c` | the LnOps calls: TREE_CONNECT, CREATE/CLOSE/READ/WRITE/FLUSH, QUERY_DIRECTORY, QUERY_INFO, SET_INFO, ECHO, reconnect |
| `smb_rpc.c` | share list: DCE/RPC over `\PIPE\srvsvc` on IPC$, NetrShareEnum level 1 |
| `smb_status.c` | NTSTATUS to `LN_E*` (and names for the log) |
| `src/core/crypto/{aes,ccm,gcm,rc4}.c`, `ln_cipher.h` | AES-128/256, AES-CMAC, AES-CCM, AES-GCM/GMAC, RC4 |
| `src/core/crypto/{aes68k,ghash68k,sha256_68k}.s` | 68020 assembly for the AES rounds, GHASH and SHA-256 (Amiga build only) |

## Features

- Dialects 2.0.2, 2.1, 3.0, 3.0.2 and 3.1.1 (the highest the server
  supports, or the `dialect=` limit). SMB1 is not supported: a server that
  only speaks SMB1 fails with `LN_ENOTSUP` and a log line saying so.
- Large MTU: multi-credit READ/WRITE up to the server's MaxRead/MaxWrite,
  capped by `io=` (default 64 KB on the Amiga, 1 MB natively). Credits are
  tracked and requested as needed; STATUS_PENDING interim replies are
  waited out; oplock/lease break notifications are ignored (we never ask for
  oplocks or leases).
- Authentication: NTLMv2 inside SPNEGO with the MIC and the SPNEGO
  mechListMIC (required by current Windows and Samba), RC4 key exchange,
  the `cifs/<host>` target name and empty channel bindings. User name forms:
  `user`, `DOMAIN;user` in the URL, `DOMAIN\user`, `user@realm`. Without a
  domain the server's own NetBIOS domain from the challenge is used. No user
  means anonymous, falling back to `guest`. Kerberos is not implemented.
- Signing: HMAC-SHA256 (2.x), AES-CMAC (3.0/3.0.2/3.1.1), AES-GMAC (3.1.1,
  offered first unless `gmac=no`). Signatures on replies are verified;
  unsigned successful replies on a signed session are rejected. Signing is
  used when the server requires it, when `sign=required`, and always on
  3.1.1 non-guest sessions (servers insist on it there). 3.0/3.0.2 sessions
  run FSCTL_VALIDATE_NEGOTIATE_INFO against downgrades.
- Keys: SP800-108 KDF (HMAC-SHA256); 3.1.1 uses the preauth integrity hash
  (SHA-512 over NEGOTIATE and SESSION_SETUP) as KDF context.
- Encryption (TRANSFORM_HEADER): AES-128-GCM, AES-128-CCM, AES-256-GCM,
  AES-256-CCM on 3.1.1 (offered in that order), AES-128-CCM on 3.0/3.0.2.
  Turned on when the server requires it for the session (Samba `server smb
  encrypt = required`) or the share (Windows "Encrypt data access",
  SHI1005_FLAGS_ENCRYPT_DATA), or with `encrypt=yes`. Unencrypted
  successful replies on an encrypted session are rejected.
- macOS: the first CREATE carries an AAPL create context
  (kAAPL_SERVER_QUERY) so macOS and Samba vfs_fruit identify us as a plain
  client and report their capabilities (logged at level 1/2). Names that come
  back decomposed (NFD, as macOS and fruit shares often store them) are
  returned NFC.
- Share list: srvsvc NetShareEnum over IPC$ (via FSCTL_PIPE_TRANSCEIVE and
  READ for long or fragmented replies). Only disk shares are listed; hidden
  `$` shares, IPC$ and printers only with `hidden=yes`.
- Reconnect: `reconnect()` opens a new connection, session and tree, then
  reopens every open file by path with the same access (never creating or
  truncating again) and every open directory (the listing continues where
  it was). NETWORK_SESSION_EXPIRED / USER_SESSION_DELETED /
  NETWORK_NAME_DELETED and lost or timed-out connections return
  `LN_ECONNRESET` so the handler calls `reconnect()` and retries.

## URL and options

```
smb://[DOMAIN;][user[:password]@]host[:port]/share[/subdir][?opt=value&...]
```

| Option | Values | Default | Meaning |
|---|---|---|---|
| `sign` | `auto`, `required` | `auto` | `required`: sign everything and refuse guest sessions |
| `encrypt` | `auto`, `yes`, `no` | `auto` | `yes`: encrypt all traffic (needs 3.x and a real account); `no`: do not offer encryption |
| `dialect` | `2.0.2`, `2.1`, `3.0`, `3.0.2`, `3.1.1` | `3.1.1` | highest dialect offered |
| `cipher` | `gcm`, `ccm`, `gcm256`, `ccm256` | all | offer only this cipher (3.1.1) |
| `gmac` | `yes`, `no` | `yes` | offer AES-GMAC signing (3.1.1) |
| `io` | bytes | 65536 (Amiga), 1048576 (host) | largest READ/WRITE |
| `timeout` | seconds | 30 | reply timeout (STATUS_PENDING waits longer) |
| `hidden` | `yes`, `no` | `no` | `list_shares`: include `$` shares, IPC$, printers |

Examples: `smb://bob:secret@nas.local/Public`,
`smb://WORK;alice@winbox/Data/Projects?encrypt=yes`,
`smb://mac.local:445/Users?dialect=3.0.2`.

A subdirectory after the share name becomes the root of the mount.

## Mapping to Lagoon

| LnOps | SMB2 |
|---|---|
| `stat` | CREATE (FILE_READ_ATTRIBUTES, QFid context) + CLOSE; attributes and times come from the CREATE reply |
| `opendir/readdir` | CREATE (directory) + QUERY_DIRECTORY FileIdBothDirectoryInformation, 64 KB per call, until STATUS_NO_MORE_FILES |
| `open` | CREATE: dispositions OPEN / CREATE (EXCL) / OPEN_IF / OVERWRITE_IF / OVERWRITE, FILE_NON_DIRECTORY_FILE, share read+write+delete |
| `read/write` | READ/WRITE split at `max_io`; STATUS_END_OF_FILE = 0 |
| `fstat` | QUERY_INFO FileNetworkOpenInformation |
| `truncate`, `LN_SET_SIZE` | SET_INFO FileEndOfFileInformation |
| `flush` | FLUSH |
| `mkdir` | CREATE FILE_CREATE + FILE_DIRECTORY_FILE |
| `remove` | CREATE (DELETE) + SET_INFO FileDispositionInformation + CLOSE (gives DIRECTORY_NOT_EMPTY and CANNOT_DELETE reliably) |
| `rename` | CREATE (DELETE) + SET_INFO FileRenameInformation, ReplaceIfExists = 0 |
| `setattr` | SET_INFO FileBasicInformation (mtime, attributes) |
| `statfs` | QUERY_INFO FileFsFullSizeInformation + FileFsVolumeInformation on the root; read-only from the tree's maximal access |
| `ping` | ECHO |

Protection bits: READONLY clears `LN_P_WRITE` and `LN_P_DELETE` (files
only; Windows uses the bit differently on directories), HIDDEN sets
`LN_P_HIDDEN`, and the Amiga archive bit is the inverse of
FILE_ATTRIBUTE_ARCHIVE (`LN_P_ARCHIVE` = archived = ATTR_ARCHIVE clear).
`setattr(LN_SET_PROT)` sets READONLY when W or D is cleared. Times are
FILETIME converted to Unix seconds. Unix modes and file comments are not
supported (`LN_SET_MODE` is ignored, comment-only setattr returns
`LN_ENOTSUP`). Paths: `/` becomes `\`, UTF-8 becomes UTF-16LE.

Errors: OBJECT_NAME/PATH_NOT_FOUND = `LN_ENOENT`, ACCESS_DENIED and
CANNOT_DELETE = `LN_EACCES`, SHARING_VIOLATION / lock conflicts / DELETE_PENDING
= `LN_EINUSE`, DIRECTORY_NOT_EMPTY = `LN_ENOTEMPTY`, OBJECT_NAME_COLLISION =
`LN_EEXIST`, DISK_FULL / QUOTA_EXCEEDED = `LN_ENOSPC`, LOGON_FAILURE and
friends = `LN_EAUTH`, BAD_NETWORK_NAME = `LN_ENOSHARE`, FILE_IS_A_DIRECTORY
= `LN_EISDIR`, NOT_A_DIRECTORY = `LN_ENOTDIR`, INVALID_SIGNATURE / bad MACs
= `LN_ECRYPTO` (see `smb_status.c` for the full table).

## Server notes

- **Windows 10/11, Server 2016+**: 3.1.1 with signing (GMAC on 24H2 and
  Server 2025, CMAC before) and GCM encryption. Guest access is disabled by
  default on current Windows: use an account. A Microsoft account works with
  its e-mail address as user name (`user@realm` form) if the PC allows
  password logons over the network; local accounts are simplest.
- **macOS** (System Settings > General > Sharing > File Sharing): 3.1.1 /
  3.0.2, needs "Windows File Sharing" enabled for the account (it stores the
  NT hash). The AAPL context is sent; names come back NFC.
- **Samba**: all dialects. `server min protocol` must allow SMB2 (the
  default). Per-share `server smb encrypt = required` and global
  `server signing = mandatory` work. vfs_fruit shares behave like macOS.
- **NAS boxes**: older firmware may stop at 2.1 or 3.0 and omit
  VALIDATE_NEGOTIATE (ignored when unsupported). SMB1-only devices are not
  supported.
- DFS referrals, Kerberos, durable/persistent handles, multichannel,
  compression, leases/oplocks and compounding are not implemented.

## Limits

- One request in flight per mount (the handler is single threaded), so
  throughput is bounded by round trips: use large `io=` on fast links.
- `max_io` is 64 KB on the Amiga by default (one credit per request, fits
  the handler's buffers); natively up to 1 MB.
- Names longer than the caller's buffer are skipped in listings (logged).
- Memory: one connection buffer per direction (about 64 KB + headers each,
  growing to the largest message), plus 4 KB of AES tables (shared) and
  per-key state (an AES-GCM key with its GHASH table is about 4.3 KB; up to
  three are live: GMAC signing and both encryption directions).

## Speed on a 68020

Measured with `build/amiga/lncli` on the emulated A1200 (68020, 14 MHz,
fs-uae, Riptide) against Samba on the host. The times cover the whole
command (connect, NEGOTIATE, NTLMv2 logon, tree connect, the transfer):

| 1 MB file | Time | Rate | Before the 68k crypto |
|---|---|---|---|
| get, 3.0.2, unsigned (`dialect=3.0.2`) | 2.9 s | ~360 KB/s | 2.9 s |
| get, 3.1.1, AES-GMAC signing (default) | 10.9 s | ~94 KB/s | 22.9 s |
| put, 3.1.1, AES-GMAC signing (default) | 12.2 s | ~84 KB/s | 24.3 s |
| get, 3.1.1, AES-CMAC signing (`gmac=no`) | 19.0 s | ~54 KB/s | 37.7 s |
| get, 2.1, HMAC-SHA256 signing (`sign=required`) | 19.8 s | ~52 KB/s | 39.4 s |
| get, 3.1.1, AES-128-GCM encryption (`encrypt=yes`) | 26.9 s | ~38 KB/s | 58.6 s |
| put, 3.1.1, GCM (share requires encryption) | 28.1 s | ~36 KB/s | 59.8 s |
| get, 3.1.1, AES-128-CCM encryption (`cipher=ccm`) | 34.8 s | ~29 KB/s | 73.3 s |

Crypto dominates. The Amiga build runs the AES rounds, GHASH and the
SHA-256 compression function in 68020 assembly (`src/core/crypto/*.s`,
see `ln_cipher.h`); on the emulated 14 MHz 68020, `tests/amiga/cryptobench.c`
measures about 61 KB/s for AES-128 (CTR/CBC-MAC), 135 KB/s for GMAC,
43 KB/s for GCM, 65 KB/s for CMAC, 32 KB/s for CCM and 60 KB/s for
SHA-256/HMAC (vbcc C: 31, 52, 18, 29, 14 and 28 KB/s). GMAC is the
cheapest signing (one GHASH pass, 8-bit table, 4 KB per key), so it is
offered first; GCM needs an AES pass plus GHASH, CCM two AES passes.
Keys are expanded once per session. 3.1.1 always signs non-guest
sessions, so on a trusted LAN where speed matters, `dialect=3.0.2` (or
`3.0`) without `sign=required` avoids per-message MACs. This only works
if the server does not require signing. Faster CPUs (68030/040/060)
scale about with the clock, the 040/060 better (data caches).

## Tests

- `tests/t_cipher.c`: FIPS-197, RFC 4493, RFC 3610, GCM spec test case 4,
  RC4 vectors, plus vectors cross-checked with Python `cryptography`.
- `tests/t_smb_unit.c`: MS-NLMP 4.2.4 NTLMv2 vectors (NTOWFv2, NTProofStr,
  session base key, encrypted session key, LMv2, NTLMSSP signing/sealing
  keys and MAC), SMB KDF and HMAC/CMAC/GMAC signatures (checked
  independently with Python), signature verification, NTSTATUS mapping,
  FILETIME, UTF-16 paths.
- `tests/t_smb_samba.c`: starts smbd (`tests/servers/smb/start.sh`) on a
  free port in 4450-4459 with shares `plain`, `readonly`, `encrypted`
  (encryption required), `fruit` (catia fruit streams_xattr), `guest`,
  `hidden$`, plus a second instance with mandatory signing, and runs every
  LnOps call over 13 dialect/signing/encryption variants (1.5 MB files with
  byte compares, also on the host), unicode and NFD names, rename/remove
  errors, attributes, statfs, 1200-entry directories, list_shares (with and
  without hidden shares, anonymous), guest/anonymous/bad password/missing
  share, and reconnect after the server kills the connection (plain, encrypted,
  2.1). Exits 77 without root or smbd.
