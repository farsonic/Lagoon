# Sharing Amiga folders (the SMB server)

Lagoon can also go the other way: it shares folders of the Amiga (`Work:`,
`DH0:Projects`, an assign) with Windows, macOS and Linux over SMB 2/3, so
Explorer (`\\AMIGA\Work`), Finder (*Go > Connect to Server*,
`smb://amiga.local/Work`), GNOME/KDE, `smbclient` and `mount.cifs` can
browse, read and write them. Shares can be open to guests (no password) or
need a user name and password.

- **LagoonPrefs > Sharing...** sets it all up: the computer name, the shared
  folders (a folder requester, *Allow guests (no password)*, *Read-only*,
  which users), the users and their passwords, *Start at boot*, and
  *Start server* / *Stop server* ([prefs.md](prefs.md#sharing)).
- **C:Lagoon** does the same from a Shell: `Lagoon SHARE`, `Lagoon USER`,
  `Lagoon SERVE` ([lagoon-command.md](lagoon-command.md#sharing-folders-share-user-serve)).
- **Install_Lagoon** adds `Run >NIL: Lagoon SERVE AUTO WAIT 30` to
  `S:User-Startup`: the server starts at boot when *Start at boot* is ticked.

## Quick start

From a Shell:

    Lagoon SHARE Public PATH Work:Public GUEST       ; anyone, no password
    Lagoon SHARE Projects PATH DH0:Projects          ; users with a password
    Lagoon USER bob PASSWORD "a long passphrase"
    Run >NIL: Lagoon SERVE                           ; Lagoon SERVE STOP stops it

`Lagoon SHARE` alone lists the shared folders, users and whether the server
runs. Changes made while the server runs take effect at once (it reloads).

Connect from:

| Client | How |
|---|---|
| Windows 10/11 | Explorer: `\\AMIGA\Public` (the computer name; or `\\192.168.1.20\Public`). A password share asks for the user name and password: enter the Amiga user (`bob`), not your Microsoft account. `net use Z: \\AMIGA\Projects /user:bob *` from a command prompt. |
| macOS | Finder: *Go > Connect to Server...* `smb://amiga.local/Public` (*Guest* for guest shares, *Registered User* otherwise). The Amiga also appears in Finder's sidebar under *Network* (mDNS). |
| Linux | `smbclient //amiga/Public -N`, `smbclient //amiga/Projects -U bob`; `sudo mount -t cifs //192.168.1.20/Projects /mnt -o user=bob,vers=3.0`; Files/Dolphin: `smb://amiga.local/`. |
| Another Amiga | Lagoon itself: `Lagoon MOUNT smb://bob@amiga.local/Projects PASSWORD ...`. |

## Guests and users

- A share with **GUEST** (*Allow guests*) can be used without a password:
  clients that log on anonymously, as "guest", or with a user name the
  Amiga does not know get a guest session (like Samba's *map to guest = bad
  user*).
- A share without it needs a user with the right password. **USERS** (*Users*
  in LagoonPrefs) limits it to some users (`USERS "bob alice"`); empty means
  every configured user.
- A known user with a wrong password is refused, never turned into a guest.
- Guests never get signed sessions; a server set to require signing (see
  below) refuses guests altogether.

Passwords are not stored: lagoon.conf keeps each user's NT hash (MD4 of the
password, what NTLM needs). The hash is as good as the password for an NTLM
client, so keep `ENVARC:Lagoon/lagoon.conf` private, and do not reuse an
important password for the Amiga.

## Security: a trusted network only

Lagoon's server signs messages (SMB 2 HMAC-SHA256, SMB 3 AES-CMAC or
AES-GMAC) for logged-on users, which stops tampering, but it **does not
encrypt**: file contents and names cross the network readable, as with any
unencrypted SMB server. Use it on your home or office LAN, never open TCP 445
or 139 to the Internet, and prefer password shares to guest shares for
anything private. NTLMv1 and LM logons are refused (only NTLMv2), and SMB1
is not served (a client's SMB1 negotiate is answered with an SMB2 upgrade).

## Being found on the network

- **NetBIOS name service** (UDP 137): answers queries for the computer name
  and node status, so `\\AMIGA` works from Windows and `nmblookup AMIGA`
  from Linux.
- **mDNS/DNS-SD** (UDP 5353): announces `_smb._tcp` and `amiga.local`, so
  Finder's sidebar, GNOME Files and KDE Dolphin list the Amiga, and
  `amiga.local` resolves.
- Not done: **WS-Discovery**, which Windows 10/11's *Network* folder uses to
  list computers. Type `\\AMIGA` (or the address) in Explorer's address bar
  instead; you can then pin the share or map it as a drive.

Both can be switched off in lagoon.conf (`server netbios=no mdns=no`) if
another program on the Amiga already answers them.

## What it supports

| Area | Supported |
|---|---|
| Dialects | SMB 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1 (preauth integrity, signing capabilities); SMB1 negotiate answered with an SMB2 upgrade; FSCTL_VALIDATE_NEGOTIATE_INFO |
| Logon | SPNEGO + NTLMSSP, NTLMv2 with MIC and key exchange, SPNEGO mechListMIC; anonymous and guest; Kerberos is declined (the client falls back to NTLM) |
| Signing | as the client asks, or always (`server signing=required`); HMAC-SHA256 (2.x), AES-CMAC (3.0), AES-GMAC or CMAC (3.1.1) |
| Encryption | no (clients that require it cannot connect) |
| Requests | NEGOTIATE, SESSION_SETUP, LOGOFF, TREE_CONNECT/DISCONNECT, CREATE (dispositions, directory/non-directory, delete on close, MxAc and QFid contexts), CLOSE (post-query attributes), READ, WRITE (append), FLUSH, QUERY_DIRECTORY (classes 1, 2, 3, 12, 37, 38; wildcards), QUERY_INFO (file basic, standard, internal, EA, access, position, mode, alignment, all, stream, compression, network open, attribute tag; file system volume, size, device, attribute, full size, object id, sector size; a simple security descriptor), SET_INFO (basic: times and read-only/archive, rename with replace, disposition (Ex), position, allocation, end of file), IOCTL (validate negotiate, pipe transceive), ECHO, CANCEL; compound (related and unrelated) requests; credits |
| Not supported | LOCK is granted but not enforced, CHANGE_NOTIFY (Explorer does not refresh by itself: press F5), oplocks and leases (never granted), durable handles, multichannel, DFS, named streams, extended attributes, quotas, ACLs (security descriptors are synthesized, changes are accepted and ignored) |
| Share lists | IPC$ with `\PIPE\srvsvc`: NetrShareEnum (levels 0, 1, 2), NetrShareGetInfo (0, 1, 2, 501, 1005), NetrServerGetInfo (100, 101) |
| Files | names in ISO-8859-1 on the Amiga, UTF-16 on the wire (a name with characters outside Latin-1 cannot be created); case-insensitive like AmigaDOS; Amiga write protection = read-only attribute, archive bit = archive attribute; dates in the Amiga's local time zone (Locale prefs); files up to 2 GB |
| Connections | up to 8 clients at once (16 at most), 64 open files each, idle connections without open files dropped after 20 minutes; 64 KB reads and writes |

## Compatibility: tested and expected

Tested natively (Linux, `make test`) and from the host against the emulated
A1200 (AROS ROM, Riptide):

- **smbclient** (Samba 4.19): share list, guest and password shares, every
  dialect from 2.0.2 to 3.1.1 with signing required, put/get/mkdir/rename/
  delete, allinfo, setmode, utimes, read-only refusals, wrong passwords.
- **impacket**: guest and user logons on 2.0.2, 2.1, 3.0 and 3.1.1, NT-hash
  logon, share list, file operations.
- **Lagoon's own SMB client** (another Amiga): every dialect and signing
  variant, the share list, all LnOps calls.
- `nmblookup -A` (NetBIOS node status) and an mDNS `_smb._tcp` query.

Not tested yet (no such machine in the test setup), expected to work because
they use the same requests as the clients above: **Windows 10/11 Explorer**
(it needs guest logons allowed for guest shares: Windows 11 24H2 and recent
Windows 10 refuse insecure guest logons and require signing by default, so
use a password share there or enable *AllowInsecureGuestAuth*), **macOS
Finder**, **mount.cifs**, GNOME/KDE. Please report what you find.

## Configuration file

`ENVARC:Lagoon/lagoon.conf` (copied to `ENV:`), next to the share list:

    server name="A1200" workgroup="WORKGROUP" comment="My Amiga" signing=auto netbios=yes mdns=yes autostart=yes
    export name="Public" path="Work:Public" comment="Amiga files" readonly=no guest=yes
    export name="Projects" path="DH0:Projects" readonly=no guest=no users="bob"
    user name="bob" nthash="8846f7eaee8fb117ad06bdd830b7586c"

| Key | Meaning |
|---|---|
| `server name` | computer name (15 characters; empty = the `HOSTNAME` variable, or "Amiga") |
| `workgroup` | the NetBIOS workgroup (default WORKGROUP) |
| `signing` | `auto` (sign when the client wants it) or `required` (unsigned clients and guests are refused) |
| `netbios`, `mdns` | answer NetBIOS name queries / mDNS (default yes) |
| `autostart` | `Lagoon SERVE AUTO` (the User-Startup line) starts the server |
| `port` | TCP port (default 445; with 445 the server also listens on 139) |
| `log`, `loglevel` | log file and detail (1 = logons and connections, 2 = every open) |
| `export` | `name`, `path`, `comment`, `readonly`, `guest`, `users` |
| `user` | `name` and `nthash` (32 hex digits) |

## Memory and speed

The server takes about 70 KB of code in `C:Lagoon`, plus per client roughly
130 KB while it reads or writes 64 KB blocks (receive and reply buffers),
and 2 KB per open file. On the emulated 14 MHz A1200 with Riptide it moved
files at 120 to 250 KB/s unsigned; signed SMB 3 sessions are slower (see
[STATUS.md](STATUS.md)).

## Source

`src/core/srv/` (portable, tested natively): `srv_conn.c` (framing,
NEGOTIATE, sessions, signing, compounds, dispatch), `srv_auth.c`
(SPNEGO/NTLMSSP, NTLMv2), `srv_file.c` (trees and file operations),
`srv_rpc.c` (srvsvc), `srv_names.c` (NetBIOS/mDNS answers), `srv_loop.c`
(the network loop), `srv_conf.c` (lagoon.conf). Every shared folder is an
`LnOps` backend: `src/amiga/fs_dos.c` (dos.library) on the Amiga,
`src/host/fs_posix.c` (a host directory) natively. `src/amiga/cmd/serve.c`
is `Lagoon SERVE/SHARE/USER`, `src/amiga/prefs/sharing.c` the Sharing
window. Tests: `tests/t_smbsrv.c`, `tests/t_smbsrv_clients.c` with
`tests/servers/lagoon/e2e.sh` (smbclient, impacket), `tests/amiga/run_share_emu.sh`
(the emulator), and `build/host/lnsrv` to run the server on the host:

    build/host/lnsrv -p 4450 -s Public=/tmp/pub,guest -s Work=/tmp/work,users=bob -u bob:secret
    smbclient -p 4450 //127.0.0.1/Public -N
