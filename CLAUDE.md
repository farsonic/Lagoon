# CLAUDE.md - working on Lagoon

Lagoon mounts network shares on AmigaOS 3.x (68020+, OS 3.0+, any bsdsocket.library TCP/IP stack) as
ordinary AmigaDOS volumes: SMB 2/3 (Windows, macOS, Samba, with signing and encryption), AFP (older
Macs, Netatalk) and NFS v3 (Unix). It has a file system handler (`L:lagoon-handler`), a Shell command
(`C:Lagoon`: MOUNT, UNMOUNT, MOUNTALL, LIST), a GadTools preferences editor with a network browser
(`SYS:Prefs/LagoonPrefs`: mDNS/Bonjour and NetBIOS discovery) and an Installer script. GPL-2.0-only
(see `LICENSE`; `docs/CREDITS.md` lists what it builds on). This file is for anyone, person or agent,
picking the work up. Read it first, then `README.md`, `docs/STATUS.md` (what is tested, speeds, known
limits) and `docs/DESIGN.md`.

## Layout

| Path | What |
|---|---|
| `src/core/` | Portable C99, no AmigaOS calls: the VFS layer every backend implements (`ln_vfs.c`), URLs and config (`ln_url.c`, `ln_conf.c`), character sets and Unicode normalisation (`ln_charset.c`, `ln_nfc_table.h`), mDNS and NetBIOS discovery, and the backends `smb/`, `afp/`, `nfs/` (with XDR/RPC), plus `crypto/` (AES-CCM/GCM, GMAC, CMAC, SHA-256/512, MD4/MD5, HMAC, DH for AFP; 68020 assembly for the hot loops on the Amiga) and `mem/`. |
| `src/host/` | POSIX system and socket layers, so the core runs and is tested on Linux/macOS. |
| `src/amiga/` | The Amiga side: `sys_amiga.c`, `net_amiga.c` (bsdsocket.library), `mount.c`, the handler (`handler/`), the command (`cmd/`) and LagoonPrefs (`prefs/`). |
| `tests/` | Native tests `t_*.c` (unit tests per backend, crypto vectors, core, handler core, mDNS, NetBIOS, and integration tests against real servers), `lncli.c` (a host command-line client), `servers/` (scripts that start private Samba, Netatalk, nfs-ganesha, mDNS and NetBIOS servers for the tests), `amiga/` (emulator tests and checks: handler, prefs screens, icons, Installer script, crypto benchmark). |
| `install/` | `Install_Lagoon` (Installer script), ReadMe, Aminet readme. |
| `tools/` | `mkpackage.sh` (the release `.lha` and `.adf`), `mkcatalog.py` (locale catalogs de/fr/es/it), `mkicon.py`, `gen_nfc.py` (makes the normalisation table). |
| `docs/` | `DESIGN.md`, `STATUS.md`, per-backend notes (`smb.md`, `afp.md`, `nfs.md`), `handler.md`, `prefs.md`, `lagoon-command.md`, `install.md`, `CREDITS.md`, screenshots. |

## Build and test

Native tests (need gcc; CI runs them and they must stay green):

    make test

Unit tests always run. The integration tests (`t_smb_samba`, `t_afp_netatalk`, `t_nfs_server`, and
parts of the mDNS/NetBIOS tests) start private servers from `tests/servers/` and exit 77 (skipped) when
the server software isn't installed or can't run; install Samba (smbd, run as root), Netatalk 3.1 and
nfs-ganesha to run them all. Locally they cover 13 SMB dialect/signing/encryption variants, AFP
guest/DHX2/clear text and NFSv3, about 6,900 checks in all. `build/host/lncli` lets you try a share from
the host by hand.

Amiga binaries: `make amiga` builds `lagoon-handler`, `Lagoon` and `LagoonPrefs` with vbcc. It needs
vbcc 0.9h with vasm and the m68k-amigaos target (`/opt/amiga/vbcc`, http://www.compilers.de/vbcc.html),
the NDK 3.2 headers (`/opt/amiga/ndk/Include_H`, Aminet `dev/misc/NDK3.2.lha`) and the bsdsocket
headers from the NDK's `SANA+RoadshowTCP-IP/netinclude` (set `VBCC`, `NDK`, `NETINC` otherwise).

Package: `make package` builds `build/lagoon-<version>.lha` (and an `.adf`) with icons and catalogs.
Before a package ships, search it for certificate or key material and refuse if any is found (test
servers generate their own keys under `build/`; none may be packaged).

Emulator tests (`tests/amiga/run_emu.sh`, `t_handler.sh`, `run_prefs_emu.sh`) boot an emulated A1200
(FS-UAE, AROS ROM) with Riptide (https://github.com/farsonic/riptide) networking to the host servers.

## Rules of the project

- C99 that vbcc compiles; 68020 code; the core stays free of AmigaOS calls so it can be tested natively.
- Security: SMB signing and encryption are negotiated as the server requires; never fall back to
  weaker authentication silently, and never log passwords. Test credentials live only in the test
  servers' generated configuration under `build/`.
- Speed matters on a 14 MHz 68020: measure with the emulator (see `docs/STATUS.md`) before and after
  changes to the backends or crypto.
- Interface strings go through the catalogs (`tools/mkcatalog.py`, English plus de/fr/es/it).
- Don't use `rm -rf` in scripts or by hand on shared machines; move things aside.
- Never put a personal email address in commits, code or docs.

## Where work stands

Lagoon 0.1 is released (see `docs/STATUS.md`): all three backends, the handler, the command and
LagoonPrefs work, tested natively against real servers and on an emulated A1200. All feature branches are
merged into `main`. Known limits and next steps, from `docs/STATUS.md`:

- Install_Lagoon has only been checked statically; run it on a real Amiga or InstallerLG.
- Catalogs were checked by script, not on screen. 68030/040/060 speeds not measured.
- Not yet tested on real hardware or with other stacks (Roadshow, Miami, AmiTCP).
- SMB: no SMB1, Kerberos, DFS, compounding, durable handles or file notes. AFP: data fork only.
  NFS: v3 over TCP, AUTH_SYS, no locking. Handler: no notifications, links or record locks.
- Each program links all three backends (about 170 KB of code each); sharing them would save memory.

## Issues

Bugs and requests come in as GitHub issues (templates in `.github/ISSUE_TEMPLATE/`). To work on them:

1. `gh issue list --repo farsonic/Lagoon` and `gh issue view N --repo farsonic/Lagoon --comments`.
2. Reproduce first. Most protocol bugs can be reproduced on the host: configure the matching test server
   in `tests/servers/` like the reporter's (dialect, signing, encryption, AFP version, NFS export), try it
   with `build/host/lncli`, then write a failing test in `tests/` and fix it in `src/core/`. Handler and
   Prefs bugs need the Amiga build; say what you could and couldn't verify.
3. Fix on a branch named `issue-N-short-name`, keep `make test` green, and open a pull request whose
   description says `Fixes #N`, what changed and how it was tested. Ask on the issue for the server type
   and version and the share's settings when they are missing. Don't close issues by hand unless asked;
   merging the PR closes them.
4. Never ask for or commit passwords, server addresses or captured traffic from a reporter's network;
   ask for redacted logs instead.

`.github/workflows/claude.yml` lets people mention `@claude` in an issue or pull request to have Claude
Code look at it (it needs the `ANTHROPIC_API_KEY` repository secret or the Claude GitHub App).
