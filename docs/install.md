# Installing Lagoon

## Requirements

* a 68020 or better (A1200, A3000, A4000, accelerated A500/A2000, or an
  emulator such as WinUAE / FS-UAE),
* AmigaOS 3.0 (V39) or newer (3.1, 3.1.4, 3.2, 3.9 all work),
* a TCP/IP stack with bsdsocket.library: Riptide, Roadshow, Miami,
  AmiTCP or Genesis, configured and running,
* about 400 KB of disk space; memory: some 100 KB per mounted share.

## The package

`lagoon-0.1.lha` unpacks into a drawer `Lagoon`:

| File | Installed to |
|---|---|
| `Install_Lagoon` | the Installer script (double-click it) |
| `L/lagoon-handler` | `L:` the file system handler, started by AmigaDOS for each mounted share |
| `C/Lagoon` | `C:` (or a drawer you choose) the command: `MOUNT`, `UNMOUNT`, `LIST`, `MOUNTALL` ... |
| `Prefs/LagoonPrefs` | `SYS:Prefs` the share list editor, with its icon |
| `Catalogs/` | `LOCALE:Catalogs/<language>/` German, French, Spanish, Italian |
| `Docs/` | a drawer you choose: README.md, install.md, prefs.md, LICENSE, CREDITS.md |
| `ReadMe`, `Lagoon.readme` | short instructions, the Aminet readme |

The same files are on `lagoon-0.1.adf` (an 880 KB floppy image) for
emulators.

## Running the Installer

Double-click `Install_Lagoon`. As *Novice* the Installer takes the
defaults and asks almost nothing; *Intermediate* and *Expert* users choose
the parts (documentation, translations), the drawers, and whether the
shares are mounted at boot. It

1. checks for a 68020+ and AmigaOS 3.0 (V39) or newer,
2. looks for a TCP/IP stack (Riptide, Roadshow, Miami, AmiTCP/Genesis or
   any bsdsocket.library in memory or in LIBS:) and warns if there is none
   (Lagoon is installed anyway),
3. copies lagoon-handler to `L:`, Lagoon to `C:`, LagoonPrefs (with icon) to
   `SYS:Prefs`, the catalogs to `LOCALE:Catalogs`, the documentation,
4. creates `ENVARC:Lagoon/` with an empty `lagoon.conf` (an existing one is
   **never** replaced: updating keeps your shares) and `ENV:Lagoon/`,
5. adds this block to the end of `S:User-Startup`, so it comes after your
   TCP/IP stack's own block (Riptide's `;BEGIN Riptide` block, for example):

   ```
   ;BEGIN Lagoon
   Lagoon MOUNTALL WAIT 30 >NIL:
   ;END Lagoon
   ```

   `MOUNTALL` mounts the shares marked *Mount at startup*; `WAIT 30` gives
   the stack up to 30 seconds to come up. When you install again, the
   Installer replaces the block in place.

Then open **SYS:Prefs/LagoonPrefs** and add your shares
([prefs.md](prefs.md)).

## Updating and uninstalling

Run `Install_Lagoon` again: *Install* updates the programs and keeps
your share list; *Uninstall* unmounts the shares, removes the programs,
catalogs and documentation (the Installer remembers where it put them in
`ENVARC:Lagoon/BinDir`, `DocDir` and `PrefsDir`) and empties the Lagoon
block in `S:User-Startup`. It asks before deleting your share list.

## Installing by hand

```
Copy Lagoon/L/lagoon-handler L:
Copy Lagoon/C/Lagoon C:
Copy Lagoon/Prefs/LagoonPrefs#? SYS:Prefs/
MakeDir ENVARC:Lagoon ENV:Lagoon
```

and add `Lagoon MOUNTALL WAIT 30 >NIL:` to `S:User-Startup` after the line
that starts your TCP/IP stack. For a translation copy e.g.
`Lagoon/Catalogs/deutsch/LagoonPrefs.catalog` to
`LOCALE:Catalogs/deutsch/` (`francais` goes to `français`, `espanol` to
`español`).

## Building the package

```
make && make test && make amiga && make package
```

`make package` runs `tools/mkpackage.sh`: it builds the catalogs
(`tools/mkcatalog.py`), the icons (`tools/mkicon.py`, adapted from
Riptide's), stages `build/package/Lagoon/`, archives it as
`build/lagoon-0.1.lha` (with `lha` or `jlha`; a zip otherwise) and writes
`build/lagoon-0.1.adf` when amitools' `xdftool` is installed. It refuses to
package certificates or private keys.

Checks: `tests/amiga/check_installer.py install/Install_Lagoon` (a static
check: balanced expressions, known Installer functions, variables set
before use); `tests/amiga/check_icons.sh build/package` parses every icon
back.
