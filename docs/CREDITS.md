# Credits

Lagoon is GPL-2.0-only. Third-party material in the tree:

- `src/core/crypto/cast128.c`: the CAST-128 S-box tables are Appendix A of
  RFC 2144 (C. Adams, "The CAST-128 Encryption Algorithm", 1997); the code
  is written from that RFC.

Taken or adapted from Riptide (same author, GPL-2.0-only):

| File | From | Licence |
|---|---|---|
| `tools/mkicon.py` | Riptide `tools/mkicon.py` (same author); new icon images | GPL-2.0-only |
| `tools/mkpackage.sh` | adapted from Riptide `tools/mkpackage.sh` (same author) | GPL-2.0-only |
| `tests/amiga/fsuae_pointer.py` | Riptide `tests/amiga/fsuae_pointer.py` (same author) | GPL-2.0-only |
| `tests/amiga/tassign.c`, `tests/amiga/check_icons.sh` | after Riptide's test helpers (same author) | GPL-2.0-only |
| `install/Install_Lagoon` | modelled on Riptide `install/Install_Riptide` (same author) | GPL-2.0-only |
| `src/amiga/prefs/` | layout and conventions after Riptide's RiptidePrefs (same author) | GPL-2.0-only |

Discovery (`src/core/ln_mdns.c`, `src/core/ln_netbios.c`) is written from
RFC 1035, RFC 6762, RFC 6763 and RFC 1001/1002.
