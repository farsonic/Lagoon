# Lagoon

Network shares on your Amiga: Lagoon mounts Windows/macOS/Samba shares (SMB
2 and 3), older Macs and Netatalk servers (AFP) and Unix servers (NFS v3) as
ordinary AmigaDOS volumes. It runs on AmigaOS 3.x (68020 or better) with any
bsdsocket.library TCP/IP stack and is developed with
[Riptide](https://github.com/farsonic/riptide).

Status: under construction. See `docs/DESIGN.md`.

## Building

```
make && make test        # native core + tests (Linux, gcc)
make amiga               # vbcc + NDK 3.2: build/amiga/
```

## Licence

GPL-2.0-only.
