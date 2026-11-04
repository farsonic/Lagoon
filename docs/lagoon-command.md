# C:Lagoon

The command-line tool for mounting network shares. Template:

    COMMAND/A,NAME,AS/K,USER/K,PASSWORD/K,DOMAIN/K,READONLY/S,VOLUME/K,WAIT/K/N

`Lagoon HELP` (or `Lagoon ?`) prints a summary. Shares are defined in
`ENV:Lagoon/lagoon.conf` (written by LagoonPrefs, copied from `ENVARC:` at
boot; format in `src/core/ln_conf.h`). Return codes: 0 OK, 5 WARN (some
shares of MOUNTALL failed), 10 ERROR (the operation failed), 20 FAIL (bad
arguments).

## MOUNT

    Lagoon MOUNT <name|URL> [AS <device>] [USER u] [PASSWORD p] [DOMAIN d]
                 [READONLY] [VOLUME label]

Mounts a share from lagoon.conf by name, or an ad-hoc URL:

    Lagoon MOUNT NAS
    Lagoon MOUNT smb://bob@nas.local/Public PASSWORD secret AS PUB: VOLUME Public
    Lagoon MOUNT afp://imac.local/Shared READONLY
    Lagoon MOUNT "nfs://server/srv/data?uid=1000&gid=1000"

- Put a URL in double quotes when it contains `=` (options such as
  `?uid=1000`): ReadArgs would take `name=value` as a keyword otherwise.
- The device is the share's name (`NAS:`), `AS` chooses another; ad-hoc
  URLs get the first free `LGN0:`, `LGN1:` ...
- The volume label is the share's `volume=` (or `VOLUME`), else the share
  name; for URLs the share/volume part of the URL.
- `USER`, `PASSWORD`, `DOMAIN`, `READONLY`, `VOLUME` override the
  configured values for this mount only. A `user:password@` in a URL is
  moved into the credentials and not kept in the URL (so `Lagoon STATUS`
  never shows it).
- The handler is started right away, so a wrong password, an unknown host,
  a missing share or a missing TCP/IP stack are reported at once, with the
  backend's message, and the device is removed again:

      Lagoon: cannot mount NAS: logon failed (user name or password)
      Lagoon: cannot mount NAS: no TCP/IP stack running (bsdsocket.library)
      Lagoon: cannot mount NAS: NAS is already mounted as NAS:

Nothing is written to lagoon.conf.

## UNMOUNT

    Lagoon UNMOUNT <device>

Sends `ACTION_DIE` to the handler; when it has quit, removes the device.
Fails with "is in use (files or locks are open)" while anything on the
volume is open or locked (including a Shell's current directory) - close
those and try again. `UMOUNT` is accepted too.

## LIST

    Lagoon LIST

The configured shares, their flags (`auto` = automount, `ro` = read-only),
where they are mounted, and their URLs; then any other Lagoon devices (ad
hoc mounts, DOSDrivers).

## MOUNTALL

    Lagoon MOUNTALL [WAIT <seconds>]

Mounts every share with `automount=yes` that is not mounted yet. With
`WAIT`, it first waits up to that long for bsdsocket.library to appear and
retries shares that fail with a network error (host unreachable, timed
out, refused, name not found) until the time is up; errors such as a wrong
password are reported at once. Ctrl-C stops waiting. Meant for
`S:User-Startup`, after the TCP/IP stack is started:

    Run >NIL: Riptide
    Lagoon MOUNTALL WAIT 30

Returns 0 if all mounted, 5 if some failed, 10 if all failed.

## STATUS

    Lagoon STATUS [device]

For each Lagoon device (or the one given): volume, online/OFFLINE (the
server is unreachable and the handler is waiting for it), read-only, the
share and URL (without password), the backend, open locks and files,
reconnects so far and bytes read/written. A device whose handler has not
started yet (e.g. from a DOSDriver) shows "not started".

## SHARES

    Lagoon SHARES <URL> [USER u] [PASSWORD p] [DOMAIN d]

Lists the shares (SMB), volumes (AFP) or exports (NFS) a server offers,
for example `Lagoon SHARES smb://nas.local USER bob PASSWORD secret`.

## TEST

    Lagoon TEST <name|URL> [USER u] [PASSWORD p] [DOMAIN d]

Connects, logs on, reads the free space and the root directory, and
disconnects, all inside the Lagoon process, without creating a device.
Useful to check a share's settings:

    Connecting to smb://nas.local/Public ...
    Connected (SMB 2/3 (Windows, macOS, Samba, NAS))
      812.3 GB free of 1.7 TB
      14 entries in the root directory
    Test OK

## For programmers

Mounting, unmounting and the mounted-state queries are in
`src/amiga/mount.c` (API documented at the top of `src/amiga/mount.h`),
which LagoonPrefs uses as well. See docs/handler.md for how the device
node is built and how the handler reports start-up errors.
