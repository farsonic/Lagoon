/*
 * Lagoon - error codes returned by the core and the backends (negative ints;
 * 0 = success). The Amiga handler maps them to DOS ERROR_* codes
 * (src/amiga/handler), ln_strerror() gives English text for the CLI/prefs.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef LN_ERR_H
#define LN_ERR_H

enum {
	LN_OK = 0,
	LN_ENOENT = -1,      /* object not found */
	LN_EEXIST = -2,      /* object exists */
	LN_ENOTDIR = -3,     /* not a directory */
	LN_EISDIR = -4,      /* is a directory */
	LN_ENOTEMPTY = -5,   /* directory not empty */
	LN_EACCES = -6,      /* permission denied / write or delete protected */
	LN_EROFS = -7,       /* read-only share or mount */
	LN_ENOSPC = -8,      /* disk full / quota */
	LN_EINUSE = -9,      /* object in use / sharing violation / locked */
	LN_EINVAL = -10,     /* bad argument / bad name */
	LN_ENAMETOOLONG = -11,
	LN_ENOMEM = -12,
	LN_EIO = -13,        /* generic I/O or protocol error */
	LN_EPROTO = -14,     /* malformed reply / unexpected protocol state */
	LN_ENOTSUP = -15,    /* not supported by server or backend */
	LN_EAUTH = -16,      /* logon failure (bad user/password) */
	LN_ETIMEDOUT = -17,
	LN_ECONNREFUSED = -18,
	LN_ECONNRESET = -19, /* connection dropped: the caller may reconnect */
	LN_EHOSTUNREACH = -20,
	LN_ENOHOST = -21,    /* name did not resolve */
	LN_EBREAK = -22,     /* interrupted by the user (Ctrl-C) */
	LN_ENOSHARE = -23,   /* share / volume / export not found */
	LN_ESTALE = -24,     /* handle no longer valid (NFS stale, SMB file closed) */
	LN_ECRYPTO = -25,    /* signature/decryption check failed */
	LN_ENONET = -26      /* no TCP/IP stack (bsdsocket.library) */
};

const char *ln_strerror(int err);

#endif
