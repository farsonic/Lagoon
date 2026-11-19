/*
 * Lagoon - C:Lagoon internals shared by lagoon.c (mounting) and serve.c
 * (sharing folders: SERVE, SHARE, USER).
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef LN_CMD_H
#define LN_CMD_H

#include <exec/types.h>
#include "ln_conf.h"

#define TEMPLATE "COMMAND/A,NAME,AS/K,USER/K,PASSWORD/K,DOMAIN/K,READONLY/S,VOLUME/K,WAIT/K/N," \
                 "PATH/K,GUEST/S,USERS/K,COMMENT/K,DELETE/S,LOG/K,PORT/K/N,NOGUEST/S,READWRITE/S"
enum { A_CMD, A_NAME, A_AS, A_USER, A_PASS, A_DOMAIN, A_RO, A_VOLUME, A_WAIT,
       A_PATH, A_GUEST, A_USERS, A_COMMENT, A_DELETE, A_LOG, A_PORT, A_NOGUEST, A_RW, A_COUNT };

void lagoon_out(const char *fmt, ...);

int cmd_serve(LnConf *c, LONG *args);
int cmd_share(LnConf *c, LONG *args);
int cmd_user(LnConf *c, LONG *args);

#endif
