/*
 * Lagoon - LagoonPrefs internals shared by the main window
 * (lagoonprefs.c), the share editor (editor.c), the network browser and the
 * share pick list (browse.c), and the helpers (gui.c).
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef LP_PREFS_H
#define LP_PREFS_H

#include <exec/types.h>
#include <exec/memory.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <intuition/intuition.h>
#include <intuition/screens.h>
#include <intuition/sghooks.h>
#include <libraries/gadtools.h>
#include <graphics/text.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/intuition.h>
#include <proto/gadtools.h>
#include <proto/graphics.h>

#include "ln_types.h"
#include "ln_conf.h"
#include "ln_url.h"
#include "ln_vfs.h"
#include "strings.h"

#define LP_ENV_CONF    "ENV:Lagoon/lagoon.conf"
#define LP_ENVARC_CONF "ENVARC:Lagoon/lagoon.conf"
#define LP_VERSION     "0.1"

/* ---- gui.c ---- */
extern struct Screen *lp_scr;
extern APTR lp_vi;
extern struct TextAttr *lp_ta;       /* gadget font: screen font, or topaz 8 if it does not fit */
extern struct TextAttr lp_fixta;     /* fixed-width font for list columns (system default) */
extern int lp_fh, lp_cw, lp_rowh, lp_ystep;   /* gadget font height, char width, row, row step */
extern int lp_lh, lp_fcw;                    /* fixed font: list line height, char width */

const char *S(int id);               /* localized string (built-in English fallback) */
void lp_locale_open(const char *language);   /* NULL = the user's languages */
void lp_locale_close(void);

int  lp_gui_open(const char *pubscreen);   /* libraries, screen, fonts; 0 = ok */
void lp_gui_close(void);
void lp_use_font(struct TextAttr *ta);     /* measure with this font */
void lp_use_topaz(void);
int  lp_textw(const char *label);          /* pixel width of a label without '_' */
char lp_key(const char *label);            /* shortcut key of a label (lower case), 0 = none */
/* GadTools gadget; tags may be NULL. Listviews and gadget id LP_ID_FIXED use
 * the fixed-width font */
#define LP_ID_FIXED 999
struct Gadget *lp_mk(ULONG kind, struct Gadget *prev, int id, const char *label, ULONG flags,
                     int x, int y, int w, int h, struct TagItem *tags);
const char *lp_gstr(struct Gadget *g);     /* text of a string gadget */
long lp_request(struct Window *w, const char *buttons, const char *fmt, ...);
void lp_message(struct Window *w, const char *fmt, ...);
extern int lp_debug;                       /* DEBUG argument: trace events to the CLI */
void lp_trace(const char *fmt, ...);
/* block input to w with a busy pointer (nesting is not supported) */
void lp_block(struct Window *w, struct Requester *rq);
void lp_unblock(struct Window *w, struct Requester *rq);
/* a window on lp_scr centred over parent (or the screen); NULL on failure */
struct Window *lp_window(struct Window *parent, const char *title, int iw, int ih, struct Gadget *gl, ULONG idcmp);
void lp_close_window(struct Window *w);
/* text in a rectangle (clears it first) with the gadget font */
void lp_text(struct Window *w, int x, int y, int wd, const char *s, int pen);
/* format a byte count as "12.3 GB" */
void lp_size(u64 bytes, char *buf, size_t n);
/* simple string list for GadTools listviews */
typedef struct LpList {
	struct List list;
	struct Node *nodes;
	char *text;                      /* nodes' strings, LP_LINE bytes each */
	int n, max;
} LpList;
#define LP_LINE 96
int  lp_list_init(LpList *l, int max);
void lp_list_clear(LpList *l);
int  lp_list_add(LpList *l, const char *fmt, ...);
void lp_list_free(LpList *l);
/* is a DOS device NAME: present? */
int  lp_device_mounted(const char *name);
/* open bsdsocket.library on first use; LN_OK or LN_ENONET (message shown) */
int  lp_net(struct Window *w);

/* ---- lagoonprefs.c ---- */
extern LnConf lp_conf;
extern struct Window *lp_main;
void lp_main_size(int *w, int *h);         /* inner size of the main window */

/* ---- editor.c ---- */
/* edit share s (index in lp_conf, or -1 for a new one); 1 = OK pressed */
int lp_edit_share(struct Window *parent, LnShare *s, int index, int list_now);
void lp_edit_size(int *w, int *h);         /* inner size of the editor window */

/* ---- browse.c ---- */
/* network browser: 1 and a new share in s (scheme, server, share) */
int lp_browse(struct Window *parent, LnShare *s);
/* list shares on url's server with creds; pick one into out (1 = picked) */
int lp_pick_share(struct Window *parent, const LnUrl *url, const LnCreds *cr, char *out, size_t n, int quiet);

#endif
