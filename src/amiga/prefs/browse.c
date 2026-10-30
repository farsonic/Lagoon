/*
 * Lagoon - LagoonPrefs network browser (mDNS/DNS-SD and NetBIOS discovery,
 * src/core/ln_mdns.c and ln_netbios.c) and the share pick list (the
 * backends' list_shares).
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "prefs.h"
#include "ln_net.h"
#include "ln_mdns.h"
#include "ln_netbios.h"

#define MAXFOUND 40
#define MAXSHARES 64
#define LIST_ROWS 8

enum { B_LIST = 1, B_STATUS, B_AGAIN, B_USE, B_CANCEL, B_HDR = LP_ID_FIXED };

/* a modal list window: browse (with Search again) or pick */
typedef struct LWin {
	struct Window *win;
	struct Gadget *glist, *g_list, *g_status;
	LpList *list;
	const char *status;
	int with_again, sel, stale;
	int iw, ih, lx, ly, lw, lh, by;
	char keys[3];
	int ids[3];
	ULONG secs, micros;
} LWin;

static void lw_layout(LWin *w)
{
	w->lw = 60 * lp_fcw + 24;
	w->lh = LIST_ROWS * lp_lh + 4;
	w->lx = lp_scr->WBorLeft + 8;
	w->ly = lp_scr->WBorTop + lp_scr->Font->ta_YSize + 1 + 5;
	w->by = w->ly + w->lh + 4 + lp_rowh + 5;
	w->iw = w->lw + 16;
	w->ih = w->by + lp_rowh + 5 - (lp_scr->WBorTop + lp_scr->Font->ta_YSize + 1);
}

static int lw_build(LWin *w)
{
	struct TagItem t[6];
	struct Gadget *g;
	int bw, i, n = 0;
	static const int ids3[3] = { B_USE, B_AGAIN, B_CANCEL };
	if (w->win && w->glist)
		RemoveGList(w->win, w->glist, -1);
	FreeGadgets(w->glist);
	w->glist = NULL;
	g = CreateContext(&w->glist);
	t[0].ti_Tag = GTLV_Labels; t[0].ti_Data = (ULONG)&w->list->list;
	t[1].ti_Tag = GTLV_ShowSelected; t[1].ti_Data = 0;
	t[2].ti_Tag = GTLV_Selected; t[2].ti_Data = w->sel >= 0 ? (ULONG)w->sel : ~0UL;
	t[3].ti_Tag = GTLV_MakeVisible; t[3].ti_Data = w->sel >= 0 ? (ULONG)w->sel : 0;
	t[4].ti_Tag = TAG_DONE;
	g = w->g_list = lp_mk(LISTVIEW_KIND, g, B_LIST, NULL, 0, w->lx, w->ly, w->lw, w->lh, t);
	t[0].ti_Tag = GTTX_Text; t[0].ti_Data = (ULONG)w->status;
	t[1].ti_Tag = GTTX_Border; t[1].ti_Data = TRUE;
	t[2].ti_Tag = GTTX_Clipped; t[2].ti_Data = TRUE;
	t[3].ti_Tag = TAG_DONE;
	g = w->g_status = lp_mk(TEXT_KIND, g, B_STATUS, NULL, 0, w->lx, w->ly + w->lh + 4, w->lw, lp_rowh, t);
	bw = LN_MAX(lp_textw(S(w->with_again ? MSG_USE : MSG_SELECT)), lp_textw(S(MSG_CANCEL)));
	if (w->with_again)
		bw = LN_MAX(bw, lp_textw(S(MSG_AGAIN)));
	bw += 4 * lp_cw;
	t[0].ti_Tag = GT_Underscore; t[0].ti_Data = '_';
	t[1].ti_Tag = GA_Disabled;
	t[2].ti_Tag = TAG_DONE;
	for (i = 0; i < 3; i++) {
		int id = ids3[i], x, msg;
		if (id == B_AGAIN && !w->with_again)
			continue;
		msg = id == B_USE ? (w->with_again ? MSG_USE : MSG_SELECT) : id == B_AGAIN ? MSG_AGAIN : MSG_CANCEL;
		x = id == B_USE ? w->lx : id == B_AGAIN ? lp_scr->WBorLeft + (w->iw - bw) / 2 : w->lx + w->lw - bw;
		t[1].ti_Data = id == B_USE && w->sel < 0;
		g = lp_mk(BUTTON_KIND, g, id, S(msg), PLACETEXT_IN, x, w->by, bw, lp_rowh, t);
		w->keys[n] = lp_key(S(msg));
		w->ids[n++] = id;
	}
	for (; n < 3; n++)
		w->keys[n] = 0;
	if (!g)
		return -1;
	if (w->win) {
		w->stale = 1;
		SetAPen(w->win->RPort, 0);
		RectFill(w->win->RPort, w->win->BorderLeft, w->win->BorderTop, w->win->Width - w->win->BorderRight - 1,
		         w->win->Height - w->win->BorderBottom - 1);
		AddGList(w->win, w->glist, (ULONG)~0, -1, NULL);
		RefreshGList(w->glist, w->win, NULL, -1);
		GT_RefreshWindow(w->win, NULL);
	}
	return 0;
}

static int lw_open(LWin *w, struct Window *parent, const char *title)
{
	lw_layout(w);
	if (lw_build(w) < 0)
		return -1;
	w->win = lp_window(parent, title, w->iw, w->ih, w->glist,
	                   BUTTONIDCMP | LISTVIEWIDCMP | TEXTIDCMP | IDCMP_CLOSEWINDOW | IDCMP_REFRESHWINDOW |
	                   IDCMP_VANILLAKEY | IDCMP_RAWKEY);
	if (!w->win) {
		lp_message(parent, "%s", S(MSG_ERR_WINDOW));
		return -1;
	}
	GT_RefreshWindow(w->win, NULL);
	return 0;
}

static void lw_close(LWin *w)
{
	if (w->win)
		CloseWindow(w->win);
	w->win = NULL;
	FreeGadgets(w->glist);
	w->glist = NULL;
}

static void lw_status(LWin *w, const char *s)
{
	struct TagItem t[2];
	w->status = s;
	t[0].ti_Tag = GTTX_Text;
	t[0].ti_Data = (ULONG)s;
	t[1].ti_Tag = TAG_DONE;
	if (w->win && w->g_status)
		GT_SetGadgetAttrsA(w->g_status, w->win, NULL, t);
}

/* events until Use (1, w->sel), Search again (2) or Cancel (0) */
static int lw_loop(LWin *w)
{
	for (;;) {
		struct IntuiMessage *im;
		WaitPort(w->win->UserPort);
		w->stale = 0;
		while ((im = GT_GetIMsg(w->win->UserPort)) != NULL) {
			ULONG cls = im->Class, s = im->Seconds, m = im->Micros;
			UWORD code = im->Code;
			struct Gadget *g = (struct Gadget *)im->IAddress;
			int id = 0, i;
			GT_ReplyIMsg(im);
			switch (cls) {
			case IDCMP_REFRESHWINDOW:
				GT_BeginRefresh(w->win);
				GT_EndRefresh(w->win, TRUE);
				break;
			case IDCMP_CLOSEWINDOW:
				return 0;
			case IDCMP_GADGETUP:
				if (w->stale)
					break;
				if (g->GadgetID == B_LIST) {
					int dbl = (int)code == w->sel && DoubleClick(w->secs, w->micros, s, m);
					w->secs = s;
					w->micros = m;
					w->sel = code;
					if (dbl)
						return 1;
					lw_build(w);
					break;
				}
				id = g->GadgetID;
				break;
			case IDCMP_RAWKEY:
				if ((code == 0x4c || code == 0x4d) && w->list->n) {
					int n = w->sel + (code == 0x4d ? 1 : -1);
					if (n < 0) n = 0;
					if (n >= w->list->n) n = w->list->n - 1;
					w->sel = n;
					lw_build(w);
				}
				break;
			case IDCMP_VANILLAKEY: {
				char k = (char)code;
				if (k >= 'A' && k <= 'Z')
					k = (char)(k + 32);
				if (code == 27)
					return 0;
				if (code == 13) {
					id = B_USE;
					break;
				}
				for (i = 0; i < 3; i++)
					if (w->keys[i] && w->keys[i] == k)
						id = w->ids[i];
				break;
			}
			}
			if (id == B_USE && w->sel >= 0)
				return 1;
			if (id == B_AGAIN)
				return 2;
			if (id == B_CANCEL)
				return 0;
		}
	}
}

/* ---- the network browser ---- */
typedef struct Found {
	char scheme[8];
	char host[LN_MDNS_NAME];     /* what goes into the URL */
	u16  port;
	char share[128];             /* NFS: TXT path= */
	u8   a[4];
} Found;

static Found *found;
static int nfound;

static int known_addr(const u8 *a, const char *scheme)
{
	int i;
	for (i = 0; i < nfound; i++)
		if (!memcmp(found[i].a, a, 4) && !strcmp(found[i].scheme, scheme))
			return 1;
	return 0;
}

static void search(LWin *w, LpList *l)
{
	LnService *svc = AllocVec(sizeof(LnService) * MAXFOUND, MEMF_ANY | MEMF_CLEAR);
	LnNbHost *nb = AllocVec(sizeof(LnNbHost) * MAXFOUND, MEMF_ANY | MEMF_CLEAR);
	struct Requester rq;
	static char status[100];
	int i, n, m;
	nfound = 0;
	lp_list_clear(l);
	w->sel = -1;
	lw_build(w);
	lw_status(w, S(MSG_SEARCHING));
	if (!svc || !nb) {
		lw_status(w, S(MSG_ERR_NOMEM));
		goto out;
	}
	lp_block(w->win, &rq);
	n = ln_mdns_browse(NULL, 3000, svc, MAXFOUND);
	m = ln_nb_discover(2000, nb, MAXFOUND);
	lp_unblock(w->win, &rq);
	for (i = 0; i < n && nfound < MAXFOUND; i++) {
		Found *f = &found[nfound];
		char addr[20] = "";
		if (!svc[i].scheme[0] || (!svc[i].host[0] && !svc[i].addr.family))
			continue;
		memset(f, 0, sizeof(*f));
		ln_strlcpy(f->scheme, svc[i].scheme, sizeof(f->scheme));
		ln_strlcpy(f->host, svc[i].host[0] ? svc[i].host : "", sizeof(f->host));
		if (svc[i].addr.family == 4) {
			memcpy(f->a, svc[i].addr.a, 4);
			ln_addr_str(&svc[i].addr, addr, sizeof(addr));
			if (!f->host[0])
				ln_strlcpy(f->host, addr, sizeof(f->host));
		}
		{
			const LnOps *ops = ln_vfs_find(f->scheme);
			if (ops && svc[i].port && svc[i].port != ops->default_port)
				f->port = svc[i].port;
		}
		if (!strcmp(f->scheme, "nfs"))
			ln_mdns_txt(&svc[i], "path", f->share, sizeof(f->share));
		lp_list_add(l, "%-4s %-24.24s %s%s%s%s", f->scheme[0] == 's' ? "SMB" : f->scheme[0] == 'a' ? "AFP" : "NFS",
		            svc[i].instance, svc[i].host, addr[0] && svc[i].host[0] ? " (" : "", addr,
		            addr[0] && svc[i].host[0] ? ")" : "");
		nfound++;
	}
	/* NetBIOS: SMB servers that did not announce themselves by mDNS; their
	 * names may not resolve through DNS, so the address goes into the URL */
	for (i = 0; i < m && nfound < MAXFOUND; i++) {
		Found *f = &found[nfound];
		char addr[20], name[40];
		if ((nb[i].name[0] && !nb[i].server) || known_addr(nb[i].addr.a, "smb"))
			continue;
		memset(f, 0, sizeof(*f));
		ln_strlcpy(f->scheme, "smb", sizeof(f->scheme));
		ln_addr_str(&nb[i].addr, addr, sizeof(addr));
		ln_strlcpy(f->host, addr, sizeof(f->host));
		memcpy(f->a, nb[i].addr.a, 4);
		if (nb[i].group[0])
			ln_snprintf(name, sizeof(name), "%s (%s)", nb[i].name[0] ? nb[i].name : "?", nb[i].group);
		else
			ln_strlcpy(name, nb[i].name[0] ? nb[i].name : "?", sizeof(name));
		lp_list_add(l, "%-4s %-24.24s %s", "SMB", name, addr);
		nfound++;
	}
	if (n == LN_EBREAK || m == LN_EBREAK || (n < 0 && m < 0 && nfound == 0 && (n == LN_ENONET || m == LN_ENONET)))
		lw_status(w, S(MSG_NO_NETWORK));
	else if (nfound) {
		ln_snprintf(status, sizeof(status), S(MSG_FOUND), (long)nfound);
		lw_status(w, status);
	} else
		lw_status(w, S(MSG_FOUND_NONE));
	lw_build(w);
out:
	if (svc)
		FreeVec(svc);
	if (nb)
		FreeVec(nb);
}

int lp_browse(struct Window *parent, LnShare *s)
{
	LWin w;
	LpList l;
	int r = 0;
	memset(&w, 0, sizeof(w));
	if (lp_net(parent) != LN_OK)
		return 0;
	found = AllocVec(sizeof(Found) * MAXFOUND, MEMF_ANY | MEMF_CLEAR);
	if (!found || lp_list_init(&l, MAXFOUND) < 0) {
		lp_message(parent, "%s", S(MSG_ERR_NOMEM));
		goto out;
	}
	w.list = &l;
	w.with_again = 1;
	w.sel = -1;
	w.status = S(MSG_SEARCHING);
	if (lw_open(&w, parent, S(MSG_BROWSE_TITLE)) < 0)
		goto out;
	do {
		search(&w, &l);
		r = lw_loop(&w);
	} while (r == 2);
	if (r == 1 && w.sel >= 0 && w.sel < nfound) {
		const Found *f = &found[w.sel];
		LnUrl u;
		memset(&u, 0, sizeof(u));
		ln_strlcpy(u.scheme, f->scheme, sizeof(u.scheme));
		ln_strlcpy(u.host, f->host, sizeof(u.host));
		u.port = f->port;
		ln_strlcpy(u.share, f->share, sizeof(u.share));
		memset(s, 0, sizeof(*s));
		ln_url_format(&u, s->url, sizeof(s->url));
	} else
		r = 0;
out:
	lw_close(&w);
	lp_list_free(&l);
	if (found)
		FreeVec(found);
	found = NULL;
	return r == 1;
}

/* ---- share pick list ---- */
typedef struct Shares {
	LpList *l;
	char (*names)[128];
	int smb;
} Shares;

static void share_cb(void *ud, const char *name, const char *comment)
{
	Shares *sh = ud;
	size_t len = strlen(name);
	int i;
	/* hidden/administrative SMB shares (IPC$, C$, ADMIN$) are not for us */
	if (sh->smb && len && name[len - 1] == '$')
		return;
	if (sh->l->n >= MAXSHARES)
		return;
	i = sh->l->n;
	ln_strlcpy(sh->names[i], name, sizeof(sh->names[i]));
	lp_list_add(sh->l, "%-24s %s", name, comment ? comment : "");
}

int lp_pick_share(struct Window *parent, const LnUrl *url, const LnCreds *cr, char *out, size_t n, int quiet)
{
	const LnOps *ops = ln_vfs_find(url->scheme);
	LWin w;
	LpList l;
	Shares sh;
	struct Requester rq;
	char title[180], status[180];
	int r, picked = 0;
	memset(&w, 0, sizeof(w));
	memset(&l, 0, sizeof(l));
	if (!ops)
		return 0;
	if (!ops->list_shares) {
		if (!quiet)
			lp_message(parent, "%s", S(MSG_LIST_UNSUP));
		return 0;
	}
	sh.names = AllocVec(128 * MAXSHARES, MEMF_ANY | MEMF_CLEAR);
	if (!sh.names || lp_list_init(&l, MAXSHARES) < 0) {
		lp_message(parent, "%s", S(MSG_ERR_NOMEM));
		goto out;
	}
	sh.l = &l;
	sh.smb = !strcmp(url->scheme, "smb");
	lp_block(parent, &rq);
	r = ops->list_shares(url, cr, share_cb, &sh);
	lp_unblock(parent, &rq);
	if (r < 0) {
		if (!quiet)
			lp_message(parent, S(MSG_LIST_FAIL), url->host, ln_strerror(r));
		goto out;
	}
	if (!l.n) {
		if (!quiet)
			lp_message(parent, S(MSG_LIST_NONE), url->host);
		goto out;
	}
	w.list = &l;
	w.sel = 0;
	ln_snprintf(title, sizeof(title), S(MSG_PICK_TITLE), url->host);
	ln_snprintf(status, sizeof(status), S(MSG_FOUND), (long)l.n);
	w.status = status;
	{
		/* the editor stays blocked while the pick list is open */
		struct Requester rq2;
		lp_block(parent, &rq2);
		if (lw_open(&w, parent, title) == 0 && lw_loop(&w) == 1 && w.sel >= 0 && w.sel < l.n) {
			ln_strlcpy(out, sh.names[w.sel], n);
			picked = 1;
		}
		lw_close(&w);
		lp_unblock(parent, &rq2);
	}
out:
	lp_list_free(&l);
	if (sh.names)
		FreeVec(sh.names);
	return picked;
}
