/*
 * Lagoon - LagoonPrefs share editor: protocol, server, share (with a List
 * button that asks the server), folder, credentials, device name, volume
 * label, startup/read-only and the protocol options, a Test button that
 * mounts the share once and shows the free space. Two columns so that it
 * fits a 640x200 screen with topaz 8.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <clib/alib_protos.h>
#include "prefs.h"
#include "ln_net.h"
#include "ln_sys.h"

enum { P_SMB, P_AFP, P_NFS, NPROTO };
static const char *const schemes[NPROTO] = { "smb", "afp", "nfs" };

enum {
	E_PROTO = 1, E_SERVER, E_SHARE, E_LIST, E_FOLDER, E_USER, E_PASS, E_DOMAIN,
	E_DEVICE, E_LABEL, E_AUTO, E_RO, E_OPT1, E_OPT2, E_URL, E_TEST, E_OK, E_CANCEL, E_MAX
};

/* the share being edited */
static struct {
	int  proto;
	char server[140];            /* host or host:port */
	char share[128];
	char folder[128];
	char user[64];
	char domain[64];
	char device[32];
	char label[64];
	int  automount, readonly, sign, encrypt, cleartext;
	char uid[12], gid[12];
	char opts[LN_URL_MAX];       /* URL options the editor does not show */
} ed;
static LnShare *cur;             /* what we edit (written on OK) */
static int cur_index;

/* password gadget: shows '*', the text is kept here */
static char pw_real[128], pw_shown[128];
static struct Hook pw_hook;

static struct Window *win;
static struct Gadget *glist, *gad[E_MAX];
static const char *cy_labels[NPROTO + 1];
static char url_text[LN_URL_MAX + 20];
static int stale;
static struct { char key; int id; } keys[E_MAX];
static int nkeys;

/* layout */
static int x0, x2, y0, lw1, fw1, lw2, fw2, lbw, inner_w, inner_h, btn_y, url_y;

/* ---- password hook (SGH_KEY runs after Intuition edited WorkBuffer) ---- */
static ULONG pw_func(struct Hook *h, struct SGWork *sg, ULONG *msg)
{
	int plen = (int)strlen(pw_real), len = sg->NumChars, pos = sg->BufferPos, i;
	LN_UNUSED(h);
	if (*msg != SGH_KEY)
		return 0;
	switch (sg->EditOp) {
	case EO_INSERTCHAR:
	case EO_REPLACECHAR:
		i = pos - 1;
		if (i < 0 || i >= (int)sizeof(pw_real) - 1)
			break;
		if (sg->EditOp == EO_INSERTCHAR && plen < (int)sizeof(pw_real) - 1) {
			memmove(pw_real + i + 1, pw_real + i, (size_t)(plen - i + 1));
		} else if (i >= plen) {
			pw_real[i + 1] = 0;
		}
		pw_real[i] = (char)sg->WorkBuffer[i];
		sg->WorkBuffer[i] = '*';
		break;
	case EO_DELBACKWARD:
	case EO_DELFORWARD:
		if (len < plen && pos <= plen)
			memmove(pw_real + pos, pw_real + pos + (plen - len), (size_t)(len - pos + 1));
		break;
	case EO_NOOP:
	case EO_MOVECURSOR:
	case EO_ENTER:
	case EO_BADFORMAT:
		break;
	default:                         /* clear, undo, big changes: start over */
		pw_real[0] = 0;
		sg->WorkBuffer[0] = 0;
		sg->NumChars = 0;
		sg->BufferPos = 0;
		break;
	}
	pw_real[LN_MIN((int)strlen(pw_real), (int)sizeof(pw_real) - 1)] = 0;
	return ~0UL;
}

/* ---- model <-> share ---- */
static int is_num(const char *s)
{
	if (!*s)
		return 1;
	for (; *s; s++)
		if (*s < '0' || *s > '9')
			return 0;
	return 1;
}

static void opt_append(char *opts, size_t n, const char *kv)
{
	if (opts[0])
		ln_strlcat(opts, "&", n);
	ln_strlcat(opts, kv, n);
}

static void from_share(const LnShare *s)
{
	LnUrl u;
	const char *p;
	memset(&ed, 0, sizeof(ed));
	ed.proto = P_SMB;
	if (ln_url_parse(s->url, &u) == LN_OK) {
		ed.proto = !strcmp(u.scheme, "afp") ? P_AFP : !strcmp(u.scheme, "nfs") ? P_NFS : P_SMB;
		if (u.port)
			ln_snprintf(ed.server, sizeof(ed.server), "%s:%u", u.host, (unsigned)u.port);
		else
			ln_strlcpy(ed.server, u.host, sizeof(ed.server));
		ln_strlcpy(ed.share, u.share, sizeof(ed.share));
		ln_strlcpy(ed.folder, u.path, sizeof(ed.folder));
		/* options: the ones we edit become fields, the rest is kept */
		for (p = u.opts; *p;) {
			char kv[LN_URL_MAX], *eq;
			const char *amp = strchr(p, '&');
			size_t l = amp ? (size_t)(amp - p) : strlen(p);
			if (l >= sizeof(kv)) l = sizeof(kv) - 1;
			memcpy(kv, p, l);
			kv[l] = 0;
			p += l;
			if (*p == '&') p++;
			eq = strchr(kv, '=');
			if (eq) *eq = 0;
			if (!ln_strcasecmp(kv, "sign") && (!eq || ln_strcasecmp(eq + 1, "no")))
				ed.sign = 1;
			else if (!ln_strcasecmp(kv, "encrypt") && (!eq || ln_strcasecmp(eq + 1, "no")))
				ed.encrypt = 1;
			else if (!ln_strcasecmp(kv, "cleartext") && (!eq || ln_strcasecmp(eq + 1, "no")))
				ed.cleartext = 1;
			else if (!ln_strcasecmp(kv, "uid") && eq)
				ln_strlcpy(ed.uid, eq + 1, sizeof(ed.uid));
			else if (!ln_strcasecmp(kv, "gid") && eq)
				ln_strlcpy(ed.gid, eq + 1, sizeof(ed.gid));
			else if (kv[0]) {
				if (eq) *eq = '=';
				opt_append(ed.opts, sizeof(ed.opts), kv);
			}
		}
	} else if (!ln_strncasecmp(s->url, "afp", 3)) {
		ed.proto = P_AFP;
	} else if (!ln_strncasecmp(s->url, "nfs", 3)) {
		ed.proto = P_NFS;
	}
	ln_strlcpy(ed.user, s->user, sizeof(ed.user));
	ln_strlcpy(ed.domain, s->domain, sizeof(ed.domain));
	ln_strlcpy(ed.device, s->name, sizeof(ed.device));
	ln_strlcpy(ed.label, s->volume, sizeof(ed.label));
	ed.automount = s->automount;
	ed.readonly = s->readonly;
	ln_strlcpy(pw_real, s->password, sizeof(pw_real));
}

static void trim(char *s)
{
	char *p = s, *e;
	while (*p == ' ')
		p++;
	if (p != s)
		memmove(s, p, strlen(p) + 1);
	e = s + strlen(s);
	while (e > s && e[-1] == ' ')
		*--e = 0;
}

/* the URL (no password) and credentials for the fields */
static void make_url(LnUrl *u, LnCreds *cr)
{
	char *c, num[24];
	memset(u, 0, sizeof(*u));
	ln_strlcpy(u->scheme, schemes[ed.proto], sizeof(u->scheme));
	ln_strlcpy(u->host, ed.server, sizeof(u->host));
	c = strrchr(u->host, ':');
	if (c && c == strchr(u->host, ':') && is_num(c + 1) && c[1]) {   /* host:port, not IPv6 */
		long v = 0;
		const char *q = c + 1;
		while (*q) v = v * 10 + (*q++ - '0');
		*c = 0;
		if (v > 0 && v < 65536) u->port = (u16)v;
	}
	if (ed.proto == P_NFS && ed.share[0] && ed.share[0] != '/')
		ln_snprintf(u->share, sizeof(u->share), "/%s", ed.share);
	else
		ln_strlcpy(u->share, ed.share, sizeof(u->share));
	if (ed.proto != P_NFS) {
		const char *f = ed.folder;
		while (*f == '/') f++;
		ln_strlcpy(u->path, f, sizeof(u->path));
		while (u->path[0] && u->path[strlen(u->path) - 1] == '/')
			u->path[strlen(u->path) - 1] = 0;
	}
	ln_strlcpy(u->opts, ed.opts, sizeof(u->opts));
	if (ed.proto == P_SMB) {
		if (ed.sign) opt_append(u->opts, sizeof(u->opts), "sign=required");
		if (ed.encrypt) opt_append(u->opts, sizeof(u->opts), "encrypt=yes");
	} else if (ed.proto == P_AFP) {
		if (ed.cleartext) opt_append(u->opts, sizeof(u->opts), "cleartext=yes");
	} else {
		if (ed.uid[0]) { ln_snprintf(num, sizeof(num), "uid=%s", ed.uid); opt_append(u->opts, sizeof(u->opts), num); }
		if (ed.gid[0]) { ln_snprintf(num, sizeof(num), "gid=%s", ed.gid); opt_append(u->opts, sizeof(u->opts), num); }
	}
	if (cr) {
		memset(cr, 0, sizeof(*cr));
		if (ed.proto != P_NFS) {
			ln_strlcpy(cr->user, ed.user, sizeof(cr->user));
			ln_strlcpy(cr->password, pw_real, sizeof(cr->password));
		}
		if (ed.proto == P_SMB)
			ln_strlcpy(cr->domain, ed.domain, sizeof(cr->domain));
	}
}

static void update_url(void)
{
	LnUrl u;
	make_url(&u, NULL);
	ln_url_format(&u, url_text, sizeof(url_text));
}

/* string gadgets -> ed */
static void get_str(int id, char *dst, size_t n)
{
	if (gad[id]) {
		ln_strlcpy(dst, lp_gstr(gad[id]), n);
		trim(dst);
	}
}

static void harvest(void)
{
	get_str(E_SERVER, ed.server, sizeof(ed.server));
	get_str(E_SHARE, ed.share, sizeof(ed.share));
	get_str(E_FOLDER, ed.folder, sizeof(ed.folder));
	get_str(E_USER, ed.user, sizeof(ed.user));
	get_str(E_DOMAIN, ed.domain, sizeof(ed.domain));
	get_str(E_DEVICE, ed.device, sizeof(ed.device));
	get_str(E_LABEL, ed.label, sizeof(ed.label));
	if (ed.proto == P_NFS) {
		get_str(E_OPT1, ed.uid, sizeof(ed.uid));
		get_str(E_OPT2, ed.gid, sizeof(ed.gid));
	}
}

/* ---- validation ---- */
static int device_ok(const char *d)
{
	size_t l = strlen(d);
	return l >= 1 && l <= 30 && !strchr(d, ':') && !strchr(d, '/') && !strchr(d, ' ');
}

static int device_used(const char *d)
{
	int i;
	for (i = 0; i < lp_conf.nshares; i++)
		if (i != cur_index && !ln_strcasecmp(lp_conf.share[i].name, d))
			return 1;
	return 0;
}

/* a device name from the share (or server) name: "Public" -> "Public",
 * "/srv/data" -> "data"; made unique with a number */
static void suggest_device(void)
{
	char base[32];
	const char *src = ed.share[0] ? ed.share : ed.server;
	const char *sl = strrchr(src, '/');
	int i, n = 0, k;
	if (sl && sl[1])
		src = sl + 1;
	for (i = 0; *src && n < 24; src++) {
		unsigned char c = (unsigned char)*src;
		if (c > ' ' && c != ':' && c != '/' && c != '.' && c < 0x7f)
			base[n++] = (char)c;
	}
	base[n] = 0;
	if (!n)
		ln_strlcpy(base, "NET", sizeof(base));
	ln_strlcpy(ed.device, base, sizeof(ed.device));
	for (k = 1; device_used(ed.device) && k < 100; k++)
		ln_snprintf(ed.device, sizeof(ed.device), "%s%d", base, k);
	LN_UNUSED(i);
}

static const char *share_label(void)
{
	return S(ed.proto == P_AFP ? MSG_SHARE_AFP : ed.proto == P_NFS ? MSG_SHARE_NFS : MSG_SHARE_SMB);
}

static int bad(int id, const char *fmt, const char *arg)
{
	char label[64];
	const char *l = share_label();
	int i = 0;
	for (; *l && i < (int)sizeof(label) - 1; l++)
		if (*l != '_')
			label[i++] = *l;
	label[i] = 0;
	lp_message(win, fmt, arg ? arg : label);
	if (gad[id])
		ActivateGadget(gad[id], win, NULL);
	return -1;
}

static int validate(void)
{
	if (!ed.server[0])
		return bad(E_SERVER, "%s", S(MSG_BAD_SERVER));
	if (ed.proto == P_NFS) {
		if (!ed.share[0])
			return bad(E_SHARE, "%s", S(MSG_BAD_EXPORT));
	} else if (!ed.share[0])
		return bad(E_SHARE, S(MSG_BAD_SHARE), NULL);
	if (!ed.device[0])
		suggest_device();
	if (!device_ok(ed.device))
		return bad(E_DEVICE, "%s", S(MSG_BAD_DEVICE));
	if (device_used(ed.device))
		return bad(E_DEVICE, S(MSG_DUP_DEVICE), ed.device);
	if (ed.proto == P_NFS && (!is_num(ed.uid) || !is_num(ed.gid)))
		return bad(E_OPT1, "%s", S(MSG_BAD_NUMBER));
	return 0;
}

static void to_share(LnShare *s)
{
	LnUrl u;
	make_url(&u, NULL);
	ln_url_format(&u, s->url, sizeof(s->url));
	ln_strlcpy(s->name, ed.device, sizeof(s->name));
	ln_strlcpy(s->volume, ed.label, sizeof(s->volume));
	ln_strlcpy(s->user, ed.proto == P_NFS ? "" : ed.user, sizeof(s->user));
	ln_strlcpy(s->domain, ed.proto == P_SMB ? ed.domain : "", sizeof(s->domain));
	ln_strlcpy(s->password, ed.proto == P_NFS ? "" : pw_real, sizeof(s->password));
	s->automount = ed.automount;
	s->readonly = ed.readonly;
}

/* ---- layout and gadgets ---- */
static int maxw(const int *ids, int n)
{
	int i, w = 0;
	for (i = 0; i < n; i++)
		w = LN_MAX(w, lp_textw(S(ids[i])));
	return w;
}

static void layout(void)
{
	static const int left[] = { MSG_PROTOCOL, MSG_SERVER, MSG_SHARE_SMB, MSG_SHARE_AFP, MSG_SHARE_NFS,
	                            MSG_FOLDER, MSG_USER, MSG_PASSWORD, MSG_DOMAIN, MSG_URL };
	static const int right[] = { MSG_DEVICE, MSG_VOLLABEL, MSG_UID, MSG_GID };
	static const int cyc[] = { MSG_PROTO_SMB, MSG_PROTO_AFP, MSG_PROTO_NFS };
	static const int cbs[] = { MSG_AUTOMOUNT, MSG_READONLY, MSG_SIGN, MSG_ENCRYPT, MSG_CLEARTEXT };
	int cbw, bw;
	lw1 = maxw(left, LN_ARRAY_SIZE(left)) + 2 * lp_cw;
	fw1 = LN_MAX(maxw(cyc, 3) + 5 * lp_cw, 26 * lp_cw);
	lbw = lp_textw(S(MSG_LIST)) + 2 * lp_cw;
	lw2 = maxw(right, LN_ARRAY_SIZE(right)) + 2 * lp_cw;
	fw2 = 12 * lp_cw;
	cbw = 26 + lp_cw + maxw(cbs, LN_ARRAY_SIZE(cbs));
	x0 = lp_scr->WBorLeft + 8;
	x2 = x0 + lw1 + fw1 + 2 * lp_cw;
	y0 = lp_scr->WBorTop + lp_scr->Font->ta_YSize + 1 + 5;
	url_y = y0 + 7 * lp_ystep + 2;
	btn_y = url_y + lp_ystep + 3;
	inner_w = x2 + LN_MAX(lw2 + fw2, cbw) + 8 - lp_scr->WBorLeft;
	bw = 0;
	inner_h = btn_y + lp_rowh + 5 - (lp_scr->WBorTop + lp_scr->Font->ta_YSize + 1);
	LN_UNUSED(bw);
}

void lp_edit_size(int *w, int *h)
{
	layout();
	*w = inner_w;
	*h = inner_h;
}

static void add_key(const char *label, int id)
{
	char k = label ? lp_key(label) : 0;
	if (k && nkeys < E_MAX) {
		keys[nkeys].key = k;
		keys[nkeys].id = id;
		nkeys++;
	}
}

static struct Gadget *str_gad(struct Gadget *g, int id, int msg, const char *text, int maxc, int x, int y, int w,
                              int disabled, struct Hook *hook)
{
	struct TagItem t[6];
	int n = 0;
	const char *label = msg >= 0 ? S(msg) : share_label();
	t[n].ti_Tag = GTST_String; t[n++].ti_Data = (ULONG)text;
	t[n].ti_Tag = GTST_MaxChars; t[n++].ti_Data = (ULONG)maxc;
	t[n].ti_Tag = GT_Underscore; t[n++].ti_Data = '_';
	t[n].ti_Tag = GA_Disabled; t[n++].ti_Data = (ULONG)disabled;
	if (hook) { t[n].ti_Tag = GTST_EditHook; t[n++].ti_Data = (ULONG)hook; }
	t[n].ti_Tag = TAG_DONE;
	g = lp_mk(STRING_KIND, g, id, label, PLACETEXT_LEFT, x, y, w, lp_rowh, t);
	gad[id] = g;
	if (!disabled)
		add_key(label, id);
	return g;
}

static struct Gadget *cb_gad(struct Gadget *g, int id, int msg, int checked, int x, int y)
{
	struct TagItem t[4];
	t[0].ti_Tag = GTCB_Checked; t[0].ti_Data = (ULONG)checked;
	t[1].ti_Tag = GT_Underscore; t[1].ti_Data = '_';
	t[2].ti_Tag = GTCB_Scaled; t[2].ti_Data = TRUE;
	t[3].ti_Tag = TAG_DONE;
	g = lp_mk(CHECKBOX_KIND, g, id, S(msg), PLACETEXT_RIGHT, x, y + (lp_rowh - LN_MAX(11, lp_fh + 3)) / 2,
	          LN_MAX(26, lp_fh * 2 + 6), LN_MAX(11, lp_fh + 3), t);
	gad[id] = g;
	add_key(S(msg), id);
	return g;
}

static struct Gadget *btn_gad(struct Gadget *g, int id, int msg, int x, int y, int w, int disabled)
{
	struct TagItem t[3];
	t[0].ti_Tag = GT_Underscore; t[0].ti_Data = '_';
	t[1].ti_Tag = GA_Disabled; t[1].ti_Data = (ULONG)disabled;
	t[2].ti_Tag = TAG_DONE;
	g = lp_mk(BUTTON_KIND, g, id, S(msg), PLACETEXT_IN, x, y, w, lp_rowh, t);
	gad[id] = g;
	if (!disabled)
		add_key(S(msg), id);
	return g;
}

static int build(void)
{
	struct TagItem t[5];
	struct Gadget *g;
	int y = y0, xf = x0 + lw1, xr = x2 + lw2, bw, i;
	int nfs = ed.proto == P_NFS;

	if (win && glist)
		RemoveGList(win, glist, -1);
	FreeGadgets(glist);
	glist = NULL;
	memset(gad, 0, sizeof(gad));
	nkeys = 0;
	update_url();
	g = CreateContext(&glist);

	/* left column */
	cy_labels[0] = S(MSG_PROTO_SMB);
	cy_labels[1] = S(MSG_PROTO_AFP);
	cy_labels[2] = S(MSG_PROTO_NFS);
	cy_labels[3] = NULL;
	t[0].ti_Tag = GTCY_Labels; t[0].ti_Data = (ULONG)cy_labels;
	t[1].ti_Tag = GTCY_Active; t[1].ti_Data = (ULONG)ed.proto;
	t[2].ti_Tag = GT_Underscore; t[2].ti_Data = '_';
	t[3].ti_Tag = TAG_DONE;
	g = gad[E_PROTO] = lp_mk(CYCLE_KIND, g, E_PROTO, S(MSG_PROTOCOL), PLACETEXT_LEFT, xf, y, fw1, lp_rowh, t);
	add_key(S(MSG_PROTOCOL), E_PROTO);
	y += lp_ystep;
	g = str_gad(g, E_SERVER, MSG_SERVER, ed.server, sizeof(ed.server) - 1, xf, y, fw1, 0, NULL);
	y += lp_ystep;
	g = str_gad(g, E_SHARE, -1, ed.share, sizeof(ed.share) - 1, xf, y, fw1 - lbw - 4, 0, NULL);
	g = btn_gad(g, E_LIST, MSG_LIST, xf + fw1 - lbw, y, lbw, 0);
	y += lp_ystep;
	g = str_gad(g, E_FOLDER, MSG_FOLDER, ed.folder, sizeof(ed.folder) - 1, xf, y, fw1, nfs, NULL);
	y += lp_ystep;
	g = str_gad(g, E_USER, MSG_USER, nfs ? "" : ed.user, sizeof(ed.user) - 1, xf, y, fw1, nfs, NULL);
	y += lp_ystep;
	for (i = 0; pw_real[i] && i < (int)sizeof(pw_shown) - 1; i++)
		pw_shown[i] = '*';
	pw_shown[i] = 0;
	pw_hook.h_Entry = (HOOKFUNC)HookEntry;
	pw_hook.h_SubEntry = (HOOKFUNC)pw_func;
	g = str_gad(g, E_PASS, MSG_PASSWORD, nfs ? "" : pw_shown, sizeof(pw_real) - 1, xf, y, fw1, nfs, &pw_hook);
	y += lp_ystep;
	g = str_gad(g, E_DOMAIN, MSG_DOMAIN, ed.proto == P_SMB ? ed.domain : "", sizeof(ed.domain) - 1, xf, y, fw1,
	            ed.proto != P_SMB, NULL);

	/* right column */
	y = y0;
	g = str_gad(g, E_DEVICE, MSG_DEVICE, ed.device, 30, xr, y, fw2, 0, NULL);
	y += lp_ystep;
	g = str_gad(g, E_LABEL, MSG_VOLLABEL, ed.label, sizeof(ed.label) - 1, xr, y, fw2, 0, NULL);
	y += lp_ystep;
	g = cb_gad(g, E_AUTO, MSG_AUTOMOUNT, ed.automount, x2, y);
	y += lp_ystep;
	g = cb_gad(g, E_RO, MSG_READONLY, ed.readonly, x2, y);
	y += lp_ystep;
	if (ed.proto == P_SMB) {
		g = cb_gad(g, E_OPT1, MSG_SIGN, ed.sign, x2, y);
		g = cb_gad(g, E_OPT2, MSG_ENCRYPT, ed.encrypt, x2, y + lp_ystep);
	} else if (ed.proto == P_AFP) {
		g = cb_gad(g, E_OPT1, MSG_CLEARTEXT, ed.cleartext, x2, y);
	} else {
		g = str_gad(g, E_OPT1, MSG_UID, ed.uid, 10, xr, y, 8 * lp_cw, 0, NULL);
		g = str_gad(g, E_OPT2, MSG_GID, ed.gid, 10, xr, y + lp_ystep, 8 * lp_cw, 0, NULL);
	}

	/* URL, then OK / Test / Cancel */
	t[0].ti_Tag = GTTX_Text; t[0].ti_Data = (ULONG)url_text;
	t[1].ti_Tag = GTTX_Border; t[1].ti_Data = TRUE;
	t[2].ti_Tag = GTTX_Clipped; t[2].ti_Data = TRUE;
	t[3].ti_Tag = TAG_DONE;
	g = gad[E_URL] = lp_mk(TEXT_KIND, g, E_URL, S(MSG_URL), PLACETEXT_LEFT, xf, url_y,
	                       inner_w - (xf - lp_scr->WBorLeft) - 8, lp_rowh, t);
	bw = LN_MAX(lp_textw(S(MSG_OK)), LN_MAX(lp_textw(S(MSG_TEST)), lp_textw(S(MSG_CANCEL)))) + 4 * lp_cw;
	g = btn_gad(g, E_OK, MSG_OK, x0, btn_y, bw, 0);
	g = btn_gad(g, E_TEST, MSG_TEST, lp_scr->WBorLeft + (inner_w - bw) / 2, btn_y, bw, 0);
	g = btn_gad(g, E_CANCEL, MSG_CANCEL, lp_scr->WBorLeft + inner_w - 8 - bw, btn_y, bw, 0);
	if (!g)
		return -1;
	if (win) {
		stale = 1;
		SetAPen(win->RPort, 0);
		RectFill(win->RPort, win->BorderLeft, win->BorderTop, win->Width - win->BorderRight - 1,
		         win->Height - win->BorderBottom - 1);
		AddGList(win, glist, (ULONG)~0, -1, NULL);
		RefreshGList(glist, win, NULL, -1);
		GT_RefreshWindow(win, NULL);
	}
	return 0;
}

static void show_url_text(const char *s)
{
	struct TagItem t[2];
	t[0].ti_Tag = GTTX_Text;
	t[0].ti_Data = (ULONG)s;
	t[1].ti_Tag = TAG_DONE;
	if (gad[E_URL])
		GT_SetGadgetAttrsA(gad[E_URL], win, NULL, t);
}

/* ---- actions ---- */
static void test(void)
{
	LnUrl u;
	LnCreds cr;
	const LnOps *ops;
	LnFs *fs = NULL;
	LnStatFs st;
	struct Requester rq;
	char msg[160], host[140], fr[24], tot[24];
	int r;
	harvest();
	if (!ed.server[0]) {
		bad(E_SERVER, "%s", S(MSG_BAD_SERVER));
		return;
	}
	if (lp_net(win) != LN_OK)
		return;
	make_url(&u, &cr);
	ops = ln_vfs_find(u.scheme);
	if (!ops)
		return;
	ln_strlcpy(host, ed.server, sizeof(host));
	ln_snprintf(msg, sizeof(msg), S(MSG_TESTING), host);
	show_url_text(msg);
	lp_block(win, &rq);
	r = ops->mount(&u, &cr, &fs);
	memset(&st, 0, sizeof(st));
	if (r == LN_OK) {
		r = ops->statfs(fs, &st);
		ops->unmount(fs);
	}
	ln_wipe(&cr, sizeof(cr));
	lp_unblock(win, &rq);
	update_url();
	show_url_text(url_text);
	if (r == LN_OK) {
		lp_size(st.free_bytes, fr, sizeof(fr));
		lp_size(st.total_bytes, tot, sizeof(tot));
		ln_snprintf(msg, sizeof(msg), S(MSG_TEST_OK), host, fr, tot);
		if (st.readonly) {
			ln_strlcat(msg, "\n", sizeof(msg));
			ln_strlcat(msg, S(MSG_TEST_RO), sizeof(msg));
		}
		lp_message(win, "%s", msg);
	} else {
		lp_message(win, S(MSG_TEST_FAIL), host, ln_strerror(r));
	}
}

static void list_shares(int quiet)
{
	LnUrl u;
	LnCreds cr;
	char pick[128];
	harvest();
	if (!ed.server[0]) {
		if (!quiet)
			bad(E_SERVER, "%s", S(MSG_FIRST_SERVER));
		return;
	}
	if (lp_net(win) != LN_OK)
		return;
	make_url(&u, &cr);
	if (lp_pick_share(win, &u, &cr, pick, sizeof(pick), quiet)) {
		ln_strlcpy(ed.share, pick, sizeof(ed.share));
		if (!ed.device[0])
			suggest_device();
		build();
	}
	ln_wipe(&cr, sizeof(cr));
}

static int do_gadget(int id, UWORD code, int shift)
{
	switch (id) {
	case E_PROTO:
		harvest();
		ed.proto = (int)code;
		build();
		break;
	case E_AUTO: ed.automount = !ed.automount; break;
	case E_RO: ed.readonly = !ed.readonly; break;
	case E_OPT1:
		if (ed.proto == P_SMB) ed.sign = !ed.sign;
		else if (ed.proto == P_AFP) ed.cleartext = !ed.cleartext;
		break;
	case E_OPT2:
		if (ed.proto == P_SMB) ed.encrypt = !ed.encrypt;
		break;
	case E_LIST: list_shares(0); break;
	case E_TEST: test(); break;
	case E_OK:
		harvest();
		if (validate() == 0)
			return 1;
		break;
	case E_CANCEL:
		return -1;
	}
	if (id != E_PROTO && id != E_LIST && id != E_TEST) {
		harvest();
		update_url();
		show_url_text(url_text);
	}
	LN_UNUSED(shift);
	return 0;
}

static int keypress(UWORD code, UWORD qual)
{
	char k = (char)code;
	int i, shift = (qual & (IEQUALIFIER_LSHIFT | IEQUALIFIER_RSHIFT)) != 0;
	if (code == 27)
		return -1;
	if ((unsigned char)k >= 'A' && (unsigned char)k <= 'Z')
		k = (char)(k + 32);
	for (i = 0; i < nkeys; i++)
		if (keys[i].key == k)
			break;
	if (i >= nkeys)
		return 0;
	switch (keys[i].id) {
	case E_PROTO:
		harvest();
		ed.proto = (ed.proto + (shift ? NPROTO - 1 : 1)) % NPROTO;
		build();
		return 0;
	case E_AUTO: case E_RO: case E_OPT1: case E_OPT2:
		if (gad[keys[i].id] && gad[keys[i].id]->GadgetType & GTYP_STRGADGET) {
			ActivateGadget(gad[keys[i].id], win, NULL);
			return 0;
		}
		harvest();
		do_gadget(keys[i].id, 0, shift);
		build();
		return 0;
	case E_LIST: case E_TEST: case E_OK: case E_CANCEL:
		return do_gadget(keys[i].id, 0, shift);
	}
	ActivateGadget(gad[keys[i].id], win, NULL);
	return 0;
}

int lp_edit_share(struct Window *parent, LnShare *s, int index, int list_now)
{
	int r = 0;
	cur = s;
	cur_index = index;
	from_share(s);
	layout();
	if (build() < 0)
		goto out;
	win = lp_window(parent, S(index < 0 ? MSG_NEW_TITLE : MSG_EDIT_TITLE), inner_w, inner_h, glist,
	                BUTTONIDCMP | STRINGIDCMP | CYCLEIDCMP | CHECKBOXIDCMP | TEXTIDCMP |
	                IDCMP_CLOSEWINDOW | IDCMP_REFRESHWINDOW | IDCMP_VANILLAKEY);
	if (!win) {
		lp_message(parent, "%s", S(MSG_ERR_WINDOW));
		goto out;
	}
	GT_RefreshWindow(win, NULL);
	if (list_now && ed.server[0] && !ed.share[0])
		list_shares(1);
	while (!r) {
		struct IntuiMessage *im;
		WaitPort(win->UserPort);
		stale = 0;
		while (!r && (im = GT_GetIMsg(win->UserPort)) != NULL) {
			ULONG cls = im->Class;
			UWORD code = im->Code, qual = im->Qualifier;
			struct Gadget *g = (struct Gadget *)im->IAddress;
			GT_ReplyIMsg(im);
			switch (cls) {
			case IDCMP_REFRESHWINDOW:
				GT_BeginRefresh(win);
				GT_EndRefresh(win, TRUE);
				break;
			case IDCMP_CLOSEWINDOW:
				r = -1;
				break;
			case IDCMP_GADGETUP:
				if (!stale)
					r = do_gadget(g->GadgetID, code, 0);
				break;
			case IDCMP_VANILLAKEY:
				r = keypress(code, qual);
				break;
			}
		}
	}
	if (r > 0)
		to_share(s);
out:
	if (win)
		CloseWindow(win);
	win = NULL;
	FreeGadgets(glist);
	glist = NULL;
	memset(gad, 0, sizeof(gad));
	ln_wipe(pw_real, sizeof(pw_real));
	ln_wipe(&ed, sizeof(ed));
	return r > 0;
}
