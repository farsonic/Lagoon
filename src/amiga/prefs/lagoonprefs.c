/*
 * Lagoon - LagoonPrefs: the share list editor (GadTools, AmigaOS 3.0+,
 * started from Workbench or the CLI).
 *
 *   LagoonPrefs [FROM=file] [EDIT] [USE] [SAVE] [PUBSCREEN=name] [LANGUAGE=name]
 *
 * Edits ENV:Lagoon/lagoon.conf (or ENVARC: when ENV: has none, or FROM).
 * "Save" writes ENVARC:Lagoon/lagoon.conf (the old one becomes
 * lagoon.conf.bak) and ENV:, "Use" writes ENV: only, "Cancel" nothing.
 * USE or SAVE on the command line copies FROM (or ENV:) without opening the
 * window, like the system prefs editors. Mount/Unmount run C:Lagoon.
 * LANGUAGE picks a catalog other than the Locale prefs' (e.g. deutsch).
 * The layout follows the screen font and falls back to topaz 8 when the
 * windows would not fit the screen (640x200 is the smallest supported).
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <workbench/startup.h>
#include <libraries/asl.h>
#include <proto/asl.h>
#include <dos/dostags.h>
#include "prefs.h"
#include "ln_net.h"
#include "ln_mdns.h"

const char lagoonprefs_version[] = "$VER: LagoonPrefs " LP_VERSION " (30.10.2026)";
size_t __stack = 32768;          /* vbcc start-up: the backends' Test needs room */

/* net_amiga.c resolves *.local through this when the stack cannot */
extern int (*ln_mdns_resolve_hook)(const char *name, LnAddr *out, int max);

LnConf lp_conf;
struct Window *lp_main;
static const char *from_path;
static int dirty;                /* changed since loaded or last written to ENV: */
static int sel = -1;
static int stale;                /* gadgets rebuilt: queued gadget messages are old */
static struct Gadget *glist, *g_list, *g_info;
static struct Menu *menus;
static LpList slist;
static char info[160];
static ULONG last_secs, last_micros;

enum { G_LIST = 1, G_ADD, G_EDIT, G_REMOVE, G_MOUNT, G_BROWSE, G_SAVE, G_USE, G_CANCEL, G_INFO, G_HDR = LP_ID_FIXED };
#define NBTN 8
static const int btn_ids[NBTN] = { G_ADD, G_EDIT, G_REMOVE, G_MOUNT, G_BROWSE, G_SAVE, G_USE, G_CANCEL };
static char btn_keys[NBTN];

/* layout */
static int x0, y0, list_w, list_h, inner_w, inner_h, row1_y, row2_y, info_y;
#define LIST_ROWS 8

/* ---- files ---- */
static char *read_file(const char *path)
{
	BPTR f, lock;
	struct FileInfoBlock *fib;
	char *buf = NULL;
	LONG size = -1;
	lock = Lock((STRPTR)path, ACCESS_READ);
	if (!lock)
		return NULL;
	fib = AllocDosObject(DOS_FIB, NULL);
	if (fib && Examine(lock, fib))
		size = fib->fib_Size;
	if (fib)
		FreeDosObject(DOS_FIB, fib);
	UnLock(lock);
	if (size < 0 || size > 1000000 || !(buf = AllocVec((ULONG)size + 1, MEMF_ANY)))
		return NULL;
	f = Open((STRPTR)path, MODE_OLDFILE);
	if (!f || Read(f, buf, size) != size) {
		if (f)
			Close(f);
		FreeVec(buf);
		return NULL;
	}
	Close(f);
	buf[size] = 0;
	return buf;
}

/* path = "VOL:Dir/file": create VOL:Dir when missing */
static void make_dir(const char *path)
{
	char dir[200];
	const char *slash = strrchr(path, '/');
	BPTR l;
	if (!slash || (size_t)(slash - path) >= sizeof(dir))
		return;
	memcpy(dir, path, (size_t)(slash - path));
	dir[slash - path] = 0;
	l = Lock((STRPTR)dir, ACCESS_READ);
	if (!l)
		l = CreateDir((STRPTR)dir);
	if (l)
		UnLock(l);
}

static int write_file(const char *path, const char *text, LONG len, int backup)
{
	char bak[220];
	BPTR f;
	LONG n;
	make_dir(path);
	if (backup) {
		BPTR l = Lock((STRPTR)path, ACCESS_READ);
		if (l) {
			UnLock(l);
			ln_snprintf(bak, sizeof(bak), "%s.bak", path);
			DeleteFile((STRPTR)bak);
			Rename((STRPTR)path, (STRPTR)bak);
		}
	}
	f = Open((STRPTR)path, MODE_NEWFILE);
	if (!f)
		return -1;
	n = len ? Write(f, (APTR)text, len) : 0;
	Close(f);
	return n == len ? 0 : -1;
}

/* load path (or ENV:, then ENVARC: when path is NULL); quiet: no message
 * when the file is missing. 0 = ok (an empty list if missing) */
static int load(const char *path, int quiet)
{
	char *text;
	const char *name = path;
	int line = 0, r;
	if (path)
		text = read_file(path);
	else if ((text = read_file(LP_ENV_CONF)) != NULL)
		name = LP_ENV_CONF;
	else {
		text = read_file(LP_ENVARC_CONF);
		name = LP_ENVARC_CONF;
	}
	if (!text) {
		ln_conf_init(&lp_conf);
		if (path && !quiet) {
			lp_message(lp_main, S(MSG_ERR_READ), path);
			return -1;
		}
		return 0;
	}
	r = ln_conf_parse(&lp_conf, text, &line);
	FreeVec(text);
	if (r != LN_OK) {
		lp_message(lp_main, S(MSG_ERR_PARSE), name, (long)line);
		return -1;
	}
	return 0;
}

static int write_conf(const char *path, int backup)
{
	char *buf = AllocVec(48 * 1024, MEMF_ANY);
	int len, r = -1;
	if (!buf) {
		lp_message(lp_main, "%s", S(MSG_ERR_NOMEM));
		return -1;
	}
	len = ln_conf_format(&lp_conf, buf, 48 * 1024);
	if (len >= 0)
		r = write_file(path, buf, len, backup);
	FreeVec(buf);
	if (r < 0)
		lp_message(lp_main, S(MSG_ERR_WRITE), path);
	return r;
}

/* save = 1: ENVARC: (with backup) and ENV:, 0: ENV: only */
static int store(int save)
{
	if (save && write_conf(LP_ENVARC_CONF, 1) < 0)
		return -1;
	if (write_conf(LP_ENV_CONF, 0) < 0)
		return -1;
	dirty = 0;
	return 0;
}

/* ---- running C:Lagoon ---- */
static int run_lagoon(const char *verb, const char *name)
{
	char cmd[120], *out;
	const char *tmp = "T:LagoonPrefs.out";
	BPTR o, in;
	LONG rc;
	struct TagItem t[4];
	struct Requester rq;
	ln_snprintf(cmd, sizeof(cmd), "Lagoon %s \"%s\"", verb, name);
	o = Open((STRPTR)tmp, MODE_NEWFILE);
	in = Open((STRPTR)"NIL:", MODE_OLDFILE);
	t[0].ti_Tag = SYS_Output;
	t[0].ti_Data = (ULONG)o;
	t[1].ti_Tag = SYS_Input;
	t[1].ti_Data = (ULONG)in;
	t[2].ti_Tag = NP_StackSize;
	t[2].ti_Data = 32768;
	t[3].ti_Tag = TAG_DONE;
	lp_block(lp_main, &rq);
	rc = (o && in) ? SystemTagList((STRPTR)cmd, t) : -1;
	lp_unblock(lp_main, &rq);
	if (o)
		Close(o);
	if (in)
		Close(in);
	if (rc != 0) {
		out = read_file(tmp);
		if (out) {
			if (strlen(out) > 400)
				out[400] = 0;
			lp_message(lp_main, S(MSG_ERR_COMMAND), cmd, out[0] ? out : "?");
			FreeVec(out);
		} else {
			lp_message(lp_main, S(MSG_ERR_COMMAND), cmd, "?");
		}
	}
	DeleteFile((STRPTR)tmp);
	return rc == 0 ? 0 : -1;
}

/* ---- the share list ---- */
static const char *proto_name(const char *url)
{
	if (!ln_strncasecmp(url, "smb:", 4) || !ln_strncasecmp(url, "cifs:", 5)) return "SMB";
	if (!ln_strncasecmp(url, "afp:", 4)) return "AFP";
	if (!ln_strncasecmp(url, "nfs:", 4)) return "NFS";
	return "?";
}

/* "nas.local/Public" from the URL */
static void where(const LnShare *s, char *buf, size_t n)
{
	LnUrl u;
	if (ln_url_parse(s->url, &u) != LN_OK) {
		ln_strlcpy(buf, s->url, n);
		return;
	}
	ln_snprintf(buf, n, "%s%s%s%s%s", u.host, u.share[0] == '/' ? "" : "/", u.share, u.path[0] ? "/" : "", u.path);
}

static void fill_list(void)
{
	int i;
	char w[64], st[16];
	lp_list_clear(&slist);
	for (i = 0; i < lp_conf.nshares; i++) {
		const LnShare *s = &lp_conf.share[i];
		where(s, w, sizeof(w));
		if (lp_device_mounted(s->name))
			ln_strlcpy(st, S(MSG_STATE_MOUNTED), sizeof(st));
		else if (s->automount)
			ln_strlcpy(st, S(MSG_STATE_STARTUP), sizeof(st));
		else
			st[0] = 0;
		lp_list_add(&slist, "%-12.12s %-4s %-34.34s %.10s", s->name, proto_name(s->url), w, st);
	}
	if (sel >= lp_conf.nshares)
		sel = lp_conf.nshares - 1;
	if (sel >= 0) {
		const LnShare *s = &lp_conf.share[sel];
		if (s->user[0]) {
			char u[80];
			ln_snprintf(u, sizeof(u), S(MSG_USER_INFO), s->user);
			ln_snprintf(info, sizeof(info), "%s  (%s)", s->url, u);
		} else
			ln_strlcpy(info, s->url, sizeof(info));
	} else
		ln_strlcpy(info, lp_conf.nshares ? "" : S(MSG_EMPTY), sizeof(info));
}

static const char *btn_label(int id)
{
	switch (id) {
	case G_ADD: return S(MSG_ADD);
	case G_EDIT: return S(MSG_EDIT);
	case G_REMOVE: return S(MSG_REMOVE);
	case G_MOUNT: return sel >= 0 && lp_device_mounted(lp_conf.share[sel].name) ? S(MSG_UNMOUNT) : S(MSG_MOUNT);
	case G_BROWSE: return S(MSG_BROWSE);
	case G_SAVE: return S(MSG_SAVE);
	case G_USE: return S(MSG_USE);
	}
	return S(MSG_CANCEL);
}

/* column header in the list's font, aligned with fill_list() */
static char header[100];

static void layout(void)
{
	int i, w1, bw;
	ln_snprintf(header, sizeof(header), "%-12.12s %-4.4s %-34.34s %.10s", S(MSG_HDR_DEVICE), S(MSG_HDR_TYPE),
	            S(MSG_HDR_SERVER), S(MSG_HDR_STATE));
	x0 = lp_scr->WBorLeft + 8;
	y0 = lp_scr->WBorTop + lp_scr->Font->ta_YSize + 1 + 4;
	list_w = 64 * lp_fcw + 24;
	list_h = LIST_ROWS * lp_lh + 4;
	info_y = y0 + lp_lh + 2 + list_h + 3;
	row1_y = info_y + lp_rowh + 4;
	row2_y = row1_y + lp_ystep + 2;
	/* row 1: Add, Edit, Remove, Mount/Unmount, Browse; widths by label */
	w1 = 0;
	for (i = 0; i < 5; i++) {
		bw = lp_textw(btn_label(btn_ids[i])) + 3 * lp_cw;
		if (btn_ids[i] == G_MOUNT && lp_textw(S(MSG_UNMOUNT)) > lp_textw(S(MSG_MOUNT)))
			bw = lp_textw(S(MSG_UNMOUNT)) + 3 * lp_cw;
		w1 += bw + 6;
	}
	inner_w = LN_MAX(list_w, w1) + 16;
	inner_h = row2_y + lp_rowh + 5 - (lp_scr->WBorTop + lp_scr->Font->ta_YSize + 1);
}

void lp_main_size(int *w, int *h)
{
	layout();
	*w = inner_w;
	*h = inner_h;
}

static int build(void)
{
	struct TagItem t[8];
	struct Gadget *g;
	int i, x, bw, tw, spare, gap;
	int w[5];

	if (lp_main && glist)
		RemoveGList(lp_main, glist, -1);
	FreeGadgets(glist);
	glist = NULL;
	fill_list();
	g = CreateContext(&glist);
	/* column header */
	t[0].ti_Tag = GTTX_Text;
	t[0].ti_Data = (ULONG)header;
	t[1].ti_Tag = TAG_DONE;
	g = lp_mk(TEXT_KIND, g, G_HDR, NULL, 0, x0, y0, list_w, lp_lh + 1, t);
	t[0].ti_Tag = GTLV_Labels;
	t[0].ti_Data = (ULONG)&slist.list;
	t[1].ti_Tag = GTLV_ShowSelected;
	t[1].ti_Data = 0;
	t[2].ti_Tag = GTLV_Selected;
	t[2].ti_Data = sel >= 0 ? (ULONG)sel : ~0UL;
	t[3].ti_Tag = GTLV_MakeVisible;
	t[3].ti_Data = sel >= 0 ? (ULONG)sel : 0;
	t[4].ti_Tag = TAG_DONE;
	g = g_list = lp_mk(LISTVIEW_KIND, g, G_LIST, NULL, 0, x0, y0 + lp_lh + 2, list_w, list_h, t);
	t[0].ti_Tag = GTTX_Text;
	t[0].ti_Data = (ULONG)info;
	t[1].ti_Tag = GTTX_Border;
	t[1].ti_Data = TRUE;
	t[2].ti_Tag = TAG_DONE;
	g = g_info = lp_mk(TEXT_KIND, g, G_INFO, NULL, 0, x0, info_y, inner_w - 16, lp_rowh, t);

	/* row 1, spread over the width */
	tw = 0;
	for (i = 0; i < 5; i++) {
		w[i] = lp_textw(btn_label(btn_ids[i])) + 3 * lp_cw;
		if (btn_ids[i] == G_MOUNT && lp_textw(S(MSG_UNMOUNT)) > lp_textw(S(MSG_MOUNT)))
			w[i] = lp_textw(S(MSG_UNMOUNT)) + 3 * lp_cw;
		tw += w[i];
	}
	spare = inner_w - 16 - tw;
	gap = spare / 4;
	x = x0;
	t[0].ti_Tag = GT_Underscore;
	t[0].ti_Data = '_';
	t[1].ti_Tag = GA_Disabled;
	t[2].ti_Tag = TAG_DONE;
	for (i = 0; i < 5; i++) {
		int id = btn_ids[i];
		t[1].ti_Data = (id == G_EDIT || id == G_REMOVE || id == G_MOUNT) && sel < 0;
		if (id == G_ADD)
			t[1].ti_Data = lp_conf.nshares >= LN_CONF_MAX_SHARES;
		g = lp_mk(BUTTON_KIND, g, id, btn_label(id), PLACETEXT_IN, x, row1_y, w[i], lp_rowh, t);
		btn_keys[i] = lp_key(btn_label(id));
		x += w[i] + gap;
	}
	/* row 2: Save left, Use centre, Cancel right (prefs convention) */
	bw = 0;
	for (i = 5; i < 8; i++)
		bw = LN_MAX(bw, lp_textw(btn_label(btn_ids[i])) + 4 * lp_cw);
	t[1].ti_Data = FALSE;
	for (i = 5; i < 8; i++) {
		int bx = i == 5 ? x0 : i == 6 ? x0 + (inner_w - 16 - bw) / 2 : x0 + inner_w - 16 - bw;
		g = lp_mk(BUTTON_KIND, g, btn_ids[i], btn_label(btn_ids[i]), PLACETEXT_IN, bx, row2_y, bw, lp_rowh, t);
		btn_keys[i] = lp_key(btn_label(btn_ids[i]));
	}
	if (!g)
		return -1;
	if (lp_main) {
		stale = 1;
		SetAPen(lp_main->RPort, 0);
		RectFill(lp_main->RPort, lp_main->BorderLeft, lp_main->BorderTop,
		         lp_main->Width - lp_main->BorderRight - 1, lp_main->Height - lp_main->BorderBottom - 1);
		AddGList(lp_main, glist, (ULONG)~0, -1, NULL);
		RefreshGList(glist, lp_main, NULL, -1);
		GT_RefreshWindow(lp_main, NULL);
	}
	return 0;
}

/* ---- menus ---- */
enum { M_OPEN = 1, M_SAVEAS, M_LASTSAVED, M_RESTORE, M_QUIT, M_RESET };

static struct Menu *make_menus(void)
{
	static struct NewMenu nm[12];
	struct TagItem t[2];
	struct Menu *m;
	int n = 0;
#define NM(type, label, key, id) (nm[n].nm_Type = (type), nm[n].nm_Label = (STRPTR)(label), \
	nm[n].nm_CommKey = (STRPTR)(key), nm[n].nm_Flags = 0, nm[n].nm_MutualExclude = 0, \
	nm[n].nm_UserData = (APTR)(id), n++)
	NM(NM_TITLE, S(MSG_MENU_PROJECT), NULL, 0);
	NM(NM_ITEM, S(MSG_MENU_OPEN), "O", M_OPEN);
	NM(NM_ITEM, S(MSG_MENU_SAVEAS), "A", M_SAVEAS);
	NM(NM_ITEM, NM_BARLABEL, NULL, 0);
	NM(NM_ITEM, S(MSG_MENU_LASTSAVED), "L", M_LASTSAVED);
	NM(NM_ITEM, S(MSG_MENU_RESTORE), "R", M_RESTORE);
	NM(NM_ITEM, NM_BARLABEL, NULL, 0);
	NM(NM_ITEM, S(MSG_MENU_QUIT), "Q", M_QUIT);
	NM(NM_TITLE, S(MSG_MENU_EDIT), NULL, 0);
	NM(NM_ITEM, S(MSG_MENU_RESET), "D", M_RESET);
	NM(NM_END, NULL, NULL, 0);
#undef NM
	m = CreateMenusA(nm, NULL);
	t[0].ti_Tag = GTMN_NewLookMenus;
	t[0].ti_Data = TRUE;
	t[1].ti_Tag = TAG_DONE;
	if (m && !LayoutMenusA(m, lp_vi, t)) {
		FreeMenus(m);
		m = NULL;
	}
	return m;
}

/* ASL file requester; 1 = path chosen */
static int file_req(int save, char *path, size_t n)
{
	struct Library *AslBase = OpenLibrary((STRPTR)"asl.library", 38);
	struct FileRequester *fr;
	struct TagItem t[8];
	int ok = 0;
	char dir[200];
	if (!AslBase)
		return 0;
	ln_strlcpy(dir, from_path ? from_path : LP_ENVARC_CONF, sizeof(dir));
	*PathPart((STRPTR)dir) = 0;
	t[0].ti_Tag = ASLFR_Window;
	t[0].ti_Data = (ULONG)lp_main;
	t[1].ti_Tag = ASLFR_TitleText;
	t[1].ti_Data = (ULONG)S(save ? MSG_ASL_SAVE : MSG_ASL_OPEN);
	t[2].ti_Tag = ASLFR_InitialDrawer;
	t[2].ti_Data = (ULONG)dir;
	t[3].ti_Tag = ASLFR_InitialFile;
	t[3].ti_Data = (ULONG)"lagoon.conf";
	t[4].ti_Tag = ASLFR_DoSaveMode;
	t[4].ti_Data = save;
	t[5].ti_Tag = ASLFR_SleepWindow;
	t[5].ti_Data = TRUE;
	t[6].ti_Tag = ASLFR_RejectIcons;
	t[6].ti_Data = TRUE;
	t[7].ti_Tag = TAG_DONE;
	fr = AllocAslRequest(ASL_FileRequest, t);
	if (fr && AslRequest(fr, NULL)) {
		ln_strlcpy(path, (const char *)fr->fr_Drawer, n);
		AddPart((STRPTR)path, fr->fr_File, (ULONG)n);
		ok = fr->fr_File[0] != 0;
	}
	if (fr)
		FreeAslRequest(fr);
	CloseLibrary(AslBase);
	return ok;
}

/* ---- actions ---- */
static void select_share(int i)
{
	sel = i;
	build();
}

static void edit(int index)
{
	LnShare s;
	int list_now = 0;
	struct Requester rq;
	if (index < 0) {
		memset(&s, 0, sizeof(s));
		ln_strlcpy(s.url, "smb://", sizeof(s.url));
	} else
		s = lp_conf.share[index];
	lp_block(lp_main, &rq);
	if (lp_edit_share(lp_main, &s, index, list_now)) {
		if (index >= 0 && ln_strcasecmp(lp_conf.share[index].name, s.name)) {
			lp_conf.share[index] = s;     /* renamed: keep its place */
		} else if (ln_conf_put(&lp_conf, &s) != LN_OK) {
			lp_message(lp_main, "%s", S(MSG_ERR_FULL));
		}
		dirty = 1;
		{
			LnShare *p = ln_conf_find(&lp_conf, s.name);
			sel = p ? (int)(p - lp_conf.share) : sel;
		}
	}
	ln_wipe(&s, sizeof(s));
	lp_unblock(lp_main, &rq);
	build();
}

static void browse(void)
{
	LnShare s;
	struct Requester rq;
	int ok;
	memset(&s, 0, sizeof(s));
	lp_block(lp_main, &rq);
	ok = lp_browse(lp_main, &s);
	if (ok && lp_edit_share(lp_main, &s, -1, 1)) {
		if (ln_conf_put(&lp_conf, &s) != LN_OK)
			lp_message(lp_main, "%s", S(MSG_ERR_FULL));
		else {
			LnShare *p = ln_conf_find(&lp_conf, s.name);
			sel = p ? (int)(p - lp_conf.share) : sel;
			dirty = 1;
		}
	}
	ln_wipe(&s, sizeof(s));
	lp_unblock(lp_main, &rq);
	build();
}

static void remove_share(void)
{
	if (sel < 0)
		return;
	if (!lp_request(lp_main, S(MSG_REQ_REMOVE), S(MSG_ASK_REMOVE), lp_conf.share[sel].name))
		return;
	ln_conf_remove(&lp_conf, lp_conf.share[sel].name);
	dirty = 1;
	build();
}

static void mount_toggle(void)
{
	const char *name;
	if (sel < 0)
		return;
	name = lp_conf.share[sel].name;
	if (lp_device_mounted(name)) {
		run_lagoon("UNMOUNT", name);
	} else {
		/* C:Lagoon reads ENV:Lagoon/lagoon.conf */
		if (dirty) {
			if (!lp_request(lp_main, S(MSG_REQ_USE), "%s", S(MSG_ASK_USE)))
				return;
			if (store(0) < 0)
				return;
		}
		run_lagoon("MOUNT", name);
	}
	build();
}

/* 1 = leave */
static int finish(int id)
{
	if (id == G_CANCEL)
		return 1;
	return store(id == G_SAVE) == 0;
}

static int menu_pick(UWORD code)
{
	while (code != MENUNULL) {
		struct MenuItem *it = ItemAddress(menus, code);
		char path[256];
		if (!it)
			break;
		switch ((int)(ULONG)GTMENUITEM_USERDATA(it)) {
		case M_OPEN:
			if (file_req(0, path, sizeof(path)) && load(path, 0) == 0) {
				dirty = 1;
				sel = -1;
			}
			build();
			break;
		case M_SAVEAS:
			if (file_req(1, path, sizeof(path)))
				write_conf(path, 0);
			break;
		case M_LASTSAVED:
			load(LP_ENVARC_CONF, 1);
			dirty = 1;
			sel = -1;
			build();
			break;
		case M_RESTORE:
			load(from_path, 1);
			dirty = 1;
			sel = -1;
			build();
			break;
		case M_RESET:
			ln_conf_init(&lp_conf);
			dirty = 1;
			sel = -1;
			build();
			break;
		case M_QUIT:
			return 1;
		}
		code = it->NextSelect;
	}
	return 0;
}

static int do_button(int id)
{
	switch (id) {
	case G_ADD: if (lp_conf.nshares < LN_CONF_MAX_SHARES) edit(-1); break;
	case G_EDIT: if (sel >= 0) edit(sel); break;
	case G_REMOVE: remove_share(); break;
	case G_MOUNT: mount_toggle(); break;
	case G_BROWSE: if (lp_conf.nshares < LN_CONF_MAX_SHARES) browse(); break;
	case G_SAVE: case G_USE: case G_CANCEL: return finish(id);
	}
	return 0;
}

static void event_loop(void)
{
	for (;;) {
		struct IntuiMessage *im;
		WaitPort(lp_main->UserPort);
		stale = 0;
		while ((im = GT_GetIMsg(lp_main->UserPort)) != NULL) {
			ULONG cls = im->Class, secs = im->Seconds, mic = im->Micros;
			UWORD code = im->Code, qual = im->Qualifier;
			struct Gadget *gad = (struct Gadget *)im->IAddress;
			int i;
			GT_ReplyIMsg(im);
			switch (cls) {
			case IDCMP_REFRESHWINDOW:
				GT_BeginRefresh(lp_main);
				GT_EndRefresh(lp_main, TRUE);
				break;
			case IDCMP_CLOSEWINDOW:
				return;
			case IDCMP_ACTIVEWINDOW:
				build();                 /* mounted state may have changed */
				break;
			case IDCMP_MENUPICK:
				if (menu_pick(code))
					return;
				break;
			case IDCMP_GADGETUP:
				if (stale)
					break;
				if (gad->GadgetID == G_LIST) {
					int dbl = (int)code == sel && DoubleClick(last_secs, last_micros, secs, mic);
					last_secs = secs;
					last_micros = mic;
					if (dbl)
						edit(sel);
					else
						select_share(code);
				} else if (do_button(gad->GadgetID))
					return;
				break;
			case IDCMP_RAWKEY:
				/* cursor up/down move the selection */
				if ((code == 0x4c || code == 0x4d) && lp_conf.nshares) {
					int n = sel + (code == 0x4d ? 1 : -1);
					if (qual & (IEQUALIFIER_LSHIFT | IEQUALIFIER_RSHIFT))
						n = code == 0x4d ? lp_conf.nshares - 1 : 0;
					if (n < 0) n = 0;
					if (n >= lp_conf.nshares) n = lp_conf.nshares - 1;
					select_share(n);
				}
				break;
			case IDCMP_VANILLAKEY: {
				char k = (char)code;
				if (k >= 'A' && k <= 'Z')
					k = (char)(k + 32);
				if (code == 13) {
					if (sel >= 0)
						edit(sel);
					break;
				}
				if (code == 27) {
					if (finish(G_CANCEL))
						return;
					break;
				}
				if (code == 127) {
					remove_share();
					break;
				}
				for (i = 0; i < NBTN; i++)
					if (btn_keys[i] && btn_keys[i] == k)
						break;
				if (i < NBTN && do_button(btn_ids[i]))
					return;
				break;
			}
			}
		}
	}
}

static int run_gui(const char *pubscreen)
{
	int w, h, ew, eh, maxw, maxh;
	if (lp_gui_open(pubscreen) < 0)
		return 20;
	/* font-sensitive, but must fit: fall back to topaz 8 */
	maxw = lp_scr->Width - lp_scr->WBorLeft - lp_scr->WBorRight;
	maxh = lp_scr->Height - lp_scr->BarHeight - 1 - lp_scr->WBorTop - lp_scr->Font->ta_YSize - 1 - lp_scr->WBorBottom;
	lp_main_size(&w, &h);
	lp_edit_size(&ew, &eh);
	if (LN_MAX(w, ew) > maxw || LN_MAX(h, eh) > maxh)
		lp_use_topaz();
	if (lp_list_init(&slist, LN_CONF_MAX_SHARES) < 0) {
		lp_message(NULL, "%s", S(MSG_ERR_NOMEM));
		return 20;
	}
	layout();
	if (build() < 0 || !(menus = make_menus())) {
		lp_message(NULL, "%s", S(MSG_ERR_WINDOW));
		return 20;
	}
	lp_main = lp_window(NULL, S(MSG_TITLE), inner_w, inner_h, glist,
	                    BUTTONIDCMP | LISTVIEWIDCMP | IDCMP_CLOSEWINDOW | IDCMP_REFRESHWINDOW |
	                    IDCMP_VANILLAKEY | IDCMP_RAWKEY | IDCMP_MENUPICK | IDCMP_ACTIVEWINDOW);
	if (!lp_main) {
		lp_message(NULL, "%s", S(MSG_ERR_WINDOW));
		return 20;
	}
	SetMenuStrip(lp_main, menus);
	GT_RefreshWindow(lp_main, NULL);
	event_loop();
	return 0;
}

static void cleanup(void)
{
	if (lp_main) {
		ClearMenuStrip(lp_main);
		CloseWindow(lp_main);
	}
	lp_main = NULL;
	if (menus)
		FreeMenus(menus);
	menus = NULL;
	FreeGadgets(glist);
	glist = NULL;
	lp_list_free(&slist);
	lp_gui_close();
}

int main(int argc, char **argv)
{
	LONG args[6] = { 0, 0, 0, 0, 0, 0 };
	struct RDArgs *rda = NULL;
	int rc = 0;
	LN_UNUSED(argv);
	ln_mdns_resolve_hook = ln_mdns_resolve;
	if (argc) {
		rda = ReadArgs((STRPTR)"FROM,EDIT/S,USE/S,SAVE/S,PUBSCREEN/K,LANGUAGE/K", args, NULL);
		if (!rda) {
			PrintFault(IoErr(), (STRPTR)"LagoonPrefs");
			return 10;
		}
		from_path = (const char *)args[0];
	}
	lp_locale_open((const char *)args[5]);
	if (load(from_path, 0) < 0 && (args[2] || args[3])) {
		rc = 10;
	} else if (args[2] || args[3]) {
		rc = store(args[3] != 0) < 0 ? 10 : 0;
	} else {
		rc = run_gui((const char *)args[4]);
		cleanup();
	}
	ln_wipe(&lp_conf, sizeof(lp_conf));
	if (rda)
		FreeArgs(rda);
	lp_locale_close();
	return rc;
}
