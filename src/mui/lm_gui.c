/*
 * Lagoon - the MUI front end: the share list, the network browser, the share editor and a file
 * browser for a connected share. One source for the Amiga and the classic Mac OS (lm_gui.h): it
 * uses MUI's built-in classes only (Application, Window, Group, Text, String, Cycle, List,
 * Listview, Rectangle), the helpers of riptide's src/amiga/prefs/mui_util.c (mui_new, mui_do,
 * mui_set, mui_get) and AmigaDOS for local files, so the Mac build needs nothing beyond
 * Riptide's MUI for the Mac (riptide docs/MAC-GUI.md). A button is MUI's usual one: a Text in
 * a button frame with RelVerify input, its label centred with ESC c.
 *
 * Windows:
 *   main      the shares of lagoon.conf; Browse network..., New..., Edit..., Remove, Connect, Save;
 *             on the Mac also Put on Desktop (the AppleShare bridge, src/mac/bridge)
 *   editor    name, protocol (SMB, AFP, NFS), server, share (List... asks the server), user,
 *             password
 *   picker    a list to choose from: the servers mDNS and NetBIOS found, or a server's shares
 *   files     a connected share: Open (a folder), Up, Download..., Upload..., New folder...,
 *             Delete, with the free space
 *   ask       a line of text (the new folder's name)
 *   confirm   a yes/no question (Delete)
 * Network calls wait in place (the Amiga's task, or Riptide's yield on the Mac); the application
 * sleeps meanwhile. Passwords are never logged; they go to lagoon.conf hidden (ln_conf_hide).
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "amiga_os.h"
#include "prefs/mui.h"
#include "ln_conf.h"
#include "ln_vfs.h"
#include "ln_url.h"
#include "ln_net.h"
#include "ln_sys.h"
#include "ln_mdns.h"
#include "ln_netbios.h"
#include "lm_gui.h"
#ifdef LM_BRIDGE
#include "bridge/lm_bridge.h"                    /* the Mac's AppleShare bridge (src/mac/bridge) */
#endif
#define LM_STRINGS_ARRAY
#include "lm_strings.h"

/* riptide src/amiga/prefs/mui_util.c */
Object *mui_new(const char *cls, ULONG tag, ...);
ULONG mui_do(Object *obj, ULONG id, ...);
void mui_set(Object *obj, ULONG attr, ULONG v);
ULONG mui_get(Object *obj, ULONG attr);

#ifndef MUIA_Text_Contents
#define MUIA_Text_Contents 0x8042f8dcUL
#endif
#ifndef MUIA_Window_ID
#define MUIA_Window_ID 0x804201bdUL
#endif
#define LM_TAGEND 0UL

/* ---- strings ---- */
#if defined(LM_AMIGA_LOCALE)
static struct Catalog *catalog;
#endif
const char *lm_str(int id)
{
	if (id < 0 || id >= MSG_COUNT)
		return "";
#if defined(LM_AMIGA_LOCALE)
	if (catalog)
		return (const char *)GetCatalogStr(catalog, id, (STRPTR)lm_builtin[id]);
#endif
	return lm_builtin[id];
}
#define S(id) lm_str(id)

/* ---- the objects ---- */
enum {
	ID_BROWSE = 100, ID_NEW, ID_EDIT, ID_REMOVE, ID_CONNECT, ID_SAVE, ID_SHARELIST, ID_MOUNT,
	ID_ED_OK = 120, ID_ED_CANCEL, ID_ED_LIST,
	ID_PK_USE = 130, ID_PK_CANCEL,
	ID_F_OPEN = 140, ID_F_UP, ID_F_DOWN, ID_F_UPLOAD, ID_F_MKDIR, ID_F_DELETE, ID_F_CLOSE,
	ID_ASK_OK = 160, ID_ASK_CANCEL, ID_CF_OK, ID_CF_CANCEL,
	ID_QUIT = 199
};

static Object *app, *wmain, *lshares, *tstatus;
static Object *wed, *ename, *eproto, *eserver, *eshare, *euser, *epass;
static Object *wpick, *ptitle, *plist, *pstatus;
static Object *wfiles, *fpath, *flist, *fstatus;
static Object *wask, *atext, *astring;
static Object *wconf, *ctext;

static LnConf conf;
static int conf_dirty;
static int edit_index = -1;                     /* the share being edited, -1 new */
static int net_ok;

static const char *proto_names[4];
static const char *const schemes[3] = { "smb", "afp", "nfs" };

/* a button: MUI's usual Text in a button frame, centred */
static Object *button(const char *label, ULONG id)
{
	char t[80];
	Object *b;
	ln_snprintf(t, sizeof t, "\033c%s", label);
	b = mui_new(MUIC_Text, MUIA_Frame, MUIV_Frame_Button, MUIA_InputMode, MUIV_InputMode_RelVerify,
	            MUIA_Text_Contents, (ULONG)t, MUIA_CycleChain, 1, LM_TAGEND);
	if (b && app)
		mui_do(b, MUIM_Notify, MUIA_Pressed, FALSE, (ULONG)app, 2, MUIM_Application_ReturnID, id);
	return b;
}
static Object *label(const char *text)
{
	char t[80];
	ln_snprintf(t, sizeof t, "\033r%s", text);
	return mui_new(MUIC_Text, MUIA_Text_Contents, (ULONG)t, MUIA_HorizWeight, 0, LM_TAGEND);
}
static Object *text(const char *s)
{
	return mui_new(MUIC_Text, MUIA_Text_Contents, (ULONG)s, LM_TAGEND);
}
static Object *string(ULONG max)
{
	return mui_new(MUIC_String, MUIA_Frame, MUIV_Frame_String, MUIA_String_MaxLen, max, MUIA_CycleChain, 1,
	               LM_TAGEND);
}
/* a password field: bullets for the characters (MUI's own, and the Mac's Human Interface
   Guidelines' password field on the Mac's MUI layer) */
#ifndef MUIA_String_Secret
#define MUIA_String_Secret 0x80428769UL
#endif
static Object *secret_string(ULONG max)
{
	return mui_new(MUIC_String, MUIA_Frame, MUIV_Frame_String, MUIA_String_MaxLen, max, MUIA_String_Secret, TRUE,
	               MUIA_CycleChain, 1, LM_TAGEND);
}
static Object *list(Object **lv, ULONG active_id)
{
	Object *l = mui_new(MUIC_List, MUIA_Frame, MUIV_Frame_InputList, MUIA_List_ConstructHook,
	                    MUIV_List_ConstructHook_String, MUIA_List_DestructHook, MUIV_List_DestructHook_String, LM_TAGEND);
	*lv = l ? mui_new(MUIC_Listview, MUIA_Listview_List, (ULONG)l, MUIA_CycleChain, 1, LM_TAGEND) : NULL;
	if (l && active_id && app)
		mui_do(l, MUIM_Notify, MUIA_List_Active, MUIV_EveryTime, (ULONG)app, 2, MUIM_Application_ReturnID, active_id);
	return l;
}
static Object *row(Object *a, Object *b, Object *c, Object *d)
{
	Object *g = mui_new(MUIC_Group, MUIA_Group_Horiz, TRUE, MUIA_Group_Spacing, 6, LM_TAGEND);
	Object *k[4];
	int i;
	k[0] = a; k[1] = b; k[2] = c; k[3] = d;
	for (i = 0; g && i < 4; i++)
		if (k[i])
			mui_do(g, OM_ADDMEMBER, (ULONG)k[i]);
	return g;
}
static Object *window(const char *title, ULONG id, Object *root, ULONG close_id)
{
	Object *w = root ? mui_new(MUIC_Window, MUIA_Window_Title, (ULONG)title, MUIA_Window_RootObject, (ULONG)root,
	                           MUIA_Window_LeftEdge, MUIV_Window_LeftEdge_Centered,
	                           MUIA_Window_TopEdge, MUIV_Window_TopEdge_Centered, LM_TAGEND) : NULL;
	(void)id;
	if (w) {
		mui_do(app, OM_ADDMEMBER, (ULONG)w);
		mui_do(w, MUIM_Notify, MUIA_Window_CloseRequest, TRUE, (ULONG)app, 2, MUIM_Application_ReturnID, close_id);
	}
	return w;
}
static Object *vgroup(int spacing)
{
	return mui_new(MUIC_Group, MUIA_Group_Spacing, spacing, MUIA_InnerLeft, 8, MUIA_InnerRight, 8, MUIA_InnerTop, 8,
	               MUIA_InnerBottom, 8, LM_TAGEND);
}
static void add(Object *g, Object *o) { if (g && o) mui_do(g, OM_ADDMEMBER, (ULONG)o); }

static void status(Object *t, const char *s) { mui_set(t, MUIA_Text_Contents, (ULONG)s); }
static void sleep_app(int on) { mui_set(app, MUIA_Application_Sleep, on ? TRUE : FALSE); }
static LONG active(Object *l) { return (LONG)mui_get(l, MUIA_List_Active); }

/* ---- lagoon.conf ---- */
static void conf_load(void)
{
	BPTR f;
	char *buf;
	LONG n = 0;
	int line;
	ln_conf_init(&conf);
	f = Open((CONST_STRPTR)LM_ENV_FILE, MODE_OLDFILE);
	if (!f)
		f = Open((CONST_STRPTR)LM_CONF_FILE, MODE_OLDFILE);
	if (!f)
		return;
	buf = ln_alloc(16384);
	if (buf) {
		n = Read(f, buf, 16383);
		if (n > 0) {
			buf[n] = 0;
			ln_conf_parse(&conf, buf, &line);
		}
		ln_free(buf);
	}
	Close(f);
}
static int conf_save(void)
{
	char *buf = ln_alloc(16384);
	BPTR f, l;
	int n, ok = 0;
	if (!buf)
		return 0;
	n = ln_conf_format(&conf, buf, 16384);
	if ((l = Lock((CONST_STRPTR)LM_CONF_DIR, ACCESS_READ)) != 0)
		UnLock(l);
	else if ((l = CreateDir((CONST_STRPTR)LM_CONF_DIR)) != 0)
		UnLock(l);
	if (n > 0 && (f = Open((CONST_STRPTR)LM_CONF_FILE, MODE_NEWFILE)) != 0) {
		ok = Write(f, buf, n) == n;
		Close(f);
	}
	ln_free(buf);
	if (ok)
		conf_dirty = 0;
	return ok;
}

static void shares_fill(void)
{
	int i;
	mui_set(lshares, MUIA_List_Quiet, TRUE);
	mui_do(lshares, MUIM_List_Clear);
	for (i = 0; i < conf.nshares; i++) {
		char t[LN_URL_MAX + 40];
		ln_snprintf(t, sizeof t, "%s   %s", conf.share[i].name, conf.share[i].url);
		mui_do(lshares, MUIM_List_InsertSingle, (ULONG)t, MUIV_List_Insert_Bottom);
	}
	mui_set(lshares, MUIA_List_Quiet, FALSE);
	status(tstatus, conf.nshares ? "" : S(MSG_NO_SHARES));
}

/* ---- the editor ---- */
static void editor_open(const LnShare *s, const char *server, int proto)
{
	LnUrl u;
	int p = proto;
	memset(&u, 0, sizeof u);
	if (s && ln_url_parse(s->url, &u) == LN_OK) {
		int k;
		for (k = 0; k < 3; k++)
			if (!strcmp(u.scheme, schemes[k]))
				p = k;
	}
	mui_set(ename, MUIA_String_Contents, (ULONG)(s ? s->name : ""));
	mui_set(eproto, MUIA_Cycle_Active, (ULONG)(p >= 0 ? p : 0));
	mui_set(eserver, MUIA_String_Contents, (ULONG)(s ? u.host : server ? server : ""));
	mui_set(eshare, MUIA_String_Contents, (ULONG)(s ? u.share : ""));
	mui_set(euser, MUIA_String_Contents, (ULONG)(s ? s->user : ""));
	mui_set(epass, MUIA_String_Contents, (ULONG)(s ? s->password : ""));
	mui_set(wmain, MUIA_Window_Sleep, TRUE);
	mui_set(wed, MUIA_Window_Open, TRUE);
}
static void editor_close(void)
{
	mui_set(epass, MUIA_String_Contents, (ULONG)"");
	mui_set(wed, MUIA_Window_Open, FALSE);
	mui_set(wmain, MUIA_Window_Sleep, FALSE);
}
/* the editor's fields as a share; 0 when the server is missing */
static int editor_share(LnShare *s)
{
	LnUrl u;
	const char *name = (const char *)mui_get(ename, MUIA_String_Contents);
	ULONG p = mui_get(eproto, MUIA_Cycle_Active);
	memset(s, 0, sizeof *s);
	memset(&u, 0, sizeof u);
	ln_strlcpy(u.scheme, schemes[p < 3 ? p : 0], sizeof u.scheme);
	ln_strlcpy(u.host, (const char *)mui_get(eserver, MUIA_String_Contents), sizeof u.host);
	ln_strlcpy(u.share, (const char *)mui_get(eshare, MUIA_String_Contents), sizeof u.share);
	if (!u.host[0])
		return 0;
	ln_url_format(&u, s->url, sizeof s->url);
	ln_strlcpy(s->name, name && name[0] ? name : u.share[0] ? u.share : u.host, sizeof s->name);
	ln_strlcpy(s->user, (const char *)mui_get(euser, MUIA_String_Contents), sizeof s->user);
	ln_strlcpy(s->password, (const char *)mui_get(epass, MUIA_String_Contents), sizeof s->password);
	return 1;
}
static void creds_of(const LnShare *s, LnCreds *cr)
{
	memset(cr, 0, sizeof *cr);
	ln_strlcpy(cr->domain, s->domain, sizeof cr->domain);
	ln_strlcpy(cr->user, s->user, sizeof cr->user);
	ln_strlcpy(cr->password, s->password, sizeof cr->password);
}

/* ---- the picker: servers, or a server's shares ---- */
#define PICK_MAX 48
static int pick_kind;                            /* 1 servers, 2 shares */
static int npick;
static struct { char host[128]; char name[96]; int proto; } pick[PICK_MAX];

static void pick_add(const char *host, const char *name, int proto)
{
	char t[256];
	int i;
	if (npick >= PICK_MAX || !host[0])
		return;
	for (i = 0; i < npick; i++)
		if (!ln_strcasecmp(pick[i].host, host) && pick[i].proto == proto && !strcmp(pick[i].name, name))
			return;
	ln_strlcpy(pick[npick].host, host, sizeof pick[npick].host);
	ln_strlcpy(pick[npick].name, name, sizeof pick[npick].name);
	pick[npick].proto = proto;
	if (pick_kind == 1)
		ln_snprintf(t, sizeof t, "%s   (%s, %s)", name[0] ? name : host, schemes[proto], host);
	else
		ln_snprintf(t, sizeof t, "%s", name);
	mui_do(plist, MUIM_List_InsertSingle, (ULONG)t, MUIV_List_Insert_Bottom);
	npick++;
}
static void picker_open(int kind, const char *title)
{
	pick_kind = kind;
	npick = 0;
	mui_do(plist, MUIM_List_Clear);
	mui_set(wpick, MUIA_Window_Title, (ULONG)title);
	status(ptitle, title);
	mui_set(wpick, MUIA_Window_Open, TRUE);
}

static void browse(void)
{
	static const char *const types[] = { "_smb._tcp", "_afpovertcp._tcp", "_nfs._tcp", NULL };
	LnService *sv = ln_alloc(sizeof(LnService) * 24);
	LnNbHost *nb = ln_alloc(sizeof(LnNbHost) * 24);
	char t[64];
	int n, i;
	picker_open(1, S(MSG_BROWSE_TITLE));
	status(pstatus, S(MSG_SEARCHING));
	sleep_app(1);
	if (sv) {
		n = ln_mdns_browse(types, 3000, sv, 24);
		for (i = 0; i < n; i++) {
			int p = !strcmp(sv[i].scheme, "afp") ? 1 : !strcmp(sv[i].scheme, "nfs") ? 2 : 0;
			pick_add(sv[i].host[0] ? sv[i].host : "", sv[i].instance, p);
		}
	}
	if (nb) {
		char a[48];
		n = ln_nb_discover(2000, nb, 24);
		for (i = 0; i < n; i++)
			if (nb[i].server) {
				ln_addr_str(&nb[i].addr, a, sizeof a);
				pick_add(a, nb[i].name, 0);
			}
	}
	sleep_app(0);
	ln_free(sv);
	ln_free(nb);
	ln_snprintf(t, sizeof t, npick ? S(MSG_FOUND) : S(MSG_NONE_FOUND), (long)npick);
	status(pstatus, t);
}

static void share_cb(void *ud, const char *name, const char *comment)
{
	(void)ud;
	(void)comment;
	pick_add("-", name, 0);
}
static void list_shares(void)
{
	LnShare s;
	LnUrl u;
	LnCreds cr;
	const LnOps *ops;
	char t[200];
	int r;
	if (!editor_share(&s)) {
		status(tstatus, S(MSG_NEED_SERVER));
		return;
	}
	ln_url_parse(s.url, &u);
	ops = ln_vfs_find(u.scheme);
	ln_snprintf(t, sizeof t, S(MSG_SHARES_ON), u.host);
	picker_open(2, t);
	ln_snprintf(t, sizeof t, S(MSG_LISTING), u.host);
	status(pstatus, t);
	creds_of(&s, &cr);
	sleep_app(1);
	r = ops && ops->list_shares ? ops->list_shares(&u, &cr, share_cb, NULL) : LN_ENOTSUP;
	sleep_app(0);
	memset(&cr, 0, sizeof cr);
	if (r < 0) {
		ln_snprintf(t, sizeof t, S(MSG_FAILED), u.host, ln_strerror(r));
		status(pstatus, t);
	} else {
		ln_snprintf(t, sizeof t, S(MSG_FOUND), (long)npick);
		status(pstatus, t);
	}
}

/* ---- a connected share ---- */
#define FMAX 400
static const LnOps *fops;
static LnFs *ffs;
static char fdir[LN_URL_MAX];                    /* the folder shown, "" the share's top */
static int nfent;
static struct fent { char name[96]; int dir; u64 size; } *fent;

static void join(char *out, size_t n, const char *dir, const char *name)
{
	if (dir[0])
		ln_snprintf(out, n, "%s/%s", dir, name);
	else
		ln_strlcpy(out, name, n);
}
static void human(u64 b, char *out, size_t n)
{
	if (b >= (u64)10 << 30)
		ln_snprintf(out, n, "%lu GB", (unsigned long)(b >> 30));
	else if (b >= (u64)10 << 20)
		ln_snprintf(out, n, "%lu MB", (unsigned long)(b >> 20));
	else
		ln_snprintf(out, n, "%lu KB", (unsigned long)((b + 1023) >> 10));
}
static void files_fill(void)
{
	LnDir *d;
	LnStat st;
	LnStatFs fs;
	char name[96], t[160], a[24], b[24];
	int r;
	nfent = 0;
	mui_set(flist, MUIA_List_Quiet, TRUE);
	mui_do(flist, MUIM_List_Clear);
	sleep_app(1);
	r = fops->opendir(ffs, fdir, &d);
	if (r == LN_OK) {
		while (nfent < FMAX && fops->readdir(d, name, sizeof name, &st) == 1) {
			ln_strlcpy(fent[nfent].name, name, sizeof fent[nfent].name);
			fent[nfent].dir = st.type == LN_T_DIR;
			fent[nfent].size = st.size;
			if (fent[nfent].dir)
				ln_snprintf(t, sizeof t, S(MSG_FOLDER_ITEM), name);
			else {
				human(st.size, a, sizeof a);
				ln_snprintf(t, sizeof t, "%s   %s", name, a);
			}
			mui_do(flist, MUIM_List_InsertSingle, (ULONG)t, MUIV_List_Insert_Bottom);
			nfent++;
		}
		fops->closedir(d);
	}
	mui_set(flist, MUIA_List_Quiet, FALSE);
	ln_snprintf(t, sizeof t, "/%s", fdir);
	status(fpath, t);
	if (r != LN_OK) {
		ln_snprintf(t, sizeof t, S(MSG_FAILED), fdir[0] ? fdir : "/", ln_strerror(r));
		status(fstatus, t);
	} else if (fops->statfs && fops->statfs(ffs, &fs) == LN_OK && fs.total_bytes) {
		human(fs.free_bytes, a, sizeof a);
		human(fs.total_bytes, b, sizeof b);
		ln_snprintf(t, sizeof t, S(MSG_FREE), a, b);
		status(fstatus, t);
	} else
		status(fstatus, "");
	sleep_app(0);
}
static void files_close(void)
{
	if (ffs)
		fops->unmount(ffs);
	ffs = NULL;
	mui_set(wfiles, MUIA_Window_Open, FALSE);
	mui_set(wmain, MUIA_Window_Sleep, FALSE);
}
static void connect_share(const LnShare *s)
{
	LnCreds cr;
	char t[200];
	int r;
	if (!net_ok) {
		status(tstatus, S(MSG_NO_STACK));
		return;
	}
	ln_snprintf(t, sizeof t, S(MSG_CONNECTING), s->name);
	status(tstatus, t);
	creds_of(s, &cr);
	sleep_app(1);
	r = ln_vfs_mount_url(s->url, &cr, &fops, &ffs);
	sleep_app(0);
	memset(&cr, 0, sizeof cr);
	if (r != LN_OK) {
		ln_snprintf(t, sizeof t, S(MSG_FAILED), s->name, ln_strerror(r));
		status(tstatus, t);
		return;
	}
	status(tstatus, "");
	fdir[0] = 0;
	mui_set(wfiles, MUIA_Window_Title, (ULONG)s->name);
	mui_set(wmain, MUIA_Window_Sleep, TRUE);
	mui_set(wfiles, MUIA_Window_Open, TRUE);
	files_fill();
}

#ifdef LM_BRIDGE
/* ---- the Mac: the share as an AppleShare volume on the desktop (src/mac/bridge) ---- */
static void bridge_failed(const LnShare *s, int err, int oserr)
{
	char t[200], n[16];
	if (err)
		ln_snprintf(t, sizeof t, S(MSG_FAILED), s->name, ln_strerror(err));
	else {
		ln_snprintf(n, sizeof n, "%ld", (long)oserr);
		ln_snprintf(t, sizeof t, S(MSG_BRIDGE_ERROR), s->name, n);
	}
	status(tstatus, t);
}

static void put_on_desktop(const LnShare *s)
{
	LnCreds cr;
	char t[200];
	int r, err = 0, oserr = 0, st;
	u32 t0;
	if (!net_ok) {
		status(tstatus, S(MSG_NO_STACK));
		return;
	}
	st = lm_bridge_state(NULL, NULL);
	if (st == LMB_SERVING && strcmp(lm_bridge_name(), s->name))
		lm_bridge_stop();                    /* one share at a time */
	if (lm_bridge_state(NULL, NULL) != LMB_SERVING) {
		if (st == LMB_FAILED)
			lm_bridge_stop();
		creds_of(s, &cr);
		r = lm_bridge_start(s->url, &cr, s->name);
		memset(&cr, 0, sizeof cr);
		if (r != LN_OK) {
			if (r == LN_ENONET)
				status(tstatus, S(MSG_NO_APPLETALK));
			else {
				lm_bridge_state(&err, &oserr);
				bridge_failed(s, oserr ? 0 : r, oserr);
			}
			return;
		}
		ln_snprintf(t, sizeof t, S(MSG_BRIDGE_STARTING), s->name);
		status(tstatus, t);
		sleep_app(1);
		t0 = ln_ms();
		while ((st = lm_bridge_state(&err, &oserr)) == LMB_STARTING && ln_ms() - t0 < 90000)
			lm_yield(NULL);
		sleep_app(0);
		if (st != LMB_SERVING) {
			bridge_failed(s, st == LMB_STARTING ? LN_ETIMEDOUT : err, oserr);
			lm_bridge_stop();
			return;
		}
	}
	ln_snprintf(t, sizeof t, S(MSG_BRIDGE_MOUNTING), s->name);
	status(tstatus, t);
	sleep_app(1);
	r = lm_bridge_mount();
	sleep_app(0);
	if (r != 0) {
		bridge_failed(s, 0, r);
		return;
	}
	ln_snprintf(t, sizeof t, S(MSG_BRIDGE_READY), s->name);
	status(tstatus, t);
}
#endif

/* ---- local files: a requester, then AmigaDOS ---- */
static int ask_file(int save, const char *title, const char *initial, char *path, size_t n)
{
	struct TagItem t[5];
	struct rt_filereq *fr;
	APTR req;
	int ok = 0;
	t[0].ti_Tag = RT_ASLFR_TitleText;      t[0].ti_Data = (ULONG)title;
	t[1].ti_Tag = RT_ASLFR_DoSaveMode;     t[1].ti_Data = (ULONG)save;
	t[2].ti_Tag = RT_ASLFR_InitialFile;    t[2].ti_Data = (ULONG)initial;
	t[3].ti_Tag = RT_ASLFR_InitialPattern; t[3].ti_Data = (ULONG)"#?";
	t[4].ti_Tag = TAG_DONE;                t[4].ti_Data = 0;
	req = MUI_AllocAslRequest(RT_ASL_FileRequest, t);
	if (!req)
		return 0;
	if (MUI_AslRequest(req, NULL)) {
		fr = (struct rt_filereq *)req;
		ln_strlcpy(path, (const char *)fr->fr_Drawer, n);
		ok = AddPart((STRPTR)path, fr->fr_File, (ULONG)n) != 0;
	}
	MUI_FreeAslRequest(req);
	return ok;
}

#define CHUNK 16384
static void download(void)
{
	LONG k = active(flist);
	char path[300], rpath[LN_URL_MAX], t[200];
	LnFile *f;
	BPTR out;
	char *buf;
	u64 off = 0;
	int r = LN_OK;
	if (k < 0 || k >= nfent || fent[k].dir) {
		status(fstatus, S(MSG_SELECT_FIRST));
		return;
	}
	if (!ask_file(1, S(MSG_ASL_SAVE), fent[k].name, path, sizeof path))
		return;
	join(rpath, sizeof rpath, fdir, fent[k].name);
	buf = ln_alloc(CHUNK);
	out = buf ? Open((CONST_STRPTR)path, MODE_NEWFILE) : 0;
	if (!out) {
		ln_snprintf(t, sizeof t, S(MSG_FILE_ERROR), path);
		status(fstatus, t);
		ln_free(buf);
		return;
	}
	sleep_app(1);
	if ((r = fops->open(ffs, rpath, LN_O_READ, &f)) == LN_OK) {
		for (;;) {
			long n = fops->read(f, off, buf, CHUNK);
			if (n <= 0) {
				if (n < 0) r = (int)n;
				break;
			}
			if (Write(out, buf, n) != n) {
				r = LN_EIO;
				break;
			}
			off += (u64)n;
			ln_snprintf(t, sizeof t, S(MSG_COPYING), fent[k].name, (long)(off >> 10));
			status(fstatus, t);
		}
		fops->close(f);
	}
	Close(out);
	sleep_app(0);
	ln_free(buf);
	if (r < 0)
		ln_snprintf(t, sizeof t, S(MSG_FAILED), fent[k].name, ln_strerror(r));
	else
		ln_snprintf(t, sizeof t, S(MSG_DONE), fent[k].name, (long)(off >> 10));
	status(fstatus, t);
}

static void upload(void)
{
	char path[300], rpath[LN_URL_MAX], t[200];
	const char *name;
	LnFile *f;
	BPTR in;
	char *buf;
	u64 off = 0;
	int r;
	if (!ask_file(0, S(MSG_ASL_OPEN), "", path, sizeof path))
		return;
	name = path;
	{
		const char *p;
		for (p = path; *p; p++)
			if (*p == ':' || *p == '/')
				name = p + 1;
	}
	join(rpath, sizeof rpath, fdir, name);
	buf = ln_alloc(CHUNK);
	in = buf ? Open((CONST_STRPTR)path, MODE_OLDFILE) : 0;
	if (!in) {
		ln_snprintf(t, sizeof t, S(MSG_FILE_ERROR), path);
		status(fstatus, t);
		ln_free(buf);
		return;
	}
	sleep_app(1);
	if ((r = fops->open(ffs, rpath, LN_O_WRITE | LN_O_CREATE | LN_O_TRUNC, &f)) == LN_OK) {
		for (;;) {
			LONG n = Read(in, buf, CHUNK);
			long w;
			if (n <= 0)
				break;
			w = fops->write(f, off, buf, n);
			if (w != n) {
				r = w < 0 ? (int)w : LN_EIO;
				break;
			}
			off += (u64)n;
			ln_snprintf(t, sizeof t, S(MSG_COPYING), name, (long)(off >> 10));
			status(fstatus, t);
		}
		fops->close(f);
	}
	Close(in);
	sleep_app(0);
	ln_free(buf);
	if (r < 0) {
		ln_snprintf(t, sizeof t, S(MSG_FAILED), name, ln_strerror(r));
		status(fstatus, t);
		return;
	}
	files_fill();
	ln_snprintf(t, sizeof t, S(MSG_DONE), name, (long)(off >> 10));
	status(fstatus, t);
}

/* ---- ask: a line of text, or yes / no ---- */
static int ask_kind;                             /* 1 new folder, 2 delete */
static LONG ask_entry;
static void ask_open(int kind, const char *question, int with_string)
{
	ask_kind = kind;
	mui_set(wfiles, MUIA_Window_Sleep, TRUE);
	if (!with_string) {
		status(ctext, question);
		mui_set(wconf, MUIA_Window_Open, TRUE);
		return;
	}
	status(atext, question);
	mui_set(astring, MUIA_String_Contents, (ULONG)"");
	mui_set(wask, MUIA_Window_Open, TRUE);
	mui_set(wask, MUIA_Window_ActiveObject, (ULONG)astring);
}
static void ask_done(int ok)
{
	char p[LN_URL_MAX], t[200];
	int r = LN_OK;
	mui_set(wask, MUIA_Window_Open, FALSE);
	mui_set(wconf, MUIA_Window_Open, FALSE);
	mui_set(wfiles, MUIA_Window_Sleep, FALSE);
	if (!ok)
		return;
	sleep_app(1);
	if (ask_kind == 1) {
		const char *name = (const char *)mui_get(astring, MUIA_String_Contents);
		if (!name || !name[0]) {
			sleep_app(0);
			return;
		}
		join(p, sizeof p, fdir, name);
		r = fops->mkdir(ffs, p);
		ln_strlcpy(t, name, sizeof t);
	} else if (ask_kind == 2 && ask_entry >= 0 && ask_entry < nfent) {
		join(p, sizeof p, fdir, fent[ask_entry].name);
		r = fops->remove(ffs, p);
		ln_strlcpy(t, fent[ask_entry].name, sizeof t);
	}
	sleep_app(0);
	if (r < 0) {
		char m[200];
		ln_snprintf(m, sizeof m, S(MSG_FAILED), t, ln_strerror(r));
		status(fstatus, m);
		return;
	}
	files_fill();
}

/* ---- the windows ---- */
static int build(void)
{
	Object *root, *lv, *g;
	proto_names[0] = S(MSG_PROTO_SMB);
	proto_names[1] = S(MSG_PROTO_AFP);
	proto_names[2] = S(MSG_PROTO_NFS);
	proto_names[3] = NULL;

	app = mui_new(MUIC_Application, MUIA_Application_Title, (ULONG)"Lagoon", MUIA_Application_Base, (ULONG)"LAGOON",
	              MUIA_Application_Version, (ULONG)"$VER: Lagoon 0.2 (18.11.2026)", LM_TAGEND);
	if (!app)
		return 0;

	/* main */
	root = vgroup(6);
	lshares = list(&lv, 0);
	tstatus = text("");
	add(root, text(S(MSG_SHARES_HDR)));
	add(root, lv);
	add(root, row(button(S(MSG_BROWSE), ID_BROWSE), button(S(MSG_NEW), ID_NEW), button(S(MSG_EDIT), ID_EDIT),
	              button(S(MSG_REMOVE), ID_REMOVE)));
#ifdef LM_BRIDGE
	add(root, row(button(S(MSG_CONNECT), ID_CONNECT), button(S(MSG_PUT_ON_DESKTOP), ID_MOUNT),
	              mui_new(MUIC_Rectangle, LM_TAGEND), button(S(MSG_SAVE), ID_SAVE)));
#else
	add(root, row(button(S(MSG_CONNECT), ID_CONNECT), mui_new(MUIC_Rectangle, LM_TAGEND), button(S(MSG_SAVE), ID_SAVE), NULL));
#endif
	add(root, tstatus);
	wmain = window(S(MSG_WIN_SHARES), 1, root, ID_QUIT);

	/* editor */
	root = vgroup(6);
	g = mui_new(MUIC_Group, MUIA_Group_Columns, 2, MUIA_Group_Spacing, 4, LM_TAGEND);
	ename = string(31);
	eproto = mui_new(MUIC_Cycle, MUIA_Cycle_Entries, (ULONG)proto_names, MUIA_CycleChain, 1, LM_TAGEND);
	eserver = string(127);
	eshare = string(127);
	euser = string(63);
	epass = secret_string(127);
	add(g, label(S(MSG_NAME)));     add(g, ename);
	add(g, label(S(MSG_PROTOCOL))); add(g, eproto);
	add(g, label(S(MSG_SERVER)));   add(g, eserver);
	add(g, label(S(MSG_USER)));     add(g, euser);
	add(g, label(S(MSG_PASSWORD))); add(g, epass);
	add(g, label(S(MSG_SHARE)));    add(g, row(eshare, button(S(MSG_LIST), ID_ED_LIST), NULL, NULL));
	add(root, g);
	add(root, row(mui_new(MUIC_Rectangle, LM_TAGEND), button(S(MSG_CANCEL), ID_ED_CANCEL), button(S(MSG_OK), ID_ED_OK), NULL));
	wed = window(S(MSG_EDITOR_TITLE), 2, root, ID_ED_CANCEL);

	/* picker */
	root = vgroup(6);
	ptitle = text("");
	plist = list(&lv, 0);
	pstatus = text("");
	add(root, ptitle);
	add(root, lv);
	add(root, pstatus);
	add(root, row(mui_new(MUIC_Rectangle, LM_TAGEND), button(S(MSG_CANCEL), ID_PK_CANCEL), button(S(MSG_USE), ID_PK_USE), NULL));
	wpick = window(S(MSG_BROWSE_TITLE), 3, root, ID_PK_CANCEL);

	/* files */
	root = vgroup(6);
	fpath = text("/");
	flist = list(&lv, 0);
	fstatus = text("");
	add(root, fpath);
	add(root, lv);
	add(root, row(button(S(MSG_OPEN), ID_F_OPEN), button(S(MSG_UP), ID_F_UP), button(S(MSG_DOWNLOAD), ID_F_DOWN),
	              button(S(MSG_UPLOAD), ID_F_UPLOAD)));
	add(root, row(button(S(MSG_NEWFOLDER), ID_F_MKDIR), button(S(MSG_DELETE), ID_F_DELETE),
	              mui_new(MUIC_Rectangle, LM_TAGEND), button(S(MSG_CLOSE), ID_F_CLOSE)));
	add(root, fstatus);
	wfiles = window("Lagoon", 4, root, ID_F_CLOSE);

	/* ask */
	root = vgroup(6);
	atext = text("");
	astring = string(95);
	add(root, atext);
	add(root, astring);
	add(root, row(mui_new(MUIC_Rectangle, LM_TAGEND), button(S(MSG_CANCEL), ID_ASK_CANCEL), button(S(MSG_OK), ID_ASK_OK), NULL));
	wask = window(S(MSG_APP_TITLE), 5, root, ID_ASK_CANCEL);

	/* confirm */
	root = vgroup(6);
	ctext = text("");
	add(root, ctext);
	add(root, row(mui_new(MUIC_Rectangle, LM_TAGEND), button(S(MSG_CANCEL), ID_CF_CANCEL), button(S(MSG_OK), ID_CF_OK), NULL));
	wconf = window(S(MSG_APP_TITLE), 6, root, ID_CF_CANCEL);

	return wmain && wed && wpick && wfiles && wask && wconf && lshares && plist && flist;
}

static void handle(LONG id)
{
	LONG k;
	LnShare s;
	char t[200];
	switch (id) {
	case ID_BROWSE:
		if (!net_ok) { status(tstatus, S(MSG_NO_STACK)); break; }
		browse();
		break;
	case ID_NEW:
		edit_index = -1;
		editor_open(NULL, NULL, 0);
		break;
	case ID_EDIT:
		k = active(lshares);
		if (k < 0 || k >= conf.nshares) { status(tstatus, S(MSG_SELECT_FIRST)); break; }
		edit_index = (int)k;
		editor_open(&conf.share[k], NULL, -1);
		break;
	case ID_REMOVE:
		k = active(lshares);
		if (k < 0 || k >= conf.nshares) { status(tstatus, S(MSG_SELECT_FIRST)); break; }
		ln_conf_remove(&conf, conf.share[k].name);
		conf_dirty = 1;
		shares_fill();
		break;
	case ID_CONNECT:
		k = active(lshares);
		if (k < 0 || k >= conf.nshares) { status(tstatus, S(MSG_SELECT_FIRST)); break; }
		connect_share(&conf.share[k]);
		break;
	case ID_SAVE:
		status(tstatus, conf_save() ? S(MSG_SAVED) : S(MSG_SAVE_FAILED));
		break;
#ifdef LM_BRIDGE
	case ID_MOUNT:
		k = active(lshares);
		if (k < 0 || k >= conf.nshares) { status(tstatus, S(MSG_SELECT_FIRST)); break; }
		put_on_desktop(&conf.share[k]);
		break;
#endif
	case ID_ED_OK:
		if (!editor_share(&s)) { status(tstatus, S(MSG_NEED_SERVER)); break; }
		if (edit_index >= 0 && edit_index < conf.nshares && strcmp(conf.share[edit_index].name, s.name))
			ln_conf_remove(&conf, conf.share[edit_index].name);
		ln_conf_put(&conf, &s);
		memset(&s, 0, sizeof s);
		conf_dirty = 1;
		editor_close();
		shares_fill();
		break;
	case ID_ED_CANCEL:
		editor_close();
		break;
	case ID_ED_LIST:
		if (!net_ok) { status(tstatus, S(MSG_NO_STACK)); break; }
		list_shares();
		break;
	case ID_PK_USE:
		k = active(plist);
		if (k < 0 || k >= npick) break;
		mui_set(wpick, MUIA_Window_Open, FALSE);
		if (pick_kind == 1) {
			edit_index = -1;
			editor_open(NULL, pick[k].host, pick[k].proto);
		} else
			mui_set(eshare, MUIA_String_Contents, (ULONG)pick[k].name);
		break;
	case ID_PK_CANCEL:
		mui_set(wpick, MUIA_Window_Open, FALSE);
		break;
	case ID_F_OPEN:
		k = active(flist);
		if (k < 0 || k >= nfent || !fent[k].dir) { status(fstatus, S(MSG_SELECT_FIRST)); break; }
		join(t, sizeof t, fdir, fent[k].name);
		ln_strlcpy(fdir, t, sizeof fdir);
		files_fill();
		break;
	case ID_F_UP: {
		char *sl = strrchr(fdir, '/');
		if (sl) *sl = 0; else fdir[0] = 0;
		files_fill();
		break;
	}
	case ID_F_DOWN:
		download();
		break;
	case ID_F_UPLOAD:
		upload();
		break;
	case ID_F_MKDIR:
		ask_open(1, S(MSG_FOLDER_NAME), 1);
		break;
	case ID_F_DELETE:
		k = active(flist);
		if (k < 0 || k >= nfent) { status(fstatus, S(MSG_SELECT_FIRST)); break; }
		ask_entry = k;
		ln_snprintf(t, sizeof t, S(MSG_CONFIRM_DELETE), fent[k].name);
		ask_open(2, t, 0);
		break;
	case ID_F_CLOSE:
		files_close();
		break;
	case ID_ASK_OK:
	case ID_CF_OK:
		ask_done(1);
		break;
	case ID_ASK_CANCEL:
	case ID_CF_CANCEL:
		ask_done(0);
		break;
	}
}

int lm_gui_run(void)
{
	ULONG sigs = 0;
#if defined(LM_AMIGA_LOCALE)
	if (LocaleBase)
		catalog = OpenCatalogA(NULL, (STRPTR)"Lagoon.catalog", NULL);
#endif
	fent = ln_alloc(sizeof(struct fent) * FMAX);
	conf_load();
	net_ok = ln_net_init() == LN_OK;
	if (!fent || !build()) {
		if (app)
			MUI_DisposeObject(app);
		ln_free(fent);
		return 20;
	}
	ln_mdns_resolve_hook = ln_mdns_resolve;
	shares_fill();
	if (!net_ok)
		status(tstatus, S(MSG_NO_STACK));
	mui_set(wmain, MUIA_Window_Open, TRUE);
	for (;;) {
		LONG id = (LONG)mui_do(app, MUIM_Application_NewInput, (ULONG)&sigs);
		if (id == MUIV_Application_ReturnID_Quit || id == ID_QUIT)
			break;
		if (id)
			handle(id);
		if (sigs)
			sigs = Wait(sigs | SIGBREAKF_CTRL_C);
	}
	if (ffs)
		fops->unmount(ffs);
#ifdef LM_BRIDGE
	lm_bridge_stop();                            /* the AppleShare volume goes with Lagoon */
#endif
	if (conf_dirty)
		conf_save();
	mui_set(wmain, MUIA_Window_Open, FALSE);
	MUI_DisposeObject(app);
	memset(&conf, 0, sizeof conf);
	ln_free(fent);
	ln_net_exit();
#if defined(LM_AMIGA_LOCALE)
	if (catalog)
		CloseCatalog(catalog);
#endif
	return 0;
}
