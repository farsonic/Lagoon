/*
 * Lagoon - LagoonPrefs "Sharing" window: share this Amiga's folders over
 * SMB (Lagoon SERVE). The computer name and workgroup, the shared folders
 * (name, folder chosen with an ASL requester, read-only, "Allow guests (no
 * password)", which users), the users (name and password: only the NT hash
 * is kept), "Start at boot", and Start/Stop for the running server.
 * Everything edits lp_conf like the share list does: Save or Use in the
 * main window writes it (and tells a running server to reload); Start
 * server writes ENV: first so the server sees what the window shows.
 * GadTools only, one column, fits 640x200 with topaz 8.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <clib/alib_protos.h>
#include <libraries/asl.h>
#include <proto/asl.h>
#include "prefs.h"
#include "ln_sys.h"
#include "mount.h"

#define F_MAX 24

/* a window of gadgets with keyboard shortcuts */
typedef struct Form {
	struct Window *win;
	struct Gadget *glist, *gad[F_MAX];
	ULONG kind[F_MAX];
	struct { char key; int id; } keys[F_MAX];
	int nkeys;
	int stale;
} Form;

static void f_key(Form *f, const char *label, int id)
{
	char k = label ? lp_key(label) : 0;
	if (k && f->nkeys < F_MAX) {
		f->keys[f->nkeys].key = k;
		f->keys[f->nkeys].id = id;
		f->nkeys++;
	}
}

static void f_begin(Form *f, struct Gadget **g)
{
	if (f->win && f->glist)
		RemoveGList(f->win, f->glist, -1);
	FreeGadgets(f->glist);
	f->glist = NULL;
	memset(f->gad, 0, sizeof(f->gad));
	f->nkeys = 0;
	*g = CreateContext(&f->glist);
}

static int f_end(Form *f, struct Gadget *g)
{
	if (!g)
		return -1;
	if (f->win) {
		f->stale = 1;
		SetAPen(f->win->RPort, 0);
		RectFill(f->win->RPort, f->win->BorderLeft, f->win->BorderTop, f->win->Width - f->win->BorderRight - 1,
		         f->win->Height - f->win->BorderBottom - 1);
		AddGList(f->win, f->glist, (ULONG)~0, -1, NULL);
		RefreshGList(f->glist, f->win, NULL, -1);
		GT_RefreshWindow(f->win, NULL);
	}
	return 0;
}

static void f_free(Form *f)
{
	if (f->win)
		CloseWindow(f->win);
	f->win = NULL;
	FreeGadgets(f->glist);
	f->glist = NULL;
}

static struct Gadget *f_str(Form *f, struct Gadget *g, int id, const char *label, const char *text, int maxc,
                            int x, int y, int w, int disabled, struct Hook *hook)
{
	struct TagItem t[6];
	int n = 0;
	t[n].ti_Tag = GTST_String; t[n++].ti_Data = (ULONG)text;
	t[n].ti_Tag = GTST_MaxChars; t[n++].ti_Data = (ULONG)maxc;
	t[n].ti_Tag = GT_Underscore; t[n++].ti_Data = '_';
	t[n].ti_Tag = GA_Disabled; t[n++].ti_Data = (ULONG)disabled;
	if (hook) { t[n].ti_Tag = GTST_EditHook; t[n++].ti_Data = (ULONG)hook; }
	t[n].ti_Tag = TAG_DONE;
	g = f->gad[id] = lp_mk(STRING_KIND, g, id, label, PLACETEXT_LEFT, x, y, w, lp_rowh, t);
	f->kind[id] = STRING_KIND;
	if (!disabled)
		f_key(f, label, id);
	return g;
}

static struct Gadget *f_cb(Form *f, struct Gadget *g, int id, const char *label, int checked, int x, int y)
{
	struct TagItem t[4];
	t[0].ti_Tag = GTCB_Checked; t[0].ti_Data = (ULONG)checked;
	t[1].ti_Tag = GT_Underscore; t[1].ti_Data = '_';
	t[2].ti_Tag = GTCB_Scaled; t[2].ti_Data = TRUE;
	t[3].ti_Tag = TAG_DONE;
	g = f->gad[id] = lp_mk(CHECKBOX_KIND, g, id, label, PLACETEXT_RIGHT, x, y + (lp_rowh - LN_MAX(11, lp_fh + 3)) / 2,
	                       LN_MAX(26, lp_fh * 2 + 6), LN_MAX(11, lp_fh + 3), t);
	f->kind[id] = CHECKBOX_KIND;
	f_key(f, label, id);
	return g;
}

static struct Gadget *f_btn(Form *f, struct Gadget *g, int id, const char *label, int x, int y, int w, int disabled)
{
	struct TagItem t[3];
	t[0].ti_Tag = GT_Underscore; t[0].ti_Data = '_';
	t[1].ti_Tag = GA_Disabled; t[1].ti_Data = (ULONG)disabled;
	t[2].ti_Tag = TAG_DONE;
	g = f->gad[id] = lp_mk(BUTTON_KIND, g, id, label, PLACETEXT_IN, x, y, w, lp_rowh, t);
	f->kind[id] = BUTTON_KIND;
	if (!disabled)
		f_key(f, label, id);
	return g;
}

static struct Gadget *f_list(Form *f, struct Gadget *g, int id, LpList *l, int sel, int x, int y, int w, int h)
{
	struct TagItem t[5];
	t[0].ti_Tag = GTLV_Labels; t[0].ti_Data = (ULONG)&l->list;
	t[1].ti_Tag = GTLV_ShowSelected; t[1].ti_Data = 0;
	t[2].ti_Tag = GTLV_Selected; t[2].ti_Data = sel >= 0 ? (ULONG)sel : ~0UL;
	t[3].ti_Tag = GTLV_MakeVisible; t[3].ti_Data = sel >= 0 ? (ULONG)sel : 0;
	t[4].ti_Tag = TAG_DONE;
	g = f->gad[id] = lp_mk(LISTVIEW_KIND, g, id, NULL, 0, x, y, w, h, t);
	f->kind[id] = LISTVIEW_KIND;
	return g;
}

static struct Gadget *f_text(Form *f, struct Gadget *g, int id, const char *text, int x, int y, int w, int fixed)
{
	struct TagItem t[3];
	t[0].ti_Tag = GTTX_Text; t[0].ti_Data = (ULONG)text;
	t[1].ti_Tag = GTTX_Border; t[1].ti_Data = !fixed;
	t[2].ti_Tag = TAG_DONE;
	g = lp_mk(TEXT_KIND, g, fixed ? LP_ID_FIXED : id, NULL, 0, x, y, w, fixed ? lp_lh + 1 : lp_rowh, t);
	if (!fixed)
		f->gad[id] = g;
	return g;
}

/* the event loop: handler(id, code) returns 0 to go on, 1 = OK, -1 = cancel;
 * Esc and the close gadget cancel; shortcut keys press buttons, toggle
 * check boxes (handler with code 0xffff) and activate string gadgets */
static int f_loop(Form *f, int (*handler)(int id, UWORD code))
{
	int r = 0;
	while (!r) {
		struct IntuiMessage *im;
		WaitPort(f->win->UserPort);
		f->stale = 0;
		while (!r && (im = GT_GetIMsg(f->win->UserPort)) != NULL) {
			ULONG cls = im->Class;
			UWORD code = im->Code;
			struct Gadget *g = (struct Gadget *)im->IAddress;
			GT_ReplyIMsg(im);
			switch (cls) {
			case IDCMP_REFRESHWINDOW:
				GT_BeginRefresh(f->win);
				GT_EndRefresh(f->win, TRUE);
				break;
			case IDCMP_CLOSEWINDOW:
				r = -1;
				break;
			case IDCMP_GADGETUP:
				if (!f->stale)
					r = handler(g->GadgetID, code);
				break;
			case IDCMP_VANILLAKEY: {
				char k = (char)code;
				int i;
				if (code == 27) {
					r = -1;
					break;
				}
				if (k >= 'A' && k <= 'Z')
					k = (char)(k + 32);
				for (i = 0; i < f->nkeys; i++)
					if (f->keys[i].key == k)
						break;
				if (i == f->nkeys)
					break;
				if (f->kind[f->keys[i].id] == STRING_KIND)
					ActivateGadget(f->gad[f->keys[i].id], f->win, NULL);
				else
					r = handler(f->keys[i].id, f->kind[f->keys[i].id] == CHECKBOX_KIND ? 0xffff : 0);
				break;
			}
			}
		}
	}
	return r;
}

/* ---- password gadgets: '*' shown, text kept in pw_real[i] ---- */
static char pw_real[2][128], pw_shown[2][128];
static struct Hook pw_hook[2];

static ULONG pw_func(struct Hook *h, struct SGWork *sg, ULONG *msg)
{
	char *real = pw_real[h == &pw_hook[1] ? 1 : 0];
	int plen = (int)strlen(real), len = sg->NumChars, pos = sg->BufferPos, i;
	if (*msg != SGH_KEY)
		return 0;
	switch (sg->EditOp) {
	case EO_INSERTCHAR:
	case EO_REPLACECHAR:
		i = pos - 1;
		if (i < 0 || i >= 127)
			break;
		if (sg->EditOp == EO_INSERTCHAR && plen < 127)
			memmove(real + i + 1, real + i, (size_t)(plen - i + 1));
		else if (i >= plen)
			real[i + 1] = 0;
		real[i] = (char)sg->WorkBuffer[i];
		sg->WorkBuffer[i] = '*';
		break;
	case EO_DELBACKWARD:
	case EO_DELFORWARD:
		if (len < plen && pos <= plen)
			memmove(real + pos, real + pos + (plen - len), (size_t)(len - pos + 1));
		break;
	case EO_CLEAR:
		real[0] = 0;
		break;
	default:
		break;
	}
	real[len < 127 ? len : 127] = 0;
	return 1;
}

static void trim(char *s)
{
	size_t l = strlen(s), i = 0;
	while (l && (s[l - 1] == ' ' || s[l - 1] == '\t'))
		s[--l] = 0;
	while (s[i] == ' ' || s[i] == '\t')
		i++;
	if (i)
		memmove(s, s + i, l - i + 1);
}

static int textw_max(const int *ids, int n)
{
	int i, w = 0;
	for (i = 0; i < n; i++)
		w = LN_MAX(w, lp_textw(S(ids[i])));
	return w;
}

/* ================================================== user (name + password) */

enum { U_NAME = 1, U_PASS, U_REPEAT, U_OK, U_CANCEL };
static Form uf;
static char u_name[64];
static int u_new;

static int u_build(void)
{
	static const int lab[] = { MSG_USER, MSG_PASSWORD, MSG_PW_REPEAT };
	struct Gadget *g;
	int lw = textw_max(lab, 3) + 2 * lp_cw, fw = 24 * lp_cw, x0 = lp_scr->WBorLeft + 8 + lw;
	int y = lp_scr->WBorTop + lp_scr->Font->ta_YSize + 1 + 5, bw, i, k;
	f_begin(&uf, &g);
	g = f_str(&uf, g, U_NAME, S(MSG_USER), u_name, 63, x0, y, fw, !u_new, NULL);
	y += lp_ystep;
	for (k = 0; k < 2; k++) {
		for (i = 0; pw_real[k][i] && i < 127; i++)
			pw_shown[k][i] = '*';
		pw_shown[k][i] = 0;
		pw_hook[k].h_Entry = (HOOKFUNC)HookEntry;
		pw_hook[k].h_SubEntry = (HOOKFUNC)pw_func;
		g = f_str(&uf, g, k ? U_REPEAT : U_PASS, S(k ? MSG_PW_REPEAT : MSG_PASSWORD), pw_shown[k], 127, x0, y, fw, 0,
		          &pw_hook[k]);
		y += lp_ystep;
	}
	bw = LN_MAX(lp_textw(S(MSG_OK)), lp_textw(S(MSG_CANCEL))) + 4 * lp_cw;
	g = f_btn(&uf, g, U_OK, S(MSG_OK), lp_scr->WBorLeft + 8, y + 3, bw, 0);
	g = f_btn(&uf, g, U_CANCEL, S(MSG_CANCEL), x0 + fw - bw, y + 3, bw, 0);
	return f_end(&uf, g);
}

static int u_handler(int id, UWORD code)
{
	(void)code;
	if (id == U_CANCEL)
		return -1;
	if (id != U_OK)
		return 0;
	if (u_new) {
		ln_strlcpy(u_name, lp_gstr(uf.gad[U_NAME]), sizeof(u_name));
		trim(u_name);
	}
	if (!u_name[0] || strchr(u_name, ' ') || strchr(u_name, '@') || strchr(u_name, '\\') || strchr(u_name, '"')) {
		lp_message(uf.win, "%s", S(MSG_BAD_USERNAME));
		return 0;
	}
	if (u_new && ln_conf_find_user(&lp_conf, u_name)) {
		lp_message(uf.win, S(MSG_DUP_USER), u_name);
		return 0;
	}
	if (!pw_real[0][0]) {
		lp_message(uf.win, "%s", S(MSG_PW_EMPTY));
		ActivateGadget(uf.gad[U_PASS], uf.win, NULL);
		return 0;
	}
	if (strcmp(pw_real[0], pw_real[1])) {
		lp_message(uf.win, "%s", S(MSG_PW_MISMATCH));
		pw_real[1][0] = 0;
		u_build();
		ActivateGadget(uf.gad[U_REPEAT], uf.win, NULL);
		return 0;
	}
	return 1;
}

/* name == NULL: a new user. 1 = changed */
static int edit_user(struct Window *parent, const char *name)
{
	int r = 0, w, h;
	char title[100];
	u_new = name == NULL;
	ln_strlcpy(u_name, name ? name : "", sizeof(u_name));
	memset(pw_real, 0, sizeof(pw_real));
	if (u_build() < 0)
		goto out;
	{
		static const int lab[] = { MSG_USER, MSG_PASSWORD, MSG_PW_REPEAT };
		w = textw_max(lab, 3) + 2 * lp_cw + 24 * lp_cw + 16;
	}
	h = 3 * lp_ystep + 3 + lp_rowh + 5 + 5;
	if (name)
		ln_snprintf(title, sizeof(title), S(MSG_USR_PW_TITLE), name);
	else
		ln_strlcpy(title, S(MSG_USR_NEW_TITLE), sizeof(title));
	uf.win = lp_window(parent, title, w, h, uf.glist,
	                   BUTTONIDCMP | STRINGIDCMP | IDCMP_CLOSEWINDOW | IDCMP_REFRESHWINDOW | IDCMP_VANILLAKEY);
	if (!uf.win) {
		lp_message(parent, "%s", S(MSG_ERR_WINDOW));
		goto out;
	}
	GT_RefreshWindow(uf.win, NULL);
	ActivateGadget(uf.gad[u_new ? U_NAME : U_PASS], uf.win, NULL);
	if (f_loop(&uf, u_handler) > 0) {
		if (ln_conf_put_user(&lp_conf, u_name, pw_real[0]) != LN_OK)
			lp_message(parent, "%s", S(MSG_ERR_FULL2));
		else
			r = 1;
	}
out:
	f_free(&uf);
	ln_wipe(pw_real, sizeof(pw_real));
	ln_wipe(pw_shown, sizeof(pw_shown));
	return r;
}

/* ============================================================= users list */

enum { L_LIST = 1, L_ADD, L_PASS, L_REMOVE, L_OK };
static Form lf;
static LpList ulist;
static int usel = -1;

static void users_fill(void)
{
	int i;
	lp_list_clear(&ulist);
	for (i = 0; i < lp_conf.nusers; i++)
		lp_list_add(&ulist, "%s", lp_conf.user[i].name);
	if (usel >= lp_conf.nusers)
		usel = lp_conf.nusers - 1;
}

static int users_w(void)
{
	static const int b[] = { MSG_ADD, MSG_USR_PASSWORD, MSG_REMOVE };
	int i, w = 0;
	for (i = 0; i < 3; i++)
		w += lp_textw(S(b[i])) + 2 * lp_cw + 6;
	return LN_MAX(w, 32 * lp_fcw + 24);
}

static int users_build(void)
{
	struct Gadget *g;
	int x0 = lp_scr->WBorLeft + 8, y = lp_scr->WBorTop + lp_scr->Font->ta_YSize + 1 + 5, w = users_w(), x, bw;
	int lh = 6 * lp_lh + 4;
	users_fill();
	f_begin(&lf, &g);
	g = f_list(&lf, g, L_LIST, &ulist, usel, x0, y, w, lh);
	y += lh + 3;
	x = x0;
	bw = lp_textw(S(MSG_ADD)) + 2 * lp_cw;
	g = f_btn(&lf, g, L_ADD, S(MSG_ADD), x, y, bw, lp_conf.nusers >= LN_CONF_MAX_USERS);
	x += bw + 6;
	bw = lp_textw(S(MSG_USR_PASSWORD)) + 2 * lp_cw;
	g = f_btn(&lf, g, L_PASS, S(MSG_USR_PASSWORD), x, y, bw, usel < 0);
	x += bw + 6;
	bw = lp_textw(S(MSG_REMOVE)) + 2 * lp_cw;
	g = f_btn(&lf, g, L_REMOVE, S(MSG_REMOVE), x0 + w - bw, y, bw, usel < 0);
	y += lp_ystep + 2;
	bw = lp_textw(S(MSG_OK)) + 4 * lp_cw;
	g = f_btn(&lf, g, L_OK, S(MSG_OK), x0 + (w - bw) / 2, y, bw, 0);
	return f_end(&lf, g);
}

static int users_handler(int id, UWORD code)
{
	switch (id) {
	case L_LIST:
		usel = (int)code;
		users_build();
		break;
	case L_ADD:
		if (edit_user(lf.win, NULL)) {
			usel = lp_conf.nusers - 1;
			users_build();
		}
		break;
	case L_PASS:
		if (usel >= 0)
			edit_user(lf.win, lp_conf.user[usel].name);
		break;
	case L_REMOVE:
		if (usel >= 0 && lp_request(lf.win, S(MSG_REQ_REMOVE), S(MSG_ASK_DELUSER), lp_conf.user[usel].name)) {
			ln_conf_remove_user(&lp_conf, lp_conf.user[usel].name);
			users_build();
		}
		break;
	case L_OK:
		return 1;
	}
	return 0;
}

static void users_window(struct Window *parent)
{
	int w = users_w() + 16, h = 6 * lp_lh + 4 + 3 + 2 * lp_ystep + 2 + 5 + 5;
	struct Requester rq;
	if (lp_list_init(&ulist, LN_CONF_MAX_USERS) < 0)
		return;
	usel = -1;
	lp_block(parent, &rq);
	if (users_build() == 0) {
		lf.win = lp_window(parent, S(MSG_USERS_TITLE), w, h, lf.glist,
		                   BUTTONIDCMP | LISTVIEWIDCMP | IDCMP_CLOSEWINDOW | IDCMP_REFRESHWINDOW | IDCMP_VANILLAKEY);
		if (lf.win) {
			GT_RefreshWindow(lf.win, NULL);
			f_loop(&lf, users_handler);
		} else
			lp_message(parent, "%s", S(MSG_ERR_WINDOW));
	}
	f_free(&lf);
	lp_list_free(&ulist);
	lp_unblock(parent, &rq);
}

/* ===================================================== a shared folder */

enum { E_NAME = 1, E_PATH, E_CHOOSE, E_COMMENT, E_USERS, E_RO, E_GUEST, E_OK, E_CANCEL };
static Form ef;
static LnExport ex;
static int ex_index;

static int ed_label_w(void)
{
	static const int lab[] = { MSG_SH_NAME, MSG_SH_PATH, MSG_SH_COMMENT, MSG_SH_USERS };
	return textw_max(lab, 4) + 2 * lp_cw;
}

static int ed_w(void)
{
	return ed_label_w() + 34 * lp_cw + 16;
}

static void ed_harvest(void)
{
	if (!ef.gad[E_NAME])
		return;
	ln_strlcpy(ex.name, lp_gstr(ef.gad[E_NAME]), sizeof(ex.name));
	ln_strlcpy(ex.path, lp_gstr(ef.gad[E_PATH]), sizeof(ex.path));
	ln_strlcpy(ex.comment, lp_gstr(ef.gad[E_COMMENT]), sizeof(ex.comment));
	ln_strlcpy(ex.users, lp_gstr(ef.gad[E_USERS]), sizeof(ex.users));
	trim(ex.name);
	trim(ex.path);
	trim(ex.users);
}

static int ed_build(void)
{
	struct Gadget *g;
	int lw = ed_label_w(), fw = 34 * lp_cw, x0 = lp_scr->WBorLeft + 8, xf = x0 + lw, bw, cw;
	int y = lp_scr->WBorTop + lp_scr->Font->ta_YSize + 1 + 5;
	f_begin(&ef, &g);
	g = f_str(&ef, g, E_NAME, S(MSG_SH_NAME), ex.name, 31, xf, y, fw, 0, NULL);
	y += lp_ystep;
	cw = lp_textw(S(MSG_CHOOSE)) + 2 * lp_cw;
	g = f_str(&ef, g, E_PATH, S(MSG_SH_PATH), ex.path, 255, xf, y, fw - cw - 4, 0, NULL);
	g = f_btn(&ef, g, E_CHOOSE, S(MSG_CHOOSE), xf + fw - cw, y, cw, 0);
	y += lp_ystep;
	g = f_str(&ef, g, E_COMMENT, S(MSG_SH_COMMENT), ex.comment, 63, xf, y, fw, 0, NULL);
	y += lp_ystep;
	g = f_str(&ef, g, E_USERS, S(MSG_SH_USERS), ex.users, 127, xf, y, fw, 0, NULL);
	y += lp_ystep;
	g = f_cb(&ef, g, E_GUEST, S(MSG_SH_GUEST), ex.guest, xf, y);
	y += lp_ystep;
	g = f_cb(&ef, g, E_RO, S(MSG_READONLY), ex.readonly, xf, y);
	y += lp_ystep + 3;
	bw = LN_MAX(lp_textw(S(MSG_OK)), lp_textw(S(MSG_CANCEL))) + 4 * lp_cw;
	g = f_btn(&ef, g, E_OK, S(MSG_OK), x0, y, bw, 0);
	g = f_btn(&ef, g, E_CANCEL, S(MSG_CANCEL), xf + fw - bw, y, bw, 0);
	return f_end(&ef, g);
}

static int choose_folder(struct Window *w, char *path, size_t n)
{
	struct Library *AslBase = OpenLibrary((STRPTR)"asl.library", 38);
	struct FileRequester *fr;
	struct TagItem t[7];
	int ok = 0;
	if (!AslBase)
		return 0;
	t[0].ti_Tag = ASLFR_Window; t[0].ti_Data = (ULONG)w;
	t[1].ti_Tag = ASLFR_TitleText; t[1].ti_Data = (ULONG)S(MSG_ASL_FOLDER);
	t[2].ti_Tag = ASLFR_InitialDrawer; t[2].ti_Data = (ULONG)(path[0] ? path : "SYS:");
	t[3].ti_Tag = ASLFR_DrawersOnly; t[3].ti_Data = TRUE;
	t[4].ti_Tag = ASLFR_SleepWindow; t[4].ti_Data = TRUE;
	t[5].ti_Tag = ASLFR_RejectIcons; t[5].ti_Data = TRUE;
	t[6].ti_Tag = TAG_DONE;
	fr = AllocAslRequest(ASL_FileRequest, t);
	if (fr && AslRequest(fr, NULL) && fr->fr_Drawer && fr->fr_Drawer[0]) {
		ln_strlcpy(path, (const char *)fr->fr_Drawer, n);
		ok = 1;
	}
	if (fr)
		FreeAslRequest(fr);
	CloseLibrary(AslBase);
	return ok;
}

/* the name of the folder at the end of a path ("DH0:Work/Pics" -> "Pics", "Work:" -> "Work") */
static void name_from_path(const char *p, char *out, size_t n)
{
	const char *s = strrchr(p, '/'), *c = strrchr(p, ':');
	size_t l;
	if (s && s[1])
		ln_strlcpy(out, s + 1, n);
	else if (c && c[1])
		ln_strlcpy(out, c + 1, n);
	else {
		l = c ? (size_t)(c - p) : strlen(p);
		if (l >= n)
			l = n - 1;
		memcpy(out, p, l);
		out[l] = 0;
	}
}

static int folder_ok(const char *p)
{
	BPTR l;
	struct FileInfoBlock *fib;
	int r = 0;
	struct Process *me = (struct Process *)FindTask(NULL);
	APTR win = me->pr_WindowPtr;
	if (!p[0])
		return 0;
	me->pr_WindowPtr = (APTR)-1;
	l = Lock((STRPTR)p, SHARED_LOCK);
	me->pr_WindowPtr = win;
	if (!l)
		return 0;
	fib = AllocDosObject(DOS_FIB, NULL);
	if (fib && Examine(l, fib))
		r = fib->fib_DirEntryType > 0;
	if (fib)
		FreeDosObject(DOS_FIB, fib);
	UnLock(l);
	return r;
}

static int share_name_ok(const char *n)
{
	size_t l = strlen(n);
	if (!l || l > 31)
		return 0;
	for (; *n; n++)
		if (strchr("\\/:*?\"<>|[];=,+", *n) || (u8)*n < 32)
			return 0;
	return 1;
}

static int ed_handler(int id, UWORD code)
{
	(void)code;
	switch (id) {
	case E_CHOOSE:
		ed_harvest();
		if (choose_folder(ef.win, ex.path, sizeof(ex.path))) {
			if (!ex.name[0])
				name_from_path(ex.path, ex.name, sizeof(ex.name));
			ed_build();
		}
		break;
	case E_GUEST: ed_harvest(); ex.guest = !ex.guest; if (code == 0xffff) ed_build(); break;
	case E_RO: ed_harvest(); ex.readonly = !ex.readonly; if (code == 0xffff) ed_build(); break;
	case E_CANCEL:
		return -1;
	case E_OK: {
		LnExport *o;
		ed_harvest();
		if (!share_name_ok(ex.name)) {
			lp_message(ef.win, "%s", S(MSG_BAD_SHNAME));
			ActivateGadget(ef.gad[E_NAME], ef.win, NULL);
			return 0;
		}
		o = ln_conf_find_export(&lp_conf, ex.name);
		if (o && (int)(o - lp_conf.export_) != ex_index) {
			lp_message(ef.win, S(MSG_DUP_SHARE), ex.name);
			return 0;
		}
		if (!folder_ok(ex.path)) {
			lp_message(ef.win, S(MSG_BAD_FOLDER), ex.path);
			ActivateGadget(ef.gad[E_PATH], ef.win, NULL);
			return 0;
		}
		if (!ex.guest && !lp_conf.nusers)
			lp_message(ef.win, S(MSG_NOBODY), ex.name);
		return 1;
	}
	}
	return 0;
}

/* index -1: a new one. 1 = OK */
static int edit_export(struct Window *parent, int index)
{
	int r = 0, w = ed_w(), h = 6 * lp_ystep + 3 + lp_rowh + 5 + 5;
	struct Requester rq;
	ex_index = index;
	if (index >= 0)
		ex = lp_conf.export_[index];
	else
		memset(&ex, 0, sizeof(ex));
	lp_block(parent, &rq);
	if (ed_build() == 0) {
		ef.win = lp_window(parent, S(index < 0 ? MSG_SH_NEW_TITLE : MSG_SH_EDIT_TITLE), w, h, ef.glist,
		                   BUTTONIDCMP | STRINGIDCMP | CHECKBOXIDCMP | IDCMP_CLOSEWINDOW | IDCMP_REFRESHWINDOW |
		                   IDCMP_VANILLAKEY);
		if (ef.win) {
			GT_RefreshWindow(ef.win, NULL);
			if (index < 0)
				ActivateGadget(ef.gad[E_NAME], ef.win, NULL);
			if (f_loop(&ef, ed_handler) > 0) {
				if (index >= 0)
					lp_conf.export_[index] = ex;
				else if (ln_conf_put_export(&lp_conf, &ex) != LN_OK)
					lp_message(parent, "%s", S(MSG_ERR_FULL2));
				r = 1;
			}
		} else
			lp_message(parent, "%s", S(MSG_ERR_WINDOW));
	}
	f_free(&ef);
	lp_unblock(parent, &rq);
	return r;
}

/* ================================================== the Sharing window */

enum { S_NAME = 1, S_GROUP, S_LIST, S_ADD, S_EDIT, S_REMOVE, S_USERS, S_AUTO, S_STATE, S_START, S_OK, S_CANCEL };
static Form sf;
static LpList elist;
static int esel = -1, running;
static char header[100], state[120];
static char s_name[16], s_group[16];

static void access_text(const LnExport *e, char *b, size_t n)
{
	ln_snprintf(b, n, "%s%s%s", S(e->readonly ? MSG_ACC_RO : MSG_ACC_RW), e->guest ? ", " : "",
	            e->guest ? S(MSG_ACC_GUEST) : "");
	if (e->users[0]) {
		ln_strlcat(b, ", ", n);
		ln_strlcat(b, e->users, n);
	}
}

static void s_fill(void)
{
	int i;
	char acc[100];
	lp_list_clear(&elist);
	for (i = 0; i < lp_conf.nexports; i++) {
		const LnExport *e = &lp_conf.export_[i];
		access_text(e, acc, sizeof(acc));
		lp_list_add(&elist, "%-14.14s %-26.26s %.22s", e->name, e->path, acc);
	}
	if (esel >= lp_conf.nexports)
		esel = lp_conf.nexports - 1;
	running = ln_amiga_server_running();
	ln_strlcpy(state, S(!lp_conf.nexports && !running ? MSG_SH_EMPTY : running ? MSG_SRV_RUNNING : MSG_SRV_STOPPED),
	           sizeof(state));
}

static int s_listw(void)
{
	return 64 * lp_fcw + 24;
}

static int s_btnrow_w(void)
{
	static const int b[] = { MSG_ADD, MSG_EDIT, MSG_REMOVE, MSG_USERS_BTN };
	int i, w = 0;
	for (i = 0; i < 4; i++)
		w += lp_textw(S(b[i])) + 2 * lp_cw + 6;
	return w + 26 + lp_cw + lp_textw(S(MSG_AUTOSTART));
}

void lp_sharing_size(int *w, int *h)
{
	*w = LN_MAX(s_listw(), s_btnrow_w()) + 16;
	*h = lp_ystep + lp_lh + 2 + 6 * lp_lh + 4 + 3 + 2 * lp_ystep + 9 + lp_rowh + 5 + 5;
}

static int s_build(void)
{
	struct Gadget *g;
	int x0 = lp_scr->WBorLeft + 8, y = lp_scr->WBorTop + lp_scr->Font->ta_YSize + 1 + 5, w, x, bw, lh, sw, gw, l1, l2;
	int iw, ih;
	lp_sharing_size(&iw, &ih);
	w = iw - 16;
	s_fill();
	ln_snprintf(header, sizeof(header), "%-14.14s %-26.26s %.22s", S(MSG_HDR_SHARE), S(MSG_HDR_FOLDER),
	            S(MSG_HDR_ACCESS));
	f_begin(&sf, &g);
	/* computer name, workgroup */
	l1 = lp_textw(S(MSG_SRV_NAME)) + 2 * lp_cw;
	l2 = lp_textw(S(MSG_SRV_GROUP)) + 2 * lp_cw;
	sw = 16 * lp_cw;
	gw = 16 * lp_cw;
	g = f_str(&sf, g, S_NAME, S(MSG_SRV_NAME), s_name, 15, x0 + l1, y, sw, 0, NULL);
	g = f_str(&sf, g, S_GROUP, S(MSG_SRV_GROUP), s_group, 15, x0 + w - gw, y, gw, 0, NULL);
	(void)l2;
	y += lp_ystep;
	g = f_text(&sf, g, LP_ID_FIXED, header, x0, y, w, 1);
	y += lp_lh + 2;
	lh = 6 * lp_lh + 4;
	g = f_list(&sf, g, S_LIST, &elist, esel, x0, y, w, lh);
	y += lh + 3;
	/* Add, Edit, Remove, Users... and Start at boot */
	x = x0;
	bw = lp_textw(S(MSG_ADD)) + 2 * lp_cw;
	g = f_btn(&sf, g, S_ADD, S(MSG_ADD), x, y, bw, lp_conf.nexports >= LN_CONF_MAX_EXPORTS);
	x += bw + 6;
	bw = lp_textw(S(MSG_EDIT)) + 2 * lp_cw;
	g = f_btn(&sf, g, S_EDIT, S(MSG_EDIT), x, y, bw, esel < 0);
	x += bw + 6;
	bw = lp_textw(S(MSG_REMOVE)) + 2 * lp_cw;
	g = f_btn(&sf, g, S_REMOVE, S(MSG_REMOVE), x, y, bw, esel < 0);
	x += bw + 6;
	bw = lp_textw(S(MSG_USERS_BTN)) + 2 * lp_cw;
	g = f_btn(&sf, g, S_USERS, S(MSG_USERS_BTN), x, y, bw, 0);
	g = f_cb(&sf, g, S_AUTO, S(MSG_AUTOSTART), lp_conf.server.autostart, x0 + w - 26 - lp_cw - lp_textw(S(MSG_AUTOSTART)), y);
	y += lp_ystep + 3;
	/* server state and Start/Stop */
	bw = LN_MAX(lp_textw(S(MSG_SRV_START)), lp_textw(S(MSG_SRV_STOP))) + 2 * lp_cw;
	g = f_text(&sf, g, S_STATE, state, x0, y, w - bw - 6, 0);
	g = f_btn(&sf, g, S_START, S(running ? MSG_SRV_STOP : MSG_SRV_START), x0 + w - bw, y, bw, 0);
	y += lp_ystep + 6;
	bw = LN_MAX(lp_textw(S(MSG_OK)), lp_textw(S(MSG_CANCEL))) + 4 * lp_cw;
	g = f_btn(&sf, g, S_OK, S(MSG_OK), x0, y, bw, 0);
	g = f_btn(&sf, g, S_CANCEL, S(MSG_CANCEL), x0 + w - bw, y, bw, 0);
	return f_end(&sf, g);
}

static void s_harvest(void)
{
	if (!sf.gad[S_NAME])
		return;
	ln_strlcpy(s_name, lp_gstr(sf.gad[S_NAME]), sizeof(s_name));
	ln_strlcpy(s_group, lp_gstr(sf.gad[S_GROUP]), sizeof(s_group));
	trim(s_name);
	trim(s_group);
}

static int s_handler(int id, UWORD code)
{
	switch (id) {
	case S_LIST:
		s_harvest();
		esel = (int)code;
		s_build();
		break;
	case S_ADD:
		s_harvest();
		if (lp_conf.nexports < LN_CONF_MAX_EXPORTS && edit_export(sf.win, -1)) {
			esel = lp_conf.nexports - 1;
			s_build();
		}
		break;
	case S_EDIT:
		s_harvest();
		if (esel >= 0 && edit_export(sf.win, esel))
			s_build();
		break;
	case S_REMOVE:
		s_harvest();
		if (esel >= 0 && lp_request(sf.win, S(MSG_REQ_REMOVE), S(MSG_ASK_UNSHARE), lp_conf.export_[esel].name)) {
			ln_conf_remove_export(&lp_conf, lp_conf.export_[esel].name);
			s_build();
		}
		break;
	case S_USERS:
		s_harvest();
		users_window(sf.win);
		s_build();
		break;
	case S_AUTO:
		s_harvest();
		lp_conf.server.autostart = !lp_conf.server.autostart;
		if (code == 0xffff)
			s_build();
		break;
	case S_START: {
		struct Requester rq;
		int i, r = LN_OK;
		s_harvest();
		ln_strlcpy(lp_conf.server.name, s_name, sizeof(lp_conf.server.name));
		ln_strlcpy(lp_conf.server.workgroup, s_group, sizeof(lp_conf.server.workgroup));
		lp_block(sf.win, &rq);
		if (ln_amiga_server_running()) {
			ln_amiga_server_signal(SIGBREAKF_CTRL_C);
			for (i = 0; i < 50 && ln_amiga_server_running(); i++)
				Delay(10);
		} else {
			/* the server reads ENV:, so it must see this list */
			r = ln_amiga_save_conf(&lp_conf, 0);
			if (r == LN_OK)
				r = ln_amiga_server_start();
			for (i = 0; r == LN_OK && i < 50 && !ln_amiga_server_running(); i++)
				Delay(10);
			if (r == LN_OK && !ln_amiga_server_running())
				r = LN_EIO;
		}
		lp_unblock(sf.win, &rq);
		if (r != LN_OK)
			lp_message(sf.win, S(MSG_SRV_START_FAIL), ln_strerror(r));
		s_build();
		break;
	}
	case S_CANCEL:
		return -1;
	case S_OK:
		s_harvest();
		return 1;
	}
	return 0;
}

int lp_sharing(struct Window *parent)
{
	LnConf *keep = AllocVec(sizeof(LnConf), MEMF_ANY);
	int w, h, r = 0;
	struct Requester rq;
	if (!keep || lp_list_init(&elist, LN_CONF_MAX_EXPORTS) < 0) {
		if (keep)
			FreeVec(keep);
		lp_message(parent, "%s", S(MSG_ERR_NOMEM));
		return 0;
	}
	CopyMem(&lp_conf, keep, sizeof(LnConf));      /* Cancel puts it back */
	ln_strlcpy(s_name, lp_conf.server.name[0] ? lp_conf.server.name : ln_hostname(), sizeof(s_name));
	ln_strlcpy(s_group, lp_conf.server.workgroup[0] ? lp_conf.server.workgroup : "WORKGROUP", sizeof(s_group));
	esel = -1;
	lp_sharing_size(&w, &h);
	lp_block(parent, &rq);
	if (s_build() == 0) {
		sf.win = lp_window(parent, S(MSG_SHARING_TITLE), w, h, sf.glist,
		                   BUTTONIDCMP | STRINGIDCMP | CHECKBOXIDCMP | LISTVIEWIDCMP | TEXTIDCMP |
		                   IDCMP_CLOSEWINDOW | IDCMP_REFRESHWINDOW | IDCMP_VANILLAKEY);
		if (sf.win) {
			GT_RefreshWindow(sf.win, NULL);
			r = f_loop(&sf, s_handler) > 0;
		} else
			lp_message(parent, "%s", S(MSG_ERR_WINDOW));
	}
	if (r) {
		ln_strlcpy(lp_conf.server.name, s_name, sizeof(lp_conf.server.name));
		ln_strlcpy(lp_conf.server.workgroup, !ln_strcasecmp(s_group, "WORKGROUP") ? "" : s_group,
		           sizeof(lp_conf.server.workgroup));
		if (!ln_strcasecmp(lp_conf.server.name, ln_hostname()))
			lp_conf.server.name[0] = 0;
	} else
		CopyMem(keep, &lp_conf, sizeof(LnConf));
	ln_wipe(keep, sizeof(LnConf));
	FreeVec(keep);
	f_free(&sf);
	lp_list_free(&elist);
	lp_unblock(parent, &rq);
	return r;
}
