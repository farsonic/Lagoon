/*
 * Lagoon - LagoonPrefs helpers: libraries, locale catalog, fonts and
 * font-sensitive measuring, gadgets, requesters, busy blocking, lists.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdarg.h>
#define LP_STRINGS_ARRAY          /* strings.h: the built-in English table */
#include <libraries/locale.h>
#include <proto/locale.h>
#include <graphics/gfxbase.h>
#include "prefs.h"
#include "ln_net.h"

int ln_vsnprintf(char *buf, size_t n, const char *fmt, va_list ap);

struct IntuitionBase *IntuitionBase;
struct GfxBase *GfxBase;
struct Library *GadToolsBase;
struct LocaleBase *LocaleBase;
static struct Catalog *catalog;

struct Screen *lp_scr;
APTR lp_vi;
struct TextAttr *lp_ta;
struct TextAttr lp_fixta;
int lp_fh, lp_cw, lp_rowh, lp_ystep, lp_lh, lp_fcw;
static struct TextAttr topaz8 = { (STRPTR)"topaz.font", 8, 0, 0 };
static struct TextFont *measure_font;
static struct RastPort measure_rp;
static int net_ok;

/* ---- locale ---- */
void lp_locale_open(const char *language)
{
	LocaleBase = (struct LocaleBase *)OpenLibrary((CONST_STRPTR)"locale.library", 38);
	if (LocaleBase) {
		struct TagItem t[3];
		t[0].ti_Tag = OC_BuiltInLanguage;
		t[0].ti_Data = (ULONG)"english";
		t[1].ti_Tag = language ? OC_Language : TAG_IGNORE;
		t[1].ti_Data = (ULONG)language;
		t[2].ti_Tag = TAG_DONE;
		catalog = OpenCatalogA(NULL, (STRPTR)"LagoonPrefs.catalog", t);
	}
	lp_trace("locale.library %s, catalog %s (%s)", LocaleBase ? "open" : "missing",
	         catalog ? "open" : "not found", language ? language : "Locale prefs");
}

void lp_locale_close(void)
{
	if (LocaleBase) {
		CloseCatalog(catalog);
		CloseLibrary((struct Library *)LocaleBase);
	}
	catalog = NULL;
	LocaleBase = NULL;
}

const char *S(int id)
{
	const char *def = id >= 0 && id < MSG_COUNT ? lp_builtin[id] : "";
	if (catalog)
		return (const char *)GetCatalogStr(catalog, id, (STRPTR)def);
	return def;
}

/* ---- fonts and measuring ---- */
void lp_use_font(struct TextAttr *ta)
{
	struct TextFont *f = OpenFont(ta);
	if (!f) {
		ta = &topaz8;
		f = OpenFont(ta);
	}
	if (measure_font)
		CloseFont(measure_font);
	measure_font = f;
	lp_ta = ta;
	InitRastPort(&measure_rp);
	if (f)
		SetFont(&measure_rp, f);
	lp_fh = f ? f->tf_YSize : 8;
	lp_cw = (TextLength(&measure_rp, (STRPTR)"abcdefghijklmnopqrstuvwxyz", 26) + 25) / 26;
	lp_rowh = lp_fh + 6;
	lp_ystep = lp_rowh + 3;
}

void lp_use_topaz(void)
{
	lp_use_font(&topaz8);
}

int lp_textw(const char *s)
{
	char t[96];
	int i = 0;
	for (; *s && i < (int)sizeof(t) - 1; s++)
		if (*s != '_')
			t[i++] = *s;
	t[i] = 0;
	return TextLength(&measure_rp, (STRPTR)t, (ULONG)i);
}

char lp_key(const char *label)
{
	const char *u = strchr(label, '_');
	unsigned char c = u ? (unsigned char)u[1] : 0;
	if ((c >= 'A' && c <= 'Z') || (c >= 0xc0 && c <= 0xde && c != 0xd7))
		c = (unsigned char)(c + 32);
	return (char)c;
}

int lp_gui_open(const char *pubscreen)
{
	struct TextFont *df;
	IntuitionBase = (struct IntuitionBase *)OpenLibrary((CONST_STRPTR)"intuition.library", 39);
	GfxBase = (struct GfxBase *)OpenLibrary((CONST_STRPTR)"graphics.library", 39);
	GadToolsBase = OpenLibrary((CONST_STRPTR)"gadtools.library", 39);
	if (!IntuitionBase || !GfxBase || !GadToolsBase)
		return -1;
	lp_scr = LockPubScreen((CONST_STRPTR)pubscreen);
	if (!lp_scr && pubscreen)
		lp_scr = LockPubScreen(NULL);
	if (!lp_scr || !(lp_vi = GetVisualInfoA(lp_scr, NULL)))
		return -1;
	/* list columns need a fixed-width font: the system default text font
	 * is one by definition (Font prefs), topaz 8 otherwise */
	df = GfxBase->DefaultFont;
	lp_fixta = topaz8;
	if (df && !(df->tf_Flags & FPF_PROPORTIONAL)) {
		lp_fixta.ta_Name = df->tf_Message.mn_Node.ln_Name;
		lp_fixta.ta_YSize = df->tf_YSize;
		lp_fixta.ta_Style = df->tf_Style;
		lp_fixta.ta_Flags = df->tf_Flags;
	}
	lp_lh = lp_fixta.ta_YSize + 1;
	lp_fcw = df && !(df->tf_Flags & FPF_PROPORTIONAL) ? df->tf_XSize : 8;
	lp_use_font(lp_scr->Font);
	return 0;
}

void lp_gui_close(void)
{
	if (net_ok)
		ln_net_exit();
	net_ok = 0;
	if (measure_font)
		CloseFont(measure_font);
	measure_font = NULL;
	if (lp_vi)
		FreeVisualInfo(lp_vi);
	lp_vi = NULL;
	if (lp_scr)
		UnlockPubScreen(NULL, lp_scr);
	lp_scr = NULL;
	if (GadToolsBase)
		CloseLibrary(GadToolsBase);
	if (GfxBase)
		CloseLibrary((struct Library *)GfxBase);
	if (IntuitionBase)
		CloseLibrary((struct Library *)IntuitionBase);
	GadToolsBase = NULL;
	GfxBase = NULL;
	IntuitionBase = NULL;
}

/* ---- gadgets ---- */
struct Gadget *lp_mk(ULONG kind, struct Gadget *prev, int id, const char *label, ULONG flags,
                     int x, int y, int w, int h, struct TagItem *tags)
{
	struct NewGadget ng;
	memset(&ng, 0, sizeof(ng));
	ng.ng_LeftEdge = (WORD)x;
	ng.ng_TopEdge = (WORD)y;
	ng.ng_Width = (WORD)w;
	ng.ng_Height = (WORD)h;
	ng.ng_GadgetText = (STRPTR)label;
	ng.ng_TextAttr = kind == LISTVIEW_KIND || id == LP_ID_FIXED ? &lp_fixta : lp_ta;
	ng.ng_GadgetID = (UWORD)id;
	ng.ng_Flags = flags;
	ng.ng_VisualInfo = lp_vi;
	return prev ? CreateGadgetA(kind, prev, &ng, tags) : NULL;
}

const char *lp_gstr(struct Gadget *g)
{
	return (const char *)((struct StringInfo *)g->SpecialInfo)->Buffer;
}

/* ---- requesters ---- */
static long vrequest(struct Window *w, const char *buttons, const char *fmt, va_list ap)
{
	struct EasyStruct es;
	char text[600];
	const char *arg = text;
	ln_vsnprintf(text, sizeof(text), fmt, ap);
	if (!IntuitionBase) {
		PutStr((STRPTR)text);
		PutStr((STRPTR)"\n");
		return 0;
	}
	es.es_StructSize = sizeof(es);
	es.es_Flags = 0;
	es.es_Title = (STRPTR)S(MSG_TITLE);
	es.es_TextFormat = (STRPTR)"%s";
	es.es_GadgetFormat = (STRPTR)buttons;
	return EasyRequestArgs(w, &es, NULL, (APTR)&arg);
}

long lp_request(struct Window *w, const char *buttons, const char *fmt, ...)
{
	va_list ap;
	long r;
	va_start(ap, fmt);
	r = vrequest(w, buttons, fmt, ap);
	va_end(ap);
	return r;
}

int lp_debug;

void lp_trace(const char *fmt, ...)
{
	va_list ap;
	char t[160];
	BPTR o;
	if (!lp_debug || !(o = Output()))
		return;
	va_start(ap, fmt);
	ln_vsnprintf(t, sizeof(t) - 1, fmt, ap);
	va_end(ap);
	ln_strlcat(t, "\n", sizeof(t));
	Write(o, t, (LONG)strlen(t));
	Flush(o);
}

void lp_message(struct Window *w, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vrequest(w, S(MSG_REQ_OK), fmt, ap);
	va_end(ap);
}

void lp_block(struct Window *w, struct Requester *rq)
{
	struct TagItem t[3];
	if (!w)
		return;
	InitRequester(rq);
	Request(rq, w);
	t[0].ti_Tag = WA_BusyPointer;
	t[0].ti_Data = TRUE;
	t[1].ti_Tag = WA_PointerDelay;
	t[1].ti_Data = TRUE;
	t[2].ti_Tag = TAG_DONE;
	SetWindowPointerA(w, t);
}

void lp_unblock(struct Window *w, struct Requester *rq)
{
	struct TagItem t[1];
	if (!w)
		return;
	EndRequest(rq, w);
	t[0].ti_Tag = TAG_DONE;
	SetWindowPointerA(w, t);
}

struct Window *lp_window(struct Window *parent, const char *title, int iw, int ih, struct Gadget *gl, ULONG idcmp)
{
	struct TagItem t[18];
	int n = 0, ow = iw + lp_scr->WBorLeft + lp_scr->WBorRight;
	int oh = ih + lp_scr->WBorTop + lp_scr->Font->ta_YSize + 1 + lp_scr->WBorBottom;
	int x, y;
	if (parent) {
		x = parent->LeftEdge + (parent->Width - ow) / 2;
		y = parent->TopEdge + (parent->Height - oh) / 2;
	} else {
		x = (lp_scr->Width - ow) / 2;
		y = lp_scr->BarHeight + 1 + (lp_scr->Height - lp_scr->BarHeight - 1 - oh) / 2;
	}
	if (x + ow > lp_scr->Width) x = lp_scr->Width - ow;
	if (y + oh > lp_scr->Height) y = lp_scr->Height - oh;
	if (x < 0) x = 0;
	if (y < lp_scr->BarHeight + 1 && lp_scr->Height - oh > lp_scr->BarHeight) y = lp_scr->BarHeight + 1;
	if (y < 0) y = 0;
#define TAG(a, b) (t[n].ti_Tag = (a), t[n++].ti_Data = (ULONG)(b))
	TAG(WA_Title, title);
	TAG(WA_ScreenTitle, S(MSG_TITLE));
	TAG(WA_PubScreen, lp_scr);
	TAG(WA_Left, x);
	TAG(WA_Top, y);
	TAG(WA_InnerWidth, iw);
	TAG(WA_InnerHeight, ih);
	TAG(WA_Gadgets, gl);
	TAG(WA_IDCMP, idcmp);
	TAG(WA_DragBar, TRUE);
	TAG(WA_DepthGadget, TRUE);
	TAG(WA_CloseGadget, TRUE);
	TAG(WA_Activate, TRUE);
	TAG(WA_SimpleRefresh, TRUE);
	TAG(WA_AutoAdjust, TRUE);
	TAG(WA_NewLookMenus, TRUE);
	TAG(TAG_DONE, 0);
#undef TAG
	return OpenWindowTagList(NULL, t);
}

/* close a window that shares no port: reply its pending messages first */
void lp_close_window(struct Window *w)
{
	if (w)
		CloseWindow(w);
}

void lp_text(struct Window *w, int x, int y, int wd, const char *s, int pen)
{
	struct RastPort *rp = w->RPort;
	struct TextFont *f = OpenFont(lp_ta);
	struct TextExtent te;
	ULONG len = (ULONG)strlen(s), fit;
	SetAPen(rp, 0);
	RectFill(rp, x, y, x + wd - 1, y + lp_fh);
	if (f)
		SetFont(rp, f);
	SetAPen(rp, pen);
	SetDrMd(rp, JAM1);
	fit = TextFit(rp, (STRPTR)s, len, &te, NULL, 1, wd, lp_fh + 1);
	Move(rp, x, y + rp->TxBaseline);
	Text(rp, (STRPTR)s, fit);
	if (f)
		CloseFont(f);
}

void lp_size(u64 b, char *buf, size_t n)
{
	static const char *const unit[] = { "bytes", "KB", "MB", "GB", "TB", "PB" };
	int u = 0;
	u64 scale = 1;
	while (u < 5 && b >= scale * 1024)
		scale *= 1024, u++;
	if (!u)
		ln_snprintf(buf, n, "%lu %s", (unsigned long)b, unit[0]);
	else {
		u64 tenths = (b * 10 + scale / 2) / scale;
		ln_snprintf(buf, n, "%lu.%lu %s", (unsigned long)(tenths / 10), (unsigned long)(tenths % 10), unit[u]);
	}
}

/* ---- lists ---- */
int lp_list_init(LpList *l, int max)
{
	memset(l, 0, sizeof(*l));
	l->nodes = AllocVec(sizeof(struct Node) * (ULONG)max, MEMF_ANY | MEMF_CLEAR);
	l->text = AllocVec((ULONG)(LP_LINE * max), MEMF_ANY | MEMF_CLEAR);
	l->max = max;
	lp_list_clear(l);
	return l->nodes && l->text ? 0 : -1;
}

void lp_list_clear(LpList *l)
{
	l->list.lh_Head = (struct Node *)&l->list.lh_Tail;
	l->list.lh_Tail = NULL;
	l->list.lh_TailPred = (struct Node *)&l->list.lh_Head;
	l->n = 0;
}

int lp_list_add(LpList *l, const char *fmt, ...)
{
	va_list ap;
	char *t;
	if (!l->nodes || !l->text || l->n >= l->max)
		return -1;
	t = l->text + LP_LINE * l->n;
	va_start(ap, fmt);
	ln_vsnprintf(t, LP_LINE, fmt, ap);
	va_end(ap);
	l->nodes[l->n].ln_Name = t;
	AddTail(&l->list, &l->nodes[l->n]);
	return l->n++;
}

void lp_list_free(LpList *l)
{
	if (l->nodes)
		FreeVec(l->nodes);
	if (l->text)
		FreeVec(l->text);
	memset(l, 0, sizeof(*l));
}

int lp_device_mounted(const char *name)
{
	struct DosList *dl;
	int found;
	if (!name[0])
		return 0;
	dl = LockDosList(LDF_DEVICES | LDF_READ);
	found = FindDosEntry(dl, (STRPTR)name, LDF_DEVICES) != NULL;
	UnLockDosList(LDF_DEVICES | LDF_READ);
	return found;
}

int lp_net(struct Window *w)
{
	if (net_ok)
		return LN_OK;
	if (ln_net_init() != LN_OK) {
		lp_message(w, "%s", S(MSG_NO_NETWORK));
		return LN_ENONET;
	}
	net_ok = 1;
	return LN_OK;
}
