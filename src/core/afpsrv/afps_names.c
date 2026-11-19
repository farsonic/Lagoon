/*
 * Lagoon - the AFP server's names: Mac Roman on the wire, the directory ID table, pathnames.
 *
 * An AFP 2.x client speaks Mac Roman, 31 bytes a name at most, and names every object by a
 * directory ID and a path below it (Inside AppleTalk 13-9 to 13-14). The VFS behind the server
 * speaks UTF-8 paths. This file is the translation: a table that gives each folder (and each file
 * the client has seen) an ID for as long as the server runs, and the two character sets. Names
 * Mac Roman cannot spell, or longer than 31 bytes, are shown mangled, "start#ID", the way
 * Netatalk shows them, and found again by the ID.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "afps_int.h"
#include "../ln_sys.h"
#include "../ln_charset.h"

/* Mac OS Roman, 0x80-0xFF, as Unicode (Apple's ROMAN.TXT; 0xDB is the euro sign since Mac OS
 * 8.5, the currency sign before: either way a name with it round-trips) */
static const u16 mac_roman[128] = {
	0x00C4, 0x00C5, 0x00C7, 0x00C9, 0x00D1, 0x00D6, 0x00DC, 0x00E1,
	0x00E0, 0x00E2, 0x00E4, 0x00E3, 0x00E5, 0x00E7, 0x00E9, 0x00E8,
	0x00EA, 0x00EB, 0x00ED, 0x00EC, 0x00EE, 0x00EF, 0x00F1, 0x00F3,
	0x00F2, 0x00F4, 0x00F6, 0x00F5, 0x00FA, 0x00F9, 0x00FB, 0x00FC,
	0x2020, 0x00B0, 0x00A2, 0x00A3, 0x00A7, 0x2022, 0x00B6, 0x00DF,
	0x00AE, 0x00A9, 0x2122, 0x00B4, 0x00A8, 0x2260, 0x00C6, 0x00D8,
	0x221E, 0x00B1, 0x2264, 0x2265, 0x00A5, 0x00B5, 0x2202, 0x2211,
	0x220F, 0x03C0, 0x222B, 0x00AA, 0x00BA, 0x03A9, 0x00E6, 0x00F8,
	0x00BF, 0x00A1, 0x00AC, 0x221A, 0x0192, 0x2248, 0x2206, 0x00AB,
	0x00BB, 0x2026, 0x00A0, 0x00C0, 0x00C3, 0x00D5, 0x0152, 0x0153,
	0x2013, 0x2014, 0x201C, 0x201D, 0x2018, 0x2019, 0x00F7, 0x25CA,
	0x00FF, 0x0178, 0x2044, 0x20AC, 0x2039, 0x203A, 0xFB01, 0xFB02,
	0x2021, 0x00B7, 0x201A, 0x201E, 0x2030, 0x00C2, 0x00CA, 0x00C1,
	0x00CB, 0x00C8, 0x00CD, 0x00CE, 0x00CF, 0x00CC, 0x00D3, 0x00D4,
	0xF8FF, 0x00D2, 0x00DA, 0x00DB, 0x00D9, 0x0131, 0x02C6, 0x02DC,
	0x00AF, 0x02D8, 0x02D9, 0x02DA, 0x00B8, 0x02DD, 0x02DB, 0x02C7,
};

/* one code point to Mac Roman, -1 if it has none */
static int to_roman(u32 c)
{
	int i;
	if (c == ':')
		return '/';
	if (c < 0x80)
		return c >= 0x20 ? (int)c : -1;  /* control characters are not names */
	if (c == 0x00A4)
		return 0xDB;                     /* the currency sign, where System 7 has it */
	for (i = 0; i < 128; i++)
		if (mac_roman[i] == c)
			return 0x80 + i;
	return -1;
}

int afps_mac_to_utf8(const u8 *mac, size_t n, char *out, size_t max)
{
	size_t o = 0, i;
	for (i = 0; i < n; i++) {
		char e[4];
		u32 c = mac[i] < 0x80 ? (mac[i] == '/' ? (u32)':' : mac[i]) : mac_roman[mac[i] - 0x80];
		int k = ln_utf8_encode(c, e);
		if (o + (size_t)k >= max)
			return -1;
		memcpy(out + o, e, (size_t)k);
		o += (size_t)k;
	}
	out[o] = 0;
	return (int)o;
}

static int hex_suffix(u32 id, char *t)
{
	return ln_snprintf(t, 12, "#%X", (unsigned)id);
}

int afps_to_mac(const char *utf8, u32 id, u8 *out, size_t max)
{
	size_t n = strlen(utf8), i = 0, o = 0;
	int ok = 1, k;
	char sfx[12];
	u8 tmp[256];
	while (i < n) {
		u32 c;
		int r;
		i += (size_t)ln_utf8_decode(utf8 + i, n - i, &c);
		r = to_roman(c);
		if (r < 0) {
			ok = 0;
			r = '_';
		}
		if (o < sizeof tmp)
			tmp[o++] = (u8)r;
	}
	if (ok && o <= AFPS_NAME_MAX && o <= max) {
		memcpy(out, tmp, o);
		return (int)o;
	}
	/* mangled: as much of the name as fits, then #ID */
	k = hex_suffix(id, sfx);
	if ((size_t)k > max)
		return -1;
	if (o > AFPS_NAME_MAX - (size_t)k)
		o = AFPS_NAME_MAX - (size_t)k;
	if (o + (size_t)k > max)
		o = max - (size_t)k;
	memcpy(out, tmp, o);
	memcpy(out + o, sfx, (size_t)k);
	return (int)o + k;
}

u32 afps_mangled_id(const u8 *mac, size_t n)
{
	size_t i = n;
	u32 id = 0;
	while (i > 0 && mac[i - 1] != '#')
		i--;
	if (i == 0 || i == n || n - i > 8)
		return 0;
	for (; i < n; i++) {
		int c = mac[i], v;
		if (c >= '0' && c <= '9') v = c - '0';
		else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
		else return 0;
		id = id << 4 | (u32)v;
	}
	return id;
}

/* ---- the ID table ----
 * Nodes live in pages of AFPS_PAGE, found through a page list that grows by a pointer, so that
 * the table never moves a large block (the Mac bridge's pool is first fit, docs/mac.md "Large
 * folders"). A folder's node stays for as long as the server runs: the client keeps folder IDs.
 * A file's node is only the server's memory of a name, and once more than AFPS_LIVE_FILES files
 * are known the oldest go: a file with a plain Mac name entirely (its slot is used again; the
 * client gets a new file number when it next sees the file, which AFP 2 allows), a file shown
 * mangled down to its parent and its name's hash, so that "start#ID" is found again by listing
 * the folder (afps_names_revive). A file with an open fork is not put away. */
#define NODE(t, id) (&(t)->page[(id) / AFPS_PAGE][(id) % AFPS_PAGE])

static u32 hash(u32 parent, const char *name)
{
	u32 h = parent * 2654435761u;
	for (; *name; name++)
		h = (h ^ (u8)*name) * 16777619u;
	return h % AFPS_HASH;
}

/* a name's own hash, kept for a mangled file put away; never 0 */
u32 afps_names_hash(const char *name)
{
	u32 h = 2166136261u;
	for (; *name; name++)
		h = (h ^ (u8)*name) * 16777619u;
	return h | 1;
}

/* is the name shown "start#ID"? (afps_to_mac with an ID that cannot be mistaken) */
static int mangled(const char *name)
{
	u8 mac[AFPS_NAME_MAX + 1];
	int l = afps_to_mac(name, 0xFFFFFFFFu, mac, AFPS_NAME_MAX);
	return l < 0 || afps_mangled_id(mac, (size_t)l) == 0xFFFFFFFFu;
}

/* a free slot (one given back, else a new one at the end); 0 = out of memory */
static u32 slot(AfpsNames *t)
{
	u32 id;
	if (t->free) {
		id = t->free;
		t->free = NODE(t, id)->hnext;
		memset(NODE(t, id), 0, sizeof(AfpsNode));
		return id;
	}
	if (t->count / AFPS_PAGE >= t->npages) {
		AfpsNode **pl = ln_realloc(t->page, sizeof(AfpsNode *) * t->npages, sizeof(AfpsNode *) * (t->npages + 16));
		if (!pl)
			return 0;
		t->page = pl;
		t->npages += 16;
	}
	if (!t->page[t->count / AFPS_PAGE]) {
		t->page[t->count / AFPS_PAGE] = ln_alloc(sizeof(AfpsNode) * AFPS_PAGE);
		if (!t->page[t->count / AFPS_PAGE])
			return 0;
	}
	return t->count++;
}

int afps_names_init(AfpsNames *t)
{
	memset(t, 0, sizeof *t);
	t->count = 1;                                /* ID 0 is nobody */
	while (t->count < AFPS_FIRST_ID)
		if (!slot(t))
			return LN_ENOMEM;
	t->evict = AFPS_FIRST_ID;
	NODE(t, AFPS_ROOT)->name = ln_strdup("");
	NODE(t, AFPS_ROOT)->parent = AFPS_PARENT_OF_ROOT;
	NODE(t, AFPS_ROOT)->isdir = 1;
	return NODE(t, AFPS_ROOT)->name ? LN_OK : LN_ENOMEM;
}

void afps_names_free(AfpsNames *t)
{
	u32 i;
	for (i = 0; i < t->count; i++)
		ln_free(NODE(t, i)->name);
	for (i = 0; i < t->npages; i++)
		ln_free(t->page[i]);
	ln_free(t->page);
	memset(t, 0, sizeof *t);
}

const AfpsNode *afps_names_node(const AfpsNames *t, u32 id)
{
	return id < t->count && NODE(t, id)->name ? NODE(t, id) : NULL;
}

u32 afps_names_find(const AfpsNames *t, u32 parent, const char *name)
{
	u32 id = t->hash[hash(parent, name)];
	for (; id; id = NODE(t, id)->hnext)
		if (NODE(t, id)->parent == parent && !strcmp(NODE(t, id)->name, name))
			return id;
	return 0;
}

static void link_in(AfpsNames *t, u32 id)
{
	u32 h = hash(NODE(t, id)->parent, NODE(t, id)->name);
	NODE(t, id)->hnext = t->hash[h];
	t->hash[h] = id;
}

/* the chains of mangled files put away, by parent and name hash */
static u32 *away_head(AfpsNames *t, u32 parent, u32 h)
{
	return &t->away[(parent * 2654435761u ^ h) % AFPS_HASH];
}

static void away_unlink(AfpsNames *t, u32 id)
{
	u32 *pp = away_head(t, NODE(t, id)->parent, NODE(t, id)->mark);
	while (*pp && *pp != id)
		pp = &NODE(t, *pp)->hnext;
	if (*pp)
		*pp = NODE(t, id)->hnext;
	NODE(t, id)->hnext = 0;
}

/* a put-away node takes its name back */
static int take_back(AfpsNames *t, u32 id, const char *name)
{
	char *nm = ln_strdup(name);
	if (!nm)
		return 0;
	away_unlink(t, id);
	NODE(t, id)->name = nm;
	NODE(t, id)->mark = t->clock;
	link_in(t, id);
	t->live++;
	return 1;
}

static void unlink_out(AfpsNames *t, u32 id)
{
	u32 *pp = &t->hash[hash(NODE(t, id)->parent, NODE(t, id)->name)];
	while (*pp && *pp != id)
		pp = &NODE(t, *pp)->hnext;
	if (*pp)
		*pp = NODE(t, id)->hnext;
	NODE(t, id)->hnext = 0;
}

/* put files away, the least recently used first, until AFPS_LIVE_FILES are left. A file used
 * in the last AFPS_LIVE_FILES / 2 lookups stays: the caller may still hold its ID */
static void put_away(AfpsNames *t)
{
	u32 tries = t->count;
	while (t->live > AFPS_LIVE_FILES && tries--) {
		u32 id = t->evict;
		AfpsNode *nd;
		if (++t->evict >= t->count)
			t->evict = AFPS_FIRST_ID;            /* round again */
		nd = NODE(t, id);
		if (!nd->name || nd->isdir || nd->pins || t->clock - nd->mark < AFPS_LIVE_FILES / 2)
			continue;
		unlink_out(t, id);
		if (mangled(nd->name)) {
			u32 *head;
			nd->mark = afps_names_hash(nd->name);   /* the parent stays, to be found again */
			ln_free(nd->name);
			nd->name = NULL;
			head = away_head(t, nd->parent, nd->mark);
			nd->hnext = *head;
			*head = id;
		} else {
			ln_free(nd->name);
			memset(nd, 0, sizeof *nd);
			nd->hnext = t->free;                 /* the slot is used again */
			t->free = id;
		}
		t->live--;
	}
}

u32 afps_names_id(AfpsNames *t, u32 parent, const char *name, int isdir)
{
	u32 id = afps_names_find(t, parent, name);
	char *nm;
	t->clock++;
	if (id) {
		NODE(t, id)->mark = t->clock;
		if (isdir >= 0 && NODE(t, id)->isdir != (u8)(isdir > 0)) {
			if (isdir > 0) t->live--; else t->live++;
			NODE(t, id)->isdir = (u8)(isdir > 0);
		}
		return id;
	}
	if (isdir <= 0) {
		/* a mangled file that was put away and is seen again keeps its ID, and so its name */
		u32 h = afps_names_hash(name);
		for (id = *away_head(t, parent, h); id; id = NODE(t, id)->hnext)
			if (NODE(t, id)->parent == parent && NODE(t, id)->mark == h)
				break;
		if (id && mangled(name))
			return take_back(t, id, name) ? (put_away(t), id) : 0;
	}
	nm = ln_strdup(name);
	if (!nm || !(id = slot(t))) {
		ln_free(nm);
		return 0;
	}
	NODE(t, id)->name = nm;
	NODE(t, id)->parent = parent;
	NODE(t, id)->isdir = (u8)(isdir > 0);
	NODE(t, id)->mark = t->clock;
	link_in(t, id);
	if (isdir <= 0) {
		t->live++;
		put_away(t);
	}
	return id;
}

/* a mangled file's node that was put away: is name (in parent) the one it was? Then it is
 * known again, under the same ID */
int afps_names_revive(AfpsNames *t, u32 id, u32 parent, const char *name)
{
	AfpsNode *nd;
	if (id < AFPS_FIRST_ID || id >= t->count)
		return 0;
	nd = NODE(t, id);
	if (nd->name || !nd->mark || nd->parent != parent || nd->mark != afps_names_hash(name) ||
	    afps_names_find(t, parent, name))
		return 0;
	t->clock++;
	return take_back(t, id, name);
}

u32 afps_names_put_away(const AfpsNames *t, u32 id)
{
	return id >= AFPS_FIRST_ID && id < t->count && !NODE(t, id)->name ? NODE(t, id)->mark : 0;
}

void afps_names_pin(AfpsNames *t, u32 id, int by)
{
	if (afps_names_node(t, id))
		NODE(t, id)->pins = (u8)(NODE(t, id)->pins + by);
}

int afps_names_path(const AfpsNames *t, u32 id, char *out, size_t max)
{
	u32 chain[64];
	int depth = 0, i;
	out[0] = 0;
	while (id != AFPS_ROOT) {
		const AfpsNode *nd = afps_names_node(t, id);
		if (!nd || depth == (int)LN_ARRAY_SIZE(chain))
			return LN_ENOENT;
		chain[depth++] = id;
		id = nd->parent;
	}
	for (i = depth - 1; i >= 0; i--)
		if (ln_path_join(out, max, out, NODE(t, chain[i])->name) != LN_OK)
			return LN_ENAMETOOLONG;
	return LN_OK;
}

void afps_names_move(AfpsNames *t, u32 id, u32 parent, const char *name)
{
	char *nn;
	if (!afps_names_node(t, id) || id == AFPS_ROOT)
		return;
	nn = ln_strdup(name);
	if (!nn)
		return;
	unlink_out(t, id);
	ln_free(NODE(t, id)->name);
	NODE(t, id)->name = nn;
	NODE(t, id)->parent = parent;
	link_in(t, id);
}

void afps_names_forget(AfpsNames *t, u32 id)
{
	if (!afps_names_node(t, id) || id == AFPS_ROOT)
		return;
	unlink_out(t, id);
	if (!NODE(t, id)->isdir)
		t->live--;
	ln_free(NODE(t, id)->name);
	NODE(t, id)->name = NULL;
	NODE(t, id)->mark = 0;                       /* gone: not to be found again */
}
