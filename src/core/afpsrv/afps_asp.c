/*
 * Lagoon - the server end of the AppleTalk Session Protocol, for the AFP server.
 *
 * ASP (Inside AppleTalk, second edition, chapter 11) carries AFP over ATP transactions. Its
 * header is the four ATP user bytes: the function, then a session ID and a sequence number or
 * the like. The server's part:
 *   GetStatus  (ALO)  answered with the status block (FPGetSrvrInfo's reply), no session needed
 *   OpenSess   (XO)   a session: the workstation's session socket (WSS) is saved, the reply
 *                     names the session ID and the server's session socket (SSS)
 *   Command    (XO)   one AFP call, its result in the reply's user bytes
 *   Write      (XO)   an AFP call with data (FPWrite, FPAddIcon): the server asks for the data
 *                     with a WriteContinue request to the WSS, then answers the Write
 *   Tickle     (ALO)  every 30 seconds from each end, never answered; two minutes without a
 *                     packet from the other end and a session is dead
 *   CloseSess  (ALO)  either end; answered at once
 *   Attention  (ALO)  server to workstation: "the server is going down"
 * Here one ATP socket is both the session listening socket and every session's SSS, as the
 * protocol allows: requests on it are told apart by the session ID in the user bytes.
 *
 * ATP's exactly-once transactions keep the response for retransmission until the requester
 * releases it: that is the transport's work (the Mac's .ATP does it). A request repeated before
 * the server answered it is dropped here, by its source and transaction ID.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "afps_int.h"
#include "../ln_sys.h"

static void user4(u8 u[4], unsigned a, unsigned b, unsigned c, unsigned d)
{
	u[0] = (u8)a; u[1] = (u8)b; u[2] = (u8)c; u[3] = (u8)d;
}

size_t afps_status(const AfpsServer *s, u8 *out, size_t max)
{
	/* FPGetSrvrInfo's reply (Inside AppleTalk 13-63): four offsets and the flags, the server
	 * name, then the machine type, the AFP versions and the login methods the offsets point at.
	 * No volume icon (offset 0): the Chooser draws AppleShare's own. */
	AfpBuf b;
	size_t o_mach, o_ver, o_uam;
	afp_b_init(&b, out, max);
	afp_b_u16(&b, 0);
	afp_b_u16(&b, 0);
	afp_b_u16(&b, 0);
	afp_b_u16(&b, 0);
	afp_b_u16(&b, 0);                            /* flags: nothing beyond AFP 2.1's basics */
	afp_b_pstr(&b, s->cfg.server);
	afp_b_pad(&b);
	o_mach = b.len;
	afp_b_pstr(&b, s->cfg.machine[0] ? s->cfg.machine : "Lagoon");
	o_ver = b.len;
	afp_b_u8(&b, 2);
	afp_b_pstr(&b, "AFPVersion 2.0");
	afp_b_pstr(&b, "AFPVersion 2.1");
	o_uam = b.len;
	afp_b_u8(&b, (unsigned)(!s->cfg.no_guest + (s->cfg.user[0] != 0)));
	if (!s->cfg.no_guest)
		afp_b_pstr(&b, "No User Authent");
	if (s->cfg.user[0])
		afp_b_pstr(&b, "Cleartxt Passwrd");
	if (b.err)
		return 0;
	ln_put_be16(out, (u16)o_mach);
	ln_put_be16(out + 2, (u16)o_ver);
	ln_put_be16(out + 4, (u16)o_uam);
	return b.len;
}

AfpsServer *afps_new(const AfpsConfig *cfg, const LnOps *ops, LnFs *fs, const AsTransport *t)
{
	AfpsServer *s = ln_alloc(sizeof *s);
	if (!s)
		return NULL;
	s->cfg = *cfg;
	s->ops = ops;
	s->fs = fs;
	s->t = *t;
	s->next_sid = 1;
	if (afps_names_init(&s->names) != LN_OK) {
		ln_free(s);
		return NULL;
	}
	return s;
}

static AfpsSess *sess_of(AfpsServer *s, unsigned id)
{
	int i;
	for (i = 0; i < AFPS_MAXSESS; i++)
		if (s->sess[i].used && s->sess[i].id == id)
			return &s->sess[i];
	return NULL;
}

int afps_sessions(const AfpsServer *s)
{
	int i, n = 0;
	for (i = 0; i < AFPS_MAXSESS; i++)
		n += s->sess[i].used;
	return n;
}

static void sess_close(AfpsServer *s, AfpsSess *se, int tell)
{
	int i;
	u8 u[4];
	u32 id;
	if (se->tickle)
		s->t.cancel(s->t.ud, se->tickle);
	for (i = 0; i < AFPS_MAXWRITE; i++)
		if (s->wr[i].used && s->wr[i].sess == se->id) {
			s->t.cancel(s->t.ud, s->wr[i].reqid);
			s->wr[i].used = 0;
		}
	afps_afp_close_session(s, se);
	if (tell) {                                  /* CloseSess to the WSS, as a courtesy */
		user4(u, SP_CLOSESESS, se->id, 0, 0);
		s->t.request(s->t.ud, se->wss, u, NULL, 0, 0, 1, 2, 2, &id);
	}
	LN_LOG(1, "afpsrv: session %u closed", se->id);
	memset(se, 0, sizeof *se);
}

void afps_free(AfpsServer *s)
{
	int i;
	u8 u[4];
	u32 id;
	if (!s)
		return;
	for (i = 0; i < AFPS_MAXSESS; i++)
		if (s->sess[i].used) {
			/* AFP's attention code: bit 15, the server shuts down, in 0 minutes */
			user4(u, SP_ATTENTION, s->sess[i].id, 0x80, 0x00);
			s->t.request(s->t.ud, s->sess[i].wss, u, NULL, 0, 0, 1, 2, 2, &id);
			sess_close(s, &s->sess[i], 1);
		}
	afps_afp_free(s);
	afps_names_free(&s->names);
	ln_free(s);
}

/* has this exactly-once request been seen already? (else remember it) */
static int seen(AfpsServer *s, const AsReq *q)
{
	unsigned i;
	for (i = 0; i < AFPS_RECENT; i++)
		if (s->recent[i].tid == q->tid && s->recent[i].a.net == q->src.net &&
		    s->recent[i].a.node == q->src.node && s->recent[i].a.socket == q->src.socket)
			return 1;
	i = s->recent_pos++ % AFPS_RECENT;
	s->recent[i].a = q->src;
	s->recent[i].tid = q->tid;
	return 0;
}

static unsigned bits(unsigned m)
{
	unsigned n = 0;
	for (; m; m >>= 1)
		n += m & 1;
	return n;
}

/* the room the requester has for the reply */
static size_t room(const AsReq *q)
{
	unsigned n = bits(q->bitmap);
	return (size_t)(n ? n : 1) * AS_ATP_DATA;
}

static void reply(AfpsServer *s, const AsReq *q, s32 result, const u8 *data, size_t len)
{
	u8 u[4];
	ln_put_be32(u, (u32)result);
	s->t.respond(s->t.ud, q, u, data, len);
}

static void command(AfpsServer *s, AfpsSess *se, const AsReq *q, const u8 *cmd, size_t n, const u8 *wdata, size_t wlen)
{
	size_t rlen = 0;
	s32 e = afps_afp_call(s, se, cmd, n, wdata, wlen, s->scratch, LN_MIN(room(q), (size_t)AS_QUANTUM), &rlen);
	if (e != kFPNoErr && e != kFPObjectNotFound && e != kFPEOFErr && e != kFPItemNotFound)
		LN_LOG(1, "afpsrv: call %u: result %ld", n ? cmd[0] : 0, (long)e);
	reply(s, q, e, s->scratch, rlen);
}

static void open_session(AfpsServer *s, const AsReq *q)
{
	AfpsSess *se = NULL;
	u8 u[4];
	int i, err = 0;
	if (ln_be16(q->user + 2) != ASP_VERSION)
		err = ASPERR_BADVERS;
	for (i = 0; i < AFPS_MAXSESS && !se && !err; i++)
		if (!s->sess[i].used)
			se = &s->sess[i];
	if (!se && !err)
		err = ASPERR_SERVERBUSY;
	if (err) {
		user4(u, s->t.socket, 0, (unsigned)(err >> 8) & 0xFF, (unsigned)err & 0xFF);
		s->t.respond(s->t.ud, q, u, NULL, 0);
		return;
	}
	memset(se, 0, sizeof *se);
	se->used = 1;
	do
		se->id = s->next_sid++;
	while (!se->id || sess_of(s, se->id) != se);
	se->wss = q->src;
	se->wss.socket = q->user[1];
	se->last_rx = ln_ms();
	user4(u, s->t.socket, se->id, 0, 0);
	s->t.respond(s->t.ud, q, u, NULL, 0);
	/* our tickles: an at-least-once request to the WSS every 30 seconds, until cancelled */
	user4(u, SP_TICKLE, se->id, 0, 0);
	if (s->t.request(s->t.ud, se->wss, u, NULL, 0, 0, 1, ASP_TICKLE_S, -1, &se->tickle) != LN_OK)
		se->tickle = 0;
	LN_LOG(1, "afpsrv: session %u opened for %u.%u:%u", se->id, se->wss.net, se->wss.node, se->wss.socket);
}

static void write_request(AfpsServer *s, AfpsSess *se, const AsReq *q)
{
	size_t want = afps_write_size(q->data, q->len);
	AfpsWrite *w = NULL;
	u8 u[4], d[2];
	int i;
	if (!want) {
		command(s, se, q, q->data, q->len, NULL, 0);
		return;
	}
	for (i = 0; i < AFPS_MAXWRITE && !w; i++)
		if (!s->wr[i].used)
			w = &s->wr[i];
	if (!w || q->len > sizeof w->cmd)
		return;                                  /* busy: the workstation sends it again */
	memset(w, 0, sizeof *w);
	w->sess = se->id;
	w->req = *q;
	memcpy(w->cmd, q->data, q->len);
	w->cmdlen = q->len;
	w->req.data = w->cmd;
	/* WriteContinue (XO): the session ID and the Write's sequence number, and the room we have */
	user4(u, SP_WRITECONT, se->id, q->user[2], q->user[3]);
	ln_put_be16(d, (u16)want);
	if (s->t.request(s->t.ud, se->wss, u, d, 2, 1, (int)((want + AS_ATP_DATA - 1) / AS_ATP_DATA), 2, -1, &w->reqid) == LN_OK)
		w->used = 1;
}

void afps_input(AfpsServer *s, const AsReq *q)
{
	AfpsSess *se;
	u8 u[4];
	if (q->xo && seen(s, q))
		return;
	switch (q->user[0]) {
	case SP_GETSTATUS: {
		size_t n = afps_status(s, s->scratch, LN_MIN(room(q), sizeof s->scratch));
		user4(u, 0, 0, 0, 0);
		s->t.respond(s->t.ud, q, u, s->scratch, n);
		break;
	}
	case SP_OPENSESS:
		open_session(s, q);
		break;
	case SP_CLOSESESS:
		user4(u, 0, 0, 0, 0);
		s->t.respond(s->t.ud, q, u, NULL, 0);
		se = sess_of(s, q->user[1]);
		if (se)
			sess_close(s, se, 0);
		break;
	case SP_COMMAND:
	case SP_WRITE:
		se = sess_of(s, q->user[1]);
		if (!se) {
			reply(s, q, ASPERR_SESSCLOSED, NULL, 0);
			break;
		}
		se->last_rx = ln_ms();
		if (q->user[0] == SP_COMMAND)
			command(s, se, q, q->data, q->len, NULL, 0);
		else
			write_request(s, se, q);
		break;
	case SP_TICKLE:
		se = sess_of(s, q->user[1]);
		if (se)
			se->last_rx = ln_ms();
		break;                                   /* tickles are never answered */
	default:
		break;
	}
}

void afps_reply(AfpsServer *s, u32 id, int err, const u8 *data, size_t len)
{
	int i;
	for (i = 0; i < AFPS_MAXWRITE; i++) {
		AfpsWrite *w = &s->wr[i];
		AfpsSess *se;
		if (!w->used || w->reqid != id)
			continue;
		w->used = 0;
		se = sess_of(s, w->sess);
		if (!se)
			return;
		se->last_rx = ln_ms();
		if (err)
			reply(s, &w->req, kFPMiscErr, NULL, 0);
		else
			command(s, se, &w->req, w->cmd, w->cmdlen, data, len);
		return;
	}
	/* a tickle, an attention or a CloseSess: nothing to do */
}

void afps_tick(AfpsServer *s)
{
	int i;
	u32 now = ln_ms();
	for (i = 0; i < AFPS_MAXSESS; i++)
		if (s->sess[i].used && now - s->sess[i].last_rx > ASP_TIMEOUT_MS) {
			LN_LOG(1, "afpsrv: session %u timed out", s->sess[i].id);
			sess_close(s, &s->sess[i], 0);
		}
}
