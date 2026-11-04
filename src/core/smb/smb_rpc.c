/*
 * Lagoon - share enumeration: DCE/RPC (C706 connection-oriented PDUs, NDR)
 * over the \PIPE\srvsvc named pipe on IPC$, NetrShareEnum level 1
 * (MS-SRVS 3.1.4.8). BIND, then REQUEST via FSCTL_PIPE_TRANSCEIVE, with
 * READ for the rest of a long or fragmented reply.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "smb_int.h"
#include "../ln_charset.h"

#define PIPE_MAX 4280            /* fragment size we offer (what Windows uses) */

/* srvsvc 4b324fc8-1670-01d3-1278-5a47bf6ee188 v3.0, NDR 8a885d04-1ceb-11c9-9fe8-08002b104860 v2 */
static const u8 srvsvc_uuid[16] = { 0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88 };
static const u8 ndr_uuid[16] = { 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60 };

static void pdu_hdr(u8 *p, u8 type, u16 len, u32 call)
{
	p[0] = 5; p[1] = 0; p[2] = type; p[3] = 3;   /* v5.0, first+last fragment */
	p[4] = 0x10; p[5] = 0; p[6] = 0; p[7] = 0;   /* little endian, ASCII, IEEE */
	ln_put_le16(p + 8, len);
	ln_put_le16(p + 10, 0);
	ln_put_le32(p + 12, call);
}

typedef struct Pipe {
	SmbConn *c;
	u8 fid[16];
	u8 *in;                  /* bytes received from the pipe */
	size_t inlen, incap;
} Pipe;

static int pipe_add(Pipe *p, const u8 *d, size_t n)
{
	if (p->inlen + n > p->incap) {
		size_t nc = (p->inlen + n) * 2 + 1024;
		u8 *b;
		if (nc > 4u * 1024 * 1024)
			return LN_EPROTO;
		b = ln_realloc(p->in, p->incap, nc);
		if (!b)
			return LN_ENOMEM;
		p->in = b;
		p->incap = nc;
	}
	memcpy(p->in + p->inlen, d, n);
	p->inlen += n;
	return LN_OK;
}

/* send a PDU with FSCTL_PIPE_TRANSCEIVE; the reply is appended to p->in */
static int transceive(Pipe *p, const u8 *pdu, size_t n, int *more)
{
	SmbConn *c = p->c;
	u8 *b = smb_body(c, 56 + n);
	int r;
	u32 oo, ol;
	if (!b)
		return LN_ENOMEM;
	ln_put_le16(b, 57);
	ln_put_le32(b + 4, 0x0011c017);
	memcpy(b + 8, p->fid, 16);
	ln_put_le32(b + 24, SMB2_HDR + 56);
	ln_put_le32(b + 28, (u32)n);
	ln_put_le32(b + 44, PIPE_MAX);           /* max output */
	ln_put_le32(b + 48, 1);
	memcpy(b + 56, pdu, n);
	r = smb_call(c, SMB2_IOCTL, 56 + n, PIPE_MAX);
	if (r)
		return r;
	if (c->status != ST_OK && c->status != ST_BUFFER_OVERFLOW) {
		LN_LOG(1, "smb: srvsvc transceive: %s", smb_status_name(c->status));
		return smb_err(c->status) ? smb_err(c->status) : LN_EIO;
	}
	*more = c->status == ST_BUFFER_OVERFLOW;
	if (c->blen < 48)
		return LN_EPROTO;
	oo = ln_le32(c->body + 32);
	ol = ln_le32(c->body + 36);
	if (oo + ol > c->msglen)
		return LN_EPROTO;
	return pipe_add(p, c->msg + oo, ol);
}

static int pipe_read(Pipe *p, int *more)
{
	SmbConn *c = p->c;
	u8 *b = smb_body(c, 49);
	int r;
	u32 doff, got;
	if (!b)
		return LN_ENOMEM;
	ln_put_le16(b, 49);
	b[2] = 0x50;
	ln_put_le32(b + 4, PIPE_MAX);
	memcpy(b + 16, p->fid, 16);
	r = smb_call(c, SMB2_READ, 49, PIPE_MAX);
	if (r)
		return r;
	if (c->status != ST_OK && c->status != ST_BUFFER_OVERFLOW)
		return smb_err(c->status) ? smb_err(c->status) : LN_EIO;
	*more = c->status == ST_BUFFER_OVERFLOW;
	doff = c->body[2];
	got = ln_le32(c->body + 4);
	if (c->blen < 16 || doff + got > c->msglen)
		return LN_EPROTO;
	return pipe_add(p, c->msg + doff, got);
}

/* collect complete fragments of one reply into stub (concatenated stub data) */
static int read_reply(Pipe *p, int more, u8 ptype, u8 **stub, size_t *slen)
{
	size_t off = 0;
	int r;
	*stub = NULL;
	*slen = 0;
	for (;;) {
		u16 fl;
		while (p->inlen - off < 16 || p->inlen - off < ln_le16(p->in + off + 8)) {
			if (!more && p->inlen - off >= 16 && p->inlen - off < ln_le16(p->in + off + 8))
				more = 1;              /* a fragment continues: keep reading */
			if (!more && p->inlen - off < 16 && p->inlen != off)
				more = 1;
			if (!more)
				return LN_EPROTO;
			if ((r = pipe_read(p, &more)) != 0)
				return r;
		}
		fl = ln_le16(p->in + off + 8);
		if (p->in[off + 2] == 3) {             /* fault */
			LN_LOG(0, "smb: srvsvc fault 0x%08x", fl >= 28 ? ln_le32(p->in + off + 24) : 0);
			return LN_EIO;
		}
		if (p->in[off + 2] != ptype || fl < 24)
			return LN_EPROTO;
		if (ptype == 2) {
			/* response: 24-byte header then stub (minus auth trailer: none) */
			u8 *ns = ln_realloc(*stub, *slen, *slen + fl - 24);
			if (!ns)
				return LN_ENOMEM;
			*stub = ns;
			memcpy(*stub + *slen, p->in + off + 24, fl - 24u);
			*slen += fl - 24u;
		}
		off += fl;
		if (p->in[off - fl + 3] & 2)          /* last fragment */
			break;
		if (p->inlen == off && !more)
			more = 1;
	}
	p->inlen = 0;
	return LN_OK;
}

/* NDR conformant varying string at *o: returns UTF-8 in out */
static int ndr_str(const u8 *s, size_t n, size_t *o, char *out, size_t max)
{
	u32 cnt;
	size_t bytes;
	*o = (*o + 3) & ~(size_t)3;
	if (*o + 12 > n)
		return -1;
	cnt = ln_le32(s + *o + 8);
	bytes = (size_t)cnt * 2;
	*o += 12;
	if (*o + bytes > n)
		return -1;
	out[0] = 0;
	if (bytes >= 2 && s[*o + bytes - 2] == 0 && s[*o + bytes - 1] == 0)
		ln_utf16le_to_utf8(s + *o, bytes - 2, out, max);
	else
		ln_utf16le_to_utf8(s + *o, bytes, out, max);
	*o += bytes;
	return 0;
}

int smb_enum_shares(SmbConn *c, const char *host, int all, ln_share_cb cb, void *ud)
{
	Pipe p;
	SmbCreate cr;
	u8 name[16], *pdu = NULL, *stub = NULL;
	size_t slen, o, k;
	int r, more, n, i;
	u32 count;
	memset(&p, 0, sizeof(p));
	p.c = c;
	memset(&cr, 0, sizeof(cr));
	cr.access = 0x0012019f;
	cr.share = 3;
	cr.disposition = 1;
	n = ln_utf8_to_utf16le("srvsvc", 6, name, sizeof(name));
	r = smb_create(c, name, n, &cr, 0);
	if (r == 1) {
		LN_LOG(0, "smb: cannot open \\PIPE\\srvsvc: %s", smb_status_name(c->status));
		return smb_err(c->status);
	}
	if (r)
		return r;
	memcpy(p.fid, cr.fid, 16);
	pdu = ln_alloc(1024);
	if (!pdu) { r = LN_ENOMEM; goto out; }

	/* BIND */
	pdu_hdr(pdu, 11, 72, 1);
	ln_put_le16(pdu + 16, PIPE_MAX);
	ln_put_le16(pdu + 18, PIPE_MAX);
	pdu[24] = 1;                             /* one context */
	pdu[30] = 1;                             /* one transfer syntax */
	memcpy(pdu + 32, srvsvc_uuid, 16);
	ln_put_le16(pdu + 48, 3);
	memcpy(pdu + 52, ndr_uuid, 16);
	ln_put_le32(pdu + 68, 2);
	r = transceive(&p, pdu, 72, &more);
	if (r) goto out;
	r = read_reply(&p, more, 12, &stub, &slen);   /* bind_ack */
	if (r) goto out;

	/* REQUEST NetrShareEnum (opnum 15), level 1 */
	{
		u8 *s = pdu + 24;
		char srv[140];
		int sl;
		ln_snprintf(srv, sizeof(srv), "\\\\%s", host);
		k = 0;
		ln_put_le32(s, 0x00020000); k = 4;            /* ServerName referent */
		sl = ln_utf8_to_utf16le(srv, strlen(srv), s + k + 12, 300);
		if (sl < 0) { r = LN_ENAMETOOLONG; goto out; }
		s[k + 12 + sl] = 0; s[k + 13 + sl] = 0;
		ln_put_le32(s + k, (u32)(sl / 2 + 1));
		ln_put_le32(s + k + 4, 0);
		ln_put_le32(s + k + 8, (u32)(sl / 2 + 1));
		k += 12 + (size_t)sl + 2;
		while (k & 3) s[k++] = 0;
		ln_put_le32(s + k, 1); k += 4;                 /* Level */
		ln_put_le32(s + k, 1); k += 4;                 /* union switch */
		ln_put_le32(s + k, 0x00020004); k += 4;        /* container referent */
		ln_put_le32(s + k, 0); k += 4;                 /* EntriesRead */
		ln_put_le32(s + k, 0); k += 4;                 /* Buffer = NULL */
		ln_put_le32(s + k, 0xffffffffu); k += 4;       /* PreferedMaximumLength */
		ln_put_le32(s + k, 0x00020008); k += 4;        /* ResumeHandle referent */
		ln_put_le32(s + k, 0); k += 4;
		pdu_hdr(pdu, 0, (u16)(24 + k), 2);
		ln_put_le32(pdu + 16, (u32)k);                 /* alloc hint */
		ln_put_le16(pdu + 22, 15);                     /* opnum */
	}
	ln_free(stub); stub = NULL;
	r = transceive(&p, pdu, 24 + k, &more);
	if (r) goto out;
	r = read_reply(&p, more, 2, &stub, &slen);
	if (r) goto out;

	/* level, switch, container ptr, EntriesRead, Buffer ptr, max count, entries[] */
	if (slen < 24) { r = LN_EPROTO; goto out; }
	count = ln_le32(stub + 12);
	if (!ln_le32(stub + 16) || count > 10000) {
		r = count ? LN_EPROTO : LN_OK;
		goto out;
	}
	o = 24;
	if (o + (size_t)count * 12 > slen) { r = LN_EPROTO; goto out; }
	{
		size_t so = o + (size_t)count * 12;
		for (i = 0; i < (int)count; i++) {
			const u8 *e = stub + o + 12 * (size_t)i;
			u32 type = ln_le32(e + 4);
			char nm[256], cm[256];
			nm[0] = cm[0] = 0;
			if (ln_le32(e) && ndr_str(stub, slen, &so, nm, sizeof(nm))) { r = LN_EPROTO; goto out; }
			if (ln_le32(e + 8) && ndr_str(stub, slen, &so, cm, sizeof(cm))) { r = LN_EPROTO; goto out; }
			if (!all && ((type & 0x0fffffffu) != 0 || (type & 0x80000000u) ||
			             (nm[0] && nm[strlen(nm) - 1] == '$')))
				continue;
			cb(ud, nm, cm);
		}
	}
	r = LN_OK;
out:
	smb_close(c, p.fid);
	ln_free(pdu);
	ln_free(stub);
	ln_free(p.in);
	return r;
}
