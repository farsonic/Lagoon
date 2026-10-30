/* Lagoon - core unit tests: hashes, HMAC, URLs, charsets, names, config, printf. */
#include "testutil.h"
#include "ln_types.h"
#include "ln_hash.h"
#include "ln_url.h"
#include "ln_charset.h"
#include "ln_conf.h"
#include "ln_vfs.h"
#include "ln_sys.h"

static void hashes(void)
{
	u8 d[64];
	char big[1000];
	ln_md4("abc", 3, d); CHECK_HEX(d, 16, "a448017aaf21d8525fc10ae87aa6729d");
	ln_md4("", 0, d); CHECK_HEX(d, 16, "31d6cfe0d16ae931b73c59d7e0c089c0");
	ln_md5("abc", 3, d); CHECK_HEX(d, 16, "900150983cd24fb0d6963f7d28e17f72");
	ln_md5("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80, d);
	CHECK_HEX(d, 16, "57edf4a22be3c955ac49da2e2107b67a");
	ln_sha256("abc", 3, d); CHECK_HEX(d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	ln_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d);
	CHECK_HEX(d, 32, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
	ln_sha512("abc", 3, d);
	CHECK_HEX(d, 64, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
	memset(big, 'a', sizeof(big));
	{
		LnSha256 c; int i;
		ln_sha256_init(&c);
		for (i = 0; i < 1000; i++) ln_sha256_update(&c, big, 1000);
		ln_sha256_final(&c, d);
		CHECK_HEX(d, 32, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
	}
	/* RFC 2104 / 4231 */
	{
		u8 k[16]; memset(k, 0x0b, 16);
		ln_hmac_md5(k, 16, "Hi There", 8, d); CHECK_HEX(d, 16, "9294727a3638bb1c13f48ef8158bfc9d");
	}
	{
		u8 k[20]; memset(k, 0x0b, 20);
		ln_hmac_sha256(k, 20, "Hi There", 8, d);
		CHECK_HEX(d, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
	}
	{
		LnHmacSha512 h;
		ln_hmac_sha512_init(&h, "Jefe", 4);
		ln_hmac_sha512_update(&h, "what do ya want ", 16);
		ln_hmac_sha512_update(&h, "for nothing?", 12);
		ln_hmac_sha512_final(&h, d);
		CHECK_HEX(d, 64, "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
	}
	/* NTLM hash of "Password" (MD4 of UTF-16LE) */
	{
		u8 w[16]; int l = ln_utf8_to_utf16le("Password", 8, w, sizeof(w));
		ln_md4(w, (size_t)l, d); CHECK_HEX(d, 16, "a4f49c406510bdcab6824ee7c30fd852");
	}
}

static void urls(void)
{
	LnUrl u;
	char b[300];
	CHECK_INT(ln_url_parse("smb://WORK;bob:p%40ss@nas.local:4455/Public/Music/Old?sign=required&encrypt", &u), 0);
	CHECK_STR(u.scheme, "smb"); CHECK_STR(u.domain, "WORK"); CHECK_STR(u.user, "bob"); CHECK_STR(u.password, "p@ss");
	CHECK_STR(u.host, "nas.local"); CHECK_INT(u.port, 4455); CHECK_STR(u.share, "Public"); CHECK_STR(u.path, "Music/Old");
	CHECK_STR(ln_url_opt(&u, "sign", "x", b, sizeof(b)), "required");
	CHECK_STR(ln_url_opt(&u, "encrypt", "x", b, sizeof(b)), "yes");
	CHECK_STR(ln_url_opt(&u, "dialect", "def", b, sizeof(b)), "def");
	ln_url_format(&u, b, sizeof(b));
	CHECK_STR(b, "smb://WORK;bob@nas.local:4455/Public/Music/Old?sign=required&encrypt");
	CHECK_INT(ln_url_parse("nfs://10.0.2.2/srv/export/amiga/?uid=1000", &u), 0);
	CHECK_STR(u.share, "/srv/export/amiga"); CHECK_STR(u.path, ""); CHECK_INT(ln_url_opt_int(&u, "uid", 0), 1000);
	CHECK_INT(ln_url_parse("afp://[fe80::1]:548/Home", &u), 0);
	CHECK_STR(u.host, "fe80::1"); CHECK_INT(u.port, 548); CHECK_STR(u.share, "Home");
	CHECK_INT(ln_url_parse("CIFS://host/My%20Share", &u), 0);
	CHECK_STR(u.scheme, "smb"); CHECK_STR(u.share, "My Share");
	ln_url_format(&u, b, sizeof(b)); CHECK_STR(b, "smb://host/My%20Share");
	CHECK(ln_url_parse("smb:/host", &u) != 0);
	CHECK(ln_url_parse("smb://:445/x", &u) != 0);
	CHECK(ln_url_parse("smb://h:99999/x", &u) != 0);
}

static void charsets(void)
{
	u8 w[64];
	char o[128];
	int l;
	l = ln_utf8_to_utf16le("A\xc3\xa9\xf0\x9f\x98\x80", 7, w, sizeof(w));
	CHECK_INT(l, 8);
	CHECK_HEX(w, 8, "4100e9003dd800de");
	CHECK_INT(ln_utf16le_to_utf8(w, 8, o, sizeof(o)), 7);
	CHECK_STR(o, "A\xc3\xa9\xf0\x9f\x98\x80");
	/* NFD <-> NFC: "é" = e + U+0301, "Ấ" two levels */
	CHECK(ln_utf8_nfd("\xc3\xa9", o, sizeof(o)) == 3); CHECK_STR(o, "e\xcc\x81");
	CHECK(ln_utf8_nfc("e\xcc\x81x", o, sizeof(o)) == 3); CHECK_STR(o, "\xc3\xa9x");
	ln_utf8_nfd("\xe1\xba\xa4", o, sizeof(o)); CHECK_STR(o, "A\xcc\x82\xcc\x81");
	ln_utf8_nfc("A\xcc\x82\xcc\x81", o, sizeof(o)); CHECK_STR(o, "\xe1\xba\xa4");
	/* Amiga names */
	ln_name_to_amiga("Caf\xc3\xa9 a:b/c 100%", o, sizeof(o)); CHECK_STR(o, "Caf\xe9 a%3Ab%2Fc 100%25");
	ln_name_from_amiga("Caf\xe9 a%3Ab%2Fc 100%25", o, sizeof(o)); CHECK_STR(o, "Caf\xc3\xa9 a:b/c 100%");
	ln_name_to_amiga("\xe2\x82\xac.txt", o, sizeof(o)); CHECK_STR(o, "%E2%82%AC.txt");
	ln_name_from_amiga("%E2%82%AC.txt", o, sizeof(o)); CHECK_STR(o, "\xe2\x82\xac.txt");
	ln_name_to_amiga("Cafe\xcc\x81", o, sizeof(o)); CHECK_STR(o, "Caf\xe9");   /* macOS NFD name */
	CHECK(ln_amiga_stricmp("\xc9t\xe9", "\xe9T\xc9") == 0);
}

static void conf(void)
{
	LnConf c, d;
	LnShare s;
	char buf[2048];
	int line = 0;
	ln_conf_init(&c);
	memset(&s, 0, sizeof(s));
	strcpy(s.name, "NAS"); strcpy(s.url, "smb://nas.local/Public"); strcpy(s.user, "bob");
	strcpy(s.password, "s3cr\"t pw"); s.automount = 1; strcpy(s.volume, "Public Files");
	CHECK_INT(ln_conf_put(&c, &s), 0);
	strcpy(s.name, "Mac"); strcpy(s.url, "afp://imac/Data"); s.password[0] = 0; s.automount = 0; s.readonly = 1;
	CHECK_INT(ln_conf_put(&c, &s), 0);
	CHECK(ln_conf_format(&c, buf, sizeof(buf)) > 0);
	CHECK(strstr(buf, "s3cr") == NULL);
	CHECK_INT(ln_conf_parse(&d, buf, &line), 0);
	CHECK_INT(d.nshares, 2);
	CHECK_STR(d.share[0].password, "s3cr\"t pw"); CHECK_STR(d.share[0].volume, "Public Files");
	CHECK_INT(d.share[0].automount, 1); CHECK_INT(d.share[1].readonly, 1);
	CHECK(ln_conf_find(&d, "nas") == &d.share[0]);
	CHECK_INT(ln_conf_parse(&d, "share name=\"X\" url=\"nfs://h/e\" future=\"1\"\n# c\n\noption loglevel=2 colour=blue\n", &line), 0);
	CHECK_STR(d.share[0].extra, "future=\"1\""); CHECK_INT(d.loglevel, 2); CHECK_STR(d.extra, "colour=\"blue\"");
	CHECK(ln_conf_parse(&d, "share name=\"X\"\n", &line) != 0); CHECK_INT(line, 1);
	CHECK(ln_conf_parse(&d, "\nbogus\n", &line) != 0); CHECK_INT(line, 2);
	CHECK_INT(ln_conf_remove(&c, "NAS"), 0); CHECK_INT(c.nshares, 1); CHECK_STR(c.share[0].name, "Mac");
}

static void misc(void)
{
	char b[64];
	CHECK_INT(ln_snprintf(b, sizeof(b), "%s|%5d|%-4u|%04x|%.2s|%llu|%c%%", "ab", -42, 7u, 0xbeefu, "xyz", 1ULL << 40, 'Z'), 38);
	CHECK_STR(b, "ab|  -42|7   |beef|xy|1099511627776|Z%");
	CHECK_INT(ln_snprintf(b, 4, "%.0s%s", "zzz", "abcdef"), 6); CHECK_STR(b, "abc");
	ln_path_join(b, sizeof(b), "", "a"); CHECK_STR(b, "a");
	ln_path_join(b, sizeof(b), "a/b", "c"); CHECK_STR(b, "a/b/c");
	ln_path_parent(b, sizeof(b), "a/b/c"); CHECK_STR(b, "a/b");
	ln_path_parent(b, sizeof(b), "a"); CHECK_STR(b, "");
	CHECK_STR(ln_path_base("a/b/c"), "c");
	CHECK(ln_vfs_find("smb") && ln_vfs_find("CIFS") && ln_vfs_find("afp") && ln_vfs_find("nfs") && !ln_vfs_find("ftp"));
}

int main(void)
{
	hashes();
	urls();
	charsets();
	conf();
	misc();
	T_DONE("t_core");
}
