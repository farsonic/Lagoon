/*
 * Lagoon - DOS-level checks for the emulator handler test (t_handler.sh),
 * with output that is easy to grep and independent of the AmigaDOS
 * commands available:
 *
 *   t_handler_tool ls DIR            Examine + ExNext
 *   t_handler_tool exall DIR [PAT]   ExAll(ED_OWNER) with a small buffer
 *   t_handler_tool info PATH         Info()
 *   t_handler_tool seek FILE         Seek / SetFileSize / read-write mix
 *   t_handler_tool locks FILE        lock and open conflicts
 *   t_handler_tool fh FILE           DupLockFromFH, NameFromFH, ExamineFH,
 *                                    ParentOfFH, OpenFromLock, ChangeMode
 *   t_handler_tool names VOL:        path parsing ("/", ":", case)
 *   t_handler_tool setdate FILE      SetFileDate to 2020-01-01 12:00
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <exec/memory.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <dos/exall.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <stdio.h>
#include <string.h>

static void prot(LONG p, char *o)
{
	const char *f = "hsparwed";
	int i;
	for (i = 0; i < 8; i++) {
		int bit = 7 - i, set = (p >> bit) & 1;
		if (bit < 4)
			set = !set;   /* rwed are active low */
		o[i] = set ? f[i] : '-';
	}
	o[8] = 0;
}

static void date(const struct DateStamp *ds, char *o)
{
	/* days since 1978 -> y-m-d (good enough for tests) */
	static const int md[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	long d = ds->ds_Days;
	int y = 1978, m = 0;
	for (;;) {
		int yl = ((y % 4 == 0 && y % 100) || y % 400 == 0) ? 366 : 365;
		if (d < yl)
			break;
		d -= yl;
		y++;
	}
	for (;;) {
		int ml = md[m] + (m == 1 && ((y % 4 == 0 && y % 100) || y % 400 == 0));
		if (d < ml)
			break;
		d -= ml;
		m++;
	}
	sprintf(o, "%04d-%02d-%02d %02ld:%02ld", y, m + 1, (int)d + 1, ds->ds_Minute / 60, ds->ds_Minute % 60);
}

static int ls(const char *dir)
{
	BPTR l = Lock((STRPTR)dir, SHARED_LOCK);
	struct FileInfoBlock *fib = AllocDosObject(DOS_FIB, NULL);
	int n = 0;
	char p[9], d[32];
	if (!l || !fib) {
		PrintFault(IoErr(), (STRPTR)dir);
		return 10;
	}
	if (!Examine(l, fib)) {
		PrintFault(IoErr(), (STRPTR)"Examine");
		return 10;
	}
	printf("examine %s type=%ld\n", fib->fib_FileName, fib->fib_DirEntryType);
	while (ExNext(l, fib)) {
		prot(fib->fib_Protection, p);
		date(&fib->fib_Date, d);
		printf("ent %s|%s|%ld|%s|%s|%s\n", fib->fib_FileName, fib->fib_DirEntryType > 0 ? "dir" : "file",
		       fib->fib_Size, p, d, fib->fib_Comment);
		n++;
	}
	printf("end %ld count=%d\n", IoErr(), n);
	FreeDosObject(DOS_FIB, fib);
	UnLock(l);
	return 0;
}

static int exall(const char *dir, const char *pat)
{
	BPTR l = Lock((STRPTR)dir, SHARED_LOCK);
	struct ExAllControl *eac = AllocDosObject(DOS_EXALLCONTROL, NULL);
	UBYTE *buf = AllocVec(600, MEMF_ANY);
	char pp[128];
	int more, n = 0, calls = 0;
	if (!l || !eac || !buf) {
		PrintFault(IoErr(), (STRPTR)dir);
		return 10;
	}
	eac->eac_LastKey = 0;
	if (pat) {
		ParsePatternNoCase((STRPTR)pat, (STRPTR)pp, sizeof(pp));
		eac->eac_MatchString = (STRPTR)pp;
	}
	do {
		struct ExAllData *ed;
		more = ExAll(l, (struct ExAllData *)buf, 600, ED_OWNER, eac);
		if (!more && IoErr() != ERROR_NO_MORE_ENTRIES) {
			PrintFault(IoErr(), (STRPTR)"ExAll");
			break;
		}
		calls++;
		for (ed = eac->eac_Entries ? (struct ExAllData *)buf : NULL; ed; ed = ed->ed_Next) {
			char p[9];
			prot((LONG)ed->ed_Prot, p);
			printf("ed %s|%s|%lu|%s|%s\n", ed->ed_Name, ed->ed_Type > 0 ? "dir" : "file", ed->ed_Size, p,
			       ed->ed_Comment ? (char *)ed->ed_Comment : "");
			n++;
		}
	} while (more);
	printf("exall count=%d calls=%d\n", n, calls);
	FreeVec(buf);
	FreeDosObject(DOS_EXALLCONTROL, eac);
	UnLock(l);
	return 0;
}

static int info(const char *path)
{
	BPTR l = Lock((STRPTR)path, SHARED_LOCK);
	struct InfoData *id = AllocVec(sizeof(struct InfoData), MEMF_CLEAR);
	char name[64];
	if (!l || !id || !Info(l, id)) {
		PrintFault(IoErr(), (STRPTR)path);
		return 10;
	}
	{
		struct DosList *v = (struct DosList *)BADDR(id->id_VolumeNode);
		UBYTE *b = v ? (UBYTE *)BADDR(v->dol_Name) : NULL;
		int k = b ? b[0] : 0;
		memcpy(name, b ? (char *)b + 1 : "", (size_t)k);
		name[k] = 0;
	}
	printf("info volume=%s blocks=%ld used=%ld bpb=%ld type=%08lx state=%ld inuse=%ld\n", name,
	       id->id_NumBlocks, id->id_NumBlocksUsed, id->id_BytesPerBlock, (unsigned long)id->id_DiskType,
	       id->id_DiskState, id->id_InUse);
	FreeVec(id);
	UnLock(l);
	return 0;
}

static int seek(const char *file)
{
	BPTR fh = Open((STRPTR)file, MODE_NEWFILE);
	char b[32];
	LONG r;
	if (!fh) {
		PrintFault(IoErr(), (STRPTR)file);
		return 10;
	}
	Write(fh, (APTR)"0123456789", 10);
	printf("seek cur->0: old=%ld\n", Seek(fh, 0, OFFSET_BEGINNING));
	printf("seek end: old=%ld\n", Seek(fh, 0, OFFSET_END));
	printf("seek end pos=%ld\n", Seek(fh, 0, OFFSET_CURRENT));
	r = Seek(fh, 5, OFFSET_END);
	printf("seek past end=%ld err=%ld\n", r, r < 0 ? IoErr() : 0);
	Seek(fh, 3, OFFSET_BEGINNING);
	Write(fh, (APTR)"abc", 3);
	Seek(fh, 0, OFFSET_BEGINNING);
	r = Read(fh, b, sizeof(b) - 1);
	b[r > 0 ? r : 0] = 0;
	printf("read %ld %s\n", r, b);
	printf("setsize=%ld\n", SetFileSize(fh, 4, OFFSET_BEGINNING));
	printf("pos after setsize=%ld\n", Seek(fh, 0, OFFSET_CURRENT));
	Seek(fh, 0, OFFSET_BEGINNING);
	r = Read(fh, b, sizeof(b) - 1);
	b[r > 0 ? r : 0] = 0;
	printf("read %ld %s\n", r, b);
	Close(fh);
	return 0;
}

static int locks(const char *file)
{
	BPTR a, b, fh;
	a = Lock((STRPTR)file, EXCLUSIVE_LOCK);
	printf("excl lock: %s\n", a ? "ok" : "fail");
	b = Lock((STRPTR)file, SHARED_LOCK);
	printf("shared while excl: %s err=%ld\n", b ? "ok" : "fail", b ? 0 : IoErr());
	fh = Open((STRPTR)file, MODE_OLDFILE);
	printf("open while excl: %s err=%ld\n", fh ? "ok" : "fail", fh ? 0 : IoErr());
	printf("delete while locked: %s err=%ld\n", DeleteFile((STRPTR)file) ? "ok" : "fail", IoErr());
	printf("duplock excl: %s\n", DupLock(a) ? "ok" : "fail");
	UnLock(a);
	a = Lock((STRPTR)file, SHARED_LOCK);
	b = Lock((STRPTR)file, SHARED_LOCK);
	printf("two shared: %s %s same=%ld\n", a ? "ok" : "fail", b ? "ok" : "fail", SameLock(a, b));
	fh = Open((STRPTR)file, MODE_NEWFILE);
	printf("newfile while shared: %s err=%ld\n", fh ? "ok" : "fail", fh ? 0 : IoErr());
	UnLock(a);
	UnLock(b);
	fh = Open((STRPTR)file, MODE_NEWFILE);
	printf("newfile: %s\n", fh ? "ok" : "fail");
	a = Lock((STRPTR)file, SHARED_LOCK);
	printf("lock while newfile: %s err=%ld\n", a ? "ok" : "fail", a ? 0 : IoErr());
	if (a)
		UnLock(a);
	Close(fh);
	return 0;
}

static int fhtest(const char *file)
{
	BPTR fh = Open((STRPTR)file, MODE_READWRITE), l, p, fh2;
	struct FileInfoBlock *fib = AllocDosObject(DOS_FIB, NULL);
	char name[256];
	if (!fh || !fib) {
		PrintFault(IoErr(), (STRPTR)file);
		return 10;
	}
	Write(fh, (APTR)"hello", 5);
	printf("namefromfh: %s\n", NameFromFH(fh, (STRPTR)name, sizeof(name)) ? name : "fail");
	if (ExamineFH(fh, fib))
		printf("examinefh: %s size=%ld\n", fib->fib_FileName, fib->fib_Size);
	else
		printf("examinefh: fail\n");
	l = DupLockFromFH(fh);
	printf("duplockfromfh: %s\n", l ? "ok" : "fail");
	p = ParentOfFH(fh);
	printf("parentoffh: %s\n", p && NameFromLock(p, (STRPTR)name, sizeof(name)) ? name : "fail");
	printf("changemode excl (with lock): %s\n", ChangeMode(CHANGE_FH, fh, EXCLUSIVE_LOCK) ? "ok" : "fail");
	UnLock(p);
	Close(fh);
	printf("changemode lock excl: %s\n", ChangeMode(CHANGE_LOCK, l, EXCLUSIVE_LOCK) ? "ok" : "fail");
	ChangeMode(CHANGE_LOCK, l, SHARED_LOCK);
	fh2 = OpenFromLock(l);
	printf("openfromlock: %s\n", fh2 ? "ok" : "fail");
	if (fh2) {
		LONG n = Read(fh2, name, 10);
		name[n > 0 ? n : 0] = 0;
		printf("read %ld %s\n", n, name);
		Close(fh2);
	} else
		UnLock(l);
	FreeDosObject(DOS_FIB, fib);
	return 0;
}

static void lockname(const char *path)
{
	BPTR l = Lock((STRPTR)path, SHARED_LOCK);
	char name[256];
	if (!l) {
		printf("name %s -> error %ld\n", path, IoErr());
		return;
	}
	printf("name %s -> %s\n", path, NameFromLock(l, (STRPTR)name, sizeof(name)) ? name : "?");
	UnLock(l);
}

static int names(const char *vol)
{
	static const char *const rel[] = { "Dir1/sub", "dir1/SUB/", "Dir1/sub//", "Dir1/sub///ReadMe.txt",
	                                   "DIR1//mixedcase.txt", "nothere", "ReadMe.txt/x", "" };
	char p[128];
	BPTR l, old;
	int i;
	for (i = 0; i < 8; i++) {
		sprintf(p, "%s%s", vol, rel[i]);
		lockname(p);
	}
	/* relative to a current directory on the volume */
	sprintf(p, "%sDir1/sub", vol);
	l = Lock((STRPTR)p, SHARED_LOCK);
	if (l) {
		old = CurrentDir(l);
		lockname("/");
		lockname("//ReadMe.txt");
		lockname(":Dir1");
		lockname("deep.txt");
		CurrentDir(old);
		UnLock(l);
	}
	return 0;
}

static int setdate(const char *file)
{
	struct DateStamp ds;
	ds.ds_Days = 15340;          /* 2020-01-01 */
	ds.ds_Minute = 12 * 60;
	ds.ds_Tick = 0;
	if (!SetFileDate((STRPTR)file, &ds)) {
		PrintFault(IoErr(), (STRPTR)file);
		return 10;
	}
	printf("setdate ok\n");
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		printf("usage: t_handler_tool ls|exall|info|seek|locks|fh|names PATH\n");
		return 20;
	}
	if (!strcmp(argv[1], "ls"))
		return ls(argv[2]);
	if (!strcmp(argv[1], "exall"))
		return exall(argv[2], argc > 3 ? argv[3] : NULL);
	if (!strcmp(argv[1], "info"))
		return info(argv[2]);
	if (!strcmp(argv[1], "seek"))
		return seek(argv[2]);
	if (!strcmp(argv[1], "locks"))
		return locks(argv[2]);
	if (!strcmp(argv[1], "fh"))
		return fhtest(argv[2]);
	if (!strcmp(argv[1], "setdate"))
		return setdate(argv[2]);
	if (!strcmp(argv[1], "names"))
		return names(argv[2]);
	return 20;
}
