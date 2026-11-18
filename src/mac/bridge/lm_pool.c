/*
 * Lagoon on the classic Mac OS: the bridge thread's memory.
 *
 * The bridge's thread runs at deferred-task time (lm_bridge.c), where the Memory Manager may
 * not be called: it can be in the middle of moving the heap for the program that was
 * interrupted. So the thread's ln_alloc comes from a block the application took from its own
 * heap before the thread started (Riptide's driver does the same, riptide docs/MAC.md,
 * "Memory"). The allocator is first fit over blocks with an eight-byte header; free neighbours
 * are joined while searching. The thread uses it for one share's connection (an SMB connection
 * keeps two 64 KB buffers), the AFP server's tables and listings: tens of blocks, not thousands,
 * so a walk from the start is quick enough.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "../../core/ln_sys.h"
#include "lm_bridge.h"

typedef struct Blk {
	unsigned long size;      /* the whole block, header included, a multiple of 8 */
	unsigned long used;
} Blk;

static unsigned char *pool;
static unsigned long pool_size;

int lm_pool_init(void *mem, unsigned long size)
{
	Blk *b;
	pool = mem;
	pool_size = size & ~7UL;
	if (!pool || pool_size < 64)
		return LN_ENOMEM;
	b = (Blk *)pool;
	b->size = pool_size;
	b->used = 0;
	return LN_OK;
}

void *lm_pool_alloc(unsigned long n)
{
	unsigned long need = (n + sizeof(Blk) + 7) & ~7UL, o = 0;
	while (o < pool_size) {
		Blk *b = (Blk *)(pool + o);
		if (!b->used) {
			/* join the free blocks that follow */
			while (o + b->size < pool_size && !((Blk *)(pool + o + b->size))->used)
				b->size += ((Blk *)(pool + o + b->size))->size;
			if (b->size >= need) {
				if (b->size - need >= 64) {      /* split: the rest stays free */
					Blk *r = (Blk *)(pool + o + need);
					r->size = b->size - need;
					r->used = 0;
					b->size = need;
				}
				b->used = 1;
				memset(b + 1, 0, b->size - sizeof(Blk));
				return b + 1;
			}
		}
		o += b->size;
	}
	return NULL;
}

int lm_pool_free(void *p)
{
	unsigned char *c = p;
	if (!pool || c < pool || c >= pool + pool_size)
		return 0;
	((Blk *)c - 1)->used = 0;
	return 1;
}
