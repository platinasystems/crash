/* lkcd_common.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * 12/10/99, 1.1    Fixes, new commands, support for v1 SGI dumps
 * 01/18/00, 2.0    Initial gdb merger, support for Alpha
 * 02/01/00, 2.1    Bug fixes, new commands, options, support for v2 SGI dumps
 * 02/29/00, 2.2    Bug fixes, new commands, options
 * 04/11/00, 2.3    Bug fixes, new command, options, initial PowerPC framework
 * 04/12/00  ---    Transition to BitKeeper version control
 * 
 * BitKeeper ID: @(#)sgi_lkcd.c 1.3
 *
 * 09/28/00  ---    Transition to CVS version control
 *
 * CVS: $Revision: 1.3 $ $Date: 2002/01/30 19:28:36 $
 */

/*
 *  lkcd_uncompress_RLE() is essentially LKCD's __cmpuncompress_page() rountine,
 *  adapted from ../cmd/lcrash/lib/libklib/arch/i386/kl_cmp.c:
 */

/*
 * arch/i386/cmp.c
 *
 * This file handles compression aspects of crash dump files
 * for i386 based systems.  Most of this is taken from the
 * IRIX compression code, with exceptions to how the index
 * is created, because the file format is different with Linux.
 *
 * Copyright 1999 Silicon Graphics, Inc. All rights reserved.
 */


/*
 *  This file has no knowledge of the dump_header_t, dump_header_asm_t or
 *  dump_page_t formats, so it gathers information from them via the version
 *  specific "_v1" or "_v2_v3" type routines.
 */

#define LKCD_COMMON
#include "defs.h"

static void dump_dump_page(char *, void *);
static int lkcd_uncompress_RLE(unsigned char *, unsigned char *,uint32_t,int *);
static int lkcd_uncompress_gzip(unsigned char *, ulong, unsigned char *, ulong);
static int hash_page(ulong);
static int page_is_cached(void);
static int page_is_hashed(long *);
static int cache_page(void);
static int get_closest_page(long *);

struct lkcd_environment lkcd_environment = { 0 };
struct lkcd_environment *lkcd = &lkcd_environment;

/*
 *  Each version has its own dump initialization.
 */
int
lkcd_dump_init(FILE *fp, int fd)
{
	switch (lkcd->version)
	{
        case LKCD_DUMP_V1:
		return(lkcd_dump_init_v1(fp, fd));

        case LKCD_DUMP_V2:
        case LKCD_DUMP_V3:
		return(lkcd_dump_init_v2_v3(fp, fd));

        case LKCD_DUMP_V5:
		return(lkcd_dump_init_v5(fp, fd));

	default:
		return FALSE;
	}
}

/*
 *  Return the page size value recorded in the dump header.
 */
uint32_t
lkcd_page_size(void)
{
	return lkcd->page_size;
}


/*
 *  Return the panic task and panic string.
 */
unsigned long
get_lkcd_panic_task(void)
{
	return(lkcd->flags & (LKCD_VALID|LKCD_REMOTE) ? lkcd->panic_task : 0);
}

void
get_lkcd_panicmsg(char *buf)
{
	if (lkcd->flags & (LKCD_VALID|LKCD_REMOTE))
		strcpy(buf, lkcd->panic_string);
}

/*
 *  Called by remote_lkcd_dump_init() the local (!valid) lkcd_environment
 *  is used to store the panic task and panic message for use by the
 *  two routines above.
 */ 
void
set_remote_lkcd_panic_data(ulong task, char *buf)
{
	if (buf) {
		if (!(lkcd->panic_string = (char *)malloc(strlen(buf)+1))) {
			fprintf(stderr, 
			    "cannot malloc space for panic message!\n");
			exit(1);
		}
		strcpy(lkcd->panic_string, buf);
	}

	if (task)
		lkcd->panic_task = task;

	lkcd->flags |= LKCD_REMOTE;
}

/*
 *  Does the magic number indicate an LKCD compressed dump?
 *  If so, set the version number for all future forays into the
 *  functions in this file.
 */
int
is_lkcd_compressed_dump(char *s)
{
        int tmpfd;
        uint64_t magic;
	uint32_t version;
	char errbuf[BUFSIZE];

        if ((tmpfd = open(s, O_RDONLY)) < 0) {
		strcpy(errbuf, s);
                perror(errbuf);
                return FALSE;
        }
        if (read(tmpfd, &magic, sizeof(uint64_t)) != sizeof(uint64_t)) {
                close(tmpfd);
                return FALSE;
        }
        if (read(tmpfd, &version, sizeof(uint32_t)) != sizeof(uint32_t)) {
                close(tmpfd);
                return FALSE;
        }

        close(tmpfd);

        if (!((magic == LKCD_DUMP_MAGIC_NUMBER) || 
	     (magic == LKCD_DUMP_MAGIC_LIVE)))
		return FALSE;

	switch (version & ~(LKCD_DUMP_MCLX_V0|LKCD_DUMP_MCLX_V1))
	{
	case LKCD_DUMP_V1:
		lkcd->version = LKCD_DUMP_V1;
		return TRUE;

	case LKCD_DUMP_V2:
	case LKCD_DUMP_V3:
		lkcd->version = LKCD_DUMP_V2;
		return TRUE;

	case LKCD_DUMP_V5:
		lkcd->version = LKCD_DUMP_V5;
		return TRUE;

	default:
		lkcd_print("unsupported LKCD dump version: %ld (%lx)\n", 
			version & ~(LKCD_DUMP_MCLX_V0|LKCD_DUMP_MCLX_V1), 
			version);
		return FALSE;
	}
}

/*
 *  console-only output for info regarding current page.
 */
static void
dump_dump_page(char *s, void *dp)
{
        switch (lkcd->version)
        {
        case LKCD_DUMP_V1:
                dump_dump_page_v1(s, dp);
		break;

        case LKCD_DUMP_V2:
        case LKCD_DUMP_V3:
                dump_dump_page_v2_v3(s, dp);
		break;

        case LKCD_DUMP_V5:
                dump_dump_page_v5(s, dp);
                break;
        }
}

/*
 *  help -S output, or as specified by arg.
 */
void
dump_lkcd_environment(ulong arg)
{
	int others;
	FILE *fp;

	fp = lkcd->fp;

	if (arg == LKCD_DUMP_HEADER_ONLY)
		goto dump_header_only;
	if (arg == LKCD_DUMP_PAGE_ONLY)
		goto dump_page_only;

	lkcd_print("              fd: %d\n", lkcd->fd);
	lkcd_print("              fp: %lx\n", lkcd->fp);
	lkcd_print("           debug: %ld\n", lkcd->debug);
	lkcd_print("           flags: %lx  (", lkcd->flags);
	others = 0;
	if (lkcd->flags & LKCD_VALID)
		lkcd_print("%sLKCD_VALID", others++ ? "|" : "");
	if (lkcd->flags & LKCD_REMOTE)
		lkcd_print("%sLKCD_REMOTE", others++ ? "|" : "");
	if (lkcd->flags & LKCD_NOHASH)
		lkcd_print("%sLKCD_NOHASH", others++ ? "|" : "");
        if (lkcd->flags & LKCD_MCLX)
                lkcd_print("%sLKCD_MCLX", others++ ? "|" : "");
        if (lkcd->flags & LKCD_BAD_DUMP)
                lkcd_print("%sLKCD_BAD_DUMP", others++ ? "|" : "");
	lkcd_print(")\n");

dump_header_only:
        switch (lkcd->version)
        {
        case LKCD_DUMP_V1:
                dump_lkcd_environment_v1(LKCD_DUMP_HEADER_ONLY);
                break;

        case LKCD_DUMP_V2:
        case LKCD_DUMP_V3:
                dump_lkcd_environment_v2_v3(LKCD_DUMP_HEADER_ONLY);
                break;

        case LKCD_DUMP_V5:
                dump_lkcd_environment_v5(LKCD_DUMP_HEADER_ONLY);
                break;
        }

        if (arg == LKCD_DUMP_HEADER_ONLY)
                return;

dump_page_only:
        switch (lkcd->version)
        {
        case LKCD_DUMP_V1:
                dump_lkcd_environment_v1(LKCD_DUMP_PAGE_ONLY);
                break;

        case LKCD_DUMP_V2:
        case LKCD_DUMP_V3:
                dump_lkcd_environment_v2_v3(LKCD_DUMP_PAGE_ONLY);
                break;

        case LKCD_DUMP_V5:
                dump_lkcd_environment_v5(LKCD_DUMP_PAGE_ONLY);
                break;
        }
	if (arg == LKCD_DUMP_PAGE_ONLY)
		return;

	lkcd_print("         version: %ld\n", lkcd->version);
	lkcd_print("       page_size: %ld\n", lkcd->page_size);
	lkcd_print("      page_shift: %d\n", lkcd->page_shift);
	lkcd_print("            bits: %d\n", lkcd->bits);
	lkcd_print("      panic_task: %lx\n", lkcd->panic_task);
	lkcd_print("    panic_string: %s%s", lkcd->panic_string,
		lkcd->panic_string && strstr(lkcd->panic_string, "\n") ? 
		"" : "\n");

	lkcd_print("     get_dp_size: ");
	if (lkcd->get_dp_size == get_dp_size_v1)
		lkcd_print("get_dp_size_v1()\n");
	else if (lkcd->get_dp_size == get_dp_size_v2_v3)
		lkcd_print("get_dp_size_v2_v3()\n");
        else if (lkcd->get_dp_size == get_dp_size_v5)
                lkcd_print("get_dp_size_v5()\n");
	else
		lkcd_print("%lx\n", lkcd->get_dp_size);

        lkcd_print("    get_dp_flags: ");
        if (lkcd->get_dp_flags == get_dp_flags_v1)
                lkcd_print("get_dp_flags_v1()\n");
        else if (lkcd->get_dp_flags == get_dp_flags_v2_v3)
                lkcd_print("get_dp_flags_v2_v3()\n");
        else if (lkcd->get_dp_flags == get_dp_flags_v5)
                lkcd_print("get_dp_flags_v5()\n");
        else
                lkcd_print("%lx\n", lkcd->get_dp_flags);

        lkcd_print("  get_dp_address: ");
        if (lkcd->get_dp_address == get_dp_address_v1)
                lkcd_print("get_dp_address_v1()\n");
        else if (lkcd->get_dp_address == get_dp_address_v2_v3)
                lkcd_print("get_dp_address_v2_v3()\n");
        else if (lkcd->get_dp_address == get_dp_address_v5)
                lkcd_print("get_dp_address_v5()\n");
        else
                lkcd_print("%lx\n", lkcd->get_dp_address);

	lkcd_print("     compression: ");
	lkcd_print(BITS32() ? "%lx  " : "%x  ", lkcd->compression);
	switch (lkcd->compression)
	{
	case LKCD_DUMP_COMPRESS_NONE:
		lkcd_print("(LKCD_DUMP_COMPRESS_NONE)\n");
		break;
	case LKCD_DUMP_COMPRESS_RLE:
		lkcd_print("(LKCD_DUMP_COMPRESS_RLE)\n");
		break;
	case LKCD_DUMP_COMPRESS_GZIP:
		lkcd_print("(LKCD_DUMP_COMPRESS_GZIP)\n");
		break;
	default:
		lkcd_print("(unknown)\n");
		break;
	}

	lkcd_print("page_header_size: %ld\n", lkcd->page_header_size);
	lkcd_print("          curpos: %ld\n", lkcd->curpos);
	lkcd_print("        curpaddr: ");
	lkcd_print(BITS32() ? "%llx\n" : "%lx\n", lkcd->curpaddr);
	lkcd_print("       curbufptr: %lx\n", lkcd->curbufptr);
	lkcd_print("      curhdroffs: %ld\n", lkcd->curhdroffs);
	lkcd_print("          kvbase: ");
	lkcd_print(BITS32() ? "%llx\n" : "%lx\n", lkcd->kvbase);
	lkcd_print("  page_cache_buf: %lx\n", lkcd->page_cache_buf);
	lkcd_print(" compressed_page: %lx\n", lkcd->compressed_page);
	lkcd_print("     evict_index: %d\n", lkcd->evict_index);
	lkcd_print("       evictions: %ld\n", lkcd->evictions);
	lkcd_print(" benchmark_pages: %ld\n", lkcd->benchmark_pages);
	lkcd_print(" benchmarks_done: %ld\n", lkcd->benchmarks_done);

	lkcd_memory_dump(lkcd->fp);
}

/*
 *  Set the shadow debug flag.
 */
void
set_lkcd_debug(ulong debug)
{
	lkcd->debug = debug;
}

/*
 *  Set no-hash flag bit.
 */
void 
set_lkcd_nohash(void)
{
	lkcd->flags |= LKCD_NOHASH; 
}

/*
 *  Set the file pointer for debug output.
 */
FILE *
set_lkcd_fp(FILE *fp)
{
	lkcd->fp = fp;
	return fp;
}

/*
 *  Return the number of pages cached.
 */
int
lkcd_memory_used(void)
{
	int i, pages;
        struct page_cache_hdr *sp;

        sp = &lkcd->page_cache_hdr[0];
        for (i = pages = 0; i < LKCD_CACHED_PAGES; i++, sp++) { 
		if (LKCD_VALID_PAGE(sp->pg_flags))
			pages++;
	}

	return pages;
}

/*
 *  Since the dumpfile pages are temporary tenants of a fixed page cache,
 *  this command doesn't do anything except clear the references. 
 */
int
lkcd_free_memory(void)
{
        int i, pages;
        struct page_cache_hdr *sp;

        sp = &lkcd->page_cache_hdr[0];
        for (i = pages = 0; i < LKCD_CACHED_PAGES; i++, sp++) {
                if (LKCD_VALID_PAGE(sp->pg_flags)) {
			sp->pg_addr = 0;
			sp->pg_hit_count = 0;
                        pages++;
		}
		sp->pg_flags = 0;
        }

        return pages;
}

/*
 *  Dump the page cache;
 */
int
lkcd_memory_dump(FILE *fp)
{
        int i, c, pages;
        struct page_cache_hdr *sp;
        struct page_hash_entry *phe;
	ulong pct_cached, pct_hashed;
	ulong pct_compressed, pct_raw;
	FILE *fpsave;
	char buf[BUFSIZE];
	int wrap;

	fpsave = lkcd->fp;
	lkcd->fp = fp;

        lkcd_print("     total_pages: %ld\n", lkcd->total_pages);
        pct_compressed = (lkcd->compressed*100) /
                (lkcd->hashed ? lkcd->hashed : 1);
        pct_raw = (lkcd->raw*100) /
                (lkcd->hashed ? lkcd->hashed : 1);
        lkcd_print("          hashed: %ld\n", lkcd->hashed);
        lkcd_print("      compressed: %ld (%ld%%)\n", 
		lkcd->compressed, pct_compressed);
        lkcd_print("             raw: %ld (%ld%%)\n", 
		lkcd->raw, pct_raw);
        pct_cached = (lkcd->cached_reads*100) /  
                (lkcd->total_reads ? lkcd->total_reads : 1);
        pct_hashed = (lkcd->hashed_reads*100) /
                (lkcd->total_reads ? lkcd->total_reads : 1); 
        lkcd_print("    cached_reads: %ld (%ld%%)\n", lkcd->cached_reads,
                pct_cached);
        lkcd_print("    hashed_reads: %ld (%ld%%)\n", lkcd->hashed_reads,
                pct_hashed);
        lkcd_print("     total_reads: %ld (hashed or cached: %ld%%) \n",
            lkcd->total_reads, pct_cached+pct_hashed);

        lkcd_print("page_hash[%2d]:\n", LKCD_PAGE_HASH);

	if (LKCD_DEBUG(1)) {
	        for (i = 0; i < LKCD_PAGE_HASH; i++) {
	                phe = &lkcd->page_hash[i];
	                if (!LKCD_VALID_PAGE(phe->pg_flags))
	                        continue;
	                lkcd_print("  [%2d]: ", i);
	                wrap = 0;
	                while (phe && LKCD_VALID_PAGE(phe->pg_flags)) {
				sprintf(buf, BITS32() ? "%llx@" : "%lx@",
					phe->pg_addr);
				sprintf(&buf[strlen(buf)],
	                        	"%lx,", phe->pg_hdr_offset);
				lkcd_print("%18s", buf);

	                        phe = phe->next;
	                        if (phe && (++wrap == 3)) {
	                                lkcd_print("\n        ");
	                                wrap = 0;
	                        }
	                }
	                lkcd_print("\n");
	        }
	} else {
	        for (i = 0; i < LKCD_PAGE_HASH; i++) {
	                phe = &lkcd->page_hash[i];
	                if (!LKCD_VALID_PAGE(phe->pg_flags))
	                        continue;
	                lkcd_print("  [%2d]: ", i);
	                wrap = 0;
	                while (phe && LKCD_VALID_PAGE(phe->pg_flags)) {
				lkcd_print(BITS32() ? "%9llx," : "%9lx,",
					phe->pg_addr);
	                        phe = phe->next;
	                        if (phe && (++wrap == 7)) {
	                                lkcd_print("\n        ");
	                                wrap = 0;
	                        }
	                }
	                lkcd_print("\n");
	        }
	}

        lkcd_print("page_cache_hdr[%2d]:\n", LKCD_CACHED_PAGES);
	lkcd_print(" INDEX   PG_ADDR  PG_BUFPTR");
        lkcd_print(BITS32() ? " PG_HIT_COUNT\n" : "        PG_HIT_COUNT\n");

        sp = &lkcd->page_cache_hdr[0];
        for (i = pages = 0; i < LKCD_CACHED_PAGES; i++, sp++) {
                if (LKCD_VALID_PAGE(sp->pg_flags))
                        pages++;
		if (BITS32())
                	lkcd_print("  [%2d] %9llx  %lx        %ld\n",
			    i, sp->pg_addr, sp->pg_bufptr, sp->pg_hit_count);
		else
                	lkcd_print("  [%2d] %9lx  %lx  %ld\n",
			    i, sp->pg_addr, sp->pg_bufptr, sp->pg_hit_count);
        }

	lkcd_print("mb_hdr_offsets[%3ld]: \n", lkcd->benchmark_pages);

	for (i = 0; i < lkcd->benchmark_pages; i += 8) {
		lkcd_print("  [%3d]", i);
		c = 0;
		while ((c < 8) && ((i+c) < lkcd->benchmark_pages)) {
			lkcd_print(" %8lx", lkcd->mb_hdr_offsets[i+c]);
			c++;
		}
		lkcd_print("\n");
	}

	lkcd->fp = fpsave;

        return pages;

}

/*
 *  The lkcd_lseek() routine does the bulk of the work setting things up 
 *  so that the subsequent lkcd_read() simply has to do a bcopy().

 *  Given a physical address, first determine:
 *
 *   (1) its page offset (lkcd->curpos).
 *   (2) its page address as specified in the dumpfile (lkcd->curpaddr).
 *
 *  If the page data is already cached, everything will be set up for the
 *  subsequent read when page_is_cached() returns.
 *
 *  If the page data is not cached, either of the following occurs:
 *
 *   (1) page_is_hashed() will check whether the page header offset is cached,
 *       and if so, will set up the page variable, and lseek to the header.
 *   (2) get_closest_page() will find the page header offset of the closest
 *       hashed or benchmarked page, set up the page variable, and lseek 
 *       to the page's header.
 *
 *  In either case above, the starting point for the page search is set up.
 *  Lastly, cache_page() stores the requested page's data.
 */
int
lkcd_lseek(unsigned long paddr)
{
        long i;
        int eof;
        void *dp;
        long page;
	uint64_t physaddr;

	dp = lkcd->dump_page;

	lkcd->curpos = paddr & (lkcd->page_size-1);
	lkcd->curpaddr = paddr & ~(lkcd->page_size-1);

	if (page_is_cached()) 
		return TRUE;

	if (!page_is_hashed(&page) && !get_closest_page(&page))
                return FALSE;

        for (i = page, eof = FALSE; !eof; i++) {

                switch (lkcd_load_dump_page_header(dp, i))
                {
                case LKCD_DUMPFILE_OK:
			break;

                case LKCD_DUMPFILE_END:
                case LKCD_DUMPFILE_EOF:
			eof = TRUE;
                        continue;
                }

        	physaddr = lkcd->get_dp_flags() & 
		    (LKCD_DUMP_MCLX_V0|LKCD_DUMP_MCLX_V1) ?
                    (lkcd->get_dp_address() - lkcd->kvbase) << lkcd->page_shift:
                    lkcd->get_dp_address() - lkcd->kvbase;

		if (physaddr == lkcd->curpaddr) 
			return(cache_page());

		if (physaddr > lkcd->curpaddr)
			break;

        	lseek(lkcd->fd, lkcd->get_dp_size(), SEEK_CUR);
	}

	return FALSE;
}

/*
 *  Everything's been set up by the previous lkcd_lseek(), so all that has
 *  to be done is to read the uncompressed data into the user buffer:
 *
 *    lkcd->curbufptr points to the uncompressed page base.
 *    lkcd->curpos is the offset into the buffer.
 */
long 
lkcd_read(void *buf, long count)
{
	char *p;

	lkcd->total_reads++;

	p = lkcd->curbufptr + lkcd->curpos;
	
	BCOPY(p, buf, count);
	return count;
}

/*
 *  Check whether lkcd->curpaddr is already cached.  If it is, update
 *  lkcd->curbufptr to point to the page's uncompressed data.  
 */
static int
page_is_cached(void)
{
	int i;

	for (i = 0; i < LKCD_CACHED_PAGES; i++) {

		if (!LKCD_VALID_PAGE(lkcd->page_cache_hdr[i].pg_flags))
			continue;

		if (lkcd->page_cache_hdr[i].pg_addr == lkcd->curpaddr) {
			lkcd->page_cache_hdr[i].pg_hit_count++;
			lkcd->curbufptr = lkcd->page_cache_hdr[i].pg_bufptr;
			lkcd->cached_reads++;
			return TRUE;
		}
	}

	return FALSE;
}


/*
 *  For an incoming page:
 *  
 *   (1) If it's already hashed just return TRUE.
 *   (2) If the base page_hash_entry is unused, fill it up and return TRUE;
 *   (3) Otherwise, find the last page_hash_entry on the list, allocate and
 *       fill a new one, link it on the list, and return TRUE.
 *   (4) If the malloc fails, quietly return FALSE (with no harm done).
 */
static int
hash_page(ulong type)
{
	struct page_hash_entry *phe;
	int index;

        if (lkcd->flags & LKCD_NOHASH) {
                lkcd->flags &= ~LKCD_NOHASH;
		return FALSE;
	}

	index = LKCD_PAGE_HASH_INDEX(lkcd->curpaddr);

	for (phe = &lkcd->page_hash[index]; LKCD_VALID_PAGE(phe->pg_flags); 
	     phe = phe->next) {
		if (phe->pg_addr == lkcd->curpaddr)
			return TRUE;
		if (!phe->next)
			break;
	}

	if (LKCD_VALID_PAGE(phe->pg_flags)) {
		if ((phe->next = malloc
		    (sizeof(struct page_hash_entry))) == NULL)
			return FALSE;
		phe = phe->next;
	}

	phe->pg_flags |= LKCD_VALID;
	phe->pg_addr = lkcd->curpaddr;
	phe->pg_hdr_offset = lkcd->curhdroffs;
	phe->next = NULL;

	lkcd->hashed++;
	switch (type)
	{
	case LKCD_DUMP_COMPRESSED:
		lkcd->compressed++;
		break;
	case LKCD_DUMP_RAW:
		lkcd->raw++;
		break;
	}

	return TRUE;
}

/*
 *  Check whether a page is currently hashed, and if so, return the page
 *  number so that the subsequent search loop will find it immediately.
 */
static int
page_is_hashed(long *pp)
{
	struct page_hash_entry *phe;
	int index;

	index = LKCD_PAGE_HASH_INDEX(lkcd->curpaddr);

	for (phe = &lkcd->page_hash[index]; LKCD_VALID_PAGE(phe->pg_flags); 
	     phe = phe->next) {
		if (phe->pg_addr == lkcd->curpaddr) {
			*pp = (long)(lkcd->curpaddr >> lkcd->page_shift);
			lseek(lkcd->fd, phe->pg_hdr_offset, SEEK_SET);
			lkcd->hashed_reads++;
			return TRUE;
		}
		if (!phe->next)
			break;
	}

	return FALSE;

}

/*
 *  Given lkcd->curpaddr, first find the closest lower hashed page, if any,
 *  and then find its associated benchmark page.  Take whichever is closer,
 *  lseek to it, and return its page number.
 */
static int
get_closest_page(long *pp)
{
        int i;
        struct page_hash_entry *phe, *phe_closest;
        uint64_t curdiff;
	long mb, page, mb_page, phe_page;

        curdiff = lkcd->curpaddr;
        phe_closest = NULL;

        for (i = 0; i < LKCD_PAGE_HASH; i++) {
                for (phe = &lkcd->page_hash[i]; LKCD_VALID_PAGE(phe->pg_flags);
                     phe = phe->next) {
                        if (phe->pg_addr < lkcd->curpaddr) {
                                if ((lkcd->curpaddr - phe->pg_addr) < curdiff) {
                                        curdiff = lkcd->curpaddr - phe->pg_addr;
                                        phe_closest = phe;
                                }
                        }
                        if (!phe->next)
                                break;
                }
        }

	page = (long)(lkcd->curpaddr >> lkcd->page_shift);

	if ((mb = LKCD_PAGE_MEGABYTE(page)) >= lkcd->benchmark_pages)
		mb = lkcd->benchmark_pages - 1;

	for (/* mb setup above */; !lkcd->mb_hdr_offsets[mb]; mb--) {
		if (mb < 0) 
			return FALSE;
        }

	mb_page = mb * LKCD_PAGES_PER_MEGABYTE();
	phe_page = phe_closest ? 
		(long)(phe_closest->pg_addr >> lkcd->page_shift) : 0;

	if (phe_page > mb_page) {
		*pp = phe_page;
                 lseek(lkcd->fd, phe_closest->pg_hdr_offset, SEEK_SET);
	} else {
		*pp = mb_page;
        	lseek(lkcd->fd, lkcd->mb_hdr_offsets[mb], SEEK_SET);
	}

	return TRUE;
}

/*
 *  The caller stores the incoming page's page header offset in 
 *  lkcd->curhdroffs.
 */
int
set_mb_benchmark(ulong page)
{
	long mb;

	if ((mb = LKCD_PAGE_MEGABYTE(page)) >= lkcd->benchmark_pages)
		return FALSE;

        if (!lkcd->mb_hdr_offsets[mb]) {
        	lkcd->mb_hdr_offsets[mb] = lkcd->curhdroffs;
		lkcd->benchmarks_done++;
	}

	return TRUE;
}
	
/*
 *  Coming into this routine:
 *
 *   (1) lkcd->curpaddr points to the page address as specified in the dumpfile.
 *   (2) the dump_page header has been copied into lkcd->dump_page.
 *   (3) the file pointer is sitting at the beginning of the page data,
 *       be it compressed or otherwise.
 *   (4) lkcd->curhdroffs contains the file pointer to the incoming page's
 *       header offset.
 *
 *  If an empty page cache location is available, take it.  Otherwise, evict
 *  the entry indexed by evict_index, and then bump evict index.  The hit_count
 *  is only gathered for dump_lkcd_environment().
 *
 *  If the page is compressed, uncompress it into the selected page cache entry.
 *  If the page is raw, just copy it into the selected page cache entry.
 *  If all works OK, update lkcd->curbufptr to point to the page's uncompressed
 *  data.
 *
 */
static int
cache_page(void)
{
	int i;
	ulong type;
	int found, newsz;
	uint32_t rawsz;

        for (i = found = 0; i < LKCD_CACHED_PAGES; i++) {
                if (LKCD_VALID_PAGE(lkcd->page_cache_hdr[i].pg_flags))
                        continue;
		found = TRUE;
		break;
        }

	if (!found) {
                i = lkcd->evict_index;
		lkcd->page_cache_hdr[i].pg_hit_count = 0;
                lkcd->evict_index = (lkcd->evict_index+1) % LKCD_CACHED_PAGES;
                lkcd->evictions++;
	}

        lkcd->page_cache_hdr[i].pg_flags = 0;
        lkcd->page_cache_hdr[i].pg_addr = lkcd->curpaddr;
	lkcd->page_cache_hdr[i].pg_hit_count++;

	type = lkcd->get_dp_flags() & (LKCD_DUMP_COMPRESSED|LKCD_DUMP_RAW);

	switch (type)
	{
	case LKCD_DUMP_COMPRESSED:
		if (LKCD_DEBUG(2)) 
			dump_dump_page("cmp: ", lkcd->dump_page);
		
		newsz = 0;
		BZERO(lkcd->compressed_page, lkcd->page_size);
                read(lkcd->fd, lkcd->compressed_page, lkcd->get_dp_size());

		switch (lkcd->compression)
		{
		case LKCD_DUMP_COMPRESS_NONE:
			lkcd_print("dump_header: DUMP_COMPRESS_NONE and "
			          "dump_page: DUMP_COMPRESSED (?)\n");
			return FALSE;

		case LKCD_DUMP_COMPRESS_RLE:
			if (!lkcd_uncompress_RLE((unsigned char *)
			    lkcd->compressed_page,
			    (unsigned char *)lkcd->page_cache_hdr[i].pg_bufptr, 	
			    lkcd->get_dp_size(), &newsz) || 
			    (newsz != lkcd->page_size)) {
				lkcd_print("uncompress of page ");
				lkcd_print(BITS32() ? 
					"%llx failed!\n" : "%lx failed!\n",
					lkcd->get_dp_address());
				lkcd_print("newsz returned: %d\n", newsz);
				return FALSE;
			}
			break;

		case LKCD_DUMP_COMPRESS_GZIP:
			if (!lkcd_uncompress_gzip((unsigned char *)
			    lkcd->page_cache_hdr[i].pg_bufptr, lkcd->page_size,
			    lkcd->compressed_page, lkcd->get_dp_size())) {
                                lkcd_print("uncompress of page ");
                                lkcd_print(BITS32() ? 
                                        "%llx failed!\n" : "%lx failed!\n",
                                        lkcd->get_dp_address());
				return FALSE;
			}
			break;
		}

		break;

	case LKCD_DUMP_RAW:
		if (LKCD_DEBUG(2)) 
			dump_dump_page("raw: ", lkcd->dump_page);
		if ((rawsz = lkcd->get_dp_size()) == 0)
			BZERO(lkcd->page_cache_hdr[i].pg_bufptr, 
				lkcd->page_size);
		else if (rawsz == lkcd->page_size)
			read(lkcd->fd, lkcd->page_cache_hdr[i].pg_bufptr, 
				lkcd->page_size);
		else {
			lkcd_print("cache_page: "
		        	"invalid LKCD_DUMP_RAW dp_size\n");
			dump_lkcd_environment(LKCD_DUMP_PAGE_ONLY);
			return FALSE;
		}
		break;

	default:
		lkcd_print("cache_page: bogus page:\n");
		dump_lkcd_environment(LKCD_DUMP_PAGE_ONLY);
		return FALSE;
	}

        lkcd->page_cache_hdr[i].pg_flags |= LKCD_VALID;
	lkcd->curbufptr = lkcd->page_cache_hdr[i].pg_bufptr;

	hash_page(type);

	return TRUE;
}

/*
 *  Uncompress an RLE-encoded buffer.
 */
static int
lkcd_uncompress_RLE(unsigned char *cbuf, unsigned char *ucbuf, 
	       uint32_t blk_size, int *new_size)
{
        int i;
        unsigned char value, count, cur_byte;
        uint32_t ri, wi;

        /* initialize the read / write indices */
        ri = wi = 0;

        /* otherwise decompress using run length encoding */
        while(ri < blk_size) {
                cur_byte = cbuf[ri++];
                if (cur_byte == 0) {
                        count = cbuf[ri++];
                        if (count == 0) {
                                ucbuf[wi++] = 0;
                        } else {
                                value = cbuf[ri++];
                                for (i = 0; i <= count; i++) {
                                        ucbuf[wi++] = value;
                                }
                        }
                } else {
                        ucbuf[wi++] = cur_byte;
                }

                /* if our write index is beyond the page size, exit out */
                if (wi > /* PAGE_SIZE */ lkcd->page_size) {
			lkcd_print( 
           "Attempted to decompress beyond page boundaries: file corrupted!\n");
                        return (0);
                }
        }

        /* set return size to be equal to uncompressed size (in bytes) */
        *new_size = wi;

        return 1;
}

/*
 *  Uncompress a gzip'd buffer.
 */
static int 
lkcd_uncompress_gzip(unsigned char *dest, ulong destlen, 
	unsigned char *source, ulong sourcelen)
{
	ulong retlen;

	switch (uncompress(dest, &retlen, source, sourcelen)) 
	{
	case Z_OK:
		if (retlen == destlen)
			return TRUE;

		lkcd_print("uncompress: returned length not page size: %ld\n",
				retlen);
		return FALSE;

	case Z_MEM_ERROR:
		lkcd_print("uncompress: Z_MEM_ERROR (not enough memory)\n");
		return FALSE;

	case Z_BUF_ERROR:
		lkcd_print("uncompress: "
			"Z_BUF_ERROR (not enough room in output buffer)\n");
		return FALSE;

	case Z_DATA_ERROR:
		lkcd_print("uncompress: Z_DATA_ERROR (input data corrupted)\n");
		return FALSE;
	}

	return FALSE;
}


/*
 *  Generic print routine to handle integral and remote daemon usage of
 */
void 
lkcd_print(char *fmt, ...)
{
	char buf[BUFSIZE];
	va_list ap;

        if (!fmt || !strlen(fmt))
                return;

        va_start(ap, fmt);
        (void)vsnprintf(buf, BUFSIZE, fmt, ap);
        va_end(ap);

	if (lkcd->fp)
		fprintf(lkcd->fp, buf);
	else
		console(buf);
}

/*
 *  Try to read the current dump page header, reporting back either
 *  LKCD_DUMPFILE_EOF, LKCD_DUMPFILE_END or LKCD_DUMPFILE_OK.  The header's
 *  file pointer position is saved in lkcd->curhdroffs.  If the page is
 *  an even megabyte, save its offset.
 */
int
lkcd_load_dump_page_header(void *dp, ulong page)
{
	uint32_t dp_flags;
	uint64_t dp_address, physaddr;

        lkcd->curhdroffs = lseek(lkcd->fd, 0, SEEK_CUR);

        if (read(lkcd->fd, dp, lkcd->page_header_size) != 
	    lkcd->page_header_size) {
		if (page > lkcd->total_pages) 
			lkcd_dumpfile_complaint(page, lkcd->total_pages, 
				LKCD_DUMPFILE_EOF);
                return LKCD_DUMPFILE_EOF;
	}

	dp_flags = lkcd->get_dp_flags();
	dp_address = lkcd->get_dp_address();

        if (dp_flags & LKCD_DUMP_END)
                return LKCD_DUMPFILE_END;

	if ((lkcd->flags & LKCD_VALID) && (page > lkcd->total_pages)) 
		lkcd->total_pages = page;

        if (page == 0)
        	lkcd->kvbase = dp_address;

	physaddr = dp_flags & (LKCD_DUMP_MCLX_V0|LKCD_DUMP_MCLX_V1) ?
		(dp_address - lkcd->kvbase) << lkcd->page_shift : 
        	dp_address - lkcd->kvbase;

        if (MEGABYTE_ALIGNED(physaddr) && !LKCD_BENCHMARKS_DONE()) 
                set_mb_benchmark((ulong)(physaddr >> lkcd->page_shift));

        return LKCD_DUMPFILE_OK;
}

/*
 *  Register a complaint one time, if appropriate.
 */
void
lkcd_dumpfile_complaint(uint32_t realpages, uint32_t dh_num_pages, int retval)
{
	if (lkcd->flags & LKCD_BAD_DUMP)
		return;
	
	lkcd->flags |= LKCD_BAD_DUMP;

	if (realpages > dh_num_pages) {
		lkcd_print(
"\n\nWARNING: This dumpfile contains more pages than the amount indicated\n"
"         in the dumpfile header.  This is indicative of a failure during\n"
"         the post-panic creation of the dumpfile on the dump device.\n\n");
	}

	if (realpages < dh_num_pages) {
		lkcd_print(
"\n\nWARNING: This dumpfile contains fewer pages than the amount indicated\n"
"         in the dumpfile header.  This is indicative of a failure during\n"
"         the creation of the dumpfile during boot.\n\n");
	}
}

