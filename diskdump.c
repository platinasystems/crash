/* 
 * diskdump.c 
 * 
 * The diskdump module optionally creates either ELF vmcore 
 * dumpfiles, or compressed dumpfiles derived from the LKCD format.
 * In the case of ELF vmcore files, since they are identical to 
 * netdump dumpfiles, the facilities in netdump.c are used.  For
 * compressed dumpfiles, the facilities in this file are used.
 *
 * Copyright (C) 2004, 2005, 2006, 2007, 2008 David Anderson
 * Copyright (C) 2004, 2005, 2006, 2007, 2008 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2005  FUJITSU LIMITED
 * Copyright (C) 2005  NEC Corporation
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
 */

#include "defs.h"
#include "diskdump.h"

#define BITMAP_SECT_LEN	4096

struct diskdump_data {
	char *filename;
	ulong flags;       /* DISKDUMP_LOCAL, plus anything else... */
        int dfd;           /* dumpfile file descriptor */
        FILE *ofp;         /* fprintf(dd->ofp, "xxx"); */
	int machine_type;  /* machine type identifier */

	/* header */
	struct disk_dump_header		*header;
	struct disk_dump_sub_header	*sub_header;
	struct kdump_sub_header		*sub_header_kdump;

	size_t	data_offset;
	int	block_size;
	int	block_shift;
	char	*bitmap;
	int	bitmap_len;
	char	*dumpable_bitmap;
	int	byte, bit;
	char	*compressed_page;	/* copy of compressed page data */
	char	*curbufptr;		/* ptr to uncompressed page buffer */

	/* page cache */
	struct page_cache_hdr {		/* header for each cached page */
		uint32_t pg_flags;
		uint64_t pg_addr;
		char *pg_bufptr;
		ulong pg_hit_count;
	} page_cache_hdr[DISKDUMP_CACHED_PAGES];
	char	*page_cache_buf;	/* base of cached buffer pages */
	int	evict_index;		/* next page to evict */
	ulong	evictions;		/* total evictions done */
	ulong	cached_reads;
	ulong  *valid_pages;
	ulong   accesses;
};

static struct diskdump_data diskdump_data = { 0 };
static struct diskdump_data *dd = &diskdump_data;
static int get_dump_level(void);

ulong *diskdump_flags = &diskdump_data.flags;

static int __diskdump_memory_dump(FILE *);

/* For split dumpfile */
static struct diskdump_data **dd_list = NULL;
static int num_dd = 0;
static int num_dumpfiles = 0;

int dumpfile_is_split(void)
{
	return KDUMP_SPLIT();
}

static void add_diskdump_data(char* name)
{
#define DDL_SIZE 16
	int i;
	int sz = sizeof(void*);
	struct diskdump_data *ddp;

	if (dd_list == NULL) {
		dd_list = calloc(DDL_SIZE, sz);
		num_dd = DDL_SIZE;
	} else {
		for (i = 0; i < num_dumpfiles; i++) {
			ddp = dd_list[i];
                	if (same_file(ddp->filename, name))
				error(FATAL, 
				    "split dumpfiles are identical:\n"
				    "  %s\n  %s\n",
					ddp->filename, name);
			if (memcmp(ddp->header, dd->header,
			    sizeof(struct disk_dump_header)))
				error(FATAL, 
				    "split dumpfiles derived from different vmcores:\n"
				    "  %s\n  %s\n",
					ddp->filename, name);
		}
	}

	if (num_dumpfiles == num_dd) {
		/* expand list */
		struct diskdump_data **tmp;
		tmp = calloc(num_dd*2, sz);
		memcpy(tmp, dd_list, sz*num_dd);
		free(dd_list);
		dd_list = tmp;
		num_dd *= 2;
	}

	dd_list[num_dumpfiles] = dd;
	dd->flags |= DUMPFILE_SPLIT;
	dd->filename = name;

	if (CRASHDEBUG(1))
		fprintf(fp, "%s: start_pfn=%lu, end_pfn=%lu\n", name,
			dd->sub_header_kdump->start_pfn,
			dd->sub_header_kdump->end_pfn);
}

static void clean_diskdump_data(void)
{
	int i;

	if (dd_list == NULL)
		return;

	for (i=1; i<num_dumpfiles; i++)
		free(dd_list[i]); /* NOTE: dd_list[0] is static dd */

	free(dd_list);
	dd_list = NULL;
	num_dumpfiles = 0;
	dd = &diskdump_data;
}

static inline int get_bit(char *map, int byte, int bit)
{
	return map[byte] & (1<<bit);
}

static inline int page_is_ram(unsigned int nr)
{
	return get_bit(dd->bitmap, nr >> 3, nr & 7);
}

static inline int page_is_dumpable(unsigned int nr)
{
	return dd->dumpable_bitmap[nr>>3] & (1 << (nr & 7));
}

static inline int dump_is_partial(const struct disk_dump_header *header)
{
	return header->bitmap_blocks >=
	    divideup(divideup(header->max_mapnr, 8), dd->block_size) * 2;
}

static int open_dump_file(char *file)
{
	int fd;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		error(INFO, "diskdump / compressed kdump: unable to open dump file %s", file);
		return FALSE;
	}

	if (KDUMP_SPLIT())
		dd = calloc(1, sizeof(*dd));

	dd->dfd = fd;
	return TRUE;
}

static int read_dump_header(char *file)
{
	struct disk_dump_header *header = NULL;
	struct disk_dump_sub_header *sub_header = NULL;
	struct kdump_sub_header *sub_header_kdump = NULL;
	int bitmap_len;
	int block_size = (int)sysconf(_SC_PAGESIZE);
	off_t offset;
	const off_t failed = (off_t)-1;
	ulong pfn;
	int i, j, max_sect_len;
	int is_split = 0;

	if (block_size < 0)
		return FALSE;

restart:
	if ((header = realloc(header, block_size)) == NULL)
		error(FATAL, "diskdump / compressed kdump: cannot malloc block_size buffer\n");

	if (lseek(dd->dfd, 0, SEEK_SET) == failed) {
		if (CRASHDEBUG(1))
			error(INFO, "diskdump / compressed kdump: cannot lseek dump header\n");
		goto err;
	}

	if (read(dd->dfd, header, block_size) < block_size) {
		if (CRASHDEBUG(1))
			error(INFO, "diskdump / compressed kdump: cannot read dump header\n");
		goto err;
	}

	/* validate dump header */
	if (!memcmp(header->signature, DISK_DUMP_SIGNATURE,
				sizeof(header->signature))) {
		dd->flags |= DISKDUMP_LOCAL;
	} else if (!memcmp(header->signature, KDUMP_SIGNATURE,
				sizeof(header->signature))) {
		dd->flags |= KDUMP_CMPRS_LOCAL;
		if (header->header_version >= 1)
			dd->flags |= ERROR_EXCLUDED;
	} else {
		if (CRASHDEBUG(1))
			error(INFO, 
			    "diskdump / compressed kdump: dump does not have panic dump header\n");
		goto err;
	}

	if (CRASHDEBUG(1))
		fprintf(fp, "%s: header->utsname.machine: %s\n", 
			DISKDUMP_VALID() ? "diskdump" : "compressed kdump",
			header->utsname.machine);

	if (STRNEQ(header->utsname.machine, "i686") &&
	    machine_type_mismatch(file, "X86", NULL, 0))
		goto err;
	else if (STRNEQ(header->utsname.machine, "x86_64") &&
	    machine_type_mismatch(file, "X86_64", NULL, 0))
		goto err;
	else if (STRNEQ(header->utsname.machine, "ia64") &&
	    machine_type_mismatch(file, "IA64", NULL, 0))
		goto err;
	else if (STRNEQ(header->utsname.machine, "ppc64") &&
	    machine_type_mismatch(file, "PPC64", NULL, 0))
		goto err;

	if (header->block_size != block_size) {
		block_size = header->block_size;
		if (CRASHDEBUG(1))
			fprintf(fp, 
			    "retrying with different block/page size: %d\n", 
				header->block_size);
		goto restart;
	}
	dd->block_size  = header->block_size;
	dd->block_shift = ffs(header->block_size) - 1;

	if (sizeof(*header) + sizeof(void *) * header->nr_cpus > block_size ||
	    header->nr_cpus <= 0) {
		error(INFO, "%s: invalid nr_cpus value: %d\n", 
			DISKDUMP_VALID() ? "diskdump" : "compressed kdump",
			header->nr_cpus);
		goto err;
	}

	/* read sub header */
	offset = (off_t)block_size;
	if (lseek(dd->dfd, offset, SEEK_SET) == failed) {
		error(INFO, "%s: cannot lseek dump sub header\n",
			DISKDUMP_VALID() ? "diskdump" : "compressed kdump");

		goto err;
	}

	if (DISKDUMP_VALID()) {
		if ((sub_header = malloc(block_size)) == NULL)
			error(FATAL, "diskdump: cannot malloc sub_header buffer\n");

		if (read(dd->dfd, sub_header, block_size)
		  < block_size) {
			error(INFO, "diskdump: cannot read dump sub header\n");
			goto err;
		}
		dd->sub_header = sub_header;
	} else if (KDUMP_CMPRS_VALID()) {
		if ((sub_header_kdump = malloc(block_size)) == NULL)
			error(FATAL, "compressed kdump: cannot malloc sub_header_kdump buffer\n");

		if (read(dd->dfd, sub_header_kdump, block_size)
		  < block_size) {
			error(INFO, "compressed kdump: cannot read dump sub header\n");
			goto err;
		}
		dd->sub_header_kdump = sub_header_kdump;
	}

	/* read memory bitmap */
	bitmap_len = block_size * header->bitmap_blocks;
	dd->bitmap_len = bitmap_len;

	offset = (off_t)block_size * (1 + header->sub_hdr_size);
	if (lseek(dd->dfd, offset, SEEK_SET) == failed) {
		error(INFO, "%s: cannot lseek memory bitmap\n",
			DISKDUMP_VALID() ? "diskdump" : "compressed kdump");

		goto err;
	}

	if ((dd->bitmap = malloc(bitmap_len)) == NULL)
		error(FATAL, "%s: cannot malloc bitmap buffer\n",
			DISKDUMP_VALID() ? "diskdump" : "compressed kdump");

	dd->dumpable_bitmap = calloc(bitmap_len, 1);
	if (read(dd->dfd, dd->bitmap, bitmap_len) < bitmap_len) {
		error(INFO, "%s: cannot read memory bitmap\n",
			DISKDUMP_VALID() ? "diskdump" : "compressed kdump");
		goto err;
	}

	if (dump_is_partial(header))
		memcpy(dd->dumpable_bitmap, dd->bitmap + bitmap_len/2,
		       bitmap_len/2);
	else
		memcpy(dd->dumpable_bitmap, dd->bitmap, bitmap_len);

	dd->data_offset
		= (1 + header->sub_hdr_size + header->bitmap_blocks)
		* header->block_size;

	dd->header = header;

	if (machine_type("X86"))
		dd->machine_type = EM_386;
	else if (machine_type("X86_64"))
		dd->machine_type = EM_X86_64;
	else if (machine_type("IA64"))
		dd->machine_type = EM_IA_64;
	else if (machine_type("PPC64"))
		dd->machine_type = EM_PPC64;
	else {
		error(INFO, "%s: unsupported machine type: %s\n", 
			DISKDUMP_VALID() ? "diskdump" : "compressed kdump",
			MACHINE_TYPE);
		goto err;
	}

	/* For split dumpfile */
	if (KDUMP_CMPRS_VALID()) {
		is_split = ((dd->header->header_version >= 2) &&
		            (sub_header_kdump->split));

		if ((is_split && (num_dumpfiles != 0) && (dd_list == NULL))||
		    (!is_split && (num_dumpfiles != 0))) {
			clean_diskdump_data();
			goto err;
		}

		if (is_split)
			add_diskdump_data(file);

		num_dumpfiles++;
	}

	if (!is_split) {
		max_sect_len = divideup(header->max_mapnr, BITMAP_SECT_LEN);
		pfn = 0;
	}
	else {
		ulong start = sub_header_kdump->start_pfn;
		ulong end = sub_header_kdump->end_pfn;
		max_sect_len = divideup(end - start + 1, BITMAP_SECT_LEN);
		pfn = start;
	}

	dd->valid_pages = calloc(sizeof(ulong), max_sect_len + 1);
	for (i = 1; i < max_sect_len + 1; i++) {
		dd->valid_pages[i] = dd->valid_pages[i - 1];
		for (j = 0; j < BITMAP_SECT_LEN; j++, pfn++)
			if (page_is_dumpable(pfn))
				dd->valid_pages[i]++;
	}

        return TRUE;

err:
	free(header);
	if (sub_header)
		free(sub_header);
	if (sub_header_kdump)
		free(sub_header_kdump);
	if (dd->bitmap)
		free(dd->bitmap);
	if (dd->dumpable_bitmap)
		free(dd->dumpable_bitmap);
	dd->flags &= ~(DISKDUMP_LOCAL|KDUMP_CMPRS_LOCAL);
	return FALSE;
}

static ulong
pfn_to_pos(ulong pfn)
{
	ulong desc_pos, j, valid;
	ulong p1, p2;

	if (KDUMP_SPLIT()) {
		p1 = pfn - dd->sub_header_kdump->start_pfn;
		p2 = round(p1, BITMAP_SECT_LEN) + dd->sub_header_kdump->start_pfn;
	}
	else {
		p1 = pfn; 
		p2 = round(pfn, BITMAP_SECT_LEN); 
	}

	valid = dd->valid_pages[p1 / BITMAP_SECT_LEN];

	for (j = p2, desc_pos = valid; j <= pfn; j++)
			if (page_is_dumpable(j))
				desc_pos++;

	return desc_pos;
}


/*
 *  Determine whether a file is a diskdump creation, and if TRUE,
 *  initialize the diskdump_data structure based upon the contents
 *  of the diskdump header data.
 */
int
is_diskdump(char *file)
{
	int sz, i;

	if (!open_dump_file(file) || !read_dump_header(file))
		return FALSE;

	sz = dd->block_size * (DISKDUMP_CACHED_PAGES);
	if ((dd->page_cache_buf = malloc(sz)) == NULL)
		error(FATAL, "%s: cannot malloc compressed page_cache_buf\n",
			DISKDUMP_VALID() ? "diskdump" : "compressed kdump");

	for (i = 0; i < DISKDUMP_CACHED_PAGES; i++)
		dd->page_cache_hdr[i].pg_bufptr =
			&dd->page_cache_buf[i * dd->block_size];

	if ((dd->compressed_page = (char *)malloc(dd->block_size)) == NULL)
		error(FATAL, "%s: cannot malloc compressed page space\n",
			DISKDUMP_VALID() ? "diskdump" : "compressed kdump");

	if (CRASHDEBUG(1))
		__diskdump_memory_dump(fp);

	return TRUE;
}

/*
 *  Perform any post-dumpfile determination stuff here.
 *  At a minimum
 */
int
diskdump_init(char *unused, FILE *fptr)
{
	if (!DISKDUMP_VALID() && !KDUMP_CMPRS_VALID())
		return FALSE;

	dd->ofp = fptr;
	return TRUE;
}

/*
 *  Get the relocational offset from the sub header of kdump.
 */
int
diskdump_phys_base(unsigned long *phys_base)
{
	if (KDUMP_CMPRS_VALID()) {
		*phys_base = dd->sub_header_kdump->phys_base;
		return TRUE;
	}

	return FALSE;
}

/*
 *  Check whether paddr is already cached.
 */
static int
page_is_cached(physaddr_t paddr)
{
	int i;
	struct page_cache_hdr *pgc;

	dd->accesses++;

	for (i = 0; i < DISKDUMP_CACHED_PAGES; i++) {

		pgc = &dd->page_cache_hdr[i];

		if (!DISKDUMP_VALID_PAGE(pgc->pg_flags))
			continue;

		if (pgc->pg_addr == paddr) {
			pgc->pg_hit_count++;
			dd->curbufptr = pgc->pg_bufptr;
			dd->cached_reads++;
			return TRUE;
		}
	}
	return FALSE;
}

/*
 *  Cache the page's data.
 *
 *  If an empty page cache location is available, take it.  Otherwise, evict
 *  the entry indexed by evict_index, and then bump evict index.  The hit_count
 *  is only gathered for dump_diskdump_environment().
 *
 *  If the page is compressed, uncompress it into the selected page cache entry.
 *  If the page is raw, just copy it into the selected page cache entry.
 *  If all works OK, update diskdump->curbufptr to point to the page's
 *  uncompressed data.
 */
static int
cache_page(physaddr_t paddr)
{
	int i, ret;
	int found;
	ulong pfn;
	ulong desc_pos;
	off_t seek_offset;
	page_desc_t pd;
	const int block_size = dd->block_size;
	const off_t failed = (off_t)-1;
	ulong retlen;

	for (i = found = 0; i < DISKDUMP_CACHED_PAGES; i++) {
		if (DISKDUMP_VALID_PAGE(dd->page_cache_hdr[i].pg_flags))
			continue;
		found = TRUE;
		break;
	}

	if (!found) {
		i = dd->evict_index;
		dd->page_cache_hdr[i].pg_hit_count = 0;
		dd->evict_index =
			(dd->evict_index+1) % DISKDUMP_CACHED_PAGES;
		dd->evictions++;
	}

	dd->page_cache_hdr[i].pg_flags = 0;
	dd->page_cache_hdr[i].pg_addr = paddr;
	dd->page_cache_hdr[i].pg_hit_count++;

	/* find page descriptor */
	pfn = paddr >> dd->block_shift;
	desc_pos = pfn_to_pos(pfn);
	seek_offset = dd->data_offset
			+ (off_t)(desc_pos - 1)*sizeof(page_desc_t);
	lseek(dd->dfd, seek_offset, SEEK_SET);

	/* read page descriptor */
	if (read(dd->dfd, &pd, sizeof(pd)) != sizeof(pd))
		return READ_ERROR;

	/* sanity check */
	if (pd.size > block_size)
		return READ_ERROR;

	if (lseek(dd->dfd, pd.offset, SEEK_SET) == failed)
		return SEEK_ERROR;

	/* read page data */
	if (read(dd->dfd, dd->compressed_page, pd.size) != pd.size)
		return READ_ERROR;

	if (pd.flags & DUMP_DH_COMPRESSED) {
		retlen = block_size;
		ret = uncompress((unsigned char *)dd->page_cache_hdr[i].pg_bufptr,
		                 &retlen,
		                 (unsigned char *)dd->compressed_page,
		                 pd.size);
		if ((ret != Z_OK) || (retlen != block_size)) {
			error(INFO, "%s: uncompress failed: %d\n", 
				DISKDUMP_VALID() ? "diskdump" : "compressed kdump",
				ret);
			return READ_ERROR;
		}
	} else
		memcpy(dd->page_cache_hdr[i].pg_bufptr,
		       dd->compressed_page, block_size);

	dd->page_cache_hdr[i].pg_flags |= PAGE_VALID;
	dd->curbufptr = dd->page_cache_hdr[i].pg_bufptr;

	return TRUE;
}

/*
 *  Read from a diskdump-created dumpfile.
 */
int
read_diskdump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	int ret;
	physaddr_t curpaddr;
	ulong pfn, page_offset;

	pfn = paddr >> dd->block_shift;

	if (KDUMP_SPLIT()) {
		/* Find proper dd */
		int i;
		unsigned long start_pfn;
		unsigned long end_pfn;

		for (i=0; i<num_dumpfiles; i++) {
			start_pfn = dd_list[i]->sub_header_kdump->start_pfn;
			end_pfn = dd_list[i]->sub_header_kdump->end_pfn;
			if ((pfn >= start_pfn) && (pfn <= end_pfn))	{
				dd = dd_list[i];
				break;
			}
		}

		if (i == num_dumpfiles)
			return SEEK_ERROR;
	}

	curpaddr = paddr & ~((physaddr_t)(dd->block_size-1));
	page_offset = paddr & ((physaddr_t)(dd->block_size-1));

	if ((pfn >= dd->header->max_mapnr) || !page_is_ram(pfn))
		return SEEK_ERROR;
	if (!page_is_dumpable(pfn)) {
		if ((dd->flags & (ZERO_EXCLUDED|ERROR_EXCLUDED)) ==
		    ERROR_EXCLUDED)
			return PAGE_EXCLUDED;
		memset(bufptr, 0, cnt);
		return cnt;
	}

	if (!page_is_cached(curpaddr))
		if ((ret = cache_page(curpaddr)) < 0)
			return ret;
	
	memcpy(bufptr, dd->curbufptr + page_offset, cnt);

	return cnt;
}

/*
 *  Write to a diskdump-created dumpfile.
 */
int
write_diskdump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	return 0;
}

ulong
get_diskdump_panic_task(void)
{
	if ((!DISKDUMP_VALID() && !KDUMP_CMPRS_VALID())
	    || !get_active_set())
		return NO_TASK;

	return (ulong)dd->header->tasks[dd->header->current_cpu];
}

extern  void get_netdump_regs_x86(struct bt_info *, ulong *, ulong *);
extern void get_netdump_regs_x86_64(struct bt_info *, ulong *, ulong *);

static void
get_diskdump_regs_ppc64(struct bt_info *bt, ulong *eip, ulong *esp)
{
	if ((bt->task == tt->panic_task) && DISKDUMP_VALID())
		bt->machdep = &dd->sub_header->elf_regs;

	machdep->get_stack_frame(bt, eip, esp);
}

/*
 *  Send the request to the proper architecture hander.
 */

void
get_diskdump_regs(struct bt_info *bt, ulong *eip, ulong *esp)
{
	switch (dd->machine_type) 
	{
	case EM_386:
		return get_netdump_regs_x86(bt, eip, esp);
		break;

	case EM_IA_64:
	       /* For normal backtraces, this information will be obtained
		* frome the switch_stack structure, which is pointed to by
		* the thread.ksp field of the task_struct. But it's still
		* needed by the "bt -t" option.
		*/
		machdep->get_stack_frame(bt, eip, esp);
		break;

	case EM_PPC64:
		return get_diskdump_regs_ppc64(bt, eip, esp);
		break;

	case EM_X86_64:
		return get_netdump_regs_x86_64(bt, eip, esp);
		break;

	default:
		error(FATAL, "%s: unsupported machine type: %s\n",
			DISKDUMP_VALID() ? "diskdump" : "compressed kdump",
			MACHINE_TYPE);

	}
}

/*
 *  Return the processor page size.
 */
uint
diskdump_page_size(void)
{
	if (!DISKDUMP_VALID() && !KDUMP_CMPRS_VALID())
		return 0;

	return dd->header->block_size;
}

/*
 *  diskdump_free_memory(), and diskdump_memory_used() 
 *  are debug only, and probably unnecessary to implement.
 */
int
diskdump_free_memory(void)
{
        return 0;
}

int diskdump_memory_used(void)
{
        return 0;
}

/*
 *  This function is dump-type independent, and could be used
 *  to dump the diskdump_data structure contents and perhaps
 *  the diskdump header data.
 */
int
__diskdump_memory_dump(FILE *fp)
{
	int i, others, dump_level;
	struct disk_dump_header *dh;
	struct disk_dump_sub_header *dsh;
	struct kdump_sub_header *kdsh;
	ulong *tasks;

        fprintf(fp, "diskdump_data: \n");
	fprintf(fp, "          filename: %s\n", dd->filename);
        fprintf(fp, "             flags: %lx (", dd->flags);
        others = 0;
        if (dd->flags & DISKDUMP_LOCAL)
                fprintf(fp, "%sDISKDUMP_LOCAL", others++ ? "|" : "");
        if (dd->flags & KDUMP_CMPRS_LOCAL)
                fprintf(fp, "%sKDUMP_CMPRS_LOCAL", others++ ? "|" : "");
        if (dd->flags & ERROR_EXCLUDED)
                fprintf(fp, "%sERROR_EXCLUDED", others++ ? "|" : "");
        if (dd->flags & ZERO_EXCLUDED)
                fprintf(fp, "%sZERO_EXCLUDED", others++ ? "|" : "");
        fprintf(fp, ")\n");
        fprintf(fp, "               dfd: %d\n", dd->dfd);
        fprintf(fp, "               ofp: %lx\n", (ulong)dd->ofp);
        fprintf(fp, "      machine_type: %d ", dd->machine_type);
	switch (dd->machine_type)
	{
	case EM_386:
		fprintf(fp, "(EM_386)\n"); break;
	case EM_X86_64:
		fprintf(fp, "(EM_X86_64)\n"); break;
	case EM_IA_64:
		fprintf(fp, "(EM_IA_64)\n"); break;
	case EM_PPC64:
		fprintf(fp, "(EM_PPC64)\n"); break;
	default:
		fprintf(fp, "(unknown)\n"); break;
	}

        fprintf(fp, "\n            header: %lx\n", (ulong)dd->header);
	dh = dd->header;
	fprintf(fp, "           signature: \"");
	for (i = 0; i < SIG_LEN; i++)
		if (dh->signature[i])
			fprintf(fp, "%c", dh->signature[i]);
	fprintf(fp, "\"\n");
	fprintf(fp, "      header_version: %d\n", dh->header_version);
	fprintf(fp, "             utsname:\n");
	fprintf(fp, "               sysname: %s\n", dh->utsname.sysname);
	fprintf(fp, "              nodename: %s\n", dh->utsname.nodename);
	fprintf(fp, "               release: %s\n", dh->utsname.release);
	fprintf(fp, "               version: %s\n", dh->utsname.version);
	fprintf(fp, "               machine: %s\n", dh->utsname.machine);
	fprintf(fp, "            domainname: %s\n", dh->utsname.domainname);
	fprintf(fp, "           timestamp:\n");
	fprintf(fp, "                tv_sec: %lx\n", dh->timestamp.tv_sec);
	fprintf(fp, "               tv_usec: %lx\n", dh->timestamp.tv_usec);
	fprintf(fp, "              status: %x (", dh->status);
        others = 0;
        if (dh->status & DUMP_HEADER_COMPLETED)
                fprintf(fp, "%sDUMP_HEADER_COMPLETED", others++ ? "|" : "");
        if (dh->status & DUMP_HEADER_INCOMPLETED)
                fprintf(fp, "%sDUMP_HEADER_INCOMPLETED", others++ ? "|" : "");
        if (dh->status & DUMP_HEADER_COMPRESSED)
                fprintf(fp, "%sDUMP_HEADER_COMPRESSED", others++ ? "|" : "");
	fprintf(fp, ")\n");
	fprintf(fp, "          block_size: %d\n", dh->block_size);
	fprintf(fp, "        sub_hdr_size: %d\n", dh->sub_hdr_size);
	fprintf(fp, "       bitmap_blocks: %u\n", dh->bitmap_blocks);
	fprintf(fp, "           max_mapnr: %u\n", dh->max_mapnr);
	fprintf(fp, "    total_ram_blocks: %u\n", dh->total_ram_blocks);
	fprintf(fp, "       device_blocks: %u\n", dh->device_blocks);
	fprintf(fp, "      written_blocks: %u\n", dh->written_blocks);
	fprintf(fp, "         current_cpu: %u\n", dh->current_cpu);
	fprintf(fp, "             nr_cpus: %d\n", dh->nr_cpus);
	tasks = (ulong *)&dh->tasks[0];
	fprintf(fp, "      tasks[nr_cpus]: %lx\n", *tasks);
	for (tasks++, i = 1; i < dh->nr_cpus; i++) {
		fprintf(fp, "                      %lx\n", *tasks);
		tasks++;
	}
        fprintf(fp, "\n");
	fprintf(fp, "        sub_header: %lx ", (ulong)dd->sub_header);
	if ((dsh = dd->sub_header)) {
		fprintf(fp, "\n            elf_regs: %lx\n", 
			(ulong)&dsh->elf_regs);
		fprintf(fp, "          dump_level: ");
		if ((pc->flags & RUNTIME) && 
		    ((dump_level = get_dump_level()) >= 0)) {
			fprintf(fp, "%d (0x%x) %s", dump_level, dump_level, 
				dump_level ? "(" : "");

#define DUMP_EXCLUDE_CACHE 0x00000001   /* Exclude LRU & SwapCache pages*/
#define DUMP_EXCLUDE_CLEAN 0x00000002   /* Exclude all-zero pages */
#define DUMP_EXCLUDE_FREE  0x00000004   /* Exclude free pages */
#define DUMP_EXCLUDE_ANON  0x00000008   /* Exclude Anon pages */
#define DUMP_SAVE_PRIVATE  0x00000010   /* Save private pages */

		        others = 0;
        		if (dump_level & DUMP_EXCLUDE_CACHE)
                		fprintf(fp, "%sDUMP_EXCLUDE_CACHE", 
					others++ ? "|" : "");
        		if (dump_level & DUMP_EXCLUDE_CLEAN)
                		fprintf(fp, "%sDUMP_EXCLUDE_CLEAN", 
					others++ ? "|" : "");
        		if (dump_level & DUMP_EXCLUDE_FREE)
                		fprintf(fp, "%sDUMP_EXCLUDE_FREE", 
					others++ ? "|" : "");
        		if (dump_level & DUMP_EXCLUDE_ANON)
                		fprintf(fp, "%sDUMP_EXCLUDE_ANON", 
					others++ ? "|" : "");
        		if (dump_level & DUMP_SAVE_PRIVATE)
                		fprintf(fp, "%sDUMP_SAVE_PRIVATE", 
					others++ ? "|" : "");
			fprintf(fp, "%s\n\n", dump_level ? ")" : "");
		} else
			fprintf(fp, "%s\n\n", pc->flags & RUNTIME ? 
				"(unknown)" : "(undetermined)");

	} else
        	fprintf(fp, "(n/a)\n\n");

	fprintf(fp, "  sub_header_kdump: %lx ", (ulong)dd->sub_header_kdump);
	if ((kdsh = dd->sub_header_kdump)) {
		fprintf(fp, "\n           phys_base: %lx\n", 
			(ulong)kdsh->phys_base);
		fprintf(fp, "          dump_level: ");
		if ((dump_level = get_dump_level()) >= 0) {
			fprintf(fp, "%d (0x%x) %s", dump_level, dump_level, 
				dump_level ? "(" : "");

#define DL_EXCLUDE_ZERO         (0x001) /* Exclude Pages filled with Zeros */
#define DL_EXCLUDE_CACHE        (0x002) /* Exclude Cache Pages without Private Pages */
#define DL_EXCLUDE_CACHE_PRI    (0x004) /* Exclude Cache Pages with Private Pages */
#define DL_EXCLUDE_USER_DATA    (0x008) /* Exclude UserProcessData Pages */
#define DL_EXCLUDE_FREE         (0x010) /* Exclude Free Pages */

        		if (dump_level & DL_EXCLUDE_ZERO)
                		fprintf(fp, "%sDUMP_EXCLUDE_ZERO", 
					others++ ? "|" : "");
        		if (dump_level & DL_EXCLUDE_CACHE)
                		fprintf(fp, "%sDUMP_EXCLUDE_CACHE", 
					others++ ? "|" : "");
        		if (dump_level & DL_EXCLUDE_CACHE_PRI)
                		fprintf(fp, "%sDUMP_EXCLUDE_CACHE_PRI", 
					others++ ? "|" : "");
        		if (dump_level & DL_EXCLUDE_USER_DATA)
                		fprintf(fp, "%sDUMP_EXCLUDE_USER_DATA", 
					others++ ? "|" : "");
        		if (dump_level & DL_EXCLUDE_FREE)
                		fprintf(fp, "%sDUMP_EXCLUDE_FREE", 
					others++ ? "|" : "");
			others = 0;

			fprintf(fp, "%s\n", dump_level ? ")" : "");
		} else
			fprintf(fp, "(unknown)\n");
		if (KDUMP_SPLIT()) {
			fprintf(fp, "           start_pfn: %lu\n", dd->sub_header_kdump->start_pfn);
			fprintf(fp, "             end_pfn: %lu\n", dd->sub_header_kdump->end_pfn);
		}
		fprintf(fp, "\n");
	} else
        	fprintf(fp, "(n/a)\n\n");

	fprintf(fp, "       data_offset: %lx\n", (ulong)dd->data_offset);
	fprintf(fp, "        block_size: %d\n", dd->block_size);
	fprintf(fp, "       block_shift: %d\n", dd->block_shift);
	fprintf(fp, "            bitmap: %lx\n", (ulong)dd->bitmap);
	fprintf(fp, "        bitmap_len: %d\n", dd->bitmap_len);
	fprintf(fp, "   dumpable_bitmap: %lx\n", (ulong)dd->dumpable_bitmap);
	fprintf(fp, "              byte: %d\n", dd->byte);
	fprintf(fp, "               bit: %d\n", dd->bit);
	fprintf(fp, "   compressed_page: %lx\n", (ulong)dd->compressed_page);
	fprintf(fp, "         curbufptr: %lx\n\n", (ulong)dd->curbufptr);

	for (i = 0; i < DISKDUMP_CACHED_PAGES; i++) {
		fprintf(fp, "%spage_cache_hdr[%d]:\n", i < 10 ? " " : "", i);
		fprintf(fp, "            pg_flags: %x (", dd->page_cache_hdr[i].pg_flags);
		others = 0;
		if (dd->page_cache_hdr[i].pg_flags & PAGE_VALID)
                	fprintf(fp, "%sPAGE_VALID", others++ ? "|" : "");
		fprintf(fp, ")\n");
		fprintf(fp, "             pg_addr: %llx\n", (ulonglong)dd->page_cache_hdr[i].pg_addr);
		fprintf(fp, "           pg_bufptr: %lx\n", (ulong)dd->page_cache_hdr[i].pg_bufptr);
		fprintf(fp, "        pg_hit_count: %ld\n", dd->page_cache_hdr[i].pg_hit_count);
	}

	fprintf(fp, "\n    page_cache_buf: %lx\n", (ulong)dd->page_cache_buf);
	fprintf(fp, "       evict_index: %d\n", dd->evict_index);
	fprintf(fp, "         evictions: %ld\n", dd->evictions);
	fprintf(fp, "          accesses: %ld\n", dd->accesses);
	fprintf(fp, "      cached_reads: %ld ", dd->cached_reads);
	if (dd->accesses)
		fprintf(fp, "(%ld%%)\n",
			dd->cached_reads * 100 / dd->accesses);
	else
		fprintf(fp, "\n");
	fprintf(fp, "       valid_pages: %lx\n", (ulong)dd->valid_pages);

	return 0;
}

/*
 * Wrapper of __diskdump_memory_dump()
 */
int
diskdump_memory_dump(FILE *fp)
{
	int i;

	if (KDUMP_SPLIT() && (dd_list != NULL))
		for (i = 0; i < num_dumpfiles; i++) {
			dd = dd_list[i];
			__diskdump_memory_dump(fp);
			fprintf(fp, "\n");
		}
	else
		__diskdump_memory_dump(fp);

	return 0;
}


/*
 *  Get the switch_stack address of the passed-in task.  
 */
ulong
get_diskdump_switch_stack(ulong task)
{
	return 0;
}

/*
 *  Versions of disk_dump that support it contain the "dump_level" symbol.
 *  Version 1 and later compressed kdump dumpfiles contain the dump level
 *  in an additional field of the sub_header_kdump structure.
 */
static int 
get_dump_level(void)
{
	int dump_level;

	if (DISKDUMP_VALID()) {
		if (symbol_exists("dump_level") &&
		    readmem(symbol_value("dump_level"), KVADDR, &dump_level,
		    sizeof(dump_level), "dump_level", QUIET|RETURN_ON_ERROR))
                 	return dump_level;
	} else if (KDUMP_CMPRS_VALID()) {
		if (dd->header->header_version >= 1)
			return dd->sub_header_kdump->dump_level;
	}

	return -1;
}

/*
 *  Used by the "sys" command to display [PARTIAL DUMP] 
 *  after the dumpfile name.
 */
int 
is_partial_diskdump(void) 
{
	return (get_dump_level() > 0 ? TRUE : FALSE);
}

/*
 *  Used by "sys" command to dump multiple split dumpfiles.
 */
void
show_split_dumpfiles(void)
{
	int i;
	struct diskdump_data *ddp;

        for (i = 0; i < num_dumpfiles; i++) {
        	ddp = dd_list[i];
		fprintf(fp, "%s%s %s", 
			i ? "              " : "", 
			ddp->filename, 
			is_partial_diskdump() ? "[PARTIAL DUMP]" : "");
		if ((i+1) < num_dumpfiles)
			fprintf(fp, "\n");
	}
}
