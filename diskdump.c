/* 
 * diskdump.c 
 * 
 * The diskdump module optionally creates either ELF vmcore 
 * dumpfiles, or compressed dumpfiles derived from the LKCD format.
 * In the case of ELF vmcore files, since they are identical to 
 * netdump dumpfiles, the facilities in netdump.c are used.  For
 * compressed dumpfiles, the facilities in this file are used.
 *
 * Copyright (C) 2004, 2005, 2006 David Anderson
 * Copyright (C) 2004, 2005, 2006 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2005  FUJITSU LIMITED
 * Copyright (C) 2005  NEC Corporation
 *
 * This software may be freely redistributed under the terms of the
 * GNU General Public License.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "defs.h"
#include "diskdump.h"

#define BITMAP_SECT_LEN	4096

struct diskdump_data {
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
};

static struct diskdump_data diskdump_data = { 0 };
static struct diskdump_data *dd = &diskdump_data;

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
		error(INFO, "diskdump: unable to open dump file %s", file);
		return FALSE;
	}
	dd->dfd = fd;
	return TRUE;
}

static int read_dump_header(void)
{
	struct disk_dump_header *header = NULL;
	struct disk_dump_sub_header *sub_header = NULL;
	struct kdump_sub_header *sub_header_kdump = NULL;
	int bitmap_len;
	const int block_size = (int)sysconf(_SC_PAGESIZE);
	off_t offset;
	const off_t failed = (off_t)-1;
	ulong pfn;
	int i, j, max_sect_len;

	if (block_size < 0)
		return FALSE;

	if ((header = malloc(block_size)) == NULL)
		error(FATAL, "diskdump: cannot malloc block_size buffer\n");

	if (lseek(dd->dfd, 0, SEEK_SET) == failed) {
		if (CRASHDEBUG(1))
			error(INFO, "diskdump: cannot lseek dump header\n");
		goto err;
	}

	if (read(dd->dfd, header, block_size) < block_size) {
		if (CRASHDEBUG(1))
			error(INFO, "diskdump: cannot read dump header\n");
		goto err;
	}

	/* validate dump header */
	if (!memcmp(header->signature, DISK_DUMP_SIGNATURE,
				sizeof(header->signature))) {
		dd->flags |= DISKDUMP_LOCAL;
	} else if (!memcmp(header->signature, KDUMP_SIGNATURE,
				sizeof(header->signature))) {
		dd->flags |= KDUMP_CMPRS_LOCAL;
	} else {
		if (CRASHDEBUG(1))
			error(INFO, "diskdump: dump does not have panic dump header\n");
		goto err;
	}

	if (header->block_size != block_size) {
		error(INFO, "diskdump: block size in the dump header does not match"
	            " with system page size\n");
		goto err;
	}
	dd->block_size  = block_size;
	dd->block_shift = ffs(block_size) - 1;

	if (sizeof(*header) + sizeof(void *) * header->nr_cpus > block_size ||
	    header->nr_cpus <= 0) {
		error(INFO, "diskdump: invalid nr_cpus value: %d\n", header->nr_cpus);
		goto err;
	}

	/* read sub header */
	offset = (off_t)block_size;
	if (lseek(dd->dfd, offset, SEEK_SET) == failed) {
		error(INFO, "diskdump: cannot lseek dump sub header\n");
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
			error(FATAL, "diskdump: cannot malloc sub_header_kdump buffer\n");

		if (read(dd->dfd, sub_header_kdump, block_size)
		  < block_size) {
			error(INFO, "diskdump: cannot read dump sub header\n");
			goto err;
		}
		dd->sub_header_kdump = sub_header_kdump;
	}

	/* read memory bitmap */
	bitmap_len = block_size * header->bitmap_blocks;
	dd->bitmap_len = bitmap_len;

	offset = (off_t)block_size * (1 + header->sub_hdr_size);
	if (lseek(dd->dfd, offset, SEEK_SET) == failed) {
		error(INFO, "diskdump: cannot lseek memory bitmap\n");
		goto err;
	}

	if ((dd->bitmap = malloc(bitmap_len)) == NULL)
		error(FATAL, "diskdump: cannot malloc bitmap buffer\n");
	dd->dumpable_bitmap = calloc(bitmap_len, 1);
	if (read(dd->dfd, dd->bitmap, bitmap_len) < bitmap_len) {
		error(INFO, "diskdump: cannot read memory bitmap\n");
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
		error(INFO, "diskdump: unsupported machine type: %s\n", MACHINE_TYPE);
		goto err;
	}

	max_sect_len = divideup(header->max_mapnr, BITMAP_SECT_LEN);

	dd->valid_pages = calloc(sizeof(ulong), max_sect_len + 1);
	pfn = 0;
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

static int
pfn_to_pos(ulong pfn)
{
	int desc_pos, j, valid;

	valid = dd->valid_pages[pfn / BITMAP_SECT_LEN];

	for (j = round(pfn, BITMAP_SECT_LEN), desc_pos = valid; j <= pfn; j++)
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

	if (!open_dump_file(file) || !read_dump_header())
		return FALSE;

	sz = dd->block_size * (DISKDUMP_CACHED_PAGES);
	if ((dd->page_cache_buf = malloc(sz)) == NULL)
		error(FATAL, "diskdump: cannot malloc compressed page_cache_buf\n");

	for (i = 0; i < DISKDUMP_CACHED_PAGES; i++)
		dd->page_cache_hdr[i].pg_bufptr =
			&dd->page_cache_buf[i * dd->block_size];

	if ((dd->compressed_page = (char *)malloc(dd->block_size)) == NULL)
		error(FATAL, "diskdump: cannot malloc compressed page space\n");

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
	int desc_pos;
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
			error(INFO, "diskdump: uncompress failed: %d\n", ret);
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
	curpaddr = paddr & ~((physaddr_t)(dd->block_size-1));
	page_offset = paddr & ((physaddr_t)(dd->block_size-1));

	if ((pfn >= dd->header->max_mapnr) || !page_is_ram(pfn))
		return SEEK_ERROR;
	if (!page_is_dumpable(pfn)) {
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
		error(FATAL, "diskdump: unsupported machine type: %s\n", MACHINE_TYPE);
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
diskdump_memory_dump(FILE *fp)
{
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
