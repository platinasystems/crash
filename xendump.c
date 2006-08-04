/* 
 * xendump.c 
 * 
 * Copyright (C) 2006 David Anderson
 * Copyright (C) 2006 Red Hat, Inc. All rights reserved.
 *
 * This software may be freely redistributed under the terms of the
 * GNU General Public License.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "defs.h"
#include "xendump.h"

static struct xendump_data xendump_data = { 0 };
static struct xendump_data *xd = &xendump_data;

static int xc_save_verify(char *);
static int xc_core_verify(char *);
static int xc_save_read(void *, int, ulong, physaddr_t);
static int xc_core_read(void *, int, ulong, physaddr_t);

static void poc_store(ulong, off_t);
static off_t poc_get(ulong, int *);

static void xen_dump_vmconfig(FILE *);

static void xc_core_p2m_create(void);
static ulong xc_core_pfn_to_page_index(ulong);

/*
 *  Determine whether a file is a xendump creation, and if TRUE,
 *  initialize the xendump_data structure.
 */
int
is_xendump(char *file)
{
	int verified;
	char buf[BUFSIZE];

        if ((xd->xfd = open(file, O_RDWR)) < 0) {
                if ((xd->xfd = open(file, O_RDONLY)) < 0) {
                        sprintf(buf, "%s: open", file);
                        perror(buf);
                        return FALSE;
                }
        }

	if (read(xd->xfd, buf, BUFSIZE) != BUFSIZE) 
		return FALSE;

        if (machine_type("X86") || machine_type("X86_64"))
                xd->page_size = 4096;
	else 
                xd->page_size = machdep->pagesize;

	verified = xc_save_verify(buf) || xc_core_verify(buf);

	if (!verified)
		close(xd->xfd);

	return (verified);
}

/*
 *  Verify whether the dump was created by the xc_domain_dumpcore()
 *  library function in libxc/xc_core.c.
 */
static int
xc_core_verify(char *buf)
{
	struct xc_core_header *xcp;

	xcp = (struct xc_core_header *)buf;

	if (xcp->xch_magic != XC_CORE_MAGIC)
		return FALSE;

	if (!xcp->xch_nr_vcpus) {
		error(INFO, 
		    "faulty xc_core dump file header: xch_nr_vcpus is 0\n\n");

        	fprintf(stderr, "         xch_magic: %x (XC_CORE_MAGIC)\n", xcp->xch_magic);
        	fprintf(stderr, "      xch_nr_vcpus: %d\n", xcp->xch_nr_vcpus);
        	fprintf(stderr, "      xch_nr_pages: %d\n", xcp->xch_nr_pages);
        	fprintf(stderr, "   xch_ctxt_offset: %d\n", xcp->xch_ctxt_offset);
        	fprintf(stderr, "  xch_index_offset: %d\n", xcp->xch_index_offset);
        	fprintf(stderr, "  xch_pages_offset: %d\n\n", xcp->xch_pages_offset);

		clean_exit(1);
	}

	BCOPY(xcp, &xd->xc_core.header, 
		sizeof(struct xc_core_header));

        xd->flags |= (XENDUMP_LOCAL | XC_CORE);

	if (!xd->page_size)
		error(FATAL,
		    "unknown page size: use -p <pagesize> command line option\n");

	if (!(xd->page = (char *)malloc(xd->page_size)))
		error(FATAL, "cannot malloc page space.");

        if (!(xd->poc = (struct pfn_offset_cache *)calloc
            (PFN_TO_OFFSET_CACHE_ENTRIES,
            sizeof(struct pfn_offset_cache))))
                error(FATAL, "cannot malloc pfn_offset_cache\n");
	xd->last_pfn = ~(0UL);

	if (CRASHDEBUG(1)) 
                xendump_memory_dump(stderr);

	return TRUE;
}

/*
 *  Do the work for read_xendump() for the XC_CORE dumpfile format.
 */
static int
xc_core_read(void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
        ulong pfn, page_index;
	off_t offset;
	int redundant;

	if (!(xd->flags & XC_CORE_P2M_INIT))
		xc_core_p2m_create();

        pfn = (ulong)BTOP(paddr);

        if ((offset = poc_get(pfn, &redundant))) {
                if (!redundant) {
                        if (lseek(xd->xfd, offset, SEEK_SET) == -1)
                                return SEEK_ERROR;
                        if (read(xd->xfd, xd->page, xd->page_size) != 
			    xd->page_size)
                                return READ_ERROR;
                }

                BCOPY(xd->page + PAGEOFFSET(paddr), bufptr, cnt);
                return cnt;
        }

	if ((page_index = xc_core_pfn_to_page_index(pfn)) == 
	    PFN_NOT_FOUND)
		return READ_ERROR;

	offset = (off_t)xd->xc_core.header.xch_pages_offset +
		((off_t)(page_index) * (off_t)xd->page_size);

	if (lseek(xd->xfd, offset, SEEK_SET) == -1) 
 		return SEEK_ERROR;

	if (read(xd->xfd, xd->page, xd->page_size) != xd->page_size)
		return READ_ERROR;

	poc_store(pfn, offset);

	BCOPY(xd->page + PAGEOFFSET(paddr), bufptr, cnt);

	return cnt;
}

/*
 *  Verify whether the dumpfile was created by the "xm save" facility.
 *  This gets started by the "save" function in XendCheckpoint.py, and
 *  then by xc_save.c, with the work done in the xc_linux_save() library
 *  function in libxc/xc_linux_save.c.
 */

#define MAX_BATCH_SIZE  1024
/*
 *  Number of P2M entries in a page.
 */
#define ULPP (xd->page_size/sizeof(unsigned long))
/*
 *  Number of P2M entries in the pfn_to_mfn_frame_list.
 */
#define P2M_FL_ENTRIES  (((xd->xc_save.nr_pfns)+ULPP-1)/ULPP)
/*
 *  Size in bytes of the pfn_to_mfn_frame_list.
 */
#define P2M_FL_SIZE     ((P2M_FL_ENTRIES)*sizeof(unsigned long))

#define XTAB  (0xf<<28) /* invalid page */
#define LTAB_MASK XTAB

static int
xc_save_verify(char *buf)
{
	int i, batch_count, done_batch, *intptr;
	ulong flags, *ulongptr;
	ulong batch_index, total_pages_read;

	if (!STRNEQ(buf, XC_SAVE_SIGNATURE))
		return FALSE;

	if (lseek(xd->xfd, strlen(XC_SAVE_SIGNATURE), SEEK_SET) == -1)
		return FALSE;

	flags = XC_SAVE;

	if (CRASHDEBUG(1)) {
		fprintf(stderr, "\"%s\"\n", buf); 
		fprintf(stderr, "endian: %d %s\n", __BYTE_ORDER, 
		    __BYTE_ORDER == __BIG_ENDIAN ? "__BIG_ENDIAN" :
		    (__BYTE_ORDER == __LITTLE_ENDIAN ? 
		    "__LITTLE_ENDIAN" : "???"));
	}
		  
	/*
	 *  size of vmconfig data structure (big-endian)
	 */
	if (read(xd->xfd, buf, sizeof(int)) != sizeof(int))
		return FALSE;

	intptr = (int *)buf;

	if (CRASHDEBUG(1) && BYTE_SWAP_REQUIRED(__BIG_ENDIAN)) {
		fprintf(stderr, "byte-swap required for this:\n");
		for (i = 0; i < sizeof(int); i++) 
			fprintf(stderr, "[%x]", buf[i] & 0xff);
		fprintf(stderr, ": %x -> ", *intptr);
	}
	
	xd->xc_save.vmconfig_size = swab32(*intptr);

	if (CRASHDEBUG(1))
		fprintf(stderr, "%x\n", xd->xc_save.vmconfig_size);

	if (!(xd->xc_save.vmconfig_buf = (char *)malloc
	    (xd->xc_save.vmconfig_size)))
		error(FATAL, "cannot malloc xc_save vmconfig space.");

	if (!xd->page_size)
		error(FATAL, 
		    "unknown page size: use -p <pagesize> command line option\n");

	if (!(xd->page = (char *)malloc(xd->page_size)))
		error(FATAL, "cannot malloc page space.");

	if (!(xd->poc = (struct pfn_offset_cache *)calloc
	    (PFN_TO_OFFSET_CACHE_ENTRIES, 
	    sizeof(struct pfn_offset_cache))))
		error(FATAL, "cannot malloc pfn_offset_cache\n");
	xd->last_pfn = ~(0UL);

	if (!(xd->xc_save.region_pfn_type = (ulong *)calloc
	    (MAX_BATCH_SIZE, sizeof(ulong))))
		error(FATAL, "cannot malloc region_pfn_type\n");

	if (read(xd->xfd, xd->xc_save.vmconfig_buf, 
	    xd->xc_save.vmconfig_size) != xd->xc_save.vmconfig_size)
		goto xc_save_bailout;

	/*
	 *  nr_pfns (native byte order)
	 */
	if (read(xd->xfd, buf, sizeof(ulong)) != sizeof(ulong))
		goto xc_save_bailout;

	ulongptr = (ulong *)buf;

	if (CRASHDEBUG(1)) {
		for (i = 0; i < sizeof(ulong); i++)
			fprintf(stderr, "[%x]", buf[i] & 0xff);
		fprintf(stderr, ": %lx (native)\n", *ulongptr);
	}

	xd->xc_save.nr_pfns = *ulongptr;

    	/* 
	 *  Get a local copy of the live_P2M_frame_list 
	 */
	if (!(xd->xc_save.p2m_frame_list = (unsigned long *)malloc(P2M_FL_SIZE))) 
        	error(FATAL, "Cannot allocate p2m_frame_list array");

	if (!(xd->xc_save.batch_offsets = (off_t *)calloc((size_t)P2M_FL_ENTRIES, 
	    sizeof(off_t))))
        	error(FATAL, "Cannot allocate batch_offsets array");

	xd->xc_save.batch_count = P2M_FL_ENTRIES;
		
	if (read(xd->xfd, xd->xc_save.p2m_frame_list, P2M_FL_SIZE) != 
	    P2M_FL_SIZE)
		goto xc_save_bailout;

	if (CRASHDEBUG(1))
		fprintf(stderr, "pre-batch file pointer: %lld\n", 
			(ulonglong)lseek(xd->xfd, 0L, SEEK_CUR));

	/*
	 *  ...
	 *  int batch_count
	 *  ulong region pfn_type[batch_count]
	 *  page 0
	 *  page 1
	 *  ...
	 *  page batch_count-1
	 *  (repeat)
	 */

	total_pages_read = 0;
	batch_index = 0;
	done_batch = FALSE;

	while (!done_batch) {

		xd->xc_save.batch_offsets[batch_index] = (off_t)
			lseek(xd->xfd, 0L, SEEK_CUR);

		if (read(xd->xfd, &batch_count, sizeof(int)) != sizeof(int))
			goto xc_save_bailout;

		if (CRASHDEBUG(1))
			fprintf(stderr, "batch[%ld]: %d ", 
				batch_index, batch_count); 

		batch_index++;

		if (batch_index >= P2M_FL_ENTRIES) {
			fprintf(stderr, "more than %ld batches encountered?\n",
				P2M_FL_ENTRIES);
			goto xc_save_bailout;
		}

	 	switch (batch_count)
	 	{
	 	case 0:
			if (CRASHDEBUG(1)) {
	 		    fprintf(stderr, 
			        ": Batch work is done: %ld pages read (P2M_FL_ENTRIES: %ld)\n", 
				    total_pages_read, P2M_FL_ENTRIES);
			}
			done_batch = TRUE;
			continue;

	 	case -1:
			if (CRASHDEBUG(1))
	 			fprintf(stderr, ": Entering page verify mode\n");
			continue;

	 	default:
	 		if (batch_count > MAX_BATCH_SIZE) {
				if (CRASHDEBUG(1))
	             		    fprintf(stderr, 
					": Max batch size exceeded. Giving up.\n");
				done_batch = TRUE;
				continue;
	 		}
			if (CRASHDEBUG(1))
	 			fprintf(stderr, "\n");
			break;
		}

		if (read(xd->xfd, xd->xc_save.region_pfn_type, batch_count * sizeof(ulong)) != 
	    	    batch_count * sizeof(ulong))
			goto xc_save_bailout;

		for (i = 0; i < batch_count; i++) {
			unsigned long pagetype;
			unsigned long pfn;
	
	            	pfn = xd->xc_save.region_pfn_type[i] & ~LTAB_MASK;
	            	pagetype = xd->xc_save.region_pfn_type[i] & LTAB_MASK;
	
		        if (pagetype == XTAB) 
			    /* a bogus/unmapped page: skip it */
	                	continue;
	
	            	if (pfn > xd->xc_save.nr_pfns) {
				if (CRASHDEBUG(1))
	                	    fprintf(stderr, 
				 	"batch_count: %d pfn %ld out of range",
						batch_count, pfn);
	            	}

			if (lseek(xd->xfd, xd->page_size, SEEK_CUR) == -1)
				goto xc_save_bailout;
	
			total_pages_read++;
		}
	}	

	/* 
	 *  Get the list of PFNs that are not in the psuedo-phys map 
	 */
	if (read(xd->xfd, &xd->xc_save.pfns_not, 
	    sizeof(xd->xc_save.pfns_not)) != sizeof(xd->xc_save.pfns_not))
		goto xc_save_bailout;

	if (CRASHDEBUG(1))
		fprintf(stderr, "PFNs not in pseudo-phys map: %d\n", 
			xd->xc_save.pfns_not);

	if ((total_pages_read + xd->xc_save.pfns_not) != 
	    xd->xc_save.nr_pfns)
		error(WARNING, 
		    "nr_pfns: %ld != (total pages: %ld + pages not saved: %d)\n",
			xd->xc_save.nr_pfns, total_pages_read, 
			xd->xc_save.pfns_not);

	xd->xc_save.pfns_not_offset = lseek(xd->xfd, 0L, SEEK_CUR);

	if (lseek(xd->xfd, sizeof(ulong) * xd->xc_save.pfns_not, SEEK_CUR) == -1)
		goto xc_save_bailout;

	xd->xc_save.vcpu_ctxt_offset = lseek(xd->xfd, 0L, SEEK_CUR);

	lseek(xd->xfd, 0, SEEK_END);
	lseek(xd->xfd,  -((off_t)(xd->page_size)), SEEK_CUR);

	xd->xc_save.shared_info_page_offset = lseek(xd->xfd, 0L, SEEK_CUR);

	xd->flags |= (XENDUMP_LOCAL | flags);
	kt->xen_flags |= (CANONICAL_PAGE_TABLES|XEN_SUSPEND);

	if (CRASHDEBUG(1))
		xendump_memory_dump(stderr);

	return TRUE;

xc_save_bailout:

	error(INFO, 
	    "xc_save_verify: \"LinuxGuestRecord\" file handling/format error\n");

	if (xd->xc_save.p2m_frame_list) {
		free(xd->xc_save.p2m_frame_list);
		xd->xc_save.p2m_frame_list = NULL;
	}
	if (xd->xc_save.batch_offsets) {
		free(xd->xc_save.batch_offsets);
		xd->xc_save.batch_offsets = NULL;
	}
	if (xd->xc_save.vmconfig_buf) {
		free(xd->xc_save.vmconfig_buf);
		xd->xc_save.vmconfig_buf = NULL;
	}
	if (xd->page) {
		free(xd->page);
		xd->page = NULL;
	}

	return FALSE;
}

/*
 *  Do the work for read_xendump() for the XC_SAVE dumpfile format.
 */
static int
xc_save_read(void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	int b, i, redundant;
	ulong reqpfn;
	int batch_count;
	off_t file_offset;

	reqpfn = (ulong)BTOP(paddr);

	if (CRASHDEBUG(8))
	    fprintf(xd->ofp, 
	        "xc_save_read(bufptr: %lx cnt: %d addr: %lx paddr: %llx (%ld, 0x%lx)\n",
		    (ulong)bufptr, cnt, addr, (ulonglong)paddr, reqpfn, reqpfn);

	if ((file_offset = poc_get(reqpfn, &redundant))) {
		if (!redundant) {
        		if (lseek(xd->xfd, file_offset, SEEK_SET) == -1)
				return SEEK_ERROR;
			if (read(xd->xfd, xd->page, xd->page_size) != xd->page_size)
                		return READ_ERROR;
		} else if (CRASHDEBUG(1))
			console("READ %ld (0x%lx) skipped!\n", reqpfn, reqpfn);

		BCOPY(xd->page + PAGEOFFSET(paddr), bufptr, cnt);
                return cnt;
	}

        /*
         *  ...
         *  int batch_count
         *  ulong region pfn_type[batch_count]
         *  page 0
         *  page 1
         *  ...
         *  page batch_count-1
         *  (repeat)
         */
	for (b = 0; b < xd->xc_save.batch_count; b++) {

		if (lseek(xd->xfd, xd->xc_save.batch_offsets[b], SEEK_SET) == -1)
			return SEEK_ERROR;

		if (CRASHDEBUG(8))
		    fprintf(xd->ofp, "check batch[%d]: offset: %llx\n",
			b, (ulonglong)xd->xc_save.batch_offsets[b]);

                if (read(xd->xfd, &batch_count, sizeof(int)) != sizeof(int))
                        return READ_ERROR;

                switch (batch_count)
                {
                case 0:
                        if (CRASHDEBUG(1)) {
                            	fprintf(xd->ofp,
                                    "batch[%d]: has count of zero -- bailing out on pfn %ld\n",
					 b, reqpfn);
                        }
			return READ_ERROR;

                case -1:
			return READ_ERROR;

                default:
			if (CRASHDEBUG(8))
		    	    fprintf(xd->ofp, 
				"batch[%d]: offset: %llx batch count: %d\n",
				    b, (ulonglong)xd->xc_save.batch_offsets[b], 
				    batch_count);
                        break;
                }

                if (read(xd->xfd, xd->xc_save.region_pfn_type, batch_count * sizeof(ulong)) !=
                    batch_count * sizeof(ulong))
                        return READ_ERROR;

                for (i = 0; i < batch_count; i++) {
                        unsigned long pagetype;
                        unsigned long pfn;

                        pfn = xd->xc_save.region_pfn_type[i] & ~LTAB_MASK;
                        pagetype = xd->xc_save.region_pfn_type[i] & LTAB_MASK;

                        if (pagetype == XTAB)
                            /* a bogus/unmapped page: skip it */
                                continue;

                        if (pfn > xd->xc_save.nr_pfns) {
                                if (CRASHDEBUG(1))
                                    fprintf(stderr,
                                        "batch_count: %d pfn %ld out of range",
                                                batch_count, pfn);
                        }

			if (pfn == reqpfn) {
				file_offset = lseek(xd->xfd, 0, SEEK_CUR);
				poc_store(pfn, file_offset);

				if (read(xd->xfd, xd->page, xd->page_size) != 
				    xd->page_size)
                			return READ_ERROR;

				BCOPY(xd->page + PAGEOFFSET(paddr), bufptr, cnt);
				return cnt;
			}

                        if (lseek(xd->xfd, xd->page_size, SEEK_CUR) == -1)
                                return SEEK_ERROR;
                }
	}

	return READ_ERROR;
}

/*
 *  Stash a pfn's offset.  If they're all in use, put it in the
 *  least-used slot that's closest to the beginning of the array.
 */
static void
poc_store(ulong pfn, off_t file_offset)
{
	int i;
	struct pfn_offset_cache *poc, *plow;
	ulong curlow;

	curlow = ~(0UL);
	plow = NULL;
	poc = xd->poc;

        for (i = 0; i < PFN_TO_OFFSET_CACHE_ENTRIES; i++, poc++) {
		if (poc->cnt == 0) {
			poc->cnt = 1;
			poc->pfn = pfn;
			poc->file_offset = file_offset;
			xd->last_pfn = pfn;
			return;
		}

		if (poc->cnt < curlow) {
			curlow = poc->cnt;
			plow = poc;
		}
	}

	plow->cnt = 1;
	plow->pfn = pfn;
	plow->file_offset = file_offset;
	xd->last_pfn = pfn;
}

/*
 *  Check whether a pfn's offset has been cached.
 */
static off_t
poc_get(ulong pfn, int *redundant)
{
	int i;
	struct pfn_offset_cache *poc;

	xd->accesses++;

	if (pfn == xd->last_pfn) {
		xd->redundant++;
		*redundant = TRUE;
		return 1;
	} else
		*redundant = FALSE;

	poc = xd->poc;

        for (i = 0; i < PFN_TO_OFFSET_CACHE_ENTRIES; i++, poc++) {
		if (poc->cnt && (poc->pfn == pfn)) {
			poc->cnt++;
			xd->cache_hits++;
			xd->last_pfn = pfn;
			return poc->file_offset;
		}
	}

	return 0;
}


/*
 *  Perform any post-dumpfile determination stuff here.
 */
int
xendump_init(char *unused, FILE *fptr)
{
        if (!XENDUMP_VALID())
                return FALSE;

        xd->ofp = fptr;
        return TRUE;
}

int
read_xendump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	if (pc->curcmd_flags & XEN_MACHINE_ADDR)
		return READ_ERROR;

	switch (xd->flags & (XC_SAVE|XC_CORE))
	{
	case XC_SAVE:
		return xc_save_read(bufptr, cnt, addr, paddr);

	case XC_CORE:
		return xc_core_read(bufptr, cnt, addr, paddr);

	default:
        	return READ_ERROR;
	}
}

int
write_xendump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
        return WRITE_ERROR;
}

uint
xendump_page_size(void)
{
        if (!XENDUMP_VALID())
                return 0;

        return xd->page_size;
}

/*
 *  xendump_free_memory(), and xendump_memory_used()
 *  are debug only, and typically unnecessary to implement.
 */
int
xendump_free_memory(void)
{
        return 0;
}

int
xendump_memory_used(void)
{
        return 0;
}

/*
 *  This function is dump-type independent, used here to
 *  to dump the xendump_data structure contents.
 */
int
xendump_memory_dump(FILE *fp)
{
	int i, linefeed, used, others;
	ulong *ulongptr;

	fprintf(fp, "        flags: %lx (", xd->flags);
	others = 0;
	if (xd->flags & XENDUMP_LOCAL)
		fprintf(fp, "%sXENDUMP_LOCAL", others++ ? "|" : "");
	if (xd->flags & XC_SAVE)
		fprintf(fp, "%sXC_SAVE", others++ ? "|" : "");
	if (xd->flags & XC_CORE)
		fprintf(fp, "%sXC_CORE", others++ ? "|" : "");
	if (xd->flags & XC_CORE_P2M_INIT)
		fprintf(fp, "%sXC_CORE_P2M_INIT", others++ ? "|" : "");
	fprintf(fp, ")\n");
	fprintf(fp, "          xfd: %d\n", xd->xfd);
	fprintf(fp, "    page_size: %d\n", xd->page_size);
	fprintf(fp, "          ofp: %lx\n", (ulong)xd->ofp);
	fprintf(fp, "         page: %lx\n", (ulong)xd->page);
	fprintf(fp, "     panic_pc: %lx\n", xd->panic_pc);
	fprintf(fp, "     panic_sp: %lx\n", xd->panic_sp);
	fprintf(fp, "     accesses: %ld\n", (ulong)xd->accesses);
	fprintf(fp, "   cache_hits: %ld ", (ulong)xd->cache_hits);
	if (xd->accesses)
 		fprintf(fp, "(%ld%%)\n", xd->cache_hits * 100 / xd->accesses);
	else
		fprintf(fp, "\n");
	fprintf(fp, "     last_pfn: %ld\n", xd->last_pfn);
	fprintf(fp, "    redundant: %ld ", (ulong)xd->redundant);
	if (xd->accesses)
 		fprintf(fp, "(%ld%%)\n", xd->redundant * 100 / xd->accesses);
	else
		fprintf(fp, "\n");
	for (i = used = 0; i < PFN_TO_OFFSET_CACHE_ENTRIES; i++) 
		if (xd->poc[i].cnt)
			used++;
	fprintf(fp, "    poc[%d]: %lx %s", PFN_TO_OFFSET_CACHE_ENTRIES, (ulong)xd->poc,
		xd->poc ? "" : "(none)");
	for (i = 0; i < PFN_TO_OFFSET_CACHE_ENTRIES; i++) {
		if (!xd->poc)
			break;
		if (!xd->poc[i].cnt) {
			if (!i)
				fprintf(fp, "(none used)\n");
			break;
		} else if (!i)
			fprintf(fp, "(%d used)\n", used);
		fprintf(fp, "  [%d]: pfn: %ld (0x%lx) count: %ld file_offset: %llx\n",
			i,
			xd->poc[i].pfn,
			xd->poc[i].pfn,
			xd->poc[i].cnt,
			(ulonglong)xd->poc[i].file_offset);
	}
	if (!xd->poc)
		fprintf(fp, "\n");

	fprintf(fp, "      xc_save:\n");
	fprintf(fp, "                  nr_pfns: %ld (0x%lx)\n", 
		xd->xc_save.nr_pfns, xd->xc_save.nr_pfns); 
	fprintf(fp, "            vmconfig_size: %d (0x%x)\n", xd->xc_save.vmconfig_size, 
		xd->xc_save.vmconfig_size);
	fprintf(fp, "             vmconfig_buf: %lx\n", (ulong)xd->xc_save.vmconfig_buf);
	if (xd->flags & XC_SAVE) 
		xen_dump_vmconfig(fp);
	fprintf(fp, "           p2m_frame_list: %lx ", (ulong)xd->xc_save.p2m_frame_list);
	if (xd->flags & XC_SAVE) {
		fprintf(fp, "\n");
		ulongptr = xd->xc_save.p2m_frame_list;
		for (i = 0; i < P2M_FL_ENTRIES; i++, ulongptr++)
			fprintf(fp, "%ld ", *ulongptr);
		fprintf(fp, "\n");
	} else
		fprintf(fp, "(none)\n");
	fprintf(fp, "                 pfns_not: %d\n", xd->xc_save.pfns_not);
	fprintf(fp, "          pfns_not_offset: %lld\n", 
		(ulonglong)xd->xc_save.pfns_not_offset);
	fprintf(fp, "         vcpu_ctxt_offset: %lld\n", 
		(ulonglong)xd->xc_save.vcpu_ctxt_offset);
	fprintf(fp, "  shared_info_page_offset: %lld\n", 
		(ulonglong)xd->xc_save.shared_info_page_offset);
	fprintf(fp, "          region_pfn_type: %lx\n", (ulong)xd->xc_save.region_pfn_type);
	fprintf(fp, "              batch_count: %ld\n", (ulong)xd->xc_save.batch_count);
	fprintf(fp, "            batch_offsets: %lx %s\n", 
		(ulong)xd->xc_save.batch_offsets, 
		xd->xc_save.batch_offsets ? "" : "(none)");
	for (i = linefeed = 0; i < xd->xc_save.batch_count; i++) {
		fprintf(fp, "[%d]: %llx ", i, 
			(ulonglong)xd->xc_save.batch_offsets[i]);
		if (((i+1)%4) == 0) {
			fprintf(fp, "\n");
			linefeed = FALSE;
		} else
			linefeed = TRUE;
	}
	if (linefeed)
		fprintf(fp, "\n");

	fprintf(fp, "      xc_core:\n");
	fprintf(fp, "                   header:\n");
	fprintf(fp, "                xch_magic: %x (%s)\n", 
		xd->xc_core.header.xch_magic,
		xd->xc_core.header.xch_magic == XC_CORE_MAGIC ?
		"XC_CORE_MAGIC" : "unknown");
	fprintf(fp, "             xch_nr_vcpus: %d\n", 
		xd->xc_core.header.xch_nr_vcpus);
	fprintf(fp, "             xch_nr_pages: %d (0x%x)\n",
		xd->xc_core.header.xch_nr_pages,
		xd->xc_core.header.xch_nr_pages);
	fprintf(fp, "          xch_ctxt_offset: %d (0x%x)\n", 
		xd->xc_core.header.xch_ctxt_offset,
		xd->xc_core.header.xch_ctxt_offset);
	fprintf(fp, "         xch_index_offset: %d (0x%x)\n",
		xd->xc_core.header.xch_index_offset,
		xd->xc_core.header.xch_index_offset);
	fprintf(fp, "         xch_pages_offset: %d (0x%x)\n",
		xd->xc_core.header.xch_pages_offset,
		xd->xc_core.header.xch_pages_offset);

	fprintf(fp, "               p2m_frames: %d\n", 
		xd->xc_core.p2m_frames);
	fprintf(fp, "     p2m_frame_index_list:\n");
	for (i = 0; i < xd->xc_core.p2m_frames; i++) {
		fprintf(fp, "%ld ", 
			xd->xc_core.p2m_frame_index_list[i]);
	}
	fprintf(fp, xd->xc_core.p2m_frames ? "\n\n" : "\n");

	return 0;
}

static void
xen_dump_vmconfig(FILE *fp)
{
	int i, opens, closes;
	char *p;

	opens = closes = 0;
	p = xd->xc_save.vmconfig_buf;
	for (i = 0; i < xd->xc_save.vmconfig_size; i++, p++) {
		if (ascii(*p))
			fprintf(fp, "%c", *p);
		else
			fprintf(fp, "<%x>", *p);

		if (*p == '(')
			opens++;
		else if (*p == ')')
			closes++;
	}
	fprintf(fp, "\n");

	if (opens != closes)
		error(WARNING, "invalid vmconfig contents?\n");
}

/*
 *  Looking at the active set, try to determine who panicked, 
 *  or who was the "suspend" kernel thread. 
 */
ulong get_xendump_panic_task(void)
{
	int i;
	ulong task;
	struct task_context *tc;

	switch (xd->flags & (XC_CORE|XC_SAVE))
	{
	case XC_CORE:
		if (machdep->xendump_panic_task)
			return (machdep->xendump_panic_task((void *)xd));
		break;

	case XC_SAVE:
        	for (i = 0; i < NR_CPUS; i++) {
                	if (!(task = tt->active_set[i]))
                        	continue;
			tc = task_to_context(task);
			if (is_kernel_thread(task) &&
			    STREQ(tc->comm, "suspend")) 
				return tc->task;
        	}
		break;
	}

	return NO_TASK;
}

/*
 *  Figure out the back trace hooks.
 */
void get_xendump_regs(struct bt_info *bt, ulong *pc, ulong *sp)
{
	int i;
	ulong *up;

	if ((tt->panic_task == bt->task) &&
	    (xd->panic_pc && xd->panic_sp)) {
		*pc = xd->panic_pc;
		*sp = xd->panic_sp;
		return;
	}

	switch (xd->flags & (XC_CORE|XC_SAVE))
	{
	case XC_CORE:
		if (machdep->get_xendump_regs)
			return (machdep->get_xendump_regs(xd, bt, pc, sp));
		break;

	case XC_SAVE:
		if (tt->panic_task != bt->task) 
			break;

                for (i = 0, up = (ulong *)bt->stackbuf;
                     i < LONGS_PER_STACK; i++, up++) {
                        if (is_kernel_text(*up) &&
		       	    (STREQ(closest_symbol(*up), 
			    "__do_suspend"))) {
				*pc = *up;
				*sp = tt->flags & THREAD_INFO ?
                               		bt->tc->thread_info +
                                        (i * sizeof(long)) :
                                        bt->task + 
					(i * sizeof(long));
				xd->panic_pc = *pc;
				xd->panic_sp = *sp;
				return;
			}
		}
	}

	machdep->get_stack_frame(bt, pc, sp);
}

/*
 *  Farm out most of the work to the proper architecture.
 */
static void 
xc_core_p2m_create(void)
{
	if (!machdep->xendump_p2m_create)
		error(FATAL, 
		    "xen xc_core dumpfiles not supported on this architecture");

	if (!machdep->xendump_p2m_create((void *)xd))
		error(FATAL,
		    "cannot create xen pfn-to-mfn mapping\n");

	xd->flags |= XC_CORE_P2M_INIT;

	if (CRASHDEBUG(1))
		xendump_memory_dump(xd->ofp);
}

/*
 *  Find the page index containing the mfn, and read the
 *  machine page into the buffer.
 */
char *
xc_core_mfn_to_page(ulong mfn, char *pgbuf)
{
	int i, b, idx, done;
	ulong tmp[MAX_BATCH_SIZE];
	off_t offset;

        if (lseek(xd->xfd, (off_t)xd->xc_core.header.xch_index_offset,
            SEEK_SET) == -1) {
                error(INFO, "cannot lseek to page index\n");
		return NULL;
	}

        for (b = 0, idx = -1, done = FALSE; 
	     !done && (b < xd->xc_core.header.xch_nr_pages); 
	     b += MAX_BATCH_SIZE) {

                if (read(xd->xfd, tmp, sizeof(ulong) * MAX_BATCH_SIZE) != 
		    (MAX_BATCH_SIZE * sizeof(ulong))) {
                        error(INFO, "cannot read index page %d\n", b);
			return NULL;
		}

                for (i = 0; i < MAX_BATCH_SIZE; i++) {
			if ((b+i) >= xd->xc_core.header.xch_nr_pages) {
				done = TRUE;
				break;
			}
                        if (tmp[i] == mfn) {
                                idx = i+b;
                                if (CRASHDEBUG(2))
                                        fprintf(xd->ofp,
                                            "page: found mfn 0x%lx (%ld) at index %d\n",
                                                mfn, mfn, idx);
				done = TRUE;
                        }
                }
	}

	if (idx == -1) {
                error(INFO, "cannot find mfn %ld (0x%lx) in page index\n",
			mfn, mfn);
		return NULL;
	}

        if (lseek(xd->xfd, (off_t)xd->xc_core.header.xch_pages_offset,
            SEEK_SET) == -1) {
                error(INFO, "cannot lseek to xch_pages_offset\n");
		return NULL;
	}

        offset = (off_t)(idx) * (off_t)xd->page_size;

        if (lseek(xd->xfd, offset, SEEK_CUR) == -1) {
                error(INFO, "cannot lseek to mfn-specified page\n");
		return NULL;
	}

        if (read(xd->xfd, pgbuf, xd->page_size) != xd->page_size) {
                error(INFO, "cannot read mfn-specified page\n");
		return NULL;
	}

	return pgbuf;
}


/*
 *  Find and return the page index containing the mfn.
 */
int 
xc_core_mfn_to_page_index(ulong mfn)
{
        int i, b;
        ulong tmp[MAX_BATCH_SIZE];

        if (lseek(xd->xfd, (off_t)xd->xc_core.header.xch_index_offset,
            SEEK_SET) == -1) {
                error(INFO, "cannot lseek to page index\n");
                return MFN_NOT_FOUND;
        }

        for (b = 0; b < xd->xc_core.header.xch_nr_pages; b += MAX_BATCH_SIZE) {

                if (read(xd->xfd, tmp, sizeof(ulong) * MAX_BATCH_SIZE) != 
		    (MAX_BATCH_SIZE * sizeof(ulong))) {
                        error(INFO, "cannot read index page %d\n", b);
			return MFN_NOT_FOUND;
		}

		for (i = 0; i < MAX_BATCH_SIZE; i++) {
			if ((b+i) >= xd->xc_core.header.xch_nr_pages)
				break;
			
                	if (tmp[i] == mfn) {
				if (CRASHDEBUG(2))
                        		fprintf(xd->ofp, 
				            "index: batch: %d found mfn %ld (0x%lx) at index %d\n",
                                		b/MAX_BATCH_SIZE, mfn, mfn, i+b);
                        	return (i+b);
                	}
		}
        }

        return MFN_NOT_FOUND;
}

/*
 *  Given a normal kernel pfn, determine the page index in the dumpfile.
 *
 *  -  First determine which of the pages making up the 
 *     phys_to_machine_mapping[] array would contain the pfn.
 *  -  From the phys_to_machine_mapping page, determine the mfn.
 *  -  Find the mfn in the dumpfile page index.
 */

#define PFNS_PER_PAGE  (xd->page_size/sizeof(unsigned long))

static ulong
xc_core_pfn_to_page_index(ulong pfn)
{
	ulong idx, p2m_idx, mfn_idx;
	ulong *up, mfn;
	off_t offset;

	idx = pfn/PFNS_PER_PAGE;

	if (idx >= xd->xc_core.p2m_frames) {
		error(INFO, "pfn: %lx is too large for dumpfile\n", 
			pfn);
		return PFN_NOT_FOUND;
	}

	p2m_idx = xd->xc_core.p2m_frame_index_list[idx];

	if (lseek(xd->xfd, (off_t)xd->xc_core.header.xch_pages_offset,
            SEEK_SET) == -1) {
                error(INFO, "cannot lseek to xch_pages_offset\n");
                return PFN_NOT_FOUND;
        }

        offset = (off_t)(p2m_idx) * (off_t)xd->page_size;

        if (lseek(xd->xfd, offset, SEEK_CUR) == -1) {
                error(INFO, "cannot lseek to pfn-specified page\n");
                return PFN_NOT_FOUND;
        }

        if (read(xd->xfd, xd->page, xd->page_size) != xd->page_size) {
                error(INFO, "cannot read pfn-specified page\n");
                return PFN_NOT_FOUND;
        }

	up = (ulong *)xd->page;
	up += (pfn%PFNS_PER_PAGE);

	mfn = *up;

	if ((mfn_idx = xc_core_mfn_to_page_index(mfn)) == MFN_NOT_FOUND) {
		error(INFO, "cannot find mfn in page index\n");
		return PFN_NOT_FOUND;
	}

	return mfn_idx;
}

/*
 *  Store the panic task's stack hooks from where it was found
 *  in get_active_set_panic_task().
 */
void
xendump_panic_hook(char *stack)
{
	int i, err, argc;
	char *arglist[MAXARGS];
	char buf[BUFSIZE];
	ulong value, *sp;

	strcpy(buf, stack);

        argc = parse_line(buf, arglist);

	if ((value = htol(strip_ending_char(arglist[0], ':'), 
	    RETURN_ON_ERROR, &err)) == BADADDR)
		return;
	for (sp = (ulong *)value, i = 1; i < argc; i++, sp++) {
		if (strstr(arglist[i], "xen_panic_event")) {
			if (!readmem((ulong)sp, KVADDR, &value,
			    sizeof(ulong), "xen_panic_event address",
                            RETURN_ON_ERROR))
				return;

			xd->panic_sp = (ulong)sp;
			xd->panic_pc = value;
		} else if (strstr(arglist[i], "panic") && !xd->panic_sp) {
                        if (!readmem((ulong)sp, KVADDR, &value,
                            sizeof(ulong), "xen_panic_event address",
                            RETURN_ON_ERROR))
                                return;

			xd->panic_sp = (ulong)sp;
			xd->panic_pc = value;
		}
	}
}
