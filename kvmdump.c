/*
 * kvmdump.c
 *
 * Copyright (C) 2009 David Anderson
 * Copyright (C) 2009 Red Hat, Inc. All rights reserved.
 *
 * This software may be freely redistributed under the terms of the
 * GNU General Public License.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "defs.h"
#include "kvmdump.h"

static struct kvmdump_data kvmdump_data = { 0 };
struct kvmdump_data *kvm = &kvmdump_data;
static int cache_page(physaddr_t);

#define RAM_OFFSET_COMPRESSED (~(off_t)255)
#define QEMU_COMPRESSED       ((WRITE_ERROR)-1)
#define CACHE_UNUSED          (1ULL)

int 
is_kvmdump(char *filename)
{
	return (is_qemu_vm_file(filename));
}

int 
kvmdump_init(char *filename, FILE *fptr)
{
	int i, page_size;
	char *buf;

	if (!machine_type("X86") && !machine_type("X86_64")) {
		error(FATAL, "invalid host architecture for KVM: %s\n",
			MACHINE_TYPE);
		return FALSE;
	}

	kvm->ofp = fptr;
	kvm->debug = &pc->debug;
	page_size = memory_page_size();

	if ((kvm->mem = tmpfile()) == NULL)
		 error(FATAL, 
		    "cannot create tmpfile for KVM file offsets: %s\n", 
			strerror(errno));

        if ((buf = calloc(1, KVMDUMP_CACHED_PAGES * page_size)) == NULL)
                error(FATAL, "%s: cannot malloc KVM page_cache_buf\n");

	for (i = 0; i < KVMDUMP_CACHED_PAGES; i++) {
		kvm->page_cache[i].paddr = CACHE_UNUSED;
		kvm->page_cache[i].bufptr = buf + (i * page_size);
	}

	if (qemu_init(filename)) {
		kvm->flags |= KVMDUMP_LOCAL; 
		return TRUE;
	} else
		return FALSE;
}

int 
read_kvmdump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	switch (cache_page(PHYSPAGEBASE(paddr)))
	{
	case READ_ERROR:
		return READ_ERROR;

	case SEEK_ERROR:
		return SEEK_ERROR;

	case QEMU_COMPRESSED:
		memset(bufptr, kvm->un.compressed, cnt);
		break;

	default:
		memcpy(bufptr, kvm->un.curbufptr + PAGEOFFSET(paddr), cnt);
		break;
	}

	return cnt;
}


int 
write_kvmdump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	return SEEK_ERROR;
}

/*
 *  kvmdump_free_memory(), and kvmdump_memory_used()
 *  are debug only, and typically unnecessary to implement.
 */
int 
kvmdump_free_memory(void)
{
	return 0;
}

int 
kvmdump_memory_used(void)
{
	return 0;
}

/*
 *  This function is dump-type independent, used here to
 *  to dump the kvmdump_data structure contents.
 */
int 
kvmdump_memory_dump(FILE *ofp)
{
	int i, others;

	fprintf(ofp, "          flags: %lx (", kvm->flags);
	others = 0;
	if (kvm->flags & KVMDUMP_LOCAL)
		fprintf(ofp, "%sKVMDUMP_LOCAL", others++ ? "|" : "");
	fprintf(ofp, ")\n");
	fprintf(ofp, "            ofp: %lx\n", (ulong)kvm->ofp);
	fprintf(ofp, "            mem: %lx\n", (ulong)kvm->mem);
	fprintf(ofp, "            vmp: %lx\n", (ulong)kvm->vmp);
	fprintf(ofp, "          debug: %lx\n", (ulong)kvm->debug);
	fprintf(ofp, "      phys_base: %lx\n", kvm->phys_base);
	fprintf(ofp, "last_ram_offset: %llx\n", (ulonglong)kvm->last_ram_offset);

	fprintf(ofp, "      curbufptr: %lx\n", (ulong)kvm->un.curbufptr);
	fprintf(ofp, "    evict_index: %d\n", kvm->evict_index);
	fprintf(ofp, "       accesses: %ld\n", kvm->accesses);
	fprintf(ofp, "      hit_count: %ld ", kvm->hit_count);
	if (kvm->accesses)
		fprintf(ofp, "(%ld%%)\n",
			kvm->hit_count * 100 / kvm->accesses);
	else
		fprintf(ofp, "\n");
	fprintf(ofp, "     compresses: %ld ", kvm->compresses);
	if (kvm->accesses)
		fprintf(ofp, "(%ld%%)\n",
			kvm->compresses * 100 / kvm->accesses);
	else
		fprintf(ofp, "\n");

	for (i = 0; i < KVMDUMP_CACHED_PAGES; i++) {
		if (kvm->page_cache[i].paddr == CACHE_UNUSED)
			fprintf(ofp, " %spage_cache[%d]: CACHE_UNUSED\n", 
				i < 10 ? " " : "", i);
		else
			fprintf(ofp, 
			    " %spage_cache[%d]: bufptr: %lx  addr: %llx\n",
				i < 10 ? " " : "", i,
				(ulong)kvm->page_cache[i].bufptr,
				(ulonglong)kvm->page_cache[i].paddr);
	}

	fprintf(ofp, "\n");
	fflush(ofp);

	dump_qemu_header(ofp);

	return TRUE;
}

void 
get_kvmdump_regs(struct bt_info *bt, ulong *pc, ulong *sp)
{
	machdep->get_stack_frame(bt, pc, sp);
}

ulong
get_kvmdump_panic_task(void)
{
	return NO_TASK;
}

int
kvmdump_phys_base(unsigned long *phys_base)
{
        if (KVMDUMP_VALID()) {
                *phys_base = kvm->phys_base;
                return TRUE;
        }

        return FALSE;
}

static int
cache_page(physaddr_t paddr)
{
	int idx, err;
	struct kvm_page_cache_hdr *pgc;
	size_t page_size;
	off_t offset;

	kvm->accesses++;

	for (idx = 0; idx < KVMDUMP_CACHED_PAGES; idx++) {
		pgc = &kvm->page_cache[idx];

		if (pgc->paddr == CACHE_UNUSED)
			continue;

		if (pgc->paddr == paddr) {
			kvm->hit_count++;
			kvm->un.curbufptr = pgc->bufptr;
			return idx;
		}
	}

	if ((err = load_memfile_offset(paddr, &offset)) < 0)
		return err;

        if ((offset & RAM_OFFSET_COMPRESSED) == RAM_OFFSET_COMPRESSED) {
                kvm->un.compressed = (unsigned char)(offset & 255);
		kvm->compresses++;
		return QEMU_COMPRESSED;
	}

	idx = kvm->evict_index;
	pgc = &kvm->page_cache[idx];
        page_size = memory_page_size();

	if (fseek(kvm->vmp, offset, SEEK_SET) < 0) {
		pgc->paddr = CACHE_UNUSED;
		return SEEK_ERROR;
	}
	if (fread(pgc->bufptr, page_size, 1, kvm->vmp) != 1) {
		pgc->paddr = CACHE_UNUSED;
		return READ_ERROR;
	}

	kvm->evict_index = (idx+1) % KVMDUMP_CACHED_PAGES;

	pgc->paddr = paddr;
	kvm->un.curbufptr = pgc->bufptr;

	return idx;
}

int 
store_memfile_offset(uint64_t physaddr, off_t *entry_ptr)
{
        if (fseek(kvm->mem, MEMFILE_OFFSET(physaddr), SEEK_SET) < 0) {
		error(INFO, "%s: fseek: %s\n", pc->dumpfile, strerror(errno));
		return SEEK_ERROR;
	}

        if (fwrite((entry_ptr), sizeof(off_t), 1, kvm->mem) != 1) {
		error(INFO, "%s: fwrite: %s\n", pc->dumpfile, strerror(errno));
		return WRITE_ERROR;
	}
	
	return 0;
}

int 
load_memfile_offset(uint64_t physaddr, off_t *entry_ptr)
{
        if (fseek(kvm->mem, MEMFILE_OFFSET(physaddr), SEEK_SET) < 0) {
		error(INFO, "%s: fseek: %s\n", pc->dumpfile, strerror(errno));
		return SEEK_ERROR;
	}

        if (fread((entry_ptr), sizeof(off_t), 1, kvm->mem) != 1) {
		error(INFO, "%s: fwrite: %s\n", pc->dumpfile, strerror(errno));
		return READ_ERROR;
	}

	return 0;
}


