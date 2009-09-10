/* 
 * kvmdump.h
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

#define KVMDUMP_CACHED_PAGES 32

struct kvmdump_data {
	ulong flags;
	FILE *ofp;
	FILE *mem;
	FILE *vmp;
	ulong *debug;
	ulong phys_base;
	uint64_t last_ram_offset;
        /* page cache */
        struct kvm_page_cache_hdr {
                uint64_t paddr;
               	char *bufptr;
        } page_cache[KVMDUMP_CACHED_PAGES];
	union {
		char *curbufptr;
		unsigned char compressed;
	} un;
        int evict_index;    
	ulong accesses;
	ulong hit_count;
	ulong compresses;
};

extern struct kvmdump_data *kvm;

#undef dprintf
#define dprintf(x...)   do { if (*(kvm->debug)) fprintf(kvm->ofp, x); } while (0)

#define MEMFILE_OFFSET(addr) ((off_t)((((uint64_t)addr/(uint64_t)4096)) * sizeof(off_t))) 

int store_memfile_offset(uint64_t, off_t *);
int load_memfile_offset(uint64_t, off_t *);
