/* 
 * xendump.h
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
#include <endian.h>

#define XC_SAVE_SIGNATURE  "LinuxGuestRecord"
#define XC_CORE_MAGIC      0xF00FEBED

/*
 *  From xenctrl.h, but probably not on most host machines.
 */
typedef struct xc_core_header {
    unsigned int xch_magic;
    unsigned int xch_nr_vcpus;
    unsigned int xch_nr_pages;
    unsigned int xch_ctxt_offset;
    unsigned int xch_index_offset;
    unsigned int xch_pages_offset;
} xc_core_header_t;

struct pfn_offset_cache {
	off_t file_offset;
	ulong pfn;
	ulong cnt;
};

#define PFN_TO_OFFSET_CACHE_ENTRIES  (1024)

struct xendump_data {
        ulong flags;       /* XENDUMP_LOCAL, plus anything else... */
	int xfd;
	int pc_next;
	uint page_size;
	FILE *ofp;
	char *page;
	ulong accesses;
	ulong cache_hits;
	ulong redundant;
	ulong last_pfn;
	struct pfn_offset_cache *poc;

	struct xc_core_data {
		int p2m_frames;
		ulong *p2m_frame_index_list;
		struct xc_core_header header;
	} xc_core;

	struct xc_save_data {
		ulong nr_pfns;
		int vmconfig_size;
		char *vmconfig_buf;
		ulong *p2m_frame_list;
		uint pfns_not;
		off_t pfns_not_offset;
		off_t vcpu_ctxt_offset;
		off_t shared_info_page_offset;
		off_t *batch_offsets;
		ulong batch_count;
		ulong *region_pfn_type;
	} xc_save;

	ulong panic_pc;
	ulong panic_sp;
};

#define XC_SAVE           (XENDUMP_LOCAL << 1)
#define XC_CORE           (XENDUMP_LOCAL << 2)
#define XC_CORE_P2M_INIT  (XENDUMP_LOCAL << 3)

#define MACHINE_BYTE_ORDER()  \
        (machine_type("X86") || \
         machine_type("X86_64") || \
         machine_type("IA64") ? __LITTLE_ENDIAN : __BIG_ENDIAN)

#define BYTE_SWAP_REQUIRED(endian) (endian != MACHINE_BYTE_ORDER())

static inline uint32_t
swab32(uint32_t x)
{
        return (((x & 0x000000ffU) << 24) |
                ((x & 0x0000ff00U) <<  8) |
                ((x & 0x00ff0000U) >>  8) |
                ((x & 0xff000000U) >> 24));
}

#define MFN_NOT_FOUND (-1)
#define PFN_NOT_FOUND (-1)