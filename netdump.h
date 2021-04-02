/* netdump.h
 *
 * Copyright (C) 2002, 2003, 2004, 2005 David Anderson
 * Copyright (C) 2002, 2003, 2004, 2005 Red Hat, Inc. All rights reserved.
 *
 * This software may be freely redistributed under the terms of the
 * GNU General Public License.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Author: David Anderson
 */

#include <elf.h>

#define MIN_NETDUMP_ELF32_HEADER_SIZE \
        sizeof(Elf32_Ehdr)+sizeof(Elf32_Phdr)+sizeof(Elf32_Phdr)
#define MIN_NETDUMP_ELF64_HEADER_SIZE \
        sizeof(Elf64_Ehdr)+sizeof(Elf64_Phdr)+sizeof(Elf64_Phdr)
#define MIN_NETDUMP_ELF_HEADER_SIZE \
        MAX(MIN_NETDUMP_ELF32_HEADER_SIZE, MIN_NETDUMP_ELF64_HEADER_SIZE)

#define NT_TASKSTRUCT 4
#define NT_DISKDUMP   0x70000001

#ifdef NOTDEF
/*
 *  Note: Based upon the original, abandoned, proposal for
 *  its contents -- keep around for potential future use.
 */
#ifndef NT_KDUMPINFO
#define NT_KDUMPINFO 7
#endif

#endif  /* NOTDEF */

struct pt_load_segment {
	off_t file_offset;
	physaddr_t phys_start;
	physaddr_t phys_end;
	physaddr_t zero_fill;
};

struct vmcore_data {
	ulong flags;
	int ndfd;
	FILE *ofp;
	uint header_size;
	char *elf_header;
	uint num_pt_load_segments;
	struct pt_load_segment *pt_load_segments;
        Elf32_Ehdr *elf32;
        Elf32_Phdr *notes32;
        Elf32_Phdr *load32;
        Elf64_Ehdr *elf64;
        Elf64_Phdr *notes64;
        Elf64_Phdr *load64;
        void *nt_prstatus;
        void *nt_prpsinfo;
        void *nt_taskstruct;
	ulong task_struct;
	uint page_size;
	ulong switch_stack;
	uint num_prstatus_notes;
	void *nt_prstatus_percpu[NR_CPUS];
	struct xen_kdump_data *xen_kdump_data;
};

/*
 *  ELF note types for Xen dom0/hypervisor kdumps.
 *  The comments below are from xen/include/public/elfnote.h.
 */

/*
 * System information exported through crash notes.
 *
 * The kexec / kdump code will create one XEN_ELFNOTE_CRASH_INFO
 * note in case of a system crash. This note will contain various
 * information about the system, see xen/include/xen/elfcore.h.
 */
#define XEN_ELFNOTE_CRASH_INFO 0x1000001

/*
 * System registers exported through crash notes.
 *
 * The kexec / kdump code will create one XEN_ELFNOTE_CRASH_REGS
 * note per cpu in case of a system crash. This note is architecture
 * specific and will contain registers not saved in the "CORE" note.
 * See xen/include/xen/elfcore.h for more information.
 */
#define XEN_ELFNOTE_CRASH_REGS 0x1000002


/* 
 * For (temporary) backwards compatibility.
 */
#define NT_XEN_KDUMP_CR3 0x10000001

struct xen_kdump_data {
	ulong flags;
	ulong cr3;
	ulong p2m_mfn;
	char *page;
	ulong last_mfn_read;
	ulong last_pmd_read;
	ulong cache_hits;
	ulong accesses;
	int p2m_frames;
        ulong *p2m_mfn_frame_list;
};

#define KDUMP_P2M_INIT  (0x1)
#define KDUMP_CR3       (0x2)
#define KDUMP_MFN_LIST  (0x4)

#define P2M_FAILURE ((physaddr_t)(0xffffffffffffffffLL))
