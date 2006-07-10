/* netdump.c 
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

#include "defs.h"
#include "netdump.h"

struct pt_load_segment {
	off_t file_offset;
	physaddr_t phys_start;
	physaddr_t phys_end;
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

static struct vmcore_data vmcore_data = { 0 };
static struct vmcore_data *nd = &vmcore_data;
static struct xen_kdump_data xen_kdump_data = { 0 };
static void netdump_print(char *, ...);
static void dump_Elf32_Ehdr(Elf32_Ehdr *);
static void dump_Elf32_Phdr(Elf32_Phdr *, int);
static size_t dump_Elf32_Nhdr(Elf32_Off offset, int);
static void dump_Elf64_Ehdr(Elf64_Ehdr *);
static void dump_Elf64_Phdr(Elf64_Phdr *, int);
static size_t dump_Elf64_Nhdr(Elf64_Off offset, int);
static void get_netdump_regs_ppc64(struct bt_info *, ulong *, ulong *);
static physaddr_t xen_kdump_p2m(physaddr_t);

#define ELFSTORE 1
#define ELFREAD  0

#define MIN_PAGE_SIZE (4096)
	
/*
 *  Determine whether a file is a netdump/diskdump/kdump creation, 
 *  and if TRUE, initialize the vmcore_data structure.
 */
int 
is_netdump(char *file, ulong source_query) 
{
        int i;
	int fd;
	Elf32_Ehdr *elf32;
	Elf32_Phdr *load32;
	Elf64_Ehdr *elf64;
	Elf64_Phdr *load64;
	char header[MIN_NETDUMP_ELF_HEADER_SIZE];
	char buf[BUFSIZE];
	size_t size, len, tot;
        Elf32_Off offset32;
        Elf64_Off offset64;
	ulong tmp_flags;
	char *tmp_elf_header;

	if ((fd = open(file, O_RDWR)) < 0) {
        	if ((fd = open(file, O_RDONLY)) < 0) {
                        sprintf(buf, "%s: open", file);
                        perror(buf);
                        return FALSE;
		}
	}

	size = MIN_NETDUMP_ELF_HEADER_SIZE;
        if (read(fd, header, size) != size) {
                sprintf(buf, "%s: read", file);
                perror(buf);
		goto bailout;
	}

        if (lseek(fd, 0, SEEK_SET) != 0) {
                sprintf(buf, "%s: lseek", file);
                perror(buf);
                goto bailout;
	}

	tmp_flags = 0;
	elf32 = (Elf32_Ehdr *)&header[0];
	elf64 = (Elf64_Ehdr *)&header[0];

  	/* 
	 *  Verify the ELF header, and determine the dumpfile format.
	 * 
	 *  For now, kdump vmcores differ from netdump/diskdump like so:
	 *
 	 *   1. The first kdump PT_LOAD segment is packed just after
	 *      the ELF header, whereas netdump/diskdump page-align 
	 *      the first PT_LOAD segment.
	 *   2. Each kdump PT_LOAD segment has a p_align field of zero,
	 *      whereas netdump/diskdump have their p_align fields set
	 *      to the system page-size. 
	 *
	 *  If either kdump difference is seen, presume kdump -- this
	 *  is obviously subject to change.
	 */
        if (STRNEQ(elf32->e_ident, ELFMAG) && 
	    (elf32->e_ident[EI_CLASS] == ELFCLASS32) &&
  	    (elf32->e_ident[EI_DATA] == ELFDATA2LSB) &&
    	    (elf32->e_ident[EI_VERSION] == EV_CURRENT) &&
	    (elf32->e_type == ET_CORE) &&
	    (elf32->e_version == EV_CURRENT) &&
	    (elf32->e_phnum >= 2)) {
		switch (elf32->e_machine)
		{
		case EM_386:
			if (machine_type("X86"))
				break;
		default:
                	goto bailout;
		}

                load32 = (Elf32_Phdr *)
                        &header[sizeof(Elf32_Ehdr)+sizeof(Elf32_Phdr)];
                size = (size_t)load32->p_offset;

		if ((load32->p_offset & (MIN_PAGE_SIZE-1)) &&
		    (load32->p_align == 0))
                	tmp_flags |= KDUMP_ELF32;
		else
                	tmp_flags |= NETDUMP_ELF32;
	} else if (STRNEQ(elf64->e_ident, ELFMAG) &&
	    (elf64->e_ident[EI_CLASS] == ELFCLASS64) &&
	    (elf64->e_ident[EI_VERSION] == EV_CURRENT) &&
	    (elf64->e_type == ET_CORE) &&
	    (elf64->e_version == EV_CURRENT) &&
	    (elf64->e_phnum >= 2)) { 
		switch (elf64->e_machine)
		{
		case EM_IA_64:
			if ((elf64->e_ident[EI_DATA] == ELFDATA2LSB) &&
				machine_type("IA64"))
				break;
			else
				goto bailout;

		case EM_PPC64:
			if ((elf64->e_ident[EI_DATA] == ELFDATA2MSB) &&
				machine_type("PPC64"))
				break;
			else
				goto bailout;

		case EM_X86_64:
			if ((elf64->e_ident[EI_DATA] == ELFDATA2LSB) &&
				machine_type("X86_64"))
				break;
			else
				goto bailout;

		case EM_386:
			if ((elf64->e_ident[EI_DATA] == ELFDATA2LSB) &&
				machine_type("X86"))
				break;
			else
				goto bailout;

		default:
			goto bailout;
		}

                load64 = (Elf64_Phdr *)
                        &header[sizeof(Elf64_Ehdr)+sizeof(Elf64_Phdr)];
                size = (size_t)load64->p_offset;
		if ((load64->p_offset & (MIN_PAGE_SIZE-1)) &&
		    (load64->p_align == 0))
                	tmp_flags |= KDUMP_ELF64;
		else
                	tmp_flags |= NETDUMP_ELF64;
	} else
		goto bailout;

	switch (DUMPFILE_FORMAT(tmp_flags))
	{
	case NETDUMP_ELF32:
	case NETDUMP_ELF64:
		if (source_query & (NETDUMP_LOCAL|NETDUMP_REMOTE))
			break;
		else
			goto bailout;

	case KDUMP_ELF32:
	case KDUMP_ELF64:
		if (source_query & KDUMP_LOCAL)
			break;
		else
			goto bailout;
	}

	if ((tmp_elf_header = (char *)malloc(size)) == NULL) {
		fprintf(stderr, "cannot malloc ELF header buffer\n");
		clean_exit(1);
	}

        if (read(fd, tmp_elf_header, size) != size) {
                sprintf(buf, "%s: read", file);
                perror(buf);
		free(tmp_elf_header);
                goto bailout;
        }

	nd->ndfd = fd;
	nd->elf_header = tmp_elf_header;
	nd->flags = tmp_flags;
	nd->flags |= source_query;

	switch (DUMPFILE_FORMAT(nd->flags))
	{
	case NETDUMP_ELF32:
	case KDUMP_ELF32:
		nd->header_size = load32->p_offset;
        	nd->elf32 = (Elf32_Ehdr *)&nd->elf_header[0];
		nd->num_pt_load_segments = nd->elf32->e_phnum - 1;
		if ((nd->pt_load_segments = (struct pt_load_segment *)
		    malloc(sizeof(struct pt_load_segment) *
		    nd->num_pt_load_segments)) == NULL) {
			fprintf(stderr, "cannot malloc PT_LOAD segment buffers\n");
			clean_exit(1);
		}
        	nd->notes32 = (Elf32_Phdr *)
		    &nd->elf_header[sizeof(Elf32_Ehdr)];
        	nd->load32 = (Elf32_Phdr *)
		    &nd->elf_header[sizeof(Elf32_Ehdr)+sizeof(Elf32_Phdr)];
		if (DUMPFILE_FORMAT(nd->flags) == NETDUMP_ELF32)
			nd->page_size = (uint)nd->load32->p_align;
                dump_Elf32_Ehdr(nd->elf32);
                dump_Elf32_Phdr(nd->notes32, ELFREAD);
		for (i = 0; i < nd->num_pt_load_segments; i++) 
                	dump_Elf32_Phdr(nd->load32 + i, ELFSTORE+i);
        	offset32 = nd->notes32->p_offset;
                for (tot = 0; tot < nd->notes32->p_filesz; tot += len) {
                        len = dump_Elf32_Nhdr(offset32, ELFSTORE);
                        offset32 += len;
                }
		break;

	case NETDUMP_ELF64:
	case KDUMP_ELF64:
                nd->header_size = load64->p_offset;
                nd->elf64 = (Elf64_Ehdr *)&nd->elf_header[0];
		nd->num_pt_load_segments = nd->elf64->e_phnum - 1;
                if ((nd->pt_load_segments = (struct pt_load_segment *)
                    malloc(sizeof(struct pt_load_segment) *
                    nd->num_pt_load_segments)) == NULL) {
                        fprintf(stderr, "cannot malloc PT_LOAD segment buffers\n");
                        clean_exit(1);
                }
                nd->notes64 = (Elf64_Phdr *)
                    &nd->elf_header[sizeof(Elf64_Ehdr)];
                nd->load64 = (Elf64_Phdr *)
                    &nd->elf_header[sizeof(Elf64_Ehdr)+sizeof(Elf64_Phdr)];
		if (DUMPFILE_FORMAT(nd->flags) == NETDUMP_ELF64)
			nd->page_size = (uint)nd->load64->p_align;
                dump_Elf64_Ehdr(nd->elf64);
                dump_Elf64_Phdr(nd->notes64, ELFREAD);
		for (i = 0; i < nd->num_pt_load_segments; i++)
                	dump_Elf64_Phdr(nd->load64 + i, ELFSTORE+i);
                offset64 = nd->notes64->p_offset;
                for (tot = 0; tot < nd->notes64->p_filesz; tot += len) {
                        len = dump_Elf64_Nhdr(offset64, ELFSTORE);
                        offset64 += len;
                }
		break;
	}

	if (CRASHDEBUG(1))
		netdump_memory_dump(fp);

	return nd->header_size;

bailout:
	close(fd);
	return FALSE;
}

/*
 *  Perform any post-dumpfile determination stuff here.
 */
int
netdump_init(char *unused, FILE *fptr)
{
	if (!VMCORE_VALID())
		return FALSE;

	nd->ofp = fptr;
        return TRUE;
}

/*
 *  Read from a netdump-created dumpfile.
 */
int
read_netdump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	off_t offset;
	struct pt_load_segment *pls;
	int i;

	/*
	 *  The Elf32_Phdr has 32-bit fields for p_paddr, p_filesz and
	 *  p_memsz, so for now, multiple PT_LOAD segment support is
	 *  restricted to 64-bit machines for netdump/diskdump vmcores.
	 *  However, kexec/kdump has introduced the optional use of a
         *  64-bit ELF header for 32-bit processors.
	 */ 
        switch (DUMPFILE_FORMAT(nd->flags))
	{
	case NETDUMP_ELF32:
		offset = (off_t)paddr + (off_t)nd->header_size;
		break;

	case NETDUMP_ELF64:
	case KDUMP_ELF32:
	case KDUMP_ELF64:
		if (nd->num_pt_load_segments == 1) {
			offset = (off_t)paddr + (off_t)nd->header_size;
			break;
		}

		for (i = offset = 0; i < nd->num_pt_load_segments; i++) {
			pls = &nd->pt_load_segments[i];
			if ((paddr >= pls->phys_start) &&
			    (paddr < pls->phys_end)) {
				offset = (off_t)(paddr - pls->phys_start) +
					pls->file_offset;
				break;
			}
		}
	
		if (!offset) 
	                return READ_ERROR;
		
		break;
	}	

        if (lseek(nd->ndfd, offset, SEEK_SET) == -1)
                return SEEK_ERROR;

        if (read(nd->ndfd, bufptr, cnt) != cnt)
                return READ_ERROR;

        return cnt;
}

/*
 *  Write to a netdump-created dumpfile.  Note that cmd_wr() does not
 *  allow writes to dumpfiles, so you can't get here from there.
 *  But, if it would ever be helpful, here it is...
 */
int
write_netdump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	off_t offset;
	struct pt_load_segment *pls;
	int i;

        switch (DUMPFILE_FORMAT(nd->flags))
	{
	case NETDUMP_ELF32:
		offset = (off_t)paddr + (off_t)nd->header_size;
		break;

	case NETDUMP_ELF64:
	case KDUMP_ELF32:
	case KDUMP_ELF64:
		if (nd->num_pt_load_segments == 1) {
			offset = (off_t)paddr + (off_t)nd->header_size;
			break;
		}

		for (i = offset = 0; i < nd->num_pt_load_segments; i++) {
			pls = &nd->pt_load_segments[i];
			if ((paddr >= pls->phys_start) &&
			    (paddr < pls->phys_end)) {
				offset = (off_t)(paddr - pls->phys_start) +
					pls->file_offset;
				break;
			}
		}
	
		if (!offset) 
	                return READ_ERROR;
		
		break;
	}	

        if (lseek(nd->ndfd, offset, SEEK_SET) == -1)
                return SEEK_ERROR;

        if (write(nd->ndfd, bufptr, cnt) != cnt)
                return READ_ERROR;

        return cnt;
}

/*
 *  Set the file pointer for debug output.
 */
FILE *
set_netdump_fp(FILE *fp)
{
	if (!VMCORE_VALID())
		return NULL;

	nd->ofp = fp;
	return fp;
}

/*
 *  Generic print routine to handle integral and remote daemon output.
 */
static void
netdump_print(char *fmt, ...)
{
        char buf[BUFSIZE];
        va_list ap;

        if (!fmt || !strlen(fmt) || !VMCORE_VALID())
                return;

        va_start(ap, fmt);
        (void)vsnprintf(buf, BUFSIZE, fmt, ap);
        va_end(ap);

        if (nd->ofp)
                fprintf(nd->ofp, buf);
        else
                console(buf);
}

uint 
netdump_page_size(void)
{
	if (!VMCORE_VALID())
		return 0;

	return nd->page_size;
}

int 
netdump_free_memory(void)
{
	return (VMCORE_VALID() ? 0 : 0);
}

int netdump_memory_used(void)
{
	return (VMCORE_VALID() ? 0 : 0);
}

/*
 *  The netdump server will eventually use the NT_TASKSTRUCT section
 *  to pass the task address.  Until such time, look at the ebp of the
 *  user_regs_struct, which is located at the end of the NT_PRSTATUS
 *  elf_prstatus structure, minus one integer:
 *
 *    struct elf_prstatus
 *    {
 *    	...
 *            elf_gregset_t pr_reg;   (maps to user_regs_struct) 
 *            int pr_fpvalid;        
 *    };
 *
 *  If it's a kernel stack address who's adjusted task_struct value is
 *  equal to one of the active set tasks, we'll presume it's legit. 
 *
 */
ulong 
get_netdump_panic_task(void)
{
#ifdef DAEMON
	return nd->task_struct;
#else
	int i, crashing_cpu;
        size_t len;
	char *user_regs;
	ulong ebp, esp, task;

	if (!VMCORE_VALID() || !get_active_set())
		goto panic_task_undetermined;

	if (nd->task_struct) {
		if (CRASHDEBUG(1))
			error(INFO, 
			    "get_netdump_panic_task: NT_TASKSTRUCT: %lx\n", 
				nd->task_struct);
		return nd->task_struct;
	}

        switch (DUMPFILE_FORMAT(nd->flags))
        {
        case NETDUMP_ELF32:
        case NETDUMP_ELF64:
		crashing_cpu = -1;
		break;

        case KDUMP_ELF32:
        case KDUMP_ELF64:
		crashing_cpu = -1;
		if (symbol_exists("crashing_cpu")) {
			get_symbol_data("crashing_cpu", sizeof(int), &i);
			if ((i >= 0) && (i < nd->num_prstatus_notes)) {
				crashing_cpu = i;
				if (CRASHDEBUG(1))
					error(INFO, 
				   "get_netdump_panic_task: crashing_cpu: %d\n",
						crashing_cpu);
			}
		}

		if ((nd->num_prstatus_notes > 1) && (crashing_cpu == -1))
			goto panic_task_undetermined;
		break;
	}

        if (nd->elf32 && (nd->elf32->e_machine == EM_386)) {
		Elf32_Nhdr *note32;

                if ((nd->num_prstatus_notes > 1) && (crashing_cpu != -1))
                        note32 = (Elf32_Nhdr *)
                                nd->nt_prstatus_percpu[crashing_cpu];
                else
                        note32 = (Elf32_Nhdr *)nd->nt_prstatus;

	        len = sizeof(Elf32_Nhdr);
	        len = roundup(len + note32->n_namesz, 4);
	        len = roundup(len + note32->n_descsz, 4);
		
		user_regs = ((char *)note32 + len)
			- SIZE(user_regs_struct) - sizeof(int);
		ebp = ULONG(user_regs + OFFSET(user_regs_struct_ebp));
		esp = ULONG(user_regs + OFFSET(user_regs_struct_esp));
check_ebp_esp:
		if (CRASHDEBUG(1)) 
			error(INFO, 
			    "get_netdump_panic_task: NT_PRSTATUS esp: %lx ebp: %lx\n",
				esp, ebp);
		if (IS_KVADDR(esp)) {
			task = stkptr_to_task(esp);
			if (CRASHDEBUG(1))
				error(INFO, 
			    "get_netdump_panic_task: esp: %lx -> task: %lx\n",
					esp, task);
			for (i = 0; task && (i < NR_CPUS); i++) {
				if (task == tt->active_set[i]) 
					return task;
			} 
		}
                if (IS_KVADDR(ebp)) {
                        task = stkptr_to_task(ebp);
			if (CRASHDEBUG(1))
				error(INFO, 
			    "get_netdump_panic_task: ebp: %lx -> task: %lx\n",
					ebp, task);
                        for (i = 0; task && (i < NR_CPUS); i++) {
                                if (task == tt->active_set[i]) 
                                      return task;
                        }
                }
	} else if (nd->elf64) {
		Elf64_Nhdr *note64;

                if ((nd->num_prstatus_notes > 1) && (crashing_cpu != -1))
                        note64 = (Elf64_Nhdr *)
                                nd->nt_prstatus_percpu[crashing_cpu];
                else
                        note64 = (Elf64_Nhdr *)nd->nt_prstatus;

	        len = sizeof(Elf64_Nhdr);
	        len = roundup(len + note64->n_namesz, 4);
		user_regs = (char *)((char *)note64 + len +
			MEMBER_OFFSET("elf_prstatus", "pr_reg"));

		if (nd->elf64->e_machine == EM_386) {
                	ebp = ULONG(user_regs + OFFSET(user_regs_struct_ebp));
                	esp = ULONG(user_regs + OFFSET(user_regs_struct_esp));
			goto check_ebp_esp;
		}

		if (nd->elf64->e_machine == EM_PPC64) {
			/*
			 * Get the GPR1 register value.
			 */
			esp = *(ulong *)((char *)user_regs + 8);
			if (CRASHDEBUG(1)) 
				error(INFO, 
			    	"get_netdump_panic_task: NT_PRSTATUS esp: %lx\n", esp);
			if (IS_KVADDR(esp)) {
				task = stkptr_to_task(esp);
				if (CRASHDEBUG(1))
					error(INFO, 
			    		"get_netdump_panic_task: esp: %lx -> task: %lx\n",
						esp, task);
				for (i = 0; task && (i < NR_CPUS); i++) {
					if (task == tt->active_set[i]) 
						return task;
				}
			}
		}
	} 

panic_task_undetermined:

	if (CRASHDEBUG(1))
		error(INFO, "get_netdump_panic_task: failed\n");

	return NO_TASK;
#endif
}

/*
 *  Get the switch_stack address of the passed-in task.  Currently only
 *  the panicking task reports its switch-stack address.
 */
ulong 
get_netdump_switch_stack(ulong task)
{
#ifdef DAEMON
	if (nd->task_struct == task)
		return nd->switch_stack;
	return 0;
#else
	if (!VMCORE_VALID() || !get_active_set())
		return 0;

	if (nd->task_struct == task)
		return nd->switch_stack;

	return 0;
#endif
}

int
netdump_memory_dump(FILE *fp)
{
	int i, others, wrap, flen;
	size_t len, tot;
	FILE *fpsave;
	Elf32_Off offset32;
	Elf32_Off offset64;
	struct pt_load_segment *pls;

	if (!VMCORE_VALID())
		return FALSE;

	fpsave = nd->ofp;
	nd->ofp = fp;

	netdump_print("vmcore_data: \n");
	netdump_print("                  flags: %lx (", nd->flags);
	others = 0;
	if (nd->flags & NETDUMP_LOCAL)
		netdump_print("%sNETDUMP_LOCAL", others++ ? "|" : "");
	if (nd->flags & KDUMP_LOCAL)
		netdump_print("%sKDUMP_LOCAL", others++ ? "|" : "");
	if (nd->flags & NETDUMP_REMOTE)
		netdump_print("%sNETDUMP_REMOTE", others++ ? "|" : "");
	if (nd->flags & NETDUMP_ELF32)
		netdump_print("%sNETDUMP_ELF32", others++ ? "|" : "");
	if (nd->flags & NETDUMP_ELF64)
		netdump_print("%sNETDUMP_ELF64", others++ ? "|" : "");
	if (nd->flags & KDUMP_ELF32)
		netdump_print("%sKDUMP_ELF32", others++ ? "|" : "");
	if (nd->flags & KDUMP_ELF64)
		netdump_print("%sKDUMP_ELF64", others++ ? "|" : "");
	if (nd->flags & PARTIAL_DUMP)
		netdump_print("%sPARTIAL_DUMP", others++ ? "|" : "");
	if (nd->flags & KDUMP_XEN)
		netdump_print("%sKDUMP_XEN", others++ ? "|" : "");
	if (nd->flags & KDUMP_P2M_INIT)
		netdump_print("%sKDUMP_P2M_INIT", others++ ? "|" : "");
	netdump_print(")\n");
	netdump_print("                   ndfd: %d\n", nd->ndfd);
	netdump_print("                    ofp: %lx\n", nd->ofp);
	netdump_print("            header_size: %d\n", nd->header_size);
	netdump_print("   num_pt_load_segments: %d\n", nd->num_pt_load_segments);
	for (i = 0; i < nd->num_pt_load_segments; i++) {
		pls = &nd->pt_load_segments[i];
		netdump_print("     pt_load_segment[%d]:\n", i);
		netdump_print("            file_offset: %lx\n", 
			pls->file_offset);
		netdump_print("             phys_start: %llx\n", 
			pls->phys_start);
		netdump_print("               phys_end: %llx\n", 
			pls->phys_end);
	}
	netdump_print("             elf_header: %lx\n", nd->elf_header);
	netdump_print("                  elf32: %lx\n", nd->elf32);
	netdump_print("                notes32: %lx\n", nd->notes32);
	netdump_print("                 load32: %lx\n", nd->load32);
	netdump_print("                  elf64: %lx\n", nd->elf64);
	netdump_print("                notes64: %lx\n", nd->notes64);
	netdump_print("                 load64: %lx\n", nd->load64);
	netdump_print("            nt_prstatus: %lx\n", nd->nt_prstatus);
	netdump_print("            nt_prpsinfo: %lx\n", nd->nt_prpsinfo);
	netdump_print("          nt_taskstruct: %lx\n", nd->nt_taskstruct);
	netdump_print("            task_struct: %lx\n", nd->task_struct);
	netdump_print("              page_size: %d\n", nd->page_size);
	netdump_print("           switch_stack: %lx\n", nd->switch_stack);
	netdump_print("         xen_kdump_data: %s\n",
		nd->flags & KDUMP_XEN ? " " : "(unused)");
	if (nd->flags & KDUMP_XEN) {
		netdump_print("                      cr3: %lx\n", 
			nd->xen_kdump_data->cr3);
		netdump_print("            last_mfn_read: %lx\n", 
			nd->xen_kdump_data->last_mfn_read);
		netdump_print("                     page: %lx\n", 
			nd->xen_kdump_data->page);
		netdump_print("                 accesses: %lx\n", 
			nd->xen_kdump_data->accesses);
		netdump_print("               cache_hits: %lx ", 
			nd->xen_kdump_data->cache_hits);
      		if (nd->xen_kdump_data->accesses)
                	netdump_print("(%ld%%)", 
			    nd->xen_kdump_data->cache_hits * 100 / nd->xen_kdump_data->accesses);
		netdump_print("\n               p2m_frames: %lx\n", 
			nd->xen_kdump_data->p2m_frames);
		netdump_print("       p2m_mfn_frame_list: %lx\n", 
			nd->xen_kdump_data->p2m_mfn_frame_list);
		for (i = 0; i < nd->xen_kdump_data->p2m_frames; i++)
			netdump_print("%lx ", 
				nd->xen_kdump_data->p2m_mfn_frame_list[i]);
		if (i) netdump_print("\n");
	}
	netdump_print("     num_prstatus_notes: %d\n", nd->num_prstatus_notes);	
	netdump_print("     nt_prstatus_percpu: ");
        wrap = sizeof(void *) == SIZEOF_32BIT ? 8 : 4;
        flen = sizeof(void *) == SIZEOF_32BIT ? 8 : 16;
	if (nd->num_prstatus_notes == 1)
                netdump_print("%.*lx\n", flen, nd->nt_prstatus_percpu[0]);
	else {
        	for (i = 0; i < nd->num_prstatus_notes; i++) {
                	if ((i % wrap) == 0)
                        	netdump_print("\n        ");
                	netdump_print("%.*lx ", flen, 
				nd->nt_prstatus_percpu[i]);
        	}
	}
	netdump_print("\n\n");

        switch (DUMPFILE_FORMAT(nd->flags))
	{
	case NETDUMP_ELF32:
	case KDUMP_ELF32:
		dump_Elf32_Ehdr(nd->elf32);
		dump_Elf32_Phdr(nd->notes32, ELFREAD);
                for (i = 0; i < nd->num_pt_load_segments; i++) 
			dump_Elf32_Phdr(nd->load32 + i, ELFREAD);
        	offset32 = nd->notes32->p_offset;
        	for (tot = 0; tot < nd->notes32->p_filesz; tot += len) {
                	len = dump_Elf32_Nhdr(offset32, ELFREAD);
			offset32 += len;
        	}
		break;

	case NETDUMP_ELF64:
	case KDUMP_ELF64:
		dump_Elf64_Ehdr(nd->elf64);
		dump_Elf64_Phdr(nd->notes64, ELFREAD);
                for (i = 0; i < nd->num_pt_load_segments; i++)
			dump_Elf64_Phdr(nd->load64 + i, ELFREAD);
        	offset64 = nd->notes64->p_offset;
        	for (tot = 0; tot < nd->notes64->p_filesz; tot += len) {
                	len = dump_Elf64_Nhdr(offset64, ELFREAD);
                	offset64 += len;
        	}
		break;
	}

	nd->ofp = fpsave;
        return TRUE;
}

/* 
 *  Dump an ELF file header.
 */
static void 
dump_Elf32_Ehdr(Elf32_Ehdr *elf)
{
	char buf[BUFSIZE];

	BZERO(buf, BUFSIZE);
	BCOPY(elf->e_ident, buf, SELFMAG); 
	netdump_print("Elf32_Ehdr:\n");
	netdump_print("                e_ident: \\%o%s\n", buf[0], 
		&buf[1]);
	netdump_print("      e_ident[EI_CLASS]: %d ", elf->e_ident[EI_CLASS]);
	switch (elf->e_ident[EI_CLASS])
	{
	case ELFCLASSNONE:
		netdump_print("(ELFCLASSNONE)");
		break;
	case ELFCLASS32:
		netdump_print("(ELFCLASS32)\n");
		break;
	case ELFCLASS64:
		netdump_print("(ELFCLASS64)\n");
		break;
	case ELFCLASSNUM:
		netdump_print("(ELFCLASSNUM)\n");
		break;
	default:
		netdump_print("(?)\n");
		break;
	}
	netdump_print("       e_ident[EI_DATA]: %d ", elf->e_ident[EI_DATA]);
	switch (elf->e_ident[EI_DATA])
	{
	case ELFDATANONE:
		netdump_print("(ELFDATANONE)\n");
		break;
	case ELFDATA2LSB: 
		netdump_print("(ELFDATA2LSB)\n");
		break;
	case ELFDATA2MSB:
		netdump_print("(ELFDATA2MSB)\n");
		break;
	case ELFDATANUM:
		netdump_print("(ELFDATANUM)\n");
		break;
        default:
                netdump_print("(?)\n");
	}
	netdump_print("    e_ident[EI_VERSION]: %d ", 
		elf->e_ident[EI_VERSION]);
	if (elf->e_ident[EI_VERSION] == EV_CURRENT)
		netdump_print("(EV_CURRENT)\n");
	else
		netdump_print("(?)\n");
	netdump_print("      e_ident[EI_OSABI]: %d ", elf->e_ident[EI_OSABI]);
	switch (elf->e_ident[EI_OSABI])
	{
	case ELFOSABI_SYSV:   
		netdump_print("(ELFOSABI_SYSV)\n");
		break;
	case ELFOSABI_HPUX:    
		netdump_print("(ELFOSABI_HPUX)\n");
		break;
	case ELFOSABI_ARM:      
		netdump_print("(ELFOSABI_ARM)\n");
		break;
	case ELFOSABI_STANDALONE:
		netdump_print("(ELFOSABI_STANDALONE)\n");
		break;
        default:
                netdump_print("(?)\n");
	}
	netdump_print(" e_ident[EI_ABIVERSION]: %d\n", 
		elf->e_ident[EI_ABIVERSION]);

	netdump_print("                 e_type: %d ", elf->e_type);
	switch (elf->e_type)
	{
	case ET_NONE:
		netdump_print("(ET_NONE)\n");
		break;
	case ET_REL:
		netdump_print("(ET_REL)\n");
		break;
	case ET_EXEC:
		netdump_print("(ET_EXEC)\n");
		break;
	case ET_DYN:
		netdump_print("(ET_DYN)\n");
		break;
	case ET_CORE:
		netdump_print("(ET_CORE)\n");
		break;
	case ET_NUM:
		netdump_print("(ET_NUM)\n");
		break;
	case ET_LOOS:
		netdump_print("(ET_LOOS)\n");
		break;
	case ET_HIOS:
		netdump_print("(ET_HIOS)\n");
		break;
	case ET_LOPROC:
		netdump_print("(ET_LOPROC)\n");
		break;
	case ET_HIPROC:
		netdump_print("(ET_HIPROC)\n");
		break;
	default:
		netdump_print("(?)\n");
	}

        netdump_print("              e_machine: %d ", elf->e_machine);
	switch (elf->e_machine) 
	{
	case EM_386:
		netdump_print("(EM_386)\n");
		break;
	default:
		netdump_print("(unsupported)\n");
		break;
	}

        netdump_print("              e_version: %ld ", elf->e_version);
	netdump_print("%s\n", elf->e_version == EV_CURRENT ? 
		"(EV_CURRENT)" : "");

        netdump_print("                e_entry: %lx\n", elf->e_entry);
        netdump_print("                e_phoff: %lx\n", elf->e_phoff);
        netdump_print("                e_shoff: %lx\n", elf->e_shoff);
        netdump_print("                e_flags: %lx\n", elf->e_flags);
        netdump_print("               e_ehsize: %x\n", elf->e_ehsize);
        netdump_print("            e_phentsize: %x\n", elf->e_phentsize);
        netdump_print("                e_phnum: %x\n", elf->e_phnum);
        netdump_print("            e_shentsize: %x\n", elf->e_shentsize);
        netdump_print("                e_shnum: %x\n", elf->e_shnum);
        netdump_print("             e_shstrndx: %x\n", elf->e_shstrndx);
}

static void 
dump_Elf64_Ehdr(Elf64_Ehdr *elf)
{
	char buf[BUFSIZE];

	BZERO(buf, BUFSIZE);
	BCOPY(elf->e_ident, buf, SELFMAG); 
	netdump_print("Elf64_Ehdr:\n");
	netdump_print("                e_ident: \\%o%s\n", buf[0], 
		&buf[1]);
	netdump_print("      e_ident[EI_CLASS]: %d ", elf->e_ident[EI_CLASS]);
	switch (elf->e_ident[EI_CLASS])
	{
	case ELFCLASSNONE:
		netdump_print("(ELFCLASSNONE)");
		break;
	case ELFCLASS32:
		netdump_print("(ELFCLASS32)\n");
		break;
	case ELFCLASS64:
		netdump_print("(ELFCLASS64)\n");
		break;
	case ELFCLASSNUM:
		netdump_print("(ELFCLASSNUM)\n");
		break;
	default:
		netdump_print("(?)\n");
		break;
	}
	netdump_print("       e_ident[EI_DATA]: %d ", elf->e_ident[EI_DATA]);
	switch (elf->e_ident[EI_DATA])
	{
	case ELFDATANONE:
		netdump_print("(ELFDATANONE)\n");
		break;
	case ELFDATA2LSB: 
		netdump_print("(ELFDATA2LSB)\n");
		break;
	case ELFDATA2MSB:
		netdump_print("(ELFDATA2MSB)\n");
		break;
	case ELFDATANUM:
		netdump_print("(ELFDATANUM)\n");
		break;
        default:
                netdump_print("(?)\n");
	}
	netdump_print("    e_ident[EI_VERSION]: %d ", 
		elf->e_ident[EI_VERSION]);
	if (elf->e_ident[EI_VERSION] == EV_CURRENT)
		netdump_print("(EV_CURRENT)\n");
	else
		netdump_print("(?)\n");
	netdump_print("      e_ident[EI_OSABI]: %d ", elf->e_ident[EI_OSABI]);
	switch (elf->e_ident[EI_OSABI])
	{
	case ELFOSABI_SYSV:   
		netdump_print("(ELFOSABI_SYSV)\n");
		break;
	case ELFOSABI_HPUX:    
		netdump_print("(ELFOSABI_HPUX)\n");
		break;
	case ELFOSABI_ARM:      
		netdump_print("(ELFOSABI_ARM)\n");
		break;
	case ELFOSABI_STANDALONE:
		netdump_print("(ELFOSABI_STANDALONE)\n");
		break;
        default:
                netdump_print("(?)\n");
	}
	netdump_print(" e_ident[EI_ABIVERSION]: %d\n", 
		elf->e_ident[EI_ABIVERSION]);

	netdump_print("                 e_type: %d ", elf->e_type);
	switch (elf->e_type)
	{
	case ET_NONE:
		netdump_print("(ET_NONE)\n");
		break;
	case ET_REL:
		netdump_print("(ET_REL)\n");
		break;
	case ET_EXEC:
		netdump_print("(ET_EXEC)\n");
		break;
	case ET_DYN:
		netdump_print("(ET_DYN)\n");
		break;
	case ET_CORE:
		netdump_print("(ET_CORE)\n");
		break;
	case ET_NUM:
		netdump_print("(ET_NUM)\n");
		break;
	case ET_LOOS:
		netdump_print("(ET_LOOS)\n");
		break;
	case ET_HIOS:
		netdump_print("(ET_HIOS)\n");
		break;
	case ET_LOPROC:
		netdump_print("(ET_LOPROC)\n");
		break;
	case ET_HIPROC:
		netdump_print("(ET_HIPROC)\n");
		break;
	default:
		netdump_print("(?)\n");
	}

        netdump_print("              e_machine: %d ", elf->e_machine);
        switch (elf->e_machine)
        {
	case EM_386:
		netdump_print("(EM_386)\n");
		break;
        case EM_IA_64:
                netdump_print("(EM_IA_64)\n");
                break;
        case EM_PPC64:
                netdump_print("(EM_PPC64)\n");
                break;
        case EM_X86_64:
                netdump_print("(EM_X86_64)\n");
                break;
        default:
                netdump_print("(unsupported)\n");
                break;
        }

        netdump_print("              e_version: %ld ", elf->e_version);
	netdump_print("%s\n", elf->e_version == EV_CURRENT ? 
		"(EV_CURRENT)" : "");

        netdump_print("                e_entry: %lx\n", elf->e_entry);
        netdump_print("                e_phoff: %lx\n", elf->e_phoff);
        netdump_print("                e_shoff: %lx\n", elf->e_shoff);
        netdump_print("                e_flags: %lx\n", elf->e_flags);
        netdump_print("               e_ehsize: %x\n", elf->e_ehsize);
        netdump_print("            e_phentsize: %x\n", elf->e_phentsize);
        netdump_print("                e_phnum: %x\n", elf->e_phnum);
        netdump_print("            e_shentsize: %x\n", elf->e_shentsize);
        netdump_print("                e_shnum: %x\n", elf->e_shnum);
        netdump_print("             e_shstrndx: %x\n", elf->e_shstrndx);
}

/*
 *  Dump a program segment header 
 */
static void
dump_Elf32_Phdr(Elf32_Phdr *prog, int store_pt_load_data)
{
	int others;
	struct pt_load_segment *pls;

	if (store_pt_load_data) 
		pls = &nd->pt_load_segments[store_pt_load_data-1];

	netdump_print("Elf32_Phdr:\n");
	netdump_print("                 p_type: %lx ", prog->p_type);
	switch (prog->p_type)
	{
	case PT_NULL: 
		netdump_print("(PT_NULL)\n");
		break;
	case PT_LOAD:
		netdump_print("(PT_LOAD)\n");
		break;
	case PT_DYNAMIC: 
		netdump_print("(PT_DYNAMIC)\n");
		break;
	case PT_INTERP: 
		netdump_print("(PT_INTERP)\n");
		break;
	case PT_NOTE:  
		netdump_print("(PT_NOTE)\n");
		break;
	case PT_SHLIB: 
		netdump_print("(PT_SHLIB)\n");
		break;
	case PT_PHDR:  
		netdump_print("(PT_PHDR)\n");
		break;
	case PT_NUM:
		netdump_print("(PT_NUM)\n");
		break;
	case PT_LOOS:
		netdump_print("(PT_LOOS)\n");
		break;
	case PT_HIOS:
		netdump_print("(PT_HIOS)\n");
		break;
	case PT_LOPROC:
		netdump_print("(PT_LOPROC)\n");
		break;
	case PT_HIPROC:
		netdump_print("(PT_HIPROC)\n");
		break;
	default:
		netdump_print("(?)\n");
	}

	netdump_print("               p_offset: %ld (%lx)\n", prog->p_offset, 
		prog->p_offset);
	if (store_pt_load_data)
		pls->file_offset = prog->p_offset;
	netdump_print("                p_vaddr: %lx\n", prog->p_vaddr);
	netdump_print("                p_paddr: %lx\n", prog->p_paddr);
	if (store_pt_load_data)
		pls->phys_start = prog->p_paddr; 
	netdump_print("               p_filesz: %lu (%lx)\n", prog->p_filesz, 
		prog->p_filesz);
	if (store_pt_load_data)
		pls->phys_end = pls->phys_start + prog->p_filesz;
	netdump_print("                p_memsz: %lu (%lx)\n", prog->p_memsz,
		prog->p_memsz);
	netdump_print("                p_flags: %lx (", prog->p_flags);
	others = 0;
	if (prog->p_flags & PF_X)
		netdump_print("PF_X", others++);
	if (prog->p_flags & PF_W)
		netdump_print("%sPF_W", others++ ? "|" : "");
	if (prog->p_flags & PF_R)
		netdump_print("%sPF_R", others++ ? "|" : "");
	netdump_print(")\n");
	netdump_print("                p_align: %ld\n", prog->p_align);
}

static void 
dump_Elf64_Phdr(Elf64_Phdr *prog, int store_pt_load_data)
{
	int others;
	struct pt_load_segment *pls;

	if (store_pt_load_data)
		pls = &nd->pt_load_segments[store_pt_load_data-1];

	netdump_print("Elf64_Phdr:\n");
	netdump_print("                 p_type: %lx ", prog->p_type);
	switch (prog->p_type)
	{
	case PT_NULL: 
		netdump_print("(PT_NULL)\n");
		break;
	case PT_LOAD:
		netdump_print("(PT_LOAD)\n");
		break;
	case PT_DYNAMIC: 
		netdump_print("(PT_DYNAMIC)\n");
		break;
	case PT_INTERP: 
		netdump_print("(PT_INTERP)\n");
		break;
	case PT_NOTE:  
		netdump_print("(PT_NOTE)\n");
		break;
	case PT_SHLIB: 
		netdump_print("(PT_SHLIB)\n");
		break;
	case PT_PHDR:  
		netdump_print("(PT_PHDR)\n");
		break;
	case PT_NUM:
		netdump_print("(PT_NUM)\n");
		break;
	case PT_LOOS:
		netdump_print("(PT_LOOS)\n");
		break;
	case PT_HIOS:
		netdump_print("(PT_HIOS)\n");
		break;
	case PT_LOPROC:
		netdump_print("(PT_LOPROC)\n");
		break;
	case PT_HIPROC:
		netdump_print("(PT_HIPROC)\n");
		break;
	default:
		netdump_print("(?)\n");
	}

	netdump_print("               p_offset: %ld (%lx)\n", prog->p_offset, 
		prog->p_offset);
	if (store_pt_load_data)
		pls->file_offset = prog->p_offset;
	netdump_print("                p_vaddr: %lx\n", prog->p_vaddr);
	netdump_print("                p_paddr: %lx\n", prog->p_paddr);
	if (store_pt_load_data)
		pls->phys_start = prog->p_paddr; 
	netdump_print("               p_filesz: %lu (%lx)\n", prog->p_filesz, 
		prog->p_filesz);
	if (store_pt_load_data)
		pls->phys_end = pls->phys_start + prog->p_filesz;
	netdump_print("                p_memsz: %lu (%lx)\n", prog->p_memsz,
		prog->p_memsz);
	netdump_print("                p_flags: %lx (", prog->p_flags);
	others = 0;
	if (prog->p_flags & PF_X)
		netdump_print("PF_X", others++);
	if (prog->p_flags & PF_W)
		netdump_print("%sPF_W", others++ ? "|" : "");
	if (prog->p_flags & PF_R)
		netdump_print("%sPF_R", others++ ? "|" : "");
	netdump_print(")\n");
	netdump_print("                p_align: %ld\n", prog->p_align);
}

/*
 *  Dump a note section header -- the actual data is defined by netdump
 */

static size_t 
dump_Elf32_Nhdr(Elf32_Off offset, int store)
{
	int i, lf;
	Elf32_Nhdr *note;
	size_t len;
	char buf[BUFSIZE];
	char *ptr;
	ulong *uptr;

	note = (Elf32_Nhdr *)((char *)nd->elf32 + offset);

        netdump_print("Elf32_Nhdr:\n");
        netdump_print("               n_namesz: %ld ", note->n_namesz);
        BZERO(buf, BUFSIZE);
        ptr = (char *)note + sizeof(Elf32_Nhdr);
        BCOPY(ptr, buf, note->n_namesz);
        netdump_print("(\"%s\")\n", buf);

        netdump_print("               n_descsz: %ld\n", note->n_descsz);
        netdump_print("                 n_type: %lx ", note->n_type);
	switch (note->n_type)
	{
	case NT_PRSTATUS:
		netdump_print("(NT_PRSTATUS)\n");
		if (store) { 
			if (!nd->nt_prstatus)
				nd->nt_prstatus = (void *)note;
			for (i = 0; i < NR_CPUS; i++) {
				if (!nd->nt_prstatus_percpu[i]) {
					nd->nt_prstatus_percpu[i] = (void *)note;
					nd->num_prstatus_notes++;
					break;
				}
			}
		}
		break;
	case NT_PRPSINFO:
		netdump_print("(NT_PRPSINFO)\n");
		if (store)
			nd->nt_prpsinfo = (void *)note;
		break;
	case NT_TASKSTRUCT:
		netdump_print("(NT_TASKSTRUCT)\n");
		if (store) {
			nd->nt_taskstruct = (void *)note;
			nd->task_struct = *((ulong *)(ptr + note->n_namesz));
			nd->switch_stack = *((ulong *)
				(ptr + note->n_namesz + sizeof(ulong)));
		}
		break;
        case NT_DISKDUMP:
                netdump_print("(NT_DISKDUMP)\n");
		uptr = (ulong *)(ptr + note->n_namesz);
		if (*uptr && store)
			nd->flags |= PARTIAL_DUMP;
		break;
#ifdef NOTDEF
	/*
	 *  Note: Based upon the original, abandoned, proposal for
	 *  its contents -- keep around for potential future use.
	 */
	case NT_KDUMPINFO:
		netdump_print("(NT_KDUMPINFO)\n");
		if (store) {
			uptr = (note->n_namesz == 5) ?
				(ulong *)(ptr + ((note->n_namesz + 3) & ~3)) :
				(ulong *)(ptr + note->n_namesz);
			nd->page_size = (uint)(1 << *uptr);
			uptr++;
			nd->task_struct = *uptr;
		}
		break;
#endif
	case NT_XEN_KDUMP_CR3:
                netdump_print("(NT_XEN_KDUMP_CR3)\n");
		if (store) { 
			nd->flags |= KDUMP_XEN;
			nd->xen_kdump_data = &xen_kdump_data;
			nd->xen_kdump_data->last_mfn_read = BADVAL;
			/*
			 *  Use the first cr3 found.
			 */
			if (!nd->xen_kdump_data->cr3) {
				uptr = (ulong *)(ptr + note->n_namesz);
				uptr = (ulong *)roundup((ulong)uptr, 4);
				nd->xen_kdump_data->cr3 = *uptr;
			}
		}
		break;

	default:
		netdump_print("(?)\n");
	}

	uptr = (ulong *)(ptr + note->n_namesz);

	/*
	 * kdumps are off-by-1, because their n_namesz is 5 for "CORE".
 	 */
	if ((nd->flags & KDUMP_ELF32) && (note->n_namesz == 5))
		uptr = (ulong *)(ptr + ((note->n_namesz + 3) & ~3));

	if (note->n_type == NT_XEN_KDUMP_CR3)
		uptr = (ulong *)roundup((ulong)uptr, 4);

	for (i = lf = 0; i < note->n_descsz/sizeof(ulong); i++) {
		if (((i%4)==0)) {
			netdump_print("%s                         ", 
				i ? "\n" : "");
			lf++;
		} else
			lf = 0;
		netdump_print("%08lx ", *uptr++);
	}
	if (!lf || (note->n_type == NT_TASKSTRUCT) ||
	    (note->n_type == NT_DISKDUMP) || 
	    (note->n_type == NT_XEN_KDUMP_CR3))
		netdump_print("\n");

  	len = sizeof(Elf32_Nhdr);
  	len = roundup(len + note->n_namesz, 4);
  	len = roundup(len + note->n_descsz, 4);

	return len;
}


static size_t 
dump_Elf64_Nhdr(Elf64_Off offset, int store)
{
	int i, lf;
	Elf64_Nhdr *note;
	size_t len;
	char buf[BUFSIZE];
	char *ptr;
	ulonglong *uptr;
	int *iptr;
	ulong *up;

	note = (Elf64_Nhdr *)((char *)nd->elf64 + offset);

        netdump_print("Elf64_Nhdr:\n");
        netdump_print("               n_namesz: %ld ", note->n_namesz);
        BZERO(buf, BUFSIZE);
        ptr = (char *)note + sizeof(Elf64_Nhdr);
        BCOPY(ptr, buf, note->n_namesz);
        netdump_print("(\"%s\")\n", buf);

        netdump_print("               n_descsz: %ld\n", note->n_descsz);
        netdump_print("                 n_type: %lx ", note->n_type);
	switch (note->n_type)
	{
	case NT_PRSTATUS:
		netdump_print("(NT_PRSTATUS)\n");
		if (store) {
			if (!nd->nt_prstatus)
				nd->nt_prstatus = (void *)note;
			for (i = 0; i < NR_CPUS; i++) {
				if (!nd->nt_prstatus_percpu[i]) {
					nd->nt_prstatus_percpu[i] = (void *)note;
					nd->num_prstatus_notes++;
					break;
				}
			}
		}
		break;
	case NT_PRPSINFO:
		netdump_print("(NT_PRPSINFO)\n");
		if (store)
			nd->nt_prpsinfo = (void *)note;
		break;
	case NT_TASKSTRUCT:
		netdump_print("(NT_TASKSTRUCT)\n");
		if (store) {
			nd->nt_taskstruct = (void *)note;
			nd->task_struct = *((ulong *)(ptr + note->n_namesz));
                        nd->switch_stack = *((ulong *)
                                (ptr + note->n_namesz + sizeof(ulong)));
		}
		break;
        case NT_DISKDUMP:
                netdump_print("(NT_DISKDUMP)\n");
		iptr = (int *)(ptr + note->n_namesz);
		if (*iptr && store)
			nd->flags |= PARTIAL_DUMP;
		if (note->n_descsz < sizeof(ulonglong))
			netdump_print("                         %08x", *iptr);
		break;
#ifdef NOTDEF
	/*
	 *  Note: Based upon the original, abandoned, proposal for
	 *  its contents -- keep around for potential future use.
	 */
        case NT_KDUMPINFO:
                netdump_print("(NT_KDUMPINFO)\n");
		if (store) {
			uint32_t *u32ptr;

			if (nd->elf64->e_machine == EM_386) {
				u32ptr = (note->n_namesz == 5) ?
				    (uint *)(ptr + ((note->n_namesz + 3) & ~3)) :
	                            (uint *)(ptr + note->n_namesz);
				nd->page_size = 1 << *u32ptr;
				u32ptr++;
				nd->task_struct = *u32ptr;
			} else {
	                       	uptr = (note->n_namesz == 5) ?
				    (ulonglong *)(ptr + ((note->n_namesz + 3) & ~3)) :
	                            (ulonglong *)(ptr + note->n_namesz);
				nd->page_size = (uint)(1 << *uptr);
				uptr++;
				nd->task_struct = *uptr;
			}
		}
                break;
#endif
	case NT_XEN_KDUMP_CR3:
                netdump_print("(NT_XEN_KDUMP_CR3)\n");
		if (store) {
			nd->flags |= KDUMP_XEN;
			nd->xen_kdump_data = &xen_kdump_data;
			nd->xen_kdump_data->last_mfn_read = BADVAL;
                        /*
                         *  Use the first cr3 found.
                         */
                        if (!nd->xen_kdump_data->cr3) {
				up = (ulong *)(ptr + note->n_namesz);
                                up = (ulong *)roundup((ulong)up, 4);
                                nd->xen_kdump_data->cr3 = *up;
                        }
		}
                break;

	default:
		netdump_print("(?)\n");
	}

	uptr = (ulonglong *)(ptr + note->n_namesz);

        /*
         * kdumps are off-by-1, because their n_namesz is 5 for "CORE".
         */
        if ((nd->flags & KDUMP_ELF64) && (note->n_namesz == 5))
                uptr = (ulonglong *)(ptr + ((note->n_namesz + 3) & ~3));

       if (note->n_type == NT_XEN_KDUMP_CR3)
                uptr = (ulonglong *)roundup((ulong)uptr, 4);

	for (i = lf = 0; i < note->n_descsz/sizeof(ulonglong); i++) {
		if (((i%2)==0)) {
			netdump_print("%s                         ", 
				i ? "\n" : "");
			lf++;
		} else
			lf = 0;
		netdump_print("%016llx ", *uptr++);
	}
	if (!lf)
		netdump_print("\n");
	else if (i && (i&1))
		netdump_print("\n");

  	len = sizeof(Elf64_Nhdr);
  	len = roundup(len + note->n_namesz, 4);
  	len = roundup(len + note->n_descsz, 4);

	return len;
}

/*
 *  Send the request to the proper architecture hander.
 */
void
get_netdump_regs(struct bt_info *bt, ulong *eip, ulong *esp)
{
	int e_machine;

        if (nd->elf32)
        	e_machine = nd->elf32->e_machine;
        else if (nd->elf64)
       		e_machine = nd->elf64->e_machine;
        else
        	e_machine = EM_NONE;

        switch (e_machine) 
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
		return get_netdump_regs_ppc64(bt, eip, esp);
		break;

	case EM_X86_64:
		return get_netdump_regs_x86_64(bt, eip, esp);
		break;

	default:
		error(FATAL, 
		   "support for ELF machine type %d not available\n",
			e_machine);  
	}
}

void 
get_netdump_regs_x86_64(struct bt_info *bt, ulong *ripp, ulong *rspp)
{
        Elf64_Nhdr *note;
        size_t len;
        char *user_regs;
        ulong rsp, rip;

        if (is_task_active(bt->task)) 
                bt->flags |= BT_DUMPFILE_SEARCH;

	if ((NETDUMP_DUMPFILE() || KDUMP_DUMPFILE()) &&
            VALID_STRUCT(user_regs_struct) && (bt->task == tt->panic_task)) {
		if (nd->num_prstatus_notes > 1)
                	note = (Elf64_Nhdr *)
				nd->nt_prstatus_percpu[bt->tc->processor];
		else
                	note = (Elf64_Nhdr *)nd->nt_prstatus;

                len = sizeof(Elf64_Nhdr);
                len = roundup(len + note->n_namesz, 4);
                len = roundup(len + note->n_descsz, 4);

                user_regs = ((char *)note + len)
                        - SIZE(user_regs_struct) - sizeof(long);

		if (CRASHDEBUG(1)) {
                	rsp = ULONG(user_regs + OFFSET(user_regs_struct_rsp));
                	rip = ULONG(user_regs + OFFSET(user_regs_struct_rip));
			netdump_print("ELF prstatus rsp: %lx rip: %lx\n", 
				rsp, rip);
		}

		bt->machdep = (void *)user_regs;
	}

        machdep->get_stack_frame(bt, ripp, rspp);
}

/*
 *  Netdump doesn't save state of the active tasks in the TSS, so poke around
 *  the raw stack for some reasonable hooks.
 */

void
get_netdump_regs_x86(struct bt_info *bt, ulong *eip, ulong *esp)
{
	int i, search, panic;
	char *sym;
	ulong *up;
	ulong ipintr_eip, ipintr_esp, ipintr_func;
	int check_hardirq, check_softirq;

	if (!is_task_active(bt->task)) {
		machdep->get_stack_frame(bt, eip, esp);
		return;
	}

	ipintr_eip = ipintr_esp = ipintr_func = panic = 0;
	check_hardirq = check_softirq = tt->flags & IRQSTACKS ? TRUE : FALSE;
	search = ((bt->flags & BT_TEXT_SYMBOLS) && (tt->flags & TASK_INIT_DONE))
		|| (machdep->flags & OMIT_FRAME_PTR);

retry:
	for (i = 0, up = (ulong *)bt->stackbuf; i < LONGS_PER_STACK; i++, up++){
		sym = closest_symbol(*up);
		if (STREQ(sym, "netconsole_netdump") || 
		    STREQ(sym, "netpoll_start_netdump") ||
		    STREQ(sym, "start_disk_dump") ||
		    STREQ(sym, "crash_kexec") ||
		    STREQ(sym, "disk_dump")) {
			*eip = *up;
			*esp = search ?
			    bt->stackbase + ((char *)(up+1) - bt->stackbuf) :
				*(up-1);
			return;
		}

                if (STREQ(sym, "panic")) {
                        *eip = *up;
                        *esp = search ?
			    bt->stackbase + ((char *)(up+1) - bt->stackbuf) :
				*(up-1);
			panic = TRUE;
                        continue;   /* keep looking for die */
                }

                if (STREQ(sym, "die")) {
                        *eip = *up;
                        *esp = search ? 
			    bt->stackbase + ((char *)(up+1) - bt->stackbuf) :
				*(up-1);
                        for (i++, up++; i < LONGS_PER_STACK; i++, up++) {
                                sym = closest_symbol(*up);
                                if (STREQ(sym, "sysrq_handle_crash"))
                                        goto next_sysrq;
                        }
                        return;
                }

                if (STREQ(sym, "sysrq_handle_crash")) {
next_sysrq:
                        *eip = *up;
			*esp = bt->stackbase + ((char *)(up+4) - bt->stackbuf);
			pc->flags |= SYSRQ;
			for (i++, up++; i < LONGS_PER_STACK; i++, up++) {
				sym = closest_symbol(*up);
                		if (STREQ(sym, "sysrq_handle_crash")) 
					goto next_sysrq; 
			}
                        return;
                }

		/* 
		 *  Obsolete -- replaced by sysrq_handle_crash 
		 */
                if (STREQ(sym, "sysrq_handle_netdump")) {
                        *eip = *up;
                        *esp = search ?
                            bt->stackbase + ((char *)(up+1) - bt->stackbuf) :
                                *(up-1);
                        pc->flags |= SYSRQ;
                        return;
                }

                if (STREQ(sym, "crash_nmi_callback")) {
                        *eip = *up;
                        *esp = search ?
                            bt->stackbase + ((char *)(up+1) - bt->stackbuf) :
                                *(up-1);
                        return;
                }

                if (STREQ(sym, "smp_call_function_interrupt")) {
			if (ipintr_eip && IS_VMALLOC_ADDR(ipintr_func) &&
		  	    IS_KERNEL_STATIC_TEXT(*(up - 2)))
				continue;
                        ipintr_eip = *up;
                        ipintr_esp = search ?
			    bt->stackbase + ((char *)(up+1) - bt->stackbuf) :
			    bt->stackbase + ((char *)(up-1) - bt->stackbuf);
			ipintr_func = *(up - 2);
                }
	}

	if (ipintr_eip) {
        	*eip = ipintr_eip;
        	*esp = ipintr_esp;
		return;
	}

	if (panic)
		return;

	bt->flags &= ~(BT_HARDIRQ|BT_SOFTIRQ);

	if (check_hardirq &&
	    (tt->hardirq_tasks[bt->tc->processor] == bt->tc->task)) {
		bt->stackbase = tt->hardirq_ctx[bt->tc->processor];
		bt->stacktop = bt->stackbase + STACKSIZE();
		alter_stackbuf(bt);
		bt->flags |= BT_HARDIRQ;
		check_hardirq = FALSE;
		goto retry;
	}

        if (check_softirq &&
            (tt->softirq_tasks[bt->tc->processor] == bt->tc->task)) {
                bt->stackbase = tt->softirq_ctx[bt->tc->processor];
                bt->stacktop = bt->stackbase + STACKSIZE();
		alter_stackbuf(bt);
		bt->flags |= BT_SOFTIRQ;
                check_softirq = FALSE;
                goto retry;
        }

	console("get_netdump_regs_x86: cannot find anything useful for task: %lx\n", bt->task);
 
	machdep->get_stack_frame(bt, eip, esp);
}

static void
get_netdump_regs_ppc64(struct bt_info *bt, ulong *eip, ulong *esp)
{
	Elf64_Nhdr *note;
	size_t len;

	if ((bt->task == tt->panic_task) ||
		(is_task_active(bt->task) && nd->num_prstatus_notes > 1)) {
		/*	
		 * Registers are saved during the dump process for the 
		 * panic task. Whereas in kdump, regs are captured for all 
		 * CPUs if they responded to an IPI.
		 */
                if (nd->num_prstatus_notes > 1)
                        note = (Elf64_Nhdr *)
                                nd->nt_prstatus_percpu[bt->tc->processor];
		else
			note = (Elf64_Nhdr *)nd->nt_prstatus;

		len = sizeof(Elf64_Nhdr);
		len = roundup(len + note->n_namesz, 4);
		bt->machdep = (void *)((char *)note + len + 
			MEMBER_OFFSET("elf_prstatus", "pr_reg"));
	}

	machdep->get_stack_frame(bt, eip, esp);
}

int 
is_partial_netdump(void)
{
	return (nd->flags & PARTIAL_DUMP ? TRUE : FALSE);
}


/*
 *  kexec/kdump generated vmcore files are similar enough in
 *  nature to netdump/diskdump such that most vmcore access
 *  functionality may be borrowed from the equivalent netdump
 *  function.  If not, re-work them here.
 */
int
is_kdump(char *file, ulong source_query)
{
        return is_netdump(file, source_query);
}

int
kdump_init(char *unused, FILE *fptr)
{
	return netdump_init(unused, fptr);
}

ulong 
get_kdump_panic_task(void)
{
	return get_netdump_panic_task();
}

int
read_kdump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	if ((nd->flags & KDUMP_XEN)) {
	    	if (!(nd->flags & KDUMP_P2M_INIT)) {
        		if (!machdep->xen_kdump_p2m_create)
                		error(FATAL,
                            "xen kdump dumpfiles not supported on this architecture\n");

			if ((nd->xen_kdump_data->page = 
			    (char *)malloc(PAGESIZE())) == NULL)
				error(FATAL,
				    "cannot malloc xen kdump data page\n");

			if (!machdep->xen_kdump_p2m_create(nd->xen_kdump_data))
                		error(FATAL,
                    	    "cannot create xen kdump pfn-to-mfn mapping\n");

        		nd->flags |= KDUMP_P2M_INIT;
		}

		if ((paddr = xen_kdump_p2m(paddr)) == P2M_FAILURE)
			return READ_ERROR;
	}

	return read_netdump(fd, bufptr, cnt, addr, paddr);
}

int
write_kdump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	return write_netdump(fd, bufptr, cnt, addr, paddr);
}

void
get_kdump_regs(struct bt_info *bt, ulong *eip, ulong *esp)
{
	get_netdump_regs(bt, eip, esp);
}

uint
kdump_page_size(void)
{
        uint pagesz;

        if (!VMCORE_VALID())
                return 0;

	if (!(pagesz = nd->page_size))
                pagesz = (uint)getpagesize();

        return pagesz;
}

int 
kdump_free_memory(void)
{
	return netdump_free_memory();
}

int 
kdump_memory_used(void)
{
	return netdump_memory_used();
}

int 
kdump_memory_dump(FILE *fp)
{
	return netdump_memory_dump(fp);
}

/*
 *  Translate a xen domain's pseudo-physical address into the
 *  xen machine address.  Since there's no compression involved,
 *  just the last phys_to_machine_mapping[] page read is cached, 
 *  which essentially caches 1024 p2m translations. 
 */
static physaddr_t 
xen_kdump_p2m(physaddr_t pseudo)
{
	ulong pfn, mfn_frame; 
	ulong *mfnptr;
	ulong mfn_idx, frame_idx;
	physaddr_t paddr;
	struct xen_kdump_data *xkd = nd->xen_kdump_data;

	xkd->accesses++;

	pfn = (ulong)BTOP(pseudo);
	mfn_idx = pfn / (PAGESIZE()/sizeof(ulong));
	frame_idx = pfn % (PAGESIZE()/sizeof(ulong));
	mfn_frame = xkd->p2m_mfn_frame_list[mfn_idx];

	if (mfn_frame == xkd->last_mfn_read)
		xkd->cache_hits++;
	else if (!read_netdump(0, xkd->page, PAGESIZE(), 0, 
	    	(physaddr_t)PTOB(mfn_frame)))
		return P2M_FAILURE;

	xkd->last_mfn_read = mfn_frame;

	mfnptr = ((ulong *)(xkd->page)) + frame_idx;
	paddr = (physaddr_t)PTOB((ulonglong)(*mfnptr));  
	paddr |= PAGEOFFSET(pseudo);

	if (CRASHDEBUG(7))
		fprintf(fp, 
		    "xen_dump_p2m(%llx): mfn_idx: %ld frame_idx: %ld"
		    " mfn_frame: %lx mfn: %lx => %llx\n",
			(ulonglong)pseudo, mfn_idx, frame_idx, 
			mfn_frame, *mfnptr, (ulonglong)paddr);
	
	return paddr;
}
