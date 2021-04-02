/* netdump.c 
 *
 * Copyright (C) 2002, 2003, 2004 David Anderson
 * Copyright (C) 2002, 2003, 2004 Red Hat, Inc. All rights reserved.
 *
 * This software may be freely redistributed under the terms of the
 * GNU General Public License.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Author: David Anderson
 *
 * CVS: $Revision: 1.33 $ $Date: 2005/02/17 15:48:56 $
 */

#include "defs.h"
#include "netdump.h"

struct netdump_data {
	ulong flags;
	int ndfd;
	FILE *ofp;
	uint header_size;
	char *netdump_header;
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
	ulong switch_stack;
};

static struct netdump_data netdump_data = { 0 };
static struct netdump_data *nd = &netdump_data;
static void netdump_print(char *, ...);
static void dump_Elf32_Ehdr(Elf32_Ehdr *);
static void dump_Elf32_Phdr(Elf32_Phdr *);
static size_t dump_Elf32_Nhdr(Elf32_Off offset, int);
static void dump_Elf64_Ehdr(Elf64_Ehdr *);
static void dump_Elf64_Phdr(Elf64_Phdr *);
static size_t dump_Elf64_Nhdr(Elf64_Off offset, int);
static void get_netdump_regs_x86(struct bt_info *, ulong *, ulong *);
static void get_netdump_regs_x86_64(struct bt_info *, ulong *, ulong *);
static void get_netdump_regs_ppc64(struct bt_info *, ulong *, ulong *);
	
/*
 *  Determine whether a file is a netdump creation, and if TRUE, 
 *  initialize the netdump_data structure.
 */
int 
is_netdump(char *file, ulong source) 
{
        int i;
	int fd;
	Elf32_Ehdr *elf32;
	Elf32_Phdr *load32;
	Elf64_Ehdr *elf64;
	Elf64_Phdr *load64;
	char header[MAX_NETDUMP_ELF_HEADER_SIZE];
	char buf[BUFSIZE];
	size_t size, len;
        Elf32_Off offset32;
        Elf64_Off offset64;

	if ((fd = open(file, O_RDWR)) < 0) {
        	if ((fd = open(file, O_RDONLY)) < 0) {
                        sprintf(buf, "%s: open", file);
                        perror(buf);
                        return FALSE;
		}
	}

	size = MAX_NETDUMP_ELF_HEADER_SIZE;
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

	elf32 = (Elf32_Ehdr *)&header[0];
	elf64 = (Elf64_Ehdr *)&header[0];

  	/* 
	 *  Verify the ELF header 
	 */
        if (STRNEQ(elf32->e_ident, ELFMAG) && 
	    (elf32->e_ident[EI_CLASS] == ELFCLASS32) &&
  	    (elf32->e_ident[EI_DATA] == ELFDATA2LSB) &&
    	    (elf32->e_ident[EI_VERSION] == EV_CURRENT) &&
	    (elf32->e_type == ET_CORE) &&
	    (elf32->e_version == EV_CURRENT) &&
	    (elf32->e_phnum == 2)) {
		switch (elf32->e_machine)
		{
		case EM_386:
			if (STREQ(MACHINE_TYPE, "X86"))
				break;
		default:
                	goto bailout;
		}
                nd->flags |= NETDUMP_ELF32;
                load32 = (Elf32_Phdr *)
                        &header[sizeof(Elf32_Ehdr)+sizeof(Elf32_Phdr)];
                size = (size_t)load32->p_offset;
	} else if (STRNEQ(elf64->e_ident, ELFMAG) &&
	    (elf64->e_ident[EI_CLASS] == ELFCLASS64) &&
	    (elf64->e_ident[EI_VERSION] == EV_CURRENT) &&
	    (elf64->e_type == ET_CORE) &&
	    (elf64->e_version == EV_CURRENT) &&
	    (elf64->e_phnum == 2)) { 
		switch (elf64->e_machine)
		{
		case EM_IA_64:
			if ((elf64->e_ident[EI_DATA] == ELFDATA2LSB) &&
				STREQ(MACHINE_TYPE, "IA64"))
				break;
			else
				goto bailout;

		case EM_PPC64:
			if ((elf64->e_ident[EI_DATA] == ELFDATA2MSB) &&
				STREQ(MACHINE_TYPE, "PPC64"))
				break;
			else
				goto bailout;

		case EM_X86_64:
			if ((elf64->e_ident[EI_DATA] == ELFDATA2LSB) &&
				STREQ(MACHINE_TYPE, "X86_64"))
				break;
			else
				goto bailout;

		default:
			goto bailout;
		}
                nd->flags |= NETDUMP_ELF64;
                load64 = (Elf64_Phdr *)
                        &header[sizeof(Elf64_Ehdr)+sizeof(Elf64_Phdr)];
                size = (size_t)load64->p_offset;
	} else
		goto bailout;

	if ((nd->netdump_header = (char *)malloc(size)) == NULL) {
		fprintf(stderr, "cannot malloc netdump header buffer\n");
		clean_exit(1);
	}

        if (read(fd, nd->netdump_header, size) != size) {
                sprintf(buf, "%s: read", file);
                perror(buf);
                goto bailout;
        }

	nd->ndfd = fd;
	nd->flags |= source;

	switch (nd->flags & (NETDUMP_ELF32|NETDUMP_ELF64))
	{
	case NETDUMP_ELF32:
		nd->header_size = load32->p_offset;
        	nd->elf32 = (Elf32_Ehdr *)&nd->netdump_header[0];
        	nd->notes32 = (Elf32_Phdr *)
		    &nd->netdump_header[sizeof(Elf32_Ehdr)];
        	nd->load32 = (Elf32_Phdr *)
		    &nd->netdump_header[sizeof(Elf32_Ehdr)+sizeof(Elf32_Phdr)];
                dump_Elf32_Ehdr(nd->elf32);
                dump_Elf32_Phdr(nd->notes32);
                dump_Elf32_Phdr(nd->load32);
        	offset32 = nd->notes32->p_offset;
        	for (i = len = 0; i < 3; i++) {
                	offset32 += len;
                	len = dump_Elf32_Nhdr(offset32, TRUE);
        	}
		break;

	case NETDUMP_ELF64:
                nd->header_size = load64->p_offset;
                nd->elf64 = (Elf64_Ehdr *)&nd->netdump_header[0];
                nd->notes64 = (Elf64_Phdr *)
                    &nd->netdump_header[sizeof(Elf64_Ehdr)];
                nd->load64 = (Elf64_Phdr *)
                    &nd->netdump_header[sizeof(Elf64_Ehdr)+sizeof(Elf64_Phdr)];
                dump_Elf64_Ehdr(nd->elf64);
                dump_Elf64_Phdr(nd->notes64);
                dump_Elf64_Phdr(nd->load64);
                offset64 = nd->notes64->p_offset;
                for (i = len = 0; i < 3; i++) {
                        offset64 += len;
                        len = dump_Elf64_Nhdr(offset64, TRUE);
                }
		break;
	}

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
	if (!NETDUMP_VALID())
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

        offset = (off_t)paddr + (off_t)nd->header_size;

        if (lseek(nd->ndfd, offset, SEEK_SET) == -1)
                return SEEK_ERROR;

        if (read(nd->ndfd, bufptr, cnt) != cnt)
                return READ_ERROR;
        return cnt;
}

/*
 *  Write to a netdump-created dumpfile.
 */
int
write_netdump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	off_t offset;

        offset = (off_t)paddr + (off_t)nd->header_size;

        if (lseek(nd->ndfd, offset, SEEK_SET) != offset)
                return SEEK_ERROR;

        if (write(nd->ndfd, bufptr, cnt) != cnt)
                return WRITE_ERROR;

        return cnt;
}

/*
 *  Set the file pointer for debug output.
 */
FILE *
set_netdump_fp(FILE *fp)
{
	if (!NETDUMP_VALID())
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

        if (!fmt || !strlen(fmt) || !NETDUMP_VALID())
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
	uint pagesz;

	if (!NETDUMP_VALID())
		return 0;

	switch (nd->flags & (NETDUMP_ELF32|NETDUMP_ELF64))
	{
	case NETDUMP_ELF32:
		pagesz = (uint)nd->load32->p_align;
		break;
	case NETDUMP_ELF64:
		pagesz = (uint)nd->load64->p_align;
		break;
	}

	return pagesz;
}

int 
netdump_free_memory(void)
{
	return (NETDUMP_VALID() ? 0 : 0);
}

int netdump_memory_used(void)
{
	return (NETDUMP_VALID() ? 0 : 0);
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
	int i;
        size_t len;
	char *user_regs;
	ulong ebp, esp, task;

	if (!NETDUMP_VALID() || !get_active_set())
		return NO_TASK;

	if (nd->task_struct)
		return nd->task_struct;

        if (nd->elf32 && nd->elf32->e_machine == EM_386) {
	        Elf32_Nhdr *note32 = (Elf32_Nhdr *)
			((char *)nd->elf32 + nd->notes32->p_offset);
		
	        len = sizeof(Elf32_Nhdr);
	        len = roundup(len + note32->n_namesz, 4);
	        len = roundup(len + note32->n_descsz, 4);
		
		user_regs = ((char *)note32 + len)
			- SIZE(user_regs_struct) - sizeof(int);
		ebp = ULONG(user_regs + OFFSET(user_regs_struct_ebp));
		esp = ULONG(user_regs + OFFSET(user_regs_struct_esp));
		if (CRASHDEBUG(1)) 
			fprintf(fp, 
			    "get_netdump_panic_task: esp: %lx ebp: %lx\n",
				esp, ebp);
		if (IS_KVADDR(esp)) {
			task = stkptr_to_task(esp);
			if (CRASHDEBUG(1))
				fprintf(fp, 
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
				fprintf(fp, 
			    "get_netdump_panic_task: ebp: %lx -> task: %lx\n",
					ebp, task);
                        for (i = 0; task && (i < NR_CPUS); i++) {
                                if (task == tt->active_set[i]) 
                                      return task;
                        }
                }
	} else if (nd->elf64) {
	        Elf64_Nhdr *note64 = (Elf64_Nhdr *)
			((char *)nd->elf64 + nd->notes64->p_offset);
		
	        len = sizeof(Elf64_Nhdr);
	        len = roundup(len + note64->n_namesz, 4);
		user_regs = (char *)((char *)note64 + len +
			MEMBER_OFFSET("elf_prstatus", "pr_reg"));
		if (nd->elf64->e_machine == EM_PPC64) {
			/*
			 * Get the GPR1 register value.
			 */
			esp = *(ulong *)((char *)user_regs + 8);
			if (CRASHDEBUG(1)) 
				fprintf(fp, 
			    	"get_netdump_panic_task: esp: %lx\n", esp);
			if (IS_KVADDR(esp)) {
				task = stkptr_to_task(esp);
				if (CRASHDEBUG(1))
					fprintf(fp, 
			    		"get_netdump_panic_task: esp: %lx -> task: %lx\n",
						esp, task);
				for (i = 0; task && (i < NR_CPUS); i++) {
					if (task == tt->active_set[i]) 
						return task;
				}
			}
		}
	} 

	if (CRASHDEBUG(1))
		fprintf(fp, "get_netdump_panic_task: returning NO_TASK\n");

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
	if (!NETDUMP_VALID() || !get_active_set())
		return 0;

	if (nd->task_struct == task)
		return nd->switch_stack;

	return 0;
#endif
}

int
netdump_memory_dump(FILE *fp)
{
	int i, others;
	size_t len;
	FILE *fpsave;
	Elf32_Off offset32;
	Elf32_Off offset64;

	if (!NETDUMP_VALID())
		return FALSE;

	fpsave = nd->ofp;
	nd->ofp = fp;

	netdump_print("netdump_data: \n");
	netdump_print("                  flags: %lx (", nd->flags);
	others = 0;
	if (nd->flags & NETDUMP_LOCAL)
		netdump_print("%sNETDUMP_LOCAL", others++ ? "|" : "");
	if (nd->flags & NETDUMP_REMOTE)
		netdump_print("%sNETDUMP_REMOTE", others++ ? "|" : "");
	if (nd->flags & NETDUMP_ELF32)
		netdump_print("%sNETDUMP_ELF32", others++ ? "|" : "");
	if (nd->flags & NETDUMP_ELF64)
		netdump_print("%sNETDUMP_ELF64", others++ ? "|" : "");
	netdump_print(")\n");
	netdump_print("                   ndfd: %d\n", nd->ndfd);
	netdump_print("                    ofp: %lx\n", nd->ofp);
	netdump_print("            header_size: %d\n", nd->header_size);
	netdump_print("         netdump_header: %lx\n", nd->netdump_header);
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
	netdump_print("           switch_stack: %lx\n\n", nd->switch_stack);

        switch (nd->flags & (NETDUMP_ELF32|NETDUMP_ELF64))
	{
	case NETDUMP_ELF32:
		dump_Elf32_Ehdr(nd->elf32);
		dump_Elf32_Phdr(nd->notes32);
		dump_Elf32_Phdr(nd->load32);
        	offset32 = nd->notes32->p_offset;
        	for (i = len = 0; i < 3; i++) {
                	offset32 += len;
                	len = dump_Elf32_Nhdr(offset32, FALSE);
        	}
		break;

	case NETDUMP_ELF64:
		dump_Elf64_Ehdr(nd->elf64);
		dump_Elf64_Phdr(nd->notes64);
		dump_Elf64_Phdr(nd->load64);
        	offset64 = nd->notes64->p_offset;
        	for (i = len = 0; i < 3; i++) {
                	offset64 += len;
                	len = dump_Elf64_Nhdr(offset64, FALSE);
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
dump_Elf32_Phdr(Elf32_Phdr *prog)
{
	int others;

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
	netdump_print("                p_vaddr: %lx\n", prog->p_vaddr);
	netdump_print("                p_paddr: %lx\n", prog->p_paddr);
	netdump_print("               p_filesz: %ld (%lx)\n", prog->p_filesz, 
		prog->p_filesz);
	netdump_print("                p_memsz: %ld (%lx)\n", prog->p_memsz,
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
dump_Elf64_Phdr(Elf64_Phdr *prog)
{
	int others;

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
	netdump_print("                p_vaddr: %lx\n", prog->p_vaddr);
	netdump_print("                p_paddr: %lx\n", prog->p_paddr);
	netdump_print("               p_filesz: %ld (%lx)\n", prog->p_filesz, 
		prog->p_filesz);
	netdump_print("                p_memsz: %ld (%lx)\n", prog->p_memsz,
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
dump_Elf32_Nhdr(Elf32_Off offset, int store_address)
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
        netdump_print("                 n_type: %ld ", note->n_type);
	switch (note->n_type)
	{
	case NT_PRSTATUS:
		netdump_print("(NT_PRSTATUS)\n");
		if (store_address)
			nd->nt_prstatus = (void *)note;
		break;
	case NT_PRPSINFO:
		netdump_print("(NT_PRPSINFO)\n");
		if (store_address)
			nd->nt_prpsinfo = (void *)note;
		break;
	case NT_TASKSTRUCT:
		netdump_print("(NT_TASKSTRUCT)\n");
		if (store_address) {
			nd->nt_taskstruct = (void *)note;
			nd->task_struct = *((ulong *)(ptr + note->n_namesz));
			nd->switch_stack = *((ulong *)
				(ptr + note->n_namesz + sizeof(ulong)));
		}
		break;
	default:
		netdump_print("(?)\n");
	}

	uptr = (ulong *)(ptr + note->n_namesz);
	for (i = lf = 0; i < note->n_descsz/sizeof(ulong); i++) {
		if (((i%4)==0)) {
			netdump_print("%s                         ", 
				i ? "\n" : "");
			lf++;
		} else
			lf = 0;
		netdump_print("%08lx ", *uptr++);
	}
	if (!lf || (note->n_type == NT_TASKSTRUCT))
		netdump_print("\n");

  	len = sizeof(Elf32_Nhdr);
  	len = roundup(len + note->n_namesz, 4);
  	len = roundup(len + note->n_descsz, 4);

	return len;
}


static size_t 
dump_Elf64_Nhdr(Elf64_Off offset, int store_address)
{
	int i, lf;
	Elf64_Nhdr *note;
	size_t len;
	char buf[BUFSIZE];
	char *ptr;
	ulonglong *uptr;

	note = (Elf64_Nhdr *)((char *)nd->elf64 + offset);

        netdump_print("Elf64_Nhdr:\n");
        netdump_print("               n_namesz: %ld ", note->n_namesz);
        BZERO(buf, BUFSIZE);
        ptr = (char *)note + sizeof(Elf64_Nhdr);
        BCOPY(ptr, buf, note->n_namesz);
        netdump_print("(\"%s\")\n", buf);

        netdump_print("               n_descsz: %ld\n", note->n_descsz);
        netdump_print("                 n_type: %ld ", note->n_type);
	switch (note->n_type)
	{
	case NT_PRSTATUS:
		netdump_print("(NT_PRSTATUS)\n");
		if (store_address)
			nd->nt_prstatus = (void *)note;
		break;
	case NT_PRPSINFO:
		netdump_print("(NT_PRPSINFO)\n");
		if (store_address)
			nd->nt_prpsinfo = (void *)note;
		break;
	case NT_TASKSTRUCT:
		netdump_print("(NT_TASKSTRUCT)\n");
		if (store_address) {
			nd->nt_taskstruct = (void *)note;
			nd->task_struct = *((ulong *)(ptr + note->n_namesz));
                        nd->switch_stack = *((ulong *)
                                (ptr + note->n_namesz + sizeof(ulong)));
		}
		break;
	default:
		netdump_print("(?)\n");
	}

	uptr = (ulonglong *)(ptr + note->n_namesz);
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
		   "netdump support for ELF machine type %d not available\n",
			e_machine);  
	}
}

static void 
get_netdump_regs_x86_64(struct bt_info *bt, ulong *ripp, ulong *rspp)
{
        Elf64_Nhdr *note;
        size_t len;
        char *user_regs;
        ulong rsp, rip;

        if (is_task_active(bt->task)) 
                bt->flags |= BT_DUMPFILE_SEARCH;

	if (VALID_STRUCT(user_regs_struct) && (bt->task == tt->panic_task)) {
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

static void
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
			machdep->flags |= SYSRQ;
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
                        machdep->flags |= SYSRQ;
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

	console("get_netdump_regs_x86: cannot find anything useful\n");
 
	machdep->get_stack_frame(bt, eip, esp);
}

static void
get_netdump_regs_ppc64(struct bt_info *bt, ulong *eip, ulong *esp)
{
	Elf64_Nhdr *note;
	size_t len;

	if (bt->task == tt->panic_task) {
		note = (Elf64_Nhdr *)nd->nt_prstatus;

		len = sizeof(Elf64_Nhdr);
		len = roundup(len + note->n_namesz, 4);
		bt->machdep = (void *)((char *)note + len + 
			MEMBER_OFFSET("elf_prstatus", "pr_reg"));
	}

	machdep->get_stack_frame(bt, eip, esp);
}
