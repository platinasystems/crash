/* s390.c - core analysis suite
 *
 * Copyright (C) 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002, 2003, 2004, 2005, 2006 David Anderson
 * Copyright (C) 2002, 2003, 2004, 2005, 2006 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2005, 2006 Michael Holzheu, IBM Corporation
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
#ifdef S390X
#include "defs.h"

#define S390X_WORD_SIZE   8

#define S390X_PAGE_BASE_MASK     (~((1ULL<<12)-1))

/* Flags used in entries of page dirs and page tables.
 */
#define S390X_PAGE_PRESENT   0x001ULL    /* set: loaded in physical memory
                                          * clear: not loaded in physical mem */
#define S390X_PAGE_RO           0x200ULL /* HW read-only */
#define S390X_PAGE_INVALID      0x400ULL /* HW invalid */
#define S390X_PAGE_INVALID_MASK 0x601ULL /* for linux 2.6 */
#define S390X_PAGE_INVALID_NONE 0x401ULL /* for linux 2.6 */

/* bits 52, 55 must contain zeroes in a pte */
#define S390X_PTE_INVALID_MASK  0x900ULL
#define S390X_PTE_INVALID(x) ((x) & S390X_PTE_INVALID_MASK)

#define ASYNC_STACK_SIZE  STACKSIZE() // can be 8192 or 16384
#define KERNEL_STACK_SIZE STACKSIZE() // can be 8192 or 16384

#define LOWCORE_SIZE 8192

/*
 * declarations of static functions
 */
static void s390x_print_lowcore(char*, struct bt_info*,int);
static int s390x_kvtop(struct task_context *, ulong, physaddr_t *, int);
static int s390x_uvtop(struct task_context *, ulong, physaddr_t *, int);
static int s390x_vtop(unsigned long, ulong, physaddr_t*, int);
static ulong s390x_vmalloc_start(void);
static int s390x_is_task_addr(ulong);
static int s390x_verify_symbol(const char *, ulong, char type);
static ulong s390x_get_task_pgd(ulong);
static int s390x_translate_pte(ulong, void *, ulonglong);
static ulong s390x_processor_speed(void);
static int s390x_eframe_search(struct bt_info *);
static void s390x_back_trace_cmd(struct bt_info *);
static void s390x_dump_irq(int);
static void s390x_get_stack_frame(struct bt_info *, ulong *, ulong *);
static int s390x_dis_filter(ulong, char *);
static void s390x_cmd_mach(void);
static int s390x_get_smp_cpus(void);
static void s390x_display_machine_stats(void);
static void s390x_dump_line_number(ulong);
static struct line_number_hook s390x_line_number_hooks[];
static int s390x_is_uvaddr(ulong, struct task_context *);


/*
 *  Do all necessary machine-specific setup here.  This is called several
 *  times during initialization.
 */
void
s390x_init(int when)
{
	switch (when)
	{
	case PRE_SYMTAB:
		machdep->verify_symbol = s390x_verify_symbol;
		if (pc->flags & KERNEL_DEBUG_QUERY)
			return;
		machdep->pagesize = memory_page_size();
		machdep->pageshift = ffs(machdep->pagesize) - 1;
		machdep->pageoffset = machdep->pagesize - 1;
		machdep->pagemask = ~((ulonglong)machdep->pageoffset);
		// machdep->stacksize = KERNEL_STACK_SIZE;
		if ((machdep->pgd = (char *)malloc(SEGMENT_TABLE_SIZE)) == NULL)
			error(FATAL, "cannot malloc pgd space.");
		machdep->pmd = machdep->pgd;
		if ((machdep->ptbl = (char *)malloc(PAGESIZE())) == NULL)
			error(FATAL, "cannot malloc ptbl space.");
		machdep->last_pgd_read = 0;
		machdep->last_pmd_read = 0;
		machdep->last_ptbl_read = 0;
		machdep->verify_paddr = generic_verify_paddr;
		machdep->ptrs_per_pgd = PTRS_PER_PGD;
		break;

	case PRE_GDB:
		machdep->kvbase = 0;
		machdep->identity_map_base = 0;
		machdep->is_kvaddr =  generic_is_kvaddr;
		machdep->is_uvaddr =  s390x_is_uvaddr;
		machdep->eframe_search = s390x_eframe_search;
		machdep->back_trace = s390x_back_trace_cmd;
		machdep->processor_speed = s390x_processor_speed;
		machdep->uvtop = s390x_uvtop;
		machdep->kvtop = s390x_kvtop;
		machdep->get_task_pgd = s390x_get_task_pgd;
		machdep->get_stack_frame = s390x_get_stack_frame;
		machdep->get_stackbase = generic_get_stackbase;
		machdep->get_stacktop = generic_get_stacktop;
		machdep->translate_pte = s390x_translate_pte;
		machdep->memory_size = generic_memory_size;
		machdep->is_task_addr = s390x_is_task_addr;
		machdep->dis_filter = s390x_dis_filter;
		machdep->cmd_mach = s390x_cmd_mach;
		machdep->get_smp_cpus = s390x_get_smp_cpus;
		machdep->line_number_hooks = s390x_line_number_hooks;
		machdep->value_to_symbol = generic_machdep_value_to_symbol;
		machdep->init_kernel_pgd = NULL;
		vt->flags |= COMMON_VADDR;
		break;

	case POST_GDB:
		machdep->nr_irqs = 0;  /* TBD */
		machdep->vmalloc_start = s390x_vmalloc_start;
		machdep->dump_irq = s390x_dump_irq;
		if (!machdep->hz)
			machdep->hz = HZ;
		machdep->section_size_bits = _SECTION_SIZE_BITS;
		machdep->max_physmem_bits = _MAX_PHYSMEM_BITS;
		break;

	case POST_INIT:
		break;
	}
}

/*
 * Dump machine dependent information
 */
void
s390x_dump_machdep_table(ulong arg)
{
	int others; 
 
	others = 0;
	fprintf(fp, "              flags: %lx (", machdep->flags);
	if (machdep->flags & KSYMS_START)
		fprintf(fp, "%sKSYMS_START", others++ ? "|" : "");
	fprintf(fp, ")\n");

	fprintf(fp, "             kvbase: %lx\n", machdep->kvbase);
	fprintf(fp, "  identity_map_base: %lx\n", machdep->kvbase);
	fprintf(fp, "           pagesize: %d\n", machdep->pagesize);
	fprintf(fp, "          pageshift: %d\n", machdep->pageshift);
	fprintf(fp, "           pagemask: %llx\n", machdep->pagemask);
	fprintf(fp, "         pageoffset: %lx\n", machdep->pageoffset);
	fprintf(fp, "          stacksize: %ld\n", machdep->stacksize);
	fprintf(fp, "                 hz: %d\n", machdep->hz);
	fprintf(fp, "                mhz: %ld\n", machdep->mhz);
	fprintf(fp, "            memsize: %lld (0x%llx)\n", 
		(unsigned long long)machdep->memsize,
		(unsigned long long)machdep->memsize);
	fprintf(fp, "               bits: %d\n", machdep->bits);
	fprintf(fp, "            nr_irqs: %d\n", machdep->nr_irqs);
	fprintf(fp, "      eframe_search: s390x_eframe_search()\n");
	fprintf(fp, "         back_trace: s390x_back_trace_cmd()\n");
	fprintf(fp, "    processor_speed: s390x_processor_speed()\n");
	fprintf(fp, "              uvtop: s390x_uvtop()\n");
	fprintf(fp, "              kvtop: s390x_kvtop()\n");
	fprintf(fp, "       get_task_pgd: s390x_get_task_pgd()\n");
	fprintf(fp, "           dump_irq: s390x_dump_irq()\n");
	fprintf(fp, "    get_stack_frame: s390x_get_stack_frame()\n");
	fprintf(fp, "      get_stackbase: generic_get_stackbase()\n");
	fprintf(fp, "       get_stacktop: generic_get_stacktop()\n");
	fprintf(fp, "      translate_pte: s390x_translate_pte()\n");
	fprintf(fp, "        memory_size: generic_memory_size()\n");
	fprintf(fp, "      vmalloc_start: s390x_vmalloc_start()\n");
	fprintf(fp, "       is_task_addr: s390x_is_task_addr()\n");
	fprintf(fp, "      verify_symbol: s390x_verify_symbol()\n");
	fprintf(fp, "         dis_filter: s390x_dis_filter()\n");
	fprintf(fp, "           cmd_mach: s390x_cmd_mach()\n");
	fprintf(fp, "       get_smp_cpus: s390x_get_smp_cpus()\n");
	fprintf(fp, "          is_kvaddr: generic_is_kvaddr()\n");
	fprintf(fp, "          is_uvaddr: s390x_is_uvaddr()\n");
	fprintf(fp, "       verify_paddr: generic_verify_paddr()\n");
	fprintf(fp, "    init_kernel_pgd: NULL\n");
	fprintf(fp, "    value_to_symbol: generic_machdep_value_to_symbol()\n");
	fprintf(fp, "  line_number_hooks: s390x_line_number_hooks\n");
	fprintf(fp, "      last_pgd_read: %lx\n", machdep->last_pgd_read);
	fprintf(fp, "      last_pmd_read: %lx\n", machdep->last_pmd_read);
	fprintf(fp, "     last_ptbl_read: %lx\n", machdep->last_ptbl_read);
	fprintf(fp, "                pgd: %lx\n", (ulong)machdep->pgd);
	fprintf(fp, "                pmd: %lx\n", (ulong)machdep->pmd);
	fprintf(fp, "               ptbl: %lx\n", (ulong)machdep->ptbl);
	fprintf(fp, "       ptrs_per_pgd: %d\n", machdep->ptrs_per_pgd);
	fprintf(fp, "   max_physmem_bits: %ld\n", machdep->max_physmem_bits);
	fprintf(fp, "  section_size_bits: %ld\n", machdep->section_size_bits);
	fprintf(fp, "           machspec: %lx\n", (ulong)machdep->machspec);
}

/*
 * Check if address is in context's address space
 */
static int 
s390x_is_uvaddr(ulong vaddr, struct task_context *tc)
{
	return IN_TASK_VMA(tc->task, vaddr);
}

/*
 *  Translates a user virtual address to its physical address
 */
static int
s390x_uvtop(struct task_context *tc, ulong vaddr, physaddr_t *paddr, int verbose)
{
	unsigned long pgd_base;
	readmem(tc->mm_struct + OFFSET(mm_struct_pgd), KVADDR,
		&pgd_base,sizeof(long), "pgd_base",FAULT_ON_ERROR);
	return s390x_vtop(pgd_base, vaddr, paddr, verbose);	
}

/*
 *  Translates a kernel virtual address to its physical address
 */
static int
s390x_kvtop(struct task_context *tc, ulong vaddr, physaddr_t *paddr, int verbose)
{
	unsigned long pgd_base;

	if (!IS_KVADDR(vaddr)){
		*paddr = 0;
		return FALSE;
	}

	if (!vt->vmalloc_start) {
	       *paddr = VTOP(vaddr);
	       return TRUE;
	}

	if (!IS_VMALLOC_ADDR(vaddr)) {
	       *paddr = VTOP(vaddr);
	       return TRUE;
	}

	pgd_base = (unsigned long)vt->kernel_pgd[0];
	return s390x_vtop(pgd_base, vaddr, paddr, verbose);	
}

/*
 * Check if page is mapped
 */
static inline int s390x_pte_present(unsigned long x){
	if(THIS_KERNEL_VERSION >= LINUX(2,6,0)){
		return !((x) & S390X_PAGE_INVALID) ||
			((x) & S390X_PAGE_INVALID_MASK) == S390X_PAGE_INVALID_NONE;
	} else {
		return ((x) & S390X_PAGE_PRESENT);
	}
}

/*
 * page table traversal functions 
 */

/* Region or segment table traversal function */
static ulong _kl_rsg_table_deref_s390x(ulong vaddr, ulong table,
					 int len, int level)
{
	ulong offset, entry;

	offset = ((vaddr >> (11*level + 20)) & 0x7ffULL) * 8;
	if (offset >= (len + 1)*4096)
		/* Offset is over the table limit. */
		return 0;
	readmem(table + offset, KVADDR, &entry, sizeof(entry), "entry",
		FAULT_ON_ERROR);
	/*
	 * Check if the segment table entry could be read and doesn't have
	 * any of the reserved bits set.
	 */
	if ((entry & 0xcULL) != (level << 2))
		return 0;
	/* Check if the region table entry has the invalid bit set. */
	if (entry & 0x40ULL)
		return 0;
	/* Region table entry is valid and well formed. */
	return entry;
}

/* Page table traversal function */
static ulong _kl_pg_table_deref_s390x(ulong vaddr, ulong table)
{
	ulong offset, entry;

	offset = ((vaddr >> 12) & 0xffULL) * 8;
	readmem(table + offset, KVADDR, &entry, sizeof(entry), "entry",
		FAULT_ON_ERROR);
	/*
	 * Check if the page table entry could be read and doesn't have
	 * any of the reserved bits set.
	 */
	if (entry & 0x900ULL)
		return 0;
	/* Check if the page table entry has the invalid bit set. */
	if (entry & 0x400ULL)
		return 0;
	/* Page table entry is valid and well formed. */
	return entry;
}

/* lookup virtual address in page tables */
int s390x_vtop(ulong table, ulong vaddr, physaddr_t *phys_addr, int verbose)
{
	ulong entry, paddr;
	int level, len;

	/*
	 * Walk the region and segment tables.
	 * We assume that the table length field in the asce is set to the
	 * maximum value of 3 (which translates to a region first, region
	 * second, region third or segment table with 2048 entries) and that
	 * the addressing mode is 64 bit.
	 */
	len = 3;
	/* Read the first entry to find the number of page table levels. */
	readmem(table, KVADDR, &entry, sizeof(entry), "entry", FAULT_ON_ERROR);
	level = (entry & 0xcULL) >> 2;
	if ((vaddr >> (31 + 11*level)) != 0ULL) {
		/* Address too big for the number of page table levels. */
		return FALSE;
	}
	while (level >= 0) {
		entry = _kl_rsg_table_deref_s390x(vaddr, table, len, level);
		if (!entry)
			return 0;
		table = entry & ~0xfffULL;
		len = entry & 0x3ULL;
		level--;
	}

	/* Check if this is a large page. */
	if (entry & 0x400ULL)
		/* Add the 1MB page offset and return the final value. */
		return table + (vaddr & 0xfffffULL);

	/* Get the page table entry */
	entry = _kl_pg_table_deref_s390x(vaddr, entry & ~0x7ffULL);
	if (!entry)
		return FALSE;

	/* Isolate the page origin from the page table entry. */
	paddr = entry & ~0xfffULL;

	/* Add the page offset and return the final value. */
	*phys_addr = paddr + (vaddr & 0xfffULL);

	return TRUE;
}

/*
 *  Determine where vmalloc'd memory starts.
 */
static ulong
s390x_vmalloc_start(void)
{
	unsigned long highmem_addr,high_memory;
	highmem_addr=symbol_value("high_memory");
       	readmem(highmem_addr, PHYSADDR, &high_memory,sizeof(long),
		"highmem",FAULT_ON_ERROR);
	return high_memory;
}

/*
 * Check if address can be a valid task_struct
 */
static int
s390x_is_task_addr(ulong task)
{
	if (tt->flags & THREAD_INFO)
		return IS_KVADDR(task);
	else
		return (IS_KVADDR(task) && (ALIGNED_STACK_OFFSET(task) == 0));
}

/*
 * return MHz - unfortunately it is not possible to get this on linux 
 *              for zSeries
 */
static ulong
s390x_processor_speed(void)
{
	return 0;
}

/*
 *  Accept or reject a symbol from the kernel namelist.
 */
static int
s390x_verify_symbol(const char *name, ulong value, char type)
{
	int i;

	if (CRASHDEBUG(8) && name && strlen(name))
		fprintf(fp, "%08lx %s\n", value, name);

	if (STREQ(name, "startup") || STREQ(name, "_stext"))
		machdep->flags |= KSYMS_START;

	if (!name || !strlen(name) || !(machdep->flags & KSYMS_START))
		return FALSE;

	if ((type == 'A') && STRNEQ(name, "__crc_"))
		return FALSE;

	if (STREQ(name, "Letext") || STREQ(name, "gcc2_compiled."))
		return FALSE;

        /* reject L2^B symbols */
	if (strstr(name, "L2\002") == name)
	    	return FALSE;

	/* throw away all symbols containing a '.' */
	for(i = 0; i < strlen(name);i++){
		if(name[i] == '.')
			return FALSE;
	}

	return TRUE;
}

/*
 *  Get the relevant page directory pointer from a task structure.
 */
static ulong
s390x_get_task_pgd(ulong task)
{
	return (error(FATAL, "s390x_get_task_pgd: TBD\n"));
}

/*
 *  Translate a PTE, returning TRUE if the page is present.
 *  If a physaddr pointer is passed in, don't print anything.
 */
static int
s390x_translate_pte(ulong pte, void *physaddr, ulonglong unused)
{
	char *arglist[MAXARGS];
	char buf[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char ptebuf[BUFSIZE];
	int c,len1,len2,len3;

	if(S390X_PTE_INVALID(pte)){
		fprintf(fp,"PTE is invalid\n");
		return FALSE;
	}

	if(physaddr)
		*((ulong *)physaddr) = pte & S390X_PAGE_BASE_MASK;

	if(!s390x_pte_present(pte)){
		swap_location(pte, buf);
		if ((c = parse_line(buf, arglist)) != 3)
			error(FATAL, "cannot determine swap location\n");

		len2 = MAX(strlen(arglist[0]), strlen("SWAP"));
		len3 = MAX(strlen(arglist[2]), strlen("OFFSET"));

		fprintf(fp, "%s  %s\n",
			mkstring(buf2, len2, CENTER|LJUST, "SWAP"),
			mkstring(buf3, len3, CENTER|LJUST, "OFFSET"));

		strcpy(buf2, arglist[0]);
		strcpy(buf3, arglist[2]);
		fprintf(fp, "%s  %s  %s\n",
			mkstring(ptebuf, len1, CENTER|RJUST, NULL),
			mkstring(buf2, len2, CENTER|RJUST, NULL),
			mkstring(buf3, len3, CENTER|RJUST, NULL));
		return FALSE;
	}
	fprintf(fp,"PTE      PHYSICAL  FLAGS\n");
	fprintf(fp,"%08lx %08llx",pte, pte & S390X_PAGE_BASE_MASK);
	fprintf(fp,"  (");
	if(pte & S390X_PAGE_INVALID)
		fprintf(fp,"INVALID ");
	if(pte & S390X_PAGE_RO)
		fprintf(fp,"PROTECTION");
	fprintf(fp,")");
	return TRUE;
}

/*
 *  Look for likely exception frames in a stack.
 */
static int 
s390x_eframe_search(struct bt_info *bt)
{
	if(bt->flags & BT_EFRAME_SEARCH2)
		return (error(FATAL, 
		    "Option '-E' is not implemented for this architecture\n"));
	else
		return (error(FATAL, 
		    "Option '-e' is not implemented for this architecture\n"));
}

/*
 * returns cpu number of task
 */ 
static int 
s390x_cpu_of_task(unsigned long task)
{
	unsigned int cpu;

	if(VALID_MEMBER(task_struct_processor)){
		/* linux 2.4 */
		readmem(task + OFFSET(task_struct_processor),KVADDR,
                        &cpu, sizeof(cpu), "task_struct_processor", 
			FAULT_ON_ERROR);		
	} else {
		/* linux 2.6 */
		char thread_info[8192];
		unsigned long thread_info_addr;
		readmem(task + OFFSET(task_struct_thread_info),KVADDR,
                        &thread_info_addr, sizeof(thread_info_addr),
                        "thread info addr", FAULT_ON_ERROR);
		readmem(thread_info_addr,KVADDR,thread_info,sizeof(thread_info),
			"thread info", FAULT_ON_ERROR);
		cpu = *((int*) &thread_info[OFFSET(thread_info_cpu)]);
	}
	return cpu;
}

/*
 * returns true, if task currently is executed by a cpu
 */ 
static int 
s390x_has_cpu(unsigned long task)
{
	if(VALID_MEMBER(task_struct_cpus_runnable)){
		/* Linux 2.4 */
		unsigned long cpus_runnable;
		readmem(task+OFFSET(task_struct_cpus_runnable),KVADDR,
			&cpus_runnable,sizeof(cpus_runnable),
			"cpus_runnable", FAULT_ON_ERROR);
		if(cpus_runnable != ~0ULL)
			return TRUE;
		else
			return FALSE;
	} else {
		/* Linux 2.6 */
		unsigned long runqueue_addr, runqueue_offset;
		unsigned long cpu_offset, per_cpu_offset_addr, running_task;
		char *runqueue;
		int cpu;

		cpu = s390x_cpu_of_task(task);
		runqueue = GETBUF(SIZE(runqueue));

		runqueue_offset=symbol_value("per_cpu__runqueues");
		per_cpu_offset_addr=symbol_value("__per_cpu_offset");
		readmem(per_cpu_offset_addr + cpu * sizeof(long),KVADDR,
			&cpu_offset, sizeof(long),"per_cpu_offset",
			FAULT_ON_ERROR);
		runqueue_addr=runqueue_offset + cpu_offset;
		readmem(runqueue_addr,KVADDR,runqueue,SIZE(runqueue),
			"runqueue", FAULT_ON_ERROR);
		running_task = ULONG(runqueue + OFFSET(runqueue_curr));
		FREEBUF(runqueue);
		if(running_task == task)
			return TRUE; 
		else
			return FALSE;
	}
}

/*
 * read lowcore for cpu
 */
static void
s390x_get_lowcore(int cpu, char* lowcore)
{
	unsigned long lowcore_array,lowcore_ptr;

	lowcore_array = symbol_value("lowcore_ptr");
	readmem(lowcore_array + cpu * S390X_WORD_SIZE,KVADDR,
		&lowcore_ptr, sizeof(long), "lowcore_ptr", FAULT_ON_ERROR);
	readmem(lowcore_ptr, KVADDR, lowcore, LOWCORE_SIZE, "lowcore", 
		FAULT_ON_ERROR);
}

/*
 * read in the async stack
 */
static void
s390x_get_async_stack(char* lowcore, char* async_stack, unsigned long* start, unsigned long* end)
{
	unsigned long async_stack_ptr;

	async_stack_ptr = ULONG(lowcore + 
				MEMBER_OFFSET("_lowcore","async_stack"));
	readmem(async_stack_ptr-ASYNC_STACK_SIZE,KVADDR, async_stack, 
		ASYNC_STACK_SIZE, "async_stack", FAULT_ON_ERROR);
	*start=async_stack_ptr-ASYNC_STACK_SIZE;
	*end=async_stack_ptr;
}

/*
 * Unroll a kernel stack.
 */
static void
s390x_back_trace_cmd(struct bt_info *bt)
{
	char* stack;
	char async_stack[ASYNC_STACK_SIZE];
	long ksp,backchain,old_backchain;
	int i=0, r14_offset,bc_offset,r14, skip_first_frame=0;
	unsigned long async_start = 0, async_end = 0;
	unsigned long stack_end, stack_start, stack_base;

	if (bt->hp && bt->hp->eip) {
		error(WARNING,
	        "instruction pointer argument ignored on this architecture!\n");
	}
	ksp = bt->stkptr;

	/* print lowcore and get async stack when task has cpu */
	if(s390x_has_cpu(bt->task)){
		char lowcore[LOWCORE_SIZE];
		unsigned long psw_flags;
		int cpu = s390x_cpu_of_task(bt->task);

		if (ACTIVE()) {
			fprintf(fp,"(active)\n");
			return;
		}
		s390x_get_lowcore(cpu,lowcore);
		psw_flags = ULONG(lowcore + MEMBER_OFFSET("_lowcore",
			    "st_status_fixed_logout"));
		if(psw_flags & 0x1000000000000ULL){
			fprintf(fp,"Task runs in userspace\n");
			s390x_print_lowcore(lowcore,bt,0);
			return;
		}

		s390x_get_async_stack(lowcore,async_stack,&async_start,
				     &async_end);
		s390x_print_lowcore(lowcore,bt,1);
		fprintf(fp,"\n");
		skip_first_frame=1;
	}

	/* get task stack start and end */
	if(THIS_KERNEL_VERSION >= LINUX(2,6,0)){
		readmem(bt->task + OFFSET(task_struct_thread_info),KVADDR,
			&stack_start, sizeof(long), "thread info", 
			FAULT_ON_ERROR);
	} else {
		stack_start = bt->task;
	}
	stack_end   = stack_start + KERNEL_STACK_SIZE;

	if(!STRUCT_EXISTS("stack_frame")){
		r14_offset = 112;
		bc_offset=0;
	} else {
		r14_offset = MEMBER_OFFSET("stack_frame","gprs") + 
			     8 * S390X_WORD_SIZE;
		bc_offset  = MEMBER_OFFSET("stack_frame","back_chain");
	}
	backchain = ksp; 
	do {
		unsigned long r14_stack_off;
		int j;

		/* Find stack: Either async stack or task stack */
		if((backchain > stack_start) && (backchain < stack_end)){
			stack = bt->stackbuf;
			stack_base = stack_start;
		} else if((backchain > async_start) && (backchain < async_end)
			  && s390x_has_cpu(bt->task)){
			stack = async_stack;
			stack_base = async_start;
		} else {
			/* invalid stackframe */
			break;
		}
		r14_stack_off=backchain - stack_base + r14_offset; 
		r14 = ULONG(&stack[r14_stack_off]);

		/* print function name */
		if(BT_REFERENCE_CHECK(bt)){
			if(bt->ref->cmdflags & BT_REF_HEXVAL){
				if(r14 == bt->ref->hexval)
					bt->ref->cmdflags |= BT_REF_FOUND;
			} else {
				if(STREQ(closest_symbol(r14),bt->ref->str))
					bt->ref->cmdflags |= BT_REF_FOUND;
			}
		} else if(skip_first_frame){
			skip_first_frame=0;
		} else {
			fprintf(fp," #%i [%08lx] ",i,backchain);
			fprintf(fp,"%s at %x\n", closest_symbol(r14), r14);
			if (bt->flags & BT_LINE_NUMBERS)
				s390x_dump_line_number(r14);
			i++;
		}
		old_backchain=backchain;
		backchain = ULONG(&stack[backchain - stack_base + bc_offset]);

		/* print stack content if -f is specified */
		if ((bt->flags & BT_FULL) && !BT_REFERENCE_CHECK(bt)) {
			int frame_size;
			if (backchain == 0) {
				frame_size = stack_base - old_backchain 
					     + KERNEL_STACK_SIZE;
			} else {
				frame_size = MIN((backchain - old_backchain),
					(stack_base - old_backchain +
					KERNEL_STACK_SIZE));
			}
			for (j = 0; j < frame_size; j += 8) {
				if(j % 16 == 0){
					fprintf(fp, "%s    %016lx: ", 
                                            j ? "\n" : "", old_backchain + j);
				}
				fprintf(fp," %016lx",
                                    ULONG(&stack[old_backchain - stack_base + j]));
			}
			fprintf(fp, "\n");
		}

		/* Check for interrupt stackframe */
		if((backchain == 0) && (stack == async_stack)){
			unsigned long psw_flags,r15;

			psw_flags = ULONG(&stack[old_backchain - stack_base 
					  +96 +MEMBER_OFFSET("pt_regs","psw")]);
			if(psw_flags & 0x1000000000000ULL){
				/* User psw: should not happen */
				break;
			}
			r15 = ULONG(&stack[old_backchain - stack_base +
				    96 + MEMBER_OFFSET("pt_regs",
				    "gprs") + 15 * S390X_WORD_SIZE]);
			backchain=r15;
			fprintf(fp," - Interrupt -\n");
		}
      } while(backchain != 0);
}

/*
 * print lowcore info (psw and all registers)
 */
static void
s390x_print_lowcore(char* lc, struct bt_info *bt,int show_symbols)
{
	char* ptr;
	unsigned long tmp[4];

	ptr = lc + MEMBER_OFFSET("_lowcore","st_status_fixed_logout");
	tmp[0]=ULONG(ptr);
	tmp[1]=ULONG(ptr + S390X_WORD_SIZE);

	if(BT_REFERENCE_CHECK(bt)){
		if(bt->ref->cmdflags & BT_REF_HEXVAL){
			if(tmp[1] == bt->ref->hexval)
				bt->ref->cmdflags |= BT_REF_FOUND;
		} else {
			if(STREQ(closest_symbol(tmp[1]),bt->ref->str))
				bt->ref->cmdflags |= BT_REF_FOUND;
		}
		return;
	}
	fprintf(fp," LOWCORE INFO:\n");
	fprintf(fp,"  -psw      : %#018lx %#018lx\n", tmp[0], tmp[1]);
	if(show_symbols){
		fprintf(fp,"  -function : %s at %lx\n", 
			closest_symbol(tmp[1]), tmp[1]);
		if (bt->flags & BT_LINE_NUMBERS)
			s390x_dump_line_number(tmp[1]);
	}
	ptr = lc + MEMBER_OFFSET("_lowcore","prefixreg_save_area");
	tmp[0] = UINT(ptr);
	fprintf(fp,"  -prefix   : %#010lx\n", tmp[0]);
	
	ptr = lc + MEMBER_OFFSET("_lowcore","cpu_timer_save_area");
	tmp[0]=UINT(ptr);
	tmp[1]=UINT(ptr + S390X_WORD_SIZE);
	fprintf(fp,"  -cpu timer: %#010lx %#010lx\n", tmp[0],tmp[1]);

	ptr = lc + MEMBER_OFFSET("_lowcore","clock_comp_save_area");
	tmp[0]=UINT(ptr);
	tmp[1]=UINT(ptr + S390X_WORD_SIZE);
	fprintf(fp,"  -clock cmp: %#010lx %#010lx\n", tmp[0], tmp[1]);

	fprintf(fp,"  -general registers:\n");
	ptr = lc + MEMBER_OFFSET("_lowcore","gpregs_save_area");
	tmp[0]=ULONG(ptr);
	tmp[1]=ULONG(ptr + S390X_WORD_SIZE);
	tmp[2]=ULONG(ptr + 2 * S390X_WORD_SIZE);
	tmp[3]=ULONG(ptr + 3 * S390X_WORD_SIZE);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[0],tmp[1]);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[2],tmp[3]);
	tmp[0]=ULONG(ptr + 4 * S390X_WORD_SIZE);
	tmp[1]=ULONG(ptr + 5 * S390X_WORD_SIZE);
	tmp[2]=ULONG(ptr + 6 * S390X_WORD_SIZE);
	tmp[3]=ULONG(ptr + 7 * S390X_WORD_SIZE);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[0],tmp[1]);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[2],tmp[3]);
	tmp[0]=ULONG(ptr + 8 * S390X_WORD_SIZE);
	tmp[1]=ULONG(ptr + 9 * S390X_WORD_SIZE);
	tmp[2]=ULONG(ptr + 10* S390X_WORD_SIZE);
	tmp[3]=ULONG(ptr + 11* S390X_WORD_SIZE);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[0],tmp[1]);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[2],tmp[3]);
	tmp[0]=ULONG(ptr + 12* S390X_WORD_SIZE);
	tmp[1]=ULONG(ptr + 13* S390X_WORD_SIZE);
	tmp[2]=ULONG(ptr + 14* S390X_WORD_SIZE);
	tmp[3]=ULONG(ptr + 15* S390X_WORD_SIZE);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[0],tmp[1]);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[2],tmp[3]);

	fprintf(fp,"  -access registers:\n");
	ptr = lc + MEMBER_OFFSET("_lowcore","access_regs_save_area");
	tmp[0]=ULONG(ptr);
	tmp[1]=ULONG(ptr + 4);
	tmp[2]=ULONG(ptr + 2 * 4);
	tmp[3]=ULONG(ptr + 3 * 4);
	fprintf(fp,"     %#010lx %#010lx %#010lx %#010lx\n", 
		tmp[0], tmp[1], tmp[2], tmp[3]);
	tmp[0]=ULONG(ptr + 4 * 4);
	tmp[1]=ULONG(ptr + 5 * 4);
	tmp[2]=ULONG(ptr + 6 * 4);
	tmp[3]=ULONG(ptr + 7 * 4);
	fprintf(fp,"     %#010lx %#010lx %#010lx %#010lx\n", 
		tmp[0], tmp[1], tmp[2], tmp[3]);
	tmp[0]=ULONG(ptr + 8 * 4);
	tmp[1]=ULONG(ptr + 9 * 4);
	tmp[2]=ULONG(ptr + 10* 4);
	tmp[3]=ULONG(ptr + 11* 4);
	fprintf(fp,"     %#010lx %#010lx %#010lx %#010lx\n", 
		tmp[0], tmp[1], tmp[2], tmp[3]);
	tmp[0]=ULONG(ptr + 12* 4);
	tmp[1]=ULONG(ptr + 13* 4);
	tmp[2]=ULONG(ptr + 14* 4);
	tmp[3]=ULONG(ptr + 15* 4);
	fprintf(fp,"     %#010lx %#010lx %#010lx %#010lx\n", 
		tmp[0], tmp[1], tmp[2], tmp[3]);

	fprintf(fp,"  -control registers:\n");
	ptr = lc + MEMBER_OFFSET("_lowcore","cregs_save_area");
	tmp[0]=ULONG(ptr);
	tmp[1]=ULONG(ptr + S390X_WORD_SIZE);
	tmp[2]=ULONG(ptr + 2 * S390X_WORD_SIZE);
	tmp[3]=ULONG(ptr + 3 * S390X_WORD_SIZE);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[0],tmp[1]);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[2],tmp[3]);
	tmp[0]=ULONG(ptr + 4 * S390X_WORD_SIZE);
	tmp[1]=ULONG(ptr + 5 * S390X_WORD_SIZE);
	tmp[2]=ULONG(ptr + 6 * S390X_WORD_SIZE);
	tmp[3]=ULONG(ptr + 7 * S390X_WORD_SIZE);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[0],tmp[1]);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[2],tmp[3]);
	tmp[0]=ULONG(ptr);
	tmp[1]=ULONG(ptr + S390X_WORD_SIZE);
	tmp[2]=ULONG(ptr + 2 * S390X_WORD_SIZE);
	tmp[3]=ULONG(ptr + 3 * S390X_WORD_SIZE);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[0],tmp[1]);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[2],tmp[3]);
	tmp[0]=ULONG(ptr + 4 * S390X_WORD_SIZE);
	tmp[1]=ULONG(ptr + 5 * S390X_WORD_SIZE);
	tmp[2]=ULONG(ptr + 6 * S390X_WORD_SIZE);
	tmp[3]=ULONG(ptr + 7 * S390X_WORD_SIZE);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[0],tmp[1]);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[2],tmp[3]);

	ptr = lc + MEMBER_OFFSET("_lowcore","floating_pt_save_area");
	fprintf(fp,"  -floating point registers 0,2,4,6:\n");
	tmp[0]=ULONG(ptr);
	tmp[1]=ULONG(ptr +  S390X_WORD_SIZE);
	tmp[2]=ULONG(ptr + 2 * S390X_WORD_SIZE);
	tmp[3]=ULONG(ptr + 3 * S390X_WORD_SIZE);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[0],tmp[1]);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[2],tmp[3]);
	tmp[0]=ULONG(ptr + 4 * S390X_WORD_SIZE);
	tmp[1]=ULONG(ptr + 5 * S390X_WORD_SIZE);
	tmp[2]=ULONG(ptr + 6 * S390X_WORD_SIZE);
	tmp[3]=ULONG(ptr + 7 * S390X_WORD_SIZE);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[0],tmp[1]);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[2],tmp[3]);
	tmp[0]=ULONG(ptr + 6 * S390X_WORD_SIZE);
	tmp[1]=ULONG(ptr + 7 * S390X_WORD_SIZE);
	tmp[2]=ULONG(ptr + 8 * S390X_WORD_SIZE);
	tmp[3]=ULONG(ptr + 9 * S390X_WORD_SIZE);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[0],tmp[1]);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[2],tmp[3]);
	tmp[0]=ULONG(ptr + 10* S390X_WORD_SIZE);
	tmp[1]=ULONG(ptr + 11* S390X_WORD_SIZE);
	tmp[2]=ULONG(ptr + 12* S390X_WORD_SIZE);
	tmp[3]=ULONG(ptr + 13* S390X_WORD_SIZE);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[0],tmp[1]);
	fprintf(fp,"     %#018lx %#018lx\n", tmp[2],tmp[3]);
}

/*
 *  Get a stack frame combination of pc and ra from the most relevent spot.
 */
static void
s390x_get_stack_frame(struct bt_info *bt, ulong *eip, ulong *esp)
{
	unsigned long ksp, r14;
	int r14_offset;
	char lowcore[LOWCORE_SIZE];

	if(s390x_has_cpu(bt->task))
		s390x_get_lowcore(s390x_cpu_of_task(bt->task),lowcore);

	/* get the stack pointer */
	if(esp){
		if(s390x_has_cpu(bt->task)){
			ksp = ULONG(lowcore + MEMBER_OFFSET("_lowcore",
				"gpregs_save_area") + (15 * S390X_WORD_SIZE));
		} else {
			readmem(bt->task + OFFSET(task_struct_thread_ksp), 
				KVADDR, &ksp, sizeof(void *),
				"thread_struct ksp", FAULT_ON_ERROR);
		}
		*esp = ksp;
	} else {
		/* for 'bt -S' */
		ksp=bt->hp->esp;
	}

	/* get the instruction address */
	if(!eip)
		return;

	if(s390x_has_cpu(bt->task) && esp){
		*eip = ULONG(lowcore + MEMBER_OFFSET("_lowcore",
		       "st_status_fixed_logout") + S390X_WORD_SIZE);
	} else {
		if(!STRUCT_EXISTS("stack_frame")){
			r14_offset = 112;
		} else {
			r14_offset = MEMBER_OFFSET("stack_frame","gprs") + 
						   8 * S390X_WORD_SIZE;
		}
		readmem(ksp + r14_offset,KVADDR,&r14,sizeof(void*),"eip",
			FAULT_ON_ERROR);
		*eip=r14; 
	}
}

/*
 *  cmd_irq() is not implemented for s390x.
 */
static void 
s390x_dump_irq(int irq)
{
	error(FATAL, "s390x_dump_irq: TBD\n");
}

/*
 *  Filter disassembly output if the output radix is not gdb's default 10
 */
static int 
s390x_dis_filter(ulong vaddr, char *inbuf)
{
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char *colon, *p1;
	int argc;
	char *argv[MAXARGS];
	ulong value;

	if (!inbuf) 
		return TRUE;
/*
 *  For some reason gdb can go off into the weeds translating text addresses,
 *  so this routine both fixes the references as well as imposing the current 
 *  output radix on the translations.
 */
	console("IN: %s", inbuf);

	colon = strstr(inbuf, ":");

	if (colon) {
		sprintf(buf1, "0x%lx <%s>", vaddr,
			value_to_symstr(vaddr, buf2, pc->output_radix));
		sprintf(buf2, "%s%s", buf1, colon);
		strcpy(inbuf, buf2);
	}

	strcpy(buf1, inbuf);
	argc = parse_line(buf1, argv);

	if ((FIRSTCHAR(argv[argc-1]) == '<') && 
	    (LASTCHAR(argv[argc-1]) == '>')) {
		p1 = rindex(inbuf, '<');
		while ((p1 > inbuf) && !STRNEQ(p1, " 0x")) 
			p1--;

		if (!STRNEQ(p1, " 0x"))
			return FALSE;
		p1++;

		if (!extract_hex(p1, &value, NULLCHAR, TRUE))
			return FALSE;

		sprintf(buf1, "0x%lx <%s>\n", value,
			value_to_symstr(value, buf2, pc->output_radix));

		sprintf(p1, buf1);
	}

	console("    %s", inbuf);

	return TRUE;
}

/*
 *   Override smp_num_cpus if possible and necessary.
 */
int
s390x_get_smp_cpus(void)
{
	unsigned long map = 0, addr;
	int i, cpu_num = 0;
	addr=symbol_value("cpu_online_map");
	readmem(addr, KVADDR, &map,sizeof(long), "cpu_online_map",FAULT_ON_ERROR);
	for(i = 0; i < sizeof(map)*8;i++){
		if(map & 0x1UL)
			cpu_num += 1;
		map >>= 1;
	}
	return cpu_num;
}

/*
 *  Machine dependent command.
 */
void
s390x_cmd_mach(void)
{
	int c;

	while ((c = getopt(argcnt, args, "cm")) != EOF) {
		switch(c)
		{
		case 'c':
			fprintf(fp,"'-c' option is not implemented on this architecture\n");
			return;
		case 'm':
			fprintf(fp,"'-m' option is not implemented on this architecture\n");
			return;
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	s390x_display_machine_stats();
}

/*
 *  "mach" command output.
 */
static void
s390x_display_machine_stats(void)
{
	struct new_utsname *uts;
	char buf[BUFSIZE];
	ulong mhz;

	uts = &kt->utsname;

	fprintf(fp, "       MACHINE TYPE: %s\n", uts->machine);
	fprintf(fp, "        MEMORY SIZE: %s\n", get_memory_size(buf));
	fprintf(fp, "               CPUS: %d\n", kt->cpus);
	fprintf(fp, "    PROCESSOR SPEED: ");
	if ((mhz = machdep->processor_speed()))
		fprintf(fp, "%ld Mhz\n", mhz);
	else
		fprintf(fp, "(unknown)\n");
	fprintf(fp, "                 HZ: %d\n", machdep->hz);
	fprintf(fp, "          PAGE SIZE: %d\n", PAGESIZE());
	// fprintf(fp, "      L1 CACHE SIZE: %d\n", l1_cache_size());
	fprintf(fp, "KERNEL VIRTUAL BASE: %lx\n", machdep->kvbase);
	fprintf(fp, "KERNEL VMALLOC BASE: %lx\n", vt->vmalloc_start);
	fprintf(fp, "  KERNEL STACK SIZE: %ld\n", STACKSIZE());

}

static const char *hook_files[] = {
	"arch/s390x/kernel/entry.S",
	"arch/s390x/kernel/head.S"
};

#define ENTRY_S      ((char **)&hook_files[0])
#define HEAD_S       ((char **)&hook_files[1])

static struct line_number_hook s390x_line_number_hooks[] = {
       {"startup",HEAD_S},
       {"_stext",HEAD_S},
       {"_pstart",HEAD_S},
       {"system_call",ENTRY_S},
       {"sysc_do_svc",ENTRY_S},
       {"sysc_do_restart",ENTRY_S},
       {"sysc_return",ENTRY_S},
       {"sysc_sigpending",ENTRY_S},
       {"sysc_restart",ENTRY_S},
       {"sysc_singlestep",ENTRY_S},
       {"sysc_tracesys",ENTRY_S},
       {"ret_from_fork",ENTRY_S},
       {"pgm_check_handler",ENTRY_S},
       {"io_int_handler",ENTRY_S},
       {"io_return",ENTRY_S},
       {"ext_int_handler",ENTRY_S},
       {"mcck_int_handler",ENTRY_S},
       {"mcck_return",ENTRY_S},
       {"restart_int_handler",ENTRY_S},
       {NULL, NULL}    /* list must be NULL-terminated */
};

static void
s390x_dump_line_number(ulong callpc)
{
	int retries;
	char buf[BUFSIZE], *p;

	retries = 0;
try_closest:
	get_line_number(callpc, buf, FALSE);

	if (strlen(buf)) {
		if (retries) {
			p = strstr(buf, ": ");
			if (p)
				*p = NULLCHAR;
		}
		fprintf(fp, "    %s\n", buf);
	} else {
		if (retries) {
			fprintf(fp, GDB_PATCHED() ?
			  "" : "    (cannot determine file and line number)\n");
		} else {
			retries++;
			callpc = closest_symbol_value(callpc);
			goto try_closest;
		}
	}
}

#endif 
