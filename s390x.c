/* s390x.c - core analysis suite
 *
 * Copyright (C) 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002, 2003, 2004 David Anderson
 * Copyright (C) 2002, 2003, 2004 Red Hat, Inc. All rights reserved.
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
 *
 * CVS: $Revision: 1.21 $ $Date: 2004/05/06 19:41:58 $
 */
#ifdef S390X 
#include "defs.h"

static int s390x_kvtop(struct task_context *, ulong, physaddr_t *, int);
static ulong s390x_lowcore(struct task_context *, ulong, int);
static int s390x_uvtop(struct task_context *, ulong, physaddr_t *, int);
static ulong s390x_vmalloc_start(void);
static int s390x_is_task_addr(ulong);
static int s390x_verify_symbol(const char *, ulong, char);
static ulong s390x_get_task_pgd(ulong);
static int s390x_translate_pte(ulong, void *, ulonglong);
static int s390x_is_kvaddr(ulong);
static int s390x_is_uvaddr(ulong, struct task_context *);
static ulong s390x_processor_speed(void);
static int s390x_eframe_search(struct bt_info *);
static void s390x_back_trace_cmd(struct bt_info *);
static void s390x_back_trace(struct gnu_request *, struct bt_info *);
static void get_s390x_frame(struct bt_info *, ulong *, ulong *);
static void s390x_print_stack_entry(int,struct gnu_request *,
	ulong, char *, struct bt_info *);
static void s390x_exception_frame(ulong,struct bt_info *, struct gnu_request *);
static void s390x_dump_irq(int);
static ulong s390x_get_pc(struct bt_info *);
static ulong s390x_get_sp(struct bt_info *);
static void s390x_get_stack_frame(struct bt_info *, ulong *, ulong *);
static int s390x_dis_filter(ulong, char *);
static void s390x_cmd_mach(void);
static int s390x_get_smp_cpus(void);
static void s390x_display_machine_stats(void);
static void s390x_dump_line_number(ulong);
static struct line_number_hook s390x_line_number_hooks[];
void s390x_compiler_warning_stub(void);

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
		machdep->stacksize = machdep->pagesize * 2;
                if ((machdep->pgd = (char *)malloc(REGION_TABLE_SIZE)) == NULL)
                        error(FATAL, "cannot malloc pgd space.");
                if ((machdep->pmd = (char *)malloc(SEGMENT_TABLE_SIZE)) == NULL)
                        error(FATAL, "cannot malloc pmd space.");
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
                machdep->is_kvaddr = s390x_is_kvaddr;
                machdep->is_uvaddr = s390x_is_uvaddr;
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
		machdep->hz = HZ;
		break;

	case POST_INIT:
		break;
	}
}

void
s390x_dump_machdep_table(ulong arg)
{
        int others; 
 
        others = 0;
        fprintf(fp, "              flags: %lx (", machdep->flags);
	if (machdep->flags & KSYMS_START)
		fprintf(fp, "%sKSYMS_START", others++ ? "|" : "");
	if (machdep->flags & SYSRQ)
		fprintf(fp, "%sSYSRQ", others++ ? "|" : "");
        fprintf(fp, ")\n");

	fprintf(fp, "             kvbase: %lx\n", machdep->kvbase);
	fprintf(fp, "  identity_map_base: %lx\n", machdep->identity_map_base);
        fprintf(fp, "           pagesize: %d\n", machdep->pagesize);
        fprintf(fp, "          pageshift: %d\n", machdep->pageshift);
        fprintf(fp, "           pagemask: %llx\n", machdep->pagemask);
        fprintf(fp, "         pageoffset: %lx\n", machdep->pageoffset);
	fprintf(fp, "          stacksize: %ld\n", machdep->stacksize);
        fprintf(fp, "                 hz: %d\n", machdep->hz);
        fprintf(fp, "                mhz: %ld\n", machdep->mhz);
        fprintf(fp, "            memsize: %lld (0x%llx)\n", 
		machdep->memsize, machdep->memsize);
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
        fprintf(fp, "          is_kvaddr: s390x_is_kvaddr()\n");
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
	fprintf(fp, "           machspec: %lx\n", (ulong)machdep->machspec);
}


/*
 *  Deal with non-traditional overlaying of kernel/user address spaces.
 */
static int s390x_is_kvaddr(ulong addr)
{
	return (error(FATAL, "s390x_is_kvaddr: TBD\n"));
}

static int s390x_is_uvaddr(ulong addr, struct task_context *tc)
{
	return (error(FATAL, "s390x_is_uvaddr: TBD\n"));
}


/*
 *  Translates a user virtual address to its physical address.  cmd_vtop()
 *  sets the verbose flag so that the pte translation gets displayed; all
 *  other callers quietly accept the translation.
 *
 *  This routine can also take mapped kernel virtual addresses if the -u flag
 *  was passed to cmd_vtop().  If so, it makes the translation using the
 *  kernel-memory PGD entry instead of swapper_pg_dir.
 */

static int
s390x_uvtop(struct task_context *tc, ulong vaddr, physaddr_t *paddr, int verbose)
{
	return (error(FATAL, "s390x_uvtop: TBD\n"));
}

/*
 *  Translates a kernel virtual address to its physical address.  cmd_vtop()
 *  sets the verbose flag so that the pte translation gets displayed; all
 *  other callers quietly accept the translation.
 *
 *  The S390X uses a three-level address translation scheme where the
 *  16K pgd consists of 2048 region-third-table entries.  Each of the pgd
 *  entries points to a 16K pmd consisting of 2048 segment-table entries.
 *  Each of the segment-table entries points to a 256-entry 2K page table. 
 *  each of which maps 1MB of data.  However, to conform to the Linux 
 *  page-size page table, each pmd entry is defined as: 
 *
 *    typedef struct {
 *          unsigned long pmd0;
 *          unsigned long pmd1;
 *    } pmd_t;
 *
 *  The 2048 regions map 2048 segments that map page tables with 256 entries;
 *  Linux defines 1024 pmd_t entries that reference 512-entry page tables.
 *  Each page table references 2MB since the page size is still 4K.
 */
static int
s390x_kvtop(struct task_context *tc, ulong kvaddr, physaddr_t *paddr, int verbose)
{
	ulong *pgd;
        ulong *page_dir;
        ulong pgd_index;
        ulong pgd_pte;
	ulong *pmd;
	ulong pmd_index;
        ulong pmd_pte;
        ulong pmd_entry;
        ulong *page_table;
        ulong pte_entry;
	ulong pte_index;
        ulong pte;

        if (!IS_KVADDR(kvaddr))
                return FALSE;
/*
 *      if (!vt->vmalloc_start) {
 *              *paddr = VTOP(kvaddr);
 *              return TRUE;
 *      }
 *
 *      if (!IS_VMALLOC_ADDR(kvaddr)) {
 *              *paddr = VTOP(kvaddr);
 *              if (!verbose)
 *                      return TRUE;
 *      }
 */

        pgd = (ulong *)vt->kernel_pgd[0];

        if (verbose)
                fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);

	pgd_index = (kvaddr >> PGDIR_SHIFT) & (PTRS_PER_PGD-1);
	page_dir = pgd + pgd_index;

	FILL_PGD(pgd, PHYSADDR, REGION_TABLE_SIZE);
	pgd_pte = ULONG(machdep->pgd + PAGEOFFSET(page_dir));

	if (verbose)
                fprintf(fp, "  PGD: %lx => %lx\n", (ulong)page_dir, pgd_pte);

	if (pgd_pte & _PGD_ENTRY_INV)
		goto no_kpage;

        /*
         *  The calculation of the pmd_index below uses the kernel manner of
         *  calculating the index of a 2-long pmd_t, which is then multiplied
         *  by 2 here to conform to our pgd being a single ulong pointer.
         */
	pmd = (ulong *)(pgd_pte & (ulong)SEGMENT_TABLE_ORIGIN);
	pmd_index = ((kvaddr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1);
	pmd_entry = (ulong)(pmd + (pmd_index*2));

	FILL_PMD(pmd, PHYSADDR, SEGMENT_TABLE_SIZE);
	pmd_pte = ULONG(machdep->pmd + PAGEOFFSET(pmd_entry));

	if (verbose)
                fprintf(fp, "  PMD: %lx => %lx\n", pmd_entry, pmd_pte);

        if (pmd_pte & _PMD_ENTRY_INV)
                goto no_kpage;

	page_table = (ulong *)(pmd_pte & (ulong)PAGE_TABLE_ORIGIN);
	pte_index = ((kvaddr) >> PAGESHIFT()) & (PTRS_PER_PTE - 1);
	pte_entry = (ulong)(page_table + pte_index); 

	FILL_PTBL(page_table, PHYSADDR, PAGESIZE());
	pte = ULONG(machdep->ptbl + PAGEOFFSET(pte_entry));

        if (verbose)
                fprintf(fp, "  PTE: %lx => %lx\n",
                        pte_entry, pte);

        if (!(pte & _PAGE_PRESENT)) {
                if (pte && verbose) {
                        fprintf(fp, "\n");
                        s390x_translate_pte(pte, 0, 0);
                }
                goto no_kpage;
        }

        if (verbose) {
                fprintf(fp, " PAGE: %lx\n\n", PAGEBASE(pte));
                s390x_translate_pte(pte, 0, 0);
        }

	if (IS_LOWCORE(kvaddr))
		*paddr = s390x_lowcore(tc, kvaddr, verbose);
	else
        	*paddr = PAGEBASE(pte) + PAGEOFFSET(kvaddr);

        return TRUE;

no_kpage:
        return FALSE;
}

/*
 *  Return the actual "prefix'd" physical location behind a lowcore reference.
 */
static ulong
s390x_lowcore(struct task_context *tc, ulong kvaddr, int verbose)
{
        void *lowcore_ptr[NR_CPUS];
        int cpu;

        if (kt->flags & SMP) {
                cpu = tc->processor == NO_PROC_ID ? 0 : tc->processor;

                readmem(symbol_value("lowcore_ptr"), KVADDR,
                        lowcore_ptr, sizeof(void *)*NR_CPUS,
                        "lowcore_ptr array", FAULT_ON_ERROR);

                if (verbose)
                        fprintf(fp, "CPU: %d  PREFIX PAGE: %lx\n\n",
                                cpu, (ulong)lowcore_ptr[cpu]);

                return(VTOP(lowcore_ptr[cpu]) + VTOP(kvaddr));
        }

        return (error(FATAL,
		"s390x_lowcore: search bootmem area for UP lowcore: TBD\n"));
}

/*
 *  Determine where vmalloc'd memory starts.
 */
static ulong
s390x_vmalloc_start(void)
{
	return (error(FATAL, "s390x_vmalloc_start: TBD\n"));
}

/*
 * 
 */
static int
s390x_is_task_addr(ulong task)
{
	return (error(FATAL, "s390x_is_task_addr: TBD\n"));
}


/*
 * 
 */
static ulong
s390x_processor_speed(void)
{
	return (error(FATAL, "s390x_processor_speed: TBD\n"));
}


/*
 *  Accept or reject a symbol from the kernel namelist.
 */
static int
s390x_verify_symbol(const char *name, ulong value, char type)
{
	return (error(FATAL, "s390x_verify_symbol: TBD\n"));
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
	return (error(FATAL, "s390x_translate_pte: TBD\n"));
}


/*
 *  Look for likely exception frames in a stack.
 */

static int 
s390x_eframe_search(struct bt_info *bt)
{
	return (error(FATAL, "s390x_eframe_search: TBD\n"));
}

/*
 *  Unroll a kernel stack.
 */
static void
s390x_back_trace_cmd(struct bt_info *bt)
{
	error(FATAL, "s390x_back_trace_cmd: TBD\n");
}

/*
 *  Unroll the kernel stack using a minimal amount of gdb services.
 */
static void
s390x_back_trace(struct gnu_request *req, struct bt_info *bt)
{
	error(FATAL, "s390x_back_trace: TBD\n");
}

/*
 *  print one entry of a stack trace
 */
static void 
s390x_print_stack_entry(int frame, 
		      struct gnu_request *req, 
		      ulong callpc, 	
		      char *name, 
		      struct bt_info *bt)
{
	error(FATAL, "s390x_print_stack_entry: TBD\n");
}

/*
 *  Print exception frame information for s390x
 */
static void
s390x_exception_frame(ulong addr, struct bt_info *bt, struct gnu_request *req)
{
	error(FATAL, "s390x_exception_frame: TBD\n");
}


/*
 *  Get a stack frame combination of pc and ra from the most relevent spot.
 */
static void
s390x_get_stack_frame(struct bt_info *bt, ulong *pcp, ulong *spp)
{
	error(FATAL, "s390x_get_stack_frame: TBD\n");
}


/*
 *  Get the saved ESP from a user-space copy of the kernel stack.
 */
static ulong
s390x_get_sp(struct bt_info *bt)
{
	return (error(FATAL, "s390x_get_sp: TBD\n"));
}

/*
 *  Get the saved PC from a user-space copy of the kernel stack.
 */
static ulong
s390x_get_pc(struct bt_info *bt)
{
	return (error(FATAL, "s390x_get_pc: TBD\n"));
}


/*
 *  Do the work for s390x_get_sp() and s390_get_pc().
 */
static void
get_s390x_frame(struct bt_info *bt, ulong *getpc, ulong *getsp)
{
	error(FATAL, "get_s390x_frame: TBD\n");
}

/*
 *  Do the work for cmd_irq().
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
 *  (on alpha -- not necessarily seen on s390x) so this routine both fixes the 
 *  references as well as imposing the current output radix on the translations.
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
s390x_get_smp_cpus()
{
	return (error(FATAL, "s390x_get_smp_cpus: TBD\n"));
}

/*
 *  Machine dependent command.
 */
void
s390x_cmd_mach(void)
{
        int c;

        while ((c = getopt(argcnt, args, "")) != EOF) {
                switch(c)
                {
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
	error(FATAL, "s390x_display_machine_stats: TBD\n");
}

static const char *hook_files[] = {
        "arch/s390x/kernel/entry.S",
        "arch/s390x/kernel/head.S",
        "arch/s390x/kernel/semaphore.c"
};

#define ENTRY_S      ((char **)&hook_files[0])
#define HEAD_S       ((char **)&hook_files[1])
#define SEMAPHORE_C  ((char **)&hook_files[2])

static struct line_number_hook s390x_line_number_hooks[] = {

       {NULL, NULL}    /* list must be NULL-terminated */
};

static void
s390x_dump_line_number(ulong callpc)
{
	error(FATAL, "s390x_dump_line_number: TBD\n");
}

void
s390x_compiler_warning_stub(void)
{
	struct line_number_hook *lhp;
	char **p;

	lhp = &s390x_line_number_hooks[0]; lhp++;
	p = ENTRY_S;
        s390x_back_trace(NULL, NULL);
        get_s390x_frame(NULL, NULL, NULL);
        s390x_print_stack_entry(0, NULL, 0, NULL, NULL);
        s390x_exception_frame(0, NULL, NULL);
        s390x_get_pc(NULL);
        s390x_get_sp(NULL);
        s390x_dump_line_number(0);
}
#endif 
