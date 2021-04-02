/* ia64.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
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
 * BitKeeper ID: @(#)ia64.c 1.17
 *
 * 09/28/00  Transition to CVS version control
 *
 * CVS: $Revision: 1.58 $ $Date: 2002/01/23 17:44:07 $
 */ 
#ifdef IA64 
#include "defs.h"

static int ia64_verify_symbol(const char *, ulong);
static void ia64_eframe_search(struct bt_info *);
static void ia64_back_trace_cmd(struct bt_info *);
static void ia64_old_unwind(struct bt_info *);
static void ia64_new_unwind(struct bt_info *);
static void ia64_dump_irq(int);
static ulong ia64_processor_speed(void);
static int ia64_uvtop(struct task_context *, ulong, ulong *, int);
static int ia64_kvtop(struct task_context *, ulong, ulong *, int);
static ulong ia64_get_task_pgd(ulong);
static int ia64_nr_irqs(void);
static ulong ia64_get_pc(struct bt_info *);
static ulong ia64_get_sp(struct bt_info *);
static void ia64_get_stack_frame(struct bt_info *, ulong *, ulong *);
static int ia64_translate_pte(ulong, ulong *);
static ulong ia64_vmalloc_start(void);
static ulong ia64_SWP_TYPE(ulong);
static ulong ia64_SWP_OFFSET(ulong);
static int ia64_is_task_addr(ulong);
static int ia64_dis_filter(ulong, char *);
static void ia64_exception_frame(ulong, ulong);
static void ia64_dump_switch_stack(ulong, ulong);
static void ia64_cmd_mach(void);
static int ia64_get_smp_cpus(void);
static void ia64_display_machine_stats(void);
static void ia64_display_cpu_data(void);
static void ia64_post_init(void);
static ulong ia64_get_thread_ksp(ulong);
static void ia64_dump_line_number(ulong);

struct unw_frame_info;
static void dump_unw_frame_info(struct unw_frame_info *);
static int old_unw_unwind(struct unw_frame_info *);
static void unw_init_from_blocked_task(struct unw_frame_info *, ulong);
static ulong ia64_rse_slot_num(ulong *);
static ulong *ia64_rse_skip_regs(ulong *, long);
static ulong *ia64_rse_rnat_addr(ulong *);
static ulong rse_read_reg(struct unw_frame_info *, int, int *);
static void rse_function_params(struct unw_frame_info *, char *);

struct machine_specific {
	ulong unimpl_va_mask;
	ulong unimpl_pa_mask;
} ia64_machine_specific = { 0 };

void
ia64_init(int when)
{
        switch (when)
        {
        case PRE_SYMTAB:
                machdep->verify_symbol = ia64_verify_symbol;
		if (pc->flags & KERNEL_DEBUG_QUERY)
			return;
                machdep->pagesize = memory_page_size();
                machdep->pageshift = ffs(machdep->pagesize) - 1;
                machdep->pageoffset = machdep->pagesize - 1;
                machdep->pagemask = ~(machdep->pageoffset);
		switch (machdep->pagesize)
		{
		case 4096:
			machdep->stacksize = (power(2, 3) * PAGESIZE());
			break;
		case 8192:
			machdep->stacksize = (power(2, 2) * PAGESIZE());
			break;
		case 16384:
			machdep->stacksize = (power(2, 1) * PAGESIZE());
			break;
		default:
			machdep->stacksize = 32*1024;
			break;
		}
                if ((machdep->pgd = (char *)malloc(PAGESIZE())) == NULL)
                        error(FATAL, "cannot malloc pgd space.");
                if ((machdep->pmd = (char *)malloc(PAGESIZE())) == NULL)
                        error(FATAL, "cannot malloc pmd space.");
                if ((machdep->ptbl = (char *)malloc(PAGESIZE())) == NULL)
                        error(FATAL, "cannot malloc ptbl space.");
                machdep->last_pgd_read = 0;
                machdep->last_pmd_read = 0;
                machdep->last_ptbl_read = 0;
                break;     

        case PRE_GDB:
		{
		/*
		 * Until the kernel core dump and va_server library code
		 * do the right thing with respect to the configured page size,
		 * try to recognize a fatal inequity between the compiled-in 
		 * page size and the page size used by the kernel.
		 */ 
		struct syment *sp, *spn;

		if ((sp = symbol_search("empty_zero_page")) &&
		    (spn = next_symbol(NULL, sp)) && 
		    ((spn->value - sp->value) != PAGESIZE())) 
			error(FATAL, 
	        "compiled-in page size: %d  (apparent) kernel page size: %ld\n",
				PAGESIZE(), spn->value - sp->value);
		}

                machdep->kvbase = KERNEL_VMALLOC_BASE;
		machdep->identity_map_base = KERNEL_CACHED_BASE;
                machdep->is_kvaddr = generic_is_kvaddr;
                machdep->is_uvaddr = generic_is_uvaddr;
                machdep->eframe_search = ia64_eframe_search;
                machdep->back_trace = ia64_back_trace_cmd;
                machdep->processor_speed = ia64_processor_speed;
                machdep->uvtop = ia64_uvtop;
                machdep->kvtop = ia64_kvtop;
                machdep->get_task_pgd = ia64_get_task_pgd;
                machdep->dump_irq = ia64_dump_irq;
                machdep->nr_irqs = ia64_nr_irqs;
		machdep->get_stack_frame = ia64_get_stack_frame;
		machdep->get_stackbase = generic_get_stackbase;
		machdep->get_stacktop = generic_get_stacktop;
                machdep->translate_pte = ia64_translate_pte;
                machdep->memory_size = generic_memory_size;
                machdep->vmalloc_start = ia64_vmalloc_start;
                machdep->SWP_TYPE = ia64_SWP_TYPE;
                machdep->SWP_OFFSET = ia64_SWP_OFFSET;
                machdep->is_task_addr = ia64_is_task_addr;
                machdep->dis_filter = ia64_dis_filter;
		machdep->cmd_mach = ia64_cmd_mach;
		machdep->machspec = &ia64_machine_specific;
		machdep->get_smp_cpus = ia64_get_smp_cpus;
                break;

        case POST_GDB:
                SIZE(pt_regs) = STRUCT_SIZE("pt_regs");
                SIZE(softirq_state) = STRUCT_SIZE("softirq_state");
                SIZE(desc_struct) = STRUCT_SIZE("desc_struct");
		SIZE(cpuinfo_ia64) = STRUCT_SIZE("cpuinfo_ia64");
		OFFSET(switch_stack_b0) = MEMBER_OFFSET("switch_stack", "b0");
		OFFSET(switch_stack_ar_bspstore) = 
			MEMBER_OFFSET("switch_stack", "ar_bspstore");
		OFFSET(switch_stack_ar_pfs) = 
			MEMBER_OFFSET("switch_stack", "ar_pfs");
		OFFSET(switch_stack_ar_rnat) = 
			MEMBER_OFFSET("switch_stack", "ar_rnat");
		machdep->hz = 1024;
                break;

	case POST_INIT:
		ia64_post_init();
		break;
	}
}

void
ia64_dump_machdep_table(void)
{
        int others;

        others = 0;
        fprintf(fp, "              flags: %lx (", machdep->flags);
        /* future flags tests here */
	if (machdep->flags & NEW_UNWIND)
		fprintf(fp, "%sNEW_UNWIND", others++ ? "|" : "");
	if (machdep->flags & OLD_UNWIND)
		fprintf(fp, "%sOLD_UNWIND", others++ ? "|" : "");
	if (machdep->flags & UNW_FI_INSYNC)
		fprintf(fp, "%sUNW_FI_INSYNC", others++ ? "|" : "");
	if (machdep->flags & UNW_FI_UNKNOWN)
		fprintf(fp, "%sUNW_FI_UNKNOWN", others++ ? "|" : "");
	if (machdep->flags & SYSRQ)
		fprintf(fp, "%sSYSRQ", others++ ? "|" : "");
        fprintf(fp, ")\n");
        fprintf(fp, "             kvbase: %lx\n", machdep->kvbase);
	fprintf(fp, "  identity_map_base: %lx\n", machdep->identity_map_base);
        fprintf(fp, "           pagesize: %d\n", machdep->pagesize);
        fprintf(fp, "          pageshift: %d\n", machdep->pageshift);
        fprintf(fp, "           pagemask: %lx\n", machdep->pagemask);
        fprintf(fp, "         pageoffset: %lx\n", machdep->pageoffset);
        fprintf(fp, "          stacksize: %ld\n", machdep->stacksize);
        fprintf(fp, "                 hz: %d\n", machdep->hz);
        fprintf(fp, "                mhz: %d\n", machdep->hz);
        fprintf(fp, "            memsize: %ld (0x%lx)\n", 
		machdep->memsize, machdep->memsize);
	fprintf(fp, "               bits: %d\n", machdep->bits);
        fprintf(fp, "      eframe_search: ia64_eframe_search()\n");
        fprintf(fp, "         back_trace: ia64_back_trace_cmd()\n");
        fprintf(fp, "get_processor_speed: ia64_processor_speed()\n");
        fprintf(fp, "              uvtop: ia64_uvtop()\n");
        fprintf(fp, "              kvtop: ia64_kvtop()\n");
        fprintf(fp, "       get_task_pgd: ia64_get_task_pgd()\n");
        fprintf(fp, "           dump_irq: ia64_dump_irq()\n");
        fprintf(fp, "            nr_irqs: ia64_nr_irqs()\n");
	fprintf(fp, "    get_stack_frame: ia64_get_stack_frame()\n");
	fprintf(fp, "      get_stackbase: generic_get_stackbase()\n");
	fprintf(fp, "       get_stacktop: generic_get_stacktop()\n");
        fprintf(fp, "      translate_pte: ia64_translate_pte()\n");
        fprintf(fp, "        memory_size: generic_memory_size()\n");
        fprintf(fp, "      vmalloc_start: ia64_vmalloc_start()\n");
        fprintf(fp, "           SWP_TYPE: ia64_SWP_TYPE()\n");
        fprintf(fp, "         SWP_OFFSET: ia64_SWP_OFFSET\n");
        fprintf(fp, "       is_task_addr: ia64_is_task_addr()\n");
        fprintf(fp, "      verify_symbol: ia64_verify_symbol()\n");
        fprintf(fp, "         dis_filter: ia64_dis_filter()\n");
        fprintf(fp, "           cmd_mach: ia64_cmd_mach()\n");
        fprintf(fp, "       get_smp_cpus: ia64_get_smp_cpus()\n");
        fprintf(fp, "          is_kvaddr: generic_is_kvaddr()\n");
        fprintf(fp, "          is_uvaddr: generic_is_uvaddr()\n");
        fprintf(fp, "      last_pgd_read: %lx\n", machdep->last_pgd_read);
        fprintf(fp, "      last_pmd_read: %lx\n", machdep->last_pmd_read);
        fprintf(fp, "     last_ptbl_read: %lx\n", machdep->last_ptbl_read);
        fprintf(fp, "                pgd: %lx\n", (ulong)machdep->pgd);
        fprintf(fp, "                pmd: %lx\n", (ulong)machdep->pmd);
        fprintf(fp, "               ptbl: %lx\n", (ulong)machdep->ptbl);
        fprintf(fp, "           machspec: ia64_machine_specific\n");
	fprintf(fp, "                     unimpl_va_mask: %lx\n", 
		machdep->machspec->unimpl_va_mask);
	fprintf(fp, "                     unimpl_pa_mask: %lx\n",
		machdep->machspec->unimpl_pa_mask);
}

/*
 *  Keep or reject a symbol from the namelist.
 */
static int
ia64_verify_symbol(const char *name, ulong value)
{
        if (MCLXDEBUG(8) && name && strlen(name))
                fprintf(fp, "%016lx %s\n", value, name);

	return (name && strlen(name) && (value >= MIN_SYMBOL_VALUE));
}


/*
 *   Look for likely exception frames in a stack.
 */
static void
ia64_eframe_search(struct bt_info *bt)
{
	error(FATAL, "ia64_eframe_search: TBD\n");
}


/*
 *  Unroll a kernel stack.
 */

#define BT_SWITCH_STACK BT_SYMBOLIC_ARGS

static void
ia64_back_trace_cmd(struct bt_info *bt)
{
	if (bt->flags & BT_SWITCH_STACK)
        	ia64_dump_switch_stack(bt->task, 0);

	switch (machdep->flags & (OLD_UNWIND|NEW_UNWIND))
	{
	case OLD_UNWIND:
		ia64_old_unwind(bt);
		break;

	case NEW_UNWIND:
		ia64_new_unwind(bt);
		break;
	}

	if (BT_REFERENCE_CHECK(bt))
		return;

        if (!is_kernel_thread(bt->task))
                ia64_exception_frame(bt->stacktop - SIZE(pt_regs), 0);
}


/*
 *  Dump the IRQ table.
 */
static void
ia64_dump_irq(int irq)
{
        if (symbol_exists("irq_desc")) {
                machdep->dump_irq = generic_dump_irq;
                return(generic_dump_irq(irq));
        }

	error(FATAL, "ia64_dump_irq: irq_desc does not exist?\n");
}


/*      
 *  Calculate and return the speed of the processor. 
 */
static ulong 
ia64_processor_speed(void)
{
	ulong mhz, proc_freq;
	int bootstrap_processor;

	if (machdep->mhz)
		return(machdep->mhz);

	mhz = 0;
	bootstrap_processor = 0;

	if (!symbol_exists("cpu_data") ||
	    !STRUCT_EXISTS("cpuinfo_ia64") ||
	    !MEMBER_EXISTS("cpuinfo_ia64", "proc_freq"))
		return (machdep->mhz = mhz);

	if (symbol_exists("bootstrap_processor"))
		get_symbol_data("bootstrap_processor", sizeof(int), 
			&bootstrap_processor);
	if (bootstrap_processor == -1)
		bootstrap_processor = 0;

        readmem(symbol_value("cpu_data") + 
		MEMBER_OFFSET("cpuinfo_ia64", "proc_freq"),
        	KVADDR, &proc_freq, sizeof(ulong),
                "cpuinfo_ia64 proc_freq", FAULT_ON_ERROR);

	mhz = proc_freq/1000000;

	return (machdep->mhz = mhz);
}


/*
 *  Translates a user virtual address to its physical address.  cmd_vtop()
 *  sets the verbose flag so that the pte translation gets displayed; all
 *  other callers quietly accept the translation.
 *
 *  This routine can also take mapped kernel virtual addresses if the -u flag
 *  was passed to cmd_vtop().  If so, it makes the translation using the
 *  swapper_pg_dir, making it irrelevant in this processor's case.
 */
static int
ia64_uvtop(struct task_context *tc, ulong uvaddr, ulong *paddr, int verbose)
{
	ulong mm;
	ulong *pgd;
	ulong *page_dir;
	ulong *page_middle;
	ulong *page_table;
	ulong pgd_pte;
	ulong pmd_pte;
	ulong pte;
	ulong region, offset;

	if (!tc)
		error(FATAL, "current context invalid\n");

	*paddr = 0;
       	region = VADDR_REGION(uvaddr);

	if (IS_KVADDR(uvaddr))
		return ia64_kvtop(tc, uvaddr, paddr, verbose);

	if ((mm = task_mm(tc->task, TRUE)))
        	pgd = ULONG_PTR(tt->mm_struct + OFFSET(mm_struct_pgd));
	else
		readmem(tc->mm_struct + OFFSET(mm_struct_pgd), KVADDR, &pgd,
			sizeof(long), "mm_struct pgd", FAULT_ON_ERROR);

	if (verbose) 
		fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);

        offset = (uvaddr >> PGDIR_SHIFT) & ((PTRS_PER_PGD >> 3) - 1);
        offset |= (region << (PAGESHIFT() - 6));
        page_dir = pgd + offset;

	FILL_PGD(PAGEBASE(pgd), KVADDR, PAGESIZE());
	pgd_pte = ULONG(machdep->pgd + PAGEOFFSET(page_dir));
	
        if (verbose) {
                fprintf(fp, "   PGD: %lx => %lx\n", (ulong)page_dir, pgd_pte);
        }

        if (!(pgd_pte))
                goto no_upage;

	offset = (uvaddr >> PMD_SHIFT) & (PTRS_PER_PMD - 1);
	page_middle = (ulong *)(PTOV(pgd_pte & _PFN_MASK)) + offset; 

	FILL_PMD(PAGEBASE(page_middle), KVADDR, PAGESIZE());
	pmd_pte = ULONG(machdep->pmd + PAGEOFFSET(page_middle));

        if (verbose)
                fprintf(fp, "   PMD: %lx => %lx\n", (ulong)page_middle,pmd_pte);

        if (!(pmd_pte))
                goto no_upage;

        offset = (uvaddr >> PAGESHIFT()) & (PTRS_PER_PTE - 1);
        page_table = (ulong *)(PTOV(pmd_pte & _PFN_MASK)) + offset;

	FILL_PTBL(PAGEBASE(page_table), KVADDR, PAGESIZE());
	pte = ULONG(machdep->ptbl + PAGEOFFSET(page_table));

        if (verbose)
                fprintf(fp, "   PTE: %lx => %lx\n", (ulong)page_table, pte);

        if (!(pte & (_PAGE_P))) {
		*paddr = pte;
		if (pte && verbose) {
			fprintf(fp, "\n");
			ia64_translate_pte(pte, 0);
		}
                goto no_upage;
        }

        *paddr = (pte & _PFN_MASK) + PAGEOFFSET(uvaddr);

        if (verbose) {
                fprintf(fp, "  PAGE: %lx\n\n", PAGEBASE(*paddr));
		ia64_translate_pte(pte, 0);
	}

	return TRUE;

no_upage:

	return FALSE;
}


/*
 *  Translates a kernel virtual address to its physical address.  cmd_vtop()
 *  sets the verbose flag so that the pte translation gets displayed; all
 *  other callers quietly accept the translation.
 */
static int
ia64_kvtop(struct task_context *tc, ulong kvaddr, ulong *paddr, int verbose)
{
        ulong *pgd;
        ulong *page_dir;
        ulong *page_middle;
        ulong *page_table;
        ulong pgd_pte;
        ulong pmd_pte;
        ulong pte;
	ulong offset;

        if (!IS_KVADDR(kvaddr))
                return FALSE;

        if (!vt->vmalloc_start) {
                *paddr = VTOP(kvaddr);
                return TRUE;
        }

	switch (VADDR_REGION(kvaddr))
	{
	case KERNEL_UNCACHED_REGION:
		*paddr = kvaddr - KERNEL_UNCACHED_BASE;
		if (verbose)
			fprintf(fp, "[UNCACHED MEMORY]\n");
                return TRUE;

	case KERNEL_CACHED_REGION:
                *paddr = VTOP(kvaddr);
		if (verbose)
			fprintf(fp, "[MAPPED IN TRANSLATION REGISTER]\n");
                return TRUE;

	case KERNEL_VMALLOC_REGION:
		break;
        }

        pgd = (ulong *)vt->kernel_pgd;

        if (verbose) {
                fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);
	}

	page_dir = pgd + ((kvaddr >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1)); 

        FILL_PGD(PAGEBASE(pgd), KVADDR, PAGESIZE());
        pgd_pte = ULONG(machdep->pgd + PAGEOFFSET(page_dir));

        if (verbose) {
                fprintf(fp, "   PGD: %lx => %lx\n", (ulong)page_dir, pgd_pte);
	}

        if (!(pgd_pte))
                goto no_kpage;

	offset = (kvaddr >> PMD_SHIFT) & (PTRS_PER_PMD - 1);
	page_middle = (ulong *)(PTOV(pgd_pte & _PFN_MASK)) + offset; 

        FILL_PMD(PAGEBASE(page_middle), KVADDR, PAGESIZE());
        pmd_pte = ULONG(machdep->pmd + PAGEOFFSET(page_middle));

        if (verbose)
                fprintf(fp, "   PMD: %lx => %lx\n", (ulong)page_middle, 
			pmd_pte);

        if (!(pmd_pte))
                goto no_kpage;

        offset = (kvaddr >> PAGESHIFT()) & (PTRS_PER_PTE - 1);
        page_table = (ulong *)(PTOV(pmd_pte & _PFN_MASK)) + offset;

        FILL_PTBL(PAGEBASE(page_table), KVADDR, PAGESIZE());
        pte = ULONG(machdep->ptbl + PAGEOFFSET(page_table));

        if (verbose)
                fprintf(fp, "   PTE: %lx => %lx\n", (ulong)page_table, pte);

        if (!(pte & (_PAGE_P))) {
		if (pte && verbose) {
			fprintf(fp, "\n");
			ia64_translate_pte(pte, 0);
		}
                goto no_kpage;
        }

        *paddr = (pte & _PFN_MASK) + PAGEOFFSET(kvaddr);

        if (verbose) {
                fprintf(fp, "  PAGE: %lx\n\n", PAGEBASE(*paddr));
		ia64_translate_pte(pte, 0);
	}

	return TRUE;

no_kpage:

	return FALSE;
}



/*
 *  Get the relevant page directory pointer from a task structure.
 */
static ulong
ia64_get_task_pgd(ulong task)
{
	return (error(FATAL, "ia64_get_task_pgd: N/A\n"));
}


/*
 *  Get the number of IRQs.
 */
static int
ia64_nr_irqs(void)
{
	int nr_irqs;

	if (symbol_exists("irq_desc")) 
                nr_irqs = get_array_length("irq_desc", NULL);
	else
        	error(FATAL, "cannot determine number of IRQs\n");

       	return nr_irqs;
}

static void
ia64_get_stack_frame(struct bt_info *bt, ulong *pcp, ulong *spp)
{
        if (pcp)
                *pcp = ia64_get_pc(bt);
        if (spp)
                *spp = ia64_get_sp(bt);
}


/*
 *  Get the saved PC from a user-space copy of the kernel stack.
 *
 *  TBD: For now -- just read it from the kernel switch_stack b0.
 */
static ulong
ia64_get_pc(struct bt_info *bt)
{
        ulong b0;

        readmem(SWITCH_STACK_ADDR(bt->task) + OFFSET(switch_stack_b0), KVADDR,
                &b0, sizeof(void *), "switch_stack b0", FAULT_ON_ERROR);

        return b0;
}


/*
 *  Get the saved SP from a user-space copy of the kernel stack if it
 *  cannot be found in the panic_ksp array.
 *
 *  TBD: For now -- just return the kernel switch_stack ar_bspstore. 
 */
static ulong
ia64_get_sp(struct bt_info *bt)
{
	ulong bspstore;

        readmem(SWITCH_STACK_ADDR(bt->task) + OFFSET(switch_stack_ar_bspstore), 
		KVADDR, &bspstore, sizeof(void *), "switch_stack ar_bspstore", 
		FAULT_ON_ERROR);

        return bspstore;
}

/*
 *  Get the ksp out of the task's thread_struct
 */
static ulong
ia64_get_thread_ksp(ulong task)
{
        ulong ksp;

        readmem(task + OFFSET(task_struct_thread_ksp), KVADDR,
                &ksp, sizeof(void *),
                "thread_struct ksp", FAULT_ON_ERROR);

        return ksp;
}

/*
 *  Translate a PTE, returning TRUE if the page is _PAGE_P.
 *  If a physaddr pointer is passed in, don't print anything.
 */
static int
ia64_translate_pte(ulong pte, ulong *physaddr)
{
	int c, len1, len2, len3, others, page_present;
	char buf[BUFSIZE];
        char buf2[BUFSIZE];
        char buf3[BUFSIZE];
	char ptebuf[BUFSIZE];
	char physbuf[BUFSIZE];
        char *arglist[MAXARGS];
	char *ptr;
	ulong paddr;

        paddr = pte & _PFN_MASK;
	page_present = pte & _PAGE_P;

	if (physaddr) {
		*physaddr = paddr;
		return page_present;
	}

	sprintf(ptebuf, "%lx", pte);
	len1 = MAX(strlen(ptebuf), strlen("PTE"));
	fprintf(fp, "%s  ", mkstring(buf, len1, CENTER|LJUST, "PTE"));

        if (!page_present && pte) {
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

                return page_present;
        }

	sprintf(physbuf, "%lx", paddr);
	len2 = MAX(strlen(physbuf), strlen("PHYSICAL"));
	fprintf(fp, "%s  ", mkstring(buf, len2, CENTER|LJUST, "PHYSICAL"));

	fprintf(fp, "FLAGS\n");

	fprintf(fp, "%s  %s  ",  
		mkstring(ptebuf, len1, CENTER|RJUST, NULL),
		mkstring(physbuf, len2, CENTER|RJUST, NULL)); 
	fprintf(fp, "(");
	others = 0;

	if (pte) {
		if (pte & _PAGE_P)
			fprintf(fp, "%sP", others++ ? "|" : "");
		switch (pte & _PAGE_MA_MASK)
		{
		case _PAGE_MA_WB:
			ptr = "MA_WB"; 
			break;
		case _PAGE_MA_UC:
			ptr = "MA_UC"; 
			break;
		case _PAGE_MA_UCE:
			ptr = "MA_UCE"; 
			break;
		case _PAGE_MA_WC:
			ptr = "MA_WC"; 
			break;
		case _PAGE_MA_NAT:
			ptr = "MA_NAT"; 
			break;
		case (0x1 << 2):
			ptr = "MA_UC"; 
			break;
		default:
			ptr = "MA_RSV";
			break;
		}
		fprintf(fp, "%s%s", others++ ? "|" : "", ptr);
		switch (pte & _PAGE_PL_MASK)
		{
		case _PAGE_PL_0:
			ptr = "PL_0";
			break;
		case _PAGE_PL_1:
			ptr = "PL_1";
			break;
		case _PAGE_PL_2:
			ptr = "PL_2";
			break;
		case _PAGE_PL_3:
			ptr = "PL_3";
			break;
		}
		fprintf(fp, "%s%s", others++ ? "|" : "", ptr);
		switch (pte & _PAGE_AR_MASK)
		{
		case _PAGE_AR_R:
			ptr = "AR_R";
			break;
		case _PAGE_AR_RX:
			ptr = "AT_RX";
			break;
		case _PAGE_AR_RW:
			ptr = "AR_RW";
			break;
		case _PAGE_AR_RWX:
			ptr = "AR_RWX";
			break;
		case _PAGE_AR_R_RW:
			ptr = "AR_R_RW";
			break;
		case _PAGE_AR_RX_RWX:
			ptr = "AR_RX_RWX";
			break;
		case _PAGE_AR_RWX_RW:
			ptr = "AR_RWX_RW";
			break;
		case _PAGE_AR_X_RX:
			ptr = "AR_X_RX";
			break;
		}
		fprintf(fp, "%s%s", others++ ? "|" : "", ptr);
		if (pte & _PAGE_A)
			fprintf(fp, "%sA", others++ ? "|" : "");
		if (pte & _PAGE_D)
			fprintf(fp, "%sD", others++ ? "|" : "");
		if (pte & _PAGE_ED)
			fprintf(fp, "%sED", others++ ? "|" : "");
		if (pte & _PAGE_PROTNONE)
			fprintf(fp, "%sPROTNONE", others++ ? "|" : "");
	} else {
		fprintf(fp, "no mapping");
	}

	fprintf(fp, ")\n");

	return page_present;
}


/*
 *  Determine where vmalloc'd memory starts.
 */
static ulong
ia64_vmalloc_start(void)
{
	return KERNEL_VMALLOC_BASE;
}


/*
 *  Break out the swap type and offset from a pte.
 */

#define SWP_TYPE(entry)    (((entry) >> 1) & 0xff)
#define SWP_OFFSET(entry)  ((entry) >> 9)

static ulong
ia64_SWP_TYPE(ulong pte)
{
	return SWP_TYPE(pte); 
}

static ulong
ia64_SWP_OFFSET(ulong pte)
{
	return SWP_OFFSET(pte); 
}


/*
 *  Verify that an address is a task_struct address.
 */
static int
ia64_is_task_addr(ulong task)
{
        int i;

        if (IS_KVADDR(task) && (ALIGNED_STACK_OFFSET(task) == 0))
                return TRUE;

        for (i = 0; i < kt->cpus; i++)
                if (task == tt->idle_threads[i])
                        return TRUE;

        return FALSE;
}


/*
 *  Filter disassembly output if the output radix is not gdb's default 10
 */
static int
ia64_dis_filter(ulong vaddr, char *inbuf)
{
        char buf1[BUFSIZE];
        char buf2[BUFSIZE];
        char *colon, *p1;
        int argc;
	int revise, stop_bit;
        char *argv[MAXARGS];
        ulong value;

        if (!inbuf)
                return TRUE;

/*
 *  For some reason gdb can go off into the weeds translating text addresses,
 *  (on alpha -- not necessarily seen on ia64) so this routine both fixes the
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

	revise = stop_bit = 0;
	if ((FIRSTCHAR(argv[argc-1]) == '<') &&
            (LASTCHAR(argv[argc-1]) == '>')) {
		revise = TRUE;
		stop_bit = FALSE;
	} else if ((FIRSTCHAR(argv[argc-1]) == '<') &&
            strstr(argv[argc-1], ">;;")) {
		revise = TRUE;
		stop_bit = TRUE;
	}

        if (revise) {
                p1 = rindex(inbuf, '<');
                while ((p1 > inbuf) && !STRNEQ(p1, " 0x"))
                        p1--;

                if (!STRNEQ(p1, " 0x"))
                        return FALSE;
                p1++;

                if (!extract_hex(p1, &value, NULLCHAR, TRUE))
                        return FALSE;

                sprintf(buf1, "0x%lx <%s>%s\n", value,
                        value_to_symstr(value, buf2, pc->output_radix),
			stop_bit ? ";;" : "");

                sprintf(p1, "%s", buf1);
        }

        console("    %s", inbuf);


	return TRUE;
}

/*
 *  Format the pt_regs structure.
 */
enum pt_reg_names { 
		P_cr_ipsr, P_cr_iip, P_cr_ifs, 
		P_ar_unat, P_ar_pfs, P_ar_rsc, P_ar_rnat, P_ar_bspstore, 
		P_ar_ccv, P_ar_fpsr,
		P_pr, P_loadrs, 
		P_b0, P_b6, P_b7,
		P_r1, P_r2, P_r3, P_r8, P_r9, P_r10, P_r11, P_r12, P_r13,
	        P_r14, P_r15, P_r16, P_r17, P_r18, P_r19, P_r20, P_r21,
		P_r22, P_r23, P_r24, P_r25, P_r26, P_r27, P_r28, P_r29,
		P_r30, P_r31,
		P_f6_lo, P_f6_hi,
		P_f7_lo, P_f7_hi,
		P_f8_lo, P_f8_hi,
		P_f9_lo, P_f9_hi, NUM_PT_REGS};
 
static void
ia64_exception_frame(ulong addr, ulong flag)
{
	char buf[BUFSIZE], *p;
	int fval;
	ulong value1, value2;
	ulong eframe[NUM_PT_REGS];

        BZERO(&eframe, sizeof(ulong) * NUM_PT_REGS);

        open_tmpfile();
        dump_struct("pt_regs", addr, RADIX(16));
        rewind(pc->tmpfile);

	fval = 0;
        while (fgets(buf, BUFSIZE, pc->tmpfile)) {

		if (strstr(buf, "f6 = ")) {
			fval = 6;
			continue;
		}
		if (strstr(buf, "f7 = ")) {
			fval = 7;
			continue;
		}
		if (strstr(buf, "f8 = ")) {
			fval = 8;
			continue;
		}
		if (strstr(buf, "f9 = ")) {
			fval = 9;
			continue;
		}

                if (!strstr(buf, "0x"))
                        continue;

		if (fval) {
			p = strstr(buf, "0x");
			extract_hex(p, &value1, ',', TRUE);
			p = strstr(buf, ",");
			extract_hex(p, &value2, '}', FALSE);  
			switch (fval)
			{
			case 6:
				eframe[P_f6_lo] = value1;
				eframe[P_f6_hi] = value2;
				break;
			case 7:
				eframe[P_f7_lo] = value1;
				eframe[P_f7_hi] = value2;
				break;
			case 8:
				eframe[P_f8_lo] = value1;
				eframe[P_f8_hi] = value2;
				break;
			case 9:
				eframe[P_f9_lo] = value1;
				eframe[P_f9_hi] = value2;
				break;
			}
			fval = 0;
			continue;
		}
		
		strip_comma(clean_line(buf));
		p = strstr(buf, " = ");
		extract_hex(p, &value1, NULLCHAR, FALSE);

		if (strstr(buf, "cr_ipsr = ")) {
			eframe[P_cr_ipsr] = value1;
		}

		if (strstr(buf, "cr_iip = ")) {
			eframe[P_cr_iip] = value1;
		}

		if (strstr(buf, "cr_ifs = ")) {
			eframe[P_cr_ifs] = value1;
		}

		if (strstr(buf, "ar_unat = ")) {
			eframe[P_ar_unat] = value1;
		}

		if (strstr(buf, "ar_pfs = ")) {
			eframe[P_ar_pfs] = value1;
		}

		if (strstr(buf, "ar_rsc = ")) {
			eframe[P_ar_rsc] = value1;
		}

		if (strstr(buf, "ar_rnat = ")) {
			eframe[P_ar_rnat] = value1;
		}

		if (strstr(buf, "ar_bspstore = ")) {
			eframe[P_ar_bspstore] = value1;
		}

		if (strstr(buf, "ar_ccv = ")) {
			eframe[P_ar_ccv] = value1;
		}

                if (strstr(buf, "ar_fpsr = ")) {
                        eframe[P_ar_fpsr] = value1;
                }

                if (strstr(buf, "pr = ")) {
                        eframe[P_pr] = value1;
                }

                if (strstr(buf, "loadrs = ")) {
                        eframe[P_loadrs] = value1;
                }

                if (strstr(buf, "b0 = ")) {
                        eframe[P_b0] = value1;
                }

                if (strstr(buf, "b6 = ")) {
                        eframe[P_b6] = value1;
                }

                if (strstr(buf, "b7 = ")) {
                        eframe[P_b7] = value1;
                }

                if (strstr(buf, "r1 = ")) {
                        eframe[P_r1] = value1;
                }


                if (strstr(buf, "r2 = ")) {
                        eframe[P_r2] = value1;
                }


                if (strstr(buf, "r3 = ")) {
                        eframe[P_r3] = value1;
                }


                if (strstr(buf, "r8 = ")) {
                        eframe[P_r8] = value1;
                }


                if (strstr(buf, "r9 = ")) {
                        eframe[P_r9] = value1;
                }

                if (strstr(buf, "r10 = ")) {
                        eframe[P_r10] = value1;
                }


                if (strstr(buf, "r11 = ")) {
                        eframe[P_r11] = value1;
                }

                if (strstr(buf, "r12 = ")) {
                        eframe[P_r12] = value1;
                }

                if (strstr(buf, "r13 = ")) {
                        eframe[P_r13] = value1;
                }

                if (strstr(buf, "r14 = ")) {
                        eframe[P_r14] = value1;
                }

                if (strstr(buf, "r15 = ")) {
                        eframe[P_r15] = value1;
                }

                if (strstr(buf, "r16 = ")) {
                        eframe[P_r16] = value1;
                }

                if (strstr(buf, "r17 = ")) {
                        eframe[P_r17] = value1;
                }

                if (strstr(buf, "r18 = ")) {
                        eframe[P_r18] = value1;
                }

                if (strstr(buf, "r19 = ")) {
                        eframe[P_r19] = value1;
                }

                if (strstr(buf, "r20 = ")) {
                        eframe[P_r20] = value1;
                }

                if (strstr(buf, "r21 = ")) {
                        eframe[P_r21] = value1;
                }

                if (strstr(buf, "r22 = ")) {
                        eframe[P_r22] = value1;
                }

                if (strstr(buf, "r23 = ")) {
                        eframe[P_r23] = value1;
                }

                if (strstr(buf, "r24 = ")) {
                        eframe[P_r24] = value1;
                }

                if (strstr(buf, "r25 = ")) {
                        eframe[P_r25] = value1;
                }

                if (strstr(buf, "r26 = ")) {
                        eframe[P_r26] = value1;
                }

                if (strstr(buf, "r27 = ")) {
                        eframe[P_r27] = value1;
                }

                if (strstr(buf, "r28 = ")) {
                        eframe[P_r28] = value1;
                }

                if (strstr(buf, "r29 = ")) {
                        eframe[P_r29] = value1;
                }

                if (strstr(buf, "r30 = ")) {
                        eframe[P_r30] = value1;
                }

                if (strstr(buf, "r31 = ")) {
                        eframe[P_r31] = value1;
                }
	}

       	close_tmpfile(); 

	fprintf(fp, "  EFRAME: %lx\n", addr);

	fprintf(fp, "      B0: %016lx      CR_IIP: %016lx\n", 
		eframe[P_b0], eframe[P_cr_iip]);
/**
	if (is_kernel_text(eframe[P_cr_iip]))
        	fprintf(fp, "<%s>",
                	value_to_symstr(eframe[P_cr_iip], buf, 0));
	fprintf(fp, "\n");
**/
	fprintf(fp, " CR_IPSR: %016lx      CR_IFS: %016lx\n", 
		eframe[P_cr_ipsr], eframe[P_cr_ifs]);
	fprintf(fp, "  AR_PFS: %016lx      AR_RSC: %016lx\n", 
		eframe[P_ar_pfs], eframe[P_ar_rsc]);
	fprintf(fp, " AR_UNAT: %016lx     AR_RNAT: %016lx\n", 
		eframe[P_ar_unat], eframe[P_ar_rnat]);
        fprintf(fp, "  AR_CCV: %016lx     AR_FPSR: %016lx\n",
                eframe[P_ar_ccv], eframe[P_ar_fpsr]);
        fprintf(fp, "  LOADRS: %016lx AR_BSPSTORE: %016lx\n", 
		eframe[P_loadrs], eframe[P_ar_bspstore]);
        fprintf(fp, "      B6: %016lx          B7: %016lx\n", 
		eframe[P_b6], eframe[P_b7]);
        fprintf(fp, "      PR: %016lx          R1: %016lx\n", 
		eframe[P_pr], eframe[P_r1]);
        fprintf(fp, "      R2: %016lx          R3: %016lx\n", 
		eframe[P_r2], eframe[P_r3]);
        fprintf(fp, "      R8: %016lx          R9: %016lx\n", 
		eframe[P_r8], eframe[P_r9]);
        fprintf(fp, "     R10: %016lx         R11: %016lx\n", 
		eframe[P_r10], eframe[P_r11]);
        fprintf(fp, "     R12: %016lx         R13: %016lx\n", 
		eframe[P_r12], eframe[P_r13]);
        fprintf(fp, "     R14: %016lx         R15: %016lx\n", 
		eframe[P_r14], eframe[P_r15]);
        fprintf(fp, "     R16: %016lx         R17: %016lx\n", 
		eframe[P_r16], eframe[P_r17]);
        fprintf(fp, "     R18: %016lx         R19: %016lx\n", 
		eframe[P_r18], eframe[P_r19]);
        fprintf(fp, "     R20: %016lx         R21: %016lx\n", 
		eframe[P_r20], eframe[P_r21]);
        fprintf(fp, "     R22: %016lx         R23: %016lx\n", 
		eframe[P_r22], eframe[P_r23]);
        fprintf(fp, "     R24: %016lx         R25: %016lx\n", 
		eframe[P_r24], eframe[P_r25]);
        fprintf(fp, "     R26: %016lx         R27: %016lx\n", 
		eframe[P_r26], eframe[P_r27]);
        fprintf(fp, "     R28: %016lx         R29: %016lx\n", 
		eframe[P_r28], eframe[P_r29]);
        fprintf(fp, "     R30: %016lx         R31: %016lx\n", 
		eframe[P_r30], eframe[P_r31]);
	fprintf(fp, "      F6: %05lx%016lx  ",
		eframe[P_f6_hi], eframe[P_f6_lo]);
        fprintf(fp, "   F7: %05lx%016lx\n",
                eframe[P_f7_hi], eframe[P_f7_lo]);
        fprintf(fp, "      F8: %05lx%016lx  ",
                eframe[P_f8_hi], eframe[P_f8_lo]);
        fprintf(fp, "   F9: %05lx%016lx\n",
                eframe[P_f9_hi], eframe[P_f9_lo]);
}

enum ss_reg_names { 
		S_caller_unat, S_ar_fpsr,
		S_f2_lo, S_f2_hi,
		S_f3_lo, S_f3_hi,
		S_f4_lo, S_f4_hi,
		S_f5_lo, S_f5_hi,
		S_f10_lo, S_f10_hi,
		S_f11_lo, S_f11_hi,
		S_f12_lo, S_f12_hi,
		S_f13_lo, S_f13_hi,
		S_f14_lo, S_f14_hi,
		S_f15_lo, S_f15_hi,
		S_f16_lo, S_f16_hi,
		S_f17_lo, S_f17_hi,
		S_f18_lo, S_f18_hi,
		S_f19_lo, S_f19_hi,
                S_f20_lo, S_f20_hi,
                S_f21_lo, S_f21_hi,
                S_f22_lo, S_f22_hi,
                S_f23_lo, S_f23_hi,
                S_f24_lo, S_f24_hi,
                S_f25_lo, S_f25_hi,
                S_f26_lo, S_f26_hi,
                S_f27_lo, S_f27_hi,
                S_f28_lo, S_f28_hi,
                S_f29_lo, S_f29_hi,
                S_f30_lo, S_f30_hi,
                S_f31_lo, S_f31_hi,
		S_r4, S_r5, S_r6, S_r7,
		S_b0, S_b1, S_b2, S_b3, S_b4, S_b5,
		S_ar_pfs, S_ar_lc, S_ar_unat, S_ar_rnat, S_ar_bspstore, S_pr,
                NUM_SS_REGS };


/*
 *  Format the switch_stack structure.
 */
static void
ia64_dump_switch_stack(ulong task, ulong flag)
{
	ulong addr;
        char buf[BUFSIZE], *p;
        int fval;
        ulong value1, value2;
        ulong ss[NUM_SS_REGS];

	addr = SWITCH_STACK_ADDR(task);

        BZERO(&ss, sizeof(ulong) * NUM_SS_REGS);

        open_tmpfile();
        dump_struct("switch_stack", addr, RADIX(16));
        rewind(pc->tmpfile);

        fval = 0;
        while (fgets(buf, BUFSIZE, pc->tmpfile)) {

		if (strstr(buf, "f2 = ")) {
			fval = 2;
			continue;
		}
		if (strstr(buf, "f3 = ")) {
			fval = 3;
			continue;
		}
		if (strstr(buf, "f4 = ")) {
			fval = 4;
			continue;
		}
		if (strstr(buf, "f5 = ")) {
			fval = 5;
			continue;
		}
		if (strstr(buf, "f10 = ")) {
			fval = 10;
			continue;
		}
		if (strstr(buf, "f11 = ")) {
			fval = 11;
			continue;
		}
		if (strstr(buf, "f12 = ")) {
			fval = 12;
			continue;
		}
		if (strstr(buf, "f13 = ")) {
			fval = 13;
			continue;
		}
		if (strstr(buf, "f14 = ")) {
			fval = 14;
			continue;
		}
		if (strstr(buf, "f15 = ")) {
			fval = 15;
			continue;
		}
		if (strstr(buf, "f16 = ")) {
			fval = 16;
			continue;
		}
		if (strstr(buf, "f17 = ")) {
			fval = 17;
			continue;
		}
		if (strstr(buf, "f18 = ")) {
			fval = 18;
			continue;
		}
		if (strstr(buf, "f19 = ")) {
			fval = 19;
			continue;
		}
		if (strstr(buf, "f20 = ")) {
			fval = 20;
			continue;
		}
		if (strstr(buf, "f21 = ")) {
			fval = 21;
			continue;
		}
		if (strstr(buf, "f22 = ")) {
			fval = 22;
			continue;
		}
		if (strstr(buf, "f23 = ")) {
			fval = 23;
			continue;
		}
		if (strstr(buf, "f24 = ")) {
			fval = 24;
			continue;
		}
		if (strstr(buf, "f25 = ")) {
			fval = 25;
			continue;
		}
		if (strstr(buf, "f26 = ")) {
			fval = 26;
			continue;
		}
		if (strstr(buf, "f27 = ")) {
			fval = 27;
			continue;
		}
		if (strstr(buf, "f28 = ")) {
			fval = 28;
			continue;
		}
		if (strstr(buf, "f29 = ")) {
			fval = 29;
			continue;
		}
                if (strstr(buf, "f30 = ")) {
                        fval = 30;
                        continue;
                }
                if (strstr(buf, "f31 = ")) {
                        fval = 31;
                        continue;
                }

                if (!strstr(buf, "0x"))
                        continue;

		if (fval) {
			p = strstr(buf, "0x");
			extract_hex(p, &value1, ',', TRUE);
			p = strstr(buf, ",");
			extract_hex(p, &value2, '}', FALSE);  
			switch (fval)
			{
			case 2:
				ss[S_f2_lo] = value1;
				ss[S_f2_hi] = value2;
				break;
			case 3:
				ss[S_f3_lo] = value1;
				ss[S_f3_hi] = value2;
				break;
			case 4:
				ss[S_f4_lo] = value1;
				ss[S_f4_hi] = value2;
				break;
			case 5:
				ss[S_f5_lo] = value1;
				ss[S_f5_hi] = value2;
				break;
                        case 10:
                                ss[S_f10_lo] = value1;
                                ss[S_f10_hi] = value2;
                                break;
                        case 11:
                                ss[S_f11_lo] = value1;
                                ss[S_f11_hi] = value2;
                                break;
                        case 12:
                                ss[S_f12_lo] = value1;
                                ss[S_f12_hi] = value2;
                                break;
                        case 13:
                                ss[S_f13_lo] = value1;
                                ss[S_f13_hi] = value2;
                                break;
                        case 14:
                                ss[S_f14_lo] = value1;
                                ss[S_f14_hi] = value2;
                                break;
                        case 15:
                                ss[S_f15_lo] = value1;
                                ss[S_f15_hi] = value2;
                                break;
                        case 16:
                                ss[S_f16_lo] = value1;
                                ss[S_f16_hi] = value2;
                                break;
                        case 17:
                                ss[S_f17_lo] = value1;
                                ss[S_f17_hi] = value2;
                                break;
                        case 18:
                                ss[S_f18_lo] = value1;
                                ss[S_f18_hi] = value2;
                                break;
                        case 19:
                                ss[S_f19_lo] = value1;
                                ss[S_f19_hi] = value2;
                                break;
                        case 20:
                                ss[S_f20_lo] = value1;
                                ss[S_f20_hi] = value2;
                                break;
                        case 21:
                                ss[S_f21_lo] = value1;
                                ss[S_f21_hi] = value2;
                                break;
                        case 22:
                                ss[S_f22_lo] = value1;
                                ss[S_f22_hi] = value2;
                                break;
                        case 23:
                                ss[S_f23_lo] = value1;
                                ss[S_f23_hi] = value2;
                                break;
                        case 24:
                                ss[S_f24_lo] = value1;
                                ss[S_f24_hi] = value2;
                                break;
                        case 25:
                                ss[S_f25_lo] = value1;
                                ss[S_f25_hi] = value2;
                                break;
                        case 26:
                                ss[S_f26_lo] = value1;
                                ss[S_f26_hi] = value2;
                                break;
                        case 27:
                                ss[S_f27_lo] = value1;
                                ss[S_f27_hi] = value2;
                                break;
                        case 28:
                                ss[S_f28_lo] = value1;
                                ss[S_f28_hi] = value2;
                                break;
                        case 29:
                                ss[S_f29_lo] = value1;
                                ss[S_f29_hi] = value2;
                                break;
                        case 30:
                                ss[S_f30_lo] = value1;
                                ss[S_f30_hi] = value2;
                                break;
                        case 31:
                                ss[S_f31_lo] = value1;
                                ss[S_f31_hi] = value2;
                                break;
			}
			fval = 0;
			continue;
		}
		
		strip_comma(clean_line(buf));
		p = strstr(buf, " = ");
		extract_hex(p, &value1, NULLCHAR, FALSE);

                if (strstr(buf, "caller_unat = ")) {
                        ss[S_caller_unat] = value1;
                }
                if (strstr(buf, "ar_fpsr = ")) {
                        ss[S_ar_fpsr] = value1;
                }
                if (strstr(buf, "r4 = ")) {
                        ss[S_r4] = value1;
                }
                if (strstr(buf, "r5 = ")) {
                        ss[S_r5] = value1;
                }
                if (strstr(buf, "r6 = ")) {
                        ss[S_r6] = value1;
                }
                if (strstr(buf, "r7 = ")) {
                        ss[S_r7] = value1;
                }
                if (strstr(buf, "b0 = ")) {
                        ss[S_b0] = value1;
                }
                if (strstr(buf, "b1 = ")) {
                        ss[S_b1] = value1;
                }
                if (strstr(buf, "b2 = ")) {
                        ss[S_b2] = value1;
                }
                if (strstr(buf, "b3 = ")) {
                        ss[S_b3] = value1;
                }
                if (strstr(buf, "b4 = ")) {
                        ss[S_b4] = value1;
                }
                if (strstr(buf, "b5 = ")) {
                        ss[S_b5] = value1;
                }
                if (strstr(buf, "ar_pfs = ")) {
                        ss[S_ar_pfs] = value1;
                }
                if (strstr(buf, "ar_lc = ")) {
                        ss[S_ar_lc] = value1;
                }
                if (strstr(buf, "ar_unat = ")) {
                        ss[S_ar_unat] = value1;
                }
                if (strstr(buf, "ar_rnat = ")) {
                        ss[S_ar_rnat] = value1;
                }
                if (strstr(buf, "ar_bspstore = ")) {
                        ss[S_ar_bspstore] = value1;
                }
                if (strstr(buf, "pr = ")) {
                        ss[S_pr] = value1;
                }
	}

	close_tmpfile();

	fprintf(fp, "SWITCH_STACK: %lx\n", addr);

        fprintf(fp, "      B0: %016lx          B1: %016lx\n",
		ss[S_b0], ss[S_b1]);
        fprintf(fp, "      B2: %016lx          B3: %016lx\n",
		ss[S_b2], ss[S_b3]);
        fprintf(fp, "      B4: %016lx          B5: %016lx\n",
		ss[S_b4], ss[S_b5]);

	fprintf(fp, "  AR_PFS: %016lx       AR_LC: %016lx\n",
		ss[S_ar_pfs], ss[S_ar_lc]);
	fprintf(fp, " AR_UNAT: %016lx     AR_RNAT: %016lx\n",
		ss[S_ar_unat], ss[S_ar_rnat]);
	fprintf(fp, "      PR: %016lx AR_BSPSTORE: %016lx\n",
		ss[S_pr], ss[S_ar_bspstore]);
	fprintf(fp, " AR_FPSR: %016lx CALLER_UNAT: %016lx\n",
		ss[S_ar_fpsr], ss[S_caller_unat]);

        fprintf(fp, "      R4: %016lx          R5: %016lx\n",
		ss[S_r4], ss[S_r5]);
        fprintf(fp, "      R6: %016lx          R7: %016lx\n",
		ss[S_r6], ss[S_r7]);

        fprintf(fp, "      F2: %05lx%016lx  ", ss[S_f2_hi], ss[S_f2_lo]);
        fprintf(fp, "   F3: %05lx%016lx\n", ss[S_f3_hi], ss[S_f3_lo]);
        fprintf(fp, "      F4: %05lx%016lx  ", ss[S_f4_hi], ss[S_f4_lo]);
        fprintf(fp, "   F5: %05lx%016lx\n", ss[S_f5_hi], ss[S_f5_lo]);
        fprintf(fp, "     F10: %05lx%016lx  ", ss[S_f10_hi], ss[S_f10_lo]);
        fprintf(fp, "  F11: %05lx%016lx\n", ss[S_f11_hi], ss[S_f11_lo]);
        fprintf(fp, "     F12: %05lx%016lx  ", ss[S_f12_hi], ss[S_f12_lo]);
        fprintf(fp, "  F13: %05lx%016lx\n", ss[S_f13_hi], ss[S_f13_lo]);
        fprintf(fp, "     F14: %05lx%016lx  ", ss[S_f14_hi], ss[S_f14_lo]);
        fprintf(fp, "  F15: %05lx%016lx\n", ss[S_f15_hi], ss[S_f15_lo]);
        fprintf(fp, "     F16: %05lx%016lx  ", ss[S_f16_hi], ss[S_f16_lo]);
        fprintf(fp, "  F17: %05lx%016lx\n", ss[S_f17_hi], ss[S_f17_lo]);
        fprintf(fp, "     F18: %05lx%016lx  ", ss[S_f18_hi], ss[S_f18_lo]);
        fprintf(fp, "  F19: %05lx%016lx\n", ss[S_f19_hi], ss[S_f19_lo]);
        fprintf(fp, "     F20: %05lx%016lx  ", ss[S_f20_hi], ss[S_f20_lo]);
        fprintf(fp, "  F21: %05lx%016lx\n", ss[S_f21_hi], ss[S_f21_lo]);
        fprintf(fp, "     F22: %05lx%016lx  ", ss[S_f22_hi], ss[S_f22_lo]);
        fprintf(fp, "  F23: %05lx%016lx\n", ss[S_f23_hi], ss[S_f23_lo]);
        fprintf(fp, "     F24: %05lx%016lx  ", ss[S_f24_hi], ss[S_f24_lo]);
        fprintf(fp, "  F25: %05lx%016lx\n", ss[S_f25_hi], ss[S_f25_lo]);
        fprintf(fp, "     F26: %05lx%016lx  ", ss[S_f26_hi], ss[S_f26_lo]);
        fprintf(fp, "  F27: %05lx%016lx\n", ss[S_f27_hi], ss[S_f27_lo]);
        fprintf(fp, "     F28: %05lx%016lx  ", ss[S_f28_hi], ss[S_f28_lo]);
        fprintf(fp, "  F29: %05lx%016lx\n", ss[S_f29_hi], ss[S_f29_lo]);
        fprintf(fp, "     F30: %05lx%016lx  ", ss[S_f30_hi], ss[S_f30_lo]);
        fprintf(fp, "  F31: %05lx%016lx\n", ss[S_f31_hi], ss[S_f31_lo]);
}

/*
 *   Override smp_num_cpus if possible and necessary.
 */
int
ia64_get_smp_cpus(void)
{
	return kt->cpus;
}

/*
 *  Machine dependent command.
 */
void
ia64_cmd_mach(void)
{
        int c;

        while ((c = getopt(argcnt, args, "c")) != EOF) {
                switch(c)
                {
		case 'c':
			ia64_display_cpu_data();
			return;
                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

	ia64_display_machine_stats();
}

/*
 *  "mach" command output.
 */
static void
ia64_display_machine_stats(void)
{
        struct new_utsname *uts;
        char buf[BUFSIZE];
        ulong mhz;

        uts = &kt->utsname;

        fprintf(fp, "              MACHINE TYPE: %s\n", uts->machine);
        fprintf(fp, "               MEMORY SIZE: %s\n", get_memory_size(buf));
        fprintf(fp, "                      CPUS: %d\n", kt->cpus);
        fprintf(fp, "           PROCESSOR SPEED: ");
        if ((mhz = machdep->processor_speed()))
                fprintf(fp, "%ld Mhz\n", mhz);
        else
                fprintf(fp, "(unknown)\n");
        fprintf(fp, "                        HZ: %d\n", machdep->hz);
        fprintf(fp, "                 PAGE SIZE: %d\n", PAGESIZE());
        fprintf(fp, "             L1 CACHE SIZE: %d\n", l1_cache_size());
        fprintf(fp, "         KERNEL STACK SIZE: %ld\n", STACKSIZE());
        fprintf(fp, "      KERNEL CACHED REGION: %lx\n",
		(ulong)KERNEL_CACHED_REGION << REGION_SHIFT);
        fprintf(fp, "    KERNEL UNCACHED REGION: %lx\n", 
		(ulong)KERNEL_UNCACHED_REGION << REGION_SHIFT);
        fprintf(fp, "     KERNEL VMALLOC REGION: %lx\n", 
		(ulong)KERNEL_VMALLOC_REGION << REGION_SHIFT);
	fprintf(fp, "         USER STACK REGION: %lx\n",
		(ulong)USER_STACK_REGION << REGION_SHIFT);
	fprintf(fp, "          USER DATA REGION: %lx\n",
		(ulong)USER_DATA_REGION << REGION_SHIFT);
	fprintf(fp, "          USER TEXT REGION: %lx\n",
		(ulong)USER_TEXT_REGION << REGION_SHIFT);
	fprintf(fp, " USER SHARED MEMORY REGION: %lx\n",
		(ulong)USER_SHMEM_REGION << REGION_SHIFT);
	fprintf(fp, "USER IA32 EMULATION REGION: %016lx\n",
		(ulong)USER_IA32_EMUL_REGION << REGION_SHIFT);
}

static void 
ia64_display_cpu_data(void)
{
        int cpu;
        ulong cpu_data;

        cpu_data = symbol_value("cpu_data");

        for (cpu = 0; cpu < kt->cpus; cpu++) {
                fprintf(fp, "%sCPU %d:\n", cpu ? "\n" : "", cpu);
                dump_struct("cpuinfo_ia64", cpu_data, 0);
                cpu_data += SIZE(cpuinfo_ia64);
        }
}

#ifndef _ASM_IA64_UNWIND_H
#define _ASM_IA64_UNWIND_H

/*
 * Copyright (C) 1999-2000 Hewlett-Packard Co
 * Copyright (C) 1999-2000 David Mosberger-Tang <davidm@hpl.hp.com>
 *
 * A simple API for unwinding kernel stacks.  This is used for
 * debugging and error reporting purposes.  The kernel doesn't need
 * full-blown stack unwinding with all the bells and whitles, so there
 * is not much point in implementing the full IA-64 unwind API (though
 * it would of course be possible to implement the kernel API on top
 * of it).
 */

struct task_struct;	/* forward declaration */
struct switch_stack;	/* forward declaration */

enum unw_application_register {
	UNW_AR_BSP,
	UNW_AR_BSPSTORE,
	UNW_AR_PFS,
	UNW_AR_RNAT,
	UNW_AR_UNAT,
	UNW_AR_LC,
	UNW_AR_EC,
	UNW_AR_FPSR,
	UNW_AR_RSC,
	UNW_AR_CCV
};

/*
 * The following declarations are private to the unwind
 * implementation:
 */

struct unw_stack {
	unsigned long limit;
	unsigned long top;
};

#define UNW_FLAG_INTERRUPT_FRAME	(1UL << 0)

/*
 * No user of this module should every access this structure directly
 * as it is subject to change.  It is declared here solely so we can
 * use automatic variables.
 */
struct unw_frame_info {
	struct unw_stack regstk;
	struct unw_stack memstk;
	unsigned int flags;
	short hint;
	short prev_script;
	unsigned long bsp;
	unsigned long sp;		/* stack pointer */
	unsigned long psp;		/* previous sp */
	unsigned long ip;		/* instruction pointer */
	unsigned long pr_val;		/* current predicates */
	unsigned long *cfm;

	struct task_struct *task;
	struct switch_stack *sw;

	/* preserved state: */
	unsigned long *pbsp;		/* previous bsp */
	unsigned long *bspstore;
	unsigned long *pfs;
	unsigned long *rnat;
	unsigned long *rp;
	unsigned long *pri_unat;
	unsigned long *unat;
	unsigned long *pr;
	unsigned long *lc;
	unsigned long *fpsr;
	struct unw_ireg {
		unsigned long *loc;
		struct unw_ireg_nat {
			int type : 3;		/* enum unw_nat_type */
			signed int off;		/* NaT word is at loc+nat.off */
		} nat;
	} r4, r5, r6, r7;
	unsigned long *b1, *b2, *b3, *b4, *b5;
	struct ia64_fpreg *f2, *f3, *f4, *f5, *fr[16];
};

#endif /* _ASM_UNWIND_H */

#define IA64_RBS_OFFSET   ((SIZE(task_struct) + 15) & ~15)
#define IA64_STK_OFFSET   (STACKSIZE())

/*
 *  Perform any leftover pre-prompt machine-specific initialization tasks here.
 */
static void
ia64_post_init(void)
{
	struct datatype_member datatype_member, *dm;
	struct machine_specific *ms;
	long len;

	if (symbol_exists("unw_init_frame_info"))
		machdep->flags |= NEW_UNWIND;
	else
		machdep->flags |= OLD_UNWIND;

	dm = &datatype_member;
        if (arg_to_datatype("unw_frame_info", dm, RETURN_ON_ERROR)) {
                if ((len = dm->size) < 0) {
			fprintf(fp, 
			    "cannot determine length of unw_frame_info\n");
			machdep->flags |= UNW_FI_UNKNOWN;
		} else if (len != sizeof(struct unw_frame_info)) {
			error(WARNING, 
			   "unw_frame_info differs: %ld (local: %d)\n", 
				len, sizeof(struct unw_frame_info));
			machdep->flags |= UNW_FI_UNKNOWN;
		} else
			machdep->flags |= UNW_FI_INSYNC;
	}

	ms = &ia64_machine_specific;
        if (symbol_exists("cpu_data") && STRUCT_EXISTS("cpuinfo_ia64")) {
            	if (MEMBER_EXISTS("cpuinfo_ia64", "unimpl_va_mask"))
       			readmem(symbol_value("cpu_data") +
                		MEMBER_OFFSET("cpuinfo_ia64", "unimpl_va_mask"),
                		KVADDR, &ms->unimpl_va_mask, sizeof(ulong),
                		"cpuinfo_ia64 unimpl_va_mask", FAULT_ON_ERROR);
            	if (MEMBER_EXISTS("cpuinfo_ia64", "unimpl_pa_mask"))
                        readmem(symbol_value("cpu_data") +
                                MEMBER_OFFSET("cpuinfo_ia64", "unimpl_pa_mask"),
                                KVADDR, &ms->unimpl_pa_mask, sizeof(ulong),
                                "cpuinfo_ia64 unimpl_pa_mask", FAULT_ON_ERROR);
	}
}

/*
 *  Unwind the stack using the basic method used when CONFIG_IA64_NEW_UNWIND
 *  is not configured into the kernel.
 *
 *  NOTE: see kernel source: show_stack() and/or kdba_bt_stack()
 */

static int unw_debug;  /* debug fprintf indent */

static void
ia64_old_unwind(struct bt_info *bt)
{
        struct unw_frame_info unw_frame_info, *info;
	struct syment *sm;
	ulong offset;
	int frame;
	ulong debug_save;
	char *name;

	if (bt->debug) {
		debug_save = pc->debug;
		pc->debug = bt->debug;
	}

	if (MCLXDEBUG(1))
		unw_debug = 0;

	info = &unw_frame_info;
	unw_init_from_blocked_task(info, bt->task);
	frame = 0;

	do {
                if (info->ip == 0) 
                        break; 

		if (!IS_KVADDR(info->ip))
			break;

		if ((sm = value_search(info->ip, &offset)))
			name = sm->name;
		else
			name = "(unknown)";

		if (BT_REFERENCE_CHECK(bt)) {
                	switch (bt->ref->cmdflags & 
				(BT_REF_SYMBOL|BT_REF_HEXVAL))
                	{
                	case BT_REF_SYMBOL:
                        	if (STREQ(name, bt->ref->str)) {
                                	bt->ref->cmdflags |= BT_REF_FOUND;
					return;
				}
                        	break;

                	case BT_REF_HEXVAL:
                        	if (bt->ref->hexval == info->ip) {
                                	bt->ref->cmdflags |= BT_REF_FOUND;
					return;
				}
                        	break;   
                	}
		} else {

			fprintf(fp, "%s#%d [BSP:%lx] %s at %lx\n",
				frame >= 10 ? "" : " ", frame,
				info->bsp, name, info->ip);

			rse_function_params(info, name);
			if (bt->flags & BT_LINE_NUMBERS)
				ia64_dump_line_number(info->ip);
		}

		frame++;

		if (MCLXDEBUG(1))
			unw_debug = 0;

	} while (old_unw_unwind(info) >= 0);

        if (bt->debug) 
                pc->debug = debug_save;
}

/*
 *  Unwind the stack using the basic method used when CONFIG_IA64_NEW_UNWIND
 *  is configured into the kernel.
 */
static void
ia64_new_unwind(struct bt_info *bt)
{
	error(INFO, "this kernel has CONFIG_IA64_NEW_UNWIND turned on!\n");
	ia64_old_unwind(bt);
}

static unsigned long
ia64_rse_slot_num (unsigned long *addr)
{
        return (((unsigned long) addr) >> 3) & 0x3f;
}

/* 
 * Given a bsp address and a number of register locations, calculate a new 
 * bsp address, accounting for any intervening RNAT stores.
 */
static unsigned long *
ia64_rse_skip_regs (unsigned long *addr, long num_regs)
{
        long delta = ia64_rse_slot_num(addr) + num_regs;

	if (MCLXDEBUG(1)) {
		fprintf(fp, 
	    "%sia64_rse_skip_regs: ia64_rse_slot_num(%lx): %ld num_regs: %ld\n",
			space(unw_debug),
			(ulong)addr, ia64_rse_slot_num(addr), num_regs);
	}

        if (num_regs < 0)
                delta -= 0x3e;

	if (MCLXDEBUG(1)) {
		fprintf(fp, "%sia64_rse_skip_regs: delta: %ld return(%lx)",
			space(unw_debug), delta,
			(ulong)(addr + num_regs + delta/0x3f));
		if (addr > (addr + num_regs + delta/0x3f)) 
			fprintf(fp, "(-%ld)\n",
				addr - (addr + num_regs + delta/0x3f));
		else
			fprintf(fp, "(+%ld)\n",
				(addr + num_regs + delta/0x3f) - addr);
	}

        return(addr + num_regs + delta/0x3f);
}

/*
 * Returns the address of the RNAT slot that covers the slot at
 * address SLOT_ADDR.
 */
static unsigned long *
ia64_rse_rnat_addr (unsigned long *slot_addr)
{
        return (unsigned long *) ((unsigned long) slot_addr | (0x3f << 3));
}

/*
 *  Initialize the key fields in the unw_frame_info structure.
 *
 *  NOTE: see kernel source: unw_init_from_blocked_task()
 */
static void
unw_init_from_blocked_task(struct unw_frame_info *info, ulong task)
{
	ulong sw;
        ulong sol, limit, top;
	ulong ar_pfs, ar_bspstore, b0;

	sw = SWITCH_STACK_ADDR(task);
	BZERO(info, sizeof(struct unw_frame_info));

        readmem(sw + OFFSET(switch_stack_b0), KVADDR,
                &b0, sizeof(ulong), "switch_stack b0", FAULT_ON_ERROR);
        readmem(sw + OFFSET(switch_stack_ar_pfs), KVADDR,
                &ar_pfs, sizeof(ulong), "switch_stack ar_pfs", FAULT_ON_ERROR);
        readmem(sw + OFFSET(switch_stack_ar_bspstore), KVADDR,
                &ar_bspstore, sizeof(ulong), "switch_stack ar_bspstore", 
		FAULT_ON_ERROR);

        sol = (ar_pfs >> 7) & 0x7f; /* size of locals */

        limit = task + IA64_RBS_OFFSET;
        top = ar_bspstore;
        if ((top - task) >= IA64_STK_OFFSET)
                top = limit;

        if (MCLXDEBUG(1)) {
		unw_debug++;
                fprintf(fp, 
                    "unw_init_from_blocked_task: stack top: %lx sol: %ld\n",
			top, sol);
	}

        info->regstk.limit = limit;
        info->regstk.top   = top;
        info->sw = (struct switch_stack *)sw;
        info->bsp = (ulong)ia64_rse_skip_regs((ulong *)info->regstk.top, -sol);
        info->cfm = (ulong *)(sw + OFFSET(switch_stack_ar_pfs));
        info->ip = b0;

	if (MCLXDEBUG(1)) 
		dump_unw_frame_info(info);
}

/*
 *  Update the unw_frame_info structure based upon its current state.
 *  This routine works without enabling CONFIG_IA64_NEW_UNWIND because 
 *  gdb allocates two additional "local" register locations for each
 *  function, found at the end of the stored locals:
 *
 *      register "sol-1" (last local) = ar.pfs (gives us previous sol)
 *      register "sol-2" (2nd to last local = b0 to previous address
 *
 *  NOTE: see kernel source: unw_unwind() (#ifndef CONFIG_IA64_NEW_UNWIND)
 *  On entry, info->regstk.top should point to the register backing
 *  store for r32.
 */

static int
old_unw_unwind (struct unw_frame_info *info)
{
	unsigned long sol, cfm;
	int is_nat;

        if (!readmem((ulong)info->cfm, KVADDR, &cfm,
             sizeof(long), "info->cfm", QUIET|RETURN_ON_ERROR))
		return -1;

        sol = (cfm >> 7) & 0x7f;        /* size of locals */

	if (MCLXDEBUG(1)) {
		fprintf(fp, "old_unw_unwind: cfm: %lx  sol: %ld\n", cfm, sol);
		unw_debug++;
	}

       /*
         * In general, we would have to make use of unwind info to
         * unwind an IA-64 stack, but for now gcc uses a special
         * convention that makes this possible without full-fledged
         * unwind info.  Specifically, we expect "rp" in the second
         * last, and "ar.pfs" in the last local register, so the
         * number of locals in a frame must be at least two.  If it's
         * less than that, we reached the end of the C call stack.
         */
        if (sol < 2)
                return -1;

        info->ip = rse_read_reg(info, sol - 2, &is_nat);

	if (MCLXDEBUG(1))
		fprintf(fp, "old_unw_unwind: ip: %lx\n", info->ip);

        if (is_nat || (info->ip & (machdep->machspec->unimpl_va_mask | 0xf)))
                return -1;

        info->cfm = ia64_rse_skip_regs((ulong *)info->bsp, sol - 1);

        cfm = rse_read_reg(info, sol - 1, &is_nat);

	if (MCLXDEBUG(1))
		fprintf(fp, "old_unw_unwind: info->cfm: %lx => %lx\n", 
			(ulong)info->cfm, cfm);

        if (is_nat)
                return -1;

        sol = (cfm >> 7) & 0x7f;

        info->bsp = (ulong)ia64_rse_skip_regs((ulong *)info->bsp, -sol);

	if (MCLXDEBUG(1)) {
		fprintf(fp, "old_unw_unwind: next sol: %ld\n", sol);
		fprintf(fp, "old_unw_unwind: next bsp: %lx\n", info->bsp);
	}

	return 0;

#ifdef KERNEL_SOURCE
        unsigned long sol, cfm = *info->cfm;
        int is_nat;

        sol = (cfm >> 7) & 0x7f;        /* size of locals */

        /*
         * In general, we would have to make use of unwind info to
         * unwind an IA-64 stack, but for now gcc uses a special
         * convention that makes this possible without full-fledged
         * unwind info.  Specifically, we expect "rp" in the second
         * last, and "ar.pfs" in the last local register, so the
         * number of locals in a frame must be at least two.  If it's
         * less than that, we reached the end of the C call stack.
         */
        if (sol < 2)
                return -1;

        info->ip = rse_read_reg(info, sol - 2, &is_nat);
        if (is_nat || (info->ip & (my_cpu_data.unimpl_va_mask | 0xf)))
                /* reject let obviously bad addresses */
                return -1;

        info->cfm = ia64_rse_skip_regs((unsigned long *) info->bsp, sol - 1);
        cfm = rse_read_reg(info, sol - 1, &is_nat);
        if (is_nat)
                return -1;

        sol = (cfm >> 7) & 0x7f;

        info->bsp = (unsigned long) ia64_rse_skip_regs((unsigned long *) info->bsp, -sol);
        return 0;
#endif  /* KERNEL_SOURCE */
}


/*
 *  Retrieve a register value from the stack, returning its NAT attribute
 *  as well.
 *
 *  NOTE: see kernel source: read_reg()
 */
static ulong
rse_read_reg (struct unw_frame_info *info, int regnum, int *is_nat)
{
        ulong *addr, *rnat_addr, rnat;
	ulong regcontent;

	if (MCLXDEBUG(1)) {
		fprintf(fp, "%srse_read_reg: bsp: %lx\n", space(unw_debug),
			info->bsp);
		unw_debug++;
	}

        addr = ia64_rse_skip_regs((unsigned long *) info->bsp, regnum);

	if (MCLXDEBUG(1)) {
		unw_debug--;
		fprintf(fp, "%srse_read_reg: addr: %lx\n", 
			space(unw_debug), (ulong)addr);
	}

        if (((ulong)addr < info->regstk.limit) || 
	    ((ulong)addr >= info->regstk.top) || 
	    (((long)addr & 0x7) != 0)) {
                *is_nat = 1;

		if (MCLXDEBUG(1))
			fprintf(fp, 
		    "%srse_read_reg: is_nat: %d -- return 0xdeadbeefdeadbeef\n",
				space(unw_debug), *is_nat);

                return 0xdeadbeefdeadbeef;
        }

        rnat_addr = ia64_rse_rnat_addr(addr);

	if (MCLXDEBUG(1))
		fprintf(fp, "%srse_read_reg: rnat_addr: %lx\n", 
			space(unw_debug), (ulong)rnat_addr);

        if ((unsigned long) rnat_addr >= info->regstk.top) 
		readmem((ulong)(info->sw) + OFFSET(switch_stack_ar_rnat), 
			KVADDR, &rnat, sizeof(long), 
			"info->sw->ar_rnat", FAULT_ON_ERROR);
        else
		readmem((ulong)rnat_addr, KVADDR, &rnat, sizeof(long), 
			"rnat_addr", FAULT_ON_ERROR);

        *is_nat = (rnat & (1UL << ia64_rse_slot_num(addr))) != 0;

	if (MCLXDEBUG(1))
		fprintf(fp, "%srse_read_reg: rnat: %lx is_nat: %d\n",
			space(unw_debug), rnat, *is_nat);

	readmem((ulong)addr, KVADDR, &regcontent, sizeof(long), 
		"rse_read_reg addr", FAULT_ON_ERROR);

	if (MCLXDEBUG(1)) {
		char buf[BUFSIZE];

		fprintf(fp, "%srse_read_reg: addr: %lx => %lx ", 
			space(unw_debug), (ulong)addr, regcontent);
		if (is_kernel_text(regcontent))
			fprintf(fp, "(%s)", 
			    value_to_symstr(regcontent, buf, pc->output_radix));
		fprintf(fp, "\n");
	}

        return regcontent;
}

/*
 *  Display the arguments to a function, presuming that they are found at
 *  the beginning of the sol section.
 */

#define MAX_REGISTER_PARAMS (8)

static void 
rse_function_params(struct unw_frame_info *info, char *name)
{
	int i;
	int numargs, is_nat[MAX_REGISTER_PARAMS];
	char buf1[BUFSIZE], buf2[BUFSIZE], *p1, *p2;
	ulong arglist[MAX_REGISTER_PARAMS];

	numargs = MIN(get_function_numargs(info->ip), MAX_REGISTER_PARAMS);

	if (MCLXDEBUG(1))
		fprintf(fp, "rse_function_params: %s: %d args\n",
			name, numargs);

	switch (numargs)
	{
	case 0:
		fprintf(fp, "    (void)\n");
		return;

	case -1:
		return;

	default:
		break;
	}

	for (i = 0; i < numargs; i++) 
		arglist[i] = rse_read_reg(info, i, &is_nat[i]);

	sprintf(buf1, "    (");
	for (i = 0; i < numargs; i++) {
		p1 = &buf1[strlen(buf1)];
		if (is_nat[i])
			sprintf(buf2, "[NAT]");
		else {
			if ((p2 = value_symbol(arglist[i])))
				sprintf(buf2, "%s", p2);
			else
				sprintf(buf2, "%lx", arglist[i]);
		}
		sprintf(p1, "%s%s", i ? ", " : "", buf2);
		if (strlen(buf1) >= 80) 
			sprintf(p1, ",\n     %s", buf2);
	}
	strcat(buf1, ")\n");

	fprintf(fp, "%s", buf1);

}


static void 
dump_unw_frame_info(struct unw_frame_info *info)
{
	unw_debug++;

	fprintf(fp, "%sregstk.limit: %lx\n", 
		space(unw_debug), info->regstk.limit);
	fprintf(fp, "%s  regstk.top: %lx\n", 
		space(unw_debug), info->regstk.top);
	fprintf(fp, "%s          sw: %lx\n", 
		space(unw_debug), (ulong)info->sw);
	fprintf(fp, "%s         bsp: %lx\n", 
		space(unw_debug), info->bsp);
	fprintf(fp, "%s         cfm: %lx\n", 
		space(unw_debug), (ulong)info->cfm);
	fprintf(fp, "%s          ip: %lx\n", 
		space(unw_debug), info->ip);

	unw_debug--;
}

static void 
ia64_dump_line_number(ulong ip)
{
	int retries;
	char buf[BUFSIZE], *p;
	char *name;

	name = closest_symbol(ip);

	/*
	 *  gdb-related kludge for routines in entry.S, head.S and initfunc
         *  (fix this...)
	 */
        if (STREQ(name, "sys_clone2") ||
	    STREQ(name, "sys_clone") ||
	    STREQ(name, "ia64_switch_to") ||
	    STREQ(name, "save_switch_stack") ||
	    STREQ(name, "invoke_syscall_trace") ||
	    STREQ(name, "ia64_trace_syscall") ||
	    STREQ(name, "ia64_ret_from_clone") ||
	    STREQ(name, "ia64_ret_from_syscall") ||
	    STREQ(name, "ia64_leave_kernel") ||
	    STREQ(name, "sys_rt_sigsuspend") ||
	    STREQ(name, "ia64_prepare_handle_unaligned") ||
	    STREQ(name, "unw_init_running") ||
            STREQ(name, "__ia64_syscall")) {
                fprintf(fp, "    %s/arch/ia64/kernel/entry.S\n",
                        get_build_directory(buf) ? buf : "..");
                return;
        }
	if (STREQ(name, "_start") ||
            STREQ(name, "ia64_save_debug_regs") ||
            STREQ(name, "ia64_load_debug_regs") ||
            STREQ(name, "__ia64_save_fpu") ||
            STREQ(name, "__ia64_load_fpu") ||
            STREQ(name, "__ia64_init_fpu") ||
            STREQ(name, "ia64_switch_mode") ||
            STREQ(name, "ia64_set_b1") ||
            STREQ(name, "ia64_set_b2") ||
            STREQ(name, "ia64_set_b3") ||
            STREQ(name, "ia64_set_b4") ||
            STREQ(name, "ia64_set_b5") ||
            STREQ(name, "ia64_spinlock_contention")) {
                fprintf(fp, "    %s/arch/ia64/kernel/head.S\n",
                	get_build_directory(buf) ? buf : "..");
		return;
	}

        retries = 0;
try_closest:
	get_line_number(ip, buf, FALSE);

        if (strlen(buf)) {
                if (retries) {
                        p = strstr(buf, ": ");
			*p = NULLCHAR;
                }
                fprintf(fp, "    %s\n", buf);
        } else {
                if (retries)
                        fprintf(fp,
                            "    (cannot determine file and line number)\n");
                else {
                        retries++;
                        ip = closest_symbol_value(ip);
                        goto try_closest;
                }
        }
}

#endif
