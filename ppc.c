/* ppc.c - core analysis suite
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
 * 04/11/00, 2.3    Bug fixes, new command, options, initial PowerPC framework
 * 04/12/00  ---    Transition to BitKeeper version control
 * 
 * BitKeeper ID: @(#)ppc.c 1.19
 *
 * 09/28/00  ---    Transition to CVS version control
 *
 * CVS: $Revision: 1.61 $ $Date: 2002/01/23 17:44:07 $
 */ 
#ifdef PPC
#include "defs.h"

static int ppc_kvtop(struct task_context *, ulong, ulong *, int);
static int ppc_uvtop(struct task_context *, ulong, ulong *, int);
static ulong ppc_vmalloc_start(void);
static int ppc_is_task_addr(ulong);
static int ppc_verify_symbol(const char *, ulong);
static ulong ppc_get_task_pgd(ulong);
static int ppc_translate_pte(ulong, ulong *);
static ulong ppc_SWP_TYPE(ulong);
static ulong ppc_SWP_OFFSET(ulong);

static ulong ppc_processor_speed(void);
static void ppc_eframe_search(struct bt_info *);
static void ppc_back_trace_cmd(struct bt_info *);
static void ppc_back_trace(struct gnu_request *, struct bt_info *);
static void get_ppc_frame(struct bt_info *, ulong *, ulong *);
static void ppc_print_stack_entry(int,struct gnu_request *,
	ulong, char *, struct bt_info *);
static void ppc_exception_frame(ulong, struct bt_info *, struct gnu_request *);
static void ppc_dump_irq(int);
static int ppc_nr_irqs(void);
static ulong ppc_get_pc(struct bt_info *);
static ulong ppc_get_sp(struct bt_info *);
static void ppc_get_stack_frame(struct bt_info *, ulong *, ulong *);
static int ppc_dis_filter(ulong, char *);
static void ppc_cmd_mach(void);
static int ppc_get_smp_cpus(void);
static void ppc_display_machine_stats(void);
static void ppc_dump_line_number(ulong);

/*
 *  Do all necessary machine-specific setup here.  This is called twice,
 *  before and after GDB has been initialized.
 */
void
ppc_init(int when)
{
	switch (when)
	{
	case PRE_SYMTAB:
		machdep->verify_symbol = ppc_verify_symbol;
                if (pc->flags & KERNEL_DEBUG_QUERY)
                        return;
                machdep->pagesize = memory_page_size();
                machdep->pageshift = ffs(machdep->pagesize) - 1;
                machdep->pageoffset = machdep->pagesize - 1;
                machdep->pagemask = ~(machdep->pageoffset);
		machdep->stacksize = machdep->pagesize * 2;
                if ((machdep->pgd = (char *)malloc(PAGESIZE())) == NULL)
                        error(FATAL, "cannot malloc pgd space.");
                machdep->pmd = machdep->pgd;
                if ((machdep->ptbl = (char *)malloc(PAGESIZE())) == NULL)
                        error(FATAL, "cannot malloc ptbl space.");
                machdep->last_pgd_read = 0;
                machdep->last_pmd_read = 0;
                machdep->last_ptbl_read = 0;
		break;

	case PRE_GDB:
	        machdep->kvbase = symbol_value("_stext");
		machdep->identity_map_base = machdep->kvbase;
                machdep->is_kvaddr = generic_is_kvaddr;
                machdep->is_uvaddr = generic_is_uvaddr;
	        machdep->eframe_search = ppc_eframe_search;
	        machdep->back_trace = ppc_back_trace_cmd;
	        machdep->processor_speed = ppc_processor_speed;
	        machdep->uvtop = ppc_uvtop;
	        machdep->kvtop = ppc_kvtop;
	        machdep->get_task_pgd = ppc_get_task_pgd;
		machdep->nr_irqs = ppc_nr_irqs;
		machdep->get_stack_frame = ppc_get_stack_frame;
		machdep->get_stackbase = generic_get_stackbase;
		machdep->get_stacktop = generic_get_stacktop;
		machdep->translate_pte = ppc_translate_pte;
		machdep->memory_size = generic_memory_size;
		machdep->SWP_TYPE = ppc_SWP_TYPE;
		machdep->SWP_OFFSET = ppc_SWP_OFFSET;
		machdep->is_task_addr = ppc_is_task_addr;
		machdep->dis_filter = ppc_dis_filter;
		machdep->cmd_mach = ppc_cmd_mach;
		machdep->get_smp_cpus = ppc_get_smp_cpus;
		break;

	case POST_GDB:
		machdep->vmalloc_start = ppc_vmalloc_start;
		OFFSET(thread_struct_pg_tables) = 
 			MEMBER_OFFSET("thread_struct", "pg_tables");
		SIZE(pt_regs) = STRUCT_SIZE("pt_regs");

               	/* as of 2.3.x PPC uses the generic irq handlers */
        	if (STRUCT_SIZE("irq_desc_t") > 0) 
                	machdep->dump_irq = generic_dump_irq;
		else
			machdep->dump_irq = ppc_dump_irq;

                SIZE(irqdesc) = STRUCT_SIZE("irqdesc");
                OFFSET(irqdesc_action) = MEMBER_OFFSET("irqdesc", "action");
                OFFSET(irqdesc_ctl) = MEMBER_OFFSET("irqdesc", "ctl");
                OFFSET(irqdesc_level) = MEMBER_OFFSET("irqdesc", "level");
 
                OFFSET(irqaction_handler) =
                        MEMBER_OFFSET("irqaction", "handler");
                OFFSET(irqaction_flags) = MEMBER_OFFSET("irqaction", "flags");
                OFFSET(irqaction_mask) = MEMBER_OFFSET("irqaction", "mask");
                OFFSET(irqaction_name) = MEMBER_OFFSET("irqaction", "name");
                OFFSET(irqaction_dev_id) = MEMBER_OFFSET("irqaction", "dev_id");
                OFFSET(irqaction_next) = MEMBER_OFFSET("irqaction", "next");

                OFFSET(hw_interrupt_type_typename) =
                        MEMBER_OFFSET("hw_interrupt_type", "typename");
                OFFSET(hw_interrupt_type_startup) =
                        MEMBER_OFFSET("hw_interrupt_type", "startup");
                OFFSET(hw_interrupt_type_shutdown) =
                        MEMBER_OFFSET("hw_interrupt_type", "shutdown");
                OFFSET(hw_interrupt_type_enable) =
                        MEMBER_OFFSET("hw_interrupt_type", "enable");
                OFFSET(hw_interrupt_type_disable) =
                        MEMBER_OFFSET("hw_interrupt_type", "disable");
		machdep->hz = HZ;
		break;

	case POST_INIT:
		break;
	}
}

void
ppc_dump_machdep_table(void)
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
        fprintf(fp, "           pagemask: %lx\n", machdep->pagemask);
        fprintf(fp, "         pageoffset: %lx\n", machdep->pageoffset);
	fprintf(fp, "          stacksize: %ld\n", machdep->stacksize);
        fprintf(fp, "                 hz: %d\n", machdep->hz);
        fprintf(fp, "                mhz: %ld\n", machdep->mhz);
        fprintf(fp, "            memsize: %lld (0x%llx)\n", 
		machdep->memsize, machdep->memsize);
	fprintf(fp, "               bits: %d\n", machdep->bits);
        fprintf(fp, "      eframe_search: ppc_eframe_search()   [TBD]\n");
        fprintf(fp, "         back_trace: ppc_back_trace_cmd()\n");
        fprintf(fp, "    processor_speed: ppc_processor_speed()\n");
        fprintf(fp, "              uvtop: ppc_uvtop()\n");
        fprintf(fp, "              kvtop: ppc_kvtop()\n");
        fprintf(fp, "       get_task_pgd: ppc_get_task_pgd()\n");
	if (machdep->dump_irq == generic_dump_irq)
		fprintf(fp, "           dump_irq: generic_dump_irq()\n");
	else
		fprintf(fp, "           dump_irq: ppc_dump_irq()\n");
	fprintf(fp, "            nr_irqs: ppc_nr_irqs()\n");
        fprintf(fp, "    get_stack_frame: ppc_get_stack_frame()\n");
        fprintf(fp, "      get_stackbase: generic_get_stackbase()\n");
        fprintf(fp, "       get_stacktop: generic_get_stacktop()\n");
        fprintf(fp, "      translate_pte: ppc_translate_pte()\n");
	fprintf(fp, "        memory_size: generic_memory_size()\n");
	fprintf(fp, "      vmalloc_start: ppc_vmalloc_start()\n");
	fprintf(fp, "           SWP_TYPE: ppc_SWP_TYPE()\n");
	fprintf(fp, "         SWP_OFFSET: ppc_SWP_OFFSET()\n");
	fprintf(fp, "       is_task_addr: ppc_is_task_addr()\n");
	fprintf(fp, "      verify_symbol: ppc_verify_symbol()\n");
	fprintf(fp, "         dis_filter: ppc_dis_filter()\n");
	fprintf(fp, "           cmd_mach: ppc_cmd_mach()\n");
	fprintf(fp, "       get_smp_cpus: ppc_get_smp_cpus()\n");
        fprintf(fp, "          is_kvaddr: generic_is_kvaddr()\n");
        fprintf(fp, "          is_uvaddr: generic_is_uvaddr()\n");
        fprintf(fp, "      last_pgd_read: %lx\n", machdep->last_pgd_read);
        fprintf(fp, "      last_pmd_read: %lx\n", machdep->last_pmd_read);
        fprintf(fp, "     last_ptbl_read: %lx\n", machdep->last_ptbl_read);
        fprintf(fp, "                pgd: %lx\n", (ulong)machdep->pgd);
        fprintf(fp, "                pmd: %lx\n", (ulong)machdep->pmd);
        fprintf(fp, "               ptbl: %lx\n", (ulong)machdep->ptbl);
	fprintf(fp, "           machspec: %lx\n", (ulong)machdep->machspec);
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
ppc_uvtop(struct task_context *tc, ulong vaddr, ulong *paddr, int verbose)
{
	ulong mm, active_mm;
	ulong *pgd;
	ulong *page_dir;
	ulong *page_middle;
	ulong *page_table;
	ulong pgd_pte;
	ulong pte;

	if (!tc)
		error(FATAL, "current context invalid\n");

	*paddr = 0;

        if (is_kernel_thread(tc->task) && IS_KVADDR(vaddr)) { 
	    	if (VALID_OFFSET(thread_struct_pg_tables)) 
                	pgd = (ulong *)machdep->get_task_pgd(tc->task);
		else {
			if (OFFSET(task_struct_active_mm) < 0)
				error(FATAL, "no pg_tables or active_mm?\n");

                	readmem(tc->task + OFFSET(task_struct_active_mm), 
				KVADDR, &active_mm, sizeof(void *),
                        	"task active_mm contents", FAULT_ON_ERROR);

			if (!active_mm)
				error(FATAL, 
				     "no active_mm for this kernel thread\n");

			readmem(active_mm + OFFSET(mm_struct_pgd), 
				KVADDR, &pgd, sizeof(long), 
				"mm_struct pgd", FAULT_ON_ERROR);
		}
        } else {
                if ((mm = task_mm(tc->task, TRUE)))
                        pgd = ULONG_PTR(tt->mm_struct +
                                OFFSET(mm_struct_pgd));
                else
			readmem(tc->mm_struct + OFFSET(mm_struct_pgd), 
				KVADDR, &pgd, sizeof(long), "mm_struct pgd", 
				FAULT_ON_ERROR);
	}

	if (verbose) 
		fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);

	page_dir = pgd + (vaddr >> PGDIR_SHIFT);

	FILL_PGD(PAGEBASE(pgd), KVADDR, PAGESIZE());
	pgd_pte = ULONG(machdep->pgd + PAGEOFFSET(page_dir));

	if (verbose)
		fprintf(fp, "  PGD: %lx => %lx\n", (ulong)page_dir, pgd_pte);

	if (!pgd_pte)
		goto no_upage;

	page_middle = (ulong *)pgd_pte;

	page_table = page_middle + (BTOP(vaddr) & (PTRS_PER_PTE - 1));

	if (verbose)
		fprintf(fp, "  PMD: %lx => %lx\n",(ulong)page_middle, 
			(ulong)page_table);
	
        FILL_PTBL(PAGEBASE(page_table), KVADDR, PAGESIZE());
	pte = ULONG(machdep->ptbl + PAGEOFFSET(page_table));

        if (verbose) 
                fprintf(fp, "  PTE: %lx => %lx\n", (ulong)page_table, pte);

	if (!(pte & _PAGE_PRESENT)) {
		*paddr = pte;
		if (pte && verbose) {
			fprintf(fp, "\n");
			ppc_translate_pte(pte, 0);
		}
		goto no_upage;
	}

	if (!pte)
		goto no_upage;

	*paddr = PAGEBASE(pte) + PAGEOFFSET(vaddr);

        if (verbose) {
                fprintf(fp, " PAGE: %lx\n\n", PAGEBASE(pte));
		ppc_translate_pte(pte, 0);
	}

	return TRUE;

no_upage:
	return FALSE;
}

/*
 * Translates a kernel virtual address to its physical address.  cmd_vtop()
 * sets the verbose flag so that the pte translation gets displayed; all
 * other callers quietly accept the translation.
 */
static int
ppc_kvtop(struct task_context *tc, ulong kvaddr, ulong *paddr, int verbose)
{
	ulong *pgd;
	ulong *page_dir;
	ulong *page_middle;
	ulong *page_table;
        ulong pgd_pte;
        ulong pte;

	if (!IS_KVADDR(kvaddr))
		return FALSE;

	if (!vt->vmalloc_start) {
		*paddr = VTOP(kvaddr);
		return TRUE;
	}

	if (!IS_VMALLOC_ADDR(kvaddr)) { 
		*paddr = VTOP(kvaddr);
		if (!verbose)
			return TRUE;
	}

	pgd = (ulong *)vt->kernel_pgd;

	if (verbose) 
		fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);

	page_dir = pgd + (kvaddr >> PGDIR_SHIFT);

        FILL_PGD(PAGEBASE(pgd), KVADDR, PAGESIZE());
        pgd_pte = ULONG(machdep->pgd + PAGEOFFSET(page_dir));

	if (verbose)
		fprintf(fp, "  PGD: %lx => %lx\n", (ulong)page_dir, pgd_pte);

	if (!pgd_pte)
		goto no_kpage;

	page_middle = (ulong *)pgd_pte;

	page_table = page_middle + (BTOP(kvaddr) & (PTRS_PER_PTE-1));

	if (verbose)
		fprintf(fp, "  PMD: %lx => %lx\n", (ulong)page_middle, 
			(ulong)page_table);

        FILL_PTBL(PAGEBASE(page_table), KVADDR, PAGESIZE());
        pte = ULONG(machdep->ptbl + PAGEOFFSET(page_table));

	if (verbose) 
		fprintf(fp, "  PTE: %lx => %lx\n", (ulong)page_table, pte);

	if (!(pte & _PAGE_PRESENT)) { 
		if (pte && verbose) {
			fprintf(fp, "\n");
			ppc_translate_pte(pte, 0);
		}
		goto no_kpage;
	}

	if (verbose) {
		fprintf(fp, " PAGE: %lx\n\n", PAGEBASE(pte));
		ppc_translate_pte(pte, 0);
	}

	*paddr = PAGEBASE(pte) + PAGEOFFSET(kvaddr);

	return TRUE;

no_kpage:
	return FALSE;
}

/*
 *  Determine where vmalloc'd memory starts by looking at the first
 *  entry on the vmlist.
 */
static ulong
ppc_vmalloc_start(void)
{
	return (first_vmalloc_address());
}

/*
 *  PPC allows the idle_task to be non-page aligned, so we have to make
 *  an additional check through the idle_threads array.
 */
static int
ppc_is_task_addr(ulong task)
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
 *  According to kernel source, this should cover all the PPC variants out
 *  There, but since we can't test them all, YMMV.
 */
static ulong
ppc_processor_speed(void)
{
	ulong res, value, ppc_md, md_setup_res;
	ulong we_have_of, prep_setup_res;
	ulong node, type, name, properties;
	char str_buf[16];
	ulong len, mhz = 0;

	if (machdep->mhz)
		return(machdep->mhz);

	/* first, check if the have_of variable a) exists, and b) is TRUE */
	if(symbol_exists("have_of")) {
		get_symbol_data("have_of", sizeof(void *), &we_have_of);
	} else {
		we_have_of = 0;
	}

	if(we_have_of) {
		/* we have a machine with open firmware, so search the OF nodes 
		 * for cpu nodes.
		 * Too bad we can't call kernel helper functions here :)
		 */
		
		if(!symbol_exists("allnodes"))
			return (machdep->mhz = 0);
		
		get_symbol_data("allnodes", sizeof(void *), &node);
		while(node) {
			readmem(node+MEMBER_OFFSET("device_node", "type"),
				KVADDR, &type, sizeof(ulong), "node type",
				FAULT_ON_ERROR);
			
			if(type != 0) {
				len = read_string(type, str_buf, 
					sizeof(str_buf));

				if(len && (strcasecmp(str_buf, "cpu") == 0))
					break;
			}
			
			readmem(node+MEMBER_OFFSET("device_node", "allnext"),
				KVADDR, &node, sizeof(ulong), "node allnext",
				FAULT_ON_ERROR);
		}

		/* now, if we found a CPU node, get the speed property */
		if(node) {
			readmem(node+MEMBER_OFFSET("device_node", "properties"),
				KVADDR, &properties, sizeof(ulong), 
				"node properties", FAULT_ON_ERROR);
			
			while(properties) {
				readmem(properties+MEMBER_OFFSET("property", 
					"name"), KVADDR, &name, 
					sizeof(ulong), "property name",
					FAULT_ON_ERROR);
				
				len = read_string(name, str_buf, 
					sizeof(str_buf));

				if (len && (strcasecmp(str_buf, 
			            "clock-frequency") == 0)) {
					/* found the right cpu property */

					readmem(properties+
					    MEMBER_OFFSET("property", "value"),
					    KVADDR, &value, sizeof(ulong), 
					    "clock freqency pointer",
					    FAULT_ON_ERROR);
					readmem(value, KVADDR, &mhz, 
					    sizeof(ulong), 
					    "clock frequency value",
                                            FAULT_ON_ERROR);
					mhz /= 1000000;
					
					break;
				}
				/* keep looking */
				
				readmem(properties+
				    MEMBER_OFFSET("property", "next"),
				    KVADDR, &properties, sizeof(ulong), 
				    "property next", FAULT_ON_ERROR);
			}
			if(!properties) {
				/* didn't find the cpu speed for some reason */
				mhz = 0;
			}
		}
	} else {
		/* for machines w/o OF */
		/* untested, but in theory this should work on prep machines */

		if (symbol_exists("res")) {
			get_symbol_data("res", sizeof(void *), &res);
			
			if (symbol_exists("prep_setup_residual")) {
				get_symbol_data("prep_setup_residual", 
					sizeof(void *), &prep_setup_res);
				get_symbol_data("ppc_md", sizeof(void *), 
					&ppc_md);
				readmem(ppc_md + 
			 	    MEMBER_OFFSET("machdep_calls", 
				    "setup_residual"), KVADDR, &md_setup_res, 
				    sizeof(ulong), "ppc_md setup_residual",
				    FAULT_ON_ERROR);
				
				if(prep_setup_res == md_setup_res) {
				/* PREP machine */
					readmem(res+
					    MEMBER_OFFSET("RESIDUAL", 
					    "VitalProductData")+
					    MEMBER_OFFSET("VPD", "ProcessorHz"),
					    KVADDR, &mhz, sizeof(ulong), 
					    "res VitalProductData", 
					    FAULT_ON_ERROR);
					
					mhz = (mhz > 1024) ? mhz >> 20 : mhz;
				}
			}
			
			if(!mhz) {
			  /* everything else seems to do this the same way... */
				readmem(res + 
				    MEMBER_OFFSET("bd_info", "bi_intfreq"),
				    KVADDR, &mhz, sizeof(ulong), 
				    "bd_info bi_intfreq", FAULT_ON_ERROR);
				
				mhz /= 1000000;
			}
		}
		/* else...well, we don't have OF, or a residual structure, so
		 * just print unknown MHz
		 */
	}

	return (machdep->mhz = mhz);
}

/*
 *  Accept or reject a symbol from the kernel namelist.
 */
static int
ppc_verify_symbol(const char *name, ulong value)
{
	if (MCLXDEBUG(8) && name && strlen(name))
		fprintf(fp, "%08lx %s\n", value, name);

	if (STREQ(name, "_start"))
		machdep->flags |= KSYMS_START;

	return (name && strlen(name) && (machdep->flags & KSYMS_START) &&
	        !STREQ(name, "Letext"));
}


/*
 *  Get the relevant page directory pointer from a task structure.
 */
static ulong
ppc_get_task_pgd(ulong task)
{
	long offset;
	ulong pg_tables;

        offset = VALID_OFFSET(task_struct_thread) ?
                OFFSET(task_struct_thread) : OFFSET(task_struct_tss);

	if (OFFSET(thread_struct_pg_tables) < 0)
		error(FATAL, 
		   "pg_tables does not exist in this kernel's thread_struct\n"); 
	offset += OFFSET(thread_struct_pg_tables);

        readmem(task + offset, KVADDR, &pg_tables,
                sizeof(ulong), "task thread pg_tables", FAULT_ON_ERROR);

	return(pg_tables);
}

/*
 *  Translate a PTE, returning TRUE if the page is _PAGE_PRESENT.
 *  If a physaddr pointer is passed in, don't print anything.
 */
static int
ppc_translate_pte(ulong pte, ulong *physaddr)
{
	int c, len1, len2, len3, others, page_present;
	char buf[BUFSIZE];
        char buf2[BUFSIZE];
        char buf3[BUFSIZE];
	char ptebuf[BUFSIZE];
	char physbuf[BUFSIZE];
        char *arglist[MAXARGS];
	ulong paddr;

        paddr = PAGEBASE(pte);
	page_present = (pte & _PAGE_PRESENT);

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
		if (pte & _PAGE_PRESENT)
			fprintf(fp, "%sPRESENT", others++ ? "|" : "");
		if (pte & _PAGE_USER)
			fprintf(fp, "%sUSER", others++ ? "|" : "");
		if (pte & _PAGE_RW)
			fprintf(fp, "%sRW", others++ ? "|" : "");
		if (pte & _PAGE_GUARDED)
			fprintf(fp, "%sGUARDED", others++ ? "|" : "");
		if (pte & _PAGE_COHERENT)
			fprintf(fp, "%sCOHERENT", others++ ? "|" : "");
		if (pte & _PAGE_NO_CACHE)
			fprintf(fp, "%sNO_CACHE", others++ ? "|" : "");
		if (pte & _PAGE_WRITETHRU)
			fprintf(fp, "%sWRITETHRU", others++ ? "|" : "");
		if (pte & _PAGE_DIRTY)
			fprintf(fp, "%sDIRTY", others++ ? "|" : "");
		if (pte & _PAGE_ACCESSED)
			fprintf(fp, "%sACCESSED", others++ ? "|" : "");
		if (pte & _PAGE_HWWRITE)
			fprintf(fp, "%sHWWRITE", others++ ? "|" : "");
	} else
		fprintf(fp, "no mapping");

	fprintf(fp, ")\n");

	return page_present;
}

/*
 * Break out the swap type and offset from a pte.
 */

#define SWP_TYPE(entry) (((entry) >> 1) & 0x7f)
#define SWP_OFFSET(entry) ((entry) >> 8)

static ulong
ppc_SWP_TYPE(ulong pte)
{
        return SWP_TYPE(pte);
}

static ulong
ppc_SWP_OFFSET(ulong pte)
{
        return SWP_OFFSET(pte);
}

/*
 *  Look for likely exception frames in a stack.
 */

/* 
 *  This structure was copied from kernel source
 *  in include/asm-ppc/ptrace.h
 */
struct ppc_pt_regs {
        long gpr[32];
        long nip;
        long msr;
        long orig_gpr3;      /* Used for restarting system calls */
        long ctr;
        long link;
        long xer;
        long ccr;
        long mq;             /* 601 only (not used at present) */
                                /* Used on APUS to hold IPL value. */
        long trap;           /* Reason for being here */
        long dar;            /* Fault registers */
        long dsisr;
        long result;         /* Result of a system call */
};

static void 
ppc_eframe_search(struct bt_info *bt)
{
	error(FATAL, "ppc_eframe_search: function not written yet!\n");
}

/*
 *  Unroll a kernel stack.
 */
static void
ppc_back_trace_cmd(struct bt_info *bt)
{
	char buf[BUFSIZE];
	struct gnu_request *req;

        bt->flags |= BT_EXCEPTION_FRAME;

        if (MCLXDEBUG(1) || bt->debug)
                fprintf(fp, " => PC: %lx (%s) FP: %lx \n",
                        bt->instptr, value_to_symstr(bt->instptr, buf, 0),
			bt->stkptr);

        req = (struct gnu_request *)GETBUF(sizeof(struct gnu_request));
        req->command = GNU_STACK_TRACE;
        req->flags = GNU_RETURN_ON_ERROR;
        req->buf = GETBUF(BUFSIZE);
        req->debug = bt->debug;
        req->task = bt->task;

        req->pc = bt->instptr;
        req->sp = bt->stkptr;

        if (bt->flags & BT_USE_GDB) {
                strcpy(req->buf, "backtrace");
                gdb_interface(req);
        }
        else
                ppc_back_trace(req, bt);

        FREEBUF(req->buf);
        FREEBUF(req);
}

/*
 *  Unroll the kernel stack using a minimal amount of gdb services.
 */
static void
ppc_back_trace(struct gnu_request *req, struct bt_info *bt)
{
        int frame;
	int done;

        for (frame = 0, done = FALSE; !done && (frame < 100); frame++) {
		if ((req->name = closest_symbol(req->pc)) == NULL) {
			error(FATAL, 
			    "ppc_back_trace hit unknown symbol (%lx).\n",
				req->pc);
			req->ra = req->pc = 0;
			break;
		}

		bt->flags |= BT_SAVE_LASTSP;
		ppc_print_stack_entry(frame, req, req->pc, req->name, bt);
		bt->flags &= ~BT_SAVE_LASTSP;
		
		if (BT_REFERENCE_FOUND(bt))
			return;

		/* get the next sp and ip values */
		readmem(req->sp, KVADDR, &req->sp, sizeof(ulong),
			"stack frame", FAULT_ON_ERROR);

		/* an actual valid end of the back-chain! */
		if(req->sp == 0)
			break;

		if((req->sp - req->lastsp) >= sizeof(struct ppc_pt_regs)) {
			/* there might be an exception frame here... */
			ppc_exception_frame(req->lastsp, bt, req);
		} else if(!IS_KVADDR(req->sp) || (req->sp < req->lastsp)) {
			/* also possible one here... */
			ppc_exception_frame(req->lastsp, bt, req);
		}
		
		if (!INSTACK(req->sp, bt) || 
		    STREQ(req->name, "start_kernel"))
			break;

		readmem(req->sp+sizeof(long), KVADDR, &req->pc, sizeof(ulong),
			"instruction pointer", FAULT_ON_ERROR);
	}

	return;
}

/*
 *  print one entry of a stack trace
 */
static void 
ppc_print_stack_entry(int frame, 
		      struct gnu_request *req, 
		      ulong callpc, 	
		      char *name, 
		      struct bt_info *bt)
{
	if (BT_REFERENCE_CHECK(bt)) {
                switch (bt->ref->cmdflags & (BT_REF_SYMBOL|BT_REF_HEXVAL))
                {
                case BT_REF_SYMBOL:
                        if (STREQ(name, bt->ref->str)) 
                        	bt->ref->cmdflags |= BT_REF_FOUND;
                        break;

                case BT_REF_HEXVAL:
                        if (bt->ref->hexval == callpc) 
                                bt->ref->cmdflags |= BT_REF_FOUND;
                        break;
                }
	} else {
		fprintf(fp, "%s#%d [%lx] %s at %lx\n",
        		frame < 10 ? " " : "", frame,
                	req->sp, name, callpc);
	}

	if (bt->flags & BT_SAVE_LASTSP)
		req->lastsp = req->sp;

	if (bt->flags & BT_LINE_NUMBERS)
		ppc_dump_line_number(callpc);
}

/*
 *  Print exception frame information for PowerPC
 */
static void
ppc_exception_frame(ulong addr, struct bt_info *bt, struct gnu_request *req)
{
	int i;
	struct ppc_pt_regs regs;
	
	if (BT_REFERENCE_CHECK(bt))
		return;

	readmem(addr+16, KVADDR, &regs, sizeof(regs),
		"exception frame", FAULT_ON_ERROR);
	
	switch(regs.trap) {
	case 0x200:
		fprintf(fp, "machine check");
		break;
	case 0x300:
		fprintf(fp, "address error (store)");
		break;
	case 0x400:
		fprintf(fp, "instruction bus error");
		break;
	case 0x500:
		fprintf(fp, "interrupt");
		break;
	case 0x600:
		fprintf(fp, "alingment");
		break;
	case 0x700:
		fprintf(fp, "breakpoint trap");
		break;
	case 0x800:
		fprintf(fp, "fpu unavailable");
		break;
	case 0x900:
		fprintf(fp, "decrementer");
		break;
	case 0xa00:
		fprintf(fp, "reserved");
		break;
	case 0xb00:
		fprintf(fp, "reserved");
		break;
	case 0xc00:
		fprintf(fp, "syscall");
		break;
	case 0xd00:
		fprintf(fp, "single-step/watch");
		break;
	case 0xe00:
		fprintf(fp, "fp assist");
		break;
	default: /* back trace ended, but no exception frame exists */
		return;
	}

	fprintf(fp, " [%lx] exception frame:", regs.trap);

	/* print out the gprs... */
	for(i=0; i<32; i++) {
		if(!(i % 4))
			fprintf(fp, "\n");

		fprintf(fp, "R%d:%s %08lx   ", i,
			((i < 10) ? " " : ""), regs.gpr[i]);
	}

	fprintf(fp, "\n");

	/* print out the rest of the registers */
	fprintf(fp, "NIP: %08lx   ", regs.nip);
	fprintf(fp, "MSR: %08lx   ", regs.msr);
	fprintf(fp, "OR3: %08lx   ", regs.orig_gpr3);
	fprintf(fp, "CTR: %08lx\n", regs.ctr);

	fprintf(fp, "LR:  %08lx   ", regs.link);
	fprintf(fp, "XER: %08lx   ", regs.xer);
	fprintf(fp, "CCR: %08lx   ", regs.ccr);
	fprintf(fp, "MQ:  %08lx\n", regs.mq);
	fprintf(fp, "DAR: %08lx ", regs.dar);
	fprintf(fp, "DSISR: %08lx ", regs.dsisr);
	fprintf(fp, "       Syscall Result: %08lx\n", regs.result);
}

/*
 *  Get a stack frame combination of pc and ra from the most relevent spot.
 */
static void
ppc_get_stack_frame(struct bt_info *bt, ulong *pcp, ulong *spp)
{
	if (pcp)
		*pcp = ppc_get_pc(bt);
	if (spp)
		*spp = ppc_get_sp(bt);
}


/*
 *  Get the saved ESP from a user-space copy of the kernel stack.
 */
static ulong
ppc_get_sp(struct bt_info *bt)
{
        ulong sp;

        get_ppc_frame(bt, NULL, &sp);

        return sp;
}

/*
 *  Get the saved PC from a user-space copy of the kernel stack.
 */
static ulong
ppc_get_pc(struct bt_info *bt)
{
	struct syment *sp;
	ulong ip;

	if (DUMPFILE() && is_task_active(bt->task)) {
		if (!(sp = next_symbol("crash_save_current_state", NULL)))
			return (symbol_value("crash_save_current_state")+16);
		else
			return (sp->value - 4);
	}
	get_ppc_frame(bt, &ip, NULL);

	return ip;
}

/*
 *  Do the work for ppc_get_sp() and ppc_get_pc().
 */
static void
get_ppc_frame(struct bt_info *bt, ulong *getpc, ulong *getsp)
{
	ulong ip;
	ulong sp;
	ulong offset;
	ulong *stack;
	ulong task;

	task = bt->task;
	stack = (ulong *)bt->stackbuf;

        if (OFFSET(task_struct_tss_ksp) > 0) 
                sp = stack[OFFSET(task_struct_tss_ksp)/sizeof(long)];
	else 
                sp = stack[OFFSET(task_struct_thread_ksp)/sizeof(long)];

	/* 
	 *  get the offset to the first pointer in the stack frame
	 *  linked list.  here is a small picture:
	 *
	 *    ksp            
	 * >c73e9d30:  c73e9d50 c007efbc 00000000 00000008
	 *             ^^^^^^^^ = Pointer to first stack frame.
	 *  c73e9d40:  c0742000 00000000 c02071e0 c73e9d50
	 * >c73e9d50:  c73e9d80 c0013928 c73e8000 c73e9d60
	 *             ^^^^^^^^ ^^^^^^^^ Pointer to return function
	 *                |              (LR save word)
	 *                 \-----------> Pointer to next stack frame
	 *  c73e9d60:  c73e9d80 c73e9e10 c01e0000 00000007
	 *  c73e9d70:  00000000 00000000 7fffffff c73e9d80
	 */

	offset = (stack[(sp-task)/sizeof(long)]-task)/sizeof(long);

	sp = stack[offset];
	ip = stack[(sp - task)/sizeof(long)+1]; 

	if (DUMPFILE() && getsp && STREQ(closest_symbol(sp), "panic")) {
		*getsp = sp;
		return;
	}

	if (getsp)
		*getsp = sp;
	if (getpc)
		*getpc = ip;

}

/*
 *  Do the work for cmd_irq().
 */
static void ppc_dump_irq(int irq)
{
	struct datatype_member datatype_member, *dm;
        ulong irq_desc_addr, addr;
        char *buf;
        int level, others;
        ulong action, ctl, value;
	char typename[32];

        dm = &datatype_member;
        buf = GETBUF(pc->sym_maxline);

        irq_desc_addr = symbol_value("irq_desc") + (SIZE(irqdesc) * irq);
	
	readmem(irq_desc_addr + OFFSET(irqdesc_level), KVADDR, &level,
                sizeof(int), "irq_desc entry", FAULT_ON_ERROR);
        readmem(irq_desc_addr + OFFSET(irqdesc_action), KVADDR, &action,
                sizeof(long), "irq_desc entry", FAULT_ON_ERROR);
        readmem(irq_desc_addr + OFFSET(irqdesc_ctl), KVADDR, &ctl,
                sizeof(long), "irq_desc entry", FAULT_ON_ERROR);

	fprintf(fp, "    IRQ: %d\n", irq);
	fprintf(fp, " STATUS: 0\n");
        fprintf(fp, "HANDLER: ");
	
	if (value_symbol(ctl)) {
                fprintf(fp, "%lx  ", ctl);
                pad_line(fp, VADDR_PRLEN == 8 ? 
			VADDR_PRLEN+2 : VADDR_PRLEN-6, ' ');
                fprintf(fp, "<%s>\n", value_symbol(ctl));
	} else
		fprintf(fp, "%lx\n", ctl);

	if(ctl) {
		/* typename */
		readmem(ctl + OFFSET(hw_interrupt_type_typename), KVADDR, &addr,
			sizeof(ulong), "typename pointer", FAULT_ON_ERROR);
		read_string(addr, typename, 32);
		
		if(typename)
			fprintf(fp, "         typename: %08lx  \"%s\"\n", 
				addr, typename);
		
		/* startup...I think this is always 0 */
		readmem(ctl + OFFSET(hw_interrupt_type_startup), KVADDR, &addr,
			sizeof(ulong), "interrupt startup", FAULT_ON_ERROR);
		fprintf(fp, "          startup: ");
		if(value_symbol(addr)) {
			fprintf(fp, "%08lx  <%s>\n", addr, value_symbol(addr));
		} else
			fprintf(fp, "%lx\n", addr);
		
		/* shutdown...I think this is always 0 */
		readmem(ctl + OFFSET(hw_interrupt_type_shutdown), KVADDR, &addr,
			sizeof(ulong), "interrupt shutdown", FAULT_ON_ERROR);
		fprintf(fp, "         shutdown: ");
		if(value_symbol(addr)) {
			fprintf(fp, "%08lx  <%s>\n", addr, value_symbol(addr));
		} else
			fprintf(fp, "%lx\n", addr);

		if (VALID_OFFSET(hw_interrupt_type_handle)) {
	                /* handle */
	                readmem(ctl + OFFSET(hw_interrupt_type_handle), 
				KVADDR, &addr, sizeof(ulong), 
				"interrupt handle", FAULT_ON_ERROR);
	                fprintf(fp, "           handle: ");
	                if(value_symbol(addr)) {
	                        fprintf(fp, "%08lx  <%s>\n", addr, 
					value_symbol(addr));
	                } else
	                        fprintf(fp, "%lx\n", addr);
		}
		
		/* enable/disable */
		readmem(ctl + OFFSET(hw_interrupt_type_enable), KVADDR, &addr,
			sizeof(ulong), "interrupt enable", FAULT_ON_ERROR);
		fprintf(fp, "           enable: ");
		if(value_symbol(addr)) {
			fprintf(fp, "%08lx  <%s>\n", addr, value_symbol(addr));
		} else
			fprintf(fp, "%lx\n", addr);
		
		readmem(ctl + OFFSET(hw_interrupt_type_disable), KVADDR, &addr,
			sizeof(ulong), "interrupt disable", FAULT_ON_ERROR);
		fprintf(fp, "          disable: ");
		if(value_symbol(addr)) {
			fprintf(fp, "%08lx  <%s>\n", addr, value_symbol(addr));
		} else
			fprintf(fp, "0\n");
	}

	/* next, the action... and its submembers */	
	if(!action)
		fprintf(fp, " ACTION: (none)\n");

	while(action) {
		fprintf(fp, " ACTION: %08lx\n", action);

		/* handler */
		readmem(action + OFFSET(irqaction_handler), KVADDR, &addr,
			sizeof(ulong), "action handler", FAULT_ON_ERROR);
		fprintf(fp, "          handler: ");
		if(value_symbol(addr)) {
			fprintf(fp, "%08lx  <%s>\n", addr, value_symbol(addr));
		} else
			fprintf(fp, "0\n");

		/* flags */
		readmem(action + OFFSET(irqaction_flags), KVADDR, &value,
			sizeof(ulong), "action flags", FAULT_ON_ERROR);
		fprintf(fp, "            flags: %lx  ", value);

		if (value) {
			others = 0;
			fprintf(fp, "(");

			if (value & SA_INTERRUPT)
				fprintf(fp,
					"%sSA_INTERRUPT",
					others++ ? "|" : "");
			if (value & SA_PROBE)
				fprintf(fp,
					"%sSA_PROBE",
					others++ ? "|" : "");
			if (value & SA_SAMPLE_RANDOM)
				fprintf(fp,
					"%sSA_SAMPLE_RANDOM",
					others++ ? "|" : "");
			if (value & SA_SHIRQ)
				fprintf(fp,
					"%sSA_SHIRQ",
					others++ ? "|" : "");
			fprintf(fp, ")");
			if (value & ~ACTION_FLAGS) {
				fprintf(fp,
					"  (bits %lx not translated)",
					value & ~ACTION_FLAGS);
			}
		}

		fprintf(fp, "\n");

		/* mask */
		readmem(action + OFFSET(irqaction_mask), KVADDR, &value,
			sizeof(ulong), "action mask", FAULT_ON_ERROR);
		fprintf(fp, "             mask: %lx\n", value);

		/* name */
		readmem(action + OFFSET(irqaction_name), KVADDR, &addr,
			sizeof(ulong), "action name", FAULT_ON_ERROR);
		read_string(addr, typename, 32);
		
		if(typename)
			fprintf(fp, "             name: %08lx  \"%s\"\n", 
				addr, typename);

		/* dev_id */
		readmem(action + OFFSET(irqaction_dev_id), KVADDR, &value,
			sizeof(ulong), "action dev_id", FAULT_ON_ERROR);
		fprintf(fp, "           dev_id: %08lx\n", value);

		/* next */
		readmem(action + OFFSET(irqaction_next), KVADDR, &value,
			sizeof(ulong), "action next", FAULT_ON_ERROR);
		fprintf(fp, "             next: %lx\n", value);

		/* keep going if there are chained interrupts */
		action = value;
	}

	fprintf(fp, "  DEPTH: %x\n\n", level);
}

/*
 *  Return the number of IRQs on this platform.
 */
static int 
ppc_nr_irqs(void)
{
        int nr_irqs;

        if (symbol_exists("irq_desc"))
		nr_irqs = get_array_length("irq_desc", NULL);
	else
	        error(FATAL, "cannot determine number of IRQs\n");

	return nr_irqs;
}

/*
 *  Filter disassembly output if the output radix is not gdb's default 10
 */
static int 
ppc_dis_filter(ulong vaddr, char *inbuf)
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
 *  (on alpha -- not necessarily seen on ppc) so this routine both fixes the 
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
ppc_get_smp_cpus(void)
{
        return kt->cpus;
}

/*
 *  Machine dependent command.
 */
void
ppc_cmd_mach(void)
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

	ppc_display_machine_stats();
}

/*
 *  "mach" command output.
 */
static void
ppc_display_machine_stats(void)
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
        fprintf(fp, "      L1 CACHE SIZE: %d\n", l1_cache_size());
        fprintf(fp, "KERNEL VIRTUAL BASE: %lx\n", machdep->kvbase);
        fprintf(fp, "KERNEL VMALLOC BASE: %lx\n", vt->vmalloc_start);
        fprintf(fp, "  KERNEL STACK SIZE: %ld\n", STACKSIZE());
}

static void
ppc_dump_line_number(ulong callpc)
{
        int retries;
        char buf[BUFSIZE], *p;
        char *name;

        name = closest_symbol(callpc);

        /*
         *  gdb-related kludge for routines in entry.S, head.S and initfunc
         *  (fix this...)
         */
        if (STREQ(name, "DoSyscall") ||
            STREQ(name, "_switch") ||
            STREQ(name, "fake_interrupt") ||
            STREQ(name, "ret_from_syscall_2") ||
            STREQ(name, "ret_from_fork") ||
            STREQ(name, "ret_from_intercept") ||
            STREQ(name, "ret_from_except") ||
            STREQ(name, "lost_irq_ret") ||
            STREQ(name, "do_bottom_half_ret") ||
            STREQ(name, "ret_to_user_hook") ||
            STREQ(name, "do_signal_ret") ||
            STREQ(name, "restore") ||
            STREQ(name, "signal_return") ||
            STREQ(name, "ret_from_syscall_1")) {
                fprintf(fp, "    %s/arch/ppc/kernel/entry.S\n",
                        get_build_directory(buf) ? buf : "..");
                return;
        }
        if (STREQ(name, "set_context")) {
                fprintf(fp, "    %s/arch/ppc/kernel/head.S\n",
                        get_build_directory(buf) ? buf : "..");
                return;
        }

        retries = 0;

try_closest:
        get_line_number(callpc, buf, FALSE);

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
                        callpc = closest_symbol_value(callpc);
                        goto try_closest;
                }
        }
}
#endif /* PPC */
