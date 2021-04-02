/* x86_64.c -- core analysis suite
 *
 * Copyright (C) 2004, 2005 David Anderson
 * Copyright (C) 2004, 2005 Red Hat, Inc. All rights reserved.
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
#include "defs.h"

#ifdef X86_64

static int x86_64_kvtop(struct task_context *, ulong, physaddr_t *, int);
static int x86_64_kvtop_xen_wpt(struct task_context *, ulong, physaddr_t *, int);
static int x86_64_uvtop(struct task_context *, ulong, physaddr_t *, int);
static int x86_64_uvtop_level4(struct task_context *, ulong, physaddr_t *, int);
static int x86_64_uvtop_level4_xen_wpt(struct task_context *, ulong, physaddr_t *, int);
static ulong x86_64_vmalloc_start(void);
static int x86_64_is_task_addr(ulong);
static int x86_64_verify_symbol(const char *, ulong, char);
static ulong x86_64_get_task_pgd(ulong);
static int x86_64_translate_pte(ulong, void *, ulonglong);
static ulong x86_64_processor_speed(void);
static int x86_64_eframe_search(struct bt_info *);
static int x86_64_eframe_verify(struct bt_info *, long, long, long, long, long, long);
static long x86_64_exception_frame(ulong,ulong,char *,struct bt_info *, FILE *);
#define EFRAME_PRINT  (0x1)
#define EFRAME_VERIFY (0x2)
#define EFRAME_CS     (0x4)
#define EFRAME_SEARCH (0x8)
static int x86_64_print_eframe_location(ulong, int, FILE *);
static void x86_64_back_trace_cmd(struct bt_info *);
static ulong x86_64_in_exception_stack(struct bt_info *);
static ulong x86_64_in_irqstack(struct bt_info *);
static void x86_64_low_budget_back_trace_cmd(struct bt_info *);
static void x86_64_get_dumpfile_stack_frame(struct bt_info *, ulong *, ulong *);
static struct syment *x86_64_function_called_by(ulong);
static int is_direct_call_target(struct bt_info *);
static void get_x86_64_frame(struct bt_info *, ulong *, ulong *);
static int x86_64_print_stack_entry(struct bt_info *, FILE *, int, int, ulong);
static void x86_64_display_full_frame(struct bt_info *, ulong, FILE *);
static void x86_64_do_bt_reference_check(struct bt_info *, ulong,char *);
static void x86_64_dump_irq(int);
static char *x86_64_extract_idt_function(ulong *, char *, ulong *);
static ulong x86_64_get_pc(struct bt_info *);
static ulong x86_64_get_sp(struct bt_info *);
static void x86_64_get_stack_frame(struct bt_info *, ulong *, ulong *);
static int x86_64_dis_filter(ulong, char *);
static void x86_64_cmd_mach(void);
static int x86_64_get_smp_cpus(void);
static void x86_64_display_machine_stats(void);
static void x86_64_display_cpu_data(void);
static void x86_64_display_memmap(void);
static void x86_64_dump_line_number(ulong);
static struct line_number_hook x86_64_line_number_hooks[];
static void x86_64_calc_phys_base(void);
static int x86_64_is_module_addr(ulong);
static int x86_64_is_kvaddr(ulong);
static int x86_64_is_uvaddr(ulong, struct task_context *);
void x86_64_compiler_warning_stub(void);
static void x86_64_init_kernel_pgd(void);
static void x86_64_cpu_pda_init(void);
static void x86_64_ist_init(void);
static void x86_64_post_init(void);
static void parse_cmdline_arg(void);
static void x86_64_clear_machdep_cache(void);
static int x86_64_xendump_p2m_create(struct xendump_data *);
static char *x86_64_xendump_load_page(ulong, struct xendump_data *);
static int x86_64_xendump_page_index(ulong, struct xendump_data *);
static int x86_64_xen_kdump_p2m_create(struct xen_kdump_data *);
static char *x86_64_xen_kdump_load_page(ulong, char *);
static ulong x86_64_xen_kdump_page_mfn(ulong);
static void x86_64_debug_dump_page(FILE *, char *, char *);
static void x86_64_get_xendump_regs(struct xendump_data *, struct bt_info *, ulong *, ulong *);
static ulong x86_64_xendump_panic_task(struct xendump_data *);

struct machine_specific x86_64_machine_specific = { 0 };

/*
 *  Do all necessary machine-specific setup here.  This is called several
 *  times during initialization.
 */
void
x86_64_init(int when)
{
	switch (when)
	{
	case PRE_SYMTAB:
		machdep->verify_symbol = x86_64_verify_symbol;
                machdep->machspec = &x86_64_machine_specific;
                if (pc->flags & KERNEL_DEBUG_QUERY)
                        return;
                machdep->pagesize = memory_page_size();
                machdep->pageshift = ffs(machdep->pagesize) - 1;
                machdep->pageoffset = machdep->pagesize - 1;
                machdep->pagemask = ~((ulonglong)machdep->pageoffset);
		machdep->stacksize = machdep->pagesize * 2;
                if ((machdep->machspec->upml = (char *)malloc(PAGESIZE())) == NULL)
                        error(FATAL, "cannot malloc upml space.");
                if ((machdep->pgd = (char *)malloc(PAGESIZE())) == NULL)
                        error(FATAL, "cannot malloc pgd space.");
                if ((machdep->pmd = (char *)malloc(PAGESIZE())) == NULL)
                        error(FATAL, "cannot malloc pmd space.");
                if ((machdep->ptbl = (char *)malloc(PAGESIZE())) == NULL)
                        error(FATAL, "cannot malloc ptbl space.");
		if ((machdep->machspec->pml4 = 
			(char *)malloc(PAGESIZE()*2)) == NULL)
                        error(FATAL, "cannot malloc pml4 space.");
                machdep->machspec->last_upml_read = 0;
                machdep->machspec->last_pml4_read = 0;
                machdep->last_pgd_read = 0;
                machdep->last_pmd_read = 0;
                machdep->last_ptbl_read = 0;
		machdep->verify_paddr = generic_verify_paddr;
		machdep->ptrs_per_pgd = PTRS_PER_PGD;
		machdep->flags |= MACHDEP_BT_TEXT;
                if (machdep->cmdline_arg)
                        parse_cmdline_arg();
		break;

	case PRE_GDB:
		if (!(machdep->flags & (VM_ORIG|VM_2_6_11|VM_XEN))) {
			if (symbol_exists("boot_vmalloc_pgt"))
				machdep->flags |= VM_ORIG;
			else if (symbol_exists("xen_start_info"))
				machdep->flags |= VM_XEN;
			else
				machdep->flags |= VM_2_6_11;
		}

		switch (machdep->flags & (VM_ORIG|VM_2_6_11|VM_XEN)) 
		{
		case VM_ORIG:
		        /* pre-2.6.11 layout */
                        machdep->machspec->userspace_top = USERSPACE_TOP_ORIG;
                        machdep->machspec->page_offset = PAGE_OFFSET_ORIG;
                        machdep->machspec->vmalloc_start_addr = VMALLOC_START_ADDR_ORIG;
                        machdep->machspec->vmalloc_end = VMALLOC_END_ORIG;
                        machdep->machspec->modules_vaddr = MODULES_VADDR_ORIG;
                        machdep->machspec->modules_end = MODULES_END_ORIG;

			free(machdep->machspec->upml);
			machdep->machspec->upml = NULL;

	        	machdep->uvtop = x86_64_uvtop;
			break;
		
		case VM_2_6_11:
			/* 2.6.11 layout */
			machdep->machspec->userspace_top = USERSPACE_TOP_2_6_11;
			machdep->machspec->page_offset = PAGE_OFFSET_2_6_11;
			machdep->machspec->vmalloc_start_addr = VMALLOC_START_ADDR_2_6_11;
			machdep->machspec->vmalloc_end = VMALLOC_END_2_6_11;
			machdep->machspec->modules_vaddr = MODULES_VADDR_2_6_11;
			machdep->machspec->modules_end = MODULES_END_2_6_11;

	        	machdep->uvtop = x86_64_uvtop_level4;
			break;

                case VM_XEN:
                        /* Xen layout */
                        machdep->machspec->userspace_top = USERSPACE_TOP_XEN;
                        machdep->machspec->page_offset = PAGE_OFFSET_XEN;
                        machdep->machspec->vmalloc_start_addr = VMALLOC_START_ADDR_XEN;
                        machdep->machspec->vmalloc_end = VMALLOC_END_XEN;
                        machdep->machspec->modules_vaddr = MODULES_VADDR_XEN;
                        machdep->machspec->modules_end = MODULES_END_XEN;
                        break;
		}
	        machdep->kvbase = (ulong)PAGE_OFFSET;
		machdep->identity_map_base = (ulong)PAGE_OFFSET;
                machdep->is_kvaddr = x86_64_is_kvaddr;
                machdep->is_uvaddr = x86_64_is_uvaddr;
	        machdep->eframe_search = x86_64_eframe_search;
	        machdep->back_trace = x86_64_low_budget_back_trace_cmd;
	        machdep->processor_speed = x86_64_processor_speed;
	        machdep->kvtop = x86_64_kvtop;
	        machdep->get_task_pgd = x86_64_get_task_pgd;
		machdep->get_stack_frame = x86_64_get_stack_frame;
		machdep->get_stackbase = generic_get_stackbase;
		machdep->get_stacktop = generic_get_stacktop;
		machdep->translate_pte = x86_64_translate_pte;
		machdep->memory_size = generic_memory_size;
		machdep->is_task_addr = x86_64_is_task_addr;
		machdep->dis_filter = x86_64_dis_filter;
		machdep->cmd_mach = x86_64_cmd_mach;
		machdep->get_smp_cpus = x86_64_get_smp_cpus;
		machdep->line_number_hooks = x86_64_line_number_hooks;
		machdep->value_to_symbol = generic_machdep_value_to_symbol;
		machdep->init_kernel_pgd = x86_64_init_kernel_pgd;
		machdep->clear_machdep_cache = x86_64_clear_machdep_cache;
		machdep->xendump_p2m_create = x86_64_xendump_p2m_create;
		machdep->get_xendump_regs = x86_64_get_xendump_regs;
		machdep->xen_kdump_p2m_create = x86_64_xen_kdump_p2m_create;
		machdep->xendump_panic_task = x86_64_xendump_panic_task;
		x86_64_calc_phys_base();
		break;

	case POST_GDB:
                STRUCT_SIZE_INIT(cpuinfo_x86, "cpuinfo_x86");
		STRUCT_SIZE_INIT(gate_struct, "gate_struct");
                STRUCT_SIZE_INIT(e820map, "e820map");
                STRUCT_SIZE_INIT(e820entry, "e820entry");
                MEMBER_OFFSET_INIT(e820map_nr_map, "e820map", "nr_map");
                MEMBER_OFFSET_INIT(e820entry_addr, "e820entry", "addr");
                MEMBER_OFFSET_INIT(e820entry_size, "e820entry", "size");
                MEMBER_OFFSET_INIT(e820entry_type, "e820entry", "type");
		MEMBER_OFFSET_INIT(thread_struct_rip, "thread_struct", "rip");
		MEMBER_OFFSET_INIT(thread_struct_rsp, "thread_struct", "rsp");
		MEMBER_OFFSET_INIT(thread_struct_rsp0, "thread_struct", "rsp0");
		STRUCT_SIZE_INIT(tss_struct, "tss_struct");
		MEMBER_OFFSET_INIT(tss_struct_ist, "tss_struct", "ist");
		MEMBER_OFFSET_INIT(user_regs_struct_rip,
			"user_regs_struct", "rip");
		MEMBER_OFFSET_INIT(user_regs_struct_rsp,
			"user_regs_struct", "rsp");
		MEMBER_OFFSET_INIT(user_regs_struct_eflags,
			"user_regs_struct", "eflags");
		MEMBER_OFFSET_INIT(user_regs_struct_cs,
			"user_regs_struct", "cs");
		MEMBER_OFFSET_INIT(user_regs_struct_ss,
			"user_regs_struct", "ss");
		STRUCT_SIZE_INIT(user_regs_struct, "user_regs_struct");
		x86_64_cpu_pda_init();
		x86_64_ist_init();
                if ((machdep->machspec->irqstack = (char *)
		    malloc(machdep->machspec->stkinfo.isize)) == NULL)
                        error(FATAL, "cannot malloc irqstack space.");
               if (symbol_exists("irq_desc"))
                        ARRAY_LENGTH_INIT(machdep->nr_irqs, irq_desc,
                                "irq_desc", NULL, 0);
                else
                        machdep->nr_irqs = 224;  /* NR_IRQS (at least) */
		machdep->vmalloc_start = x86_64_vmalloc_start;
		machdep->dump_irq = x86_64_dump_irq;
		if (!machdep->hz) {
			machdep->hz = HZ;
			if (THIS_KERNEL_VERSION >= LINUX(2,6,0))
				machdep->hz = 1000;
		}
		machdep->section_size_bits = _SECTION_SIZE_BITS;
		machdep->max_physmem_bits = _MAX_PHYSMEM_BITS;
                if (XEN()) {
			if (kt->xen_flags & WRITABLE_PAGE_TABLES)
                        	machdep->uvtop = x86_64_uvtop_level4_xen_wpt;
			else
                        	machdep->uvtop = x86_64_uvtop_level4;
                        MEMBER_OFFSET_INIT(vcpu_guest_context_user_regs,
                                "vcpu_guest_context", "user_regs");
			ASSIGN_OFFSET(cpu_user_regs_rsp) = 
				MEMBER_OFFSET("cpu_user_regs", "ss") - sizeof(ulong);
			ASSIGN_OFFSET(cpu_user_regs_rip) = 
				MEMBER_OFFSET("cpu_user_regs", "cs") - sizeof(ulong);
                }
		break;

	case POST_INIT:
		x86_64_post_init();
		break;
	}
}

void
x86_64_dump_machdep_table(ulong arg)
{
	int c, i, cpus;
        int others; 
        struct machine_specific *ms;

        ms = machdep->machspec;
 
        others = 0;
        fprintf(fp, "              flags: %lx (", machdep->flags);
	if (machdep->flags & KSYMS_START)
		fprintf(fp, "%sKSYMS_START", others++ ? "|" : "");
	if (machdep->flags & PT_REGS_INIT)
		fprintf(fp, "%sPT_REGS_INIT", others++ ? "|" : "");
	if (machdep->flags & MACHDEP_BT_TEXT)
		fprintf(fp, "%sMACHDEP_BT_TEXT", others++ ? "|" : "");
	if (machdep->flags & VM_ORIG)
		fprintf(fp, "%sVM_ORIG", others++ ? "|" : "");
	if (machdep->flags & VM_2_6_11)
		fprintf(fp, "%sVM_2_6_11", others++ ? "|" : "");
	if (machdep->flags & VM_XEN)
		fprintf(fp, "%sVM_XEN", others++ ? "|" : "");
	if (machdep->flags & NO_TSS)
		fprintf(fp, "%sNO_TSS", others++ ? "|" : "");
	if (machdep->flags & SCHED_TEXT)
		fprintf(fp, "%sSCHED_TEXT", others++ ? "|" : "");
	if (machdep->flags & PHYS_BASE)
		fprintf(fp, "%sPHYS_BASE", others++ ? "|" : "");
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
        fprintf(fp, "            memsize: %llu (0x%llx)\n", 
		(ulonglong)machdep->memsize, (ulonglong)machdep->memsize);
	fprintf(fp, "               bits: %d\n", machdep->bits);
	fprintf(fp, "            nr_irqs: %d\n", machdep->nr_irqs);
        fprintf(fp, "      eframe_search: x86_64_eframe_search()\n");
	if (machdep->back_trace == x86_64_back_trace_cmd)
        	fprintf(fp, "         back_trace: x86_64_back_trace_cmd()\n");
	else if (machdep->back_trace == x86_64_low_budget_back_trace_cmd)
        	fprintf(fp, 
		   "         back_trace: x86_64_low_budget_back_trace_cmd()\n");
	else
		fprintf(fp, "         back_trace: %lx\n",
			(ulong)machdep->back_trace);
        fprintf(fp, "    processor_speed: x86_64_processor_speed()\n");
	if (machdep->uvtop == x86_64_uvtop)
        	fprintf(fp, "              uvtop: x86_64_uvtop()\n");
	else if (machdep->uvtop == x86_64_uvtop_level4)
        	fprintf(fp, "              uvtop: x86_64_uvtop_level4()\n");
	else if (machdep->uvtop == x86_64_uvtop_level4_xen_wpt)
        	fprintf(fp, "              uvtop: x86_64_uvtop_level4_xen_wpt()\n");
	else
        	fprintf(fp, "              uvtop: %lx\n", (ulong)machdep->uvtop);
        fprintf(fp, "              kvtop: x86_64_kvtop()\n");
        fprintf(fp, "       get_task_pgd: x86_64_get_task_pgd()\n");
	fprintf(fp, "           dump_irq: x86_64_dump_irq()\n");
        fprintf(fp, "    get_stack_frame: x86_64_get_stack_frame()\n");
        fprintf(fp, "      get_stackbase: generic_get_stackbase()\n");
        fprintf(fp, "       get_stacktop: generic_get_stacktop()\n");
        fprintf(fp, "      translate_pte: x86_64_translate_pte()\n");
	fprintf(fp, "        memory_size: generic_memory_size()\n");
	fprintf(fp, "      vmalloc_start: x86_64_vmalloc_start()\n");
	fprintf(fp, "       is_task_addr: x86_64_is_task_addr()\n");
	fprintf(fp, "      verify_symbol: x86_64_verify_symbol()\n");
	fprintf(fp, "         dis_filter: x86_64_dis_filter()\n");
	fprintf(fp, "           cmd_mach: x86_64_cmd_mach()\n");
	fprintf(fp, "       get_smp_cpus: x86_64_get_smp_cpus()\n");
        fprintf(fp, "          is_kvaddr: x86_64_is_kvaddr()\n");
        fprintf(fp, "          is_uvaddr: x86_64_is_uvaddr()\n");
        fprintf(fp, "       verify_paddr: generic_verify_paddr()\n");
        fprintf(fp, "    init_kernel_pgd: x86_64_init_kernel_pgd()\n");
        fprintf(fp, "clear_machdep_cache: x86_64_clear_machdep_cache()\n");
	fprintf(fp, " xendump_p2m_create: x86_64_xendump_p2m_create()\n");
	fprintf(fp, "   get_xendump_regs: x86_64_get_xendump_regs()\n");
	fprintf(fp, " xendump_panic_task: x86_64_xendump_panic_task()\n");
	fprintf(fp, "xen_kdump_p2m_create: x86_64_xen_kdump_p2m_create()\n");
        fprintf(fp, "  line_number_hooks: x86_64_line_number_hooks\n");
        fprintf(fp, "    value_to_symbol: generic_machdep_value_to_symbol()\n");
        fprintf(fp, "      last_pgd_read: %lx\n", machdep->last_pgd_read);
        fprintf(fp, "      last_pmd_read: %lx\n", machdep->last_pmd_read);
        fprintf(fp, "     last_ptbl_read: %lx\n", machdep->last_ptbl_read);
        fprintf(fp, "                pgd: %lx\n", (ulong)machdep->pgd);
        fprintf(fp, "                pmd: %lx\n", (ulong)machdep->pmd);
        fprintf(fp, "               ptbl: %lx\n", (ulong)machdep->ptbl);
	fprintf(fp, "       ptrs_per_pgd: %d\n", machdep->ptrs_per_pgd);
	fprintf(fp, "  section_size_bits: %ld\n", machdep->section_size_bits);
        fprintf(fp, "   max_physmem_bits: %ld\n", machdep->max_physmem_bits);
        fprintf(fp, "  sections_per_root: %ld\n", machdep->sections_per_root);

	fprintf(fp, "           machspec: %016lx\n", (ulong)machdep->machspec);
	fprintf(fp, "            userspace_top: %016lx\n", (ulong)ms->userspace_top);
	fprintf(fp, "              page_offset: %016lx\n", (ulong)ms->page_offset);
	fprintf(fp, "       vmalloc_start_addr: %016lx\n", (ulong)ms->vmalloc_start_addr);
	fprintf(fp, "              vmalloc_end: %016lx\n", (ulong)ms->vmalloc_end);
	fprintf(fp, "            modules_vaddr: %016lx\n", (ulong)ms->modules_vaddr);
	fprintf(fp, "              modules_end: %016lx\n", (ulong)ms->modules_end);
	fprintf(fp, "                phys_base: %lx\n", (ulong)ms->phys_base);
	fprintf(fp, "                     pml4: %lx\n", (ulong)ms->pml4);
	fprintf(fp, "           last_pml4_read: %lx\n", (ulong)ms->last_pml4_read);
	if (ms->upml) {
		fprintf(fp, "                     upml: %lx\n", (ulong)ms->upml);
		fprintf(fp, "           last_upml_read: %lx\n", (ulong)ms->last_upml_read);
	} else {
		fprintf(fp, "                     upml: (unused)\n");
		fprintf(fp, "           last_upml_read: (unused)\n");
	}
	fprintf(fp, "                 irqstack: %lx\n", (ulong)ms->irqstack);
	fprintf(fp, "                      pto: %s",
		machdep->flags & PT_REGS_INIT ? "\n" : "(uninitialized)\n");
	if (machdep->flags & PT_REGS_INIT) {
 	fprintf(fp, "                           r15: %ld\n", ms->pto.r15);
 	fprintf(fp, "                           r14: %ld\n", ms->pto.r14);
 	fprintf(fp, "                           r13: %ld\n", ms->pto.r13);
 	fprintf(fp, "                           r12: %ld\n", ms->pto.r12);
	fprintf(fp, "                           rbp: %ld\n", ms->pto.rbp);
	fprintf(fp, "                           rbx: %ld\n", ms->pto.rbx);
 	fprintf(fp, "                           r11: %ld\n", ms->pto.r11);
 	fprintf(fp, "                           r10: %ld\n", ms->pto.r10);
 	fprintf(fp, "                            r9: %ld\n", ms->pto.r9);
 	fprintf(fp, "                            r8: %ld\n", ms->pto.r8);
	fprintf(fp, "                           rax: %ld\n", ms->pto.rax);
	fprintf(fp, "                           rcx: %ld\n", ms->pto.rcx);
	fprintf(fp, "                           rdx: %ld\n", ms->pto.rdx);
	fprintf(fp, "                           rsi: %ld\n", ms->pto.rsi);
	fprintf(fp, "                           rdi: %ld\n", ms->pto.rdi);
	fprintf(fp, "                      orig_rax: %ld\n", ms->pto.orig_rax);
	fprintf(fp, "                           rip: %ld\n", ms->pto.rip);
	fprintf(fp, "                            cs: %ld\n", ms->pto.cs);
	fprintf(fp, "                        eflags: %ld\n", ms->pto.eflags);
	fprintf(fp, "                           rsp: %ld\n", ms->pto.rsp);
	fprintf(fp, "                            ss: %ld\n", ms->pto.ss);
	}
	fprintf(fp, "                  stkinfo: esize: %d%sisize: %d\n", 
		ms->stkinfo.esize, 
		machdep->flags & NO_TSS ? " (NO TSS) " : " ",
		ms->stkinfo.isize);
	fprintf(fp, "                           ebase[%s][7]:",
		arg ? "NR_CPUS" : "cpus");
	cpus = arg ? NR_CPUS : kt->cpus;
	for (c = 0; c < cpus; c++) {
		fprintf(fp, "\n  %s[%d]: ", c < 10 ? " " : "", c);
		for (i = 0; i < 7; i++) { 
			fprintf(fp, "%016lx ", ms->stkinfo.ebase[c][i]);
			if (i == 3)
				fprintf(fp, "\n        ");
		}
	}
	fprintf(fp, "\n                           ibase[%s]:\n   ",
		arg ? "NR_CPUS" : "cpus");
	for (c = 0; c < cpus; c++) {
		if (c && !(c%4))
			fprintf(fp, "\n   ");
		fprintf(fp, "%016lx ", ms->stkinfo.ibase[c]);
	}
	fprintf(fp, "\n");
}

/*
 *  Gather the cpu_pda array info, updating any smp-related items that
 *  were possibly bypassed or improperly initialized in kernel_init().
 */
static void 
x86_64_cpu_pda_init(void)
{
	int i, cpus, nr_pda, cpunumber, _cpu_pda;
	char *cpu_pda_buf;
	ulong level4_pgt, data_offset, cpu_pda_addr;
	struct syment *sp, *nsp;
	ulong offset, istacksize;

	STRUCT_SIZE_INIT(x8664_pda, "x8664_pda");
	MEMBER_OFFSET_INIT(x8664_pda_pcurrent, "x8664_pda", "pcurrent");
	MEMBER_OFFSET_INIT(x8664_pda_data_offset, "x8664_pda", "data_offset");
	MEMBER_OFFSET_INIT(x8664_pda_kernelstack, "x8664_pda", "kernelstack");
	MEMBER_OFFSET_INIT(x8664_pda_irqrsp, "x8664_pda", "irqrsp");
	MEMBER_OFFSET_INIT(x8664_pda_irqstackptr, "x8664_pda", "irqstackptr");
	MEMBER_OFFSET_INIT(x8664_pda_level4_pgt, "x8664_pda", "level4_pgt");
	MEMBER_OFFSET_INIT(x8664_pda_cpunumber, "x8664_pda", "cpunumber");
	MEMBER_OFFSET_INIT(x8664_pda_me, "x8664_pda", "me");

	cpu_pda_buf = GETBUF(SIZE(x8664_pda));

	if (symbol_exists("_cpu_pda")) {
		if (!(nr_pda = get_array_length("_cpu_pda", NULL, 0)))
			nr_pda = NR_CPUS;
		_cpu_pda = TRUE;
	} else {
		if (!(nr_pda = get_array_length("cpu_pda", NULL, 0)))
			nr_pda = NR_CPUS;
		_cpu_pda = FALSE;
	}

	for (i = cpus = 0; i < nr_pda; i++) {
		if (_cpu_pda) {
			if (!_CPU_PDA_READ(i, cpu_pda_buf))
				break;
		} else {
			if (!CPU_PDA_READ(i, cpu_pda_buf))
				break;
		}

		if (VALID_MEMBER(x8664_pda_level4_pgt)) {
			level4_pgt = ULONG(cpu_pda_buf + OFFSET(x8664_pda_level4_pgt));
			if (!VALID_LEVEL4_PGT_ADDR(level4_pgt))
				break;
		}
		cpunumber = INT(cpu_pda_buf + OFFSET(x8664_pda_cpunumber));
		if (cpunumber != cpus)
			break;
		cpus++;

		if (VALID_MEMBER(x8664_pda_data_offset)) {
			data_offset = ULONG(cpu_pda_buf + 
				OFFSET(x8664_pda_data_offset));
                        kt->__per_cpu_offset[i] = data_offset;
                        kt->flags |= PER_CPU_OFF;
		} else
			data_offset = 0;

		machdep->machspec->stkinfo.ibase[i] = ULONG(cpu_pda_buf + 
			OFFSET(x8664_pda_irqstackptr));

		if (CRASHDEBUG(2)) 
			fprintf(fp, "CPU%d: level4_pgt: %lx data_offset: %lx\n",
				i, level4_pgt, data_offset);
	}


	if ((i = get_array_length("boot_cpu_stack", NULL, 0))) {
		istacksize = i;
	} else if ((sp = symbol_search("boot_cpu_stack")) &&
 	    (nsp = next_symbol(NULL, sp))) {
		istacksize = (nsp->value - sp->value) & ~(PAGESIZE()-1);
		if (istacksize != 16384)
			error(WARNING, 
			    "calculated irqstack size of %ld != 16K?\n\n",
				istacksize);
	} else 
		istacksize = 16384;

	machdep->machspec->stkinfo.isize = istacksize;

	/*
	 *  Adjust the kernel top-of-stack values down to their base.
	 */
	for (i = 0; i < NR_CPUS; i++) {
		if (machdep->machspec->stkinfo.ibase[i])
			machdep->machspec->stkinfo.ibase[i] -= (istacksize-64);
		else
			break;
	}

	/*
	 *  Sanity check cpu 0's IRQ stack, which should be located at
	 *  the address of &boot_cpu_stack[0].
	 */
	sp = value_search(machdep->machspec->stkinfo.ibase[0], &offset);
	if (!sp || offset || !STREQ(sp->name, "boot_cpu_stack")) {
		if (symbol_value("boot_cpu_stack")) {
			error(WARNING, 
		       "cpu 0 IRQ stack: %lx\n         boot_cpu_stack: %lx\n\n",
				machdep->machspec->stkinfo.ibase[0], 
				symbol_value("boot_cpu_stack"));
			if (!machdep->machspec->stkinfo.ibase[0])
				machdep->machspec->stkinfo.ibase[0] = 
					symbol_value("boot_cpu_stack");
		} else
			error(WARNING, 
	 	     "boot_cpu_stack: symbol does not exist in this kernel!\n");
	}

	kt->cpus = cpus;
	if (kt->cpus > 1)
		kt->flags |= SMP;

	verify_spinlock();

	FREEBUF(cpu_pda_buf);
}

/*
 *  Gather the ist addresses for each CPU.
 */
static void 
x86_64_ist_init(void)
{
	int c, i, cpus;
	ulong vaddr, offset;
	ulong init_tss;
	struct machine_specific *ms;
	struct syment *sp;

        ms = machdep->machspec;
	if (symbol_exists("init_tss")) {
		init_tss = symbol_value("init_tss");
	
		for (c = cpus = 0; c < NR_CPUS; c++) {
			vaddr = init_tss + (c * SIZE(tss_struct)) +
				OFFSET(tss_struct_ist); 
			readmem(vaddr, KVADDR, &ms->stkinfo.ebase[c][0], 
				sizeof(ulong) * 7, "tss_struct ist array", 
				FAULT_ON_ERROR);
			if (ms->stkinfo.ebase[c][0] == 0)
				break;
		}
	} else if (symbol_exists("per_cpu__init_tss")) {
		for (c = 0; c < NR_CPUS; c++) {
                	if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF)) {
				if (kt->__per_cpu_offset[c] == 0)
					break;
                		vaddr = symbol_value("per_cpu__init_tss") +
                                        kt->__per_cpu_offset[c];
			} else 
				vaddr = symbol_value("per_cpu__init_tss");

			vaddr += OFFSET(tss_struct_ist);

                        readmem(vaddr, KVADDR, &ms->stkinfo.ebase[c][0],
                                sizeof(ulong) * 7, "tss_struct ist array",
                                FAULT_ON_ERROR);

                        if (ms->stkinfo.ebase[c][0] == 0)
                                break;
		}
	} else if (!symbol_exists("boot_exception_stacks")) {
		machdep->flags |= NO_TSS;

		if (CRASHDEBUG(1))
			error(NOTE, "CONFIG_X86_NO_TSS\n");

		return;
	}

	if (ms->stkinfo.ebase[0][0] && ms->stkinfo.ebase[0][1])
		ms->stkinfo.esize = ms->stkinfo.ebase[0][1] - 
			ms->stkinfo.ebase[0][0];
	else
		ms->stkinfo.esize = 4096;  /*  safe a bet as process stk size */

	/*
 	 *  Knowing the size, now adjust the top-of-stack addresses back down
	 *  to the base stack address.
	 */
        for (c = 0; c < kt->cpus; c++) {
                for (i = 0; i < 7; i++) {
                        if (ms->stkinfo.ebase[c][i] == 0)
                                break;
			ms->stkinfo.ebase[c][i] -= ms->stkinfo.esize;
		}
	}

	/*
	 *  Sanity check cpu 0's first exception stack, which should be
	 *  located at: &boot_exception_stacks[0]
	 */
        sp = value_search(ms->stkinfo.ebase[0][0], &offset);
       	if (!sp || offset || !STREQ(sp->name, "boot_exception_stacks")) {
		if (symbol_value("boot_exception_stacks")) {
                	error(WARNING,
    "cpu 0 first exception stack: %lx\n         boot_exception_stacks: %lx\n\n",
                        	ms->stkinfo.ebase[0][0], 
				symbol_value("boot_exception_stacks"));
			if (!ms->stkinfo.ebase[0][0])
				ms->stkinfo.ebase[0][0] = 
					symbol_value("boot_exception_stacks");
		} else 
			error(WARNING, 
	      "boot_exception_stacks: symbol does not exist in this kernel!\n");
	}
}

static void 
x86_64_post_init(void)
{ 
        int c, i, clues;
        struct machine_specific *ms;
	ulong *up;
	struct syment *spt, *spc;
	ulong offset;

	/*
	 *  Check whether each cpu was stopped by an NMI.
	 */
        ms = machdep->machspec;

        for (c = 0; c < kt->cpus; c++) {
                if (ms->stkinfo.ebase[c][NMI_STACK] == 0)
                        break;

                if (!readmem(ms->stkinfo.ebase[c][NMI_STACK], 
		    KVADDR, ms->irqstack,
		    ms->stkinfo.esize,
                    "NMI exception stack contents", 
		    RETURN_ON_ERROR|QUIET)) 
			continue;

       		for (i = clues = 0; i < (ms->stkinfo.esize)/sizeof(ulong); i++){
                	up = (ulong *)(&ms->irqstack[i*sizeof(ulong)]);

                	if (!is_kernel_text(*up) ||
                            !(spt = value_search(*up, &offset)))
				continue;

			if (STREQ(spt->name, "try_crashdump") ||
			    STREQ(spt->name, "die_nmi")) 
				clues++;

                    	if ((STREQ(spt->name, "nmi_watchdog_tick") ||
                     	     STREQ(spt->name, "default_do_nmi"))) {
                        	spc = x86_64_function_called_by((*up)-5);
                        	if (spc && STREQ(spc->name, "die_nmi"))
                                	clues += 2;
			}
		}

		if (clues >= 2) 
			kt->cpu_flags[c] |= NMI;
        }

	if (symbol_exists("__sched_text_start") && 
	    (symbol_value("__sched_text_start") == symbol_value("schedule")))
		machdep->flags |= SCHED_TEXT;
}

/*
 *  No x86_64 swapper_pg_dir; initialize the vt->kernel_pgd[NR_CPUS] array
 *  with the lazily-sync'd init_level4_pgt page address.  The level4 page
 *  could be taken from the per-cpu cpu_pda.level4_pgt pointer, but since
 *  the kernel pgd_offset_k() is defined as shown below, we'll derive
 *  the third-level pgd in the same manner:
 *   
 *   /@ This accesses the reference page table of the boot cpu.
 *      Other CPUs get synced lazily via the page fault handler. @/
 *
 *   static inline pgd_t *pgd_offset_k(unsigned long address)
 *   {
 *           unsigned long addr;
 *   
 *           addr = pml4_val(init_level4_pgt[pml4_index(address)]);
 *           addr &= PHYSICAL_PAGE_MASK;
 *           return __pgd_offset_k((pgd_t *)__va(addr), address);
 *   } 
 */ 
static void 
x86_64_init_kernel_pgd(void)
{
	int i;
	ulong init_level4_pgt;

	init_level4_pgt = symbol_value("init_level4_pgt");

	for (i = 0; i < NR_CPUS; i++) 
		vt->kernel_pgd[i] = init_level4_pgt;

	FILL_PML4();
}

/*
 *  x86_64 __pa() clone.
 */
ulong x86_64_VTOP(ulong vaddr) 
{
	if (vaddr >= __START_KERNEL_map)
		return ((vaddr) - (ulong)__START_KERNEL_map + machdep->machspec->phys_base);
	else
		return ((vaddr) - PAGE_OFFSET);
}

/*
 *  Include both vmalloc'd and module address space as VMALLOC space.
 */
int 
x86_64_IS_VMALLOC_ADDR(ulong vaddr)
{
	return ((vaddr >= VMALLOC_START && vaddr <= VMALLOC_END) ||
                (vaddr >= MODULES_VADDR && vaddr <= MODULES_END));
}

static int 
x86_64_is_module_addr(ulong vaddr)
{
	return (vaddr >= MODULES_VADDR && vaddr <= MODULES_END);
}

/*
 *  Refining this may cause more problems than just doing it this way.
 */
static int 
x86_64_is_kvaddr(ulong addr)
{
        return (addr >= PAGE_OFFSET); 
}

static int 
x86_64_is_uvaddr(ulong addr, struct task_context *tc)
{
        return (addr < USERSPACE_TOP);
}


/*
 *  Translates a user virtual address to its physical address.  cmd_vtop()
 *  sets the verbose flag so that the pte translation gets displayed; all
 *  other callers quietly accept the translation.
 *
 *  This routine can also take mapped kernel virtual addresses if the -u flag
 *  was passed to cmd_vtop(), just pass it to x86_64_kvtop().
 */

static int
x86_64_uvtop_level4(struct task_context *tc, ulong uvaddr, physaddr_t *paddr, int verbose)
{
	ulong mm;
	ulong *pml;
	ulong pml_paddr;
	ulong pml_pte;
	ulong *pgd;
	ulong pgd_paddr;
	ulong pgd_pte;
	ulong *pmd;
	ulong pmd_paddr;
	ulong pmd_pte;
	ulong *ptep;
	ulong pte_paddr;
	ulong pte;
	physaddr_t physpage;

	if (!tc)
		error(FATAL, "current context invalid\n");

	*paddr = 0;

	if (IS_KVADDR(uvaddr))
		return x86_64_kvtop(tc, uvaddr, paddr, verbose);

	if ((mm = task_mm(tc->task, TRUE)))
		pml = ULONG_PTR(tt->mm_struct + OFFSET(mm_struct_pgd));
	else
		readmem(tc->mm_struct + OFFSET(mm_struct_pgd), KVADDR, &pml,
			sizeof(long), "mm_struct pgd", FAULT_ON_ERROR);

	pml_paddr = x86_64_VTOP((ulong)pml);
	FILL_UPML(pml_paddr, PHYSADDR, PAGESIZE());
	pml = ((ulong *)pml_paddr) + pml4_index(uvaddr); 
	pml_pte = ULONG(machdep->machspec->upml + PAGEOFFSET(pml));
	if (verbose) 
		fprintf(fp, "   PML: %lx => %lx\n", (ulong)pml, pml_pte);
	if (!(pml_pte & _PAGE_PRESENT))
		goto no_upage;

	pgd_paddr = pml_pte & PHYSICAL_PAGE_MASK;
	FILL_PGD(pgd_paddr, PHYSADDR, PAGESIZE());
	pgd = ((ulong *)pgd_paddr) + pgd_index(uvaddr); 
	pgd_pte = ULONG(machdep->pgd + PAGEOFFSET(pgd));
	if (verbose) 
                fprintf(fp, "   PUD: %lx => %lx\n", (ulong)pgd, pgd_pte);
	if (!(pgd_pte & _PAGE_PRESENT))
		goto no_upage;

	/*
         *  pmd = pmd_offset(pgd, address);
	 */
	pmd_paddr = pgd_pte & PHYSICAL_PAGE_MASK;
	FILL_PMD(pmd_paddr, PHYSADDR, PAGESIZE());
	pmd = ((ulong *)pmd_paddr) + pmd_index(uvaddr);
	pmd_pte = ULONG(machdep->pmd + PAGEOFFSET(pmd));
        if (verbose) 
                fprintf(fp, "   PMD: %lx => %lx\n", (ulong)pmd, pmd_pte);
	if (!(pmd_pte & _PAGE_PRESENT))
		goto no_upage;
        if (pmd_pte & _PAGE_PSE) {
                if (verbose) {
                        fprintf(fp, "  PAGE: %lx  (2MB)\n\n", 
				PAGEBASE(pmd_pte) & PHYSICAL_PAGE_MASK);
                        x86_64_translate_pte(pmd_pte, 0, 0);
                }

                physpage = (PAGEBASE(pmd_pte) & PHYSICAL_PAGE_MASK) + 
			(uvaddr & ~_2MB_PAGE_MASK);
                *paddr = physpage;
                return TRUE;
        }

        /*
	 *  ptep = pte_offset_map(pmd, address);
	 *  pte = *ptep;
	 */
	pte_paddr = pmd_pte & PHYSICAL_PAGE_MASK;
	FILL_PTBL(pte_paddr, PHYSADDR, PAGESIZE());
	ptep = ((ulong *)pte_paddr) + pte_index(uvaddr);
	pte = ULONG(machdep->ptbl + PAGEOFFSET(ptep));
	if (verbose)
		fprintf(fp, "   PTE: %lx => %lx\n", (ulong)ptep, pte);
	if (!(pte & (_PAGE_PRESENT))) {
		if (pte && verbose) {
			fprintf(fp, "\n");
			x86_64_translate_pte(pte, 0, 0);
		}
		goto no_upage;
	}

	*paddr = (PAGEBASE(pte) & PHYSICAL_PAGE_MASK) + PAGEOFFSET(uvaddr);

	if (verbose) {
		fprintf(fp, "  PAGE: %lx\n\n", 
			PAGEBASE(*paddr) & PHYSICAL_PAGE_MASK);
		x86_64_translate_pte(pte, 0, 0);
	}

	return TRUE;

no_upage:

	return FALSE;
}

static int
x86_64_uvtop_level4_xen_wpt(struct task_context *tc, ulong uvaddr, physaddr_t *paddr, int verbose)
{
	ulong mm;
	ulong *pml;
	ulong pml_paddr;
	ulong pml_pte;
	ulong *pgd;
	ulong pgd_paddr;
	ulong pgd_pte;
	ulong *pmd;
	ulong pmd_paddr;
	ulong pmd_pte;
	ulong pseudo_pmd_pte;
	ulong *ptep;
	ulong pte_paddr;
	ulong pte;
	ulong pseudo_pte;
	physaddr_t physpage;
	char buf[BUFSIZE];

	if (!tc)
		error(FATAL, "current context invalid\n");

	*paddr = 0;

	if (IS_KVADDR(uvaddr))
		return x86_64_kvtop(tc, uvaddr, paddr, verbose);

	if ((mm = task_mm(tc->task, TRUE)))
		pml = ULONG_PTR(tt->mm_struct + OFFSET(mm_struct_pgd));
	else
		readmem(tc->mm_struct + OFFSET(mm_struct_pgd), KVADDR, &pml,
			sizeof(long), "mm_struct pgd", FAULT_ON_ERROR);

	pml_paddr = x86_64_VTOP((ulong)pml);
	FILL_UPML(pml_paddr, PHYSADDR, PAGESIZE());
	pml = ((ulong *)pml_paddr) + pml4_index(uvaddr); 
	pml_pte = ULONG(machdep->machspec->upml + PAGEOFFSET(pml));
	if (verbose) 
		fprintf(fp, "   PML: %lx => %lx [machine]\n", (ulong)pml, pml_pte);
	if (!(pml_pte & _PAGE_PRESENT))
		goto no_upage;

	pgd_paddr = pml_pte & PHYSICAL_PAGE_MASK;
	pgd_paddr = xen_m2p(pgd_paddr);
	if (verbose)
		fprintf(fp, "   PML: %lx\n", pgd_paddr);
	FILL_PGD(pgd_paddr, PHYSADDR, PAGESIZE());
	pgd = ((ulong *)pgd_paddr) + pgd_index(uvaddr); 
	pgd_pte = ULONG(machdep->pgd + PAGEOFFSET(pgd));
	if (verbose) 
                fprintf(fp, "   PUD: %lx => %lx [machine]\n", (ulong)pgd, pgd_pte);
	if (!(pgd_pte & _PAGE_PRESENT))
		goto no_upage;

	/*
         *  pmd = pmd_offset(pgd, address);
	 */
	pmd_paddr = pgd_pte & PHYSICAL_PAGE_MASK;
	pmd_paddr = xen_m2p(pmd_paddr);
	if (verbose)
                fprintf(fp, "   PUD: %lx\n", pmd_paddr);
	FILL_PMD(pmd_paddr, PHYSADDR, PAGESIZE());
	pmd = ((ulong *)pmd_paddr) + pmd_index(uvaddr);
	pmd_pte = ULONG(machdep->pmd + PAGEOFFSET(pmd));
        if (verbose) 
                fprintf(fp, "   PMD: %lx => %lx [machine]\n", (ulong)pmd, pmd_pte);
	if (!(pmd_pte & _PAGE_PRESENT))
		goto no_upage;
        if (pmd_pte & _PAGE_PSE) {
                if (verbose)
                        fprintf(fp, "  PAGE: %lx  (2MB) [machine]\n", 
				PAGEBASE(pmd_pte) & PHYSICAL_PAGE_MASK);

		pseudo_pmd_pte = xen_m2p(PAGEBASE(pmd_pte));

                if (pseudo_pmd_pte == XEN_MACHADDR_NOT_FOUND) {
                        if (verbose)
                                fprintf(fp, " PAGE: page not available\n");
                        *paddr = PADDR_NOT_AVAILABLE;
                        return FALSE;
                }

		pseudo_pmd_pte |= PAGEOFFSET(pmd_pte);

                if (verbose) {
                        fprintf(fp, " PAGE: %s  (2MB)\n\n",
                                mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX,
                                MKSTR(PAGEBASE(pseudo_pmd_pte) & 
				PHYSICAL_PAGE_MASK)));

                        x86_64_translate_pte(pseudo_pmd_pte, 0, 0);
                }

                physpage = (PAGEBASE(pseudo_pmd_pte) & PHYSICAL_PAGE_MASK) + 
			(uvaddr & ~_2MB_PAGE_MASK);

                *paddr = physpage;
                return TRUE;
        }

        /*
	 *  ptep = pte_offset_map(pmd, address);
	 *  pte = *ptep;
	 */
	pte_paddr = pmd_pte & PHYSICAL_PAGE_MASK;
	pte_paddr = xen_m2p(pte_paddr);
	if (verbose)
		fprintf(fp, "   PMD: %lx\n", pte_paddr);
	FILL_PTBL(pte_paddr, PHYSADDR, PAGESIZE());
	ptep = ((ulong *)pte_paddr) + pte_index(uvaddr);
	pte = ULONG(machdep->ptbl + PAGEOFFSET(ptep));
	if (verbose)
		fprintf(fp, "   PTE: %lx => %lx [machine]\n", (ulong)ptep, pte);
	if (!(pte & (_PAGE_PRESENT))) {
		if (pte && verbose) {
			fprintf(fp, "\n");
			x86_64_translate_pte(pte, 0, 0);
		}
		goto no_upage;
	}
	
	pseudo_pte = xen_m2p(pte & PHYSICAL_PAGE_MASK);
	if (verbose)
		fprintf(fp, "   PTE: %lx\n", pseudo_pte + PAGEOFFSET(pte));

	*paddr = (PAGEBASE(pseudo_pte) & PHYSICAL_PAGE_MASK) + PAGEOFFSET(uvaddr);

	if (verbose) {
		fprintf(fp, "  PAGE: %lx [machine]\n", 
			PAGEBASE(pte) & PHYSICAL_PAGE_MASK);
		fprintf(fp, "  PAGE: %lx\n\n", 
			PAGEBASE(*paddr) & PHYSICAL_PAGE_MASK);
		x86_64_translate_pte(pseudo_pte + PAGEOFFSET(pte), 0, 0);
	}

	return TRUE;

no_upage:

	return FALSE;
}

static int
x86_64_uvtop(struct task_context *tc, ulong uvaddr, physaddr_t *paddr, int verbose)
{
       	ulong mm;
        ulong *pgd;
	ulong pgd_paddr;
	ulong pgd_pte;
	ulong *pmd;
	ulong pmd_paddr;
	ulong pmd_pte;
        ulong *ptep;
        ulong pte_paddr;
        ulong pte;
        physaddr_t physpage;

        if (!tc)
                error(FATAL, "current context invalid\n");

        *paddr = 0;

        if (IS_KVADDR(uvaddr))
                return x86_64_kvtop(tc, uvaddr, paddr, verbose);

        /*
         *  pgd = pgd_offset(mm, address);
         */
        if ((mm = task_mm(tc->task, TRUE)))
                pgd = ULONG_PTR(tt->mm_struct + OFFSET(mm_struct_pgd));
        else
                readmem(tc->mm_struct + OFFSET(mm_struct_pgd), KVADDR, &pgd,
                        sizeof(long), "mm_struct pgd", FAULT_ON_ERROR);

        pgd_paddr = x86_64_VTOP((ulong)pgd);
        FILL_PGD(pgd_paddr, PHYSADDR, PAGESIZE());
	pgd = ((ulong *)pgd_paddr) + pgd_index(uvaddr); 
	pgd_pte = ULONG(machdep->pgd + PAGEOFFSET(pgd));
        if (verbose) 
                fprintf(fp, "   PGD: %lx => %lx\n", (ulong)pgd, pgd_pte);
	if (!(pgd_pte & _PAGE_PRESENT))
		goto no_upage;

	/*
         *  pmd = pmd_offset(pgd, address);
	 */
	pmd_paddr = pgd_pte & PHYSICAL_PAGE_MASK;
	FILL_PMD(pmd_paddr, PHYSADDR, PAGESIZE());
	pmd = ((ulong *)pmd_paddr) + pmd_index(uvaddr);
	pmd_pte = ULONG(machdep->pmd + PAGEOFFSET(pmd));
        if (verbose) 
                fprintf(fp, "   PMD: %lx => %lx\n", (ulong)pmd, pmd_pte);
	if (!(pmd_pte & _PAGE_PRESENT))
		goto no_upage;
        if (pmd_pte & _PAGE_PSE) {
                if (verbose) {
                        fprintf(fp, "  PAGE: %lx  (2MB)\n\n", 
				PAGEBASE(pmd_pte) & PHYSICAL_PAGE_MASK);
                        x86_64_translate_pte(pmd_pte, 0, 0);
                }

                physpage = (PAGEBASE(pmd_pte) & PHYSICAL_PAGE_MASK) + 
			(uvaddr & ~_2MB_PAGE_MASK);
                *paddr = physpage;
                return TRUE;
        }

        /*
	 *  ptep = pte_offset_map(pmd, address);
         *  pte = *ptep;
	 */
        pte_paddr = pmd_pte & PHYSICAL_PAGE_MASK;
        FILL_PTBL(pte_paddr, PHYSADDR, PAGESIZE());
        ptep = ((ulong *)pte_paddr) + pte_index(uvaddr);
        pte = ULONG(machdep->ptbl + PAGEOFFSET(ptep));
        if (verbose)
                fprintf(fp, "   PTE: %lx => %lx\n", (ulong)ptep, pte);
        if (!(pte & (_PAGE_PRESENT))) {
                if (pte && verbose) {
                        fprintf(fp, "\n");
                        x86_64_translate_pte(pte, 0, 0);
                }
                goto no_upage;
        }

        *paddr = (PAGEBASE(pte) & PHYSICAL_PAGE_MASK) + PAGEOFFSET(uvaddr);

        if (verbose) {
                fprintf(fp, "  PAGE: %lx\n\n", 
			PAGEBASE(*paddr) & PHYSICAL_PAGE_MASK);
                x86_64_translate_pte(pte, 0, 0);
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
x86_64_kvtop(struct task_context *tc, ulong kvaddr, physaddr_t *paddr, int verbose)
{
	ulong *pml4;
        ulong *pgd;
	ulong pgd_paddr;
	ulong pgd_pte;
	ulong *pmd;
	ulong pmd_paddr;
	ulong pmd_pte;
	ulong *ptep;
	ulong pte_paddr;
	ulong pte;
	physaddr_t physpage;

        if (!IS_KVADDR(kvaddr))
                return FALSE;

        if (!vt->vmalloc_start) {
                *paddr = x86_64_VTOP(kvaddr);
                return TRUE;
        }

        if (!IS_VMALLOC_ADDR(kvaddr)) {
                *paddr = x86_64_VTOP(kvaddr);
                if (!verbose)
                        return TRUE;
        }
	
	if (XEN() && (kt->xen_flags & WRITABLE_PAGE_TABLES))
		return (x86_64_kvtop_xen_wpt(tc, kvaddr, paddr, verbose));

 	/*	
	 *  pgd = pgd_offset_k(addr);
	 */
	FILL_PML4();
	pml4 = ((ulong *)machdep->machspec->pml4) + pml4_index(kvaddr);  
        if (verbose) {
		fprintf(fp, "PML4 DIRECTORY: %lx\n", vt->kernel_pgd[0]);
                fprintf(fp, "PAGE DIRECTORY: %lx\n", *pml4);
	}
	if (!(*pml4) & _PAGE_PRESENT)
		goto no_kpage;
	pgd_paddr = (*pml4) & PHYSICAL_PAGE_MASK;
	FILL_PGD(pgd_paddr, PHYSADDR, PAGESIZE());
	pgd = ((ulong *)pgd_paddr) + pgd_index(kvaddr); 
	pgd_pte = ULONG(machdep->pgd + PAGEOFFSET(pgd));
        if (verbose) 
                fprintf(fp, "   PUD: %lx => %lx\n", (ulong)pgd, pgd_pte);
	if (!(pgd_pte & _PAGE_PRESENT))
		goto no_kpage;

	/*
	 *  pmd = pmd_offset(pgd, addr); 
	 */
	pmd_paddr = pgd_pte & PHYSICAL_PAGE_MASK;
	FILL_PMD(pmd_paddr, PHYSADDR, PAGESIZE());
	pmd = ((ulong *)pmd_paddr) + pmd_index(kvaddr);
	pmd_pte = ULONG(machdep->pmd + PAGEOFFSET(pmd));
        if (verbose) 
                fprintf(fp, "   PMD: %lx => %lx\n", (ulong)pmd, pmd_pte);
	if (!(pmd_pte & _PAGE_PRESENT))
		goto no_kpage;
	if (pmd_pte & _PAGE_PSE) {
		if (verbose) {
			fprintf(fp, "  PAGE: %lx  (2MB)\n\n", 
				PAGEBASE(pmd_pte) & PHYSICAL_PAGE_MASK);
                       	x86_64_translate_pte(pmd_pte, 0, 0);
                }

                physpage = (PAGEBASE(pmd_pte) & PHYSICAL_PAGE_MASK) + 
			(kvaddr & ~_2MB_PAGE_MASK);
                *paddr = physpage;
                return TRUE;
	}

	/*
	 *  ptep = pte_offset_map(pmd, addr);
	 *  pte = *ptep;
	 */
	pte_paddr = pmd_pte & PHYSICAL_PAGE_MASK;
	FILL_PTBL(pte_paddr, PHYSADDR, PAGESIZE());
	ptep = ((ulong *)pte_paddr) + pte_index(kvaddr);
	pte = ULONG(machdep->ptbl + PAGEOFFSET(ptep));
        if (verbose) 
                fprintf(fp, "   PTE: %lx => %lx\n", (ulong)ptep, pte);
        if (!(pte & (_PAGE_PRESENT))) {
                if (pte && verbose) {
                        fprintf(fp, "\n");
                        x86_64_translate_pte(pte, 0, 0);
                }
                goto no_kpage;
        }

        *paddr = (PAGEBASE(pte) & PHYSICAL_PAGE_MASK) + PAGEOFFSET(kvaddr);

        if (verbose) {
                fprintf(fp, "  PAGE: %lx\n\n", 
			PAGEBASE(*paddr) & PHYSICAL_PAGE_MASK);
                x86_64_translate_pte(pte, 0, 0);
        }

        return TRUE;

no_kpage:
        return FALSE;
}


static int
x86_64_kvtop_xen_wpt(struct task_context *tc, ulong kvaddr, physaddr_t *paddr, int verbose)
{
	ulong *pml4;
        ulong *pgd;
	ulong pgd_paddr;
	ulong pgd_pte;
	ulong *pmd;
	ulong pmd_paddr;
	ulong pmd_pte;
	ulong pseudo_pmd_pte;
	ulong *ptep;
	ulong pte_paddr;
	ulong pte;
	ulong pseudo_pte;
	physaddr_t physpage;
	char buf[BUFSIZE];

 	/*	
	 *  pgd = pgd_offset_k(addr);
	 */
	FILL_PML4();
	pml4 = ((ulong *)machdep->machspec->pml4) + pml4_index(kvaddr);  
        if (verbose) {
		fprintf(fp, "PML4 DIRECTORY: %lx\n", vt->kernel_pgd[0]);
                fprintf(fp, "PAGE DIRECTORY: %lx [machine]\n", *pml4);
	}
	if (!(*pml4) & _PAGE_PRESENT)
		goto no_kpage;
	pgd_paddr = (*pml4) & PHYSICAL_PAGE_MASK;
	pgd_paddr = xen_m2p(pgd_paddr);
	if (verbose)
                fprintf(fp, "PAGE DIRECTORY: %lx\n", pgd_paddr);
	FILL_PGD(pgd_paddr, PHYSADDR, PAGESIZE());
	pgd = ((ulong *)pgd_paddr) + pgd_index(kvaddr); 
	pgd_pte = ULONG(machdep->pgd + PAGEOFFSET(pgd));
        if (verbose) 
                fprintf(fp, "   PUD: %lx => %lx [machine]\n", (ulong)pgd, pgd_pte);
	if (!(pgd_pte & _PAGE_PRESENT))
		goto no_kpage;

	/*
	 *  pmd = pmd_offset(pgd, addr); 
	 */
	pmd_paddr = pgd_pte & PHYSICAL_PAGE_MASK;
	pmd_paddr = xen_m2p(pmd_paddr);
	if (verbose)
                fprintf(fp, "   PUD: %lx\n", pmd_paddr);
	FILL_PMD(pmd_paddr, PHYSADDR, PAGESIZE());
	pmd = ((ulong *)pmd_paddr) + pmd_index(kvaddr);
	pmd_pte = ULONG(machdep->pmd + PAGEOFFSET(pmd));
        if (verbose) 
                fprintf(fp, "   PMD: %lx => %lx [machine]\n", (ulong)pmd, pmd_pte);
	if (!(pmd_pte & _PAGE_PRESENT))
		goto no_kpage;
	if (pmd_pte & _PAGE_PSE) {
		if (verbose)
			fprintf(fp, "  PAGE: %lx  (2MB) [machine]\n", 
				PAGEBASE(pmd_pte) & PHYSICAL_PAGE_MASK);

                pseudo_pmd_pte = xen_m2p(PAGEBASE(pmd_pte));

                if (pseudo_pmd_pte == XEN_MACHADDR_NOT_FOUND) {
                        if (verbose)
                                fprintf(fp, " PAGE: page not available\n");
                        *paddr = PADDR_NOT_AVAILABLE;
                        return FALSE;
                }

                pseudo_pmd_pte |= PAGEOFFSET(pmd_pte);

                if (verbose) {
                        fprintf(fp, " PAGE: %s  (2MB)\n\n",
                                mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX,
                                MKSTR(PAGEBASE(pseudo_pmd_pte) &
                                PHYSICAL_PAGE_MASK)));

                        x86_64_translate_pte(pseudo_pmd_pte, 0, 0);
                }

                physpage = (PAGEBASE(pseudo_pmd_pte) & PHYSICAL_PAGE_MASK) +
                        (kvaddr & ~_2MB_PAGE_MASK);

                *paddr = physpage;
                return TRUE;
	}

	/*
	 *  ptep = pte_offset_map(pmd, addr);
	 *  pte = *ptep;
	 */
	pte_paddr = pmd_pte & PHYSICAL_PAGE_MASK;
	pte_paddr = xen_m2p(pte_paddr);
	if (verbose)
		fprintf(fp, "   PMD: %lx\n", pte_paddr); 
	FILL_PTBL(pte_paddr, PHYSADDR, PAGESIZE());
	ptep = ((ulong *)pte_paddr) + pte_index(kvaddr);
	pte = ULONG(machdep->ptbl + PAGEOFFSET(ptep));
        if (verbose) 
                fprintf(fp, "   PTE: %lx => %lx [machine]\n", (ulong)ptep, pte);
        if (!(pte & (_PAGE_PRESENT))) {
                if (pte && verbose) {
                        fprintf(fp, "\n");
                        x86_64_translate_pte(pte, 0, 0);
                }
                goto no_kpage;
        }

	pseudo_pte = xen_m2p(pte & PHYSICAL_PAGE_MASK);
	if (verbose)
                fprintf(fp, "   PTE: %lx\n", pseudo_pte + PAGEOFFSET(pte));

        *paddr = (PAGEBASE(pseudo_pte) & PHYSICAL_PAGE_MASK) + PAGEOFFSET(kvaddr);

        if (verbose) {
                fprintf(fp, "  PAGE: %lx [machine]\n", 
			PAGEBASE(pte) & PHYSICAL_PAGE_MASK);
                fprintf(fp, "  PAGE: %lx\n\n", 
			PAGEBASE(*paddr) & PHYSICAL_PAGE_MASK);
                x86_64_translate_pte(pseudo_pte + PAGEOFFSET(pte), 0, 0);
        }

        return TRUE;

no_kpage:
        return FALSE;
}


/*
 *  Determine where vmalloc'd memory starts.
 */
static ulong
x86_64_vmalloc_start(void)
{
	return ((ulong)VMALLOC_START);
}

/*
 *  thread_info implementation makes for less accurate results here.
 */
static int
x86_64_is_task_addr(ulong task)
{
        if (tt->flags & THREAD_INFO)
                return IS_KVADDR(task);
        else
                return (IS_KVADDR(task) && (ALIGNED_STACK_OFFSET(task) == 0));
}


/*
 *  easy enough...
 */
static ulong
x86_64_processor_speed(void)
{
        unsigned long cpu_khz = 0;

        if (machdep->mhz)
                return (machdep->mhz);

        if (symbol_exists("cpu_khz")) {
                get_symbol_data("cpu_khz", sizeof(int), &cpu_khz);
                if (cpu_khz)
                        return(machdep->mhz = cpu_khz/1000);
        }

        return 0;
}


/*
 *  Accept or reject a symbol from the kernel namelist.
 */
static int
x86_64_verify_symbol(const char *name, ulong value, char type)
{
        if (STREQ(name, "_text") || STREQ(name, "_stext"))
                machdep->flags |= KSYMS_START;

        if (!name || !strlen(name) || !(machdep->flags & KSYMS_START))
                return FALSE;
	return TRUE;
}


/*
 *  Get the relevant page directory pointer from a task structure.
 */
static ulong
x86_64_get_task_pgd(ulong task)
{
	return (error(FATAL, "x86_64_get_task_pgd: N/A\n"));
}


/*
 *  Translate a PTE, returning TRUE if the page is present.
 *  If a physaddr pointer is passed in, don't print anything.
 */
static int
x86_64_translate_pte(ulong pte, void *physaddr, ulonglong unused)
{
	int c, others, len1, len2, len3;
	ulong paddr;
	char buf[BUFSIZE];
        char buf2[BUFSIZE];
        char buf3[BUFSIZE];
	char ptebuf[BUFSIZE];
	char physbuf[BUFSIZE];
        char *arglist[MAXARGS];
	int page_present;

        paddr = pte & PHYSICAL_PAGE_MASK;
        page_present = pte & _PAGE_PRESENT;

        if (physaddr) {
		*((ulong *)physaddr) = paddr;
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
		if (pte & _PAGE_RW)
			fprintf(fp, "%sRW", others++ ? "|" : "");
		if (pte & _PAGE_USER)
			fprintf(fp, "%sUSER", others++ ? "|" : "");
		if (pte & _PAGE_PWT)
			fprintf(fp, "%sPWT", others++ ? "|" : "");
		if (pte & _PAGE_PCD)
			fprintf(fp, "%sPCD", others++ ? "|" : "");
		if (pte & _PAGE_ACCESSED)
			fprintf(fp, "%sACCESSED", others++ ? "|" : "");
		if (pte & _PAGE_DIRTY)
			fprintf(fp, "%sDIRTY", others++ ? "|" : "");
		if ((pte & _PAGE_PSE) && (pte & _PAGE_PRESENT))
			fprintf(fp, "%sPSE", others++ ? "|" : "");
		if ((pte & _PAGE_PROTNONE) && !(pte & _PAGE_PRESENT))
			fprintf(fp, "%sPROTNONE", others++ ? "|" : "");
		if (pte & _PAGE_GLOBAL)
			fprintf(fp, "%sGLOBAL", others++ ? "|" : "");
		if (pte & _PAGE_NX)
			fprintf(fp, "%sNX", others++ ? "|" : "");
	} else {
                fprintf(fp, "no mapping");
        }

        fprintf(fp, ")\n");

	return (page_present);
}

static char *
x86_64_exception_stacks[7] = {
	"STACKFAULT",
	"DOUBLEFAULT",
	"NMI",
	"DEBUG",
	"MCE",
	"(unknown)",
	"(unknown)"
};

/*
 *  Look for likely exception frames in a stack.
 */
static int 
x86_64_eframe_search(struct bt_info *bt)
{
	int i, c, cnt;
        ulong estack, irqstack, stacksize;
	ulong *up;
        struct machine_specific *ms;
	struct bt_info bt_local;

	if (bt->flags & BT_EFRAME_SEARCH2) {
		BCOPY(bt, &bt_local, sizeof(struct bt_info));
		bt->flags &= ~(ulonglong)BT_EFRAME_SEARCH2;

        	ms = machdep->machspec;

        	for (c = 0; c < kt->cpus; c++) {
                	if (ms->stkinfo.ibase[c] == 0)
                        	break;
                                bt->hp->esp = ms->stkinfo.ibase[c];
                                fprintf(fp, "CPU %d IRQ STACK:\n", c);
                                if ((cnt = x86_64_eframe_search(bt)))
					fprintf(fp, "\n");
				else
                                        fprintf(fp, "(none found)\n\n");
                }

        	for (c = 0; c < kt->cpus; c++) {
                	for (i = 0; i < 7; i++) {
                        	if (ms->stkinfo.ebase[c][i] == 0)
                                	break;
                                bt->hp->esp = ms->stkinfo.ebase[c][i];
                                fprintf(fp, "CPU %d %s EXCEPTION STACK:\n", 
					c, x86_64_exception_stacks[i]);
                                if ((cnt = x86_64_eframe_search(bt)))
					fprintf(fp, "\n");
				else
                                        fprintf(fp, "(none found)\n\n");
                	}
        	}

		return 0;
        }

        if (bt->hp && bt->hp->esp) {
        	ms = machdep->machspec;
		bt->stkptr = bt->hp->esp;
		if ((estack = x86_64_in_exception_stack(bt))) {
			stacksize = ms->stkinfo.esize;
			bt->stackbase = estack;
			bt->stacktop = estack + ms->stkinfo.esize;
                	bt->stackbuf = ms->irqstack;
                	alter_stackbuf(bt);
		} else if ((irqstack = x86_64_in_irqstack(bt))) {
			stacksize = ms->stkinfo.isize;
			bt->stackbase = irqstack;
			bt->stacktop = irqstack + ms->stkinfo.isize;
                	bt->stackbuf = ms->irqstack;
                	alter_stackbuf(bt);
		} else if (!INSTACK(bt->stkptr, bt))
			error(FATAL, 
			    "unrecognized stack address for this task: %lx\n",
				bt->hp->esp);
	} 

	stacksize = bt->stacktop - bt->stackbase - SIZE(pt_regs);

	if (bt->stkptr)
		i = (bt->stkptr - bt->stackbase)/sizeof(ulong);
	else
		i = 0;

	for (cnt = 0; i <= stacksize/sizeof(ulong); i++) {
		up = (ulong *)(&bt->stackbuf[i*sizeof(ulong)]);

                if (x86_64_exception_frame(EFRAME_SEARCH|EFRAME_PRINT|
		    EFRAME_VERIFY, 0, (char *)up, bt, fp)) 
			cnt++;
	}

	return cnt;
}

static void
x86_64_display_full_frame(struct bt_info *bt, ulong rsp, FILE *ofp)
{
	int i, u_idx;
	ulong *up;
	ulong words, addr;

	if (rsp < bt->frameptr)
		return;

        words = (rsp - bt->frameptr) / sizeof(ulong) + 1;

	addr = bt->frameptr;
	u_idx = (bt->frameptr - bt->stackbase)/sizeof(ulong);
	for (i = 0; i < words; i++, u_idx++) {
		if (!(i & 1)) 
			fprintf(ofp, "%s    %lx: ", i ? "\n" : "", addr);
		
		up = (ulong *)(&bt->stackbuf[u_idx*sizeof(ulong)]);
		fprintf(ofp, "%016lx ", *up);
		addr += sizeof(ulong);
	}
	fprintf(ofp, "\n");
}

/*
 *  Check a frame for a requested reference.
 */
static void
x86_64_do_bt_reference_check(struct bt_info *bt, ulong text, char *name)
{
	struct syment *sp;
	ulong offset;

	if (!name)
		sp = value_search(text, &offset); 
	else if (!text)
		sp = symbol_search(name);

        switch (bt->ref->cmdflags & (BT_REF_SYMBOL|BT_REF_HEXVAL))
        {
        case BT_REF_SYMBOL:
                if (name) {
			if (STREQ(name, bt->ref->str))
                        	bt->ref->cmdflags |= BT_REF_FOUND;
		} else {
			if (sp && !offset && STREQ(sp->name, bt->ref->str))
                        	bt->ref->cmdflags |= BT_REF_FOUND;
		}
                break;

        case BT_REF_HEXVAL:
                if (text) {
			if (bt->ref->hexval == text) 
                        	bt->ref->cmdflags |= BT_REF_FOUND;
		} else if (sp && (bt->ref->hexval == sp->value))
                       	bt->ref->cmdflags |= BT_REF_FOUND;
		else if (!name && !text && (bt->ref->hexval == 0))
			bt->ref->cmdflags |= BT_REF_FOUND;
                break;
        }
}

/*
 *  print one entry of a stack trace
 */
#define BACKTRACE_COMPLETE                   (1)
#define BACKTRACE_ENTRY_IGNORED              (2)
#define BACKTRACE_ENTRY_DISPLAYED            (3)
#define BACKTRACE_ENTRY_AND_EFRAME_DISPLAYED (4)

static int
x86_64_print_stack_entry(struct bt_info *bt, FILE *ofp, int level, 
	int stkindex, ulong text)
{
	ulong rsp, offset;
	struct syment *sp;
	char *name;
	int result; 
	long eframe_check;
	char buf[BUFSIZE];

	eframe_check = -1;
	offset = 0;
	sp = value_search(text, &offset);
	if (!sp)
		return BACKTRACE_ENTRY_IGNORED;

	name = sp->name;

	if (bt->flags & BT_TEXT_SYMBOLS) {
		if (bt->flags & BT_EXCEPTION_FRAME)
			rsp = bt->stkptr;
		else
			rsp = bt->stackbase + (stkindex * sizeof(long));
                fprintf(ofp, "  [%s] %s at %lx\n",
                	mkstring(buf, VADDR_PRLEN, RJUST|LONG_HEX, MKSTR(rsp)),
                        name, text);
		if (BT_REFERENCE_CHECK(bt))
			x86_64_do_bt_reference_check(bt, text, name);
		return BACKTRACE_ENTRY_DISPLAYED;
	}

	if (!offset && !(bt->flags & BT_EXCEPTION_FRAME) &&
	    !(bt->flags & BT_START)) { 
		if (STREQ(name, "child_rip")) {
			if (symbol_exists("kernel_thread"))
				name = "kernel_thread";
			else if (symbol_exists("arch_kernel_thread"))
				name = "arch_kernel_thread";
		}
		else if (!(bt->flags & BT_SCHEDULE)) {
			if (STREQ(name, "error_exit")) 
				eframe_check = 8;
			else {
				if (CRASHDEBUG(2))
					fprintf(ofp, 
		              "< ignoring text symbol with no offset: %s() >\n",
						sp->name);
				return BACKTRACE_ENTRY_IGNORED;
			}
		}
	}

	if (bt->flags & BT_SCHEDULE)
		name = "schedule";

        if (STREQ(name, "child_rip")) {
                if (symbol_exists("kernel_thread"))
                        name = "kernel_thread";
                else if (symbol_exists("arch_kernel_thread"))
                        name = "arch_kernel_thread";
		result = BACKTRACE_COMPLETE;
        } else if (STREQ(name, "cpu_idle"))
		result = BACKTRACE_COMPLETE;
	else
		result = BACKTRACE_ENTRY_DISPLAYED;

	if (bt->flags & BT_EXCEPTION_FRAME)
		rsp = bt->stkptr;
	else if (bt->flags & BT_START)
		rsp = bt->stkptr;
	else
		rsp = bt->stackbase + (stkindex * sizeof(long));

	if ((bt->flags & BT_FULL)) {
		if (bt->frameptr) 
			x86_64_display_full_frame(bt, rsp, ofp);
		bt->frameptr = rsp + sizeof(ulong);
	}

        fprintf(ofp, "%s#%d [%8lx] %s at %lx\n", level < 10 ? " " : "", level,
		rsp, name, text);

        if (bt->flags & BT_LINE_NUMBERS) {
                get_line_number(text, buf, FALSE);
                if (strlen(buf))
                        fprintf(ofp, "    %s\n", buf);
	}

	if (eframe_check >= 0) {
		if (x86_64_exception_frame(EFRAME_PRINT|EFRAME_VERIFY, 
		    bt->stackbase + (stkindex*sizeof(long)) + eframe_check,
		    NULL, bt, ofp))
			result = BACKTRACE_ENTRY_AND_EFRAME_DISPLAYED;
	}

	if (BT_REFERENCE_CHECK(bt))
		x86_64_do_bt_reference_check(bt, text, name);

	bt->call_target = name;

	if (is_direct_call_target(bt)) {
		if (CRASHDEBUG(2))
			fprintf(ofp, "< enable BT_CHECK_CALLER for %s >\n", 
				bt->call_target);
		bt->flags |= BT_CHECK_CALLER;
	} else {
		if (CRASHDEBUG(2) && (bt->flags & BT_CHECK_CALLER))
			fprintf(ofp, "< disable BT_CHECK_CALLER for %s >\n", 
				bt->call_target);
		if (bt->flags & BT_CHECK_CALLER) {
			if (CRASHDEBUG(2))
			    	fprintf(ofp, "< set BT_NO_CHECK_CALLER >\n");
			bt->flags |= BT_NO_CHECK_CALLER;
		}
		bt->flags &= ~(ulonglong)BT_CHECK_CALLER;
	}

	return result;
}

/*
 *  Unroll a kernel stack.
 */
static void
x86_64_back_trace_cmd(struct bt_info *bt)
{
	error(FATAL, "x86_64_back_trace_cmd: TBD\n");
}



/*
 *  Determine whether the initial stack pointer is located in one of the
 *  exception stacks.
 */
static ulong
x86_64_in_exception_stack(struct bt_info *bt) 
{
	int c, i;
	ulong rsp;
	ulong estack;
	struct machine_specific *ms;

	rsp = bt->stkptr;
	ms = machdep->machspec;
	estack = 0;

        for (c = 0; !estack && (c < kt->cpus); c++) {
		for (i = 0; i < 7; i++) {
			if (ms->stkinfo.ebase[c][i] == 0)
				break;
			if ((rsp >= ms->stkinfo.ebase[c][i]) &&
			    (rsp < (ms->stkinfo.ebase[c][i] + 
			    ms->stkinfo.esize))) {
				estack = ms->stkinfo.ebase[c][i]; 
				if (CRASHDEBUG(1) && (c != bt->tc->processor)) 
					error(INFO, 
      		                      "task cpu: %d  exception stack cpu: %d\n",
						bt->tc->processor, c);
				break;
			}
		}
        }

	return estack;
}

/*
 *  Determine whether the current stack pointer is in a cpu's irqstack.
 */
static ulong
x86_64_in_irqstack(struct bt_info *bt) 
{
        int c;
        ulong rsp;
        ulong irqstack;
        struct machine_specific *ms;

        rsp = bt->stkptr;
        ms = machdep->machspec;
        irqstack = 0;

        for (c = 0; !irqstack && (c < kt->cpus); c++) {
                if (ms->stkinfo.ibase[c] == 0)
                 	break;
                if ((rsp >= ms->stkinfo.ibase[c]) &&
                    (rsp < (ms->stkinfo.ibase[c] + ms->stkinfo.isize))) {
                	irqstack = ms->stkinfo.ibase[c];
                        if (CRASHDEBUG(1) && (c != bt->tc->processor)) 
                                error(INFO, 
			          "task cpu: %d  IRQ stack cpu: %d\n",
                                	bt->tc->processor, c);
                        break;
                }
        }

        return irqstack;
}

#define STACK_TRANSITION_ERRMSG_E_I_P \
"cannot transition from exception stack to IRQ stack to current process stack:\n    exception stack pointer: %lx\n          IRQ stack pointer: %lx\n      process stack pointer: %lx\n         current stack base: %lx\n" 
#define STACK_TRANSITION_ERRMSG_E_P \
"cannot transition from exception stack to current process stack:\n    exception stack pointer: %lx\n      process stack pointer: %lx\n         current_stack_base: %lx\n"
#define STACK_TRANSITION_ERRMSG_I_P \
"cannot transition from IRQ stack to current process stack:\n        IRQ stack pointer: %lx\n    process stack pointer: %lx\n       current stack base: %lx"

/*
 *  Low-budget back tracer -- dump text return addresses, following call chain
 *  when possible, along with any verifiable exception frames.
 */
static void
x86_64_low_budget_back_trace_cmd(struct bt_info *bt_in)
{
	int i, level, done;
	ulong rsp, offset, stacktop;
	ulong *up;
	long cs;
	struct syment *sp, *spt;
	FILE *ofp;
	ulong estack, irqstack;
	ulong irq_eframe;
	struct bt_info bt_local, *bt;
	struct machine_specific *ms;
	ulong last_process_stack_eframe;
	ulong user_mode_eframe;

	bt = &bt_local;
	BCOPY(bt_in, bt, sizeof(struct bt_info));

	level = 0;
	done = FALSE;
	irq_eframe = 0;
	last_process_stack_eframe = 0;
	bt->call_target = NULL;
	rsp = bt->stkptr;
	if (!rsp) {
		error(INFO, "cannot determine starting stack pointer\n");
		return;
	}
	ms = machdep->machspec;
	if (BT_REFERENCE_CHECK(bt))
		ofp = pc->nullfp;
	else
		ofp = fp;

        if (bt->flags & BT_TEXT_SYMBOLS) {
		if (!(bt->flags & BT_TEXT_SYMBOLS_ALL))
                	fprintf(ofp, "%sSTART: %s%s at %lx\n",
                	    space(VADDR_PRLEN > 8 ? 14 : 6),
                	    closest_symbol(bt->instptr), 
			    STREQ(closest_symbol(bt->instptr), "thread_return") ?
			    " (schedule)" : "",
			    bt->instptr);
        } else if (bt->flags & BT_START) {
                x86_64_print_stack_entry(bt, ofp, level,
                        0, bt->instptr);
		bt->flags &= ~BT_START;
		level++;
	}


        if ((estack = x86_64_in_exception_stack(bt))) {
in_exception_stack:
		bt->flags |= BT_EXCEPTION_STACK;
		/*
	 	 *  The stack buffer will have been loaded with the process
		 *  stack, so switch to the indicated exception stack.
		 */
                bt->stackbase = estack;
                bt->stacktop = estack + ms->stkinfo.esize;
                bt->stackbuf = ms->irqstack;

                if (!readmem(bt->stackbase, KVADDR, bt->stackbuf,
                    bt->stacktop - bt->stackbase,
		    bt->hp && (bt->hp->esp == bt->stkptr) ? 
	 	    "irqstack contents via hook" : "irqstack contents", 
		    RETURN_ON_ERROR))
                    	error(FATAL, "read of exception stack at %lx failed\n",
                        	bt->stackbase);

		/*
	 	 *  If irq_eframe is set, we've jumped back here from the
		 *  IRQ stack dump below.  Do basically the same thing as if
		 *  had come from the processor stack, but presume that we
		 *  must have been in kernel mode, i.e., took an exception
	 	 *  while operating on an IRQ stack.  (untested)
		 */
                if (irq_eframe) {
                        bt->flags |= BT_EXCEPTION_FRAME;
                        i = (irq_eframe - bt->stackbase)/sizeof(ulong);
                        x86_64_print_stack_entry(bt, ofp, level, i, 
				bt->instptr);
                        bt->flags &= ~(ulonglong)BT_EXCEPTION_FRAME;
                        cs = x86_64_exception_frame(EFRAME_PRINT|EFRAME_CS, 0,
                        	bt->stackbuf + (irq_eframe - bt->stackbase), 
				bt, ofp);
                        rsp += SIZE(pt_regs);  /* guaranteed kernel mode */
                        level++;
                        irq_eframe = 0;
                }

		stacktop = bt->stacktop - SIZE(pt_regs);

        	for (i = (rsp - bt->stackbase)/sizeof(ulong);
	     	    !done && (rsp < stacktop); i++, rsp += sizeof(ulong)) {

			up = (ulong *)(&bt->stackbuf[i*sizeof(ulong)]);

			if (!is_kernel_text(*up))
		        	continue;

	                switch (x86_64_print_stack_entry(bt, ofp, level, i,*up))
	                {
	                case BACKTRACE_ENTRY_AND_EFRAME_DISPLAYED:
				rsp += SIZE(pt_regs);
				i += SIZE(pt_regs)/sizeof(ulong);
	                case BACKTRACE_ENTRY_DISPLAYED:
	                        level++;
	                        break;
	                case BACKTRACE_ENTRY_IGNORED:
	                        break;
	                case BACKTRACE_COMPLETE:
	                        done = TRUE;
	                        break;
	                }
		}

                cs = x86_64_exception_frame(EFRAME_PRINT|EFRAME_CS, 0, 
			bt->stackbuf + (bt->stacktop - bt->stackbase) - 
			SIZE(pt_regs), bt, ofp);

		if (!BT_REFERENCE_CHECK(bt))
			fprintf(fp, "--- <exception stack> ---\n");

                /* 
		 *  stack = (unsigned long *) estack_end[-2]; 
		 */
		up = (ulong *)(&bt->stackbuf[bt->stacktop - bt->stackbase]);
		up -= 2;
		rsp = bt->stkptr = *up;
		up -= 3;
		bt->instptr = *up;  
		if (cs & 3)
			done = TRUE;   /* user-mode exception */
		else
			done = FALSE;  /* kernel-mode exception */
		bt->frameptr = 0;

		/*
		 *  Print the return values from the estack end.
		 */
		if (!done) {
                	bt->flags |= BT_START;
                	x86_64_print_stack_entry(bt, ofp, level,
                        	0, bt->instptr);
                	bt->flags &= ~BT_START;
			level++;
		}
	}

	/*
	 *  IRQ stack entry always comes in via the process stack, regardless
	 *  whether it happened while running in user or kernel space.
	 */
        if (!done && (irqstack = x86_64_in_irqstack(bt))) {
		bt->flags |= BT_IRQSTACK;
		/*
		 *  Until coded otherwise, the stackbase will be pointing to
		 *  either the exception stack or, more likely, the process
		 *  stack base.  Switch it to the IRQ stack.
		 */
                bt->stackbase = irqstack;
                bt->stacktop = irqstack + ms->stkinfo.isize;
                bt->stackbuf = ms->irqstack;

                if (!readmem(bt->stackbase, KVADDR, 
	  	    bt->stackbuf, bt->stacktop - bt->stackbase,
                    bt->hp && (bt->hp->esp == bt_in->stkptr) ?
		    "irqstack contents via hook" : "irqstack contents", 
		    RETURN_ON_ERROR))
                    	error(FATAL, "read of IRQ stack at %lx failed\n",
				bt->stackbase);

		stacktop = bt->stacktop - 64; /* from kernel code */

                for (i = (rsp - bt->stackbase)/sizeof(ulong);
                    !done && (rsp < stacktop); i++, rsp += sizeof(ulong)) {

                        up = (ulong *)(&bt->stackbuf[i*sizeof(ulong)]);

                        if (!is_kernel_text(*up))
                                continue;

                        switch (x86_64_print_stack_entry(bt, ofp, level, i,*up))
                        {
			case BACKTRACE_ENTRY_AND_EFRAME_DISPLAYED:
				rsp += SIZE(pt_regs);
				i += SIZE(pt_regs)/sizeof(ulong);
                        case BACKTRACE_ENTRY_DISPLAYED:
                                level++;
                                break;
                        case BACKTRACE_ENTRY_IGNORED:
                                break;
                        case BACKTRACE_COMPLETE:
                                done = TRUE;
                                break;
                        }
                }

		if (!BT_REFERENCE_CHECK(bt))
                	fprintf(fp, "--- <IRQ stack> ---\n");

                /*
		 *  stack = (unsigned long *) (irqstack_end[-1]);
		 *  (where irqstack_end is 64 bytes below page end)
                 */
                up = (ulong *)(&bt->stackbuf[stacktop - bt->stackbase]);
                up -= 1;
                irq_eframe = rsp = bt->stkptr = *up;
		up -= 1;
                bt->instptr = *up;
                bt->frameptr = 0;
                done = FALSE;
        } else
		irq_eframe = 0;

        if (!done && (estack = x86_64_in_exception_stack(bt))) 
		goto in_exception_stack;

	if (!done && (bt->flags & (BT_EXCEPTION_STACK|BT_IRQSTACK))) {
		/*
		 *  Verify that the rsp pointer taken from either the
		 *  exception or IRQ stack points into the process stack.
		 */
		bt->stackbase = GET_STACKBASE(bt->tc->task);
		bt->stacktop = GET_STACKTOP(bt->tc->task);

		if (!INSTACK(rsp, bt)) {
			switch (bt->flags & (BT_EXCEPTION_STACK|BT_IRQSTACK))
			{
			case (BT_EXCEPTION_STACK|BT_IRQSTACK):
				error(FATAL, STACK_TRANSITION_ERRMSG_E_I_P,
					bt_in->stkptr, bt->stkptr, rsp,
					bt->stackbase);

			case BT_EXCEPTION_STACK:
				error(FATAL, STACK_TRANSITION_ERRMSG_E_P,
					bt_in->stkptr, rsp, bt->stackbase);

			case BT_IRQSTACK:
				error(FATAL, STACK_TRANSITION_ERRMSG_I_P,
					bt_in->stkptr, rsp, bt->stackbase);
			}
		}

		/*
	 	 *  Now fill the local stack buffer from the process stack.
	  	 */
               	if (!readmem(bt->stackbase, KVADDR, bt->stackbuf,
                    bt->stacktop - bt->stackbase, 
		    "irqstack contents", RETURN_ON_ERROR))
                	error(FATAL, "read of process stack at %lx failed\n",
				bt->stackbase);
	}

	/*
	 *  For a normally blocked task, hand-create the first level.
	 */
        if (!done && 
	    !(bt->flags & (BT_TEXT_SYMBOLS|BT_EXCEPTION_STACK|BT_IRQSTACK)) &&
	    STREQ(closest_symbol(bt->instptr), "thread_return")) {
		bt->flags |= BT_SCHEDULE;
		i = (rsp - bt->stackbase)/sizeof(ulong);
		x86_64_print_stack_entry(bt, ofp, level, 
			i, bt->instptr);
		bt->flags &= ~(ulonglong)BT_SCHEDULE;
		rsp += sizeof(ulong);
		level++;
	}

	/*
	 *  Dump the IRQ exception frame from the process stack.
	 *  If the CS register indicates a user exception frame,
	 *  then set done to TRUE to avoid the process stack walk-through.
	 *  Otherwise, bump up the rsp past the kernel-mode eframe.
	 */
        if (irq_eframe) {
                bt->flags |= BT_EXCEPTION_FRAME;
                i = (irq_eframe - bt->stackbase)/sizeof(ulong);
                x86_64_print_stack_entry(bt, ofp, level, i, bt->instptr);
                bt->flags &= ~(ulonglong)BT_EXCEPTION_FRAME;
                cs = x86_64_exception_frame(EFRAME_PRINT|EFRAME_CS, 0, 
			bt->stackbuf + (irq_eframe - bt->stackbase), bt, ofp);
		if (cs & 3)
			done = TRUE;   /* IRQ from user-mode */
		else {
			if (x86_64_print_eframe_location(rsp, level, ofp))
				level++;
			rsp += SIZE(pt_regs);
			irq_eframe = 0;
		}
		level++;
        }

	/*
	 *  Walk the process stack.  
	 */
        for (i = (rsp - bt->stackbase)/sizeof(ulong);
	     !done && (rsp < bt->stacktop); i++, rsp += sizeof(ulong)) {

		up = (ulong *)(&bt->stackbuf[i*sizeof(ulong)]);

		if (!is_kernel_text(*up))
			continue;

		if ((bt->flags & BT_CHECK_CALLER)) {
			/*
			 *  A non-zero offset value from the value_search() 
			 *  lets us know if it's a real text return address.
			 */
			spt = value_search(*up, &offset);
			/*
		         *  sp gets the syment of the function that the text 
			 *  routine above called before leaving its return 
			 *  address on the stack -- if it can be determined.
			 */
			sp = x86_64_function_called_by((*up)-5); 

			if (sp == NULL) {
				/* 
				 *  We were unable to get the called function.
				 *  If the text address had an offset, then
				 *  it must have made an indirect call, and
				 *  can't have called our target function.
				 */
				if (offset) {
					if (CRASHDEBUG(1))
						fprintf(ofp, 
                       "< ignoring %s() -- makes indirect call and NOT %s()>\n",
						    	spt->name, 
						    	bt->call_target);
					continue;
				}
			} else if ((machdep->flags & SCHED_TEXT) &&
				STREQ(bt->call_target, "schedule") &&
				STREQ(sp->name, "__sched_text_start")) {
				;  /*  bait and switch */
			} else if (!STREQ(sp->name, bt->call_target)) {
				/*
				 *  We got function called by the text routine,
			 	 *  but it's not our target function.
				 */
				if (CRASHDEBUG(2))
					fprintf(ofp, 
 		                "< ignoring %s() -- calls %s() and NOT %s()>\n",
						spt->name, sp->name, 
						bt->call_target);
				continue;
			}
		}

		switch (x86_64_print_stack_entry(bt, ofp, level, i,*up))
		{
		case BACKTRACE_ENTRY_AND_EFRAME_DISPLAYED:
			last_process_stack_eframe = rsp + 8;
			if (x86_64_print_eframe_location(last_process_stack_eframe, level, ofp))
				level++;
			rsp += SIZE(pt_regs);
			i += SIZE(pt_regs)/sizeof(ulong);
		case BACKTRACE_ENTRY_DISPLAYED:
			level++;
			break;
		case BACKTRACE_ENTRY_IGNORED:	
			break;
		case BACKTRACE_COMPLETE:
			done = TRUE;
			break;
		}
        }

        if (!irq_eframe && !is_kernel_thread(bt->tc->task) &&
            (GET_STACKBASE(bt->tc->task) == bt->stackbase)) {
		user_mode_eframe = bt->stacktop - SIZE(pt_regs);
		if (last_process_stack_eframe < user_mode_eframe)
                	x86_64_exception_frame(EFRAME_PRINT, 0, bt->stackbuf +
                        	(bt->stacktop - bt->stackbase) - SIZE(pt_regs),
                        	bt, ofp);
	}

        if (bt->flags & BT_TEXT_SYMBOLS) {
        	if (BT_REFERENCE_FOUND(bt)) {
                	print_task_header(fp, task_to_context(bt->task), 0);
			BCOPY(bt_in, bt, sizeof(struct bt_info));
                	bt->ref = NULL;
                	machdep->back_trace(bt);
                	fprintf(fp, "\n");
        	}
	}
}

/*
 *  Functions that won't be called indirectly.
 *  Add more to this as they are discovered.
 */
static const char *direct_call_targets[] = {
        "schedule",
        "schedule_timeout",
	NULL
};

static int
is_direct_call_target(struct bt_info *bt)
{
	int i;

	if (!bt->call_target || (bt->flags & BT_NO_CHECK_CALLER))
		return FALSE;

	for (i = 0; direct_call_targets[i]; i++) {
		if (STREQ(direct_call_targets[i], bt->call_target)) 
			return TRUE;
	}

	return FALSE;
}

static struct syment *
x86_64_function_called_by(ulong rip)
{
	struct syment *sp;
	char buf[BUFSIZE], *p1;
	ulong value, offset;
	unsigned char byte;

	value = 0;
	sp = NULL;

        if (!readmem(rip, KVADDR, &byte, sizeof(unsigned char), "call byte",
            RETURN_ON_ERROR)) 
		return sp;

        if (byte != 0xe8) 
		return sp;

        sprintf(buf, "x/i 0x%lx", rip);

        open_tmpfile2();
	if (gdb_pass_through(buf, pc->tmpfile2, GNU_RETURN_ON_ERROR)) {
	        rewind(pc->tmpfile2);
	        while (fgets(buf, BUFSIZE, pc->tmpfile2)) {
			if ((p1 = strstr(buf, "callq")) &&
			    whitespace(*(p1-1))) { 
				if (extract_hex(p1, &value, NULLCHAR, TRUE)) 
					break;
			}
		}
	}
        close_tmpfile2();

	if (value)
		sp = value_search(value, &offset);

	return sp;
}

/*
 *  Unroll the kernel stack using a minimal amount of gdb services.
 */
static void
x86_64_back_trace(struct gnu_request *req, struct bt_info *bt)
{
	error(FATAL, "x86_64_back_trace: unused\n");
}


/*
 *  Print exception frame information for x86_64.
 *
 *    Pid: 0, comm: swapper Not tainted 2.6.5-1.360phro.rootsmp
 *    RIP: 0010:[<ffffffff8010f534>] <ffffffff8010f534>{default_idle+36}
 *    RSP: 0018:ffffffff8048bfd8  EFLAGS: 00000246
 *    RAX: 0000000000000000 RBX: ffffffff8010f510 RCX: 0000000000000018
 *    RDX: 0000010001e37280 RSI: ffffffff803ac0a0 RDI: 000001007f43c400
 *    RBP: 0000000000000000 R08: ffffffff8048a000 R09: 0000000000000000
 *    R10: ffffffff80482188 R11: 0000000000000001 R12: 0000000000000000
 *    R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
 *    FS:  0000002a96e14fc0(0000) GS:ffffffff80481d80(0000) GS:0000000055578aa0
 *    CS:  0010 DS: 0018 ES: 0018 CR0: 000000008005003b
 *    CR2: 0000002a9556b000 CR3: 0000000000101000 CR4: 00000000000006e0
 *
 */

static long 
x86_64_exception_frame(ulong flags, ulong kvaddr, char *local, 
	struct bt_info *bt, FILE *ofp)
{
        long rip, rsp, cs, ss, rflags, orig_rax, rbp; 
	long rax, rbx, rcx, rdx, rsi, rdi;
        long r8, r9, r10, r11, r12, r13, r14, r15;
	struct machine_specific *ms;
	struct syment *sp;
	ulong offset;
	char *pt_regs_buf;
	long verified;
	int err;

        ms = machdep->machspec;

	if (!(machdep->flags & PT_REGS_INIT)) {
		err = 0;
		err |= ((ms->pto.r15 = MEMBER_OFFSET("pt_regs", "r15")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.r14 = MEMBER_OFFSET("pt_regs", "r14")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.r13 = MEMBER_OFFSET("pt_regs", "r13")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.r12 = MEMBER_OFFSET("pt_regs", "r12")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.r11 = MEMBER_OFFSET("pt_regs", "r11")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.r10 = MEMBER_OFFSET("pt_regs", "r10")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.r9 = MEMBER_OFFSET("pt_regs", "r9")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.r8 = MEMBER_OFFSET("pt_regs", "r8")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.rax = MEMBER_OFFSET("pt_regs", "rax")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.rbx = MEMBER_OFFSET("pt_regs", "rbx")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.rcx = MEMBER_OFFSET("pt_regs", "rcx")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.rdx = MEMBER_OFFSET("pt_regs", "rdx")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.rsi = MEMBER_OFFSET("pt_regs", "rsi")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.rdi = MEMBER_OFFSET("pt_regs", "rdi")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.rip = MEMBER_OFFSET("pt_regs", "rip")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.rsp = MEMBER_OFFSET("pt_regs", "rsp")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.cs = MEMBER_OFFSET("pt_regs", "cs")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.ss = MEMBER_OFFSET("pt_regs", "ss")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.eflags = MEMBER_OFFSET("pt_regs", "eflags")) ==
			INVALID_OFFSET);
		err |= ((ms->pto.orig_rax = 
			MEMBER_OFFSET("pt_regs", "orig_rax")) == 
			INVALID_OFFSET);
		err |= ((ms->pto.rbp = MEMBER_OFFSET("pt_regs", "rbp")) == 
			INVALID_OFFSET);

		if (err)
			error(WARNING, "pt_regs structure has changed\n");

		machdep->flags |= PT_REGS_INIT;
	}

	if (kvaddr) {
		pt_regs_buf = GETBUF(SIZE(pt_regs));
        	readmem(kvaddr, KVADDR, pt_regs_buf,
                	SIZE(pt_regs), "pt_regs", FAULT_ON_ERROR);
	} else
		pt_regs_buf = local;

	rip = ULONG(pt_regs_buf + ms->pto.rip);
	rsp = ULONG(pt_regs_buf + ms->pto.rsp);
	cs = ULONG(pt_regs_buf + ms->pto.cs);
	ss = ULONG(pt_regs_buf + ms->pto.ss);
	rflags = ULONG(pt_regs_buf + ms->pto.eflags);
	orig_rax = ULONG(pt_regs_buf + ms->pto.orig_rax);
	rbp = ULONG(pt_regs_buf + ms->pto.rbp);
	rax = ULONG(pt_regs_buf + ms->pto.rax);
	rbx = ULONG(pt_regs_buf + ms->pto.rbx);
	rcx = ULONG(pt_regs_buf + ms->pto.rcx);
	rdx = ULONG(pt_regs_buf + ms->pto.rdx);
	rsi = ULONG(pt_regs_buf + ms->pto.rsi);
	rdi = ULONG(pt_regs_buf + ms->pto.rdi);
	r8 = ULONG(pt_regs_buf + ms->pto.r8);
	r9 = ULONG(pt_regs_buf + ms->pto.r9);
	r10 = ULONG(pt_regs_buf + ms->pto.r10);
	r11 = ULONG(pt_regs_buf + ms->pto.r11);
	r12 = ULONG(pt_regs_buf + ms->pto.r12);
	r13 = ULONG(pt_regs_buf + ms->pto.r13);
	r14 = ULONG(pt_regs_buf + ms->pto.r14);
	r15 = ULONG(pt_regs_buf + ms->pto.r15);

        verified = x86_64_eframe_verify(bt, 
		kvaddr ? kvaddr : (local - bt->stackbuf) + bt->stackbase,
		cs, ss, rip, rsp, rflags);

	/*
	 *  If it's print-if-verified request, don't print bogus eframes.
	 */
        if (!verified && ((flags & (EFRAME_VERIFY|EFRAME_PRINT)) == 
	    (EFRAME_VERIFY|EFRAME_PRINT))) 
		flags &= ~EFRAME_PRINT;

	if (CRASHDEBUG(2)) 
		fprintf(ofp, "< exception frame at: %lx >\n", kvaddr ?  kvaddr :
			(local - bt->stackbuf) + bt->stackbase);

	if (flags & EFRAME_PRINT) {
		if (flags & EFRAME_SEARCH) {
			fprintf(ofp, "\n  %s-MODE EXCEPTION FRAME AT: %lx\n",
				cs & 3 ? "USER" : "KERNEL", 
				kvaddr ?  kvaddr : 
				(local - bt->stackbuf) + bt->stackbase);
		} else if (!(cs & 3)) {
			fprintf(ofp, "    [exception RIP: ");
			if ((sp = value_search(rip, &offset))) {
                		fprintf(ofp, "%s", sp->name);
                		if (offset)
                        		fprintf(ofp, (output_radix == 16) ? 
						"+0x%lx" : "+%ld", offset);
			} else
                		fprintf(ofp, "unknown or invalid address");
			fprintf(ofp, "]\n");
		}
		fprintf(ofp, "    RIP: %016lx  RSP: %016lx  RFLAGS: %08lx\n", 
			rip, rsp, rflags);
		fprintf(ofp, "    RAX: %016lx  RBX: %016lx  RCX: %016lx\n", 
			rax, rbx, rcx);
		fprintf(ofp, "    RDX: %016lx  RSI: %016lx  RDI: %016lx\n", 
	 		rdx, rsi, rdi);
		fprintf(ofp, "    RBP: %016lx   R8: %016lx   R9: %016lx\n", 
			rbp, r8, r9);
		fprintf(ofp, "    R10: %016lx  R11: %016lx  R12: %016lx\n", 
			r10, r11, r12);
		fprintf(ofp, "    R13: %016lx  R14: %016lx  R15: %016lx\n", 
			r13, r14, r15);
		fprintf(ofp, "    ORIG_RAX: %016lx  CS: %04lx  SS: %04lx\n", 
			orig_rax, cs, ss);

		if (!verified)
			error(WARNING, "possibly bogus exception frame\n");
	}

        if ((flags & EFRAME_PRINT) && BT_REFERENCE_CHECK(bt)) {
                x86_64_do_bt_reference_check(bt, rip, NULL);
                x86_64_do_bt_reference_check(bt, rsp, NULL);
                x86_64_do_bt_reference_check(bt, cs, NULL);
                x86_64_do_bt_reference_check(bt, ss, NULL);
                x86_64_do_bt_reference_check(bt, rflags, NULL);
                x86_64_do_bt_reference_check(bt, orig_rax, NULL);
                x86_64_do_bt_reference_check(bt, rbp, NULL);
                x86_64_do_bt_reference_check(bt, rax, NULL);
                x86_64_do_bt_reference_check(bt, rbx, NULL);
                x86_64_do_bt_reference_check(bt, rcx, NULL);
                x86_64_do_bt_reference_check(bt, rdx, NULL);
                x86_64_do_bt_reference_check(bt, rsi, NULL);
                x86_64_do_bt_reference_check(bt, rdi, NULL);
                x86_64_do_bt_reference_check(bt, r8, NULL);
                x86_64_do_bt_reference_check(bt, r9, NULL);
                x86_64_do_bt_reference_check(bt, r10, NULL);
                x86_64_do_bt_reference_check(bt, r11, NULL);
                x86_64_do_bt_reference_check(bt, r12, NULL);
                x86_64_do_bt_reference_check(bt, r13, NULL);
                x86_64_do_bt_reference_check(bt, r14, NULL);
                x86_64_do_bt_reference_check(bt, r15, NULL);
        }

	if (kvaddr)
		FREEBUF(pt_regs_buf);

	if (flags & EFRAME_CS)
		return cs;
	else if (flags & EFRAME_VERIFY)
		return verified;

	return 0;
}

static int 
x86_64_print_eframe_location(ulong eframe, int level, FILE *ofp)
{
	return FALSE;

#ifdef NOTDEF
	ulong rip;
	char *pt_regs_buf;
        struct machine_specific *ms;
        struct syment *sp;

        ms = machdep->machspec;

        pt_regs_buf = GETBUF(SIZE(pt_regs));
        if (!readmem(eframe, KVADDR, pt_regs_buf, SIZE(pt_regs), 
	    "pt_regs", RETURN_ON_ERROR|QUIET)) {
		FREEBUF(pt_regs_buf);
		return FALSE;
	}

        rip = ULONG(pt_regs_buf + ms->pto.rip);
	FREEBUF(pt_regs_buf);

        if (!(sp = value_search(rip, NULL)))
                return FALSE;

        fprintf(ofp, "%s#%d [%8lx] %s at %lx\n", level < 10 ? " " : "", level+1,
		eframe, sp->name, rip);

	return TRUE;
#endif
}

/*
 *  Check that the verifiable registers contain reasonable data.
 */
#define RAZ_MASK 0xffffffffffc08028    /* return-as-zero bits */

static int 
x86_64_eframe_verify(struct bt_info *bt, long kvaddr, long cs, long ss,
	long rip, long rsp, long rflags)
{
	if ((rflags & RAZ_MASK) || !(rflags & 0x2))
		return FALSE;

        if ((cs == 0x10) && (ss == 0x18)) {
                if (is_kernel_text(rip) && IS_KVADDR(rsp))
                        return TRUE;

                if (x86_64_is_module_addr(rip) &&
		    IS_KVADDR(rsp) &&
		    (rsp == (kvaddr + SIZE(pt_regs))))
                        return TRUE;
        }

        if ((cs == 0x10) && kvaddr) {
                if (is_kernel_text(rip) && IS_KVADDR(rsp) &&
		    (rsp == (kvaddr + SIZE(pt_regs) + 8)))
                        return TRUE;
	}

        if ((cs == 0x10) && kvaddr) {
                if (is_kernel_text(rip) && IS_KVADDR(rsp) &&
		    (rsp == (kvaddr + SIZE(pt_regs))))
                        return TRUE;
	}

        if ((cs == 0x33) && (ss == 0x2b)) {
                if (IS_UVADDR(rip, bt->tc) && IS_UVADDR(rsp, bt->tc))
                        return TRUE;
        }

        if (XEN() && ((cs == 0x33) || (cs == 0xe033)) && 
	    ((ss == 0x2b) || (ss == 0xe02b))) {
                if (IS_UVADDR(rip, bt->tc) && IS_UVADDR(rsp, bt->tc))
                        return TRUE;
        }

	if (XEN() && ((cs == 0x10000e030) || (cs == 0xe030)) && 
	    (ss == 0xe02b)) {
                if (is_kernel_text(rip) && IS_KVADDR(rsp))
                        return TRUE;
	}

	/* 
	 *  32-bit segments 
	 */
        if ((cs == 0x23) && (ss == 0x2b)) {
                if (IS_UVADDR(rip, bt->tc) && IS_UVADDR(rsp, bt->tc))
                        return TRUE;
        }

	return FALSE;
}

/*
 *  Get a stack frame combination of pc and ra from the most relevent spot.
 */
static void
x86_64_get_stack_frame(struct bt_info *bt, ulong *pcp, ulong *spp)
{
	if (bt->flags & BT_DUMPFILE_SEARCH)
		return x86_64_get_dumpfile_stack_frame(bt, pcp, spp);

        if (pcp)
                *pcp = x86_64_get_pc(bt);
        if (spp)
                *spp = x86_64_get_sp(bt);
}

/*
 *  Get the starting point for the active cpus in a diskdump/netdump.
 */
static void
x86_64_get_dumpfile_stack_frame(struct bt_info *bt_in, ulong *rip, ulong *rsp) 
{
	int panic_task;
        int i, estack, panic, stage;
        char *sym;
	struct syment *sp;
        ulong *up;
	struct bt_info bt_local, *bt;
        struct machine_specific *ms;
	char *user_regs;
	ulong ur_rip;
	ulong ur_rsp;

        bt = &bt_local;
        BCOPY(bt_in, bt, sizeof(struct bt_info));
        ms = machdep->machspec;
	ur_rip = ur_rsp = 0;
	stage = 0;
	estack = -1;

	panic_task = tt->panic_task == bt->task ? TRUE : FALSE;

	if (panic_task && bt->machdep) {
		user_regs = bt->machdep;

		if (x86_64_eframe_verify(bt, 
		    0,
		    ULONG(user_regs + OFFSET(user_regs_struct_cs)),
		    ULONG(user_regs + OFFSET(user_regs_struct_ss)),
		    ULONG(user_regs + OFFSET(user_regs_struct_rip)),
        	    ULONG(user_regs + OFFSET(user_regs_struct_rsp)),
		    ULONG(user_regs + OFFSET(user_regs_struct_eflags)))) {
			bt->stkptr = ULONG(user_regs + 
				OFFSET(user_regs_struct_rsp));
			if (x86_64_in_irqstack(bt)) {
				ur_rip = ULONG(user_regs + 
					OFFSET(user_regs_struct_rip));
				ur_rsp = ULONG(user_regs + 
					OFFSET(user_regs_struct_rsp));
				goto skip_stage;
			}
		}
	}

	panic = FALSE;

	/*
	 *  Check the process stack first.
	 */
next_stack:
        for (i = 0, up = (ulong *)bt->stackbuf; 
	     i < (bt->stacktop - bt->stackbase)/sizeof(ulong); i++, up++) {
                sym = closest_symbol(*up);

                if (STREQ(sym, "netconsole_netdump") || 
		    STREQ(sym, "netpoll_start_netdump") ||
		    STREQ(sym, "start_disk_dump") ||
		    STREQ(sym, "disk_dump") ||
		    STREQ(sym, "crash_kexec") ||
		    STREQ(sym, "try_crashdump")) {
                        *rip = *up;
                        *rsp = bt->stackbase + ((char *)(up) - bt->stackbuf);
                        return;
                }

                if ((estack >= 0) && 
                    (STREQ(sym, "nmi_watchdog_tick") ||
                     STREQ(sym, "default_do_nmi"))) {
			sp = x86_64_function_called_by((*up)-5);
			if (!sp || !STREQ(sp->name, "die_nmi")) 
				continue;
                        *rip = *up;
                        *rsp = bt->stackbase + ((char *)(up) - bt->stackbuf);
			bt_in->flags |= BT_START;
			*rip = symbol_value("die_nmi");
			*rsp = (*rsp) - (7*sizeof(ulong));
                        return;
                }

                if (STREQ(sym, "panic")) {
                        *rip = *up;
                        *rsp = bt->stackbase + ((char *)(up) - bt->stackbuf);
                        panic = TRUE;
                        continue;   /* keep looking for die */
                }

                if (STREQ(sym, "die")) {
                        *rip = *up;
                        *rsp = bt->stackbase + ((char *)(up) - bt->stackbuf);
                        for (i++, up++; i < LONGS_PER_STACK; i++, up++) {
                                sym = closest_symbol(*up);
                                if (STREQ(sym, "sysrq_handle_crash"))
                                        goto next_sysrq;
                        }
                        return;
                }

                if (STREQ(sym, "sysrq_handle_crash")) {
next_sysrq:
                        *rip = *up;
                        *rsp = bt->stackbase + ((char *)(up) - bt->stackbuf);
                        pc->flags |= SYSRQ;
                        for (i++, up++; i < LONGS_PER_STACK; i++, up++) {
                                sym = closest_symbol(*up);
                                if (STREQ(sym, "sysrq_handle_crash"))
                                        goto next_sysrq;
                        }
                        return;
                }

                if (!panic_task && (stage > 0) && 
		    STREQ(sym, "smp_call_function_interrupt")) {
                        *rip = *up;
                        *rsp = bt->stackbase + ((char *)(up) - bt->stackbuf);
			return;
                }

                if (!panic_task && STREQ(sym, "crash_nmi_callback")) {
                        *rip = *up;
                        *rsp = bt->stackbase + ((char *)(up) - bt->stackbuf);
                        return;
                }
	}

	if (panic) 
		return;

skip_stage:
	switch (stage) 
	{
	/*
         *  Now check the processor's interrupt stack.
         */
	case 0:
		bt->stackbase = ms->stkinfo.ibase[bt->tc->processor];
		bt->stacktop = ms->stkinfo.ibase[bt->tc->processor] + 
			ms->stkinfo.isize;
		console("x86_64_get_dumpfile_stack_frame: searching IRQ stack at %lx\n", 
			bt->stackbase);
		bt->stackbuf = ms->irqstack;
		alter_stackbuf(bt);
		stage = 1;
		goto next_stack;

        /*
         *  Check the exception stacks.
         */
	case 1:
		if (++estack == 7)
			break;
		bt->stackbase = ms->stkinfo.ebase[bt->tc->processor][estack];
		bt->stacktop = ms->stkinfo.ebase[bt->tc->processor][estack] +
                	ms->stkinfo.esize;
		console("x86_64_get_dumpfile_stack_frame: searching %s estack at %lx\n", 
			x86_64_exception_stacks[estack], bt->stackbase);
		if (!(bt->stackbase)) 
			goto skip_stage;
		bt->stackbuf = ms->irqstack;
		alter_stackbuf(bt);
		goto next_stack;

	}

	/*
	 *  We didn't find what we were looking for, so just use what was
	 *  passed in from the ELF header.
	 */
	if (ur_rip && ur_rsp) {
        	*rip = ur_rip;
		*rsp = ur_rsp;
	}

        console("x86_64_get_dumpfile_stack_frame: cannot find anything useful\n");

	bt->flags &= ~(ulonglong)BT_DUMPFILE_SEARCH;

        machdep->get_stack_frame(bt, rip, rsp);
}

/*
 *  Get the saved RSP from the task's thread_struct.
 */
static ulong
x86_64_get_sp(struct bt_info *bt)
{
        ulong offset, rsp;

        if (tt->flags & THREAD_INFO) {
                readmem(bt->task + OFFSET(task_struct_thread) +
			OFFSET(thread_struct_rsp), KVADDR,
                        &rsp, sizeof(void *),
                        "thread_struct rsp", FAULT_ON_ERROR);
                return rsp;
        }

        offset = OFFSET(task_struct_thread) + OFFSET(thread_struct_rsp); 

        return GET_STACK_ULONG(offset);
}

/*
 *  Get the saved PC from the task's thread_struct if it exists;
 *  otherwise just use the "thread_return" label value.
 */
static ulong
x86_64_get_pc(struct bt_info *bt)
{
        ulong offset, rip;

	if (INVALID_MEMBER(thread_struct_rip))
		return symbol_value("thread_return");

        if (tt->flags & THREAD_INFO) {
                readmem(bt->task + OFFSET(task_struct_thread) +
                        OFFSET(thread_struct_rip), KVADDR,
                        &rip, sizeof(void *),
                        "thread_struct rip", FAULT_ON_ERROR);
                return rip;
        }

        offset = OFFSET(task_struct_thread) + OFFSET(thread_struct_rip);

        return GET_STACK_ULONG(offset);
}


/*
 *  Do the work for x86_64_get_sp() and x86_64_get_pc().
 */
static void
get_x86_64_frame(struct bt_info *bt, ulong *getpc, ulong *getsp)
{
	error(FATAL, "get_x86_64_frame: TBD\n");
}

/*
 *  Do the work for cmd_irq().
 */
static void 
x86_64_dump_irq(int irq)
{
        if (symbol_exists("irq_desc")) {
                machdep->dump_irq = generic_dump_irq;
                return(generic_dump_irq(irq));
        }

        error(FATAL, "ia64_dump_irq: irq_desc[] does not exist?\n");
}

/* 
 *  Do the work for irq -d
 */
void 
x86_64_display_idt_table(void)
{
	int i;
	char *idt_table_buf;
	char buf[BUFSIZE];
	ulong *ip;

	idt_table_buf = GETBUF(SIZE(gate_struct) * 256);
        readmem(symbol_value("idt_table"), KVADDR, idt_table_buf, 
		SIZE(gate_struct) * 256, "idt_table", FAULT_ON_ERROR);
	ip = (ulong *)idt_table_buf;

	for (i = 0; i < 256; i++, ip += 2) {
                if (i < 10)
                        fprintf(fp, "  ");
                else if (i < 100)
                        fprintf(fp, " ");
                fprintf(fp, "[%d] %s\n",
                        i, x86_64_extract_idt_function(ip, buf, NULL));
	}

	FREEBUF(idt_table_buf);
}

/*
 *  Extract the function name out of the IDT entry.
 */
static char *
x86_64_extract_idt_function(ulong *ip, char *buf, ulong *retaddr)
{
	ulong i1, i2, addr;
	char locbuf[BUFSIZE];
	physaddr_t phys;

	if (buf)
		BZERO(buf, BUFSIZE);

	i1 = *ip;
	i2 = *(ip+1);

	i2 <<= 32;
	addr = i2 & 0xffffffff00000000;
	addr |= (i1 & 0xffff);
	i1 >>= 32;
	addr |= (i1 & 0xffff0000);

	if (retaddr)
		*retaddr = addr;

	if (!buf)
		return NULL;

	value_to_symstr(addr, locbuf, 0);
	if (strlen(locbuf))
		sprintf(buf, locbuf);
	else {
		sprintf(buf, "%016lx", addr);
		if (kvtop(NULL, addr, &phys, 0)) {
			addr = machdep->kvbase + (ulong)phys;
			if (value_to_symstr(addr, locbuf, 0)) {
				strcat(buf, "  <");
				strcat(buf, locbuf);
				strcat(buf, ">");
			}
		}
	}

	return buf;
}

/*
 *  Filter disassembly output if the output radix is not gdb's default 10
 */
static int 
x86_64_dis_filter(ulong vaddr, char *inbuf)
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
 *  (on alpha -- not necessarily seen on x86_64) so this routine both fixes the 
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
	
        } else if (STREQ(argv[argc-2], "callq") &&
            hexadecimal(argv[argc-1], 0)) {
            	/*
             	 *  Update module code of the form:
             	 *
             	 *    callq  0xffffffffa0017aa0
	      	 *
             	 *  to show a bracketed direct call target.
             	 */
                p1 = &LASTCHAR(inbuf);

                if (extract_hex(argv[argc-1], &value, NULLCHAR, TRUE)) {
                        sprintf(buf1, " <%s>\n",
                                value_to_symstr(value, buf2,
                                pc->output_radix));
                        if (IS_MODULE_VADDR(value) &&
                            !strstr(buf2, "+"))
                                sprintf(p1, buf1);
                }
        }

	console("    %s", inbuf);

	return TRUE;
}


/*
 *   Override smp_num_cpus if possible and necessary.
 */
int
x86_64_get_smp_cpus(void)
{
	int i, cpus, nr_pda, cpunumber, _cpu_pda;
	char *cpu_pda_buf;
	ulong level4_pgt, cpu_pda_addr;

	if (!VALID_STRUCT(x8664_pda))
		return 1;

	cpu_pda_buf = GETBUF(SIZE(x8664_pda));

	if (symbol_exists("_cpu_pda")) {
		if (!(nr_pda = get_array_length("_cpu_pda", NULL, 0)))
        	       nr_pda = NR_CPUS;
		_cpu_pda = TRUE;
	} else {
		if (!(nr_pda = get_array_length("cpu_pda", NULL, 0)))
        	       nr_pda = NR_CPUS;
		_cpu_pda = FALSE;
	}
	for (i = cpus = 0; i < nr_pda; i++) {
		if (_cpu_pda) {
			if (!_CPU_PDA_READ(i, cpu_pda_buf))
				break;
		} else {
			if (!CPU_PDA_READ(i, cpu_pda_buf))
				break;
		}
		if (VALID_MEMBER(x8664_pda_level4_pgt)) {
			level4_pgt = ULONG(cpu_pda_buf + OFFSET(x8664_pda_level4_pgt));
			if (!VALID_LEVEL4_PGT_ADDR(level4_pgt))
				break;
		}
		cpunumber = INT(cpu_pda_buf + OFFSET(x8664_pda_cpunumber));
		if (cpunumber != cpus)
			break;
                cpus++;
	}

	FREEBUF(cpu_pda_buf);

	return cpus;
}

/*
 *  Machine dependent command.
 */
void
x86_64_cmd_mach(void)
{
        int c;

        while ((c = getopt(argcnt, args, "cm")) != EOF) {
                switch(c)
                {
                case 'c':
                        x86_64_display_cpu_data();
                        return;

                case 'm':
                        x86_64_display_memmap();
                        return;

                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

        x86_64_display_machine_stats();
}

/*
 *  "mach" command output.
 */
static void
x86_64_display_machine_stats(void)
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
	fprintf(fp, "   KERNEL START MAP: %lx\n", __START_KERNEL_map);
        fprintf(fp, "KERNEL MODULES BASE: %lx\n", MODULES_VADDR);
        fprintf(fp, "  KERNEL STACK SIZE: %ld\n", STACKSIZE());
}

/*
 *  "mach -c" 
 */
static void 
x86_64_display_cpu_data(void)
{
        int cpu, cpus, boot_cpu, _cpu_pda;
        ulong cpu_data;
	ulong cpu_pda, cpu_pda_addr;

	if (symbol_exists("cpu_data")) {
        	cpu_data = symbol_value("cpu_data");
		cpus = kt->cpus;
		boot_cpu = FALSE;
	} else if (symbol_exists("boot_cpu_data")) {
        	cpu_data = symbol_value("boot_cpu_data");
		boot_cpu = TRUE;
		cpus = 1;
	}
	if (symbol_exists("_cpu_pda")) {
		cpu_pda = symbol_value("_cpu_pda");
		_cpu_pda = TRUE;
	} else if (symbol_exists("cpu_pda")) {
		cpu_pda = symbol_value("cpu_pda");
		_cpu_pda = FALSE;
	}

        for (cpu = 0; cpu < cpus; cpu++) {
		if (boot_cpu)
                	fprintf(fp, "BOOT CPU:\n");
		else
                	fprintf(fp, "%sCPU %d:\n", cpu ? "\n" : "", cpu);

                dump_struct("cpuinfo_x86", cpu_data, 0);
		fprintf(fp, "\n");

		if (_cpu_pda) {
			readmem(cpu_pda, KVADDR, &cpu_pda_addr,
				sizeof(unsigned long), "_cpu_pda addr", FAULT_ON_ERROR);
			dump_struct("x8664_pda", cpu_pda_addr, 0);
			cpu_pda += sizeof(void *);
		} else {
			dump_struct("x8664_pda", cpu_pda, 0);
			cpu_pda += SIZE(x8664_pda);
		}
                cpu_data += SIZE(cpuinfo_x86);
        }
}

/*
 *  "mach -m"
 */
static char *e820type[] = {
        "(invalid type)",
        "E820_RAM",
        "E820_RESERVED",
        "E820_ACPI",
        "E820_NVS",
};

static void
x86_64_display_memmap(void)
{
        ulong e820;
        int nr_map, i;
        char *buf, *e820entry_ptr;
        ulonglong addr, size;
        uint type;

        e820 = symbol_value("e820");
	if (CRASHDEBUG(1))
		dump_struct("e820map", e820, RADIX(16));
        buf = (char *)GETBUF(SIZE(e820map));

        readmem(e820, KVADDR, &buf[0], SIZE(e820map),
                "e820map", FAULT_ON_ERROR);

        nr_map = INT(buf + OFFSET(e820map_nr_map));

        fprintf(fp, "      PHYSICAL ADDRESS RANGE         TYPE\n");

        for (i = 0; i < nr_map; i++) {
                e820entry_ptr = buf + sizeof(int) + (SIZE(e820entry) * i);
                addr = ULONGLONG(e820entry_ptr + OFFSET(e820entry_addr));
                size = ULONGLONG(e820entry_ptr + OFFSET(e820entry_size));
                type = UINT(e820entry_ptr + OFFSET(e820entry_type));
                fprintf(fp, "%016llx - %016llx  %s\n", addr, addr+size,
			e820type[type]);
        }
}


static const char *hook_files[] = {
        "arch/x86_64/kernel/entry.S",
        "arch/x86_64/kernel/head.S",
        "arch/x86_64/kernel/semaphore.c"
};

#define ENTRY_S      ((char **)&hook_files[0])
#define HEAD_S       ((char **)&hook_files[1])
#define SEMAPHORE_C  ((char **)&hook_files[2])

static struct line_number_hook x86_64_line_number_hooks[] = {
	{"ret_from_fork", ENTRY_S},
	{"system_call", ENTRY_S},
	{"int_ret_from_sys_call", ENTRY_S},
	{"ptregscall_common", ENTRY_S},
	{"stub_execve", ENTRY_S},
	{"stub_rt_sigreturn", ENTRY_S},
	{"common_interrupt", ENTRY_S},
	{"ret_from_intr", ENTRY_S},
	{"load_gs_index", ENTRY_S},
	{"arch_kernel_thread", ENTRY_S},
	{"execve", ENTRY_S},
	{"page_fault", ENTRY_S},
	{"coprocessor_error", ENTRY_S},
	{"simd_coprocessor_error", ENTRY_S},
	{"device_not_available", ENTRY_S},
	{"debug", ENTRY_S},
	{"nmi", ENTRY_S},
	{"int3", ENTRY_S},
	{"overflow", ENTRY_S},
	{"bounds", ENTRY_S},
	{"invalid_op", ENTRY_S},
	{"coprocessor_segment_overrun", ENTRY_S},
	{"reserved", ENTRY_S},
	{"double_fault", ENTRY_S},
	{"invalid_TSS", ENTRY_S},
	{"segment_not_present", ENTRY_S},
	{"stack_segment", ENTRY_S},
	{"general_protection", ENTRY_S},
	{"alignment_check", ENTRY_S},
	{"divide_error", ENTRY_S},
	{"spurious_interrupt_bug", ENTRY_S},
	{"machine_check", ENTRY_S},
	{"call_debug", ENTRY_S},

	{NULL, NULL}    /* list must be NULL-terminated */
};

static void
x86_64_dump_line_number(ulong callpc)
{
	error(FATAL, "x86_64_dump_line_number: TBD\n");
}

void
x86_64_compiler_warning_stub(void)
{
        struct line_number_hook *lhp;
        char **p;

        lhp = &x86_64_line_number_hooks[0]; lhp++;
        p = ENTRY_S;
	x86_64_back_trace(NULL, NULL);
	get_x86_64_frame(NULL, NULL, NULL);
	x86_64_dump_line_number(0);
}

/*
 *  Force the VM address-range selection via:
 *
 *   --machdep vm=orig 
 *   --machdep vm=2.6.11
 *  
 *  Force the phys_base address via:
 *
 *   --machdep phys_base=<address>
 */

void
parse_cmdline_arg(void)
{
	int i, c, errflag;
	char *p;
	char buf[BUFSIZE];
	char *arglist[MAXARGS];
	int megabytes;
	int lines = 0;
	ulong value;

	if (!strstr(machdep->cmdline_arg, "=")) {
		error(WARNING, "ignoring --machdep option: %s\n\n",
			machdep->cmdline_arg);
		return;
        }

	strcpy(buf, machdep->cmdline_arg);

	for (p = buf; *p; p++) {
		if (*p == ',')
			 *p = ' ';
	}

	c = parse_line(buf, arglist);

	for (i = 0; i < c; i++) {
		errflag = 0;

		if (STRNEQ(arglist[i], "vm=")) {
			p = arglist[i] + strlen("vm=");
			if (strlen(p)) {
				if (STREQ(p, "orig")) {
					machdep->flags |= VM_ORIG;
					continue;
				} else if (STREQ(p, "2.6.11")) {
					machdep->flags |= VM_2_6_11;
					continue;
				} else if (STREQ(p, "xen")) {
					machdep->flags |= VM_XEN;
					continue;
				}
			}
		} else if (STRNEQ(arglist[i], "phys_base=")) {
			megabytes = FALSE;
			if ((LASTCHAR(arglist[i]) == 'm') || 
			    (LASTCHAR(arglist[i]) == 'M')) {
				LASTCHAR(arglist[i]) = NULLCHAR;
				megabytes = TRUE;
			}
                        p = arglist[i] + strlen("phys_base=");
                        if (strlen(p)) {
				if (megabytes) {
                                	value = dtol(p, RETURN_ON_ERROR|QUIET,
                                        	&errflag);
				} else
                                	value = htol(p, RETURN_ON_ERROR|QUIET,
                                        	&errflag);
                                if (!errflag) {
					if (megabytes)
						value = MEGABYTES(value);
                                        machdep->machspec->phys_base = value;
                                        error(NOTE,
                                            "setting phys_base to: 0x%lx\n\n",
                                                machdep->machspec->phys_base);
					machdep->flags |= PHYS_BASE;
                                        continue;
                                }
                        }
                }

		error(WARNING, "ignoring --machdep option: %s\n", arglist[i]);
		lines++;
	} 

	switch (machdep->flags & (VM_ORIG|VM_2_6_11|VM_XEN))
	{
	case 0:
		break;

	case VM_ORIG:
		error(NOTE, "using original x86_64 VM address ranges\n");
		lines++;
		break;

	case VM_2_6_11:
		error(NOTE, "using 2.6.11 x86_64 VM address ranges\n");
		lines++;
		break;

	case VM_XEN:
		error(NOTE, "using xen x86_64 VM address ranges\n");
		lines++;
		break;

	default:
		error(WARNING, "cannot set multiple vm values\n");
		lines++;
		machdep->flags &= ~(VM_ORIG|VM_2_6_11|VM_XEN);
		break;
	} 

	if (lines)
		fprintf(fp, "\n");
}

void
x86_64_clear_machdep_cache(void)
{
	machdep->machspec->last_upml_read = 0;
}

#include "netdump.h"

/*
 *  Determine the physical address base for relocatable kernels.
 */
static void
x86_64_calc_phys_base(void)
{
	int i;
	FILE *iomem;
	char buf[BUFSIZE];
	char *p1;
	ulong phys_base, text_start, kernel_code_start;
	int errflag;
	struct vmcore_data *vd;
	Elf64_Phdr *phdr;

	if (machdep->flags & PHYS_BASE)     /* --machdep override */
		return;

	machdep->machspec->phys_base = 0;   /* default/traditional */

	if (!symbol_exists("phys_base"))
		return;

	if (!symbol_exists("_text"))
		return;
	else
		text_start = symbol_value("_text");

	if (ACTIVE()) {
	        if ((iomem = fopen("/proc/iomem", "r")) == NULL)
	                return;
	
		errflag = 1;
	        while (fgets(buf, BUFSIZE, iomem)) {
			if (strstr(buf, ": Kernel code")) {
				clean_line(buf);
				errflag = 0;
				break;
			}
		}
	        fclose(iomem);
	
		if (errflag)
			return;
	
		if (!(p1 = strstr(buf, "-")))
			return;
		else
			*p1 = NULLCHAR;
	
		errflag = 0;
		kernel_code_start = htol(buf, RETURN_ON_ERROR|QUIET, &errflag);
	        if (errflag)
			return;
	
		machdep->machspec->phys_base = kernel_code_start -
			(text_start - __START_KERNEL_map);
	
		if (CRASHDEBUG(1)) {
			fprintf(fp, "_text: %lx  ", text_start);
			fprintf(fp, "Kernel code: %lx -> ", kernel_code_start);
			fprintf(fp, "phys_base: %lx\n\n", 
				machdep->machspec->phys_base);
		}

		return;
	}

	/*
	 *  Get relocation value from whatever dumpfile format is being used.
	 */

	if (DISKDUMP_DUMPFILE()) {
		if (diskdump_phys_base(&phys_base)) {
			machdep->machspec->phys_base = phys_base;
			if (CRASHDEBUG(1))
				fprintf(fp, "compressed kdump: phys_base: %lx\n",
					phys_base);
		}
		return;
	}

	if ((vd = get_kdump_vmcore_data())) {
                for (i = 0; i < vd->num_pt_load_segments; i++) {
			phdr = vd->load64 + i;
			if ((phdr->p_vaddr >= __START_KERNEL_map) &&
			    !(IS_VMALLOC_ADDR(phdr->p_vaddr))) {

				machdep->machspec->phys_base = phdr->p_paddr - 
				    (phdr->p_vaddr & ~(__START_KERNEL_map));

				if (CRASHDEBUG(1)) {
					fprintf(fp, "p_vaddr: %lx p_paddr: %lx -> ",
						phdr->p_vaddr, phdr->p_paddr);
					fprintf(fp, "phys_base: %lx\n\n", 
						machdep->machspec->phys_base);
				}
				break;
			}
		}

		return;
	}
}

/*
 *  From the xen vmcore, create an index of mfns for each page that makes
 *  up the dom0 kernel's complete phys_to_machine_mapping[max_pfn] array.
 */

#define MAX_X86_64_FRAMES  (512)
#define MFNS_PER_FRAME     (PAGESIZE()/sizeof(ulong))

static int
x86_64_xen_kdump_p2m_create(struct xen_kdump_data *xkd)
{
        int i, j;
        ulong kvaddr;
        ulong *up;
        ulong frames;
        ulong frame_mfn[MAX_X86_64_FRAMES] = { 0 };
        int mfns[MAX_X86_64_FRAMES] = { 0 };

        /*
         *  Temporarily read physical (machine) addresses from vmcore by
         *  going directly to read_netdump() instead of via read_kdump().
         */
        pc->readmem = read_netdump;

        if (xkd->flags & KDUMP_CR3)
                goto use_cr3;

        if (CRASHDEBUG(1))
                fprintf(fp, "x86_64_xen_kdump_p2m_create: p2m_mfn: %lx\n", 
			xkd->p2m_mfn);

	if (!readmem(PTOB(xkd->p2m_mfn), PHYSADDR, xkd->page, PAGESIZE(), 
	    "xen kdump p2m mfn page", RETURN_ON_ERROR))
		error(FATAL, "cannot read xen kdump p2m mfn page\n");

	if (CRASHDEBUG(1))
		x86_64_debug_dump_page(fp, xkd->page, "pfn_to_mfn_frame_list");

	for (i = 0, up = (ulong *)xkd->page; i < MAX_X86_64_FRAMES; i++, up++)
		frame_mfn[i] = *up;

	for (i = 0; i < MAX_X86_64_FRAMES; i++) {
		if (!frame_mfn[i])
			break;

        	if (!readmem(PTOB(frame_mfn[i]), PHYSADDR, xkd->page, 
		    PAGESIZE(), "xen kdump p2m mfn list page", RETURN_ON_ERROR))
                	error(FATAL, "cannot read xen kdump p2m mfn list page\n");

		for (j = 0, up = (ulong *)xkd->page; j < MFNS_PER_FRAME; j++, up++)
			if (*up)
				mfns[i]++;

		xkd->p2m_frames += mfns[i];
		
	        if (CRASHDEBUG(7))
			x86_64_debug_dump_page(fp, xkd->page, "pfn_to_mfn_frame_list page");
	}

        if (CRASHDEBUG(1))
		fprintf(fp, "p2m_frames: %d\n", xkd->p2m_frames);

        if ((xkd->p2m_mfn_frame_list = (ulong *)
	    malloc(xkd->p2m_frames * sizeof(ulong))) == NULL)
                error(FATAL, "cannot malloc p2m_frame_index_list");

	for (i = 0, frames = xkd->p2m_frames; frames; i++) {
        	if (!readmem(PTOB(frame_mfn[i]), PHYSADDR, 
		    &xkd->p2m_mfn_frame_list[i * MFNS_PER_FRAME], 
		    mfns[i] * sizeof(ulong), "xen kdump p2m mfn list page", 
		    RETURN_ON_ERROR))
                	error(FATAL, "cannot read xen kdump p2m mfn list page\n");

		frames -= mfns[i];
	}

        pc->readmem = read_kdump;
	return FALSE;

use_cr3:

        if (CRASHDEBUG(1))
                fprintf(fp, "x86_64_xen_kdump_p2m_create: cr3: %lx\n", xkd->cr3);

        if (!readmem(PTOB(xkd->cr3), PHYSADDR, machdep->machspec->pml4, 
	    PAGESIZE(), "xen kdump cr3 page", RETURN_ON_ERROR))
                error(FATAL, "cannot read xen kdump cr3 page\n");

        if (CRASHDEBUG(7))
                x86_64_debug_dump_page(fp, machdep->machspec->pml4,
                        "contents of PML4 page:");

	kvaddr = symbol_value("end_pfn");
        if (!x86_64_xen_kdump_load_page(kvaddr, xkd->page))
                return FALSE;
        up = (ulong *)(xkd->page + PAGEOFFSET(kvaddr));

        xkd->p2m_frames = (*up/(PAGESIZE()/sizeof(ulong))) +
                ((*up%(PAGESIZE()/sizeof(ulong))) ? 1 : 0);

        if (CRASHDEBUG(1))
                fprintf(fp, "end_pfn at %lx: %lx (%ld) -> %d p2m_frames\n",
                        kvaddr, *up, *up, xkd->p2m_frames);

        if ((xkd->p2m_mfn_frame_list = (ulong *)
            malloc(xkd->p2m_frames * sizeof(ulong))) == NULL)
                error(FATAL, "cannot malloc p2m_frame_index_list");

        kvaddr = symbol_value("phys_to_machine_mapping");
        if (!x86_64_xen_kdump_load_page(kvaddr, xkd->page))
                return FALSE;
        up = (ulong *)(xkd->page + PAGEOFFSET(kvaddr));
        kvaddr = *up;
        if (CRASHDEBUG(1))
                fprintf(fp, "phys_to_machine_mapping: %lx\n", kvaddr);

        machdep->last_pgd_read = BADADDR;
        machdep->last_pmd_read = BADADDR;
        machdep->last_ptbl_read = BADADDR;

        for (i = 0; i < xkd->p2m_frames; i++) {
                xkd->p2m_mfn_frame_list[i] = x86_64_xen_kdump_page_mfn(kvaddr);
                kvaddr += PAGESIZE();
        }

        if (CRASHDEBUG(1)) {
                for (i = 0; i < xkd->p2m_frames; i++)
                        fprintf(fp, "%lx ", xkd->p2m_mfn_frame_list[i]);
                fprintf(fp, "\n");
        }

	machdep->last_pgd_read = 0;
        machdep->last_ptbl_read = 0;
        machdep->last_pmd_read = 0;
        pc->readmem = read_kdump;

        return TRUE;
}

static char *
x86_64_xen_kdump_load_page(ulong kvaddr, char *pgbuf)
{
	ulong mfn;
	ulong *pml4, *pgd, *pmd, *ptep;

        pml4 = ((ulong *)machdep->machspec->pml4) + pml4_index(kvaddr);
	mfn = ((*pml4) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

	if (CRASHDEBUG(3))
		fprintf(fp, 
		    "[%lx] pml4: %lx  mfn: %lx  pml4_index: %lx\n", 
			kvaddr, *pml4, mfn, pml4_index(kvaddr));

        if (!readmem(PTOB(mfn), PHYSADDR, machdep->pgd, PAGESIZE(),
            "xen kdump pud page", RETURN_ON_ERROR))
		error(FATAL, "cannot read/find pud page\n");
        
        if (CRASHDEBUG(7))
		x86_64_debug_dump_page(fp, machdep->pgd, 
                	"contents of page upper directory page:");

        pgd = ((ulong *)machdep->pgd) + pgd_index(kvaddr);
	mfn = ((*pgd) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

	if (CRASHDEBUG(3))
		fprintf(fp, 
		    "[%lx] pgd: %lx  mfn: %lx  pgd_index: %lx\n", 
			kvaddr, *pgd, mfn, pgd_index(kvaddr));

	if (!readmem(PTOB(mfn), PHYSADDR, machdep->pmd, PAGESIZE(),
            "xen kdump pmd page", RETURN_ON_ERROR))
                error(FATAL, "cannot read/find pmd page\n");

        if (CRASHDEBUG(7)) 
		x86_64_debug_dump_page(fp, machdep->pmd, 
			"contents of page middle directory page:");

        pmd = ((ulong *)machdep->pmd) + pmd_index(kvaddr);
	mfn = ((*pmd) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

	if (CRASHDEBUG(3))
		fprintf(fp, 
		    "[%lx] pmd: %lx  mfn: %lx  pmd_index: %lx\n", 
			kvaddr, *pmd, mfn, pmd_index(kvaddr));

       if (!readmem(PTOB(mfn), PHYSADDR, machdep->ptbl, PAGESIZE(),
            "xen kdump page table page", RETURN_ON_ERROR))
                error(FATAL, "cannot read/find page table page\n");

        if (CRASHDEBUG(7)) 
		x86_64_debug_dump_page(fp, machdep->ptbl, 
			"contents of page table page:");

        ptep = ((ulong *)machdep->ptbl) + pte_index(kvaddr);
	mfn = ((*ptep) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

	if (CRASHDEBUG(3))
		fprintf(fp, 
		    "[%lx] ptep: %lx  mfn: %lx  pte_index: %lx\n", 
			kvaddr, *ptep, mfn, pte_index(kvaddr));

       if (!readmem(PTOB(mfn), PHYSADDR, pgbuf, PAGESIZE(),
            "xen kdump page table page", RETURN_ON_ERROR))
                error(FATAL, "cannot read/find pte page\n");

        if (CRASHDEBUG(7)) 
		x86_64_debug_dump_page(fp, pgbuf, 
			"contents of page:");

	return pgbuf;
}

static ulong 
x86_64_xen_kdump_page_mfn(ulong kvaddr)
{
	ulong mfn;
	ulong *pml4, *pgd, *pmd, *ptep;

        pml4 = ((ulong *)machdep->machspec->pml4) + pml4_index(kvaddr);
	mfn = ((*pml4) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

        if ((mfn != machdep->last_pgd_read) && 
	    !readmem(PTOB(mfn), PHYSADDR, machdep->pgd, PAGESIZE(),
            "xen kdump pud entry", RETURN_ON_ERROR))
		error(FATAL, "cannot read/find pud page\n");
        machdep->last_pgd_read = mfn;

        pgd = ((ulong *)machdep->pgd) + pgd_index(kvaddr);
	mfn = ((*pgd) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

        if ((mfn != machdep->last_pmd_read) && 
            !readmem(PTOB(mfn), PHYSADDR, machdep->pmd, PAGESIZE(),
            "xen kdump pmd entry", RETURN_ON_ERROR))
                error(FATAL, "cannot read/find pmd page\n");
        machdep->last_pmd_read = mfn;

        pmd = ((ulong *)machdep->pmd) + pmd_index(kvaddr);
	mfn = ((*pmd) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

        if ((mfn != machdep->last_ptbl_read) && 
            !readmem(PTOB(mfn), PHYSADDR, machdep->ptbl, PAGESIZE(),
            "xen kdump page table page", RETURN_ON_ERROR))
                error(FATAL, "cannot read/find page table page\n");
        machdep->last_ptbl_read = mfn;

        ptep = ((ulong *)machdep->ptbl) + pte_index(kvaddr);
	mfn = ((*ptep) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

	return mfn;
}

#include "xendump.h"

/*
 *  Create an index of mfns for each page that makes up the
 *  kernel's complete phys_to_machine_mapping[max_pfn] array.
 */
static int 
x86_64_xendump_p2m_create(struct xendump_data *xd)
{
	int i, idx;
	ulong mfn, kvaddr, ctrlreg[8], ctrlreg_offset;
	ulong *up;
	off_t offset; 

	if ((ctrlreg_offset = MEMBER_OFFSET("vcpu_guest_context", "ctrlreg")) ==
	     INVALID_OFFSET)
		error(FATAL, 
		    "cannot determine vcpu_guest_context.ctrlreg offset\n");
	else if (CRASHDEBUG(1))
		fprintf(xd->ofp, 
		    "MEMBER_OFFSET(vcpu_guest_context, ctrlreg): %ld\n",
			ctrlreg_offset);

	offset = (off_t)xd->xc_core.header.xch_ctxt_offset + 
		(off_t)ctrlreg_offset;

	if (lseek(xd->xfd, offset, SEEK_SET) == -1)
		error(FATAL, "cannot lseek to xch_ctxt_offset\n");

	if (read(xd->xfd, &ctrlreg, sizeof(ctrlreg)) !=
	    sizeof(ctrlreg))
		error(FATAL, "cannot read vcpu_guest_context ctrlreg[8]\n");

	for (i = 0; CRASHDEBUG(1) && (i < 8); i++)
		fprintf(xd->ofp, "ctrlreg[%d]: %lx\n", i, ctrlreg[i]);

	mfn = ctrlreg[3] >> PAGESHIFT();

	if (!xc_core_mfn_to_page(mfn, machdep->machspec->pml4))
		error(FATAL, "cannot read/find cr3 page\n");

	if (CRASHDEBUG(7)) 
		x86_64_debug_dump_page(xd->ofp, machdep->machspec->pml4, 
                	"contents of PML4 page:");

	kvaddr = symbol_value("end_pfn");
	if (!x86_64_xendump_load_page(kvaddr, xd))
		return FALSE;

	up = (ulong *)(xd->page + PAGEOFFSET(kvaddr));
	if (CRASHDEBUG(1))
		fprintf(xd->ofp, "end_pfn: %lx\n", *up);

	xd->xc_core.p2m_frames = (*up/(PAGESIZE()/sizeof(ulong))) +
                ((*up%(PAGESIZE()/sizeof(ulong))) ? 1 : 0);

	if ((xd->xc_core.p2m_frame_index_list = (ulong *)
	    malloc(xd->xc_core.p2m_frames * sizeof(ulong))) == NULL)
        	error(FATAL, "cannot malloc p2m_frame_list");

	kvaddr = symbol_value("phys_to_machine_mapping");
	if (!x86_64_xendump_load_page(kvaddr, xd))
		return FALSE;

	up = (ulong *)(xd->page + PAGEOFFSET(kvaddr));
	if (CRASHDEBUG(1))
		fprintf(fp, "phys_to_machine_mapping: %lx\n", *up);

	kvaddr = *up;
	machdep->last_ptbl_read = BADADDR;

	for (i = 0; i < xd->xc_core.p2m_frames; i++) {
		if ((idx = x86_64_xendump_page_index(kvaddr, xd)) == MFN_NOT_FOUND)
			return FALSE;
		xd->xc_core.p2m_frame_index_list[i] = idx; 
		kvaddr += PAGESIZE();
	}

	machdep->last_ptbl_read = 0;

	return TRUE;
}

static void
x86_64_debug_dump_page(FILE *ofp, char *page, char *name)
{
	int i;
	ulong *up;

        fprintf(ofp, "%s\n", name);

        up = (ulong *)page;
        for (i = 0; i < 256; i++) {
        	fprintf(ofp, "%016lx: %016lx %016lx\n",
                        (ulong)((i * 2) * sizeof(ulong)),
                        *up, *(up+1));
                up += 2;
        }
}

/*
 *  Find the page associate with the kvaddr, and read its contents
 *  into the passed-in buffer.
 */
static char *
x86_64_xendump_load_page(ulong kvaddr, struct xendump_data *xd)
{
	ulong mfn;
	ulong *pml4, *pgd, *pmd, *ptep;

        pml4 = ((ulong *)machdep->machspec->pml4) + pml4_index(kvaddr);
	mfn = ((*pml4) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

	if (CRASHDEBUG(3))
		fprintf(xd->ofp, 
		    "[%lx] pml4: %lx  mfn: %lx  pml4_index: %lx\n", 
			kvaddr, *pml4, mfn, pml4_index(kvaddr));

	if (!xc_core_mfn_to_page(mfn, machdep->pgd))
		error(FATAL, "cannot read/find pud page\n");

        if (CRASHDEBUG(7))
		x86_64_debug_dump_page(xd->ofp, machdep->pgd, 
                	"contents of page upper directory page:");

        pgd = ((ulong *)machdep->pgd) + pgd_index(kvaddr);
	mfn = ((*pgd) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

	if (CRASHDEBUG(3))
		fprintf(xd->ofp, 
		    "[%lx] pgd: %lx  mfn: %lx  pgd_index: %lx\n", 
			kvaddr, *pgd, mfn, pgd_index(kvaddr));

        if (!xc_core_mfn_to_page(mfn, machdep->pmd))
                error(FATAL, "cannot read/find pmd page\n");

        if (CRASHDEBUG(7)) 
		x86_64_debug_dump_page(xd->ofp, machdep->pmd, 
			"contents of page middle directory page:");

        pmd = ((ulong *)machdep->pmd) + pmd_index(kvaddr);
	mfn = ((*pmd) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

	if (CRASHDEBUG(3))
		fprintf(xd->ofp, 
		    "[%lx] pmd: %lx  mfn: %lx  pmd_index: %lx\n", 
			kvaddr, *pmd, mfn, pmd_index(kvaddr));

        if (!xc_core_mfn_to_page(mfn, machdep->ptbl))
                error(FATAL, "cannot read/find page table page\n");

        if (CRASHDEBUG(7)) 
		x86_64_debug_dump_page(xd->ofp, machdep->ptbl, 
			"contents of page table page:");

        ptep = ((ulong *)machdep->ptbl) + pte_index(kvaddr);
	mfn = ((*ptep) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

	if (CRASHDEBUG(3))
		fprintf(xd->ofp, 
		    "[%lx] ptep: %lx  mfn: %lx  pte_index: %lx\n", 
			kvaddr, *ptep, mfn, pte_index(kvaddr));

        if (!xc_core_mfn_to_page(mfn, xd->page))
                error(FATAL, "cannot read/find pte page\n");

        if (CRASHDEBUG(7)) 
		x86_64_debug_dump_page(xd->ofp, xd->page, 
			"contents of page:");

	return xd->page;
}

/*
 *  Find the dumpfile page index associated with the kvaddr.
 */
static int 
x86_64_xendump_page_index(ulong kvaddr, struct xendump_data *xd)
{
        int idx;
	ulong mfn;
	ulong *pml4, *pgd, *pmd, *ptep;

        pml4 = ((ulong *)machdep->machspec->pml4) + pml4_index(kvaddr);
	mfn = ((*pml4) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

        if ((mfn != machdep->last_pgd_read) && 
	    !xc_core_mfn_to_page(mfn, machdep->pgd))
		error(FATAL, "cannot read/find pud page\n");
        machdep->last_pgd_read = mfn;

        pgd = ((ulong *)machdep->pgd) + pgd_index(kvaddr);
	mfn = ((*pgd) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

        if ((mfn != machdep->last_pmd_read) && 
            !xc_core_mfn_to_page(mfn, machdep->pmd))
                error(FATAL, "cannot read/find pmd page\n");

        machdep->last_pmd_read = mfn;

        pmd = ((ulong *)machdep->pmd) + pmd_index(kvaddr);
	mfn = ((*pmd) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

        if ((mfn != machdep->last_ptbl_read) && 
	    !xc_core_mfn_to_page(mfn, machdep->ptbl))
                error(FATAL, "cannot read/find page table page\n");
        machdep->last_ptbl_read = mfn;

        ptep = ((ulong *)machdep->ptbl) + pte_index(kvaddr);
	mfn = ((*ptep) & PHYSICAL_PAGE_MASK) >> PAGESHIFT();

        if ((idx = xc_core_mfn_to_page_index(mfn)) == MFN_NOT_FOUND)
                error(INFO, "cannot determine page index for %lx\n",
                        kvaddr);

	return idx;
}

/*
 *  Pull the rsp from the cpu_user_regs struct in the header
 *  turn it into a task, and match it with the active_set.
 *  Unfortunately, the registers in the vcpu_guest_context 
 *  are not necessarily those of the panic task, so for now
 *  let get_active_set_panic_task() get the right task.
 */
static ulong 
x86_64_xendump_panic_task(struct xendump_data *xd)
{
	int i;
	ulong rsp;
	off_t offset;
	ulong task;

	if (INVALID_MEMBER(vcpu_guest_context_user_regs) ||
	    INVALID_MEMBER(cpu_user_regs_esp))
		return NO_TASK;

        offset = (off_t)xd->xc_core.header.xch_ctxt_offset +
                (off_t)OFFSET(vcpu_guest_context_user_regs) +
		(off_t)OFFSET(cpu_user_regs_rsp);

        if (lseek(xd->xfd, offset, SEEK_SET) == -1)
		return NO_TASK;

        if (read(xd->xfd, &rsp, sizeof(ulong)) != sizeof(ulong))
		return NO_TASK;

        if (IS_KVADDR(rsp) && (task = stkptr_to_task(rsp))) {

                for (i = 0; i < NR_CPUS; i++) {
                	if (task == tt->active_set[i]) {
                        	if (CRASHDEBUG(0))
                                	error(INFO,
                            "x86_64_xendump_panic_task: rsp: %lx -> task: %lx\n",
                                        	rsp, task);
                        	return task;
			}
		}               

               	error(WARNING,
		    "x86_64_xendump_panic_task: rsp: %lx -> task: %lx (not active)\n",
			rsp);
        }

	return NO_TASK;
}

/*
 *  Because of an off-by-one vcpu bug in early xc_domain_dumpcore()
 *  instantiations, the registers in the vcpu_guest_context are not 
 *  necessarily those of the panic task.  Furthermore, the rsp is
 *  seemingly unassociated with the task, presumably due a hypervisor
 *  callback, so only accept the contents if they retfer to the panic
 *  task's stack. 
 */
static void 
x86_64_get_xendump_regs(struct xendump_data *xd, struct bt_info *bt, ulong *rip, ulong *rsp)
{
	ulong task, xrip, xrsp;
	off_t offset;
	struct syment *sp;
	int cpu;

        if (INVALID_MEMBER(vcpu_guest_context_user_regs) ||
            INVALID_MEMBER(cpu_user_regs_rip) ||
            INVALID_MEMBER(cpu_user_regs_rsp))
                goto generic;

        offset = (off_t)xd->xc_core.header.xch_ctxt_offset +
                (off_t)OFFSET(vcpu_guest_context_user_regs) +
                (off_t)OFFSET(cpu_user_regs_rsp);
        if (lseek(xd->xfd, offset, SEEK_SET) == -1)
                goto generic;
        if (read(xd->xfd, &xrsp, sizeof(ulong)) != sizeof(ulong))
                goto generic;

        offset = (off_t)xd->xc_core.header.xch_ctxt_offset +
                (off_t)OFFSET(vcpu_guest_context_user_regs) +
                (off_t)OFFSET(cpu_user_regs_rip);
        if (lseek(xd->xfd, offset, SEEK_SET) == -1)
                goto generic;
        if (read(xd->xfd, &xrip, sizeof(ulong)) != sizeof(ulong))
                goto generic;

	/*
	 *  This works -- comes from smp_send_stop call in panic.
	 *  But xendump_panic_hook() will forestall this function 
	 *  from being called (for now).
	 */
        if (IS_KVADDR(xrsp) && (task = stkptr_to_task(xrsp)) &&
	    (task == bt->task)) {
		if (CRASHDEBUG(1))
			fprintf(xd->ofp, 
		"hooks from vcpu_guest_context: rip: %lx rsp: %lx\n", xrip, xrsp);
		*rip = xrip;
		*rsp = xrsp;
		return;
	}

generic:

	machdep->get_stack_frame(bt, rip, rsp);

	/*
	 *  If this is an active task showing itself in schedule(), 
	 *  then the thread_struct rsp is stale.  It has to be coming 
	 *  from a callback via the interrupt stack.
	 */
	if (is_task_active(bt->task) && (symbol_value("thread_return") == *rip)) {
		cpu = bt->tc->processor;
		xrsp = machdep->machspec->stkinfo.ibase[cpu] + 
			machdep->machspec->stkinfo.isize - sizeof(ulong);

                while (readmem(xrsp, KVADDR, &xrip,
                    sizeof(ulong), "xendump rsp", RETURN_ON_ERROR)) {
        		if ((sp = value_search(xrip, (ulong *)&offset)) && 
			    STREQ(sp->name, "smp_really_stop_cpu") && offset) {
                                *rip = xrip;
                                *rsp = xrsp;
                                if (CRASHDEBUG(1))
                                        error(INFO,
                                            "switch thread_return to smp_call_function_interrupt\n");
                                break;
                        }
                        xrsp -= sizeof(ulong);
                        if (xrsp <= machdep->machspec->stkinfo.ibase[cpu])
                                break;
                }
	}
}
#endif  /* X86_64 */ 