/* kernel.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 David Anderson
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 Red Hat, Inc. All rights reserved.
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
#include "xen_hyper_defs.h"
#include <elf.h>

static void do_module_cmd(ulong, char *, ulong, char *, char *);
static char *find_module_objfile(char *, char *, char *);
static char *module_objfile_search(char *, char *, char *);
static char *get_loadavg(char *);
static void get_lkcd_regs(struct bt_info *, ulong *, ulong *);
static void dump_sys_call_table(char *, int);
static int get_NR_syscalls(void);
static void display_bh_1(void);
static void display_bh_2(void);
static void display_bh_3(void);
static void dump_timer_data(void);
static void dump_timer_data_tvec_bases_v1(void);
static void dump_timer_data_tvec_bases_v2(void);
struct tv_range;
static void init_tv_ranges(struct tv_range *, int, int, int);
static int do_timer_list(ulong,int, ulong *, void *,ulong *,struct tv_range *);
static int compare_timer_data(const void *, const void *);
static void panic_this_kernel(void);
static void dump_waitq(ulong, char *);
static void reinit_modules(void);
static int verify_modules(void);
static void verify_namelist(void);
static char *debug_kernel_version(char *);
static int restore_stack(struct bt_info *);
static ulong __xen_m2p(ulonglong, ulong);
static int search_mapping_page(ulong, ulong *, ulong *, ulong *);
static void read_in_kernel_config_err(int, char *);
static void BUG_bytes_init(void);
static int BUG_x86(void);
static int BUG_x86_64(void);
static void cpu_maps_init(void);


/*
 *  Gather a few kernel basics.
 */
void
kernel_init()
{
	int i, c;
	char *p1, *p2, buf[BUFSIZE];
	struct syment *sp1, *sp2;
	char *rqstruct;
	char *irq_desc_type_name;	

	if (pc->flags & KERNEL_DEBUG_QUERY)
		return;

	kt->flags |= IN_KERNEL_INIT;

        if (!(kt->cpu_flags = (ulong *)calloc(NR_CPUS, sizeof(ulong))))
                error(FATAL, "cannot malloc cpu_flags array");

	cpu_maps_init();

	kt->stext = symbol_value("_stext");
	kt->etext = symbol_value("_etext");
	get_text_init_space(); 
	if (symbol_exists("__init_begin")) {
		kt->init_begin = symbol_value("__init_begin");
		kt->init_end = symbol_value("__init_end");
	}
	if (symbol_exists("_end"))
		kt->end = symbol_value("_end");
	else
		kt->end = highest_bss_symbol();
	
	/*
	 *  For the traditional (non-pv_ops) Xen architecture, default to writable 
         *  page tables unless:
	 *  
	 *  (1) it's an "xm save" CANONICAL_PAGE_TABLES dumpfile,  or
	 *  (2) the --shadow_page_tables option was explicitly entered.  
	 *
	 *  But if the "phys_to_maching_mapping" array does not exist, and 
         *  it's not an "xm save" canonical dumpfile, then we have no choice 
         *  but to presume shadow page tables.
	 */ 
	if (!PVOPS() && symbol_exists("xen_start_info")) {
		kt->flags |= ARCH_XEN;
		if (!(kt->xen_flags & (SHADOW_PAGE_TABLES|CANONICAL_PAGE_TABLES)))
			kt->xen_flags |= WRITABLE_PAGE_TABLES;
		if (symbol_exists("phys_to_machine_mapping"))
         		get_symbol_data("phys_to_machine_mapping", sizeof(ulong),
                       		&kt->phys_to_machine_mapping);
		else if (!(kt->xen_flags & CANONICAL_PAGE_TABLES)) {
			kt->xen_flags &= ~WRITABLE_PAGE_TABLES;
			kt->xen_flags |= SHADOW_PAGE_TABLES;
		}
		if (machine_type("X86"))
                	get_symbol_data("max_pfn", sizeof(ulong), &kt->p2m_table_size);
		if (machine_type("X86_64")) {
			/*
			 * kernel version <  2.6.27 => end_pfn
			 * kernel version >= 2.6.27 => max_pfn
			 */
			if (!try_get_symbol_data("end_pfn", sizeof(ulong), &kt->p2m_table_size))
				get_symbol_data("max_pfn", sizeof(ulong), &kt->p2m_table_size);
		}
                if ((kt->m2p_page = (char *)malloc(PAGESIZE())) == NULL)
                       	error(FATAL, "cannot malloc m2p page.");
	}

	if (symbol_exists("smp_num_cpus")) {
		kt->flags |= SMP;
		get_symbol_data("smp_num_cpus", sizeof(int), &kt->cpus);
		if (kt->cpus < 1 || kt->cpus > NR_CPUS)
			error(WARNING, 
			    "invalid value: smp_num_cpus: %d\n",
				kt->cpus);
	} else if (symbol_exists("__per_cpu_offset")) {
		kt->flags |= SMP;
		kt->cpus = 1;
	} else 
		kt->cpus = 1;

	if ((sp1 = symbol_search("__per_cpu_start")) &&
 	    (sp2 = symbol_search("__per_cpu_end")) &&
	    (sp1->type == 'A' || sp1->type == 'D') && 
	    (sp2->type == 'A' || sp2->type == 'D') &&
	    (sp2->value > sp1->value))
		kt->flags |= SMP|PER_CPU_OFF;
	
	get_symbol_data("xtime", sizeof(struct timespec), &kt->date);
	
	if (pc->flags & GET_TIMESTAMP) {
        	fprintf(fp, "%s\n\n", 
			strip_linefeeds(ctime(&kt->date.tv_sec)));
		clean_exit(0);
	}
	
	if (symbol_exists("system_utsname"))
        	readmem(symbol_value("system_utsname"), KVADDR, &kt->utsname,
                	sizeof(struct new_utsname), "system_utsname", 
			RETURN_ON_ERROR);
	else if (symbol_exists("init_uts_ns"))
		readmem(symbol_value("init_uts_ns") + sizeof(int),
			KVADDR,  &kt->utsname, sizeof(struct new_utsname), 
			"init_uts_ns", RETURN_ON_ERROR);
	else
		error(INFO, "cannot access utsname information\n\n");

	strncpy(buf, kt->utsname.release, MIN(strlen(kt->utsname.release), 65));
	if (ascii_string(kt->utsname.release)) {
		p1 = p2 = buf;
		while (*p2 != '.')
			p2++;
		*p2 = NULLCHAR;
		kt->kernel_version[0] = atoi(p1);
		p1 = ++p2;
		while (*p2 != '.')
			p2++;
		*p2 = NULLCHAR;
		kt->kernel_version[1] = atoi(p1);
		p1 = ++p2;
		while ((*p2 >= '0') && (*p2 <= '9'))
			p2++;
		*p2 = NULLCHAR;
		kt->kernel_version[2] = atoi(p1);

		if (CRASHDEBUG(1))
			fprintf(fp, "base kernel version: %d.%d.%d\n",
				kt->kernel_version[0],
				kt->kernel_version[1],
				kt->kernel_version[2]);
	} else
		error(INFO, "cannot determine base kernel version\n");


	verify_version();

	if (symbol_exists("__per_cpu_offset")) {
		if (LKCD_KERNTYPES())
			i = get_cpus_possible();
		else
			i = get_array_length("__per_cpu_offset", NULL, 0);
		get_symbol_data("__per_cpu_offset",
			sizeof(long)*((i && (i <= NR_CPUS)) ? i : NR_CPUS),
			&kt->__per_cpu_offset[0]);
                kt->flags |= PER_CPU_OFF;
	}
	if (STRUCT_EXISTS("runqueue"))
		rqstruct = "runqueue";
	else if (STRUCT_EXISTS("rq"))
		rqstruct = "rq";
	else {
		rqstruct = NULL;
		error(FATAL, "neither runqueue nor rq structures exist\n");
	}

	MEMBER_OFFSET_INIT(runqueue_cpu, rqstruct, "cpu");
	/*
	 * 'cpu' does not exist in 'struct rq'.
	 */
	if (VALID_MEMBER(runqueue_cpu) &&
	    (get_array_length("runqueue.cpu", NULL, 0) > 0)) {
		MEMBER_OFFSET_INIT(cpu_s_curr, "cpu_s", "curr");
		MEMBER_OFFSET_INIT(cpu_s_idle, "cpu_s", "idle");
	 	STRUCT_SIZE_INIT(cpu_s, "cpu_s"); 
		kt->runq_siblings = get_array_length("runqueue.cpu", 
			NULL, 0);
		if (symbol_exists("__cpu_idx") &&
		    symbol_exists("__rq_idx")) {
			if (!(kt->__cpu_idx = (long *)
			    calloc(NR_CPUS, sizeof(long))))
				error(FATAL, "cannot malloc __cpu_idx array");
			if (!(kt->__rq_idx = (long *)
			    calloc(NR_CPUS, sizeof(long))))
				error(FATAL, "cannot malloc __rq_idx array");
			if (!readmem(symbol_value("__cpu_idx"), KVADDR, 
		            &kt->__cpu_idx[0], sizeof(long) * NR_CPUS,
                            "__cpu_idx[NR_CPUS]", RETURN_ON_ERROR))
				error(INFO, 
			            "cannot read __cpu_idx[NR_CPUS] array\n");
			if (!readmem(symbol_value("__rq_idx"), KVADDR, 
		            &kt->__rq_idx[0], sizeof(long) * NR_CPUS,
                            "__rq_idx[NR_CPUS]", RETURN_ON_ERROR))
				error(INFO, 
			           "cannot read __rq_idx[NR_CPUS] array\n");
		} else if (kt->runq_siblings > 1) 
			error(INFO, 
     	   "runq_siblings: %d: __cpu_idx and __rq_idx arrays don't exist?\n",
				kt->runq_siblings);
	} else {
		MEMBER_OFFSET_INIT(runqueue_idle, rqstruct, "idle");
		MEMBER_OFFSET_INIT(runqueue_curr, rqstruct, "curr");
		ASSIGN_OFFSET(runqueue_cpu) = INVALID_OFFSET;
	}
	MEMBER_OFFSET_INIT(runqueue_active, rqstruct, "active");
	MEMBER_OFFSET_INIT(runqueue_expired, rqstruct, "expired");
	MEMBER_OFFSET_INIT(runqueue_arrays, rqstruct, "arrays");
	MEMBER_OFFSET_INIT(prio_array_queue, "prio_array", "queue");
        MEMBER_OFFSET_INIT(prio_array_nr_active, "prio_array", "nr_active");
	STRUCT_SIZE_INIT(runqueue, rqstruct); 
	STRUCT_SIZE_INIT(prio_array, "prio_array"); 

	MEMBER_OFFSET_INIT(rq_cfs, "rq", "cfs");

       /*
        *  In 2.4, smp_send_stop() sets smp_num_cpus back to 1
        *  in some, but not all, architectures.  So if a count
        *  of 1 is found, be suspicious, and check the
        *  init_tasks[NR_CPUS] array (also intro'd in 2.4),
        *  for idle thread addresses.  For 2.2, prepare for the
     	*  eventuality by verifying the cpu count with the machine
	*  dependent count.
        */
        if ((kt->flags & SMP) && DUMPFILE() && (kt->cpus == 1)) {
                if (symbol_exists("init_tasks")) {
                        ulong init_tasks[NR_CPUS];
			int nr_cpus;

			BZERO(&init_tasks[0], sizeof(ulong) * NR_CPUS);

			nr_cpus = get_array_length("init_tasks", NULL, 0);
			if ((nr_cpus < 1) || (nr_cpus > NR_CPUS))
                                nr_cpus = NR_CPUS;

			get_idle_threads(&init_tasks[0], nr_cpus);

                        for (i = kt->cpus = 0; i < nr_cpus; i++)
                                if (init_tasks[i])
                                        kt->cpus++;
                } else 
			kt->cpus = machdep->get_smp_cpus();
	}

	if ((kt->flags & SMP) && ACTIVE() && (kt->cpus == 1) &&
	    (kt->flags & PER_CPU_OFF))
		kt->cpus = machdep->get_smp_cpus();

	if (kt->cpus_override && (c = atoi(kt->cpus_override))) {
		error(WARNING, "forcing cpu count to: %d\n\n", c);
		kt->cpus = c;
	}

	if (kt->cpus > NR_CPUS) {
		error(WARNING, 
       "%s number of cpus (%d) greater than compiled-in NR_CPUS (%d)\n",
			kt->cpus_override && atoi(kt->cpus_override) ? 
			"configured" : "calculated", kt->cpus, NR_CPUS);
		error(FATAL, "recompile crash with larger NR_CPUS\n");
	}

	STRUCT_SIZE_INIT(spinlock_t, "spinlock_t");
	verify_spinlock();

	STRUCT_SIZE_INIT(list_head, "list_head"); 
	MEMBER_OFFSET_INIT(list_head_next, "list_head", "next"); 
	MEMBER_OFFSET_INIT(list_head_prev, "list_head", "prev"); 
	if (OFFSET(list_head_next) != 0)
	    	error(WARNING, 
		    "list_head.next offset: %ld: list command may fail\n",
			OFFSET(list_head_next));

        MEMBER_OFFSET_INIT(hlist_node_next, "hlist_node", "next");
        MEMBER_OFFSET_INIT(hlist_node_pprev, "hlist_node", "pprev");
	STRUCT_SIZE_INIT(hlist_head, "hlist_head"); 
	STRUCT_SIZE_INIT(hlist_node, "hlist_node"); 

	if (STRUCT_EXISTS("irq_desc_t"))
		irq_desc_type_name = "irq_desc_t";
	else
		irq_desc_type_name = "irq_desc";

	STRUCT_SIZE_INIT(irq_desc_t, irq_desc_type_name);
	MEMBER_OFFSET_INIT(irq_desc_t_status, irq_desc_type_name, "status");
	if (MEMBER_EXISTS(irq_desc_type_name, "handler"))
		MEMBER_OFFSET_INIT(irq_desc_t_handler, irq_desc_type_name, "handler");
	else
		MEMBER_OFFSET_INIT(irq_desc_t_chip, irq_desc_type_name, "chip");
	MEMBER_OFFSET_INIT(irq_desc_t_action, irq_desc_type_name, "action");
	MEMBER_OFFSET_INIT(irq_desc_t_depth, irq_desc_type_name, "depth");
	if (STRUCT_EXISTS("hw_interrupt_type")) {
		MEMBER_OFFSET_INIT(hw_interrupt_type_typename,
			"hw_interrupt_type", "typename");
		MEMBER_OFFSET_INIT(hw_interrupt_type_startup,
			"hw_interrupt_type", "startup");
		MEMBER_OFFSET_INIT(hw_interrupt_type_shutdown,
			"hw_interrupt_type", "shutdown");
		MEMBER_OFFSET_INIT(hw_interrupt_type_handle,
        	        "hw_interrupt_type", "handle");
		MEMBER_OFFSET_INIT(hw_interrupt_type_enable,
			"hw_interrupt_type", "enable");
		MEMBER_OFFSET_INIT(hw_interrupt_type_disable,
			"hw_interrupt_type", "disable");
		MEMBER_OFFSET_INIT(hw_interrupt_type_ack,
			"hw_interrupt_type", "ack");
		MEMBER_OFFSET_INIT(hw_interrupt_type_end,
			"hw_interrupt_type", "end");
		MEMBER_OFFSET_INIT(hw_interrupt_type_set_affinity,
			"hw_interrupt_type", "set_affinity");
	} else { /*
		  * On later kernels where hw_interrupt_type was replaced
		  * by irq_chip
		  */
		MEMBER_OFFSET_INIT(irq_chip_typename,
			"irq_chip", "name");
		MEMBER_OFFSET_INIT(irq_chip_startup,
			"irq_chip", "startup");
		MEMBER_OFFSET_INIT(irq_chip_shutdown,
			"irq_chip", "shutdown");
		MEMBER_OFFSET_INIT(irq_chip_enable,
			"irq_chip", "enable");
		MEMBER_OFFSET_INIT(irq_chip_disable,
			"irq_chip", "disable");
		MEMBER_OFFSET_INIT(irq_chip_ack,
			"irq_chip", "ack");
		MEMBER_OFFSET_INIT(irq_chip_mask,
			"irq_chip", "mask");
		MEMBER_OFFSET_INIT(irq_chip_mask_ack,
			"irq_chip", "mask_ack");
		MEMBER_OFFSET_INIT(irq_chip_unmask,
			"irq_chip", "unmask");
		MEMBER_OFFSET_INIT(irq_chip_eoi,
			"irq_chip", "eoi");
		MEMBER_OFFSET_INIT(irq_chip_end,
			"irq_chip", "end");
		MEMBER_OFFSET_INIT(irq_chip_set_affinity,
			"irq_chip", "set_affinity");
		MEMBER_OFFSET_INIT(irq_chip_retrigger,
			"irq_chip", "retrigger");
		MEMBER_OFFSET_INIT(irq_chip_set_type,
			"irq_chip", "set_type");
		MEMBER_OFFSET_INIT(irq_chip_set_wake,
			"irq_chip", "set_wake");
	}
	MEMBER_OFFSET_INIT(irqaction_handler, "irqaction", "handler");
	MEMBER_OFFSET_INIT(irqaction_flags, "irqaction", "flags");
	MEMBER_OFFSET_INIT(irqaction_mask, "irqaction", "mask");
	MEMBER_OFFSET_INIT(irqaction_name, "irqaction", "name");
	MEMBER_OFFSET_INIT(irqaction_dev_id, "irqaction", "dev_id");
	MEMBER_OFFSET_INIT(irqaction_next, "irqaction", "next");

        STRUCT_SIZE_INIT(irq_cpustat_t, "irq_cpustat_t");
        MEMBER_OFFSET_INIT(irq_cpustat_t___softirq_active, 
                "irq_cpustat_t", "__softirq_active");
        MEMBER_OFFSET_INIT(irq_cpustat_t___softirq_mask, 
                "irq_cpustat_t", "__softirq_mask");

        STRUCT_SIZE_INIT(timer_list, "timer_list");
        MEMBER_OFFSET_INIT(timer_list_list, "timer_list", "list");
        MEMBER_OFFSET_INIT(timer_list_next, "timer_list", "next");
        MEMBER_OFFSET_INIT(timer_list_entry, "timer_list", "entry");
        MEMBER_OFFSET_INIT(timer_list_expires, "timer_list", "expires");
        MEMBER_OFFSET_INIT(timer_list_function, "timer_list", "function");
        STRUCT_SIZE_INIT(timer_vec_root, "timer_vec_root");
	if (VALID_STRUCT(timer_vec_root))
               	MEMBER_OFFSET_INIT(timer_vec_root_vec, 
			"timer_vec_root", "vec");
        STRUCT_SIZE_INIT(timer_vec, "timer_vec");
	if (VALID_STRUCT(timer_vec))
               	MEMBER_OFFSET_INIT(timer_vec_vec, "timer_vec", "vec");

	STRUCT_SIZE_INIT(tvec_root_s, "tvec_root_s");
        if (VALID_STRUCT(tvec_root_s)) {
               	STRUCT_SIZE_INIT(tvec_t_base_s, "tvec_t_base_s");
                MEMBER_OFFSET_INIT(tvec_t_base_s_tv1,
                        "tvec_t_base_s", "tv1");
	        MEMBER_OFFSET_INIT(tvec_root_s_vec, 
			"tvec_root_s", "vec");
	        STRUCT_SIZE_INIT(tvec_s, "tvec_s");
	        MEMBER_OFFSET_INIT(tvec_s_vec, "tvec_s", "vec");
	} else {
		STRUCT_SIZE_INIT(tvec_root_s, "tvec_root");
        	if (VALID_STRUCT(tvec_root_s)) {
               		STRUCT_SIZE_INIT(tvec_t_base_s, "tvec_base");
                	MEMBER_OFFSET_INIT(tvec_t_base_s_tv1,
                        	"tvec_base", "tv1");
	        	MEMBER_OFFSET_INIT(tvec_root_s_vec, 
				"tvec_root", "vec");
	        	STRUCT_SIZE_INIT(tvec_s, "tvec");
	        	MEMBER_OFFSET_INIT(tvec_s_vec, "tvec", "vec");
		}
	}
        STRUCT_SIZE_INIT(__wait_queue, "__wait_queue");
        if (VALID_STRUCT(__wait_queue)) {
		if (MEMBER_EXISTS("__wait_queue", "task"))
			MEMBER_OFFSET_INIT(__wait_queue_task,
				"__wait_queue", "task");
		else
			MEMBER_OFFSET_INIT(__wait_queue_task,
				"__wait_queue", "private");
                MEMBER_OFFSET_INIT(__wait_queue_head_task_list,
                        "__wait_queue_head", "task_list");
                MEMBER_OFFSET_INIT(__wait_queue_task_list,
                        "__wait_queue", "task_list");
        } else {
               	STRUCT_SIZE_INIT(wait_queue, "wait_queue");
		if (VALID_STRUCT(wait_queue)) {
               		MEMBER_OFFSET_INIT(wait_queue_task, 
				"wait_queue", "task");
               		MEMBER_OFFSET_INIT(wait_queue_next, 
				"wait_queue", "next");
		}
	}

	STRUCT_SIZE_INIT(pt_regs, "pt_regs");
	STRUCT_SIZE_INIT(softirq_state, "softirq_state");
	STRUCT_SIZE_INIT(desc_struct, "desc_struct");

	STRUCT_SIZE_INIT(char_device_struct, "char_device_struct");
	if (VALID_STRUCT(char_device_struct)) {
		MEMBER_OFFSET_INIT(char_device_struct_next,
			"char_device_struct", "next");
		MEMBER_OFFSET_INIT(char_device_struct_name,
			"char_device_struct", "name");
		MEMBER_OFFSET_INIT(char_device_struct_fops,
			"char_device_struct", "fops");
		MEMBER_OFFSET_INIT(char_device_struct_major,
			"char_device_struct", "major");
		MEMBER_OFFSET_INIT(char_device_struct_baseminor,
			"char_device_struct", "baseminor");
		MEMBER_OFFSET_INIT(char_device_struct_cdev,
			"char_device_struct", "cdev");
	}

	STRUCT_SIZE_INIT(cdev, "cdev");
	if (VALID_STRUCT(cdev)) 
		MEMBER_OFFSET_INIT(cdev_ops, "cdev", "ops");

	STRUCT_SIZE_INIT(probe, "probe");
	if (VALID_STRUCT(probe)) {
		MEMBER_OFFSET_INIT(probe_next, "probe", "next");
		MEMBER_OFFSET_INIT(probe_dev, "probe", "dev");
		MEMBER_OFFSET_INIT(probe_data, "probe", "data");
	}

	STRUCT_SIZE_INIT(kobj_map, "kobj_map");
	if (VALID_STRUCT(kobj_map)) 
		MEMBER_OFFSET_INIT(kobj_map_probes, "kobj_map", "probes");

	MEMBER_OFFSET_INIT(module_kallsyms_start, "module", 
		"kallsyms_start");

	STRUCT_SIZE_INIT(kallsyms_header, "kallsyms_header");

	if (VALID_MEMBER(module_kallsyms_start) &&
	    VALID_SIZE(kallsyms_header)) {
        	MEMBER_OFFSET_INIT(kallsyms_header_sections,
			"kallsyms_header", "sections");
        	MEMBER_OFFSET_INIT(kallsyms_header_section_off,
			"kallsyms_header", "section_off");
        	MEMBER_OFFSET_INIT(kallsyms_header_symbols,
			"kallsyms_header", "symbols");
        	MEMBER_OFFSET_INIT(kallsyms_header_symbol_off,
			"kallsyms_header", "symbol_off");
        	MEMBER_OFFSET_INIT(kallsyms_header_string_off,
			"kallsyms_header", "string_off");
        	MEMBER_OFFSET_INIT(kallsyms_symbol_section_off,
			"kallsyms_symbol", "section_off");
        	MEMBER_OFFSET_INIT(kallsyms_symbol_symbol_addr,
			"kallsyms_symbol", "symbol_addr");
        	MEMBER_OFFSET_INIT(kallsyms_symbol_name_off,
			"kallsyms_symbol", "name_off");
        	MEMBER_OFFSET_INIT(kallsyms_section_start,
			"kallsyms_section", "start");
        	MEMBER_OFFSET_INIT(kallsyms_section_size,
			"kallsyms_section", "size");
        	MEMBER_OFFSET_INIT(kallsyms_section_name_off,
			"kallsyms_section", "name_off");
		STRUCT_SIZE_INIT(kallsyms_symbol, "kallsyms_symbol");
		STRUCT_SIZE_INIT(kallsyms_section, "kallsyms_section");
			
		if (!(kt->flags & NO_KALLSYMS))
			kt->flags |= KALLSYMS_V1;
	}

	MEMBER_OFFSET_INIT(module_num_symtab, "module", "num_symtab");

	if (VALID_MEMBER(module_num_symtab)) {
		MEMBER_OFFSET_INIT(module_symtab, "module", "symtab");
		MEMBER_OFFSET_INIT(module_strtab, "module", "strtab");
			
		if (!(kt->flags & NO_KALLSYMS))
			kt->flags |= KALLSYMS_V2;
	}

	if (!(kt->flags & DWARF_UNWIND))
		kt->flags |= NO_DWARF_UNWIND; 

	/* 
	 *  OpenVZ 
	 */
	if (kernel_symbol_exists("pcpu_info") && 
	    STRUCT_EXISTS("pcpu_info") && STRUCT_EXISTS("vcpu_struct")) {
		MEMBER_OFFSET_INIT(pcpu_info_vcpu, "pcpu_info", "vcpu");
		MEMBER_OFFSET_INIT(pcpu_info_idle, "pcpu_info", "idle");
		MEMBER_OFFSET_INIT(vcpu_struct_rq, "vcpu_struct", "rq");
		STRUCT_SIZE_INIT(pcpu_info, "pcpu_info");
		STRUCT_SIZE_INIT(vcpu_struct, "vcpu_struct");
		kt->flags |= ARCH_OPENVZ;
	}

	BUG_bytes_init();
	
	kt->flags &= ~IN_KERNEL_INIT;
}

/*
 * Get cpu map address.  Types are: possible, online, present and active.
 * They exist as either:
 *
 *  (1) cpu_<type>_map symbols, or 
 *  (2) what is pointed to by cpu_<type>_mask
 */
ulong
cpu_map_addr(const char *type)
{
	char map_symbol[32];
	ulong addr;

	sprintf(map_symbol, "cpu_%s_map", type);
	if (kernel_symbol_exists(map_symbol))
		return symbol_value(map_symbol);

        sprintf(map_symbol, "cpu_%s_mask", type);
        if (kernel_symbol_exists(map_symbol)) {
        	get_symbol_data(map_symbol, sizeof(ulong), &addr);
        	return addr;
	}

	return 0;
}

/*
 * Get cpu map (possible, online, etc.) size
 */
static int
cpu_map_size(const char *type)
{
	int len;
	char map_symbol[32];
	struct gnu_request req;

        if (LKCD_KERNTYPES()) {
                if ((len = STRUCT_SIZE("cpumask_t")) < 0)
                        error(FATAL, "cannot determine type cpumask_t\n");
		return len;
	}

	sprintf(map_symbol, "cpu_%s_map", type);
	if (kernel_symbol_exists(map_symbol)) {
		len = get_symbol_type(map_symbol, NULL, &req) ==
                        TYPE_CODE_UNDEF ? sizeof(ulong) : req.length;
		return len;
	}

	len = STRUCT_SIZE("cpumask_t");
	if (len < 0)
		return sizeof(ulong);
	else
		return len;
}

/*
 *  If the cpu_present_map, cpu_online_map and cpu_possible_maps exist,
 *  set up the kt->cpu_flags[NR_CPUS] with their settings.
 */ 
static void
cpu_maps_init(void)
{
        int i, c, m, cpu, len;
        char *buf;
        ulong *maskptr, addr;
	struct mapinfo {
		ulong cpu_flag;
		char *name;
	} mapinfo[] = {
		{ POSSIBLE, "possible" },
		{ PRESENT, "present" },
		{ ONLINE, "online" },
	};

	if ((len = STRUCT_SIZE("cpumask_t")) < 0)
		len = sizeof(ulong);

	buf = GETBUF(len);

	for (m = 0; m < sizeof(mapinfo)/sizeof(struct mapinfo); m++) {
		if (!(addr = cpu_map_addr(mapinfo[m].name)))
			continue;

		if (!readmem(addr, KVADDR, buf, len,
		    mapinfo[m].name, RETURN_ON_ERROR)) {
			error(WARNING, "cannot read cpu_%s_map\n",
			      mapinfo[m].name);
			continue;
		}

		maskptr = (ulong *)buf;
		for (i = 0; i < (len/sizeof(ulong)); i++, maskptr++) {
			if (*maskptr == 0)
				continue;
			for (c = 0; c < BITS_PER_LONG; c++)
				if (*maskptr & (0x1UL << c)) {
					cpu = (i * BITS_PER_LONG) + c;
					kt->cpu_flags[cpu] |= mapinfo[m].cpu_flag;
				}
		}

		if (CRASHDEBUG(1)) {
			fprintf(fp, "cpu_%s_map: ", mapinfo[m].name);
			for (i = 0; i < NR_CPUS; i++) {
				if (kt->cpu_flags[i] & mapinfo[m].cpu_flag)
					fprintf(fp, "%d ", i);
			}
			fprintf(fp, "\n");
		}

	}

	FREEBUF(buf);
}

/*
 *  Determine whether a cpu is in one of the cpu masks.
 */
int
in_cpu_map(int map, int cpu)
{
	if (cpu >= (kt->kernel_NR_CPUS ? kt->kernel_NR_CPUS : NR_CPUS)) {
		error(INFO, "in_cpu_map: invalid cpu: %d\n", cpu);
		return FALSE;
	}

	switch (map)
	{
	case POSSIBLE:
		if (!cpu_map_addr("possible")) {
			error(INFO, "cpu_possible_map does not exist\n");
			return FALSE;
		}
		return (kt->cpu_flags[cpu] & POSSIBLE);

	case PRESENT:
		if (!cpu_map_addr("present")) {
			error(INFO, "cpu_present_map does not exist\n");
			return FALSE;
		}
		return (kt->cpu_flags[cpu] & PRESENT);

	case ONLINE:
		if (!cpu_map_addr("online")) {
			error(INFO, "cpu_online_map does not exist\n");
			return FALSE;
		}
		return (kt->cpu_flags[cpu] & ONLINE);
	}

	return FALSE;
}


/*
 *  For lack of a better manner of verifying that the namelist and dumpfile
 *  (or live kernel) match up, verify that the Linux banner is where
 *  the namelist says it is.  Since this is common place to bail, extra
 *  debug statements are available.
 */
void
verify_version(void)
{
	char buf[BUFSIZE];
	ulong linux_banner;
        int argc, len;
        char *arglist[MAXARGS];
	char *p1, *p2;
	struct syment *sp;

	if (pc->flags & KERNEL_DEBUG_QUERY)
		return;

	BZERO(buf, BUFSIZE);

	if (!(sp = symbol_search("linux_banner")))
		error(FATAL, "linux_banner symbol does not exist?\n");
	else if ((sp->type == 'R') || (sp->type == 'r'))
		linux_banner = symbol_value("linux_banner");
	else
		get_symbol_data("linux_banner", sizeof(ulong), &linux_banner);

	if (!IS_KVADDR(linux_banner))
		error(WARNING, "invalid linux_banner pointer: %lx\n", 
			linux_banner);

	if (!accessible(linux_banner)) 
		goto bad_match;

	if (!read_string(linux_banner, buf, BUFSIZE-1))
		error(WARNING, "cannot read linux_banner string\n");

	if (ACTIVE()) {
		len = strlen(kt->proc_version);
		if ((len > 0) && (strncmp(buf, kt->proc_version, len) != 0)) {
               		if (CRASHDEBUG(1)) {
                        	fprintf(fp, "/proc/version:\n%s\n", 
					kt->proc_version);
                        	fprintf(fp, "linux_banner:\n%s\n", buf);
                	}
			goto bad_match;
		} else if (CRASHDEBUG(1)) 
                       	fprintf(fp, "linux_banner:\n%s\n", buf);
	}

	if (DUMPFILE()) {
		if (!STRNEQ(buf, "Linux version")) {
                	if (CRASHDEBUG(1)) 
                        	fprintf(fp, "linux_banner:\n%s\n", buf);
			goto bad_match;
		}
		strcpy(kt->proc_version, strip_linefeeds(buf));
	}

	verify_namelist();

	if (strstr(kt->proc_version, "gcc version 3.3.3"))
		kt->flags |= GCC_3_3_3;
	if (strstr(kt->proc_version, "gcc version 3.3.2"))
		kt->flags |= GCC_3_3_2;
	else if (strstr(kt->proc_version, "gcc version 3.2.3"))
		kt->flags |= GCC_3_2_3;
	else if (strstr(kt->proc_version, "gcc version 3.2"))
		kt->flags |= GCC_3_2;
	else if (strstr(kt->proc_version, "gcc version 2.96"))
		kt->flags |= GCC_2_96;

	/*
	 *  Keeping the gcc version with #define's is getting out of hand.
	 */
	if ((p1 = strstr(kt->proc_version, "gcc version "))) {
		BZERO(buf, BUFSIZE);
		p1 += strlen("gcc version ");
		p2 = buf;
		while (((*p1 >= '0') && (*p1 <= '9')) || (*p1 == '.')) {
			if (*p1 == '.')
				*p2++ = ' ';
			else
				*p2++ = *p1;
			p1++;
		}
		argc = parse_line(buf, arglist);

		switch (argc)
		{
		case 0:
		case 1:
			break;
		case 2:
			kt->gcc_version[0] = atoi(arglist[0]);
			kt->gcc_version[1] = atoi(arglist[1]);
			break;
		default:
			kt->gcc_version[0] = atoi(arglist[0]);
			kt->gcc_version[1] = atoi(arglist[1]);		
			kt->gcc_version[2] = atoi(arglist[2]);
			break;
		}
	}

	if (CRASHDEBUG(1))
		gdb_readnow_warning();

	return;

bad_match:
	if (REMOTE())
		sprintf(buf, "%s:%s", pc->server, pc->server_memsrc);
	else
		sprintf(buf, ACTIVE() ? pc->live_memsrc : pc->dumpfile);

	error(INFO, "%s and %s do not match!\n",
		pc->system_map ? pc->system_map : 
		pc->namelist_debug ? pc->namelist_debug : pc->namelist, buf); 

	program_usage(SHORT_FORM);
}

/*
 *  Quick test to verify that we're not using a UP debug kernel on
 *  an SMP system.
 */
void
verify_spinlock(void)
{
	char buf[BUFSIZE];

	if ((kt->flags & SMP) && (SIZE(spinlock_t) == 0)) {
        	error(INFO,
           "debug data shows spinlock_t as an incomplete type (undefined),\n");
                fprintf(fp, "%sbut \"%s\" is an SMP kernel.\n",
                	space(strlen(pc->program_name)+2),
                        pc->namelist);
                if (CRASHDEBUG(1)) {
                        fprintf(fp, "\ngdb> ptype spinlock_t\n");
                        sprintf(buf, "ptype spinlock_t");
                        gdb_pass_through(buf, NULL, 0);
                }
                non_matching_kernel();
	}
}

/*
 *  Something doesn't jive.
 */
void
non_matching_kernel(void)
{
	int kernels = 0;

	if (pc->namelist)
		kernels++;
	if (pc->namelist_debug)
		kernels++;
	if (pc->debuginfo_file)
		kernels++;

	fprintf(fp, 
"\nErrors like the one above typically occur when the kernel%s and memory source\ndo not match.  These are the files being used:\n\n", kernels > 1 ? "s" : "");

        if (REMOTE()) {
                switch (pc->flags &
                        (NAMELIST_LOCAL|NAMELIST_UNLINKED|NAMELIST_SAVED))
                {
                case NAMELIST_UNLINKED:
                        fprintf(fp, "      KERNEL: %s  (temporary)\n",
                                pc->namelist);
                        break;

                case (NAMELIST_UNLINKED|NAMELIST_SAVED):
                        fprintf(fp, "      KERNEL: %s\n", pc->namelist);
                        break;

                case NAMELIST_LOCAL:
                        fprintf(fp, "      KERNEL: %s\n", pc->namelist);
                        break;
                }
        } else {
        	if (pc->system_map) {
                	fprintf(fp, "  SYSTEM MAP: %s\n", pc->system_map);
                	fprintf(fp, "DEBUG KERNEL: %s %s\n", pc->namelist,
                		debug_kernel_version(pc->namelist));
        	} else
                	fprintf(fp, "      KERNEL: %s\n", pc->namelist);
	}

        if (pc->debuginfo_file)
                fprintf(fp, "   DEBUGINFO: %s\n", pc->debuginfo_file);
        else if (pc->namelist_debug)
                fprintf(fp, "DEBUG KERNEL: %s %s\n", pc->namelist_debug,
                        debug_kernel_version(pc->namelist_debug));

	if (dumpfile_is_split())
        	fprintf(fp, "   DUMPFILES: ");
	else
        	fprintf(fp, "    DUMPFILE: ");
        if (ACTIVE()) {
                if (REMOTE_ACTIVE())
                        fprintf(fp, "%s@%s  (remote live system)\n",
                                pc->server_memsrc, pc->server);
                else 
                        fprintf(fp, "%s\n", pc->live_memsrc);
        } else {
                if (REMOTE_DUMPFILE())
                        fprintf(fp, "%s@%s  (remote dumpfile)\n",
                                pc->server_memsrc, pc->server);
                else {
                        if (dumpfile_is_split())
                                show_split_dumpfiles();
                        else
                                fprintf(fp, "%s", pc->dumpfile);
                }
        }

	fprintf(fp, "\n");

	if ((pc->flags & FINDKERNEL) && !(pc->system_map)) {
		fprintf(fp, 
		   "The kernel \"%s\" is most likely incorrect.\n",
			pc->namelist);
		fprintf(fp, 
         "Try a different kernel name, or use a System.map file argument.\n\n");
	}

	exit(1);
}

/*
 *  Only two checks are made here: 
 *
 *    1. if the namelist is SMP and the memory source isn't, bail out.
 *    2. if the basic gcc versions differ, issue a warning only.
 */
static void
verify_namelist()
{
	int i;
	char command[BUFSIZE];
	char buffer[BUFSIZE];
	char buffer2[BUFSIZE];
	char buffer3[BUFSIZE];
	char buffer4[BUFSIZE];
	char buffer5[BUFSIZE];
	char *p1;
	FILE *pipe;
	int found;
	char *namelist;
	int namelist_smp;
	int target_smp;

	if (pc->flags & KERNEL_DEBUG_QUERY)
		return;

	/* the kerntypes may not match in terms of gcc version or SMP */
	if (LKCD_KERNTYPES())
		return;

	if (!strlen(kt->utsname.version))
		return;

	namelist = pc->namelist ? pc->namelist : pc->namelist_debug;
	target_smp = strstr(kt->utsname.version, " SMP ") ? TRUE : FALSE;
	namelist_smp = FALSE;

        sprintf(command, "/usr/bin/strings %s", namelist);
        if ((pipe = popen(command, "r")) == NULL) {
                error(INFO, "%s: %s\n", namelist, strerror(errno));
                return;
        }

	found = FALSE;
	sprintf(buffer3, "(unknown)");
        while (fgets(buffer, BUFSIZE-1, pipe)) {
		if (!strstr(buffer, "Linux version 2."))
			continue;

                if (strstr(buffer, kt->proc_version)) {
                	found = TRUE;
			break;
		}

		if (strstr(buffer, " SMP ")) {
			namelist_smp = TRUE;
			strcpy(buffer2, buffer);
		}

		if ((p1 = strstr(buffer, "(gcc version "))) {
			p1 += strlen("(gcc version ");
			i = 0;
			while (*p1 != ' ') 
				buffer3[i++] = *p1++;
			buffer3[i] = NULLCHAR;
		}

		break;
        }
        pclose(pipe);

	if (!found && (p1 = strstr(kt->proc_version, "(gcc version "))) {
		p1 += strlen("(gcc version ");
		i = 0;
		while (*p1 != ' ') 
			buffer4[i++] = *p1++;
		buffer4[i] = NULLCHAR;
		if (!STREQ(buffer3, buffer4)) {
        		if (REMOTE())
                		sprintf(buffer, "%s:%s kernel", 
					pc->server, pc->server_memsrc);
        		else
                		sprintf(buffer, "%s kernel", ACTIVE() ? 
					"live system" : pc->dumpfile);
        		sprintf(buffer5, "  %s: %s\n  %s: %s\n\n",
                		namelist, buffer3,
                		buffer, buffer4);
        		error(WARNING, 
		           "kernels compiled by different gcc versions:\n%s",
				buffer5);
		}
	}

	if (found) {
                if (CRASHDEBUG(1)) {
                	fprintf(fp, "verify_namelist:\n");
			fprintf(fp, "/proc/version:\n%s\n", kt->proc_version);
			fprintf(fp, "utsname version: %s\n",
				kt->utsname.version);
			fprintf(fp, "%s:\n%s\n", namelist, buffer);
		}
		return;
	}

        if (CRASHDEBUG(1)) {
		error(WARNING, 
		    "\ncannot find matching kernel version in %s file:\n\n",
			namelist);
			
               	fprintf(fp, "verify_namelist:\n");
                fprintf(fp, "/proc/version:\n%s\n", kt->proc_version);
                fprintf(fp, "utsname version: %s\n", kt->utsname.version);
                fprintf(fp, "%s:\n%s\n", namelist, buffer2);
        }

	if (target_smp == namelist_smp)
		return;

        if (REMOTE())
                sprintf(buffer, "%s:%s", pc->server, pc->server_memsrc);
        else
                sprintf(buffer, ACTIVE() ? "live system" : pc->dumpfile);

	sprintf(buffer2, " %s is %s -- %s is %s\n",
                namelist, namelist_smp ? "SMP" : "not SMP",
                buffer, target_smp ? "SMP" : "not SMP");

	error(INFO, "incompatible arguments: %s%s",
		strlen(buffer2) > 48 ? "\n  " : "", buffer2);

        program_usage(SHORT_FORM);
}




/*
 *  This routine disassembles text in one of four manners.  A starting
 *  address, an expression, or symbol must be entered.  Then:
 *
 *   1. if a count is appended, disassemble that many instructions starting
 *      at the target address.
 *   2. if a count is NOT entered, and the target address is the starting
 *      address of a function, disassemble the whole function.
 *   3. if the target address is other than the starting address of a 
 *      function, and no count argument is appended, then disassemble one 
 *      instruction. 
 *   4. If the -r option is used, disassemble all instructions in a routine
 *      up to and including the target address.
 *   5. If -u option, just pass the user address and count, ignoring any of
 *      the above.
 */

static char *dis_err = "gdb unable to disassemble kernel virtual address %lx\n";

void
cmd_dis(void)
{
	int c;
	int do_load_module_filter, do_machdep_filter, reverse; 
	int unfiltered, user_mode, count_entered, bug_bytes_entered;
	ulong curaddr;
	ulong revtarget;
	ulong count;
	ulong offset;
	struct syment *sp;
	struct gnu_request *req;
	char *savename, *ret;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char buf5[BUFSIZE];
	
	if ((argcnt == 2) && STREQ(args[1], "-b")) {
		fprintf(fp, "encoded bytes being skipped after ud2a: ");
		if (kt->BUG_bytes < 0)
			fprintf(fp, "undetermined\n");
		else
			fprintf(fp, "%d\n", kt->BUG_bytes);
		return;
	}

	reverse = count_entered = bug_bytes_entered = FALSE;
	sp = NULL;
	unfiltered = user_mode = do_machdep_filter = do_load_module_filter = 0;

	req = (struct gnu_request *)getbuf(sizeof(struct gnu_request));
	req->buf = GETBUF(BUFSIZE);
	req->flags |= GNU_FROM_TTY_OFF|GNU_RETURN_ON_ERROR;
	req->count = 1;

        while ((c = getopt(argcnt, args, "ulrxb:B:")) != EOF) {
                switch(c)
		{
		case 'x':
			unfiltered = TRUE;
			break;

		case 'u':
			user_mode = TRUE;
			break;

		case 'r':
			reverse = TRUE;
			break;

		case 'l':
			if (GDB_PATCHED())
				error(INFO, "line numbers are not available\n");
			else
				req->flags |= GNU_PRINT_LINE_NUMBERS;
			BZERO(buf4, BUFSIZE);
			break;

		case 'B':
		case 'b':
			kt->BUG_bytes = atoi(optarg);
			bug_bytes_entered = TRUE;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

        if (args[optind]) {
                if (can_eval(args[optind])) 
                        req->addr = eval(args[optind], FAULT_ON_ERROR, NULL);
                else if (hexadecimal(args[optind], 0)) {
                        req->addr = htol(args[optind], FAULT_ON_ERROR, NULL);
			if (!user_mode && 
			    !(sp = value_search(req->addr, &offset))) {
				error(WARNING, 
				    "%x: no associated kernel symbol found\n",
					req->addr);
				unfiltered = TRUE;
			}
                } else if ((sp = symbol_search(args[optind]))) {
                        req->addr = sp->value;
			req->flags |= GNU_FUNCTION_ONLY;
		} else {
                        fprintf(fp, "symbol not found: %s\n", args[optind]);
                        fprintf(fp, "possible aternatives:\n");
                        if (!symbol_query(args[optind], "  ", NULL))
                                fprintf(fp, "  (none found)\n");
			FREEBUF(req->buf);
			FREEBUF(req);
                        return;
                }

                if (args[++optind]) {
			if (reverse) {
				error(INFO, 
			            "count argument ignored with -r option\n");
			} else {
                        	req->count = stol(args[optind], 
					FAULT_ON_ERROR, NULL);
				req->flags &= ~GNU_FUNCTION_ONLY;
				count_entered++;
			}
		}

		if (unfiltered) {
                	sprintf(buf1, "x/%ldi 0x%lx",  
				req->count ? req->count : 1, req->addr);
        		gdb_pass_through(buf1, NULL, 0);
			return;
		}

		if (!user_mode && !IS_KVADDR(req->addr)) 
			error(FATAL, "%lx is not a kernel virtual address\n",
				req->addr);

		if (user_mode) {
                	sprintf(buf1, "x/%ldi 0x%lx",  
				req->count ? req->count : 1, req->addr);
			pc->curcmd_flags |= MEMTYPE_UVADDR;
        		gdb_pass_through(buf1, NULL, 0);
			return;
		}

		do_load_module_filter = module_symbol(req->addr, NULL, NULL, 
			NULL, output_radix);

		if (!reverse) {
			req->command = GNU_RESOLVE_TEXT_ADDR;
			gdb_interface(req);
                        if ((req->flags & GNU_COMMAND_FAILED) ||
			    do_load_module_filter ||
			    (req->flags & GNU_FUNCTION_ONLY)) {
				req->flags &= ~GNU_COMMAND_FAILED;
				if (sp) {
					savename = sp->name;
                                        if ((sp = next_symbol(NULL, sp)))
                                                req->addr2 = sp->value;
					else
                                		error(FATAL, 
				        "unable to determine symbol after %s\n",
                                        		savename);
				} else {
					if ((sp = value_search(req->addr, NULL))
                                             && (sp = next_symbol(NULL, sp)))
						req->addr2 = sp->value;	
					else 
						error(FATAL, dis_err, req->addr);
				}
                        }

			do_machdep_filter = machdep->dis_filter(req->addr,NULL);
			count = 0;
			open_tmpfile();
#ifdef OLDWAY
			req->command = GNU_DISASSEMBLE;
			req->fp = pc->tmpfile;
			gdb_interface(req);
#else
			sprintf(buf1, "x/%ldi 0x%lx",
                                count_entered && req->count ? req->count : 
				req->flags & GNU_FUNCTION_ONLY ? 
				req->addr2 - req->addr : 1, 
				req->addr);
        		gdb_pass_through(buf1, NULL, GNU_RETURN_ON_ERROR);
#endif
			if (req->flags & GNU_COMMAND_FAILED) {
				close_tmpfile();
				error(FATAL, dis_err, req->addr);
			}

        		rewind(pc->tmpfile);
        		while (fgets(buf2, BUFSIZE, pc->tmpfile)) {
				if (STRNEQ(buf2, "Dump of") ||
				    STRNEQ(buf2, "End of"))
					continue;

				if (do_load_module_filter)
					load_module_filter(buf2, LM_DIS_FILTER);

				if (STRNEQ(buf2, "0x")) 
					extract_hex(buf2, &curaddr, ':', TRUE);

				if ((req->flags & GNU_FUNCTION_ONLY) &&
				    (curaddr >= req->addr2))
					break;

				if (do_machdep_filter)
					machdep->dis_filter(curaddr, buf2);

				if (req->flags & GNU_FUNCTION_ONLY) {
                                        if (req->flags & 
                                            GNU_PRINT_LINE_NUMBERS) {
                                                get_line_number(curaddr, buf3,
                                                        FALSE);
                                                if (!STREQ(buf3, buf4)) {
                                                        print_verbatim(
                                                            pc->saved_fp, buf3);
                                                        print_verbatim(
                                                            pc->saved_fp, "\n");
                                                        strcpy(buf4, buf3);
                                                }
                                        }

                			print_verbatim(pc->saved_fp, buf2); 
					continue;
				} else {
					if (curaddr < req->addr) 
						continue;

                			if (req->flags & 
					    GNU_PRINT_LINE_NUMBERS) {
                        			get_line_number(curaddr, buf3, 
							FALSE);
                        			if (!STREQ(buf3, buf4)) {
                                			print_verbatim(
							    pc->saved_fp, buf3);
                                			print_verbatim(
						            pc->saved_fp, "\n");
                                			strcpy(buf4, buf3);
                        			}
                			} 

                			print_verbatim(pc->saved_fp, buf2);

					if (LASTCHAR(clean_line(buf2)) 
						!= ':') {
						if (++count == req->count)
							break;
					}
				}
        		}
			close_tmpfile();
		}
        }
        else if (bug_bytes_entered)
		return;
	else cmd_usage(pc->curcmd, SYNOPSIS);

	if (!reverse) {
		FREEBUF(req->buf);
		FREEBUF(req);
		return;
	}

        revtarget = req->addr;
        if ((sp = value_search(revtarget, NULL)) == NULL)
                error(FATAL, "cannot resolve address: %lx\n", revtarget);

        sprintf(buf1, "0x%lx", revtarget);

        open_tmpfile();

        req->addr = sp->value;
        req->flags |= GNU_FUNCTION_ONLY;
        req->command = GNU_RESOLVE_TEXT_ADDR;
        gdb_interface(req);
        req->flags &= ~GNU_COMMAND_FAILED;
	savename = sp->name;
        if ((sp = next_symbol(NULL, sp)))
                req->addr2 = sp->value;
        else {
		close_tmpfile();
                error(FATAL, "unable to determine symbol after %s\n", savename);
	}

	do_machdep_filter = machdep->dis_filter(req->addr, NULL);
#ifdef OLDWAY
	req->command = GNU_DISASSEMBLE;
	req->fp = pc->tmpfile;
	gdb_interface(req);
#else
        sprintf(buf5, "x/%ldi 0x%lx",
        	(revtarget - req->addr) ? revtarget - req->addr : 1, 
		req->addr);
        gdb_pass_through(buf5, NULL, GNU_RETURN_ON_ERROR);
#endif
        if (req->flags & GNU_COMMAND_FAILED) {
		close_tmpfile();
        	error(FATAL, dis_err, req->addr);
	}

        rewind(pc->tmpfile);
        while (fgets(buf2, BUFSIZE, pc->tmpfile)) {
                if (STRNEQ(buf2, "Dump of") || STRNEQ(buf2, "End of"))
                	continue;

                if (do_load_module_filter)
                        load_module_filter(buf2, LM_DIS_FILTER);

                if (STRNEQ(buf2, "0x"))
                	extract_hex(buf2, &curaddr, ':', TRUE);

		if (do_machdep_filter)
			machdep->dis_filter(curaddr, buf2);

		if (req->flags & GNU_PRINT_LINE_NUMBERS) {
			get_line_number(curaddr, buf3, FALSE);
			if (!STREQ(buf3, buf4)) {
				print_verbatim(pc->saved_fp, buf3);
				print_verbatim(pc->saved_fp, "\n");
				strcpy(buf4, buf3);
			}
		}

                print_verbatim(pc->saved_fp, buf2);
                if (STRNEQ(buf2, buf1)) {
                	if (LASTCHAR(clean_line(buf2)) != ':') 
                        	break;

        		ret = fgets(buf2, BUFSIZE, pc->tmpfile);

                	if (do_load_module_filter)
                        	load_module_filter(buf2, LM_DIS_FILTER);

			if (do_machdep_filter) 
				machdep->dis_filter(curaddr, buf2);

                	print_verbatim(pc->saved_fp, buf2);
			break;
		}
        }

        close_tmpfile();
	FREEBUF(req->buf);
	FREEBUF(req);
}

/*
 *  x86 and x86_64 kernels may have file/line-number encoding
 *  asm()'d in just after the "ud2a" instruction, which confuses
 *  the disassembler and the x86 backtracer.  Determine the 
 *  number of bytes to skip.
 */
static void
BUG_bytes_init(void)
{
	if (machine_type("X86"))
		kt->BUG_bytes = BUG_x86();
	else if (machine_type("X86_64"))
		kt->BUG_bytes = BUG_x86_64();
}

static int
BUG_x86(void)
{
	struct syment *sp, *spn;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char *arglist[MAXARGS];
	ulong vaddr, fileptr;
	int found;

	/*
	 *  Prior to 2.4.19, a call to do_BUG() preceded
	 *  the standalone ud2a instruction.
	 */ 
	if (THIS_KERNEL_VERSION < LINUX(2,4,19))
		return 0;

	/*
	 *  2.6.20 introduced __bug_table support for i386, 
	 *  but even if CONFIG_DEBUG_BUGVERBOSE is not configured,
	 *  the ud2a stands alone.
	 */
	if (THIS_KERNEL_VERSION >= LINUX(2,6,20))
		return 0;

	/*
	 *  For previous kernel versions, it may depend upon 
	 *  whether CONFIG_DEBUG_BUGVERBOSE was configured:
	 *
	 *   #ifdef CONFIG_DEBUG_BUGVERBOSE
	 *   #define BUG()                           \
	 *    __asm__ __volatile__(  "ud2\n"         \
	 *                           "\t.word %c0\n" \
	 *                           "\t.long %c1\n" \
	 *                            : : "i" (__LINE__), "i" (__FILE__))
	 *   #else
	 *   #define BUG() __asm__ __volatile__("ud2\n")
	 *   #endif
	 *
  	 *  But that's not necessarily true, since there are
	 *  pre-2.6.11 versions that force it like so:
	 *
         *   #if 1   /- Set to zero for a slightly smaller kernel -/
         *   #define BUG()                           \
         *    __asm__ __volatile__(  "ud2\n"         \
         *                           "\t.word %c0\n" \
         *                           "\t.long %c1\n" \
         *                            : : "i" (__LINE__), "i" (__FILE__))
         *   #else
         *   #define BUG() __asm__ __volatile__("ud2\n")
         *   #endif
	 */

	/*
	 *  This works if in-kernel config data is available.
	 */
	if ((THIS_KERNEL_VERSION >= LINUX(2,6,11)) &&
	    (kt->flags & BUGVERBOSE_OFF))
		return 0;

	/*
	 *  At this point, it's a pretty safe bet that it's configured,
	 *  but to be sure, disassemble a known BUG() caller and
	 *  verify that the encoding is there.
	 */

#define X86_BUG_BYTES (6)  /* sizeof(short) + sizeof(pointer) */

	if (!(sp = symbol_search("do_exit")) ||
	    !(spn = next_symbol(NULL, sp)))
		return X86_BUG_BYTES;

	sprintf(buf1, "x/%ldi 0x%lx", spn->value - sp->value, sp->value);

	found = FALSE;
	vaddr = 0;
	open_tmpfile();
	gdb_pass_through(buf1, pc->tmpfile, GNU_RETURN_ON_ERROR);
	rewind(pc->tmpfile);
	while (fgets(buf2, BUFSIZE, pc->tmpfile)) {
		if (parse_line(buf2, arglist) < 3)
			continue;

		if ((vaddr = htol(arglist[0], RETURN_ON_ERROR, NULL)) >= spn->value)
			continue; 

		if (STREQ(arglist[2], "ud2a")) {
			found = TRUE;
			break;
		}
	}
	close_tmpfile();

        if (!found || !readmem(vaddr+4, KVADDR, &fileptr, sizeof(ulong),
            "BUG filename pointer", RETURN_ON_ERROR|QUIET))
		return X86_BUG_BYTES;

	if (!IS_KVADDR(fileptr)) {
		if (CRASHDEBUG(1))
			fprintf(fp, 
			    "no filename pointer: kt->BUG_bytes: 0\n");
		return 0;
	}

	if (!read_string(fileptr, buf1, BUFSIZE-1))
		error(WARNING, 
		    "cannot read BUG (ud2a) encoded filename address: %lx\n",
			fileptr);
	else if (CRASHDEBUG(1))
		fprintf(fp, "BUG bytes filename encoding: [%s]\n", buf1);

	return X86_BUG_BYTES;
}

static int
BUG_x86_64(void)
{
        /*
         *  2.6.20 introduced __bug_table support for x86_64,
         *  but even if CONFIG_DEBUG_BUGVERBOSE is not configured,
	 *  the ud2a stands alone.
         */
        if (THIS_KERNEL_VERSION >= LINUX(2,6,20))
                return 0;

	/*
	 *  The original bug_frame structure looks like this, which
	 *  causes the disassembler to go off into the weeds:
	 *
	 *    struct bug_frame { 
	 *        unsigned char ud2[2];          
	 *        char *filename;  
	 *        unsigned short line; 
	 *    } 
	 *  
	 *  In 2.6.13, fake push and ret instructions were encoded 
	 *  into the frame so that the disassembly would at least 
	 *  "work", although the two fake instructions show nonsensical
	 *  arguments:
	 *
	 *    struct bug_frame {
	 *        unsigned char ud2[2];
	 *        unsigned char push;
	 *        signed int filename;
	 *        unsigned char ret;
	 *        unsigned short line;
	 *    }
	 */  

	if (STRUCT_EXISTS("bug_frame"))
		return (int)(STRUCT_SIZE("bug_frame") - 2);

	return 0;
}


/*
 *  Callback from gdb disassembly code.
 */
int
kernel_BUG_encoding_bytes(void)
{
	return kt->BUG_bytes;
}

#ifdef NOT_USED
/*
 *  To avoid premature stoppage/extension of a dis <function> that includes
 *  one of the following x86/gcc 3.2 constant declarations, don't allow them
 *  to be considered the next text symbol.
 */
static struct syment *
next_text_symbol(struct syment *sp_in)
{
	return next_symbol(NULL, sp_in);
	struct syment *sp;

	sp = sp_in; 
	while ((sp = next_symbol(NULL, sp))) {
		if (STREQ(sp->name, "__constant_c_and_count_memset") ||
		    STREQ(sp->name, "__constant_copy_from_user") ||
	            STREQ(sp->name, "__constant_copy_from_user_nocheck") ||
	            STREQ(sp->name, "__constant_copy_to_user") ||
                    STREQ(sp->name, "__constant_copy_to_user_nocheck") ||
		    STREQ(sp->name, "__constant_memcpy") ||
		    STREQ(sp->name, "__constant_c_and_count_memset") ||
		    STREQ(sp->name, "__constant_c_x_memset") ||
		    STREQ(sp->name, "__constant_memcpy")) {
			continue;
		}
		break;
	}
	return sp;
}
#endif  /* NOT_USED */

/*
 *  Nothing to do.
 */
int
generic_dis_filter(ulong value, char *buf)
{
	return TRUE;
}

#define FRAMESIZE_DEBUG_MESSAGE \
"\nx86 usage: bt -F [size|clear|dump|seek|noseek|validate|novalidate] [-I eip]\n  If eip:  set its associated framesize to size.\n           \"validate/novalidate\" will turn on/off V bit for this eip entry.\n  If !eip: \"clear\" will clear the framesize cache and RA seek/noseek flags.\n           \"dump\" will dump the current framesize cache entries.\n           \"seek/noseek\" turns on/off RA seeking.\n           \"validate/novalidate\" turns on/off V bit for all current entries.\n\nx86_64 usage: bt -F [clear|dump|validate] [-I rip]\n  If rip:  \"validate\" will verbosely recalculate the framesize.\n  If !rip: \"clear\" will clear the framesize cache.\n           \"dump\" will dump the current framesize cache entries.\n"


/*
 *  Display a kernel stack backtrace.  Arguments may be any number pid or task
 *  values, or, if no arguments are given, the stack trace of the current 
 *  context will be displayed.  Alternatively:
 *
 *     -a  displays the stack traces of the active tasks on each CPU.
 *         (only applicable to crash dumps)
 *     -r  display raw stack data, consisting of a memory dump of the two
 *         pages of memory containing the task_union structure.
 *     -s  displays arguments symbolically.
 */

void
clone_bt_info(struct bt_info *orig, struct bt_info *new,
	      struct task_context *tc)
{
	BCOPY(orig, new, sizeof(*new));
	new->stackbuf = NULL;
	new->tc = tc;
	new->task = tc->task;
	new->stackbase = GET_STACKBASE(tc->task);
	new->stacktop = GET_STACKTOP(tc->task);
}

#define BT_SETUP(TC)                                          \
	clone_bt_info(&bt_setup, bt, (TC));         	      \
        if (refptr) {                                         \
		BZERO(&reference, sizeof(struct reference));  \
		bt->ref = &reference;                         \
        	bt->ref->str = refptr;                        \
	}

#define DO_TASK_BACKTRACE() 					\
	{							\
	BT_SETUP(tc);						\
	if (!BT_REFERENCE_CHECK(bt))				\
		print_task_header(fp, tc, subsequent++);	\
	back_trace(bt);						\
	}
 
#define DO_THREAD_GROUP_BACKTRACE()	 			\
	{							\
	tc = pid_to_context(tgid);				\
	BT_SETUP(tc);						\
	if (!BT_REFERENCE_CHECK(bt))				\
		print_task_header(fp, tc, subsequent++);	\
	if (setjmp(pc->foreach_loop_env)) {			\
		pc->flags &= ~IN_FOREACH;			\
		free_all_bufs();				\
	} else {						\
		pc->flags |= IN_FOREACH;			\
		back_trace(bt);					\
		pc->flags &= ~IN_FOREACH;			\
	}							\
	tc = FIRST_CONTEXT();					\
	for (i = 0; i < RUNNING_TASKS(); i++, tc++) {		\
		if (tc->pid == tgid) 				\
			continue;				\
		if (task_tgid(tc->task) != tgid)		\
			continue;				\
		BT_SETUP(tc);					\
		if (!BT_REFERENCE_CHECK(bt))			\
			print_task_header(fp, tc, subsequent++);\
		if (setjmp(pc->foreach_loop_env)) {		\
			pc->flags &= ~IN_FOREACH;		\
			free_all_bufs();			\
		} else {					\
			pc->flags |= IN_FOREACH;		\
			back_trace(bt);				\
			pc->flags &= ~IN_FOREACH;		\
		}						\
       	}							\
	pc->flags &= ~IN_FOREACH;				\
	}

void
cmd_bt(void)
{
	int i, c;
	ulong value;
        struct task_context *tc;
	int count, subsequent, active;
	struct stack_hook hook;
	struct bt_info bt_info, bt_setup, *bt;
	struct reference reference;
	char *refptr;
	ulong tgid;

	tc = NULL;
	subsequent = active = count = 0;
	hook.eip = hook.esp = 0;
	refptr = 0;
	bt = &bt_info;
	BZERO(bt, sizeof(struct bt_info));

	if (kt->flags & USE_OLD_BT)
		bt->flags |= BT_OLD_BACK_TRACE;

        while ((c = getopt(argcnt, args, "fF:I:S:aloreEgstTd:R:O")) != EOF) {
                switch (c)
		{
		case 'f':
			bt->flags |= BT_FULL;
			break;

		case 'o':
			if (XEN_HYPER_MODE())
				option_not_supported(c);
			bt->flags |= BT_OLD_BACK_TRACE;
			break;

		case 'O':
			if (!(machine_type("X86") || machine_type("X86_64")) ||
			    XEN_HYPER_MODE()) 
				option_not_supported(c);
			else if (kt->flags & USE_OLD_BT) { 
				/* 
				 *  Make this setting idempotent across the use of
				 *  $HOME/.crashrc, ./.crashrc, and "-i input" files. 
				 *  If we've been here before during initialization,
				 *  leave it alone.
			 	 */
				if (pc->flags & INIT_IFILE) {
					error(INFO, "use old bt method by default (already set)\n");
					return;
				}
				kt->flags &= ~USE_OLD_BT;
				error(INFO, "use new bt method by default\n");
			} else {
				kt->flags |= USE_OLD_BT;
				error(INFO, "use old bt method by default\n");
			}
			return;

		case 'R':
			if (refptr) 
				error(INFO, "only one -R option allowed\n");
			else 
				refptr = optarg;
			break;
			
		case 'l':
			if (GDB_PATCHED())
				error(INFO, "line numbers are not available\n");
			else
				bt->flags |= BT_LINE_NUMBERS;
			break;

		case 'E':
			if (XEN_HYPER_MODE())
				option_not_supported(c);
			bt->flags |= BT_EFRAME_SEARCH|BT_EFRAME_SEARCH2;
			bt->hp = &hook;
			break;

		case 'e':
			if (XEN_HYPER_MODE())
				option_not_supported(c);
			bt->flags |= BT_EFRAME_SEARCH;
			break;

		case 'g':
#if defined(GDB_6_0) || defined(GDB_6_1)
			bt->flags |= BT_THREAD_GROUP;
#else
			bt->flags |= BT_USE_GDB;
#endif
			break;

		case 'd':
			bt->debug = dtol(optarg, FAULT_ON_ERROR, NULL);
			break;

		case 'I':
			bt->hp = &hook;
			hook.eip = convert(optarg, FAULT_ON_ERROR, 
				NULL, NUM_HEX|NUM_EXPR);
			break;

		case 'F':
			if (STREQ(optarg, "seek")) {
				kt->flags |= RA_SEEK;
				kt->flags &= ~NO_RA_SEEK;
				return;
			} else if (STREQ(optarg, "noseek")) {
				kt->flags |= NO_RA_SEEK;
				kt->flags &= ~RA_SEEK;
				return;
			}
			bt->hp = &hook;
			bt->flags |= BT_FRAMESIZE_DEBUG;
			if (STREQ(optarg, "dump"))
				hook.esp = 1;
			else if (STREQ(optarg, "validate"))
				hook.esp = (ulong)-1;
			else if (STREQ(optarg, "novalidate"))
				hook.esp = (ulong)-2;
			else if (STREQ(optarg, "clear")) {
				kt->flags &= ~(RA_SEEK|NO_RA_SEEK);
				hook.esp = 0;
			} else if (*optarg == '-') {
				hook.esp = dtol(optarg+1, FAULT_ON_ERROR, NULL);
				hook.esp = (ulong)(0 - (long)hook.esp);
			} else if (STREQ(optarg, "dwarf") || STREQ(optarg, "cfi")) {
                        	if (!(kt->flags & DWARF_UNWIND_CAPABLE))
					return;
			} else
				hook.esp = dtol(optarg, FAULT_ON_ERROR, NULL);
			break;

		case 'S':
			bt->hp = &hook;
			hook.esp = htol(optarg, FAULT_ON_ERROR, NULL);
			if (!hook.esp)
				error(FATAL, 
				    "invalid stack address for this task: 0\n");
			break;

		case 'a':
			active++;
			break;

		case 'r':
			bt->flags |= BT_RAW;
			break;

		case 's':
			bt->flags |= BT_SYMBOLIC_ARGS;
			break;

		case 'T':
			bt->flags |= BT_TEXT_SYMBOLS_ALL;
		case 't':
			bt->flags |= BT_TEXT_SYMBOLS;
			break;

		default:
			argerrs++;
			if (optopt == 'F') {
				fprintf(fp, FRAMESIZE_DEBUG_MESSAGE);
				return;
			}
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (bt->flags & BT_FRAMESIZE_DEBUG) {
		if (machdep->flags & FRAMESIZE_DEBUG) {
			while (args[optind]) {
				if (!hook.eip)
                       			hook.eip = convert(args[optind], 
						FAULT_ON_ERROR, NULL, 
						NUM_HEX|NUM_EXPR);
				else {
					fprintf(fp, FRAMESIZE_DEBUG_MESSAGE);
					return;
				}
				optind++;
			}
			machdep->back_trace(bt);
			return;
		}
		error(FATAL, "framesize debug not available\n");
	}

	BCOPY(bt, &bt_setup, sizeof(struct bt_info));

	if (bt->flags & BT_EFRAME_SEARCH2) {
               	tc = CURRENT_CONTEXT();  /* borrow stack */
                BT_SETUP(tc);
                back_trace(bt);
                return;
	}

	if (XEN_HYPER_MODE()) {
#ifdef XEN_HYPERVISOR_ARCH
		/* "task" means vcpu for xen hypervisor */
		if (active) {
			for (c = 0; c < XEN_HYPER_MAX_CPUS(); c++) {
				if (!xen_hyper_test_pcpu_id(c))
					continue;
				fake_tc.task = xen_hyper_pcpu_to_active_vcpu(c);
				BT_SETUP(&fake_tc);
			        if (!BT_REFERENCE_CHECK(bt))
					xen_hyper_print_bt_header(fp, fake_tc.task, 
						subsequent++);
				back_trace(bt);
			}
		} else {
			if (args[optind]) {
				fake_tc.task = xen_hyper_pcpu_to_active_vcpu(
				    convert(args[optind], 0, NULL, NUM_DEC | NUM_HEX));
			} else {
				fake_tc.task = XEN_HYPER_VCPU_LAST_CONTEXT()->vcpu;
			}
			BT_SETUP(&fake_tc);
			if (!BT_REFERENCE_CHECK(bt))
				xen_hyper_print_bt_header(fp, fake_tc.task, 0);
			back_trace(bt);
		}
		return;
#else
		error(FATAL, XEN_HYPERVISOR_NOT_SUPPORTED);
#endif
	}

	if (active) {
		if (ACTIVE())
			error(FATAL, 
			    "-a option not supported on a live system\n");

		if (bt->flags & BT_THREAD_GROUP)
			error(FATAL, 
			    "-a option cannot be used with the -g option\n");

		for (c = 0; c < NR_CPUS; c++) {
			if (setjmp(pc->foreach_loop_env)) {
				pc->flags &= ~IN_FOREACH;
				free_all_bufs();
				continue;
			}
			if ((tc = task_to_context(tt->panic_threads[c]))) {
				pc->flags |= IN_FOREACH;
				DO_TASK_BACKTRACE();
				pc->flags &= ~IN_FOREACH;
			}
		}

		return;
	}

	if (!args[optind]) {
		if (CURRENT_PID() && (bt->flags & BT_THREAD_GROUP)) {
			tgid = task_tgid(CURRENT_TASK());
			DO_THREAD_GROUP_BACKTRACE();
		} else {
			tc = CURRENT_CONTEXT();
			DO_TASK_BACKTRACE();
		}
		return;
	}

	while (args[optind]) {
                switch (str_to_context(args[optind], &value, &tc))
                {
                case STR_PID:
                        for (tc = pid_to_context(value); tc; tc = tc->tc_next) {
				if (tc->pid && (bt->flags & BT_THREAD_GROUP)) {
					tgid = task_tgid(tc->task);
					DO_THREAD_GROUP_BACKTRACE();
					break;
				} else if (tc->tc_next) {
		                        if (setjmp(pc->foreach_loop_env)) {
						pc->flags &= ~IN_FOREACH;
						free_all_bufs();
						continue;
					}
					pc->flags |= IN_FOREACH;
					DO_TASK_BACKTRACE();
					pc->flags &= ~IN_FOREACH;
				} else 
					DO_TASK_BACKTRACE();
			}
			break;

                case STR_TASK:
			if (tc->pid && (bt->flags & BT_THREAD_GROUP)) {
				tgid = task_tgid(value);
				DO_THREAD_GROUP_BACKTRACE();
			} else
				DO_TASK_BACKTRACE();
			break;

                case STR_INVALID:
                        error(INFO, "%sinvalid task or pid value: %s\n",
                                subsequent++ ? "\n" : "", args[optind]);
                        break;
                }

		optind++;
	}
}

void
print_stack_text_syms(struct bt_info *bt, ulong esp, ulong eip)
{
	ulong next_sp, next_pc;
	int i;
	ulong *up;
	char buf[BUFSIZE];

	if (bt->flags & BT_TEXT_SYMBOLS) {
		if (!(bt->flags & BT_TEXT_SYMBOLS_ALL))
			fprintf(fp, "%sSTART: %s at %lx\n",
				space(VADDR_PRLEN > 8 ? 14 : 6),
		        	closest_symbol(eip), eip);
	}

	if (bt->hp) 
		bt->hp->eip = bt->hp->esp = 0;
	next_pc = next_sp = 0;

	for (i = (esp - bt->stackbase)/sizeof(ulong);
	     i < LONGS_PER_STACK; i++) {
		up = (ulong *)(&bt->stackbuf[i*sizeof(ulong)]);
		if (is_kernel_text_offset(*up)) {
			if (!next_pc) 
				next_pc = *up;
			else if (!next_sp) 
				next_sp = bt->stackbase + (i * sizeof(long));
		}
		if (is_kernel_text(*up) && (bt->flags & 
		    (BT_TEXT_SYMBOLS|BT_TEXT_SYMBOLS_PRINT))) { 
			if (bt->flags & (BT_ERROR_MASK|BT_TEXT_SYMBOLS))
                               	fprintf(fp, "  %s[%s] %s at %lx\n",
					bt->flags & BT_ERROR_MASK ?
					"  " : "",
					mkstring(buf, VADDR_PRLEN, 
					RJUST|LONG_HEX,
                               		MKSTR(bt->stackbase + 
					(i * sizeof(long)))),
					closest_symbol(*up), *up);
			else
                               	fprintf(fp, "%lx: %s\n",
                                       	bt->stackbase + 
					(i * sizeof(long)),
                                       	value_to_symstr(*up, buf, 0));
		}
	}

	if (bt->hp) {
		bt->hp->eip = next_pc;
		bt->hp->esp = next_sp;
	}
}

/*
 *  Gather the EIP, ESP and stack address for the target task, and passing 
 *  them on to the machine-specific back trace command.
 */
void
back_trace(struct bt_info *bt)
{
	int i;
	ulong *up;
	char buf[BUFSIZE];
	ulong eip, esp;
	struct bt_info btsave;

	if (bt->flags & BT_RAW) {
		if (bt->hp && bt->hp->esp)
			esp = bt->hp->esp;
		else 
			esp = GET_STACKBASE(bt->task);
		raw_stack_dump(esp, STACKSIZE());
		return;
	}

	if (ACTIVE() && !(bt->flags & BT_EFRAME_SEARCH) && 
            ((bt->task == tt->this_task) || is_task_active(bt->task))) {

		if (BT_REFERENCE_CHECK(bt) ||
		    bt->flags & (BT_TEXT_SYMBOLS_PRINT|BT_TEXT_SYMBOLS_NOPRINT))
			return;

		if (!(bt->flags & BT_KSTACKP))
			fprintf(fp, "(active)\n");

		return;
 	}

	fill_stackbuf(bt);

	if (CRASHDEBUG(4)) {
		for (i = 0, up = (ulong *)bt->stackbuf; 
		     i < LONGS_PER_STACK; i++, up++) {
			if (is_kernel_text(*up))
				fprintf(fp, "%lx: %s\n", 
					tt->flags & THREAD_INFO ?
					bt->tc->thread_info + 
					(i * sizeof(long)) :
					bt->task + (i * sizeof(long)),
					value_to_symstr(*up, buf, 0));
		}
	}

	if (BT_REFERENCE_CHECK(bt)) {
		if (can_eval(bt->ref->str)) {
			bt->ref->hexval = eval(bt->ref->str, 
				FAULT_ON_ERROR, NULL);
			bt->ref->cmdflags |= BT_REF_HEXVAL;
		} else if (hexadecimal(bt->ref->str, 0)) {
			bt->ref->hexval = htol(bt->ref->str, 
				FAULT_ON_ERROR, NULL);
			bt->ref->cmdflags |= BT_REF_HEXVAL;
		} else
			bt->ref->cmdflags |= BT_REF_SYMBOL;
	}

	if (bt->flags & BT_EFRAME_SEARCH) {
		machdep->eframe_search(bt); 
		return;
	}
	
	if (bt->hp) {
		if (bt->hp->esp && !INSTACK(bt->hp->esp, bt))
			error(INFO, 
			    "non-process stack address for this task: %lx\n    (valid range: %lx - %lx)\n",
				bt->hp->esp, bt->stackbase, bt->stacktop);
		eip = bt->hp->eip;
		esp = bt->hp->esp;

		machdep->get_stack_frame(bt, eip ? NULL : &eip, 
			esp ? NULL : &esp);
	 
        } else if (XEN_HYPER_MODE())
		machdep->get_stack_frame(bt, &eip, &esp);
	else if (NETDUMP_DUMPFILE())
                get_netdump_regs(bt, &eip, &esp);
	else if (KDUMP_DUMPFILE())
                get_kdump_regs(bt, &eip, &esp);
	else if (DISKDUMP_DUMPFILE())
                get_diskdump_regs(bt, &eip, &esp);
	else if (KVMDUMP_DUMPFILE())
                get_kvmdump_regs(bt, &eip, &esp);
        else if (LKCD_DUMPFILE())
                get_lkcd_regs(bt, &eip, &esp);
	else if (XENDUMP_DUMPFILE())
		get_xendump_regs(bt, &eip, &esp);
        else
                machdep->get_stack_frame(bt, &eip, &esp);

	if (bt->flags & BT_KSTACKP) {
		bt->stkptr = esp;
		return;
	}

	if (ACTIVE() && !INSTACK(esp, bt)) {
		sprintf(buf, "/proc/%ld", bt->tc->pid); 
		if (!file_exists(buf, NULL))
			error(INFO, "task no longer exists\n");
		else 
			error(INFO, 
			    "invalid/stale stack pointer for this task: %lx\n", 
				esp);
		return;
	}

	if (bt->flags & 
	    (BT_TEXT_SYMBOLS|BT_TEXT_SYMBOLS_PRINT|BT_TEXT_SYMBOLS_NOPRINT)) {

		if (bt->flags & BT_TEXT_SYMBOLS_ALL) {
			esp = bt->stackbase + 
				((tt->flags & THREAD_INFO) ?
				SIZE(thread_info) : SIZE(task_struct));
			eip = 0;
		}

		if (machdep->flags & MACHDEP_BT_TEXT) {
			bt->instptr = eip;
			bt->stkptr = esp;
			machdep->back_trace(bt);
		} else
			print_stack_text_syms(bt, esp, eip);

		if (bt->flags & (BT_HARDIRQ|BT_SOFTIRQ)) {
			struct bt_info btloc;
			struct stack_hook stack_hook;

			BZERO(&btloc, sizeof(struct bt_info));
			BZERO(&stack_hook, sizeof(struct stack_hook));
			btloc.flags = bt->flags & ~(BT_HARDIRQ|BT_SOFTIRQ);
			btloc.hp = &stack_hook;
			btloc.tc = bt->tc;
			btloc.task = bt->task;
			btloc.stackbase = GET_STACKBASE(bt->task);
			btloc.stacktop = GET_STACKTOP(bt->task);

        		switch (bt->flags & (BT_HARDIRQ|BT_SOFTIRQ))
        		{
        		case BT_HARDIRQ:
				btloc.hp->eip = symbol_value("do_IRQ");
				if (symbol_exists("__do_IRQ"))
					btloc.hp->esp = ULONG(bt->stackbuf +
					    OFFSET(thread_info_previous_esp));
				else
					btloc.hp->esp = ULONG(bt->stackbuf +
					    SIZE(irq_ctx) - 
					    (sizeof(char *)*2));
				fprintf(fp, "--- <hard IRQ> ---\n");
                		break;

        		case BT_SOFTIRQ:
				btloc.hp->eip = symbol_value("do_softirq");
                		btloc.hp->esp = ULONG(bt->stackbuf +
                        		OFFSET(thread_info_previous_esp));
				fprintf(fp, "--- <soft IRQ> ---\n");
                		break;
        		}

			back_trace(&btloc);
		}
		
		return;
	}

	bt->instptr = eip;
	bt->stkptr = esp;

complete_trace:

	if (BT_REFERENCE_CHECK(bt))
		BCOPY(bt, &btsave, sizeof(struct bt_info));

	if (CRASHDEBUG(4))
		dump_bt_info(bt, "back_trace");

	machdep->back_trace(bt);

	if ((bt->flags & (BT_HARDIRQ|BT_SOFTIRQ)) && restore_stack(bt))  
		goto complete_trace;

	if (BT_REFERENCE_FOUND(bt)) {
#ifdef XEN_HYPERVISOR_ARCH
		if (XEN_HYPER_MODE())
			xen_hyper_print_bt_header(fp, bt->task, 0);
		else
			print_task_header(fp, task_to_context(bt->task), 0);
#else
		print_task_header(fp, task_to_context(bt->task), 0);
#endif /* XEN_HYPERVISOR_ARCH */

		BCOPY(&btsave, bt, sizeof(struct bt_info));
		bt->ref = NULL;
		machdep->back_trace(bt);
		fprintf(fp, "\n");
	}
}

/*
 *  Restore a bt_info to make the jump from an IRQ stack to the task's
 *  normal stack.
 */
static int 
restore_stack(struct bt_info *bt)
{
	ulonglong type;
	struct syment *sp;
	ulong retvaddr;

	bt->instptr = bt->stkptr = 0;
	type = 0;

	switch (bt->flags & (BT_HARDIRQ|BT_SOFTIRQ)) 
	{ 
	case BT_HARDIRQ:
		retvaddr = ULONG(bt->stackbuf +
			SIZE(irq_ctx) - sizeof(char *));
		if ((sp = value_search(retvaddr, NULL)) && 
			STREQ(sp->name, "do_IRQ"))
			bt->instptr = retvaddr; 
		else
			bt->instptr = symbol_value("do_IRQ");
		if (symbol_exists("__do_IRQ"))
            		bt->stkptr = ULONG(bt->stackbuf +
                     		OFFSET(thread_info_previous_esp));
		else
			bt->stkptr = ULONG(bt->stackbuf + 
				SIZE(irq_ctx) - (sizeof(char *)*2));
		type = BT_HARDIRQ;
		break;

	case BT_SOFTIRQ:
		retvaddr = ULONG(bt->stackbuf +
			SIZE(irq_ctx) - sizeof(char *));
		if ((sp = value_search(retvaddr, NULL)) && 
			STREQ(sp->name, "do_softirq"))
			bt->instptr = retvaddr; 
		else
			bt->instptr = symbol_value("do_softirq");
               	bt->stkptr = ULONG(bt->stackbuf +
                       	OFFSET(thread_info_previous_esp));
		type = BT_SOFTIRQ;
		break;
	}

	bt->flags &= ~(BT_HARDIRQ|BT_SOFTIRQ); 
	bt->stackbase = GET_STACKBASE(bt->tc->task);
        bt->stacktop = GET_STACKTOP(bt->tc->task);

        if (!readmem(bt->stackbase, KVADDR, bt->stackbuf,
            bt->stacktop - bt->stackbase, 
	    "restore_stack contents", RETURN_ON_ERROR)) {
        	error(INFO, "restore_stack of stack at %lx failed\n", 
			bt->stackbase);
		type = 0;
	}

	if (!(bt->instptr && INSTACK(bt->stkptr, bt)))
		type = 0;

	if (type) {
		if (!BT_REFERENCE_CHECK(bt))
		fprintf(fp, "--- %s ---\n", type == BT_HARDIRQ ? 
			"<hard IRQ>" : "<soft IRQ>");
		return TRUE;
	}

	return FALSE;
}


#define MAXHOOKS (100)

struct stack_hook *
gather_text_list(struct bt_info *bt) 
{
	int cnt;
	struct bt_info btloc;
	char buf[BUFSIZE], *p1;
	struct stack_hook *hooks;
	ulong esp, eip;
	FILE *savedfp;

	BCOPY(bt, &btloc, sizeof(struct bt_info));
	hooks = (struct stack_hook *)GETBUF(sizeof(struct stack_hook)*MAXHOOKS);
	cnt = 0;

	savedfp = fp;
        open_tmpfile2();
	fp = pc->tmpfile2;
        btloc.flags = BT_TEXT_SYMBOLS_PRINT;
        back_trace(&btloc);
        rewind(pc->tmpfile2);
        while (fgets(buf, BUFSIZE, pc->tmpfile2)) {
		if ((p1 = strstr(buf, ":"))) {
			esp = eip = 0;
                	*p1 = NULLCHAR;
			if (((esp = htol(buf, RETURN_ON_ERROR, NULL)) != BADADDR)
			    && INSTACK(esp, bt))
                                eip = GET_STACK_ULONG(esp);
			if (esp && eip) {
				hooks[cnt].esp = esp;
				hooks[cnt].eip = eip;
				if (++cnt == MAXHOOKS)
					break;
			}
		}
	}
	close_tmpfile2();
	fp = savedfp;

	if (cnt)
		return (bt->textlist = hooks);
	else {
		FREEBUF(hooks);
		return (bt->textlist = NULL);
	}
}

/*
 *  Debug routine most likely useful from above in back_trace()
 */
void
dump_bt_info(struct bt_info *bt, char *where)
{
	fprintf(fp, "[%lx] %s:\n", (ulong)bt, where);
	fprintf(fp, "        task: %lx\n", bt->task);
	fprintf(fp, "       flags: %llx\n", bt->flags);
	fprintf(fp, "     instptr: %lx\n", bt->instptr);
	fprintf(fp, "      stkptr: %lx\n", bt->stkptr);
	fprintf(fp, "        bptr: %lx\n", bt->bptr);
	fprintf(fp, "   stackbase: %lx\n", bt->stackbase);
	fprintf(fp, "    stacktop: %lx\n", bt->stacktop);
	fprintf(fp, "          tc: %lx ", (ulong)bt->tc);
	if (bt->tc)
		fprintf(fp, "(%ld, %lx)\n", bt->tc->pid, bt->tc->task);
	else
		fprintf(fp, "(unknown context)\n");
	fprintf(fp, "          hp: %lx\n", (ulong)bt->hp);
	fprintf(fp, "         ref: %lx\n", (ulong)bt->ref);
	fprintf(fp, "    stackbuf: %lx\n", (ulong)bt->stackbuf);
	fprintf(fp, "    textlist: %lx\n", (ulong)bt->textlist);
	fprintf(fp, "    frameptr: %lx\n", (ulong)bt->frameptr);
	fprintf(fp, " call_target: %s\n", bt->call_target ? 
		bt->call_target : "none");
	fprintf(fp, "   eframe_ip: %lx\n", bt->eframe_ip);
	fprintf(fp, "       debug: %lx\n", bt->debug);
}

/*
 *  LKCD doesn't save state of the active tasks in the TSS, so poke around 
 *  the raw stack for some reasonable hooks.
 */
static void
get_lkcd_regs(struct bt_info *bt, ulong *eip, ulong *esp)
{
	int i;
	char *sym;
	ulong *up;
	ulong sysrq_eip, sysrq_esp;

	if (!is_task_active(bt->task)) {
		machdep->get_stack_frame(bt, eip, esp);
		return;
	}

	/* try to get it from the header */
	if (get_lkcd_regs_for_cpu(bt, eip, esp) == 0)
		return;

	/* if that fails: do guessing */
	sysrq_eip = sysrq_esp = 0;

	for (i = 0, up = (ulong *)bt->stackbuf; i < LONGS_PER_STACK; i++, up++){
		sym = closest_symbol(*up);
		if (STREQ(sym, "dump_execute") && INSTACK(*(up-1), bt)) {
			*eip = *up;
			*esp = *(up-1);
			return;
		}
                /* Begin 3PAR change -- required for our panic path */
		if (STREQ(sym, "dump_ipi") && INSTACK(*(up-1), bt)) {
			*eip = *up;
			*esp = *(up-1);
			return;
		}
		/* End 3PAR change */
                if (STREQ(sym, "panic") && INSTACK(*(up-1), bt)) {
                        *eip = *up;
                        *esp = *(up-1);
                        return;
                }
		/* Egenera */
                if (STREQ(sym, "netdump_ipi")) {
                        *eip = *up;
                        *esp = bt->task + 
				((char *)(up-1) - bt->stackbuf);
                        return;
                }
		if (STREQ(sym, "dump_execute")) {
                        *eip = *up;
                        *esp = bt->stackbase + 
				((char *)(up) - bt->stackbuf);
                        return;
		}
		if (STREQ(sym, "vmdump_nmi_callback")) {
                        *eip = *up;
                        *esp = bt->stackbase + 
				((char *)(up) - bt->stackbuf);
                        return;
		}
                if (STREQ(sym, "smp_stop_cpu_interrupt")) {
                        *eip = *up;
                        *esp = bt->task + 
				((char *)(up-1) - bt->stackbuf);
                        return;
                }
                if (STREQ(sym, "stop_this_cpu")) {
                        *eip = *up;
                        *esp = bt->task + 
				((char *)(up-1) - bt->stackbuf);
                        return;
                }
                if (SYSRQ_TASK(bt->task) &&
		    STREQ(sym, "smp_call_function_interrupt")) {
                        sysrq_eip = *up;
                        sysrq_esp = bt->task +
                                ((char *)(up-1) - bt->stackbuf);
                }
	}

	if (sysrq_eip) {
        	*eip = sysrq_eip;
        	*esp = sysrq_esp;
		return;
	}

	machdep->get_stack_frame(bt, eip, esp);
}


/*
 *  Store the head of the kernel module list for future use.
 *  Count the number of symbols defined by all modules in the system,
 *  and pass it on to store_module_symbols() to deal with.
 */
void
module_init(void)
{
	int i, c;
        ulong size, mod, mod_next;
	uint nsyms;
	ulong total, numksyms;
        char *modbuf, *kallsymsbuf;
	ulong kallsyms_header;
	struct syment *sp, *sp_array[10];
	struct kernel_list_head list;
	int modules_found;

	if (kernel_symbol_exists("module_list")) 
		kt->flags |= KMOD_V1;
	else if (kernel_symbol_exists("modules"))
		kt->flags |= KMOD_V2;
	else 
		error(WARNING, "cannot determine how modules are linked\n");

        if (kt->flags & NO_MODULE_ACCESS || !(kt->flags & (KMOD_V1|KMOD_V2))) {
                error(WARNING, "no kernel module access\n\n");
                kt->module_list = 0;
                kt->mods_installed = 0;
                return;
        }

	STRUCT_SIZE_INIT(module, "module");
        MEMBER_OFFSET_INIT(module_name, "module", "name");
        MEMBER_OFFSET_INIT(module_syms, "module", "syms");
	mod_next = nsyms = 0;

	switch (kt->flags & (KMOD_V1|KMOD_V2))
	{
	case KMOD_V1:
        	MEMBER_OFFSET_INIT(module_size_of_struct, "module", 
			"size_of_struct");
        	MEMBER_OFFSET_INIT(module_next, "module", "next");
        	MEMBER_OFFSET_INIT(module_nsyms, "module", "nsyms");
        	MEMBER_OFFSET_INIT(module_size, "module", "size");
        	MEMBER_OFFSET_INIT(module_flags, "module", "flags");

        	get_symbol_data("module_list", sizeof(ulong), &kt->module_list);
        	kt->kernel_module = symbol_value("kernel_module");
		break;	

	case KMOD_V2: 
		MEMBER_OFFSET_INIT(module_num_syms, "module", "num_syms");
		MEMBER_OFFSET_INIT(module_list, "module", "list");
        	MEMBER_OFFSET_INIT(module_gpl_syms, "module", "gpl_syms");
        	MEMBER_OFFSET_INIT(module_num_gpl_syms, "module", 
			"num_gpl_syms");
        	MEMBER_OFFSET_INIT(module_module_core, "module", 
			"module_core");
        	MEMBER_OFFSET_INIT(module_core_size, "module", 
			"core_size");
        	MEMBER_OFFSET_INIT(module_core_text_size, "module", 
			"core_text_size");

		/*
		 *  Make sure to pick the kernel "modules" list_head symbol,
		 *  not to be confused with the ia64/sn "modules[]" array.
		 *  The kernel modules list_head will either point to itself
		 *  (empty) or contain vmalloc'd module addresses; the ia64/sn
		 *  modules array contains a list of kmalloc'd addresses.
		 */
        	if ((c = get_syment_array("modules", sp_array, 10)) > 1) {
			modules_found = FALSE;
			for (i = 0; i < c; i++) {
				sp = sp_array[i];

				if (!readmem(sp->value, KVADDR, 
				    &list, sizeof(struct kernel_list_head), 
				    "modules list_head test", 
				    RETURN_ON_ERROR|QUIET)) 
					continue;

				if ((ulong)list.next == symbol_value("modules")) {
                			kt->mods_installed = 0;
					return;
				}

				if (IS_VMALLOC_ADDR((ulong)list.next) &&
				    IS_VMALLOC_ADDR((ulong)list.prev)) {
					kt->kernel_module = sp->value;
					kt->module_list = (ulong)list.next;
					modules_found = TRUE;
					break;
				}
			} 

			if (!modules_found) {
                        	error(WARNING,
          "cannot determine which of %d \"modules\" symbols is appropriate\n\n",
					c);
                       		kt->mods_installed = 0;
                        	kt->flags |= NO_MODULE_ACCESS;
				return;
			}
		} else {
        		get_symbol_data("modules", sizeof(ulong), 
				&kt->module_list);
			if (kt->module_list == symbol_value("modules")) {
                		kt->mods_installed = 0;
				return;
			}
        		kt->kernel_module = symbol_value("modules");
		}
		kt->module_list -= OFFSET(module_list);
		break;
	}

	total = kt->mods_installed = 0;

        modbuf = GETBUF(SIZE(module));
	kallsymsbuf = kt->flags & KALLSYMS_V1 ?
		GETBUF(SIZE(kallsyms_header)) : NULL;

	please_wait("gathering module symbol data");

        for (mod = kt->module_list; mod != kt->kernel_module; mod = mod_next) {
		if (CRASHDEBUG(3))
			fprintf(fp, "module: %lx\n", mod);

                if (!readmem(mod, KVADDR, modbuf, SIZE(module), 
		    "module struct", RETURN_ON_ERROR|QUIET)) {
                        error(WARNING,
                            "%scannot access vmalloc'd module memory\n\n",
				DUMPFILE() ? "\n" : "");
                        kt->mods_installed = 0;
                        kt->flags |= NO_MODULE_ACCESS;
                        FREEBUF(modbuf); 
			return;
		}

		switch (kt->flags & (KMOD_V1|KMOD_V2))
		{
		case KMOD_V1:
                	nsyms = UINT(modbuf + OFFSET(module_nsyms));
			break;
		case KMOD_V2: 
                	nsyms = UINT(modbuf + OFFSET(module_num_syms)) +
				UINT(modbuf + OFFSET(module_num_gpl_syms));
			break;
		}

		total += nsyms;
		total += 2;  /* store the module's start/ending addresses */

		/*
		 *  If the module has kallsyms, set up to grab them as well.
		 */
		switch (kt->flags & (KALLSYMS_V1|KALLSYMS_V2))
		{
		case KALLSYMS_V1: 
			kallsyms_header = ULONG(modbuf +
				OFFSET(module_kallsyms_start));	
			if (kallsyms_header) {
	                	if (!readmem(kallsyms_header, KVADDR, 
				    kallsymsbuf, SIZE(kallsyms_header), 
				    "kallsyms_header", RETURN_ON_ERROR|QUIET)) {
	                        	error(WARNING,
                                      "%scannot access module kallsyms_header\n",
					    DUMPFILE() ? "\n" : "");
				} else {
					nsyms = UINT(kallsymsbuf +
				 	    OFFSET(kallsyms_header_symbols));
					total += nsyms; 
				}
			}
			break;

		case KALLSYMS_V2:
			if (THIS_KERNEL_VERSION >= LINUX(2,6,27)) {
				numksyms = UINT(modbuf + OFFSET(module_num_symtab));
				size = UINT(modbuf + OFFSET(module_core_size));
			} else {
				numksyms = ULONG(modbuf + OFFSET(module_num_symtab));
				size = ULONG(modbuf + OFFSET(module_core_size));
			}

			if (!size) {
				/*
				 *  Bail out here instead of a crashing with a 
				 *  getbuf(0) failure during storage later on.
				 */
				error(WARNING, 
				    "invalid kernel module size: 0\n");
					kt->mods_installed = 0;
					kt->flags |= NO_MODULE_ACCESS;
				FREEBUF(modbuf); 
				return;
			}

			total += numksyms; 
			break;
		}

		kt->mods_installed++;

		NEXT_MODULE(mod_next, modbuf);
	}

        FREEBUF(modbuf);
	if (kallsymsbuf)
		FREEBUF(kallsymsbuf);

	switch (kt->flags & (KMOD_V1|KMOD_V2))
	{
	case KMOD_V1:
		store_module_symbols_v1(total, kt->mods_installed);
		break;
	case KMOD_V2:
		store_module_symbols_v2(total, kt->mods_installed);
		break;
	}

	please_wait_done();
}


/*
 *  Verify that the current set of modules jives with what's stored.
 */
static int
verify_modules(void)
{
	int i;
	int found, irregularities;
        ulong mod, mod_next, mod_base;
	long mod_size;
        char *modbuf, *module_name;
	ulong module_list, mod_name; 
	physaddr_t paddr;
	int mods_installed;
	struct load_module *lm;
	char buf[BUFSIZE];

	if (DUMPFILE() || !kt->module_list || (kt->flags & NO_MODULE_ACCESS))
		return TRUE;

	switch (kt->flags & (KMOD_V1|KMOD_V2))
	{
	case KMOD_V1:
        	get_symbol_data("module_list", sizeof(ulong), &module_list);
		break;
	case KMOD_V2:
                if (kt->module_list == symbol_value("modules")) {
			if (!kt->mods_installed)
				return TRUE;
                }
                get_symbol_data("modules", sizeof(ulong), &module_list);
                module_list -= OFFSET(module_list);
		break;
	}

	mods_installed = irregularities = 0;
	mod_base = mod_next = 0;
        modbuf = GETBUF(SIZE(module));

        for (mod = module_list; mod != kt->kernel_module; mod = mod_next) {

                if (!readmem(mod, KVADDR, modbuf, SIZE(module), 
		    "module struct", RETURN_ON_ERROR|QUIET)) {
                        error(WARNING,
                            "cannot access vmalloc'd module memory\n");
                        FREEBUF(modbuf);
                        return FALSE;
		}


                for (i = 0, found = FALSE; i < kt->mods_installed; i++) {
                        lm = &st->load_modules[i];
			if (!kvtop(NULL, lm->mod_base, &paddr, 0)) {
				irregularities++;
                                break;
			}

			switch (kt->flags & (KMOD_V1|KMOD_V2))
			{
			case KMOD_V1:
				mod_base = mod;
				break;
			case KMOD_V2:
				mod_base = ULONG(modbuf + 
					OFFSET(module_module_core));
				break;
			}

			if (lm->mod_base == mod_base) {
				switch (kt->flags & (KMOD_V1|KMOD_V2))
				{
				case KMOD_V1:
        				mod_name = ULONG(modbuf + 
						OFFSET(module_name));
					mod_size = LONG(modbuf + 
						OFFSET(module_size));
                			if (!read_string(mod_name, buf, 
					    BUFSIZE-1) || !STREQ(lm->mod_name, 
					    buf) || (mod_size != lm->mod_size)){
						irregularities++;
						goto irregularity;
					}
					break;
				case KMOD_V2:
        				module_name = modbuf + 
						OFFSET(module_name);
					if (THIS_KERNEL_VERSION >= LINUX(2,6,27))
						mod_size = UINT(modbuf +
							OFFSET(module_core_size));
					else
						mod_size = ULONG(modbuf +
							OFFSET(module_core_size));
                			if (strlen(module_name) < MAX_MOD_NAME)
                        			strcpy(buf, module_name);
                			else 
                        			strncpy(buf, module_name, 
							MAX_MOD_NAME-1);
					if (!STREQ(lm->mod_name, buf) ||
					    (mod_size != lm->mod_size)) {
						irregularities++;
						goto irregularity;
					}
					break;
				}
				found = TRUE;
irregularity:
				break;
			}
		}

		if (!found || irregularities) 
			return FALSE;

		mods_installed++;

		NEXT_MODULE(mod_next, modbuf);
	}

        FREEBUF(modbuf);

	if (mods_installed != kt->mods_installed) 
		return FALSE;

	return TRUE;
}


/*
 *  With no arguments, just dump basic data concerning each of the 
 *  currently-loaded modules.  The -s and -S arguments dynamically
 *  loads module symbols from its object file.
 */
#define LIST_MODULE_HDR               (0)
#define LIST_MODULE                   (1)
#define LOAD_ALL_MODULE_SYMBOLS       (2)
#define LOAD_SPECIFIED_MODULE_SYMBOLS (3)
#define DELETE_MODULE_SYMBOLS         (4)
#define DELETE_ALL_MODULE_SYMBOLS     (5)
#define REMOTE_MODULE_SAVE_MSG        (6)
#define REINIT_MODULES                (7)

void
cmd_mod(void)
{
	int c;
	char *objfile, *modref, *tree, *symlink;
	ulong flag, address;
	char buf[BUFSIZE];

	if (kt->flags & NO_MODULE_ACCESS)
		error(FATAL, "cannot access vmalloc'd module memory\n");

	if (!verify_modules()) {
 	 	error(NOTE, 
	             "modules have changed on this system -- reinitializing\n");
		reinit_modules();
	}

	if (!kt->mods_installed) {
		fprintf(fp, "no modules installed\n");
		return;
	}

	modref = objfile = tree = symlink = NULL;
	address = 0;
	flag = LIST_MODULE_HDR;

        while ((c = getopt(argcnt, args, "rd:Ds:So")) != EOF) {
                switch(c)
		{
                case 'r':
                        if (flag)
                                cmd_usage(pc->curcmd, SYNOPSIS);
                        flag = REINIT_MODULES;
                        break;

		case 'D':
			if (flag) 
				cmd_usage(pc->curcmd, SYNOPSIS);
			flag = DELETE_ALL_MODULE_SYMBOLS;
			break;

		case 'd':
                        if (flag)
                                cmd_usage(pc->curcmd, SYNOPSIS);
                        else
                                flag = DELETE_MODULE_SYMBOLS;

                        if (hexadecimal(optarg, 0) &&
                            (strlen(optarg) == VADDR_PRLEN)) {
                                address = htol(optarg, FAULT_ON_ERROR, NULL);
                                if (!is_module_address(address, buf))
                                        cmd_usage(pc->curcmd, SYNOPSIS);
				modref = buf;
                        } else if (is_module_name(optarg, &address, NULL))
                                modref = optarg;
                        else
                                cmd_usage(pc->curcmd, SYNOPSIS);
                        break;

                /*
                 *  Revert to using old-style add-symbol-file command
		 *  for KMOD_V2 kernels.
                 */
                case 'o':
			if (flag) 
				cmd_usage(pc->curcmd, SYNOPSIS);
			if (kt->flags & KMOD_V1)
				error(INFO, 
				    "-o option is not applicable to this kernel version\n");
                        st->flags |= USE_OLD_ADD_SYM;
			return;

		case 'S':
			if (flag) 
				cmd_usage(pc->curcmd, SYNOPSIS);
			else
				flag = LOAD_ALL_MODULE_SYMBOLS; 
			break;

		case 's':
                        if (flag)
				cmd_usage(pc->curcmd, SYNOPSIS);
			else
				flag = LOAD_SPECIFIED_MODULE_SYMBOLS;

			if (hexadecimal(optarg, 0) && 
			    (strlen(optarg) == VADDR_PRLEN)) {
				address = htol(optarg, FAULT_ON_ERROR, NULL);
				if (!is_module_address(address, buf))
					cmd_usage(pc->curcmd, SYNOPSIS);
				modref = buf;
			} else if (is_module_name(optarg, &address, NULL))
				modref = optarg;
			else
				cmd_usage(pc->curcmd, SYNOPSIS);
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (tree && (flag != LOAD_ALL_MODULE_SYMBOLS))
		argerrs++;

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (NO_MODULES()) {
                error(INFO, "no modules loaded in this kernel\n");
		if (flag != LIST_MODULE_HDR)
                	cmd_usage(pc->curcmd, SYNOPSIS);
		return;
	}

	switch (flag)
	{
	case LOAD_ALL_MODULE_SYMBOLS:
		switch (argcnt) 
		{
		case 3:
			if (is_directory(args[2]))
				tree = args[2];
			else {
                		error(INFO, "%s is not a directory\n", args[2]);
				cmd_usage(pc->curcmd, SYNOPSIS);
			}
			break;

		case 2:
			break;

		default:
			cmd_usage(pc->curcmd, SYNOPSIS);
		}
		break;

	case LOAD_SPECIFIED_MODULE_SYMBOLS:
		switch (argcnt)
		{
		case 4:
			objfile = args[3];
			if (!file_exists(objfile, NULL)) { 
				if (!(objfile = 
				    find_module_objfile(modref, objfile, tree)))
					error(FATAL, 
				    "%s: cannot find or load object file: %s\n",
						modref, args[3]);
			} 
			break;

		case 3:
                        if (!(objfile = find_module_objfile(modref,NULL,tree)))
                        	error(FATAL, 
                              "cannot find or load object file for %s module\n",
					modref);
			break;

		default:
			cmd_usage(pc->curcmd, SYNOPSIS);
		}

                if (!is_elf_file(objfile)) {
                        error(INFO, "%s: not an ELF format object file\n", 
				objfile);
                        cmd_usage(pc->curcmd, SYNOPSIS);
                }

		break;

	default:
		break;
	}

	if ((flag == LOAD_ALL_MODULE_SYMBOLS) &&
	    (tree || kt->module_tree)) {
		if (!tree)
			tree = kt->module_tree;

		pc->curcmd_flags |= MODULE_TREE;
	}

	do_module_cmd(flag, modref, address, objfile, tree);

	if (symlink)
		FREEBUF(symlink);
}

int
check_specified_module_tree(char *module, char *gdb_buffer)
{
	char *p1, *treebuf;
	int retval;

	retval = FALSE;

	if (!(pc->curcmd_flags & MODULE_TREE))
		return retval;
	/*
	 *  Search for "/lib/modules" in the module name string
	 *  and insert "/usr/lib/debug" there.
	 */
	if (strstr(module, "/lib/modules")) {
		treebuf = GETBUF(strlen(module) + strlen("/usr/lib/debug") +
                        strlen(".debug") + 1);
		strcpy(treebuf, module);
		p1 = strstr(treebuf, "/lib/modules");
		shift_string_right(p1, strlen("/usr/lib/debug"));
		BCOPY("/usr/lib/debug", p1, strlen("/usr/lib/debug"));
		strcat(treebuf, ".debug");
		if (file_exists(treebuf, NULL)) {
			strcpy(gdb_buffer, treebuf);
			retval = TRUE;
		}
		FREEBUF(treebuf);
	}

	return retval;
}


/*
 *  Do the simple list work for cmd_mod().
 */

static void
do_module_cmd(ulong flag, char *modref, ulong address, 
	char *objfile, char *tree)
{
	int i, j;
	struct load_module *lm, *lmp;
	int maxnamelen;
	int maxsizelen;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];

	if (NO_MODULES())
		return;

	switch (flag)
	{
	case LIST_MODULE:
	case LIST_MODULE_HDR:
	 	maxnamelen = maxsizelen = 0;
		
		for (i = 0; i < kt->mods_installed; i++) {
			lm = &st->load_modules[i];
			maxnamelen = strlen(lm->mod_name) > maxnamelen ? 
				strlen(lm->mod_name) : maxnamelen;
	
	                sprintf(buf1, "%ld", lm->mod_size);
			maxsizelen = strlen(buf1) > maxsizelen ? 
				strlen(buf1) : maxsizelen;
	        }
	
		if (flag == LIST_MODULE_HDR) {
			fprintf(fp, "%s  %s  %s  OBJECT FILE\n",
				mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, 
				"MODULE"),
				mkstring(buf2, maxnamelen, LJUST, "NAME"),
				mkstring(buf3, maxsizelen, RJUST, "SIZE"));
		}
	
		for (i = 0; i < kt->mods_installed; i++) {
			lm = &st->load_modules[i];
			if (!address || (lm->module_struct == address) ||
			    (lm->mod_base == address)) {
				fprintf(fp, "%s  ", mkstring(buf1, VADDR_PRLEN,
				    LONG_HEX|RJUST, MKSTR(lm->module_struct)));
				fprintf(fp, "%s  ", mkstring(buf2, maxnamelen, 
					LJUST, lm->mod_name));
				fprintf(fp, "%s  ", mkstring(buf3, maxsizelen,
					RJUST|LONG_DEC, MKSTR(lm->mod_size)));
				// fprintf(fp, "%6ld  ", lm->mod_size);
		
				if (strlen(lm->mod_namelist))
					fprintf(fp, "%s %s", 
						lm->mod_namelist,
						lm->mod_flags & MOD_REMOTE ?
						" (temporary)" : "");  
				else {
					fprintf(fp, "(not loaded)");
					if (lm->mod_flags & MOD_KALLSYMS)
						fprintf(fp, 
					   "  [CONFIG_KALLSYMS]");
				}
		
				fprintf(fp, "\n");
			}
		}
		break;

	case REMOTE_MODULE_SAVE_MSG:
		if (!REMOTE())
			return;

                for (i = j = 0, lmp = NULL; i < kt->mods_installed; i++) {
                        lm = &st->load_modules[i];
			if (lm->mod_flags & MOD_REMOTE) {
				j++;
				lmp = lm;
			}
		}

		switch (j)
		{
		case 0:
			return;

		case 1:
			error(NOTE, 
 "\nTo save the %s module object locally,\n      enter: \"save %s\"\n",
				lmp->mod_name, lmp->mod_name);
			break;

		default:
			error(NOTE, 
"\nTo save all temporary remote module objects locally,\n      enter: \"save modules\"\n");
			fprintf(fp, 
 "      To save a single remote module object locally,\n      enter: \"save NAME\",\n"
 "      where \"NAME\" is one of the module names shown in the list above.\n");
			break;
		}
		break;
	
	case LOAD_SPECIFIED_MODULE_SYMBOLS:
		if (!load_module_symbols(modref, objfile, address)) 
			error(FATAL, "cannot load symbols from: %s\n", objfile);
		do_module_cmd(LIST_MODULE_HDR, 0, address, 0, NULL);
		do_module_cmd(REMOTE_MODULE_SAVE_MSG, 0, 0, 0, NULL);
		break;

	case LOAD_ALL_MODULE_SYMBOLS:
		for (i = j = 0; i < kt->mods_installed; i++) {
			lm = &st->load_modules[i];

			if (STREQ(lm->mod_name, "(unknown module)")) {
				error(INFO,
                          "cannot find object file for unknown module at %lx\n",
					lm->mod_base);
				continue;
			}

			modref = lm->mod_name;
			address = lm->mod_base;

			if ((objfile = find_module_objfile(modref,NULL,tree))) {
				if (!is_elf_file(objfile)) {
                        		error(INFO, 
			                  "%s: not an ELF format object file\n",
						objfile);
				} else if (!load_module_symbols(modref, 
					objfile, address))
					error(INFO, 
				           "cannot load symbols from: %s\n",
						objfile);
				do_module_cmd(j++ ? 
					LIST_MODULE : LIST_MODULE_HDR,
					0, address, 0, tree);
				FREEBUF(objfile);
			} else if ((lm->mod_flags & MOD_LOAD_SYMS) ||
			    strlen(lm->mod_namelist)) { 
				if (CRASHDEBUG(1))
                        		fprintf(fp, 
				      "%s: module symbols are already loaded\n",
                                		modref);
				do_module_cmd(j++ ? 
					LIST_MODULE : LIST_MODULE_HDR,
					0, address, 0, tree);
			} else
				error(INFO,
                              "cannot find or load object file for %s module\n",
					modref);
		}
		do_module_cmd(REMOTE_MODULE_SAVE_MSG, 0, 0, 0, tree);
		break;

	case DELETE_ALL_MODULE_SYMBOLS:
		delete_load_module(ALL_MODULES);
		break;

	case DELETE_MODULE_SYMBOLS:
		delete_load_module(address);
		break;

	case REINIT_MODULES:
		reinit_modules();
        	do_module_cmd(LIST_MODULE_HDR, NULL, 0, NULL, NULL);
		break;
	}
}

/*
 *  Reinitialize the current set of modules:
 *
 *   1. first clear out all references to the current set.
 *   2. call module_init() again.
 *   3. display the new set.
 */
static void
reinit_modules(void)
{
        delete_load_module(ALL_MODULES);
        st->mods_installed = 0;
        st->flags &= ~MODULE_SYMS;
        free(st->ext_module_symtable);
        free(st->load_modules);
        st->ext_module_symtable = NULL;
        st->load_modules = NULL;
        kt->mods_installed = 0;
	clear_text_value_cache();

        module_init();
}


static char *
module_objfile_search(char *modref, char *filename, char *tree)
{
	char buf[BUFSIZE];
	char file[BUFSIZE];
	char dir[BUFSIZE];
	struct load_module *lm;
	char *retbuf;
	int initrd;
	struct syment *sp;
	char *p1, *p2;

	retbuf = NULL;
	initrd = FALSE;

	if (filename)
		strcpy(file, filename);
#ifdef MODULES_IN_CWD
       else {
		char *fileext[] = { "ko", "o"};
		int i;
		for (i = 0; i < 2; i++) {
			sprintf(file, "%s.%s", modref, fileext[i]);
			if (access(file, R_OK) == 0) {
				retbuf = GETBUF(strlen(file)+1);
				strcpy(retbuf, file);
				if (CRASHDEBUG(1))
					fprintf(fp, 
					    "find_module_objfile: [%s] file in cwd\n",
						retbuf);
				return retbuf;
			}
		}
	}
#else
	else 
		sprintf(file, "%s.o", modref);
#endif

	/*
	 *  Later versions of insmod create a symbol at the module's base
	 *  address.  Examples:
         *
         * __insmod_sunrpc_O/lib/modules/2.2.17/misc/sunrpc.o_M3A7EE300_V131601 
         * __insmod_lockd_O/lib/modules/2.2.17/fs/lockd.o_M3A7EE300_V131601  
         * __insmod_nfsd_O/lib/modules/2.2.17/fs/nfsd.o_M3A7EE300_V131601  
         * __insmod_nfs_O/lib/modules/2.2.17/fs/nfs.o_M3A7EE300_V131601
	 */
	if ((st->flags & INSMOD_BUILTIN) && !filename) {
		sprintf(buf, "__insmod_%s_O/", modref);
		if (symbol_query(buf, NULL, &sp) == 1) {
                        if (CRASHDEBUG(1))
                                fprintf(fp, "search: INSMOD_BUILTIN %s\n", sp->name);
			BZERO(buf, BUFSIZE);
			p1 = strstr(sp->name, "/");
			if ((p2 = strstr(sp->name, file)))
				p2 += strlen(file);
			if (p2) {
				strncpy(buf, p1, p2-p1); 	
                                if (!strstr(buf, "/lib/modules/")) {
					sprintf(dir, "/lib/%s.o", modref);
					if (STREQ(dir, buf))
						initrd = TRUE;
				} else if (REMOTE()) 
					strcpy(file, buf);
				else {
					retbuf = GETBUF(strlen(buf)+1);
					strcpy(retbuf, buf);
					if (CRASHDEBUG(1))
				    		fprintf(fp, 
					          "find_module_objfile: [%s]\n",
							retbuf);
					return retbuf;
				}
			}
		}
		if (is_module_name(modref, NULL, &lm) && 
		    (lm->mod_flags & MOD_INITRD)) {
			sprintf(dir, "/lib/%s.o", modref);
			initrd = TRUE;
		}
	}
        
	if (initrd) 
		error(NOTE, "%s: installed from initrd image\n", dir);

	if (REMOTE()) {
		retbuf = GETBUF(MAX_MOD_NAMELIST*2);

		if (!is_module_name(modref, NULL, &lm)) {
			error(INFO, "%s is not a module reference\n", modref);
			return NULL;
		}

        	if ((lm->mod_flags & MOD_LOAD_SYMS) &&
		    strlen(lm->mod_namelist)) {
			if (CRASHDEBUG(1))
				fprintf(fp, "redundant mod call: %s\n", 
					lm->mod_namelist);
			strcpy(retbuf, lm->mod_namelist);
			return retbuf;
		}

		if (find_remote_module_objfile(lm, file, retbuf))
			return retbuf;

		return NULL;
	}

	if (tree) {
		if (!(retbuf = search_directory_tree(tree, file, 1))) {
			switch (kt->flags & (KMOD_V1|KMOD_V2))
			{
			case KMOD_V2:
				sprintf(file, "%s.ko", modref);
				retbuf = search_directory_tree(tree, file, 1);
			}
		}
		return retbuf;
	}

	sprintf(dir, "%s/%s", DEFAULT_REDHAT_DEBUG_LOCATION, 
		kt->utsname.release);
	retbuf = search_directory_tree(dir, file, 0);

	if (!retbuf) {
		sprintf(dir, "/lib/modules/%s/updates", kt->utsname.release);
		if (!(retbuf = search_directory_tree(dir, file, 0))) {
			switch (kt->flags & (KMOD_V1|KMOD_V2))
			{
			case KMOD_V2:
				sprintf(file, "%s.ko", modref);
				retbuf = search_directory_tree(dir, file, 0);
			}
		}
	}

	if (!retbuf) {
		sprintf(dir, "/lib/modules/%s", kt->utsname.release);
		if (!(retbuf = search_directory_tree(dir, file, 0))) {
			switch (kt->flags & (KMOD_V1|KMOD_V2))
			{
			case KMOD_V2:
				sprintf(file, "%s.ko", modref);
				retbuf = search_directory_tree(dir, file, 0);
			}
		}
	}

	return retbuf;
}

/*
 *  First look for a module based upon its reference name.
 *  If that fails, try replacing any underscores in the
 *  reference name with a dash.  
 *  If that fails, because of intermingled dashes and underscores, 
 *  try a regex expression.
 *
 *  Example: module name "dm_mod" comes from "dm-mod.ko" objfile
 *           module name "dm_region_hash" comes from "dm-region_hash.ko" objfile
 */
static char *
find_module_objfile(char *modref, char *filename, char *tree)
{
	char * retbuf;
	char tmpref[BUFSIZE];
	int i, c;

	retbuf = module_objfile_search(modref, filename, tree);

	if (!retbuf) {
		strncpy(tmpref, modref, BUFSIZE);
		for (c = 0; c < BUFSIZE && tmpref[c]; c++)
			if (tmpref[c] == '_')
				tmpref[c] = '-';
		retbuf = module_objfile_search(tmpref, filename, tree);
	}

	if (!retbuf && (count_chars(modref, '_') > 1)) {
		for (i = c = 0; modref[i]; i++) {
			if (modref[i] == '_') {
				tmpref[c++] = '[';
				tmpref[c++] = '_';
				tmpref[c++] = '-';
				tmpref[c++] = ']';
			} else
				tmpref[c++] = modref[i];
		} 
		tmpref[c] = NULLCHAR;
		retbuf = module_objfile_search(tmpref, filename, tree);
	}

	return retbuf;
}

/*
 *  Unlink any temporary remote module object files.
 */
void
unlink_module(struct load_module *load_module)
{
	int i;
	struct load_module *lm;

	if (load_module) {
		if (load_module->mod_flags & MOD_REMOTE)
			unlink(load_module->mod_namelist);
		return;
	}

        for (i = 0; i < kt->mods_installed; i++) {
                lm = &st->load_modules[i];
		if (lm->mod_flags & MOD_REMOTE) 
			unlink(lm->mod_namelist);
        }
}


/*
 *  Dump the kernel log_buf in chronological order.
 */

void
cmd_log(void)
{
	int c;
	int msg_level;

	msg_level = FALSE;

        while ((c = getopt(argcnt, args, "m")) != EOF) {
                switch(c)
                {
                case 'm':
                        msg_level = TRUE;
                        break;
                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

	dump_log(msg_level);
}


void 
dump_log(int msg_level)
{
	int i;
	ulong log_buf, log_end;
	char *buf;
	char last;
	ulong index;
	struct syment *nsp;
	int log_wrap, loglevel, log_buf_len;

	if (symbol_exists("log_buf_len")) {
		get_symbol_data("log_buf_len", sizeof(int), &log_buf_len);
		get_symbol_data("log_buf", sizeof(ulong), &log_buf);
	} else {
		if ((ARRAY_LENGTH(log_buf) == 0) &&
	            (get_array_length("log_buf", NULL, 0) == 0)) {
	                if ((nsp = next_symbol("log_buf", NULL)) == NULL)
	                        error(FATAL, 
				    "cannot determine length of log_buf\n");
	                builtin_array_length("log_buf", 
				(int)(nsp->value - symbol_value("log_buf")), 
				NULL);
		}
	
		log_buf_len = ARRAY_LENGTH(log_buf);
		log_buf = symbol_value("log_buf");
	}

	buf = GETBUF(log_buf_len);
	log_wrap = FALSE;
	last = 0;
	get_symbol_data("log_end", sizeof(ulong), &log_end);
        readmem(log_buf, KVADDR, buf,
        	log_buf_len, "log_buf contents", FAULT_ON_ERROR);

	if (log_end < log_buf_len)
		index = 0;
	else
		index = log_end & (log_buf_len - 1);

	if ((log_end < log_buf_len) && (index == 0) && (buf[index] == '<'))
		loglevel = TRUE;
	else
		loglevel = FALSE;

	if (index != 0)
		log_wrap = TRUE;

wrap_around:

	for (i = index; i < log_buf_len; i++) {
                if (loglevel && !msg_level) {
                        switch (buf[i])
                        {
                        case '>':
                                loglevel = FALSE;
                                /* FALLTHROUGH */
                        case '<':
                        case '0':
                        case '1':
                        case '2':
                        case '3':
                        case '4':
                        case '5':
                        case '6':
                        case '7':
                                continue;

                        default:
                                loglevel = FALSE;
                                break;
                        }
                }

		if (buf[i]) {
                	fputc(ascii(buf[i]) ? buf[i] : '.', fp);
                	loglevel = buf[i] == '\n' ? TRUE : FALSE;
                	last = buf[i];
		}
	}

	if (log_wrap) {
		log_buf_len = index;
		index = 0;
		log_wrap = FALSE;
		goto wrap_around;
	}

	if (last != '\n')
		fprintf(fp, "\n");

	FREEBUF(buf);
}


/*
 *  Display general system info.
 */
void
cmd_sys(void)
{
        int c, cnt;
	ulong sflag;

	sflag = FALSE;

        while ((c = getopt(argcnt, args, "cp:")) != EOF) {
                switch(c)
                {
		case 'p':
			if (STREQ(optarg, "anic"))
				panic_this_kernel();
			else
				argerrs++;
			break;

		case 'c':
			sflag = TRUE;
			break;

                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

        if (!args[optind]) {
		if (sflag)
			dump_sys_call_table(NULL, 0);
		else
			display_sys_stats();
		return;
	}

	cnt = 0;
        do {
                if (sflag)
                        dump_sys_call_table(args[optind], cnt++);
		else if (STREQ(args[optind], "config"))
			read_in_kernel_config(IKCFG_READ);
                else
                        cmd_usage(args[optind], COMPLETE_HELP);
                optind++;
        } while (args[optind]);
}

/*
 *  Display system stats at init-time or for the sys command.
 */
void
display_sys_stats(void)
{
        struct new_utsname *uts;
        char buf[BUFSIZE];
	ulong mhz;

	uts = &kt->utsname;

//	if (!(pc->flags & RUNTIME) && !DUMPFILE() && !GDB_PATCHED())
//		fprintf(fp, "\n");

        /*
         *  It's now safe to unlink the remote namelist.
         */
        if (pc->flags & UNLINK_NAMELIST) {
                unlink(pc->namelist);
                pc->flags &= ~UNLINK_NAMELIST;
                pc->flags |= NAMELIST_UNLINKED;
        }

	if (REMOTE()) {
		switch (pc->flags & 
			(NAMELIST_LOCAL|NAMELIST_UNLINKED|NAMELIST_SAVED))
		{
		case NAMELIST_UNLINKED:
			fprintf(fp, "      KERNEL: %s  (temporary)\n", 
				pc->namelist);
			break;

		case (NAMELIST_UNLINKED|NAMELIST_SAVED):
			fprintf(fp, "      KERNEL: %s\n", pc->namelist);
			break;

		case NAMELIST_LOCAL:
			fprintf(fp, "      KERNEL: %s\n", pc->namelist);
			break;
		}
	} else {
        	if (pc->system_map) {
                	fprintf(fp, "  SYSTEM MAP: %s\n", pc->system_map);
			fprintf(fp, "DEBUG KERNEL: %s %s\n", 
					pc->namelist,
					debug_kernel_version(pc->namelist));
		} else
			fprintf(fp, "      KERNEL: %s\n", pc->namelist);
	}

	if (pc->debuginfo_file)
		fprintf(fp, "   DEBUGINFO: %s\n", pc->debuginfo_file);
	else if (pc->namelist_debug)
		fprintf(fp, "DEBUG KERNEL: %s %s\n", pc->namelist_debug,
			debug_kernel_version(pc->namelist_debug));

	if (dumpfile_is_split())
		fprintf(fp, "   DUMPFILES: ");
	else
		fprintf(fp, "    DUMPFILE: ");
        if (ACTIVE()) {
		if (REMOTE_ACTIVE()) 
			fprintf(fp, "%s@%s  (remote live system)\n",
			    	pc->server_memsrc, pc->server);
		else
                	fprintf(fp, "%s\n", pc->live_memsrc);
	} else {
		if (REMOTE_DUMPFILE())
                	fprintf(fp, "%s@%s  (remote dumpfile)", 
				pc->server_memsrc, pc->server);
		else {
			if (dumpfile_is_split())
				show_split_dumpfiles();
			else
                		fprintf(fp, "%s", pc->dumpfile);
		}

		if (NETDUMP_DUMPFILE() && is_partial_netdump())
			fprintf(fp, "  [PARTIAL DUMP]");

		if (DISKDUMP_DUMPFILE() && !dumpfile_is_split() &&
		     is_partial_diskdump())
			fprintf(fp, "  [PARTIAL DUMP]");

		fprintf(fp, "\n");
	}
	

        fprintf(fp, "        CPUS: %d\n", kt->cpus);
	if (ACTIVE())
        	get_symbol_data("xtime", sizeof(struct timespec), &kt->date);
        fprintf(fp, "        DATE: %s\n", 
		strip_linefeeds(ctime(&kt->date.tv_sec))); 
        fprintf(fp, "      UPTIME: %s\n", get_uptime(buf, NULL)); 
        fprintf(fp, "LOAD AVERAGE: %s\n", get_loadavg(buf)); 
	fprintf(fp, "       TASKS: %ld\n", RUNNING_TASKS());
	fprintf(fp, "    NODENAME: %s\n", uts->nodename); 
        fprintf(fp, "     RELEASE: %s\n", uts->release); 
	fprintf(fp, "     VERSION: %s\n", uts->version); 
	fprintf(fp, "     MACHINE: %s  ", uts->machine);
	if ((mhz = machdep->processor_speed()))
		fprintf(fp, "(%ld Mhz)\n", mhz);
	else
		fprintf(fp, "(unknown Mhz)\n");
	fprintf(fp, "      MEMORY: %s\n", get_memory_size(buf));
#ifdef WHO_CARES
	fprintf(fp, "  DOMAINNAME: %s\n", uts->domainname);
#endif
	if (XENDUMP_DUMPFILE() && (kt->xen_flags & XEN_SUSPEND))
		return;

	if (DUMPFILE()) {
		fprintf(fp, "       PANIC: ");
		if (machdep->flags & HWRESET)
			fprintf(fp, "(HARDWARE RESET)\n");
		else if (machdep->flags & INIT)
			fprintf(fp, "(INIT)\n");
		else if (machdep->flags & MCA)
			fprintf(fp, "(MCA)\n");
		else {
        		strip_linefeeds(get_panicmsg(buf));
			fprintf(fp, "\"%s\"%s\n", buf, 
				strstr(buf, "Oops: ") ? 
				" (check log for details)" : "");
		}
	}
}

/*
 *  Get the kernel version from the debug kernel and store it here.
 */
static char *debug_kernel_version_string = NULL;

static char *
debug_kernel_version(char *namelist)
{
	FILE *pipe;
	int found, argc;
	char buf[BUFSIZE], *ptr;
	char command[BUFSIZE];
	char *arglist[MAXARGS];

	if (debug_kernel_version_string)
		return debug_kernel_version_string;

        sprintf(command, "/usr/bin/strings %s", namelist);

        if ((pipe = popen(command, "r")) == NULL) { 
		debug_kernel_version_string = " ";
                return debug_kernel_version_string;
	}

	argc = 0;
	ptr = NULL;
        found = FALSE;
        while (fgets(buf, BUFSIZE-1, pipe)) {
                if (!strstr(buf, "Linux version 2."))
                        continue;

		argc = parse_line(buf, arglist); 
		break;
        }
        pclose(pipe);

	if ((argc >= 3) && (debug_kernel_version_string = (char *) 
	    malloc(strlen(arglist[2])+3)))
		sprintf(debug_kernel_version_string, "(%s)", arglist[2]);
	else
		debug_kernel_version_string = " ";

	return debug_kernel_version_string;
}

/*
 *  Calculate and return the uptime.
 */
char *
get_uptime(char *buf, ulonglong *j64p)
{
	ulong jiffies, tmp1, tmp2;
	ulonglong jiffies_64, wrapped;

	if (symbol_exists("jiffies_64")) {
		get_symbol_data("jiffies_64", sizeof(ulonglong), &jiffies_64);
		if (THIS_KERNEL_VERSION >= LINUX(2,6,0)) {
			wrapped = (jiffies_64 & 0xffffffff00000000ULL);
			if (wrapped) {
				wrapped -= 0x100000000ULL;
				jiffies_64 &= 0x00000000ffffffffULL;
				jiffies_64 |= wrapped;
                		jiffies_64 += (ulonglong)(300*machdep->hz);
			} else {
				tmp1 = (ulong)(uint)(-300*machdep->hz);
				tmp2 = (ulong)jiffies_64;
				jiffies_64 = (ulonglong)(tmp2 - tmp1);
			}
		}
		if (buf)
			convert_time(jiffies_64, buf);
		if (j64p)
			*j64p = jiffies_64;
	} else {
		get_symbol_data("jiffies", sizeof(long), &jiffies);
		if (buf)
			convert_time((ulonglong)jiffies, buf);
		if (j64p)
			*j64p = (ulonglong)jiffies;
	}

	return buf;
}

#define FSHIFT          11              /* nr of bits of precision */
#define FIXED_1 (1<<FSHIFT)
#define LOAD_INT(x) ((x) >> FSHIFT)
#define LOAD_FRAC(x) LOAD_INT(((x) & (FIXED_1-1)) * 100)

static char *
get_loadavg(char *buf)
{
        int a, b, c;
	long avenrun[3];

        readmem(symbol_value("avenrun"), KVADDR, &avenrun[0],
                sizeof(long)*3, "avenrun array", FAULT_ON_ERROR);

        a = avenrun[0] + (FIXED_1/200);
        b = avenrun[1] + (FIXED_1/200);
        c = avenrun[2] + (FIXED_1/200);
        sprintf(buf, "%d.%02d, %d.%02d, %d.%02d",
                LOAD_INT(a), LOAD_FRAC(a),
                LOAD_INT(b), LOAD_FRAC(b),
                LOAD_INT(c), LOAD_FRAC(c));

	return buf;
}



/*
 *  Determine whether a string or value equates to a system call name or value.
 */
int
is_system_call(char *name, ulong value)
{
	int i;
        ulong *sys_call_table, *sct;
	char *sp;
        long size;
	int NR_syscalls;

	NR_syscalls = get_NR_syscalls();
        size = sizeof(void *) * NR_syscalls;
        sys_call_table = (ulong *)GETBUF(size);

        readmem(symbol_value("sys_call_table"), KVADDR, sys_call_table,
                size, "sys_call_table", FAULT_ON_ERROR);

	for (i = 0, sct = sys_call_table; i < NR_syscalls; i++, sct++) {
		if (name && (sp = value_symbol(*sct))) {
			if (STREQ(name, sp))
				return TRUE;
		} else if (value) {
			if (value == *sct)
				return TRUE;
		}
	}

        return FALSE;
}

char *sys_call_hdr = "NUM  SYSTEM CALL                FILE AND LINE NUMBER\n";

static void
dump_sys_call_table(char *spec, int cnt)
{
        int i;
        char buf1[BUFSIZE], *scp;
        char buf2[BUFSIZE], *p;
	char buf3[BUFSIZE];
	char *arglist[MAXARGS];
	int argc, NR_syscalls;
	int number, printit, hdr_printed;
	struct syment *sp, *spn;
        long size;
#ifdef S390X
	unsigned int *sct, *sys_call_table, sys_ni_syscall, addr;
#else
	ulong *sys_call_table, *sct, sys_ni_syscall, addr;
#endif
	if (GDB_PATCHED())
		error(INFO, "line numbers are not available\n"); 

	NR_syscalls = get_NR_syscalls();
	if (CRASHDEBUG(1))
		fprintf(fp, "NR_syscalls: %d\n", NR_syscalls);
        size = sizeof(addr) * NR_syscalls;
#ifdef S390X
        sys_call_table = (unsigned int *)GETBUF(size);
#else
        sys_call_table = (ulong *)GETBUF(size);
#endif

        readmem(symbol_value("sys_call_table"), KVADDR, sys_call_table,
                size, "sys_call_table", FAULT_ON_ERROR);

	sys_ni_syscall = symbol_value("sys_ni_syscall");

	if (spec)
		open_tmpfile();

	fprintf(fp, sys_call_hdr);

        for (i = 0, sct = sys_call_table; i < NR_syscalls; i++, sct++) {
                if (!(scp = value_symbol(*sct))) {
			if (CRASHDEBUG(1)) {
				fprintf(fp, (output_radix == 16) ? 
					"%3x  " : "%3d  ", i);
				fprintf(fp, 
			    	    "invalid sys_call_table entry: %lx (%s)\n", 
					(unsigned long)*sct,
					value_to_symstr(*sct, buf1, 0));
			}
			continue;
		}
		
		fprintf(fp, (output_radix == 16) ? "%3x  " : "%3d  ", i);
  		if (sys_ni_syscall && *sct == sys_ni_syscall)
			fprintf(fp, "%-26s ", "sys_ni_syscall");
		else
			fprintf(fp, "%-26s ", scp);

		/*
		 *  For system call symbols whose first instruction is
		 *  an inline from a header file, the file/line-number is 
		 *  confusing.  For this command only, look for the first
	 	 *  instruction address in the system call that shows the
		 *  the actual source file containing the system call.
	  	 */
                sp = value_search(*sct, NULL);
                spn = next_symbol(NULL, sp);
		get_build_directory(buf2);

		for (addr = *sct; sp && spn && (addr < spn->value); addr++) {
			BZERO(buf1, BUFSIZE);
			get_line_number(addr, buf1, FALSE);

			if (strstr(buf1, ".h: ") && strstr(buf1, "include/")) 
				continue;

			if (strstr(buf1, buf2)) {
                                p = buf1 + strlen(buf2);
                                fprintf(fp, "%s%s",
                                        strlen(buf1) ? ".." : "", p);
                                break;
                        }
		}

		fprintf(fp, "\n");
       	}

        if (spec) {
                rewind(pc->tmpfile);

		hdr_printed = cnt;
		if ((number = IS_A_NUMBER(spec))) 
                	sprintf(buf3, (output_radix == 16) ?  "%lx" : "%ld",
                        	stol(spec, FAULT_ON_ERROR, NULL));

                while (fgets(buf1, BUFSIZE, pc->tmpfile)) {
			printit = FALSE;
			strcpy(buf2, buf1);
			argc = parse_line(buf2, arglist);
			if (argc < 2)
				continue;

			if (number && STREQ(arglist[0], buf3))
				printit = TRUE;
			else if (!number && strstr(arglist[1], spec))
				printit = TRUE;

			if (printit) {
				fprintf(pc->saved_fp, "%s%s", hdr_printed++ ? 
					"" : sys_call_hdr, buf1);
				if (number)
					break;
			}
                }

                close_tmpfile();
        }
}

/*
 *  Get the number of system calls in the sys_call_table based upon the
 *  next symbol after it. 
 */
static int
get_NR_syscalls(void)
{
       	ulong sys_call_table;
	struct syment *sp;
	int cnt;

	sys_call_table = symbol_value("sys_call_table");
	if (!(sp = next_symbol("sys_call_table", NULL)))
		return 256;

        while (sp->value == sys_call_table) {
                if (!(sp = next_symbol(sp->name, NULL)))
                        return 256;
        }

	if (machine_type("S390X"))
		cnt = (sp->value - sys_call_table)/sizeof(int);
	else
		cnt = (sp->value - sys_call_table)/sizeof(void *);

	return cnt;
}

/*
 *  "help -k" output
 */
void
dump_kernel_table(int verbose)
{
	int i, j, more, nr_cpus;
        struct new_utsname *uts;
        int others;

        others = 0;
	more = FALSE;
        uts = &kt->utsname;

        fprintf(fp, "         flags: %lx\n  (", kt->flags);
	if (kt->flags & NO_MODULE_ACCESS)
		fprintf(fp, "%sNO_MODULE_ACCESS", others++ ? "|" : "");
	if (kt->flags & TVEC_BASES_V1)
		fprintf(fp, "%sTVEC_BASES_V1", others++ ? "|" : "");
	if (kt->flags & TVEC_BASES_V2)
		fprintf(fp, "%sTVEC_BASES_V2", others++ ? "|" : "");
	if (kt->flags & GCC_2_96)
		fprintf(fp, "%sGCC_2_96", others++ ? "|" : "");
	if (kt->flags & GCC_3_2)
		fprintf(fp, "%sGCC_3_2", others++ ? "|" : "");
	if (kt->flags & GCC_3_2_3)
		fprintf(fp, "%sGCC_3_2_3", others++ ? "|" : "");
	if (kt->flags & GCC_3_3_2)
		fprintf(fp, "%sGCC_3_3_2", others++ ? "|" : "");
	if (kt->flags & GCC_3_3_3)
		fprintf(fp, "%sGCC_3_3_3", others++ ? "|" : "");
	if (kt->flags & RA_SEEK)
		fprintf(fp, "%sRA_SEEK", others++ ? "|" : "");
	if (kt->flags & NO_RA_SEEK)
		fprintf(fp, "%sNO_RA_SEEK", others++ ? "|" : "");
	if (kt->flags & KALLSYMS_V1)
		fprintf(fp, "%sKALLSYMS_V1", others++ ? "|" : "");
	if (kt->flags & NO_KALLSYMS)
		fprintf(fp, "%sNO_KALLSYMS", others++ ? "|" : "");
	if (kt->flags & PER_CPU_OFF)
		fprintf(fp, "%sPER_CPU_OFF", others++ ? "|" : "");
	if (kt->flags & SMP)
		fprintf(fp, "%sSMP", others++ ? "|" : "");
	if (kt->flags & KMOD_V1)
		fprintf(fp, "%sKMOD_V1", others++ ? "|" : "");
	if (kt->flags & KMOD_V2)
		fprintf(fp, "%sKMOD_V2", others++ ? "|" : "");
	if (kt->flags & KALLSYMS_V2)
		fprintf(fp, "%sKALLSYMS_V2", others++ ? "|" : "");
	if (kt->flags & USE_OLD_BT)
		fprintf(fp, "%sUSE_OLD_BT", others++ ? "|" : "");
	if (kt->flags & ARCH_XEN)
		fprintf(fp, "%sARCH_XEN", others++ ? "|" : "");
	if (kt->flags & ARCH_OPENVZ)
		fprintf(fp, "%sARCH_OPENVZ", others++ ? "|" : "");
	if (kt->flags & ARCH_PVOPS)
		fprintf(fp, "%sARCH_PVOPS", others++ ? "|" : "");
	if (kt->flags & NO_IKCONFIG)
		fprintf(fp, "%sNO_IKCONFIG", others++ ? "|" : "");
	if (kt->flags & DWARF_UNWIND)
		fprintf(fp, "%sDWARF_UNWIND", others++ ? "|" : "");
	if (kt->flags & NO_DWARF_UNWIND)
		fprintf(fp, "%sNO_DWARF_UNWIND", others++ ? "|" : "");
	if (kt->flags & DWARF_UNWIND_MEMORY)
		fprintf(fp, "%sDWARF_UNWIND_MEMORY", others++ ? "|" : "");
	if (kt->flags & DWARF_UNWIND_EH_FRAME)
		fprintf(fp, "%sDWARF_UNWIND_EH_FRAME", others++ ? "|" : "");
	if (kt->flags & DWARF_UNWIND_MODULES)
		fprintf(fp, "%sDWARF_UNWIND_MODULES", others++ ? "|" : "");
	if (kt->flags & BUGVERBOSE_OFF)
		fprintf(fp, "%sBUGVERBOSE_OFF", others++ ? "|" : "");
	if (kt->flags & RELOC_SET)
		fprintf(fp, "%sRELOC_SET", others++ ? "|" : "");
	if (kt->flags & RELOC_FORCE)
		fprintf(fp, "%sRELOC_FORCE", others++ ? "|" : "");
	if (kt->flags & IN_KERNEL_INIT)
		fprintf(fp, "%sIN_KERNEL_INIT", others++ ? "|" : "");
	fprintf(fp, ")\n");
        fprintf(fp, "         stext: %lx\n", kt->stext);
        fprintf(fp, "         etext: %lx\n", kt->etext);
        fprintf(fp, "    stext_init: %lx\n", kt->stext_init);
        fprintf(fp, "    etext_init: %lx\n", kt->etext_init);
        fprintf(fp, "    init_begin: %lx\n", kt->init_begin);
        fprintf(fp, "      init_end: %lx\n", kt->init_end);
        fprintf(fp, "           end: %lx\n", kt->end);
        fprintf(fp, "          cpus: %d\n", kt->cpus);
        fprintf(fp, " cpus_override: %s\n", kt->cpus_override);
        fprintf(fp, "       NR_CPUS: %d (compiled-in to this version of %s)\n",
		NR_CPUS, pc->program_name); 
	fprintf(fp, "kernel_NR_CPUS: %d\n", kt->kernel_NR_CPUS);
	if (kt->display_bh == display_bh_1)
        	fprintf(fp, "    display_bh: display_bh_1()\n");
	else if (kt->display_bh == display_bh_2)
        	fprintf(fp, "    display_bh: display_bh_2()\n");
	else if (kt->display_bh == display_bh_3)
        	fprintf(fp, "    display_bh: display_bh_3()\n");
	else
        	fprintf(fp, "    display_bh: %lx\n", (ulong)kt->display_bh);
        fprintf(fp, "   module_list: %lx\n", kt->module_list);
        fprintf(fp, " kernel_module: %lx\n", kt->kernel_module);
	fprintf(fp, "mods_installed: %d\n", kt->mods_installed);
	fprintf(fp, "   module_tree: %s\n", kt->module_tree ? 
		kt->module_tree : "(not used)");
	if (!(pc->flags & KERNEL_DEBUG_QUERY) && ACTIVE()) 
                get_symbol_data("xtime", sizeof(struct timespec), &kt->date);
        fprintf(fp, "          date: %s\n",
                strip_linefeeds(ctime(&kt->date.tv_sec)));
        fprintf(fp, "  proc_version: %s\n", strip_linefeeds(kt->proc_version));
        fprintf(fp, "   new_utsname: \n");
        fprintf(fp, "      .sysname: %s\n", uts->sysname);
        fprintf(fp, "     .nodename: %s\n", uts->nodename);
        fprintf(fp, "      .release: %s\n", uts->release);
        fprintf(fp, "      .version: %s\n", uts->version);
        fprintf(fp, "      .machine: %s\n", uts->machine);
        fprintf(fp, "   .domainname: %s\n", uts->domainname);
	fprintf(fp, "kernel_version: %d.%d.%d\n", kt->kernel_version[0], 
		kt->kernel_version[1], kt->kernel_version[2]);
	fprintf(fp, "   gcc_version: %d.%d.%d\n", kt->gcc_version[0], 
		kt->gcc_version[1], kt->gcc_version[2]);
	fprintf(fp, "     BUG_bytes: %d\n", kt->BUG_bytes);
	fprintf(fp, "      relocate: %lx\n", kt->relocate);
	fprintf(fp, " runq_siblings: %d\n", kt->runq_siblings);
	fprintf(fp, "  __rq_idx[NR_CPUS]: ");
	nr_cpus = kt->kernel_NR_CPUS ? kt->kernel_NR_CPUS : NR_CPUS;
	for (i = 0; i < nr_cpus; i++) {
		if (!(kt->__rq_idx)) {
			fprintf(fp, "(unused)");
			break;
		}
		fprintf(fp, "%ld ", kt->__rq_idx[i]);
		for (j = i, more = FALSE; j < nr_cpus; j++) {
			if (kt->__rq_idx[j])
				more = TRUE;
		}
		if (!more) {
			fprintf(fp, "...");
			break;
		}
	}
	fprintf(fp, "\n __cpu_idx[NR_CPUS]: ");
	for (i = 0; i < nr_cpus; i++) {
		if (!(kt->__cpu_idx)) {
			fprintf(fp, "(unused)");
			break;
		}
		fprintf(fp, "%ld ", kt->__cpu_idx[i]);
		for (j = i, more = FALSE; j < nr_cpus; j++) {
			if (kt->__cpu_idx[j])
				more = TRUE;
		}
		if (!more) {
			fprintf(fp, "...");
			break;
		}
	}
	fprintf(fp, "\n __per_cpu_offset[NR_CPUS]:");
	for (i = 0; i < nr_cpus; i++) {
		fprintf(fp, "%s%.*lx ", (i % 4) == 0 ? "\n    " : "",
			LONG_PRLEN, kt->__per_cpu_offset[i]);
		if ((i % 4) == 0) {
			for (j = i, more = FALSE; j < nr_cpus; j++) {
				if (kt->__per_cpu_offset[j])
					more = TRUE;
			}
		}
		if (!more) {
			fprintf(fp, "...");
			break;
		}

	}
	fprintf(fp, "\n cpu_flags[NR_CPUS]: ");
	for (i = 0; i < nr_cpus; i++) {
		if (!(kt->cpu_flags)) {
			fprintf(fp, "(unused)\n");
			goto no_cpu_flags;
		}
		fprintf(fp, "%lx ", kt->cpu_flags[i]);
		for (j = i, more = FALSE; j < nr_cpus; j++) {
			if (kt->cpu_flags[j])
				more = TRUE;
		}
		if (!more) {
			fprintf(fp, "...");
			break;
		}
	}
	fprintf(fp, "\n");
	fprintf(fp, "       cpu_possible_map: ");
	if (cpu_map_addr("possible")) {
		for (i = 0; i < nr_cpus; i++) {
			if (kt->cpu_flags[i] & POSSIBLE)
				fprintf(fp, "%d ", i);
		}
		fprintf(fp, "\n");
	} else
		fprintf(fp, "(does not exist)\n");
	fprintf(fp, "        cpu_present_map: ");
	if (cpu_map_addr("present")) {
		for (i = 0; i < nr_cpus; i++) {
			if (kt->cpu_flags[i] & PRESENT)
				fprintf(fp, "%d ", i);
		}
		fprintf(fp, "\n");
	} else
		fprintf(fp, "(does not exist)\n");
	fprintf(fp, "         cpu_online_map: ");
	if (cpu_map_addr("online")) {
		for (i = 0; i < nr_cpus; i++) {
			if (kt->cpu_flags[i] & ONLINE)
				fprintf(fp, "%d ", i);
		}
		fprintf(fp, "\n");
	} else
		fprintf(fp, "(does not exist)\n");
no_cpu_flags:
	others = 0;
	fprintf(fp, "     xen_flags: %lx (", kt->xen_flags);
        if (kt->xen_flags & WRITABLE_PAGE_TABLES)
                fprintf(fp, "%sWRITABLE_PAGE_TABLES", others++ ? "|" : "");
        if (kt->xen_flags & SHADOW_PAGE_TABLES)
                fprintf(fp, "%sSHADOW_PAGE_TABLES", others++ ? "|" : "");
        if (kt->xen_flags & CANONICAL_PAGE_TABLES)
                fprintf(fp, "%sCANONICAL_PAGE_TABLES", others++ ? "|" : "");
        if (kt->xen_flags & XEN_SUSPEND)
                fprintf(fp, "%sXEN_SUSPEND", others++ ? "|" : "");
	fprintf(fp, ")\n");
	fprintf(fp, "               m2p_page: %lx\n", (ulong)kt->m2p_page);
        fprintf(fp, "phys_to_machine_mapping: %lx\n", kt->phys_to_machine_mapping);
        fprintf(fp, "         p2m_table_size: %ld\n", kt->p2m_table_size);
	fprintf(fp, " p2m_mapping_cache[%d]: %s\n", P2M_MAPPING_CACHE,
		 verbose ? "" : "(use \"help -K\" to view cache contents)");
	for (i = 0; verbose && (i < P2M_MAPPING_CACHE); i++) {
		if (!kt->p2m_mapping_cache[i].mapping)
			continue;
		fprintf(fp, "       [%d] mapping: %lx start: %lx end: %lx (%ld mfns)\n",
			i, kt->p2m_mapping_cache[i].mapping,
			kt->p2m_mapping_cache[i].start,
			kt->p2m_mapping_cache[i].end,
			kt->p2m_mapping_cache[i].end -  kt->p2m_mapping_cache[i].start + 1);
        }
	fprintf(fp, "      last_mapping_read: %lx\n", kt->last_mapping_read);
	fprintf(fp, "        p2m_cache_index: %ld\n", kt->p2m_cache_index);
	fprintf(fp, "     p2m_pages_searched: %ld\n", kt->p2m_pages_searched);
	fprintf(fp, "     p2m_mfn_cache_hits: %ld ", kt->p2m_mfn_cache_hits);
	if (kt->p2m_pages_searched)
		fprintf(fp, "(%ld%%)\n", kt->p2m_mfn_cache_hits * 100 / kt->p2m_pages_searched);
	else
		fprintf(fp, "\n");
	fprintf(fp, "    p2m_page_cache_hits: %ld ", kt->p2m_page_cache_hits);
	if (kt->p2m_pages_searched)
		fprintf(fp, "(%ld%%)\n", kt->p2m_page_cache_hits * 100 / kt->p2m_pages_searched);
	else
		fprintf(fp, "\n");
}

/*
 *  Set the context to the active task on a given cpu -- dumpfiles only.
 */
void
set_cpu(int cpu)
{
	ulong task;

	if (cpu >= kt->cpus)
		error(FATAL, "invalid cpu number: system has only %d cpu%s\n", 
			kt->cpus, kt->cpus > 1 ? "s" : "");
	if ((task = get_active_task(cpu))) 
		set_context(task, NO_PID);
	else
		error(FATAL, "cannot determine active task on cpu %ld\n", cpu);

	show_context(CURRENT_CONTEXT());
}


/*
 *  Collect the irq_desc[] entry along with its associated handler and
 *  action structures.
 */

void
cmd_irq(void)
{
        int i, c;
	int nr_irqs;

	if (machine_type("S390") || machine_type("S390X"))
		command_not_supported();

        while ((c = getopt(argcnt, args, "dbu")) != EOF) {
                switch(c)
                {
		case 'd':
			display_idt_table();
			return;

		case 'b':
			if (!kt->display_bh) {
			        if (symbol_exists("bh_base") &&
			            symbol_exists("bh_mask") &&
			            symbol_exists("bh_active"))
			                kt->display_bh = display_bh_1;
			        else if (symbol_exists("bh_base") &&
			            symbol_exists("softirq_state") &&
			            symbol_exists("softirq_vec"))
			                kt->display_bh = display_bh_2;
			        else if (symbol_exists("bh_base") &&
			            symbol_exists("irq_stat") &&
			            symbol_exists("softirq_vec") &&
				    VALID_MEMBER(irq_cpustat_t___softirq_active)
                        	    && VALID_MEMBER(irq_cpustat_t___softirq_mask))
			                kt->display_bh = display_bh_3;
				else
					error(FATAL, 
					    "bottom-half option not supported\n");
			}
			kt->display_bh();
			return;

		case 'u':
			pc->curcmd_flags |= IRQ_IN_USE;
			if (kernel_symbol_exists("no_irq_chip"))
				pc->curcmd_private = (ulonglong)symbol_value("no_irq_chip");
			else if (kernel_symbol_exists("no_irq_type"))
				pc->curcmd_private = (ulonglong)symbol_value("no_irq_type");
			else
				error(WARNING, 
       "irq: -u option ignored: \"no_irq_chip\" or \"no_irq_type\" symbols do not exist\n");
			break;

                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

	if ((nr_irqs = machdep->nr_irqs) == 0)
		error(FATAL, "cannot determine number of IRQs\n");

	if (!args[optind]) {
		for (i = 0; i < nr_irqs; i++)
			machdep->dump_irq(i);
		return;
	}

	pc->curcmd_flags &= ~IRQ_IN_USE;

	while (args[optind]) {
		i = dtoi(args[optind], FAULT_ON_ERROR, NULL);
		if (i >= nr_irqs)
			error(FATAL, "invalid IRQ value: %d  (%d max)\n", 
				i, nr_irqs-1);
		machdep->dump_irq(i);
		optind++;
	}
}


/*
 *  Do the work for cmd_irq().
 */
void
generic_dump_irq(int irq)
{
	struct datatype_member datatype_member, *dm;
	ulong irq_desc_addr;
	ulong irq_desc_ptr;
	long len;
	char buf[BUFSIZE];
	int status, depth, others;
	ulong handler, action, value;
	ulong tmp1, tmp2;

	dm = &datatype_member;
	
	if (!VALID_STRUCT(irq_desc_t))
		error(FATAL, "cannot determine size of irq_desc_t\n");
	len = SIZE(irq_desc_t);

        if (symbol_exists("irq_desc"))
		irq_desc_addr = symbol_value("irq_desc") + (len * irq);
        else if (symbol_exists("_irq_desc"))
		irq_desc_addr = symbol_value("_irq_desc") + (len * irq);
	else if (symbol_exists("irq_desc_ptrs")) {
		get_symbol_data("irq_desc_ptrs", sizeof(void *), &irq_desc_ptr);
		irq_desc_ptr += (irq * sizeof(void *));
		readmem(irq_desc_ptr, KVADDR, &irq_desc_addr,
                        sizeof(void *), "irq_desc_ptrs entry",
                        FAULT_ON_ERROR);
		if (!irq_desc_addr) {
			fprintf(fp, "    IRQ: %d (unused)\n\n", irq);
			return;
		}
	} else {
		irq_desc_addr = 0;
		error(FATAL, 
		    "neither irq_desc, _irq_desc, nor irq_desc_ptrs "
		    "symbols exist\n");
	}

        readmem(irq_desc_addr + OFFSET(irq_desc_t_status), KVADDR, &status,
                sizeof(int), "irq_desc entry", FAULT_ON_ERROR);
	if (VALID_MEMBER(irq_desc_t_handler))
	        readmem(irq_desc_addr + OFFSET(irq_desc_t_handler), KVADDR,
        	        &handler, sizeof(long), "irq_desc entry",
			FAULT_ON_ERROR);
	else if (VALID_MEMBER(irq_desc_t_chip))
	        readmem(irq_desc_addr + OFFSET(irq_desc_t_chip), KVADDR,
        	        &handler, sizeof(long), "irq_desc entry",
			FAULT_ON_ERROR);
        readmem(irq_desc_addr + OFFSET(irq_desc_t_action), KVADDR, &action,
                sizeof(long), "irq_desc entry", FAULT_ON_ERROR);
        readmem(irq_desc_addr + OFFSET(irq_desc_t_depth), KVADDR, &depth,
                sizeof(int), "irq_desc entry", FAULT_ON_ERROR);

	if (!action && (handler == (ulong)pc->curcmd_private))
		return;

	fprintf(fp, "    IRQ: %d\n", irq);
	fprintf(fp, " STATUS: %x %s", status, status ? "(" : "");
	others = 0;
	if (status & IRQ_INPROGRESS) {
		fprintf(fp, "IRQ_INPROGRESS");
		others++;
	}
	if (status & IRQ_DISABLED)
		fprintf(fp, "%sIRQ_DISABLED", others++ ? "|" : "");
        if (status & IRQ_PENDING)
                fprintf(fp, "%sIRQ_PENDING", others++ ? "|" : "");
        if (status & IRQ_REPLAY)
                fprintf(fp, "%sIRQ_REPLAY", others++ ? "|" : "");
        if (status & IRQ_AUTODETECT)
                fprintf(fp, "%sIRQ_AUTODETECT", others++ ? "|" : "");
        if (status & IRQ_WAITING)
                fprintf(fp, "%sIRQ_WAITING", others++ ? "|" : "");
        if (status & IRQ_LEVEL)
                fprintf(fp, "%sIRQ_LEVEL", others++ ? "|" : "");
        if (status & IRQ_MASKED)
                fprintf(fp, "%sIRQ_MASKED", others++ ? "|" : "");
	fprintf(fp, "%s\n", status ? ")" : "");

	fprintf(fp, "HANDLER: ");
	if (value_symbol(handler)) {
		fprintf(fp, "%lx  ", handler);
		pad_line(fp, VADDR_PRLEN == 8 ? 
			VADDR_PRLEN+2 : VADDR_PRLEN-6, ' ');
		fprintf(fp, "<%s>\n", value_symbol(handler));
	} else
		fprintf(fp, "%lx\n", handler);

	if (handler) {
		if (VALID_MEMBER(hw_interrupt_type_typename))
	        	readmem(handler+OFFSET(hw_interrupt_type_typename),
				KVADDR,	&tmp1, sizeof(void *),
        	        	"hw_interrupt_type typename", FAULT_ON_ERROR);
		else if (VALID_MEMBER(irq_chip_typename))
	        	readmem(handler+OFFSET(irq_chip_typename),
				KVADDR,	&tmp1, sizeof(void *),
                		"hw_interrupt_type typename", FAULT_ON_ERROR);

	 	fprintf(fp, "         typename: %lx  ", tmp1);
		BZERO(buf, BUFSIZE);
        	if (read_string(tmp1, buf, BUFSIZE-1))
			fprintf(fp, "\"%s\"", buf);
		fprintf(fp, "\n");

		if (VALID_MEMBER(hw_interrupt_type_startup))
			readmem(handler+OFFSET(hw_interrupt_type_startup),
				KVADDR,	&tmp1, sizeof(void *),
				"hw_interrupt_type startup", FAULT_ON_ERROR);
		else if (VALID_MEMBER(irq_chip_startup))
			readmem(handler+OFFSET(irq_chip_startup),
				KVADDR,	&tmp1, sizeof(void *),
				"hw_interrupt_type startup", FAULT_ON_ERROR);
		fprintf(fp, "          startup: %lx  ", tmp1); 
		if (is_kernel_text(tmp1)) 
			fprintf(fp, "<%s>", value_to_symstr(tmp1, buf, 0));
		else if (readmem(tmp1, KVADDR, &tmp2,
                	sizeof(ulong), "startup indirection",
                        RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                            	fprintf(fp, "<%s>",
                                	value_to_symstr(tmp2, buf, 0));
		fprintf(fp, "\n");

		if (VALID_MEMBER(hw_interrupt_type_shutdown))
	                readmem(handler+OFFSET(hw_interrupt_type_shutdown),
				KVADDR, &tmp1, sizeof(void *),
	                        "hw_interrupt_type shutdown", FAULT_ON_ERROR);
		else if (VALID_MEMBER(irq_chip_shutdown))
	                readmem(handler+OFFSET(irq_chip_shutdown),
				KVADDR, &tmp1, sizeof(void *),
	                        "hw_interrupt_type shutdown", FAULT_ON_ERROR);

                fprintf(fp, "         shutdown: %lx  ", tmp1);
                if (is_kernel_text(tmp1))
                        fprintf(fp, "<%s>", value_to_symstr(tmp1, buf, 0));
                else if (readmem(tmp1, KVADDR, &tmp2,
                        sizeof(ulong), "shutdown indirection",
                        RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp2, buf, 0));
                fprintf(fp, "\n");

		if (VALID_MEMBER(hw_interrupt_type_handle)) {
	                readmem(handler+OFFSET(hw_interrupt_type_handle), 
				KVADDR,
	                        &tmp1, sizeof(void *),
	                        "hw_interrupt_type handle", FAULT_ON_ERROR);
	                fprintf(fp, "           handle: %lx  ", tmp1);
	                if (is_kernel_text(tmp1))
	                        fprintf(fp, "<%s>", 
					value_to_symstr(tmp1, buf, 0));
	                else if (readmem(tmp1, KVADDR, &tmp2,
	                        sizeof(ulong), "handle indirection",
	                        RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
	                                fprintf(fp, "<%s>",
	                                        value_to_symstr(tmp2, buf, 0));
	                fprintf(fp, "\n");
		}

		if (VALID_MEMBER(hw_interrupt_type_enable))
	                readmem(handler+OFFSET(hw_interrupt_type_enable),
				KVADDR, &tmp1, sizeof(void *),
	                        "hw_interrupt_type enable", FAULT_ON_ERROR);
		else if (VALID_MEMBER(irq_chip_enable))
	                readmem(handler+OFFSET(irq_chip_enable),
				KVADDR, &tmp1, sizeof(void *),
	                        "hw_interrupt_type enable", FAULT_ON_ERROR);
                fprintf(fp, "           enable: %lx  ", tmp1);
                if (is_kernel_text(tmp1))
                        fprintf(fp, "<%s>", value_to_symstr(tmp1, buf, 0));
                else if (readmem(tmp1, KVADDR, &tmp2,
                        sizeof(ulong), "enable indirection",
                        RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp2, buf, 0));
                fprintf(fp, "\n");

		if (VALID_MEMBER(hw_interrupt_type_disable))
	                readmem(handler+OFFSET(hw_interrupt_type_disable),
				KVADDR, &tmp1, sizeof(void *),
	                        "hw_interrupt_type disable", FAULT_ON_ERROR);
		else if (VALID_MEMBER(irq_chip_disable))
	                readmem(handler+OFFSET(irq_chip_disable),
				KVADDR, &tmp1, sizeof(void *),
	                        "hw_interrupt_type disable", FAULT_ON_ERROR);
                fprintf(fp, "          disable: %lx  ", tmp1);
                if (is_kernel_text(tmp1))
                        fprintf(fp, "<%s>", value_to_symstr(tmp1, buf, 0));
                else if (readmem(tmp1, KVADDR, &tmp2,
                        sizeof(ulong), "disable indirection",
                        RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp2, buf, 0));
                fprintf(fp, "\n");

		if (VALID_MEMBER(hw_interrupt_type_ack)) {
                	readmem(handler+OFFSET(hw_interrupt_type_ack), KVADDR,
                        	&tmp1, sizeof(void *),
                        	"hw_interrupt_type ack", FAULT_ON_ERROR);
                	fprintf(fp, "              ack: %lx  ", tmp1);
                	if (is_kernel_text(tmp1))
                        	fprintf(fp, "<%s>", 
					value_to_symstr(tmp1, buf, 0));
                	else if (readmem(tmp1, KVADDR, &tmp2,
                        	sizeof(ulong), "ack indirection",
                        	RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                	fprintf(fp, "<%s>",
                                        	value_to_symstr(tmp2, buf, 0));
                	fprintf(fp, "\n");
		} else if (VALID_MEMBER(irq_chip_ack)) {
                	readmem(handler+OFFSET(irq_chip_ack), KVADDR,
                        	&tmp1, sizeof(void *),
                        	"irq_chip ack", FAULT_ON_ERROR);
                	fprintf(fp, "              ack: %lx  ", tmp1);
                	if (is_kernel_text(tmp1))
                        	fprintf(fp, "<%s>",
					value_to_symstr(tmp1, buf, 0));
                	else if (readmem(tmp1, KVADDR, &tmp2,
                        	sizeof(ulong), "ack indirection",
                        	RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                	fprintf(fp, "<%s>",
                                        	value_to_symstr(tmp2, buf, 0));
                	fprintf(fp, "\n");
		}

		if (VALID_MEMBER(irq_chip_mask)) {
			readmem(handler+OFFSET(irq_chip_mask), KVADDR,
				&tmp1, sizeof(void *),
				"irq_chip mask", FAULT_ON_ERROR);
                        fprintf(fp, "             mask: %lx  ", tmp1);
                        if (is_kernel_text(tmp1))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp1, buf, 0));
                        else if (readmem(tmp1, KVADDR, &tmp2,
                                sizeof(ulong), "mask indirection",
                                RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                        fprintf(fp, "<%s>",
                                                value_to_symstr(tmp2, buf, 0));
                        fprintf(fp, "\n");
		}
		
		if (VALID_MEMBER(irq_chip_mask_ack)) {
			readmem(handler+OFFSET(irq_chip_mask_ack), KVADDR,
				&tmp1, sizeof(void *),
				"irq_chip mask_ack", FAULT_ON_ERROR);
                        fprintf(fp, "         mask_ack: %lx  ", tmp1);
                        if (is_kernel_text(tmp1))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp1, buf, 0));
                        else if (readmem(tmp1, KVADDR, &tmp2,
                                sizeof(ulong), "mask_ack indirection",
                                RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                        fprintf(fp, "<%s>",
                                                value_to_symstr(tmp2, buf, 0));
                        fprintf(fp, "\n");
		}

		if (VALID_MEMBER(irq_chip_unmask)) {
			readmem(handler+OFFSET(irq_chip_unmask), KVADDR,
				&tmp1, sizeof(void *),
				"irq_chip unmask", FAULT_ON_ERROR);
                        fprintf(fp, "           unmask: %lx  ", tmp1);
                        if (is_kernel_text(tmp1))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp1, buf, 0));
                        else if (readmem(tmp1, KVADDR, &tmp2,
                                sizeof(ulong), "unmask indirection",
                                RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                        fprintf(fp, "<%s>",
                                                value_to_symstr(tmp2, buf, 0));
                        fprintf(fp, "\n");
		}

		if (VALID_MEMBER(irq_chip_eoi)) {
			readmem(handler+OFFSET(irq_chip_eoi), KVADDR,
				&tmp1, sizeof(void *),
				"irq_chip eoi", FAULT_ON_ERROR);
                        fprintf(fp, "              eoi: %lx  ", tmp1);
                        if (is_kernel_text(tmp1))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp1, buf, 0));
                        else if (readmem(tmp1, KVADDR, &tmp2,
                                sizeof(ulong), "eoi indirection",
                                RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                        fprintf(fp, "<%s>",
                                                value_to_symstr(tmp2, buf, 0));
                        fprintf(fp, "\n");
		}

		if (VALID_MEMBER(hw_interrupt_type_end)) {
                	readmem(handler+OFFSET(hw_interrupt_type_end), KVADDR,
                        	&tmp1, sizeof(void *),
                        	"hw_interrupt_type end", FAULT_ON_ERROR);
                        fprintf(fp, "              end: %lx  ", tmp1);
                        if (is_kernel_text(tmp1))
                                fprintf(fp, "<%s>", 
                                        value_to_symstr(tmp1, buf, 0));
                        else if (readmem(tmp1, KVADDR, &tmp2,
                                sizeof(ulong), "end indirection",
                                RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                        fprintf(fp, "<%s>",
                                                value_to_symstr(tmp2, buf, 0));
                        fprintf(fp, "\n");
		} else if (VALID_MEMBER(irq_chip_end)) {
                	readmem(handler+OFFSET(irq_chip_end), KVADDR,
                        	&tmp1, sizeof(void *),
                        	"irq_chip end", FAULT_ON_ERROR);
                        fprintf(fp, "              end: %lx  ", tmp1);
                        if (is_kernel_text(tmp1))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp1, buf, 0));
                        else if (readmem(tmp1, KVADDR, &tmp2,
                                sizeof(ulong), "end indirection",
                                RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                        fprintf(fp, "<%s>",
                                                value_to_symstr(tmp2, buf, 0));
                        fprintf(fp, "\n");
		}

		if (VALID_MEMBER(hw_interrupt_type_set_affinity)) {
                	readmem(handler+OFFSET(hw_interrupt_type_set_affinity),
				KVADDR, &tmp1, sizeof(void *),
                        	"hw_interrupt_type set_affinity", 
				FAULT_ON_ERROR);
                        fprintf(fp, "     set_affinity: %lx  ", tmp1);
                        if (is_kernel_text(tmp1))
                                fprintf(fp, "<%s>", 
                                        value_to_symstr(tmp1, buf, 0));
                        else if (readmem(tmp1, KVADDR, &tmp2,
                                sizeof(ulong), "set_affinity indirection",
                                RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                        fprintf(fp, "<%s>",
                                                value_to_symstr(tmp2, buf, 0));
                        fprintf(fp, "\n");
		} else if (VALID_MEMBER(irq_chip_set_affinity)) {
                	readmem(handler+OFFSET(irq_chip_set_affinity),
				KVADDR, &tmp1, sizeof(void *),
                        	"irq_chip set_affinity",
				FAULT_ON_ERROR);
                        fprintf(fp, "     set_affinity: %lx  ", tmp1);
                        if (is_kernel_text(tmp1))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp1, buf, 0));
                        else if (readmem(tmp1, KVADDR, &tmp2,
                                sizeof(ulong), "set_affinity indirection",
                                RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                        fprintf(fp, "<%s>",
                                                value_to_symstr(tmp2, buf, 0));
                        fprintf(fp, "\n");
		}
		if (VALID_MEMBER(irq_chip_retrigger)) {
			readmem(handler+OFFSET(irq_chip_retrigger), KVADDR,
				&tmp1, sizeof(void *),
				"irq_chip retrigger", FAULT_ON_ERROR);
                        fprintf(fp, "        retrigger: %lx  ", tmp1);
                        if (is_kernel_text(tmp1))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp1, buf, 0));
                        else if (readmem(tmp1, KVADDR, &tmp2,
                                sizeof(ulong), "retrigger indirection",
                                RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                        fprintf(fp, "<%s>",
                                                value_to_symstr(tmp2, buf, 0));
                        fprintf(fp, "\n");
		}
		if (VALID_MEMBER(irq_chip_set_type)) {
			readmem(handler+OFFSET(irq_chip_set_type), KVADDR,
				&tmp1, sizeof(void *),
				"irq_chip set_type", FAULT_ON_ERROR);
                        fprintf(fp, "         set_type: %lx  ", tmp1);
                        if (is_kernel_text(tmp1))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp1, buf, 0));
                        else if (readmem(tmp1, KVADDR, &tmp2,
                                sizeof(ulong), "set_type indirection",
                                RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                        fprintf(fp, "<%s>",
                                                value_to_symstr(tmp2, buf, 0));
                        fprintf(fp, "\n");
		}
		if (VALID_MEMBER(irq_chip_set_wake)) {
			readmem(handler+OFFSET(irq_chip_set_wake), KVADDR,
				&tmp1, sizeof(void *),
				"irq_chip set wake", FAULT_ON_ERROR);
                        fprintf(fp, "         set_wake: %lx  ", tmp1);
                        if (is_kernel_text(tmp1))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp1, buf, 0));
                        else if (readmem(tmp1, KVADDR, &tmp2,
                                sizeof(ulong), "set_wake indirection",
                                RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                        fprintf(fp, "<%s>",
                                                value_to_symstr(tmp2, buf, 0));
                        fprintf(fp, "\n");
		}
	}

do_linked_action:

	fprintf(fp, " ACTION: ");
        if (value_symbol(action)) {
                fprintf(fp, "%lx  ", action);
                pad_line(fp, VADDR_PRLEN == 8 ? 
			VADDR_PRLEN+2 : VADDR_PRLEN-6, ' ');
                fprintf(fp, "<%s>\n", value_symbol(action));
        } else if (action)
                fprintf(fp, "%lx\n", action);
	else
		fprintf(fp, "(none)\n");


	if (action) {
                readmem(action+OFFSET(irqaction_handler), KVADDR,
                        &tmp1, sizeof(void *),
                        "irqaction handler", FAULT_ON_ERROR);
		fprintf(fp, "          handler: %lx  ", tmp1);
                if (is_kernel_text(tmp1))
                        fprintf(fp, "<%s>", value_to_symstr(tmp1, buf, 0));
                else if (readmem(tmp1, KVADDR, &tmp2,
                        sizeof(ulong), "handler indirection",
                        RETURN_ON_ERROR|QUIET) && is_kernel_text(tmp2))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(tmp2, buf, 0));
                fprintf(fp, "\n");

                readmem(action+OFFSET(irqaction_flags), KVADDR,
                        &value, sizeof(void *),
                        "irqaction flags", FAULT_ON_ERROR);
                fprintf(fp, "            flags: %lx\n", value);

                readmem(action+OFFSET(irqaction_mask), KVADDR,
                        &tmp1, sizeof(void *),
                        "irqaction mask", FAULT_ON_ERROR);
                fprintf(fp, "             mask: %lx\n", tmp1);

                readmem(action+OFFSET(irqaction_name), KVADDR,
                        &tmp1, sizeof(void *),
                        "irqaction name", FAULT_ON_ERROR);
                fprintf(fp, "             name: %lx  ", tmp1);
                BZERO(buf, BUFSIZE);
                if (read_string(tmp1, buf, BUFSIZE-1))
                        fprintf(fp, "\"%s\"", buf);
                fprintf(fp, "\n");

                readmem(action+OFFSET(irqaction_dev_id), KVADDR,
                        &tmp1, sizeof(void *),
                        "irqaction dev_id", FAULT_ON_ERROR);
                fprintf(fp, "           dev_id: %lx\n", tmp1);

                readmem(action+OFFSET(irqaction_next), KVADDR,
                        &action, sizeof(void *),
                        "irqaction dev_id", FAULT_ON_ERROR);
                fprintf(fp, "             next: %lx\n", action);
	}

	if (action) 
		goto do_linked_action;

	fprintf(fp, "  DEPTH: %d\n\n", depth);
}

/*
 *  Dump the earlier 2.2 Linux version's bottom-half essentials.
 */
static void
display_bh_1(void)
{
        int i;
        ulong bh_mask, bh_active;
        ulong bh_base[32];
        char buf[BUFSIZE];

        get_symbol_data("bh_mask", sizeof(ulong), &bh_mask);
        get_symbol_data("bh_active", sizeof(ulong), &bh_active);
        readmem(symbol_value("bh_base"), KVADDR, bh_base, sizeof(void *) * 32,
                "bh_base[32]", FAULT_ON_ERROR);

        fprintf(fp, "BH_MASK   BH_ACTIVE\n");
        fprintf(fp, "%08lx  %08lx\n", bh_mask, bh_active);
        fprintf(fp, "\nBH_BASE   %s\n",
                mkstring(buf, VADDR_PRLEN, CENTER|LJUST, "FUNCTION"));
        for (i = 0; i < 32; i++) {
                if (!bh_base[i])
                        continue;
                fprintf(fp, "  %2d      %lx  <%s>\n", i, bh_base[i],
                        value_to_symstr(bh_base[i], buf, 0));
        }
}

/*
 *  Dump the 2.3-ish Linux version's bottom half essentials.  
 */
static void 
display_bh_2(void)
{
	int i;
        ulong bh_base[32];
	struct softirq_state {
        	uint32_t active;
        	uint32_t mask;
	} softirq_state; 
	struct softirq_action {
	        void    *action;
        	void    *data;
	} softirq_vec[32];
	char buf[BUFSIZE];

        readmem(symbol_value("bh_base"), KVADDR, bh_base, sizeof(void *) * 32,
                "bh_base[32]", FAULT_ON_ERROR);

        readmem(symbol_value("softirq_vec"), KVADDR, softirq_vec, 
		sizeof(struct softirq_action) * 32,
                "softirq_vec[32]", FAULT_ON_ERROR);

	fprintf(fp, "CPU    MASK     ACTIVE\n");
	
	for (i = 0; i < kt->cpus; i++) {
		readmem(symbol_value("softirq_state") + 
			(i * SIZE(softirq_state)), KVADDR,
			&softirq_state, sizeof(struct softirq_state),
			"softirq_state", FAULT_ON_ERROR);

		fprintf(fp, " %-2d  %08x  %08x\n", 
			i, softirq_state.mask,
			softirq_state.active);
	}

	fprintf(fp, "\nVEC  %s\n", 
		mkstring(buf, VADDR_PRLEN, CENTER|LJUST, "ACTION"));

	for (i = 0; i < 32; i++) {
		if (!softirq_vec[i].action)
			continue;

		fprintf(fp, " %-2d  %lx  <%s>\n", i, 
			(ulong)softirq_vec[i].action,
			value_to_symstr((ulong)softirq_vec[i].action, buf, 0));
	}

        fprintf(fp, "\nBH_BASE   %s\n", 
		mkstring(buf, VADDR_PRLEN, CENTER|LJUST, "FUNCTION"));
        for (i = 0; i < 32; i++) {
                if (!bh_base[i])
                        continue;
                fprintf(fp, "  %2d      %lx  <%s>\n", i, bh_base[i],
                        value_to_symstr(bh_base[i], buf, 0));
        }

}

/*
 *  Dump the 2.4 Linux version's bottom half essentials.  
 */
static void 
display_bh_3(void)
{
	int i;
        ulong bh_base[32];
	struct softirq_action {
	        void    *action;
        	void    *data;
	} softirq_vec[32];
	char buf[BUFSIZE];
	uint active, mask;
	ulong function;

        readmem(symbol_value("bh_base"), KVADDR, bh_base, sizeof(void *) * 32,
                "bh_base[32]", FAULT_ON_ERROR);

        readmem(symbol_value("softirq_vec"), KVADDR, softirq_vec, 
		sizeof(struct softirq_action) * 32,
                "softirq_vec[32]", FAULT_ON_ERROR);

	fprintf(fp, "CPU    MASK     ACTIVE\n");
	
	for (i = 0; i < kt->cpus; i++) {
		readmem(symbol_value("irq_stat") + 
			(i * SIZE(irq_cpustat_t)) +
			OFFSET(irq_cpustat_t___softirq_active), KVADDR,
			&active, sizeof(uint),
			"__softirq_active", FAULT_ON_ERROR);

                readmem(symbol_value("irq_stat") +
                        (i * SIZE(irq_cpustat_t)) +
                        OFFSET(irq_cpustat_t___softirq_mask), KVADDR,
                        &mask, sizeof(uint),
                        "__softirq_mask", FAULT_ON_ERROR);

		fprintf(fp, " %-2d  %08x  %08x\n", i, mask, active);
	}

	fprintf(fp, "\nVEC  %s\n", 
		mkstring(buf, VADDR_PRLEN, CENTER|LJUST, "ACTION"));

	for (i = 0; i < 32; i++) {
		if (!softirq_vec[i].action)
			continue;

		fprintf(fp, " %-2d  %lx  ", i, (ulong)softirq_vec[i].action);
		if (is_kernel_text((ulong)softirq_vec[i].action))
			fprintf(fp, "<%s>",
			    	value_to_symstr((ulong)softirq_vec[i].action, 
			    	buf, 0));
                else if (readmem((ulong)softirq_vec[i].action, KVADDR, 
			&function, sizeof(ulong), "action indirection",
                        RETURN_ON_ERROR|QUIET) && is_kernel_text(function))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(function, buf, 0));
		fprintf(fp, "\n");
	}

        fprintf(fp, "\nBH_BASE   %s\n", 
		mkstring(buf, VADDR_PRLEN, CENTER|LJUST, "FUNCTION"));
        for (i = 0; i < 32; i++) {
                if (!bh_base[i])
                        continue;
                fprintf(fp, "  %2d      %lx  ", i, bh_base[i]);
		if (is_kernel_text(bh_base[i]))
			fprintf(fp, "<%s>", 
				value_to_symstr(bh_base[i], buf, 0));
                else if (readmem(bh_base[i], KVADDR, &function,
                        sizeof(ulong), "bh_base indirection",
                        RETURN_ON_ERROR|QUIET) && is_kernel_text(function))
                                fprintf(fp, "<%s>",
                                        value_to_symstr(function, buf, 0));
		fprintf(fp, "\n");
        }

}

/*
 *  Dump the entries in the old- and new-style timer queues in
 *  chronological order.
 */
void
cmd_timer(void)
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

	dump_timer_data();
}

/*
 *  Display the pending timer queue entries, both the old and new-style.
 */
struct timer_data {
	ulong address; 
	ulong expires;
	ulong function;
};

struct tv_range {
        ulong base;
        ulong end;
};

#define TVN (6)

static void
dump_timer_data(void)
{
	int i;
	ulong timer_active;
	struct timer_struct {
        	unsigned long expires;
        	void *fn;
	} timer_table[32];
	char buf[BUFSIZE];
	char buf1[BUFSIZE];
        struct timer_struct *tp;
        ulong mask, highest, function;
	ulong jiffies, timer_jiffies;
	ulong *vec;
	long count;
        int vec_root_size, vec_size;
	struct timer_data *td;
	int flen, tdx, old_timers_exist;
        struct tv_range tv[TVN];

	if (symbol_exists("tvec_bases")) {
		dump_timer_data_tvec_bases_v1();
		return;
	} else if (symbol_exists("per_cpu__tvec_bases")) {
		dump_timer_data_tvec_bases_v2();
		return;
	}

	BZERO(tv, sizeof(struct tv_range) * TVN);

	vec_root_size = (i = ARRAY_LENGTH(timer_vec_root_vec)) ?
		i : get_array_length("timer_vec_root.vec", 
			NULL, SIZE(list_head));
	vec_size = (i = ARRAY_LENGTH(timer_vec_vec)) ? 
		i : get_array_length("timer_vec.vec", NULL, SIZE(list_head));

	vec = (ulong *)GETBUF(SIZE(list_head) * MAX(vec_root_size, vec_size));

	if (symbol_exists("timer_active") && symbol_exists("timer_table")) {
		get_symbol_data("timer_active", sizeof(ulong), &timer_active);
        	readmem(symbol_value("timer_table"), KVADDR, &timer_table,
                	sizeof(struct timer_struct) * 32, "timer_table[32]", 
			FAULT_ON_ERROR);
		old_timers_exist = TRUE;
	} else
		old_timers_exist = FALSE;

	/*
 	 * Get rough count first, and then gather a bunch of timer_data
	 * structs to stuff in a sortable array.
	 */

	count = 0;
        for (mask = 1, tp = timer_table+0; old_timers_exist && mask; 
	     tp++, mask += mask) {
                if (mask > timer_active)
                        break;
                if (!(mask & timer_active))
                        continue;
		count++;
        }

	init_tv_ranges(tv, vec_root_size, vec_size, 0);

        count += do_timer_list(symbol_value("tv1") + OFFSET(timer_vec_root_vec),
		vec_root_size, vec, NULL, NULL, tv);
        count += do_timer_list(symbol_value("tv2") + OFFSET(timer_vec_vec),
		vec_size, vec, NULL, NULL, tv);
        count += do_timer_list(symbol_value("tv3") + OFFSET(timer_vec_vec),
		vec_size, vec, NULL, NULL, tv);
        count += do_timer_list(symbol_value("tv4") + OFFSET(timer_vec_vec),
		vec_size, vec, NULL, NULL, tv);
        count += do_timer_list(symbol_value("tv4") + OFFSET(timer_vec_vec),
		vec_size, vec, NULL, NULL, tv);

	td = (struct timer_data *)
		GETBUF((count*2) * sizeof(struct timer_data));
	tdx = 0;

	get_symbol_data("jiffies", sizeof(ulong), &jiffies);
	get_symbol_data("timer_jiffies", sizeof(ulong), &timer_jiffies);
	if (old_timers_exist)
		get_symbol_data("timer_active", sizeof(ulong), &timer_active);

	highest = 0;
        for (i = 0, mask = 1, tp = timer_table+0; old_timers_exist && mask; 
	     i++, tp++, mask += mask) {
                if (mask > timer_active) 
                        break;

                if (!(mask & timer_active)) 
                        continue;

		td[tdx].address = i;
		td[tdx].expires = tp->expires;
		td[tdx].function = (ulong)tp->fn;
		if (td[tdx].expires > highest)
			highest = td[tdx].expires;
		tdx++;
        }

	do_timer_list(symbol_value("tv1") + OFFSET(timer_vec_root_vec),
		vec_root_size, vec, (void *)td, &highest, tv);
	do_timer_list(symbol_value("tv2") + OFFSET(timer_vec_vec),
		vec_size, vec, (void *)td, &highest, tv);
	do_timer_list(symbol_value("tv3") + OFFSET(timer_vec_vec),
		vec_size, vec, (void *)td, &highest, tv);
	do_timer_list(symbol_value("tv4") + OFFSET(timer_vec_vec),
		vec_size, vec, (void *)td, &highest, tv);
	tdx = do_timer_list(symbol_value("tv5") + OFFSET(timer_vec_vec),
		vec_size, vec, (void *)td, &highest, tv);

        qsort(td, tdx, sizeof(struct timer_data), compare_timer_data);

	/*
	 *  Because the jiffies values can fluctuate wildly from dump to
	 *  dump, try to use the appropriate amount of space...
	 */
	sprintf(buf, "%ld", highest); 
	flen = MAX(strlen(buf), strlen("JIFFIES"));
	fprintf(fp, "%s\n", mkstring(buf, flen, CENTER|LJUST, "JIFFIES"));
	fprintf(fp, "%s\n", mkstring(buf, flen, RJUST|LONG_DEC,MKSTR(jiffies)));

	fprintf(fp, "%s  TIMER_LIST/TABLE  FUNCTION\n",
		mkstring(buf, flen, CENTER|LJUST, "EXPIRES"));

        for (i = 0; i < tdx; i++) {
        	fprintf(fp, "%s", 
		    mkstring(buf, flen, RJUST|LONG_DEC, MKSTR(td[i].expires)));

		if (td[i].address < 32) {
                        sprintf(buf, "timer_table[%ld]", td[i].address);
                        fprintf(fp, "  %s  ",
                                mkstring(buf, 16, CENTER|LJUST, NULL));
		} else {
			mkstring(buf1, VADDR_PRLEN, RJUST|LONG_HEX, 
				MKSTR(td[i].address));
			fprintf(fp, "  %s  ", mkstring(buf, 16, CENTER, buf1));
		}
		
		if (is_kernel_text(td[i].function)) 
			fprintf(fp, "%s  <%s>\n",
				mkstring(buf1, VADDR_PRLEN, RJUST|LONG_HEX, 
				MKSTR(td[i].function)),
                        	value_to_symstr(td[i].function, buf, 0));
		else {
			fprintf(fp, "%s  ", 
				mkstring(buf1, VADDR_PRLEN, RJUST|LONG_HEX, 
				MKSTR(td[i].function)));
                	if (readmem(td[i].function, KVADDR, &function,
                            sizeof(ulong), "timer function",
                            RETURN_ON_ERROR|QUIET)) {
				if (is_kernel_text(function))
					fprintf(fp, "<%s>",
					    value_to_symstr(function, buf, 0));
			} 
			fprintf(fp, "\n");
		}
        }
}

/*
 *  Newer per-cpu timers, using "tvec_bases".
 */

static void
dump_timer_data_tvec_bases_v1(void)
{
	int i, cpu, tdx, flen;
        struct timer_data *td;
        int vec_root_size, vec_size;
        struct tv_range tv[TVN];
	ulong *vec, jiffies, highest, function;
	long count;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];

	kt->flags |= TVEC_BASES_V1;

	/*
         */
        vec_root_size = (i = ARRAY_LENGTH(tvec_root_s_vec)) ?
                i : get_array_length("tvec_root_s.vec", NULL, SIZE(list_head));
        vec_size = (i = ARRAY_LENGTH(tvec_s_vec)) ?
                i : get_array_length("tvec_s.vec", NULL, SIZE(list_head));
        vec = (ulong *)GETBUF(SIZE(list_head) * MAX(vec_root_size, vec_size));

	cpu = 0;

next_cpu:

        count = 0;
        td = (struct timer_data *)NULL;

	BZERO(tv, sizeof(struct tv_range) * TVN);

        init_tv_ranges(tv, vec_root_size, vec_size, cpu);

        count += do_timer_list(tv[1].base + OFFSET(tvec_root_s_vec),
                vec_root_size, vec, NULL, NULL, tv);
        count += do_timer_list(tv[2].base + OFFSET(tvec_s_vec),
                vec_size, vec, NULL, NULL, tv);
        count += do_timer_list(tv[3].base + OFFSET(tvec_s_vec),
                vec_size, vec, NULL, NULL, tv);
        count += do_timer_list(tv[4].base + OFFSET(tvec_s_vec),
                vec_size, vec, NULL, NULL, tv);
        count += do_timer_list(tv[5].base + OFFSET(tvec_s_vec),
                vec_size, vec, NULL, NULL, tv);

	if (count)
        	td = (struct timer_data *)
                	GETBUF((count*2) * sizeof(struct timer_data));
        tdx = 0;
	highest = 0;
        get_symbol_data("jiffies", sizeof(ulong), &jiffies);

        do_timer_list(tv[1].base + OFFSET(tvec_root_s_vec),
                vec_root_size, vec, (void *)td, &highest, tv);
        do_timer_list(tv[2].base + OFFSET(tvec_s_vec),
                vec_size, vec, (void *)td, &highest, tv);
        do_timer_list(tv[3].base + OFFSET(tvec_s_vec),
                vec_size, vec, (void *)td, &highest, tv);
        do_timer_list(tv[4].base + OFFSET(tvec_s_vec),
                vec_size, vec, (void *)td, &highest, tv);
        tdx = do_timer_list(tv[5].base + OFFSET(tvec_s_vec),
                vec_size, vec, (void *)td, &highest, tv);

        qsort(td, tdx, sizeof(struct timer_data), compare_timer_data);

	fprintf(fp, "TVEC_BASES[%d]: %lx\n", cpu,
        	symbol_value("tvec_bases") + (SIZE(tvec_t_base_s) * cpu));
		
        sprintf(buf1, "%ld", highest);
        flen = MAX(strlen(buf1), strlen("JIFFIES"));
        fprintf(fp, "%s\n", mkstring(buf1,flen, CENTER|RJUST, "JIFFIES"));
        fprintf(fp, "%s\n", mkstring(buf1,flen, 
		RJUST|LONG_DEC,MKSTR(jiffies)));

	fprintf(fp, "%s  %s  %s\n",
		mkstring(buf1, flen, CENTER|RJUST, "EXPIRES"),
		mkstring(buf2, VADDR_PRLEN, CENTER|LJUST, "TIMER_LIST"),
		mkstring(buf3, VADDR_PRLEN, CENTER|LJUST, "FUNCTION"));

        for (i = 0; i < tdx; i++) {
                fprintf(fp, "%s",
                    mkstring(buf1, flen, RJUST|LONG_DEC, MKSTR(td[i].expires)));

                fprintf(fp, "  %s  ", mkstring(buf1, 
			MAX(VADDR_PRLEN, strlen("TIMER_LIST")), 
			RJUST|CENTER|LONG_HEX, MKSTR(td[i].address)));

                if (is_kernel_text(td[i].function)) {
                        fprintf(fp, "%s  <%s>\n",
				mkstring(buf2, VADDR_PRLEN, RJUST|LONG_HEX,
				MKSTR(td[i].function)),
                                value_to_symstr(td[i].function, buf1, 0));
                } else {
                        fprintf(fp, "%s  ", mkstring(buf1, VADDR_PRLEN, 
				RJUST|LONG_HEX, MKSTR(td[i].function)));
                        if (readmem(td[i].function, KVADDR, &function,
                            sizeof(ulong), "timer function",
                            RETURN_ON_ERROR|QUIET)) {
                                if (is_kernel_text(function))
                                        fprintf(fp, "<%s>",
                                            value_to_symstr(function, buf1, 0));
                        }
                        fprintf(fp, "\n");
                }
        }

	if (td)
		FREEBUF(td);

	if (++cpu < kt->cpus)
		goto next_cpu;
}

/*
 *  2.6 per-cpu timers, using "per_cpu__tvec_bases".
 */

static void
dump_timer_data_tvec_bases_v2(void)
{
	int i, cpu, tdx, flen;
        struct timer_data *td;
        int vec_root_size, vec_size;
        struct tv_range tv[TVN];
	ulong *vec, jiffies, highest, function;
	ulong tvec_bases;
	long count;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];

	kt->flags |= TVEC_BASES_V2;

	/*
         */
        vec_root_size = (i = ARRAY_LENGTH(tvec_root_s_vec)) ?
                i : get_array_length("tvec_root_s.vec", NULL, SIZE(list_head));
	if (!vec_root_size && 
	    (i = get_array_length("tvec_root.vec", NULL, SIZE(list_head))))
		vec_root_size = i;
	if (!vec_root_size)
		error(FATAL, "cannot determine tvec_root.vec[] array size\n");

        vec_size = (i = ARRAY_LENGTH(tvec_s_vec)) ?
                i : get_array_length("tvec_s.vec", NULL, SIZE(list_head));
	if (!vec_size &&
	    (i = get_array_length("tvec.vec", NULL, SIZE(list_head))))
		vec_size = i;
	if (!vec_size)
		error(FATAL, "cannot determine tvec.vec[] array size\n");

        vec = (ulong *)GETBUF(SIZE(list_head) * MAX(vec_root_size, vec_size));
	cpu = 0;

next_cpu:

	count = 0;
	td = (struct timer_data *)NULL;

	BZERO(tv, sizeof(struct tv_range) * TVN);

        init_tv_ranges(tv, vec_root_size, vec_size, cpu);

        count += do_timer_list(tv[1].base + OFFSET(tvec_root_s_vec),
                vec_root_size, vec, NULL, NULL, tv);
        count += do_timer_list(tv[2].base + OFFSET(tvec_s_vec),
                vec_size, vec, NULL, NULL, tv);
        count += do_timer_list(tv[3].base + OFFSET(tvec_s_vec),
                vec_size, vec, NULL, NULL, tv);
        count += do_timer_list(tv[4].base + OFFSET(tvec_s_vec),
                vec_size, vec, NULL, NULL, tv);
        count += do_timer_list(tv[5].base + OFFSET(tvec_s_vec),
                vec_size, vec, NULL, NULL, tv);

	if (count)
        	td = (struct timer_data *)
                	GETBUF((count*2) * sizeof(struct timer_data));
        tdx = 0;
	highest = 0;
        get_symbol_data("jiffies", sizeof(ulong), &jiffies);

        do_timer_list(tv[1].base + OFFSET(tvec_root_s_vec),
                vec_root_size, vec, (void *)td, &highest, tv);
        do_timer_list(tv[2].base + OFFSET(tvec_s_vec),
                vec_size, vec, (void *)td, &highest, tv);
        do_timer_list(tv[3].base + OFFSET(tvec_s_vec),
                vec_size, vec, (void *)td, &highest, tv);
        do_timer_list(tv[4].base + OFFSET(tvec_s_vec),
                vec_size, vec, (void *)td, &highest, tv);
        tdx = do_timer_list(tv[5].base + OFFSET(tvec_s_vec),
                vec_size, vec, (void *)td, &highest, tv);

        qsort(td, tdx, sizeof(struct timer_data), compare_timer_data);

        if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF))
                tvec_bases = symbol_value("per_cpu__tvec_bases") +
                        kt->__per_cpu_offset[cpu];
        else
                tvec_bases =  symbol_value("per_cpu__tvec_bases");

	if (symbol_exists("boot_tvec_bases")) {
		readmem(tvec_bases, KVADDR, &tvec_bases, sizeof(void *),
                        "per-cpu tvec_bases", FAULT_ON_ERROR);
        }

        fprintf(fp, "TVEC_BASES[%d]: %lx\n", cpu, tvec_bases);
		
        sprintf(buf1, "%ld", highest);
        flen = MAX(strlen(buf1), strlen("JIFFIES"));
        fprintf(fp, "%s\n", mkstring(buf1,flen, CENTER|RJUST, "JIFFIES"));
        fprintf(fp, "%s\n", mkstring(buf1,flen, 
		RJUST|LONG_DEC,MKSTR(jiffies)));

	fprintf(fp, "%s  %s  %s\n",
		mkstring(buf1, flen, CENTER|RJUST, "EXPIRES"),
		mkstring(buf2, VADDR_PRLEN, CENTER|LJUST, "TIMER_LIST"),
		mkstring(buf3, VADDR_PRLEN, CENTER|LJUST, "FUNCTION"));

        for (i = 0; i < tdx; i++) {
                fprintf(fp, "%s",
                    mkstring(buf1, flen, RJUST|LONG_DEC, MKSTR(td[i].expires)));

                fprintf(fp, "  %s  ", mkstring(buf1, 
			MAX(VADDR_PRLEN, strlen("TIMER_LIST")), 
			RJUST|CENTER|LONG_HEX, MKSTR(td[i].address)));

                if (is_kernel_text(td[i].function)) {
                        fprintf(fp, "%s  <%s>\n",
				mkstring(buf2, VADDR_PRLEN, RJUST|LONG_HEX,
				MKSTR(td[i].function)),
                                value_to_symstr(td[i].function, buf1, 0));
                } else {
                        fprintf(fp, "%s  ", mkstring(buf1, VADDR_PRLEN, 
				RJUST|LONG_HEX, MKSTR(td[i].function)));
                        if (readmem(td[i].function, KVADDR, &function,
                            sizeof(ulong), "timer function",
                            RETURN_ON_ERROR|QUIET)) {
                                if (is_kernel_text(function))
                                        fprintf(fp, "<%s>",
                                            value_to_symstr(function, buf1, 0));
                        }
                        fprintf(fp, "\n");
                }
        }

	if (td)
		FREEBUF(td);

	if (++cpu < kt->cpus)
		goto next_cpu;
}

/*
 *  The comparison function must return an integer less  than,
 *  equal  to,  or  greater than zero if the first argument is
 *  considered to be respectively  less  than,  equal  to,  or
 *  greater than the second.  If two members compare as equal,
 *  their order in the sorted array is undefined.
 */

static int
compare_timer_data(const void *v1, const void *v2)
{
        struct timer_data *t1, *t2;

        t1 = (struct timer_data *)v1;
        t2 = (struct timer_data *)v2;

	return (t1->expires < t2->expires ? -1 :
		t1->expires == t2->expires ? 0 : 1);
}

/*
 *  Create the address range for each of the timer vectors.
 */
static void
init_tv_ranges(struct tv_range *tv, int vec_root_size, int vec_size, int cpu)
{
	ulong tvec_bases;

	if (kt->flags & TVEC_BASES_V1) {
                tv[1].base = symbol_value("tvec_bases") +
			(SIZE(tvec_t_base_s) * cpu) +
			OFFSET(tvec_t_base_s_tv1);
                tv[1].end = tv[1].base + SIZE(tvec_root_s);

                tv[2].base = tv[1].end;
                tv[2].end = tv[2].base + SIZE(tvec_s);

                tv[3].base = tv[2].end;
                tv[3].end = tv[3].base + SIZE(tvec_s);

                tv[4].base = tv[3].end;
                tv[4].end = tv[4].base + SIZE(tvec_s);

                tv[5].base = tv[4].end;
                tv[5].end = tv[5].base + SIZE(tvec_s);
	} else if (kt->flags & TVEC_BASES_V2) {
		if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF)) 
			tvec_bases = symbol_value("per_cpu__tvec_bases") +
				kt->__per_cpu_offset[cpu];
		else		
			tvec_bases =  symbol_value("per_cpu__tvec_bases");

		if (symbol_exists("boot_tvec_bases")) {
			readmem(tvec_bases, KVADDR, &tvec_bases, sizeof(void *), 
				"per-cpu tvec_bases", FAULT_ON_ERROR);
		}

                tv[1].base = tvec_bases +
                        OFFSET(tvec_t_base_s_tv1);
                tv[1].end = tv[1].base + SIZE(tvec_root_s);

                tv[2].base = tv[1].end;
                tv[2].end = tv[2].base + SIZE(tvec_s);

                tv[3].base = tv[2].end;
                tv[3].end = tv[3].base + SIZE(tvec_s);

                tv[4].base = tv[3].end;
                tv[4].end = tv[4].base + SIZE(tvec_s);

                tv[5].base = tv[4].end;
                tv[5].end = tv[5].base + SIZE(tvec_s);
	} else {
		tv[1].base = symbol_value("tv1");
	        tv[1].end = tv[1].base + SIZE(timer_vec_root);
	
	        tv[2].base = symbol_value("tv2");
	        tv[2].end = tv[2].base + SIZE(timer_vec);
	
	        tv[3].base = symbol_value("tv3");
	        tv[3].end = tv[3].base + SIZE(timer_vec);
	
	        tv[4].base = symbol_value("tv4");
	        tv[4].end = tv[4].base + SIZE(timer_vec);
	
	        tv[5].base = symbol_value("tv5");
	        tv[5].end = tv[5].base + SIZE(timer_vec);
	}
}

#define IN_TV_RANGE(vaddr) \
	((((vaddr) >= tv[1].base) && ((vaddr) < tv[1].end)) || \
	 (((vaddr) >= tv[2].base) && ((vaddr) < tv[2].end)) || \
	 (((vaddr) >= tv[3].base) && ((vaddr) < tv[3].end)) || \
	 (((vaddr) >= tv[4].base) && ((vaddr) < tv[4].end)) || \
	 (((vaddr) >= tv[5].base) && ((vaddr) < tv[5].end)))

/*
 *  Count, or stash, the entries of a linked timer_list -- depending
 *  upon the option value.
 */
static int
do_timer_list(ulong vec_kvaddr,
	      int size, 
	      ulong *vec, 
	      void *option, 
	      ulong *highest,
	      struct tv_range *tv)
{
	int i, t; 
	int count, tdx;
	ulong expires, function;
	struct timer_data *td;
	char *timer_list_buf;
	ulong *timer_list;
	int timer_cnt;
        struct list_data list_data, *ld;
	long sz;
	ulong offset;

	tdx = 0;
	td = option ? (struct timer_data *)option : NULL;
	if (td) {
		while (td[tdx].function)
			tdx++;
	}

        if (VALID_MEMBER(timer_list_list))
		sz = SIZE(list_head) * size;
	else if (VALID_MEMBER(timer_list_entry))
		sz = SIZE(list_head) * size;
	else 
		sz = sizeof(ulong) * size;

        readmem(vec_kvaddr, KVADDR, vec, sz, "timer_list vec array",
                FAULT_ON_ERROR);

	if (VALID_MEMBER(timer_list_list)) {
		offset = OFFSET(timer_list_list);
		goto new_timer_list_format;
	}

	if (VALID_MEMBER(timer_list_entry)) {
		offset = OFFSET(timer_list_entry);
		goto new_timer_list_format;
	}

	if (VALID_MEMBER(timer_list_next) >= 0)
		offset = OFFSET(timer_list_next);
	else
		error(FATAL, "no timer_list next, list, or entry members?\n");

	ld = &list_data;
	timer_list_buf = GETBUF(SIZE(timer_list));

        for (i = count = 0; i < size; i++) {
                if (vec[i]) {
			BZERO(ld, sizeof(struct list_data));
			ld->start = vec[i];
			ld->member_offset = offset;

			hq_open();
                	timer_cnt = do_list(ld);
			if (!timer_cnt)
				continue;
                	timer_list = (ulong *)GETBUF(timer_cnt * sizeof(ulong));
                	timer_cnt = retrieve_list(timer_list, timer_cnt);
                	hq_close();

			for (t = 0; t < timer_cnt; t++) {
                                readmem(timer_list[t], KVADDR, timer_list_buf,
                                        SIZE(timer_list), "timer_list buffer",
                                        FAULT_ON_ERROR);

                                expires = ULONG(timer_list_buf +
                                        OFFSET(timer_list_expires));
                                function = ULONG(timer_list_buf +
                                        OFFSET(timer_list_function));

                                if (td) {
                                        td[tdx].address = timer_list[t];
                                        td[tdx].expires = expires;
                                        td[tdx].function = function;
                                        if (highest && (expires > *highest))
                                                *highest = expires;
                                        tdx++;
                                }
			}
			FREEBUF(timer_list);
			count += timer_cnt;
        	}
	}

	FREEBUF(timer_list_buf);

	return(td ? tdx : count);

new_timer_list_format:

	ld = &list_data;
	timer_list_buf = GETBUF(SIZE(timer_list));

        for (i = count = 0; i < (size*2); i += 2, 
	     vec_kvaddr += SIZE(list_head)) {

		if (vec[i] == vec_kvaddr)
			continue;

                BZERO(ld, sizeof(struct list_data));
                ld->start = vec[i];
                ld->list_head_offset = offset;
		ld->end = vec_kvaddr;
		ld->flags = RETURN_ON_LIST_ERROR;

                hq_open();
		if ((timer_cnt = do_list(ld)) == -1) {
			/* Ignore chains with errors */
			error(INFO, 
	      	      "ignoring faulty timer list at index %d of timer array\n",
				i/2);
			continue; 
		}
                if (!timer_cnt)
                	continue;
                timer_list = (ulong *)GETBUF(timer_cnt * sizeof(ulong));
                timer_cnt = retrieve_list(timer_list, timer_cnt);
                hq_close();

                for (t = 0; t < timer_cnt; t++) {
			if (IN_TV_RANGE(timer_list[t]))
				break;

			count++;

                        readmem(timer_list[t], KVADDR, timer_list_buf,
                                SIZE(timer_list), "timer_list buffer",
                                FAULT_ON_ERROR);

                        expires = ULONG(timer_list_buf + 
				OFFSET(timer_list_expires));
                        function = ULONG(timer_list_buf +
                        	OFFSET(timer_list_function));

                        if (td) {
                                td[tdx].address = timer_list[t];
                                td[tdx].expires = expires;
                                td[tdx].function = function;
                                if (highest && (expires > *highest))
                                        *highest = expires;
                                tdx++;
                        }
		}
	}

	FREEBUF(timer_list_buf);

	return(td ? tdx : count);
}

/*
 *  Panic a live system by exploiting this code in do_exit():
 *
 *      if (!tsk->pid)
 *              panic("Attempted to kill the idle task!");
 *
 *  by writing a zero to this task's pid number.  If the write
 *  succeeds, the subsequent exit() call will invoke the panic.
 */
static void
panic_this_kernel(void)
{
	pid_t zero_pid = 0;

	if (DUMPFILE())
		error(FATAL, "cannot panic a dumpfile!\n");

	if (!(pc->flags & MFD_RDWR) || (pc->flags & MEMMOD))
		error(FATAL, "cannot write to %s\n", pc->live_memsrc);

	writemem(pid_to_task(pc->program_pid) + OFFSET(task_struct_pid), KVADDR,
		&zero_pid, sizeof(pid_t), "zero pid", FAULT_ON_ERROR);

	clean_exit(0);
}

/*
 *  Dump the list of entries on a wait queue, taking into account the two
 *  different definitions: wait_queue vs. __wait_queue (wait_queue_t).
 */
void
cmd_waitq(void)
{
	ulong q = 0;
	char *wq_name = NULL;		/* name of symbol which is a waitq */
	char *wq_struct = NULL;		/* struct containing the waitq */
	char *wq_member = NULL;		/* member of struct which is a waitq */
	int recd_address = 0;

	if (argcnt < 2 || argcnt > 3) {
		cmd_usage(pc->curcmd, SYNOPSIS);
	}

	if (IS_A_NUMBER(args[1])) {
		q = htol(args[1], FAULT_ON_ERROR, NULL);
		recd_address = 1;
	} else {
		/*
		 * We weren't given a number... see if it is the name of
		 * a symbol or and struct.member format.
		 */
		char *dot;

		dot = strstr(args[1], ".");
		if (dot == NULL) {
			wq_name = args[1];
			q = symbol_value(wq_name);
		} else {

			wq_struct = args[1];
			wq_member = dot+1;
			*dot = '\0';
			if (argcnt != 3) {
				fprintf(fp, "must supply an address for %s\n",
					wq_struct);
				return;
			}
			q = htol(args[2], FAULT_ON_ERROR, NULL);
			if (MEMBER_OFFSET(wq_struct, wq_member) == -1) {
				fprintf(fp, "%s is not a member of %s\n",
					wq_member, wq_struct);
				return;
			}
			q += MEMBER_OFFSET(wq_struct, wq_member);
		}
	}

	if (q != 0 && IS_KVADDR(q)) {
		/*
		 * If we weren't passed in an address and we're dealing
		 * with old style wait_queue, we must dereference the pointer
		 * and pass in the addr of the first elem on the queue.
		 * If we were supplied an address, assume the user knows
		 * what should be provided.
		 */
		if (!recd_address && VALID_STRUCT(wait_queue)) {
			ulong first_elem;
			readmem(q, KVADDR, &first_elem, sizeof(q),
				"wait queue pointer", FAULT_ON_ERROR);
			if (first_elem == 0) {
				fprintf(fp, "wait queue %lx is empty\n", q);
				return;
			} else {
				q = first_elem;
			}
		}
		dump_waitq(q, wq_name);
	}
}

static void
dump_waitq(ulong wq, char *wq_name)
{
	struct list_data list_data, *ld;
	ulong *wq_list;			/* addr of wait queue element */
	ulong next_offset;		/* next pointer of wq element */
	ulong task_offset;		/* offset of task in wq element */
	int cnt;			/* # elems on Queue */
	int start_index;		/* where to start in wq array */
	int i;

	ld = &list_data;
	BZERO(ld, sizeof(*ld));

	/*
	 * setup list depending on how the wait queues are organized.
	 */
	if (VALID_STRUCT(wait_queue)) {
		task_offset = OFFSET(wait_queue_task);
		next_offset = OFFSET(wait_queue_next);
		ld->end = wq;
		ld->start = wq;
		ld->member_offset = next_offset;
		ld->list_head_offset = task_offset;

		start_index = 0;
	} else if (VALID_STRUCT(__wait_queue)) {
		ulong task_list_offset;

                next_offset = OFFSET(list_head_next);
                task_offset = OFFSET(__wait_queue_task);
                task_list_offset = OFFSET(__wait_queue_head_task_list);
                ld->end = ld->start = wq + task_list_offset + next_offset;
                ld->list_head_offset = OFFSET(__wait_queue_task_list);
                ld->member_offset = next_offset;

		start_index = 1;
	} else {
		return;
	}

	hq_open();

	cnt = do_list(ld);
	if (cnt <= 1) {
		/*
		 * Due to the queueing of wait queues, list count returns
		 * an extra number of list entries:
		 * - in the case of a wait_queue_head_t, there is the
		 *   the list_entry in that structure;
		 * - in the case of a simple wait_queue, we have the
		 *   pointer back to the wait_queue head (see the
		 *   WAIT_QUEUE_HEAD macro in 2.2 systems).
		 */
		if (wq_name)
			fprintf(fp, "wait queue \"%s\" (%lx) is empty\n", 
				wq_name, wq);
		else
			fprintf(fp, "wait queue %lx is empty\n", wq);
		hq_close();
		return;
	}

	wq_list = (ulong *) GETBUF(cnt * sizeof(ulong));
	cnt = retrieve_list(wq_list, cnt);

	for (i = start_index; i < cnt; i++) {
		struct task_context *tc;
		ulong task;

		readmem(wq_list[i] + task_offset, KVADDR, &task,
			sizeof(void *), "wait_queue_t.task", FAULT_ON_ERROR);

		if ((tc = task_to_context(task))) {
			print_task_header(fp, tc, 0);
		} else {
			break;
		}
	}

	hq_close();
}

/*
 *  If active, clear the references to the last page tables read.
 */
void
clear_machdep_cache(void)
{
	if (ACTIVE()) {
		machdep->last_pgd_read = 0;
		machdep->last_pmd_read = 0;
		machdep->last_ptbl_read = 0;
		if (machdep->clear_machdep_cache)
			machdep->clear_machdep_cache();
	}
}

/*
 *  If it exists, return the number of cpus in the cpu_online_map.
 */
int
get_cpus_online()
{
	int i, len, online;
	char *buf;
	ulong *maskptr, addr;

	if (!(addr = cpu_map_addr("online")))
		return 0;

	len = cpu_map_size("online");
	buf = GETBUF(len);

	online = 0;

        if (readmem(addr, KVADDR, buf, len, 
	    "cpu_online_map", RETURN_ON_ERROR)) {

		maskptr = (ulong *)buf;
		for (i = 0; i < (len/sizeof(ulong)); i++, maskptr++)
			online += count_bits_long(*maskptr);

		if (CRASHDEBUG(1))
			error(INFO, "get_cpus_online: online: %d\n", online);
	}

	FREEBUF(buf);

	return online;
}

/*
 *  If it exists, return the highest cpu number in the cpu_online_map.
 */
int
get_highest_cpu_online()
{
	int i, len;
	char *buf;
	ulong *maskptr, addr;
	int high, highest;

	if (!(addr = cpu_map_addr("online")))
		return -1;

	len = cpu_map_size("online");
	buf = GETBUF(len);
	highest = -1;

        if (readmem(addr, KVADDR, buf, len, 
	    "cpu_online_map", RETURN_ON_ERROR)) {

		maskptr = (ulong *)buf;
		for (i = 0; i < (len/sizeof(ulong)); i++, maskptr++) {
			if ((high = highest_bit_long(*maskptr)) < 0)
				continue;
			highest = high + (i * (sizeof(ulong)*8));
		}

		if (CRASHDEBUG(1))
			error(INFO, "get_highest_cpu_online: %d\n", highest);
	}

	FREEBUF(buf);

	return highest;
}

/*
 *  If it exists, return the number of cpus in the cpu_present_map.
 */
int
get_cpus_present()
{
	int i, len, present;
	char *buf;
	ulong *maskptr, addr;

	if (!(addr = cpu_map_addr("present"))) 
		return 0;

	len = cpu_map_size("present");
	buf = GETBUF(len);

	present = 0;

		if (readmem(addr, KVADDR, buf, len,
		    "cpu_present_map", RETURN_ON_ERROR)) {

		maskptr = (ulong *)buf;
		for (i = 0; i < (len/sizeof(ulong)); i++, maskptr++)
			present += count_bits_long(*maskptr);

		if (CRASHDEBUG(1))
			error(INFO, "get_cpus_present: present: %d\n", present);
	}

	FREEBUF(buf);

	return present;
}

/*
 *  If it exists, return the number of cpus in the cpu_possible_map.
 */
int
get_cpus_possible()
{
	int i, len, possible;
	char *buf;
	ulong *maskptr, addr;

	if (!(addr = cpu_map_addr("possible")))
		return 0;

	len = cpu_map_size("possible");
	buf = GETBUF(len);

	possible = 0;

	if (readmem(addr, KVADDR, buf, len,
		"cpu_possible_map", RETURN_ON_ERROR)) {

		maskptr = (ulong *)buf;
		for (i = 0; i < (len/sizeof(ulong)); i++, maskptr++)
			possible += count_bits_long(*maskptr);

		if (CRASHDEBUG(1))
			error(INFO, "get_cpus_possible: possible: %d\n",
				possible);
	}

	FREEBUF(buf);

	return possible;
}

/*
 *  Xen machine-address to pseudo-physical-page translator.
 */ 
ulonglong
xen_m2p(ulonglong machine)
{
	ulong mfn, pfn;

	mfn = XEN_MACHINE_TO_MFN(machine);
	pfn = __xen_m2p(machine, mfn);

	if (pfn == XEN_MFN_NOT_FOUND) {
		if (CRASHDEBUG(1))
			error(INFO, 
			    "xen_machine_to_pseudo_PAE: machine address %lx not found\n",
                           	 machine);
		return XEN_MACHADDR_NOT_FOUND;
	}

	return XEN_PFN_TO_PSEUDO(pfn);
}

static ulong
__xen_m2p(ulonglong machine, ulong mfn)
{
	ulong mapping, kmfn, pfn, p, i, c;
	ulong start, end;
	ulong *mp;

	mp = (ulong *)kt->m2p_page;
	mapping = kt->phys_to_machine_mapping;

	/*
	 *  Check the FIFO cache first.
	 */
	for (c = 0; c < P2M_MAPPING_CACHE; c++) {
		if (kt->p2m_mapping_cache[c].mapping &&
		    ((mfn >= kt->p2m_mapping_cache[c].start) && 
		     (mfn <= kt->p2m_mapping_cache[c].end))) { 

			if (kt->p2m_mapping_cache[c].mapping != kt->last_mapping_read) {
                        	if (!readmem(kt->p2m_mapping_cache[c].mapping, KVADDR, 
			       	    mp, PAGESIZE(), "phys_to_machine_mapping page (cached)", 
			    	    RETURN_ON_ERROR))
                                	error(FATAL, "cannot access "
                                    	    "phys_to_machine_mapping page\n");
				else
					kt->last_mapping_read = kt->p2m_mapping_cache[c].mapping;
			} else
				kt->p2m_page_cache_hits++;

                	for (i = 0; i < XEN_PFNS_PER_PAGE; i++) {
				kmfn = (*(mp+i)) & ~XEN_FOREIGN_FRAME;
                        	if (kmfn == mfn) {
					p = P2M_MAPPING_TO_PAGE_INDEX(c);
					pfn = p + i;

                                	if (CRASHDEBUG(1))
                                    	    console("(cached) mfn: %lx (%llx) p: %ld"
                                        	" i: %ld pfn: %lx (%llx)\n",
						mfn, machine, p,
						i, pfn, XEN_PFN_TO_PSEUDO(pfn));
					kt->p2m_mfn_cache_hits++;

					return pfn;
				}
			}
			/*
			 *  Stale entry -- clear it out.
			 */
			kt->p2m_mapping_cache[c].mapping = 0;
		}
	}

	/*
	 *  The machine address was not cached, so search from the
	 *  beginning of the phys_to_machine_mapping array, caching
	 *  only the found machine address.
	 */
	for (p = 0; p < kt->p2m_table_size; p += XEN_PFNS_PER_PAGE) 
	{
		if (mapping != kt->last_mapping_read) {
			if (!readmem(mapping, KVADDR, mp, PAGESIZE(), 
		    	    "phys_to_machine_mapping page", RETURN_ON_ERROR))
				error(FATAL, 
			     	    "cannot access phys_to_machine_mapping page\n");
			else
				kt->last_mapping_read = mapping;
		}

		kt->p2m_pages_searched++;

		if (search_mapping_page(mfn, &i, &start, &end)) {
			pfn = p + i;
			if (CRASHDEBUG(1))
			    console("pages: %d mfn: %lx (%llx) p: %ld"
				" i: %ld pfn: %lx (%llx)\n",
				(p/XEN_PFNS_PER_PAGE)+1, mfn, machine,
				p, i, pfn, XEN_PFN_TO_PSEUDO(pfn));

			c = kt->p2m_cache_index;
			kt->p2m_mapping_cache[c].start = start;
			kt->p2m_mapping_cache[c].end = end;
			kt->p2m_mapping_cache[c].mapping = mapping;
			kt->p2m_cache_index = (c+1) % P2M_MAPPING_CACHE;

			return pfn;
		}

		mapping += PAGESIZE();
	}

	if (CRASHDEBUG(1))
		console("machine address %llx not found\n", machine);

	return (XEN_MFN_NOT_FOUND);
}

/*
 *  Search for an mfn in the current mapping page, and if found, 
 *  determine the range of contiguous mfns that it's contained
 *  within (if any). 
 */
#define PREV_UP    0x1
#define NEXT_UP    0x2
#define PREV_DOWN  0x4
#define NEXT_DOWN  0x8

static int
search_mapping_page(ulong mfn, ulong *index, ulong *startptr, ulong *endptr)
{
	int n, found;
	ulong i, kmfn;
	ulong flags, start, end, next, prev, curr;
	ulong *mp;

	mp = (ulong *)kt->m2p_page;

	for (i = 0, found = FALSE; i < XEN_PFNS_PER_PAGE; i++) {
		kmfn = (*(mp+i)) & ~XEN_FOREIGN_FRAME;

		if (kmfn == mfn) {
			found = TRUE;
			*index = i;
			break;
		}
	}

	if (found) {
		flags = 0;
		next = prev = XEN_MFN_NOT_FOUND;
		start = end = kmfn;

		if (i)
			prev = (*(mp+(i-1))) & ~XEN_FOREIGN_FRAME;
		if ((i+1) != XEN_PFNS_PER_PAGE)
			next = (*(mp+(i+1))) & ~XEN_FOREIGN_FRAME;

		if (prev == (kmfn-1))
			flags |= PREV_UP;
		else if (prev == (kmfn+1))
			flags |= PREV_DOWN;

		if (next == (kmfn+1))
			flags |= NEXT_UP;
		else if (next == (kmfn-1))
			flags |= NEXT_DOWN;

		/*  Should be impossible, but just in case... */
		if ((flags & PREV_UP) && (flags & NEXT_DOWN))
			flags &= ~NEXT_DOWN;
		else if ((flags & PREV_DOWN) && (flags & NEXT_UP))
			flags &= ~NEXT_UP;

		if (flags & (PREV_UP|PREV_DOWN)) {
			start = prev;

			for (n = (i-2); n >= 0; n--) {
				curr = (*(mp+n)) & ~XEN_FOREIGN_FRAME;
				if (flags & PREV_UP) {
					if (curr == (start-1))
						start = curr;
				} else {
					if (curr == (start+1))
						start = curr;
				}
			}

		}

		if (flags & (NEXT_UP|NEXT_DOWN)) {
			end = next;

			for (n = (i+2); n < XEN_PFNS_PER_PAGE; n++) {
				curr = (*(mp+n)) & ~XEN_FOREIGN_FRAME;
				if (flags & NEXT_UP) {
					if (curr == (end+1))
						end = curr;
				} else {
					if (curr == (end-1))
						end = curr;
				}
			}


		}

		if (start > end) {
			curr = start;
			start = end;
			end = curr;	
		}

		*startptr = start;
		*endptr = end;

		if (CRASHDEBUG(2))
			fprintf(fp, "mfn: %lx -> start: %lx end: %lx (%ld mfns)\n", 
				mfn, start, end, end - start);
	}

	return found;
}



/*
 *  Read the relevant IKCONFIG (In Kernel Config) data if available.
 */

static char *ikconfig[] = {
        "CONFIG_NR_CPUS",
        "CONFIG_PGTABLE_4",
        "CONFIG_HZ",
	"CONFIG_DEBUG_BUGVERBOSE",
        NULL,
};

void
read_in_kernel_config(int command)
{
	struct syment *sp;
	int ii, jj, ret, end, found=0;
	unsigned long size, bufsz;
	char *pos, *ln, *buf, *head, *tail, *val, *uncomp;
	char line[512];
	z_stream stream;

	if ((kt->flags & NO_IKCONFIG) && !(pc->flags & RUNTIME))
		return;

	if ((sp = symbol_search("kernel_config_data")) == NULL) {
		if (command == IKCFG_READ)
			error(FATAL, 
			    "kernel_config_data does not exist in this kernel\n");
		return;
	}
	
	/* We don't know how large IKCONFIG is, so we start with 
	 * 32k, if we can't find MAGIC_END assume we didn't read 
	 * enough, double it and try again.
	 */
	ii = 32;

again:
	size = ii * 1024;

	if ((buf = (char *)malloc(size)) == NULL) {
		error(WARNING, "cannot malloc IKCONFIG input buffer\n");
		return;
	}
	
        if (!readmem(sp->value, KVADDR, buf, size,
            "kernel_config_data", RETURN_ON_ERROR)) {
		error(WARNING, "cannot read kernel_config_data\n");
		goto out2;
	}
		
	/* Find the start */
	if (strstr(buf, MAGIC_START))
		head = buf + MAGIC_SIZE + 10; /* skip past MAGIC_START and gzip header */
	else {
		error(WARNING, "could not find MAGIC_START!\n");
		goto out2;
	}

	tail = head;

	end = strlen(MAGIC_END);

	/* Find the end*/
	while (tail < (buf + (size - 1))) {
		
		if (strncmp(tail, MAGIC_END, end)==0) {
			found = 1;
			break;
		}
		tail++;
	}

	if (found) {
		bufsz = tail - head;
		size = 10 * bufsz;
		if ((uncomp = (char *)malloc(size)) == NULL) {
			error(WARNING, "cannot malloc IKCONFIG output buffer\n");
			goto out2;
		}
	} else {
		if (ii > 512) {
			error(WARNING, "could not find MAGIC_END!\n");
			goto out2;
		} else {
			free(buf);
			ii *= 2;
			goto again;
		}
	}


	/* initialize zlib */
	stream.next_in = (Bytef *)head;
	stream.avail_in = (uInt)bufsz;

	stream.next_out = (Bytef *)uncomp;
	stream.avail_out = (uInt)size;

	stream.zalloc = NULL;
	stream.zfree = NULL;
	stream.opaque = NULL;

	ret = inflateInit2(&stream, -MAX_WBITS);
	if (ret != Z_OK) {
		read_in_kernel_config_err(ret, "initialize");
		goto out1;
	}

	ret = inflate(&stream, Z_FINISH);

	if (ret != Z_STREAM_END) {
		inflateEnd(&stream);
		if (ret == Z_NEED_DICT || 
		   (ret == Z_BUF_ERROR && stream.avail_in == 0)) {
			read_in_kernel_config_err(Z_DATA_ERROR, "uncompress");
			goto out1;
		}
		read_in_kernel_config_err(ret, "uncompress");
		goto out1;
	}
	size = stream.total_out;

	ret = inflateEnd(&stream);

	pos = uncomp;

	do {
		ret = sscanf(pos, "%511[^\n]\n%n", line, &ii);
		if (ret > 0) {
			if ((command == IKCFG_READ) || CRASHDEBUG(8))
				fprintf(fp, "%s\n", line);

			pos += ii;

			ln = line;
				
			/* skip leading whitespace */
			while (whitespace(*ln))
				ln++;

			/* skip comments -- except when looking for "not set" */
			if (*ln == '#') {
				if (strstr(ln, "CONFIG_DEBUG_BUGVERBOSE") &&
				    strstr(ln, "not set"))
					kt->flags |= BUGVERBOSE_OFF;
				continue;
			}

			/* Find '=' */
			if ((head = strchr(ln, '=')) != NULL) {
				*head = '\0';
				val = head + 1;

				head--;

				/* skip trailing whitespace */
				while (whitespace(*head)) {
					*head = '\0';
					head--;
				}

				/* skip whitespace */
				while (whitespace(*val))
					val++;

			} else /* Bad line, skip it */
				continue;

			if (command != IKCFG_INIT)
				continue;

			for (jj = 0; ikconfig[jj]; jj++) {
				 if (STREQ(ln, ikconfig[jj])) {

					if (STREQ(ln, "CONFIG_NR_CPUS")) {
						kt->kernel_NR_CPUS = atoi(val);
						if (CRASHDEBUG(1)) 
							error(INFO, 
							    "CONFIG_NR_CPUS: %d\n",
								kt->kernel_NR_CPUS);

					} else if (STREQ(ln, "CONFIG_PGTABLE_4")) {
						machdep->flags |= VM_4_LEVEL;
						if (CRASHDEBUG(1))
							error(INFO, "CONFIG_PGTABLE_4\n");

					} else if (STREQ(ln, "CONFIG_HZ")) {
						machdep->hz = atoi(val);
						if (CRASHDEBUG(1))
							error(INFO, 
							    "CONFIG_HZ: %d\n",
								machdep->hz);
					}
				}
			}
		}
	} while (ret > 0);

out1:
	free(uncomp);
out2:
	free(buf);

	return;
}

static void
read_in_kernel_config_err(int e, char *msg)
{
	error(WARNING, "zlib could not %s\n", msg);
	switch (e) {
		case Z_OK:
			fprintf(fp, "Z_OK\n");
			break;

		case Z_STREAM_END:
			fprintf(fp, "Z_STREAM_END\n");
			break;

		case Z_NEED_DICT:
			fprintf(fp, "Z_NEED_DICT\n");
			break;
		
		case Z_ERRNO:
			fprintf(fp, "Z_ERNO\n");
			break;

		case Z_STREAM_ERROR:
			fprintf(fp, "Z_STREAM\n");
			break;

		case Z_DATA_ERROR: 
			fprintf(fp, "Z_DATA_ERROR\n");
			break;

		case Z_MEM_ERROR: /* out of memory */
			fprintf(fp, "Z_MEM_ERROR\n");
			break;

		case Z_BUF_ERROR: /* not enough room in output buf */
			fprintf(fp, "Z_BUF_ERROR\n");
			break;
		
		case Z_VERSION_ERROR:
			fprintf(fp, "Z_VERSION_ERROR\n");
			break;

		default: 
			fprintf(fp, "UNKNOWN ERROR: %d\n", e);
			break;
	}
}

/*
 *  With the evidence available, attempt to pre-determine whether
 *  this is a paravirt-capable kernel running as bare-metal, xen, 
 *  kvm, etc. 
 *
 *  NOTE: Only bare-metal pv_ops kernels are supported so far. 
 */
void
paravirt_init(void)
{
	/*
	 *  pv_init_ops appears to be (as of 2.6.27) an arch-common
	 *  symbol.  This may have to change.
	 */
	if (kernel_symbol_exists("pv_init_ops")) {
		if (CRASHDEBUG(1))
			error(INFO, "pv_init_ops exists: ARCH_PVOPS\n");
		kt->flags |= ARCH_PVOPS;
	}
}
