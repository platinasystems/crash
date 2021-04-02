/*
 *  xen_hyper.c
 *
 *  Portions Copyright (C) 2006 Fujitsu Limited
 *  Portions Copyright (C) 2006 VA Linux Systems Japan K.K.
 *
 *  This file is part of Xencrash.
 *
 *  Xencrash is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation (version 2 of the License).
 *
 *  Xencrash is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Xencrash; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA.
 */

#include "defs.h"

#ifdef XEN_HYPERVISOR_ARCH
#include "xen_hyper_defs.h"

/*
 * Do initialization for Xen Hyper system here.
 */
void
xen_hyper_init(void)
{
	char *buf;
	long member_offset;

	get_symbol_data("crashing_cpu", sizeof(xht->crashing_cpu),
		&xht->crashing_cpu);
	machdep->get_smp_cpus();
	machdep->memory_size();

	if (machine_type("X86") || machine_type("X86_64")) {
		member_offset = MEMBER_OFFSET("cpuinfo_x86", "x86_model_id");
		buf = GETBUF(XEN_HYPER_SIZE(cpuinfo_x86));	
		xen_hyper_fill_cpu_data_x86(xht->crashing_cpu, buf);
		strncpy(xht->utsname.machine, (char *)(buf + member_offset),
			sizeof(xht->utsname.machine)-1);
		FREEBUF(buf);
	}

	XEN_HYPER_STRUCT_SIZE_INIT(note_buf_t, "note_buf_t");
	XEN_HYPER_STRUCT_SIZE_INIT(crash_note_t, "crash_note_t");
	XEN_HYPER_MEMBER_OFFSET_INIT(crash_note_t_core, "crash_note_t", "core");
	XEN_HYPER_MEMBER_OFFSET_INIT(crash_note_t_xen, "crash_note_t", "xen");
	XEN_HYPER_MEMBER_OFFSET_INIT(crash_note_t_xen_regs, "crash_note_t", "xen_regs");
	XEN_HYPER_MEMBER_OFFSET_INIT(crash_note_t_xen_info, "crash_note_t", "xen_info");

	XEN_HYPER_STRUCT_SIZE_INIT(crash_note_core_t, "crash_note_core_t");
	XEN_HYPER_MEMBER_OFFSET_INIT(crash_note_core_t_note, "crash_note_core_t", "note");
	XEN_HYPER_MEMBER_OFFSET_INIT(crash_note_core_t_desc, "crash_note_core_t", "desc");

	XEN_HYPER_STRUCT_SIZE_INIT(crash_note_xen_t, "crash_note_xen_t");
	XEN_HYPER_MEMBER_OFFSET_INIT(crash_note_xen_t_note, "crash_note_xen_t", "note");
	XEN_HYPER_MEMBER_OFFSET_INIT(crash_note_xen_t_desc, "crash_note_xen_t", "desc");
	XEN_HYPER_STRUCT_SIZE_INIT(crash_note_xen_core_t, "crash_note_xen_core_t");
	XEN_HYPER_MEMBER_OFFSET_INIT(crash_note_xen_core_t_note, "crash_note_xen_core_t", "note");
	XEN_HYPER_MEMBER_OFFSET_INIT(crash_note_xen_core_t_desc, "crash_note_xen_core_t", "desc");
	XEN_HYPER_STRUCT_SIZE_INIT(crash_note_xen_info_t, "crash_note_xen_info_t");
	XEN_HYPER_MEMBER_OFFSET_INIT(crash_note_xen_info_t_note, "crash_note_xen_info_t", "note");
	XEN_HYPER_MEMBER_OFFSET_INIT(crash_note_xen_info_t_desc, "crash_note_xen_info_t", "desc");
	XEN_HYPER_STRUCT_SIZE_INIT(crash_xen_core_t, "crash_xen_core_t");
	XEN_HYPER_STRUCT_SIZE_INIT(crash_xen_info_t, "crash_xen_info_t");
	XEN_HYPER_STRUCT_SIZE_INIT(xen_crash_xen_regs_t, "xen_crash_xen_regs_t");

	XEN_HYPER_STRUCT_SIZE_INIT(ELF_Prstatus,"ELF_Prstatus");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_info, "ELF_Prstatus", "pr_info");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_cursig, "ELF_Prstatus", "pr_cursig");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_sigpend, "ELF_Prstatus", "pr_sigpend");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_sighold, "ELF_Prstatus", "pr_sighold");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_pid, "ELF_Prstatus", "pr_pid");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_ppid, "ELF_Prstatus", "pr_ppid");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_pgrp, "ELF_Prstatus", "pr_pgrp");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_sid, "ELF_Prstatus", "pr_sid");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_utime, "ELF_Prstatus", "pr_utime");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_stime, "ELF_Prstatus", "pr_stime");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_cutime, "ELF_Prstatus", "pr_cutime");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_cstime, "ELF_Prstatus", "pr_cstime");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_reg, "ELF_Prstatus", "pr_reg");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Prstatus_pr_fpvalid, "ELF_Prstatus", "pr_fpvalid");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Timeval_tv_sec, "ELF_Timeval", "tv_sec");
	XEN_HYPER_MEMBER_OFFSET_INIT(ELF_Timeval_tv_usec, "ELF_Timeval", "tv_usec");
	XEN_HYPER_STRUCT_SIZE_INIT(ELF_Signifo,"ELF_Signifo");
	XEN_HYPER_STRUCT_SIZE_INIT(ELF_Gregset,"ELF_Gregset");
	XEN_HYPER_STRUCT_SIZE_INIT(ELF_Timeval,"ELF_Timeval");
	XEN_HYPER_STRUCT_SIZE_INIT(domain, "domain");
	XEN_HYPER_STRUCT_SIZE_INIT(vcpu, "vcpu");
	XEN_HYPER_STRUCT_SIZE_INIT(cpu_info, "cpu_info");
	XEN_HYPER_STRUCT_SIZE_INIT(cpu_user_regs, "cpu_user_regs");

	xen_hyper_dumpinfo_init();
}

/*
 * Do initialization for Domain of Xen Hyper system here.
 */
void
xen_hyper_domain_init(void)
{
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_domain_id, "domain", "domain_id");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_tot_pages, "domain", "tot_pages");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_max_pages, "domain", "max_pages");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_xenheap_pages, "domain", "xenheap_pages");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_shared_info, "domain", "shared_info");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_sched_priv, "domain", "sched_priv");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_next_in_list, "domain", "next_in_list");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_domain_flags, "domain", "domain_flags");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_evtchn, "domain", "evtchn");
	XEN_HYPER_MEMBER_OFFSET_INIT(domain_vcpu, "domain", "vcpu");

	if((xhdt->domain_struct = malloc(XEN_HYPER_SIZE(domain))) == NULL) {
		error(FATAL, "cannot malloc domain struct space.\n");
	}
	if((xhdt->domain_struct_verify = malloc(XEN_HYPER_SIZE(domain))) == NULL) {
		error(FATAL, "cannot malloc domain struct space to verification.\n");
	}
	xen_hyper_refresh_domain_context_space();
	xhdt->flags |= XEN_HYPER_DOMAIN_F_INIT;
}

/*
 * Do initialization for vcpu of Xen Hyper system here.
 */
void
xen_hyper_vcpu_init(void)
{
	XEN_HYPER_STRUCT_SIZE_INIT(timer, "timer");
	XEN_HYPER_MEMBER_OFFSET_INIT(timer_expires, "timer", "expires");
	XEN_HYPER_MEMBER_OFFSET_INIT(timer_cpu, "timer", "cpu");
	XEN_HYPER_MEMBER_OFFSET_INIT(timer_function, "timer", "function");
	XEN_HYPER_MEMBER_OFFSET_INIT(timer_data, "timer", "data");
	XEN_HYPER_MEMBER_OFFSET_INIT(timer_heap_offset, "timer", "heap_offset");
	XEN_HYPER_MEMBER_OFFSET_INIT(timer_killed, "timer", "killed");

	XEN_HYPER_STRUCT_SIZE_INIT(vcpu_runstate_info, "vcpu_runstate_info");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_runstate_info_state, "vcpu_runstate_info", "state");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_runstate_info_state_entry_time, "vcpu_runstate_info", "state_entry_time");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_runstate_info_time, "vcpu_runstate_info", "time");

	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_vcpu_id, "vcpu", "vcpu_id");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_processor, "vcpu", "processor");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_vcpu_info, "vcpu", "vcpu_info");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_domain, "vcpu", "domain");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_next_in_list, "vcpu", "next_in_list");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_timer, "vcpu", "timer");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_sleep_tick, "vcpu", "sleep_tick");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_poll_timer, "vcpu", "poll_timer");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_sched_priv, "vcpu", "sched_priv");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_runstate, "vcpu", "runstate");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_runstate_guest, "vcpu", "runstate_guest");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_vcpu_flags, "vcpu", "vcpu_flags");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_pause_count, "vcpu", "pause_count");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_virq_to_evtchn, "vcpu", "virq_to_evtchn");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_cpu_affinity, "vcpu", "cpu_affinity");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_nmi_addr, "vcpu", "nmi_addr");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_vcpu_dirty_cpumask, "vcpu", "vcpu_dirty_cpumask");
	XEN_HYPER_MEMBER_OFFSET_INIT(vcpu_arch, "vcpu", "arch");

	if((xhvct->vcpu_struct = malloc(XEN_HYPER_SIZE(vcpu))) == NULL) {
		error(FATAL, "cannot malloc vcpu struct space.\n");
	}
	if((xhvct->vcpu_struct_verify = malloc(XEN_HYPER_SIZE(vcpu))) == NULL) {
		error(FATAL, "cannot malloc vcpu struct space to verification.\n");
	}

	xen_hyper_refresh_vcpu_context_space();
	xhvct->flags |= XEN_HYPER_VCPU_F_INIT;
	xhvct->idle_vcpu = symbol_value("idle_vcpu");
}

/*
 * Do initialization for pcpu of Xen Hyper system here.
 */
void
x86_xen_hyper_pcpu_init(void)
{
	ulong cpu_info;
	ulong init_tss_base, init_tss;
	long sp;
	struct xen_hyper_pcpu_context *pcc;
	char *buf, *bp;
	int i, cpuid;

	XEN_HYPER_MEMBER_OFFSET_INIT(cpu_info_guest_cpu_user_regs, "cpu_info", "guest_cpu_user_regs");
	XEN_HYPER_MEMBER_OFFSET_INIT(cpu_info_processor_id, "cpu_info", "processor_id");
	XEN_HYPER_MEMBER_OFFSET_INIT(cpu_info_current_vcpu, "cpu_info", "current_vcpu");

	if((xhpct->pcpu_struct = malloc(XEN_HYPER_SIZE(cpu_info))) == NULL) {
		error(FATAL, "cannot malloc pcpu struct space.\n");
	}

	/* get physical cpu context */
	xen_hyper_alloc_pcpu_context_space(XEN_HYPER_MAX_CPUS());
	init_tss_base = symbol_value("init_tss");
	buf = GETBUF(XEN_HYPER_SIZE(tss_struct));	
	for_cpu_indexes(i, cpuid)
	{
		init_tss = init_tss_base + XEN_HYPER_SIZE(tss_struct) * cpuid;
		if (!readmem(init_tss, KVADDR, buf,
			XEN_HYPER_SIZE(tss_struct), "init_tss", RETURN_ON_ERROR)) {
			error(FATAL, "cannot read init_tss.\n");
		}
		if (machine_type("X86")) {
			sp = ULONG(buf + XEN_HYPER_OFFSET(tss_struct_esp0));
		} else if (machine_type("X86_64")) {
			sp = ULONG(buf + XEN_HYPER_OFFSET(tss_struct_rsp0));
		}
		cpu_info = XEN_HYPER_GET_CPU_INFO(sp);
		if (CRASHDEBUG(1)) {
			fprintf(fp, "sp=%lx, cpu_info=%lx\n", sp, cpu_info);
		}
		if(!(bp = xen_hyper_read_pcpu(cpu_info))) {
			error(FATAL, "cannot read cpu_info.\n");
		}
		pcc = &xhpct->context_array[cpuid];
		xen_hyper_store_pcpu_context(pcc, cpu_info, bp);
	}
	FREEBUF(buf);
}

/*
 * This should be called after all initailize process finished.
 */
void
xen_hyper_post_init(void)
{
	/* set pcpu last */
	if (!(xhpct->last =
		xen_hyper_id_to_pcpu_context(xht->crashing_cpu))) {
		xhpct->last = &xhpct->context_array[xht->cpu_idxs[0]];
	}

	/* set vcpu last */
	if (xhpct->last) {
		xhvct->last =
			xen_hyper_vcpu_to_vcpu_context(xhpct->last->current_vcpu);
		/* set crashing vcpu */
		xht->crashing_vcc = xhvct->last;
	}
	if (!xhvct->last) {
		xhvct->last = xhvct->vcpu_context_arrays->context_array;
	}

	/* set domain last */
	if (xhvct->last) {
		xhdt->last =
			xen_hyper_domain_to_domain_context(xhvct->last->domain);
	}
	if (!xhdt->last) {
		xhdt->last = xhdt->context_array;
	}
}

/*
 * Do initialization for dump information header here.
 */
void
xen_hyper_dumpinfo_init(void)
{
	Elf32_Nhdr *note;
	char *buf, *bp, *np, *upp;
	ulong addr;
	long size;
	int i, cpuid;

	/*
	 * kakuma NOTE: It is not clear that what ikind of
	 * a elf note format each one of the xen uses.
	 * So, we decide it confirming whether a symbol exists.
	 */
	if (STRUCT_EXISTS("note_buf_t"))
		xhdit->note_ver = XEN_HYPER_ELF_NOTE_V1;
	else if (STRUCT_EXISTS("crash_note_xen_t"))
		xhdit->note_ver = XEN_HYPER_ELF_NOTE_V2;
	else if (STRUCT_EXISTS("crash_note_xen_core_t"))
		xhdit->note_ver = XEN_HYPER_ELF_NOTE_V3;
	else {
		error(WARNING, "unsupported elf note format.\n");
		return;
	}

	size = sizeof(struct xen_hyper_dumpinfo_context) * XEN_HYPER_MAX_CPUS();
	if((xhdit->context_array = malloc(size)) == NULL) {
		error(FATAL, "cannot malloc dumpinfo table context space.\n");
	}
	BZERO(xhdit->context_array, size);
	addr = symbol_value("per_cpu__crash_notes");
	for (i = 0; i < XEN_HYPER_MAX_CPUS(); i++) {
		xhdit->context_array[i].note = xen_hyper_per_cpu(addr, i);
	}

	if (xhdit->note_ver == XEN_HYPER_ELF_NOTE_V1) {
		xhdit->note_size = XEN_HYPER_SIZE(note_buf_t);
	} else {
		xhdit->note_size = XEN_HYPER_SIZE(crash_note_t);
	}
		
	/* read a sample note */
	buf = GETBUF(xhdit->note_size);
	if (!xen_hyper_fill_elf_notes(xhdit->context_array[xht->crashing_cpu].note,
	buf, XEN_HYPER_ELF_NOTE_FILL_T_NOTE)) {
		error(FATAL, "cannot read per_cpu__crash_notes.\n");
	}
	bp = buf;

	switch (xhdit->note_ver) {
	case XEN_HYPER_ELF_NOTE_V1:
		/* core data */
		note = (Elf32_Nhdr *)bp;
		np = bp + sizeof(Elf32_Nhdr);
		upp = np + note->n_namesz;
		upp = (char *)roundup((ulong)upp, 4);
		xhdit->core_offset = (Elf_Word)((ulong)upp - (ulong)note);
		note = (Elf32_Nhdr *)(upp + note->n_descsz);
		/* cr3 data */
		np = (char *)note + sizeof(Elf32_Nhdr);
		upp = np + note->n_namesz;
		upp = (char *)roundup((ulong)upp, 4);
		upp = upp + note->n_descsz;
		xhdit->core_size = upp - bp;
		break;
	case XEN_HYPER_ELF_NOTE_V2:
		/* core data */
		xhdit->core_offset = XEN_HYPER_OFFSET(crash_note_core_t_desc);
		xhdit->core_size = XEN_HYPER_SIZE(crash_note_core_t);
		/* xen core */
		xhdit->xen_info_offset = XEN_HYPER_OFFSET(crash_note_xen_t_desc);
		xhdit->xen_info_size = XEN_HYPER_SIZE(crash_note_xen_t);
		if((xhdit->crash_note_xen_info_ptr =
		malloc(xhdit->xen_info_size)) == NULL) {
			error(FATAL, "cannot malloc dumpinfo table "
				"crash_note_xen_info_ptr space.\n");
		}
		memcpy(xhdit->crash_note_xen_info_ptr,
			bp + xhdit->core_size, xhdit->xen_info_size);
		xhdit->context_xen_info.note =
			xhdit->context_array[xht->crashing_cpu].note +
			xhdit->core_size;
		xhdit->context_xen_info.pcpu_id = xht->crashing_cpu;
		xhdit->context_xen_info.crash_xen_info_ptr =
			xhdit->crash_note_xen_info_ptr + xhdit->xen_info_offset;
		break;
	case XEN_HYPER_ELF_NOTE_V3:
		/* core data */
		xhdit->core_offset = XEN_HYPER_OFFSET(crash_note_core_t_desc);
		xhdit->core_size = XEN_HYPER_SIZE(crash_note_core_t);
		/* xen core */
		xhdit->xen_core_offset = XEN_HYPER_OFFSET(crash_note_xen_core_t_desc);
		xhdit->xen_core_size = XEN_HYPER_SIZE(crash_note_xen_core_t);
		if((xhdit->crash_note_xen_core_ptr =
		malloc(xhdit->xen_core_size)) == NULL) {
			error(FATAL, "cannot malloc dumpinfo table "
				"crash_note_xen_core_ptr space.\n");
		}
		memcpy(xhdit->crash_note_xen_core_ptr,
			bp + xhdit->core_size, xhdit->xen_core_size);
		xhdit->context_xen_core.note =
			xhdit->context_array[xht->crashing_cpu].note +
			xhdit->core_size;
		xhdit->context_xen_core.pcpu_id = xht->crashing_cpu;
		xhdit->context_xen_core.crash_xen_core_ptr =
			xhdit->crash_note_xen_core_ptr + xhdit->xen_core_offset;
		/* xen info */
		xhdit->xen_info_offset = XEN_HYPER_OFFSET(crash_note_xen_info_t_desc);
		xhdit->xen_info_size = XEN_HYPER_SIZE(crash_note_xen_info_t);
		if((xhdit->crash_note_xen_info_ptr =
		malloc(xhdit->xen_info_size)) == NULL) {
			error(FATAL, "cannot malloc dumpinfo table "
				"crash_note_xen_info_ptr space.\n");
		}
		memcpy(xhdit->crash_note_xen_info_ptr,
			bp + xhdit->core_size + xhdit->xen_core_size,
			xhdit->xen_info_size);
		xhdit->context_xen_info.note =
			xhdit->context_array[xht->crashing_cpu].note +
			xhdit->core_size + xhdit->xen_core_size;
		xhdit->context_xen_info.pcpu_id = xht->crashing_cpu;
		xhdit->context_xen_info.crash_xen_info_ptr =
			xhdit->crash_note_xen_info_ptr + xhdit->xen_info_offset;
		break;
	default:
		error(FATAL, "logic error in cheking elf note format occurs.\n");
	}

	size = xhdit->core_size * XEN_HYPER_MAX_PCPUS();
	if(!(xhdit->crash_note_core_array = malloc(size))) {
		error(FATAL, "cannot malloc note_buf_t struct space.\n");
	}
	bp = xhdit->crash_note_core_array;
	BZERO(bp, size);
	for_cpu_indexes(i, cpuid)
	{
		addr = xhdit->context_array[cpuid].note;
		if (!xen_hyper_fill_elf_notes(addr, bp,
		XEN_HYPER_ELF_NOTE_FILL_T_CORE)) {
			error(FATAL, "cannot read ELF_Prstatus.\n");
		}
		xhdit->context_array[cpuid].pcpu_id = cpuid;
		xhdit->context_array[cpuid].ELF_Prstatus_ptr =
			bp + xhdit->core_offset;
		xhdit->context_array[cpuid].pr_reg_ptr =
			bp + xhdit->core_offset +
			XEN_HYPER_OFFSET(ELF_Prstatus_pr_reg);
		bp += xhdit->core_size;
	}
	FREEBUF(buf);
}

/*
 * Get dump information context from physical cpu id.
 */
struct xen_hyper_dumpinfo_context *
xen_hyper_id_to_dumpinfo_context(uint id)
{
	return &xhdit->context_array[id];
}

/*
 * Get dump information context from ELF Note address.
 */
struct xen_hyper_dumpinfo_context *
xen_hyper_note_to_dumpinfo_context(ulong note)
{
	int i;

	for (i = 0; i < XEN_HYPER_MAX_CPUS(); i++) {
		if (note == xhdit->context_array[i].note) {
			return &xhdit->context_array[i];
		}
	}
	return NULL;
}

/*
 * Fill ELF Notes header here.
 */
char *
xen_hyper_fill_elf_notes(ulong note, char *note_buf, int type)
{
	long size;

	if (type == XEN_HYPER_ELF_NOTE_FILL_T_NOTE)
		size = xhdit->note_size;
	else if (type == XEN_HYPER_ELF_NOTE_FILL_T_CORE)
		size = xhdit->core_size;
	else if (type == XEN_HYPER_ELF_NOTE_FILL_T_XEN_CORE)
		size = xhdit->xen_core_size;
	else if (type == XEN_HYPER_ELF_NOTE_FILL_T_PRS)
		size = XEN_HYPER_SIZE(ELF_Prstatus);
	else if (type == XEN_HYPER_ELF_NOTE_FILL_T_XEN_REGS)
		size = XEN_HYPER_SIZE(xen_crash_xen_regs_t);
	else
		return NULL;

	if (!readmem(note, KVADDR, note_buf, size,
		"note_buf_t or crash_note_t", RETURN_ON_ERROR)) {
		if (type == XEN_HYPER_ELF_NOTE_FILL_T_NOTE)
			error(WARNING, "cannot fill note_buf_t or crash_note_t.\n");
		else if (type == XEN_HYPER_ELF_NOTE_FILL_T_CORE)
			error(WARNING, "cannot fill note core.\n");
		else if (type == XEN_HYPER_ELF_NOTE_FILL_T_XEN_CORE)
			error(WARNING, "cannot fill note xen core.\n");
		else if (type == XEN_HYPER_ELF_NOTE_FILL_T_PRS)
			error(WARNING, "cannot fill ELF_Prstatus.\n");
		else if (type == XEN_HYPER_ELF_NOTE_FILL_T_XEN_REGS)
			error(WARNING, "cannot fill xen_crash_xen_regs_t.\n");
		return NULL;
	}
	return note_buf;
}



/*
 * Get domain status.
 */
ulong
xen_hyper_domain_state(struct xen_hyper_domain_context *dc)
{
	if (ACTIVE()) {
		if (xen_hyper_read_domain_verify(dc->domain) == NULL) {
			return XEN_HYPER_DOMF_ERROR;
		}
	}
	return dc->domain_flags;
}

/*
 * Allocate domain context space.
 */
void
xen_hyper_refresh_domain_context_space(void)
{
	char *domain_struct;
	ulong domain, next, idle_vcpu;
	struct xen_hyper_domain_context *dc;
	struct xen_hyper_domain_context *dom0;

	if ((xhdt->flags & XEN_HYPER_DOMAIN_F_INIT) && !ACTIVE()) {
		return;
	}

	XEN_HYPER_RUNNING_DOMAINS() = XEN_HYPER_MAX_DOMAINS() =
		xen_hyper_get_domains();
	xen_hyper_alloc_domain_context_space(XEN_HYPER_MAX_DOMAINS());

	dc = xhdt->context_array;
	/* restore an idle domain context. */
	get_symbol_data("idle_vcpu", sizeof(idle_vcpu), &idle_vcpu);
	if (!readmem(idle_vcpu + MEMBER_OFFSET("vcpu", "domain"),
		KVADDR, &domain, sizeof(domain), "domain", RETURN_ON_ERROR)) {
		error(WARNING, "cannot read domain member in vcpu.\n");
	}
	if (CRASHDEBUG(1)) {
		fprintf(fp, "idle_vcpu=%lx, domain=%lx\n", idle_vcpu, domain);
	}
	if ((domain_struct = xen_hyper_read_domain(domain)) == NULL) {
		error(FATAL, "cannot read idle domain.\n");
	}
	xen_hyper_store_domain_context(dc, domain, domain_struct);
	xhdt->idle_domain = dc;
	dc++;

	/* restore domain contexts from dom0 symbol. */
	xen_hyper_get_domain_next(XEN_HYPER_DOMAIN_READ_DOM0, &next);
	domain = next;
	dom0 = dc;
	while((domain_struct =
	xen_hyper_get_domain_next(XEN_HYPER_DOMAIN_READ_NEXT, &next)) != NULL) {
		xen_hyper_store_domain_context(dc, domain, domain_struct);
		domain = next;
		dc++;
	}
	xhdt->dom0 = dom0;
}

/*
 * Get number of domain.
 */
int
xen_hyper_get_domains(void)
{
	ulong domain, next_in_list;
	long domain_next_in_list;
	int i;

	get_symbol_data("dom0", sizeof(void *), &domain);
	domain_next_in_list = MEMBER_OFFSET("domain", "next_in_list");
	i = 0;
	while (domain != 0) {
		i++;
		next_in_list = domain + domain_next_in_list;
		if (!readmem(next_in_list, KVADDR, &domain, sizeof(void *),
			"domain.next_in_list", RETURN_ON_ERROR)) {
			error(FATAL, "cannot read domain.next_in_list.\n");
		}
	}
	i++;					/* for idle domain */
	return i;
}

/*
 * Get next domain struct.
 * 	mod - XEN_HYPER_DOMAIN_READ_DOM0:start from dom0 symbol
 * 	    - XEN_HYPER_DOMAIN_READ_INIT:start from xhdt->context_array
 * 	    - XEN_HYPER_DOMAIN_READ_NEXT:next
 */
char *
xen_hyper_get_domain_next(int mod, ulong *next)
{
	static int idx = 0;

	char *domain_struct;
	struct xen_hyper_domain_context *dc;

	switch (mod) {
	case XEN_HYPER_DOMAIN_READ_DOM0:
		/* Case of search from dom0 symbol. */
		idx = 0;
		if (xhdt->dom0) {
			*next = xhdt->dom0->domain;
		} else {
			get_symbol_data("dom0", sizeof(void *), next);
		}
		return xhdt->domain_struct;
		break;
	case XEN_HYPER_DOMAIN_READ_INIT:
		/* Case of search from context_array. */
		if (xhdt->context_array && xhdt->context_array->domain) {
			idx = 1; 		/* this has a next index. */
			*next = xhdt->context_array->domain;
		} else {
			idx = 0;
			*next = 0;
			return NULL;
		}
		return xhdt->domain_struct;
		break;
	case XEN_HYPER_DOMAIN_READ_NEXT:
		break;
	default :
		error(FATAL, "xen_hyper_get_domain_next mod error: %d\n", mod);
		return NULL;
	}

	/* Finished search */
	if (!*next) {
		return NULL;
	}

	domain_struct = NULL;
	/* Is domain context array valid? */
	if (idx) {
		if ((domain_struct =
			xen_hyper_read_domain(*next)) == NULL) {
			error(FATAL, "cannot get next domain from domain context array.\n");
		}
		if (idx > XEN_HYPER_MAX_DOMAINS()) {
			*next = 0;
		} else {
			dc = xhdt->context_array;
			dc += idx;
			*next = dc->domain;
			idx++;
		}
		return domain_struct;
	}

	/* Search from dom0 symbol. */
	if ((domain_struct =
		xen_hyper_read_domain(*next)) == NULL) {
		error(FATAL, "cannot get next domain from dom0 symbol.\n");
	}
	*next = ULONG(domain_struct + XEN_HYPER_OFFSET(domain_next_in_list));
	return domain_struct;
}

/*
 * from domain address to id.
 */
domid_t
xen_hyper_domain_to_id(ulong domain)
{
	struct xen_hyper_domain_context *dc;

	/* Is domain context array valid? */
	if (xhdt->context_array && xhdt->context_array->domain) {
		if ((dc = xen_hyper_domain_to_domain_context(domain)) == NULL) {
			return XEN_HYPER_DOMAIN_ID_INVALID;
		} else {
			return dc->domain_id;
		}
	} else {
		return XEN_HYPER_DOMAIN_ID_INVALID;
	}
}

/*
 * Get domain struct from id.
 */
char *
xen_hyper_id_to_domain_struct(domid_t id)
{
	char *domain_struct;
	struct xen_hyper_domain_context *dc;

	domain_struct = NULL;

	/* Is domain context array valid? */
	if (xhdt->context_array && xhdt->context_array->domain) {
		if ((dc = xen_hyper_id_to_domain_context(id)) == NULL) {
			return NULL;
		} else {
			if ((domain_struct =
				xen_hyper_read_domain(dc->domain)) == NULL) {
				error(FATAL, "cannot get domain from domain context array with id.\n");
			}
			return domain_struct;
		}
	} else {
		return NULL;
	}
}

/*
 * Get domain context from domain address.
 */
struct xen_hyper_domain_context *
xen_hyper_domain_to_domain_context(ulong domain)
{
	struct xen_hyper_domain_context *dc;
	int i;

	if (xhdt->context_array == NULL ||
		xhdt->context_array->domain == 0) {
		return NULL;
	}
	if (!domain) {
		return NULL;
	}
	for (i = 0, dc = xhdt->context_array; i < XEN_HYPER_MAX_DOMAINS();
		i++, dc++) {
		if (domain == dc->domain) {
			return dc;
		}
	}
	return NULL;
}

/*
 * Get domain context from domain id.
 */
struct xen_hyper_domain_context *
xen_hyper_id_to_domain_context(domid_t id)
{
	struct xen_hyper_domain_context *dc;
	int i;

	if (xhdt->context_array == NULL ||
		xhdt->context_array->domain == 0) {
		return NULL;
	}
	if (id == XEN_HYPER_DOMAIN_ID_INVALID) {
		return NULL;
	}
	for (i = 0, dc = xhdt->context_array; i < XEN_HYPER_MAX_DOMAINS();
		i++, dc++) {
		if (id == dc->domain_id) {
			return dc;
		}
	}
	return NULL;
}

/*
 * Store domain struct contents.
 */
struct xen_hyper_domain_context *
xen_hyper_store_domain_context(struct xen_hyper_domain_context *dc,
	       ulong domain, char *dp)
{
	int i;

	dc->domain = domain;
	BCOPY((char *)(dp + XEN_HYPER_OFFSET(domain_domain_id)),
		&dc->domain_id, sizeof(domid_t));
	dc->tot_pages = UINT(dp + XEN_HYPER_OFFSET(domain_tot_pages));
	dc->max_pages = UINT(dp + XEN_HYPER_OFFSET(domain_max_pages));
	dc->xenheap_pages = UINT(dp + XEN_HYPER_OFFSET(domain_xenheap_pages));
	dc->shared_info = ULONG(dp + XEN_HYPER_OFFSET(domain_shared_info));
	dc->sched_priv = ULONG(dp + XEN_HYPER_OFFSET(domain_sched_priv));
	dc->next_in_list = ULONG(dp + XEN_HYPER_OFFSET(domain_next_in_list));
	dc->domain_flags = ULONG(dp + XEN_HYPER_OFFSET(domain_domain_flags));
	dc->evtchn = ULONG(dp + XEN_HYPER_OFFSET(domain_evtchn));
	for (i = 0; i < XEN_HYPER_MAX_VIRT_CPUS; i++) {
		dc->vcpu[i] = ULONG(dp + XEN_HYPER_OFFSET(domain_vcpu) + i*sizeof(void *));
		if (dc->vcpu[i])	XEN_HYPER_MAX_VCPUS(dc)++;
	}

	return dc;
}

/*
 * Read domain struct from domain context.
 */
char *
xen_hyper_read_domain_from_context(struct xen_hyper_domain_context *dc)
{
	return xen_hyper_fill_domain_struct(dc->domain, xhdt->domain_struct);
}

/*
 * Read domain struct.
 */
char *
xen_hyper_read_domain(ulong domain)
{
	return xen_hyper_fill_domain_struct(domain, xhdt->domain_struct);
}

/*
 * Read domain struct to verification.
 */
char *
xen_hyper_read_domain_verify(ulong domain)
{
	return xen_hyper_fill_domain_struct(domain, xhdt->domain_struct_verify);
}

/*
 * Fill domain struct.
 */
char *
xen_hyper_fill_domain_struct(ulong domain, char *domain_struct)
{
	if (!readmem(domain, KVADDR, domain_struct,
		XEN_HYPER_SIZE(domain), "fill_domain_struct",
	       	ACTIVE() ? (RETURN_ON_ERROR|QUIET) : RETURN_ON_ERROR)) {
		error(WARNING, "cannot fill domain struct.\n");
		return NULL;
	}
	return domain_struct;
}

/*
 * Allocate domain context space.
 */
void
xen_hyper_alloc_domain_context_space(int domains)
{
	if (xhdt->context_array == NULL) {
		if (!(xhdt->context_array =
			malloc(domains * sizeof(struct xen_hyper_domain_context)))) {
			error(FATAL, "cannot malloc context array (%d domains).",
				domains);
		}
		xhdt->context_array_cnt = domains;
	} else if (domains > xhdt->context_array_cnt) {
		if (!(xhdt->context_array =
			realloc(xhdt->context_array,
				domains * sizeof(struct xen_hyper_domain_context)))) {
			error(FATAL, "cannot realloc context array (%d domains).",
				domains);
		}
		xhdt->context_array_cnt = domains;
	}
	BZERO(xhdt->context_array,
		domains * sizeof(struct xen_hyper_domain_context));
}



/*
 * Get vcpu status.
 */
int
xen_hyper_vcpu_state(struct xen_hyper_vcpu_context *vcc)
{
	if (ACTIVE()) {
		if (xen_hyper_read_vcpu_verify(vcc->vcpu) == NULL) {
			return XEN_HYPER_RUNSTATE_ERROR;
		}
	}
	return vcc->state;
}

/*
 * Allocate vcpu context space.
 */
void
xen_hyper_refresh_vcpu_context_space(void)
{
	struct xen_hyper_domain_context *dc;
	struct xen_hyper_vcpu_context_array *vcca;
	struct xen_hyper_vcpu_context *vcc;
	int i, j;

	if ((xhvct->flags & XEN_HYPER_VCPU_F_INIT) && !ACTIVE()) {
		return;
	}

	xen_hyper_alloc_vcpu_context_arrays_space(XEN_HYPER_MAX_DOMAINS());
	for (i = 0, xht->vcpus = 0, dc = xhdt->context_array,
	vcca = xhvct->vcpu_context_arrays;
	i < XEN_HYPER_MAX_DOMAINS(); i++, dc++, vcca++) {
		dc->vcpu_context_array = vcca;
		xen_hyper_alloc_vcpu_context_space(vcca,
			XEN_HYPER_MAX_VCPUS(dc));
		for (j = 0, vcc = vcca->context_array;
		j < XEN_HYPER_MAX_VCPUS(dc); j++, vcc++) {
			xen_hyper_read_vcpu(dc->vcpu[j]);
			xen_hyper_store_vcpu_context(vcc, dc->vcpu[j],
				xhvct->vcpu_struct);	
		}
		if (dc == xhdt->idle_domain) {
			xhvct->idle_vcpu_context_array = vcca;
		}
		xht->vcpus += vcca->context_array_cnt;
	}
}

/*
 * Get vcpu context from vcpu address.
 */
struct xen_hyper_vcpu_context *
xen_hyper_vcpu_to_vcpu_context(ulong vcpu)
{
	struct xen_hyper_vcpu_context_array *vcca;
	struct xen_hyper_vcpu_context *vcc;
	int i, j;

	if (!vcpu) {
		return NULL;
	}
	for (i = 0, vcca = xhvct->vcpu_context_arrays;
		i < xhvct->vcpu_context_arrays_cnt; i++, vcca++) {
		for (j = 0, vcc = vcca->context_array;
			j < vcca->context_array_cnt; j++, vcc++) {
			if (vcpu == vcc->vcpu) {
				return vcc;
			}
		}
	}
	return NULL;
}

/*
 * Get vcpu context.
 */
struct xen_hyper_vcpu_context *
xen_hyper_id_to_vcpu_context(ulong domain, domid_t did, int vcid)
{
	struct xen_hyper_vcpu_context_array *vcca;
	struct xen_hyper_vcpu_context *vcc;
	int i;

	if (vcid == XEN_HYPER_VCPU_ID_INVALID) {
		return NULL;
	}
	if ((vcca = xen_hyper_domain_to_vcpu_context_array(domain))) {
		;
	} else if (!(vcca = xen_hyper_domid_to_vcpu_context_array(did))) {
		return NULL;
	}
	for (i = 0, vcc = vcca->context_array;
		i < vcca->context_array_cnt; i++, vcc++) {
		if (vcid == vcc->vcpu_id) {
			return vcc;
		}
	}
	return NULL;
}

/*
 * Get pointer of a vcpu context array from domain address.
 */
struct xen_hyper_vcpu_context_array *
xen_hyper_domain_to_vcpu_context_array(ulong domain)
{
	struct xen_hyper_domain_context *dc;

	if(!(dc = xen_hyper_domain_to_domain_context(domain))) {
		return NULL;
	}
	return dc->vcpu_context_array;
}

/*
 * Get pointer of a vcpu context array from domain id.
 */
struct xen_hyper_vcpu_context_array *
xen_hyper_domid_to_vcpu_context_array(domid_t id)
{
	struct xen_hyper_domain_context *dc;

	if (!(dc = xen_hyper_id_to_domain_context(id))) {
		return NULL;
	}
	return dc->vcpu_context_array;
}

/*
 * Store vcpu struct contents.
 */
struct xen_hyper_vcpu_context *
xen_hyper_store_vcpu_context(struct xen_hyper_vcpu_context *vcc,
       ulong vcpu, char *vcp)
{
	vcc->vcpu = vcpu;
	vcc->vcpu_id = INT(vcp + XEN_HYPER_OFFSET(vcpu_vcpu_id));
	vcc->processor = INT(vcp + XEN_HYPER_OFFSET(vcpu_processor));
	vcc->vcpu_info = ULONG(vcp + XEN_HYPER_OFFSET(vcpu_vcpu_info));
	vcc->domain = ULONG(vcp + XEN_HYPER_OFFSET(vcpu_domain));
	vcc->next_in_list = ULONG(vcp + XEN_HYPER_OFFSET(vcpu_next_in_list));
	vcc->sleep_tick = ULONG(vcp + XEN_HYPER_OFFSET(vcpu_sleep_tick));
	vcc->sched_priv = ULONG(vcp + XEN_HYPER_OFFSET(vcpu_sched_priv));
	vcc->state = INT(vcp + XEN_HYPER_OFFSET(vcpu_runstate) +
		XEN_HYPER_OFFSET(vcpu_runstate_info_state));
	vcc->state_entry_time = ULONGLONG(vcp +
		XEN_HYPER_OFFSET(vcpu_runstate) +
		XEN_HYPER_OFFSET(vcpu_runstate_info_state_entry_time));
	vcc->runstate_guest = ULONG(vcp + XEN_HYPER_OFFSET(vcpu_runstate_guest));
	vcc->vcpu_flags = ULONG(vcp + XEN_HYPER_OFFSET(vcpu_vcpu_flags));
	return vcc;
}

/*
 * Read vcpu struct from vcpu context.
 */
char *
xen_hyper_read_vcpu_from_context(struct xen_hyper_vcpu_context *vcc)
{
	return xen_hyper_fill_vcpu_struct(vcc->vcpu, xhvct->vcpu_struct);
}

/*
 * Read vcpu struct.
 */
char *
xen_hyper_read_vcpu(ulong vcpu)
{
	return xen_hyper_fill_vcpu_struct(vcpu, xhvct->vcpu_struct);
}

/*
 * Read vcpu struct to verification.
 */
char *
xen_hyper_read_vcpu_verify(ulong vcpu)
{
	return xen_hyper_fill_vcpu_struct(vcpu, xhvct->vcpu_struct_verify);
}

/*
 * Fill vcpu struct.
 */
char *
xen_hyper_fill_vcpu_struct(ulong vcpu, char *vcpu_struct)
{
	if (!readmem(vcpu, KVADDR, vcpu_struct,
		XEN_HYPER_SIZE(vcpu), "fill_vcpu_struct",
	       	ACTIVE() ? (RETURN_ON_ERROR|QUIET) : RETURN_ON_ERROR)) {
		error(WARNING, "cannot fill vcpu struct.\n");
		return NULL;
	}
	return vcpu_struct;
}

/*
 * Allocate vcpu context arrays space.
 */
void
xen_hyper_alloc_vcpu_context_arrays_space(int domains)
{
	struct xen_hyper_vcpu_context_array *vcca;

	if (xhvct->vcpu_context_arrays == NULL) {
		if (!(xhvct->vcpu_context_arrays =
			malloc(domains * sizeof(struct xen_hyper_vcpu_context_array)))) {
			error(FATAL, "cannot malloc context arrays (%d domains).",
				domains);
		}
		xhvct->vcpu_context_arrays_cnt = domains;
		BZERO(xhvct->vcpu_context_arrays, domains * sizeof(struct xen_hyper_vcpu_context_array));
	} else if (domains > xhvct->vcpu_context_arrays_cnt) {
		if (!(xhvct->vcpu_context_arrays =
			realloc(xhvct->vcpu_context_arrays,
				domains * sizeof(struct xen_hyper_vcpu_context_array)))) {
			error(FATAL, "cannot realloc context arrays (%d domains).",
				domains);
		}
		vcca = xhvct->vcpu_context_arrays + domains;
		BZERO(vcca, (domains - xhvct->vcpu_context_arrays_cnt) *
			sizeof(struct xen_hyper_vcpu_context_array));
		xhvct->vcpu_context_arrays_cnt = domains;
	}
}

/*
 * Allocate vcpu context space.
 */
void
xen_hyper_alloc_vcpu_context_space(struct xen_hyper_vcpu_context_array *vcca, int vcpus)
{
	if (vcca->context_array == NULL) {
		if (!(vcca->context_array =
			malloc(vcpus * sizeof(struct xen_hyper_vcpu_context)))) {
			error(FATAL, "cannot malloc context array (%d vcpus).",
				vcpus);
		}
		vcca->context_array_cnt = vcpus;
	} else if (vcpus > vcca->context_array_cnt) {
		if (!(vcca->context_array =
			realloc(vcca->context_array,
				vcpus * sizeof(struct xen_hyper_vcpu_context_array)))) {
			error(FATAL, "cannot realloc context array (%d vcpus).",
				vcpus);
		}
		vcca->context_array_cnt = vcpus;
	}
	vcca->context_array_valid = vcpus;
	BZERO(vcca->context_array, vcpus * sizeof(struct xen_hyper_vcpu_context));
}



/*
 * Get pcpu context from pcpu id.
 */
struct xen_hyper_pcpu_context *
xen_hyper_id_to_pcpu_context(uint id)
{
	if (xhpct->context_array == NULL) {
		return NULL;
	}
	if (!xen_hyper_test_pcpu_id(id)) {
		return NULL;
	}
	return &xhpct->context_array[id];
}

/*
 * Get pcpu context from pcpu address.
 */
struct xen_hyper_pcpu_context *
xen_hyper_pcpu_to_pcpu_context(ulong pcpu)
{
	struct xen_hyper_pcpu_context *pcc;
	int i;
	uint cpuid;

	if (xhpct->context_array == NULL) {
		return NULL;
	}
	if (!pcpu) {
		return NULL;
	}
	for_cpu_indexes(i, cpuid)
	{
		pcc = &xhpct->context_array[cpuid];
		if (pcpu == pcc->pcpu) {
			return pcc;
		}
	}
	return NULL;
}

/*
 * Store pcpu struct contents.
 */
struct xen_hyper_pcpu_context *
xen_hyper_store_pcpu_context(struct xen_hyper_pcpu_context *pcc,
       ulong pcpu, char *pcp)
{
	pcc->pcpu = pcpu;
	pcc->processor_id =
		UINT(pcp + XEN_HYPER_OFFSET(cpu_info_processor_id));
	pcc->guest_cpu_user_regs = (ulong)(pcpu +
			XEN_HYPER_OFFSET(cpu_info_guest_cpu_user_regs));
	pcc->current_vcpu =
		ULONG(pcp + XEN_HYPER_OFFSET(cpu_info_current_vcpu));
	return pcc;
}

/*
 * Read pcpu struct.
 */
char *
xen_hyper_read_pcpu(ulong pcpu)
{
	return xen_hyper_fill_pcpu_struct(pcpu, xhpct->pcpu_struct);
}

/*
 * Fill pcpu struct.
 */
char *
xen_hyper_fill_pcpu_struct(ulong pcpu, char *pcpu_struct)
{
	if (!readmem(pcpu, KVADDR, pcpu_struct,
		XEN_HYPER_SIZE(cpu_info), "fill_pcpu_struct",
	       	ACTIVE() ? (RETURN_ON_ERROR|QUIET) : RETURN_ON_ERROR)) {
		error(WARNING, "cannot fill pcpu_struct.\n");
		return NULL;
	}
	return pcpu_struct;
}

/*
 * Allocate pcpu context space.
 */
void
xen_hyper_alloc_pcpu_context_space(int pcpus)
{
	if (xhpct->context_array == NULL) {
		if (!(xhpct->context_array =
			malloc(pcpus * sizeof(struct xen_hyper_pcpu_context)))) {
			error(FATAL, "cannot malloc context array (%d pcpus).",
				pcpus);
		}
	}
	BZERO(xhpct->context_array, pcpus * sizeof(struct xen_hyper_pcpu_context));
}



/*
 * Fill cpu_data.
 * ia64 has difference cpu_data format.
 */
char *
xen_hyper_fill_cpu_data_x86(int idx, char *cpuinfo_x86)
{
	ulong cpu_data_base, cpu_data;

	cpu_data_base = symbol_value("cpu_data");
	cpu_data = cpu_data_base + XEN_HYPER_SIZE(cpuinfo_x86) *idx;
	if (!readmem(cpu_data, KVADDR, cpuinfo_x86, XEN_HYPER_SIZE(cpuinfo_x86),
		"cpu_data", RETURN_ON_ERROR)) {
		error(WARNING, "cannot read cpu_data.\n");
		return NULL;
	}
	return cpuinfo_x86;
}

/*
 * Return whether vcpu is crashing.
 */
int
is_xen_hyper_vcpu_crash(struct xen_hyper_vcpu_context *vcc)
{
	if (vcc == xht->crashing_vcc)
		return TRUE;
	return FALSE;
}

/*
 * Test whether cpu for pcpu id exists.
 */
int
xen_hyper_test_pcpu_id(uint pcpu_id)
{
	ulong *cpumask = xht->cpumask;
	uint i, j;

	if (pcpu_id > XEN_HYPER_MAX_CPUS()) {
		return FALSE;
	}

	i = pcpu_id / (sizeof(ulong) * 8);
	j = pcpu_id % (sizeof(ulong) * 8);
	cpumask += i;
	if (*cpumask & (1UL << j)) {
		return TRUE;
	} else {
		return FALSE;
	}
}



/*
 *  Calculate and return the uptime.
 */
ulonglong
get_uptime_hyper(void)
{
	ulong jiffies, tmp1, tmp2;
	ulonglong jiffies_64, wrapped;

	if (symbol_exists("jiffies_64")) {
		get_symbol_data("jiffies_64", sizeof(ulonglong), &jiffies_64);
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
	} else {
		get_symbol_data("jiffies", sizeof(long), &jiffies);
		jiffies_64 = (ulonglong)jiffies;
	}

	return jiffies_64;
}

/*
 * Get cpu informatin around.
 */
void
xen_hyper_get_cpu_info(void)
{
	ulong addr;
	ulong *cpumask;
	uint *cpu_idx;
	int i, j, cpus;

	get_symbol_data("max_cpus", sizeof(xht->max_cpus), &xht->max_cpus);
	XEN_HYPER_STRUCT_SIZE_INIT(cpumask_t, "cpumask_t");
	if (XEN_HYPER_SIZE(cpumask_t) * 8 > xht->max_cpus) {
		xht->max_cpus = XEN_HYPER_SIZE(cpumask_t) * 8;
	}
	if (xht->cpumask) {
		free(xht->cpumask);
	}
	if((xht->cpumask = malloc(XEN_HYPER_SIZE(cpumask_t))) == NULL) {
		error(FATAL, "cannot malloc cpumask space.\n");
	}
	/* kakuma: It may be better to use cpu_present_map. */
	addr = symbol_value("cpu_online_map");
	if (!readmem(addr, KVADDR, xht->cpumask,
		XEN_HYPER_SIZE(cpumask_t), "cpu_online_map", RETURN_ON_ERROR)) {
		error(FATAL, "cannot read cpu_online_map.\n");
	}
	if (xht->cpu_idxs) {
		free(xht->cpu_idxs);
	}
	if((xht->cpu_idxs = malloc(sizeof(uint) * XEN_HYPER_MAX_PCPUS())) == NULL) {
		error(FATAL, "cannot malloc cpu_idxs space.\n");
	}
	for (i = cpus = 0, cpumask = xht->cpumask, cpu_idx = xht->cpu_idxs;
	i < (XEN_HYPER_SIZE(cpumask_t)/sizeof(ulong)); i++, cpumask++) {
		for (j = 0; j < sizeof(ulong) * 8; j++) {
			if (*cpumask & (1UL << j)) {
				*cpu_idx++ = i * sizeof(ulong) * 8 + j;
				cpus++;
			}
		}
	}
	xht->pcpus = cpus;
}

/*
 * Calculate the number of physical cpu for x86.
 */
int
x86_get_smp_cpus_hyper(void)
{
	if (xht->pcpus) {
		return xht->pcpus;
	}
	xen_hyper_get_cpu_info();
	return xht->pcpus;
}

/*
 * Calculate used memory size.
 */
uint64_t
x86_memory_size_hyper(void)
{
	ulong vaddr;

	if (machdep->memsize) {
		return machdep->memsize;
	}
	vaddr = symbol_value("max_page");
	if (!readmem(vaddr, KVADDR, &xht->max_page, sizeof(xht->max_page),
		"max_page", RETURN_ON_ERROR)) {
		error(WARNING, "cannot read max_page.\n");
	}
	machdep->memsize = (uint64_t)(xht->max_page) * (uint64_t)(machdep->pagesize);
	return machdep->memsize;
}



/*
 * Print an aligned string with specified length.
 */
void
xen_hyper_fpr_indent(FILE *fp, int len, char *str1, char *str2, int flag)
{
	char buf[XEN_HYPER_CMD_BUFSIZE];
	int sl, r;
	char *s1, *s2;

	sl = strlen(str1);
	if (sl > len) {
		r = 0;
	} else {
		r = len - sl;
	}

	memset(buf, ' ', sizeof(buf));
	buf[r] =  '\0';
	if (flag & XEN_HYPER_PRI_L) {
		s1 = str1;
		s2 = buf;
	} else {
		s1 = buf;
		s2 = str1;
	}
	if (str2) {
		fprintf(fp, "%s%s%s", s1, s2, str2);
	} else {
		fprintf(fp, "%s%s", s1, s2);
	}
	if (flag & XEN_HYPER_PRI_LF) {
		fprintf(fp, "\n");
	}
}

void
print_pcpu_header_hyper(FILE *out, int pcpu, int newline)
{
	if (newline)
		fprintf(out, "\n");
	fprintf(out, "PCPU: %2d\n", pcpu);
}
#endif