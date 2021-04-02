/*
 *  xen_hyper_dump_tables.c
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

static void dump_xen_hyper_table(int verbose);
static void dump_xen_hyper_dumpinfo_table(int verbose);
static void dump_xen_hyper_domain_table(int verbose);
static void dump_xen_hyper_vcpu_table(int verbose);
static void dump_xen_hyper_pcpu_table(int verbose);
static void dump_xen_hyper_size_table(char *spec, ulong makestruct);
static void dump_xen_hyper_offset_table(char *spec, ulong makestruct);

/*
 *  Get help for a command, to dump an internal table, or the GNU public
 *  license copying/warranty information.
 */
void
cmd_xen_hyper_help(void)
{
	int c;
	int oflag;

	oflag = 0;

        while ((c = getopt(argcnt, args, 
	        "aBbcDgHhMmnOopszX:")) != EOF) {
                switch(c)
                {
		case 'a':
			dump_alias_data();
			return;
		case 'b':
			dump_shared_bufs();
			return;
		case 'B':
			dump_build_data();
			return;
		case 'c':
			dump_numargs_cache();
			return;
		case 'n':
		case 'D':
			dumpfile_memory(DUMPFILE_MEM_DUMP);
			return;
		case 'g':
			dump_gdb_data();
			return;
		case 'H':
			dump_hash_table(VERBOSE);
			return;
		case 'h':
			dump_hash_table(!VERBOSE);
 			return;
		case 'M':
			dump_machdep_table(stol(optarg, FAULT_ON_ERROR, NULL));
			return;
		case 'm':
			dump_machdep_table(0);
			return;
		case 'O':
			dump_offset_table(NULL, TRUE);
			return;
		case 'o':
			oflag = TRUE;
			break;
		case 'p':
			dump_program_context();
			return;
		case 's':
			dump_symbol_table();
			return;
		case 'X':
			if (strlen(optarg) != 3) {
				argerrs++;
				break;
			}
			if (!strncmp("Xen", optarg, strlen(optarg)))
				dump_xen_hyper_table(VERBOSE);
			else if (!strncmp("xen", optarg, strlen(optarg)))
				dump_xen_hyper_table(!VERBOSE);
			else if (!strncmp("Dmp", optarg, strlen(optarg)))
				dump_xen_hyper_dumpinfo_table(VERBOSE);
			else if (!strncmp("dmp", optarg, strlen(optarg)))
				dump_xen_hyper_dumpinfo_table(!VERBOSE);
			else if (!strncmp("Dom", optarg, strlen(optarg)))
				dump_xen_hyper_domain_table(VERBOSE);
			else if (!strncmp("dom", optarg, strlen(optarg)))
				dump_xen_hyper_domain_table(!VERBOSE);
			else if (!strncmp("Vcp", optarg, strlen(optarg)))
				dump_xen_hyper_vcpu_table(VERBOSE);
			else if (!strncmp("vcp", optarg, strlen(optarg)))
				dump_xen_hyper_vcpu_table(!VERBOSE);
			else if (!strncmp("Pcp", optarg, strlen(optarg)))
				dump_xen_hyper_pcpu_table(!VERBOSE);
			else if (!strncmp("pcp", optarg, strlen(optarg)))
				dump_xen_hyper_pcpu_table(VERBOSE);
			else if (!strncmp("siz", optarg, strlen(optarg)))
				dump_xen_hyper_size_table(NULL, TRUE);
			else if (!strncmp("ofs", optarg, strlen(optarg)))
				dump_xen_hyper_offset_table(NULL, TRUE);
 			return;
		case 'z':
			fprintf(fp, "help options:\n");
			fprintf(fp, " -a - alias data\n");
			fprintf(fp, " -b - shared buffer data\n");
			fprintf(fp, " -B - build data\n");
			fprintf(fp, " -c - numargs cache\n");
			fprintf(fp, " -M <num> machine specific\n");
			fprintf(fp, " -m - machdep_table\n");
			fprintf(fp, " -s - symbol table data\n");
			fprintf(fp, " -o - offset_table and size_table\n");
			fprintf(fp, " -p - program_context\n");
			fprintf(fp, " -h - hash_table data\n");
			fprintf(fp, " -H - hash_table data (verbose)\n");
			fprintf(fp, " -X Xen - xen table data (verbose)\n");
			fprintf(fp, " -X xen - xen table data\n");
			fprintf(fp, " -X Dmp - dumpinfo table data (verbose)\n");
			fprintf(fp, " -X dmp - dumpinfo table data\n");
			fprintf(fp, " -X Dom - domain table data (verbose)\n");
			fprintf(fp, " -X dom - domain table data\n");
			fprintf(fp, " -X Vcp - vcpu table data (verbose)\n");
			fprintf(fp, " -X vcp - vcpu table data\n");
			fprintf(fp, " -X Pcp - pcpu table data (verbose)\n");
			fprintf(fp, " -X pcp - pcpu table data\n");
			fprintf(fp, " -X siz - size table data\n");
			fprintf(fp, " -X ofs - offset table data\n");
			return;
                default:  
			argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, COMPLETE_HELP);

	if (!args[optind]) {
		if (oflag) 
			dump_offset_table(NULL, FALSE);
		else 
			display_help_screen("");
		return;
	}

        do {
		if (oflag) 
			dump_offset_table(args[optind], FALSE);
		else	
        		cmd_usage(args[optind], COMPLETE_HELP);
		optind++;
        } while (args[optind]);
}

/*
 * "help -x xen" output
 */
static void
dump_xen_hyper_table(int verbose)
{
	char buf[XEN_HYPER_CMD_BUFSIZE];
	uint cpuid;
	int len, flag, i;

	len = 14;
	flag = XEN_HYPER_PRI_R;

	XEN_HYPER_PRI(fp, len, "cpu_curr: ", buf, flag,
		(buf, "%u\n", xht->cpu_curr));
	XEN_HYPER_PRI(fp, len, "max_cpus: ", buf, flag,
		(buf, "%u\n", xht->max_cpus));
	XEN_HYPER_PRI(fp, len, "cores: ", buf, flag,
		(buf, "%d\n", xht->cores));
	XEN_HYPER_PRI(fp, len, "pcpus: ", buf, flag,
		(buf, "%d\n", xht->pcpus));
	XEN_HYPER_PRI(fp, len, "vcpus: ", buf, flag,
		(buf, "%d\n", xht->vcpus));
	XEN_HYPER_PRI(fp, len, "domains: ", buf, flag,
		(buf, "%d\n", xht->domains));
	XEN_HYPER_PRI(fp, len, "crashing_cpu: ", buf, flag,
		(buf, "%d\n", xht->crashing_cpu));
	XEN_HYPER_PRI(fp, len, "crashing_vcc: ", buf, flag,
		(buf, "%p\n", xht->crashing_vcc));
	XEN_HYPER_PRI(fp, len, "max_page: ", buf, flag,
		(buf, "%lu\n", xht->max_page));
	XEN_HYPER_PRI(fp, len, "cpumask: ", buf, flag,
		(buf, "%p\n", xht->cpumask));
	XEN_HYPER_PRI(fp, len, "cpu_idxs: ", buf, flag,
		(buf, "%p\n", xht->cpu_idxs));
	if (verbose) {
		for_cpu_indexes(i, cpuid)
			fprintf(fp, "%03d : %d\n", i, cpuid);
	}
}

/*
 * "help -x dmp" output
 */
static void
dump_xen_hyper_dumpinfo_table(int verbose)
{
	char buf[XEN_HYPER_CMD_BUFSIZE];
	int len, flag;

	len = 24;
	flag = XEN_HYPER_PRI_R;

	XEN_HYPER_PRI(fp, len, "note_ver: ", buf, flag,
		(buf, "%u\n", xhdit->note_ver));
	XEN_HYPER_PRI(fp, len, "context_array: ", buf, flag,
		(buf, "%p\n", xhdit->context_array));
	XEN_HYPER_PRI_CONST(fp, len, "context_xen_core: ", flag|XEN_HYPER_PRI_LF);
	XEN_HYPER_PRI(fp, len, "note: ", buf, flag,
		(buf, "%lx\n", xhdit->context_xen_core.note));
	XEN_HYPER_PRI(fp, len, "pcpu_id: ", buf, flag,
		(buf, "%u\n", xhdit->context_xen_core.pcpu_id));
	XEN_HYPER_PRI(fp, len, "crash_xen_core_ptr: ", buf, flag,
		(buf, "%p\n", xhdit->context_xen_core.crash_xen_core_ptr));
	XEN_HYPER_PRI_CONST(fp, len, "context_xen_info: ", flag|XEN_HYPER_PRI_LF);
	XEN_HYPER_PRI(fp, len, "note: ", buf, flag,
		(buf, "%lx\n", xhdit->context_xen_info.note));
	XEN_HYPER_PRI(fp, len, "pcpu_id: ", buf, flag,
		(buf, "%u\n", xhdit->context_xen_info.pcpu_id));
	XEN_HYPER_PRI(fp, len, "crash_xen_info_ptr: ", buf, flag,
		(buf, "%p\n", xhdit->context_xen_info.crash_xen_info_ptr));
	XEN_HYPER_PRI(fp, len, "crash_note_core_array: ", buf, flag,
		(buf, "%p\n", xhdit->crash_note_core_array));
	XEN_HYPER_PRI(fp, len, "crash_note_xen_core_ptr: ", buf, flag,
		(buf, "%p\n", xhdit->crash_note_xen_core_ptr));
	XEN_HYPER_PRI(fp, len, "crash_note_xen_info_ptr: ", buf, flag,
		(buf, "%p\n", xhdit->crash_note_xen_info_ptr));
	XEN_HYPER_PRI(fp, len, "note_size: ", buf, flag,
		(buf, "%u\n", xhdit->note_size));
	XEN_HYPER_PRI(fp, len, "core_offset: ", buf, flag,
		(buf, "%u\n", xhdit->core_offset));
	XEN_HYPER_PRI(fp, len, "core_size: ", buf, flag,
		(buf, "%u\n", xhdit->core_size));
	XEN_HYPER_PRI(fp, len, "xen_core_offset: ", buf, flag,
		(buf, "%u\n", xhdit->xen_core_offset));
	XEN_HYPER_PRI(fp, len, "xen_core_size: ", buf, flag,
		(buf, "%u\n", xhdit->xen_core_size));
	XEN_HYPER_PRI(fp, len, "xen_info_offset: ", buf, flag,
		(buf, "%u\n", xhdit->xen_info_offset));
	XEN_HYPER_PRI(fp, len, "xen_info_size: ", buf, flag,
		(buf, "%u\n", xhdit->xen_info_size));
}

/*
 * "help -x dom" output
 */
static void
dump_xen_hyper_domain_table(int verbose)
{
	char buf[XEN_HYPER_CMD_BUFSIZE];
	int len, flag;

	len = 22;
	flag = XEN_HYPER_PRI_R;

	XEN_HYPER_PRI(fp, len, "context_array: ", buf, flag,
		(buf, "%p\n", xhdt->context_array));
	XEN_HYPER_PRI(fp, len, "context_array_cnt: ", buf, flag,
		(buf, "%d\n", xhdt->context_array_cnt));
	XEN_HYPER_PRI(fp, len, "running_domains: ", buf, flag,
		(buf, "%lu\n", xhdt->running_domains));
	XEN_HYPER_PRI(fp, len, "dom0: ", buf, flag,
		(buf, "%p\n", xhdt->dom0));
	XEN_HYPER_PRI(fp, len, "idle_domain: ", buf, flag,
		(buf, "%p\n", xhdt->idle_domain));
	XEN_HYPER_PRI(fp, len, "curr_domain: ", buf, flag,
		(buf, "%p\n", xhdt->curr_domain));
	XEN_HYPER_PRI(fp, len, "last: ", buf, flag,
		(buf, "%p\n", xhdt->last));
	XEN_HYPER_PRI(fp, len, "domain_struct: ", buf, flag,
		(buf, "%p\n", xhdt->domain_struct));
	XEN_HYPER_PRI(fp, len, "domain_struct_verify: ", buf, flag,
		(buf, "%p\n", xhdt->domain_struct_verify));
}

/*
 * "help -x vcp" output
 */
static void
dump_xen_hyper_vcpu_table(int verbose)
{
	char buf[XEN_HYPER_CMD_BUFSIZE];
	int len, flag;

	len = 25;
	flag = XEN_HYPER_PRI_R;

	XEN_HYPER_PRI(fp, len, "vcpu_context_arrays: ", buf, flag,
		(buf, "%p\n", xhvct->vcpu_context_arrays));
	XEN_HYPER_PRI(fp, len, "vcpu_context_arrays_cnt: ", buf, flag,
		(buf, "%d\n", xhvct->vcpu_context_arrays_cnt));
	XEN_HYPER_PRI(fp, len, "idle_vcpu: ", buf, flag,
		(buf, "%lx\n", xhvct->idle_vcpu));
	XEN_HYPER_PRI(fp, len, "idle_vcpu_context_array: ", buf, flag,
		(buf, "%p\n", xhvct->idle_vcpu_context_array));
	XEN_HYPER_PRI(fp, len, "last: ", buf, flag,
		(buf, "%p\n", xhvct->last));
	XEN_HYPER_PRI(fp, len, "vcpu_struct: ", buf, flag,
		(buf, "%p\n", xhvct->vcpu_struct));
	XEN_HYPER_PRI(fp, len, "vcpu_struct_verify: ", buf, flag,
		(buf, "%p\n", xhvct->vcpu_struct_verify));
}

/*
 * "help -x pcp" output
 */
static void
dump_xen_hyper_pcpu_table(int verbose)
{
	char buf[XEN_HYPER_CMD_BUFSIZE];
	int len, flag;

	len = 15;
	flag = XEN_HYPER_PRI_R;

	XEN_HYPER_PRI(fp, len, "context_array: ", buf, flag,
		(buf, "%p\n", xhpct->context_array));
	XEN_HYPER_PRI(fp, len, "last: ", buf, flag,
		(buf, "%p\n", xhpct->last));
	XEN_HYPER_PRI(fp, len, "pcpu_struct: ", buf, flag,
		(buf, "%p\n", xhpct->pcpu_struct));
}

/*
 * "help -x siz" output
 */
static void
dump_xen_hyper_size_table(char *spec, ulong makestruct)
{
	char buf[XEN_HYPER_CMD_BUFSIZE];
	int len, flag;

	len = 20;
	flag = XEN_HYPER_PRI_R;

	XEN_HYPER_PRI(fp, len, "ELF_Prstatus: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.ELF_Prstatus));
	XEN_HYPER_PRI(fp, len, "ELF_Signifo: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.ELF_Signifo));
	XEN_HYPER_PRI(fp, len, "ELF_Gregset: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.ELF_Gregset));
	XEN_HYPER_PRI(fp, len, "ELF_Timeval: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.ELF_Timeval));
	XEN_HYPER_PRI(fp, len, "cpu_info: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.cpu_info));
	XEN_HYPER_PRI(fp, len, "cpu_time: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.cpu_time));
	XEN_HYPER_PRI(fp, len, "cpu_user_regs: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.cpu_user_regs));
	XEN_HYPER_PRI(fp, len, "cpumask_t: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.cpumask_t));
	XEN_HYPER_PRI(fp, len, "cpuinfo_x86: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.cpuinfo_x86));
	XEN_HYPER_PRI(fp, len, "crash_note_t: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.crash_note_t));
	XEN_HYPER_PRI(fp, len, "crash_note_core_t: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.crash_note_core_t));
	XEN_HYPER_PRI(fp, len, "crash_note_xen_t: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.crash_note_xen_t));
	XEN_HYPER_PRI(fp, len, "crash_note_xen_core_t: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.crash_note_xen_core_t));
	XEN_HYPER_PRI(fp, len, "crash_note_xen_info_t: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.crash_note_xen_info_t));
	XEN_HYPER_PRI(fp, len, "crash_xen_core_t: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.crash_xen_core_t));
	XEN_HYPER_PRI(fp, len, "crash_xen_info_t: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.crash_xen_info_t));
	XEN_HYPER_PRI(fp, len, "domain: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.domain));
	XEN_HYPER_PRI(fp, len, "note_buf_t: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.note_buf_t));
	XEN_HYPER_PRI(fp, len, "scheduler: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.scheduler));
	XEN_HYPER_PRI(fp, len, "timer: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.timer));
	XEN_HYPER_PRI(fp, len, "tss_struct: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.tss_struct));
	XEN_HYPER_PRI(fp, len, "vcpu: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.vcpu));
	XEN_HYPER_PRI(fp, len, "vcpu_runstate_info: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.vcpu_runstate_info));
	XEN_HYPER_PRI(fp, len, "xen_crash_xen_regs_t: ", buf, flag,
		(buf, "%ld\n", xen_hyper_size_table.xen_crash_xen_regs_t));
}

/*
 * "help -x ofs" output
 */
static void
dump_xen_hyper_offset_table(char *spec, ulong makestruct)
{
	char buf[XEN_HYPER_CMD_BUFSIZE];
	int len, flag;

	len = 37;
	flag = XEN_HYPER_PRI_R;

	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_info: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_info));
	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_cursig: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_cursig));
	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_sigpend: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_sigpend));
	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_sighold: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_sighold));
	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_pid: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_pid));
	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_ppid: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_ppid));
	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_pgrp: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_pgrp));
	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_sid: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_sid));
	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_stime: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_stime));
	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_cutime: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_cutime));
	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_cstime: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_cstime));
	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_reg: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_reg));
	XEN_HYPER_PRI(fp, len, "ELF_Prstatus_pr_fpvalid: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Prstatus_pr_fpvalid));
	XEN_HYPER_PRI(fp, len, "ELF_Timeval_tv_sec: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Timeval_tv_sec));
	XEN_HYPER_PRI(fp, len, "ELF_Timeval_tv_usec: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.ELF_Timeval_tv_usec));
	XEN_HYPER_PRI(fp, len, "cpu_info_guest_cpu_user_regs: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.cpu_info_guest_cpu_user_regs));
	XEN_HYPER_PRI(fp, len, "cpu_info_processor_id: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.cpu_info_processor_id));
	XEN_HYPER_PRI(fp, len, "cpu_info_current_vcpu: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.cpu_info_current_vcpu));
	XEN_HYPER_PRI(fp, len, "cpu_time_local_tsc_stamp: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.cpu_time_local_tsc_stamp));
	XEN_HYPER_PRI(fp, len, "cpu_time_stime_local_stamp: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.cpu_time_stime_local_stamp));
	XEN_HYPER_PRI(fp, len, "cpu_time_stime_master_stamp: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.cpu_time_stime_master_stamp));
	XEN_HYPER_PRI(fp, len, "cpu_time_tsc_scale: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.cpu_time_tsc_scale));
	XEN_HYPER_PRI(fp, len, "cpu_time_calibration_timer: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.cpu_time_calibration_timer));

	XEN_HYPER_PRI(fp, len, "crash_note_t_core: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.crash_note_t_core));
	XEN_HYPER_PRI(fp, len, "crash_note_t_xen: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.crash_note_t_xen));
	XEN_HYPER_PRI(fp, len, "crash_note_t_xen_regs: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.crash_note_t_xen_regs));
	XEN_HYPER_PRI(fp, len, "crash_note_t_xen_info: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.crash_note_t_xen_info));

	XEN_HYPER_PRI(fp, len, "crash_note_core_t_note: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.crash_note_core_t_note));
	XEN_HYPER_PRI(fp, len, "crash_note_core_t_desc: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.crash_note_core_t_desc));

	XEN_HYPER_PRI(fp, len, "crash_note_xen_t_note: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.crash_note_xen_t_note));
	XEN_HYPER_PRI(fp, len, "crash_note_xen_t_desc: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.crash_note_xen_t_desc));

	XEN_HYPER_PRI(fp, len, "crash_note_xen_core_t_note: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.crash_note_xen_core_t_note));
	XEN_HYPER_PRI(fp, len, "crash_note_xen_core_t_desc: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.crash_note_xen_core_t_desc));

	XEN_HYPER_PRI(fp, len, "crash_note_xen_info_t_note: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.crash_note_xen_info_t_note));
	XEN_HYPER_PRI(fp, len, "crash_note_xen_info_t_desc: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.crash_note_xen_info_t_desc));

	XEN_HYPER_PRI(fp, len, "domain_page_list: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_page_list));
	XEN_HYPER_PRI(fp, len, "domain_xenpage_list: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_xenpage_list));
	XEN_HYPER_PRI(fp, len, "domain_domain_id: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_domain_id));
	XEN_HYPER_PRI(fp, len, "domain_tot_pages: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_tot_pages));
	XEN_HYPER_PRI(fp, len, "domain_max_pages: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_max_pages));
	XEN_HYPER_PRI(fp, len, "domain_xenheap_pages: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_xenheap_pages));
	XEN_HYPER_PRI(fp, len, "domain_shared_info: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_shared_info));
	XEN_HYPER_PRI(fp, len, "domain_sched_priv: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_sched_priv));
	XEN_HYPER_PRI(fp, len, "domain_next_in_list: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_next_in_list));
	XEN_HYPER_PRI(fp, len, "domain_domain_flags: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_domain_flags));
	XEN_HYPER_PRI(fp, len, "domain_evtchn: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_evtchn));
	XEN_HYPER_PRI(fp, len, "domain_vcpu: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.domain_vcpu));
	XEN_HYPER_PRI(fp, len, "timer_expires: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.timer_expires));
	XEN_HYPER_PRI(fp, len, "timer_cpu: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.timer_cpu));
	XEN_HYPER_PRI(fp, len, "timer_function: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.timer_function));
	XEN_HYPER_PRI(fp, len, "timer_data: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.timer_data));
	XEN_HYPER_PRI(fp, len, "timer_heap_offset: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.timer_heap_offset));
	XEN_HYPER_PRI(fp, len, "timer_killed: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.timer_killed));
	XEN_HYPER_PRI(fp, len, "tss_struct_rsp0: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.tss_struct_rsp0));
	XEN_HYPER_PRI(fp, len, "tss_struct_esp0: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.tss_struct_esp0));
	XEN_HYPER_PRI(fp, len, "vcpu_vcpu_id: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_vcpu_id));
	XEN_HYPER_PRI(fp, len, "vcpu_processor: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_processor));
	XEN_HYPER_PRI(fp, len, "vcpu_vcpu_info: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_vcpu_info));
	XEN_HYPER_PRI(fp, len, "vcpu_domain: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_domain));
	XEN_HYPER_PRI(fp, len, "vcpu_next_in_list: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_next_in_list));
	XEN_HYPER_PRI(fp, len, "vcpu_timer: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_timer));
	XEN_HYPER_PRI(fp, len, "vcpu_sleep_tick: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_sleep_tick));
	XEN_HYPER_PRI(fp, len, "vcpu_poll_timer: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_poll_timer));
	XEN_HYPER_PRI(fp, len, "vcpu_sched_priv: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_sched_priv));
	XEN_HYPER_PRI(fp, len, "vcpu_runstate: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_runstate));
	XEN_HYPER_PRI(fp, len, "vcpu_runstate_guest: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_runstate_guest));
	XEN_HYPER_PRI(fp, len, "vcpu_vcpu_flags: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_vcpu_flags));
	XEN_HYPER_PRI(fp, len, "vcpu_pause_count: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_pause_count));
	XEN_HYPER_PRI(fp, len, "vcpu_virq_to_evtchn: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_virq_to_evtchn));
	XEN_HYPER_PRI(fp, len, "vcpu_cpu_affinity: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_cpu_affinity));
	XEN_HYPER_PRI(fp, len, "vcpu_nmi_addr: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_nmi_addr));
	XEN_HYPER_PRI(fp, len, "vcpu_vcpu_dirty_cpumask: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_vcpu_dirty_cpumask));
	XEN_HYPER_PRI(fp, len, "vcpu_arch: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_arch));
	XEN_HYPER_PRI(fp, len, "vcpu_runstate_info_state: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_runstate_info_state));
	XEN_HYPER_PRI(fp, len, "vcpu_runstate_info_state_entry_time: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_runstate_info_state_entry_time));
	XEN_HYPER_PRI(fp, len, "vcpu_runstate_info_time: ", buf, flag,
		(buf, "%ld\n", xen_hyper_offset_table.vcpu_runstate_info_time));
}
#endif
