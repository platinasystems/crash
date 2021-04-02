/*
 *  xen_hyper_global_data.c
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
 * Global data for Xen hypervisor.
 */

struct xen_hyper_machdep_table xen_hyper_machdep_table = { 0 };
struct xen_hyper_machdep_table *xhmachdep = &xen_hyper_machdep_table;

struct xen_hyper_table xen_hyper_table = { 0 };
struct xen_hyper_table *xht = &xen_hyper_table;

struct xen_hyper_dumpinfo_table xen_hyper_dumpinfo_table = { 0 };
struct xen_hyper_dumpinfo_table *xhdit = &xen_hyper_dumpinfo_table;

struct xen_hyper_domain_table xen_hyper_domain_table = { 0 };
struct xen_hyper_domain_table *xhdt = &xen_hyper_domain_table;

struct xen_hyper_vcpu_table xen_hyper_vcpu_table = { 0 };
struct xen_hyper_vcpu_table *xhvct = &xen_hyper_vcpu_table;

struct xen_hyper_pcpu_table xen_hyper_pcpu_table = { 0 };
struct xen_hyper_pcpu_table *xhpct = &xen_hyper_pcpu_table;

struct xen_hyper_sched_table xen_hyper_sched_table = { 0 };
struct xen_hyper_sched_table *xhscht = &xen_hyper_sched_table;

struct xen_hyper_symbol_table_data xen_hyper_symbol_table_data = { 0 };
struct xen_hyper_symbol_table_data *xhsymt = &xen_hyper_symbol_table_data;

/*
 * The following commands are for Xen hypervisor.
 */

struct command_table_entry xen_hyper_command_table[] = {
	{"*", 	    cmd_pointer, help_pointer, 0},
	{"alias",   cmd_alias,   help_alias,   0},
        {"ascii",   cmd_ascii,   help_ascii,   0},
        {"bt",      cmd_bt,      help_bt,      0},
	{"dis",     cmd_dis,     help_dis,     0},
	{"domain",  cmd_xen_hyper_domain,   help_xen_hyper_domain,  REFRESH_TASK_TABLE},
	{"doms",    cmd_xen_hyper_doms,     help_xen_hyper_doms,    REFRESH_TASK_TABLE},
	{"dumpinfo",cmd_xen_hyper_dumpinfo, help_xen_hyper_dumpinfo,0},
	{"eval",    cmd_eval,    help_eval,    0},
	{"exit",    cmd_quit,    help_exit,    0},
	{"extend",  cmd_extend,  help_extend,  0},
	{"foreach", cmd_foreach, help_foreach, 0},
	{"gdb",     cmd_gdb,     help_gdb,     0},
        {"help",    cmd_xen_hyper_help,     help_help,              0},
	{"list",    cmd_list,    help__list,   0},
	{"log",     cmd_xen_hyper_log,      help_xen_hyper_log,     0},
	{"p",       cmd_p,       help_p,       0},
	{"pcpus",   cmd_xen_hyper_pcpus,    help_xen_hyper_pcpus,   0},
        {"pte",     cmd_pte,     help_pte,     0},
        {"q",       cmd_quit,    help_quit,    0},
        {"rd",      cmd_rd,      help_rd,      0},
	{"repeat",  cmd_repeat,  help_repeat,  0},
        {"search",  cmd_search,  help_search,  0},
        {"set",     cmd_set,     help_set,     0},
        {"struct",  cmd_struct,  help_struct,  0},
        {"sym",     cmd_sym,     help_sym,     0},
        {"sys",     cmd_xen_hyper_sys,      help_xen_hyper_sys,     0},
	{"test",    cmd_test,    NULL,         HIDDEN_COMMAND},
	{"union",   cmd_union,   help_union,   0},
	{"vcpu",    cmd_xen_hyper_vcpu,     help_xen_hyper_vcpu,    REFRESH_TASK_TABLE},
	{"vcpus",   cmd_xen_hyper_vcpus,    help_xen_hyper_vcpus,   REFRESH_TASK_TABLE},
	{"whatis",  cmd_whatis,  help_whatis,  0},
	{"wr",      cmd_wr,      help_wr,      0},
	{(char *)NULL}
};

/*
 *
 */
struct xen_hyper_offset_table xen_hyper_offset_table = { 0 };
struct xen_hyper_size_table xen_hyper_size_table = { 0 };

/*
 * help data
 */

char *help_xen_hyper_domain[] = {
"domain",
"display contents of domain struct",
"[domain-id | domainp] ...",
"  This command displays contents of domain struct for selected, or all, domains",
"     domain-id  a domain id.",
"       domainp  a domain pointer.",
NULL               
};

char *help_xen_hyper_doms[] = {
"doms",
"display domain status information",
"[domain-id | domainp] ...",
"  This command displays domain status for selected, or all, domains" ,
"     domain-id  a domain id.",
"       domainp  a domain pointer.",
" ",
"    1. the DOMAIN-ID.",
"    2. the struct domain pointer.",
"    3. the domain state (SH, DY, CP, PO, PA, RU).",
"    4. the TYPE of domain(I, 0, G).",
"    5. displays percentage of page of max_pages member of domain",
"       for max_page of system.",
"    6. displays percentage of page of tot_pages member of domain" ,
"       for max_page of system." ,
"    7. a number of vcpu that domain is assigned.",
" ",
"  The active domain on each CPU will be highlighted by an angle ",
"  bracket (\">\") preceding its information.",
"  The crashing domain on each CPU will be highlighted by an aster ",
"  (\"*\") preceding its information.",
"\nEXAMPLES",
"  Show the domain status of all:\n",
"    %s> doms",
"       DID   DOMAIN  ST T %MMEM %TMEM VCPU",
"      32767 ffbfc080 RU I   0.0   0.0   2",
"    >*    0 ff198080 RU 0 100.0  79.0   2",
"          4 ffbee080 RU G   6.3   6.3   2",
"          5 ff186080 RU G   6.3   6.3   2",
"    %s>",
NULL               
};

char *help_xen_hyper_dumpinfo[] = {
"dumpinfo",
"display Xen dump information",
"[-t | -r] [pcpu-id | enotep] ...",
"  This command displays Xen dump information for selected, or all, cpus" ,
"       pcpu-id  a physical cpu id.",
"        enotep  a ELF Note pointer.",
"            -t  display time information.",
"            -r  display register information.",
NULL               
};

char *help_xen_hyper_log[] = {
"log",
"dump system message buffer",
"  This command dumps the xen conring contents in chronological order." ,
NULL               
};

char *help_xen_hyper_pcpus[] = {
"pcpus",
"display physical cpu information",
"[-r] [pcpu-id | pcpup] ...",
"  This command displays physical cpu information for selected, or all, cpus" ,
"       pcpu-id  a physical cpu id.",
"         pcpup  a physical cpu pointer.",
"      cur-vcpu  a current virtual cpu pointer.",
"            -r  display register information.",
" ",
"  The crashing physical cpu will be highlighted by an aster ",
"  (\"*\") preceding its information.",
"\nEXAMPLES",
"  Show the physical cpu status of all:\n",
"    %s> pcpus",
"       PCID   PCPU   CUR-VCPU",
"          0 ff1a3fb4 ffbf9080",
"     *    1 ff1dbfb4 ffbf8080",
"    %s>",
NULL               
};

char *help_xen_hyper_sys[] = {
"sys",
"system data",
"[-c [name|number]] config",
"  This command displays system-specific data.  If no arguments are entered,\n"
"  the same system data shown during %s invocation is shown.\n",
"\nEXAMPLES",
"  Display essential system information:\n",
"    %s> sys",
"      DEBUG KERNEL: xen-syms",
"          DUMPFILE: vmcore",
"              CPUS: 2",
"           DOMAINS: 2",
"           MACHINE: Pentium III (Coppermine)  (866 Mhz)",
"            MEMORY: 2 GB",
"    %s>",
NULL               
};

char *help_xen_hyper_vcpu[] = {
"vcpu",
"display contents of vcpu struct",
"[vcpup] ...",
"  This command displays contents of vcpu struct for selected, or all, vcpus",
"       vcpu-id  a virtual cpu id.",
"         vcpup  a virtual cpu pointer.",
NULL               
};

char *help_xen_hyper_vcpus[] = {
"vcpus",
"display vcpu status information",
"[-i domain-id vcpu-id | vcpup] ...",
"  This command displays vcpu status for selected, or all, vcpus" ,
"     domain-id  a domain id.",
"       vcpu-id  a VCPU-ID.",
"         vcpup  a hexadecimal struct vcpu pointer.",
"            -i  specify vcpu id as an argument.",
" ",
"    1. the VCPU-ID.",
"    2. the physical CPU-ID.",
"    3. the struct vcpu pointer.",
"    4. the vcpu state (RU, BL, OF).",
"    5. the TYPE of domain that vcpu is assigned(I, 0, G).",
"    6. the DOMAIN-ID of domain that vcpu is assigned.",
"    7. the struct domain pointer of domain that vcpu is assigned.",
" ",
"  The active vcpu on each CPU will be highlighted by an angle ",
"  bracket (\">\") preceding its information.",
"  The crashing vcpu on each CPU will be highlighted by an aster ",
"  (\"*\") preceding its information.",
"\nEXAMPLES",
"  Show the vcpu status of all:\n",
"    %s> vcpus",
"       VCID  PCID   VCPU   ST T DOMID  DOMAIN",
"          0     0 ffbfe080 RU I 32767 ffbfc080",
"          1     1 ff1df080 RU I 32767 ffbfc080",
"    >*    0     0 ff195180 RU 0     0 ff198080",
"    >     1     1 ff190080 BL 0     0 ff198080",
"          0     1 ff18a080 BL G     4 ffbee080",
"          1     0 ff189080 BL G     4 ffbee080",
"          0     1 ff1f3080 BL G     5 ff186080",
"          1     0 ff1f2080 BL G     5 ff186080",
"    %s>",
NULL               
};

struct task_context fake_tc = { 0 };

#endif
