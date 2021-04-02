/* defs.h - core analysis suite
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
 * 11/09/99, 1.0    Initial Release
 * 11/12/99, 1.0-1  Bug fixes
 * 12/10/99, 1.1    Fixes, new commands, support for v1 SGI dumps
 * 01/18/00, 2.0    Initial gdb merger, support for Alpha
 * 02/01/00, 2.1    Bug fixes, new commands, options, support for v2 SGI dumps
 * 02/29/00, 2.2    Bug fixes, new commands, options
 * 04/11/00, 2.3    Bug fixes, new command, options, initial PowerPC framework
 * 04/12/00  ---    Transition to BitKeeper version control
 * 
 * BitKeeper ID: @(#)defs.h 1.56
 *
 * 09/28/00  ---    Transition to CVS version control
 *
 * CVS: $Revision: 1.213 $ $Date: 2002/02/18 18:39:34 $
 */

#ifndef GDB_COMMON

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <termios.h>
#include <unistd.h>
#include <setjmp.h>
#undef basename
#if !defined(__USE_GNU)
#define __USE_GNU
#include <string.h>
#undef __USE_GNU
#else
#include <string.h>
#endif
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <zlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <sys/time.h>

#define BASELEVEL_REVISION  "3.3"

#undef TRUE
#undef FALSE

#define TRUE  (1)
#define FALSE (0)

#define NR_CPUS  (32)

#define BUFSIZE  (1500)
#define NULLCHAR ('\0')

#define MAXARGS    (100)   /* max number of arguments to one function */
#define MAXARGLEN  (40)   /* max length of argument */

#define HIST_BLKSIZE  (4096)

#define STREQ(A, B)      (A && B && (strcmp(A, B) == 0))
#define STRNEQ(A, B)     (A && B && (strncmp(A, B, strlen(B)) == 0))
#define BZERO(S, N)      (memset(S, NULLCHAR, N))
#define BCOPY(S, D, C)   (memcpy(D, S, C))
#define BNEG(S, N)       (memset(S, 0xff, N))
#define BEEP()           fprintf(stderr, "%c", 0x7)
#define LASTCHAR(s)      (s[strlen(s)-1])
#define FIRSTCHAR(s)     (s[0])
#define QUOTED_STRING(s) ((FIRSTCHAR(s) == '"') && (LASTCHAR(s) == '"'))

#define roundup(x, y)  ((((x)+((y)-1))/(y))*(y))

typedef unsigned long long int ulonglong;
struct number_option {
        ulong num;
        ulonglong ll_num;
};

/*
 *  program_context flags
 */
#define LIVE_SYSTEM                 (0x1)
#define TTY                         (0x2)
#define RUNTIME                     (0x4)
#define IN_FOREACH                  (0x8)
#define MCLXCD                     (0x10)
#define CMDLINE_IFILE              (0x20)
#define MFD_RDWR                   (0x40)
#define KFD_RDWR                   (0x80)
#define DFD_RDWR                  (0x100)
#define SILENT                    (0x200)
#define DAEMON                    (0x400)
#define HASH                      (0x800)
#define SCROLL                   (0x1000)
#define NO_CONSOLE               (0x2000)
#define RUNTIME_IFILE            (0x4000)
#define DROP_CORE                (0x8000)
#define LKCD                    (0x10000)
#define GDB_INIT                (0x20000)
#define IN_GDB                  (0x40000)
#define RCLOCAL_IFILE           (0x80000)
#define RCHOME_IFILE           (0x100000)
#define GET_TIMESTAMP          (0x200000)
#define READLINE               (0x400000) 
#define _SIGINT_               (0x800000)
#define IN_RESTART            (0x1000000)
#define KERNEL_DEBUG_QUERY    (0x2000000)
#define DEVMEM                (0x4000000)
#define REM_LIVE_SYSTEM       (0x8000000)
#define NAMELIST_LOCAL       (0x10000000)
#define MEMSRC_LOCAL         (0x20000000)
#define NAMELIST_SAVED       (0x40000000)
#define DUMPFILE_SAVED       (0x80000000)
#define UNLINK_NAMELIST     (0x100000000) 
#define NAMELIST_UNLINKED   (0x200000000)
#define REM_MCLXCD          (0x400000000)
#define REM_LKCD            (0x800000000)
#define NAMELIST_NO_GZIP   (0x1000000000)
#define UNLINK_MODULES     (0x2000000000)
#define S390D              (0x4000000000)
#define REM_S390D          (0x8000000000)
#define S390XD            (0x10000000000)
#define REM_S390XD        (0x20000000000)

#define ACTIVE()          (pc->flags & LIVE_SYSTEM)
#define DUMPFILE()        (!(pc->flags & LIVE_SYSTEM))
#define REMOTE()          (pc->flags & DAEMON)
#define REMOTE_ACTIVE()   (pc->flags & REM_LIVE_SYSTEM) 
#define REMOTE_DUMPFILE() \
		       (pc->flags & (REM_MCLXCD|REM_LKCD|REM_S390D|REM_S390XD))
#define REMOTE_MEMSRC()   (REMOTE_ACTIVE() || REMOTE_DUMPFILE())
#define LKCD_DUMPFILE()   (pc->flags & (LKCD|REM_LKCD))

#define MCLXDEBUG(x)  (pc->debug >= (x))

#define VERBOSE (0x1)
#define ADDRESS_SPECIFIED (0x2)

#define FAULT_ON_ERROR   (0x1)
#define RETURN_ON_ERROR  (0x2)
#define QUIET            (0x4)
#define HEX_BIAS         (0x8)
#define LONG_LONG       (0x10)

#define SEEK_ERROR       (-1)
#define READ_ERROR       (-2)
#define WRITE_ERROR      (-3)

#define RESTART()         (longjmp(pc->main_loop_env, 1))
#define RESUME_FOREACH()  (longjmp(pc->foreach_loop_env, 1))

#define INFO           (1)
#define FATAL          (2)
#define FATAL_RESTART  (3)
#define WARNING        (4)
#define FATAL_ERROR(x) (((x) == FATAL) || ((x) == FATAL_RESTART))

#define CONSOLE_OFF(x) ((x) = console_off())
#define CONSOLE_ON(x)  (console_on(x))

#define RADIX(X)   (X)

#define NUM_HEX  (0x1)
#define NUM_DEC  (0x2)
#define NUM_EXPR (0x4)
#define NUM_ANY  (NUM_HEX|NUM_DEC|NUM_EXPR)

/*
 *  program context redirect flags 
 */
#define FROM_COMMAND_LINE        (0x1)
#define FROM_INPUT_FILE          (0x2)
#define REDIRECT_NOT_DONE        (0x4)
#define REDIRECT_TO_PIPE         (0x8)
#define REDIRECT_TO_STDPIPE     (0x10)
#define REDIRECT_TO_FILE        (0x20)
#define REDIRECT_FAILURE        (0x40)
#define REDIRECT_SHELL_ESCAPE   (0x80)
#define REDIRECT_SHELL_COMMAND (0x100)
#define REDIRECT_PID_KNOWN     (0x200)
#define REDIRECT_MULTI_PIPE    (0x400)

#define PIPE_OPTIONS (FROM_COMMAND_LINE | FROM_INPUT_FILE | REDIRECT_TO_PIPE | \
                      REDIRECT_TO_STDPIPE | REDIRECT_TO_FILE)

/*
 *  structure definitions
 */
struct program_context {
	char *program_name;             /* this program's name */
	char *program_version;          /* this program's version */
	char *gdb_version;              /* embedded gdb version */
	char *prompt;                   /* this program's prompt */
	long long flags;                /* flags from above */
	char *namelist;         	/* linux namelist */
	char *dumpfile;         	/* dumpfile or /dev/kmem */ 
	char *machine_type;             /* machine's processor type */
	char *editing_mode;             /* readline vi or emacs */
	char *server;                   /* network daemon */
	char *server_memsrc;            /* memory source on server */
	char *server_namelist;          /* kernel namelist on server */
	int nfd;             		/* linux namelist fd */
	int kfd;			/* /dev/kmem fd */
	int mfd;			/* /dev/mmem fd */
	int dfd;			/* dumpfile fd */
	int confd;			/* console fd */
	int sockfd;                     /* network daemon socket */
	ushort port;                    /* network daemon port */
	int rmfd;                       /* remote server memory source fd */
	int rkfd;                       /* remote server /dev/kmem fd */
	ulong program_pid;              /* program pid */
	ulong server_pid;               /* server pid */
	ulong rcvbufsize;               /* client-side receive buffer size */
#ifdef USE_MMAP
	char *mmap_addr;                /* live system address mapping */
	ulong mmap_phys;                /* currently-mapped physical address */
	ulong remaps;                   /* count of mmap ops */
	ulong maphits;                  /* count of mmap'd page hits */
#endif
	char *home;                     /* user's home directory */
	char command_line[BUFSIZE];     /* possibly parsed input command line */
	char orig_line[BUFSIZE];        /* original input line */
	char *readline;                 /* pointer to last readline() return */
	char my_tty[10];                /* real tty name (shown by ps -ef) */
	ulong debug;                    /* level of debug */
	char *console;                  /* current debug console device */
	int pipefd[2];                  /* output pipe file descriptors */
	FILE *nullfp;                   /* bitbucket */
	FILE *stdpipe;                  /* standard pipe for output */
	FILE *pipe;                     /* command line specified pipe */
	FILE *ofile;                    /* command line specified output file */
	FILE *ifile;                    /* command line specified input file */
	FILE *ifile_pipe;               /* output pipe specified from file */
	FILE *ifile_ofile;              /* output file specified from file */
	FILE *symfile;                  /* symbol table data file */
	FILE *symfile2;                 /* alternate access to above */
	FILE *tmpfile;                  /* tmpfile for selective data output */
	FILE *saved_fp;                 /* for printing while parsing tmpfile */
	FILE *tmp_fp;                   /* stored tmpfile pointer */
	char *input_file;               /* input file specified at invocation */
	FILE *tmpfile2;                 /* tmpfile2 does not use save_fp! */
	int eoc_index;                  /* end of redirected command index */
	int scroll_command;             /* default scroll command for output */
#define SCROLL_NONE 0
#define SCROLL_LESS 1
#define SCROLL_MORE 2
	ulong redirect;			/* per-cmd origin and output flags */
	pid_t pipe_pid;                 /* per-cmd output pipe's pid */
	pid_t stdpipe_pid;              /* per-cmd standard output pipe's pid */
	char pipe_command[BUFSIZE];     /* pipe command line */
	char *symbol_file;              /* name of symbol table data file */
	int sym_maxline;                /* longest line in symbol file */
	char *curcmd;                   /* currently-executing command */
	char *lastcmd;                  /* previously-executed command */
	int cur_gdb_cmd;                /* current gdb command */
	int last_gdb_cmd;               /* previously-executed gdb command */
	int sigint_cnt;                 /* number of ignored SIGINTs */
	struct gnu_request *cur_req;    /* current gdb gnu_request */
	struct sigaction sigaction;     /* general usage sigaction. */
	struct sigaction gdb_sigaction; /* gdb's SIGINT sigaction. */
	jmp_buf main_loop_env;          /* longjmp target default */
	jmp_buf foreach_loop_env;       /* longjmp target within foreach */
        jmp_buf gdb_interface_env;      /* longjmp target for gdb error catch */
	struct termios termios_orig;    /* non-raw settings */
	struct termios termios_raw;     /* while gathering command input */
	int ncmds;                      /* number of commands in menu */
	char **cmdlist;                 /* current list of available commands */
	int cmdlistsz;                  /* space available in cmdlist */
	unsigned output_radix;          /* current gdb output_radix */
	void *sbrk;                     /* current sbrk value */
	struct extension_table *curext; /* extension being loaded */
        int (*readmem)(int, void *, int, ulong, ulong); /* memory access */
        int (*writemem)(int, void *, int, ulong, ulong); /* memory access */
};

#define READMEM  pc->readmem

typedef void (*cmd_func_t)(void);

struct command_table_entry {               /* one for each command in menu */
	char *name;
	cmd_func_t func;
	char **help_data;
	ulong flags;
};

#define REFRESH_TASK_TABLE (0x1)           /* command_table_entry flags */
#define HIDDEN_COMMAND     (0x2)

/*
 *  A linked list of extension table structures keeps track of the current
 *  set of shared library extensions.
 */
struct extension_table {
	void *handle;				    /* handle from dlopen() */
	char *filename;				    /* name of shared library */
	struct command_table_entry *command_table;  /* list of commands */
	ulong flags;                                /* registration flags */
	struct extension_table *next, *prev;        /* bookkeeping */
};

#define REGISTERED              (0x1)      /* extension_table flags */
#define DUPLICATE_COMMAND_NAME  (0x2)

struct new_utsname {
        char sysname[65];
        char nodename[65];
        char release[65];
        char version[65];
        char machine[65];
        char domainname[65];
};

#define NO_MODULE_ACCESS (0x1)

struct kernel_table {                   /* kernel data */
	ulong flags;
	ulong stext;
	ulong etext;
	ulong stext_init;
	ulong etext_init;
	ulong init_end;
	ulong end;
	int cpus;
	int smp;
	void (*display_bh)(void);
        ulong module_list;
        ulong kernel_module;
	int mods_installed;
	struct timespec date;
	char proc_version[BUFSIZE];
	struct new_utsname utsname;
};

#define SMP() (kt->smp)

struct task_context {                     /* context stored for each task */
        ulong task;
        ulong pid;
        char comm[16+1];
	int processor;
	ulong ptask;
	ulong mm_struct;
	struct task_context *tc_next;
};

struct task_table {                      /* kernel/local task table data */
	struct task_context *current;
	struct task_context *context_array;
	void (*refresh_task_table)(void);
	ulong flags;
        ulong task_start;
	ulong task_end;
	void *task_local;
        int nr_tasks;
	int nr_threads;
	ulong running_tasks;
	ulong retries;
        ulong panicmsg;
        int panic_processor;
        ulong idle_threads[NR_CPUS];
        ulong panic_threads[NR_CPUS];
	ulong panic_ksp[NR_CPUS];
	ulong current_set[NR_CPUS];
        ulong panic_task;
	ulong this_task;
	int pidhash_len;
	ulong pidhash_addr;
	ulong last_task_read;
	ulong last_mm_read;
	char *task_struct;
	char *mm_struct;
};

#define TASK_INIT_DONE       (0x1)
#define TASK_ARRAY_EXISTS    (0x2)
#define PANIC_TASK_NOT_FOUND (0x4)
#define TASK_REFRESH         (0x8)
#define TASK_REFRESH_OFF    (0x10)
#define PANIC_KSP           (0x20)

#define TASK_SLUSH (20)

#define NO_PROC_ID 0xFF       /* No processor magic marker (from kernel) */

/*
 *  Global "tt" points to task_table
 */
#define CURRENT_CONTEXT() (tt->current)
#define CURRENT_TASK()    (tt->current->task)
#define CURRENT_PID()     (tt->current->pid)
#define CURRENT_COMM()    (tt->current->comm)
#define RUNNING_TASKS()   (tt->running_tasks)
#define FIRST_CONTEXT()   (tt->context_array)

#define NO_PID   ((ulong)-1)
#define NO_TASK  (0)

#define IS_TASK_ADDR(X)    (machdep->is_task_addr(X))
#define GET_STACKBASE(X)   (machdep->get_stackbase(X))
#define GET_STACKTOP(X)    (machdep->get_stacktop(X))
#define STACKSIZE()        (machdep->stacksize)
#define LONGS_PER_STACK    (machdep->stacksize/sizeof(ulong))

#define INSTACK(X,BT) \
        (((ulong)(X) >= (BT)->stackbase) && ((ulong)(X) < (BT)->stacktop))

#define ALIGNED_STACK_OFFSET(task)  ((ulong)(task) & (STACKSIZE()-1))

#define BITS()		   (machdep->bits)
#define BITS32()           (machdep->bits == 32)
#define BITS64()           (machdep->bits == 64)
#define IS_KVADDR(X)       (machdep->is_kvaddr(X))
#define IS_UVADDR(X,C)     (machdep->is_uvaddr(X,C))
#define KVADDR_EXISTS(X)   (kvtop(NULL, X, NULL, 0))

#define HWRESET         (0x80000000)
#define SYSRQ           (0x40000000)
#define SYSRQ_TASK(X)   ((machdep->flags & SYSRQ) && is_task_active(X))

#define PID_ALIVE(x) (kill(x, 0) == 0)

struct stack_hook {
        ulong esp;
        ulong eip;
};

struct bt_info {
        ulong task;
        ulong flags;
        ulong instptr;
        ulong stkptr;
	ulong stackbase;
	ulong stacktop;
	struct task_context *tc;
        struct stack_hook *hp;
        struct reference *ref;
	char *stackbuf;
        ulong debug;
};

#define STACK_OFFSET_TYPE(OFF) \
  (((ulong)(OFF) > STACKSIZE()) ? \
  (ulong)((ulong)(OFF) - (ulong)(bt->stackbase)) : (ulong)(OFF)) 

#define GET_STACK_ULONG(OFF) \
 *((ulong *)((char *)(&bt->stackbuf[(ulong)(STACK_OFFSET_TYPE(OFF))])))

#define GET_STACK_DATA(OFF, LOC, SZ) memcpy((void *)(LOC), \
    (void *)(&bt->stackbuf[(ulong)STACK_OFFSET_TYPE(OFF)]), (size_t)(SZ))

struct machine_specific;  /* uniquely defined in each machine's module */

struct machdep_table {
	ulong flags;
	ulong kvbase;
	ulong identity_map_base;
	uint pagesize;
	uint pageshift;
	ulong pagemask;
	ulong pageoffset;
	ulong stacksize;
	uint hz;
	ulong mhz;
	int bits;
	uint64_t memsize;
        void (*eframe_search)(struct bt_info *);
        void (*back_trace)(struct bt_info *);
        ulong (*processor_speed)(void);
        int (*uvtop)(struct task_context *, ulong, ulong *, int);
        int (*kvtop)(struct task_context *, ulong, ulong *, int);
        ulong (*get_task_pgd)(ulong);
	void (*dump_irq)(int);
	int (*nr_irqs)(void);
	void (*get_stack_frame)(struct bt_info *, ulong *, ulong *);
	ulong (*get_stackbase)(ulong);
	ulong (*get_stacktop)(ulong);
	int (*translate_pte)(ulong, ulong *);
	uint64_t (*memory_size)(void);
	ulong (*vmalloc_start)(void);
	ulong (*SWP_TYPE)(ulong);
	ulong (*SWP_OFFSET)(ulong);
        int (*is_task_addr)(ulong);
	int (*verify_symbol)(const char *, ulong);
	int (*dis_filter)(ulong, char *);
	int (*get_smp_cpus)(void);
        int (*is_kvaddr)(ulong);
        int (*is_uvaddr)(ulong, struct task_context *);
	void (*cmd_mach)(void);
	ulong last_pgd_read;
	ulong last_pmd_read;
	ulong last_ptbl_read;
	char *pgd;
 	char *pmd;	
	char *ptbl;
	struct machine_specific *machspec;
};

extern struct machdep_table *machdep;

#define IS_LAST_PGD_READ(pgd)     ((ulong)(pgd) == machdep->last_pgd_read)
#define IS_LAST_PMD_READ(pmd)     ((ulong)(pmd) == machdep->last_pmd_read)
#define IS_LAST_PTBL_READ(ptbl)   ((ulong)(ptbl) == machdep->last_ptbl_read)

#define FILL_PGD(PGD, TYPE, SIZE) 					    \
    if (!IS_LAST_PGD_READ(PGD)) {                                           \
            readmem((ulong)(PGD), TYPE, machdep->pgd,                       \
                    SIZE, "fill pgd", FAULT_ON_ERROR);                      \
            machdep->last_pgd_read = (ulong)(PGD);                          \
    }								            

#define FILL_PMD(PMD, TYPE, SIZE)			                    \
    if (!IS_LAST_PMD_READ(PMD)) {                                           \
            readmem((ulong)(PMD), TYPE, machdep->pmd,                       \
	            SIZE, "fill pmd", FAULT_ON_ERROR);                      \
            machdep->last_pmd_read = (ulong)(PMD);                          \
    }					                                    

#define FILL_PTBL(PTBL, TYPE, SIZE)			           	    \
    if (!IS_LAST_PTBL_READ(PTBL)) {                                         \
    	    readmem((ulong)(PTBL), TYPE, machdep->ptbl,                     \
	            SIZE, "fill ptbl", FAULT_ON_ERROR);                     \
            machdep->last_ptbl_read = (ulong)(PTBL); 	                    \
    }

#define PRE_SYMTAB (1)
#define PRE_GDB    (2)
#define POST_GDB   (3)
#define POST_INIT  (4)

#define FOREACH_BT     (1)
#define FOREACH_VM     (2)
#define FOREACH_TASK   (3)
#define FOREACH_SET    (4)
#define FOREACH_FILES  (5)
#define FOREACH_NET    (6)
#define FOREACH_TEST   (7)
#define FOREACH_VTOP   (8)
#define FOREACH_SIG    (9)

#define MAX_FOREACH_KEYWORDS (10)
#define MAX_FOREACH_TASKS    (50)
#define MAX_FOREACH_PIDS     (50)
#define MAX_FOREACH_COMMS    (50)
#define MAX_FOREACH_ARGS     (50)

#define FOREACH_CMD          (0x1)
#define FOREACH_r_FLAG       (0x2)
#define FOREACH_s_FLAG       (0x4)
#define FOREACH_S_FLAG       (0x8)
#define FOREACH_i_FLAG      (0x10)
#define FOREACH_e_FLAG      (0x20)
#define FOREACH_g_FLAG      (0x40)
#define FOREACH_l_FLAG      (0x80)
#define FOREACH_p_FLAG     (0x100)
#define FOREACH_t_FLAG     (0x200)
#define FOREACH_u_FLAG     (0x400)
#define FOREACH_m_FLAG     (0x800)
#define FOREACH_v_FLAG    (0x1000)
#define FOREACH_KERNEL    (0x2000)
#define FOREACH_USER      (0x4000)
#define FOREACH_SPECIFIED (0x8000)
#define FOREACH_ACTIVE   (0x10000)
#define FOREACH_k_FLAG   (0x20000)
#define FOREACH_c_FLAG   (0x40000)

struct foreach_data {
	ulong flags;
        int keyword_array[MAX_FOREACH_KEYWORDS];
        ulong task_array[MAX_FOREACH_TASKS];
        char *comm_array[MAX_FOREACH_COMMS];
        ulong pid_array[MAX_FOREACH_PIDS];
	ulong arg_array[MAX_FOREACH_ARGS];
	char *reference;
	int keys;
	int pids;
	int tasks;
	int comms;
	int args;
};

struct reference {       
        char *str;       
        ulong cmdflags;  
        ulong hexval;     
        ulong decval;     
        ulong ref1;
        ulong ref2;
	void *refp;
};

struct offset_table {                    /* stash of commonly-used offsets */
	long list_head_next;
	long task_struct_pid;
	long task_struct_state;
	long task_struct_comm;
	long task_struct_mm;
	long task_struct_tss;
	long task_struct_thread;
	long task_struct_active_mm;
	long task_struct_tss_eip;
	long task_struct_tss_esp;
	long task_struct_tss_ksp;
	long task_struct_processor;
	long task_struct_p_pptr;
	long task_struct_has_cpu;
	long task_struct_cpus_runnable;
	long task_struct_thread_eip;
	long task_struct_thread_esp;
	long task_struct_thread_ksp;
	long task_struct_next_task;
	long task_struct_files;
	long task_struct_fs;
	long task_struct_pidhash_next;
	long task_struct_next_run;
	long task_struct_flags;
	long task_struct_sig;
	long task_struct_signal;
	long task_struct_blocked;
	long task_struct_sigpending;
	long task_struct_pending;
	long task_struct_sigqueue;
	long task_struct_start_time;
	long task_struct_times;
	long tms_tms_utime;
	long tms_tms_stime;
	long signal_struct_count;
	long signal_struct_action;
	long k_sigaction_sa;
	long sigaction_sa_handler;
	long sigaction_sa_flags;
	long sigaction_sa_mask;
	long sigpending_head;
	long sigpending_signal;
	long signal_queue_next;
	long signal_queue_info;
	long sigqueue_next;
	long sigqueue_info;
	long siginfo_si_signo;
	long thread_struct_cr3;
	long thread_struct_ptbr;
	long thread_struct_pg_tables;
	long switch_stack_r26;
	long switch_stack_b0;
	long switch_stack_ar_bspstore;
	long switch_stack_ar_pfs;
	long switch_stack_ar_rnat;
	long hwrpb_struct_cycle_freq;
	long hwrpb_struct_processor_offset;
	long hwrpb_struct_processor_size;
	long percpu_struct_halt_PC;
	long percpu_struct_halt_ra;
	long percpu_struct_halt_pv;
	long mm_struct_mmap;
	long mm_struct_pgd;
	long mm_struct_rss;
	long mm_struct_total_vm;
	long mm_struct_start_code;
        long vm_area_struct_vm_mm;
        long vm_area_struct_vm_next;
        long vm_area_struct_vm_end;
        long vm_area_struct_vm_start; 
	long vm_area_struct_vm_flags;
	long vm_area_struct_vm_file;
	long vm_area_struct_vm_offset;
	long vm_area_struct_vm_pgoff;
        long vm_struct_addr;
        long vm_struct_size;
        long vm_struct_next;
	long module_size_of_struct;
	long module_next;
	long module_size;
	long module_name;
	long module_nsyms;
	long module_syms;
	long module_flags;
	long page_next;
	long page_prev;
	long page_next_hash;
	long page_list_next;
	long page_list_prev;
	long page_inode;
	long page_offset;
	long page_count;
	long page_flags;
	long page_mapping;
	long page_index;
	long page_buffers;
	long page_lru;
	long swap_info_struct_swap_file;
	long swap_info_struct_swap_vfsmnt;
	long swap_info_struct_flags;
	long swap_info_struct_swap_map;
	long swap_info_struct_swap_device;
	long swap_info_struct_prio;
	long swap_info_struct_max;
	long swap_info_struct_pages;
	long irq_desc_t_status;
	long irq_desc_t_handler;
	long irq_desc_t_action;
	long irq_desc_t_depth;
	long irqdesc_action;
	long irqdesc_ctl;
	long irqdesc_level;
	long irqaction_handler;
	long irqaction_flags;
	long irqaction_mask;
	long irqaction_name;
	long irqaction_dev_id;
	long irqaction_next;
	long hw_interrupt_type_typename;
	long hw_interrupt_type_startup;
	long hw_interrupt_type_shutdown;
	long hw_interrupt_type_handle;
	long hw_interrupt_type_enable;
	long hw_interrupt_type_disable;
	long hw_interrupt_type_ack;
	long hw_interrupt_type_end;
	long hw_interrupt_type_set_affinity;
	long irq_cpustat_t___softirq_active;
	long irq_cpustat_t___softirq_mask;
        long files_struct_max_fds;
        long files_struct_max_fdset;
        long files_struct_open_fds;
        long files_struct_fd;
	long files_struct_open_fds_init;
        long file_f_dentry;
        long file_f_vfsmnt;
        long file_f_count;
        long fs_struct_root;
        long fs_struct_pwd;
        long fs_struct_rootmnt;
        long fs_struct_pwdmnt;
        long dentry_d_inode;
        long dentry_d_parent;
        long dentry_d_name;
	long dentry_d_covers;
	long dentry_d_iname;
        long qstr_len;
        long qstr_name;
        long inode_i_mode;
        long inode_i_op;
        long inode_i_sb;
	long inode_u;
	long inode_i_flock;
	long inode_i_fop;
	long vfsmount_mnt_next;
	long vfsmount_mnt_devname;
	long vfsmount_mnt_dirname;
	long vfsmount_mnt_sb;
	long vfsmount_mnt_list;
	long vfsmount_mnt_mountpoint;
	long vfsmount_mnt_parent;
	long super_block_s_dirty;
	long super_block_s_type;
	long super_block_s_files;
	long file_system_type_name;
	long nlm_file_f_file;
	long file_lock_fl_owner;
	long nlm_host_h_exportent;
	long svc_client_cl_ident;
	long kmem_cache_s_c_nextp;
	long kmem_cache_s_c_name;
	long kmem_cache_s_c_num;
	long kmem_cache_s_c_org_size;
	long kmem_cache_s_c_flags;
	long kmem_cache_s_c_offset;
	long kmem_cache_s_c_firstp;
	long kmem_cache_s_c_gfporder;
	long kmem_cache_s_c_magic;
	long kmem_cache_s_num;
	long kmem_cache_s_next;
	long kmem_cache_s_name;
	long kmem_cache_s_objsize;
	long kmem_cache_s_flags;
	long kmem_cache_s_gfporder;
	long kmem_cache_s_slabs;
	long kmem_cache_s_slabs_full;
	long kmem_cache_s_slabs_partial;
	long kmem_cache_s_slabs_free;
	long kmem_cache_s_cpudata;
	long kmem_cache_s_c_align;
	long kmem_cache_s_colour_off;
	long cpucache_s_avail;
	long cpucache_s_limit;
	long kmem_slab_s_s_nextp;
	long kmem_slab_s_s_freep;
	long kmem_slab_s_s_inuse;
	long kmem_slab_s_s_mem;
	long kmem_slab_s_s_index;
	long kmem_slab_s_s_offset;
	long kmem_slab_s_s_magic;
	long slab_s_list;
	long slab_s_s_mem;
	long slab_s_inuse;
	long slab_s_free;
	long socket_sk;
	long sock_daddr;
	long sock_rcv_saddr;
	long sock_dport;
	long sock_num;
	long sock_type;
	long sock_family;
	long timer_list_list;
	long timer_list_next;
	long timer_list_expires;
	long timer_list_function;
	long timer_vec_root_vec;
	long timer_vec_vec;
	long pglist_data_node_zones;
	long pglist_data_node_mem_map;
	long pglist_data_node_start_paddr;
        long pglist_data_node_start_mapnr;
        long pglist_data_node_size;
        long pglist_data_node_id;
        long pglist_data_node_next;
	long pglist_data_bdata;
        long zone_struct_free_pages;
        long zone_struct_free_area;
        long zone_struct_zone_pgdat;
        long zone_struct_name;
        long zone_struct_size;
        long zone_struct_zone_start_paddr;
        long zone_struct_zone_start_mapnr;
        long zone_struct_zone_mem_map;
	long zone_struct_inactive_clean_pages;
	long zone_struct_inactive_clean_list;
        long neighbour_next;
        long neighbour_primary_key;
        long neighbour_ha;
        long neighbour_dev;
        long neighbour_nud_state;
	long neigh_table_hash_buckets;
	long neigh_table_key_len;
        long in_device_ifa_list;
        long in_ifaddr_ifa_next;
        long in_ifaddr_ifa_address;
	long pci_dev_global_list;
	long pci_dev_next;
	long pci_dev_bus;
	long pci_dev_devfn;
	long pci_dev_class;
	long pci_dev_device;
	long pci_dev_vendor;
	long pci_bus_number;
        long resource_entry_t_from;
        long resource_entry_t_num;
        long resource_entry_t_name; 
        long resource_entry_t_next;
        long resource_name;
        long resource_start;
        long resource_end;
        long resource_sibling;
        long resource_child;
};

struct size_table {         /* stash of commonly-used sizes */
	long page;
	long free_area_struct;
	long zone_struct;
	long kmem_slab_s;
	long kmem_cache_s;
	long kmem_bufctl_t;
	long slab_s;
	long cpucache_s;
	long swap_info_struct;
	long mm_struct;
	long vm_area_struct;
	long pt_regs;
	long task_struct;
	long softirq_state;
	long desc_struct;
	long umode_t;
	long dentry;
	long files_struct;
	long fs_struct;
	long file;
	long inode;
	long vfsmount;
	long super_block;
        long irqdesc;
	long module;
	long list_head;
	long irq_cpustat_t;
	long cpuinfo_x86;
	long cpuinfo_ia64;
	long timer_list;
	long timer_vec_root;
	long timer_vec;
	long sock;
	long signal_struct;
	long signal_queue;
	long sigqueue;
	long k_sigaction;
	long resource_entry_t;
	long resource;
};

#define INVALID_MEMBER     (-1)
#define OFFSET(X)          (offset_table.X)
#define VALID_OFFSET(X)    (offset_table.X >= 0)
#define INVALID_OFFSET(X)  (offset_table.X == INVALID_MEMBER)
#define SIZE(X)            (size_table.X)
#define INVALID_SIZE(X)    (size_table.X == -1)
#define VALID_SIZE(X)      (size_table.X >= 0)

#define INT(ADDR)       *((int *)((char *)(ADDR)))
#define UINT(ADDR)      *((uint *)((char *)(ADDR)))
#define LONG(ADDR)      *((long *)((char *)(ADDR)))
#define ULONG(ADDR)     *((ulong *)((char *)(ADDR)))
#define ULONG_PTR(ADDR) *((ulong **)((char *)(ADDR)))
#define USHORT(ADDR)    *((ushort *)((char *)(ADDR)))
#define VOID_PTR(ADDR)  *((void **)((char *)(ADDR)))

struct numa_table {
	int node_id;
	ulong pgdat;
	ulong mem_map;
	ulong size;
	ulong start_paddr;
	ulong start_mapnr;
};

struct meminfo;
struct slab_data;

#define VMA_CACHE   (20)

struct vm_table {                /* kernel VM-related data */
	ulong flags;
	ulong kernel_pgd;
	ulong high_memory;
	ulong vmalloc_start;
	ulong mem_map;
	long total_pages;
	ulong totalram_pages;
	ulong max_mapnr;
	ulong kmem_max_c_num;
	ulong kmem_max_limit;
	ulong kmem_max_cpus;
	ulong kmem_cache_count;
	int paddr_prlen;
	int numnodes;
	struct numa_table *numa_table;
        void (*dump_free_pages)(struct meminfo *);
	void (*dump_kmem_cache)(struct meminfo *);
	struct slab_data *slab_data;
	uint nr_swapfiles;
	ulong last_swap_read;
	char *swap_info_struct;
        char *vma_cache;
        ulong cached_vma[VMA_CACHE];
        ulong cached_vma_hits[VMA_CACHE];
        int vma_cache_index;
        ulong vma_cache_fills;
};

#define NUMA           (0x1)
#define ZONES          (0x2)
#define PERCPU_KMALLOC (0x4)
#define COMMON_VADDR   (0x8)

#define COMMON_VADDR_SPACE() (vt->flags & COMMON_VADDR)
#define PADDR_PRLEN          (vt->paddr_prlen)

struct datatype_member {        /* minimal definition of a structure/union */
	char *name;             /* and possibly a member within it */
	char *member;
	ulong type;
	long size;
	long member_offset;
	ulong flags;
	char *tagname;         /* tagname and value for enums */
	long value;
};

#define union_name struct_name

struct list_data {             /* generic structure used by do_list() to walk */
        ulong flags;           /* through linked lists in the kernel */
        ulong start;
        long member_offset;
	long list_head_offset;
        ulong end;
	ulong searchfor;
	char *structname;
	char *header;
};
#define RETURN_ON_DUPLICATE  (VERBOSE << 1)

#define ALIAS_RUNTIME  (1)
#define ALIAS_RCLOCAL  (2)
#define ALIAS_RCHOME   (3)
#define ALIAS_BUILTIN  (4)

struct alias_data {                 /* command alias storage */
	struct alias_data *next;
	char *alias;
	int argcnt;
	int size;
	int origin;
	char *args[MAXARGS];
	char argbuf[1];
};

#endif /* !GDB_COMMON */


struct syment {
        ulong value;
	char type;
        char *name;
	struct syment *val_hash_next;
};
                
#define NAMESPACE_INIT     (1)
#define NAMESPACE_REUSE    (2)
#define NAMESPACE_FREE     (3)
#define NAMESPACE_INSTALL  (4)
#define NAMESPACE_COMPLETE (5)

struct namespace {
	char *address;
	size_t size;
	long index;
	long cnt;
};

#define SYMVAL_HASH (512)
#define SYMVAL_HASH_INDEX(vaddr) \
        (((vaddr) >> machdep->pageshift) % SYMVAL_HASH)

#define SYMNAME_HASH (8)    
#define SYMNAME_HASH_INDEX(name) (((name[0] ^ strlen(name))) % SYMNAME_HASH)

#ifndef GDB_COMMON

struct symbol_table_data {
	ulong flags;
	struct _bfd *bfd;
	struct sec *sections;
	struct syment *symtable;
	struct syment *symend;
	long symcnt;
	ulong syment_size;
        struct symval_hash_chain {
                struct syment *val_hash_head;
                struct syment *val_hash_last;
        } symval_hash[SYMVAL_HASH];
        double val_hash_searches;
        double val_hash_iterations;
	struct symname_hash_entry {
		struct syment *sp;
		struct symname_hash_entry *next;
	} *symname_hash[SYMNAME_HASH];
	struct namespace namespace;
	struct syment *ext_module_symtable;
	struct syment *ext_module_symend;
	long ext_module_symcnt;
	struct namespace ext_module_namespace;
	int mods_installed;
	struct load_module *current;
	struct load_module *load_modules;
};

#define KERNEL_SYMS       (0x1)
#define MODULE_SYMS       (0x2)
#define LOAD_MODULE_SYMS  (0x4)
#define DATATYPE_INIT     (0x8)
#define INSMOD_BUILTIN    (0x10)

#endif /* !GDB_COMMON */

#define MAX_MOD_NAMELIST (128)
#define MAX_MOD_NAME     (32)
#define MAX_MOD_SEC_NAME (32)
#define MOD_MAX_SECTIONS (20)

#define MOD_EXT_SYMS    (0x1)
#define MOD_LOAD_SYMS   (0x2)
#define MOD_REMOTE      (0x4)

struct load_module {
        ulong mod_base;
        long mod_size;
        char mod_namelist[MAX_MOD_NAMELIST];
        char mod_name[MAX_MOD_NAME];
        ulong mod_flags;
	struct syment *mod_symtable;
	struct syment *mod_symend;
        long mod_ext_symcnt;
	struct syment *mod_ext_symtable;
	struct syment *mod_ext_symend;
        long mod_load_symcnt;
        struct syment *mod_load_symtable;
        struct syment *mod_load_symend;
        long mod_symalloc;
	struct namespace mod_load_namespace;
	ulong mod_size_of_struct;
        ulong mod_text_start;
	ulong mod_etext_guess;
	ulong mod_rodata_start;
        ulong mod_data_start;
	ulong mod_bss_start;
	int mod_sections;
	struct mod_section_data {
        	struct sec *section;
		char name[MAX_MOD_SEC_NAME];
		ulong offset;
		ulong size;
        	int priority;
		int flags;
	} mod_section_data[MOD_MAX_SECTIONS];
};

#define IN_MODULE(A,L) \
 (((ulong)(A) >= (L)->mod_base) && ((ulong)(A) < ((L)->mod_base+(L)->mod_size)))

#ifndef GDB_COMMON

#define KVADDR             (0x1)
#define UVADDR             (0x2)
#define PHYSADDR           (0x4)
#define AMBIGUOUS          (~0)

#define USE_USER_PGD       (UVADDR << 2)

#define VERIFY_ADDR        (0x8)   /* vm_area_dump() flags -- must follow */
#define PRINT_INODES      (0x10)   /* KVADDR, UVADDR, and PHYSADDR */
#define PRINT_MM_STRUCT   (0x20)
#define PRINT_VMA_STRUCTS (0x40)

#define MIN_PAGE_SIZE  (4096)

#define PTOB(X)       ((ulong)(X) << machdep->pageshift)
#define BTOP(X)       ((ulong)(X) >> machdep->pageshift)

#define PAGESIZE()    (machdep->pagesize)
#define PAGESHIFT()   (machdep->pageshift)

#define PAGEOFFSET(X) (((ulong)(X)) & machdep->pageoffset)
#define PAGEBASE(X)   (((ulong)(X)) & machdep->pagemask)

/*
 *  Machine specific stuff
 */

#ifdef X86
#define _32BIT_
#define MACHINE_TYPE       "X86"
#define PTOV(X)            ((unsigned long)(X)+(machdep->kvbase))
#define VTOP(X)            ((unsigned long)(X)-(machdep->kvbase))
#define IS_VMALLOC_ADDR(X) ((ulong)(X) >= vt->vmalloc_start)
#define KVBASE_MASK        (0x1fffff)
#define VMALLOC_OFFSET     (8*1024*1024)

#define PGDIR_SHIFT   (22)
#define PTRS_PER_PTE  (1024)
#define PTRS_PER_PGD  (1024)

#define _PAGE_PRESENT   0x001
#define _PAGE_RW        0x002
#define _PAGE_USER      0x004
#define _PAGE_PWT       0x008
#define _PAGE_PCD       0x010
#define _PAGE_ACCESSED  0x020
#define _PAGE_DIRTY     0x040
#define _PAGE_4M        0x080   /* 4 MB page, Pentium+, if present.. */
#define _PAGE_PSE       0x080   /* 4 MB (or 2MB) page, Pentium+, if present.. */
#define _PAGE_GLOBAL    0x100   /* Global TLB entry PPro+ */
#define _PAGE_PROTNONE  0x080   /* If not present */
#endif  /* X86 */

#ifdef ALPHA
#define _64BIT_
#define MACHINE_TYPE       "ALPHA"

#define PTOV(X)            ((unsigned long)(X)+(machdep->kvbase))
#define VTOP(X)            ((unsigned long)(X)-(machdep->kvbase))
#define IS_VMALLOC_ADDR(X) ((ulong)(X) >= vt->vmalloc_start)
#define KSEG_BASE_48_BIT   (0xffff800000000000)
#define KSEG_BASE          (0xfffffc0000000000)
#define _PFN_MASK          (0xFFFFFFFF00000000)
#define VMALLOC_START      (0xFFFFFE0000000000)
#define MIN_SYMBOL_VALUE   (KSEG_BASE_48_BIT)

#define PGDIR_SHIFT     (PAGESHIFT() + 2*(PAGESHIFT()-3))
#define PMD_SHIFT       (PAGESHIFT() + (PAGESHIFT()-3))
#define PTRS_PER_PAGE   (1024)
/*
 * OSF/1 PAL-code-imposed page table bits
 */
#define _PAGE_VALID     0x0001
#define _PAGE_FOR       0x0002  /* used for page protection (fault on read) */
#define _PAGE_FOW       0x0004  /* used for page protection (fault on write) */
#define _PAGE_FOE       0x0008  /* used for page protection (fault on exec) */
#define _PAGE_ASM       0x0010
#define _PAGE_KRE       0x0100  /* xxx - see below on the "accessed" bit */
#define _PAGE_URE       0x0200  /* xxx */
#define _PAGE_KWE       0x1000  /* used to do the dirty bit in software */
#define _PAGE_UWE       0x2000  /* used to do the dirty bit in software */

/* .. and these are ours ... */
#define _PAGE_DIRTY     0x20000
#define _PAGE_ACCESSED  0x40000
#endif  /* ALPHA */

#ifdef PPC
#define _32BIT_
#define MACHINE_TYPE       "PPC"

#define PTOV(X)            ((unsigned long)(X)+(machdep->kvbase))
#define VTOP(X)            ((unsigned long)(X)-(machdep->kvbase))
#define IS_VMALLOC_ADDR(X) ((ulong)(X) >= vt->vmalloc_start)
#define VMALLOC_OFFSET     (0x4000000)    /* 64M */

#define PGDIR_SHIFT   (22)
#define PTRS_PER_PTE  (1024)
#define PTRS_PER_PGD  (1024)

#define _PAGE_PRESENT   0x001   /* software: pte contains a translation */
#define _PAGE_USER      0x002   /* matches one of the PP bits */
#define _PAGE_RW        0x004   /* software: user write access allowed */
#define _PAGE_GUARDED   0x008
#define _PAGE_COHERENT  0x010   /* M: enforce memory coherence (SMP systems) */
#define _PAGE_NO_CACHE  0x020   /* I: cache inhibit */
#define _PAGE_WRITETHRU 0x040   /* W: cache write-through */
#define _PAGE_DIRTY     0x080   /* C: page changed */
#define _PAGE_ACCESSED  0x100   /* R: page referenced */
#define _PAGE_HWWRITE   0x200   /* software: _PAGE_RW & _PAGE_DIRTY */
#define _PAGE_SHARED    0
#endif  /* PPC */

#ifdef IA64
#define _64BIT_
#define MACHINE_TYPE          "IA64"

#define REGION_SHIFT           (61)
#define VADDR_REGION(X)        ((ulong)(X) >> REGION_SHIFT)

#define KERNEL_CACHED_REGION   (7)
#define KERNEL_UNCACHED_REGION (6)
#define KERNEL_VMALLOC_REGION  (5)
#define USER_STACK_REGION      (4)
#define USER_DATA_REGION       (3)
#define USER_TEXT_REGION       (2)
#define USER_SHMEM_REGION      (1)
#define USER_IA32_EMUL_REGION  (0)

#define KERNEL_VMALLOC_BASE   ((ulong)KERNEL_VMALLOC_REGION << REGION_SHIFT)
#define KERNEL_UNCACHED_BASE  ((ulong)KERNEL_UNCACHED_REGION << REGION_SHIFT)
#define KERNEL_CACHED_BASE    ((ulong)KERNEL_CACHED_REGION << REGION_SHIFT)

#define PTOV(X)               ((ulong)(X) + (ulong)(KERNEL_CACHED_BASE))
#define VTOP(X)               ((ulong)(X) - (ulong)(KERNEL_CACHED_BASE))
#define IS_VMALLOC_ADDR(X)    (((ulong)(X) >= (ulong)KERNEL_VMALLOC_BASE) && \
			         ((ulong)(X) < (ulong)KERNEL_UNCACHED_BASE))
#define MIN_SYMBOL_VALUE      ((ulong)(KERNEL_CACHED_BASE))

#define SWITCH_STACK_ADDR(X)  (ia64_get_thread_ksp((ulong)(X))+16)

#define PGDIR_SHIFT     (PAGESHIFT() + 2*(PAGESHIFT()-3))
#define PMD_SHIFT       (PAGESHIFT() + (PAGESHIFT()-3))
#define PTRS_PER_PGD    (((ulong)(1)) << (PAGESHIFT()-3))
#define PTRS_PER_PMD    (((ulong)(1)) << (PAGESHIFT()-3))
#define PTRS_PER_PTE    (((ulong)(1)) << (PAGESHIFT()-3))
#define PTRS_PER_PAGE   (((ulong)(1)) << (PAGESHIFT()-3))
#define __IA64_UL(x)           ((unsigned long)(x))
#define IA64_MAX_PHYS_BITS  (50)  /* max # of phys address bits (architected) */

/*
 * First, define the various bits in a PTE.  Note that the PTE format
 * matches the VHPT short format, the firt doubleword of the VHPD long
 * format, and the first doubleword of the TLB insertion format.
 */
#define _PAGE_P			(1 <<  0)       /* page present bit */
#define _PAGE_MA_WB		(0x0 <<  2)	/* write back memory attribute */
#define _PAGE_MA_UC		(0x4 <<  2)	/* uncacheable memory attribute */
#define _PAGE_MA_UCE		(0x5 <<  2)	/* UC exported attribute */
#define _PAGE_MA_WC		(0x6 <<  2)	/* write coalescing memory attribute */
#define _PAGE_MA_NAT		(0x7 <<  2)	/* not-a-thing attribute */
#define _PAGE_MA_MASK		(0x7 <<  2)
#define _PAGE_PL_0		(0 <<  7)	/* privilege level 0 (kernel) */
#define _PAGE_PL_1		(1 <<  7)	/* privilege level 1 (unused) */
#define _PAGE_PL_2		(2 <<  7)	/* privilege level 2 (unused) */
#define _PAGE_PL_3		(3 <<  7)	/* privilege level 3 (user) */
#define _PAGE_PL_MASK		(3 <<  7)
#define _PAGE_AR_R		(0 <<  9)	/* read only */
#define _PAGE_AR_RX		(1 <<  9)	/* read & execute */
#define _PAGE_AR_RW		(2 <<  9)	/* read & write */
#define _PAGE_AR_RWX		(3 <<  9)	/* read, write & execute */
#define _PAGE_AR_R_RW		(4 <<  9)	/* read / read & write */
#define _PAGE_AR_RX_RWX		(5 <<  9)	/* read & exec / read, write & exec */
#define _PAGE_AR_RWX_RW		(6 <<  9)	/* read, write & exec / read & write */
#define _PAGE_AR_X_RX		(7 <<  9)	/* exec & promote / read & exec */
#define _PAGE_AR_MASK		(7 <<  9)
#define _PAGE_AR_SHIFT		9
#define _PAGE_A			(1 <<  5)	/* page accessed bit */
#define _PAGE_D			(1 <<  6)	/* page dirty bit */
#define _PAGE_PPN_MASK		(((__IA64_UL(1) << IA64_MAX_PHYS_BITS) - 1) & ~0xfffUL)
#define _PAGE_ED		(__IA64_UL(1) << 52)	/* exception deferral */
#define _PAGE_PROTNONE		(__IA64_UL(1) << 63)

#define _PFN_MASK		_PAGE_PPN_MASK
#define _PAGE_CHG_MASK		(_PFN_MASK | _PAGE_A | _PAGE_D)

#define _PAGE_SIZE_4K	12
#define _PAGE_SIZE_8K	13
#define _PAGE_SIZE_16K	14
#define _PAGE_SIZE_64K	16
#define _PAGE_SIZE_256K	18
#define _PAGE_SIZE_1M	20
#define _PAGE_SIZE_4M	22
#define _PAGE_SIZE_16M	24
#define _PAGE_SIZE_64M	26
#define _PAGE_SIZE_256M	28

#define __ACCESS_BITS		_PAGE_ED | _PAGE_A | _PAGE_P | _PAGE_MA_WB
#define __DIRTY_BITS_NO_ED	_PAGE_A | _PAGE_P | _PAGE_D | _PAGE_MA_WB
#define __DIRTY_BITS		_PAGE_ED | __DIRTY_BITS_NO_ED
#endif  /* IA64 */

#ifdef S390
#define _32BIT_
#define MACHINE_TYPE       "S390"

#define PTOV(X)            ((unsigned long)(X)+(machdep->kvbase))
#define VTOP(X)            ((unsigned long)(X)-(machdep->kvbase))
#define IS_VMALLOC_ADDR(X) ((ulong)(X) >= vt->vmalloc_start)
#define VMALLOC_OFFSET     (8*1024*1024)
#define VMALLOC_END        (0x7fffffffL)

#define IS_LOWCORE(X)  ((unsigned long)(X) < (unsigned long)(machdep->pagesize))

#define PMD_SHIFT       22
#define PMD_SIZE        (1UL << PMD_SHIFT)
#define PMD_MASK        (~(PMD_SIZE-1))
#define PGDIR_SHIFT     22
#define PGDIR_SIZE      (1UL << PGDIR_SHIFT)
#define PGDIR_MASK      (~(PGDIR_SIZE-1))
#define PTRS_PER_PTE    1024
#define PTRS_PER_PMD    1
#define PTRS_PER_PGD    512
/* 
 * pgd_t swapper_pg_dir[PTRS_PER_PGD]  NOTE: w/4 ulongs per pgd_t 
 */
#define SEGMENT_TABLE_SIZE  ((sizeof(ulong)*4) * PTRS_PER_PGD)  
#define _PAGE_TABLE_INV     0x20        /* invalid in segment table */
#define PAGE_TABLE_ORIGIN   (0x7fffffc0)

/* PTE bit translation -- NOTE: changes in 2.4.13 */
#define _PAGE_PRESENT   0x001          /* Software                         */
#define _PAGE_INVALID   0x400          /* HW invalid                       */

#endif  /* S390 */

#ifdef S390X
#define _64BIT_
#define MACHINE_TYPE       "S390X"

#define PTOV(X)            ((unsigned long)(X)+(machdep->kvbase))
#define VTOP(X)            ((unsigned long)(X)-(machdep->kvbase))
#define IS_VMALLOC_ADDR(X) ((ulong)(X) >= vt->vmalloc_start)
#define VMALLOC_OFFSET     (8*1024*1024)
#define VMALLOC_END        (0x40000000000L)

#define IS_LOWCORE(X) \
	          ((unsigned long)(X) < ((unsigned long)(machdep->pagesize)*2))

#define PMD_SHIFT       21
#define PMD_SIZE        (1UL << PMD_SHIFT)
#define PMD_MASK        (~(PMD_SIZE-1))
#define PGDIR_SHIFT     31
#define PGDIR_SIZE      (1UL << PGDIR_SHIFT)
#define PGDIR_MASK      (~(PGDIR_SIZE-1))
#define PTRS_PER_PTE    512
#define PTRS_PER_PMD    1024
#define PTRS_PER_PGD    2048
/* 
 *  pgd_t swapper_pg_dir[PTRS_PER_PGD]  NOTE: 1 ulong per pgd_t 
 */
#define REGION_TABLE_SIZE     (sizeof(ulong) * PTRS_PER_PGD)
#define _PGD_ENTRY_INV        0x20          /* invalid region table entry */
#define SEGMENT_TABLE_ORIGIN  (0xfffffffffffff000)

#define SEGMENT_TABLE_SIZE    ((sizeof(ulong)*2) * PTRS_PER_PMD)
#define _PMD_ENTRY_INV        0x20          /* invalid segment table entry */
#define PAGE_TABLE_ORIGIN     (0xfffffffffffff800)

/* PTE bit translation -- NOTE: changes in 2.4.13 */
#define _PAGE_PRESENT   0x001          /* Software                         */
#define _PAGE_INVALID   0x400          /* HW invalid                       */

#endif  /* S390X */

#define KILOBYTES(x)  ((x) * (1024))
#define MEGABYTES(x)  ((x) * (1048576))
#define GIGABYTES(x)  ((x) * (1073741824))

#define MEGABYTE_MASK (MEGABYTES(1)-1)

#define SIZEOF_64BIT  (8)
#define SIZEOF_32BIT  (4)
#define SIZEOF_16BIT  (2)
#define SIZEOF_8BIT   (1)

#ifdef X86
#define MAX_HEXADDR_STRLEN (8)             
#define UVADDR_PRLEN       (8)
#endif
#ifdef ALPHA
#define MAX_HEXADDR_STRLEN (16)             
#define UVADDR_PRLEN       (11)
#endif
#ifdef PPC
#define MAX_HEXADDR_STRLEN (8)             
#define UVADDR_PRLEN       (8)
#endif
#ifdef IA64
#define MAX_HEXADDR_STRLEN (16)
#define UVADDR_PRLEN       (16)
#endif
#ifdef S390
#define MAX_HEXADDR_STRLEN (8)
#define UVADDR_PRLEN       (8)
#endif
#ifdef S390X
#define MAX_HEXADDR_STRLEN (16)
#define UVADDR_PRLEN       (16)
#endif

#define BADADDR  ((ulong)(-1))
#define BADVAL   ((ulong)(-1))
#define UNUSED   (-1)

#define BITS_PER_BYTE (8)

/*
 *  precision lengths for fprintf
 */ 
#define VADDR_PRLEN      (sizeof(char *) == 8 ? 16 : 8)
#define LONG_LONG_PRLEN  (16)
#define LONG_PRLEN       (sizeof(long) == 8 ? 16 : 8)
#define INT_PRLEN        (sizeof(int) == 8 ? 16 : 8)
#define CHAR_PRLEN       (2)
#define SHORT_PRLEN      (4)

#define MINSPACE  (-100)

#define SYNOPSIS      (1)
#define COMPLETE_HELP (2)

#define LEFT_JUSTIFY   (1)
#define RIGHT_JUSTIFY  (2)

#define CENTER    (0x1)
#define LJUST     (0x2)
#define RJUST     (0x4)
#define LONG_DEC  (0x8)
#define LONG_HEX (0x10)
#define INT_DEC  (0x20)
#define INT_HEX  (0x40)

#define INIT_TIME (1)
#define RUN_TIME  (2)

/*
 * IRQ line status.
 */
#define IRQ_INPROGRESS  1       /* IRQ handler active - do not enter! */
#define IRQ_DISABLED    2       /* IRQ disabled - do not enter! */
#define IRQ_PENDING     4       /* IRQ pending - replay on enable */
#define IRQ_REPLAY      8       /* IRQ has been replayed but not acked yet */
#define IRQ_AUTODETECT  16      /* IRQ is being autodetected */
#define IRQ_WAITING     32      /* IRQ not yet seen - for autodetection */
#define IRQ_LEVEL       64      /* IRQ level triggered */
#define IRQ_MASKED      128     /* IRQ masked - shouldn't be seen again */

#ifdef X86
#define SA_PROBE                SA_ONESHOT
#define SA_SAMPLE_RANDOM        SA_RESTART
#define SA_SHIRQ                0x04000000
#define SA_RESTORER             0x04000000
#endif

#ifdef ALPHA
#define SA_PROBE                SA_ONESHOT
#define SA_SAMPLE_RANDOM        SA_RESTART
#define SA_SHIRQ                0x40000000
#endif

#ifdef PPC
#define SA_PROBE                SA_ONESHOT
#define SA_SAMPLE_RANDOM        SA_RESTART
#define SA_SHIRQ                0x04000000
#define SA_RESTORER             0x04000000
#endif

#ifdef IA64
#define SA_PROBE                SA_ONESHOT
#define SA_SAMPLE_RANDOM        SA_RESTART
#define SA_SHIRQ                0x04000000
#define SA_RESTORER             0x04000000
#endif

#ifdef S390
#define SA_PROBE                SA_ONESHOT
#define SA_SAMPLE_RANDOM        SA_RESTART
#define SA_SHIRQ                0x04000000
#define SA_RESTORER     	0x04000000
#endif

#ifdef S390X
#define SA_PROBE                SA_ONESHOT
#define SA_SAMPLE_RANDOM        SA_RESTART
#define SA_SHIRQ                0x04000000
#define SA_RESTORER     	0x04000000
#endif


#define ACTION_FLAGS (SA_INTERRUPT|SA_PROBE|SA_SAMPLE_RANDOM|SA_SHIRQ)


#endif /* !GDB_COMMON */

/*
 *  Common request structure for BFD or GDB data or commands.
 */
struct gnu_request {    
	int command;
	char *buf;
	FILE *fp;
	ulong addr;
	ulong addr2;
	ulong count;
	ulong flags;
	char *name;
	ulong length;
	int typecode;
	int is_typedef;
	char *member;
	long member_offset;
	long value;
	char *tagname;
	ulong pc;
	ulong sp;
	ulong ra;
	int curframe;
	ulong frame;
	ulong prevsp;
	ulong prevpc;
	ulong lastsp;
	ulong task;
	ulong debug;
	struct stack_hook *hookp;
};

/*
 *  GNU commands
 */
#define GNU_DATATYPE_INIT       (1)
#define GNU_DISASSEMBLE         (2)
#define GNU_GET_LINE_NUMBER     (3)
#define GNU_PASS_THROUGH        (4)
#define GNU_GET_DATATYPE        (5)
#define GNU_COMMAND_EXISTS      (6)
#define GNU_STACK_TRACE         (7)
#define GNU_ALPHA_FRAME_OFFSET  (8)
#define GNU_FUNCTION_NUMARGS    (9)
#define GNU_RESOLVE_TEXT_ADDR  (10)
#define GNU_ADD_SYMBOL_FILE    (11)
#define GNU_DELETE_SYMBOL_FILE (12)
#define GNU_VERSION            (13)
#define GNU_DEBUG_COMMAND     (100)
/*
 *  GNU flags
 */
#define GNU_PRINT_LINE_NUMBERS   (0x1)
#define GNU_FUNCTION_ONLY        (0x2)
#define GNU_PRINT_ENUMERATORS    (0x4)
#define GNU_RETURN_ON_ERROR      (0x8)
#define GNU_COMMAND_FAILED      (0x10)
#define GNU_FROM_TTY_OFF        (0x20)

#undef TRUE
#undef FALSE

#define TRUE  (1)
#define FALSE (0)

#ifdef GDB_COMMON
/*
 *  function prototypes required by modified gdb source files.
 */
int console(char *, ...);
int gdb_MCLXDEBUG(ulong);
int gdb_readmem_callback(ulong, void *, int, int);
void patch_load_module(struct objfile *objfile, struct minimal_symbol *msymbol);
#endif

#ifndef GDB_COMMON
/*
 *  WARNING: the following type codes are type_code enums from gdb/gdbtypes.h
 */
enum type_code {
  TYPE_CODE_UNDEF,              /* Not used; catches errors */
  TYPE_CODE_PTR,                /* Pointer type */
  TYPE_CODE_ARRAY,              /* Array type with lower & upper bounds. */
  TYPE_CODE_STRUCT,             /* C struct or Pascal record */
  TYPE_CODE_UNION,              /* C union or Pascal variant part */
  TYPE_CODE_ENUM,               /* Enumeration type */
  TYPE_CODE_FUNC,               /* Function type */
  TYPE_CODE_INT,                /* Integer type */

  /* Floating type.  This is *NOT* a complex type.  Beware, there are parts
     of GDB which bogusly assume that TYPE_CODE_FLT can mean complex.  */
  TYPE_CODE_FLT,

  /* Void type.  The length field specifies the length (probably always
     one) which is used in pointer arithmetic involving pointers to
     this type, but actually dereferencing such a pointer is invalid;
     a void type has no length and no actual representation in memory
     or registers.  A pointer to a void type is a generic pointer.  */
  TYPE_CODE_VOID,

  TYPE_CODE_SET,                /* Pascal sets */
  TYPE_CODE_RANGE,              /* Range (integers within spec'd bounds) */

  /* 
   *  NOTE: the remainder of the type codes are not list or used here...
   */
};

/*
 *  Task state and flags taken from kernel source.
 */
#define TASK_RUNNING            0
#define TASK_INTERRUPTIBLE      1
#define TASK_UNINTERRUPTIBLE    2
#define TASK_ZOMBIE             4
#define TASK_STOPPED            8
#define TASK_SWAPPING           16
#define TASK_EXCLUSIVE          32

#define PF_EXITING 0x00000004  /* getting shut down */

#define IS_ZOMBIE(task)   (task_state(task) & TASK_ZOMBIE)
#define IS_EXITING(task)  (task_flags(task) & PF_EXITING)
  
/*
 *  ps command options.
 */
#define PS_BY_PID      (0x1)
#define PS_BY_TASK     (0x2)
#define PS_BY_CMD      (0x4)
#define PS_SHOW_ALL    (0x8)
#define PS_PPID_LIST  (0x10)
#define PS_CHILD_LIST (0x20)
#define PS_KERNEL     (0x40)
#define PS_USER       (0x80)
#define PS_TIMES     (0x100)
#define PS_KSTACKP   (0x200)

#define MAX_PS_ARGS    (100)   /* maximum command-line specific requests */

struct psinfo {
	int argc;
        ulong pid[MAX_PS_ARGS];
	int type[MAX_PS_ARGS];
        ulong task[MAX_PS_ARGS];
        char comm[MAX_PS_ARGS][16+1];
};

#define IS_A_NUMBER(X)      (decimal(X, 0) || hexadecimal(X, 0))
#define AMBIGUOUS_NUMBER(X) (decimal(X, 0) && hexadecimal(X, 0))

#define is_mclx_compressed_dump(X)  (va_server_init((X), 0, 0, 0) == 0)

struct task_mem_usage {
        ulong rss;
        ulong total_vm;
        double pct_physmem;
        ulong mm_struct_addr;
	ulong pgd_addr;
};

/*
 *  Global data (global_data.c) 
 */
extern FILE *fp; 
extern struct program_context program_context, *pc;
extern struct task_table task_table, *tt;
extern struct kernel_table kernel_table, *kt;
extern struct command_table_entry base_command_table[];
extern char *args[MAXARGS];      
extern int argcnt;            
extern int argerrs;
extern struct offset_table offset_table;
extern struct size_table size_table;
extern struct vm_table vm_table, *vt;
extern struct machdep_table *machdep;
extern struct symbol_table_data symbol_table_data, *st;
extern struct extension_table *extension_table;

/*
 *  Generated in build_data.c
 */
extern char *build_command;
extern char *build_data;
extern char *build_version;


/*
 *  command prototypes
 */
void cmd_quit(void);         /* main.c */
void cmd_mach(void);         /* main.c */
void cmd_help(void);         /* help.c */
void cmd_test(void);         /* test.c */
void cmd_ascii(void);        /* tools.c */
void cmd_set(void);          /* tools.c */
void cmd_eval(void);         /* tools.c */
void cmd_list(void);         /* tools.c */
void cmd_template(void);     /* tools.c */
void cmd_alias(void);        /* cmdline.c */
void cmd_repeat(void);       /* cmdline.c */
void cmd_rd(void);           /* memory.c */
void cmd_wr(void);           /* memory.c */
void cmd_ptov(void);         /* memory.c */
void cmd_vtop(void);         /* memory.c */
void cmd_vm(void);           /* memory.c */
void cmd_ptob(void);         /* memory.c */
void cmd_btop(void);         /* memory.c */
void cmd_kmem(void);         /* memory.c */
void cmd_search(void);       /* memory.c */
void cmd_swap(void);         /* memory.c */
void cmd_pte(void);          /* memory.c */
void cmd_ps(void);           /* task.c */
void cmd_task(void);         /* task.c */
void cmd_foreach(void);      /* task.c */
void cmd_runq(void);         /* task.c */
void cmd_sig(void);          /* task.c */
void cmd_bt(void);           /* kernel.c */
void cmd_dis(void);          /* kernel.c */
void cmd_mod(void);          /* kernel.c */
void cmd_log(void);          /* kernel.c */
void cmd_sys(void);          /* kernel.c */
void cmd_irq(void);          /* kernel.c */
void cmd_timer(void);        /* kernel.c */
void cmd_waitq(void);        /* kernel.c */
void cmd_sym(void);          /* symbols.c */
void cmd_struct(void);       /* symbols.c */
void cmd_union(void);        /* symbols.c */
void cmd_pointer(void);      /* symbols.c */
void cmd_whatis(void);       /* symbols.c */
void cmd_p(void);            /* symbols.c */
void cmd_mount(void);        /* filesys.c */
void cmd_files(void);        /* filesys.c */
void cmd_fuser(void);        /* filesys.c */
void cmd_dev(void);          /* dev.c */
void cmd_gdb(void);          /* gdb_interface.c */
void cmd_net(void);          /* net.c */
void cmd_extend(void);       /* extensions.c */

/*
 *  main.c
 */
void main_loop(void);
void exec_command(void);
struct command_table_entry *get_command_table_entry(char *);
void program_usage(void);
void dump_program_context(void);
void dump_build_data(void);
#ifdef X86
#define machdep_init(X) x86_init(X)
#endif
#ifdef ALPHA
#define machdep_init(X) alpha_init(X)
#endif
#ifdef PPC
#define machdep_init(X) ppc_init(X)
#endif
#ifdef IA64 
#define machdep_init(X) ia64_init(X)
#endif
#ifdef S390
#define machdep_init(X) s390_init(X)
#endif
#ifdef S390X
#define machdep_init(X) s390x_init(X)
#endif

/*
 *  cmdline.c
 */
void restart(int);
void alias_init(void);
struct alias_data *is_alias(char *);
void deallocate_alias(char *);
void cmdline_init(void);
void exec_input_file(void);
void get_command_line(void);
void dump_history(void);
void resolve_rc_cmd(char *, int);
void dump_alias_data(void);
int output_open(void);
#define output_closed() (!output_open())
void close_output(void);
int interruptible(void);
int received_SIGINT(void);
void debug_redirect(char *);

/*
 *  tools.c
 */
int __error(int, char *, ...);
#define error __error               /* avoid conflict with gdb error() */
int console(char *, ...);
void create_console_device(char *);
int console_off(void);
int console_on(int);
int console_verbatim(char *);
int whitespace(int);
int ascii(int);
int ascii_string(char *);
char *clean_line(char *);
char *strip_line_end(char *);
char *strip_linefeeds(char *);
char *strip_beginning_whitespace(char *);
char *strip_ending_whitespace(char *);
char *strip_ending_char(char *, char);
char *strip_beginning_char(char *, char);
char *strip_comma(char *);
char *strip_hex(char *);
char *upper_case(char *, char *);
char *first_nonspace(char *);
char *first_space(char *);
char *replace_string(char *, char *, char);
char *null_first_space(char *);
int parse_line(char *, char **);
void print_verbatim(FILE *, char *);
char *fixup_percent(char *);
int can_eval(char *);
ulong eval(char *, int, int *);
ulonglong evall(char *, int, int *);
int eval_common(char *, int, int *, struct number_option *);
ulong htol(char *, int, int *);
ulong dtol(char *, int, int *);
unsigned int dtoi(char *, int, int *);
ulong stol(char *, int, int *);
ulonglong stoll(char *, int, int *);
ulonglong htoll(char *, int, int *);
ulonglong dtoll(char *, int, int *);
int decimal(char *, int);
int hexadecimal(char *, int);
int hexadecimal_only(char *, int);
ulong convert(char *, int, int *, ulong);
void pad_line(FILE *, int, char);
#define INDENT(x)  pad_line(fp, x, ' ')
char *mkstring(char *, int, ulong, const char *);
#define MKSTR(X) ((const char *)(X))
int count_leading_spaces(char *);
int count_chars(char *, char);
long count_buffer_chars(char *, char, long);
char *space(int);
char *concat_args(char *, int, int);
char *shift_string_left(char *, int);
char *shift_string_right(char *, int);
int bracketed(char *, char *, int);
void backspace(int);
int do_list(struct list_data *);
#define LIST_OFFSET_ENTERED (VERBOSE << 1)
#define LIST_START_ENTERED  (VERBOSE << 2)
#define LIST_HEAD_FORMAT    (VERBOSE << 3)
#define LIST_HEAD_POINTER   (VERBOSE << 4)
int retrieve_list(ulong *, int);
long power(long, int);
void hq_init(void);
int hq_open(void);
int hq_close(void);
int hq_enter(ulong);
long get_embedded(void);
void dump_embedded(char *);
char *ordinal(ulong, char *);
char *first_nonspace(char *);
void dump_hash_table(int);
void dump_shared_bufs(void);
void drop_core(char *);
int extract_hex(char *, ulong *, char, ulong);
int count_bits_int(int);
int count_bits_long(long);
void buf_init(void);
void sym_buf_init(void);
void free_all_bufs(void);
char *getbuf(long);
void freebuf(char *);
#define GETBUF(X)   getbuf((long)(X))
#define FREEBUF(X)  freebuf((char *)(X))
void sigsetup(int, void *, struct sigaction *, struct sigaction *);
#define SIGACTION(s, h, a, o) sigsetup(s, h, a, o)
char *convert_time(ulong, char *);


/* 
 *  symbols.c 
 */
void symtab_init(void);
void no_debugging_data(void);
void get_text_init_space(void);
int is_kernel_text(ulong);
int is_kernel_data(ulong);
int is_init_data(ulong value); 
int is_kernel_text_offset(ulong, ulong *);
int is_rodata(ulong, ulong *, struct syment **);
void datatype_init(void);
struct syment *symbol_search(char *);
struct syment *value_search(ulong, off_t *);
int in_ksymbol_range(ulong);
int module_symbol(ulong, struct syment **, 
	struct load_module **, char *, ulong);
#define IS_MODULE_VADDR(X) \
	(module_symbol((ulong)(X), NULL, NULL, NULL, output_radix))
char *closest_symbol(ulong);
ulong closest_symbol_value(ulong);
#define SAME_FUNCTION(X,Y) (closest_symbol_value(X) == closest_symbol_value(Y))
void show_symbol(struct syment *, off_t, ulong);
#define SHOW_LINENUM  (0x1)
#define SHOW_SECTION  (0x2)
#define SHOW_HEX_OFFS (0x4)
#define SHOW_DEC_OFFS (0x8)
#define SHOW_RADIX() (output_radix == 16 ? SHOW_HEX_OFFS : SHOW_DEC_OFFS)
int symbol_query(char *, char *, struct syment **);
struct syment *next_symbol(char *, struct syment *);
struct syment *prev_symbol(char *, struct syment *);
void get_symbol_data(char *, long, void *);
struct syment *symbol_search(char *);
char *value_to_symstr(ulong, char *, ulong);
char *value_symbol(ulong);
ulong symbol_value(char *);
int symbol_exists(char *s);
void dump_struct(char *, ulong, unsigned);
void dump_struct_member(char *, ulong, unsigned);
void dump_union(char *, ulong, unsigned);
void store_module_symbols(ulong, int);
int is_datatype_command(void);
int arg_to_datatype(char *, struct datatype_member *, ulong);
void dump_symbol_table(void);
void dump_struct_table(ulong);
void dump_offset_table(char *);
ulong sizeof_variable(char *);
int is_elf_file(char *);
int get_array_length(char *, int *);
char *get_line_number(ulong, char *, int);
char *get_build_directory(char *);
int datatype_exists(char *);
int get_function_numargs(ulong);
int is_module_name(char *, ulong *, struct load_module **);
int is_module_address(ulong, char *);
int load_module_symbols(char *, char *, ulong);
void delete_load_module(ulong);
ulong gdb_load_module_callback(ulong, char *);
char *load_module_filter(char *, int);
#define LM_P_FILTER   (1)
#define LM_DIS_FILTER (2)
long datatype_info(char *, char *, struct datatype_member *);
#define STRUCT_SIZE(X)      datatype_info((X), NULL, NULL)
#define UNION_SIZE(X)       datatype_info((X), NULL, NULL)
#define DATATYPE_SIZE(X)    datatype_info((X)->name, NULL, (X))
#define MEMBER_OFFSET(X,Y)  datatype_info((X), (Y), NULL)
#define STRUCT_EXISTS(X)    (datatype_info((X), NULL, NULL) >= 0)
#define MEMBER_EXISTS(X,Y)  (datatype_info((X), (Y), NULL) >= 0)
int text_value_cache(ulong, uint32_t, uint32_t *);
int text_value_cache_byte(ulong, unsigned char *);
void dump_text_value_cache(int);
void clear_text_value_cache(void);
void dump_numargs_cache(void);

/*  
 *  memory.c 
 */
void mem_init(void);
void vm_init(void);
int readmem(ulong, int, void *, long, char *, ulong);
int writemem(ulong, int, void *, long, char *, ulong);
int read_dev_mem(int, void *, int, ulong, ulong);
int read_mclx_dumpfile(int, void *, int, ulong, ulong);
int read_lkcd_dumpfile(int, void *, int, ulong, ulong);
int read_daemon(int, void *, int, ulong, ulong);
int write_dev_mem(int, void *, int, ulong, ulong);
int write_mclx_dumpfile(int, void *, int, ulong, ulong);
int write_lkcd_dumpfile(int, void *, int, ulong, ulong);
int write_daemon(int, void *, int, ulong, ulong);
int kvtop(struct task_context *, ulong, ulong *, int);
int uvtop(struct task_context *, ulong, ulong *, int);
void do_vtop(ulong, struct task_context *, ulong);
void raw_stack_dump(ulong);
void raw_data_dump(ulong, long, int);
int accessible(ulong);
ulong vm_area_dump(ulong, ulong, ulong, struct reference *);
#define IN_TASK_VMA(TASK,VA) (vm_area_dump((TASK), UVADDR|VERIFY_ADDR, (VA), 0))
char *fill_vma_cache(ulong);
void clear_vma_cache(void);
void dump_vma_cache(ulong);
int is_page_ptr(ulong, ulong *);
void dump_vm_table(int);
int read_string(ulong, char *, int);
void get_task_mem_usage(ulong, struct task_mem_usage *);
char *get_memory_size(char *);
uint64_t generic_memory_size(void);
char *swap_location(ulong, char *); 
void clear_swap_info_cache(void);
uint memory_page_size(void);
ulong first_vmalloc_address(void);
int l1_cache_size(void);
int dumpfile_memory(int);
#define DUMPFILE_MEM_USED    (1)
#define DUMPFILE_FREE_MEM    (2)
#define DUMPFILE_MEM_DUMP    (3)
#define DUMPFILE_ENVIRONMENT (4)
uint64_t total_node_memory(void);
int generic_is_kvaddr(ulong);
int generic_is_uvaddr(ulong, struct task_context *);
void fill_stackbuf(struct bt_info *);
int vaddr_type(ulong, struct task_context *);

/*
 *  filesys.c 
 */
void fd_init(void);
void vfs_init(void);
int is_a_tty(char *);
int file_exists(char *, struct stat *);
int file_readable(char *);
int is_directory(char *);
void open_tmpfile(void);
void close_tmpfile(void);
void open_tmpfile2(void);
void close_tmpfile2(void);
void open_files_dump(ulong, int, struct reference *);
void get_pathname(ulong, char *, int, int, ulong);
void nlm_files_dump(void);
int get_proc_version(void);
int file_checksum(char *, long *);
void dump_filesys_table(int);
char *fill_file_cache(ulong);
void clear_file_cache(void);
char *fill_dentry_cache(ulong);
void clear_dentry_cache(void);
char *fill_inode_cache(ulong);
void clear_inode_cache(void);
int monitor_memory(long *, long *, long *, long *);
#endif  /* !GDB_COMMON */
int same_file(char *, char *);
#ifndef GDB_COMMON


/*
 *  help.c 
 */
#define HELP_COLUMNS 5
#define START_OF_HELP_DATA(X)  "START_OF_HELP_DATA" X
#define END_OF_HELP_DATA       "END_OF_HELP_DATA"
void help_init(void);
void cmd_usage(char *, int);
void display_version(void);
#ifdef X86
#define dump_machdep_table() x86_dump_machdep_table()
#endif
#ifdef ALPHA
#define dump_machdep_table() alpha_dump_machdep_table()
#endif
#ifdef PPC
#define dump_machdep_table() ppc_dump_machdep_table()
#endif
#ifdef IA64
#define dump_machdep_table() ia64_dump_machdep_table()
#endif
#ifdef S390
#define dump_machdep_table() s390_dump_machdep_table()
#endif
#ifdef S390X
#define dump_machdep_table() s390x_dump_machdep_table()
#endif
extern char *help_pointer[];
extern char *help_alias[];
extern char *help_ascii[];
extern char *help_bt[];
extern char *help_btop[];
extern char *help_dev[];
extern char *help_dis[];
extern char *help_eval[];
extern char *help_exit[];
extern char *help_extend[];
extern char *help_files[];
extern char *help_foreach[];
extern char *help_fuser[];
extern char *help_gdb[];
extern char *help_help[];
extern char *help_irq[];
extern char *help_kmem[];
extern char *help__list[];
extern char *help_log[];
extern char *help_mach[];
extern char *help_mod[];
extern char *help_mount[];
extern char *help_net[];
extern char *help_p[];
extern char *help_ps[];
extern char *help_pte[];
extern char *help_ptob[];
extern char *help_ptov[];
extern char *help_quit[];
extern char *help_rd[];
extern char *help_repeat[];
extern char *help_runq[];
extern char *help_search[];
extern char *help_set[];
extern char *help_sig[];
extern char *help_struct[];
extern char *help_swap[];
extern char *help_sym[];
extern char *help_sys[];
extern char *help_task[];
extern char *help_timer[];
extern char *help_union[];
extern char *help_vm[];
extern char *help_vtop[];
extern char *help_waitq[];
extern char *help_whatis[];
extern char *help_wr[];

/*
 *  task.c
 */ 
void task_init(void);
int set_context(ulong, ulong);
void show_context(struct task_context *, int, int);
ulong pid_to_task(ulong);
ulong task_to_pid(ulong);
int task_exists(ulong);
int is_kernel_thread(ulong);
int is_idle_thread(ulong);
char *task_state_string(ulong, char *, int);
ulong task_flags(ulong);
ulong task_state(ulong);
ulong task_mm(ulong, int);
int comm_exists(char *);
struct task_context *task_to_context(ulong);
struct task_context *pid_to_context(ulong);
int str_to_context(char *, ulong *, struct task_context **);
#define STR_PID     (0x1)
#define STR_TASK    (0x2)
#define STR_INVALID (0x4)
char *get_panicmsg(char *);
char *task_cpu(int, char *, int);
void print_task_header(FILE *, struct task_context *, int);
ulong get_active_task(int);
int is_task_active(ulong);
int is_panic_thread(ulong);
int get_panic_ksp(struct bt_info *, ulong *);
void foreach(struct foreach_data *);
int pid_exists(ulong);
#define TASKS_PER_PID(x)  pid_exists(x)
char *fill_task_struct(ulong);
#define IS_LAST_TASK_READ(task) ((ulong)(task) == tt->last_task_read)
char *fill_mm_struct(ulong);
#define IS_LAST_MM_READ(mm)     ((ulong)(mm) == tt->last_mm_read)
void do_task(ulong, ulong, struct reference *);
void clear_task_cache(void);
void do_sig(ulong, ulong, struct reference *);
void modify_signame(int, char *, char *);
ulong generic_get_stackbase(ulong);
ulong generic_get_stacktop(ulong);
void dump_task_table(int);

/*
 *  extensions.c
 */
void register_extension(struct command_table_entry *);
void dump_extension_table(int);

/*
 *  kernel.c 
 */ 
void kernel_init(int);
void module_init(void);
void verify_version(void);
struct load_module *modref_to_load_module(char *);
void unlink_module(struct load_module *);
int is_system_call(char *, ulong);
void generic_dump_irq(int);
int generic_dis_filter(ulong, char *);
void display_sys_stats(void);
void dump_kernel_table(void);
void set_cpu(int);
void clear_machdep_cache(void);
void back_trace(struct bt_info *);
#define BT_RAW                    (0x1)
#define BT_SYMBOLIC_ARGS          (0x2)
#define BT_NOARGS                 (0x4)
#define BT_TEXT_SYMBOLS           (0x8)
#define BT_TEXT_SYMBOLS_PRINT    (0x10)
#define BT_TEXT_SYMBOLS_NOPRINT  (0x20)
#define BT_USE_GDB               (0x40)
#define BT_EXCEPTION_FRAME       (0x80)
#define BT_LINE_NUMBERS         (0x100)
#define BT_USER_EFRAME          (0x200)
#define BT_SAVE_LASTSP          (0x400)
#define BT_FROM_EXCEPTION       (0x800)
#define BT_FROM_CALLFRAME      (0x1000)
#define BT_EFRAME_SEARCH       (0x2000)
#define BT_SPECULATE           (0x4000)
#define BT_RESCHEDULE          (0x8000)
#define BT_RET_FROM_SMP_FORK  (0x10000)
#define BT_STRACE             (0x20000)
#define BT_KSTACKP            (0x40000)

#define BT_REF_HEXVAL         (0x1)
#define BT_REF_SYMBOL         (0x2)
#define BT_REF_FOUND          (0x4)
#define BT_REFERENCE_CHECK(X) ((X)->ref)
#define BT_REFERENCE_FOUND(X) ((X)->ref && ((X)->ref->cmdflags & BT_REF_FOUND))

#define NO_MODULES() \
	 (!kt->module_list || (kt->module_list == kt->kernel_module))

#define USER_EFRAME_ADDR(task) \
	((ulong)task + UNION_SIZE("task_union") - SIZE(pt_regs))

struct remote_file {
	char *filename;
	char *local;
	int fd;
	int flags;
	int type;
	long csum;
	off_t size;
};

#define REMOTE_VERBOSE   (O_RDWR << 1)
#define REMOTE_COPY_DONE (REMOTE_VERBOSE << 1)
#define TYPE_ELF         (REMOTE_VERBOSE << 2)
#define TYPE_DEVMEM      (REMOTE_VERBOSE << 3)
#define TYPE_MCLXCD      (REMOTE_VERBOSE << 4)
#define TYPE_LKCD        (REMOTE_VERBOSE << 5)
#define TYPE_S390D       (REMOTE_VERBOSE << 6)
#define TYPE_S390XD      (REMOTE_VERBOSE << 7)

/*
 *  dev.c
 */
void dev_init(void);
void dump_dev_table(void);

/*
 *  alpha.c
 */
#ifdef ALPHA
void alpha_init(int);
void alpha_dump_machdep_table(void);
#define display_idt_table() \
        error(FATAL, "-d option is not applicable to alpha architecture\n")

#define HWRESET_TASK(X)  ((machdep->flags & HWRESET) && is_task_active(X) && \
                         (task_to_context(X)->processor == 0)) 
#endif

/*
 *  x86.c           
 */
#ifdef X86
void x86_init(int);
void x86_dump_machdep_table(void);
void x86_display_idt_table(void);
#define display_idt_table() x86_display_idt_table()
#define KSYMS_START (0x1)
#endif

/*
 *  ppc.c
 */
#ifdef PPC
void ppc_init(int);
void ppc_dump_machdep_table(void);
#define display_idt_table() \
        error(FATAL, "-d option is not applicable to PowerPC architecture\n")
#define KSYMS_START (0x1)
#endif

/*
 *  ia64.c
 */
#ifdef IA64
void ia64_init(int);
void ia64_dump_machdep_table(void);
#define display_idt_table() \
	error(FATAL, "-d option TBD on ia64 architecture\n");

#define OLD_UNWIND     (0x1)   /* CONFIG_IA64_NEW_UNWIND turned on */
#define NEW_UNWIND     (0x2)   /* CONFIG_IA64_NEW_UNWIND turned on */
#define UNW_FI_INSYNC  (0x4)   /* unw_frame_info same as kernel's */
#define UNW_FI_UNKNOWN (0x8)   /* unw_frame_info has changed! */ 
#define UNW_FI_STATE   (UNW_FI_INSYNC|UNW_FI_UNKNOWN)

#endif

/*
 *  s390.c
 */
#ifdef S390 
void s390_init(int);
void s390_dump_machdep_table(void);
#define display_idt_table() \
        error(FATAL, "-d option is not applicable to S390 architecture\n")
#define KSYMS_START (0x1)
#endif

/*
 *  s390_dump.c
 */
int is_s390_dump(char *);
gzFile s390_dump_init(char *);
int read_s390_dumpfile(int, void *, int, ulong, ulong);
int write_s390_dumpfile(int, void *, int, ulong, ulong);
uint s390_page_size(void);
int s390_memory_used(void);
int s390_free_memory(void);
int s390_memory_dump(FILE *);
ulong get_s390_panic_task(void);
void get_s390_panicmsg(char *);

/*
 *  s390x.c
 */
#ifdef S390X
void s390x_init(int);
void s390x_dump_machdep_table(void);
#define display_idt_table() \
        error(FATAL, "-d option is not applicable to S390X architecture\n")
#define KSYMS_START (0x1)
#endif

/*
 *  s390x_dump.c
 */
int is_s390x_dump(char *);
gzFile s390x_dump_init(char *);
int read_s390x_dumpfile(int, void *, int, ulong, ulong);
int write_s390x_dumpfile(int, void *, int, ulong, ulong);
uint s390x_page_size(void);
int s390x_memory_used(void);
int s390x_free_memory(void);
int s390x_memory_dump(FILE *);
ulong get_s390x_panic_task(void);
void get_s390x_panicmsg(char *);

/*
 *  net.c
 */
void net_init(void);
void dump_net_table(void);
void dump_sockets_workhorse(ulong, ulong, struct reference *);

/*
 *  remote.c
 */
int is_remote_daemon(char *);
void remote_fd_init(void);
int get_remote_file(struct remote_file *);
uint remote_page_size(void);
int find_remote_module_objfile(struct load_module *lm, char *, char *);
int remote_free_memory(void);
int remote_memory_dump(int);
int remote_memory_used(void);
void remote_exit(void);
int remote_execute(void);
void remote_clear_pipeline(void);
int remote_memory_read(int, char *, int, ulong);

/*
 *  gnu_binutils.c
 */

/* NO LONGER IN USE */

/*
 *  test.c
 */
void cmd_template(void);
void foreach_test(ulong, ulong);

/*
 *  va_server.c
 */
int mclx_page_size(void);
int vas_memory_used(void);
int vas_memory_dump(FILE *);
int vas_free_memory(char *);
void set_vas_debug(ulong);
size_t vas_write(void *, size_t);
int va_server_init(char *, ulong *, ulong *, ulong *);
size_t vas_read(void *, size_t);
int vas_lseek(ulong, int);

/*
 * lkcd_common.c
 */
int lkcd_dump_init(FILE *, int);
ulong get_lkcd_panic_task(void);
void get_lkcd_panicmsg(char *);
int is_lkcd_compressed_dump(char *);
void dump_lkcd_environment(ulong);
int lkcd_lseek(unsigned long);
long lkcd_read(void *, long);
void set_lkcd_debug(ulong);
FILE *set_lkcd_fp(FILE *);
uint lkcd_page_size(void);
int lkcd_memory_used(void);
int lkcd_memory_dump(FILE *);
int lkcd_free_memory(void);
void lkcd_print(char *, ...);
void set_remote_lkcd_panic_data(ulong, char *);
void set_lkcd_nohash(void);
int lkcd_load_dump_page_header(void *, ulong);
void lkcd_dumpfile_complaint(uint32_t, uint32_t, int);
int set_mb_benchmark(ulong);

/*
 * lkcd_v1.c
 */
int lkcd_dump_init_v1(FILE *, int);
void dump_dump_page_v1(char *, void *);
void dump_lkcd_environment_v1(ulong);
uint32_t get_dp_size_v1(void);
uint32_t get_dp_flags_v1(void);
uint64_t get_dp_address_v1(void);

/*
 * lkcd_v2_v3.c
 */
int lkcd_dump_init_v2_v3(FILE *, int);
void dump_dump_page_v2_v3(char *, void *);
void dump_lkcd_environment_v2_v3(ulong);
uint32_t get_dp_size_v2_v3(void);
uint32_t get_dp_flags_v2_v3(void);
uint64_t get_dp_address_v2_v3(void);

/*
 * lkcd_v5.c
 */
int lkcd_dump_init_v5(FILE *, int);
void dump_dump_page_v5(char *, void *);
void dump_lkcd_environment_v5(ulong);
uint32_t get_dp_size_v5(void); 
uint32_t get_dp_flags_v5(void);
uint64_t get_dp_address_v5(void); 

#ifdef LKCD_COMMON
/*
 *  Until they differ across versions, these remain usable in the common
 *  routines in lkcd_common.c
 */
#define LKCD_DUMP_MAGIC_NUMBER        (0xa8190173618f23edULL)
#define LKCD_DUMP_MAGIC_LIVE          (0xa8190173618f23cdULL)  

#define LKCD_DUMP_V1                  (0x1)  /* DUMP_VERSION_NUMBER */ 
#define LKCD_DUMP_V2                  (0x2)  /* DUMP_VERSION_NUMBER */
#define LKCD_DUMP_V3                  (0x3)  /* DUMP_VERSION_NUMBER */
#define LKCD_DUMP_V5                  (0x5)  /* DUMP_VERSION_NUMBER */

#define LKCD_DUMP_VERSION_NUMBER_MASK (0x7)
#define LKCD_DUMP_RAW                 (0x1)   /* DUMP_[DH_]RAW */ 
#define LKCD_DUMP_COMPRESSED          (0x2)   /* DUMP_[DH_]COMPRESSED */
#define LKCD_DUMP_END                 (0x4)   /* DUMP_[DH_]END */

#define LKCD_DUMP_COMPRESS_NONE    (0x0)      /* DUMP_COMPRESS_NONE */ 
#define LKCD_DUMP_COMPRESS_RLE     (0x1)      /* DUMP_COMPRESS_RLE */
#define LKCD_DUMP_COMPRESS_GZIP    (0x2)      /* DUMP_COMPRESS_GZIP */

#define LKCD_DUMP_MCLX_V0            (0x80000000)   /* MCLX mod of LKCD */
#define LKCD_DUMP_MCLX_V1            (0x40000000)   /* Extra page header data */
#define LKCD_OFFSET_TO_FIRST_PAGE    (65536)

#define MCLX_PAGE_HEADERS            (4096)
#define MCLX_V1_PAGE_HEADER_CACHE    ((sizeof(uint64_t)) * MCLX_PAGE_HEADERS)

/*
 *  lkcd_load_dump_page_header() return values
 */
#define LKCD_DUMPFILE_OK  (0)
#define LKCD_DUMPFILE_EOF (1)
#define LKCD_DUMPFILE_END (2)

/*
 *  Common handling of LKCD dump environment 
 */
#define LKCD_CACHED_PAGES     (16)
#define LKCD_PAGE_HASH        (32)
#define LKCD_DUMP_HEADER_ONLY (1)       /* arguments to lkcd_dump_environment */
#define LKCD_DUMP_PAGE_ONLY   (2)

#define LKCD_VALID     (0x1)      	       /* flags */
#define LKCD_REMOTE    (0x2)
#define LKCD_NOHASH    (0x4)
#define LKCD_MCLX      (0x8)
#define LKCD_BAD_DUMP (0x10)

struct page_hash_entry {
	uint32_t pg_flags;
	uint64_t pg_addr;
	off_t pg_hdr_offset;
	struct page_hash_entry *next;
};

struct lkcd_environment {
        int fd;                        /* dumpfile file descriptor */
	ulong flags;                   /* flags from above */
	ulong debug;                   /* shadow of pc->debug */
	FILE *fp;		       /* abstracted fp for fprintf */
        void *dump_header;             /* header stash, v1 or v2 */
	void *dump_header_asm;         /* architecture specific header for v2 */
        void *dump_page;               /* current page header holder */
	uint32_t version;              /* version number of this dump */
	uint32_t page_size;	       /* size of a Linux memory page */
	int page_shift;                /* byte address to page */
	int bits;                      /* processor bitsize */
	ulong panic_task;              /* panic task address */
	char *panic_string;            /* pointer to stashed panic string */
	uint32_t compression;          /* compression type */
        uint32_t (*get_dp_size)(void); /* returns current page's dp_size */
        uint32_t (*get_dp_flags)(void); /* returns current page's dp_size */
        uint64_t (*get_dp_address)(void); /* returns current page's dp_address*/
	size_t page_header_size;       /* size of version's page header */
        unsigned long curpos;          /* offset into current page */
        uint64_t curpaddr;             /* current page's physical address */
	off_t curhdroffs;              /* current page's header offset */
        char *curbufptr;               /* pointer to uncompressed page buffer */
        uint64_t kvbase;               /* physical-to-LKCD page address format*/
        char *page_cache_buf;          /* base of cached buffer pages */
        char *compressed_page;         /* copy of compressed page data */
        int evict_index;               /* next page to evict */
        ulong evictions;               /* total evictions done */
        struct page_cache_hdr {        /* header for each cached page */
		uint32_t pg_flags;
                uint64_t pg_addr;
                char *pg_bufptr;
                ulong pg_hit_count;
        } page_cache_hdr[LKCD_CACHED_PAGES];
	struct page_hash_entry *page_hash;
	ulong total_pages;
	ulong benchmark_pages;
	ulong benchmarks_done;
	off_t *mb_hdr_offsets;
	ulong total_reads;
	ulong cached_reads;
	ulong hashed_reads;
	ulong hashed;
	ulong compressed;
	ulong raw;
};

#define MEGABYTE_ALIGNED(vaddr)  (!((uint64_t)(vaddr) & MEGABYTE_MASK))

#define LKCD_PAGE_HASH_INDEX(paddr) \
        (((paddr) >> lkcd->page_shift) % LKCD_PAGE_HASH)
#define LKCD_PAGES_PER_MEGABYTE() (MEGABYTES(1) / lkcd->page_size)
#define LKCD_PAGE_MEGABYTE(page)  ((page) / LKCD_PAGES_PER_MEGABYTE())
#define LKCD_BENCHMARKS_DONE()  (lkcd->benchmarks_done >= lkcd->benchmark_pages)
#define LKCD_VALID_PAGE(flags) ((flags) & LKCD_VALID)

extern struct lkcd_environment *lkcd;

#define LKCD_DEBUG(x)  (lkcd->debug >= (x))
#undef BITS
#undef BITS32
#undef BITS64
#define BITS()    (lkcd->bits)
#define BITS32()  (lkcd->bits == 32)
#define BITS64()  (lkcd->bits == 64)

#endif  /* LKCD_COMMON */

/*
 *  gdb_interface.c
 */
void gdb_main_loop(int, char **);
void display_gdb_banner(void);
void get_gdb_version(void);
void gdb_session_init(void);
void gdb_interface(struct gnu_request *);
int gdb_pass_through(char *, FILE *, ulong);
int gdb_readmem_callback(ulong, void *, int, int);
volatile void gdb_error_hook(void);
void restore_gdb_sanity(void);
int is_gdb_command(int, ulong);
char *gdb_command_string(int, char *, int);
void dump_gnu_request(struct gnu_request *, int);
int gdb_MCLXDEBUG(ulong);
void dump_gdb_data(void);

/*
 *  gdb/top.c
 */
extern void (*command_loop_hook)(void);
extern volatile void (*error_hook)(void);
extern void execute_command (char *, int);

/*
 *  gdb/symtab.c
 */
extern void gdb_command_funnel(struct gnu_request *);

/*
 *  gdb/valprint.c
 */
extern unsigned output_radix;
extern int output_format;
extern int prettyprint_structs;
extern int prettyprint_arrays;
extern int repeat_count_threshold;
extern int repeat_count_threshold;
extern unsigned int print_max;

/*
 *  gdb/utils.c
 */
extern void do_cleanups(void *);

/*
 *  gdb/version.c
 */
extern char *version;

/*
 *  readline/readline.c
 */
extern char *readline(char *);
extern int rl_editing_mode;

/*
 *  readline/history.c
 */
extern int history_offset;

/*
 *  external gdb routines
 */
extern int gdb_main(int, char **);
extern int have_partial_symbols(void); 
extern int have_full_symbols(void);

#endif /* !GDB_COMMON */
