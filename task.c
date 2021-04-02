/* task.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002, 2003, 2004, 2005, 2006 David Anderson
 * Copyright (C) 2002, 2003, 2004, 2005, 2006 Red Hat, Inc. All rights reserved.
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

static ulong get_panic_context(void);
static int sort_by_pid(const void *, const void *);
static void show_ps(ulong, struct psinfo *);
static struct task_context *panic_search(void);
static void allocate_task_space(int);
static void refresh_fixed_task_table(void);
static void refresh_unlimited_task_table(void); 
static void refresh_pidhash_task_table(void);
static void refresh_pid_hash_task_table(void);
static void refresh_hlist_task_table(void);
static void refresh_hlist_task_table_v2(void);
static struct task_context *store_context(struct task_context *, ulong, char *);
static void refresh_context(ulong, ulong);
static void parent_list(ulong);
static void child_list(ulong);
static void show_task_times(struct task_context *, ulong);
static void show_task_args(struct task_context *);
static void show_tgid_list(ulong);
static int compare_start_time(const void *, const void *);
static int start_time_timespec(void);
static ulonglong convert_start_time(ulonglong, ulonglong);
static ulong get_dumpfile_panic_task(void);
static ulong get_active_set_panic_task(void);
static void populate_panic_threads(void);
static int verify_task(struct task_context *, int);
static ulong get_idle_task(int, char *);
static ulong get_curr_task(int, char *);
static long rq_idx(int);
static long cpu_idx(int);
static void dump_runq(void);
static void dump_runqueues(void);
static void dump_prio_array(int, ulong, char *);
static void task_struct_member(struct task_context *,ulong,struct reference *);
static void signal_reference(struct task_context *, ulong, struct reference *);
static void do_sig_thread_group(ulong);
static void dump_signal_data(struct task_context *, ulong);
#define TASK_LEVEL         (0x1)
#define THREAD_GROUP_LEVEL (0x2)
#define TASK_INDENT        (0x4)
static int sigrt_minmax(int *, int *);
static void signame_list(void);
static void sigqueue_list(ulong);
static ulonglong task_signal(ulong, ulong*);
static ulonglong task_blocked(ulong);
static void translate_sigset(ulonglong);
static ulonglong sigaction_mask(ulong);
static int task_has_cpu(ulong, char *);
static int is_foreach_keyword(char *, int *);
static char *task_pointer_string(struct task_context *, ulong, char *);
static int panic_context_adjusted(struct task_context *tc);
static void show_last_run(struct task_context *);
static int sort_by_last_run(const void *arg1, const void *arg2);
static void sort_context_array_by_last_run(void);
static void irqstacks_init(void);

/*
 *  Figure out how much space will be required to hold the task context
 *  data, malloc() it, and call refresh_task_table() to fill it up.
 *  Gather a few key offset and size values.  Lastly, get, and then set, 
 *  the initial context.
 */
void
task_init(void)
{
	long len;
	int dim;
        struct syment *nsp;
	long tss_offset, thread_offset; 
	long eip_offset, esp_offset, ksp_offset;
	struct gnu_request req;
	ulong active_pid;

        if (kernel_symbol_exists("nr_tasks")) {
		/*
		 *  Figure out what maximum NR_TASKS would be by getting the 
		 *  address of the next symbol after "task".
		 */
	        tt->task_start = symbol_value("task");
	        if ((nsp = next_symbol("task", NULL)) == NULL)
	        	error(FATAL, "cannot determine size of task table\n");

		tt->flags |= TASK_ARRAY_EXISTS;
		tt->task_end = nsp->value;
	        tt->max_tasks = (tt->task_end-tt->task_start) / sizeof(void *);
		allocate_task_space(tt->max_tasks);

		tss_offset = MEMBER_OFFSET_INIT(task_struct_tss,  
			"task_struct", "tss");
		eip_offset = MEMBER_OFFSET_INIT(thread_struct_eip, 
			"thread_struct", "eip");
		esp_offset = MEMBER_OFFSET_INIT(thread_struct_esp,
			"thread_struct", "esp");
		ksp_offset = MEMBER_OFFSET_INIT(thread_struct_ksp, 
			"thread_struct", "ksp");
	        ASSIGN_OFFSET(task_struct_tss_eip) = 
			(eip_offset == INVALID_OFFSET) ? 
			INVALID_OFFSET : tss_offset + eip_offset;
	        ASSIGN_OFFSET(task_struct_tss_esp) = 
			(esp_offset == INVALID_OFFSET) ?
			INVALID_OFFSET : tss_offset + esp_offset;
                ASSIGN_OFFSET(task_struct_tss_ksp) = 
			(ksp_offset == INVALID_OFFSET) ?
                        INVALID_OFFSET : tss_offset + ksp_offset;

		tt->flags |= TASK_REFRESH;
		tt->refresh_task_table = refresh_fixed_task_table;

                readmem(tt->task_start, KVADDR, &tt->idle_threads[0],
                	kt->cpus * sizeof(void *), "idle threads",
                        FAULT_ON_ERROR);
	} else {
		/*
		 *  Make the task table big enough to hold what's running.
		 *  It can be realloc'd later if it grows on a live system.
	         */
	        get_symbol_data("nr_threads", sizeof(int), &tt->nr_threads);
		tt->max_tasks = tt->nr_threads + NR_CPUS + TASK_SLUSH; 
		allocate_task_space(tt->max_tasks);
	
		thread_offset = MEMBER_OFFSET_INIT(task_struct_thread, 
			"task_struct", "thread");
		eip_offset = MEMBER_OFFSET_INIT(thread_struct_eip,
			"thread_struct", "eip");
		esp_offset = MEMBER_OFFSET_INIT(thread_struct_esp,
			"thread_struct", "esp");
		ksp_offset = MEMBER_OFFSET_INIT(thread_struct_ksp,
			"thread_struct", "ksp");
	        ASSIGN_OFFSET(task_struct_thread_eip) = 
		    (eip_offset == INVALID_OFFSET) ? 
			INVALID_OFFSET : thread_offset + eip_offset;
	        ASSIGN_OFFSET(task_struct_thread_esp) = 
		    (esp_offset == INVALID_OFFSET) ?
			INVALID_OFFSET : thread_offset + esp_offset;
	        ASSIGN_OFFSET(task_struct_thread_ksp) = 
		    (ksp_offset == INVALID_OFFSET) ?
			INVALID_OFFSET : thread_offset + ksp_offset;
	
		tt->flags |= TASK_REFRESH;
		tt->refresh_task_table = refresh_unlimited_task_table;

		get_idle_threads(&tt->idle_threads[0], kt->cpus);
	}

        MEMBER_OFFSET_INIT(task_struct_thread_info, "task_struct", 
		"thread_info");
	if (VALID_MEMBER(task_struct_thread_info)) {
        	MEMBER_OFFSET_INIT(thread_info_task, "thread_info", "task"); 
        	MEMBER_OFFSET_INIT(thread_info_cpu, "thread_info", "cpu");
        	MEMBER_OFFSET_INIT(thread_info_flags, "thread_info", "flags");
        	MEMBER_OFFSET_INIT(thread_info_previous_esp, "thread_info", 
			"previous_esp");
		STRUCT_SIZE_INIT(thread_info, "thread_info");
		tt->flags |= THREAD_INFO;
	}

        MEMBER_OFFSET_INIT(task_struct_state, "task_struct", "state");
        MEMBER_OFFSET_INIT(task_struct_pid, "task_struct", "pid");
        MEMBER_OFFSET_INIT(task_struct_comm, "task_struct", "comm");
        MEMBER_OFFSET_INIT(task_struct_next_task, "task_struct", "next_task");
        MEMBER_OFFSET_INIT(task_struct_processor, "task_struct", "processor");
        MEMBER_OFFSET_INIT(task_struct_p_pptr, "task_struct", "p_pptr");
        MEMBER_OFFSET_INIT(task_struct_parent, "task_struct", "parent");
        MEMBER_OFFSET_INIT(task_struct_has_cpu, "task_struct", "has_cpu");
        MEMBER_OFFSET_INIT(task_struct_cpus_runnable,  
		"task_struct", "cpus_runnable");
	MEMBER_OFFSET_INIT(task_struct_cpu, "task_struct", "cpu");
	MEMBER_OFFSET_INIT(task_struct_active_mm, "task_struct", "active_mm");
	MEMBER_OFFSET_INIT(task_struct_next_run, "task_struct", "next_run");
	MEMBER_OFFSET_INIT(task_struct_flags, "task_struct", "flags");
        MEMBER_OFFSET_INIT(task_struct_pidhash_next,
                "task_struct", "pidhash_next");
	MEMBER_OFFSET_INIT(task_struct_pgrp, "task_struct", "pgrp");
	MEMBER_OFFSET_INIT(task_struct_tgid, "task_struct", "tgid");
        MEMBER_OFFSET_INIT(task_struct_pids, "task_struct", "pids");
        MEMBER_OFFSET_INIT(task_struct_last_run, "task_struct", "last_run");
        MEMBER_OFFSET_INIT(task_struct_timestamp, "task_struct", "timestamp");
	if (VALID_MEMBER(task_struct_last_run) || 
	    VALID_MEMBER(task_struct_timestamp)) {
		char buf[BUFSIZE];
	        strcpy(buf, "alias last ps -l");
        	alias_init(buf);
	}
	MEMBER_OFFSET_INIT(pid_link_pid, "pid_link", "pid");
	MEMBER_OFFSET_INIT(pid_hash_chain, "pid", "hash_chain");

	STRUCT_SIZE_INIT(pid_link, "pid_link");

	MEMBER_OFFSET_INIT(pid_pid_chain, "pid", "pid_chain");

	STRUCT_SIZE_INIT(task_struct, "task_struct");

	MEMBER_OFFSET_INIT(task_struct_sig, "task_struct", "sig");
	MEMBER_OFFSET_INIT(task_struct_signal, "task_struct", "signal");
	MEMBER_OFFSET_INIT(task_struct_blocked, "task_struct", "blocked");
	MEMBER_OFFSET_INIT(task_struct_sigpending, "task_struct", "sigpending");
	MEMBER_OFFSET_INIT(task_struct_pending, "task_struct", "pending");
	MEMBER_OFFSET_INIT(task_struct_sigqueue, "task_struct", "sigqueue");
	MEMBER_OFFSET_INIT(task_struct_sighand, "task_struct", "sighand");
	 
	MEMBER_OFFSET_INIT(signal_struct_count, "signal_struct", "count");
	MEMBER_OFFSET_INIT(signal_struct_action, "signal_struct", "action");
	MEMBER_OFFSET_INIT(signal_struct_shared_pending, "signal_struct",
		"shared_pending");

	MEMBER_OFFSET_INIT(k_sigaction_sa, "k_sigaction", "sa");
	
	MEMBER_OFFSET_INIT(sigaction_sa_handler, "sigaction", "sa_handler");
	MEMBER_OFFSET_INIT(sigaction_sa_mask, "sigaction", "sa_mask");
	MEMBER_OFFSET_INIT(sigaction_sa_flags, "sigaction", "sa_flags");
	MEMBER_OFFSET_INIT(sigpending_head, "sigpending", "head");
	if (INVALID_MEMBER(sigpending_head))
		MEMBER_OFFSET_INIT(sigpending_list, "sigpending", "list");
	MEMBER_OFFSET_INIT(sigpending_signal, "sigpending", "signal");
	MEMBER_SIZE_INIT(sigpending_signal, "sigpending", "signal");

	STRUCT_SIZE_INIT(sigqueue, "sigqueue");
       	STRUCT_SIZE_INIT(signal_queue, "signal_queue");

	STRUCT_SIZE_INIT(sighand_struct, "sighand_struct");
	if (VALID_STRUCT(sighand_struct))
		MEMBER_OFFSET_INIT(sighand_struct_action, "sighand_struct", 
			"action");

        MEMBER_OFFSET_INIT(siginfo_si_signo, "siginfo", "si_signo");

	STRUCT_SIZE_INIT(signal_struct, "signal_struct");
	STRUCT_SIZE_INIT(k_sigaction, "k_sigaction");

        MEMBER_OFFSET_INIT(task_struct_start_time, "task_struct", "start_time");
        MEMBER_SIZE_INIT(task_struct_start_time, "task_struct", "start_time");
        MEMBER_OFFSET_INIT(task_struct_times, "task_struct", "times");
        MEMBER_OFFSET_INIT(tms_tms_utime, "tms", "tms_utime");
        MEMBER_OFFSET_INIT(tms_tms_stime, "tms", "tms_stime");
	MEMBER_OFFSET_INIT(task_struct_utime, "task_struct", "utime");
	MEMBER_OFFSET_INIT(task_struct_stime, "task_struct", "stime");

	STRUCT_SIZE_INIT(cputime_t, "cputime_t");

	if (symbol_exists("cfq_slice_async")) {
		uint cfq_slice_async;

		get_symbol_data("cfq_slice_async", sizeof(int), 
			&cfq_slice_async);
		machdep->hz = cfq_slice_async * 25; 

		if (CRASHDEBUG(2))
			fprintf(fp, 
			    "cfq_slice_async exitsts: setting hz to %d\n", 
				machdep->hz);
	}

	if (VALID_MEMBER(runqueue_arrays)) 
		MEMBER_OFFSET_INIT(task_struct_run_list, "task_struct",
			"run_list");

        if ((tt->task_struct = (char *)malloc(SIZE(task_struct))) == NULL)
        	error(FATAL, "cannot malloc task_struct space.");

        if ((tt->mm_struct = (char *)malloc(SIZE(mm_struct))) == NULL)
        	error(FATAL, "cannot malloc mm_struct space.");

	if ((tt->flags & THREAD_INFO) &&
            ((tt->thread_info = (char *)malloc(SIZE(thread_info))) == NULL)) 
        	error(FATAL, "cannot malloc thread_info space.");

	STRUCT_SIZE_INIT(task_union, "task_union");
	STRUCT_SIZE_INIT(thread_union, "thread_union");

	if (VALID_SIZE(task_union) && (SIZE(task_union) != STACKSIZE())) {
		error(WARNING, "\nnon-standard stack size: %ld\n", 
			len = SIZE(task_union));
		machdep->stacksize = len;
	} else if (VALID_SIZE(thread_union) && 
	    	((len = SIZE(thread_union)) != STACKSIZE())) 
		machdep->stacksize = len;

	if (symbol_exists("pidhash") && symbol_exists("pid_hash") &&
	    !symbol_exists("pidhash_shift"))
		error(FATAL, 
        "pidhash and pid_hash both exist -- cannot distinquish between them\n");

	if (symbol_exists("pid_hash") && symbol_exists("pidhash_shift")) {
		int pidhash_shift;

	   	if (get_symbol_type("PIDTYPE_PID", NULL, &req) != 
		    TYPE_CODE_ENUM) 
			error(FATAL,
		           "cannot determine PIDTYPE_PID pid_hash dimension\n");

		get_symbol_data("pidhash_shift", sizeof(int), &pidhash_shift);
		tt->pidhash_len = 1 << pidhash_shift;
		get_symbol_data("pid_hash", sizeof(ulong), &tt->pidhash_addr);

		if (VALID_MEMBER(pid_link_pid) && VALID_MEMBER(pid_hash_chain)) {
			get_symbol_data("pid_hash", sizeof(ulong), &tt->pidhash_addr);
                	tt->refresh_task_table = refresh_pid_hash_task_table;
		} else {
                	tt->pidhash_addr = symbol_value("pid_hash");
			if (!get_array_length("pid_hash", NULL, sizeof(void *)) &&
			    VALID_STRUCT(pid_link))
                		tt->refresh_task_table = refresh_hlist_task_table_v2;
			else
                		tt->refresh_task_table = refresh_hlist_task_table;
		}

                tt->flags |= PID_HASH;

	} else if (symbol_exists("pid_hash")) { 
	   	if (get_symbol_type("PIDTYPE_PGID", NULL, &req) != 
		    TYPE_CODE_ENUM) 
			error(FATAL,
		           "cannot determine PIDTYPE_PID pid_hash dimension\n");
		if (!(tt->pidhash_len = get_array_length("pid_hash",
                    &dim, SIZE(list_head))))
			error(FATAL, 
				"cannot determine pid_hash array dimensions\n");
                
                tt->pidhash_addr = symbol_value("pid_hash");
                tt->refresh_task_table = refresh_pid_hash_task_table;
                tt->flags |= PID_HASH;

        } else if (symbol_exists("pidhash")) {
                tt->pidhash_addr = symbol_value("pidhash");
                tt->pidhash_len = get_array_length("pidhash", NULL, 0);
                if (tt->pidhash_len == 0) {
                        if (!(nsp = next_symbol("pidhash", NULL)))
                                error(FATAL,
                                    "cannot determine pidhash length\n");
                        tt->pidhash_len =
                                (nsp->value-tt->pidhash_addr) / sizeof(void *);
                }
                if (ACTIVE())
                        tt->refresh_task_table = refresh_pidhash_task_table;
                tt->flags |= PIDHASH;
	}

	/*
	 *  Get the IRQ stacks info if it's configured.
	 */
        if (VALID_STRUCT(irq_ctx))
		irqstacks_init();

	get_active_set();
	tt->refresh_task_table(); 

	if (tt->flags & TASK_REFRESH_OFF) 
		tt->flags &= ~(TASK_REFRESH|TASK_REFRESH_OFF);

	if (ACTIVE()) {
		active_pid = REMOTE() ? pc->server_pid : pc->program_pid; 
		set_context(NO_TASK, active_pid);
		tt->this_task = pid_to_task(active_pid);
	}
	else
		set_context(get_panic_context(), NO_PID);

	sort_context_array();

	tt->flags |= TASK_INIT_DONE;
}

/*
 *  Store the pointers to the hard and soft irq_ctx arrays as well as
 *  the task pointers contained within each of them.
 */
static void
irqstacks_init(void)
{
	int i;
	char *thread_info_buf;

	thread_info_buf = GETBUF(SIZE(irq_ctx));

        i = get_array_length("hardirq_ctx", NULL, 0);
        get_symbol_data("hardirq_ctx",
                sizeof(long)*(i <= NR_CPUS ? i : NR_CPUS),
                &tt->hardirq_ctx[0]);

	for (i = 0; i < NR_CPUS; i++) {
        	if (!(tt->hardirq_ctx[i]))
                        continue;

                if (!readmem(tt->hardirq_ctx[i], KVADDR, thread_info_buf, 
		    SIZE(irq_ctx), "hardirq thread_union", 
		    RETURN_ON_ERROR)) {
                	error(INFO, "cannot read hardirq_ctx[%d] at %lx\n",
                            	i, tt->hardirq_ctx[i]);
                        continue;
                }

                tt->hardirq_tasks[i] = 
			ULONG(thread_info_buf+OFFSET(thread_info_task));
	}

        i = get_array_length("softirq_ctx", NULL, 0);
        get_symbol_data("softirq_ctx",
                sizeof(long)*(i <= NR_CPUS ? i : NR_CPUS),
                &tt->softirq_ctx[0]);

        for (i = 0; i < NR_CPUS; i++) {
                if (!(tt->softirq_ctx[i]))
                        continue;

                if (!readmem(tt->softirq_ctx[i], KVADDR, thread_info_buf,
                    SIZE(irq_ctx), "softirq thread_union",
                    RETURN_ON_ERROR)) {
			error(INFO, "cannot read softirq_ctx[%d] at %lx\n",
                       		i, tt->hardirq_ctx[i]);
                    	continue;
                }

                tt->softirq_tasks[i] =
                        ULONG(thread_info_buf+OFFSET(thread_info_task));
        }


        tt->flags |= IRQSTACKS;

	FREEBUF(thread_info_buf);

}

/*
 *  Allocate or re-allocated space for the task_context array and task list.
 */
static void
allocate_task_space(int cnt)
{
	if (tt->context_array == NULL) {
               if (!(tt->task_local = (void *)
                    malloc(cnt * sizeof(void *))))
                        error(FATAL,
                            "cannot malloc kernel task array (%d tasks)", cnt);

                if (!(tt->context_array = (struct task_context *)
                    malloc(cnt * sizeof(struct task_context))))
                        error(FATAL, "cannot malloc context array (%d tasks)",
                                cnt);
	} else {
                if (!(tt->task_local = (void *)
		    realloc(tt->task_local, cnt * sizeof(void *)))) 
                        error(FATAL,
                            "%scannot realloc kernel task array (%d tasks)",
                            	(pc->flags & RUNTIME) ? "" : "\n", cnt);
                
                if (!(tt->context_array = (struct task_context *)
                    realloc(tt->context_array, 
		    cnt * sizeof(struct task_context)))) 
                        error(FATAL,
                            "%scannot realloc context array (%d tasks)",
	                	(pc->flags & RUNTIME) ? "" : "\n", cnt);
	}
}


/*
 *  This routine runs one time on dumpfiles, and constantly on live systems.
 *  It walks through the kernel task array looking for active tasks, and
 *  populates the local task table with their essential data.
 */
static void
refresh_fixed_task_table(void)
{
	int i;
	ulong *tlp;
	struct task_context *tc;
	ulong curtask;
	ulong retries;
	ulong curpid;
	char *tp;

#define TASK_FREE(x)   ((x == 0) || (((ulong)(x) >= tt->task_start) && \
                       ((ulong)(x) < tt->task_end)))
#define TASK_IN_USE(x) (!TASK_FREE(x))

	if (DUMPFILE() && (tt->flags & TASK_INIT_DONE))
		return;

	if (DUMPFILE()) {
        	fprintf(fp, (pc->flags & SILENT) || !(pc->flags & TTY) ?
                        "" : "%splease wait... (gathering task table data)",
			GDB_PATCHED() ? "" : "\n");
		fflush(fp);
		if (!symbol_exists("panic_threads"))
			tt->flags |= POPULATE_PANIC;
	} 

	if (ACTIVE() && !(tt->flags & TASK_REFRESH))
		return;

        /*
         *  The current task's task_context entry may change,
         *  or the task may not even exist anymore.
         */
	if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) {
		curtask = CURRENT_TASK();
		curpid = CURRENT_PID();
	}

	retries = 0;
retry:
        if (!readmem(tt->task_start, KVADDR, tt->task_local,
            tt->max_tasks * sizeof(void *), "kernel task array", 
	    RETURN_ON_ERROR))
        	error(FATAL, "cannot read kernel task array");

	clear_task_cache();

        for (i = 0, tlp = (ulong *)tt->task_local, 
	     tt->running_tasks = 0, tc = tt->context_array;
             i < tt->max_tasks; i++, tlp++) {
                if (TASK_IN_USE(*tlp)) {
                	if (!(tp = fill_task_struct(*tlp))) {
                        	if (DUMPFILE())
                                	continue;
                        	retries++;
                        	goto retry;
                	}

                	if (store_context(tc, *tlp, tp)) {
                        	tc++;
                        	tt->running_tasks++;
                	}
		}
        }

	if (DUMPFILE()) {
		fprintf(fp, (pc->flags & SILENT) || !(pc->flags & TTY) ? "" :
                        "\r                                                \r");
                fflush(fp);
	}

        if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) 
		refresh_context(curtask, curpid);

	tt->retries = MAX(tt->retries, retries);
}

/*
 *  Verify that a task_context's data makes sense enough to include
 *  in the task_context array.
 */
static int
verify_task(struct task_context *tc, int level)
{
	ulong next_task;
	ulong readflag;

        readflag = ACTIVE() ? (RETURN_ON_ERROR|QUIET) : (RETURN_ON_ERROR);

	switch (level)
	{
	case 1:
        	if (!readmem(tc->task + OFFSET(task_struct_next_task),
	    	    KVADDR, &next_task, sizeof(void *), "next_task", readflag)) {
			return FALSE;
        	}
		if (!IS_TASK_ADDR(next_task))
			return FALSE;

		if (tc->processor & ~NO_PROC_ID)
			return FALSE;

		/* fall through */
	case 2:
        	if ((tc->processor < 0) || (tc->processor >= NR_CPUS))
			return FALSE;

		if (!IS_TASK_ADDR(tc->ptask))
			return FALSE;
		break;
	}

	return TRUE;
}

/*
 *  This routine runs one time on dumpfiles, and constantly on live systems.
 *  It walks through the kernel task array looking for active tasks, and
 *  populates the local task table with their essential data.
 */

#define MAX_UNLIMITED_TASK_RETRIES (500)

void
refresh_unlimited_task_table(void)
{
	int i;
	ulong *tlp;
	struct task_context *tc;
	ulong curtask;
	ulong curpid;
	struct list_data list_data, *ld;
	ulong init_tasks[NR_CPUS];
	ulong retries;
	char *tp;
	int cnt;

	if (DUMPFILE() && (tt->flags & TASK_INIT_DONE))
		return;

        if (DUMPFILE()) {
                fprintf(fp, (pc->flags & SILENT) || !(pc->flags & TTY) ?
                        "" : "%splease wait... (gathering task table data)",
                        GDB_PATCHED() ? "" : "\n");
                fflush(fp);
		if (!symbol_exists("panic_threads"))
			tt->flags |= POPULATE_PANIC;
        } 

        if (ACTIVE() && !(tt->flags & TASK_REFRESH))
                return;

	/*
	 *  The current task's task_context entry may change,  
	 *  or the task may not even exist anymore.
	 */
        if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) {
                curtask = CURRENT_TASK();
                curpid = CURRENT_PID();
        }

	retries = 0;
retry:
	if (retries && DUMPFILE()) {
		if (tt->flags & PIDHASH) {
			error(WARNING, 
		      "\ncannot gather a stable task list -- trying pidhash\n");
			refresh_pidhash_task_table();
			return;
		}
		error(FATAL, "\ncannot gather a stable task list\n");
	}

	if ((retries == MAX_UNLIMITED_TASK_RETRIES) &&  
	    !(tt->flags & TASK_INIT_DONE)) 
		error(FATAL, "cannot gather a stable task list\n");

	/*
	 *  Populate the task_local array with a quick walk-through.
 	 *  If there's not enough room in the local array, realloc() it.
	 */
	ld = &list_data;
	BZERO(ld, sizeof(struct list_data));
	ld->flags |= RETURN_ON_LIST_ERROR;
	ld->start = symbol_value("init_task_union");
	ld->member_offset = OFFSET(task_struct_next_task);

	if (!hq_open()) {
		error(INFO, "cannot hash task_struct entries\n");
		if (!(tt->flags & TASK_INIT_DONE))
			clean_exit(1);
		error(INFO, "using stale task_structs\n");
		FREEBUF(tp);
		return;
	}

	if ((cnt = do_list(ld)) < 0) {
		retries++;
		goto retry;
	}

	if ((cnt+NR_CPUS+1) > tt->max_tasks) { 
		tt->max_tasks = cnt + NR_CPUS + TASK_SLUSH;
		allocate_task_space(tt->max_tasks);
		hq_close();
		if (!DUMPFILE())
			retries++;
		goto retry;
	}

	BZERO(tt->task_local, tt->max_tasks * sizeof(void *));
	cnt = retrieve_list((ulong *)tt->task_local, cnt);
	hq_close();

	/*
	 *  If SMP, add in the other idle tasks.
	 */
	if (kt->flags & SMP) {   
        	/*
         	 *  Now get the rest of the init_task[] entries, starting
		 *  at offset 1 since we've got the init_task already.
         	 */
		BZERO(&init_tasks[0], sizeof(ulong) * NR_CPUS);
		get_idle_threads(&init_tasks[0], kt->cpus);

		tlp = (ulong *)tt->task_local;
		tlp += cnt;

		for (i = 1; i < kt->cpus; i++) {
			if (init_tasks[i]) {
				*tlp = init_tasks[i];
				tlp++;
			}
	 	}
	}

	clear_task_cache();

        for (i = 0, tlp = (ulong *)tt->task_local, 
             tt->running_tasks = 0, tc = tt->context_array;
             i < tt->max_tasks; i++, tlp++) {
		if (!(*tlp))
			continue;

		if (!IS_TASK_ADDR(*tlp)) {
			error(INFO, 
			    "\ninvalid task address in task list: %lx\n", *tlp);
			retries++;
			goto retry;
		}	
	
		if (task_exists(*tlp)) {
			error(INFO, 
		            "\nduplicate task address in task list: %lx\n",
				*tlp);
			retries++;
			goto retry;
		}

                if (!(tp = fill_task_struct(*tlp))) {
                     	if (DUMPFILE())
                        	continue;
                        retries++;
                        goto retry;
                }

		if (store_context(tc, *tlp, tp)) {
                	tc++;
                	tt->running_tasks++;
		}
	}

	if (DUMPFILE()) {
		fprintf(fp, (pc->flags & SILENT) || !(pc->flags & TTY) ? "" :
                        "\r                                                \r");
                fflush(fp);
	}

        if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) 
		refresh_context(curtask, curpid);

	tt->retries = MAX(tt->retries, retries);

}

/*
 *  This routine runs one time on dumpfiles, and constantly on live systems.
 *  It walks through the kernel pidhash array looking for active tasks, and
 *  populates the local task table with their essential data.
 *
 *  The following manner of refreshing the task table can be used for all
 *  kernels that have a pidhash[] array, whether or not they still 
 *  have a fixed task[] array or an unlimited list.
 */
static void
refresh_pidhash_task_table(void)
{
	int i;
	char *pidhash, *tp; 
	ulong *pp, next, pnext;
	int len, cnt;
        struct task_context *tc;
        ulong curtask;
        ulong curpid;
        ulong retries;
	ulong *tlp;

        if (DUMPFILE() && (tt->flags & TASK_INIT_DONE))   /* impossible */
                return;

        if (DUMPFILE()) {                                 /* impossible */
                fprintf(fp, (pc->flags & SILENT) || !(pc->flags & TTY) ?
                        "" : "\rplease wait... (gathering task table data)");
                fflush(fp);
                if (!symbol_exists("panic_threads"))
                        tt->flags |= POPULATE_PANIC;
        }

        if (ACTIVE() && !(tt->flags & TASK_REFRESH))
                return;

        /*
         *  The current task's task_context entry may change,
         *  or the task may not even exist anymore.
         */
        if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) {
                curtask = CURRENT_TASK();
                curpid = CURRENT_PID();
        }

	len = tt->pidhash_len;
	pidhash = GETBUF(len * sizeof(ulong));
        retries = 0;

retry_pidhash:
	if (retries && DUMPFILE())
		error(FATAL,"\ncannot gather a stable task list via pidhash\n");

        if ((retries == MAX_UNLIMITED_TASK_RETRIES) &&
            !(tt->flags & TASK_INIT_DONE)) 
                error(FATAL, 
	        "\ncannot gather a stable task list via pidhash (%d retries)\n",
			retries);

        if (!readmem(tt->pidhash_addr, KVADDR, pidhash, 
	    len * sizeof(ulong), "pidhash contents", RETURN_ON_ERROR)) 
		error(FATAL, "\ncannot read pidhash array\n");

        if (!hq_open()) {
                error(INFO, "cannot hash task_struct entries\n");
                if (!(tt->flags & TASK_INIT_DONE))
                        clean_exit(1);
                error(INFO, "using stale task_structs\n");
                FREEBUF(pidhash);
                return;
        }

	/*
	 *  Get the idle threads first. 
	 */
	cnt = 0;
	for (i = 0; i < kt->cpus; i++) {
		if (hq_enter(tt->idle_threads[i]))
			cnt++;
		else
			error(WARNING, "%sduplicate idle tasks?\n",
				DUMPFILE() ? "\n" : "");
	}

	/*
	 *  Then dump the pidhash contents.
	 */
	for (i = 0, pp = (ulong *)pidhash; i < len; i++, pp++) {
		if (!(*pp) || !IS_KVADDR(*pp))
			continue;
		/*
		 *  Mininum verification here -- make sure that a task address
		 *  and its pidhash_next entry (if any) both appear to be 
		 *  properly aligned before accepting the task.
		 */
		next = *pp;
		while (next) {
			if (!IS_TASK_ADDR(next)) {
                                error(INFO, 
				    "%sinvalid task address in pidhash: %lx\n",
                                        DUMPFILE() ? "\n" : "", next);
                                if (DUMPFILE()) 
                                        break;
                                hq_close();
                                retries++;
                                goto retry_pidhash;

			}

                        if (!readmem(next + OFFSET(task_struct_pidhash_next),
                            KVADDR, &pnext, sizeof(void *),
                            "pidhash_next entry", QUIET|RETURN_ON_ERROR)) {
                                error(INFO, "%scannot read from task: %lx\n",
                                        DUMPFILE() ? "\n" : "", next);
				if (DUMPFILE()) 
					break;
                                hq_close();
				retries++;
                                goto retry_pidhash;
                        }

			if (!hq_enter(next)) {
				error(INFO, 
				    "%sduplicate task in pidhash: %lx\n",
					DUMPFILE() ? "\n" : "", next);
				if (DUMPFILE())
					break;
				hq_close();
				retries++;
				goto retry_pidhash;
			}

			next = pnext;

			cnt++;
		}
	}

        if ((cnt+1) > tt->max_tasks) {
                tt->max_tasks = cnt + NR_CPUS + TASK_SLUSH;
		allocate_task_space(tt->max_tasks);
                hq_close();
		if (!DUMPFILE())
                	retries++;
                goto retry_pidhash;
        }

        BZERO(tt->task_local, tt->max_tasks * sizeof(void *));
        cnt = retrieve_list((ulong *)tt->task_local, cnt);

	hq_close();

	clear_task_cache();

        for (i = 0, tlp = (ulong *)tt->task_local, 
             tt->running_tasks = 0, tc = tt->context_array;
             i < tt->max_tasks; i++, tlp++) {
		if (!(*tlp))
			continue;

		if (!IS_TASK_ADDR(*tlp)) {
			error(WARNING, 
		            "%sinvalid task address found in task list: %lx\n", 
				DUMPFILE() ? "\n" : "", *tlp);
			if (DUMPFILE()) 
				continue;
			retries++;
			goto retry_pidhash;
		}	
	
		if (task_exists(*tlp)) {
			error(WARNING, 
		           "%sduplicate task address found in task list: %lx\n",
				DUMPFILE() ? "\n" : "", *tlp);
			if (DUMPFILE())
				continue;
			retries++;
			goto retry_pidhash;
		}

		if (!(tp = fill_task_struct(*tlp))) {
                        if (DUMPFILE())
                                continue;
                        retries++;
                        goto retry_pidhash;
                }

		if (store_context(tc, *tlp, tp)) {
			tc++;
			tt->running_tasks++;
		}
	}

        FREEBUF(pidhash);

	if (DUMPFILE()) {
		fprintf(fp, (pc->flags & SILENT) || !(pc->flags & TTY) ? "" :
                        "\r                                                \r");
                fflush(fp);
	}

        if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) 
		refresh_context(curtask, curpid);

	tt->retries = MAX(tt->retries, retries);
}


/*
 *  The following manner of refreshing the task table is used for all
 *  kernels that have a pid_hash[][] array.
 *
 *  This routine runs one time on dumpfiles, and constantly on live systems.
 *  It walks through the kernel pid_hash[PIDTYPE_PID] array looking for active
 *  tasks, and populates the local task table with their essential data.
 */

#define HASH_TO_TASK(X) ((ulong)(X) - (OFFSET(task_struct_pids) + \
                         OFFSET(pid_link_pid) + OFFSET(pid_hash_chain)))

#define TASK_TO_HASH(X) ((ulong)(X) + (OFFSET(task_struct_pids) + \
                         OFFSET(pid_link_pid) + OFFSET(pid_hash_chain)))

static void
refresh_pid_hash_task_table(void)
{
	int i;
	struct kernel_list_head *pid_hash, *pp, *kpp;
	char *tp; 
	ulong next, pnext;
	int len, cnt;
        struct task_context *tc;
        ulong curtask;
        ulong curpid;
        ulong retries;
	ulong *tlp;

        if (DUMPFILE() && (tt->flags & TASK_INIT_DONE))   /* impossible */
                return;

        if (DUMPFILE()) {                                 /* impossible */
		please_wait("gathering task table data");
                if (!symbol_exists("panic_threads"))
                        tt->flags |= POPULATE_PANIC;
        }

        if (ACTIVE() && !(tt->flags & TASK_REFRESH))
                return;

        /*
         *  The current task's task_context entry may change,
         *  or the task may not even exist anymore.
         */
        if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) {
                curtask = CURRENT_TASK();
                curpid = CURRENT_PID();
        }

	len = tt->pidhash_len;
	pid_hash = (struct kernel_list_head *)GETBUF(len * SIZE(list_head));
        retries = 0;

retry_pid_hash:
	if (retries && DUMPFILE())
		error(FATAL,
			"\ncannot gather a stable task list via pid_hash\n");

        if ((retries == MAX_UNLIMITED_TASK_RETRIES) &&
            !(tt->flags & TASK_INIT_DONE)) 
                error(FATAL, 
	       "\ncannot gather a stable task list via pid_hash (%d retries)\n",
			retries);

        if (!readmem(tt->pidhash_addr, KVADDR, pid_hash, 
	    len * SIZE(list_head), "pid_hash contents", RETURN_ON_ERROR)) 
		error(FATAL, "\ncannot read pid_hash array\n");

        if (!hq_open()) {
                error(INFO, "cannot hash task_struct entries\n");
                if (!(tt->flags & TASK_INIT_DONE))
                        clean_exit(1);
                error(INFO, "using stale task_structs\n");
                FREEBUF(pid_hash);
                return;
        }

	/*
	 *  Get the idle threads first. 
	 */
	cnt = 0;
	for (i = 0; i < kt->cpus; i++) {
		if (hq_enter(tt->idle_threads[i]))
			cnt++;
		else
			error(WARNING, "%sduplicate idle tasks?\n",
				DUMPFILE() ? "\n" : "");
	}

	for (i = 0; i < len; i++) {
		pp = &pid_hash[i];
		kpp = (struct kernel_list_head *)(tt->pidhash_addr + 
			i * SIZE(list_head));
		if (pp->next == kpp)
			continue;

		if (CRASHDEBUG(7))
		    console("%lx: pid_hash[%d]: %lx (%lx) %lx (%lx)\n", kpp, i,
			pp->next, HASH_TO_TASK(pp->next),
			pp->prev, HASH_TO_TASK(pp->prev));

		next = (ulong)HASH_TO_TASK(pp->next);
		while (next) {
                        if (!IS_TASK_ADDR(next)) {
                                error(INFO,
                                    "%sinvalid task address in pid_hash: %lx\n",
                                        DUMPFILE() ? "\n" : "", next);
                                if (DUMPFILE())
                                        break;
                                hq_close();
                                retries++;
                                goto retry_pid_hash;

                        }

                        if (!readmem(TASK_TO_HASH(next),
                            KVADDR, &pnext, sizeof(void *),
                            "pid_hash entry", QUIET|RETURN_ON_ERROR)) {
                                error(INFO, "%scannot read from task: %lx\n",
                                        DUMPFILE() ? "\n" : "", next);
                                if (DUMPFILE())
                                        break;
                                hq_close();
                                retries++;
                                goto retry_pid_hash;
                        }

                        if (!is_idle_thread(next) && !hq_enter(next)) {
                                error(INFO,
                                    "%sduplicate task in pid_hash: %lx\n",
                                        DUMPFILE() ? "\n" : "", next);
                                if (DUMPFILE())
                                        break;
                                hq_close();
                                retries++;
                                goto retry_pid_hash;
                        }

                        cnt++;

			if (pnext == (ulong)kpp) 
				break;

                        next = HASH_TO_TASK(pnext);
		}
	}

        BZERO(tt->task_local, tt->max_tasks * sizeof(void *));
        cnt = retrieve_list((ulong *)tt->task_local, cnt);

	hq_close();

	clear_task_cache();

        for (i = 0, tlp = (ulong *)tt->task_local, 
             tt->running_tasks = 0, tc = tt->context_array;
             i < tt->max_tasks; i++, tlp++) {
		if (!(*tlp))
			continue;

		if (!IS_TASK_ADDR(*tlp)) {
			error(WARNING, 
		            "%sinvalid task address found in task list: %lx\n", 
				DUMPFILE() ? "\n" : "", *tlp);
			if (DUMPFILE()) 
				continue;
			retries++;
			goto retry_pid_hash;
		}	
	
		if (task_exists(*tlp)) {
			error(WARNING, 
		           "%sduplicate task address found in task list: %lx\n",
				DUMPFILE() ? "\n" : "", *tlp);
			if (DUMPFILE())
				continue;
			retries++;
			goto retry_pid_hash;
		}

		if (!(tp = fill_task_struct(*tlp))) {
                        if (DUMPFILE())
                                continue;
                        retries++;
                        goto retry_pid_hash;
                }

		if (store_context(tc, *tlp, tp)) {
			tc++;
			tt->running_tasks++;
		}
	}

        FREEBUF(pid_hash);

	please_wait_done();

        if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) 
		refresh_context(curtask, curpid);

	tt->retries = MAX(tt->retries, retries);
}

/*
 *  Adapt to yet another scheme, using later 2.6 hlist_head and hlist_nodes.
 */

#define HLIST_TO_TASK(X) ((ulong)(X) - (OFFSET(task_struct_pids) + \
                           OFFSET(pid_pid_chain)))

static void
refresh_hlist_task_table(void)
{
	int i;
	ulong *pid_hash;
	struct syment *sp;
	ulong pidhash_array;
	ulong kpp;
	char *tp; 
	ulong next, pnext, pprev;
	char *nodebuf;
	int plen, len, cnt;
	long value;
        struct task_context *tc;
        ulong curtask;
        ulong curpid;
        ulong retries;
	ulong *tlp;

        if (DUMPFILE() && (tt->flags & TASK_INIT_DONE))   /* impossible */
                return;

        if (DUMPFILE()) {                                 /* impossible */
		please_wait("gathering task table data");
                if (!symbol_exists("panic_threads"))
                        tt->flags |= POPULATE_PANIC;
        }

        if (ACTIVE() && !(tt->flags & TASK_REFRESH))
                return;

        /*
         *  The current task's task_context entry may change,
         *  or the task may not even exist anymore.
         */
        if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) {
                curtask = CURRENT_TASK();
                curpid = CURRENT_PID();
        }

	if (!(plen = get_array_length("pid_hash", NULL, sizeof(void *)))) {
		/*
		 *  Workaround for gcc omitting debuginfo data for pid_hash.
		 */
		if (enumerator_value("PIDTYPE_MAX", &value)) {
			if ((sp = next_symbol("pid_hash", NULL)) &&
		    	    (((sp->value - tt->pidhash_addr) / sizeof(void *)) < value))
				error(WARNING, "possible pid_hash array mis-handling\n");
			plen = (int)value;
		} else {
			error(WARNING, 
			    "cannot determine pid_hash array dimensions\n");
			plen = 1;
		}
	}

	pid_hash = (ulong *)GETBUF(plen * sizeof(void *));

        if (!readmem(tt->pidhash_addr, KVADDR, pid_hash, 
	    plen * SIZE(hlist_head), "pid_hash[] contents", RETURN_ON_ERROR)) 
		error(FATAL, "\ncannot read pid_hash array\n");

	if (CRASHDEBUG(7)) 
		for (i = 0; i < plen; i++)
			console("pid_hash[%d]: %lx\n", i, pid_hash[i]);

	/*
	 *  The zero'th (PIDTYPE_PID) entry is the hlist_head array
	 *  that we want.
	 */
	if (CRASHDEBUG(1)) {
		if (!enumerator_value("PIDTYPE_PID", &value))
			error(WARNING, 
			    "possible pid_hash array mis-handling: PIDTYPE_PID: (unknown)\n");
		else if (value != 0)
			error(WARNING, 
			    "possible pid_hash array mis-handling: PIDTYPE_PID: %d \n", 
				value);
	}

	pidhash_array = pid_hash[0];
	FREEBUF(pid_hash);

	len = tt->pidhash_len;
	pid_hash = (ulong *)GETBUF(len * SIZE(hlist_head));
	nodebuf = GETBUF(SIZE(hlist_node));
        retries = 0;

retry_pid_hash:
	if (retries && DUMPFILE())
		error(FATAL,
			"\ncannot gather a stable task list via pid_hash\n");

        if ((retries == MAX_UNLIMITED_TASK_RETRIES) &&
            !(tt->flags & TASK_INIT_DONE)) 
                error(FATAL, 
	       "\ncannot gather a stable task list via pid_hash (%d retries)\n",
			retries);

        if (!readmem(pidhash_array, KVADDR, pid_hash, 
	    len * SIZE(hlist_head), "pid_hash[0] contents", RETURN_ON_ERROR)) 
		error(FATAL, "\ncannot read pid_hash[0] array\n");

        if (!hq_open()) {
                error(INFO, "cannot hash task_struct entries\n");
                if (!(tt->flags & TASK_INIT_DONE))
                        clean_exit(1);
                error(INFO, "using stale task_structs\n");
                FREEBUF(pid_hash);
                return;
        }

	/*
	 *  Get the idle threads first. 
	 */
	cnt = 0;
	for (i = 0; i < kt->cpus; i++) {
		if (hq_enter(tt->idle_threads[i]))
			cnt++;
		else
			error(WARNING, "%sduplicate idle tasks?\n",
				DUMPFILE() ? "\n" : "");
	}

	for (i = 0; i < len; i++) {
		if (!pid_hash[i])
			continue;

        	if (!readmem(pid_hash[i], KVADDR, nodebuf, 
	    	    SIZE(hlist_node), "pid_hash node", RETURN_ON_ERROR|QUIET)) { 
			error(INFO, "\ncannot read pid_hash node\n");
                        if (DUMPFILE())
                                continue;
                        hq_close();
                        retries++;
                        goto retry_pid_hash;
		}

		kpp = pid_hash[i];
		next = (ulong)HLIST_TO_TASK(kpp);
		pnext = ULONG(nodebuf + OFFSET(hlist_node_next));
		pprev = ULONG(nodebuf + OFFSET(hlist_node_pprev));

		if (CRASHDEBUG(1)) 
			console("pid_hash[%d]: %lx task: %lx (node: %lx) next: %lx pprev: %lx\n",
				i, pid_hash[i], next, kpp, pnext, pprev);

		while (next) {
                        if (!IS_TASK_ADDR(next)) {
                                error(INFO,
                                    "%sinvalid task address in pid_hash: %lx\n",
                                        DUMPFILE() ? "\n" : "", next);
                                if (DUMPFILE())
                                        break;
                                hq_close();
                                retries++;
                                goto retry_pid_hash;

                        }

                        if (!is_idle_thread(next) && !hq_enter(next)) {
                                error(INFO,
                                    "%sduplicate task in pid_hash: %lx\n",
                                        DUMPFILE() ? "\n" : "", next);
                                if (DUMPFILE())
                                        break;
                                hq_close();
                                retries++;
                                goto retry_pid_hash;
                        }

                        cnt++;

			if (!pnext) 
				break;

                        if (!readmem((ulonglong)pnext, KVADDR, nodebuf,
                                SIZE(hlist_node), "task hlist_node", RETURN_ON_ERROR|QUIET)) {
                                error(INFO, "\ncannot read hlist_node from task\n");
                                if (DUMPFILE())
                                        break;
                                hq_close();
                                retries++;
                                goto retry_pid_hash;
                        }

			kpp = (ulong)pnext;
			next = (ulong)HLIST_TO_TASK(kpp);
			pnext = ULONG(nodebuf + OFFSET(hlist_node_next));
			pprev = ULONG(nodebuf + OFFSET(hlist_node_pprev));

			if (CRASHDEBUG(1)) 
				console("  chained task: %lx (node: %lx) next: %lx pprev: %lx\n",
					(ulong)HLIST_TO_TASK(kpp), kpp, pnext, pprev);
		}
	}

        if (cnt > tt->max_tasks) {
                tt->max_tasks = cnt + TASK_SLUSH;
                allocate_task_space(tt->max_tasks);
                hq_close();
                if (!DUMPFILE())
                        retries++;
                goto retry_pid_hash;
        }

        BZERO(tt->task_local, tt->max_tasks * sizeof(void *));
        cnt = retrieve_list((ulong *)tt->task_local, cnt);

	hq_close();

	clear_task_cache();

        for (i = 0, tlp = (ulong *)tt->task_local, 
             tt->running_tasks = 0, tc = tt->context_array;
             i < tt->max_tasks; i++, tlp++) {
		if (!(*tlp))
			continue;

		if (!IS_TASK_ADDR(*tlp)) {
			error(WARNING, 
		            "%sinvalid task address found in task list: %lx\n", 
				DUMPFILE() ? "\n" : "", *tlp);
			if (DUMPFILE()) 
				continue;
			retries++;
			goto retry_pid_hash;
		}	
	
		if (task_exists(*tlp)) {
			error(WARNING, 
		           "%sduplicate task address found in task list: %lx\n",
				DUMPFILE() ? "\n" : "", *tlp);
			if (DUMPFILE())
				continue;
			retries++;
			goto retry_pid_hash;
		}

		if (!(tp = fill_task_struct(*tlp))) {
                        if (DUMPFILE())
                                continue;
                        retries++;
                        goto retry_pid_hash;
                }

		if (store_context(tc, *tlp, tp)) {
			tc++;
			tt->running_tasks++;
		}
	}

        FREEBUF(pid_hash);
	FREEBUF(nodebuf);

	please_wait_done();

        if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) 
		refresh_context(curtask, curpid);

	tt->retries = MAX(tt->retries, retries);
}

/*
 *  2.6.17 replaced:
 *    static struct hlist_head *pid_hash[PIDTYPE_MAX];
 *  with
 *     static struct hlist_head *pid_hash;
 */
static void
refresh_hlist_task_table_v2(void)
{
	int i;
	ulong *pid_hash;
	ulong pidhash_array;
	ulong kpp;
	char *tp; 
	ulong next, pnext, pprev;
	char *nodebuf;
	int len, cnt;
        struct task_context *tc;
        ulong curtask;
        ulong curpid;
        ulong retries;
	ulong *tlp;

        if (DUMPFILE() && (tt->flags & TASK_INIT_DONE))   /* impossible */
                return;

        if (DUMPFILE()) {                                 /* impossible */
		please_wait("gathering task table data");
                if (!symbol_exists("panic_threads"))
                        tt->flags |= POPULATE_PANIC;
        }

        if (ACTIVE() && !(tt->flags & TASK_REFRESH))
                return;

        /*
         *  The current task's task_context entry may change,
         *  or the task may not even exist anymore.
         */
        if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) {
                curtask = CURRENT_TASK();
                curpid = CURRENT_PID();
        }

	get_symbol_data("pid_hash", sizeof(void *), &pidhash_array);

	len = tt->pidhash_len;
	pid_hash = (ulong *)GETBUF(len * SIZE(hlist_head));
	nodebuf = GETBUF(SIZE(pid_link));
        retries = 0;

retry_pid_hash:
	if (retries && DUMPFILE())
		error(FATAL,
			"\ncannot gather a stable task list via pid_hash\n");

        if ((retries == MAX_UNLIMITED_TASK_RETRIES) &&
            !(tt->flags & TASK_INIT_DONE)) 
                error(FATAL, 
	       "\ncannot gather a stable task list via pid_hash (%d retries)\n",
			retries);

        if (!readmem(pidhash_array, KVADDR, pid_hash, 
	    len * SIZE(hlist_head), "pid_hash contents", RETURN_ON_ERROR)) 
		error(FATAL, "\ncannot read pid_hash array\n");

        if (!hq_open()) {
                error(INFO, "cannot hash task_struct entries\n");
                if (!(tt->flags & TASK_INIT_DONE))
                        clean_exit(1);
                error(INFO, "using stale task_structs\n");
                FREEBUF(pid_hash);
                return;
        }

	/*
	 *  Get the idle threads first. 
	 */
	cnt = 0;
	for (i = 0; i < kt->cpus; i++) {
		if (hq_enter(tt->idle_threads[i]))
			cnt++;
		else
			error(WARNING, "%sduplicate idle tasks?\n",
				DUMPFILE() ? "\n" : "");
	}

	for (i = 0; i < len; i++) {
		if (!pid_hash[i])
			continue;

        	if (!readmem(pid_hash[i], KVADDR, nodebuf, 
	    	    SIZE(pid_link), "pid_hash node pid_link", RETURN_ON_ERROR|QUIET)) { 
			error(INFO, "\ncannot read pid_hash node pid_link\n");
                        if (DUMPFILE())
                                continue;
                        hq_close();
                        retries++;
                        goto retry_pid_hash;
		}

		kpp = pid_hash[i];
		next = ULONG(nodebuf + OFFSET(pid_link_pid)); 
		if (next)
			next -= OFFSET(task_struct_pids);
		pnext = ULONG(nodebuf + OFFSET(hlist_node_next));
		pprev = ULONG(nodebuf + OFFSET(hlist_node_pprev));

		if (CRASHDEBUG(1)) 
			console("pid_hash[%d]: %lx task: %lx (node: %lx) next: %lx pprev: %lx\n",
				i, pid_hash[i], next, kpp, pnext, pprev);

		while (next) {
                        if (!IS_TASK_ADDR(next)) {
                                error(INFO,
                                    "%sinvalid task address in pid_hash: %lx\n",
                                        DUMPFILE() ? "\n" : "", next);
                                if (DUMPFILE())
                                        break;
                                hq_close();
                                retries++;
                                goto retry_pid_hash;

                        }

                        if (!is_idle_thread(next) && !hq_enter(next)) {
                                error(INFO,
                                    "%sduplicate task in pid_hash: %lx\n",
                                        DUMPFILE() ? "\n" : "", next);
                                if (DUMPFILE())
                                        break;
                                hq_close();
                                retries++;
                                goto retry_pid_hash;
                        }

                        cnt++;

			if (!pnext) 
				break;

                        if (!readmem((ulonglong)pnext, KVADDR, nodebuf,
                                SIZE(pid_link), "task hlist_node pid_link", RETURN_ON_ERROR|QUIET)) {
                                error(INFO, "\ncannot read hlist_node pid_link from node next\n");
                                if (DUMPFILE())
                                        break;
                                hq_close();
                                retries++;
                                goto retry_pid_hash;
                        }

			kpp = (ulong)pnext;
			next = ULONG(nodebuf + OFFSET(pid_link_pid));
			if (next)
				next -= OFFSET(task_struct_pids);
			pnext = ULONG(nodebuf + OFFSET(hlist_node_next));
			pprev = ULONG(nodebuf + OFFSET(hlist_node_pprev));

			if (CRASHDEBUG(1)) 
				console("  chained task: %lx (node: %lx) next: %lx pprev: %lx\n",
					next, kpp, pnext, pprev);
		}
	}

        if (cnt > tt->max_tasks) {
                tt->max_tasks = cnt + TASK_SLUSH;
                allocate_task_space(tt->max_tasks);
                hq_close();
                if (!DUMPFILE())
                        retries++;
                goto retry_pid_hash;
        }

        BZERO(tt->task_local, tt->max_tasks * sizeof(void *));
        cnt = retrieve_list((ulong *)tt->task_local, cnt);

	hq_close();

	clear_task_cache();

        for (i = 0, tlp = (ulong *)tt->task_local, 
             tt->running_tasks = 0, tc = tt->context_array;
             i < tt->max_tasks; i++, tlp++) {
		if (!(*tlp))
			continue;

		if (!IS_TASK_ADDR(*tlp)) {
			error(WARNING, 
		            "%sinvalid task address found in task list: %lx\n", 
				DUMPFILE() ? "\n" : "", *tlp);
			if (DUMPFILE()) 
				continue;
			retries++;
			goto retry_pid_hash;
		}	
	
		if (task_exists(*tlp)) {
			error(WARNING, 
		           "%sduplicate task address found in task list: %lx\n",
				DUMPFILE() ? "\n" : "", *tlp);
			if (DUMPFILE())
				continue;
			retries++;
			goto retry_pid_hash;
		}

		if (!(tp = fill_task_struct(*tlp))) {
                        if (DUMPFILE())
                                continue;
                        retries++;
                        goto retry_pid_hash;
                }

		if (store_context(tc, *tlp, tp)) {
			tc++;
			tt->running_tasks++;
		}
	}

        FREEBUF(pid_hash);
	FREEBUF(nodebuf);

	please_wait_done();

        if (ACTIVE() && (tt->flags & TASK_INIT_DONE)) 
		refresh_context(curtask, curpid);

	tt->retries = MAX(tt->retries, retries);
}


/*
 *  Fill a task_context structure with the data from a task.  If a NULL
 *  task_context pointer is passed in, use the next available one.
 */
static struct task_context *
store_context(struct task_context *tc, ulong task, char *tp)
{
        pid_t *pid_addr;
        char *comm_addr;
        int *processor_addr;
        ulong *parent_addr;
        ulong *mm_addr;
        int has_cpu;
	int do_verify;

	if (tt->refresh_task_table == refresh_fixed_task_table)
		do_verify = 1;
	else if (tt->refresh_task_table == refresh_pid_hash_task_table)
		do_verify = 2;
	else
		do_verify = 0;

	if (!tc)
		tc = tt->context_array + tt->running_tasks;

        pid_addr = (pid_t *)(tp + OFFSET(task_struct_pid));
        comm_addr = (char *)(tp + OFFSET(task_struct_comm));
	if (tt->flags & THREAD_INFO) {
		tc->thread_info = ULONG(tp + OFFSET(task_struct_thread_info));
		fill_thread_info(tc->thread_info);
		processor_addr = (int *) (tt->thread_info + 
			OFFSET(thread_info_cpu));
	} else if (VALID_MEMBER(task_struct_processor))
                processor_addr = (int *) (tp + OFFSET(task_struct_processor));
        else if (VALID_MEMBER(task_struct_cpu))
                processor_addr = (int *) (tp + OFFSET(task_struct_cpu));
	if (VALID_MEMBER(task_struct_p_pptr))
        	parent_addr = (ulong *)(tp + OFFSET(task_struct_p_pptr));
	else
        	parent_addr = (ulong *)(tp + OFFSET(task_struct_parent));
        mm_addr = (ulong *)(tp + OFFSET(task_struct_mm));
        has_cpu = task_has_cpu(task, tp);

        tc->pid = (ulong)(*pid_addr);
        BCOPY(comm_addr, &tc->comm[0], 16);
        tc->comm[16] = NULLCHAR;
        tc->processor = *processor_addr;
        tc->ptask = *parent_addr;
        tc->mm_struct = *mm_addr;
        tc->task = task;
        tc->tc_next = NULL;

        if (do_verify && !verify_task(tc, do_verify)) {
		error(INFO, "invalid task address: %lx\n", tc->task);
                BZERO(tc, sizeof(struct task_context));
                return NULL;
        }

        if (has_cpu && (tt->flags & POPULATE_PANIC))
                tt->panic_threads[tc->processor] = tc->task;

	return tc;
}

/*
 *  The current context may have moved to a new spot in the task table
 *  or have exited since the last command.  If it still exists, reset its
 *  new position.  If it doesn't exist, set the context back to the initial
 *  crash context.  If necessary, complain and show the restored context.
 */
static void
refresh_context(ulong curtask, ulong curpid)
{
	ulong value, complain;
	struct task_context *tc;

	if (task_exists(curtask) && pid_exists(curpid)) {
                set_context(curtask, NO_PID);
        } else {
                set_context(tt->this_task, NO_PID);

                complain = TRUE;
                if (STREQ(args[0], "set") && (argcnt == 2) &&
                    IS_A_NUMBER(args[1])) {

	                switch (str_to_context(args[optind], &value, &tc))
	                {
	                case STR_PID:
	                case STR_TASK:
				complain = FALSE;
	                        break;
	                case STR_INVALID:
				complain = TRUE;
	                        break;
	                }
                }

                if (complain) {
                        error(INFO, "current context no longer exists -- "
                                    "restoring \"%s\" context:\n\n",
                        	pc->program_name);
                        show_context(CURRENT_CONTEXT());
			fprintf(fp, "\n");
                }
        }
}

/*
 *  Sort the task_context array by PID number; for PID 0, sort by processor.
 */
void
sort_context_array(void)
{
        ulong curtask;

	curtask = CURRENT_TASK();
	qsort((void *)tt->context_array, (size_t)tt->running_tasks,
        	sizeof(struct task_context), sort_by_pid);
	set_context(curtask, NO_PID);
}

static int
sort_by_pid(const void *arg1, const void *arg2)
{
	struct task_context *t1, *t2;

	t1 = (struct task_context *)arg1;
	t2 = (struct task_context *)arg2;

        if ((t1->pid == 0) && (t2->pid == 0))
                return (t1->processor < t2->processor ? -1 :
                        t1->processor == t2->processor ? 0 : 1);
        else
                return (t1->pid < t2->pid ? -1 :
                        t1->pid == t2->pid ? 0 : 1);
}


static int
sort_by_last_run(const void *arg1, const void *arg2)
{
	ulong task_last_run_stamp(ulong);
	struct task_context *t1, *t2;
	ulonglong lr1, lr2;

	t1 = (struct task_context *)arg1;
	t2 = (struct task_context *)arg2;

	lr1 = task_last_run(t1->task);
	lr2 = task_last_run(t2->task);
	
        return (lr2 < lr1 ? -1 :
        	lr2 == lr1 ? 0 : 1);
}

static void
sort_context_array_by_last_run(void)
{
        ulong curtask;

	curtask = CURRENT_TASK();
	qsort((void *)tt->context_array, (size_t)tt->running_tasks,
        	sizeof(struct task_context), sort_by_last_run);
	set_context(curtask, NO_PID);
}

/*
 *  Keep a stash of the last task_struct accessed.  Chances are it will
 *  be hit several times before the next task is accessed.
 */

char *
fill_task_struct(ulong task)
{
	if (!IS_LAST_TASK_READ(task)) { 
        	if (!readmem(task, KVADDR, tt->task_struct, 
	     		SIZE(task_struct), "fill_task_struct", 
	     		ACTIVE() ? (RETURN_ON_ERROR|QUIET) : RETURN_ON_ERROR)) {
			tt->last_task_read = 0;
			return NULL;
		}
	}

	tt->last_task_read = task;
	return(tt->task_struct);
}

/*
 *  Keep a stash of the last thread_info struct accessed.  Chances are it will
 *  be hit several times before the next task is accessed.
 */

char *
fill_thread_info(ulong thread_info)
{
        if (!IS_LAST_THREAD_INFO_READ(thread_info)) {
                if (!readmem(thread_info, KVADDR, tt->thread_info,
                        SIZE(thread_info), "fill_thread_info",
                        ACTIVE() ? (RETURN_ON_ERROR|QUIET) : RETURN_ON_ERROR)) {
                        tt->last_thread_info_read = 0;
                        return NULL;
                }
        }

        tt->last_thread_info_read = thread_info;
        return(tt->thread_info);
}
/*
 *  Used by back_trace(), copy the complete kernel stack into a local buffer
 *  and fill the task_struct buffer, dealing with possible future separation
 *  of task_struct and stack and/or cache coloring of stack top.
 */
void
fill_stackbuf(struct bt_info *bt)
{
	if (!bt->stackbuf) {
		bt->stackbuf = GETBUF(bt->stacktop - bt->stackbase);

        	if (!readmem(bt->stackbase, KVADDR, bt->stackbuf, 
	    	    bt->stacktop - bt->stackbase, 
		    "stack contents", RETURN_ON_ERROR))
                	error(FATAL, "read of stack at %lx failed\n", 
				bt->stackbase);
	} 

	if (!IS_LAST_TASK_READ(bt->task)) {
		if (bt->stackbase == bt->task) {
			BCOPY(bt->stackbuf, tt->task_struct, SIZE(task_struct));
			tt->last_task_read = bt->task;
		} else
			fill_task_struct(bt->task);
	}
}

/*
 *  Keeping the task_struct info intact, alter the contents of the already
 *  allocated local copy of a kernel stack, for things like IRQ stacks or
 *  non-standard eframe searches.  The caller must change the stackbase
 *  and stacktop values.
 */
void
alter_stackbuf(struct bt_info *bt)
{
	if (!readmem(bt->stackbase, KVADDR, bt->stackbuf,
       	    bt->stacktop - bt->stackbase, "stack contents", RETURN_ON_ERROR))
        	error(FATAL, "read of stack at %lx failed\n", bt->stackbase);
}

/*
 *  In the same vein as fill_task_struct(), keep a stash of the mm_struct
 *  of a task.
 */

char *fill_mm_struct(ulong mm)
{
	if (!IS_LAST_MM_READ(mm)) {
        	if (!readmem(mm, KVADDR, tt->mm_struct,
             		SIZE(mm_struct), "fill_mm_struct",
             		ACTIVE() ? (RETURN_ON_ERROR|QUIET) : RETURN_ON_ERROR)) {
                	tt->last_mm_read = 0;
                	return NULL;
        	}
	}

        tt->last_mm_read = mm;
        return(tt->mm_struct);
}

/*
 *  If active, clear out references to the last task and mm_struct read.
 */
void
clear_task_cache(void)
{
        if (ACTIVE())
                tt->last_task_read = tt->last_mm_read = 0;
}

/*
 *  Shorthand command to dump the current context's task_struct, or if
 *  pid or task arguments are entered, the task_structs of the targets.
 *  References to structure members can be given to pare down the output,
 *  which are put in a comma-separated list.
 */
void
cmd_task(void)
{
	int c, tcnt, bogus;
	ulong value;
	struct reference *ref;
	struct task_context *tc;
	ulong *tasklist;
	char *memberlist;

	tasklist = (ulong *)GETBUF((MAXARGS+NR_CPUS)*sizeof(ulong));
	ref = (struct reference *)GETBUF(sizeof(struct reference));
	memberlist = GETBUF(BUFSIZE);
	ref->str = memberlist;

        while ((c = getopt(argcnt, args, "R:")) != EOF) {
                switch(c)
		{
		case 'R':
			if (strlen(ref->str))
				strcat(ref->str, ",");
			strcat(ref->str, optarg);
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	tcnt = bogus = 0;

        while (args[optind]) {
		if (IS_A_NUMBER(args[optind])) {
	                switch (str_to_context(args[optind], &value, &tc))
	                {
	                case STR_PID:
                                for (tc = pid_to_context(value); tc;
                                     tc = tc->tc_next)
                                        tasklist[tcnt++] = tc->task;
	                        break;
	
	                case STR_TASK:
				tasklist[tcnt++] = value;	
	                        break;
	
	                case STR_INVALID:
				bogus++;
	                        error(INFO, "invalid task or pid value: %s\n\n",
	                                args[optind]);
	                        break;
	                }
		} else if (strstr(args[optind], ",") ||
			MEMBER_EXISTS("task_struct", args[optind])) {
			if (strlen(ref->str))
				strcat(ref->str, ",");
			strcat(ref->str, args[optind]);
		} else
                        error(INFO, 
			    "invalid task, pid, or task_struct member: %s\n\n",
                                args[optind]);
                optind++;
        }

	if (!tcnt && !bogus)
		tasklist[tcnt++] = CURRENT_TASK();

	for (c = 0; c < tcnt; c++) 
		do_task(tasklist[c], 0, strlen(ref->str) ? ref : NULL);

}

/*
 *  Do the work for the task command.
 */
void
do_task(ulong task, ulong flags, struct reference *ref)
{
	struct task_context *tc;

	tc = task_to_context(task);

	if (ref) 
		task_struct_member(tc, flags, ref);
	else { 
		if (!(flags & FOREACH_TASK))
			print_task_header(fp, tc, 0);
		dump_struct("task_struct", task, 0);
	}

	fprintf(fp, "\n");
}

/*
 *  Search the task_struct for the referenced field.
 */
static void
task_struct_member(struct task_context *tc, ulong flags, struct reference *ref)
{
	int i;
	int argcnt;
	char *arglist[MAXARGS];
	char *refcopy;
	char buf[BUFSIZE];
	char lookfor1[BUFSIZE];
	char lookfor2[BUFSIZE];
	char lookfor3[BUFSIZE];
	int header_printed;

	header_printed = FALSE;

	if ((count_chars(ref->str, ',')+1) > MAXARGS) {
		error(INFO, 
		    	"too many -R arguments in comma-separated list!\n");
		return;
	}

	refcopy = GETBUF(strlen(ref->str)+1);
	strcpy(refcopy, ref->str);
	replace_string(refcopy, ",", ' ');

	argcnt = parse_line(refcopy, arglist);
	for (i = 0; i < argcnt; i++)
		if (!MEMBER_EXISTS("task_struct", arglist[i]))
			error(INFO, "%s: not a task_struct member\n", 
				arglist[i]);

        open_tmpfile();
        dump_struct("task_struct", tc->task, 0);
        rewind(pc->tmpfile);

	BZERO(lookfor1, BUFSIZE);
	BZERO(lookfor2, BUFSIZE);
	BZERO(lookfor3, BUFSIZE);

        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
		if (strlen(lookfor2)) {
			if (!header_printed) {
				print_task_header(pc->saved_fp, tc, 0);
				header_printed = TRUE;
			}
			fprintf(pc->saved_fp, buf);
			if (STRNEQ(buf, lookfor2))
				BZERO(lookfor2, BUFSIZE);
			continue;
		}

		if (strlen(lookfor3)) {
                        if (!header_printed) {
                                print_task_header(pc->saved_fp, tc, 0);
                                header_printed = TRUE;
                        }
			fprintf(pc->saved_fp, buf);
			if (strstr(buf, lookfor3))
				BZERO(lookfor3, BUFSIZE);
			continue;
		}

		for (i = 0; i < argcnt; i++) {
			BZERO(lookfor1, BUFSIZE);
			BZERO(lookfor2, BUFSIZE);
			BZERO(lookfor3, BUFSIZE);
			sprintf(lookfor1, "  %s = ", arglist[i]);
			if (STRNEQ(buf, lookfor1)) {
                        	if (!header_printed) {
                                	print_task_header(pc->saved_fp, tc, 0);
                                	header_printed = TRUE;
                        	}
				fprintf(pc->saved_fp, buf); 
                        	if (strstr(buf, "{{\n")) 
                                	sprintf(lookfor2, "    }},");
                        	else if (strstr(buf, "{\n")) 
                                	sprintf(lookfor2, "  },");
				else if (strstr(buf, "{"))
                                	sprintf(lookfor3, "},");
				break;
			}
		}
	}
	close_tmpfile();
}

/*
 *  Display ps-like data for all tasks, or as specified by pid, task, or
 *  command-name arguments.
 */
void
cmd_ps(void)
{
	int c, ac;
	ulong flag;
	ulong value;
	struct psinfo psinfo;
	struct task_context *tc;
	char *p;

	BZERO(&psinfo, sizeof(struct psinfo));
	flag = 0;

        while ((c = getopt(argcnt, args, "gstcpkula")) != EOF) {
                switch(c)
		{
		case 'k':
			flag |= PS_KERNEL;
			flag &= ~PS_USER;
			break;

		case 'u':
			flag |= PS_USER;
			flag &= ~PS_KERNEL;
			break;

		/*
		 *  The a, t, c, p, g and l flags are all mutually-exclusive.
		 */
		case 'g':
			flag &= ~(PS_EXCLUSIVE);
			flag |= PS_TGID_LIST;
			break;

		case 'a':
			flag &= ~(PS_EXCLUSIVE);
			flag |= PS_ARGV_ENVP;
			break;

		case 't':
			flag &= ~(PS_EXCLUSIVE);
			flag |= PS_TIMES;
			break;

		case 'c': 
			flag &= ~(PS_EXCLUSIVE);
			flag |= PS_CHILD_LIST;
			break;

		case 'p':
			flag &= ~(PS_EXCLUSIVE);
			flag |= PS_PPID_LIST;
			break;
			
		case 'l':
			if (INVALID_MEMBER(task_struct_last_run) &&
			    INVALID_MEMBER(task_struct_timestamp)) {
				error(INFO, 
"neither task_struct.last_run nor task_struct.timestamp exist in this kernel\n");
				argerrs++;
				break;
			}
			flag &= ~(PS_EXCLUSIVE);
			flag |= PS_LAST_RUN;
			break;

		case 's':
			flag |= PS_KSTACKP;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (!args[optind]) {
		show_ps(PS_SHOW_ALL|flag, NULL);
		return;
	}

	ac = 0;
	while (args[optind]) {
		if (IS_A_NUMBER(args[optind])) {
	                switch (str_to_context(args[optind], &value, &tc))
	                {
	                case STR_PID:
                                psinfo.pid[ac] = value;
                                psinfo.task[ac] = NO_TASK;
                                psinfo.type[ac] = PS_BY_PID;
                                flag |= PS_BY_PID;
	                        break;
	
	                case STR_TASK:
                                psinfo.task[ac] = value;
                                psinfo.pid[ac] = NO_PID;
                                psinfo.type[ac] = PS_BY_TASK;
                                flag |= PS_BY_TASK;
	                        break;
	
	                case STR_INVALID:
	                        error(INFO, "invalid task or pid value: %s\n\n",
	                                args[optind]);
	                        break;
	                }
			ac++;
		}
		else {
			psinfo.pid[ac] = NO_PID;
			psinfo.task[ac] = NO_TASK;
			p = args[optind][0] == '\\' ? 
				&args[optind][1] : args[optind];
			strncpy(psinfo.comm[ac], p, 16); 
			psinfo.type[ac] = PS_BY_CMD;
			flag |= PS_BY_CMD;
			ac++;
		}
		optind++;
	}

	psinfo.argc = ac;
	show_ps(flag, &psinfo);
}

/*
 *  Do the work requested by cmd_ps().
 */

#define SHOW_PS_DATA()                                                \
        if ((flag & PS_USER) && is_kernel_thread(tc->task))           \
                continue;                                             \
        if ((flag & PS_KERNEL) && !is_kernel_thread(tc->task))        \
                continue;                                             \
        if (flag & PS_PPID_LIST) {                                    \
                parent_list(tc->task);                                \
                fprintf(fp, "\n");                                    \
                continue;                                             \
        }                                                             \
        if (flag & PS_CHILD_LIST) {                                   \
                child_list(tc->task);                                 \
                fprintf(fp, "\n");                                    \
                continue;                                             \
        }                                                             \
        if (flag & PS_LAST_RUN) {                                     \
                show_last_run(tc);                                    \
                continue;                                             \
        }                                                             \
        if (flag & PS_ARGV_ENVP) {                                    \
                show_task_args(tc);                                   \
                continue;                                             \
        }                                                             \
        if (flag & PS_TGID_LIST) {                                    \
                show_tgid_list(tc->task);                             \
                continue;                                             \
        }                                                             \
        get_task_mem_usage(tc->task, tm);                             \
        fprintf(fp, "%s", is_task_active(tc->task) ? "> " : "  ");    \
        fprintf(fp, "%5ld  %5ld  %2s  %s %3s",                        \
                tc->pid, task_to_pid(tc->ptask),                      \
                task_cpu(tc->processor, buf2, !VERBOSE),              \
                task_pointer_string(tc, flag & PS_KSTACKP, buf3),     \
                task_state_string(tc->task, buf1, !VERBOSE));         \
        pad_line(fp, strlen(buf1) > 3 ? 1 : 2, ' ');                  \
        sprintf(buf1, "%.1f", tm->pct_physmem);                       \
        if (strlen(buf1) == 3)                                        \
        	mkstring(buf1, 4, CENTER|RJUST, NULL);                \
        fprintf(fp, "%s ", buf1);                                     \
        fprintf(fp, "%7ld ", (tm->total_vm * PAGESIZE())/1024);       \
        fprintf(fp, "%6ld  ", (tm->rss * PAGESIZE())/1024);           \
        if (is_kernel_thread(tc->task))                               \
                fprintf(fp, "[%s]\n", tc->comm);                      \
        else                                                          \
                fprintf(fp, "%s\n", tc->comm);    

static void
show_ps(ulong flag, struct psinfo *psi)
{
	int i, ac;
        struct task_context *tc;
	struct task_mem_usage task_mem_usage, *tm;
	int print;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];

	if (!(flag & PS_EXCLUSIVE)) 
		fprintf(fp, 
		    "   PID    PPID  CPU %s  ST  %%MEM     VSZ    RSS  COMM\n",
			flag & PS_KSTACKP ?
			mkstring(buf1, VADDR_PRLEN, CENTER|RJUST, "KSTACKP") :
			mkstring(buf1, VADDR_PRLEN, CENTER, "TASK"));

	if (flag & PS_LAST_RUN)
		sort_context_array_by_last_run();

	if (flag & PS_SHOW_ALL) {
		tm = &task_mem_usage;

		if (flag & PS_TIMES) {
			show_task_times(NULL, flag);
			return;
		}

		tc = FIRST_CONTEXT();
        	for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
			SHOW_PS_DATA();
		}
		
		return;
	}

	pc->curcmd_flags |= TASK_SPECIFIED;

	for (ac = 0; ac < psi->argc; ac++) {
		tm = &task_mem_usage;
		tc = FIRST_CONTEXT();

        	for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
			print = FALSE;

			switch(psi->type[ac])
			{
			case PS_BY_PID:
				if (tc->pid == psi->pid[ac])
					print = TRUE;
				break;

			case PS_BY_TASK:
				if ((tc->task == psi->task[ac]))
					print = TRUE;
				break;

			case PS_BY_CMD:
				if (STREQ(tc->comm, psi->comm[ac])) {
					if (flag & PS_TGID_LIST) {
						if (tc->pid == task_tgid(tc->task))
							print = TRUE;
						else
							print = FALSE;
					} else
						print = TRUE;
				}
				break;
			}

			if (print) {
				if (flag & PS_TIMES) 
					show_task_times(tc, flag);
				else if (flag & PS_LAST_RUN)
					show_last_run(tc);
				else {
					SHOW_PS_DATA();
				}
			}
		}
	}
}

/*
 *  Display the task preceded by the last_run stamp.
 */
static void
show_last_run(struct task_context *tc)
{
	int i, c;
	struct task_context *tcp;
	char format[10];
	char buf[BUFSIZE];

       	tcp = FIRST_CONTEXT();
	sprintf(buf, pc->output_radix == 10 ? "%lld" : "%llx", 
		task_last_run(tcp->task));
	c = strlen(buf);
	sprintf(format, "[%c%dll%c]  ", '%', c, 
		pc->output_radix == 10 ? 'u' : 'x');

	if (tc) {
		fprintf(fp, format, task_last_run(tc->task));
		print_task_header(fp, tc, FALSE);
	} else {
        	tcp = FIRST_CONTEXT();
        	for (i = 0; i < RUNNING_TASKS(); i++, tcp++) {
			fprintf(fp, format, task_last_run(tcp->task));
			print_task_header(fp, tcp, FALSE);
		}
	}
}

/*
 *  Show the argv and envp strings pointed to by mm_struct->arg_start 
 *  and mm_struct->env_start.  The user addresses need to broken up
 *  into physical on a page-per-page basis because we typically are
 *  not going to be working in the context of the target task. 
 */
static void
show_task_args(struct task_context *tc)
{
	ulong arg_start, arg_end, env_start, env_end;
	char *buf, *bufptr, *p1;
	char *as, *ae, *es, *ee;
	physaddr_t paddr;
	ulong uvaddr, size, cnt;
	int c, d;

	print_task_header(fp, tc, 0);

        if (!tc || !tc->mm_struct) {     /* probably a kernel thread */
               	error(INFO, "no user stack\n\n");
                return;
	}

        if (!task_mm(tc->task, TRUE))
                return;

	if (INVALID_MEMBER(mm_struct_arg_start)) {
		MEMBER_OFFSET_INIT(mm_struct_arg_start, "mm_struct", "arg_start");
		MEMBER_OFFSET_INIT(mm_struct_arg_end, "mm_struct", "arg_end");
		MEMBER_OFFSET_INIT(mm_struct_env_start, "mm_struct", "env_start");
		MEMBER_OFFSET_INIT(mm_struct_env_end, "mm_struct", "env_end");
	}
	
	arg_start = ULONG(tt->mm_struct + OFFSET(mm_struct_arg_start));
	arg_end = ULONG(tt->mm_struct + OFFSET(mm_struct_arg_end));
	env_start = ULONG(tt->mm_struct + OFFSET(mm_struct_env_start));
	env_end = ULONG(tt->mm_struct + OFFSET(mm_struct_env_end));

	if (CRASHDEBUG(1)) {
		fprintf(fp, "arg_start: %lx arg_end: %lx (%ld)\n", 
			arg_start, arg_end, arg_end - arg_start);
		fprintf(fp, "env_start: %lx env_end: %lx (%ld)\n", 
			env_start, env_end, env_end - env_start);
	}

	buf = GETBUF(env_end - arg_start + 1);

	uvaddr = arg_start;
	size = env_end - arg_start;
	bufptr = buf;

	while (size > 0) {
        	if (!uvtop(tc, uvaddr, &paddr, 0)) {
                	error(INFO, "cannot access user stack address: %lx\n\n",
                        	uvaddr);
			goto bailout;
        	}

		cnt = PAGESIZE() - PAGEOFFSET(uvaddr);

		if (cnt > size)
			cnt = size;

        	if (!readmem(paddr, PHYSADDR, bufptr, cnt,
                    "user stack contents", RETURN_ON_ERROR|QUIET)) {
                	error(INFO, "cannot access user stack address: %lx\n\n",
                        	uvaddr);
			goto bailout;
        	}
		
		uvaddr += cnt;
                bufptr += cnt;
                size -= cnt;
	}

	as = buf;
	ae = &buf[arg_end - arg_start];
	es = &buf[env_start - arg_start];
	ee = &buf[env_end - arg_start];

	fprintf(fp, "ARG: ");
	for (p1 = as, c = 0; p1 < ae; p1++) {
		if (*p1 == NULLCHAR) {
			if (c)
				fprintf(fp, " ");
			c = 0;
		} else {
			fprintf(fp, "%c", *p1);
			c++;
		}
	}

	fprintf(fp, "\nENV: ");
	for (p1 = es, c = d = 0; p1 < ee; p1++) {
		if (*p1 == NULLCHAR) {
			if (c)
				fprintf(fp, "\n");
			c = 0;
		} else {
			fprintf(fp, "%s%c", !c && (p1 != es) ? "     " : "", *p1);
			c++, d++;
		}
	}
	fprintf(fp, "\n%s", d ? "" : "\n");

bailout:
	FREEBUF(buf);
}

/*
 *  Put either the task_struct address or kernel stack pointer into a string.
 *  If the kernel stack pointer is requested, piggy-back on top of the
 *  back trace code to avoid having to deal with machine dependencies,
 *  live active tasks, and dumpfile panic tasks.
 */
static char *
task_pointer_string(struct task_context *tc, ulong do_kstackp, char *buf)
{
	struct bt_info bt_info, *bt;
	char buf1[BUFSIZE];

	if (do_kstackp) {
		bt = &bt_info;
               	BZERO(bt, sizeof(struct bt_info));;

		if (is_task_active(tc->task)) {
			bt->stkptr = 0;
		} else if (VALID_MEMBER(task_struct_thread_esp)) {
        		readmem(tc->task + OFFSET(task_struct_thread_esp), 
				KVADDR, &bt->stkptr, sizeof(void *),
                		"thread_struct esp", FAULT_ON_ERROR);
		} else if (VALID_MEMBER(task_struct_thread_ksp)) {
        		readmem(tc->task + OFFSET(task_struct_thread_ksp), 
				KVADDR, &bt->stkptr, sizeof(void *),
                		"thread_struct ksp", FAULT_ON_ERROR);
		} else {
               		bt->task = tc->task;
               		bt->tc = tc;
               		bt->stackbase = GET_STACKBASE(tc->task);
               		bt->stacktop = GET_STACKTOP(tc->task);
			bt->flags |= BT_KSTACKP;
			back_trace(bt);
		}

		if (bt->stkptr)
			sprintf(buf, mkstring(buf1, VADDR_PRLEN, 
				CENTER|RJUST|LONG_HEX,
                        	MKSTR(bt->stkptr)));
		else
			sprintf(buf, "%s",
			    mkstring(buf1, VADDR_PRLEN, CENTER|RJUST, "--"));
	} else 
		sprintf(buf, mkstring(buf1, VADDR_PRLEN, 
			CENTER|RJUST|LONG_HEX, 
			MKSTR(tc->task)));

	return buf;
}


/*
 *  Dump the task list ordered by start_time.
 */
struct kernel_timeval {
	unsigned int tv_sec;
    	unsigned int tv_usec;
};

struct task_start_time {
	struct task_context *tc;
        ulonglong start_time;
	ulong tms_utime;
	ulong tms_stime;
	struct timeval utime;
	struct timeval stime;
	struct kernel_timeval kutime;
	struct kernel_timeval kstime;
};

static void
show_task_times(struct task_context *tcp, ulong flags)
{
	int i, tasks, use_kernel_timeval;
	struct task_context *tc;
	struct task_start_time *task_start_times, *tsp;
	ulong jiffies;
	ulonglong jiffies_64;
	char buf1[BUFSIZE];

	task_start_times = (struct task_start_time *)
		GETBUF(RUNNING_TASKS() * sizeof(struct task_start_time));
 
	use_kernel_timeval = STRUCT_EXISTS("kernel_timeval");
        get_symbol_data("jiffies", sizeof(long), &jiffies);
	if (symbol_exists("jiffies_64"))
		get_uptime(NULL, &jiffies_64);
	tsp = task_start_times;
	tc = tcp ? tcp : FIRST_CONTEXT();

        for (i = tasks = 0; i < RUNNING_TASKS(); i++, tc++) {

                if ((flags & PS_USER) && is_kernel_thread(tc->task))
                        continue;
                if ((flags & PS_KERNEL) && !is_kernel_thread(tc->task))
                        continue;

		fill_task_struct(tc->task);
        	if (!tt->last_task_read) {
			if (tcp)
				return;
			continue;
		}

 		tsp->tc = tc;

		if (BITS32() && (SIZE(task_struct_start_time) == 8)) {
			if (start_time_timespec())
				tsp->start_time = 
					ULONG(tt->task_struct +
					OFFSET(task_struct_start_time));
			else
				tsp->start_time = 
					ULONGLONG(tt->task_struct +
					OFFSET(task_struct_start_time));
		} else {
			start_time_timespec();
			tsp->start_time = ULONG(tt->task_struct +
				OFFSET(task_struct_start_time));
		}

		if (VALID_MEMBER(task_struct_times)) {
			tsp->tms_utime = ULONG(tt->task_struct +
                        	OFFSET(task_struct_times) +
				OFFSET(tms_tms_utime));
                	tsp->tms_stime = ULONG(tt->task_struct +
                        	OFFSET(task_struct_times) +
                        	OFFSET(tms_tms_stime));
		} else if (VALID_MEMBER(task_struct_utime)) {
			if (use_kernel_timeval) {
                                BCOPY(tt->task_struct +
                                        OFFSET(task_struct_utime), &tsp->kutime,
					sizeof(struct kernel_timeval));
                                BCOPY(tt->task_struct +
                                        OFFSET(task_struct_stime), &tsp->kstime,
					sizeof(struct kernel_timeval));
			} else if (VALID_STRUCT(cputime_t)) {
				/* since linux 2.6.11 */
				if (SIZE(cputime_t) == 8) {
					uint64_t utime_64, stime_64;
					BCOPY(tt->task_struct + 
						OFFSET(task_struct_utime), 
						&utime_64, 8);
					BCOPY(tt->task_struct + 
						OFFSET(task_struct_stime), 
						&stime_64, 8);
					/* convert from micro-sec. to sec. */
					tsp->utime.tv_sec = utime_64 / 1000000;
					tsp->stime.tv_sec = stime_64 / 1000000;
				} else {
					uint32_t utime_32, stime_32;
					BCOPY(tt->task_struct + 
						OFFSET(task_struct_utime), 
						&utime_32, 4);
					BCOPY(tt->task_struct + 
						OFFSET(task_struct_stime), 
						&stime_32, 4);
					tsp->utime.tv_sec = utime_32;
					tsp->stime.tv_sec = stime_32;
				}
			} else {
				BCOPY(tt->task_struct + 
					OFFSET(task_struct_utime), 
					&tsp->utime, sizeof(struct timeval));
				BCOPY(tt->task_struct + 
					OFFSET(task_struct_stime), 
					&tsp->stime, sizeof(struct timeval));
			}
		}

		tasks++;
		tsp++;

		if (tcp)
			break;
	}

	qsort((void *)task_start_times, (size_t)tasks, 
		sizeof(struct task_start_time), compare_start_time);

        for (i = 0, tsp = task_start_times; i < tasks; i++, tsp++) {
		print_task_header(fp, tsp->tc, 0);
		fprintf(fp, "    RUN TIME: %s\n", symbol_exists("jiffies_64") ? 
			convert_time(convert_start_time(tsp->start_time, jiffies_64), buf1) :
			convert_time(jiffies - tsp->start_time, buf1));
		fprintf(fp, "  START TIME: %llu\n", tsp->start_time); 
		if (VALID_MEMBER(task_struct_times)) {
			fprintf(fp, "   USER TIME: %ld\n", tsp->tms_utime);
			fprintf(fp, " SYSTEM TIME: %ld\n\n", tsp->tms_stime);
		} else if (VALID_MEMBER(task_struct_utime)) {
			if (use_kernel_timeval) {
				fprintf(fp, "   USER TIME: %d\n", 
					tsp->kutime.tv_sec);
				fprintf(fp, " SYSTEM TIME: %d\n\n", 
					tsp->kstime.tv_sec);
			} else {
				fprintf(fp, "   USER TIME: %ld\n", 
					tsp->utime.tv_sec);
				fprintf(fp, " SYSTEM TIME: %ld\n\n", 
					tsp->stime.tv_sec);
			}
		}
	}
	FREEBUF(task_start_times);
}

static int
start_time_timespec(void)
{
        char buf[BUFSIZE], *p1;

	switch(tt->flags & (TIMESPEC | NO_TIMESPEC))
	{
	case TIMESPEC:
		return TRUE;
	case NO_TIMESPEC:
		return FALSE;
	default:
		break;
	}

	tt->flags |= NO_TIMESPEC;

        open_tmpfile();
        sprintf(buf, "ptype struct task_struct");
        if (!gdb_pass_through(buf, NULL, GNU_RETURN_ON_ERROR)) {
                close_tmpfile();
                return FALSE;
        }

        rewind(pc->tmpfile);
        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
                p1 = buf;
                if (strstr(buf, "start_time;")) {
			if (strstr(buf, "struct timespec")) {
				tt->flags &= ~NO_TIMESPEC;
				tt->flags |= TIMESPEC;
			}
		}
        }

        close_tmpfile();

        return (tt->flags & TIMESPEC ? TRUE : FALSE);
}

static ulonglong
convert_start_time(ulonglong start_time, ulonglong current)
{
	ulong tmp1, tmp2;
	ulonglong wrapped;

        switch(tt->flags & (TIMESPEC | NO_TIMESPEC))
        {
        case TIMESPEC:
		if ((start_time * (ulonglong)machdep->hz) > current)
			return 0;
		else
                	return current - (start_time * (ulonglong)machdep->hz); 

        case NO_TIMESPEC:
                if (THIS_KERNEL_VERSION >= LINUX(2,6,0)) {
                        wrapped = (start_time & 0xffffffff00000000ULL);
                        if (wrapped) {
                                wrapped -= 0x100000000ULL;
                                start_time &= 0x00000000ffffffffULL;
                                start_time |= wrapped;
                                start_time += (ulonglong)(300*machdep->hz);
                        } else {
                                tmp1 = (ulong)(uint)(-300*machdep->hz);
                                tmp2 = (ulong)start_time;
                                start_time = (ulonglong)(tmp2 - tmp1);
                        }
                }
		break;

        default:
                break;
        }

	return start_time;
}

/*
 *  The comparison function must return an integer less  than,
 *  equal  to,  or  greater than zero if the first argument is
 *  considered to be respectively  less  than,  equal  to,  or
 *  greater than the second.  If two members compare as equal,
 *  their order in the sorted array is undefined.
 */

static int
compare_start_time(const void *v1, const void *v2)
{
        struct task_start_time *t1, *t2;

        t1 = (struct task_start_time *)v1;
        t2 = (struct task_start_time *)v2;

	return (t1->start_time < t2->start_time ? -1 :
		t1->start_time == t2->start_time ? 0 : 1);
}

/*
 *  Dump the parental hierarchy of a task.
 */
static void
parent_list(ulong task)
{
	int i, j;
	int cnt, errflag;
        struct list_data list_data, *ld;
	ulong *tlist;
        struct task_context *tc;
	char buf[BUFSIZE];

	ld = &list_data;
	BZERO(ld, sizeof(struct list_data));
        ld->start = task;
	if (VALID_MEMBER(task_struct_p_pptr))
        	ld->member_offset = OFFSET(task_struct_p_pptr);
	else
		ld->member_offset = OFFSET(task_struct_parent);
	ld->flags |= VERBOSE;

	open_tmpfile();
	cnt = do_list(ld);
	tlist = (ulong *)GETBUF(cnt * sizeof(ulong));
 	rewind(pc->tmpfile);

        for (i = errflag = 0; fgets(buf, BUFSIZE, pc->tmpfile); i++) {
		if (i == cnt) {
                	error(INFO, "task list count mismatch?\n");
			errflag++;
		}
		if (sscanf(buf, "%lx", &tlist[i]) != 1) { 
			error(INFO, "task list parse error\n");
			errflag++;
		}
        }
	close_tmpfile();

	if (!errflag) {
		for (i = cnt-1, j = 0; i >= 0; i--, j++) {
			INDENT(j);
			tc = task_to_context(tlist[i]);
			if (tc)
				print_task_header(fp, tc, 0);
		}
	}
	
	FREEBUF((char *)tlist);
}

/*
 *  Dump the children of a task.
 */
static void
child_list(ulong task)
{
        int i;
	int cnt;
        struct task_context *tc;

	tc = task_to_context(task);
	print_task_header(fp, tc, 0);

        tc = FIRST_CONTEXT();
        for (i = cnt = 0; i < RUNNING_TASKS(); i++, tc++) {
                if (tc->ptask == task) {
			INDENT(2);
			print_task_header(fp, tc, 0);
			cnt++;
		}
	}

	if (!cnt)
		fprintf(fp, "  (no children)\n");
}

/*
 *  Dump the children of a task.
 */
static void
show_tgid_list(ulong task)
{
        int i;
        int cnt;
        struct task_context *tc;
	ulong tgid;

        tc = task_to_context(task);
	tgid = task_tgid(task);

	if (tc->pid != tgid) {
		if (pc->curcmd_flags & TASK_SPECIFIED) {
			if (!(tc = tgid_to_context(tgid)))
				return;
			task = tc->task;
		} else
			return;
	}

	if ((tc->pid == 0) && (pc->curcmd_flags & IDLE_TASK_SHOWN))
		return;

       	print_task_header(fp, tc, 0);

        tc = FIRST_CONTEXT();
        for (i = cnt = 0; i < RUNNING_TASKS(); i++, tc++) {
		if (tc->task == task)
			continue;

		if (task_tgid(tc->task)	== tgid) {
                        INDENT(2);
                        print_task_header(fp, tc, 0);
                        cnt++;
			if (tc->pid == 0)
				pc->curcmd_flags |= IDLE_TASK_SHOWN;
                }
        }

        if (!cnt)
                fprintf(fp, "  (no threads)\n");

	fprintf(fp, "\n");
}

/*
 * Return the first task found that belongs to a pid. 
 */
ulong
pid_to_task(ulong pid)
{
	int i;
	struct task_context *tc;

	tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++, tc++) 
        	if (tc->pid == pid)
			return(tc->task);

	return((ulong)NULL);
}


/*
 *  Return the pid of a task.
 */
ulong
task_to_pid(ulong task)
{
        int i;
        struct task_context *tc;

        
        tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++, tc++) 
                if (tc->task == task)
                        return(tc->pid);
        
        return(NO_PID);
}

/*
 *  Verify whether a task exists.
 */
int
task_exists(ulong task)
{
        int i;
        struct task_context *tc;

        tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++, tc++) 
                if (tc->task == task)
                        return TRUE;
        
        return FALSE;
}

/*
 *  Return the task_context structure of a task.
 */
struct task_context *
task_to_context(ulong task)
{
        int i;
        struct task_context *tc;

        tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++, tc++) 
                if (tc->task == task)
                        return tc; 
        
        return NULL;
}

/*
 *  Return a tgid's parent task_context structure.
 */
struct task_context *
tgid_to_context(ulong parent_tgid)
{
        int i;
        struct task_context *tc;
	ulong tgid;

        tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
		tgid = task_tgid(tc->task);
		if ((tgid == parent_tgid) && (tgid == tc->pid))
                        return tc;
	}

        return NULL;
}


/*
 *  Return the task_context structure of the first task found with a pid,
 *  while linking all tasks that have that pid. 
 */
struct task_context *
pid_to_context(ulong pid)
{
        int i;
        struct task_context *tc, *firsttc, *lasttc;

        tc = FIRST_CONTEXT();
        firsttc = lasttc = NULL;

        for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
                if (tc->pid == pid) {
			if (!firsttc)
                        	firsttc = tc;
                        if (lasttc)
                                lasttc->tc_next = tc;
                        tc->tc_next = NULL;
                        lasttc = tc;
		}
	}

        return firsttc;
}


/*
 *  Verify whether a pid exists, and if found, linking all tasks having the pid.
 */
int
pid_exists(ulong pid)
{
        int i;
        struct task_context *tc, *lasttc;
	int count;

        tc = FIRST_CONTEXT();
	count = 0;
	lasttc = NULL;

        for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
                if (tc->pid == pid) {
                        count++;
			if (lasttc)
				lasttc->tc_next = tc;
			tc->tc_next = NULL;
			lasttc = tc;
		}
	}
        
        return(count);
}

/*
 *  Translate a stack pointer to a task, dealing with possible split.
 *  If that doesn't work, check the hardirq_stack and softirq_stack.
 */
ulong
stkptr_to_task(ulong sp)
{
        int i, c;
        struct task_context *tc;
	struct bt_info bt_info, *bt;

	bt = &bt_info;
        tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
        	bt->stackbase = GET_STACKBASE(tc->task);
        	bt->stacktop = GET_STACKTOP(tc->task);
		if (INSTACK(sp, bt)) 
			return tc->task;
	}

	if (!(tt->flags & IRQSTACKS))
        	return NO_TASK;

        bt = &bt_info;
        tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
		for (c = 0; c < NR_CPUS; c++) {
			if (tt->hardirq_ctx[c]) {
				bt->stackbase = tt->hardirq_ctx[c];
				bt->stacktop = bt->stackbase + 
					SIZE(irq_ctx);
                		if (INSTACK(sp, bt) && 
				    (tt->hardirq_tasks[c] == tc->task)) 
                        		return tc->task;
			}
			if (tt->softirq_ctx[c]) {
                        	bt->stackbase = tt->softirq_ctx[c];
                        	bt->stacktop = bt->stackbase + 
					SIZE(irq_ctx);
                        	if (INSTACK(sp, bt) &&
				    (tt->softirq_tasks[c] == tc->task)) 
                                	return tc->task;
			}
		}
        }

	return NO_TASK;
}

/*
 *  Translate a task pointer to its thread_info.
 */
ulong
task_to_thread_info(ulong task)
{
	int i;
        struct task_context *tc;

	if (!(tt->flags & THREAD_INFO))
		error(FATAL, 
		   "task_to_thread_info: thread_info struct does not exist!\n");

        tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
		if (tc->task == task)
			return tc->thread_info;
	}
	return(error(FATAL, "task does not exist: %lx\n", task));
}

/*
 *  Translate a task address to its stack base, dealing with potential split.
 */
ulong
task_to_stackbase(ulong task)
{
	if (tt->flags & THREAD_INFO)
		return task_to_thread_info(task);
	else
		return (task & ~(STACKSIZE()-1));
}

/*
 *  Try to translate a decimal or hexadecimal string into a task or pid,
 *  failing if no task or pid exists, or if there is ambiguity between
 *  the decimal and hexadecimal translations.  However, if the value could
 *  be a decimal PID and a hexadecimal PID of two different processes, then
 *  default to the decimal value. 
 *
 *  This was added in preparation for overlapping, zero-based, user and kernel
 *  virtual addresses on s390 and s390x, allowing for the entry of ambiguous
 *  decimal/hexadecimal task address values without the leading "0x".
 *  It should be used in lieu of "stol" when parsing for task/pid arguments.
 */
int 
str_to_context(char *string, ulong *value, struct task_context **tcp)
{
	ulong dvalue, hvalue;
	int found, type;
	char *s;
	struct task_context *tc_dp, *tc_dt, *tc_hp, *tc_ht;

	if (string == NULL) {
		error(INFO, "received NULL string\n");
		return STR_INVALID;
	}

	s = string;
        dvalue = hvalue = BADADDR;

        if (decimal(s, 0))
                dvalue = dtol(s, RETURN_ON_ERROR, NULL);

        if (hexadecimal(s, 0)) {
        	if (STRNEQ(s, "0x") || STRNEQ(s, "0X"))
                	s += 2;
		if (strlen(s) <= MAX_HEXADDR_STRLEN) 
                	hvalue = htol(s, RETURN_ON_ERROR, NULL);
	}

        found = 0;
        tc_dp = tc_dt = tc_hp = tc_ht = NULL;
	type = STR_INVALID;

	if (dvalue != BADADDR) {
		if ((tc_dp = pid_to_context(dvalue)))
			found++;
	        if ((tc_dt = task_to_context(dvalue)))
			found++;
	}
	
	if ((hvalue != BADADDR) && (dvalue != hvalue)) {
	        if ((tc_hp = pid_to_context(hvalue)))
			found++;
	        if ((tc_ht = task_to_context(hvalue)))
			found++;
	}

	switch (found) 
	{
	case 2: 
		if (tc_dp && tc_hp) {      
                	*tcp = tc_dp;      
                	*value = dvalue;   
                	type = STR_PID;
		}
		break;
		
	case 1: 
		if (tc_dp) {
			*tcp = tc_dp;
			*value = dvalue;
			type = STR_PID;
		}
	
		if (tc_dt) {
			*tcp = tc_dt;
			*value = dvalue;
			type = STR_TASK;
		}
	
		if (tc_hp) {
			*tcp = tc_hp;
			*value = hvalue;
			type = STR_PID;
		}
	
		if (tc_ht) {
			*tcp = tc_ht;
			*value = hvalue;
			type = STR_TASK;
		}
		break;
	}

	return type;
}


/*
 *  Verify whether any task is running a command.
 */
int
comm_exists(char *s)
{
        int i;
        struct task_context *tc;

        tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++, tc++) 
                if (STREQ(tc->comm, s))
                        return TRUE;
        
        return FALSE;
}

/*
 *  Set a new context.  If only a pid is passed, the first task found with
 *  that pid is selected.
 */
int
set_context(ulong task, ulong pid)
{
	int i;
	struct task_context *tc;
	int found;

	tc = FIRST_CONTEXT();

        for (i = 0, found = FALSE; i < RUNNING_TASKS(); i++, tc++) {
		if (task && (tc->task == task)) {
			found = TRUE;
			break;
		} else if (pid == tc->pid) {
			found = TRUE;
			break;
		}
        }

	if (found) {
		CURRENT_CONTEXT() = tc;
		return TRUE;
	} else {
		if (task) 
			error(INFO, "cannot set context for task: %lx\n", task);
		else 
			error(INFO, "cannot set context for pid: %d\n", pid);
		return FALSE;
	}
}

/*
 *  Check whether the panic was determined to be caused by a "sys -panic" 
 *  command.  If so, fix the task_context's pid despite what the task_struct
 *  says.
 */
#define CONTEXT_ADJUSTED      (1)
#define CONTEXT_ERRONEOUS     (2)

static int
panic_context_adjusted(struct task_context *tc)
{
        pid_t pgrp, tgid;
	char buf[BUFSIZE];

        if (!(DUMPFILE() && (tc == task_to_context(tt->panic_task)) &&
            (tc->pid == 0) && STRNEQ(tc->comm, pc->program_name) &&
            strstr(get_panicmsg(buf), "Attempted to kill the idle task")))
		return 0;

        if (INVALID_MEMBER(task_struct_pgrp) || 
	    INVALID_MEMBER(task_struct_tgid))
                return CONTEXT_ERRONEOUS;

        fill_task_struct(tc->task);

        pgrp = tt->last_task_read ?
                UINT(tt->task_struct + OFFSET(task_struct_pgrp)) : 0;
        tgid = tt->last_task_read ?
                UINT(tt->task_struct + OFFSET(task_struct_tgid)) : 0;

        if (pgrp && tgid && (pgrp == tgid) && !pid_exists((ulong)pgrp)) {
                tc->pid = (ulong)pgrp;
                return CONTEXT_ADJUSTED;
        }

        return CONTEXT_ERRONEOUS;
}

/*
 *  Display a task context.
 */

void
show_context(struct task_context *tc)
{
	char buf[BUFSIZE];
	char *p1;
	int adjusted, cnt, indent;

	adjusted = pc->flags & RUNTIME ? 0 : panic_context_adjusted(tc); 
	indent = pc->flags & RUNTIME ? 0 : 5;

	INDENT(indent);
	fprintf(fp, "    PID: %ld\n", tc->pid);
	INDENT(indent);
	fprintf(fp, "COMMAND: \"%s\"\n", tc->comm);
	INDENT(indent);
	fprintf(fp, "   TASK: %lx  ", tc->task);
	if ((cnt = TASKS_PER_PID(tc->pid)) > 1)
		fprintf(fp, "(1 of %d)  ", cnt);
	if (tt->flags & THREAD_INFO)
		fprintf(fp, "[THREAD_INFO: %lx]", tc->thread_info);
	fprintf(fp, "\n");
	INDENT(indent);
	fprintf(fp, "    CPU: %s\n", task_cpu(tc->processor, buf, VERBOSE));
	INDENT(indent);
	fprintf(fp, "  STATE: %s ", 
		task_state_string(tc->task, buf, VERBOSE));
	if (is_task_active(tc->task)) {
		if (machdep->flags & HWRESET)
			fprintf(fp, "(HARDWARE RESET)");
		else if ((pc->flags & SYSRQ) && (tc->task == tt->panic_task))
			fprintf(fp, "(SYSRQ)");
		else if (machdep->flags & INIT)
			fprintf(fp, "(INIT)");
		else if ((tc->processor >= 0) && 
		        (tc->processor < NR_CPUS) && 
			(kt->cpu_flags[tc->processor] & NMI))
			fprintf(fp, "(NMI)");
		else if ((tc->task == tt->panic_task) &&
			XENDUMP_DUMPFILE() && (kt->xen_flags & XEN_SUSPEND))
			fprintf(fp, "(SUSPEND)");
		else if (tc->task == tt->panic_task)
			fprintf(fp, "(PANIC)");
		else
			fprintf(fp, "(ACTIVE)");
	}

	if (!(pc->flags & RUNTIME) && (tt->flags & PANIC_TASK_NOT_FOUND) &&
	    !SYSRQ_TASK(tc->task)) {
		fprintf(fp, "\n"); INDENT(indent);
		if (machine_type("S390") || machine_type("S390X"))
			fprintf(fp, "   INFO: no panic task found");
		else if (tt->panic_processor >= 0)
			fprintf(fp,
			    "WARNING: reported panic task %lx not found",
				tt->panic_threads[tt->panic_processor]);
		else 
			fprintf(fp, "WARNING: panic task not found");
	}

	fprintf(fp, "\n");

	if (pc->flags & RUNTIME)
		return;

	/*
	 *  Dump any pre-first-prompt messages here.
	 */
	cnt = 0;

	if (pc->flags & NAMELIST_UNLINKED) {
		strcpy(buf, pc->namelist);
		if ((p1 = strstr(buf, "@")))
			*p1 = NULLCHAR;
		fprintf(fp, 
 "%sNOTE: To save the remote \"%s\" locally,\n      enter: \"save kernel\"\n",
			cnt++ ? "" : "\n", buf);
	}

	if (REMOTE_DUMPFILE())
		fprintf(fp, 
         "%sNOTE: To save the remote \"%s\" locally,\n      enter: \"save dumpfile\"\n",
			cnt++ ? "" : "\n", 
			basename(pc->server_memsrc));

	/*
	 *  If this panic was caused by a "sys -panic" command, issue the
	 *  proper warning message.
	 */
	switch (adjusted) 
	{
	case CONTEXT_ADJUSTED:
               	fprintf(fp,
          "%sNOTE: The \"%s\" task_struct will erroneously show a p_pid of 0\n",
                	cnt++ ? "" : "\n", tc->comm);
		break;

	case CONTEXT_ERRONEOUS:
              	fprintf(fp,
             "%sWARNING: The \"%s\" context will erroneously show a PID of 0\n",
               		cnt++ ? "" : "\n", tc->comm);
		break;
	}
}


/*
 *  Translate a task_struct state value into a long (verbose), or short string,
 *  or if requested, just pass back the state value.
 */

#define TASK_STATE_UNINITIALIZED (-1)

static long _RUNNING_ = TASK_STATE_UNINITIALIZED;
static long _INTERRUPTIBLE_ = TASK_STATE_UNINITIALIZED;
static long _UNINTERRUPTIBLE_ = TASK_STATE_UNINITIALIZED;
long _ZOMBIE_ = TASK_STATE_UNINITIALIZED;      /* also used by IS_ZOMBIE() */
static long _STOPPED_ = TASK_STATE_UNINITIALIZED;
static long _DEAD_ = TASK_STATE_UNINITIALIZED;
static long _SWAPPING_ = TASK_STATE_UNINITIALIZED;
static long _EXCLUSIVE_ = TASK_STATE_UNINITIALIZED;

/*
 *  Initialize the task state fields based upon the kernel's task_state_array
 *  string table.
 */
static void
initialize_task_state(void)
{
	ulong bitpos;
	ulong str, task_state_array;
	char buf[BUFSIZE];

	if (!symbol_exists("task_state_array") ||
	    !readmem(task_state_array = symbol_value("task_state_array"),
            KVADDR, &str, sizeof(void *),
            "task_state_array", RETURN_ON_ERROR)) {
old_defaults:
		_RUNNING_ = 0;
		_INTERRUPTIBLE_ = 1;
		_UNINTERRUPTIBLE_ = 2;
		_ZOMBIE_ = 4;
		_STOPPED_ = 8;
		_SWAPPING_ = 16;
		_EXCLUSIVE_ = 32;
		return;
	}
		
	bitpos = 0;
	while (str) {
		if (!read_string(str, buf, BUFSIZE-1))
			break;

		if (CRASHDEBUG(3)) 
			fprintf(fp, "%s[%s]\n", bitpos ? "" : "\n", buf);

		if (STRNEQ(buf, "R "))
			_RUNNING_ = bitpos;
		if (STRNEQ(buf, "S "))
			_INTERRUPTIBLE_ = bitpos;
		if (STRNEQ(buf, "D "))
			_UNINTERRUPTIBLE_ = bitpos;
		if (STRNEQ(buf, "T "))
			_STOPPED_ = bitpos;
		if (STRNEQ(buf, "Z "))
			_ZOMBIE_ = bitpos;
		if (STRNEQ(buf, "X "))
			_DEAD_ = bitpos;
		if (STRNEQ(buf, "W "))
			_SWAPPING_ = bitpos;

		if (!bitpos)
			bitpos = 1;
		else
			bitpos = bitpos << 1;

		task_state_array += sizeof(void *);
		if (!readmem(task_state_array, KVADDR, &str, sizeof(void *),
              	    "task_state_array", RETURN_ON_ERROR))
			break;
	}

	if (CRASHDEBUG(3)) {
		fprintf(fp, "RUNNING: %ld\n", _RUNNING_);
		fprintf(fp, "INTERRUPTIBLE: %ld\n", _INTERRUPTIBLE_);
		fprintf(fp, "UNINTERRUPTIBLE: %ld\n", _UNINTERRUPTIBLE_);
		fprintf(fp, "STOPPED: %ld\n", _STOPPED_);
		fprintf(fp, "ZOMBIE: %ld\n", _ZOMBIE_);
		fprintf(fp, "DEAD: %ld\n", _DEAD_);
		fprintf(fp, "SWAPPING: %ld\n", _SWAPPING_);
	}

	if ((_RUNNING_ == TASK_STATE_UNINITIALIZED) ||
	    (_INTERRUPTIBLE_ == TASK_STATE_UNINITIALIZED) ||
	    (_UNINTERRUPTIBLE_ == TASK_STATE_UNINITIALIZED) ||
	    (_ZOMBIE_ == TASK_STATE_UNINITIALIZED) ||
	    (_STOPPED_ == TASK_STATE_UNINITIALIZED)) {
		if (CRASHDEBUG(3))
			fprintf(fp, 
			    "initialize_task_state: using old defaults\n");
		goto old_defaults;
	}
}

char *
task_state_string(ulong task, char *buf, int verbose)
{
	long state;
	int exclusive;
	int valid;

	if (_RUNNING_ == TASK_STATE_UNINITIALIZED) 
		initialize_task_state();

	if (buf)
		sprintf(buf, verbose ? "(unknown)" : "??");

	state = task_state(task);

	valid = exclusive = 0;
	if (_EXCLUSIVE_ != TASK_STATE_UNINITIALIZED) {
		exclusive = state & _EXCLUSIVE_;
		state &= ~(_EXCLUSIVE_);
	}

	if (state == _RUNNING_) {
		sprintf(buf, verbose ? "TASK_RUNNING" : "RU"); valid++;
	} else if (state == _INTERRUPTIBLE_) { 
		sprintf(buf, verbose ? "TASK_INTERRUPTIBLE" : "IN"); valid++;
	} else if (state == _UNINTERRUPTIBLE_) {
		sprintf(buf, verbose ? "TASK_UNINTERRUPTIBLE" : "UN"); valid++;
	} else if (state == _ZOMBIE_) { 
		sprintf(buf, verbose ? "TASK_ZOMBIE" : "ZO"); valid++;
	} else if (state == _STOPPED_) { 
		sprintf(buf, verbose ? "TASK_STOPPED" : "ST"); valid++;
	} else if (state == _DEAD_) { 
		sprintf(buf, verbose ? "TASK_DEAD" : "DE"); valid++;
	} else if (state == _SWAPPING_) {
		sprintf(buf, verbose ? "TASK_SWAPPING" : "SW"); valid++;
	}

	if (valid && exclusive) 
		strcat(buf, verbose ? "|TASK_EXCLUSIVE" : "EX");

	return buf;
}

/*
 *  Return a task's state.
 */
ulong
task_state(ulong task)
{
        ulong state;

	fill_task_struct(task);

	state = tt->last_task_read ?
		ULONG(tt->task_struct + OFFSET(task_struct_state)) : 0;

        return state;
}

/*
 *  Return a task's flags.
 */
ulong
task_flags(ulong task)
{
	ulong flags;

	fill_task_struct(task);

	flags = tt->last_task_read ?
		 ULONG(tt->task_struct + OFFSET(task_struct_flags)) : 0;

	return flags;
}

/*
 *  Return a task's tgid.
 */
ulong
task_tgid(ulong task)
{
        uint tgid;

        fill_task_struct(task);

        tgid = tt->last_task_read ?
                 UINT(tt->task_struct + OFFSET(task_struct_tgid)) : 0;

        return (ulong)tgid;
}

ulonglong
task_last_run(ulong task)
{
        ulong last_run;
	ulonglong timestamp;

        fill_task_struct(task);

	if (VALID_MEMBER(task_struct_last_run)) {
        	last_run = tt->last_task_read ?  ULONG(tt->task_struct + 
			OFFSET(task_struct_last_run)) : 0;
		timestamp = (ulonglong)last_run;
	} else if (VALID_MEMBER(task_struct_timestamp))
        	timestamp = tt->last_task_read ?  ULONGLONG(tt->task_struct + 
			OFFSET(task_struct_timestamp)) : 0;
	
        return timestamp;
}

/*
 *  Return a task's mm_struct address.  If "fill" is set, the mm_struct
 *  cache is loaded.
 */
ulong
task_mm(ulong task, int fill)
{
	ulong mm_struct;

	fill_task_struct(task);

	if (!tt->last_task_read)
		return 0;

	mm_struct = ULONG(tt->task_struct + OFFSET(task_struct_mm));

	if (fill && mm_struct)
		fill_mm_struct(mm_struct);

	return mm_struct;
}

/*
 *  Translate a processor number into a string, taking NO_PROC_ID into account.
 */
char *
task_cpu(int processor, char *buf, int verbose)
{
	if (processor < NO_PROC_ID)
		sprintf(buf, "%d", processor);
	if (processor == NO_PROC_ID)
		sprintf(buf, verbose ? "NO_PROC_ID" : "-");

        return buf;
}

/*
 *  Check either the panic_threads[] array on a dump, or the has_cpu flag 
 *  of a task_struct on a live system.  Also account for deprecation of
 *  usage of has_cpu on non-SMP systems.
 */
int
is_task_active(ulong task)
{
	int has_cpu;

	if (DUMPFILE() && is_panic_thread(task))
		return TRUE;

        fill_task_struct(task);

	has_cpu = tt->last_task_read ? 
		task_has_cpu(task, tt->task_struct) : 0;

	if (!(kt->flags & SMP) && !has_cpu && ACTIVE() && 
	    (task == tt->this_task))
		has_cpu = TRUE;

	return(has_cpu);
}

/*
 *  Return true if a task is the panic_task or is contained within the 
 *  panic_threads[] array.
 */
int
is_panic_thread(ulong task)
{
	int i;

        if (DUMPFILE()) {
		if (tt->panic_task == task)
			return TRUE;

                for (i = 0; i < NR_CPUS; i++)
                        if (tt->panic_threads[i] == task)
                                return TRUE;
        }

	return FALSE;
}

/*
 *  Depending upon the kernel, check the task_struct's has_cpu or cpus_runnable 
 *  field if either exist, or the global runqueues[].curr via get_active_set()
 *  to determine whether a task is running on a cpu. 
 */
static int
task_has_cpu(ulong task, char *local_task) 
{
	int i, has_cpu;
	ulong cpus_runnable;

	if (DUMPFILE() && (task == tt->panic_task))  /* no need to continue */
		return TRUE;

	if (VALID_MEMBER(task_struct_has_cpu)) {
		if (local_task) 
			has_cpu = INT(local_task+OFFSET(task_struct_has_cpu));
		else if (!readmem((ulong)(task+OFFSET(task_struct_has_cpu)), 
			KVADDR, &has_cpu, sizeof(int), 
		    	"task_struct has_cpu", RETURN_ON_ERROR))
				has_cpu = FALSE;	
	} else if (VALID_MEMBER(task_struct_cpus_runnable)) {
                if (local_task) 
                        cpus_runnable = ULONG(local_task +
				OFFSET(task_struct_cpus_runnable));
		else if (!readmem((ulong)(task + 
			OFFSET(task_struct_cpus_runnable)),
                        KVADDR, &cpus_runnable, sizeof(ulong),
                        "task_struct cpus_runnable", RETURN_ON_ERROR))
                                cpus_runnable = ~0UL;
		has_cpu = (cpus_runnable != ~0UL);
	} else if (get_active_set()) {
                for (i = 0, has_cpu = FALSE; i < NR_CPUS; i++) {
                        if (task == tt->active_set[i]) {
				has_cpu = TRUE;
				break;
			}
		}
	} else
		error(FATAL, 
    "task_struct has no has_cpu, or cpus_runnable; runqueues[] not defined?\n");

	return has_cpu;
}


/*
 *  If a task is in the panic_threads array and has an associated panic_ksp
 *  array entry, return it.
 */
int
get_panic_ksp(struct bt_info *bt, ulong *ksp)
{
	int i;

	if (tt->flags & PANIC_KSP) {
        	for (i = 0; i < NR_CPUS; i++) {
        		if ((tt->panic_threads[i] == bt->task) && 
			     tt->panic_ksp[i] &&
			     INSTACK(tt->panic_ksp[i], bt)) {
				*ksp = tt->panic_ksp[i];
				return TRUE;
			}
		}
	}
	return FALSE;
}


/*
 *  Look for kcore's storage information for the system's panic state.
 *  If it's not there (somebody else's dump format?), look through all the
 *  stack traces for evidence of panic. 
 */
static ulong
get_panic_context(void)
{
        struct task_context *tc;
	ulong panic_threads_addr;
	ulong task;

	tt->panic_processor = -1;
	task = NO_TASK;
        tc = FIRST_CONTEXT();

	if (symbol_exists("panic_threads") &&
	    symbol_exists("panicmsg") &&
	    symbol_exists("panic_processor")) {
		panic_threads_addr = symbol_value("panic_threads");
		get_symbol_data("panic_processor", sizeof(int), 
			&tt->panic_processor);
		get_symbol_data("panicmsg", sizeof(char *), &tt->panicmsg);
	
		if (!readmem(panic_threads_addr, KVADDR, tt->panic_threads,
		    sizeof(void *)*NR_CPUS, "panic_processor array", 
		    RETURN_ON_ERROR))
			goto use_task_0;
	
		task = tt->panic_threads[tt->panic_processor];

		if (symbol_exists("panic_ksp")) {
		    	readmem(symbol_value("panic_ksp"), KVADDR, 
			    tt->panic_ksp,
		            sizeof(void *)*NR_CPUS, "panic_ksp array", 
		            RETURN_ON_ERROR);
			tt->flags |= PANIC_KSP;
		}

		if (machdep->flags & HWRESET) {
			populate_panic_threads();
			task = tt->panic_threads[0];
		}
	}

	if (task && task_exists(task)) 
		return(tt->panic_task = task);

	if (task) 
		error(INFO, "reported panic task %lx does not exist!\n\n", 
			task);

	if ((tc = panic_search())) {
		tt->panic_processor = tc->processor;
		return(tt->panic_task = tc->task);
	}

use_task_0:

	if (CRASHDEBUG(1))
		error(INFO, "get_panic_context: panic task not found\n");

	tt->flags |= PANIC_TASK_NOT_FOUND;
	tc = FIRST_CONTEXT();
        return(tc->task);
}

/*
 *  Get the active task on a cpu -- from a dumpfile only.
 */
ulong
get_active_task(int cpu)
{
	int i;
	ulong task;
        struct task_context *tc;

	if ((task = tt->panic_threads[cpu]))
		return task;

        tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
                if ((tc->processor == cpu) && is_task_active(tc->task))
                	return(tc->task);
	}

	return NO_TASK;
}


/*
 *  Read the panic string.
 */
char *
get_panicmsg(char *buf)
{
	int msg_found;

        BZERO(buf, BUFSIZE);
	msg_found = FALSE;

	if (tt->panicmsg) {
		read_string(tt->panicmsg, buf, BUFSIZE-1);
		msg_found = TRUE;
	} else if (LKCD_DUMPFILE()) {
		get_lkcd_panicmsg(buf);
		msg_found = TRUE;
	}

        if (msg_found == TRUE)
                return(buf);

	open_tmpfile();
	dump_log(FALSE);

	/*
	 *  First check for a SYSRQ-generated crash, and set the
	 *  active-task flag appropriately.  The message may or
	 *  may not be used as the panic message.
	 */
        rewind(pc->tmpfile);
        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
                if (strstr(buf, "SysRq : Crash") ||
		    strstr(buf, "SysRq : Trigger a crashdump")) {
			pc->flags |= SYSRQ;
			break;
		}
	}

	rewind(pc->tmpfile);
	while (!msg_found && fgets(buf, BUFSIZE, pc->tmpfile)) {
		if (strstr(buf, "Kernel panic: ")) 
			msg_found = TRUE;
	}
	rewind(pc->tmpfile);
	while (!msg_found && fgets(buf, BUFSIZE, pc->tmpfile)) {
	        if (strstr(buf, "Oops: ") || 
		    strstr(buf, "kernel BUG at")) 
	        	msg_found = TRUE;
	}
        rewind(pc->tmpfile);
        while (!msg_found && fgets(buf, BUFSIZE, pc->tmpfile)) {
                if (strstr(buf, "SysRq : Netdump") ||
		    strstr(buf, "SysRq : Trigger a crashdump") ||
		    strstr(buf, "SysRq : Crash")) {
			pc->flags |= SYSRQ;
                        msg_found = TRUE;
		}
        }
        rewind(pc->tmpfile);
        while (!msg_found && fgets(buf, BUFSIZE, pc->tmpfile)) {
                if (strstr(buf, "sysrq") && 
		    symbol_exists("sysrq_pressed")) 
			get_symbol_data("sysrq_pressed", sizeof(int), 
				&msg_found);
        }

        close_tmpfile();

	if (!msg_found)
       		BZERO(buf, BUFSIZE);

	return(buf);
}

/*
 *  This command allows the running of a set of commands on any or all 
 *  tasks running on a system.  The target tasks may be designated by
 *  pid, task or command name.  The available command set is designated by 
 *  the FOREACH_xxx definitions below.  If a running command name string
 *  conflicts with a foreach command, the command name string may be
 *  prefixed with a \ character.
 */

void
cmd_foreach(void)
{
	int a, c, k, t, p;
	ulong value;
	struct foreach_data foreach_data, *fd;
	struct task_context *tc;
	char *p1;
	int key;

	BZERO(&foreach_data, sizeof(struct foreach_data));
	fd = &foreach_data;

        while ((c = getopt(argcnt, args, "R:vomlgersStTpukcf")) != EOF) {
                switch(c)
		{
		case 'R':
			fd->reference = optarg;
			break;

		case 'v':
			fd->flags |= FOREACH_v_FLAG;
			break;

		case 'm':
			fd->flags |= FOREACH_m_FLAG;
			break;

		case 'l':
			fd->flags |= FOREACH_l_FLAG;
			break;

		case 'o':
                        fd->flags |= FOREACH_o_FLAG;
                        break;

		case 'g':
			fd->flags |= FOREACH_g_FLAG;
			break;

		case 'e':
			fd->flags |= FOREACH_e_FLAG;
			break;

		case 's':
			fd->flags |= FOREACH_s_FLAG;
			break;

		case 'S':
			fd->flags |= FOREACH_S_FLAG;
			break;

		case 'r':
			fd->flags |= FOREACH_r_FLAG;
			break;

		case 'T':
			fd->flags |= FOREACH_T_FLAG;
			break;

		case 't':
			fd->flags |= FOREACH_t_FLAG;
			break;

		case 'p':
			fd->flags |= FOREACH_p_FLAG;
			break;

                case 'u':
                        fd->flags |= FOREACH_u_FLAG;
                        break;

                case 'k':
                        fd->flags |= FOREACH_k_FLAG;
                        break;

		case 'c':
                        fd->flags |= FOREACH_c_FLAG;
                        break;

		case 'f':
			fd->flags |= FOREACH_f_FLAG;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs || !args[optind])
		cmd_usage(pc->curcmd, SYNOPSIS);

	a = c = k = t = p = 0;

	while (args[optind]) {
		/*
		 *  Once a keyword has been entered, then only accept
		 *  command arguments.
		 */
		if (k) {
			p1 = args[optind];
			goto command_argument;
		}

		/*
		 *  If it's a keyword, grab it and check no further.
		 */
                if (is_foreach_keyword(args[optind], &key)) {
			if (k == MAX_FOREACH_KEYWORDS)
				error(INFO, "too many keywords!\n");
			else 
                        	fd->keyword_array[k++] = key;
                        optind++;
                        continue;
                }

		/*
		 *  If it's a task pointer or pid, take it.
		 */
                if (IS_A_NUMBER(args[optind])) {

			switch (str_to_context(args[optind], &value, &tc))
			{
			case STR_PID:
                                if (p == MAX_FOREACH_PIDS)
                                        error(INFO,
                                            "too many pids specified!\n");
                                else {
                                        fd->pid_array[p++] = value;
                                        fd->flags |= FOREACH_SPECIFIED;
                                        optind++;
                                        continue;
                                }
				break;

			case STR_TASK:
                                if (t == MAX_FOREACH_TASKS)
                                        error(INFO,
                                            "too many tasks specified!\n");
                                else {
                                        fd->task_array[t++] = value;
                                        fd->flags |= FOREACH_SPECIFIED;
                                        optind++;
                                        continue;
                                }
				break;

			case STR_INVALID:
				break;
			}
                }

		/*
		 *  Select all kernel threads.
		 */
		if (STREQ(args[optind], "kernel")) {
			if (fd->flags & FOREACH_USER)
				error(FATAL, 
				   "user and kernel are mutually exclusive!\n");
			fd->flags |= FOREACH_KERNEL;
			optind++;
			continue;
		}

		/*
		 *  Select only user threads.
		 */
                if (STREQ(args[optind], "user")) {
                        if (fd->flags & FOREACH_KERNEL)
                                error(FATAL, 
                                   "user and kernel are mutually exclusive!\n");
			fd->flags |= FOREACH_USER;
                        optind++;
                        continue;
                }

		/* 
		 *  Select only active tasks (dumpfile only)
	  	 */
                if (STREQ(args[optind], "active")) {
			if (!DUMPFILE())
				error(FATAL, 
				 "active option not allowed on live systems\n");
                        fd->flags |= FOREACH_ACTIVE;
                        optind++;
                        continue;
                }

		/*
	         *  If it's a command name, prefixed or otherwise, take it.
		 */
		p1 = (args[optind][0] == '\\') ? 
			&args[optind][1] : args[optind];

		if (comm_exists(p1)) {
			if (c == MAX_FOREACH_COMMS)
				error(INFO, "too many commands specified!\n");
			else {
				fd->comm_array[c++] = p1;
				fd->flags |= FOREACH_SPECIFIED;
			}
			optind++;
			continue;
		} 

command_argument:
		/*
	 	 *  If no keyword has been entered, we don't know what this
		 *  is -- most likely it's a bogus command specifier. We set
		 *  FOREACH_SPECIFIED in case it was a bad specifier and no
		 *  other task selectors exist -- which in turn would causes
		 *  the command to be erroneously run on all tasks.
	 	 */
		if (!k) {
			fd->flags |= FOREACH_SPECIFIED;
			error(INFO, "unknown argument: \"%s\"\n",
				args[optind]);
			optind++;
			continue;
		}

                /*  
                 *  Must be an command argument -- so store it and let
                 *  the command deal with it...
                 */
		if (a == MAX_FOREACH_ARGS)
			error(INFO, "too many arguments specified!\n");
		else
               		fd->arg_array[a++] = (ulong)p1;

		optind++;
	}

	fd->flags |= FOREACH_CMD;
	fd->pids = p;
	fd->keys = k;
	fd->comms = c;
	fd->tasks = t;
	fd->args = a;

	if (!fd->keys)
		error(FATAL, "no keywords specified\n");

	foreach(fd);
}

/*
 *  Do the work for cmd_foreach().
 */
void
foreach(struct foreach_data *fd)
{
        int i, j, k, a;
        struct task_context *tc, *tgc;
	int specified;
	int doit;
	int subsequent;
	ulong cmdflags; 
	ulong tgid;
	struct reference reference, *ref;
	int print_header;
	struct bt_info bt_info, *bt;

	/* 
	 *  Filter out any command/option issues.
	 */
	if (CRASHDEBUG(1)) {
		fprintf(fp, "        flags: %lx\n", fd->flags);
		fprintf(fp, "   task_array: %s", fd->tasks ? "" : "(none)");
                for (j = 0; j < fd->tasks; j++)
			fprintf(fp, "[%lx] ", fd->task_array[j]); 
		fprintf(fp, "\n");

		fprintf(fp, "    pid_array: %s", fd->pids ? "" : "(none)");
                for (j = 0; j < fd->pids; j++)
			fprintf(fp, "[%ld] ", fd->pid_array[j]); 
		fprintf(fp, "\n");

		fprintf(fp, "   comm_array: %s", fd->comms ? "" : "(none)");
                for (j = 0; j < fd->comms; j++)
			fprintf(fp, "[%s] ", fd->comm_array[j]); 
		fprintf(fp, "\n");

		fprintf(fp, "keyword_array: %s", fd->keys ? "" : "(none)");
        	for (k = 0; k < fd->keys; k++) 
			fprintf(fp, "[%d] ", fd->keyword_array[k]);
		fprintf(fp, "\n");

		fprintf(fp, "    arg_array: %s", fd->args ? "" : "(none)");
		for (a = 0; a < fd->args; a++)
                	fprintf(fp, "[%lx (%s)] ", 
				fd->arg_array[a],
				(char *)fd->arg_array[a]);
		fprintf(fp, "\n");
		fprintf(fp, "    reference: \"%s\"\n", 
			fd->reference ?  fd->reference : "");
	}

	print_header = TRUE;

        for (k = 0; k < fd->keys; k++) {
        	switch(fd->keyword_array[k])
                {
		case FOREACH_FILES:
			if ((fd->flags & (FOREACH_CMD|FOREACH_l_FLAG)) ==
			    (FOREACH_CMD|FOREACH_l_FLAG)) {
				error(WARNING, 
				    "files: -l option is not applicable\n\n");
				fd->flags &= ~FOREACH_l_FLAG;
			}
			break;

                case FOREACH_NET:
			switch (fd->flags & (FOREACH_s_FLAG|FOREACH_S_FLAG))
			{
			case (FOREACH_s_FLAG|FOREACH_S_FLAG):
				error(WARNING, 
			     "net -s and -S options are mutually exclusive!\n");
				fd->flags = FOREACH_s_FLAG;
				break;

			case 0:
				error(WARNING, 
				    "net command requires -s or -S option\n\n");
				fd->flags |= FOREACH_s_FLAG;
				break;
			}
			break;

		case FOREACH_VTOP:
			if (!fd->args)
			    error(FATAL, 
			        "foreach command requires address argument\n");
			if (fd->reference)
				error(FATAL,
				   "vtop command does not support -R option\n");
                        if ((fd->flags & (FOREACH_u_FLAG|FOREACH_k_FLAG)) ==
				(FOREACH_u_FLAG|FOREACH_k_FLAG)) {
                                error(FATAL,
                            "vtop: -u and -k options are mutually exclusive\n");
                        }
			break;

		case FOREACH_VM:
                        if (count_bits_long(fd->flags &
                            (FOREACH_i_FLAG|FOREACH_p_FLAG|
                             FOREACH_m_FLAG|FOREACH_v_FLAG)) > 1)
				error(FATAL, 
			 "vm command accepts only one of -p, -m or -v flags\n");
			if (fd->reference) {
				if (fd->flags & FOREACH_i_FLAG)
					error(FATAL,
                                 "vm: -i is not applicable to the -R option\n");
				if (fd->flags & FOREACH_m_FLAG)
					error(FATAL, 
                                 "vm: -m is not applicable to the -R option\n");
				if (fd->flags & FOREACH_v_FLAG)
					error(FATAL, 
                                 "vm: -v is not applicable to the -R option\n");
			}
			break;

		case FOREACH_BT:
                        if ((fd->flags & FOREACH_l_FLAG) && GDB_PATCHED()) {
				error(INFO, "line numbers are not available\n");
				fd->flags &= ~FOREACH_l_FLAG;
			}
			bt = &bt_info;
			break;

		case FOREACH_TASK:
			break;

		case FOREACH_SET:
			if (fd->reference)
				error(FATAL,
				    "set command does not support -R option\n");
			break;

                case FOREACH_SIG:
			if (fd->flags & (FOREACH_l_FLAG|FOREACH_s_FLAG)) {
				error(FATAL, 
			    	 "sig: -l and -s options are not applicable\n");
			}
			if (fd->flags & FOREACH_g_FLAG) {
				if (!hq_open()) {
                			error(INFO, 
					   "cannot hash thread group tasks\n");
					fd->flags &= ~FOREACH_g_FLAG;
				} else
					print_header = FALSE;
			}
                        break;

		case FOREACH_TEST:
			break;
		}
	}

	
	subsequent = FALSE;
	specified = (fd->tasks || fd->pids || fd->comms ||
		(fd->flags & FOREACH_SPECIFIED));
	ref = &reference;

        tc = FIRST_CONTEXT();

        for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
		doit = FALSE;

		if ((fd->flags & FOREACH_ACTIVE) && !is_task_active(tc->task))
			continue;

		if ((fd->flags & FOREACH_USER) && is_kernel_thread(tc->task))
			continue;

		if ((fd->flags & FOREACH_KERNEL) && !is_kernel_thread(tc->task))
			continue;

		if (specified) {
	        	for (j = 0; j < fd->tasks; j++) 
				if (fd->task_array[j] == tc->task)
					doit = TRUE;
	
	       		for (j = 0; j < fd->pids; j++) 
				if (fd->pid_array[j] == tc->pid)
					doit = TRUE;
	
	        	for (j = 0; j < fd->comms; j++) 
				if (STREQ(fd->comm_array[j], tc->comm))
					doit = TRUE;
		}
		else 
			doit = TRUE;

		if (!doit)
			continue;

		if (output_closed() || received_SIGINT()) {
			free_all_bufs();
			goto foreach_bailout;
		}

                if (setjmp(pc->foreach_loop_env)) {
			free_all_bufs();
                        continue;
		}
		pc->flags |= IN_FOREACH;

		if (fd->reference) {
			BZERO(ref, sizeof(struct reference));
			ref->str = fd->reference;
		} else if (print_header)
			print_task_header(fp, tc, subsequent++);

		for (k = 0; k < fd->keys; k++) {
			free_all_bufs();

			switch(fd->keyword_array[k])
			{
			case FOREACH_BT:
				pc->curcmd = "bt";
				BZERO(bt, sizeof(struct bt_info));;
				bt->task = tc->task;
				bt->tc = tc;
				bt->stackbase = GET_STACKBASE(tc->task);
				bt->stacktop = GET_STACKTOP(tc->task);
				if (fd->flags & FOREACH_r_FLAG)
					bt->flags |= BT_RAW;
				if (fd->flags & FOREACH_s_FLAG)
					bt->flags |= BT_SYMBOLIC_ARGS;
				if (fd->flags & FOREACH_t_FLAG)
					bt->flags |= BT_TEXT_SYMBOLS;
				if (fd->flags & FOREACH_T_FLAG) {
					bt->flags |= BT_TEXT_SYMBOLS;
					bt->flags |= BT_TEXT_SYMBOLS_ALL;
				}
				if ((fd->flags & FOREACH_o_FLAG) ||
				    (kt->flags & USE_OLD_BT))
					bt->flags |= BT_OLD_BACK_TRACE;
                                if (fd->flags & FOREACH_e_FLAG)
                                        bt->flags |= BT_EFRAME_SEARCH;
                                if (fd->flags & FOREACH_g_FLAG)
#if defined(GDB_6_0) || defined(GDB_6_1)
				error(FATAL, 
		       "-g option is not supported with this version of gdb\n");
#else
                                        bt->flags |= BT_USE_GDB;
#endif
                                if (fd->flags & FOREACH_l_FLAG) 
                                        bt->flags |= BT_LINE_NUMBERS;
                                if (fd->flags & FOREACH_f_FLAG) 
                                        bt->flags |= BT_FULL;
				if (fd->reference)
					bt->ref = ref;
				back_trace(bt); 
				break;

			case FOREACH_VM:
				pc->curcmd = "vm";
				if (fd->flags & FOREACH_i_FLAG)
					vm_area_dump(tc->task, 
					    PRINT_INODES, 0, NULL);
				else if (fd->flags & FOREACH_p_FLAG)
					vm_area_dump(tc->task, 
					    PHYSADDR, 0, 
					    fd->reference ? ref : NULL);
				else if (fd->flags & FOREACH_m_FLAG)
					vm_area_dump(tc->task, 
					    PRINT_MM_STRUCT, 0, NULL);
				else if (fd->flags & FOREACH_v_FLAG)
					vm_area_dump(tc->task, 
					    PRINT_VMA_STRUCTS, 0, NULL);
				else
					vm_area_dump(tc->task, 0, 0, 
					    fd->reference ? ref : NULL);
				break;

			case FOREACH_TASK:
				pc->curcmd = "task";
				do_task(tc->task, FOREACH_TASK, 
					fd->reference ? ref : NULL);
				break;

                        case FOREACH_SIG:
				pc->curcmd = "sig";
				if (fd->flags & FOREACH_g_FLAG) {
					tgid = task_tgid(tc->task);	
					tgc = tgid_to_context(tgid);
					if (hq_enter(tgc->task))
						do_sig_thread_group(tgc->task);
				} else 
                                	do_sig(tc->task, FOREACH_SIG,
                                        	fd->reference ? ref : NULL);
                                break;

			case FOREACH_SET:
				pc->curcmd = "set";
				show_context(tc);
				break;

			case FOREACH_FILES:
				pc->curcmd = "files";
				open_files_dump(tc->task, 
					fd->flags & FOREACH_i_FLAG ?
					PRINT_INODES : 0, 
					fd->reference ? ref : NULL);
				break;

			case FOREACH_NET:
				pc->curcmd = "net";
				if (fd->flags & (FOREACH_s_FLAG|FOREACH_S_FLAG))
					dump_sockets_workhorse(tc->task,
						fd->flags, 
						fd->reference ? ref : NULL);
				break;

			case FOREACH_VTOP:
				pc->curcmd = "vtop";
				cmdflags = 0;
				if (fd->flags & FOREACH_c_FLAG)
					cmdflags |= USE_USER_PGD;
				if (fd->flags & FOREACH_u_FLAG)
					cmdflags |= UVADDR;
				if (fd->flags & FOREACH_k_FLAG)
					cmdflags |= KVADDR;

				for (a = 0; a < fd->args; a++) { 
					do_vtop(htol((char *)fd->arg_array[a], 
						FAULT_ON_ERROR, NULL), tc,
						cmdflags);
				}
				break;

			case FOREACH_TEST:
				pc->curcmd = "test";
				foreach_test(tc->task, 0);
				break;
			}

			pc->curcmd = "foreach";
		} 
	}

	/*
	 *  Post-process any commands requiring it.
	 */
        for (k = 0; k < fd->keys; k++) {
                switch(fd->keyword_array[k])
                {
                case FOREACH_FILES:
                        if (fd->flags & FOREACH_l_FLAG) {
				pc->curcmd = "files";
				fprintf(fp, "\n");
				nlm_files_dump();
			}
			break;

		case FOREACH_SIG:
                        if (fd->flags & FOREACH_g_FLAG)
				hq_close();
			break;
		}
	}

foreach_bailout:

	pc->flags &= ~IN_FOREACH;
}


/*
 *  The currently available set of foreach commands.
 */
static int
is_foreach_keyword(char *s, int *key)
{
	if (STREQ(args[optind], "bt")) {
		*key = FOREACH_BT;
		return TRUE;
	}

	if (STREQ(args[optind], "vm")) {
		*key = FOREACH_VM;
		return TRUE;
	}

        if (STREQ(args[optind], "task")) {
                *key = FOREACH_TASK;
                return TRUE;
        }

        if (STREQ(args[optind], "set")) {
                *key = FOREACH_SET;
                return TRUE;
        }

        if (STREQ(args[optind], "files")) {
                *key = FOREACH_FILES;
                return TRUE;
        }

	if (STREQ(args[optind], "net")) {
                *key = FOREACH_NET;
                return TRUE;
	}

        if (STREQ(args[optind], "vtop")) {
                *key = FOREACH_VTOP;
                return TRUE;
        }

        if (STREQ(args[optind], "sig")) {
                *key = FOREACH_SIG;
                return TRUE;
        }

        if (STREQ(args[optind], "test")) {
                *key = FOREACH_TEST;
                return TRUE;
        }

	return FALSE;
}

/*
 *  Try the dumpfile-specific manner of finding the panic task first.  If
 *  that fails, find the panic task the hard way -- do a "foreach bt" in the 
 *  background, and look for the only one that has "panic" embedded in it.
 */
static struct task_context *
panic_search(void)
{
        struct foreach_data foreach_data, *fd;
	char *p1, *p2, *tp;
	ulong lasttask, dietask, found;
	char buf[BUFSIZE];
	struct task_context *tc;

	if ((lasttask = get_dumpfile_panic_task())) {
		found = TRUE;
		goto found_panic_task;
	}

        BZERO(&foreach_data, sizeof(struct foreach_data));
        fd = &foreach_data;
	fd->keys = 1;
	fd->keyword_array[0] = FOREACH_BT; 
	fd->flags |= FOREACH_t_FLAG;

	dietask = lasttask = NO_TASK;
	
	found = FALSE;

	open_tmpfile();

	foreach(fd);

        rewind(pc->tmpfile);

        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
		if ((p1 = strstr(buf, "  TASK: "))) {
			p1 += strlen("  TASK: ");
			p2 = p1;
			while (!whitespace(*p2))
				p2++;
			*p2 = NULLCHAR;
			lasttask = htol(p1, RETURN_ON_ERROR, NULL);
		}

		if (strstr(buf, " panic at ")) {
			found = TRUE;
			break;	
		}

		if (strstr(buf, " crash_kexec at ") ||
		    strstr(buf, " .crash_kexec at ")) {
			found = TRUE;
			break;	
		}

                if (strstr(buf, " die at ")) {
			switch (dietask)
			{
			case NO_TASK:
				dietask = lasttask;
				break;
			default:
				dietask = NO_TASK+1;
				break;
			}
                }
	}

	close_tmpfile();

	if (!found && (dietask > (NO_TASK+1)) && task_has_cpu(dietask, NULL)) {
		lasttask = dietask;
		found = TRUE;
	}

	if (dietask == (NO_TASK+1))
		error(WARNING, "multiple active tasks have called die\n\n");

	if (CRASHDEBUG(1))
		error(INFO, "panic_search: %lx (via foreach bt)\n", 
			lasttask);

found_panic_task:
	populate_panic_threads();

	if (found) {
		if ((tc = task_to_context(lasttask)))
			return tc;

		/*
		 *  If the task list was corrupted, add this one in.
		 */
                if ((tp = fill_task_struct(lasttask))) {
			if ((tc = store_context(NULL, lasttask, tp))) {
				tt->running_tasks++;
				return tc;
			}
		}
	} 

	if (CRASHDEBUG(1))
		error(INFO, "panic_search: failed (via foreach bt)\n");

	return NULL;
}

/*
 *   Get the panic task from the appropriate dumpfile handler.
 */
static ulong
get_dumpfile_panic_task(void)
{
	ulong task;

	if (NETDUMP_DUMPFILE()) {
		task = pc->flags & REM_NETDUMP ?
			tt->panic_task : get_netdump_panic_task();
		if (task) 
			return task;
	} else if (KDUMP_DUMPFILE()) {
                task = get_kdump_panic_task();
                if (task)
                        return task;
        } else if (DISKDUMP_DUMPFILE()) {
                task = get_diskdump_panic_task();
                if (task)
                        return task;
	} else if (XENDUMP_DUMPFILE()) {
                task = get_xendump_panic_task();
                if (task)
                        return task;
        } else if (LKCD_DUMPFILE())
		return(get_lkcd_panic_task());

	if (get_active_set())
		return(get_active_set_panic_task());

	return NO_TASK;
}

/*
 *  If runqueues is defined in the kernel, get the panic threads from the
 *  active set.
 *
 *  If it's an LKCD dump, or for some other reason the active threads cannot
 *  be determined, do it the hard way.
 *
 *  NOTE: this function should be deprecated -- the work should have been
 *        done in the initial task table refresh.
 */
static void
populate_panic_threads(void)
{
	int i;
	int found;
        struct task_context *tc;

	if (get_active_set()) {
		for (i = 0; i < NR_CPUS; i++) 
			tt->panic_threads[i] = tt->active_set[i];
		return;
	}

	found = 0;
        if (!(machdep->flags & HWRESET)) {
		for (i = 0; i < kt->cpus; i++) {
			if (tt->panic_threads[i]) {
				if (++found == kt->cpus)
					return;
			}
		}
	}

        tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
		if (task_has_cpu(tc->task, NULL) && 
		    (tc->processor >= 0) && 
		    (tc->processor < NR_CPUS)) {
			tt->panic_threads[tc->processor] = tc->task;
			found++;
		}
	}

	if (!found && !(kt->flags & SMP) &&
	    (LKCD_DUMPFILE() || NETDUMP_DUMPFILE() || 
	     KDUMP_DUMPFILE() || DISKDUMP_DUMPFILE())) 
		tt->panic_threads[0] = get_dumpfile_panic_task();
}
	
/*
 *  Separate the foreach command's output on a task-by-task basis by
 *  displaying this header string.
 */
void
print_task_header(FILE *out, struct task_context *tc, int newline)
{
	char buf[BUFSIZE];
	char buf1[BUFSIZE];

        fprintf(out, "%sPID: %-5ld  TASK: %s  CPU: %-2s  COMMAND: \"%s\"\n",
		newline ? "\n" : "", tc->pid, 
		mkstring(buf1, VADDR_PRLEN, LJUST|LONG_HEX, MKSTR(tc->task)),
		task_cpu(tc->processor, buf, !VERBOSE), tc->comm);
}

/*
 *  "help -t" output
 */
void
dump_task_table(int verbose)
{
	int i, nr_cpus;
	struct task_context *tc;
	char buf[BUFSIZE];
	int others, wrap, flen;

	tc = tt->current;
	others = 0;

	fprintf(fp, "           current: %lx [%ld]\n",  (ulong)tt->current,
		(ulong)(tt->current - tt->context_array));
	if (tt->current) {
		fprintf(fp, "              .pid: %ld\n", tc->pid);
		fprintf(fp, "             .comm: \"%s\"\n", tc->comm);
		fprintf(fp, "             .task: %lx\n", tc->task);
		fprintf(fp, "      .thread_info: %lx\n", tc->thread_info);
		fprintf(fp, "        .processor: %d\n", tc->processor);
		fprintf(fp, "            .ptask: %lx\n", tc->ptask);
		fprintf(fp, "        .mm_struct: %lx\n", tc->mm_struct);
		fprintf(fp, "          .tc_next: %lx\n", (ulong)tc->tc_next);
	}
	fprintf(fp, "     context_array: %lx\n",  (ulong)tt->context_array);
	fprintf(fp, "refresh_task_table: ");
	if (tt->refresh_task_table == refresh_fixed_task_table)
		fprintf(fp, "refresh_fixed_task_table()\n");
	else if (tt->refresh_task_table == refresh_unlimited_task_table)
		fprintf(fp, "refresh_unlimited_task_table()\n");
	else if (tt->refresh_task_table == refresh_pidhash_task_table)
		fprintf(fp, "refresh_pidhash_task_table()\n");
        else if (tt->refresh_task_table == refresh_pid_hash_task_table)
                fprintf(fp, "refresh_pid_hash_task_table()\n");
        else if (tt->refresh_task_table == refresh_hlist_task_table)
                fprintf(fp, "refresh_hlist_task_table()\n");
        else if (tt->refresh_task_table == refresh_hlist_task_table_v2)
                fprintf(fp, "refresh_hlist_task_table_v2()\n");
	else
		fprintf(fp, "%lx\n", (ulong)tt->refresh_task_table);

	buf[0] = NULLCHAR;
	fprintf(fp, "             flags: %lx  ",  tt->flags);
	sprintf(buf, "(");
	if (tt->flags & TASK_INIT_DONE)
		sprintf(&buf[strlen(buf)], 
			"%sTASK_INIT_DONE", others++ ? "|" : "");
        if (tt->flags & TASK_ARRAY_EXISTS)
                sprintf(&buf[strlen(buf)], 
			"%sTASK_ARRAY_EXISTS", others++ ? "|" : "");
        if (tt->flags & PANIC_TASK_NOT_FOUND)
                sprintf(&buf[strlen(buf)], 
			"%sPANIC_TASK_NOT_FOUND", others++ ? "|" : "");
        if (tt->flags & TASK_REFRESH)
                sprintf(&buf[strlen(buf)], 
			"%sTASK_REFRESH", others++ ? "|" : "");
        if (tt->flags & TASK_REFRESH_OFF)
                sprintf(&buf[strlen(buf)], 
			"%sTASK_REFRESH_OFF", others++ ? "|" : "");
        if (tt->flags & PANIC_KSP)
                sprintf(&buf[strlen(buf)], 
			"%sPANIC_KSP", others++ ? "|" : "");
       if (tt->flags & POPULATE_PANIC)
                sprintf(&buf[strlen(buf)],
                        "%sPOPULATE_PANIC", others++ ? "|" : "");
        if (tt->flags & ACTIVE_SET)
                sprintf(&buf[strlen(buf)], 
			"%sACTIVE_SET", others++ ? "|" : "");
        if (tt->flags & PIDHASH)
                sprintf(&buf[strlen(buf)], 
			"%sPIDHASH", others++ ? "|" : "");
        if (tt->flags & PID_HASH)
                sprintf(&buf[strlen(buf)], 
			"%sPID_HASH", others++ ? "|" : "");
        if (tt->flags & THREAD_INFO)
                sprintf(&buf[strlen(buf)], 
			"%sTHREAD_INFO", others++ ? "|" : "");
        if (tt->flags & IRQSTACKS)
                sprintf(&buf[strlen(buf)], 
			"%sIRQSTACKS", others++ ? "|" : "");
        if (tt->flags & TIMESPEC)
                sprintf(&buf[strlen(buf)], 
			"%sTIMESPEC", others++ ? "|" : "");
        if (tt->flags & NO_TIMESPEC)
                sprintf(&buf[strlen(buf)], 
			"%sNO_TIMESPEC", others++ ? "|" : "");
	sprintf(&buf[strlen(buf)], ")");

        if (strlen(buf) > 54)
                fprintf(fp, "\n%s\n", mkstring(buf, 80, CENTER|LJUST, NULL));
        else
                fprintf(fp, "%s\n", buf);

	fprintf(fp, "        task_start: %lx\n",  tt->task_start);
	fprintf(fp, "          task_end: %lx\n",  tt->task_end);
	fprintf(fp, "        task_local: %lx\n",  (ulong)tt->task_local);
	fprintf(fp, "         max_tasks: %d\n", tt->max_tasks);
	fprintf(fp, "        nr_threads: %d\n", tt->nr_threads);
	fprintf(fp, "     running_tasks: %ld\n", tt->running_tasks);
	fprintf(fp, "           retries: %ld\n", tt->retries);
        fprintf(fp, "          panicmsg: \"%s\"\n",
                strip_linefeeds(get_panicmsg(buf)));
        fprintf(fp, "   panic_processor: %d\n", tt->panic_processor);
        fprintf(fp, "        panic_task: %lx\n", tt->panic_task);
        fprintf(fp, "         this_task: %lx\n", tt->this_task);
        fprintf(fp, "       pidhash_len: %d\n", tt->pidhash_len);
        fprintf(fp, "      pidhash_addr: %lx\n", tt->pidhash_addr);
	fprintf(fp, "    last_task_read: %lx\n", tt->last_task_read);
	fprintf(fp, "      last_mm_read: %lx\n", tt->last_mm_read);
	fprintf(fp, "       task_struct: %lx\n", (ulong)tt->task_struct);
	fprintf(fp, "         mm_struct: %lx\n", (ulong)tt->mm_struct);


        fprintf(fp, "     panic_threads:");

	wrap = sizeof(void *) == SIZEOF_32BIT ? 8 : 4;
	flen = sizeof(void *) == SIZEOF_32BIT ? 8 : 16;

	nr_cpus = kt->kernel_NR_CPUS ? kt->kernel_NR_CPUS : nr_cpus;

        for (i = 0; i < nr_cpus; i++) {
                if ((i % wrap) == 0)
                        fprintf(fp, "\n        ");
                fprintf(fp, "%.*lx ", flen, tt->panic_threads[i]); 
        }
        fprintf(fp, "\n");

        fprintf(fp, "         panic_ksp:");
        for (i = 0; i < nr_cpus; i++) {
                if ((i % wrap) == 0)
                        fprintf(fp, "\n        ");
                fprintf(fp, "%.*lx ", flen, tt->panic_ksp[i]);
        }
        fprintf(fp, "\n");

        fprintf(fp, "       hardirq_ctx:");
        for (i = 0; i < nr_cpus; i++) {
                if ((i % wrap) == 0)
                        fprintf(fp, "\n        ");
                fprintf(fp, "%.*lx ", flen, tt->hardirq_ctx[i]);
        }
        fprintf(fp, "\n");

        fprintf(fp, "     hardirq_tasks:");
        for (i = 0; i < nr_cpus; i++) {
                if ((i % wrap) == 0)
                        fprintf(fp, "\n        ");
                fprintf(fp, "%.*lx ", flen, tt->hardirq_tasks[i]);
        }
        fprintf(fp, "\n");

        fprintf(fp, "       softirq_ctx:");
        for (i = 0; i < nr_cpus; i++) {
                if ((i % wrap) == 0)
                        fprintf(fp, "\n        ");
                fprintf(fp, "%.*lx ", flen, tt->softirq_ctx[i]);
        }
        fprintf(fp, "\n");

        fprintf(fp, "     softirq_tasks:");
        for (i = 0; i < nr_cpus; i++) {
                if ((i % wrap) == 0)
                        fprintf(fp, "\n        ");
                fprintf(fp, "%.*lx ", flen, tt->softirq_tasks[i]);
        }
        fprintf(fp, "\n");

        fprintf(fp, "      idle_threads:");
        for (i = 0; i < nr_cpus; i++) {
                if ((i % wrap) == 0)
                        fprintf(fp, "\n        ");
                fprintf(fp, "%.*lx ", flen, tt->idle_threads[i]);
        }
        fprintf(fp, "\n");

	fprintf(fp, "        active_set:");
	for (i = 0; i < nr_cpus; i++) {
		if ((i % wrap) == 0)
	        	fprintf(fp, "\n        ");
	        fprintf(fp, "%.*lx ", flen, tt->active_set[i]);
	}
	fprintf(fp, "\n");


	if (!verbose)
		return;

	if (tt->flags & THREAD_INFO)
		fprintf(fp, 
	     "\nINDEX   TASK/THREAD_INFO    PID CPU PTASK   MM_STRUCT  COMM\n");
	else
		fprintf(fp, 
			"\nINDEX   TASK    PID CPU PTASK   MM_STRUCT  COMM\n");
        tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
		if (tt->flags & THREAD_INFO)
			fprintf(fp, 
			    "[%3d] %08lx/%08lx %5ld %d %08lx %08lx %s\n",
				i, tc->task, tc->thread_info, tc->pid, 
				tc->processor, tc->ptask, (ulong)tc->mm_struct,
				tc->comm); 
		else
			fprintf(fp, "[%3d] %08lx %5ld %d %08lx %08lx %s\n",
				i, tc->task, tc->pid, tc->processor, tc->ptask,
				(ulong)tc->mm_struct, tc->comm); 
	}
}

/*
 *  Determine whether a task is a kernel thread.  This would seem easier than
 *  it looks, but on live systems it's easy to get faked out.
 */
int
is_kernel_thread(ulong task)
{
	struct task_context *tc;
	ulong mm;

	tc = task_to_context(task);

	if ((tc->pid == 0) && !STREQ(tc->comm, pc->program_name))
		return TRUE;

	if (IS_ZOMBIE(task) || IS_EXITING(task))
                return FALSE;

	/*
	 *  Check for shifting sands on a live system.
	 */
	mm = task_mm(task, TRUE);

	if (ACTIVE() && (mm != tc->mm_struct))
		return FALSE;

        /*
         *  Later version Linux kernel threads have no mm_struct at all.
	 *  Earlier version kernel threads point to common init_mm.
         */
        if (!tc->mm_struct) {
		if (IS_EXITING(task)) 
			return FALSE;

		if (!task_state(task) && !task_flags(task))
			return FALSE;

		return TRUE;
                
	} else if (tc->mm_struct == symbol_value("init_mm")) 
		return TRUE;

	return FALSE;
}

/*
 *  Gather an arry of pointers to the per-cpu idle tasks.  The tasklist
 *  argument must be at least the size of ulong[NR_CPUS].  There may be
 *  junk in everything after the first entry on a single CPU box, so the
 *  data gathered may be throttled by kt->cpus.
 */
void
get_idle_threads(ulong *tasklist, int nr_cpus)
{
	int i, cnt;
	ulong runq, runqaddr;
	char *runqbuf;

	BZERO(tasklist, sizeof(ulong) * NR_CPUS);
	runqbuf = NULL;
	cnt = 0;

	if (symbol_exists("per_cpu__runqueues") && 
	    VALID_MEMBER(runqueue_idle)) {
		runqbuf = GETBUF(SIZE(runqueue));
		for (i = 0; i < nr_cpus; i++) {
			if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF)) {
				runq = symbol_value("per_cpu__runqueues") +
					kt->__per_cpu_offset[i];
			} else
				runq = symbol_value("per_cpu__runqueues");

			readmem(runq, KVADDR, runqbuf,
                        	SIZE(runqueue), "runqueues entry (per_cpu)",
                        	FAULT_ON_ERROR);		
			tasklist[i] = ULONG(runqbuf + OFFSET(runqueue_idle)); 
			if (IS_KVADDR(tasklist[i]))
				cnt++;
		}
	} else if (symbol_exists("runqueues") && VALID_MEMBER(runqueue_idle)) {
		runq = symbol_value("runqueues");
		runqbuf = GETBUF(SIZE(runqueue));
		for (i = 0; i < nr_cpus; i++, runq += SIZE(runqueue)) {
			readmem(runq, KVADDR, runqbuf,
                        	SIZE(runqueue), "runqueues entry (old)",
                        	FAULT_ON_ERROR);		
			tasklist[i] = ULONG(runqbuf + OFFSET(runqueue_idle)); 
			if (IS_KVADDR(tasklist[i]))
				cnt++;
		}
	} else if (symbol_exists("runqueues") && VALID_MEMBER(runqueue_cpu)) {
		runq = symbol_value("runqueues");
		runqbuf = GETBUF(SIZE(runqueue));

		for (i = 0; i < nr_cpus; i++) {
			runqaddr = runq + (SIZE(runqueue) * rq_idx(i));
			readmem(runqaddr, KVADDR, runqbuf,
                        	SIZE(runqueue), "runqueues entry",
                        	FAULT_ON_ERROR);		
			if ((tasklist[i] = get_idle_task(i, runqbuf)))
				cnt++;
		}
	} else if (symbol_exists("init_tasks")) {
                readmem(symbol_value("init_tasks"), KVADDR, tasklist,
                        sizeof(void *) * nr_cpus, "init_tasks array",
                        FAULT_ON_ERROR);
                if (IS_KVADDR(tasklist[0]))
			cnt++;
		else
                	BZERO(tasklist, sizeof(ulong) * NR_CPUS);
	}

	if (runqbuf)
		FREEBUF(runqbuf);

	if (!cnt) {
		error(INFO, 
     "cannot determine idle task addresses from init_tasks[] or runqueues[]\n");
		tasklist[0] = symbol_value("init_task_union");
	}
}

/*
 *  Emulate the kernel rq_idx() macro.
 */
static long
rq_idx(int cpu)
{
	if (kt->runq_siblings == 1)
		return cpu;
	else
		return kt->__rq_idx[cpu];
}

/*
 *  Emulate the kernel cpu_idx() macro.
 */
static long
cpu_idx(int cpu)
{
        if (kt->runq_siblings == 1)
                return 0;
        else
                return kt->__cpu_idx[cpu];
}

/*
 *  Dig out the idle task data from a runqueue structure.
 */
static ulong 
get_idle_task(int cpu, char *runqbuf)
{
	ulong idle_task;

	idle_task = ULONG(runqbuf + OFFSET(runqueue_cpu) +
		(SIZE(cpu_s) * cpu_idx(cpu)) + OFFSET(cpu_s_idle));

	if (IS_KVADDR(idle_task)) 
		return idle_task;
	else { 
		if (cpu < kt->cpus)
			error(INFO, 
				"cannot determine idle task for cpu %d\n", cpu);
		return NO_TASK;
	}
}

/*
 *  Dig out the current task data from a runqueue structure.
 */
static ulong
get_curr_task(int cpu, char *runqbuf)
{
        ulong curr_task;

        curr_task = ULONG(runqbuf + OFFSET(runqueue_cpu) +
                (SIZE(cpu_s) * cpu_idx(cpu)) + OFFSET(cpu_s_curr));

        if (IS_KVADDR(curr_task)) 
                return curr_task;
        else 
                return NO_TASK;
}

/*
 *  On kernels with runqueue[] array, store the active set of tasks.
 */
int
get_active_set(void)
{
        int i, cnt, per_cpu;
        ulong runq, runqaddr;
        char *runqbuf;

        if (tt->flags & ACTIVE_SET)
                return TRUE;

	if (symbol_exists("runqueues")) {
		runq = symbol_value("runqueues");
		per_cpu = FALSE;
	} else if (symbol_exists("per_cpu__runqueues")) {
		runq = symbol_value("per_cpu__runqueues");
		per_cpu = TRUE;
	} else
		return FALSE;

        BZERO(tt->active_set, sizeof(ulong) * NR_CPUS);
        runqbuf = GETBUF(SIZE(runqueue));
	cnt = 0;

	if (VALID_MEMBER(runqueue_curr) && per_cpu) {
               	for (i = 0; i < kt->cpus; i++) {
                        if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF)) {
                                runq = symbol_value("per_cpu__runqueues") +
                                        kt->__per_cpu_offset[i];
                        } else
                                runq = symbol_value("per_cpu__runqueues");

                        readmem(runq, KVADDR, runqbuf, SIZE(runqueue), 
				"active runqueues entry (per_cpu)",
                                FAULT_ON_ERROR);

	               	tt->active_set[i] = ULONG(runqbuf + 
				OFFSET(runqueue_curr));
			if (IS_KVADDR(tt->active_set[i]))
				cnt++;
		}
	} else if (VALID_MEMBER(runqueue_curr)) {
	        for (i = 0; i < NR_CPUS; i++, runq += SIZE(runqueue)) {
	                readmem(runq, KVADDR, runqbuf,
	                	SIZE(runqueue), "(old) runqueues curr",
	                        FAULT_ON_ERROR);
	               	tt->active_set[i] = ULONG(runqbuf + 
				OFFSET(runqueue_curr));
			if (IS_KVADDR(tt->active_set[i]))
				cnt++;
		}
        } else if (VALID_MEMBER(runqueue_cpu)) {
		for (i = 0; i < kt->cpus; i++) {
                        runqaddr = runq + (SIZE(runqueue) * rq_idx(i));
                        readmem(runqaddr, KVADDR, runqbuf,
                                SIZE(runqueue), "runqueues curr",
                                FAULT_ON_ERROR);
			if ((tt->active_set[i] = get_curr_task(i, runqbuf)))
				cnt++;
                }
	}

	if (cnt) {
		tt->flags |= ACTIVE_SET;
		return TRUE;
	} else {
		error(INFO, "get_active_set: no tasks found?\n");
		return FALSE;
	}
}

/*
 *  Clear the ACTIVE_SET flag on a live system, forcing a re-read of the
 *  runqueues[] array the next time get_active_set() is called above.
 */
void
clear_active_set(void)
{
        if (ACTIVE() && (tt->flags & TASK_REFRESH))
                tt->flags &= ~ACTIVE_SET;
}

#define RESOLVE_PANIC_AND_DIE_CALLERS()               		\
	if (xen_panic_task) {					\
                if (CRASHDEBUG(1))                              \
                        error(INFO,                             \
         "get_active_set_panic_task: %lx (xen_panic_event)\n",  \
                                xen_panic_task);		\
		return xen_panic_task;				\
	}							\
	if (crash_kexec_task) {					\
		if (CRASHDEBUG(1))				\
			error(INFO,				\
	    "get_active_set_panic_task: %lx (crash_kexec)\n",   \
				crash_kexec_task);	  	\
		return crash_kexec_task;			\
	}							\
        if ((panic_task > (NO_TASK+1)) && !die_task) {		\
		if (CRASHDEBUG(1))				\
			fprintf(fp, 				\
		    "get_active_set_panic_task: %lx (panic)\n", \
				panic_task);			\
                return panic_task;                    		\
	}							\
                                                      		\
        if (panic_task && die_task) {                 		\
                error(WARNING,                        		\
     "multiple active tasks have called die and/or panic\n\n"); \
		goto no_panic_task_found;			\
        }                                             		\
                                                      		\
        if (die_task > (NO_TASK+1)) {                 		\
		if (CRASHDEBUG(1))				\
			fprintf(fp, 				\
		    "get_active_set_panic_task: %lx (die)\n", 	\
				die_task);			\
                return die_task;                      		\
	}							\
        else if (die_task == (NO_TASK+1))             		\
                error(WARNING,                        		\
	"multiple active tasks have called die\n\n"); 

#define SEARCH_STACK_FOR_PANIC_DIE_AND_KEXEC_CALLERS()  \
	while (fgets(buf, BUFSIZE, pc->tmpfile)) {      \
                if (strstr(buf, " die+")) {             \
                        switch (die_task)               \
                        {                               \
                        case NO_TASK:                   \
                                die_task = task;        \
                                break;                  \
                        default:                        \
                                die_task = NO_TASK+1;   \
                                break;                  \
                        }                               \
                }                                       \
                if (strstr(buf, " panic+")) {           \
                        switch (panic_task)             \
                        {                               \
                        case NO_TASK:                   \
                                panic_task = task;      \
				if (XENDUMP_DUMPFILE()) \
					xendump_panic_hook(buf); \
                                break;                  \
                        default:                        \
                                panic_task = NO_TASK+1; \
                                break;                  \
                        }                               \
                }                                       \
                if (strstr(buf, " crash_kexec+") ||     \
                    strstr(buf, " .crash_kexec+")) {    \
			crash_kexec_task = task;	\
                }                                       \
                if (strstr(buf, " xen_panic_event+") || \
                    strstr(buf, " .xen_panic_event+")){ \
			xen_panic_task = task;	        \
			xendump_panic_hook(buf);	\
		}					\
	}

/*
 *  Search the active set tasks for instances of die or panic calls.
 */
static ulong
get_active_set_panic_task()
{
	int i, j, found;
	ulong task;
	char buf[BUFSIZE];
	ulong panic_task, die_task, crash_kexec_task;
	ulong xen_panic_task;
	char *tp;
	struct task_context *tc;

	panic_task = die_task = crash_kexec_task = xen_panic_task = NO_TASK;

        for (i = 0; i < NR_CPUS; i++) {
                if (!(task = tt->active_set[i]))
			continue;

		if (!task_exists(task)) {
			error(WARNING, 
			  "active task %lx on cpu %d not found in PID hash\n\n",
				task, i);
                	if ((tp = fill_task_struct(task))) {
                        	if ((tc = store_context(NULL, task, tp))) 
                                	tt->running_tasks++;
                	}
			continue;
		}

        	open_tmpfile();
		raw_stack_dump(GET_STACKBASE(task), STACKSIZE());
        	rewind(pc->tmpfile);

		SEARCH_STACK_FOR_PANIC_DIE_AND_KEXEC_CALLERS();

		close_tmpfile();
        }

	RESOLVE_PANIC_AND_DIE_CALLERS();

	if (tt->flags & IRQSTACKS) {
		panic_task = die_task = NO_TASK;

	        for (i = 0; i < NR_CPUS; i++) {
			if (!(task = tt->hardirq_tasks[i]))
				continue;

			for (j = found = 0; j < NR_CPUS; j++) {
				if (task == tt->active_set[j]) {
					found++;
					break;
				}
			}

			if (!found)
				continue;

	        	open_tmpfile();
			raw_stack_dump(tt->hardirq_ctx[i], SIZE(thread_union));
	        	rewind(pc->tmpfile);
	
			SEARCH_STACK_FOR_PANIC_DIE_AND_KEXEC_CALLERS();

			close_tmpfile();
	        }

		RESOLVE_PANIC_AND_DIE_CALLERS();

		panic_task = die_task = NO_TASK;

	        for (i = 0; i < NR_CPUS; i++) {
			if (!(task = tt->softirq_tasks[i]))
				continue;

			for (j = found = 0; j < NR_CPUS; j++) {
				if (task == tt->active_set[j]) {
					found++;
					break;
				}
			}

			if (!found)
				continue;
	
	        	open_tmpfile();
			raw_stack_dump(tt->softirq_ctx[i], SIZE(thread_union));
	        	rewind(pc->tmpfile);
	
			SEARCH_STACK_FOR_PANIC_DIE_AND_KEXEC_CALLERS();

			close_tmpfile();
	        }

		RESOLVE_PANIC_AND_DIE_CALLERS();
	} 

	if (crash_kexec_task) {
		if (CRASHDEBUG(1))
			error(INFO,
		    "get_active_set_panic_task: %lx (crash_kexec)\n", 
				crash_kexec_task);
		return crash_kexec_task;
	}

no_panic_task_found:

	if (CRASHDEBUG(1)) 
		error(INFO,
		    "get_active_set_panic_task: failed\n");

	return NO_TASK;
}


/*
 *  Determine whether a task is one of the idle threads.
 */
int
is_idle_thread(ulong task)
{
	int i;

        for (i = 0; i < NR_CPUS; i++) 
		if (task == tt->idle_threads[i])
			return TRUE;

	return FALSE;
}


/*
 *  Dump the current run queue task list.  This command should be expanded
 *  to deal with timer queues, bottom halves, etc...
 */
void
cmd_runq(void)
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

	dump_runq();
}

/*
 *  Dump the task run queue on behalf cmd_runq().
 */

static void
dump_runq(void)
{
	int i;
	ulong next, runqueue_head;
	long offs;
	int qlen, cnt;
	ulong *tlist;
	struct task_context *tc;

	if (VALID_MEMBER(runqueue_arrays)) {
		dump_runqueues();
		return;
	}

	qlen = 1000;

start_again:
	tlist = (ulong *)GETBUF(qlen * sizeof(void *));

        if (symbol_exists("runqueue_head")) {
		next = runqueue_head = symbol_value("runqueue_head");
		offs = 0;
        } else if (VALID_MEMBER(task_struct_next_run)) {
		offs = OFFSET(task_struct_next_run);
		next = runqueue_head = symbol_value("init_task_union");
	} else
		error(FATAL, 
		    "cannot determine run queue structures being used\n");

	cnt = 0;
	do {
		if (cnt == qlen) {
			FREEBUF(tlist);
			qlen += 1000;
			goto start_again;
		} 

		tlist[cnt++] = next;

                readmem(next+offs, KVADDR, &next, sizeof(void *), 
			"run queue entry", FAULT_ON_ERROR);

		if (next == runqueue_head)
			break;
	} while (next);

	for (i = 0; i < cnt; i++) {
		if (tlist[i] == runqueue_head)
			continue;

		if (!(tc = task_to_context(VIRTPAGEBASE(tlist[i])))) {
			fprintf(fp, 
			    	"PID: ?      TASK: %lx  CPU: ?   COMMAND: ?\n",
					tlist[i]);
			continue;
		}

		if (!is_idle_thread(tc->task))
			print_task_header(fp, tc, 0);
	}
}

#define RUNQ_ACTIVE  (1)
#define RUNQ_EXPIRED (2)

static void
dump_runqueues(void)
{
	int cpu;
	ulong runq, offset;
	char *runqbuf;
	ulong active, expired, arrays;
	int per_cpu;


        if (symbol_exists("runqueues")) {
                runq = symbol_value("runqueues");
                per_cpu = FALSE;
        } else if (symbol_exists("per_cpu__runqueues")) {
                runq = symbol_value("per_cpu__runqueues");
                per_cpu = TRUE;
        }

        runqbuf = GETBUF(SIZE(runqueue));

	for (cpu = 0; cpu < kt->cpus; cpu++, runq += SIZE(runqueue)) {
		if (per_cpu) {
			if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF)) {
                 		runq = symbol_value("per_cpu__runqueues") +
                        		kt->__per_cpu_offset[cpu];
                 	} else
                 		runq = symbol_value("per_cpu__runqueues");
		}

		fprintf(fp, "RUNQUEUES[%d]: %lx\n", cpu, runq);

                readmem(runq, KVADDR, runqbuf, SIZE(runqueue), 
			"runqueues array entry", FAULT_ON_ERROR);
		active = ULONG(runqbuf + OFFSET(runqueue_active));
		expired = ULONG(runqbuf + OFFSET(runqueue_expired));
		arrays = runq + OFFSET(runqueue_arrays);

		console("active: %lx\n", active);
		console("expired: %lx\n", expired);
		console("arrays: %lx\n", arrays);

		offset = active == arrays ? OFFSET(runqueue_arrays) :
			OFFSET(runqueue_arrays) + SIZE(prio_array);
		offset = active - runq;
		dump_prio_array(RUNQ_ACTIVE, active, &runqbuf[offset]);

		offset = expired == arrays ? OFFSET(runqueue_arrays) :
			OFFSET(runqueue_arrays) + SIZE(prio_array);
		offset = expired - runq;
		dump_prio_array(RUNQ_EXPIRED, expired, &runqbuf[offset]);
	}
}

static void
dump_prio_array(int which, ulong k_prio_array, char *u_prio_array)
{
	int i, c, cnt, qheads, nr_active;
	ulong offset, kvaddr, uvaddr;
	ulong list_head[2];
        struct list_data list_data, *ld;
	struct task_context *tc;
	ulong *tlist;

        qheads = (i = ARRAY_LENGTH(prio_array_queue)) ?
                i : get_array_length("prio_array.queue", NULL, SIZE(list_head));

	console("dump_prio_array[%d]: %lx %lx\n",
		which, k_prio_array, (ulong)u_prio_array);

	nr_active = INT(u_prio_array + OFFSET(prio_array_nr_active));
	console("nr_active: %d\n", nr_active);

	fprintf(fp, " %s PRIO_ARRAY: %lx\n",  
		which == RUNQ_ACTIVE ? "ACTIVE" : "EXPIRED", k_prio_array);

	ld = &list_data;

	for (i = 0; i < 140; i++) {
		offset =  OFFSET(prio_array_queue) + (i * SIZE(list_head));
		kvaddr = k_prio_array + offset;
		uvaddr = (ulong)u_prio_array + offset;
		BCOPY((char *)uvaddr, (char *)&list_head[0], sizeof(ulong)*2);

		if (CRASHDEBUG(1))
			fprintf(fp, "prio_array[%d] @ %lx => %lx/%lx\n", 
				i, kvaddr, list_head[0], list_head[1]);

		if ((list_head[0] == kvaddr) && (list_head[1] == kvaddr))
			continue;

		console("[%d] %lx => %lx-%lx ", i, kvaddr, list_head[0],
			list_head[1]);

		fprintf(fp, "  [%3d] ", i);

		BZERO(ld, sizeof(struct list_data));
		ld->start = list_head[0];
		ld->list_head_offset = OFFSET(task_struct_run_list);
		ld->end = kvaddr;
		hq_open();
		cnt = do_list(ld);
		hq_close();
		console("%d entries\n", cnt);
        	tlist = (ulong *)GETBUF((cnt) * sizeof(ulong));
		cnt = retrieve_list(tlist, cnt);
		for (c = 0; c < cnt; c++) {
			if (!(tc = task_to_context(tlist[c])))
				continue;
			if (c)
				INDENT(8);
			print_task_header(fp, tc, FALSE);
		}
		FREEBUF(tlist);
	}
}

#undef _NSIG
#define _NSIG           64
#define _NSIG_BPW       machdep->bits
#define _NSIG_WORDS     (_NSIG / _NSIG_BPW)

#undef SIGRTMIN
#define SIGRTMIN	32

static struct signame {
        char *name;
        char *altname;
} signame[_NSIG] = {
    /* 0 */   {NULL,         NULL},
    /* 1 */   {"SIGHUP",     NULL},
    /* 2 */   {"SIGINT",     NULL},
    /* 3 */   {"SIGQUIT",    NULL},
    /* 4 */   {"SIGILL",     NULL},
    /* 5 */   {"SIGTRAP",    NULL},
    /* 6 */   {"SIGABRT",    "SIGIOT"},
    /* 7 */   {"SIGBUS",     NULL},
    /* 8 */   {"SIGFPE",     NULL},
    /* 9 */   {"SIGKILL",    NULL},
    /* 10 */  {"SIGUSR1",    NULL},
    /* 11 */  {"SIGSEGV",    NULL},
    /* 12 */  {"SIGUSR2",    NULL},
    /* 13 */  {"SIGPIPE",    NULL},
    /* 14 */  {"SIGALRM",    NULL},
    /* 15 */  {"SIGTERM",    NULL},
    /* 16 */  {"SIGSTKFLT",  NULL},
    /* 17 */  {"SIGCHLD",    "SIGCLD"},
    /* 18 */  {"SIGCONT",    NULL},
    /* 19 */  {"SIGSTOP",    NULL},
    /* 20 */  {"SIGTSTP",    NULL},
    /* 21 */  {"SIGTTIN",    NULL},
    /* 22 */  {"SIGTTOU",    NULL},
    /* 23 */  {"SIGURG",     NULL},
    /* 24 */  {"SIGXCPU",    NULL},
    /* 25 */  {"SIGXFSZ",    NULL},
    /* 26 */  {"SIGVTALRM",  NULL},
    /* 27 */  {"SIGPROF",    NULL},
    /* 28 */  {"SIGWINCH",   NULL},
    /* 29 */  {"SIGIO",      "SIGPOLL"},
    /* 30 */  {"SIGPWR",     NULL},
    /* 31 */  {"SIGSYS",     "SIGUNUSED"},
              {NULL,         NULL},    /* Real time signals start here. */
};

static int
sigrt_minmax(int *min, int *max) 
{
	int sigrtmax, j;

	sigrtmax = THIS_KERNEL_VERSION < LINUX(2,5,0) ? 
		_NSIG - 1  : _NSIG;

	if (min && max) {
		j = sigrtmax-SIGRTMIN-1;
		*max = j / 2;
		*min = j - *max;
	}

	return sigrtmax;
}

static void
signame_list(void)
{
	int i, sigrtmax, j, min, max;

	sigrtmax = sigrt_minmax(&min, &max);
	j = 1;

        for (i = 1; i <= sigrtmax; i++) {
		if ((i == SIGRTMIN) || (i == sigrtmax)) {
			fprintf(fp, "[%d] %s", i, 
			    (i== SIGRTMIN) ? "SIGRTMIN" : "SIGRTMAX");
		} else if (i > SIGRTMIN) {
			if (j <= min){
				fprintf(fp, "[%d] %s%d", i , "SIGRTMIN+", j);
				j++;
			} else if (max >= 1) {
				fprintf(fp, "[%d] %s%d", i , "SIGRTMAX-",max);
				max--;
			}
		} else {
                	if (!signame[i].name)
                        	continue;

                	fprintf(fp, "%s[%d] %s", i < 10 ? " " : "", 
				i, signame[i].name);
			if (signame[i].altname)
				fprintf(fp, "/%s",  signame[i].altname);
		}
		fprintf(fp, "\n");
        }
}

/*
 *  Translate the bits in a signal set into their name strings.
 */
static void 
translate_sigset(ulonglong sigset)
{
	int sigrtmax, min, max, i, j, c, len;
	char buf[BUFSIZE];

	if (!sigset) {
		fprintf(fp, "(none)\n");
		return;
	}

	len = 0;
	sigrtmax= sigrt_minmax(&min, &max);
	j = 1;

        for (i = 1, c = 0; i <= sigrtmax; i++) {
		if (sigset & (ulonglong)1) {
			if (i == SIGRTMIN || i == sigrtmax)
				sprintf(buf, "%s%s", c++ ? " " : "", 
					(i==SIGRTMIN) ? "SIGRTMIN" : "SIGRTMAX");
			else if (i > SIGRTMIN) {
				if (j <= min)
					sprintf(buf, "%s%s%d", 
						c++ ? " " : "", "SIGRTMIN+", j);
				else if (max >= 1)
					sprintf(buf, "%s%s%d", 
						c++ ? " " : "", "SIGRTMAX-", max);
			} else
				sprintf(buf, "%s%s", c++ ? " " : "", 
					signame[i].name);

			if ((len + strlen(buf)) > 80) {
				shift_string_left(buf, 1);
				fprintf(fp,  "\n");
				len = 0;
			}

			len += strlen(buf);
			fprintf(fp, buf);
		}

		sigset >>= 1;
		if (i > SIGRTMIN) {
			if (j <= min) 
				j++;
			else if (max >= 1)
				max--;
		}	
	}
	fprintf(fp, "\n");
}

/*
 *  Machine dependent interface to modify signame struct contents.
 */
void modify_signame(int sig, char *name, char *altname)
{
	signame[sig].name = name;
	signame[sig].altname = altname;
}

/*
 *  Display all signal-handling data for a task.
 *
 *  Reference handling framework is here, but not used as of yet.
 */

void
cmd_sig(void)
{
	int c, tcnt, bogus;
	ulong value;
	ulonglong sigset;
	struct reference *ref;
	struct task_context *tc;
	ulong *tasklist;
	char *siglist;
	int thread_group = FALSE;

	tasklist = (ulong *)GETBUF((MAXARGS+NR_CPUS)*sizeof(ulong));
	ref = (struct reference *)GETBUF(sizeof(struct reference));
	siglist = GETBUF(BUFSIZE);
	ref->str = siglist;

        while ((c = getopt(argcnt, args, "lR:s:g")) != EOF) {
                switch(c)
		{
		case 's':
			sigset = htoll(optarg, FAULT_ON_ERROR, NULL);
			translate_sigset(sigset);
			return;

		case 'R':
			if (strlen(ref->str))
				strcat(ref->str, ",");
			strcat(ref->str, optarg);
			break;

		case 'l':
			signame_list();
			return;

		case 'g':
			pc->curcmd_flags |= TASK_SPECIFIED;
			thread_group = TRUE;
			break;
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	tcnt = bogus = 0;

        while (args[optind]) {
		if (IS_A_NUMBER(args[optind])) {
	                switch (str_to_context(args[optind], &value, &tc))
	                {
	                case STR_PID:
                                for (tc = pid_to_context(value); tc;
                                     tc = tc->tc_next)
                                        tasklist[tcnt++] = tc->task;
	                        break;
	
	                case STR_TASK:
				tasklist[tcnt++] = value;
	                        break;
	
	                case STR_INVALID:
				bogus++;
	                        error(INFO, "invalid task or pid value: %s\n\n",
	                                args[optind]);
	                        break;
	                }
		} else if (strstr(args[optind], ",") ||
			MEMBER_EXISTS("task_struct", args[optind])) {
			if (strlen(ref->str))
				strcat(ref->str, ",");
			strcat(ref->str, args[optind]);
		} else
                        error(INFO, "invalid task or pid value: %s\n\n",
                                args[optind]);
                optind++;
        }

	if (!tcnt && !bogus)
		tasklist[tcnt++] = CURRENT_TASK();

	for (c = 0; c < tcnt; c++) {
		if (thread_group)
			do_sig_thread_group(tasklist[c]);
		else {
			do_sig(tasklist[c], 0, strlen(ref->str) ? ref : NULL);
			fprintf(fp, "\n");
		}
	}

}


/*
 *  Do the work for the "sig -g" command option, coming from sig or foreach.
 */
static void
do_sig_thread_group(ulong task)
{
        int i;
        int cnt;
        struct task_context *tc;
	ulong tgid;

        tc = task_to_context(task);
	tgid = task_tgid(task);

	if (tc->pid != tgid) {
		if (pc->curcmd_flags & TASK_SPECIFIED) {
			if (!(tc = tgid_to_context(tgid))) 
				return;
			task = tc->task;
		} else 
			return;
	}

	if ((tc->pid == 0) && (pc->curcmd_flags & IDLE_TASK_SHOWN))
		return;

       	print_task_header(fp, tc, 0);
	dump_signal_data(tc, THREAD_GROUP_LEVEL);
	fprintf(fp, "\n  ");
	print_task_header(fp, tc, 0);
	dump_signal_data(tc, TASK_LEVEL|TASK_INDENT);

	tc = FIRST_CONTEXT();
        for (i = cnt = 0; i < RUNNING_TASKS(); i++, tc++) {
		if (tc->task == task)
			continue;

		if (task_tgid(tc->task)	== tgid) {
			fprintf(fp, "\n  ");
                        print_task_header(fp, tc, 0);
			dump_signal_data(tc, TASK_LEVEL|TASK_INDENT);
                        cnt++;
			if (tc->pid == 0)
				pc->curcmd_flags |= IDLE_TASK_SHOWN;
                }
        }

	fprintf(fp, "\n");
}

/*
 *  Do the work for the sig command, coming from sig or foreach.
 */
void
do_sig(ulong task, ulong flags, struct reference *ref)
{
        struct task_context *tc;

        tc = task_to_context(task);

        if (ref)
                signal_reference(tc, flags, ref);
        else {
                if (!(flags & FOREACH_TASK))
                        print_task_header(fp, tc, 0);
                dump_signal_data(tc, TASK_LEVEL|THREAD_GROUP_LEVEL);
        }
}

/*
 *  Implementation for -R reference for the sig command.
 */
static void
signal_reference(struct task_context *tc, ulong flags, struct reference *ref)
{
	if (flags & FOREACH_SIG)
		error(FATAL, "sig: -R not supported yet\n");
	else
		error(FATAL, "-R not supported yet\n");
}

/*
 *  Dump all signal-handling data for a task.
 */
static void
dump_signal_data(struct task_context *tc, ulong flags)
{
	int i, sigrtmax, others, use_sighand;
	int translate, sigpending;
	uint ti_flags;
	ulonglong sigset, blocked, mask;
	ulong signal_struct, kaddr, handler, sa_flags, sigqueue;
	ulong sighand_struct;
	long size;
	char *signal_buf, *uaddr;
	ulong shared_pending, signal;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];

        if (VALID_STRUCT(sigqueue) && !VALID_MEMBER(sigqueue_next)) {
                MEMBER_OFFSET_INIT(sigqueue_next, "sigqueue", "next");
                MEMBER_OFFSET_INIT(sigqueue_list, "sigqueue", "list");
                MEMBER_OFFSET_INIT(sigqueue_info, "sigqueue", "info");
        } else if (!VALID_MEMBER(signal_queue_next)) {
                MEMBER_OFFSET_INIT(signal_queue_next, "signal_queue", "next");
                MEMBER_OFFSET_INIT(signal_queue_info, "signal_queue", "info");
        }

	sigset = task_signal(tc->task, 0);
	if (!tt->last_task_read)
		return;

	if (VALID_MEMBER(task_struct_sig))
		signal_struct = ULONG(tt->task_struct + 
			OFFSET(task_struct_sig));
	else if (VALID_MEMBER(task_struct_signal))
		signal_struct = ULONG(tt->task_struct + 
			OFFSET(task_struct_signal));

	size = MAX(SIZE(signal_struct), VALID_SIZE(signal_queue) ?  
		SIZE(signal_queue) : SIZE(sigqueue));
	if (VALID_SIZE(sighand_struct))
		size = MAX(size, SIZE(sighand_struct));
	signal_buf = GETBUF(size);

	if (signal_struct)
		readmem(signal_struct, KVADDR, signal_buf,
			SIZE(signal_struct), "signal_struct buffer",
			FAULT_ON_ERROR);

	/*
	 *  Signal dispositions (thread group level).
	 */
	if (flags & THREAD_GROUP_LEVEL) {
		if (flags & TASK_INDENT)
			INDENT(2);
		fprintf(fp, "SIGNAL_STRUCT: %lx  ", signal_struct);
		if (!signal_struct) {
			fprintf(fp, "\n");
			return;
		}
		fprintf(fp, "COUNT: %d\n",
			INT(signal_buf + OFFSET(signal_struct_count)));

		if (flags & TASK_INDENT)
			INDENT(2);
		fprintf(fp, " SIG %s %s %s %s\n",
			mkstring(buf1, VADDR_PRLEN == 8 ? 9 : VADDR_PRLEN, 
				CENTER, "SIGACTION"),
		mkstring(buf2, UVADDR_PRLEN, RJUST, "HANDLER"),
		mkstring(buf3, 16, CENTER, "MASK"),
		mkstring(buf4, VADDR_PRLEN, LJUST, "FLAGS"));

		if (VALID_MEMBER(task_struct_sighand)) {
			sighand_struct = ULONG(tt->task_struct +
	                        OFFSET(task_struct_sighand));
			readmem(sighand_struct, KVADDR, signal_buf,
				SIZE(sighand_struct), "sighand_struct buffer",
				FAULT_ON_ERROR);
			use_sighand = TRUE;
		} else
			use_sighand = FALSE;

		sigrtmax = sigrt_minmax(NULL, NULL);

	        for (i = 1; i <= sigrtmax; i++) {
			if (flags & TASK_INDENT)
				INDENT(2);

	                fprintf(fp, "%s[%d] ", i < 10 ? " " : "", i);
	
			if (use_sighand) {
				kaddr = sighand_struct + 
					OFFSET(sighand_struct_action) +
					((i-1) * SIZE(k_sigaction));
				uaddr = signal_buf + 
					OFFSET(sighand_struct_action) +
					((i-1) * SIZE(k_sigaction));
			} else {
				kaddr = signal_struct + 
					OFFSET(signal_struct_action) +
					((i-1) * SIZE(k_sigaction));
				uaddr = signal_buf + 
					OFFSET(signal_struct_action) +
					((i-1) * SIZE(k_sigaction));
			}
	
			handler = ULONG(uaddr + OFFSET(sigaction_sa_handler));
			switch ((long)handler)
			{
			case -1:
				mkstring(buf1, UVADDR_PRLEN, RJUST, "SIG_ERR");
				break;
			case 0:
				mkstring(buf1, UVADDR_PRLEN, RJUST, "SIG_DFL");
				break;
			case 1:
				mkstring(buf1, UVADDR_PRLEN, RJUST, "SIG_IGN");
				break;
			default:
				mkstring(buf1, UVADDR_PRLEN, RJUST|LONG_HEX,
	                                    MKSTR(handler));
				break;
			}
	
			mask = sigaction_mask((ulong)uaddr);
			sa_flags = ULONG(uaddr + OFFSET(sigaction_sa_flags));
	
			fprintf(fp, "%s%s %s %016llx %lx ",
				space(MINSPACE-1), 
				mkstring(buf2,
				UVADDR_PRLEN,LJUST|LONG_HEX,MKSTR(kaddr)),
				buf1,
				mask,
				sa_flags);
	
			if (sa_flags) {
				others = 0; translate = 1;
				if (sa_flags & SA_NOCLDSTOP)
					fprintf(fp, "%s%sSA_NOCLDSTOP",
						translate-- > 0 ? "(" : "",
						others++ ? "|" : "");
#ifdef SA_RESTORER
	                        if (sa_flags & SA_RESTORER)
	                                fprintf(fp, "%s%sSA_RESTORER",
	                                        translate-- > 0 ? "(" : "",
	                                        others++ ? "|" : "");
#endif
#ifdef SA_NOCLDWAIT
				if (sa_flags & SA_NOCLDWAIT)
					fprintf(fp, "%s%sSA_NOCLDWAIT", 
						translate-- > 0 ? "(" : "",
						others++ ? "|" : "");
#endif
				if (sa_flags & SA_SIGINFO)
					fprintf(fp, "%s%sSA_SIGINFO", 
						translate-- > 0 ? "(" : "",
						others++ ? "|" : "");
				if (sa_flags & SA_ONSTACK)
					fprintf(fp, "%s%sSA_ONSTACK", 
						translate-- > 0 ? "(" : "",
						others++ ? "|" : "");
				if (sa_flags & SA_RESTART)
					fprintf(fp, "%s%sSA_RESTART", 
						translate-- > 0 ? "(" : "",
						others++ ? "|" : "");
				if (sa_flags & SA_NODEFER)
					fprintf(fp, "%s%sSA_NODEFER", 
						translate-- > 0 ? "(" : "",
						others++ ? "|" : "");
				if (sa_flags & SA_RESETHAND)
					fprintf(fp, "%s%sSA_RESETHAND", 
						translate-- > 0 ? "(" : "",
						others++ ? "|" : "");
				if (translate < 1)
	                		fprintf(fp, ")");
			}
	
	                fprintf(fp, "\n");
	        }
	}
	
	if (flags & TASK_LEVEL) {
		/*
	 	* Pending signals (task level).
		*/
		if (VALID_MEMBER(task_struct_sigpending))
			sigpending = INT(tt->task_struct + 
				OFFSET(task_struct_sigpending));
		else if (VALID_MEMBER(thread_info_flags)) {
			fill_thread_info(tc->thread_info);
			ti_flags = UINT(tt->thread_info + OFFSET(thread_info_flags));
			sigpending = ti_flags & (1<<TIF_SIGPENDING);
		}
		if (flags & TASK_INDENT)
			INDENT(2);
		fprintf(fp, "SIGPENDING: %s\n", sigpending ? "yes" : "no");

		/*
	 	*  Blocked signals (task level).
	 	*/

		blocked = task_blocked(tc->task);
		if (flags & TASK_INDENT)
			INDENT(2);
		fprintf(fp, "   BLOCKED: %016llx\n", blocked);
		
		/*
	 	*  Pending queue (task level).
	 	*/
	
		if (flags & TASK_INDENT)
			INDENT(2);
		if (VALID_MEMBER(signal_struct_shared_pending)) {
			fprintf(fp, "PRIVATE_PENDING\n");
			if (flags & TASK_INDENT)
				INDENT(2);
		}
		fprintf(fp, "    SIGNAL: %016llx\n", sigset);

		if (VALID_MEMBER(task_struct_sigqueue)) 
			sigqueue = ULONG(tt->task_struct + 
				OFFSET(task_struct_sigqueue));
	
		else if (VALID_MEMBER(task_struct_pending)) 
			sigqueue = ULONG(tt->task_struct +
				OFFSET(task_struct_pending) +
				OFFSET_OPTION(sigpending_head, 
				sigpending_list));
	
		if (VALID_MEMBER(sigqueue_list) && empty_list(sigqueue))
			sigqueue = 0;

		if (flags & TASK_INDENT)
			INDENT(2);
		if (sigqueue) {
                	fprintf(fp, "  SIGQUEUE:  SIG  %s\n",
                        	mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "SIGINFO"));
		 	sigqueue_list(sigqueue);
		} else
                	fprintf(fp, "  SIGQUEUE: (empty)\n");
	}

	/*
	 *  Pending queue (thread group level).
	 */
	if ((flags & THREAD_GROUP_LEVEL) &&
	    VALID_MEMBER(signal_struct_shared_pending)) {

		fprintf(fp, "SHARED_PENDING\n");
		shared_pending = signal_struct + OFFSET(signal_struct_shared_pending);
		signal = shared_pending + OFFSET(sigpending_signal);
		readmem(signal, KVADDR, signal_buf,SIZE(sigpending_signal),
			"signal", FAULT_ON_ERROR);
		sigset = task_signal(0, (ulong*)signal_buf);
		if (flags & TASK_INDENT)
			INDENT(2);
		fprintf(fp, "    SIGNAL: %016llx\n", sigset);
                sigqueue = (shared_pending + 
			OFFSET_OPTION(sigpending_head, sigpending_list) + 
			OFFSET(list_head_next));
		readmem(sigqueue,KVADDR, signal_buf,
			SIZE(sigqueue), "sigqueue", FAULT_ON_ERROR);
		sigqueue = ULONG(signal_buf);

		if (VALID_MEMBER(sigqueue_list) && empty_list(sigqueue))
			sigqueue = 0;
		if (flags & TASK_INDENT)
			INDENT(2);
		if (sigqueue) {
               		fprintf(fp, "  SIGQUEUE:  SIG  %s\n",
                       		mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "SIGINFO"));
			 sigqueue_list(sigqueue);
		} else
               		fprintf(fp, "  SIGQUEUE: (empty)\n");
	}
	FREEBUF(signal_buf);
}

/*
 *  Dump a pending signal queue (private/shared).
 */

static void sigqueue_list(ulong sigqueue) {
        ulong sigqueue_save, next;
	int sig;
	char *signal_buf;
	long size;
        size = VALID_SIZE(signal_queue) ?  SIZE(signal_queue) : SIZE(sigqueue);
        signal_buf = GETBUF(size);

        sigqueue_save = sigqueue;
        while (sigqueue) {
        	readmem(sigqueue, KVADDR, signal_buf, 
			SIZE_OPTION(signal_queue, sigqueue), 
			"signal_queue/sigqueue", FAULT_ON_ERROR);

		if (VALID_MEMBER(signal_queue_next) && 
		    VALID_MEMBER(signal_queue_info)) {
                	next = ULONG(signal_buf + OFFSET(signal_queue_next));
                	sig = INT(signal_buf + OFFSET(signal_queue_info) +
				 OFFSET(siginfo_si_signo));
		} else {
			next = ULONG(signal_buf +
                        	OFFSET_OPTION(sigqueue_next, sigqueue_list));
                	sig = INT(signal_buf + OFFSET(sigqueue_info) + 
				OFFSET(siginfo_si_signo));
		}

		if (sigqueue_save == next)
			break;

                fprintf(fp, "             %3d  %lx\n",
                        sig, sigqueue +
			OFFSET_OPTION(signal_queue_info, sigqueue_info));

                sigqueue = next;
        }
	FREEBUF(signal_buf);

}

/*
 *  Return the current set of signals sent to a task, in the form of 
 *  a long long data type form that can be easily masked regardless
 *  of its size.
 */

static ulonglong 
task_signal(ulong task, ulong *signal)
{
	ulonglong sigset;
	ulong *sigset_ptr;

	if (task) {
        	fill_task_struct(task);

	if (!tt->last_task_read) 
		return 0;

        if (VALID_MEMBER(sigpending_signal)) {
                sigset_ptr = (ulong *)(tt->task_struct +
                        OFFSET(task_struct_pending) +
                        OFFSET(sigpending_signal));
	} else if (VALID_MEMBER(task_struct_signal)) {
                sigset_ptr = (ulong *)(tt->task_struct +
                        OFFSET(task_struct_signal));
        } else
		return 0;
	} else if (signal) {
		sigset_ptr = signal;
	} else
		return 0;

	switch (_NSIG_WORDS)
	{
	case 1:
		sigset = (ulonglong)sigset_ptr[0];
		break;

	case 2:
		sigset = (ulonglong)(sigset_ptr[1]) << 32;
		sigset |= (ulonglong)(sigset_ptr[0]);
		break;
	}

	return sigset;
}

/*
 *  Return the current set of signals that a task has blocked, in the form
 *  of a long long data type form that can be easily masked regardless
 *  of its size.
 */

static ulonglong
task_blocked(ulong task)
{
        ulonglong sigset;
        ulong *sigset_ptr;

        fill_task_struct(task);

        if (!tt->last_task_read)
                return 0;

        sigset_ptr = (ulong *)(tt->task_struct + OFFSET(task_struct_blocked));

        sigset = (ulonglong)(sigset_ptr[1]) << 32;
        sigset |= (ulonglong)(sigset_ptr[0]);

	return sigset;
}

static ulonglong
sigaction_mask(ulong sigaction)
{
        ulonglong sigset;
        ulong *sigset_ptr;

	sigset_ptr = (ulong *)(sigaction + OFFSET(sigaction_sa_mask));

        switch (_NSIG_WORDS)
        {
        case 1:
                sigset = (ulonglong)sigset_ptr[0];
                break;

        case 2:
                sigset = (ulonglong)(sigset_ptr[1]) << 32;
                sigset |= (ulonglong)(sigset_ptr[0]);
                break;
        }

        return sigset;
}

/*
 *  Deal with potential separation of task_struct and kernel stack.
 */
ulong 
generic_get_stackbase(ulong task)
{
	return task_to_stackbase(task);
}

ulong
generic_get_stacktop(ulong task)
{
        return task_to_stackbase(task) + STACKSIZE();
}


