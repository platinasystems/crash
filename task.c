/* task.c - core analysis suite
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
 * 11/09/99, 1.0    Initial Release
 * 11/12/99, 1.0-1  Bug fixes
 * 12/10/99, 1.1    Fixes, new commands, support for v1 SGI dumps
 * 01/18/00, 2.0    Initial gdb merger, support for Alpha
 * 02/01/00, 2.1    Bug fixes, new commands, options, support for v2 SGI dumps
 * 02/29/00, 2.2    Bug fixes, new commands, options
 * 04/11/00, 2.3    Bug fixes, new command, options, initial PowerPC framework
 * 04/12/00  ---    Transition to BitKeeper version control
 * 
 * BitKeeper ID: @(#)task.c 1.12
 *
 * 09/28/00  ---    Transition to CVS version control
 *
 * CVS: $Revision: 1.73 $ $Date: 2002/02/18 18:39:35 $
 */

#include "defs.h"

static ulong get_panic_context(void);
static void show_ps(ulong, struct psinfo *);
static struct task_context *panic_search(void);
static ulong highest_pid(void);
static void refresh_fixed_task_table(void);
static void refresh_unlimited_task_table(void); 
static void refresh_active_task_table(void);
static void refresh_context(ulong, ulong);
static void parent_list(ulong);
static void child_list(ulong);
static void show_task_times(struct task_context *, ulong);
static int compare_start_time(const void *, const void *);
static void populate_panic_threads(void);
static int verify_task(struct task_context *);
static void dump_runq(void);
static void task_struct_member(struct task_context *,ulong,struct reference *);
static void signal_reference(struct task_context *, ulong, struct reference *);
static void dump_signal_data(struct task_context *);
static void signame_list(void);
static ulonglong task_signal(ulong);
static ulonglong task_blocked(ulong);
static void translate_sigset(ulonglong);
static ulonglong sigaction_mask(ulong);
static int task_has_cpu(ulong, char *);
static int is_foreach_keyword(char *, int *);
static char *task_pointer_string(struct task_context *, ulong, char *);


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
        struct syment *nsp;
	long tss_offset, thread_offset; 
	long eip_offset, esp_offset, ksp_offset;
	ulong active_pid;

        if (symbol_exists("nr_tasks")) {
		/*
		 *  Figure out what maximum NR_TASKS would be by getting the 
		 *  address of the next symbol after "task".
		 */
	        tt->task_start = symbol_value("task");
	        if ((nsp = next_symbol("task", NULL)) == NULL)
	        	error(FATAL, "cannot determine size of task table\n");

		tt->flags |= TASK_ARRAY_EXISTS;
	
		tt->task_end = nsp->value;
	        tt->nr_tasks = (tt->task_end - tt->task_start) / sizeof(void *);
	
	        if ((tt->task_local = (void *)
		    malloc(tt->nr_tasks * sizeof(void *))) == NULL)
	        	error(FATAL, 
			    "cannot malloc kernel task array (%d tasks)",
				tt->nr_tasks);
	
		if ((tt->context_array = (struct task_context *)
		    malloc(tt->nr_tasks * sizeof(struct task_context))) == NULL)
			error(FATAL, "cannot malloc context array (%d tasks)",
				tt->nr_tasks);
	
		OFFSET(task_struct_tss) = tss_offset = 
			MEMBER_OFFSET("task_struct", "tss");
		eip_offset = MEMBER_OFFSET("thread_struct", "eip");
		esp_offset = MEMBER_OFFSET("thread_struct", "esp");
		ksp_offset = MEMBER_OFFSET("thread_struct", "ksp");
	        OFFSET(task_struct_tss_eip) = (eip_offset == INVALID_MEMBER) ? 
			INVALID_MEMBER : tss_offset + eip_offset;
	        OFFSET(task_struct_tss_esp) = (esp_offset == INVALID_MEMBER) ?
			INVALID_MEMBER : tss_offset + esp_offset;
                OFFSET(task_struct_tss_ksp) = (ksp_offset == INVALID_MEMBER) ?
                        INVALID_MEMBER : tss_offset + ksp_offset;

		tt->flags |= TASK_REFRESH;
		tt->refresh_task_table = refresh_fixed_task_table;

		if (ACTIVE() && symbol_exists("pidhash")) {
        		tt->pidhash_len = get_array_length("pidhash", NULL);
        		tt->pidhash_addr = symbol_value("pidhash");

			OFFSET(task_struct_pidhash_next) =
				MEMBER_OFFSET("task_struct", "pidhash_next");

			tt->refresh_task_table = refresh_active_task_table; 
		} 

                readmem(tt->task_start, KVADDR, &tt->idle_threads[0],
                	kt->cpus * sizeof(void *), "idle threads",
                        FAULT_ON_ERROR);

	} else {
		/*
		 *  Make the task table big enough to hold what's running.
		 *  It can be realloc'd later if it grows on a live system.
	         */
	        get_symbol_data("nr_threads", sizeof(int), &tt->nr_threads);
		tt->nr_tasks = tt->nr_threads + NR_CPUS + TASK_SLUSH; 
	
	        if ((tt->task_local = (void *)
	            malloc(tt->nr_tasks * sizeof(void *))) == NULL)
	                error(FATAL, 
			    "cannot malloc kernel task array (%d tasks)",
	                        tt->nr_tasks);
	
		if ((tt->context_array = (struct task_context *)
		    malloc(tt->nr_tasks * sizeof(struct task_context))) == NULL)
			error(FATAL, "cannot malloc context array (%d tasks)",
				tt->nr_tasks);
	
		OFFSET(task_struct_thread) = thread_offset = 
			MEMBER_OFFSET("task_struct", "thread");
		eip_offset = MEMBER_OFFSET("thread_struct", "eip");
		esp_offset = MEMBER_OFFSET("thread_struct", "esp");
		ksp_offset = MEMBER_OFFSET("thread_struct", "ksp");
	        OFFSET(task_struct_thread_eip) = 
		    (eip_offset == INVALID_MEMBER) ? 
			INVALID_MEMBER : thread_offset + eip_offset;
	        OFFSET(task_struct_thread_esp) = 
		    (esp_offset == INVALID_MEMBER) ?
			INVALID_MEMBER : thread_offset + esp_offset;
	        OFFSET(task_struct_thread_ksp) = 
		    (ksp_offset == INVALID_MEMBER) ?
			INVALID_MEMBER : thread_offset + ksp_offset;
	
		tt->flags |= TASK_REFRESH;
		tt->refresh_task_table = refresh_unlimited_task_table;

                if (ACTIVE() && symbol_exists("pidhash")) {
                        tt->pidhash_len = get_array_length("pidhash", NULL);
                        tt->pidhash_addr = symbol_value("pidhash");

                        OFFSET(task_struct_pidhash_next) =
                                MEMBER_OFFSET("task_struct", "pidhash_next");

			tt->refresh_task_table = refresh_active_task_table;
		} 

                readmem(symbol_value("init_tasks"), KVADDR,
                	&tt->idle_threads[0], sizeof(void *) * kt->cpus, 
			"init_tasks array", FAULT_ON_ERROR);
	}

        OFFSET(task_struct_state) = MEMBER_OFFSET("task_struct", "state");
        OFFSET(task_struct_pid) = MEMBER_OFFSET("task_struct", "pid");
        OFFSET(task_struct_comm) = MEMBER_OFFSET("task_struct", "comm");
        OFFSET(task_struct_next_task) = MEMBER_OFFSET("task_struct",
        	"next_task");
        OFFSET(task_struct_processor) = MEMBER_OFFSET("task_struct", 
		"processor");
        OFFSET(task_struct_p_pptr) = MEMBER_OFFSET("task_struct", "p_pptr");
        OFFSET(task_struct_has_cpu) = MEMBER_OFFSET("task_struct", "has_cpu");
        OFFSET(task_struct_cpus_runnable) = 
		MEMBER_OFFSET("task_struct", "cpus_runnable");
	OFFSET(task_struct_active_mm) = 
		MEMBER_OFFSET("task_struct", "active_mm");
	OFFSET(task_struct_next_run) =
		MEMBER_OFFSET("task_struct", "next_run");
	OFFSET(task_struct_flags) = MEMBER_OFFSET("task_struct", "flags");

	SIZE(task_struct) = STRUCT_SIZE("task_struct");

        if ((tt->task_struct = (char *)malloc(SIZE(task_struct))) == NULL)
        	error(FATAL, "cannot malloc task_struct space.");

        if ((tt->mm_struct = (char *)malloc(SIZE(mm_struct))) == NULL)
        	error(FATAL, "cannot malloc mm_struct space.");

	if (symbol_exists("current_set")) 
	        if (!readmem(symbol_value("current_set"), KVADDR, 
		     tt->current_set, kt->cpus * sizeof(ulong), 
		     "current_set array", RETURN_ON_ERROR))
		     	error(FATAL, "cannot read kernel current_set array");

	if ((len = STRUCT_SIZE("task_union")) != STACKSIZE()) { 
		error(WARNING, "\nnon-standard stack size: %ld\n", len);
		machdep->stacksize = len;
	}

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

	tt->flags |= TASK_INIT_DONE;
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
	pid_t *pid_addr;
	char *comm_addr;
	int *processor_addr;
	ulong *p_pptr_addr;
	ulong *mm_addr;
	int has_cpu;
	ulong curtask;
	ulong retries;
	ulong curpid;
	int populate_panic;
	char *tp;

#define TASK_FREE(x)   ((x == 0) || (((ulong)(x) >= tt->task_start) && \
                       ((ulong)(x) < tt->task_end)))
#define TASK_IN_USE(x) (!TASK_FREE(x))

	if (DUMPFILE() && (tt->flags & TASK_INIT_DONE))
		return;

	if (DUMPFILE()) {
        	fprintf(fp, (pc->flags & SILENT) || !(pc->flags & TTY) ?
                        "" : "%splease wait... (gathering task table data)",
			"\n");
		fflush(fp);
		populate_panic = !symbol_exists("panic_threads");
	} else
		populate_panic = FALSE;

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
            tt->nr_tasks * sizeof(void *), "kernel task array", 
	    RETURN_ON_ERROR))
        	error(FATAL, "cannot read kernel task array");

	clear_task_cache();

        for (i = 0, tlp = (ulong *)tt->task_local, 
	     tt->running_tasks = 0, tc = tt->context_array;
             i < tt->nr_tasks; i++, tlp++) {
                if (TASK_IN_USE(*tlp)) {

                	if (!(tp = fill_task_struct(*tlp))) {
                        	if (DUMPFILE())
                                	continue;
                        	retries++;
                        	goto retry;
                	}

                 	pid_addr = (pid_t *)(tp + OFFSET(task_struct_pid));
                	comm_addr = (char *)(tp + OFFSET(task_struct_comm));
                	processor_addr = (int *)
				(tp + OFFSET(task_struct_processor));
                	p_pptr_addr = (ulong *)
				(tp + OFFSET(task_struct_p_pptr));
                	mm_addr = (ulong *)(tp + OFFSET(task_struct_mm));
			has_cpu = task_has_cpu(NO_TASK, tp);

                	tc->pid = (ulong)(*pid_addr);
                	BCOPY(comm_addr, &tc->comm[0], 16);
                	tc->comm[16] = NULLCHAR;
                	tc->processor = *processor_addr;
                	tc->ptask = *p_pptr_addr;
                	tc->mm_struct = *mm_addr;
                	tc->task = *tlp;
			if (!verify_task(tc)) {
				BZERO(tc, sizeof(struct task_context));
				continue;
			}
			if (populate_panic && has_cpu) 
				tt->panic_threads[tc->processor] = tc->task;
			tc->tc_next = NULL;
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
 *  Verify that a task_context's data makes sense enough to include
 *  in the task_context array.
 */
static int
verify_task(struct task_context *tc)
{
	ulong next_task;
	ulong readflag;

        readflag = ACTIVE() ? (RETURN_ON_ERROR|QUIET) : (RETURN_ON_ERROR);

        if (!readmem(tc->task + OFFSET(task_struct_next_task),
	    KVADDR, &next_task, sizeof(void *), "next_task", readflag)) {
		return FALSE;
        }
	if (!IS_TASK_ADDR(next_task))
		return FALSE;

	if (tc->processor & ~NO_PROC_ID)
		return FALSE;

        if ((tc->processor < 0) || (tc->processor >= NR_CPUS))
		return FALSE;

	if (!IS_TASK_ADDR(tc->ptask))
		return FALSE;

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
	pid_t *pid_addr;
	char *comm_addr;
	int *processor_addr;
	ulong *p_pptr_addr;
	ulong *mm_addr;
	int has_cpu;
	ulong curtask;
	ulong curpid;
	struct list_data list_data, *ld;
	ulong init_tasks[NR_CPUS];
	ulong retries;
	char *tp;
	int populate_panic, cnt;

	if (DUMPFILE() && (tt->flags & TASK_INIT_DONE))
		return;

        if (DUMPFILE()) {
                fprintf(fp, (pc->flags & SILENT) || !(pc->flags & TTY) ?
                        "" : "%splease wait... (gathering task table data)",
                        "\n");
                fflush(fp);
		populate_panic = !symbol_exists("panic_threads");
        } else
		populate_panic = FALSE;



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
	if (retries && DUMPFILE())
		error(FATAL, "cannot gather a stable task list\n");

	if ((retries == MAX_UNLIMITED_TASK_RETRIES) &&  
	    !(tt->flags & TASK_INIT_DONE)) 
		error(FATAL, "cannot gather a stable task list\n");

	/*
	 *  Populate the task_local array with a quick walk-through.
 	 *  If there's not enough room in the local array, realloc() it.
	 */
	ld = &list_data;
	BZERO(ld, sizeof(struct list_data));
	ld->start = symbol_value("init_task_union");
	ld->member_offset = OFFSET(task_struct_next_task);

	if (!hq_open()) {
		error(INFO, "cannot hash task_struct entries\n");
		if (!(tt->flags & TASK_INIT_DONE))
			exit(1);
		error(INFO, "using stale task_structs\n");
		FREEBUF(tp);
		return;
	}

	cnt = do_list(ld);

	if ((cnt+NR_CPUS) > tt->nr_tasks) {
		tt->nr_tasks = cnt + NR_CPUS + TASK_SLUSH;

        	if ((tt->task_local = (void *)
            		realloc(tt->task_local,
			    tt->nr_tasks * sizeof(void *))) == NULL) {
			    	error(FATAL,
				  "cannot realloc kernel task array (%d tasks)",
                        		tt->nr_tasks);
		}
        	if ((tt->context_array = (struct task_context *)
            		realloc(tt->context_array,
			    tt->nr_tasks * sizeof(struct task_context))) 
			    == NULL) {
                		error(FATAL, 
				    "cannot realloc context array (%d tasks)",
                        		tt->nr_tasks);
		}

		hq_close();
		retries++;
		goto retry;
	}

	BZERO(tt->task_local, tt->nr_tasks * sizeof(void *));
	cnt = retrieve_list((ulong *)tt->task_local, cnt);
	hq_close();

	tlp = (ulong *)tt->task_local;
	tlp += cnt;

	/*
	 *  If SMP, add in the other idle tasks.
	 */
	if (SMP()) {   
        	/*
         	 *  Now get the rest of the init_task[] entries, starting
		 *  at offset 1 since we've got the init_task already.
         	 */
        	readmem(symbol_value("init_tasks"), KVADDR, init_tasks,
                	sizeof(void *) * NR_CPUS, "init_tasks array",
                	FAULT_ON_ERROR);

		for (i = 1; i < NR_CPUS; i++) {
			if (init_tasks[i]) {
				*tlp = init_tasks[i];
				tlp++;
			}
	 	}
	}

	clear_task_cache();

        for (i = 0, tlp = (ulong *)tt->task_local, 
             tt->running_tasks = 0, tc = tt->context_array;
             i < tt->nr_tasks; i++, tlp++) {
		if (!(*tlp))
			continue;

		if (!IS_TASK_ADDR(*tlp)) {
			retries++;
			goto retry;
		}	
	
		if (task_exists(*tlp)) {
			retries++;
			goto retry;
		}

                if (!(tp = fill_task_struct(*tlp))) {
                     	if (DUMPFILE())
                        	continue;
                        retries++;
                        goto retry;
                }

                pid_addr = (pid_t *)(tp + OFFSET(task_struct_pid));
                comm_addr = (char *)(tp + OFFSET(task_struct_comm));
                processor_addr = (int *)(tp + OFFSET(task_struct_processor));
                p_pptr_addr = (ulong *)(tp + OFFSET(task_struct_p_pptr));
                mm_addr = (ulong *)(tp + OFFSET(task_struct_mm));
		has_cpu = task_has_cpu(NO_TASK, tp);

                tc->pid = (ulong)(*pid_addr);
                BCOPY(comm_addr, &tc->comm[0], 16);
                tc->comm[16] = NULLCHAR;
                tc->processor = *processor_addr;
                tc->ptask = *p_pptr_addr;
                tc->mm_struct = *mm_addr;
                tc->task = *tlp;
		if (populate_panic && has_cpu) 
			tt->panic_threads[tc->processor] = tc->task;
                tc->tc_next = NULL;
                tc++;
                tt->running_tasks++;
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
 *  The following manner of refreshing the task table is used for all
 *  ACTIVE() kernels that have a pidhash[] array, whether or not they still 
 *  have a fixed task[] array or an unlimited list.
 */
static void
refresh_active_task_table(void)
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
        pid_t *pid_addr;
        char *comm_addr;
        int *processor_addr;
        ulong *p_pptr_addr;
	ulong *mm_addr;

        if (DUMPFILE() && (tt->flags & TASK_INIT_DONE))   /* impossible */
                return;

        if (DUMPFILE()) {                                 /* impossible */
                fprintf(fp, (pc->flags & SILENT) || !(pc->flags & TTY) ?
                        "" : "\rplease wait... (gathering task table data)");
                fflush(fp);
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
		error(FATAL, "cannot gather a stable task list via pidhash\n");

        if ((retries == MAX_UNLIMITED_TASK_RETRIES) &&
            !(tt->flags & TASK_INIT_DONE)) 
                error(FATAL, 
	          "cannot gather a stable task list via pidhash (%d retries)\n",
			retries);

        if (!readmem(tt->pidhash_addr, KVADDR, pidhash, 
	    len * sizeof(ulong), "pidhash contents", RETURN_ON_ERROR)) 
		error(FATAL, "cannot read pidhash array\n");

	hq_open();

	/*
	 *  Get the idle threads first. 
	 */
	cnt = 0;
	for (i = 0; i < kt->cpus; i++) {
		if (!hq_enter(tt->idle_threads[i]))
			error(FATAL, "duplicate idle tasks?\n");
		cnt++;
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
                        if (!readmem(next + OFFSET(task_struct_pidhash_next),
                            KVADDR, &pnext, sizeof(void *),
                            "pidhash_next entry", RETURN_ON_ERROR)) {
                                hq_close();
                                goto retry_pidhash;
                        }

                        if (!IS_TASK_ADDR(next))
                                break;

			if (!hq_enter(next)) {
				hq_close();
				goto retry_pidhash;
			}

			next = pnext;

			cnt++;
		}
	}

        if (cnt > tt->nr_tasks) {
                tt->nr_tasks = cnt + NR_CPUS + TASK_SLUSH;

                if ((tt->task_local = (void *)
                        realloc(tt->task_local,
                            tt->nr_tasks * sizeof(void *))) == NULL) {
                                error(INFO,
                                  "cannot realloc kernel task array (%d tasks)",
                                        tt->nr_tasks);
                        exit(1);
                }
                if ((tt->context_array = (struct task_context *)
                        realloc(tt->context_array,
                            tt->nr_tasks * sizeof(struct task_context)))
                            == NULL) {
                                error(INFO,
                                    "cannot realloc context array (%d tasks)",
                                        tt->nr_tasks);
                        exit(1);
                }

                hq_close();
                retries++;
                goto retry_pidhash;
        }

        BZERO(tt->task_local, tt->nr_tasks * sizeof(void *));
        cnt = retrieve_list((ulong *)tt->task_local, cnt);

	hq_close();

	clear_task_cache();

        for (i = 0, tlp = (ulong *)tt->task_local, 
             tt->running_tasks = 0, tc = tt->context_array;
             i < tt->nr_tasks; i++, tlp++) {
		if (!(*tlp))
			continue;

		if (!IS_TASK_ADDR(*tlp)) {
			retries++;
			goto retry_pidhash;
		}	
	
		if (task_exists(*tlp)) {
			retries++;
			goto retry_pidhash;
		}

		if (!(tp = fill_task_struct(*tlp))) {
                        if (DUMPFILE())
                                continue;
                        retries++;
                        goto retry_pidhash;
                }

                pid_addr = (pid_t *)(tp + OFFSET(task_struct_pid));
                comm_addr = (char *)(tp + OFFSET(task_struct_comm));
		processor_addr = (int *)(tp + OFFSET(task_struct_processor));
		p_pptr_addr = (ulong *)(tp + OFFSET(task_struct_p_pptr));
		mm_addr = (ulong *)(tp + OFFSET(task_struct_mm));

		tc->pid = (ulong)(*pid_addr);
		BCOPY(comm_addr, &tc->comm[0], 16);
                tc->comm[16] = NULLCHAR;
		tc->processor = *processor_addr;
		tc->ptask = *p_pptr_addr;
		tc->mm_struct = *mm_addr;
		tc->task = *tlp;
		tc->tc_next = NULL;
		tc++;
		tt->running_tasks++;
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
                        show_context(CURRENT_CONTEXT(), 0, FALSE);
			fprintf(fp, "\n");
                }
        }
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
 *  Used by back_trace(), copy the complete kernel stack into a local buffer
 *  and fill the task_struct buffer, dealing with future separation of
 *  task_struct and stack and cache coloring of stack top.
 */
void
fill_stackbuf(struct bt_info *bt)
{
	bt->stackbuf = GETBUF(bt->stacktop - bt->stackbase);

        if (!readmem(bt->stackbase, KVADDR, bt->stackbuf, 
	    bt->stacktop - bt->stackbase, "stack contents", RETURN_ON_ERROR))
                error(FATAL, "read of stack at %lx failed\n", bt->stackbase);

	if (bt->stackbase == bt->task) {
		BCOPY(bt->stackbuf, tt->task_struct, SIZE(task_struct));
		tt->last_task_read = bt->task;
	} else
		fill_task_struct(bt->task);
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

        while ((c = getopt(argcnt, args, "stcpku")) != EOF) {
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
		 *  The remaining flags are all mutually-exclusive.
		 */
		case 't':
			flag |= PS_TIMES;
			flag &= ~(PS_CHILD_LIST|PS_PPID_LIST);
			break;

		case 'c': 
			flag |= PS_CHILD_LIST;
			flag &= ~(PS_PPID_LIST|PS_TIMES);
			break;

		case 'p':
			flag |= PS_PPID_LIST;
			flag &= ~(PS_CHILD_LIST|PS_TIMES);
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
        fprintf(fp, "%5ld ", (tm->total_vm * PAGESIZE())/1024);       \
        fprintf(fp, "%5ld  ", (tm->rss * PAGESIZE())/1024);           \
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
	ulong pid, maxpid;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];

	if (!(flag & (PS_PPID_LIST|PS_CHILD_LIST|PS_TIMES))) 
		fprintf(fp, 
		    "   PID    PPID  CPU %s  ST  %%MEM   VSZ   RSS  COMM\n",
			flag & PS_KSTACKP ?
			mkstring(buf1, VADDR_PRLEN, CENTER|RJUST, "KSTACKP") :
			mkstring(buf1, VADDR_PRLEN, CENTER, "TASK"));

	if (flag & PS_SHOW_ALL) {
		tm = &task_mem_usage;

		if (flag & PS_TIMES) {
			show_task_times(NULL, flag);
			return;
		}

		for (pid = 0, maxpid = highest_pid(); pid <= maxpid; pid++) {
			if (!pid_exists(pid))
				continue;
			for (tc = pid_to_context(pid); tc; tc = tc->tc_next) {
				SHOW_PS_DATA();
			}
		}
		return;
	}

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
				if (STREQ(tc->comm, psi->comm[ac]))
					print = TRUE;
				break;
			}

			if (print) {
				if (flag & PS_TIMES) 
					show_task_times(tc, flag);
				else {
					SHOW_PS_DATA();
				}
			}
		}
	}
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

	if (do_kstackp) {
		bt = &bt_info;
                BZERO(bt, sizeof(struct bt_info));;
                bt->task = tc->task;
                bt->tc = tc;
                bt->stackbase = GET_STACKBASE(tc->task);
                bt->stacktop = GET_STACKTOP(tc->task);
		bt->flags |= BT_KSTACKP;
		back_trace(bt);
		if (bt->stkptr)
			sprintf(buf, "%lx", bt->stkptr);
		else
			sprintf(buf, "%s",
			    mkstring(buf, VADDR_PRLEN, CENTER|RJUST, "--"));
	}
	else 
		sprintf(buf, "%lx", tc->task);

	return buf;
}


/*
 *  Dump the task list ordered by start_time.
 */
struct task_start_time {
	struct task_context *tc;
        ulong start_time;
	ulong tms_utime;
	ulong tms_stime;
};

static void
show_task_times(struct task_context *tcp, ulong flags)
{
	int i, tasks;
	struct task_context *tc;
	struct task_start_time *task_start_times, *tsp;
	ulong jiffies;
	char buf1[BUFSIZE];

	if (INVALID_OFFSET(task_struct_start_time)) {
        	OFFSET(task_struct_start_time) = MEMBER_OFFSET("task_struct",
                	"start_time");
        	OFFSET(task_struct_times) = MEMBER_OFFSET("task_struct",
                	"times");
        	OFFSET(tms_tms_utime) = MEMBER_OFFSET("tms", "tms_utime");
        	OFFSET(tms_tms_stime) = MEMBER_OFFSET("tms", "tms_stime");
	}

	task_start_times = (struct task_start_time *)
		GETBUF(RUNNING_TASKS() * sizeof(struct task_start_time));
 
        get_symbol_data("jiffies", sizeof(long), &jiffies);
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
		tsp->start_time = ULONG(tt->task_struct +
			OFFSET(task_struct_start_time));
		tsp->tms_utime = ULONG(tt->task_struct +
                        OFFSET(task_struct_times) +
			OFFSET(tms_tms_utime));
                tsp->tms_stime = ULONG(tt->task_struct +
                        OFFSET(task_struct_times) +
                        OFFSET(tms_tms_stime));

		tasks++;
		tsp++;

		if (tcp)
			break;
	}

	qsort((void *)task_start_times, (size_t)tasks, 
		sizeof(struct task_start_time), compare_start_time);

        for (i = 0, tsp = task_start_times; i < tasks; i++, tsp++) {
		print_task_header(fp, tsp->tc, 0);
		fprintf(fp, "    RUN TIME: %s\n", 
			convert_time(jiffies - tsp->start_time, buf1));
		fprintf(fp, "  START TIME: %ld\n", tsp->start_time); 
		fprintf(fp, "   USER TIME: %ld\n", tsp->tms_utime);
		fprintf(fp, " SYSTEM TIME: %ld\n\n", tsp->tms_stime);
	}
	FREEBUF(task_start_times);
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
        ld->member_offset = OFFSET(task_struct_p_pptr);
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

static ulong
highest_pid(void)
{
        int i;
        struct task_context *tc;
	ulong pid;

        tc = FIRST_CONTEXT();
        for (i = 0, pid = 0; i < RUNNING_TASKS(); i++, tc++)
                if (tc->pid > pid)
                        pid = tc->pid;

        return pid;
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
 *  Display a task context.
 */

void
show_context(struct task_context *tc, int indent, int inittime)
{
	char buf[BUFSIZE];
	char *p1;
	int cnt;
	struct task_context *tcp;

	INDENT(indent);
	fprintf(fp, "    PID: %ld\n", tc->pid);
	INDENT(indent);
	fprintf(fp, "COMMAND: \"%s\"\n", tc->comm);
	INDENT(indent);
	fprintf(fp, "   TASK: %lx  ", tc->task);
	if ((cnt = TASKS_PER_PID(tc->pid)) > 1)
		fprintf(fp, "(1 of %d)", cnt);
	fprintf(fp, "\n");
	INDENT(indent);
	fprintf(fp, "    CPU: %s\n", task_cpu(tc->processor, buf, VERBOSE));
	INDENT(indent);
	fprintf(fp, "  STATE: %s ", 
		task_state_string(tc->task, buf, VERBOSE));
	if (is_task_active(tc->task)) {
		if (machdep->flags & HWRESET)
			fprintf(fp, "(HARDWARE RESET)");
		else if (machdep->flags & SYSRQ)
			fprintf(fp, "(SYSRQ)");
		else if (tc->task == tt->panic_task)
			fprintf(fp, "(PANIC)");
		else
			fprintf(fp, "(ACTIVE)");
	}

	if (inittime && (tt->flags & PANIC_TASK_NOT_FOUND)) {
		fprintf(fp, "\n"); INDENT(indent);
		fprintf(fp, "WARNING: reported panic task %lx not found", 
			tt->panic_threads[tt->panic_processor]);
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
 "%sNOTE: To save the temporary remote \"%s\" locally, enter \"save kernel\"\n",
			cnt++ ? "" : "\n", buf);
	}

	if (pc->flags & (REM_MCLXCD|REM_LKCD|REM_S390D|REM_S390XD))
		fprintf(fp, 
         "%sNOTE: To save the remote \"%s\" locally, enter \"save dumpfile\"\n",
			cnt++ ? "" : "\n", 
			basename(pc->server_memsrc));

	if (DUMPFILE() && (tcp = task_to_context(tt->panic_task))) {
		if ((tc->pid == 0) &&
		     STRNEQ(tc->comm, pc->program_name) &&
		     strstr(get_panicmsg(buf), 
		     "Attempted to kill the idle task")) {
                	fprintf(fp,
                 "%sWARNING: The %s context will erroneously show a PID of 0\n",
                        	cnt++ ? "" : "\n", tc->comm);

		}
	}
}

/*
 *  Translate a task_struct state value into a long (verbose), or short string,
 *  or if requested, just pass back the state value.
 */

char *
task_state_string(ulong task, char *buf, int verbose)
{
	long state;
	int exclusive;
	int valid;

	if (buf)
		sprintf(buf, verbose ? "(unknown)" : "??");

	state = task_state(task);

	valid = 0;
	exclusive = state & TASK_EXCLUSIVE;
	state &= ~TASK_EXCLUSIVE;

	if (state == TASK_RUNNING) 
		sprintf(buf, verbose ? "TASK_RUNNING" : "RU", valid++);
	else if (state == TASK_INTERRUPTIBLE) 
		sprintf(buf, verbose ? "TASK_INTERRUPTIBLE" : "IN", valid++);
	else if (state == TASK_UNINTERRUPTIBLE) 
		sprintf(buf, verbose ? "TASK_UNINTERRUPTIBLE" : "UN", valid++);
	else if (state == TASK_ZOMBIE) 
		sprintf(buf, verbose ? "TASK_ZOMBIE" : "ZO", valid++);
	else if (state == TASK_STOPPED) 
		sprintf(buf, verbose ? "TASK_STOPPED" : "ST", valid++);
	else if (state == TASK_SWAPPING) 
		sprintf(buf, verbose ? "TASK_SWAPPING" : "SW", valid++);

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
		 ULONG(tt->task_struct + OFFSET(task_struct_state)) : 0;

	return flags;
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
		task_has_cpu(NO_TASK, tt->task_struct) : 0;

	if (!SMP() && !has_cpu && ACTIVE() && (task == tt->this_task))
		has_cpu = TRUE;

	return(has_cpu);
}

/*
 *  Return true if a task is contained within the panic_threadsp[] array.
 */
int
is_panic_thread(ulong task)
{
	int i;

        if (DUMPFILE()) {
                for (i = 0; i < NR_CPUS; i++)
                        if (tt->panic_threads[i] == task)
                                return TRUE;
        }

	return FALSE;
}

/*
 *  Check has_cpu or cpus_runnable to determine whether a task is running
 *  on a cpu.
 */
static int
task_has_cpu(ulong task, char *local_task) 
{
	int has_cpu;
	ulong cpus_runnable;

	if (VALID_OFFSET(task_struct_has_cpu)) {
		if (local_task) 
			has_cpu = INT(local_task+OFFSET(task_struct_has_cpu));
		else if (!readmem((ulong)(task+OFFSET(task_struct_has_cpu)), 
			KVADDR, &has_cpu, sizeof(int), 
		    	"task_struct has_cpu", RETURN_ON_ERROR))
				has_cpu = FALSE;	
	} else if (VALID_OFFSET(task_struct_cpus_runnable)) {
                if (local_task) 
                        cpus_runnable = ULONG(local_task +
				OFFSET(task_struct_cpus_runnable));
		else if (!readmem((ulong)(task + 
			OFFSET(task_struct_cpus_runnable)),
                        KVADDR, &cpus_runnable, sizeof(ulong),
                        "task_struct cpus_runnable", RETURN_ON_ERROR))
                                cpus_runnable = ~0UL;
		has_cpu = (cpus_runnable != ~0UL);
	} else
		error(FATAL, 
		    "task_struct change: no has_cpu or cpus_runnable?\n");

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
	int sysrq_pressed;
	buf[0] = NULLCHAR;

	if (tt->panicmsg)
		read_string(tt->panicmsg, buf, BUFSIZE-1);
	else
		get_lkcd_panicmsg(buf);

	if (STREQ(buf, "sysrq") && symbol_exists("sysrq_pressed")) {
		get_symbol_data("sysrq_pressed", sizeof(int), &sysrq_pressed);
		if (sysrq_pressed)
			machdep->flags |= SYSRQ;
	}

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

        while ((c = getopt(argcnt, args, "R:vmlgersStpukc")) != EOF) {
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
        struct task_context *tc;
	int specified;
	int doit;
	int subsequent;
	ulong cmdflags; 
	struct reference reference, *ref;
	struct bt_info bt_info, *bt;

	/* 
	 *  Filter out any command/option issues.
	 */
	if (MCLXDEBUG(1)) {
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
		} else
			print_task_header(fp, tc, subsequent++);

		for (k = 0; k < fd->keys; k++) {
			free_all_bufs();

			switch(fd->keyword_array[k])
			{
			case FOREACH_BT:
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
                                if (fd->flags & FOREACH_e_FLAG)
                                        bt->flags |= BT_EFRAME_SEARCH;
                                if (fd->flags & FOREACH_g_FLAG)
                                        bt->flags |= BT_USE_GDB;
                                if (fd->flags & FOREACH_l_FLAG)
                                        bt->flags |= BT_LINE_NUMBERS;
				if (fd->reference)
					bt->ref = ref;
				back_trace(bt); 
				break;

			case FOREACH_VM:
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
				do_task(tc->task, FOREACH_TASK, 
					fd->reference ? ref : NULL);
				break;

                        case FOREACH_SIG:
                                do_sig(tc->task, FOREACH_SIG,
                                        fd->reference ? ref : NULL);
                                break;

			case FOREACH_SET:
				show_context(tc, 0, FALSE);
				break;

			case FOREACH_FILES:
				open_files_dump(tc->task, 
					fd->flags & FOREACH_i_FLAG ?
					PRINT_INODES : 0, 
					fd->reference ? ref : NULL);
				break;

			case FOREACH_NET:
				if (fd->flags & (FOREACH_s_FLAG|FOREACH_S_FLAG))
					dump_sockets_workhorse(tc->task,
						fd->flags, 
						fd->reference ? ref : NULL);
				break;

			case FOREACH_VTOP:
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
				foreach_test(tc->task, 0);
				break;
			}
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
				fprintf(fp, "\n");
				nlm_files_dump();
			}
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
 *  Find the panic task the hard way -- do a "foreach bt" in the background,
 *  and look for the only one that has "panic" embedded in it.
 */
static struct task_context *
panic_search(void)
{
        struct foreach_data foreach_data, *fd;
	char *p1, *p2;
	ulong lasttask, found;
	char buf[BUFSIZE];

	if ((lasttask = get_lkcd_panic_task())) {
		found = TRUE;
		goto found_panic_task;
	}

        BZERO(&foreach_data, sizeof(struct foreach_data));
        fd = &foreach_data;
	fd->keys = 1;
	fd->keyword_array[0] = FOREACH_BT; 
	fd->flags |= FOREACH_t_FLAG;

	lasttask = NO_TASK;
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

		if (strstr(buf, ": panic+")) {
			found = TRUE;
			break;	
		}
	}

	close_tmpfile();

found_panic_task:
	populate_panic_threads();
	return(found ? task_to_context(lasttask) : NULL);
}

/*
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
		if (task_has_cpu(tc->task, NULL)) {
			tt->panic_threads[tc->processor] = tc->task;
			found++;
		}
	}

	if (!found && LKCD_DUMPFILE() && !SMP()) 
		tt->panic_threads[0] = get_lkcd_panic_task();
}
	
/*
 *  Separate the foreach command's output on a task-by-task basis by
 *  displaying this header string.
 */
void
print_task_header(FILE *out, struct task_context *tc, int newline)
{
	char buf[BUFSIZE];

        fprintf(out, "%sPID: %-5ld  TASK: %lx  CPU: %-2s  COMMAND: \"%s\"\n",
		newline ? "\n" : "", tc->pid, tc->task, 
		task_cpu(tc->processor, buf, !VERBOSE), tc->comm);
}

/*
 *  "help -t" output
 */
void
dump_task_table(int verbose)
{
	int i;
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
	else if (tt->refresh_task_table == refresh_active_task_table)
		fprintf(fp, "refresh_active_task_table()\n");
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
	sprintf(&buf[strlen(buf)], ")");

        if (strlen(buf) > 54)
                fprintf(fp, "\n%s\n", mkstring(buf, 80, CENTER|LJUST, NULL));
        else
                fprintf(fp, "%s\n", buf);

	fprintf(fp, "        task_start: %lx\n",  tt->task_start);
	fprintf(fp, "          task_end: %lx\n",  tt->task_end);
	fprintf(fp, "        task_local: %lx\n",  (ulong)tt->task_local);
	fprintf(fp, "          nr_tasks: %d\n", tt->nr_tasks);
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

        for (i = 0; i < NR_CPUS; i++) {
                if ((i % wrap) == 0)
                        fprintf(fp, "\n        ");
                fprintf(fp, "%.*lx ", flen, tt->panic_threads[i]); 
        }
        fprintf(fp, "\n");

        fprintf(fp, "         panic_ksp:");
        for (i = 0; i < NR_CPUS; i++) {
                if ((i % wrap) == 0)
                        fprintf(fp, "\n        ");
                fprintf(fp, "%.*lx ", flen, tt->panic_ksp[i]);
        }
        fprintf(fp, "\n");

        fprintf(fp, "      idle_threads:");
        for (i = 0; i < NR_CPUS; i++) {
                if ((i % wrap) == 0)
                        fprintf(fp, "\n        ");
                fprintf(fp, "%.*lx ", flen, tt->idle_threads[i]);
        }
        fprintf(fp, "\n");

	fprintf(fp, "       current_set:");
	for (i = 0; i < NR_CPUS; i++) {
		if ((i % wrap) == 0)
	        	fprintf(fp, "\n        ");
	        fprintf(fp, "%.*lx ", flen, tt->current_set[i]);
	}
	fprintf(fp, "\n");


	if (!verbose)
		return;

	fprintf(fp, "\nINDEX   TASK    PID CPU PTASK   MM_STRUCT  COMM\n");
        tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
		fprintf(fp, "[%3d] %lx %5ld %d %lx %08lx %s\n",
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

	if (tc->pid == 0)
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

	qlen = 1000;

start_again:
	tlist = (ulong *)GETBUF(qlen * sizeof(void *));

        if (symbol_exists("runqueue_head")) {
		next = runqueue_head = symbol_value("runqueue_head");
		offs = 0;
        } else if ((offs = OFFSET(task_struct_next_run)) >= 0) {
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

		if (!(tc = task_to_context(PAGEBASE(tlist[i])))) {
			fprintf(fp, 
			    	"PID: ?      TASK: %lx  CPU: ?   COMMAND: ?\n",
					tlist[i]);
			continue;
		}

		if (!is_idle_thread(tc->task))
			print_task_header(fp, tc, 0);
	}
}

#define _NSIG           64
#define _NSIG_BPW       machdep->bits
#define _NSIG_WORDS     (_NSIG / _NSIG_BPW)

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
    /* 31 */  {"SIGSYS",     NULL},
              {NULL,         NULL},    /* Real time signals start here. */
};

static void
signame_list(void)
{
	int i;

        for (i = 0; i < _NSIG; i++) {
                if (!signame[i].name)
                        continue;

                fprintf(fp, "%s[%d] %s", i < 10 ? " " : "", 
			i, signame[i].name);
		if (signame[i].altname)
			fprintf(fp, "/%s",  signame[i].altname);
		fprintf(fp, "\n");
        }
}

/*
 *  Translate the bits in a signal set into their name strings.
 */
static void 
translate_sigset(ulonglong sigset)
{
	int i, c, bit, len;
	ulonglong mask, sig;
	char buf[BUFSIZE];

	if (!sigset) {
		fprintf(fp, "(none)\n");
		return;
	}

	len = 0;

        for (i = c = 0; i < (_NSIG/2); i++) {
              	mask = (ulong)(1) << i;
		if ((sig = (sigset & mask))) {
			bit = ffs((int)sig);
			sprintf(buf, "%s%s", c++ ? " " : "", 
				signame[bit].name);
			if ((len + strlen(buf)) > 80) {
				shift_string_left(buf, 1);
				fprintf(fp,  "\n");
				len = 0;
			}
			len += strlen(buf);
			fprintf(fp, buf);
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

	tasklist = (ulong *)GETBUF((MAXARGS+NR_CPUS)*sizeof(ulong));
	ref = (struct reference *)GETBUF(sizeof(struct reference));
	siglist = GETBUF(BUFSIZE);
	ref->str = siglist;

        while ((c = getopt(argcnt, args, "lR:s:")) != EOF) {
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
		do_sig(tasklist[c], 0, strlen(ref->str) ? ref : NULL);
		fprintf(fp, "\n");
	}

}

/*
 *  Do the work for the sig command, coming from sig or foreach.
 */
void
do_sig(ulong task, ulong flags, struct reference *ref)
{
        struct task_context *tc;

	if (!VALID_OFFSET(task_struct_sigpending)) {
	        OFFSET(task_struct_sig) = MEMBER_OFFSET("task_struct", "sig");
	        OFFSET(task_struct_signal) = 
			MEMBER_OFFSET("task_struct", "signal");
	        OFFSET(task_struct_blocked) = 
			MEMBER_OFFSET("task_struct", "blocked");
	        OFFSET(task_struct_sigpending) = MEMBER_OFFSET("task_struct",
	                "sigpending");
	        OFFSET(task_struct_pending) = 
			MEMBER_OFFSET("task_struct", "pending");
	        OFFSET(task_struct_sigqueue) = 
			MEMBER_OFFSET("task_struct", "sigqueue");
	 
	        OFFSET(signal_struct_count) = 
			MEMBER_OFFSET("signal_struct", "count");
	        OFFSET(signal_struct_action) = 
			MEMBER_OFFSET("signal_struct", "action");

	        OFFSET(k_sigaction_sa) = MEMBER_OFFSET("k_sigaction", "sa");
	
	        OFFSET(sigaction_sa_handler) = 
			MEMBER_OFFSET("sigaction", "sa_handler");
	        OFFSET(sigaction_sa_mask) = 
			MEMBER_OFFSET("sigaction", "sa_mask");
	        OFFSET(sigaction_sa_flags) = 
			MEMBER_OFFSET("sigaction", "sa_flags");

	        OFFSET(sigpending_head) = 
			MEMBER_OFFSET("sigpending", "head");
	        OFFSET(sigpending_signal) = 
			MEMBER_OFFSET("sigpending", "signal");

                OFFSET(signal_queue_next) =
                        MEMBER_OFFSET("signal_queue", "next");
                OFFSET(signal_queue_info) =
                        MEMBER_OFFSET("signal_queue", "info");

                OFFSET(sigqueue_next) =
                        MEMBER_OFFSET("sigqueue", "next");
                OFFSET(sigqueue_info) =
                        MEMBER_OFFSET("sigqueue", "info");

                OFFSET(siginfo_si_signo) =
                        MEMBER_OFFSET("siginfo", "si_signo");

		SIZE(signal_struct) = STRUCT_SIZE("signal_struct");
		SIZE(k_sigaction) = STRUCT_SIZE("k_sigaction");
		SIZE(signal_queue) = STRUCT_SIZE("signal_queue");
		SIZE(sigqueue) = STRUCT_SIZE("sigqueue");
	}

        tc = task_to_context(task);

        if (ref)
                signal_reference(tc, flags, ref);
        else {
                if (!(flags & FOREACH_TASK))
                        print_task_header(fp, tc, 0);
                dump_signal_data(tc);
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
dump_signal_data(struct task_context *tc)
{
	int i, others;
	int translate, sig, sigpending;
	ulonglong sigset, blocked, mask;
	ulong signal_struct, kaddr, handler, flags, sigqueue, next;
	char *signal_buf, *uaddr;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];

	sigset = task_signal(tc->task);
	if (!tt->last_task_read)
		return;
	blocked = task_blocked(tc->task);

	sigpending = INT(tt->task_struct + OFFSET(task_struct_sigpending));
	fprintf(fp, "SIGPENDING: %s\n", sigpending ? "yes" : "no");
		
	fprintf(fp, "    SIGNAL: %016llx\n", sigset);

	fprintf(fp, "   BLOCKED: %016llx\n", blocked);

	signal_struct = ULONG(tt->task_struct + OFFSET(task_struct_sig));
	fprintf(fp, "SIGNAL_STRUCT: %lx  ", signal_struct);
	signal_buf = GETBUF(MAX(SIZE(signal_struct), 
		VALID_SIZE(signal_queue) ? 
		SIZE(signal_queue) : SIZE(sigqueue)));
	readmem(signal_struct, KVADDR, signal_buf,
		SIZE(signal_struct), "signal_struct buffer",
		FAULT_ON_ERROR);
	fprintf(fp, "COUNT: %d\n",
		INT(signal_buf + OFFSET(signal_struct_count)));

	fprintf(fp, " SIG %s %s %s %s\n",
		mkstring(buf1, VADDR_PRLEN == 8 ? 9 : VADDR_PRLEN, 
			CENTER, "SIGACTION"),
		mkstring(buf2, UVADDR_PRLEN, RJUST, "HANDLER"),
		mkstring(buf3, 16, CENTER, "MASK"),
		mkstring(buf4, VADDR_PRLEN, LJUST, "FLAGS"));

        for (i = 1; i < _NSIG; i++) {
                if (!signame[i].name)
                        break;

                fprintf(fp, "%s[%d] ", i < 10 ? " " : "", i);

		kaddr = signal_struct + OFFSET(signal_struct_action) +
			((i-1) * SIZE(k_sigaction));

		uaddr = signal_buf + OFFSET(signal_struct_action) +
			((i-1) * SIZE(k_sigaction));

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
		flags = ULONG(uaddr + OFFSET(sigaction_sa_flags));

		fprintf(fp, "%s%lx %s %016llx %lx ",
			VADDR_PRLEN == 8 ? " " : "", kaddr,
			buf1,
			mask,
			flags);

		if (flags) {
			others = 0; translate = 1;
			if (flags & SA_NOCLDSTOP)
				fprintf(fp, "%s%sSA_NOCLDSTOP",
					translate-- > 0 ? "(" : "",
					others++ ? "|" : "");
#ifdef SA_RESTORER
                        if (flags & SA_RESTORER)
                                fprintf(fp, "%s%sSA_RESTORER",
                                        translate-- > 0 ? "(" : "",
                                        others++ ? "|" : "");
#endif
#ifdef SA_NOCLDWAIT
			if (flags & SA_NOCLDWAIT)
				fprintf(fp, "%s%sSA_NOCLDWAIT", 
					translate-- > 0 ? "(" : "",
					others++ ? "|" : "");
#endif
			if (flags & SA_SIGINFO)
				fprintf(fp, "%s%sSA_SIGINFO", 
					translate-- > 0 ? "(" : "",
					others++ ? "|" : "");
			if (flags & SA_ONSTACK)
				fprintf(fp, "%s%sSA_ONSTACK", 
					translate-- > 0 ? "(" : "",
					others++ ? "|" : "");
			if (flags & SA_RESTART)
				fprintf(fp, "%s%sSA_RESTART", 
					translate-- > 0 ? "(" : "",
					others++ ? "|" : "");
			if (flags & SA_NODEFER)
				fprintf(fp, "%s%sSA_NODEFER", 
					translate-- > 0 ? "(" : "",
					others++ ? "|" : "");
			if (flags & SA_RESETHAND)
				fprintf(fp, "%s%sSA_RESETHAND", 
					translate-- > 0 ? "(" : "",
					others++ ? "|" : "");
			if (translate < 1)
                		fprintf(fp, ")");
		}

                fprintf(fp, "\n");
        }

	if (VALID_OFFSET(task_struct_sigqueue)) 
		sigqueue = ULONG(tt->task_struct + 
			OFFSET(task_struct_sigqueue));

	else if (VALID_OFFSET(task_struct_pending)) 
		sigqueue = ULONG(tt->task_struct +
			OFFSET(task_struct_pending) +
			OFFSET(sigpending_head));

        if (!sigqueue)
                fprintf(fp, "SIGQUEUE: (empty)\n");
        else
                fprintf(fp, "SIGQUEUE:  SIG  %s\n",
                        mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "SIGINFO"));

        while (sigqueue) {
        	readmem(sigqueue, KVADDR, signal_buf, 
			VALID_SIZE(signal_queue) ? 
			SIZE(signal_queue) : SIZE(sigqueue), 
			"signal_queue/sigqueue", FAULT_ON_ERROR);

        	next = ULONG(signal_buf + 
			(VALID_OFFSET(signal_queue_next) ? 
			OFFSET(signal_queue_next) : OFFSET(sigqueue_next)));

        	sig = INT(signal_buf + 
			(VALID_OFFSET(signal_queue_info) ? 
			OFFSET(signal_queue_info) : OFFSET(sigqueue_info)) +
                	OFFSET(siginfo_si_signo));

                fprintf(fp, "           %3d  %lx\n",
                	sig, sigqueue + 
			VALID_OFFSET(signal_queue_info) ?
			OFFSET(signal_queue_info) : OFFSET(sigqueue_info));

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
task_signal(ulong task)
{
	ulonglong sigset;
	ulong *sigset_ptr;

        fill_task_struct(task);

	if (!tt->last_task_read) 
		return 0;

	if (VALID_OFFSET(task_struct_signal))
		sigset_ptr = (ulong *)(tt->task_struct + 
			OFFSET(task_struct_signal));
	else if (VALID_OFFSET(sigpending_signal)) {
		sigset_ptr = (ulong *)(tt->task_struct + 
			OFFSET(task_struct_pending) +
			OFFSET(sigpending_signal));
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
 *  Prepare for 2.5.X separation of task_struct and kernel stack and the
 *  cache coloring of the stack top.
 */
ulong 
generic_get_stackbase(ulong task)
{
	return task;
}

ulong
generic_get_stacktop(ulong task)
{
        return task + STACKSIZE();
}


