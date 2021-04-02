/* kernel.c - core analysis suite
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
 * BitKeeper ID: @(#)kernel.c 1.21
 *
 * 09/28/00  ---    Transition to CVS version control
 *
 * CVS: $Revision: 1.86 $ $Date: 2002/02/18 18:39:35 $
 */

#include "defs.h"
#include <elf.h>

static void do_module_cmd(ulong, char *, ulong, char *);
static char *find_module_objfile(char *, char *);
static char *get_uptime(char *);
static char *get_loadavg(char *);
static void get_lkcd_regs(struct bt_info *, ulong *, ulong *);
static void dump_sys_call_table(char *, int);
static int get_NR_syscalls(void);
static void display_bh_1(void);
static void display_bh_2(void);
static void display_bh_3(void);
static void dump_timer_data(void);
static void dump_bt_info(struct bt_info *);
struct tv_range;
static void init_tv_ranges(struct tv_range *, int, int);
static int do_timer_list(char *,int, ulong *, void *,ulong *,struct tv_range *);
static int compare_timer_data(const void *, const void *);
static void panic_this_kernel(void);
static void dump_waitq(ulong, char *);
static void reinit_modules(void);
static int verify_modules(void);



/*
 *  Gather a few kernel basics.
 */
void
kernel_init(int when)
{
	int i;

	if (pc->flags & KERNEL_DEBUG_QUERY)
		return;

	switch (when)
	{
	case PRE_GDB:
		kt->stext = symbol_value("_stext");
		kt->etext = symbol_value("_etext");
		get_text_init_space(); 
		kt->init_end = symbol_value("__init_end");
		kt->end = symbol_value("_end");
	
		if (symbol_exists("smp_num_cpus")) {
			kt->smp = TRUE;
			get_symbol_data("smp_num_cpus", sizeof(int), &kt->cpus);
			if (kt->cpus < 1 || kt->cpus > NR_CPUS)
				error(WARNING, 
				    "invalid value: smp_num_cpus: %d\n",
					kt->cpus);
		}
		else {
			kt->smp = FALSE;
			kt->cpus = 1;
		}
	
		get_symbol_data("xtime", sizeof(struct timespec), &kt->date);
	
		if (pc->flags & GET_TIMESTAMP) {
	        	fprintf(fp, "%s\n\n", 
				strip_linefeeds(ctime(&kt->date.tv_sec)));
			exit(0);
		}
	
	        readmem(symbol_value("system_utsname"), KVADDR, &kt->utsname,
	                sizeof(struct new_utsname), "system_utsname", 
			FAULT_ON_ERROR);
		break;

	case POST_GDB:
               /*
                *  In 2.4, smp_send_stop() sets smp_num_cpus back to 1
                *  in some, but not all, architectures.  So if a count
                *  of 1 is found, be suspicious, and check the
                *  init_tasks[NR_CPUS] array (also intro'd in 2.4),
                *  for idle thread addresses.  For 2.2, prepare for the
	        *  eventuality by verifying the cpu count with the machine
		*  dependent count.
                */
                if (SMP() && DUMPFILE() && (kt->cpus == 1)) {
                        if (symbol_exists("init_tasks")) {
                                ulong init_tasks[NR_CPUS];

                                readmem(symbol_value("init_tasks"), KVADDR,
                                        init_tasks, sizeof(void *) * NR_CPUS,
                                        "init_tasks[]", FAULT_ON_ERROR);

                                for (i = kt->cpus = 0; i < NR_CPUS; i++)
                                        if (init_tasks[i])
                                                kt->cpus++;
                	} else 
				kt->cpus = machdep->get_smp_cpus();
		}

		SIZE(list_head) = STRUCT_SIZE("list_head"); 
		OFFSET(list_head_next) = MEMBER_OFFSET("list_head", "next"); 
		if (OFFSET(list_head_next) != 0)
		    error(WARNING, 
			"list_head.next offset: %ld: list command may fail\n",
				OFFSET(list_head_next));
		break;
	}
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

	if (pc->flags & KERNEL_DEBUG_QUERY)
		return;

	BZERO(buf, BUFSIZE);

	get_symbol_data("linux_banner", sizeof(ulong), &linux_banner);

	if (!IS_KVADDR(linux_banner))
		error(WARNING, "invalid linux_banner pointer: %lx\n", 
			linux_banner);

	if (!accessible(linux_banner)) 
		goto bad_match;

	if (!read_string(linux_banner, buf, BUFSIZE-1))
		error(WARNING, "cannot read linux_banner string\n");

	if (ACTIVE()) {
		if (strlen(kt->proc_version) && !STREQ(buf, kt->proc_version)) {
               		if (MCLXDEBUG(1)) {
                        	fprintf(fp, "/proc/version: %s", 
					kt->proc_version);
                        	fprintf(fp, " linux_banner: %s\n", buf);
                	}
			goto bad_match;
		}
	}

	if (DUMPFILE()) {
		if (!STRNEQ(buf, "Linux version")) {
                	if (MCLXDEBUG(1)) 
                        	fprintf(fp, "linux_banner: %s\n", buf);
			goto bad_match;
		}
		strcpy(kt->proc_version, buf);
	}

	return;

bad_match:
	if (REMOTE())
		sprintf(buf, "%s:%s", pc->server, pc->server_memsrc);
	else
		sprintf(buf, ACTIVE() ? "/dev/mem" : pc->dumpfile);

	error(FATAL, "%s and %s do not match!\n",
		pc->namelist, buf);
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
 */
void
cmd_dis(void)
{
	int c;
	int do_load_module_filter, do_machdep_filter, reverse;
	ulong curaddr;
	ulong revtarget;
	off_t offset, revoffs;
	ulong count;
	struct syment *sp;
	struct gnu_request *req;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];

	reverse = FALSE;
	sp = NULL;
	do_machdep_filter = do_load_module_filter = 0;

	req = (struct gnu_request *)getbuf(sizeof(struct gnu_request));
	req->buf = GETBUF(BUFSIZE);
	req->flags |= GNU_FROM_TTY_OFF|GNU_RETURN_ON_ERROR;
	req->count = 1;

        while ((c = getopt(argcnt, args, "lr")) != EOF) {
                switch(c)
		{
		case 'r':
			reverse = TRUE;
			break;

		case 'l':
			req->flags |= GNU_PRINT_LINE_NUMBERS;
			BZERO(buf4, BUFSIZE);
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
                else if (hexadecimal(args[optind], 0))
                        req->addr = htol(args[optind], FAULT_ON_ERROR, NULL);
                else if ((sp = symbol_search(args[optind]))) {
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
			}
		}

		do_load_module_filter = module_symbol(req->addr, NULL, NULL, 
			NULL, output_radix);

		if (!reverse) {
			req->command = GNU_RESOLVE_TEXT_ADDR;
			gdb_interface(req);
                        if ((req->flags & GNU_COMMAND_FAILED) ||
			    do_load_module_filter) {
				req->flags &= ~GNU_COMMAND_FAILED;
				if (sp) {
                                        if ((sp = next_symbol(NULL, sp)))
                                                req->addr2 = sp->value;
					else
                                		error(FATAL, 
				            "gdb unable to resolve symbol %s\n",
                                        		sp->name);
				} else {
					if ((sp = value_search(req->addr, 
					    &offset)) && 
				            (sp = next_symbol(NULL, sp))) 
						req->addr2 = sp->value;	
					else 
						error(FATAL,
				      "gdb unable to disassemble address %lx\n",
							req->addr);
				}
                        }

			do_machdep_filter = machdep->dis_filter(req->addr,NULL);
			count = 0;
			open_tmpfile();
			req->command = GNU_DISASSEMBLE;
			req->fp = pc->tmpfile;
			gdb_interface(req);
			if (req->flags & GNU_COMMAND_FAILED) {
				close_tmpfile();
				error(FATAL, 
				    "gdb unable to disassemble address %lx\n",
					req->addr);
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
        else cmd_usage(pc->curcmd, SYNOPSIS);

	if (!reverse) {
		FREEBUF(req->buf);
		FREEBUF(req);
		return;
	}

        revtarget = req->addr;
        if ((sp = value_search(revtarget, &revoffs)) == NULL)
                error(FATAL, "cannot resolve address: %lx\n", revtarget);

        sprintf(buf1, "0x%lx", revtarget);

        open_tmpfile();

        req->addr = sp->value;
        req->flags |= GNU_FUNCTION_ONLY;
        req->command = GNU_RESOLVE_TEXT_ADDR;
        gdb_interface(req);
        if ((req->flags & GNU_COMMAND_FAILED) || do_load_module_filter) {
                req->flags &= ~GNU_COMMAND_FAILED;
                if ((sp = next_symbol(NULL, sp)))
                        req->addr2 = sp->value;
                else {
			close_tmpfile();
                        error(FATAL, "gdb unable to resolve symbol %s\n",
                                                        sp->name);
		}
        }

	do_machdep_filter = machdep->dis_filter(req->addr, NULL);
	req->command = GNU_DISASSEMBLE;
	req->fp = pc->tmpfile;
	gdb_interface(req);
        if (req->flags & GNU_COMMAND_FAILED) {
		close_tmpfile();
        	error(FATAL, "gdb unable to disassemble address %lx\n", 
			req->addr);
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

        		fgets(buf2, BUFSIZE, pc->tmpfile);

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
 *  Nothing to do.
 */
int
generic_dis_filter(ulong value, char *buf)
{
	return TRUE;
}

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

#define BT_SETUP(TC)                                          \
	BCOPY(&bt_setup, bt, sizeof(struct bt_info));         \
        if (refptr) {                                         \
		BZERO(&reference, sizeof(struct reference));  \
		bt->ref = &reference;                         \
        	bt->ref->str = refptr;                        \
	}                                                     \
        bt->tc = (TC);                                        \
        bt->task = ((TC)->task);			      \
	bt->stackbase = GET_STACKBASE((TC)->task);            \
	bt->stacktop = GET_STACKTOP((TC)->task);            
 
void
cmd_bt(void)
{
	int c;
	ulong value;
        struct task_context *tc;
	int count, subsequent, active;
	struct stack_hook hook;
	struct bt_info bt_info, bt_setup, *bt;
	struct reference reference;
	char *refptr;

	tc = NULL;
	subsequent = active = count = 0;
	hook.eip = hook.esp = 0;
	refptr = 0;
	bt = &bt_info;
	BZERO(bt, sizeof(struct bt_info));

        while ((c = getopt(argcnt, args, "I:S:alregstd:R:")) != EOF) {
                switch(c)
		{
		case 'R':
			if (refptr) 
				error(INFO, "only one -R option allowed\n");
			else 
				refptr = optarg;
			break;
			
		case 'l':
			bt->flags |= BT_LINE_NUMBERS;
			break;

		case 'e':
			bt->flags |= BT_EFRAME_SEARCH;
			break;

		case 'g':
			bt->flags |= BT_USE_GDB;
			break;

		case 'd':
			bt->debug = dtol(optarg, FAULT_ON_ERROR, NULL);
			break;

		case 'I':
			bt->hp = &hook;
			hook.eip = convert(optarg, FAULT_ON_ERROR, 
				NULL, NUM_HEX|NUM_EXPR);
			break;

		case 'S':
			bt->hp = &hook;
			hook.esp = htol(optarg, FAULT_ON_ERROR, NULL);
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

		case 't':
			bt->flags |= BT_TEXT_SYMBOLS;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	BCOPY(bt, &bt_setup, sizeof(struct bt_info));

	if (active) {
		if (ACTIVE())
			error(FATAL, 
				"-a option not supported on a live system\n");

		for (c = 0; c < NR_CPUS; c++) {
			if ((tc = task_to_context(tt->panic_threads[c]))) {
				BT_SETUP(tc);
				if (!BT_REFERENCE_CHECK(bt))
					print_task_header(fp, tc, subsequent++);
				back_trace(bt);
			}
		}

		return;
	}

	if (!args[optind]) {
		tc = CURRENT_CONTEXT();
		BT_SETUP(tc);
		if (!BT_REFERENCE_CHECK(bt))
			print_task_header(fp, tc, 0);
		back_trace(bt);
		return;
	}

	while (args[optind]) {
                switch (str_to_context(args[optind], &value, &tc))
                {
                case STR_PID:
                        for (tc = pid_to_context(value); tc; tc = tc->tc_next) {
                                BT_SETUP(tc);
                                if (!BT_REFERENCE_CHECK(bt))
                                        print_task_header(fp, tc, subsequent++);
                                back_trace(bt);
                        }
                        break;

                case STR_TASK:
                        BT_SETUP(tc);
                        if (!BT_REFERENCE_CHECK(bt))
                                print_task_header(fp, tc, subsequent++);
                        back_trace(bt);
                        break;

                case STR_INVALID:
                        error(INFO, "%sinvalid task or pid value: %s\n",
                                subsequent++ ? "\n" : "", args[optind]);
                        break;
                }

		optind++;
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
	ulong next_pc;
	ulong next_sp;

	if (bt->flags & BT_RAW) {
		raw_stack_dump(bt->task);
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

	if (MCLXDEBUG(4)) {
		for (i = 0, up = (ulong *)bt->stackbuf; 
		     i < LONGS_PER_STACK; i++, up++) {
			if (is_kernel_text(*up))
				fprintf(fp, "%lx: %s\n", 
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
			error(FATAL, 
			    "invalid stack address for this task: %lx\n",
				bt->hp->esp);
		eip = bt->hp->eip;
		esp = bt->hp->esp;

		machdep->get_stack_frame(bt, eip ? NULL : &eip, 
			esp ? NULL : &esp);

	} else if ((pc->flags & LKCD) || (pc->flags & REM_LKCD)) 
		get_lkcd_regs(bt, &eip, &esp);
        else 
		machdep->get_stack_frame(bt, &eip, &esp);

	if (bt->flags & BT_KSTACKP) {
		bt->stkptr = esp;
		return;
	}

	if (bt->flags & 
	    (BT_TEXT_SYMBOLS|BT_TEXT_SYMBOLS_PRINT|BT_TEXT_SYMBOLS_NOPRINT)) {
		if (bt->flags & BT_TEXT_SYMBOLS) {
			fprintf(fp, "%sSTART: %s\n",
				space(VADDR_PRLEN > 8 ? 11 : 3),
				value_to_symstr(eip, buf, 0));
		}

		if (bt->hp) 
			bt->hp->eip = bt->hp->esp = 0;
		next_pc = next_sp = 0;

		for (i = (esp - bt->task)/sizeof(ulong);
		     i < LONGS_PER_STACK; i++) {
			up = (ulong *)(&bt->stackbuf[i*sizeof(ulong)]);
                        if (is_kernel_text_offset(*up, NULL)) {
				if (!next_pc) 
					next_pc = *up;
				else if (!next_sp) 
					next_sp = bt->task + (i * sizeof(long));

			}
			if (is_kernel_text(*up)) {
				if (bt->flags & 
				    (BT_TEXT_SYMBOLS|BT_TEXT_SYMBOLS_PRINT))
                                	fprintf(fp, "%lx: %s\n",
                                        	bt->task + (i * sizeof(long)),
                                        	value_to_symstr(*up, buf, 0));
			}
		}

		if (bt->hp) {
			bt->hp->eip = next_pc;
			bt->hp->esp = next_sp;
		}
		
		return;
	}

	bt->instptr = eip;
	bt->stkptr = esp;

	if (BT_REFERENCE_CHECK(bt))
		BCOPY(bt, &btsave, sizeof(struct bt_info));

	if (MCLXDEBUG(4))
		dump_bt_info(bt);

	machdep->back_trace(bt);

	if (BT_REFERENCE_FOUND(bt)) {
		print_task_header(fp, task_to_context(bt->task), 0);
		BCOPY(&btsave, bt, sizeof(struct bt_info));
		bt->ref = NULL;
		machdep->back_trace(bt);
		fprintf(fp, "\n");
	}
}

/*
 *  Debug routine most likely useful from above in back_trace()
 */
static void
dump_bt_info(struct bt_info *bt)
{
	fprintf(fp, "     task: %lx\n", bt->task);
	fprintf(fp, "    flags: %lx\n", bt->flags);
	fprintf(fp, "  instptr: %lx\n", bt->instptr);
	fprintf(fp, "   stkptr: %lx\n", bt->stkptr);
	fprintf(fp, "stackbase: %lx\n", bt->stackbase);
	fprintf(fp, "       tc: %lx ", (ulong)bt->tc);
	if (bt->tc)
		fprintf(fp, "(%ld, %lx)\n", bt->tc->pid, bt->tc->task);
	else
		fprintf(fp, "(unknown context)\n");
	fprintf(fp, "    flags: %lx\n", bt->flags);
	fprintf(fp, "       hp: %lx\n", (ulong)bt->hp);
	fprintf(fp, "      ref: %lx\n", (ulong)bt->ref);
	fprintf(fp, " stackbuf: %lx\n", (ulong)bt->stackbuf);
	fprintf(fp, "    debug: %lx\n", bt->debug);
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

	sysrq_eip = sysrq_esp = 0;

	for (i = 0, up = (ulong *)bt->stackbuf; i < LONGS_PER_STACK; i++, up++){
		sym = closest_symbol(*up);
		if (STREQ(sym, "dump_execute")) {
			*eip = *up;
			*esp = *(up-1);
			return;
		}
                if (STREQ(sym, "panic")) {
                        *eip = *up;
                        *esp = *(up-1);
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
        ulong mod, mod_next;
	uint nsyms;
	ulong total;
        char *modbuf;

        if (!symbol_exists("module_list")) {
                kt->module_list = 0;
                return;
        }

	SIZE(module) = STRUCT_SIZE("module");
        OFFSET(module_size_of_struct) = 
		MEMBER_OFFSET("module", "size_of_struct");
        OFFSET(module_next) = MEMBER_OFFSET("module", "next");
        OFFSET(module_name) = MEMBER_OFFSET("module", "name");
        OFFSET(module_nsyms) = MEMBER_OFFSET("module", "nsyms");
        OFFSET(module_syms) = MEMBER_OFFSET("module", "syms");
        OFFSET(module_flags) = MEMBER_OFFSET("module", "flags");
        OFFSET(module_size) = MEMBER_OFFSET("module", "size");

        get_symbol_data("module_list", sizeof(ulong), &kt->module_list);
        kt->kernel_module = symbol_value("kernel_module");

	total = kt->mods_installed = 0;

        modbuf = GETBUF(SIZE(module));

        for (mod = kt->module_list; mod != kt->kernel_module; mod = mod_next) {

                if (!readmem(mod, KVADDR, modbuf, SIZE(module), 
		    "module struct", RETURN_ON_ERROR|QUIET)) {
                        error(WARNING,
                            "cannot access vmalloc'd module memory\n");
                        kt->mods_installed = 0;
                        kt->flags |= NO_MODULE_ACCESS;
                        FREEBUF(modbuf); 
			return;
		}

                nsyms = UINT(modbuf + OFFSET(module_nsyms));

		total += nsyms;
		total += 2;  /* store the module's start/ending addresses */

		kt->mods_installed++;

                mod_next = ULONG(modbuf + OFFSET(module_next));
	}

        FREEBUF(modbuf);

	store_module_symbols(total, kt->mods_installed);
}


/*
 *  Verify that the current set of modules jives with what's stored.
 */
static int
verify_modules(void)
{
	int i;
	int found, irregularities;
        ulong mod, mod_next;
	long mod_size;
        char *modbuf;
	ulong module_list, mod_name, paddr;
	int mods_installed;
	struct load_module *lm;
	char buf[BUFSIZE];

	if (DUMPFILE() || !kt->module_list || (kt->flags & NO_MODULE_ACCESS))
		return TRUE;

        get_symbol_data("module_list", sizeof(ulong), &module_list);
	mods_installed = irregularities = 0;
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

			if (lm->mod_base == mod) {
        			mod_name = ULONG(modbuf + OFFSET(module_name));
				mod_size = LONG(modbuf + OFFSET(module_size));
                		if (!read_string(mod_name, buf, BUFSIZE-1) ||
				    !STREQ(lm->mod_name, buf) ||
				    (mod_size != lm->mod_size)) {
					irregularities++;
					break;
				}
				found = TRUE;
				break;
			}
		}

		if (!found || irregularities) 
			return FALSE;

		mods_installed++;
                mod_next = ULONG(modbuf + OFFSET(module_next));
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

#define ALL_MODULES                   (0)

void
cmd_mod(void)
{
	int c;
	char *objfile, *modref;
	ulong flag, address;
	char buf[BUFSIZE];

	if (kt->flags & NO_MODULE_ACCESS)
		error(FATAL, "cannot access vmalloc'd module memory\n");

	if (!verify_modules()) {
 	 	error(INFO, 
	       "NOTE: modules have changed on this system -- reinitializing\n");
		reinit_modules();
	}

	modref = objfile = NULL;
	address = 0;
	flag = LIST_MODULE_HDR;

        while ((c = getopt(argcnt, args, "rd:Ds:S")) != EOF) {
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
	case LOAD_SPECIFIED_MODULE_SYMBOLS:
		switch (argcnt)
		{
		case 4:
			objfile = args[3];
			if (!file_exists(objfile, NULL)) { 
				if (!(objfile = 
				    find_module_objfile(modref, objfile)))
					error(FATAL, 
				    "%s: cannot find or load object file: %s\n",
						modref, args[3]);
			} 
			break;

		case 3:
                        if (!(objfile = find_module_objfile(modref, NULL)))
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

	do_module_cmd(flag, modref, address, objfile);

}


/*
 *  Do the simple list work for cmd_mod().
 */

static void
do_module_cmd(ulong flag, char *modref, ulong address, char *objfile)
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
			if (!address || (lm->mod_base == address)) {
				fprintf(fp, "%lx  ", lm->mod_base);
		
				fprintf(fp, "%s  ", mkstring(buf1, maxnamelen, 
					LJUST, lm->mod_name));
		
				fprintf(fp, "%6ld  ", lm->mod_size);
		
				if (strlen(lm->mod_namelist))
					fprintf(fp, "%s %s", 
						lm->mod_namelist,
						lm->mod_flags & MOD_REMOTE ?
						" (temporary)" : "");  
				else
					fprintf(fp, "(not loaded)");
		
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
			fprintf(fp, 
          "\nNOTE: To save the %s module object locally, enter \"save %s\".\n",
				lmp->mod_name, lmp->mod_name);
			break;

		default:
			fprintf(fp, 
"\nNOTE: To save all temporary remote module objects locally, enter \"save modules\".\n");
			fprintf(fp, 
 "      To save a single remote module object locally, enter \"save NAME\",\n"
 "      where \"NAME\" is one of the module names shown in the list above.\n");
			break;
		}
		break;
	
	case LOAD_SPECIFIED_MODULE_SYMBOLS:
		if (!load_module_symbols(modref, objfile, address)) 
			error(FATAL, "cannot load symbols from: %s\n", objfile);
		do_module_cmd(LIST_MODULE_HDR, 0, address, 0);
		do_module_cmd(REMOTE_MODULE_SAVE_MSG, 0, 0, 0);
		break;

	case LOAD_ALL_MODULE_SYMBOLS:
		for (i = j = 0; i < kt->mods_installed; i++) {
			lm = &st->load_modules[i];

			modref = lm->mod_name;
			address = lm->mod_base;

			if ((objfile = find_module_objfile(modref, NULL))) {
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
					0, address, 0);
				FREEBUF(objfile);
			} else if (lm->mod_flags & MOD_LOAD_SYMS) { 
				if (MCLXDEBUG(1))
                        		fprintf(fp, 
				      "%s: module symbols are already loaded\n",
                                		modref);
				do_module_cmd(j++ ? 
					LIST_MODULE : LIST_MODULE_HDR,
					0, address, 0);
			} else
				error(INFO,
                              "cannot find or load object file for %s module\n",
					modref);
		}
		do_module_cmd(REMOTE_MODULE_SAVE_MSG, 0, 0, 0);
		break;

	case DELETE_ALL_MODULE_SYMBOLS:
		delete_load_module(ALL_MODULES);
		break;

	case DELETE_MODULE_SYMBOLS:
		delete_load_module(address);
		break;

	case REINIT_MODULES:
		reinit_modules();
        	do_module_cmd(LIST_MODULE_HDR, NULL, 0, NULL);
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
find_module_objfile(char *modref, char *filename)
{
	char command[BUFSIZE];
	char buf[BUFSIZE];
	char file[BUFSIZE];
	struct load_module *lm;
	FILE *pipe;
	char *retbuf;
	struct syment *sp;
	char *p1, *p2;

	retbuf = NULL;

	if (filename)
		strcpy(file, filename);
	else 
		sprintf(file, "%s.o", modref);

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
			BZERO(buf, BUFSIZE);
			p1 = strstr(sp->name, "/");
			if ((p2 = strstr(sp->name, file)))
				p2 += strlen(file);
			if (p2) {
				strncpy(buf, p1, p2-p1); 	
				if (REMOTE()) 
					strcpy(file, buf);
				else {
					retbuf = GETBUF(strlen(buf)+1);
					strcpy(retbuf, buf);
					if (MCLXDEBUG(1))
				    	fprintf(fp, 
					    "find_module_objfile: [%s]\n", 
						retbuf);
					return retbuf;
				}
			}
		}
	}

	if (REMOTE()) {
		retbuf = GETBUF(MAX_MOD_NAMELIST*2);

		if (!is_module_name(modref, NULL, &lm)) {
			error(INFO, "%s is not a module reference\n", modref);
			return NULL;
		}

        	if ((lm->mod_flags & MOD_LOAD_SYMS) &&
		    strlen(lm->mod_namelist)) {
			if (MCLXDEBUG(1))
				fprintf(fp, "redundant mod call: %s\n", 
					lm->mod_namelist);
			strcpy(retbuf, lm->mod_namelist);
			return retbuf;
		}

		if (find_remote_module_objfile(lm, file, retbuf))
			return retbuf;

		return NULL;
	}

	sprintf(command, "/usr/bin/find /lib/modules/%s -name %s -print",
		kt->utsname.release, file);

        if ((pipe = popen(command, "r")) == NULL) {
                error(INFO, "%s: %s\n", command, strerror(errno));
                return NULL;
        }

	retbuf = NULL;

        while (fgets(buf, BUFSIZE-1, pipe)) {
		if (STREQ((char *)basename(strip_linefeeds(buf)), file)) {
			retbuf = GETBUF(strlen(buf)+1);
			strcpy(retbuf, buf);
                        break;
                }
        }

        pclose(pipe);

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
	int i;
	int c;
	ulong log_buf, log_start, logged_chars;
	char *buf;
	char last;
	ulong index;
	int log_wrap, loglevel, log_buf_len, msg_level;

	log_buf_len = get_array_length("log_buf", NULL);
	buf = GETBUF(log_buf_len);
	log_wrap = msg_level = FALSE;

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

	log_buf = symbol_value("log_buf");
	get_symbol_data("log_start", sizeof(ulong), &log_start);
	get_symbol_data("logged_chars", sizeof(ulong), &logged_chars);
        readmem(log_buf, KVADDR, buf,
        	log_buf_len, "log_buf contents", FAULT_ON_ERROR);

	log_start &= log_buf_len-1;
	index = (logged_chars < log_buf_len) ? 0 : log_start;

	if ((logged_chars < log_buf_len) && (index == 0) && (buf[index] == '<'))
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

	if (!(pc->flags & RUNTIME) && !DUMPFILE())
		fprintf(fp, "\n");

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
	} else
		fprintf(fp, "      KERNEL: %s\n", pc->namelist);

	fprintf(fp, "    DUMPFILE: ");
        if (ACTIVE()) {
		if (REMOTE_ACTIVE()) 
			fprintf(fp, "%s@%s  (remote live system)\n",
			    	pc->server_memsrc, pc->server);
		else
                	fprintf(fp, "/dev/mem\n");
	} else {
		if (REMOTE_DUMPFILE())
                	fprintf(fp, "%s@%s  (remote dumpfile)\n", 
				pc->server_memsrc, pc->server);
		else
                	fprintf(fp, "%s\n", pc->dumpfile);
	}
        fprintf(fp, "        CPUS: %d\n", kt->cpus);
	if (ACTIVE())
        	get_symbol_data("xtime", sizeof(struct timespec), &kt->date);
        fprintf(fp, "        DATE: %s\n", 
		strip_linefeeds(ctime(&kt->date.tv_sec))); 
        fprintf(fp, "      UPTIME: %s\n", get_uptime(buf)); 
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
	if (DUMPFILE()) {
		fprintf(fp, "       PANIC: ");
		if (machdep->flags & HWRESET)
			fprintf(fp, "HARDWARE RESET\n");
		else
			fprintf(fp, "\"%s\"\n",
        			strip_linefeeds(get_panicmsg(buf)));
	}
}

/*
 *  Calculate and return the uptime.
 */

static char *
get_uptime(char *buf)
{
	ulong jiffies; 

	get_symbol_data("jiffies", sizeof(long), &jiffies);
	convert_time(jiffies, buf);

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
        ulong *sys_call_table, *sct;
        char buf1[BUFSIZE], *sp;
        char buf2[BUFSIZE], *p;
	char buf3[BUFSIZE];
	char *arglist[MAXARGS];
	int argc, NR_syscalls;
	int number, printit, hdr_printed;
        long size;

	NR_syscalls = get_NR_syscalls();
        size = sizeof(void *) * NR_syscalls;
        sys_call_table = (ulong *)GETBUF(size);

	if (MCLXDEBUG(1))
		fprintf(fp, "NR_syscalls: %d\n", NR_syscalls);

        readmem(symbol_value("sys_call_table"), KVADDR, sys_call_table,
                size, "sys_call_table", FAULT_ON_ERROR);

	if (spec)
		open_tmpfile();

	fprintf(fp, sys_call_hdr);

        for (i = 0, sct = sys_call_table; i < NR_syscalls; i++, sct++) {
                if (!(sp = value_symbol(*sct))) {
			if (MCLXDEBUG(1)) {
				fprintf(fp, (output_radix == 16) ? 
					"%3x  " : "%3d  ", i);
				fprintf(fp, 
			    	    "invalid sys_call_table entry: %lx (%s)\n", 
					*sct, value_to_symstr(*sct, buf1, 0));
			}
			continue;
		}
		
		fprintf(fp, (output_radix == 16) ? "%3x  " : "%3d  ", i);
		fprintf(fp, "%-26s ", sp);

		get_line_number(*sct, buf1, FALSE);
		get_build_directory(buf2);
		p = buf1 + strlen(buf2);
		fprintf(fp, "..%s\n", p);
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

	cnt = (sp->value - sys_call_table)/sizeof(void *);

	return cnt;
}

/*
 *  "help -k" output
 */
void
dump_kernel_table(void)
{
        struct new_utsname *uts;
        int others;

        others = 0;
        uts = &kt->utsname;

        fprintf(fp, "         flags: %lx  (", kt->flags);
	if (kt->flags & NO_MODULE_ACCESS)
		fprintf(fp, "%sNO_MODULE_ACCESS", others++ ? "|" : "");
	fprintf(fp, ")\n");
        fprintf(fp, "         stext: %lx\n", kt->stext);
        fprintf(fp, "         etext: %lx\n", kt->etext);
        fprintf(fp, "    stext_init: %lx\n", kt->stext_init);
        fprintf(fp, "    etext_init: %lx\n", kt->etext_init);
        fprintf(fp, "      init_end: %lx\n", kt->init_end);
        fprintf(fp, "           end: %lx\n", kt->end);
        fprintf(fp, "          cpus: %d\n", kt->cpus);
        fprintf(fp, "           smp: %d\n", kt->smp);
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
        if (ACTIVE())
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

	show_context(CURRENT_CONTEXT(), 0, FALSE);
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

        while ((c = getopt(argcnt, args, "db")) != EOF) {
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
			            symbol_exists("softirq_vec"))
			                kt->display_bh = display_bh_3;
				else
					error(FATAL, 
		                 "unsupported style of bottom-half handling\n");
			}
			kt->display_bh();
			return;

                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

	nr_irqs = machdep->nr_irqs();

	if (!args[optind]) {
		for (i = 0; i < nr_irqs; i++)
			machdep->dump_irq(i);
		return;
	}

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
	long len;
	char *buf;
	int status, depth, others;
	ulong handler, action, value;
	ulong tmp1, tmp2;

	dm = &datatype_member;
	buf = GETBUF(BUFSIZE);
	
        if (!arg_to_datatype("irq_desc_t", dm, RETURN_ON_ERROR) ||
            ((len = dm->size) < 0))
		error(FATAL, "cannot determine size of irq_desc_t\n");

	if (INVALID_OFFSET(irq_desc_t_status)) {
		OFFSET(irq_desc_t_status) = MEMBER_OFFSET(dm->name, "status");
		OFFSET(irq_desc_t_handler) = MEMBER_OFFSET(dm->name, "handler");
		OFFSET(irq_desc_t_action) = MEMBER_OFFSET(dm->name, "action");
		OFFSET(irq_desc_t_depth) = MEMBER_OFFSET(dm->name, "depth");
		OFFSET(hw_interrupt_type_typename) =
			MEMBER_OFFSET("hw_interrupt_type", "typename");
		OFFSET(hw_interrupt_type_startup) =
			MEMBER_OFFSET("hw_interrupt_type", "startup");
		OFFSET(hw_interrupt_type_shutdown) =
			MEMBER_OFFSET("hw_interrupt_type", "shutdown");
		OFFSET(hw_interrupt_type_handle) =
                        MEMBER_OFFSET("hw_interrupt_type", "handle");
		OFFSET(hw_interrupt_type_enable) =
			MEMBER_OFFSET("hw_interrupt_type", "enable");
		OFFSET(hw_interrupt_type_disable) =
			MEMBER_OFFSET("hw_interrupt_type", "disable");
		OFFSET(hw_interrupt_type_ack) =
			MEMBER_OFFSET("hw_interrupt_type", "ack");
		OFFSET(hw_interrupt_type_end) =
			MEMBER_OFFSET("hw_interrupt_type", "end");
		OFFSET(hw_interrupt_type_set_affinity) =
			MEMBER_OFFSET("hw_interrupt_type", "set_affinity");
		OFFSET(irqaction_handler) = 
			MEMBER_OFFSET("irqaction", "handler");
		OFFSET(irqaction_flags) =
			MEMBER_OFFSET("irqaction", "flags");
		OFFSET(irqaction_mask) =
			MEMBER_OFFSET("irqaction", "mask");
		OFFSET(irqaction_name) =
			MEMBER_OFFSET("irqaction", "name");
		OFFSET(irqaction_dev_id) =
			MEMBER_OFFSET("irqaction", "dev_id");
		OFFSET(irqaction_next) =
			MEMBER_OFFSET("irqaction", "next");
	}
	
	irq_desc_addr = symbol_value("irq_desc") + (len * irq);

        readmem(irq_desc_addr + OFFSET(irq_desc_t_status), KVADDR, &status,
                sizeof(int), "irq_desc entry", FAULT_ON_ERROR);
        readmem(irq_desc_addr + OFFSET(irq_desc_t_handler), KVADDR, &handler,
                sizeof(long), "irq_desc entry", FAULT_ON_ERROR);
        readmem(irq_desc_addr + OFFSET(irq_desc_t_action), KVADDR, &action,
                sizeof(long), "irq_desc entry", FAULT_ON_ERROR);
        readmem(irq_desc_addr + OFFSET(irq_desc_t_depth), KVADDR, &depth,
                sizeof(int), "irq_desc entry", FAULT_ON_ERROR);

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
        	readmem(handler+OFFSET(hw_interrupt_type_typename), KVADDR, 
			&tmp1, sizeof(void *),
                	"hw_interrupt_type typename", FAULT_ON_ERROR);
	 	fprintf(fp, "         typename: %lx  ", tmp1);
		BZERO(buf, BUFSIZE);
        	if (read_string(tmp1, buf, BUFSIZE-1))
			fprintf(fp, "\"%s\"", buf);
		fprintf(fp, "\n");

		readmem(handler+OFFSET(hw_interrupt_type_startup), KVADDR,
			&tmp1, sizeof(void *),
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

                readmem(handler+OFFSET(hw_interrupt_type_shutdown), KVADDR,
                        &tmp1, sizeof(void *),
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

		if (VALID_OFFSET(hw_interrupt_type_handle)) {
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

                readmem(handler+OFFSET(hw_interrupt_type_enable), KVADDR,
                        &tmp1, sizeof(void *),
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

                readmem(handler+OFFSET(hw_interrupt_type_disable), KVADDR,
                        &tmp1, sizeof(void *),
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

		if (VALID_OFFSET(hw_interrupt_type_ack)) {
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
		}

		if (VALID_OFFSET(hw_interrupt_type_end)) {
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
		}

		if (VALID_OFFSET(hw_interrupt_type_set_affinity)) {
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
                fprintf(fp, "            flags: %lx  ", value);
                if (value) {
                        others = 0;
                        fprintf(fp, "(");
				
                        if (value & SA_INTERRUPT)
                                fprintf(fp, "%sSA_INTERRUPT",
                                                        others++ ? "|" : "");
                        if (value & SA_PROBE)
                                fprintf(fp, "%sSA_PROBE",
                                                        others++ ? "|" : "");
                        if (value & SA_SAMPLE_RANDOM)
                                fprintf(fp, "%sSA_SAMPLE_RANDOM",
                                                        others++ ? "|" : "");
                        if (value & SA_SHIRQ)
                                fprintf(fp, "%sSA_SHIRQ", others++ ? "|" : "");

                        fprintf(fp, ")");
                        if (value & ~ACTION_FLAGS) {
                                fprintf(fp, "  (bits %lx not translated)",
                                        	value & ~ACTION_FLAGS);
                        }
                }
		fprintf(fp, "\n");

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

	free_all_bufs();
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

	if (INVALID_SIZE(irq_cpustat_t)) {
		SIZE(irq_cpustat_t) = STRUCT_SIZE("irq_cpustat_t");
		OFFSET(irq_cpustat_t___softirq_active) = 		
			MEMBER_OFFSET("irq_cpustat_t", "__softirq_active");
		OFFSET(irq_cpustat_t___softirq_mask) = 		
			MEMBER_OFFSET("irq_cpustat_t", "__softirq_mask");
	}

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
        struct timer_struct *tp;
        ulong mask, highest, function;
	ulong jiffies, timer_jiffies;
	ulong *vec;
	long count;
        int vec_root_size, vec_size;
	struct timer_data *td;
	int flen, tdx, old_timers_exist;
        struct tv_range tv[TVN];

	if (OFFSET(timer_list_next) < 0) {
		OFFSET(timer_list_list) =
			MEMBER_OFFSET("timer_list", "list");
        	OFFSET(timer_list_next) = 
			MEMBER_OFFSET("timer_list", "next");
        	OFFSET(timer_list_expires) = 
			MEMBER_OFFSET("timer_list", "expires");
        	OFFSET(timer_list_function) = 
			MEMBER_OFFSET("timer_list", "function");
        	OFFSET(timer_vec_root_vec) = 
			MEMBER_OFFSET("timer_vec_root", "vec");
        	OFFSET(timer_vec_vec) = 
			MEMBER_OFFSET("timer_vec", "vec");
		SIZE(timer_list) = STRUCT_SIZE("timer_list");
	}


	BZERO(tv, sizeof(struct tv_range) * TVN);
        vec_root_size = get_array_length("timer_vec_root.vec", NULL);
        vec_size = get_array_length("timer_vec.vec", NULL);
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

	init_tv_ranges(tv, vec_root_size, vec_size);

        count += do_timer_list("tv1", vec_root_size, vec, NULL, NULL, tv);
        count += do_timer_list("tv2", vec_size, vec, NULL, NULL, tv);
        count += do_timer_list("tv3", vec_size, vec, NULL, NULL, tv);
        count += do_timer_list("tv4", vec_size, vec, NULL, NULL, tv);
        count += do_timer_list("tv5", vec_size, vec, NULL, NULL, tv);

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

	do_timer_list("tv1", vec_root_size, vec, (void *)td, &highest, tv);
	do_timer_list("tv2", vec_size, vec, (void *)td, &highest, tv);
	do_timer_list("tv3", vec_size, vec, (void *)td, &highest, tv);
	do_timer_list("tv4", vec_size, vec, (void *)td, &highest, tv);
	tdx = do_timer_list("tv5", vec_size, vec, (void *)td, &highest, tv);

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
		} else 
			fprintf(fp, "  %s  ", mkstring(buf, 16, CENTER|LONG_HEX,
				MKSTR(td[i].address)));
		
		if (is_kernel_text(td[i].function)) 
			fprintf(fp, "%lx  <%s>\n",
                        	td[i].function,
                        	value_to_symstr(td[i].function, buf, 0));
		else {
			fprintf(fp, "%lx  ", td[i].function);
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
init_tv_ranges(struct tv_range *tv, int vec_root_size, int vec_size)
{
	if (INVALID_SIZE(timer_vec_root)) {
		SIZE(timer_vec_root) = STRUCT_SIZE("timer_vec_root");
		SIZE(timer_vec) = STRUCT_SIZE("timer_vec");
	}

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
do_timer_list(char *tvn, 
	      int size, 
	      ulong *vec, 
	      void *option, 
	      ulong *highest,
	      struct tv_range *tv)
{
	int i, t; 
	int count, tdx;
	ulong expires, function;
	ulong vec_kvaddr;
	struct timer_data *td;
	char *timer_list_buf;
	ulong *timer_list;
	int timer_cnt;
        struct list_data list_data, *ld;
	long sz;

	if (STREQ(tvn, "tv1"))
		vec_kvaddr = symbol_value(tvn) + OFFSET(timer_vec_root_vec);
	else
		vec_kvaddr = symbol_value(tvn) + OFFSET(timer_vec_vec);

	td = option ? (struct timer_data *)option : NULL;
	if (td) {
		tdx = 0;
		while (td[tdx].function)
			tdx++;
	}

        if (OFFSET(timer_list_list) >= 0)
		sz = SIZE(list_head) * size;
	else 
		sz = sizeof(ulong) * size;

        readmem(vec_kvaddr, KVADDR, vec, sz, "timer_list vec array",
                FAULT_ON_ERROR);

	if (OFFSET(timer_list_list) >= 0)
		goto new_timer_list_format;

	ld = &list_data;
	timer_list_buf = GETBUF(SIZE(timer_list));

        for (i = count = 0; i < size; i++) {
                if (vec[i]) {
			BZERO(ld, sizeof(struct list_data));
			ld->start = vec[i];
			ld->member_offset = OFFSET(timer_list_next);

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
                ld->list_head_offset = OFFSET(timer_list_list);
		ld->end = vec_kvaddr;

                hq_open();
                timer_cnt = do_list(ld);
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

	if (!(pc->flags & MFD_RDWR))
		error(FATAL, "cannot write to /dev/mem (uid: %d)\n",
			getuid());

	writemem(pid_to_task(pc->program_pid) + OFFSET(task_struct_pid), KVADDR,
		&zero_pid, sizeof(pid_t), "zero pid", FAULT_ON_ERROR);

	exit(0);
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
		if (!recd_address && STRUCT_EXISTS("wait_queue")) {
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
	if (STRUCT_EXISTS("wait_queue")) {
		task_offset = MEMBER_OFFSET("wait_queue", "task");
		next_offset = MEMBER_OFFSET("wait_queue", "next");
		ld->end = wq;
		ld->start = wq;
		ld->member_offset = next_offset;
		ld->list_head_offset = task_offset;

		start_index = 0;
	} else if (STRUCT_EXISTS("__wait_queue")) {
		ulong task_list_offset;

                next_offset = MEMBER_OFFSET("list_head", "next");
                task_offset = MEMBER_OFFSET("__wait_queue", "task");
                task_list_offset = MEMBER_OFFSET("__wait_queue_head",
                                        "task_list");
                ld->end = ld->start = wq + task_list_offset + next_offset;
                ld->list_head_offset = MEMBER_OFFSET("__wait_queue",
                                                     "task_list");
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
	}
}
