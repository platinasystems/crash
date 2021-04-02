/* main.c - core analysis suite
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
 * BitKeeper ID: @(#)main.c 1.16
 *
 * 09/28/00  ---    Transition to CVS version control
 *
 * CVS: $Revision: 1.64 $ $Date: 2002/01/30 19:28:34 $
 */

#include "defs.h"
#include <curses.h>

static void setup_environment(char *);
static int is_external_command(void);
static int is_builtin_command(void);
static int is_input_file(void);

int
main(int argc, char **argv)
{
	int c;

	setup_environment(argv[0]);

	/* 
	 *  Get and verify command line options.
	 */
	optind = 0;
	while ((c = getopt(argc, argv, "n:gh:e:i:s:vc:d:t")) > 0) {
		switch (c)
		{
		case 'g':
			pc->flags |= KERNEL_DEBUG_QUERY;
			break;

		case 'n':
			if (strstr(optarg, "z"))
				pc->flags |= NAMELIST_NO_GZIP;
			break;

		case 'h':
			cmd_usage(optarg, COMPLETE_HELP);
			exit(0);
			
		case 'e':
			if (STREQ(optarg, "vi"))
				pc->editing_mode = "vi";
			else if (STREQ(optarg, "emacs"))
				pc->editing_mode = "emacs";
			else
				fprintf(fp, "invalid edit mode: %s\n", optarg);	
			break;

		case 't':
			pc->flags |= GET_TIMESTAMP;
			break;

		case 'i':
			pc->input_file = optarg;
			pc->flags |= CMDLINE_IFILE;
			break;

		case 'v':
			display_version();
			display_gdb_banner();
			exit(0);

		case 's':
			if (STREQ(optarg, "ilent")) {
				pc->flags |= SILENT;
				pc->flags &= ~SCROLL;
				pc->scroll_command = SCROLL_NONE;
			}
			break;

		case 'c':
			create_console_device(optarg);
			break;

		case 'd': 
			pc->debug = atol(optarg);
			set_lkcd_debug(pc->debug);
			set_vas_debug(pc->debug);
			break;

		default:
			program_usage();
		}
	}

	display_version();

	/*
	 *  Take the kernel and dumpfile arguments in either order.
	 */
	while (argv[optind]) {

		if (is_remote_daemon(argv[optind])) {
                	if (pc->flags & (MCLXCD|LKCD|S390D|S390XD)) {
				error(INFO, 
				      "too many dumpfile/memory arguments\n");
				program_usage();
			}
			pc->flags |= DAEMON;
			optind++;
			continue;
		}

       		if (!file_exists(argv[optind], NULL)) {
                	error(INFO, "%s: %s\n", argv[optind], strerror(ENOENT));
                	program_usage();
        	}

		if (is_elf_file(argv[optind])) {
			if (pc->namelist) {
                               	error(INFO, "too many namelist arguments\n");
                               	program_usage();
			}
			pc->namelist = argv[optind];

		} else if (!(pc->flags & KERNEL_DEBUG_QUERY)) {

			if (STREQ(argv[optind], "/dev/mem")) {
                        	if (pc->flags & 
				    (MCLXCD|LKCD|DEVMEM|S390D|S390XD)) {
                                	error(INFO, 
                                            "too many dumpfile arguments\n");
                                	program_usage();
                        	}
				pc->flags |= DEVMEM;
				pc->dumpfile = NULL;
				pc->readmem = read_dev_mem;
				pc->writemem = write_dev_mem;

			} else if (is_lkcd_compressed_dump(argv[optind])) {
				if (pc->flags & 
				    (MCLXCD|LKCD|DEVMEM|S390D|S390XD)) {
                                        error(INFO,
                                            "too many dumpfile arguments\n");
                                        program_usage();
                                }
                                pc->flags |= LKCD;
                                pc->dumpfile = argv[optind];
				pc->readmem = read_lkcd_dumpfile;
				pc->writemem = write_lkcd_dumpfile;

			} else if (is_mclx_compressed_dump(argv[optind])) {
				if (pc->flags & 
				    (MCLXCD|LKCD|DEVMEM|S390D|S390XD)) {
					error(INFO,
                                            "too many dumpfile arguments\n");
                                        program_usage();
                                }
				pc->flags |= MCLXCD;
				pc->dumpfile = argv[optind];
				pc->readmem = read_mclx_dumpfile;
				pc->writemem = write_mclx_dumpfile;

                        } else if (is_s390_dump(argv[optind])) {
                                if (pc->flags &
                                    (MCLXCD|LKCD|DEVMEM|S390D|S390XD)) {
                                        error(INFO,
                                            "too many dumpfile arguments\n");
                                        program_usage();
                                }
                                pc->flags |= S390D;
                                pc->dumpfile = argv[optind];
                                pc->readmem = read_s390_dumpfile;
                                pc->writemem = write_s390_dumpfile;

                        } else if (is_s390x_dump(argv[optind])) {
                                if (pc->flags &
                                    (MCLXCD|LKCD|DEVMEM|S390D|S390XD)) {
                                        error(INFO,
                                            "too many dumpfile arguments\n");
                                        program_usage();
                                }
                                pc->flags |= S390XD;
                                pc->dumpfile = argv[optind];
                                pc->readmem = read_s390x_dumpfile;
                                pc->writemem = write_s390x_dumpfile;

			} else { 
				error(INFO, "%s: not a supported dumpfile\n",
					argv[optind]);
				error(INFO, "%s: not an uncompressed kernel\n",
                                        argv[optind]);
				error(FATAL, NULL);
			}
		}
		optind++;
	}
	
        if (setjmp(pc->main_loop_env))
                exit(1);

	/*
	 *  Initialize various subsystems.
	 */
	fd_init();
	buf_init();
        cmdline_init();
        mem_init();
	machdep_init(PRE_SYMTAB);
        symtab_init();
	machdep_init(PRE_GDB);
	kernel_init(PRE_GDB);
	verify_version();
        datatype_init();

	/*
	 *  gdb_main_loop() modifies "command_loop_hook" to point to the 
         *  main_loop() function below, and then calls gdb's main() function.
         *  After gdb initializes itself, it calls back to main_loop().
	 */
	gdb_main_loop(argc, argv);   

	exit(0);  
}

/*
 *  This routine is called from above, but also will be re-entered
 *  as part of gdb's SIGINT handling.  Since GDB_INIT and RUNTIME 
 *  will be set on re-entrancy, the initialization routines won't 
 *  be called.  This can be avoided by always making gdb ignore SIGINT.
 */
void
main_loop(void)
{
        if (!(pc->flags & GDB_INIT)) {
		gdb_session_init();
		kernel_init(POST_GDB);
		machdep_init(POST_GDB);
        	vm_init();
        	module_init();
        	help_init();
        	hq_init();
        	task_init();
        	vfs_init();
		net_init();
		dev_init();
		machdep_init(POST_INIT);
	} else
		SIGACTION(SIGINT, restart, &pc->sigaction, NULL);

        /*
         *  Display system statistics and current context.
         */
        if (!(pc->flags & SILENT) && !(pc->flags & RUNTIME)) {
                display_sys_stats();
                show_context(CURRENT_CONTEXT(), 5, TRUE);
                fprintf(fp, "\n");
        }

        pc->flags |= RUNTIME;

	/*
	 *  Return here if a non-recoverable error occurs
	 *  during command execution.
	 */
	if (setjmp(pc->main_loop_env)) {
		;
	}

	/*
	 *  get_command_line() reads, parses and stores input command lines
	 *  in the global args[] array.  exec_command() figures out what to 
         *  do with the parsed line.
	 */
	while (TRUE) {
		get_command_line();
		exec_command();
	}
}

/*
 *  Most of the time args[0] simply contains the name string of a command
 *  found in the global command_table[].  Special consideration is done for 
 *  dealing with input files, "known" external commands, and built-in commands.
 *  If none of the above apply, the args[0] string is checked against the
 *  known list of structure, union and typedef names, and if found, passed
 *  on to cmd_struct(), cmd_union() or cmd_whatis().
 */
void
exec_command(void)
{
	struct command_table_entry *ct;

reattempt:
	if (!args[0])
		return;

	optind = argerrs = 0;

	if ((ct = get_command_table_entry(args[0]))) {
                if (ct->flags & REFRESH_TASK_TABLE)
                        tt->refresh_task_table();
                if (!STREQ(pc->curcmd, pc->program_name))
                        pc->lastcmd = pc->curcmd;
                pc->curcmd = ct->name;
                (*ct->func)();
                pc->lastcmd = pc->curcmd;
                pc->curcmd = pc->program_name;
                return;
	}

	if (is_input_file())
		return;

	if (is_external_command())
		return;

	if (is_builtin_command())
		return;

        if (is_datatype_command()) 
                goto reattempt;

	if (is_gdb_command(TRUE, FAULT_ON_ERROR)) 
		goto reattempt;

	if (REMOTE() && remote_execute())
		return;

	pc->curcmd = pc->program_name;
	error(INFO, "command not found: %s\n", args[0]);
}


/*
 *  Find the command_table structure associated with a command name.
 */
struct command_table_entry *
get_command_table_entry(char *name)
{       
        struct command_table_entry *cp;
        struct extension_table *ext;
  
        for (cp = &base_command_table[0]; cp->name; cp++) {
                if (STREQ(cp->name, name))
                        return cp;
        }
                
        for (ext = extension_table; ext; ext = ext->next) {
                for (cp = ext->command_table; cp->name; cp++) {
                        if (STREQ(cp->name, name)) {
                                return cp;
			}
                }
        }       

        return NULL;
}


static int
is_input_file(void)
{
        if (STREQ(args[0], "<")) {
                exec_input_file();
                return TRUE;
        }

	return FALSE;
}

static int
is_builtin_command(void)
{
	int i;
	struct remote_file remote_file, *rfp;

	/*
	 *  cmd_test() is used strictly for debugging -- but not advertised
	 *  in the help menu.
	 */ 
        if (STREQ(args[0], "test")) {
		pc->curcmd = "test";
                cmd_test();
                return TRUE;
        }

        if (STREQ(args[0], "save")) {
		pc->curcmd = "save";
		rfp = &remote_file;
		BZERO(rfp, sizeof(struct remote_file));
		rfp->flags |= REMOTE_VERBOSE;
		for (i = 1; i < argcnt; i++) {
			rfp->filename = args[i];
			get_remote_file(rfp); 
		}
		return TRUE;
	}

	return FALSE;
}

/*
 *  Pure laziness -- to avoid having to type the exclamation point at the
 *  beginning of the line.
 */
static int
is_external_command(void)
{
	int i;
	char *cmd;
	char command[BUFSIZE];

	cmd = args[0];

        if (STREQ(cmd, "vi") ||
            STREQ(cmd, "pwd") ||
            STREQ(cmd, "grep") ||
            STREQ(cmd, "cat") ||
            STREQ(cmd, "more") ||
            STREQ(cmd, "less") ||
	    STREQ(cmd, "echo") ||
            STREQ(cmd, "ls")) {
                sprintf(command, "%s", cmd);
                for (i = 1; i < argcnt; i++) {
                        strcat(command, " ");
			if (strstr(args[i], " ")) {
				strcat(command, "\"");
                        	strcat(command, args[i]);
				strcat(command, "\"");
			}
			else
                        	strcat(command, args[i]);
                }
                system(command);
                return TRUE;
        }

	return FALSE;
}

void
cmd_quit(void)
{
	if (REMOTE())
		remote_exit();

	exit(0);
}

void
cmd_mach(void)
{
	machdep->cmd_mach();
}


void
program_usage(void)
{
	fprintf(fp, 
    "usage: %s [-v][-silent][-i inputfile][-d num] [namelist] [dumpfile]\n\n", 
		pc->program_name);
	exit(1);
}

static void
setup_environment(char *program)
{
	char *p1;
	char buf[BUFSIZE];
	FILE *afp;

	/*
	 *  Program output typically goes via "fprintf(fp, ...)", but the 
	 *  contents of fp are modified on the fly to handle redirection
	 *  to pipes or output files.
	 */
	fp = stdout;

	/*
	 *  Start populating the program_context structure.  It's used so
	 *  frequently that "pc" has been declared globally to point to the
	 *  "program_context" structure.
	 */
        pc->program_name = (char *)basename(program);
        pc->program_version = build_version;
	pc->program_pid = (ulong)getpid();
        pc->curcmd = pc->program_name;
        pc->flags = (HASH|SCROLL);
	pc->confd = -2;
	pc->machine_type = MACHINE_TYPE;
	pc->readmem = read_dev_mem;      /* defaults until argv[] is parsed */
	pc->writemem = write_dev_mem;
	machdep->bits = sizeof(long) * 8;

	/*
	 *  Get gdb version before initializing it since this might be one 
         *  of the short-hand commands that need it without running gdb.
	 */
	get_gdb_version();

	/* 
	 *  Set up the default scrolling behavior for terminal output.
	 */
	if (isatty(fileno(stdout))) {
        	if (file_exists("/usr/bin/less", NULL)) {
			pc->flags |= SCROLL;
			pc->scroll_command = SCROLL_LESS;
		} else if (file_exists("/bin/more", NULL)) {
			pc->flags |= SCROLL;
			pc->scroll_command = SCROLL_MORE;
		} else {
                	pc->scroll_command = SCROLL_NONE;
                	pc->flags &= ~SCROLL;
        	}
	} 

	/*
	 *  Setup the readline command line editing mode based upon the 
	 *  following order:
	 *
	 *   (1) EDITOR environment variable
         *   (2) overridden by any .crashrc entry: "set vi" or "set emacs"
         *   (3) RL_VI_MODE if not set anywhere else
	 */

	pc->flags |= READLINE;
	pc->editing_mode = "no_mode";

	if ((p1 = getenv("EDITOR"))) {
		if (strstr(p1, "vi"))
			pc->editing_mode = "vi";
		if (strstr(p1, "emacs"))
			pc->editing_mode = "emacs";
	}

	/*
	 *  Resolve $HOME .rc file first, then the one in the local directory.
         *  Note that only "set" and "alias" commands are done at this time.
	 */
	alias_init();

	if ((p1 = getenv("HOME"))) {
		if ((pc->home = (char *)malloc(strlen(p1)+1)) == NULL) {
                        error(INFO, "home directory malloc: %s\n",
                                strerror(errno));
			pc->home = "(unknown)";
		} else
			strcpy(pc->home, p1);
	        sprintf(buf, "%s/.%src", pc->home, pc->program_name);
	        if (file_exists(buf, NULL)) {
	                if ((afp = fopen(buf, "r")) == NULL)
	                        error(INFO, "cannot open %s: %s\n",
	                                buf, strerror(errno));
	                else {
	                        while (fgets(buf, BUFSIZE, afp))
	                                resolve_rc_cmd(buf, ALIAS_RCHOME);
	                        fclose(afp);
	                }
	        }
	}

        sprintf(buf, ".%src", pc->program_name);
	if (file_exists(buf, NULL)) {
		if ((afp = fopen(buf, "r")) == NULL)
                        error(INFO, "cannot open %s: %s\n",
				buf, strerror(errno));
		else {
			while (fgets(buf, BUFSIZE, afp)) 
				resolve_rc_cmd(buf, ALIAS_RCLOCAL);
			fclose(afp);
		}
	}

	if (STREQ(pc->editing_mode, "no_mode"))
		pc->editing_mode = "vi";
}


/*
 *  "help -p" output
 */
void
dump_program_context(void)
{
	int i;
	int others = 0;
	char buf[BUFSIZE];
	char buf2[BUFSIZE];

	fprintf(fp, "     program_name: %s\n", pc->program_name);
	fprintf(fp, "  program_version: %s\n", pc->program_version);
	fprintf(fp, "      gdb_version: %s\n", pc->gdb_version);
	fprintf(fp, "      program_pid: %ld\n", pc->program_pid);
	fprintf(fp, "           prompt: \"%s\"\n", pc->prompt);
	fprintf(fp, "            flags: %llx ", pc->flags);

	if (pc->flags)
		sprintf(buf, "(");
	if (pc->flags & RUNTIME)
		sprintf(&buf[strlen(buf)], "%sRUNTIME", others++ ? "|" : "");
	if (pc->flags & LIVE_SYSTEM)
		sprintf(&buf[strlen(buf)], "%sLIVE_SYSTEM", 
			others++ ? "|" : "");
	if (pc->flags & TTY)
		sprintf(&buf[strlen(buf)], "%sTTY", others++ ? "|" : "");
        if (pc->flags & IN_FOREACH)
                sprintf(&buf[strlen(buf)], "%sIN_FOREACH", others++ ? "|" : "");
        if (pc->flags & MFD_RDWR)
                sprintf(&buf[strlen(buf)], "%sMFD_RDWR", others++ ? "|" : "");
        if (pc->flags & KFD_RDWR)
                sprintf(&buf[strlen(buf)], "%sKFD_RDWR", others++ ? "|" : "");
        if (pc->flags & DFD_RDWR)
                sprintf(&buf[strlen(buf)], "%sDFD_RDWR", others++ ? "|" : "");
        if (pc->flags & SILENT)
                sprintf(&buf[strlen(buf)], "%sSILENT", others++ ? "|" : "");
        if (pc->flags & HASH)
                sprintf(&buf[strlen(buf)], "%sHASH", others++ ? "|" : "");
        if (pc->flags & SCROLL)
                sprintf(&buf[strlen(buf)], "%sSCROLL", others++ ? "|" : "");
        if (pc->flags & NO_CONSOLE)
                sprintf(&buf[strlen(buf)], "%sNO_CONSOLE", others++ ? "|" : "");
        if (pc->flags & MCLXCD)
                sprintf(&buf[strlen(buf)], "%sMCLXCD", others++ ? "|" : "");
        if (pc->flags & RUNTIME_IFILE)
                sprintf(&buf[strlen(buf)], "%sRUNTIME_IFILE", 
			others++ ? "|" : "");
        if (pc->flags & CMDLINE_IFILE)
                sprintf(&buf[strlen(buf)], "%sCMDLINE_IFILE", 
			others++ ? "|" : "");
        if (pc->flags & DROP_CORE)
                sprintf(&buf[strlen(buf)], "%sDROP_CORE", others++ ? "|" : "");
        if (pc->flags & LKCD)
                sprintf(&buf[strlen(buf)], "%sLKCD", others++ ? "|" : "");
        if (pc->flags & DAEMON)
                sprintf(&buf[strlen(buf)], "%sDAEMON", others++ ? "|" : "");
        if (pc->flags & GDB_INIT)
                sprintf(&buf[strlen(buf)], "%sGDB_INIT", others++ ? "|" : "");
        if (pc->flags & IN_GDB)
                sprintf(&buf[strlen(buf)], "%sIN_GDB", others++ ? "|" : "");
	if (pc->flags & RCHOME_IFILE)
                sprintf(&buf[strlen(buf)], "%sRCHOME_IFILE", 
			others++ ? "|" : "");
	if (pc->flags & RCLOCAL_IFILE)
                sprintf(&buf[strlen(buf)], "%sRCLOCAL_IFILE", 
			others++ ? "|" : "");
	if (pc->flags & READLINE)
                sprintf(&buf[strlen(buf)], "%sREADLINE", others++ ? "|" : "");
        if (pc->flags & _SIGINT_)
                sprintf(&buf[strlen(buf)], 
			"%s_SIGINT_", others++ ? "|" : "");
        if (pc->flags & IN_RESTART)
                sprintf(&buf[strlen(buf)], "%sIN_RESTART", others++ ? "|" : "");
        if (pc->flags & KERNEL_DEBUG_QUERY)
                sprintf(&buf[strlen(buf)], 
			"%sKERNEL_DEBUG_QUERY", others++ ? "|" : "");
        if (pc->flags & DEVMEM)
                sprintf(&buf[strlen(buf)], 
			"%sDEVMEM", others++ ? "|" : "");
        if (pc->flags & REM_LIVE_SYSTEM)
                sprintf(&buf[strlen(buf)],
                        "%sREM_LIVE_SYSTEM", others++ ? "|" : "");
        if (pc->flags & MEMSRC_LOCAL)
                sprintf(&buf[strlen(buf)],
                        "%sMEMSRC_LOCAL", others++ ? "|" : "");
        if (pc->flags & NAMELIST_LOCAL)
                sprintf(&buf[strlen(buf)],
                        "%sNAMELIST_LOCAL", others++ ? "|" : "");
        if (pc->flags & DUMPFILE_SAVED)
                sprintf(&buf[strlen(buf)],
                        "%sDUMPFILE_SAVED", others++ ? "|" : "");
        if (pc->flags & NAMELIST_SAVED)
                sprintf(&buf[strlen(buf)],
                        "%sNAMELIST_SAVED", others++ ? "|" : "");
        if (pc->flags & UNLINK_NAMELIST)
                sprintf(&buf[strlen(buf)],
                        "%sUNLINK_NAMELIST", others++ ? "|" : "");
        if (pc->flags & NAMELIST_UNLINKED)
                sprintf(&buf[strlen(buf)],
                        "%sNAMELIST_UNLINKED", others++ ? "|" : "");
        if (pc->flags & REM_MCLXCD)
                sprintf(&buf[strlen(buf)],
                        "%sREM_MCLXCD", others++ ? "|" : "");
        if (pc->flags & REM_LKCD)
                sprintf(&buf[strlen(buf)],
                        "%sREM_LKCD", others++ ? "|" : "");
        if (pc->flags & NAMELIST_NO_GZIP)
                sprintf(&buf[strlen(buf)],
                        "%sNAMELIST_NO_GZIP", others++ ? "|" : "");
        if (pc->flags & UNLINK_MODULES)
                sprintf(&buf[strlen(buf)],
                        "%sUNLINK_MODULES", others++ ? "|" : "");
        if (pc->flags & S390D)
                sprintf(&buf[strlen(buf)],
                        "%sS390D", others++ ? "|" : "");
        if (pc->flags & S390XD)
                sprintf(&buf[strlen(buf)],
                        "%sS390XD", others++ ? "|" : "");
        if (pc->flags & REM_S390D)
                sprintf(&buf[strlen(buf)],
                        "%sREM_S390D", others++ ? "|" : "");
        if (pc->flags & REM_S390XD)
                sprintf(&buf[strlen(buf)],
                        "%sREM_S390XD", others++ ? "|" : "");

	if (pc->flags)
		strcat(buf, ")");

	if (strlen(buf)) {
		if (strlen(buf) > 54) {
			sprintf(buf2, "\n%s\n", 
				mkstring(buf, 80, CENTER|LJUST, NULL));
			if (strlen(buf2) <= 82) 
				fprintf(fp, "%s", buf2);
			else {
				for (i = strlen(buf2)-1; i; i--) {
					if ((buf2[i] == '|') && (i < 80))
						break;
				}

				strcpy(buf, buf2);
				buf[i+1] = NULLCHAR;
				fprintf(fp, "%s\n %s", buf, &buf2[i+1]);
			}
		}
		else
			fprintf(fp, "%s\n", buf);
	}

	fprintf(fp, "         namelist: %s\n", pc->namelist);
	fprintf(fp, "         dumpfile: %s\n", pc->dumpfile);
	fprintf(fp, "     machine_type: %s\n", pc->machine_type);
	fprintf(fp, "     editing_mode: %s\n", pc->editing_mode);
	fprintf(fp, "              nfd: %d\n", pc->nfd);
	fprintf(fp, "              kfd: %d\n", pc->kfd);
	fprintf(fp, "              mfd: %d\n", pc->mfd);
	fprintf(fp, "              dfd: %d\n", pc->dfd);
	fprintf(fp, "            confd: %d\n", pc->confd);
#ifdef USE_MMAP
	fprintf(fp, "        mmap_addr: %lx\n", pc->mmap_addr);
	fprintf(fp, "        mmap_phys: %lx\n", pc->mmap_phys);
	fprintf(fp, "           remaps: %lu\n", pc->remaps);
	fprintf(fp, "          maphits: %lu\n", pc->maphits);
#endif
	fprintf(fp, "             home: %s\n", pc->home);
	fprintf(fp, "     command_line: ");
	if (STRNEQ(pc->command_line, args[0]))
		fprintf(fp, "%s\n", concat_args(buf, 0, FALSE));
	else
		fprintf(fp, "%s\n", pc->command_line);
	fprintf(fp, "        orig_line: %s\n", pc->orig_line);
	fprintf(fp, "        eoc_index: %d\n", pc->eoc_index);
	fprintf(fp, "         readline: %lx\n", (ulong)pc->readline);
	fprintf(fp, "           my_tty: %s\n", pc->my_tty);
	fprintf(fp, "            debug: %ld\n", pc->debug);
	fprintf(fp, "          console: %s\n", pc->console);
	fprintf(fp, "        pipefd[2]: %d,%d\n", pc->pipefd[0], pc->pipefd[1]);
	fprintf(fp, "           nullfp: %lx\n", (ulong)pc->nullfp);
	fprintf(fp, "          stdpipe: %lx\n", (ulong)pc->stdpipe);
	fprintf(fp, "             pipe: %lx\n", (ulong)pc->pipe);
	fprintf(fp, "            ifile: %lx\n", (ulong)pc->ifile);
	fprintf(fp, "            ofile: %lx\n", (ulong)pc->ofile);
	fprintf(fp, "       ifile_pipe: %lx\n", (ulong)pc->ifile_pipe);
	fprintf(fp, "      ifile_ofile: %lx\n", (ulong)pc->ifile_ofile);
	fprintf(fp, "       input_file: %s\n", pc->input_file);
	fprintf(fp, "   scroll_command: %s\n", 
		pc->scroll_command == SCROLL_NONE ? "(none)" :
		    pc->scroll_command == SCROLL_LESS ? 
			"/usr/bin/less" : "/bin/more");

	fprintf(fp, "         redirect: %lx ", pc->redirect);
	if (pc->redirect)
		sprintf(buf, "(");
	others = 0;
	if (pc->redirect & FROM_COMMAND_LINE)
		sprintf(&buf[strlen(buf)], 
			"%sFROM_COMMAND_LINE", others++ ? "|" : "");
	if (pc->redirect & FROM_INPUT_FILE)
		sprintf(&buf[strlen(buf)], 
			"%sFROM_INPUT_FILE", others++ ? "|" : "");
	if (pc->redirect & REDIRECT_NOT_DONE)
		sprintf(&buf[strlen(buf)], 
			"%sREDIRECT_NOT_DONE", others++ ? "|" : "");
	if (pc->redirect & REDIRECT_TO_PIPE)
		sprintf(&buf[strlen(buf)], 
			"%sREDIRECT_TO_PIPE", others++ ? "|" : "");
	if (pc->redirect & REDIRECT_TO_STDPIPE)
		sprintf(&buf[strlen(buf)], 
			"%sREDIRECT_TO_STDPIPE", others++ ? "|" : "");
	if (pc->redirect & REDIRECT_TO_FILE)
		sprintf(&buf[strlen(buf)], 
			"%sREDIRECT_TO_FILE", others++ ? "|" : "");
	if (pc->redirect & REDIRECT_FAILURE)
		sprintf(&buf[strlen(buf)], 
			"%sREDIRECT_FAILURE", others++ ? "|" : "");
	if (pc->redirect & REDIRECT_SHELL_ESCAPE)
		sprintf(&buf[strlen(buf)], 
			"%sREDIRECT_SHELL_ESCAPE", others++ ? "|" : "");
	if (pc->redirect & REDIRECT_SHELL_COMMAND)
		sprintf(&buf[strlen(buf)], 
			"%sREDIRECT_SHELL_COMMAND", others++ ? "|" : "");
	if (pc->redirect & REDIRECT_PID_KNOWN)
		sprintf(&buf[strlen(buf)], 
			"%sREDIRECT_PID_KNOWN", others++ ? "|" : "");
	if (pc->redirect & REDIRECT_MULTI_PIPE)
		sprintf(&buf[strlen(buf)], 
			"%sREDIRECT_MULTI_PIPE", others++ ? "|" : "");
	if (pc->redirect)
		strcat(buf, ")");

        if (strlen(buf)) {
                if (strlen(buf) > 54)
                        fprintf(fp, "\n%s\n",
                                mkstring(buf, 80, CENTER|LJUST, NULL));
                else
                        fprintf(fp, "%s\n", buf);
        }

	if (!pc->redirect)
		fprintf(fp, "\n");

	fprintf(fp, "         pipe_pid: %d\n", pc->pipe_pid);
	fprintf(fp, "      stdpipe_pid: %d\n", pc->stdpipe_pid);
	fprintf(fp, "     pipe_command: %s\n", pc->pipe_command);
	if (pc->symfile && pc->symfile2) {
		fprintf(fp, "          symfile: %lx  (%ld)\n", 
			(ulong)pc->symfile, (ulong)ftell(pc->symfile));
		fprintf(fp, "         symfile2: %lx  (%ld)\n", 
			(ulong)pc->symfile2, (ulong)ftell(pc->symfile2));
	} else {
		fprintf(fp, "          symfile: %lx \n", (ulong)pc->symfile);
		fprintf(fp, "         symfile2: %lx \n", (ulong)pc->symfile2);
	}
	fprintf(fp, "          tmpfile: %lx\n", (ulong)pc->tmpfile);
	fprintf(fp, "         saved_fp: %lx\n", (ulong)pc->saved_fp);
	fprintf(fp, "           tmp_fp: %lx\n", (ulong)pc->tmp_fp);
	fprintf(fp, "         tmpfile2: %lx\n", (ulong)pc->tmpfile2);
	fprintf(fp, "      symbol_file: %s\n", pc->symbol_file);
	fprintf(fp, "      sym_maxline: %d\n", pc->sym_maxline);

	fprintf(fp, "           curcmd: %s\n", pc->curcmd);
	fprintf(fp, "          lastcmd: %s\n", pc->lastcmd);
	fprintf(fp, "      cur_gdb_cmd: %d  %s\n", pc->cur_gdb_cmd,
		gdb_command_string(pc->cur_gdb_cmd, buf, FALSE));
	fprintf(fp, "     last_gdb_cmd: %d  %s\n", pc->last_gdb_cmd,
		gdb_command_string(pc->last_gdb_cmd, buf, FALSE));
	fprintf(fp, "          cur_req: %lx\n", (ulong)pc->cur_req);
	fprintf(fp, "       sigint_cnt: %d\n", pc->sigint_cnt);
	fprintf(fp, "        sigaction: %lx\n", (ulong)&pc->sigaction);
	fprintf(fp, "    gdb_sigaction: %lx\n", (ulong)&pc->gdb_sigaction);
	fprintf(fp, "    main_loop_env: %lx\n", (ulong)&pc->main_loop_env);
	fprintf(fp, " foreach_loop_env: %lx\n", (ulong)&pc->foreach_loop_env);
	fprintf(fp, "gdb_interface_env: %lx\n", (ulong)&pc->gdb_interface_env);
	fprintf(fp, "     termios_orig: %lx\n", (ulong)&pc->termios_orig);
	fprintf(fp, "      termios_raw: %lx\n", (ulong)&pc->termios_raw);
	fprintf(fp, "            ncmds: %d\n", pc->ncmds);
	fprintf(fp, "          cmdlist: %lx\n", (ulong)pc->cmdlist);
	fprintf(fp, "        cmdlistsz: %d\n", pc->cmdlistsz);
	fprintf(fp, "     output_radix: %d (%s)\n", pc->output_radix,
		pc->output_radix == 16 ? 
		"hex" : ((pc->output_radix == 10) ? "decimal" : "???"));

	fprintf(fp, "           server: %s\n", pc->server);
	fprintf(fp, "       server_pid: %ld\n", pc->server_pid);
	fprintf(fp, "             port: %d\n", pc->port);
	fprintf(fp, "           sockfd: %d\n", pc->sockfd);
	fprintf(fp, "    server_memsrc: %s\n", pc->server_memsrc);
	fprintf(fp, "  server_namelist: %s\n", pc->server_namelist);
	fprintf(fp, "             rmfd: %d\n", pc->rmfd);
	fprintf(fp, "             rkfd: %d\n", pc->rkfd);
	fprintf(fp, "       rcvbufsize: %ld\n", pc->rcvbufsize);
	if (pc->readmem == read_dev_mem)
		fprintf(fp, "          readmem: read_dev_mem()\n");
	else if (pc->readmem == read_mclx_dumpfile)
		fprintf(fp, "          readmem: read_mclx_dumpfile()\n");
	else if (pc->readmem == read_lkcd_dumpfile)
		fprintf(fp, "          readmem: read_lkcd_dumpfile()\n");
	else if (pc->readmem == read_daemon)
		fprintf(fp, "          readmem: read_daemon()\n");
	else
		fprintf(fp, "          readmem: %lx\n", (ulong)pc->readmem);
        if (pc->writemem == write_dev_mem)
                fprintf(fp, "         writemem: write_dev_mem()\n");
        else if (pc->writemem == write_mclx_dumpfile)
                fprintf(fp, "         writemem: write_mclx_dumpfile()\n");
        else if (pc->writemem == write_lkcd_dumpfile)
                fprintf(fp, "         writemem: write_lkcd_dumpfile()\n");
        else if (pc->writemem == write_daemon)
                fprintf(fp, "         writemem: write_daemon()\n");
        else
                fprintf(fp, "         writemem: %lx\n", (ulong)pc->writemem);

	fprintf(fp, "  dumpfile memory: %d\n", 
		dumpfile_memory(DUMPFILE_MEM_USED)); 
	fprintf(fp, "           curext: %lx\n", (ulong)pc->curext); 
	fprintf(fp, "             sbrk: %lx\n", (ulong)pc->sbrk); 
}

/*
 *  "help -B" output
 */
void
dump_build_data(void)
{
        fprintf(fp, "build_command: %s\n", build_command);
        fprintf(fp, "   build_data: %s\n", build_data);
        fprintf(fp, "build_version: %s\n", build_version);
}
