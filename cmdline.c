/* cmdline.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002, 2003, 2004 David Anderson
 * Copyright (C) 2002, 2003, 2004 Red Hat, Inc. All rights reserved.
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
 * BitKeeper ID: @(#)cmdline.c 1.16
 *
 * 09/28/00  ---    Transition to CVS version control
 *
 * CVS: $Revision: 1.14 $ $Date: 2004/05/21 15:19:27 $
 */

#include "defs.h"

static void restore_sanity(void);
static void restore_ifile_sanity(void);
static int pseudo_command(char *);
static void check_special_handling(char *);
static int is_shell_script(char *);
static void list_aliases(char *);
static int allocate_alias(int);
static int alias_exists(char *);
static void resolve_aliases(void);
static int setup_redirect(int);
static int output_command_to_pids(void);
static void set_my_tty(void);
static char *signame(int);
static int setup_stdpipe(void);
static void wait_for_children(ulong);
#define ZOMBIES_ONLY (1)
#define ALL_CHILDREN (2)

#define READLINE_LIBRARY

#include <readline.h>
#include <rldefs.h>
#include <history.h>

static void readline_init(void);

static struct alias_data alias_head = { 0 }; 

void
get_command_line(void)
{
	/*
	 *  Restore normal environment, clearing out any excess baggage
	 *  piled up by the previous command.
	 */
	restore_sanity();
	fp = stdout;
	BZERO(pc->command_line, BUFSIZE);

	if (!(pc->flags & 
	    (READLINE|SILENT|CMDLINE_IFILE|RCHOME_IFILE|RCLOCAL_IFILE))) 
		fprintf(fp, pc->prompt);
	fflush(fp);

	/*
	 *  Input can come from five possible sources:
	 *
	 *    1. an .rc file located in the user's HOME directory.
         *    2. an .rc file located in the current directory.
	 *    3. an input file that was designated by the -i flag at 
	 *       program invocation.
	 *    4. from a terminal.
	 *    5. from a pipe, if stdin is a pipe rather than a terminal.
	 */
	if (pc->flags & RCHOME_IFILE)  
                sprintf(pc->command_line, "< %s/.%src", 
			pc->home, pc->program_name);
	else if (pc->flags & RCLOCAL_IFILE) 
                sprintf(pc->command_line, "< .%src", pc->program_name);
	else if (pc->flags & CMDLINE_IFILE) 
		sprintf(pc->command_line, "< %s", pc->input_file);
	else if (pc->flags & TTY) {
		if (!(pc->readline = readline(pc->prompt))) {
			args[0] = NULL;
			fprintf(fp, "\n");
			return;
		} 

		strcpy(pc->command_line, pc->readline);
		free(pc->readline); 

		clean_line(pc->command_line);
		pseudo_command(pc->command_line);
		strcpy(pc->orig_line, pc->command_line);

		if (strlen(pc->command_line) && !iscntrl(pc->command_line[0])) 
			add_history(pc->command_line);
		
		check_special_handling(pc->command_line);
        } else {
                fflush(fp);
        	if (fgets(pc->command_line, BUFSIZE-1, stdin) == NULL)
			clean_exit(1);
		strcpy(pc->orig_line, pc->command_line);
        }

	/*
	 *  First clean out all linefeeds and leading/trailing spaces.
	 *  Then substitute aliases for the real thing they represent.
	 */
	clean_line(pc->command_line);
	resolve_aliases();

	/*
	 *  Setup output redirection based upon the command line itself or
	 *  based upon the default scrolling behavior, if any.
	 */

	switch (setup_redirect(FROM_COMMAND_LINE))
	{
	case REDIRECT_NOT_DONE:
	case REDIRECT_TO_STDPIPE:
	case REDIRECT_TO_PIPE:
	case REDIRECT_TO_FILE:
		break;

	case REDIRECT_SHELL_ESCAPE:
	case REDIRECT_SHELL_COMMAND:
	case REDIRECT_FAILURE:  
		RESTART();
		break;
	}

	/*
	 *  Setup the global argcnt and args[] array for use by everybody
	 *  during the life of this command.
	 */
	argcnt = parse_line(pc->command_line, args);
}


/*
 *  Allow input file redirection without having to put a space between 
 *  the < and the filename.  Allow the "pointer-to" asterisk to "touch"
 *  the structure/union name.
 */
static void 
check_special_handling(char *s)
{
	char local[BUFSIZE];

	strcpy(local, s);

	if ((local[0] == '*') && (!whitespace(local[1]))) {
		sprintf(s, "* %s", &local[1]);
		return;
	}

        if ((local[0] == '<') && (!whitespace(local[1]))) {
                sprintf(s, "< %s", &local[1]);
                return;
        }
}


/*
 *  At this point the only pseudo commands are the "r" (repeat) and 
 *  the "h" (history) command:
 *
 *    1. an "r" alone, or "!!" along, just means repeat the last command.
 *    2. an "r" followed by a number, means repeat that command from the
 *       history table.
 *    3. an "r" followed by one or more non-decimal characters means to
 *       seek back until a line-beginning match is found. 
 *    4. an "h" alone, or a string beginning with "hi", means history.
 */
static int
pseudo_command(char *input)
{
        int i;
	HIST_ENTRY *entry;
	int idx, found;
	char *p;

        clean_line(input);

        /*  
         *  Just dump all commands that have been entered to date.
         */
        if (STREQ(input, "h") || STRNEQ(input, "hi")) {
                dump_history();
                pc->command_line[0] = NULLCHAR;
                return TRUE;
        }

        if (STREQ(input, "r") || STREQ(input, "!!")) {
                if (!history_offset)
                        error(FATAL, "no commands entered!\n");
                entry = history_get(history_offset);
                strcpy(input, entry->line);
                fprintf(fp, "%s%s\n", pc->prompt, input);
                return TRUE;
        }

        if ((input[0] == 'r') && decimal(&input[1], 0)) {
                if (!history_offset)
                        error(FATAL, "no commands entered!\n");
                p = &input[1];
                goto rerun;
        }


	if (STRNEQ(input, "r ")) {
                if (!history_offset)
                        error(FATAL, "no commands entered!\n");

		p = first_nonspace(&input[1]);
rerun:
		if (decimal(p, 0)) {
			idx = atoi(p);
			if (idx == 0)
				goto invalid_repeat_request;
			if (idx > history_offset) 
				error(FATAL, "command %d not entered yet!\n",
					idx);	
                	entry = history_get(idx);
               		strcpy(input, entry->line);
                	fprintf(fp, "%s%s\n", pc->prompt, input);
                	return TRUE;
		} 

		idx = -1;
		found = FALSE;

        	for (i = history_offset; i > 0; i--) {
                	entry = history_get(i);
			if (STRNEQ(entry->line, p)) {
				found = TRUE;
				break;
			}
        	}

		if (found) {
			strcpy(input, entry->line);
			fprintf(fp, "%s%s\n", pc->prompt, input);
			return TRUE;
		}

invalid_repeat_request:
		fprintf(fp, "invalid repeat request: %s\n", input);
		strcpy(input, "");
		return TRUE;
	}

	return FALSE;
}

/*
 *  Dump the history table in first-to-last chronological order.
 */
void
dump_history(void)
{
        int i;
        HIST_ENTRY **the_history;
        HIST_ENTRY *entry;

        if (!history_offset)
                error(FATAL, "no commands entered!\n");

        the_history = history_list();

        for (i = 0; i < history_offset; i++) {
                entry = the_history[i];
                fprintf(fp, "[%d] %s\n", i+1, entry->line);
        }
}

/*
 *  Parse the command line for pipe or redirect characters:  
 *
 *   1. if a "|" character is found, popen() what comes after it, and 
 *      modify the contents of the global "fp" FILE pointer.
 *   2. if one or two ">" characters are found, fopen() the filename that
 *      follows, and modify the contents of the global "fp" FILE pointer.
 * 
 *  Care is taken to segregate:
 *
 *   1. expressions encompassed by parentheses, or
 *   2. strings encompassed by apostrophes. 
 *
 *  When either of the above are in affect, no redirection is done.
 *
 *  Lastly, if no redirection is requested by the user on the command line,
 *  output is passed to the default scrolling command, which is popen()'d
 *  and again, the contents of the global "fp" FILE pointer is modified.
 *  This default behavior is not performed if the command is coming from
 *  an input file, nor if scrolling has been turned off.
 */
static int
setup_redirect(int origin)
{
	char *p, which;
	int append;
	int expression;
	int string;
	FILE *pipe;
	FILE *ofile;

	pc->redirect = origin;
	pc->eoc_index = 0;

	p = pc->command_line;

        if (STREQ(p, "|") || STREQ(p, "!")) {
        	system("/bin/sh");
		pc->redirect |= REDIRECT_SHELL_ESCAPE;
		return REDIRECT_SHELL_ESCAPE;
	}

	if (FIRSTCHAR(p) == '|' || FIRSTCHAR(p) == '!')
		pc->redirect |= REDIRECT_SHELL_COMMAND;

	expression = string = FALSE;

	while (*p) {
		if (*p == '(')
			expression = TRUE;
		if (*p == ')')
			expression = FALSE;

		if (*p == '"')
			string = !string;

		if (!(expression || string) && 
		    ((*p == '|') || (*p == '!'))) {
			which = *p;
			*p = NULLCHAR;
			pc->eoc_index = p - pc->command_line;
			p++;
			p = strip_beginning_whitespace(p);

			if (!strlen(p)) {
				error(INFO, "no shell command after '%c'\n",
					which);
				pc->redirect |= REDIRECT_FAILURE;
				return REDIRECT_FAILURE;
			}
		
			if (LASTCHAR(p) == '|')
				error(FATAL_RESTART, "pipe to nowhere?\n");

			if (pc->redirect & REDIRECT_SHELL_COMMAND) {
				system(p);
				return REDIRECT_SHELL_COMMAND;
			} 

                        if ((pipe = popen(p, "w")) == NULL) {
                                error(INFO, "cannot open pipe\n");
				pc->redirect |= REDIRECT_FAILURE;
				return REDIRECT_FAILURE;
                        }
                        setbuf(pipe, NULL);

			switch (origin)
			{
			case FROM_COMMAND_LINE:
				fp = pc->pipe = pipe;
				break;

			case FROM_INPUT_FILE:
				fp = pc->ifile_pipe = pipe;
				break;
			}

			if (strstr(p, "|")) {
				p = rindex(p, '|') + 1;
				p = first_nonspace(p);
				pc->redirect |= REDIRECT_MULTI_PIPE;
			}

			strcpy(pc->pipe_command, p);
			null_first_space(pc->pipe_command);

			pc->redirect |= REDIRECT_TO_PIPE;

			if (!(pc->redirect & REDIRECT_SHELL_COMMAND)) {
				if ((pc->pipe_pid = output_command_to_pids()))
					pc->redirect |= REDIRECT_PID_KNOWN;
				else 
					error(FATAL_RESTART, 
						"pipe operation failed\n");
			}

			return REDIRECT_TO_PIPE;
		}

                if (!(expression || string) && (*p == '>') &&
		    !((p > pc->command_line) && (*(p-1) == '-'))) {
                	append = FALSE;

			*p = NULLCHAR;
			pc->eoc_index = p - pc->command_line;
                        if (*(p+1) == '>') {
                                append = TRUE;
				*p = NULLCHAR;
				p++;
			}
			p++;
			p = strip_beginning_whitespace(p);

                        if (!strlen(p)) {
                                error(INFO, "no file name after %s\n",
					append ? ">>" : ">");
				pc->redirect |= REDIRECT_FAILURE;
                                return REDIRECT_FAILURE;
                        }

        		if ((ofile = 
			    fopen(p, append ? "a+" : "w+")) == NULL) {
                		error(INFO, "unable to open %s\n", p);
				pc->redirect = REDIRECT_FAILURE;
				return REDIRECT_FAILURE;
        		}
			setbuf(ofile, NULL);

                        switch (origin)
                        {
                        case FROM_COMMAND_LINE:
                                fp = pc->ofile = ofile;
                                break;

                        case FROM_INPUT_FILE:
                                fp = pc->ifile_ofile = ofile;
                                break;
                        }

			pc->redirect |= REDIRECT_TO_FILE;
			return REDIRECT_TO_FILE;
		}

		p++;
	}

	if ((origin == FROM_COMMAND_LINE) && (pc->flags & TTY) && 
	    (pc->flags & SCROLL) && pc->scroll_command) {
		if (!strlen(pc->command_line) ||
		    STREQ(pc->command_line, "q") ||
		    STREQ(pc->command_line, "Q") ||
		    STREQ(pc->command_line, "exit") ||
		    STRNEQ(pc->command_line, "<")) {
			pc->redirect |= REDIRECT_NOT_DONE;
			return REDIRECT_NOT_DONE;
		}

                if (!setup_stdpipe()) {
                        error(INFO, "cannot open pipe\n");
			pc->redirect |= REDIRECT_FAILURE;
                        return REDIRECT_FAILURE;
                }
                fp = pc->stdpipe;

		pc->redirect |= REDIRECT_TO_STDPIPE;
	
		switch (pc->scroll_command)
		{
		case SCROLL_LESS:
			strcpy(pc->pipe_command, "/usr/bin/less");
			break;
		case SCROLL_MORE:
			strcpy(pc->pipe_command, "/bin/more");
			break;
		}

                return REDIRECT_TO_STDPIPE;
	}

	pc->redirect |= REDIRECT_NOT_DONE;

	return REDIRECT_NOT_DONE;
}

void
debug_redirect(char *s)
{
	int others;
	int alive;

        others = 0;
        console("%s: (", s);
        if (pc->redirect & FROM_COMMAND_LINE)
                console("%sFROM_COMMAND_LINE", others++ ? "|" : "");
        if (pc->redirect & FROM_INPUT_FILE)
                console("%sFROM_INPUT_FILE", others++ ? "|" : "");
        if (pc->redirect & REDIRECT_NOT_DONE)
                console("%sREDIRECT_NOT_DONE", others++ ? "|" : "");
        if (pc->redirect & REDIRECT_TO_PIPE)
                console("%sREDIRECT_TO_PIPE", others++ ? "|" : "");
        if (pc->redirect & REDIRECT_TO_STDPIPE)
                console("%sREDIRECT_TO_STDPIPE", others++ ? "|" : "");
        if (pc->redirect & REDIRECT_TO_FILE)
                console("%sREDIRECT_TO_FILE", others++ ? "|" : "");
        if (pc->redirect & REDIRECT_FAILURE)
                console("%sREDIRECT_FAILURE", others++ ? "|" : "");
        if (pc->redirect & REDIRECT_SHELL_ESCAPE)
                console("%sREDIRECT_SHELL_ESCAPE", others++ ? "|" : "");
        if (pc->redirect & REDIRECT_SHELL_COMMAND)
                console("%sREDIRECT_SHELL_COMMAND", others++ ? "|" : "");
        if (pc->redirect & REDIRECT_PID_KNOWN)
                console("%sREDIRECT_PID_KNOWN", others++ ? "|" : "");
        if (pc->redirect & REDIRECT_MULTI_PIPE)
                console("%sREDIRECT_MULTI_PIPE", others++ ? "|" : "");
        console(")\n");

	if (pc->pipe_pid || strlen(pc->pipe_command)) {
		if (pc->pipe_pid && PID_ALIVE(pc->pipe_pid))
			alive = TRUE;
		else
			alive = FALSE;
        	console("pipe_pid: %d (%s) pipe_command: %s\n", 
			pc->pipe_pid, 
			alive ? "alive" : "dead",
			pc->pipe_command);
	}
}

/*
 *  Determine whether the pid receiving the current piped output is still
 *  alive. 
 *
 *  NOTE: This routine returns TRUE by default, and only returns FALSE if
 *        the pipe_pid exists *and* it's known to have died.  Therefore the
 *        caller must be cognizant of pc->pipe_pid or pc->stdpipe_pid.
 */ 
int
output_open(void)
{
	int waitstatus, waitret;

	if (!(pc->flags & TTY)) 
		return TRUE;

	switch (pc->redirect & PIPE_OPTIONS)
	{
	case (REDIRECT_TO_STDPIPE|FROM_COMMAND_LINE):
		waitret = waitpid(pc->stdpipe_pid, &waitstatus, WNOHANG);
		if ((waitret == pc->stdpipe_pid) || (waitret == -1))
               		return FALSE;
		break;

	case (REDIRECT_TO_PIPE|FROM_COMMAND_LINE):
	case (REDIRECT_TO_PIPE|FROM_INPUT_FILE):
		switch (pc->redirect & (REDIRECT_MULTI_PIPE)) 
		{
		case REDIRECT_MULTI_PIPE:
			if (!PID_ALIVE(pc->pipe_pid))
				return FALSE;
			break;

		default:
               		waitret = waitpid(pc->pipe_pid, &waitstatus, WNOHANG);
                	if (waitret == pc->pipe_pid) 
                        	return FALSE;
			if (waitret == -1) {  /* intervening sh */
				if (!PID_ALIVE(pc->pipe_pid))
					return FALSE;
			}
			break;
		}
		break;

	default:
		break;
	}

	return TRUE;
}


/*
 *  Determine the pids of the current popen'd shell and output command.
 *  This is all done using /proc; the ps kludge at the bottom of this
 *  routine is legacy, and should only get executed if /proc doesn't exist.
 */
static int
output_command_to_pids(void)
{
	DIR *dirp;
        struct dirent *dp;
	FILE *stp;
        char buf1[BUFSIZE];
        char buf2[BUFSIZE];
        char lookfor[BUFSIZE];
        char *pid, *name, *status, *p_pid, *pgrp;
	char *arglist[MAXARGS];
	int argc;
	FILE *pipe;
	int retries;

	retries = 0;
	pc->pipe_pid = pc->pipe_shell_pid = 0;
        sprintf(lookfor, "(%s)", pc->pipe_command);
	stall(1000);
retry:
        if (is_directory("/proc") && (dirp = opendir("/proc"))) {
                for (dp = readdir(dirp); dp && !pc->pipe_pid; 
		     dp = readdir(dirp)) {
			if (!decimal(dp->d_name, 0))
				continue;
                        sprintf(buf1, "/proc/%s/stat", dp->d_name);
                        if (file_exists(buf1, NULL) && 
			    (stp = fopen(buf1, "r"))) {
                                if (fgets(buf2, BUFSIZE, stp)) {
                                        pid = strtok(buf2, " ");
                                        name = strtok(NULL, " ");
                                        status = strtok(NULL, " ");
                                        p_pid = strtok(NULL, " ");
                                        pgrp = strtok(NULL, " ");
				        if (STREQ(name, "(sh)") &&
					    (atoi(p_pid) == getpid())) 
						pc->pipe_shell_pid = atoi(pid);
                                        if (STREQ(name, lookfor) &&
                                            ((atoi(p_pid) == getpid()) ||
				             (atoi(p_pid) == pc->pipe_shell_pid)
			                     || (atoi(pgrp) == getpid()))) {
						pc->pipe_pid = atoi(pid);
						console(
                            "FOUND[%d] (%d->%d->%d) %s %s p_pid: %s pgrp: %s\n",
						    retries, getpid(), 
						    pc->pipe_shell_pid, 
						    pc->pipe_pid,
						    name, status, p_pid, pgrp);
					}  
                                }
				fclose(stp);
                        }
                }
		closedir(dirp);
        }

	if (!pc->pipe_pid && ((retries++ < 10) || pc->pipe_shell_pid)) {
		stall(1000);
		goto retry;
	}
		
	if (pc->pipe_pid)	
		return pc->pipe_pid;

	sprintf(buf1, "ps -ft %s", pc->my_tty);
	console("%s: ", buf1);

	if ((pipe = popen(buf1, "r")) == NULL) {
        	error(INFO, "cannot determine output pid\n");
		return 0;
	}

	while (fgets(buf1, BUFSIZE, pipe)) {
		argc = parse_line(buf1, arglist);
		if ((argc >= 8) && 
		    STREQ(arglist[7], pc->pipe_command) &&
		    STRNEQ(pc->my_tty, arglist[5])) {
			pc->pipe_pid = atoi(arglist[1]);
			break;
		}
	}
	pclose(pipe);
	console("%d\n", pc->pipe_pid);

	return pc->pipe_pid;
}

/*
 *  Close straggling, piped-to, output commands.
 */
void
close_output(void)
{
        if ((pc->flags & TTY) &&
	    (pc->pipe_pid || strlen(pc->pipe_command)) && 
            output_open()) 
                kill(pc->pipe_pid, 9);
}

/*
 *  Initialize what's needed for the command line:
 *
 *   1. termios structures for raw and cooked terminal mode.
 *   2. set up SIGINT and SIGPIPE handlers for aborted commands. 
 *   3. set up the command history table.
 *   4. create the prompt string.
 */
void
cmdline_init(void)
{
	int fd;

	/*
	 *  Stash a copy of the original termios setup. 
         *  Build a raw version for quick use for each command entry.
	 */ 
	if (isatty(fileno(stdin))) {
        	if ((fd = open("/dev/tty", O_RDONLY)) < 0) 
			error(FATAL, "/dev/tty: %s\n", strerror(errno));
                
		if (tcgetattr(fd, &pc->termios_orig) == -1) 
			error(FATAL, "tcgetattr /dev/tty: %s\n", 
				strerror(errno));

                if (tcgetattr(fd, &pc->termios_raw) == -1) 
			error(FATAL, "tcgetattr /dev/tty: %s\n", 
				strerror(errno));
                 
                close(fd);

		pc->termios_raw.c_lflag &= ~ECHO & ~ICANON;
        	pc->termios_raw.c_cc[VMIN] = (char)1;
        	pc->termios_raw.c_cc[VTIME] = (char)0;

		restore_sanity();

		pc->flags |= TTY;
		set_my_tty();

		SIGACTION(SIGINT, restart, &pc->sigaction, NULL);
		readline_init();
        }
        else {
        	fprintf(fp, pc->flags & SILENT ? 
			"" : "    NOTE: stdin: not a tty\n");
                fflush(fp);
		pc->flags &= ~TTY;
        }

	SIGACTION(SIGPIPE, SIG_IGN, &pc->sigaction, NULL);

	if ((pc->prompt = (char *)malloc(strlen(pc->program_name)+3)) == NULL)
		pc->prompt = "> ";
	else
		sprintf(pc->prompt, "%s> ", pc->program_name);

}

/*
 *  SIGINT, SIGPIPE, and SIGSEGV handler.
 *  Signal number 0 is sent for a generic restart.
 */
#define MAX_RECURSIVE_SIGNALS (10)
#define MAX_SIGINTS_ACCEPTED  (3)

void
restart(int sig)
{
	static int in_restart = 0;

	console("restart (%s) %s\n", signame(sig), 
		pc->flags & IN_GDB ? "(in gdb)" : "(in crash)");

        if (pc->flags & IN_RESTART) {
                fprintf(stderr, 
		   "\nembedded signal received (%s): recursive restart call\n",
			signame(sig));
		if (++in_restart < MAX_RECURSIVE_SIGNALS) 
			return;
		fprintf(stderr, "bailing out...\n");
               	clean_exit(1);
        } else {
		pc->flags |= IN_RESTART;
		in_restart = 0;
	}

	switch (sig) 
	{
        case SIGSEGV:
		fflush(fp);
                fprintf(stderr, "   <segmentation violation%s>\n",
                        pc->flags & IN_GDB ? " in gdb" : "");
        case 0:
	case SIGPIPE:
                restore_sanity();
                break;

	case SIGINT:
		SIGACTION(SIGINT, restart, &pc->sigaction, NULL);
		pc->flags |= _SIGINT_;
		pc->sigint_cnt++;
		pc->flags &= ~IN_RESTART;
		if (pc->sigint_cnt == MAX_SIGINTS_ACCEPTED) {
			restore_sanity();
			break;
		}
		return;

	default:
		fprintf(stderr, "unexpected signal received: %s\n", 
			signame(sig));
		restore_sanity();
		close_output();
		break;
	}

	fprintf(fp, "\n");

	pc->flags &= ~(IN_FOREACH|IN_GDB|IN_RESTART);
	longjmp(pc->main_loop_env, 1);
}

/*
 *  Return a signal name string, or a number if the signal is not listed.
 */
static char *
signame(int sig)
{
	static char sigbuf[20];

	switch (sig)
	{
	case SIGINT:
		sprintf(sigbuf, "SIGINT-%d", pc->sigint_cnt+1);
		return sigbuf;
	case SIGPIPE:
		return "SIGPIPE";
	case SIGSEGV:
		return "SIGSEGV";
	default:
		sprintf(sigbuf, "%d", sig);
		return sigbuf;
	}
}

/*
 *  Restore the program environment to the state it was in before the
 *  last command was executed:  
 *
 *   1. close all temporarily opened pipes and output files.
 *   2. set the terminal back to normal cooked mode.
 *   3. free all temporary buffers.
 *   4. restore the last known output radix.
 */
static void
restore_sanity(void)
{
	int fd, waitstatus;

        if (pc->stdpipe) {
		close(fileno(pc->stdpipe));
                pc->stdpipe = NULL;
		if (pc->stdpipe_pid && PID_ALIVE(pc->stdpipe_pid)) {
			while (!waitpid(pc->stdpipe_pid, &waitstatus, WNOHANG))
				;
		}
		pc->stdpipe_pid = 0;
        }
	if (pc->pipe) {
		close(fileno(pc->pipe));
	 	pc->pipe = NULL;
		console("wait for redirect %d->%d to finish...\n",
			pc->pipe_shell_pid, pc->pipe_pid);
		if (pc->pipe_pid)
			while (PID_ALIVE(pc->pipe_pid)) 
				waitpid(pc->pipe_pid, &waitstatus, WNOHANG);
                if (pc->pipe_shell_pid)
		        while (PID_ALIVE(pc->pipe_shell_pid)) 
                        	waitpid(pc->pipe_shell_pid, 
					&waitstatus, WNOHANG);
		pc->pipe_pid = 0;
	}
	if (pc->ifile_pipe) {
		fflush(pc->ifile_pipe);
		close(fileno(pc->ifile_pipe));
		pc->ifile_pipe = NULL;
        	if (pc->pipe_pid &&
            	    ((pc->redirect & (PIPE_OPTIONS|REDIRECT_PID_KNOWN)) ==
                    (FROM_INPUT_FILE|REDIRECT_TO_PIPE|REDIRECT_PID_KNOWN))) {
			console("wait for redirect %d->%d to finish...\n",
				pc->pipe_shell_pid, pc->pipe_pid);
                	while (PID_ALIVE(pc->pipe_pid))
				waitpid(pc->pipe_pid, &waitstatus, WNOHANG);
                        if (pc->pipe_shell_pid) 
                                while (PID_ALIVE(pc->pipe_shell_pid))
                                        waitpid(pc->pipe_shell_pid,
                                                &waitstatus, WNOHANG);
			if (pc->redirect & (REDIRECT_MULTI_PIPE))
				wait_for_children(ALL_CHILDREN);
		}
	}

	if (pc->ofile) {
		fclose(pc->ofile);
		pc->ofile = NULL;
	}
	if (pc->ifile_ofile) {
		fclose(pc->ifile_ofile);
		pc->ifile_ofile = NULL;
	}

	if (pc->ifile) {
		fclose(pc->ifile);
		pc->ifile = NULL;
	}

	if (pc->tmpfile) {
		close_tmpfile();
	}

	if (pc->tmpfile2) {
		close_tmpfile2();
	}

	if (pc->flags & TTY) {
		if ((fd = open("/dev/tty", O_RDONLY)) < 0) 
			error(FATAL, "/dev/tty: %s\n", strerror(errno));
	        
	        if (tcsetattr(fd, TCSANOW, &pc->termios_orig) == -1) 
                        error(FATAL, "tcsetattr /dev/tty: %s\n",
                                strerror(errno));
	        
		close(fd);
	}

	wait_for_children(ZOMBIES_ONLY);

	pc->flags &= ~(RUNTIME_IFILE|_SIGINT_);
	pc->sigint_cnt = 0;
	pc->redirect = 0;
	pc->pipe_command[0] = NULLCHAR;
	pc->pipe_pid = 0;
	pc->pipe_shell_pid = 0;
	pc->sbrk = sbrk(0);

	restore_gdb_sanity();

	free_all_bufs();

	/*
	 *  Clear the structure cache references -- no-ops if DUMPFILE().
	 */
	clear_task_cache();
	clear_machdep_cache();
	clear_swap_info_cache();
	clear_file_cache();
	clear_dentry_cache();
	clear_inode_cache();
	clear_vma_cache();
	clear_active_set();

	if (CRASHDEBUG(4)) {
                dump_filesys_table(0);
		dump_vma_cache(0);
		dump_text_value_cache(0);
	}
	
	if (REMOTE())
		remote_clear_pipeline();
}

/*
 *  Similar to above, but only called in between each command that is
 *  read from an input file.
 */
static void
restore_ifile_sanity(void)
{
        int fd;

        if (pc->ifile_pipe) {
		close(fileno(pc->ifile_pipe));
                pc->ifile_pipe = NULL;
        }

        if (pc->ifile_ofile) {
                fclose(pc->ifile_ofile);
                pc->ifile_ofile = NULL;
        }

        if (pc->flags & TTY) {
                if ((fd = open("/dev/tty", O_RDONLY)) < 0) 
			error(FATAL, "/dev/tty: %s\n", strerror(errno));
                
                if (tcsetattr(fd, TCSANOW, &pc->termios_orig) == -1) 
			error(FATAL, "tcsetattr /dev/tty: %s\n",
                                strerror(errno));
                
                close(fd);
        }

	if (pc->tmpfile2) {
		close_tmpfile2();
	}

	restore_gdb_sanity();

	free_all_bufs();
}

/*
 *  Check whether a SIGINT was received during the execution of a command,
 *  clearing the flag if it was set.  This allows individual commands or
 *  entities to do whatever is appropriate to handle CTRL-C.
 */
int
received_SIGINT(void)
{
	if (pc->flags & _SIGINT_) {
		pc->flags &= ~_SIGINT_;
		pc->sigint_cnt = 0;
		return TRUE;
	} else 
		return FALSE;
}


/*
 *  Look for an executable file that begins with #!
 */
static int
is_shell_script(char *s)
{
        int fd;
        char interp[2];
        struct stat sbuf;

        if ((fd = open(s, O_RDONLY)) < 0) 
                return FALSE;
        
        if (isatty(fd)) 
                return FALSE;
        
        if (read(fd, interp, 2) != 2) {
                close(fd);
                return FALSE;
        }

        if (!STRNEQ(interp, "#!")) {
                close(fd);
                return FALSE;
        }

        close(fd);

        if (stat(s, &sbuf) == -1) 
		return FALSE;

        if (!(sbuf.st_mode & (S_IXUSR|S_IXGRP|S_IXOTH))) 
		return FALSE;
        
        return TRUE;
}

/*
 *  After verifying the user's input file, loop through each line, executing
 *  one command at a time.  This command pretty much does the same as
 *  get_command_line(), but also kicks off the command execution as well.  
 *  It's kept self-contained, as indicated by the RUNTIME_IFILE flag, and 
 *  keeps its own internal sanity by calling restore_ifile_sanity() between 
 *  each line.
 */ 
void
exec_input_file(void)
{
        char *file;
	FILE *incoming_fp;
        char buf[BUFSIZE];
	ulong this;

	/*
	 *  Do start-up .rc or input files in the proper order.
	 */
	if (pc->flags & RCHOME_IFILE) {
		this = RCHOME_IFILE;
		pc->flags &= ~RCHOME_IFILE;
	} else if (pc->flags & RCLOCAL_IFILE) {
		this = RCLOCAL_IFILE;
		pc->flags &= ~RCLOCAL_IFILE;
	} else if (pc->flags & CMDLINE_IFILE) {
		this = CMDLINE_IFILE;
		pc->flags &= ~CMDLINE_IFILE;
	} else
		this = 0;


        if (pc->flags & RUNTIME_IFILE) {
                error(INFO, "embedded input files not allowed!\n");
                return;
        }

        if (argcnt < 2) {
                error(INFO, "no input file entered!\n");
                return;
        } else
                file = args[1];

        if (!file_exists(file, NULL)) {
                error(INFO, "%s: %s\n", file, strerror(ENOENT));
                return;
        }

        if (is_elf_file(file)) {
                error(INFO, "input from executable files not supported yet!\n");
                return;
        }

        if (is_shell_script(file)) {
                error(INFO, "input from shell scripts not supported yet!\n");
                return;
        }

        if ((pc->ifile = fopen(file, "r")) == NULL) {
                error(INFO, "%s: %s\n", file, strerror(errno));
                return;
        }

        pc->flags |= RUNTIME_IFILE;
	incoming_fp = fp;

        while (fgets(buf, BUFSIZE-1, pc->ifile)) {
                /*
                 *  Restore normal environment.
                 */
                fp = incoming_fp;
		restore_ifile_sanity();
        	BZERO(pc->command_line, BUFSIZE);
        	BZERO(pc->orig_line, BUFSIZE);

		if (STRNEQ(buf, "#") || STREQ(buf, "\n"))
			continue;

                check_special_handling(buf);
                strcpy(pc->command_line, buf);
                clean_line(pc->command_line);
                strcpy(pc->orig_line, pc->command_line);
		strip_linefeeds(pc->orig_line);
		resolve_aliases();

	        switch (setup_redirect(FROM_INPUT_FILE))
	        {
	        case REDIRECT_NOT_DONE:
	        case REDIRECT_TO_PIPE:
	        case REDIRECT_TO_FILE:
	                break;
	
		case REDIRECT_SHELL_ESCAPE:
		case REDIRECT_SHELL_COMMAND:
			continue;

	        case REDIRECT_FAILURE:
	                goto done_input;
	        }

		if (CRASHDEBUG(1))
			console(buf);

		if (!(argcnt = parse_line(pc->command_line, args)))
			continue;

		if ((this & (RCHOME_IFILE|RCLOCAL_IFILE)) &&
		    (STREQ(args[0], "set") || STREQ(args[0], "alias")))
			continue;

                if (!(pc->flags & SILENT)) {
                        fprintf(fp, "%s%s", pc->prompt, buf);
                        fflush(fp);
                }

                exec_command();
        }

done_input:

        fclose(pc->ifile);
        pc->ifile = NULL;
        pc->flags &= ~RUNTIME_IFILE;
}

/*
 *  Prime the alias list with a few built-in's.
 */
void
alias_init(char *inbuf)
{
	char buf[BUFSIZE];

	if (inbuf) {
		strcpy(buf, inbuf);
		argcnt = parse_line(buf, args);
		allocate_alias(ALIAS_BUILTIN);
		return;
	}

	strcpy(buf, "alias man help");
	argcnt = parse_line(buf, args);
	allocate_alias(ALIAS_BUILTIN);

        strcpy(buf, "alias ? help");
        argcnt = parse_line(buf, args);
        allocate_alias(ALIAS_BUILTIN);

        strcpy(buf, "alias quit q");
        argcnt = parse_line(buf, args);
        allocate_alias(ALIAS_BUILTIN);

	strcpy(buf, "alias sf set scroll off");
        argcnt = parse_line(buf, args);
        allocate_alias(ALIAS_BUILTIN);

	strcpy(buf, "alias sn set scroll on");
        argcnt = parse_line(buf, args);
        allocate_alias(ALIAS_BUILTIN);

	strcpy(buf, "alias hex set radix 16");
        argcnt = parse_line(buf, args);
        allocate_alias(ALIAS_BUILTIN);

        strcpy(buf, "alias dec set radix 10");
        argcnt = parse_line(buf, args);
        allocate_alias(ALIAS_BUILTIN);

        strcpy(buf, "alias g gdb");
        argcnt = parse_line(buf, args);
        allocate_alias(ALIAS_BUILTIN);

        strcpy(buf, "alias px p -x");
        argcnt = parse_line(buf, args);
        allocate_alias(ALIAS_BUILTIN);

        strcpy(buf, "alias pd p -d");
        argcnt = parse_line(buf, args);
        allocate_alias(ALIAS_BUILTIN);

	strcpy(buf, "alias for foreach");
        argcnt = parse_line(buf, args);
        allocate_alias(ALIAS_BUILTIN);

	strcpy(buf, "alias size *");
        argcnt = parse_line(buf, args);
        allocate_alias(ALIAS_BUILTIN);

        strcpy(buf, "alias dmesg log");
        argcnt = parse_line(buf, args);
        allocate_alias(ALIAS_BUILTIN);

}

/*
 *  Before the command line is parsed, take a snapshot and parse the snapshot.
 *  If args[0] is an known alias, recreate the pc->command_line string with 
 *  the alias substitution.
 */
static void
resolve_aliases(void)
{
	int i;
	struct alias_data *ad;
	int found;
	char *p1, *remainder;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];

	if (!strlen(pc->command_line))
		return;

	strcpy(buf1, pc->command_line);
	argcnt = parse_line(buf1, args);

	if (argcnt > 1) {
		strcpy(buf2, &pc->command_line[args[1] - buf1]);
		remainder = buf2;
	} else
		remainder = NULL;

	found = FALSE;
	for (ad = alias_head.next; ad; ad = ad->next) {
		if (STREQ(ad->alias, args[0])) {
                        for (i = 0; i < ad->argcnt; i++)
                                args[i] = ad->args[i];
			found = TRUE;
			break;
		}
	}

	if (!found)
		return;

	BZERO(pc->command_line, BUFSIZE);
	p1 = pc->command_line;

	for (i = 0; i < ad->argcnt; i++) {
		snprintf(p1, BUFSIZE - (p1-pc->command_line), "%s ", args[i]);
		while (*p1)
			p1++;
                if ((p1 - pc->command_line) >= BUFSIZE) 
                        break;
	}
        if (remainder) {
                if ((strlen(remainder)+strlen(pc->command_line)) < BUFSIZE) 
                        strcat(pc->command_line, remainder);
                else 
                        error(INFO, "command line overflow.\n");
        } else if (strlen(pc->command_line) >= (BUFSIZE-1)) 
                error(INFO, "command line overflow.\n");

	clean_line(pc->command_line);
}

/*
 *  If input string is an alias, return a pointer to the alias_data struct.
 */
struct alias_data *
is_alias(char *s)
{
        struct alias_data *ad;

        for (ad = alias_head.next; ad; ad = ad->next) {
		if (STREQ(ad->alias, s)) 
			return(ad);
	}
	return NULL;
}

/*
 *  .rc file commands that consist of either "set" or "alias" commands
 *  are performed during initialization.  Determine which is being requested, 
 *  and pass the line to either cmd_set() or allocate_alias().  If any
 *  runtime commands are found, flag them for later execution by 
 *  exec_rc_commands().
 */
void
resolve_rc_cmd(char *s, int origin)
{
	int i;
	struct alias_data *ad;

	clean_line(s);

	if (*s == '#')
		return;

	if ((argcnt = parse_line(s, args)) == 0)
		return;

	/*
	 *  If the command is a built-in alias of "set", switch the
         *  args so that it will be caught by the subsequent set-string
         *  check below.
	 */
	if ((argcnt == 1) && 
	    (ad = is_alias(args[0])) &&
	    STREQ(ad->args[0], "set")) {
		argcnt = ad->argcnt;
		for (i = 0; i < ad->argcnt; i++)
			args[i] = ad->args[i];
	}

	if (STREQ(args[0], "set")) {
		optind = 0;
		cmd_set();
	} else if (STREQ(args[0], "alias") && (argcnt > 2))
		allocate_alias(origin);
	else {
        	switch (origin)
        	{
        	case ALIAS_RCHOME:
                	pc->flags |= RCHOME_IFILE;
                	break;
        	case ALIAS_RCLOCAL:
                	pc->flags |= RCLOCAL_IFILE;
               	 	break;
        	}
	}

	return;
}


/*
 *  The "alias" command.  With no arguments, list all aliases. With one
 *  argument -- which must be an alias -- display the string it's aliased to.
 *  With two or more arguments, setup a new alias, where the first argument
 *  is the alias, and the remaining arguments make up the alias string.
 *  If the second arg is the NULL string "", delete the alias.
 */   
void
cmd_alias(void)
{
	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	switch (argcnt)
	{
	case 1:
		list_aliases(NULL);
		break;

	case 2:
		list_aliases(args[1]);
		break;
	
	default:
		if (allocate_alias(ALIAS_RUNTIME))
			list_aliases(args[1]);
		break;
	}
}

/*
 *  Dump the current set of aliases.
 */
static void
list_aliases(char *s)
{
	int i;
        struct alias_data *ad;
	int found, precision;
	char buf[BUFSIZE];

	if (!alias_head.next) {
		error(INFO, "alias list is empty\n");
		return;
	}

	BZERO(buf, BUFSIZE);
	found = FALSE;
	precision = 7;

        for (ad = alias_head.next; ad; ad = ad->next) {
                switch (ad->origin)
		{
                case ALIAS_RCLOCAL:
                        sprintf(buf, ".%src", pc->program_name);
			if (strlen(buf) > precision)
				precision = strlen(buf);
                        break;
                case ALIAS_RCHOME:
                        sprintf(buf, "$HOME/.%src", pc->program_name);
			if (strlen(buf) > precision)
				precision = strlen(buf);
			break;
		}
	}

	fprintf(fp, "ORIGIN");
	pad_line(fp, precision-6, ' ');

	BZERO(buf, BUFSIZE);
	fprintf(fp, "  ALIAS    COMMAND\n");

        for (ad = alias_head.next; ad; ad = ad->next) {
		if (s && !STREQ(s, ad->alias))
			continue;

		found = TRUE;

                switch (ad->origin)
                {
                case ALIAS_RUNTIME:
                        sprintf(buf, "runtime");
                        break;
                case ALIAS_RCLOCAL:
                        sprintf(buf, ".%src", pc->program_name);
                        break;
                case ALIAS_RCHOME:
                        sprintf(buf, "$HOME/.%src", pc->program_name);
                        break;
                case ALIAS_BUILTIN:
                        sprintf(buf, "builtin");
                        break;
                }

		fprintf(fp, "%s  ", buf);
		pad_line(fp, precision-strlen(buf), ' ');

                fprintf(fp, "%-7s  ", ad->alias);

		for (i = 0; i < ad->argcnt; i++) {
			fprintf(fp, "%s ", ad->args[i]);
		}
		fprintf(fp, "\n");
	}

	if (s && !found)
		fprintf(fp, "alias does not exist: %s\n", s);
		
}

/*
 *  Verify the alias request set up in the args[] array: 
 *
 *    1. make sure that the alias string starts with a legitimate command.
 *    2. if the already exists, deallocate its current version.
 *   
 *  Then malloc space for the alias string, and link it in to the alias list.
 */
static int
allocate_alias(int origin)
{
	int i;
	int size;
        struct alias_data *ad;
        struct alias_data *newad;
	char *p1, *enclosed_string;
	int found;

	if ((enclosed_string = strstr(args[2], " ")))
		*enclosed_string = NULLCHAR;

	found = FALSE;

	if (get_command_table_entry(args[1])) {
                error(INFO, "cannot alias existing command name: %s\n", 
			args[1]);
                return FALSE;
	}

	if (get_command_table_entry(args[2])) 
		found = TRUE;

	if (!found) {
		if (!strlen(args[2])) {
			if (alias_exists(args[1])) {
				deallocate_alias(args[1]);
				fprintf(fp, "alias deleted: %s\n", args[1]);
			}
		} else {
			error(INFO, 
		          "invalid alias attempt on non-existent command: %s\n",
				args[2]);
		}
		return FALSE;
	} 

	if (alias_exists(args[1]))
		deallocate_alias(args[1]);

	if (enclosed_string)
		*enclosed_string = ' ';

	size = sizeof(struct alias_data) + argcnt;
	for (i = 0; i < argcnt; i++) 
		size += strlen(args[i]);

        if ((newad = (struct alias_data *)malloc(size+1)) == NULL) {
                error(INFO, "alias_data malloc: %s\n", strerror(errno));
                return FALSE;
        }

	BZERO(newad, size);
	newad->next = NULL;
	newad->size = size;
	newad->origin = origin;

	p1 = newad->argbuf;
	for (i = 1; i < argcnt; i++) {
                sprintf(p1, "%s ", args[i]);
		while (*p1)
			p1++;
	}
	p1 = strstr(newad->argbuf, " ");
	*p1 = NULLCHAR;

	newad->alias = newad->argbuf;
	newad->argcnt = parse_line(p1+1, newad->args); 

	for (ad = &alias_head; ad->next; ad = ad->next) 
		;
	ad->next = newad;

	return TRUE;
}


/*
 *  Check whether the passed-in string is a currently-existing alias.
 */
static int
alias_exists(char *s)
{
        struct alias_data *ad;

        if (!alias_head.next) 
                return FALSE;

        for (ad = alias_head.next; ad; ad = ad->next) 
		if (STREQ(ad->alias, s)) 
			return TRUE;

	return FALSE;
}

/*
 *  If the passed-in string is an alias, delink it and free its memory. 
 */
void
deallocate_alias(char *s)
{
        struct alias_data *ad, *lastad;

        for (ad = alias_head.next, lastad = &alias_head; ad; ad = ad->next) {
                if (!STREQ(ad->alias, s)) { 
			lastad = ad;
                        continue;
		}

		lastad->next = ad->next;
		free(ad);
		break;
	}
}

/*
 *  "help -a" output
 */
void
dump_alias_data(void)
{
        int i;
        struct alias_data *ad;

	fprintf(fp, "alias_head.next: %lx\n\n", (ulong)alias_head.next);

        for (ad = alias_head.next; ad; ad = ad->next) {
        	fprintf(fp, "      next: %lx\n", (ulong)ad->next);
        	fprintf(fp, "     alias: %s\n", ad->alias);
        	fprintf(fp, "      size: %d\n", ad->size);
        	fprintf(fp, "    origin: ");
		switch (ad->origin)
		{
		case ALIAS_RUNTIME:
			fprintf(fp, "runtime setting \n");
			break;
		case ALIAS_RCLOCAL:
			fprintf(fp, ".%src \n", pc->program_name);
			break;
		case ALIAS_RCHOME:
			fprintf(fp, "$HOME/.%src \n", pc->program_name);
			break;
		case ALIAS_BUILTIN:
			fprintf(fp, "builtin\n");
			break;
		}
        	fprintf(fp, "    argcnt: %d\n", ad->argcnt);
        	for (i = 0; i < ad->argcnt; i++)
                	fprintf(fp, "   args[%d]: %lx: %s\n", 
				i, (ulong)ad->args[i], ad->args[i]);
                fprintf(fp, "\n");
        }
}


/*
 *  Repeat a command on a live system.
 */
void
cmd_repeat(void)
{
	ulong delay;
	char buf[BUFSIZE]; 
	char bufsave[BUFSIZE];

	if (argcnt == 1)
		cmd_usage(pc->curcmd, SYNOPSIS);

	delay = 0;

	if (args[1][0] == '-') {
		switch (args[1][1])
		{
		default:
		case NULLCHAR:
			cmd_usage(pc->curcmd, SYNOPSIS);

		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case '0':
			delay = dtol(&args[1][1], FAULT_ON_ERROR, NULL);
			concat_args(buf, 2, FALSE);
			break;
		}
	} else 
		concat_args(buf, 1, FALSE);

	check_special_handling(buf);

#ifdef TODO
	/* 
	 * make aliases work... 
	 */
	strcpy(pc->command_line, buf);
	resolve_aliases();
	if (!argcnt)
		return;
	concat_args(buf, 0, FALSE);
#endif

	strcpy(bufsave, buf);
	argcnt = parse_line(buf, args);
	if (!argcnt)
		return;

	if (STREQ(args[0], "<") && (pc->flags & TTY) &&
            (pc->flags & SCROLL) && pc->scroll_command) 
		error(FATAL, 
		"scrolling must be turned off when repeating an input file\n");

	while (TRUE) {
		optind = 0;
console("exec_command...\n");
		exec_command();
		free_all_bufs();

		if (received_SIGINT() || !output_open())
			break;

		if (delay)
			sleep(delay);

		strcpy(buf, bufsave);
		argcnt = parse_line(buf, args);
	}
}

/*
 *  Initialize readline, set the editing mode, and then perform any 
 *  crash-specific bindings, etc.
 */
static void
readline_init(void)
{               
        rl_initialize();

	if (STREQ(pc->editing_mode, "vi")) {
		rl_editing_mode = vi_mode;

		rl_bind_key(CTRL('N'), rl_get_next_history);
		rl_bind_key(CTRL('P'), rl_get_previous_history);

		rl_bind_key_in_map(CTRL('P'), rl_get_previous_history,
			vi_insertion_keymap);
		rl_bind_key_in_map(CTRL('N'), rl_get_next_history,
			vi_insertion_keymap);

		rl_generic_bind(ISFUNC, "[A", (char *)rl_get_previous_history, 
			vi_movement_keymap);
		rl_generic_bind(ISFUNC, "[B", (char *)rl_get_next_history, 
			vi_movement_keymap);
	}

	if (STREQ(pc->editing_mode, "emacs")) {
        	rl_editing_mode = emacs_mode;
	}
}

/*
 *  Find and set the tty string of this session as seen in "ps -ef" output. 
 */
static void
set_my_tty(void)
{
        char buf[BUFSIZE];
        char *arglist[MAXARGS];
        int argc;
        FILE *pipe;

        strcpy(pc->my_tty, "?");

	if (file_exists("/usr/bin/tty", NULL)) {
	        sprintf(buf, "/usr/bin/tty");
	        if ((pipe = popen(buf, "r")) == NULL) 
	                return;
	
	        while (fgets(buf, BUFSIZE, pipe)) {
			if (STRNEQ(buf, "/dev/")) {
				strcpy(pc->my_tty, strip_line_end(&buf[strlen("/dev/")]));
				break;
			}
		}
		pclose(pipe);
		return;
	}

        sprintf(buf, "ps -ef | grep ' %d '", getpid());

	if (CRASHDEBUG(1))
		fprintf(fp, "popen(%s)\n", buf);

        if ((pipe = popen(buf, "r")) == NULL) 
                return;

        while (fgets(buf, BUFSIZE, pipe)) {
                argc = parse_line(buf, arglist);
                if ((argc >= 8) && (atoi(arglist[1]) == getpid())) {
			if (strlen(arglist[5]) < 9)
				strcpy(pc->my_tty, arglist[5]);
			else
				strncpy(pc->my_tty, arglist[5], 9); 
                }
        }
        pclose(pipe);
}

/*
 *  Check whether SIGINT's are allowed before shipping a request off to gdb.
 */
int
interruptible(void)
{
	if (!(pc->flags & RUNTIME))
		return FALSE;

	if (!(pc->flags & TTY))
		return FALSE;

	if ((pc->redirect & (FROM_INPUT_FILE|REDIRECT_NOT_DONE)) ==
	    (FROM_INPUT_FILE|REDIRECT_NOT_DONE)) 
		return TRUE;

	if (strlen(pc->pipe_command))
		return FALSE;
		
	return TRUE;
}


/*
 *  Set up the standard output pipe using whichever was selected during init.
 */

static char *less_argv[5] = {
	"/usr/bin/less",
	"-E",
	"-X",
        "-Ps -- MORE --  forward\\: <SPACE>, <ENTER> or j  backward\\: b or k  quit\\: q",
	NULL
};

static char *more_argv[2] = {
	"/bin/more",
	NULL
};

static int
setup_stdpipe(void)
{
	char *path;

	if (pipe(pc->pipefd) < 0) {
		error(INFO, "pipe system call failed: %s", strerror(errno));
		return FALSE;
	}

	if ((pc->stdpipe_pid = fork()) < 0) {
		error(INFO, "fork system call failed: %s", strerror(errno));
		return FALSE;
	}

	if (pc->stdpipe_pid > 0) {               
		pc->redirect |= REDIRECT_PID_KNOWN;

		close(pc->pipefd[0]);    /* parent closes read end */

		if ((pc->stdpipe = fdopen(pc->pipefd[1], "w")) == NULL) {
			error(INFO, "fdopen system call failed: %s", 
				strerror(errno));
			return FALSE;
		}
		setbuf(pc->stdpipe, NULL);

                switch (pc->scroll_command)
                {
                case SCROLL_LESS:
                        strcpy(pc->pipe_command, less_argv[0]);
                        break;
                case SCROLL_MORE:
                        strcpy(pc->pipe_command, more_argv[0]);
                        break;
                }

		if (CRASHDEBUG(2))
			console("pipe: %lx\n", pc->stdpipe);
		return TRUE;;

	} else {                        
		close(pc->pipefd[1]);    /* child closes write end */

		if (dup2(pc->pipefd[0], 0) != 0) {
			perror("child dup2 failed");
			clean_exit(1);
		}

		if (CRASHDEBUG(2))
			console("execv: %d\n", getpid());

                switch (pc->scroll_command)
		{
		case SCROLL_LESS:
			path = less_argv[0];
			execv(path, less_argv);
			break;

                case SCROLL_MORE:
			path = more_argv[0];
			execv(path, more_argv);
			break;
		}

		perror("child execv failed"); 
		return(clean_exit(1));
	}
}

static void 
wait_for_children(ulong waitflag)
{
        int status, pid;

	while (TRUE) {
        	switch (pid = waitpid(-1, &status, WNOHANG))
        	{
        	case  0:
			if (CRASHDEBUG(2))
			    console("wait_for_children: child running...\n");
			if (waitflag == ZOMBIES_ONLY)
				return;
			break;

        	case -1:
			if (CRASHDEBUG(2))
			    console("wait_for_children: no children alive\n");
                	return;

        	default:
			console("wait_for_children(%d): reaped %d\n", 
				waitflag, pid);
			if (CRASHDEBUG(2))
			    fprintf(fp, "wait_for_children: reaped %d\n", pid);
                	break;
        	}
	}
}
