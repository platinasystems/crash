/* extensions.c - core analysis suite
 *
 * Copyright (C) 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002, 2003, 2004, 2005 David Anderson
 * Copyright (C) 2002, 2003, 2004, 2005 Red Hat, Inc. All rights reserved.
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
#include <dlfcn.h>

static void load_extension(char *);
static void unload_extension(char *);

#define DUMP_EXTENSIONS   (0)
#define LOAD_EXTENSION    (1)
#define UNLOAD_EXTENSION  (2)

/*
 *  Load, unload, or list the extension libaries.
 */
void
cmd_extend(void)
{
        int c;
	int flag;

	flag = DUMP_EXTENSIONS;

        while ((c = getopt(argcnt, args, "lu")) != EOF) {
                switch(c)
                {
		case 'l':
			if (flag & UNLOAD_EXTENSION) {
				error(INFO, 
					"-l and -u are mutually exclusive\n");
				argerrs++;
			} else
				flag |= LOAD_EXTENSION;
			break;

		case 'u':
                        if (flag & LOAD_EXTENSION) {
                                error(INFO, 
                                        "-u and -l are mutually exclusive\n");
                                argerrs++;
                        } else
                                flag |= UNLOAD_EXTENSION;
			break;

                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs)
                cmd_usage(pc->curcmd, SYNOPSIS);

	switch (flag)
	{
	case DUMP_EXTENSIONS:
		if (!args[optind]) {
			dump_extension_table(!VERBOSE);
			return;
		}
		/* FALLTHROUGH */

	case LOAD_EXTENSION:
		if (!args[optind]) { 
			error(INFO, 
		       "-l requires one or more extension library arguments\n");
			cmd_usage(pc->curcmd, SYNOPSIS);
			break;
		}

        	while (args[optind]) {
			load_extension(args[optind]);
			optind++;
		}
		break;

	case UNLOAD_EXTENSION:
		if (!args[optind]) { 
			unload_extension(NULL);
			break;
		}

        	while (args[optind]) {
			unload_extension(args[optind]);
			optind++;
		}
		break;
	}
}

/*
 *  List all extension libaries and their commands in either the extend
 *  command format or for "help -e" (verbose).
 */
void 
dump_extension_table(int verbose)
{
	struct extension_table *ext;
	struct command_table_entry *cp;
	char buf[BUFSIZE];
	int longest, others;

	if (!extension_table)
		return;

	if (verbose) {
       		for (ext = extension_table; ext; ext = ext->next) {
                        fprintf(fp, "     filename: %s\n", ext->filename);
                        fprintf(fp, "       handle: %lx\n", (ulong)ext->handle);
                        fprintf(fp, "command_table: %lx (", 
				(ulong)ext->command_table);
                        for (others = 0, cp = ext->command_table; cp->name;cp++)
                                fprintf(fp, "%s%s%s", others++ ? " " : "",
                                        cp->name, cp->help_data ? "*" : "");
                        fprintf(fp, ")\n");
			fprintf(fp, "        flags: %lx (", ext->flags);
			others = 0;
			if (ext->flags & REGISTERED)
				fprintf(fp, "%sREGISTERED", others++ ?
					"|" : "");
			fprintf(fp, ")\n");
                        fprintf(fp, "         next: %lx\n", (ulong)ext->next);
                        fprintf(fp, "         prev: %lx\n%s", 
				(ulong)ext->prev, ext->next ? "\n" : "");
		}
		return;
	}


       /*
	*  Print them out in the order they were loaded.
	*/
	for (longest = 0, ext = extension_table; ext; ext = ext->next) {
		if (strlen(ext->filename) > longest)
			longest = strlen(ext->filename);
	}

	fprintf(fp, "%s  COMMANDS\n", 
		mkstring(buf, longest, LJUST, "SHARED OBJECT"));
	longest = MAX(longest, strlen("SHARED OBJECT"));

	for (ext = extension_table; ext; ext = ext->next) 
		if (ext->next == NULL)
			break;

	do {
                fprintf(fp, "%s  ", 
                        mkstring(buf, longest, LJUST, ext->filename));
                for (cp = ext->command_table; cp->name; cp++)
                        fprintf(fp, "%s ", cp->name);
		fprintf(fp, "\n");
	} while ((ext = ext->prev));
}


/*
 *  Load an extension library.
 */
static void 
load_extension(char *lib)
{
	struct extension_table *ext;
	char buf[BUFSIZE];
	size_t size;

	for (ext = extension_table; ext; ext = ext->next) {
		if (same_file(ext->filename, lib)) {
			fprintf(fp, "%s: shared object already loaded\n", lib);
			return;
		}
	}

	size = sizeof(struct extension_table) + strlen(lib) + strlen("./") + 1;

	if ((ext = (struct extension_table *)malloc(size)) == NULL) 
		error(FATAL, "cannot malloc extension_table space.");

	BZERO(ext, size);

	ext->filename = (char *)((ulong)ext + sizeof(struct extension_table));
	
       /*
	*  If the library is not specified by an absolute pathname, dlopen() 
        *  does not look in the current directory.
        */
	if ((*lib != '.') && (*lib != '/') && is_elf_file(lib)) 
		sprintf(ext->filename, "./%s", lib);
	else
		strcpy(ext->filename, lib);

       /*
        *  register_extension() will be called by the shared object's
        *  _init() function before dlopen() returns below.
	*/
	pc->curext = ext;
	ext->handle = dlopen(ext->filename, RTLD_NOW); 

	if (!ext->handle) {
		strcpy(buf, dlerror());
		error(INFO, "%s\n", buf);
		if (strstr(buf, "undefined symbol: register_extension")) {
			error(INFO, "%s may be statically linked: ",
				pc->program_name);
			fprintf(fp, "recompile without the -static flag\n");
		}
		free(ext);
		return;
	}

	if (!(ext->flags & REGISTERED)) {
		dlclose(ext->handle);
		if (ext->flags & DUPLICATE_COMMAND_NAME)
			error(INFO, 
		         "%s: shared object unloaded\n", ext->filename);
		else
			error(INFO, 
		         "%s: no commands registered: shared object unloaded\n",
				ext->filename);
		free(ext);
		return;
	}

	fprintf(fp, "%s: shared object loaded\n", ext->filename);

	/*
	 *  Put new libraries at the head of the list.
         */
	if (extension_table) {
		extension_table->prev = ext;
		ext->next = extension_table;
	}
	extension_table = ext;

	help_init();
}

/*
 *  Unload all, or as specified, extension libraries.
 */
static void 
unload_extension(char *lib)
{
        struct extension_table *ext;

	if (!lib) {
		while (extension_table) {
			ext = extension_table;
                        if (dlclose(ext->handle))
                                error(FATAL,
                                    "dlclose: %s: shared object not open\n",
                                        ext->filename);

			fprintf(fp, "%s: shared object unloaded\n", 
				ext->filename);

			extension_table = ext->next;
			free(ext);
		}

		help_init();
		return;
	}

        for (ext = extension_table; ext; ext = ext->next) {
                if (same_file(lib, ext->filename)) {
			if (dlclose(ext->handle))
				error(INFO, 
				    "dlclose: %s: shared object not open\n", 
					ext->filename);
			else {
				fprintf(fp, "%s: shared object unloaded\n",
					ext->filename);

				if (extension_table == ext) {       /* first */
					extension_table = ext->next;
					if (ext->next)
						ext->next->prev = NULL;
				} else if (ext->next == NULL)       /* last */
					ext->prev->next = NULL;
				else {                              /* middle */
					ext->prev->next = ext->next;
					ext->next->prev = ext->prev;
				}

				free(ext);
				help_init();
			}
		}
        }
}

/*
 *  Register the command_table as long as there are no command namespace
 *  clashes with the currently-existing command set.  Also delete any aliases
 *  that clash, giving the registered command name priority.
 *
 *  This function is called from the shared object's _init() function
 *  before the dlopen() call returns back to load_extension() above.  
 *  The mark of approval for load_extension() is the setting of the 
 *  REGISTERED bit in the "current" extension_table structure flags.
 */ 
void 
register_extension(struct command_table_entry *command_table)
{
	struct command_table_entry *cp;

        for (cp = command_table; cp->name; cp++) {
		if (get_command_table_entry(cp->name)) {
			error(INFO, 
                  "%s: \"%s\" is a duplicate of a currently-existing command\n",
				pc->curext->filename, cp->name);
			pc->curext->flags |= DUPLICATE_COMMAND_NAME;
			return;
		}
	}

        for (cp = command_table; cp->name; cp++) {
		if (is_alias(cp->name)) {
			error(INFO, 
               "alias \"%s\" deleted: name clash with extension command\n",
				cp->name);
			deallocate_alias(cp->name);
		}
	}

	pc->curext->command_table = command_table;   
	pc->curext->flags |= REGISTERED;             /* Mark of approval */
}


