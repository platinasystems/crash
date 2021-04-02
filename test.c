/* test.c - core analysis suite
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
 * 02/29/00, 2.2    Bug fixes, new commands, options
 * 04/11/00, 2.3    Bug fixes, new command, options, initial PowerPC framework
 * 04/12/00  ---    Transition to BitKeeper version control
 * 
 * BitKeeper ID: @(#)test.c 1.1
 *
 * 09/28/00  ---    Transition to CVS version control
 *
 * CVS: $Revision: 1.3 $ $Date: 2004/01/28 17:11:25 $
 */

#include "defs.h"

/*
 *  Test your stuff here first if you'd like.  If anything's being done
 *  below in this routine, consider it leftover trash...
 */
void
cmd_test(void)
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

        while (args[optind]) {
                ;
                optind++;
        }
}

/* 
 *  Scratch routine for testing a feature on a per-task basis by entering
 *  the "foreach test" command.  Like cmd_test(), anything that's being done
 *  below in this routine can be considered trash.
 */     
void
foreach_test(ulong task, ulong flags)
{
 
}

/*
 *  Template for building a new command.
 */
void
cmd_template(void)
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

	while (args[optind]) {
		;
		optind++;
	}
}

