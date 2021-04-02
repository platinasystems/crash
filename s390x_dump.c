/* s390x_dump.c - core analysis suite
 *
 * Copyright (C) 2001, 2002 Mission Critical Linux, Inc.
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
 * CVS: $Revision: 1.4 $ $Date: 2004/01/28 17:10:25 $
 */
#include "defs.h"
#include <asm/page.h>
#include "ibm_common.h"

static gzFile s390x_gzfp;

int 
is_s390x_dump(char *file)  
{
        return FALSE;
}

gzFile
s390x_dump_init(char *file)
{
        if ((s390x_gzfp = gzopen(file, "r+")) == NULL) {
                if ((s390x_gzfp = gzopen(file, "r")) == NULL)
                        return NULL;
        }

        return s390x_gzfp;
}

int
read_s390x_dumpfile(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
        paddr += S390_DUMP_HEADER_SIZE;

        if (gzseek(s390x_gzfp, (ulong)paddr, SEEK_SET) != (ulong)paddr)
                return SEEK_ERROR;

        if (gzread(s390x_gzfp, bufptr, cnt) != cnt)
                return READ_ERROR;

        return READ_ERROR;
}

int
write_s390x_dumpfile(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	return WRITE_ERROR;
}

uint
s390x_page_size(void)
{
        return PAGE_SIZE;
}

int 
s390x_memory_used(void) 
{
	return 0;
}

int 
s390x_free_memory(void) 
{
	return 0;
}

int 
s390x_memory_dump(FILE *fp)
{
	return 0;
}

ulong
get_s390x_panic_task(void)
{
        return BADVAL;
}

void 
get_s390x_panicmsg(char *buf)
{
        return;
}

