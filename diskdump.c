/* 
 * diskdump.c 
 * 
 * NOTE: The Red Hat diskdump module currently creates
 *       vmcore dumpfiles that are identical to those made
 *       by the Red Hat netdump module, and therefore the 
 *       dumpfile is recognized as such.  But just in case 
 *       there's ever a divergence, this file is being kept
 *       in place, along with the DISKDUMP-related #define's
 *       and their usage throughout the crash sources.
 *
 * Copyright (C) 2004 David Anderson
 * Copyright (C) 2004 Red Hat, Inc. All rights reserved.
 *
 * This software may be freely redistributed under the terms of the
 * GNU General Public License.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Author: David Anderson
 *
 * CVS: $Revision: 1.6 $ $Date: 2004/05/12 20:26:19 $
 */

#include "defs.h"
#include "diskdump.h"

struct diskdump_data {
	ulong flags;       /* DISKDUMP_LOCAL, plus anything else... */
        int dfd;           /* dumpfile file descriptor */
        FILE *ofp;         /* fprintf(dd->ofp, "xxx"); */
	int machine_type;  /* machine type identifier */
};

static struct diskdump_data diskdump_data = { 0 };
static struct diskdump_data *dd = &diskdump_data;

/*
 *  Determine whether a file is a diskdump creation, and if TRUE,
 *  initialize the diskdump_data structure based upon the contents
 *  of the diskdump header data.
 */
int
is_diskdump(char *file)
{
	return FALSE;
}

/*
 *  Perform any post-dumpfile determination stuff here.
 *  At a minimum
 */
int
diskdump_init(char *unused, FILE *fptr)
{
        if (!DISKDUMP_VALID())
                return FALSE;

        dd->ofp = fptr;
        return TRUE;
}

/*
 *  Read from a diskdump-created dumpfile.
 */
int
read_diskdump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
        return 0;
}

/*
 *  Write to a diskdump-created dumpfile.
 */
int
write_diskdump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	return 0;
}

ulong
get_diskdump_panic_task(void)
{
	return NO_TASK;
}

/*
 *  Send the request to the proper architecture hander.
 */

void
get_diskdump_regs(struct bt_info *bt, ulong *eip, ulong *esp)
{
        switch (dd->machine_type)
        {
        default:
                error(FATAL,
                   "diskdump support for this machine type is not available\n");
        }
}

/*
 *  Return the processor page size.
 */
uint
diskdump_page_size(void)
{
	return 0;
}

/*
 *  diskdump_free_memory(), and diskdump_memory_used() 
 *  are debug only, and probably unnecessary to implement.
 */
int
diskdump_free_memory(void)
{
        return 0;
}

int diskdump_memory_used(void)
{
        return 0;
}

/*
 *  This function is dump-type independent, and could be used
 *  to dump the diskdump_data structure contents and perhaps
 *  the diskdump header data.
 */
int
diskdump_memory_dump(FILE *fp)
{
	return 0;
}

/*
 *  Get the switch_stack address of the passed-in task.  
 */
ulong
get_diskdump_switch_stack(ulong task)
{
	return 0;
}
