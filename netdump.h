/* netdump.h
 *
 * Copyright (C) 2002, 2003, 2004 David Anderson
 * Copyright (C) 2002, 2003, 2004 Red Hat, Inc. All rights reserved.
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
 * CVS: $Revision: 1.5 $ $Date: 2004/01/28 17:10:25 $
 */

#include <elf.h>

#define NETDUMP_ELF32_HEADER_SIZE \
        sizeof(Elf32_Ehdr)+sizeof(Elf32_Phdr)+sizeof(Elf32_Phdr)
#define NETDUMP_ELF64_HEADER_SIZE \
        sizeof(Elf64_Ehdr)+sizeof(Elf64_Phdr)+sizeof(Elf64_Phdr)
#define MAX_NETDUMP_ELF_HEADER_SIZE \
        MAX(NETDUMP_ELF32_HEADER_SIZE, NETDUMP_ELF64_HEADER_SIZE)

#define NT_TASKSTRUCT 4
