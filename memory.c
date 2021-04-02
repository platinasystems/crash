/* memory.c - core analysis suite
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
 * BitKeeper ID: @(#)memory.c 1.17
 *
 * 09/28/00  ---    Transition to CVS version control
 *
 * CVS: $Revision: 1.90 $ $Date: 2002/02/22 15:16:36 $
 */

#include "defs.h"
#ifdef USE_MMAP
#include <sys/mman.h>
#endif

struct meminfo {           /* general purpose memory information structure */
        ulong cache;       /* used by the various memory searching/dumping */
        ulong slab;        /* routines.  Only one of these is used per cmd */
        ulong c_flags;     /* so stuff whatever's helpful in here...       */
        ulong c_offset;
	ulong c_num;
	ulong s_mem; 
	void *s_freep; 
	ulong *s_index; 
	ulong s_inuse;
	ulong cpucached_cache;
	ulong cpucached_slab;
        ulong inuse;
	ulong order;
	ulong slabsize;
        ulong num_slabs;
        ulong spec_addr;
        ulong flags;
	ulong size;
	int memtype;
	int free;
        char *reqname;
	char *curname;
	ulong *addrlist;
	int *kmem_bufctl;
	ulong *cpudata[NR_CPUS];
	ulong found;
	ulong retval;
	char *ignore;
	int errors;
	int calls;
	int cpu;
	ulong get_shared;
	ulong get_totalram;
	ulong get_buffers;
	ulong get_slabs;
	char *slab_buf;
	char *cache_buf;
};

static char *memtype_string(int);
static char *error_handle_string(ulong);
static void dump_mem_map(struct meminfo *);
static void dump_free_pages(struct meminfo *);
static void dump_multidimensional_free_pages(struct meminfo *);
static void dump_free_pages_zones(struct meminfo *);
static int dump_zone_free_area(ulong, int, ulong);
static void dump_page_hash_table(struct meminfo *);
static void kmem_search(struct meminfo *);
static void kmem_cache_init(void);
static ulong max_cpudata_limit(ulong, ulong *);
static char *is_kmem_cache_addr(ulong, char *);
static void dump_kmem_cache(struct meminfo *);
static void dump_kmem_cache_percpu(struct meminfo *);
static char *vaddr_to_kmem_cache(ulong, char *);
static ulong vaddr_to_slab(ulong);
static void do_slab_chain(int, struct meminfo *);
static void do_slab_chain_percpu(long, struct meminfo *);
static void save_slab_data(struct meminfo *);
static int slab_data_saved(struct meminfo *);
static void dump_saved_slab_data(void);
static void dump_slab(struct meminfo *);
static void dump_slab_percpu(struct meminfo *);
static void gather_slab_free_list(struct meminfo *);
static void gather_slab_free_list_percpu(struct meminfo *);
static void gather_cpudata_list(struct meminfo *);
static int check_cpudata_list(struct meminfo *, ulong);
static void gather_slab_cached_count(struct meminfo *);
static void dump_slab_objects(struct meminfo *);
static void dump_slab_objects_percpu(struct meminfo *);
static void dump_vmlist(struct meminfo *);
static int dump_page_lists(struct meminfo *);
static void dump_kmeminfo(void);
static int page_to_phys(ulong, ulong *); 
static int phys_to_page(ulong, ulong *); 
static void display_memory(ulong, long, ulong, int); 
static void search(ulong, ulong, ulong, int, ulong *, int);
static int next_upage(struct task_context *, ulong, ulong *);
static int next_kpage(ulong, ulong *);
static int vm_area_page_dump(ulong, ulong, ulong, ulong, void *, 
	struct reference *);
static void dump_swap_info(ulong, ulong *, ulong *);
static char *get_swapdev(ulong, char *);
static void fill_swap_info(ulong);
static char *vma_file_offset(ulong, ulong, char *);
#ifdef USE_MMAP
static char *mmap_page(ulong, int);
#endif
static ssize_t read_dev_kmem(ulong, char *, long);
static void dump_numa_nodes(ulong);
static void numa_table_init(void);
static void do_vm_flags(ulong);


/*
 *  Memory display modes specific to this file.
 */
#define DISPLAY_8      (0x2)
#define DISPLAY_16     (0x4)
#define DISPLAY_32     (0x8)
#define DISPLAY_64     (0x10)
#define DISPLAY_TYPES  (DISPLAY_8|DISPLAY_16|DISPLAY_32|DISPLAY_64)
#define SHOW_OFFSET    (0x20)
#define SYMBOLIC       (0x40)
#define HEXADECIMAL    (0x80)
#define DECIMAL        (0x100)
#define UDECIMAL       (0x200)
#define ASCII_ENDLINE  (0x400)

static ulong DISPLAY_DEFAULT;

/*
 *  Verify that the sizeof the primitive types are reasonable.
 */
void
mem_init(void)
{
        if (sizeof(char) != SIZEOF_8BIT)
                error(FATAL, "unsupported sizeof(char): %d\n", sizeof(char));
        if (sizeof(short) != SIZEOF_16BIT)
                error(FATAL, "unsupported sizeof(short): %d\n", sizeof(short));
        if ((sizeof(int) != SIZEOF_32BIT) && (sizeof(int) != SIZEOF_64BIT))
                error(FATAL, "unsupported sizeof(int): %d\n", sizeof(int));
        if ((sizeof(long) != SIZEOF_32BIT) && (sizeof(long) != SIZEOF_64BIT))
                error(FATAL, "unsupported sizeof(long): %d\n", sizeof(long));

        DISPLAY_DEFAULT = (sizeof(long) == 8) ? DISPLAY_64 : DISPLAY_32;
}


/*
 *  Stash a few popular offsets and some basic kernel virtual memory
 *  items used by routines in this file.
 */
void
vm_init(void)
{
	char buf[BUFSIZE];
	long offset;
	int dimension;

        OFFSET(task_struct_mm) = MEMBER_OFFSET("task_struct", "mm");
        OFFSET(mm_struct_mmap) = MEMBER_OFFSET("mm_struct", "mmap");
        OFFSET(mm_struct_pgd) = MEMBER_OFFSET("mm_struct", "pgd");
	OFFSET(mm_struct_rss) = MEMBER_OFFSET("mm_struct", "rss");
	OFFSET(mm_struct_total_vm) = MEMBER_OFFSET("mm_struct", "total_vm");
	OFFSET(mm_struct_start_code) = MEMBER_OFFSET("mm_struct", "start_code");
        OFFSET(vm_area_struct_vm_mm) = 
                MEMBER_OFFSET("vm_area_struct", "vm_mm");
        OFFSET(vm_area_struct_vm_next) = 
                MEMBER_OFFSET("vm_area_struct", "vm_next");
        OFFSET(vm_area_struct_vm_end) =
                MEMBER_OFFSET("vm_area_struct", "vm_end");
        OFFSET(vm_area_struct_vm_start) = 
                MEMBER_OFFSET("vm_area_struct", "vm_start");
        OFFSET(vm_area_struct_vm_flags) =
                MEMBER_OFFSET("vm_area_struct", "vm_flags");
        OFFSET(vm_area_struct_vm_file) =
                MEMBER_OFFSET("vm_area_struct", "vm_file");
        OFFSET(vm_area_struct_vm_offset) =
                MEMBER_OFFSET("vm_area_struct", "vm_offset");
        OFFSET(vm_area_struct_vm_pgoff) =
                MEMBER_OFFSET("vm_area_struct", "vm_pgoff");

	OFFSET(vm_struct_addr) = MEMBER_OFFSET("vm_struct", "addr");
	OFFSET(vm_struct_size) = MEMBER_OFFSET("vm_struct", "size");
	OFFSET(vm_struct_next) = MEMBER_OFFSET("vm_struct", "next");

	if ((offset = MEMBER_OFFSET("page", "next")) >= 0) {
		OFFSET(page_next) = offset;
		OFFSET(page_prev) = MEMBER_OFFSET("page", "prev");
	} else if ((offset = MEMBER_OFFSET("page", "list")) >= 0) {
		OFFSET(page_list_next) = 
			MEMBER_OFFSET("list_head", "next") + offset;
		OFFSET(page_list_prev) = 
			MEMBER_OFFSET("list_head", "prev") + offset;
	}
	OFFSET(page_next_hash) = MEMBER_OFFSET("page", "next_hash");
	OFFSET(page_inode) = MEMBER_OFFSET("page", "inode");
	OFFSET(page_offset) = MEMBER_OFFSET("page", "offset");
	OFFSET(page_count) = MEMBER_OFFSET("page", "count");
	OFFSET(page_flags) = MEMBER_OFFSET("page", "flags");
        OFFSET(page_mapping) = MEMBER_OFFSET("page", "mapping");
        OFFSET(page_index) = MEMBER_OFFSET("page", "index");
        OFFSET(page_buffers) = MEMBER_OFFSET("page", "buffers");
	OFFSET(page_lru) = MEMBER_OFFSET("page", "lru");

	OFFSET(mm_struct_pgd) = MEMBER_OFFSET("mm_struct", "pgd");

	OFFSET(swap_info_struct_swap_file) =
        	MEMBER_OFFSET("swap_info_struct", "swap_file");
	OFFSET(swap_info_struct_swap_vfsmnt) =
        	MEMBER_OFFSET("swap_info_struct", "swap_vfsmnt");
	OFFSET(swap_info_struct_flags) =
        	MEMBER_OFFSET("swap_info_struct", "flags");	
	OFFSET(swap_info_struct_swap_map) =
        	MEMBER_OFFSET("swap_info_struct", "swap_map");
	OFFSET(swap_info_struct_swap_device) =
        	MEMBER_OFFSET("swap_info_struct", "swap_device");
	OFFSET(swap_info_struct_prio) =
        	MEMBER_OFFSET("swap_info_struct", "prio");
	OFFSET(swap_info_struct_max) =
        	MEMBER_OFFSET("swap_info_struct", "max");
	OFFSET(swap_info_struct_pages) =
        	MEMBER_OFFSET("swap_info_struct", "pages");

        if (!STRUCT_EXISTS("kmem_slab_s") && STRUCT_EXISTS("slab_s")) {
                vt->flags |= PERCPU_KMALLOC;
		OFFSET(kmem_cache_s_num) = 
			MEMBER_OFFSET("kmem_cache_s", "num");
		OFFSET(kmem_cache_s_next) = 
			MEMBER_OFFSET("kmem_cache_s", "next");
		OFFSET(kmem_cache_s_name) = 
			MEMBER_OFFSET("kmem_cache_s", "name");
		OFFSET(kmem_cache_s_objsize) = 
			MEMBER_OFFSET("kmem_cache_s", "objsize");
		OFFSET(kmem_cache_s_flags) = 
			MEMBER_OFFSET("kmem_cache_s", "flags");
		OFFSET(kmem_cache_s_gfporder) = 
			MEMBER_OFFSET("kmem_cache_s", "gfporder");
		OFFSET(kmem_cache_s_slabs) = 
			MEMBER_OFFSET("kmem_cache_s", "slabs");
                OFFSET(kmem_cache_s_slabs_full) =
			MEMBER_OFFSET("kmem_cache_s", "slabs_full");
                OFFSET(kmem_cache_s_slabs_partial) =
			MEMBER_OFFSET("kmem_cache_s", "slabs_partial");
                OFFSET(kmem_cache_s_slabs_free) = 
			MEMBER_OFFSET("kmem_cache_s", "slabs_free");
		OFFSET(kmem_cache_s_cpudata) =
			MEMBER_OFFSET("kmem_cache_s", "cpudata");
		OFFSET(kmem_cache_s_colour_off) =
			MEMBER_OFFSET("kmem_cache_s", "colour_off");

		OFFSET(slab_s_list) = MEMBER_OFFSET("slab_s", "list");
		OFFSET(slab_s_s_mem) = MEMBER_OFFSET("slab_s", "s_mem");
		OFFSET(slab_s_inuse) = MEMBER_OFFSET("slab_s", "inuse");
		OFFSET(slab_s_free) = MEMBER_OFFSET("slab_s", "free");

		OFFSET(cpucache_s_avail) = MEMBER_OFFSET("cpucache_s", "avail");
		OFFSET(cpucache_s_limit) = MEMBER_OFFSET("cpucache_s", "limit");

		SIZE(slab_s) = STRUCT_SIZE("slab_s");
		SIZE(cpucache_s) = STRUCT_SIZE("cpucache_s");
	} else {
		OFFSET(kmem_cache_s_c_nextp) = 
			MEMBER_OFFSET("kmem_cache_s", "c_nextp");
		OFFSET(kmem_cache_s_c_name) = 
			MEMBER_OFFSET("kmem_cache_s", "c_name");
		OFFSET(kmem_cache_s_c_num) = 
			MEMBER_OFFSET("kmem_cache_s", "c_num");
		OFFSET(kmem_cache_s_c_org_size) = 
			MEMBER_OFFSET("kmem_cache_s", "c_org_size");
		OFFSET(kmem_cache_s_c_flags) = 
			MEMBER_OFFSET("kmem_cache_s", "c_flags");
		OFFSET(kmem_cache_s_c_offset) = 
			MEMBER_OFFSET("kmem_cache_s", "c_offset");
		OFFSET(kmem_cache_s_c_firstp) = 
			MEMBER_OFFSET("kmem_cache_s", "c_firstp");
		OFFSET(kmem_cache_s_c_gfporder) =
			MEMBER_OFFSET("kmem_cache_s", "c_gfporder");
		OFFSET(kmem_cache_s_c_magic) =
			MEMBER_OFFSET("kmem_cache_s", "c_magic");
		OFFSET(kmem_cache_s_c_align) =
			MEMBER_OFFSET("kmem_cache_s", "c_align");
	
		OFFSET(kmem_slab_s_s_nextp) = 
			MEMBER_OFFSET("kmem_slab_s", "s_nextp");
		OFFSET(kmem_slab_s_s_freep) = 
			MEMBER_OFFSET("kmem_slab_s", "s_freep");
		OFFSET(kmem_slab_s_s_inuse) = 
			MEMBER_OFFSET("kmem_slab_s", "s_inuse");
		OFFSET(kmem_slab_s_s_mem) = 
			MEMBER_OFFSET("kmem_slab_s", "s_mem");
		OFFSET(kmem_slab_s_s_index) = 
			MEMBER_OFFSET("kmem_slab_s", "s_index");
		OFFSET(kmem_slab_s_s_offset) = 
			MEMBER_OFFSET("kmem_slab_s", "s_offset");
		OFFSET(kmem_slab_s_s_magic) = 
			MEMBER_OFFSET("kmem_slab_s", "s_magic");

		SIZE(kmem_slab_s) = STRUCT_SIZE("kmem_slab_s");
	}

	vt->kernel_pgd = symbol_value("swapper_pg_dir");
	get_symbol_data("high_memory", sizeof(ulong), &vt->high_memory);
	get_symbol_data("mem_map", sizeof(char *), &vt->mem_map);
	vt->vmalloc_start = machdep->vmalloc_start();
	vt->total_pages = BTOP(VTOP(vt->high_memory));
	if (symbol_exists("totalram_pages"))
		get_symbol_data("totalram_pages", sizeof(ulong), 
			&vt->totalram_pages);
        get_symbol_data("max_mapnr", sizeof(ulong), &vt->max_mapnr);
	get_symbol_data("nr_swapfiles", sizeof(unsigned int), 
		&vt->nr_swapfiles);

	SIZE(page) = STRUCT_SIZE("page");
	SIZE(free_area_struct) = STRUCT_SIZE("free_area_struct");
	SIZE(zone_struct) = STRUCT_SIZE("zone_struct");
	SIZE(kmem_cache_s) = STRUCT_SIZE("kmem_cache_s");
	SIZE(kmem_bufctl_t) = STRUCT_SIZE("kmem_bufctl_t");
	SIZE(swap_info_struct) = STRUCT_SIZE("swap_info_struct");
	SIZE(mm_struct) = STRUCT_SIZE("mm_struct");
	SIZE(vm_area_struct) = STRUCT_SIZE("vm_area_struct");

	if (STRUCT_EXISTS("pglist_data")) {
		vt->flags |= ZONES;

		if (symbol_exists("pgdat_list")) 
			vt->flags |= NUMA;

		if (symbol_exists("numnodes"))
			get_symbol_data("numnodes", sizeof(int), &vt->numnodes);
		else 
			vt->numnodes = 1;

		OFFSET(pglist_data_node_zones) =
			MEMBER_OFFSET("pglist_data", "node_zones");
		OFFSET(pglist_data_node_mem_map) =
			MEMBER_OFFSET("pglist_data", "node_mem_map");
		OFFSET(pglist_data_node_start_paddr) =
			MEMBER_OFFSET("pglist_data", "node_start_paddr");
		OFFSET(pglist_data_node_start_mapnr) =
			MEMBER_OFFSET("pglist_data", "node_start_mapnr");
		OFFSET(pglist_data_node_size) =
			MEMBER_OFFSET("pglist_data", "node_size");
		OFFSET(pglist_data_node_id) =
			MEMBER_OFFSET("pglist_data", "node_id");
		OFFSET(pglist_data_node_next) =
			MEMBER_OFFSET("pglist_data", "node_next");
		OFFSET(pglist_data_bdata) =
			MEMBER_OFFSET("pglist_data", "bdata");

                OFFSET(zone_struct_free_pages) =
                        MEMBER_OFFSET("zone_struct", "free_pages");
                OFFSET(zone_struct_free_area) =
                        MEMBER_OFFSET("zone_struct", "free_area");
                OFFSET(zone_struct_zone_pgdat) =
                        MEMBER_OFFSET("zone_struct", "zone_pgdat");
                OFFSET(zone_struct_name) =
                        MEMBER_OFFSET("zone_struct", "name");
                OFFSET(zone_struct_size) =
                        MEMBER_OFFSET("zone_struct", "size");
                OFFSET(zone_struct_zone_start_paddr) = 
                        MEMBER_OFFSET("zone_struct", "zone_start_paddr");
                OFFSET(zone_struct_zone_start_mapnr) =
                        MEMBER_OFFSET("zone_struct", "zone_start_mapnr");
                OFFSET(zone_struct_zone_mem_map) =
                        MEMBER_OFFSET("zone_struct", "zone_mem_map");
                OFFSET(zone_struct_inactive_clean_pages) =
                        MEMBER_OFFSET("zone_struct", "inactive_clean_pages");
                OFFSET(zone_struct_inactive_clean_list) =
                        MEMBER_OFFSET("zone_struct", "inactive_clean_list");
	} else
		vt->numnodes = 1;

	numa_table_init();

	sprintf(buf, BITS32() ? "%llx" : "%lx", machdep->memory_size());

	vt->paddr_prlen = strlen(buf);

	if (vt->flags & PERCPU_KMALLOC) 
                vt->dump_kmem_cache = dump_kmem_cache_percpu;
	else
                vt->dump_kmem_cache = dump_kmem_cache;

        if (vt->flags & (NUMA|ZONES)) {
                vt->dump_free_pages = dump_free_pages_zones;
        } else {
        	get_array_length("free_area", &dimension);
        	if (dimension) 
                	vt->dump_free_pages = dump_multidimensional_free_pages;
		else
                	vt->dump_free_pages = dump_free_pages;
        }

        if (!(vt->vma_cache = (char *)malloc(SIZE(vm_area_struct)*VMA_CACHE)))
                error(FATAL, "cannot malloc vm_area_struct cache\n");

#if defined(S390) || defined(S390X)
	vt->flags |= COMMON_VADDR;
#endif
}

/*
 *  This command displays the contents of memory, with the output formatted
 *  in several different manners.  The starting address may be entered either
 *  symbolically or by address.  The default output size is the size of a long
 *  data type, and the default output format is hexadecimal.  When hexadecimal
 *  output is used, the output will be accompanied by an ASCII translation.
 *  These are the options:
 *
 *      -p  address argument is a physical address.
 *      -u  address argument is a user virtual address.
 *      -d  display output in signed decimal format (default is hexadecimal).
 *      -D  display output in unsigned decimal format (default is hexadecimal).
 *      -s  displays output symbolically when appropriate.
 *      -8  display output in 8-bit values.
 *     -16  display output in 16-bit values.
 *     -32  display output in 32-bit values (default on 32-bit machines).
 *     -64  display output in 64-bit values (default on 64-bit machines).
 *
 *  The default number of items to display is 1, but a count argument, if any,
 *  must follow the address.
 */
void
cmd_rd(void)
{
	int c, memtype;
	ulong flag;
	long count;
	ulong addr, endaddr;
	ulong offset;
	struct syment *sp;

	flag = HEXADECIMAL|DISPLAY_DEFAULT;
	endaddr = 0;
	memtype = KVADDR;
	count = -1;

        while ((c = getopt(argcnt, args, "e:pudDuso:81:3:6:")) != EOF) {
                switch(c)
		{
		case '8':
			flag &= ~DISPLAY_TYPES;
                        flag |= DISPLAY_8;
			break;

		case '1':
			if (!STREQ(optarg, "6")) {
				error(INFO, 
				    "invalid option: %c%s\n", c, optarg);
				argerrs++;
			} else {
				flag &= ~DISPLAY_TYPES;
				flag |= DISPLAY_16;
			}
			break;

		case '3':
                        if (!STREQ(optarg, "2")) {
                                error(INFO, 
				    "invalid option: %c%s\n", c, optarg);
                                argerrs++;
                        } else {
                                flag &= ~DISPLAY_TYPES;
                                flag |= DISPLAY_32;
                        }
			break;

		case '6':
                        if (!STREQ(optarg, "4")) {
                                error(INFO, 
				    "invalid option: %c%s\n", c, optarg);
                                argerrs++;
                        } else {
                                flag &= ~DISPLAY_TYPES;
                                flag |= DISPLAY_64;
                        }
			break;

		case 'e':
			endaddr = htol(optarg, FAULT_ON_ERROR, NULL);
			break;

		case 's':
			if (flag & DISPLAY_DEFAULT)
				flag |= SYMBOLIC;
			else {
				error(INFO, 
				   "-s only allowed with %d-bit display\n",
					DISPLAY_DEFAULT == DISPLAY_64 ?
					64 : 32);
				argerrs++;
			}
			break;

		case 'o':
			offset = stol(optarg, FAULT_ON_ERROR, NULL);
			flag |= SHOW_OFFSET;
			break;

		case 'p':
			memtype &= ~(UVADDR|KVADDR);
			memtype = PHYSADDR;
			break;

		case 'u':
			memtype &= ~(KVADDR|PHYSADDR);
			memtype = UVADDR;
			break;

		case 'd':
			flag &= ~(HEXADECIMAL|DECIMAL);
			flag |= DECIMAL;
			break;

		case 'D':
			flag &= ~(HEXADECIMAL|UDECIMAL);
                        flag |= UDECIMAL;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs || !args[optind])
		cmd_usage(pc->curcmd, SYNOPSIS);

        if (*args[optind] == '(') 
                addr = eval(args[optind], FAULT_ON_ERROR, NULL);
	else if (hexadecimal(args[optind], 0)) 
                addr = htol(args[optind], FAULT_ON_ERROR, NULL);
        else if ((sp = symbol_search(args[optind])))
                addr = sp->value;
        else {
		fprintf(fp, "symbol not found: %s\n", args[optind]);
                fprintf(fp, "possible aternatives:\n");
                if (!symbol_query(args[optind], "  ", NULL))
                      	fprintf(fp, "  (none found)\n");
		return;
	}

        if (flag & SHOW_OFFSET)
                addr += offset;

        if (args[++optind])
                count = stol(args[optind], FAULT_ON_ERROR, NULL);

	if (count == -1) {
		if (endaddr) {
			long bcnt;

			if (endaddr <= addr)
				error(FATAL, "invalid ending address: %lx\n",
					endaddr);

			bcnt = endaddr - addr;

        		switch (flag & (DISPLAY_TYPES))
        		{
        		case DISPLAY_64:
				count = bcnt/8;
                		break;
        		case DISPLAY_32:
				count = bcnt/4;
				break;
        		case DISPLAY_16:
				count = bcnt/2;
				break;
        		case DISPLAY_8:
				count = bcnt;
				break;
			}

			if (bcnt == 0)
				count = 1;
		} else
			count = 1;
	} else if (endaddr)
		error(WARNING, 
		    "ending address ignored when count is specified\n");

	if ((flag & HEXADECIMAL) && !(flag & SYMBOLIC))
		flag |= ASCII_ENDLINE;

	if (memtype == KVADDR) {
		if (!COMMON_VADDR_SPACE() && !IS_KVADDR(addr))
			memtype = UVADDR;
	}

	display_memory(addr, count, flag, memtype);
        
}

/*
 *  display_memory() does the work for cmd_rd(), but can (and is) called by
 *  other routines that want to dump raw data.  Based upon the flag, the 
 *  output format is tailored to fit in an 80-character line.  Hexadecimal
 *  output is accompanied by an end-of-line ASCII translation.
 */
#define MAX_HEXCHARS_PER_LINE (32)

#define ASCII_START_8   (59)     /* line locations where ASCII output starts */
#define ASCII_START_16  (51)
#define ASCII_START_32  (47)
#define ASCII_START_64  (45)

#define ENTRIES_8   (16)         /* number of entries per line per size */
#define ENTRIES_16  (8)
#define ENTRIES_32  (4)
#define ENTRIES_64  (2)

struct memloc {                  /* common holder of read memory */
        uint8_t u8;
        uint16_t u16;
        uint32_t u32;
        uint64_t u64;
};

static void
display_memory(ulong addr, long count, ulong flag, int memtype)
{
	int i, j;
	size_t typesz;
	void *location;
	char readtype[20];
	char *addrtype;
	ulong origaddr;
	struct memloc mem;
	int per_line;
	int hx;
	char hexchars[MAX_HEXCHARS_PER_LINE+1];
	char ch;
	int linelen;
	char buf[BUFSIZE];
	int int32;
	int ascii_start;
	char *hex_64_fmt = BITS32() ? "%.*llx " : "%.*lx ";
	char *dec_64_fmt = BITS32() ? "%12lld " : "%15ld ";
	char *dec_u64_fmt = BITS32() ? "%12llu " : "%20lu ";

	if (count <= 0) 
		error(FATAL, "invalid count request: %ld\n", count);

	int32 = sizeof(int) == 4 ? TRUE : FALSE;

	switch (memtype)
	{
	case KVADDR:
		addrtype = "KVADDR";
		break;
	case UVADDR:
		addrtype = "UVADDR";
		break;
	case PHYSADDR:
		addrtype = "PHYSADDR";
		break;
	}

	if (MCLXDEBUG(4))
		fprintf(fp, "<addr: %lx count: %ld flag: %lx (%s)>\n", 
			addr, count, flag, addrtype);

	origaddr = addr;

	switch (flag & (DISPLAY_TYPES))
	{
	case DISPLAY_64:
		ascii_start = ASCII_START_64; 
		typesz = SIZEOF_64BIT;
		location = &mem.u64;
		sprintf(readtype, "64-bit %s", addrtype); 
		per_line = ENTRIES_64; 
		break;

	case DISPLAY_32:
		ascii_start = ASCII_START_32; 
		typesz = SIZEOF_32BIT;
		location = int32 ?  (void *)&mem.u32 : &mem.u64;
		sprintf(readtype, "32-bit %s", addrtype);
		per_line = ENTRIES_32;
		break;

	case DISPLAY_16:
		ascii_start = ASCII_START_16; 
		typesz = SIZEOF_16BIT;
		location = &mem.u16;
		sprintf(readtype, "16-bit %s", addrtype);
		per_line = ENTRIES_16;
		break;

	case DISPLAY_8:
		ascii_start = ASCII_START_8; 
		typesz = SIZEOF_8BIT;
		location = &mem.u8;
		sprintf(readtype, "8-bit %s", addrtype);
		per_line = ENTRIES_8;
		break;
	}

	for (i = 0; i < count; i++) {
		readmem(addr, memtype, location, typesz, 
			readtype, FAULT_ON_ERROR);

                if ((i % per_line) == 0) {
                        if (i) {
				if (flag & ASCII_ENDLINE) {
					fprintf(fp, "  %s", hexchars);
				}
				fprintf(fp, "\n");
			}
                        fprintf(fp,"%.*lx:  ", VADDR_PRLEN, addr);
			hx = 0;
			BZERO(hexchars, MAX_HEXCHARS_PER_LINE+1);
			linelen = VADDR_PRLEN + strlen(":  ");
                }

	        switch (flag & DISPLAY_TYPES)
	        {
	        case DISPLAY_64:
			if ((flag & (HEXADECIMAL|SYMBOLIC|DISPLAY_DEFAULT)) ==
			    (HEXADECIMAL|SYMBOLIC|DISPLAY_DEFAULT)) {
				if (in_ksymbol_range(mem.u64)) {
					fprintf(fp, "%-16s ",
                                            value_to_symstr(mem.u64, buf, 0));
					linelen += strlen(buf)+1;
					break;
				}
			} 
			if (flag & HEXADECIMAL) {
				fprintf(fp, hex_64_fmt, LONG_LONG_PRLEN, 
					mem.u64);
				linelen += (LONG_LONG_PRLEN + 1);
			}

                        else if (flag & DECIMAL)
                                fprintf(fp, dec_64_fmt, mem.u64);
                        else if (flag & UDECIMAL)
                                fprintf(fp, dec_u64_fmt, mem.u64);

	                break;

	        case DISPLAY_32:
                        if ((flag & (HEXADECIMAL|SYMBOLIC|DISPLAY_DEFAULT)) ==
                            (HEXADECIMAL|SYMBOLIC|DISPLAY_DEFAULT)) {
				if (in_ksymbol_range(int32 ? 
				    mem.u32 : mem.u64)) {
					fprintf(fp, INT_PRLEN == 16 ? 
					    "%-16s " : "%-8s ",
                                                value_to_symstr(int32 ?
						mem.u32 : mem.u64, buf, 0));
					linelen += strlen(buf)+1;
					break;
				}
                        }
			if (flag & HEXADECIMAL) {
				fprintf(fp, "%.*x ", INT_PRLEN, 
					int32 ?  mem.u32 : (uint32_t)mem.u64);
				linelen += (INT_PRLEN + 1);
			}
                        else if (flag & DECIMAL)
                                fprintf(fp, "%12d ", 
					int32 ?  mem.u32 : (uint32_t)mem.u64);
                        else if (flag & UDECIMAL)
                                fprintf(fp, "%12u ", 
					int32 ?  mem.u32 : (uint32_t)mem.u64);
	                break;

	        case DISPLAY_16:
			if (flag & HEXADECIMAL) {
				fprintf(fp, "%.*x ", SHORT_PRLEN, mem.u16);
				linelen += (SHORT_PRLEN + 1);
			}
                        else if (flag & DECIMAL)
                                fprintf(fp, "%5d ", mem.u16);
                        else if (flag & UDECIMAL)
                                fprintf(fp, "%5u ", mem.u16);
	                break;

	        case DISPLAY_8:
			if (flag & HEXADECIMAL) {
				fprintf(fp, "%.*x ", CHAR_PRLEN, mem.u8);
				linelen += (CHAR_PRLEN + 1);
			}
                        else if (flag & DECIMAL)
                                fprintf(fp, "%3d ", mem.u8); 
			else if (flag & UDECIMAL)
                                fprintf(fp, "%3u ", mem.u8);
	                break;
	        }

		if (flag & HEXADECIMAL) {
	                switch (flag & DISPLAY_TYPES)
	                {
	                case DISPLAY_64:
		                for (j = 0; j < SIZEOF_64BIT; j++) {
		                        ch = (mem.u64 >> (8*j)) & 0xff;
		                        if ((ch >= 0x20) && (ch < 0x7f)) {
		                                hexchars[hx++] = ch;
		                        }
		                        else hexchars[hx++] = '.';
		                }
	                        break;
	
	                case DISPLAY_32:
	                        for (j = 0; j < (SIZEOF_32BIT); j++) {
					ch = int32 ?
	                                    (mem.u32 >> (8*j)) & 0xff :
					    (mem.u64 >> (8*j)) & 0xff;
	                                if ((ch >= 0x20) && (ch < 0x7f)) {
	                                        hexchars[hx++] = ch;
	                                }
	                                else hexchars[hx++] = '.';
	                        }
	                        break;
	
	                case DISPLAY_16:
	                        for (j = 0; j < SIZEOF_16BIT; j++) {
	                                ch = (mem.u16 >> (8*j)) & 0xff;
	                                if ((ch >= 0x20) && (ch < 0x7f)) {
	                                        hexchars[hx++] = ch;
	                                }
	                                else hexchars[hx++] = '.';
	                        }
	                        break;
	
	                case DISPLAY_8:
	                        for (j = 0; j < SIZEOF_8BIT; j++) {
	                                ch = (mem.u8 >> (8*j)) & 0xff;
	                                if ((ch >= 0x20) && (ch < 0x7f)) {
	                                        hexchars[hx++] = ch;
	                                }
	                                else hexchars[hx++] = '.';
	                        }
	                        break;
	                }
		}

		addr += typesz;
	}

	if ((flag & ASCII_ENDLINE) && hx) {
		pad_line(fp, ascii_start - linelen, ' ');
		fprintf(fp, "  %s", hexchars);
	}

	fprintf(fp,"\n");
}

/*
 *  cmd_wr() is the sister routine of cmd_rd(), used to modify the contents
 *  of memory.  Like the "rd" command, the starting address may be entered 
 *  either symbolically or by address.  The default modification size 
 *  is the size of a long data type.  Write permission must exist on the
 *  /dev/mem.  The flags are similar to those used by rd:  
 * 
 *      -p  address argument is a physical address.
 *      -u  address argument is user virtual address (only if ambiguous).
 *      -k  address argument is user virtual address (only if ambiguous).
 *      -8  write data in an 8-bit value.
 *     -16  write data in a 16-bit value.
 *     -32  write data in a 32-bit values (default on 32-bit machines).
 *     -64  write data in a 64-bit values (default on 64-bit machines).
 * 
 *  Only one value of a given datasize may be modified.
 */
void
cmd_wr(void)
{
	int c;
	ulong value; 
	int addr_entered, value_entered;
	int memtype;
        struct memloc mem;
	ulong addr;
	void *buf;
	long size;
	struct syment *sp;

	if (DUMPFILE()) 
		error(FATAL, "not allowed on dumpfiles\n");

	memtype = 0;
	size = 4;
	addr_entered = value_entered = FALSE;

        while ((c = getopt(argcnt, args, "ukp81:3:6:")) != EOF) {
                switch(c)
		{
		case '8':
			size = 1;
			break;

		case '1':
			if (!STREQ(optarg, "6")) {
				error(INFO, 
				    "invalid option: %c%s\n", c, optarg);
				argerrs++;
			} else 
				size = 2;
			break;

		case '3':
                        if (!STREQ(optarg, "2")) {
                                error(INFO, 
				    "invalid option: %c%s\n", c, optarg);
                                argerrs++;
                        } else 
                                size = 4;
			break;

		case '6':
                        if (!STREQ(optarg, "4")) {
                                error(INFO, 
				    "invalid option: %c%s\n", c, optarg);
                                argerrs++;
                        } else 
                                size = 8;
			break;

		case 'p':
			memtype = PHYSADDR;
			break;

		case 'u':
			memtype = UVADDR;
			break;

		case 'k':
			memtype = KVADDR;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

        if (args[optind]) {
		if (hexadecimal(args[optind], 0)) 
                        addr = htol(args[optind], FAULT_ON_ERROR, NULL);
                else if ((sp = symbol_search(args[optind])))
                        addr = sp->value;
                else {
			fprintf(fp, "symbol not found: %s\n", args[optind]);
                        fprintf(fp, "possible aternatives:\n");
                        if (!symbol_query(args[optind], "  ", NULL))
                        	fprintf(fp, "  (none found)\n");
			return;
		}
		addr_entered = TRUE;

                if (args[++optind]) {
                        value = stol(args[optind], FAULT_ON_ERROR, NULL);
			value_entered = TRUE;
        
			switch (size) 
			{
			case 1:
				mem.u8 = (uint8_t)value;
				buf = (void *)&mem.u8;
				break;
			case 2:
				mem.u16 = (uint16_t)value;
				buf = (void *)&mem.u16;
				break;
			case 4:
				mem.u32 = (uint32_t)value;
				buf = (void *)&mem.u32;
				break;
			case 8:
				mem.u64 = (uint64_t)value;
				buf = (void *)&mem.u64;
				break;
			}
		}
        }

	if (!addr_entered || !value_entered)
        	cmd_usage(pc->curcmd, SYNOPSIS);

	if (!memtype)
		memtype = vaddr_type(addr, CURRENT_CONTEXT());

	switch (memtype)
	{
	case UVADDR:
		if (!IS_UVADDR(addr, CURRENT_CONTEXT())) {
			error(INFO, "invalid user virtual address: %lx\n", 
				addr);
                	cmd_usage(pc->curcmd, SYNOPSIS);
		}
		break;

	case KVADDR:
		if (!IS_KVADDR(addr)) {
			error(INFO, "invalid kernel virtual address: %lx\n",
				addr);
               		cmd_usage(pc->curcmd, SYNOPSIS);
		}
		break;

	case PHYSADDR:
		break;

	case AMBIGUOUS:	
		error(INFO, "ambiguous address: %lx  (requires -p, -u or -k)\n",
			addr);
                cmd_usage(pc->curcmd, SYNOPSIS);
	}
	
	writemem(addr, memtype, buf, size, "write memory", FAULT_ON_ERROR); 
}

/*
 *  For processors with "traditional" kernel/user address space distinction.
 */
int
generic_is_kvaddr(ulong addr)
{
	return (addr >= (ulong)(machdep->kvbase));
}

/*
 *  NOTE: Perhaps even this generic version should tighten up requirements
 *        by calling uvtop()?
 */
int
generic_is_uvaddr(ulong addr, struct task_context *tc)
{
	return (addr < (ulong)(machdep->kvbase));
}


/*
 *  Raw dump of a task's stack, forcing symbolic output.
 */
void
raw_stack_dump(ulong addr)
{
	display_memory(addr, STACKSIZE()/sizeof(ulong), 
	    	HEXADECIMAL|DISPLAY_DEFAULT|SYMBOLIC, KVADDR);
}

/*
 *  Raw data dump, with the option of symbolic output.
 */
void
raw_data_dump(ulong addr, long count, int symbolic)
{
	long wordcnt;

	switch (sizeof(long))
	{
	case SIZEOF_32BIT:
		wordcnt = count/SIZEOF_32BIT;
		if (count % SIZEOF_32BIT)
			wordcnt++;
		break;

	case SIZEOF_64BIT:
		wordcnt = count/SIZEOF_64BIT;
		if (count % SIZEOF_64BIT)
			wordcnt++;
		break;

	default:
		break;
	}

	display_memory(addr, wordcnt, 
 	    HEXADECIMAL|DISPLAY_DEFAULT|(symbolic ? SYMBOLIC : ASCII_ENDLINE),
		KVADDR);
}

/*
 *  Quietly checks the accessibility of a memory location.
 */
int
accessible(ulong kva)
{
	ulong tmp;

	return(readmem(kva, KVADDR, &tmp, sizeof(ulong), 
	       "accessible check", RETURN_ON_ERROR|QUIET));
}

/*
 *  readmem() is by far *the* workhorse of this whole program.  It reads
 *  memory from /dev/kmem, /dev/mem the dumpfile or /proc/kcore, whichever
 *  is appropriate:
 *
 *         addr  a user, kernel or physical memory address.
 *      memtype  addr type: UVADDR, KVADDR or PHYSADDR. 
 *       buffer  supplied buffer to read the data into.
 *         size  number of bytes to read.
 *         type  string describing the request -- helpful when the read fails.
 * error_handle  what to do if the read fails: FAULT_ON_ERROR kills the command
 *               immediately; RETURN_ON_ERROR returns FALSE; QUIET suppresses
 *               the error message.
 */

#define PRINT_ERROR_MESSAGE ((!(error_handle & QUIET)) || MCLXDEBUG(1))

#define INVALID_UVADDR   "invalid user virtual address: %lx  type: \"%s\"\n"
#define INVALID_KVADDR   "invalid kernel virtual address: %lx  type: \"%s\"\n"

#define SEEK_ERRMSG      "seek error: address: %lx  type: \"%s\"\n"
#define READ_ERRMSG      "read error: address: %lx  type: \"%s\"\n"
#define WRITE_ERRMSG     "write error: address: %lx  type: \"%s\"\n"

int
readmem(ulong addr, int memtype, void *buffer, long size,
	char *type, ulong error_handle)
{
	int fd;
	long cnt;
	ulong paddr;
	char *bufptr;

	if (MCLXDEBUG(4))
		fprintf(fp, "<readmem: %lx, %s, \"%s\", %ld, %s, %lx>\n", 
			addr, memtype_string(memtype), type, size, 
			error_handle_string(error_handle), (ulong)buffer);

	if (size <= 0) {
		if (PRINT_ERROR_MESSAGE)
                       	error(INFO, "invalid size request: %ld  type: \"%s\"\n",
				size, type);
		goto readmem_error;
	}

	bufptr = (char *)buffer;

	fd = REMOTE_MEMSRC() ? pc->sockfd : (ACTIVE() ? pc->mfd : pc->dfd); 

	/*
	 * Screen out any error conditions.
	 */
        switch (memtype)
        {
        case UVADDR:
                if (!CURRENT_CONTEXT()) {
                        if (PRINT_ERROR_MESSAGE)
                                error(INFO, "no current user process\n");
                        goto readmem_error;
                }
                if (!IS_UVADDR(addr, CURRENT_CONTEXT())) {
                        if (PRINT_ERROR_MESSAGE)
                                error(INFO, INVALID_UVADDR, addr, type);
                        goto readmem_error;
                }
                break;

        case KVADDR:
                if (!IS_KVADDR(addr)) {
                        if (PRINT_ERROR_MESSAGE)
                                error(INFO, INVALID_KVADDR, addr, type);
                        goto readmem_error;
                }
                break;

        case PHYSADDR:
                break;
        }

        while (size > 0) {
		switch (memtype)
		{
		case UVADDR:
                	if (!uvtop(CURRENT_CONTEXT(), addr, &paddr, 0)) {
                        	if (PRINT_ERROR_MESSAGE)
                                	error(INFO, INVALID_UVADDR, addr, type);
                        	goto readmem_error;
                	}
			break;

		case KVADDR:
                	if (!kvtop(CURRENT_CONTEXT(), addr, &paddr, 0)) {
                        	if (PRINT_ERROR_MESSAGE)
                                	error(INFO, INVALID_KVADDR, addr, type);
                        	goto readmem_error;
                	}
			break;

		case PHYSADDR:
			paddr = addr;
			break;
		}

		/* 
		 *  Compute bytes till end of page.
		 */
		cnt = PAGESIZE() - PAGEOFFSET(paddr); 

                if (cnt > size)
                        cnt = size;

		switch (READMEM(fd, bufptr, cnt, addr, paddr))
		{
		case SEEK_ERROR:
                        if (PRINT_ERROR_MESSAGE)
                        	error(INFO, SEEK_ERRMSG, addr, type);
                        goto readmem_error;

		case READ_ERROR:
                        if (PRINT_ERROR_MESSAGE)
                        	error(INFO, READ_ERRMSG, addr, type);
                        goto readmem_error;

		default:
			break;
		}

		addr += cnt;
                bufptr += cnt;
                size -= cnt;
        }

        return TRUE;

readmem_error:
	
        switch (error_handle)
        {
        case (FAULT_ON_ERROR):
        case (QUIET|FAULT_ON_ERROR):
                if (pc->flags & IN_FOREACH)
                        RESUME_FOREACH();
                RESTART();

        case (RETURN_ON_ERROR):
	case (QUIET|RETURN_ON_ERROR):
		break;
        }

	return FALSE;
}

/*
 *  Read from /dev/mem.
 */
int
read_dev_mem(int fd, void *bufptr, int cnt, ulong addr, ulong paddr) 
{
	int readcnt;

	if (lseek(fd, paddr, SEEK_SET) == -1) 
		return SEEK_ERROR;

        errno = 0;
        readcnt = read(fd, bufptr, cnt);

        /*
         *  On 32-bit intel architectures w/memory above ~936MB,
         *  that memory can only be accessed via vmalloc'd
         *  addresses.  However, /dev/mem returns 0 bytes,
         *  and non-reserved memory pages can't be mmap'd, so
         *  the only alternative is to read it from /dev/kmem.
         */
        if ((readcnt != cnt) && !readcnt && !errno && IS_VMALLOC_ADDR(addr))
                readcnt = read_dev_kmem(addr, bufptr, cnt);

        if (readcnt != cnt) 
		return READ_ERROR;

	return readcnt;
}

/*
 *  Write to /dev/mem.
 */
int
write_dev_mem(int fd, void *bufptr, int cnt, ulong addr, ulong paddr) 
{
        if (lseek(fd, paddr, SEEK_SET) == -1) 
		return SEEK_ERROR;

        if (write(fd, bufptr, cnt) != cnt) 
		return WRITE_ERROR;

	return cnt;
}

/*
 *  Read from an MCLX formatted dumpfile.
 */
int
read_mclx_dumpfile(int fd, void *bufptr, int cnt, ulong addr, ulong paddr) 
{
        if (vas_lseek(paddr, SEEK_SET)) 
		return SEEK_ERROR;
        
        if (vas_read((void *)bufptr, cnt) != cnt) 
		return READ_ERROR;

	return cnt;
}

/*
 *  Write to an MCLX formatted dumpfile.  This only modifies the buffered 
 *  copy only; if it gets flushed, the modification is lost.
 */
int
write_mclx_dumpfile(int fd, void *bufptr, int cnt, ulong addr, ulong paddr)
{
        if (vas_lseek(paddr, SEEK_SET)) 
        	return SEEK_ERROR;
                                
        if (vas_write((void *)bufptr, cnt) != cnt) 
		return WRITE_ERROR;

	return cnt;
}

/*
 *  Read from an LKCD formatted dumpfile.
 */
int
read_lkcd_dumpfile(int fd, void *bufptr, int cnt, ulong addr, ulong paddr) 
{
	set_lkcd_fp(fp);

        if (!lkcd_lseek((ulong)paddr)) 
		return SEEK_ERROR;
        
        if (lkcd_read((void *)bufptr, cnt) != cnt) 
		return READ_ERROR;

	return cnt;
}

/*
 *  Write to an LKCD formatted dumpfile.  (dummy routine -- not allowed)
 */
int
write_lkcd_dumpfile(int fd, void *bufptr, int cnt, ulong addr, ulong paddr) 
{
	return (error(FATAL, "cannot write to an LKCD compressed dump!\n"));
}


/*
 *  Read from network daemon.
 */
int
read_daemon(int fd, void *bufptr, int cnt, ulong vaddr, ulong paddr) 
{
	if (remote_memory_read(pc->rmfd, bufptr, cnt, paddr) == cnt)
		return cnt;

	if (!IS_VMALLOC_ADDR(vaddr) || DUMPFILE())
		return READ_ERROR;

        /*
         *  On 32-bit architectures w/memory above ~936MB,
         *  that memory can only be accessed via vmalloc'd
         *  addresses.  However, /dev/mem returns 0 bytes,
         *  and non-reserved memory pages can't be mmap'd, so
         *  the only alternative is to read it from /dev/kmem.
         */

	if (BITS32() && remote_memory_read(pc->rkfd, bufptr, cnt, vaddr) == cnt)
                return cnt;

	return READ_ERROR;
}

/*
 *  Write to network daemon.
 */
int
write_daemon(int fd, void *bufptr, int cnt, ulong addr, ulong paddr) 
{
	return (error(FATAL, "writing to daemon not supported yet [TBD]\n"));
}

/*
 *  Turn the memtype bitmask into a string.
 */
static
char *memtype_string(int memtype)
{
	static char membuf[20];

	switch (memtype)
	{
	case UVADDR:
		sprintf(membuf, "UVADDR");
		break;
	case KVADDR:
		sprintf(membuf, "KVADDR");
		break;
	case PHYSADDR:
		sprintf(membuf, "UVADDR");
		break;
	default:
		sprintf(membuf, "0x%x (?)", memtype);
		break;
	}

	return membuf;
}

/*
 *  Turn the error_handle bitmask into a string,
 *  Note: FAULT_ON_ERROR == 0
 */
static
char *error_handle_string(ulong error_handle)
{
        static char ebuf[20];
	int others;

	sprintf(ebuf, "(");
	others = 0;

	if (error_handle & RETURN_ON_ERROR)
		sprintf(&ebuf[strlen(ebuf)], "%sROE", others++ ? "|" : "");
	if (error_handle & FAULT_ON_ERROR)
		sprintf(&ebuf[strlen(ebuf)], "%sFOE", others++ ? "|" : "");
	if (error_handle & QUIET)
		sprintf(&ebuf[strlen(ebuf)], "%sQ", others++ ? "|" : "");
	if (error_handle & HEX_BIAS)
		sprintf(&ebuf[strlen(ebuf)], "%sHB", others++ ? "|" : "");

	strcat(ebuf, ")");

        return ebuf;
}


/*
 *  Sister routine to readmem().
 */

int
writemem(ulong addr, int memtype, void *buffer, long size,
	char *type, ulong error_handle)
{
	int fd;
	long cnt;
	ulong paddr;
	char *bufptr;

        if (MCLXDEBUG(1))
		fprintf(fp, "writemem: %lx, %s, \"%s\", %ld, %s %lx\n", 
			addr, memtype_string(memtype), type, size, 
			error_handle_string(error_handle), (ulong)buffer);

	if (size < 0) {
		if (PRINT_ERROR_MESSAGE)
                       	error(INFO, "invalid size request: %ld\n", size);
		goto writemem_error;
	}

	bufptr = (char *)buffer;

	fd = ACTIVE() ? pc->mfd : pc->dfd;

	/*
	 * Screen out any error conditions.
	 */
        switch (memtype)
        {
        case UVADDR:
                if (!CURRENT_CONTEXT()) {
                        if (PRINT_ERROR_MESSAGE)
                                error(INFO, "no current user process\n");
                        goto writemem_error;
                }
                if (!IS_UVADDR(addr, CURRENT_CONTEXT())) {
                        if (PRINT_ERROR_MESSAGE)
                                error(INFO, INVALID_UVADDR, addr, type);
                        goto writemem_error;
                }
                break;

        case KVADDR:
                if (!IS_KVADDR(addr)) {
                        if (PRINT_ERROR_MESSAGE)
                                error(INFO, INVALID_KVADDR, addr, type);
                        goto writemem_error;
                }
                break;

        case PHYSADDR:
                break;
        }

        while (size > 0) {
                switch (memtype)
                {
                case UVADDR:
                        if (!uvtop(CURRENT_CONTEXT(), addr, &paddr, 0)) {
                                if (PRINT_ERROR_MESSAGE)
                                        error(INFO, INVALID_UVADDR, addr, type);
                                goto writemem_error;
                        }
                        break;

                case KVADDR:
                        if (!kvtop(CURRENT_CONTEXT(), addr, &paddr, 0)) {
                                if (PRINT_ERROR_MESSAGE)
                                        error(INFO, INVALID_KVADDR, addr, type);
                                goto writemem_error;
                        }
                        break;

                case PHYSADDR:
                        paddr = addr;
                        break;
                }

		/* 
		 *  Compute bytes till end of page.
		 */
		cnt = PAGESIZE() - PAGEOFFSET(paddr); 

                if (cnt > size)
                        cnt = size;

		switch (pc->writemem(fd, bufptr, cnt, addr, paddr))
		{
		case SEEK_ERROR:
                        if (PRINT_ERROR_MESSAGE)
                                error(INFO, SEEK_ERRMSG, addr, type);
                        goto writemem_error;
			
		case WRITE_ERROR:
                        if (PRINT_ERROR_MESSAGE)
                                error(INFO, WRITE_ERRMSG, addr, type);
                        goto writemem_error;

		default:
			break;
		}

                addr += cnt;
                bufptr += cnt;
                size -= cnt;
        }

        return TRUE;

writemem_error:
	
        switch (error_handle)
        {
        case (FAULT_ON_ERROR):
        case (QUIET|FAULT_ON_ERROR):
                RESTART();

        case (RETURN_ON_ERROR):
	case (QUIET|RETURN_ON_ERROR):
		break;
        }

	return FALSE;
}

/*
 *  When /dev/mem won't allow access, try /dev/kmem.  
 */
static ssize_t
read_dev_kmem(ulong vaddr, char *bufptr, long cnt)
{
	int fd;
	ssize_t readcnt;

	if ((fd = open("/dev/kmem", O_RDONLY)) < 0)
		return 0; 

	if (lseek(fd, vaddr, SEEK_SET) == -1) {
		close(fd);
		return 0;
	}

	readcnt = read(fd, bufptr, cnt);
	if (readcnt != cnt)
		readcnt = 0;

	close(fd);

	return readcnt;
}

#ifdef USE_MMAP
/*
 *  With each invocation of readmem(), mmap() the page containing the
 *  requested address.  Keep the mapping in place so that if the next read
 *  is from the same page, it's already there.  Also, as of this writing,
 *  /dev/mem won't allow read() system calls to access memory above high_memory,
 *  even if it's there -- but will allow mmap calls on the high addresses.
 *
 *  ALERT: this is no good -- /dev/mem won't allow non-reserved pages to 
 *         be mmap'd...
 *
 */
static char *
mmap_page(ulong paddr, int prot)
{
	ulong offset;
	ulong physpage;

	offset = PAGEOFFSET(paddr);
	physpage = PAGEBASE(paddr);

	if (pc->mmap_addr && (pc->mmap_phys == physpage)) {
		pc->maphits++;
		return(pc->mmap_addr + offset);
	}

	if (pc->mmap_addr) {
		munmap(pc->mmap_addr, PAGESIZE());
		pc->mmap_addr = (char *)0xdeadbeef;
	}

        if ((pc->mmap_addr = mmap(0, PAGESIZE(), prot, MAP_SHARED, 
	    pc->mfd, physpage)) == MAP_FAILED)
        	error(FATAL, "mmap address %lx: %s\n", strerror(errno));

	pc->mmap_phys = physpage;
	pc->remaps++;

	return(pc->mmap_addr + offset);
}
#endif

/*
 *  Translates a kernel virtual address to its physical address.  cmd_vtop()
 *  sets the verbose flag so that the pte translation gets displayed; all 
 *  other callers quietly accept the translation.
 */
int
kvtop(struct task_context *tc, ulong kvaddr, ulong *paddr, int verbose)
{
	ulong unused;

	return (machdep->kvtop(tc ? tc : CURRENT_CONTEXT(), kvaddr, 
		paddr ? paddr : &unused, verbose));
}


/*
 *  Translates a user virtual address to its physical address.  cmd_vtop()
 *  sets the verbose flag so that the pte translation gets displayed; all 
 *  other callers quietly accept the translation.
 *
 *  This routine can also take mapped kernel virtual addresses if the -u flag
 *  was passed to cmd_vtop().  If so, it makes the translation using the
 *  kernel-memory PGD entry instead of swapper_pg_dir.
 */
int
uvtop(struct task_context *tc, ulong vaddr, ulong *paddr, int verbose)
{
	return(machdep->uvtop(tc, vaddr, paddr, verbose));
}

/*
 *  The vtop command does a verbose translation of a user or kernel virtual
 *  address into it physical address.  The pte translation is shown by
 *  passing the VERBOSE flag to kvtop() or uvtop().  If it's a user virtual
 *  address, the vm_area_struct data containing the page is displayed.
 *  Lastly, the mem_map[] page data containing the address is displayed.
 */

void
cmd_vtop(void)
{
	int c;
	ulong vaddr, context;
	int others;
	ulong vtop_flags, loop_vtop_flags;
	struct task_context *tc;

	vtop_flags = 0;
	tc = NULL;

        while ((c = getopt(argcnt, args, "ukc:")) != EOF) {
                switch(c)
		{
		case 'c':
	                switch (str_to_context(optarg, &context, &tc))
	                {
	                case STR_PID:
	                case STR_TASK:
				vtop_flags |= USE_USER_PGD;
	                        break;
	
	                case STR_INVALID:
	                        error(FATAL, "invalid task or pid value: %s\n",
	                                optarg);
	                        break;
	                }
			break;

		case 'u':
			vtop_flags |= UVADDR;
			break;

		case 'k':
			vtop_flags |= KVADDR;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs || !args[optind])
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (!tc && !(tc = CURRENT_CONTEXT())) 
      		error(FATAL, "no current user process\n");

	if ((vtop_flags & (UVADDR|KVADDR)) == (UVADDR|KVADDR))
		error(FATAL, "-u and -k options are mutually exclusive\n");

	others = 0;
        while (args[optind]) {
		vaddr = htol(args[optind], FAULT_ON_ERROR, NULL);

		if (!(vtop_flags & (UVADDR|KVADDR))) {
			switch (vaddr_type(vaddr, tc))
			{
                	case UVADDR:
				loop_vtop_flags = UVADDR;
                        	break;
                	case KVADDR:
				loop_vtop_flags = KVADDR;
                        	break;
                	case AMBIGUOUS:
                        	error(FATAL,
                                "ambiguous address: %lx  (requires -u or -k)\n",
                                	vaddr);
                        	break;
			}
		} else
			loop_vtop_flags = 0;
	
		if (others++)
			fprintf(fp, "\n");

		do_vtop(vaddr, tc, vtop_flags | loop_vtop_flags);

		optind++;
	}
}

/*
 *  Do the work for cmd_vtop(), or less likely, foreach().
 */
void
do_vtop(ulong vaddr, struct task_context *tc, ulong vtop_flags)
{
	ulong paddr, vma;
	int page_exists;
        struct meminfo meminfo;
        char buf1[BUFSIZE];
        char buf2[BUFSIZE];
	int memtype;

	switch (vtop_flags & (UVADDR|KVADDR))
	{
	case UVADDR:
		memtype = UVADDR;
		break;

	case KVADDR:
		memtype = KVADDR;
		break;

	case (UVADDR|KVADDR):
		error(FATAL, "-u and -k options are mutually exclusive\n");
		break;

	default:
                switch (vaddr_type(vaddr, tc))
                {
                case UVADDR:
                        memtype = UVADDR;
                        break;
                case KVADDR:
                        memtype = KVADDR;
                        break;
                case AMBIGUOUS:
			error(FATAL,
                            "ambiguous address: %lx  (requires -u or -k)\n",
                            	vaddr);
                        break;
                }
		break;
        }

	switch (memtype) {
	case UVADDR: 
                fprintf(fp, "%s  %s\n",
                        mkstring(buf1, UVADDR_PRLEN, LJUST, "VIRTUAL"),
                        mkstring(buf2, VADDR_PRLEN, LJUST, "PHYSICAL"));

		if (!IN_TASK_VMA(tc->task, vaddr)) {
			fprintf(fp, "%s  (not accessible)\n\n", 
				mkstring(buf1, UVADDR_PRLEN, LJUST|LONG_HEX,
				    MKSTR(vaddr)));
			return;
		}
		if (!uvtop(tc, vaddr, &paddr, 0)) {
			fprintf(fp, "%s  (not mapped)\n\n", 
				mkstring(buf1, UVADDR_PRLEN, LJUST|LONG_HEX,
				    MKSTR(vaddr)));
			page_exists = FALSE;
		} else {
			fprintf(fp, "%s  %s\n\n",
			    mkstring(buf1, UVADDR_PRLEN, LJUST|LONG_HEX, 
				MKSTR(vaddr)),
			    mkstring(buf2, VADDR_PRLEN, LJUST|LONG_HEX, 
				MKSTR(paddr)));
			page_exists = TRUE;
		}
		uvtop(tc, vaddr, &paddr, VERBOSE);
		fprintf(fp, "\n");
		vma = vm_area_dump(tc->task, UVADDR, vaddr, 0);
		if (!page_exists) { 
			if (swap_location(paddr, buf1))
                       		fprintf(fp, "\nSWAP: %s\n", buf1);
			else if (vma_file_offset(vma, vaddr, buf1))
				fprintf(fp, "\nFILE: %s\n", buf1);
		}
		break; 

	case KVADDR:
                fprintf(fp, "%s  %s\n",
                        mkstring(buf1, VADDR_PRLEN, LJUST, "VIRTUAL"),
                        mkstring(buf2, VADDR_PRLEN, LJUST, "PHYSICAL"));

		if (!IS_KVADDR(vaddr)) {
			fprintf(fp, "%-8lx  (not a kernel virtual address)\n\n",
				vaddr);
			return;
		}
		if (vtop_flags & USE_USER_PGD) {
                	if (!uvtop(tc, vaddr, &paddr, 0)) {
                        	fprintf(fp, "%-8lx  (not mapped)\n\n", vaddr);
                        	page_exists = FALSE;
                	} else {
                         	fprintf(fp, "%-8lx  %-8lx\n\n", vaddr, paddr);
                         	page_exists = TRUE;
                	}
                	uvtop(tc, vaddr, &paddr, VERBOSE);
		} else {
			if (!kvtop(tc, vaddr, &paddr, 0)) {
				fprintf(fp, "%-8lx  (not mapped)\n\n", vaddr);
				page_exists = FALSE;
			} else {
				fprintf(fp, "%-8lx  %-8lx\n\n", vaddr, paddr);
				page_exists = TRUE;
			}
			kvtop(tc, vaddr, &paddr, VERBOSE);
		}
		break;
	}

	fprintf(fp, "\n");

	if (page_exists && (paddr < VTOP(vt->high_memory))) { 
		BZERO(&meminfo, sizeof(struct meminfo));
		meminfo.flags = ADDRESS_SPECIFIED;
		meminfo.spec_addr = paddr;
		meminfo.memtype = PHYSADDR;
		dump_mem_map(&meminfo);
	}
}

/*
 *  Runs PTOV() on the physical address argument.
 */
void
cmd_ptov(void)
{
	int c;
	ulong vaddr, paddr;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	int others;

        while ((c = getopt(argcnt, args, "")) != EOF) {
                switch(c)
		{
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs || !args[optind])
		cmd_usage(pc->curcmd, SYNOPSIS);

	others = 0;
        while (args[optind]) {
		paddr = htol(args[optind], FAULT_ON_ERROR, NULL);
		vaddr = PTOV(paddr);

		fprintf(fp, "%s%s  %s\n", others++ ? "\n" : "", 
		    mkstring(buf1, VADDR_PRLEN, LJUST, "VIRTUAL"),
		    mkstring(buf2, VADDR_PRLEN, LJUST, "PHYSICAL"));
		fprintf(fp, "%s  %s\n",
		    mkstring(buf1, VADDR_PRLEN, LJUST|LONG_HEX, MKSTR(vaddr)),
                    mkstring(buf2, VADDR_PRLEN, LJUST|LONG_HEX, MKSTR(paddr)));

		optind++;
	}
}


/*
 *  Runs PTOB() on the page frame number to get the page address.
 */
void
cmd_ptob(void)
{
        ulong value;

        optind = 1;
        if (!args[optind])
                cmd_usage(pc->curcmd, SYNOPSIS);

        while (args[optind]) {
		value = stol(args[optind], FAULT_ON_ERROR, NULL);
		fprintf(fp, "%lx: %lx\n", value, PTOB(value));
                optind++;
        }
}


/*
 *  Runs BTOP() on the address to get the page frame number.
 */
void
cmd_btop(void)
{
        ulong value;

        optind = 1;
        if (!args[optind])
                cmd_usage(pc->curcmd, SYNOPSIS);

        while (args[optind]) {
		value = htol(args[optind], FAULT_ON_ERROR, NULL); 
		fprintf(fp, "%lx: %lx\n", value, BTOP(value));
                optind++;
        }
}

/*
 *  This command displays basic virtual memory information of a context,
 *  consisting of a pointer to its mm_struct, its RSS and total virtual
 *  memory size; and a list of pointers to each vm_area_struct, its starting
 *  and ending address, and vm_flags value.  The argument can be a task
 *  address or a PID number; if no args, the current context is used.
 */
void
cmd_vm(void)
{
	int c;
	ulong flag;
	ulong value;
	struct task_context *tc;
	struct reference reference, *ref;
	int subsequent;

	flag = 0;
	ref = NULL;
	BZERO(&reference, sizeof(struct reference));

        while ((c = getopt(argcnt, args, "f:pmvR:")) != EOF) {
                switch(c)
		{
		case 'f':
			if (flag) 
				argerrs++;
			else {
				value = htol(optarg, FAULT_ON_ERROR, NULL);
				do_vm_flags(value);
				return;
			}
			break;

		case 'p': 
			if (flag)
				argerrs++;
			else
				flag |= PHYSADDR;
			break;
		case 'm':
			if (flag)
				argerrs++;
			else
				flag |= PRINT_MM_STRUCT;
			break;
		case 'v':
			if (flag)
				argerrs++;
			else
				flag |= PRINT_VMA_STRUCTS;
			break;

		case 'R':
			if (ref) {
				error(INFO, "only one -R option allowed\n");
				argerrs++;
			} else if (flag && !(flag & PHYSADDR))
				argerrs++;
			else {
				ref = &reference;
				ref->str = optarg;
				flag |= PHYSADDR;
			}
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (!args[optind]) {
		if (!ref)
			print_task_header(fp, CURRENT_CONTEXT(), 0);
		vm_area_dump(CURRENT_TASK(), flag, 0, ref);
		return;
	}

	subsequent = 0;

	while (args[optind]) {
		switch (str_to_context(args[optind], &value, &tc))
		{
		case STR_PID:
			for (tc = pid_to_context(value); tc; tc = tc->tc_next) {
                                if (!ref)
                                        print_task_header(fp, tc, subsequent++);
                                vm_area_dump(tc->task, flag, 0, ref);
                        }
			break;

		case STR_TASK:
			if (!ref)
                                print_task_header(fp, tc, subsequent++);
                        vm_area_dump(tc->task, flag, 0, ref);
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
 *  Translate a vm_flags value.
 */

#define VM_READ		0x00000001	/* currently active flags */
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008
#define VM_MAYREAD	0x00000010	/* limits for mprotect() etc */
#define VM_MAYWRITE	0x00000020
#define VM_MAYEXEC	0x00000040
#define VM_MAYSHARE	0x00000080
#define VM_GROWSDOWN	0x00000100	/* general info on the segment */
#define VM_GROWSUP	0x00000200
#define VM_SHM		0x00000400	/* shared memory area, don't swap out */
#define VM_DENYWRITE	0x00000800	/* ETXTBSY on write attempts.. */
#define VM_EXECUTABLE	0x00001000
#define VM_LOCKED	0x00002000
#define VM_IO           0x00004000	/* Memory mapped I/O or similar */
#define VM_SEQ_READ	0x00008000	/* App will access data sequentially */
#define VM_RAND_READ	0x00010000	/* App will not benefit from clustered reads */
#define VM_DONTCOPY	0x00020000      /* Do not copy this vma on fork */
#define VM_DONTEXPAND   0x00040000      /* Cannot expand with mremap() */
#define VM_RESERVED     0x00080000      /* Don't unmap it from swap_out */
#define VM_STACK_FLAGS	0x00000177

static void
do_vm_flags(ulong flags)
{
	int others;

	others = 0;

	fprintf(fp, "%lx: (", flags);

	if (flags & VM_READ) {
		fprintf(fp, "READ");
		others++;
	}
	if (flags & VM_WRITE)
		fprintf(fp, "%sWRITE", others++ ? "|" : "");
	if (flags & VM_EXEC)
		fprintf(fp, "%sEXEC", others++ ? "|" : "");
	if (flags & VM_SHARED)
		fprintf(fp, "%sSHARED", others++ ? "|" : "");
	if (flags & VM_MAYREAD)
		fprintf(fp, "%sMAYREAD", others++ ? "|" : "");
	if (flags & VM_MAYWRITE)
		fprintf(fp, "%sMAYWRITE", others++ ? "|" : "");
	if (flags & VM_MAYEXEC)
		fprintf(fp, "%sMAYEXEC", others++ ? "|" : "");
	if (flags & VM_MAYSHARE)
		fprintf(fp, "%sMAYSHARE", others++ ? "|" : "");
	if (flags & VM_GROWSDOWN)
		fprintf(fp, "%sGROWSDOWN", others++ ? "|" : "");
	if (flags & VM_GROWSUP)
		fprintf(fp, "%sGROWSUP", others++ ? "|" : "");
	if (flags & VM_SHM)
		fprintf(fp, "%sSHM", others++ ? "|" : "");
	if (flags & VM_DENYWRITE)
		fprintf(fp, "%sDENYWRITE", others++ ? "|" : "");
	if (flags & VM_EXECUTABLE)
		fprintf(fp, "%sEXECUTABLE", others++ ? "|" : "");
	if (flags & VM_LOCKED)
		fprintf(fp, "%sLOCKED", others++ ? "|" : "");
	if (flags & VM_IO)
		fprintf(fp, "%sIO", others++ ? "|" : "");
	if (flags & VM_SEQ_READ)
		fprintf(fp, "%sSEQ_READ", others++ ? "|" : "");
	if (flags & VM_RAND_READ)
		fprintf(fp, "%sRAND_READ", others++ ? "|" : "");
	if (flags & VM_DONTCOPY)
		fprintf(fp, "%sDONTCOPY", others++ ? "|" : "");
        if (flags & VM_DONTEXPAND)
                fprintf(fp, "%sDONTEXPAND", others++ ? "|" : "");
        if (flags & VM_RESERVED)
                fprintf(fp, "%sRESERVED", others++ ? "|" : "");
	fprintf(fp, ")\n");

}


/*
 *  vm_area_dump() primarily does the work for cmd_vm(), but is also called
 *  from IN_TASK_VMA(), do_vtop(), and foreach().  How it behaves depends
 *  upon the flag and ref arguments:
 *
 *   UVADDR               do_vtop() when dumping the VMA for a uvaddr
 *   UVADDR|VERIFY_ADDR   IN_TASK_VMA() macro checks if a uvaddr is in a VMA
 *   PHYSADDR             cmd_vm() or foreach(vm) for -p and -R options
 *   PRINT_MM_STRUCT      cmd_vm() or foreach(vm) for -m option
 *   PRINT_VMA_STRUCTS    cmd_vm() or foreach(vm) for -v option
 *   PRINT_INODES         open_files_dump() backdoors foreach(vm)
 *
 *   ref                  cmd_vm() or foreach(vm) for -R option that searches
 *                        for references -- and only then does a display      
 */

#define PRINT_VM_DATA()                                                  \
                {                                                        \
                fprintf(fp, "%s  %s  ",                                  \
                    mkstring(buf4, VADDR_PRLEN, CENTER|LJUST, "MM"),     \
                    mkstring(buf5, VADDR_PRLEN, CENTER|LJUST, "PGD"));   \
                fprintf(fp, "%s  %s\n",                                  \
                    mkstring(buf4, 6, CENTER|LJUST, "RSS"),              \
                    mkstring(buf5, 8, CENTER|LJUST, "TOTAL_VM"));        \
                                                                         \
                fprintf(fp, "%s  %s  ",                                  \
                    mkstring(buf4, VADDR_PRLEN, CENTER|LJUST|LONG_HEX,   \
                        MKSTR(tm->mm_struct_addr)),                      \
                    mkstring(buf5, VADDR_PRLEN, CENTER|LJUST|LONG_HEX,   \
                        MKSTR(tm->pgd_addr)));                           \
                                                                         \
                sprintf(buf4, "%ldk", (tm->rss * PAGESIZE())/1024);      \
                sprintf(buf5, "%ldk", (tm->total_vm * PAGESIZE())/1024); \
                fprintf(fp, "%s  %s\n",                                  \
                    mkstring(buf4, 6, CENTER|LJUST, NULL),               \
                    mkstring(buf5, 8, CENTER|LJUST, NULL));              \
	        }

#define PRINT_VMA_DATA()                                                       \
	fprintf(fp, "%lx%s%s%s%s%s%4x%s%s\n",                                  \
	        vma, space(MINSPACE),                                          \
                mkstring(buf2, UVADDR_PRLEN, RJUST|LONG_HEX, MKSTR(vm_start)), \
                space(MINSPACE),                                               \
                mkstring(buf3, UVADDR_PRLEN, RJUST|LONG_HEX, MKSTR(vm_end)),   \
		space(MINSPACE), vm_flags, space(MINSPACE), buf1); 

#define FILENAME_COMPONENT(P,C) \
        ((STREQ((P), "/") && STREQ((C), "/")) || \
        (!STREQ((C), "/") && strstr((P),(C))))

#define VM_REF_SEARCH       (0x1)
#define VM_REF_DISPLAY      (0x2)
#define VM_REF_NUMBER       (0x4)
#define VM_REF_VMA          (0x8)
#define VM_REF_PAGE        (0x10)
#define VM_REF_HEADER      (0x20)
#define DO_REF_SEARCH(X)   ((X) && ((X)->cmdflags & VM_REF_SEARCH))
#define DO_REF_DISPLAY(X)  ((X) && ((X)->cmdflags & VM_REF_DISPLAY))
#define VM_REF_CHECK_HEXVAL(X,V) \
   (DO_REF_SEARCH(X) && ((X)->cmdflags & VM_REF_NUMBER) && ((X)->hexval == (V)))
#define VM_REF_CHECK_DECVAL(X,V) \
   (DO_REF_SEARCH(X) && ((X)->cmdflags & VM_REF_NUMBER) && ((X)->decval == (V)))
#define VM_REF_CHECK_STRING(X,S) \
   (DO_REF_SEARCH(X) && (S) && FILENAME_COMPONENT((S),(X)->str))
#define VM_REF_FOUND(X)    ((X) && ((X)->cmdflags & VM_REF_HEADER))

ulong
vm_area_dump(ulong task, ulong flag, ulong vaddr, struct reference *ref)
{
        struct task_context *tc;
	ulong vma;
	ulong vm_start;
	ulong vm_end;
	void *vm_next, *vm_mm;
	char *dentry_buf, *vma_buf, *file_buf;
	ushort vm_flags;
	ulong vm_file, inode;
	ulong dentry, vfsmnt;
	int found;
	struct task_mem_usage task_mem_usage, *tm;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char buf5[BUFSIZE];
	char vma_header[BUFSIZE];

        tc = task_to_context(task);
	tm = &task_mem_usage;
	get_task_mem_usage(task, tm);

	if (ref) {
		ref->cmdflags = VM_REF_SEARCH;
		if (IS_A_NUMBER(ref->str)) {
			ref->hexval = htol(ref->str, FAULT_ON_ERROR, NULL);
			if (decimal(ref->str, 0))
				ref->decval = dtol(ref->str, 
					FAULT_ON_ERROR, NULL);
			ref->cmdflags |= VM_REF_NUMBER;
		} 
	}

        if (VM_REF_CHECK_HEXVAL(ref, tm->mm_struct_addr) ||
            VM_REF_CHECK_HEXVAL(ref, tm->pgd_addr)) {
        	print_task_header(fp, tc, 0);
		PRINT_VM_DATA();
		fprintf(fp, "\n");
                return (ulong)NULL;
        }

        if (!(flag & (UVADDR|PRINT_MM_STRUCT|PRINT_VMA_STRUCTS)) &&
	    !DO_REF_SEARCH(ref)) 
		PRINT_VM_DATA();

        if (!tm->mm_struct_addr)
                return (ulong)NULL;

	if (flag & PRINT_MM_STRUCT) {
		dump_struct("mm_struct", tm->mm_struct_addr, 0);
                return (ulong)NULL;
	}

	readmem(tm->mm_struct_addr + OFFSET(mm_struct_mmap), KVADDR, 
		&vma, sizeof(void *), "mm_struct mmap", FAULT_ON_ERROR);

       	sprintf(vma_header, "%s%s%s%s%s%sFLAGS%sFILE\n",
                mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "VMA"),
                space(MINSPACE),              
                mkstring(buf2, UVADDR_PRLEN, CENTER|RJUST, "START"),
                space(MINSPACE),              
                mkstring(buf3, UVADDR_PRLEN, CENTER|RJUST, "END"),
                space(MINSPACE-1),
		space(MINSPACE));

	if (!(flag & (PHYSADDR|VERIFY_ADDR|PRINT_VMA_STRUCTS)) && 
	    !DO_REF_SEARCH(ref)) 
		fprintf(fp, vma_header);

	for (found = FALSE; vma; vma = (ulong)vm_next) {

		if ((flag & PHYSADDR) && !DO_REF_SEARCH(ref))
			fprintf(fp, "%s", vma_header);

		inode = 0;
		BZERO(buf1, BUFSIZE);
		vma_buf = fill_vma_cache(vma);

		vm_mm = VOID_PTR(vma_buf + OFFSET(vm_area_struct_vm_mm));
		vm_end = ULONG(vma_buf + OFFSET(vm_area_struct_vm_end));
		vm_next = VOID_PTR(vma_buf + OFFSET(vm_area_struct_vm_next));
		vm_start = ULONG(vma_buf + OFFSET(vm_area_struct_vm_start));
		vm_flags = USHORT(vma_buf+ OFFSET(vm_area_struct_vm_flags));
		vm_file = ULONG(vma_buf + OFFSET(vm_area_struct_vm_file));

		if (flag & PRINT_VMA_STRUCTS) {
			dump_struct("vm_area_struct", vma, 0);
			continue;
		}

		if (vm_file && !(flag & VERIFY_ADDR)) {
			file_buf = fill_file_cache(vm_file);
			dentry = ULONG(file_buf + OFFSET(file_f_dentry));
			if (dentry) {
				dentry_buf = fill_dentry_cache(dentry);
				if (VALID_OFFSET(file_f_vfsmnt)) {
					vfsmnt = ULONG(file_buf +
                                		OFFSET(file_f_vfsmnt));
					get_pathname(dentry, buf1, BUFSIZE,
						1, vfsmnt);
				} else {
					get_pathname(dentry, buf1, BUFSIZE, 
						1, 0);
				}
			}
			if ((flag & PRINT_INODES) && dentry) {
				inode = ULONG(dentry_buf + 
					OFFSET(dentry_d_inode));
			}
		}

		if (!(flag & UVADDR) || ((flag & UVADDR) && 
		    ((vaddr >= vm_start) && (vaddr < vm_end)))) {
			found = TRUE;

			if (flag & VERIFY_ADDR)
				return vma;

			if (DO_REF_SEARCH(ref)) {
				if (VM_REF_CHECK_HEXVAL(ref, vma) ||
				    VM_REF_CHECK_HEXVAL(ref, (ulong)vm_flags) ||
				    VM_REF_CHECK_STRING(ref, buf1)) {
					if (!(ref->cmdflags & VM_REF_HEADER)) {
						print_task_header(fp, tc, 0);
                				PRINT_VM_DATA();
						ref->cmdflags |= VM_REF_HEADER;
					}
					if (!(ref->cmdflags & VM_REF_VMA) ||
					    (ref->cmdflags & VM_REF_PAGE)) { 
						fprintf(fp, "%s", vma_header);
						ref->cmdflags |= VM_REF_VMA;
						ref->cmdflags &= ~VM_REF_PAGE;
						ref->ref1 = vma;
					}
					PRINT_VMA_DATA();
				}

				if (vm_area_page_dump(vma, task, 
				    vm_start, vm_end, vm_mm, ref)) {
					if (!(ref->cmdflags & VM_REF_HEADER)) {
					        print_task_header(fp, tc, 0);
                			        PRINT_VM_DATA();
						ref->cmdflags |= VM_REF_HEADER;
					}
                                        if (!(ref->cmdflags & VM_REF_VMA) ||
                                            (ref->ref1 != vma)) {
                                                fprintf(fp, "%s", vma_header);
						PRINT_VMA_DATA();
                                                ref->cmdflags |= VM_REF_VMA;
                                                ref->ref1 = vma;
					}

					ref->cmdflags |= VM_REF_DISPLAY;
					vm_area_page_dump(vma, task,
						vm_start, vm_end, vm_mm, ref); 
					ref->cmdflags &= ~VM_REF_DISPLAY;
				}

				continue;
			}

			if (inode) {
                                fprintf(fp, "%lx%s%s%s%s%s%4x%s%lx %s\n",
                                    vma, space(MINSPACE),               
                                    mkstring(buf2, UVADDR_PRLEN, RJUST|LONG_HEX,
                                        MKSTR(vm_start)), space(MINSPACE),      
                                    mkstring(buf3, UVADDR_PRLEN, RJUST|LONG_HEX,
                                        MKSTR(vm_end)), space(MINSPACE), 
				    vm_flags, space(MINSPACE), inode, buf1);
			} else {
				PRINT_VMA_DATA();
				     
				if (flag & PHYSADDR) 
					vm_area_page_dump(vma, task,
						vm_start, vm_end, vm_mm, ref);
			}

			if (flag & UVADDR)
				return vma;
		} 
	}

	if (flag & VERIFY_ADDR)
		return (ulong)NULL;

	if ((flag & UVADDR) && !found) 
		fprintf(fp, "(not found)\n");

	if (VM_REF_FOUND(ref))
		fprintf(fp, "\n");

	return (ulong)NULL;
}

static int
vm_area_page_dump(ulong vma, 
		  ulong task, 
		  ulong start, 
		  ulong end, 
		  void *mm,
		  struct reference *ref)
{
	ulong paddr;
	ulong offs;
	char *p1, *p2;
	int display;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];

	if ((ulong)mm == symbol_value("init_mm")) 
		return FALSE;

	if (!ref || DO_REF_DISPLAY(ref))
		fprintf(fp, "%s  %s\n",
			mkstring(buf1, UVADDR_PRLEN, LJUST, "VIRTUAL"),
			mkstring(buf2, MAX(PADDR_PRLEN, strlen("PHYSICAL")), 
			LJUST, "PHYSICAL"));

	if (DO_REF_DISPLAY(ref)) {
		start = ref->ref2;
	}

	while (start < end) {

		display = DO_REF_SEARCH(ref) ? FALSE : TRUE;
	
		if (VM_REF_CHECK_HEXVAL(ref, start)) {
			if (DO_REF_DISPLAY(ref)) 
				display = TRUE;
			else {
				ref->cmdflags |= VM_REF_PAGE;
				ref->ref2 = start;
				return TRUE;
			}
		}

                if (uvtop(task_to_context(task), start, &paddr, 0)) {
			sprintf(buf3, "%s  %s\n",
				mkstring(buf1, UVADDR_PRLEN, LJUST|LONG_HEX,
				MKSTR(start)),
                	        mkstring(buf2, MAX(PADDR_PRLEN, 
				strlen("PHYSICAL")), RJUST|LONG_HEX, 
				MKSTR(paddr)));

			if (VM_REF_CHECK_HEXVAL(ref, paddr)) {
				if (DO_REF_DISPLAY(ref)) 
					display = TRUE;
				else {
					ref->cmdflags |= VM_REF_PAGE;
					ref->ref2 = start;
					return TRUE;
				}
			}

                } else if (paddr && swap_location(paddr, buf1)) {

			sprintf(buf3, "%s  SWAP: %s\n",
			    mkstring(buf2, UVADDR_PRLEN, LJUST|LONG_HEX,
                                MKSTR(start)), buf1);

			if (DO_REF_SEARCH(ref)) { 
				if (VM_REF_CHECK_DECVAL(ref, 
				    machdep->SWP_OFFSET(paddr))) {
					if (DO_REF_DISPLAY(ref))
						display = TRUE;
					else {
						ref->cmdflags |= VM_REF_PAGE;
						ref->ref2 = start;
						return TRUE;
					}
				}

				strcpy(buf4, buf3);
				p1 = strstr(buf4, "SWAP:") + strlen("SWAP: ");
				p2 = strstr(buf4, "  OFFSET:");
				*p2 = NULLCHAR;
				if (VM_REF_CHECK_STRING(ref, p1)) {
					if (DO_REF_DISPLAY(ref))
						display = TRUE;
					else {
						ref->cmdflags |= VM_REF_PAGE;
						ref->ref2 = start;
						return TRUE;
					}
				}
			}
                } else if (vma_file_offset(vma, start, buf1)) {

                        sprintf(buf3, "%s  FILE: %s\n", 
			    mkstring(buf2, UVADDR_PRLEN, LJUST|LONG_HEX,
                                MKSTR(start)), buf1);

			if (DO_REF_SEARCH(ref)) {
			 	extract_hex(strstr(buf3, "OFFSET:") + 
					strlen("OFFSET: "), &offs, 0, 0);

				if (VM_REF_CHECK_HEXVAL(ref, offs)) {
					if (DO_REF_DISPLAY(ref))
						display = TRUE;
					else {
						ref->cmdflags |= VM_REF_PAGE;
				        	ref->ref2 = start;
						return TRUE;
					}
				}
			}
                } else {
                        sprintf(buf3, "%s  (not mapped)\n", 
			    mkstring(buf1, UVADDR_PRLEN, LJUST|LONG_HEX,
                                MKSTR(start)));
		}

		if (display)
			fprintf(fp, buf3);

		start += PAGESIZE();
	}

	return FALSE;
}



/*
 *  Cache the passed-in vm_area_struct.
 */
char *
fill_vma_cache(ulong vma)
{
	int i;
	char *cache;

	vt->vma_cache_fills++;

        for (i = 0; i < VMA_CACHE; i++) {
                if (vt->cached_vma[i] == vma) {
			vt->cached_vma_hits[i]++;
			cache = vt->vma_cache + (SIZE(vm_area_struct)*i);
			return(cache);
		}
	}

	cache = vt->vma_cache + (SIZE(vm_area_struct)*vt->vma_cache_index);

        readmem(vma, KVADDR, cache, SIZE(vm_area_struct),
        	"fill_vma_cache", FAULT_ON_ERROR);

	vt->cached_vma[vt->vma_cache_index] = vma;

	vt->vma_cache_index = (vt->vma_cache_index+1) % VMA_CACHE;

	return(cache);
}

/*
 *  If active, clear the vm_area_struct references.
 */
void
clear_vma_cache(void)
{
	int i;

	if (DUMPFILE())
		return;

        for (i = 0; i < VMA_CACHE; i++) {
                vt->cached_vma[i] = 0;
        	vt->cached_vma_hits[i] = 0;
	}

        vt->vma_cache_fills = 0;
	vt->vma_cache_index = 0;
}


/*
 *  Fill in the task_mem_usage structure with the RSS, virtual memory size,
 *  percent of physical memory being used, and the mm_struct address.
 */
void
get_task_mem_usage(ulong task, struct task_mem_usage *tm)
{
	int rdflags;
	struct task_context *tc;

	BZERO(tm, sizeof(struct task_mem_usage));

	if (IS_ZOMBIE(task) || IS_EXITING(task)) 
		return;

	rdflags = ACTIVE() ? (QUIET|RETURN_ON_ERROR) : RETURN_ON_ERROR;

	tc = task_to_context(task);

	if (!tc || !tc->mm_struct)     /* probably a kernel thread */
		return;

	tm->mm_struct_addr = tc->mm_struct;

	if (!task_mm(task, TRUE))
		return;

        tm->rss = ULONG(tt->mm_struct + OFFSET(mm_struct_rss));
        tm->total_vm = ULONG(tt->mm_struct + OFFSET(mm_struct_total_vm));
        tm->pgd_addr = ULONG(tt->mm_struct + OFFSET(mm_struct_pgd));

	if (is_kernel_thread(task))
		return;

	tm->pct_physmem = ((double)(tm->rss*100))/((double)(vt->total_pages));
}


/*
 *  cmd_kmem() is designed as a multi-purpose kernel memory investigator with
 *  the flag argument sending it off in a multitude of areas.  To date, the
 *  following options are defined:
 *
 *      -f  displays the contents of the system free_area[] array headers;
 *          also verifies that the page count equals nr_free_pages
 *      -F  same as -f, but also dumps all pages linked to that header.
 *      -p  displays basic information about each page in the system 
 *          mem_map[] array.
 *      -s  displays kmalloc() slab data.
 *      -S  same as -s, but displays all kmalloc() objects.
 *      -v  displays the vmlist entries.
 *      -c  displays the number of pages in the page_hash_table.
 *      -C  displays all entries in the page_hash_table.
 *      -i  displays informational data shown by /proc/meminfo.
 *
 *      -P  forces address to be defined as a physical address
 * address  when used with -f, the address can be either a page pointer
 *          or a physical address; the free_area header containing the page
 *          (if any) is displayed.
 *          When used with -p, the address can be either a page pointer or a
 *          physical address; its basic mem_map page information is displayed.
 *          When used with -c, the page_hash_table entry containing the
 *          page pointer is displayed.
 */

/*  Note: VERBOSE is 0x1, ADDRESS_SPECIFIED is 0x2 */

#define GET_TOTALRAM_PAGES     (ADDRESS_SPECIFIED << 1)
#define GET_SHARED_PAGES       (ADDRESS_SPECIFIED << 2)
#define GET_FREE_PAGES         (ADDRESS_SPECIFIED << 3)
#define GET_FREE_HIGHMEM_PAGES (ADDRESS_SPECIFIED << 4)
#define GET_ZONE_SIZES         (ADDRESS_SPECIFIED << 5)
#define GET_HIGHEST            (ADDRESS_SPECIFIED << 6)
#define GET_BUFFERS_PAGES      (ADDRESS_SPECIFIED << 7)
#define GET_SLAB_PAGES         (ADDRESS_SPECIFIED << 8)
#define GET_PHYS_TO_VMALLOC    (ADDRESS_SPECIFIED << 9)
#define GET_ACTIVE_LIST        (ADDRESS_SPECIFIED << 10)
#define GET_INACTIVE_LIST      (ADDRESS_SPECIFIED << 11)
#define GET_INACTIVE_CLEAN     (ADDRESS_SPECIFIED << 12)  /* obsolete */
#define GET_INACTIVE_DIRTY     (ADDRESS_SPECIFIED << 13)  /* obsolete */
#define SLAB_GET_COUNTS        (ADDRESS_SPECIFIED << 14)
#define SLAB_WALKTHROUGH       (ADDRESS_SPECIFIED << 15)

#define GET_ALL \
	(GET_SHARED_PAGES|GET_TOTALRAM_PAGES|GET_BUFFERS_PAGES|GET_SLAB_PAGES)

void
cmd_kmem(void)
{
	int i;
	int c;
	int sflag, Sflag, pflag, fflag, Fflag, vflag; 
	int nflag, cflag, Cflag, iflag, lflag, Lflag, Pflag;
	struct meminfo meminfo;
	ulong value[MAXARGS];
	char buf[BUFSIZE];
	char *p1;
	int spec_addr;

	spec_addr = 0;
        sflag =	Sflag = pflag = fflag = Fflag = Pflag = 0;
	vflag = Cflag = cflag = iflag = nflag = lflag = Lflag = 0;
	BZERO(&meminfo, sizeof(struct meminfo));
	BZERO(&value[0], sizeof(ulong)*MAXARGS);

        while ((c = getopt(argcnt, args, "I:sSFfpvcCinl:L:P")) != EOF) {
                switch(c)
		{
		case 'n':
			nflag = 1;
			break;

		case 'i': 
			iflag = 1;
			break;

		case 'C':
			Cflag = 1, cflag = 0;;
			break;

		case 'c':
			cflag = 1, Cflag = 0;
			break;

		case 'v':
			vflag = 1;
			break;

		case 's':
			sflag = 1; Sflag = 0;
			break;

		case 'S':
			Sflag = 1; sflag = 0;
			break;

		case 'F':
			Fflag = 1; fflag = 0;
			break;;

		case 'f':
			fflag = 1; Fflag = 0;
			break;;

		case 'p':
			pflag = 1;
			break;

		case 'I':
			meminfo.ignore = optarg;
			break;	

		case 'l':
			if (STREQ(optarg, "a")) {
				meminfo.flags |= GET_ACTIVE_LIST;
				lflag = 1; Lflag = 0;
                        } else if (STREQ(optarg, "i")) { 
                                meminfo.flags |= GET_INACTIVE_LIST;
                                lflag = 1; Lflag = 0;
			} else if (STREQ(optarg, "ic")) {
				meminfo.flags |= GET_INACTIVE_CLEAN;
				lflag = 1; Lflag = 0;
			} else if (STREQ(optarg, "id")) {
				meminfo.flags |= GET_INACTIVE_DIRTY;
				lflag = 1; Lflag = 0;
			} else
				argerrs++;
			break;

                case 'L':
                        if (STREQ(optarg, "a")) {
                                meminfo.flags |= GET_ACTIVE_LIST;
                                Lflag = 1; lflag = 0;
			} else if (STREQ(optarg, "i")) {
                                meminfo.flags |= GET_INACTIVE_LIST;
                                Lflag = 1; lflag = 0;
                        } else if (STREQ(optarg, "ic")) {
                                meminfo.flags |= GET_INACTIVE_CLEAN;
                                Lflag = 1; lflag = 0;
                        } else if (STREQ(optarg, "id")) {
                                meminfo.flags |= GET_INACTIVE_DIRTY;
                                Lflag = 1; lflag = 0;
                        } else
                                argerrs++;
                        break;

		case 'P':
			Pflag = 1;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

        if ((sflag + Sflag + pflag + fflag + Fflag + 
            vflag + Cflag + cflag + iflag + lflag + Lflag) > 1) {
		error(INFO, "only one flag allowed!\n");
		cmd_usage(pc->curcmd, SYNOPSIS);
	} 

	if (sflag || Sflag)
		kmem_cache_init();   

	while (args[optind]) {
                if (hexadecimal(args[optind], 0)) {
                        value[spec_addr++] = 
				htol(args[optind], FAULT_ON_ERROR, NULL);
                } else {
		        if (meminfo.reqname)
                                error(FATAL,
                                  "only one kmem_cache reference is allowed\n");
                        meminfo.reqname = args[optind];
                        if (!sflag && !Sflag)
                                cmd_usage(pc->curcmd, SYNOPSIS);
                }

		optind++;
	}

	for (i = 0; i < spec_addr; i++) {

		if (Pflag) 
			meminfo.memtype = PHYSADDR;
		else 
			meminfo.memtype = IS_KVADDR(value[i]) ? 
				KVADDR : PHYSADDR;

               	if (fflag) {
                        meminfo.spec_addr = value[i];
                        meminfo.flags = ADDRESS_SPECIFIED;
                        if (meminfo.calls++)
                                fprintf(fp, "\n");
                        vt->dump_free_pages(&meminfo);
                        fflag++;
                }

                if (pflag) {
			meminfo.spec_addr = value[i];
			meminfo.flags = ADDRESS_SPECIFIED;
                        if (meminfo.calls++)
                        	fprintf(fp, "\n");
                        dump_mem_map(&meminfo);
                        pflag++;
                }

                if (sflag || Sflag) {
			meminfo.flags = Sflag ? VERBOSE : 0;

			if (meminfo.memtype == PHYSADDR) {
                          	if (value[i] < VTOP(vt->high_memory)) {
                        		value[i] = PTOV(value[i]);
					meminfo.memtype = KVADDR;
				} else
                			error(WARNING,
                    	   "cannot make virtual-to-physical translation: %lx\n",
                        			value[i]);
			}
			
			if ((p1 = is_kmem_cache_addr(value[i], buf))) {
				if (meminfo.reqname)
					error(FATAL, 
				  "only one kmem_cache reference is allowed\n");
				meminfo.reqname = p1;
                        	if ((i+1) == spec_addr) { /* done? */ 
					if (meminfo.calls++)
						fprintf(fp, "\n");
                        		vt->dump_kmem_cache(&meminfo);
				}
			} else {
                        	meminfo.spec_addr = value[i];
                        	meminfo.flags = ADDRESS_SPECIFIED;
				if (meminfo.calls++)
					fprintf(fp, "\n");
                        	vt->dump_kmem_cache(&meminfo);
			}

			if (sflag)
                        	sflag++;
			if (Sflag)
				Sflag++;
                }

                if (vflag) {
			meminfo.spec_addr = value[i];
			meminfo.flags = ADDRESS_SPECIFIED; 
			if (meminfo.calls++)
				fprintf(fp, "\n");
                        dump_vmlist(&meminfo);
                        vflag++;
                }

                if (cflag) {
			meminfo.spec_addr = value[i];
			meminfo.flags = ADDRESS_SPECIFIED; 
			if (meminfo.calls++)
				fprintf(fp, "\n");
                        dump_page_hash_table(&meminfo);
                        cflag++;
                }

                if (lflag) {
                        meminfo.spec_addr = value[i];
                        meminfo.flags |= (ADDRESS_SPECIFIED|VERBOSE);
                        if (meminfo.calls++)
                                fprintf(fp, "\n");
                        dump_page_lists(&meminfo);
                        lflag++;
                }

                /* 
                 * no value arguments allowed! 
                 */
                if (nflag || iflag || Fflag || Cflag || Lflag) {
			error(INFO, 
			    "no address arguments allowed with this option\n");
                        cmd_usage(pc->curcmd, SYNOPSIS);
		}

        	if (!(sflag + Sflag + pflag + fflag + vflag + cflag + 
		      lflag + Lflag)) {
			meminfo.spec_addr = value[i];
                        meminfo.flags = ADDRESS_SPECIFIED;
                        if (meminfo.calls++)
                                fprintf(fp, "\n");
			else
				kmem_cache_init();   
                        kmem_search(&meminfo);
		}

	}

	if (iflag == 1)
		dump_kmeminfo();

	if (pflag == 1)
		dump_mem_map(&meminfo);

	if (fflag == 1)
		vt->dump_free_pages(&meminfo);

	if (Fflag == 1) {
		meminfo.flags = VERBOSE;
		vt->dump_free_pages(&meminfo);
	}

	if (sflag == 1) 
		vt->dump_kmem_cache(&meminfo);

	if (Sflag == 1) {
		meminfo.flags = VERBOSE;
		vt->dump_kmem_cache(&meminfo);
	}

	if (vflag == 1)
		dump_vmlist(&meminfo);

	if (Cflag == 1) {
		meminfo.flags = VERBOSE;
		dump_page_hash_table(&meminfo);
	}

	if (cflag == 1)
		dump_page_hash_table(&meminfo);

	if (nflag == 1)
		dump_numa_nodes(VERBOSE);

	if (lflag == 1) { 
		dump_page_lists(&meminfo);
	}

	if (Lflag == 1) {
		meminfo.flags |= VERBOSE;
		dump_page_lists(&meminfo);
	}

	if (!(sflag + Sflag + pflag + fflag + Fflag + vflag + 
              cflag + Cflag + iflag + nflag + lflag + Lflag + meminfo.calls))
		cmd_usage(pc->curcmd, SYNOPSIS);

}

/*
 *  dump_mem_map() displays basic data about each entry in the mem_map[]
 *  array, or if an address is specified, just the mem_map[] entry for that
 *  address.  Specified addresses can either be physical address or page
 *  structure pointers.
 */

/* Page flag bit values */
#define v22_PG_locked                0
#define v22_PG_error                 1
#define v22_PG_referenced            2
#define v22_PG_dirty                 3
#define v22_PG_uptodate              4
#define v22_PG_free_after            5
#define v22_PG_decr_after            6
#define v22_PG_swap_unlock_after     7
#define v22_PG_DMA                   8
#define v22_PG_Slab                  9
#define v22_PG_swap_cache           10
#define v22_PG_skip                 11
#define v22_PG_reserved             31

#define v24_PG_locked                0
#define v24_PG_error                 1
#define v24_PG_referenced            2
#define v24_PG_uptodate              3
#define v24_PG_dirty                 4
#define v24_PG_decr_after            5
#define v24_PG_active                6
#define v24_PG_inactive_dirty        7
#define v24_PG_slab                  8
#define v24_PG_swap_cache            9
#define v24_PG_skip                 10
#define v24_PG_inactive_clean       11
#define v24_PG_highmem              12
                                /* bits 21-30 unused */
#define v24_PG_arch_1               30
#define v24_PG_reserved             31

#define PGMM_CACHED (512)

static void
dump_mem_map(struct meminfo *mi)
{
	long i, n;
	long total_pages;
	int others;
	ulong pp, ppend, physend;
	ulong tmp, reserved, shared, phys, slabs;
	long buffers;
	ulong inode, offset, flags, mapping, index;
	uint count;
	int print_hdr, pg_spec, phys_spec, done;
	int v22;
	struct numa_table *nt;
	char hdr[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char *page_cache;
	char *pcache;

	v22 = VALID_OFFSET(page_inode);  /* page.inode vs. page.mapping */

        if (v22) {
		sprintf(hdr, "%s%s%s%s%s%s%s%sCNT FLAGS\n",
		    mkstring(buf1, VADDR_PRLEN, CENTER, "PAGE"), 
		    space(MINSPACE),               
                    mkstring(buf2, MAX(PADDR_PRLEN, strlen("PHYSICAL")),
			RJUST, "PHYSICAL"),		    
		    space(MINSPACE),               
		    mkstring(buf3, VADDR_PRLEN, CENTER|RJUST, "INODE"), 
		    space(MINSPACE),               
		    mkstring(buf4, 8, CENTER|LJUST, "OFFSET"),
		    space(MINSPACE-1));
        } else {
		sprintf(hdr, "%s%s%s%s%s%s%sCNT FLAGS\n",
		    mkstring(buf1, VADDR_PRLEN, CENTER, "PAGE"), 
		    space(MINSPACE),             
                    mkstring(buf2, MAX(PADDR_PRLEN, strlen("PHYSICAL")),
                        RJUST, "PHYSICAL"),
		    space(MINSPACE),             
		    mkstring(buf3, VADDR_PRLEN, CENTER|RJUST, "MAPPING"),
		    space(MINSPACE),               
		    mkstring(buf4, 8, CENTER|RJUST, "INDEX"));
        }

	pg_spec = phys_spec = print_hdr = FALSE;
	
	switch (mi->flags)
	{
	case ADDRESS_SPECIFIED: 
		switch (mi->memtype)
		{
		case KVADDR:
                        if (is_page_ptr(mi->spec_addr, NULL))
                                pg_spec = TRUE;
                        else {
                                if (kvtop(NULL, mi->spec_addr, &tmp, 0)) {
                                        mi->spec_addr = tmp;
                                        phys_spec = TRUE;
                                }
                                else
                                        return;
                        }
			break;
		case PHYSADDR:
			phys_spec = TRUE;
			break;
		default:
			error(FATAL, "dump_mem_map: no memtype specified\n");
			break;
		}
		print_hdr = TRUE;
		break;

	case GET_ALL:
		shared = 0;
                reserved = 0;
		buffers = 0;
		slabs = 0;
		break;

	case GET_SHARED_PAGES:
		shared = 0;
		break;

	case GET_TOTALRAM_PAGES:
                reserved = 0;
		break;

	case GET_BUFFERS_PAGES:
		buffers = 0;
		break;

	case GET_SLAB_PAGES:
		slabs = 0;
		break;

	default:
		print_hdr = TRUE;
		break;
	}

	page_cache = GETBUF(SIZE(page) * PGMM_CACHED);
	done = FALSE;
	total_pages = 0;

	for (n = 0; n < vt->numnodes; n++) {

		if (print_hdr) 
			fprintf(fp, "%s%s", n ? "\n" : "", hdr);

		nt = &vt->numa_table[n];
		total_pages += nt->size;
		pp = nt->mem_map;
		phys = nt->start_paddr;

		for (i = 0; i < nt->size; 
		     i++, pp += SIZE(page), phys += PAGESIZE()) {

			if ((i % PGMM_CACHED) == 0) {

				ppend = pp + ((PGMM_CACHED-1) * SIZE(page));
				physend = phys + ((PGMM_CACHED-1) * PAGESIZE());

				if ((pg_spec && (mi->spec_addr > ppend)) ||
			            (phys_spec && 
					(PAGEBASE(mi->spec_addr) > physend))) {
					i += (PGMM_CACHED-1);
					pp = ppend;
					phys = physend;
					continue;
				}  

	        		readmem(pp, KVADDR, page_cache, 
					SIZE(page) * PGMM_CACHED, 
					"page cache", FAULT_ON_ERROR);
			}

			pcache = page_cache + ((i%PGMM_CACHED) * SIZE(page));

			if (received_SIGINT())
				restart(0);
	
			if ((pg_spec && (pp == mi->spec_addr)) || 
			    (phys_spec && (phys == PAGEBASE(mi->spec_addr)))) 
				done = TRUE;

			if (!done && (pg_spec || phys_spec))
				continue;
			
			flags = ULONG(pcache + OFFSET(page_flags));
			count = UINT(pcache + OFFSET(page_count));

	                switch (mi->flags)
			{
			case GET_ALL:
			case GET_BUFFERS_PAGES:
				tmp = ULONG(pcache + OFFSET(page_buffers));
				if (tmp)
					buffers++;

				if (mi->flags != GET_ALL)
					continue;

				/* FALLTHROUGH */

			case GET_SLAB_PAGES:
				if (v22) {
	                                if ((flags >> v22_PG_Slab) & 1) 
						slabs++;
				} else {
	                                if ((flags >> v24_PG_slab) & 1) 
						slabs++;
				}
				if (mi->flags != GET_ALL)
					continue;

				/* FALLTHROUGH */

			case GET_SHARED_PAGES:
			case GET_TOTALRAM_PAGES:
	                        if (v22) {
	                                if ((flags >> v22_PG_reserved) & 1) {
	                                        reserved++;
					} else {
						if (count > 1)
							shared++;
					}
	                        } else {
	                                if ((flags >> v24_PG_reserved) & 1) {
	                                        reserved++;
					} else {
						if (count > 1)
							shared++;
					}
	                        }
	                        continue;
	                }
	
			if (v22) {
				inode = ULONG(pcache + OFFSET(page_inode));
				offset = ULONG(pcache + OFFSET(page_offset));
			} else { 
				mapping = ULONG(pcache + 
					OFFSET(page_mapping));
				index = ULONG(pcache + OFFSET(page_index));
			}
	
			if (v22) {
				fprintf(fp, "%lx%s%s%s%s%s%8lx %2d%s",
					pp,
					space(MINSPACE),
                    			mkstring(buf1, MAX(PADDR_PRLEN, 
					    strlen("PHYSICAL")), 
					    RJUST|LONG_HEX, MKSTR(phys)),
					space(MINSPACE),
				        mkstring(buf2, VADDR_PRLEN, 
						RJUST|LONG_HEX, MKSTR(inode)),
					space(MINSPACE),
					offset,
					count,
					space(MINSPACE));
			} else {
                               fprintf(fp, "%lx%s%s%s%s%s%8ld %2d ",
                                        pp,
                                        space(MINSPACE),
                                        mkstring(buf1, MAX(PADDR_PRLEN,
                                            strlen("PHYSICAL")),
                                            RJUST|LONG_HEX, MKSTR(phys)),
                                        space(MINSPACE),
                                        mkstring(buf2, VADDR_PRLEN,
                                                RJUST|LONG_HEX, MKSTR(mapping)),
                                        space(MINSPACE),
                                        index,
                                        count);
			}
	
			others = 0;
	
			if (v22) {
		                if ((flags >> v22_PG_DMA) & 1)
		                        fprintf(fp, "%sDMA", 
						others++ ? "," : "");
				if ((flags >> v22_PG_locked) & 1)
					fprintf(fp, "%slocked", 
						others++ ? "," : "");
				if ((flags >> v22_PG_error) & 1)
					fprintf(fp, "%serror", 
						others++ ? "," : "");
				if ((flags >> v22_PG_referenced) & 1)
					fprintf(fp, "%sreferenced", 
						others++ ? "," : "");
				if ((flags >> v22_PG_dirty) & 1)
					fprintf(fp, "%sdirty", 
						others++ ? "," : "");
				if ((flags >> v22_PG_uptodate) & 1)
					fprintf(fp, "%suptodate", 
						others++ ? "," : "");
				if ((flags >> v22_PG_free_after) & 1)
					fprintf(fp, "%sfree_after", 
						others++ ? "," : "");
				if ((flags >> v22_PG_decr_after) & 1)
					fprintf(fp, "%sdecr_after", 
						others++ ? "," : "");
				if ((flags >> v22_PG_swap_unlock_after) & 1)
					fprintf(fp, "%sswap_unlock_after", 
						others++ ? "," : "");
				if ((flags >> v22_PG_Slab) & 1)
					fprintf(fp, "%sslab", 
						others++ ? "," : "");
				if ((flags >> v22_PG_swap_cache) & 1)
					fprintf(fp, "%sswap_cache", 
						others++ ? "," : "");
				if ((flags >> v22_PG_skip) & 1)
					fprintf(fp, "%sskip", 
						others++ ? "," : "");
	                        if ((flags >> v22_PG_reserved) & 1)
	                                fprintf(fp, "%sreserved", 
						others++ ? "," : "");
				fprintf(fp, "\n");
			} else {
	
		                if ((flags >> v24_PG_locked) & 1)
		                        fprintf(fp, "%slocked", 
						others++ ? "," : "");
				if ((flags >> v24_PG_error) & 1)
					fprintf(fp, "%serror", 
						others++ ? "," : "");
				if ((flags >> v24_PG_referenced) & 1)
					fprintf(fp, "%sreferenced", 
						others++ ? "," : "");
				if ((flags >> v24_PG_uptodate) & 1)
					fprintf(fp, "%suptodate", 
						others++ ? "," : "");
                                if ((flags >> v24_PG_dirty) & 1)
                                        fprintf(fp, "%sdirty",
                                                others++ ? "," : "");
				if ((flags >> v24_PG_decr_after) & 1)
					fprintf(fp, "%sdecr_after", 
						others++ ? "," : "");
                                if ((flags >> v24_PG_active) & 1)
                                        fprintf(fp, "%sactive",
                                                others++ ? "," : "");
                                if ((flags >> v24_PG_inactive_dirty) & 1)
                                        fprintf(fp, "%sinactive_dirty",
                                                others++ ? "," : "");
				if ((flags >> v24_PG_slab) & 1)
					fprintf(fp, "%sslab", 
						others++ ? "," : "");
				if ((flags >> v24_PG_swap_cache) & 1)
					fprintf(fp, "%sswap_cache", 
						others++ ? "," : "");
				if ((flags >> v24_PG_skip) & 1)
					fprintf(fp, "%sskip", 
						others++ ? "," : "");
				if ((flags >> v24_PG_inactive_clean) & 1)
					fprintf(fp, "%sinactive_clean", 
						others++ ? "," : "");
				if ((flags >> v24_PG_highmem) & 1)
					fprintf(fp, "%shighmem", 
						others++ ? "," : "");
                                if ((flags >> v24_PG_arch_1) & 1)
                                        fprintf(fp, "%sarch_1",
                                                others++ ? "," : "");
				if ((flags >> v24_PG_reserved) & 1)
					fprintf(fp, "%sreserved", 
						others++ ? "," : "");
				fprintf(fp, "\n");
			}
	
			if (done)
				break;
		}
	}

	switch (mi->flags)
	{
	case GET_TOTALRAM_PAGES:
		mi->retval = total_pages - reserved;
		break;

	case GET_SHARED_PAGES:
		mi->retval = shared;
		break;

	case GET_BUFFERS_PAGES:
		mi->retval = buffers;
		break;

	case GET_SLAB_PAGES:
		mi->retval = slabs;
		break;

	case GET_ALL:
		mi->get_totalram = total_pages - reserved;
		mi->get_shared = shared;
		mi->get_buffers = buffers;
        	mi->get_slabs = slabs;
		break;

	case ADDRESS_SPECIFIED:
		mi->retval = done;
		break; 
	}

	FREEBUF(page_cache);
}

/*
 *  dump_page_hash_table() displays the entries in each page_hash_table.
 */

#define PGHASH_CACHED (1024)

static void
dump_page_hash_table(struct meminfo *hi)
{
	int i;
	int len;
	unsigned int page_hash_bits;
	ulong page_hash_table, head;
	struct list_data list_data, *ld;
	long total_cached;
	long page_cache_size;
	ulong this_addr, searchpage;
	int errflag, found, cnt, populated, verbose;
	uint ival;
	char buf[BUFSIZE];
	char hash_table[BUFSIZE];
	char *pcache, *pghash_cache;

	ld = &list_data;

	if (hi->spec_addr && (hi->flags & ADDRESS_SPECIFIED)) {
		verbose = TRUE;
		searchpage = hi->spec_addr;
	} else if (hi->flags & VERBOSE) {
		verbose = TRUE;
		searchpage = 0;
	} else { 
		verbose = FALSE;
		searchpage = 0;
	}

	if ((len = get_array_length("page_hash_table", NULL)) == 0) {
		if (!symbol_exists("page_hash_bits"))
			error(FATAL, 
				"cannot determine size of page_hash_table\n");

		get_symbol_data("page_hash_bits", sizeof(unsigned int), 
			&page_hash_bits);
		len = (1 << page_hash_bits);
                get_symbol_data("page_hash_table", sizeof(void *),
                        &page_hash_table);
	} else 
		page_hash_table = symbol_value("page_hash_table");

	if (MCLXDEBUG(1)) {
		populated = 0;
		fprintf(fp, "page_hash_table length: %d\n", len);
	}

        if (sizeof_variable("page_cache_size") == sizeof(int)) {
                get_symbol_data("page_cache_size", sizeof(int), &ival);
                page_cache_size = (long)ival;
        } else
                get_symbol_data("page_cache_size", sizeof(long),
                        &page_cache_size);

        pghash_cache = GETBUF(sizeof(void *) * PGHASH_CACHED);

	if (searchpage)
		open_tmpfile();

	hq_open();
	for (i = total_cached = 0; i < len; i++, 
	     page_hash_table += sizeof(void *)) {

                if ((i % PGHASH_CACHED) == 0) {
                	readmem(page_hash_table, KVADDR, pghash_cache,
                        	sizeof(void *) * PGHASH_CACHED,
                                "page hash cache", FAULT_ON_ERROR);
                }

                pcache = pghash_cache + ((i%PGHASH_CACHED) * sizeof(void *));
		head = ULONG(pcache);

		if (!head) 
			continue;

		if (verbose) 
			fprintf(fp, "page_hash_table[%d]\n", i);
		
		if (MCLXDEBUG(1))
			populated++;

                BZERO(ld, sizeof(struct list_data));
                ld->flags = verbose;
                ld->start = head;
		ld->searchfor = searchpage;
		ld->member_offset = OFFSET(page_next_hash);
                cnt = do_list(ld);
                total_cached += cnt;

		if (ld->searchfor)
			break;

		if (received_SIGINT())
			restart(0);
	}
	hq_close();

        fprintf(fp, "%spage_cache_size: %ld ", verbose ? "\n" : "",
                page_cache_size);
        if (page_cache_size != total_cached)
                fprintf(fp, "(found %ld)\n", total_cached);
        else
                fprintf(fp, "(verified)\n");

	if (MCLXDEBUG(1))
		fprintf(fp, "heads containing page(s): %d\n", populated);

	if (searchpage) {
		rewind(pc->tmpfile);
		found = FALSE;
		while (fgets(buf, BUFSIZE, pc->tmpfile)) {
			if (MCLXDEBUG(1) && STRNEQ(buf, "<readmem:"))
				continue;

			if (strstr(buf, "page_hash_table")) {
				strcpy(hash_table, buf); 
				continue;
			}
			if (strstr(buf, "page_cache_size"))
				continue;

			if (MCLXDEBUG(1) && 
			    !hexadecimal(strip_linefeeds(buf), 0))
				continue;

                	this_addr = htol(strip_linefeeds(buf),
                        	RETURN_ON_ERROR, &errflag);

			if (this_addr == searchpage) {
				found = TRUE;
				break;
			}
		}
		close_tmpfile();

		if (found) {
			fprintf(fp, hash_table);
			fprintf(fp, "%lx\n", searchpage);
			hi->retval = TRUE;
		}
	}
}

/*
 *  dump_free_pages() displays basic data about pages currently resident
 *  in the free_area[] memory lists.  If the flags contains the VERBOSE 
 *  bit, each page slab base address is dumped.  If an address is specified
 *  only the free_area[] data containing that page is displayed, along with
 *  the page slab base address.  Specified addresses can either be physical 
 *  address or page structure pointers.
 */
char *free_area_hdr1 = \
	"AREA  SIZE  FREE_AREA_STRUCT  BLOCKS   PAGES\n";
char *free_area_hdr2 = \
	"AREA  SIZE  FREE_AREA_STRUCT\n";

static void
dump_free_pages(struct meminfo *fi)
{
	int i;
	int order;
	ulong free_area;
	char *free_area_buf;
	ulong *pp;
	int nr_mem_lists;
	struct list_data list_data, *ld;
	long cnt, total_free, chunk_size;
	int nr_free_pages;
	char buf[BUFSIZE];
	char last_free[BUFSIZE];
	char last_free_hdr[BUFSIZE];
	int verbose, errflag, found;
	ulong searchphys, this_addr, this_phys;
	int do_search;
	ulong kfp, offset;
	int flen, dimension;

        if (vt->flags & (NUMA|ZONES)) 
		error(FATAL, "dump_free_pages called with (NUMA|ZONES)\n");

	if ((nr_mem_lists = get_array_length("free_area", &dimension)) == 0)
		error(FATAL, "cannot determine size/dimensions of free_area\n");

	if (dimension) 
		error(FATAL, 
		    "dump_free_pages called with multidimensional free area\n");

	ld = &list_data;
	total_free = 0;
	searchphys = 0;
	do_search = FALSE;
	get_symbol_data("nr_free_pages", sizeof(int), &nr_free_pages);
	
	switch (fi->flags)
	{
	case GET_FREE_HIGHMEM_PAGES:
                error(FATAL, "GET_FREE_HIGHMEM_PAGES invalid in this kernel\n");

	case GET_FREE_PAGES:
		fi->retval = (ulong)nr_free_pages;
		return;

	case ADDRESS_SPECIFIED:
		switch (fi->memtype)
		{
		case KVADDR:
                        if (!page_to_phys(fi->spec_addr, &searchphys)) {
                                if (!kvtop(NULL, fi->spec_addr, &searchphys, 0))
                                        return;
                        }
			break;
		case PHYSADDR:
			searchphys = fi->spec_addr;
			break;
		default:
			error(FATAL, "dump_free_pages: no memtype specified\n");
		}
		do_search = TRUE;
		break;
	} 

	verbose = (do_search || (fi->flags & VERBOSE)) ? TRUE : FALSE;

	free_area_buf = GETBUF(nr_mem_lists * SIZE(free_area_struct));
	kfp = free_area = symbol_value("free_area");
	flen = MAX(VADDR_PRLEN, strlen("FREE_AREA_STRUCT"));
	readmem(free_area, KVADDR, free_area_buf, 
		SIZE(free_area_struct) * nr_mem_lists, 
		"free_area_struct", FAULT_ON_ERROR);

	if (do_search)
		open_tmpfile();

	if (!verbose)
		fprintf(fp, free_area_hdr1);

       	hq_open();
	for (i = 0; i < nr_mem_lists; i++) {
		pp = (ulong *)(free_area_buf + (SIZE(free_area_struct)*i));

		chunk_size = power(2, i);

		if (verbose)
			fprintf(fp, free_area_hdr2);

		fprintf(fp, "%3d  ", i);
		sprintf(buf, "%ldk", (chunk_size * PAGESIZE())/1024);
		fprintf(fp, "%5s  ", buf);

		fprintf(fp, "%s  %s", 
			mkstring(buf, flen, CENTER|LONG_HEX, MKSTR(kfp)),
			verbose ? "\n" : "");

		if (is_page_ptr(*pp, NULL)) {
			BZERO(ld, sizeof(struct list_data));
			ld->flags = verbose;
			ld->start = *pp;
			ld->end = free_area;
        		cnt = do_list(ld);
			total_free += (cnt * chunk_size);
		} else 
			cnt = 0;

		if (!verbose)
			fprintf(fp, "%6ld  %6ld\n", cnt, cnt * chunk_size );

		free_area += SIZE(free_area_struct);
		kfp += SIZE(free_area_struct);
	}
       	hq_close();

	fprintf(fp, "\nnr_free_pages: %d ", nr_free_pages);
	if (total_free != nr_free_pages)
		fprintf(fp, "(found %ld)\n", total_free);
	else
		fprintf(fp, "(verified)\n");

	if (!do_search)
		return;

	found = FALSE;
        rewind(pc->tmpfile);
	order = offset = 0;

        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
		if (MCLXDEBUG(1) && STRNEQ(buf, "<readmem"))
			continue;

		if (strstr(buf, "nr_free_pages") ||
		    STREQ(buf, "\n"))
			continue;

		if (strstr(buf, "AREA")) {
			strcpy(last_free_hdr, buf);
			continue;
		}

		if (strstr(buf, "k")) {
			strcpy(last_free, buf);
			chunk_size = power(2, order) * PAGESIZE();
			order++;
			continue;
		}

		if (MCLXDEBUG(1) && !hexadecimal(strip_linefeeds(buf), 0))
			continue;

		errflag = 0;
		this_addr = htol(strip_linefeeds(buf), 
			RETURN_ON_ERROR, &errflag);
                if (errflag) 
			continue;

		if (!page_to_phys(this_addr, &this_phys))
			continue;

		if ((searchphys >= this_phys) && 
		    (searchphys < (this_phys+chunk_size))) {
			if (searchphys > this_phys) 
				offset = (searchphys - this_phys)/PAGESIZE();
			found = TRUE;
			break;
		}
	}
        close_tmpfile();

	if (found) {
		order--;

		fprintf(fp, last_free_hdr);
		fprintf(fp, last_free);
		fprintf(fp, "%lx  ", this_addr);
		if (order) {
                	switch (fi->memtype)
                	{
                	case KVADDR:
				fprintf(fp, "(%lx is ", fi->spec_addr);
                        	break;
                	case PHYSADDR:
				fprintf(fp, "(%lx is %s", fi->spec_addr,
				    PAGEOFFSET(fi->spec_addr) ?  "in " : "");
                        	break;
			}
			fprintf(fp, "%s of %ld pages) ",
				ordinal(offset+1, buf), power(2, order));
		}

		fi->retval = TRUE;
		fprintf(fp, "\n");
	}
}

/*
 *  Dump free pages on kernels with a multi-dimensional free_area array.
 */
char *free_area_hdr5 = \
	"  AREA    SIZE  FREE_AREA_STRUCT  BLOCKS   PAGES\n";
char *free_area_hdr6 = \
	"  AREA    SIZE  FREE_AREA_STRUCT\n";

static void
dump_multidimensional_free_pages(struct meminfo *fi)
{
	int i, j;
	struct list_data list_data, *ld;
	long cnt, total_free;
	ulong searchphys, kfp, free_area;
	int flen, errflag, verbose, nr_free_pages;
	int nr_mem_lists, dimension, order, do_search;
	ulong sum, found, offset;
	char *free_area_buf, *p;
	ulong *pp;
	long chunk_size;
        ulong this_addr, this_phys;
	char buf[BUFSIZE];
	char last_area[BUFSIZE];
	char last_area_hdr[BUFSIZE];


        if (vt->flags & (NUMA|ZONES)) 
                error(FATAL, 
		"dump_multidimensional_free_pages called with (NUMA|ZONES)\n");

        ld = &list_data;
	if (SIZE(free_area_struct) % sizeof(ulong))
		error(FATAL, "free_area_struct not long-word aligned?\n");

        total_free = 0;
        searchphys = 0;
	do_search = FALSE;
        get_symbol_data("nr_free_pages", sizeof(int), &nr_free_pages);

        switch (fi->flags)
        {
        case GET_FREE_HIGHMEM_PAGES:
                error(FATAL, "GET_FREE_HIGHMEM_PAGES invalid in this kernel\n");

        case GET_FREE_PAGES:
                fi->retval = (ulong)nr_free_pages;
                return;

	case ADDRESS_SPECIFIED:
		switch (fi->memtype)
                {
                case KVADDR:
                        if (!page_to_phys(fi->spec_addr, &searchphys)) {
                                if (!kvtop(NULL, fi->spec_addr, &searchphys, 0))
                                        return;
                        }
                        break;
                case PHYSADDR:
                        searchphys = fi->spec_addr;
                        break;
                default:
                        error(FATAL, 
		    "dump_multidimensional_free_pages: no memtype specified\n");
                }
		do_search = TRUE;
		break;
	}

        verbose = (do_search || (fi->flags & VERBOSE)) ? TRUE : FALSE;

	flen = MAX(VADDR_PRLEN, strlen("FREE_AREA_STRUCT"));
        nr_mem_lists = get_array_length("free_area", &dimension);
	if (!nr_mem_lists || !dimension)
		error(FATAL, "cannot determine free_area dimensions\n");
        free_area_buf = 
		GETBUF((nr_mem_lists * SIZE(free_area_struct)) * dimension);
        kfp = free_area = symbol_value("free_area");
        readmem(free_area, KVADDR, free_area_buf, 
		(SIZE(free_area_struct) * nr_mem_lists) * dimension,
                "free_area arrays", FAULT_ON_ERROR);

        if (do_search)
                open_tmpfile();

        hq_open();
        for (i = sum = found = 0; i < dimension; i++) {
        	if (!verbose)
                	fprintf(fp, free_area_hdr5);
               	pp = (ulong *)(free_area_buf + 
			((SIZE(free_area_struct)*nr_mem_lists)*i));
		for (j = 0; j < nr_mem_lists; j++) {
                        if (verbose)
                                fprintf(fp, free_area_hdr6);

			sprintf(buf, "[%d][%d]", i, j);
			fprintf(fp, "%7s  ", buf);

                	chunk_size = power(2, j);

                	sprintf(buf, "%ldk", (chunk_size * PAGESIZE())/1024);
                	fprintf(fp, "%5s  ", buf);

                	fprintf(fp, "%s  %s",  
			    mkstring(buf, flen, CENTER|LONG_HEX, MKSTR(kfp)),
			    verbose ? "\n" : "");

                	if (is_page_ptr(*pp, NULL)) {
                        	BZERO(ld, sizeof(struct list_data));
                        	ld->flags = verbose;
                        	ld->start = *pp;
                        	ld->end = free_area;
                        	cnt = do_list(ld);
                        	total_free += (cnt * chunk_size);
                	} else
                        	cnt = 0;

                	if (!verbose)
                        	fprintf(fp, 
					"%6ld  %6ld\n", cnt, cnt * chunk_size );

			pp += (SIZE(free_area_struct)/sizeof(ulong));
			free_area += SIZE(free_area_struct);
			kfp += SIZE(free_area_struct);
		}
		fprintf(fp, "\n");
	}
	hq_close();

        fprintf(fp, "nr_free_pages: %d ", nr_free_pages);
        if (total_free != nr_free_pages)
                fprintf(fp, "(found %ld)\n", total_free);
        else
                fprintf(fp, "(verified)\n");

        if (!do_search)
                return;

        found = FALSE;
        rewind(pc->tmpfile);
        order = offset = 0;

        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
		if (MCLXDEBUG(1) && STRNEQ(buf, "<readmem:"))
			continue;

		if (STRNEQ(buf, "nr_free_pages:"))
			continue;

		if (strstr(buf, "AREA")) {
                        strcpy(last_area_hdr, buf);
                        fgets(buf, BUFSIZE, pc->tmpfile);
                        strcpy(last_area, strip_linefeeds(buf));
			p = strstr(buf, "k");
			*p = NULLCHAR;
			while (*p != ' ')
				p--;
			chunk_size = atol(p+1) * 1024;
			if (chunk_size == PAGESIZE())
				order = 0;
			else
				order++;
                        continue;
                }

                errflag = 0;
                this_addr = htol(strip_linefeeds(buf),
                        RETURN_ON_ERROR, &errflag);
                if (errflag)
                        continue;

                if (!page_to_phys(this_addr, &this_phys))
                        continue;

                if ((searchphys >= this_phys) &&
                    (searchphys < (this_phys+chunk_size))) {
                        if (searchphys > this_phys)
                                offset = (searchphys - this_phys)/PAGESIZE();
                        found = TRUE;
                        break;
                }

	}
	close_tmpfile();

	if (found) {
		fprintf(fp, last_area_hdr);
		fprintf(fp, "%s\n", last_area);
		fprintf(fp, "%lx  ", this_addr);
                if (order) {
                	switch (fi->memtype)
                	{
                	case KVADDR:
                                fprintf(fp, "(%lx is ", fi->spec_addr);
                        	break;
                	case PHYSADDR:
                                fprintf(fp, "(%lx is %s", fi->spec_addr,
                                    PAGEOFFSET(fi->spec_addr) ?  "in " : "");
                        	break;
			}
                        fprintf(fp, "%s of %ld pages) ",
                                ordinal(offset+1, buf), power(2, order));
                }

		fi->retval = TRUE;
                fprintf(fp, "\n");
	}
}


/*
 *  Dump free pages in newer kernels that have zones.  This is a work in
 *  progress, because although the framework for NUMA nodes has been laid
 *  down, complete support has not been put in place.
 */
char *zone_hdr = "ZONE  NAME        SIZE    FREE";

/*
 *  From linux/mmzone.h
 */
#define ZONE_DMA                0
#define ZONE_NORMAL             1
#define ZONE_HIGHMEM            2


static void
dump_free_pages_zones(struct meminfo *fi)
{
	int i, n;
	ulong node_zones;
	ulong size;
	long chunk_size;
	int nr_zones, nr_areas;
	int order, errflag, do_search;
	ulong offset, verbose, searchphys, value, sum, found; 
	ulong this_addr, this_phys;
        ulong zone_mem_map;
        ulong zone_start_paddr;
        ulong zone_start_mapnr;
	struct numa_table *nt;
	char buf[BUFSIZE], *p;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char last_node[BUFSIZE];
	char last_zone[BUFSIZE];
	char last_area[BUFSIZE];
	char last_area_hdr[BUFSIZE];

       if (!(vt->flags & (NUMA|ZONES)))
		error(FATAL, 
			"dump_free_pages_zones called without (NUMA|ZONES)\n");

        if (fi->flags & ADDRESS_SPECIFIED) {
                switch (fi->memtype)
                {
                case KVADDR:
                        if (!page_to_phys(fi->spec_addr, &searchphys)) {
                                if (!kvtop(NULL, fi->spec_addr, &searchphys, 0))
                                        return;
                        }
                        break;
                case PHYSADDR:
                        searchphys = fi->spec_addr;
                        break;
                default:
                        error(FATAL, 
			    "dump_free_pages_zones: no memtype specified\n");
                }
		do_search = TRUE;
        } else {
                searchphys = 0;
		do_search = FALSE;
	}
        verbose = (do_search || (fi->flags & VERBOSE)) ? TRUE : FALSE;

	nr_zones = get_array_length("pglist_data.node_zones", NULL);
	nr_areas = get_array_length("zone_struct.free_area", NULL);

	if (do_search)
		open_tmpfile();

	hq_open();

	for (n = sum = found = 0; n < vt->numnodes; n++) {
                nt = &vt->numa_table[n];
		node_zones = nt->pgdat + OFFSET(pglist_data_node_zones);

		for (i = 0; i < nr_zones; i++) {
	
			if (fi->flags == GET_FREE_PAGES) {
	                	readmem(node_zones+
					OFFSET(zone_struct_free_pages), 
					KVADDR, &value, sizeof(ulong),
	                        	"node_zones free_pages", 
					FAULT_ON_ERROR);
				sum += value;
				node_zones += SIZE(zone_struct);
				continue;
			}
	
	                if (fi->flags == GET_FREE_HIGHMEM_PAGES) {
	                        if (i == ZONE_HIGHMEM) {
	                                readmem(node_zones+
						OFFSET(zone_struct_free_pages),
						KVADDR, &value, sizeof(ulong),
	                                        "node_zones free_pages",
	                                        FAULT_ON_ERROR);
	                                sum += value;
	                        }
	                        node_zones += SIZE(zone_struct);
	                        continue;
	                }
	
			if (fi->flags == GET_ZONE_SIZES) {
	                	readmem(node_zones+OFFSET(zone_struct_size), 
					KVADDR, &size, sizeof(ulong),
	                        	"node_zones size", FAULT_ON_ERROR);
	                        sum += size;
	                        node_zones += SIZE(zone_struct);
	                        continue;
			}
	
			if ((i == 0) && (vt->flags & NUMA)) {
				fprintf(fp, "%sNODE\n %2d\n", 
					n ? "\n" : "", nt->node_id);
			}

	                fprintf(fp, "%s  %s  START_PADDR  START_MAPNR\n",
	                        zone_hdr,
	                        mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, 
				    "MEM_MAP"));
	
			fprintf(fp, "%3d   ", i);
	
	        	readmem(node_zones+OFFSET(zone_struct_name), KVADDR, 
				&value, sizeof(void *), 
				"node_zones name", FAULT_ON_ERROR);
	                if (read_string(value, buf, BUFSIZE-1))
	                	fprintf(fp, "%-9s ", buf);
			else
				fprintf(fp, "(unknown) ");
	
	        	readmem(node_zones+OFFSET(zone_struct_size), KVADDR, 
				&size, sizeof(ulong), 
				"node_zones size", FAULT_ON_ERROR);
	                fprintf(fp, "%6ld  ", size);
	
	        	readmem(node_zones+OFFSET(zone_struct_free_pages), 
				KVADDR, &value, sizeof(ulong), 
				"node_zones free_pages", FAULT_ON_ERROR);
	
	                fprintf(fp, "%6ld  ", value);
	
	                readmem(node_zones+OFFSET(zone_struct_zone_start_paddr),
	                        KVADDR, &zone_start_paddr, sizeof(ulong),
	                        "node_zones zone_start_paddr", FAULT_ON_ERROR);
	                readmem(node_zones+OFFSET(zone_struct_zone_start_mapnr),
	                        KVADDR, &zone_start_mapnr, sizeof(ulong),
	                        "node_zones zone_start_mapnr", FAULT_ON_ERROR);
	                readmem(node_zones+OFFSET(zone_struct_zone_mem_map),
	                        KVADDR, &zone_mem_map, sizeof(ulong),
	                        "node_zones zone_mem_map", FAULT_ON_ERROR);
	
	                fprintf(fp, "%s  %s  %s\n",
	                	mkstring(buf1, VADDR_PRLEN,
	                            CENTER|LONG_HEX,MKSTR(zone_mem_map)),
	                	mkstring(buf2, strlen("START_PADDR"),
	                            CENTER|LONG_HEX|RJUST,
					MKSTR(zone_start_paddr)),
	                	mkstring(buf3, strlen("START_MAPNR"),
	                            CENTER|LONG_DEC|RJUST,
					MKSTR(zone_start_mapnr)));
	
			sum += value;
	
			if (value)
				found += dump_zone_free_area(node_zones+
					OFFSET(zone_struct_free_area), 
					nr_areas, verbose);
	
			node_zones += SIZE(zone_struct);
		}
	}

	hq_close();

        if (fi->flags & (GET_FREE_PAGES|GET_ZONE_SIZES|GET_FREE_HIGHMEM_PAGES)){
                fi->retval = sum;
                return;
        }

	fprintf(fp, "\nnr_free_pages: %ld  ", sum);
	if (sum == found)
		fprintf(fp, "(verified)\n");
	else
		fprintf(fp, "(found %ld)\n", found);

	if (!do_search)
		return;

        found = FALSE;
        rewind(pc->tmpfile);
        order = offset = 0;
	last_node[0] = NULLCHAR;
        last_zone[0] = NULLCHAR;
        last_area[0] = NULLCHAR;
        last_area_hdr[0] = NULLCHAR;


        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
		if (MCLXDEBUG(1) && STRNEQ(buf, "<readmem"))
			continue;

		if (STRNEQ(buf, "nr_free_pages:"))
			continue;

		if (STRNEQ(buf, "NODE")) { 
			fgets(buf, BUFSIZE, pc->tmpfile);
			strcpy(last_node, strip_linefeeds(buf));
			continue;
		}
		if (STRNEQ(buf, "ZONE")) {
			fgets(buf, BUFSIZE, pc->tmpfile);
			strcpy(last_zone, strip_linefeeds(buf));
			continue;
		}
		if (STRNEQ(buf, "AREA")) {
                        strcpy(last_area_hdr, buf);
                        fgets(buf, BUFSIZE, pc->tmpfile);
                        strcpy(last_area, strip_linefeeds(buf));
			p = strstr(buf, "k");
			*p = NULLCHAR;
			while (*p != ' ')
				p--;
			chunk_size = atol(p+1) * 1024;
			if (chunk_size == PAGESIZE())
				order = 0;
			else
				order++;
                        continue;
                }

                if (MCLXDEBUG(1) &&
                    !hexadecimal(strip_linefeeds(buf), 0))
                        continue;

                errflag = 0;
                this_addr = htol(strip_linefeeds(buf),
                        RETURN_ON_ERROR, &errflag);
                if (errflag)
                        continue;

                if (!page_to_phys(this_addr, &this_phys))
                        continue;

                if ((searchphys >= this_phys) &&
                    (searchphys < (this_phys+chunk_size))) {
                        if (searchphys > this_phys)
                                offset = (searchphys - this_phys)/PAGESIZE();
                        found = TRUE;
                        break;
                }

	}
	close_tmpfile();

	if (found) {
		if (strlen(last_node)) 
			fprintf(fp, "NODE\n%s\n", last_node); 
                fprintf(fp, "%s  %s  START_PADDR  START_MAPNR\n",
                        zone_hdr,
                        mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "MEM_MAP"));
		fprintf(fp, "%s\n", last_zone);
		fprintf(fp, last_area_hdr);
		fprintf(fp, "%s\n", last_area);
		fprintf(fp, "%lx  ", this_addr);
                if (order) {
                	switch (fi->memtype)
                	{
                	case KVADDR:
                                fprintf(fp, "(%lx is ", fi->spec_addr);
                        	break;
                	case PHYSADDR:
                                fprintf(fp, "(%lx is %s", fi->spec_addr,
                                    PAGEOFFSET(fi->spec_addr) ?  "in " : "");
                        	break;
			}
                        fprintf(fp, "%s of %ld pages) ",
                                ordinal(offset+1, buf), power(2, order));
                }

		fi->retval = TRUE;
                fprintf(fp, "\n");
	}
}


/*
 *  Dump the num "order" contents of the zone_t free_area array.
 */
char *free_area_hdr3 = "AREA  SIZE  FREE_AREA_STRUCT\n";
char *free_area_hdr4 = "AREA  SIZE  FREE_AREA_STRUCT  BLOCKS  PAGES\n";

static int
dump_zone_free_area(ulong free_area, int num, ulong verbose)
{
	int i;
	long chunk_size;
	int flen, total_free, cnt;
	char buf[BUFSIZE];
	ulong free_area_buf[3];
	struct list_data list_data, *ld;

	if (SIZE(free_area_struct) != (3 * sizeof(ulong)))
		error(FATAL, 
		    "unrecognized free_area_struct size: %ld\n", 
			SIZE(free_area_struct));

	ld = &list_data;

	if (!verbose)
		fprintf(fp, free_area_hdr4);

	total_free = 0;
	flen = MAX(VADDR_PRLEN, strlen("FREE_AREA_STRUCT"));

	for (i = 0; i < num; i++, free_area += SIZE(free_area_struct)) {
		if (verbose)
			fprintf(fp, free_area_hdr3);
		fprintf(fp, "%3d ", i);
		chunk_size = power(2, i);
		sprintf(buf, "%ldk", (chunk_size * PAGESIZE())/1024);
                fprintf(fp, " %5s  ", buf);

                readmem(free_area, KVADDR, free_area_buf,
                        sizeof(ulong) * 3, "free_area_struct", FAULT_ON_ERROR);

		fprintf(fp, "%s  ",
			mkstring(buf, flen, CENTER|LONG_HEX, MKSTR(free_area)));

		if (free_area_buf[0] == free_area) {
			if (verbose)
				fprintf(fp, "\n");
			else
				fprintf(fp, "%6d %6d\n", 0, 0);
			continue;
		}
	
		if (verbose)
			fprintf(fp, "\n");

                BZERO(ld, sizeof(struct list_data));
                ld->flags = verbose | RETURN_ON_DUPLICATE;
                ld->start = free_area_buf[0];
                ld->end = free_area;
                cnt = do_list(ld);
		if (cnt < 0) 
			error(FATAL, 
			    "corrupted free list from free_area_struct: %lx\n", 
				free_area);

		if (!verbose)
			fprintf(fp, "%6d %6ld\n", cnt, cnt*chunk_size);

                total_free += (cnt * chunk_size);
	}

	return total_free;
}

/*
 *  dump_kmeminfo displays basic memory use information typically shown 
 *  by /proc/meminfo, and then some...
 */

char *kmeminfo_hdr = "              PAGES     TOTAL        PERCENTAGE\n";

static void
dump_kmeminfo(void)
{
	ulong totalram_pages;
	ulong freeram_pages;
	ulong used_pages;
	ulong shared_pages;
	ulong buffer_pages;
	ulong totalswap_pages, totalused_pages;
        ulong totalhigh_pages;
        ulong freehighmem_pages;
        ulong totallowmem_pages;
        ulong freelowmem_pages;
	ulong pct;
	uint tmp;
	struct meminfo meminfo;
	long page_cache_size;
        ulong get_totalram;
        ulong get_buffers;
        ulong get_slabs;


	BZERO(&meminfo, sizeof(struct meminfo));
	meminfo.flags = GET_ALL;
	dump_mem_map(&meminfo);
	get_totalram = meminfo.get_totalram;
	shared_pages = meminfo.get_shared;
	get_buffers = meminfo.get_buffers;
	get_slabs = meminfo.get_slabs;

	fprintf(fp, kmeminfo_hdr);
	/*
	 *  Get total RAM based upon how the various versions of si_meminfo()
         *  have done it, latest to earliest:
	 *
         *    Prior to 2.3.36, count all mem_map pages minus the reserved ones.
         *    From 2.3.36 onwards, use "totalram_pages".
	 */
	if (symbol_exists("totalram_pages"))   
		totalram_pages = vt->totalram_pages;
	else 
		totalram_pages = get_totalram;

	fprintf(fp, "%10s  %7ld  %10lu         ----\n", "TOTAL MEM", 
		totalram_pages, PTOB(totalram_pages));

	/*
	 *  Get free pages from dump_free_pages() or its associates.
	 *  Used pages are a free-bee...
	 */
	meminfo.flags = GET_FREE_PAGES;
	vt->dump_free_pages(&meminfo);
	freeram_pages = meminfo.retval;
        pct = (freeram_pages * 100)/totalram_pages;
	fprintf(fp, "%10s  %7ld  %10lu  %3ld%% of TOTAL MEM\n", 
		"FREE", freeram_pages, PTOB(freeram_pages), pct);

	used_pages = totalram_pages - freeram_pages;
        pct = (used_pages * 100)/totalram_pages;
        fprintf(fp, "%10s  %7ld  %10lu  %3ld%% of TOTAL MEM\n", 
		"USED", used_pages, PTOB(used_pages), pct);

	/*
	 *  Get shared pages from dump_mem_map().  Note that this is done
         *  differently than the kernel -- it just tallies the non-reserved
         *  pages that have a count of greater than 1.
	 */
        pct = (shared_pages * 100)/totalram_pages;
        fprintf(fp, "%10s  %7ld  %10lu  %3ld%% of TOTAL MEM\n", 
		"SHARED", shared_pages, PTOB(shared_pages), pct);

	if (symbol_exists("buffermem_pages")) { 
                get_symbol_data("buffermem_pages", sizeof(int), &tmp);
		buffer_pages = (ulong)tmp;

	} else if (symbol_exists("buffermem")) {
                get_symbol_data("buffermem", sizeof(int), &tmp);
		buffer_pages = BTOP(tmp);
	} else
		buffer_pages = 0;

        pct = (buffer_pages * 100)/totalram_pages;
        fprintf(fp, "%10s  %7ld  %10lu  %3ld%% of TOTAL MEM\n", 
		"BUFFERS", buffer_pages, PTOB(buffer_pages), pct);

	if (MCLXDEBUG(1)) 
        	fprintf(fp, "NOTE: pages with buffers: %ld\n", get_buffers);

	/*
	 *  page_cache_size has evolved from a long to an atomic_t.
	 */
        if (sizeof_variable("page_cache_size") == sizeof(int)) {
                get_symbol_data("page_cache_size", sizeof(int), &tmp);
                page_cache_size = (long)tmp;
        } else
                get_symbol_data("page_cache_size", sizeof(long),
                        &page_cache_size);

        pct = (page_cache_size * 100)/totalram_pages;
        fprintf(fp, "%10s  %7ld  %10lu  %3ld%% of TOTAL MEM\n", 
		"CACHED", page_cache_size, PTOB(page_cache_size), pct);

	/*
 	 *  Although /proc/meminfo doesn't show it, show how much memory
	 *  the slabs take up.
	 */

        pct = (get_slabs * 100)/totalram_pages;
	fprintf(fp, "%10s  %7ld  %10lu  %3ld%% of TOTAL MEM\n",
		"SLAB", get_slabs, PTOB(get_slabs), pct);

        if (symbol_exists("totalhigh_pages")) {
                get_symbol_data("totalhigh_pages", sizeof(ulong),
                        &totalhigh_pages);
		pct = totalhigh_pages ?
			(totalhigh_pages * 100)/totalram_pages : 0;
                fprintf(fp, "\n%10s  %7ld  %10lu  %3ld%% of TOTAL MEM\n", 
			"TOTAL HIGH", totalhigh_pages, 
			PTOB(totalhigh_pages), pct);

		meminfo.flags = GET_FREE_HIGHMEM_PAGES;
                vt->dump_free_pages(&meminfo);
		freehighmem_pages = meminfo.retval;
        	pct = freehighmem_pages ?  
			(freehighmem_pages * 100)/totalhigh_pages : 0;
                fprintf(fp, "%10s  %7ld  %10lu  %3ld%% of TOTAL HIGH\n", 
			"FREE HIGH", freehighmem_pages, 
			PTOB(freehighmem_pages), pct);

                totallowmem_pages = totalram_pages - totalhigh_pages;
		pct = (totallowmem_pages * 100)/totalram_pages;
                fprintf(fp, "%10s  %7ld  %10lu  %3ld%% of TOTAL MEM\n", 
			"TOTAL LOW", totallowmem_pages, 
			PTOB(totallowmem_pages), pct);

                freelowmem_pages = freeram_pages - freehighmem_pages;
        	pct = (freelowmem_pages * 100)/totallowmem_pages;
                fprintf(fp, "%10s  %7ld  %10lu  %3ld%% of TOTAL LOW\n", 
			"FREE LOW", freelowmem_pages, 
			PTOB(freelowmem_pages), pct);
        }

        /*
         *  get swap data from dump_swap_info().
         */
        dump_swap_info(0, &totalswap_pages, &totalused_pages);
        fprintf(fp, "\n%10s  %7ld  %10lu         ----\n", 
		"TOTAL SWAP", totalswap_pages, PTOB(totalswap_pages));
        pct = (totalused_pages * 100)/totalswap_pages;
        fprintf(fp, "%10s  %7ld  %10lu  %3ld%% of TOTAL SWAP\n",
                "SWAP USED", totalused_pages,
                PTOB(totalused_pages), pct);
        pct = ((totalswap_pages - totalused_pages) * 100)/totalswap_pages;
        fprintf(fp, "%10s  %7ld  %10lu  %3ld%% of TOTAL SWAP\n", "SWAP FREE",
                totalswap_pages - totalused_pages,
                PTOB(totalswap_pages - totalused_pages), pct);

}


/*
 *  dump_vmlist() displays information from the vmlist.
 */

static void
dump_vmlist(struct meminfo *vi)
{
	char buf[BUFSIZE];
	ulong vmlist;
	ulong addr, size, next; 
	ulong pcheck, paddr;

	get_symbol_data("vmlist", sizeof(void *), &vmlist);
	next = vmlist;

	while (next) {
		if ((next == vmlist) && 
		    !(vi->flags & (GET_HIGHEST|GET_PHYS_TO_VMALLOC))) {
			fprintf(fp, "%s  ", 
			    mkstring(buf, MAX(strlen("VM_STRUCT"), VADDR_PRLEN),
			    	CENTER|LJUST, "VM_STRUCT"));
			fprintf(fp, "%s    SIZE\n",
			    mkstring(buf, (VADDR_PRLEN * 2) + strlen(" - "),
				CENTER|LJUST, "ADDRESS RANGE"));
		}

                readmem(next+OFFSET(vm_struct_addr), KVADDR, 
			&addr, sizeof(void *),
                        "vmlist addr", FAULT_ON_ERROR);
                readmem(next+OFFSET(vm_struct_size), KVADDR, 
			&size, sizeof(ulong),
                        "vmlist size", FAULT_ON_ERROR);

		if (!(vi->flags & ADDRESS_SPECIFIED) || 
		    ((vi->memtype == KVADDR) &&
		    ((vi->spec_addr >= addr) && (vi->spec_addr < (addr+size)))))
			fprintf(fp, "%9lx  %lx - %lx  %6ld\n",
				next, addr, addr+size, size);

		if ((vi->flags & ADDRESS_SPECIFIED) && 
		     (vi->memtype == PHYSADDR)) {
			for (pcheck = addr; pcheck < (addr+size); 
			     pcheck += PAGESIZE()) {
				if (!kvtop(NULL, pcheck, &paddr, 0))
					continue;
		    		if ((vi->spec_addr >= paddr) && 
				    (vi->spec_addr < (paddr+PAGESIZE()))) {
					if (vi->flags & GET_PHYS_TO_VMALLOC) {
						vi->retval = pcheck +
						    PAGEOFFSET(paddr);
						return;
				        } else
						fprintf(fp, 
						    "%9lx  %lx - %lx  %6ld\n",
						    	next, addr, 
						    	addr+size, size);
					break;
				}
			}

		}

                readmem(next+OFFSET(vm_struct_next), 
			KVADDR, &next, sizeof(void *),
                        "vmlist next", FAULT_ON_ERROR);
	}

	if (vi->flags & GET_HIGHEST)
		vi->retval = addr+size;
}

/*
 *  dump_page_lists() displays information from the active_list,
 *  inactive_dirty_list and inactive_clean_list from each zone.
 */
static int
dump_page_lists(struct meminfo *mi)
{
	int i, c, n, retval;
        ulong node_zones, pgdat;
	int nr_zones;
	struct numa_table *nt;
	struct list_data list_data, *ld;
	char buf[BUFSIZE];
	ulong value;
	ulong inactive_clean_pages, inactive_clean_list;
	int nr_active_pages, nr_inactive_pages;
	int nr_inactive_dirty_pages;

	ld = &list_data;

	retval = FALSE;
	nr_active_pages = nr_inactive_dirty_pages = -1;

	BZERO(ld, sizeof(struct list_data));
	ld->list_head_offset = OFFSET(page_lru);
	if (mi->flags & ADDRESS_SPECIFIED)
		ld->searchfor = mi->spec_addr;
	else if (mi->flags & VERBOSE)
		ld->flags |= VERBOSE;
	
	if (mi->flags & GET_ACTIVE_LIST) {
		if (!symbol_exists("active_list"))
			error(FATAL, 
			    "active_list does not exist in this kernel\n");

		if (symbol_exists("nr_active_pages"))
			get_symbol_data("nr_active_pages", sizeof(int), 
				&nr_active_pages);
		else
			error(FATAL, 
			    "nr_active_pages does not exist in this kernel\n");

		ld->end = symbol_value("active_list");
                readmem(ld->end, KVADDR, &ld->start, sizeof(void *),
                	"LIST_HEAD contents", FAULT_ON_ERROR);
		
		if (mi->flags & VERBOSE)
			fprintf(fp, "active_list:\n");

                if (ld->start == ld->end) {
                       c = 0;
                       ld->searchfor = 0;
                       if (mi->flags & VERBOSE)
                               fprintf(fp, "(empty)\n");
                } else {
                	hq_open();
                	c = do_list(ld);
                	hq_close();
		}

		if ((mi->flags & ADDRESS_SPECIFIED) && ld->searchfor) {
			fprintf(fp, "%lx\n", ld->searchfor);
			retval = TRUE;
                } else {
                        fprintf(fp, "%snr_active_pages: %d ", 
				mi->flags & VERBOSE ? "\n" : "",
                                nr_active_pages);
                        if (c != nr_active_pages)
                                fprintf(fp, "(found %d)\n", c);
                        else
                                fprintf(fp, "(verified)\n");
		}
	}

	if (mi->flags & GET_INACTIVE_LIST) {
		if (!symbol_exists("inactive_list"))
			error(FATAL, 
			    "inactive_list does not exist in this kernel\n");

		if (symbol_exists("nr_inactive_pages"))
			get_symbol_data("nr_inactive_pages", sizeof(int), 
				&nr_inactive_pages);
		else
			error(FATAL, 
			    "nr_active_pages does not exist in this kernel\n");

		ld->end = symbol_value("inactive_list");
                readmem(ld->end, KVADDR, &ld->start, sizeof(void *),
                	"LIST_HEAD contents", FAULT_ON_ERROR);
		
		if (mi->flags & VERBOSE)
			fprintf(fp, "inactive_list:\n");

                if (ld->start == ld->end) {
                       c = 0;
                       ld->searchfor = 0;
                       if (mi->flags & VERBOSE)
                               fprintf(fp, "(empty)\n");
                } else {
                	hq_open();
                	c = do_list(ld);
                	hq_close();
		}

		if ((mi->flags & ADDRESS_SPECIFIED) && ld->searchfor) {
			fprintf(fp, "%lx\n", ld->searchfor);
			retval = TRUE;
                } else {
                        fprintf(fp, "%snr_inactive_pages: %d ", 
				mi->flags & VERBOSE ? "\n" : "",
                                nr_inactive_pages);
                        if (c != nr_inactive_pages)
                                fprintf(fp, "(found %d)\n", c);
                        else
                                fprintf(fp, "(verified)\n");
		}
	}

        if (mi->flags & GET_INACTIVE_DIRTY) {
		if (!symbol_exists("inactive_dirty_list"))
			error(FATAL, 
		        "inactive_dirty_list does not exist in this kernel\n");

                if (symbol_exists("nr_inactive_dirty_pages"))
                        get_symbol_data("nr_inactive_dirty_pages", sizeof(int), 
                                &nr_inactive_dirty_pages);
		else
			error(FATAL,
                     "nr_inactive_dirty_pages does not exist in this kernel\n");

		ld->end = symbol_value("inactive_dirty_list");
                readmem(ld->end, KVADDR, &ld->start, sizeof(void *),
                	"LIST_HEAD contents", FAULT_ON_ERROR);

		if (mi->flags & VERBOSE)
			fprintf(fp, "%sinactive_dirty_list:\n",
				mi->flags & GET_ACTIVE_LIST ? "\n" : "");

                if (ld->start == ld->end) {
                       c = 0;
                       ld->searchfor = 0;
                       if (mi->flags & VERBOSE)
                               fprintf(fp, "(empty)\n");
                } else {
			hq_open();
        		c = do_list(ld);
        		hq_close();
		}

                if ((mi->flags & ADDRESS_SPECIFIED) && ld->searchfor) { 
                        fprintf(fp, "%lx\n", ld->searchfor);
			retval = TRUE;
		} else {
			fprintf(fp, "%snr_inactive_dirty_pages: %d ", 
				mi->flags & VERBOSE ? "\n" : "",
				nr_inactive_dirty_pages);
        		if (c != nr_inactive_dirty_pages)
                		fprintf(fp, "(found %d)\n", c);
        		else
                		fprintf(fp, "(verified)\n");
		}
        }

        if (mi->flags & GET_INACTIVE_CLEAN) {
		if (INVALID_OFFSET(zone_struct_inactive_clean_list))
			error(FATAL, 
		        "inactive_clean_list(s) do not exist in this kernel\n");

        	nr_zones = get_array_length("pglist_data.node_zones", NULL);

        	get_symbol_data("pgdat_list", sizeof(void *), &pgdat);

                if ((mi->flags & VERBOSE) && 
		    (mi->flags & (GET_ACTIVE_LIST|GET_INACTIVE_DIRTY)))
			fprintf(fp, "\n");

        	for (n = 0; pgdat; n++) {
                	nt = &vt->numa_table[n];

                	node_zones = nt->pgdat + OFFSET(pglist_data_node_zones);

                	for (i = 0; i < nr_zones; i++) {
                        	readmem(node_zones+OFFSET(zone_struct_name), 
					KVADDR, &value, sizeof(void *),
                                	"zone_struct name", FAULT_ON_ERROR);
                        	if (!read_string(value, buf, BUFSIZE-1))
                                	sprintf(buf, "(unknown) ");

                		if (mi->flags & VERBOSE) {
					if (vt->numnodes > 1)
                        			fprintf(fp, "NODE %d ", n);
                        		fprintf(fp, 
				            "\"%s\" inactive_clean_list:\n", 
						buf);
				}

				readmem(node_zones +
				    OFFSET(zone_struct_inactive_clean_pages),
                                    KVADDR, &inactive_clean_pages, 
				    sizeof(ulong), "inactive_clean_pages", 
				    FAULT_ON_ERROR);

                                readmem(node_zones +
                                    OFFSET(zone_struct_inactive_clean_list),
                                    KVADDR, &inactive_clean_list, 
                                    sizeof(ulong), "inactive_clean_list", 
                                    FAULT_ON_ERROR);

				ld->start = inactive_clean_list;
				ld->end = node_zones +
                                    OFFSET(zone_struct_inactive_clean_list);
        			if (mi->flags & ADDRESS_SPECIFIED)
                			ld->searchfor = mi->spec_addr;

				if (ld->start == ld->end) {
					c = 0;
					ld->searchfor = 0;
					if (mi->flags & VERBOSE)
						fprintf(fp, "(empty)\n");
				} else {
                			hq_open();
                			c = do_list(ld);
                			hq_close();
				}

		                if ((mi->flags & ADDRESS_SPECIFIED) && 
				    ld->searchfor) {
		                        fprintf(fp, "%lx\n", ld->searchfor);
		                        retval = TRUE;
		                } else {
					if (vt->numnodes > 1)
						fprintf(fp, "NODE %d ", n);
					fprintf(fp, "\"%s\" ", buf);
		                        fprintf(fp, 
					    "inactive_clean_pages: %ld ",
		                                inactive_clean_pages);
		                        if (c != inactive_clean_pages)
		                                fprintf(fp, "(found %d)\n", c);
		                        else
		                                fprintf(fp, "(verified)\n");
		                }

				node_zones += SIZE(zone_struct);
			}

                	readmem(pgdat + OFFSET(pglist_data_node_next), KVADDR,
                        	&pgdat, sizeof(void *), "pglist_data node_next",
                        	FAULT_ON_ERROR);
		}
        }

	return retval;
}



/*
 *  Check whether an address is a kmem_cache_t address, and if so, return
 *  a pointer to the static buffer containing its name string.  Otherwise
 *  return NULL on failure.
 */

#define PERCPU_NOT_SUPPORTED "per-cpu slab format not supported yet\n"

static char * 
is_kmem_cache_addr(ulong vaddr, char *kbuf)
{
        ulong cache, cache_cache, name;
	int name_len;
	long next_offset, name_offset;
	char *cache_buf;

        name_offset = vt->flags & PERCPU_KMALLOC ?
                OFFSET(kmem_cache_s_name) : OFFSET(kmem_cache_s_c_name);
        next_offset = vt->flags & PERCPU_KMALLOC ?
                OFFSET(kmem_cache_s_next) : OFFSET(kmem_cache_s_c_nextp);

        cache = cache_cache = symbol_value("cache_cache");

	cache_buf = GETBUF(SIZE(kmem_cache_s));

        do {
	        readmem(cache, KVADDR, cache_buf, SIZE(kmem_cache_s),
	        	"kmem_cache_s buffer", FAULT_ON_ERROR);

		if (cache == vaddr) {
		        name_len = vt->flags & PERCPU_KMALLOC ?
				get_array_length("kmem_cache_s.name", NULL) :
				get_array_length("kmem_cache_s.c_name", NULL);

	                if (name_len) {
				BCOPY(cache_buf+name_offset, kbuf, name_len);
	                } else {
				name = ULONG(cache_buf + name_offset);
	                        if (!read_string(name, kbuf, BUFSIZE-1)) {
					if (vt->flags & PERCPU_KMALLOC)
	                                	error(FATAL,
	                      "cannot read kmem_cache_s.name string at %lx\n",
	                                        	name);
					else
	                                	error(FATAL,
	                      "cannot read kmem_cache_s.c_name string at %lx\n",
	                                        	name);
				}
	                }
			FREEBUF(cache_buf);
			return kbuf;
		}

		cache = ULONG(cache_buf + next_offset);

		if (vt->flags & PERCPU_KMALLOC)
			cache -= next_offset;

        } while (cache != cache_cache);

	FREEBUF(cache_buf);
	return NULL;
}

/*
 *  Translate an address to its physical page number, verify that the
 *  page in fact belongs to the slab subsystem, and if so, return the 
 *  name of the cache to which it belongs.
 */
static char *
vaddr_to_kmem_cache(ulong vaddr, char *buf)
{
	ulong paddr;
	ulong page;
	ulong cache;

        if (!kvtop(NULL, vaddr, &paddr, 0)) {
		error(WARNING, 
		    "cannot make virtual-to-physical translation: %lx\n", 
			vaddr);
		return NULL;
	}

	if (!phys_to_page(paddr, &page)) {
		error(WARNING, "cannot find mem_map page for address: %lx\n", 
			vaddr);
		return NULL;
	}

	if (VALID_OFFSET(page_next))
                readmem(page+OFFSET(page_next),
                        KVADDR, &cache, sizeof(void *),
                        "page.next", FAULT_ON_ERROR);

	else if (VALID_OFFSET(page_list_next))
                readmem(page+OFFSET(page_list_next),
                        KVADDR, &cache, sizeof(void *),
                        "page.list.next", FAULT_ON_ERROR);
	else
		error(FATAL, "unknown definition of struct page?\n");

	return(is_kmem_cache_addr(cache, buf)); 
}

/*
 *  Translate an address to its physical page number, verify that the
 *  page in fact belongs to the slab subsystem, and if so, return the
 *  address of the slab to which it belongs.
 */
static ulong
vaddr_to_slab(ulong vaddr)
{
        ulong paddr;
        ulong page;
        ulong slab;

        if (!kvtop(NULL, vaddr, &paddr, 0)) {
                error(WARNING,
                    "cannot make virtual-to-physical translation: %lx\n",
                        vaddr);
                return 0;
        }

        if (!phys_to_page(paddr, &page)) {
                error(WARNING, "cannot find mem_map page for address: %lx\n",
                        vaddr);
                return 0;
        }

	slab = 0;

        if (VALID_OFFSET(page_prev))
                readmem(page+OFFSET(page_prev),
                        KVADDR, &slab, sizeof(void *),
                        "page.prev", FAULT_ON_ERROR);

        else if (VALID_OFFSET(page_list_prev))
                readmem(page+OFFSET(page_list_prev),
                        KVADDR, &slab, sizeof(void *),
                        "page.list.prev", FAULT_ON_ERROR);
        else
                error(FATAL, "unknown definition of struct page?\n");

	return slab;
}


/*
 *  Initialize any data required for scouring the kmalloc subsystem more
 *  efficiently.
 */
char slab_hdr[BUFSIZE] = { 0 };
char kmem_cache_hdr[BUFSIZE] = { 0 };
char free_inuse_hdr[BUFSIZE] = { 0 };

static void
kmem_cache_init(void)
{
	ulong cache, cache_cache, max_cnum, max_limit, max_cpus, tmp, tmp2;
	long cache_count, num_offset, next_offset;
	char *cache_buf;

	if (DUMPFILE() && vt->kmem_max_c_num)
		return; 

        if (!strlen(slab_hdr)) 
                sprintf(slab_hdr, 
		    "SLAB%sMEMORY%sTOTAL  ALLOCATED  FREE\n",
                        space(VADDR_PRLEN > 8 ? 14 : 6),
                        space(VADDR_PRLEN > 8 ? 12 : 4));

	if (!strlen(kmem_cache_hdr)) 
		sprintf(kmem_cache_hdr,
      "CACHE%sNAME                OBJSIZE  ALLOCATED     TOTAL  SLABS  SSIZE\n",
			space(VADDR_PRLEN > 8 ? 13 : 5));

	if (!strlen(free_inuse_hdr)) 
		sprintf(free_inuse_hdr, "FREE / [ALLOCATED]\n");

        cache = cache_cache = symbol_value("cache_cache");
	num_offset = vt->flags & PERCPU_KMALLOC ? 
		OFFSET(kmem_cache_s_num) : OFFSET(kmem_cache_s_c_num);
	next_offset = vt->flags & PERCPU_KMALLOC ?
		OFFSET(kmem_cache_s_next) : OFFSET(kmem_cache_s_c_nextp);
        max_cnum = max_limit = max_cpus = cache_count = 0;

	cache_buf = GETBUF(SIZE(kmem_cache_s));

        do {
		cache_count++;

                readmem(cache, KVADDR, cache_buf, SIZE(kmem_cache_s),
                        "kmem_cache_s buffer", FAULT_ON_ERROR);

		tmp = ULONG(cache_buf + num_offset);

                if (tmp > max_cnum)
                        max_cnum = tmp;

		if ((tmp = max_cpudata_limit(cache, &tmp2)) > max_limit)
			max_limit = tmp;

		if (tmp2 > max_cpus)
			max_cpus = tmp2;

		cache = ULONG(cache_buf + next_offset);

		if (vt->flags & PERCPU_KMALLOC)
			cache -= next_offset;

        } while (cache != cache_cache);

	FREEBUF(cache_buf);

	vt->kmem_max_c_num = max_cnum;
	vt->kmem_max_limit = max_limit;
	vt->kmem_max_cpus = max_cpus;
	vt->kmem_cache_count = cache_count;
}

/*
 *  Determine the largest cpudata limit for a given cache.
 */
static ulong
max_cpudata_limit(ulong cache, ulong *cpus)
{
	int i;
	ulong cpudata[NR_CPUS];
	int limit; 
	ulong max_limit;

	if (INVALID_OFFSET(kmem_cache_s_cpudata)) {
		*cpus = 0;
		return 0;
	}

	readmem(cache+OFFSET(kmem_cache_s_cpudata),
        	KVADDR, &cpudata[0], sizeof(ulong) * NR_CPUS,
                "cpudata array", FAULT_ON_ERROR);

	for (i = max_limit = 0; (i < NR_CPUS) && cpudata[i]; i++) {
		readmem(cpudata[i]+OFFSET(cpucache_s_limit),
        		KVADDR, &limit, sizeof(int),
                	"cpucache limit", FAULT_ON_ERROR);
		if (limit > max_limit)
			max_limit = limit;
	}

	*cpus = i;

	return max_limit;
}


/*
 *  dump_kmem_cache() displays basic information about kmalloc() slabs.
 *  At this point, only kmem_cache_s structure data for each slab is dumped.
 *
 *  TBD: Given a specified physical address, and determine which slab it came
 *  from, and whether it's in use or not.
 */

#define SLAB_C_MAGIC            0x4F17A36DUL
#define SLAB_MAGIC_ALLOC        0xA5C32F2BUL    /* slab is alive */
#define SLAB_MAGIC_DESTROYED    0xB2F23C5AUL    /* slab has been destroyed */

#define SLAB_CFLGS_BUFCTL       0x020000UL      /* bufctls in own cache */

#define KMEM_SLAB_ADDR          (1)
#define KMEM_BUFCTL_ADDR        (2)
#define KMEM_OBJECT_ADDR_FREE   (3)
#define KMEM_OBJECT_ADDR_INUSE  (4)
#define KMEM_OBJECT_ADDR_CACHED (5)
#define KMEM_ON_SLAB            (6)

#define DUMP_KMEM_CACHE_INFO() \
      {  \
	fprintf(fp, "%lx %-18s  %8ld  ", si->cache, buf, si->size); \
        fprintf(fp, "%9ld  %8ld  %5ld   %3ldk\n", \
		vt->flags & PERCPU_KMALLOC ? si->inuse - si->cpucached_cache : \
                si->inuse, si->num_slabs * si->c_num, \
                si->num_slabs, si->slabsize/1024); \
      }

#define DUMP_SLAB_INFO() \
      { \
	ulong allocated, freeobjs; \
        if (vt->flags & PERCPU_KMALLOC) { \
                allocated = si->s_inuse - si->cpucached_slab; \
                freeobjs = si->c_num - allocated - si->cpucached_slab; \
        } else { \
                allocated = si->s_inuse; \
                freeobjs = si->c_num - si->s_inuse; \
        } \
        fprintf(fp, "%lx  %lx  %5ld  %9ld  %4ld\n", \
		si->slab, si->s_mem, \
		si->c_num, allocated, \
		vt->flags & PERCPU_KMALLOC ? freeobjs + si->cpucached_slab : \
		freeobjs); \
      }  

static void
dump_kmem_cache(struct meminfo *si)
{
	char buf[BUFSIZE];
	char kbuf[BUFSIZE];
	char *reqname;
	ulong cache_cache;
	int c_name_len;
	ulong name, magic;
	int cnt;
	char *p1;

	if (vt->flags & PERCPU_KMALLOC) 
		error(FATAL, 
		    "dump_kmem_cache called with PERCPU_KMALLOC set\n");

	c_name_len = get_array_length("kmem_cache_s.c_name", NULL);
	si->found = si->retval = 0;
	reqname = NULL;

	if ((!(si->flags & VERBOSE) || si->reqname) &&
	     !(si->flags & (ADDRESS_SPECIFIED|GET_SLAB_PAGES)))
		fprintf(fp, kmem_cache_hdr);

	si->addrlist = (ulong *)GETBUF((vt->kmem_max_c_num+1) * sizeof(ulong));
	cnt = 0;
	si->cache = cache_cache = symbol_value("cache_cache");

	if (si->flags & ADDRESS_SPECIFIED) {
	        if (!(p1 = vaddr_to_kmem_cache(si->spec_addr, kbuf))) {
			error(INFO, 
			   "address is not allocated in slab subsystem: %lx\n",
				si->spec_addr);
			return;
		}
		
		if (si->reqname && (si->reqname != p1)) 
			error(INFO, 
			    "ignoring pre-selected %s cache for address: %lx\n",
				si->reqname, si->spec_addr, si->reqname);

		reqname = p1;
	} else
		reqname = si->reqname;

	si->cache_buf = GETBUF(SIZE(kmem_cache_s));

	do {
		if ((si->flags & VERBOSE) && !si->reqname &&
		    !(si->flags & ADDRESS_SPECIFIED))
			fprintf(fp, "%s%s", cnt++ ? "\n" : "", kmem_cache_hdr);

                readmem(si->cache, KVADDR, si->cache_buf, SIZE(kmem_cache_s),
                	"kmem_cache_s buffer", FAULT_ON_ERROR);

		if (c_name_len) {
			BCOPY(si->cache_buf + OFFSET(kmem_cache_s_c_name),
				buf, c_name_len);
		} else {
			name = ULONG(si->cache_buf + 
				OFFSET(kmem_cache_s_c_name));
                	if (!read_string(name, buf, BUFSIZE-1))
				error(FATAL, 
			      "cannot read kmem_cache_s.c_name string at %lx\n",
					name);
		}

		if (reqname && !STREQ(reqname, buf)) 
			goto next_cache;

		if (STREQ(si->ignore, buf)) {
			fprintf(fp, "%lx  %-19s [IGNORED]\n", si->cache, buf);
			goto next_cache;
		}

		si->curname = buf;

		if (MCLXDEBUG(1))
			fprintf(fp, "cache: %lx %s\n", si->cache, si->curname);
		console("cache: %lx %s\n", si->cache, si->curname);

		magic = ULONG(si->cache_buf + OFFSET(kmem_cache_s_c_magic));

		if (magic == SLAB_C_MAGIC) {

			si->size = ULONG(si->cache_buf + 
				OFFSET(kmem_cache_s_c_org_size));
			if (!si->size) {
				if (STREQ(si->curname, "kmem_cache"))
					si->size = SIZE(kmem_cache_s);
				else {
					error(INFO, 
					    "\"%s\" cache: c_org_size: %ld\n",
						si->curname, si->size);
					si->errors++;
				}
			}
			si->c_flags = ULONG(si->cache_buf +
				OFFSET(kmem_cache_s_c_flags));
			si->c_offset = ULONG(si->cache_buf + 
				OFFSET(kmem_cache_s_c_offset));
			si->order = ULONG(si->cache_buf + 
				OFFSET(kmem_cache_s_c_gfporder));
			si->c_num = ULONG(si->cache_buf +
				OFFSET(kmem_cache_s_c_num));

			do_slab_chain(SLAB_GET_COUNTS, si);

			if (!(si->flags & (ADDRESS_SPECIFIED|GET_SLAB_PAGES))) 
				DUMP_KMEM_CACHE_INFO();

			if (si->flags == GET_SLAB_PAGES) 
				si->retval += (si->num_slabs * 
				    	(si->slabsize/PAGESIZE()));

			if (si->flags & (VERBOSE|ADDRESS_SPECIFIED)) {
				si->slab = (si->flags & ADDRESS_SPECIFIED) ?
					vaddr_to_slab(si->spec_addr) : 0;
			
				do_slab_chain(SLAB_WALKTHROUGH, si);

				if (si->found) {
					fprintf(fp, kmem_cache_hdr);
					DUMP_KMEM_CACHE_INFO();
					fprintf(fp, slab_hdr);
					DUMP_SLAB_INFO();

					switch (si->found)
					{
					case KMEM_BUFCTL_ADDR:
						fprintf(fp, "   %lx ", 
							si->spec_addr);
						fprintf(fp, 
						   "(ON-SLAB kmem_bufctl_t)\n");
						break;

					case KMEM_SLAB_ADDR:
						fprintf(fp, "   %lx ", 
							si->spec_addr);
						fprintf(fp,
					            "(ON-SLAB kmem_slab_t)\n");
						break;

					case KMEM_ON_SLAB:
						fprintf(fp, "   %lx ", 
							si->spec_addr);
						fprintf(fp, 
						    "(unused part of slab)\n");
						break;
						
					case KMEM_OBJECT_ADDR_FREE:
                                                fprintf(fp, free_inuse_hdr);
						fprintf(fp, "   %lx\n", 
                                                        si->spec_addr);
						break;

                                        case KMEM_OBJECT_ADDR_INUSE:
                                                fprintf(fp, free_inuse_hdr);
                                                fprintf(fp, "  [%lx]\n",
                                                        si->spec_addr);
                                                break;
					}

					break;
				}
			}

		} else {
			error(INFO, "\"%s\" cache: invalid c_magic: %lx\n", 
				si->curname, magic);
			si->errors++;
		}

next_cache:
		si->cache = ULONG(si->cache_buf + OFFSET(kmem_cache_s_c_nextp));

	} while (si->cache != cache_cache);

	FREEBUF(si->cache_buf);

        if ((si->flags & ADDRESS_SPECIFIED) && !si->found)
		error(INFO, "%s: address not found in cache: %lx\n", 
			reqname, si->spec_addr);
 
	if (si->errors)
		error(INFO, "%ld error%s encountered\n", 
			si->errors, si->errors > 1 ? "s" : "");

	FREEBUF(si->addrlist);
}

/*
 *  dump_kmem_cache() adapted for newer percpu slab format.
 */

static void
dump_kmem_cache_percpu(struct meminfo *si)
{
	int i;
	char buf[BUFSIZE];
	char kbuf[BUFSIZE];
	char *reqname;
	ulong cache_cache;
	int name_len;
	ulong name;
	int cnt;
	char *p1;

        if (!(vt->flags & PERCPU_KMALLOC)) 
                error(FATAL, 
                    "dump_kmem_cache_percpu called without PERCPU_KMALLOC\n");

	name_len = get_array_length("kmem_cache_s.name", NULL);
	si->found = si->retval = 0;
	reqname = NULL;

	if ((!(si->flags & VERBOSE) || si->reqname) &&
	     !(si->flags & (ADDRESS_SPECIFIED|GET_SLAB_PAGES)))
		fprintf(fp, kmem_cache_hdr);

	si->addrlist = (ulong *)GETBUF((vt->kmem_max_c_num+1) * sizeof(ulong));
	si->kmem_bufctl = (int *)GETBUF((vt->kmem_max_c_num+1) * sizeof(int));
	for (i = 0; i < vt->kmem_max_cpus; i++) 
		si->cpudata[i] = (ulong *)
			GETBUF(vt->kmem_max_limit * sizeof(ulong)); 

	cnt = 0;
	si->cache = cache_cache = symbol_value("cache_cache");

	if (si->flags & ADDRESS_SPECIFIED) {
	        if (!(p1 = vaddr_to_kmem_cache(si->spec_addr, kbuf))) {
			error(INFO, 
			   "address is not allocated in slab subsystem: %lx\n",
				si->spec_addr);
			return;
		}
		
		if (si->reqname && (si->reqname != p1)) 
			error(INFO, 
			    "ignoring pre-selected %s cache for address: %lx\n",
				si->reqname, si->spec_addr, si->reqname);
		reqname = p1;
	} else
		reqname = si->reqname;

	do {
		if ((si->flags & VERBOSE) && !si->reqname &&
		    !(si->flags & ADDRESS_SPECIFIED))
			fprintf(fp, "%s%s", cnt++ ? "\n" : "", kmem_cache_hdr);

		if (name_len) {
                        readmem(si->cache+OFFSET(kmem_cache_s_name), 
				KVADDR, buf, name_len,
                                "name array", FAULT_ON_ERROR);
		} else {
                	readmem(si->cache+OFFSET(kmem_cache_s_name), 
				KVADDR, &name, sizeof(ulong),
                        	"name", FAULT_ON_ERROR);
                	if (!read_string(name, buf, BUFSIZE-1))
				error(FATAL, 
			      "cannot read kmem_cache_s.name string at %lx\n",
					name);
		}

		if (reqname && !STREQ(reqname, buf)) 
			goto next_cache;

                if (STREQ(si->ignore, buf)) {
                        fprintf(fp, "%lx  %-19s [IGNORED]\n", si->cache, buf);
                        goto next_cache;
                }

		si->curname = buf;

		if (MCLXDEBUG(1))
			fprintf(fp, "cache: %lx %s\n", si->cache, si->curname);

	        readmem(si->cache+OFFSET(kmem_cache_s_objsize),
	        	KVADDR, &si->size, sizeof(int),
	                "objsize", FAULT_ON_ERROR);
		if (!si->size) {
			if (STREQ(si->curname, "kmem_cache"))
				si->size = SIZE(kmem_cache_s);
			else {
				error(INFO, "\"%s\" cache: objsize: %ld\n",
					si->curname, si->size);
				si->errors++;
			}
		}

	        readmem(si->cache+OFFSET(kmem_cache_s_flags), 
			KVADDR, &si->c_flags, sizeof(ulong),
	                "kmem_cache_s flags", FAULT_ON_ERROR);

                readmem(si->cache+OFFSET(kmem_cache_s_gfporder),
                        KVADDR, &si->order, sizeof(int),
                        "gfporder", FAULT_ON_ERROR);

        	readmem(si->cache+OFFSET(kmem_cache_s_num),
                	KVADDR, &si->c_num, sizeof(int),
                	"kmem_cache_s num", FAULT_ON_ERROR);

		do_slab_chain_percpu(SLAB_GET_COUNTS, si);

		if (!(si->flags & (ADDRESS_SPECIFIED|GET_SLAB_PAGES))) 
			DUMP_KMEM_CACHE_INFO();

		if (si->flags == GET_SLAB_PAGES) 
			si->retval += (si->num_slabs * 
				(si->slabsize/PAGESIZE()));

		if (si->flags & (VERBOSE|ADDRESS_SPECIFIED)) {

			gather_cpudata_list(si);

                        si->slab = (si->flags & ADDRESS_SPECIFIED) ?
                        	vaddr_to_slab(si->spec_addr) : 0;

			do_slab_chain_percpu(SLAB_WALKTHROUGH, si);

			if (si->found) {
				fprintf(fp, kmem_cache_hdr);
				DUMP_KMEM_CACHE_INFO();
				fprintf(fp, slab_hdr);
        			gather_slab_cached_count(si);
				DUMP_SLAB_INFO();

				switch (si->found)
				{
				case KMEM_BUFCTL_ADDR:
					fprintf(fp, "   %lx ", si->spec_addr);
					fprintf(fp,"(kmem_bufctl_t)\n");
					break;

				case KMEM_SLAB_ADDR:
					fprintf(fp, "   %lx ", si->spec_addr);
					fprintf(fp, "(slab_s)\n");
					break;

				case KMEM_ON_SLAB:
					fprintf(fp, "   %lx ", si->spec_addr);
					fprintf(fp, "(unused part of slab)\n");
					break;
						
				case KMEM_OBJECT_ADDR_FREE:
                                        fprintf(fp, free_inuse_hdr);
					fprintf(fp, "   %lx\n", si->spec_addr);
					break;

                                case KMEM_OBJECT_ADDR_INUSE:
                                        fprintf(fp, free_inuse_hdr);
                                        fprintf(fp, "  [%lx]\n", si->spec_addr);
                                        break;

                                case KMEM_OBJECT_ADDR_CACHED:
                                        fprintf(fp, free_inuse_hdr);
                                        fprintf(fp, 
					    "   %lx  (cpu %d cache)\n", 
						si->spec_addr, si->cpu);
                                        break;
				}

				break;
			}
		}

next_cache:
                readmem(si->cache+OFFSET(kmem_cache_s_next), 
		        KVADDR, &si->cache, sizeof(ulong),
                        "kmem_cache_s next", FAULT_ON_ERROR);

		si->cache -= OFFSET(kmem_cache_s_next);

	} while (si->cache != cache_cache);

        if ((si->flags & ADDRESS_SPECIFIED) && !si->found)
		error(INFO, "%s: address not found in cache: %lx\n", 
			reqname, si->spec_addr);
 
	if (si->errors)
		error(INFO, "%ld error%s encountered\n", 
			si->errors, si->errors > 1 ? "s" : "");

	FREEBUF(si->addrlist);
	FREEBUF(si->kmem_bufctl);
        for (i = 0; i < vt->kmem_max_cpus; i++)
                FREEBUF(si->cpudata[i]);

}



/*
 *  Walk through the slab chain hanging off a kmem_cache_s structure,
 *  gathering basic statistics.
 *
 *  TBD: Given a specified physical address, determine whether it's in this
 *  slab chain, and whether it's in use or not.
 */

#define INSLAB(obj, si) \
  ((ulong)((ulong)(obj) & ~(si->slabsize-1)) == si->s_mem)

static void
do_slab_chain(int cmd, struct meminfo *si)
{
	ulong tmp, magic;
	ulong kmem_slab_end;
	char *kmem_slab_s_buf;

	si->slabsize = (power(2, si->order) * PAGESIZE());

	kmem_slab_end = si->cache + OFFSET(kmem_cache_s_c_offset);

	switch (cmd)
	{
	case SLAB_GET_COUNTS:
		si->slab = ULONG(si->cache_buf + OFFSET(kmem_cache_s_c_firstp));

		if (slab_data_saved(si))
			return;

		si->num_slabs = si->inuse = 0;

		if (si->slab == kmem_slab_end)
			return;

		kmem_slab_s_buf = GETBUF(SIZE(kmem_slab_s));

		do {
			if (received_SIGINT()) {
				FREEBUF(kmem_slab_s_buf);
				restart(0);
			}

			readmem(si->slab, KVADDR, kmem_slab_s_buf,
				SIZE(kmem_slab_s), "kmem_slab_s buffer",
				FAULT_ON_ERROR);

			magic = ULONG(kmem_slab_s_buf +
				OFFSET(kmem_slab_s_s_magic));

			if (magic == SLAB_MAGIC_ALLOC) {
	
				tmp = ULONG(kmem_slab_s_buf +
					OFFSET(kmem_slab_s_s_inuse));
	
				si->inuse += tmp;
				si->num_slabs++;
			} else {
				fprintf(fp, 
			   	    "\"%s\" cache: invalid s_magic: %lx\n", 
					si->curname, magic);
				si->errors++;
				FREEBUF(kmem_slab_s_buf);
				return;
			}
	
			si->slab = ULONG(kmem_slab_s_buf +
				OFFSET(kmem_slab_s_s_nextp));
	
		} while (si->slab != kmem_slab_end);
		
		FREEBUF(kmem_slab_s_buf);
		save_slab_data(si);
		break;

	case SLAB_WALKTHROUGH:
        	if (!si->slab)
			si->slab = ULONG(si->cache_buf + 
				OFFSET(kmem_cache_s_c_firstp));

		if (si->slab == kmem_slab_end)
			return;

		if (MCLXDEBUG(1)) {
			fprintf(fp, "search cache: [%s] ", si->curname);
			if (si->flags & ADDRESS_SPECIFIED) 
				fprintf(fp, "for %lx", si->spec_addr);
			fprintf(fp, "\n");
		}

		si->slab_buf = kmem_slab_s_buf = GETBUF(SIZE(kmem_slab_s));

	        do {
                        if (received_SIGINT()) {
				FREEBUF(kmem_slab_s_buf);
                                restart(0);
			}

			readmem(si->slab, KVADDR, kmem_slab_s_buf,
				SIZE(kmem_slab_s), "kmem_slab_s buffer",
				FAULT_ON_ERROR);

	                dump_slab(si);
	
	                if (si->found) {
				FREEBUF(kmem_slab_s_buf);
	                        return;
			}
	
			si->slab = ULONG(kmem_slab_s_buf +
				OFFSET(kmem_slab_s_s_nextp));
	
	        } while (si->slab != kmem_slab_end);

		FREEBUF(kmem_slab_s_buf);
		break;
	}
}


/*
 *  do_slab_chain() adapted for newer percpu slab format.
 */

#define SLAB_BASE(X) (PTOB(BTOP(X)))

#define INSLAB_PERCPU(obj, si) \
  ((ulong)((ulong)(obj) & ~(si->slabsize-1)) == SLAB_BASE(si->s_mem))

#define SLAB_CHAINS (3)

static void
do_slab_chain_percpu(long cmd, struct meminfo *si)
{
	int tmp, s;
	char *slab_s_buf;
	ulong specified_slab;
	ulong slab_chains[SLAB_CHAINS];

	si->slabsize = (power(2, si->order) * PAGESIZE());
	si->cpucached_slab = 0;

	if (VALID_OFFSET(kmem_cache_s_slabs)) {
		slab_chains[0] = si->cache + OFFSET(kmem_cache_s_slabs);
		slab_chains[1] = 0;
		slab_chains[2] = 0;
	} else {
		slab_chains[0] = si->cache + OFFSET(kmem_cache_s_slabs_full);
		slab_chains[1] = si->cache + OFFSET(kmem_cache_s_slabs_partial);
		slab_chains[2] = si->cache + OFFSET(kmem_cache_s_slabs_free);
	}

	switch (cmd)
	{
	case SLAB_GET_COUNTS:
		si->flags |= SLAB_GET_COUNTS;
		si->flags &= ~SLAB_WALKTHROUGH;
		si->cpucached_cache = 0;
        	si->num_slabs = si->inuse = 0;

		slab_s_buf = GETBUF(SIZE(slab_s));

		for (s = 0; s < SLAB_CHAINS; s++) {
			if (!slab_chains[s])
				continue;

	                readmem(slab_chains[s],
	                        KVADDR, &si->slab, sizeof(ulong),
	                        "first slab", FAULT_ON_ERROR);
	
			if (slab_data_saved(si)) {
				FREEBUF(slab_s_buf);
				return;
			}
	
			if (si->slab == slab_chains[s]) 
				continue;
	
			do {
	                        if (received_SIGINT()) {
					FREEBUF(slab_s_buf);
	                                restart(0);
				}
	
		                readmem(si->slab, KVADDR, slab_s_buf, 
					SIZE(slab_s), "slab_s buffer", 
					FAULT_ON_ERROR);
	
				tmp = INT(slab_s_buf + OFFSET(slab_s_inuse));
				si->inuse += tmp;
	
				gather_cpudata_list(si);
				si->s_mem = ULONG(slab_s_buf + 
					OFFSET(slab_s_s_mem));
				gather_slab_cached_count(si);
	
				si->num_slabs++;
		
				si->slab = ULONG(slab_s_buf + 
					OFFSET(slab_s_list));
				si->slab -= OFFSET(slab_s_list);
		
			} while (si->slab != slab_chains[s]);
		}

		FREEBUF(slab_s_buf);
		save_slab_data(si);
		break;

	case SLAB_WALKTHROUGH:
		specified_slab = si->slab;
		si->flags |= SLAB_WALKTHROUGH;
		si->flags &= ~SLAB_GET_COUNTS;

		for (s = 0; s < SLAB_CHAINS; s++) {
			if (!slab_chains[s])
				continue;

	        	if (!specified_slab) {
	                	readmem(slab_chains[s],
	                        	KVADDR, &si->slab, sizeof(ulong),
	                        	"slabs", FAULT_ON_ERROR);
			}
	
			if (si->slab == slab_chains[s])
				continue;
	
			if (MCLXDEBUG(1)) {
				fprintf(fp, "search cache: [%s] ", si->curname);
				if (si->flags & ADDRESS_SPECIFIED) 
					fprintf(fp, "for %lx", si->spec_addr);
				fprintf(fp, "\n");
			}
	
		        do {
	                        if (received_SIGINT())
	                                restart(0);
	
		                dump_slab_percpu(si);
		
		                if (si->found) {
					return;
				}
		
		                readmem(si->slab+OFFSET(slab_s_list),
		                        KVADDR, &si->slab, sizeof(ulong),
		                        "slab list", FAULT_ON_ERROR);
		
				si->slab -= OFFSET(slab_s_list);
	
		        } while (si->slab != slab_chains[s]);
		}

		break;
	}
}

/*
 *  If it's a dumpfile, save the essential slab data to avoid re-reading 
 *  the whole slab chain more than once.  This may seem like overkill, but
 *  if the problem is a memory leak, or just the over-use of the buffer_head
 *  cache, it's painful to wait each time subsequent kmem -s or -i commands
 *  simply need the basic slab counts.
 */
struct slab_data {
	ulong cache_addr;
	int num_slabs;
	int inuse;
	ulong cpucached_cache;
};

#define NO_SLAB_DATA ((void *)(-1))

static void 
save_slab_data(struct meminfo *si)
{
	int i;

	if (ACTIVE())
		return;

	if (vt->slab_data == NO_SLAB_DATA)
		return;

	if (!vt->slab_data) {
        	if (!(vt->slab_data = (struct slab_data *)
            	    malloc(sizeof(struct slab_data) * vt->kmem_cache_count))) {
                	error(INFO, "cannot malloc slab_data table");
			vt->slab_data = NO_SLAB_DATA;
			return;
		}
		for (i = 0; i < vt->kmem_cache_count; i++) {
			vt->slab_data[i].cache_addr = (ulong)NO_SLAB_DATA;
			vt->slab_data[i].num_slabs = 0;
			vt->slab_data[i].inuse = 0;
			vt->slab_data[i].cpucached_cache = 0;
		}
	}

	for (i = 0; i < vt->kmem_cache_count; i++) {
		if (vt->slab_data[i].cache_addr == si->cache) 
			break;

		if (vt->slab_data[i].cache_addr == (ulong)NO_SLAB_DATA) {
			vt->slab_data[i].cache_addr = si->cache; 
			vt->slab_data[i].num_slabs = si->num_slabs; 
			vt->slab_data[i].inuse = si->inuse; 
			vt->slab_data[i].cpucached_cache = si->cpucached_cache;
			break;
		}
	}
}

static int 
slab_data_saved(struct meminfo *si)
{
	int i;

	if (ACTIVE() || !vt->slab_data || (vt->slab_data == NO_SLAB_DATA)) 
		return FALSE;

	for (i = 0; i < vt->kmem_cache_count; i++) {
		if (vt->slab_data[i].cache_addr == si->cache) {
			si->inuse = vt->slab_data[i].inuse;
			si->num_slabs = vt->slab_data[i].num_slabs;
			si->cpucached_cache = vt->slab_data[i].cpucached_cache;
			return TRUE;
		}
	}

	return FALSE;
}

static void
dump_saved_slab_data(void)
{
	int i;

	if (!vt->slab_data || (vt->slab_data == NO_SLAB_DATA))
		return;

	for (i = 0; i < vt->kmem_cache_count; i++) {
		if (vt->slab_data[i].cache_addr == (ulong)NO_SLAB_DATA)
			break;

		fprintf(fp, 
                "  cache: %lx inuse: %5d num_slabs: %3d cpucached_cache: %ld\n",
			vt->slab_data[i].cache_addr,
			vt->slab_data[i].inuse,
			vt->slab_data[i].num_slabs,
			vt->slab_data[i].cpucached_cache);
	}
}

/*
 *  Dump the contents of a kmem slab.
 */

static void
dump_slab(struct meminfo *si)
{
	uint16_t s_offset;

	si->s_mem = ULONG(si->slab_buf + OFFSET(kmem_slab_s_s_mem));
	si->s_mem = PTOB(BTOP(si->s_mem));

        if (si->flags & ADDRESS_SPECIFIED)  {
                if (INSLAB(si->slab, si) && (si->spec_addr >= si->slab) &&
                    (si->spec_addr < (si->slab+SIZE(kmem_slab_s)))){
                	si->found = KMEM_SLAB_ADDR;
                        return;
                }
		if (INSLAB(si->spec_addr, si))
			si->found = KMEM_ON_SLAB;  /* But don't return yet... */
		else
			return;
        }

	si->s_freep = VOID_PTR(si->slab_buf + OFFSET(kmem_slab_s_s_freep));
	si->s_inuse = ULONG(si->slab_buf + OFFSET(kmem_slab_s_s_inuse));
	si->s_index = ULONG_PTR(si->slab_buf + OFFSET(kmem_slab_s_s_index));
	s_offset = USHORT(si->slab_buf + OFFSET(kmem_slab_s_s_offset));

	if (!(si->flags & ADDRESS_SPECIFIED)) {
		fprintf(fp, slab_hdr);
		DUMP_SLAB_INFO();
	}

	dump_slab_objects(si);
}

/*
 *  dump_slab() adapted for newer percpu slab format.
 */

static void
dump_slab_percpu(struct meminfo *si)
{
	int tmp;

        readmem(si->slab+OFFSET(slab_s_s_mem),
                KVADDR, &si->s_mem, sizeof(ulong),
                "s_mem", FAULT_ON_ERROR);

	/*
	 * Include the array of kmem_bufctl_t's appended to slab.
	 */
	tmp = SIZE(slab_s) + (SIZE(kmem_bufctl_t) * si->c_num);

        if (si->flags & ADDRESS_SPECIFIED)  {
                if (INSLAB_PERCPU(si->slab, si) && 
		    (si->spec_addr >= si->slab) &&
                    (si->spec_addr < (si->slab+tmp))) {
			if (si->spec_addr >= (si->slab + SIZE(slab_s)))
				si->found = KMEM_BUFCTL_ADDR;
			else
                		si->found = KMEM_SLAB_ADDR;
                        return;
                }
		if (INSLAB_PERCPU(si->spec_addr, si))
			si->found = KMEM_ON_SLAB;  /* But don't return yet... */
		else
			return;
        }

        readmem(si->slab+OFFSET(slab_s_inuse),
                KVADDR, &tmp, sizeof(int),
                "inuse", FAULT_ON_ERROR);
	si->s_inuse = tmp;

        readmem(si->slab+OFFSET(slab_s_free),
                KVADDR, &si->free, SIZE(kmem_bufctl_t),
                "kmem_bufctl_t", FAULT_ON_ERROR);

	gather_slab_free_list_percpu(si);
	gather_slab_cached_count(si);

	if (!(si->flags & ADDRESS_SPECIFIED)) {
		fprintf(fp, slab_hdr);
		DUMP_SLAB_INFO();
	}

	dump_slab_objects_percpu(si);
}



/*
 *  Gather the free objects in a slab into the si->addrlist, checking for
 *  specified addresses that are in-slab kmem_bufctls, and making error checks 
 *  along the way.  Object address checks are deferred to dump_slab_objects().
 */

#define INOBJECT(addr, obj) ((addr >= obj) && (addr < (obj+si->size)))

static void
gather_slab_free_list(struct meminfo *si)
{
	ulong *next, obj;
	ulong expected, cnt;

	BNEG(si->addrlist, sizeof(ulong) * (si->c_num+1));

	if (!si->s_freep)
		return;

	cnt = 0;
	expected = si->c_num - si->s_inuse;

	next = si->s_freep; 
	do {

		if (cnt == si->c_num) {
			error(INFO, 
		     "\"%s\" cache: too many objects found in slab free list\n",
				si->curname);
			si->errors++;
			return;
		}

		/*
                 *  Off-slab kmem_bufctls are contained in arrays of object 
		 *  pointers that point to:
	         *    1. next kmem_bufctl (or NULL) if the object is free.
	         *    2. to the object if it the object is in use.
                 *
	 	 *  On-slab kmem_bufctls resides just after the object itself,
	         *  and point to:
	         *    1. next kmem_bufctl (or NULL) if object is free.
	         *    2. the containing slab if the object is in use.
		 */

	        if (si->c_flags & SLAB_CFLGS_BUFCTL) 
                	obj = si->s_mem + ((next - si->s_index) * si->c_offset);
		else 
			obj = (ulong)next - si->c_offset;

		si->addrlist[cnt] = obj; 

		if (si->flags & ADDRESS_SPECIFIED) {
			if (INSLAB(next, si) && 
		            (si->spec_addr >= (ulong)next) &&
			    (si->spec_addr < (ulong)(next + 1))) {
				si->found = KMEM_BUFCTL_ADDR;
				return;
			}
		}

		cnt++;

		if (!INSLAB(obj, si)) {
			error(INFO, 
		       "\"%s\" cache: address not contained within slab: %lx\n",
				si->curname, obj);
			si->errors++;
		}

        	readmem((ulong)next, KVADDR, &next, sizeof(void *),
                	"s_freep chain entry", FAULT_ON_ERROR);
	} while (next); 

	if (cnt != expected) {
		error(INFO, 
	       "\"%s\" cache: free object mismatch: expected: %ld found: %ld\n",
			si->curname, expected, cnt); 
		si->errors++;
	}
}


/*
 *  gather_slab_free_list() adapted for newer percpu slab format.
 */

#define BUFCTL_END 0xffffFFFF

static void
gather_slab_free_list_percpu(struct meminfo *si)
{
	int i;
	ulong obj;
	ulong expected, cnt;
	int free_index;
	ulong kmembp;

	BNEG(si->addrlist, sizeof(ulong) * (si->c_num+1));

	if (si->s_inuse == si->c_num )
		return;

	kmembp = si->slab + SIZE(slab_s);
        readmem((ulong)kmembp, KVADDR, si->kmem_bufctl, 
		SIZE(kmem_bufctl_t) * si->c_num,
                "kmem_bufctl array", FAULT_ON_ERROR);

	if (MCLXDEBUG(1)) {
		for (i = 0; i < si->c_num; i++)
			fprintf(fp, "%d ", si->kmem_bufctl[i]);
		fprintf(fp, "\n");
	}

	cnt = 0;
	expected = si->c_num - si->s_inuse;

	for (free_index = si->free; free_index != BUFCTL_END;
	     free_index = si->kmem_bufctl[free_index]) {

                if (cnt == si->c_num) {
                        error(INFO,
                     "\"%s\" cache: too many objects found in slab free list\n",
                                si->curname);
                        si->errors++;
                        return;
                }

		obj = si->s_mem + (free_index*si->size);
		si->addrlist[cnt] = obj; 
		cnt++;
	}

	if (cnt != expected) {
		error(INFO, 
	       "\"%s\" cache: free object mismatch: expected: %ld found: %ld\n",
			si->curname, expected, cnt); 
		si->errors++;
	}
}



/*
 *  Dump the FREE, [ALLOCATED] and <CACHED> objects of a slab.
 */  

#define DUMP_SLAB_OBJECT() \
        for (j = on_free_list = 0; j < si->c_num; j++) {	\
                if (obj == si->addrlist[j]) {			\
                        on_free_list = TRUE;			\
                        break;					\
                }						\
        }							\
								\
        if (on_free_list) {					\
                if (!(si->flags & ADDRESS_SPECIFIED))		\
                        fprintf(fp, "   %lx\n", obj);		\
                if (si->flags & ADDRESS_SPECIFIED) {		\
                        if (INOBJECT(si->spec_addr, obj)) {	\
                                si->found =			\
                                    KMEM_OBJECT_ADDR_FREE;	\
                                return;				\
                        }					\
                }						\
        } else {						\
                if (!(si->flags & ADDRESS_SPECIFIED))		\
                        fprintf(fp, "  [%lx]\n", obj);		\
                cnt++;						\
                if (si->flags & ADDRESS_SPECIFIED) {		\
                        if (INOBJECT(si->spec_addr, obj)) {	\
                                si->found =			\
                                    KMEM_OBJECT_ADDR_INUSE;	\
                                return;				\
                        }					\
                }						\
        }

static void
dump_slab_objects(struct meminfo *si)
{
	int i, j;
	ulong *next;
	int on_free_list; 
	ulong cnt, expected;
	ulong bufctl, obj;

	gather_slab_free_list(si);

	if ((si->flags & ADDRESS_SPECIFIED) && (si->found & ~KMEM_ON_SLAB))
		return;

        cnt = 0;
        expected = si->s_inuse;

        if (MCLXDEBUG(1))
                for (i = 0; i < si->c_num; i++) {
                        fprintf(fp, "si->addrlist[%d]: %lx\n", 
				i, si->addrlist[i]);
                }

        if (!(si->flags & ADDRESS_SPECIFIED)) 
		fprintf(fp, free_inuse_hdr);

        /* For on-slab bufctls, c_offset is the distance between the start of
         * an obj and its related bufctl.  For off-slab bufctls, c_offset is
         * the distance between objs in the slab.
         */

        if (si->c_flags & SLAB_CFLGS_BUFCTL) {
		for (i = 0, next = si->s_index; i < si->c_num; i++, next++){
                	obj = si->s_mem + 
				((next - si->s_index) * si->c_offset);
			DUMP_SLAB_OBJECT();
		}
	} else {
		/*
		 *  Get the "real" s_mem, i.e., without the offset stripped off.
		 *  It contains the address of the first object.
		 */
        	readmem(si->slab+OFFSET(kmem_slab_s_s_mem),
                	KVADDR, &obj, sizeof(ulong),
                	"s_mem", FAULT_ON_ERROR);

		for (i = 0; i < si->c_num; i++) {
			DUMP_SLAB_OBJECT();

                	if (si->flags & ADDRESS_SPECIFIED) {
				bufctl = obj + si->c_offset;

                        	if ((si->spec_addr >= bufctl) &&
                                    (si->spec_addr < 
				    (bufctl + SIZE(kmem_bufctl_t)))) {
                                	si->found = KMEM_BUFCTL_ADDR;
                                	return;
                        	}
                	}

			obj += (si->c_offset + SIZE(kmem_bufctl_t));
		}
	}

        if (cnt != expected) {
                error(INFO,
              "\"%s\" cache: inuse object mismatch: expected: %ld found: %ld\n",
                        si->curname, expected, cnt);
                si->errors++;
        }

}


/*
 *  dump_slab_objects() adapted for newer percpu slab format.
 */

static void
dump_slab_objects_percpu(struct meminfo *si)
{
	int i, j;
	int on_free_list, on_cpudata_list; 
	ulong cnt, expected;
	ulong obj;

	if ((si->flags & ADDRESS_SPECIFIED) && (si->found & ~KMEM_ON_SLAB))
		return;

        cnt = 0;
        expected = si->s_inuse;

        if (MCLXDEBUG(1))
                for (i = 0; i < si->c_num; i++) {
                        fprintf(fp, "si->addrlist[%d]: %lx\n", 
				i, si->addrlist[i]);
                }

        if (!(si->flags & ADDRESS_SPECIFIED)) 
		fprintf(fp, free_inuse_hdr);

	for (i = 0, obj = si->s_mem; i < si->c_num; i++, obj += si->size) {
		on_free_list = FALSE;
		on_cpudata_list = FALSE;

	        for (j = 0; j < si->c_num; j++) {        
	                if (obj == si->addrlist[j]) {                   
	                        on_free_list = TRUE;                    
	                        break;                                  
	                }                                               
	        }                                                       

		on_cpudata_list = check_cpudata_list(si, obj);

		if (on_free_list && on_cpudata_list) {
			error(INFO, 
		    "\"%s\" cache: object %lx on both free and cpudata lists\n",
				si->curname, obj);
			si->errors++;
		}
	                                                               
	        if (on_free_list) {                                     
	                if (!(si->flags & ADDRESS_SPECIFIED))           
	                        fprintf(fp, "   %lx\n", obj);           
	                if (si->flags & ADDRESS_SPECIFIED) {            
	                        if (INOBJECT(si->spec_addr, obj)) {     
	                                si->found =                     
	                                    KMEM_OBJECT_ADDR_FREE;      
	                                return;                         
	                        }                                       
	                }                                               
		} else if (on_cpudata_list) {
                        if (!(si->flags & ADDRESS_SPECIFIED))
                                fprintf(fp, "   %lx  (cpu %d cache)\n", obj,
					si->cpu);
                        cnt++;    
                        if (si->flags & ADDRESS_SPECIFIED) {
                                if (INOBJECT(si->spec_addr, obj)) {
                                        si->found =
                                            KMEM_OBJECT_ADDR_CACHED;
                                        return;
                                } 
                        }
	        } else {                                                
	                if (!(si->flags & ADDRESS_SPECIFIED))           
	                        fprintf(fp, "  [%lx]\n", obj);          
	                cnt++;                                          
	                if (si->flags & ADDRESS_SPECIFIED) {            
	                        if (INOBJECT(si->spec_addr, obj)) {     
	                                si->found =                     
	                                    KMEM_OBJECT_ADDR_INUSE;     
	                                return;                         
	                        }                                       
	                }                                               
	        }
	}

        if (cnt != expected) {
                error(INFO,
              "\"%s\" cache: inuse object mismatch: expected: %ld found: %ld\n",
                        si->curname, expected, cnt);
                si->errors++;
        }
}

/*
 *  Determine how many of the "inuse" slab objects are actually cached
 *  in the kmem_cache_s header.  Set the per-slab count and update the 
 *  cumulative per-cache count.
 */

static void
gather_slab_cached_count(struct meminfo *si)
{
	int i;
	ulong obj;

	si->cpucached_slab = 0;

        for (i = 0, obj = si->s_mem; i < si->c_num; i++, obj += si->size) {
		if (check_cpudata_list(si, obj)) {
			si->cpucached_slab++;
			if (si->flags & SLAB_GET_COUNTS) {
				si->cpucached_cache++;
			}
		}
	}
}

/*
 *  Populate the percpu object list for a given slab.
 */

static void
gather_cpudata_list(struct meminfo *si)
{
        int i, j;
	int avail;
        ulong cpudata[NR_CPUS];

        if (INVALID_OFFSET(kmem_cache_s_cpudata))
                return;

        readmem(si->cache+OFFSET(kmem_cache_s_cpudata),
                KVADDR, &cpudata[0], sizeof(ulong) * NR_CPUS,
                "cpudata array", FAULT_ON_ERROR);

        for (i = 0; (i < NR_CPUS) && cpudata[i]; i++) {
		BZERO(si->cpudata[i], sizeof(ulong) * vt->kmem_max_limit);

                readmem(cpudata[i]+OFFSET(cpucache_s_avail),
                        KVADDR, &avail, sizeof(int),
                        "cpucache avail", FAULT_ON_ERROR);

		if (!avail) 
			continue;

		if (avail > vt->kmem_max_limit) {
			error(INFO, 
	  	  "\"%s\" cache: cpucache_s.avail %d greater than limit %ld\n",
				si->curname, avail, vt->kmem_max_limit);
			si->errors++;
		}

		if (MCLXDEBUG(1))
			fprintf(fp, "%s: cpu[%d] avail: %d\n", 
				si->curname, i, avail);

                readmem(cpudata[i]+SIZE(cpucache_s),
                        KVADDR, si->cpudata[i],
			sizeof(void *) * avail,
                        "cpucache avail", FAULT_ON_ERROR);

		if (MCLXDEBUG(1))
			for (j = 0; j < avail; j++)
				fprintf(fp, "  %lx\n", si->cpudata[i][j]);
        }
}

/*
 *  Check whether a given address is contained in the previously-gathered
 *  percpu object cache.
 */

static int
check_cpudata_list(struct meminfo *si, ulong obj)
{
        int i, j;

        for (i = 0; i < vt->kmem_max_cpus; i++) {
                for (j = 0; si->cpudata[i][j]; j++)
			if (si->cpudata[i][j] == obj) {
				si->cpu = i;
				return TRUE;
			}
	}

	return FALSE;
}


/*
 *  Search the various memory subsystems for instances of this address.
 *  Start with the most specific areas, ending up with at least the 
 *  mem_map page data.
 */
static void
kmem_search(struct meminfo *mi)
{
	struct syment *sp;
	struct meminfo tmp_meminfo;
	char buf[BUFSIZE];
	ulong vaddr, paddr, orig_flags;
	off_t offset;

	switch (mi->memtype)
	{
	case KVADDR:
		vaddr = mi->spec_addr;
		break;

	case PHYSADDR:
		vaddr = mi->spec_addr < VTOP(vt->high_memory) ?
			PTOV(mi->spec_addr) : BADADDR;
		break;
	}

	orig_flags = mi->flags;
	mi->retval = 0;

	/*
	 *  Check first for a possible symbolic display of the virtual
	 *  address associated with mi->spec_addr or PTOV(mi->spec_addr).
	 */
	if (((vaddr >= kt->stext) && (vaddr <= kt->end)) ||
	    IS_MODULE_VADDR(mi->spec_addr)) {
		if ((sp = value_search(vaddr, &offset))) {
			show_symbol(sp, offset, SHOW_LINENUM | SHOW_RADIX());
			fprintf(fp, "\n");
		}
	}

	/*
	 *  Check for a valid mapped address.
	 */
	if ((mi->memtype == KVADDR) && IS_VMALLOC_ADDR(mi->spec_addr)) {
		if (kvtop(NULL, mi->spec_addr, &paddr, 0)) {
			mi->flags = orig_flags;
        		dump_vmlist(mi);
			fprintf(fp, "\n");
			mi->spec_addr = paddr;
			mi->memtype = PHYSADDR;
		}
		goto mem_map;
	}
	/*
	 *  If the address is physical, check whether it's in vmalloc space.
	 */

	if (mi->memtype == PHYSADDR) {
		mi->flags = orig_flags;
		mi->flags |= GET_PHYS_TO_VMALLOC;
		mi->retval = 0;
        	dump_vmlist(mi);
		mi->flags &= ~GET_PHYS_TO_VMALLOC;

		if (mi->retval) {
			if ((sp = value_search(mi->retval, &offset))) {
                        	show_symbol(sp, offset, 
					SHOW_LINENUM | SHOW_RADIX());
                        	fprintf(fp, "\n");
                	}
        		dump_vmlist(mi);
			fprintf(fp, "\n");
			goto mem_map;
		}
	}

	/*
         *  Check whether the containing page belongs to the slab subsystem.
	 */
	mi->flags = orig_flags;
	mi->retval = 0;
	if ((vaddr != BADADDR) && vaddr_to_kmem_cache(vaddr, buf)) {
		BZERO(&tmp_meminfo, sizeof(struct meminfo));
		tmp_meminfo.spec_addr = vaddr;
		tmp_meminfo.memtype = KVADDR;
		tmp_meminfo.flags = mi->flags;
		vt->dump_kmem_cache(&tmp_meminfo);
		fprintf(fp, "\n");
	}

	/*
	 *  Check free list.
	 */
	mi->flags = orig_flags;
	mi->retval = 0;
	vt->dump_free_pages(mi);
	if (mi->retval)
		fprintf(fp, "\n");

	/*
	 *  Check the page cache.
	 */
	mi->flags = orig_flags;
	mi->retval = 0;
	dump_page_hash_table(mi);
	if (mi->retval)
		fprintf(fp, "\n");

mem_map:
	mi->flags = orig_flags;
        dump_mem_map(mi);

	if (!mi->retval)
		fprintf(fp, "%lx: address not found\n", mi->spec_addr);

}

/*
 *  Determine whether an address is a page pointer from the mem_map[] array.
 *  If the caller requests it, return the associated physical address.
 */
int
is_page_ptr(ulong addr, ulong *phys)
{
	int n;
        ulong ppstart, ppend;
	struct numa_table *nt;
	ulong pgnum;

	for (n = 0; n < vt->numnodes; n++) {
		nt = &vt->numa_table[n];

        	ppstart = nt->mem_map;
		ppend = ppstart + (nt->size * SIZE(page));

		if ((addr < ppstart) || (addr >= ppend))
                	continue;

		/*
		 *  We're in the mem_map range -- but it is a page pointer?
		 */
	        if ((addr - ppstart) % SIZE(page))
			return FALSE;

		if (phys) {
			pgnum = (addr - nt->mem_map) / SIZE(page);
			*phys = (pgnum * PAGESIZE()) + nt->start_paddr;
		}

		return TRUE;
	}

	return FALSE;

#ifdef PRE_NUMA
        ppstart = vt->mem_map;
	ppend = ppstart + (vt->total_pages * vt->page_struct_len);

	if ((addr < ppstart) || (addr >= ppend)) 
		return FALSE;

	if ((addr - ppstart) % vt->page_struct_len)
		return FALSE;

	return TRUE;
#endif
}

/*
 *  Return the physical address associated with this page pointer.
 */
static int 
page_to_phys(ulong pp, ulong *phys)
{
	return(is_page_ptr(pp, phys));
}


/*
 *  Return the page pointer associated with this physical address.
 */
static int 
phys_to_page(ulong phys, ulong *pp)
{
	int n;
        ulong pgnum;
        struct numa_table *nt;
	ulonglong pstart, pend;

        for (n = 0; n < vt->numnodes; n++) {
                nt = &vt->numa_table[n];

                pstart = nt->start_paddr;
                pend = pstart + ((ulonglong)nt->size * PAGESIZE());

                if ((phys < pstart) || (phys >= pend))
                        continue;
                /*
                 *  We're in the physical range -- calculate the page.
                 */
		pgnum = BTOP(phys - pstart);
		*pp = nt->mem_map + (pgnum * SIZE(page));

                return TRUE;
        }

	return FALSE;

#ifdef PRE_NUMA
	if (phys >= (vt->total_pages * PAGESIZE()))
		return FALSE;

	pgnum = PTOB(BTOP(phys)) / PAGESIZE();
	*pp = vt->mem_map + (pgnum * vt->page_struct_len);
	
	return TRUE;
#endif
}


/*
 *  Try to read a string of non-NULL characters from a memory location, 
 *  returning the number of characters read.
 */
int
read_string(ulong kvaddr, char *buf, int maxlen)
{
	char strbuf[MIN_PAGE_SIZE];
        ulong kp;
	char *bufptr;
	long cnt, size;

        BZERO(buf, maxlen);
	BZERO(strbuf, MIN_PAGE_SIZE);

	kp = kvaddr;
	bufptr = strbuf;
	size = maxlen;

	while (size > 0) {
        	cnt = MIN_PAGE_SIZE - (kp & (MIN_PAGE_SIZE-1)); 
 
        	if (cnt > size)
                        cnt = size;

                if (!readmem(kp, KVADDR, bufptr, cnt,
                    "readstring characters", QUIET|RETURN_ON_ERROR))
                        break;

		if (count_buffer_chars(bufptr, NULLCHAR, cnt))
			break;

                kp += cnt;
                bufptr += cnt;
                size -= cnt;
	}

	strcpy(buf, strbuf);
	return (strlen(buf));
}

/*
 *  "help -v" output
 */
void
dump_vm_table(int verbose)
{
	int i;
	struct numa_table *nt;
	int others;

	others = 0;
	fprintf(fp, "           flags: %lx  (", vt->flags);
	if (vt->flags & NUMA)
		fprintf(fp, "%sNUMA", others++ ? "|" : "");
	if (vt->flags & ZONES)
		fprintf(fp, "%sZONES", others++ ? "|" : "");
	if (vt->flags & PERCPU_KMALLOC)
		fprintf(fp, "%sPERCPU_KMALLOC", others++ ? "|" : "");
	if (vt->flags & COMMON_VADDR)
		fprintf(fp, "%sCOMMON_VADDR", others++ ? "|" : "");
	fprintf(fp, ")\n");
        fprintf(fp, "      kernel_pgd: %lx\n", vt->kernel_pgd);
        fprintf(fp, "     high_memory: %lx\n", vt->high_memory);
        fprintf(fp, "   vmalloc_start: %lx\n", vt->vmalloc_start);
        fprintf(fp, "         mem_map: %lx\n", vt->mem_map);
        fprintf(fp, "     total_pages: %ld\n", vt->total_pages);
        fprintf(fp, "       max_mapnr: %ld\n", vt->max_mapnr);
        fprintf(fp, "  totalram_pages: %ld\n", vt->totalram_pages);
	fprintf(fp, "  kmem_max_c_num: %ld\n", vt->kmem_max_c_num);
	fprintf(fp, "  kmem_max_limit: %ld\n", vt->kmem_max_limit);
	fprintf(fp, "   kmem_max_cpus: %ld\n", vt->kmem_max_cpus);
	fprintf(fp, "kmem_cache_count: %ld\n", vt->kmem_cache_count);
	fprintf(fp, "     paddr_prlen: %d\n", vt->paddr_prlen);
	fprintf(fp, "        numnodes: %d\n", vt->numnodes);
	for (i = 0; i < vt->numnodes; i++) {
		nt = &vt->numa_table[i];
		fprintf(fp, "   numa_table[%d]: \n", i);
		fprintf(fp, "              id: %d\n", nt->node_id);
		fprintf(fp, "           pgdat: %lx\n", nt->pgdat);
		fprintf(fp, "            size: %ld\n", nt->size);
		fprintf(fp, "         mem_map: %lx\n", nt->mem_map);
		fprintf(fp, "     start_paddr: %lx\n", nt->start_paddr);
		fprintf(fp, "     start_mapnr: %ld\n", nt->start_mapnr);
	}

	fprintf(fp, " dump_free_pages: ");
	if (vt->dump_free_pages == dump_free_pages)
		fprintf(fp, "dump_free_pages()\n");
	else if (vt->dump_free_pages == dump_free_pages_zones)
		fprintf(fp, "dump_free_pages_zones()\n");
	else if (vt->dump_free_pages == dump_multidimensional_free_pages)
		fprintf(fp, "dump_multidimensional_free_pages()\n");
	else
		fprintf(fp, "%lx (unknown)\n", (ulong)vt->dump_free_pages);

	fprintf(fp, " dump_kmem_cache: ");
	if (vt->dump_kmem_cache == dump_kmem_cache)
		fprintf(fp, "dump_kmem_cache()\n");
	else if (vt->dump_kmem_cache == dump_kmem_cache_percpu)
		fprintf(fp, "dump_kmem_cache_percpu()\n");
	else
		fprintf(fp, "%lx (unknown)\n", (ulong)vt->dump_kmem_cache);
	fprintf(fp, "       slab_data: %lx\n", (ulong)vt->slab_data);
	if (verbose) 
		dump_saved_slab_data();
	fprintf(fp, "    nr_swapfiles: %d\n", vt->nr_swapfiles);
	fprintf(fp, "  last_swap_read: %lx\n", vt->last_swap_read);
	fprintf(fp, "swap_info_struct: %lx\n", (ulong)vt->swap_info_struct);

	dump_vma_cache(VERBOSE);
}

/*
 *  Calculate the amount of memory referenced in the kernel-specific "nodes".
 */
uint64_t
total_node_memory()
{
	int i;
	struct numa_table *nt;
	uint64_t total;

        for (i = total = 0; i < vt->numnodes; i++) {
                nt = &vt->numa_table[i];

		if (MCLXDEBUG(1)) {
                	console("numa_table[%d]: \n", i);
                	console("           id: %d\n", nt->node_id);
                	console("        pgdat: %lx\n", nt->pgdat);
                	console("         size: %ld\n", nt->size);
                	console("      mem_map: %lx\n", nt->mem_map);
                	console("  start_paddr: %lx\n", nt->start_paddr);
                	console("  start_mapnr: %ld\n", nt->start_mapnr);
		}

		total += (uint64_t)((uint64_t)nt->size * (uint64_t)PAGESIZE());
        }

	return total;
}

/*
 *  Dump just the vm_area_struct cache table data so that it can be
 *  called from above or for debug purposes.
 */
void
dump_vma_cache(ulong verbose)
{
	int i;
        ulong vhits;

	if (!verbose)
		goto show_hits;

        for (i = 0; i < VMA_CACHE; i++)
                fprintf(fp, "  cached_vma[%2d]: %lx (%ld)\n",
                        i, vt->cached_vma[i],
                        vt->cached_vma_hits[i]);
        fprintf(fp, "       vma_cache: %lx\n", (ulong)vt->vma_cache);
        fprintf(fp, " vma_cache_index: %d\n", vt->vma_cache_index);
        fprintf(fp, " vma_cache_fills: %ld\n", vt->vma_cache_fills);
	fflush(fp);

show_hits:
        if (vt->vma_cache_fills) {
                for (i = vhits = 0; i < VMA_CACHE; i++)
                        vhits += vt->cached_vma_hits[i];

                fprintf(stderr, "%s    vma hit rate: %2ld%% (%ld of %ld)\n",
			verbose ? "" : "  ",
                        (vhits * 100)/vt->vma_cache_fills,
                        vhits, vt->vma_cache_fills);
        }
}

/*
 *  Guess at the "real" amount of physical memory installed, formatting
 *  it in a MB or GB based string.
 */
char *
get_memory_size(char *buf)
{
	uint64_t total;
	ulong next_gig;
	ulong mbs, gbs;

	total = machdep->memory_size();

	if ((next_gig = roundup(total, GIGABYTES(1)))) {
		if ((next_gig - total) <= MEGABYTES(64))
			total = next_gig;
	}

	gbs = (ulong)(total/GIGABYTES(1));
	mbs = (ulong)(total/MEGABYTES(1));
	if (gbs) 
		mbs = (total % GIGABYTES(1))/MEGABYTES(1);

        if (total%MEGABYTES(1))
                mbs++;

	if (gbs) 
		sprintf(buf, mbs ? "%ld GB %ld MB" : "%ld GB", gbs, mbs);
	else 
		sprintf(buf, "%ld MB", mbs);

	return buf;
}

/*
 *  For use by architectures not having machine-specific manners for
 *  best determining physical memory size.
 */ 
uint64_t
generic_memory_size(void)
{
	if (machdep->memsize)
		return machdep->memsize;

        return (machdep->memsize = total_node_memory());
}

/*
 *  Determine whether a virtual address is user or kernel or ambiguous.
 */ 
int
vaddr_type(ulong vaddr, struct task_context *tc)
{
	int memtype, found;

	if (!tc)
		tc = CURRENT_CONTEXT();
	memtype = found = 0;

	if (machdep->is_uvaddr(vaddr, tc)) {
		memtype |= UVADDR;
		found++;
	}

	if (machdep->is_kvaddr(vaddr)) {
		memtype |= KVADDR;
		found++;
	}

	if (found == 1)
		return memtype;
	else
		return AMBIGUOUS;
}

/*
 *  Search for a given value between a starting and ending address range,
 *  applying an optional mask for "don't care" bits.  As an alternative
 *  to entering the starting address value, -k means "start of kernel address
 *  space".  For processors with ambiguous user/kernel address spaces,
 *  -u or -k must be used (with or without -s) as a differentiator.
 */
void
cmd_search(void)
{
        int c;
	ulong start, end, mask, memtype, len;
	int sflag;
	struct meminfo meminfo;
	ulong value_array[MAXARGS];
	struct syment *sp;

	start = end = mask = sflag = memtype = len = 0;
	BZERO(value_array, sizeof(ulong) * MAXARGS);

        while ((c = getopt(argcnt, args, "l:uks:e:v:m:")) != EOF) {
                switch(c)
                {
		case 'u':
			if (!sflag) {
				start = 0;
				sflag++;
			}
			memtype = UVADDR;
			sflag++;
			break;

		case 'k':
			if (!sflag) {
				start = machdep->kvbase;
				sflag++;
			}
			memtype = KVADDR;
			sflag++;
			break;

		case 's':
			if ((sp = symbol_search(optarg)))
				start = sp->value;
			else
				start = htol(optarg, FAULT_ON_ERROR, NULL);
			sflag++;
			break;

		case 'e':
                        if ((sp = symbol_search(optarg)))
                                end = sp->value;
                        else
                        	end = htol(optarg, FAULT_ON_ERROR, NULL);
                        break;

		case 'l':
			len = stol(optarg, FAULT_ON_ERROR, NULL);
			break;

		case 'm':
                        mask = htol(optarg, FAULT_ON_ERROR, NULL);
                        break;

                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs || !sflag || !args[optind] || (len && end))
                cmd_usage(pc->curcmd, SYNOPSIS);

	if (!memtype)
		memtype = vaddr_type(start, CURRENT_CONTEXT());

	switch (memtype)
	{
	case UVADDR:
		if (!IS_UVADDR(start, CURRENT_CONTEXT())) {
			error(INFO, "invalid user virtual address: %lx\n", 
				start);
                	cmd_usage(pc->curcmd, SYNOPSIS);
		}
		break;

	case KVADDR:
		if (!IS_KVADDR(start)) {
			error(INFO, "invalid kernel virtual address: %lx\n",
				start);
               		cmd_usage(pc->curcmd, SYNOPSIS);
		}
		break;

	case AMBIGUOUS:	
		error(INFO, 
		    "ambiguous virtual address: %lx  (requires -u or -k)\n",
			start);
               	cmd_usage(pc->curcmd, SYNOPSIS);
	}

	if (!end && !len) {
		switch (memtype)
		{
		case UVADDR:
			end = machdep->kvbase;
			break;

		case KVADDR:
			if (vt->vmalloc_start < machdep->identity_map_base)
				end = (ulong)(-1);
			else {
				meminfo.memtype = KVADDR;
				meminfo.spec_addr = 0;
				meminfo.flags = (ADDRESS_SPECIFIED|GET_HIGHEST);
				dump_vmlist(&meminfo);
				end = meminfo.retval;
			}
			break;
		}
	} else if (len)  
		end = start + len;

	switch (memtype)
	{
	case UVADDR:
		if (end > machdep->kvbase) {
			error(INFO, 
	          "address range starts in user space and ends kernel space\n");
               		cmd_usage(pc->curcmd, SYNOPSIS);
		}
			/* FALLTHROUGH */
	case KVADDR:
		if (end < start) {
			error(INFO, 
			   "ending address %lx is below starting address %lx\n",
				end, start);
               		cmd_usage(pc->curcmd, SYNOPSIS);
		}
		break;
	}

	c = 0;
	while (args[optind]) {
		value_array[c] = htol(args[optind], FAULT_ON_ERROR, NULL);
		c++;
		optind++;
	}

	search(start, end, mask, memtype, value_array, c);
}

/*
 *  Do the work for cmd_search().
 */

#define SEARCHMASK(X) ((X) | mask) 

static void
search(ulong start, ulong end, ulong mask, int memtype, ulong *value, int vcnt)
{
	int i, j;
	ulong pp, next, *ubp;
	int wordcnt, lastpage;
	ulong paddr, page;
	char *pagebuf;

	if (start & (sizeof(long)-1)) {
		start &= ~(sizeof(long)-1);
		error(INFO, "rounding down start address to: %lx\n", start);
	}

	pagebuf = GETBUF(PAGESIZE());
	next = start;

	for (pp = PAGEBASE(start); next < end; next = pp) {
		lastpage = (PAGEBASE(next) == PAGEBASE(end));
		if (LKCD_DUMPFILE())
			set_lkcd_nohash();

                switch (memtype)
                {
                case UVADDR:
                        if (!uvtop(CURRENT_CONTEXT(), pp, &paddr, 0) ||
                            !phys_to_page(paddr, &page)) { 
				if (!next_upage(CURRENT_CONTEXT(), pp, &pp)) 
					return;
                                continue;
			}
                        break;

                case KVADDR:
                        if (!kvtop(CURRENT_CONTEXT(), pp, &paddr, 0) ||
                            !phys_to_page(paddr, &page)) {
				if (!next_kpage(pp, &pp))
					return;
                                continue;
			}
                        break;
                }

                if (!readmem(paddr, PHYSADDR, pagebuf, PAGESIZE(),
                    "search page", RETURN_ON_ERROR|QUIET)) {
			pp += PAGESIZE();
			continue;
		}

		ubp = (ulong *)&pagebuf[next - pp];
		if (lastpage) {
			if (end == (ulong)(-1))
				wordcnt = PAGESIZE()/sizeof(long);
			else
				wordcnt = (end - next)/sizeof(long);
		} else
			wordcnt = (PAGESIZE() - (next - pp))/sizeof(long);

		for (i = 0; i < wordcnt; i++, ubp++, next += sizeof(long)) {
			for (j = 0; j < vcnt; j++) {
				if (SEARCHMASK(*ubp) == SEARCHMASK(value[j])) 
					fprintf(fp, "%lx: %lx\n", next, *ubp);
			}
		}

		if (MCLXDEBUG(1))
			if ((pp % (1024*1024)) == 0)
				console("%lx\n", pp);

		pp += PAGESIZE();
	}
}


/*
 *  Return the next mapped user virtual address page that comes after 
 *  the passed-in address.
 */
static int
next_upage(struct task_context *tc, ulong vaddr, ulong *nextvaddr)
{
	ulong vma, total_vm;
	int found;
	char *vma_buf;
        ulong vm_start, vm_end;
	void *vm_next;

        if (!tc->mm_struct)
                return FALSE;

        fill_mm_struct(tc->mm_struct);
	vma = ULONG(tt->mm_struct + OFFSET(mm_struct_mmap));
	total_vm = ULONG(tt->mm_struct + OFFSET(mm_struct_total_vm));

	if (!vma || (total_vm == 0))
		return FALSE;

	vaddr = PAGEBASE(vaddr) + PAGESIZE();  /* first possible page */

        for (found = FALSE; vma; vma = (ulong)vm_next) {
                vma_buf = fill_vma_cache(vma);

                vm_start = ULONG(vma_buf + OFFSET(vm_area_struct_vm_start));
                vm_end = ULONG(vma_buf + OFFSET(vm_area_struct_vm_end));
                vm_next = VOID_PTR(vma_buf + OFFSET(vm_area_struct_vm_next));

		if (vaddr <= vm_start) {
			*nextvaddr = vm_start;
			return TRUE;
		}

		if ((vaddr > vm_start) && (vaddr < vm_end)) {
			*nextvaddr = vaddr;
			return TRUE;
		}
	}

	return FALSE;
}

/*
 *  Return the next kernel virtual address page that comes after
 *  the passed-in address.
 */
static int
next_kpage(ulong vaddr, ulong *nextvaddr)
{
        int n;
        ulong paddr, vaddr_orig;
        struct numa_table *nt;
        ulonglong pstart, pend;
	ulong vmalloc_limit;
	struct meminfo meminfo;

	vaddr_orig = vaddr;
	vaddr = PAGEBASE(vaddr) + PAGESIZE();  /* first possible page */

        if (vaddr < vaddr_orig)  /* wrapped back to zero? */
                return FALSE;

        meminfo.memtype = KVADDR;
        meminfo.spec_addr = 0;
        meminfo.flags = (ADDRESS_SPECIFIED|GET_HIGHEST);
        dump_vmlist(&meminfo);
        vmalloc_limit = meminfo.retval;

	if (IS_VMALLOC_ADDR(vaddr_orig)) {
		if (IS_VMALLOC_ADDR(vaddr) && (vaddr < vmalloc_limit)) {
			*nextvaddr = vaddr;
			return TRUE;
		}

		if (vt->vmalloc_start < machdep->identity_map_base) {   
			*nextvaddr = machdep->identity_map_base;
			return TRUE;
		}

		return FALSE;	
	}

	paddr = VTOP(vaddr);

        for (n = 0; n < vt->numnodes; n++) {
                nt = &vt->numa_table[n];

                pstart = nt->start_paddr;
                pend = pstart + ((ulonglong)nt->size * PAGESIZE());

                if ((paddr < pstart) || (paddr >= pend))
                        continue;
                /*
                 *  We're in the physical range.
                 */
                return TRUE;
        }

	if (vt->vmalloc_start > vaddr) {
		*nextvaddr = vt->vmalloc_start;
		return TRUE;
	} else
        	return FALSE;
}

/*
 *  Display swap statistics.
 */
void
cmd_swap(void)
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

	dump_swap_info(VERBOSE, NULL, NULL);
}

/*
 *  Do the work for cmd_swap().
 */

#define SWP_USED        1
#define SWAP_MAP_BAD    0x8000

char *swap_info_hdr = \
"FILENAME           TYPE         SIZE      USED   PCT  PRIORITY\n";

static void
dump_swap_info(ulong swapflags, ulong *totalswap_pages, ulong *totalused_pages)
{
	int i, j;
	int flags, swap_device, pages, prio, usedswap;
	ulong swap_file, max, swap_map, pct;
	ulong vfsmnt;
	ulong swap_info;
	ushort *map;
	ulong totalswap, totalused;
	char buf[BUFSIZE];

	if (!symbol_exists("nr_swapfiles"))
		error(FATAL, "nr_swapfiles doesn't exist in this kernel!\n");

        if (!symbol_exists("swap_info"))
                error(FATAL, "swap_info doesn't exist in this kernel!\n");

	swap_info = symbol_value("swap_info");

	if (swapflags == VERBOSE)
		fprintf(fp, swap_info_hdr);

	totalswap = totalused = 0;

	for (i = 0; i < vt->nr_swapfiles; i++, 
	    swap_info += SIZE(swap_info_struct)){
		fill_swap_info(swap_info);

		flags = INT(vt->swap_info_struct + 
			OFFSET(swap_info_struct_flags));

		if (!(flags & SWP_USED))
			continue;

		swap_file = ULONG(vt->swap_info_struct + 
			OFFSET(swap_info_struct_swap_file));

                swap_device = INT(vt->swap_info_struct +
                        OFFSET(swap_info_struct_swap_device));

                pages = INT(vt->swap_info_struct +
                        OFFSET(swap_info_struct_pages));

		totalswap += pages;
		pages <<= (PAGESHIFT() - 10);

                prio = INT(vt->swap_info_struct + 
			OFFSET(swap_info_struct_prio));

                max = ULONG(vt->swap_info_struct +
                        OFFSET(swap_info_struct_max));

                swap_map = ULONG(vt->swap_info_struct +
                        OFFSET(swap_info_struct_swap_map));

		if (swap_file) {
			if (VALID_OFFSET(swap_info_struct_swap_vfsmnt)) {
                		vfsmnt = ULONG(vt->swap_info_struct +
                        		OFFSET(swap_info_struct_swap_vfsmnt));
				get_pathname(swap_file, buf, BUFSIZE, 
					1, vfsmnt);
			} else {
				get_pathname(swap_file, buf, BUFSIZE, 1, 0);
			}
		} else
			sprintf(buf, "(unknown)");

		map = (ushort *)GETBUF(sizeof(ushort) * max);

		readmem(swap_map, KVADDR, map, 
			sizeof(ushort) * max, "swap_info swap_map data",
			FAULT_ON_ERROR);

		usedswap = 0;
                for (j = 0; j < max; j++) {
                        switch (map[j])
                        {
                        case SWAP_MAP_BAD:
                        case 0:
                                continue;
                        default:
                                usedswap++;
                        }
		}

		FREEBUF(map);

		totalused += usedswap;
		usedswap <<= (PAGESHIFT() - 10);
		pct = (usedswap * 100)/pages;

		if (swapflags == VERBOSE)
			fprintf(fp, "%-15s  %s    %7dk %7dk  %2ld%%     %d\n", 
				buf, swap_device ? "PARTITION" : "  FILE   ", 
				pages, usedswap, pct, prio);
	}

	if (totalswap_pages)
		*totalswap_pages = totalswap;
	if (totalused_pages)
		*totalused_pages = totalused;
}

/*
 *  Translate a PTE into a swap device and offset string.
 */
char *
swap_location(ulong pte, char *buf)
{
	char swapdev[BUFSIZE];

        if (!pte)
                return NULL;

	sprintf(buf, "%s  OFFSET: %ld", 
		get_swapdev(machdep->SWP_TYPE(pte), swapdev), 
		machdep->SWP_OFFSET(pte));

        return buf;
}

/*
 *  Given the type field from a PTE, return the name of the swap device.
 */
static char *
get_swapdev(ulong type, char *buf)
{
	unsigned int swap_info_len;
	ulong swap_info, swap_file;
	ulong vfsmnt;

        if (!symbol_exists("nr_swapfiles"))
                error(FATAL, "nr_swapfiles doesn't exist in this kernel!\n");

        if (!symbol_exists("swap_info"))
                error(FATAL, "swap_info doesn't exist in this kernel!\n");

        swap_info = symbol_value("swap_info");
	swap_info_len = get_array_length("swap_info", NULL);

        sprintf(buf, "(unknown swap location)");

	if (type >= swap_info_len)
		return buf;

	swap_info += (SIZE(swap_info_struct) * type);
	fill_swap_info(swap_info);
	swap_file = ULONG(vt->swap_info_struct + 
		OFFSET(swap_info_struct_swap_file));

        if (swap_file) {
		if (VALID_OFFSET(swap_info_struct_swap_vfsmnt)) {
			vfsmnt = ULONG(vt->swap_info_struct + 
				OFFSET(swap_info_struct_swap_vfsmnt));
        		get_pathname(swap_file, buf, BUFSIZE, 1, vfsmnt);
		} else {
        		get_pathname(swap_file, buf, BUFSIZE, 1, 0);
		}
        } 

	return buf;
}

/*
 *  If not currently stashed, cache the passed-in swap_info_struct.
 */
static void
fill_swap_info(ulong swap_info)
{
	if (vt->last_swap_read == swap_info)
		return;

	if (!vt->swap_info_struct && !(vt->swap_info_struct = (char *)
        	malloc(SIZE(swap_info_struct))))
			error(FATAL, "cannot malloc swap_info_struct space\n");
	
        readmem(swap_info, KVADDR, vt->swap_info_struct, SIZE(swap_info_struct),
                "fill_swap_info", FAULT_ON_ERROR);

	vt->last_swap_read = swap_info;
}

/*
 *  If active, clear references to the swap_info references.
 */
void
clear_swap_info_cache(void)
{
	if (ACTIVE())
		vt->last_swap_read = 0;
}


/*
 *  Translage a vm_area_struct and virtual address into a filename
 *  and offset string.
 */ 

#define PAGE_CACHE_SHIFT  (machdep->pageshift) /* This is supposed to change! */

static char *
vma_file_offset(ulong vma, ulong vaddr, char *buf)
{
	ulong vm_file, vm_start, vm_offset, vm_pgoff, dentry, offset;
	ulong vfsmnt;
	char file[BUFSIZE];
	char *vma_buf, *file_buf;

	if (!vma)
		return NULL;

        vma_buf = fill_vma_cache(vma);

        vm_file = ULONG(vma_buf + OFFSET(vm_area_struct_vm_file));

	if (!vm_file) 
		goto no_file_offset;

        file_buf = fill_file_cache(vm_file);
        dentry = ULONG(file_buf + OFFSET(file_f_dentry));

	if (!dentry) 
		goto no_file_offset;

	file[0] = NULLCHAR;
	if (VALID_OFFSET(file_f_vfsmnt)) {
        	vfsmnt = ULONG(file_buf + OFFSET(file_f_vfsmnt));
               	get_pathname(dentry, file, BUFSIZE, 1, vfsmnt);
	} else 
               	get_pathname(dentry, file, BUFSIZE, 1, 0);

	if (!strlen(file)) 
		goto no_file_offset;

        vm_start = ULONG(vma_buf + OFFSET(vm_area_struct_vm_start));

	vm_offset = vm_pgoff = 0xdeadbeef;

	if (VALID_OFFSET(vm_area_struct_vm_offset)) 
        	vm_offset = ULONG(vma_buf + 
			OFFSET(vm_area_struct_vm_offset));
	else if (VALID_OFFSET(vm_area_struct_vm_pgoff))
        	vm_pgoff = ULONG(vma_buf + 
			OFFSET(vm_area_struct_vm_pgoff));
	else 
		goto no_file_offset;

	if (vm_offset != 0xdeadbeef) 
		offset = PAGEBASE(vaddr) - vm_start + vm_offset;
	else if (vm_pgoff != 0xdeadbeef) {
		offset = ((vaddr - vm_start) >> PAGE_CACHE_SHIFT) + vm_pgoff;
		offset <<= PAGE_CACHE_SHIFT;
	}

	sprintf(buf, "%s  OFFSET: %lx", file, offset);

	return buf;

no_file_offset:
	return NULL;
}

/*
 *  Translate a PTE into its physical address and flags.
 */
void
cmd_pte(void)
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
		machdep->translate_pte(htol(args[optind], 
			FAULT_ON_ERROR, NULL), NULL);
		optind++;
	}

}

/*
 *  On systems supporting numa nodes, display the basic per-node data.
 */
static void
dump_numa_nodes(ulong verbose)
{
	int i;
	int n, id, flen;
	ulong node_mem_map;
        ulong node_start_paddr;
        ulong node_start_mapnr;
        ulong free_pages, zone_size, node_size;
	ulong zone_start_paddr, zone_start_mapnr, zone_mem_map;
	ulong bdata;
	ulong pgdat;
	ulong node_zones;
        int nr_zones;
	ulong value;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	struct numa_table *nt;

        if (!(vt->flags & NUMA)) {
		if (verbose) 
			error(FATAL, 
			    "NUMA nodes not supported by this kernel\n\n");
		else {
			nt = &vt->numa_table[0];
			nt->node_id = 0;
			if (symbol_exists("contig_page_data"))
				nt->pgdat = symbol_value("contig_page_data");
			else
				nt->pgdat = 0;
			nt->size = vt->total_pages;
			nt->mem_map = vt->mem_map;
			nt->start_paddr = 0;
			nt->start_mapnr = 0;
			return;
		}
	}

        nr_zones = get_array_length("pglist_data.node_zones", NULL);

	get_symbol_data("pgdat_list", sizeof(void *), &pgdat);

	for (n = 0; pgdat; n++) {
		nt = &vt->numa_table[n];

		readmem(pgdat+OFFSET(pglist_data_node_id), KVADDR, &id,
			sizeof(int), "pglist node_id", FAULT_ON_ERROR);
		readmem(pgdat+OFFSET(pglist_data_node_mem_map), KVADDR, 
			&node_mem_map, sizeof(ulong), 
			"node_mem_map", FAULT_ON_ERROR);
		readmem(pgdat+OFFSET(pglist_data_node_start_paddr), KVADDR, 
			&node_start_paddr, sizeof(ulong), 
			"pglist node_start_paddr", FAULT_ON_ERROR);
		readmem(pgdat+OFFSET(pglist_data_node_start_mapnr), KVADDR, 
			&node_start_mapnr, sizeof(ulong), 
			"pglist node_start_mapnr", FAULT_ON_ERROR);
		readmem(pgdat+OFFSET(pglist_data_node_size), KVADDR, &node_size,
			sizeof(ulong), "pglist node_size", FAULT_ON_ERROR);
		readmem(pgdat+OFFSET(pglist_data_bdata), KVADDR, &bdata,
			sizeof(ulong), "pglist bdata", FAULT_ON_ERROR);

		if (!verbose) {
			nt->node_id = id;
			nt->pgdat = pgdat;
			nt->size = node_size;
			nt->mem_map = node_mem_map;
			nt->start_paddr = node_start_paddr;
			nt->start_mapnr = node_start_mapnr;
		}

		if (verbose) {
			flen = MAX(VADDR_PRLEN, strlen("BOOTMEM_DATA"));
			fprintf(fp, "%sNODE  %s  %s  %s\n", 
			    n ? "\n\n" : "",
			    mkstring(buf1, 8, CENTER, "SIZE"),
			    mkstring(buf2, flen, CENTER|LJUST, "PGLIST_DATA"),
			    mkstring(buf3, flen, CENTER|LJUST, "BOOTMEM_DATA"));
			fprintf(fp, " %2d   %s  %s  %s\n", id, 
			    mkstring(buf1, 8, CENTER|LJUST|LONG_DEC, 
				MKSTR(node_size)),
			    mkstring(buf2, flen, CENTER|LJUST|LONG_HEX, 
				MKSTR(pgdat)),
			    mkstring(buf3, flen, CENTER|LONG_HEX, 
				MKSTR(bdata)));
	
	                fprintf(fp, "\n%s  START_PADDR  START_MAPNR\n",
	                    mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, 
				"MEM_MAP"));
	                fprintf(fp, "%s  %s  %s\n",
	                    mkstring(buf1, VADDR_PRLEN,
	                        CENTER|LONG_HEX, MKSTR(node_mem_map)),
	                    mkstring(buf2, strlen("START_PADDR"),
	                        CENTER|LONG_HEX|RJUST, MKSTR(node_start_paddr)),
	                    mkstring(buf3, strlen("START_MAPNR"),
	                        CENTER|LONG_DEC|RJUST, 
				    MKSTR(node_start_mapnr)));
	
			fprintf(fp, "\n%s  %s  START_PADDR  START_MAPNR\n", 
				zone_hdr,
				mkstring(buf1, VADDR_PRLEN, CENTER|RJUST, 
				    "MEM_MAP"));
		}

       		node_zones = pgdat + OFFSET(pglist_data_node_zones);

		for (i = 0; i < nr_zones; i++) {
			if (MCLXDEBUG(1))
				fprintf(fp, "%lx\n", node_zones);

                	readmem(node_zones+OFFSET(zone_struct_size), KVADDR,
                        	&zone_size, sizeof(ulong),
                        	"zone_struct size", FAULT_ON_ERROR);
                	readmem(node_zones+OFFSET(zone_struct_free_pages), 
				KVADDR, &free_pages, sizeof(ulong),
                        	"zone_struct free_pages", FAULT_ON_ERROR);
                	readmem(node_zones+OFFSET(zone_struct_name), KVADDR,
                        	&value, sizeof(void *),
                        	"zone_struct name", FAULT_ON_ERROR);
                	if (!read_string(value, buf1, BUFSIZE-1))
                        	sprintf(buf1, "(unknown) ");
                        readmem(node_zones+OFFSET(zone_struct_zone_start_paddr),
                                KVADDR, &zone_start_paddr, sizeof(ulong),
                                "node_zones zone_start_paddr", FAULT_ON_ERROR);
                        readmem(node_zones+OFFSET(zone_struct_zone_start_mapnr),
                                KVADDR, &zone_start_mapnr, sizeof(ulong),
                                "node_zones zone_start_mapnr", FAULT_ON_ERROR);
                        readmem(node_zones+OFFSET(zone_struct_zone_mem_map),
                                KVADDR, &zone_mem_map, sizeof(ulong),
                                "node_zones zone_mem_map", FAULT_ON_ERROR);

			if (verbose) {
				fprintf(fp, " %2d   %-9s %6ld  %6ld  ", 
					i, buf1, zone_size, free_pages);
				fprintf(fp, "%s  %s  %s\n",
	                    	    mkstring(buf1, VADDR_PRLEN,
	                        	RJUST|LONG_HEX,MKSTR(zone_mem_map)),
	                            mkstring(buf2, strlen("START_PADDR"),
	                        	LONG_HEX|RJUST,MKSTR(zone_start_paddr)),
	                    	    mkstring(buf3, strlen("START_MAPNR"),
	                        	LONG_DEC|RJUST,
					MKSTR(zone_start_mapnr)));
			}

			node_zones += SIZE(zone_struct);
		}

		readmem(pgdat + OFFSET(pglist_data_node_next), KVADDR,
			&pgdat, sizeof(void *), "pglist_data node_next",
			FAULT_ON_ERROR);
	} 

	if (n != vt->numnodes)
		error(FATAL, "numnodes out of sync with pgdat_list?\n");
}

/*
 *  Gather essential information regarding each NUMA node.
 */
static void
numa_table_init(void)
{
       	if (!(vt->numa_table = (struct numa_table *)
	    malloc(sizeof(struct numa_table) * vt->numnodes)))
		error(FATAL, "cannot malloc numa_table %s(%d nodes)",
			vt->numnodes > 1 ? "array " : "", vt->numnodes);

	BZERO(vt->numa_table, sizeof(struct numa_table) * vt->numnodes);

	dump_numa_nodes(!VERBOSE);
}


/*
 *  Depending upon the processor, and whether we're running live or on a 
 *  dumpfile, get the system page size.
 */
uint
memory_page_size(void)
{
	uint psz;

	if (REMOTE_MEMSRC()) 
		return remote_page_size();

	switch (pc->flags & (MCLXCD|LKCD|DEVMEM|S390D|S390XD))
	{
	case MCLXCD:
		psz = (uint)mclx_page_size();
		break;

	case LKCD:
		psz = lkcd_page_size();
		break;

	case DEVMEM:                      
		psz = (uint)getpagesize();  
		break;

	case S390D:
		psz = s390_page_size();
		break;

	case S390XD:
		psz = s390x_page_size();
		break;

	default:
		error(FATAL, "memory_page_size: invalid pc->flags: %lx\n", 
			pc->flags & (MCLXCD|LKCD|DEVMEM|S390D|S390XD)); 
	}

	return psz;
}

/*
 *  Return the vmalloc address referenced by the first vm_struct
 *  on the vmlist.  This can normally be used by the machine-specific
 *  xxx_vmalloc_start() routines.
 */

ulong
first_vmalloc_address(void)
{
        ulong vmlist, addr;

        get_symbol_data("vmlist", sizeof(void *), &vmlist);

        readmem(vmlist+OFFSET(vm_struct_addr), KVADDR, &addr, sizeof(void *),
              "first vmlist addr", FAULT_ON_ERROR);

        return addr;
}

/*
 *  Return the L1 cache size in bytes, which can be found stored in the
 *  cache_cache.
 */

int
l1_cache_size(void)
{
	ulong cache_cache;
	ulong c_align;
	int colour_off;
	int retval;

        cache_cache = symbol_value("cache_cache");

	retval = -1;

	if (MEMBER_EXISTS("kmem_cache_s", "c_align")) {
                readmem(cache_cache+OFFSET(kmem_cache_s_c_align),
                	KVADDR, &c_align, sizeof(ulong),
                        "c_align", FAULT_ON_ERROR);
		retval = (int)c_align;
	} else if (MEMBER_EXISTS("kmem_cache_s", "colour_off")) {
                readmem(cache_cache+OFFSET(kmem_cache_s_colour_off),
                	KVADDR, &colour_off, sizeof(int),
                        "colour_off", FAULT_ON_ERROR);
		retval = colour_off;
	}

	return retval;
}

/*
 *  Multi-purpose routine used to query/control dumpfile memory usage.
 */
int
dumpfile_memory(int cmd)
{
	int retval;

	retval = 0;

	if (!DUMPFILE())
		return retval;

	switch (cmd)
	{
	case DUMPFILE_MEM_USED:
                if (pc->flags & (REM_MCLXCD|REM_LKCD|REM_S390D|REM_S390XD))
                        retval = remote_memory_used();
		else if (pc->flags & LKCD)
        		retval = lkcd_memory_used();
		else if (pc->flags & MCLXCD)
                        retval = vas_memory_used();
		else if (pc->flags & S390D)
			retval = s390_memory_used();
		else if (pc->flags & S390XD)
			retval = s390x_memory_used();
		break;

	case DUMPFILE_FREE_MEM:
                if (pc->flags & (REM_MCLXCD|REM_LKCD|REM_S390D|REM_S390XD))
                        retval = remote_free_memory();
                else if (pc->flags & LKCD)
                        retval = lkcd_free_memory();
                else if (pc->flags & MCLXCD)
                        retval = vas_free_memory(NULL);
                else if (pc->flags & S390D)
                        retval = s390_free_memory();
                else if (pc->flags & S390XD)
                        retval = s390x_free_memory();
		break;

	case DUMPFILE_MEM_DUMP:
                if (pc->flags & (REM_MCLXCD|REM_LKCD|REM_S390D|REM_S390XD))
                        retval = remote_memory_dump(0);
                else if (pc->flags & LKCD) 
                        retval = lkcd_memory_dump(set_lkcd_fp(fp));
                else if (pc->flags & MCLXCD)
                        retval = vas_memory_dump(fp);
                else if (pc->flags & S390D)
                        retval = s390_memory_dump(fp);
                else if (pc->flags & S390XD)
                        retval = s390x_memory_dump(fp);
		break;
	
	case DUMPFILE_ENVIRONMENT:
                if (pc->flags & LKCD) {
                        set_lkcd_fp(fp);
                        dump_lkcd_environment(0);
		} else if (pc->flags & REM_LKCD) 
                        retval = remote_memory_dump(VERBOSE);
		break;
	}

	return retval;
}

