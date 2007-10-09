/* memory.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007 David Anderson
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2002 Silicon Graphics, Inc.
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
#include <sys/mman.h>

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
        ulonglong spec_addr;
        ulong flags;
	ulong size;
	int memtype;
	int free;
        char *reqname;
	char *curname;
	ulong *addrlist;
	int *kmem_bufctl;
	ulong *cpudata[NR_CPUS];
	ulong *shared_array_cache;
	int current_cache_index;
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
	struct vmlist {
		ulong addr;
		ulong size;
	} *vmlist;
};

static char *memtype_string(int, int);
static char *error_handle_string(ulong);
static void dump_mem_map(struct meminfo *);
static void dump_mem_map_SPARSEMEM(struct meminfo *);
static void fill_mem_map_cache(ulong, ulong, char *);
static void dump_free_pages(struct meminfo *);
static int dump_zone_page_usage(void);
static void dump_multidimensional_free_pages(struct meminfo *);
static void dump_free_pages_zones_v1(struct meminfo *);
static void dump_free_pages_zones_v2(struct meminfo *);
static int dump_zone_free_area(ulong, int, ulong);
static void dump_page_hash_table(struct meminfo *);
static void kmem_search(struct meminfo *);
static void kmem_cache_init(void);
static ulong max_cpudata_limit(ulong, ulong *);
static int ignore_cache(struct meminfo *, char *);
static char *is_kmem_cache_addr(ulong, char *);
static void kmem_cache_list(void);
static void dump_kmem_cache(struct meminfo *);
static void dump_kmem_cache_percpu_v1(struct meminfo *);
static void dump_kmem_cache_percpu_v2(struct meminfo *);
static void dump_kmem_cache_info_v2(struct meminfo *);
static char *vaddr_to_kmem_cache(ulong, char *);
static ulong vaddr_to_slab(ulong);
static void do_slab_chain(int, struct meminfo *);
static void do_slab_chain_percpu_v1(long, struct meminfo *);
static void do_slab_chain_percpu_v2(long, struct meminfo *);
static void do_slab_chain_percpu_v2_nodes(long, struct meminfo *);
static void save_slab_data(struct meminfo *);
static int slab_data_saved(struct meminfo *);
static void dump_saved_slab_data(void);
static void dump_slab(struct meminfo *);
static void dump_slab_percpu_v1(struct meminfo *);
static void dump_slab_percpu_v2(struct meminfo *);
static int verify_slab_v1(struct meminfo *, ulong, int);
static int verify_slab_v2(struct meminfo *, ulong, int);
static void gather_slab_free_list(struct meminfo *);
static void gather_slab_free_list_percpu(struct meminfo *);
static void gather_cpudata_list_v1(struct meminfo *);
static void gather_cpudata_list_v2(struct meminfo *);
static void gather_cpudata_list_v2_nodes(struct meminfo *, int);
static int check_cpudata_list(struct meminfo *, ulong);
static int check_shared_list(struct meminfo *, ulong);
static void gather_slab_cached_count(struct meminfo *);
static void dump_slab_objects(struct meminfo *);
static void dump_slab_objects_percpu(struct meminfo *);
static void dump_vmlist(struct meminfo *);
static int dump_page_lists(struct meminfo *);
static void dump_kmeminfo(void);
static int page_to_phys(ulong, physaddr_t *); 
static int phys_to_page(physaddr_t, ulong *); 
static void display_memory(ulonglong, long, ulong, int); 
static void search(ulong, ulong, ulong, int, ulong *, int);
static int next_upage(struct task_context *, ulong, ulong *);
static int next_kpage(ulong, ulong *);
static ulong next_vmlist_vaddr(struct meminfo *, ulong);
static int vm_area_page_dump(ulong, ulong, ulong, ulong, void *, 
	struct reference *);
static int dump_swap_info(ulong, ulong *, ulong *);
static char *get_swapdev(ulong, char *);
static void fill_swap_info(ulong);
static char *vma_file_offset(ulong, ulong, char *);
static ssize_t read_dev_kmem(ulong, char *, long);
static void dump_memory_nodes(int);
#define MEMORY_NODES_DUMP       (0)
#define MEMORY_NODES_INITIALIZE (1)
static void node_table_init(void);
static int compare_node_data(const void *, const void *);
static void do_vm_flags(ulong);
static void PG_reserved_flag_init(void);
static void PG_slab_flag_init(void);
static ulong nr_blockdev_pages(void);
void sparse_mem_init(void);
void dump_mem_sections(void);
void list_mem_sections(void);
ulong sparse_decode_mem_map(ulong, ulong);
char *read_mem_section(ulong);
ulong nr_to_section(ulong);
int valid_section(ulong);
int section_has_mem_map(ulong);
ulong section_mem_map_addr(ulong);
ulong valid_section_nr(ulong);
ulong pfn_to_map(ulong);
static int get_nodes_online(void);
static int next_online_node(int);
static ulong next_online_pgdat(int);
static int vm_stat_init(void);
static int dump_vm_stat(char *, long *);
static int generic_read_dumpfile(ulonglong, void *, long, char *, ulong);
static int generic_write_dumpfile(ulonglong, void *, long, char *, ulong);

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
#define NO_ASCII       (0x800)

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
        if (sizeof(void *) != sizeof(long))
                error(FATAL, "pointer size: %d is not sizeof(long): %d\n", sizeof(void *), sizeof(long));

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
	int i, len, dimension;
	struct syment *sp_array[2];
	ulong value1, value2;

        MEMBER_OFFSET_INIT(task_struct_mm, "task_struct", "mm");
        MEMBER_OFFSET_INIT(mm_struct_mmap, "mm_struct", "mmap");
        MEMBER_OFFSET_INIT(mm_struct_pgd, "mm_struct", "pgd");
	MEMBER_OFFSET_INIT(mm_struct_rss, "mm_struct", "rss");
	if (!VALID_MEMBER(mm_struct_rss))
		MEMBER_OFFSET_INIT(mm_struct_rss, "mm_struct", "_rss");
	if (!VALID_MEMBER(mm_struct_rss))
		MEMBER_OFFSET_INIT(mm_struct_rss, "mm_struct", "_file_rss");
	MEMBER_OFFSET_INIT(mm_struct_anon_rss, "mm_struct", "anon_rss");
	if (!VALID_MEMBER(mm_struct_anon_rss))
		MEMBER_OFFSET_INIT(mm_struct_anon_rss, "mm_struct", "_anon_rss");
	MEMBER_OFFSET_INIT(mm_struct_total_vm, "mm_struct", "total_vm");
	MEMBER_OFFSET_INIT(mm_struct_start_code, "mm_struct", "start_code");
        MEMBER_OFFSET_INIT(vm_area_struct_vm_mm, "vm_area_struct", "vm_mm");
        MEMBER_OFFSET_INIT(vm_area_struct_vm_next, "vm_area_struct", "vm_next");
        MEMBER_OFFSET_INIT(vm_area_struct_vm_end, "vm_area_struct", "vm_end");
        MEMBER_OFFSET_INIT(vm_area_struct_vm_start, 
		"vm_area_struct", "vm_start");
        MEMBER_OFFSET_INIT(vm_area_struct_vm_flags, 
                "vm_area_struct", "vm_flags");
        MEMBER_OFFSET_INIT(vm_area_struct_vm_file, "vm_area_struct", "vm_file");
        MEMBER_OFFSET_INIT(vm_area_struct_vm_offset, 
                "vm_area_struct", "vm_offset");
        MEMBER_OFFSET_INIT(vm_area_struct_vm_pgoff, 
                "vm_area_struct", "vm_pgoff");
        MEMBER_SIZE_INIT(vm_area_struct_vm_flags, "vm_area_struct", "vm_flags");

	MEMBER_OFFSET_INIT(vm_struct_addr, "vm_struct", "addr");
	MEMBER_OFFSET_INIT(vm_struct_size, "vm_struct", "size");
	MEMBER_OFFSET_INIT(vm_struct_next, "vm_struct", "next");

	MEMBER_OFFSET_INIT(page_next, "page", "next");
	if (VALID_MEMBER(page_next)) 
		MEMBER_OFFSET_INIT(page_prev, "page", "prev");

	MEMBER_OFFSET_INIT(page_list, "page", "list");
	if (VALID_MEMBER(page_list)) {
		ASSIGN_OFFSET(page_list_next) = OFFSET(page_list) +
			OFFSET(list_head_next);
		ASSIGN_OFFSET(page_list_prev) = OFFSET(page_list) +
			OFFSET(list_head_prev);
	}

	MEMBER_OFFSET_INIT(page_next_hash, "page", "next_hash");
	MEMBER_OFFSET_INIT(page_inode, "page", "inode");
	MEMBER_OFFSET_INIT(page_offset, "page", "offset");
	MEMBER_OFFSET_INIT(page_count, "page", "count");
	if (INVALID_MEMBER(page_count))
		MEMBER_OFFSET_INIT(page_count, "page", "_count");
	MEMBER_OFFSET_INIT(page_flags, "page", "flags");
        MEMBER_OFFSET_INIT(page_mapping, "page", "mapping");
        MEMBER_OFFSET_INIT(page_index, "page", "index");
        MEMBER_OFFSET_INIT(page_buffers, "page", "buffers");
	MEMBER_OFFSET_INIT(page_lru, "page", "lru");
	MEMBER_OFFSET_INIT(page_pte, "page", "pte");

	MEMBER_OFFSET_INIT(mm_struct_pgd, "mm_struct", "pgd");

	MEMBER_OFFSET_INIT(swap_info_struct_swap_file,
        	"swap_info_struct", "swap_file");
	MEMBER_OFFSET_INIT(swap_info_struct_swap_vfsmnt, 
        	"swap_info_struct", "swap_vfsmnt");
	MEMBER_OFFSET_INIT(swap_info_struct_flags,
        	"swap_info_struct", "flags");	
	MEMBER_OFFSET_INIT(swap_info_struct_swap_map, 
        	"swap_info_struct", "swap_map");
	MEMBER_OFFSET_INIT(swap_info_struct_swap_device, 
        	"swap_info_struct", "swap_device");
	MEMBER_OFFSET_INIT(swap_info_struct_prio, "swap_info_struct", "prio");
	MEMBER_OFFSET_INIT(swap_info_struct_max, "swap_info_struct", "max");
	MEMBER_OFFSET_INIT(swap_info_struct_pages, "swap_info_struct", "pages");
	MEMBER_OFFSET_INIT(swap_info_struct_old_block_size, 
        	"swap_info_struct", "old_block_size");
	MEMBER_OFFSET_INIT(block_device_bd_inode, "block_device", "bd_inode");
	MEMBER_OFFSET_INIT(block_device_bd_list, "block_device", "bd_list");
	MEMBER_OFFSET_INIT(block_device_bd_disk, "block_device", "bd_disk");
	MEMBER_OFFSET_INIT(inode_i_mapping, "inode", "i_mapping");
	MEMBER_OFFSET_INIT(address_space_nrpages, "address_space", "nrpages");
	MEMBER_OFFSET_INIT(gendisk_major, "gendisk", "major");
	MEMBER_OFFSET_INIT(gendisk_fops, "gendisk", "fops");
	MEMBER_OFFSET_INIT(gendisk_disk_name, "gendisk", "disk_name");

	STRUCT_SIZE_INIT(block_device, "block_device");
	STRUCT_SIZE_INIT(address_space, "address_space");
	STRUCT_SIZE_INIT(gendisk, "gendisk");

	STRUCT_SIZE_INIT(blk_major_name, "blk_major_name");
	if (VALID_STRUCT(blk_major_name)) {
		MEMBER_OFFSET_INIT(blk_major_name_next, "blk_major_name", 
			"next");
		MEMBER_OFFSET_INIT(blk_major_name_name, "blk_major_name", 
			"name");
		MEMBER_OFFSET_INIT(blk_major_name_major, "blk_major_name", 
			"major");
	}

	STRUCT_SIZE_INIT(kmem_slab_s, "kmem_slab_s");
	STRUCT_SIZE_INIT(slab_s, "slab_s");
	STRUCT_SIZE_INIT(slab, "slab");
	STRUCT_SIZE_INIT(kmem_cache_s, "kmem_cache_s");
	STRUCT_SIZE_INIT(pgd_t, "pgd_t");

        if (!VALID_STRUCT(kmem_slab_s) && VALID_STRUCT(slab_s)) {
                vt->flags |= PERCPU_KMALLOC_V1;
		MEMBER_OFFSET_INIT(kmem_cache_s_num, "kmem_cache_s", "num");
		MEMBER_OFFSET_INIT(kmem_cache_s_next, "kmem_cache_s", "next");
		MEMBER_OFFSET_INIT(kmem_cache_s_name, "kmem_cache_s", "name");
		MEMBER_OFFSET_INIT(kmem_cache_s_objsize,  
			"kmem_cache_s", "objsize");
		MEMBER_OFFSET_INIT(kmem_cache_s_flags, "kmem_cache_s", "flags");
		MEMBER_OFFSET_INIT(kmem_cache_s_gfporder,  
			"kmem_cache_s", "gfporder");
		MEMBER_OFFSET_INIT(kmem_cache_s_slabs,  
			"kmem_cache_s", "slabs");
                MEMBER_OFFSET_INIT(kmem_cache_s_slabs_full,
			"kmem_cache_s", "slabs_full");
                MEMBER_OFFSET_INIT(kmem_cache_s_slabs_partial, 
			"kmem_cache_s", "slabs_partial");
                MEMBER_OFFSET_INIT(kmem_cache_s_slabs_free,  
			"kmem_cache_s", "slabs_free");
		MEMBER_OFFSET_INIT(kmem_cache_s_cpudata, 
			"kmem_cache_s", "cpudata");
                ARRAY_LENGTH_INIT(len, NULL, "kmem_cache_s.cpudata", NULL, 0);
		MEMBER_OFFSET_INIT(kmem_cache_s_colour_off, 
			"kmem_cache_s", "colour_off");

		MEMBER_OFFSET_INIT(slab_s_list, "slab_s", "list");
		MEMBER_OFFSET_INIT(slab_s_s_mem, "slab_s", "s_mem");
		MEMBER_OFFSET_INIT(slab_s_inuse, "slab_s", "inuse");
		MEMBER_OFFSET_INIT(slab_s_free, "slab_s", "free");

		MEMBER_OFFSET_INIT(cpucache_s_avail, "cpucache_s", "avail");
		MEMBER_OFFSET_INIT(cpucache_s_limit, "cpucache_s", "limit");

		STRUCT_SIZE_INIT(cpucache_s, "cpucache_s");

        } else if (!VALID_STRUCT(kmem_slab_s) && 
		   !VALID_STRUCT(slab_s) && VALID_STRUCT(slab)) {
                vt->flags |= PERCPU_KMALLOC_V2;

		if (VALID_STRUCT(kmem_cache_s)) {
			MEMBER_OFFSET_INIT(kmem_cache_s_num, "kmem_cache_s", "num");
			MEMBER_OFFSET_INIT(kmem_cache_s_next, "kmem_cache_s", "next");
			MEMBER_OFFSET_INIT(kmem_cache_s_name, "kmem_cache_s", "name");
			MEMBER_OFFSET_INIT(kmem_cache_s_colour_off, "kmem_cache_s", 
				"colour_off");
			MEMBER_OFFSET_INIT(kmem_cache_s_objsize,  "kmem_cache_s", 
				"objsize");
			MEMBER_OFFSET_INIT(kmem_cache_s_flags, "kmem_cache_s", "flags");
			MEMBER_OFFSET_INIT(kmem_cache_s_gfporder,  
				"kmem_cache_s", "gfporder");

			MEMBER_OFFSET_INIT(kmem_cache_s_lists, "kmem_cache_s", "lists");
			MEMBER_OFFSET_INIT(kmem_cache_s_array, "kmem_cache_s", "array");
			ARRAY_LENGTH_INIT(len, NULL, "kmem_cache_s.array", NULL, 0);
		} else {
			STRUCT_SIZE_INIT(kmem_cache_s, "kmem_cache");
			MEMBER_OFFSET_INIT(kmem_cache_s_num, "kmem_cache", "num");
			MEMBER_OFFSET_INIT(kmem_cache_s_next, "kmem_cache", "next");
			MEMBER_OFFSET_INIT(kmem_cache_s_name, "kmem_cache", "name");
			MEMBER_OFFSET_INIT(kmem_cache_s_colour_off, "kmem_cache", 
				"colour_off");
			if (MEMBER_EXISTS("kmem_cache", "objsize"))
				MEMBER_OFFSET_INIT(kmem_cache_s_objsize, "kmem_cache", 
					"objsize");
			else if (MEMBER_EXISTS("kmem_cache", "buffer_size"))
				MEMBER_OFFSET_INIT(kmem_cache_s_objsize, "kmem_cache", 
					"buffer_size");
			MEMBER_OFFSET_INIT(kmem_cache_s_flags, "kmem_cache", "flags");
			MEMBER_OFFSET_INIT(kmem_cache_s_gfporder,  
				"kmem_cache", "gfporder");

			if (MEMBER_EXISTS("kmem_cache", "lists"))
				MEMBER_OFFSET_INIT(kmem_cache_s_lists, "kmem_cache", "lists");
			else if (MEMBER_EXISTS("kmem_cache", "nodelists")) {
                		vt->flags |= PERCPU_KMALLOC_V2_NODES;
				MEMBER_OFFSET_INIT(kmem_cache_s_lists, "kmem_cache", "nodelists");
				ARRAY_LENGTH_INIT(vt->kmem_cache_len_nodes, NULL, 
					"kmem_cache.nodelists", NULL, 0);
			}
			MEMBER_OFFSET_INIT(kmem_cache_s_array, "kmem_cache", "array");
			ARRAY_LENGTH_INIT(len, NULL, "kmem_cache.array", NULL, 0);
		}
		MEMBER_OFFSET_INIT(slab_list, "slab", "list");
		MEMBER_OFFSET_INIT(slab_s_mem, "slab", "s_mem");
		MEMBER_OFFSET_INIT(slab_inuse, "slab", "inuse");
		MEMBER_OFFSET_INIT(slab_free, "slab", "free");

		MEMBER_OFFSET_INIT(array_cache_avail, "array_cache", "avail");
		MEMBER_OFFSET_INIT(array_cache_limit, "array_cache", "limit");
		STRUCT_SIZE_INIT(array_cache, "array_cache");

		MEMBER_OFFSET_INIT(kmem_list3_slabs_partial, 
			"kmem_list3", "slabs_partial");
		MEMBER_OFFSET_INIT(kmem_list3_slabs_full, 
			"kmem_list3", "slabs_full");
		MEMBER_OFFSET_INIT(kmem_list3_slabs_free, 
			"kmem_list3", "slabs_free");
		MEMBER_OFFSET_INIT(kmem_list3_free_objects, 
			"kmem_list3", "free_objects");
		MEMBER_OFFSET_INIT(kmem_list3_shared, "kmem_list3", "shared");
	} else if (MEMBER_EXISTS("kmem_cache", "cpu_slab") &&
		STRUCT_EXISTS("kmem_cache_node")) {
		vt->flags |= KMALLOC_SLUB;
	} else {
		MEMBER_OFFSET_INIT(kmem_cache_s_c_nextp,  
			"kmem_cache_s", "c_nextp");
		MEMBER_OFFSET_INIT(kmem_cache_s_c_name,   
			"kmem_cache_s", "c_name");
		MEMBER_OFFSET_INIT(kmem_cache_s_c_num,   
			"kmem_cache_s", "c_num");
		MEMBER_OFFSET_INIT(kmem_cache_s_c_org_size,   
			"kmem_cache_s", "c_org_size");
		MEMBER_OFFSET_INIT(kmem_cache_s_c_flags,   
			"kmem_cache_s", "c_flags");
		MEMBER_OFFSET_INIT(kmem_cache_s_c_offset,   
			"kmem_cache_s", "c_offset");
		MEMBER_OFFSET_INIT(kmem_cache_s_c_firstp,   
			"kmem_cache_s", "c_firstp");
		MEMBER_OFFSET_INIT(kmem_cache_s_c_gfporder,  
			"kmem_cache_s", "c_gfporder");
		MEMBER_OFFSET_INIT(kmem_cache_s_c_magic,  
			"kmem_cache_s", "c_magic");
		MEMBER_OFFSET_INIT(kmem_cache_s_c_align,  
			"kmem_cache_s", "c_align");
	
		MEMBER_OFFSET_INIT(kmem_slab_s_s_nextp,   
			"kmem_slab_s", "s_nextp");
		MEMBER_OFFSET_INIT(kmem_slab_s_s_freep,   
			"kmem_slab_s", "s_freep");
		MEMBER_OFFSET_INIT(kmem_slab_s_s_inuse,   
			"kmem_slab_s", "s_inuse");
		MEMBER_OFFSET_INIT(kmem_slab_s_s_mem,   
			"kmem_slab_s", "s_mem");
		MEMBER_OFFSET_INIT(kmem_slab_s_s_index,   
			"kmem_slab_s", "s_index");
		MEMBER_OFFSET_INIT(kmem_slab_s_s_offset,   
			"kmem_slab_s", "s_offset");
		MEMBER_OFFSET_INIT(kmem_slab_s_s_magic,   
			"kmem_slab_s", "s_magic");
	}

	if (!kt->kernel_NR_CPUS) {
		kt->kernel_NR_CPUS = ARRAY_LENGTH(kmem_cache_s_cpudata) ?
			ARRAY_LENGTH(kmem_cache_s_cpudata) : 
			ARRAY_LENGTH(kmem_cache_s_array);
	}
		
        if (kt->kernel_NR_CPUS > NR_CPUS) {
		error(WARNING, 
		    "kernel-configured NR_CPUS (%d) greater than compiled-in NR_CPUS (%d)\n",
			kt->kernel_NR_CPUS, NR_CPUS);
		error(FATAL, "recompile crash with larger NR_CPUS\n");
	}

	if (machdep->init_kernel_pgd)
		machdep->init_kernel_pgd();
	else if (symbol_exists("swapper_pg_dir")) {
		value1 = symbol_value("swapper_pg_dir");
		for (i = 0; i < NR_CPUS; i++)
			vt->kernel_pgd[i] = value1;
	} else if (symbol_exists("cpu_pgd")) {
                len = get_array_length("cpu_pgd", &dimension, 0);
		if ((len == NR_CPUS) && (dimension == machdep->ptrs_per_pgd)) {
			value1 = symbol_value("cpu_pgd");
			for (i = 0; i < NR_CPUS; i++) {
				value2 = i * 
				        (SIZE(pgd_t) * machdep->ptrs_per_pgd);
				vt->kernel_pgd[i] = value1 + value2;
			}
			error(WARNING, 
                  "no swapper_pg_dir: using first entry of cpu_pgd[%d][%d]\n\n",
				dimension, len);
		} else {
			error(WARNING, 
                            "unrecognized dimensions: cpu_pgd[%d][%d]\n",
				dimension, len);
			value1 = symbol_value("cpu_pgd");
			for (i = 0; i < NR_CPUS; i++)
				vt->kernel_pgd[i] = value1;
			error(WARNING, 
                  "no swapper_pg_dir: using first entry of cpu_pgd[%d][%d]\n\n",
				dimension, len);

		}
	} else
		error(FATAL, "no swapper_pg_dir or cpu_pgd symbols exist?\n");

	get_symbol_data("high_memory", sizeof(ulong), &vt->high_memory);

	if (kernel_symbol_exists("mem_map")) {
		get_symbol_data("mem_map", sizeof(char *), &vt->mem_map);
		vt->flags |= FLATMEM;
	} else if (kernel_symbol_exists("mem_section"))
		vt->flags |= SPARSEMEM;
	else
		vt->flags |= DISCONTIGMEM;

	sparse_mem_init();

	vt->vmalloc_start = machdep->vmalloc_start();
	if (IS_VMALLOC_ADDR(vt->mem_map))
		vt->flags |= V_MEM_MAP;
	vt->total_pages = BTOP(VTOP(vt->high_memory));
	switch (get_syment_array("totalram_pages", sp_array, 2)) 
	{
	case 1:
		get_symbol_data("totalram_pages", sizeof(ulong), 
			&vt->totalram_pages);
		break;
	case 2:
		if (!(readmem(sp_array[0]->value, KVADDR, 
		    &value1, sizeof(ulong), 
		    "totalram_pages #1", RETURN_ON_ERROR)))
			break;
                if (!(readmem(sp_array[1]->value, KVADDR,
                    &value2, sizeof(ulong), 
		    "totalram_pages #2", RETURN_ON_ERROR)))
                        break;
		vt->totalram_pages = MAX(value1, value2);
		break;
	}

	if (symbol_exists("totalhigh_pages")) {
	        switch (get_syment_array("totalhigh_pages", sp_array, 2))
	        {
	        case 1:
	                get_symbol_data("totalhigh_pages", sizeof(ulong),
	                        &vt->totalhigh_pages);
	                break;
	        case 2:
	                if (!(readmem(sp_array[0]->value, KVADDR,
	                    &value1, sizeof(ulong),
	                    "totalhigh_pages #1", RETURN_ON_ERROR)))
	                        break;
	                if (!(readmem(sp_array[1]->value, KVADDR,
	                    &value2, sizeof(ulong),
	                    "totalhigh_pages #2", RETURN_ON_ERROR)))
	                        break;
	                vt->totalhigh_pages = MAX(value1, value2);
	                break;
	        }
		vt->total_pages += vt->totalhigh_pages;
	}

	if (symbol_exists("num_physpages"))
        	get_symbol_data("num_physpages", sizeof(ulong), 
			&vt->num_physpages);

	if (kernel_symbol_exists("mem_map"))
        	get_symbol_data("max_mapnr", sizeof(ulong), &vt->max_mapnr);
	get_symbol_data("nr_swapfiles", sizeof(unsigned int), 
		&vt->nr_swapfiles);

	STRUCT_SIZE_INIT(page, "page");
	STRUCT_SIZE_INIT(free_area, "free_area");
	STRUCT_SIZE_INIT(free_area_struct, "free_area_struct");
	STRUCT_SIZE_INIT(zone, "zone");
	STRUCT_SIZE_INIT(zone_struct, "zone_struct");
	STRUCT_SIZE_INIT(kmem_bufctl_t, "kmem_bufctl_t");
	STRUCT_SIZE_INIT(swap_info_struct, "swap_info_struct");
	STRUCT_SIZE_INIT(mm_struct, "mm_struct");
	STRUCT_SIZE_INIT(vm_area_struct, "vm_area_struct");
	STRUCT_SIZE_INIT(pglist_data, "pglist_data");

	if (VALID_STRUCT(pglist_data)) {
		vt->flags |= ZONES;

		if (symbol_exists("pgdat_list") && !IS_SPARSEMEM()) 
			vt->flags |= NODES;

		/*
		 *  Determine the number of nodes the best way possible,
		 *  starting with a default of 1.
		 */
		vt->numnodes = 1;

		if (symbol_exists("numnodes"))
			get_symbol_data("numnodes", sizeof(int), &vt->numnodes);

		if ((vt->numnodes = get_nodes_online()))
			vt->flags |= NODES_ONLINE;

		MEMBER_OFFSET_INIT(pglist_data_node_zones, 
			"pglist_data", "node_zones");
		MEMBER_OFFSET_INIT(pglist_data_node_mem_map, 
			"pglist_data", "node_mem_map");
		MEMBER_OFFSET_INIT(pglist_data_node_start_paddr, 
			"pglist_data", "node_start_paddr");
		MEMBER_OFFSET_INIT(pglist_data_node_start_mapnr, 
			"pglist_data", "node_start_mapnr");
		MEMBER_OFFSET_INIT(pglist_data_node_size, 
			"pglist_data", "node_size");
		MEMBER_OFFSET_INIT(pglist_data_node_id, 
			"pglist_data", "node_id");
		MEMBER_OFFSET_INIT(pglist_data_node_next, 
			"pglist_data", "node_next");
		MEMBER_OFFSET_INIT(pglist_data_bdata, "pglist_data", "bdata");
		MEMBER_OFFSET_INIT(pglist_data_nr_zones, "pglist_data", 
			"nr_zones");
		MEMBER_OFFSET_INIT(pglist_data_node_start_pfn, "pglist_data", 
			"node_start_pfn");
		MEMBER_OFFSET_INIT(pglist_data_pgdat_next, "pglist_data", 
			"pgdat_next");
		MEMBER_OFFSET_INIT(pglist_data_node_present_pages, 
			"pglist_data", "node_present_pages");
		MEMBER_OFFSET_INIT(pglist_data_node_spanned_pages, 
			"pglist_data", "node_spanned_pages");
		ARRAY_LENGTH_INIT(vt->nr_zones, pglist_data_node_zones,
			"pglist_data.node_zones", NULL, 
			SIZE_OPTION(zone_struct, zone));
		vt->ZONE_HIGHMEM = vt->nr_zones - 1;

		if (VALID_STRUCT(zone_struct)) {
	                MEMBER_OFFSET_INIT(zone_struct_free_pages, 
	                        "zone_struct", "free_pages");
	                MEMBER_OFFSET_INIT(zone_struct_free_area, 
	                        "zone_struct", "free_area");
	                MEMBER_OFFSET_INIT(zone_struct_zone_pgdat, 
	                        "zone_struct", "zone_pgdat");
	                MEMBER_OFFSET_INIT(zone_struct_name, "zone_struct", 
				"name");
	                MEMBER_OFFSET_INIT(zone_struct_size, "zone_struct", 
				"size");
			if (INVALID_MEMBER(zone_struct_size))
	                	MEMBER_OFFSET_INIT(zone_struct_memsize, 
					"zone_struct", "memsize");
			MEMBER_OFFSET_INIT(zone_struct_zone_start_pfn,
				"zone_struct", "zone_start_pfn");
	                MEMBER_OFFSET_INIT(zone_struct_zone_start_paddr,  
	                        "zone_struct", "zone_start_paddr");
	                MEMBER_OFFSET_INIT(zone_struct_zone_start_mapnr, 
	                        "zone_struct", "zone_start_mapnr");
	                MEMBER_OFFSET_INIT(zone_struct_zone_mem_map, 
	                        "zone_struct", "zone_mem_map");
	                MEMBER_OFFSET_INIT(zone_struct_inactive_clean_pages, 
	                        "zone_struct", "inactive_clean_pages");
	                MEMBER_OFFSET_INIT(zone_struct_inactive_clean_list, 
	                        "zone_struct", "inactive_clean_list");
	        	ARRAY_LENGTH_INIT(vt->nr_free_areas, 
				zone_struct_free_area, "zone_struct.free_area",
				NULL, SIZE(free_area_struct));
	                MEMBER_OFFSET_INIT(zone_struct_inactive_dirty_pages,
	                        "zone_struct", "inactive_dirty_pages");
	                MEMBER_OFFSET_INIT(zone_struct_active_pages,
	                        "zone_struct", "active_pages");
	                MEMBER_OFFSET_INIT(zone_struct_pages_min,
	                        "zone_struct", "pages_min");
	                MEMBER_OFFSET_INIT(zone_struct_pages_low,
	                        "zone_struct", "pages_low");
	                MEMBER_OFFSET_INIT(zone_struct_pages_high,
	                        "zone_struct", "pages_high");
                	vt->dump_free_pages = dump_free_pages_zones_v1;

		} else if (VALID_STRUCT(zone)) {
			MEMBER_OFFSET_INIT(zone_vm_stat, "zone", "vm_stat");
			MEMBER_OFFSET_INIT(zone_free_pages, "zone", "free_pages");
			if (INVALID_MEMBER(zone_free_pages) && 
			    VALID_MEMBER(zone_vm_stat)) {
				long nr_free_pages = 0;
				if (!enumerator_value("NR_FREE_PAGES", &nr_free_pages))
					error(WARNING, 
					    "cannot determine NR_FREE_PAGES enumerator\n");
				ASSIGN_OFFSET(zone_free_pages) = OFFSET(zone_vm_stat) + 
					(nr_free_pages * sizeof(long));
			}
                        MEMBER_OFFSET_INIT(zone_free_area,
                                "zone", "free_area");
                        MEMBER_OFFSET_INIT(zone_zone_pgdat,
                                "zone", "zone_pgdat");
                        MEMBER_OFFSET_INIT(zone_name, "zone",
                                "name");
	                MEMBER_OFFSET_INIT(zone_zone_mem_map, 
	                        "zone", "zone_mem_map");
                        MEMBER_OFFSET_INIT(zone_zone_start_pfn,
                                "zone", "zone_start_pfn");
                        MEMBER_OFFSET_INIT(zone_spanned_pages,
                                "zone", "spanned_pages");
                        MEMBER_OFFSET_INIT(zone_pages_min,
                                "zone", "pages_min");
                        MEMBER_OFFSET_INIT(zone_pages_low,
                                "zone", "pages_low");
                        MEMBER_OFFSET_INIT(zone_pages_high,
                                "zone", "pages_high");
	        	ARRAY_LENGTH_INIT(vt->nr_free_areas, zone_free_area,
				"zone.free_area", NULL, SIZE(free_area));
                	vt->dump_free_pages = dump_free_pages_zones_v2;
		}
	} else
		vt->numnodes = 1;

	node_table_init();

	sprintf(buf, "%llx", (ulonglong) 
		MAX((uint64_t)vt->max_mapnr * PAGESIZE(), 
		machdep->memory_size()));
	vt->paddr_prlen = strlen(buf);

	if (vt->flags & PERCPU_KMALLOC_V1) 
                vt->dump_kmem_cache = dump_kmem_cache_percpu_v1;
	else if (vt->flags & PERCPU_KMALLOC_V2) 
                vt->dump_kmem_cache = dump_kmem_cache_percpu_v2;
	else if (vt->flags & KMALLOC_SLUB)
		vt->flags |= KMEM_CACHE_UNAVAIL;  /* TBD */
	else 
                vt->dump_kmem_cache = dump_kmem_cache;

        if (!(vt->flags & (NODES|ZONES))) {
        	get_array_length("free_area", &dimension, 0);
        	if (dimension) 
                	vt->dump_free_pages = dump_multidimensional_free_pages;
		else
                	vt->dump_free_pages = dump_free_pages;
        }

        if (!(vt->vma_cache = (char *)malloc(SIZE(vm_area_struct)*VMA_CACHE)))
                error(FATAL, "cannot malloc vm_area_struct cache\n");

        if (symbol_exists("page_hash_bits")) {
		unsigned int page_hash_bits;
               	get_symbol_data("page_hash_bits", sizeof(unsigned int),
               		&page_hash_bits);
               	len = (1 << page_hash_bits);
               	builtin_array_length("page_hash_table", len, NULL);
               	get_symbol_data("page_hash_table", sizeof(void *),
               		&vt->page_hash_table);
               	vt->page_hash_table_len = len;
		 
		STRUCT_SIZE_INIT(page_cache_bucket, "page_cache_bucket");
		if (VALID_STRUCT(page_cache_bucket))
			MEMBER_OFFSET_INIT(page_cache_bucket_chain, 
				"page_cache_bucket", "chain");
        } else if (symbol_exists("page_hash_table")) {
                vt->page_hash_table = symbol_value("page_hash_table");
                vt->page_hash_table_len = 0;
        } else if (CRASHDEBUG(1))
		error(NOTE, "page_hash_table does not exist in this kernel\n");

	kmem_cache_init();

	PG_reserved_flag_init();
	PG_slab_flag_init();
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
	ulonglong addr, endaddr;
	ulong offset;
	struct syment *sp;

	flag = HEXADECIMAL|DISPLAY_DEFAULT;
	endaddr = 0;
	memtype = KVADDR;
	count = -1;

        while ((c = getopt(argcnt, args, "xme:pfudDuso:81:3:6:")) != EOF) {
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
			endaddr = htoll(optarg, FAULT_ON_ERROR, NULL);
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
			memtype &= ~(UVADDR|KVADDR|XENMACHADDR|FILEADDR);
			memtype = PHYSADDR;
			break;

		case 'u':
			memtype &= ~(KVADDR|PHYSADDR|XENMACHADDR|FILEADDR);
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

		case 'm':
                	if (!(kt->flags & ARCH_XEN))
                        	error(FATAL, "-m option only applies to xen architecture\n");
			memtype &= ~(UVADDR|KVADDR|FILEADDR);
			memtype = XENMACHADDR;
			break;

		case 'f':
			if (!pc->dumpfile)
				error(FATAL, 
					"-f option requires a dumpfile\n");
			memtype &= ~(KVADDR|UVADDR|PHYSADDR|XENMACHADDR);
			memtype = FILEADDR;
			break;

		case 'x':
                        flag |= NO_ASCII;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs || !args[optind])
		cmd_usage(pc->curcmd, SYNOPSIS);

        if (*args[optind] == '(') 
                addr = evall(args[optind], FAULT_ON_ERROR, NULL);
	else if (hexadecimal(args[optind], 0)) 
                addr = htoll(args[optind], FAULT_ON_ERROR, NULL);
        else if ((sp = symbol_search(args[optind])))
                addr = (ulonglong)sp->value;
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
				error(FATAL, "invalid ending address: %llx\n",
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

	if ((flag & HEXADECIMAL) && !(flag & SYMBOLIC) && !(flag & NO_ASCII))
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

/* line locations where ASCII output starts */
#define ASCII_START_8   (51 + VADDR_PRLEN)
#define ASCII_START_16  (43 + VADDR_PRLEN)
#define ASCII_START_32  (39 + VADDR_PRLEN)
#define ASCII_START_64  (37 + VADDR_PRLEN)

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
display_memory(ulonglong addr, long count, ulong flag, int memtype)
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
	int ascii_start;
	char *hex_64_fmt = BITS32() ? "%.*llx " : "%.*lx ";
	char *dec_64_fmt = BITS32() ? "%12lld " : "%15ld ";
	char *dec_u64_fmt = BITS32() ? "%12llu " : "%20lu ";

	if (count <= 0) 
		error(FATAL, "invalid count request: %ld\n", count);

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
	case XENMACHADDR:
		addrtype = "XENMACHADDR";
		break;
	case FILEADDR:
		addrtype = "FILEADDR";
		break;
	}

	if (CRASHDEBUG(4))
		fprintf(fp, "<addr: %llx count: %ld flag: %lx (%s)>\n", 
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
		location = &mem.u32;
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
			fprintf(fp, "%s:  ",
				mkstring(buf, VADDR_PRLEN, RJUST|LONGLONG_HEX,
                                MKSTR(&addr)));
			hx = 0;
			BZERO(hexchars, MAX_HEXCHARS_PER_LINE+1);
			linelen = VADDR_PRLEN + strlen(":  ");
                }

	        switch (flag & DISPLAY_TYPES)
	        {
	        case DISPLAY_64:
			if ((flag & (HEXADECIMAL|SYMBOLIC|DISPLAY_DEFAULT)) ==
			    (HEXADECIMAL|SYMBOLIC|DISPLAY_DEFAULT)) {
				if (in_ksymbol_range(mem.u64) &&
				    strlen(value_to_symstr(mem.u64, buf, 0))) {
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
				if (in_ksymbol_range(mem.u32) &&
				    strlen(value_to_symstr(mem.u32, buf, 0))) {
					fprintf(fp, INT_PRLEN == 16 ? 
					    "%-16s " : "%-8s ",
                                                value_to_symstr(mem.u32,
						                buf, 0));
					linelen += strlen(buf)+1;
					break;
				}
                        }
			if (flag & HEXADECIMAL) {
				fprintf(fp, "%.*x ", INT_PRLEN, mem.u32 );
				linelen += (INT_PRLEN + 1);
			}
                        else if (flag & DECIMAL)
                                fprintf(fp, "%12d ", mem.u32 );
                        else if (flag & UDECIMAL)
                                fprintf(fp, "%12u ", mem.u32 );
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
			char* ptr;
	                switch (flag & DISPLAY_TYPES)
	                {
	                case DISPLAY_64:
				ptr = (char*)&mem.u64;
		                for (j = 0; j < SIZEOF_64BIT; j++) {
					ch = ptr[j];
		                        if ((ch >= 0x20) && (ch < 0x7f)) {
		                                hexchars[hx++] = ch;
		                        }
		                        else {
						hexchars[hx++] = '.';
					}
		                }
	                        break;
	
	                case DISPLAY_32:
				ptr = (char*)&mem.u32;
	                        for (j = 0; j < (SIZEOF_32BIT); j++) {
					ch = ptr[j];
	                                if ((ch >= 0x20) && (ch < 0x7f)) {
	                                        hexchars[hx++] = ch;
	                                } else {
						hexchars[hx++] = '.';
					}
	                        }
	                        break;
	
	                case DISPLAY_16:
				ptr = (char*)&mem.u16;
	                        for (j = 0; j < SIZEOF_16BIT; j++) {
					ch = ptr[j];
	                                if ((ch >= 0x20) && (ch < 0x7f)) {
	                                        hexchars[hx++] = ch;
	                                } else {
						hexchars[hx++] = '.';
					}
	                        }
	                        break;
	
	                case DISPLAY_8:
				ptr = (char*)&mem.u8;
	                        for (j = 0; j < SIZEOF_8BIT; j++) {
	                                ch = ptr[j];
	                                if ((ch >= 0x20) && (ch < 0x7f)) {
	                                        hexchars[hx++] = ch;
	                                } else {
						hexchars[hx++] = '.';
					}
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
	ulonglong value; 
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
	size = sizeof(void*);
	addr_entered = value_entered = FALSE;

        while ((c = getopt(argcnt, args, "fukp81:3:6:")) != EOF) {
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
			memtype &= ~(UVADDR|KVADDR|FILEADDR);
			memtype = PHYSADDR;
			break;

		case 'u':
			memtype &= ~(PHYSADDR|KVADDR|FILEADDR);
			memtype = UVADDR;
			break;

		case 'k':
			memtype &= ~(PHYSADDR|UVADDR|FILEADDR);
			memtype = KVADDR;
			break;

		case 'f':   
			/*  
			 *  Unsupported, but can be forcibly implemented
			 *  by removing the DUMPFILE() check above and
		 	 *  recompiling.
			 */
			if (!pc->dumpfile)
				error(FATAL, 
					"-f option requires a dumpfile\n");
			memtype &= ~(PHYSADDR|UVADDR|KVADDR);
			memtype = FILEADDR;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

        if (args[optind]) {
        	if (*args[optind] == '(')
                	addr = evall(args[optind], FAULT_ON_ERROR, NULL);
		else if (hexadecimal(args[optind], 0)) 
                        addr = htoll(args[optind], FAULT_ON_ERROR, NULL);
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
			error(INFO, "invalid user virtual address: %llx\n", 
				addr);
                	cmd_usage(pc->curcmd, SYNOPSIS);
		}
		break;

	case KVADDR:
		if (!IS_KVADDR(addr)) {
			error(INFO, "invalid kernel virtual address: %llx\n",
				addr);
               		cmd_usage(pc->curcmd, SYNOPSIS);
		}
		break;

	case PHYSADDR:
		break;

	case FILEADDR:
		break;

	case AMBIGUOUS:	
		error(INFO, 
		    "ambiguous address: %llx  (requires -p, -u or -k)\n",
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
raw_stack_dump(ulong stackbase, ulong size)
{
	display_memory(stackbase, size/sizeof(ulong), 
	    	HEXADECIMAL|DISPLAY_DEFAULT|SYMBOLIC, KVADDR);
}

/*
 *  Raw data dump, with the option of symbolic output.
 */
void
raw_data_dump(ulong addr, long count, int symbolic)
{
	long wordcnt;
	ulonglong address;
	int memtype;

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

	if (pc->curcmd_flags & MEMTYPE_FILEADDR) {
		address = pc->curcmd_private;
		memtype = FILEADDR;
	} else if (pc->curcmd_flags & MEMTYPE_UVADDR) {
		address = (ulonglong)addr;
		memtype = UVADDR;
	} else {
		address = (ulonglong)addr;
		memtype = KVADDR;
	}

	display_memory(address, wordcnt, 
 	    HEXADECIMAL|DISPLAY_DEFAULT|(symbolic ? SYMBOLIC : ASCII_ENDLINE),
		memtype);
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
 *      memtype  addr type: UVADDR, KVADDR, PHYSADDR, XENMACHADDR or FILEADDR 
 *       buffer  supplied buffer to read the data into.
 *         size  number of bytes to read.
 *         type  string describing the request -- helpful when the read fails.
 * error_handle  what to do if the read fails: FAULT_ON_ERROR kills the command
 *               immediately; RETURN_ON_ERROR returns FALSE; QUIET suppresses
 *               the error message.
 */

#define PRINT_ERROR_MESSAGE ((!(error_handle & QUIET)) || CRASHDEBUG(1))

#define INVALID_UVADDR   "invalid user virtual address: %llx  type: \"%s\"\n"
#define INVALID_KVADDR   "invalid kernel virtual address: %llx  type: \"%s\"\n"

#define SEEK_ERRMSG      "seek error: %s address: %llx  type: \"%s\"\n"
#define READ_ERRMSG      "read error: %s address: %llx  type: \"%s\"\n"
#define WRITE_ERRMSG     "write error: %s address: %llx  type: \"%s\"\n"
#define PAGE_EXCLUDED_ERRMSG  "page excluded: %s address: %llx  type: \"%s\"\n"

int
readmem(ulonglong addr, int memtype, void *buffer, long size,
	char *type, ulong error_handle)
{
	int fd;
	long cnt;
	physaddr_t paddr;
	ulonglong pseudo;
	char *bufptr;

	if (CRASHDEBUG(4))
		fprintf(fp, "<readmem: %llx, %s, \"%s\", %ld, %s, %lx>\n", 
			addr, memtype_string(memtype, 1), type, size, 
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
                if (LKCD_DUMPFILE())
                    	addr = fix_lkcd_address(addr);

                if (!IS_KVADDR(addr)) {
                        if (PRINT_ERROR_MESSAGE)
                                error(INFO, INVALID_KVADDR, addr, type);
                        goto readmem_error;
                }
                break;

        case PHYSADDR:
	case XENMACHADDR:
                break;

	case FILEADDR:
		return generic_read_dumpfile(addr, buffer, size, type, error_handle);
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

		case XENMACHADDR:
			pseudo = xen_m2p(addr);

                	if (pseudo == XEN_MACHADDR_NOT_FOUND) {
                        	pc->curcmd_flags |= XEN_MACHINE_ADDR;
				paddr = addr;  
                	} else
                        	paddr = pseudo | PAGEOFFSET(addr);

			break;
		}

		/* 
		 *  Compute bytes till end of page.
		 */
		cnt = PAGESIZE() - PAGEOFFSET(paddr); 

                if (cnt > size)
                        cnt = size;

		switch (READMEM(fd, bufptr, cnt, 
		    (memtype == PHYSADDR) || (memtype == XENMACHADDR) ? 0 : addr, paddr))
		{
		case SEEK_ERROR:
                        if (PRINT_ERROR_MESSAGE)
                        	error(INFO, SEEK_ERRMSG, memtype_string(memtype, 0), addr, type);
                        goto readmem_error;

		case READ_ERROR:
                        if (PRINT_ERROR_MESSAGE)
                        	error(INFO, READ_ERRMSG, memtype_string(memtype, 0), addr, type);
                        goto readmem_error;

		case PAGE_EXCLUDED:
                        if (PRINT_ERROR_MESSAGE)
                        	error(INFO, PAGE_EXCLUDED_ERRMSG, memtype_string(memtype, 0), addr, type);
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
 *  Accept anything...
 */
int
generic_verify_paddr(physaddr_t paddr)
{
	return TRUE;
}

/*
 *  Read from /dev/mem.
 */
int
read_dev_mem(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr) 
{
	int readcnt;

	if (!machdep->verify_paddr(paddr)) {
		if (CRASHDEBUG(1))
			error(INFO, "verify_paddr(%lx) failed\n", paddr);
		return READ_ERROR;
	}

	/*
	 *  /dev/mem disallows anything >= __pa(high_memory)
	 *
         *  However it will allow 64-bit lseeks to anywhere, and when followed
	 *  by pulling a 32-bit address from the 64-bit file position, it
	 *  quietly returns faulty data from the (wrapped-around) address.
  	 */
	if (vt->high_memory && (paddr >= (physaddr_t)(VTOP(vt->high_memory)))) {
		readcnt = 0;
		errno = 0;
		goto try_dev_kmem;
	}

	if (lseek(fd, (off_t)paddr, SEEK_SET) == -1) 
		return SEEK_ERROR;

next_read:
        errno = 0;
        readcnt = read(fd, bufptr, cnt);

	if ((readcnt != cnt) && CRASHDEBUG(4)) {
		if (errno)
			perror("/dev/mem");
		error(INFO, "read(/dev/mem, %lx, %ld): %ld (%lx)\n",
			paddr, cnt, readcnt, readcnt);	
	}

try_dev_kmem:
        /*
         *  On 32-bit intel architectures high memory can can only be accessed
	 *  via vmalloc'd addresses.  However, /dev/mem returns 0 bytes, and
	 *  non-reserved memory pages can't be mmap'd, so the only alternative
	 *  is to read it from /dev/kmem.
         */
        if ((readcnt != cnt) && BITS32() && !readcnt && !errno && 
	    IS_VMALLOC_ADDR(addr))
                readcnt = read_dev_kmem(addr, bufptr, cnt);

	/*
	 *  The 2.6 valid_phys_addr_range() can potentially shorten the 
	 *  count of a legitimate read request.  So far this has only been
	 *  seen on an ia64 where a kernel page straddles an EFI segment.
	 */
	if ((readcnt != cnt) && readcnt && (machdep->flags & DEVMEMRD) && 
	     !errno) {
		if (CRASHDEBUG(1))
			error(INFO, "read(/dev/mem, %lx, %ld): %ld (%lx)\n",
				paddr, cnt, readcnt, readcnt);	
		cnt -= readcnt;
		bufptr += readcnt;
		goto next_read;
	}

        if (readcnt != cnt) 
		return READ_ERROR;

	return readcnt;
}

/*
 *  Write to /dev/mem.
 */
int
write_dev_mem(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr) 
{
	if (!machdep->verify_paddr(paddr)) {
		if (CRASHDEBUG(1))
			error(INFO, "verify_paddr(%lx) failed\n", paddr);
		return WRITE_ERROR;
	}

        if (lseek(fd, (off_t)paddr, SEEK_SET) == -1) 
		return SEEK_ERROR;

        if (write(fd, bufptr, cnt) != cnt) 
		return WRITE_ERROR;

	return cnt;
}

/*
 *  Read from memory driver.
 */
int
read_memory_device(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	if (pc->curcmd_flags & XEN_MACHINE_ADDR)
		return READ_ERROR;

        if (!machdep->verify_paddr(paddr)) {
                if (CRASHDEBUG(1))
                        error(INFO, "verify_paddr(%lx) failed\n", paddr);
                return READ_ERROR;
        }

        lseek(fd, (loff_t)paddr, SEEK_SET); 

        if (read(fd, bufptr, cnt) != cnt) 
                return READ_ERROR;

        return cnt;
}

/*
 *  Write to memory driver.  
 */
int
write_memory_device(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	if (!(MEMORY_DRIVER_DEVICE_MODE & S_IWUSR))
        	return (error(FATAL, "cannot write to %s!\n", pc->live_memsrc));

        if (lseek(fd, (loff_t)paddr, SEEK_SET) == -1)
                return SEEK_ERROR;

        if (write(fd, bufptr, cnt) != cnt)
                return WRITE_ERROR;

        return cnt;
}

/*
 *  Read from an MCLX formatted dumpfile.
 */
int
read_mclx_dumpfile(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr) 
{
        if (vas_lseek((ulong)paddr, SEEK_SET)) 
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
write_mclx_dumpfile(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
        if (vas_lseek((ulong)paddr, SEEK_SET)) 
        	return SEEK_ERROR;
                                
        if (vas_write((void *)bufptr, cnt) != cnt) 
		return WRITE_ERROR;

	return cnt;
}

/*
 *  Read from an LKCD formatted dumpfile.
 */
int
read_lkcd_dumpfile(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr) 
{
	set_lkcd_fp(fp);

        if (!lkcd_lseek(paddr)) 
		return SEEK_ERROR;
        
        if (lkcd_read((void *)bufptr, cnt) != cnt) 
		return READ_ERROR;

	return cnt;
}

/*
 *  Write to an LKCD formatted dumpfile.  (dummy routine -- not allowed)
 */
int
write_lkcd_dumpfile(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr) 
{
	return (error(FATAL, "cannot write to an LKCD compressed dump!\n"));
}


/*
 *  Read from network daemon.
 */
int
read_daemon(int fd, void *bufptr, int cnt, ulong vaddr, physaddr_t paddr) 
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
write_daemon(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr) 
{
	return (error(FATAL, "writing to daemon not supported yet [TBD]\n"));
}

/*
 *  Turn the memtype bitmask into a string.
 */
static
char *memtype_string(int memtype, int debug)
{
	static char membuf[40];

	switch (memtype)
	{
	case UVADDR:
		sprintf(membuf, debug ? "UVADDR" : "user virtual");
		break;
	case KVADDR:
		sprintf(membuf, debug ? "KVADDR" : "kernel virtual");
		break;
	case PHYSADDR:
		sprintf(membuf, debug ? "PHYSADDR" : "physical");
		break;
	case XENMACHADDR:
		sprintf(membuf, debug ? "XENMACHADDR" : "xen machine");
		break;
	case FILEADDR:
		sprintf(membuf, debug ? "FILEADDR" : "dumpfile");
		break;
	default:
		if (debug)
			sprintf(membuf, "0x%x (?)", memtype);
		else
			sprintf(membuf, "unknown");
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
writemem(ulonglong addr, int memtype, void *buffer, long size,
	char *type, ulong error_handle)
{
	int fd;
	long cnt;
	physaddr_t paddr;
	char *bufptr;

        if (CRASHDEBUG(1))
		fprintf(fp, "writemem: %llx, %s, \"%s\", %ld, %s %lx\n", 
			addr, memtype_string(memtype, 1), type, size, 
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


	case FILEADDR:
		return generic_write_dumpfile(addr, buffer, size, type, error_handle);
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
                                error(INFO, SEEK_ERRMSG, memtype_string(memtype, 0), addr, type);
                        goto writemem_error;
			
		case WRITE_ERROR:
                        if (PRINT_ERROR_MESSAGE)
                                error(INFO, WRITE_ERRMSG, memtype_string(memtype, 0), addr, type);
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
	ssize_t readcnt;

	if (pc->kfd < 0) {
		if ((pc->kfd = open("/dev/kmem", O_RDONLY)) < 0)
			return 0; 
	}

	if (lseek(pc->kfd, vaddr, SEEK_SET) == -1) 
		return 0;

	readcnt = read(pc->kfd, bufptr, cnt);
	if (readcnt != cnt)
		readcnt = 0;

	return readcnt;
}

/*
 *  Generic dumpfile read/write functions to handle FILEADDR 
 *  memtype arguments to readmem() and writemem().  These are
 *  not to be confused with pc->readmem/writemem plug-ins.
 */
static int 
generic_read_dumpfile(ulonglong addr, void *buffer, long size, char *type, 
	ulong error_handle)
{
	int fd;
	int retval;

	retval = TRUE;

	if (!pc->dumpfile)
		error(FATAL, "command requires a dumpfile\n");

	if ((fd = open(pc->dumpfile, O_RDONLY)) < 0)
		error(FATAL, "%s: %s\n", pc->dumpfile,
			strerror(errno));

	if (lseek(fd, addr, SEEK_SET) == -1) {
		if (PRINT_ERROR_MESSAGE)
                	error(INFO, SEEK_ERRMSG, 
				memtype_string(FILEADDR, 0), addr, type);
		retval = FALSE;
	} else if (read(fd, buffer, size) != size) {
		if (PRINT_ERROR_MESSAGE)
			error(INFO, READ_ERRMSG, 
				memtype_string(FILEADDR, 0), addr, type);
		retval = FALSE;
	}

	close(fd);

	return retval;
}

static int 
generic_write_dumpfile(ulonglong addr, void *buffer, long size, char *type, 
	ulong error_handle)
{
	int fd;
	int retval;

	retval = TRUE;

	if (!pc->dumpfile)
		error(FATAL, "command requires a dumpfile\n");

	if ((fd = open(pc->dumpfile, O_WRONLY)) < 0)
		error(FATAL, "%s: %s\n", pc->dumpfile,
			strerror(errno));

	if (lseek(fd, addr, SEEK_SET) == -1) {
		if (PRINT_ERROR_MESSAGE)
                	error(INFO, SEEK_ERRMSG, 
				memtype_string(FILEADDR, 0), addr, type);
		retval = FALSE;
	} else if (write(fd, buffer, size) != size) {
		if (PRINT_ERROR_MESSAGE)
			error(INFO, WRITE_ERRMSG, 
				memtype_string(FILEADDR, 0), addr, type);
		retval = FALSE;
	}

	close(fd);

	return retval;
}

/*
 *  Translates a kernel virtual address to its physical address.  cmd_vtop()
 *  sets the verbose flag so that the pte translation gets displayed; all 
 *  other callers quietly accept the translation.
 */
int
kvtop(struct task_context *tc, ulong kvaddr, physaddr_t *paddr, int verbose)
{
	physaddr_t unused;

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
uvtop(struct task_context *tc, ulong vaddr, physaddr_t *paddr, int verbose)
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
	physaddr_t paddr; 
	ulong vma;
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

	paddr = 0;

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
			fprintf(fp, "%s  %s\n\n", 
				mkstring(buf1, UVADDR_PRLEN, LJUST|LONG_HEX,
				    MKSTR(vaddr)),
				(XEN() && (paddr == PADDR_NOT_AVAILABLE)) ?
				"(page not available)" : "(not mapped)");

			page_exists = FALSE;
		} else {
			fprintf(fp, "%s  %s\n\n",
			    mkstring(buf1, UVADDR_PRLEN, LJUST|LONG_HEX, 
				MKSTR(vaddr)),
			    mkstring(buf2, VADDR_PRLEN, LJUST|LONGLONG_HEX, 
				MKSTR(&paddr)));
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
                        	fprintf(fp, "%s  %s\n\n", 
					mkstring(buf1, UVADDR_PRLEN,
                                        LJUST|LONG_HEX, MKSTR(vaddr)),
					(XEN() && 
					(paddr == PADDR_NOT_AVAILABLE)) ?
					"(page not available)" :
					"(not mapped)");
                        	page_exists = FALSE;
                	} else {
                         	fprintf(fp, "%s  %s\n\n", 
			     		mkstring(buf1, UVADDR_PRLEN, 
					LJUST|LONG_HEX, MKSTR(vaddr)),
                            		mkstring(buf2, VADDR_PRLEN, 
					LJUST|LONGLONG_HEX, MKSTR(&paddr)));
                         	page_exists = TRUE;
                	}
                	uvtop(tc, vaddr, &paddr, VERBOSE);
		} else {
			if (!kvtop(tc, vaddr, &paddr, 0)) {
				fprintf(fp, "%s  %s\n\n", 
					mkstring(buf1, VADDR_PRLEN,
                                        LJUST|LONG_HEX, MKSTR(vaddr)),
					(XEN() && 
					(paddr == PADDR_NOT_AVAILABLE)) ?
					"(page not available)" :
					"(not mapped)");
				page_exists = FALSE;
			} else {
				fprintf(fp, "%s  %s\n\n",
                                        mkstring(buf1, VADDR_PRLEN,
                                        LJUST|LONG_HEX, MKSTR(vaddr)),
                                        mkstring(buf2, VADDR_PRLEN,
                                        LJUST|LONGLONG_HEX, MKSTR(&paddr)));
				page_exists = TRUE;
			}
			kvtop(tc, vaddr, &paddr, VERBOSE);
		}
		break;
	}

	fprintf(fp, "\n");

	if (page_exists) { 
		if ((pc->flags & DEVMEM) && (paddr >= VTOP(vt->high_memory)))
			return;
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
	ulong vaddr;
	physaddr_t paddr;
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
		paddr = htoll(args[optind], FAULT_ON_ERROR, NULL);
		vaddr = PTOV(paddr);

		fprintf(fp, "%s%s  %s\n", others++ ? "\n" : "", 
		    mkstring(buf1, VADDR_PRLEN, LJUST, "VIRTUAL"),
		    mkstring(buf2, VADDR_PRLEN, LJUST, "PHYSICAL"));
		fprintf(fp, "%s  %s\n",
		    mkstring(buf1, VADDR_PRLEN, LJUST|LONG_HEX, MKSTR(vaddr)),
                    mkstring(buf2, VADDR_PRLEN, LJUST|LONGLONG_HEX, 
			MKSTR(&paddr)));

		optind++;
	}
}


/*
 *  Runs PTOB() on the page frame number to get the page address.
 */
void
cmd_ptob(void)
{
        ulonglong value;

        optind = 1;
        if (!args[optind])
                cmd_usage(pc->curcmd, SYNOPSIS);

        while (args[optind]) {
		value = stoll(args[optind], FAULT_ON_ERROR, NULL);
		fprintf(fp, "%llx: %llx\n", value, PTOB(value));
                optind++;
        }
}


/*
 *  Runs BTOP() on the address to get the page frame number.
 */
void
cmd_btop(void)
{
        ulonglong value;

        optind = 1;
        if (!args[optind])
                cmd_usage(pc->curcmd, SYNOPSIS);

        while (args[optind]) {
		value = htoll(args[optind], FAULT_ON_ERROR, NULL); 
		fprintf(fp, "%llx: %llx\n", value, BTOP(value));
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

#define VM_BIGPAGE      0x00100000      /* bigpage mappings, no pte's */
#define VM_BIGMAP       0x00200000      /* user wants bigpage mapping */

#define VM_WRITECOMBINED 0x00100000      /* Write-combined */
#define VM_NONCACHED     0x00200000      /* Noncached access */
#define VM_HUGETLB       0x00400000      /* Huge tlb Page*/
#define VM_ACCOUNT       0x00100000      /* Memory is a vm accounted object */

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
	if (symbol_exists("nr_bigpages") && (THIS_KERNEL_VERSION == LINUX(2,4,9))) {
        	if (flags & VM_BIGPAGE)
                	fprintf(fp, "%sBIGPAGE", others++ ? "|" : "");
        	if (flags & VM_BIGMAP)
                	fprintf(fp, "%sBIGMAP", others++ ? "|" : "");
	} else {
        	if (flags & VM_WRITECOMBINED)
                	fprintf(fp, "%sWRITECOMBINED", others++ ? "|" : "");
        	if (flags & VM_NONCACHED)
                	fprintf(fp, "%sNONCACHED", others++ ? "|" : "");
        	if (flags & VM_HUGETLB)
                	fprintf(fp, "%sHUGETLB", others++ ? "|" : "");
        	if (flags & VM_ACCOUNT)
                	fprintf(fp, "%sACCOUNT", others++ ? "|" : "");
	}

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
	fprintf(fp, "%s%s%s%s%s %6lx%s%s\n",                                   \
                mkstring(buf4, VADDR_PRLEN, CENTER|LJUST|LONG_HEX, MKSTR(vma)),       \
	        space(MINSPACE),                                               \
                mkstring(buf2, UVADDR_PRLEN, RJUST|LONG_HEX, MKSTR(vm_start)), \
                space(MINSPACE),                                               \
                mkstring(buf3, UVADDR_PRLEN, RJUST|LONG_HEX, MKSTR(vm_end)),   \
		vm_flags, space(MINSPACE), buf1); 

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
	ulong vm_flags;
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

       	sprintf(vma_header, "%s%s%s%s%s  FLAGS%sFILE\n",
                mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "VMA"),
                space(MINSPACE),              
                mkstring(buf2, UVADDR_PRLEN, CENTER|RJUST, "START"),
                space(MINSPACE),              
                mkstring(buf3, UVADDR_PRLEN, CENTER|RJUST, "END"),
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
		vm_flags = SIZE(vm_area_struct_vm_flags) == sizeof(short) ?
			USHORT(vma_buf+ OFFSET(vm_area_struct_vm_flags)) :
			ULONG(vma_buf+ OFFSET(vm_area_struct_vm_flags));
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
				if (VALID_MEMBER(file_f_vfsmnt)) {
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
                                fprintf(fp, "%lx%s%s%s%s%s%6lx%s%lx %s\n",
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
	physaddr_t paddr;
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
				strlen("PHYSICAL")), RJUST|LONGLONG_HEX, 
				MKSTR(&paddr)));

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
				    THIS_KERNEL_VERSION >= LINUX(2,6,0) ?
				    __swp_offset(paddr) : SWP_OFFSET(paddr))) {
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
	if (VALID_MEMBER(mm_struct_anon_rss))
		tm->rss +=  ULONG(tt->mm_struct + OFFSET(mm_struct_anon_rss));
        tm->total_vm = ULONG(tt->mm_struct + OFFSET(mm_struct_total_vm));
        tm->pgd_addr = ULONG(tt->mm_struct + OFFSET(mm_struct_pgd));

	if (is_kernel_thread(task))
		return;

	tm->pct_physmem = ((double)(tm->rss*100)) /
		((double)(MIN(vt->total_pages, 
		vt->num_physpages ? vt->num_physpages : vt->total_pages)));
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
#define GET_VMLIST_COUNT       (ADDRESS_SPECIFIED << 16)
#define GET_VMLIST             (ADDRESS_SPECIFIED << 17)
#define SLAB_DATA_NOSAVE       (ADDRESS_SPECIFIED << 18)

#define GET_ALL \
	(GET_SHARED_PAGES|GET_TOTALRAM_PAGES|GET_BUFFERS_PAGES|GET_SLAB_PAGES)

void
cmd_kmem(void)
{
	int i;
	int c;
	int sflag, Sflag, pflag, fflag, Fflag, vflag; 
	int nflag, cflag, Cflag, iflag, lflag, Lflag, Pflag, Vflag;
	struct meminfo meminfo;
	ulonglong value[MAXARGS];
	char buf[BUFSIZE];
	char *p1;
	int spec_addr;

	spec_addr = 0;
        sflag =	Sflag = pflag = fflag = Fflag = Pflag = 0;
	vflag = Cflag = cflag = iflag = nflag = lflag = Lflag = Vflag = 0;
	BZERO(&meminfo, sizeof(struct meminfo));
	BZERO(&value[0], sizeof(ulonglong)*MAXARGS);

        while ((c = getopt(argcnt, args, "I:sSFfpvcCinl:L:PV")) != EOF) {
                switch(c)
		{
		case 'V':
			Vflag = 1;
			break;

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

        if ((sflag + Sflag + pflag + fflag + Fflag + Vflag +
            vflag + Cflag + cflag + iflag + lflag + Lflag) > 1) {
		error(INFO, "only one flag allowed!\n");
		cmd_usage(pc->curcmd, SYNOPSIS);
	} 

	if (sflag || Sflag || !(vt->flags & KMEM_CACHE_INIT))
		kmem_cache_init();

	while (args[optind]) {
                if (hexadecimal(args[optind], 0)) {
                        value[spec_addr++] = 
				htoll(args[optind], FAULT_ON_ERROR, NULL);
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
                        dump_mem_map(&meminfo);
                        pflag++;
                }

                if (sflag || Sflag) {
        		if (vt->flags & KMEM_CACHE_UNAVAIL) 
                		error(FATAL, 
				   "kmem cache slab subsystem not available\n");
 
			meminfo.flags = Sflag ? VERBOSE : 0;

			if (meminfo.memtype == PHYSADDR) {
                          	if (value[i] < VTOP(vt->high_memory)) {
                        		value[i] = PTOV(value[i]);
					meminfo.memtype = KVADDR;
				} else
                			error(WARNING,
                    	   "cannot make virtual-to-physical translation: %llx\n",
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
                if (nflag || iflag || Fflag || Cflag || Lflag || Vflag) {
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

	if (sflag == 1) {
                if (vt->flags & KMEM_CACHE_UNAVAIL)
                     	error(FATAL, 
			    "kmem cache slab subsystem not available\n");
		if (STREQ(meminfo.reqname, "list"))
			kmem_cache_list();
		else
			vt->dump_kmem_cache(&meminfo);
	}

	if (Sflag == 1) {
                if (vt->flags & KMEM_CACHE_UNAVAIL)
                     	error(FATAL, 
			    "kmem cache slab subsystem not available\n");
		meminfo.flags = VERBOSE;
		if (STREQ(meminfo.reqname, "list"))
			kmem_cache_list();
		else
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
		dump_memory_nodes(MEMORY_NODES_DUMP);

	if (lflag == 1) { 
		dump_page_lists(&meminfo);
	}

	if (Lflag == 1) {
		meminfo.flags |= VERBOSE;
		dump_page_lists(&meminfo);
	}

	if (Vflag == 1)
		dump_vm_stat(NULL, NULL);

	if (!(sflag + Sflag + pflag + fflag + Fflag + vflag + Vflag +
              cflag + Cflag + iflag + nflag + lflag + Lflag + meminfo.calls))
		cmd_usage(pc->curcmd, SYNOPSIS);

}

static void
PG_reserved_flag_init(void)
{
	ulong pageptr;
	ulong vaddr, flags;
	char *buf;

	vaddr = kt->stext ? kt->stext : symbol_value("sys_read");

	if (!phys_to_page((physaddr_t)VTOP(vaddr), &pageptr))
		return;

	buf = (char *)GETBUF(SIZE(page));

	if (!readmem(pageptr, KVADDR, buf, SIZE(page),
            "reserved page", RETURN_ON_ERROR|QUIET)) {
		FREEBUF(buf);
		return;
	}

	flags = ULONG(buf + OFFSET(page_flags));

	if (count_bits_long(flags) == 1)
		vt->PG_reserved = flags;
	else
		vt->PG_reserved = 0;

	if (CRASHDEBUG(2))
		fprintf(fp, 
		    "PG_reserved: vaddr: %lx page: %lx flags: %lx => %lx\n",
			vaddr, pageptr, flags, vt->PG_reserved);

	FREEBUF(buf);
}

static void 
PG_slab_flag_init(void)
{
	int bit;
        ulong pageptr;
        ulong vaddr, flags;
        char buf[BUFSIZE];  /* safe for a page struct */

	/*
	 *  Set the old defaults in case the search below fails.
	 */
        if (VALID_MEMBER(page_pte)) {
                if (THIS_KERNEL_VERSION < LINUX(2,6,0))
                        vt->PG_slab = 10;
                else if (THIS_KERNEL_VERSION >= LINUX(2,6,0))
                        vt->PG_slab = 7;
        } else if (THIS_KERNEL_VERSION >= LINUX(2,6,0))
                vt->PG_slab = 7;

       	if (try_get_symbol_data("vm_area_cachep", sizeof(void *), &vaddr) &&
            phys_to_page((physaddr_t)VTOP(vaddr), &pageptr) &&
            readmem(pageptr, KVADDR, buf, SIZE(page),
            "vm_area_cachep page", RETURN_ON_ERROR|QUIET)) {

        	flags = ULONG(buf + OFFSET(page_flags));

	        if ((bit = ffsl(flags))) {
	                vt->PG_slab = bit - 1;
	
	        	if (CRASHDEBUG(2))
	                	fprintf(fp,
	                    "PG_slab bit: vaddr: %lx page: %lx flags: %lx => %ld\n",
	                        vaddr, pageptr, flags, vt->PG_slab);
	
		}
	}
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
#define v24_PG_checked              13      /* kill me in 2.5.<early>. */
#define v24_PG_bigpage              14
                                /* bits 21-30 unused */
#define v24_PG_arch_1               30
#define v24_PG_reserved             31

#define v26_PG_private              12

#define PGMM_CACHED (512)

static void
dump_mem_map_SPARSEMEM(struct meminfo *mi)
{
	ulong i;
	long total_pages;
	int others, page_not_mapped, phys_not_mapped, page_mapping;
	ulong pp, ppend;
	physaddr_t phys, physend;
	ulong tmp, reserved, shared, slabs;
        ulong PG_reserved_flag;
	long buffers;
	ulong inode, offset, flags, mapping, index;
	uint count;
	int print_hdr, pg_spec, phys_spec, done;
	int v22;
	char hdr[BUFSIZE];
	char buf0[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char *page_cache;
	char *pcache;
	ulong section, section_nr, nr_mem_sections, section_size;

	v22 = VALID_MEMBER(page_inode);  /* page.inode vs. page.mapping */

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
                                if (kvtop(NULL, mi->spec_addr, &phys, 0)) {
                                        mi->spec_addr = phys;
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

	nr_mem_sections = NR_MEM_SECTIONS();

	/* 
	 *  Iterate over all possible sections
	 */
        for (section_nr = 0; section_nr < nr_mem_sections ; section_nr++) {

		if (CRASHDEBUG(2)) 
			fprintf(fp, "section_nr = %ld\n", section_nr);

		/* 
		 *  If we are looking up a specific address, jump directly
		 *  to the section with that page 
		 */
		if (mi->flags & ADDRESS_SPECIFIED) {        
			ulong pfn;
			physaddr_t tmp;

			if (pg_spec) {
				if (!page_to_phys(mi->spec_addr, &tmp))
					return;
				pfn = tmp >> PAGESHIFT();
			} else
				pfn = mi->spec_addr >> PAGESHIFT();
			section_nr = pfn_to_section_nr(pfn);
		}

                if (!(section = valid_section_nr(section_nr))) {
#ifdef NOTDEF
                        break;    /* On a real sparsemem system we need to check
				   * every section as gaps may exist.  But this
				   * can be slow.  If we know we don't have gaps
				   * just stop validating sections when we 
				   * get to the end of the valid ones.  
				   * In the future find a way to short circuit
				   * this loop.
				   */
#endif
			if (mi->flags & ADDRESS_SPECIFIED)
				break;
			continue;
		}

		if (print_hdr) {
			if (!(pc->curcmd_flags & HEADER_PRINTED))
				fprintf(fp, "%s", hdr);
			print_hdr = FALSE;
			pc->curcmd_flags |= HEADER_PRINTED;
		}

		pp = section_mem_map_addr(section);
		pp = sparse_decode_mem_map(pp, section_nr);
		phys = section_nr * PAGES_PER_SECTION() * PAGESIZE();
		section_size = PAGES_PER_SECTION();

		for (i = 0; i < section_size; 
		     i++, pp += SIZE(page), phys += PAGESIZE()) {

			if ((i % PGMM_CACHED) == 0) {

				ppend = pp + ((PGMM_CACHED-1) * SIZE(page));
				physend = phys + ((PGMM_CACHED-1) * PAGESIZE());

				if ((pg_spec && (mi->spec_addr > ppend)) ||
			            (phys_spec && 
				    (PHYSPAGEBASE(mi->spec_addr) > physend))) {
					i += (PGMM_CACHED-1);
					pp = ppend;
					phys = physend;
					continue;
				}  

				fill_mem_map_cache(pp, ppend, page_cache);
			}

			pcache = page_cache + ((i%PGMM_CACHED) * SIZE(page));

			if (received_SIGINT())
				restart(0);
	
			if ((pg_spec && (pp == mi->spec_addr)) || 
			   (phys_spec && (phys == PHYSPAGEBASE(mi->spec_addr))))
				done = TRUE;

			if (!done && (pg_spec || phys_spec))
				continue;
			
			flags = ULONG(pcache + OFFSET(page_flags));
			count = UINT(pcache + OFFSET(page_count));

	                switch (mi->flags)
			{
			case GET_ALL:
			case GET_BUFFERS_PAGES:
				if (VALID_MEMBER(page_buffers)) {
					tmp = ULONG(pcache + 
						OFFSET(page_buffers));
					if (tmp)
						buffers++;
				} else if (THIS_KERNEL_VERSION >= LINUX(2,6,0)) {
	                                if ((flags >> v26_PG_private) & 1) 
						buffers++;
				} else
					error(FATAL, 
			       "cannot determine whether pages have buffers\n");

				if (mi->flags != GET_ALL)
					continue;

				/* FALLTHROUGH */

			case GET_SLAB_PAGES:
				if (v22) {
	                                if ((flags >> v22_PG_Slab) & 1) 
						slabs++;
				} else if (vt->PG_slab) {
	                                if ((flags >> vt->PG_slab) & 1) 
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
                                if (vt->PG_reserved)
					PG_reserved_flag = vt->PG_reserved;
				else
                                        PG_reserved_flag = v22 ?
                                                1 << v22_PG_reserved :
                                                1 << v24_PG_reserved;

	                        if (flags & PG_reserved_flag) {
	                                reserved++;
				} else {
					if (count > 1)
						shared++;
				}
	                        continue;
	                }
			page_mapping = VALID_MEMBER(page_mapping);
	
			if (v22) {
				inode = ULONG(pcache + OFFSET(page_inode));
				offset = ULONG(pcache + OFFSET(page_offset));
			} else if (page_mapping) { 
				mapping = ULONG(pcache + 
					OFFSET(page_mapping));
				index = ULONG(pcache + OFFSET(page_index));
			}
	
			page_not_mapped = phys_not_mapped = FALSE;

			if (v22) {
				fprintf(fp, "%lx%s%s%s%s%s%8lx %2d%s",
					pp,
					space(MINSPACE),
                    			mkstring(buf1, MAX(PADDR_PRLEN, 
					    strlen("PHYSICAL")), 
					    RJUST|LONGLONG_HEX, MKSTR(&phys)),
					space(MINSPACE),
				        mkstring(buf2, VADDR_PRLEN, 
						RJUST|LONG_HEX, MKSTR(inode)),
					space(MINSPACE),
					offset,
					count,
					space(MINSPACE));
			} else {
				if ((vt->flags & V_MEM_MAP)) {
				    	if (!machdep->verify_paddr(phys)) 
						phys_not_mapped = TRUE;
					if (!kvtop(NULL, pp, NULL, 0))
						page_not_mapped = TRUE;
				}
				if (page_not_mapped)
                                fprintf(fp, "%s%s%s%s%s%s%s %2s ", 
					mkstring(buf0, VADDR_PRLEN, 
					LJUST|LONG_HEX, MKSTR(pp)),
                                       	space(MINSPACE),
                                       	mkstring(buf1, MAX(PADDR_PRLEN,
                                        strlen("PHYSICAL")),
                                        RJUST|LONGLONG_HEX, MKSTR(&phys)),
                                        space(MINSPACE),
					mkstring(buf3, VADDR_PRLEN, 
					CENTER|RJUST, " "),
                                        space(MINSPACE),
					mkstring(buf4, 8, CENTER|RJUST, " "),
                                        " ");
				else if (!page_mapping)
				 fprintf(fp, "%s%s%s%s%s%s%s %2d ",
					 mkstring(buf0, VADDR_PRLEN,
					 LJUST|LONG_HEX, MKSTR(pp)),
					 space(MINSPACE),
					 mkstring(buf1, MAX(PADDR_PRLEN,
					 strlen("PHYSICAL")),
					 RJUST|LONGLONG_HEX, MKSTR(&phys)),
					 space(MINSPACE),
					 mkstring(buf3, VADDR_PRLEN,
					 CENTER|RJUST, "-------"),
					 space(MINSPACE),
					 mkstring(buf4, 8, CENTER|RJUST, "-----"),
					 count);
				else
                                fprintf(fp, "%s%s%s%s%s%s%8ld %2d ",
					mkstring(buf0, VADDR_PRLEN, 
					LJUST|LONG_HEX, MKSTR(pp)),
                                       	space(MINSPACE),
                                       	mkstring(buf1, MAX(PADDR_PRLEN,
                                        strlen("PHYSICAL")),
                                        RJUST|LONGLONG_HEX, MKSTR(&phys)),
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
			} else if (THIS_KERNEL_VERSION > LINUX(2,4,9)) {
				fprintf(fp, "%lx\n", flags);
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
				if ((flags >> v24_PG_checked) & 1)
					fprintf(fp, "%schecked", 
						others++ ? "," : "");
				if ((flags >> v24_PG_bigpage) & 1)
					fprintf(fp, "%sbigpage", 
						others++ ? "," : "");
                                if ((flags >> v24_PG_arch_1) & 1)
                                        fprintf(fp, "%sarch_1",
                                                others++ ? "," : "");
				if ((flags >> v24_PG_reserved) & 1)
					fprintf(fp, "%sreserved", 
						others++ ? "," : "");
				if (phys_not_mapped)
					fprintf(fp, "%s[NOT MAPPED]", 
						others++ ? " " : "");

				fprintf(fp, "\n");
			}
	
			if (done)
				break;
		}

		if (done)
			break;
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

static void
dump_mem_map(struct meminfo *mi)
{
	long i, n;
	long total_pages;
	int others, page_not_mapped, phys_not_mapped, page_mapping;
	ulong pp, ppend;
	physaddr_t phys, physend;
	ulong tmp, reserved, shared, slabs;
        ulong PG_reserved_flag;
	long buffers;
	ulong inode, offset, flags, mapping, index;
	ulong node_size;
	uint count;
	int print_hdr, pg_spec, phys_spec, done;
	int v22;
	struct node_table *nt;
	char hdr[BUFSIZE];
	char buf0[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char *page_cache;
	char *pcache;

	if (IS_SPARSEMEM()) {
		dump_mem_map_SPARSEMEM(mi);
		return;
	}

	v22 = VALID_MEMBER(page_inode);  /* page.inode vs. page.mapping */

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
                                if (kvtop(NULL, mi->spec_addr, &phys, 0)) {
                                        mi->spec_addr = phys;
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
		if (print_hdr) {
			if (!(pc->curcmd_flags & HEADER_PRINTED))
				fprintf(fp, "%s%s", n ? "\n" : "", hdr);
			print_hdr = FALSE;
			pc->curcmd_flags |= HEADER_PRINTED;
		}

		nt = &vt->node_table[n];
		total_pages += nt->size;
		pp = nt->mem_map;
		phys = nt->start_paddr;
		if ((vt->flags & V_MEM_MAP) && (vt->numnodes == 1))
			node_size = vt->max_mapnr;
		else
			node_size = nt->size;

		for (i = 0; i < node_size; 
		     i++, pp += SIZE(page), phys += PAGESIZE()) {

			if ((i % PGMM_CACHED) == 0) {
				ppend = pp + ((PGMM_CACHED-1) * SIZE(page));
				physend = phys + ((PGMM_CACHED-1) * PAGESIZE());

				if ((pg_spec && (mi->spec_addr > ppend)) ||
			            (phys_spec && 
				    (PHYSPAGEBASE(mi->spec_addr) > physend))) {
					i += (PGMM_CACHED-1);
					pp = ppend;
					phys = physend;
					continue;
				}  

				fill_mem_map_cache(pp, ppend, page_cache);
			}

			pcache = page_cache + ((i%PGMM_CACHED) * SIZE(page));

			if (received_SIGINT())
				restart(0);
	
			if ((pg_spec && (pp == mi->spec_addr)) || 
			   (phys_spec && (phys == PHYSPAGEBASE(mi->spec_addr))))
				done = TRUE;

			if (!done && (pg_spec || phys_spec))
				continue;
			
			flags = ULONG(pcache + OFFSET(page_flags));
			count = UINT(pcache + OFFSET(page_count));

	                switch (mi->flags)
			{
			case GET_ALL:
			case GET_BUFFERS_PAGES:
				if (VALID_MEMBER(page_buffers)) {
					tmp = ULONG(pcache + 
						OFFSET(page_buffers));
					if (tmp)
						buffers++;
				} else if (THIS_KERNEL_VERSION >= LINUX(2,6,0)) {
	                                if ((flags >> v26_PG_private) & 1) 
						buffers++;
				} else
					error(FATAL, 
			       "cannot determine whether pages have buffers\n");

				if (mi->flags != GET_ALL)
					continue;

				/* FALLTHROUGH */

			case GET_SLAB_PAGES:
				if (v22) {
	                                if ((flags >> v22_PG_Slab) & 1) 
						slabs++;
				} else if (vt->PG_slab) {
	                                if ((flags >> vt->PG_slab) & 1) 
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
                                if (vt->PG_reserved)
					PG_reserved_flag = vt->PG_reserved;
				else
                                        PG_reserved_flag = v22 ?
                                                1 << v22_PG_reserved :
                                                1 << v24_PG_reserved;

	                        if (flags & PG_reserved_flag) {
	                                reserved++;
				} else {
					if (count > 1)
						shared++;
				}
	                        continue;
	                }
	
			page_mapping = VALID_MEMBER(page_mapping);

			if (v22) {
				inode = ULONG(pcache + OFFSET(page_inode));
				offset = ULONG(pcache + OFFSET(page_offset));
			} else if (page_mapping) {
				mapping = ULONG(pcache + 
					OFFSET(page_mapping));
				index = ULONG(pcache + OFFSET(page_index));
			}
	
			page_not_mapped = phys_not_mapped = FALSE;

			if (v22) {
				fprintf(fp, "%lx%s%s%s%s%s%8lx %2d%s",
					pp,
					space(MINSPACE),
                    			mkstring(buf1, MAX(PADDR_PRLEN, 
					    strlen("PHYSICAL")), 
					    RJUST|LONGLONG_HEX, MKSTR(&phys)),
					space(MINSPACE),
				        mkstring(buf2, VADDR_PRLEN, 
						RJUST|LONG_HEX, MKSTR(inode)),
					space(MINSPACE),
					offset,
					count,
					space(MINSPACE));
			} else {
				if ((vt->flags & V_MEM_MAP)) {
				    	if (!machdep->verify_paddr(phys)) 
						phys_not_mapped = TRUE;
					if (!kvtop(NULL, pp, NULL, 0))
						page_not_mapped = TRUE;
				}
				if (page_not_mapped)
                                fprintf(fp, "%s%s%s%s%s%s%s %2s ", 
					mkstring(buf0, VADDR_PRLEN, 
					LJUST|LONG_HEX, MKSTR(pp)),
                                       	space(MINSPACE),
                                       	mkstring(buf1, MAX(PADDR_PRLEN,
                                        strlen("PHYSICAL")),
                                        RJUST|LONGLONG_HEX, MKSTR(&phys)),
                                        space(MINSPACE),
					mkstring(buf3, VADDR_PRLEN, 
					CENTER|RJUST, " "),
                                        space(MINSPACE),
					mkstring(buf4, 8, CENTER|RJUST, " "),
                                        " ");
				else if (!page_mapping)
                                fprintf(fp, "%s%s%s%s%s%s%s %2d ",
                                        mkstring(buf0, VADDR_PRLEN,
                                        LJUST|LONG_HEX, MKSTR(pp)),
                                        space(MINSPACE),
                                        mkstring(buf1, MAX(PADDR_PRLEN,
                                        strlen("PHYSICAL")),
                                        RJUST|LONGLONG_HEX, MKSTR(&phys)),
                                        space(MINSPACE),
                                        mkstring(buf3, VADDR_PRLEN, 
                                        CENTER|RJUST, "-------"),
                                        space(MINSPACE),
                                        mkstring(buf4, 8, CENTER|RJUST, "-----"),
                                        count);
				else
                                fprintf(fp, "%s%s%s%s%s%s%8ld %2d ",
					mkstring(buf0, VADDR_PRLEN, 
					LJUST|LONG_HEX, MKSTR(pp)),
                                       	space(MINSPACE),
                                       	mkstring(buf1, MAX(PADDR_PRLEN,
                                        strlen("PHYSICAL")),
                                        RJUST|LONGLONG_HEX, MKSTR(&phys)),
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
			} else if (THIS_KERNEL_VERSION > LINUX(2,4,9)) {
				fprintf(fp, "%lx\n", flags);
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
				if ((flags >> v24_PG_checked) & 1)
					fprintf(fp, "%schecked", 
						others++ ? "," : "");
				if ((flags >> v24_PG_bigpage) & 1)
					fprintf(fp, "%sbigpage", 
						others++ ? "," : "");
                                if ((flags >> v24_PG_arch_1) & 1)
                                        fprintf(fp, "%sarch_1",
                                                others++ ? "," : "");
				if ((flags >> v24_PG_reserved) & 1)
					fprintf(fp, "%sreserved", 
						others++ ? "," : "");
				if (phys_not_mapped)
					fprintf(fp, "%s[NOT MAPPED]", 
						others++ ? " " : "");

				fprintf(fp, "\n");
			}
	
			if (done)
				break;
		}

		if (done)
			break;
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
 *  Stash a chunk of PGMM_CACHED page structures, starting at addr, into the
 *  passed-in buffer.  The mem_map array is normally guaranteed to be
 *  readable except in the case of virtual mem_map usage.  When V_MEM_MAP
 *  is in place, read all pages consumed by PGMM_CACHED page structures
 *  that are currently mapped, leaving the unmapped ones just zeroed out.
 */
static void
fill_mem_map_cache(ulong pp, ulong ppend, char *page_cache)
{
	long size, cnt;
	ulong addr;
        char *bufptr;

	/*
	 *  Try to read it in one fell swoop.
 	 */
	if (readmem(pp, KVADDR, page_cache, SIZE(page) * PGMM_CACHED,
      	    "page struct cache", RETURN_ON_ERROR|QUIET))
		return;

	/*
	 *  Break it into page-size-or-less requests, warning if it's
	 *  not a virtual mem_map.
	 */
        size = SIZE(page) * PGMM_CACHED;
        addr = pp;
        bufptr = page_cache;

        while (size > 0) {
		/* 
		 *  Compute bytes till end of page.
		 */
		cnt = PAGESIZE() - PAGEOFFSET(addr); 

                if (cnt > size)
                        cnt = size;

		if (!readmem(addr, KVADDR, bufptr, size,
                    "virtual page struct cache", RETURN_ON_ERROR|QUIET)) {
			BZERO(bufptr, size);
			if (!(vt->flags & V_MEM_MAP) && ((addr+size) < ppend)) 
				error(WARNING, 
		                   "mem_map[] from %lx to %lx not accessible\n",
					addr, addr+size);
		}

		addr += cnt;
                bufptr += cnt;
                size -= cnt;
        }
}


/*
 *  dump_page_hash_table() displays the entries in each page_hash_table.
 */

#define PGHASH_CACHED (1024)

static void
dump_page_hash_table(struct meminfo *hi)
{
	int i;
	int len, entry_len;
	ulong page_hash_table, head;
	struct list_data list_data, *ld;
	struct gnu_request req;
	long total_cached;
	long page_cache_size;
	ulong this_addr, searchpage;
	int errflag, found, cnt, populated, verbose;
	uint ival;
	ulong buffer_pages;
	char buf[BUFSIZE];
	char hash_table[BUFSIZE];
	char *pcache, *pghash_cache;

	if (!vt->page_hash_table) {
		if (hi->flags & VERBOSE)
			error(FATAL, 
			 "address_space page cache radix tree not supported\n");
		
        	if (symbol_exists("nr_pagecache")) {
			buffer_pages = nr_blockdev_pages();
                	get_symbol_data("nr_pagecache", sizeof(int), &ival);
                	page_cache_size = (ulong)ival;
			page_cache_size -= buffer_pages;
        		fprintf(fp, "page cache size: %ld\n", page_cache_size);
			if (hi->flags & ADDRESS_SPECIFIED)
				error(INFO, 
    "address_space page cache radix tree not supported: %lx: ignored\n",
					hi->spec_addr);
		} else
			error(FATAL, "cannot determine page cache size\n");
		return;
	}

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

	if (vt->page_hash_table_len == 0) 
		error(FATAL, "cannot determine size of page_hash_table\n");

	page_hash_table = vt->page_hash_table;
	len = vt->page_hash_table_len;
	entry_len = VALID_STRUCT(page_cache_bucket) ?
		SIZE(page_cache_bucket) : sizeof(void *);

	if (CRASHDEBUG(1)) {
		populated = 0;
		fprintf(fp, "page_hash_table length: %d\n", len);
	}

	get_symbol_type("page_cache_size", NULL, &req);
        if (req.length == sizeof(int)) {
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
	     page_hash_table += entry_len) {

                if ((i % PGHASH_CACHED) == 0) {
                	readmem(page_hash_table, KVADDR, pghash_cache,
                        	entry_len * PGHASH_CACHED,
                                "page hash cache", FAULT_ON_ERROR);
                }

                pcache = pghash_cache + ((i%PGHASH_CACHED) * entry_len);
		if (VALID_STRUCT(page_cache_bucket))
			pcache += OFFSET(page_cache_bucket_chain);
			
		head = ULONG(pcache);

		if (!head) 
			continue;

		if (verbose) 
			fprintf(fp, "page_hash_table[%d]\n", i);
		
		if (CRASHDEBUG(1))
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

	if (CRASHDEBUG(1))
		fprintf(fp, "heads containing page(s): %d\n", populated);

	if (searchpage) {
		rewind(pc->tmpfile);
		found = FALSE;
		while (fgets(buf, BUFSIZE, pc->tmpfile)) {
			if (CRASHDEBUG(1) && STRNEQ(buf, "<readmem:"))
				continue;

			if (strstr(buf, "page_hash_table")) {
				strcpy(hash_table, buf); 
				continue;
			}
			if (strstr(buf, "page_cache_size"))
				continue;

			if (CRASHDEBUG(1) && 
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
	physaddr_t searchphys;
	ulong this_addr; 
	physaddr_t this_phys;
	int do_search;
	ulong kfp, offset;
	int flen, dimension;

        if (vt->flags & (NODES|ZONES)) 
		error(FATAL, "dump_free_pages called with (NODES|ZONES)\n");

	nr_mem_lists = ARRAY_LENGTH(free_area);
	dimension = ARRAY_LENGTH(free_area_DIMENSION);

	if (nr_mem_lists == 0)
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
		if (CRASHDEBUG(1) && STRNEQ(buf, "<readmem"))
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

		if (CRASHDEBUG(1) && !hexadecimal(strip_linefeeds(buf), 0))
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
				fprintf(fp, "(%lx is ", (ulong)fi->spec_addr);
                        	break;
                	case PHYSADDR:
				fprintf(fp, "(%llx is %s", fi->spec_addr,
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
	ulong kfp, free_area;
	physaddr_t searchphys;
	int flen, errflag, verbose, nr_free_pages;
	int nr_mem_lists, dimension, order, do_search;
	ulong sum, found, offset;
	char *free_area_buf, *p;
	ulong *pp;
	long chunk_size;
        ulong this_addr; 
	physaddr_t this_phys;
	char buf[BUFSIZE];
	char last_area[BUFSIZE];
	char last_area_hdr[BUFSIZE];


        if (vt->flags & (NODES|ZONES)) 
                error(FATAL, 
		"dump_multidimensional_free_pages called with (NODES|ZONES)\n");

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
        nr_mem_lists = ARRAY_LENGTH(free_area);
	dimension = ARRAY_LENGTH(free_area_DIMENSION);
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
		if (CRASHDEBUG(1) && STRNEQ(buf, "<readmem:"))
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
                                fprintf(fp, "(%lx is ", (ulong)fi->spec_addr);
                        	break;
                	case PHYSADDR:
                                fprintf(fp, "(%llx is %s", fi->spec_addr,
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
 *  progress, because although the framework for memory nodes has been laid
 *  down, complete support has not been put in place.
 */
static char *zone_hdr = "ZONE  NAME        SIZE    FREE";

static void
dump_free_pages_zones_v1(struct meminfo *fi)
{
	int i, n;
	ulong node_zones;
	ulong size;
	long zone_size_offset;
	long chunk_size;
	int order, errflag, do_search;
	ulong offset, verbose, value, sum, found; 
	ulong this_addr;
	physaddr_t this_phys, searchphys;
        ulong zone_mem_map;
        ulong zone_start_paddr;
        ulong zone_start_mapnr;
	struct node_table *nt;
	char buf[BUFSIZE], *p;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char last_node[BUFSIZE];
	char last_zone[BUFSIZE];
	char last_area[BUFSIZE];
	char last_area_hdr[BUFSIZE];

       if (!(vt->flags & (NODES|ZONES)))
		error(FATAL, 
		    "dump_free_pages_zones_v1 called without (NODES|ZONES)\n");

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
			    "dump_free_pages_zones_v1: no memtype specified\n");
                }
		do_search = TRUE;
        } else {
                searchphys = 0;
		do_search = FALSE;
	}
        verbose = (do_search || (fi->flags & VERBOSE)) ? TRUE : FALSE;

	if (VALID_MEMBER(zone_struct_size))
		zone_size_offset =  OFFSET(zone_struct_size);
	else if (VALID_MEMBER(zone_struct_memsize))
		zone_size_offset =  OFFSET(zone_struct_memsize);
	else
		error(FATAL, 
			"zone_struct has neither size nor memsize field\n");

	if (do_search)
		open_tmpfile();

	hq_open();

	for (n = sum = found = 0; n < vt->numnodes; n++) {
                nt = &vt->node_table[n];
		node_zones = nt->pgdat + OFFSET(pglist_data_node_zones);

		for (i = 0; i < vt->nr_zones; i++) {
	
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
	                        if (i == vt->ZONE_HIGHMEM) {
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
	                	readmem(node_zones+zone_size_offset, 
					KVADDR, &size, sizeof(ulong),
	                        	"node_zones {mem}size", FAULT_ON_ERROR);
	                        sum += size;
	                        node_zones += SIZE(zone_struct);
	                        continue;
			}

			if ((i == 0) && (vt->flags & NODES)) {
				if (n) {
					fprintf(fp, "\n");
                                	pad_line(fp, 
						VADDR_PRLEN > 8 ? 74 : 66, '-');
                                	fprintf(fp, "\n");
				}
				fprintf(fp, "%sNODE\n %2d\n", 
					n ? "\n" : "", nt->node_id);
			}

	                fprintf(fp, "%s%s  %s  START_PADDR  START_MAPNR\n",
				i > 0 ? "\n" : "",
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
	
	        	readmem(node_zones+zone_size_offset, KVADDR, 
				&size, sizeof(ulong), 
				"node_zones {mem}size", FAULT_ON_ERROR);
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
					vt->nr_free_areas, verbose);

			node_zones += SIZE(zone_struct);
		}
	}

	hq_close();

        if (fi->flags & (GET_FREE_PAGES|GET_ZONE_SIZES|GET_FREE_HIGHMEM_PAGES)) {
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
		if (CRASHDEBUG(1) && STRNEQ(buf, "<readmem"))
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

                if (CRASHDEBUG(0) &&
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
                                fprintf(fp, "(%lx is ", (ulong)fi->spec_addr);
                        	break;
                	case PHYSADDR:
                                fprintf(fp, "(%llx is %s", fi->spec_addr,
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
 *  Same as dump_free_pages_zones_v1(), but updated for numerous 2.6 zone 
 *  and free_area related data structure changes.
 */
static void
dump_free_pages_zones_v2(struct meminfo *fi)
{
	int i, n;
	ulong node_zones;
	ulong size;
	long zone_size_offset;
	long chunk_size;
	int order, errflag, do_search;
	ulong offset, verbose, value, sum, found; 
	ulong this_addr;
	physaddr_t phys, this_phys, searchphys;
	ulong pp;
        ulong zone_mem_map;
        ulong zone_start_paddr;
	ulong zone_start_pfn;
        ulong zone_start_mapnr;
	struct node_table *nt;
	char buf[BUFSIZE], *p;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char last_node[BUFSIZE];
	char last_zone[BUFSIZE];
	char last_area[BUFSIZE];
	char last_area_hdr[BUFSIZE];

       if (!(vt->flags & (NODES|ZONES)))
		error(FATAL, 
		    "dump_free_pages_zones_v2 called without (NODES|ZONES)\n");

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
			    "dump_free_pages_zones_v2: no memtype specified\n");
                }
		do_search = TRUE;
        } else {
                searchphys = 0;
		do_search = FALSE;
	}

        verbose = (do_search || (fi->flags & VERBOSE)) ? TRUE : FALSE;

	if (VALID_MEMBER(zone_spanned_pages))
		zone_size_offset =  OFFSET(zone_spanned_pages);
	else
		error(FATAL, "zone struct has no spanned_pages field\n");

	if (do_search)
		open_tmpfile();

	hq_open();

	for (n = sum = found = 0; n < vt->numnodes; n++) {
                nt = &vt->node_table[n];
		node_zones = nt->pgdat + OFFSET(pglist_data_node_zones);

		for (i = 0; i < vt->nr_zones; i++) {
			if (fi->flags == GET_FREE_PAGES) {
	                	readmem(node_zones+
					OFFSET(zone_free_pages), 
					KVADDR, &value, sizeof(ulong),
	                        	"node_zones free_pages", 
					FAULT_ON_ERROR);
				sum += value;
				node_zones += SIZE(zone);
				continue;
			}
	
	                if (fi->flags == GET_FREE_HIGHMEM_PAGES) {
	                        if (i == vt->ZONE_HIGHMEM) {
	                                readmem(node_zones+
						OFFSET(zone_free_pages),
						KVADDR, &value, sizeof(ulong),
	                                        "node_zones free_pages",
	                                        FAULT_ON_ERROR);
	                                sum += value;
	                        }
	                        node_zones += SIZE(zone);
	                        continue;
	                }
	
			if (fi->flags == GET_ZONE_SIZES) {
	                	readmem(node_zones+zone_size_offset, 
					KVADDR, &size, sizeof(ulong),
	                        	"node_zones size", FAULT_ON_ERROR);
	                        sum += size;
	                        node_zones += SIZE(zone);
	                        continue;
			}

			if ((i == 0) && (vt->flags & NODES)) {
				if (n) {
					fprintf(fp, "\n");
					pad_line(fp, 
						VADDR_PRLEN > 8 ? 74 : 66, '-');
					fprintf(fp, "\n");
				}
				fprintf(fp, "%sNODE\n %2d\n", 
					n ? "\n" : "", nt->node_id);
			}

	                fprintf(fp, "%s%s  %s  START_PADDR  START_MAPNR\n",
				i > 0 ? "\n" : "",
	                        zone_hdr,
	                        mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, 
				    "MEM_MAP"));
	
			fprintf(fp, "%3d   ", i);
	
	        	readmem(node_zones+OFFSET(zone_name), KVADDR, 
				&value, sizeof(void *), 
				"node_zones name", FAULT_ON_ERROR);
	                if (read_string(value, buf, BUFSIZE-1))
	                	fprintf(fp, "%-9s ", buf);
			else
				fprintf(fp, "(unknown) ");
	
	        	readmem(node_zones+zone_size_offset, KVADDR, 
				&size, sizeof(ulong), 
				"node_zones size", FAULT_ON_ERROR);
	                fprintf(fp, "%6ld  ", size);
	
	        	readmem(node_zones+OFFSET(zone_free_pages), 
				KVADDR, &value, sizeof(ulong), 
				"node_zones free_pages", FAULT_ON_ERROR);
	
	                fprintf(fp, "%6ld  ", value);
	
			if (VALID_MEMBER(zone_zone_mem_map)) {
                        	readmem(node_zones+OFFSET(zone_zone_mem_map),
                                	KVADDR, &zone_mem_map, sizeof(ulong),
                                	"node_zones zone_mem_map", FAULT_ON_ERROR);
			}

			readmem(node_zones+ OFFSET(zone_zone_start_pfn),
                                KVADDR, &zone_start_pfn, sizeof(ulong),
                                "node_zones zone_start_pfn", FAULT_ON_ERROR);
                        zone_start_paddr = PTOB(zone_start_pfn);

			if (!VALID_MEMBER(zone_zone_mem_map)) {
				if (IS_SPARSEMEM() || IS_DISCONTIGMEM()) {
					zone_mem_map = 0;
					if (size) {
						phys = PTOB(zone_start_pfn);
                                        	if (phys_to_page(phys, &pp))
                                                	zone_mem_map = pp;
					}
				} else if (vt->flags & FLATMEM) {
					zone_mem_map = 0;
					if (size)
						zone_mem_map = nt->mem_map +
							(zone_start_pfn * SIZE(page));
				} else
					error(FATAL, "\ncannot determine zone mem_map: TBD\n");
			}

                        if (zone_mem_map) 
                        	zone_start_mapnr = 
					(zone_mem_map - nt->mem_map) / 
						SIZE(page);
                        else
                                zone_start_mapnr = 0;
	
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
					OFFSET(zone_free_area), 
					vt->nr_free_areas, verbose);

			node_zones += SIZE(zone);
		}
	}

	hq_close();

        if (fi->flags & (GET_FREE_PAGES|GET_ZONE_SIZES|GET_FREE_HIGHMEM_PAGES)) {
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
		if (CRASHDEBUG(1) && STRNEQ(buf, "<readmem"))
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

                if (CRASHDEBUG(0) &&
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
                                fprintf(fp, "(%lx is ", (ulong)fi->spec_addr);
                        	break;
                	case PHYSADDR:
                                fprintf(fp, "(%llx is %s", fi->spec_addr,
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


static char *
page_usage_hdr = "ZONE  NAME        FREE   ACTIVE  INACTIVE_DIRTY  INACTIVE_CLEAN  MIN/LOW/HIGH";

/*
 *  Display info about the non-free pages in each zone.
 */
static int
dump_zone_page_usage(void)
{
	int i, n;
	ulong value, node_zones;
	struct node_table *nt;
	ulong inactive_dirty_pages, inactive_clean_pages, active_pages; 
	ulong free_pages, pages_min, pages_low, pages_high;
	char namebuf[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];

	if (!VALID_MEMBER(zone_struct_inactive_dirty_pages) ||
	    !VALID_MEMBER(zone_struct_inactive_clean_pages) ||
	    !VALID_MEMBER(zone_struct_active_pages) ||
	    !VALID_MEMBER(zone_struct_pages_min) ||
	    !VALID_MEMBER(zone_struct_pages_low) ||
	    !VALID_MEMBER(zone_struct_pages_high))
		return FALSE;

	fprintf(fp, "\n");

        for (n = 0; n < vt->numnodes; n++) {
                nt = &vt->node_table[n];
                node_zones = nt->pgdat + OFFSET(pglist_data_node_zones);
                
		if ((i == 0) && (vt->flags & NODES)) {
                	fprintf(fp, "%sNODE\n %2d\n",
                        	n ? "\n" : "", nt->node_id);
                }
		fprintf(fp, "%s\n", page_usage_hdr);

                for (i = 0; i < vt->nr_zones; i++) {
			readmem(node_zones+OFFSET(zone_struct_free_pages),
                                KVADDR, &free_pages, sizeof(ulong),
                                "node_zones free_pages", FAULT_ON_ERROR);
		        readmem(node_zones+
				OFFSET(zone_struct_inactive_dirty_pages),
		                KVADDR, &inactive_dirty_pages, sizeof(ulong),
		                "node_zones inactive_dirty_pages", 
				FAULT_ON_ERROR);
		        readmem(node_zones+
				OFFSET(zone_struct_inactive_clean_pages),
		                KVADDR, &inactive_clean_pages, sizeof(ulong),
		                "node_zones inactive_clean_pages", 
				FAULT_ON_ERROR);
		        readmem(node_zones+OFFSET(zone_struct_active_pages),
		                KVADDR, &active_pages, sizeof(ulong),
		                "node_zones active_pages", FAULT_ON_ERROR);
		        readmem(node_zones+OFFSET(zone_struct_pages_min),
		                KVADDR, &pages_min, sizeof(ulong),
		                "node_zones pages_min", FAULT_ON_ERROR);
		        readmem(node_zones+OFFSET(zone_struct_pages_low),
		                KVADDR, &pages_low, sizeof(ulong),
		                "node_zones pages_low", FAULT_ON_ERROR);
		        readmem(node_zones+OFFSET(zone_struct_pages_high),
		                KVADDR, &pages_high, sizeof(ulong),
		                "node_zones pages_high", FAULT_ON_ERROR);

                        readmem(node_zones+OFFSET(zone_struct_name), KVADDR,
                                &value, sizeof(void *),
                                "node_zones name", FAULT_ON_ERROR);
                        if (read_string(value, buf1, BUFSIZE-1))
                                sprintf(namebuf, "%-8s", buf1);
                        else
                                sprintf(namebuf, "(unknown)");

		        sprintf(buf2, "%ld/%ld/%ld", 
				pages_min, pages_low, pages_high);
		        fprintf(fp, "%3d   %s %7ld  %7ld %15ld %15ld  %s\n",
				i,
				namebuf,
		                free_pages,
		                active_pages,
		                inactive_dirty_pages,
		                inactive_clean_pages,
		                mkstring(buf3, strlen("MIN/LOW/HIGH"), 
				CENTER, buf2));

			node_zones += SIZE(zone_struct);
		}
	}

	return TRUE;
}


/*
 *  Dump the num "order" contents of the zone_t free_area array.
 */
char *free_area_hdr3 = "AREA    SIZE  FREE_AREA_STRUCT\n";
char *free_area_hdr4 = "AREA    SIZE  FREE_AREA_STRUCT  BLOCKS  PAGES\n";

static int
dump_zone_free_area(ulong free_area, int num, ulong verbose)
{
	int i;
	long chunk_size;
	int flen, total_free, cnt;
	char buf[BUFSIZE];
	ulong free_area_buf[3];
	struct list_data list_data, *ld;

	if (VALID_STRUCT(free_area_struct)) {
		if (SIZE(free_area_struct) != (3 * sizeof(ulong)))
			error(FATAL, 
			    "unrecognized free_area_struct size: %ld\n", 
				SIZE(free_area_struct));
	} else if (VALID_STRUCT(free_area)) {
                if (SIZE(free_area) != (3 * sizeof(ulong)))
                        error(FATAL,
                            "unrecognized free_area struct size: %ld\n",
                                SIZE(free_area));
	} else error(FATAL, 
		"neither free_area_struct or free_area structures exist\n");

	ld = &list_data;

	if (!verbose)
		fprintf(fp, free_area_hdr4);

	total_free = 0;
	flen = MAX(VADDR_PRLEN, strlen("FREE_AREA_STRUCT"));

	for (i = 0; i < num; i++, 
	     free_area += SIZE_OPTION(free_area_struct, free_area)) {
		if (verbose)
			fprintf(fp, free_area_hdr3);
		fprintf(fp, "%3d ", i);
		chunk_size = power(2, i);
		sprintf(buf, "%ldk", (chunk_size * PAGESIZE())/1024);
                fprintf(fp, " %7s  ", buf);

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
		if (VALID_MEMBER(page_list_next))
			ld->list_head_offset = OFFSET(page_list);
        	else if (VALID_MEMBER(page_lru))
			ld->list_head_offset = OFFSET(page_lru)+
				OFFSET(list_head_next);
		else error(FATAL, 
			"neither page.list or page.lru exist?\n");

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

char *kmeminfo_hdr = "              PAGES        TOTAL      PERCENTAGE\n";

static void
dump_kmeminfo(void)
{
	ulong totalram_pages;
	ulong freeram_pages;
	ulong used_pages;
	ulong shared_pages;
	ulong buffer_pages;
	ulong subtract_buffer_pages;
	ulong totalswap_pages, totalused_pages;
        ulong totalhigh_pages;
        ulong freehighmem_pages;
        ulong totallowmem_pages;
        ulong freelowmem_pages;
	long nr_file_pages, nr_slab;
	ulong swapper_space_nrpages;
	ulong pct;
	ulong value1, value2;
	uint tmp;
	struct meminfo meminfo;
	struct gnu_request req;
	long page_cache_size;
        ulong get_totalram;
        ulong get_buffers;
        ulong get_slabs;
        struct syment *sp_array[2];
	char buf[BUFSIZE];


	BZERO(&meminfo, sizeof(struct meminfo));
	meminfo.flags = GET_ALL;
	dump_mem_map(&meminfo);
	get_totalram = meminfo.get_totalram;
	shared_pages = meminfo.get_shared;
	get_buffers = meminfo.get_buffers;
	get_slabs = meminfo.get_slabs;

	/*
	 *  If vm_stat array exists, override page search info.
	 */
	if (vm_stat_init()) {
		if (dump_vm_stat("NR_SLAB", &nr_slab))
			get_slabs = nr_slab;
	}

	fprintf(fp, kmeminfo_hdr);
	/*
	 *  Get total RAM based upon how the various versions of si_meminfo()
         *  have done it, latest to earliest:
	 *
         *    Prior to 2.3.36, count all mem_map pages minus the reserved ones.
         *    From 2.3.36 onwards, use "totalram_pages" if set.
	 */
	if (symbol_exists("totalram_pages")) {  
		totalram_pages = vt->totalram_pages ? 
			vt->totalram_pages : get_totalram; 
	} else 
		totalram_pages = get_totalram;

	fprintf(fp, "%10s  %7ld  %11s         ----\n", "TOTAL MEM", 
		totalram_pages, pages_to_size(totalram_pages, buf));

	/*
	 *  Get free pages from dump_free_pages() or its associates.
	 *  Used pages are a free-bee...
	 */
	meminfo.flags = GET_FREE_PAGES;
	vt->dump_free_pages(&meminfo);
	freeram_pages = meminfo.retval;
        pct = (freeram_pages * 100)/totalram_pages;
	fprintf(fp, "%10s  %7ld  %11s  %3ld%% of TOTAL MEM\n", 
		"FREE", freeram_pages, pages_to_size(freeram_pages, buf), pct);

	used_pages = totalram_pages - freeram_pages;
        pct = (used_pages * 100)/totalram_pages;
        fprintf(fp, "%10s  %7ld  %11s  %3ld%% of TOTAL MEM\n", 
		"USED", used_pages, pages_to_size(used_pages, buf), pct);

	/*
	 *  Get shared pages from dump_mem_map().  Note that this is done
         *  differently than the kernel -- it just tallies the non-reserved
         *  pages that have a count of greater than 1.
	 */
        pct = (shared_pages * 100)/totalram_pages;
        fprintf(fp, "%10s  %7ld  %11s  %3ld%% of TOTAL MEM\n", 
		"SHARED", shared_pages, pages_to_size(shared_pages, buf), pct);

	subtract_buffer_pages = 0;
	if (symbol_exists("buffermem_pages")) { 
                get_symbol_data("buffermem_pages", sizeof(int), &tmp);
		buffer_pages = (ulong)tmp;
	} else if (symbol_exists("buffermem")) {
                get_symbol_data("buffermem", sizeof(int), &tmp);
		buffer_pages = BTOP(tmp);
	} else if ((THIS_KERNEL_VERSION >= LINUX(2,6,0)) && 
		symbol_exists("nr_blockdev_pages")) {
		subtract_buffer_pages = buffer_pages = nr_blockdev_pages();
	} else
		buffer_pages = 0;

        pct = (buffer_pages * 100)/totalram_pages;
        fprintf(fp, "%10s  %7ld  %11s  %3ld%% of TOTAL MEM\n", 
		"BUFFERS", buffer_pages, pages_to_size(buffer_pages, buf), pct);

	if (CRASHDEBUG(1)) 
        	error(NOTE, "pages with buffers: %ld\n", get_buffers);

	/*
	 *  page_cache_size has evolved from a long to an atomic_t to
	 *  not existing at all.
	 */
	
	if (symbol_exists("page_cache_size")) {
		get_symbol_type("page_cache_size", NULL, &req);
        	if (req.length == sizeof(int)) {
                	get_symbol_data("page_cache_size", sizeof(int), &tmp);
                	page_cache_size = (long)tmp;
        	} else
                	get_symbol_data("page_cache_size", sizeof(long),
                        	&page_cache_size);
		page_cache_size -= subtract_buffer_pages;
	} else if (symbol_exists("nr_pagecache")) {
               	get_symbol_data("nr_pagecache", sizeof(int), &tmp);
               	page_cache_size = (long)tmp;
		page_cache_size -= subtract_buffer_pages;
	} else if (dump_vm_stat("NR_FILE_PAGES", &nr_file_pages)) {
		char *swapper_space = GETBUF(SIZE(address_space));
		
                if (!readmem(symbol_value("swapper_space"), KVADDR, swapper_space,
                    SIZE(address_space), "swapper_space", RETURN_ON_ERROR))
			swapper_space_nrpages = 0;
		else
			swapper_space_nrpages = ULONG(swapper_space + 
				OFFSET(address_space_nrpages));
			
		page_cache_size = nr_file_pages - swapper_space_nrpages -
			buffer_pages;
		FREEBUF(swapper_space);
	}


        pct = (page_cache_size * 100)/totalram_pages;
        fprintf(fp, "%10s  %7ld  %11s  %3ld%% of TOTAL MEM\n", 
		"CACHED", page_cache_size, 
		pages_to_size(page_cache_size, buf), pct);

	/*
 	 *  Although /proc/meminfo doesn't show it, show how much memory
	 *  the slabs take up.
	 */

        pct = (get_slabs * 100)/totalram_pages;
	fprintf(fp, "%10s  %7ld  %11s  %3ld%% of TOTAL MEM\n",
		"SLAB", get_slabs, pages_to_size(get_slabs, buf), pct);

        if (symbol_exists("totalhigh_pages")) {
	        switch (get_syment_array("totalhigh_pages", sp_array, 2))
	        {
	        case 1:
	                get_symbol_data("totalhigh_pages", sizeof(ulong),
	                        &totalhigh_pages);
	                break;
	        case 2:
	                if (!(readmem(sp_array[0]->value, KVADDR,
	                    &value1, sizeof(ulong),
	                    "totalhigh_pages #1", RETURN_ON_ERROR)))
	                        break;
	                if (!(readmem(sp_array[1]->value, KVADDR,
	                    &value2, sizeof(ulong),
	                    "totalhigh_pages #2", RETURN_ON_ERROR)))
	                        break;
	                totalhigh_pages = MAX(value1, value2);
	                break;
	        }

		pct = totalhigh_pages ?
			(totalhigh_pages * 100)/totalram_pages : 0;
                fprintf(fp, "\n%10s  %7ld  %11s  %3ld%% of TOTAL MEM\n", 
			"TOTAL HIGH", totalhigh_pages, 
			pages_to_size(totalhigh_pages, buf), pct);

		meminfo.flags = GET_FREE_HIGHMEM_PAGES;
                vt->dump_free_pages(&meminfo);
		freehighmem_pages = meminfo.retval;
        	pct = freehighmem_pages ?  
			(freehighmem_pages * 100)/totalhigh_pages : 0;
                fprintf(fp, "%10s  %7ld  %11s  %3ld%% of TOTAL HIGH\n", 
			"FREE HIGH", freehighmem_pages, 
			pages_to_size(freehighmem_pages, buf), pct);

                totallowmem_pages = totalram_pages - totalhigh_pages;
		pct = (totallowmem_pages * 100)/totalram_pages;
                fprintf(fp, "%10s  %7ld  %11s  %3ld%% of TOTAL MEM\n", 
			"TOTAL LOW", totallowmem_pages, 
			pages_to_size(totallowmem_pages, buf), pct);

                freelowmem_pages = freeram_pages - freehighmem_pages;
        	pct = (freelowmem_pages * 100)/totallowmem_pages;
                fprintf(fp, "%10s  %7ld  %11s  %3ld%% of TOTAL LOW\n", 
			"FREE LOW", freelowmem_pages, 
			pages_to_size(freelowmem_pages, buf), pct);
        }

        /*
         *  get swap data from dump_swap_info().
         */
	fprintf(fp, "\n");
        if (dump_swap_info(RETURN_ON_ERROR, &totalswap_pages, 
	    &totalused_pages)) {
	        fprintf(fp, "%10s  %7ld  %11s         ----\n", 
			"TOTAL SWAP", totalswap_pages, 
			pages_to_size(totalswap_pages, buf));
	        pct = totalswap_pages ? (totalused_pages * 100) /
			totalswap_pages : 100;
	        fprintf(fp, "%10s  %7ld  %11s  %3ld%% of TOTAL SWAP\n",
	                "SWAP USED", totalused_pages,
	                pages_to_size(totalused_pages, buf), pct);
	        pct = totalswap_pages ? ((totalswap_pages - totalused_pages) *
			100) / totalswap_pages : 0;
	        fprintf(fp, "%10s  %7ld  %11s  %3ld%% of TOTAL SWAP\n", 
			"SWAP FREE",
	                totalswap_pages - totalused_pages,
	                pages_to_size(totalswap_pages - totalused_pages, buf), 
			pct);
	} else
		error(INFO, "swap_info[%ld].swap_map at %lx is unaccessible\n",
			totalused_pages, totalswap_pages);

	dump_zone_page_usage();
}

/*
 *  Emulate 2.6 nr_blockdev_pages() function.
 */
static ulong
nr_blockdev_pages(void)
{
        struct list_data list_data, *ld;
	ulong *bdevlist;
	int i, bdevcnt;
	ulong inode, address_space;
	ulong nrpages;
	char *block_device_buf, *inode_buf, *address_space_buf;

        ld = &list_data;
        BZERO(ld, sizeof(struct list_data));
	get_symbol_data("all_bdevs", sizeof(void *), &ld->start);
	if (empty_list(ld->start))
		return 0;
	ld->end = symbol_value("all_bdevs");
        ld->list_head_offset = OFFSET(block_device_bd_list);

	block_device_buf = GETBUF(SIZE(block_device));
	inode_buf = GETBUF(SIZE(inode));
	address_space_buf = GETBUF(SIZE(address_space));

        hq_open();
        bdevcnt = do_list(ld);
        bdevlist = (ulong *)GETBUF(bdevcnt * sizeof(ulong));
        bdevcnt = retrieve_list(bdevlist, bdevcnt);
        hq_close();

	/*
	 *  go through the block_device list, emulating:
	 *
	 *      ret += bdev->bd_inode->i_mapping->nrpages;
	 */
	for (i = nrpages = 0; i < bdevcnt; i++) {
                readmem(bdevlist[i], KVADDR, block_device_buf, 
			SIZE(block_device), "block_device buffer", 
			FAULT_ON_ERROR);
		inode = ULONG(block_device_buf + OFFSET(block_device_bd_inode));
                readmem(inode, KVADDR, inode_buf, SIZE(inode), "inode buffer", 
			FAULT_ON_ERROR);
		address_space = ULONG(inode_buf + OFFSET(inode_i_mapping));
                readmem(address_space, KVADDR, address_space_buf, 
			SIZE(address_space), "address_space buffer", 
			FAULT_ON_ERROR);
		nrpages += ULONG(address_space_buf + 
			OFFSET(address_space_nrpages));
	}

	FREEBUF(bdevlist);
	FREEBUF(block_device_buf);
	FREEBUF(inode_buf);
	FREEBUF(address_space_buf);

	return nrpages;
} 

/*
 *  dump_vmlist() displays information from the vmlist.
 */

static void
dump_vmlist(struct meminfo *vi)
{
	char buf[BUFSIZE];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	ulong vmlist;
	ulong addr, size, next, pcheck, count; 
	physaddr_t paddr;

	get_symbol_data("vmlist", sizeof(void *), &vmlist);
	next = vmlist;
	count = 0;

	while (next) {
		if (!(pc->curcmd_flags & HEADER_PRINTED) && (next == vmlist) && 
		    !(vi->flags & (GET_HIGHEST|GET_PHYS_TO_VMALLOC|
		      GET_VMLIST_COUNT|GET_VMLIST))) {
			fprintf(fp, "%s  ", 
			    mkstring(buf, MAX(strlen("VM_STRUCT"), VADDR_PRLEN),
			    	CENTER|LJUST, "VM_STRUCT"));
			fprintf(fp, "%s    SIZE\n",
			    mkstring(buf, (VADDR_PRLEN * 2) + strlen(" - "),
				CENTER|LJUST, "ADDRESS RANGE"));
			pc->curcmd_flags |= HEADER_PRINTED;
		}

                readmem(next+OFFSET(vm_struct_addr), KVADDR, 
			&addr, sizeof(void *),
                        "vmlist addr", FAULT_ON_ERROR);
                readmem(next+OFFSET(vm_struct_size), KVADDR, 
			&size, sizeof(ulong),
                        "vmlist size", FAULT_ON_ERROR);

		if (vi->flags & (GET_VMLIST_COUNT|GET_VMLIST)) {
			/*
			 *  Preceding GET_VMLIST_COUNT set vi->retval.
			 */
			if (vi->flags & GET_VMLIST) {
				if (count < vi->retval) {
					vi->vmlist[count].addr = addr;
					vi->vmlist[count].size = size;
				}
			}
			count++;
			goto next_entry;
		}

		if (!(vi->flags & ADDRESS_SPECIFIED) || 
		    ((vi->memtype == KVADDR) &&
		    ((vi->spec_addr >= addr) && (vi->spec_addr < (addr+size)))))
			fprintf(fp, "%s%s  %s - %s  %6ld\n",
				mkstring(buf,VADDR_PRLEN, LONG_HEX|CENTER|LJUST,
				MKSTR(next)), space(MINSPACE-1),
				mkstring(buf1, VADDR_PRLEN, LONG_HEX|RJUST,
				MKSTR(addr)),
				mkstring(buf2, VADDR_PRLEN, LONG_HEX|LJUST,
				MKSTR(addr+size)),
				size);

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
						"%s%s  %s - %s  %6ld\n",
						mkstring(buf, VADDR_PRLEN,
						LONG_HEX|CENTER|LJUST,
						MKSTR(next)), space(MINSPACE-1),
						mkstring(buf1, VADDR_PRLEN,
						LONG_HEX|RJUST, MKSTR(addr)),
						mkstring(buf2, VADDR_PRLEN,
						LONG_HEX|LJUST,
						MKSTR(addr+size)), size);
					break;
				}
			}

		}
next_entry:
                readmem(next+OFFSET(vm_struct_next), 
			KVADDR, &next, sizeof(void *),
                        "vmlist next", FAULT_ON_ERROR);
	}

	if (vi->flags & GET_HIGHEST)
		vi->retval = addr+size;

	if (vi->flags & GET_VMLIST_COUNT)
		vi->retval = count;
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
	struct node_table *nt;
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
		if (INVALID_MEMBER(zone_struct_inactive_clean_list))
			error(FATAL, 
		        "inactive_clean_list(s) do not exist in this kernel\n");

        	get_symbol_data("pgdat_list", sizeof(void *), &pgdat);

                if ((mi->flags & VERBOSE) && 
		    (mi->flags & (GET_ACTIVE_LIST|GET_INACTIVE_DIRTY)))
			fprintf(fp, "\n");

        	for (n = 0; pgdat; n++) {
                	nt = &vt->node_table[n];

                	node_zones = nt->pgdat + OFFSET(pglist_data_node_zones);

                	for (i = 0; i < vt->nr_zones; i++) {
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

                	readmem(pgdat + OFFSET_OPTION(pglist_data_node_next,
				pglist_data_pgdat_next), KVADDR,
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
	long next_offset, name_offset;
	char *cache_buf;

	if (vt->flags & KMEM_CACHE_UNAVAIL) {
		error(INFO, "kmem cache slab subsystem not available\n");
		return NULL;
	}

        name_offset = vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2) ?
                OFFSET(kmem_cache_s_name) : OFFSET(kmem_cache_s_c_name);
        next_offset = vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2) ?
                OFFSET(kmem_cache_s_next) : OFFSET(kmem_cache_s_c_nextp);

        cache = cache_cache = symbol_value("cache_cache");

	cache_buf = GETBUF(SIZE(kmem_cache_s));

        do {
	        readmem(cache, KVADDR, cache_buf, SIZE(kmem_cache_s),
	        	"kmem_cache_s buffer", FAULT_ON_ERROR);

		if (cache == vaddr) {
	                if (vt->kmem_cache_namelen) {
				BCOPY(cache_buf+name_offset, kbuf, 
					vt->kmem_cache_namelen);
	                } else {
				name = ULONG(cache_buf + name_offset);
	                        if (!read_string(name, kbuf, BUFSIZE-1)) {
					if (vt->flags & 
					  (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2))
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

		if (vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2))
			cache -= next_offset;

        } while (cache != cache_cache);

	FREEBUF(cache_buf);
	return NULL;
}

/*
 *  Note same functionality as above, but instead it just
 *  dumps all slab cache names and their addresses.
 */
static void
kmem_cache_list(void)
{
        ulong cache, cache_cache, name;
	long next_offset, name_offset;
	char *cache_buf;
	char buf[BUFSIZE];

	if (vt->flags & KMEM_CACHE_UNAVAIL) {
		error(INFO, "kmem cache slab subsystem not available\n");
		return;
	}

        name_offset = vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2) ?
                OFFSET(kmem_cache_s_name) : OFFSET(kmem_cache_s_c_name);
        next_offset = vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2) ?
                OFFSET(kmem_cache_s_next) : OFFSET(kmem_cache_s_c_nextp);

        cache = cache_cache = symbol_value("cache_cache");

	cache_buf = GETBUF(SIZE(kmem_cache_s));

        do {
	        readmem(cache, KVADDR, cache_buf, SIZE(kmem_cache_s),
	        	"kmem_cache_s buffer", FAULT_ON_ERROR);

	        if (vt->kmem_cache_namelen) {
			BCOPY(cache_buf+name_offset, buf, 
				vt->kmem_cache_namelen);
	        } else {
			name = ULONG(cache_buf + name_offset);
	                if (!read_string(name, buf, BUFSIZE-1)) {
				if (vt->flags & 
				    (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2))
	                               	error(FATAL,
	                      "cannot read kmem_cache_s.name string at %lx\n",
	                                       	name);
				else
	                               	error(FATAL,
	                      "cannot read kmem_cache_s.c_name string at %lx\n",
	                                       	name);
			}
	        }

		fprintf(fp, "%lx %s\n", cache, buf);

		cache = ULONG(cache_buf + next_offset);

		if (vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2))
			cache -= next_offset;

        } while (cache != cache_cache);

	FREEBUF(cache_buf);
}

/*
 *  Translate an address to its physical page number, verify that the
 *  page in fact belongs to the slab subsystem, and if so, return the 
 *  name of the cache to which it belongs.
 */
static char *
vaddr_to_kmem_cache(ulong vaddr, char *buf)
{
	physaddr_t paddr;
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

	if (VALID_MEMBER(page_next))
                readmem(page+OFFSET(page_next),
                        KVADDR, &cache, sizeof(void *),
                        "page.next", FAULT_ON_ERROR);
	else if (VALID_MEMBER(page_list_next))
                readmem(page+OFFSET(page_list_next),
                        KVADDR, &cache, sizeof(void *),
                        "page.list.next", FAULT_ON_ERROR);
	else if (VALID_MEMBER(page_lru))
                readmem(page+OFFSET(page_lru)+OFFSET(list_head_next),
                        KVADDR, &cache, sizeof(void *),
                        "page.lru.next", FAULT_ON_ERROR);
	else
		error(FATAL, "cannot determine slab cache from page struct\n");

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
        physaddr_t paddr;
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

        if (VALID_MEMBER(page_prev))
                readmem(page+OFFSET(page_prev),
                        KVADDR, &slab, sizeof(void *),
                        "page.prev", FAULT_ON_ERROR);
        else if (VALID_MEMBER(page_list_prev))
                readmem(page+OFFSET(page_list_prev),
                        KVADDR, &slab, sizeof(void *),
                        "page.list.prev", FAULT_ON_ERROR);
	else if (VALID_MEMBER(page_lru))
                readmem(page+OFFSET(page_lru)+OFFSET(list_head_prev),
                        KVADDR, &slab, sizeof(void *),
                        "page.lru.prev", FAULT_ON_ERROR);
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
	ulong cache, cache_end, max_cnum, max_limit, max_cpus, tmp, tmp2;
	long cache_count, num_offset, next_offset;
	char *cache_buf;

	if (vt->flags & KMEM_CACHE_UNAVAIL)
		return;

	if ((vt->flags & KMEM_CACHE_DELAY) && !(pc->flags & RUNTIME))
		return;

	if (DUMPFILE() && (vt->flags & KMEM_CACHE_INIT))
		return; 

	please_wait("gathering kmem slab cache data");

        if (!strlen(slab_hdr)) 
                sprintf(slab_hdr, 
		    "SLAB%sMEMORY%sTOTAL  ALLOCATED  FREE\n",
                        space(VADDR_PRLEN > 8 ? 14 : 6),
                        space(VADDR_PRLEN > 8 ? 12 : 4));

	if (!strlen(kmem_cache_hdr)) 
		sprintf(kmem_cache_hdr,
     "CACHE%sNAME                 OBJSIZE  ALLOCATED     TOTAL  SLABS  SSIZE\n",
			space(VADDR_PRLEN > 8 ? 12 : 4));

	if (!strlen(free_inuse_hdr)) 
		sprintf(free_inuse_hdr, "FREE / [ALLOCATED]\n");

	num_offset = vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2) ? 
		OFFSET(kmem_cache_s_num) : OFFSET(kmem_cache_s_c_num);
	next_offset = vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2) ?
		OFFSET(kmem_cache_s_next) : OFFSET(kmem_cache_s_c_nextp);
        max_cnum = max_limit = max_cpus = cache_count = 0;

	/*
	 *  Pre-2.6 versions used the "cache_cache" as the head of the
	 *  slab chain list.  2.6 uses the "cache_chain" list_head.
	 */
        if (vt->flags & PERCPU_KMALLOC_V2) {
                get_symbol_data("cache_chain", sizeof(ulong), &cache);
		cache -= next_offset;
                cache_end = symbol_value("cache_chain");
        } else
                cache = cache_end = symbol_value("cache_cache");

	cache_buf = GETBUF(SIZE(kmem_cache_s));

        do {
		cache_count++;

                if (!readmem(cache, KVADDR, cache_buf, SIZE(kmem_cache_s),
                        "kmem_cache_s buffer", RETURN_ON_ERROR)) {
			FREEBUF(cache_buf);
			vt->flags |= KMEM_CACHE_UNAVAIL;
			error(INFO, 
		          "%sunable to initialize kmem slab cache subsystem\n\n",
				DUMPFILE() ? "\n" : "");
			return;
		}

		tmp = (ulong)(UINT(cache_buf + num_offset));

                if (tmp > max_cnum)
                        max_cnum = tmp;

		if ((tmp = max_cpudata_limit(cache, &tmp2)) > max_limit)
			max_limit = tmp;
		/*
		 *  Recognize and bail out on any max_cpudata_limit() failures.
		 */
		if (vt->flags & KMEM_CACHE_UNAVAIL) {
			FREEBUF(cache_buf);
			return;
		}

		if (tmp2 > max_cpus)
			max_cpus = tmp2;

		cache = ULONG(cache_buf + next_offset);

		switch (vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2)) 
		{
		case PERCPU_KMALLOC_V1:
			cache -= next_offset;
			break;
		case PERCPU_KMALLOC_V2:
			if (cache != cache_end)
				cache -= next_offset;
			break;
		}

        } while (cache != cache_end);

	FREEBUF(cache_buf);

	vt->kmem_max_c_num = max_cnum;
	vt->kmem_max_limit = max_limit;
	vt->kmem_max_cpus = max_cpus;
	vt->kmem_cache_count = cache_count;

	if (CRASHDEBUG(2)) {
		fprintf(fp, "kmem_cache_init:\n");
		fprintf(fp, "  kmem_max_c_num: %ld\n", vt->kmem_max_c_num);
		fprintf(fp, "  kmem_max_limit: %ld\n", vt->kmem_max_limit);
		fprintf(fp, "  kmem_max_cpus: %ld\n", vt->kmem_max_cpus);
		fprintf(fp, "  kmem_cache_count: %ld\n", vt->kmem_cache_count);
	}

	if (!(vt->flags & KMEM_CACHE_INIT)) {
		if (vt->flags & PERCPU_KMALLOC_V1)
			ARRAY_LENGTH_INIT(vt->kmem_cache_namelen,
				kmem_cache_s_name, "kmem_cache_s.name", 
				NULL, sizeof(char));
		else if (vt->flags & PERCPU_KMALLOC_V2)
			vt->kmem_cache_namelen = 0;
		else
			ARRAY_LENGTH_INIT(vt->kmem_cache_namelen,
				kmem_cache_s_c_name, "kmem_cache_s.c_name", 
				NULL, 0);
	}

	please_wait_done();

	vt->flags |= KMEM_CACHE_INIT;
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
	ulong shared; 
	ulong *start_address;
	
	if (vt->flags & PERCPU_KMALLOC_V2_NODES)
		goto kmem_cache_s_array_nodes;
	
	if (vt->flags & PERCPU_KMALLOC_V2)
		goto kmem_cache_s_array;
	
	 if (INVALID_MEMBER(kmem_cache_s_cpudata)) {
		*cpus = 0;
		return 0;
	}

	if (!readmem(cache+OFFSET(kmem_cache_s_cpudata),
            KVADDR, &cpudata[0], 
	    sizeof(ulong) * ARRAY_LENGTH(kmem_cache_s_cpudata),
            "cpudata array", RETURN_ON_ERROR))
		goto bail_out;

	for (i = max_limit = 0; (i < ARRAY_LENGTH(kmem_cache_s_cpudata)) && 
	     cpudata[i]; i++) {
		if (!readmem(cpudata[i]+OFFSET(cpucache_s_limit),
        	    KVADDR, &limit, sizeof(int),
                    "cpucache limit", RETURN_ON_ERROR))
			goto bail_out;
		if (limit > max_limit)
			max_limit = limit;
	}

	*cpus = i;

	return max_limit;

kmem_cache_s_array:

	if (!readmem(cache+OFFSET(kmem_cache_s_array),
            KVADDR, &cpudata[0], 
	    sizeof(ulong) * ARRAY_LENGTH(kmem_cache_s_array),
            "array cache array", RETURN_ON_ERROR))
		goto bail_out;

	for (i = max_limit = 0; (i < ARRAY_LENGTH(kmem_cache_s_array)) && 
	     cpudata[i]; i++) {
                if (!readmem(cpudata[i]+OFFSET(array_cache_limit),
                    KVADDR, &limit, sizeof(int),
                    "array cache limit", RETURN_ON_ERROR))
			goto bail_out;
                if (limit > max_limit)
                        max_limit = limit;
        }

	/*
	 *  If the shared list can be accessed, check its size as well.
	 */
	if (VALID_MEMBER(kmem_list3_shared) &&
	    VALID_MEMBER(kmem_cache_s_lists) &&
            readmem(cache+OFFSET(kmem_cache_s_lists)+OFFSET(kmem_list3_shared),
	    KVADDR, &shared, sizeof(void *), "kmem_list3 shared", 
	    RETURN_ON_ERROR|QUIET) &&
	    readmem(shared+OFFSET(array_cache_limit), 
	    KVADDR, &limit, sizeof(int), "shared array_cache limit",
	    RETURN_ON_ERROR|QUIET)) {
		if (limit > max_limit)
			max_limit = limit;
	}
		   
	*cpus = i;
	return max_limit;

kmem_cache_s_array_nodes:

	if (!readmem(cache+OFFSET(kmem_cache_s_array),
            KVADDR, &cpudata[0], 
	    sizeof(ulong) * ARRAY_LENGTH(kmem_cache_s_array),
            "array cache array", RETURN_ON_ERROR))
		goto bail_out;

	for (i = max_limit = 0; (i < ARRAY_LENGTH(kmem_cache_s_array)) && 
	     cpudata[i]; i++) {
                if (!readmem(cpudata[i]+OFFSET(array_cache_limit),
                    KVADDR, &limit, sizeof(int),
                    "array cache limit", RETURN_ON_ERROR))
			goto bail_out;
                if (limit > max_limit)
                        max_limit = limit;
        }

	*cpus = i;

	/*
	 *  Check the shared list of all the nodes.
	 */
	start_address = (ulong *)GETBUF(sizeof(ulong) * vt->kmem_cache_len_nodes);
	
	if (VALID_MEMBER(kmem_list3_shared) && VALID_MEMBER(kmem_cache_s_lists) &&
	    readmem(cache+OFFSET(kmem_cache_s_lists), KVADDR, &start_address[0], 
	    sizeof(ulong) * vt->kmem_cache_len_nodes, "array nodelist array", 
	    RETURN_ON_ERROR)) {  
		for (i = 0; i < vt->kmem_cache_len_nodes && start_address[i]; i++) {
			if (readmem(start_address[i] + OFFSET(kmem_list3_shared), 
			    KVADDR, &shared, sizeof(void *),
			    "kmem_list3 shared", RETURN_ON_ERROR|QUIET) &&
			    readmem(shared + OFFSET(array_cache_limit),
	       		    KVADDR, &limit, sizeof(int), "shared array_cache limit",
		            RETURN_ON_ERROR|QUIET)) {
				if (limit > max_limit)
					max_limit = limit;
			}
		}
	}
	FREEBUF(start_address);
	return max_limit;

bail_out:
	vt->flags |= KMEM_CACHE_UNAVAIL;
	error(INFO, "unable to initialize kmem slab cache subsystem\n\n");
	*cpus = 0;
	return 0;
}

/*
 *  Determine whether the current slab cache is contained in
 *  the comma-separated list from a "kmem -I list1,list2 ..."
 *  command entry.
 */
static int
ignore_cache(struct meminfo *si, char *name)
{
	int i, argc;
	char *p1;
	char *arglist[MAXARGS];
	char buf[BUFSIZE];

	if (!si->ignore)
		return FALSE;

	strcpy(buf, si->ignore);

	p1 = buf;
	while (*p1) {
		if (*p1 == ',')
			*p1 = ' ';
		p1++;
	}

	argc = parse_line(buf, arglist);

	for (i = 0; i < argc; i++) {
		if (STREQ(name, arglist[i]))
			return TRUE;
	}

	return FALSE;
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
#define KMEM_OBJECT_ADDR_SHARED (7)

#define DUMP_KMEM_CACHE_INFO_V1() \
      {  \
	char b1[BUFSIZE]; \
	fprintf(fp, "%s %-18s  %8ld  ", \
		mkstring(b1, VADDR_PRLEN, LJUST|LONG_HEX, MKSTR(si->cache)), \
        	buf, si->size); \
        fprintf(fp, "%9ld  %8ld  %5ld   %3ldk\n", \
		vt->flags & PERCPU_KMALLOC_V1 ? \
		si->inuse - si->cpucached_cache : \
                si->inuse, si->num_slabs * si->c_num, \
                si->num_slabs, si->slabsize/1024); \
      }

#define DUMP_KMEM_CACHE_INFO_V2()  dump_kmem_cache_info_v2(si) 

static void
dump_kmem_cache_info_v2(struct meminfo *si)
{
	char b1[BUFSIZE];
	char b2[BUFSIZE];
	int namelen, sizelen, spacelen;

	fprintf(fp, "%s ",
		mkstring(b1, VADDR_PRLEN, LJUST|LONG_HEX, MKSTR(si->cache))); 

	namelen = strlen(si->curname);
	sprintf(b2, "%ld", si->size);
	sizelen = strlen(b2);
	spacelen = 0;

	if (namelen++ > 18) {
		spacelen = 29 - namelen - sizelen;
		fprintf(fp, "%s%s%ld  ", si->curname,
			space(spacelen <= 0 ? 1 : spacelen), si->size); 
		if (spacelen > 0)
			spacelen = 1;
		sprintf(b1, "%c%dld  ", '%', 9 + spacelen - 1);
	} else {
		fprintf(fp, "%-18s  %8ld  ", si->curname, si->size); 
		sprintf(b1, "%c%dld  ", '%', 9);
	}

        fprintf(fp, b1, vt->flags & (PERCPU_KMALLOC_V2) ?
                si->inuse - si->cpucached_cache : si->inuse); 

        fprintf(fp, "%8ld  %5ld   %3ldk\n",  
		si->num_slabs * si->c_num, 
                si->num_slabs, si->slabsize/1024); 
}

#define DUMP_SLAB_INFO() \
      { \
        char b1[BUFSIZE], b2[BUFSIZE]; \
        ulong allocated, freeobjs; \
        if (vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2)) { \
                allocated = si->s_inuse - si->cpucached_slab; \
                freeobjs = si->c_num - allocated - si->cpucached_slab; \
        } else { \
                allocated = si->s_inuse; \
                freeobjs = si->c_num - si->s_inuse; \
        } \
        fprintf(fp, "%s  %s  %5ld  %9ld  %4ld\n", \
                mkstring(b1, VADDR_PRLEN, LJUST|LONG_HEX, MKSTR(si->slab)), \
                mkstring(b2, VADDR_PRLEN, LJUST|LONG_HEX, MKSTR(si->s_mem)), \
                si->c_num, allocated, \
                vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2) ? \
		freeobjs + si->cpucached_slab : freeobjs); \
      }

static void
dump_kmem_cache(struct meminfo *si)
{
	char buf[BUFSIZE];
	char kbuf[BUFSIZE];
	char *reqname;
	ulong cache_cache;
	ulong name, magic;
	int cnt;
	char *p1;

	if (vt->flags & (PERCPU_KMALLOC_V1|PERCPU_KMALLOC_V2)) 
		error(FATAL, 
		    "dump_kmem_cache called with PERCPU_KMALLOC_V[12] set\n");

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

		if (vt->kmem_cache_namelen) {
			BCOPY(si->cache_buf + OFFSET(kmem_cache_s_c_name),
				buf, vt->kmem_cache_namelen);
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

		if (ignore_cache(si, buf)) {
			fprintf(fp, "%lx %-18s [IGNORED]\n", si->cache, buf);
			goto next_cache;
		}

		si->curname = buf;

		if (CRASHDEBUG(1))
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
				DUMP_KMEM_CACHE_INFO_V1();

			if (si->flags == GET_SLAB_PAGES) 
				si->retval += (si->num_slabs * 
				    	(si->slabsize/PAGESIZE()));

			if (si->flags & (VERBOSE|ADDRESS_SPECIFIED)) {
				si->slab = (si->flags & ADDRESS_SPECIFIED) ?
					vaddr_to_slab(si->spec_addr) : 0;
			
				do_slab_chain(SLAB_WALKTHROUGH, si);

				if (si->found) {
					fprintf(fp, kmem_cache_hdr);
					DUMP_KMEM_CACHE_INFO_V1();
					fprintf(fp, slab_hdr);
					DUMP_SLAB_INFO();

					switch (si->found)
					{
					case KMEM_BUFCTL_ADDR:
						fprintf(fp, "   %lx ", 
							(ulong)si->spec_addr);
						fprintf(fp, 
						   "(ON-SLAB kmem_bufctl_t)\n");
						break;

					case KMEM_SLAB_ADDR:
						fprintf(fp, "   %lx ", 
							(ulong)si->spec_addr);
						fprintf(fp,
					            "(ON-SLAB kmem_slab_t)\n");
						break;

					case KMEM_ON_SLAB:
						fprintf(fp, "   %lx ", 
							(ulong)si->spec_addr);
						fprintf(fp, 
						    "(unused part of slab)\n");
						break;
						
					case KMEM_OBJECT_ADDR_FREE:
                                                fprintf(fp, free_inuse_hdr);
						fprintf(fp, "   %lx\n", 
                                                        (ulong)si->spec_addr);
						break;

                                        case KMEM_OBJECT_ADDR_INUSE:
                                                fprintf(fp, free_inuse_hdr);
                                                fprintf(fp, "  [%lx]\n",
                                                        (ulong)si->spec_addr);
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
dump_kmem_cache_percpu_v1(struct meminfo *si)
{
	int i;
	char buf[BUFSIZE];
	char kbuf[BUFSIZE];
	char *reqname;
	ulong cache_cache;
	ulong name;
	int cnt;
	uint tmp_val;  /* Used as temporary variable to read sizeof(int) and 
			assigned to ulong variable. We are doing this to mask
			the endian issue */
	char *p1;

        if (!(vt->flags & PERCPU_KMALLOC_V1)) 
                error(FATAL, 
                   "dump_kmem_cache_percpu called without PERCPU_KMALLOC_V1\n");

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

		if (vt->kmem_cache_namelen) {
                        readmem(si->cache+OFFSET(kmem_cache_s_name), 
				KVADDR, buf, vt->kmem_cache_namelen,
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

                if (ignore_cache(si, buf)) {
                        fprintf(fp, "%lx %-18s [IGNORED]\n", si->cache, buf);
                        goto next_cache;
                }

		si->curname = buf;

	        readmem(si->cache+OFFSET(kmem_cache_s_objsize),
	        	KVADDR, &tmp_val, sizeof(uint),
	                "objsize", FAULT_ON_ERROR);
		si->size = (ulong)tmp_val;

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
			KVADDR, &tmp_val, sizeof(uint),
	                "kmem_cache_s flags", FAULT_ON_ERROR);
		si->c_flags = (ulong)tmp_val;

                readmem(si->cache+OFFSET(kmem_cache_s_gfporder),
                        KVADDR, &tmp_val, sizeof(uint),
                        "gfporder", FAULT_ON_ERROR);
		si->order = (ulong)tmp_val;

        	readmem(si->cache+OFFSET(kmem_cache_s_num),
                	KVADDR, &tmp_val, sizeof(uint),
                	"kmem_cache_s num", FAULT_ON_ERROR);
		si->c_num = (ulong)tmp_val;

		do_slab_chain_percpu_v1(SLAB_GET_COUNTS, si);

		if (!(si->flags & (ADDRESS_SPECIFIED|GET_SLAB_PAGES))) {
			DUMP_KMEM_CACHE_INFO_V1();
			if (CRASHDEBUG(3))
				dump_struct("kmem_cache_s", si->cache, 0);
		}

		if (si->flags == GET_SLAB_PAGES) 
			si->retval += (si->num_slabs * 
				(si->slabsize/PAGESIZE()));

		if (si->flags & (VERBOSE|ADDRESS_SPECIFIED)) {

			gather_cpudata_list_v1(si);

                        si->slab = (si->flags & ADDRESS_SPECIFIED) ?
                        	vaddr_to_slab(si->spec_addr) : 0;

			do_slab_chain_percpu_v1(SLAB_WALKTHROUGH, si);

			if (si->found) {
				fprintf(fp, kmem_cache_hdr);
				DUMP_KMEM_CACHE_INFO_V1();
				fprintf(fp, slab_hdr);
        			gather_slab_cached_count(si);
				DUMP_SLAB_INFO();

				switch (si->found)
				{
				case KMEM_BUFCTL_ADDR:
					fprintf(fp, "   %lx ", 
						(ulong)si->spec_addr);
					fprintf(fp,"(kmem_bufctl_t)\n");
					break;

				case KMEM_SLAB_ADDR:
					fprintf(fp, "   %lx ", 
						(ulong)si->spec_addr);
					fprintf(fp, "(slab_s)\n");
					break;

				case KMEM_ON_SLAB:
					fprintf(fp, "   %lx ", 
						(ulong)si->spec_addr);
					fprintf(fp, "(unused part of slab)\n");
					break;
						
				case KMEM_OBJECT_ADDR_FREE:
                                        fprintf(fp, free_inuse_hdr);
					fprintf(fp, "   %lx\n", 
						(ulong)si->spec_addr);
					break;

                                case KMEM_OBJECT_ADDR_INUSE:
                                        fprintf(fp, free_inuse_hdr);
                                        fprintf(fp, "  [%lx]\n", 
						(ulong)si->spec_addr);
                                        break;

                                case KMEM_OBJECT_ADDR_CACHED:
                                        fprintf(fp, free_inuse_hdr);
                                        fprintf(fp, 
					    "   %lx  (cpu %d cache)\n", 
						(ulong)si->spec_addr, si->cpu);
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
 *  Updated for 2.6 slab substructure. 
 */
static void
dump_kmem_cache_percpu_v2(struct meminfo *si)
{
	int i;
	char buf[BUFSIZE];
	char kbuf[BUFSIZE];
	char *reqname;
	ulong cache_end;
	ulong name;
	int cnt;
	uint tmp_val; /* Used as temporary variable to read sizeof(int) and
			assigned to ulong variable. We are doing this to mask
			the endian issue */
	char *p1;

        if (!(vt->flags & PERCPU_KMALLOC_V2)) 
                error(FATAL, 
                   "dump_kmem_cache_percpu called without PERCPU_KMALLOC_V2\n");

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
	if(vt->flags & PERCPU_KMALLOC_V2_NODES)
		si->shared_array_cache = (ulong *)
			GETBUF(vt->kmem_cache_len_nodes * 
				(vt->kmem_max_limit+1) * sizeof(ulong)); 
	else
		si->shared_array_cache = (ulong *)
			GETBUF((vt->kmem_max_limit+1) * sizeof(ulong)); 

	cnt = 0;

        get_symbol_data("cache_chain", sizeof(ulong), &si->cache);
        si->cache -= OFFSET(kmem_cache_s_next);
        cache_end = symbol_value("cache_chain");

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

		if (vt->kmem_cache_namelen) {
                        readmem(si->cache+OFFSET(kmem_cache_s_name), 
				KVADDR, buf, vt->kmem_cache_namelen,
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

                if (ignore_cache(si, buf)) {
                        fprintf(fp, "%lx %-18s [IGNORED]\n", si->cache, buf);
                        goto next_cache;
                }

		si->curname = buf;

	        readmem(si->cache+OFFSET(kmem_cache_s_objsize),
	        	KVADDR, &tmp_val, sizeof(uint),
	                "objsize", FAULT_ON_ERROR);
		si->size = (ulong)tmp_val;

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
			KVADDR, &tmp_val, sizeof(uint),
	                "kmem_cache_s flags", FAULT_ON_ERROR);
		si->c_flags = (ulong)tmp_val;

                readmem(si->cache+OFFSET(kmem_cache_s_gfporder),
                        KVADDR, &tmp_val, sizeof(uint),
                        "gfporder", FAULT_ON_ERROR);
		si->order = (ulong)tmp_val;

        	readmem(si->cache+OFFSET(kmem_cache_s_num),
                	KVADDR, &tmp_val, sizeof(uint),
                	"kmem_cache_s num", FAULT_ON_ERROR);
		si->c_num = (ulong)tmp_val;

		if( vt->flags & PERCPU_KMALLOC_V2_NODES )
			do_slab_chain_percpu_v2_nodes(SLAB_GET_COUNTS, si);
		else
			do_slab_chain_percpu_v2(SLAB_GET_COUNTS, si);

		if (!(si->flags & (ADDRESS_SPECIFIED|GET_SLAB_PAGES))) {
			DUMP_KMEM_CACHE_INFO_V2();
			if (CRASHDEBUG(3))
				dump_struct("kmem_cache_s", si->cache, 0);
		}

		if (si->flags == GET_SLAB_PAGES) 
			si->retval += (si->num_slabs * 
				(si->slabsize/PAGESIZE()));

		if (si->flags & (VERBOSE|ADDRESS_SPECIFIED)) {

			if (!(vt->flags & PERCPU_KMALLOC_V2_NODES))
				gather_cpudata_list_v2(si);

                        si->slab = (si->flags & ADDRESS_SPECIFIED) ?
                        	vaddr_to_slab(si->spec_addr) : 0;

			if (vt->flags & PERCPU_KMALLOC_V2_NODES)
				do_slab_chain_percpu_v2_nodes(SLAB_WALKTHROUGH, si);
			else 
				do_slab_chain_percpu_v2(SLAB_WALKTHROUGH, si);

			if (si->found) {
				fprintf(fp, kmem_cache_hdr);
				DUMP_KMEM_CACHE_INFO_V2();
				fprintf(fp, slab_hdr);
        			gather_slab_cached_count(si);
				DUMP_SLAB_INFO();

				switch (si->found)
				{
				case KMEM_BUFCTL_ADDR:
					fprintf(fp, "   %lx ", 
						(ulong)si->spec_addr);
					fprintf(fp,"(kmem_bufctl_t)\n");
					break;

				case KMEM_SLAB_ADDR:
					fprintf(fp, "   %lx ", 
						(ulong)si->spec_addr);
					fprintf(fp, "(slab)\n");
					break;

				case KMEM_ON_SLAB:
					fprintf(fp, "   %lx ", 
						(ulong)si->spec_addr);
					fprintf(fp, "(unused part of slab)\n");
					break;
						
				case KMEM_OBJECT_ADDR_FREE:
                                        fprintf(fp, free_inuse_hdr);
					fprintf(fp, "   %lx\n", 
						(ulong)si->spec_addr);
					break;

                                case KMEM_OBJECT_ADDR_INUSE:
                                        fprintf(fp, free_inuse_hdr);
                                        fprintf(fp, "  [%lx]\n", 
						(ulong)si->spec_addr);
                                        break;

                                case KMEM_OBJECT_ADDR_CACHED:
                                        fprintf(fp, free_inuse_hdr);
                                        fprintf(fp, 
					    "   %lx  (cpu %d cache)\n", 
						(ulong)si->spec_addr, si->cpu);
                                        break;

                                case KMEM_OBJECT_ADDR_SHARED:
                                        fprintf(fp, free_inuse_hdr);
                                        fprintf(fp,
                                            "   %lx  (shared cache)\n",
                                                (ulong)si->spec_addr);
                                        break;
                                }

				break;
			}
		}

next_cache:
                readmem(si->cache+OFFSET(kmem_cache_s_next), 
		        KVADDR, &si->cache, sizeof(ulong),
                        "kmem_cache_s next", FAULT_ON_ERROR);

                if (si->cache != cache_end)
			si->cache -= OFFSET(kmem_cache_s_next);

	} while (si->cache != cache_end);

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
	FREEBUF(si->shared_array_cache);

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

		if (CRASHDEBUG(1)) {
			fprintf(fp, "search cache: [%s] ", si->curname);
			if (si->flags & ADDRESS_SPECIFIED) 
				fprintf(fp, "for %llx", si->spec_addr);
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

static char *slab_chain_name_v1[] = {"full", "partial", "free"};

static void
do_slab_chain_percpu_v1(long cmd, struct meminfo *si)
{
	int i, tmp, s;
	int list_borked;
	char *slab_s_buf;
	ulong specified_slab;
	ulong last;
	ulong slab_chains[SLAB_CHAINS];

	list_borked = 0;
	si->slabsize = (power(2, si->order) * PAGESIZE());
	si->cpucached_slab = 0;

	if (VALID_MEMBER(kmem_cache_s_slabs)) {
		slab_chains[0] = si->cache + OFFSET(kmem_cache_s_slabs);
		slab_chains[1] = 0;
		slab_chains[2] = 0;
	} else {
		slab_chains[0] = si->cache + OFFSET(kmem_cache_s_slabs_full);
		slab_chains[1] = si->cache + OFFSET(kmem_cache_s_slabs_partial);
		slab_chains[2] = si->cache + OFFSET(kmem_cache_s_slabs_free);
	}

	if (CRASHDEBUG(1)) {
		fprintf(fp, "[ %s: %lx ", si->curname, si->cache);
		fprintf(fp, "full: %lx partial: %lx free: %lx ]\n",
			slab_chains[0], slab_chains[1], slab_chains[2]);
	}

	switch (cmd)
	{
	case SLAB_GET_COUNTS:
		si->flags |= SLAB_GET_COUNTS;
		si->flags &= ~SLAB_WALKTHROUGH;
		si->cpucached_cache = 0;
        	si->num_slabs = si->inuse = 0;
		gather_cpudata_list_v1(si); 

		slab_s_buf = GETBUF(SIZE(slab_s));

		for (s = 0; s < SLAB_CHAINS; s++) {

			if (!slab_chains[s])
				continue;

	                if (!readmem(slab_chains[s],
	                    KVADDR, &si->slab, sizeof(ulong),
	                    "first slab", QUIET|RETURN_ON_ERROR)) {
                		error(INFO, 
				    "%s: %s list: bad slab pointer: %lx\n",
                        		si->curname, slab_chain_name_v1[s],
					slab_chains[s]);
				list_borked = 1;
				continue;
			}
	
			if (slab_data_saved(si)) {
				FREEBUF(slab_s_buf);
				return;
			}
	
			if (si->slab == slab_chains[s]) 
				continue;
	
			last = slab_chains[s];

			do {
	                        if (received_SIGINT()) {
					FREEBUF(slab_s_buf);
	                                restart(0);
				}

				if (!verify_slab_v1(si, last, s)) {
					list_borked = 1;
					continue;
				}
				last = si->slab - OFFSET(slab_s_list);
	
		                readmem(si->slab, KVADDR, slab_s_buf, 
					SIZE(slab_s), "slab_s buffer", 
					FAULT_ON_ERROR);
	
				tmp = INT(slab_s_buf + OFFSET(slab_s_inuse));
				si->inuse += tmp;
	
				if (ACTIVE())
					gather_cpudata_list_v1(si); 

				si->s_mem = ULONG(slab_s_buf + 
					OFFSET(slab_s_s_mem));
				gather_slab_cached_count(si);
	
				si->num_slabs++;
		
				si->slab = ULONG(slab_s_buf + 
					OFFSET(slab_s_list));
				si->slab -= OFFSET(slab_s_list);

				/*
				 *  Check for slab transition. (Tony Dziedzic)
				 */
				for (i = 0; i < SLAB_CHAINS; i++) {
     					if ((i != s) && 
					    (si->slab == slab_chains[i])) {
       						error(NOTE, 
	  	                      "%s: slab chain inconsistency: %s list\n",
							si->curname,
							slab_chain_name_v1[s]);
       						list_borked = 1;
     					}
				}
		
			} while (si->slab != slab_chains[s] && !list_borked);
		}

		FREEBUF(slab_s_buf);
		if (!list_borked)
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
	                	if (!readmem(slab_chains[s],
	                            KVADDR, &si->slab, sizeof(ulong),
	                            "slabs", QUIET|RETURN_ON_ERROR)) {
                			error(INFO, 
				         "%s: %s list: bad slab pointer: %lx\n",
                        			si->curname, 
						slab_chain_name_v1[s],
						slab_chains[s]);
					list_borked = 1;
					continue;
				}
				last = slab_chains[s];
			} else
				last = 0;
	
			if (si->slab == slab_chains[s])
				continue;

			if (CRASHDEBUG(1)) {
				fprintf(fp, "search cache: [%s] ", si->curname);
				if (si->flags & ADDRESS_SPECIFIED) 
					fprintf(fp, "for %llx", si->spec_addr);
				fprintf(fp, "\n");
			}
	
		        do {
	                        if (received_SIGINT())
	                                restart(0);

				if (!verify_slab_v1(si, last, s)) {
					list_borked = 1;
					continue;
				}
				last = si->slab - OFFSET(slab_s_list);
	
		                dump_slab_percpu_v1(si);
		
		                if (si->found) {
					return;
				}
		
		                readmem(si->slab+OFFSET(slab_s_list),
		                        KVADDR, &si->slab, sizeof(ulong),
		                        "slab list", FAULT_ON_ERROR);
		
				si->slab -= OFFSET(slab_s_list);
	
		        } while (si->slab != slab_chains[s] && !list_borked);
		}

		break;
	}
}

/*
 *  Try to preclude any attempt to translate a bogus slab structure.
 */

static int
verify_slab_v1(struct meminfo *si, ulong last, int s)
{
	char slab_s_buf[BUFSIZE];
	struct kernel_list_head *list_head;
	unsigned int inuse;
	ulong s_mem;
	char *list;
	int errcnt;

	list = slab_chain_name_v1[s];

	errcnt = 0;

        if (!readmem(si->slab, KVADDR, slab_s_buf,
            SIZE(slab_s), "slab_s buffer", QUIET|RETURN_ON_ERROR)) {
                error(INFO, "%s: %s list: bad slab pointer: %lx\n",
                        si->curname, list, si->slab);
		return FALSE;
        }                        

        list_head = (struct kernel_list_head *)
		(slab_s_buf + OFFSET(slab_s_list));

	if (!IS_KVADDR((ulong)list_head->next) || 
	    !accessible((ulong)list_head->next)) {
                error(INFO, "%s: %s list: slab: %lx  bad next pointer: %lx\n",
                        si->curname, list, si->slab,
			(ulong)list_head->next);
		errcnt++;
	}

	if (last && (last != (ulong)list_head->prev)) {
                error(INFO, "%s: %s list: slab: %lx  bad prev pointer: %lx\n",
                        si->curname, list, si->slab,
                        (ulong)list_head->prev);
		errcnt++;
	}

	inuse = UINT(slab_s_buf + OFFSET(slab_s_inuse));
	if (inuse > si->c_num) {
                error(INFO, "%s: %s list: slab: %lx  bad inuse counter: %ld\n",
                        si->curname, list, si->slab, inuse);
		errcnt++;
	}

	if (!last)
		goto no_inuse_check_v1;

	switch (s) 
	{
	case 0: /* full -- but can be one singular list */
                if (VALID_MEMBER(kmem_cache_s_slabs_full) && 
		    (inuse != si->c_num)) {
                        error(INFO,
                            "%s: %s list: slab: %lx  bad inuse counter: %ld\n",
                                si->curname, list, si->slab, inuse);
                        errcnt++;
                }
		break;

	case 1: /* partial */
		if ((inuse == 0) || (inuse == si->c_num)) {
                	error(INFO, 
		 	    "%s: %s list: slab: %lx  bad inuse counter: %ld\n",
                        	si->curname,  list, si->slab, inuse);
			errcnt++;
		}
		break;

	case 2: /* free */
		if (inuse > 0) {
                	error(INFO, 
		 	    "%s: %s list: slab: %lx  bad inuse counter: %ld\n",
                        	si->curname, list, si->slab, inuse);
			errcnt++;
		}
		break;
	}

no_inuse_check_v1:
	s_mem = ULONG(slab_s_buf + OFFSET(slab_s_s_mem));
	if (!IS_KVADDR(s_mem) || !accessible(s_mem)) {
                error(INFO, "%s: %s list: slab: %lx  bad s_mem pointer: %lx\n",
                        si->curname, list, si->slab, s_mem);
		errcnt++;
	}

	return(errcnt ? FALSE : TRUE);
}

/*
 *  Updated for 2.6 slab substructure.
 */

static char *slab_chain_name_v2[] = {"partial", "full", "free"};

static void
do_slab_chain_percpu_v2(long cmd, struct meminfo *si)
{
	int i, tmp, s;
	int list_borked;
	char *slab_buf;
	ulong specified_slab;
	ulong last;
	ulong slab_chains[SLAB_CHAINS];

	list_borked = 0;
	si->slabsize = (power(2, si->order) * PAGESIZE());
	si->cpucached_slab = 0;

	slab_chains[0] = si->cache + OFFSET(kmem_cache_s_lists) +
		OFFSET(kmem_list3_slabs_partial);
	slab_chains[1] = si->cache + OFFSET(kmem_cache_s_lists) +
                OFFSET(kmem_list3_slabs_full);
        slab_chains[2] = si->cache + OFFSET(kmem_cache_s_lists) +
                OFFSET(kmem_list3_slabs_free);

        if (CRASHDEBUG(1)) {
                fprintf(fp, "[ %s: %lx ", si->curname, si->cache);
                fprintf(fp, "partial: %lx full: %lx free: %lx ]\n",
                        slab_chains[0], slab_chains[1], slab_chains[2]);
        }

	switch (cmd)
	{
	case SLAB_GET_COUNTS:
		si->flags |= SLAB_GET_COUNTS;
		si->flags &= ~SLAB_WALKTHROUGH;
		si->cpucached_cache = 0;
        	si->num_slabs = si->inuse = 0;
		gather_cpudata_list_v2(si); 

		slab_buf = GETBUF(SIZE(slab));

		for (s = 0; s < SLAB_CHAINS; s++) {
			if (!slab_chains[s])
				continue;

	                if (!readmem(slab_chains[s],
	                    KVADDR, &si->slab, sizeof(ulong),
	                    "first slab", QUIET|RETURN_ON_ERROR)) {
                                error(INFO, 
				    "%s: %s list: bad slab pointer: %lx\n",
                                        si->curname,
					slab_chain_name_v2[s],
                                        slab_chains[s]);
				list_borked = 1;
				continue;
			}
	
			if (slab_data_saved(si)) {
				FREEBUF(slab_buf);
				return;
			}
	
			if (si->slab == slab_chains[s]) 
				continue;
	
			last = slab_chains[s];

			do {
	                        if (received_SIGINT()) {
					FREEBUF(slab_buf);
	                                restart(0);
				}

				if (!verify_slab_v2(si, last, s)) {
					list_borked = 1;
					continue;
				}
				last = si->slab - OFFSET(slab_list);
	
		                readmem(si->slab, KVADDR, slab_buf, 
					SIZE(slab), "slab buffer", 
					FAULT_ON_ERROR);
	
				tmp = INT(slab_buf + OFFSET(slab_inuse));
				si->inuse += tmp;
	
				if (ACTIVE())
					gather_cpudata_list_v2(si); 

				si->s_mem = ULONG(slab_buf + 
					OFFSET(slab_s_mem));
				gather_slab_cached_count(si);
	
				si->num_slabs++;
		
				si->slab = ULONG(slab_buf + 
					OFFSET(slab_list));
				si->slab -= OFFSET(slab_list);

				/*
				 *  Check for slab transition. (Tony Dziedzic)
				 */
				for (i = 0; i < SLAB_CHAINS; i++) {
     					if ((i != s) && 
					    (si->slab == slab_chains[i])) {
       						error(NOTE, 
	  	                      "%s: slab chain inconsistency: %s list\n",
							si->curname,
							slab_chain_name_v2[s]);
       						list_borked = 1;
     					}
				}
		
			} while (si->slab != slab_chains[s] && !list_borked);
		}

		FREEBUF(slab_buf);
		if (!list_borked)
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
	                	if (!readmem(slab_chains[s],
	                            KVADDR, &si->slab, sizeof(ulong),
	                            "slabs", QUIET|RETURN_ON_ERROR)) {
                                        error(INFO,
                                         "%s: %s list: bad slab pointer: %lx\n",
                                                si->curname,
						slab_chain_name_v2[s],
                                                slab_chains[s]);
					list_borked = 1;
					continue;
				}
				last = slab_chains[s];
			} else
				last = 0;
			
			if (si->slab == slab_chains[s])
				continue;
	
			if (CRASHDEBUG(1)) {
				fprintf(fp, "search cache: [%s] ", si->curname);
				if (si->flags & ADDRESS_SPECIFIED) 
					fprintf(fp, "for %llx", si->spec_addr);
				fprintf(fp, "\n");
			}
	
		        do {
	                        if (received_SIGINT())
	                                restart(0);
	
                                if (!verify_slab_v2(si, last, s)) {
                                        list_borked = 1;
                                        continue;
                                }
                                last = si->slab - OFFSET(slab_list);

		                dump_slab_percpu_v2(si);
		
		                if (si->found) {
					return;
				}
		
		                readmem(si->slab+OFFSET(slab_list),
		                        KVADDR, &si->slab, sizeof(ulong),
		                        "slab list", FAULT_ON_ERROR);
		
				si->slab -= OFFSET(slab_list);
	
		        } while (si->slab != slab_chains[s] && !list_borked);
		}

		break;
	}
}


/* 
* Added To  Traverse the Nodelists 
*/

static void
do_slab_chain_percpu_v2_nodes(long cmd, struct meminfo *si)
{
	int i, tmp, s;
	int list_borked;
	char *slab_buf;
	ulong specified_slab;
	ulong last;
	ulong slab_chains[SLAB_CHAINS];
	ulong *start_address;
	int index;

	list_borked = 0;
	si->slabsize = (power(2, si->order) * PAGESIZE());
	si->cpucached_slab = 0;
	start_address = (ulong *)GETBUF(sizeof(ulong) * vt->kmem_cache_len_nodes);

	if (!readmem(si->cache+OFFSET(kmem_cache_s_lists), KVADDR, 
            &start_address[0], sizeof(ulong) * vt->kmem_cache_len_nodes, 
            "array nodelist array", RETURN_ON_ERROR)) 
                    error(INFO, "cannot read kmem_cache nodelists array"); 

	switch (cmd)
	{
	case SLAB_GET_COUNTS:
		si->flags |= SLAB_GET_COUNTS;
		si->flags &= ~SLAB_WALKTHROUGH;
		si->cpucached_cache = 0;
        	si->num_slabs = si->inuse = 0;
		slab_buf = GETBUF(SIZE(slab));
		for (index=0; (index < vt->kmem_cache_len_nodes) && start_address[index]; index++)
		{ 
			slab_chains[0] = start_address[index] + OFFSET(kmem_list3_slabs_partial);
			slab_chains[1] = start_address[index] + OFFSET(kmem_list3_slabs_full);
		        slab_chains[2] = start_address[index] + OFFSET(kmem_list3_slabs_free);
			
			gather_cpudata_list_v2_nodes(si, index); 
	
		        if (CRASHDEBUG(1)) {
                		fprintf(fp, "[ %s: %lx ", si->curname, si->cache);
	                	fprintf(fp, "partial: %lx full: %lx free: %lx ]\n",
                        		slab_chains[0], slab_chains[1], slab_chains[2]);
			}

			for (s = 0; s < SLAB_CHAINS; s++) {
				if (!slab_chains[s])
					continue;
	
		                if (!readmem(slab_chains[s],
	        	            KVADDR, &si->slab, sizeof(ulong),
	                	    "first slab", QUIET|RETURN_ON_ERROR)) {
	                                error(INFO, 
					    "%s: %s list: bad slab pointer: %lx\n",
                	                        si->curname,
						slab_chain_name_v2[s],
                                	        slab_chains[s]);
					list_borked = 1;
					continue;
				}
	
				if (slab_data_saved(si)) {
					FREEBUF(slab_buf);
					FREEBUF(start_address);
					return;
				}
			
				if (si->slab == slab_chains[s]) 
					continue;
	
				last = slab_chains[s];

				do {
	        	                if (received_SIGINT()) {
						FREEBUF(slab_buf);
						FREEBUF(start_address);
	                        	        restart(0);
					}

					if (!verify_slab_v2(si, last, s)) {
						list_borked = 1;
						continue;
					}
					last = si->slab - OFFSET(slab_list);
		
		        	        readmem(si->slab, KVADDR, slab_buf, 
						SIZE(slab), "slab buffer", 
						FAULT_ON_ERROR);
		
					tmp = INT(slab_buf + OFFSET(slab_inuse));
					si->inuse += tmp;
	
					if (ACTIVE())
						gather_cpudata_list_v2_nodes(si, index); 

					si->s_mem = ULONG(slab_buf + 
						OFFSET(slab_s_mem));
					gather_slab_cached_count(si);
	
					si->num_slabs++;
		
					si->slab = ULONG(slab_buf + 
						OFFSET(slab_list));
					si->slab -= OFFSET(slab_list);

				/*
				 *  Check for slab transition. (Tony Dziedzic)
				 */
					for (i = 0; i < SLAB_CHAINS; i++) {
     						if ((i != s) && 
						    (si->slab == slab_chains[i])) {
       							error(NOTE, 
		  	                      "%s: slab chain inconsistency: %s list\n",
								si->curname,
								slab_chain_name_v2[s]);
       							list_borked = 1;
     						}
					}
			
				} while (si->slab != slab_chains[s] && !list_borked);
			}
		}

		if (!list_borked)
			save_slab_data(si);
		break;

	case SLAB_WALKTHROUGH:
		specified_slab = si->slab;     
		si->flags |= SLAB_WALKTHROUGH;
		si->flags &= ~SLAB_GET_COUNTS;
		slab_buf = GETBUF(SIZE(slab));
		for (index=0; (index < vt->kmem_cache_len_nodes) && start_address[index]; index++)
		{ 
			slab_chains[0] = start_address[index] + OFFSET(kmem_list3_slabs_partial);
			slab_chains[1] = start_address[index] + OFFSET(kmem_list3_slabs_full);
		        slab_chains[2] = start_address[index] + OFFSET(kmem_list3_slabs_free);
	
			gather_cpudata_list_v2_nodes(si, index);
 
		        if (CRASHDEBUG(1)) {
                		fprintf(fp, "[ %s: %lx ", si->curname, si->cache);
	                	fprintf(fp, "partial: %lx full: %lx free: %lx ]\n",
                        		slab_chains[0], slab_chains[1], slab_chains[2]);
			}

			for (s = 0; s < SLAB_CHAINS; s++) {
				if (!slab_chains[s])
					continue;

	        	if (!specified_slab) {
	                	if (!readmem(slab_chains[s],
	       	                    KVADDR, &si->slab, sizeof(ulong),
	               	            "slabs", QUIET|RETURN_ON_ERROR)) {
                               	        error(INFO,
	                                        "%s: %s list: bad slab pointer: %lx\n",
                                                si->curname,
						slab_chain_name_v2[s],
                       	                        slab_chains[s]);
						list_borked = 1;
						continue;
					}
					last = slab_chains[s];
				} else
					last = 0;
			
				if (si->slab == slab_chains[s])
					continue;
				
				readmem(si->slab, KVADDR, slab_buf, 
						SIZE(slab), "slab buffer", 
						FAULT_ON_ERROR);
		
				si->s_mem = ULONG(slab_buf + 
						OFFSET(slab_s_mem));

				if (CRASHDEBUG(1)) {
					fprintf(fp, "search cache: [%s] ", si->curname);
					if (si->flags & ADDRESS_SPECIFIED) 
						fprintf(fp, "for %llx", si->spec_addr);
					fprintf(fp, "\n");
				}
	
			        do {
		                        if (received_SIGINT())
					{
						FREEBUF(start_address);
						FREEBUF(slab_buf);
	        	                        restart(0);
					}
	
                        	        if (!verify_slab_v2(si, last, s)) {
                                	        list_borked = 1;
                                        	continue;
	                                }
        	                        last = si->slab - OFFSET(slab_list);
	
			                dump_slab_percpu_v2(si);
					
					if (si->found) {
						FREEBUF(start_address);
						FREEBUF(slab_buf);
						return;
					}
		
			                readmem(si->slab+OFFSET(slab_list),
			                        KVADDR, &si->slab, sizeof(ulong),
			                        "slab list", FAULT_ON_ERROR);
			
					si->slab -= OFFSET(slab_list);
	
			        } while (si->slab != slab_chains[s] && !list_borked);
			}
		}

		break;
	}
	FREEBUF(slab_buf);
	FREEBUF(start_address);
}

/*
 *  Try to preclude any attempt to translate a bogus slab structure.
 */
static int
verify_slab_v2(struct meminfo *si, ulong last, int s)
{
	char slab_buf[BUFSIZE];
	struct kernel_list_head *list_head;
	unsigned int inuse;
	ulong s_mem;
	char *list;
	int errcnt;

	list = slab_chain_name_v2[s];

	errcnt = 0;

        if (!readmem(si->slab, KVADDR, slab_buf,
            SIZE(slab), "slab buffer", QUIET|RETURN_ON_ERROR)) {
                error(INFO, "%s: %s list: bad slab pointer: %lx\n",
                        si->curname, list, si->slab);
		return FALSE;
        }                        

        list_head = (struct kernel_list_head *)(slab_buf + OFFSET(slab_list));
	if (!IS_KVADDR((ulong)list_head->next) || 
	    !accessible((ulong)list_head->next)) {
                error(INFO, "%s: %s list: slab: %lx  bad next pointer: %lx\n",
                        si->curname, list, si->slab,
			(ulong)list_head->next);
		errcnt++;
	}

	if (last && (last != (ulong)list_head->prev)) {
                error(INFO, "%s: %s list: slab: %lx  bad prev pointer: %lx\n",
                        si->curname, list, si->slab,
                        (ulong)list_head->prev);
		errcnt++;
	}

	inuse = UINT(slab_buf + OFFSET(slab_inuse));
	if (inuse > si->c_num) {
                error(INFO, "%s: %s list: slab: %lx  bad inuse counter: %ld\n",
                        si->curname, list, si->slab, inuse);
		errcnt++;
	}

	if (!last)
		goto no_inuse_check_v2;

	switch (s) 
	{
	case 0: /* partial */
                if ((inuse == 0) || (inuse == si->c_num)) {
                	error(INFO, 
		 	    "%s: %s list: slab: %lx  bad inuse counter: %ld\n",
                        	si->curname, list, si->slab, inuse);
			errcnt++;
		}
		break;

	case 1: /* full */
		if (inuse != si->c_num) {
                	error(INFO, 
		 	    "%s: %s list: slab: %lx  bad inuse counter: %ld\n",
                        	si->curname, list, si->slab, inuse);
			errcnt++;
		}
		break;

	case 2: /* free */
		if (inuse > 0) {
                	error(INFO, 
		 	    "%s: %s list: slab: %lx  bad inuse counter: %ld\n",
                        	si->curname, list, si->slab, inuse);
			errcnt++;
		}
		break;
	}

no_inuse_check_v2:
	s_mem = ULONG(slab_buf + OFFSET(slab_s_mem));
	if (!IS_KVADDR(s_mem) || !accessible(s_mem)) {
                error(INFO, "%s: %s list: slab: %lx  bad s_mem pointer: %lx\n",
                        si->curname, list, si->slab, s_mem);
		errcnt++;
	}

	return(errcnt ? FALSE : TRUE);
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

	if (si->flags & SLAB_DATA_NOSAVE) {
		si->flags &= ~SLAB_DATA_NOSAVE;
		return;
	}

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
             "     cache: %lx inuse: %5d num_slabs: %3d cpucached_cache: %ld\n",
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
                    (si->spec_addr < (si->slab+SIZE(kmem_slab_s)))) {
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
dump_slab_percpu_v1(struct meminfo *si)
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
                } else if (INSLAB_PERCPU(si->spec_addr, si))
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
 *  Updated for 2.6 slab substructure.
 */
static void
dump_slab_percpu_v2(struct meminfo *si)
{
	int tmp;

        readmem(si->slab+OFFSET(slab_s_mem),
                KVADDR, &si->s_mem, sizeof(ulong),
                "s_mem", FAULT_ON_ERROR);

	/*
	 * Include the array of kmem_bufctl_t's appended to slab.
	 */
	tmp = SIZE(slab) + (SIZE(kmem_bufctl_t) * si->c_num);

        if (si->flags & ADDRESS_SPECIFIED)  {
                if (INSLAB_PERCPU(si->slab, si) && 
		    (si->spec_addr >= si->slab) &&
                    (si->spec_addr < (si->slab+tmp))) {
			if (si->spec_addr >= (si->slab + SIZE(slab)))
				si->found = KMEM_BUFCTL_ADDR;
			else
                		si->found = KMEM_SLAB_ADDR;
                } else if (INSLAB_PERCPU(si->spec_addr, si))
			si->found = KMEM_ON_SLAB;  /* But don't return yet... */
		else
			return;
        }

        readmem(si->slab+OFFSET(slab_inuse),
                KVADDR, &tmp, sizeof(int),
                "inuse", FAULT_ON_ERROR);
	si->s_inuse = tmp;

        readmem(si->slab+OFFSET(slab_free),
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
	short *kbp;

	BNEG(si->addrlist, sizeof(ulong) * (si->c_num+1));

	if (CRASHDEBUG(1)) 
		fprintf(fp, "slab: %lx si->s_inuse: %ld si->c_num: %ld\n", 
			si->slab, si->s_inuse, si->c_num);

	if (si->s_inuse == si->c_num )
		return;

	kmembp = si->slab + SIZE_OPTION(slab_s, slab);
        readmem((ulong)kmembp, KVADDR, si->kmem_bufctl, 
		SIZE(kmem_bufctl_t) * si->c_num,
                "kmem_bufctl array", FAULT_ON_ERROR);

	if (CRASHDEBUG(1)) {
		for (i = 0; (SIZE(kmem_bufctl_t) == sizeof(int)) && 
		     (i < si->c_num); i++) 
			fprintf(fp, "%d ", si->kmem_bufctl[i]);

		for (kbp = (short *)&si->kmem_bufctl[0], i = 0; 
		     (SIZE(kmem_bufctl_t) == sizeof(short)) && (i < si->c_num);
		     i++) 
			fprintf(fp, "%d ", *(kbp + i));

		fprintf(fp, "\n");
	}

	cnt = 0;
	expected = si->c_num - si->s_inuse;

	if (SIZE(kmem_bufctl_t) == sizeof(int)) {
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
	} else if (SIZE(kmem_bufctl_t) == sizeof(short)) {
		kbp = (short *)&si->kmem_bufctl[0];

                for (free_index = si->free; free_index != BUFCTL_END;
                     free_index = (int)*(kbp + free_index)) {

                        if (cnt == si->c_num) {
                                error(INFO,
                     "\"%s\" cache: too many objects found in slab free list\n",                                        si->curname);
                                si->errors++;
                                return;
                        }

                        obj = si->s_mem + (free_index*si->size);
                        si->addrlist[cnt] = obj;
                        cnt++;
                }
	} else 
		error(FATAL, 
                "size of kmem_bufctl_t (%d) not sizeof(int) or sizeof(short)\n",
			SIZE(kmem_bufctl_t));

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

        if (CRASHDEBUG(1))
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
		for (i = 0, next = si->s_index; i < si->c_num; i++, next++) {
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
	int on_free_list, on_cpudata_list, on_shared_list; 
	ulong cnt, expected;
	ulong obj;

	if ((si->flags & ADDRESS_SPECIFIED) && (si->found & ~KMEM_ON_SLAB))
		return;

        cnt = 0;
        expected = si->s_inuse;

        if (CRASHDEBUG(1))
                for (i = 0; i < si->c_num; i++) {
                        fprintf(fp, "si->addrlist[%d]: %lx\n", 
				i, si->addrlist[i]);
                }

        if (!(si->flags & ADDRESS_SPECIFIED)) 
		fprintf(fp, free_inuse_hdr);

	for (i = 0, obj = si->s_mem; i < si->c_num; i++, obj += si->size) {
		on_free_list = FALSE;
		on_cpudata_list = FALSE;
		on_shared_list = FALSE;

	        for (j = 0; j < si->c_num; j++) {        
	                if (obj == si->addrlist[j]) {                   
	                        on_free_list = TRUE;                    
	                        break;                                  
	                }                                               
	        }                                                       

		on_cpudata_list = check_cpudata_list(si, obj);
		on_shared_list = check_shared_list(si, obj);

		if (on_free_list && on_cpudata_list) {
			error(INFO, 
		    "\"%s\" cache: object %lx on both free and cpu %d lists\n",
				si->curname, si->cpu, obj);
			si->errors++;
		}
		if (on_free_list && on_shared_list) {
			error(INFO, 
		    "\"%s\" cache: object %lx on both free and shared lists\n",
				si->curname, obj);
			si->errors++;
		}
		if (on_cpudata_list && on_shared_list) {
			error(INFO, 
		    "\"%s\" cache: object %lx on both cpu %d and shared lists\n",
				si->curname, obj, si->cpu);
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
		} else if (on_shared_list) {
                        if (!(si->flags & ADDRESS_SPECIFIED))
                                fprintf(fp, "   %lx  (shared cache)\n", obj);
			cnt++;
                        if (si->flags & ADDRESS_SPECIFIED) {
                                if (INOBJECT(si->spec_addr, obj)) {
                                        si->found =
                                            KMEM_OBJECT_ADDR_SHARED;
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
 *  cumulative per-cache count.  With the addition of the shared list
 *  check, the terms "cpucached_cache" and "cpucached_slab" are somewhat
 *  misleading.  But they both are types of objects that are cached
 *  in the kmem_cache_s header, just not necessarily per-cpu.
 */

static void
gather_slab_cached_count(struct meminfo *si)
{
	int i;
	ulong obj;
	int in_cpudata, in_shared;

	si->cpucached_slab = 0;

        for (i = 0, obj = si->s_mem; i < si->c_num; i++, obj += si->size) {
		in_cpudata = in_shared = 0;
		if (check_cpudata_list(si, obj)) {
			in_cpudata = TRUE;
			si->cpucached_slab++;
			if (si->flags & SLAB_GET_COUNTS) {
				si->cpucached_cache++;
			}
		}
                if (check_shared_list(si, obj)) {
			in_shared = TRUE;
			if (!in_cpudata) {
                        	si->cpucached_slab++;
                        	if (si->flags & SLAB_GET_COUNTS) {
                                	si->cpucached_cache++;
                        	}
			}
                }
		if (in_cpudata && in_shared) {
			si->flags |= SLAB_DATA_NOSAVE;
			if (!(si->flags & VERBOSE))
				error(INFO, 
		    "\"%s\" cache: object %lx on both cpu %d and shared lists\n",
				si->curname, obj, si->cpu);
		}
	}
}

/*
 *  Populate the percpu object list for a given slab.
 */

static void
gather_cpudata_list_v1(struct meminfo *si)
{
        int i, j;
	int avail;
        ulong cpudata[NR_CPUS];

        if (INVALID_MEMBER(kmem_cache_s_cpudata))
                return;

        readmem(si->cache+OFFSET(kmem_cache_s_cpudata),
                KVADDR, &cpudata[0], 
		sizeof(ulong) * ARRAY_LENGTH(kmem_cache_s_cpudata),
                "cpudata array", FAULT_ON_ERROR);

        for (i = 0; (i < ARRAY_LENGTH(kmem_cache_s_cpudata)) && 
	     cpudata[i]; i++) {
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

		if (CRASHDEBUG(2))
			fprintf(fp, "%s: cpu[%d] avail: %d\n", 
				si->curname, i, avail);

                readmem(cpudata[i]+SIZE(cpucache_s),
                        KVADDR, si->cpudata[i],
			sizeof(void *) * avail,
                        "cpucache avail", FAULT_ON_ERROR);

		if (CRASHDEBUG(2))
			for (j = 0; j < avail; j++)
				fprintf(fp, "  %lx\n", si->cpudata[i][j]);
        }
}

/*
 *  Updated for 2.6 slab percpu data structure, this also gathers
 *  the shared array_cache list as well.
 */
static void
gather_cpudata_list_v2(struct meminfo *si)
{
        int i, j;
	int avail;
        ulong cpudata[NR_CPUS];
	ulong shared;

        readmem(si->cache+OFFSET(kmem_cache_s_array),
                KVADDR, &cpudata[0], 
		sizeof(ulong) * ARRAY_LENGTH(kmem_cache_s_array),
                "array_cache array", FAULT_ON_ERROR);

        for (i = 0; (i < ARRAY_LENGTH(kmem_cache_s_array)) && 
	     cpudata[i]; i++) {
		BZERO(si->cpudata[i], sizeof(ulong) * vt->kmem_max_limit);

                readmem(cpudata[i]+OFFSET(array_cache_avail),
                        KVADDR, &avail, sizeof(int),
                        "array cache avail", FAULT_ON_ERROR);

		if (!avail) 
			continue;

		if (avail > vt->kmem_max_limit) {
			error(INFO, 
	  	  "\"%s\" cache: array_cache.avail %d greater than limit %ld\n",
				si->curname, avail, vt->kmem_max_limit);
			si->errors++;
		}

		if (CRASHDEBUG(2))
			fprintf(fp, "%s: cpu[%d] avail: %d\n", 
				si->curname, i, avail);

                readmem(cpudata[i]+SIZE(array_cache),
                        KVADDR, si->cpudata[i],
			sizeof(void *) * avail,
                        "array_cache avail", FAULT_ON_ERROR);

		if (CRASHDEBUG(2))
			for (j = 0; j < avail; j++)
				fprintf(fp, "  %lx (cpu %d)\n", si->cpudata[i][j], i);
        }

        /*
         *  If the shared list contains anything, gather them as well.
         */
	BZERO(si->shared_array_cache, sizeof(ulong) * vt->kmem_max_limit);

        if (!VALID_MEMBER(kmem_list3_shared) ||
            !VALID_MEMBER(kmem_cache_s_lists) ||
            !readmem(si->cache+OFFSET(kmem_cache_s_lists)+
       	    OFFSET(kmem_list3_shared), KVADDR, &shared, sizeof(void *),
	    "kmem_list3 shared", RETURN_ON_ERROR|QUIET) ||
	    !readmem(shared+OFFSET(array_cache_avail),
            KVADDR, &avail, sizeof(int), "shared array_cache avail",
            RETURN_ON_ERROR|QUIET) || !avail)
		return;

	if (avail > vt->kmem_max_limit) {
		error(INFO, 
  	  "\"%s\" cache: shared array_cache.avail %d greater than limit %ld\n",
			si->curname, avail, vt->kmem_max_limit);
		si->errors++;
		return;
	}

	if (CRASHDEBUG(2))
		fprintf(fp, "%s: shared avail: %d\n", 
			si->curname, avail);

        readmem(shared+SIZE(array_cache), KVADDR, si->shared_array_cache,
        	sizeof(void *) * avail, "shared array_cache avail", 
		FAULT_ON_ERROR);

        if (CRASHDEBUG(2))
        	for (j = 0; j < avail; j++)
                	fprintf(fp, "  %lx (shared list)\n", si->shared_array_cache[j]);
}



/*
 *  Updated gather_cpudata_list_v2 for per-node kmem_list3's in kmem_cache 
 */
static void
gather_cpudata_list_v2_nodes(struct meminfo *si, int index)
{
        int i, j;
	int avail;
        ulong cpudata[NR_CPUS];
	ulong shared;
	ulong *start_address;

	start_address = (ulong *) GETBUF(sizeof(ulong) * vt->kmem_cache_len_nodes);
        readmem(si->cache+OFFSET(kmem_cache_s_array),
                KVADDR, &cpudata[0], 
		sizeof(ulong) * ARRAY_LENGTH(kmem_cache_s_array),
                "array_cache array", FAULT_ON_ERROR);

        for (i = 0; (i < ARRAY_LENGTH(kmem_cache_s_array)) && 
	     (cpudata[i]) && !(index); i++) {
		BZERO(si->cpudata[i], sizeof(ulong) * vt->kmem_max_limit);

                readmem(cpudata[i]+OFFSET(array_cache_avail),
                        KVADDR, &avail, sizeof(int),
                        "array cache avail", FAULT_ON_ERROR);

		if (!avail) 
			continue;

		if (avail > vt->kmem_max_limit) {
			error(INFO, 
	  	  "\"%s\" cache: array_cache.avail %d greater than limit %ld\n",
				si->curname, avail, vt->kmem_max_limit);
			si->errors++;
		}

		if (CRASHDEBUG(2))
			fprintf(fp, "%s: cpu[%d] avail: %d\n", 
				si->curname, i, avail);
		
                readmem(cpudata[i]+SIZE(array_cache),
                        KVADDR, si->cpudata[i],
			sizeof(void *) * avail,
                        "array_cache avail", FAULT_ON_ERROR);

		if (CRASHDEBUG(2))
			for (j = 0; j < avail; j++)
				fprintf(fp, "  %lx (cpu %d)\n", si->cpudata[i][j], i);
        }

        /*
         *  If the shared list contains anything, gather them as well.
         */
	if (!index) {
		BZERO(si->shared_array_cache, sizeof(ulong) * 
			vt->kmem_max_limit * vt->kmem_cache_len_nodes);
		si->current_cache_index = 0;
	}

	if (!readmem(si->cache+OFFSET(kmem_cache_s_lists), KVADDR, &start_address[0], 
	    sizeof(ulong) * vt->kmem_cache_len_nodes , "array nodelist array", 
	    RETURN_ON_ERROR) ||  
	    !readmem(start_address[index] + OFFSET(kmem_list3_shared), KVADDR, &shared,
	     sizeof(void *), "kmem_list3 shared", RETURN_ON_ERROR|QUIET) ||
	    !readmem(shared + OFFSET(array_cache_avail), KVADDR, &avail, sizeof(int), 
	    "shared array_cache avail", RETURN_ON_ERROR|QUIET) || !avail) {
		FREEBUF(start_address);
		return;
	}

	if (avail > vt->kmem_max_limit) {
		error(INFO, 
  	  "\"%s\" cache: shared array_cache.avail %d greater than limit %ld\n",
			si->curname, avail, vt->kmem_max_limit);
		si->errors++;
		FREEBUF(start_address);
		return;
	}

	if (CRASHDEBUG(2))
		fprintf(fp, "%s: shared avail: %d\n", 
			si->curname, avail);

        readmem(shared+SIZE(array_cache), KVADDR, si->shared_array_cache + si->current_cache_index,
        	sizeof(void *) * avail, "shared array_cache avail", 
		FAULT_ON_ERROR);

	if ((si->current_cache_index + avail) > 
	    (vt->kmem_max_limit * vt->kmem_cache_len_nodes)) {
		error(INFO, 
  	  "\"%s\" cache: total shared array_cache.avail %d greater than total limit %ld\n",
			si->curname, 
			si->current_cache_index + avail, 
			vt->kmem_max_limit * vt->kmem_cache_len_nodes);
		si->errors++;
		FREEBUF(start_address);
		return;
	}

        if (CRASHDEBUG(2))
        	for (j = si->current_cache_index; j < (si->current_cache_index + avail); j++)
                	fprintf(fp, "  %lx (shared list)\n", si->shared_array_cache[j]);
	
	si->current_cache_index += avail;
	FREEBUF(start_address);
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
 *  Check whether a given address is contained in the previously-gathered
 *  shared object cache.
 */

static int
check_shared_list(struct meminfo *si, ulong obj)
{
	int i;

	if (INVALID_MEMBER(kmem_list3_shared) ||
	    !si->shared_array_cache)
		return FALSE;

        for (i = 0; si->shared_array_cache[i]; i++) {
		if (si->shared_array_cache[i] == obj)
			return TRUE;
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
	ulong vaddr, orig_flags;
	physaddr_t paddr;
	ulong offset;
	ulong task;
	struct task_context *tc;

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

	if (vt->page_hash_table) {
		/*
		 *  Check the page cache.
		 */
		mi->flags = orig_flags;
		mi->retval = 0;
		dump_page_hash_table(mi);
		if (mi->retval)
			fprintf(fp, "\n");
	}

	/*
	 *  Check whether it's a current task or stack address.
	 */
	if ((mi->memtype == KVADDR) && (task = vaddr_in_task_struct(vaddr)) &&
	    (tc = task_to_context(task))) {
		show_context(tc);
		fprintf(fp, "\n");
	} else if ((mi->memtype == KVADDR) && (task = stkptr_to_task(vaddr)) &&
	    (tc = task_to_context(task))) {
		show_context(tc);
		fprintf(fp, "\n");
	}

mem_map:
	mi->flags = orig_flags;
	pc->curcmd_flags &= ~HEADER_PRINTED;
        dump_mem_map(mi);

	if (!mi->retval)
		fprintf(fp, "%llx: address not found\n", mi->spec_addr);

}

/*
 *  Determine whether an address is a page pointer from the mem_map[] array.
 *  If the caller requests it, return the associated physical address.
 */
int
is_page_ptr(ulong addr, physaddr_t *phys)
{
	int n;
        ulong ppstart, ppend;
	struct node_table *nt;
	ulong pgnum, node_size;
	ulong nr, sec_addr;
	ulong nr_mem_sections;
	ulong coded_mem_map, mem_map, end_mem_map;
	physaddr_t section_paddr;

	if (IS_SPARSEMEM()) {
		nr_mem_sections = NR_MEM_SECTIONS();
	        for (nr = 0; nr <= nr_mem_sections ; nr++) {
	                if ((sec_addr = valid_section_nr(nr))) {
	                        coded_mem_map = section_mem_map_addr(sec_addr);
	                        mem_map = sparse_decode_mem_map(coded_mem_map, nr);
				end_mem_map = mem_map + (PAGES_PER_SECTION() * SIZE(page));

				if ((addr >= mem_map) && (addr < end_mem_map)) { 
	        			if ((addr - mem_map) % SIZE(page))
						return FALSE;
					if (phys) {
						section_paddr = PTOB(section_nr_to_pfn(nr));
						pgnum = (addr - mem_map) / SIZE(page);
						*phys = section_paddr + (pgnum * PAGESIZE());
					} 
					return TRUE;
				}
	                }
	        }
		return FALSE;
	}

	for (n = 0; n < vt->numnodes; n++) {
		nt = &vt->node_table[n];
                if ((vt->flags & V_MEM_MAP) && (vt->numnodes == 1))
	        	node_size = vt->max_mapnr;
		else
	        	node_size = nt->size;

        	ppstart = nt->mem_map;
		ppend = ppstart + (node_size * SIZE(page));

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

#ifdef PRE_NODES
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
page_to_phys(ulong pp, physaddr_t *phys)
{
	return(is_page_ptr(pp, phys));
}


/*
 *  Return the page pointer associated with this physical address.
 */
static int 
phys_to_page(physaddr_t phys, ulong *pp)
{
	int n;
        ulong pgnum;
        struct node_table *nt;
	physaddr_t pstart, pend;
	ulong node_size;

	if (IS_SPARSEMEM()) {
		ulong map;
		map = pfn_to_map(phys >> PAGESHIFT());
		if (map) {
			*pp = map;
			return TRUE;
		}
		return FALSE;
	}

        for (n = 0; n < vt->numnodes; n++) {
                nt = &vt->node_table[n];
                if ((vt->flags & V_MEM_MAP) && (vt->numnodes == 1))
                        node_size = vt->max_mapnr;
                else
                        node_size = nt->size;

                pstart = nt->start_paddr;
                pend = pstart + ((ulonglong)node_size * PAGESIZE());

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

#ifdef PRE_NODES
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
	struct node_table *nt;
	int others;
	ulong *up;

	others = 0;
	fprintf(fp, "              flags: %lx  %s(", 
		vt->flags, count_bits_long(vt->flags) > 4 ? "\n " : "");
	if (vt->flags & NODES)
		fprintf(fp, "%sNODES", others++ ? "|" : "");
	if (vt->flags & NODES_ONLINE)
		fprintf(fp, "%sNODES_ONLINE", others++ ? "|" : "");
	if (vt->flags & ZONES)
		fprintf(fp, "%sZONES", others++ ? "|" : "");
	if (vt->flags & PERCPU_KMALLOC_V1)
		fprintf(fp, "%sPERCPU_KMALLOC_V1", others++ ? "|" : "");
	if (vt->flags & PERCPU_KMALLOC_V2)
		fprintf(fp, "%sPERCPU_KMALLOC_V2", others++ ? "|" : "");
	if (vt->flags & COMMON_VADDR)
		fprintf(fp, "%sCOMMON_VADDR", others++ ? "|" : "");
	if (vt->flags & KMEM_CACHE_INIT)
		fprintf(fp, "%sKMEM_CACHE_INIT", others++ ? "|" : "");
	if (vt->flags & V_MEM_MAP)
		fprintf(fp, "%sV_MEM_MAP", others++ ? "|" : "");
	if (vt->flags & KMEM_CACHE_UNAVAIL)
		fprintf(fp, "%sKMEM_CACHE_UNAVAIL", others++ ? "|" : "");
	if (vt->flags & DISCONTIGMEM)
		fprintf(fp, "%sDISCONTIGMEM", others++ ? "|" : "");
	if (vt->flags & FLATMEM)
		fprintf(fp, "%sFLATMEM", others++ ? "|" : "");
	if (vt->flags & SPARSEMEM)
		fprintf(fp, "%sSPARSEMEM", others++ ? "|" : "");\
	if (vt->flags & SPARSEMEM_EX)
		fprintf(fp, "%sSPARSEMEM_EX", others++ ? "|" : "");\
	if (vt->flags & KMEM_CACHE_DELAY)
		fprintf(fp, "%sKMEM_CACHE_DELAY", others++ ? "|" : "");\
	if (vt->flags & PERCPU_KMALLOC_V2_NODES)
		fprintf(fp, "%sPERCPU_KMALLOC_V2_NODES", others++ ? "|" : "");\
	if (vt->flags & VM_STAT)
		fprintf(fp, "%sVM_STAT", others++ ? "|" : "");\
	if (vt->flags & KMALLOC_SLUB)
		fprintf(fp, "%sKMALLOC_SLUB", others++ ? "|" : "");\

	fprintf(fp, ")\n");
	if (vt->kernel_pgd[0] == vt->kernel_pgd[1])
       		fprintf(fp, "     kernel_pgd[NR_CPUS]: %lx ...\n", 
			vt->kernel_pgd[0]);
	else {
       		fprintf(fp, "     kernel_pgd[NR_CPUS]: ");
		for (i = 0; i < NR_CPUS; i++) {
			if ((i % 4) == 0)
				fprintf(fp, "\n     ");
			fprintf(fp, "%lx ", vt->kernel_pgd[i]);
		}
		fprintf(fp, "\n");
	}
        fprintf(fp, "        high_memory: %lx\n", vt->high_memory);
        fprintf(fp, "      vmalloc_start: %lx\n", vt->vmalloc_start);
        fprintf(fp, "            mem_map: %lx\n", vt->mem_map);
        fprintf(fp, "        total_pages: %ld\n", vt->total_pages);
        fprintf(fp, "          max_mapnr: %ld\n", vt->max_mapnr);
        fprintf(fp, "     totalram_pages: %ld\n", vt->totalram_pages);
        fprintf(fp, "    totalhigh_pages: %ld\n", vt->totalhigh_pages);
        fprintf(fp, "      num_physpages: %ld\n", vt->num_physpages);
	fprintf(fp, "    page_hash_table: %lx\n", vt->page_hash_table);
	fprintf(fp, "page_hash_table_len: %d\n", vt->page_hash_table_len);
	fprintf(fp, "     kmem_max_c_num: %ld\n", vt->kmem_max_c_num);
	fprintf(fp, "     kmem_max_limit: %ld\n", vt->kmem_max_limit);
	fprintf(fp, "      kmem_max_cpus: %ld\n", vt->kmem_max_cpus);
	fprintf(fp, "   kmem_cache_count: %ld\n", vt->kmem_cache_count);
	fprintf(fp, " kmem_cache_namelen: %d\n", vt->kmem_cache_namelen);
	fprintf(fp, "kmem_cache_nodelist_len: %ld\n", vt->kmem_cache_len_nodes);
	fprintf(fp, "        PG_reserved: %lx\n", vt->PG_reserved);
	fprintf(fp, "            PG_slab: %ld\n", vt->PG_slab);
	fprintf(fp, "        paddr_prlen: %d\n", vt->paddr_prlen);
	fprintf(fp, "           numnodes: %d\n", vt->numnodes);
	fprintf(fp, "           nr_zones: %d\n", vt->nr_zones);
	fprintf(fp, "      nr_free_areas: %d\n", vt->nr_free_areas);
	for (i = 0; i < vt->numnodes; i++) {
		nt = &vt->node_table[i];
		fprintf(fp, "      node_table[%d]: \n", i);
		fprintf(fp, "                   id: %d\n", nt->node_id);
		fprintf(fp, "                pgdat: %lx\n", nt->pgdat);
		fprintf(fp, "                 size: %ld\n", nt->size);
		fprintf(fp, "              present: %ld\n", nt->present);
		fprintf(fp, "              mem_map: %lx\n", nt->mem_map);
		fprintf(fp, "          start_paddr: %llx\n", nt->start_paddr);
		fprintf(fp, "          start_mapnr: %ld\n", nt->start_mapnr);
	}

	fprintf(fp, "    dump_free_pages: ");
	if (vt->dump_free_pages == dump_free_pages)
		fprintf(fp, "dump_free_pages()\n");
	else if (vt->dump_free_pages == dump_free_pages_zones_v1)
		fprintf(fp, "dump_free_pages_zones_v1()\n");
	else if (vt->dump_free_pages == dump_free_pages_zones_v2)
		fprintf(fp, "dump_free_pages_zones_v2()\n");
	else if (vt->dump_free_pages == dump_multidimensional_free_pages)
		fprintf(fp, "dump_multidimensional_free_pages()\n");
	else
		fprintf(fp, "%lx (unknown)\n", (ulong)vt->dump_free_pages);

	fprintf(fp, "    dump_kmem_cache: ");
	if (vt->dump_kmem_cache == dump_kmem_cache)
		fprintf(fp, "dump_kmem_cache()\n");
	else if (vt->dump_kmem_cache == dump_kmem_cache_percpu_v1)
		fprintf(fp, "dump_kmem_cache_percpu_v1()\n");
	else if (vt->dump_kmem_cache == dump_kmem_cache_percpu_v2)
		fprintf(fp, "dump_kmem_cache_percpu_v2()\n");
	else
		fprintf(fp, "%lx (unknown)\n", (ulong)vt->dump_kmem_cache);
	fprintf(fp, "          slab_data: %lx\n", (ulong)vt->slab_data);
	if (verbose) 
		dump_saved_slab_data();
	fprintf(fp, "       nr_swapfiles: %d\n", vt->nr_swapfiles);
	fprintf(fp, "     last_swap_read: %lx\n", vt->last_swap_read);
	fprintf(fp, "   swap_info_struct: %lx\n", (ulong)vt->swap_info_struct);
	fprintf(fp, "            mem_sec: %lx\n", (ulong)vt->mem_sec);
	fprintf(fp, "       ZONE_HIGHMEM: %d\n", vt->ZONE_HIGHMEM);
	fprintf(fp, "node_online_map_len: %d\n", vt->node_online_map_len);
	if (vt->node_online_map_len) {
		fprintf(fp, "    node_online_map: ");
		up = (ulong *)vt->node_online_map;
		for (i = 0; i < vt->node_online_map_len; i++) {
			fprintf(fp, "%s%lx", i ? ", " : "[", *up);
			up++;
		}
		fprintf(fp, "]\n");
	} else {
		fprintf(fp, "    node_online_map: (unused)\n");
	}
	fprintf(fp, "   nr_vm_stat_items: %d\n", vt->nr_vm_stat_items);
	fprintf(fp, "      vm_stat_items: %s", (vt->flags & VM_STAT) ?
		"\n" : "(not used)\n");
	for (i = 0; i < vt->nr_vm_stat_items; i++)
		fprintf(fp, "        [%d] %s\n", i, vt->vm_stat_items[i]);

	dump_vma_cache(VERBOSE);
}

/*
 *  Calculate the amount of memory referenced in the kernel-specific "nodes".
 */
uint64_t
total_node_memory()
{
	int i;
	struct node_table *nt;
	uint64_t total;

        for (i = total = 0; i < vt->numnodes; i++) {
                nt = &vt->node_table[i];

		if (CRASHDEBUG(1)) {
                	console("node_table[%d]: \n", i);
                	console("           id: %d\n", nt->node_id);
                	console("        pgdat: %lx\n", nt->pgdat);
                	console("         size: %ld\n", nt->size);
                	console("      present: %ld\n", nt->present);
                	console("      mem_map: %lx\n", nt->mem_map);
                	console("  start_paddr: %lx\n", nt->start_paddr);
                	console("  start_mapnr: %ld\n", nt->start_mapnr);
		}

		if (nt->present)
			total += (uint64_t)((uint64_t)nt->present * (uint64_t)PAGESIZE());
		else
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
                fprintf(fp, "     cached_vma[%2d]: %lx (%ld)\n",
                        i, vt->cached_vma[i],
                        vt->cached_vma_hits[i]);
        fprintf(fp, "          vma_cache: %lx\n", (ulong)vt->vma_cache);
        fprintf(fp, "    vma_cache_index: %d\n", vt->vma_cache_index);
        fprintf(fp, "    vma_cache_fills: %ld\n", vt->vma_cache_fills);
	fflush(fp);

show_hits:
        if (vt->vma_cache_fills) {
                for (i = vhits = 0; i < VMA_CACHE; i++)
                        vhits += vt->cached_vma_hits[i];

                fprintf(stderr, "%s       vma hit rate: %2ld%% (%ld of %ld)\n",
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
#ifdef OLDWAY
	ulong mbs, gbs;
#endif

	total = machdep->memory_size();

	if ((next_gig = roundup(total, GIGABYTES(1)))) {
		if ((next_gig - total) <= MEGABYTES(64))
			total = next_gig;
	}

	return (pages_to_size((ulong)(total/PAGESIZE()), buf));

#ifdef OLDWAY
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
#endif
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
 * Determine the first valid user space address
 */
static int
address_space_start(struct task_context *tc, ulong *addr)
{
        ulong vma;
        char *vma_buf;

        if (!tc->mm_struct)
                return FALSE;

        fill_mm_struct(tc->mm_struct);
        vma = ULONG(tt->mm_struct + OFFSET(mm_struct_mmap));
        if (!vma)
                return FALSE;
	vma_buf = fill_vma_cache(vma);
        *addr = ULONG(vma_buf + OFFSET(vm_area_struct_vm_start));
	
	return TRUE;
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
	ulong uvaddr_end;
	int sflag;
	struct meminfo meminfo;
	ulong value_array[MAXARGS];
	struct syment *sp;

	start = end = mask = sflag = memtype = len = 0;
	uvaddr_end = COMMON_VADDR_SPACE() ? (ulong)(-1) : machdep->kvbase;
	BZERO(value_array, sizeof(ulong) * MAXARGS);

        while ((c = getopt(argcnt, args, "l:uks:e:v:m:")) != EOF) {
                switch(c)
                {
		case 'u':
			if (!sflag) {
				address_space_start(CURRENT_CONTEXT(),&start);
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
			end = uvaddr_end;
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
		if (end > uvaddr_end) {
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
	ulong page;
	physaddr_t paddr;
	char *pagebuf;

	if (start & (sizeof(long)-1)) {
		start &= ~(sizeof(long)-1);
		error(INFO, "rounding down start address to: %lx\n", start);
	}

	pagebuf = GETBUF(PAGESIZE());
	next = start;

	for (pp = VIRTPAGEBASE(start); next < end; next = pp) {
		lastpage = (VIRTPAGEBASE(next) == VIRTPAGEBASE(end));
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

		if (CRASHDEBUG(1))
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

	vaddr = VIRTPAGEBASE(vaddr) + PAGESIZE();  /* first possible page */

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
 *  Return the next mapped kernel virtual address in the vmlist
 *  that is equal to or comes after the passed-in address.
 */
static ulong
next_vmlist_vaddr(struct meminfo *mi, ulong vaddr)
{
	ulong i, count;

	BZERO(mi, sizeof(struct meminfo));

        mi->flags = GET_VMLIST_COUNT;
        dump_vmlist(mi);
	count = mi->retval;

	if (!count)
		return vaddr;

	mi->vmlist = (struct vmlist *)GETBUF(sizeof(struct vmlist)*count);
        mi->flags = GET_VMLIST;
        dump_vmlist(mi);

	for (i = 0; i < count; i++) {
		if (vaddr <= mi->vmlist[i].addr) {
			vaddr = mi->vmlist[i].addr;
			break;
		}
		if (vaddr < (mi->vmlist[i].addr + mi->vmlist[i].size))
			break;
	}

	FREEBUF(mi->vmlist);

	return vaddr;
}


/*
 *  Return the next kernel virtual address page that comes after
 *  the passed-in address.
 */
static int
next_kpage(ulong vaddr, ulong *nextvaddr)
{
        int n;
        ulong paddr, vaddr_orig, node_size;
        struct node_table *nt;
        ulonglong pstart, pend;
	ulong vmalloc_limit;
	struct meminfo meminfo;

	vaddr_orig = vaddr;
	vaddr = VIRTPAGEBASE(vaddr) + PAGESIZE();  /* first possible page */

        if (vaddr < vaddr_orig)  /* wrapped back to zero? */
                return FALSE;

        meminfo.memtype = KVADDR;
        meminfo.spec_addr = 0;
        meminfo.flags = (ADDRESS_SPECIFIED|GET_HIGHEST);
        dump_vmlist(&meminfo);
        vmalloc_limit = meminfo.retval;

	if (IS_VMALLOC_ADDR(vaddr_orig)) {
		if (IS_VMALLOC_ADDR(vaddr) && (vaddr < vmalloc_limit)) {
			if (machine_type("X86_64")) 
				vaddr = next_vmlist_vaddr(&meminfo, vaddr);
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
                nt = &vt->node_table[n];
                if ((vt->flags & V_MEM_MAP) && (vt->numnodes == 1))
                        node_size = vt->max_mapnr;
                else
	                node_size = nt->size;

                pstart = nt->start_paddr;
                pend = pstart + ((ulonglong)node_size * PAGESIZE());

                if ((paddr < pstart) || (paddr >= pend))
                        continue;
                /*
                 *  We're in the physical range.
                 */
		*nextvaddr = vaddr;
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

static int
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

	if (swapflags & VERBOSE)
		fprintf(fp, swap_info_hdr);

	totalswap = totalused = 0;

	for (i = 0; i < vt->nr_swapfiles; i++, 
	    swap_info += SIZE(swap_info_struct)) {
		fill_swap_info(swap_info);

		flags = INT(vt->swap_info_struct + 
			OFFSET(swap_info_struct_flags));

		if (!(flags & SWP_USED))
			continue;

		swap_file = ULONG(vt->swap_info_struct + 
			OFFSET(swap_info_struct_swap_file));

                swap_device = INT(vt->swap_info_struct +
                        OFFSET_OPTION(swap_info_struct_swap_device, 
			swap_info_struct_old_block_size));

                pages = INT(vt->swap_info_struct +
                        OFFSET(swap_info_struct_pages));

		totalswap += pages;
		pages <<= (PAGESHIFT() - 10);

                prio = INT(vt->swap_info_struct + 
			OFFSET(swap_info_struct_prio));

		if (MEMBER_SIZE("swap_info_struct", "max") == sizeof(int))
			max = UINT(vt->swap_info_struct +
                                OFFSET(swap_info_struct_max));
		else
                	max = ULONG(vt->swap_info_struct +
                        	OFFSET(swap_info_struct_max));

                swap_map = ULONG(vt->swap_info_struct +
                        OFFSET(swap_info_struct_swap_map));

		if (swap_file) {
			if (VALID_MEMBER(swap_info_struct_swap_vfsmnt)) {
                		vfsmnt = ULONG(vt->swap_info_struct +
                        		OFFSET(swap_info_struct_swap_vfsmnt));
				get_pathname(swap_file, buf, BUFSIZE, 
					1, vfsmnt);
			} else if (VALID_MEMBER
				(swap_info_struct_old_block_size)) {
				get_pathname(file_to_dentry(swap_file), 
					buf, BUFSIZE, 1, file_to_vfsmnt(swap_file));
			} else {
				get_pathname(swap_file, buf, BUFSIZE, 1, 0);
			}
		} else
			sprintf(buf, "(unknown)");

		map = (ushort *)GETBUF(sizeof(ushort) * max);

		if (!readmem(swap_map, KVADDR, map, 
		    sizeof(ushort) * max, "swap_info swap_map data",
		    RETURN_ON_ERROR|QUIET)) {
			if (swapflags & RETURN_ON_ERROR) {
				*totalswap_pages = swap_map;
				*totalused_pages = i;
				return FALSE;
			} else 
				error(FATAL, 
		              "swap_info[%d].swap_map at %lx is unaccessible\n",
                        		i, swap_map);
		}

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

		if (swapflags & VERBOSE)
			fprintf(fp, "%-15s  %s    %7dk %7dk  %2ld%%     %d\n", 
				buf, swap_device ? "PARTITION" : "  FILE   ", 
				pages, usedswap, pct, prio);
	}

	if (totalswap_pages)
		*totalswap_pages = totalswap;
	if (totalused_pages)
		*totalused_pages = totalused;

	return TRUE;
}

/*
 *  Translate a PTE into a swap device and offset string.
 */
char *
swap_location(ulonglong pte, char *buf)
{
	char swapdev[BUFSIZE];

        if (!pte)
                return NULL;

	if (THIS_KERNEL_VERSION >= LINUX(2,6,0))
		sprintf(buf, "%s  OFFSET: %lld", 
			get_swapdev(__swp_type(pte), swapdev), __swp_offset(pte));
	else
		sprintf(buf, "%s  OFFSET: %llx", 
			get_swapdev(SWP_TYPE(pte), swapdev), SWP_OFFSET(pte));

        return buf;
}

/*
 *  Given the type field from a PTE, return the name of the swap device.
 */
static char *
get_swapdev(ulong type, char *buf)
{
	unsigned int i, swap_info_len;
	ulong swap_info, swap_file;
	ulong vfsmnt;

        if (!symbol_exists("nr_swapfiles"))
                error(FATAL, "nr_swapfiles doesn't exist in this kernel!\n");

        if (!symbol_exists("swap_info"))
                error(FATAL, "swap_info doesn't exist in this kernel!\n");

        swap_info = symbol_value("swap_info");

	swap_info_len = (i = ARRAY_LENGTH(swap_info)) ?
		i : get_array_length("swap_info", NULL, 0);

        sprintf(buf, "(unknown swap location)");

	if (type >= swap_info_len)
		return buf;

	swap_info += (SIZE(swap_info_struct) * type);
	fill_swap_info(swap_info);
	swap_file = ULONG(vt->swap_info_struct + 
		OFFSET(swap_info_struct_swap_file));

        if (swap_file) {
		if (VALID_MEMBER(swap_info_struct_swap_vfsmnt)) {
			vfsmnt = ULONG(vt->swap_info_struct + 
				OFFSET(swap_info_struct_swap_vfsmnt));
        		get_pathname(swap_file, buf, BUFSIZE, 1, vfsmnt);
                } else if (VALID_MEMBER (swap_info_struct_old_block_size)) {
                        get_pathname(file_to_dentry(swap_file),
                        	buf, BUFSIZE, 1, 0);
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
	if (VALID_MEMBER(file_f_vfsmnt)) {
        	vfsmnt = ULONG(file_buf + OFFSET(file_f_vfsmnt));
               	get_pathname(dentry, file, BUFSIZE, 1, vfsmnt);
	} else 
               	get_pathname(dentry, file, BUFSIZE, 1, 0);

	if (!strlen(file)) 
		goto no_file_offset;

        vm_start = ULONG(vma_buf + OFFSET(vm_area_struct_vm_start));

	vm_offset = vm_pgoff = 0xdeadbeef;

	if (VALID_MEMBER(vm_area_struct_vm_offset)) 
        	vm_offset = ULONG(vma_buf + 
			OFFSET(vm_area_struct_vm_offset));
	else if (VALID_MEMBER(vm_area_struct_vm_pgoff))
        	vm_pgoff = ULONG(vma_buf + 
			OFFSET(vm_area_struct_vm_pgoff));
	else 
		goto no_file_offset;

	if (vm_offset != 0xdeadbeef) 
		offset = VIRTPAGEBASE(vaddr) - vm_start + vm_offset;
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
	ulonglong pte;

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
		pte = htoll(args[optind], FAULT_ON_ERROR, NULL);
		machdep->translate_pte((ulong)pte, NULL, pte);
		optind++;
	}

}

static char *node_zone_hdr = "ZONE  NAME         SIZE";

/*
 *  On systems supporting memory nodes, display the basic per-node data.
 */
static void
dump_memory_nodes(int initialize)
{
	int i, j;
	int n, id, node, flen, slen, badaddr;
	ulong node_mem_map;
        ulong node_start_paddr;
	ulong node_start_pfn;
        ulong node_start_mapnr;
	ulong node_spanned_pages, node_present_pages;
        ulong free_pages, zone_size, node_size, cum_zone_size;
	ulong zone_start_paddr, zone_start_mapnr, zone_mem_map;
	physaddr_t phys;
	ulong pp;
	ulong zone_start_pfn;
	ulong bdata;
	ulong pgdat;
	ulong node_zones;
	ulong value;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];
	char buf5[BUFSIZE];
	struct node_table *nt;

	if (!(vt->flags & (NODES|NODES_ONLINE)) && initialize) {
		nt = &vt->node_table[0];
		nt->node_id = 0;
		if (symbol_exists("contig_page_data"))
			nt->pgdat = symbol_value("contig_page_data");
                else
			nt->pgdat = 0;
		nt->size = vt->total_pages;
		nt->mem_map = vt->mem_map;
		nt->start_paddr = 0;
		nt->start_mapnr = 0;
                if (CRASHDEBUG(1)) {
                        fprintf(fp, "node_table[%d]: \n", 0);
                        fprintf(fp, "             id: %d\n", nt->node_id);
                        fprintf(fp, "          pgdat: %lx\n", nt->pgdat);
                        fprintf(fp, "           size: %ld\n", nt->size);
                        fprintf(fp, "        present: %ld\n", nt->present);
                        fprintf(fp, "        mem_map: %lx\n", nt->mem_map);
                        fprintf(fp, "    start_paddr: %llx\n", nt->start_paddr);
                        fprintf(fp, "    start_mapnr: %ld\n", nt->start_mapnr);
                }
		return;
	}

	if (initialize) {
		/*
		 *  This order may have to change based upon architecture...
		 */
		if (symbol_exists("pgdat_list") && 
		    (VALID_MEMBER(pglist_data_node_next) || 
		     VALID_MEMBER(pglist_data_pgdat_next))) {
                        get_symbol_data("pgdat_list", sizeof(void *), &pgdat);
			vt->flags &= ~NODES_ONLINE;
		} else if (vt->flags & NODES_ONLINE) {
			if ((node = next_online_node(0)) < 0) {
				error(WARNING, 
				   "cannot determine first node from node_online_map\n\n");
				return;
			} 
			if (!(pgdat = next_online_pgdat(node))) { 
				error(WARNING, 
				   "cannot determine pgdat list for this kernel/architecture\n\n");
				return;
			}
		} 
	} else
		pgdat = vt->node_table[0].pgdat;

	for (n = 0, badaddr = FALSE; pgdat; n++) {
		if (n >= vt->numnodes)
			error(FATAL, "numnodes out of sync with pgdat_list?\n");

		nt = &vt->node_table[n];

		readmem(pgdat+OFFSET(pglist_data_node_id), KVADDR, &id,
			sizeof(int), "pglist node_id", FAULT_ON_ERROR);

		if (VALID_MEMBER(pglist_data_node_mem_map)) {
			readmem(pgdat+OFFSET(pglist_data_node_mem_map), KVADDR, 
				&node_mem_map, sizeof(ulong), 
				"node_mem_map", FAULT_ON_ERROR);
		} else {
			node_mem_map = BADADDR;
			badaddr = TRUE;
		}

		if (VALID_MEMBER(pglist_data_node_start_paddr))
			readmem(pgdat+OFFSET(pglist_data_node_start_paddr), 
				KVADDR, &node_start_paddr, sizeof(ulong), 
				"pglist node_start_paddr", FAULT_ON_ERROR);
		else if (VALID_MEMBER(pglist_data_node_start_pfn)) {
			readmem(pgdat+OFFSET(pglist_data_node_start_pfn), 
				KVADDR, &node_start_pfn, sizeof(ulong), 
				"pglist node_start_pfn", FAULT_ON_ERROR);
				node_start_mapnr = node_start_pfn;
				node_start_paddr = PTOB(node_start_pfn);
			if (badaddr && IS_SPARSEMEM()) {
				phys = PTOB(node_start_pfn);
                                if (phys_to_page(phys, &pp))
                                	node_mem_map = pp;
			}
		} else error(INFO, 
			"cannot determine zone starting physical address\n");

		if (VALID_MEMBER(pglist_data_node_start_mapnr))
			readmem(pgdat+OFFSET(pglist_data_node_start_mapnr), 
				KVADDR, &node_start_mapnr, sizeof(ulong), 
				"pglist node_start_mapnr", FAULT_ON_ERROR);

		if (VALID_MEMBER(pglist_data_node_size)) 
			readmem(pgdat+OFFSET(pglist_data_node_size), 
				KVADDR, &node_size, sizeof(ulong), 
				"pglist node_size", FAULT_ON_ERROR);
		else if (VALID_MEMBER(pglist_data_node_spanned_pages)) {
			readmem(pgdat+OFFSET(pglist_data_node_spanned_pages), 
				KVADDR, &node_spanned_pages, sizeof(ulong), 
				"pglist node_spanned_pages", FAULT_ON_ERROR);
			node_size = node_spanned_pages;
		} else error(INFO, "cannot determine zone size\n");

		if (VALID_MEMBER(pglist_data_node_present_pages))
                        readmem(pgdat+OFFSET(pglist_data_node_present_pages),
                                KVADDR, &node_present_pages, sizeof(ulong),
                                "pglist node_present_pages", FAULT_ON_ERROR);
		else
			node_present_pages = 0;

		readmem(pgdat+OFFSET(pglist_data_bdata), KVADDR, &bdata,
			sizeof(ulong), "pglist bdata", FAULT_ON_ERROR);

		if (initialize) {
			nt->node_id = id;
			nt->pgdat = pgdat;
			if (VALID_MEMBER(zone_struct_memsize)) 
				nt->size = 0;  /* initialize below */
			else 
				nt->size = node_size;
			nt->present = node_present_pages;
			nt->mem_map = node_mem_map;
			nt->start_paddr = node_start_paddr;
			nt->start_mapnr = node_start_mapnr;

			if (CRASHDEBUG(1)) {
                		fprintf(fp, "node_table[%d]: \n", n);
                		fprintf(fp, "             id: %d\n", nt->node_id);
                		fprintf(fp, "          pgdat: %lx\n", nt->pgdat);
                		fprintf(fp, "           size: %ld\n", nt->size);
                		fprintf(fp, "        present: %ld\n", nt->present);
                		fprintf(fp, "        mem_map: %lx\n", nt->mem_map);
                		fprintf(fp, "    start_paddr: %llx\n", nt->start_paddr);
                		fprintf(fp, "    start_mapnr: %ld\n", nt->start_mapnr);
			}
		}

		if (!initialize) {
			if (n) {
				fprintf(fp, "\n");
				pad_line(fp, slen, '-');
			}
			flen = MAX(VADDR_PRLEN, strlen("BOOTMEM_DATA"));
			fprintf(fp, "%sNODE  %s  %s  %s  %s\n", 
			    n ? "\n\n" : "",
			    mkstring(buf1, 8, CENTER, "SIZE"),
			    mkstring(buf2, flen, CENTER|LJUST, "PGLIST_DATA"),
			    mkstring(buf3, flen, CENTER|LJUST, "BOOTMEM_DATA"),
			    mkstring(buf4, flen, CENTER|LJUST, "NODE_ZONES"));

			node_zones = pgdat + OFFSET(pglist_data_node_zones);
			sprintf(buf5, " %2d   %s  %s  %s  %s\n", id, 
			    mkstring(buf1, 8, CENTER|LJUST|LONG_DEC, 
				MKSTR(node_size)),
			    mkstring(buf2, flen, CENTER|LJUST|LONG_HEX, 
				MKSTR(pgdat)),
			    mkstring(buf3, flen, CENTER|LONG_HEX, 
				MKSTR(bdata)),
			    mkstring(buf4, flen, CENTER|LJUST|LONG_HEX,
                                MKSTR(node_zones)));
			fprintf(fp, "%s", buf5);

			j = 12 + strlen(buf1) + strlen(buf2) + strlen(buf3) +
				count_leading_spaces(buf4);
                	for (i = 1; i < vt->nr_zones; i++) {
				node_zones += SIZE_OPTION(zone_struct, zone);
				INDENT(j);
				fprintf(fp, "%lx\n", node_zones);
			}
	
	                fprintf(fp, "%s  START_PADDR  START_MAPNR\n",
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
	
			sprintf(buf2, "%s  %s  START_PADDR  START_MAPNR", 
				node_zone_hdr,
				mkstring(buf1, VADDR_PRLEN, CENTER|RJUST, 
				    "MEM_MAP"));
			slen = strlen(buf2);
			fprintf(fp, "\n%s\n", buf2);
		}

       		node_zones = pgdat + OFFSET(pglist_data_node_zones);
		cum_zone_size = 0;
		for (i = 0; i < vt->nr_zones; i++) {
			if (CRASHDEBUG(7))
				fprintf(fp, "zone %d at %lx\n", i, node_zones);

			if (VALID_MEMBER(zone_struct_size))
                		readmem(node_zones+OFFSET(zone_struct_size), 
				    	KVADDR, &zone_size, sizeof(ulong),
                        		"zone_struct size", FAULT_ON_ERROR);
			else if (VALID_MEMBER(zone_struct_memsize)) {
                		readmem(node_zones+OFFSET(zone_struct_memsize), 
				    	KVADDR, &zone_size, sizeof(ulong),
                        		"zone_struct memsize", FAULT_ON_ERROR);
				nt->size += zone_size;
			} else if (VALID_MEMBER(zone_spanned_pages)) {
                		readmem(node_zones+ OFFSET(zone_spanned_pages), 
				    	KVADDR, &zone_size, sizeof(ulong),
                        		"zone spanned_pages", FAULT_ON_ERROR);
			} else error(FATAL, 
			    "zone_struct has neither size nor memsize field\n");

                	readmem(node_zones+ 
				OFFSET_OPTION(zone_struct_free_pages,
				zone_free_pages), KVADDR, &free_pages, 
				sizeof(ulong), "zone[_struct] free_pages", 
				FAULT_ON_ERROR);
                	readmem(node_zones+OFFSET_OPTION(zone_struct_name,
				zone_name), KVADDR, &value, sizeof(void *),
                        	"zone[_struct] name", FAULT_ON_ERROR);
                	if (!read_string(value, buf1, BUFSIZE-1))
                        	sprintf(buf1, "(unknown) ");
			if (VALID_STRUCT(zone_struct)) {
				if (VALID_MEMBER(zone_struct_zone_start_paddr))
				{
                        		readmem(node_zones+OFFSET
					    (zone_struct_zone_start_paddr),
                                	    KVADDR, &zone_start_paddr, 
					    sizeof(ulong), 
					    "node_zones zone_start_paddr", 
					    FAULT_ON_ERROR);
				} else {
					readmem(node_zones+
					    OFFSET(zone_struct_zone_start_pfn),
					    KVADDR, &zone_start_pfn,
					    sizeof(ulong),
					    "node_zones zone_start_pfn",
					    FAULT_ON_ERROR);
					    zone_start_paddr = 
						PTOB(zone_start_pfn);
				}
                        	readmem(node_zones+
					OFFSET(zone_struct_zone_start_mapnr),
                                	KVADDR, &zone_start_mapnr, 
					sizeof(ulong), 
					"node_zones zone_start_mapnr", 
					FAULT_ON_ERROR);
			} else {
                                readmem(node_zones+
                                        OFFSET(zone_zone_start_pfn),
                                        KVADDR, &zone_start_pfn,
                                        sizeof(ulong),
                                        "node_zones zone_start_pfn",
                                        FAULT_ON_ERROR);
				zone_start_paddr = PTOB(zone_start_pfn);

				if (IS_SPARSEMEM()) {
					zone_mem_map = 0;
					zone_start_mapnr = 0;
					if (zone_size) {
						phys = PTOB(zone_start_pfn);
						zone_start_mapnr = phys/PAGESIZE();
					}

				} else if (!(vt->flags & NODES) && 
				    INVALID_MEMBER(zone_zone_mem_map)) {
					readmem(pgdat+OFFSET(pglist_data_node_mem_map),
                                    	    KVADDR, &zone_mem_map, sizeof(void *),
                                    	    "contig_page_data mem_map", FAULT_ON_ERROR);
					if (zone_size)
						zone_mem_map += cum_zone_size * SIZE(page);
				} else readmem(node_zones+
                                        OFFSET(zone_zone_mem_map),
                                        KVADDR, &zone_mem_map,
                                        sizeof(ulong),
                                        "node_zones zone_mem_map",
                                        FAULT_ON_ERROR);

				if (zone_mem_map)
					zone_start_mapnr = 
				    	    (zone_mem_map - node_mem_map) / 
					    SIZE(page);
				else if (!IS_SPARSEMEM())
					zone_start_mapnr = 0;
			}

			if (IS_SPARSEMEM()) {
				zone_mem_map = 0;
				if (zone_size) {
					phys = PTOB(zone_start_pfn);
					if (phys_to_page(phys, &pp))
						zone_mem_map = pp;
				}
			} else if (!(vt->flags & NODES) && 
			    INVALID_MEMBER(zone_struct_zone_mem_map) &&
			    INVALID_MEMBER(zone_zone_mem_map)) {
                		readmem(pgdat+OFFSET(pglist_data_node_mem_map),
				    KVADDR, &zone_mem_map, sizeof(void *), 
				    "contig_page_data mem_map", FAULT_ON_ERROR);
				if (zone_size)
					zone_mem_map += cum_zone_size * SIZE(page);
				else
					zone_mem_map = 0;
			} else 
				readmem(node_zones+
				    OFFSET_OPTION(zone_struct_zone_mem_map,
				    zone_zone_mem_map), KVADDR, &zone_mem_map, 
				    sizeof(ulong), "node_zones zone_mem_map", 
				    FAULT_ON_ERROR);

			if (!initialize) {
				fprintf(fp, " %2d   %-9s %7ld  ", 
					i, buf1, zone_size);
				cum_zone_size += zone_size;
				fprintf(fp, "%s  %s  %s\n",
	                    	    mkstring(buf1, VADDR_PRLEN,
	                        	RJUST|LONG_HEX,MKSTR(zone_mem_map)),
	                            mkstring(buf2, strlen("START_PADDR"),
	                        	LONG_HEX|RJUST,MKSTR(zone_start_paddr)),
	                    	    mkstring(buf3, strlen("START_MAPNR"),
	                        	LONG_DEC|RJUST,
					MKSTR(zone_start_mapnr)));
			}

			node_zones += SIZE_OPTION(zone_struct, zone);
		}

		if (initialize) {
			if (vt->flags & NODES_ONLINE) {
				if ((node = next_online_node(node+1)) < 0)
					pgdat = 0;
                        	else if (!(pgdat = next_online_pgdat(node))) {
                                	error(WARNING,
                   "cannot determine pgdat list for this kernel/architecture (node %d)\n\n", 
						node);
					pgdat = 0;
                        	}
			} else 
				readmem(pgdat + OFFSET_OPTION(pglist_data_node_next,
					pglist_data_pgdat_next), KVADDR,
					&pgdat, sizeof(void *), "pglist_data node_next",
					FAULT_ON_ERROR);
		} else {
			if ((n+1) < vt->numnodes)
				pgdat = vt->node_table[n+1].pgdat;
			else
				pgdat = 0;
		}
	} 

	if (n != vt->numnodes) {
		if (CRASHDEBUG(2))
			error(NOTE, "changing numnodes from %d to %d\n",
				vt->numnodes, n);
		vt->numnodes = n;
	}

	if (!initialize && IS_SPARSEMEM())
		dump_mem_sections();
}

/*
 *  Gather essential information regarding each memory node.
 */
static void
node_table_init(void)
{
	int n;
	ulong pgdat;

	/*
	 *  Override numnodes -- some kernels may leave it at 1 on a system
	 *  with multiple memory nodes.
	 */
	if ((vt->flags & NODES) && (VALID_MEMBER(pglist_data_node_next) || 
	    VALID_MEMBER(pglist_data_pgdat_next))) {

	        get_symbol_data("pgdat_list", sizeof(void *), &pgdat);
	
	        for (n = 0; pgdat; n++) {
	                readmem(pgdat + OFFSET_OPTION(pglist_data_node_next,
	                        pglist_data_pgdat_next), KVADDR,
	                        &pgdat, sizeof(void *), "pglist_data node_next",
	                        FAULT_ON_ERROR);
		}
		if (n != vt->numnodes) {
			if (CRASHDEBUG(2))
				error(NOTE, "changing numnodes from %d to %d\n",
					vt->numnodes, n);
			vt->numnodes = n;
		}
	} else
		vt->flags &= ~NODES;

       	if (!(vt->node_table = (struct node_table *)
	    malloc(sizeof(struct node_table) * vt->numnodes)))
		error(FATAL, "cannot malloc node_table %s(%d nodes)",
			vt->numnodes > 1 ? "array " : "", vt->numnodes);

	BZERO(vt->node_table, sizeof(struct node_table) * vt->numnodes);

	dump_memory_nodes(MEMORY_NODES_INITIALIZE);

        qsort((void *)vt->node_table, (size_t)vt->numnodes,
                sizeof(struct node_table), compare_node_data);

	if (CRASHDEBUG(2))
		dump_memory_nodes(MEMORY_NODES_DUMP);
}

/*
 *  The comparison function must return an integer less  than,
 *  equal  to,  or  greater than zero if the first argument is
 *  considered to be respectively  less  than,  equal  to,  or
 *  greater than the second.  If two members compare as equal,
 *  their order in the sorted array is undefined.
 */

static int
compare_node_data(const void *v1, const void *v2)
{
        struct node_table *t1, *t2;

        t1 = (struct node_table *)v1;
        t2 = (struct node_table *)v2;

        return (t1->node_id < t2->node_id ? -1 :
                t1->node_id == t2->node_id ? 0 : 1);
}


/*
 *  Depending upon the processor, and whether we're running live or on a 
 *  dumpfile, get the system page size.
 */
uint
memory_page_size(void)
{
	uint psz;

	if (machdep->pagesize)
		return machdep->pagesize;

	if (REMOTE_MEMSRC()) 
		return remote_page_size();

	switch (pc->flags & MEMORY_SOURCES)
	{
	case DISKDUMP:
		psz = diskdump_page_size();
		break;

        case XENDUMP:
                psz = xendump_page_size();
                break;

	case KDUMP:
		psz = kdump_page_size();
		break;

	case NETDUMP:
		psz = netdump_page_size();
		break;

	case MCLXCD:
		psz = (uint)mclx_page_size();
		break;

	case LKCD:
#if 0							/* REMIND: */
		psz = lkcd_page_size();			/* dh_dump_page_size is HW page size; should add dh_page_size */
#else
		psz = (uint)getpagesize();
#endif
		break;

	case DEVMEM:                      
	case MEMMOD:
		psz = (uint)getpagesize();  
		break;

	case S390D:
		psz = s390_page_size();
		break;

	default:
		error(FATAL, "memory_page_size: invalid pc->flags: %lx\n", 
			pc->flags & MEMORY_SOURCES); 
	}

	return psz;
}

/*
 *  If the page size cannot be determined by the dumpfile (like kdump),
 *  and the processor default cannot be used, allow the force-feeding
 *  of a crash command-line page size option.
 */
void
force_page_size(char *s)
{
	int k, err;
	ulong psize;

	k = 1;
	err = FALSE;

	switch (LASTCHAR(s))
	{
	case 'k':
	case 'K':
		LASTCHAR(s) = NULLCHAR;
		if (!decimal(s, 0)) {
			err = TRUE;
			break;
		}
		k = 1024;

		/* FALLTHROUGH */

	default:
        	if (decimal(s, 0))
                	psize = dtol(s, QUIET|RETURN_ON_ERROR, &err);
        	else if (hexadecimal(s, 0))
                	psize = htol(s, QUIET|RETURN_ON_ERROR, &err);
		else
			err = TRUE;
		break;
	}

	if (err) 
		error(INFO, "invalid page size: %s\n", s);
	else
		machdep->pagesize = psize * k;
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

	if (!vmlist)
		return 0;

        if (!readmem(vmlist+OFFSET(vm_struct_addr), KVADDR, &addr, 
	    sizeof(void *), "first vmlist addr", RETURN_ON_ERROR)) 
		non_matching_kernel();

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

	if (VALID_MEMBER(kmem_cache_s_c_align)) {
                readmem(cache_cache+OFFSET(kmem_cache_s_c_align),
                	KVADDR, &c_align, sizeof(ulong),
                        "c_align", FAULT_ON_ERROR);
		retval = (int)c_align;
	} else if (VALID_MEMBER(kmem_cache_s_colour_off)) {
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
                if (REMOTE_DUMPFILE()) 
                        retval = remote_memory_used();
		else if (pc->flags & NETDUMP)
        		retval = netdump_memory_used();
		else if (pc->flags & KDUMP)
        		retval = kdump_memory_used();
		else if (pc->flags & XENDUMP)
        		retval = xendump_memory_used();
		else if (pc->flags & DISKDUMP)
        		retval = diskdump_memory_used();
		else if (pc->flags & LKCD)
        		retval = lkcd_memory_used();
		else if (pc->flags & MCLXCD)
                        retval = vas_memory_used();
		else if (pc->flags & S390D)
			retval = s390_memory_used();
		break;

	case DUMPFILE_FREE_MEM:
                if (REMOTE_DUMPFILE())
                        retval = remote_free_memory();
                else if (pc->flags & NETDUMP)
			retval = netdump_free_memory();
                else if (pc->flags & KDUMP)
			retval = kdump_free_memory();
                else if (pc->flags & XENDUMP)
			retval = xendump_free_memory();
                else if (pc->flags & DISKDUMP)
			retval = diskdump_free_memory();
                else if (pc->flags & LKCD)
                        retval = lkcd_free_memory();
                else if (pc->flags & MCLXCD)
                        retval = vas_free_memory(NULL);
                else if (pc->flags & S390D)
                        retval = s390_free_memory();
		break;

	case DUMPFILE_MEM_DUMP:
		if (REMOTE_DUMPFILE())
                        retval = remote_memory_dump(0);
                else if (pc->flags & NETDUMP) 
                        retval = netdump_memory_dump(fp);
                else if (pc->flags & KDUMP) 
                        retval = kdump_memory_dump(fp);
                else if (pc->flags & XENDUMP) 
                        retval = xendump_memory_dump(fp);
                else if (pc->flags & DISKDUMP) 
                        retval = diskdump_memory_dump(fp);
                else if (pc->flags & LKCD) 
                        retval = lkcd_memory_dump(set_lkcd_fp(fp));
                else if (pc->flags & MCLXCD)
                        retval = vas_memory_dump(fp);
                else if (pc->flags & S390D)
                        retval = s390_memory_dump(fp);
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

/* 
 *  Functions for sparse mem support 
 */
ulong 
sparse_decode_mem_map(ulong coded_mem_map, ulong section_nr)
{
        return coded_mem_map + 
	    (section_nr_to_pfn(section_nr) * SIZE(page));
}

void
sparse_mem_init(void)
{
	ulong addr;
	ulong mem_section_size;

	if (!IS_SPARSEMEM())
		return;

	MEMBER_OFFSET_INIT(mem_section_section_mem_map, "mem_section",
		"section_mem_map");
	STRUCT_SIZE_INIT(mem_section, "mem_section");

	if (!MAX_PHYSMEM_BITS())
		error(FATAL, 
		    "CONFIG_SPARSEMEM kernels not supported for this architecture\n");
		
	if (get_array_length("mem_section", NULL, 0) ==
	    (NR_MEM_SECTIONS() / _SECTIONS_PER_ROOT_EXTREME()))
		vt->flags |= SPARSEMEM_EX;

	if (IS_SPARSEMEM_EX()) {
		machdep->sections_per_root = _SECTIONS_PER_ROOT_EXTREME();
		mem_section_size = sizeof(void *) * NR_SECTION_ROOTS();
	} else {
		machdep->sections_per_root = _SECTIONS_PER_ROOT();
		mem_section_size = SIZE(mem_section) * NR_SECTION_ROOTS();
	}

	if (CRASHDEBUG(1)) {
		fprintf(fp, "PAGESIZE=%d\n",PAGESIZE());
		fprintf(fp,"mem_section_size = %ld\n", mem_section_size);
		fprintf(fp, "NR_SECTION_ROOTS = %ld\n", NR_SECTION_ROOTS());
		fprintf(fp, "NR_MEM_SECTIONS = %ld\n", NR_MEM_SECTIONS());
		fprintf(fp, "SECTIONS_PER_ROOT = %ld\n", SECTIONS_PER_ROOT() );
		fprintf(fp, "SECTION_ROOT_MASK = 0x%lx\n", SECTION_ROOT_MASK());
		fprintf(fp, "PAGES_PER_SECTION = %ld\n", PAGES_PER_SECTION());
	}

	if (!(vt->mem_sec = malloc(mem_section_size)))
		error(FATAL, "cannot malloc mem_sec cache\n");

	addr = symbol_value("mem_section");
	readmem(addr, KVADDR,vt->mem_sec ,mem_section_size,
		"memory section root table", FAULT_ON_ERROR);
}

char
*read_mem_section(ulong addr)
{
	static char *mem_section;

	if (!mem_section) {
		mem_section = GETBUF(SIZE(mem_section));
	}

	if (!IS_KVADDR(addr))
		return 0;
	
	readmem(addr, KVADDR, mem_section, SIZE(mem_section),
		"memory section", FAULT_ON_ERROR);

	return mem_section;
}

ulong
nr_to_section(ulong nr)
{
	ulong addr;
	ulong *mem_sec = vt->mem_sec;

	if (!IS_KVADDR(mem_sec[SECTION_NR_TO_ROOT(nr)]))
		return 0;

	if (IS_SPARSEMEM_EX())
		addr = mem_sec[SECTION_NR_TO_ROOT(nr)] + 
		    (nr & SECTION_ROOT_MASK()) * SIZE(mem_section);
	else
		addr = mem_sec[0] + (nr & SECTION_ROOT_MASK()) * SIZE(mem_section);

	if (!IS_KVADDR(addr))
		return 0;

	return addr;
}

/*
 * We use the lower bits of the mem_map pointer to store
 * a little bit of information.  There should be at least
 * 3 bits here due to 32-bit alignment.
 */
#define SECTION_MARKED_PRESENT	(1UL<<0)
#define SECTION_HAS_MEM_MAP	(1UL<<1)
#define SECTION_MAP_LAST_BIT	(1UL<<2)
#define SECTION_MAP_MASK	(~(SECTION_MAP_LAST_BIT-1))


int 
valid_section(ulong addr)
{
	char *mem_section;

	if ((mem_section = read_mem_section(addr)))
        	return (ULONG(mem_section + 
			OFFSET(mem_section_section_mem_map)) && 
			SECTION_MARKED_PRESENT);
	return 0;
}

int 
section_has_mem_map(ulong addr)
{
	char *mem_section;

	if ((mem_section = read_mem_section(addr)))
		return (ULONG(mem_section + 
			OFFSET(mem_section_section_mem_map))
			&& SECTION_HAS_MEM_MAP);
	return 0;
}

ulong 
section_mem_map_addr(ulong addr)
{   
	char *mem_section;
	ulong map;

	if ((mem_section = read_mem_section(addr))) {
		map = ULONG(mem_section + 
			OFFSET(mem_section_section_mem_map));
		map &= SECTION_MAP_MASK;
		return map;
	}
	return 0;
}


ulong 
valid_section_nr(ulong nr)
{
	ulong addr = nr_to_section(nr);

	if (valid_section(addr))
		return addr;

	return 0;
}

ulong 
pfn_to_map(ulong pfn)
{
	ulong section, page_offset;
	ulong section_nr;
	ulong coded_mem_map, mem_map;

	section_nr = pfn_to_section_nr(pfn);
	if (!(section = valid_section_nr(section_nr))) 
		return 0;

	if (section_has_mem_map(section)) {
		page_offset = pfn - section_nr_to_pfn(section_nr);
		coded_mem_map = section_mem_map_addr(section);
		mem_map = sparse_decode_mem_map(coded_mem_map, section_nr) +
			(page_offset * SIZE(page));
		return mem_map;
	}

	return 0;
}

void 
dump_mem_sections(void)
{
	ulong nr,addr;
	ulong nr_mem_sections;
	ulong coded_mem_map, mem_map, pfn;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char buf3[BUFSIZE];
	char buf4[BUFSIZE];

	nr_mem_sections = NR_MEM_SECTIONS();

	fprintf(fp, "\n");
	pad_line(fp, BITS32() ? 59 : 67, '-');
        fprintf(fp, "\n\nNR  %s  %s  %s  PFN\n",
                mkstring(buf1, VADDR_PRLEN, CENTER|LJUST, "SECTION"),
                mkstring(buf2, VADDR_PRLEN, CENTER|LJUST, "CODED_MEM_MAP"),
                mkstring(buf3, VADDR_PRLEN, CENTER|LJUST, "MEM_MAP"));

	for (nr = 0; nr <= nr_mem_sections ; nr++) {
		if ((addr = valid_section_nr(nr))) {
			coded_mem_map = section_mem_map_addr(addr);
			mem_map = sparse_decode_mem_map(coded_mem_map,nr);
			pfn = section_nr_to_pfn(nr);

        		fprintf(fp, "%2ld  %s  %s  %s  %s\n",
                		nr,
                		mkstring(buf1, VADDR_PRLEN,
                        	CENTER|LONG_HEX, MKSTR(addr)),
                		mkstring(buf2, VADDR_PRLEN,
                        	CENTER|LONG_HEX|RJUST, MKSTR(coded_mem_map)),
                		mkstring(buf3, VADDR_PRLEN,
                        	CENTER|LONG_HEX|RJUST, MKSTR(mem_map)),
				pc->output_radix == 10 ?
                		mkstring(buf4, VADDR_PRLEN,
                        	LONG_DEC|LJUST, MKSTR(pfn)) :
                		mkstring(buf4, VADDR_PRLEN,
                        	LONG_HEX|LJUST, MKSTR(pfn)));
		}
	}
}

void 
list_mem_sections(void)
{
	ulong nr,addr;
	ulong nr_mem_sections = NR_MEM_SECTIONS();
	ulong coded_mem_map;

	for (nr = 0; nr <= nr_mem_sections ; nr++) {
		if ((addr = valid_section_nr(nr))) {
			coded_mem_map = section_mem_map_addr(addr);
			fprintf(fp,
			    "nr=%ld section = %lx coded_mem_map=%lx pfn=%ld mem_map=%lx\n",
				nr,
				addr,
				coded_mem_map,
				section_nr_to_pfn(nr),
				sparse_decode_mem_map(coded_mem_map,nr));
		}
	}
}

/*
 *  For kernels containing the node_online_map, return
 *  the number of node bits set.
 */
static int
get_nodes_online(void)
{
	int i, len, online;
	struct gnu_request req;
	ulong *maskptr;

	if (!symbol_exists("node_online_map")) 
		return 0;

	if (LKCD_KERNTYPES()) {
                if ((len = STRUCT_SIZE("nodemask_t")) < 0)
       			error(FATAL, "cannot determine type nodemask_t\n");
	} else
		len = get_symbol_type("node_online_map", NULL, &req)
			== TYPE_CODE_UNDEF ?  sizeof(ulong) : req.length;

       	if (!(vt->node_online_map = (ulong *)malloc(len)))
       		error(FATAL, "cannot malloc node_online_map\n");

       	if (!readmem(symbol_value("node_online_map"), KVADDR, 
	    (void *)&vt->node_online_map[0], len, "node_online_map", 
	    QUIET|RETURN_ON_ERROR))
		error(FATAL, "cannot read node_online_map\n");

	vt->node_online_map_len = len/sizeof(ulong);

	online = 0;

	maskptr = (ulong *)vt->node_online_map;
	for (i = 0; i < vt->node_online_map_len; i++, maskptr++)
		online += count_bits_long(*maskptr);

	if (CRASHDEBUG(1)) {
		fprintf(fp, "node_online_map: [");
		for (i = 0; i < vt->node_online_map_len; i++)
			fprintf(fp, "%s%lx", i ? ", " : "",  vt->node_online_map[i]);
		fprintf(fp, "] -> nodes online: %d\n", online);
	}

	return online;
}

/*
 *  Return the next node index, with "first" being the first acceptable node.
 */
static int
next_online_node(int first)
{
	int i, j, node;
	ulong mask, *maskptr;

	if ((first/BITS_PER_LONG) >= vt->node_online_map_len) {
		error(INFO, "next_online_node: %d is too large!\n", first);
		return -1;
	}

	maskptr = (ulong *)vt->node_online_map;
	for (i = node = 0; i <  vt->node_online_map_len; i++, maskptr++) {
		mask = *maskptr;
        	for (j = 0; j < BITS_PER_LONG; j++, node++) {
                	if (mask & 1) {
				if (node >= first)
					return node;
			}
               	 	mask >>= 1;
        	}
	}

	return -1;
}

/*
 *  Modify appropriately for architecture/kernel nuances.
 */
static ulong
next_online_pgdat(int node)
{
        char buf[BUFSIZE];
	ulong pgdat;

	/*
  	 *  Default -- look for type: struct pglist_data node_data[]
	 */
	if (LKCD_KERNTYPES()) {
		if (!kernel_symbol_exists("node_data"))
			goto pgdat2;
		/* 
		 *  Just index into node_data[] without checking that it is
		 *  an array; kerntypes have no such symbol information.
	 	 */
	} else {
		if (get_symbol_type("node_data", NULL, NULL) != TYPE_CODE_ARRAY)
			goto pgdat2;

	        open_tmpfile();
	        sprintf(buf, "whatis node_data");
	        if (!gdb_pass_through(buf, fp, GNU_RETURN_ON_ERROR)) {
	                close_tmpfile();
			goto pgdat2;
	        }
	        rewind(pc->tmpfile);
	        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
	                if (STRNEQ(buf, "type = "))
	                        break;
	        }
	        close_tmpfile();

		if ((!strstr(buf, "struct pglist_data *") &&
		     !strstr(buf, "pg_data_t *")) ||
		    (count_chars(buf, '[') != 1) ||
		    (count_chars(buf, ']') != 1))
			goto pgdat2;
	}

	if (!readmem(symbol_value("node_data") + (node * sizeof(void *)), 
	    KVADDR, &pgdat, sizeof(void *), "node_data", RETURN_ON_ERROR) ||
	    !IS_KVADDR(pgdat))
		goto pgdat2;

	return pgdat;

pgdat2:
	if (LKCD_KERNTYPES()) {
		if (!kernel_symbol_exists("pgdat_list"))
			goto pgdat3;
	} else {
		if (get_symbol_type("pgdat_list",NULL,NULL) != TYPE_CODE_ARRAY)
			goto pgdat3;

	        open_tmpfile();
	        sprintf(buf, "whatis pgdat_list");
	        if (!gdb_pass_through(buf, fp, GNU_RETURN_ON_ERROR)) {
	                close_tmpfile();
			goto pgdat3;
	        }
	        rewind(pc->tmpfile);
	        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
	                if (STRNEQ(buf, "type = "))
	                        break;
	        }
	        close_tmpfile();

		if ((!strstr(buf, "struct pglist_data *") &&
		     !strstr(buf, "pg_data_t *")) ||
		    (count_chars(buf, '[') != 1) ||
		    (count_chars(buf, ']') != 1))
			goto pgdat3;
	}

	if (!readmem(symbol_value("pgdat_list") + (node * sizeof(void *)), 
	    KVADDR, &pgdat, sizeof(void *), "pgdat_list", RETURN_ON_ERROR) ||
	    !IS_KVADDR(pgdat))
		goto pgdat3;

	return pgdat;

pgdat3:
	if (symbol_exists("contig_page_data") && (node == 0))
		return symbol_value("contig_page_data");

	return 0;
}

/*
 *  Make the vm_stat[] array contents easily accessible.
 */
static int
vm_stat_init(void)
{
        char buf[BUFSIZE];
        char *arglist[MAXARGS];
	int i, c, stringlen, total;
        struct gnu_request *req;
	char *start;

	if (vt->flags & VM_STAT)
		return TRUE;

	if ((vt->nr_vm_stat_items == -1) || !symbol_exists("vm_stat"))
		goto bailout;

        /*
         *  look for type: type = atomic_long_t []
         */
	if (LKCD_KERNTYPES()) {
        	if (!symbol_exists("vm_stat"))
			goto bailout;
		/* 
		 *  Just assume that vm_stat is an array; there is
		 *  no symbol info in a kerntypes file. 
		 */
	} else {
		if (!symbol_exists("vm_stat") ||
		    get_symbol_type("vm_stat", NULL, NULL) != TYPE_CODE_ARRAY)
			goto bailout;

	        open_tmpfile();
	        sprintf(buf, "whatis vm_stat");
	        if (!gdb_pass_through(buf, fp, GNU_RETURN_ON_ERROR)) {
	                close_tmpfile();
			goto bailout;
	        }
	        rewind(pc->tmpfile);
	        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
	                if (STRNEQ(buf, "type = "))
	                        break;
	        }
	        close_tmpfile();

	        if (!strstr(buf, "atomic_long_t") ||
	            (count_chars(buf, '[') != 1) ||
	            (count_chars(buf, ']') != 1))
	                goto bailout;
	}

        open_tmpfile();
        req = (struct gnu_request *)GETBUF(sizeof(struct gnu_request));
        req->command = GNU_GET_DATATYPE;
        req->name = "zone_stat_item";
        req->flags = GNU_PRINT_ENUMERATORS;
        gdb_interface(req);
        FREEBUF(req);

	stringlen = 1;

        rewind(pc->tmpfile);
        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
		if (strstr(buf, "{") || strstr(buf, "}"))
			continue;
		clean_line(buf);
		c = parse_line(buf, arglist);
		if (STREQ(arglist[0], "NR_VM_ZONE_STAT_ITEMS")) {
			vt->nr_vm_stat_items = atoi(arglist[2]);
			break;
		} else
			stringlen += strlen(arglist[0]);
        }

	total = stringlen + vt->nr_vm_stat_items + 
		(sizeof(void *) * vt->nr_vm_stat_items);
        if (!(vt->vm_stat_items = (char **)malloc(total))) {
		close_tmpfile();
                error(FATAL, "cannot malloc vm_area_struct cache\n");
	}

	start = (char *)&vt->vm_stat_items[vt->nr_vm_stat_items];

        rewind(pc->tmpfile);
        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
                if (strstr(buf, "{") || strstr(buf, "}"))
                        continue;
		c = parse_line(buf, arglist);
		i = atoi(arglist[2]);
		if (i < vt->nr_vm_stat_items) {
			vt->vm_stat_items[i] = start;
			strcpy(start, arglist[0]);
			start += strlen(arglist[0]) + 1;
		}
        }
	close_tmpfile();

	vt->flags |= VM_STAT;
	return TRUE;

bailout:
	vt->nr_vm_stat_items = -1;
	return FALSE;
}

/*
 *  Either dump all vm_stat entries, or return the value of
 *  the specified vm_stat item.
 */
static int
dump_vm_stat(char *item, long *retval)
{
	char *buf;
	ulong *vp;
	int i;

	if (!vm_stat_init()) {
		if (!item)
			error(FATAL, 
			    "vm_stat not available in this kernel\n");
		return FALSE;
	}

	buf = GETBUF(sizeof(ulong) * vt->nr_vm_stat_items);

	readmem(symbol_value("vm_stat"), KVADDR, buf, 
	    sizeof(ulong) * vt->nr_vm_stat_items, 
	    "vm_stat", FAULT_ON_ERROR);


	if (!item) {
		vp = (ulong *)buf;
		for (i = 0; i < vt->nr_vm_stat_items; i++)
			fprintf(fp, "%20s: %ld\n", vt->vm_stat_items[i], vp[i]);
		return TRUE;
	}

	vp = (ulong *)buf;
	for (i = 0; i < vt->nr_vm_stat_items; i++) {
		if (STREQ(vt->vm_stat_items[i], item)) {
			*retval = vp[i];
			return TRUE;
		}
	}

	return FALSE;
}
