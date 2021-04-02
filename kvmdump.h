/* 
 * kvmdump.h
 *
 * Copyright (C) 2009, 2010 David Anderson
 * Copyright (C) 2009, 2010 Red Hat, Inc. All rights reserved.
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

struct mapinfo_trailer {
	uint64_t map_start_offset;
	uint64_t phys_base;
	uint32_t cpu_version_id;
	uint32_t ram_version_id;
	uint64_t checksum;
	uint64_t magic;
};

#define MAPFILE_MAGIC (0xfeedbabedeadbeefULL)
#define CHKSUM_SIZE   (4096)

#define KVMDUMP_CACHED_PAGES 32

struct kvmdump_data {
	ulong flags;
	FILE *ofp;
	FILE *vmp;
	int mapfd;
	int vmfd;
	struct mapinfo_trailer mapinfo;
        /* page cache */
        struct kvm_page_cache_hdr {
                uint64_t paddr;
               	char *bufptr;
        } page_cache[KVMDUMP_CACHED_PAGES];
	union {
		char *curbufptr;
		unsigned char compressed;
	} un;
        int evict_index;    
	ulong accesses;
	ulong hit_count;
	ulong compresses;
	uint64_t kvbase;
	ulong *debug;
};

#define TMPFILE           (0x2)
#define MAPFILE           (0x4)
#define MAPFILE_FOUND     (0x8)
#define MAPFILE_APPENDED (0x10)

extern struct kvmdump_data *kvm;

#undef dprintf
#define dprintf(x...)   do { if (*(kvm->debug)) fprintf(kvm->ofp, x); } while (0)

int store_mapfile_offset(uint64_t, off_t *);
int load_mapfile_offset(uint64_t, off_t *);
