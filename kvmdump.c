/*
 * kvmdump.c
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

#include "defs.h"
#include "kvmdump.h"

static struct kvmdump_data kvmdump_data = { 0 };  
struct kvmdump_data *kvm = &kvmdump_data;
static int cache_page(physaddr_t);
static int kvmdump_mapfile_exists(void);
static off_t mapfile_offset(uint64_t);
static void kvmdump_mapfile_create(char *);
static void kvmdump_mapfile_append(void);
static char *mapfile_in_use(void);
static void write_mapfile_trailer(void);
static void read_mapfile_trailer(void);

#define RAM_OFFSET_COMPRESSED (~(off_t)255)
#define QEMU_COMPRESSED       ((WRITE_ERROR)-1)
#define CACHE_UNUSED          (1ULL)

int 
is_kvmdump(char *filename)
{
	int i;
	ulong *ptr;
	off_t eof;
	ulonglong csum;
	struct mapinfo_trailer trailer;
	char buf[CHKSUM_SIZE];

	if (!is_qemu_vm_file(filename))
		return FALSE;

	if (lseek(kvm->vmfd, 0, SEEK_SET) < 0) {
		error(INFO, "%s: read: %s\n", filename, strerror(errno));
		return FALSE;
	}
	if (read(kvm->vmfd, buf, CHKSUM_SIZE) != CHKSUM_SIZE) {
		error(INFO, "%s: read: %s\n", filename, strerror(errno));
		return FALSE;
        }

	ptr = (ulong *)&buf[0];	
	for (i = csum = 0; i < (CHKSUM_SIZE/sizeof(ulong)); i++, ptr++)
		csum += *ptr;

	eof = lseek(kvm->vmfd, 0, SEEK_END);
	if (lseek(kvm->vmfd, eof - sizeof(trailer), SEEK_SET) < 0) {
		error(INFO, "%s: lseek: %s\n", filename, strerror(errno));
		return FALSE;
	} 
	if (read(kvm->vmfd, &trailer, sizeof(trailer)) != sizeof(trailer)) {
		error(INFO, "%s: read: %s\n", filename, strerror(errno));
		return FALSE;
	}
	if (trailer.magic == MAPFILE_MAGIC) {
		kvm->mapinfo.map_start_offset = trailer.map_start_offset;
		kvm->flags |= MAPFILE_APPENDED;
	}

	kvm->mapinfo.checksum = csum;

	return TRUE;
}

int 
kvmdump_init(char *filename, FILE *fptr)
{
	int i, page_size;
        struct command_table_entry *cp;
	char *cachebuf;
	FILE *tmpfp;

	if (!machine_type("X86") && !machine_type("X86_64")) {
		error(FATAL, "invalid host architecture for KVM: %s\n",
			MACHINE_TYPE);
		return FALSE;
	}

	kvm->ofp = fptr;
	kvm->debug = &pc->debug;
	page_size = memory_page_size();

#ifdef X86_64
	kvm->kvbase = __START_KERNEL_map;
#endif

	switch (kvm->flags & (TMPFILE|MAPFILE|MAPFILE_APPENDED))
	{
	case MAPFILE_APPENDED:
		kvm->mapfd = kvm->vmfd;
		break;

	case MAPFILE|MAPFILE_APPENDED:
	case MAPFILE:
		break;

	default:
		if (kvmdump_mapfile_exists())
			break;

		if ((tmpfp = tmpfile()) == NULL) 
			error(FATAL, 
			    "cannot create tmpfile for KVM file offsets: %s\n", 
				strerror(errno));

		kvm->mapfd = fileno(tmpfp);
		kvm->flags |= TMPFILE;
		break;
	}

        if ((cachebuf = calloc(1, KVMDUMP_CACHED_PAGES * page_size)) == NULL)
                error(FATAL, "%s: cannot malloc KVM page_cache_buf\n");

	for (i = 0; i < KVMDUMP_CACHED_PAGES; i++) {
		kvm->page_cache[i].paddr = CACHE_UNUSED;
		kvm->page_cache[i].bufptr = cachebuf + (i * page_size);
	}

	if (qemu_init(filename)) {
		switch (kvm->flags & (TMPFILE|MAPFILE|MAPFILE_APPENDED))
		{
		case TMPFILE:
			write_mapfile_trailer();
			break;

		case MAPFILE:
		case MAPFILE_APPENDED:
		case MAPFILE|MAPFILE_APPENDED:
			read_mapfile_trailer();
			break;
		}

		for (cp = pc->cmd_table; cp->name; cp++) {
			if (STREQ(cp->name, "map")) {
				cp->flags &= ~HIDDEN_COMMAND;
				break;
			}
		}

		kvm->flags |= KVMDUMP_LOCAL; 
		return TRUE;
	} else
		return FALSE;
}

int 
read_kvmdump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	switch (cache_page(PHYSPAGEBASE(paddr)))
	{
	case READ_ERROR:
		return READ_ERROR;

	case SEEK_ERROR:
		return SEEK_ERROR;

	case QEMU_COMPRESSED:
		memset(bufptr, kvm->un.compressed, cnt);
		break;

	default:
		memcpy(bufptr, kvm->un.curbufptr + PAGEOFFSET(paddr), cnt);
		break;
	}

	return cnt;
}


int 
write_kvmdump(int fd, void *bufptr, int cnt, ulong addr, physaddr_t paddr)
{
	return SEEK_ERROR;
}

/*
 *  kvmdump_free_memory(), and kvmdump_memory_used()
 *  are debug only, and typically unnecessary to implement.
 */
int 
kvmdump_free_memory(void)
{
	return 0;
}

int 
kvmdump_memory_used(void)
{
	return 0;
}

/*
 *  This function is dump-type independent, used here to
 *  to dump the kvmdump_data structure contents.
 */
int 
kvmdump_memory_dump(FILE *ofp)
{
	int i, others;
	struct mapinfo_trailer trailer;
	off_t eof;

	fprintf(ofp, "            flags: %lx (", kvm->flags);
	others = 0;
	if (kvm->flags & KVMDUMP_LOCAL)
		fprintf(ofp, "%sKVMDUMP_LOCAL", others++ ? "|" : "");
	if (kvm->flags & TMPFILE)
		fprintf(ofp, "%sTMPFILE", others++ ? "|" : "");
	if (kvm->flags & MAPFILE)
		fprintf(ofp, "%sMAPFILE", others++ ? "|" : "");
	if (kvm->flags & MAPFILE_FOUND)
		fprintf(ofp, "%sMAPFILE_FOUND", others++ ? "|" : "");
	if (kvm->flags & MAPFILE_APPENDED)
		fprintf(ofp, "%sMAPFILE_APPENDED", others++ ? "|" : "");
	fprintf(ofp, ")\n");

	fprintf(ofp, "            mapfd: %d\n", kvm->mapfd);
	fprintf(ofp, "             vmfd: %d\n", kvm->vmfd);
	fprintf(ofp, "              vmp: %lx (fd: %d)\n", (ulong)kvm->vmp, 
		fileno(kvm->vmp));
	fprintf(ofp, "              ofp: %lx\n", (ulong)kvm->ofp);
	fprintf(ofp, "            debug: %lx\n", (ulong)kvm->debug);
	if (machine_type("X86_64"))
        	fprintf(ofp, "           kvbase: %llx\n", (ulonglong)kvm->kvbase);
	else
        	fprintf(ofp, "           kvbase: (unused)\n");
	fprintf(ofp, "          mapinfo:\n");
        fprintf(ofp, "              magic: %llx %s\n", (ulonglong)kvm->mapinfo.magic,
		kvm->mapinfo.magic == MAPFILE_MAGIC ?  "(MAPFILE_MAGIC)" : "");
        fprintf(ofp, "          phys_base: %llx %s\n", (ulonglong)kvm->mapinfo.phys_base,
		machine_type("X86") ? "(unused)" : "");
        fprintf(ofp, "     cpu_version_id: %ld\n", (ulong)kvm->mapinfo.cpu_version_id);
        fprintf(ofp, "     ram_version_id: %ld\n", (ulong)kvm->mapinfo.ram_version_id);
        fprintf(ofp, "   map_start_offset: %llx\n", (ulonglong)kvm->mapinfo.map_start_offset);
        fprintf(ofp, "           checksum: %llx\n", (ulonglong)kvm->mapinfo.checksum);

	fprintf(ofp, "        curbufptr: %lx\n", (ulong)kvm->un.curbufptr);
	fprintf(ofp, "      evict_index: %d\n", kvm->evict_index);
	fprintf(ofp, "         accesses: %ld\n", kvm->accesses);
	fprintf(ofp, "        hit_count: %ld ", kvm->hit_count);
	if (kvm->accesses)
		fprintf(ofp, "(%ld%%)\n",
			kvm->hit_count * 100 / kvm->accesses);
	else
		fprintf(ofp, "\n");
	fprintf(ofp, "       compresses: %ld ", kvm->compresses);
	if (kvm->accesses)
		fprintf(ofp, "(%ld%%)\n",
			kvm->compresses * 100 / kvm->accesses);
	else
		fprintf(ofp, "\n");

	for (i = 0; i < KVMDUMP_CACHED_PAGES; i++) {
		if (kvm->page_cache[i].paddr == CACHE_UNUSED)
			fprintf(ofp, "   %spage_cache[%d]: CACHE_UNUSED\n", 
				i < 10 ? " " : "", i);
		else
			fprintf(ofp, 
			    "   %spage_cache[%d]: bufptr: %lx  addr: %llx\n",
				i < 10 ? " " : "", i,
				(ulong)kvm->page_cache[i].bufptr,
				(ulonglong)kvm->page_cache[i].paddr);
	}

	fprintf(ofp, "\n");
	fflush(ofp);

	dump_qemu_header(ofp);

	fprintf(ofp, "\n%s: mapinfo trailer:\n\n", mapfile_in_use());

	eof = lseek(kvm->mapfd, 0, SEEK_END);
	if (lseek(kvm->mapfd, eof - sizeof(trailer), SEEK_SET) < 0)
		error(FATAL, "%s: lseek: %s\n", mapfile_in_use(), 
			strerror(errno));
	if (read(kvm->mapfd, &trailer, sizeof(trailer)) != sizeof(trailer))
		error(FATAL, "%s: read: %s\n", mapfile_in_use(), 
			strerror(errno));

	fprintf(ofp, "             magic: %llx %s\n", (ulonglong)trailer.magic,
		trailer.magic == MAPFILE_MAGIC ? "(MAPFILE_MAGIC)" : "");
	fprintf(ofp, "         phys_base: %llx %s\n", (ulonglong)trailer.phys_base,
		machine_type("X86") ? "(unused)" : "");
	fprintf(ofp, "    cpu_version_id: %ld\n", (ulong)trailer.cpu_version_id);
	fprintf(ofp, "    ram_version_id: %ld\n", (ulong)trailer.ram_version_id);
        fprintf(ofp, "  map_start_offset: %llx\n", (ulonglong)trailer.map_start_offset);
	fprintf(ofp, "          checksum: %llx\n\n", (ulonglong)trailer.checksum);

	return TRUE;
}

void 
get_kvmdump_regs(struct bt_info *bt, ulong *pc, ulong *sp)
{
	machdep->get_stack_frame(bt, pc, sp);
}

ulong
get_kvmdump_panic_task(void)
{
	return NO_TASK;
}

int
kvmdump_phys_base(unsigned long *phys_base)
{
        if (KVMDUMP_VALID()) {
		if (CRASHDEBUG(1) && (kvm->mapinfo.cpu_version_id > 9)) 
			error(NOTE, 
			    "KVM/QEMU CPU_SAVE_VERSION %d is greater than"
			    " supported version 9\n\n",
				kvm->mapinfo.cpu_version_id);

                *phys_base = kvm->mapinfo.phys_base;
                return TRUE;
        }

        return FALSE;
}

static int
cache_page(physaddr_t paddr)
{
	int idx, err;
	struct kvm_page_cache_hdr *pgc;
	size_t page_size;
	off_t offset;

	kvm->accesses++;

	for (idx = 0; idx < KVMDUMP_CACHED_PAGES; idx++) {
		pgc = &kvm->page_cache[idx];

		if (pgc->paddr == CACHE_UNUSED)
			continue;

		if (pgc->paddr == paddr) {
			kvm->hit_count++;
			kvm->un.curbufptr = pgc->bufptr;
			return idx;
		}
	}

	if ((err = load_mapfile_offset(paddr, &offset)) < 0)
		return err;

        if ((offset & RAM_OFFSET_COMPRESSED) == RAM_OFFSET_COMPRESSED) {
                kvm->un.compressed = (unsigned char)(offset & 255);
		kvm->compresses++;
		return QEMU_COMPRESSED;
	}

	idx = kvm->evict_index;
	pgc = &kvm->page_cache[idx];
        page_size = memory_page_size();

	if (lseek(kvm->vmfd, offset, SEEK_SET) < 0) {
		pgc->paddr = CACHE_UNUSED;
		return SEEK_ERROR;
	}
	if (read(kvm->vmfd, pgc->bufptr, page_size) != page_size) {
		pgc->paddr = CACHE_UNUSED;
		return READ_ERROR;
	}

	kvm->evict_index = (idx+1) % KVMDUMP_CACHED_PAGES;

	pgc->paddr = paddr;
	kvm->un.curbufptr = pgc->bufptr;

	return idx;
}

static off_t 
mapfile_offset(uint64_t physaddr)
{
	off_t offset = 0;

	switch (kvm->flags & (TMPFILE|MAPFILE|MAPFILE_APPENDED))
	{
	case TMPFILE:
	case TMPFILE|MAPFILE_APPENDED:
	case MAPFILE:
	case MAPFILE|MAPFILE_APPENDED:
		offset = (off_t)(((((uint64_t)physaddr/(uint64_t)4096)) 
			* sizeof(off_t))); 
		break;
	
	case MAPFILE_APPENDED:
		offset = (off_t)(((((uint64_t)physaddr/(uint64_t)4096)) 
			* sizeof(off_t)) + kvm->mapinfo.map_start_offset); 
                break;
	}

	return offset;
}

int 
store_mapfile_offset(uint64_t physaddr, off_t *entry_ptr)
{
        if (lseek(kvm->mapfd, mapfile_offset(physaddr), SEEK_SET) < 0) {
		error(INFO, "%s: lseek: %s\n", 
			mapfile_in_use(), strerror(errno));
		return SEEK_ERROR;
	}

        if (write(kvm->mapfd, entry_ptr, sizeof(off_t)) != sizeof(off_t)) {
		error(INFO, "%s: write: %s\n", 
			mapfile_in_use(), strerror(errno));
		return WRITE_ERROR;
	}
	
	return 0;
}

int 
load_mapfile_offset(uint64_t physaddr, off_t *entry_ptr)
{
        if (lseek(kvm->mapfd, mapfile_offset(physaddr), SEEK_SET) < 0) {
		error(INFO, "load_memfile_offset: lseek: %s\n", 
			strerror(errno));
		return SEEK_ERROR;
	}

        if (read(kvm->mapfd, entry_ptr, sizeof(off_t)) != sizeof(off_t)) {
		error(INFO, "load_memfile_offset: read: %s\n", strerror(errno));
		return READ_ERROR;
	}

	return 0;
}

static void
kvmdump_mapfile_create(char *filename)
{
	int fdmem, n;
	off_t offset;
	char buf[4096];

	if (kvm->flags & MAPFILE) {
		error(INFO, "%s: mapfile in use\n", pc->kvmdump_mapfile);
		return;
	}

	if (file_exists(filename, NULL)) {
		error(INFO, 
		    "%s: file already exists!\n", filename);
		return;
	}

	if ((fdmem = open(filename, O_CREAT|O_RDWR, 0644)) < 0) {
		error(INFO, "%s: open: %s\n", filename, strerror(errno));
		return;
	}

	offset = kvm->mapinfo.map_start_offset;

	if (lseek(kvm->mapfd, offset, SEEK_SET) < 0) {
		error(INFO, "%s: leek: %s\n", 
			mapfile_in_use(), strerror(errno));
		return;
	}

	while ((n = read(kvm->mapfd, buf, 4096)) > 0) {
		if (write(fdmem, buf, n) != n) {
			error(INFO, "%s: write: %s\n", filename, 
				strerror(errno));
			break;
		}
	}

	close(fdmem);

	fprintf(fp, "MAP FILE CREATED: %s\n", filename);
}

static void
kvmdump_mapfile_append(void)
{
	int n, fdcore; 
	ulong round_bytes;
	struct stat statbuf;
	uint64_t map_start_offset;
	off_t eof, orig_dumpfile_size;
	char buf[4096];

	if (kvm->flags & MAPFILE_APPENDED)
		error(FATAL, "mapfile already appended to %s\n",
			pc->dumpfile);

	if (access(pc->dumpfile, W_OK) != 0)
		error(FATAL, 
		    "%s: cannot append map information to this file\n",
			pc->dumpfile);

	if (stat(pc->dumpfile, &statbuf) < 0)
		error(FATAL, "%s: stat: %s\n",
			pc->dumpfile, strerror(errno));

	round_bytes = (sizeof(uint64_t) - (statbuf.st_size % sizeof(uint64_t)))
		% sizeof(uint64_t);

	if ((fdcore = open(pc->dumpfile, O_WRONLY)) < 0)
		error(FATAL, "%s: open: %s\n", 
			pc->dumpfile, strerror(errno));

	if ((orig_dumpfile_size = lseek(fdcore, 0, SEEK_END)) < 0) {
		error(INFO, "%s: lseek: %s\n", pc->dumpfile, strerror(errno));
		goto bailout1;
	}

	if (round_bytes) {
		BZERO(buf, round_bytes);

		if (write(fdcore, buf, round_bytes) != round_bytes) {
			error(INFO, "%s: write: %s\n", 
				pc->dumpfile, strerror(errno));
			goto bailout2;
		}

	}

	map_start_offset = orig_dumpfile_size + round_bytes;

	if (lseek(kvm->mapfd, 0, SEEK_SET) != 0) {
		error(INFO, "%s: lseek: %s\n", 
			mapfile_in_use(), strerror(errno));
		goto bailout2;
	}

	while ((n = read(kvm->mapfd, buf, 4096)) > 0) {
		if (write(fdcore, buf, n) != n) {
			error(INFO, "%s: write: %s\n", pc->dumpfile, 
				strerror(errno));
			goto bailout2;
		}
	}

	/*
	 *  Overwrite the map_start_offset value in the trailer to reflect
	 *  its location in the appended-to dumpfile.
	 */
        eof = lseek(fdcore, 0, SEEK_END);
        if (lseek(fdcore, eof - sizeof(struct mapinfo_trailer), SEEK_SET) < 0) {
		error(INFO, "%s: write: %s\n", pc->dumpfile, strerror(errno));
		goto bailout2;
	}
	if (write(fdcore, &map_start_offset, sizeof(uint64_t)) != sizeof(uint64_t)) { 
		error(INFO, "%s: write: %s\n", pc->dumpfile, strerror(errno));
		goto bailout2;
	}

	close(fdcore);

	kvm->flags |= MAPFILE_APPENDED;
	fprintf(fp, "MAP FILE APPENDED TO: %s\n", pc->dumpfile);

	return;

bailout2:
	if (ftruncate(fdcore, (off_t)orig_dumpfile_size) < 0)
		error(INFO, "%s: ftruncate: %s\n", 
			pc->dumpfile, strerror(errno));
bailout1:
	close(fdcore);
	error(INFO, "failed to append map to %s\n", pc->dumpfile);
}

int 
is_kvmdump_mapfile(char *filename)
{
	int fd;
	struct mapinfo_trailer trailer;
	off_t eof;

        if ((fd = open(filename, O_RDONLY)) < 0) {
                error(INFO, "%s: open: %s\n", filename, strerror(errno));
                return FALSE;
        }

	eof = lseek(fd, 0, SEEK_END);
	if (lseek(fd, eof - sizeof(trailer), SEEK_SET) < 0) {
                error(INFO, "%s: lseek: %s\n", filename, strerror(errno));
		goto bailout;
	}

        if (read(fd, &trailer, sizeof(trailer)) != sizeof(trailer)) {
                error(INFO, "%s: read: %s\n", filename, strerror(errno));
		goto bailout;
        }

	if (trailer.magic == MAPFILE_MAGIC) {
		if (pc->dumpfile && (trailer.checksum != kvm->mapinfo.checksum)) {
			error(kvm->flags & MAPFILE_FOUND ? INFO : FATAL,
			    "checksum mismatch between %s and %s\n\n",
				pc->dumpfile, filename);
			goto bailout;
		}
		kvm->mapfd = fd;
		kvm->flags |= MAPFILE;
		return TRUE;
	} 

bailout:
	close(fd);
	return FALSE;
}

static int
kvmdump_mapfile_exists(void)
{
	char *filename;
	struct stat stat;

	if (!(filename = malloc(strlen(pc->dumpfile) + strlen(".map") + 10))) 
		return FALSE;

	sprintf(filename, "%s.map", pc->dumpfile);

	if (!file_exists(filename, &stat) || !S_ISREG(stat.st_mode))
		return FALSE;

	if (is_kvmdump_mapfile(filename)) {
		pc->kvmdump_mapfile = filename;
		kvm->flags |= MAPFILE_FOUND;
		return TRUE;
	}

	free(filename);
	return FALSE;
}

void
cmd_map(void)
{
	int c;
	int append, file, specified;
	char *mapfile;

	append = file = specified = 0;
	mapfile = NULL;

        while ((c = getopt(argcnt, args, "af")) != EOF) {
                switch(c)
		{
		case 'a':
			append++;
			break;
		case 'f':
			file++;
			break;
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

        while (args[optind]) {
		if (!mapfile) {
			mapfile = args[optind];	
			specified++;
		} else
			cmd_usage(pc->curcmd, SYNOPSIS);
		optind++;
	}

	if (file && !specified) {
		mapfile = GETBUF(strlen(pc->dumpfile)+10);
		sprintf(mapfile, "%s.map", pc->dumpfile);
	}

	if (append)
		kvmdump_mapfile_append();

	if (file) {
		kvmdump_mapfile_create(mapfile);
		if (!specified)
			FREEBUF(mapfile);
	}

	if (!file && !append)
		fprintf(fp, "MAP FILE IN USE: %s\n", mapfile_in_use());
}

static char *
mapfile_in_use(void)
{
	char *name;

	switch (kvm->flags & (TMPFILE|MAPFILE|MAPFILE_APPENDED))
	{
	default:
	case TMPFILE:
	case TMPFILE|MAPFILE_APPENDED:
		name = "(tmpfile)";
		break;
	case MAPFILE:
	case MAPFILE|MAPFILE_APPENDED:
		name = pc->kvmdump_mapfile;
		break;
	case MAPFILE_APPENDED:
		name = pc->dumpfile;
		break;
	}

	return name;
}

static void
write_mapfile_trailer(void)
{
        kvm->mapinfo.magic = MAPFILE_MAGIC;

        if (lseek(kvm->mapfd, 0, SEEK_END) < 0)
		error(FATAL, "%s: lseek: %s\n", mapfile_in_use(), strerror(errno));

	if (write(kvm->mapfd, &kvm->mapinfo, sizeof(struct mapinfo_trailer)) 
	    != sizeof(struct mapinfo_trailer))
		error(FATAL, "%s: write: %s\n", mapfile_in_use(), strerror(errno));
}

static void
read_mapfile_trailer(void)
{
	off_t eof;
	struct mapinfo_trailer trailer;

	if ((eof = lseek(kvm->mapfd, 0, SEEK_END)) < 0)
		error(FATAL, "%s: lseek: %s\n", 
			mapfile_in_use(), strerror(errno));

	if (lseek(kvm->mapfd, eof - sizeof(trailer), SEEK_SET) < 0)
		error(FATAL, "%s: lseek: %s\n", 
			mapfile_in_use(), strerror(errno));

	if (read(kvm->mapfd, &trailer, sizeof(trailer)) != sizeof(trailer))
		error(FATAL, "%s: read: %s\n", 
			mapfile_in_use(), strerror(errno));

	if (kvm->mapinfo.checksum != trailer.checksum)
		error(FATAL, "checksum mismatch between %s and %s\n",
			pc->dumpfile, mapfile_in_use());

	kvm->mapinfo = trailer;
}
