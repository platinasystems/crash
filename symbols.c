/* symbols.c - core analysis suite
 *
 * Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
 * Copyright (C) 2002, 2003, 2004, 2005, 2006 David Anderson
 * Copyright (C) 2002, 2003, 2004, 2005, 2006 Red Hat, Inc. All rights reserved.
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
#include <elf.h>
#include "bfd.h"

static void store_symbols(bfd *, int, void *, long, unsigned int);
static void store_sysmap_symbols(void);
static void strip_module_symbol_end(char *s);
static int compare_syms(const void *, const void *);
static int compare_mods(const void *, const void *);
static int compare_prios(const void *v1, const void *v2);
static asection *get_kernel_section(char *);
static char * get_section(ulong vaddr, char *buf);
static void symbol_dump(ulong, char *);
static void check_for_dups(struct load_module *);
static int symbol_name_count(char *);
static struct syment *symbol_search_next(char *, struct syment *);
static void store_load_module_symbols \
	(bfd *, int, void *, long, uint, ulong, char *);
static int load_module_index(struct syment *);
static void section_header_info(bfd *, asection *, void *);
static void store_section_data(struct load_module *, bfd *, asection *);
static void calculate_load_order(struct load_module *, bfd *);
static void check_insmod_builtin(struct load_module *, int, ulong *);
static int is_insmod_builtin(struct load_module *, struct syment *);
struct load_module;
static int add_symbol_file(struct load_module *lm);
static void find_mod_etext(struct load_module *); 
static long rodata_search(ulong *, ulong);
static int ascii_long(ulong word);
static int is_bfd_format(char *); 
static int namespace_ctl(int, struct namespace *, void *, void *);
static void symval_hash_init(void);
static struct syment *symval_hash_search(ulong);
static void symname_hash_init(void);
static void symname_hash_install(struct syment *);
static struct syment *symname_hash_search(char *);
static void gnu_qsort(bfd *, void *, long, unsigned int, asymbol *, asymbol *);
static int check_gnu_debuglink(bfd *);
static int separate_debug_file_exists(const char *, unsigned long, int *);
static int store_module_kallsyms_v1(struct load_module *, int, int, char *);
static int store_module_kallsyms_v2(struct load_module *, int, int, char *);
static void datatype_error(ulong *, char *, char *, char *, int);
static char *get_thisfile(void);
struct elf_common;
static void Elf32_Sym_to_common(Elf32_Sym *, struct elf_common *); 
static void Elf64_Sym_to_common(Elf64_Sym *, struct elf_common *); 


#define KERNEL_SECTIONS  (void *)(1)
#define MODULE_SECTIONS  (void *)(2) 
#define VERIFY_SECTIONS  (void *)(3)

#define PARSE_FOR_DATA        (1)
#define PARSE_FOR_DECLARATION (2)
static void parse_for_member(struct datatype_member *, ulong);
static int show_member_offset(FILE *, struct datatype_member *, char *);


/*
 *  structure/union printing stuff
 */

#define UINT8              (0x1)
#define INT8               (0x2)
#define UINT16             (0x4)
#define INT16              (0x8)
#define UINT32            (0x10)
#define INT32             (0x20)
#define UINT64            (0x40)
#define INT64             (0x80)
#define POINTER          (0x100)
#define FUNCTION         (0x200)
#define UNION_REQUEST    (0x400)
#define STRUCT_REQUEST   (0x800) 
#define ARRAY           (0x1000)
#define ENUM            (0x2000)
#define TYPEDEF         (0x4000)
#define STRUCT_VERBOSE  (0x8000)
#define SHOW_OFFSET    (0x10000)
#define IN_UNION       (0x20000)
#define IN_STRUCT      (0x40000)

#define INTEGER_TYPE    (UINT8|INT8|UINT16|INT16|UINT32|INT32|UINT64|INT64)

#define INITIAL_INDENT  (4)
#define INDENT_INCR     (2)

static int is_typedef(char *);
static void whatis_datatype(char *, ulong);
static void whatis_variable(struct syment *);
static void print_struct(char *, ulong);
static void print_union(char *, ulong);
static void dump_datatype_member(FILE *, struct datatype_member *);
static void dump_datatype_flags(ulong, FILE *);
static void dump_enumerator_list(char *);
static int gdb_whatis(char *);
static void do_datatype_declaration(struct datatype_member *, ulong);

#define DEBUGINFO_ERROR_MESSAGE1 \
"the use of a System.map file requires that the accompanying namelist\nargument is a kernel file built with the -g CFLAG.  The namelist argument\nsupplied in this case is a debuginfo file, which must be accompanied by the\nkernel file from which it was derived.\n"

#define DEBUGINFO_ERROR_MESSAGE2 \
"The namelist argument supplied in this case is a debuginfo file,\nwhich must be accompanied by the kernel file from which it was derived.\n"

/*
 *  This routine scours the namelist for kernel text and data symbols,
 *  sorts, and stores, them in a static table for quick reference.
 */
void
symtab_init(void)
{
	char **matching;
  	long symcount;
  	void *minisyms;
  	unsigned int size;
	asymbol *sort_x;
	asymbol *sort_y;

  	if ((st->bfd = bfd_openr(pc->namelist, NULL)) == NULL) 
		error(FATAL, "cannot open object file: %s\n", pc->namelist);

  	if (!bfd_check_format_matches(st->bfd, bfd_object, &matching))
		error(FATAL, "cannot determine object file format: %s\n",
			pc->namelist);

	if (pc->flags & SYSMAP) {
		bfd_map_over_sections(st->bfd, section_header_info, 
			VERIFY_SECTIONS);
		if ((st->flags & (NO_SEC_LOAD|NO_SEC_CONTENTS)) ==
		    (NO_SEC_LOAD|NO_SEC_CONTENTS)) {
			error(INFO, "%s: no text and data contents\n",
				pc->namelist);
			error(FATAL, pc->flags & SYSMAP_ARG ? 
				DEBUGINFO_ERROR_MESSAGE1 :
				DEBUGINFO_ERROR_MESSAGE2);
		}
		store_sysmap_symbols();
		return;
	} 

	/*
	 *  Pull a bait-and-switch on st->bfd if we've got a separate
         *  .gnu_debuglink file that matches the CRC.
	 */
	if (!(bfd_get_file_flags(st->bfd) & HAS_SYMS)) {
		if (!check_gnu_debuglink(st->bfd))
			no_debugging_data(FATAL);
	}
	
	symcount = bfd_read_minisymbols(st->bfd, FALSE, &minisyms, &size);

	if (symcount <= 0)
		no_debugging_data(FATAL);
	
	sort_x = bfd_make_empty_symbol(st->bfd);
	sort_y = bfd_make_empty_symbol(st->bfd);
	if (sort_x == NULL || sort_y == NULL)
		error(FATAL, "bfd_make_empty_symbol() failed\n");
	
	gnu_qsort(st->bfd, minisyms, symcount, size, sort_x, sort_y);
	
	store_symbols(st->bfd, FALSE, minisyms, symcount, size);
	
	free(minisyms);

	/*
	 *  Gather references to the kernel sections.
	 */
        if ((st->sections = (struct sec *)
             malloc(st->bfd->section_count * sizeof(struct sec *))) == NULL)
                error(FATAL, "symbol table section array malloc: %s\n",
                        strerror(errno));
	BZERO(st->sections, st->bfd->section_count * sizeof(struct sec *));

	bfd_map_over_sections(st->bfd, section_header_info, KERNEL_SECTIONS);
	if ((st->flags & (NO_SEC_LOAD|NO_SEC_CONTENTS)) ==
	    (NO_SEC_LOAD|NO_SEC_CONTENTS)) {
		if (!pc->namelist_debug && !pc->debuginfo_file) {
			error(INFO, "%s: no text and data contents\n",
				pc->namelist);
			error(FATAL, DEBUGINFO_ERROR_MESSAGE2);
		}
	}

	symname_hash_init();
	symval_hash_init();
}                           

/*
 *  Adapted from gdb's get_debug_link_info()
 *
 *  Look in: current directory
 *           basename-of-namelist/.debug directory
 *           /usr/lib/debug/boot (since we know it's a Red Hat kernel)
 */
static int
check_gnu_debuglink(bfd *bfd)
{
	int i, exists, found;
	asection *sect;
	bfd_size_type debuglink_size;
	char *contents;
	int crc_offset;	
	unsigned long crc32;
	char *dirname;
	char *filename;
	char *namelist_debug;
        char **matching;

        sect = bfd_get_section_by_name(bfd, ".gnu_debuglink");
	if (!sect) {
		error(INFO, "%s: no .gnu_debuglink section\n", pc->namelist);
		return FALSE;
	}

	debuglink_size = bfd_section_size(bfd, sect);

	contents = GETBUF(debuglink_size);

  	bfd_get_section_contents(bfd, sect, contents,
        	(file_ptr)0, (bfd_size_type)debuglink_size);

  	crc_offset = strlen (contents) + 1;
  	crc_offset = (crc_offset + 3) & ~3;

	crc32 = bfd_get_32(bfd, (bfd_byte *)(contents + crc_offset));

	if (CRASHDEBUG(1))
		error(NOTE, "gnu_debuglink file: %s\ncrc32: %lx\n",
			contents, crc32);

  	if ((pc->debuginfo_file = (char *)
	    malloc(((strlen(pc->namelist) + strlen("/.debug/") +
	    + strlen(".debug") + strlen(" /usr/lib/debug/boot/ "))*10)
	    + strlen(pc->namelist_debug ? pc->namelist_debug : " "))) == NULL)
		error(FATAL, "debuginfo file name malloc: %s\n", 
			strerror(errno));

	filename = basename(pc->namelist);
	dirname = GETBUF(strlen(pc->namelist)+1);
	strcpy(dirname, pc->namelist);

  	for (i = strlen(dirname)-1; i >= 0; i--)
    	{
      		if (dirname[i] == '/')
        		break;
    	}
  	dirname[i+1] = NULLCHAR;
	if (!strlen(dirname))
		sprintf(dirname, ".");

	namelist_debug = NULL;
	if (pc->namelist_debug) { 
		sprintf(pc->debuginfo_file, "%s", pc->namelist_debug);
		if (separate_debug_file_exists(pc->debuginfo_file, 
		    crc32, &exists)) {
			if (CRASHDEBUG(1)) 
				fprintf(fp, "%s: CRC matches\n", 
					pc->debuginfo_file);
			st->flags |= CRC_MATCHES;
			goto reset_bfd;
		} else {
			if ((st->flags & FORCE_DEBUGINFO) && exists) {
				error(WARNING, 
				   "%s:\n         CRC value does not match\n\n",
					pc->debuginfo_file);
				goto reset_bfd; 
			} else 
				error(INFO, "%s:\n       CRC value does not match\n\n",
					pc->debuginfo_file);
			namelist_debug = pc->namelist_debug;
			pc->namelist_debug = NULL;
		}
	}
		
	found = 0;
	sprintf(pc->debuginfo_file, "%s/%s", dirname, contents);
	if (separate_debug_file_exists(pc->debuginfo_file, crc32, &exists)) {
		if (CRASHDEBUG(1)) 
			fprintf(fp, "%s: CRC matches\n", pc->debuginfo_file);
		st->flags |= CRC_MATCHES;
		goto reset_bfd;
	} else {
		 if (CRASHDEBUG(1)) 
			fprintf(fp, "%s: %s\n", pc->debuginfo_file, exists ? 
				"CRC does not match" : "not readable/found");
		if (exists) {
			error(INFO, "%s: CRC does not match\n\n",
				pc->debuginfo_file);
			found++;
		}
	}

	sprintf(pc->debuginfo_file, "%s/.debug/%s", dirname, contents);
	if (separate_debug_file_exists(pc->debuginfo_file, crc32, &exists)) {
		if (CRASHDEBUG(1)) 
			fprintf(fp, "%s: CRC matches\n", pc->debuginfo_file);
		st->flags |= CRC_MATCHES;
		goto reset_bfd;
	} else {
		if (CRASHDEBUG(1)) 
                	fprintf(fp, "%s: %s\n", pc->debuginfo_file, exists ? 
				"CRC does not match" : "not readable/found"); 
		if (exists) {
			error(INFO, "%s: CRC does not match\n\n",
				pc->debuginfo_file);
			found++;
		}
	}

	sprintf(pc->debuginfo_file, "/usr/lib/debug/boot/%s", contents);
	if (separate_debug_file_exists(pc->debuginfo_file, crc32, &exists)) {
		if (CRASHDEBUG(1)) 
			fprintf(fp, "%s: CRC matches\n", pc->debuginfo_file);
		st->flags |= CRC_MATCHES;
		goto reset_bfd;
	} else {
		if (CRASHDEBUG(1))
                	fprintf(fp, "%s: %s\n", pc->debuginfo_file, exists ? 
				"CRC does not match" : "not readable/found");
		if (exists) {
			error(INFO, "%s: CRC does not match\n\n",
				pc->debuginfo_file);
			found++;
		}
	}

	if (!found && namelist_debug) {
		error(INFO, 
		    "%s:\n       use of -f option may suffice, or may fail miserably\n",
			namelist_debug);
	}

	if (!found && !namelist_debug) {
		no_debugging_data(INFO);
		error(INFO, "%s: debuginfo file not found\n", contents);
		error(FATAL, 
"either install the appropriate kernel debuginfo package, or\n       copy %s to this machine", contents);

	}

	return FALSE;

reset_bfd:

        if ((st->bfd = bfd_openr(pc->debuginfo_file, NULL)) == NULL)
                error(FATAL, "cannot open object file: %s\n", 
			pc->debuginfo_file);

        if (!bfd_check_format_matches(st->bfd, bfd_object, &matching))
                error(FATAL, "cannot determine object file format: %s\n",
                        pc->debuginfo_file);

	FREEBUF(contents);
	FREEBUF(dirname);

	return TRUE;
}

/*
 *  Based upon gdb's separate_debug_file_exists().
 */
static int
separate_debug_file_exists(const char *name, unsigned long crc, int *exists)
{
	unsigned long file_crc = 0;
  	int fd;
  	char buffer[8*1024];
  	size_t count;

  	fd = open(name, O_RDONLY);
  	if (fd < 0) {
		*exists = FALSE;
    		return 0;
	}

	*exists = TRUE;
  	while ((count = read(fd, buffer, sizeof(buffer))) > 0)
#if defined(GDB_5_3)
    		file_crc = calc_crc32(file_crc, buffer, count);
#elif defined(GDB_6_0) || defined(GDB_6_1)
    		file_crc = gnu_debuglink_crc32(file_crc, 
			(unsigned char *)buffer, count);
#else
		file_crc = 0xdeadbeef;  /* can't get here */
#endif

  	close (fd);

  	return crc == file_crc;
}

/*
 *  Callback for gdb to use a specified debug file.
 */
char *
check_specified_debug_file()
{
	return (pc->namelist_debug ? pc->namelist_debug : NULL);
}


/*
 *  Common bailout/warning routine when running against non-debug kernels.
 *
 *       INFO: used when this routine should return.
 *      FATAL: kills function if runtime, or kills program if during init.
 *    WARNING: called by gdb_session_init() only, in an attempt to at least
 *             get by with built-in debug data; if not possible the program
 *             is killed.
 */
void
no_debugging_data(int error_type)
{
	switch (error_type)
	{
	case INFO:
		error(INFO, "%s: no debugging data available\n", pc->namelist);
		break;

	case FATAL:
        	error(FATAL, "%s%s: no debugging data available\n",
			pc->flags & RUNTIME ? "" : "\n", pc->namelist);
		clean_exit(1);

	case WARNING:
                error(FATAL, "\n%s: no debugging data available\n",
                        pc->namelist);
		clean_exit(1);
	}
}

/*
 *  Get the address space formerly used as init-time text.  While there
 *  get the boundaries of the kernel .rodata section so that it won't
 *  be confused with text.
 *
 *  This is done indirectly by the call-back to section_header_info().
 */
void
get_text_init_space(void)
{
	asection *section;

	if (pc->flags & SYSMAP)
		return;

	if (((section = get_kernel_section(".text.init")) == NULL) &&
	    ((section = get_kernel_section(".init.text")) == NULL)) {
		error(WARNING, "cannot determine text init space\n");
		return;
	}

        kt->stext_init = (ulong)bfd_get_section_vma(st->bfd, section);
        kt->etext_init = kt->stext_init +
        	(ulong)bfd_section_size(st->bfd, section);
}

/*
 *  Store the symbols gathered by symtab_init().  The symbols are stored
 *  in increasing numerical order.
 */
static void
store_symbols(bfd *abfd, int dynamic, void *minisyms, long symcount, 
	      unsigned int size)
{
  	asymbol *store;
        asymbol *sym;
  	bfd_byte *from, *fromend;
        symbol_info syminfo;
	struct syment *sp;

  	if ((store = bfd_make_empty_symbol(abfd)) == NULL)
		error(FATAL, "bfd_make_empty_symbol() failed\n");

	if ((st->symtable = (struct syment *)
	     calloc(symcount, sizeof(struct syment))) == NULL)
		error(FATAL, "symbol table syment space malloc: %s\n",
			strerror(errno));

	if (!namespace_ctl(NAMESPACE_INIT, &st->namespace, 
	    (void *)symcount, NULL))
		error(FATAL, "symbol table namespace malloc: %s\n", 
			strerror(errno));

	st->syment_size = symcount * sizeof(struct syment);

	st->symcnt = 0;
	sp = st->symtable;

  	from = (bfd_byte *) minisyms;
  	fromend = from + symcount * size;
  	for (; from < fromend; from += size)
    	{
      		if ((sym = bfd_minisymbol_to_symbol(abfd, dynamic, from, store))
      		    == NULL)
			error(FATAL, "bfd_minisymbol_to_symbol() failed\n");

      		bfd_get_symbol_info(abfd, sym, &syminfo);
		if (machdep->verify_symbol(syminfo.name, syminfo.value, 
		    syminfo.type)) {
			sp->value = syminfo.value;
			sp->type = syminfo.type;
			namespace_ctl(NAMESPACE_INSTALL, &st->namespace,
				sp, (char *)syminfo.name); 
			sp++;
			st->symcnt++;
		}
    	}

	st->symend = &st->symtable[st->symcnt];

	st->flags |= KERNEL_SYMS;

	namespace_ctl(NAMESPACE_COMPLETE, &st->namespace, 
		st->symtable, st->symend);
}

/*
 *  Store the symbols from the designated System.map.  The symbols are stored
 *  in increasing numerical order.
 */
static void
store_sysmap_symbols(void)
{
	int c;
	long symcount;
	char buf[BUFSIZE];
	FILE *map;
        char *mapitems[MAXARGS];
	struct syment *sp, syment;

	if ((map = fopen(pc->system_map, "r")) == NULL) 
		error(FATAL, "cannot open %s\n", pc->system_map);

	symcount = 0;
	while (fgets(buf, BUFSIZE, map)) 
		symcount++;

        if ((st->symtable = (struct syment *)
             calloc(symcount, sizeof(struct syment))) == NULL)
                error(FATAL, "symbol table syment space malloc: %s\n",
                        strerror(errno));

        if (!namespace_ctl(NAMESPACE_INIT, &st->namespace,
            (void *)symcount, NULL))
                error(FATAL, "symbol table namespace malloc: %s\n",
                        strerror(errno));

        st->syment_size = symcount * sizeof(struct syment);
        st->symcnt = 0;
        sp = st->symtable;

	rewind(map);

	while (fgets(buf, BUFSIZE, map)) {
		if ((c = parse_line(buf, mapitems)) != 3)
			continue;

		syment.value = htol(mapitems[0], FAULT_ON_ERROR, NULL);
		syment.type = mapitems[1][0];
		syment.name = mapitems[2];

                if (machdep->verify_symbol(syment.name, syment.value, 
		    syment.type)) {
                        sp->value = syment.value;
                        sp->type = syment.type;
                        namespace_ctl(NAMESPACE_INSTALL, &st->namespace,
                                sp, syment.name);
                        sp++;
                        st->symcnt++;
                }
	}

	fclose(map);

        st->symend = &st->symtable[st->symcnt];

        st->flags |= KERNEL_SYMS;

        namespace_ctl(NAMESPACE_COMPLETE, &st->namespace,
                st->symtable, st->symend);

	symname_hash_init();
	symval_hash_init();
}

/*
 *  Install all static kernel symbol values into the symval_hash.
 */
static void
symval_hash_init(void)
{
	int index;
	struct syment *sp, *sph;

        for (sp = st->symtable; sp < st->symend; sp++) {
		index = SYMVAL_HASH_INDEX(sp->value);

		if (st->symval_hash[index].val_hash_head == NULL) {
			st->symval_hash[index].val_hash_head = sp;
			st->symval_hash[index].val_hash_last = sp;
			continue;
		}

		sph = st->symval_hash[index].val_hash_head; 
		while (sph->val_hash_next)
			sph = sph->val_hash_next;
				
		sph->val_hash_next = sp;
	}
}

/*
 *  Static kernel symbol value search
 */
static struct syment *
symval_hash_search(ulong value)
{
	int index;
	struct syment *sp, *splo;

	index = SYMVAL_HASH_INDEX(value);

	if (!st->symval_hash[index].val_hash_head) 
		return NULL;

	st->val_hash_searches += 1;
	st->val_hash_iterations += 1;

	if (st->symval_hash[index].val_hash_last->value <= value) 
		sp = st->symval_hash[index].val_hash_last;
	else
		sp = st->symval_hash[index].val_hash_head;

	for (splo = NULL; sp; sp = sp->val_hash_next) {
		if (sp->value == value) {
			st->symval_hash[index].val_hash_last = sp;
			return sp;
		}

		if (sp->value > value) 
			break;

		st->val_hash_iterations += 1;

		splo = sp;
	}

	if (splo) 
		st->symval_hash[index].val_hash_last = splo;

	return splo;
}

/*
 *  Store all kernel static symbols into the symname_hash.
 */
static void
symname_hash_init(void)
{
        struct syment *sp;

        for (sp = st->symtable; sp < st->symend; sp++) 
		symname_hash_install(sp);
}

/*
 *  Install a single static kernel symbol into the symname_hash.
 */
static void
symname_hash_install(struct syment *spn)
{
	struct syment *sp;
        int index;

        index = SYMNAME_HASH_INDEX(spn->name);
	spn->cnt = 1;

        if ((sp = st->symname_hash[index]) == NULL) 
        	st->symname_hash[index] = spn;
	else {
		while (sp) {
	        	if (STREQ(sp->name, spn->name)) {
	                	sp->cnt++;
	                	spn->cnt++;
	        	}
			if (sp->name_hash_next)
				sp = sp->name_hash_next;
			else {
				sp->name_hash_next = spn;
				break;
			}
		}
	}
}

/*
 *  Static kernel symbol value search
 */
static struct syment *
symname_hash_search(char *name)
{
	struct syment *sp;

        sp = st->symname_hash[SYMNAME_HASH_INDEX(name)];

	while (sp) {
		if (STREQ(sp->name, name)) 
			return sp;
		sp = sp->name_hash_next;
	}

        return NULL;
}

/*
 *  Output for sym -[lL] command.
 */

#define MODULE_PSEUDO_SYMBOL(sp) \
    (STRNEQ((sp)->name, "_MODULE_START_") || STRNEQ((sp)->name, "_MODULE_END_"))

#define MODULE_START(sp) (STRNEQ((sp)->name, "_MODULE_START_"))
#define MODULE_END(sp)   (STRNEQ((sp)->name, "_MODULE_END_"))

static void
symbol_dump(ulong flags, char *module)
{
	int i;
        struct syment *sp, *sp_end;
	struct load_module *lm;
	char *p1, *p2;;

	if (flags & KERNEL_SYMS) {
        	for (sp = st->symtable; sp < st->symend; sp++) 
			show_symbol(sp, 0, SHOW_RADIX());
	}

	if (!(flags & MODULE_SYMS))
		return;

	for (i = 0; i < st->mods_installed; i++) {

		lm = &st->load_modules[i];
		if (module && !STREQ(module, lm->mod_name))
			continue;

		sp = lm->mod_symtable;
		sp_end = lm->mod_symend;

                for ( ; sp <= sp_end; sp++) {
			if (MODULE_PSEUDO_SYMBOL(sp)) {
				if (MODULE_START(sp)) {
					p1 = "MODULE START";
					p2 = sp->name+strlen("_MODULE_START_");
				} else {
					p1 = "MODULE END";
					p2 = sp->name+strlen("_MODULE_END_");
				}
				fprintf(fp, "%lx %s: %s\n", sp->value, p1, p2);
			} else
				show_symbol(sp, 0, SHOW_RADIX());
                }
	}
}

/*
 *  Get a pointer to the desired asection.
 */
static asection *
get_kernel_section(char *name)
{
	int i;
        asection **sec;
 
        sec = (asection **)st->sections;
        for (i = 0; i < st->bfd->section_count; i++, sec++) {
		if (STREQ(name, (*sec)->name))
			return(*sec);
	}

	return NULL;
}


/*
 *  Walk through the current set of symbols and check for duplicates.
 */
static void
check_for_dups(struct load_module *lm)
{
	struct syment *sp, *sp_end;

        sp = lm->mod_symtable;
        sp_end = lm->mod_symend;

        for ( ; sp <= sp_end; sp++) {
                if (symbol_name_count(sp->name) > 1)
			error(WARNING, "%s: duplicate symbol name: %s\n",
				lm->mod_name, sp->name);
        }
}


/*
 *  Store the externally declared symbols for all modules in the system.
 *  allowing for dynamic loading of symbols from individual mod object files
 *  during runtime.
 */

struct module_symbol {
	unsigned long value;
        const char *name;
};

void
store_module_symbols_v1(ulong total, int mods_installed)
{
        int i, m;
        ulong mod, mod_next, mod_name;
        uint nsyms;
        ulong syms, size_of_struct;
	long strbuflen, size;
	int mcnt, lm_mcnt;
	struct module_symbol *modsym;
	struct load_module *lm;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char name[BUFSIZE];
	char rodata[BUFSIZE];
	char *strbuf, *modbuf, *modsymbuf;
	struct syment *sp;
	ulong first, last;

	st->mods_installed = mods_installed;

	if (!st->mods_installed) {
		st->flags &= ~MODULE_SYMS;
		return;
	}

	/*
	 *  If we've been here before, free up everything and start over.
	 */
	if (st->flags & MODULE_SYMS) {
		error(FATAL, 
		  "re-initialization of module symbols not implemented yet!\n");
	}

        if ((st->ext_module_symtable = (struct syment *)
             calloc(total, sizeof(struct syment))) == NULL)
                error(FATAL, "module syment space malloc: %s\n",
			strerror(errno));

        if (!namespace_ctl(NAMESPACE_INIT, &st->ext_module_namespace, 
	    (void *)total, NULL))
                error(FATAL, "module namespace malloc: %s\n", 
                        strerror(errno));

	if ((st->load_modules = (struct load_module *)calloc
	    (st->mods_installed, sizeof(struct load_module))) == NULL)
		error(FATAL, "load_module array malloc: %s\n", strerror(errno));

	modbuf = GETBUF(SIZE(module));
	modsymbuf = NULL;
	m = mcnt = 0;

        for (mod = kt->module_list; mod != kt->kernel_module; mod = mod_next) {

		readmem(mod, KVADDR, modbuf, SIZE(module), 
			"module buffer", FAULT_ON_ERROR);

		nsyms = UINT(modbuf + OFFSET(module_nsyms));
		syms = ULONG(modbuf + OFFSET(module_syms));
		size = LONG(modbuf + OFFSET(module_size));
		mod_name = ULONG(modbuf + OFFSET(module_name));
		size_of_struct = ULONG(modbuf + 
			OFFSET(module_size_of_struct));

		if (!read_string(mod_name, name, BUFSIZE-1))
			sprintf(name, "(unknown module)");
		
		sprintf(rodata, "__insmod_%s_S.rodata", name); 

		lm = &st->load_modules[m++];
		BZERO(lm, sizeof(struct load_module));
		lm->mod_base = lm->module_struct = mod;
		lm->mod_size = size;
		lm->mod_size_of_struct = size_of_struct;
        	if (strlen(name) < MAX_MOD_NAME)
                	strcpy(lm->mod_name, name);
        	else {
			error(INFO, 
			    "module name greater than MAX_MOD_NAME: %s\n",
				name);
                	strncpy(lm->mod_name, name, MAX_MOD_NAME-1);
		}

		lm->mod_flags = MOD_EXT_SYMS;
		lm->mod_ext_symcnt = mcnt;
		lm->mod_etext_guess = 0;

		st->ext_module_symtable[mcnt].value = mod;
		st->ext_module_symtable[mcnt].type = 'm';
		sprintf(buf2, "%s%s", "_MODULE_START_", name);
		namespace_ctl(NAMESPACE_INSTALL, &st->ext_module_namespace,
			&st->ext_module_symtable[mcnt], buf2);
		lm_mcnt = mcnt;
		mcnt++;

		if (nsyms) {
			modsymbuf = GETBUF(sizeof(struct module_symbol)*nsyms);
			readmem((ulong)syms, KVADDR, modsymbuf,
				nsyms * sizeof(struct module_symbol),
				"module symbols", FAULT_ON_ERROR);
		} 

		for (i = first = last = 0; i < nsyms; i++) {
			modsym = (struct module_symbol *)
			    (modsymbuf + (i * sizeof(struct module_symbol)));
			if (!first)
				first = (ulong)modsym->name;
			last = (ulong)modsym->name;
		}

		if (last > first) {
			strbuflen = (last-first) + BUFSIZE;
			if ((first + strbuflen) >= 
				(lm->mod_base + lm->mod_size)) {
				strbuflen = (lm->mod_base + lm->mod_size) - 
					first;

			}
                        strbuf = GETBUF(strbuflen);

                        if (!readmem(first, KVADDR, strbuf, strbuflen, 
			    "module symbol strings", RETURN_ON_ERROR)) {
				FREEBUF(strbuf);
				strbuf = NULL;
			}
		} else
			strbuf = NULL;

		for (i = first = last = 0; i < nsyms; i++) {

			modsym = (struct module_symbol *)
			    (modsymbuf + (i * sizeof(struct module_symbol)));

			if (!first) 
				first = (ulong)modsym->name;
			last = (ulong)modsym->name;

			BZERO(buf1, BUFSIZE);

			if (strbuf) 
				strcpy(buf1,
					&strbuf[(ulong)modsym->name - first]);
			else 
				read_string((ulong)modsym->name, buf1,
                            		BUFSIZE-1);

                	if (strlen(buf1)) {
				st->ext_module_symtable[mcnt].value = 
					modsym->value;
				st->ext_module_symtable[mcnt].type = '?'; 
				strip_module_symbol_end(buf1);
                		namespace_ctl(NAMESPACE_INSTALL, 
				    &st->ext_module_namespace,
                        	    &st->ext_module_symtable[mcnt], buf1);

				if (strstr(buf1, rodata))
					lm->mod_etext_guess = modsym->value;

				sprintf(buf2, "__insmod_%s_O/", lm->mod_name);
				if (strstr(buf1, buf2) && 
				    !strstr(buf1, "modules"))
					lm->mod_flags |= MOD_INITRD;
				mcnt++;
			}
		}
	
		if (modsymbuf) {
			FREEBUF(modsymbuf);
			modsymbuf = NULL;
		}

		if (strbuf)
			FREEBUF(strbuf);

		/*
	 	 *  If the module was compiled with kallsyms, add them in.
		 */
		switch (kt->flags & (KALLSYMS_V1|KALLSYMS_V2))
		{
		case KALLSYMS_V1:
			mcnt += store_module_kallsyms_v1(lm, lm_mcnt, 
				mcnt, modbuf);
			break;
		case KALLSYMS_V2:  /* impossible, I hope... */
			mcnt += store_module_kallsyms_v2(lm, lm_mcnt, 
				mcnt, modbuf);
			break;
		}

		st->ext_module_symtable[mcnt].value = mod + size;
		st->ext_module_symtable[mcnt].type = 'm';
		sprintf(buf2, "%s%s", "_MODULE_END_", name);
                namespace_ctl(NAMESPACE_INSTALL, 
			&st->ext_module_namespace,
                        &st->ext_module_symtable[mcnt], buf2);
		mcnt++;

		lm->mod_ext_symcnt = mcnt - lm->mod_ext_symcnt;

		if (!lm->mod_etext_guess)
			find_mod_etext(lm);

		NEXT_MODULE(mod_next, modbuf);
        }

	FREEBUF(modbuf);

	st->ext_module_symcnt = mcnt;
	st->ext_module_symend = &st->ext_module_symtable[mcnt];

	namespace_ctl(NAMESPACE_COMPLETE, &st->ext_module_namespace,
		st->ext_module_symtable, st->ext_module_symend);

	qsort(st->ext_module_symtable, mcnt, sizeof(struct syment), 
		compare_syms);

	qsort(st->load_modules, m, sizeof(struct load_module), compare_mods);

        for (m = 0; m < st->mods_installed; m++) {
                lm = &st->load_modules[m];
		sprintf(buf1, "_MODULE_START_%s", lm->mod_name);
		sprintf(buf2, "_MODULE_END_%s", lm->mod_name);

        	for (sp = st->ext_module_symtable; 
		     sp < st->ext_module_symend; sp++) {
			if (STREQ(sp->name, buf1)) {
				lm->mod_ext_symtable = sp;
				lm->mod_symtable = sp;
			}
			if (STREQ(sp->name, buf2)) {
				lm->mod_ext_symend = sp;
				lm->mod_symend = sp;
			}
		}
	}

	st->flags |= MODULE_SYMS;

        if (symbol_query("__insmod_", NULL, NULL))
                st->flags |= INSMOD_BUILTIN;
}

struct kernel_symbol
{
        unsigned long value;
        const char *name;
};

void
store_module_symbols_v2(ulong total, int mods_installed)
{

        int i, m;
        ulong mod, mod_next; 
	char *mod_name;
        uint nsyms, ngplsyms;
        ulong syms, gpl_syms;
	ulong nksyms;
	long strbuflen;
	ulong size;
	int mcnt, lm_mcnt;
	struct kernel_symbol *modsym;
	struct load_module *lm;
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char *strbuf, *modbuf, *modsymbuf;
	struct syment *sp;
	ulong first, last;

	st->mods_installed = mods_installed;

	if (!st->mods_installed) {
		st->flags &= ~MODULE_SYMS;
		return;
	}

	/*
	 *  If we've been here before, free up everything and start over.
	 */
	if (st->flags & MODULE_SYMS) {
		error(FATAL, 
		  "re-initialization of module symbols not implemented yet!\n");
	}

        if ((st->ext_module_symtable = (struct syment *)
             calloc(total, sizeof(struct syment))) == NULL)
                error(FATAL, "v2 module syment space malloc (%ld symbols): %s\n",
			total, strerror(errno));

        if (!namespace_ctl(NAMESPACE_INIT, &st->ext_module_namespace, 
	    (void *)total, NULL))
                error(FATAL, "module namespace malloc: %s\n", 
                        strerror(errno));

	if ((st->load_modules = (struct load_module *)calloc
	    (st->mods_installed, sizeof(struct load_module))) == NULL)
		error(FATAL, "load_module array malloc: %s\n", strerror(errno));

	modbuf = GETBUF(SIZE(module));
	modsymbuf = NULL;
	m = mcnt = 0;

        for (mod = kt->module_list; mod != kt->kernel_module; mod = mod_next) {

		readmem(mod, KVADDR, modbuf, SIZE(module), 
			"module buffer", FAULT_ON_ERROR);

		syms = ULONG(modbuf + OFFSET(module_syms));
		gpl_syms = ULONG(modbuf + OFFSET(module_gpl_syms));
                nsyms = UINT(modbuf + OFFSET(module_num_syms));
                ngplsyms = UINT(modbuf + OFFSET(module_num_gpl_syms));
                nksyms = ULONG(modbuf + OFFSET(module_num_symtab));
		size = ULONG(modbuf + OFFSET(module_core_size));
		mod_name = modbuf + OFFSET(module_name);

		lm = &st->load_modules[m++];
		BZERO(lm, sizeof(struct load_module));
		lm->mod_base = ULONG(modbuf + OFFSET(module_module_core));
		lm->module_struct = mod;
		lm->mod_size = size;
        	if (strlen(mod_name) < MAX_MOD_NAME)
                	strcpy(lm->mod_name, mod_name);
        	else {
			error(INFO, 
			    "module name greater than MAX_MOD_NAME: %s\n",
				mod_name);
                	strncpy(lm->mod_name, mod_name, MAX_MOD_NAME-1);
		}
		if (CRASHDEBUG(3))
			fprintf(fp, 
			    "%lx (%lx): %s syms: %d gplsyms: %d ksyms: %ld\n", 
				mod, lm->mod_base, lm->mod_name, nsyms, 
				ngplsyms, nksyms);
		lm->mod_flags = MOD_EXT_SYMS;
		lm->mod_ext_symcnt = mcnt;
		lm->mod_etext_guess = lm->mod_base + 
			ULONG(modbuf + OFFSET(module_core_text_size));
		lm->mod_text_start = lm->mod_base;

		st->ext_module_symtable[mcnt].value = lm->mod_base;
		st->ext_module_symtable[mcnt].type = 'm';
		sprintf(buf2, "%s%s", "_MODULE_START_", mod_name);
		namespace_ctl(NAMESPACE_INSTALL, &st->ext_module_namespace,
			&st->ext_module_symtable[mcnt], buf2);
		lm_mcnt = mcnt;
		mcnt++;

		if (nsyms) {
			modsymbuf = GETBUF(sizeof(struct kernel_symbol)*nsyms);
			readmem((ulong)syms, KVADDR, modsymbuf,
				nsyms * sizeof(struct kernel_symbol),
				"module symbols", FAULT_ON_ERROR);
		} 

		for (i = first = last = 0; i < nsyms; i++) {
			modsym = (struct kernel_symbol *)
			    (modsymbuf + (i * sizeof(struct kernel_symbol)));
			if (!first)
				first = (ulong)modsym->name;
			last = (ulong)modsym->name;
		}

		if (last > first) {
			strbuflen = (last-first) + BUFSIZE;
			if ((first + strbuflen) >= 
				(lm->mod_base + lm->mod_size)) {
				strbuflen = (lm->mod_base + lm->mod_size) - 
					first;

			}
                        strbuf = GETBUF(strbuflen);

                        if (!readmem(first, KVADDR, strbuf, strbuflen, 
			    "module symbol strings", RETURN_ON_ERROR)) {
				FREEBUF(strbuf);
				strbuf = NULL;
			}
		} else 
			strbuf = NULL;

		for (i = first = last = 0; i < nsyms; i++) {

			modsym = (struct kernel_symbol *)
			    (modsymbuf + (i * sizeof(struct kernel_symbol)));

			if (!first) 
				first = (ulong)modsym->name;
			last = (ulong)modsym->name;

			BZERO(buf1, BUFSIZE);

			if (strbuf) 
				strcpy(buf1,
					&strbuf[(ulong)modsym->name - first]);
			else 
				read_string((ulong)modsym->name, buf1,
                            		BUFSIZE-1);

                	if (strlen(buf1)) {
				st->ext_module_symtable[mcnt].value = 
					modsym->value;
				st->ext_module_symtable[mcnt].type = '?'; 
				strip_module_symbol_end(buf1);
                		namespace_ctl(NAMESPACE_INSTALL, 
				    &st->ext_module_namespace,
                        	    &st->ext_module_symtable[mcnt], buf1);

				mcnt++;
			}
		}
	
		if (modsymbuf) {
			FREEBUF(modsymbuf);
			modsymbuf = NULL;
		}

		if (strbuf)
			FREEBUF(strbuf);

		if (ngplsyms) {
			modsymbuf = GETBUF(sizeof(struct kernel_symbol) *
				ngplsyms);
			readmem((ulong)gpl_syms, KVADDR, modsymbuf,
				ngplsyms * sizeof(struct kernel_symbol),
				"module gpl symbols", FAULT_ON_ERROR);
		} 

		for (i = first = last = 0; i < ngplsyms; i++) {
			modsym = (struct kernel_symbol *)
			    (modsymbuf + (i * sizeof(struct kernel_symbol)));
			if (!first)
				first = (ulong)modsym->name;
			last = (ulong)modsym->name;
		}

		if (last > first) {
			strbuflen = (last-first) + BUFSIZE;
			if ((first + strbuflen) >= 
				(lm->mod_base + lm->mod_size)) {
				strbuflen = (lm->mod_base + lm->mod_size) - 
					first;

			}
                        strbuf = GETBUF(strbuflen);

                        if (!readmem(first, KVADDR, strbuf, strbuflen, 
			    "module gpl symbol strings", RETURN_ON_ERROR)) {
				FREEBUF(strbuf);
				strbuf = NULL;
			}
		} else 
			strbuf = NULL;

		for (i = first = last = 0; i < ngplsyms; i++) {

			modsym = (struct kernel_symbol *)
			    (modsymbuf + (i * sizeof(struct kernel_symbol)));

			if (!first) 
				first = (ulong)modsym->name;
			last = (ulong)modsym->name;

			BZERO(buf1, BUFSIZE);

			if (strbuf) 
				strcpy(buf1,
					&strbuf[(ulong)modsym->name - first]);
			else 
				read_string((ulong)modsym->name, buf1,
                            		BUFSIZE-1);

                	if (strlen(buf1)) {
				st->ext_module_symtable[mcnt].value = 
					modsym->value;
				st->ext_module_symtable[mcnt].type = '?'; 
				strip_module_symbol_end(buf1);
                		namespace_ctl(NAMESPACE_INSTALL, 
				    &st->ext_module_namespace,
                        	    &st->ext_module_symtable[mcnt], buf1);

				mcnt++;
			}
		}
	
		if (modsymbuf) {
			FREEBUF(modsymbuf);
			modsymbuf = NULL;
		}

		if (strbuf)
			FREEBUF(strbuf);

		/*
	 	 *  If the module was compiled with kallsyms, add them in.
		 */
                switch (kt->flags & (KALLSYMS_V1|KALLSYMS_V2))
                {
                case KALLSYMS_V1:  /* impossible, I hope... */
                        mcnt += store_module_kallsyms_v1(lm, lm_mcnt,
                                mcnt, modbuf);
                        break;
                case KALLSYMS_V2:  
                        mcnt += store_module_kallsyms_v2(lm, lm_mcnt,
                                mcnt, modbuf);
                        break;
                }

		st->ext_module_symtable[mcnt].value = lm->mod_base + size;
		st->ext_module_symtable[mcnt].type = 'm';
		sprintf(buf2, "%s%s", "_MODULE_END_", mod_name);
                namespace_ctl(NAMESPACE_INSTALL, 
			&st->ext_module_namespace,
                        &st->ext_module_symtable[mcnt], buf2);
		mcnt++;

		lm->mod_ext_symcnt = mcnt - lm->mod_ext_symcnt;

		if (!lm->mod_etext_guess)
			find_mod_etext(lm);

		NEXT_MODULE(mod_next, modbuf);
        }

	FREEBUF(modbuf);

	st->ext_module_symcnt = mcnt;
	st->ext_module_symend = &st->ext_module_symtable[mcnt];

	namespace_ctl(NAMESPACE_COMPLETE, &st->ext_module_namespace,
		st->ext_module_symtable, st->ext_module_symend);

	qsort(st->ext_module_symtable, mcnt, sizeof(struct syment), 
		compare_syms);

	qsort(st->load_modules, m, sizeof(struct load_module), compare_mods);

        for (m = 0; m < st->mods_installed; m++) {
                lm = &st->load_modules[m];
		sprintf(buf1, "_MODULE_START_%s", lm->mod_name);
		sprintf(buf2, "_MODULE_END_%s", lm->mod_name);

        	for (sp = st->ext_module_symtable; 
		     sp < st->ext_module_symend; sp++) {
			if (STREQ(sp->name, buf1)) {
				lm->mod_ext_symtable = sp;
				lm->mod_symtable = sp;
			}
			if (STREQ(sp->name, buf2)) {
				lm->mod_ext_symend = sp;
				lm->mod_symend = sp;
			}
		}
	}

	st->flags |= MODULE_SYMS;

        if (symbol_query("__insmod_", NULL, NULL))
                st->flags |= INSMOD_BUILTIN;
}

/*
 *  Get the module's kallsyms list if it was compiled in.
 */
static int
store_module_kallsyms_v1(struct load_module *lm, int start, int curr, 
			 char *modbuf)
{
	int i, j;
	struct syment *sp;
	ulong kallsyms_header;
	char *module_buf;
	char *header_buf;
	uint symbols;
	uint sections;
	ulong name_off;
	ulong sec_name_off;
	ulong section_off;
	ulong symptr;
	ulong symbol_addr;
	ulong stringptr;
	ulong sectionptr;
	char *nameptr;
	char *secnameptr;
	ulong secptr;
	char type;
	int mcnt;
	int mcnt_idx;
	int found;
	struct namespace *ns;

	if (!(kt->flags & KALLSYMS_V1))
		return 0;

        kallsyms_header = ULONG(modbuf + OFFSET(module_kallsyms_start));
	if (!kallsyms_header)
		return 0;

	mcnt = 0;
	mcnt_idx = curr;
	module_buf = GETBUF(ULONG(modbuf + OFFSET(module_size)));
        ns = &st->ext_module_namespace;

       	if (!readmem(lm->mod_base, KVADDR, module_buf, lm->mod_size,
            "module (kallsyms)", RETURN_ON_ERROR|QUIET)) { 
        	error(WARNING,"cannot access module kallsyms\n");
		FREEBUF(module_buf);
		return 0;
	} 

#define IN_MODULE_BUF_V1(x) \
        (((x) >= module_buf) && ((x) < (module_buf + lm->mod_size)))

	header_buf = module_buf + (kallsyms_header - lm->mod_base);
        symbols = UINT(header_buf + OFFSET(kallsyms_header_symbols));
        sections = UINT(header_buf + OFFSET(kallsyms_header_sections));

	if (CRASHDEBUG(7))
		fprintf(fp, "kallsyms: module: %s\n", lm->mod_name);

	symptr = (ulong)(header_buf + 
		ULONG(header_buf + OFFSET(kallsyms_header_symbol_off)));
	stringptr = (ulong)(header_buf + 
		ULONG(header_buf + OFFSET(kallsyms_header_string_off)));
	sectionptr = (ulong)(header_buf + 
		ULONG(header_buf + OFFSET(kallsyms_header_section_off)));

	for (i = 0; i < symbols; i++, symptr += SIZE(kallsyms_symbol)) {
		symbol_addr = ULONG(symptr+OFFSET(kallsyms_symbol_symbol_addr));
		name_off = ULONG(symptr+OFFSET(kallsyms_symbol_name_off));
		section_off = ULONG(symptr+OFFSET(kallsyms_symbol_section_off));
		nameptr = (char *)(stringptr + name_off);
		secptr = (ulong)(sectionptr + section_off);
		sec_name_off = ULONG(secptr+OFFSET(kallsyms_section_name_off));
		secnameptr = (char *)(stringptr + sec_name_off);

                if (!IN_MODULE_BUF_V1(nameptr)) {
                        if (CRASHDEBUG(7))
                                error(INFO,
                 "%s: invalid nameptr: %lx  (stringptr: %lx + name_off: %lx)\n",                                        lm->mod_name, nameptr,
                                        stringptr, name_off);
                        continue;
                }
                if (!IN_MODULE_BUF_V1(secnameptr)) {
                        if (CRASHDEBUG(7))
                                error(INFO,
           "%s: invalid secnameptr: %lx (stringptr: %lx + sec_name_off: %lx)\n",                                        lm->mod_name, secnameptr,
                                        stringptr, sec_name_off);
                        continue;
                }

		if (!STREQ(nameptr, secnameptr)) {
		    	if (STREQ(secnameptr, ".text"))
				type = 't'; 
			else if (STREQ(secnameptr, ".data"))
				type = 'd'; 
			else if (STREQ(secnameptr, ".bss")) 
				type = 'b'; 
			else if (STREQ(secnameptr, ".rodata")) 
				type = 'd'; 
			else 
				continue;

			strip_module_symbol_end(nameptr);

			if (CRASHDEBUG(7))
				fprintf(fp,"  symbol: %lx \"%s\" section: %s\n",
					symbol_addr, nameptr, secnameptr);

			for (found = 0, j = start; j < curr; j++) {
				sp = &st->ext_module_symtable[j];
				if ((sp->value == symbol_addr) &&
				    STREQ(nameptr, 
				    &ns->address[(ulong)sp->name])) {
					if (CRASHDEBUG(7)) 
					    fprintf(fp, 
		                 "current symbol \"%s\" at %lx of type (%c)\n", 
						&ns->address[(ulong)sp->name], 
						sp->value, sp->type);
					if (sp->type == '?')
						sp->type = type;
					found++;
					break;
				}
			}

			if (found)
				continue;

                       	st->ext_module_symtable[mcnt_idx].value = symbol_addr;
                       	st->ext_module_symtable[mcnt_idx].type = type;
                        namespace_ctl(NAMESPACE_INSTALL,
                                &st->ext_module_namespace,
                                &st->ext_module_symtable[mcnt_idx++], nameptr);
                                mcnt++;
		}
	}

	lm->mod_flags |= MOD_KALLSYMS;

	FREEBUF(module_buf);
	return mcnt;
}

/*
 *  Translate either an Elf32_Sym or Elf64_Sym to an elf_common structure
 *  for more convenient use by store_module_kallsyms_v2().
 */

struct elf_common {
	ulong st_name;
	ulong st_value;
	ulong st_shndx;
	unsigned char st_info;
};

static void Elf32_Sym_to_common(Elf32_Sym *e32, struct elf_common *ec)
{
	ec->st_name = (ulong)e32->st_name;
	ec->st_value = (ulong)e32->st_value;
	ec->st_shndx = (ulong)e32->st_shndx;
	ec->st_info = e32->st_info;
}

static void Elf64_Sym_to_common(Elf64_Sym *e64, struct elf_common *ec)
{
	ec->st_name = (ulong)e64->st_name;
	ec->st_value = (ulong)e64->st_value;
	ec->st_shndx = (ulong)e64->st_shndx;
	ec->st_info = e64->st_info;
}

static int
store_module_kallsyms_v2(struct load_module *lm, int start, int curr,
                         char *modbuf)
{
	int i, j, found;
	Elf32_Sym *elf32_sym;
	Elf64_Sym *elf64_sym;
	struct elf_common elf_common, *ec;
	ulong nksyms, ksymtab, kstrtab;
	char *module_buf, *ptr, *locsymtab, *locstrtab, *nameptr;
	struct syment *sp;
	struct namespace *ns;
        int mcnt;
        int mcnt_idx;

	if (!(kt->flags & KALLSYMS_V2))
		return 0;

	mcnt = 0;
	mcnt_idx = curr;
        ns = &st->ext_module_namespace;
	ec = &elf_common;

	elf32_sym = NULL;
	elf64_sym = NULL;

        module_buf = GETBUF(lm->mod_size);

        if (!readmem(lm->mod_base, KVADDR, module_buf, lm->mod_size,
            "module (kallsyms)", RETURN_ON_ERROR|QUIET)) {
                error(WARNING,"cannot access module kallsyms\n");
                FREEBUF(module_buf);
                return 0;
        }

	nksyms = ULONG(modbuf + OFFSET(module_num_symtab));
	ksymtab = ULONG(modbuf + OFFSET(module_symtab));
	locsymtab = module_buf + (ksymtab - lm->mod_base);
	kstrtab = ULONG(modbuf + OFFSET(module_strtab));
	locstrtab = module_buf + (kstrtab - lm->mod_base);

	for (i = 1; i < nksyms; i++) {  /* ELF starts real symbols at 1 */
		switch (BITS())
		{
		case 32:
			ptr = locsymtab + (i * sizeof(Elf32_Sym));
			Elf32_Sym_to_common((Elf32_Sym *)ptr, ec);
			break;
		case 64:
			ptr = locsymtab + (i * sizeof(Elf64_Sym));
			Elf64_Sym_to_common((Elf64_Sym *)ptr, ec);
			break;
		}

		if ((ec->st_value < lm->mod_base) || 
		    (ec->st_value >  (lm->mod_base + lm->mod_size))) 
				continue;

		if (ec->st_shndx == SHN_UNDEF)
                        continue;

		nameptr = locstrtab + ec->st_name;
		if (*nameptr == '\0')
			continue;

		if (CRASHDEBUG(7))
			fprintf(fp, 
	          "%s: st_name: %ld st_value: %lx st_shndx: %ld st_info: %c\n",
				nameptr, ec->st_name, ec->st_value, 
				ec->st_shndx, ec->st_info);

                for (found = 0, j = start; j < curr; j++) {
                        sp = &st->ext_module_symtable[j];
                        if ((sp->value == ec->st_value) &&
                             STREQ(nameptr, &ns->address[(ulong)sp->name])) {
                        	if (CRASHDEBUG(7))
                                            fprintf(fp,
                                  "current symbol \"%s\" at %lx of type (%c)\n",
                                                &ns->address[(ulong)sp->name],
                                                sp->value, sp->type);
                                if (sp->type == '?')
                                        sp->type = ec->st_info;
                                found++;
                                break;
                        }
                }

		if (found)
			continue;

                st->ext_module_symtable[mcnt_idx].value = ec->st_value;
                st->ext_module_symtable[mcnt_idx].type = ec->st_info;
                namespace_ctl(NAMESPACE_INSTALL,
                	&st->ext_module_namespace,
                        &st->ext_module_symtable[mcnt_idx++], nameptr);
                        mcnt++;
	}

        lm->mod_flags |= MOD_KALLSYMS;
        FREEBUF(module_buf);

        return mcnt;
}

/*
 *  Strip the kernel clutter tagged on the end of an exported module symbol.
 */
static void
strip_module_symbol_end(char *buf)
{
	char *p1, *lastR;

	if (!(lastR = strrchr(buf, 'R')))
		return;

	if (((p1 = lastR-1) < buf) || (*p1 != '_')) 
		return;

	if ((kt->flags & SMP) && STRNEQ(p1, "_Rsmp_")) { 
		*p1 = NULLCHAR;
		return;
	}

	if (!hexadecimal(lastR+1, 0))
		return;

	*p1 = NULLCHAR;
}

/*
 *  Look through a string for bogus kernel clutter of an exported 
 *  module symbol.  In the case of LM_P_FILTER, shift the string left
 *  as appropriate to get rid of the extra stuff.  In the case of
 *  LM_DIS_FILTER, translation of the previous address is done first,
 *  and its results are stuffed into the string.  In both cases,
 *  this routine is recursive to catch multiple instances.
 */

#define SMP_CLUTTER   (strlen("_Rsmp_"))
#define UP_CLUTTER    (strlen("_R"))
#define CLUTTER_IDLEN (8)

char *
load_module_filter(char *s, int type)
{
        char *arglist[MAXARGS];
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	int clen, last;
	int prev;
	char *pstart, *p1, *p2, *smp, *pend, *colon;
	ulong vaddr;
	ulong offset;
	struct syment *sp;
        int argc;

	switch (type)
	{
	case LM_P_FILTER:    
        	if (!(pstart = strstr(s, "_R")))
                	return s;

        	smp = strstr(s, "_Rsmp_");
        	pend = &s[strlen(s)];

        	p2 = pstart + (smp ? SMP_CLUTTER : UP_CLUTTER);

        	if ((p2 >= pend) || !hexadecimal(p2, CLUTTER_IDLEN))
                	return s;

        	clen = smp ? 
			SMP_CLUTTER+CLUTTER_IDLEN : UP_CLUTTER+CLUTTER_IDLEN;

		if (bracketed(s, pstart, clen)) {  /* hack it out for now */
			pstart--;
			shift_string_left(pstart, clen+2);
			if (*pstart == ',')
				shift_string_left(pstart-1, 1);
		} else
			shift_string_left(pstart, clen);

		return (load_module_filter(s, type));   /* catch multiples */

	case LM_DIS_FILTER:
		strip_beginning_whitespace(s);
        	strcpy(buf1, s);
        	argc = parse_line(buf1, arglist);

		if (argc < 2)
			return s;

		/* 
		 *  Fix up the first half of the disassembly expression,
		 *  that is, the address and symbol to the left of the
	         *  colon.
		 */
		colon = NULL;

		if (hexadecimal(arglist[0], VADDR_PRLEN+2) &&
		    bracketed(arglist[1], &arglist[1][1], 0) &&
		    (colon = strstr(s, ":"))) {  
			strcpy(buf2, colon+2);

			vaddr = htol(arglist[0], FAULT_ON_ERROR, NULL);
			if ((sp = value_search(vaddr, &offset))) {
				if (offset)
					sprintf(s, "%s <%s+%ld>:\t%s", 
					    arglist[0], sp->name, offset, buf2);
				else
					sprintf(s, "%s <%s>:\t%s", 
					    arglist[0], sp->name, buf2);
			}
		} 

		/*
		 *  Now work on the second part -- if it exists.
 		 *  Find a virtual address followed by a bracked symbol
		 *  at the end of the line.
		 */

		if (colon) {
        		strcpy(buf1, s);
        		argc = parse_line(buf1, arglist);
		    	colon = strstr(s, ":"); 
		}

		last = argc-1;
		prev = argc-2;

		if (bracketed(arglist[last], &arglist[last][1], 0) &&
		    hexadecimal(arglist[prev], VADDR_PRLEN+2)) {

			vaddr = htol(arglist[prev], FAULT_ON_ERROR, NULL);
			p1 = strstr(s, arglist[last]);

			if ((sp = value_search(vaddr, &offset)) && 
			    !(colon && (p1 < colon))) {
				if (offset)
					sprintf(p1, "<%s+%ld>\n", 
						sp->name, offset);
				else
					sprintf(p1, "<%s>\n", sp->name);
			}
		} 

       		pend = &s[strlen(s)-3];
        	if (STREQ(pend, ":\t\n"))
                	LASTCHAR(s) = NULLCHAR;

		return s;

	default:
		return NULL;   /* can't get here */
	}
}

/*
 *  Handle the various commands for controlling symbol string space:
 *
 *      NAMESPACE_INIT: Allocates an estimated size for the string space.
 *     NAMESPACE_REUSE: Resets appropriate fields to allow a previously
 *                      allocated module string buffer to be reused. 
 *      NAMESPACE_FREE: Frees (module) string space.
 *   NAMESPACE_INSTALL: Copies a symbol name string into the next available
 *                      buffer space.  If the string cannot be squeezed in,
 *                      the whole string space is reallocated, which may 
 *                      change its starting address.  For that reason, the
 *                      buffer index is temporarily stored in the sp->name
 *                      field, which NAMESPACE_COMPLETE later transforms into
 *                      the proper address when the buffer is set.
 *  NAMESPACE_COMPLETE: Reallocs a completed string buffer to the exact
 *                      size that is required, and then calculates and stores
 *                      the proper addresses into the name fields of the
 *                      passed-in syment array.
 */

#define AVERAGE_SYMBOL_SIZE (16)

static int
namespace_ctl(int cmd, struct namespace *ns, void *nsarg1, void *nsarg2)
{
	char *addr;
	struct syment *sp, *sp_end;
	char *name;
	long cnt;
	int len;

	switch (cmd)
	{
	case NAMESPACE_INIT:
		cnt = (long)nsarg1;
		if ((addr = calloc(cnt, AVERAGE_SYMBOL_SIZE)) == NULL)
			return FALSE;
		ns->address = addr;
		ns->index = 0;
		ns->cnt = 0;
		ns->size = cnt * AVERAGE_SYMBOL_SIZE;
		return TRUE;

	case NAMESPACE_REUSE:
		ns->index = 0;
		ns->cnt = 0;
		return TRUE;

	case NAMESPACE_FREE:
		if (!ns->address)
			error(FATAL, 
			    "attempt to free unallocated module namespace\n");
		free(ns->address);
		ns->address = 0;
		ns->index = 0;
		ns->size = 0;
		ns->cnt = 0;
		return TRUE;

	case NAMESPACE_INSTALL:
		sp = (struct syment *)nsarg1;
		name = (char *)nsarg2;
		len = strlen(name)+1;
		if ((ns->index + len) >= ns->size) { 
                        if (!(addr = realloc(ns->address, ns->size*2))) 
				error(FATAL, "symbol name space malloc: %s\n",
					strerror(errno));
                        ns->address = addr;
                        ns->size *= 2;
		}
		sp->name = (char *)ns->index;  
		BCOPY(name, &ns->address[ns->index], len);
		ns->index += len;
		ns->cnt++;
		return TRUE;

	case NAMESPACE_COMPLETE:
		sp = (struct syment *)nsarg1;
		sp_end = (struct syment *)nsarg2;
		if (ns->index < (ns->size-1)) {
			if ((addr = realloc(ns->address, ns->index+1))) {
				ns->address = addr;
				ns->size = ns->index+1;
			}
		}
		for ( ; sp < sp_end; sp++) 
			sp->name = ns->address + (long)sp->name;
		return TRUE;

	default:
		return FALSE;   /* can't get here */
	}
}


/*
 *  These comparison functions must return an integer less  than,
 *  equal  to,  or  greater than zero if the first argument is
 *  considered to be respectively  less  than,  equal  to,  or
 *  greater than the second.  If two members compare as equal,
 *  their order in the sorted array is undefined.
 */

static int
compare_syms(const void *v1, const void *v2)
{
	struct syment *s1, *s2;

	s1 = (struct syment *)v1;
	s2 = (struct syment *)v2;

	if (s1->value == s2->value) {
		if (STRNEQ(s1->name, "__insmod"))
			return -1;
		if (STRNEQ(s2->name, "__insmod"))
			return 1;
	}

	return (s1->value < s2->value ? -1 : 
		s1->value == s2->value ? 0 : 1);
}

static int
compare_mods(const void *v1, const void *v2)
{
	struct load_module *lm1, *lm2;

	lm1 = (struct load_module *)v1;
	lm2 = (struct load_module *)v2;

	return (lm1->mod_base < lm2->mod_base ? -1 :
		lm1->mod_base == lm2->mod_base ? 0 : 1);
}


/*
 *  Check whether a value falls into a text-type (SEC_CODE) section.
 *  If it's a module address, and symbols are not loaded, we're forced
 *  to use our "mod_etext_guess" value.
 */
int
is_kernel_text(ulong value)
{
        int i, s;
        asection **sec, *section;
        struct load_module *lm;
	ulong start, end;
	struct syment *sp;

	if (pc->flags & SYSMAP) {
		sp = st->symtable;
		if ((value >= sp->value) && (value < kt->etext))
			return TRUE;
        	if ((sp = value_search(value, NULL)) &&
		    ((sp->type == 'T') || (sp->type == 't'))) 
			return TRUE;
	} else {
	        sec = (asection **)st->sections;
	        for (i = 0; i < st->bfd->section_count; i++, sec++) {
			section = *sec;
	                if (section->flags & SEC_CODE) {
				start = (ulong)bfd_get_section_vma(st->bfd, 
					section);
				end = start + (ulong)bfd_section_size(st->bfd, 
					section);
	
	        		if ((value >= start) && (value < end)) 
	                		return TRUE;
			}
		}
	}

        if ((sp = value_search(value, NULL)) &&
	    ((sp->type == 'T') || (sp->type == 't'))) 
		return TRUE;

        if (NO_MODULES())
                return FALSE;

        for (i = 0; i < st->mods_installed; i++) {
                lm = &st->load_modules[i];

		if (!IN_MODULE(value, lm))
			continue;

		if (lm->mod_flags & MOD_LOAD_SYMS) {
	               	for (s = (lm->mod_sections-1); s >= 0; s--) {
				if (!(lm->mod_section_data[s].flags & SEC_CODE))
					continue;
	
				start = lm->mod_base + 
					lm->mod_section_data[s].offset;
				end = start + lm->mod_section_data[s].size;
	
	        		if ((value >= start) && (value < end)) 
	                		return TRUE;
	                }
		} else {
			switch (kt->flags & (KMOD_V1|KMOD_V2))
			{
			case KMOD_V1:
				start = lm->mod_base + lm->mod_size_of_struct;
				break;
			case KMOD_V2:
				start = lm->mod_base;
				break;
			}
			end = lm->mod_etext_guess;

	        	if ((value >= start) && (value < end)) 
	               		return TRUE;
		}
        }

	return FALSE;
}

/*
 *  Detemine whether an address is offset into a text function, i.e., not
 *  the starting address of the function.
 */
int
is_kernel_text_offset(ulong value)
{
	struct syment *sp;
	ulong offset;

	if (!is_kernel_text(value))
		return FALSE;

	if (!(sp = value_search(value, &offset)))
		return FALSE;

	return(offset ? TRUE : FALSE);
}


/*
 *  Check whether an address is most likely kernel data.
 *
 *  TBD: This should be refined to recognize module text/data.
 */ 
int
is_kernel_data(ulong value)
{
        return(IS_KVADDR(value) && 
	       !is_kernel_text(value) && !IS_MODULE_VADDR(value));
}

/*
 *  Check whether the closest symbol to a value is rodata.
 */
int
is_rodata(ulong value, struct syment **spp)
{
        struct syment *sp;

        if (!(sp = value_search(value, NULL)))
                return FALSE;

	if ((sp->type == 'r') || (sp->type == 'R')) {
		if (spp)
			*spp = sp;
		return TRUE;
	}

        return FALSE;
}

/*
 *  "help -s" output
 */
void
dump_symbol_table(void)
{
	int i, s, cnt, tot;
        struct load_module *lm;
	struct syment *sp;
	int others;
	asection **sec;

        fprintf(fp, "               flags: %lx%s(", st->flags,
		count_bits_long(st->flags) > 3 ? "\n   " : "  ");
        others = 0;
        if (st->flags & KERNEL_SYMS)
                fprintf(fp, "%sKERNEL_SYMS", others++ ? "|" : "");
        if (st->flags & MODULE_SYMS)
                fprintf(fp, "%sMODULE_SYMS", others++ ? "|" : "");
        if (st->flags & LOAD_MODULE_SYMS)
                fprintf(fp, "%sLOAD_MODULE_SYMS",
                        others++ ? "|" : "");
        if (st->flags & INSMOD_BUILTIN)
                fprintf(fp, "%sINSMOD_BUILTIN", others++ ? "|" : "");
        if (st->flags & GDB_SYMS_PATCHED)
                fprintf(fp, "%sGDB_SYMS_PATCHED", others++ ? "|" : "");
        if (st->flags & NO_SEC_LOAD)
                fprintf(fp, "%sNO_SEC_LOAD", others++ ? "|" : "");
        if (st->flags & NO_SEC_CONTENTS)
                fprintf(fp, "%sNO_SEC_CONTENTS", others++ ? "|" : "");
        if (st->flags & FORCE_DEBUGINFO)
                fprintf(fp, "%sFORCE_DEBUGINFO", others++ ? "|" : "");
        if (st->flags & CRC_MATCHES)
                fprintf(fp, "%sCRC_MATCHES", others++ ? "|" : "");
        if (st->flags & ADD_SYMBOL_FILE)
                fprintf(fp, "%sADD_SYMBOL_FILE", others++ ? "|" : "");
        fprintf(fp, ")\n");

	fprintf(fp, "                 bfd: %lx\n", (ulong)st->bfd);

	sec = (asection **)st->sections;
	fprintf(fp, "            sections: %s\n", sec ? "" : "(not in use)");
	for (i = 0; sec && (i < st->bfd->section_count); i++, sec++) {
		asection *section;

		section = *sec;
		fprintf(fp, "%25s  vma: %.*lx  size: %ld\n", 
			section->name, VADDR_PRLEN,
			(ulong)bfd_get_section_vma(st->bfd, section),
			(ulong)bfd_section_size(st->bfd, section));
	}

	fprintf(fp, "            symtable: %lx\n", (ulong)st->symtable);
	fprintf(fp, "              symend: %lx\n", (ulong)st->symend);
	fprintf(fp, "              symcnt: %ld\n", st->symcnt);
	fprintf(fp, "         syment_size: %ld\n", st->syment_size);

        fprintf(fp, "    symval_hash[%d]: %lx\n", SYMVAL_HASH,
                (ulong)&st->symval_hash[0]);

	if (CRASHDEBUG(1)) {
		fprintf(fp, "   ");
	        for (i = 0; i < SYMVAL_HASH; i++) {
	                fprintf(fp, " [%3d]: ", i);
	
	                sp = st->symval_hash[i].val_hash_head;
	                if (!sp) {
	                        fprintf(fp, "  0 ");
	                } else {
	                	cnt = 1;
	                	while ((sp = sp->val_hash_next)) 
	                        	cnt++;
	
	                	fprintf(fp, "%3d ", cnt);
			}

			if (i && (((i+1)%6)== 0))
				fprintf(fp, "\n   ");
	        }
	}

        fprintf(fp, "%s   val_hash_searches: %.0f\n", 
		CRASHDEBUG(1) ? "\n" : "", st->val_hash_searches);
        fprintf(fp, " val_hash_iterations: %.0f  (avg: %.1f)\n",
                st->val_hash_iterations,
                st->val_hash_iterations/st->val_hash_searches);

        fprintf(fp, "   symname_hash[%d]: %lx\n", SYMNAME_HASH,
                (ulong)&st->symname_hash[0]);

	if (CRASHDEBUG(1)) {
		fprintf(fp, "    ");
	        for (i = tot = 0; i < SYMNAME_HASH; i++) {
	                fprintf(fp, "[%3d]: ", i);
	                if ((sp = st->symname_hash[i]) == NULL) 
	                        fprintf(fp, "%3d  ", 0);
	                else {
		                cnt = 1;
		                while (sp->name_hash_next) {
		                        cnt++;
		                        sp = sp->name_hash_next;
		                }
		                fprintf(fp, "%3d  ", cnt);
				tot += cnt;
			}
			if (i && (((i+1) % 6) == 0))
				fprintf(fp, "\n    ");
	        }
		if (SYMNAME_HASH % 6)
			fprintf(fp, "\n");
	}
	fprintf(fp, "           namespace: ");
	fprintf(fp, "address: %lx  ", (ulong)st->namespace.address);
	fprintf(fp, "index: %ld  ", st->namespace.index); 
	fprintf(fp, "size: %ld  ", (ulong)st->namespace.size);
	fprintf(fp, "cnt: %ld\n", st->namespace.cnt);
	fprintf(fp, " ext_module_symtable: %lx\n", 
		(ulong)st->ext_module_symtable);
	fprintf(fp, "   ext_module_symend: %lx\n", 
		(ulong)st->ext_module_symend);
	fprintf(fp, "   ext_module_symcnt: %ld\n", 
		(ulong)st->ext_module_symcnt);
        fprintf(fp, "ext_module_namespace: ");
        fprintf(fp, "address: %lx  ", 
		(ulong)st->ext_module_namespace.address);
        fprintf(fp, "index: %ld  ", 
		st->ext_module_namespace.index);
        fprintf(fp, "size: %ld  ", 
		(ulong)st->ext_module_namespace.size);
        fprintf(fp, "cnt: %ld\n", 
		st->ext_module_namespace.cnt);

	fprintf(fp, "      mods_installed: %d\n", st->mods_installed);
	fprintf(fp, "             current: %lx\n", (ulong)st->current);
	fprintf(fp, "        load_modules: %lx\n", (ulong)st->load_modules);

	for (i = 0; i < st->mods_installed; i++) {
	        lm = &st->load_modules[i]; 
		others = 0;

		fprintf(fp, "\n              mod_base: %lx\n", lm->mod_base);
		fprintf(fp, "         module_struct: %lx\n", lm->module_struct);
		fprintf(fp, "              mod_name: %s\n", lm->mod_name);
		fprintf(fp, "              mod_size: %ld\n", lm->mod_size);
		fprintf(fp, "          mod_namelist: %s\n", lm->mod_namelist);
		fprintf(fp, "             mod_flags: %lx  (", lm->mod_flags);
		if (lm->mod_flags & MOD_EXT_SYMS)
			fprintf(fp, "%sMOD_EXT_SYMS", others++ ? "|" : "");
		if (lm->mod_flags & MOD_LOAD_SYMS)
			fprintf(fp, "%sMOD_LOAD_SYMS", others++ ? "|" : "");
		if (lm->mod_flags & MOD_REMOTE)
			fprintf(fp, "%sMOD_REMOTE", others++ ? "|" : "");
		if (lm->mod_flags & MOD_KALLSYMS)
			fprintf(fp, "%sMOD_KALLSYMS", others++ ? "|" : "");
		if (lm->mod_flags & MOD_INITRD)
			fprintf(fp, "%sMOD_INITRD", others++ ? "|" : "");
		fprintf(fp, ")\n");

        	fprintf(fp, "          mod_symtable: %lx\n",
			(ulong)lm->mod_symtable);
        	fprintf(fp, "            mod_symend: %lx\n",
			(ulong)lm->mod_symend);

                fprintf(fp, "        mod_ext_symcnt: %ld\n",
                        lm->mod_ext_symcnt);
        	fprintf(fp, "      mod_ext_symtable: %lx\n",
			(ulong)lm->mod_ext_symtable);
        	fprintf(fp, "        mod_ext_symend: %lx\n",
			(ulong)lm->mod_ext_symend);

		fprintf(fp, "       mod_load_symcnt: %ld\n", 
			lm->mod_load_symcnt);
		fprintf(fp, "     mod_load_symtable: %lx\n", 
			(ulong)lm->mod_load_symtable);
		fprintf(fp, "       mod_load_symend: %lx\n", 
			(ulong)lm->mod_load_symend);

        	fprintf(fp, "    mod_load_namespace: ");
                fprintf(fp, "address: %lx  ", 
                        (ulong)lm->mod_load_namespace.address);
                fprintf(fp, "index: %ld  ", 
                        lm->mod_load_namespace.index);
                fprintf(fp, "size: %ld  ", 
                        (ulong)lm->mod_load_namespace.size);
                fprintf(fp, "cnt: %ld\n", 
                        lm->mod_load_namespace.cnt);

		fprintf(fp, "          mod_symalloc: %ld\n", lm->mod_symalloc);
		fprintf(fp, "    mod_size_of_struct: %ld (%lx)\n",
			lm->mod_size_of_struct, lm->mod_size_of_struct); 
		fprintf(fp, "        mod_text_start: %lx (%lx)\n", 
			lm->mod_text_start,
			lm->mod_text_start ?
			lm->mod_text_start - lm->mod_base : 0);
		fprintf(fp, "       mod_etext_guess: %lx (%lx)\n",
                        lm->mod_etext_guess,
                        lm->mod_etext_guess ?
                        lm->mod_etext_guess - lm->mod_base : 0);
                fprintf(fp, "      mod_rodata_start: %lx (%lx)\n",
                        lm->mod_rodata_start,
                        lm->mod_rodata_start ?
                        lm->mod_rodata_start - lm->mod_base : 0);
		fprintf(fp, "        mod_data_start: %lx (%lx)\n", 
			lm->mod_data_start,
			lm->mod_data_start ?
			lm->mod_data_start - lm->mod_base : 0);
                fprintf(fp, "         mod_bss_start: %lx (%lx)\n",
                        lm->mod_bss_start,
                        lm->mod_bss_start ?
                        lm->mod_bss_start - lm->mod_base : 0);

		fprintf(fp, "          mod_sections: %d\n", lm->mod_sections);
		fprintf(fp, "      mod_section_data: %lx %s\n",
			(ulong)lm->mod_section_data,
			lm->mod_section_data ? "" : "(not allocated)");


		for (s = 0; s < lm->mod_sections; s++) {
			fprintf(fp, 
                "       %12s  prio: %x  flags: %05x  offset: %-8lx size: %lx\n",
				lm->mod_section_data[s].name,
				lm->mod_section_data[s].priority,
				lm->mod_section_data[s].flags,
				lm->mod_section_data[s].offset,
				lm->mod_section_data[s].size);
		}

		if (CRASHDEBUG(1)) {
        		for (sp = lm->mod_load_symtable; 
			     sp < lm->mod_load_symend; sp++) {
				fprintf(fp, "  %lx  %s\n",
					sp->value, sp->name);	
			}
                }
	}
}


/*
 *  Determine whether a file is in ELF format by checking the magic number
 *  in the first EI_NIDENT characters of the file; if those match, check
 *  whether the file is a known BFD format.
 */
int
is_elf_file(char *s)
{
	int fd;
	char magic[EI_NIDENT];

	if ((fd = open(s, O_RDONLY)) < 0) {
		error(INFO, "%s: %s\n", s, strerror(errno));
		return FALSE;
	}
	if (read(fd, magic, EI_NIDENT) != EI_NIDENT) {
                /* error(INFO, "%s: %s\n", s, strerror(errno)); */
		close(fd);
		return FALSE;
	}  
	close(fd);

	magic[EI_CLASS] = NULLCHAR;

	if (!STREQ(magic, ELFMAG))
		return FALSE;

	return(is_bfd_format(s));
}

/*
 *  Given a choice between two namelists, pick the one for gdb to use.
 *  For now, just check get their stats and check their sizes; the larger 
 *  one presumably has debug data.
 */
int
select_namelist(char *new)
{
	struct stat stat1, stat2;

	if (pc->server_namelist) {
        	pc->namelist_debug = new;
		return TRUE;
	}

	if (!file_exists(pc->namelist, &stat1) ||
	    !file_exists(new, &stat2)) {
		return FALSE;
	}

	if (stat1.st_size > stat2.st_size) {
		pc->namelist_debug = pc->namelist;
		pc->namelist = new;		
	} else if (stat2.st_size > stat1.st_size) 
		pc->namelist_debug = new;
	else {
		error(INFO, "cannot distinguish %s and %s\n",
			pc->namelist, new);
		return FALSE;
	}

	return TRUE;
}

/*
 *  Make a sweep of a non-dump, non-ELF file to guess whether it's a
 *  legitimate System.map file.
 */
int 
is_system_map(char *s)
{
	int i, lines, retval;
        char *mapitems[MAXARGS];
	char buf[16384];
	FILE *map;

       /*
	*  First simulate what "file" does by verifying that the first 16K
        *  bytes are ascii data.
	*/
        if ((map = fopen(s, "r")) == NULL) {
                error(INFO, "cannot open %s\n", s);
		return FALSE;
	}

	retval = FALSE;
        if (fread(buf, sizeof(char), 16384, map) != (16384*sizeof(char))) {
		if (CRASHDEBUG(1))
			error(INFO, "%s: cannot read 16K\n", s);
		goto not_system_map;
	}

	for (i = 0; i < 16384; i++) {
		if (!ascii(buf[i]))
			goto not_system_map;
	}

	rewind(map);

	for (lines = 0; lines < 100; lines++) {
		if (!fgets(buf, BUFSIZE, map)) 
			goto not_system_map;
		if (parse_line(buf, mapitems) != 3)
                        goto not_system_map;
		if ((strlen(mapitems[0]) != MAX_HEXADDR_STRLEN) ||
		    !hexadecimal(mapitems[0], 0) || (strlen(mapitems[1]) > 1))
			goto not_system_map;
	}

	if ((pc->flags & SYSMAP) && !same_file("/boot/System.map", s))
		error(INFO, "overriding /boot/System.map with %s\n", s);

	retval = TRUE;

not_system_map:

	fclose(map);
	return retval;
}

/*
 *  Check whether a file is a known BFD format.
 */
static int
is_bfd_format(char *filename) 
{
#if defined(GDB_6_0) || defined(GDB_6_1)
        struct bfd *bfd;
#else
        struct _bfd *bfd;
#endif
        char **matching;

        if ((bfd = bfd_openr(filename, NULL)) == NULL) 
                return FALSE;
        
        if (!bfd_check_format_matches(bfd, bfd_object, &matching)) {
                bfd_close(bfd);
                return FALSE;
        }
     
        bfd_close(bfd);
        return TRUE;
}


/*
 *  This command may be used to:
 *
 *   1. Translate a symbol to its value.
 *   2. Translate a value to it symbol.
 *   3. List all stored symbols.
 *   4. Query for symbols containing a string.
 *   5. Show the next and previous symbols.
 */
void
cmd_sym(void)
{
	int c;
	struct syment *sp, *spp, *spn;
	ulong value, show_flags; 
	ulong offset;
	int next, prev, multiples, others;
	char *name;
	int errflag;
	char buf[BUFSIZE];

	next = prev = others = 0;
	show_flags = SHOW_LINENUM | SHOW_RADIX();

        while ((c = getopt(argcnt, args, "lLQ:q:npsMm:")) != EOF) {
                switch(c)
		{
		case 'n':
			next++;
			break;

		case 'p':
			prev++;
			break;

                case 'Q':
                        fprintf(fp, "%d found ", 
				symbol_query(optarg, NULL, &sp));
			if (sp)
				fprintf(fp, "(%s)", sp->name);
			fprintf(fp, "\n");
                        others++;
                        break;
		
		case 'q':
			if (!symbol_query(optarg, "", NULL))
				fprintf(fp, "(none found)\n");
			others++;
			break;

		case 'm':
			symbol_dump(MODULE_SYMS, optarg);
                        others++;
                        break;

		case 'M':
			symbol_dump(MODULE_SYMS, NULL);
			others++;
			break;

		case 'L': /* obsolete */
		case 'l':
			symbol_dump(KERNEL_SYMS|MODULE_SYMS, NULL);
			others++;
			break;

		case 's':
			show_flags &= ~SHOW_LINENUM;
			show_flags |= SHOW_SECTION;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

        if (args[optind]) {
                do {
			name = NULL;
			multiples = 0;
			sp = NULL;

			if (hexadecimal(args[optind], 0)) {
				errflag = 0;
				value = htol(args[optind], RETURN_ON_ERROR,
					&errflag);
				if (errflag || !in_ksymbol_range(value)) {
					error(INFO, "invalid address: %s\n",
						args[optind]);
				} else if ((sp = value_search(value, &offset))){
					name = sp->name;
					if (prev && 
					    (spp = prev_symbol(NULL, sp))) 
						show_symbol(spp, 0, show_flags);

					show_symbol(sp, offset, show_flags);
				}
				else if (module_symbol(value, &sp, 
				        NULL, buf, output_radix)) {
					name = buf;

                                        if (prev && sp && 
					    (spp = prev_symbol(NULL, sp))) 
						show_symbol(spp, 0, show_flags);
					
					fprintf(fp, "%lx (?) %s\n",	
						value, buf);
				} else 
					fprintf(fp, "symbol not found: %s\n",
						args[optind]);
			} else {
				if ((sp = symbol_search(args[optind]))) {
					multiples = symbol_name_count(sp->name);
do_multiples:
					name = sp->name;
					if (prev && 
					    (spp = prev_symbol(NULL, sp)))
						show_symbol(spp, 0, show_flags);
					
					show_symbol(sp, 0, show_flags);
				}
				else {
					fprintf(fp, "symbol not found: %s\n",
						args[optind]);
					fprintf(fp, "possible alternatives:\n");
					if (!symbol_query(args[optind], "  ", 
					    NULL))
						fprintf(fp, "  (none found)\n");
				}
			}

			if (name && next && (spn = next_symbol(NULL, sp))) 
				show_symbol(spn, 0, show_flags);

			if (multiples > 1) {
				if ((sp = symbol_search_next(name, sp)))
					goto do_multiples;
			}

			optind++;
                } while(args[optind]);
        }
        else if (!others) 
		cmd_usage(pc->curcmd, SYNOPSIS);
}

/*
 *  Common symbol display for cmd_sym().
 */
void
show_symbol(struct syment *sp, ulong offset, ulong show_flags)
{
	char buf[BUFSIZE];
	char *p1;
	ulong radix;

	switch (show_flags & (SHOW_HEX_OFFS|SHOW_DEC_OFFS))
	{
	case SHOW_DEC_OFFS:
		radix = 10;
		break;

	default:
	case SHOW_HEX_OFFS:
		radix = 16;
		break;
	}


	if (MODULE_START(sp)) {
		p1 = sp->name + strlen("_MODULE_START_");
		fprintf(fp, "%lx (%c) (%s module)", sp->value, sp->type, p1);
		if (offset)
			fprintf(fp, (radix == 16) ? "+0x%lx" : "+%ld", 
				offset);
		fprintf(fp, "\n");
		return;
	}

        if (offset)
                fprintf(fp, (radix == 16) ?
			"%lx (%c) %s+0x%lx  " : "%lx (%c) %s+%ld  ", 
			sp->value+offset, sp->type, sp->name, offset);
        else
                fprintf(fp, "%lx (%c) %s  ", sp->value, sp->type, sp->name);

        if (is_kernel_text(sp->value+offset) && 
	    (show_flags & SHOW_LINENUM))
                fprintf(fp, "%s", 
			get_line_number(sp->value+offset, buf, TRUE));

	if (show_flags & SHOW_SECTION)
                fprintf(fp, "[%s]", get_section(sp->value+offset, buf));
		

	fprintf(fp, "\n");
}

/*
 *  Use the gdb_interface to get a line number associated with a 
 *  text address -- but first check whether the address gets past 
 *  any machine-dependent line_number_hooks reference.
 */
char *
get_line_number(ulong addr, char *buf, int strip_usr_src)
{
	char *p;
	struct gnu_request request, *req;
	struct line_number_hook *lnh;
	char bldbuf[BUFSIZE], *name;

	buf[0] = NULLCHAR;
	if (!is_kernel_text(addr) || GDB_PATCHED()) 
		return(buf);

	if ((lnh = machdep->line_number_hooks)) {
        	name = closest_symbol(addr);
		while (lnh->func) {
                	if (STREQ(name, lnh->func)) {
                                sprintf(buf, "%s/%s",
                                        get_build_directory(bldbuf) ?
                                        bldbuf : "..", *(lnh->file));
				break;
			}
			lnh++;
		}
	}

	if (!strlen(buf)) {
		req = &request;
		BZERO(req, sizeof(struct gnu_request));
		req->command = GNU_GET_LINE_NUMBER;
		req->addr = addr;
		req->buf = buf;
		gdb_interface(req);
	}

	if (strip_usr_src && STRNEQ(buf, "/usr/src")) {
		p = buf + strlen("/usr/src");
		strcpy(buf, "..");
		strcpy(&buf[2], p);
	}

	return(buf);
}

static char *
get_section(ulong vaddr, char *buf)
{
	int i;
	asection **sec;
	asection *section;
	ulong start, end;
	struct load_module *lm;

	buf[0] = NULLCHAR;

	if (module_symbol(vaddr, NULL, &lm, NULL, output_radix)) {
		if (lm->mod_flags & MOD_LOAD_SYMS) { 
			for (i = (lm->mod_sections-1); i >= 0; i--) {
                                start = lm->mod_base +
                                        lm->mod_section_data[i].offset;
                                end = start + lm->mod_section_data[i].size;

                                if ((vaddr >= start) && (vaddr < end)) {
                                        strcpy(buf, 
						lm->mod_section_data[i].name);
					break;
				}
                        }
		} else
			sprintf(buf, "in %s module", lm->mod_name);
	} else {
	        sec = (asection **)st->sections;
	        for (i = 0; i < st->bfd->section_count; i++, sec++) {
			section = *sec;
	                start = (ulong)bfd_get_section_vma(st->bfd, section);
	                end = start + (ulong)bfd_section_size(st->bfd, section);
	
	                if ((vaddr >= start) && (vaddr < end)) {
				strcpy(buf, bfd_get_section_name(st->bfd, 
					section));
				break;
			}
		}
	}

	return buf;
}

/*
 *  Get the kernel build directory.
 */
char *
get_build_directory(char *buf)
{
	char *p;

	if (symbol_exists("schedule"))
		get_line_number(symbol_value("schedule"), buf, FALSE); 
	else if (symbol_exists("do_schedule"))
		get_line_number(symbol_value("do_schedule"), buf, FALSE); 
	else
		return NULL;
	if ((p = strstr(buf, "/kernel/")))
		*p = NULLCHAR;
	else
		return(NULL);

	return buf;
}
/*
 *  Search for all symbols containing a string.
 */
int 
symbol_query(char *s, char *print_pad, struct syment **spp)
{
	int i;
        struct syment *sp, *sp_end;
	struct load_module *lm;
	int cnt;

	cnt = 0;

        for (sp = st->symtable; sp < st->symend; sp++) {
		if (strstr(sp->name, s)) {
			if (print_pad) {
				if (strlen(print_pad))
					fprintf(fp, "%s", print_pad);
				show_symbol(sp, 0, SHOW_RADIX());
			}
			if (spp)
				*spp = sp;
			cnt++;
		}
	}

	for (i = 0; i < st->mods_installed; i++) {
		lm = &st->load_modules[i];
		sp = lm->mod_symtable;
		sp_end = lm->mod_symend;

		for ( ; sp < sp_end; sp++) {
			if (MODULE_START(sp))
				continue;

			if (strstr(sp->name, s)) {
				if (print_pad) {
					if (strlen(print_pad))
						fprintf(fp, "%s", print_pad);
					show_symbol(sp, 0, SHOW_RADIX());
				}
				if (spp)
					*spp = sp;
				cnt++;
			}
		}
	}
	
	return(cnt);
}


/*
 *  Return the syment of a symbol.
 */
struct syment *
symbol_search(char *s)
{
	int i;
        struct syment *sp_hashed, *sp, *sp_end;
	struct load_module *lm;
	int pseudos;

	sp_hashed = symname_hash_search(s);

        for (sp = sp_hashed ? sp_hashed : st->symtable; sp < st->symend; sp++) {
                if (STREQ(s, sp->name)) 
                        return(sp);
        }

	pseudos = (strstr(s, "_MODULE_START_") || strstr(s, "_MODULE_END_"));

        for (i = 0; i < st->mods_installed; i++) {
                lm = &st->load_modules[i];
		sp = lm->mod_symtable;
                sp_end = lm->mod_symend;

                for ( ; sp < sp_end; sp++) {
                	if (!pseudos && MODULE_PSEUDO_SYMBOL(sp))
                        	continue;

                	if (STREQ(s, sp->name))
                        	return(sp);
                }
        }

        return((struct syment *)NULL);
}

/*
 *  Count the number of instances of a symbol name.
 */
static int
symbol_name_count(char *s)
{
        int i;
        struct syment *sp, *sp_end;
        struct load_module *lm;
        int count, pseudos;

	count = 0;

        for (sp = st->symtable; sp < st->symend; sp++) {
                if (STREQ(s, sp->name)) {
			count = sp->cnt;
			break;
		}
        }

        pseudos = (strstr(s, "_MODULE_START_") || strstr(s, "_MODULE_END_"));

        for (i = 0; i < st->mods_installed; i++) {
                lm = &st->load_modules[i];
                sp = lm->mod_symtable;
                sp_end = lm->mod_symend;
 
                for ( ; sp < sp_end; sp++) {
                        if (!pseudos && MODULE_PSEUDO_SYMBOL(sp))
                                continue;
 
                        if (STREQ(s, sp->name))
				count++;
                }
        }

        return(count);
}

/*
 *  Return the syment of the next symbol with the same name of the input symbol.
 */
static struct syment *
symbol_search_next(char *s, struct syment *spstart)
{
	int i;
        struct syment *sp, *sp_end;
	struct load_module *lm;
	int found_start;
	int pseudos;

	found_start = FALSE;

        for (sp = st->symtable; sp < st->symend; sp++) {
		if (sp == spstart) {
			found_start = TRUE;
			continue;
		} else if (!found_start)
			continue;

                if (strcmp(s, sp->name) == 0) {
                        return(sp);
		}
        }

	pseudos = (strstr(s, "_MODULE_START_") || strstr(s, "_MODULE_END_"));

        for (i = 0; i < st->mods_installed; i++) {
                lm = &st->load_modules[i];
		sp = lm->mod_symtable;
                sp_end = lm->mod_symend;

                for ( ; sp < sp_end; sp++) {
                	if (!pseudos && MODULE_PSEUDO_SYMBOL(sp))
                        	continue;

			if (sp == spstart) {
				found_start = TRUE;
				continue;
			} else if (!found_start)
				continue;

                	if (STREQ(s, sp->name))
                        	return(sp);
                }
        }

        return((struct syment *)NULL);
}

/*
 *  Determine whether an address falls within the kernel's, or any module's,
 *  address space.
 */
int
in_ksymbol_range(ulong value)
{
        if ((value >= st->symtable[0].value) && 
	    (value <= st->symtable[st->symcnt-1].value))
                return TRUE;

	if (module_symbol(value, NULL, NULL, NULL, output_radix))
		return TRUE;

	if (machdep->value_to_symbol(value, NULL))
		return TRUE;

        return FALSE;
}

/*
 *  Determine whether an address falls within any module's address space.
 *  If syment or load_module pointers are passed, send them back.
 *  If a pointer to a name buffer is passed, stuff it with the particulars.
 */
int
module_symbol(ulong value, 
	      struct syment **spp, 
	      struct load_module **lmp,
	      char *name,
	      ulong radix)
{
        int i;
	struct load_module *lm;
	struct syment *sp;
	long mcnt;
	char buf[BUFSIZE];
	ulong offs, offset;

	if (NO_MODULES())
		return FALSE;

        if (!radix)
                radix = output_radix;
        if ((radix != 10) && (radix != 16))
                radix = 16;

        mcnt = 0;
	for (i = 0; i < st->mods_installed; i++) {
		lm = &st->load_modules[i];

		if ((value >= lm->mod_base) && 
		    (value < (lm->mod_base + lm->mod_size))) {
			if (lmp) 
				*lmp = lm;

			if (name) {
				offs = value - lm->mod_base;
        			if ((sp = value_search(value, &offset))) {
                			if (offset)
                        			sprintf(buf, radix == 16 ? 
						     "%s+0x%lx" : "%s+%ld",
						        sp->name, offset);
                			else
                        			sprintf(buf, "%s", sp->name);
					strcpy(name, buf);
					if (spp)
						*spp = sp;
					return TRUE;
        			}

				sprintf(name, "(%s module)", lm->mod_name);

				if (offs) {
					sprintf(buf, radix == 16 ?
						"+0x%lx" : "+%ld", offs);
					strcat(name, buf);
				}
			}
			return TRUE;
		}
	}

	return FALSE;
}

/*
 *  Return the syment of the symbol closest to the value, along with
 *  the offset from the symbol value if requested.
 */
struct syment *
value_search(ulong value, ulong *offset)
{
	int i;
        struct syment *sp, *sp_end, *spnext, *splast;
	struct load_module *lm;

        if (!in_ksymbol_range(value))
                return((struct syment *)NULL);

	if ((sp = machdep->value_to_symbol(value, offset)))
		return sp;

	if (IS_VMALLOC_ADDR(value)) 
		goto check_modules;

	if ((sp = symval_hash_search(value)) == NULL)
		sp = st->symtable;
 
        for ( ; sp < st->symend; sp++) {
                if (value == sp->value) {
                        if (offset) 
				*offset = 0;
                        return((struct syment *)sp);
                }
                if (sp->value > value) {
			if (offset)
                        	*offset = value - ((sp-1)->value);
                        return((struct syment *)(sp-1));
                }
        }

check_modules:
        for (i = 0; i < st->mods_installed; i++) {
                lm = &st->load_modules[i];
		sp = lm->mod_symtable;
                sp_end = lm->mod_symend;

		if (sp->value > value)  /* invalid -- between modules */
			break;

	       /*
		*  splast will contain the last module symbol encountered.
		*  Note: "__insmod_"-type symbols will be set in splast only 
                *  when they have unique values.
		*/
		splast = NULL;
                for ( ; sp < sp_end; sp++) {
                	if (value == sp->value) {
				if (MODULE_START(sp)) {
					spnext = sp+1;
					if (spnext->value == value)
						sp = spnext;
				}
				if (is_insmod_builtin(lm, sp)) {
					spnext = sp+1;
					if ((spnext < sp_end) &&
					    (value == spnext->value)) 
						sp = spnext;
				}
                        	if (offset)
					*offset = 0;
                        	return((struct syment *)sp);
                	}

                	if (sp->value > value) {
				sp = splast ? splast : sp - 1;
                        	if (offset)
					*offset = value - sp->value;
                        	return(sp);
                	}

			if (!MODULE_PSEUDO_SYMBOL(sp)) {
				if (is_insmod_builtin(lm, sp)) {
					if (!splast || 
					    (sp->value > splast->value)) 
						splast = sp;
					 
				} else
					splast = sp;
			}
                }
        }

        return((struct syment *)NULL);
}

/*
 *  Search for a value only within the base kernel's symbols,
 *  also avoiding the machdep->value_to_symbol() call, which will
 *  most likely be the prime consumer of this call. 
 */
struct syment *
value_search_base_kernel(ulong value, ulong *offset)
{
        struct syment *sp, *splast;

        if (value < st->symtable[0].value)
        	return((struct syment *)NULL);

	if ((sp = symval_hash_search(value)) == NULL)
		sp = st->symtable;
 
        for ( ; sp < st->symend; sp++) {
                if (value == sp->value) {
                        if (offset) 
				*offset = 0;
                        return((struct syment *)sp);
                }
                if (sp->value > value) {
			if (offset)
                        	*offset = value - ((sp-1)->value);
                        return((struct syment *)(sp-1));
                }
		splast = sp;
        }

	/* 
	 *  If we go off the end, just use the last symbol plus offset.
	 */
	sp = st->symend;
	if (offset) 
        	*offset = value - ((sp-1)->value);
        return((struct syment *)(sp-1));
}

/*
 *  Allow platforms to assign symbols to their own special values.
 */
struct syment *
generic_machdep_value_to_symbol(ulong value, ulong *offset)
{
	return NULL;
}	


/*
 *  For a given value, format a string containing the nearest symbol name
 *  plus the offset if appropriate.  Display the offset in the specified
 *  radix (10 or 16) -- if it's 0, set it to the current pc->output_radix.
 */
char *
value_to_symstr(ulong value, char *buf, ulong radix)
{
        struct syment *sp;
        ulong offset;
	char *p1, locbuf[BUFSIZE];
	struct load_module *lm;

	sp = NULL;
	offset = 0;
	buf[0] = NULLCHAR;

	if (!radix)
		radix = output_radix;
	if ((radix != 10) && (radix != 16))
		radix = 16;

        if ((sp = value_search(value, &offset))) {
                if (offset)
                        sprintf(buf, radix == 16 ? "%s+0x%lx" : "%s+%ld",
				sp->name, offset);
                else
                        sprintf(buf, "%s", sp->name);
        }

	if (module_symbol(value, NULL, NULL, locbuf, output_radix)) {
		if (sp) {
			if (STRNEQ(locbuf, "_MODULE_START_"))
				shift_string_left(locbuf, 
					strlen("_MODULE_START_"));
			if ((p1 = strstr(locbuf, "+")))
				*p1 = NULLCHAR;

			if (offset) {
				if (is_module_name(locbuf, NULL, &lm) &&
				    (value < lm->mod_text_start)) 
					sprintf(buf, radix == 16 ?
						"(%s module)+0x%lx" :
						"(%s module)+%ld",
						locbuf, offset);
				else
					sprintf(buf, radix == 16 ?
						"%s+0x%lx" : "%s+%ld",
						locbuf, offset);
			} else {
				if (is_module_name(locbuf, NULL, &lm) &&
				    (value < lm->mod_text_start))
					sprintf(buf, "(%s)", locbuf);
				else
					sprintf(buf, "%s", locbuf);
			}
		} else  
			sprintf(buf, "%s", locbuf);
	}

        return(buf);
}

/*
 *  For a given value, return the closest (lower-in-value) symbol name.
 */
char *
closest_symbol(ulong value)
{
        struct syment *sp;

        if ((sp = value_search(value, NULL))) 
        	return(sp->name);
        else 
		return(NULL);
}

/*
 *  Same as above, but return the closest (lower-in-value) symbol value.
 */
ulong
closest_symbol_value(ulong value)
{
        struct syment *sp;

        if ((sp = value_search(value, NULL)))
                return(sp->value);
        else
                return(0);
}

/*
 *  For a given symbol, return a pointer to the next (higher) symbol's syment. 
 *  Either a symbol name or syment pointer may be passed as an argument.
 */
struct syment *
next_symbol(char *symbol, struct syment *sp_in)
{
	int i;
	int found;
        struct syment *sp, *sp_end;
	struct load_module *lm;
	char buf[BUFSIZE], *p1;

	if (!symbol && !sp_in)
		error(FATAL, "next_symbol: two NULL args!\n");

	if (sp_in) {
		found = FALSE;
	        for (sp = st->symtable; sp < st->symend; sp++) {
	                if (sp == sp_in) 
	                        found = TRUE;
	                else if (found) {
				if (sp->value > sp_in->value)
					return sp;
			}
	        }
	
	        for (i = 0; i < st->mods_installed; i++) {
	                lm = &st->load_modules[i];
	                sp = lm->mod_symtable;
	                sp_end = lm->mod_symend;
	
	                for ( ; sp < sp_end; sp++) {
	                        if (MODULE_PSEUDO_SYMBOL(sp))
	                                continue;
                       		if (sp == sp_in) 
                                	found = TRUE;
                        	else if (found) {
					if ((sp->value == sp_in->value) &&
					    is_insmod_builtin(lm, sp))
						continue;
                                	return sp;
				}
	                }
	        }

		return NULL;
	}


	/*
	 *  Deal with a few special cases...
	 */
	if (strstr(symbol, " module)")) {
                sprintf(buf, "_MODULE_START_");
                strcat(buf, &symbol[1]);
                p1 = strstr(buf, " module)");
                *p1 = NULLCHAR;
                symbol = buf;
	}

	if (STREQ(symbol, "_end")) {
		if (!st->mods_installed)
			return NULL;

                lm = &st->load_modules[0];

		return lm->mod_symtable;
	}

        if ((sp = symbol_search(symbol))) {
		sp++;
		if (MODULE_END(sp)) {
			sp--;
			i = load_module_index(sp);
			if ((i+1) == st->mods_installed)
				return NULL;

			lm = &st->load_modules[i+1];

			sp = lm->mod_symtable;
		}
		return sp;
	}

        return NULL;
}

/*
 * For a given symbol, return a pointer to the previous (lower) symbol's syment.
 * Either a symbol name or syment pointer may be passed as an argument.
 */
struct syment *
prev_symbol(char *symbol, struct syment *sp_in)
{
	int i;
        struct syment *sp, *sp_end, *sp_prev;
	char buf[BUFSIZE], *p1;
	struct load_module *lm;

       if (!symbol && !sp_in)
                error(FATAL, "prev_symbol: two NULL args!\n");

	if (sp_in) {
		sp_prev = NULL;
                for (sp = st->symtable; sp < st->symend; sp++) {
                        if (sp == sp_in)
                                return sp_prev;
			sp_prev = sp;
                }

                for (i = 0; i < st->mods_installed; i++) {
                        lm = &st->load_modules[i];
                        sp = lm->mod_symtable;
                        sp_end = lm->mod_symend;

                        for ( ; sp < sp_end; sp++) {
                                if (MODULE_PSEUDO_SYMBOL(sp))
                                        continue;
                                if (sp == sp_in)
                                        return sp_prev;

                                if (is_insmod_builtin(lm, sp)) {
                                        if (sp->value > sp_prev->value)
                                                sp_prev = sp;
                                } else
                                	sp_prev = sp;
                        }
                }

                return NULL;
	}

        if (strstr(symbol, " module)")) {
		sprintf(buf, "_MODULE_START_");
                strcat(buf, &symbol[1]);
                p1 = strstr(buf, " module)");
                *p1 = NULLCHAR;
                symbol = buf;
        }

        if ((sp = symbol_search(symbol))) {
		if (sp == st->symtable)
			return((struct syment *)NULL);

		if (module_symbol(sp->value, NULL, NULL, NULL, 0)) {
			if (MODULE_START(sp)) {
				i = load_module_index(sp);
				if (i == 0)
					sp = symbol_search("_end");
				else {
					lm = &st->load_modules[i-1];
					sp = lm->mod_symend;
					sp--;
				}
			} else
				sp--;
		} else
			sp--;

		return sp;
	}

        return NULL;
}


/*
 *  Read the specified amount of data from the given symbol's value.
 */
void
get_symbol_data(char *symbol, long size, void *local)
{
        struct syment *sp;

        if ((sp = symbol_search(symbol))) 
                readmem(sp->value, KVADDR, local,
                        size, symbol, FAULT_ON_ERROR);
        else 
                error(FATAL, "cannot resolve: \"%s\"\n", symbol);
}

/*
 *  Same as above, but allow for failure.
 */
int
try_get_symbol_data(char *symbol, long size, void *local)
{
        struct syment *sp;

        if ((sp = symbol_search(symbol)) &&
            readmem(sp->value, KVADDR, local,
            size, symbol, RETURN_ON_ERROR|QUIET))
			return TRUE;

	return FALSE;
}

/*
 *  Return the value of a given symbol.
 */
ulong
symbol_value(char *symbol)
{
        struct syment *sp;

        if (!(sp = symbol_search(symbol)))
                error(FATAL, "cannot resolve \"%s\"\n", symbol);

        return(sp->value);
}

/*
 *  Return the symbol name of a given value, with no allowance for offsets.
 *  Returns NULL on failure to allow for testing of a value.
 */
char *
value_symbol(ulong value)
{
        struct syment *sp;
	ulong offset;

        if ((sp = value_search(value, &offset))) {
                if (offset)
                        return NULL;
                else
                        return sp->name;
        }

	return NULL;
}


/*
 *  Determine whether a symbol exists.
 */
int
symbol_exists(char *symbol)
{
	int i;
        struct syment *sp, *sp_end;
	struct load_module *lm;

	if ((sp = symname_hash_search(symbol)))
		return TRUE;

        for (i = 0; i < st->mods_installed; i++) {
                lm = &st->load_modules[i];
		sp = lm->mod_symtable;
                sp_end = lm->mod_symend;

                for ( ; sp < sp_end; sp++) {
                	if (STREQ(symbol, sp->name))
                        	return(TRUE);
                }
	}

        return(FALSE);
}

/*
 *  Determine whether a static kernel symbol exists.
 */
int
kernel_symbol_exists(char *symbol)
{
	struct syment *sp;

        if ((sp = symname_hash_search(symbol)))
                return TRUE;
	else
        	return FALSE;
}

/*
 *  Return the number of instances of a symbol name along with pointers to
 *  their syment structures.
 */
int
get_syment_array(char *symbol, struct syment **sp_array, int max)
{
        int i, cnt;
        struct syment *sp, *sp_end;
        struct load_module *lm;

	cnt = 0;

        for (sp = st->symtable; sp < st->symend; sp++) {
                if ((*symbol == *(sp->name)) && STREQ(symbol, sp->name)) {
			if (!sp_array) 
				return sp->cnt;
			if (max) { 
				if (cnt == max) {
					error(INFO, 
					    "symbol count overflow (%s)\n",
						symbol); 
					return cnt;
				} else
					sp_array[cnt] = sp;
			}
			if (sp->cnt == 1)
				return 1;
			cnt++;
		}
        }

        for (i = 0; i < st->mods_installed; i++) {
                lm = &st->load_modules[i];
                sp = lm->mod_symtable;
                sp_end = lm->mod_symend;

                for ( ; sp < sp_end; sp++) {
                        if (STREQ(symbol, sp->name)) {
				if (max && (cnt < max))
                                	sp_array[cnt] = sp;
                                cnt++;
			}
                }
        }

        return cnt;
}

/*
 *  Perform any datatype-related initializations here.  
 */
void
datatype_init(void)
{
	BNEG(&offset_table, sizeof(offset_table));
	BNEG(&size_table, sizeof(size_table));
	BZERO(&array_table, sizeof(array_table));
}

/*
 *  This function is called through the following macros:
 *
 *   #define STRUCT_SIZE(X)      datatype_info((X), NULL, NULL)
 *   #define UNION_SIZE(X)       datatype_info((X), NULL, NULL)
 *   #define DATATYPE_SIZE(X)    datatype_info((X)->name, NULL, (X))
 *   #define MEMBER_OFFSET(X,Y)  datatype_info((X), (Y), NULL)
 *   #define STRUCT_EXISTS(X)    (datatype_info((X), NULL, NULL) >= 0)
 *   #define MEMBER_EXISTS(X,Y)  (datatype_info((X), (Y), NULL) >= 0)
 *   #define MEMBER_SIZE(X,Y)    datatype_info((X), (Y), MEMBER_SIZE_REQUEST)
 *
 *  to determine structure or union sizes, or member offsets.
 */
long
datatype_info(char *name, char *member, struct datatype_member *dm)
{
	struct gnu_request *req;
        long offset, size, member_size;
	int member_typecode;
        ulong type_found;
	char buf[BUFSIZE];

	strcpy(buf, name);

	req = (struct gnu_request *)GETBUF(sizeof(struct gnu_request));
	req->command = GNU_GET_DATATYPE;
	req->flags |= GNU_RETURN_ON_ERROR;
	req->name = buf;
	req->member = member;
	req->fp = pc->nullfp;

	gdb_interface(req);
        if (req->flags & GNU_COMMAND_FAILED) {
		FREEBUF(req);
		return -1;
	}

	if (!req->typecode) {
		sprintf(buf, "struct %s", name);
		gdb_interface(req);
	}

	if (!req->typecode) {
		sprintf(buf, "union %s", name);
		gdb_interface(req);
	}

	if (CRASHDEBUG(2)) {
		if (req->typecode) {
			console("name: %s ", req->name);
			if (member)
				console("member: %s ", req->member);
			console("typecode: %d%s ", req->typecode,
				req->is_typedef ? " (TYPEDEF)" : "");
			console("length: %ld ", req->length);
			console("member_offset: %ld\n", req->member_offset);
		}
		else
			console("%s: unknown\n", name);
	}

	switch (req->typecode)
	{
	case TYPE_CODE_STRUCT:
		type_found = STRUCT_REQUEST;
		size = req->length;
                if (req->member_offset >= 0) {
                        offset = req->member_offset/BITS_PER_BYTE;
                        member_size = req->member_length;
                        member_typecode = req->member_typecode;
                } else {
                        offset = -1;
                        member_size = 0;
                        member_typecode = TYPE_CODE_UNDEF;
                }
		break;

	case TYPE_CODE_UNION:
		type_found = UNION_REQUEST;
		size = req->length;
		if (req->member_offset >= 0) {
			offset = req->member_offset/BITS_PER_BYTE;
			member_size = req->member_length;
			member_typecode = req->member_typecode;
		} else {
			offset = -1;
			member_size = 0;
			member_typecode = TYPE_CODE_UNDEF;
		}
		break;

	case TYPE_CODE_RANGE:
	case TYPE_CODE_INT:
		size = req->length;
		offset = 0;
		switch (size)
		{
		case SIZEOF_64BIT: 
			type_found = INT64; 
			break;
		case SIZEOF_32BIT:
			type_found = INT32;
			break;
		case SIZEOF_16BIT:
			type_found = INT16;
			break;
		case SIZEOF_8BIT:
			type_found = INT8;
			break; 
		}
		break;

	case TYPE_CODE_PTR:
		size = req->length;
		offset = 0;
		type_found = POINTER;
		break;

	case TYPE_CODE_FUNC:
                size = req->length;
                offset = 0;
                type_found = FUNCTION;
                break;

	case TYPE_CODE_ARRAY:
		size = req->length;
		offset = 0;
		type_found = ARRAY;
		break;

	case TYPE_CODE_ENUM:
		size = req->length;
		offset = 0;
		type_found = ENUM;
		break;	

	default:
		type_found = 0;
		size = -1;
		offset = -1;
		break;
	}

	FREEBUF(req);

        if (dm && (dm != MEMBER_SIZE_REQUEST)) {
                dm->type = type_found;
                dm->size = size;
		dm->member_size = member_size;
		dm->member_typecode = member_typecode;
		if (req->is_typedef) {
			dm->flags |= TYPEDEF;
		}
		if (req->tagname) {
			dm->tagname = req->tagname;
			dm->value = req->value;
		}
        }

        if (!type_found) 
        	return -1;

	if (dm == MEMBER_SIZE_REQUEST)
		return member_size;
        else if (member) 
		return offset;
	else
                return size;
}

/*
 *  Get the basic type info for a symbol.  Let the caller pass in the 
 *  gnu_request structure to have access to the full response; in either
 *  case, return the type code.  The member field can be used for structures
 *  with no type names, and if there, the member data will be filled in
 *  as well.
 */
int
get_symbol_type(char *name, char *member, struct gnu_request *caller_req)
{
	struct gnu_request *req;
	int typecode;

	if (!caller_req) 
		req = (struct gnu_request *)GETBUF(sizeof(struct gnu_request));
	else {
		req = caller_req;
		BZERO(req, sizeof(struct gnu_request));
	}

	req->command = GNU_GET_SYMBOL_TYPE;
	req->name = name;
	req->member = member;
	req->flags = GNU_RETURN_ON_ERROR; 

        gdb_interface(req);

        if (req->flags & GNU_COMMAND_FAILED) 
                typecode = TYPE_CODE_UNDEF;
	else if (member) {
		if (req->member_offset >= 0)
			typecode = req->member_typecode;
		else
			typecode = TYPE_CODE_UNDEF;
	} else
		typecode = req->typecode;

	if (!caller_req)
		FREEBUF(req);

	return(typecode);
}


/*
 *  Externally available routine to dump a structure at an address.
 */
void
dump_struct(char *s, ulong addr, unsigned radix)
{
	unsigned restore_radix;
	long len;

	if ((len = STRUCT_SIZE(s)) < 0)
		error(FATAL, "invalid structure name: %s\n", s);

	if (radix) {
		restore_radix = output_radix; 
		output_radix = radix;
		output_format = (output_radix == 10) ? 0 : 'x';
	}

        print_struct(s, addr);

	if (radix) {
		output_radix = restore_radix;
		output_format = (output_radix == 10) ? 0 : 'x';
	}
}

/*
 *  Externally available routine to dump a structure member, given the
 *  base structure address.  The input string must be in struct.member format.
 */
void
dump_struct_member(char *s, ulong addr, unsigned radix)
{
	struct datatype_member datatype_member, *dm;
        unsigned restore_radix;
	char *buf, *p1;

	buf = GETBUF(strlen(s)+1);
	strcpy(buf, s);

	p1 = strstr(buf, ".");
	*p1 = NULLCHAR;
	p1++;

	dm = &datatype_member;
	dm->name = buf;
	dm->member = p1;
        
        if (!STRUCT_EXISTS(dm->name)) {
		FREEBUF(buf);
                error(FATAL, "invalid structure name: %s\n", dm->name);
	}
	if (!MEMBER_EXISTS(dm->name, dm->member)) {
		FREEBUF(buf);
                error(FATAL, "invalid structure member name: %s\n", 
			dm->member);
	}
 
        if (radix) {
                restore_radix = output_radix; 
                output_radix = radix;
                output_format = (output_radix == 10) ? 0 : 'x';
        }
                
        open_tmpfile();
        print_struct(dm->name, addr);
        parse_for_member(dm, PARSE_FOR_DATA);
        close_tmpfile();
                
        if (radix) {
                output_radix = restore_radix;
                output_format = (output_radix == 10) ? 0 : 'x';
        }

	FREEBUF(buf);
}


/*
 *  Externally available routine to dump a union at an address.
 */
void
dump_union(char *s, ulong addr, unsigned radix)
{
	unsigned restore_radix;
        long len;

        if ((len = UNION_SIZE(s)) < 0)
                error(FATAL, "invalid union name: %s\n", s);

        if (radix) {
                restore_radix = output_radix;
                output_radix = radix;
		output_format = (output_radix == 10) ? 0 : 'x';
        }

        print_union(s, addr);

        if (radix) {
                output_radix = restore_radix;
		output_format = (output_radix == 10) ? 0 : 'x';
	}
}

/*
 * This command displays either a structure definition, or a formatted display
 * of the contents of a structure at a specified address.  If no address is
 * specified, the structure size and the file in which the structure is defined
 * are also displayed.  A structure member may be appended to the structure 
 * name (in a "struct.member" format) in order to limit the scope of the data
 * displayed to that particular member.  Structure data is shown in hexadecimal
 * format.  The raw data in a structure may be dumped with the -r flag.
 */
void
cmd_struct(void)
{
	int c;
	ulong addr, aflag;
	struct syment *sp;
	int rawdata;
	long len;
	ulong flags;
	ulong list_head_offset;
	int count;
        struct datatype_member struct_member, *sm;

        sm = &struct_member;
	count = 1;
	rawdata = 0;
	aflag = 0;
	list_head_offset = 0;
	flags = STRUCT_REQUEST;

        while ((c = getopt(argcnt, args, "c:rvol:")) != EOF) {
                switch(c)
		{
		case 'c':
			count = atoi(optarg);
			break;

		case 'r':
			rawdata = 1;
			break;

		case 'v':
			flags |= STRUCT_VERBOSE;
			break;

		case 'o':
			flags |= SHOW_OFFSET;
			break;

		case 'l':
                        if (IS_A_NUMBER(optarg))
                                list_head_offset = stol(optarg,
                                        FAULT_ON_ERROR, NULL);
                        else if (arg_to_datatype(optarg,
                                sm, RETURN_ON_ERROR) > 1)
                                list_head_offset = sm->member_offset;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs || !args[optind])
		cmd_usage(pc->curcmd, SYNOPSIS);

	if ((arg_to_datatype(args[optind++], sm, FAULT_ON_ERROR) > 1) && 
	    rawdata)
        	error(FATAL, "member-specific output not allowed with -r\n");

	if ((len = sm->size) < 0) {
		error(INFO, "structure not found: %s\n", sm->name);
		cmd_usage(pc->curcmd, SYNOPSIS); 
	}
	
	if (!args[optind]) {
		do_datatype_declaration(sm, flags | (sm->flags & TYPEDEF));
		return;
	}

	while (args[optind]) {
		if (clean_arg() && IS_A_NUMBER(args[optind])) { 
			if (aflag) 
				count = stol(args[optind], 
					FAULT_ON_ERROR, NULL);
			else {
				if (!IS_KVADDR(addr = htol(args[optind], 
                                    FAULT_ON_ERROR, NULL)))
					error(FATAL, 
					"invalid kernel virtual address: %s\n",
						args[optind]);
				aflag++;
			}
		}
	        else if ((sp = symbol_search(args[optind]))) {
	                addr = sp->value;
			aflag++;
	        } else {
			fprintf(fp, "symbol not found: %s\n", args[optind]);
	                fprintf(fp, "possible aternatives:\n");
	                if (!symbol_query(args[optind], "  ", NULL))
	                   	fprintf(fp, "  (none found)\n");
			return;
		}
		optind++;
	}

	if (!aflag)
		error(FATAL, "no kernel virtual address argument entered\n");

	if (list_head_offset)
		addr -= list_head_offset;

	if (count < 0) {
		addr -= len * abs(count);
		addr += len;
	}

	for (c =  0; c < abs(count); c++, addr += len) {
		if (rawdata) 
			raw_data_dump(addr, len, flags & STRUCT_VERBOSE);
		else {
			if (sm->member) 
				open_tmpfile();

			print_struct(sm->name, addr);

			if (sm->member) {
				parse_for_member(sm, PARSE_FOR_DATA);
				close_tmpfile();
			}
		}
	}
}

/*
 *  After determining what type of data type follows the *, this routine
 *  has the identical functionality as cmd_struct() or cmd_union().
 */
void 
cmd_pointer(void)
{
	int c;
	ulong addr, aflag;
	struct syment *sp;
	int rawdata;
	long len;
	ulong flags;
	int count;
        struct datatype_member datatype_member, *dm;

        dm = &datatype_member;
	rawdata = 0;
	flags = 0;
	aflag = 0;
	count = 1;

        while ((c = getopt(argcnt, args, "c:rvo")) != EOF) {
                switch(c)
		{
                case 'c':
                        count = atoi(optarg);
                        break;

		case 'r':
			rawdata = 1;
			break;

		case 'v':
			flags |= STRUCT_VERBOSE;
			break;

		case 'o':
			flags |= SHOW_OFFSET;
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs || !args[optind])
		cmd_usage(pc->curcmd, SYNOPSIS);

	if ((arg_to_datatype(args[optind++], dm, FAULT_ON_ERROR) > 1) && 
	     rawdata)
        	error(FATAL, "member-specific output not allowed with -r\n");

	if ((len = dm->size) < 0) {
		error(INFO, "structure or union not found: %s\n", dm->name);
		cmd_usage(pc->curcmd, SYNOPSIS);
	}

	flags |= dm->type;

	if (!args[optind]) {
		do_datatype_declaration(dm, flags | (dm->flags & TYPEDEF));
                return;
	}

	while (args[optind]) {
		if (clean_arg() && IS_A_NUMBER(args[optind])) { 
                        if (aflag)
                                count = stol(args[optind],
                                        FAULT_ON_ERROR, NULL);
                        else {
                                if (!IS_KVADDR(addr = htol(args[optind],
                                    FAULT_ON_ERROR, NULL)))
                                        error(FATAL,
                                        "invalid kernel virtual address: %s\n",
                                                args[optind]);
                                aflag++;
                        }
		}
	        else if ((sp = symbol_search(args[optind]))) {
	                addr = sp->value;
			aflag++;
	        } else {
			fprintf(fp, "symbol not found: %s\n", args[optind]);
	                fprintf(fp, "possible aternatives:\n");
	                if (!symbol_query(args[optind], "  ", NULL))
	                   	fprintf(fp, "  (none found)\n");
			return;
		}
		optind++;
	}

	if (!(flags & (UNION_REQUEST|STRUCT_REQUEST)))
		error(FATAL, "invalid argument!");

        if (!aflag) 
                error(FATAL, "no kernel virtual address argument entered\n");

	if (count < 0) {
		addr -= len * abs(count);
		addr += len;
	}

        for (c =  0; c < abs(count); c++, addr += len) {
                if (rawdata)
                        raw_data_dump(addr, len, flags & STRUCT_VERBOSE);
                else {
                        if (dm->member)
                                open_tmpfile();

        		if (flags & UNION_REQUEST)
                		print_union(dm->name, addr);
        		else if (flags & STRUCT_REQUEST)
                		print_struct(dm->name, addr);

                        if (dm->member) {
                                parse_for_member(dm, PARSE_FOR_DATA);
                                close_tmpfile();
                        }
                }
        }
}

/*
 * This command displays either a union definition, or a formatted display
 * of the contents of a union at a specified address.  If no address is
 * specified, the union size and the file in which the union is defined
 * are also displayed.  A union member may be appended to the union
 * name (in a "union.member" format) in order to limit the scope of the data 
 * displayed to that particular member.  Structure data is shown in hexadecimal
 * format.  The raw data in a union may be dumped with the -r flag.
 */
void
cmd_union(void)
{
	int c;
	ulong addr, aflag;
	struct syment *sp;
	int rawdata;
	long len;
	ulong flags;
	int count;
        struct datatype_member union_member, *um;
	ulong list_head_offset;

        um = &union_member;
	count = 1;
	rawdata = 0;
	aflag = 0;
	list_head_offset = 0;
	flags = UNION_REQUEST;

        while ((c = getopt(argcnt, args, "c:rvol:")) != EOF) {
                switch(c)
		{
		case 'c':
			count = atoi(optarg);
			break;

		case 'r':
			rawdata = 1;
			break;

		case 'v':
			flags |= STRUCT_VERBOSE;
			break;

		case 'o':
			flags |= SHOW_OFFSET;
			break;

                case 'l':
                        if (IS_A_NUMBER(optarg))
                                list_head_offset = stol(optarg,
                                        FAULT_ON_ERROR, NULL);
                        else if (arg_to_datatype(optarg,
                                um, RETURN_ON_ERROR) > 1)
                                list_head_offset = um->member_offset;
                        break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs || !args[optind])
		cmd_usage(pc->curcmd, SYNOPSIS);

	if ((arg_to_datatype(args[optind++], um, FAULT_ON_ERROR) > 1) && 
	     rawdata)
        	error(FATAL, "member-specific output not allowed with -r\n");

	if ((len = um->size) < 0)  {
		error(INFO, "union not found: %s\n", um->name);
		cmd_usage(pc->curcmd, SYNOPSIS);
	}
	
	if (!args[optind]) {
		do_datatype_declaration(um, flags | (um->flags & TYPEDEF));
                return;
	}

	while (args[optind]) {
		if (clean_arg() && IS_A_NUMBER(args[optind])) { 
                        if (aflag)
                                count = stol(args[optind],
                                        FAULT_ON_ERROR, NULL);
                        else {
                                if (!IS_KVADDR(addr = htol(args[optind],
                                    FAULT_ON_ERROR, NULL)))
                                        error(FATAL,
                                        "invalid kernel virtual address: %s\n",
                                                args[optind]);
                                aflag++;
                        }
		}
	        else if ((sp = symbol_search(args[optind]))) {
	                addr = sp->value;
			aflag++;
		} else {
			fprintf(fp, "symbol not found: %s\n", args[optind]);
	                fprintf(fp, "possible aternatives:\n");
	                if (!symbol_query(args[optind], "  ", NULL))
	                   	fprintf(fp, "  (none found)\n");
			return;
		}
		optind++;
	}

        if (!aflag) 
                error(FATAL, "no kernel virtual address argument entered\n");

	if (list_head_offset)
		addr -= list_head_offset;

	if (count < 0) {
		addr -= len * abs(count);
		addr += len;
	}

	for (c = 0; c < abs(count); c++, addr += len) {
		if (rawdata) 
			raw_data_dump(addr, len, flags & STRUCT_VERBOSE);
		else {
			if (um->member)
				open_tmpfile();

			print_union(um->name, addr);

			if (um->member) {
				parse_for_member(um, PARSE_FOR_DATA);
				close_tmpfile();
			}
		}
	}
}

/*
 *  Generic function for dumping data structure declarations, with a small
 *  fixup for typedefs, sizes and member offsets.
 */
static void
do_datatype_declaration(struct datatype_member *dm, ulong flags)
{
	long len;
	char buf[BUFSIZE];
        char *p1, *p2, *multiline;
	FILE *sfp;

	if (CRASHDEBUG(1))
		dump_datatype_member(fp, dm);

        open_tmpfile();
        whatis_datatype(dm->name, flags);
        rewind(pc->tmpfile);

	if (dm->member)
		flags |= SHOW_OFFSET;

	sfp = pc->saved_fp;
	len = dm->size;
	multiline = NULL;
        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
                if (STRNEQ(buf, "type = ")) {
			multiline = strstr(buf, "{");
			if (flags & TYPEDEF)
				fprintf(sfp, "typedef ");
                        p1 = buf + strlen("type = ");
			if ((p2 = strstr(buf, "(*)()"))) { 
				*p2 = NULLCHAR;
				fprintf(sfp, "%s(*%s)();\n",
						p1, dm->name);
			} else if ((p2 = strstr(buf, "()"))) {
				*p2 = NULLCHAR;
				fprintf(sfp, "%s(%s)();\n", p1, dm->name);
			} else if (multiline) 
				fprintf(sfp, "%s", p1);
			else 
				fprintf(sfp, "%s %s;\n",
					strip_linefeeds(p1), dm->name);
                } else {
			if (multiline && STRNEQ(buf, "}") && (flags & TYPEDEF)){
				if (strstr(buf, "} **()"))
					fprintf(sfp, "} **(%s)();\n", dm->name);
				else
					fprintf(sfp, "%s %s;\n", 
						strip_linefeeds(buf), dm->name);
			} else {
				if ((flags & SHOW_OFFSET) && whitespace(buf[0]))
					show_member_offset(sfp, dm, buf);
				else
                                        fprintf(sfp, buf);
			}
		}
        }

	if (!dm->member) {
		switch (output_radix)
		{
		default:
		case 10:
               		fprintf(sfp, "SIZE: %ld\n", len);
			break;
		case 16:
               		fprintf(sfp, "SIZE: 0x%lx\n", len);
			break;
		}
	}

        close_tmpfile();
}


/*
 *  Take a argument string, which may be in "struct.member" or "union.member"
 *  format, figure out whether it's a structure or a union reference, and
 *  fill in the appropriate fields of the dataytype_member structure.
 *  Return 1 if it's a straight struct or union reference, 2 if it has
 *  a legitimate .member attached to it, or 0 if it's bogus.
 */
int
arg_to_datatype(char *s, struct datatype_member *dm, ulong flags) 
{
	char *p1;
	int both;
	
	BZERO(dm, sizeof(struct datatype_member));

	dm->name = s;

	if (!(p1 = strstr(s, "."))) 
		both = FALSE;
	else {
		if ((p1 == s) || !strlen(p1+1))
        		goto datatype_member_fatal;
        	*p1 = NULLCHAR;
       		if (strstr(p1+1, ".")) 
                	goto datatype_member_fatal;

		both = TRUE;
	}

	if ((dm->size = DATATYPE_SIZE(dm)) < 0) {
		if (flags & RETURN_ON_ERROR)
			goto datatype_member_fatal;

		error(FATAL, 
              "cannot handle \"%s\": try \"gdb whatis\" or \"gdb ptype\"\n", s);
	}

	if (!both) 
		return 1;

	dm->member = p1+1;

    	if ((dm->member_offset = MEMBER_OFFSET(dm->name, dm->member)) < 0) 
		goto datatype_member_fatal;

	return 2;

datatype_member_fatal:

	if (flags & RETURN_ON_ERROR) {
		if (both)
			*p1 = '.';
		return 0;
	}

	if (both) {
		*p1 = '.';
		if (strstr(p1+1, ".")) 
                	error(FATAL, "only one %s member allowed: %s\n",
			    (dm->type == STRUCT_REQUEST) ? "struct" :
			    ((dm->type == UNION_REQUEST) ? 
			    "union" : "struct/union"), s);
	}

       	return (error(FATAL, "invalid argument: %s\n", s));
}

/*
 *  debug routine -- not called on purpose by anybody.
 */
static void
dump_datatype_member(FILE *ofp, struct datatype_member *dm)
{
	int others;

	others = 0;
        fprintf(ofp, "         name: %s\n", dm->name);
        fprintf(ofp, "       member: %s\n", dm->member);
        fprintf(ofp, "         type: %lx (", dm->type);
	if (dm->type & STRUCT_REQUEST)
		fprintf(ofp, "%sSTRUCT_REQUEST", others++ ? "|" : "");
        if (dm->type & UNION_REQUEST)
		fprintf(fp, "%sUNION_REQUEST", others++ ? "|" : "");
        if (dm->type & INT64) 
		fprintf(ofp, "%sINT64", others++ ? "|" : "");
        if (dm->type & INT32)
		fprintf(ofp, "%sINT32", others++ ? "|" : "");
        if (dm->type & INT16)
		fprintf(ofp, "%sINT16", others++ ? "|" : "");
        if (dm->type & INT8)
		fprintf(ofp, "%sINT8", others++ ? "|" : "");
        if (dm->type & POINTER)
		fprintf(ofp, "%sPOINTER", others++ ? "|" : "");
        if (dm->type & FUNCTION)
		fprintf(ofp, "%sFUNCTION", others++ ? "|" : "");
        if (dm->type & ARRAY)
		fprintf(ofp, "%sARRAY", others++ ? "|" : "");
        if (dm->type & ENUM)
		fprintf(ofp, "%sENUM", others++ ? "|" : "");
        if (dm->type & IN_UNION)
		fprintf(ofp, "%sIN_UNION", others++ ? "|" : "");
        if (dm->type & IN_STRUCT)
		fprintf(ofp, "%sIN_STRUCT", others++ ? "|" : "");
	fprintf(ofp, ")\n");
        fprintf(ofp, "         size: %ld\n", dm->size);
        fprintf(ofp, "member_offset: %ld\n", dm->member_offset);
        fprintf(ofp, "  member_size: %ld\n", dm->member_size);
        fprintf(ofp, "        flags: %lx ", dm->flags);
	dump_datatype_flags(dm->flags, ofp);
	fprintf(ofp, "\n");
}

/*
 *  This command displays the definition of structures, unions, typedefs or
 *  text/data symbols:  
 *
 *  1. For a structure name, the output is the same as if the "struct"
 *     command was used.
 *  2. For a union name, the output is the same as if the "union" command
 *     was used.
 *  3. For a typedef name that translates to a structure or union, the output
 *     is the same as if the "struct" or "union" command was used. 
 *  4. For a typedef name that translates to a primitive datatype, the one-line
 *     declaration is displayed.
 *  5. For a kernel symbol name, the output is the same as if the "sym" command
 *     was used.
 */
void
cmd_whatis(void)
{
        struct datatype_member datatype_member, *dm;
	struct syment *sp;
        char buf[BUFSIZE];
	long len;
	int c;
        ulong flags;

        dm = &datatype_member;
	flags = 0;

        while ((c = getopt(argcnt, args, "o")) != EOF) {
                switch(c)
                {
		case 'o':
			flags |= SHOW_OFFSET;
			break;

                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs || !args[optind])
                cmd_usage(pc->curcmd, SYNOPSIS);

	if (STREQ(args[optind], "struct") || 
	    STREQ(args[optind], "union") ||
	    STREQ(args[optind], "enum"))
		optind++;
	else if ((sp = symbol_search(args[optind]))) {
		whatis_variable(sp);
		return;
	}

	if (!args[optind])
                cmd_usage(pc->curcmd, SYNOPSIS);

        if (arg_to_datatype(args[optind], dm, RETURN_ON_ERROR)) {
		if ((len = dm->size) < 0) 
			goto whatis_failure;

		flags |= dm->type;

		if (dm->type == ENUM) {
			if (dm->tagname)
				fprintf(fp, "%senum%s%s = %ld\n",
					dm->flags & TYPEDEF ? "typedef " : "",
					strlen(dm->tagname) ? " " : "",
					dm->tagname, dm->value);
			else 
				dump_enumerator_list(args[optind]);

			return;
		}

		do_datatype_declaration(dm, flags | (dm->flags & TYPEDEF));
	} else {
		if (!gdb_whatis(concat_args(buf, 1, FALSE))) 
			goto whatis_failure;
	} 

	return;

whatis_failure:

        error(INFO, "cannot resolve: %s\n", concat_args(buf, 1, FALSE));
	cmd_usage(pc->curcmd, SYNOPSIS);

}

/*
 *  Try gdb's whatis on a command string. 
 */
static int
gdb_whatis(char *s)
{
	char buf[BUFSIZE], *p1;

	open_tmpfile();
        sprintf(buf, "whatis %s", s);
        if (!gdb_pass_through(buf, fp, GNU_RETURN_ON_ERROR)) {
		close_tmpfile();
		return FALSE;
	}

        rewind(pc->tmpfile);
        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
		p1 = buf;
		if (STRNEQ(buf, "type = "))
			p1 += strlen("type = ");
		fprintf(pc->saved_fp, p1);
        }

	close_tmpfile();

	return TRUE;
}

/*
 *  Given the name of an enum, have gdb dump its enumertor list.
 */
static void
dump_enumerator_list(char *e)
{
        struct gnu_request *req;

        req = (struct gnu_request *)GETBUF(sizeof(struct gnu_request));
        req->command = GNU_GET_DATATYPE;
        req->name = e;
	req->flags = GNU_PRINT_ENUMERATORS;

        gdb_interface(req);

	FREEBUF(req);
}

/*
 *  Given the name of an enum, return its value.
 */
int 
enumerator_value(char *e, long *value) 
{
	struct datatype_member datatype_member, *dm;

	dm = &datatype_member;

        if (arg_to_datatype(e, dm, RETURN_ON_ERROR)) {
                if ((dm->size >= 0) && 
		    (dm->type == ENUM) && dm->tagname) {
			*value = dm->value;
			return TRUE;
		}
	}

	return FALSE;
}

/*
 *  Verify that a datatype exists, but return on error.
 */
int
datatype_exists(char *s)
{
	int retval;
	char buf[BUFSIZE], *p;
        struct gnu_request *req;

	strcpy(buf, s);
	if ((p = strstr(buf, ".")))
		*p = NULLCHAR;

        req = (struct gnu_request *)GETBUF(sizeof(struct gnu_request));
        req->command = GNU_GET_DATATYPE;
        req->name = buf;
        req->flags = GNU_RETURN_ON_ERROR;
	req->fp = pc->nullfp;

        gdb_interface(req);

	retval = req->typecode;

        FREEBUF(req);

	return retval;
}


/*
 *  Set the output radix if requested, and pass it on to gdb.
 */
void
cmd_p(void)
{
        int c;
	struct syment *sp;
	unsigned restore_radix;
	int leader, do_load_module_filter, success;
	char buf1[BUFSIZE]; 
	char buf2[BUFSIZE]; 
	char *p1;

	leader = do_load_module_filter = restore_radix = 0;

        while ((c = getopt(argcnt, args, "dhx")) != EOF) {
                switch(c)
                {
		case 'd':
			restore_radix = output_radix;
			output_radix = 10;
                	output_format = (output_radix == 10) ? 0 : 'x';
			break;

		case 'h':
		case 'x':
                        restore_radix = output_radix;
                        output_radix = 16;
                        output_format = (output_radix == 10) ? 0 : 'x';
                        break;

                default:
                        argerrs++;
                        break;
                }
        }

        if (argerrs || !args[optind])
                cmd_usage(pc->curcmd, SYNOPSIS);

	if ((sp = symbol_search(args[optind])) && !args[optind+1]) {
		sprintf(buf2, "%s = ", args[optind]);
		leader = strlen(buf2);
		if (module_symbol(sp->value, NULL, NULL, NULL, output_radix))
			do_load_module_filter = TRUE;
	} else if (st->flags & LOAD_MODULE_SYMS)
		do_load_module_filter = TRUE;

	if (leader || do_load_module_filter)
		open_tmpfile();

       	success = gdb_pass_through(concat_args(buf1, 0, TRUE), NULL, 
		GNU_RETURN_ON_ERROR);

	if (success && (leader || do_load_module_filter)) {
		int firstline;

		if (leader) {
			fprintf(pc->saved_fp, buf2); 
			fflush(pc->saved_fp);
		}

		firstline = TRUE;
		rewind(pc->tmpfile);
                while (fgets(buf1, BUFSIZE, pc->tmpfile)) {
			if (firstline && 
			    (p1 = strstr(buf1, "{")) &&
			    !STRNEQ(p1, "{\n")) { 
				*p1 = NULLCHAR;
				fprintf(pc->saved_fp, buf1);
				fprintf(pc->saved_fp, "\n {%s", p1+1);
			} else 
				fprintf(pc->saved_fp, do_load_module_filter ?
				    load_module_filter(buf1, LM_P_FILTER) : 
				    buf1);

			firstline = FALSE;
		}
	}

	if (leader || do_load_module_filter)
		close_tmpfile();

	if (restore_radix) {
                output_radix = restore_radix;
                output_format = (output_radix == 10) ? 0 : 'x';
	}

	if (!success) 
		error(FATAL, "gdb request failed: %s\n",
			concat_args(buf1, 0, TRUE));
}

/*
 *  As a latch ditch effort before a command is thrown away by exec_command(),
 *  args[0] is checked to see whether it's the name of a variable, structure, 
 *  union, or typedef.  If so, args[0] is changed to the appropriate command, 
 *  i.e., "p", "struct", "union", or "whatis", and the original args are all 
 *  shifted into the next higer args[] location.
 */
int
is_datatype_command(void)
{
	int i;
	long len;
	char *command;
	struct datatype_member datatype_member, *dm;
	struct syment *sp;
	char *rdarg;
	char buf[BUFSIZE];

	if (!args[0])
		return FALSE;

	strcpy(buf, args[0]);
	dm = &datatype_member;

	if ((sp = symbol_search(args[0])) && (argcnt == 1)) {
		if (is_gdb_command(FALSE, RETURN_ON_ERROR)) { 
			pc->curcmd = pc->program_name;
			error(FATAL, 
		            "ambiguous command: %s (symbol and gdb command)\n", 
				args[0]);
		}
		command = "p";
	} else if (STREQ(args[0], "enum"))
		command = "whatis";
	else if (!datatype_exists(args[0]))
		return FALSE;
	else if (!arg_to_datatype(buf, dm, RETURN_ON_ERROR)) {
		return FALSE;
	} else {
                if (is_gdb_command(FALSE, RETURN_ON_ERROR)) {
			pc->curcmd = pc->program_name;
                	error(FATAL, 
		   "ambiguous command: %s (symbol/data type and gdb command)\n",
				args[0]);
		}

		if ((sp = symbol_search(args[0])) && (argcnt == 1)) {
			command = "p";
			dm->type = 0;
		} else if ((len = DATATYPE_SIZE(dm)) < 0) {
			return FALSE;
		} else if (sp) {
			command = "p";
			dm->type = 0;
		}

		switch (dm->type)
		{
		case STRUCT_REQUEST:
			if ((dm->flags & TYPEDEF) && (argcnt == 1))
				command = "whatis";
			else
	               		command = "struct";
			break;

		case UNION_REQUEST:
                        if ((dm->flags & TYPEDEF) && (argcnt == 1))
                                command = "whatis";
                        else
                                command = "union";
                        break;

		case POINTER:
			command = "whatis";
			break;

		case ARRAY:
			command = "whatis";
			break;

		case FUNCTION:
			command = "whatis";
			break;

		case ENUM:
			command = "whatis";
			break;

		default:
			if (dm->type & INTEGER_TYPE) { 
				switch (dm->type)
				{
				case INT64: rdarg = "-64"; break;
				case INT32: rdarg = "-32"; break;
				case INT16: rdarg = "-16"; break;
				case  INT8: rdarg =  "-8"; break;
				}

				if (args[1]) {
					if ((sp = symbol_search(args[1]))) {
						command = "p";
						args[0] = args[1];
						argcnt--;
					} else {
						command = "rd";
						args[0] = rdarg;
					}
				} else
					command = "whatis";
			} else 
				return FALSE;
			break;
		}
	}

	for (i = argcnt; i; i--) 
		args[i] = args[i-1];
	args[0] = command;
	argcnt++;

	return TRUE;
}

/*
 *  Given a structure name and an address, have gdb do most of the work.
 */
static void
print_struct(char *s, ulong addr)
{
	char buf[BUFSIZE];

	if (is_typedef(s))
        	sprintf(buf, "output *(%s *)0x%lx", s, addr);
	else
        	sprintf(buf, "output *(struct %s *)0x%lx", s, addr);
	fprintf(fp, "struct %s ", s);
        gdb_pass_through(buf, NULL, 0);
	fprintf(fp, "\n");
}


/*
 *  Given a union name and an address, let gdb do the work.
 */
static void
print_union(char *s, ulong addr)
{
	char buf[BUFSIZE];

        if (is_typedef(s))
                sprintf(buf, "output *(%s *)0x%lx", s, addr);
        else 
        	sprintf(buf, "output *(union %s *)0x%lx", s, addr);
        fprintf(fp, "union %s ", s);
        gdb_pass_through(buf, NULL, 0);
}

/*
 *  Given a structure or union, find its definition in the datatype symbol
 *  file, and dump it.  If the verbose flags is set, everything from the
 *  file is shown; otherwise the bitpos, size and id data is stripped.
 */
static void 
whatis_datatype(char *st, ulong flags)
{
	char lookbuf[BUFSIZE];

	if (flags & TYPEDEF) 
                sprintf(lookbuf, "ptype %s", st);
        else if (flags & UNION_REQUEST)
                sprintf(lookbuf, "ptype union %s", st);
        else if (flags & STRUCT_REQUEST)
                sprintf(lookbuf, "ptype struct %s", st);
        else
                return;

	if (!gdb_pass_through(lookbuf, fp, GNU_RETURN_ON_ERROR)) {
		/*
		 *  When a structure is defined using the format:
                 *
                 *    typedef struct {
		 *        yada yada yada
		 *    } type_t;
                 *
                 *  gdb says it's a structure and not a typedef.  So
                 *  if the union or struct pass-through fails, it can't
                 *  hurt to retry it with just "ptype type_t" before
                 *  giving up.
                 */
		if (flags & (UNION_REQUEST|STRUCT_REQUEST)) {
                	sprintf(lookbuf, "ptype %s", st);
			gdb_pass_through(lookbuf, fp, 0);
		}
	}
}

/*
 *  Scan the symbol file for a variable declaration.
 */
static void
whatis_variable(struct syment *sp)
{
	char *p1;
	char buf[BUFSIZE];

        open_tmpfile();
        sprintf(buf, "whatis %s", sp->name);
        if (!gdb_pass_through(buf, fp, GNU_RETURN_ON_ERROR)) {
                close_tmpfile();
                error(FATAL, "gdb request failed: whatis %s\n", sp->name);
        }

        rewind(pc->tmpfile);
        while (fgets(buf, BUFSIZE, pc->tmpfile)) {
                if (STRNEQ(buf, "type = ")) 
			break;
        }
        close_tmpfile();

	clean_line(buf);

	if ((p1 = strstr(buf, "["))) {
		shift_string_right(p1, strlen(sp->name));
		BCOPY(sp->name, p1, strlen(sp->name));
        	p1 = buf + strlen("type = ");
		fprintf(fp, "%s;\n", p1);
	} else if ((p1 = strstr(buf, "("))) {
		if (index(buf, '(') == rindex(buf, '(')) {
			shift_string_right(p1, strlen(sp->name));
			BCOPY(sp->name, p1, strlen(sp->name));
		} else {
			p1 = strstr(buf, ")");
			shift_string_right(p1, strlen(sp->name));
			BCOPY(sp->name, p1, strlen(sp->name));
		}
		p1 = buf + strlen("type = ");
                fprintf(fp, "%s;\n", p1);
	} else {
        	p1 = buf + strlen("type = ");
                fprintf(fp, "%s%s%s;\n", p1, LASTCHAR(p1) == '*' ? "":" ",
			sp->name);
	}
}

/*
 *  Determines whether the current structure or union member is a typedef.
 */
static int 
is_typedef(char *name)
{
	struct datatype_member datatype_member, *dm;

	if (!name)
		drop_core("is_typedef() received NULL name string\n");

	dm = &datatype_member;
        BZERO(dm, sizeof(struct datatype_member));
	dm->name = name;
	return (DATATYPE_SIZE(dm) < 0 ? FALSE : (dm->flags & TYPEDEF));
}

static void
dump_datatype_flags(ulong flags, FILE *ofp)
{
	int others;

	others = 0;

	fprintf(ofp, "(");
	if (flags & UINT8)
		fprintf(ofp, "%sUINT8", others++ ? "|" : "");
	if (flags & INT8)
		fprintf(ofp, "%sINT8", others++ ? "|" : "");
	if (flags & UINT16)
		fprintf(ofp, "%sUINT16", others++ ? "|" : "");
	if (flags & INT16)
		fprintf(ofp, "%sINT16", others++ ? "|" : "");
	if (flags & UINT32)
		fprintf(ofp, "%sUINT32", others++ ? "|" : "");
	if (flags & INT32)
		fprintf(ofp, "%sINT32", others++ ? "|" : "");
	if (flags & UINT64)
		fprintf(ofp, "%sUINT64", others++ ? "|" : "");
	if (flags & INT64)
		fprintf(ofp, "%sINT64", others++ ? "|" : "");
	if (flags & POINTER)
		fprintf(ofp, "%sPOINTER", others++ ? "|" : "");
        if (flags & FUNCTION)
                fprintf(ofp, "%sFUNCTION", others++ ? "|" : "");
	if (flags & ARRAY)
		fprintf(ofp, "%sARRAY", others++ ? "|" : "");
	if (flags & ENUM)
		fprintf(ofp, "%sENUM", others++ ? "|" : "");
	if (flags & TYPEDEF)
		fprintf(ofp, "%sTYPEDEF", others++ ? "|" : "");
	if (flags & STRUCT_VERBOSE)
		fprintf(ofp, "%sSTRUCT_VERBOSE", others++ ? "|" : "");
	if (flags & SHOW_OFFSET)
		fprintf(ofp, "%sSHOW_OFFSET", others++ ? "|" : "");
	fprintf(ofp, ")\n");
}

/*
 *  When a request is made to print just a member of a structure or union,
 *  the whole datatype is dumped to a temporary file, and this routine
 *  parses through it for the targeted member.
 */
static void
parse_for_member(struct datatype_member *dm, ulong flag)
{
	char *s;
	char buf[BUFSIZE];
	char lookfor1[BUFSIZE];
	char lookfor2[BUFSIZE];
	char lookfor3[BUFSIZE];
	char lookfor4[BUFSIZE];
	char lookfor5[BUFSIZE];
	long curpos, last_open_bracket;
	int indent, on, array;

	s = dm->member;
	indent = 0;
	array = FALSE;
	on = 0;
	rewind(pc->tmpfile);

	switch (flag)  
	{
	case PARSE_FOR_DATA:
		sprintf(lookfor1, "  %s ", s);
		sprintf(lookfor2, "  %s[", s);
next_item:
		while (fgets(buf, BUFSIZE, pc->tmpfile)) {
			if (STRNEQ(buf, lookfor1) || STRNEQ(buf, lookfor2)) {
				on++;
				if (strstr(buf, "= {")) 
					indent = count_leading_spaces(buf);
				if (strstr(buf, "["))
					array = TRUE;
			}
	
			if (on) {
				if ((indent && (on > 1) && (count_leading_spaces(buf) == indent) &&
				    !strstr(buf, "}")) || (buf[0] == '}')) {
					break;
				}
				fprintf(pc->saved_fp, buf);
				if (!indent)
					break;
				if (strstr(buf, "}") && 
				    (count_leading_spaces(buf) == indent))
					break;
				on++;
			}
		}
		if (array) {
			on = array = FALSE;
			on = 0;
			goto next_item; 
		}
		break;

	case PARSE_FOR_DECLARATION:
		last_open_bracket = curpos = 0;

		sprintf(lookfor1, " %s;", s);
		sprintf(lookfor2, "*%s;", s);
		sprintf(lookfor3, " %s[", s);
		sprintf(lookfor4, "*%s[", s);
		sprintf(lookfor5, " %s :", s);

                while (fgets(buf, BUFSIZE, pc->tmpfile)) {
			indent = count_leading_spaces(buf);

			switch (indent)
			{
			case 0:
				curpos = ftell(pc->tmpfile);
				continue;

			case INITIAL_INDENT:
				if (strstr(buf, "{"))
					last_open_bracket = curpos;
				break;

			default:
				if (!on && (indent != INITIAL_INDENT)) 
					continue;
			}

                        if (strstr(buf, lookfor1) || 
			    strstr(buf, lookfor2) ||
			    strstr(buf, lookfor3) ||
			    strstr(buf, lookfor4) ||
			    strstr(buf, lookfor5)) {
				if (strstr(buf, "}") && !on) {
					on = TRUE;
					fseek(pc->tmpfile, last_open_bracket,
						SEEK_SET);
				} else {
					print_verbatim(pc->saved_fp, buf);
					if (indent == INITIAL_INDENT)
                                		break;
				}
                        }
			else if (on)
				print_verbatim(pc->saved_fp, buf);

			curpos = ftell(pc->tmpfile);
                }

		break;
	}
}

/*
 *  Dig out a member name from a formatted gdb structure declaration dump,
 *  and print its offset from the named structure passed in.
 */
static int
show_member_offset(FILE *ofp, struct datatype_member *dm, char *inbuf)
{
	int i, c, len;
	long offset;
	char *target;
	char *arglist[MAXARGS];
	char buf1[BUFSIZE];
	char fmt[BUFSIZE];
	char workbuf[BUFSIZE];
	int end_of_block;

	if (!STRNEQ(inbuf, "    ")) {
		fprintf(ofp, "rejecting: %s", inbuf);
		return FALSE;
	}

	if (STRNEQ(inbuf, "    union {")) 
		dm->flags |= IN_UNION;
	if (STRNEQ(inbuf, "    struct {")) 
		dm->flags |= IN_STRUCT;
	end_of_block =  STRNEQ(inbuf, "    } ");

	switch (output_radix)
	{
	default:
	case 10:
		sprintf(buf1, "%ld", dm->size);
		break;
	case 16:
		sprintf(buf1, "0x%lx", dm->size);
	}
	len = strlen(buf1) + 4;

	strcpy(workbuf, inbuf);
	c = parse_line(workbuf, arglist);

	target = NULL;
	if (strstr(inbuf, ":")) {
		for (i = 0; i < c; i++) {
			if (i && STREQ(arglist[i], ":")) {
				target = arglist[i-1];
				break;
			}
		}
	} else if (c) { 
		target = arglist[c-1];
		if (!strstr(target, ";"))
			target = NULL;
	}

	if (!target) 
		goto do_empty_offset;

	null_first_space(clean_line(replace_string(target, "*[];()", ' ')));

	if (strlen(target) == 0) 
		goto do_empty_offset;
	
	if (dm->member && !STREQ(dm->member, target)) {
		if (end_of_block)
			dm->flags &= ~(IN_UNION|IN_STRUCT);
		return FALSE;
	}

	offset = MEMBER_OFFSET(dm->name, target);

	if (offset == -1) 
		goto do_empty_offset;

	if (end_of_block && dm->member) {
        	sprintf(buf1, output_radix == 10 ?  
			"  [%ld]" : "  [0x%lx]", offset);
        	sprintf(fmt, "%c%ds", '%', len+1);
        	fprintf(ofp, fmt, " ");

        	switch (dm->flags & (IN_UNION|IN_STRUCT))
		{
		case IN_UNION:
			fprintf(ofp, "union {\n");
			break;

		case IN_STRUCT:
			fprintf(ofp, "struct {\n");
			break;
		}
                dm->flags &= ~(IN_UNION|IN_STRUCT);
	}

	sprintf(buf1, output_radix == 10 ?  "  [%ld]" : "  [0x%lx]", offset);
	sprintf(fmt, "%c%ds", '%', len);
	fprintf(ofp, fmt, buf1);
	fprintf(ofp, &inbuf[3]);

	return TRUE;

do_empty_offset:
        if (end_of_block)
                dm->flags &= ~(IN_UNION|IN_STRUCT);

	if (dm->member) 
		return FALSE;
	
	len = strlen(buf1)+1;
	fprintf(ofp, "%s%s", space(len), inbuf);
	return FALSE;

}

/*
 *   Get and store the size of a "known" array.  This function is only called
 *   once per requested array; after the first time, ARRAY_LENGTH() should be
 *   used.  
 *
 *   For data symbols, get_symbol_type() does the work.
 *   For structure member arrays, datatype_info() does the work.
 *   For two-dimension arrays, or if the designated function above fails,
 *   then just parse "whatis" or "ptype" commands as a last resort. 
 */
int
get_array_length(char *s, int *two_dim, long entry_size)
{
	char copy[BUFSIZE];
	char buf[BUFSIZE];
	char lookfor1[BUFSIZE];
	char lookfor2[BUFSIZE];
	int retval;
        struct datatype_member datatype_member, *dm;
	struct gnu_request gnu_request, *req;
	char *p1, *p2;
	
	strcpy(copy, s);
       	dm = &datatype_member;
	BZERO(dm, sizeof(struct datatype_member));

	if ((retval = builtin_array_length(s, 0, two_dim)))
		return retval;

	if (symbol_search(s)) {
		if (!two_dim) {
			req = &gnu_request;
			if ((get_symbol_type(copy, NULL, req) == 
			    TYPE_CODE_ARRAY) && req->target_typecode && 
			    req->target_length) {
				retval = req->length / req->target_length;
				goto store_builtin;
			}
		}
		sprintf(buf, "whatis %s", s);
	} else { 
        	if (arg_to_datatype(copy, dm, RETURN_ON_ERROR)) {
			if (!dm->member)
				goto store_builtin;

			datatype_info(dm->name, dm->member, dm);

			switch (dm->type)
			{
			case UNION_REQUEST:
                                if (entry_size && dm->member_size &&
                                    (dm->member_typecode == TYPE_CODE_ARRAY)) {
                                        retval = dm->member_size/entry_size;
                                        goto store_builtin;
                                }
				sprintf(buf, "ptype union %s", dm->name);
				break;
			case STRUCT_REQUEST:
				if (entry_size && dm->member_size &&
				    (dm->member_typecode == TYPE_CODE_ARRAY)) {
					retval = dm->member_size/entry_size;
					goto store_builtin;
				}
				sprintf(buf, "ptype struct %s", dm->name);
				break;
			default:
				goto store_builtin;
			}

        		sprintf(lookfor1, " %s[", dm->member);
        		sprintf(lookfor2, "*%s[", dm->member);

		} else
			goto store_builtin;
	}

        open_tmpfile2();
	if (two_dim)
		*two_dim = 0;

        gdb_pass_through(buf, pc->tmpfile2, 0);
        rewind(pc->tmpfile2);
        while (fgets(buf, BUFSIZE, pc->tmpfile2)) {
                if (STRNEQ(buf, "type = ") && 
		    (p1 = strstr(buf, "[")) &&
		    (p2 = strstr(buf, "]")) &&
                    (index(buf, '[') == rindex(buf, '['))) {
			*p2 = NULLCHAR;
			p1++;
			if (strlen(p1)) {
				retval = atoi(p1);
				break;
			}
		}
                if (STRNEQ(buf, "type = ") &&
                    (count_chars(buf, '[') == 2) &&
                    (count_chars(buf, ']') == 2) && two_dim) { 
			p1 = strstr(buf, "[");
			p2 = strstr(buf, "]");
                        *p2 = NULLCHAR;
			p1++;
                        if (strlen(p1)) 
                                *two_dim = atoi(p1);
			else
				break;
			p2++;
                        p1 = strstr(p2, "[");
			p2 = strstr(p1, "]");
			p1++;
                        if (strlen(p1)) 
                                retval = atoi(p1);
			else {
				retval = 0; 
				*two_dim = 0;
				break;
			}
			break;
                }
		if (dm->type &&
		    (strstr(buf, lookfor1) || strstr(buf, lookfor2)) &&
		    (p1 = strstr(buf, "[")) &&
                    (p2 = strstr(buf, "]")) &&
                    (index(buf, '[') == rindex(buf, '['))) {
                        *p2 = NULLCHAR;
                        p1++;
                        if (strlen(p1)) {
                                retval = atoi(p1);
                                break;
                        }
                }
        }
        close_tmpfile2();

store_builtin:

	return (builtin_array_length(s, retval, two_dim));
}

/*
 *  Designed for use by non-debug kernels, but used by all.
 */
int
builtin_array_length(char *s, int len, int *two_dim)
{
	int *lenptr;
	int *dimptr;

	lenptr = dimptr = NULL;

        if (STREQ(s, "kmem_cache_s.name"))
                lenptr = &array_table.kmem_cache_s_name;
        else if (STREQ(s, "kmem_cache_s.c_name"))
                lenptr = &array_table.kmem_cache_s_c_name;
        else if (STREQ(s, "kmem_cache_s.array"))
                lenptr = &array_table.kmem_cache_s_array;
        else if (STREQ(s, "kmem_cache.array"))
                lenptr = &array_table.kmem_cache_s_array;
        else if (STREQ(s, "kmem_cache_s.cpudata"))
                lenptr = &array_table.kmem_cache_s_cpudata;
	else if (STREQ(s, "log_buf")) 
		lenptr = &array_table.log_buf;
	else if (STREQ(s, "irq_desc") || STREQ(s, "_irq_desc")) 
		lenptr = &array_table.irq_desc;
	else if (STREQ(s, "irq_action")) 
		lenptr = &array_table.irq_action;
	else if (STREQ(s, "timer_vec.vec")) 
		lenptr = &array_table.timer_vec_vec;
	else if (STREQ(s, "timer_vec_root.vec")) 
		lenptr = &array_table.timer_vec_root_vec;
        else if (STREQ(s, "tvec_s.vec"))
                lenptr = &array_table.tvec_s_vec;
        else if (STREQ(s, "tvec_root_s.vec"))
                lenptr = &array_table.tvec_root_s_vec;
	else if (STREQ(s, "net_device.name"))
                lenptr = &array_table.net_device_name;
        else if (STREQ(s, "neigh_table.hash_buckets"))
                lenptr = &array_table.neigh_table_hash_buckets;
        else if (STREQ(s, "neighbour.ha"))
                lenptr = &array_table.neighbour_ha;
        else if (STREQ(s, "swap_info"))
                lenptr = &array_table.swap_info;
        else if (STREQ(s, "page_hash_table"))
                lenptr = &array_table.page_hash_table;
        else if (STREQ(s, "pglist_data.node_zones"))
                lenptr = &array_table.pglist_data_node_zones;
        else if (STREQ(s, "zone_struct.free_area"))
                lenptr = &array_table.zone_struct_free_area;
        else if (STREQ(s, "zone.free_area"))
                lenptr = &array_table.zone_free_area;
        else if (STREQ(s, "prio_array.queue"))
                lenptr = &array_table.prio_array_queue;
	else if (STREQ(s, "height_to_maxindex"))
		lenptr = &array_table.height_to_maxindex;
        else if (STREQ(s, "free_area")) {
                lenptr = &array_table.free_area;
		if (two_dim)
			dimptr = &array_table.free_area_DIMENSION;
	} 

	if (!lenptr)                /* not stored */
		return(len);        

	if (*lenptr) {              /* pre-set */
		if (dimptr && two_dim)
			*two_dim = *dimptr;
		return(*lenptr);    
	}

	if (len) {
		*lenptr = len;      /* initialize passed-in value(s) */
		if (dimptr && two_dim)
			*dimptr = *two_dim;
		return(len);
	}

	return(0);                  /* in table, but not set yet */
}

/*
 *  "help -o" output  
 */
void
dump_offset_table(char *spec, ulong makestruct)
{
	char buf[BUFSIZE], *p1;
	char revname[BUFSIZE];
        struct new_utsname *uts;
	long long data_debug;

	data_debug = pc->flags & DATADEBUG;
	pc->flags &= ~DATADEBUG;

	if (makestruct) {
        	uts = &kt->utsname;
		sprintf(revname, "%s_%s", pc->machine_type, uts->release);
		p1 = revname + strlen(pc->machine_type);
		while (*p1) {
			if (((*p1 >= '0') && (*p1 <= '9')) ||
			    ((*p1 >= 'a') && (*p1 <= 'z')) ||
			    ((*p1 >= 'A') && (*p1 <= 'Z')))
		 		p1++;
			else
				*p1++ = '_';	
		}
	}

	if (spec || makestruct) 
		open_tmpfile();

	fprintf(fp, "                  offset_table:\n");
	fprintf(fp, "                list_head_next: %ld\n", 
		OFFSET(list_head_next));
	fprintf(fp, "                list_head_prev: %ld\n", 
		OFFSET(list_head_prev));
	fprintf(fp, "               task_struct_pid: %ld\n", 
		OFFSET(task_struct_pid));
	fprintf(fp, "             task_struct_state: %ld\n", 
		OFFSET(task_struct_state));
	fprintf(fp, "              task_struct_comm: %ld\n", 
		OFFSET(task_struct_comm));
	fprintf(fp, "                task_struct_mm: %ld\n", 
		OFFSET(task_struct_mm));
	fprintf(fp, "               task_struct_tss: %ld\n",
		OFFSET(task_struct_tss));
	fprintf(fp, "            task_struct_thread: %ld\n",
		OFFSET(task_struct_thread));
	fprintf(fp, "         task_struct_active_mm: %ld\n",
		OFFSET(task_struct_active_mm));
	fprintf(fp, "           task_struct_tss_eip: %ld\n", 
		OFFSET(task_struct_tss_eip));
	fprintf(fp, "           task_struct_tss_esp: %ld\n", 
		OFFSET(task_struct_tss_esp));
	fprintf(fp, "           task_struct_tss_ksp: %ld\n", 
		OFFSET(task_struct_tss_ksp));
        fprintf(fp, "        task_struct_thread_eip: %ld\n",
                OFFSET(task_struct_thread_eip));
        fprintf(fp, "        task_struct_thread_esp: %ld\n",
                OFFSET(task_struct_thread_esp));
        fprintf(fp, "        task_struct_thread_ksp: %ld\n",
                OFFSET(task_struct_thread_ksp));
	fprintf(fp, "         task_struct_processor: %ld\n", 
		OFFSET(task_struct_processor));
	fprintf(fp, "            task_struct_p_pptr: %ld\n",
		OFFSET(task_struct_p_pptr));
        fprintf(fp, "            task_struct_parent: %ld\n",
                OFFSET(task_struct_parent));
	fprintf(fp, "           task_struct_has_cpu: %ld\n",
		OFFSET(task_struct_has_cpu));
        fprintf(fp, "     task_struct_cpus_runnable: %ld\n",
                OFFSET(task_struct_cpus_runnable));
	fprintf(fp, "         task_struct_next_task: %ld\n",
		OFFSET(task_struct_next_task));
        fprintf(fp, "             task_struct_files: %ld\n",
                OFFSET(task_struct_files));
        fprintf(fp, "                task_struct_fs: %ld\n",
                OFFSET(task_struct_fs));
        fprintf(fp, "      task_struct_pidhash_next: %ld\n",
                OFFSET(task_struct_pidhash_next));
	fprintf(fp, "          task_struct_next_run: %ld\n",
		OFFSET(task_struct_next_run));
	fprintf(fp, "             task_struct_flags: %ld\n",
		OFFSET(task_struct_flags));
	fprintf(fp, "               task_struct_sig: %ld\n",
        	OFFSET(task_struct_sig));
	fprintf(fp, "            task_struct_signal: %ld\n",
        	OFFSET(task_struct_signal));
	fprintf(fp, "           task_struct_blocked: %ld\n",
        	OFFSET(task_struct_blocked));
	fprintf(fp, "        task_struct_sigpending: %ld\n",
        	OFFSET(task_struct_sigpending));
	fprintf(fp, "           task_struct_pending: %ld\n",
        	OFFSET(task_struct_pending));
        fprintf(fp, "          task_struct_sigqueue: %ld\n",
                OFFSET(task_struct_sigqueue));
        fprintf(fp, "           task_struct_sighand: %ld\n",
                OFFSET(task_struct_sighand));
        fprintf(fp, "          task_struct_run_list: %ld\n",
                OFFSET(task_struct_run_list));
        fprintf(fp, "              task_struct_pgrp: %ld\n",
                OFFSET(task_struct_pgrp));
        fprintf(fp, "              task_struct_tgid: %ld\n",
                OFFSET(task_struct_tgid));
        fprintf(fp, "         task_struct_namespace: %ld\n",
                OFFSET(task_struct_namespace));
        fprintf(fp, "              task_struct_pids: %ld\n",
                OFFSET(task_struct_pids));
        fprintf(fp, "          task_struct_last_run: %ld\n",
                OFFSET(task_struct_last_run));
        fprintf(fp, "         task_struct_timestamp: %ld\n",
                OFFSET(task_struct_timestamp));
        fprintf(fp, "       task_struct_thread_info: %ld\n",
                OFFSET(task_struct_thread_info));

	fprintf(fp, "              thread_info_task: %ld\n",
                OFFSET(thread_info_task));
	fprintf(fp, "               thread_info_cpu: %ld\n",
                OFFSET(thread_info_cpu));
	fprintf(fp, "             thread_info_flags: %ld\n",
                OFFSET(thread_info_flags));
	fprintf(fp, "      thread_info_previous_esp: %ld\n",
                OFFSET(thread_info_previous_esp));

        fprintf(fp, "                  pid_link_pid: %ld\n",
                OFFSET(pid_link_pid));
        fprintf(fp, "                pid_hash_chain: %ld\n",
                OFFSET(pid_hash_chain));

        fprintf(fp, "               hlist_node_next: %ld\n",
		OFFSET(hlist_node_next));
        fprintf(fp, "              hlist_node_pprev: %ld\n",
		OFFSET(hlist_node_pprev));
        fprintf(fp, "                 pid_pid_chain: %ld\n",
		OFFSET(pid_pid_chain));

	fprintf(fp, "             thread_struct_eip: %ld\n",
		OFFSET(thread_struct_eip));
	fprintf(fp, "             thread_struct_esp: %ld\n",
		OFFSET(thread_struct_esp));
	fprintf(fp, "             thread_struct_ksp: %ld\n",
		OFFSET(thread_struct_ksp));
        fprintf(fp, "             thread_struct_rip: %ld\n",
                OFFSET(thread_struct_rip));
        fprintf(fp, "             thread_struct_rsp: %ld\n",
                OFFSET(thread_struct_rsp));
        fprintf(fp, "            thread_struct_rsp0: %ld\n",
                OFFSET(thread_struct_rsp0));

	fprintf(fp, "           signal_struct_count: %ld\n",
        	OFFSET(signal_struct_count));
	fprintf(fp, "          signal_struct_action: %ld\n",
        	OFFSET(signal_struct_action));
	fprintf(fp, "  signal_struct_shared_pending: %ld\n",
        	OFFSET(signal_struct_shared_pending));
        fprintf(fp, "        task_struct_start_time: %ld\n",
                OFFSET(task_struct_start_time));
        fprintf(fp, "             task_struct_times: %ld\n",
                OFFSET(task_struct_times));
        fprintf(fp, "               task_struct_cpu: %ld\n",
                OFFSET(task_struct_cpu));
        fprintf(fp, "             task_struct_utime: %ld\n",
                OFFSET(task_struct_utime));
        fprintf(fp, "             task_struct_stime: %ld\n",
                OFFSET(task_struct_stime));

        fprintf(fp, "                 tms_tms_utime: %ld\n",
                OFFSET(tms_tms_utime));
        fprintf(fp, "                 tms_tms_stime: %ld\n",
                OFFSET(tms_tms_stime));

	fprintf(fp, "                k_sigaction_sa: %ld\n",
        	OFFSET(k_sigaction_sa));

	fprintf(fp, "          sigaction_sa_handler: %ld\n",
        	OFFSET(sigaction_sa_handler));
	fprintf(fp, "            sigaction_sa_flags: %ld\n",
        	OFFSET(sigaction_sa_flags));
	fprintf(fp, "             sigaction_sa_mask: %ld\n",
        	OFFSET(sigaction_sa_mask));

	fprintf(fp, "               sigpending_head: %ld\n",
                OFFSET(sigpending_head));
	fprintf(fp, "             sigpending_signal: %ld\n",
                OFFSET(sigpending_signal));
	fprintf(fp, "               sigpending_list: %ld\n",
                OFFSET(sigpending_list));

        fprintf(fp, "             signal_queue_next: %ld\n",
                OFFSET(signal_queue_next));
        fprintf(fp, "             signal_queue_info: %ld\n",
                OFFSET(signal_queue_info));

        fprintf(fp, "                 sigqueue_next: %ld\n",
                OFFSET(sigqueue_next));
        fprintf(fp, "                 sigqueue_info: %ld\n",
                OFFSET(sigqueue_info));
        fprintf(fp, "                 sigqueue_list: %ld\n",
                OFFSET(sigqueue_list));

	fprintf(fp, "         sighand_struct_action: %ld\n",
		OFFSET(sighand_struct_action));

        fprintf(fp, "              siginfo_si_signo: %ld\n",
                OFFSET(siginfo_si_signo));

	fprintf(fp, "             thread_struct_fph: %ld\n",
		OFFSET(thread_struct_fph));
	fprintf(fp, "             thread_struct_cr3: %ld\n",
		OFFSET(thread_struct_cr3));
	fprintf(fp, "            thread_struct_ptbr: %ld\n",
		OFFSET(thread_struct_ptbr));
	fprintf(fp, "       thread_struct_pg_tables: %ld\n",
	        OFFSET(thread_struct_pg_tables));

	fprintf(fp, "              switch_stack_r26: %ld\n",
		OFFSET(switch_stack_r26));
	fprintf(fp, "               switch_stack_b0: %ld\n",
		OFFSET(switch_stack_b0));
	fprintf(fp, "      switch_stack_ar_bspstore: %ld\n",
		OFFSET(switch_stack_ar_bspstore));
	fprintf(fp, "           switch_stack_ar_pfs: %ld\n",
		OFFSET(switch_stack_ar_pfs));
	fprintf(fp, "          switch_stack_ar_rnat: %ld\n",
		OFFSET(switch_stack_ar_rnat));
	fprintf(fp, "               switch_stack_pr: %ld\n",
		OFFSET(switch_stack_pr));
        fprintf(fp, "        cpuinfo_ia64_proc_freq: %ld\n", 
        	OFFSET(cpuinfo_ia64_proc_freq));
        fprintf(fp, "   cpuinfo_ia64_unimpl_va_mask: %ld\n", 
        	OFFSET(cpuinfo_ia64_unimpl_va_mask));
        fprintf(fp, "   cpuinfo_ia64_unimpl_pa_mask: %ld\n", 
        	OFFSET(cpuinfo_ia64_unimpl_pa_mask));

	fprintf(fp, "              device_node_type: %ld\n",
        	OFFSET(device_node_type));
	fprintf(fp, "           device_node_allnext: %ld\n",
        	OFFSET(device_node_allnext));
	fprintf(fp, "        device_node_properties: %ld\n",
        	OFFSET(device_node_properties));
	fprintf(fp, "                 property_name: %ld\n",
        	OFFSET(property_name));
	fprintf(fp, "                property_value: %ld\n",
        	OFFSET(property_value));
	fprintf(fp, "                 property_next: %ld\n",
        	OFFSET(property_next));
	fprintf(fp, "  machdep_calls_setup_residual: %ld\n",
        	OFFSET(machdep_calls_setup_residual));
	fprintf(fp, "     RESIDUAL_VitalProductData: %ld\n",
        	OFFSET(RESIDUAL_VitalProductData));
	fprintf(fp, "               VPD_ProcessorHz: %ld\n",
        	OFFSET(VPD_ProcessorHz));
	fprintf(fp, "            bd_info_bi_intfreq: %ld\n",
        	OFFSET(bd_info_bi_intfreq));

	fprintf(fp, "       hwrpb_struct_cycle_freq: %ld\n",
		OFFSET(hwrpb_struct_cycle_freq));
	fprintf(fp, " hwrpb_struct_processor_offset: %ld\n",
		OFFSET(hwrpb_struct_processor_offset));
        fprintf(fp, "   hwrpb_struct_processor_size: %ld\n", 
                OFFSET(hwrpb_struct_processor_size));
	fprintf(fp, "         percpu_struct_halt_PC: %ld\n",
                OFFSET(percpu_struct_halt_PC));
        fprintf(fp, "         percpu_struct_halt_ra: %ld\n",
                OFFSET(percpu_struct_halt_ra));
        fprintf(fp, "         percpu_struct_halt_pv: %ld\n",
                OFFSET(percpu_struct_halt_pv));

	fprintf(fp, "                mm_struct_mmap: %ld\n", 
		OFFSET(mm_struct_mmap));
	fprintf(fp, "                 mm_struct_pgd: %ld\n", 
		OFFSET(mm_struct_pgd));
	fprintf(fp, "                 mm_struct_rss: %ld\n", 
		OFFSET(mm_struct_rss));
	fprintf(fp, "            mm_struct_anon_rss: %ld\n", 
		OFFSET(mm_struct_anon_rss));
	fprintf(fp, "            mm_struct_total_vm: %ld\n", 
		OFFSET(mm_struct_total_vm));
	fprintf(fp, "          mm_struct_start_code: %ld\n", 
		OFFSET(mm_struct_start_code));
	fprintf(fp, "           mm_struct_arg_start: %ld\n", 
		OFFSET(mm_struct_arg_start));
	fprintf(fp, "             mm_struct_arg_end: %ld\n", 
		OFFSET(mm_struct_arg_end));
	fprintf(fp, "           mm_struct_env_start: %ld\n", 
		OFFSET(mm_struct_env_start));
	fprintf(fp, "             mm_struct_env_end: %ld\n", 
		OFFSET(mm_struct_env_end));

	fprintf(fp, "          vm_area_struct_vm_mm: %ld\n", 
		OFFSET(vm_area_struct_vm_mm));
	fprintf(fp, "        vm_area_struct_vm_next: %ld\n", 
		OFFSET(vm_area_struct_vm_next));
	fprintf(fp, "       vm_area_struct_vm_start: %ld\n", 
		OFFSET(vm_area_struct_vm_start));
	fprintf(fp, "         vm_area_struct_vm_end: %ld\n", 
		OFFSET(vm_area_struct_vm_end));
        fprintf(fp, "       vm_area_struct_vm_flags: %ld\n",
		OFFSET(vm_area_struct_vm_flags));

        fprintf(fp, "        vm_area_struct_vm_file: %ld\n",
		OFFSET(vm_area_struct_vm_file));
        fprintf(fp, "      vm_area_struct_vm_offset: %ld\n",
		OFFSET(vm_area_struct_vm_offset));
        fprintf(fp, "       vm_area_struct_vm_pgoff: %ld\n",
		OFFSET(vm_area_struct_vm_pgoff));

	fprintf(fp, "                vm_struct_addr: %ld\n", 
		OFFSET(vm_struct_addr));
	fprintf(fp, "                vm_struct_size: %ld\n",
        	OFFSET(vm_struct_size));
	fprintf(fp, "                vm_struct_next: %ld\n",
        	OFFSET(vm_struct_next));

	fprintf(fp, "         module_size_of_struct: %ld\n", 
		OFFSET(module_size_of_struct));
	fprintf(fp, "                   module_next: %ld\n", 
		OFFSET(module_next));
	fprintf(fp, "                   module_name: %ld\n",
		OFFSET(module_name));
	fprintf(fp, "                   module_syms: %ld\n",
		OFFSET(module_syms));
	fprintf(fp, "                  module_nsyms: %ld\n",
		OFFSET(module_nsyms));
	fprintf(fp, "                   module_size: %ld\n",
		OFFSET(module_size));
	fprintf(fp, "                  module_flags: %ld\n",
		OFFSET(module_flags));
	fprintf(fp, "               module_num_syms: %ld\n",
		OFFSET(module_num_syms));
	fprintf(fp, "               module_gpl_syms: %ld\n",
		OFFSET(module_gpl_syms));
	fprintf(fp, "           module_num_gpl_syms: %ld\n",
		OFFSET(module_num_gpl_syms));
	fprintf(fp, "                   module_list: %ld\n",
		OFFSET(module_list));
	fprintf(fp, "            module_module_core: %ld\n",
		OFFSET(module_module_core));
	fprintf(fp, "              module_core_size: %ld\n",
		OFFSET(module_core_size));
	fprintf(fp, "         module_core_text_size: %ld\n",
		OFFSET(module_core_text_size));
	fprintf(fp, "             module_num_symtab: %ld\n",
		OFFSET(module_num_symtab));
	fprintf(fp, "                 module_symtab: %ld\n",
		OFFSET(module_symtab));
	fprintf(fp, "                 module_strtab: %ld\n",
		OFFSET(module_strtab));

        fprintf(fp, "         module_kallsyms_start: %ld\n",
        	OFFSET(module_kallsyms_start));
        fprintf(fp, "      kallsyms_header_sections: %ld\n",
        	OFFSET(kallsyms_header_sections));
        fprintf(fp, "   kallsyms_header_section_off: %ld\n",
        	OFFSET(kallsyms_header_section_off));
        fprintf(fp, "       kallsyms_header_symbols: %ld\n",
        	OFFSET(kallsyms_header_symbols));
        fprintf(fp, "    kallsyms_header_symbol_off: %ld\n",
        	OFFSET(kallsyms_header_symbol_off));
        fprintf(fp, "    kallsyms_header_string_off: %ld\n",
        	OFFSET(kallsyms_header_string_off));
        fprintf(fp, "   kallsyms_symbol_section_off: %ld\n",
        	OFFSET(kallsyms_symbol_section_off));
        fprintf(fp, "   kallsyms_symbol_symbol_addr: %ld\n",
        	OFFSET(kallsyms_symbol_symbol_addr));
        fprintf(fp, "      kallsyms_symbol_name_off: %ld\n",
        	OFFSET(kallsyms_symbol_name_off));
        fprintf(fp, "        kallsyms_section_start: %ld\n",
        	OFFSET(kallsyms_section_start));
        fprintf(fp, "         kallsyms_section_size: %ld\n",
        	OFFSET(kallsyms_section_size));
        fprintf(fp, "     kallsyms_section_name_off: %ld\n",
        	OFFSET(kallsyms_section_name_off));

	fprintf(fp, "                     page_next: %ld\n", OFFSET(page_next));
	fprintf(fp, "                     page_prev: %ld\n", OFFSET(page_prev));
	fprintf(fp, "                page_next_hash: %ld\n", 
		OFFSET(page_next_hash));
	fprintf(fp, "                     page_list: %ld\n", 
		OFFSET(page_list));
	fprintf(fp, "                page_list_next: %ld\n", 
		OFFSET(page_list_next));
	fprintf(fp, "                page_list_prev: %ld\n", 
		OFFSET(page_list_prev));
	fprintf(fp, "                    page_inode: %ld\n", 
		OFFSET(page_inode));
	fprintf(fp, "                   page_offset: %ld\n", 
		OFFSET(page_offset));
	fprintf(fp, "                    page_count: %ld\n", 
		OFFSET(page_count));
	fprintf(fp, "                    page_flags: %ld\n", 
		OFFSET(page_flags));
	fprintf(fp, "                  page_mapping: %ld\n",
		OFFSET(page_mapping));
	fprintf(fp, "                    page_index: %ld\n", 
		OFFSET(page_index));
	fprintf(fp, "                  page_buffers: %ld\n",
		OFFSET(page_buffers));
        fprintf(fp, "                      page_lru: %ld\n",
                OFFSET(page_lru));
        fprintf(fp, "                      page_pte: %ld\n",
                OFFSET(page_pte));

        fprintf(fp, "    swap_info_struct_swap_file: %ld\n",
		OFFSET(swap_info_struct_swap_file));
        fprintf(fp, "  swap_info_struct_swap_vfsmnt: %ld\n",
		OFFSET(swap_info_struct_swap_vfsmnt));
        fprintf(fp, "        swap_info_struct_flags: %ld\n",
		OFFSET(swap_info_struct_flags));
        fprintf(fp, "     swap_info_struct_swap_map: %ld\n",
		OFFSET(swap_info_struct_swap_map));
        fprintf(fp, "  swap_info_struct_swap_device: %ld\n",
		OFFSET(swap_info_struct_swap_device));
        fprintf(fp, "         swap_info_struct_prio: %ld\n",
		OFFSET(swap_info_struct_prio));
        fprintf(fp, "          swap_info_struct_max: %ld\n",
		OFFSET(swap_info_struct_max));
        fprintf(fp, "        swap_info_struct_pages: %ld\n",
		OFFSET(swap_info_struct_pages));
        fprintf(fp, "swap_info_struct_old_block_size: %ld\n",
		OFFSET(swap_info_struct_old_block_size));
	fprintf(fp, "         block_device_bd_inode: %ld\n",
		OFFSET(block_device_bd_inode));
	fprintf(fp, "          block_device_bd_list: %ld\n",
		OFFSET(block_device_bd_list));
	fprintf(fp, "          block_device_bd_disk: %ld\n",
		OFFSET(block_device_bd_disk));
	fprintf(fp, "         address_space_nrpages: %ld\n",
		OFFSET(address_space_nrpages));
	fprintf(fp, "                 gendisk_major: %ld\n",
		OFFSET(gendisk_major));
	fprintf(fp, "                  gendisk_fops: %ld\n",
		OFFSET(gendisk_fops));
	fprintf(fp, "             gendisk_disk_name: %ld\n",
		OFFSET(gendisk_disk_name));

	fprintf(fp, "             irq_desc_t_status: %ld\n",
		OFFSET(irq_desc_t_status));
	fprintf(fp, "            irq_desc_t_handler: %ld\n",
		OFFSET(irq_desc_t_handler));
	fprintf(fp, "             irq_desc_t_action: %ld\n",
		OFFSET(irq_desc_t_action));
	fprintf(fp, "              irq_desc_t_depth: %ld\n",
		OFFSET(irq_desc_t_depth));

	fprintf(fp, "                irqdesc_action: %ld\n",
		OFFSET(irqdesc_action));
	fprintf(fp, "                   irqdesc_ctl: %ld\n",
		OFFSET(irqdesc_ctl));
	fprintf(fp, "                 irqdesc_level: %ld\n",
		OFFSET(irqdesc_level));

	fprintf(fp, "             irqaction_handler: %ld\n",
		OFFSET(irqaction_handler));
	fprintf(fp, "               irqaction_flags: %ld\n",
		OFFSET(irqaction_flags));
	fprintf(fp, "                irqaction_mask: %ld\n",
		OFFSET(irqaction_mask));
	fprintf(fp, "                irqaction_name: %ld\n",
		OFFSET(irqaction_name));
	fprintf(fp, "              irqaction_dev_id: %ld\n",
		OFFSET(irqaction_dev_id));
	fprintf(fp, "                irqaction_next: %ld\n",
		OFFSET(irqaction_next));

	
	fprintf(fp, "    hw_interrupt_type_typename: %ld\n",
		OFFSET(hw_interrupt_type_typename));
	fprintf(fp, "     hw_interrupt_type_startup: %ld\n",
		OFFSET(hw_interrupt_type_startup));
	fprintf(fp, "    hw_interrupt_type_shutdown: %ld\n",
		OFFSET(hw_interrupt_type_shutdown));
        fprintf(fp, "      hw_interrupt_type_handle: %ld\n",
                OFFSET(hw_interrupt_type_handle));
	fprintf(fp, "      hw_interrupt_type_enable: %ld\n",
		OFFSET(hw_interrupt_type_enable));
	fprintf(fp, "     hw_interrupt_type_disable: %ld\n",
		OFFSET(hw_interrupt_type_disable));
	fprintf(fp, "         hw_interrupt_type_ack: %ld\n",
		OFFSET(hw_interrupt_type_ack));
	fprintf(fp, "         hw_interrupt_type_end: %ld\n",
		OFFSET(hw_interrupt_type_end));
	fprintf(fp, "hw_interrupt_type_set_affinity: %ld\n",
		OFFSET(hw_interrupt_type_set_affinity));

	fprintf(fp, "irq_cpustat_t___softirq_active: %ld\n",
        	OFFSET(irq_cpustat_t___softirq_active));
	fprintf(fp, "  irq_cpustat_t___softirq_mask: %ld\n",
        	OFFSET(irq_cpustat_t___softirq_mask));
	
        fprintf(fp, "              files_struct_fdt: %ld\n",
		OFFSET(files_struct_fdt));
        fprintf(fp, "               fdtable_max_fds: %ld\n",
		OFFSET(fdtable_max_fds));
        fprintf(fp, "             fdtable_max_fdset: %ld\n",
		OFFSET(fdtable_max_fdset));
        fprintf(fp, "              fdtable_open_fds: %ld\n",
		OFFSET(fdtable_open_fds));
        fprintf(fp, "                    fdtable_fd: %ld\n",
		OFFSET(fdtable_fd));
        fprintf(fp, "          files_struct_max_fds: %ld\n", 
		OFFSET(files_struct_max_fds));
        fprintf(fp, "        files_struct_max_fdset: %ld\n", 
		OFFSET(files_struct_max_fdset));
        fprintf(fp, "         files_struct_open_fds: %ld\n", 
		OFFSET(files_struct_open_fds));
        fprintf(fp, "               files_struct_fd: %ld\n", 
		OFFSET(files_struct_fd));
        fprintf(fp, "    files_struct_open_fds_init: %ld\n", 
		OFFSET(files_struct_open_fds_init));
        fprintf(fp, "                 file_f_dentry: %ld\n", 
		OFFSET(file_f_dentry));
        fprintf(fp, "                 file_f_vfsmnt: %ld\n", 
		OFFSET(file_f_vfsmnt));
        fprintf(fp, "                  file_f_count: %ld\n", 
		OFFSET(file_f_count));
	fprintf(fp, "                fs_struct_root: %ld\n",
		OFFSET(fs_struct_root));
	fprintf(fp, "                 fs_struct_pwd: %ld\n",
		OFFSET(fs_struct_pwd));
	fprintf(fp, "             fs_struct_rootmnt: %ld\n",
		OFFSET(fs_struct_rootmnt));
	fprintf(fp, "              fs_struct_pwdmnt: %ld\n",
		OFFSET(fs_struct_pwdmnt));

        fprintf(fp, "                dentry_d_inode: %ld\n", 
		OFFSET(dentry_d_inode));
        fprintf(fp, "               dentry_d_parent: %ld\n", 
		OFFSET(dentry_d_parent));
        fprintf(fp, "                 dentry_d_name: %ld\n", 
		OFFSET(dentry_d_name));
        fprintf(fp, "                dentry_d_iname: %ld\n", 
		OFFSET(dentry_d_iname));
        fprintf(fp, "               dentry_d_covers: %ld\n",
                OFFSET(dentry_d_covers));
        fprintf(fp, "                      qstr_len: %ld\n", OFFSET(qstr_len));
        fprintf(fp, "                     qstr_name: %ld\n", OFFSET(qstr_name));
        fprintf(fp, "                  inode_i_mode: %ld\n",
		OFFSET(inode_i_mode));
        fprintf(fp, "                    inode_i_op: %ld\n", 
		OFFSET(inode_i_op));
        fprintf(fp, "                    inode_i_sb: %ld\n", 
		OFFSET(inode_i_sb));
        fprintf(fp, "                       inode_u: %ld\n", OFFSET(inode_u));
        fprintf(fp, "                 inode_i_flock: %ld\n", 
		OFFSET(inode_i_flock));
        fprintf(fp, "                   inode_i_fop: %ld\n", 
		OFFSET(inode_i_fop)); 
	fprintf(fp, "               inode_i_mapping: %ld\n",
		OFFSET(inode_i_mapping));

        fprintf(fp, "             vfsmount_mnt_next: %ld\n", 
		OFFSET(vfsmount_mnt_next));
        fprintf(fp, "          vfsmount_mnt_devname: %ld\n", 
		OFFSET(vfsmount_mnt_devname));
        fprintf(fp, "          vfsmount_mnt_dirname: %ld\n", 
		OFFSET(vfsmount_mnt_dirname));
        fprintf(fp, "               vfsmount_mnt_sb: %ld\n", 
		OFFSET(vfsmount_mnt_sb));
        fprintf(fp, "             vfsmount_mnt_list: %ld\n", 
		OFFSET(vfsmount_mnt_list));
        fprintf(fp, "       vfsmount_mnt_mountpoint: %ld\n", 
		OFFSET(vfsmount_mnt_mountpoint));
        fprintf(fp, "           vfsmount_mnt_parent: %ld\n", 
		OFFSET(vfsmount_mnt_parent));
	fprintf(fp, "                namespace_root: %ld\n",
			OFFSET(namespace_root));
	fprintf(fp, "                namespace_list: %ld\n",
			OFFSET(namespace_list));

        fprintf(fp, "           super_block_s_dirty: %ld\n", 
		OFFSET(super_block_s_dirty));
        fprintf(fp, "            super_block_s_type: %ld\n", 
		OFFSET(super_block_s_type));
        fprintf(fp, "           super_block_s_files: %ld\n", 
		OFFSET(super_block_s_files));

	fprintf(fp, "               nlm_file_f_file: %ld\n",
		OFFSET(nlm_file_f_file));

        fprintf(fp, "         file_system_type_name: %ld\n", 
		OFFSET(file_system_type_name));

        fprintf(fp, "            file_lock_fl_owner: %ld\n", 
		OFFSET(file_lock_fl_owner));
        fprintf(fp, "          nlm_host_h_exportent: %ld\n", 
		OFFSET(nlm_host_h_exportent));
        fprintf(fp, "           svc_client_cl_ident: %ld\n", 
		OFFSET(svc_client_cl_ident));

	fprintf(fp, "          kmem_cache_s_c_nextp: %ld\n", 
		OFFSET(kmem_cache_s_c_nextp));
        fprintf(fp, "           kmem_cache_s_c_name: %ld\n", 
                OFFSET(kmem_cache_s_c_name));
        fprintf(fp, "            kmem_cache_s_c_num: %ld\n", 
                OFFSET(kmem_cache_s_c_num));
        fprintf(fp, "       kmem_cache_s_c_org_size: %ld\n", 
                OFFSET(kmem_cache_s_c_org_size));
        fprintf(fp, "          kmem_cache_s_c_flags: %ld\n", 
                OFFSET(kmem_cache_s_c_flags));
        fprintf(fp, "         kmem_cache_s_c_offset: %ld\n", 
                OFFSET(kmem_cache_s_c_offset));
        fprintf(fp, "         kmem_cache_s_c_firstp: %ld\n", 
                OFFSET(kmem_cache_s_c_firstp));
        fprintf(fp, "       kmem_cache_s_c_gfporder: %ld\n", 
                OFFSET(kmem_cache_s_c_gfporder));
        fprintf(fp, "          kmem_cache_s_c_magic: %ld\n", 
                OFFSET(kmem_cache_s_c_magic));
        fprintf(fp, "          kmem_cache_s_c_align: %ld\n", 
                OFFSET(kmem_cache_s_c_align));

        fprintf(fp, "              kmem_cache_s_num: %ld\n",
                OFFSET(kmem_cache_s_num));
        fprintf(fp, "             kmem_cache_s_next: %ld\n",
                OFFSET(kmem_cache_s_next));
        fprintf(fp, "             kmem_cache_s_name: %ld\n",
                OFFSET(kmem_cache_s_name));
        fprintf(fp, "          kmem_cache_s_objsize: %ld\n",
                OFFSET(kmem_cache_s_objsize));
        fprintf(fp, "            kmem_cache_s_flags: %ld\n",
                OFFSET(kmem_cache_s_flags));
        fprintf(fp, "         kmem_cache_s_gfporder: %ld\n",
                OFFSET(kmem_cache_s_gfporder));
        fprintf(fp, "            kmem_cache_s_slabs: %ld\n",
                OFFSET(kmem_cache_s_slabs));
        fprintf(fp, "       kmem_cache_s_slabs_full: %ld\n",
                OFFSET(kmem_cache_s_slabs_full));
        fprintf(fp, "    kmem_cache_s_slabs_partial: %ld\n",
                OFFSET(kmem_cache_s_slabs_partial));
        fprintf(fp, "       kmem_cache_s_slabs_free: %ld\n",
                OFFSET(kmem_cache_s_slabs_free));
        fprintf(fp, "          kmem_cache_s_cpudata: %ld\n",
                OFFSET(kmem_cache_s_cpudata));
        fprintf(fp, "       kmem_cache_s_colour_off: %ld\n",
                OFFSET(kmem_cache_s_colour_off));

	fprintf(fp, "              cpucache_s_avail: %ld\n",
                OFFSET(cpucache_s_avail));
	fprintf(fp, "              cpucache_s_limit: %ld\n",
                OFFSET(cpucache_s_limit));
	fprintf(fp, "             array_cache_avail: %ld\n",
                OFFSET(array_cache_avail));
	fprintf(fp, "             array_cache_limit: %ld\n",
                OFFSET(array_cache_limit));

	fprintf(fp, "            kmem_cache_s_array: %ld\n",
                OFFSET(kmem_cache_s_array));
	fprintf(fp, "            kmem_cache_s_lists: %ld\n",
                OFFSET(kmem_cache_s_lists));
	fprintf(fp, "      kmem_list3_slabs_partial: %ld\n",
                OFFSET(kmem_list3_slabs_partial));
	fprintf(fp, "         kmem_list3_slabs_full: %ld\n",
                OFFSET(kmem_list3_slabs_full));
	fprintf(fp, "         kmem_list3_slabs_free: %ld\n",
                OFFSET(kmem_list3_slabs_free));
	fprintf(fp, "       kmem_list3_free_objects: %ld\n",
                OFFSET(kmem_list3_free_objects));
	fprintf(fp, "             kmem_list3_shared: %ld\n",
                OFFSET(kmem_list3_shared));

        fprintf(fp, "           kmem_slab_s_s_nextp: %ld\n", 
                OFFSET(kmem_slab_s_s_nextp));
        fprintf(fp, "           kmem_slab_s_s_freep: %ld\n", 
                OFFSET(kmem_slab_s_s_freep));
        fprintf(fp, "           kmem_slab_s_s_inuse: %ld\n", 
                OFFSET(kmem_slab_s_s_inuse));
        fprintf(fp, "             kmem_slab_s_s_mem: %ld\n", 
                OFFSET(kmem_slab_s_s_mem));
        fprintf(fp, "           kmem_slab_s_s_index: %ld\n", 
                OFFSET(kmem_slab_s_s_index));
        fprintf(fp, "          kmem_slab_s_s_offset: %ld\n", 
                OFFSET(kmem_slab_s_s_offset));
        fprintf(fp, "           kmem_slab_s_s_magic: %ld\n", 
                OFFSET(kmem_slab_s_s_magic));

	fprintf(fp, "                   slab_s_list: %ld\n",
		OFFSET(slab_s_list));
	fprintf(fp, "                  slab_s_s_mem: %ld\n",
		OFFSET(slab_s_s_mem));
	fprintf(fp, "                  slab_s_inuse: %ld\n",
		OFFSET(slab_s_inuse));
	fprintf(fp, "                   slab_s_free: %ld\n",
		OFFSET(slab_s_free));

        fprintf(fp, "                     slab_list: %ld\n",
                OFFSET(slab_list));
        fprintf(fp, "                    slab_s_mem: %ld\n",
                OFFSET(slab_s_mem));
        fprintf(fp, "                    slab_inuse: %ld\n",
                OFFSET(slab_inuse));
        fprintf(fp, "                     slab_free: %ld\n",
                OFFSET(slab_free));

	fprintf(fp, "               net_device_next: %ld\n",
        	OFFSET(net_device_next));
	fprintf(fp, "               net_device_name: %ld\n",
        	OFFSET(net_device_name));
	fprintf(fp, "               net_device_type: %ld\n",
        	OFFSET(net_device_type));
	fprintf(fp, "           net_device_addr_len: %ld\n",
        	OFFSET(net_device_addr_len));
	fprintf(fp, "             net_device_ip_ptr: %ld\n",
        	OFFSET(net_device_ip_ptr));
	fprintf(fp, "                   device_next: %ld\n",
        	OFFSET(device_next));
	fprintf(fp, "                   device_name: %ld\n",
        	OFFSET(device_name));
	fprintf(fp, "                   device_type: %ld\n",
        	OFFSET(device_type));
	fprintf(fp, "                 device_ip_ptr: %ld\n",
        	OFFSET(device_ip_ptr));
	fprintf(fp, "               device_addr_len: %ld\n",
        	OFFSET(device_addr_len));

        fprintf(fp, "                     socket_sk: %ld\n", OFFSET(socket_sk));
        fprintf(fp, "                    sock_daddr: %ld\n", 
		OFFSET(sock_daddr));
        fprintf(fp, "                sock_rcv_saddr: %ld\n", 
		OFFSET(sock_rcv_saddr));
        fprintf(fp, "                    sock_dport: %ld\n", 
		OFFSET(sock_dport));
        fprintf(fp, "                    sock_sport: %ld\n", 
		OFFSET(sock_sport));
        fprintf(fp, "                      sock_num: %ld\n", OFFSET(sock_num));
        fprintf(fp, "                   sock_family: %ld\n", 
		OFFSET(sock_family));
        fprintf(fp, "                     sock_type: %ld\n", OFFSET(sock_type));

        fprintf(fp, "                  sock_sk_type: %ld\n", 
		OFFSET(sock_sk_type));
        fprintf(fp, "        sock_common_skc_family: %ld\n", 
		OFFSET(sock_common_skc_family));
        fprintf(fp, "                inet_sock_inet: %ld\n", 
		OFFSET(inet_sock_inet));
        fprintf(fp, "                inet_opt_daddr: %ld\n", 
		OFFSET(inet_opt_daddr));
        fprintf(fp, "            inet_opt_rcv_saddr: %ld\n", 
		OFFSET(inet_opt_rcv_saddr));
        fprintf(fp, "                inet_opt_dport: %ld\n", 
		OFFSET(inet_opt_dport));
        fprintf(fp, "                inet_opt_sport: %ld\n", 
		OFFSET(inet_opt_sport));
        fprintf(fp, "                  inet_opt_num: %ld\n", 
		OFFSET(inet_opt_num));

        fprintf(fp, "          ipv6_pinfo_rcv_saddr: %ld\n", 
		OFFSET(ipv6_pinfo_rcv_saddr));
        fprintf(fp, "              ipv6_pinfo_daddr: %ld\n", 
		OFFSET(ipv6_pinfo_daddr));

        fprintf(fp, "               timer_list_list: %ld\n",
                OFFSET(timer_list_list));
        fprintf(fp, "               timer_list_next: %ld\n", 
		OFFSET(timer_list_next));
        fprintf(fp, "              timer_list_entry: %ld\n", 
		OFFSET(timer_list_entry));
        fprintf(fp, "            timer_list_expires: %ld\n", 
		OFFSET(timer_list_expires));
        fprintf(fp, "           timer_list_function: %ld\n", 
		OFFSET(timer_list_function));
        fprintf(fp, "            timer_vec_root_vec: %ld\n", 
		OFFSET(timer_vec_root_vec));
        fprintf(fp, "                 timer_vec_vec: %ld\n", 
		OFFSET(timer_vec_vec));
        fprintf(fp, "               tvec_root_s_vec: %ld\n",
                OFFSET(tvec_root_s_vec));
        fprintf(fp, "                    tvec_s_vec: %ld\n",
                OFFSET(tvec_s_vec));
        fprintf(fp, "             tvec_t_base_s_tv1: %ld\n",
                OFFSET(tvec_t_base_s_tv1));

        fprintf(fp, "               wait_queue_task: %ld\n", 
        	OFFSET(wait_queue_task));
        fprintf(fp, "               wait_queue_next: %ld\n", 
        	OFFSET(wait_queue_next));
        fprintf(fp, "             __wait_queue_task: %ld\n", 
        	OFFSET(__wait_queue_task));
        fprintf(fp, "   __wait_queue_head_task_list: %ld\n", 
        	OFFSET(__wait_queue_head_task_list));
        fprintf(fp, "        __wait_queue_task_list: %ld\n", 
        	OFFSET(__wait_queue_task_list));
 
	fprintf(fp, "        pglist_data_node_zones: %ld\n",
		OFFSET(pglist_data_node_zones));
	fprintf(fp, "      pglist_data_node_mem_map: %ld\n",
		OFFSET(pglist_data_node_mem_map));
	fprintf(fp, "  pglist_data_node_start_paddr: %ld\n",
		OFFSET(pglist_data_node_start_paddr));
	fprintf(fp, "  pglist_data_node_start_mapnr: %ld\n",
                OFFSET(pglist_data_node_start_mapnr));
	fprintf(fp, "         pglist_data_node_size: %ld\n",
                OFFSET(pglist_data_node_size));
	fprintf(fp, "           pglist_data_node_id: %ld\n",
                OFFSET(pglist_data_node_id));
	fprintf(fp, "         pglist_data_node_next: %ld\n",
                OFFSET(pglist_data_node_next));
	fprintf(fp, "             pglist_data_bdata: %ld\n",
                OFFSET(pglist_data_bdata));
	fprintf(fp, "          pglist_data_nr_zones: %ld\n",
                OFFSET(pglist_data_nr_zones));
	fprintf(fp, "    pglist_data_node_start_pfn: %ld\n",
                OFFSET(pglist_data_node_start_pfn));
	fprintf(fp, "        pglist_data_pgdat_next: %ld\n",
                OFFSET(pglist_data_pgdat_next));
	fprintf(fp, "pglist_data_node_present_pages: %ld\n",
                OFFSET(pglist_data_node_present_pages));
	fprintf(fp, "pglist_data_node_spanned_pages: %ld\n",
                OFFSET(pglist_data_node_spanned_pages));

	fprintf(fp, "       page_cache_bucket_chain: %ld\n",
		OFFSET(page_cache_bucket_chain));

	fprintf(fp, "        zone_struct_free_pages: %ld\n",
                OFFSET(zone_struct_free_pages));
	fprintf(fp, "         zone_struct_free_area: %ld\n",
                OFFSET(zone_struct_free_area));
	fprintf(fp, "        zone_struct_zone_pgdat: %ld\n",
                OFFSET(zone_struct_zone_pgdat));
	fprintf(fp, "              zone_struct_name: %ld\n",
                OFFSET(zone_struct_name));
	fprintf(fp, "              zone_struct_size: %ld\n",
                OFFSET(zone_struct_size));
	fprintf(fp, "           zone_struct_memsize: %ld\n",
                OFFSET(zone_struct_memsize));
	fprintf(fp, "    zone_struct_zone_start_pfn: %ld\n",
                OFFSET(zone_struct_zone_start_pfn));
	fprintf(fp, "  zone_struct_zone_start_paddr: %ld\n",
                OFFSET(zone_struct_zone_start_paddr));
	fprintf(fp, "  zone_struct_zone_start_mapnr: %ld\n",
                OFFSET(zone_struct_zone_start_mapnr));
	fprintf(fp, "      zone_struct_zone_mem_map: %ld\n",
                OFFSET(zone_struct_zone_mem_map));
        fprintf(fp, "zone_struct_inactive_clean_pages: %ld\n",
                OFFSET(zone_struct_inactive_clean_pages));
        fprintf(fp, "zone_struct_inactive_clean_list: %ld\n",
                OFFSET(zone_struct_inactive_clean_list));
        fprintf(fp, "zone_struct_inactive_dirty_pages: %ld\n",
                OFFSET(zone_struct_inactive_dirty_pages));
        fprintf(fp, "      zone_struct_active_pages: %ld\n",
                OFFSET(zone_struct_active_pages));
        fprintf(fp, "         zone_struct_pages_min: %ld\n",
                OFFSET(zone_struct_pages_min));
        fprintf(fp, "         zone_struct_pages_low: %ld\n",
                OFFSET(zone_struct_pages_low));
        fprintf(fp, "        zone_struct_pages_high: %ld\n",
                OFFSET(zone_struct_pages_high));

	fprintf(fp, "               zone_free_pages: %ld\n",
                OFFSET(zone_free_pages));
	fprintf(fp, "                zone_free_area: %ld\n",
                OFFSET(zone_free_area));
	fprintf(fp, "               zone_zone_pgdat: %ld\n",
                OFFSET(zone_zone_pgdat));
	fprintf(fp, "             zone_zone_mem_map: %ld\n",
                OFFSET(zone_zone_mem_map));
	fprintf(fp, "                     zone_name: %ld\n",
                OFFSET(zone_name));
	fprintf(fp, "            zone_spanned_pages: %ld\n",
                OFFSET(zone_spanned_pages));
	fprintf(fp, "           zone_zone_start_pfn: %ld\n",
                OFFSET(zone_zone_start_pfn));
	fprintf(fp, "                zone_pages_min: %ld\n",
                OFFSET(zone_pages_min));
	fprintf(fp, "                zone_pages_low: %ld\n",
                OFFSET(zone_pages_low));
	fprintf(fp, "               zone_pages_high: %ld\n",
                OFFSET(zone_pages_high));

        fprintf(fp, "                neighbour_next: %ld\n", 
		OFFSET(neighbour_next));
        fprintf(fp, "         neighbour_primary_key: %ld\n", 
		OFFSET(neighbour_primary_key));
        fprintf(fp, "                  neighbour_ha: %ld\n", 
		OFFSET(neighbour_ha));
        fprintf(fp, "                 neighbour_dev: %ld\n", 
		OFFSET(neighbour_dev));
        fprintf(fp, "           neighbour_nud_state: %ld\n", 
		OFFSET(neighbour_nud_state));
        fprintf(fp, "      neigh_table_hash_buckets: %ld\n",
		OFFSET(neigh_table_hash_buckets));
        fprintf(fp, "           neigh_table_key_len: %ld\n",
		OFFSET(neigh_table_key_len));

        fprintf(fp, "            in_device_ifa_list: %ld\n",
		OFFSET(in_device_ifa_list));
        fprintf(fp, "            in_ifaddr_ifa_next: %ld\n",
		OFFSET(in_ifaddr_ifa_next));
        fprintf(fp, "         in_ifaddr_ifa_address: %ld\n",
		OFFSET(in_ifaddr_ifa_address));

        fprintf(fp, "           pci_dev_global_list: %ld\n",
        	OFFSET(pci_dev_global_list));
        fprintf(fp, "                  pci_dev_next: %ld\n",
        	OFFSET(pci_dev_next));
        fprintf(fp, "                   pci_dev_bus: %ld\n",
        	OFFSET(pci_dev_bus));
        fprintf(fp, "                 pci_dev_devfn: %ld\n",
        	OFFSET(pci_dev_devfn));
        fprintf(fp, "                 pci_dev_class: %ld\n",
        	OFFSET(pci_dev_class));
        fprintf(fp, "                pci_dev_device: %ld\n",
        	OFFSET(pci_dev_device));
        fprintf(fp, "                pci_dev_vendor: %ld\n",
        	OFFSET(pci_dev_vendor));
        fprintf(fp, "                pci_bus_number: %ld\n",
        	OFFSET(pci_bus_number));


        fprintf(fp, "         resource_entry_t_from: %ld\n",
        	OFFSET(resource_entry_t_from));
        fprintf(fp, "          resource_entry_t_num: %ld\n",
        	OFFSET(resource_entry_t_num));
        fprintf(fp, "         resource_entry_t_name: %ld\n",
        	OFFSET(resource_entry_t_name)); 
        fprintf(fp, "         resource_entry_t_next: %ld\n",
        	OFFSET(resource_entry_t_next));
        fprintf(fp, "                 resource_name: %ld\n",
        	OFFSET(resource_name));
        fprintf(fp, "                resource_start: %ld\n",
        	OFFSET(resource_start));
        fprintf(fp, "                  resource_end: %ld\n",
        	OFFSET(resource_end));
        fprintf(fp, "              resource_sibling: %ld\n",
        	OFFSET(resource_sibling));
        fprintf(fp, "                resource_child: %ld\n",
        	OFFSET(resource_child));

        fprintf(fp, "                 runqueue_curr: %ld\n",
                OFFSET(runqueue_curr));
        fprintf(fp, "                 runqueue_idle: %ld\n",
                OFFSET(runqueue_idle));
        fprintf(fp, "               runqueue_active: %ld\n",
                OFFSET(runqueue_active));
        fprintf(fp, "              runqueue_expired: %ld\n",
                OFFSET(runqueue_expired));
        fprintf(fp, "               runqueue_arrays: %ld\n",
                OFFSET(runqueue_arrays));
        fprintf(fp, "                  runqueue_cpu: %ld\n",
                OFFSET(runqueue_cpu));
        fprintf(fp, "                    cpu_s_idle: %ld\n", 
		OFFSET(cpu_s_idle));
        fprintf(fp, "                    cpu_s_curr: %ld\n", 
		OFFSET(cpu_s_curr));
	fprintf(fp, "              prio_array_queue: %ld\n",
		OFFSET(prio_array_queue));
	fprintf(fp, "          prio_array_nr_active: %ld\n",
		OFFSET(prio_array_nr_active));
	fprintf(fp, "          user_regs_struct_ebp: %ld\n",
		OFFSET(user_regs_struct_ebp));
	fprintf(fp, "          user_regs_struct_esp: %ld\n",
		OFFSET(user_regs_struct_esp));
	fprintf(fp, "          user_regs_struct_rip: %ld\n",
		OFFSET(user_regs_struct_rip));
	fprintf(fp, "          user_regs_struct_rsp: %ld\n",
		OFFSET(user_regs_struct_rsp));
	fprintf(fp, "       user_regs_struct_eflags: %ld\n",
		OFFSET(user_regs_struct_eflags));
	fprintf(fp, "           user_regs_struct_cs: %ld\n",
		OFFSET(user_regs_struct_cs));
	fprintf(fp, "           user_regs_struct_ss: %ld\n",
		OFFSET(user_regs_struct_ss));

	fprintf(fp, "                e820map_nr_map: %ld\n",
		OFFSET(e820map_nr_map));
	fprintf(fp, "                e820entry_addr: %ld\n",
		OFFSET(e820entry_addr));
	fprintf(fp, "                e820entry_size: %ld\n",
		OFFSET(e820entry_size));
	fprintf(fp, "                e820entry_type: %ld\n",
		OFFSET(e820entry_type));

	fprintf(fp, "       char_device_struct_name: %ld\n",
		OFFSET(char_device_struct_name));
	fprintf(fp, "       char_device_struct_next: %ld\n",
		OFFSET(char_device_struct_next));
	fprintf(fp, "       char_device_struct_fops: %ld\n",
		OFFSET(char_device_struct_fops));
	fprintf(fp, "      char_device_struct_major: %ld\n",
		OFFSET(char_device_struct_major));

	fprintf(fp, "           blk_major_name_next: %ld\n",
		OFFSET(blk_major_name_next));
	fprintf(fp, "          blk_major_name_major: %ld\n",
		OFFSET(blk_major_name_major));
	fprintf(fp, "           blk_major_name_name: %ld\n",
		OFFSET(blk_major_name_name));

	fprintf(fp, "        radix_tree_root_height: %ld\n",
		OFFSET(radix_tree_root_height));
        fprintf(fp, "         radix_tree_root_rnode: %ld\n",
                OFFSET(radix_tree_root_rnode));

	fprintf(fp, "            x8664_pda_pcurrent: %ld\n",
		OFFSET(x8664_pda_pcurrent));
	fprintf(fp, "         x8664_pda_data_offset: %ld\n",
		OFFSET(x8664_pda_data_offset));
	fprintf(fp, "         x8664_pda_kernelstack: %ld\n",
		OFFSET(x8664_pda_kernelstack));
	fprintf(fp, "              x8664_pda_irqrsp: %ld\n",
		OFFSET(x8664_pda_irqrsp));
	fprintf(fp, "           x8664_pda_cpunumber: %ld\n",
		OFFSET(x8664_pda_cpunumber));
	fprintf(fp, "         x8664_pda_irqstackptr: %ld\n",
		OFFSET(x8664_pda_irqstackptr));
	fprintf(fp, "          x8664_pda_level4_pgt: %ld\n",
		OFFSET(x8664_pda_level4_pgt));
	fprintf(fp, "                  x8664_pda_me: %ld\n",
		OFFSET(x8664_pda_me));

	fprintf(fp, "                tss_struct_ist: %ld\n", 
		OFFSET(tss_struct_ist));
	fprintf(fp, "   mem_section_section_mem_map: %ld\n",
		OFFSET(mem_section_section_mem_map));

	fprintf(fp, "  vcpu_guest_context_user_regs: %ld\n",
		OFFSET(vcpu_guest_context_user_regs));
	fprintf(fp, "             cpu_user_regs_eip: %ld\n",
		OFFSET(cpu_user_regs_eip));
	fprintf(fp, "             cpu_user_regs_esp: %ld\n",
		OFFSET(cpu_user_regs_esp));
	fprintf(fp, "             cpu_user_regs_rip: %ld\n",
		OFFSET(cpu_user_regs_rip));
	fprintf(fp, "             cpu_user_regs_rsp: %ld\n",
		OFFSET(cpu_user_regs_rsp));
	

	fprintf(fp, "\n                    size_table:\n");
	fprintf(fp, "                          page: %ld\n", SIZE(page));
        fprintf(fp, "              free_area_struct: %ld\n", 
		SIZE(free_area_struct));
        fprintf(fp, "                     free_area: %ld\n", 
		SIZE(free_area));
        fprintf(fp, "                   zone_struct: %ld\n", SIZE(zone_struct));
        fprintf(fp, "                         zone: %ld\n", SIZE(zone));
        fprintf(fp, "                   kmem_slab_s: %ld\n", SIZE(kmem_slab_s));
        fprintf(fp, "                        slab_s: %ld\n", SIZE(slab_s));
        fprintf(fp, "                          slab: %ld\n", SIZE(slab));
        fprintf(fp, "                  kmem_cache_s: %ld\n", 
		SIZE(kmem_cache_s));
        fprintf(fp, "                    cpucache_s: %ld\n", SIZE(cpucache_s));
        fprintf(fp, "                   array_cache: %ld\n", SIZE(array_cache));
        fprintf(fp, "                 kmem_bufctl_t: %ld\n", 
		SIZE(kmem_bufctl_t));
        fprintf(fp, "              swap_info_struct: %ld\n", 
		SIZE(swap_info_struct));
        fprintf(fp, "                vm_area_struct: %ld\n", 
		SIZE(vm_area_struct));
        fprintf(fp, "                     mm_struct: %ld\n", SIZE(mm_struct));
        fprintf(fp, "                   pglist_data: %ld\n", SIZE(pglist_data));
        fprintf(fp, "             page_cache_bucket: %ld\n", 
		SIZE(page_cache_bucket));
        fprintf(fp, "                       pt_regs: %ld\n", SIZE(pt_regs));
        fprintf(fp, "                   task_struct: %ld\n", SIZE(task_struct));
        fprintf(fp, "                   thread_info: %ld\n", SIZE(thread_info));
        fprintf(fp, "                 softirq_state: %ld\n", 
		SIZE(softirq_state));
        fprintf(fp, "                   desc_struct: %ld\n", SIZE(desc_struct));
	fprintf(fp, "                       umode_t: %ld\n", SIZE(umode_t));
	fprintf(fp, "                        dentry: %ld\n", SIZE(dentry));
	fprintf(fp, "                     fs_struct: %ld\n", SIZE(fs_struct));
	fprintf(fp, "                  files_struct: %ld\n", 
		SIZE(files_struct));
	fprintf(fp, "                       fdtable: %ld\n", SIZE(fdtable));
	fprintf(fp, "                          file: %ld\n", SIZE(file)); 
	fprintf(fp, "                         inode: %ld\n", SIZE(inode)); 
	fprintf(fp, "                      vfsmount: %ld\n", SIZE(vfsmount)); 
	fprintf(fp, "                   super_block: %ld\n", 
		SIZE(super_block)); 
	fprintf(fp, "                       irqdesc: %ld\n", SIZE(irqdesc));
	fprintf(fp, "                        module: %ld\n", SIZE(module));
	fprintf(fp, "                     list_head: %ld\n", SIZE(list_head));
	fprintf(fp, "                    hlist_head: %ld\n", SIZE(hlist_head));
	fprintf(fp, "                    hlist_node: %ld\n", SIZE(hlist_node));
	fprintf(fp, "                 irq_cpustat_t: %ld\n", 
		SIZE(irq_cpustat_t));
	fprintf(fp, "                   cpuinfo_x86: %ld\n", SIZE(cpuinfo_x86));
	fprintf(fp, "                  cpuinfo_ia64: %ld\n", 
		SIZE(cpuinfo_ia64));
	fprintf(fp, "                    timer_list: %ld\n", SIZE(timer_list));
	fprintf(fp, "                timer_vec_root: %ld\n", 
		SIZE(timer_vec_root));
	fprintf(fp, "                     timer_vec: %ld\n", SIZE(timer_vec));
        fprintf(fp, "                   tvec_root_s: %ld\n",
                SIZE(tvec_root_s));
        fprintf(fp, "                        tvec_s: %ld\n", SIZE(tvec_s));
        fprintf(fp, "                 tvec_t_base_s: %ld\n", 
		SIZE(tvec_t_base_s));

	fprintf(fp, "                    wait_queue: %ld\n", SIZE(wait_queue));
	fprintf(fp, "                  __wait_queue: %ld\n", 
		SIZE(__wait_queue));
	fprintf(fp, "                        device: %ld\n", SIZE(device));
	fprintf(fp, "                    net_device: %ld\n", SIZE(net_device));

	fprintf(fp, "                          sock: %ld\n", SIZE(sock));
	fprintf(fp, "                     inet_sock: %ld\n", SIZE(inet_sock));
	fprintf(fp, "                        socket: %ld\n", SIZE(socket));
	fprintf(fp, "                      in6_addr: %ld\n", SIZE(in6_addr));
	fprintf(fp, "                 signal_struct: %ld\n", 
		SIZE(signal_struct));
	fprintf(fp, "             sigpending_signal: %ld\n", 
		SIZE(sigpending_signal));
	fprintf(fp, "                  signal_queue: %ld\n", 
		SIZE(signal_queue));
	fprintf(fp, "                      sigqueue: %ld\n", SIZE(sigqueue));
	fprintf(fp, "                   k_sigaction: %ld\n", 
		SIZE(k_sigaction));
	fprintf(fp, "                sighand_struct: %ld\n", 
		SIZE(sighand_struct));
	fprintf(fp, "              resource_entry_t: %ld\n", 
		SIZE(resource_entry_t));
	fprintf(fp, "                      resource: %ld\n", SIZE(resource));
	fprintf(fp, "                      runqueue: %ld\n", SIZE(runqueue));
	fprintf(fp, "                    irq_desc_t: %ld\n", SIZE(irq_desc_t));
	fprintf(fp, "                    task_union: %ld\n", SIZE(task_union));
	fprintf(fp, "                  thread_union: %ld\n", SIZE(thread_union));
	fprintf(fp, "                    prio_array: %ld\n", SIZE(prio_array));
	fprintf(fp, "              user_regs_struct: %ld\n", 
		SIZE(user_regs_struct));
	fprintf(fp, "                  switch_stack: %ld\n", 
		SIZE(switch_stack));
	fprintf(fp, "       vm_area_struct_vm_flags: %ld\n", 
		SIZE(vm_area_struct_vm_flags));
	fprintf(fp, "                       e820map: %ld\n", SIZE(e820map));
	fprintf(fp, "                     e820entry: %ld\n", SIZE(e820entry));
	fprintf(fp, "                         cpu_s: %ld\n", SIZE(cpu_s));
	fprintf(fp, "                         pgd_t: %ld\n", SIZE(pgd_t));
	fprintf(fp, "               kallsyms_header: %ld\n", 
		SIZE(kallsyms_header));
	fprintf(fp, "               kallsyms_symbol: %ld\n", 
		SIZE(kallsyms_symbol));
	fprintf(fp, "              kallsyms_section: %ld\n", 
		SIZE(kallsyms_section));
	fprintf(fp, "                  block_device: %ld\n",
		SIZE(block_device));
	fprintf(fp, "                blk_major_name: %ld\n",
		SIZE(blk_major_name));
	fprintf(fp, "                 address_space: %ld\n",
		SIZE(address_space));
	fprintf(fp, "                       gendisk: %ld\n",
		SIZE(gendisk));

	fprintf(fp, "                       irq_ctx: %ld\n", SIZE(irq_ctx));
	fprintf(fp, "            char_device_struct: %ld\n",
		SIZE(char_device_struct));
	fprintf(fp, "                    spinlock_t: %ld\n",
		SIZE(spinlock_t));

	fprintf(fp, "               radix_tree_root: %ld\n",
                SIZE(radix_tree_root));
	fprintf(fp, "               radix_tree_node: %ld\n",
                SIZE(radix_tree_node));

	fprintf(fp, "                     x8664_pda: %ld\n", 
		SIZE(x8664_pda));
	fprintf(fp, "                    ppc64_paca: %ld\n", 
		SIZE(ppc64_paca));
	fprintf(fp, "                   gate_struct: %ld\n", 
		SIZE(gate_struct));
	fprintf(fp, "                    tss_struct: %ld\n", 
		SIZE(tss_struct));
	fprintf(fp, "        task_struct_start_time: %ld\n", 
		SIZE(task_struct_start_time));
	fprintf(fp, "                     cputime_t: %ld\n", 
		SIZE(cputime_t));
	fprintf(fp, "                   mem_section: %ld\n", 
		SIZE(mem_section));
	fprintf(fp, "                      pid_link: %ld\n", 
		SIZE(pid_link));

        fprintf(fp, "\n                   array_table:\n");
	/*
	 *  Use get_array_length() for those fields not set up at init-time;
         *  ARRAY_LENGTH() will work for the rest.
	 */
        fprintf(fp, "             kmem_cache_s_name: %d\n",
                ARRAY_LENGTH(kmem_cache_s_name));
        fprintf(fp, "           kmem_cache_s_c_name: %d\n",
                ARRAY_LENGTH(kmem_cache_s_c_name));
        fprintf(fp, "            kmem_cache_s_array: %d\n",
                ARRAY_LENGTH(kmem_cache_s_array));
        fprintf(fp, "          kmem_cache_s_cpudata: %d\n",
                ARRAY_LENGTH(kmem_cache_s_cpudata));
	fprintf(fp, "                       log_buf: %d\n", 
		ARRAY_LENGTH(log_buf));
	fprintf(fp, "                      irq_desc: %d\n",
		ARRAY_LENGTH(irq_desc));
        fprintf(fp, "                    irq_action: %d\n",
                ARRAY_LENGTH(irq_action));
	fprintf(fp, "                 timer_vec_vec: %d\n", 
		get_array_length("timer_vec.vec", NULL, SIZE(list_head)));
	fprintf(fp, "            timer_vec_root_vec: %d\n", 
		get_array_length("timer_vec_root.vec", NULL, SIZE(list_head)));
        fprintf(fp, "               tvec_root_s_vec: %d\n",
                get_array_length("tvec_root_s.vec", NULL, SIZE(list_head)));
        fprintf(fp, "                    tvec_s_vec: %d\n",
                get_array_length("tvec_s.vec", NULL, SIZE(list_head)));
	fprintf(fp, "               page_hash_table: %d\n", 
		ARRAY_LENGTH(page_hash_table));
	fprintf(fp, "               net_device_name: %d\n", 
		ARRAY_LENGTH(net_device_name));
	fprintf(fp, "      neigh_table_hash_buckets: %d\n", 
		get_array_length("neigh_table.hash_buckets", NULL, 
			sizeof(void *)));
	fprintf(fp, "                  neighbour_ha: %d\n", 
		get_array_length("neighbour.ha", NULL, sizeof(char)));
	fprintf(fp, "                     swap_info: %d\n", 
		get_array_length("swap_info", NULL, 0));
	fprintf(fp, "        pglist_data_node_zones: %d\n",
                ARRAY_LENGTH(pglist_data_node_zones));
	fprintf(fp, "         zone_struct_free_area: %d\n",
                ARRAY_LENGTH(zone_struct_free_area));
	fprintf(fp, "                zone_free_area: %d\n",
                ARRAY_LENGTH(zone_free_area));
	fprintf(fp, "                     free_area: %d\n",
		ARRAY_LENGTH(free_area));
	fprintf(fp, "           free_area_DIMENSION: %d\n",
		ARRAY_LENGTH(free_area_DIMENSION));
        fprintf(fp, "              prio_array_queue: %d\n",
                get_array_length("prio_array.queue", NULL, SIZE(list_head)));
	fprintf(fp, "            height_to_maxindex: %d\n",
		ARRAY_LENGTH(height_to_maxindex));

	if (spec) {
		int in_size_table, in_array_table, arrays, offsets, sizes;

		in_size_table = in_array_table = arrays = offsets = sizes = 0;

        	rewind(pc->tmpfile);
        	while (fgets(buf, BUFSIZE, pc->tmpfile)) {
			if (strstr(buf, "size_table:"))
				in_size_table = TRUE;

                        if (strstr(buf, "array_table:")) {
                                in_array_table = TRUE;
				in_size_table = FALSE;
			}

			if (strstr(buf, spec)) {
				if (in_size_table) {
					if (!sizes)
						fprintf(pc->saved_fp,
                                          "%s                    size_table:\n",
							offsets ? "\n" : "");
					sizes++;
                                } else if (in_array_table) {
                                        if (!arrays)
                                                fprintf(pc->saved_fp,
                                          "%s                   array_table:\n",
                                                        offsets || sizes ? 
							"\n" : "");
                                        arrays++;
			        } else {
					if (!offsets)
        					fprintf(pc->saved_fp, 
				           "                  offset_table:\n");
					offsets++;
				}

				if (strstr(buf, " size_table:") ||
				    strstr(buf, " array_table:") ||
				    strstr(buf, " offset_table:"))
					break;
		
				fprintf(pc->saved_fp, buf);
			}
		}
		close_tmpfile();
	}

	if (makestruct) {
		fprintf(pc->saved_fp, 
		    "static struct builtin_debug_table %s;\n\n", 
			revname);

                rewind(pc->tmpfile);
                while (fgets(buf, BUFSIZE, pc->tmpfile)) {
			if (strstr(buf, " offset_table:\n")) {
				fprintf(pc->saved_fp, 
			     "static struct offset_table %s_offset_table = {\n",
					revname);
				continue;
			}
			if (strstr(buf, " size_table:\n")) {
				fprintf(pc->saved_fp, 
			         "static struct size_table %s_size_table = {\n",
					revname);
				continue;
			}
			if (strstr(buf, " array_table:\n")) {
				fprintf(pc->saved_fp, 
			       "static struct array_table %s_array_table = {\n",
					revname);
				continue;
			}
			if (STREQ(buf, "\n")) {
				fprintf(pc->saved_fp, "};\n\n");
				continue; 
			}
			
			fprintf(pc->saved_fp, "%s,\n", strip_linefeeds(buf));
		}
		fprintf(pc->saved_fp, "};\n\n");

		close_tmpfile();

		fprintf(fp, "static struct builtin_debug_table %s = {\n", 
			revname);
		fprintf(fp, "         release: \"%s\",\n", uts->release);
		fprintf(fp, "    machine_type: \"%s\",\n", pc->machine_type);
		fprintf(fp, "    offset_table: &%s_offset_table,\n", revname);
		fprintf(fp, "      size_table: &%s_size_table,\n", revname);
		fprintf(fp, "     array_table: &%s_array_table,\n", revname);
		fprintf(fp, "};\n\n");
	}

	pc->flags |= data_debug;
}




#define NUMARGS_CACHE_ENTRIES (100)

static struct numargs_cache {
        ulong function;
        int numargs;
} numargs_cache[NUMARGS_CACHE_ENTRIES] = { {0} };

static int numargs_cache_index = 0;

int
get_function_numargs(ulong callpc)
{
	int i;
        struct numargs_cache *na;
	struct gnu_request *req;
	int retval;
	ulong func;

	func = closest_symbol_value(callpc);

	if (!func)
		return -1;

        for (i = 0; i < NUMARGS_CACHE_ENTRIES; i++) {
                na = &numargs_cache[i];
		if (!na->function) {
			numargs_cache_index = i;
			break;
		}

		if (na->function == func) 
			return na->numargs;
        }

	req = (struct gnu_request *)GETBUF(sizeof(struct gnu_request));
	req->buf = GETBUF(BUFSIZE);

	req->command = GNU_FUNCTION_NUMARGS;
	req->flags |= GNU_RETURN_ON_ERROR;
	req->pc = func;
	gdb_interface(req);

	if (req->flags & GNU_COMMAND_FAILED) { 
		retval = -1;
		goto func_done; 
	}

	retval = (int)req->value;

func_done:

	FREEBUF(req->buf);
	FREEBUF(req);

        numargs_cache_index %= NUMARGS_CACHE_ENTRIES;
        na = &numargs_cache[numargs_cache_index++];
        na->function = func;
        na->numargs = retval;

	return retval;
}

/*
 *  help -c output
 */
void
dump_numargs_cache(void)
{
        int i;
        struct numargs_cache *na;
	char buf[BUFSIZE];

        fprintf(fp, "numargs_cache_index: %d\n", numargs_cache_index);

        for (i = 0; i < NUMARGS_CACHE_ENTRIES; i++) {
                na = &numargs_cache[i];

		if (!na->function)
			break;

		fprintf(fp, "%lx (%s): %d\n", 
			na->function, 
			value_to_symstr(na->function, buf, 0),
			na->numargs);
        }
}

/*
 *  This is the call-back function that is passed to bfd_map_over_sections().
 *  Based upon the request, check whether the passed-in section has what
 *  the caller needs.  The MODULE_SECTIONS code is tricky because it has
 *  to keep a running alignment value as it walks through the section
 *  headers in order to eventually calculate the module's base data address.
 */
static void
section_header_info(bfd *bfd, asection *section, void *reqptr)
{
	int i;
	struct load_module *lm;
	int request;
        asection **sec;

	request = (int)((ulong)reqptr);

	switch (request)
	{
	case (uint)KERNEL_SECTIONS:
        	sec = (asection **)st->sections;
        	for (i = 0; (i < st->bfd->section_count) && *sec; i++)
			sec++;
		*sec = section;

        	if (STREQ(bfd_get_section_name(bfd, section), ".text.init") ||
		    STREQ(bfd_get_section_name(bfd, section), ".init.text")) {
                	kt->stext_init = (ulong)
				bfd_get_section_vma(bfd, section);
                	kt->etext_init = kt->stext_init +
                        	(ulong)bfd_section_size(bfd, section);
		}
                if (STREQ(bfd_get_section_name(bfd, section), ".text") ||
                    STREQ(bfd_get_section_name(bfd, section), ".data")) {
                        if (!(bfd_get_section_flags(bfd, section) & SEC_LOAD))
                                st->flags |= NO_SEC_LOAD;
                        if (!(bfd_get_section_flags(bfd, section) &
                            SEC_HAS_CONTENTS))
                                st->flags |= NO_SEC_CONTENTS;
                }
		break;

	case (uint)MODULE_SECTIONS:
		lm = st->current;
		store_section_data(lm, bfd, section);
		break;

	case (uint)VERIFY_SECTIONS:
		if (STREQ(bfd_get_section_name(bfd, section), ".text") ||
		    STREQ(bfd_get_section_name(bfd, section), ".data")) {
			if (!(bfd_get_section_flags(bfd, section) & SEC_LOAD))
				st->flags |= NO_SEC_LOAD;
			if (!(bfd_get_section_flags(bfd, section) & 
			    SEC_HAS_CONTENTS))
				st->flags |= NO_SEC_CONTENTS;
		}
		break;

	default:
		error(FATAL, "invalid call to section_header_info\n");
		break;

	}
}

/*
 *  Emulate insmod by calculating the priorities of each section.
 *  The priority number will be used later by calculate_load_order()
 *  to determine the the starting addresses of the text and data 
 *  sections.
 *
 *  insmod uses the following code sequence -- which references the actual ELF
 *  section header structure data:
 *
 *    ac = 0;
 *    if (a->name[0] != '.' || strlen(a->name) != 10 ||
 *        strcmp(a->name + 5, ".init")) ac |= 32;
 *    if (af & SHF_ALLOC) ac |= 16;
 *    if (!(af & SHF_WRITE)) ac |= 8;
 *    if (af & SHF_EXECINSTR) ac |= 4;
 *    if (a->header.sh_type != SHT_NOBITS) ac |= 2;
 *
 *  BFD abstracts the ELF section header into an asection structure, so this
 *  code determines the priority using the relevant logic.
 */

static void
store_section_data(struct load_module *lm, bfd *bfd, asection *section)
{
	int i;
	int prio;
	char *name;

	prio = 0;
	name = (char *)bfd_get_section_name(bfd, section);

        if (name[0] != '.' || strlen(name) != 10 || strcmp(name + 5, ".init")) 
		prio |= 32;
	if (section->flags & SEC_ALLOC)
		prio |= 16;
	if (section->flags & SEC_READONLY)
		prio |= 8;
	if (section->flags & SEC_CODE)
		prio |= 4;
	if (!STREQ(name, ".bss"))
		prio |= 2;

	i = lm->mod_sections;
	lm->mod_section_data[i].section = section;
	lm->mod_section_data[i].priority = prio;
	lm->mod_section_data[i].flags = section->flags;
	lm->mod_section_data[i].size = bfd_section_size(bfd, section);
	if (strlen(name) < MAX_MOD_SEC_NAME)
		strcpy(lm->mod_section_data[i].name, name);
	else
		strncpy(lm->mod_section_data[i].name, name, MAX_MOD_SEC_NAME-1);
	lm->mod_sections += 1;
}

/*    
 *  insmod first calculates a priority for each module section, and re-orders
 *  the sections from their ELF object file position -- that priority was
 *  determined in store_section_priority().  Now, based upon a priority-based
 *  ordering, this routine calculates the starting offset for each section.
 *  This is the code segment from insmod that is being emulated here:
 *
 *    unsigned long
 *    obj_load_size (struct obj_file *f)
 *    {
 *      unsigned long dot = 0;
 *      struct obj_section *sec;
 *    
 *      /+ Finalize the positions of the sections relative to one another.  +/
 *    
 *      for (sec = f->load_order; sec ; sec = sec->load_next)
 *        {
 *          ElfW(Addr) align;
 *    
 *          align = sec->header.sh_addralign;
 *          if (align && (dot & (align - 1)))
 *            dot = (dot | (align - 1)) + 1;
 *    
 *          sec->header.sh_addr = dot;
 *          dot += sec->header.sh_size;
 *        }
 *    
 *      return dot;
 *    }
 *
 *  Another insmod hack extends the .kstrtab section with a string containing
 *  the name of the module.  If the .kstrtab comes before the .data section,
 *  it in turn gets bumped up.
 *
 *  BFD abstracts the ELF section header into an asection structure, so this
 *  code determines the priority using the relevant logic.
 *
 *  Later versions of insmod do the work for us by creating pseudo-symbols
 *  that contain the base address of the text, rodata, data and bss sections.
 *  When that's the case, veer off to check_insmod_builtin() to potentially
 *  override the offset value calculated here.
 */

static void
calculate_load_order(struct load_module *lm, bfd *bfd)
{
	int i;
	asection *section;
	ulong alignment;
	ulong offset;

	switch (kt->flags & (KMOD_V1|KMOD_V2))
	{
	case KMOD_V1:
        	offset = lm->mod_size_of_struct;
		break;
	case KMOD_V2:
		offset = lm->mod_base;
		break;
	}

        qsort(&lm->mod_section_data[0], lm->mod_sections, 
		sizeof(struct mod_section_data), compare_prios);

	for (i = (lm->mod_sections-1); i >= 0; i--) {
		section = lm->mod_section_data[i].section;

               	alignment = power(2, bfd_get_section_alignment(bfd, section));

                if (alignment && (offset & (alignment - 1)))
                	offset = (offset | (alignment - 1)) + 1;

		lm->mod_section_data[i].offset = offset;

                if (CRASHDEBUG(1))
                        fprintf(fp, "%12s  prio: %x  flags: %x offset: %lx\n",
                                lm->mod_section_data[i].name,
                                lm->mod_section_data[i].priority,
                                lm->mod_section_data[i].flags,
				lm->mod_section_data[i].offset);

		if (st->flags & INSMOD_BUILTIN)
			check_insmod_builtin(lm, i, &offset);

		if (STREQ(lm->mod_section_data[i].name, ".text"))
                	lm->mod_text_start = lm->mod_base + offset;

		if (STREQ(lm->mod_section_data[i].name, ".data"))
                	lm->mod_data_start = lm->mod_base + offset;

                if (STREQ(lm->mod_section_data[i].name, ".bss"))
                        lm->mod_bss_start = lm->mod_base + offset;

                if (STREQ(lm->mod_section_data[i].name, ".rodata"))
                        lm->mod_rodata_start = lm->mod_base + offset;

		offset += bfd_section_size(bfd, section);

                if (STREQ(bfd_get_section_name(bfd, section), ".kstrtab"))
                	offset += strlen(lm->mod_name)+1;
        }
}

/*
 *  Later versons of insmod store basic address information of each
 *  module in a format that looks like the following example of the
 *  nfsd module:
 *
 *  d004d000  __insmod_nfsd_O/lib/modules/2.2.17/fs/nfsd.o_M3A7EE300_V131601
 *  d004d054  __insmod_nfsd_S.text_L30208
 *  d0054840  __insmod_nfsd_S.rodata_L8930
 *  d0056b40  __insmod_nfsd_S.data_L1220
 *  d00570c0  __insmod_nfsd_S.bss_L123840
 *
 *  When that's true, override the offset value made by calculate_load_order().
 */

static void
check_insmod_builtin(struct load_module *lm, int index, ulong *offset)
{
	struct syment *sp;
	char buf[BUFSIZE];
	ulong offs;

        sprintf(buf, "__insmod_%s_S%s", 
		lm->mod_name,
		lm->mod_section_data[index].name);

        if (symbol_query(buf, NULL, &sp) == 1) {
		if (CRASHDEBUG(1))
			fprintf(fp, "check_insmod_builtin: %lx %s\n",
				sp->value, sp->name);
		offs = sp->value - lm->mod_base;
		if (offs != *offset) {
			if (CRASHDEBUG(1))
			    	fprintf(fp, 
			           "check_insmod_builtin: [%s] %s %lx != %lx\n",
					lm->mod_name, 
					lm->mod_section_data[index].name,
					offs, *offset);
			*offset = offs;
		}
        }
}

/*
 *  Determine whether a module symbol is one of the insmod-created symbols
 *  described above.
 */

static int
is_insmod_builtin(struct load_module *lm, struct syment *sp)
{
        char buf[BUFSIZE];

        if (!(st->flags & INSMOD_BUILTIN))
                return FALSE;

        sprintf(buf, "__insmod_%s_S", lm->mod_name);
        if (strstr(sp->name, buf))
                return TRUE;

        return FALSE;
}


/*
 *  Modified from typical "qsort" help functions to simulate section-ordering
 *  done by insmod when loading modules.
 */
static int
compare_prios(const void *v1, const void *v2)
{
        struct mod_section_data *md1, *md2;

        md1 = (struct mod_section_data *)v1;
        md2 = (struct mod_section_data *)v2;

	return (md1->priority < md2->priority ? -1 : 1);
}



/*
 *  This routine scours a module object file namelist for global text and
 *  data symbols, sorting and storing them in a static table for quick 
 *  reference.  This allows access to non-EXPORT_SYMBOL() symbols.
 *  The object file is then passed to gdb for loading of all symbolic
 *  and debugging data.
 *
 *  Thanks to David Addison (addy@quadrics.com) for the suggestion.
 */
int
load_module_symbols(char *modref, char *namelist, ulong base_addr)
{
	static bfd *mbfd;
	char **matching;
  	long symcount;
  	void *minisyms;
  	unsigned int size;
	int result;
	struct load_module *lm;
	asymbol *sort_x;
	asymbol *sort_y;

	if (!is_module_name(modref, NULL, &lm))
		error(FATAL, "%s: not a loaded module name\n", modref);

	if ((lm->mod_flags & MOD_LOAD_SYMS) || strlen(lm->mod_namelist)) {
		if (CRASHDEBUG(1))
			fprintf(fp, "%s: module symbols are already loaded\n", 
				modref);
		return TRUE;
	}

	if (CRASHDEBUG(1))
		fprintf(fp, "load_module_symbols: %s %s %lx\n",
			modref, namelist, base_addr);

	switch (kt->flags & (KMOD_V1|KMOD_V2))
	{
	case KMOD_V1:
		break;
	case KMOD_V2:
		st->current = lm;
        	BZERO(lm->mod_namelist, MAX_MOD_NAMELIST);
        	if (strlen(namelist) < MAX_MOD_NAMELIST)
                	strcpy(lm->mod_namelist, namelist);
        	else
                	strncpy(lm->mod_namelist, namelist, MAX_MOD_NAMELIST-1);
		goto add_symbols;
	}

  	if ((mbfd = bfd_openr(namelist, NULL)) == NULL) 
		error(FATAL, "cannot open object file: %s\n", namelist);

  	if (!bfd_check_format_matches(mbfd, bfd_object, &matching))
		error(FATAL, "cannot determine object file format: %s\n",
			namelist);

        if (!(bfd_get_file_flags(mbfd) & HAS_SYMS)) 
          	error(FATAL, "no symbols in object file: %s\n", namelist);

	symcount = bfd_read_minisymbols(mbfd, FALSE, &minisyms, &size);
	if (symcount < 0)
		error(FATAL, "cannot access symbol table data: %s\n",
			namelist);
	else if (symcount == 0)
		error(FATAL, "no symbols in object file: %s\n", namelist);

        sort_x = bfd_make_empty_symbol(mbfd);
        sort_y = bfd_make_empty_symbol(mbfd);
        if (sort_x == NULL || sort_y == NULL)
		error(FATAL, "bfd_make_empty_symbol() failed\n");

	gnu_qsort(mbfd, minisyms, symcount, size, sort_x, sort_y);

	store_load_module_symbols(mbfd, FALSE, minisyms, symcount, 
		size, base_addr, namelist); 

	free(minisyms);

	bfd_close(mbfd);

add_symbols:
	result = add_symbol_file(st->current);

	if (CRASHDEBUG(1))
		check_for_dups(st->current);

	st->current = NULL;

	return result;
}

/*
 *  Add a module's symbol file data to gdb's notion of the world.
 */
static int
add_symbol_file(struct load_module *lm)
{
        struct gnu_request request, *req;
	char buf[BUFSIZE];

	req = &request;
	BZERO(req, sizeof(struct gnu_request));
        req->command = GNU_ADD_SYMBOL_FILE;
	req->addr = (ulong)lm;
	req->buf = buf;
	if (!CRASHDEBUG(1))
		req->fp = pc->nullfp;

	st->flags |= ADD_SYMBOL_FILE;
	gdb_interface(req); 
	st->flags &= ~ADD_SYMBOL_FILE;

	sprintf(buf, "set complaints 0");
	gdb_pass_through(buf, NULL, 0);

	return(!(req->flags & GNU_COMMAND_FAILED));
}


/*
 *  Given a syment structure of a valid symbol, determine which 
 *  load_module (if any) it belongs to.
 */
static int
load_module_index(struct syment *sp)
{
	int i;
	ulong value;
	struct load_module *lm;

	value = sp->value;

        for (i = 0; i < st->mods_installed; i++) {
                lm = &st->load_modules[i];

                if ((value >= lm->mod_base) &&
                    (value < (lm->mod_base + lm->mod_size))) 
                        return i;
        }

	return (error(FATAL, "cannot find %lx (%s) in module space\n",
		sp->value, sp->name));
}


/*
 *  Replace the externally-defined module symbols found in store_load_modules() 
 *  with all the text and data symbols found in the load module object file.
 */
static void
store_load_module_symbols(bfd *bfd, int dynamic, void *minisyms, 
	long symcount, unsigned int size, ulong base_addr, char *namelist)
{
	int i;
  	asymbol *store;
        asymbol *sym;
  	bfd_byte *from, *fromend;
        symbol_info syminfo;
	struct syment *sp, *spx;
	struct load_module *lm;
	char name[BUFSIZE];
	char *nameptr, *secname;
	long index;
	long symalloc;
	int found;

        if ((store = bfd_make_empty_symbol(bfd)) == NULL)
                error(FATAL, "bfd_make_empty_symbol() failed\n");

	st->current = NULL;

	/*
	 *  Find out whether this module has already been loaded.  Coming
	 *  out of this for loop, lm->mod_load_symtable will either be set to 
	 *  a reusable symbol table, or NULL if it needs to be re-malloc'd.
	 */

	for (i = 0; i < st->mods_installed; i++) {
		lm = &st->load_modules[i];

               	if (lm->mod_base == base_addr) {
			symalloc = symcount + lm->mod_ext_symcnt;
			if (lm->mod_load_symtable && 
			   (lm->mod_symalloc < symalloc)) {
				free(lm->mod_load_symtable);
				namespace_ctl(NAMESPACE_FREE, 
					&lm->mod_load_namespace, NULL, NULL);
				lm->mod_load_symtable = NULL;
			}
			break;
		}
       	}

	if (i == st->mods_installed)
		error(FATAL, "cannot find module at %lx\n", base_addr);

	if (!lm->mod_load_symtable) {
	        if ((lm->mod_load_symtable = (struct syment *)
	             malloc(symalloc * sizeof(struct syment))) == NULL)
	                error(FATAL, "module syment space malloc: %s\n",
	                        strerror(errno));

		if (!namespace_ctl(NAMESPACE_INIT, &lm->mod_load_namespace, 
		    (void *)symalloc, NULL))
			error(FATAL, "module name space malloc: %s\n",
	                        strerror(errno));
	} else 
                namespace_ctl(NAMESPACE_REUSE, &lm->mod_load_namespace, 
			NULL, NULL); 

	st->current = lm;
	lm->mod_symalloc = symalloc;
	BZERO(lm->mod_namelist, MAX_MOD_NAMELIST);
	if (strlen(namelist) < MAX_MOD_NAMELIST)
		strcpy(lm->mod_namelist, namelist);
	else
		strncpy(lm->mod_namelist, namelist, MAX_MOD_NAMELIST-1);
        lm->mod_text_start = lm->mod_data_start = 0;
	lm->mod_rodata_start = lm->mod_bss_start = 0;
	lm->mod_load_symcnt = 0;
	lm->mod_sections = 0;
	sp = lm->mod_load_symtable;

	if (!(lm->mod_section_data = (struct mod_section_data *)
	    malloc(sizeof(struct mod_section_data) *
	    (bfd->section_count+1))))
		error(FATAL, "module section data array malloc: %s\n",
                        strerror(errno));

        bfd_map_over_sections(bfd, section_header_info, MODULE_SECTIONS);

	calculate_load_order(lm, bfd);

        from = (bfd_byte *) minisyms;
        fromend = from + symcount * size;
        for (; from < fromend; from += size)
        {
                if ((sym = bfd_minisymbol_to_symbol(bfd, dynamic, from, store))
                    == NULL)
                        error(FATAL, "bfd_minisymbol_to_symbol() failed\n");

                bfd_get_symbol_info(bfd, sym, &syminfo);

		secname = (char *)bfd_get_section_name(bfd, sym->section);

		switch (syminfo.type)
		{
		case 'b':
		case 'B':
                       if (CRASHDEBUG(2))
                            fprintf(fp, "%08lx (%c) [%s] %s\n",  
				(ulong)syminfo.value,
                                syminfo.type, secname, syminfo.name);

                        syminfo.value += lm->mod_bss_start;
                        strcpy(name, syminfo.name);
                        strip_module_symbol_end(name);

                        if (machdep->verify_symbol(name, syminfo.value, 
			    syminfo.type)) {
                                sp->value = syminfo.value;
				sp->type = syminfo.type;
				
                                namespace_ctl(NAMESPACE_INSTALL,
                                        &lm->mod_load_namespace, sp, name); 

                                if (CRASHDEBUG(1))
                                    fprintf(fp, "%08lx %s\n",  sp->value,
                                        name);

                                sp++;
                                lm->mod_load_symcnt++;
                        }
			break;

		case 'd': 
		case 'D':
                        if (CRASHDEBUG(2))
                            fprintf(fp, "%08lx (%c) [%s] %s\n",  
				(ulong)syminfo.value,
                                syminfo.type, secname, syminfo.name);

			if (STREQ(secname, ".rodata"))
                        	syminfo.value += lm->mod_rodata_start;
			else
                        	syminfo.value += lm->mod_data_start;

                        strcpy(name, syminfo.name);
                        strip_module_symbol_end(name);

                        if (machdep->verify_symbol(name, syminfo.value, 
			    syminfo.type)) {
                                sp->value = syminfo.value;
				sp->type = syminfo.type;
                                namespace_ctl(NAMESPACE_INSTALL,
                                        &lm->mod_load_namespace, sp, name); 

                                if (CRASHDEBUG(1))
                                    fprintf(fp, "%08lx %s\n",  sp->value,
                                        name);

                                sp++;
                                lm->mod_load_symcnt++;
                        }
			break;

		case 't':
		case 'T':
			if (CRASHDEBUG(2))
			    fprintf(fp, "%08lx (%c) [%s] %s\n",  
				(ulong)syminfo.value, 
				syminfo.type, secname, syminfo.name); 

			syminfo.value += lm->mod_text_start;
			strcpy(name, syminfo.name);
			strip_module_symbol_end(name);

			if ((st->flags & INSMOD_BUILTIN) &&
			    (STREQ(name, "init_module") || 
			    STREQ(name, "cleanup_module")))
				break;

                	if (machdep->verify_symbol(name, syminfo.value, 
			    syminfo.type)) {
                        	sp->value = syminfo.value;
				sp->type = syminfo.type;
                                namespace_ctl(NAMESPACE_INSTALL,
                                        &lm->mod_load_namespace, sp, name);

                                if (CRASHDEBUG(1))
                                    fprintf(fp, "%08lx %s\n",  sp->value,
                                	name);

                        	sp++;
				lm->mod_load_symcnt++;
                	} 

			break;

		default:
			break;
		}
	}

	lm->mod_load_symend = &lm->mod_load_symtable[lm->mod_load_symcnt];

	/* 
	 *  Merge in any externals that didn't show up in the four
	 *  syminfo data types accepted above, plus the two pseudo symbols.
         *  Note that the new syment name pointers haven't been resolved yet.
	 */
	for (spx = lm->mod_ext_symtable; spx <= lm->mod_ext_symend; spx++) {
		found = FALSE;
	        for (sp = lm->mod_load_symtable; 
		     sp < lm->mod_load_symend; sp++) {
			index = (long)sp->name;
			nameptr = &lm->mod_load_namespace.address[index]; 
			if (STREQ(spx->name, nameptr)) {
				found = TRUE;
				if (spx->value == sp->value) {
					if (CRASHDEBUG(1))
						fprintf(fp, 
						    "%s: %s matches!\n",
							lm->mod_name,
							nameptr);
				} else {
					if (CRASHDEBUG(1))
						fprintf(fp, 
				       "[%s] %s: %lx != extern'd value: %lx\n",
							lm->mod_name,
							nameptr, sp->value,
							spx->value);
				}
				break;
			}
	    	}
		if (!found) {
			if (CRASHDEBUG(1))
				fprintf(fp, "append ext %s (%lx)\n",
                       			spx->name, spx->value);
			/* append it here... */
        		namespace_ctl(NAMESPACE_INSTALL, 
				&lm->mod_load_namespace, 
				lm->mod_load_symend, spx->name); 

			lm->mod_load_symend->value = spx->value;
			lm->mod_load_symend->type = spx->type;
			lm->mod_load_symend++;
			lm->mod_load_symcnt++;
		} 
	}

        namespace_ctl(NAMESPACE_COMPLETE, &lm->mod_load_namespace, 
		lm->mod_load_symtable, lm->mod_load_symend);

        qsort(lm->mod_load_symtable, lm->mod_load_symcnt, sizeof(struct syment),
                compare_syms);

	lm->mod_load_symend--;
	if (!MODULE_END(lm->mod_load_symend))
		error(INFO, "%s: last symbol is not _MODULE_END_%s?\n",
			lm->mod_name, lm->mod_name);

        lm->mod_symtable = lm->mod_load_symtable;
        lm->mod_symend = lm->mod_load_symend;

	lm->mod_flags &= ~MOD_EXT_SYMS;
	lm->mod_flags |= MOD_LOAD_SYMS;

	st->flags |= LOAD_MODULE_SYMS;

}

/*
 *  Delete a load module's symbol table.  If base_addr is NULL, delete the
 *  complete list of modules.
 */
void 
delete_load_module(ulong base_addr)
{
	int i;
        struct load_module *lm;
	struct gnu_request request, *req;

        req = &request; 
	BZERO(req, sizeof(struct gnu_request));
       	req->command = GNU_DELETE_SYMBOL_FILE;

	if (base_addr == ALL_MODULES) {
		for (i = 0; i < st->mods_installed; i++) {
        		lm = &st->load_modules[i];
			if (lm->mod_flags & MOD_LOAD_SYMS) {
        			req->name = lm->mod_namelist;
        			gdb_interface(req); 
			}
			if (lm->mod_load_symtable) {
                        	free(lm->mod_load_symtable);
                                namespace_ctl(NAMESPACE_FREE,
                                        &lm->mod_load_namespace, NULL, NULL);
			}
			if (lm->mod_flags & MOD_REMOTE)
				unlink_module(lm);
			lm->mod_symtable = lm->mod_ext_symtable;
			lm->mod_symend = lm->mod_ext_symend;
			lm->mod_flags &= ~(MOD_LOAD_SYMS|MOD_REMOTE);
			lm->mod_flags |= MOD_EXT_SYMS;
			lm->mod_load_symtable = NULL;
			lm->mod_load_symend = NULL;
			lm->mod_namelist[0] = NULLCHAR;
			lm->mod_load_symcnt = lm->mod_symalloc = 0;
			lm->mod_text_start = lm->mod_data_start = 0; 
			lm->mod_bss_start = lm->mod_rodata_start = 0;
			lm->mod_sections = 0;
			if (lm->mod_section_data)
				free(lm->mod_section_data);
			lm->mod_section_data = (struct mod_section_data *)0;
		}
		st->flags &= ~LOAD_MODULE_SYMS;
		return;
	}

	st->flags &= ~LOAD_MODULE_SYMS;  /* restored below (if any found) */

	for (i = 0; i < st->mods_installed; i++) {
		lm = &st->load_modules[i];
                if (lm->mod_base == base_addr) {
			if (lm->mod_flags & MOD_LOAD_SYMS) {
                        	req->name = lm->mod_namelist;
                        	gdb_interface(req);
			}
			if (lm->mod_load_symtable) {
                        	free(lm->mod_load_symtable);
				namespace_ctl(NAMESPACE_FREE,
                                        &lm->mod_load_namespace, NULL, NULL);
			}
			if (lm->mod_flags & MOD_REMOTE)
				unlink_module(lm);
			lm->mod_symtable = lm->mod_ext_symtable;
			lm->mod_symend = lm->mod_ext_symend;
                        lm->mod_flags &= ~(MOD_LOAD_SYMS|MOD_REMOTE);
                        lm->mod_flags |= MOD_EXT_SYMS;
                        lm->mod_load_symtable = NULL;
                        lm->mod_load_symend = NULL;
                        lm->mod_namelist[0] = NULLCHAR;
                        lm->mod_load_symcnt = lm->mod_symalloc = 0;
                        lm->mod_text_start = lm->mod_data_start = 0;
			lm->mod_bss_start = lm->mod_rodata_start = 0;
			lm->mod_sections = 0;
			if (lm->mod_section_data)
				free(lm->mod_section_data);
			lm->mod_section_data = (struct mod_section_data *)0;
                } else if (lm->mod_flags & MOD_LOAD_SYMS)
			st->flags |= LOAD_MODULE_SYMS;
        }
}


/*
 *  Check whether a string is the name of a module.  If requested, return 
 *  the base address of the module.
 */
int
is_module_name(char *s, ulong *addr, struct load_module **lmp)
{
        int i;
        struct load_module *lm;

        if (NO_MODULES())
                return FALSE;

        for (i = 0; i < st->mods_installed; i++) {
                lm = &st->load_modules[i];
		if (STREQ(s, lm->mod_name)) {
			if (addr)
				*addr = lm->mod_base;
			if (lmp)
				*lmp = lm;
			return TRUE;
		}
        }

	return FALSE;
}


/*
 *  Check whether an value is the base address of a module.  If requested,
 *  return the module name.
 */
int
is_module_address(ulong check_addr, char *module_name)
{
        int i;
        struct load_module *lm;

        if (NO_MODULES())
                return FALSE;

        for (i = 0; i < st->mods_installed; i++) {
                lm = &st->load_modules[i];
                if (check_addr == lm->mod_base) {
                        if (module_name)
				strcpy(module_name, lm->mod_name);
                        return TRUE;
                }
        }

	return FALSE;
}

/*
 *  In a MOD_EXT_SYMBOLS module, find a rough estimate as to where the
 *  .rodata section starts.  The value will be used by is_kernel_text()
 *  when symbols are not loaded.
 */

static void
find_mod_etext(struct load_module *lm)
{
	ulong start, end;
	char *modbuf;
	ulong maxchunk, alloc;
	long offset;

        start = roundup(lm->mod_size_of_struct, sizeof(long)) + lm->mod_base;
        end = lm->mod_base + lm->mod_size;

	maxchunk = MIN(end-start, KILOBYTES(32));

	modbuf = GETBUF(maxchunk);

	while (start < end) {
		alloc = MIN(maxchunk, end-start);

	        readmem(start, KVADDR, modbuf, alloc, 
			"module rodata search chunk", FAULT_ON_ERROR);

		if ((offset = rodata_search((ulong *)modbuf, alloc)) >= 0) 
			break;

		start += alloc;
	}

	FREEBUF(modbuf);

	if (offset >= 0) 
		lm->mod_etext_guess = start + offset;
	else
		lm->mod_etext_guess = end;
	
}

#define ASCII_WORD_COUNT (16/sizeof(ulong))

static long
rodata_search(ulong *buf, ulong size)
{
	int i, acnt, words;
	long offset;
	ulong *wordptr;
	
	words = size/sizeof(ulong);
	wordptr = buf;

	for (i = acnt = 0, offset = -1; i < words; i++, wordptr++) {
		if (ascii_long(*wordptr)) {
			if (acnt++ == 0)
				offset = i * sizeof(ulong);
		} else {
			acnt = 0;
			offset = -1;
		}

		if (acnt == ASCII_WORD_COUNT) 
			break;
	}

	return offset;
}

static int
ascii_long(ulong word)
{
	int i, cnt;
	unsigned char c;

	for (i = cnt = 0; i < sizeof(ulong); i++) {
		c = (unsigned char)((word >> (i*BITS_PER_BYTE)) & 0xff);
		if ((c >= ' ') && (c < 0x7f))
			cnt++; 
	}

	return (cnt == sizeof(ulong));
}

/*
 *  Symbol sorting routines adapted from binutils/nm.c
 */

/* nm.c -- Describe symbol table of a rel file.
   Copyright 1991, 92, 93, 94, 95, 96, 97, 1998 Free Software Foundation, Inc.

   This file is part of GNU Binutils.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

static bfd *gnu_sort_bfd;
static asymbol *gnu_sort_x;
static asymbol *gnu_sort_y;

#define valueof(x) ((x)->section->vma + (x)->value)

static int
non_numeric_forward(const void *P_x, const void *P_y)
{
  	asymbol *x, *y;
  	const char *xn, *yn;

  	x = bfd_minisymbol_to_symbol(gnu_sort_bfd, FALSE, P_x, gnu_sort_x);
  	y = bfd_minisymbol_to_symbol(gnu_sort_bfd, FALSE, P_y, gnu_sort_y);
  	if (x == NULL || y == NULL)
		error(FATAL, "bfd_minisymbol_to_symbol failed\n");

  	xn = bfd_asymbol_name(x);
  	yn = bfd_asymbol_name(y);

  	return ((xn == NULL) ? ((yn == NULL) ? 0 : -1) :
          	((yn == NULL) ? 1 : strcmp (xn, yn)));
}

static int
numeric_forward(const void *P_x, const void *P_y)
{
  	asymbol *x, *y;
  	asection *xs, *ys;

  	x = bfd_minisymbol_to_symbol(gnu_sort_bfd, FALSE, P_x, gnu_sort_x);
  	y = bfd_minisymbol_to_symbol(gnu_sort_bfd, FALSE, P_y, gnu_sort_y);
  	if (x == NULL || y == NULL)
		error(FATAL, "bfd_minisymbol_to_symbol failed\n");

  	xs = bfd_get_section(x);
  	ys = bfd_get_section(y);

  	if (bfd_is_und_section(xs)) {
      		if (!bfd_is_und_section(ys))
        		return -1;
    	}
  	else if (bfd_is_und_section (ys))
    		return 1;
  	else if (valueof (x) != valueof (y))
    		return valueof (x) < valueof (y) ? -1 : 1;

  	return non_numeric_forward(P_x, P_y);
}

static void
gnu_qsort(bfd *bfd, 
	  void *minisyms, 
	  long symcount, 
	  unsigned int size,
	  asymbol *x,
	  asymbol *y)
{
	gnu_sort_bfd = bfd;
	gnu_sort_x = x;
	gnu_sort_y = y;
	
        qsort(minisyms, symcount, size, numeric_forward);
}

/*
 *  Keep a stash of commonly-accessed text locations checked by the 
 *  back_trace code.  The saved values unsigned 32-bit values.
 *  The same routine is used to store and query, based upon whether
 *  the passed-in value and valptr args are non-zero.
 */
#define TEXT_CACHE     (50)
#define MAX_TEXT_CACHE (TEXT_CACHE*4)

struct text_cache_entry {
	ulong vaddr;
	uint32_t value;
};

static struct text_cache {
	int index;
	int entries;
	ulong hits;
	ulong refs;
	struct text_cache_entry *cache;
} text_cache = { 0 };

/*
 *  Cache the contents of 32-bit text addresses.  If "value" is set, the purpose
 *  is to cache it.  If "valptr" is set, a query is being made for the text
 *  address.
 */
int
text_value_cache(ulong vaddr, uint32_t value, uint32_t *valptr)
{
	int i;
	struct text_cache *tc;

	if (!is_kernel_text(vaddr)) 
		return FALSE;	

	tc = &text_cache;

	if (!tc->cache) {
		if (!(tc->cache = (struct text_cache_entry *)
		    malloc(sizeof(struct text_cache_entry) * TEXT_CACHE))) 
			return FALSE;
		BZERO(tc->cache, sizeof(struct text_cache_entry) * TEXT_CACHE);
		tc->index = 0;
		tc->entries = TEXT_CACHE;
	}

	if (value) {
		for (i = 0; i < tc->entries; i++) {
			if (tc->cache[i].vaddr == vaddr)
				return TRUE;
		}

		i = tc->index;
		tc->cache[i].vaddr = vaddr;
		tc->cache[i].value = value;
		tc->index++;
		if (tc->index == MAX_TEXT_CACHE) {
			tc->index = 0;
		} else if (tc->index == tc->entries) {
			struct text_cache_entry *old_cache;

			old_cache = tc->cache;
			if ((tc->cache = (struct text_cache_entry *)
                    	    realloc(old_cache, sizeof(struct text_cache_entry) *
			    (TEXT_CACHE+tc->entries)))) {
				BZERO(&tc->cache[tc->index], 
				    sizeof(struct text_cache_entry) * 
				    TEXT_CACHE);
				tc->entries += TEXT_CACHE;
			} else {
				tc->cache = old_cache;
				tc->index = 0;
			} 
		}
		return TRUE;
	}

	if (valptr) {
		tc->refs++;

		for (i = 0; i < tc->entries; i++) {
			if (!tc->cache[i].vaddr)
				return FALSE;

			if (tc->cache[i].vaddr == vaddr) {
				*valptr = tc->cache[i].value;
				tc->hits++;
				return TRUE;
			}
		}
	}

	return FALSE;
}

/*
 *  The gdb disassembler reads text memory byte-by-byte, so this routine
 *  acts as a front-end to the 32-bit (4-byte) text storage.
 */

int
text_value_cache_byte(ulong vaddr, unsigned char *valptr)
{
        int i;
	int shift;
        struct text_cache *tc;
	ulong valtmp;

        if (!is_kernel_text(vaddr))
                return FALSE;

        tc = &text_cache;

        tc->refs++;

        for (i = 0; i < tc->entries; i++) {
                if (!tc->cache[i].vaddr)
                        return FALSE;

                if ((vaddr >= tc->cache[i].vaddr) &&
		    (vaddr < (tc->cache[i].vaddr+SIZEOF_32BIT))) {
                        valtmp = tc->cache[i].value;
			shift = (vaddr - tc->cache[i].vaddr) * 8;
			valtmp >>= shift;
			*valptr = valtmp & 0xff;
                        tc->hits++;
                        return TRUE;
                }
        }
        return FALSE;
}

void
dump_text_value_cache(int verbose)
{
	int i;
	struct syment *sp;
	ulong offset;
	struct text_cache *tc;

	tc = &text_cache;

	if (!verbose) {
		if (!tc->refs || !tc->cache) 
			return;

		fprintf(stderr, "     text hit rate: %2ld%% (%ld of %ld)\n",
			(tc->hits * 100)/tc->refs, 
			(ulong)tc->hits, (ulong)tc->refs);
		return;
	}
		
	for (i = 0; tc->cache && (i < tc->entries); i++) {
		if (!tc->cache[i].vaddr)
			break;
		fprintf(fp, "[%2d]: %lx %08x ", i, tc->cache[i].vaddr,
			tc->cache[i].value);
		if ((sp = value_search(tc->cache[i].vaddr, &offset))) {
			fprintf(fp, "(%s+", sp->name);
			switch (pc->output_radix)
			{
			case 10:
				fprintf(fp, "%ld)", offset);
				break;
			case 16:
				fprintf(fp, "%lx)", offset);
				break;
			}
		}
		fprintf(fp, "\n");
	}

	fprintf(fp, 
	    "text_cache entries: %d index: %d hit rate: %ld%% (%ld of %ld)\n", 
		tc->entries, tc->index, 
		(tc->hits * 100)/(tc->refs ? tc->refs : 1),
		tc->hits, tc->refs);

}

void
clear_text_value_cache(void)
{
        int i;
        struct text_cache *tc;

        tc = &text_cache;
	tc->index = 0;

        for (i = 0; tc->cache && (i < tc->entries); i++) {
                tc->cache[i].vaddr = 0;
                tc->cache[i].value = 0;
	}
}

/*
 *  If a System.map file or a debug kernel was specified, the name hash
 *  has been filled -- so sync up gdb's notion of symbol values with
 *  the local values, taking dups into account.  Given that gdb's 
 *  minimal_symbol dump is sorted by value, shortcut the get_syment_array()
 *  call if the sp after the last one found is associated with the
 *  new one.
 */

#define allocated pad1
#define last_sp addr2

int 
patch_kernel_symbol(struct gnu_request *req)
{
	int i, c;
	struct syment *sp_array[200], *sp;

	if (req->name == PATCH_KERNEL_SYMBOLS_START) {
                fprintf(fp, (pc->flags & SILENT) || !(pc->flags & TTY) ? "" :
                 "\nplease wait... (patching %ld gdb minimal_symbol values) ",
			st->symcnt);
		fflush(fp);
		req->count = 0;
		req->length = 0;
		req->last_sp = 0;
		return TRUE;
	}

        if (req->name == PATCH_KERNEL_SYMBOLS_STOP) {
                fprintf(fp, (pc->flags & SILENT) || !(pc->flags & TTY) ? "" :
 "\r                                                                       \r");
		st->flags |= GDB_SYMS_PATCHED;
                return TRUE;
        }

	if (!req->name || !req->addr)
		return FALSE;

	sp = (struct syment *)req->last_sp; 
	sp += sp ? 1 : 0;
	if (sp && (sp->cnt == 1) && !(sp->allocated) && 
	    STREQ(sp->name, req->name)) {
                *((ulong *)req->addr) = sp->value;
                sp->allocated = TRUE;
                req->last_sp = (ulong)sp;
	} else {
		switch (c = get_syment_array(req->name, sp_array, 200))
		{
		case 0: req->last_sp = 0;
			return TRUE;
	
		case 1: 
			*((ulong *)req->addr) = sp_array[0]->value;
			sp_array[0]->allocated = TRUE;
			req->last_sp = (ulong)sp_array[0];
			break;
	
		default:
			for (i = 0; i < c; i++) {
				if (sp_array[i]->allocated)
					continue;
				*((ulong *)req->addr) = sp_array[i]->value;
				sp_array[i]->allocated = TRUE;
				req->last_sp = (ulong)sp_array[i];
				break;
			}
			break;
		}
	}

	return TRUE;
}

#undef allocated
#undef last_sp

/*
 *  If the first offset/size is bogus, then use the second if it's OK.
 *  But if both are bogus, then check whether we're debugging datatypes,
 *  and act accordingly.
 */
long
OFFSET_option(long offset1, long offset2, char *func, char *file, int line,
	      char *item1, char *item2)
{
	char errmsg[BUFSIZE];

	if (offset1 >= 0)
		return offset1;
	if (offset2 >= 0)
		return offset2;

	if (pc->flags & DATADEBUG) {
        	ulong retaddr[4] = { 0 };
		save_return_address(retaddr);
		sprintf(errmsg, 	
		    "invalid (optional) structure member offsets: %s or %s",
			item1, item2);
		datatype_error(retaddr, errmsg, func, file, line);
	}

	return -1;
}

long
SIZE_option(long size1, long size2, char *func, char *file, int line,
	    char *item1, char *item2)
{
	char errmsg[BUFSIZE];

        if (size1 >= 0)
                return size1;
        if (size2 >= 0)
                return size2;

        if (pc->flags & DATADEBUG) {
        	ulong retaddr[4] = { 0 };
		save_return_address(retaddr);
		sprintf(errmsg, "invalid (optional) structure sizes: %s or %s",
			item1, item2);
                datatype_error(retaddr, errmsg, func, file, line);
        }

        return -1;
}

/*
 *  Do the work of the former OFFSET() and SIZE() macros.  
 *
 *  For now verification that the offset is legitimate is only done
 *  if the "--data_debug" command line option was used.  There
 *  could still be constructs like "OFFSET(x) >= 0" in the current
 *  code, or in user extensions.  Perhaps there should be an option
 *  to turn it off instead?
 */
long
OFFSET_verify(long offset, char *func, char *file, int line, char *item)
{
	char errmsg[BUFSIZE];

	if (!(pc->flags & DATADEBUG))
		return offset;

	if (offset < 0) {
        	ulong retaddr[4] = { 0 };
		save_return_address(retaddr);
		sprintf(errmsg, "invalid structure member offset: %s",
			item);
		datatype_error(retaddr, errmsg, func, file, line);
	}
	return offset;
}

long
SIZE_verify(long size, char *func, char *file, int line, char *item)
{
	char errmsg[BUFSIZE];

        if (!(pc->flags & DATADEBUG))
                return size;

        if (size < 0) {
        	ulong retaddr[4] = { 0 };
		save_return_address(retaddr);
		sprintf(errmsg, "invalid structure size: %s", item);
                datatype_error(retaddr, errmsg, func, file, line);
        }
        return size;
}

/*
 *  Perform the common datatype error handling.
 */
static void
datatype_error(ulong *retaddr, char *errmsg, char *func, char *file, int line)
{
	char buf[BUFSIZE];
	int fd;

        fprintf(stderr, "\n%s: %s\n", pc->curcmd, errmsg);
        fprintf(stderr, "%s  FILE: %s  LINE: %d  FUNCTION: %s()\n\n", 
		space(strlen(pc->curcmd)), file, line, func);
	fflush(stderr);

        dump_trace(retaddr);

        if (pc->flags & TTY) {
                if ((fd = open("/dev/tty", O_RDONLY)) >= 0) {
                	tcsetattr(fd, TCSANOW, &pc->termios_orig);
                	close(fd);
		}
        }

        if (pc->flags & DROP_CORE)
        	drop_core("DROP_CORE flag set: forcing a segmentation fault\n");
	
	gdb_readnow_warning();

	if (pc->flags & RUNTIME) {
		sprintf(buf, "%s\n%s  FILE: %s  LINE: %d  FUNCTION: %s()\n",
			errmsg, space(strlen(pc->curcmd)), file, line, func);
		error(FATAL, "%s\n", buf);
	}

        exit(1);
}


/*
 *  Dump a trace leading to the improper datatype usage.
 */
void
dump_trace(ulong *retaddr)
{
	int i, c;
	char *thisfile;
	char *arglist[MAXARGS];
	char buf[BUFSIZE];
	FILE *pipe;
	ulong vaddr, lookfor;
	ulong last_vaddr;
	char symbol[BUFSIZE];

	fflush(fp);
	fflush(stdout);
	fflush(pc->stdpipe);

	thisfile = get_thisfile();

	fprintf(stderr, "[%s] error trace: ", thisfile);
        for (i = 3; i >= 0; i--) {
                if (retaddr[i])
                        fprintf(stderr, "%s%lx%s",
                                i == 3 ? "" : "=> ",
                                retaddr[i],
                                i == 0 ? "\n" : " ");
        }
	fflush(stderr);

	if (!file_exists("/usr/bin/nm", NULL)) {
		fprintf(stderr, "crash: /usr/bin/nm: no such file\n");
		return;
	}

        for (i = 0; i < 4; i++) {
		if (!(lookfor = retaddr[i]))
			continue;

		sprintf(buf, "/usr/bin/nm -Bn %s", thisfile);
	        if (!(pipe = popen(buf, "r"))) {
			perror("pipe");
			break;
		}

		last_vaddr = 0;
		BZERO(symbol, BUFSIZE);

	        while (fgets(buf, 80, pipe)) {
			c = parse_line(strip_linefeeds(buf), arglist);
			if (c != 3)
				continue;
			vaddr = htol(arglist[0], FAULT_ON_ERROR, NULL);
			if (vaddr > lookfor) {
				fprintf(stderr, "%s  %lx: %s+%ld\n",
					i == 0 ? "\n" : "", 
					lookfor, symbol, 
					lookfor-last_vaddr);
				break;
			}
			strcpy(symbol, arglist[2]);
			last_vaddr = vaddr;
		}

		pclose(pipe);
	}

	fprintf(stderr, "\n");
}

/*
 *  Try best to determine which executable this is.
 */
static char *
get_thisfile(void)
{
	char *buf1;
	char buf2[BUFSIZE];
	char *tok, *path;

	if (pc->program_path[0] == '.' ||
	    pc->program_path[0] == '/')
		return pc->program_path;

        if ((path = getenv("PATH"))) {
		strcpy(buf2, path);
	} else
		return pc->program_path;

	buf1 = GETBUF(BUFSIZE);
	tok = strtok(buf2, ":");
	while (tok) {
		sprintf(buf1, "%s/%s", tok, pc->program_name);
		if (file_exists(buf1, NULL) && is_elf_file(buf1)) {
			return buf1;
		}
		tok = strtok(NULL, ":");
	}

	return pc->program_path;
}
