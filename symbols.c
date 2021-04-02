/* symbols.c - core analysis suite
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
 * BitKeeper ID: @(#)symbols.c 1.27
 *
 * 09/28/00  ---    Transition to CVS version control
 *
 * CVS: $Revision: 1.85 $ $Date: 2002/02/18 13:48:25 $
 */

#include "defs.h"
#include <elf.h>
#include "bfd.h"

static void store_symbols(bfd *, int, void *, long, unsigned int);
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
struct load_module;
static int add_symbol_file(struct load_module *lm);
static void find_mod_etext(struct load_module *); 
static long rodata_search(ulong *, ulong);
static int ascii_long(ulong word);
static int is_bfd_format(char *); 
static int namespace_ctl(int, struct namespace *, void *, void *);
static void symval_hash_init(void);
static struct syment *symval_hash_search(ulong);
static void symname_hash_install(struct syment *);
static struct syment *symname_hash_search(char *);
static void gnu_qsort(bfd *, void *, long, unsigned int, asymbol *, asymbol *);


#define KERNEL_SECTIONS  (void *)(1)
#define MODULE_SECTIONS  (void *)(2) 

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
static void whatis_datatype(char *, off_t *, ulong);
static void whatis_variable(struct syment *);
static void print_struct(char *, ulong);
static void print_union(char *, ulong);
static void dump_datatype_member(FILE *, struct datatype_member *);
static void dump_datatype_flags(ulong, FILE *);
static void dump_enumerator_list(char *);
static int gdb_whatis(char *);
static void do_datatype_declaration(struct datatype_member *, ulong);


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

        if (!(bfd_get_file_flags(st->bfd) & HAS_SYMS)) 
		no_debugging_data();

	symcount = bfd_read_minisymbols(st->bfd, FALSE, &minisyms, &size);
	if (symcount <= 0)
		no_debugging_data();

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

	symval_hash_init();
}

/*
 *  Common bailout routine used here and from gdb_session_init().
 */
void
no_debugging_data(void)
{
	error(FATAL, "%s: no debugging data available\n", pc->namelist);
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

	section = get_kernel_section(".text.init");
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
		if (machdep->verify_symbol(syminfo.name, syminfo.value)) {
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
 *  Install a static kernel symbol into the symname_hash upon its first use.
 */
static void
symname_hash_install(struct syment *sp)
{
        int index;
	struct symname_hash_entry *she, *shep;

        if (!(she = (struct symname_hash_entry *)
            malloc(sizeof(struct symname_hash_entry))))
            	return;

	she->sp = sp;
	she->next = NULL;

	index = SYMNAME_HASH_INDEX(sp->name);

        if (st->symname_hash[index] == NULL) {
               st->symname_hash[index] = she;
               return;
        } else {
       		shep = st->symname_hash[index];

       		while (shep->next)
                	shep = shep->next;

       		shep->next = she;
	}
}


/*
 *  Static kernel symbol value search
 */
static struct syment *
symname_hash_search(char *name)
{
	int index;
	struct symname_hash_entry *she;

	index = SYMNAME_HASH_INDEX(name);

        if ((she = st->symname_hash[index]) == NULL) 
		return NULL;

	while (she) {
		if (STREQ(name, she->sp->name)) 
			return she->sp;
		she = she->next;
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
        for (i = 0; i < st->bfd->section_count; i++, sec++)
		if (STREQ(name, (*sec)->name))
			return(*sec);

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
store_module_symbols(ulong total, int mods_installed)
{
        int i, m;
        ulong mod, mod_next, mod_name;
        uint nsyms;
        ulong syms, size_of_struct;
	long strbuflen, size;
	int mcnt;
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
		lm->mod_base = mod;
		lm->mod_size = size;
		lm->mod_size_of_struct = size_of_struct;
        	if (strlen(name) < MAX_MOD_NAME)
                	strcpy(lm->mod_name, name);
        	else {
			error(INFO, 
			    "module name greater than MAX_MOD_NAME: %s\n",
				lm->mod_name);
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

				mcnt++;
			}
		}
	
		if (modsymbuf) {
			FREEBUF(modsymbuf);
			modsymbuf = NULL;
		}

		if (strbuf)
			FREEBUF(strbuf);

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

		mod_next = ULONG(modbuf + OFFSET(module_next));
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

	if (SMP() && STRNEQ(p1, "_Rsmp_")) { 
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
	off_t offset;
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

        sec = (asection **)st->sections;
        for (i = 0; i < st->bfd->section_count; i++, sec++) {
		section = *sec;
                if (section->flags & SEC_CODE) {
			start = (ulong)bfd_get_section_vma(st->bfd, section);
			end = start + (ulong)bfd_section_size(st->bfd, section);

        		if ((value >= start) && (value < end)) 
                		return TRUE;
		}
	}

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
			start = lm->mod_base + lm->mod_size_of_struct;
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
is_kernel_text_offset(ulong value, ulong *return_offset)
{
	struct syment *sp;
	off_t offset;

	if (!is_kernel_text(value))
		return FALSE;

	if (!(sp = value_search(value, &offset)))
		return FALSE;

	if (return_offset)
		*return_offset = offset;

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
is_rodata(ulong value, ulong *return_offset, struct syment **spp)
{
        struct syment *sp;
        off_t offset;

        if (!(sp = value_search(value, &offset)))
                return FALSE;

	if ((sp->type == 'r') || (sp->type == 'R')) {
		if (return_offset)
			*return_offset = offset;
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
        if (st->flags & DATATYPE_INIT)
                fprintf(fp, "%sDATATYPE_INIT", others++ ? "|" : "");
        if (st->flags & INSMOD_BUILTIN)
                fprintf(fp, "%sINSMOD_BUILTIN", others++ ? "|" : "");
        fprintf(fp, ")\n");

	fprintf(fp, "                 bfd: %lx\n", (ulong)st->bfd);
	fprintf(fp, "            sections: \n");
	sec = (asection **)st->sections;
	for (i = 0; i < st->bfd->section_count; i++, sec++) {
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

	if (MCLXDEBUG(1)) {
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
		MCLXDEBUG(1) ? "\n" : "", st->val_hash_searches);
        fprintf(fp, " val_hash_iterations: %.0f  (avg: %.1f)\n",
                st->val_hash_iterations,
                st->val_hash_iterations/st->val_hash_searches);

        fprintf(fp, "     symname_hash[%d]: %lx  ", SYMNAME_HASH,
                (ulong)&st->symname_hash[0]);

        for (i = tot = 0; i < SYMNAME_HASH; i++) {
		struct symname_hash_entry *she;

                she = st->symname_hash[i];
                if (!she) {
                        fprintf(fp, "0 ");
                        continue;
                }

                cnt = 1;
                while ((she = she->next)) 
                        cnt++;

                fprintf(fp, "%d ", cnt);

                tot += cnt;
        }
        fprintf(fp, "(%d)\n", tot);


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

		for (s = 0; s < lm->mod_sections; s++) {
			fprintf(fp, 
                "       %12s  prio: %x  flags: %05x  offset: %-8lx size: %lx\n",
				lm->mod_section_data[s].name,
				lm->mod_section_data[s].priority,
				lm->mod_section_data[s].flags,
				lm->mod_section_data[s].offset,
				lm->mod_section_data[s].size);
		}

		if (MCLXDEBUG(1)) {
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
 *  Check whether a file is a known BFD format.
 */
static int
is_bfd_format(char *filename) 
{
        struct _bfd *bfd;
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
	off_t offset;
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
show_symbol(struct syment *sp, off_t offset, ulong show_flags)
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
 *  text address.
 */
char *
get_line_number(ulong addr, char *buf, int strip_usr_src)
{
	char *p;
	struct gnu_request request, *req;

	buf[0] = NULLCHAR;
	if (!is_kernel_text(addr))
		return(buf);

	req = &request;
	BZERO(req, sizeof(struct gnu_request));
	req->command = GNU_GET_LINE_NUMBER;
	req->addr = addr;
	req->buf = buf;

	gdb_interface(req);

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

	get_line_number(symbol_value("schedule"), buf, FALSE);
	if ((p = strstr(buf, "/kernel")))
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
                if (strcmp(s, sp->name) == 0) {
        		if (!(IS_VMALLOC_ADDR(sp->value)) && !sp_hashed) 
				symname_hash_install(sp);
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
                if (STREQ(s, sp->name)) 
			count++;
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
 *  the offset from the symbol value.
 */
struct syment *
value_search(ulong value, off_t *offset)
{
	int i;
        struct syment *sp, *sp_end;
	struct load_module *lm;

        if (!in_ksymbol_range(value))
                return((struct syment *)NULL);

	if (IS_VMALLOC_ADDR(value)) 
		goto check_modules;

	if ((sp = symval_hash_search(value)) == NULL)
		sp = st->symtable;
 
        for ( ; sp < st->symend; sp++) {
                if (value == sp->value) {
                        *offset = 0;
                        return((struct syment *)sp);
                }
                if (sp->value > value) {
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

                for ( ; sp < sp_end; sp++) {
                	if (value == sp->value) {
                        	*offset = 0;
                        	return((struct syment *)sp);
                	}

                	if (sp->value > value) {
                        	sp--;
                        	*offset = value - sp->value;
                        	return(sp);
                	}
                }
        }

        return((struct syment *)NULL);
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
        off_t offset;
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
        off_t offset;

        if ((sp = value_search(value, &offset))) 
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
        off_t offset;

        if ((sp = value_search(value, &offset)))
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
	                else if (found)
				return sp;
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
                        	else if (found)
                                	return sp;
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
	off_t offset;

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

        for (sp = st->symtable; sp < st->symend; sp++) {
                if (STREQ(symbol, sp->name))
                        return(TRUE);
        }

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
 *  Create a temporary datatype file containing all struct, union, and
 *  typedef information.  If the file was specified during initialization,
 *  just use it.  If not, create a temporary file that will disappear when 
 *  the program exits, and use the BFD interface to populate it.  Lastly,
 *  verify that no lines in the datatype file exceed BUFSIZE, and that
 *  the primitive data type sizes make sense.
 */
void
datatype_init(void)
{
	int max, pages;

	max = BUFSIZE;
	pages = 2;
	BNEG(&offset_table, sizeof(offset_table));
	BNEG(&size_table, sizeof(size_table));

	pc->sym_maxline = MAX(max+80, BUFSIZE+80);
	sym_buf_init();

	st->flags |= DATATYPE_INIT;
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
 *
 *  to determine structure or union sizes, or member offsets.
 */
long
datatype_info(char *name, char *member, struct datatype_member *dm)
{
	struct gnu_request *req;
        long offset, size;
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

	if (MCLXDEBUG(2)) {
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
		offset = req->member_offset >= 0 ? 
			req->member_offset/BITS_PER_BYTE : -1;
		break;

	case TYPE_CODE_UNION:
		type_found = UNION_REQUEST;
		size = req->length;
                offset = req->member_offset >= 0 ? 
                        req->member_offset/BITS_PER_BYTE : -1;
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

        if (dm) {
                dm->type = type_found;
                dm->size = size;
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

        if (member) 
		return offset;
	else
                return size;
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
	int count;
        struct datatype_member struct_member, *sm;

        sm = &struct_member;
	count = 1;
	rawdata = 0;
	aflag = 0;
	flags = STRUCT_REQUEST;

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
		if (IS_A_NUMBER(args[optind])) { 
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

	for (c =  0; c < count; c++, addr += len) {
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
		if (IS_A_NUMBER(args[optind])) { 
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

        for (c =  0; c < count; c++, addr += len) {
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
 * displayed to that particular member.  Structure data is shown in hexadecimal  * format.  The raw data in a union may be dumped with the -r flag.
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

        um = &union_member;
	count = 1;
	rawdata = 0;
	aflag = 0;
	flags = UNION_REQUEST;

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
		if (IS_A_NUMBER(args[optind])) { 
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

	for (c = 0; c < count; c++, addr += len) {
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

	if (MCLXDEBUG(1))
		dump_datatype_member(fp, dm);

        open_tmpfile();
        whatis_datatype(dm->name, NULL, flags);
        rewind(pc->tmpfile);

	if (dm->member)
		flags |= SHOW_OFFSET;

	sfp = pc->saved_fp;
	len = dm->size;
	multiline = NULL;
        while (fgets(buf, pc->sym_maxline, pc->tmpfile)) {
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
        char *buf;
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

	buf = GETBUF(pc->sym_maxline);

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

			FREEBUF(buf);
			return;
		}

		do_datatype_declaration(dm, flags | (dm->flags & TYPEDEF));
	} else {
		if (!gdb_whatis(concat_args(buf, 1, FALSE))) 
			goto whatis_failure;
	} 

	FREEBUF(buf);
	return;

whatis_failure:

        error(INFO, "cannot resolve: %s\n", concat_args(buf, 1, FALSE));
	FREEBUF(buf);
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
                while (fgets(buf1, pc->sym_maxline, pc->tmpfile)) {
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
whatis_datatype(char *st, long *offset, ulong flags)
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
	char *buf;
	char lookfor1[BUFSIZE];
	char lookfor2[BUFSIZE];
	char lookfor3[BUFSIZE];
	char lookfor4[BUFSIZE];
	char lookfor5[BUFSIZE];
	long curpos, last_open_bracket;
	int indent, on, array;

	s = dm->member;
	indent = 0;
	on = array = FALSE;
	buf = GETBUF(pc->sym_maxline);
	rewind(pc->tmpfile);

	switch (flag)  
	{
	case PARSE_FOR_DATA:
		sprintf(lookfor1, "  %s ", s);
		sprintf(lookfor2, "  %s[", s);
next_item:
		while (fgets(buf, pc->sym_maxline, pc->tmpfile)) {
			if (STRNEQ(buf, lookfor1) || STRNEQ(buf, lookfor2)) {
				on = TRUE;
				if (strstr(buf, "= {")) 
					indent = count_leading_spaces(buf);
				if (strstr(buf, "["))
					array = TRUE;
			}
	
			if (on) {
				fprintf(pc->saved_fp, buf);
				if (!indent)
					break;
				if (strstr(buf, "}") && 
				    (count_leading_spaces(buf) == indent))
					break;
			}
		}
		if (array) {
			on = array = FALSE;
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

                while (fgets(buf, pc->sym_maxline, pc->tmpfile)) {
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

	FREEBUF(buf);
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
 *   Get the size of a "known" array.
 */

int
get_array_length(char *s, int *two_dim)
{
	char copy[BUFSIZE];
	char buf[BUFSIZE];
	char lookfor1[BUFSIZE];
	char lookfor2[BUFSIZE];
	int retval;
        struct datatype_member datatype_member, *dm;
	char *p1, *p2;
	
	strcpy(copy, s);
       	dm = &datatype_member;
	BZERO(dm, sizeof(struct datatype_member));

	if (symbol_search(s))
		sprintf(buf, "whatis %s", s);
	else { 
        	if (arg_to_datatype(copy, dm, RETURN_ON_ERROR)) {
			if (!dm->member)
				return 0;

			switch (dm->type)
			{
			case UNION_REQUEST:
				sprintf(buf, "ptype union %s", dm->name);
				break;
			case STRUCT_REQUEST:
				sprintf(buf, "ptype struct %s", dm->name);
				break;
			default:
				return retval;
			}
        		sprintf(lookfor1, " %s[", dm->member);
        		sprintf(lookfor2, "*%s[", dm->member);
		} else
			return 0;
	}

        open_tmpfile2();
	retval = 0;
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

	return retval;
}

/*
 *  Get the sizeof an expression from gdb.
 */
ulong
sizeof_variable(char *s)
{
        char buf[BUFSIZE];
	ulong result;
	int found;

	found = FALSE;
        open_tmpfile2();
        sprintf(buf, "output/x sizeof(%s)", s);
        if (!gdb_pass_through(buf, pc->tmpfile2, GNU_RETURN_ON_ERROR)) {
		close_tmpfile2();
		error(FATAL, "cannot determine sizeof(%s)\n", s);
	}

        rewind(pc->tmpfile2);
        if (fgets(buf, BUFSIZE, pc->tmpfile2)) {
		clean_line(buf);
		if (extract_hex(buf, &result, NULLCHAR, FALSE)) 
			found = TRUE;
        }
        close_tmpfile2();

	if (!found)
		error(FATAL, "cannot determine sizeof(%s)\n", s);

	return result;
}

/*
 *  "help -o" output  
 */
void
dump_offset_table(char *spec)
{
	char buf[BUFSIZE];

	if (spec) 
		open_tmpfile();

	fprintf(fp, "                  offset_table:\n");
	fprintf(fp, "                list_head_next: %ld\n", 
		OFFSET(list_head_next));
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

	fprintf(fp, "           signal_struct_count: %ld\n",
        	OFFSET(signal_struct_count));
	fprintf(fp, "          signal_struct_action: %ld\n",
        	OFFSET(signal_struct_action));
        fprintf(fp, "        task_struct_start_time: %ld\n",
                OFFSET(task_struct_start_time));
        fprintf(fp, "             task_struct_times: %ld\n",
                OFFSET(task_struct_times));

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

        fprintf(fp, "             signal_queue_next: %ld\n",
                OFFSET(signal_queue_next));
        fprintf(fp, "             signal_queue_info: %ld\n",
                OFFSET(signal_queue_info));

        fprintf(fp, "                 sigqueue_next: %ld\n",
                OFFSET(sigqueue_next));
        fprintf(fp, "                 sigqueue_info: %ld\n",
                OFFSET(sigqueue_info));

        fprintf(fp, "              siginfo_si_signo: %ld\n",
                OFFSET(siginfo_si_signo));

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
	fprintf(fp, "            mm_struct_total_vm: %ld\n", 
		OFFSET(mm_struct_total_vm));
	fprintf(fp, "          mm_struct_start_code: %ld\n", 
		OFFSET(mm_struct_start_code));

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

	fprintf(fp, "                     page_next: %ld\n", OFFSET(page_next));
	fprintf(fp, "                     page_prev: %ld\n", OFFSET(page_prev));
	fprintf(fp, "                page_next_hash: %ld\n", 
		OFFSET(page_next_hash));
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

        fprintf(fp, "                     socket_sk: %ld\n", OFFSET(socket_sk));
        fprintf(fp, "                    sock_daddr: %ld\n", 
		OFFSET(sock_daddr));
        fprintf(fp, "                sock_rcv_saddr: %ld\n", 
		OFFSET(sock_rcv_saddr));
        fprintf(fp, "                    sock_dport: %ld\n", 
		OFFSET(sock_dport));
        fprintf(fp, "                      sock_num: %ld\n", OFFSET(sock_num));
        fprintf(fp, "                   sock_family: %ld\n", 
		OFFSET(sock_family));
        fprintf(fp, "                     sock_type: %ld\n", OFFSET(sock_type));


        fprintf(fp, "               timer_list_list: %ld\n",
                OFFSET(timer_list_list));
        fprintf(fp, "               timer_list_next: %ld\n", 
		OFFSET(timer_list_next));
        fprintf(fp, "            timer_list_expires: %ld\n", 
		OFFSET(timer_list_expires));
        fprintf(fp, "           timer_list_function: %ld\n", 
		OFFSET(timer_list_function));
        fprintf(fp, "            timer_vec_root_vec: %ld\n", 
		OFFSET(timer_vec_root_vec));
        fprintf(fp, "                 timer_vec_vec: %ld\n", 
		OFFSET(timer_vec_vec));
 
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


	fprintf(fp, "\n                    size_table:\n");
	fprintf(fp, "                          page: %ld\n", SIZE(page));
        fprintf(fp, "              free_area_struct: %ld\n", 
		SIZE(free_area_struct));
        fprintf(fp, "                   zone_struct: %ld\n", SIZE(zone_struct));
        fprintf(fp, "                   kmem_slab_s: %ld\n", SIZE(kmem_slab_s));
        fprintf(fp, "                        slab_s: %ld\n", SIZE(slab_s));
        fprintf(fp, "                  kmem_cache_s: %ld\n", 
		SIZE(kmem_cache_s));
        fprintf(fp, "                    cpucache_s: %ld\n", SIZE(cpucache_s));
        fprintf(fp, "                 kmem_bufctl_t: %ld\n", 
		SIZE(kmem_bufctl_t));
        fprintf(fp, "              swap_info_struct: %ld\n", 
		SIZE(swap_info_struct));
        fprintf(fp, "                vm_area_struct: %ld\n", 
		SIZE(vm_area_struct));
        fprintf(fp, "                     mm_struct: %ld\n", SIZE(mm_struct));
        fprintf(fp, "                       pt_regs: %ld\n", SIZE(pt_regs));
        fprintf(fp, "                   task_struct: %ld\n", SIZE(task_struct));
        fprintf(fp, "                 softirq_state: %ld\n", 
		SIZE(softirq_state));
        fprintf(fp, "                   desc_struct: %ld\n", SIZE(desc_struct));
	fprintf(fp, "                       umode_t: %ld\n", SIZE(umode_t));
	fprintf(fp, "                        dentry: %ld\n", SIZE(dentry));
	fprintf(fp, "                     fs_struct: %ld\n", SIZE(fs_struct));
	fprintf(fp, "                  files_struct: %ld\n", 
		SIZE(files_struct));
	fprintf(fp, "                          file: %ld\n", SIZE(file)); 
	fprintf(fp, "                         inode: %ld\n", SIZE(inode)); 
	fprintf(fp, "                      vfsmount: %ld\n", SIZE(vfsmount)); 
	fprintf(fp, "                   super_block: %ld\n", 
		SIZE(super_block)); 
	fprintf(fp, "                       irqdesc: %ld\n", SIZE(irqdesc));
	fprintf(fp, "                        module: %ld\n", SIZE(module));
	fprintf(fp, "                     list_head: %ld\n", SIZE(list_head));
	fprintf(fp, "                 irq_cpustat_t: %ld\n", 
		SIZE(irq_cpustat_t));
	fprintf(fp, "                   cpuinfo_x86: %ld\n", SIZE(cpuinfo_x86));
	fprintf(fp, "                  cpuinfo_ia64: %ld\n", 
		SIZE(cpuinfo_ia64));
	fprintf(fp, "                    timer_list: %ld\n", SIZE(timer_list));
	fprintf(fp, "                timer_vec_root: %ld\n", 
		SIZE(timer_vec_root));
	fprintf(fp, "                     timer_vec: %ld\n", SIZE(timer_vec));
	fprintf(fp, "                          sock: %ld\n", SIZE(sock));
	fprintf(fp, "                 signal_struct: %ld\n", 
		SIZE(signal_struct));
	fprintf(fp, "                  signal_queue: %ld\n", 
		SIZE(signal_queue));
	fprintf(fp, "                      sigqueue: %ld\n", SIZE(sigqueue));
	fprintf(fp, "                   k_sigaction: %ld\n", 
		SIZE(k_sigaction));
	fprintf(fp, "              resource_entry_t: %ld\n", 
		SIZE(resource_entry_t));
	fprintf(fp, "                      resource: %ld\n", SIZE(resource));

	if (spec) {
		int in_size_table, offsets, sizes;

		in_size_table = offsets = sizes = 0;

        	rewind(pc->tmpfile);
        	while (fgets(buf, BUFSIZE, pc->tmpfile)) {
			if (strstr(buf, "size_table:"))
				in_size_table = TRUE;

			if (strstr(buf, spec)) {
				if (in_size_table) {
					if (!sizes)
						fprintf(pc->saved_fp,
                                          "%s                    size_table:\n",
							offsets ? "\n" : "");
					sizes++;
			        } else {
					if (!offsets)
        					fprintf(pc->saved_fp, 
				           "                  offset_table:\n");
					offsets++;
				}

				if (strstr(buf, " size_table:") ||
				    strstr(buf, " offset_table:"))
					break;
		
				fprintf(pc->saved_fp, buf);
			}
		}
		close_tmpfile();
	}
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
	case KERNEL_SECTIONS:
        	sec = (asection **)st->sections;
        	for (i = 0; (i < st->bfd->section_count) && *sec; i++)
			sec++;
		*sec = section;

        	if (STREQ(bfd_get_section_name(bfd, section), ".text.init")) {
                	kt->stext_init = (ulong)
				bfd_get_section_vma(bfd, section);
                	kt->etext_init = kt->stext_init +
                        	(ulong)bfd_section_size(bfd, section);
		}
		break;

	case MODULE_SECTIONS:
		lm = st->current;
		store_section_data(lm, bfd, section);
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

        offset = lm->mod_size_of_struct;

        qsort(&lm->mod_section_data[0], lm->mod_sections, 
		sizeof(struct mod_section_data), compare_prios);

	for (i = (lm->mod_sections-1); i >= 0; i--) {
		section = lm->mod_section_data[i].section;

               	alignment = power(2, bfd_get_section_alignment(bfd, section));

                if (alignment && (offset & (alignment - 1)))
                	offset = (offset | (alignment - 1)) + 1;

		lm->mod_section_data[i].offset = offset;

                if (MCLXDEBUG(1))
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
		if (MCLXDEBUG(1))
			fprintf(fp, "check_insmod_builtin: %lx %s\n",
				sp->value, sp->name);
		offs = sp->value - lm->mod_base;
		if (offs != *offset) {
			if (MCLXDEBUG(1))
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

	if (lm->mod_flags & MOD_LOAD_SYMS) {
		if (MCLXDEBUG(1))
			fprintf(fp, "%s: module symbols are already loaded\n", 
				modref);
		return TRUE;
	}

	if (MCLXDEBUG(1))
		fprintf(fp, "load_module_symbols: %s %s %lx\n",
			modref, namelist, base_addr);

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

	result = add_symbol_file(st->current);

	if (MCLXDEBUG(1))
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
	if (!MCLXDEBUG(1))
		req->fp = pc->nullfp;

	gdb_interface(req); 

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
                       if (MCLXDEBUG(2))
                            fprintf(fp, "%08lx (%c) [%s] %s\n",  syminfo.value,
                                syminfo.type, secname, syminfo.name);

                        syminfo.value += lm->mod_bss_start;
                        strcpy(name, syminfo.name);
                        strip_module_symbol_end(name);

                        if (machdep->verify_symbol(name, syminfo.value)) {
                                sp->value = syminfo.value;
				sp->type = syminfo.type;
				
                                namespace_ctl(NAMESPACE_INSTALL,
                                        &lm->mod_load_namespace, sp, name); 

                                if (MCLXDEBUG(1))
                                    fprintf(fp, "%08lx %s\n",  sp->value,
                                        name);

                                sp++;
                                lm->mod_load_symcnt++;
                        }
			break;

		case 'd': 
		case 'D':
                        if (MCLXDEBUG(2))
                            fprintf(fp, "%08lx (%c) [%s] %s\n",  syminfo.value,
                                syminfo.type, secname, syminfo.name);

			if (STREQ(secname, ".rodata"))
                        	syminfo.value += lm->mod_rodata_start;
			else
                        	syminfo.value += lm->mod_data_start;

                        strcpy(name, syminfo.name);
                        strip_module_symbol_end(name);

                        if (machdep->verify_symbol(name, syminfo.value)) {
                                sp->value = syminfo.value;
				sp->type = syminfo.type;
                                namespace_ctl(NAMESPACE_INSTALL,
                                        &lm->mod_load_namespace, sp, name); 

                                if (MCLXDEBUG(1))
                                    fprintf(fp, "%08lx %s\n",  sp->value,
                                        name);

                                sp++;
                                lm->mod_load_symcnt++;
                        }
			break;

		case 't':
		case 'T':
			if (MCLXDEBUG(2))
			    fprintf(fp, "%08lx (%c) [%s] %s\n",  syminfo.value, 
				syminfo.type, secname, syminfo.name); 

			syminfo.value += lm->mod_text_start;
			strcpy(name, syminfo.name);
			strip_module_symbol_end(name);

                	if (machdep->verify_symbol(name, syminfo.value)) {
                        	sp->value = syminfo.value;
				sp->type = syminfo.type;
                                namespace_ctl(NAMESPACE_INSTALL,
                                        &lm->mod_load_namespace, sp, name);

                                if (MCLXDEBUG(1))
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
				if (spx->value == sp->value) {
					found = TRUE;
					if (MCLXDEBUG(1))
						fprintf(fp, 
						    "%s: %s matches!\n",
							lm->mod_name,
							nameptr);
				} else {
					error(INFO, 
				     "[%s] %s: %lx != extern'd value: %lx\n",
						lm->mod_name,
						nameptr, sp->value,
						spx->value);
				}
				break;
			}
	    	}
		if (!found) {
			if (MCLXDEBUG(1))
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

        qsort(lm->mod_load_symtable, lm->mod_load_symcnt, sizeof(struct syment),
                compare_syms);

        namespace_ctl(NAMESPACE_COMPLETE, &lm->mod_load_namespace, 
		lm->mod_load_symtable, lm->mod_load_symend);

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

	if (!base_addr) {
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
	off_t offset;
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
