# Makefile for core analysis suite
#
# Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
#       www.missioncriticallinux.com, info@missioncriticallinux.com
#
# Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011 David Anderson
# Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011 Red Hat, Inc. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#

PROGRAM=crash

#
# Supported targets: X86 ALPHA PPC IA64 PPC64
# TARGET and GDB_CONF_FLAGS will be configured automatically by configure
#
TARGET=
GDB_CONF_FLAGS=

ARCH := $(shell uname -m | sed -e s/i.86/i386/ -e s/sun4u/sparc64/ -e s/arm.*/arm/ -e s/sa110/arm/)
ifeq ($(ARCH), ppc64)
CONF_FLAGS = -m64
endif

#
# GDB, GDB_FILES, GDB_OFILES and GDB_PATCH_FILES will be configured automatically by configure 
#
GDB=gdb-7.0
GDB_FILES=${GDB_7.0_FILES}
GDB_OFILES=
GDB_PATCH_FILES=gdb-7.0.patch

#
# Default installation directory
#
INSTALLDIR=${DESTDIR}/usr/bin

#
# The executable is dynamically linked by default.  To build a statically 
# linked version for X86, ALPHA or PPC, perform either of the following options:
#
# (1) Invoke make like so:  make LDFLAGS=-static
# (2) Or uncomment the "LDFLAGS=-static" definition below:

#LDFLAGS=-static

# For IA64, perform either of the following options:
#
# (1) Uncomment "LDFLAGS=-static" above and then invoke make like so:
#    make NAT_CLIBS="-lc -lresolv" GDBSERVER_LIBS="-lc -lresolv"
# (2) Or invoke make like so:
#    make LDFLAGS=-static NAT_CLIBS="-lc -lresolv" GDBSERVER_LIBS="-lc -lresolv"

GENERIC_HFILES=defs.h xen_hyper_defs.h
MCORE_HFILES=va_server.h vas_crash.h
REDHAT_HFILES=netdump.h diskdump.h makedumpfile.h xendump.h kvmdump.h qemu-load.h
LKCD_DUMP_HFILES=lkcd_vmdump_v1.h lkcd_vmdump_v2_v3.h lkcd_dump_v5.h \
        lkcd_dump_v7.h lkcd_dump_v8.h
LKCD_OBSOLETE_HFILES=lkcd_fix_mem.h
LKCD_TRACE_HFILES=lkcd_x86_trace.h
IBM_HFILES=ibm_common.h
SADUMP_HFILES=sadump.h
UNWIND_HFILES=unwind.h unwind_i.h rse.h unwind_x86.h unwind_x86_64.h

CFILES=main.c tools.c global_data.c memory.c filesys.c help.c task.c \
	kernel.c test.c gdb_interface.c configure.c net.c dev.c \
	alpha.c x86.c ppc.c ia64.c s390.c s390x.c s390dbf.c ppc64.c x86_64.c \
	arm.c \
	extensions.c remote.c va_server.c va_server_v1.c symbols.c cmdline.c \
	lkcd_common.c lkcd_v1.c lkcd_v2_v3.c lkcd_v5.c lkcd_v7.c lkcd_v8.c\
	lkcd_fix_mem.c s390_dump.c lkcd_x86_trace.c \
	netdump.c diskdump.c makedumpfile.c xendump.c unwind.c unwind_decoder.c \
	unwind_x86_32_64.c unwind_arm.c \
	xen_hyper.c xen_hyper_command.c xen_hyper_global_data.c \
	xen_hyper_dump_tables.c kvmdump.c qemu.c qemu-load.c sadump.c

SOURCE_FILES=${CFILES} ${GENERIC_HFILES} ${MCORE_HFILES} \
	${REDHAT_CFILES} ${REDHAT_HFILES} ${UNWIND_HFILES} \
	${LKCD_DUMP_HFILES} ${LKCD_TRACE_HFILES} ${LKCD_OBSOLETE_HFILES}\
	${IBM_HFILES} ${SADUMP_HFILES}

OBJECT_FILES=main.o tools.o global_data.o memory.o filesys.o help.o task.o \
	build_data.o kernel.o test.o gdb_interface.o net.o dev.o \
	alpha.o x86.o ppc.o ia64.o s390.o s390x.o s390dbf.o ppc64.o x86_64.o \
	arm.o \
	extensions.o remote.o va_server.o va_server_v1.o symbols.o cmdline.o \
	lkcd_common.o lkcd_v1.o lkcd_v2_v3.o lkcd_v5.o lkcd_v7.o lkcd_v8.o \
	lkcd_fix_mem.o s390_dump.o netdump.o diskdump.o makedumpfile.o xendump.o \
	lkcd_x86_trace.o unwind_v1.o unwind_v2.o unwind_v3.o \
	unwind_x86_32_64.o unwind_arm.o \
	xen_hyper.o xen_hyper_command.o xen_hyper_global_data.o \
	xen_hyper_dump_tables.o kvmdump.o qemu.o qemu-load.o sadump.o

MEMORY_DRIVER_FILES=memory_driver/Makefile memory_driver/crash.c memory_driver/README

# These are the current set of crash extensions sources.  They are not built
# by default unless the third command line of the "all:" stanza is uncommented.
# Alternatively, they can be built by entering "make extensions" from this
# directory.

EXTENSIONS=extensions
EXTENSION_SOURCE_FILES=${EXTENSIONS}/Makefile ${EXTENSIONS}/echo.c ${EXTENSIONS}/dminfo.c \
	${EXTENSIONS}/snap.c ${EXTENSIONS}/snap.mk \
	${EXTENSIONS}/trace.c \
        ${EXTENSIONS}/libsial/Makefile \
        ${EXTENSIONS}/libsial/mkbaseop.c \
        ${EXTENSIONS}/libsial/README \
        ${EXTENSIONS}/libsial/README.sial \
        ${EXTENSIONS}/libsial/sial_alloc.c \
        ${EXTENSIONS}/libsial/sial_api.c \
        ${EXTENSIONS}/libsial/sial_api.h \
        ${EXTENSIONS}/libsial/sial_builtin.c \
        ${EXTENSIONS}/libsial/sial_case.c \
        ${EXTENSIONS}/libsial/sial_define.c \
        ${EXTENSIONS}/libsial/sial_func.c \
        ${EXTENSIONS}/libsial/sial.h \
        ${EXTENSIONS}/libsial/sial_input.c \
        ${EXTENSIONS}/libsial/sial.l \
        ${EXTENSIONS}/libsial/sial-lsed \
        ${EXTENSIONS}/libsial/sial_member.c \
        ${EXTENSIONS}/libsial/sial_node.c \
        ${EXTENSIONS}/libsial/sial_num.c \
        ${EXTENSIONS}/libsial/sial_op.c \
        ${EXTENSIONS}/libsial/sialpp.l \
        ${EXTENSIONS}/libsial/sialpp-lsed \
        ${EXTENSIONS}/libsial/sialpp.y \
        ${EXTENSIONS}/libsial/sial_print.c \
        ${EXTENSIONS}/libsial/sial_stat.c \
        ${EXTENSIONS}/libsial/sial_str.c \
        ${EXTENSIONS}/libsial/sial_type.c \
        ${EXTENSIONS}/libsial/sial_util.c \
        ${EXTENSIONS}/libsial/sial_var.c \
        ${EXTENSIONS}/libsial/sial.y \
        ${EXTENSIONS}/sial.c \
        ${EXTENSIONS}/sial.mk

DAEMON_OBJECT_FILES=remote_daemon.o va_server.o va_server_v1.o \
	lkcd_common.o lkcd_v1.o lkcd_v2_v3.o lkcd_v5.o lkcd_v7.o lkcd_v8.o \
	s390_dump.o netdump_daemon.o

GDB_5.0_FILES=${GDB}/gdb/Makefile.in \
	  ${GDB}/gdb/main.c ${GDB}/gdb/symtab.c ${GDB}/gdb/target.c \
	  ${GDB}/gdb/blockframe.c ${GDB}/gdb/alpha-tdep.c \
	  ${GDB}/gdb/symfile.c ${GDB}/gdb/elfread.c \
	  ${GDB}/gdb/ui-file.c ${GDB}/gdb/utils.c ${GDB}/gdb/gnu-regex.c \
	  ${GDB}/gdb/ppc-linux-nat.c
GDB_5.0_OFILES=${GDB}/gdb/main.o ${GDB}/gdb/symtab.o ${GDB}/gdb/target.o \
          ${GDB}/gdb/blockframe.o ${GDB}/gdb/alpha-tdep.o \
          ${GDB}/gdb/symfile.o ${GDB}/gdb/elfread.o \
          ${GDB}/gdb/ui-file.o ${GDB}/gdb/utils.o ${GDB}/gdb/gnu-regex.o \
          ${GDB}/gdb/ppc-linux-nat.o

GDB_5.1_FILES=${GDB}/gdb/Makefile.in \
	  ${GDB}/gdb/main.c ${GDB}/gdb/symtab.c ${GDB}/gdb/target.c \
	  ${GDB}/gdb/blockframe.c ${GDB}/gdb/alpha-tdep.c \
	  ${GDB}/gdb/symfile.c ${GDB}/gdb/elfread.c \
	  ${GDB}/gdb/ui-file.c ${GDB}/gdb/utils.c  ${GDB}/gdb/gnu-regex.c
GDB_5.1_OFILES=${GDB}/gdb/main.o ${GDB}/gdb/symtab.o ${GDB}/gdb/target.o \
          ${GDB}/gdb/blockframe.o ${GDB}/gdb/alpha-tdep.o \
          ${GDB}/gdb/symfile.o ${GDB}/gdb/elfread.o \
          ${GDB}/gdb/ui-file.o ${GDB}/gdb/utils.o ${GDB}/gdb/gnu-regex.o

GDB_5.2.1_FILES=${GDB}/gdb/Makefile.in \
          ${GDB}/gdb/main.c ${GDB}/gdb/symtab.c ${GDB}/gdb/target.c \
          ${GDB}/gdb/blockframe.c ${GDB}/gdb/alpha-tdep.c \
          ${GDB}/gdb/symfile.c ${GDB}/gdb/elfread.c \
          ${GDB}/gdb/ui-file.c ${GDB}/gdb/utils.c
GDB_5.2.1_OFILES=${GDB}/gdb/main.o ${GDB}/gdb/symtab.o ${GDB}/gdb/target.o \
          ${GDB}/gdb/blockframe.o ${GDB}/gdb/alpha-tdep.o \
          ${GDB}/gdb/symfile.o ${GDB}/gdb/elfread.o \
          ${GDB}/gdb/ui-file.o ${GDB}/gdb/utils.o 

GDB_5.3post-0.20021129.36rh_FILES=${GDB}/gdb/Makefile.in \
          ${GDB}/gdb/main.c ${GDB}/gdb/symtab.c ${GDB}/gdb/target.c \
          ${GDB}/gdb/frame.c ${GDB}/gdb/alpha-tdep.c \
          ${GDB}/gdb/symfile.c ${GDB}/gdb/elfread.c \
          ${GDB}/gdb/ui-file.c ${GDB}/gdb/utils.c ${GDB}/gdb/dwarf2read.c
GDB_5.3post-0.20021129.36rh_OFILES=${GDB}/gdb/main.o ${GDB}/gdb/symtab.o \
          ${GDB}/gdb/target.o ${GDB}/gdb/frame.o ${GDB}/gdb/alpha-tdep.o \
          ${GDB}/gdb/symfile.o ${GDB}/gdb/elfread.o ${GDB}/gdb/ui-file.o \
          ${GDB}/gdb/utils.o ${GDB}/gdb/dwarf2read.o

GDB_6.0_FILES=${GDB}/gdb/Makefile.in ${GDB}/Makefile.in \
          ${GDB}/gdb/main.c ${GDB}/gdb/symtab.c ${GDB}/gdb/target.c \
          ${GDB}/gdb/symfile.c ${GDB}/gdb/elfread.c \
          ${GDB}/gdb/ui-file.c ${GDB}/gdb/utils.c \
	  ${GDB}/gdb/ppc-linux-tdep.c ${GDB}/sim/ppc/ppc-instructions \
	  ${GDB}/bfd/simple.c ${GDB}/include/obstack.h
GDB_6.0_OFILES=${GDB}/gdb/main.o ${GDB}/gdb/symtab.o \
          ${GDB}/gdb/target.o ${GDB}/gdb/symfile.o ${GDB}/gdb/elfread.o \
          ${GDB}/gdb/ui-file.o ${GDB}/gdb/utils.o \
	  ${GDB}/gdb/ppc-linux-tdep.o ${GDB}/bfd/simple.o

GDB_6.1_FILES=${GDB}/gdb/Makefile.in ${GDB}/Makefile.in \
          ${GDB}/gdb/main.c ${GDB}/gdb/symtab.c ${GDB}/gdb/target.c \
          ${GDB}/gdb/symfile.c ${GDB}/gdb/elfread.c \
          ${GDB}/gdb/ui-file.c ${GDB}/gdb/utils.c ${GDB}/gdb/dwarf2read.c \
          ${GDB}/include/obstack.h ${GDB}/gdb/ppc-linux-tdep.c
GDB_6.1_OFILES=${GDB}/gdb/main.o ${GDB}/gdb/symtab.o \
          ${GDB}/gdb/target.o ${GDB}/gdb/symfile.o ${GDB}/gdb/elfread.o \
          ${GDB}/gdb/ui-file.o ${GDB}/gdb/utils.o ${GDB}/gdb/dwarf2read.o \
          ${GDB}/gdb/ppc-linux-tdep.o

GDB_7.0_FILES=
GDB_7.0_OFILES=${GDB}/gdb/symtab.o

# 
# GDB_FLAGS is passed up from the gdb Makefile.
#
GDB_FLAGS=

#
# WARNING_OPTIONS and WARNING_ERROR are both applied on a per-file basis. 
# WARNING_ERROR is NOT used on files including "dirty" gdb headers so that 
# successful compilations can be achieved with acceptable warnings; its 
# usefulness is also dependent upon the processor's compiler -- your mileage
# may vary.
#
#WARNING_OPTIONS=-Wall -O2 -Wstrict-prototypes -Wmissing-prototypes -fstack-protector
#WARNING_ERROR=-Werror

# TARGET_CFLAGS will be configured automatically by configure
TARGET_CFLAGS=

CRASH_CFLAGS=-g -D${TARGET} ${TARGET_CFLAGS} ${CFLAGS}

GPL_FILES=COPYING3
TAR_FILES=${SOURCE_FILES} Makefile ${GPL_FILES} README .rh_rpm_package crash.8 \
	${EXTENSION_SOURCE_FILES} ${MEMORY_DRIVER_FILES}
CSCOPE_FILES=${SOURCE_FILES}

READLINE_DIRECTORY=./${GDB}/readline
BFD_DIRECTORY=./${GDB}/bfd
GDB_INCLUDE_DIRECTORY=./${GDB}/include

REDHATFLAGS=-DREDHAT

# target could be set on command line when invoking make. Like: make target=ARM
# otherwise target will be the same as the host
ifneq ($(target),)
CONF_TARGET_FLAG="-t$(target)"
endif

# To build the extensions library by default, uncomment the third command
# line below.  Otherwise they can be built by entering "make extensions".

all: make_configure
	@./configure ${CONF_TARGET_FLAG} -p "RPMPKG=${RPMPKG}" -b
	@make --no-print-directory gdb_merge
#	@make --no-print-directory extensions

gdb_merge: force
	@if [ ! -f ${GDB}/README ]; then \
	  make --no-print-directory gdb_unzip; fi
	@echo "${LDFLAGS} -lz -ldl -rdynamic" > ${GDB}/gdb/mergelibs
	@echo "../../${PROGRAM} ../../${PROGRAM}lib.a" > ${GDB}/gdb/mergeobj
	@if [ ! -f ${GDB}/config.status ]; then \
	  (cd ${GDB}; ./configure ${GDB_CONF_FLAGS} --with-separate-debug-dir=/usr/lib/debug \
	    --with-bugurl="" --with-expat=no --with-python=no; \
	  make --no-print-directory; echo ${TARGET} > crash.target) \
	else (cd ${GDB}/gdb; make --no-print-directory;); fi
	@if [ ! -f ${GDB}/gdb/libgdb.a ]; then \
	  echo; echo "gdb build failed: ${GDB}/gdb/libgdb.a does not exist"; \
	  echo; exit 1; fi

gdb_unzip:
	@rm -f gdb.files
	@for FILE in ${GDB_FILES} dummy; do\
	  echo $$FILE >> gdb.files; done
	@tar --exclude-from gdb.files -xvzmf ${GDB}.tar.gz
	@make --no-print-directory gdb_patch

gdb_patch:
	if [ -f ${GDB}.patch ] && [ -s ${GDB}.patch ]; then \
		patch -p0 < ${GDB}.patch; fi

library: make_build_data ${OBJECT_FILES}
	ar -rs ${PROGRAM}lib.a ${OBJECT_FILES}

gdb: force
	rm -f ${GDB_OFILES}
	@make --no-print-directory all

force:
	

make_configure: force
	@rm -f configure
	@cc ${CONF_FLAGS} -o configure configure.c ${WARNING_ERROR} ${WARNING_OPTIONS}

clean: make_configure
	@./configure ${CONF_TARGET_FLAG} -q -b
	@make --no-print-directory do_clean

do_clean:
	rm -f ${OBJECT_FILES} ${DAEMON_OBJECT_FILES} ${PROGRAM} ${PROGRAM}lib.a ${GDB_OFILES}
	@(cd extensions; make --no-print-directory -i clean)
	@(cd memory_driver; make --no-print-directory -i clean)

make_build_data: force
	cc -c ${CRASH_CFLAGS} build_data.c ${WARNING_OPTIONS} ${WARNING_ERROR}

install:
	/usr/bin/install ${PROGRAM} ${INSTALLDIR}
#	/usr/bin/install ${PROGRAM}d ${INSTALLDIR}

unconfig: make_configure
	@./configure -u

warn: make_configure
	@./configure ${CONF_TARGET_FLAG} -w -b
	@make --no-print-directory gdb_merge

Warn: make_configure
	@./configure ${CONF_TARGET_FLAG} -W -b
	@make --no-print-directory gdb_merge

nowarn: make_configure
	@./configure ${CONF_TARGET_FLAG} -n -b
	@make --no-print-directory gdb_merge

main.o: ${GENERIC_HFILES} main.c
	cc -c ${CRASH_CFLAGS} main.c ${WARNING_OPTIONS} ${WARNING_ERROR} 

cmdline.o: ${GENERIC_HFILES} cmdline.c
	cc -c ${CRASH_CFLAGS} cmdline.c ${GDB_FLAGS} -I${READLINE_DIRECTORY} ${WARNING_OPTIONS} ${WARNING_ERROR}

tools.o: ${GENERIC_HFILES} tools.c
	cc -c ${CRASH_CFLAGS} tools.c ${WARNING_OPTIONS} ${WARNING_ERROR}

global_data.o: ${GENERIC_HFILES} global_data.c
	cc -c ${CRASH_CFLAGS} global_data.c ${WARNING_OPTIONS} ${WARNING_ERROR}

symbols.o: ${GENERIC_HFILES} symbols.c
	cc -c ${CRASH_CFLAGS} symbols.c ${GDB_FLAGS} -I${BFD_DIRECTORY} -I${GDB_INCLUDE_DIRECTORY} ${WARNING_OPTIONS} ${WARNING_ERROR}

filesys.o: ${GENERIC_HFILES} filesys.c
	cc -c ${CRASH_CFLAGS} filesys.c ${WARNING_OPTIONS} ${WARNING_ERROR}

help.o: ${GENERIC_HFILES} help.c
	cc -c ${CRASH_CFLAGS} help.c ${GDB_FLAGS} ${WARNING_OPTIONS} ${WARNING_ERROR}

memory.o: ${GENERIC_HFILES} memory.c
	cc -c ${CRASH_CFLAGS} memory.c ${WARNING_OPTIONS} ${WARNING_ERROR}

test.o: ${GENERIC_HFILES} test.c
	cc -c ${CRASH_CFLAGS} test.c ${WARNING_OPTIONS} ${WARNING_ERROR}

task.o: ${GENERIC_HFILES} task.c
	cc -c ${CRASH_CFLAGS} task.c ${GDB_FLAGS} ${WARNING_OPTIONS} ${WARNING_ERROR}

kernel.o: ${GENERIC_HFILES} kernel.c
	cc -c ${CRASH_CFLAGS} kernel.c ${GDB_FLAGS} ${WARNING_OPTIONS} ${WARNING_ERROR}

gdb_interface.o: ${GENERIC_HFILES} gdb_interface.c
	cc -c ${CRASH_CFLAGS} gdb_interface.c ${GDB_FLAGS} ${WARNING_OPTIONS} ${WARNING_ERROR}

va_server.o: ${MCORE_HFILES} va_server.c
	cc -c ${CRASH_CFLAGS} va_server.c ${WARNING_OPTIONS} ${WARNING_ERROR}

va_server_v1.o: ${MCORE_HFILES} va_server_v1.c
	cc -c ${CRASH_CFLAGS} va_server_v1.c ${WARNING_OPTIONS} ${WARNING_ERROR}

lkcd_common.o: ${GENERIC_HFILES} ${LKCD_DUMP_HFILES} lkcd_common.c
	cc -c ${CRASH_CFLAGS} lkcd_common.c ${WARNING_OPTIONS} ${WARNING_ERROR}

lkcd_v1.o: ${GENERIC_HFILES} ${LKCD_DUMP_HFILES} lkcd_v1.c
	cc -c ${CRASH_CFLAGS} lkcd_v1.c -DMCLX ${WARNING_OPTIONS} ${WARNING_ERROR}

lkcd_v2_v3.o: ${GENERIC_HFILES} ${LKCD_DUMP_HFILES} lkcd_v2_v3.c
	cc -c ${CRASH_CFLAGS} lkcd_v2_v3.c -DMCLX ${WARNING_OPTIONS} ${WARNING_ERROR}

lkcd_v5.o: ${GENERIC_HFILES} ${LKCD_DUMP_HFILES} lkcd_v5.c
	cc -c ${CRASH_CFLAGS} lkcd_v5.c -DMCLX ${WARNING_OPTIONS} ${WARNING_ERROR}

lkcd_v7.o: ${GENERIC_HFILES} ${LKCD_DUMP_HFILES} lkcd_v7.c
	cc -c ${CRASH_CFLAGS} lkcd_v7.c -DMCLX ${WARNING_OPTIONS} ${WARNING_ERROR}

lkcd_v8.o: ${GENERIC_HFILES} ${LKCD_DUMP_HFILES} lkcd_v8.c
	cc -c ${CRASH_CFLAGS} lkcd_v8.c -DMCLX ${WARNING_OPTIONS} ${WARNING_ERROR}

net.o: ${GENERIC_HFILES} net.c
	cc -c ${CRASH_CFLAGS} net.c ${WARNING_OPTIONS} ${WARNING_ERROR}

dev.o: ${GENERIC_HFILES} dev.c
	cc -c ${CRASH_CFLAGS} dev.c ${WARNING_OPTIONS} ${WARNING_ERROR}

# remote.c functionality has been deprecated
remote.o: ${GENERIC_HFILES} remote.c
	@cc -c ${CRASH_CFLAGS} remote.c ${WARNING_OPTIONS} ${WARNING_ERROR}
remote_daemon.o: ${GENERIC_HFILES} remote.c
	cc -c ${CRASH_CFLAGS} -DDAEMON remote.c -o remote_daemon.o ${WARNING_OPTIONS} ${WARNING_ERROR}

x86.o: ${GENERIC_HFILES} ${REDHAT_HFILES} x86.c
	cc -c ${CRASH_CFLAGS} x86.c -DMCLX ${WARNING_OPTIONS} ${WARNING_ERROR}

alpha.o: ${GENERIC_HFILES} alpha.c
	cc -c ${CRASH_CFLAGS} alpha.c ${GDB_FLAGS} ${WARNING_OPTIONS} ${WARNING_ERROR}

ppc.o: ${GENERIC_HFILES} ppc.c
	cc -c ${CRASH_CFLAGS} ppc.c ${WARNING_OPTIONS} ${WARNING_ERROR}

ia64.o: ${GENERIC_HFILES} ${REDHAT_HFILES} ia64.c
	cc -c ${CRASH_CFLAGS} ia64.c ${WARNING_OPTIONS} ${WARNING_ERROR}

ppc64.o: ${GENERIC_HFILES} ppc64.c
	cc -c ${CRASH_CFLAGS} ppc64.c ${WARNING_OPTIONS} ${WARNING_ERROR}

x86_64.o: ${GENERIC_HFILES} ${REDHAT_HFILES} x86_64.c
	cc -c ${CRASH_CFLAGS} x86_64.c ${WARNING_OPTIONS} ${WARNING_ERROR}

arm.o: ${GENERIC_HFILES} ${REDHAT_HFILES} arm.c
	cc -c ${CRASH_CFLAGS} arm.c ${WARNING_OPTIONS} ${WARNING_ERROR}

s390.o: ${GENERIC_HFILES} ${IBM_HFILES} s390.c
	cc -c ${CRASH_CFLAGS} s390.c ${WARNING_OPTIONS} ${WARNING_ERROR}

s390x.o: ${GENERIC_HFILES} ${IBM_HFILES} s390x.c
	cc -c ${CRASH_CFLAGS} s390x.c ${WARNING_OPTIONS} ${WARNING_ERROR}

s390dbf.o: ${GENERIC_HFILES} ${IBM_HFILES} s390dbf.c
	cc -c ${CRASH_CFLAGS} s390dbf.c ${WARNING_OPTIONS} ${WARNING_ERROR}

s390_dump.o: ${GENERIC_HFILES} ${IBM_HFILES} s390_dump.c
	cc -c ${CRASH_CFLAGS} s390_dump.c ${WARNING_OPTIONS} ${WARNING_ERROR}

netdump.o: ${GENERIC_HFILES} ${REDHAT_HFILES} netdump.c
	cc -c ${CRASH_CFLAGS} netdump.c ${WARNING_OPTIONS} ${WARNING_ERROR}
netdump_daemon.o: ${GENERIC_HFILES} ${REDHAT_HFILES} netdump.c
	cc -c ${CRASH_CFLAGS} -DDAEMON netdump.c -o netdump_daemon.o ${WARNING_OPTIONS} ${WARNING_ERROR}

diskdump.o: ${GENERIC_HFILES} ${REDHAT_HFILES} diskdump.c
	cc -c ${CRASH_CFLAGS} diskdump.c ${WARNING_OPTIONS} ${WARNING_ERROR}

makedumpfile.o: ${GENERIC_HFILES} ${REDHAT_HFILES} makedumpfile.c
	cc -c ${CRASH_CFLAGS} makedumpfile.c ${WARNING_OPTIONS} ${WARNING_ERROR}

xendump.o: ${GENERIC_HFILES} ${REDHAT_HFILES} xendump.c
	cc -c ${CRASH_CFLAGS} xendump.c ${WARNING_OPTIONS} ${WARNING_ERROR}

kvmdump.o: ${GENERIC_HFILES} ${REDHAT_HFILES} kvmdump.c
	cc -c ${CRASH_CFLAGS} kvmdump.c ${WARNING_OPTIONS} ${WARNING_ERROR}

qemu.o: ${GENERIC_HFILES} ${REDHAT_HFILES} qemu.c
	cc -c ${CRASH_CFLAGS} qemu.c ${WARNING_OPTIONS} ${WARNING_ERROR}

qemu-load.o: ${GENERIC_HFILES} ${REDHAT_HFILES} qemu-load.c
	cc -c ${CRASH_CFLAGS} qemu-load.c ${WARNING_OPTIONS} ${WARNING_ERROR}

sadump.o: ${GENERIC_HFILES} ${SADUMP_HFILES} sadump.c
	cc -c ${CRASH_CFLAGS} sadump.c ${WARNING_OPTIONS} ${WARNING_ERROR}

extensions.o: ${GENERIC_HFILES} extensions.c
	cc -c ${CRASH_CFLAGS} extensions.c ${WARNING_OPTIONS} ${WARNING_ERROR}

lkcd_x86_trace.o: ${GENERIC_HFILES} ${LKCD_TRACE_HFILES} lkcd_x86_trace.c 
	cc -c ${CRASH_CFLAGS} lkcd_x86_trace.c -DREDHAT ${WARNING_OPTIONS} ${WARNING_ERROR}

unwind_x86_32_64.o: ${GENERIC_HFILES} ${UNWIND_HFILES} unwind_x86_32_64.c
	cc -c ${CRASH_CFLAGS} unwind_x86_32_64.c -o unwind_x86_32_64.o ${WARNING_OPTIONS} ${WARNING_ERROR}

unwind_arm.o: ${GENERIC_HFILES} ${UNWIND_HFILES} unwind_arm.c
	cc -c ${CRASH_CFLAGS} unwind_arm.c -o unwind_arm.o ${WARNING_OPTIONS} ${WARNING_ERROR}

unwind_v1.o: ${GENERIC_HFILES} ${UNWIND_HFILES} unwind.c unwind_decoder.c
	cc -c ${CRASH_CFLAGS} unwind.c -DREDHAT -DUNWIND_V1 -o unwind_v1.o ${WARNING_OPTIONS} ${WARNING_ERROR}

unwind_v2.o: ${GENERIC_HFILES} ${UNWIND_HFILES} unwind.c unwind_decoder.c
	cc -c ${CRASH_CFLAGS} unwind.c -DREDHAT -DUNWIND_V2 -o unwind_v2.o ${WARNING_OPTIONS} ${WARNING_ERROR}

unwind_v3.o: ${GENERIC_HFILES} ${UNWIND_HFILES} unwind.c unwind_decoder.c
	cc -c ${CRASH_CFLAGS} unwind.c -DREDHAT -DUNWIND_V3 -o unwind_v3.o ${WARNING_OPTIONS} ${WARNING_ERROR}

lkcd_fix_mem.o: ${GENERIC_HFILES} ${LKCD_HFILES} lkcd_fix_mem.c
	cc -c ${CRASH_CFLAGS} lkcd_fix_mem.c -DMCLX ${WARNING_OPTIONS} ${WARNING_ERROR}

xen_hyper.o: ${GENERIC_HFILES} xen_hyper.c
	cc -c ${CRASH_CFLAGS} xen_hyper.c ${WARNING_OPTIONS} ${WARNING_ERROR}

xen_hyper_command.o: ${GENERIC_HFILES} xen_hyper_command.c
	cc -c ${CRASH_CFLAGS} xen_hyper_command.c ${WARNING_OPTIONS} ${WARNING_ERROR}

xen_hyper_global_data.o: ${GENERIC_HFILES} xen_hyper_global_data.c
	cc -c ${CRASH_CFLAGS} xen_hyper_global_data.c ${WARNING_OPTIONS} ${WARNING_ERROR}

xen_hyper_dump_tables.o: ${GENERIC_HFILES} xen_hyper_dump_tables.c
	cc -c ${CRASH_CFLAGS} xen_hyper_dump_tables.c ${WARNING_OPTIONS} ${WARNING_ERROR}

${PROGRAM}: force
	@make --no-print-directory all

# Remote daemon functionality has been deprecated.
daemon_deprecated: force
	@echo "WARNING: remote daemon functionality has been deprecated"
	@echo 

${PROGRAM}d: daemon_deprecated make_configure
	@./configure -d
	@make --no-print-directory make_build_data
	@make --no-print-directory daemon 

daemon: ${DAEMON_OBJECT_FILES}
	cc ${LDFLAGS} -o ${PROGRAM}d ${DAEMON_OBJECT_FILES} build_data.o -lz 

files: make_configure
	@./configure -q -b
	@make --no-print-directory show_files

gdb_files: make_configure
	@./configure -q -b
	@echo ${GDB_FILES} ${GDB_PATCH_FILES}

show_files:
	@if [ -f ${PROGRAM}  ]; then \
		./${PROGRAM} --no_scroll --no_crashrc -h README > README; fi
	@echo ${SOURCE_FILES} Makefile ${GDB_FILES} ${GDB_PATCH_FILES} ${GPL_FILES} README \
	.rh_rpm_package crash.8 ${EXTENSION_SOURCE_FILES} ${MEMORY_DRIVER_FILES}

ctags:
	ctags ${SOURCE_FILES}

tar: make_configure
	@./configure -q -b
	@make --no-print-directory do_tar

do_tar:
	@if [ -f ${PROGRAM}  ]; then \
		./${PROGRAM} --no_scroll --no_crashrc -h README > README; fi
	tar cvzf ${PROGRAM}.tar.gz ${TAR_FILES} ${GDB_FILES} ${GDB_PATCH_FILES}
	@echo; ls -l ${PROGRAM}.tar.gz

VERSION=5.1.8
RELEASE=0

release: make_configure
	@if [ "`id --user`" != "0" ]; then \
		echo "make release: must be super-user"; exit 1; fi
	@./configure -P "RPMPKG=${RPMPKG}" -u -g
	@make --no-print-directory release_configure
	@echo 
	@echo "cvs tag this release if necessary"

release_configure: make_configure
	@if [ "${GDB}" = "" ] ; then \
		echo "make release: GDB not defined: append GDB=gdb-x.x to make command line"; echo; exit 1; fi 
	@./configure -r ${GDB}
	@make --no-print-directory do_release

do_release:
	@echo "CRASH VERSION: ${VERSION}  GDB VERSION: ${GDB}"
	@if [ ! -f .rh_rpm_package  ]; then \
		echo "no .rh_rpm_package exists!"; exit 1; fi
	@chmod 666 .rh_rpm_package
	@rm -rf ./RELDIR; mkdir ./RELDIR; mkdir ./RELDIR/${PROGRAM}-${VERSION}
	@rm -f ${PROGRAM}-${VERSION}.tar.gz 
	@rm -f ${PROGRAM}-${VERSION}-${RELEASE}.src.rpm
	@chown root ./RELDIR/${PROGRAM}-${VERSION}
	@tar cf - ${SOURCE_FILES} Makefile ${GDB_FILES} ${GDB_PATCH_FILES} ${GPL_FILES} \
	.rh_rpm_package crash.8 ${EXTENSION_SOURCE_FILES} ${MEMORY_DRIVER_FILES} | \
	(cd ./RELDIR/${PROGRAM}-${VERSION}; tar xf -)
	@cp ${GDB}.tar.gz ./RELDIR/${PROGRAM}-${VERSION}
	@./${PROGRAM} --no_scroll --no_crashrc -h README > ./RELDIR/${PROGRAM}-${VERSION}/README
	@(cd ./RELDIR; find . -exec chown root {} ";")
	@(cd ./RELDIR; find . -exec chgrp root {} ";")
	@(cd ./RELDIR; find . -exec touch {} ";")
	@(cd ./RELDIR; \
		tar czvf ../${PROGRAM}-${VERSION}.tar.gz ${PROGRAM}-${VERSION})
	@chgrp root ${PROGRAM}-${VERSION}.tar.gz
	@rm -rf ./RELDIR
	@echo
	@ls -l ${PROGRAM}-${VERSION}.tar.gz
	@./configure -s -u > ${PROGRAM}.spec
	@if [ -s ${PROGRAM}.spec ]; then \
	  rm -rf ./RPMBUILD; \
	  mkdir -p ./RPMBUILD/SOURCES ./RPMBUILD/SPECS ./RPMBUILD/SRPMS; \
	  cp ${PROGRAM}-${VERSION}.tar.gz ./RPMBUILD/SOURCES; \
	  cp ${PROGRAM}.spec ./RPMBUILD/SPECS; \
	  rpmbuild --define "_sourcedir ./RPMBUILD/SOURCES" \
	    --define "_srcrpmdir ./RPMBUILD/SRPMS" \
	    --define "_specdir ./RPMBUILD/SPECS" \
	    --nodeps -bs ./RPMBUILD/SPECS/${PROGRAM}.spec > /dev/null; \
	   mv ./RPMBUILD/SRPMS/${PROGRAM}-${VERSION}-${RELEASE}.src.rpm . ; \
	   rm -rf ./RPMBUILD; \
	   ls -l ${PROGRAM}-${VERSION}-${RELEASE}.src.rpm; \
	fi

ref:
	make ctags cscope

cscope:
	rm -f cscope.files cscope_out
	for FILE in ${SOURCE_FILES}; do \
	echo $$FILE >> cscope.files; done
	cscope

glink: make_configure
	@./configure -q -b
	rm -f gdb
	ln -s ${GDB}/gdb gdb
	(cd ${GDB}/gdb; rm -f ${PROGRAM}; ln -s ../../${PROGRAM} ${PROGRAM})

name:
	@echo ${PROGRAM}

dis:
	objdump --disassemble --line-numbers ${PROGRAM} > ${PROGRAM}.dis

extensions: make_configure
	@./configure ${CONF_TARGET_FLAG} -q -b
	@make --no-print-directory do_extensions

do_extensions:
	@(cd extensions; make -i TARGET=$(TARGET) TARGET_CFLAGS="$(TARGET_CFLAGS)" GDB=$(GDB) GDB_FLAGS=$(GDB_FLAGS))

memory_driver: make_configure 
	@(cd memory_driver; make --no-print-directory -i)
