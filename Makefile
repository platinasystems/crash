# Makefile for core analysis suite
#
# Copyright (C) 1999, 2000, 2001, 2002 Mission Critical Linux, Inc.
#       www.missioncriticallinux.com, info@missioncriticallinux.com
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
# BitKeeper ID: @(#)Makefile 1.13
#
# 09/28/00  Transition to CVS version control
#
# CVS: $Revision: 1.72 $ $Date: 2002/01/30 19:28:34 $
#

PROGRAM=crash

#
# Supported targets: X86 ALPHA PPC IA64
# TARGET will be configured automatically by mktarget
#
TARGET=

#
# Supported gdb versions: gdb-5.0 gdb-5.0-7 gdb-5.1
# GDB, GDB_FILES and GDB_OFILES will be configured automatically by mktarget 
#
GDB=
GDB_FILES=${GDB_5.1_FILES}
GDB_OFILES=

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

MCLX_HFILES=defs.h va_server.h vas_crash.h 
LKCD_HFILES=lkcd_vmdump_v1.h lkcd_vmdump_v2_v3.h lkcd_dump_v5.h
IBM_HFILES=ibm_common.h
MCLX_CFILES=main.c tools.c global_data.c memory.c filesys.c help.c task.c \
	kernel.c test.c gdb_interface.c mktarget.c net.c dev.c \
	alpha.c x86.c ppc.c ia64.c s390.c s390x.c \
	extensions.c remote.c va_server.c va_server_v1.c symbols.c cmdline.c \
	lkcd_common.c lkcd_v1.c lkcd_v2_v3.c lkcd_v5.c \
	s390_dump.c s390x_dump.c
SOURCE_FILES=${MCLX_CFILES} ${MCLX_HFILES} ${LKCD_HFILES} ${IBM_HFILES} 

OBJECT_FILES=main.o tools.o global_data.o memory.o filesys.o help.o task.o \
	build_data.o kernel.o test.o gdb_interface.o net.o dev.o \
	alpha.o x86.o ppc.o ia64.o s390.o s390x.o \
	extensions.o remote.o va_server.o va_server_v1.o symbols.o cmdline.o \
	lkcd_common.o lkcd_v1.o lkcd_v2_v3.o lkcd_v5.o \
	s390_dump.o s390x_dump.o

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

GDB_5.0-7_FILES=${GDB_5.0_FILES}
GDB_5.0-7_OFILES=${GDB_5.0_OFILES}

GDB_5.1_FILES=${GDB}/gdb/Makefile.in \
	  ${GDB}/gdb/main.c ${GDB}/gdb/symtab.c ${GDB}/gdb/target.c \
	  ${GDB}/gdb/blockframe.c ${GDB}/gdb/alpha-tdep.c \
	  ${GDB}/gdb/symfile.c ${GDB}/gdb/elfread.c \
	  ${GDB}/gdb/ui-file.c ${GDB}/gdb/utils.c  ${GDB}/gdb/gnu-regex.c
GDB_5.1_OFILES=${GDB}/gdb/main.o ${GDB}/gdb/symtab.o ${GDB}/gdb/target.o \
          ${GDB}/gdb/blockframe.o ${GDB}/gdb/alpha-tdep.o \
          ${GDB}/gdb/symfile.o ${GDB}/gdb/elfread.o \
          ${GDB}/gdb/ui-file.o ${GDB}/gdb/utils.o ${GDB}/gdb/gnu-regex.o

# 
# GDB_FLAGS is currently unused.  It's passed up from the gdb Makefile, and
# can be resurrected if the need arises.
#
GDB_FLAGS=

#
# WARNING_OPTIONS and WARNING_ERROR are both applied on a per-file basis. 
# WARNING_ERROR is NOT used on files including "dirty" gdb headers so that 
# successful compilations can be achieved with acceptable warnings; its 
# usefulness is also dependent upon the processor's compiler -- your mileage
# may vary.
#
#WARNING_OPTIONS=-Wall -Wstrict-prototypes -Wmissing-prototypes
#WARNING_ERROR=-Werror

CFLAGS=-g -DMCLX -D${TARGET}

TAR_FILES=${SOURCE_FILES} Makefile COPYING README
CSCOPE_FILES=${SOURCE_FILES}

READLINE_DIRECTORY=./${GDB}/readline
BFD_DIRECTORY=./${GDB}/bfd

all: target
	@./mktarget -b
	@make --no-print-directory gdb_merge

gdb_merge: force
	@if [ ! -f ${GDB}/Makefile.in ]; then \
	  make --no-print-directory gdb_unzip; fi
	@echo "${LDFLAGS} ../../${PROGRAM}lib.a -lz -ldl -rdynamic" > \
		${GDB}/gdb/mergelibs
	@echo "../../${PROGRAM}" > ${GDB}/gdb/mergeobj
	@if [ ! -f ${GDB}/config.status ]; then \
	  (cd ${GDB}; ./configure; make --no-print-directory;) \
	else (cd ${GDB}/gdb; make --no-print-directory;); fi

gdb_unzip:
	@rm -f gdb.files
	@for FILE in ${GDB_FILES}; do\
	  echo $$FILE >> gdb.files; done
	@tar --exclude-from gdb.files -xvzmf ${GDB}.tar.gz

library: stamp ${OBJECT_FILES}
	ar -rs ${PROGRAM}lib.a ${OBJECT_FILES}
	
gdb: force
	rm -f ${GDB_OFILES}
	@make --no-print-directory all

force:
	

target: force
	@rm -f mktarget
	@cc -o mktarget mktarget.c ${WARNING_ERROR} ${WARNING_OPTIONS}

clean:
	rm -f ${OBJECT_FILES} ${PROGRAM} ${PROGRAM}lib.a ${GDB_OFILES}

stamp: force
	cc -c ${CFLAGS} build_data.c ${WARNING_OPTIONS} ${WARNING_ERROR}

unconfig: target
	@./mktarget -u

warn: target
	@./mktarget -w -b
	@make --no-print-directory gdb_merge

Warn: target
	@./mktarget -W -b
	@make --no-print-directory gdb_merge

nowarn: target
	@./mktarget -n -b
	@make --no-print-directory gdb_merge

main.o: ${MCLX_HFILES} main.c
	cc -c ${CFLAGS} main.c ${WARNING_OPTIONS} ${WARNING_ERROR} 

cmdline.o: ${MCLX_HFILES} cmdline.c
	cc -c ${CFLAGS} cmdline.c -I${READLINE_DIRECTORY} ${WARNING_OPTIONS}

tools.o: ${MCLX_HFILES} tools.c
	cc -c ${CFLAGS} tools.c ${WARNING_OPTIONS} ${WARNING_ERROR}

global_data.o: ${MCLX_HFILES} global_data.c
	cc -c ${CFLAGS} global_data.c ${WARNING_OPTIONS} ${WARNING_ERROR}

symbols.o: ${MCLX_HFILES} symbols.c
	cc -c ${CFLAGS} symbols.c -I${BFD_DIRECTORY} ${WARNING_OPTIONS} ${WARNING_ERROR}

filesys.o: ${MCLX_HFILES} filesys.c
	cc -c ${CFLAGS} filesys.c ${WARNING_OPTIONS} ${WARNING_ERROR}

help.o: ${MCLX_HFILES} help.c
	cc -c ${CFLAGS} help.c ${WARNING_OPTIONS} ${WARNING_ERROR}

memory.o: ${MCLX_HFILES} memory.c
	cc -c ${CFLAGS} memory.c ${WARNING_OPTIONS} ${WARNING_ERROR}

test.o: ${MCLX_HFILES} test.c
	cc -c ${CFLAGS} test.c ${WARNING_OPTIONS} ${WARNING_ERROR}

task.o: ${MCLX_HFILES} task.c
	cc -c ${CFLAGS} task.c ${WARNING_OPTIONS} ${WARNING_ERROR}

kernel.o: ${MCLX_HFILES} kernel.c
	cc -c ${CFLAGS} kernel.c ${WARNING_OPTIONS} ${WARNING_ERROR}

gdb_interface.o: ${MCLX_HFILES} gdb_interface.c
	cc -c ${CFLAGS} gdb_interface.c ${WARNING_OPTIONS} ${WARNING_ERROR}

va_server.o: ${MCLX_HFILES} va_server.c
	cc -c ${CFLAGS} va_server.c ${WARNING_OPTIONS} ${WARNING_ERROR}

va_server_v1.o: ${MCLX_HFILES} va_server_v1.c
	cc -c ${CFLAGS} va_server_v1.c ${WARNING_OPTIONS} ${WARNING_ERROR}

lkcd_common.o: ${MCLX_HFILES} ${LKCD_HFILES} lkcd_common.c
	cc -c ${CFLAGS} lkcd_common.c ${WARNING_OPTIONS} ${WARNING_ERROR}

lkcd_v1.o: ${MCLX_HFILES} ${LKCD_HFILES} lkcd_v1.c
	cc -c ${CFLAGS} lkcd_v1.c ${WARNING_OPTIONS} ${WARNING_ERROR}

lkcd_v2_v3.o: ${MCLX_HFILES} ${LKCD_HFILES} lkcd_v2_v3.c
	cc -c ${CFLAGS} lkcd_v2_v3.c ${WARNING_OPTIONS} ${WARNING_ERROR}

lkcd_v5.o: ${MCLX_HFILES} ${LKCD_HFILES} lkcd_v5.c
	cc -c ${CFLAGS} lkcd_v5.c ${WARNING_OPTIONS} ${WARNING_ERROR}

net.o: ${MCLX_HFILES} net.c
	cc -c ${CFLAGS} net.c ${WARNING_OPTIONS} ${WARNING_ERROR}

dev.o: ${MCLX_HFILES} dev.c
	cc -c ${CFLAGS} dev.c ${WARNING_OPTIONS} ${WARNING_ERROR}

remote.o: ${MCLX_HFILES} remote.c
	cc -c ${CFLAGS} remote.c ${WARNING_OPTIONS} ${WARNING_ERROR}

x86.o: ${MCLX_HFILES} x86.c
	cc -c ${CFLAGS} x86.c ${WARNING_OPTIONS} ${WARNING_ERROR}

alpha.o: ${MCLX_HFILES} alpha.c
	cc -c ${CFLAGS} alpha.c ${WARNING_OPTIONS} ${WARNING_ERROR}

ppc.o: ${MCLX_HFILES} ppc.c
	cc -c ${CFLAGS} ppc.c ${WARNING_OPTIONS} ${WARNING_ERROR}

ia64.o: ${MCLX_HFILES} ia64.c
	cc -c ${CFLAGS} ia64.c ${WARNING_OPTIONS} ${WARNING_ERROR}

s390.o: ${MCLX_HFILES} ${IBM_HFILES} s390.c
	cc -c ${CFLAGS} s390.c ${WARNING_OPTIONS} ${WARNING_ERROR}

s390x.o: ${MCLX_HFILES} ${IBM_HFILES} s390x.c
	cc -c ${CFLAGS} s390x.c ${WARNING_OPTIONS} ${WARNING_ERROR}

s390_dump.o: ${MCLX_HFILES} ${IBM_HFILES} s390_dump.c
	cc -c ${CFLAGS} s390_dump.c ${WARNING_OPTIONS} ${WARNING_ERROR}

s390x_dump.o: ${MCLX_HFILES} ${IBM_HFILES} s390x_dump.c
	cc -c ${CFLAGS} s390x_dump.c ${WARNING_OPTIONS} ${WARNING_ERROR}

extensions.o: ${MCLX_HFILES} extensions.c
	cc -c ${CFLAGS} extensions.c ${WARNING_OPTIONS} ${WARNING_ERROR}

${PROGRAM}: force
	@make --no-print-directory all

${PROGRAM}d: target
	@./mktarget -d
	@make --no-print-directory stamp
	@make --no-print-directory daemon 

daemon: va_server.o va_server_v1.o lkcd_common.o lkcd_v1.o \
	lkcd_v2_v3.o lkcd_v5.o s390_dump.o s390x_dump.o
	cc -c ${CFLAGS} remote.c -o daemon.o -D_DAEMON_ ${WARNING_OPTIONS} ${WARNING_ERROR} 
	cc ${LDFLAGS} -o ${PROGRAM}d daemon.o va_server.o va_server_v1.o \
	lkcd_common.o lkcd_v1.o lkcd_v2_v3.o lkcd_v5.o \
	s390_dump.o s390x_dump.o build_data.o -lz 
	
files: target
	@./mktarget -q -b
	@make --no-print-directory show_files

show_files:
	@echo ${SOURCE_FILES} Makefile ${GDB_FILES} COPYING README

ctags:
	ctags ${SOURCE_FILES}

tar: target
	@./mktarget -q -b
	@make --no-print-directory do_tar

do_tar:
	tar cvzf ${PROGRAM}.tar.gz ${TAR_FILES} ${GDB_FILES}

RELEASE=

release:
	@if [ "`id --user`" != "0" ]; then \
		echo "make release: must be super-user"; exit 1; fi
	@if [ "${RELEASE}" = "" ] || [ "${GDB}" = "" ] ; then \
		echo "Enter RELEASE=x.x and, if not set, GDB=gdb-x.x on make command line "; \
	else make --no-print-directory release_configure; fi

release_configure: target
	@./mktarget -u -r ${GDB}
	@make --no-print-directory do_release

do_release:
	@echo "RELEASE: ${RELEASE}  GDB VERSION: ${GDB}"
	@rm -rf ./RELDIR; mkdir ./RELDIR; mkdir ./RELDIR/${PROGRAM}${RELEASE}
	@rm -f ${PROGRAM}${RELEASE}.tar.gz ${PROGRAM}${RELEASE}-IA64.tar.gz
	@chown root ./RELDIR/${PROGRAM}${RELEASE}
	@tar cf - ${SOURCE_FILES} Makefile ${GDB_FILES} COPYING \
	| (cd ./RELDIR/${PROGRAM}${RELEASE}; tar xf -)
	@cp ${GDB}.tar.gz ./RELDIR/${PROGRAM}${RELEASE}
	@./crash -h README > ./RELDIR/${PROGRAM}${RELEASE}/README
	@(cd ./RELDIR; find . -exec chown root {} ";")
	@(cd ./RELDIR; find . -exec chgrp root {} ";")
	@(cd ./RELDIR; find . -exec touch {} ";")
	@(cd ./RELDIR; \
		tar czvf ../${PROGRAM}${RELEASE}.tar.gz ${PROGRAM}${RELEASE})
	@chgrp root ${PROGRAM}${RELEASE}.tar.gz
	@rm -rf ./RELDIR
	@echo
	@if [ "${GDB}" = "gdb-5.0-7" ]; then \
		mv ${PROGRAM}${RELEASE}.tar.gz \
			${PROGRAM}${RELEASE}-IA64.tar.gz; \
		ls -l ${PROGRAM}${RELEASE}-IA64.tar.gz; \
	else ls -l ${PROGRAM}${RELEASE}.tar.gz; fi


ref:
	make ctags cscope

cscope:
	rm -f cscope.files cscope_out
	for FILE in ${SOURCE_FILES}; do \
	echo $$FILE >> cscope.files; done
	cscope

glink: target
	@./mktarget -q -b
	rm -f gdb
	ln -s ${GDB}/gdb gdb
	(cd ${GDB}/gdb; rm -f ${PROGRAM}; ln -s ../../${PROGRAM} ${PROGRAM})

name:
	@echo ${PROGRAM}
