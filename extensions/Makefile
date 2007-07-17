#
# Makefile for building crash shared object extensions
#
# Copyright (C) 2005 David Anderson
# Copyright (C) 2005 Red Hat, Inc. All rights reserved.
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
# To build the extension shared objects in this directory, run 
# "make extensions" from the top-level directory.
#
# To add a new extension object: 
#
#  - add the new source file to the EXTENSION_SOURCE_FILES list 
#    in the top-level Makefile
#  - add the object file name to the EXTENSION_OBJECT_FILES list
#    in the top-level Makefile
#  - create a compile stanza below, typically using "echo.so" as 
#    a base template.
# 

all: link_defs $(OBJECTS)
	
link_defs:
	@if [ ! -f defs.h ]; then \
	  ln -s ../defs.h; fi 

echo.so: ../defs.h echo.c
	gcc -nostartfiles -shared -rdynamic -o echo.so echo.c -fPIC \
				 		-D$(TARGET) $(TARGET_CFLAGS)

dminfo.so: ../defs.h dminfo.c
	gcc -nostartfiles -shared -rdynamic -o dminfo.so dminfo.c -fPIC \
				 		-D$(TARGET) $(TARGET_CFLAGS)
	
