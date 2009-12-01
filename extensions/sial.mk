#
ifeq ($(TARGET), PPC64)
        TARGET_FLAGS = -D$(TARGET) -m64
else
        TARGET_FLAGS = -D$(TARGET)
endif

all:
	@if [ -f /usr/bin/flex ] && [ -f /usr/bin/bison ]; then \
	  make -f sial.mk sial.so; \
	else \
	  echo "sial.so: build failed: requires /usr/bin/flex and /usr/bin/bison"; fi

lib-sial: 
	cd libsial && make
        
sial.so: ../defs.h sial.c lib-sial
	gcc -g -I.. -Ilibsial -I../$(GDB)/bfd -I../$(GDB)/include -I../$(GDB)/gdb -I../$(GDB)/gdb/config -I../$(GDB)/gdb/common -I../$(GDB) -nostartfiles -shared -rdynamic -o sial.so sial.c -fPIC $(TARGET_FLAGS) $(GDB_FLAGS) -Llibsial -lsial 

clean:
	cd libsial && make clean
