#
ifeq ($(TARGET), PPC64)
        TARGET_FLAGS = -D$(TARGET) -m64
else
        TARGET_FLAGS = -D$(TARGET)
endif

all: sial.so

lib-sial: 
	cd libsial && make
        
sial.so: ../defs.h sial.c lib-sial
	gcc -g -I.. -Ilibsial -I../gdb-6.1/bfd -I../gdb-6.1/include -I../gdb-6.1/gdb -I../gdb-6.1/gdb/config -nostartfiles -shared -rdynamic -o sial.so sial.c -fPIC $(TARGET_FLAGS) -Llibsial -lsial 

clean:
	cd libsial && make clean
