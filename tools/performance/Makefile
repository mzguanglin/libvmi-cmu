CC       = gcc

CFLAGS   += -Wall
#CFLAGS   += -Werror
CFLAGS   += -I/usr/local/include/libvmi -O3
#CFLAGS   += $(INCLUDES) -I.
#CFLAGS   += -Wp,-MD,.$(@F).d
#LDFLAGS  += -L. -L../libxa/
#DEPS     = .*.d
LIBS     = -lxenctrl -lvmi -lm

#all: kern_sym virt_addr user_virt_addr-linux user_virt_addr-windows read_mem
all: kern_sym virt_addr read_mem bw_mem

clean:
	rm -rf *.a *.o *~ $(DEPS) kern_sym virt_addr user_virt_addr-linux user_virt_addr-windows read_mem bw_mem

kern_sym: kern_sym.c common.c
	$(CC) $(CFLAGS) $(LDFLAGS)  -o $@ $^ $(LIBS)

virt_addr: virt_addr.c common.c
	$(CC) $(CFLAGS) $(LDFLAGS)  -o $@ $^ $(LIBS)

user_virt_addr-linux: user_virt_addr-linux.c common.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

user_virt_addr-windows: user_virt_addr-windows.c common.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

read_mem: read_mem.c common.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

bw_mem: bw_mem.c lib_timing.c getopt.c lib_sched.c lib_debug.c
	$(CC) $(CFLAGS) $(LDFLAGS)  -o $@ $^ $(LIBS)

-include $(DEPS)
