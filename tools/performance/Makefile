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
all: kern_sym virt_addr read_mem read_mem_snapshot read_mem_snapshot_direct_access read_mem_host host_memcpy host_mimic_lmbench bw_mem bw_mem_snapshot_dma

clean:
	rm -rf *.a *.o *~ $(DEPS) kern_sym virt_addr user_virt_addr-linux user_virt_addr-windows read_mem read_mem_snapshot read_mem_snapshot_direct_access read_mem_host host_memcpy host_mimic_lmbench bw_mem bw_mem_snapshot_dma

bw_mem: bw_mem.c lib_timing.c getopt.c lib_sched.c lib_debug.c
	$(CC) $(CFLAGS) $(LDFLAGS)  -o $@ $^ $(LIBS)
	
bw_mem_snapshot_dma: bw_mem_snapshot_dma.c lib_timing.c getopt.c lib_sched.c lib_debug.c
	$(CC) $(CFLAGS) $(LDFLAGS)  -o $@ $^ $(LIBS)

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

read_mem_snapshot: read_mem_snapshot.c common.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

read_mem_snapshot_direct_access: read_mem_snapshot_direct_access.c common.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

read_mem_host: read_mem_host.c common.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)
	
host_memcpy: host_memcpy.c common.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)
	
host_mimic_lmbench: host_mimic_lmbench.c common.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

-include $(DEPS)
