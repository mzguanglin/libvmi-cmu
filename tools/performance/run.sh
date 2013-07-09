#! /bin/sh

#nohup bash -x ./run.sh
#read_mem_host :host
#read_mem_snapshot_direct_access   :shm snapshot with direct access
#read_mem_snapshot : shm snapshot with origin LibVMI API
#read_mem : KVM patch with origin LibVMI API


#virsh destroy qcxp
virsh snapshot-revert qcxp qcxp-snapshot2

for chunk_loop_mode in 1 2
do
	for benchmark_program in read_mem_host read_mem_snapshot_direct_access read_mem_snapshot read_mem
	do
		for buf_size in 32768 65536 131072 262144 524288 1048576 2097152 4194304 8388608 16777216 33554432 67108864
		do
			./$benchmark_program qcxp $buf_size 15 1 $chunk_loop_mode
		done
	done
done
