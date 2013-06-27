/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
 *
 * This file is part of LibVMI.
 *
 * LibVMI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * LibVMI is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "libvmi.h"
#include "private.h"
#include "driver/kvm.h"
#include "driver/interface.h"
#include "driver/memory_cache.h"

#if ENABLE_KVM == 1
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <glib.h>
#include <math.h>
#include <glib/gstdio.h>
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>

// request struct matches a definition in qemu source code
struct request {
    uint8_t type;   // 0 quit, 1 read, 2 write, ... rest reserved
    uint64_t address;   // address to read from OR write to
    uint64_t length;    // number of bytes to read OR write
};

//----------------------------------------------------------------------------
// Helper functions

//
// QMP Command Interactions
static char *
exec_qmp_cmd(
    kvm_instance_t *kvm,
    char *query)
{
    FILE *p;
    char *output = safe_malloc(20000);
    size_t length = 0;

    char *name = (char *) virDomainGetName(kvm->dom);
    int cmd_length = strlen(name) + strlen(query) + 29;
    char *cmd = safe_malloc(cmd_length);

    snprintf(cmd, cmd_length, "virsh qemu-monitor-command %s %s", name,
             query);
    dbprint("--qmp: %s\n", cmd);

    p = popen(cmd, "r");
    if (NULL == p) {
        dbprint("--failed to run QMP command\n");
        free(cmd);
        return NULL;
    }

    length = fread(output, 1, 20000, p);
    pclose(p);
    free(cmd);

    if (length == 0) {
        free(output);
        return NULL;
    }
    else {
        return output;
    }
}

static char *
exec_info_registers(
    kvm_instance_t *kvm)
{
    char *query =
        "'{\"execute\": \"human-monitor-command\", \"arguments\": {\"command-line\": \"info registers\"}}'";
    return exec_qmp_cmd(kvm, query);
}

static char *
exec_memory_access(
    kvm_instance_t *kvm)
{
    char *tmpfile = tempnam("/tmp", "vmi");
    char *query = (char *) safe_malloc(256);

    sprintf(query,
            "'{\"execute\": \"pmemaccess\", \"arguments\": {\"path\": \"%s\"}}'",
            tmpfile);
    kvm->ds_path = strdup(tmpfile);
    free(tmpfile);

    char *output = exec_qmp_cmd(kvm, query);

    free(query);
    return output;
}

static char *
exec_xp(
    kvm_instance_t *kvm,
    int numwords,
    addr_t paddr)
{
    char *query = (char *) safe_malloc(256);

    sprintf(query,
            "'{\"execute\": \"human-monitor-command\", \"arguments\": {\"command-line\": \"xp /%dwx 0x%x\"}}'",
            numwords, paddr);

    char *output = exec_qmp_cmd(kvm, query);

    free(query);
    return output;
}

static reg_t
parse_reg_value(
    char *regname,
    char *ir_output)
{
    if (NULL == ir_output || NULL == regname) {
        return 0;
    }

    char *ptr = strcasestr(ir_output, regname);

    if (NULL != ptr) {
        ptr += strlen(regname) + 1;
        return (reg_t) strtoll(ptr, (char **) NULL, 16);
    }
    else {
        return 0;
    }
}

status_t
exec_memory_access_success(
    char *status)
{
    if (NULL == status) {
        return VMI_FAILURE;
    }

    char *ptr = strcasestr(status, "CommandNotFound");

    if (NULL == ptr) {
        return VMI_SUCCESS;
    }
    else {
        return VMI_FAILURE;
    }
}

//
// Domain socket interactions (for memory access from KVM-QEMU)
static status_t
init_domain_socket(
    kvm_instance_t *kvm)
{
    struct sockaddr_un address;
    int socket_fd;
    size_t address_length;

    socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        dbprint("--socket() failed\n");
        return VMI_FAILURE;
    }

    address.sun_family = AF_UNIX;
    address_length =
        sizeof(address.sun_family) + sprintf(address.sun_path, "%s",
                                             kvm->ds_path);

    if (connect(socket_fd, (struct sockaddr *) &address, address_length)
        != 0) {
        dbprint("--connect() failed to %s\n", kvm->ds_path);
        return VMI_FAILURE;
    }

    kvm->socket_fd = socket_fd;
    return VMI_SUCCESS;
}

static void
destroy_domain_socket(
    kvm_instance_t *kvm)
{
    if (kvm->socket_fd) {
        struct request req;

        req.type = 0;   // quit
        req.address = 0;
        req.length = 0;
        write(kvm->socket_fd, &req, sizeof(struct request));
    }
}

//----------------------------------------------------------------------------
// KVM-Specific Interface Functions (no direction mapping to driver_*)

static kvm_instance_t *
kvm_get_instance(
    vmi_instance_t vmi)
{
    return ((kvm_instance_t *) vmi->driver);
}

void *
kvm_get_memory_patch(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t length)
{
    char *buf = safe_malloc(length + 1);
    struct request req;

    req.type = 1;   // read request
    req.address = (uint64_t) paddr;
    req.length = (uint64_t) length;

    int nbytes =
        write(kvm_get_instance(vmi)->socket_fd, &req,
              sizeof(struct request));
    if (nbytes != sizeof(struct request)) {
        goto error_exit;
    }
    else {
        // get the data from kvm
        nbytes =
            read(kvm_get_instance(vmi)->socket_fd, buf, length + 1);
        if (nbytes != (length + 1)) {
            goto error_exit;
        }

        // check that kvm thinks everything is ok by looking at the last byte
        // of the buffer, 0 is failure and 1 is success
        if (buf[length]) {
            // success, return pointer to buf
            return buf;
        }
    }

    // default failure
error_exit:
    if (buf)
        free(buf);
    return NULL;
}

void *
kvm_get_memory_native(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t length)
{
    int numwords = ceil(length / 4);
    char *buf = safe_malloc(numwords * 4);
    char *bufstr = exec_xp(kvm_get_instance(vmi), numwords, paddr);

    char *paddrstr = safe_malloc(32);

    sprintf(paddrstr, "%.16x", paddr);

    char *ptr = strcasestr(bufstr, paddrstr);
    int i = 0, j = 0;

    while (i < numwords && NULL != ptr) {
        ptr += strlen(paddrstr) + 2;

        for (j = 0; j < 4; ++j) {
            uint32_t value = strtol(ptr, (char **) NULL, 16);

            memcpy(buf + i * 4, &value, 4);
            ptr += 11;
            i++;
        }

        sprintf(paddrstr, "%.16x", paddr + i * 4);
        ptr = strcasestr(ptr, paddrstr);
    }
    if (bufstr)
        free(bufstr);
    if (paddrstr)
        free(paddrstr);
    return buf;
}


void *
kvm_snapshot_get_memory(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t length)
{
    void *memory = 0;

    if (paddr + length > vmi->size) { /* LibVMI bug fix: modify comparison operator from ">=" to ">"
                                       so that we can read the last page. -Guanglin */
        dbprint
            ("--%s: request for PA range [0x%.16"PRIx64"-0x%.16"PRIx64"] reads past end of pmemsave file\n",
             __FUNCTION__, paddr, paddr + length);
        goto error_noprint;
    }   // if

    memory = safe_malloc(length);

#if USE_MMAP
    (void) memcpy(memory,
                  ((uint8_t *) file_get_instance(vmi)->map) + paddr,
                  length);
#else
    if (paddr != lseek(kvm_get_instance(vmi)->fd, paddr, SEEK_SET)) {
        goto error_print;
    }
    if (length != read(kvm_get_instance(vmi)->fd, memory, length)) {
        goto error_print;
    }
#endif // USE_MMAP

    return memory;

error_print:
    dbprint("%s: failed to read %d bytes at "
            "PA (offset) 0x%.16"PRIx64" [VM size 0x%.16"PRIx64"]\n", __FUNCTION__,
            length, paddr, vmi->size);
error_noprint:
    if (memory)
        free(memory);
    return NULL;
}

void
kvm_release_memory(
    void *memory,
    size_t length)
{
    if (memory)
        free(memory);
}

status_t
kvm_put_memory(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t length,
    void *buf)
{
    struct request req;

    req.type = 2;   // write request
    req.address = (uint64_t) paddr;
    req.length = (uint64_t) length;

    int nbytes =
        write(kvm_get_instance(vmi)->socket_fd, &req,
              sizeof(struct request));
    if (nbytes != sizeof(struct request)) {
        goto error_exit;
    }
    else {
        uint8_t status = 0;

        write(kvm_get_instance(vmi)->socket_fd, buf, length);
        read(kvm_get_instance(vmi)->socket_fd, &status, 1);
        if (0 == status) {
            goto error_exit;
        }
    }

    return VMI_SUCCESS;
error_exit:
    return VMI_FAILURE;
}

//----------------------------------------------------------------------------
// General Interface Functions (1-1 mapping to driver_* function)

status_t
kvm_init(
    vmi_instance_t vmi)
{
    virConnectPtr conn = NULL;
    virDomainPtr dom = NULL;
    virDomainInfo info;

    conn =
        virConnectOpenAuth("qemu:///system", virConnectAuthPtrDefault,
                           0);
    if (NULL == conn) {
        dbprint("--no connection to kvm hypervisor\n");
        return VMI_FAILURE;
    }

    dom = virDomainLookupByID(conn, kvm_get_instance(vmi)->id);
    if (NULL == dom) {
        dbprint("--failed to find kvm domain\n");
        return VMI_FAILURE;
    }

    // get the libvirt version
    unsigned long libVer = 0;

    if (virConnectGetLibVersion(conn, &libVer) != 0) {
        dbprint("--failed to get libvirt version\n");
        return VMI_FAILURE;
    }
    dbprint("--libvirt version %lu\n", libVer);

    kvm_get_instance(vmi)->conn = conn;
    kvm_get_instance(vmi)->dom = dom;
    kvm_get_instance(vmi)->socket_fd = 0;

    kvm_get_instance(vmi)->fd = 0;
    kvm_get_instance(vmi)->filename = NULL;
    kvm_get_instance(vmi)->map = NULL;
    kvm_get_instance(vmi)->cpuRegisterFilePath = NULL;
    kvm_get_instance(vmi)->cpuRegistersStr = NULL;

    vmi->hvm = 1;

    //get the VCPU count from virDomainInfo structure
    if (-1 == virDomainGetInfo(kvm_get_instance(vmi)->dom, &info)) {
        dbprint("--failed to get vm info\n");
        return VMI_FAILURE;
    }
    vmi->num_vcpus = info.nrVirtCpu;

    char *status = exec_memory_access(kvm_get_instance(vmi));

    if (VMI_SUCCESS == exec_memory_access_success(status)) {
        printf("--kvm: using custom patch for fast memory access\n");
        memory_cache_init(vmi, kvm_get_memory_patch, kvm_release_memory,
                          1);
        if (status)
            free(status);
        return init_domain_socket(kvm_get_instance(vmi));
    }
    else {
        printf
            ("--kvm: didn't find patch, falling back to slower native access\n");
        memory_cache_init(vmi, kvm_get_memory_native,
                          kvm_release_memory, 1);
        if (status)
            free(status);
        return VMI_SUCCESS;
    }
}

void
kvm_destroy(
    vmi_instance_t vmi)
{
    destroy_domain_socket(kvm_get_instance(vmi));

    if (kvm_get_instance(vmi)->dom) {
        virDomainFree(kvm_get_instance(vmi)->dom);
    }
    if (kvm_get_instance(vmi)->conn) {
        virConnectClose(kvm_get_instance(vmi)->conn);
    }
}

unsigned long
kvm_get_id_from_name(
    vmi_instance_t vmi,
    char *name)
{
    virConnectPtr conn = NULL;
    virDomainPtr dom = NULL;
    unsigned long id;

    conn =
        virConnectOpenAuth("qemu:///system", virConnectAuthPtrDefault,
                           0);
    if (NULL == conn) {
        dbprint("--no connection to kvm hypervisor\n");
        return -1;
    }

    dom = virDomainLookupByName(conn, name);
    if (NULL == dom) {
        dbprint("--failed to find kvm domain\n");
        return -1;
    }

    id = (unsigned long) virDomainGetID(dom);

    if (dom)
        virDomainFree(dom);
    if (conn)
        virConnectClose(conn);

    return id;
}

status_t
kvm_get_name_from_id(
    vmi_instance_t vmi,
    unsigned long domid,
    char **name)
{
    virConnectPtr conn = NULL;
    virDomainPtr dom = NULL;

    conn =
        virConnectOpenAuth("qemu:///system", virConnectAuthPtrDefault,
                           0);
    if (NULL == conn) {
        dbprint("--no connection to kvm hypervisor\n");
        return VMI_FAILURE;
    }

    dom = virDomainLookupByID(conn, domid);
    if (NULL == dom) {
        dbprint("--failed to find kvm domain\n");
        return VMI_FAILURE;
    }

    *name = virDomainGetName(dom);

    if (dom)
        virDomainFree(dom);
    if (conn)
        virConnectClose(conn);

    return VMI_SUCCESS;
}

unsigned long
kvm_get_id(
    vmi_instance_t vmi)
{
    return kvm_get_instance(vmi)->id;
}

void
kvm_set_id(
    vmi_instance_t vmi,
    unsigned long id)
{
    kvm_get_instance(vmi)->id = id;
}

status_t
kvm_check_id(
    vmi_instance_t vmi,
    unsigned long id)
{
    virConnectPtr conn = NULL;
    virDomainPtr dom = NULL;

    conn =
        virConnectOpenAuth("qemu:///system", virConnectAuthPtrDefault,
                           0);
    if (NULL == conn) {
        dbprint("--no connection to kvm hypervisor\n");
        return VMI_FAILURE;
    }

    dom = virDomainLookupByID(conn, id);
    if (NULL == dom) {
        dbprint("--failed to find kvm domain\n");
        return VMI_FAILURE;
    }

    if (dom)
        virDomainFree(dom);
    if (conn)
        virConnectClose(conn);

    return VMI_SUCCESS;
}

status_t
kvm_get_name(
    vmi_instance_t vmi,
    char **name)
{
    const char *tmpname = virDomainGetName(kvm_get_instance(vmi)->dom);

    // don't need to deallocate the name, it will go away with the domain object

    if (NULL != tmpname) {
        *name = strdup(tmpname);
        return VMI_SUCCESS;
    }
    else {
        return VMI_FAILURE;
    }
}

void
kvm_set_name(
    vmi_instance_t vmi,
    char *name)
{
    kvm_get_instance(vmi)->name = strndup(name, 500);
}

status_t
kvm_get_memsize(
    vmi_instance_t vmi,
    unsigned long *size)
{
    virDomainInfo info;

    if (-1 == virDomainGetInfo(kvm_get_instance(vmi)->dom, &info)) {
        dbprint("--failed to get vm info\n");
        goto error_exit;
    }
    *size = info.maxMem * 1024; // convert KBytes to bytes

    return VMI_SUCCESS;
error_exit:
    return VMI_FAILURE;
}

status_t
kvm_get_vcpureg(
    vmi_instance_t vmi,
    reg_t *value,
    registers_t reg,
    unsigned long vcpu)
{
	char *regs = NULL;

	// if we have loaded cpu register values from file, then read from the loaded string.
	kvm_instance_t *ki = kvm_get_instance(vmi);
	if (ki->cpuRegistersStr != NULL) {
		regs = strdup(ki->cpuRegistersStr);
		dbprint("read cpu regs from %s\n", ki->cpuRegisterFilePath);
	}
	else
		regs = exec_info_registers(kvm_get_instance(vmi));


    status_t ret = VMI_SUCCESS;

    if (VMI_PM_IA32E == vmi->page_mode) {
        switch (reg) {
        case RAX:
            *value = parse_reg_value("RAX", regs);
            break;
        case RBX:
            *value = parse_reg_value("RBX", regs);
            break;
        case RCX:
            *value = parse_reg_value("RCX", regs);
            break;
        case RDX:
            *value = parse_reg_value("RDX", regs);
            break;
        case RBP:
            *value = parse_reg_value("RBP", regs);
            break;
        case RSI:
            *value = parse_reg_value("RSI", regs);
            break;
        case RDI:
            *value = parse_reg_value("RDI", regs);
            break;
        case RSP:
            *value = parse_reg_value("RSP", regs);
            break;
        case R8:
            *value = parse_reg_value("R8", regs);
            break;
        case R9:
            *value = parse_reg_value("R9", regs);
            break;
        case R10:
            *value = parse_reg_value("R10", regs);
            break;
        case R11:
            *value = parse_reg_value("R11", regs);
            break;
        case R12:
            *value = parse_reg_value("R12", regs);
            break;
        case R13:
            *value = parse_reg_value("R13", regs);
            break;
        case R14:
            *value = parse_reg_value("R14", regs);
            break;
        case R15:
            *value = parse_reg_value("R15", regs);
            break;
        case RIP:
            *value = parse_reg_value("RIP", regs);
            break;
        case RFLAGS:
            *value = parse_reg_value("RFL", regs);
            break;
        case CR0:
            *value = parse_reg_value("CR0", regs);
            break;
        case CR2:
            *value = parse_reg_value("CR2", regs);
            break;
        case CR3:
            *value = parse_reg_value("CR3", regs);
            break;
        case CR4:
            *value = parse_reg_value("CR4", regs);
            break;
        case DR0:
            *value = parse_reg_value("DR0", regs);
            break;
        case DR1:
            *value = parse_reg_value("DR1", regs);
            break;
        case DR2:
            *value = parse_reg_value("DR2", regs);
            break;
        case DR3:
            *value = parse_reg_value("DR3", regs);
            break;
        case DR6:
            *value = parse_reg_value("DR6", regs);
            break;
        case DR7:
            *value = parse_reg_value("DR7", regs);
            break;
        case MSR_EFER:
            *value = parse_reg_value("EFER", regs);
            break;
        default:
            ret = VMI_FAILURE;
            break;
        }
    }
    else {
        switch (reg) {
        case RAX:
            *value = parse_reg_value("EAX", regs);
            break;
        case RBX:
            *value = parse_reg_value("EBX", regs);
            break;
        case RCX:
            *value = parse_reg_value("ECX", regs);
            break;
        case RDX:
            *value = parse_reg_value("EDX", regs);
            break;
        case RBP:
            *value = parse_reg_value("EBP", regs);
            break;
        case RSI:
            *value = parse_reg_value("ESI", regs);
            break;
        case RDI:
            *value = parse_reg_value("EDI", regs);
            break;
        case RSP:
            *value = parse_reg_value("ESP", regs);
            break;
        case RIP:
            *value = parse_reg_value("EIP", regs);
            break;
        case RFLAGS:
            *value = parse_reg_value("EFL", regs);
            break;
        case CR0:
            *value = parse_reg_value("CR0", regs);
            break;
        case CR2:
            *value = parse_reg_value("CR2", regs);
            break;
        case CR3:
            *value = parse_reg_value("CR3", regs);
            break;
        case CR4:
            *value = parse_reg_value("CR4", regs);
            break;
        case DR0:
            *value = parse_reg_value("DR0", regs);
            break;
        case DR1:
            *value = parse_reg_value("DR1", regs);
            break;
        case DR2:
            *value = parse_reg_value("DR2", regs);
            break;
        case DR3:
            *value = parse_reg_value("DR3", regs);
            break;
        case DR6:
            *value = parse_reg_value("DR6", regs);
            break;
        case DR7:
            *value = parse_reg_value("DR7", regs);
            break;
        case MSR_EFER:
            *value = parse_reg_value("EFER", regs);
            break;
        default:
            ret = VMI_FAILURE;
            break;
        }
    }

    if (regs)
        free(regs);
    return ret;
}

void *
kvm_read_page(
    vmi_instance_t vmi,
    addr_t page)
{
    addr_t paddr = page << vmi->page_shift;

    return memory_cache_insert(vmi, paddr);
}

status_t
kvm_write(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    uint32_t length)
{
    return kvm_put_memory(vmi, paddr, length, buf);
}

int
kvm_is_pv(
    vmi_instance_t vmi)
{
    return 0;
}

status_t
kvm_test(
    unsigned long id,
    char *name)
{
    virConnectPtr conn = NULL;
    virDomainPtr dom = NULL;

    conn =
        virConnectOpenAuth("qemu:///system", virConnectAuthPtrDefault,
                           0);
    if (NULL == conn) {
        dbprint("--no connection to kvm hypervisor\n");
        return VMI_FAILURE;
    }

    if (conn)
        virConnectClose(conn);
    return VMI_SUCCESS;
}

status_t
kvm_pause_vm(
    vmi_instance_t vmi)
{
    if (-1 == virDomainSuspend(kvm_get_instance(vmi)->dom)) {
        return VMI_FAILURE;
    }
    return VMI_SUCCESS;
}

status_t
kvm_resume_vm(
    vmi_instance_t vmi)
{
    if (-1 == virDomainResume(kvm_get_instance(vmi)->dom)) {
        return VMI_FAILURE;
    }
    return VMI_SUCCESS;
}


#define MEASUREMENT

#ifdef MEASUREMENT
void print_measurement(struct timeval ktv_start, struct timeval ktv_end,
		long int *diff) {

	*diff =

	(((long int) ktv_end.tv_usec - (long int) ktv_start.tv_usec)
			+

			(((long int) ktv_end.tv_sec % 1000000
					- (long int) ktv_start.tv_sec % 1000000) * 1000000));

	printf("%ld.%.6ld : %ld.%.6ld : %ld\n",

	((long int) ktv_start.tv_sec) % 1000000, (long int) ktv_start.tv_usec,

	((long int) ktv_end.tv_sec) % 1000000, (long int) ktv_end.tv_usec, *diff);

}

#endif

static char *
exec_pmemsave(
	    kvm_instance_t* ki, unsigned long memSize)
{

    char *query = (char *) safe_malloc(512);

    sprintf(query, "'{\"execute\": \"pmemsave\", \"arguments\": {\"val\": 0,"
    		" \"size\": %ld, \"filename\": \"%s\"}}'", memSize,
    		ki->filename);

    char *output = exec_qmp_cmd(ki, query);

    free(query);
    return output;
}

static status_t
exec_pmemsave_success(
		char* status)
{
	// TODO:
	/* verify pmemsave operation
	    valid: libvirt (git master) {"return":{},"id":"libvirt-356"}
	    invalid: libvirt-bin (ubuntu 12.04 apt-get) need to collect return value.
	*/

	if (NULL == status) {
        return VMI_FAILURE;
    }

    char *ptr = strcasestr(status, "CommandNotFound");

	free(status);

    if (NULL == ptr) {
        return VMI_SUCCESS;
    }
    else {
        return VMI_FAILURE;
    }
}

static status_t
mmap_snapshot_dev(
	    vmi_instance_t vmi, uint64_t memSize)
{

    kvm_instance_t *ki = kvm_get_instance(vmi);

#define USE_MMAP 1

    int shmSnapFd = NULL;

    char devName[256] = "/";  // or "\" ?
    strcat(devName, (char *) virDomainGetName(ki->dom));

    if ((shmSnapFd = shm_open(devName, O_RDONLY, NULL)) < 0) {
    	errprint("fail in shm_open %s", devName);
    	goto fail;
    }
    ki->fd = shmSnapFd;

    ftruncate(shmSnapFd, memSize);

    // reset memory cache.
   memory_cache_destroy(vmi);
   memory_cache_init(vmi, kvm_snapshot_get_memory, kvm_release_memory,
                      ULONG_MAX);

#if USE_MMAP
    /* try memory mapped file I/O */


    int mmap_flags = (MAP_PRIVATE | MAP_NORESERVE | MAP_POPULATE);

#ifdef MMAP_HUGETLB // since kernel 2.6.32
    mmap_flags |= MMAP_HUGETLB;
#endif // MMAP_HUGETLB

#ifdef MEASUREMENT
	struct timeval ktv_start;
	struct timeval ktv_end;
	long int diff;

	gettimeofday(&ktv_start, 0);
#endif

    void *map = mmap(NULL,  // addr
                     memSize,  // len
                     PROT_READ, // prot
                     mmap_flags,    // flags
                     ki->fd,    // file descriptor
                     (off_t) 0);    // offset

    if (MAP_FAILED == map) {
        perror("Failed to mmap snapshot dev");
        goto fail;
    }

#ifdef MEASUREMENT

	gettimeofday(&ktv_end, 0);

	print_measurement(ktv_start, ktv_end, &diff);

	printf("mmap measurement: %ld\n", diff);

#endif

    ki->map = map;

    // Note: madvise(.., MADV_SEQUENTIAL | MADV_WILLNEED) does not seem to
    // improve performance

#endif // USE_MMAP

    vmi->hvm = 0;
    return VMI_SUCCESS;

fail:
    kvm_destroy_snapshot_vm(vmi);
    return VMI_FAILURE;
}

static status_t
munmap_snapshot_dev(
	    vmi_instance_t vmi, uint64_t memSize)
{
    kvm_instance_t *kvm = kvm_get_instance(vmi);

#if USE_MMAP
    if (kvm->map) {
        (void) munmap(kvm->map, memSize);
        kvm->map = 0;
    }
#endif // USE_MMAP

    if (kvm->fd) {
    	shm_unlink(kvm->snapshotShmDevPath);
        kvm->fd = 0;
    }

    return VMI_SUCCESS;
}



static char *
exec_peter_kvm_snapshot_shm(
	    kvm_instance_t *kvm, uint64_t memSize, char* fileName)
{
    char *query = (char *) safe_malloc(512);

    sprintf(query, "'{\"execute\": \"snapshot\", \"arguments\": {"
    		" \"size\": %ld, \"filename\": \"/%s\"}}'", memSize,
    		fileName);

#ifdef MEASUREMENT
	struct timeval ktv_start;
	struct timeval ktv_end;
	long int diff;

	gettimeofday(&ktv_start, 0);
#endif
    char *output = exec_qmp_cmd(kvm, query);

#ifdef MEASUREMENT

	gettimeofday(&ktv_end, 0);

	print_measurement(ktv_start, ktv_end, &diff);

	printf("qmp measurement: %ld\n", diff);

#endif

    free(query);
    return output;

}

static status_t
exec_peter_kvm_snapshot_shm_success(
		char* status)
{
	// TODO:
	/* verify snapshot operation
	    valid:
	    invalid:
	*/

	if (NULL == status) {
        return VMI_FAILURE;
    }

    char *ptr = strcasestr(status, "CommandNotFound");

	free(status);

    if (NULL == ptr) {
        return VMI_SUCCESS;
    }
    else {
        return VMI_FAILURE;
    }
}

void setup_snapshot_path(kvm_instance_t* kvm)
{
    char tmpPath[256] = "";

	// 1. shm dev path
	tmpPath[0] = '\0';
	strcat(tmpPath, "/");
    strcat(tmpPath, (char *) virDomainGetName(kvm->dom));
	if (kvm->snapshotShmDevPath) free (kvm->snapshotShmDevPath);
	kvm->snapshotShmDevPath = strdup(tmpPath);

	// 2. cpu register file path;
	tmpPath[0] = '\0';
	strcat(tmpPath, "/tmp/");
	strcat(tmpPath, (char*)virDomainGetName(kvm->dom));
	strcat(tmpPath, ".cpu");
	if (kvm->cpuRegisterFilePath) free(kvm->cpuRegisterFilePath);
	kvm->cpuRegisterFilePath = strdup(tmpPath);
}

void teardown_snapshot_path(kvm_instance_t* ki) {

	// 1. shm dev path
	if (ki->snapshotShmDevPath) {
		free(ki->snapshotShmDevPath);
		ki->snapshotShmDevPath = NULL;
	}

	// 2. cpu register file path;
    if (ki->cpuRegisterFilePath) {
   	 free(ki->cpuRegisterFilePath);
   	 ki->cpuRegisterFilePath = NULL;
    }

    if (ki->cpuRegistersStr) {
   	 free(ki->cpuRegistersStr);
   	 ki->cpuRegistersStr = NULL;
    }
}


status_t
kvm_snapshot_vm(
    vmi_instance_t vmi)
{
    printf("snapshot vm\n");

	kvm_instance_t *kvm = kvm_get_instance(vmi);

	setup_snapshot_path(kvm);

	// 1. pause vm;
	if (VMI_FAILURE == vmi_pause_vm(vmi)) {
		warnprint("fail to pause VM before snapshot, may cause inconsistant state\n");
	}

    // 2. create peter's qemu shm dev
    printf("start create peterSnapshot dev\n");
	char *peterSnapshot =  exec_peter_kvm_snapshot_shm(kvm, vmi->size, kvm->snapshotShmDevPath);
	if (VMI_FAILURE == exec_peter_kvm_snapshot_shm_success(peterSnapshot)) {
		errprint("fail to execute qmp snapshot command \n");
		goto fail;
	}
    printf("finish create peterSnapshot dev\n");

    // 3. dump cpu registers;
	char* cpuregs = exec_info_registers(kvm);
    FILE *fhandle = NULL;
    if ((fhandle = fopen(kvm->cpuRegisterFilePath, "w+")) == NULL) {
        errprint("Failed to open %s file for writing., errno = %d\n", kvm->cpuRegisterFilePath, errno);
        goto fail;
    }
    uint32_t cpuRegStrLen = strlen(cpuregs);
    size_t writeCount = fwrite(&cpuRegStrLen, sizeof(uint32_t), 1, fhandle);
    size_t strWriteCount = fwrite(cpuregs, sizeof(char), cpuRegStrLen, fhandle);
    fclose(fhandle);
    free(cpuregs);
    cpuregs = NULL;

	// 4. resume vm;
	if (VMI_FAILURE == vmi_resume_vm(vmi)) {
		warnprint("fail to resume VM after snapshot\n");
        goto fail;
	}

    //  5. mmap
    printf("start mmapping snapshot dev\n");
	if (VMI_FAILURE == mmap_snapshot_dev(vmi, vmi->size)) {
        errprint("Failed to mmap snapshot dev\n");
        goto fail;
	}
    printf("finish mmapping snapshot dev\n");

    //  6. load cpu regs from file;
    if ((fhandle = fopen(kvm->cpuRegisterFilePath, "r")) == NULL) {
        errprint("Failed to open %s for reading., errno = %d\n", kvm->cpuRegisterFilePath,  errno);
        goto fail;
    }
    size_t readCount = fread(&cpuRegStrLen, sizeof(uint32_t), 1, fhandle);
    cpuregs = safe_malloc(cpuRegStrLen);
    size_t strReadCount = fread(cpuregs, sizeof(char), cpuRegStrLen, fhandle);
	kvm->cpuRegistersStr = cpuregs;
    fclose(fhandle);

    return VMI_SUCCESS;

    fail:
    //TODO: clean up codes.
    kvm_destroy_snapshot_vm(vmi);
    return VMI_FAILURE;
}

status_t
kvm_destroy_snapshot_vm(
    vmi_instance_t vmi)
{

    printf("destroy snapshot\n");

    kvm_instance_t *ki = kvm_get_instance(vmi);

	// 1. reset cache subsystem
    memory_cache_destroy(vmi);

    char *status = exec_memory_access(kvm_get_instance(vmi));

     if (VMI_SUCCESS == exec_memory_access_success(status)) {
         printf("--kvm: using custom patch for fast memory access\n");
         memory_cache_init(vmi, kvm_get_memory_patch, kvm_release_memory,
                           1);
         if (status)
             free(status);
     }
     else {
         printf
             ("--kvm: didn't find patch, falling back to slower native access\n");
         memory_cache_init(vmi, kvm_get_memory_native,
                           kvm_release_memory, 1);
         if (status)
             free(status);
     }

     // 2. munmap and unlink dev;
     munmap_snapshot_dev(vmi, vmi->size);

     // 3. delete cpu regs file;
     if (remove(ki->cpuRegisterFilePath))
    	 warnprint("fail to delete %s\n", ki->cpuRegisterFilePath);

     teardown_snapshot_path(ki);

     return VMI_SUCCESS;

     fail:
     //TODO: clean up codes.
     return VMI_FAILURE;

}


//////////////////////////////////////////////////////////////////////
#else

status_t
kvm_init(
    vmi_instance_t vmi)
{
    return VMI_FAILURE;
}

void
kvm_destroy(
    vmi_instance_t vmi)
{
    return;
}

unsigned long
kvm_get_id_from_name(
    vmi_instance_t vmi,
    char *name)
{
    return 0;
}

status_t
kvm_get_name_from_id(
    vmi_instance_t vmi,
    unsigned long domid,
    char **name)
{
    return VMI_FAILURE;
}

unsigned long
kvm_get_id(
    vmi_instance_t vmi)
{
    return 0;
}

void
kvm_set_id(
    vmi_instance_t vmi,
    unsigned long id)
{
    return;
}

status_t
kvm_check_id(
    vmi_instance_t vmi,
    unsigned long id)
{
    return VMI_FAILURE;
}

status_t
kvm_get_name(
    vmi_instance_t vmi,
    char **name)
{
    return VMI_FAILURE;
}

void
kvm_set_name(
    vmi_instance_t vmi,
    char *name)
{
    return;
}

status_t
kvm_get_memsize(
    vmi_instance_t vmi,
    unsigned long *size)
{
    return VMI_FAILURE;
}

status_t
kvm_get_vcpureg(
    vmi_instance_t vmi,
    reg_t *value,
    registers_t reg,
    unsigned long vcpu)
{
    return VMI_FAILURE;
}

void *
kvm_read_page(
    vmi_instance_t vmi,
    addr_t page)
{
    return NULL;
}

status_t
kvm_write(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    uint32_t length)
{
    return VMI_FAILURE;
}

int
kvm_is_pv(
    vmi_instance_t vmi)
{
    return 0;
}

status_t
kvm_test(
    unsigned long id,
    char *name)
{
    return VMI_FAILURE;
}

status_t
kvm_pause_vm(
    vmi_instance_t vmi)
{
    return VMI_FAILURE;
}

status_t
kvm_resume_vm(
    vmi_instance_t vmi)
{
    return VMI_FAILURE;
}

status_t kvm_snapshot_vm(
    vmi_instance_t vmi)
{
    return VMI_FAILURE;
}

status_t kvm_destroy_snapshot_vm(
    vmi_instance_t vmi)
{
    return VMI_FAILURE;
}

#endif /* ENABLE_KVM */
