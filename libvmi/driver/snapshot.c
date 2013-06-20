/*
 * snapshot.c
 *
 *  Created on: Jun 19, 2013
 *      Author: root
 */

#include "libvmi.h"
#include "private.h"
#include "driver/snapshot.h"
#include "driver/interface.h"
#include "driver/memory_cache.h"

#define ENABLE_SNAPSHOT 1

#if ENABLE_SNAPSHOT == 1
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

// Use mmap() if this evaluates to true; otherwise, use a file pointer with
// seek/read
#define USE_MMAP 1

// Avoid errors on systems that don't have MAP_POPULATE defined
#ifndef MAP_POPULATE
#define MAP_POPULATE 0
#endif

//----------------------------------------------------------------------------
// Snapshot-Specific Interface Functions (no direction mapping to driver_*)

static snapshot_instance_t *
snapshot_get_instance(
    vmi_instance_t vmi)
{
    return ((snapshot_instance_t *) vmi->driver);
}


void *
snapshot_get_memory(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t length)
{
    void *memory = 0;

    if (paddr + length > vmi->size) { /* LibVMI bug fix: modify comparison operator from ">=" to ">"
                                       so that we can read the last page. -Guanglin */
        dbprint
            ("--%s: request for PA range [0x%.16"PRIx64"-0x%.16"PRIx64"] reads past end of file\n",
             __FUNCTION__, paddr, paddr + length);
        goto error_noprint;
    }   // if

    memory = safe_malloc(length);

#if USE_MMAP
    (void) memcpy(memory,
                  ((uint8_t *) snapshot_get_instance(vmi)->map) + paddr,
                  length);
#else
    if (paddr != lseek(snapshot_get_instance(vmi)->fd, paddr, SEEK_SET)) {
        goto error_print;
    }
    if (length != read(snapshot_get_instance(vmi)->fd, memory, length)) {
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

//----------------------------------------------------------------------------
// General Interface Functions (1-1 mapping to driver_* function)

status_t snapshot_init(
    vmi_instance_t vmi)
{
	return 0;
}

void snapshot_destroy(
    vmi_instance_t vmi)
{
}

status_t snapshot_get_name(
    vmi_instance_t vmi,
    char **name)
{
    *name = strdup(snapshot_get_instance(vmi)->filename);
    return VMI_SUCCESS;
}

void snapshot_set_name(
    vmi_instance_t vmi,
    char *name)
{
	snapshot_get_instance(vmi)->filename = strndup(name, 500);
}

status_t snapshot_get_memsize(
    vmi_instance_t vmi,
    unsigned long *size)
{
    status_t ret = VMI_FAILURE;
    struct stat s;

    if (fstat(snapshot_get_instance(vmi)->fd, &s) == -1) {
        errprint("Failed to stat file.\n");
        goto error_exit;
    }
    *size = (unsigned long) s.st_size;
    ret = VMI_SUCCESS;

error_exit:
    return ret;
}



//----------------------------------------------------------------------------
// Helper functions (from kvm driver) -Guanglin

//
// QMP Command Interactions
static char *
exec_qmp_cmd(
	snapshot_instance_t *snapshotInstance,
    char *query)
{
    FILE *p;
    char *output = safe_malloc(20000);
    size_t length = 0;

    char *name = (char *) snapshotInstance -> filename;
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
	snapshot_instance_t *fileInstance)
{
    char *query =
        "'{\"execute\": \"human-monitor-command\", \"arguments\": {\"command-line\": \"info registers\"}}'";
    return exec_qmp_cmd(fileInstance, query);
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

status_t snapshot_get_vcpureg(
    vmi_instance_t vmi,
    reg_t *value,
    registers_t reg,
    unsigned long vcpu) {


    char *regs = exec_info_registers(snapshot_get_instance(vmi));
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

void *snapshot_read_page(
    vmi_instance_t vmi,
    addr_t page)
{
    addr_t paddr = page << vmi->page_shift;

    return memory_cache_insert(vmi, paddr);
}

status_t snapshot_write(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    uint32_t length)
{
    return VMI_FAILURE;
}

int snapshot_is_pv(
    vmi_instance_t vmi)
{
    return 0;
}

status_t snapshot_test(
    unsigned long id,
    char *name)
{
	return VMI_FAILURE;
}

status_t snapshot_pause_vm(
    vmi_instance_t vmi)
{
    return VMI_SUCCESS;
}

status_t snapshot_resume_vm(
    vmi_instance_t vmi)
{
    return VMI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////
#else
status_t snapshot_init(
    vmi_instance_t vmi)
{
    return VMI_FAILURE;
}

void snapshot_destroy(
    vmi_instance_t vmi)
{
    return;
}

status_t snapshot_get_name(
    vmi_instance_t vmi,
    char **name)
{
    return VMI_FAILURE;
}

void snapshot_set_name(
    vmi_instance_t vmi,
    char *name)
{
    return;
}

status_t snapshot_get_memsize(
    vmi_instance_t vmi,
    unsigned long *size)
{
    return VMI_FAILURE;
}

status_t snapshot_get_vcpureg(
    vmi_instance_t vmi,
    reg_t *value,
    registers_t reg,
    unsigned long vcpu)
{
    return VMI_FAILURE;
}

void *snapshot_read_page(
    vmi_instance_t vmi,
    addr_t page)
{
    return NULL;
}

status_t snapshot_write(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    uint32_t length)
{
    return VMI_FAILURE;
}

int snapshot_is_pv(
    vmi_instance_t vmi)
{
    return 0;
}

status_t snapshot_test(
    unsigned long id,
    char *name)
{
    return VMI_FAILURE;
}

status_t snapshot_pause_vm(
    vmi_instance_t vmi)
{
    return VMI_FAILURE;
}

status_t snapshot_resume_vm(
    vmi_instance_t vmi)
{
    return VMI_FAILURE;
}

#endif /* ENABLE_SNAPSHOT */
