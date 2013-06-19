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
#include "driver/file.h"
#include "driver/interface.h"
#include "driver/memory_cache.h"

#if ENABLE_FILE == 1
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
// File-Specific Interface Functions (no direction mapping to driver_*)

static file_instance_t *
file_get_instance(
    vmi_instance_t vmi)
{
    return ((file_instance_t *) vmi->driver);
}

void *
file_get_memory(
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
                  ((uint8_t *) file_get_instance(vmi)->map) + paddr,
                  length);
#else
    if (paddr != lseek(file_get_instance(vmi)->fd, paddr, SEEK_SET)) {
        goto error_print;
    }
    if (length != read(file_get_instance(vmi)->fd, memory, length)) {
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
file_release_memory(
    void *memory,
    size_t length)
{
    if (memory)
        free(memory);
}

//----------------------------------------------------------------------------
// General Interface Functions (1-1 mapping to driver_* function)

status_t
file_init(
    vmi_instance_t vmi)
{
    FILE *fhandle = NULL;
    int fd = -1;
    file_instance_t *fi = file_get_instance(vmi);

    /* open handle to memory file */
    if ((fhandle = fopen(fi->filename, "rb")) == NULL) {
        errprint("Failed to open file for reading.\n");
        goto fail;
    }
    fd = fileno(fhandle);

    fi->fhandle = fhandle;
    fi->fd = fd;
    memory_cache_init(vmi, file_get_memory, file_release_memory,
                      ULONG_MAX);
    //    memory_cache_init(vmi, file_get_memory, file_release_memory, 0);

#if USE_MMAP
    /* try memory mapped file I/O */
    unsigned long size;

    if (VMI_FAILURE == file_get_memsize(vmi, &size)) {
        goto fail;
    }   // if

    int mmap_flags = (MAP_PRIVATE | MAP_NORESERVE | MAP_POPULATE);

#ifdef MMAP_HUGETLB // since kernel 2.6.32
    mmap_flags |= MMAP_HUGETLB;
#endif // MMAP_HUGETLB

    void *map = mmap(NULL,  // addr
                     size,  // len
                     PROT_READ, // prot
                     mmap_flags,    // flags
                     fd,    // file descriptor
                     (off_t) 0);    // offset

    if (MAP_FAILED == map) {
        perror("Failed to mmap file");
        goto fail;
    }
    fi->map = map;

    // Note: madvise(.., MADV_SEQUENTIAL | MADV_WILLNEED) does not seem to
    // improve performance

#endif // USE_MMAP

    vmi->hvm = 0;
    return VMI_SUCCESS;

fail:
    file_destroy(vmi);
    return VMI_FAILURE;
}

void
file_destroy(
    vmi_instance_t vmi)
{
    file_instance_t *fi = file_get_instance(vmi);

#if USE_MMAP
    if (fi->map) {
        (void) munmap(fi->map, vmi->size);
        fi->map = 0;
    }
#endif // USE_MMAP
    // fi->fhandle refers to fi->fd; closing both would be an error
    if (fi->fhandle) {
        fclose(fi->fhandle);
        fi->fhandle = 0;
        fi->fd = 0;
    }
}

status_t
file_get_name(
    vmi_instance_t vmi,
    char **name)
{
    *name = strdup(file_get_instance(vmi)->filename);
    return VMI_SUCCESS;
}

void
file_set_name(
    vmi_instance_t vmi,
    char *name)
{
    file_get_instance(vmi)->filename = strndup(name, 500);
}

status_t
file_get_memsize(
    vmi_instance_t vmi,
    unsigned long *size)
{
    status_t ret = VMI_FAILURE;
    struct stat s;

    if (fstat(file_get_instance(vmi)->fd, &s) == -1) {
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
	file_instance_t *fileInstance,
    char *query)
{
    FILE *p;
    char *output = safe_malloc(20000);
    size_t length = 0;

    char *name = (char *) fileInstance -> filename;
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
	file_instance_t *fileInstance)
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

status_t
file_get_vcpureg(
    vmi_instance_t vmi,
    reg_t *value,
    registers_t reg,
    unsigned long vcpu)
{

    char *regs = exec_info_registers(file_get_instance(vmi));
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
file_read_page(
    vmi_instance_t vmi,
    addr_t page)
{
    addr_t paddr = page << vmi->page_shift;

    return memory_cache_insert(vmi, paddr);
}

//TODO decide if this functionality makes sense for files
status_t
file_write(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    uint32_t length)
{
    return VMI_FAILURE;
}

int
file_is_pv(
    vmi_instance_t vmi)
{
    return 0;
}

status_t
file_test(
    unsigned long id,
    char *name)
{
    status_t ret = VMI_FAILURE;
    FILE *f = NULL;
    struct stat s;

    if (NULL == name) {
        goto error_exit;
    }
    if ((f = fopen(name, "rb")) == NULL) {
        goto error_exit;
    }
    if (fstat(fileno(f), &s) == -1) {
        goto error_exit;
    }
    if (!s.st_size) {
        goto error_exit;
    }
    ret = VMI_SUCCESS;

error_exit:
    if (f)
        fclose(f);
    return ret;
}

status_t
file_pause_vm(
    vmi_instance_t vmi)
{
    return VMI_SUCCESS;
}

status_t
file_resume_vm(
    vmi_instance_t vmi)
{
    return VMI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////
#else

status_t
file_init(
    vmi_instance_t vmi)
{
    return VMI_FAILURE;
}

void
file_destroy(
    vmi_instance_t vmi)
{
    return;
}

status_t
file_get_name(
    vmi_instance_t vmi,
    char **name)
{
    return VMI_FAILURE;
}

void
file_set_name(
    vmi_instance_t vmi,
    char *name)
{
    return;
}

status_t
file_get_memsize(
    vmi_instance_t vmi,
    unsigned long *size)
{
    return VMI_FAILURE;
}

status_t
file_get_vcpureg(
    vmi_instance_t vmi,
    reg_t *value,
    registers_t reg,
    unsigned long vcpu)
{
    return VMI_FAILURE;
}

void *
file_read_page(
    vmi_instance_t vmi,
    unsigned long page)
{
    return NULL;
}

status_t
file_write(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    uint32_t length)
{
    return VMI_FAILURE;
}

int
file_is_pv(
    vmi_instance_t vmi)
{
    return 0;
}

status_t
file_test(
    unsigned long id,
    char *name)
{
    return VMI_FAILURE;
}

status_t
file_pause_vm(
    vmi_instance_t vmi)
{
    return VMI_FAILURE;
}

status_t
file_resume_vm(
    vmi_instance_t vmi)
{
    return VMI_FAILURE;
}

#endif /* ENABLE_FILE */
