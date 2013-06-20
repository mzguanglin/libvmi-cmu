/*
 * snapshot.h
 *
 *  Created on: Jun 19, 2013
 *      Author: root
 */


#ifndef SNAPSHOT_H_
#define SNAPSHOT_H_


typedef struct snapshot_instance {

    FILE *fhandle;       /**< handle to the snapshot file */

    int fd;              /**< file descriptor to the snapshot file */

    char *filename;      /**< name of the file being accessed */

    void *map;           /**< memory mapped file */

    char *domainName;

    //driver_instance_t kvmInstance;

} snapshot_instance_t;

status_t snapshot_init(
    vmi_instance_t vmi);
void snapshot_destroy(
    vmi_instance_t vmi);
status_t snapshot_get_name(
    vmi_instance_t vmi,
    char **name);
void snapshot_set_name(
    vmi_instance_t vmi,
    char *name);
status_t snapshot_get_memsize(
    vmi_instance_t vmi,
    unsigned long *size);
status_t snapshot_get_vcpureg(
    vmi_instance_t vmi,
    reg_t *value,
    registers_t reg,
    unsigned long vcpu);
void *snapshot_read_page(
    vmi_instance_t vmi,
    addr_t page);
status_t snapshot_write(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    uint32_t length);
int snapshot_is_pv(
    vmi_instance_t vmi);
status_t snapshot_test(
    unsigned long id,
    char *name);
status_t snapshot_pause_vm(
    vmi_instance_t vmi);
status_t snapshot_resume_vm(
    vmi_instance_t vmi);


#endif /* SNAPSHOT_H_ */
