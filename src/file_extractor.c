#include <error.h>
#include <stdio.h>
#include <glib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <parted/parted.h>

#define __USE_BSD
#include <dirent.h>

#include "structures.h"
#include "vmi.h"
#include "win-handles.h"
#include "md5.h"

#define PATH_PREPEND "/dev/mapper"
#define TMP          "/tmp"

// From FILE_INFORMATION_CLASS
#define FILE_DISPOSITION_INFORMATION 13

char *str_replace(const char *str, const char *old, const char *new)
{
    char *ret, *r;
    const char *p, *q;
    size_t oldlen = strlen(old);
    size_t count, retlen, newlen = strlen(new);

    if (oldlen != newlen) {
        for (count = 0, p = str; (q = strstr(p, old)) != NULL; p = q + oldlen)
            count++;
        /* this is undefined if p - str > PTRDIFF_MAX */
        retlen = p - str + strlen(p) + count * (newlen - oldlen);
    } else
        retlen = strlen(str);

    if ((ret = malloc(retlen + 1)) == NULL)
        return NULL;

    for (r = ret, p = str; (q = strstr(p, old)) != NULL; p = q + oldlen) {
        /* this is undefined if q - p > PTRDIFF_MAX */
        ptrdiff_t l = q - p;
        memcpy(r, p, l);
        r += l;
        memcpy(r, new, newlen);
        r += newlen;
    }
    strcpy(r, p);

    return ret;
}

gboolean get_file(const char *file, gpointer x, honeymon_clone_t *clone) {

    char *tmp1 = str_replace(file, "\\", "/");
    char *file_path = g_malloc0(snprintf(NULL, 0, "%s/%s/%s", TMP, clone->clone_name, tmp1) + 1);
    sprintf(file_path, "%s/%s/%s", TMP, clone->clone_name, tmp1);

    struct stat s;
    if( stat(file_path,&s) == 0)
    {
        if( s.st_mode & S_IFREG )
        {
            unsigned char *md5 = md5_sum(file_path);
            if(md5) {
                if(!g_tree_lookup(clone->origin->fschecksum, md5)) {
                    printf("Getting file '%s'\n", file_path);
                }

                /*int i;
                for(i=0;i<MD5_DIGEST_LENGTH;i++)
                    printf("%.2x", md5[i]);*/

                free(md5);
            }

            vmi_pause_vm(clone->vmi);
        }
    }

    free(tmp1);
    free(file_path);
    return FALSE;
}

void extract_file (honeymon_clone_t * clone, const char *filename, GTree *files)
{

    PedDevice* device;
    PedDiskType* type;
    PedDisk* disk;
    PedPartition* part;
    char *command = NULL;

    char *tmp = g_malloc0(snprintf(NULL, 0, "%s/%s", TMP, clone->clone_name) + 1);
    sprintf(tmp, "%s/%s", TMP, clone->clone_name);

    char* lv_name = str_replace(clone->clone_name, "-", "--");

    char* path=g_malloc0(snprintf(NULL, 0, "%s/%s-%s", PATH_PREPEND, clone->origin->vg_name, lv_name) + 1);
    sprintf(path, "%s/%s-%s", PATH_PREPEND, clone->origin->vg_name, lv_name);
    printf("Clone LV Path: %s\n", path);

    device = ped_device_get (path);

    if (device == NULL) goto error;

    type = ped_disk_probe (device);
    if (type == NULL) goto error_destroy_device;

    disk = ped_disk_new (device);
    if (disk == NULL) goto error_destroy_disk;

    command = g_malloc0(snprintf(NULL, 0, "%s -r -s -a %s", KPARTX, path) + 1);
    sprintf(command, "%s -r -s -a %s", KPARTX, path);
    printf("** RUNNING COMMAND: %s\n", command);
    g_spawn_command_line_sync(command, NULL, NULL, NULL, NULL);
    free(command);

    mkdir(tmp, S_IRWXU|S_IRGRP|S_IXGRP);

    for (part = ped_disk_next_partition (disk, NULL); part; part = ped_disk_next_partition (disk, part)) {
        if (part->num < 0) continue;

        printf("Partition: %u. Type: %s\n", part->num, (part->fs_type) ? part->fs_type->name : "");

                command = g_malloc0(snprintf(NULL, 0, "%s %sp%u %s", MOUNT, path, part->num, tmp) + 1);
                sprintf(command, "%s %sp%u %s", MOUNT, path, part->num, tmp);
                printf("** RUNNING COMMAND: %s\n", command);
                g_spawn_command_line_sync(command, NULL, NULL, NULL, NULL);
                free(command);

                if(filename) {
                    get_file(filename, NULL, clone);
                } else {
                    g_tree_foreach(files, (GTraverseFunc)get_file, clone);
                }

                command = g_malloc0(snprintf(NULL, 0, "%s %s", UMOUNT, tmp) + 1);
                sprintf(command, "%s %s", UMOUNT, tmp);
                printf("** RUNNING COMMAND: %s\n", command);
                g_spawn_command_line_sync(command, NULL, NULL, NULL, NULL);
                free(command);
    }

    rmdir(tmp);

    command = g_malloc0(snprintf(NULL, 0, "%s -d %s", KPARTX, path) + 1);
    sprintf(command, "%s -d %s", KPARTX, path);
    printf("** RUNNING COMMAND: %s\n", command);
    g_spawn_command_line_sync(command, NULL, NULL, NULL, NULL);
    free(command);

    ped_disk_destroy (disk);
    ped_device_destroy (device);
    free(lv_name);
    free(path);
    free(tmp);
    return;

    error_destroy_disk:
    ped_disk_destroy (disk);

    error_destroy_device:
    ped_device_destroy (device);
    error:

    free(lv_name);
    free(path);
    free(tmp);
    return;
}

void listdir(honeymon_honeypot_t *honeypot, const char *base, const char *name, int level, FILE *f)
{
    DIR *dir = NULL;
    struct dirent *entry = NULL;

    if (!(dir = opendir(name)))
        return;
    if (!(entry = readdir(dir)))
        return;

    do {

       char path[1024];
       int len = snprintf(path, sizeof(path)-1, "%s/%s", name, entry->d_name);
       path[len] = 0;

        if (entry->d_type == DT_DIR) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            listdir(honeypot, base, path, level + 1, f);
        } else if(entry->d_type == DT_REG) {
            unsigned char *md5 = md5_sum(path);
            g_tree_insert(honeypot->fschecksum, md5, strdup(path + strlen(base)));
            fprintf(f, "%s,%s\n", md5, path + strlen(base));

            /*int i;
            for(i=0;i<MD5_DIGEST_LENGTH;i++) printf("%.2x", md5[i]);
            printf(" %s\n", path + strlen(base));*/

        }
    } while ((entry = readdir(dir)));
    closedir(dir);
}

void create_checksum (honeymon_t *honeymon, honeymon_honeypot_t * honeypot)
{

    PedDevice* device;
    PedDiskType* type;
    PedDisk* disk;
    PedPartition* part;
    char *command = NULL;

    char *tmp = g_malloc0(snprintf(NULL, 0, "%s/%s", TMP, honeypot->origin_name) + 1);
    sprintf(tmp, "%s/%s", TMP, honeypot->origin_name);

    char* lv_name = str_replace(honeypot->lv_name, "-", "--");

    char* path=g_malloc0(snprintf(NULL, 0, "%s/%s-%s", PATH_PREPEND, honeypot->vg_name, lv_name) + 1);
    sprintf(path, "%s/%s-%s", PATH_PREPEND, honeypot->vg_name, lv_name);
    printf("LV Path: %s\n", path);

    device = ped_device_get (path);

    if (device == NULL) goto error;

    type = ped_disk_probe (device);
    if (type == NULL) goto error_destroy_device;

    disk = ped_disk_new (device);
    if (disk == NULL) goto error_destroy_disk;

    command = g_malloc0(snprintf(NULL, 0, "%s -r -s -a %s", KPARTX, path) + 1);
    sprintf(command, "%s -r -s -a %s", KPARTX, path);
    printf("** RUNNING COMMAND: %s\n", command);
    g_spawn_command_line_sync(command, NULL, NULL, NULL, NULL);
    free(command);

    mkdir(tmp, S_IRWXU|S_IRGRP|S_IXGRP);

    char* chkpath=g_malloc0(snprintf(NULL, 0, "%s/%s.md5", honeymon->originsdir, honeypot->origin_name) + 1);
    sprintf(chkpath, "%s/%s.md5", honeymon->originsdir, honeypot->origin_name);
    printf("\tCreating checksum file %s\n", chkpath);
    FILE *file = fopen ( chkpath, "w" );
    free(chkpath);

    for (part = ped_disk_next_partition (disk, NULL); part; part = ped_disk_next_partition (disk, part)) {
        if (part->num < 0) continue;

        printf("Partition: %u. Type: %s\n", part->num, (part->fs_type) ? part->fs_type->name : "");

                command = g_malloc0(snprintf(NULL, 0, "%s %sp%u %s", MOUNT, path, part->num, tmp) + 1);
                sprintf(command, "%s %sp%u %s", MOUNT, path, part->num, tmp);
                printf("** RUNNING COMMAND: %s\n", command);
                g_spawn_command_line_sync(command, NULL, NULL, NULL, NULL);
                free(command);

                listdir(honeypot, tmp, tmp, 0, file);

                command = g_malloc0(snprintf(NULL, 0, "%s %s", UMOUNT, tmp) + 1);
                sprintf(command, "%s %s", UMOUNT, tmp);
                printf("** RUNNING COMMAND: %s\n", command);
                g_spawn_command_line_sync(command, NULL, NULL, NULL, NULL);
                free(command);
    }

    rmdir(tmp);
    fclose ( file );

    command = g_malloc0(snprintf(NULL, 0, "%s -d %s", KPARTX, path) + 1);
    sprintf(command, "%s -d %s", KPARTX, path);
    printf("** RUNNING COMMAND: %s\n", command);
    g_spawn_command_line_sync(command, NULL, NULL, NULL, NULL);
    free(command);

    ped_disk_destroy (disk);
    ped_device_destroy (device);
    free(lv_name);
    free(path);
    free(tmp);
    return;

    error_destroy_disk:
    ped_disk_destroy (disk);

    error_destroy_device:
    ped_device_destroy (device);
    error:

    free(lv_name);
    free(path);
    free(tmp);
    return;
}

void grab_file_before_delete(vmi_instance_t vmi, vmi_event_t *event, reg_t cr3, struct symbolwrap *s) {

    honeymon_clone_t *clone = event->data;
    vmi_pid_t pid = vmi_dtb_to_pid(vmi, cr3);

    if(!strcmp(s->symbol->name, "NtSetInformationFile") || !strcmp(s->symbol->name, "ZwSetInformationFile")) {
        if(PM2BIT(clone->pm)==BIT64) {
            reg_t rcx, r8, r9, rsp;
            vmi_get_vcpureg(vmi, &rcx, RCX, event->vcpu_id); // HANDLE FileHandle
            vmi_get_vcpureg(vmi, &r8, R8, event->vcpu_id); // PVOID FileInformation
            vmi_get_vcpureg(vmi, &r9, R9, event->vcpu_id); // ULONG Length
            vmi_get_vcpureg(vmi, &rsp, RSP, event->vcpu_id); // stack pointer

            // The 5th input, FileInformationClass, is pushed on the stack
            // RSP:return addr, 8 bytes
            // 4*4 bytes of homing space (for first 4 inputs)
            uint32_t fileinfoclass = 0;
            addr_t fileinfoclass_addr = rsp + 5*(sizeof(addr_t));
            vmi_read_32_va(vmi, fileinfoclass_addr, pid, &fileinfoclass);

            if(fileinfoclass == FILE_DISPOSITION_INFORMATION && r9 == 1) {
                uint8_t del = 0;
                vmi_read_8_va(vmi, r8, pid, &del);
                if(del) {
                    //printf("DELETE FILE _FILE_OBJECT Handle: 0x%lx.\n", rcx);

                    addr_t obj = get_obj_by_handle(clone, vmi, pid, rcx);
                    addr_t file = obj + sizeof(struct object_header_win7_x64);
                    //printf("Object header is @ 0x%lx. File Object is @ 0x%lx. PID %i\n", obj, file, pid);

                    struct unicode_string_x64 us = {0};
                    vmi_read_va(vmi, file + offsets[VMI_OS_WINDOWS_7][BIT64][FILE_OBJECT_FILENAME], pid, &us, sizeof(struct unicode_string_x64));

                    if(us.length && us.buffer) {

                        unicode_string_t str = {0};
                        str.length = us.length;
                        str.encoding = "UTF-16";
                        str.contents = malloc(us.length);
                        vmi_read_va(vmi,us.buffer,pid,str.contents,us.length);

                        unicode_string_t str2 = {0};
                        vmi_convert_str_encoding(&str, &str2, "UTF-8");
                        if(str2.contents) {
                            printf("\tDelete request cought: %s\n", str2.contents);

                            extract_file(clone, str2.contents, NULL);

                            free(str2.contents);
                        }

                        free(str.contents);
                    }
                }
            }
        }
    }
}
