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
            char *md5 = md5_sum(file_path);
            if(md5) {

                //printf("checking for saved md5 with path '%s'\n", tmp1);
                char *saved_md5 = g_tree_lookup(clone->origin->fschecksum, tmp1);

                if(!saved_md5 || strcmp(md5, saved_md5)) {
                    char *tmp2 = str_replace(file_path, " ", "\\ ");
                    char *tmp3 = str_replace(tmp2, "{", "\\{");
                    char *tmp4 = str_replace(tmp3, "}", "\\}");
                    char *command = g_malloc0(snprintf(NULL, 0, "%s %s %s/%s", CP, tmp2, clone->honeymon->virusdir, md5) + 1);
                    sprintf(command, "%s %s %s/%s", CP, tmp2, clone->honeymon->virusdir, md5);
                    printf("** RUNNING COMMAND: %s\n", command);
                    g_spawn_command_line_sync(command, NULL, NULL, NULL, NULL);
                    free(command);
                    free(tmp2);
                    free(tmp3);
                    free(tmp4);

                    vmi_pause_vm(clone->vmi);

                }

                free(md5);
            }

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
    //printf("Clone LV Path: %s\n", path);

    device = ped_device_get (path);

    if (device == NULL) goto error;

    type = ped_disk_probe (device);
    if (type == NULL) goto error_destroy_device;

    disk = ped_disk_new (device);
    if (disk == NULL) goto error_destroy_disk;

    command = g_malloc0(snprintf(NULL, 0, "%s -r -s -a %s", KPARTX, path) + 1);
    sprintf(command, "%s -r -s -a %s", KPARTX, path);
    //printf("** RUNNING COMMAND: %s\n", command);
    g_spawn_command_line_sync(command, NULL, NULL, NULL, NULL);
    free(command);

    mkdir(tmp, S_IRWXU|S_IRGRP|S_IXGRP);

    for (part = ped_disk_next_partition (disk, NULL); part; part = ped_disk_next_partition (disk, part)) {
        if (part->num < 0) continue;

        //printf("Partition: %u. Type: %s\n", part->num, (part->fs_type) ? part->fs_type->name : "");

                command = g_malloc0(snprintf(NULL, 0, "%s %sp%u %s", MOUNT, path, part->num, tmp) + 1);
                sprintf(command, "%s %sp%u %s", MOUNT, path, part->num, tmp);
                //printf("** RUNNING COMMAND: %s\n", command);
                g_spawn_command_line_sync(command, NULL, NULL, NULL, NULL);
                free(command);

                if(filename) {
                    get_file(filename, NULL, clone);
                } else {
                    g_tree_foreach(files, (GTraverseFunc)get_file, clone);
                }

                command = g_malloc0(snprintf(NULL, 0, "%s %s", UMOUNT, tmp) + 1);
                sprintf(command, "%s %s", UMOUNT, tmp);
                //printf("** RUNNING COMMAND: %s\n", command);
                g_spawn_command_line_sync(command, NULL, NULL, NULL, NULL);
                free(command);
    }

    rmdir(tmp);

    command = g_malloc0(snprintf(NULL, 0, "%s -d %s", KPARTX, path) + 1);
    sprintf(command, "%s -d %s", KPARTX, path);
    //printf("** RUNNING COMMAND: %s\n", command);
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
            char *md5 = md5_sum(path);
            if(md5) {
                g_tree_insert(honeypot->fschecksum, strdup(path + strlen(base)), md5);
                fprintf(f, "%s,%s\n", md5, path + strlen(base));
                printf("%s,%s\n", md5, path + strlen(base));
            }
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

    if(!strcmp(s->symbol->name, "NtSetInformationFile") || !strcmp(s->symbol->name, "ZwSetInformationFile")) {

        uint32_t fileinfoclass;
        reg_t handle, info, length, rsp;
        vmi_get_vcpureg(vmi, &rsp, RSP, event->vcpu_id); // stack pointer

        if(PM2BIT(clone->pm)==BIT32) {
            addr_t paddr = vmi_pagetable_lookup(vmi, cr3, rsp + sizeof(uint32_t));
            vmi_read_32_pa(vmi, paddr, (uint32_t*)&handle);
            paddr += 2*sizeof(uint32_t);
            vmi_read_32_pa(vmi, paddr, (uint32_t*)&info);
            paddr += sizeof(uint32_t);
            vmi_read_32_pa(vmi, paddr, (uint32_t*)&length);
            paddr += sizeof(uint32_t);
            vmi_read_32_pa(vmi, paddr, &fileinfoclass);
        } else {
            vmi_get_vcpureg(vmi, &handle, RCX, event->vcpu_id); // HANDLE FileHandle
            vmi_get_vcpureg(vmi, &info, R8, event->vcpu_id); // PVOID FileInformation
            vmi_get_vcpureg(vmi, &length, R9, event->vcpu_id); // ULONG Length

            addr_t fileinfoclass_paddr = vmi_pagetable_lookup(vmi, cr3, rsp + 5*sizeof(addr_t));
            vmi_read_32_pa(vmi, fileinfoclass_paddr, &fileinfoclass);
        }

            if(fileinfoclass == FILE_DISPOSITION_INFORMATION && length == 1) {
                uint8_t del = 0;
                vmi_read_8_pa(vmi, vmi_pagetable_lookup(vmi, cr3, info), &del);
                if(del) {
                    //printf("DELETE FILE _FILE_OBJECT Handle: 0x%lx.\n", rcx);

                    addr_t obj = get_obj_by_handle(clone, vmi, event->vcpu_id, cr3, handle);
                    addr_t file = obj + sizeof(struct object_header_win7_x64);
                    //printf("Object header is @ 0x%lx. File Object is @ 0x%lx. PID %i\n", obj, file, pid);

                    uint16_t length = 0;
                    addr_t buffer = 0;
                    addr_t filename_pa = vmi_pagetable_lookup(vmi, cr3, file + offsets[VMI_OS_WINDOWS_7][PM2BIT(clone->pm)][FILE_OBJECT_FILENAME]);

                    if(PM2BIT(clone->pm)==BIT32) {
                        struct unicode_string_x86 us = {0};
                        vmi_read_pa(vmi, filename_pa, &us, sizeof(struct unicode_string_x86));
                        length = us.length;
                        buffer = us.buffer;
                    } else {
                        struct unicode_string_x64 us = {0};
                        vmi_read_pa(vmi, filename_pa, &us, sizeof(struct unicode_string_x64));
                        length = us.length;
                        buffer = us.buffer;
                    }

                    if(length && buffer) {

                        unicode_string_t str = {0};
                        str.length = length;
                        str.encoding = "UTF-16";
                        str.contents = malloc(length);
                        vmi_read_pa(vmi,vmi_pagetable_lookup(vmi, cr3, buffer),str.contents,length);

                        unicode_string_t str2 = {0};
                        vmi_convert_str_encoding(&str, &str2, "UTF-8");
                        if(str2.contents) {
                            printf("\tDelete request cought: %s\n", str2.contents);

                            extract_file(clone, (const char *)str2.contents, NULL);

                            free(str2.contents);
                        }

                        free(str.contents);
                    }
                }
            }
    }
}
