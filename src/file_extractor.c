#include <error.h>
#include <stdio.h>
#include <glib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <parted/parted.h>

#include "structures.h"

#define PATH_PREPEND "/dev/mapper"
#define TMP          "/tmp"

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

gboolean get_file(char *file, gpointer x, honeymon_clone_t *clone) {

    char *file_path = str_replace(file, "\\", "/");
    char *tmp = g_malloc0(snprintf(NULL, 0, "%s/%s/%s", TMP, clone->clone_name, file_path) + 1);
    sprintf(tmp, "%s/%s/%s", TMP, clone->clone_name, file_path);

    struct stat s;
    if( stat(tmp,&s) == 0)
    {
        if( s.st_mode & S_IFREG )
        {
            printf("Getting file %s\n", tmp);
        }
    }

    free(tmp);
    free(file_path);
    return FALSE;
}

void extract_files (honeymon_clone_t * clone)
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

    command = g_malloc0(snprintf(NULL, 0, "%s -r -a %s", KPARTX, path) + 1);
    sprintf(command, "%s -r -a %s", KPARTX, path);
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

                g_tree_foreach(clone->files_accessed, (GTraverseFunc)get_file, clone);

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

