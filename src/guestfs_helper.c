#include <string.h>
#include <stdio.h>

#include "structures.h"
#include "log.h"

int honeymon_guestfs_start(honeymon_t *honeymon, honeymon_clone_t *clone) {
#ifdef HAVE_LIBGUESTFS
    if(honeymon->guestfs_enable) {
        printf("\tCreating GuestFS appliance for %s with disk %s\n", clone->clone_name, clone->qcow2_path);
        clone->guestfs=guestfs_create();
        guestfs_add_drive_opts (clone->guestfs, clone->qcow2_path,
                GUESTFS_ADD_DRIVE_OPTS_FORMAT, "qcow2",
                GUESTFS_ADD_DRIVE_OPTS_READONLY, 1,
                -1);
        guestfs_set_memsize(clone->guestfs,96);
        return guestfs_launch(clone->guestfs);
    }
#endif
    return -1;

}

void honeymon_guestfs_stop(honeymon_clone_t *clone) {
#ifdef HAVE_LIBGUESTFS
    if(clone->guestfs!=NULL) {
        guestfs_close(clone->guestfs);
        clone->guestfs=NULL;
    }
#endif
}

void honeymon_guestfs_checksum(honeymon_t *honeymon,
        honeymon_honeypot_t *origin, char *disk_path) {
#ifdef HAVE_LIBGUESTFS
    printf("Creating GuestFS appliance for %s\n", disk_path);
    guestfs_h *g=guestfs_create();
    guestfs_add_drive_opts (g, disk_path,
            GUESTFS_ADD_DRIVE_OPTS_READONLY, 1,
            -1);
    guestfs_set_memsize(g,96);
    if(guestfs_launch(g)!=0) {
        printf("GuestFS FAIL!\n");
        return;
    }

    char **partitions=guestfs_list_partitions(g);

    int p;
    for(p=0;partitions[p]!=NULL;p++) {
        printf("Calculating checksum of partition %s of %s\n", partitions[p], origin->origin_name);
        char *p_path=malloc(snprintf(NULL, 0, "%s/%s.dev_%i.%s", honeymon->originsdir, origin->origin_name, p, GUESTFS_HASH_TYPE) + 1);
        sprintf(p_path, "%s/%s.dev_%i.%s", honeymon->originsdir, origin->origin_name, p, GUESTFS_HASH_TYPE);
        guestfs_mount_ro(g, partitions[p], "/");
        guestfs_checksums_out(g, GUESTFS_HASH_TYPE, "/", p_path);
        guestfs_umount(g, partitions[p]);
        free(partitions[p]);
    }
    guestfs_close(g);
#endif
}

int honeymon_guestfs_magic_check(honeymon_t *honeymon, char *file) {
#ifdef HAVE_LIBMAGIC
    const char *type=magic_file(honeymon->magic_cookie, file);
    if(!strncmp(type, "text", 4))
    return 0;
    else
    return 1;
#else
    return 1;
#endif
}

void honeymon_guestfs_extract(honeymon_t *honeymon, honeymon_clone_t *clone,
        GSList *guestfs_check) {
#ifdef HAVE_LIBGUESTFS
    char delim[]="'";

    printf("Checking %i files with guestfs on %s..\n", g_slist_length(guestfs_check), clone->clone_name);
    if(honeymon_guestfs_start(honeymon, clone)!=0) {
        printf("GuestFS failed to launch!\n");
        return;
    }

    int extracted=0;

    char **partitions=guestfs_list_partitions(clone->guestfs);
    int p;
    for(p=0;partitions[p]!=NULL;p++) {

        //printf("GuestFS mounting partition %s\n", partitions[p]);

        guestfs_mount_ro(clone->guestfs, partitions[p], "/");

        GSList *check=guestfs_check;

        while(check!=NULL) {

            char *result = strdup((char *)check->data);

            //Offset(V)  Obj Type   #Ptr #Hnd Access Name
            char *progress;
            char *first_half=strtok_r(result, delim, &progress);
            char *file=strtok_r(NULL, delim, &progress);

            if(file!=NULL) {
                int i;
                for(i=0;i<strlen(file);i++) {
                    if(file[i]==92) file[i]=47;
                    if(file[i+1]==92) {
                        int x=i+1;
                        while(file[x]!=0) {
                            file[x]=file[x+1];
                            x++;
                        }
                    }
                }

                //char *real_file=guestfs_case_sensitive_path(clone->guestfs, file);

                //printf("GuestFS check file %s on partition %s\n", real_file, partitions[p]);

                char *new_hash=NULL;
                int exists=0;

                //if(real_file!=NULL)
                exists=guestfs_is_file(clone->guestfs, file);

                if(exists) {
                    new_hash=guestfs_checksum(clone->guestfs, GUESTFS_HASH_TYPE, file);
                }
                //else
                //printf("It's not a file: %i!\n", exists);

                if(exists && new_hash!= NULL) {

                    //printf("Its a file with hash %s\n", new_hash);

                    GSList *checksum=clone->origin->fschecksum;
                    bool found=0;

                    while(checksum!=NULL) {
                        GTree *tree=(GTree *)checksum->data;
                        char *old_hash=(char *)g_tree_lookup(tree, file);
                        if(old_hash != NULL) {

                            found=1;

                            if(strcmp(old_hash, new_hash)) {
                                // File changed
                                char *extract=malloc(snprintf(NULL, 0, "%s/%s", honeymon->virusdir, new_hash) + 1);
                                sprintf(extract, "%s/%s", honeymon->virusdir, new_hash);
                                FILE *fp=fopen(extract, "r");
                                if(fp!=NULL) {
                                    //printf("already got it\n");
                                    // already got it
                                    fclose(fp);
                                } else {
                                    // EXTRACT
                                    //printf("New capture: %s (changed hash from %s to %s)\n", file, old_hash, new_hash);
                                    guestfs_download(clone->guestfs, file, extract);
                                    if(honeymon_guestfs_magic_check(clone->honeymon, extract)) {
                                        honeymon_log_scan(clone->honeymon, clone, "guestfs", file, new_hash);
                                        extracted++;
                                    } else {
                                        unlink(extract);
                                        honeymon_log_scan(clone->honeymon, clone, "guestfs-n.e.", file, new_hash);
                                    }
                                }
                                free(extract);
                            } //else {
                              // File is the same
                              //printf("File %s is the same!\n", file);
                              //}

                            break;
                        }

                        checksum=checksum->next;
                    }

                    if(!found) {
                        char *extract=malloc(snprintf(NULL, 0, "%s/%s", honeymon->virusdir, new_hash) + 1);
                        sprintf(extract, "%s/%s", honeymon->virusdir, new_hash);
                        FILE *fp=fopen(extract, "r");
                        if(fp!=NULL) {
                            // already got it
                            //printf("already got it\n");
                            fclose(fp);
                        } else {
                            // EXTRACT
                            //printf("New capture: %s!\n", file);
                            guestfs_download(clone->guestfs, file, extract);
                            if(honeymon_guestfs_magic_check(clone->honeymon, extract)) {
                                honeymon_log_scan(clone->honeymon, clone, "guestfs", file, new_hash);
                                extracted++;
                            } else {
                                unlink(extract);
                                honeymon_log_scan(clone->honeymon, clone, "guestfs-n.e.", file, new_hash);
                            }
                        }
                        free(extract);
                    }
                    free(new_hash);
                }

                //if(real_file!=NULL)
                //	free(real_file);
            }
            check=check->next;
            free(result);
        }
        guestfs_umount(clone->guestfs, partitions[p]);
        free(partitions[p]);
    }

    printf("Extracted %i files\n", extracted);
    honeymon_guestfs_stop(clone);
#endif
}
