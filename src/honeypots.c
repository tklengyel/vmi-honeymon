#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <dirent.h>
#include <glib.h>
#include <math.h>
#include <pthread.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "structures.h"
#include "scan.h"
#include "log.h"
#include "honeypots.h"
#include "xen_helper.h"
#include "guestfs_helper.h"

void honeymon_honeypots_build_list(honeymon_t *honeymon) {
    if (honeymon->workdir == NULL || honeymon->originsdir == NULL) {
        printf("You need to set a workdir for this!\n");
        return;
    }

    DIR *dp;
    struct dirent *ep = NULL;

    char delim[] = ".";
    char delim2[] = "_";
    char delim3[] = " ";
    dp = opendir(honeymon->originsdir);
    if (dp != NULL) {
        while ((ep = readdir(dp)) != NULL) {
            unsigned int domID = 0;
            char* file_name = strdup(ep->d_name);
            char* name = strtok(file_name, delim);
            char* extension = strtok(NULL, delim);
            char* fschecksum = strtok(NULL, delim);
            if (name != NULL && extension != NULL) {
                honeymon_honeypot_t *honeypot =
                        honeymon_honeypots_init_honeypot(honeymon, name);

                if (fschecksum != NULL
                        && !strcmp(fschecksum, GUESTFS_HASH_TYPE)) {
#ifdef HAVE_LIBGUESTFS
                    char *dev=strtok(extension, delim2);
                    int devID=atoi(strtok(NULL, delim2));

                    char* path=malloc(snprintf(NULL, 0, "%s/%s", honeymon->originsdir, ep->d_name) + 1);
                    sprintf(path, "%s/%s", honeymon->originsdir, ep->d_name);
                    printf("\tReading checksum file %s\n", path);
                    FILE *file = fopen ( path, "r" );
                    GTree *holder=NULL;
                    if ( file != NULL ) {
                        char line [ 2048 ];
                        holder=g_tree_new_full((GCompareDataFunc)strcmp, NULL, (GDestroyNotify)free, (GDestroyNotify)free);

                        while ( fgets ( line, 2048, file ) != NULL ) {
                            char *hash=strdup(strtok(line, delim3));
                            char *f=strdup(strtok(NULL, delim3));
                            memmove(f, f+1, strlen(f));
                            char *nl = strrchr(f, '\n');
                            if (nl) *nl = '\0';
                            nl = strrchr(f, '\r');
                            if (nl) *nl = '\0';

                            //printf("Inserting key %s with data %s\n", f, hash);
                            g_tree_insert(holder, f, hash);
                        }
                        fclose ( file );

                        //printf("Appending checksum list with new tree..\n");
                        honeypot->fschecksum=g_slist_append(honeypot->fschecksum, (gpointer)holder);
                    }

                    free(path);
#else
                    //printf("\tLibGuestFS is present, skipping hash load.\n");
#endif
                    //printf("\tFound fs checksum for dev ID %i\n", devID);
                } else if (strcmp(extension, "origin")
                        && strcmp(extension, "config")) {
                    GSList *test = g_slist_find_custom(honeymon->scans,
                            extension, (GCompareFunc) strcmp);
                    if (test != NULL) {
                        char *scan = strdup(extension);
                        honeypot->scans = g_slist_append(honeypot->scans, scan);
                    } // else {
                      //	printf("\tCouldn't find scan in scanconf: %s\n", extension);
                      //}
                }
            }

            free(file_name);
        }
        closedir(dp);
    } else {
        printf("Failed to open directory %s!", honeymon->originsdir);
        return;
    }
}

void honeymon_honeypots_build_clone_list(honeymon_t *honeymon) {
    if (honeymon->workdir == NULL) {
        printf("You need to set a workdir for this!\n");
        return;
    }

    DIR *dp;
    struct dirent *ep = NULL;

    char delim[] = ".";
    dp = opendir(honeymon->honeypotsdir);
    if (dp != NULL) {
        while ((ep = readdir(dp)) != NULL) {

            if (!strcmp(ep->d_name, ".") || !strcmp(ep->d_name, ".."))
                continue;

            unsigned int honeypotID = 0, domID = 0;
            char *split = strdup(ep->d_name);
            char *common_name = NULL, *id_s = NULL, *extension = NULL;
            common_name = strtok(split, delim);
            id_s = strtok(NULL, delim);
            if (id_s != NULL)
                sscanf(id_s, "%u", &honeypotID);
            extension = strtok(NULL, delim);
            if (common_name != NULL && extension != NULL
                    && !strcmp(extension, "config") && honeypotID != 0) {

                char* clone_name = malloc(
                        snprintf(NULL, 0, "%s.%u", common_name, honeypotID)
                                + 1);
                sprintf(clone_name, "%s.%u", common_name, honeypotID);

                honeymon_honeypots_init_clone(honeymon, common_name, clone_name,
                        NULL);

            } else {
                if (extension == NULL || strcmp(extension, "qcow2")) {
                    printf(
                            "\tGarbage file found in honeypots folder: %s.%s.%s!\n",
                            common_name, id_s, extension);

                    char *fullpath = malloc(
                            snprintf(NULL, 0, "%s/%s", honeymon->honeypotsdir,
                                    ep->d_name) + 1);
                    sprintf(fullpath, "%s/%s", honeymon->honeypotsdir,
                            ep->d_name);
                    unlink(fullpath);
                    free(fullpath);
                }
            }
            free(split);
        }
        closedir(dp);
    } else {
        printf("Failed to open directory %s!", honeymon->honeypotsdir);
        return;
    }
}

void honeymon_init_honeypot_lists(honeymon_t *honeymon) {
    if (honeymon->workdir != NULL) {
        honeymon_honeypots_build_list(honeymon);
        honeymon_honeypots_build_clone_list(honeymon);
        honeymon_honeypots_build_bridge_list(honeymon);
    }
}

int honeymon_honeypots_list_loop2(gpointer key, gpointer value, gpointer data) {
    char *name = (char *) key;
    honeymon_clone_t *clone = (honeymon_clone_t *) value;

    printf("  Clone VM: %s. DomID: %u.\n", name, clone->domID);
    printf("\tConfig path: %s\n\tQCoW2 path: %s\n\tBridge: %s\n",
            clone->config_path, clone->qcow2_path, clone->bridge);

    return 0;
}

int honeymon_honeypots_list_loop(gpointer key, gpointer value, gpointer data) {
    char *name = (char *) key;
    honeymon_honeypot_t *origin = (honeymon_honeypot_t *) value;

    if (origin->domID > 0)
        printf("Origin VM: %s. DomID: %u. Clones: %u.\n", name, origin->domID,
                g_tree_nnodes(origin->clone_list));
    else
        printf("Origin VM: %s. NOT RUNNING!\n", name);

    printf("\tConfig path: %s\n\tSnapshot path: %s\n\tProfile: %s\n",
            origin->config_path, origin->snapshot_path, origin->profile);

    g_tree_foreach(origin->clone_list,
            (GTraverseFunc) honeymon_honeypots_list_loop2, NULL);

    return 0;
}

void honeymon_honeypots_list(honeymon_t *honeymon) {
    g_tree_foreach(honeymon->honeypots,
            (GTraverseFunc) honeymon_honeypots_list_loop, NULL);
}

bool honeymon_honeypots_br_lookup_clones(gpointer key, gpointer value,
        gpointer bridge_search) {
    /*honeymon_clone_t *clone=(honeymon_clone_t *)value;
     //printf("Looping through clones with bridge search: %s %s\n", clone->clone_name, (char *)bridge_search);

     if(clone->bridge != NULL) return false;

     rhash bridge_hash=rhash_init(RHASH_CRC32);
     rhash_update(bridge_hash, (char *)key, strlen((char *)key));
     rhash_final(bridge_hash, NULL);
     char bridge_hash_s[10];
     rhash_print(bridge_hash_s, bridge_hash, RHASH_CRC32, RHPR_UPPERCASE);

     char *bridge=malloc(sizeof(char)*16);
     sprintf(bridge, "honey.%s", bridge_hash_s);

     if(bridge_search == NULL) {
     printf("Honeypot bridge doesn't exist! Recreating it..\n");
     } else {
     //printf("Bridge search %s to %s\n", bridge, bridge_search);
     if(!strcmp(bridge, (char *)bridge_search)) {
     clone->bridge=strdup((char *)bridge_search);
     //printf("Bridge owner found, bridge set to %s!\n", clone->bridge);
     }
     }

     free(bridge);

     if(clone->bridge==NULL)
     return FALSE;
     else*/
    return TRUE;
}

bool honeymon_honeypots_br_lookup_honeypots(gpointer key, gpointer value,
        gpointer bridge_search) {
    honeymon_honeypot_t *honeypot = (honeymon_honeypot_t *) value;
    //printf("Looping through honeypots with bridge search: %s %s\n", honeypot->origin_name, (char *)bridge_search);
    //printf("Number of clones: %i\n", g_tree_nnodes(honeypot->clone_list));
    g_tree_foreach(honeypot->clone_list,
            (GTraverseFunc) honeymon_honeypots_br_lookup_clones, bridge_search);
    return FALSE;
}

int honeymon_honeypots_build_bridge_list(honeymon_t *honeymon) {
    // brctl show | grep honey
    /*int commpipe1[2], commpipe2[2], commpipe3[2];
     int rv;
     rv=pipe(commpipe1);
     rv=pipe(commpipe2);

     pid_t pID = fork();
     if (pID == 0) {
     // Code only executed by child process
     close(commpipe1[0]);
     dup2(commpipe1[1], STDOUT_FILENO);
     dup2(commpipe1[1], STDERR_FILENO);
     prctl(PR_SET_PDEATHSIG, SIGHUP); // pass sighup to die if parent dies

     execl(BRCTL, "brctl", "show",  NULL);
     return 0;
     } else if (pID < 0) {
     errx(1,"Failed to fork!\n");
     }

     close(commpipe1[1]);

     pID = fork();
     if (pID == 0) {
     close(commpipe2[0]);
     dup2(commpipe1[0], 0);
     dup2(commpipe2[1], STDOUT_FILENO);
     dup2(commpipe2[1], STDERR_FILENO);
     prctl(PR_SET_PDEATHSIG, SIGHUP); // pass sighup to die if parent dies

     execl(GREP, "grep", "honey", NULL);
     return 0;
     } else if (pID < 0) {
     errx(1,"Failed to fork!\n");
     }

     close(commpipe2[1]);
     wait(&rv);

     FILE *stream;
     int c;
     stream = fdopen (commpipe2[0], "r");

     while (!feof(stream)) {
     char *bridge=malloc(sizeof(char)*15);
     c=fscanf(stream,"%s%*[^\n]", bridge);

     if(strcmp(bridge, "") && strlen(bridge)==14) {
     //printf("Bridge found: %s\n", bridge);

     // Determine whose bridge it is
     g_tree_foreach(honeymon->honeypots, (GTraverseFunc)honeymon_honeypots_br_lookup_honeypots, (gpointer)bridge);

     free(bridge);
     }
     }

     fclose (stream);

     // Recreate missing bridges (if any)
     //g_tree_foreach(honeymon->honeypots, (GTraverseFunc)honeymon_honeypots_br_lookup_honeypots, NULL);
     */
    return 0;
}

void* honeymon_honeypot_membench(void *input) {
    honeymon_clone_t *clone = (honeymon_clone_t *) input;

    printf("Starting mem benchmark thread for %s\n", clone->clone_name);
    int count = 0;

    if (clone != NULL && clone->logIDX > 0)
        while (clone->membench) {
            libxl_dominfo info;
            libxl_domain_info(clone->honeymon->xen->xl_ctx, &info,
                    clone->domID);
            honeymon_log_membenchmark(clone->honeymon, clone->logIDX,
                    info.current_memkb, info.shared_memkb, info.max_memkb);
            sleep(1);
            count++;
        }

    pthread_exit(0);
    return NULL;
}

/* Honeypot thread to start scans periodically */
void* honeymon_honeypot_runner(void *input) {
    honeymon_clone_t* clone = (honeymon_clone_t *) input;
    honeymon_t *honeymon = clone->honeymon;

    //printf("Clone thread created for %s\n", clone->clone_name);

    int rc;

    struct timespec ts;
    struct timeval tp;

    gint64 sleep_cycle;

    while (1) {
        //printf("Loop start, waiting for clone lock\n");
        g_mutex_lock(&(clone->lock));

        if (clone->active && clone->revert) {
            printf(
                    "Got network signal while scan was already running. Forcing new scan and reverting!\n");

            libxl_domain_pause(honeymon->xen->xl_ctx, clone->domID);
            g_mutex_lock(&(clone->scan_lock));
            honeymon_scan_start_all(clone);
            honeymon_xen_revert_clone(honeymon, clone->clone_name);
            g_mutex_unlock(&(clone->scan_lock));
            clone->cscan = 0;
            clone->revert = 0;

            //pthread_cond_signal(&(clone->network_cond));
        }

        if (clone->active && clone->paused) {
            //printf("Clone is paused, waiting for wake signal!\n");

            // Wait for signal
            g_cond_wait(&clone->cond, &clone->lock);

            //printf("Clone awaken!\n");
        }

        if (!clone->active)
            break;

        if (clone->cscan >= clone->nscans && clone->nscans > 0) {
            printf(
                    "Clone is still active but ran out of scheduled scans (%i/%i). Reverting clone.\n",
                    clone->cscan, clone->nscans);
            honeymon_xen_revert_clone(honeymon, clone->clone_name);
            clone->cscan = 0;
        }

        /* Convert from timeval to timespec */

        if (clone->nscans > 0) {

            sleep_cycle = g_get_monotonic_time() + clone->tscan[clone->cscan] * G_TIME_SPAN_SECOND;
            clone->cscan++;

            if (honeymon->membench && clone->memshared) {
                clone->membench = 1;
                pthread_attr_t tattr;
                int ret = pthread_attr_init(&tattr);
                ret = pthread_attr_setdetachstate(&tattr,
                        PTHREAD_CREATE_DETACHED);
                pthread_create(&(clone->membench_thread), &tattr,
                        honeymon_honeypot_membench, (void *) clone);
                pthread_attr_destroy(&tattr);
            }

            rc = g_cond_wait_until(&(clone->cond), &(clone->lock), sleep_cycle);

            printf("Got out of timed cond wait!\n");
        } else {
            printf(
                    "No scan schedule was defined, waiting for network event signal.\n");
            g_cond_wait(&(clone->cond), &(clone->lock));
            rc = TRUE;
        }

        if (rc == FALSE) {
            // Regular scan scheduled
            printf("Regular scan scheduled\n");
            g_mutex_lock(&(clone->scan_lock));
            clone->scan_initiator = 0;

            if (!honeymon->stealthy)
                libxl_domain_pause(honeymon->xen->xl_ctx, clone->domID);

            int change = honeymon_scan_start_all(clone);

            if (change) {
                clone->membench = 0;
                clone->cscan = 0;
                honeymon_xen_revert_clone(honeymon, clone->clone_name);
            } else if (!honeymon->stealthy)
                libxl_domain_unpause(honeymon->xen->xl_ctx, clone->domID);

            g_mutex_unlock(&(clone->scan_lock));

        } else {
            if (clone->active) {
                // if clone is paused, don't do anything
                if (!clone->paused) {
                    // Network event signal received, immediate scan scheduled and pausing VM
                    printf("Network event signal received!\n");
                    libxl_domain_pause(honeymon->xen->xl_ctx, clone->domID);
                    clone->membench = 0;
                    g_mutex_lock(&(clone->scan_lock));
                    clone->scan_initiator = 1;
                    honeymon_scan_start_all(clone);

                    honeymon_xen_revert_clone(honeymon, clone->clone_name);
                    clone->cscan = 0;

                    g_mutex_unlock(&(clone->scan_lock));

                    //pthread_cond_signal(&(clone->network_cond));

                } else {
                    printf("Got signal to pause VM!\n");
                }
            } else {
                // Signal was received to end all scans
                printf("Singal received to end scan\n");
                break;
            }
        }

        g_mutex_unlock(&(clone->lock));
    }

    //printf("Clone thread is exiting..\n");
    pthread_exit(0);
    return NULL;
}

/* Structure inits */
honeymon_honeypot_t* honeymon_honeypots_init_honeypot(honeymon_t *honeymon,
        char *name) {

    honeymon_honeypot_t *origin = g_tree_lookup(honeymon->honeypots,
            (gconstpointer) name);

    if (origin == NULL) {
        origin = malloc(sizeof(honeymon_honeypot_t));
        origin->origin_name = strdup(name);
        origin->snapshot_path = malloc(
                snprintf(NULL, 0, "%s/%s.origin", honeymon->originsdir, name)
                        + 1);
        origin->config_path = malloc(
                snprintf(NULL, 0, "%s/%s.config", honeymon->honeypotsdir, name)
                        + 1);
        origin->profile_path = malloc(
                snprintf(NULL, 0, "%s/%s.profile", honeymon->honeypotsdir, name)
                        + 1);

        unsigned int domID = 0;
        libxl_name_to_domid(honeymon->xen->xl_ctx, name, &domID);

        sprintf(origin->snapshot_path, "%s/%s.origin", honeymon->originsdir,
                name);
        sprintf(origin->config_path, "%s/%s.config", honeymon->originsdir,
                name);
        sprintf(origin->profile_path, "%s/%s.profile", honeymon->originsdir,
                name);

        origin->domID = domID;
        origin->clones = 0; // clones will be updated by honeymon_xen_build_clone_list
        origin->clone_list = g_tree_new_full((GCompareDataFunc) strcmp, NULL,
                (GDestroyNotify) free,
                (GDestroyNotify) honeymon_honeypots_destroy_clone_t);

        origin->scans = NULL;
        origin->fschecksum = NULL;
        origin->profile = NULL;

        FILE *file = fopen(origin->profile_path, "r");
        if (file != NULL) {
            char line[128];
            char *p = fgets(line, 128, file);
            char *nl = strrchr(p, '\r');
            if (nl)
                *nl = '\0';
            nl = strrchr(p, '\n');
            if (nl)
                *nl = '\0';
            origin->profile = strdup(line);
            fclose(file);
        }

        g_tree_insert(honeymon->honeypots, (gpointer) origin->origin_name,
                (gpointer) origin);

    } else {
        // update?
    }

    return origin;
}

honeymon_clone_t* honeymon_honeypots_init_clone(honeymon_t *honeymon,
        char *origin_name, char *clone_name, char *bridge_name) {

    unsigned int domID = INVALID_DOMID;

    libxl_name_to_domid(honeymon->xen->xl_ctx, clone_name, &domID);
    libxl_dominfo clone_info;
    libxl_domain_info(honeymon->xen->xl_ctx, &clone_info, domID);
    honeymon_honeypot_t *origin = (honeymon_honeypot_t *) g_tree_lookup(
            honeymon->honeypots, origin_name);

    if (domID == INVALID_DOMID || origin == NULL) {

        if (domID != INVALID_DOMID) {
            printf("\tDestroying clone %s because origin VM is not defined!\n",
                    clone_name);
            libxl_domain_destroy(honeymon->xen->xl_ctx, domID, NULL);
        }

        printf("\tCleaning non-existent honeypot leftovers for %s\n",
                clone_name);
        char* config_path = malloc(
                snprintf(NULL, 0, "%s/%s.config", honeymon->honeypotsdir,
                        clone_name) + 1);
        char* qcow2_path = malloc(
                snprintf(NULL, 0, "%s/%s.qcow2", honeymon->honeypotsdir,
                        clone_name) + 1);
        sprintf(config_path, "%s/%s.config", honeymon->honeypotsdir,
                clone_name);
        sprintf(qcow2_path, "%s/%s.qcow2", honeymon->honeypotsdir, clone_name);
        unlink(config_path);
        unlink(qcow2_path);
        free(config_path);
        free(qcow2_path);

        return NULL;
    } else {
        honeymon_clone_t *clone = (honeymon_clone_t *) g_tree_lookup(
                origin->clone_list, clone_name);
        if (clone == NULL) {
            clone = malloc(sizeof(honeymon_clone_t));
            clone->honeymon = honeymon;
            clone->origin = origin;

            if (!clone_info.dying && !clone_info.shutdown)
                clone->active = 1;
            else
                clone->active = 0;

            if (clone_info.paused) {
                clone->paused = 1;
                clone->logIDX = 0;
            }
            if (clone_info.running || clone_info.blocked) {
                clone->paused = 0;

                pthread_mutex_lock(&(honeymon->log->log_IDX_lock));
                honeymon->log->log_IDX += 1;
                clone->logIDX = honeymon->log->log_IDX;
                pthread_mutex_unlock(&(honeymon->log->log_IDX_lock));
            }

            clone->revert = 0;
            clone->membench = 0;
            clone->origin_name = strdup(origin_name);
            clone->clone_name = strdup(clone_name);
            if (bridge_name != NULL)
                clone->bridge = strdup(bridge_name);
            else
                clone->bridge = NULL;

            clone->qcow2_path = malloc(
                    snprintf(NULL, 0, "%s/%s.qcow2", honeymon->honeypotsdir,
                            clone_name) + 1);
            clone->config_path = malloc(
                    snprintf(NULL, 0, "%s/%s.config", honeymon->honeypotsdir,
                            clone_name) + 1);
            sprintf(clone->qcow2_path, "%s/%s.qcow2", honeymon->honeypotsdir,
                    clone_name);
            sprintf(clone->config_path, "%s/%s.config", honeymon->honeypotsdir,
                    clone_name);

            clone->domID = domID;

            clone->nscans = honeymon->number_of_scans;
            clone->scan_threads = malloc(
                    sizeof(pthread_t) * honeymon->number_of_scans);
            clone->cscan = 0;
            clone->tscan = malloc(sizeof(uint32_t) * honeymon->number_of_scans);

#ifdef HAVE_LIBGUESTFS
            clone->guestfs=NULL;
#endif

            int x;
            for (x = 0; x < honeymon->number_of_scans; x++)
                clone->tscan[x] = honeymon->scanschedule[x];


            g_mutex_init(&(clone->lock));
            g_mutex_init(&(clone->scan_lock));
            g_cond_init(&(clone->cond));
            //pthread_mutex_init(&(clone->network_cond_lock), NULL);
            //pthread_cond_init(&(clone->network_cond), NULL);

            pthread_create(&(clone->thread), NULL, honeymon_honeypot_runner,
                    (void *) clone);

            //printf("Inserting it to clone list!\n");
            g_tree_insert(origin->clone_list, clone->clone_name, clone);

            // increment only if its startup initialization
            if (bridge_name == NULL) {
                //printf("Increment clone count!\n");
                origin->clones++;
            }
        } else {
            // update?
        }
        return clone;
    }
}

gboolean honeymon_honeypots_unpause_clones2(gpointer key, gpointer value,
        gpointer data) {
    honeymon_clone_t *clone = (honeymon_clone_t *) value;

    printf("Unpausing %s!\n", clone->clone_name);

    g_mutex_lock(&(clone->lock));
    if (clone->paused) {
        libxl_domain_unpause(clone->honeymon->xen->xl_ctx, clone->domID);
        clone->paused = 0;

        struct timeval tp;
        gettimeofday(&tp, NULL);
        clone->start_time = tp.tv_sec;

        if (clone->logIDX == 0) {
            pthread_mutex_lock(&(clone->honeymon->log->log_IDX_lock));
            clone->honeymon->log->log_IDX += 1;
            clone->logIDX = clone->honeymon->log->log_IDX;
            printf("Clone is assigned log IDX: %u\n", clone->logIDX);
            honeymon_log_session(clone->honeymon, clone);
            pthread_mutex_unlock(&(clone->honeymon->log->log_IDX_lock));
        } else {
            printf("Clone already had log IDX: %u\n", clone->logIDX);
        }

        g_cond_signal(&(clone->cond));
    } else {
        printf("ERROR: %s wasn't paused!\n", clone->clone_name);
    }
    g_mutex_unlock(&(clone->lock));

    return FALSE;
}

void honeymon_honeypots_unpause_clones(honeymon_t *honeymon, char *origin_name) {

    printf("Unpausing clones of %s\n", origin_name);

    honeymon_honeypot_t *origin = (honeymon_honeypot_t *) g_tree_lookup(
            honeymon->honeypots, origin_name);
    if (origin == NULL) {
        printf("That honeypot is not defined!\n");
        return;
    }

    g_tree_foreach(origin->clone_list,
            (GTraverseFunc) honeymon_honeypots_unpause_clones2, NULL);
}

gboolean honeymon_honeypots_pause_clones2(gpointer key, gpointer value,
        gpointer data) {
    honeymon_clone_t *clone = (honeymon_clone_t *) value;

    g_mutex_lock(&(clone->lock));
    if (!clone->paused) {
        printf("Pausing scans and domain %s with domID %u\n", clone->clone_name,
                clone->domID);
        libxl_domain_pause(clone->honeymon->xen->xl_ctx, clone->domID);
        clone->paused = 1;
        g_cond_signal(&(clone->cond));
    } else {
        printf("%s wasn't running!\n", clone->clone_name);
    }
    g_mutex_unlock(&(clone->lock));

    return FALSE;
}

/*gboolean honeymon_honeypots_pause_clones3(gpointer key, gpointer value, gpointer data) {
 honeymon_clone_t *clone=(honeymon_clone_t *)value;

 printf("Pausing scans for %s with domID %u\n", clone->clone_name, clone->domID);

 pthread_cond_signal(&(clone->cond));
 int test=pthread_mutex_lock(&(clone->lock));

 printf("Scan lock mutex: %i\n", test);

 return FALSE;
 }*/

void honeymon_honeypots_pause_clones(honeymon_t *honeymon, char *origin_name) {
    honeymon_honeypot_t *origin = (honeymon_honeypot_t *) g_tree_lookup(
            honeymon->honeypots, origin_name);

    printf("Pausing clones of %s!\n", origin_name);

    if (origin == NULL) {
        printf("That honeypot is not defined!\n");
        return;
    }

    // pause domains
    g_tree_foreach(origin->clone_list,
            (GTraverseFunc) honeymon_honeypots_pause_clones2, NULL);
    // pause scans
    //g_tree_foreach(origin->clone_list, (GTraverseFunc)honeymon_honeypots_pause_clones3, NULL);
}

honeymon_clone_t* honeymon_honeypots_find_clone(honeymon_t *honeymon,
        char *clone_name) {

    char delim[] = ".";
    char *c_name_dup = strdup(clone_name);
    char *origin_name = strtok(c_name_dup, delim);
    honeymon_clone_t *clone = NULL;

    honeymon_honeypot_t *origin = (honeymon_honeypot_t *) g_tree_lookup(
            honeymon->honeypots, origin_name);
    if (origin != NULL) {
        clone = (honeymon_clone_t *) g_tree_lookup(origin->clone_list,
                clone_name);
    }

    free(c_name_dup);
    return clone;
}

gboolean honeymon_honeypots_count_free_clones3(gpointer key, gpointer value,
        gpointer data) {
    honeymon_clone_t *clone = (honeymon_clone_t *) value;
    uint32_t *free_clones = (uint32_t *) data;

    if (clone->paused)
        (*free_clones)++;

    return FALSE;
}

gboolean honeymon_honeypots_count_free_clones2(gpointer key, gpointer value,
        gpointer data) {
    honeymon_honeypot_t *origin = (honeymon_honeypot_t *) value;
    g_tree_foreach(origin->clone_list,
            (GTraverseFunc) honeymon_honeypots_count_free_clones3, data);
    return FALSE;
}

uint32_t honeymon_honeypots_count_free_clones(honeymon_t *honeymon) {
    uint32_t free_clones = 0;
    g_tree_foreach(honeymon->honeypots,
            (GTraverseFunc) honeymon_honeypots_count_free_clones2,
            (gpointer) &free_clones);
    return free_clones;
}

gboolean honeymon_honeypots_get_random3(gpointer key, gpointer value,
        gpointer data) {

    honeymon_clone_t *clone = (honeymon_clone_t *) value;
    GSList *free_clones = (GSList *) data;

    if (clone->paused) {
        //printf("Adding free clone to the list: %s\n", clone->clone_name);
        free_clones = g_slist_append(free_clones, (gpointer) clone);
    }

    return FALSE;
}

gboolean honeymon_honeypots_get_random2(gpointer key, gpointer value,
        gpointer data) {

    honeymon_honeypot_t *origin = (honeymon_honeypot_t *) value;
    g_tree_foreach(origin->clone_list,
            (GTraverseFunc) honeymon_honeypots_get_random3, data);
    return FALSE;
}

honeymon_clone_t *honeymon_honeypots_get_random(honeymon_t *honeymon) {
    GSList *free_clones = g_slist_alloc();
    g_tree_foreach(honeymon->honeypots,
            (GTraverseFunc) honeymon_honeypots_get_random2,
            (gpointer) free_clones);
    free_clones = g_slist_delete_link(free_clones, free_clones);

    guint count = g_slist_length(free_clones);
    //printf("Got %i free clones\n", count);
    if (count > 0) {
        gint32 pick = g_random_int_range(0, count);
        //printf("Pick %i\n", pick);
        honeymon_clone_t *clone = (honeymon_clone_t *) g_slist_nth_data(
                free_clones, pick);
        //printf("Pick is %s\n", clone->clone_name);
        g_slist_free(free_clones);
        return clone;
    } else
        return NULL;
}

/* Structure destroyers */

void honeymon_honeypots_destroy_clone_t(gpointer data) {
    honeymon_clone_t *clone = (honeymon_clone_t *) data;

    // stop clone thread
    if (clone->active) {
        clone->active = 0;
        g_cond_signal(&(clone->cond));
        pthread_join(clone->thread, NULL);
    }
    g_mutex_clear(&(clone->lock));
    g_mutex_clear(&(clone->scan_lock));
    g_cond_clear(&(clone->cond));

    honeymon_guestfs_stop(clone);

    if (clone->origin_name != NULL)
        free(clone->origin_name);
    if (clone->qcow2_path != NULL)
        free(clone->qcow2_path);
    if (clone->config_path != NULL)
        free(clone->config_path);
    if (clone->bridge != NULL)
        free(clone->bridge);
    free(clone);

    //printf("Clone freed\n");
}

void honeymon_honeypots_destroy_honeypot_t(gpointer data) {
    honeymon_honeypot_t *honeypot = (honeymon_honeypot_t *) data;

    //printf("Clearing honeypots: %s\n", honeypot->origin_name);

    if (honeypot->snapshot_path != NULL)
        free(honeypot->snapshot_path);
    if (honeypot->config_path != NULL)
        free(honeypot->config_path);
    if (honeypot->profile_path != NULL)
        free(honeypot->profile_path);
    if (honeypot->profile != NULL)
        free(honeypot->profile);
    if (honeypot->clone_list != NULL)
        g_tree_destroy(honeypot->clone_list);
    free(honeypot);
}

