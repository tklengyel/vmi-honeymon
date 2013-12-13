/*
 * This file is part of the VMI-Honeymon project.
 *
 * 2012-2013 University of Connecticut (http://www.uconn.edu)
 * Tamas K Lengyel <tamas.k.lengyel@gmail.com>
 *
 * VMI-Honeymon is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

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
#include "log.h"
#include "honeypots.h"
#include "xen_helper.h"
#include "guestfs_helper.h"
#include "vmi.h"

void honeymon_honeypots_build_list(honeymon_t *honeymon) {
    if (honeymon->workdir == NULL || honeymon->originsdir == NULL) {
        printf("You need to set a workdir for this!\n");
        return;
    }

    DIR *dp;
    struct dirent *ep = NULL;

    char delim[] = ".";
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
                    char delim2[] = "_";
                    char delim3[] = " ";
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

            if (!strcmp(ep->d_name, ".") || !strcmp(ep->d_name, "..")) continue;

            uint16_t vlan = 0;
            char *split = strdup(ep->d_name);
            char *common_name = NULL, *id_s = NULL, *extension = NULL;
            common_name = strtok(split, delim);
            id_s = strtok(NULL, delim);
            if (id_s != NULL) sscanf(id_s, "%"SCNu16, &vlan);
            extension = strtok(NULL, delim);
            if (common_name != NULL && extension != NULL
                    && !strcmp(extension, "config") && vlan != 0) {

                char* clone_name = malloc(
                        snprintf(NULL, 0, "%s.%u", common_name, vlan) + 1);
                sprintf(clone_name, "%s.%u", common_name, vlan);

                honeymon_honeypots_init_clone(honeymon, common_name, clone_name,
                        vlan);

                free(clone_name);

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
    }
}

int honeymon_honeypots_list_loop2(gpointer key, gpointer value, gpointer data) {
    char *name = (char *) key;
    honeymon_clone_t *clone = (honeymon_clone_t *) value;

    printf("  Clone VM: %s. DomID: %u.\n", name, clone->domID);
    printf("\tConfig path: %s\n\tVLAN: %u\n",
            clone->config_path, clone->vlan);

    return 0;
}

int honeymon_honeypots_list_loop(gpointer key, gpointer value, gpointer data) {
    char *name = (char *) key;
    honeymon_honeypot_t *origin = (honeymon_honeypot_t *) value;

    if (origin->domID > 0) printf("Origin VM: %s. DomID: %u. Clones: %u.\n",
            name, origin->domID, g_tree_nnodes(origin->clone_list));
    else printf("Origin VM: %s. NOT RUNNING!\n", name);

    printf("\tConfig path: %s\n", origin->config_path);
    printf("\tSnapshot path: %s\n",origin->snapshot_path);
    printf("\tMAC: %s\n", origin->mac);
    printf("\tLVM VG: %s\n", origin->vg_name);
    printf("\tLVM LV: %s\n", origin->lv_name);

    g_tree_foreach(origin->clone_list,
            (GTraverseFunc) honeymon_honeypots_list_loop2, NULL);

    return 0;
}

void honeymon_honeypots_list(honeymon_t *honeymon) {
    g_tree_foreach(honeymon->honeypots,
            (GTraverseFunc) honeymon_honeypots_list_loop, NULL);
}

void* honeymon_honeypot_membench(void *input) {
    honeymon_clone_t *clone = (honeymon_clone_t *) input;

    printf("Starting mem benchmark thread for %s\n", clone->clone_name);
    int count = 0;

    if (clone != NULL && clone->logIDX > 0) while (clone->membench) {
        libxl_dominfo info;
        libxl_domain_info(clone->honeymon->xen->xl_ctx, &info, clone->domID);
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

    g_mutex_lock(&(clone->lock));
    if (clone->active && clone->paused) {
        clone_vmi_init(clone);
        g_cond_wait(&clone->cond, &clone->lock);
    }

    // shutdown
    if(!clone->active) goto done;

    // start LibVMI API watcher thread
    // TODO
    pthread_create(&(clone->vmi_thread), NULL, clone_vmi_thread,
            (void *) clone);
    g_cond_wait(&clone->cond, &clone->lock);
    pthread_join(clone->vmi_thread, NULL);

    libxl_domain_pause(honeymon->xen->xl_ctx, clone->domID);

    printf("Destroying clone %s\n", clone->clone_name);
    libxl_domain_destroy(honeymon->xen->xl_ctx, clone->domID, NULL);
    g_mutex_lock(&clone->origin->lock);
    g_tree_steal(clone->origin->clone_list, clone->clone_name);
    clone->origin->clones--;
    g_mutex_unlock(&clone->origin->lock);
    honeymon_free_clone(clone);

    done: printf("Clone thread is exiting.\n");
    pthread_exit(0);
    return NULL;
}

void* honeymon_honeypot_clone_factory(void *input) {

    honeymon_t *honeymon = (honeymon_t *) input;
    while (1) {
        char *honeypot = g_async_queue_pop(honeymon->clone_requests);
        if (!strcmp(honeypot, "exit thread")) break;

        honeymon_xen_clone_vm(honeymon, honeypot);

        free(honeypot);
    }

    pthread_exit(0);
    return NULL;
}

/* Structure inits */
honeymon_honeypot_t* honeymon_honeypots_init_honeypot(honeymon_t *honeymon,
        char *name) {

    honeymon_honeypot_t *origin = g_tree_lookup(honeymon->honeypots,
            (gconstpointer) name);

    if (origin == NULL) {
        origin = g_malloc0(sizeof(honeymon_honeypot_t));

        g_mutex_init(&origin->lock);

        origin->origin_name = g_strdup(name);
        origin->snapshot_path = malloc(
                snprintf(NULL, 0, "%s/%s.origin", honeymon->originsdir, name)
                        + 1);
        origin->config_path = malloc(
                snprintf(NULL, 0, "%s/%s.config", honeymon->honeypotsdir, name)
                        + 1);
        origin->ip_path = malloc(
                snprintf(NULL, 0, "%s/%s.ip", honeymon->originsdir, name) + 1);

        unsigned int domID = 0;
        libxl_name_to_domid(honeymon->xen->xl_ctx, name, &domID);

        sprintf(origin->snapshot_path, "%s/%s.origin", honeymon->originsdir,
                name);
        sprintf(origin->config_path, "%s/%s.config", honeymon->originsdir,
                name);
        sprintf(origin->ip_path, "%s/%s.ip", honeymon->originsdir, name);

        FILE *test1 = NULL, *test2 = NULL;
        printf("Checking for %s: ", origin->config_path);

        if ((test1 = fopen(origin->config_path, "r")) != NULL) {
            printf("OK\n");
            fclose(test1);
            origin->config = (XLU_Config2 *) xlu_cfg_init(stderr, "cmdline");
            xlu_cfg_readfile((XLU_Config *) origin->config,
                    origin->config_path);
        } else {
            printf("missing!\n");
            honeymon_honeypots_destroy_honeypot_t(origin);
            return NULL;
        }

        origin->mac = honeymon_xen_first_vif_mac(origin->config);
        char *disk_config = honeymon_xen_first_disk_path(origin->config);
        char **disk_config_details = g_strsplit(disk_config, "/", 4);
        if(disk_config_details && disk_config_details[2] && disk_config_details[3]) {
            origin->vg_name = g_strdup(disk_config_details[2]);
            origin->lv_name = g_strdup(disk_config_details[3]);
            g_strfreev(disk_config_details);
        } else {
            printf("Missing disk config info!\n");
            return NULL;
        }
        free(disk_config);

        origin->vg = lvm_vg_open(honeymon->lvm, origin->vg_name, "w", 0);
        origin->lv = lvm_lv_from_name(origin->vg, origin->lv_name);

        printf("Checking for LVM2 VG: %s LV: %s\n", origin->vg_name, origin->lv_name);

        printf("Checking for %s: ", origin->snapshot_path);

        if ((test2 = fopen(origin->snapshot_path, "r")) != NULL) {
            fclose(test2);
            printf("OK\n");
        } else {
            printf("missing!\n");
            honeymon_honeypots_destroy_honeypot_t(origin);
            return NULL;
        }

        origin->domID = domID;
        origin->clones = 0; // clones will be updated by honeymon_xen_build_clone_list
        origin->clone_list = g_tree_new_full((GCompareDataFunc) strcmp, NULL,
                NULL, (GDestroyNotify) honeymon_honeypots_destroy_clone_t);

        origin->fschecksum = NULL;

        FILE *file = fopen(origin->ip_path, "r");
        if (file != NULL) {
            char *p = fgets(origin->ip, INET_ADDRSTRLEN, file);
            char *nl = strrchr(p, '\r');
            if (nl) *nl = '\0';
            nl = strrchr(p, '\n');
            if (nl) *nl = '\0';
            fclose(file);
        } else {
            printf("IP is missing\n");
            honeymon_honeypots_destroy_honeypot_t(origin);
            return NULL;
        }

        g_tree_insert(honeymon->honeypots, (gpointer) origin->origin_name,
                (gpointer) origin);

    } else {
        // update?
    }

    return origin;
}

honeymon_clone_t* honeymon_honeypots_init_clone(honeymon_t *honeymon,
        char *origin_name, char *clone_name, uint16_t vlan) {

    uint32_t domID = INVALID_DOMID;

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
        sprintf(config_path, "%s/%s.config", honeymon->honeypotsdir,
                clone_name);
        unlink(config_path);
        free(config_path);

        lv_t clone_lv = lvm_lv_from_name(origin->vg, clone_name);
        lvm_vg_remove_lv(clone_lv);

        return NULL;
    }

    honeymon_clone_t *clone = (honeymon_clone_t *) g_tree_lookup(
            origin->clone_list, clone_name);

    if (clone == NULL) {
        clone = g_malloc0(sizeof(honeymon_clone_t));
        clone->honeymon = honeymon;
        clone->origin = origin;
        clone->vlan = vlan;

        // When we reconstruct clones after a restart, we need to update the vlan ids to start from for new clones
        g_mutex_lock(&honeymon->lock);
        if(honeymon->vlans<=vlan) honeymon->vlans = vlan+1;
        g_mutex_unlock(&honeymon->lock);

        if (!clone_info.dying && !clone_info.shutdown) {
            clone->active = 1;
        }

        if (clone_info.paused) {
            clone->paused = 1;
        }
        if (clone_info.running || clone_info.blocked) {

            pthread_mutex_lock(&(honeymon->log->log_IDX_lock));
            honeymon->log->log_IDX += 1;
            clone->logIDX = honeymon->log->log_IDX;
            pthread_mutex_unlock(&(honeymon->log->log_IDX_lock));
        }

        clone->origin_name = strdup(origin_name);
        clone->clone_name = strdup(clone_name);

        clone->clone_lv = lvm_lv_from_name(origin->vg, clone->clone_name);

        clone->config_path = malloc(
                snprintf(NULL, 0, "%s/%s.config", honeymon->honeypotsdir,
                        clone_name) + 1);
        sprintf(clone->config_path, "%s/%s.config", honeymon->honeypotsdir,
                clone_name);

        clone->domID = domID;

#ifdef HAVE_LIBGUESTFS
        clone->guestfs=NULL;
#endif

        g_mutex_init(&(clone->lock));
        g_cond_init(&(clone->cond));

        pthread_create(&(clone->signal_thread), NULL, honeymon_honeypot_runner,
                (void *) clone);

        //printf("Inserting it to clone list!\n");
        g_tree_insert(origin->clone_list, clone->clone_name, clone);

        origin->clone_buffer++;

    } else {
        // update?
    }
    return clone;
}

gboolean honeymon_honeypots_unpause_clones2(char *clone_name,
        honeymon_clone_t *clone, gpointer data) {

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

        g_mutex_lock(&(clone->origin->lock));
        clone->origin->clone_buffer--;
        clone->origin->clones++;
        g_mutex_unlock(&(clone->origin->lock));

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

gboolean honeymon_honeypots_count_free_clones3(gpointer key,
        honeymon_clone_t *clone, gpointer data) {

    uint32_t *free_clones = (uint32_t *) data;

    if (clone->paused) (*free_clones)++;

    return FALSE;
}

gboolean honeymon_honeypots_count_free_clones2(gpointer key,
        honeymon_honeypot_t *origin, gpointer data) {
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

gboolean honeymon_honeypots_get_random3(gpointer key, honeymon_clone_t *clone,
        GSList **free_clones) {

    if (clone->paused) {
        *free_clones = g_slist_append(*free_clones, (gpointer) clone);
    }

    return FALSE;
}

gboolean honeymon_honeypots_get_random2(gpointer key,
        honeymon_honeypot_t *origin, GSList **free_clones) {

    if (origin->clone_buffer
            && (!origin->max_clones || origin->clones <= origin->max_clones)) {
        g_tree_foreach(origin->clone_list,
                (GTraverseFunc) honeymon_honeypots_get_random3, free_clones);
    }
    return FALSE;
}

honeymon_clone_t *honeymon_honeypots_get_random_free(honeymon_t *honeymon) {
    GSList *free_clones = NULL;
    g_tree_foreach(honeymon->honeypots,
            (GTraverseFunc) honeymon_honeypots_get_random2, &free_clones);

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
    } else return NULL;
}

gboolean honeymon_honeypots_get_free2(gpointer key, honeymon_clone_t *clone,
		honeymon_clone_t **out) {

	if (clone->paused) {
		*out = clone;
		return TRUE;
	}
	return FALSE;
}

honeymon_clone_t *honeymon_honeypots_get_free(honeymon_t *honeymon,
		const char *honeypot) {

	honeymon_clone_t *ret = NULL;
	honeymon_honeypot_t *origin = g_tree_lookup(honeymon->honeypots, honeypot);

	if (origin) {
		g_tree_foreach(origin->clone_list,
				(GTraverseFunc) honeymon_honeypots_get_free2, &ret);
	}

	return ret;
}

/* Structure destroyers */

void honeymon_free_clone(honeymon_clone_t *clone) {
    if (clone) {
        g_mutex_clear(&(clone->lock));
        g_mutex_clear(&(clone->scan_lock));
        g_cond_clear(&(clone->cond));

        honeymon_guestfs_stop(clone);

        g_free(clone->clone_name);
        g_free(clone->origin_name);
        g_free(clone->config_path);
        g_free(clone->scan_threads);
        g_free(clone->tscan);
        g_free(clone);
    }
}

void honeymon_honeypots_destroy_clone_t(honeymon_clone_t *clone) {
    // stop clone thread
    printf("Clearing honeypot clone: %s\n", clone->clone_name);

    clone->active=false;
    g_cond_signal(&(clone->cond));
    pthread_join(clone->signal_thread, NULL);

    honeymon_free_clone(clone);
}

void honeymon_honeypots_destroy_honeypot_t(honeymon_honeypot_t *honeypot) {
    printf("Clearing honeypots: %s\n", honeypot->origin_name);

    if (honeypot->clone_list != NULL) g_tree_destroy(honeypot->clone_list);
    g_free(honeypot->snapshot_path);
    g_free(honeypot->config_path);
    g_free(honeypot->ip_path);
    g_free(honeypot->mac);
    g_free(honeypot->vg_name);
    g_free(honeypot->lv_name);
    lvm_vg_close(honeypot->vg);
    xlu_cfg_destroy((XLU_Config *) honeypot->config);
    g_free(honeypot->origin_name);
    g_mutex_clear(&honeypot->lock);
    g_free(honeypot);
}

