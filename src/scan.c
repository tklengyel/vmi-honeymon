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
#include <err.h>

#include "structures.h"
#include "log.h"
#include "scan.h"

#define MAX_LINE_LENGTH 1024

#ifdef TODO_LIBVMI

bool honeymon_scan_start_all(honeymon_clone_t *clone) {

    printf("Starting all available scans on %s\n", clone->clone_name);

    GSList* scan = clone->origin->scans;
    guint nscans = g_slist_length(clone->origin->scans);

    clone->scan_threads = g_malloc0(sizeof(pthread_t) * nscans);
    clone->scan_results = g_malloc0(sizeof(bool) * nscans);
    guint c = 0;

    while (scan != NULL && c < nscans) {
        //printf("Starting scan %s\n", (char *)scan->data);
        honeymon_scan_input_t *scan_input = malloc(
                sizeof(honeymon_scan_input_t));
        scan_input->scan = (char *) scan->data;
        scan_input->domain = clone->clone_name;
        scan_input->clone = clone;
        scan_input->result = &(clone->scan_results[c]);
        scan_input->honeymon = clone->honeymon;

        pthread_create(&(clone->scan_threads[c]), NULL, (void *) honeymon_scan,
                (void *) scan_input);

        scan = scan->next;
        c++;
    }

    // Get all the results
    bool change = 0;

    while (c > 0) {
        c--;
        pthread_join(clone->scan_threads[c], NULL);
        if (clone->scan_results[c] == 1) change = clone->scan_results[c];
    }

    free(clone->scan_threads);
    free(clone->scan_results);
    clone->scan_threads = NULL;

    return change;
}

void* honeymon_scan(honeymon_scan_input_t *input) {
    //printf("Running scan %s for %s\n", input->scan, input->domain);

    char *output = malloc(
            snprintf(NULL, 0, "%s/%s.%s", input->honeymon->honeypotsdir,
                    input->domain, input->scan) + 1);
    sprintf(output, "%s/%s.%s", input->honeymon->honeypotsdir, input->domain,
            input->scan);
    int out = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    char *vmi = malloc(snprintf(NULL, 0, "vmi://%s", input->domain) + 1);
    sprintf(vmi, "vmi://%s", input->domain);
    char *profile = malloc(
            snprintf(NULL, 0, "--profile=%s", input->clone->origin->profile)
                    + 1);
    sprintf(profile, "--profile=%s", input->clone->origin->profile);

    pid_t pID = fork();
    if (pID == 0) {
        dup2(out, STDOUT_FILENO);
        dup2(out, STDERR_FILENO);
        prctl(PR_SET_PDEATHSIG, SIGHUP); // pass sighup to die if parent dies
        execl(PYTHON, PYTHON, input->honeymon->volatility, "-l", vmi, profile,
                input->scan, NULL);
        exit(0);
    } else if (pID < 0) {
        errx(1, "Failed to fork!\n");
    }

    waitpid(pID, NULL, 0);

    close(out);
    free(vmi);
    free(profile);

    // Compare
    char *origin_scan = g_malloc0(
            snprintf(NULL, 0, "%s/%s.%s", input->honeymon->originsdir,
                    input->clone->origin_name, input->scan) + 1);
    sprintf(origin_scan, "%s/%s.%s", input->honeymon->originsdir,
            input->clone->origin_name, input->scan);

    bool change = honeymon_scan_compare(input->scan, origin_scan, output,
            input->clone);
    *(input->result) = change;

    //printf("Got %u and assigned %u\n", change, *(input->result));
    //printf("Scan finished: %s\n", input->scan);

    free(input);
    free(output);
    free(origin_scan);

    //pthread_exit(0);

    return NULL;
}

bool honeymon_scan_compare(char *scan, char *origin_scan, char *clone_scan,
        honeymon_clone_t *clone) {

    //printf("Comparing scan results %s to origin scan for %s!\n", scan, clone_name);

    bool change = 0;

    GSList *oscan = NULL;
    GSList *cscan = NULL;

    uint32_t oscan_l = 0;
    uint32_t cscan_l = 0;

    FILE *file;
    if (NULL != (file = fopen(origin_scan, "r"))) {
        char scan[MAX_LINE_LENGTH];
        while (fgets(scan, MAX_LINE_LENGTH, file)) {
            char *nlptr = strchr(scan, '\n');
            if (nlptr) *nlptr = '\0';
            char *save = strdup(scan);
            oscan = g_slist_append(oscan, (gpointer) save);
            oscan_l++;
        }
        fclose(file);
    }

    if (NULL != (file = fopen(clone_scan, "r"))) {
        char scan[MAX_LINE_LENGTH];
        while (fgets(scan, MAX_LINE_LENGTH, file)) {
            char *nlptr = strchr(scan, '\n');
            if (nlptr) *nlptr = '\0';
            char *save = strdup(scan);
            cscan = g_slist_append(cscan, (gpointer) save);
            cscan_l++;
        }
        fclose(file);
    }

#ifdef HAVE_LIBGUESTFS
    GSList *guestfs_check=NULL;
#endif

    if (cscan_l != oscan_l) {
        //printf("Number of lines don't match!\n\tOrigin: %u\n\tClone: %u\n", oscan_l, cscan_l);
        change = 1;
    }

    //char delim2[]=" ";

    // compare cscan to oscan
    GSList *c = NULL;
    GSList *o = NULL;
    for (c = cscan; c != NULL; c = c->next) {
        bool found = 0;
        for (o = oscan; o != NULL; o = o->next) {
            if (!strcmp((char *) c->data, (char *) o->data)) {
                found = 1;
                break;
            }
        }

        if (!found) {
            //printf("New/changed line found in clone scan: %s\n%s\n", scan, (char *)c->data);
            honeymon_log_scan(clone->honeymon, clone, scan, "NEW",
                    (char *) c->data);
            change = 1;

#ifdef HAVE_LIBGUESTFS
            if(clone->honeymon->guestfs_enable && !strcmp(scan, "filescan")) {
                guestfs_check=g_slist_append(guestfs_check, (gpointer)strdup((char *)c->data));
            }
#endif
        }
    }

    c = NULL;
    o = NULL;
    for (o = oscan; o != NULL; o = o->next) {
        bool found = 0;
        for (c = cscan; c != NULL; c = c->next) {
            if (!strcmp((char *) c->data, (char *) o->data)) {
                found = 1;
                break;
            }
        }

        if (!found) {
            //printf("Missing/changed line found in origin scan: %s\n%s\n", scan, (char *)o->data);
            honeymon_log_scan(clone->honeymon, clone, scan, "MISSING",
                    (char *) o->data);
            change = 1;

            //#ifdef HAVE_LIBGUESTFS
            //if(clone->honeymon->guestfs_enable && !strcmp(scan, "filescan")) {
            //	guestfs_check=g_slist_append(guestfs_check, (gpointer)strdup((char *)o->data));
            //}
            //#endif
        }
    }

#ifdef HAVE_LIBGUESTFS
    if(!strcmp(scan, "filescan") && g_slist_length(guestfs_check)>0 )
    honeymon_guestfs_extract(clone->honeymon, clone, guestfs_check);
#endif

    g_slist_free_full(oscan, (GDestroyNotify) free);
    g_slist_free_full(cscan, (GDestroyNotify) free);

    return change;
}

#endif //TODO
