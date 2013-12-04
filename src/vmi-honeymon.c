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
#include <limits.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <malloc.h>
#include <glib.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "vmi-honeymon.h"
#include "structures.h"
#include "honeypots.h"
#include "xen_helper.h"
#include "input_parser.h"
#include "honeypots.h"
#include "rpc_server.h"
#include "log.h"

//TODO
void honeymon_interrupt(int signal) {
}

void honeymon_init() {

    fprintf(stderr, "Starting %s\n", PACKAGE_STRING);

    honeymon = (honeymon_t*) g_malloc0(sizeof(honeymon_t));

    g_mutex_init(&honeymon->lock);

#ifdef HAVE_XMLRPC
    g_mutex_init(&honeymon->rpc_lock);
    g_cond_init(&honeymon->rpc_cond);

    pthread_create(&(honeymon->rpc_server_thread), NULL, rpc_server_thread,
			(void *) honeymon);
#endif

    honeymon->interactive = 1;
    honeymon->vlans = MIN_VLAN;

    honeymon->honeypots = g_tree_new_full((GCompareDataFunc) strcmp, NULL,
            NULL,
            (GDestroyNotify) honeymon_honeypots_destroy_honeypot_t);

    honeymon->log = g_malloc0(sizeof(honeymon_log_interface_t));

    honeymon->clone_requests = g_async_queue_new();

    honeymon->lvm = lvm_init(NULL);

#ifdef HAVE_LIBMAGIC
    honeymon->magic_cookie=magic_open(MAGIC_MIME);
    if(honeymon->magic_cookie!=NULL && magic_load(honeymon->magic_cookie, NULL) != 0) {
        printf("\tCannot load magic database - %s\n", magic_error(honeymon->magic_cookie));
        magic_close(honeymon->magic_cookie);
    }
#endif

    pthread_create(&(honeymon->clone_factory), NULL,
            honeymon_honeypot_clone_factory, (void *) honeymon);
}

void honeymon_free(honeymon_t* honeymon) {
    if (honeymon != NULL) {
        g_mutex_clear(&honeymon->lock);
        g_free(honeymon->workdir);
        g_free(honeymon->originsdir);
        g_free(honeymon->honeypotsdir);
        g_free(honeymon->backupdir);
        g_free(honeymon->virusdir);
        g_free(honeymon->scanconf);
        honeymon_xen_free_interface(honeymon->xen);
        g_async_queue_unref(honeymon->clone_requests);
        lvm_quit(honeymon->lvm);
        g_free(honeymon->log);
        g_free(honeymon);
    }
}

honeymon_t* honeymon_quit(honeymon_t* honeymon) {

    g_mutex_lock(&honeymon->lock);
    g_tree_destroy(honeymon->honeypots);
    g_async_queue_push(honeymon->clone_requests,"exit thread");
    pthread_join(honeymon->clone_factory,NULL);

#ifdef HAVE_XMLRPC
	xmlrpc_env env;
	xmlrpc_env_init(&env);
	xmlrpc_server_abyss_terminate(&env, honeymon->rpc_server);
	xmlrpc_env_clean(&env);
	pthread_join(honeymon->rpc_server_thread, NULL);
#endif

    honeymon_free(honeymon);
    return NULL;
}

void honeymon_scanlist_init(honeymon_t *honeymon) {
    FILE *file;
    if (NULL != (file = fopen(honeymon->scanconf, "r"))) {
        if (honeymon->scans != NULL) g_slist_free_full(honeymon->scans,
                (GDestroyNotify) free);

        char scan[32];
        while (fgets(scan, 32, file)) {
            char *nlptr = strchr(scan, '\n');
            if (nlptr) *nlptr = '\0';
            char *save_scan = strdup(scan);
            printf("\tEnabling scan: %s\n", save_scan);
            honeymon->scans = g_slist_append(honeymon->scans, save_scan);
        }

        fclose(file);
    } else {
        printf("%s doesn't exists!\n", honeymon->scanconf);
    }
}

//TODO
void honeymon_scanpool_init(honeymon_t *honeymon) {

}

void honeymon_scanschedule_init(honeymon_t *honeymon) {
    FILE *file;
    if (NULL != (file = fopen(honeymon->scanscheduleconf, "r"))) {
        if (honeymon->scanschedule != NULL) free(honeymon->scanschedule);

        char line[32];
        int line_number = -1;

        while (fgets(line, 32, file)) {
            char *nlptr = strchr(line, '\n');
            if (nlptr) *nlptr = '\0';
            int number = atoi(line);

            if (line_number == -1) {
                honeymon->scanschedule = malloc(sizeof(int) * number);
                honeymon->number_of_scans = number;
            } else if (honeymon->number_of_scans > line_number) {
                honeymon->scanschedule[line_number] = number;
                printf("\tAddig scan interval: %i\n", number);
            }

            line_number++;
        }

        fclose(file);
    } else {
        printf("%s doesn't exists!\n", honeymon->scanscheduleconf);
    }
}
void honeymon_workdir_init(honeymon_t *honeymon) {

    if (honeymon->workdir == NULL) {
        printf("No working directory is specified!\n");
        return;
    }

    struct stat st;
    if (stat(honeymon->workdir, &st) != 0) {
        printf("Working directory doesn't exists!\n");
        free(honeymon->workdir);
        honeymon->workdir = NULL;
        return;
    }

    char *originsFolder = malloc(
            snprintf(NULL, 0, "%s/origins", honeymon->workdir) + 1);
    sprintf(originsFolder, "%s/origins", honeymon->workdir);
    if (stat(originsFolder, &st) != 0) {
        printf("Creating %s\n", originsFolder);
        mkdir(originsFolder, 0644);
    }
    if (honeymon->originsdir != NULL) free(honeymon->originsdir);
    honeymon->originsdir = originsFolder;

    char *honeypotsFolder = malloc(
            snprintf(NULL, 0, "%s/honeypots", honeymon->workdir) + 1);
    ;
    sprintf(honeypotsFolder, "%s/honeypots", honeymon->workdir);
    if (stat(honeypotsFolder, &st) != 0) {
        printf("Creating %s\n", honeypotsFolder);
        mkdir(honeypotsFolder, 0644);
    }
    if (honeymon->honeypotsdir != NULL) free(honeymon->honeypotsdir);
    honeymon->honeypotsdir = honeypotsFolder;

    char *backupFolder = malloc(
            snprintf(NULL, 0, "%s/backup", honeymon->workdir) + 1);
    sprintf(backupFolder, "%s/backup", honeymon->workdir);
    if (stat(backupFolder, &st) != 0) {
        printf("Creating %s\n", backupFolder);
        mkdir(backupFolder, 0644);
    }
    if (honeymon->backupdir != NULL) free(honeymon->backupdir);
    honeymon->backupdir = backupFolder;

    char *virusFolder = malloc(
            snprintf(NULL, 0, "%s/viruses", honeymon->workdir) + 1);
    sprintf(virusFolder, "%s/viruses", honeymon->workdir);
    if (stat(virusFolder, &st) != 0) {
        printf("Creating %s\n", virusFolder);
        mkdir(virusFolder, 0644);
    }
    if (honeymon->virusdir != NULL) free(honeymon->virusdir);
    honeymon->virusdir = virusFolder;

}

void honeymon_set_workdir(honeymon_t* honeymon, char *workdir) {

    //printf("Trying to set workdir to %s\n", workdir);

    if (strlen(workdir) < 1) {
        printf("Unable to set workdir!\n");
        return;
    }
    if (strlen(workdir) == 1 && strcmp(workdir, ".")) {
        printf("Unable to set workdir!\n");
        return;
    }
    if ((int) workdir[strlen(workdir) - 1] == 47) {
        workdir[strlen(workdir) - 1] = 0;
    }

    struct stat st;
    if (stat(workdir, &st) != 0) {
        printf("Directory (%s) doesn't exist!\n", workdir);
        return;
    }

    /* Check if we have rights to that folder */
    char *test = malloc(snprintf(NULL, 0, "%s/%s", workdir, "test") + 1);
    sprintf(test, "%s/%s", workdir, "test");
    if (mkdir(test, 0644) != 0 && errno != EEXIST) {
        printf("Don't seem to have rights to that folder (%s)!\n", test);
        free(test);
        return;
    } else rmdir(test);
    free(test);

    if (honeymon->workdir != NULL) free(honeymon->workdir);
    honeymon->workdir = strdup(workdir);

    honeymon_workdir_init(honeymon);

    printf("Working directory changed to %s\n", honeymon->workdir);
}

void honeymon_shell_print_menu() {

    printf("Please select an option:\n");
    printf("\t[workdir <dir>]:			Set working directory\n");
    printf("\t[volatility <path>]:			Set Volatility vol.py path\n");
    printf(
            "\t[scanconf <path>]:			Set and initiate list of Volatility scans\n");
    printf(
            "\t[scanschedule <path>]:		\tSet and initiate schedule of Volatility scans\n");
    printf("\t[list|l {honeypots}]:			List all VM's or only honeypots\n");
    printf(
            "\t[designate|d <domID>]:		\tDesignate a running VM to be clone origin\n");
    printf("\t[restore|r <origin>]:		Restore <origin>\n");
    printf(
            "\t[clone|c <origin>]:			Setup clones of an origin VM (buffer size: %u)\n",
            CLONE_BUFFER);
    printf("\t[unpause|u <origin>]:			Unpause all the clones of <origin>\n");
    printf("\t[pause|p <origin>]:			Pause all the clones of <origin>\n");
    printf("\t[tcpport <port #>]:			TCP port to listen on\n");
    printf("\t[tcpif <IP>]:				IP to listen on (or \"any\")\n");
    printf("\t[tcpinit]:				Start TCP listener\n");
    //printf("\t[watch|w]:				Watch live action\n");
    printf("\t[quit|q]:				Quit \n");
    printf("\t[help|?|h]:			 	Print this help\n");

}

//TODO switch and const definitions instead of if-else ladder on command
void honeymon_shell(honeymon_t* honeymon) {
    char delim[] = " ";
    while (honeymon != NULL) {

        if (honeymon->workdir == NULL) printf("honeymon #> ");
        else printf("%s #> ", honeymon->workdir);

        fflush(stdout);

        char buffer[1024];
        if (!fgets(buffer, 1024, stdin)) {
            continue;
        }
        buffer[strlen(buffer) - 1] = '\0';

        // check for command options
        char* command = strtok(buffer, delim);
        char* option = strtok(NULL, delim);
        char* option2 = NULL;
        if (option != NULL) option2 = strtok(NULL, delim);

        //printf("Got command: %s Option: %s\n", command, option);

        if (command != NULL) {

            if (!strcmp(command, "list") || !strcmp(command, "l")) {
                if (option == NULL) {
                    honeymon_xen_list_domains(honeymon);
                } else {
                    honeymon_honeypots_list(honeymon);
                }
            } else if (!strcmp(command, "workdir")) {
                if (option != NULL) {
                    honeymon_set_workdir(honeymon, option);
                } else {
                    printf("Current workdir is %s\n", honeymon->workdir);
                }
            } else if (!strcmp(command, "scanconf")) {
                if (option != NULL) {
                    g_free(honeymon->scanconf);
                    honeymon->scanconf = strdup(option);
                    honeymon_scanlist_init(honeymon);
                } else {
                    printf("Current Scan config path is %s\n",
                            honeymon->scanconf);
                }
            } else if (!strcmp(command, "scanschedule")) {
                if (option != NULL) {
                    g_free(honeymon->scanscheduleconf);
                    honeymon->scanscheduleconf = strdup(option);
                    honeymon_scanschedule_init(honeymon);
                } else {
                    printf("Current Scan schedule config path is %s\n",
                            honeymon->scanscheduleconf);
                }
            } else if (!strcmp(command, "designate") || !strcmp(command, "d")) {
                if (option != NULL) {
                    honeymon_xen_designate_vm(honeymon, option);
                } else {
                    printf(
                            "Plese specify the vm by name or by id (designate X or d X)!\n");
                }
            } else if (!strcmp(command, "restore") || !strcmp(command, "r")) {
                if (option != NULL) {
                    honeymon_xen_restore(honeymon, option);
                } else {
                    printf(
                            "Please specify the vm by name or by id (restore X or r X)!\n");
                }
            } else if (!strcmp(command, "clone") || !strcmp(command, "c")) {
                if (option != NULL) {
                    if (option2 == NULL) {
                        g_async_queue_push(honeymon->clone_requests, strdup(option));
                    } else {
                        int number = atoi(option2);
                        while(number>0) {
                            g_async_queue_push(honeymon->clone_requests, strdup(option));
                            number--;
                        }
                    }
                } else {
                    printf(
                            "Please specify the vm by name or by id (clone X or c X)!\n");
                }
            } else if (!strcmp(command, "unpause") || !strcmp(command, "u")) {
                if (option != NULL) {
                    honeymon_honeypots_unpause_clones(honeymon, option);
                } else {
                    printf("Please specify the Honeypot origin by name!\n");
                }
            } else if (!strcmp(command, "pause") || !strcmp(command, "p")) {
                if (option != NULL) {
                    honeymon_honeypots_pause_clones(honeymon, option);
                } else {
                    printf("Please specify the Honeypot origin by name!\n");
                }
            } else if (!strcmp(command, "quit") || !strcmp(command, "q")
                    || !strcmp(command, "exit")) {
                honeymon = honeymon_quit(honeymon);
            } else if (!strcmp(command, "help") || !strcmp(command, "?")
                    || !strcmp(command, "h")) {
                honeymon_shell_print_menu();
            }

        }
    }
}

int main(int argc, char **argv) {

    honeymon_init();
    honeymon_input_parse(honeymon, argc, argv);

    if (!honeymon_xen_init_interface(honeymon)) {
        fprintf(stderr, "Failed to initialize Xen interface!\n");
        return 1;
    } else printf("\tXen interface initialized\n");

    honeymon_log_init_interface(honeymon);

    if (honeymon->workdir != NULL) {
        honeymon_workdir_init(honeymon);
    }

    if (honeymon->scanconf != NULL) {
        honeymon_scanlist_init(honeymon);
    }

    if (honeymon->scanscheduleconf != NULL) {
        honeymon_scanschedule_init(honeymon);
    }

    honeymon_scanpool_init(honeymon);

    honeymon_init_honeypot_lists(honeymon);

    if (honeymon->interactive) {

        if (honeymon->action == 5) {
        	//TODO XMLRPC
            //honeymon_tcp_start_listener(honeymon);
        }

        //TODO
        //signal(SIGINT, honeymon_interrupt);
        //signal(SIGKILL, honeymon_interrupt);

        honeymon_shell_print_menu();
        honeymon_shell(honeymon);

    } else {
        switch (honeymon->action) {
            case 1:
                //honeymon_print_help();
                break;
            case 2:
                honeymon_xen_list_domains(honeymon);
                break;
            case 3:
                honeymon_honeypots_list(honeymon);
                break;
            case 4:
                honeymon_xen_restore_origin(honeymon, honeymon->action_option);
                break;
            case 100:
                // test case
                //test(honeymon, honeymon->action_option);
                break;
            case 0:
            default:
                return 1;
        }
    }

    return 0;
}
