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

#include "structures.h"

void honeymon_input_parse(honeymon_t* honeymon, int argc, char **argv) {

    if (argc < 1 || (argc == 1 && strcmp(argv[0], "vmi-honeymon"))) return;

    int x = 1;
    while (x < argc) {
        if (strlen(argv[x]) > 1 && (int) (argv[x][0]) == 45) {

            if (!strcmp(argv[x], "-h") || !strcmp(argv[x], "--help")) {
                honeymon->interactive = 0;
                honeymon->action = 1;
            } else if (!strcmp(argv[x], "-workdir") && x + 1 < argc) {
                // Remove tailing "/" from the workdir
                if ((int) (argv[x + 1][strlen(argv[x + 1]) - 1]) == 47) {
                    argv[x + 1][strlen(argv[x + 1]) - 1] = 0;
                }

                honeymon->workdir = strdup(argv[x + 1]);
                x += 2;
            } else if (!strcmp(argv[x], "-mysqluser") && x + 1 < argc) {
                honeymon->log->mysql_user = strdup(argv[x + 1]);
                x += 2;
            } else if (!strcmp(argv[x], "-mysqladdress") && x + 1 < argc) {
                honeymon->log->mysql_address = strdup(argv[x + 1]);
                x += 2;
            } else if (!strcmp(argv[x], "-mysqlpass") && x + 1 < argc) {
                honeymon->log->mysql_pass = strdup(argv[x + 1]);
                x += 2;
            } else if (!strcmp(argv[x], "-mysqldb") && x + 1 < argc) {
                honeymon->log->mysql_db = strdup(argv[x + 1]);
                x += 2;
            } else if (!strcmp(argv[x], "-mysqlport") && x + 1 < argc) {
                honeymon->log->mysql_port = atoi(argv[x + 1]);
                x += 2;
            } else if (!strcmp(argv[x], "--start-mysql")) {
                honeymon->log->mysql_enabled = 1;
                x++;
            } else if (!strcmp(argv[x], "--list-loaded")) {
                honeymon->interactive = 0;
                honeymon->action = 2;
                x++;
            } else if (!strcmp(argv[x], "--list-honeypots")) {
                honeymon->interactive = 0;
                honeymon->action = 3;
                x++;
            } else if (!strcmp(argv[x], "-restore-origin") && x + 1 < argc) {
                honeymon->interactive = 0;
                honeymon->action = 4;
                honeymon->action_option = strdup(argv[x + 1]);
                x += 2;
            } else if (!strcmp(argv[x], "--start-tcp")) {
                honeymon->action = 5;
                x++;
            } else if (!strcmp(argv[x], "--stealthy")
                    || !strcmp(argv[x], "--unpaused-scans")) {
                honeymon->stealthy = 1;
                x++;
            } else if (!strcmp(argv[x], "--enable-guestfs")) {
                honeymon->guestfs_enable = 1;
                x++;
            } else if (!strcmp(argv[x], "-test") && x + 1 < argc) {
                honeymon->interactive = 0;
                honeymon->action = 100;
                honeymon->action_option = strdup(argv[x + 1]);
                x += 2;
            } else if (!strcmp(argv[x], "--test")) {

            } else {
                honeymon->interactive = 0;
                honeymon->action = 0;
                printf("Unrecognized option: %s. Aborting!\n", argv[x]);
                break;
            }

        } else {
            honeymon->interactive = 0;
            honeymon->action = 0;
            printf("Unrecognized option: %s. Aborting!\n", argv[x]);
            break;
        }
    }
}
