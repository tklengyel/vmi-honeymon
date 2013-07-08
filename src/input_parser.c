#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "structures.h"

void honeymon_input_parse(honeymon_t* honeymon, int argc, char **argv) {

    if (argc < 1 || (argc == 1 && strcmp(argv[0], "vmi-honeymon"))) return;

    int x = 1;
    while (x < argc) {
        if (strlen(argv[x]) > 1 && (int) (argv[x][0]) == 45) {

            if (!strcmp(argv[x], "-h") || !strcmp(argv[x], "--help")) {
                honeymon->interactive = 0;
                honeymon->action = 1;
            } else if (!strcmp(argv[x], "-volatility") && x + 1 < argc) {
                honeymon->volatility = strdup(argv[x + 1]);
                x += 2;
            } else if (!strcmp(argv[x], "-workdir") && x + 1 < argc) {
                // Remove tailing "/" from the workdir
                if ((int) (argv[x + 1][strlen(argv[x + 1]) - 1]) == 47) {
                    argv[x + 1][strlen(argv[x + 1]) - 1] = 0;
                }

                honeymon->workdir = strdup(argv[x + 1]);
                x += 2;
            } else if (!strcmp(argv[x], "-scanconf") && x + 1 < argc) {
                honeymon->scanconf = strdup(argv[x + 1]);
                x += 2;
            } else if (!strcmp(argv[x], "-scanschedule") && x + 1 < argc) {
                honeymon->scanscheduleconf = strdup(argv[x + 1]);
                x += 2;
            } else if (!strcmp(argv[x], "-scanpool") && x + 1 < argc) {
                honeymon->scanpool = atoi(argv[x + 1]);
                x += 2;
            } else if (!strcmp(argv[x], "-tcpport") && x + 1 < argc) {
                honeymon->tcp_port = atoi(argv[x + 1]);
                x += 2;
            } else if (!strcmp(argv[x], "-tcpif") && x + 1 < argc) {
                if (!strcmp(argv[x + 1], "localhost")) {
                    printf("Specify localhost with 127.0.0.1! Aborting!\n");
                    break;
                }
                free(honeymon->tcp_if);
                honeymon->tcp_if = strdup(argv[x + 1]);
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
            } else if (!strcmp(argv[x], "--membench")) {
                honeymon->membench = 1;
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
