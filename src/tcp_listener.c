#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "structures.h"
#include "honeypots.h"
#include "tcp_listener.h"
#include "xen_helper.h"

void *honeymon_tcp_handle_connection(void *arg) {

    honeymon_tcp_conn_t *conn_handler = (honeymon_tcp_conn_t *) arg;
    honeymon_t *honeymon = conn_handler->honeymon;

    FILE *fp = conn_handler->buffer; /* get & convert the data */
    char s[100];
    char delim[] = ",";
    char delim2[] = ".";

    /* proc client's requests */
    while (fgets(s, sizeof(s), fp) != 0) {

        char *nl = strrchr(s, '\r');
        if (nl) *nl = '\0';
        nl = strrchr(s, '\n');
        if (nl) *nl = '\0';

        printf("Incoming: %s\n", s); /* display message */
        if (!strcmp(s, "bye")) {
            break;
        }

        char *saveptr = NULL;
        char *first = strtok_r(s, delim, &saveptr);
        char *second = strtok_r(NULL, delim, &saveptr);
        char *third = strtok_r(NULL, delim, &saveptr);

        if (first == NULL) break;
        else if (!strcmp(first, "hello")) fputs("hi\n\r", fp);
        else if (!strcmp(first, "free")) {
            uint32_t free_clones = honeymon_honeypots_count_free_clones(
                    honeymon);
            char *reply = malloc(snprintf(NULL, 0, "%u\n\r", free_clones) + 1);
            sprintf(reply, "%u\n\r", free_clones);
            fputs(reply, fp);
            free(reply);
        } else if (!strcmp(first, "random")) {
            honeymon_clone_t *clone = honeymon_honeypots_get_random(honeymon);

            char *reply = NULL;

            if (clone != NULL) {

                reply = malloc(
                        snprintf(NULL, 0, "%s,%u,%u\n\r", clone->clone_name, clone->vlan, clone->logIDX) + 1);
                sprintf(reply, "%s,%u,%u\n\r", clone->clone_name, clone->vlan, clone->logIDX);

                honeymon_honeypots_unpause_clones2(NULL, clone, NULL);

                // Replace this clone in the buffer
                g_async_queue_push(clone->honeymon->clone_requests, strdup(clone->origin_name));

            } else {
                reply = malloc(snprintf(NULL, 0, "-\n\r") + 1);
                sprintf(reply, "-\n\r");
            }

            fputs(reply, fp);
            free(reply);
        } else if (third != NULL) {
            // network event!

            char *clone_name = first;
            char *attacker = second;
            char *conn_out = third;

            honeymon_clone_t *clone = honeymon_honeypots_find_clone(honeymon,
                    clone_name);

            if (clone == NULL) fputs("inactive\n\r", fp);
            else if (clone->paused) {
                fputs("paused\n\r", fp);
            } else {
                printf("Network event going to %s\n", conn_out);
                if (!clone->finish) {
                    if (g_mutex_trylock(&(clone->scan_lock))) {
                        // No scan is running right now, send signal!
                        g_cond_signal(&(clone->cond));
                        g_mutex_unlock(&(clone->scan_lock));
                    } else {
                        clone->finish = 1;
                    }
                } else {
                    // Clone is already scheduled for scan and destroy
                }
            }
        }
    }
    fclose(fp);

    printf("Closing TCP conn.\n");
    close(conn_handler->socket);

    free(conn_handler);
    return 0;
}

void honeymon_tcp_listener(void *arg) {

    honeymon_t *honeymon = (honeymon_t *) arg;

    struct sockaddr_in addr;
    int port;

    port = htons(honeymon->tcp_port);

    honeymon->tcp_socket = socket(PF_INET, SOCK_STREAM, 0);
    if (honeymon->tcp_socket < 0) {
        printf("Failed to create socket!\n");
        return;
    }

    int optval = 1;
    setsockopt(honeymon->tcp_socket, SOL_SOCKET, SO_REUSEADDR,
            (const void *) &optval, sizeof(int));

    /* Bind port/address to socket */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = port;

    if (!strcmp(honeymon->tcp_if, "any")) addr.sin_addr.s_addr = INADDR_ANY;
    else addr.sin_addr.s_addr = inet_addr(honeymon->tcp_if);

    if (bind(honeymon->tcp_socket, (struct sockaddr*) &addr, sizeof(addr))
            != 0) {
        printf("Couldn't bind to socket!\n");
        return;
    }

    /* Make into listener with 10 slots */
    if (listen(honeymon->tcp_socket, 10) != 0) {
        printf("Error creating TCP listener.\n");
        return;
    } else {

        honeymon->tcp_init = 1;

        while (1) {
            pthread_t c;
            struct sockaddr_in *c_addr = malloc(sizeof(struct sockaddr_in));
            memset(&c_addr, 0, sizeof(c_addr));

            socklen_t clilen = sizeof(c_addr);

            honeymon_tcp_conn_t *conn_handler = malloc(
                    sizeof(honeymon_tcp_conn_t));
            conn_handler->socket = accept(honeymon->tcp_socket,
                    (struct sockaddr *) c_addr, &clilen); /* accept connection */
            if (conn_handler->socket < 0) {
                //printf("Error on accept: %i!\n", conn_handler->socket);
                free(conn_handler);
            } else {

                conn_handler->buffer = fdopen(conn_handler->socket, "r+");
                conn_handler->client = c_addr;
                conn_handler->honeymon = honeymon;
                pthread_create(&c, NULL, honeymon_tcp_handle_connection,
                        (void *) conn_handler);
                pthread_detach(c);
            }
        }
    }
}

void honeymon_tcp_start_listener(honeymon_t *honeymon) {

    printf("Starting TCP listener on address %s and port %u!\n",
            honeymon->tcp_if, honeymon->tcp_port);

    pthread_t c;
    pthread_create(&c, NULL, (void *) honeymon_tcp_listener, (void *) honeymon);
    //pthread_detach(c);
}
