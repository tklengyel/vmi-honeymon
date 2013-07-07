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
        if (nl)
            *nl = '\0';
        nl = strrchr(s, '\n');
        if (nl)
            *nl = '\0';

        printf("Incoming: %s\n", s); /* display message */
        if (!strcmp(s, "bye")) {
            break;
        }

        char *first = strtok(s, delim);
        char *second = strtok(NULL, delim);
        char *third = strtok(NULL, delim);
        //fputs(s, fp);                             /* echo it back */

        if (first == NULL)
            break;
        else if (!strcmp(first, "hello"))
            fputs("hi\n\r", fp);
        else if (!strcmp(first, "free")) {
            uint32_t free_clones = honeymon_honeypots_count_free_clones(
                    honeymon);
            char *reply = malloc(snprintf(NULL, 0, "%u\n\r", free_clones) + 1);
            sprintf(reply, "%u\n\r", free_clones);
            fputs(reply, fp);
            free(reply);
        } else if (!strcmp(first, "listening")) {
            pthread_mutex_lock(&(honeymon->revert_queue_lock));

            if (honeymon->revert_queue == NULL) {
                pthread_cond_wait(&(honeymon->revert_queue_cond),
                        &(honeymon->revert_queue_lock));
            }

            char *reply = malloc(
                    snprintf(NULL, 0, "reverted,%s\n\r",
                            (char *) honeymon->revert_queue->data) + 1);
            sprintf(reply, "reverted,%s\n\r",
                    (char *) honeymon->revert_queue->data);

            printf("Sending revert info of %s\n",
                    (char *) honeymon->revert_queue->data);

            free((char *) honeymon->revert_queue->data);
            honeymon->revert_queue = g_slist_delete_link(honeymon->revert_queue,
                    honeymon->revert_queue);

            pthread_mutex_unlock(&(honeymon->revert_queue_lock));

            fputs(reply, fp);
            free(reply);
        } else if (!strcmp(first, "random")) {
            honeymon_clone_t *clone = honeymon_honeypots_get_random(honeymon);

            char *reply = NULL;

            if (clone != NULL) {
                reply = malloc(
                        snprintf(NULL, 0, "%s\n\r", clone->clone_name) + 1);
                sprintf(reply, "%s\n\r", clone->clone_name);
            } else {
                reply = malloc(snprintf(NULL, 0, "-\n\r") + 1);
                sprintf(reply, "-\n\r");
            }

            fputs(reply, fp);
            free(reply);
        } else if (second == NULL)
            break;
        else if (!strcmp(first, "status")) {
            // query vm state (paused/running/inactive)

            char *clone_name = second;
            honeymon_clone_t *clone = honeymon_honeypots_find_clone(honeymon,
                    clone_name);

            if (clone == NULL) {
                //printf("Clone is null, inactive\n");
                fputs("inactive\n\r", fp);
            } else {
                if (clone->paused) {
                    //printf("Clone found, paused sent\n");
                    fputs("paused\n\r", fp);
                } else {
                    //printf("Clone found, active sent\n");
                    fputs("active\n\r", fp);
                }
            }
        } else if (!strcmp(first, "pause")) {
            char *clone_name = second;
            honeymon_clone_t *clone = honeymon_honeypots_find_clone(honeymon,
                    clone_name);
            if (clone != NULL) {
                honeymon_honeypots_pause_clones2((gpointer) clone_name,
                        (gpointer) clone, NULL);
                //honeymon_honeypots_pause_clones3((gpointer)clone_name, (gpointer)clone, NULL);
                fputs("paused\n\r", fp);
            } else
                fputs("inactive\n\r", fp);
        } else if (!strcmp(first, "activate")) {
            char *clone_name = second;
            honeymon_clone_t *clone = honeymon_honeypots_find_clone(honeymon,
                    clone_name);
            if (clone != NULL) {
                honeymon_honeypots_unpause_clones2((gpointer) clone_name,
                        (gpointer) clone, NULL);
                char *reply = malloc(
                        snprintf(NULL, 0, "activated,%u\n\r", clone->logIDX)
                                + 1);
                sprintf(reply, "activated,%u\n\r", clone->logIDX);
                fputs(reply, fp);
                free(reply);
            } else
                fputs("inactive\n\r", fp);

        } else if (third != NULL) {
            // network event!

            char *clone_name = first;
            char *attacker = second;
            char *conn_out = third;

            honeymon_clone_t *clone = honeymon_honeypots_find_clone(honeymon,
                    clone_name);

            if (clone == NULL)
                fputs("inactive\n\r", fp);
            else if (clone->paused) {
                fputs("paused\n\r", fp);
            } else {
                printf("Network event going to %s\n", conn_out);
                if (!clone->revert) {
                    int rt = g_mutex_trylock(&(clone->scan_lock));
                    if (rt == 0) {
                        // No scan is running right now, send signal!
                        g_cond_signal(&(clone->cond));
                        g_mutex_unlock(&(clone->scan_lock));
                    } else {
                        // A scan is already running, revert it after its done!
                        clone->revert = 1;
                        clone->paused = 1;
                        libxl_domain_pause(honeymon->xen->xl_ctx, clone->domID);
                    }
                } else {
                    // Clone is already scheduled for scan and revert
                }
                /*printf("Waiting for results to send back..\n");
                 pthread_mutex_lock(&(clone->network_cond_lock));
                 pthread_cond_wait(&(clone->network_cond), &(clone->network_cond_lock));
                 pthread_mutex_unlock(&(clone->network_cond_lock));
                 fputs("reverted\n\r", fp);*/
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

    if (!strcmp(honeymon->tcp_if, "any"))
        addr.sin_addr.s_addr = INADDR_ANY;
    else
        addr.sin_addr.s_addr = inet_addr(honeymon->tcp_if);

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

    pthread_mutex_init(&(honeymon->revert_queue_lock), NULL);
    pthread_cond_init(&(honeymon->revert_queue_cond), NULL);

    pthread_t c;
    pthread_create(&c, NULL, (void *) honeymon_tcp_listener, (void *) honeymon);
    //pthread_detach(c);
}
