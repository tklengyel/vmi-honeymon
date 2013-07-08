#include <stdlib.h>

#ifdef HAVE_MYSQL
#include <my_global.h>
#include <mysql.h>
#endif

#include "structures.h"
#include "log.h"
#include "log_mysql.h"

void honeymon_mysql_init(honeymon_t *honeymon) {
#ifdef HAVE_MYSQL

    honeymon->log->mysql_conn = mysql_init(NULL);
    my_bool reconnect = 1;
    mysql_options(honeymon->log->mysql_conn, MYSQL_OPT_RECONNECT, &reconnect);
    pthread_mutex_init(&(honeymon->log->mysql_lock), NULL);

    if (honeymon->log->mysql_conn == NULL) {
        printf("Error %u: %s\n", mysql_errno(honeymon->log->mysql_conn),
                mysql_error(honeymon->log->mysql_conn));
        honeymon->log->mysql_enabled = 0;
        return;
    }

    printf("\tInitialized MySQL interface\n");

    if (mysql_real_connect(honeymon->log->mysql_conn,
            honeymon->log->mysql_address, honeymon->log->mysql_user,
            honeymon->log->mysql_pass, honeymon->log->mysql_db,
            honeymon->log->mysql_port, NULL, 0) == NULL) {
        printf("Error %u: %s\n", mysql_errno(honeymon->log->mysql_conn),
                mysql_error(honeymon->log->mysql_conn));
        honeymon->log->mysql_enabled = 0;
        return;
    }

    mysql_query(honeymon->log->mysql_conn,
            "SELECT MAX(session_IDX) FROM `sessions`");

    MYSQL_RES *result = mysql_store_result(honeymon->log->mysql_conn);
    if (result != NULL) {
        MYSQL_ROW row;
        if ((row = mysql_fetch_row(result))) {
            uint32_t num_fields = mysql_num_fields(result);
            if (num_fields == 1 && row[0]) {
                printf("\tGot max IDX %i from MySQL\n", atoi(row[0]));
                honeymon->log->log_IDX = atoi(row[0]);
            } else {
                printf("\tMySQL Table is empty, init log IDX to 1\n");
                honeymon->log->log_IDX = 1;
            }
        }
    } else {
        printf("\tFailed to init session IDX from MySQL table!\n");
        honeymon->log->mysql_enabled = 0;
    }

    mysql_free_result(result);
    //mysql_close(honeymon->log->mysql_conn);
#endif
}

void honeymon_mysql_log_session(honeymon_t *honeymon, honeymon_clone_t *clone) {
#ifdef HAVE_MYSQL
    struct timeval tp;
    gettimeofday(&tp, NULL);
    char *query = malloc(
            snprintf(NULL, 0,
                    "INSERT INTO `sessions` VALUES ('%u', '%s', '%u', '%li');",
                    clone->logIDX, clone->clone_name, clone->start_time,
                    tp.tv_sec) + 1);
    sprintf(query, "INSERT INTO `sessions` VALUES ('%u', '%s', '%u', '%li');",
            clone->logIDX, clone->clone_name, clone->start_time, tp.tv_sec);

    //printf("Session Query: %s\n", query);

    pthread_mutex_lock(&(honeymon->log->mysql_lock));
    mysql_ping(honeymon->log->mysql_conn);
    if (mysql_query(honeymon->log->mysql_conn, query)) printf(
            "Logging session to MySQL failed: %s\n",
            mysql_error(honeymon->log->mysql_conn));
    pthread_mutex_unlock(&(honeymon->log->mysql_lock));

    free(query);
#endif
}

void honeymon_mysql_update_session(honeymon_t *honeymon,
        honeymon_clone_t *clone) {
#ifdef HAVE_MYSQL
    struct timeval tp;
    gettimeofday(&tp, NULL);
    char *query = malloc(
            snprintf(NULL, 0,
                    "UPDATE `sessions` SET end='%li' WHERE session_IDX='%u';",
                    tp.tv_sec, clone->logIDX) + 1);
    sprintf(query, "UPDATE `sessions` SET end='%li' WHERE session_IDX='%u';",
            tp.tv_sec, clone->logIDX);

    //printf("Session Query: %s\n", query);

    pthread_mutex_lock(&(honeymon->log->mysql_lock));
    mysql_ping(honeymon->log->mysql_conn);
    if (mysql_query(honeymon->log->mysql_conn, query)) printf(
            "Updating session in MySQL failed: %s\n",
            mysql_error(honeymon->log->mysql_conn));
    pthread_mutex_unlock(&(honeymon->log->mysql_lock));

    free(query);
#endif
}

void honeymon_mysql_log_scan(honeymon_t *honeymon, honeymon_clone_t *clone,
        char *scan, char *result_type, char *result) {
#ifdef HAVE_MYSQL
    char *query =
            malloc(
                    snprintf(NULL, 0,
                            "INSERT INTO `scans` VALUES ('', \"%u\", \"%u\", \"%i\", \"%s\", \"%s\", \"%s\");",
                            clone->cscan - 1, clone->logIDX,
                            clone->scan_initiator, scan, result_type, result)
                            + 1);
    sprintf(query,
            "INSERT INTO `scans` VALUES ('', \"%u\", \"%u\", \"%i\", \"%s\", \"%s\", \"%s\");",
            clone->cscan - 1, clone->logIDX, clone->scan_initiator, scan,
            result_type, result);

    //printf("Query: %s\n", query);

    pthread_mutex_lock(&(honeymon->log->mysql_lock));
    mysql_ping(honeymon->log->mysql_conn);
    if (mysql_query(honeymon->log->mysql_conn, query)) printf(
            "Logging scan to MySQL failed: %s\n",
            mysql_error(honeymon->log->mysql_conn));
    pthread_mutex_unlock(&(honeymon->log->mysql_lock));

    free(query);
#endif
}

void honeymon_mysql_log_meminfo(honeymon_t *honeymon, uint32_t logIDX,
        uint64_t current_mem, uint64_t shared_mem, uint64_t paged_mem,
        uint64_t max_mem) {
#ifdef HAVE_MYSQL
    //printf("Saving meminfo to MySQL for session %u\n", logIDX);
    char *query =
            malloc(
                    snprintf(NULL, 0,
                            "INSERT INTO `meminfo` VALUES ('', %u, %lu, %lu, %lu, %lu);",
                            logIDX, current_mem, shared_mem, paged_mem, max_mem)
                            + 1);
    sprintf(query, "INSERT INTO `meminfo` VALUES ('', %u, %lu, %lu, %lu, %lu);",
            logIDX, current_mem, shared_mem, paged_mem, max_mem);

    //printf("Query: %s\n", query);

    pthread_mutex_lock(&(honeymon->log->mysql_lock));
    mysql_ping(honeymon->log->mysql_conn);
    if (mysql_query(honeymon->log->mysql_conn, query)) printf(
            "Logging scan to MySQL failed: %s\n",
            mysql_error(honeymon->log->mysql_conn));
    pthread_mutex_unlock(&(honeymon->log->mysql_lock));

    free(query);
#endif
}

void honeymon_mysql_log_membenchmark(honeymon_t *honeymon, uint32_t logIDX,
        uint64_t current_mem, uint64_t shared_mem, uint64_t max_mem) {
#ifdef HAVE_MYSQL
    //printf("Saving meminfo to MySQL for session %u\n", logIDX);
    char *query = malloc(
            snprintf(NULL, 0,
                    "INSERT INTO `membench` VALUES ('', %u, %lu, %lu, %lu);",
                    logIDX, current_mem, shared_mem, max_mem) + 1);
    sprintf(query, "INSERT INTO `membench` VALUES ('', %u, %lu, %lu, %lu);",
            logIDX, current_mem, shared_mem, max_mem);

    //printf("Query: %s\n", query);

    pthread_mutex_lock(&(honeymon->log->mysql_lock));
    mysql_ping(honeymon->log->mysql_conn);
    if (mysql_query(honeymon->log->mysql_conn, query)) printf(
            "Logging scan to MySQL failed: %s\n",
            mysql_error(honeymon->log->mysql_conn));
    pthread_mutex_unlock(&(honeymon->log->mysql_lock));

    free(query);
#endif
}
