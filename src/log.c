#include <config.h>
#include <pthread.h>

#ifdef HAVE_MYSQL
#include <mysql.h>
#endif

#include "structures.h"
#include "log_mysql.h"

void honeymon_log_init_interface(honeymon_t *honeymon) {

    pthread_mutex_init(&(honeymon->log->log_IDX_lock), NULL);

#ifdef HAVE_MYSQL
    if (honeymon->log->mysql_enabled && honeymon->log->mysql_address != NULL
            && honeymon->log->mysql_user != NULL
            && honeymon->log->mysql_pass != NULL
            && honeymon->log->mysql_db != NULL) {
        honeymon_mysql_init(honeymon);
    }
#endif
}

void honeymon_log_free_interface(honeymon_t *honeymon) {

#ifdef HAVE_MYSQL

#endif

    pthread_mutex_destroy(&(honeymon->log->log_IDX_lock));
    free(honeymon->log);
}

void honeymon_log_session(honeymon_t *honeymon, honeymon_clone_t *clone) {

    if (honeymon->log->mysql_enabled) honeymon_mysql_log_session(honeymon,
            clone);

}

void honeymon_log_session_update(honeymon_t *honeymon, honeymon_clone_t *clone) {
    if (honeymon->log->mysql_enabled) honeymon_mysql_update_session(honeymon,
            clone);
}

void honeymon_log_scan(honeymon_t *honeymon, honeymon_clone_t *clone,
        char *scan, char *result_type, char *result) {
    if (honeymon->log->mysql_enabled) honeymon_mysql_log_scan(honeymon, clone,
            scan, result_type, result);
}

void honeymon_log_meminfo(honeymon_t *honeymon, uint32_t logIDX,
        uint64_t current_mem, uint64_t shared_mem, uint64_t paged_mem,
        uint64_t max_mem) {
    if (honeymon->log->mysql_enabled) honeymon_mysql_log_meminfo(honeymon,
            logIDX, current_mem, shared_mem, paged_mem, max_mem);
}

void honeymon_log_membenchmark(honeymon_t *honeymon, uint32_t logIDX,
        uint64_t current_mem, uint64_t shared_mem, uint64_t max_mem) {
    if (honeymon->log->mysql_enabled) honeymon_mysql_log_membenchmark(honeymon,
            logIDX, current_mem, shared_mem, max_mem);
}
