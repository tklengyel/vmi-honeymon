#ifndef LOG_MYSQL_H
#define LOG_MYSQL_H

void honeymon_mysql_init(honeymon_t *honeymon);
void honeymon_mysql_log_membenchmark(honeymon_t *honeymon, uint32_t logIDX,
        uint64_t current_mem, uint64_t shared_mem, uint64_t max_mem);
void honeymon_mysql_log_meminfo(honeymon_t *honeymon, uint32_t logIDX,
        uint64_t current_mem, uint64_t shared_mem, uint64_t paged_mem,
        uint64_t max_mem);
void honeymon_mysql_log_scan(honeymon_t *honeymon, honeymon_clone_t *clone,
        char *scan, char *result_type, char *result);

void honeymon_mysql_update_session(honeymon_t *honeymon,
        honeymon_clone_t *clone);
void honeymon_mysql_log_session(honeymon_t *honeymon, honeymon_clone_t *clone);
#endif
