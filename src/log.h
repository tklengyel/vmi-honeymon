#ifndef LOG_H
#define LOG_H

#include "log_mysql.h"

#define printdbg(...) g_printerr(__VA_ARGS__)

void honeymon_log_session(honeymon_t *honeymon, honeymon_clone_t *clone);
void honeymon_log_scan(honeymon_t *honeymon, honeymon_clone_t *clone,
        char *scan, char *result_type, char *result);
void honeymon_log_meminfo(honeymon_t *honeymon, uint32_t logIDX,
        uint64_t current_mem, uint64_t shared_mem, uint64_t paged_mem,
        uint64_t max_mem);
void honeymon_log_membenchmark(honeymon_t *honeymon, uint32_t logIDX,
        uint64_t current_mem, uint64_t shared_mem, uint64_t max_mem);
void honeymon_log_init_interface(honeymon_t *honeymon);
void honeymon_log_session_update(honeymon_t *honeymon, honeymon_clone_t *clone);

#endif
