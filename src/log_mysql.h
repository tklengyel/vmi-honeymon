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
