/*
 * This file is part of the VMI-Honeymon project.
 *
 * 2012-2014 University of Connecticut (http://www.uconn.edu)
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

#include <libvmi/libvmi.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <glib.h>

#include "vmi.h"

/* this should work for both 32 and 64bit */
#define EX_FAST_REF_MASK    7
#define HANDLE_MULTIPLIER   4
#define PAGE_SIZE           0x1000

addr_t handle_table_get_entry(vmi_instance_t vmi, addr_t table_base, uint32_t level, uint32_t depth, uint32_t *handle_count, uint64_t handle) {

    uint32_t count;
    uint32_t level_entry_size;
    uint32_t obj_count = 0;
    uint32_t table_entry_size = 0;

    if(level > 0) {
        table_entry_size = 0x8; // TODO: 0x4 on 32-bit
    } else if (level == 0) {
        table_entry_size = 0x10; // TODO: 0x8 on 32-bit
    };

    count = PAGE_SIZE / table_entry_size;

    //printf("\tArray size: %u at 0x%lx. Table entry size is %u. Handle count remaining: %u\n", count, table_base, table_entry_size, *handle_count);

    uint32_t i;
    for(i=0;i<count;i++) {

        // Only read the already known number of entries
        if(*handle_count == 0)
            break;

        addr_t table_entry_addr = 0;
        vmi_read_addr_va(vmi, table_base + i*table_entry_size, 0, &table_entry_addr);

        // skip entries that point nowhere
        if(table_entry_addr == 0) {
            continue;
        }

        // real entries are further down the chain
        if(level > 0) {
            addr_t next_level = 0;
            vmi_read_addr_va(vmi, table_base + i*table_entry_size, 0, &next_level);

            addr_t test = 0;
            test = handle_table_get_entry(vmi, next_level, level-1, depth, handle_count, handle);
            if(test) return test;

            depth++;
            continue;
        }

        // At this point each (table_base + i*entry) is a _HANDLE_TABLE_ENTRY

        uint32_t level_base = depth * count * HANDLE_MULTIPLIER;
        uint32_t handle_value = (i*table_entry_size*HANDLE_MULTIPLIER)/table_entry_size + level_base;

        //printf("\t\tHandle #: %u. Addr: 0x%lx. Value: 0x%x\n", *handle_count, table_entry_addr & ~EX_FAST_REF_MASK, handle_value);

        if(handle_value == handle) {
            return table_entry_addr & ~EX_FAST_REF_MASK;
        }

        // decrement the handle counter because we found one here
        --(*handle_count);
    }
    return 0;
}

addr_t get_obj_by_handle(honeymon_clone_t *clone, vmi_instance_t vmi, vmi_pid_t target_pid, uint64_t handle) {

    addr_t current_process = 0, next_list_entry = 0, ret = 0;
    vmi_read_addr_ksym(vmi, "PsInitialSystemProcess", &current_process);

    addr_t list_head = current_process + offsets[VMI_OS_WINDOWS_7][PM2BIT(clone->pm)][EPROCESS_TASKS];
    addr_t current_list_entry = list_head;

    status_t status = vmi_read_addr_va(vmi, current_list_entry, 0, &next_list_entry);
    if (status == VMI_FAILURE) {
        //printf("Failed to read next pointer at 0x%"PRIx64" before entering loop\n",
        //        current_list_entry);
        return ret;
    }

    do {

        uint32_t pid;
        vmi_read_32_va(vmi, current_process + offsets[VMI_OS_WINDOWS_7][PM2BIT(clone->pm)][EPROCESS_PID], 0, &pid);

        if((int)pid == target_pid) {

            if(PM2BIT(clone->pm) == BIT64) {
                addr_t handletable=0, tablecode=0;
                vmi_read_addr_va(vmi, current_process+offsets[VMI_OS_WINDOWS_7][PM2BIT(clone->pm)][EPROCESS_OBJECTTABLE], 0, &handletable);
                vmi_read_addr_va(vmi, handletable, 0, &tablecode);

                uint32_t handlecount = 0;
                vmi_read_32_va(vmi, handletable+offsets[VMI_OS_WINDOWS_7][PM2BIT(clone->pm)][HANDLE_TABLE_HANDLECOUNT], 0, &handlecount);

                // _EX_FAST_REF-style pointer, last three bits are used for storing the number of levels
                addr_t table_base = tablecode & ~EX_FAST_REF_MASK;
                uint32_t table_levels = tablecode & EX_FAST_REF_MASK;
                uint32_t table_depth = 0;

                //printf("Handle table @ 0x%lx. Handle count %u. Looking for handle: 0x%lx\n", table_base, handlecount, handle);
                return handle_table_get_entry(vmi, table_base, table_levels, table_depth, &handlecount, handle);
            }

            return ret;
        }

        current_list_entry = next_list_entry;
        current_process = current_list_entry - offsets[VMI_OS_WINDOWS_7][PM2BIT(clone->pm)][EPROCESS_TASKS];

        status = vmi_read_addr_va(vmi, current_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE) {
            return ret;
        }

    } while (next_list_entry != list_head);

    return ret;
}
