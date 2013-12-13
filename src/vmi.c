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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <dirent.h>
#include <glib.h>
#include <err.h>

#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>

#include "structures.h"
#include "log.h"
#include "vmi.h"

#define BIT32 0
#define BIT64 1
#define PM2BIT(pm) ((pm == VMI_PM_IA32E) ? BIT64 : BIT32)

enum offset_t {
    EPROCESS_PID,
    EPROCESS_PDBASE,
    EPROCESS_PNAME,
    EPROCESS_TASKS,

    OFFSET_MAX
};

static size_t offsets[VMI_OS_WINDOWS_7+1][2][OFFSET_MAX] = {
    [VMI_OS_WINDOWS_XP] =  {
        [BIT32] = {
        },
    },
    [VMI_OS_WINDOWS_7] = {
        [BIT32] = {
            [EPROCESS_PID]                      = 0xb4,
            [EPROCESS_PDBASE]                   = 0x18,
            [EPROCESS_TASKS]                    = 0xb8,
            [EPROCESS_PNAME]                    = 0x16c,
        },
        [BIT64] = {
            [EPROCESS_PID]                      = 0x180,
            [EPROCESS_PDBASE]                   = 0x28,
            [EPROCESS_TASKS]                    = 0x188,
            [EPROCESS_PNAME]                    = 0x2e0,
        }
    },
};

void *clone_vmi_thread(void *input) {

}

void clone_vmi_init(honeymon_clone_t *clone) {

    GHashTable *config = g_hash_table_new(g_str_hash, g_str_equal);
    g_hash_table_insert(config, "os_type", "Windows");
    g_hash_table_insert(config, "name", clone->clone_name);

    /* partialy initialize the libvmi library */
    if (vmi_init_custom(&clone->vmi, VMI_XEN | VMI_INIT_PARTIAL | VMI_CONFIG_GHASHTABLE, (vmi_config_t)config) == VMI_FAILURE) {
        return 0;
    }

    clone->pm=vmi_get_page_mode(clone->vmi);
    vmi_destroy(clone->vmi);

    g_hash_table_insert(config, "win_tasks", &offsets[clone->origin->winver][PM2BIT(clone->pm)][EPROCESS_TASKS]);
    g_hash_table_insert(config, "win_pdbase", &offsets[clone->origin->winver][PM2BIT(clone->pm)][EPROCESS_PDBASE]);
    g_hash_table_insert(config, "win_pid", &offsets[clone->origin->winver][PM2BIT(clone->pm)][EPROCESS_PID]);
    g_hash_table_insert(config, "win_pname", &offsets[clone->origin->winver][PM2BIT(clone->pm)][EPROCESS_PNAME]);

    // Initialize the libvmi library.
    if (vmi_init_custom(&clone->vmi, VMI_XEN | VMI_INIT_COMPLETE | VMI_INIT_EVENTS | VMI_CONFIG_GHASHTABLE, (vmi_config_t)config) == VMI_FAILURE) {
        printf("Failed to init LibVMI library.\n");
        if (clone->vmi != NULL ) {
            vmi_destroy(clone->vmi);
        }
        return 0;
    }
    else{
        printf("LibVMI init succeeded!\n");
    }
    g_hash_table_destroy(config);

}
