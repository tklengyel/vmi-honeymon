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
#include "win-guid.h"
#include "vmi.h"

#include "win7_sp1_x64_config.h"

#define BIT32 0
#define BIT64 1
#define PM2BIT(pm) ((pm == VMI_PM_IA32E) ? BIT64 : BIT32)

#define TRAP 0xCC

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

gint intcmp(gconstpointer v1, gconstpointer v2,
        __attribute__((unused))      gconstpointer unused) {
    return (*(uint64_t *) v1 < (*(uint64_t *) v2) ? 1 :
            (*(uint64_t *) v1 == (*(uint64_t *) v2)) ? 0 : -1);
}

void inject_traps(honeymon_clone_t *clone) {

    vmi_instance_t vmi = clone->vmi;
    addr_t next_module, list_head;

    // Loop kernel modules
    vmi_read_addr_ksym(vmi, "PsLoadedModuleList", &next_module);
    list_head = next_module;

    while (1) {

        addr_t tmp_next = 0;
        vmi_read_addr_va(vmi, next_module, 0, &tmp_next);

        if (list_head == tmp_next) {
            break;
        }

        char *pe_guid = NULL, *pdb_guid = NULL;
        get_guid(vmi, next_module, 0, &pe_guid, &pdb_guid);

        struct sym_lookup *s = NULL;
        if(pdb_guid) {
            s=g_tree_lookup(clone->sym_lookup, pdb_guid);
        } else if(pe_guid) {
            s=g_tree_lookup(clone->sym_lookup, pe_guid);
        }

        if(s) {
            uint32_t i=0;
            uint8_t trap = TRAP;
            for(; i < *(s->conf->sym_count); i++) {
                //backup current byte
                vmi_read_8_va(vmi, next_module + s->conf->syms[i].rva, 0, &s->conf->syms[i].backup);

                //add trap
                vmi_write_8_va(vmi, next_module + s->conf->syms[i].rva, 0, &trap);

                printf("Trap added @ VA 0x%lx for %s!%s\n", next_module + s->conf->syms[i].rva, s->conf->name, s->conf->syms[i].name);
            }
        }

        g_free(pe_guid);
        g_free(pdb_guid);

        next_module = tmp_next;
    };
}

void *clone_vmi_thread(void *input) {
    pthread_exit(0);
    return NULL;
}

void clone_vmi_init(honeymon_clone_t *clone) {

    GHashTable *config = g_hash_table_new(g_str_hash, g_str_equal);
    g_hash_table_insert(config, "os_type", "Windows");
    g_hash_table_insert(config, "name", clone->clone_name);

    /* partialy initialize the libvmi library */
    if (vmi_init_custom(&clone->vmi, VMI_XEN | VMI_INIT_PARTIAL | VMI_CONFIG_GHASHTABLE, (vmi_config_t)config) == VMI_FAILURE) {
        return;
    }

    clone->pm=vmi_get_page_mode(clone->vmi);
    vmi_destroy(clone->vmi);

    //TODO: don't harcode VMI_OS_WINDOWS_7
    g_hash_table_insert(config, "win_tasks", &offsets[VMI_OS_WINDOWS_7][PM2BIT(clone->pm)][EPROCESS_TASKS]);
    g_hash_table_insert(config, "win_pdbase", &offsets[VMI_OS_WINDOWS_7][PM2BIT(clone->pm)][EPROCESS_PDBASE]);
    g_hash_table_insert(config, "win_pid", &offsets[VMI_OS_WINDOWS_7][PM2BIT(clone->pm)][EPROCESS_PID]);
    g_hash_table_insert(config, "win_pname", &offsets[VMI_OS_WINDOWS_7][PM2BIT(clone->pm)][EPROCESS_PNAME]);

    // Initialize the libvmi library.
    if (vmi_init_custom(&clone->vmi, VMI_XEN | VMI_INIT_COMPLETE | VMI_INIT_EVENTS | VMI_CONFIG_GHASHTABLE, (vmi_config_t)config) == VMI_FAILURE) {
        printf("Failed to init LibVMI library.\n");
        if (clone->vmi != NULL ) {
            vmi_destroy(clone->vmi);
        }
        return;
    }
    g_hash_table_destroy(config);


    // Crete Binary search trees to lokup symbols from
    clone->sym_lookup = g_tree_new((GCompareFunc)strcmp);

    if(PM2BIT(clone->pm) == BIT64) {
        uint32_t i=0;
        for(;i<win7_sp1_x64_config_count;i++) {
            struct sym_lookup *s = malloc(sizeof(struct sym_lookup));
            s->conf = &win7_sp1_x64_configs[i];
            s->rva_lookup = g_tree_new((GCompareFunc)intcmp);

            uint32_t z=0;
            for(; z < *(s->conf->sym_count) ; z++) {
                g_tree_insert(s->rva_lookup, &s->conf->syms[z].rva, s->conf->syms[z].name);
            }

            g_tree_insert(clone->sym_lookup, s->conf->guids[0], s);
            g_tree_insert(clone->sym_lookup, s->conf->guids[1], s);
        }
    }
}
