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
    EPROCESS_PEB,

    PEB_IMAGEBASADDRESS,
    PEB_LDR,

    PEB_LDR_DATA_INLOADORDERMODULELIST,

    LDR_DATA_TABLE_ENTRY_DLLBASE,

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
            [EPROCESS_PEB]                      = 0x338,

            [PEB_IMAGEBASADDRESS]               = 0x10,
            [PEB_LDR]                           = 0x18,

            [PEB_LDR_DATA_INLOADORDERMODULELIST]= 0x10,

            [LDR_DATA_TABLE_ENTRY_DLLBASE]      = 0x30,
        }
    },
};

gint intcmp(gconstpointer v1, gconstpointer v2,
        __attribute__((unused))      gconstpointer unused) {
    return (*(uint64_t *) v1 < (*(uint64_t *) v2) ? 1 :
            (*(uint64_t *) v1 == (*(uint64_t *) v2)) ? 0 : -1);
}

void print_registers(vmi_instance_t vmi, unsigned long vcpu) {
    registers_t i=0;
    for(;i<TSC;i++) {
        reg_t reg=0;
        vmi_get_vcpureg(vmi, &reg, i, vcpu);
        printf("REG %i: 0x%lx\n", i, reg);
    }
}

// This is the callback when an int3 or a read event happens
void reset_trap(vmi_instance_t vmi, vmi_event_t *event) {
    //add trap back
    uint8_t trap = TRAP;
    honeymon_clone_t *clone = event->data;
    vmi_write_8_pa(vmi, clone->trap_reset, &trap);
    clone->trap_reset = 0;
}

// This is the callback when an write event happens
void save_and_reset_trap(vmi_instance_t vmi, vmi_event_t *event) {
    uint8_t trap = TRAP;
    honeymon_clone_t *clone = event->data;
    struct symbol *s = g_tree_lookup(clone->pa_lookup, &clone->trap_reset);
    //save the write
    vmi_read_8_pa(vmi, clone->trap_reset, &s->backup);
    //add trap back
    vmi_write_8_pa(vmi, clone->trap_reset, &trap);
    clone->trap_reset = 0;
}

void mem_event_cb(vmi_instance_t vmi, vmi_event_t *event){

    honeymon_clone_t *clone = event->data;
    addr_t pa = (event->mem_event.gfn << 12) + event->mem_event.offset;

    struct symbol *s = g_tree_lookup(clone->pa_lookup, &pa);

    vmi_clear_event(vmi, event);

    if(s) {
        /*printf("PA %"PRIx64" ACCESS: %c%c%c for GFN %"PRIx64" (offset %06"PRIx64") gla %016"PRIx64" (vcpu %u)\n",
            pa,
            (event->mem_event.out_access & VMI_MEMACCESS_R) ? 'r' : '-',
            (event->mem_event.out_access & VMI_MEMACCESS_W) ? 'w' : '-',
            (event->mem_event.out_access & VMI_MEMACCESS_X) ? 'x' : '-',
            event->mem_event.gfn,
            event->mem_event.offset,
            event->mem_event.gla,
            event->vcpu_id);*/

        if(event->mem_event.out_access & VMI_MEMACCESS_R) {
            printf("Read memaccess @ Symbol: %s!%s\n", s->conf->name, s->name);
            vmi_write_8_pa(vmi, pa, &s->backup);
            clone->trap_reset = pa;
            vmi_step_event(vmi, event, event->vcpu_id, 1, reset_trap);
        }
        if(event->mem_event.out_access & VMI_MEMACCESS_W) {
            printf("Write memaccess @ Symbol: %s!%s\n", s->conf->name, s->name);
            clone->trap_reset = pa;
            vmi_step_event(vmi, event, event->vcpu_id, 1, save_and_reset_trap);
        }
    } else {
        vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);
    }

    return;
}

void int3_cb(vmi_instance_t vmi, vmi_event_t *event) {

    reg_t cr3;
    vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
    vmi_pid_t pid = vmi_dtb_to_pid(vmi, cr3);
    honeymon_clone_t *clone = event->data;
    addr_t pa = (event->interrupt_event.gfn<<12) + event->interrupt_event.offset;
    struct symbol *s = g_tree_lookup(clone->pa_lookup, &pa);

    //print_registers(vmi, event->vcpu_id);

    if(s) {
        printf("PID: %"PRIi32" PA=%"PRIx64" RIP=%"PRIx64" Symbol: %s!%s\n",
          pid, pa, event->interrupt_event.gla, s->conf->name, s->name);

        // remove trap
        vmi_write_8_pa(vmi, pa, &s->backup);

        vmi_clear_event(vmi, event);
        event->interrupt_event.enabled = 1;
        event->interrupt_event.reinject = 0;
        clone->trap_reset = pa;
        vmi_step_event(vmi, event, event->vcpu_id, 1, reset_trap);
    } else {
        printf("Unknown Int3 event: PID: %"PRIi32" GFN=%"PRIx64" RIP=%"PRIx64"\n",
            pid, event->interrupt_event.gfn, event->interrupt_event.gla);
        event->interrupt_event.reinject = 1;
    }
}

void inject_traps_pe(honeymon_clone_t *clone, addr_t vaddr, uint32_t pid) {

    vmi_instance_t vmi = clone->vmi;
    uint8_t trap = TRAP;

        char *pe_guid = NULL, *pdb_guid = NULL;
        get_guid(vmi, vaddr, pid, &pe_guid, &pdb_guid);

        printf("\t\tPE: %s PDB: %s\n", pe_guid, pdb_guid);

        struct guid_lookup *s = NULL;
        if(pdb_guid) {
            s=g_tree_lookup(clone->guid_lookup, pdb_guid);
        } else if(pe_guid) {
            s=g_tree_lookup(clone->guid_lookup, pe_guid);
        }

        if(s) {
            uint32_t i=0;
            uint64_t trapped = 0;
            for(; i < *(s->conf->sym_count); i++) {

                // get pa
                addr_t pa =0;
                if(!pid) {
                    pa = vmi_translate_kv2p(vmi, vaddr + s->conf->syms[i].rva);
                } else {
                    pa = vmi_translate_uv2p(vmi, vaddr + s->conf->syms[i].rva, pid);
                }

                // check if pa is valid and if already marked
                if(!pa || g_tree_lookup(clone->pa_lookup, &pa)) {
                    continue;
                }

                // backup current byte
                vmi_read_8_pa(vmi, pa, &s->conf->syms[i].backup);

                // write trap
                vmi_write_8_pa(vmi, pa, &trap);

                // set the pa on this symbol
                s->conf->syms[i].pa = pa;

                // save trap location into lookup tree
                g_tree_insert(clone->pa_lookup, &s->conf->syms[i].pa, &s->conf->syms[i]);

                if(NULL == vmi_get_mem_event(vmi, pa, VMI_MEMEVENT_PAGE)) {
                    vmi_event_t *mem_event = g_malloc0(sizeof(vmi_event_t));
                    SETUP_MEM_EVENT(mem_event, pa, VMI_MEMEVENT_PAGE, VMI_MEMACCESS_RW, mem_event_cb);
                    mem_event->data = clone;
                    if(VMI_FAILURE == vmi_register_event(vmi, mem_event)) {
                        free(mem_event);
                    }
                }

                trapped++;
                //printf("\t\tTrap added @ VA 0x%lx PA 0x%lx for %s!%s. Backup: 0x%x\n", vaddr + s->conf->syms[i].rva, s->conf->syms[i].pa, s->conf->name, s->conf->syms[i].name, s->conf->syms[i].backup);
            }

            printf("\tInjected %lu traps into PE with GUID %s:%s\n", trapped, pe_guid, pdb_guid);
        }

        g_free(pe_guid);
        g_free(pdb_guid);
}

void inject_traps_modules(honeymon_clone_t *clone, addr_t list_head, vmi_pid_t pid) {

    printf("Inject traps in module list of PID %u\n", pid);

    vmi_instance_t vmi = clone->vmi;

    addr_t next_module = list_head;

    while (1) {

        addr_t tmp_next = 0;
        vmi_read_addr_va(vmi, next_module, pid, &tmp_next);

        if (list_head == tmp_next) {
            break;
        }

        addr_t dllbase = 0;
        vmi_read_addr_va(vmi, next_module + offsets[VMI_OS_WINDOWS_7][PM2BIT(clone->pm)][LDR_DATA_TABLE_ENTRY_DLLBASE], pid, &dllbase);

        if(!dllbase) {
            return;
        }

            unicode_string_t *us = NULL;
            if (VMI_PM_IA32E == vmi_get_page_mode(vmi)) {
                us = vmi_read_unicode_str_va(vmi, next_module + 0x58, pid);
            } else {
                us = vmi_read_unicode_str_va(vmi, next_module + 0x2c, pid);
            }

            unicode_string_t out = { 0 };
            if (us &&
                VMI_SUCCESS == vmi_convert_str_encoding(us, &out, "UTF-8")) {
                printf("\t%s\n", out.contents);
                free(out.contents);
            }   // if
            if (us) vmi_free_unicode_str(us);

        inject_traps_pe(clone, dllbase, pid);

        next_module = tmp_next;
    };
}

void inject_traps(honeymon_clone_t *clone) {

    vmi_instance_t vmi = clone->vmi;

    // Loop kernel modules
    addr_t kernel_list_head;
    vmi_read_addr_ksym(vmi, "PsLoadedModuleList", &kernel_list_head);
    inject_traps_modules(clone, kernel_list_head, 0);

    addr_t current_process = 0, next_list_entry = 0;
    vmi_read_addr_ksym(vmi, "PsInitialSystemProcess", &current_process);

    addr_t list_head = current_process + offsets[VMI_OS_WINDOWS_7][PM2BIT(clone->pm)][EPROCESS_TASKS];
    addr_t current_list_entry = list_head;

    status_t status = vmi_read_addr_va(vmi, current_list_entry, 0, &next_list_entry);
    if (status == VMI_FAILURE) {
        printf("Failed to read next pointer at 0x%"PRIx64" before entering loop\n",
                current_list_entry);
        return;
    }

    do {

        uint32_t pid;
        vmi_read_32_va(vmi, current_process + offsets[VMI_OS_WINDOWS_7][PM2BIT(clone->pm)][EPROCESS_PID], 0, &pid);

        addr_t imagebase=0, peb=0, ldr=0, modlist=0;
        vmi_read_addr_va(vmi, current_process+offsets[VMI_OS_WINDOWS_7][PM2BIT(clone->pm)][EPROCESS_PEB], 0, &peb);
        vmi_read_addr_va(vmi, peb+offsets[VMI_OS_WINDOWS_7][PM2BIT(clone->pm)][PEB_IMAGEBASADDRESS], pid, &imagebase);
        vmi_read_addr_va(vmi, peb+offsets[VMI_OS_WINDOWS_7][PM2BIT(clone->pm)][PEB_LDR], pid, &ldr);
        vmi_read_addr_va(vmi, ldr+offsets[VMI_OS_WINDOWS_7][PM2BIT(clone->pm)][PEB_LDR_DATA_INLOADORDERMODULELIST], pid, &modlist);

        if(pid != 4) {
            inject_traps_pe(clone, imagebase, pid);
            inject_traps_modules(clone, modlist, pid);
        }

        current_list_entry = next_list_entry;
        current_process = current_list_entry - offsets[VMI_OS_WINDOWS_7][PM2BIT(clone->pm)][EPROCESS_TASKS];

        /* follow the next pointer */

        status = vmi_read_addr_va(vmi, current_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE) {
            printf("Failed to read next pointer in loop at %"PRIx64"\n", current_list_entry);
            return;
        }

    } while (next_list_entry != list_head);

}

void *clone_vmi_thread(void *input) {

    printf("Started vmi clone thread\n");

    honeymon_clone_t *clone = (honeymon_clone_t *)input;
    vmi_event_t interrupt_event;
    memset(&interrupt_event, 0, sizeof(vmi_event_t));
    interrupt_event.type = VMI_EVENT_INTERRUPT;
    interrupt_event.interrupt_event.intr = INT3;
    interrupt_event.interrupt_event.enabled = 1;
    interrupt_event.callback = int3_cb;
    interrupt_event.data = clone;

    vmi_register_event(clone->vmi, &interrupt_event);

    vmi_resume_vm(clone->vmi);

    while (!clone->interrupted) {
        //printf("Waiting for events...\n");
        status_t status = vmi_events_listen(clone->vmi, 500);
        if (status != VMI_SUCCESS) {
            printf("Error waiting for events, quitting...\n");
            clone->interrupted = -1;
        }
    }

    pthread_exit(0);
    return NULL;
}

void clone_vmi_init(honeymon_clone_t *clone) {

    printf("Init VMI on %s\n", clone->clone_name);

    GHashTable *config = g_hash_table_new(g_str_hash, g_str_equal);
    g_hash_table_insert(config, "os_type", "Windows");
    g_hash_table_insert(config, "domid", &clone->domID);

    /* partialy initialize the libvmi library */
    if (vmi_init_custom(&clone->vmi, VMI_XEN | VMI_INIT_PARTIAL | VMI_CONFIG_GHASHTABLE, (vmi_config_t)config) == VMI_FAILURE) {
        clone->vmi = NULL;
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
        clone->vmi = NULL;
        return;
    }
    g_hash_table_destroy(config);

    // Crete Binary search trees to lokup symbols from
    clone->guid_lookup = g_tree_new_full((GCompareDataFunc)strcmp, NULL, NULL, free_guid_lookup);
    clone->pa_lookup = g_tree_new((GCompareFunc)intcmp);

    if(PM2BIT(clone->pm) == BIT64) {
        uint32_t i=0;
        for(;i<win7_sp1_x64_config_count;i++) {
            struct guid_lookup *s = g_malloc0(sizeof(struct guid_lookup));
            s->conf = &win7_sp1_x64_configs[i];
            s->rva_lookup = g_tree_new((GCompareFunc)intcmp);

            uint32_t z=0;
            for(; z < *(s->conf->sym_count) ; z++) {
                s->conf->syms[z].backup = s->conf->syms[z].pa = 0;
                s->conf->syms[z].conf = s->conf;
                g_tree_insert(s->rva_lookup, &s->conf->syms[z].rva, s->conf->syms[z].name);
            }

            g_tree_insert(clone->guid_lookup, s->conf->guids[0], s);
            g_tree_insert(clone->guid_lookup, s->conf->guids[1], s);
        }
    }

    inject_traps(clone);
}

// -------------------------- closing

void free_guid_lookup(gpointer z) {
    struct guid_lookup *s = (struct guid_lookup *)z;
    if(!s->free) {
        s->free++;
    } else {
        g_tree_destroy(s->rva_lookup);
        free(s);
        s=NULL;
    }
}

void close_vmi_clone(honeymon_clone_t *clone) {
    g_tree_destroy(clone->guid_lookup);
    g_tree_destroy(clone->pa_lookup);
    if(clone->vmi) {
        vmi_destroy(clone->vmi);
    }
}
