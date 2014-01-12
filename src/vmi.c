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
#include "vmi-poolmon.h"
#include "file_extractor.h"

void vmi_build_guid_tree(honeymon_t *honeymon) {
    honeymon->guids = g_tree_new((GCompareFunc)strcmp);
    uint32_t i;
    for(i=0;i<win7_sp1_x64_config_count;i++) {
        g_tree_insert(honeymon->guids, win7_sp1_x64_config[i].guids[0], &win7_sp1_x64_config[i]);
        g_tree_insert(honeymon->guids, win7_sp1_x64_config[i].guids[1], &win7_sp1_x64_config[i]);
    }
}

// This is the callback when an int3 or a read event happens
void vmi_reset_trap(vmi_instance_t vmi, vmi_event_t *event) {
    //add trap back
    uint8_t trap = TRAP;
    honeymon_clone_t *clone = event->data;
    vmi_write_8_pa(vmi, clone->trap_reset, &trap);
    clone->trap_reset = 0;
}

// This is the callback when an write event happens
void vmi_save_and_reset_trap(vmi_instance_t vmi, vmi_event_t *event) {
    uint8_t trap = TRAP;
    honeymon_clone_t *clone = event->data;
    struct symbolwrap *s = g_hash_table_lookup(clone->pa_lookup, &clone->trap_reset);
    //save the write
    vmi_read_8_pa(vmi, clone->trap_reset, &s->backup);
    //add trap back
    vmi_write_8_pa(vmi, clone->trap_reset, &trap);
    clone->trap_reset = 0;
}

void mem_event_cb(vmi_instance_t vmi, vmi_event_t *event){

    honeymon_clone_t *clone = event->data;
    addr_t pa = (event->mem_event.gfn << 12) + event->mem_event.offset;

    struct symbolwrap *s = g_hash_table_lookup(clone->pa_lookup, &pa);

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
            printf("Read memaccess @ Symbol: %s!%s\n", s->config->name, s->symbol->name);
            vmi_write_8_pa(vmi, pa, &s->backup);
            clone->trap_reset = pa;
            vmi_step_event(vmi, event, event->vcpu_id, 1, vmi_reset_trap);
        }
        if(event->mem_event.out_access & VMI_MEMACCESS_W) {
            printf("Write memaccess @ Symbol: %s!%s\n", s->config->name, s->symbol->name);
            clone->trap_reset = pa;
            vmi_step_event(vmi, event, event->vcpu_id, 1, vmi_save_and_reset_trap);
        }
    } else {
        // Should not happen with BYTE events
        vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);
    }

    return;
}

void int3_cb(vmi_instance_t vmi, vmi_event_t *event) {

    char *ts = NULL;
    now(&ts);

    reg_t cr3;
    vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
    honeymon_clone_t *clone = event->data;
    addr_t pa = (event->interrupt_event.gfn<<12) + event->interrupt_event.offset;
    struct symbolwrap *s = g_hash_table_lookup(clone->pa_lookup, &pa);

    if(s) {
        //printf("%s DTB: %"PRIi32" PA=%"PRIx64" RIP=%"PRIx64" Symbol: %s!%s\n",
        //  ts, (int)cr3, pa, event->interrupt_event.gla, s->config->name, s->symbol->name);

        if(!strcmp(s->config->name,"ntkrnlmp")) {
            if(!strncmp(s->symbol->name, "ExAllocatePoolWithTag", 21) || !strcmp(s->symbol->name, "ExAllocatePoolWithQuotaTag")) {
                pool_tracker(vmi, event, cr3);
            }

            if(!strcmp(s->symbol->name, "NtDeleteFile") || !strcmp(s->symbol->name, "ZwDeleteFile") ||
               !strcmp(s->symbol->name, "NtSetInformationFile") || !strcmp(s->symbol->name, "ZwSetInformationFile")
            ) {
                grab_file_before_delete(vmi, event, cr3, s);
            }
        }

        // remove trap
        vmi_write_8_pa(vmi, pa, &s->backup);

        vmi_clear_event(vmi, event);
        event->interrupt_event.enabled = 1;
        event->interrupt_event.reinject = 0;
        clone->trap_reset = pa;
        vmi_step_event(vmi, event, event->vcpu_id, 1, vmi_reset_trap);
    } else {
        struct pool_lookup *pool = g_hash_table_lookup(clone->pool_lookup, &pa);
        if(pool) {
            pool_alloc_return(vmi, event, pa, cr3, ts, pool);
        } else {
            printf("%s Unknown Int3 event: DTB: %"PRIi32" PA=%"PRIx64" RIP=%"PRIx64"\n",
                ts, (int)cr3,pa, event->interrupt_event.gla);
            event->interrupt_event.reinject = 1;
        }
    }

    g_free(ts);
}

void inject_traps_pe(honeymon_clone_t *clone, addr_t vaddr, uint32_t pid) {

    vmi_instance_t vmi = clone->vmi;
    uint8_t trap = TRAP;

    char *pe_guid = NULL, *pdb_guid = NULL;
    get_guid(vmi, vaddr, pid, &pe_guid, &pdb_guid);

    //printf("\t\tPE: %s PDB: %s\n", pe_guid, pdb_guid);

    GTree *guid_lookup = clone->honeymon->guids;

        struct config *config = NULL;
        if(pdb_guid) {
            config=g_tree_lookup(guid_lookup, pdb_guid);
        } else if(pe_guid) {
            config=g_tree_lookup(guid_lookup, pe_guid);
        }

        if(config) {
            uint32_t i=0;
            uint64_t trapped = 0;
            for(; i < *(config->sym_count); i++) {

                // skip symbols starting with _ (latency)
                if(config->syms[i].name[0] == 0x5f)
                    continue;

                // only trap Nt* functions in ntdll (latency)
                if(!strcmp(config->name, "ntdll")) {
                    if(strncmp(config->syms[i].name, "Nt", 2)) // && strncmp(s->conf->syms[i].name, "Zw", 2))
                        continue;
                }

                //DEBUG
                if(strcmp(config->name, "ntkrnlmp")) continue;

                // get pa
                addr_t pa =0;
                uint8_t byte = 0;

                if(!pid || pid == 4) {
                    pa = vmi_translate_kv2p(vmi, vaddr + config->syms[i].rva);
                } else {
                    pa = vmi_translate_uv2p(vmi, vaddr + config->syms[i].rva, pid);
                }

                // check if pa is valid and if already marked
                if(!pa || g_hash_table_lookup(clone->pa_lookup, &pa)) {
                    continue;
                }

                // backup current byte
                vmi_read_8_pa(vmi, pa, &byte);

                if(byte == TRAP) {
                    //printf("\n\n** PA IS ALREADY TRAPPED @ 0x%lx **\n\n", pa);
                    continue;
                }

                struct symbolwrap *wrap = g_malloc0(sizeof(struct symbolwrap));
                wrap->vmi = vmi;
                wrap->config = config;
                wrap->symbol = &config->syms[i];
                wrap->backup = byte;
                wrap->pa = pa;

                // write trap
                vmi_write_8_pa(vmi, pa, &trap);

                wrap->guard = g_malloc0(sizeof(vmi_event_t));
                SETUP_MEM_EVENT(wrap->guard, pa, VMI_MEMEVENT_BYTE, VMI_MEMACCESS_RW, mem_event_cb);
                wrap->guard->data = clone;
                if(VMI_FAILURE == vmi_register_event(vmi, wrap->guard)) {
                    free(wrap->guard);
                    wrap->guard = NULL;
                }

                // save trap location into lookup tree
                g_hash_table_insert(clone->pa_lookup, &wrap->pa, wrap);

                trapped++;
                printf("\t\tTrap added @ VA 0x%lx PA 0x%lx for %s!%s. Backup: 0x%x\n", vaddr + config->syms[i].rva, pa, config->name, config->syms[i].name, wrap->backup);
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

    printf("Vmi clone thread exiting\n");
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
        g_hash_table_destroy(config);
        vmi_destroy(clone->vmi);
        clone->vmi=NULL;
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

    // Crete tables to lokup symbols from
    clone->pa_lookup = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, free_symbolwrap);

    // Pool/file watcher tables
    clone->file_watch = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, free_file_watch);
    clone->pool_lookup = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, free);

    inject_traps(clone);
}

// -------------------------- closing

void free_symbolwrap(gpointer z) {
    struct symbolwrap *wrap = (struct symbolwrap *)z;
    // remove EPT guards
    if(wrap && wrap->vmi && wrap->guard) {
        vmi_clear_event(wrap->vmi, wrap->guard);
        // remove INT trap
        vmi_write_8_pa(wrap->vmi, wrap->pa, &wrap->backup);
        free(wrap->guard);
        free(wrap);
    }
}

void free_file_watch(gpointer z) {
    if(!z) return;
    struct file_watch *watch = (struct file_watch *)z;
    if(watch->event) {
        if(VMI_SUCCESS == vmi_clear_event(watch->vmi, watch->event))
            free(watch->event);
    }
    free(watch);
}

void close_vmi_clone(honeymon_clone_t *clone) {
    g_hash_table_destroy(clone->pa_lookup);
    g_hash_table_destroy(clone->pool_lookup);
    g_hash_table_destroy(clone->file_watch);
    if(clone->vmi) {
        vmi_destroy(clone->vmi);
        clone->vmi = NULL;
    }
    printf("close_vmi_clone finished\n");
}
