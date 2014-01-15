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
#include <stdlib.h>
#include <sys/prctl.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <glib.h>
#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>

#include "vmi.h"
#include "win-syms.h"

#define MAX_HEADER_SIZE 1024

// search for the given module+symbol in the given module list
status_t modlist_sym2va(
    vmi_instance_t vmi,
    addr_t list_head,
    uint32_t pid,
    const char *mod_name,
    const char *symbol,
    addr_t *va)
{

    page_mode_t pm=vmi_get_page_mode(vmi);
    win_ver_t winver = vmi_get_winver(vmi);
    addr_t next_module=list_head;
    /* walk the module list */
    while (1) {

        /* follow the next pointer */
        addr_t tmp_next = 0;
        vmi_read_addr_va(vmi, next_module, pid, &tmp_next);

        /* if we are back at the list head, we are done */
        if (list_head == tmp_next || !tmp_next) {
            break;
        }
        unicode_string_t *us =
                vmi_read_unicode_str_va(vmi, next_module + offsets[winver][PM2BIT(pm)][LDR_DATA_TABLE_ENTRY_BASEDLLNAME], pid);
        unicode_string_t out = { 0 };

        if (us && VMI_SUCCESS == vmi_convert_str_encoding(us, &out, "UTF-8")) {

            //printf("Has %s\n", out.contents);

            if(!strcasecmp((char*)out.contents, mod_name)) {

                addr_t dllbase;
                vmi_read_addr_va(vmi, next_module+offsets[winver][PM2BIT(pm)][LDR_DATA_TABLE_ENTRY_DLLBASE], pid, &dllbase);

                *va=vmi_translate_sym2v(vmi, dllbase, pid, (char *)symbol);

                //printf("\t%s @ 0x%lx\n", symbol, *va);

                free(out.contents);
                vmi_free_unicode_str(us);
                return VMI_SUCCESS;
            }

            free(out.contents);
        }

        if (us) vmi_free_unicode_str(us);

        next_module = tmp_next;
    }

    return VMI_FAILURE;
}

addr_t sym2va(vmi_instance_t vmi,
    vmi_pid_t target_pid,
    const char *mod_name,
    const char *symbol)
{
    addr_t ret=0;
    addr_t list_head;
    status_t status;

        page_mode_t pm=vmi_get_page_mode(vmi);
        win_ver_t winver = vmi_get_winver(vmi);
        size_t pid_offset=vmi_get_offset(vmi, "win_pid");
        size_t tasks_offset=vmi_get_offset(vmi, "win_tasks");

        addr_t current_process, current_list_entry, next_list_entry;
        vmi_read_addr_ksym(vmi, "PsInitialSystemProcess", &current_process);

        /* walk the task list */
        list_head = current_process + tasks_offset;
        current_list_entry = list_head;

        status = vmi_read_addr_va(vmi, current_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE) {
            printf("Failed to read next pointer at 0x%lx before entering loop\n",
                    current_list_entry);
            return ret;
        }

        do {
            current_list_entry = next_list_entry;
            current_process = current_list_entry - tasks_offset;

            /* follow the next pointer */

            addr_t peb, ldr, inloadorder;
            vmi_pid_t pid;
            vmi_read_32_va(vmi, current_process + pid_offset, 0, &pid);

            if(pid==target_pid) {

                vmi_read_addr_va(vmi, current_process+offsets[winver][PM2BIT(pm)][EPROCESS_PEB], 0, &peb);
                vmi_read_addr_va(vmi, peb+offsets[winver][PM2BIT(pm)][PEB_LDR], pid, &ldr);
                vmi_read_addr_va(vmi, ldr+offsets[winver][PM2BIT(pm)][PEB_LDR_DATA_INLOADORDERMODULELIST], pid, &inloadorder);

                //printf("Found target pid of %u. PEB @ 0x%lx. LDR @ 0x%lx. INLOADORDER @ 0x%lx.\n",
                //    target_pid, peb, ldr, inloadorder);

                if(VMI_SUCCESS==modlist_sym2va(vmi, inloadorder, pid, mod_name, symbol, &ret)) {
                    return ret;
                }
            }

            status = vmi_read_addr_va(vmi, current_list_entry, 0, &next_list_entry);
            if (status == VMI_FAILURE) {
                printf("Failed to read next pointer in loop at %lx\n", current_list_entry);
                return ret;
            }
        } while (next_list_entry != list_head);

    return ret;
}

// search for the given module+symbol in the given module list
status_t modlist_va2sym(
    vmi_instance_t vmi,
    addr_t list_head,
    addr_t va,
    vmi_pid_t pid,
    char **out_mod,
    char **out_sym)
{

    page_mode_t pm=vmi_get_page_mode(vmi);
    win_ver_t winver = vmi_get_winver(vmi);
    addr_t next_module=list_head;
    /* walk the module list */
    while (1) {

        /* follow the next pointer */
        addr_t tmp_next = 0;
        vmi_read_addr_va(vmi, next_module, pid, &tmp_next);

        /* if we are back at the list head, we are done */
        if (list_head == tmp_next || !tmp_next) {
            break;
        }
        unicode_string_t *us =
                vmi_read_unicode_str_va(vmi, next_module + offsets[winver][PM2BIT(pm)][LDR_DATA_TABLE_ENTRY_BASEDLLNAME], pid);
        unicode_string_t out = { 0 };

        if (us && VMI_SUCCESS == vmi_convert_str_encoding(us, &out, "UTF-8")) {
            addr_t dllbase;
            vmi_read_addr_va(vmi, next_module+offsets[winver][PM2BIT(pm)][LDR_DATA_TABLE_ENTRY_DLLBASE], pid, &dllbase);

            const char *sym=vmi_translate_v2sym(vmi, dllbase, pid, va);
            if(sym) {
                *out_mod = g_strdup(out.contents);
                *out_sym = (char*)sym;
                free(out.contents);
                vmi_free_unicode_str(us);
                return VMI_SUCCESS;
            } else {
                free(out.contents);
            }
        }

        if (us) vmi_free_unicode_str(us);

        next_module = tmp_next;
    }

    return VMI_FAILURE;
}

status_t va2sym(vmi_instance_t vmi, addr_t va, vmi_pid_t target_pid, char **out_mod, char **out_sym) {

    addr_t list_head;

        page_mode_t pm=vmi_get_page_mode(vmi);
        win_ver_t winver = vmi_get_winver(vmi);
        size_t pid_offset=vmi_get_offset(vmi, "win_pid");
        size_t tasks_offset=vmi_get_offset(vmi, "win_tasks");

        addr_t current_process, current_list_entry, next_list_entry;
        vmi_read_addr_ksym(vmi, "PsInitialSystemProcess", &current_process);

        /* walk the task list */
        list_head = current_process + tasks_offset;
        current_list_entry = list_head;

        if(VMI_FAILURE == vmi_read_addr_va(vmi, current_list_entry, 0, &next_list_entry)) {
            printf("Failed to read next pointer at 0x%lx before entering loop\n",
                    current_list_entry);
            return VMI_FAILURE;
        }

        do {
            current_list_entry = next_list_entry;
            current_process = current_list_entry - tasks_offset;

            /* follow the next pointer */

            addr_t peb, ldr, inloadorder;
            vmi_pid_t pid;
            vmi_read_32_va(vmi, current_process + pid_offset, 0, &pid);

            if(pid==target_pid) {

                vmi_read_addr_va(vmi, current_process+offsets[winver][PM2BIT(pm)][EPROCESS_PEB], 0, &peb);
                vmi_read_addr_va(vmi, peb+offsets[winver][PM2BIT(pm)][PEB_LDR], pid, &ldr);
                vmi_read_addr_va(vmi, ldr+offsets[winver][PM2BIT(pm)][PEB_LDR_DATA_INLOADORDERMODULELIST], pid, &inloadorder);

                if(VMI_SUCCESS==modlist_va2sym(vmi, inloadorder, va, pid, out_mod, out_sym)) {
                    return VMI_SUCCESS;
                }
            }

            if(VMI_FAILURE == vmi_read_addr_va(vmi, current_list_entry, 0, &next_list_entry)) {
                printf("Failed to read next pointer in loop at %lx\n", current_list_entry);
                return VMI_FAILURE;
            }
        } while (next_list_entry != list_head);

    return VMI_FAILURE;
}
