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

#include "vmi.h"
#include "log.h"

// post-write
void file_name_post_cb(vmi_instance_t vmi, vmi_event_t *event) {

    struct file_watch *watch = event->data;

    addr_t file_name = 0;
    uint16_t length = 0;
    uint16_t max = 0;
    if(PM2BIT(watch->clone->pm)==BIT32) {
        struct unicode_string_x32 us;
        vmi_read_pa(vmi, watch->file_name, &us, sizeof(struct unicode_string_x32));
        file_name = us.buffer;
        length = us.length;
        max = us.maximum_length;
    } else {
        struct unicode_string_x64 us;
        vmi_read_pa(vmi, watch->file_name, &us, sizeof(struct unicode_string_x64));
        file_name = us.buffer;
        length = us.length;
        max = us.maximum_length;
    }

    if(file_name && length) {
        unicode_string_t str = {0};
        str.length = length;
        str.encoding = "UTF-16";
        str.contents = malloc(length);
        vmi_read_va(vmi,file_name,0,str.contents,length);

        unicode_string_t str2 = {0};
        vmi_convert_str_encoding(&str, &str2, "UTF-8");

        printf("\tFile accessed: %s\n", str2.contents);

        g_hash_table_remove(watch->clone->file_watch, &watch->pa);

        if(!g_tree_lookup(watch->clone->files_accessed, str2.contents)) {
            g_tree_insert(watch->clone->files_accessed, str2.contents, str2.contents);
        } else {
            free(str2.contents);
        }

        free(str.contents);
    }
}

// pre-write
void file_name_pre_cb(vmi_instance_t vmi, vmi_event_t *event) {
    vmi_clear_event(vmi, event);
    vmi_step_event(vmi, event, event->vcpu_id, 1, file_name_post_cb);
}

void pool_tracker(vmi_instance_t vmi, vmi_event_t *event, reg_t cr3) {
    // get the inputs of the function
    // TODO: x32 version, input is on the stack (rsp+4+...)
    reg_t pool_type, size, tag, rsp;
    vmi_get_vcpureg(vmi, &pool_type, RCX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &size, RDX, event->vcpu_id);
    vmi_get_vcpureg(vmi, &tag, R8, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rsp, RSP, event->vcpu_id);

    char *ctag = alloca(sizeof(char)*5);
    ctag[0] = (char)tag;
    ctag[1] = (char)*(((char *)&tag) + 1);
    ctag[2] = (char)*(((char *)&tag) + 2);
    ctag[3] = (char)*(((char *)&tag) + 3);
    ctag[4]=0;

    honeymon_clone_t *clone = event->data;
    struct pooltag *s = g_tree_lookup(clone->honeymon->pooltags, ctag);

    if(s) {
        //printf("\t\tKnown pool tag: %s, %s, %s. Pool type: %u. Size: %u. Return addr: 0x%lx\n", ctag, s->source, s->description, pool_type, size, rsp);

        // We are only going to watch File allocations for now
        if(strcmp("Fil\xe5", ctag)) return;

        // Get the return address of the function
        // It is pushed through the stack
        // and RSP is pointing at it right now as a VA
        vmi_pid_t pid = vmi_dtb_to_pid(vmi, cr3);
        addr_t ret_pa=0, ret_va=0;

        vmi_read_addr_va(vmi, rsp, pid, &ret_va);
        if(pid && pid != 4) {
            ret_pa = vmi_translate_uv2p(vmi, ret_va, pid);
        } else {
            ret_pa = vmi_translate_kv2p(vmi, ret_va);
        }

        struct pool_lookup *pool = g_hash_table_lookup(clone->pool_lookup, &ret_pa);
        if(pool) {
            pool->count++;
        } else {
            pool = malloc(sizeof(struct pool_lookup));
            pool->pa = ret_pa;
            pool->count=1;
            vmi_read_8_pa(vmi, pool->pa, &pool->backup);
            g_hash_table_insert(clone->pool_lookup, &pool->pa, pool);
        }

        // trap the return
        uint8_t trap = TRAP;
        vmi_write_8_pa(vmi, pool->pa, &trap);
    } else {
        //printf("\t\tUnknown pool tag: %s \\x%x\\x%x\\x%x\\x%x. Pool type: %u. Size: %u. Return addr: 0x%lx\n", ctag, ctag[0], ctag[1], ctag[2], ctag[3], pool_type, size, rsp);
    }
}

/*
 * The memory allocated by ExAllocatePoolWithTag is unitialized.
 * The only header that has been created is the _POOL_HEADER
 * located right before the address that has been returned in RAX.
 * For regular allocations the _POOL_HEADER will be followed by
 * optional object headers. The actual object will be at the
 * bottom of the allocation (base of _POOL_HEADER + pool block size - sizeof(object));
 * We need to grab the block size from the _POOL_HEADER and work our
 * way back from there.
 *
 * See: http://www.codemachine.com/article_objectheader.html
 *
 * With Windows 8 this approach will need to be reexamined.
 */
void pool_alloc_return(vmi_instance_t vmi, vmi_event_t *event, addr_t pa, reg_t cr3, char *ts, struct pool_lookup *s) {

    honeymon_clone_t *clone = event->data;
    vmi_pid_t pid = vmi_dtb_to_pid(vmi, cr3);

    reg_t rax;
    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);

    //printf("%s Pool allocation return @ 0x%lx. Trap count: %u. Value: 0x%lx\n", ts, pa, s->count, rax);

    s->count--;

    vmi_write_8_pa(vmi, pa, &s->backup);

    if(s->count == 0) {
        g_hash_table_remove(clone->pool_lookup, &pa);
    } else {
        clone->trap_reset = pa;
        vmi_clear_event(vmi, event);
        event->interrupt_event.enabled = 1;
        event->interrupt_event.reinject = 0;
        vmi_step_event(vmi, event, event->vcpu_id, 1, vmi_reset_trap);
    }

    // Create mem event to catch when the memory space of the struct gets written to
    addr_t obj_pa;
    if(pid && pid != 4) {
        obj_pa = vmi_translate_uv2p(vmi, rax, pid);
    } else {
        obj_pa = vmi_translate_kv2p(vmi, rax);
    }

    uint32_t block_size = 0;
    addr_t ph_base = 0;

    // Write events happen in two chunks
    addr_t last_write = 0;

    if(PM2BIT(clone->pm)==BIT32) {
        ph_base = obj_pa-sizeof(struct pool_header_x32);
        struct pool_header_x32 ph;
        vmi_read_pa(vmi, obj_pa-sizeof(struct pool_header_x32), &ph, sizeof(struct pool_header_x32));
        block_size = ph.block_size * 0x8; // align it
        last_write = 0x4;
    } else {
        ph_base = obj_pa-sizeof(struct pool_header_x64);
        struct pool_header_x64 ph;
        vmi_read_pa(vmi, obj_pa-sizeof(struct pool_header_x64), &ph, sizeof(struct pool_header_x64));
        block_size = ph.block_size * 0x10; // align it
        last_write = 0x8;
    }

    addr_t file_base = ph_base + block_size - sizes[VMI_OS_WINDOWS_7][PM2BIT(clone->pm)][FILE_OBJECT];
    addr_t file_name = file_base + offsets[VMI_OS_WINDOWS_7][PM2BIT(clone->pm)][FILE_OBJECT_FILENAME];
    last_write += file_name;

    //printf("PH 0x%lx. Block size: %u\n", ph_base, block_size);
    //printf("File base: 0x%lx. Unicode string @ 0x%lx. Last write @ 0x%lx\n", file_base, file_name, last_write);

    if(g_hash_table_lookup(clone->file_watch, &last_write)) return;

    struct file_watch *watch = g_malloc0(sizeof(struct file_watch));
    watch->vmi = vmi;
    watch->pa = last_write;
    watch->file_name = file_name;
    watch->pid = s->pid;
    watch->clone = clone;

    watch->event = g_malloc0(sizeof(vmi_event_t));
    SETUP_MEM_EVENT(watch->event, last_write, VMI_MEMEVENT_BYTE, VMI_MEMACCESS_W, file_name_pre_cb);
    watch->event->data = watch;
    if(VMI_FAILURE == vmi_register_event(vmi, watch->event)) {
        free(watch->event);
        free(watch);
        return;
    }
    g_hash_table_insert(clone->file_watch, &watch->pa, watch);
}
