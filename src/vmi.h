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

#ifndef VMI_H
#define VMI_H

#include "structures.h"
#include "win7_sp1_x64_config.h"
#include "vmi-poolmon.h"

#define BIT32 0
#define BIT64 1
#define PM2BIT(pm) ((pm == VMI_PM_IA32E) ? BIT64 : BIT32)

#define TRAP 0xCC

#define ghashtable_foreach(table, i, key, val) \
        g_hash_table_iter_init(&i, table); \
        while(g_hash_table_iter_next(&i,(void**)&key,(void**)&val))

enum offset {
    EPROCESS_PID,
    EPROCESS_PDBASE,
    EPROCESS_PNAME,
    EPROCESS_TASKS,
    EPROCESS_PEB,
    EPROCESS_OBJECTTABLE,

    PEB_IMAGEBASADDRESS,
    PEB_LDR,

    PEB_LDR_DATA_INLOADORDERMODULELIST,

    LDR_DATA_TABLE_ENTRY_DLLBASE,

    FILE_OBJECT_DEVICEOBJECT,
    FILE_OBJECT_READACCESS,
    FILE_OBJECT_WRITEACCESS,
    FILE_OBJECT_DELETEACCESS,
    FILE_OBJECT_FILENAME,

    HANDLE_TABLE_HANDLECOUNT,

    KPCR_CURRENTTHREAD,

    KTHREAD_PROCESS,

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
            [EPROCESS_PEB]                      = 0x1a8,
            [EPROCESS_OBJECTTABLE]              = 0xf4,

            [PEB_IMAGEBASADDRESS]               = 0x8,
            [PEB_LDR]                           = 0xc,

            [PEB_LDR_DATA_INLOADORDERMODULELIST]= 0xc,

            [LDR_DATA_TABLE_ENTRY_DLLBASE]      = 0x18,

            [FILE_OBJECT_DEVICEOBJECT]          = 0x4,
            [FILE_OBJECT_READACCESS]            = 0x26,
            [FILE_OBJECT_WRITEACCESS]           = 0x27,
            [FILE_OBJECT_DELETEACCESS]          = 0x28,
            [FILE_OBJECT_FILENAME]              = 0x30,

            [HANDLE_TABLE_HANDLECOUNT]          = 0x30,

            [KPCR_CURRENTTHREAD]                = 0x124,

            [KTHREAD_PROCESS]                   = 0x150,

        },
        [BIT64] = {
            [EPROCESS_PID]                      = 0x180,
            [EPROCESS_PDBASE]                   = 0x28,
            [EPROCESS_TASKS]                    = 0x188,
            [EPROCESS_PNAME]                    = 0x2e0,
            [EPROCESS_PEB]                      = 0x338,
            [EPROCESS_OBJECTTABLE]              = 0x200,

            [PEB_IMAGEBASADDRESS]               = 0x10,
            [PEB_LDR]                           = 0x18,

            [PEB_LDR_DATA_INLOADORDERMODULELIST]= 0x10,

            [LDR_DATA_TABLE_ENTRY_DLLBASE]      = 0x30,

            [FILE_OBJECT_DEVICEOBJECT]          = 0x8,
            [FILE_OBJECT_READACCESS]            = 0x4a,
            [FILE_OBJECT_WRITEACCESS]           = 0x4b,
            [FILE_OBJECT_DELETEACCESS]          = 0x4c,
            [FILE_OBJECT_FILENAME]              = 0x58,

            [HANDLE_TABLE_HANDLECOUNT]          = 0x58,

            [KPCR_CURRENTTHREAD]                = 0x188,

            [KTHREAD_PROCESS]                   = 0x210,
        }
    },
};

enum size {
    FILE_OBJECT,

    SIZE_LIST_MAX
};

// Aligned object sizes
static size_t sizes[VMI_OS_WINDOWS_7+1][2][SIZE_LIST_MAX] = {
    [VMI_OS_WINDOWS_7] = {
        [BIT32] = {
        },
        [BIT64] = {
            [FILE_OBJECT] = 0xE0, // 0xd8 + 0x10 - 0x8
        },
    },
};

struct unicode_string_x86 {
    uint16_t length;
    uint16_t maximum_length;
    uint32_t buffer; // pointer
} __attribute__ ((packed));

struct unicode_string_x64 {
    uint16_t length;
    uint16_t maximum_length;
    uint32_t _unused;
    uint64_t buffer; // pointer
} __attribute__ ((packed));

struct object_attributes_x86 {
  uint32_t Length;
  uint32_t RootDirectory;
  uint32_t ObjectName;
  uint32_t Attributes;
  uint32_t SecurityDescriptor;
  uint32_t SecurityQualityOfService;
} __attribute__ ((packed));

struct object_attributes_x64 {
  uint64_t Length;
  uint64_t RootDirectory;
  uint64_t ObjectName;
  uint64_t Attributes;
  uint64_t SecurityDescriptor;
  uint64_t SecurityQualityOfService;
} __attribute__ ((packed));

struct object_header_win7_x32 {
    uint32_t pointer_count;
    union {
        uint32_t handle_count;
        uint32_t next_to_free; // void *
    };
    uint32_t lock; // _EX_PUSH_LOCK
    unsigned char type_index; // id in the typeindex array
    unsigned char trace_flags;
    unsigned char info_mask;
    unsigned char flags;
    union {
        uint32_t object_create_info; // _OBJECT_CREATE_INFORMATION *
        uint32_t quota_block_charged; // void*
    };
    uint32_t security_descriptor; // void*
//    uint64_t body; // _QUAD
};

struct object_header_win7_x64 {
    uint64_t pointer_count;
    union {
        uint64_t handle_counter;
        uint64_t next_to_free; // void *
    };
    uint64_t lock; //_EX_PUSH_LOCK
    unsigned char type_index; // id in the typeindex array
    unsigned char trace_flags;
    unsigned char info_mask;
    unsigned char flags;
    union {
        uint64_t object_create_info; // _OBJECT_CREATE_INFORMATION *
        uint64_t quota_block_charged; // void*
    };
    uint64_t security_descriptor; // void*
//    uint64_t body; // _QUAD
};

void vmi_build_guid_tree(honeymon_t *honeymon);

void *clone_vmi_thread(void *input);
void clone_vmi_init(honeymon_clone_t *clone);
void close_vmi_clone(honeymon_clone_t *clone);

void vmi_reset_trap(vmi_instance_t vmi, vmi_event_t *event);
void vmi_save_and_reset_trap(vmi_instance_t vmi, vmi_event_t *event);

void free_guid_lookup(gpointer s);
void free_symbolwrap(gpointer z);
void free_file_watch(gpointer z);
#endif
