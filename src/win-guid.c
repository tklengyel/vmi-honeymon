/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Tamas K Lengyel (tamas.lengyel@zentific.com)
 *
 * This file is part of LibVMI.
 *
 * LibVMI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * LibVMI is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <glib.h>

#include "win-guid.h"

#define PAGE_SIZE           0x1000
#define MAX_HEADER_SIZE     1024
#define MAX_SEARCH_SIZE     536715264 //512MB

#define NB09 0x3930424e // 90BN
#define NB10 0x3031424e // 01BN
#define NB11 0x3131424e // 11BN
#define RSDS 0x53445352 // SDSR

#define IMAGE_DEBUG_TYPE_UNKNOWN          0
#define IMAGE_DEBUG_TYPE_COFF             1
#define IMAGE_DEBUG_TYPE_CODEVIEW         2
#define IMAGE_DEBUG_TYPE_FPO              3
#define IMAGE_DEBUG_TYPE_MISC             4
#define IMAGE_DEBUG_TYPE_EXCEPTION        5
#define IMAGE_DEBUG_TYPE_FIXUP            6
#define IMAGE_DEBUG_TYPE_OMAP_TO_SRC      7
#define IMAGE_DEBUG_TYPE_OMAP_FROM_SRC    8
#define IMAGE_DEBUG_TYPE_BORLAND          9
#define IMAGE_DEBUG_TYPE_RESERVED10       10
#define IMAGE_DEBUG_TYPE_CLSID            11

struct image_debug_directory {
    uint32_t   characteristics;
    uint32_t   time_date_stamp;
    uint16_t   major_version;
    uint16_t   minor_version;
    uint32_t   type;
    uint32_t   size_of_data;
    uint32_t   address_of_raw_data;
    uint32_t   pointer_to_raw_data;
} __attribute__ ((packed));

struct guid {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t  data4[8];
} __attribute__ ((packed));

struct cv_info_pdb70 {
  uint32_t      cv_signature;
  struct guid   signature;
  uint32_t      age;
  uint8_t       pdb_file_name[];
} __attribute__ ((packed));

struct cv_info_nb10 {
    uint32_t cv_signature;
    uint32_t offset;
    uint32_t timestamp;
    uint32_t age;
    uint8_t  pdb_file_name[];
} __attribute__ ((packed));

status_t is_WINDOWS_KERNEL(vmi_instance_t vmi, addr_t base_p, uint8_t *pe) {

    status_t ret = VMI_FAILURE;

    void *optional_pe_header = NULL;
    uint16_t optional_header_type = 0;
    struct export_table et;

    peparse_assign_headers(pe, NULL, NULL, &optional_header_type, &optional_pe_header, NULL, NULL);
    addr_t export_header_offset = peparse_get_idd_rva(IMAGE_DIRECTORY_ENTRY_EXPORT, &optional_header_type, optional_pe_header, NULL, NULL);

    // The kernel's export table is continuously allocated on the PA level with the PE header
    // This trick may not work for other PE headers (though may work for some drivers)
    uint32_t nbytes = vmi_read_pa(vmi, base_p + export_header_offset, &et, sizeof(struct export_table));
    if(nbytes == sizeof(struct export_table) && !(et.export_flags || !et.name) ) {

        char *name = vmi_read_str_pa(vmi, base_p + et.name);

        if(name) {
            if(strcmp("ntoskrnl.exe", name)==0)
                ret = VMI_SUCCESS;

            free(name);
        }
    }

    return ret;
}

/*void print_os_version(vmi_instance_t vmi, addr_t kernel_base_p, uint8_t* pe) {

    uint16_t major_os_version;
    uint16_t minor_os_version;

    uint16_t optional_header_type = 0;
    struct optional_header_pe32 *oh32 = NULL;
    struct optional_header_pe32plus *oh32plus = NULL;

    peparse_assign_headers(pe, NULL, NULL, &optional_header_type, NULL, &oh32, &oh32plus);

    printf("\tVersion: ");

    if(optional_header_type == IMAGE_PE32_MAGIC) {

        major_os_version=oh32->major_os_version;
        minor_os_version=oh32->minor_os_version;

        printf("32-bit");
    } else
    if(optional_header_type == IMAGE_PE32_PLUS_MAGIC) {

        major_os_version=oh32plus->major_os_version;
        minor_os_version=oh32plus->minor_os_version;

        printf("64-bit");
    }

    if(major_os_version == 3) {
        if (minor_os_version == 1)
                printf(" Windows NT 3.1");
        if (minor_os_version == 5)
                printf(" Windows NT 3.5");
    } else
    if(major_os_version == 4) {
            printf(" Windows NT 4.0");
    } else
    if(major_os_version == 5) {
        if (minor_os_version == 0)
                printf(" Windows 2000");
        if (minor_os_version == 1)
                printf(" Windows XP");
        if (minor_os_version == 2)
                printf(" Windows Server_2003");
    } else
    if(major_os_version == 6) {
        if (minor_os_version == 0)
                printf(" Windows Vista or Server 2008");
        if (minor_os_version == 1)
                printf(" Windows 7");
        if (minor_os_version == 2)
                printf(" Windows 8");
    } else {
            printf("OS version unknown or not Windows\n");
    }

    printf("\n");

}*/

status_t get_guid(vmi_instance_t vmi, addr_t base_vaddr, uint32_t pid, char **pe_guid, char **pdb_guid) {

    status_t ret=VMI_FAILURE;

    if(pe_guid==NULL || pdb_guid==NULL) return ret;

    uint8_t pe[MAX_HEADER_SIZE];

    if(VMI_FAILURE == peparse_get_image_virt(vmi, base_vaddr, pid, MAX_HEADER_SIZE, pe)) {
        printf("Failed to read PE header @ %u:0x%lx\n", pid, base_vaddr);
        return ret;
    }

    uint16_t major_os_version = 0;
    uint16_t minor_os_version = 0;
    uint32_t size_of_image = 0;

    struct pe_header *pe_header = NULL;
    uint16_t optional_header_type = 0;
    struct optional_header_pe32 *oh32 = NULL;
    struct optional_header_pe32plus *oh32plus = NULL;

    peparse_assign_headers(pe, NULL, &pe_header, &optional_header_type, NULL, &oh32, &oh32plus);
    addr_t debug_offset = peparse_get_idd_rva(IMAGE_DIRECTORY_ENTRY_DEBUG, NULL, NULL, oh32, oh32plus);

    if(optional_header_type == IMAGE_PE32_MAGIC) {

        major_os_version=oh32->major_os_version;
        minor_os_version=oh32->minor_os_version;
        size_of_image=oh32->size_of_image;
    } else
    if(optional_header_type == IMAGE_PE32_PLUS_MAGIC) {

        major_os_version=oh32plus->major_os_version;
        minor_os_version=oh32plus->minor_os_version;
        size_of_image=oh32plus->size_of_image;
    }

    struct image_debug_directory debug_directory;
    size_t read=vmi_read_va(vmi, base_vaddr + debug_offset, pid, (uint8_t *)&debug_directory, sizeof(struct image_debug_directory));

    if(read == sizeof(struct image_debug_directory)) {
        *pe_guid=malloc(snprintf(NULL,0,"%.8x%.5x", pe_header->time_date_stamp, size_of_image)+1);
        sprintf(*pe_guid, "%.8x%.5x", pe_header->time_date_stamp, size_of_image);
        ret = VMI_SUCCESS;
    }

    if(debug_directory.type != IMAGE_DEBUG_TYPE_CODEVIEW) {
        //printf("The header is not in CodeView format, it is in %u, unable to deal with that!\n", debug_directory.type);
        return ret;
    }

    struct cv_info_nb10  *pdb_nb10_header = NULL;
    struct cv_info_pdb70 *pdb_rsds_header = (struct cv_info_pdb70 *)malloc(debug_directory.size_of_data);
    vmi_read_va(vmi, base_vaddr + debug_directory.address_of_raw_data, pid, pdb_rsds_header, debug_directory.size_of_data);

    char * filename = NULL;

    if(pdb_rsds_header->cv_signature != RSDS) {
        if(pdb_rsds_header->cv_signature != NB10) {
            //printf("The CodeView debug information has to be in PDB 7.0 (RSDS) or NB10 format!\n");
            return ret;
        }

        pdb_nb10_header = (struct cv_info_nb10 *)pdb_rsds_header;

        *pdb_guid=(char*)g_malloc0(snprintf(NULL, 0, "%x%x", pdb_nb10_header->timestamp, pdb_nb10_header->age)+1);
        sprintf(*pdb_guid, "%x%x", pdb_nb10_header->timestamp, pdb_nb10_header->age);
        filename=(char*)strdup((char *)pdb_nb10_header->pdb_file_name);

    } else {
        *pdb_guid=(char*)g_malloc0(snprintf(NULL, 0,
            "%.8x%.4x%.4x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.1x",
            pdb_rsds_header->signature.data1, pdb_rsds_header->signature.data2, pdb_rsds_header->signature.data3,
            pdb_rsds_header->signature.data4[0], pdb_rsds_header->signature.data4[1], pdb_rsds_header->signature.data4[2],
            pdb_rsds_header->signature.data4[3], pdb_rsds_header->signature.data4[4], pdb_rsds_header->signature.data4[5],
            pdb_rsds_header->signature.data4[6], pdb_rsds_header->signature.data4[7],
            pdb_rsds_header->age & 0xf
            )+1);

        sprintf(*pdb_guid, "%.8x%.4x%.4x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.1x",
            pdb_rsds_header->signature.data1, pdb_rsds_header->signature.data2, pdb_rsds_header->signature.data3,
            pdb_rsds_header->signature.data4[0], pdb_rsds_header->signature.data4[1], pdb_rsds_header->signature.data4[2],
            pdb_rsds_header->signature.data4[3], pdb_rsds_header->signature.data4[4], pdb_rsds_header->signature.data4[5],
            pdb_rsds_header->signature.data4[6], pdb_rsds_header->signature.data4[7],
            pdb_rsds_header->age & 0xf);

        filename=(char*)strdup((char *)pdb_rsds_header->pdb_file_name);
    }

    //printf("%s:%s:%s\n", filename, *pe_guid, *pdb_guid);

    ret=VMI_SUCCESS;

    free(pdb_rsds_header);
    free(filename);

    return ret;
}

