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

}

void print_guid(vmi_instance_t vmi, addr_t kernel_base_p, uint8_t* pe) {

    uint16_t major_os_version;
    uint16_t minor_os_version;
    uint32_t size_of_image;

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
    vmi_read_pa(vmi, kernel_base_p + debug_offset, (uint8_t *)&debug_directory, sizeof(struct image_debug_directory));

    printf("\tPE GUID: %.8x%.5x\n",pe_header->time_date_stamp,size_of_image);

    if(debug_directory.type == IMAGE_DEBUG_TYPE_MISC) {
        printf("This operating system uses .dbg instead of .pdb\n");
        return;
    } else
    if(debug_directory.type != IMAGE_DEBUG_TYPE_CODEVIEW) {
        printf("The header is not in CodeView format, unable to deal with that!\n");
        return;
    }

    struct cv_info_pdb70 *pdb_header = malloc(debug_directory.size_of_data);
    vmi_read_pa(vmi, kernel_base_p + debug_directory.address_of_raw_data, pdb_header, debug_directory.size_of_data);

    // The PDB header has to be PDB 7.0
    // http://www.debuginfo.com/articles/debuginfomatch.html
    if(pdb_header->cv_signature != RSDS) {
       printf("The CodeView debug information has to be in PDB 7.0 for the kernel!\n");
       return;
    }

     printf("\tPDB GUID: ");
     printf("%.8x", pdb_header->signature.data1);
     printf("%.4x", pdb_header->signature.data2);
     printf("%.4x", pdb_header->signature.data3);

     int c;
     for(c=0;c<8;c++) printf("%.2x", pdb_header->signature.data4[c]);

     printf("%.1x", pdb_header->age & 0xf);
     printf("\n");
     printf("\tKernel filename: %s\n", pdb_header->pdb_file_name);

     if(!strcmp("ntoskrnl.pdb", pdb_header->pdb_file_name)) {
        printf("\tSingle-processor without PAE\n");
     } else
     if(!strcmp("ntkrnlmp.pdb", pdb_header->pdb_file_name)) {
        printf("\tMulti-processor without PAE\n");
     } else
     if(!strcmp("ntkrnlpa.pdb", pdb_header->pdb_file_name)) {
        printf("\tSingle-processor with PAE (version 5.0 and higher)\n");
     } else
     if(!strcmp("ntkrpamp.pdb", pdb_header->pdb_file_name)) {
        printf("\tMulti-processor with PAE (version 5.0 and higher)\n");
     }

     free(pdb_header);
}*/

void get_guid(vmi_instance_t vmi, addr_t vaddr, vmi_pid_t pid, char **pe_guid, char **pdb_guid) {

    uint32_t size_of_image = 0;

    struct pe_header *pe_header = NULL;
    uint16_t optional_header_type = 0;
    struct optional_header_pe32 *oh32 = NULL;
    struct optional_header_pe32plus *oh32plus = NULL;

    uint8_t pe[MAX_HEADER_SIZE];
    vmi_read_va(vmi, vaddr, pid, pe, MAX_HEADER_SIZE);

    peparse_assign_headers(pe, NULL, &pe_header, &optional_header_type, NULL, &oh32, &oh32plus);
    addr_t debug_offset = peparse_get_idd_rva(IMAGE_DIRECTORY_ENTRY_DEBUG, NULL, NULL, oh32, oh32plus);

    if(optional_header_type == IMAGE_PE32_MAGIC) {
        size_of_image=oh32->size_of_image;
    } else
    if(optional_header_type == IMAGE_PE32_PLUS_MAGIC) {
        size_of_image=oh32plus->size_of_image;
    }

    struct image_debug_directory debug_directory;
    vmi_read_va(vmi, vaddr + debug_offset, pid, (uint8_t *)&debug_directory, sizeof(struct image_debug_directory));

    *pe_guid = g_malloc0(snprintf(NULL, 0, "%.8x%.5x", pe_header->time_date_stamp,size_of_image) + 1);
    sprintf(*pe_guid, "%.8x%.5x", pe_header->time_date_stamp,size_of_image);

    if(debug_directory.type == IMAGE_DEBUG_TYPE_MISC) {
        printf("This operating system uses .dbg instead of .pdb\n");
        return;
    } else
    if(debug_directory.type != IMAGE_DEBUG_TYPE_CODEVIEW) {
        printf("The header is not in CodeView format, unable to deal with that!\n");
        return;
    }

    struct cv_info_pdb70 *pdb_header = malloc(debug_directory.size_of_data);
    vmi_read_va(vmi, vaddr + debug_directory.address_of_raw_data, pid, pdb_header, debug_directory.size_of_data);

    // The PDB header has to be PDB 7.0
    // http://www.debuginfo.com/articles/debuginfomatch.html
    if(pdb_header->cv_signature != RSDS) {
       printf("The CodeView debug information has to be in PDB 7.0 for the kernel!\n");
       return;
    }

    char *format = "%.8x%.4x%.4x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.1x";
    *pdb_guid = g_malloc0(snprintf(NULL, 0, format,
            pdb_header->signature.data1,
            pdb_header->signature.data2,
            pdb_header->signature.data3,
            pdb_header->signature.data4[0],
            pdb_header->signature.data4[1],
            pdb_header->signature.data4[2],
            pdb_header->signature.data4[3],
            pdb_header->signature.data4[4],
            pdb_header->signature.data4[5],
            pdb_header->signature.data4[6],
            pdb_header->signature.data4[7],
            pdb_header->age & 0xf
        ) + 1);

    sprintf(*pdb_guid, format,
            pdb_header->signature.data1,
            pdb_header->signature.data2,
            pdb_header->signature.data3,
            pdb_header->signature.data4[0],
            pdb_header->signature.data4[1],
            pdb_header->signature.data4[2],
            pdb_header->signature.data4[3],
            pdb_header->signature.data4[4],
            pdb_header->signature.data4[5],
            pdb_header->signature.data4[6],
            pdb_header->signature.data4[7],
            pdb_header->age & 0xf
        );
}

void print_pe_header(vmi_instance_t vmi, addr_t image_base_p, uint8_t *pe) {

    struct pe_header *pe_header = NULL;
    struct dos_header *dos_header = NULL;
    uint16_t optional_header_type = 0;
    peparse_assign_headers(pe, &dos_header, &pe_header, &optional_header_type, NULL, NULL, NULL);

    printf("\tSignature: %u.\n", pe_header->signature);
    printf("\tMachine: %u.\n", pe_header->machine);
    printf("\t# of sections: %u.\n", pe_header->number_of_sections);
    printf("\t# of symbols: %u.\n", pe_header->number_of_symbols);
    printf("\tTimestamp: %u.\n", pe_header->time_date_stamp);
    printf("\tCharacteristics: %u.\n", pe_header->characteristics);
    printf("\tOptional header size: %u.\n", pe_header->size_of_optional_header);
    printf("\tOptional header type: 0x%x\n", optional_header_type);

    uint32_t c;
    for(c=0; c < pe_header->number_of_sections; c++) {

        struct section_header section;
        addr_t section_addr = image_base_p
            + dos_header->offset_to_pe
            + sizeof(struct pe_header)
            + pe_header->size_of_optional_header
            + c*sizeof(struct section_header);

        // Read the section from memory
        vmi_read_pa(vmi, section_addr, (uint8_t *)&section, sizeof(struct section_header));

        // The character array is not null terminated, so only print the first 8 characters!
        printf("\tSection %u: %.8s\n", c+1, section.short_name);
    }
}

/*int main(int argc, char **argv) {

    vmi_instance_t vmi;

    if (argc != 3) {
        printf("Usage: %s name|domid <domain name|domain id>\n", argv[0]);
        return 1;
    }   // if

    uint32_t domid = VMI_INVALID_DOMID;
    GHashTable *config = g_hash_table_new(g_str_hash, g_str_equal);

    if(strcmp(argv[1],"name")==0) {
        g_hash_table_insert(config, "name", argv[2]);
    } else
    if(strcmp(argv[1],"domid")==0) {
        domid = atoi(argv[2]);
        g_hash_table_insert(config, "domid", &domid);
    } else {
        printf("You have to specify either name or domid!\n");
        return 1;
    }

    if (vmi_init_custom(&vmi, VMI_AUTO | VMI_INIT_PARTIAL | VMI_CONFIG_GHASHTABLE, config) == VMI_FAILURE) {
        printf("Failed to init LibVMI library.\n");
        g_hash_table_destroy(config);
        return 1;
    }
    g_hash_table_destroy(config);

    uint32_t i;
    uint32_t found = 0;
    for(i = 0; i < MAX_SEARCH_SIZE; i += PAGE_SIZE) {

        uint8_t pe[MAX_HEADER_SIZE];

        if(VMI_SUCCESS == peparse_get_image_phys(vmi, i, MAX_HEADER_SIZE, pe)) {
            if(VMI_SUCCESS == is_WINDOWS_KERNEL(vmi, i, pe)) {

                printf("Windows Kernel found @ 0x%"PRIx32"\n", i);
                print_os_version(vmi, i, pe);
                print_guid(vmi, i, pe);
                print_pe_header(vmi, i, pe);
                found=1;
                break;
            }
        }
    }

    vmi_destroy(vmi);

    if(found) return 0;
    return 1;
}*/
