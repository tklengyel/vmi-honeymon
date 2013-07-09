#ifndef XEN_HELPER_H
#define XEN_HELPER_H

#include "structures.h"

/*
 * libxlutil hides these structures when used normally, making them only accessible by the get functions they provide.
 * The structures below can be used to unmask the structure with a simple cast between
 * XLU_ConfigList <-> XLU_ConfigList2
 * XLU_Config     <-> XLU_Config2
 *
 */

/* FUNCTIONS */

bool honeymon_xen_init_interface(honeymon_t* honeymon);
void honeymon_xen_free_interface(honeymon_xen_interface_t* xen);

void honeymon_xen_list_domains(honeymon_t* honeymon);

honeymon_xen_domconfig_raw_t* honeymon_xen_domconfig_raw_by_id(
        honeymon_xen_interface_t *xen, unsigned int domID);
void honeymon_xen_free_domconfig_raw(honeymon_xen_domconfig_raw_t* raw_config);
void honeymon_xen_save_domconfig(honeymon_t *honeymon, XLU_Config *config,
        char* path);
XLU_Config* honeymon_xen_parse_domconfig_raw(
        honeymon_xen_domconfig_raw_t* raw_config);
XLU_Config* honeymon_xen_domconfig_by_name(honeymon_xen_interface_t *xen,
        char* domain_name);
XLU_Config* honeymon_xen_domconfig_by_id(honeymon_xen_interface_t *xen,
        unsigned int domID);
void honeymon_xen_free_domconfig(XLU_Config *config);
int honeymon_xen_designate_vm(honeymon_t* honeymon, char *dom);
void honeymon_xen_restore(honeymon_t *honeymon, char *option);
int honeymon_xen_clone_vm(honeymon_t* honeymon, char* dom);
int honeymon_xen_restore_origin(honeymon_t* honeymon, char* dom);
void honeymon_xen_revert_clone(honeymon_t *honeymon, char *name);

void test(honeymon_t *honeymon, char *option);

#endif
