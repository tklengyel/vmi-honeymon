#ifndef WIN_HANDLES_H
#define WIN_HANDLES_H

#include <libvmi/libvmi.h>
#include "structures.h"

addr_t get_obj_by_handle(honeymon_clone_t *clone, vmi_instance_t vmi, uint64_t vcpu_id, reg_t cr3, uint64_t handle);

#endif
