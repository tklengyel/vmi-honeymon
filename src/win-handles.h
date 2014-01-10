#ifndef WIN_HANDLES_H
#define WIN_HANDLES_H

#include <libvmi/libvmi.h>
#include "structures.h"

addr_t get_obj_by_handle(honeymon_clone_t *clone, vmi_instance_t vmi, vmi_pid_t target_pid, uint64_t handle);

#endif
