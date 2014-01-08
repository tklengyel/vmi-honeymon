#ifndef VMI_POOLMON_H
#define VMI_POOLMON_H

#include <libvmi/libvmi.h>
#include "structures.h"
#include "pooltag.h"

void pool_tracker(vmi_instance_t vmi, vmi_event_t *event, reg_t cr3);
void pool_alloc_return(vmi_instance_t vmi, vmi_event_t *event, addr_t pa, reg_t cr3, char *ts, struct pool_lookup *s);

#endif
