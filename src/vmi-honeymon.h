#ifndef VMI_HONEYMON_H
#define VMI_HONEYMON_H

#include "structures.h"

void honeymon_start_scan_scheduler(honeymon_t *h);
void honeymon_interrupt(int signal);
void honeymon_shell();

#endif
