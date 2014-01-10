#ifndef FILE_EXTRACTOR_H
#define FILE_EXTRACTOR_H

#include <libvmi/libvmi.h>
#include "structures.h"

void extract_file (honeymon_clone_t * clone, const char *filename, GTree *files);
void grab_file_before_delete(vmi_instance_t vmi, vmi_event_t *event, reg_t cr3, struct symbolwrap *s);

#endif
