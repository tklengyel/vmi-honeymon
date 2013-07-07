#ifndef SCAN_H
#define SCAN_H

bool honeymon_scan_start_all(honeymon_clone_t *clone);
void* honeymon_scan(honeymon_scan_input_t *input);
bool honeymon_scan_compare(char *scan, char *origin_scan, char *clone_scan, honeymon_clone_t *clone);

#endif
