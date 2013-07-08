#ifndef HONEYPOTS_H
#define HONEYPOTS_H

int honeymon_honeypots_build_bridge_list(honeymon_t *honeymon);

honeymon_honeypot_t * honeymon_honeypots_init_honeypot(honeymon_t *honeymon,
        char *name);
honeymon_clone_t * honeymon_honeypots_init_clone(honeymon_t *honeymon,
        char *origin_name, char *clone_name, uint16_t vlan);
honeymon_clone_t * honeymon_honeypots_find_clone(honeymon_t *honeymon,
        char *clone_name);
honeymon_clone_t * honeymon_honeypots_get_random(honeymon_t *honeymon);
void honeymon_honeypots_list(honeymon_t *honeymon);
void honeymon_free_clone(honeymon_clone_t *clone);
void honeymon_honeypots_destroy_clone_t(honeymon_clone_t *clone);
void honeymon_honeypots_destroy_honeypot_t(honeymon_honeypot_t *honeypot);

void honeymon_honeypots_unpause_clones(honeymon_t *honeymon, char *origin_name);
void honeymon_honeypots_pause_clones(honeymon_t *honeymon, char *origin_name);
void honeymon_init_honeypot_lists(honeymon_t *honeymon);

uint32_t honeymon_honeypots_count_free_clones(honeymon_t *honeymon);
gboolean honeymon_honeypots_pause_clones2(gpointer key, gpointer value,
        gpointer data);
gboolean honeymon_honeypots_unpause_clones2(gpointer key, gpointer value,
        gpointer data);

#endif
