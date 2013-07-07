#ifndef TCP_LISTENER_H
#define TCP_LISTENER_H

void *honeymon_tcp_handle_connection(void *arg);
void honeymon_tcp_start_listener(honeymon_t *honeymon);
#endif
