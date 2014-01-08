#include <stdio.h>
#include <pthread.h>
#include <signal.h>
#include <libvmi/libvmi.h>

#include "structures.h"
#include "vmi.h"

honeymon_clone_t clone;
honeymon_t honeymon;

static void close_handler(int sig){
    clone.interrupted = sig;
}

int main(int argc, char** argv) {

    if(argc != 2) {
        printf("Usage: %s <domid>\n", argv[0]);
        return 1;
    }

    memset(&honeymon, 0, sizeof(honeymon_t));
    pooltag_build_tree(&honeymon);
    vmi_build_guid_tree(&honeymon);

    memset(&clone, 0, sizeof(honeymon_clone_t));
    clone.clone_name = "vmi-test";
    clone.domID = atoi(argv[1]);
    clone.honeymon = &honeymon;

    clone_vmi_init(&clone);

    if(!clone.vmi) {
        return 1;
    }

    /* for a clean exit */
    struct sigaction act;
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    pthread_t clone_thread;
    pthread_create(&(clone_thread), NULL, clone_vmi_thread,
            (void *) &clone);

    pthread_join(clone_thread, NULL);
    close_vmi_clone(&clone);

    return 0;
}
