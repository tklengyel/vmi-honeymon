/*
 * Tamas K Lengyel (C) 2013
 * Compile with gcc -o test test.c
 */

#include <stdio.h>
#include <inttypes.h>

struct symbol {
    char *name;
    uint64_t rva;
};

struct config {
    char *name;
    const char **guids;
    const struct symbol *syms;
    const uint64_t *sym_count;
};

#include "config.h"

int main(int argc, char **argv) {

    printf("We have %u symbol headers compiled in\n", config_count);

    int i;
    for(i=0;i<config_count;i++) {
        printf("Config name: %s. PE GUID: %s. PDB GUID: %s. Symbols %u\n",
            configs[i].name, configs[i].guids[0], configs[i].guids[1], *configs[i].sym_count);

        /*int z;
        for(z=0;z<*configs[i].sym_count;z++) {
            printf("\tSymbol: %s\n", configs[i].syms[z].name);
        }*/
    }

    return 0;
};
