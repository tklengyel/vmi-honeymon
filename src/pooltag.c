/*
 * This file is part of the VMI-Honeymon project.
 *
 * 2012-2014 University of Connecticut (http://www.uconn.edu)
 * Tamas K Lengyel <tamas.k.lengyel@gmail.com>
 *
 * VMI-Honeymon is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "structures.h"
#include "pooltag.h"

void pooltag_build_tree(honeymon_t *honeymon) {
    honeymon->pooltags = g_tree_new((GCompareFunc)strcmp);

    uint32_t i=0;
    for(;i<TAG_COUNT;i++) {
        g_tree_insert(honeymon->pooltags, tags[i].tag, &tags[i]);
    }
}
