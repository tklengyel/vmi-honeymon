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

#ifndef WINSYMS_H
#define WINSYMS_H

#include <libvmi/libvmi.h>

addr_t sym2va(vmi_instance_t vmi, vmi_pid_t pid, const char *mod_name, const char *sym);
const char *rva2sym(vmi_instance_t vmi, const char *mod_name, addr_t base_vaddr, uint32_t pid, addr_t rva);
status_t va2sym(vmi_instance_t vmi, addr_t va, vmi_pid_t pid, char **mod, char **sym);

#endif
