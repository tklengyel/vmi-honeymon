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

#ifndef WIN_GUID_H
#define WIN_GUID_H

#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>

status_t get_guid(vmi_instance_t vmi, addr_t vaddr, uint32_t pid, char **pe_guid, char **pdb_guid);
//status_t get_guid2(vmi_instance_t vmi, const char *mod_name, addr_t base_vaddr, uint32_t pid, char **guid, char **filename);

#endif
