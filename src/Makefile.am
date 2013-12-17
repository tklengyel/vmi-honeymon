# This file is part of the VMI-Honeymon project.
#
# 2012-2013 University of Connecticut (http://www.uconn.edu)
# Tamas K Lengyel (tamas.k.lengyel@gmail.com)
#
#  VMI-Honeymon is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.
# 
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
# 
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, see <http://www.gnu.org/licenses/>.
 
bin_PROGRAMS = vmi-honeymon

vmi_honeymon_SOURCES =  vmi-honeymon.c vmi-honeymon.h
vmi_honeymon_SOURCES += input_parser.c input_parser.h
vmi_honeymon_SOURCES += xen_helper.c xen_helper.h
vmi_honeymon_SOURCES += honeypots.c honeypots.h
vmi_honeymon_SOURCES += guestfs_helper.c guestfs_helper.h
vmi_honeymon_SOURCES += log.c log.h
vmi_honeymon_SOURCES += log_mysql.c log_mysql.h
vmi_honeymon_SOURCES += rpc_server.c rpc_server.h
vmi_honeymon_SOURCES += vmi.c vmi.h
vmi_honeymon_SOURCES += win-guid.c win-guid.h

AM_CFLAGS = $(CFLAGS)
AM_CFLAGS += $(VMI_CFLAGS)
AM_CFLAGS += $(GLIB_CFLAGS)
AM_CFLAGS += $(XMLRPC_CLIENT_CFLAGS)
AM_CFLAGS += $(XMLRPC_SERVER_CFLAGS)
AM_CFLAGS += $(MYSQL_CFLAGS)
AM_CFLAGS += -D_XOPEN_SOURCE=500

if HARDENING
AM_CFLAGS += $(HARDEN_CFLAGS) -DHARDENING
endif

# Note that -pg is incompatible with HARDENING
if DEBUG
AM_CFLAGS += -DHONEYMON_DEBUG -Wall -Wextra -Wno-override-init -Wno-strict-aliasing -g -ggdb3
AM_CFLAGS += -Wno-unused-parameter
# -Wno-unused-but-set-variable -Wno-unused-variable
if !HARDENING
AM_CFLAGS += -pg
endif
endif

AM_LDFLAGS = $(LIBS)
AM_LDFLAGS += $(VMI_LIBS)
AM_LDFLAGS += $(GLIB_LIBS)
AM_LDFLAGS += $(XMLRPC_CLIENT_LIBS)
AM_LDFLAGS += $(XMLRPC_SERVER_LIBS)
AM_LDFLAGS += $(XC_LIBS)
AM_LDFLAGS += $(MYSQL_LIBS)
AM_LDFLAGS += $(GUESTFS_LIBS)
AM_LDFLAGS += $(HARDEN_LDFLAGS)
