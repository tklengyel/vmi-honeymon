bin_PROGRAMS = vmi-honeymon

vmi_honeymon_SOURCES =  vmi-honeymon.c input_parser.c xen_helper.c \
			honeypots.c scan.c tcp_listener.c \
			log.c log_mysql.c guestfs_helper.c

vmi_honeymon_h 	     =  structures.h vmi-honeymon.h input_parser.h xen_helper.h \
			honeypots.h scan.h tcp_listener.h \
			log.h log_mysql.h guestfs_helper.h

vmi_honeymon_SOURCES += $(vmi_honeymon_h)

AM_CFLAGS = $(CFLAGS)
AM_CFLAGS += $(GLIB_CFLAGS)
AM_CFLAGS += $(XML2_CFLAGS)
AM_CFLAGS += $(MYSQL_CFLAGS)
AM_CFLAGS += -D_XOPEN_SOURCE=500

if HARDENING
AM_CFLAGS += $(HARDEN_CFLAGS) -DHARDENING
endif

# Note that -pg is incompatible with HARDENING
if DEBUG
AM_CFLAGS += -DHONEYMON_DEBUG -Wall -Wextra -Wno-override-init -Wno-strict-aliasing -g -ggdb3
AM_CFLAGS += -Wno-unused-parameter -Wno-unused-but-set-variable -Wno-unused-variable
if !HARDENING
AM_CFLAGS += -pg
endif
endif

AM_LDFLAGS = $(LIBS)
AM_LDFLAGS += $(GLIB_LIBS)
AM_LDFLAGS += $(XML2_LIBS)
AM_LDFLAGS += $(XC_LIBS)
AM_LDFLAGS += $(MYSQL_LIBS)
AM_LDFLAGS += $(GUESTFS_LIBS)
AM_LDFLAGS += $(HARDEN_LDFLAGS)
