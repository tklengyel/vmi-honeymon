/*
 * This file is part of the VMI-Honeymon project.
 *
 * 2012-2013 University of Connecticut (http://www.uconn.edu)
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

#ifndef STRUCTURES_H
#define STRUCTURES_H

/*
 * These are some internal definitions used to configure various aspects of VMI-Honeymon
 * TODO: Convert these to input parameters
 */
#define GUESTFS_HASH_TYPE "SHA1"
#define CLONE_BUFFER 5
#define MIN_VLAN 10
#define VIF_APPEND "script=vif-openvswitch,backend=openvswitch"
#define RPC_SERVER_PORT 4567
#define RPC_SERVER_LOG NULL

/******************************************/

#define LIBXL_API_VERSION 0x040300
#define INVALID_DOMID ~(uint32_t)0

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <libxl.h>
#ifdef HAVE_LIBXLUTIL_H
#include <libxlutil.h>
#else
#include "_libxlutil.h"
#endif
#include <libxl_utils.h>
#include <xenctrl.h>
#include <xenguest.h>
#include <xenstore.h>

#include <glib.h>
#include <libdevmapper.h>
#include <lvm2app.h>

#include <libvmi/libvmi.h>

#ifdef HAVE_MYSQL
#include <mysql.h>
#endif

#ifdef HAVE_LIBGUESTFS
#include <guestfs.h>
#endif

#ifdef HAVE_LIBMAGIC
#include <magic.h>
#endif

#ifdef HAVE_XMLRPC
#include <xmlrpc-c/base.h>
#include <xmlrpc-c/server.h>
#include <xmlrpc-c/server_abyss.h>
#endif

typedef struct xen_interface {
    struct xs_handle *xsh;
    xc_interface *xc;
    libxl_ctx *xl_ctx;
    xentoollog_logger *xl_logger;
} honeymon_xen_interface_t;

typedef struct xen_domconfig_raw {
    uint8_t *config_data;
    int config_length;
} honeymon_xen_domconfig_raw_t;

typedef struct log_interface {

    pthread_mutex_t log_IDX_lock;
    uint32_t log_IDX;

    pthread_mutex_t mysql_lock;
    bool mysql_enabled;
    char* mysql_address;
    char* mysql_user;
    char* mysql_pass;
    char* mysql_db;
    uint32_t mysql_port;

#ifdef HAVE_MYSQL
    MYSQL* mysql_conn;
#endif

} honeymon_log_interface_t;

typedef struct lvm {
	lvm_t handle;
	vg_t vg;
	lv_t lv;
} honeymon_lvm2_interface_t;

typedef struct honeymon {

    GMutex lock;

    honeymon_xen_interface_t* xen;
    honeymon_log_interface_t* log;

    lvm_t lvm;

    bool stealthy;
    bool interactive;
    uint32_t action;
    char* action_option;

    char* workdir;
    char* originsdir;
    char* honeypotsdir;
    char* backupdir;
    char* virusdir;

    GTree* honeypots; // a tree of honeymon_honeypot_t's
    uint16_t vlans :12; //vlan id

    // clone factory
    GAsyncQueue *clone_requests;
    pthread_t clone_factory;

    win_ver_t winver;

    bool guestfs_enable;

#ifdef HAVE_LIBMAGIC
magic_t magic_cookie;
#endif

#ifdef HAVE_XMLRPC
    GMutex rpc_lock;
    GCond rpc_cond;
    pthread_t rpc_server_thread;

    xmlrpc_server_abyss_t *rpc_server;
#endif
} honeymon_t;

/* These structs are opaque in xlu but we need them
 * to parse the configuration files. */
typedef struct {
    struct XLU_ConfigList2 *next;
    char *name;
    int nvalues, avalues; /* lists have avalues>1 */
    char **values;
    int lineno;
} XLU_ConfigList2;

typedef struct {
    XLU_ConfigList2 *settings;
    FILE *report;
    char *config_source;
} XLU_Config2;

typedef struct honeypot {

    GMutex lock;

    char* origin_name;
    char* snapshot_path;
    char* config_path;
    char* ip_path;

    vg_t vg;
    char *vg_name;

    lv_t lv;
    char *lv_name;

    XLU_Config2 *config;

    // network info
    char ip[INET_ADDRSTRLEN];
    char *mac;

    win_ver_t winver;

    unsigned int domID; // 0 if not actually running but restorable
    unsigned int clones; // number of active clones
    unsigned int max_clones; // max number of active clones
    unsigned int clone_buffer; // number of inactive clones to keep around at any time
    GTree* clone_list; // clone list of honeymon_clone_t

    GSList* fschecksum; // each node is a GTree with the file path as key and hash as value
} honeymon_honeypot_t;

typedef struct clone {
    honeymon_t* honeymon;
    honeymon_honeypot_t* origin;
    char* origin_name;
    char* clone_name;
    char* config_path;

    lv_t clone_lv;

    uint16_t vlan;
    uint32_t domID;

    // thread stuff
    pthread_t signal_thread;
    pthread_t vmi_thread;

    GMutex lock;
    GMutex scan_lock;
    GCond cond;
    bool active;
    bool paused;

    // scan scheduling
    uint32_t nscans; // number of scans to be scheduled
    uint32_t cscan; // the scan to be scheduled next (cscan is always < nscans)
    uint32_t* tscan; // list of times to wait between scans
    pthread_t* scan_threads;
    bool* scan_results;
    uint32_t scan_initiator; //0=scheduled, 1=network event, 2=timeout

    // log IDX
    uint32_t logIDX;
    uint32_t start_time;

    // VMI
    int interrupted;
    page_mode_t pm;
    vmi_instance_t vmi;

    // memory benchmark
    bool membench;
    pthread_t membench_thread;

// guestfs
#ifdef HAVE_LIBGUESTFS
guestfs_h* guestfs;
#endif
} honeymon_clone_t;

#endif
