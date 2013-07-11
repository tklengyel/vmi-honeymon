#ifndef STRUCTURES_H
#define STRUCTURES_H

#define LIBXL_API_VERSION 0x040300
#define INVALID_DOMID ~(uint32_t)0
#define GUESTFS_HASH_TYPE "SHA1"
#define CLONE_BUFFER 5
#define MIN_VLAN 10

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <libxl.h>
#include <libxlutil.h>
#include <libxl_utils.h>
#include <xenctrl.h>
#include <xenguest.h>
#include <xenstore.h>
#include <glib.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#ifdef HAVE_LIBTHPOOL
#include <thpool.h>
#endif

#ifdef HAVE_MYSQL
#include <mysql.h>
#endif

#ifdef HAVE_LIBGUESTFS
#include <guestfs.h>
#endif

#ifdef HAVE_LIBMAGIC
#include <magic.h>
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

typedef struct honeymon {

    GMutex lock;

    honeymon_xen_interface_t* xen;
    honeymon_log_interface_t* log;

    // absolute path to Volatility vol.py
    char* volatility;

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

    char* scanconf;
    char* scanscheduleconf;
    GSList* scans; // available volatility scans
    int number_of_scans;
    int* scanschedule;

    char* tcp_if; // IP to listen on or "any" for all interface
    uint32_t tcp_port;
    bool tcp_init;
    int tcp_socket;

    bool guestfs_enable;

    bool membench;

    int scanpool;
    GThreadPool *thpool;

#ifdef HAVE_LIBMAGIC
magic_t magic_cookie;
#endif
} honeymon_t;

typedef struct tcp_conn {
    honeymon_t *honeymon;
    FILE *buffer;
    int socket;
    struct sockaddr_in *client;
} honeymon_tcp_conn_t;

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

    XLU_Config2 *config;

    // network info
    char ip[INET_ADDRSTRLEN];
    char *mac;

    char* profile_path;
    char* profile;

    unsigned int domID; // 0 if not actually running but restorable
    unsigned int clones; // number of active clones
    unsigned int max_clones; // max number of active clones
    unsigned int clone_buffer; // number of inactive clones to keep around at any time
    GTree* clone_list; // clone list of honeymon_clone_t
    GSList* scans; // enabled volatility scans

    GSList* fschecksum; // each node is a GTree with the file path as key and hash as value
} honeymon_honeypot_t;

typedef struct clone {
    honeymon_t* honeymon;
    honeymon_honeypot_t* origin;
    char* origin_name;
    char* clone_name;
    char* qcow2_path;
    char* config_path;
    uint16_t vlan;
    uint32_t domID;

    // thread stuff
    pthread_t thread;
    GMutex lock;
    GMutex scan_lock;
    GCond cond;
    bool active;
    bool paused;
    bool finish;

    // scan scheduling
    uint32_t nscans; // number of scans to be scheduled
    uint32_t cscan; // the scan to be scheduled next (cscan is always < nscans)
    uint32_t* tscan; // list of times to wait between scans
    pthread_t* scan_threads;
    bool* scan_results;
    uint32_t scan_initiator; //0=scheduled, 1=network event, 2=timeout

    // log IDX
    int logIDX;
    uint32_t start_time;

    // memory benchmark
    bool membench;
    pthread_t membench_thread;

// guestfs
#ifdef HAVE_LIBGUESTFS
guestfs_h* guestfs;
#endif
} honeymon_clone_t;

typedef struct scan_input {
    char* domain;
    char* scan;
    honeymon_t* honeymon;
    honeymon_clone_t* clone;
    bool* result;
} honeymon_scan_input_t;

#endif
