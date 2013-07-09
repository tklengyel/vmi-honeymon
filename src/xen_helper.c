#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <dirent.h>
#include <glib.h>
#include <math.h>
#include <err.h>

//#include <libvmi/libvmi.h>

#include "xen_helper.h"
#include "log.h"
#include "honeypots.h"

bool honeymon_xen_init_interface(honeymon_t* honeymon) {

    honeymon_xen_interface_t *xen = malloc(sizeof(honeymon_xen_interface_t));

    /* We create an xc interface to test connection to it */
    xen->xc = xc_interface_open(0, 0, 0);

    if (xen->xc == NULL) {
        fprintf(stderr, "xc_interface_open() failed!\n");
        honeymon_xen_free_interface(xen);
        return 0;
    }

    /* We don't need this at the moment, but just in case */
    //xen->xsh=xs_open(XS_OPEN_READONLY);
    xen->xl_logger = (xentoollog_logger *) xtl_createlogger_stdiostream(stderr,
            XTL_PROGRESS, 0);

    if (!xen->xl_logger) return 0;

    if (0
            != libxl_ctx_alloc(&(xen->xl_ctx), LIBXL_VERSION, 0,
                    xen->xl_logger)) {
        fprintf(stderr, "libxl_ctx_alloc() failed!\n");
        honeymon_xen_free_interface(xen);
        return 0;
    }

    honeymon->xen = xen;
    return 1;
}

void honeymon_xen_free_interface(honeymon_xen_interface_t* xen) {
    if (xen != NULL) {
        if (xen->xsh != NULL) xs_close(xen->xsh);
        if (xen->xc != NULL) xc_interface_close(xen->xc);
        if (xen->xl_logger) xtl_logger_destroy(xen->xl_logger);
        if (xen->xl_ctx != NULL) libxl_ctx_free(xen->xl_ctx);
        free(xen);
    }
}

char *honeymon_xen_first_disk_path(XLU_ConfigList *disks_masked) {
    // Get the path to the disk
    XLU_ConfigList2 *disks = (XLU_ConfigList2 *) disks_masked;

    disks = (XLU_ConfigList2 *) disks_masked;
    char delim[] = ":,";
    char *disk_path = strtok((disks->values[0]), delim);

    while (disk_path != NULL) {
        if ((int) disk_path[0] == 47) break;
        disk_path = strtok(NULL, delim);
    }

    return disk_path;
}

int honeymon_xen_clone_vm(honeymon_t* honeymon, char* dom) {

    if (honeymon->workdir == NULL) {
        printf("You need to set a workdir for that!\n");
        return 1;
    }

    honeymon_xen_interface_t *xen = honeymon->xen;
    uint32_t domID = INVALID_DOMID;
    char* name = NULL;
    char* config_path;
    char* origin_path;
    int sysret;

    printf("Checking for %s..\n", dom);
    sscanf(dom, "%u", &domID);

    if (domID == INVALID_DOMID) {
        name = malloc(sizeof(char) * strlen(dom));
        sprintf(name, "%s", dom);
        libxl_name_to_domid(xen->xl_ctx, name, &domID);
        if (domID == INVALID_DOMID) {
            printf("Domain is not running, failed to get domID from name!\n");
        } else {
            printf("Got domID from name: %u\n", domID);
        }
    } else {
        name = libxl_domid_to_name(xen->xl_ctx, domID);
        if (name == NULL) {
            printf(
                    "Failed to get domain name from ID, is the domain running?\n");
            return 1;
        } else {
            printf("Got name from domID: %s\n", name);
        }
    }

    config_path = malloc(
            snprintf(NULL, 0, "%s/%s.config", honeymon->originsdir, name) + 1);
    origin_path = malloc(
            snprintf(NULL, 0, "%s/%s.origin", honeymon->originsdir, name) + 1);
    sprintf(config_path, "%s/%s.config", honeymon->originsdir, name);
    sprintf(origin_path, "%s/%s.origin", honeymon->originsdir, name);

    FILE *test1 = NULL, *test2 = NULL;
    printf("Checking for %s: ", config_path);

    if ((test1 = fopen(config_path, "r")) != NULL) {
        printf("OK\n");
        fclose(test1);
    } else {
        printf("missing!\n");
        return 1;
    }

    printf("Checking for %s: ", origin_path);

    if ((test2 = fopen(origin_path, "r")) != NULL) {
        fclose(test2);
        printf("OK\n");
    } else {
        printf("missing!\n");
        return 1;
    }

    XLU_Config2 *config = (XLU_Config2 *) xlu_cfg_init(stderr, "cmdline");
    xlu_cfg_readfile((XLU_Config *) config, config_path);

    int number_of_disks;
    XLU_ConfigList *disks_masked = NULL;
    XLU_ConfigList2 *disks = NULL;
    if (xlu_cfg_get_list((XLU_Config *) config, "disk", &disks_masked,
            &number_of_disks, 0)) {
        printf("The VM config didn't contain a disk configuration line!\n");
        return 1;
    } else disks = (XLU_ConfigList2 *) disks_masked;

    if (number_of_disks < 1) {
        printf("No disks are defined in the config!\n");
        return 1;
    }

    char *disk_path = honeymon_xen_first_disk_path(
            (XLU_ConfigList *) disks_masked);

    if (disk_path == NULL) return 0;
    else printf("The original disk path is %s\n", disk_path);

    // Get the first network interface
    XLU_ConfigList *vifs_masked = NULL;
    XLU_ConfigList2 *vifs = NULL;
    int number_of_vifs;
    if (xlu_cfg_get_list((XLU_Config *) config, "vif", &vifs_masked,
            &number_of_vifs, 0)) {
        printf("The VM config didn't contain network configuration line!\n");
        return 1;
    }

    if (number_of_vifs < 1) {
        printf("No network interfaces are defined in the config!\n");
        return 1;
    }

    vifs = (XLU_ConfigList2 *) vifs_masked;

    // Get the honeypot structure
    honeymon_honeypot_t *honeypot = (honeymon_honeypot_t *) g_tree_lookup(
            honeymon->honeypots, name);

    if(!honeypot) return 1;

    repeat:
    g_mutex_lock(&honeypot->lock);

    if(honeypot->clone_buffer >= CLONE_BUFFER) {
        g_mutex_unlock(&honeypot->lock);
        return 1;
    }

    honeypot->cloneIDs++;
    uint32_t clone_id = honeypot->cloneIDs;

    g_mutex_lock(&honeymon->lock);
    honeymon->vlans++;
    uint16_t vlan_id = honeymon->vlans;
    g_mutex_unlock(&honeymon->lock);

    // Setup clone
    char *disk_clone_path = malloc(
            snprintf(NULL, 0, "%s/%s.%u.qcow2", honeymon->honeypotsdir, name,
                    clone_id) + 1);
    char *clone_config_path = malloc(
            snprintf(NULL, 0, "%s/%s.%u.config", honeymon->honeypotsdir, name,
                    clone_id) + 1);
    char *clone_name = malloc(
            snprintf(NULL, 0, "%s.%u", name, clone_id) + 1);
    char *vlan = malloc(snprintf(NULL, 0, ".%u", vlan_id) + 1);
    sprintf(disk_clone_path, "%s/%s.%u.qcow2", honeymon->honeypotsdir, name,
            clone_id);
    sprintf(clone_config_path, "%s/%s.%u.config", honeymon->honeypotsdir, name,
            clone_id);
    sprintf(clone_name, "%s.%u", name, clone_id);
    sprintf(vlan, ".%u", vlan_id);

    printf("Creating clone %s\n\tDisk %s\n\tConfig %s\n\tVLAN %u\n", clone_name,
            disk_clone_path, clone_config_path, honeymon->vlans);

    char *command = malloc(
            snprintf(NULL, 0, "%s create -f qcow2 -b %s %s", QEMUIMG, disk_path,
                    disk_clone_path) + 1);
    sprintf(command, "%s create -f qcow2 -b %s %s", QEMUIMG, disk_path,
            disk_clone_path);
    printf("** RUNNING COMMAND: %s\n", command);
    sysret = system(command);
    free(command);

    printf("Qcow2 filesystem clone is created at %s\n", disk_clone_path);

    // Update config

    // Replace disk config
    free(disks->values[0]);
    disks->values[0] = malloc(
            snprintf(NULL, 0, "tap:qcow2:%s,xvda,w", disk_clone_path) + 1);
    sprintf(disks->values[0], "tap:qcow2:%s,xvda,w", disk_clone_path);

    // Replace network bridge
    char delim2[] = ",=";

    GString *new_vif = g_string_new("");
    char *saveptr = NULL;
    char *vif_bridge = strtok_r((vifs->values[0]), delim2, &saveptr);
    int elements = 1;
    bool bridge = 0;

    while (vif_bridge != NULL) {

        //printf("%i %s %i\n", elements, vif_bridge, bridge);

        g_string_append(new_vif, vif_bridge);

        if (bridge) {
            g_string_append(new_vif, vlan);
        }

        if (elements % 2 == 0) g_string_append(new_vif, ",");
        else g_string_append(new_vif, "=");

        if (!strcmp(vif_bridge, "bridge")) bridge = 1;

        vif_bridge = strtok_r(NULL, delim2, &saveptr);

        elements++;
    }

    //printf("New vif is %s\n", new_vif);
    free(vifs->values[0]);
    vifs->values[0] = g_string_free(new_vif, FALSE);

    // Update the name in the config
    XLU_ConfigList2 *search = config->settings;
    while (search != NULL) {
        if (!strcmp(search->name, "name")) {
            free(search->values[0]);
            char *c_name = strdup(clone_name); // this will be freed when the XLU_Config gets destroyed
            search->values[0] = c_name;
            break;
        }
        search = (XLU_ConfigList2 *) search->next;
    }

    honeymon_xen_save_domconfig(honeymon, (XLU_Config *) config,
            clone_config_path);

    command = malloc(
            snprintf(NULL, 0, "%s create -p %s", XL, clone_config_path) + 1);
    sprintf(command, "%s create -p %s", XL, clone_config_path);
    printf("** RUNNING COMMAND: %s\n", command);
    sysret = system(command);
    free(command);

    uint32_t cloneID = 0;
    libxl_name_to_domid(xen->xl_ctx, clone_name, &cloneID);
    if (cloneID != 0) {
        printf("Clone shell created with domID %i!\n", cloneID);
    } else {
        printf("Clone shell creation failed!\n");
        return 1;
    }

    //clone->domID=cloneID;
    int memshared = 0;
    if (domID == INVALID_DOMID) {
        printf("Skipping memshare as the origin VM is not running!\n");
    } else {

        int page = xc_domain_maximum_gpfn(xen->xc, domID) + 1;

        if (page <= 0) {
            printf("Failed to get origin max gpfn!\n");
            goto done;
        }

        if (xc_memshr_control(xen->xc, domID, 1)) {
            printf("Failed to enable memsharing on origin!\n");
            goto done;
        }
        if (xc_memshr_control(xen->xc, cloneID, 1)) {
            printf("Failed to enable memsharing on clone!\n");
            goto done;
        }

        uint64_t shandle, chandle;
        int shared = 0;
        while (page >= 0) {

            page--;

            if (xc_memshr_nominate_gfn(xen->xc, domID, page, &shandle)) continue;
            if (xc_memshr_nominate_gfn(xen->xc, cloneID, page, &chandle)) continue;
            if (xc_memshr_share_gfns(xen->xc, domID, page, shandle, cloneID,
                    page, chandle)) continue;

            shared++;
        }

        printf("Shared %i pages!\n", shared);
        memshared = 1;
    }

    honeymon_clone_t *clone = honeymon_honeypots_init_clone(honeymon, name,
            clone_name, vlan_id);

    clone->memshared = memshared;

    if(honeypot->clone_buffer < CLONE_BUFFER)
        goto repeat;

    done: xlu_cfg_destroy((XLU_Config *) config);
    //free(disk_clone_path);
    //free(clone_config_path);
    free(config_path);
    free(origin_path);
    free(name);

    g_mutex_unlock(&honeypot->lock);

    return 0;
}

void honeymon_xen_list_domains(honeymon_t* honeymon) {

    honeymon_xen_interface_t *xen = honeymon->xen;
    int number_of_domains;
    libxl_dominfo* domains = libxl_list_domain(xen->xl_ctx, &number_of_domains);

    printf("Number of domains running: %i\n", number_of_domains);

    int i;
    for (i = 0; i < number_of_domains; i++) {

        char *name = libxl_domid_to_name(xen->xl_ctx, domains[i].domid);

        printf(
                "<#%i> Domain name: %s\n\tID: %i\tMemory: %lu\tShared memory: %lu\tState: ",
                i, name, domains[i].domid, domains[i].current_memkb / 1024,
                domains[i].shared_memkb / 1024);

        if (domains[i].running) printf("running");
        if (domains[i].blocked) printf("blocked");
        if (domains[i].paused) printf("paused");
        if (domains[i].shutdown) printf("shutdown");
        if (domains[i].dying) printf("dying");

        printf("\tOrigin VM: ");
        if (honeymon->originsdir != NULL) {
            struct stat buf;
            char *file = malloc(
                    snprintf(NULL, 0, "%s/%s.origin", honeymon->originsdir,
                            name) + 1);
            sprintf(file, "%s/%s.origin", honeymon->originsdir, name);
            if (stat(file, &buf) == 0) printf("Y");
            else printf("N");
            free(file);
        } else printf("N");

        printf("\tConfig found: ");
        XLU_Config *config = honeymon_xen_domconfig_by_id(xen,
                domains[i].domid);
        if (config != NULL) {
            printf("Y");
            honeymon_xen_free_domconfig(config);
        } else printf("N");

        printf("\n");

        free(name);
    }

    libxl_dominfo_list_free(domains, number_of_domains);

}

int honeymon_xen_designate_vm(honeymon_t* honeymon, char *dom) {

    if (honeymon->workdir == NULL) {
        printf("You can't do this without a workdir specified!\n");
        return 1;
    }

    if (honeymon->volatility == NULL) {
        printf("You can't do this without Volatility path specified!\n");
        return 1;
    }

    honeymon_xen_interface_t *xen = honeymon->xen;
    uint32_t domID = INVALID_DOMID;
    sscanf(dom, "%u", &domID);

    if (domID == INVALID_DOMID) {
        printf("Please specify domain by ID!\n");
        return 1;
    }

    char *name = libxl_domid_to_name(xen->xl_ctx, domID);
    honeymon_xen_domconfig_raw_t *config = honeymon_xen_domconfig_raw_by_id(xen,
            domID);

    libxl_dominfo info;
    int doesntExist = libxl_domain_info(xen->xl_ctx, &info, domID);

    if (doesntExist) {
        printf("Domain doesn't exists!\n");
        return 1;
    }

    printf("Designating domain %u as an origin VM..\n", domID);

    if (info.shutdown || info.dying) {
        printf("Domain is an unusable state, aborting!\n");
        return 1;
    }

    /* We need to unpause the VM cause of Xl.. sigh */
    if (info.paused) {
        printf("Unpausing VM for snapshot!\n");
        libxl_domain_unpause(xen->xl_ctx, domID);
        libxl_domain_info(xen->xl_ctx, &info, domID);
    }

    char *output = malloc(
            snprintf(NULL, 0, "%s/%s.origin", honeymon->originsdir, name) + 1);
    char *output_config = malloc(
            snprintf(NULL, 0, "%s/%s.config", honeymon->originsdir, name) + 1);
    sprintf(output, "%s/%s.origin", honeymon->originsdir, name);
    sprintf(output_config, "%s/%s.config", honeymon->originsdir, name);

    struct stat buf;
    if (!stat(output, &buf)) printf("Overwriting snapshot of %u at %s!\n",
            domID, output);
    else printf("Saving snapshot of %u to %s!\n", domID, output);

    /* Save config to a separate file */
    int cfd = open(output_config, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    libxl_write_exactly(xen->xl_ctx, cfd, config->config_data,
            config->config_length, output_config, "header");
    close(cfd);

    char *command = malloc(
            snprintf(NULL, 0, "%s save %u %s", XL, domID, output) + 1);
    sprintf(command, "%s save %u %s", XL, domID, output);
    printf("** RUNNING COMMAND: %s\n", command);
    int sysret = system(command);
    free(command);

    command = malloc(snprintf(NULL, 0, "%s restore -p %s", XL, output) + 1);
    sprintf(command, "%s restore -p %s", XL, output);
    printf("** RUNNING COMMAND: %s\n", command);
    sysret = system(command);
    free(command);

    libxl_name_to_domid(xen->xl_ctx, name, &domID);

    honeymon_honeypot_t* honeypot = honeymon_honeypots_init_honeypot(honeymon,
            name);

    if (honeypot->profile != NULL) {
        printf("Previous profile was %s\n", honeypot->profile);
        free(honeypot->profile);
    }

    char profile[128];
    printf("Please enter the Volatility profile of this VM: ");
    fflush(stdout);
    char *p = fgets(profile, sizeof(profile), stdin);
    char *nl = strrchr(p, '\r');
    if (nl) *nl = '\0';
    nl = strrchr(p, '\n');
    if (nl) *nl = '\0';
    honeypot->profile = strdup(profile);

    FILE *output_prof = fopen(honeypot->profile_path, "w");
    fprintf(output_prof, "%s", honeypot->profile);
    fclose(output_prof);

    if (honeypot->scans != NULL) g_slist_free_full(honeypot->scans,
            (GDestroyNotify) free);

    GSList *scans = honeymon->scans;
    while (scans != NULL) {
        char *scan = strdup((char *) scans->data);
        char *output = malloc(
                snprintf(NULL, 0, "%s/%s.%s", honeymon->originsdir, name, scan)
                        + 1);
        sprintf(output, "%s/%s.%s", honeymon->originsdir, name, scan);
        int out = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        char *vmi = malloc(snprintf(NULL, 0, "vmi://%s", name) + 1);
        sprintf(vmi, "vmi://%s", name);
        char *profile = malloc(
                snprintf(NULL, 0, "--profile=%s", honeypot->profile) + 1);
        sprintf(profile, "--profile=%s", honeypot->profile);

        printf("Running scan: %s\n", scan);

        struct timeval scan_time_start, scan_time_end;
        gettimeofday(&scan_time_start, NULL);

        pid_t pID = fork();
        if (pID == 0) {
            dup2(out, STDOUT_FILENO);
            dup2(out, STDERR_FILENO);
            prctl(PR_SET_PDEATHSIG, SIGHUP); // pass sighup to die if parent dies
            execl(PYTHON, PYTHON, honeymon->volatility, "-l", vmi, profile,
                    scan, NULL);
            exit(0);
        } else if (pID < 0) {
            errx(1, "Failed to fork!\n");
        }
        waitpid(pID, NULL, 0);

        gettimeofday(&scan_time_end, NULL);
        printf("Scan rune time: %lis\n",
                scan_time_end.tv_sec - scan_time_start.tv_sec);

        close(out);
        free(output);
        free(vmi);
        free(profile);

        honeypot->scans = g_slist_append(honeypot->scans, scan);
        scans = scans->next;
    }

#ifdef HAVE_LIBGUESTFS
    XLU_Config2 *xlu_config = (XLU_Config2 *)honeymon_xen_parse_domconfig_raw(config);

    int number_of_disks;
    XLU_ConfigList *disks_masked=NULL;
    XLU_ConfigList2 *disks=NULL;
    if(xlu_cfg_get_list((XLU_Config *)xlu_config, "disk", &disks_masked, &number_of_disks, 0)) {
        printf("The VM config didn't contain a disk configuration line!\n");
    } else
    disks=(XLU_ConfigList2 *)disks_masked;

    if(number_of_disks<1) {
        printf("No disks are defined in the config!\n");
    }

    char *disk_path=honeymon_xen_first_disk_path((XLU_ConfigList *)disks_masked);

    if(disk_path!=NULL) {
        printf("The original disk path is %s\n", disk_path);
        honeymon_guestfs_checksum(honeymon, honeypot, disk_path);
    }

#endif

    printf("Done!\n");

    free(output);
    free(output_config);
    return 0;
}

int honeymon_xen_restore_origin(honeymon_t* honeymon, char* dom) {

    if (honeymon->workdir == NULL) {
        printf("You need to set a workdir for that!\n");
        return 0;
    }

    honeymon_xen_interface_t *xen = honeymon->xen;
    unsigned int domID = INVALID_DOMID;
    int sysret;
    char* name = NULL;
    sscanf(dom, "%u", &domID);

    if (domID == INVALID_DOMID) {
        name = malloc(sizeof(char) * strlen(dom));
        sprintf(name, "%s", dom);
        libxl_name_to_domid(xen->xl_ctx, name, &domID);
    } else {
        name = libxl_domid_to_name(xen->xl_ctx, domID);
    }

    if (name == NULL) return 0;

    // If domID is invalid at this point, it means the domain is not running right now

    char *path = malloc(
            sizeof(char) * strlen(honeymon->originsdir) + strlen(name) + 9);
    sprintf(path, "%s/%s.origin", honeymon->originsdir, name);

    char *config_path = malloc(
            sizeof(char) * strlen(honeymon->originsdir) + strlen(name) + 9);
    sprintf(config_path, "%s/%s.config", honeymon->originsdir, name);

    struct stat buf;
    if (stat(path, &buf)) {
        printf("Error: you don't have a snapshot of that VM!\n");
        return 0;
    }

    if (stat(config_path, &buf)) {
        printf("Error: you don't have a config of that VM!\n");
        return 0;
    }

    if (domID != INVALID_DOMID) {
        printf("Destroying current loaded version of VM!\n");
        libxl_domain_destroy(xen->xl_ctx, domID, NULL);
        domID = INVALID_DOMID;
    }

    /* We need to call the XL program itself for this... sigh */
    char *command = malloc(
            snprintf(NULL, 0, "%s restore -p %s %s", XL, config_path, path)
                    + 1);
    sprintf(command, "%s restore -p %s %s", XL, config_path, path);
    printf("** RUNNING COMMAND: %s\n", command);
    sysret = system(command);
    free(command);

    libxl_name_to_domid(xen->xl_ctx, name, &domID);

    if (domID == INVALID_DOMID) {
        printf("Restore failed!\n");
    } else {
        honeymon_honeypot_t *origin = (honeymon_honeypot_t *) g_tree_lookup(
                honeymon->honeypots, name);
        origin->domID = domID;
    }

    free(path);
    free(config_path);
    free(name);
    return 0;
}

void honeymon_xen_restore(honeymon_t *honeymon, char *option) {

    if (honeymon->workdir == NULL) {
        printf("You need to set a workdir for that!\n");
        return;
    }

    honeymon_clone_t *clone = honeymon_honeypots_find_clone(honeymon, option);
    if (honeymon_honeypots_find_clone(honeymon, option)) printf(
            "We already have a clone defined with this name: %s\n", option);
    else honeymon_xen_restore_origin(honeymon, option);

}

void honeymon_xen_save_domconfig(honeymon_t* honeymon,
        XLU_Config *config_masked, char* path) {

    // Unmask the config datastructure
    XLU_Config2 *config = (XLU_Config2 *) config_masked;
    XLU_ConfigList2 *setting;

    FILE *output;
    output = fopen(path, "w");

    for (setting = config->settings; setting; setting =
            (XLU_ConfigList2 *) setting->next) {
        //printf("%s %i %i %s %i\n", setting->name, setting->nvalues, setting->avalues, *(setting->values), setting->lineno);

        fprintf(output, "%s", setting->name);
        if (setting->nvalues >= 1) {
            if (setting->avalues > 1) {
                fprintf(output, "=[ \"%s\" ]", *(setting->values));
            } else {

                long int x;
                int number = sscanf(*(setting->values), "%ld", &x);

                if (number) {

                    // Lets check if the number is actually an IP
                    char delim[] = ".";
                    char *ip = NULL;
                    char *token = malloc(
                            sizeof(char) * strlen(*(setting->values)));
                    sprintf(token, "%s", *(setting->values));
                    strtok(token, delim);
                    strtok(NULL, delim);
                    ip = strtok(NULL, delim);

                    if (ip != NULL) fprintf(output, "=\"%s\"",
                            *(setting->values));
                    else fprintf(output, "=%s", *(setting->values));

                    free(token);
                } else fprintf(output, "=\"%s\"", *(setting->values));
            }
        }
        fprintf(output, "\n");
    }

    fclose(output);
}

/*
 * DomU Configuration management stuff
 */
honeymon_xen_domconfig_raw_t* honeymon_xen_domconfig_raw_by_id(
        honeymon_xen_interface_t *xen, unsigned int domID) {
    honeymon_xen_domconfig_raw_t *config = malloc(
            sizeof(honeymon_xen_domconfig_raw_t));
    config->config_data = NULL;

    int rc = libxl_userdata_retrieve(xen->xl_ctx, domID, "xl",
            &(config->config_data), &(config->config_length));

    //if(rc) printf("Unable to get config file\n");
    //else printf("Config length: %i\tData: %s\n", *config_length, config_data);

    return config;
}

void honeymon_xen_free_domconfig_raw(honeymon_xen_domconfig_raw_t* raw_config) {
    if (raw_config->config_data != NULL) free(raw_config->config_data);
    free(raw_config);
}

XLU_Config* honeymon_xen_parse_domconfig_raw(
        honeymon_xen_domconfig_raw_t* raw_config) {

    XLU_Config *config = xlu_cfg_init(stderr, "cmdline");
    xlu_cfg_readdata(config, (char *) (raw_config->config_data),
            raw_config->config_length);

    /*const char *build=NULL;

     xlu_cfg_get_string(config, "builder", &build, 0);

     printf("Yay, got builder string out of config: %s\n", build);*/

    return config;
}

void honeymon_xen_free_domconfig(XLU_Config *config) {
    xlu_cfg_destroy(config);
}

XLU_Config* honeymon_xen_domconfig_by_id(honeymon_xen_interface_t *xen,
        unsigned int domID) {

    XLU_Config* to_return = NULL;

    /* Get raw config */
    honeymon_xen_domconfig_raw_t* raw_config = honeymon_xen_domconfig_raw_by_id(
            xen, domID);

    if (raw_config->config_length > 0) {
        /* Parse it */
        to_return = honeymon_xen_parse_domconfig_raw(raw_config);
    }
    honeymon_xen_free_domconfig_raw(raw_config);

    /* Return parsed config */
    return to_return;
}

XLU_Config* honeymon_xen_domconfig_by_name(honeymon_xen_interface_t *xen,
        char* domain_name) {
    unsigned int domID;
    libxl_name_to_domid(xen->xl_ctx, domain_name, &domID);
    return honeymon_xen_domconfig_by_id(xen, domID);
}
