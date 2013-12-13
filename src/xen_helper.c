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

#include <libvmi/libvmi.h>

#include "xen_helper.h"
#include "log.h"
#include "honeypots.h"

bool honeymon_xen_init_interface(honeymon_t* honeymon) {

    honeymon_xen_interface_t *xen = g_malloc0(sizeof(honeymon_xen_interface_t));

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
    if (xen) {
        if (xen->xl_ctx) libxl_ctx_free(xen->xl_ctx);
        if (xen->xl_logger) xtl_logger_destroy(xen->xl_logger);
        if (xen->xsh) xs_close(xen->xsh);
        if (xen->xc) xc_interface_close(xen->xc);
        free(xen);
    }
}

char *honeymon_xen_first_vif_mac(XLU_Config2 *config) {
    // Get the first network interface
    char *ret = NULL;
    XLU_ConfigList2 *vifs = NULL;
    int number_of_vifs;
    if (xlu_cfg_get_list((XLU_Config *) config, "vif", (XLU_ConfigList **)&vifs,
            &number_of_vifs, 0)) {
        printf("The VM config didn't contain network configuration line!\n");
        return NULL;
    }

    if (number_of_vifs < 1) {
        printf("No network interfaces are defined in the config!\n");
        return NULL;
    }

    char delim2[] = ",=";
    char *saveptr;
    char *b = strdup(vifs->values[0]);
    char *vif_parse = strtok_r(b, delim2, &saveptr);
    bool mac = 0;

    while (vif_parse != NULL) {
        if (mac) {
            ret = strdup(vif_parse);
        }

        if (!strcmp(vif_parse, "mac")) mac = 1;
        else mac = 0;

        vif_parse = strtok_r(NULL, delim2, &saveptr);
    }

    free(b);
    return ret;
}

char *honeymon_xen_first_disk_path(XLU_Config2 *config) {
    // Get the path to the disk

    XLU_ConfigList2 *disks = NULL;
    int number_of_disks;
    if (xlu_cfg_get_list((XLU_Config *) config, "disk",
            (XLU_ConfigList **) &disks, &number_of_disks, 0)) {
        printf("The VM config didn't contain disk configuration line!\n");
        return NULL;
    }

    if (number_of_disks < 1) {
        printf("No disks are defined in the config!\n");
        return NULL;
    }

    char delim[] = ":,";
    char *saveptr = NULL;
    char *s = strdup(disks->values[0]);
    char *disk_path = strtok_r(s, delim, &saveptr);

    while (disk_path != NULL) {
        if ((int) disk_path[0] == 47) break;
        disk_path = strtok_r(NULL, delim, &saveptr);
    }

    char *ret = disk_path?strdup(disk_path):NULL;
    free(s);
    return ret;
}

int get_dom_info(honeymon_xen_interface_t *xen, const char *input, uint32_t *domID,
		char **name) {

	uint32_t _domID = INVALID_DOMID;
	char *_name = NULL;

	sscanf(input, "%u", &_domID);

	if (_domID == INVALID_DOMID) {
        _name = strdup(input);
		libxl_name_to_domid(xen->xl_ctx, input, &_domID);
		if (!_domID || _domID == INVALID_DOMID) {
			printf("Domain is not running, failed to get domID from name!\n");
			return -1;
		} else {
			printf("Got domID from name: %u\n", _domID);
		}
	} else {
        printf("Converting domid %u to name\n", _domID);
		_name = libxl_domid_to_name(xen->xl_ctx, _domID);
		if (_name == NULL) {
			printf(
					"Failed to get domain name from ID, is the domain running?\n");
			return -1;
		} else {
			printf("Got name from domID: %s\n", _name);
		}
	}

	*name = _name;
	*domID = _domID;

	return 1;
}

int get_config_disks(XLU_Config2 *config, XLU_ConfigList2 **disks) {
	int number_of_disks;
	XLU_ConfigList *disks_masked = NULL;
	if (xlu_cfg_get_list((XLU_Config *) config, "disk", &disks_masked,
			&number_of_disks, 0)) {
		printf("The VM config didn't contain a disk configuration line!\n");
		return -1;
	}

	if (number_of_disks < 1) {
		printf("No disks are defined in the config!\n");
		return -1;
	}

	*disks = (XLU_ConfigList2 *) disks_masked;
	return 1;
}

int get_config_vifs(XLU_Config2 *config, XLU_ConfigList2 **vifs) {
	// Get the first network interface
	XLU_ConfigList *vifs_masked = NULL;
	int number_of_vifs;
	if (xlu_cfg_get_list((XLU_Config *) config, "vif", &vifs_masked,
			&number_of_vifs, 0)) {
		printf("The VM config didn't contain network configuration line!\n");
		return -1;
	}

	if (number_of_vifs < 1) {
		printf("No network interfaces are defined in the config!\n");
		return -1;
	}

	*vifs = (XLU_ConfigList2 *) vifs_masked;
	return 1;
}

int honeymon_xen_clone_vm(honeymon_t* honeymon, const char* dom) {

    honeymon_xen_interface_t *xen = honeymon->xen;
    honeymon_honeypot_t *honeypot = NULL;
    uint32_t domID = INVALID_DOMID;
    char* name = NULL;
    char* command = NULL;
    int ret = -1;

    if (honeymon->workdir == NULL) {
        printf("You need to set a workdir for that!\n");
        return ret;
    }
    if(-1 == get_dom_info(xen, dom, &domID, &name)) {
    	return ret;
    }

    // Get the honeypot structure
    g_mutex_lock(&honeymon->lock);
	honeypot = g_tree_lookup(honeymon->honeypots, name);

    if (!honeypot) {
    	return ret;
    }

    g_mutex_lock(&honeypot->lock);

    uint16_t vlan_id = honeymon->vlans;
    honeymon->vlans++;
    if (honeymon->vlans < MIN_VLAN) honeymon->vlans += MIN_VLAN;
    g_mutex_unlock(&honeymon->lock);

    XLU_ConfigList2 *disks = NULL, *vifs = NULL;

    if(-1 == get_config_disks(honeypot->config, &disks)) {
    	goto done;
    }

	if (-1 == get_config_vifs(honeypot->config, &vifs)) {
		goto done;
	}

    char *backup_disk = strdup(disks->values[0]);
    char *original_vif = strdup(vifs->values[0]);
    char *backup_vif = strdup(vifs->values[0]);

    // Setup clone
    char *clone_config_path = malloc(
            snprintf(NULL, 0, "%s/%s.%u.config", honeymon->honeypotsdir, name,
                    vlan_id) + 1);
    char *clone_name = malloc(snprintf(NULL, 0, "%s.%u", name, vlan_id) + 1);
    char *vlan = malloc(snprintf(NULL, 0, ".%u", vlan_id) + 1);
    sprintf(clone_config_path, "%s/%s.%u.config", honeymon->honeypotsdir, name,
            vlan_id);
    sprintf(clone_name, "%s.%u", name, vlan_id);
    sprintf(vlan, ".%u", vlan_id);

    printf("Creating clone %s\n\tConfig %s\n\tVLAN %u\n", clone_name,
            clone_config_path, vlan_id);

    // Create LVM2 disk CoW clone
    if(!lvm_lv_snapshot(honeypot->lv, clone_name, lvm_lv_get_size(honeypot->lv))) {
        printf("Failed to create LVM2 snapshot of %s with name %s\n", lvm_lv_get_name(honeypot->lv), clone_name);
        goto done;
    }

    // Update config

    // Replace network bridge
    char delim2[] = ",=";

    GString *new_vif = g_string_new("");
    char *saveptr = NULL;
    char *vif_bridge = strtok_r(original_vif, delim2, &saveptr);
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
        else bridge = 0;

        vif_bridge = strtok_r(NULL, delim2, &saveptr);

        elements++;
    }

    free(original_vif);
    free(vifs->values[0]);

    g_string_append(new_vif, VIF_APPEND);
    printf("New vif is %s\n", new_vif->str);
    vifs->values[0] = g_string_free(new_vif, FALSE);

    // Update the name in the config
    XLU_ConfigList2 *search = honeypot->config->settings;
    while (search != NULL) {
        if (!strcmp(search->name, "name")) {
            free(search->values[0]);
            char *c_name = strdup(clone_name); // this will be freed when the XLU_Config gets destroyed
            search->values[0] = c_name;
            break;
        }
        search = (XLU_ConfigList2 *) search->next;
    }

    honeymon_xen_save_domconfig(honeymon, (XLU_Config *) honeypot->config,
            clone_config_path);

    // Restore the original contents in the config
    free(vifs->values[0]);
    free(disks->values[0]);
    vifs->values[0] = backup_vif;
    disks->values[0] = backup_disk;

    command = malloc(
            snprintf(NULL, 0, "%s restore -p %s %s", XL, clone_config_path,
                    honeypot->snapshot_path) + 1);
    sprintf(command, "%s restore -p %s %s", XL, clone_config_path, honeypot->snapshot_path);
    printf("** RUNNING COMMAND: %s\n", command);
    g_spawn_command_line_sync(command, NULL, NULL, NULL, NULL);
    free(command);

    uint32_t cloneID = 0;
    libxl_name_to_domid(xen->xl_ctx, clone_name, &cloneID);
    if (cloneID != 0) {
        printf("Clone created with domID %i!\n", cloneID);
    } else {
        printf("Clone creation failed!\n");
        goto done;
    }

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

        if (xc_memshr_nominate_gfn(xen->xc, domID, page, &shandle))
        	continue;
        if (xc_memshr_nominate_gfn(xen->xc, cloneID, page, &chandle))
        	continue;
        if (xc_memshr_share_gfns(xen->xc, domID, page, shandle, cloneID, page,
                chandle))
        	continue;

        shared++;
    }

    printf("Shared %i pages!\n", shared);

    honeymon_clone_t *clone = honeymon_honeypots_init_clone(honeymon, name,
            clone_name, vlan_id);

    ret = CLONE_BUFFER - honeypot->clone_buffer;

    printf("Clone %s created\n", clone->clone_name);

    done:
    g_mutex_unlock(&honeypot->lock);

    g_free(clone_name);
    g_free(clone_config_path);
    g_free(vlan);
    g_free(name);

    return ret;
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
    char *output_profile = malloc(
            snprintf(NULL, 0, "%s/%s.profile", honeymon->originsdir, name) + 1);
    char *output_ip = malloc(snprintf(NULL, 0, "%s/%s.ip", honeymon->originsdir, name) + 1);
    sprintf(output, "%s/%s.origin", honeymon->originsdir, name);
    sprintf(output_config, "%s/%s.config", honeymon->originsdir, name);
    sprintf(output_profile, "%s/%s.profile", honeymon->originsdir, name);
    sprintf(output_ip, "%s/%s.ip", honeymon->originsdir, name);

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
    g_spawn_command_line_sync(command, NULL, NULL, NULL, NULL);
    free(command);

    command = malloc(snprintf(NULL, 0, "%s restore -p %s", XL, output) + 1);
    sprintf(command, "%s restore -p %s", XL, output);
    printf("** RUNNING COMMAND: %s\n", command);
    g_spawn_command_line_sync(command, NULL, NULL, NULL, NULL);
	free(command);

    char ip[INET_ADDRSTRLEN];
    printf("Please enter the IP of this VM: ");
    fflush(stdout);
    char *p = fgets(ip, INET_ADDRSTRLEN, stdin);
    char *nl = strrchr(p, '\r');
    if (nl) *nl = '\0';
    nl = strrchr(p, '\n');
    if (nl) *nl = '\0';

    FILE *output_ipf = fopen(output_ip, "w");
    fprintf(output_ipf, "%s", ip);
    fclose(output_ipf);

    libxl_name_to_domid(xen->xl_ctx, name, &domID);

    honeymon_honeypot_t* honeypot = honeymon_honeypots_init_honeypot(honeymon,
            name);

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

    free(name);
    free(output);
    free(output_config);
    free(output_profile);
    free(output_ip);
    return 0;
}

int honeymon_xen_restore_origin(honeymon_t* honeymon, char* dom) {

    if (honeymon->workdir == NULL) {
        printf("You need to set a workdir for that!\n");
        return 0;
    }

    honeymon_xen_interface_t *xen = honeymon->xen;
    unsigned int domID = INVALID_DOMID;
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
    g_spawn_command_line_sync(command, NULL, NULL, NULL, NULL);
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
            if(setting->avalues > 1)
            fprintf(output, "=[ \"%s\" ]", *(setting->values));
            else fprintf(output, "= \"%s\" ", *(setting->values));
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

	if(libxl_userdata_retrieve(xen->xl_ctx, domID, "xl",

			&(config->config_data), &(config->config_length))) {
		 printf("Unable to get config file\n");
		 return NULL;
	}

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
