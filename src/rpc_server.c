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

#include "vmi-honeymon.h"
#include "honeypots.h"
#include "structures.h"
#include "config.h"

#ifdef HAVE_XMLRPC

#include <xmlrpc-c/base.h>
#include <xmlrpc-c/server.h>
#include <xmlrpc-c/server_abyss.h>

static void dieIfFailed(const char * const description, xmlrpc_env const env) {

	if (env.fault_occurred) {
		g_printerr("%s failed. %s\n", description, env.fault_string);
		exit(1);
	}
}

static xmlrpc_value *
rpc_get_clone(xmlrpc_env * const envP,
		__attribute__((unused))   xmlrpc_value * const paramArrayP,
		__attribute__((unused))void * const serverInfo,
		__attribute__((unused))void * const channelInfo) {

	char *s = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &s);

	honeymon_clone_t *clone = honeymon_honeypots_get_free(honeymon, s);

	if (clone) {
		g_async_queue_push(honeymon->clone_requests, strdup(s));
		honeymon_honeypots_unpause_clones2(clone->clone_name, clone, NULL);
		return xmlrpc_build_value(envP, "(sd)", clone->clone_name, clone->vlan);
	}

	g_free(s);

	return xmlrpc_build_value(envP, "(sd)", "-", 0);
}

static xmlrpc_value *
rpc_get_random_clone(xmlrpc_env * const envP,
		__attribute__((unused))   xmlrpc_value * const paramArrayP,
		__attribute__((unused))void * const serverInfo,
		__attribute__((unused))void * const channelInfo) {

	honeymon_clone_t *clone = honeymon_honeypots_get_random_free(honeymon);

	if (clone) {
		g_async_queue_push(honeymon->clone_requests, strdup(clone->clone_name));
		honeymon_honeypots_unpause_clones2(clone->clone_name, clone, NULL);
		return xmlrpc_build_value(envP, "(sd)", clone->clone_name, clone->vlan);
	}

	return xmlrpc_build_value(envP, "(sd)", "-", 0);
}

static xmlrpc_value *
rpc_stop_clone(xmlrpc_env * const envP,
		__attribute__((unused))   xmlrpc_value * const paramArrayP,
		__attribute__((unused))void * const serverInfo,
		__attribute__((unused))void * const channelInfo) {

	//TODO
	return xmlrpc_build_value(envP, "i", 1);
}

static xmlrpc_value *
rpc_echo_test(xmlrpc_env * const envP,
        __attribute__((unused))   xmlrpc_value * const paramArrayP,
        __attribute__((unused))void * const serverInfo,
        __attribute__((unused))void * const channelInfo) {

    return xmlrpc_build_value(envP, "s", PACKAGE_STRING);
}

/******************************************************************************/

enum rpc_function {
    RPC_ECHO_TEST,
	RPC_GET_CLONE,
	RPC_GET_RANDOM_CLONE,
	RPC_STOP_CLONE,

	__MAX_RPC_FUNCTIONS
};

struct xmlrpc_method_info3
const method[__MAX_RPC_FUNCTIONS] = {
	[RPC_ECHO_TEST] =
		{ 	.methodName = "echo_test",
			.methodFunction = &rpc_echo_test },
	[RPC_GET_CLONE] =
		{ 	.methodName = "get_clone",
			.methodFunction = &rpc_get_clone },
	[RPC_GET_RANDOM_CLONE] =
		{ 	.methodName = "get_random_clone",
			.methodFunction = &rpc_get_random_clone },
	[RPC_STOP_CLONE] =
		{ 	.methodName = "stop_clone",
			.methodFunction = &rpc_stop_clone },
};

/******************************************************************************/

void* rpc_server_thread(void *input) {
	honeymon_t *honeymon = (honeymon_t *)input;
	xmlrpc_server_abyss_parms serverparm;
	xmlrpc_registry * registryP;
	xmlrpc_env env;

	xmlrpc_env_init(&env);

	xmlrpc_server_abyss_global_init(&env);
	dieIfFailed("xmlrpc_server_abyss_global_init", env);

	registryP = xmlrpc_registry_new(&env);
	dieIfFailed("xmlrpc_registry_new", env);

	int i;
	for(i=0;i<__MAX_RPC_FUNCTIONS;i++) {
		xmlrpc_registry_add_method3(&env, registryP, &method[i]);
	}

	dieIfFailed("xmlrpc_registry_add_method2", env);

	serverparm.registryP = registryP;
	serverparm.port_number = RPC_SERVER_PORT;
	serverparm.config_file_name = RPC_SERVER_LOG;

	xmlrpc_server_abyss_create(&env, &serverparm, XMLRPC_APSIZE(port_number),
			&honeymon->rpc_server);
	dieIfFailed("xmlrpc_server_abyss_create", env);

    printf("\tXML-RPC Server has been created\n");

	xmlrpc_server_abyss_run_server(&env, honeymon->rpc_server);
	dieIfFailed("xmlrpc_server_abyss_run_server", env);

	printf("XML-RPC Server has terminated\n");

	xmlrpc_server_abyss_destroy(honeymon->rpc_server);
	xmlrpc_registry_free(registryP);
	xmlrpc_server_abyss_global_term();
	xmlrpc_env_clean(&env);
	return NULL;
}
#endif
