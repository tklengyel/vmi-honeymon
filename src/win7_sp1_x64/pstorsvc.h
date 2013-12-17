static char *win7_sp1_x64_pstorsvc_guid[2] = {
	"4a5be02b0d000",
	"e3820a5cb7394ed0bec746a0b464fd882"
	};
static struct symbol win7_sp1_x64_pstorsvc[] = {
	{.name = "PstoreCallback", .rva = 0x1374},
	{.name = "_string_", .rva = 0x7620},
	{.name = "_string__2", .rva = 0x7670},
	{.name = "_FindPESection", .rva = 0x3f50},
	{.name = "__imp_load_GetSidIdentifierAuthority", .rva = 0x1dfc},
	{.name = "__delayLoadHelper2", .rva = 0x1bd0},
	{.name = "__imp_load_InitializeAcl", .rva = 0x1e80},
	{.name = "__security_cookie_complement", .rva = 0x9128},
	{.name = "__imp_load_RpcServerUnregisterIf", .rva = 0x412c},
	{.name = "_string__3", .rva = 0x5388},
	{.name = "_CRT_INIT", .rva = 0x1230},
	{.name = "__imp_GetCurrentThreadId", .rva = 0x5180},
	{.name = "__imp_NdrServerCallAll", .rva = 0x9000},
	{.name = "__imp_RpcServerRegisterIfEx", .rva = 0x9028},
	{.name = "__imp_load_ImpersonateSelf", .rva = 0x415c},
	{.name = "__imp_CreateFileW", .rva = 0x5088},
	{.name = "_string__4", .rva = 0x7690},
	{.name = "__imp_GetSidIdentifierAuthority", .rva = 0x90d8},
	{.name = "FIsACLSatisfied", .rva = 0x3b90},
	{.name = "_string__5", .rva = 0x7518},
	{.name = "g_liProv", .rva = 0x9190},
	{.name = "_string__6", .rva = 0x7550},
	{.name = "__imp_load_GetSidSubAuthorityCount", .rva = 0x1e14},
	{.name = "__imp_RpcServerUnregisterIf", .rva = 0x9020},
	{.name = "__imp_SetEvent", .rva = 0x5130},
	{.name = "NdrServerCall2", .rva = 0x1d30},
	{.name = "_string__7", .rva = 0x7748},
	{.name = "s_SSGetSubtypeInfo", .rva = 0x3134},
	{.name = "__imp_load_NdrServerCall2", .rva = 0x1d14},
	{.name = "__imp_RevertToSelf", .rva = 0x90d0},
	{.name = "__hmod__RPCRT4_dll", .rva = 0x9268},
	{.name = "s_SSAcquireContext", .rva = 0x1830},
	{.name = "service_ctrl", .rva = 0x3c84},
	{.name = "_XcptFilter", .rva = 0x3efc},
	{.name = "__xc_a", .rva = 0x5198},
	{.name = "s_SSCloseItem", .rva = 0x3ad4},
	{.name = "hServiceStarted", .rva = 0x9148},
	{.name = "GetTokenUserSid", .rva = 0x1534},
	{.name = "_string__8", .rva = 0x5360},
	{.name = "ReportStatusToSCMgr", .rva = 0x2200},
	{.name = "GetLastError", .rva = 0x4188},
	{.name = "memcpy", .rva = 0x1368},
	{.name = "__imp_memset", .rva = 0x5038},
	{.name = "_initterm", .rva = 0x1330},
	{.name = "ServiceEntry", .rva = 0x3c38},
	{.name = "__dyn_tls_init_callback", .rva = 0x97f8},
	{.name = "__imp_load_RpcBindingToStringBindingW", .rva = 0x1db4},
	{.name = "__imp_Sleep", .rva = 0x5170},
	{.name = "__xi_z", .rva = 0x51b8},
	{.name = "s_SSReadAccessRuleset", .rva = 0x39ec},
	{.name = "__imp_UnhandledExceptionFilter", .rva = 0x5098},
	{.name = "__C_specific_handler", .rva = 0x3ffc},
	{.name = "_string__9", .rva = 0x7560},
	{.name = "MIDL_user_free", .rva = 0x1ce0},
	{.name = "__imp_AddAccessAllowedAce", .rva = 0x9058},
	{.name = "FRevertToSelf", .rva = 0x1b14},
	{.name = "_string__10", .rva = 0x7528},
	{.name = "__GSHandlerCheckCommon", .rva = 0x41b8},
	{.name = "_string__11", .rva = 0x75a0},
	{.name = "__imp_SetErrorMode", .rva = 0x5110},
	{.name = "g_hInst", .rva = 0x9158},
	{.name = "_string__12", .rva = 0x5378},
	{.name = "_amsg_exit", .rva = 0x3ff0},
	{.name = "_string__13", .rva = 0x74b8},
	{.name = "_string__14", .rva = 0x7790},
	{.name = "g_fBaseInitialized", .rva = 0x9114},
	{.name = "__DELAY_IMPORT_DESCRIPTOR_RPCRT4_dll", .rva = 0x77d4},
	{.name = "_string__15", .rva = 0x7538},
	{.name = "__imp_LoadLibraryExA", .rva = 0x5160},
	{.name = "__imp_load_RevertToSelf", .rva = 0x4168},
	{.name = "__imp_CreateEventA", .rva = 0x50c0},
	{.name = "__sz_ADVAPI32_dll", .rva = 0x7850},
	{.name = "__imp_load_IsValidSid", .rva = 0x1e38},
	{.name = "__imp_GetCurrentProcess", .rva = 0x50a0},
	{.name = "__imp_InitializeSid", .rva = 0x9098},
	{.name = "s_SSOpenItem", .rva = 0x3a00},
	{.name = "__native_startup_lock", .rva = 0x9100},
	{.name = "DllMain", .rva = 0x1200},
	{.name = "__sz_RPCRT4_dll", .rva = 0x7840},
	{.name = "__GSHandlerCheck_SEH", .rva = 0x4248},
	{.name = "__imp_IsValidSid", .rva = 0x9060},
	{.name = "__imp___C_specific_handler", .rva = 0x5000},
	{.name = "__imp_RtlCaptureContext", .rva = 0x5078},
	{.name = "GetProcAddress", .rva = 0x1cc0},
	{.name = "__imp_GetLastError", .rva = 0x5118},
	{.name = "__native_dllmain_reason", .rva = 0x9108},
	{.name = "__GSHandlerCheck", .rva = 0x4224},
	{.name = "FGetUser", .rva = 0x19e4},
	{.name = "_string__16", .rva = 0x75d0},
	{.name = "__imp_load_CopySid", .rva = 0x1e2c},
	{.name = "__imp_load_RegisterEventSourceW", .rva = 0x4138},
	{.name = "__imp_GetCurrentProcessId", .rva = 0x5188},
	{.name = "_string__17", .rva = 0x7630},
	{.name = "s_SSReleaseContext", .rva = 0x1934},
	{.name = "_ValidateImageBase", .rva = 0x3f10},
	{.name = "_string__18", .rva = 0x7770},
	{.name = "TerminationNotify", .rva = 0x3df0},
	{.name = "__imp_FreeLibrary", .rva = 0x50c8},
	{.name = "__imp_CompareStringW", .rva = 0x5120},
	{.name = "__imp_LocalSize", .rva = 0x5158},
	{.name = "__imp_GetSidSubAuthority", .rva = 0x90a0},
	{.name = "GetTextualSid", .rva = 0x1634},
	{.name = "_DllMainCRTStartup", .rva = 0x10fc},
	{.name = "NdrServerCallAll", .rva = 0x1b48},
	{.name = "s_SSGetProvInfo", .rva = 0x3048},
	{.name = "__imp__initterm", .rva = 0x5018},
	{.name = "__imp_RpcImpersonateClient", .rva = 0x9018},
	{.name = "__imp_SetLastError", .rva = 0x50d8},
	{.name = "__imp_load_RpcServerRegisterIfEx", .rva = 0x1e50},
	{.name = "s_SSPasswordInterface", .rva = 0x3034},
	{.name = "$$VProc_ImageExportDirectory", .rva = 0x76c0},
	{.name = "StringCchPrintfW", .rva = 0x17b0},
	{.name = "__imp_InitializeSecurityDescriptor", .rva = 0x90b8},
	{.name = "__onexitend", .rva = 0x9160},
	{.name = "__imp_RpcServerUseProtseqEpW", .rva = 0x9030},
	{.name = "RtlLookupFunctionEntry", .rva = 0x41ac},
	{.name = "_string__19", .rva = 0x75b0},
	{.name = "__tailMerge_ADVAPI32_dll", .rva = 0x1d38},
	{.name = "__imp_TerminateProcess", .rva = 0x50a8},
	{.name = "__imp_RegisterEventSourceW", .rva = 0x9080},
	{.name = "__imp_GetTokenInformation", .rva = 0x9070},
	{.name = "s_SSDeleteType", .rva = 0x36e8},
	{.name = "__xi_a", .rva = 0x51a8},
	{.name = "__imp_load_AddAccessAllowedAce", .rva = 0x1e8c},
	{.name = "__imp_GetTickCount", .rva = 0x5100},
	{.name = "_string__20", .rva = 0x75c0},
	{.name = "_string__21", .rva = 0x75f0},
	{.name = "__hmod__ADVAPI32_dll", .rva = 0x9270},
	{.name = "__imp_load_DeregisterEventSource", .rva = 0x4150},
	{.name = "_pRawDllMain", .rva = 0x97f0},
	{.name = "FAcquireProvider", .rva = 0x2288},
	{.name = "__imp_RpcRevertToSelfEx", .rva = 0x9010},
	{.name = "LoadLibraryExA", .rva = 0x1eb8},
	{.name = "_string__22", .rva = 0x7610},
	{.name = "FImpersonateClient", .rva = 0x1500},
	{.name = "__imp_load_SetSecurityDescriptorDacl", .rva = 0x1ea4},
	{.name = "s_SSEnumSubtypes", .rva = 0x33f4},
	{.name = "__imp_PulseEvent", .rva = 0x5150},
	{.name = "__security_check_cookie", .rva = 0x1340},
	{.name = "__xc_z", .rva = 0x51a0},
	{.name = "__imp_GetProcAddress", .rva = 0x50f0},
	{.name = "__pfnDefaultDliNotifyHook2", .rva = 0x76b8},
	{.name = "__imp_GetSystemTimeAsFileTime", .rva = 0x5128},
	{.name = "__imp_LocalAlloc", .rva = 0x50f8},
	{.name = "__imp_ReportEventW", .rva = 0x9088},
	{.name = "__imp_DelayLoadFailureHook", .rva = 0x5168},
	{.name = "AddToMessageLog", .rva = 0x3cf4},
	{.name = "__imp_load_InitializeSecurityDescriptor", .rva = 0x1e98},
	{.name = "__imp_SetServiceStatus", .rva = 0x5050},
	{.name = "__imp_RegisterServiceCtrlHandlerW", .rva = 0x5060},
	{.name = "s_SSCreateType", .rva = 0x3570},
	{.name = "__imp_RpcStringBindingParseW", .rva = 0x9040},
	{.name = "s_SSEnumItems", .rva = 0x34ac},
	{.name = "_string__23", .rva = 0x7570},
	{.name = "DeleteCallState", .rva = 0x190c},
	{.name = "__imp_load_GetLengthSid", .rva = 0x1e74},
	{.name = "Start", .rva = 0x3c5c},
	{.name = "__imp_load_GetSidSubAuthority", .rva = 0x1e68},
	{.name = "_string__24", .rva = 0x7500},
	{.name = "__imp_load_RpcRevertToSelfEx", .rva = 0x1de4},
	{.name = "__imp_UnregisterWaitEx", .rva = 0x5140},
	{.name = "ServiceStart", .rva = 0x1f24},
	{.name = "FSetServerParam", .rva = 0x3c1c},
	{.name = "s_SSReadItem", .rva = 0x1428},
	{.name = "FreeLibrary", .rva = 0x417c},
	{.name = "__imp_RpcBindingToStringBindingW", .rva = 0x9048},
	{.name = "__imp__amsg_exit", .rva = 0x5008},
	{.name = "__imp_load_GetTokenInformation", .rva = 0x1e20},
	{.name = "__imp_DisableThreadLibraryCalls", .rva = 0x5108},
	{.name = "__pfnDliNotifyHook2", .rva = 0x76b8},
	{.name = "StringCchPrintfW_2", .rva = 0x17b0},
	{.name = "_string__25", .rva = 0x7590},
	{.name = "__imp_RtlLookupFunctionEntry", .rva = 0x5080},
	{.name = "__imp_QueryPerformanceCounter", .rva = 0x5178},
	{.name = "s_SSPStoreEnumProviders", .rva = 0x2e10},
	{.name = "s_SSWriteItem", .rva = 0x38fc},
	{.name = "hRegisteredWait", .rva = 0x9808},
	{.name = "__imp_DeregisterEventSource", .rva = 0x9090},
	{.name = "__imp_RpcStringFreeW", .rva = 0x9038},
	{.name = "__imp_RtlVirtualUnwind", .rva = 0x50b8},
	{.name = "__imp_load_InitializeSid", .rva = 0x1e5c},
	{.name = "MIDL_user_allocate", .rva = 0x1ccc},
	{.name = "_string__26", .rva = 0x74e8},
	{.name = "_string__27", .rva = 0x75e0},
	{.name = "__imp_RegisterWaitForSingleObject", .rva = 0x5138},
	{.name = "__DELAY_IMPORT_DESCRIPTOR_ADVAPI32_dll", .rva = 0x77f4},
	{.name = "HotPatchBuffer", .rva = 0x9810},
	{.name = "PSTOREServiceMain", .rva = 0x1ec4},
	{.name = "__imp__XcptFilter", .rva = 0x5028},
	{.name = "__imp_memcpy", .rva = 0x5040},
	{.name = "_string__28", .rva = 0x7600},
	{.name = "SearchProvListByID", .rva = 0x19a8},
	{.name = "TeardownServer", .rva = 0x3e20},
	{.name = "__imp_GetSidSubAuthorityCount", .rva = 0x9078},
	{.name = "s_SSCreateSubtype", .rva = 0x361c},
	{.name = "__security_cookie", .rva = 0x9120},
	{.name = "__imp_ResetEvent", .rva = 0x5148},
	{.name = "_string__29", .rva = 0x7648},
	{.name = "__imp_CloseHandle", .rva = 0x50e0},
	{.name = "__imp_LocalFree", .rva = 0x50d0},
	{.name = "__imp_GetLengthSid", .rva = 0x90a8},
	{.name = "__tailMerge_RPCRT4_dll", .rva = 0x1b50},
	{.name = "__imp_LoadLibraryW", .rva = 0x50e8},
	{.name = "__imp_CopySid", .rva = 0x9068},
	{.name = "__onexitbegin", .rva = 0x9168},
	{.name = "__imp_load_OpenThreadToken", .rva = 0x1e08},
	{.name = "s_SSEnumTypes", .rva = 0x3348},
	{.name = "__imp_ImpersonateSelf", .rva = 0x90c8},
	{.name = "__imp__vsnwprintf", .rva = 0x5030},
	{.name = "hServerStopEvent", .rva = 0x9140},
	{.name = "__imp_SetUnhandledExceptionFilter", .rva = 0x5090},
	{.name = "__imp_GetCurrentThread", .rva = 0x50b0},
	{.name = "DelayLoadFailureHook", .rva = 0x4194},
	{.name = "__security_init_cookie", .rva = 0x1048},
	{.name = "__imp_SetSecurityDescriptorDacl", .rva = 0x90c0},
	{.name = "__imp_load_RpcStringFreeW", .rva = 0x1dcc},
	{.name = "__imp_load_NdrServerCallAll", .rva = 0x1df0},
	{.name = "s_SSGetTypeInfo", .rva = 0x3088},
	{.name = "pDaclInitEvent", .rva = 0x9150},
	{.name = "__imp_malloc", .rva = 0x5020},
	{.name = "__imp_load_ReportEventW", .rva = 0x4144},
	{.name = "RtlVirtualUnwind", .rva = 0x41a0},
	{.name = "s_SSDeleteItem", .rva = 0x3830},
	{.name = "__report_gsfailure", .rva = 0x4008},
	{.name = "FGetServerParam", .rva = 0x2734},
	{.name = "_string__30", .rva = 0x7580},
	{.name = "__imp_SearchPathW", .rva = 0x5070},
	{.name = "g_dwLastHandleIssued", .rva = 0x9138},
	{.name = "__native_startup_state", .rva = 0x9118},
	{.name = "__imp_load_RpcStringBindingParseW", .rva = 0x1dc0},
	{.name = "s_SSDeleteSubtype", .rva = 0x3784},
	{.name = "s_SSSetProvParam", .rva = 0x329c},
	{.name = "_string__31", .rva = 0x5370},
	{.name = "s_SSGetProvParam", .rva = 0x31f0},
	{.name = "__imp_load_RpcServerUseProtseqEpW", .rva = 0x1e44},
	{.name = "_string__32", .rva = 0x74d0},
	{.name = "__imp_OpenThreadToken", .rva = 0x90e0},
	{.name = "sshStatusHandle", .rva = 0x9130},
	{.name = "__imp_InitializeAcl", .rva = 0x90b0},
	{.name = "__imp_load_RpcImpersonateClient", .rva = 0x1dd8},
	{.name = "__imp_NdrServerCall2", .rva = 0x9008},
	{.name = "__imp_free", .rva = 0x5010},
	{.name = "s_SSWriteAccessRuleset", .rva = 0x39ec},
	{.name = "_IsNonwritableInCurrentImage", .rva = 0x3f9c},
	{.name = "memset", .rva = 0x27d8},

};
static uint64_t win7_sp1_x64_pstorsvc_count = 245;
