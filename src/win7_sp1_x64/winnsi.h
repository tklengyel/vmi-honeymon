static char *win7_sp1_x64_winnsi_guid[2] = {
	"4a5be0b10b000",
	"20d0e4c982ca45afa5260fa6e6c256182"
	};
static struct symbol win7_sp1_x64_winnsi[] = {
	{.name = "_FindPESection", .rva = 0x30a0},
	{.name = "__security_cookie_complement", .rva = 0x7028},
	{.name = "__imp_NsiSetParameterEx", .rva = 0x40d8},
	{.name = "HeapHandle", .rva = 0x7048},
	{.name = "_string_", .rva = 0x5538},
	{.name = "_CRT_INIT", .rva = 0x1010},
	{.name = "__imp_GetCurrentThreadId", .rva = 0x4188},
	{.name = "__imp_RpcAsyncCompleteCall", .rva = 0x4088},
	{.name = "NsiRpcDeregisterChangeNotification", .rva = 0x1634},
	{.name = "__imp_RpcAsyncCancelCall", .rva = 0x40a0},
	{.name = "NsiGetParameterEx", .rva = 0x32d0},
	{.name = "__imp_SetEvent", .rva = 0x41b0},
	{.name = "NsiRpcDeregisterChangeNotificationEx", .rva = 0x1670},
	{.name = "_XcptFilter", .rva = 0x3048},
	{.name = "__xc_a", .rva = 0x4218},
	{.name = "NsiRpcEnumerateObjectsAllParameters", .rva = 0x2c40},
	{.name = "__imp_memset", .rva = 0x4030},
	{.name = "__imp_CreateEventW", .rva = 0x41c8},
	{.name = "_initterm", .rva = 0x13d8},
	{.name = "__dyn_tls_init_callback", .rva = 0x7610},
	{.name = "__imp_Sleep", .rva = 0x4158},
	{.name = "__xi_z", .rva = 0x4238},
	{.name = "__imp_UnhandledExceptionFilter", .rva = 0x40f0},
	{.name = "__C_specific_handler", .rva = 0x314c},
	{.name = "MIDL_user_free", .rva = 0x3038},
	{.name = "__imp_HeapFree", .rva = 0x4120},
	{.name = "__imp_InitializeCriticalSectionAndSpinCount", .rva = 0x41d0},
	{.name = "NsiDisconnectFromServer", .rva = 0x18ec},
	{.name = "_amsg_exit", .rva = 0x3140},
	{.name = "NsiRpcRegisterChangeNotification", .rva = 0x1910},
	{.name = "__imp_NsiGetParameterEx", .rva = 0x40c8},
	{.name = "__imp_EnterCriticalSection", .rva = 0x41c0},
	{.name = "NsiRpcGetAllParametersEx", .rva = 0x2560},
	{.name = "RpcNsiDeregisterChangeNotification", .rva = 0x1898},
	{.name = "Ndr64AsyncClientCall", .rva = 0x14a0},
	{.name = "__imp_GetCurrentProcess", .rva = 0x4170},
	{.name = "NsiConnectToServer", .rva = 0x1d24},
	{.name = "__native_startup_lock", .rva = 0x7008},
	{.name = "DllMain", .rva = 0x12a4},
	{.name = "NsiSetParameterEx", .rva = 0x32ac},
	{.name = "__imp___C_specific_handler", .rva = 0x4028},
	{.name = "__imp_RtlCaptureContext", .rva = 0x4050},
	{.name = "NsiRpcGetAllParameters", .rva = 0x26e4},
	{.name = "PrepareRpcAsyncState", .rva = 0x14ac},
	{.name = "__imp_GetLastError", .rva = 0x4100},
	{.name = "__native_dllmain_reason", .rva = 0x7010},
	{.name = "__imp_GetCurrentProcessId", .rva = 0x4180},
	{.name = "__imp_WaitForSingleObject", .rva = 0x41a8},
	{.name = "_ValidateImageBase", .rva = 0x3060},
	{.name = "__imp_HeapAlloc", .rva = 0x4130},
	{.name = "Instance", .rva = 0x7030},
	{.name = "__imp_RpcBindingFree", .rva = 0x40a8},
	{.name = "_DllMainCRTStartup", .rva = 0x1198},
	{.name = "__imp__initterm", .rva = 0x4020},
	{.name = "__imp_RpcStringBindingComposeW", .rva = 0x4090},
	{.name = "NsiRpcSetAllParameters", .rva = 0x2b88},
	{.name = "__imp_SetLastError", .rva = 0x40f8},
	{.name = "$$VProc_ImageExportDirectory", .rva = 0x5290},
	{.name = "NsiRpcSetAllParametersEx", .rva = 0x2a04},
	{.name = "__onexitend", .rva = 0x7038},
	{.name = "RtlLookupFunctionEntry", .rva = 0x3288},
	{.name = "__imp_TerminateProcess", .rva = 0x4178},
	{.name = "__imp_NsiGetAllParametersEx", .rva = 0x40d0},
	{.name = "NotificationListHead", .rva = 0x7050},
	{.name = "__xi_a", .rva = 0x4228},
	{.name = "__imp_GetTickCount", .rva = 0x41f0},
	{.name = "_pRawDllMain", .rva = 0x7608},
	{.name = "__imp_I_RpcExceptionFilter", .rva = 0x4078},
	{.name = "__imp_RegisterWaitForSingleObjectEx", .rva = 0x4208},
	{.name = "__imp_DeleteCriticalSection", .rva = 0x41d8},
	{.name = "__xc_z", .rva = 0x4220},
	{.name = "NsiWorkerThread", .rva = 0x1500},
	{.name = "NsiRpcSetParameterEx", .rva = 0x27c0},
	{.name = "NsiRpcSetParameter", .rva = 0x2944},
	{.name = "__imp_GetSystemTimeAsFileTime", .rva = 0x41e8},
	{.name = "__imp_LocalAlloc", .rva = 0x4160},
	{.name = "__imp_GetProcessHeap", .rva = 0x4128},
	{.name = "__imp_UnregisterWaitEx", .rva = 0x4200},
	{.name = "__imp_RpcBindingSetAuthInfoW", .rva = 0x4070},
	{.name = "__imp_Ndr64AsyncClientCall", .rva = 0x4060},
	{.name = "NsiRpcGetParameter", .rva = 0x1de0},
	{.name = "__imp_RpcBindingFromStringBindingW", .rva = 0x4098},
	{.name = "__imp__amsg_exit", .rva = 0x4010},
	{.name = "__imp_DisableThreadLibraryCalls", .rva = 0x4140},
	{.name = "__imp_RtlLookupFunctionEntry", .rva = 0x4040},
	{.name = "__imp_QueryPerformanceCounter", .rva = 0x4198},
	{.name = "NsiSetAllParametersEx", .rva = 0x32dc},
	{.name = "__imp_RpcStringFreeW", .rva = 0x4080},
	{.name = "__imp_RtlVirtualUnwind", .rva = 0x4048},
	{.name = "NsiEnumerateObjectsAllParameters", .rva = 0x32b8},
	{.name = "NsiRpcGetParameterEx", .rva = 0x1e9c},
	{.name = "MIDL_user_allocate", .rva = 0x1620},
	{.name = "__imp_NsiSetAllParametersEx", .rva = 0x40c0},
	{.name = "HotPatchBuffer", .rva = 0x7620},
	{.name = "__imp__XcptFilter", .rva = 0x4008},
	{.name = "NsiRpcRegisterChangeNotificationEx", .rva = 0x19a0},
	{.name = "__security_cookie", .rva = 0x7020},
	{.name = "EchoNotificationRegistered", .rva = 0x7000},
	{.name = "NotificationListLock", .rva = 0x75e0},
	{.name = "__imp_CloseHandle", .rva = 0x4110},
	{.name = "__imp_LocalFree", .rva = 0x4150},
	{.name = "__onexitbegin", .rva = 0x7040},
	{.name = "__imp_SetUnhandledExceptionFilter", .rva = 0x40e8},
	{.name = "__security_init_cookie", .rva = 0x13e4},
	{.name = "__imp_NsiEnumerateObjectsAllParameters", .rva = 0x40b8},
	{.name = "__imp_malloc", .rva = 0x4000},
	{.name = "_string__2", .rva = 0x54f0},
	{.name = "RtlVirtualUnwind", .rva = 0x327c},
	{.name = "I_RpcExceptionFilter", .rva = 0x32a0},
	{.name = "__report_gsfailure", .rva = 0x3154},
	{.name = "__imp_LeaveCriticalSection", .rva = 0x41b8},
	{.name = "__imp_RpcAsyncInitializeHandle", .rva = 0x4068},
	{.name = "__native_startup_state", .rva = 0x7018},
	{.name = "NsiGetAllParametersEx", .rva = 0x32c4},
	{.name = "__imp_free", .rva = 0x4018},
	{.name = "_IsNonwritableInCurrentImage", .rva = 0x30ec},
	{.name = "memset", .rva = 0x14f0},

};
static uint64_t win7_sp1_x64_winnsi_count = 117;