static char *win7_sp1_x86_PlaySndSrv_guid[2] = {
	"4a5bdaec16000",
	"f8dc426eaf594d93a7944a25b710b0a32"
	};
static struct symbol win7_sp1_x86_PlaySndSrv[] = {
	{.name = "__imp__InterlockedIncrement_4", .rva = 0x114c},
	{.name = "__imp__FreeLibrary_4", .rva = 0x1138},
	{.name = "___onexitend", .rva = 0x6068},
	{.name = "__real_41f0000000000000", .rva = 0x41c0},
	{.name = "_WPP_MAIN_CB", .rva = 0x60b8},
	{.name = "__imp__RpcServerInqCallAttributesW_8", .rva = 0x10b0},
	{.name = "_CLSID_StdGlobalInterfaceTable", .rva = 0x3ba0},
	{.name = "__imp__EtwGetTraceLoggerHandle_4", .rva = 0x104c},
	{.name = "___CppXcptFilter", .rva = 0x4404},
	{.name = "CPlaySoundShellService__Stop", .rva = 0x3bf5},
	{.name = "_EtwRegisterTraceGuidsW_32", .rva = 0x168d},
	{.name = "_GetProcAddress_8", .rva = 0x25d5},
	{.name = "CPlaySoundServiceModule___vector_deleting_destructor_", .rva = 0x3bc5},
	{.name = "_string_", .rva = 0x27cc},
	{.name = "_string__2", .rva = 0x1430},
	{.name = "___security_cookie", .rva = 0x616c},
	{.name = "___security_check_cookie_4", .rva = 0x1d55},
	{.name = "__GUID_839d7762_5121_4009_9234_4f0d19394f04", .rva = 0x293c},
	{.name = "ATL__CComObject_CPlaySoundShellService___Release", .rva = 0x200b},
	{.name = "ATL__CComCreator_ATL__CComObject_CPlaySoundShellService_____CreateInstance", .rva = 0x2a86},
	{.name = "ATL__AtlCallTermFunc", .rva = 0x3a10},
	{.name = "__imp__QueryPerformanceCounter_4", .rva = 0x10c8},
	{.name = "__SEH_epilog4", .rva = 0x12a0},
	{.name = "__imp__DelayLoadFailureHook_8", .rva = 0x1144},
	{.name = "__imp__Sleep_4", .rva = 0x10cc},
	{.name = "ATL__CComClassFactory___vftable_", .rva = 0x2854},
	{.name = "__imp__HeapFree_12", .rva = 0x1160},
	{.name = "ATL__CComCreator2_ATL__CComCreator_ATL__CComObject_CPlaySoundShellService____ATL__CComFailCreator_-2147221232_____CreateInstance", .rva = 0x2a61},
	{.name = "CBeepRedirector__WorkThread", .rva = 0x2ceb},
	{.name = "__SEH_prolog4", .rva = 0x12c0},
	{.name = "__imp__DeviceIoControl_32", .rva = 0x10fc},
	{.name = "ATL__CAtlBaseModule___CAtlBaseModule", .rva = 0x437f},
	{.name = "__imp__RtlInitUnicodeString_8", .rva = 0x1060},
	{.name = "ATL__CAtlBaseModule__CAtlBaseModule", .rva = 0x1c84},
	{.name = "ATL__CComObjectNoLock_ATL__CComClassFactory___CComObjectNoLock_ATL__CComClassFactory_", .rva = 0x29cb},
	{.name = "__imp__CoCreateInstance_20", .rva = 0x6000},
	{.name = "_DllGetClassObject_12", .rva = 0x2385},
	{.name = "_string__6", .rva = 0x214c},
	{.name = "_string__8", .rva = 0x27dc},
	{.name = "CBeepRedirector__Generate16bitMonoTone", .rva = 0x40c6},
	{.name = "_string__9", .rva = 0x2158},
	{.name = "__imp__TerminateProcess_8", .rva = 0x10b8},
	{.name = "ATL___pAtlModule", .rva = 0x604c},
	{.name = "_string__10", .rva = 0x1370},
	{.name = "_string__11", .rva = 0x13f8},
	{.name = "CPlaySoundShellService__UpdateRegistry", .rva = 0x3beb},
	{.name = "CPlaySoundServiceModule___scalar_deleting_destructor_", .rva = 0x3bc5},
	{.name = "__imp__CreateMutexW_12", .rva = 0x111c},
	{.name = "__imp__LoadLibraryExA_12", .rva = 0x1130},
	{.name = "_WPP_GLOBAL_Control", .rva = 0x6040},
	{.name = "__imp__LoadLibraryExW_12", .rva = 0x112c},
	{.name = "_DllMain_12", .rva = 0x1b09},
	{.name = "__imp__GetSystemTimeAsFileTime_4", .rva = 0x10bc},
	{.name = "ATL__CComObjectNoLock_ATL__CComClassFactory____vftable_", .rva = 0x29e4},
	{.name = "_CLSID_PlaySoundShellService", .rva = 0x15a4},
	{.name = "ATL__AtlInternalQueryInterface", .rva = 0x1f83},
	{.name = "_string__12", .rva = 0x13a0},
	{.name = "__imp__NdrAsyncServerCall_4", .rva = 0x1098},
	{.name = "__imp__RpcServerUnregisterIf_12", .rva = 0x10a8},
	{.name = "__imp___ftol2_sse", .rva = 0x1010},
	{.name = "___pobjMapEntryFirst", .rva = 0x1ed0},
	{.name = "__imp__WaitForMultipleObjectsEx_20", .rva = 0x10f0},
	{.name = "__imp__ProcessIdToSessionId_8", .rva = 0x110c},
	{.name = "__CIsin", .rva = 0x4474},
	{.name = "__imp__CreateThread_24", .rva = 0x10e0},
	{.name = "_DoSoundConnect_0", .rva = 0x2279},
	{.name = "__imp__NtCreateFile_44", .rva = 0x105c},
	{.name = "_atexit", .rva = 0x1922},
	{.name = "CBeepRedirector___CBeepRedirector", .rva = 0x4048},
	{.name = "ATL__CComObjectNoLock_ATL__CComClassFactory____CComObjectNoLock_ATL__CComClassFactory_", .rva = 0x3ca5},
	{.name = "_CurrentSessionId", .rva = 0x6100},
	{.name = "StringCchPrintfW", .rva = 0x2084},
	{.name = "CBeepRedirector__CBeepRedirector", .rva = 0x20e6},
	{.name = "__imp__QueryServiceStatus_8", .rva = 0x1074},
	{.name = "__imp__GetTickCount_0", .rva = 0x10c4},
	{.name = "__unlock", .rva = 0x19e7},
	{.name = "_WPP_SF_dd_24", .rva = 0x3d9a},
	{.name = "ATL___ATL_WIN_MODULE70___ATL_WIN_MODULE70", .rva = 0x1bdd},
	{.name = "__imp__CreateEventW_16", .rva = 0x10e4},
	{.name = "ATL__CAtlModuleT_CPlaySoundServiceModule___AddCommonRGSReplacements", .rva = 0x3ab5},
	{.name = "__hmod__ole32_dll", .rva = 0x6170},
	{.name = "__imp__DisableThreadLibraryCalls_4", .rva = 0x1150},
	{.name = "ATL__CComObjectRootBase__ObjectMain", .rva = 0x15e1},
	{.name = "__imp__SetUnhandledExceptionFilter_4", .rva = 0x1110},
	{.name = "_EtwGetTraceEnableFlags_8", .rva = 0x1a6a},
	{.name = "__imp___amsg_exit", .rva = 0x1038},
	{.name = "StringCbCatW", .rva = 0x3e20},
	{.name = "ATL__CSimpleArray_unsigned_short_ATL__CSimpleArrayEqualHelper_unsigned_short_____RemoveAll", .rva = 0x42c1},
	{.name = "LoadAccessResourceDll", .rva = 0x3e99},
	{.name = "ATL__CComClassFactory___InternalQueryInterface", .rva = 0x2a19},
	{.name = "__real_3fe0000000000000", .rva = 0x41a8},
	{.name = "__purecall", .rva = 0x4453},
	{.name = "__imp__GetCurrentProcessId_0", .rva = 0x1108},
	{.name = "__DELAY_IMPORT_DESCRIPTOR_ole32_dll", .rva = 0x478c},
	{.name = "___CxxFrameHandler3", .rva = 0x445e},
	{.name = "__initterm_e", .rva = 0x169c},
	{.name = "_string__13", .rva = 0x278c},
	{.name = "__CRT_INIT_12", .rva = 0x1d67},
	{.name = "_string__16", .rva = 0x135c},
	{.name = "__imp__GetSystemDirectoryW_8", .rva = 0x1128},
	{.name = "_GetObjectDescription__$CComCoClass_VCPlaySoundShellService__$1_CLSID_PlaySoundShellService__3U_GUID__B_ATL__SGPBGXZ", .rva = 0x3c39},
	{.name = "_WPP_ThisDir_CTLGUID_AudioTrace", .rva = 0x1b68},
	{.name = "_PlaySoundServerTerminate_12", .rva = 0x3f6d},
	{.name = "CPlaySoundShellService___InternalQueryInterface", .rva = 0x2909},
	{.name = "_string__17", .rva = 0x21d8},
	{.name = "__imp__memset", .rva = 0x1008},
	{.name = "ATL___AtlBaseModule", .rva = 0x6130},
	{.name = "ATL__CAtlComModule__Term", .rva = 0x43bb},
	{.name = "ATL__CAtlModule__Term", .rva = 0x3a5a},
	{.name = "__imp__EtwGetTraceEnableFlags_8", .rva = 0x106c},
	{.name = "__SEH_prolog4_GS", .rva = 0x21f2},
	{.name = "ATL__CAtlModule__GetLockCount", .rva = 0x3b49},
	{.name = "__imp__InitializeCriticalSection_4", .rva = 0x1158},
	{.name = "__imp__EtwRegisterTraceGuidsW_32", .rva = 0x1050},
	{.name = "ATL__CAtlComModule__ExecuteObjectMain", .rva = 0x176c},
	{.name = "InlineIsEqualGUID", .rva = 0x2485},
	{.name = "__SEH_epilog4_GS", .rva = 0x2bb4},
	{.name = "_WppControlCallback_16", .rva = 0x19f2},
	{.name = "__imp__RpcAsyncCompleteCall_8", .rva = 0x10ac},
	{.name = "__imp___initterm", .rva = 0x103c},
	{.name = "__ftol2_sse", .rva = 0x4469},
	{.name = "_CPlaySoundShellService___GetEntries____2____entries", .rva = 0x2924},
	{.name = "_I_PlaySoundkPostMessage_24", .rva = 0x1180},
	{.name = "_string__18", .rva = 0x3ad8},
	{.name = "__sz_WINMM_dll", .rva = 0x4810},
	{.name = "__imp__GetProcAddress_8", .rva = 0x1140},
	{.name = "___pobjMapEntryLast", .rva = 0x1ed8},
	{.name = "_EtwUnregisterTraceGuids_8", .rva = 0x46ad},
	{.name = "___delayLoadHelper2_8", .rva = 0x24d6},
	{.name = "__imp__GetOverlappedResult_16", .rva = 0x10e8},
	{.name = "CBeepRedirector__Terminate", .rva = 0x404e},
	{.name = "__tailMerge_WINMM_dll", .rva = 0x24c0},
	{.name = "__imp__ResetEvent_4", .rva = 0x10ec},
	{.name = "ATL__CComObject_CPlaySoundShellService____vftable_", .rva = 0x28c8},
	{.name = "__imp__DoSoundConnect_0", .rva = 0x108c},
	{.name = "_string__21", .rva = 0x1388},
	{.name = "_string__22", .rva = 0x137c},
	{.name = "__imp__Beep_8", .rva = 0x1124},
	{.name = "___native_dllmain_reason", .rva = 0x6048},
	{.name = "_floor", .rva = 0x447f},
	{.name = "_NdrAsyncServerCall_4", .rva = 0x1565},
	{.name = "__lock", .rva = 0x166c},
	{.name = "_WppCleanupUm_0", .rva = 0x39b3},
	{.name = "_WPP_INIT_CONTROL_ARRAY_4", .rva = 0x15b9},
	{.name = "__imp___except_handler4_common", .rva = 0x1034},
	{.name = "CBeepRedirector__IsBeepRunning", .rva = 0x20ff},
	{.name = "__imp__SetEvent_4", .rva = 0x1100},
	{.name = "__imp___unlock", .rva = 0x1030},
	{.name = "_string__23", .rva = 0x2cc8},
	{.name = "ATL__CComObjectRootBase__GetCategoryMap", .rva = 0x3c39},
	{.name = "__imp__OpenServiceW_12", .rva = 0x107c},
	{.name = "__imp__RtlAllocateHeap_12", .rva = 0x1068},
	{.name = "_LoadLibraryExA_12", .rva = 0x228f},
	{.name = "$$VProc_ImageExportDirectory", .rva = 0x22cc},
	{.name = "__imp__RpcServerRegisterIfEx_24", .rva = 0x10a0},
	{.name = "___security_init_cookie", .rva = 0x1620},
	{.name = "__FindPESection", .rva = 0x44da},
	{.name = "_string__26", .rva = 0x131c},
	{.name = "__imp__EnterCriticalSection_4", .rva = 0x1168},
	{.name = "_string__27", .rva = 0x1344},
	{.name = "_GetLastError_0", .rva = 0x46e6},
	{.name = "___xi_a", .rva = 0x1e38},
	{.name = "__DELAY_IMPORT_DESCRIPTOR_WINMM_dll", .rva = 0x47ac},
	{.name = "___xc_a", .rva = 0x1e20},
	{.name = "___xc_z", .rva = 0x1e34},
	{.name = "___xi_z", .rva = 0x1e40},
	{.name = "g_hMutexAccessibilitySoundAgentRunning", .rva = 0x6058},
	{.name = "_string__28", .rva = 0x3f48},
	{.name = "__objMap_CPlaySoundShellService", .rva = 0x6178},
	{.name = "__except_handler4", .rva = 0x4429},
	{.name = "ATL__CAtlModule__CAtlModule", .rva = 0x1a75},
	{.name = "ATL__CComObject_CPlaySoundShellService___QueryInterface", .rva = 0x28ed},
	{.name = "_string__29", .rva = 0x13b4},
	{.name = "operator_new", .rva = 0x1f0d},
	{.name = "ATL__CAtlDllModuleT_CPlaySoundServiceModule___GetClassObject", .rva = 0x2397},
	{.name = "__imp__DoSoundDisconnect_0", .rva = 0x1090},
	{.name = "ATL__CComObjectNoLock_ATL__CComClassFactory____scalar_deleting_destructor_", .rva = 0x3d0a},
	{.name = "__XcptFilter", .rva = 0x4495},
	{.name = "__imp__GetCurrentProcess_0", .rva = 0x10d0},
	{.name = "___pfnDefaultDliNotifyHook2", .rva = 0x25cc},
	{.name = "___security_cookie_complement", .rva = 0x6044},
	{.name = "ATL__CComObjectNoLock_ATL__CComClassFactory___Release", .rva = 0x2051},
	{.name = "__imp___lock", .rva = 0x1028},
	{.name = "___pobjMap_CPlaySoundShellService", .rva = 0x1ed4},
	{.name = "__imp__free", .rva = 0x101c},
	{.name = "ATL__CAtlModule__GetGITPtr", .rva = 0x3b52},
	{.name = "___pfnDliNotifyHook2", .rva = 0x25cc},
	{.name = "__imp__LoadLibraryW_4", .rva = 0x10dc},
	{.name = "BeepRedirector", .rva = 0x605c},
	{.name = "CBeepRedirector__SubmitBeepRedirectorRequest", .rva = 0x2d66},
	{.name = "ATL___AtlWinModule", .rva = 0x6104},
	{.name = "__sz_ole32_dll", .rva = 0x4800},
	{.name = "_BeepRedirectorCritSec", .rva = 0x60a0},
	{.name = "_string__32", .rva = 0x1330},
	{.name = "__imp__floor", .rva = 0x1018},
	{.name = "_string__33", .rva = 0x1418},
	{.name = "__EH_epilog3", .rva = 0x2c2d},
	{.name = "ATL__AtlWinModuleTerm", .rva = 0x4316},
	{.name = "operator_delete", .rva = 0x3995},
	{.name = "__imp__GetVersionExA_4", .rva = 0x10d8},
	{.name = "__imp__RpcServerListen_12", .rva = 0x10a4},
	{.name = "ATL__CComFailCreator_-2147221232___CreateInstance", .rva = 0x3c41},
	{.name = "ATL___ATL_BASE_MODULE70___ATL_BASE_MODULE70", .rva = 0x15e9},
	{.name = "__imp__GetProcessHeap_0", .rva = 0x115c},
	{.name = "__imp__EtwUnregisterTraceGuids_8", .rva = 0x1054},
	{.name = "_memset", .rva = 0x160a},
	{.name = "ATL__CSimpleArray_HINSTANCE_____ATL__CSimpleArrayEqualHelper_HINSTANCE_________RemoveAll", .rva = 0x42c1},
	{.name = "__onexit", .rva = 0x193e},
	{.name = "__imp__RpcServerUseProtseqEpW_16", .rva = 0x109c},
	{.name = "__hmod__WINMM_dll", .rva = 0x6174},
	{.name = "__imp__WaitForSingleObject_8", .rva = 0x1104},
	{.name = "_PlaySoundServerInitialize_12", .rva = 0x2624},
	{.name = "ATL__CAtlModule__Unlock", .rva = 0x3b39},
	{.name = "__imp___purecall", .rva = 0x1000},
	{.name = "__GUID_00000146_0000_0000_c000_000000000046", .rva = 0x3bb0},
	{.name = "__EH_prolog3", .rva = 0x2241},
	{.name = "___dllonexit", .rva = 0x1661},
	{.name = "ATL__CComClassFactory__CComClassFactory", .rva = 0x283a},
	{.name = "ATL___AtlComModule", .rva = 0x60d8},
	{.name = "__imp__PlaySoundW_12", .rva = 0x6008},
	{.name = "_EtwGetTraceEnableLevel_8", .rva = 0x1677},
	{.name = "ATL__CComObject_CPlaySoundShellService___CComObject_CPlaySoundShellService_", .rva = 0x28a3},
	{.name = "__imp___vsnwprintf", .rva = 0x1004},
	{.name = "ATL__CComClassFactory__LockServer", .rva = 0x3c7f},
	{.name = "CPlaySoundShellService__Pause", .rva = 0x3beb},
	{.name = "__real_401921fb54442d18", .rva = 0x41b8},
	{.name = "CPlaySoundShellService__Resume", .rva = 0x3beb},
	{.name = "__imp__InterlockedDecrement_4", .rva = 0x1148},
	{.name = "__imp__EtwTraceMessage", .rva = 0x1058},
	{.name = "__except_handler4_common", .rva = 0x45bc},
	{.name = "__initterm", .rva = 0x1615},
	{.name = "___onexitbegin", .rva = 0x606c},
	{.name = "ATL__CAtlBaseModule__m_bInitFailed", .rva = 0x64bc},
	{.name = "ATL__CAtlComModule__CAtlComModule", .rva = 0x1e8d},
	{.name = "_string__36", .rva = 0x3b28},
	{.name = "_WppInitUm_4", .rva = 0x16c3},
	{.name = "__imp__CancelIo_4", .rva = 0x10f4},
	{.name = "ATL__CComCreator_ATL__CComObjectNoLock_ATL__CComClassFactory_____CreateInstance", .rva = 0x2951},
	{.name = "_PlaySoundKRpc_v1_0_s_ifspec", .rva = 0x64c8},
	{.name = "__imp____CxxFrameHandler3", .rva = 0x100c},
	{.name = "__imp__UnhandledExceptionFilter_4", .rva = 0x1114},
	{.name = "__imp__FreeLibraryAndExitThread_8", .rva = 0x10f8},
	{.name = "ATL__CComObjectNoLock_ATL__CComClassFactory___AddRef", .rva = 0x2036},
	{.name = "__imp__GetLastError_0", .rva = 0x113c},
	{.name = "CBeepRedirector__Initialize", .rva = 0x2c46},
	{.name = "___report_gsfailure", .rva = 0x45c2},
	{.name = "__imp__InterlockedCompareExchange_12", .rva = 0x1134},
	{.name = "_WPP_REGISTRATION_GUIDS", .rva = 0x6050},
	{.name = "___native_startup_lock", .rva = 0x609c},
	{.name = "CBeepRedirector__DoPlaySound", .rva = 0x41cd},
	{.name = "ATL__CComClassFactory__CreateInstance", .rva = 0x286d},
	{.name = "__imp__malloc", .rva = 0x1020},
	{.name = "_DllCanUnloadNow_0", .rva = 0x39f7},
	{.name = "ATL__CAtlDllModuleT_CPlaySoundServiceModule___CAtlDllModuleT_CPlaySoundServiceModule_", .rva = 0x174d},
	{.name = "ATL__CAtlWinModule__CAtlWinModule", .rva = 0x1c30},
	{.name = "ATL__CComObjectNoLock_ATL__CComClassFactory___QueryInterface", .rva = 0x29fd},
	{.name = "ATL__CComObject_CPlaySoundShellService____CComObject_CPlaySoundShellService_", .rva = 0x3cbd},
	{.name = "ATL__CAtlWinModule___CAtlWinModule", .rva = 0x439c},
	{.name = "ATL__CAtlDllModuleT_CPlaySoundServiceModule____CAtlDllModuleT_CPlaySoundServiceModule_", .rva = 0x3a9a},
	{.name = "ATL__CComObject_CPlaySoundShellService____scalar_deleting_destructor_", .rva = 0x3ce4},
	{.name = "___native_startup_state", .rva = 0x6064},
	{.name = "_ATL__CComClassFactory___GetEntries____2____entries", .rva = 0x2a34},
	{.name = "__load_config_used", .rva = 0x3940},
	{.name = "_InterlockedCompareExchange_12", .rva = 0x2284},
	{.name = "_FreeLibrary_4", .rva = 0x46f1},
	{.name = "ATL__CComSafeDeleteCriticalSection__Init", .rva = 0x2b10},
	{.name = "_WPP_SF__16", .rva = 0x1f3b},
	{.name = "__imp__RaiseException_16", .rva = 0x1164},
	{.name = "_DoSoundDisconnect_0", .rva = 0x46d0},
	{.name = "__tailMerge_ole32_dll", .rva = 0x46ba},
	{.name = "__imp__EtwGetTraceEnableLevel_8", .rva = 0x1048},
	{.name = "PlaySoundServerInitializeBeepRedirector", .rva = 0x2bc8},
	{.name = "__pRawDllMain", .rva = 0x64c0},
	{.name = "__imp_load__CoCreateInstance_20", .rva = 0x46b3},
	{.name = "_DelayLoadFailureHook_8", .rva = 0x46db},
	{.name = "_free", .rva = 0x448a},
	{.name = "ATL__CComObjectRootEx_ATL__CComMultiThreadModel___CComObjectRootEx_ATL__CComMultiThreadModel_", .rva = 0x1f61},
	{.name = "CPlaySoundShellService__Start", .rva = 0x25e0},
	{.name = "ATL__CComObjectRootEx_ATL__CComMultiThreadModel____CComObjectRootEx_ATL__CComMultiThreadModel_", .rva = 0x3c65},
	{.name = "__imp__DeleteCriticalSection_4", .rva = 0x1154},
	{.name = "_EtwGetTraceLoggerHandle_4", .rva = 0x1682},
	{.name = "__imp__CloseHandle_4", .rva = 0x1120},
	{.name = "_AtlModule", .rva = 0x6070},
	{.name = "__real_40dfffc000000000", .rva = 0x41b0},
	{.name = "CPlaySoundServiceModule___vftable_", .rva = 0x1730},
	{.name = "__DllMainCRTStartup_12", .rva = 0x1799},
	{.name = "_PlaySndServer_midl_user_free_4", .rva = 0x3e09},
	{.name = "__imp__OpenSCManagerW_12", .rva = 0x1080},
	{.name = "_string__38", .rva = 0x13d4},
	{.name = "CBeepRedirector__OpenBeepDevice", .rva = 0x217b},
	{.name = "ATL__CAtlDllModuleT_CPlaySoundServiceModule____DllMain", .rva = 0x1bad},
	{.name = "__imp___onexit", .rva = 0x1024},
	{.name = "ATL__CComObject_CPlaySoundShellService____vector_deleting_destructor_", .rva = 0x3ce4},
	{.name = "ATL__AtlComModuleGetClassObject", .rva = 0x23b8},
	{.name = "__imp__HeapAlloc_12", .rva = 0x1118},
	{.name = "___dyn_tls_init_callback", .rva = 0x64c4},
	{.name = "__imp__LeaveCriticalSection_4", .rva = 0x116c},
	{.name = "__imp__GetCurrentThreadId_0", .rva = 0x10c0},
	{.name = "ATL__CComCriticalSection__CComCriticalSection", .rva = 0x1bfe},
	{.name = "__GUID_00000000_0000_0000_c000_000000000046", .rva = 0x2470},
	{.name = "__amsg_exit", .rva = 0x45b1},
	{.name = "__imp_load__PlaySoundW_12", .rva = 0x24b9},
	{.name = "__IsNonwritableInCurrentImage", .rva = 0x4523},
	{.name = "__imp___CIsin", .rva = 0x1014},
	{.name = "__GUID_00000001_0000_0000_c000_000000000046", .rva = 0x2a4c},
	{.name = "ATL__InlineIsEqualUnknown", .rva = 0x22b7},
	{.name = "_string__39", .rva = 0x1b78},
	{.name = "__imp___XcptFilter", .rva = 0x1040},
	{.name = "__imp__RtlFreeHeap_12", .rva = 0x1064},
	{.name = "_PlaySndServer_midl_user_allocate_4", .rva = 0x3df2},
	{.name = "CBeepRedirector___scalar_deleting_destructor_", .rva = 0x3dcc},
	{.name = "_GUID_ATLVer70", .rva = 0x1d40},
	{.name = "ATL__CSimpleArray_unsigned_short_ATL__CSimpleArrayEqualHelper_unsigned_short_____operator[]", .rva = 0x42e5},
	{.name = "__imp__UnregisterClassA_8", .rva = 0x1088},
	{.name = "__imp__InterlockedExchange_8", .rva = 0x10d4},
	{.name = "__imp____dllonexit", .rva = 0x102c},
	{.name = "_string__41", .rva = 0x1308},
	{.name = "ATL__CComCriticalSection__Init", .rva = 0x1ab9},
	{.name = "_WPP_SF_d_20", .rva = 0x1570},
	{.name = "_WPP_SF_D_20", .rva = 0x1570},
	{.name = "__ValidateImageBase", .rva = 0x44a0},
	{.name = "ATL__CAtlModule__Lock", .rva = 0x1f2b},
	{.name = "_EtwTraceMessage", .rva = 0x159c},
	{.name = "ATL__AtlWinModuleInit", .rva = 0x1c57},
	{.name = "ATL__CComObject_CPlaySoundShellService___AddRef", .rva = 0x2036},

};
static uint64_t win7_sp1_x86_PlaySndSrv_count = 325;
