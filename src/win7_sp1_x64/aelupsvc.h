static char *win7_sp1_x64_aelupsvc_guid[2] = {
	"4a5bde7215000",
	"d7c4415f9a16482ba2dfe716c851a1232"
	};
static struct symbol win7_sp1_x64_aelupsvc[] = {
	{.name = "_string_", .rva = 0xdb20},
	{.name = "__imp_CreateThreadpoolWork", .rva = 0xb1a0},
	{.name = "_string__2", .rva = 0xb998},
	{.name = "__imp_RtlReleaseRelativeName", .rva = 0xb238},
	{.name = "__delayLoadHelper2", .rva = 0x675c},
	{.name = "__imp_RtlFreeUnicodeString", .rva = 0xb230},
	{.name = "_string__3", .rva = 0xbf78},
	{.name = "CFileUtils__GetSharedDirectoryLocation", .rva = 0x9e94},
	{.name = "__imp_SetThreadpoolThreadMinimum", .rva = 0xb180},
	{.name = "__security_cookie_complement", .rva = 0x110f8},
	{.name = "_string__4", .rva = 0xce38},
	{.name = "CBinaryLog__StartWriteNew", .rva = 0xa2f0},
	{.name = "__imp_GetProcessId", .rva = 0xb100},
	{.name = "_string__5", .rva = 0xe7e8},
	{.name = "CBinaryLog__MapFile", .rva = 0x462c},
	{.name = "CRecentFilesLog___vector_deleting_destructor_", .rva = 0x9ba4},
	{.name = "AelpEnableDebugMode", .rva = 0x110e4},
	{.name = "_string__6", .rva = 0xc3d8},
	{.name = "_string__7", .rva = 0xe380},
	{.name = "__imp_GetCurrentThreadId", .rva = 0xb108},
	{.name = "AelpUpdateFileAndProgramId", .rva = 0x2034},
	{.name = "__imp_AlpcGetMessageAttribute", .rva = 0xb200},
	{.name = "_string__8", .rva = 0xc658},
	{.name = "__CxxFrameHandler3", .rva = 0xaaec},
	{.name = "__imp_RtlInitUnicodeString", .rva = 0xb2c0},
	{.name = "CBinaryLog__ReadStringBufferUnaligned", .rva = 0x528c},
	{.name = "AelpState", .rva = 0x11150},
	{.name = "_string__9", .rva = 0xd068},
	{.name = "_string__10", .rva = 0xe908},
	{.name = "__imp_CreateFileW", .rva = 0xb0d8},
	{.name = "_string__11", .rva = 0xdc00},
	{.name = "CRecentFileCache__IsFileInLog", .rva = 0x49d4},
	{.name = "_string__12", .rva = 0xd8b0},
	{.name = "_string__13", .rva = 0xce70},
	{.name = "_string__14", .rva = 0xe048},
	{.name = "_string__15", .rva = 0xd995},
	{.name = "AelpGetDebugValue", .rva = 0x5b60},
	{.name = "CMemoryUtils__DeallocString", .rva = 0x4990},
	{.name = "_string__16", .rva = 0xd5d0},
	{.name = "AelpValidateFilePath", .rva = 0x1ea4},
	{.name = "_string__17", .rva = 0xc628},
	{.name = "__imp_RtlCreateSecurityDescriptor", .rva = 0xb298},
	{.name = "CBinaryLog___scalar_deleting_destructor_", .rva = 0x9ba4},
	{.name = "_string__18", .rva = 0xe2c8},
	{.name = "_string__19", .rva = 0xe200},
	{.name = "__imp_RtlEnterCriticalSection", .rva = 0xb310},
	{.name = "_string__20", .rva = 0xbd20},
	{.name = "_string__21", .rva = 0xc5e0},
	{.name = "_string__22", .rva = 0xc300},
	{.name = "_string__23", .rva = 0xb830},
	{.name = "__imp__wcsnicmp", .rva = 0xb068},
	{.name = "_string__24", .rva = 0xe280},
	{.name = "__imp_SetFilePointer", .rva = 0xb358},
	{.name = "_string__25", .rva = 0xd520},
	{.name = "_string__26", .rva = 0xbe18},
	{.name = "_string__27", .rva = 0xc0a8},
	{.name = "__imp_RegisterServiceCtrlHandlerExW", .rva = 0xb088},
	{.name = "AelpGetMaxThreadCount", .rva = 0x6194},
	{.name = "UpdateCRC32", .rva = 0x50d0},
	{.name = "_string__28", .rva = 0xcbf0},
	{.name = "_string__29", .rva = 0xe9d0},
	{.name = "CRecentFilesLog___vftable_", .rva = 0xb588},
	{.name = "SciUpdateFileHandleInformation", .rva = 0x3bec},
	{.name = "AelpLPCListenerThreadHandle", .rva = 0x11118},
	{.name = "_string__30", .rva = 0xc390},
	{.name = "_string__31", .rva = 0xd350},
	{.name = "CRecentFilesLog___scalar_deleting_destructor_", .rva = 0x9ba4},
	{.name = "_string__32", .rva = 0xb8c0},
	{.name = "_string__33", .rva = 0xec20},
	{.name = "_wcsicmp", .rva = 0x24c0},
	{.name = "AelpFileHandleToPath", .rva = 0x182c},
	{.name = "ServiceMain", .rva = 0x5e20},
	{.name = "_string__34", .rva = 0xce00},
	{.name = "_string__35", .rva = 0xe0d8},
	{.name = "CBinaryLog__ReadByteStreamUnaligned", .rva = 0x5388},
	{.name = "_string__36", .rva = 0xb3d0},
	{.name = "CFileUtils__AllocAdminSecurityAttributes", .rva = 0x9d80},
	{.name = "GetLastError", .rva = 0x54e4},
	{.name = "memcpy", .rva = 0x1508},
	{.name = "_string__37", .rva = 0xe698},
	{.name = "__imp_memset", .rva = 0xb030},
	{.name = "__imp_CloseThreadpoolCleanupGroup", .rva = 0xb1a8},
	{.name = "AelpProcessStopListeningMessage", .rva = 0x6a10},
	{.name = "__imp_TraceMessage", .rva = 0x11010},
	{.name = "__imp_NtWaitForSingleObject", .rva = 0xb1e0},
	{.name = "_string__38", .rva = 0xcca0},
	{.name = "_string__39", .rva = 0xcc50},
	{.name = "_string__40", .rva = 0xe138},
	{.name = "__imp_Sleep", .rva = 0xb390},
	{.name = "_string__41", .rva = 0xd9c0},
	{.name = "__imp_UnhandledExceptionFilter", .rva = 0xb0b0},
	{.name = "AelpProcessLPCCalls", .rva = 0x1ab0},
	{.name = "_string__42", .rva = 0xdb70},
	{.name = "__C_specific_handler", .rva = 0xaaf8},
	{.name = "CBinaryLog__ReadExpectedByteStream", .rva = 0x54f0},
	{.name = "_string__43", .rva = 0xc760},
	{.name = "_string__44", .rva = 0xde60},
	{.name = "_string__45", .rva = 0xc880},
	{.name = "CBinaryLog__OpenFile", .rva = 0x540c},
	{.name = "memmove", .rva = 0x1f74},
	{.name = "__imp_HeapFree", .rva = 0xb368},
	{.name = "CBinaryLog___vector_deleting_destructor_", .rva = 0x9ba4},
	{.name = "_DllMain", .rva = 0x1050},
	{.name = "AelTpInitializeThreadPool", .rva = 0x5c5c},
	{.name = "__imp_RtlCreateAcl", .rva = 0xb290},
	{.name = "__imp__wtoi", .rva = 0xb058},
	{.name = "_string__46", .rva = 0xeb40},
	{.name = "_string__47", .rva = 0xcb70},
	{.name = "CBinaryLog__WriteString", .rva = 0x5910},
	{.name = "_string__48", .rva = 0xd850},
	{.name = "__GSHandlerCheckCommon", .rva = 0xa9b0},
	{.name = "__imp_NtCreateEvent", .rva = 0xb1e8},
	{.name = "_string__49", .rva = 0xbfc8},
	{.name = "CBinaryLog__WriteHeader", .rva = 0xa534},
	{.name = "_string__50", .rva = 0xc1c0},
	{.name = "AelpLastDatabaseLookupTimeStart", .rva = 0x11048},
	{.name = "__imp_RtlAllocateHeap", .rva = 0xb2d8},
	{.name = "_string__51", .rva = 0xe650},
	{.name = "_string__52", .rva = 0xe608},
	{.name = "__imp_AlpcInitializeMessageAttribute", .rva = 0xb208},
	{.name = "_string__53", .rva = 0xd760},
	{.name = "AelpGetRegistryDWORD", .rva = 0x6280},
	{.name = "__imp_NtAlpcOpenSenderProcess", .rva = 0xb228},
	{.name = "CBinaryLogUtils__ClearLog", .rva = 0x9f4c},
	{.name = "_string__54", .rva = 0xd180},
	{.name = "_string__55", .rva = 0xd710},
	{.name = "_string__56", .rva = 0xed00},
	{.name = "AelServiceControlFlags", .rva = 0x11040},
	{.name = "AelTppCancelCallback", .rva = 0x99bc},
	{.name = "SvchostPushServiceGlobals", .rva = 0x5b50},
	{.name = "CRecentFileCache__InitializeLog", .rva = 0x4ad8},
	{.name = "__imp_lstrcmpiW", .rva = 0xb388},
	{.name = "_string__57", .rva = 0xbe90},
	{.name = "CRecentFileCache___vftable_", .rva = 0xb548},
	{.name = "CRecentFileCache___scalar_deleting_destructor_", .rva = 0x5194},
	{.name = "AelpProcessPortClosedClientDied", .rva = 0x5de8},
	{.name = "__imp_SetEndOfFile", .rva = 0xb348},
	{.name = "__imp_LoadLibraryExA", .rva = 0xb3a0},
	{.name = "_string__58", .rva = 0xe3f8},
	{.name = "AelTppWorkCallback", .rva = 0x147c},
	{.name = "_string__59", .rva = 0xccf0},
	{.name = "CBinaryLogUtils__StartFreshLog", .rva = 0xa01c},
	{.name = "AelpCreatePortSecurityDescriptor", .rva = 0x6400},
	{.name = "_string__60", .rva = 0xde10},
	{.name = "__imp_CreateThreadpoolCleanupGroup", .rva = 0xb188},
	{.name = "_string__61", .rva = 0xd490},
	{.name = "_string__62", .rva = 0xb680},
	{.name = "__sz_ADVAPI32_dll", .rva = 0xee00},
	{.name = "_string__63", .rva = 0xca00},
	{.name = "_string__64", .rva = 0xda70},
	{.name = "__imp_NtQueryInformationFile", .rva = 0xb280},
	{.name = "__imp_GetSystemInfo", .rva = 0xb148},
	{.name = "__imp_GetCurrentProcess", .rva = 0xb118},
	{.name = "_string__65", .rva = 0xcee0},
	{.name = "ComputeSha1Hash", .rva = 0x271c},
	{.name = "_string__66", .rva = 0xc550},
	{.name = "_string__67", .rva = 0xe170},
	{.name = "_string__68", .rva = 0xc8d0},
	{.name = "DllMain", .rva = 0x1010},
	{.name = "AelpProcessCacheExeMessage", .rva = 0x1080},
	{.name = "AelpHeap", .rva = 0x11128},
	{.name = "_string__69", .rva = 0xd680},
	{.name = "__GSHandlerCheck_SEH", .rva = 0xaa50},
	{.name = "__imp__wcsicmp", .rva = 0xb008},
	{.name = "__imp___C_specific_handler", .rva = 0xb048},
	{.name = "_string__70", .rva = 0xe240},
	{.name = "__imp_RtlCaptureContext", .rva = 0xb1c8},
	{.name = "_string__71", .rva = 0xdd20},
	{.name = "GetProcAddress", .rva = 0x68a4},
	{.name = "__imp_GetLastError", .rva = 0xb0b8},
	{.name = "operator_new", .rva = 0x4718},
	{.name = "FormatAeHashString", .rva = 0x3db0},
	{.name = "__GSHandlerCheck", .rva = 0xaa20},
	{.name = "_string__72", .rva = 0xd230},
	{.name = "__imp_EtwTraceMessage", .rva = 0xb288},
	{.name = "CRecentFileCache__AddFile", .rva = 0x4890},
	{.name = "__imp_memcmp", .rva = 0xb000},
	{.name = "_string__73", .rva = 0xcf60},
	{.name = "__imp_RtlAddAccessAllowedAce", .rva = 0xb270},
	{.name = "_string__74", .rva = 0xe308},
	{.name = "_string__75", .rva = 0xd0a8},
	{.name = "CBinaryLog__EndWriteNew", .rva = 0xa420},
	{.name = "AelpLastDatabaseLookupTimeStop", .rva = 0x11050},
	{.name = "__imp_OutputDebugStringA", .rva = 0xb098},
	{.name = "_string__76", .rva = 0xdca0},
	{.name = "__imp_load_RegisterEventSourceW", .rva = 0xa8a4},
	{.name = "AelpSvchostGlobal", .rva = 0x11110},
	{.name = "_string__77", .rva = 0xd340},
	{.name = "_string__78", .rva = 0xd388},
	{.name = "__imp_GetCurrentProcessId", .rva = 0xb120},
	{.name = "CBinaryLog__UnmapFile", .rva = 0x47d8},
	{.name = "_string__79", .rva = 0xbaf0},
	{.name = "AelpMaxThreadCount", .rva = 0x110e0},
	{.name = "_string__80", .rva = 0xc418},
	{.name = "_string__81", .rva = 0xb870},
	{.name = "_string__82", .rva = 0xe0a8},
	{.name = "CBinaryLog__StartRead", .rva = 0x4544},
	{.name = "_string__83", .rva = 0xe5a0},
	{.name = "__imp_GetFinalPathNameByHandleW", .rva = 0xb0d0},
	{.name = "_string__84", .rva = 0xb960},
	{.name = "_string__85", .rva = 0xd7b0},
	{.name = "__imp_RtlFreeHeap", .rva = 0xb2d0},
	{.name = "__imp_CloseThreadpool", .rva = 0xb170},
	{.name = "CRecentFileCache___CRecentFileCache", .rva = 0x4730},
	{.name = "CRecentFileCache___vector_deleting_destructor_", .rva = 0x5194},
	{.name = "_string__86", .rva = 0xb518},
	{.name = "WPP_SF_", .rva = 0x9b80},
	{.name = "__imp_NtAlpcCreatePort", .rva = 0xb250},
	{.name = "_string__87", .rva = 0xeaa0},
	{.name = "sha1_finish", .rva = 0x40f4},
	{.name = "__imp_HeapAlloc", .rva = 0xb380},
	{.name = "__imp_FreeLibrary", .rva = 0xb340},
	{.name = "_string__88", .rva = 0xe778},
	{.name = "_string__89", .rva = 0xdce8},
	{.name = "CBinaryLog__VerifyChecksum", .rva = 0x500c},
	{.name = "_string__90", .rva = 0xc470},
	{.name = "_string__91", .rva = 0xbe58},
	{.name = "_string__92", .rva = 0xb7b0},
	{.name = "_string__93", .rva = 0xe4b8},
	{.name = "_string__94", .rva = 0xbef8},
	{.name = "_string__95", .rva = 0xc7f0},
	{.name = "TraceMessage", .rva = 0xa98c},
	{.name = "_string__96", .rva = 0xd400},
	{.name = "_string__97", .rva = 0xbc70},
	{.name = "SciRetrieveFileHandleInformation", .rva = 0x227c},
	{.name = "_string__98", .rva = 0xdbb0},
	{.name = "__imp_SetThreadpoolThreadMaximum", .rva = 0xb190},
	{.name = "__imp_CloseThreadpoolCleanupGroupMembers", .rva = 0xb160},
	{.name = "__imp_RtlCreateHeap", .rva = 0xb2e8},
	{.name = "_string__99", .rva = 0xd9a0},
	{.name = "_string__100", .rva = 0xdff0},
	{.name = "__tailMerge_apphelp_dll", .rva = 0x66dc},
	{.name = "_string__101", .rva = 0xb668},
	{.name = "_string__102", .rva = 0xcb20},
	{.name = "_string__103", .rva = 0xc008},
	{.name = "$$VProc_ImageExportDirectory", .rva = 0xb9b0},
	{.name = "_string__104", .rva = 0xcfa0},
	{.name = "_string__105", .rva = 0xc6c0},
	{.name = "RtlLookupFunctionEntry", .rva = 0xa958},
	{.name = "AelpStopEventHandle", .rva = 0x11120},
	{.name = "__tailMerge_ADVAPI32_dll", .rva = 0xa8b0},
	{.name = "_string__106", .rva = 0xb700},
	{.name = "_string__107", .rva = 0xcbc0},
	{.name = "_string__108", .rva = 0xd998},
	{.name = "__imp_TerminateProcess", .rva = 0xb110},
	{.name = "ApphelpCheckRunAppEx", .rva = 0x1f80},
	{.name = "__imp_RegisterEventSourceW", .rva = 0x11018},
	{.name = "_string__109", .rva = 0xd3c0},
	{.name = "_string__110", .rva = 0xd6c8},
	{.name = "__imp_NtApphelpCacheControl", .rva = 0xb248},
	{.name = "CRecentFileCache__Initialize", .rva = 0x4dd4},
	{.name = "_string__111", .rva = 0xe730},
	{.name = "__imp_GetTickCount", .rva = 0xb150},
	{.name = "_string__112", .rva = 0xdfa0},
	{.name = "_string__113", .rva = 0xe1b0},
	{.name = "__hmod__ADVAPI32_dll", .rva = 0x11188},
	{.name = "_string__114", .rva = 0xbf70},
	{.name = "__imp_load_DeregisterEventSource", .rva = 0xa938},
	{.name = "_string__115", .rva = 0xdf58},
	{.name = "CBinaryLog__StartWriteAppend", .rva = 0x55ac},
	{.name = "WPP_SF_Dd", .rva = 0x9f04},
	{.name = "WPP_SF_dd", .rva = 0xa23c},
	{.name = "WPP_SF_DS", .rva = 0x9a3c},
	{.name = "WPP_SF_dS", .rva = 0x9cd8},
	{.name = "WPP_GLOBAL_Control", .rva = 0x11180},
	{.name = "__imp_NtAlpcSendWaitReceivePort", .rva = 0xb318},
	{.name = "_string__116", .rva = 0xb4d0},
	{.name = "_string__117", .rva = 0xe940},
	{.name = "__hmod__apphelp_dll", .rva = 0x11190},
	{.name = "WPP_SF_D", .rva = 0x9a00},
	{.name = "WPP_SF_d", .rva = 0x9a00},
	{.name = "_string__118", .rva = 0xdad0},
	{.name = "_string__119", .rva = 0xbf80},
	{.name = "_string__120", .rva = 0xc838},
	{.name = "__imp_RtlFreeSid", .rva = 0xb260},
	{.name = "__imp_GetDriveTypeW", .rva = 0xb0e0},
	{.name = "_string__121", .rva = 0xb730},
	{.name = "LoadLibraryExA", .rva = 0x66c8},
	{.name = "CBinaryLog__ReadDword", .rva = 0x45b8},
	{.name = "_string__122", .rva = 0xeaf0},
	{.name = "operator_delete", .rva = 0x51cc},
	{.name = "__imp_NtResumeThread", .rva = 0xb218},
	{.name = "__imp_RtlInitializeCriticalSectionAndSpinCount", .rva = 0xb2f8},
	{.name = "CBinaryLogUtils__OpenLog", .rva = 0x4e5c},
	{.name = "_string__123", .rva = 0xd900},
	{.name = "AelpProcessMessage", .rva = 0x1d50},
	{.name = "_string__124", .rva = 0xb4d8},
	{.name = "__imp_NtQueryValueKey", .rva = 0xb2c8},
	{.name = "__imp__vsnprintf", .rva = 0xb070},
	{.name = "__security_check_cookie", .rva = 0x14e0},
	{.name = "_string__125", .rva = 0xd330},
	{.name = "_string__126", .rva = 0xbf68},
	{.name = "_string__127", .rva = 0xc520},
	{.name = "CBinaryLog__Deinit", .rva = 0x4774},
	{.name = "CBinaryLog__WriteByteStream", .rva = 0x59d0},
	{.name = "__imp_GetProcAddress", .rva = 0xb3a8},
	{.name = "ConvertStringSecurityDescriptorToSecurityDescriptorW", .rva = 0xa9a4},
	{.name = "_string__128", .rva = 0xc170},
	{.name = "_PopulateFileAttributePair", .rva = 0x21d0},
	{.name = "_string__129", .rva = 0xbf28},
	{.name = "CMemoryUtils__AllocCopyString", .rva = 0x43d0},
	{.name = "_string__130", .rva = 0xbd50},
	{.name = "__pfnDefaultDliNotifyHook2", .rva = 0xb660},
	{.name = "CRecentFileCache__Deinitialize", .rva = 0x4268},
	{.name = "__imp_GetSystemTimeAsFileTime", .rva = 0xb140},
	{.name = "AeComputeFileHashFromHandle", .rva = 0x258c},
	{.name = "_string__131", .rva = 0xcad0},
	{.name = "AelTpQueueWorkItem", .rva = 0x1dd8},
	{.name = "__imp_ReportEventW", .rva = 0x11000},
	{.name = "__imp_DelayLoadFailureHook", .rva = 0xb398},
	{.name = "__imp_GetProcessHeap", .rva = 0xb378},
	{.name = "__chkstk", .rva = 0x6ec0},
	{.name = "_string__132", .rva = 0xd620},
	{.name = "_string__133", .rva = 0xba20},
	{.name = "_string__134", .rva = 0xd1e0},
	{.name = "EtwTraceMessage", .rva = 0xa998},
	{.name = "__imp_SetServiceStatus", .rva = 0xb080},
	{.name = "__imp_CloseThreadpoolWork", .rva = 0xb198},
	{.name = "_string__135", .rva = 0xbb90},
	{.name = "__imp__errno", .rva = 0xb050},
	{.name = "AelpDebugPrintfEx", .rva = 0x166c},
	{.name = "__imp_UnmapViewOfFile", .rva = 0xb330},
	{.name = "_string__136", .rva = 0xec70},
	{.name = "_string__137", .rva = 0xe4f0},
	{.name = "AelTpInfo", .rva = 0x11080},
	{.name = "_string__138", .rva = 0xc7b0},
	{.name = "CBinaryLog__WriteDword", .rva = 0x57d0},
	{.name = "sha1_update", .rva = 0x27e4},
	{.name = "_string__139", .rva = 0xc120},
	{.name = "memcpy_s", .rva = 0x4cb4},
	{.name = "_string__140", .rva = 0xdc50},
	{.name = "__imp_load_TraceMessage", .rva = 0xa978},
	{.name = "_string__141", .rva = 0xbb40},
	{.name = "_wcslwr_s", .rva = 0x4724},
	{.name = "CRecentFileCache__AddFileToLog", .rva = 0x5644},
	{.name = "CBinaryLog__AddChecksum", .rva = 0x5720},
	{.name = "_string__142", .rva = 0xba80},
	{.name = "__imp_UnregisterWaitEx", .rva = 0xb168},
	{.name = "AelpServiceHandler", .rva = 0x9700},
	{.name = "_string__143", .rva = 0xd268},
	{.name = "AelpShimCacheUpdate", .rva = 0x1f8c},
	{.name = "__imp_ZwClose", .rva = 0xb1c0},
	{.name = "__imp___2_YAPEAX_K_Z", .rva = 0xb018},
	{.name = "AelpUpdateServiceStatus", .rva = 0x60c4},
	{.name = "CBinaryLog___vftable_", .rva = 0xb588},
	{.name = "OfcOpenStore", .rva = 0x4cc0},
	{.name = "FreeLibrary", .rva = 0xa964},
	{.name = "_string__144", .rva = 0xc440},
	{.name = "___B_1___$close_VCRecentFileCache___close_delete__SAXPEAVCRecentFileCache___Z_51", .rva = 0x11c50},
	{.name = "_string__145", .rva = 0xea50},
	{.name = "_string__146", .rva = 0xdeb0},
	{.name = "_string__147", .rva = 0xdf00},
	{.name = "__imp_RtlCreateUserThread", .rva = 0xb220},
	{.name = "_string__148", .rva = 0xcdc8},
	{.name = "__imp_NtClose", .rva = 0xb2b0},
	{.name = "_string__149", .rva = 0xb430},
	{.name = "__pfnDliNotifyHook2", .rva = 0xb660},
	{.name = "_string__150", .rva = 0xe980},
	{.name = "__imp_RtlLookupFunctionEntry", .rva = 0xb1d0},
	{.name = "_string__151", .rva = 0xe7b0},
	{.name = "__imp_QueryPerformanceCounter", .rva = 0xb130},
	{.name = "AelpStartService", .rva = 0x5ea0},
	{.name = "_string__152", .rva = 0xc210},
	{.name = "__imp_SubmitThreadpoolWork", .rva = 0xb1b0},
	{.name = "__imp_RtlLeaveCriticalSection", .rva = 0xb308},
	{.name = "__imp_DeregisterEventSource", .rva = 0x11008},
	{.name = "__imp_CreateFileMappingW", .rva = 0xb328},
	{.name = "__imp_RtlVirtualUnwind", .rva = 0xb1d8},
	{.name = "_string__153", .rva = 0xed48},
	{.name = "_string__154", .rva = 0xbce8},
	{.name = "__imp_ExpandEnvironmentStringsW", .rva = 0xb360},
	{.name = "memcmp", .rva = 0x5574},
	{.name = "OfcAddFile", .rva = 0x4824},
	{.name = "__imp_NtAlpcAcceptConnectPort", .rva = 0xb210},
	{.name = "_string__155", .rva = 0xe6c8},
	{.name = "Log", .rva = 0x9adc},
	{.name = "AelpFreeMessageBundle", .rva = 0x158c},
	{.name = "AelpProcessQueryStateMessage", .rva = 0x9940},
	{.name = "__imp_ConvertStringSecurityDescriptorToSecurityDescriptorW", .rva = 0xb3c0},
	{.name = "_string__156", .rva = 0xe8c0},
	{.name = "_string__157", .rva = 0xe700},
	{.name = "_string__158", .rva = 0xb4a0},
	{.name = "_string__159", .rva = 0xc348},
	{.name = "__DELAY_IMPORT_DESCRIPTOR_ADVAPI32_dll", .rva = 0xed88},
	{.name = "HotPatchBuffer", .rva = 0x11b50},
	{.name = "AelpValidateMessageBundle", .rva = 0x1a70},
	{.name = "_string__160", .rva = 0xb550},
	{.name = "__imp_memcpy", .rva = 0xb038},
	{.name = "_string__161", .rva = 0xcfe8},
	{.name = "WPP_SF_ddd", .rva = 0xa290},
	{.name = "__imp_ApphelpCheckRunAppEx", .rva = 0x11028},
	{.name = "CBinaryLog__Open", .rva = 0x4ed0},
	{.name = "_string__162", .rva = 0xca50},
	{.name = "AelpLogEventToEventLog", .rva = 0x97fc},
	{.name = "__imp___CxxFrameHandler3", .rva = 0xb040},
	{.name = "CBinaryLog__ValidateFile", .rva = 0x4fac},
	{.name = "__security_cookie", .rva = 0x110f0},
	{.name = "_string__163", .rva = 0xd950},
	{.name = "_string__164", .rva = 0xc040},
	{.name = "__DELAY_IMPORT_DESCRIPTOR_apphelp_dll", .rva = 0xeda8},
	{.name = "_string__165", .rva = 0xbf60},
	{.name = "AelpInitializeLPCPort", .rva = 0x62f8},
	{.name = "CFileUtils__GetCacheFilePath", .rva = 0x42bc},
	{.name = "_alloca_probe", .rva = 0x6ec0},
	{.name = "_string__166", .rva = 0xbc20},
	{.name = "__imp_RtlExitUserThread", .rva = 0xb1f0},
	{.name = "CRecentFilesLog__ReadNextRecord", .rva = 0x51d8},
	{.name = "_string__167", .rva = 0xebb0},
	{.name = "__imp_CloseHandle", .rva = 0xb0f0},
	{.name = "_string__168", .rva = 0xda10},
	{.name = "AelpWaitHandle", .rva = 0x11b48},
	{.name = "__imp_LocalFree", .rva = 0xb370},
	{.name = "_string__169", .rva = 0xc970},
	{.name = "_string__170", .rva = 0xb910},
	{.name = "_string__171", .rva = 0xe078},
	{.name = "__imp_GetFileAttributesW", .rva = 0xb0c8},
	{.name = "_string__172", .rva = 0xea08},
	{.name = "__sz_apphelp_dll", .rva = 0xee10},
	{.name = "_string__173", .rva = 0xbcb8},
	{.name = "_string__174", .rva = 0xbbd0},
	{.name = "__imp_RtlAllocateAndInitializeSid", .rva = 0xb2a8},
	{.name = "_string__175", .rva = 0xc920},
	{.name = "_string__176", .rva = 0xb788},
	{.name = "__imp_SetUnhandledExceptionFilter", .rva = 0xb0a8},
	{.name = "AelReleaseCacheExeMessageAttributes", .rva = 0x1608},
	{.name = "_string__177", .rva = 0xd120},
	{.name = "_string__178", .rva = 0xb470},
	{.name = "DelayLoadFailureHook", .rva = 0xa970},
	{.name = "__security_init_cookie", .rva = 0x5a9c},
	{.name = "_string__179", .rva = 0xcd80},
	{.name = "CRecentFilesLog__WriteNextRecord", .rva = 0x5860},
	{.name = "__imp_AlpcMaxAllowedMessageLength", .rva = 0xb258},
	{.name = "_string__180", .rva = 0xc260},
	{.name = "__imp_RtlDestroyHeap", .rva = 0xb2e0},
	{.name = "AelpDebugLevel", .rva = 0x110e8},
	{.name = "_string__181", .rva = 0xe828},
	{.name = "__imp_memmove", .rva = 0xb060},
	{.name = "_string__182", .rva = 0xb3e0},
	{.name = "_string__183", .rva = 0xe478},
	{.name = "_string__184", .rva = 0xc5a0},
	{.name = "__imp_NtOpenKey", .rva = 0xb2b8},
	{.name = "__imp__wcslwr_s", .rva = 0xb010},
	{.name = "__imp_load_ReportEventW", .rva = 0xa92c},
	{.name = "RtlVirtualUnwind", .rva = 0xa94c},
	{.name = "__imp_WriteFile", .rva = 0xb350},
	{.name = "_string__185", .rva = 0xd0d0},
	{.name = "_string__186", .rva = 0xbd98},
	{.name = "__imp_RtlLengthSid", .rva = 0xb2a0},
	{.name = "__imp_GetFileSize", .rva = 0xb3b0},
	{.name = "_string__187", .rva = 0xcd38},
	{.name = "__imp_NtSetInformationFile", .rva = 0xb278},
	{.name = "_string__188", .rva = 0xb818},
	{.name = "__imp_RtlDeleteCriticalSection", .rva = 0xb2f0},
	{.name = "_string__189", .rva = 0xb5a0},
	{.name = "__report_gsfailure", .rva = 0xa780},
	{.name = "__imp_CreateThreadpool", .rva = 0xb178},
	{.name = "AelQueryCacheExeMessage", .rva = 0x16c8},
	{.name = "_string__190", .rva = 0xd4e0},
	{.name = "_string__191", .rva = 0xc068},
	{.name = "_string__192", .rva = 0xc2b0},
	{.name = "_string__193", .rva = 0xb488},
	{.name = "_string__194", .rva = 0xd800},
	{.name = "_string__195", .rva = 0xcea8},
	{.name = "_string__196", .rva = 0xbed0},
	{.name = "_string__197", .rva = 0xb7d8},
	{.name = "_string__198", .rva = 0xcf20},
	{.name = "_string__199", .rva = 0xc4f0},
	{.name = "_string__200", .rva = 0xc718},
	{.name = "AelpStopService", .rva = 0x6b60},
	{.name = "__imp___3_YAXPEAX_Z", .rva = 0xb020},
	{.name = "AelpConnectionPortHandle", .rva = 0x11108},
	{.name = "_string__201", .rva = 0xc4b8},
	{.name = "_string__202", .rva = 0xdd80},
	{.name = "__imp_MapViewOfFile", .rva = 0xb338},
	{.name = "_string__203", .rva = 0xddd0},
	{.name = "_string__204", .rva = 0xe430},
	{.name = "__imp_load_ApphelpCheckRunAppEx", .rva = 0x66d0},
	{.name = "__imp_RtlSetDaclSecurityDescriptor", .rva = 0xb268},
	{.name = "_string__205", .rva = 0xd028},
	{.name = "AelpCopyMessageBundle", .rva = 0x1978},
	{.name = "_string__206", .rva = 0xe3c0},
	{.name = "CBinaryLog__Init", .rva = 0x4ba4},
	{.name = "WPP_SF_sD", .rva = 0x9bfc},
	{.name = "WPP_SF_sd", .rva = 0x9c5c},
	{.name = "__imp_NtSetEvent", .rva = 0xb300},
	{.name = "_string__207", .rva = 0xe870},
	{.name = "__imp_memcpy_s", .rva = 0xb028},
	{.name = "_string__208", .rva = 0xc9b8},
	{.name = "__imp_RtlDosPathNameToRelativeNtPathName_U", .rva = 0xb240},
	{.name = "_string__209", .rva = 0xbdd8},
	{.name = "CRecentFilesLog___CRecentFilesLog", .rva = 0x9be4},
	{.name = "_string__210", .rva = 0xe108},
	{.name = "_string__211", .rva = 0xc688},
	{.name = "_string__212", .rva = 0xc0e0},
	{.name = "_string__213", .rva = 0xd580},
	{.name = "__imp_NtAlpcCancelMessage", .rva = 0xb1f8},
	{.name = "memset", .rva = 0x14d4},
	{.name = "_string__214", .rva = 0xe348},
	{.name = "_string__215", .rva = 0xe540},
	{.name = "_string__216", .rva = 0xd440},

};
static uint64_t win7_sp1_x64_aelupsvc_count = 500;
