static char *win7_sp1_x86_rdpwsx_guid[2] = {
	"4ce7b9b411000",
	"42aee42dbe8a48b68059ef7fb2f037852"
	};
static struct symbol win7_sp1_x86_rdpwsx[] = {
	{.name = "__imp__InterlockedIncrement_4", .rva = 0x114c},
	{.name = "_g_WsxRefCritSect", .rva = 0xe134},
	{.name = "_TSrvDoDisconnect_8", .rva = 0x5e9b},
	{.name = "_string_", .rva = 0x9cac},
	{.name = "__imp__FreeLibrary_4", .rva = 0x10d4},
	{.name = "___onexitend", .rva = 0xe120},
	{.name = "CBuffer__Resize", .rva = 0x8f5d},
	{.name = "__imp_load__ReleaseDC_8", .rva = 0x9ee3},
	{.name = "__imp__PathIsUNCW_4", .rva = 0xe048},
	{.name = "_AesUseXmm", .rva = 0xe5c4},
	{.name = "_string__2", .rva = 0x7b98},
	{.name = "_TSrvCreateGCCDataList_8", .rva = 0x5335},
	{.name = "_TSrvInitGlobalData_0", .rva = 0x1a5e},
	{.name = "_Square_12", .rva = 0xc7da},
	{.name = "_AesCtrRng_Reseed_20", .rva = 0xa6b0},
	{.name = "__imp__TerminateThread_8", .rva = 0x10ac},
	{.name = "_g_fGCCRegistered", .rva = 0xe0dc},
	{.name = "_GCCConferenceCreateResponse_36", .rva = 0x81a1},
	{.name = "_GetProcAddress_8", .rva = 0x205c},
	{.name = "_gccFreeUserData_4", .rva = 0x8555},
	{.name = "_WsxExchangeStackConfig_8", .rva = 0x6ff1},
	{.name = "___security_cookie", .rva = 0xe1a4},
	{.name = "_GCCCleanup_12", .rva = 0x8135},
	{.name = "___security_check_cookie_4", .rva = 0x2237},
	{.name = "__imp__NtOpenFile_24", .rva = 0x1050},
	{.name = "_TSrvConfDisconnectReq_8", .rva = 0x5470},
	{.name = "_string__3", .rva = 0x7df8},
	{.name = "_TSrvNotifyVC_8", .rva = 0x6168},
	{.name = "_MD5Update_12", .rva = 0xa8cd},
	{.name = "_AesInitialize_0", .rva = 0xab58},
	{.name = "_EncryptClientRandom_24", .rva = 0x8db7},
	{.name = "__imp__SHEvaluateSystemCommandTemplate_16", .rva = 0xe058},
	{.name = "_EstimateQuotient_16", .rva = 0xc879},
	{.name = "__imp_load__CertVerifySubjectCertificateContext_12", .rva = 0xd01f},
	{.name = "_g_AddinCount", .rva = 0xe0ec},
	{.name = "__SEH_epilog4", .rva = 0x24e7},
	{.name = "__imp__DelayLoadFailureHook_8", .rva = 0x10cc},
	{.name = "_string__4", .rva = 0x4880},
	{.name = "_string__5", .rva = 0x7bd8},
	{.name = "__imp__Sleep_4", .rva = 0x10e4},
	{.name = "__imp__TLSFreeTSCertificate_4", .rva = 0x105c},
	{.name = "__hmod__SHELL32_dll", .rva = 0xe1c0},
	{.name = "_AesCtr_safe_startup_4", .rva = 0x18f2},
	{.name = "_TSrvReferenceInfo_4", .rva = 0x5900},
	{.name = "__imp__HeapFree_12", .rva = 0x1138},
	{.name = "_GetClientRandom_16", .rva = 0x5d12},
	{.name = "__imp__ControlService_12", .rva = 0xe000},
	{.name = "__imp__GetDeviceCaps_8", .rva = 0xe06c},
	{.name = "__SEH_prolog4", .rva = 0x24a2},
	{.name = "__hmod__USERENV_dll", .rva = 0xe1b4},
	{.name = "__imp__SetThreadPriority_8", .rva = 0x10b4},
	{.name = "__imp__DeviceIoControl_32", .rva = 0x10c8},
	{.name = "__imp__PostQueuedCompletionStatus_16", .rva = 0x10f8},
	{.name = "VerifyDocAllowed", .rva = 0x96f1},
	{.name = "_string__6", .rva = 0x98a0},
	{.name = "_GCCConferenceTerminateRequest_16", .rva = 0x820e},
	{.name = "_TSrvShadowTargetConnect_16", .rva = 0x51a5},
	{.name = "__imp__TLSGetTSCertificate_16", .rva = 0x1060},
	{.name = "_MCSDereferenceDomain_4", .rva = 0x867f},
	{.name = "_string__7", .rva = 0x72d8},
	{.name = "_string__8", .rva = 0x7cd8},
	{.name = "_TranslateVerifyAppAllowedParametersIn_20", .rva = 0x6e3d},
	{.name = "__imp__RtlInitUnicodeString_8", .rva = 0x1048},
	{.name = "_TSrvDoConnectResponse_4", .rva = 0x54a1},
	{.name = "_AesCreateDecryptionRoundKeyAsm_8", .rva = 0x3817},
	{.name = "_IcaChannelClose_4", .rva = 0x916c},
	{.name = "__imp__GetQueuedCompletionStatus_20", .rva = 0x1100},
	{.name = "_LogonUIScreenSizeForConnection_12", .rva = 0x6c69},
	{.name = "_MCSPortData_8", .rva = 0x872f},
	{.name = "__imp__TLSCspShutdown_0", .rva = 0x1068},
	{.name = "__imp__PathSkipRootW_4", .rva = 0xe038},
	{.name = "CBuffer__Access", .rva = 0x8e8e},
	{.name = "_string__9", .rva = 0x4830},
	{.name = "_BenalohEstimateQuotient_12", .rva = 0x3f24},
	{.name = "_malloc", .rva = 0x7ec8},
	{.name = "_GetAudioVideoDriverCLSID_16", .rva = 0x7419},
	{.name = "_AesCpuFamilyLockedOut_0", .rva = 0xaa75},
	{.name = "_string__10", .rva = 0x7e28},
	{.name = "__imp_load__CryptAcquireContextA_20", .rva = 0x9e60},
	{.name = "__imp_load__SLGetWindowsInformationDWORD_8", .rva = 0xcd95},
	{.name = "__imp__HeapDestroy_4", .rva = 0x10f4},
	{.name = "_AesEncrypt_12", .rva = 0x24fb},
	{.name = "_AesCtr_safe_16", .rva = 0x9fe1},
	{.name = "_string__11", .rva = 0x6098},
	{.name = "_BSafeEncPublicEx_12", .rva = 0xa754},
	{.name = "__imp__TerminateProcess_8", .rva = 0x10b0},
	{.name = "__imp__HeapCreate_12", .rva = 0x10f0},
	{.name = "_HandleConnectProviderIndication_12", .rva = 0x85a8},
	{.name = "_gccMapMcsError_4", .rva = 0x2141},
	{.name = "_VerifyAppAllowed_40", .rva = 0x9acf},
	{.name = "_g_hTShareHeap", .rva = 0xe0fc},
	{.name = "_string__12", .rva = 0x47b8},
	{.name = "CBuffer__Presize", .rva = 0x8ed3},
	{.name = "_string__13", .rva = 0x7e50},
	{.name = "__imp__LoadLibraryExA_12", .rva = 0x10dc},
	{.name = "_TSrvBindStack_4", .rva = 0x5065},
	{.name = "_TSrvMainThread_4", .rva = 0x1194},
	{.name = "_TSRNG_Shutdown_0", .rva = 0x8b2a},
	{.name = "_wcsncmp", .rva = 0xce0a},
	{.name = "_BaseMult_16", .rva = 0xcb34},
	{.name = "_WsxBrokenConnection_12", .rva = 0x63c5},
	{.name = "__imp__ReadFile_20", .rva = 0x10fc},
	{.name = "__sz_USER32_dll", .rva = 0xd2a0},
	{.name = "_g_WsxRefCount", .rva = 0xe0d4},
	{.name = "_IcaChannelOpen_16", .rva = 0x9177},
	{.name = "_g_MainThreadExitEvent", .rva = 0xe0d0},
	{.name = "_SendConnectProviderResponse_20", .rva = 0x89f2},
	{.name = "__imp__StartServiceW_12", .rva = 0xe018},
	{.name = "_GCCConferenceInit_16", .rva = 0x8168},
	{.name = "_WsxWinStationInitialize_12", .rva = 0x14f2},
	{.name = "__hmod__SHLWAPI_dll", .rva = 0xe1b8},
	{.name = "__imp__RegEnumKeyExW_32", .rva = 0x1090},
	{.name = "_string__14", .rva = 0x5f58},
	{.name = "__sz_slc_dll", .rva = 0xd2c0},
	{.name = "_ValidateServerCert_4", .rva = 0x8ca0},
	{.name = "__imp__CreateThread_24", .rva = 0x10a4},
	{.name = "_string__15", .rva = 0x1e00},
	{.name = "__imp__NtCreateFile_44", .rva = 0x1044},
	{.name = "_string__16", .rva = 0x7c54},
	{.name = "__tailMerge_CRYPTSP_dll", .rva = 0x9e48},
	{.name = "StringCchPrintfW", .rva = 0x97b3},
	{.name = "__imp__QueryServiceStatus_8", .rva = 0xe004},
	{.name = "_g_bWsxRefCritSect", .rva = 0xe0d8},
	{.name = "__imp__CreateEventW_16", .rva = 0x111c},
	{.name = "__hmod__ole32_dll", .rva = 0xe1bc},
	{.name = "__imp__GetTokenInformation_20", .rva = 0x10c0},
	{.name = "__imp__DisableThreadLibraryCalls_4", .rva = 0x1130},
	{.name = "__imp__memcpy", .rva = 0x102c},
	{.name = "__imp__SetUnhandledExceptionFilter_4", .rva = 0x10ec},
	{.name = "_MD5Init_4", .rva = 0xa893},
	{.name = "__imp__RtlEqualSid_8", .rva = 0x104c},
	{.name = "__imp___amsg_exit", .rva = 0x1028},
	{.name = "__imp_load__CertFreeCertificateContext_4", .rva = 0xd018},
	{.name = "_g_bTSrvCritSect", .rva = 0xe0e0},
	{.name = "_WsxEscape_28", .rva = 0x6688},
	{.name = "_string__17", .rva = 0x75b8},
	{.name = "_WsxVerify_24", .rva = 0x6ef9},
	{.name = "_AesSboxMatrixMult", .rva = 0x2800},
	{.name = "__DELAY_IMPORT_DESCRIPTOR_ole32_dll", .rva = 0xd0d4},
	{.name = "_TSrvHandleCreateInd_8", .rva = 0x4f53},
	{.name = "__imp_load__OpenServiceW_12", .rva = 0x1b30},
	{.name = "__initterm_e", .rva = 0x170e},
	{.name = "_GatherRandomKeyFastUserMode_16", .rva = 0xa0f4},
	{.name = "__CRT_INIT_12", .rva = 0x1963},
	{.name = "__imp__HeapReAlloc_16", .rva = 0x1148},
	{.name = "_MCSDisconnectProviderRequest_12", .rva = 0x8a4f},
	{.name = "_string__18", .rva = 0x9d70},
	{.name = "_TSrvTerminating_4", .rva = 0x5a60},
	{.name = "__hmod__API_MS_WIN_Service_Management_L1_1_0_dll", .rva = 0xe1ac},
	{.name = "_TSrvDereferenceInfo_4", .rva = 0x59d6},
	{.name = "__imp__AssocQueryStringW_24", .rva = 0xe044},
	{.name = "_WsxInitializeClientData_44", .rva = 0x7046},
	{.name = "__imp__PathGetDriveNumberW_4", .rva = 0xe03c},
	{.name = "_g_TSrvCritSect", .rva = 0xe180},
	{.name = "__imp__CoTaskMemFree_4", .rva = 0xe050},
	{.name = "__imp__CreateIoCompletionPort_16", .rva = 0x1104},
	{.name = "_GetSpoolerHandle_4", .rva = 0x6022},
	{.name = "_Multiply_16", .rva = 0xc74e},
	{.name = "__hmod__CRYPT32_dll", .rva = 0xe1d0},
	{.name = "__sz_CRYPTSP_dll", .rva = 0xd230},
	{.name = "_StringCchCopyW_12", .rva = 0x1a7d},
	{.name = "__imp__memset", .rva = 0x1004},
	{.name = "_BSafeEncPublic_12", .rva = 0xa860},
	{.name = "_MD5Final_4", .rva = 0xa9e6},
	{.name = "_AesCtrRng_Generate_24", .rva = 0xa517},
	{.name = "_string__19", .rva = 0x72f0},
	{.name = "__imp__IcaChannelOpen_16", .rva = 0x107c},
	{.name = "__tailMerge_GDI32_dll", .rva = 0x9f09},
	{.name = "_gccDecodeUserData_12", .rva = 0x838f},
	{.name = "CBuffer___vector_deleting_destructor_", .rva = 0x9063},
	{.name = "__DELAY_IMPORT_DESCRIPTOR_SHLWAPI_dll", .rva = 0xd0b4},
	{.name = "_MCSReferenceDomain_4", .rva = 0x866e},
	{.name = "__imp__wcsncmp", .rva = 0x1014},
	{.name = "_string__20", .rva = 0x72c4},
	{.name = "__imp_load__PathSkipRootW_4", .rva = 0x9e9e},
	{.name = "_string__21", .rva = 0x72e0},
	{.name = "__imp__RtlDeleteCriticalSection_4", .rva = 0x1034},
	{.name = "CheckAllowListGroupPolicy", .rva = 0x92c8},
	{.name = "__imp_load__CertCreateCertificateContext_12", .rva = 0xd02d},
	{.name = "__DELAY_IMPORT_DESCRIPTOR_USERENV_dll", .rva = 0xd094},
	{.name = "_TSUtilInit_0", .rva = 0x16d9},
	{.name = "__imp__PathQuoteSpacesW_4", .rva = 0xe040},
	{.name = "_SlavePrng_8", .rva = 0xa2a9},
	{.name = "_AesDetectXmmDone", .rva = 0xe5c8},
	{.name = "_AesCtr_safe_lock_8", .rva = 0x9f97},
	{.name = "_HandleDisconnectProviderIndication_12", .rva = 0x862d},
	{.name = "_UnpackServerCert_12", .rva = 0x8bdc},
	{.name = "_AesExpandKey_12", .rva = 0xab5e},
	{.name = "_string__22", .rva = 0x9ac4},
	{.name = "_string__23", .rva = 0x6e28},
	{.name = "__imp___initterm", .rva = 0x1010},
	{.name = "_string__24", .rva = 0x6088},
	{.name = "_MCSDisconnectPort_8", .rva = 0x86c8},
	{.name = "_mcsCallback_16", .rva = 0x8358},
	{.name = "_g_hMainThread", .rva = 0xe0c8},
	{.name = "__imp_load__StartServiceW_12", .rva = 0x1b44},
	{.name = "_TLSCspShutdown_0", .rva = 0x9135},
	{.name = "_BenalohModExp_20", .rva = 0xc2f4},
	{.name = "_string__25", .rva = 0x4858},
	{.name = "__imp__GetProcAddress_8", .rva = 0x10d0},
	{.name = "_GetRemoteDShowFiltersCLSID_12", .rva = 0x6ba1},
	{.name = "_string__26", .rva = 0x6e30},
	{.name = "__imp_load__CryptGenRandom_12", .rva = 0x9e59},
	{.name = "_WsxConnect_16", .rva = 0x73d7},
	{.name = "_WsxIcaStackIoControl_36", .rva = 0x1648},
	{.name = "_string__27", .rva = 0x1e0c},
	{.name = "_AppendSecurityData_20", .rva = 0x5a76},
	{.name = "__imp__OpenThreadToken_16", .rva = 0x10a0},
	{.name = "___delayLoadHelper2_8", .rva = 0x1fb5},
	{.name = "_AesDetectXmm_0", .rva = 0xaafe},
	{.name = "__imp__ExpandEnvironmentStringsForUserW_16", .rva = 0xe030},
	{.name = "_TSrvAllocVCContext_8", .rva = 0x1566},
	{.name = "__hmod__API_MS_WIN_Service_winsvc_L1_1_0_dll", .rva = 0xe1a8},
	{.name = "_NewGenRandom_16", .rva = 0x9f7c},
	{.name = "_AesCtr_safe_shutdown_4", .rva = 0xa06a},
	{.name = "_string__28", .rva = 0x1dd0},
	{.name = "_g_pPublicKey", .rva = 0xe5cc},
	{.name = "_BenalohModSquare_12", .rva = 0xc1f7},
	{.name = "_Mod_20", .rva = 0xc8eb},
	{.name = "_TSrvGCCCallBack_4", .rva = 0x4ff5},
	{.name = "_WsxQueryGatewayPolicies_8", .rva = 0x6658},
	{.name = "_GetErrorRedirectorCLSID_12", .rva = 0x6bfd},
	{.name = "_TSrvReady_4", .rva = 0x1622},
	{.name = "_GCCRegisterNodeControllerApplication_32", .rva = 0x20bc},
	{.name = "_PROPERTY_TYPE_LOGON_REDIRECTOR_CLSID", .rva = 0x6b2c},
	{.name = "_DigitLen_8", .rva = 0xc68e},
	{.name = "__imp___except_handler4_common", .rva = 0x1000},
	{.name = "_string__29", .rva = 0x4890},
	{.name = "_TSrvSaveUserDataMember_16", .rva = 0x4e0c},
	{.name = "_GetTokenUser_8", .rva = 0x6316},
	{.name = "__imp__SetEvent_4", .rva = 0x1124},
	{.name = "__imp__GetDC_4", .rva = 0xe060},
	{.name = "_Reduce_16", .rva = 0xcc7c},
	{.name = "_WsxConvertPublishedApp_12", .rva = 0x757e},
	{.name = "StringCchCopyW", .rva = 0x1a7d},
	{.name = "CBuffer___scalar_deleting_destructor_", .rva = 0x9063},
	{.name = "__imp_load__ExpandEnvironmentStringsForUserW_16", .rva = 0x9e67},
	{.name = "_g_hKsecDriver", .rva = 0xe5bc},
	{.name = "__imp__OpenServiceW_12", .rva = 0xe010},
	{.name = "_SetValDWORD_12", .rva = 0xc652},
	{.name = "_WsxLogonNotify_20", .rva = 0x72fc},
	{.name = "_TSrvSaveUserData_8", .rva = 0x4ea0},
	{.name = "_TSrvGotAddinChangedEvent_0", .rva = 0x613c},
	{.name = "_string__30", .rva = 0x7ddc},
	{.name = "_AesCtrRng_Update_16", .rva = 0xa373},
	{.name = "_g_hReadyEvent", .rva = 0xe0cc},
	{.name = "_TSrvConfCreateResp_4", .rva = 0x539b},
	{.name = "_WsxGetConnectionProperty_16", .rva = 0x748d},
	{.name = "_gccIsInitialized_4", .rva = 0x1af0},
	{.name = "__imp__GetCurrentThread_0", .rva = 0x10b8},
	{.name = "_LoadLibraryExA_12", .rva = 0x1b5e},
	{.name = "$$VProc_ImageExportDirectory", .rva = 0x1234},
	{.name = "__imp__SLGetWindowsInformationDWORD_8", .rva = 0xe074},
	{.name = "__hmod__USER32_dll", .rva = 0xe1c4},
	{.name = "__FindPESection", .rva = 0x7f18},
	{.name = "_BenalohSetup_12", .rva = 0xc005},
	{.name = "_TSUtilCleanup_0", .rva = 0x8118},
	{.name = "_MCSDllCleanup_8", .rva = 0x8abe},
	{.name = "_AesCtrRng_Increment_4", .rva = 0xa2f6},
	{.name = "__imp__EnterCriticalSection_4", .rva = 0x1140},
	{.name = "__imp__CertCreateCertificateContext_12", .rva = 0xe08c},
	{.name = "_GetLastError_0", .rva = 0xcdbd},
	{.name = "_RdpSetExtendedStackInfo_4", .rva = 0x76a8},
	{.name = "___xi_a", .rva = 0x1a24},
	{.name = "_MCSChannelClose_4", .rva = 0x86a0},
	{.name = "___xc_a", .rva = 0x1a1c},
	{.name = "_g_bTSrvVCCritSec", .rva = 0xe0e8},
	{.name = "__tailMerge_slc_dll", .rva = 0xcd9c},
	{.name = "__imp_load__CryptReleaseContext_8", .rva = 0x9e41},
	{.name = "_BitLen_8", .rva = 0xc6bc},
	{.name = "___xc_z", .rva = 0x1a20},
	{.name = "_g_hDllInstance", .rva = 0xe0c4},
	{.name = "__imp__CryptAcquireContextA_20", .rva = 0xe020},
	{.name = "___xi_z", .rva = 0x1a2c},
	{.name = "CBuffer___vftable_", .rva = 0x482c},
	{.name = "__imp_load__SHEvaluateSystemCommandTemplate_16", .rva = 0x9ecb},
	{.name = "_TSrvReleaseVCAddins_4", .rva = 0x22de},
	{.name = "_string__31", .rva = 0x4718},
	{.name = "__imp_load__AssocQueryStringW_24", .rva = 0x9e7f},
	{.name = "__except_handler4", .rva = 0x7ffc},
	{.name = "_IcaStackIoControl_28", .rva = 0x16c3},
	{.name = "_WsxCanLogonProceed_28", .rva = 0x6cd5},
	{.name = "_GetActivatedTSFeatures_4", .rva = 0x5eab},
	{.name = "_TSrvConsoleConnect_16", .rva = 0x560d},
	{.name = "_TranslateVerifyAppAllowedParametersOut_32", .rva = 0x6e89},
	{.name = "operator_new", .rva = 0xcde9},
	{.name = "_UpdateUserConfigGatewayOverride_8", .rva = 0x651c},
	{.name = "__imp__CryptDecodeObject_28", .rva = 0xe088},
	{.name = "_TSRNG_Initialize_0", .rva = 0x18a5},
	{.name = "_string__33", .rva = 0x96c4},
	{.name = "__imp__GetCurrentProcess_0", .rva = 0x10a8},
	{.name = "_TSrvSignalIndication_8", .rva = 0x4f33},
	{.name = "_string__34", .rva = 0x72b4},
	{.name = "___pfnDefaultDliNotifyHook2", .rva = 0x1fac},
	{.name = "___security_cookie_complement", .rva = 0xe540},
	{.name = "__imp__CloseServiceHandle_4", .rva = 0xe014},
	{.name = "__hmod__slc_dll", .rva = 0xe1cc},
	{.name = "_TSrvTermVC_0", .rva = 0x5fc9},
	{.name = "_TSrvDestroyInfo_4", .rva = 0x5981},
	{.name = "__imp_load__CloseServiceHandle_4", .rva = 0x1f36},
	{.name = "__imp__free", .rva = 0x100c},
	{.name = "__IcaStackIoControl_28", .rva = 0x9161},
	{.name = "__tailMerge_USER32_dll", .rva = 0x9eea},
	{.name = "_g_fTSrvReady", .rva = 0xe0e4},
	{.name = "_BenalohMod_12", .rva = 0xc0fa},
	{.name = "_Add_16", .rva = 0x3e9c},
	{.name = "_TSrvInitWDConnectInfo_32", .rva = 0x5094},
	{.name = "___pfnDliNotifyHook2", .rva = 0x1fac},
	{.name = "_string__35", .rva = 0x488c},
	{.name = "_MCSCleanup_8", .rva = 0x8967},
	{.name = "__imp_load__CryptDecodeObject_28", .rva = 0xd000},
	{.name = "__imp__CryptGenRandom_12", .rva = 0xe028},
	{.name = "CBuffer__Clear", .rva = 0x8ead},
	{.name = "_TLSCspInit_0", .rva = 0x1b2a},
	{.name = "_gccSetCallback_4", .rva = 0x1b14},
	{.name = "__imp_load__PathQuoteSpacesW_4", .rva = 0x9ea5},
	{.name = "__tailMerge_API_MS_WIN_Service_winsvc_L1_1_0_dll", .rva = 0x9e29},
	{.name = "__sz_API_MS_WIN_Service_Management_L1_1_0_dll", .rva = 0xd200},
	{.name = "__sz_ole32_dll", .rva = 0xd280},
	{.name = "_MCSConnectProviderResponse_16", .rva = 0x8ace},
	{.name = "_GetConnectionGUID_12", .rva = 0x692f},
	{.name = "__imp__WaitForMultipleObjects_16", .rva = 0x1134},
	{.name = "_TSrvStackConnect_12", .rva = 0x55cb},
	{.name = "_g_fInitialized", .rva = 0xe100},
	{.name = "_BenalohScramblePowerTable_12", .rva = 0xc228},
	{.name = "__imp__NtClose_4", .rva = 0x1040},
	{.name = "operator_delete", .rva = 0xcdde},
	{.name = "__imp_load__PathIsUNCW_4", .rva = 0x9eac},
	{.name = "_TSrvValidateServerCertificate_28", .rva = 0x4b5b},
	{.name = "_VerifyCertChain_20", .rva = 0x908f},
	{.name = "_ShutdownRNG_4", .rva = 0x9f1f},
	{.name = "_PROPERTY_TYPE_LOGON_SCREEN_SIZE", .rva = 0x6b4c},
	{.name = "_string__36", .rva = 0x96d8},
	{.name = "_AesCtr_safe_unlock_8", .rva = 0x9fbc},
	{.name = "__DELAY_IMPORT_DESCRIPTOR_API_MS_WIN_Service_Management_L1_1_0_dll", .rva = 0xd054},
	{.name = "_string__37", .rva = 0x7bb8},
	{.name = "__imp__GetProcessHeap_0", .rva = 0x110c},
	{.name = "__imp_load__OpenSCManagerW_12", .rva = 0x1b3a},
	{.name = "__imp___wcsicmp", .rva = 0x1018},
	{.name = "__DELAY_IMPORT_DESCRIPTOR_USER32_dll", .rva = 0xd114},
	{.name = "_IoThreadFunc_4", .rva = 0x2476},
	{.name = "_memset", .rva = 0x7ebd},
	{.name = "_MCSInitialize_4", .rva = 0x23f7},
	{.name = "__sz_SHELL32_dll", .rva = 0xd290},
	{.name = "__imp__WaitForSingleObject_8", .rva = 0x1120},
	{.name = "_g_AesCtrSafeCtx", .rva = 0xe130},
	{.name = "__imp__LocalAlloc_8", .rva = 0x1110},
	{.name = "_TSrvSetAddinChangeNotification_0", .rva = 0x1ef6},
	{.name = "_string__38", .rva = 0x9cd8},
	{.name = "__sz_USERENV_dll", .rva = 0xd240},
	{.name = "__hmod__GDI32_dll", .rva = 0xe1c8},
	{.name = "_LsCsp_DecryptEnvelopedData_20", .rva = 0x9156},
	{.name = "__imp___vsnwprintf", .rva = 0x101c},
	{.name = "_string__39", .rva = 0x5f40},
	{.name = "ExpandAlias", .rva = 0x98c7},
	{.name = "_string__40", .rva = 0x23d8},
	{.name = "_WsxSetErrorInfo_12", .rva = 0x68f7},
	{.name = "_string__41", .rva = 0xa1b4},
	{.name = "_TSrvUnregisterNC_8", .rva = 0x5036},
	{.name = "__imp_load__GetDeviceCaps_8", .rva = 0x9f02},
	{.name = "_g_TSrvVCCritSect", .rva = 0xe14c},
	{.name = "__imp__ReleaseDC_8", .rva = 0xe064},
	{.name = "__imp__NtCreateEvent_20", .rva = 0x103c},
	{.name = "__imp__RegNotifyChangeKeyValue_20", .rva = 0x108c},
	{.name = "_IsSpoolerRunning_4", .rva = 0x60bb},
	{.name = "_SLGetWindowsInformationDWORD_8", .rva = 0xcdb2},
	{.name = "__imp__InterlockedDecrement_4", .rva = 0x1150},
	{.name = "__DELAY_IMPORT_DESCRIPTOR_API_MS_WIN_Service_winsvc_L1_1_0_dll", .rva = 0xd034},
	{.name = "__except_handler4_common", .rva = 0x810d},
	{.name = "__initterm", .rva = 0x16ce},
	{.name = "___onexitbegin", .rva = 0xe124},
	{.name = "_WsxSendAutoReconnectStatus_12", .rva = 0x6c9d},
	{.name = "_string__42", .rva = 0x6e20},
	{.name = "__imp__LocalFree_4", .rva = 0x1108},
	{.name = "__imp__CertDuplicateCertificateContext_4", .rva = 0xe07c},
	{.name = "_StringCchLengthW_12", .rva = 0x700a},
	{.name = "_string__43", .rva = 0x7c7c},
	{.name = "_SendClientRandom_24", .rva = 0x5df1},
	{.name = "_string__44", .rva = 0x7db0},
	{.name = "_g_bNeedToSetRegNotify", .rva = 0xe0c0},
	{.name = "_InitializeRNG_4", .rva = 0x18b2},
	{.name = "_TSrvAllocInfoNew_0", .rva = 0x591b},
	{.name = "__imp__CryptReleaseContext_8", .rva = 0xe024},
	{.name = "_string__45", .rva = 0x8900},
	{.name = "__imp__UnhandledExceptionFilter_4", .rva = 0x10e8},
	{.name = "_string__46", .rva = 0x7cb0},
	{.name = "__imp__RegQueryValueExW_24", .rva = 0x1088},
	{.name = "_TSCAPI_GenerateRandomBits_8", .rva = 0x8b54},
	{.name = "_g_GCCCallBack", .rva = 0xe104},
	{.name = "__DELAY_IMPORT_DESCRIPTOR_CRYPTSP_dll", .rva = 0xd074},
	{.name = "GetDrivePrefix", .rva = 0x9769},
	{.name = "ExpandDriveRedirection", .rva = 0x9811},
	{.name = "__tailMerge_CRYPT32_dll", .rva = 0xd007},
	{.name = "__imp__GetLastError_0", .rva = 0x1118},
	{.name = "_VERIFY_TYPE_LOGON_EXCEPTION", .rva = 0x6fdc},
	{.name = "_WsxOpenVirtualChannel_28", .rva = 0x6d49},
	{.name = "___report_gsfailure", .rva = 0x8021},
	{.name = "__DELAY_IMPORT_DESCRIPTOR_CRYPT32_dll", .rva = 0xd174},
	{.name = "_AesInvMatrixMult", .rva = 0xb000},
	{.name = "_AesCtr_safe_key_24", .rva = 0xa010},
	{.name = "_WsxWinStationRundown_8", .rva = 0x6446},
	{.name = "_string__47", .rva = 0x1830},
	{.name = "__aulldiv", .rva = 0x3f41},
	{.name = "ExpandAppPath", .rva = 0x99bc},
	{.name = "_g_WsxInitialized", .rva = 0xe19c},
	{.name = "__imp__InterlockedCompareExchange_12", .rva = 0x10e0},
	{.name = "__tailMerge_API_MS_WIN_Service_Management_L1_1_0_dll", .rva = 0x1f3d},
	{.name = "___native_startup_lock", .rva = 0xe12c},
	{.name = "__sz_GDI32_dll", .rva = 0xd2b0},
	{.name = "__imp__malloc", .rva = 0x1008},
	{.name = "__tailMerge_SHLWAPI_dll", .rva = 0x9e86},
	{.name = "_string__48", .rva = 0x9344},
	{.name = "_MCSCreateDomain_16", .rva = 0x87d7},
	{.name = "VerifyCommandLine", .rva = 0x9182},
	{.name = "___native_startup_state", .rva = 0xe11c},
	{.name = "__load_config_used", .rva = 0x4a00},
	{.name = "_TSrvHandleTerminateInd_8", .rva = 0x4f8f},
	{.name = "_InterlockedCompareExchange_12", .rva = 0x1b53},
	{.name = "_TSrvDoConnect_4", .rva = 0x54e7},
	{.name = "_FreeLibrary_4", .rva = 0xcdd3},
	{.name = "__imp_load__CoTaskMemFree_4", .rva = 0x9eb3},
	{.name = "_RandomFillBuffer_8", .rva = 0xa1d7},
	{.name = "__imp___3_YAXPAX_Z", .rva = 0x1024},
	{.name = "__tailMerge_ole32_dll", .rva = 0x9eba},
	{.name = "_string__49", .rva = 0x4768},
	{.name = "_memcpy", .rva = 0x1617},
	{.name = "_AesCtrRng_Instantiate_20", .rva = 0xa43c},
	{.name = "_Aes4SboxXmmAsm_8", .rva = 0x3800},
	{.name = "__imp_load__ControlService_12", .rva = 0x9e3a},
	{.name = "__hmod__CRYPTSP_dll", .rva = 0xe1b0},
	{.name = "__DELAY_IMPORT_DESCRIPTOR_SHELL32_dll", .rva = 0xd0f4},
	{.name = "_Compare_12", .rva = 0xc6fe},
	{.name = "_DestroyDomain_4", .rva = 0x857c},
	{.name = "_DelayLoadFailureHook_8", .rva = 0xcdc8},
	{.name = "_string__50", .rva = 0x7d90},
	{.name = "_free", .rva = 0x7ed3},
	{.name = "_AesCtrRng_XOR_12", .rva = 0xa33f},
	{.name = "_g_pAddin", .rva = 0xe0f0},
	{.name = "_BenalohGetPower_20", .rva = 0xc2b8},
	{.name = "__DELAY_IMPORT_DESCRIPTOR_GDI32_dll", .rva = 0xd134},
	{.name = "_AesSbox", .rva = 0x4900},
	{.name = "_MapPropertyGuidToRdpType_4", .rva = 0x6a25},
	{.name = "__imp__DeleteCriticalSection_4", .rva = 0x112c},
	{.name = "_g_abPublicKeyModulus", .rva = 0xe548},
	{.name = "_g_hVCAddinChangeEvent", .rva = 0xe0f4},
	{.name = "_g_bInitialized", .rva = 0xe118},
	{.name = "_TShareDLLEntry_12", .rva = 0x1735},
	{.name = "__imp__CloseHandle_4", .rva = 0x1128},
	{.name = "_MCSDLLInit_0", .rva = 0x1701},
	{.name = "_TLSVerifyProprietyChainedCertificate_16", .rva = 0xce15},
	{.name = "__imp_load__GetDC_4", .rva = 0x9efb},
	{.name = "_IsSpoolerStopped_0", .rva = 0x60f9},
	{.name = "__imp___IcaStackIoControl_28", .rva = 0x1074},
	{.name = "__sz_API_MS_WIN_Service_winsvc_L1_1_0_dll", .rva = 0xd1c0},
	{.name = "_TSrvIsReady_4", .rva = 0x115d},
	{.name = "_TSRVShutdown_8", .rva = 0x4a51},
	{.name = "_g_hAddinRegKey", .rva = 0xe198},
	{.name = "_g_GCCAppID", .rva = 0xe128},
	{.name = "_TSrvNotifyVC_0_8", .rva = 0x216f},
	{.name = "_VERIFY_TYPE_PUBLISHED_APPLICATION", .rva = 0x6fcc},
	{.name = "__imp__OpenSCManagerW_12", .rva = 0xe00c},
	{.name = "__imp__IcaChannelClose_4", .rva = 0x1070},
	{.name = "__imp__CertVerifySubjectCertificateContext_12", .rva = 0xe080},
	{.name = "__imp__LsCsp_DecryptEnvelopedData_20", .rva = 0x1064},
	{.name = "_TSRVStartup_0", .rva = 0x17bf},
	{.name = "__DELAY_IMPORT_DESCRIPTOR_slc_dll", .rva = 0xd154},
	{.name = "__imp__RegOpenKeyExW_20", .rva = 0x1084},
	{.name = "_gccDisconnectProviderIndication_8", .rva = 0x82e7},
	{.name = "_MCSDeleteDomain_12", .rva = 0x890d},
	{.name = "_WsxDestroy_0", .rva = 0x6388},
	{.name = "_gccEncodeUserData_16", .rva = 0x8447},
	{.name = "__imp__TLSCspInit_0", .rva = 0x1058},
	{.name = "__imp__RtlInitializeCriticalSection_4", .rva = 0x1038},
	{.name = "_TSrvExchangeStackConfig_8", .rva = 0x75d5},
	{.name = "__tailMerge_SHELL32_dll", .rva = 0x9ed2},
	{.name = "_TSrvInitWD_8", .rva = 0x5309},
	{.name = "_TSrvInitialize_0", .rva = 0x1205},
	{.name = "_SendSecurityData_8", .rva = 0x5c90},
	{.name = "_WsxVirtualChannelSecurity_12", .rva = 0x683a},
	{.name = "_PROPERTY_TYPE_REMOTE_MM_FILTERS", .rva = 0x6b3c},
	{.name = "__imp__HeapAlloc_12", .rva = 0x1144},
	{.name = "___dyn_tls_init_callback", .rva = 0xe4f4},
	{.name = "_TSrvCalculateUserDataSize_4", .rva = 0x4dc0},
	{.name = "_ConvertHRESULT2NT_4", .rva = 0x61af},
	{.name = "__imp_load__CertDuplicateCertificateContext_4", .rva = 0xd026},
	{.name = "__sz_CRYPT32_dll", .rva = 0xd2d0},
	{.name = "_string__52", .rva = 0x7d18},
	{.name = "__imp__LeaveCriticalSection_4", .rva = 0x113c},
	{.name = "_IsCallerUser_8", .rva = 0x6cdf},
	{.name = "__imp_load__PathGetDriveNumberW_4", .rva = 0x9e97},
	{.name = "_WsxDisconnect_12", .rva = 0x6815},
	{.name = "__wcsicmp", .rva = 0xcdff},
	{.name = "_TSrvAllocInfo_12", .rva = 0x59fd},
	{.name = "_GetLicenseType_12", .rva = 0x69a9},
	{.name = "_string__53", .rva = 0x72cc},
	{.name = "__amsg_exit", .rva = 0x7ff1},
	{.name = "__imp__RegQueryInfoKeyW_48", .rva = 0x1094},
	{.name = "_WsxInitialize_0", .rva = 0x2316},
	{.name = "__IsNonwritableInCurrentImage", .rva = 0x7f61},
	{.name = "__sz_SHLWAPI_dll", .rva = 0xd250},
	{.name = "_NewGenRandomEx_12", .rva = 0x9f58},
	{.name = "_StartUmRdpService_0", .rva = 0x2376},
	{.name = "__tailMerge_USERENV_dll", .rva = 0x9e6e},
	{.name = "_Sub_16", .rva = 0x3ee0},
	{.name = "__imp_load__QueryServiceStatus_8", .rva = 0x9e22},
	{.name = "_AesCtr_safe_select_12", .rva = 0xa0ae},
	{.name = "_TLSFreeTSCertificate_4", .rva = 0x9140},
	{.name = "__imp__RegCloseKey_4", .rva = 0x1098},
	{.name = "_TSrvRegisterNC_0", .rva = 0x2067},
	{.name = "_StopUmRdpService_0", .rva = 0x6270},
	{.name = "_TransformMD5_8", .rva = 0x3823},
	{.name = "__vsnwprintf", .rva = 0xcdf4},
	{.name = "_AccumulateSquares_12", .rva = 0xcd50},
	{.name = "__imp__GetVersionExW_4", .rva = 0x1114},
	{.name = "_Accumulate_16", .rva = 0xcba8},
	{.name = "_TSRNG_GenerateRandomBits_8", .rva = 0x8b37},
	{.name = "VerifyRealAppAllowed", .rva = 0x9383},
	{.name = "__imp__IcaStackIoControl_28", .rva = 0x1078},
	{.name = "__imp__InterlockedExchange_8", .rva = 0x10d8},
	{.name = "__imp__CertFreeCertificateContext_4", .rva = 0xe084},
	{.name = "_TLSGetTSCertificate_16", .rva = 0x914b},
	{.name = "__imp___2_YAPAXI_Z", .rva = 0x1020},
	{.name = "_g_fTSrvTerminating", .rva = 0xe5ac},
	{.name = "_TSrvInitVC_0", .rva = 0x2249},
	{.name = "__ValidateImageBase", .rva = 0x7ede},
	{.name = "_TSrvReadVCAddins_0", .rva = 0x1b69},
	{.name = "_string__54", .rva = 0x7d58},
	{.name = "_gccConnectProviderIndication_8", .rva = 0x8273},
	{.name = "_WsxAutomationVerification_16", .rva = 0x6668},
	{.name = "_GccMcsErrorTBL", .rva = 0xe4f8},
	{.name = "_CreateSessionKeys_12", .rva = 0x5cde},
	{.name = "_TSrvShadowClientConnect_8", .rva = 0x5216},
	{.name = "_g_DoubleInitialized", .rva = 0xe5b0},

};
static uint64_t win7_sp1_x86_rdpwsx_count = 533;
