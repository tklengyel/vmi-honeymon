static char *win7_sp1_x64_i8042prt_guid[2] = {
	"4a5bc11d1e000",
	"0d034925f957425597f99d862e43da532"
	};
static struct symbol win7_sp1_x64_i8042prt[] = {
	{.name = "_string_", .rva = 0xf250},
	{.name = "I8xSetWmiDataBlock", .rva = 0x17988},
	{.name = "__imp_IoAllocateIrp", .rva = 0xc1e0},
	{.name = "__imp_ExAcquireFastMutexUnsafe", .rva = 0xc100},
	{.name = "_string__2", .rva = 0xf290},
	{.name = "WppClassicProviderCallback", .rva = 0x7358},
	{.name = "__imp_KeStallExecutionProcessor", .rva = 0xc2d0},
	{.name = "__imp_WmiCompleteRequest", .rva = 0xc2e8},
	{.name = "_string__3", .rva = 0xc510},
	{.name = "__imp_RtlFreeUnicodeString", .rva = 0xc1b0},
	{.name = "_string__4", .rva = 0xc4e0},
	{.name = "_string__5", .rva = 0x11f0},
	{.name = "__imp_KeSetTimer", .rva = 0xc060},
	{.name = "__imp_IoSetStartIoAttributes", .rva = 0xc258},
	{.name = "_string__6", .rva = 0xc568},
	{.name = "__security_cookie_complement", .rva = 0xd108},
	{.name = "WppTraceCallback", .rva = 0x14834},
	{.name = "I8xServiceDebugEnable", .rva = 0x12bb8},
	{.name = "__imp_ObfDereferenceObject", .rva = 0xc068},
	{.name = "_string__7", .rva = 0x18c30},
	{.name = "_string__8", .rva = 0xc4c8},
	{.name = "I8xCompletePendedRequest", .rva = 0x2870},
	{.name = "_string__9", .rva = 0x18bb0},
	{.name = "_string__10", .rva = 0xc5e0},
	{.name = "__imp_RtlInitUnicodeString", .rva = 0xc0c8},
	{.name = "_string__11", .rva = 0xf140},
	{.name = "_string__12", .rva = 0x11d0},
	{.name = "_string__13", .rva = 0xf450},
	{.name = "_string__14", .rva = 0xf010},
	{.name = "I8xKeyboardSynchWritePort", .rva = 0xbb64},
	{.name = "I8xGetControllerCommand", .rva = 0x4170},
	{.name = "_string__15", .rva = 0x1220},
	{.name = "__imp_IoCreateDevice", .rva = 0xc268},
	{.name = "I8xInitiateIo", .rva = 0x3830},
	{.name = "I8xUpdateSysButtonCapsGetPendedIrp", .rva = 0xbac0},
	{.name = "__imp_IoWriteErrorLogEntry", .rva = 0xc278},
	{.name = "__imp_IoAllocateErrorLogEntry", .rva = 0xc020},
	{.name = "__imp_KdChangeOption", .rva = 0xc178},
	{.name = "I8xPowerUpToD0Complete", .rva = 0x5b60},
	{.name = "WPP_RECORDER_SF_sdDD", .rva = 0x4bcc},
	{.name = "I8xKeyboardRemoveDevice", .rva = 0x14c18},
	{.name = "__imp_IofCompleteRequest", .rva = 0xc048},
	{.name = "_string__16", .rva = 0xf120},
	{.name = "WPP_RECORDER_SF_Dddd", .rva = 0xaa80},
	{.name = "WPP_RECORDER_SF_DDDD", .rva = 0x52fc},
	{.name = "WPP_RECORDER_SF_dddD", .rva = 0x6230},
	{.name = "_string__17", .rva = 0xf210},
	{.name = "_string__18", .rva = 0xf620},
	{.name = "I8xKeyboardRemoveDeviceInitialized", .rva = 0x7fc0},
	{.name = "I8xKeyboardGetSysButtonCaps", .rva = 0x1758c},
	{.name = "__imp_IoSetDeviceInterfaceState", .rva = 0xc198},
	{.name = "I8xManuallyRemoveDevice", .rva = 0x17328},
	{.name = "__imp_IoAttachDeviceToDeviceStack", .rva = 0xc248},
	{.name = "I8xMouseResetSynchRoutine", .rva = 0xaeb4},
	{.name = "_string__19", .rva = 0x1200},
	{.name = "_string__20", .rva = 0xf5d0},
	{.name = "_string__21", .rva = 0x18be0},
	{.name = "I8xFilterResourceRequirements", .rva = 0x13a44},
	{.name = "I8xInitializeHardwareAtBoot", .rva = 0x11c50},
	{.name = "__imp_PoStartNextPowerIrp", .rva = 0xc118},
	{.name = "_string__22", .rva = 0x18c50},
	{.name = "__imp_MmGetSystemRoutineAddress", .rva = 0xc0d8},
	{.name = "_string__23", .rva = 0x11c0},
	{.name = "I8xResetMouseFromDpc", .rva = 0xac7c},
	{.name = "__imp_KiBugCheckData", .rva = 0xc2a8},
	{.name = "__imp_KeInitializeTimerEx", .rva = 0xc210},
	{.name = "I8xDecrementTimer", .rva = 0x6af4},
	{.name = "WppAutoLogTrace", .rva = 0x1010},
	{.name = "_string__24", .rva = 0xf520},
	{.name = "MouWmiGuidList", .rva = 0xd150},
	{.name = "__imp_KeWaitForSingleObject", .rva = 0xc050},
	{.name = "_string__25", .rva = 0x18b80},
	{.name = "__imp_KeReleaseSpinLock", .rva = 0xc1a8},
	{.name = "_string__26", .rva = 0xf570},
	{.name = "I8xFindPortCallout", .rva = 0x17400},
	{.name = "__imp_IoRegisterPlugPlayNotification", .rva = 0xc1f0},
	{.name = "__imp_IoReleaseCancelSpinLock", .rva = 0xc088},
	{.name = "I8xPutBytePolled", .rva = 0x42dc},
	{.name = "memcpy", .rva = 0x14a0},
	{.name = "__imp_IoRegisterDeviceInterface", .rva = 0xc220},
	{.name = "I8xInternalDeviceControl", .rva = 0x1920},
	{.name = "__imp_KdDebuggerNotPresent", .rva = 0xc140},
	{.name = "_string__27", .rva = 0xf4b0},
	{.name = "I8xReadPortUchar", .rva = 0x2238},
	{.name = "__imp_KeInitializeDpc", .rva = 0xc1a0},
	{.name = "KbWmiGuidList", .rva = 0xd120},
	{.name = "__imp_IoWMIWriteEvent", .rva = 0xc0c0},
	{.name = "I8xQueueCurrentMouseInput", .rva = 0xa9d8},
	{.name = "__imp_ZwSetValueKey", .rva = 0xc150},
	{.name = "_string__28", .rva = 0xf600},
	{.name = "__imp_IoDeleteDevice", .rva = 0xc228},
	{.name = "pfnWppGetVersion", .rva = 0xd1c0},
	{.name = "__C_specific_handler", .rva = 0xbecc},
	{.name = "I8xMouseResetTimeoutProc", .rva = 0xadb8},
	{.name = "__imp_IofCallDriver", .rva = 0xc0a0},
	{.name = "_string__29", .rva = 0xc5a0},
	{.name = "__imp_IoAcquireRemoveLockEx", .rva = 0xc280},
	{.name = "_string__30", .rva = 0xf540},
	{.name = "_string__31", .rva = 0xf500},
	{.name = "GUID_HWPROFILE_CHANGE_COMPLETE", .rva = 0xc488},
	{.name = "memmove", .rva = 0x14a0},
	{.name = "_string__32", .rva = 0xf5a0},
	{.name = "_string__33", .rva = 0xf320},
	{.name = "__imp_IoFreeController", .rva = 0xc028},
	{.name = "_string__34", .rva = 0xf000},
	{.name = "I8xInitWmi", .rva = 0x139a4},
	{.name = "__GSHandlerCheckCommon", .rva = 0xbda0},
	{.name = "I8xGetBytePolledIterated", .rva = 0x157c4},
	{.name = "_string__35", .rva = 0xc630},
	{.name = "__imp_IoBuildDeviceIoControlRequest", .rva = 0xc270},
	{.name = "_string__36", .rva = 0xf1f0},
	{.name = "I8xStartIo", .rva = 0x26f8},
	{.name = "WPP_MAIN_CB", .rva = 0xd2a0},
	{.name = "KdDebuggerNotPresent", .rva = 0xc140},
	{.name = "I8xCompleteSysButtonEventWorker", .rva = 0x176c0},
	{.name = "I8xMouseQueryWmiDataBlock", .rva = 0x179b8},
	{.name = "I8xClose", .rva = 0x14390},
	{.name = "I8xInitializeKeyboard", .rva = 0x109a8},
	{.name = "__imp_IoQueueWorkItem", .rva = 0xc208},
	{.name = "__imp_ExReleaseFastMutexUnsafe", .rva = 0xc0b8},
	{.name = "I8xKeyboardConfiguration", .rva = 0x121b4},
	{.name = "I8xReinitializeHardware", .rva = 0x14450},
	{.name = "_string__37", .rva = 0xf170},
	{.name = "I8xInitializeHardware", .rva = 0x1046c},
	{.name = "I8042KeyboardIsrDpc", .rva = 0x7390},
	{.name = "__imp_ExAllocatePoolWithTag", .rva = 0xc290},
	{.name = "_string__38", .rva = 0x11a0},
	{.name = "I8xDpcVariableOperation", .rva = 0x6b30},
	{.name = "__imp__wcsupr", .rva = 0xc1e8},
	{.name = "pfnWppQueryTraceInformation", .rva = 0xd1a0},
	{.name = "I8xMouseInitializeHardware", .rva = 0x16b6c},
	{.name = "I8xTransmitControllerCommand", .rva = 0x3efc},
	{.name = "I8xKeyboardIsrWritePort", .rva = 0xbb7c},
	{.name = "_string__39", .rva = 0x18ca0},
	{.name = "_string__40", .rva = 0x1300},
	{.name = "WppAutoLogStart", .rva = 0x5744},
	{.name = "I8xWriteDataToMouseQueue", .rva = 0x84c8},
	{.name = "__GSHandlerCheck_SEH", .rva = 0xbe30},
	{.name = "__imp___C_specific_handler", .rva = 0xc2c0},
	{.name = "_string__41", .rva = 0x18c10},
	{.name = "I8xVerifyMousePnPID", .rva = 0xb13c},
	{.name = "I8xKeyboardServiceParameters", .rva = 0x13180},
	{.name = "I8xGetBytePolled", .rva = 0x45f4},
	{.name = "__imp_KeReleaseSpinLockFromDpcLevel", .rva = 0xc018},
	{.name = "_string__42", .rva = 0xf440},
	{.name = "__GSHandlerCheck", .rva = 0xbe0c},
	{.name = "__imp_IoStartPacket", .rva = 0xc000},
	{.name = "GetWppAutoLogRegistrySettings", .rva = 0x547c},
	{.name = "__imp_ExAllocatePoolWithQuotaTag", .rva = 0xc2b8},
	{.name = "__imp_IoFreeWorkItem", .rva = 0xc0d0},
	{.name = "__imp_IoAcquireCancelSpinLock", .rva = 0xc098},
	{.name = "_string__43", .rva = 0xf180},
	{.name = "I8xFlush", .rva = 0x6660},
	{.name = "pfnEtwRegisterClassicProvider", .rva = 0xd1b8},
	{.name = "zzz_AsmCodeRange_End", .rva = 0x3e10},
	{.name = "_string__44", .rva = 0xf480},
	{.name = "I8xUnload", .rva = 0x14ae0},
	{.name = "_string__45", .rva = 0xf2f0},
	{.name = "WPP_ThisDir_CTLGUID_I8042prtTraceGuid", .rva = 0xc478},
	{.name = "I8xKeyboardStartDevice", .rva = 0x117d8},
	{.name = "__imp_IoReleaseRemoveLockEx", .rva = 0xc010},
	{.name = "pfnEtwUnregister", .rva = 0xd1b0},
	{.name = "_string__46", .rva = 0xf660},
	{.name = "I8xPnP", .rva = 0xf680},
	{.name = "I8xConvertTypematicParameters", .rva = 0x31b8},
	{.name = "I8xKeyboardConnectInterrupt", .rva = 0x11d04},
	{.name = "_string__47", .rva = 0xf650},
	{.name = "I8xWriteRegisterUchar", .rva = 0x7058},
	{.name = "_string__48", .rva = 0xf3e0},
	{.name = "_string__49", .rva = 0xf160},
	{.name = "I8xFindWheelMouse", .rva = 0x1581c},
	{.name = "_string__50", .rva = 0x11b0},
	{.name = "WppAutoLogStop", .rva = 0xbb90},
	{.name = "__imp_IoInvalidateDeviceState", .rva = 0xc288},
	{.name = "_string__51", .rva = 0xf080},
	{.name = "WppAutoLogpBugCheckCallbackFilter", .rva = 0xbc20},
	{.name = "I8xMouseStartDevice", .rva = 0x16c40},
	{.name = "GsDriverEntry", .rva = 0x18070},
	{.name = "_string__52", .rva = 0xf150},
	{.name = "WPP_RECORDER_SF_sqD", .rva = 0x63ec},
	{.name = "__imp_IoAllocateController", .rva = 0xc070},
	{.name = "__imp_RtlAppendUnicodeToString", .rva = 0xc0e0},
	{.name = "__imp_IoQueryDeviceDescription", .rva = 0xc218},
	{.name = "__imp_KeSetTimerEx", .rva = 0xc1d0},
	{.name = "__imp_IoCreateController", .rva = 0xc0a8},
	{.name = "_string__53", .rva = 0xf2d0},
	{.name = "WPP_RECORDER_SF_qq", .rva = 0x2368},
	{.name = "I8xSysButtonCancelRoutine", .rva = 0xb9e4},
	{.name = "I8xInitializeDataQueue", .rva = 0x4d40},
	{.name = "I8xPutByteAsynchronous", .rva = 0x3b64},
	{.name = "I8xGetDataQueuePointer", .rva = 0x6c7c},
	{.name = "__imp_IoStartNextPacket", .rva = 0xc030},
	{.name = "I8xStartDevice", .rva = 0x116a4},
	{.name = "WPP_GLOBAL_Control", .rva = 0xd198},
	{.name = "_string__54", .rva = 0xf470},
	{.name = "I8xQueryWmiRegInfo", .rva = 0x11f30},
	{.name = "WPP_RECORDER_SF_qDDDssDs", .rva = 0x4904},
	{.name = "I8xSetWmiDataItem", .rva = 0x17988},
	{.name = "WPP_RECORDER_SF_", .rva = 0x1310},
	{.name = "WPP_RECORDER_SF_dddddddd", .rva = 0x865c},
	{.name = "I8xFinishResetRequest", .rva = 0xa634},
	{.name = "I8xProfileNotificationCallback", .rva = 0x170e8},
	{.name = "I8xControllerRoutine", .rva = 0x2470},
	{.name = "WPP_RECORDER_SF_S", .rva = 0x4e24},
	{.name = "WPP_RECORDER_SF_s", .rva = 0x17e0},
	{.name = "__imp_KdEnableDebugger", .rva = 0xc170},
	{.name = "__security_check_cookie", .rva = 0x3190},
	{.name = "WPP_RECORDER_SF_q", .rva = 0x89a0},
	{.name = "_string__55", .rva = 0xc678},
	{.name = "WPP_RECORDER_SF_D", .rva = 0x13c0},
	{.name = "WPP_RECORDER_SF_d", .rva = 0x13c0},
	{.name = "WPP_RECORDER_SF_ddddddddd", .rva = 0x87ec},
	{.name = "__imp_IoDetachDevice", .rva = 0xc238},
	{.name = "I8042MouseInterruptService", .rva = 0x8a70},
	{.name = "__imp_WmiSystemControl", .rva = 0xc2e0},
	{.name = "I8xMouseEnableDpc", .rva = 0xac04},
	{.name = "__imp_KdDebuggerEnabled", .rva = 0xc158},
	{.name = "_string__56", .rva = 0x1190},
	{.name = "I8xPnPComplete", .rva = 0x48e0},
	{.name = "_string__57", .rva = 0xf230},
	{.name = "I8xServiceCrashDump", .rva = 0x125f0},
	{.name = "I8xLogError", .rva = 0x6df0},
	{.name = "_string__58", .rva = 0x18c80},
	{.name = "I8042MouseIsrDpc", .rva = 0x805c},
	{.name = "I8xMouseEnableSynchRoutine", .rva = 0xab78},
	{.name = "I8xMouseIsrWritePort", .rva = 0xbb2c},
	{.name = "__imp_KeDelayExecutionThread", .rva = 0xc110},
	{.name = "__imp_KeAcquireSpinLockAtDpcLevel", .rva = 0xc080},
	{.name = "__imp_IoDeleteController", .rva = 0xc130},
	{.name = "WPP_RECORDER_SF_ssD", .rva = 0x5164},
	{.name = "_string__59", .rva = 0xf4e0},
	{.name = "__imp_IoInitializeRemoveLockEx", .rva = 0xc260},
	{.name = "I8xServiceParameters", .rva = 0x18520},
	{.name = "_string__60", .rva = 0xf490},
	{.name = "DbgPrint", .rva = 0xbd94},
	{.name = "WPP_RECORDER_SF_SS", .rva = 0x7070},
	{.name = "WppAutoLogpGetImageBase", .rva = 0x593c},
	{.name = "_string__61", .rva = 0xf410},
	{.name = "__imp_IoReleaseRemoveLockAndWaitEx", .rva = 0xc240},
	{.name = "_string__62", .rva = 0xf040},
	{.name = "I8xSendResetCommand", .rva = 0xa960},
	{.name = "__imp_DbgBreakPointWithStatus", .rva = 0xc148},
	{.name = "I8xPower", .rva = 0xff40},
	{.name = "_string__63", .rva = 0xf4a0},
	{.name = "I8xInitiateOutputWrapper", .rva = 0x3cd4},
	{.name = "__imp_ZwClose", .rva = 0xc160},
	{.name = "__imp_IoDisconnectInterrupt", .rva = 0xc1c0},
	{.name = "I8042KeyboardInterruptService", .rva = 0x2a04},
	{.name = "I8xMouseConnectInterruptAndEnable", .rva = 0x16818},
	{.name = "I8xKeyboardInitializeHardware", .rva = 0x11bac},
	{.name = "_string__64", .rva = 0xf200},
	{.name = "_string__65", .rva = 0xf380},
	{.name = "__imp_KeInitializeEvent", .rva = 0xc008},
	{.name = "I8xTransmitByteSequence", .rva = 0x156d0},
	{.name = "I8xMouseServiceParameters", .rva = 0x15c9c},
	{.name = "__imp_KeSynchronizeExecution", .rva = 0xc090},
	{.name = "WppAutoLogpBugCheckCallback", .rva = 0xbcf4},
	{.name = "MSKeyboard_PortInformation_GUID", .rva = 0xc4a8},
	{.name = "_string__66", .rva = 0x18b30},
	{.name = "I8xIsrResetDpc", .rva = 0xace8},
	{.name = "GUID_DEVICE_SYS_BUTTON", .rva = 0xc498},
	{.name = "I8xSystemControl", .rva = 0xfc7c},
	{.name = "I8042TimeOutDpc", .rva = 0x688c},
	{.name = "I8xWriteDataToKeyboardQueue", .rva = 0x77fc},
	{.name = "_string__67", .rva = 0xf0c0},
	{.name = "__imp_IoFreeIrp", .rva = 0xc1d8},
	{.name = "__imp_MmMapIoSpace", .rva = 0xc038},
	{.name = "I8xReadRegisterUchar", .rva = 0x704c},
	{.name = "I8042RetriesExceededDpc", .rva = 0x66c0},
	{.name = "I8xKeyboardSysButtonEventDpc", .rva = 0xb85c},
	{.name = "MSKeyboard_ExtendedID_GUID", .rva = 0xc4b8},
	{.name = "I8xAddDevice", .rva = 0x13f80},
	{.name = "__imp_IoConnectInterrupt", .rva = 0xc1b8},
	{.name = "I8xDeviceControl", .rva = 0x147c0},
	{.name = "__imp_IoWMIRegistrationControl", .rva = 0xc0b0},
	{.name = "I8xResetMouse", .rva = 0xa7a4},
	{.name = "I8xRemovePort", .rva = 0x13ec0},
	{.name = "I8xCheckPowerFlag", .rva = 0x5b10},
	{.name = "_string__68", .rva = 0x1240},
	{.name = "WmiCompleteRequest", .rva = 0x3468},
	{.name = "__imp_ZwQuerySystemInformation", .rva = 0xc2a0},
	{.name = "W2kTraceMessage", .rva = 0x7200},
	{.name = "HotPatchBuffer", .rva = 0xd000},
	{.name = "_string__69", .rva = 0xf130},
	{.name = "__imp_KeBugCheckEx", .rva = 0xc168},
	{.name = "I8xWritePortUchar", .rva = 0x2250},
	{.name = "I8xSetDataQueuePointer", .rva = 0x6e90},
	{.name = "_string__70", .rva = 0xf1e0},
	{.name = "KiBugCheckData", .rva = 0xc2a8},
	{.name = "WmiSystemControl", .rva = 0x345c},
	{.name = "I8xQueryNumberOfMouseButtons", .rva = 0x15520},
	{.name = "__imp_KeAcquireSpinLockRaiseToDpc", .rva = 0xc1c8},
	{.name = "I8042CompletionDpc", .rva = 0x35b0},
	{.name = "__imp_KeInsertQueueDpc", .rva = 0xc040},
	{.name = "__security_cookie", .rva = 0xd100},
	{.name = "I8xQueueCurrentKeyboardInput", .rva = 0x7ef0},
	{.name = "KdDebuggerEnabled", .rva = 0xc158},
	{.name = "WPP_RECORDER_SF_qDD", .rva = 0x2924},
	{.name = "WPP_RECORDER_SF_qdD", .rva = 0xb4b4},
	{.name = "__imp_KeCancelTimer", .rva = 0xc078},
	{.name = "WPP_RECORDER_SF_ddD", .rva = 0x508c},
	{.name = "WPP_RECORDER_SF_DDd", .rva = 0xb244},
	{.name = "WPP_RECORDER_SF_ddd", .rva = 0xb31c},
	{.name = "_string__71", .rva = 0xf060},
	{.name = "__imp_RtlCompareMemory", .rva = 0xc128},
	{.name = "WPP_RECORDER_SF_sd", .rva = 0x3480},
	{.name = "WPP_RECORDER_SF_sD", .rva = 0x32fc},
	{.name = "WPP_RECORDER_SF_SD", .rva = 0x7a14},
	{.name = "WPP_RECORDER_SF_Sd", .rva = 0x4fa0},
	{.name = "WPP_RECORDER_SF_qd", .rva = 0x6330},
	{.name = "WPP_RECORDER_SF_qD", .rva = 0xb3f8},
	{.name = "I8xSetPowerFlag", .rva = 0x5ab0},
	{.name = "WPP_RECORDER_SF_DD", .rva = 0x2260},
	{.name = "WPP_RECORDER_SF_dD", .rva = 0x2260},
	{.name = "WPP_RECORDER_SF_dd", .rva = 0x2260},
	{.name = "zzz_AsmCodeRange_Begin", .rva = 0x3d20},
	{.name = "_string__72", .rva = 0xf350},
	{.name = "I8xToggleInterrupts", .rva = 0x10364},
	{.name = "I8xCreate", .rva = 0xfcf8},
	{.name = "I8xMouseConfiguration", .rva = 0x15260},
	{.name = "__imp_KeInitializeTimer", .rva = 0xc0f8},
	{.name = "_string__73", .rva = 0xf460},
	{.name = "_string__74", .rva = 0x11e0},
	{.name = "AuxKlibQueryModuleInformation", .rva = 0x141a0},
	{.name = "__imp_RtlQueryRegistryValues", .rva = 0xc0e8},
	{.name = "IoSetStartIoAttributes", .rva = 0x5738},
	{.name = "__imp_DbgPrint", .rva = 0xc298},
	{.name = "__imp_MmUnmapIoSpace", .rva = 0xc0f0},
	{.name = "_string__75", .rva = 0xf1d0},
	{.name = "I8xKeyboardSynchReadPort", .rva = 0xbb54},
	{.name = "_string__76", .rva = 0xf670},
	{.name = "__security_init_cookie", .rva = 0x18010},
	{.name = "I8xPnPStartComplete", .rva = 0x53f4},
	{.name = "I8xKeyboardQueryWmiDataBlock", .rva = 0xfe2c},
	{.name = "__imp_KeQueryTimeIncrement", .rva = 0xc120},
	{.name = "__imp_IoAllocateWorkItem", .rva = 0xc1f8},
	{.name = "I8xMouseInitializeInterruptWorker", .rva = 0x171a0},
	{.name = "I8xSendIoctl", .rva = 0x47e8},
	{.name = "WPPTraceSuite", .rva = 0xd1c8},
	{.name = "__imp_KeSetEvent", .rva = 0xc230},
	{.name = "I8xSendIrpSynchronously", .rva = 0x115d8},
	{.name = "_string__77", .rva = 0xf270},
	{.name = "I8xResetMouseFailed", .rva = 0xa74c},
	{.name = "KdChangeOption", .rva = 0xbd88},
	{.name = "I8xMouseInitializePolledWorker", .rva = 0x171dc},
	{.name = "__imp_IoOpenDeviceRegistryKey", .rva = 0xc180},
	{.name = "_string__78", .rva = 0xf030},
	{.name = "I8xMouseEnableTransmission", .rva = 0xa4bc},
	{.name = "I8xUpdateSysButtonCaps", .rva = 0x17710},
	{.name = "__report_gsfailure", .rva = 0xbd54},
	{.name = "_string__79", .rva = 0xc538},
	{.name = "I8042ErrorLogDpc", .rva = 0x6544},
	{.name = "I8xSanityCheckResources", .rva = 0x11f60},
	{.name = "__imp_PoCallDriver", .rva = 0xc250},
	{.name = "__imp_IoUnregisterPlugPlayNotification", .rva = 0xc200},
	{.name = "I8xKeyboardGetSysButtonEvent", .rva = 0xb614},
	{.name = "I8xCompleteSysButtonIrp", .rva = 0xb594},
	{.name = "I8xInitializeMouse", .rva = 0x14ce0},
	{.name = "_string__80", .rva = 0xf3b0},
	{.name = "I8xProcessCrashDump", .rva = 0x7b80},
	{.name = "_string__81", .rva = 0x18cb0},
	{.name = "_string__82", .rva = 0xf020},
	{.name = "__imp_KeRemoveQueueDpc", .rva = 0xc190},
	{.name = "_string__83", .rva = 0xf2b0},
	{.name = "I8xMouseRemoveDevice", .rva = 0x1702c},
	{.name = "__imp_IoGetAttachedDeviceReference", .rva = 0xc058},
	{.name = "__imp_ExFreePoolWithTag", .rva = 0xc138},
	{.name = "I8xDrainOutputBuffer", .rva = 0x3e20},
	{.name = "_string__84", .rva = 0xf1a0},
	{.name = "_string__85", .rva = 0x1210},
	{.name = "__imp_PoSetPowerState", .rva = 0xc108},
	{.name = "DriverEntry", .rva = 0x18094},
	{.name = "I8xGetByteAsynchronous", .rva = 0x3990},
	{.name = "__imp_PsGetVersion", .rva = 0xc2b0},
	{.name = "pfnWppTraceMessage", .rva = 0xd1a8},
	{.name = "__imp_ZwOpenKey", .rva = 0xc188},
	{.name = "MouPointerPortGuid", .rva = 0xd140},
	{.name = "_string__86", .rva = 0x1230},
	{.name = "I8xStartDeviceCallback", .rva = 0x121a8},
	{.name = "memset", .rva = 0x3d30},
	{.name = "Globals", .rva = 0xd200},
	{.name = "_string__87", .rva = 0xf100},
	{.name = "_string__88", .rva = 0xc4f8},

};
static uint64_t win7_sp1_x64_i8042prt_count = 383;