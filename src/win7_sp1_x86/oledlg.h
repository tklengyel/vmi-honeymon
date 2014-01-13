static char *win7_sp1_x86_oledlg_guid[2] = {
	"4a5bdace1c000",
	"ade1f2eb35ed4c0cab4b8bf3307c93792"
	};
static struct symbol win7_sp1_x86_oledlg[] = {
	{.name = "EnableDisplayAsIcon", .rva = 0xdfdb},
	{.name = "__imp__DestroyWindow_4", .rva = 0x118c},
	{.name = "WrappedIOleUILinkContainer__GetLinkUpdateOptions", .rva = 0x11ae2},
	{.name = "UFillClassList", .rva = 0x9499},
	{.name = "_g_cfObjectDescriptor", .rva = 0x1505c},
	{.name = "__imp__GlobalUnlock_4", .rva = 0x1108},
	{.name = "__imp__FreeLibrary_4", .rva = 0x1100},
	{.name = "___onexitend", .rva = 0x15080},
	{.name = "__imp__IsWindowVisible_4", .rva = 0x1284},
	{.name = "_OleUIBusyW_4", .rva = 0x52ce},
	{.name = "ChangeAllLinks", .rva = 0xc153},
	{.name = "__imp__IsBadCodePtr_4", .rva = 0x10a4},
	{.name = "__imp__GetWindowInfo_8", .rva = 0x11ec},
	{.name = "__imp__RegisterClipboardFormatW_4", .rva = 0x1230},
	{.name = "_string_", .rva = 0x5834},
	{.name = "_g_cfLinkSource", .rva = 0x15040},
	{.name = "__imp__GetWindowLongW_8", .rva = 0x1260},
	{.name = "__imp__CLSIDFromString_8", .rva = 0x13ec},
	{.name = "_OleUIMetafilePictIconDraw_16", .rva = 0x780b},
	{.name = "WrappedIOleUILinkContainer__AddRef", .rva = 0x114e0},
	{.name = "OleDlgIsBadStringPtr", .rva = 0x1255f},
	{.name = "__imp__GetDlgItemTextW_16", .rva = 0x12cc},
	{.name = "_string__2", .rva = 0x1d24},
	{.name = "_string__3", .rva = 0x2710},
	{.name = "__imp__GetFocus_0", .rva = 0x11bc},
	{.name = "__imp__RegisterClassW_4", .rva = 0x11dc},
	{.name = "SetConvertResults", .rva = 0x5b2a},
	{.name = "___CppXcptFilter", .rva = 0x1259f},
	{.name = "_OleUIInsertObjectA_4", .rva = 0x1100d},
	{.name = "WrappedIOleUIObjInfo__SetViewInfo", .rva = 0x11b28},
	{.name = "_OleStdFree_4", .rva = 0xd880},
	{.name = "_OleStdQueryInterface_8", .rva = 0xd75e},
	{.name = "Atol", .rva = 0x10222},
	{.name = "___security_cookie", .rva = 0x150c4},
	{.name = "EnumMetafileIconDraw", .rva = 0x731b},
	{.name = "___security_check_cookie_4", .rva = 0x125c4},
	{.name = "_string__4", .rva = 0x1cf0},
	{.name = "OleDlgIsBadReadPtr", .rva = 0x1251f},
	{.name = "__imp__GetTextMetricsW_8", .rva = 0x133c},
	{.name = "SetInsertObjectResults", .rva = 0x9d79},
	{.name = "_string__5", .rva = 0x10a6c},
	{.name = "WrappedIOleUIObjInfo__Release", .rva = 0x120ac},
	{.name = "_OpenClassesRootKeyExW_12", .rva = 0x12c68},
	{.name = "__imp__SendDlgItemMessageW_20", .rva = 0x12d8},
	{.name = "__imp__GetWindowRect_8", .rva = 0x1178},
	{.name = "IconBoxWndProc", .rva = 0x8efd},
	{.name = "WrappedIOleUILinkContainer__GetLinkSource", .rva = 0x11bf4},
	{.name = "__imp__InvalidateRect_12", .rva = 0x1194},
	{.name = "__imp__QueryPerformanceCounter_4", .rva = 0x10b4},
	{.name = "StringCchCatW", .rva = 0x2ae8},
	{.name = "ResultImageUninitialize", .rva = 0xfcd6},
	{.name = "__SEH_epilog4", .rva = 0x168f},
	{.name = "__imp__Sleep_4", .rva = 0x10ac},
	{.name = "_OleStdMarkPasteEntryList_12", .rva = 0xde9d},
	{.name = "WrappedIOleUILinkContainer___WrappedIOleUILinkContainer", .rva = 0x11557},
	{.name = "_string__6", .rva = 0xb2b8},
	{.name = "_OleUIMetafilePictExtractIconSource_12", .rva = 0x7a08},
	{.name = "ULongLongToUInt", .rva = 0x2911},
	{.name = "_string__7", .rva = 0x42b4},
	{.name = "GetTaskInfo", .rva = 0x4f8b},
	{.name = "__imp__lstrlenW_4", .rva = 0x1158},
	{.name = "__imp__GetDeviceCaps_8", .rva = 0x1348},
	{.name = "__SEH_prolog4", .rva = 0x164a},
	{.name = "__imp__DrawMenuBar_4", .rva = 0x11f0},
	{.name = "_OleUIUnInitialize_4", .rva = 0xcc1c},
	{.name = "_string__8", .rva = 0x57c0},
	{.name = "FBusyInit", .rva = 0x504c},
	{.name = "_string__9", .rva = 0x354c},
	{.name = "BuildBusyDialogString", .rva = 0x4f01},
	{.name = "__imp__ExtTextOutW_32", .rva = 0x1320},
	{.name = "__imp__SearchPathW_24", .rva = 0x10ec},
	{.name = "_string__10", .rva = 0x1c44},
	{.name = "__imp__SetViewportExtEx_16", .rva = 0x1310},
	{.name = "RegHelpSuspendImpersonate", .rva = 0x12965},
	{.name = "_XformHeightInHimetricToPixels_8", .rva = 0xfc7b},
	{.name = "__imp__WideCharToMultiByte_32", .rva = 0x1128},
	{.name = "_string__11", .rva = 0x2804},
	{.name = "__imp__FillRect_12", .rva = 0x11d0},
	{.name = "WrappedIOleUILinkContainer__GetNextLink", .rva = 0x114fa},
	{.name = "uMsgCloseBusyDlg", .rva = 0x15030},
	{.name = "_g_pfnAllocate", .rva = 0x15090},
	{.name = "__imp__EndDialog_8", .rva = 0x12c8},
	{.name = "_string__12", .rva = 0x5748},
	{.name = "__imp__GetMetaFileBitsEx_12", .rva = 0x1364},
	{.name = "_string__13", .rva = 0x1478},
	{.name = "__imp__SaveDC_4", .rva = 0x131c},
	{.name = "__imp__GetStockObject_4", .rva = 0x1344},
	{.name = "__imp__OpenProcessToken_12", .rva = 0x1374},
	{.name = "CheckButton", .rva = 0x90a5},
	{.name = "_string__14", .rva = 0x56c4},
	{.name = "_OleUIInsertObjectW_4", .rva = 0xb2cf},
	{.name = "FHasPercentS", .rva = 0xe76a},
	{.name = "RegHelpResumeImpersonate", .rva = 0x12903},
	{.name = "WrappedIOleUILinkContainer__Release", .rva = 0x11e87},
	{.name = "__imp__CheckRadioButton_16", .rva = 0x12a8},
	{.name = "CStringCache__AddString", .rva = 0xfb22},
	{.name = "__imp__GetBkColor_4", .rva = 0x1350},
	{.name = "FValidateInsertFile", .rva = 0x919d},
	{.name = "WrappedIOleUIObjInfo__GetConvertInfo", .rva = 0x11ab6},
	{.name = "_OleStdGetSize_4", .rva = 0xd8cb},
	{.name = "__imp__CharLowerW_4", .rva = 0x124c},
	{.name = "_string__15", .rva = 0x9b5c},
	{.name = "__imp__GetVersion_0", .rva = 0x1060},
	{.name = "_g_cfFileNameW", .rva = 0x1503c},
	{.name = "_string__16", .rva = 0x1dc4},
	{.name = "__imp__TerminateProcess_8", .rva = 0x10c8},
	{.name = "__imp__PlayMetaFile_8", .rva = 0x1308},
	{.name = "DetermineDosPathNameType", .rva = 0x7ddb},
	{.name = "_string__17", .rva = 0x6b10},
	{.name = "__imp__IsDlgButtonChecked_8", .rva = 0x1198},
	{.name = "FGnrlPropsInit", .rva = 0x44f7},
	{.name = "_string__18", .rva = 0x2070},
	{.name = "_OleUIEditLinksA_4", .rva = 0x11ed8},
	{.name = "gInsObjStringCache", .rva = 0x1509c},
	{.name = "_string__19", .rva = 0x1550},
	{.name = "ShortSizeFormat", .rva = 0x42c3},
	{.name = "uMsgFileOKString", .rva = 0x15010},
	{.name = "_WPP_GLOBAL_Control", .rva = 0x150c8},
	{.name = "__imp__GetShortPathNameW_12", .rva = 0x10e0},
	{.name = "__imp__SendMessageW_16", .rva = 0x12c0},
	{.name = "IsValidClassID", .rva = 0x102f9},
	{.name = "FChangeIconInit", .rva = 0x8425},
	{.name = "UpdateLinksDlgProc", .rva = 0xd286},
	{.name = "WrappedIOleUIObjInfo__QueryInterface", .rva = 0x114c7},
	{.name = "_OleUIBusyA_4", .rva = 0x1185c},
	{.name = "_DllMain_12", .rva = 0x1b29},
	{.name = "_g_cfFileName", .rva = 0x15048},
	{.name = "__imp__MessageBoxW_16", .rva = 0x1294},
	{.name = "__imp__GetWindowTextLengthW_4", .rva = 0x129c},
	{.name = "__imp__GetSystemTimeAsFileTime_4", .rva = 0x10c4},
	{.name = "_string__20", .rva = 0x9af8},
	{.name = "__imp__CharPrevW_8", .rva = 0x1180},
	{.name = "__imp__IsBadWritePtr_8", .rva = 0x1168},
	{.name = "__imp__DeleteDC_4", .rva = 0x134c},
	{.name = "StandardExtractIcon", .rva = 0x575c},
	{.name = "_string__21", .rva = 0x1307c},
	{.name = "Browse", .rva = 0x103e1},
	{.name = "__imp__UpdateWindow_4", .rva = 0x1190},
	{.name = "InsertObjCacheUninitialize", .rva = 0xfbcd},
	{.name = "__imp__StringFromCLSID_8", .rva = 0x13e8},
	{.name = "WrappedIOleUIObjInfo__ConvertObject", .rva = 0x11ae2},
	{.name = "__imp__CreateSolidBrush_4", .rva = 0x1334},
	{.name = "WrappedIOleUILinkContainer__WrappedIOleUILinkContainer", .rva = 0x11eab},
	{.name = "FEditLinksInit", .rva = 0xbb6f},
	{.name = "__imp__GetSysColor_4", .rva = 0x11b4},
	{.name = "LpvAltStandardEntry", .rva = 0x58b3},
	{.name = "StandardGetFileTitle", .rva = 0x584a},
	{.name = "RefreshLinkLB", .rva = 0xbacc},
	{.name = "_string__22", .rva = 0x1d78},
	{.name = "GetAssociatedExecutable", .rva = 0x10dd7},
	{.name = "ChangeIconDialogProc", .rva = 0x88b6},
	{.name = "_atexit", .rva = 0x1958},
	{.name = "CStringCache__ResetEnumerator", .rva = 0xfa0b},
	{.name = "__imp__GlobalFree_4", .rva = 0x1104},
	{.name = "__imp__IsDialogMessageW_8", .rva = 0x122c},
	{.name = "WrappedIOleUILinkContainer___scalar_deleting_destructor_", .rva = 0x11de8},
	{.name = "_g_cfLinkSrcDescriptor", .rva = 0x15054},
	{.name = "_string__23", .rva = 0x6470},
	{.name = "StringCchPrintfW", .rva = 0x3e78},
	{.name = "__imp__GetWindowThreadProcessId_8", .rva = 0x12e4},
	{.name = "__imp__GetTickCount_0", .rva = 0x10b8},
	{.name = "_string__24", .rva = 0x10858},
	{.name = "__unlock", .rva = 0x1a17},
	{.name = "__imp__CreateEventW_16", .rva = 0x1080},
	{.name = "FInsertObjectInit", .rva = 0xa368},
	{.name = "Container_OpenSource", .rva = 0xc0a8},
	{.name = "__imp__GetTokenInformation_20", .rva = 0x137c},
	{.name = "__imp__DisableThreadLibraryCalls_4", .rva = 0x1094},
	{.name = "__imp__memcpy", .rva = 0x101c},
	{.name = "__imp__SetUnhandledExceptionFilter_4", .rva = 0x10d4},
	{.name = "__imp__ShowWindow_8", .rva = 0x12b8},
	{.name = "__imp__SetForegroundWindow_4", .rva = 0x127c},
	{.name = "__imp__GetForegroundWindow_0", .rva = 0x1234},
	{.name = "__imp___amsg_exit", .rva = 0x1040},
	{.name = "__alloca_probe_16", .rva = 0x21b2},
	{.name = "FLinkPropsInit", .rva = 0x36cc},
	{.name = "PromptUserDlgProc", .rva = 0xd14e},
	{.name = "WrappedIOleUILinkContainer__OpenLinkSource", .rva = 0x11d3a},
	{.name = "CStringCache__IsUptodate", .rva = 0xf993},
	{.name = "__imp__OleQueryLinkFromData_4", .rva = 0x13b4},
	{.name = "__imp__GetCurrentProcessId_0", .rva = 0x10c0},
	{.name = "__initterm_e", .rva = 0x17b4},
	{.name = "__CRT_INIT_12", .rva = 0x2097},
	{.name = "PopupMessage", .rva = 0x1031d},
	{.name = "__imp__SetThreadToken_8", .rva = 0x1384},
	{.name = "__imp__FileTimeToLocalFileTime_8", .rva = 0x1140},
	{.name = "FTogglePasteType", .rva = 0xea5e},
	{.name = "__imp__SetWindowLongW_12", .rva = 0x12d0},
	{.name = "__imp__UnrealizeObject_4", .rva = 0x132c},
	{.name = "__imp__SetDlgItemTextW_12", .rva = 0x12d4},
	{.name = "FormatIncluded", .rva = 0x5a77},
	{.name = "__imp__CompareStringW_24", .rva = 0x10f4},
	{.name = "StandardPropertySheet", .rva = 0x56f7},
	{.name = "__imp__SetFocus_4", .rva = 0x12a4},
	{.name = "UStandardInvocation", .rva = 0x5400},
	{.name = "__imp__CreateCompatibleDC_4", .rva = 0x1358},
	{.name = "__allmul", .rva = 0x21c8},
	{.name = "_string__25", .rva = 0x157c},
	{.name = "__imp__TlsSetValue_8", .rva = 0x106c},
	{.name = "_string__26", .rva = 0x1b04},
	{.name = "_OleUIEditLinksW_4", .rva = 0xcb5b},
	{.name = "__resetstkoflw_downlevel", .rva = 0x12ee7},
	{.name = "_string__27", .rva = 0x159c},
	{.name = "_string__28", .rva = 0x272c},
	{.name = "LpvStandardEntry", .rva = 0x58b3},
	{.name = "FFillPasteLinkList", .rva = 0xe561},
	{.name = "__imp__DeleteMenu_12", .rva = 0x1208},
	{.name = "_OpenClassesRootKeyW_8", .rva = 0x12e9b},
	{.name = "__imp__GetDateFormatW_24", .rva = 0x1148},
	{.name = "__imp__CoTaskMemFree_4", .rva = 0x13ac},
	{.name = "StandardGetOpenFileName", .rva = 0x57dd},
	{.name = "__imp__GetModuleHandleW_4", .rva = 0x10dc},
	{.name = "FChangeSourceInit", .rva = 0x29d1},
	{.name = "FAddPasteListItem", .rva = 0xe341},
	{.name = "UpdateClassType", .rva = 0x90f7},
	{.name = "__imp__SetMapMode_8", .rva = 0x1318},
	{.name = "_string__29", .rva = 0x153c},
	{.name = "SwapWindows", .rva = 0x59f8},
	{.name = "__imp__FindFirstFileW_8", .rva = 0x10e4},
	{.name = "WrappedIOleUILinkInfo__SetLinkSource", .rva = 0x11b86},
	{.name = "DoesFileExist", .rva = 0x108ce},
	{.name = "FindChar", .rva = 0x101c8},
	{.name = "__imp__CoGetMalloc_8", .rva = 0x13bc},
	{.name = "__imp__memset", .rva = 0x1010},
	{.name = "_string__30", .rva = 0x9aa4},
	{.name = "_GetTaskData_0", .rva = 0xcbff},
	{.name = "__imp__OleCreateFromFile_32", .rva = 0x13c4},
	{.name = "__SEH_prolog4_GS", .rva = 0x21fc},
	{.name = "__imp__EndPaint_8", .rva = 0x11c4},
	{.name = "_OleUIChangeSourceW_4", .rva = 0x2e2a},
	{.name = "__imp__GetClientRect_8", .rva = 0x1188},
	{.name = "_OleStdCopyString_4", .rva = 0xd93e},
	{.name = "__imp__SetBkMode_8", .rva = 0x1330},
	{.name = "UpdateResultIcon", .rva = 0x8201},
	{.name = "__imp__SetBrushOrgEx_16", .rva = 0x1328},
	{.name = "__imp__DestroyIcon_4", .rva = 0x1298},
	{.name = "__imp__SetTextColor_8", .rva = 0x1338},
	{.name = "__SEH_epilog4_GS", .rva = 0x2244},
	{.name = "__imp__CreateIcon_28", .rva = 0x119c},
	{.name = "Container_AutomaticManual", .rva = 0xbd6d},
	{.name = "__imp__IsBadStringPtrW_8", .rva = 0x10a0},
	{.name = "_OleStdRelease_4", .rva = 0xd978},
	{.name = "__imp__GetLayout_4", .rva = 0x135c},
	{.name = "__imp___initterm", .rva = 0x103c},
	{.name = "_string__31", .rva = 0x2748},
	{.name = "_string__32", .rva = 0x6198},
	{.name = "__imp__CreateBitmap_20", .rva = 0x12fc},
	{.name = "__imp__SetWindowWord_12", .rva = 0x11d4},
	{.name = "_string__33", .rva = 0x1454},
	{.name = "_string__34", .rva = 0x1ccc},
	{.name = "WrappedIOleUILinkInfo__Release", .rva = 0x120d0},
	{.name = "OleUIPromptUserInternal", .rva = 0xd22f},
	{.name = "__imp__GetProcAddress_8", .rva = 0x10fc},
	{.name = "__imp__SetTimer_16", .rva = 0x1210},
	{.name = "g_dwOldListType", .rva = 0x1543c},
	{.name = "__imp__SetBkColor_8", .rva = 0x1324},
	{.name = "FormatString1", .rva = 0x10b11},
	{.name = "__imp__OpenThreadToken_16", .rva = 0x1380},
	{.name = "FToggleObjectSource", .rva = 0x9fa9},
	{.name = "IconBoxUninitialize", .rva = 0x8e9f},
	{.name = "UStandardValidation", .rva = 0x5309},
	{.name = "_string__35", .rva = 0x128c8},
	{.name = "EnableDisableScaleControls", .rva = 0x331d},
	{.name = "__imp__ScreenToClient_8", .rva = 0x1214},
	{.name = "WrappedIOleUILinkInfo__CancelLink", .rva = 0x1153a},
	{.name = "__imp__LoadStringW_16", .rva = 0x12bc},
	{.name = "WrappedIOleUIObjInfo__GetObjectInfo", .rva = 0x11919},
	{.name = "__imp__ResetEvent_4", .rva = 0x1078},
	{.name = "__imp__GetFileType_4", .rva = 0x1088},
	{.name = "UFillIconList", .rva = 0x7a9f},
	{.name = "__imp__GetDialogBaseUnits_0", .rva = 0x1184},
	{.name = "CStringCache__NewCall", .rva = 0xfaf3},
	{.name = "_string__36", .rva = 0x27c8},
	{.name = "ShortSizeFormat64", .rva = 0x4135},
	{.name = "_VerifyStackAvailable_4", .rva = 0x13117},
	{.name = "__imp__OleQueryCreateFromData_4", .rva = 0x13b8},
	{.name = "_string__37", .rva = 0x27e4},
	{.name = "___native_dllmain_reason", .rva = 0x15004},
	{.name = "WrappedIOleUILinkContainer__UpdateLink", .rva = 0x11517},
	{.name = "LpvStandardInit", .rva = 0x546b},
	{.name = "__imp__CreateICW_16", .rva = 0x1368},
	{.name = "__lock", .rva = 0x16f4},
	{.name = "EnumMetafileExtractIconSource", .rva = 0x7741},
	{.name = "__imp___except_handler4_common", .rva = 0x1044},
	{.name = "__imp__GetFileAttributesW_4", .rva = 0x1058},
	{.name = "_string__38", .rva = 0x270c},
	{.name = "__imp__RegEnumKeyW_16", .rva = 0x1390},
	{.name = "__imp__IsWindow_4", .rva = 0x126c},
	{.name = "__imp___unlock", .rva = 0x1048},
	{.name = "_OleUIMetafilePictIconFree_4", .rva = 0x72eb},
	{.name = "ConvertDialogProc", .rva = 0x6b27},
	{.name = "__imp__GetDC_4", .rva = 0x11a8},
	{.name = "StringCchCopyW", .rva = 0x2a5f},
	{.name = "_string__39", .rva = 0x13048},
	{.name = "WrappedIOleUIObjInfo___scalar_deleting_destructor_", .rva = 0x11e0e},
	{.name = "ToggleDisplayAsIcon", .rva = 0xea02},
	{.name = "__allshr", .rva = 0x2191},
	{.name = "__imp__OleGetIconOfFile_8", .rva = 0x13cc},
	{.name = "CStringCache__ExpandOffsetTable", .rva = 0x1e98},
	{.name = "_string__40", .rva = 0x9b2c},
	{.name = "uMsgBrowseOFN", .rva = 0x1502c},
	{.name = "__imp__DispatchMessageW_4", .rva = 0x1224},
	{.name = "_OleUIMetafilePictExtractIcon_4", .rva = 0x7999},
	{.name = "GetSelectedItems", .rva = 0xb4fb},
	{.name = "_string__41", .rva = 0x5738},
	{.name = "CStringCache__ExpandStringTable", .rva = 0x1611},
	{.name = "InsertObjCacheInitialize", .rva = 0x1de7},
	{.name = "__imp__GetClassFile_8", .rva = 0x13d4},
	{.name = "IsLongComponent", .rva = 0x7ceb},
	{.name = "_OleStdGetObjectDescriptorData_48", .rva = 0xd9cd},
	{.name = "__imp__OleCreate_28", .rva = 0x13c0},
	{.name = "__imp__RtlAllocateHeap_12", .rva = 0x13fc},
	{.name = "__imp__GetCurrentThread_0", .rva = 0x1164},
	{.name = "_g_cfEmbedSource", .rva = 0x15050},
	{.name = "_OleUIChangeSourceA_4", .rva = 0x1224a},
	{.name = "__imp__GetSystemInfo_4", .rva = 0x10d8},
	{.name = "_IID_IOleLink", .rva = 0xd9b8},
	{.name = "InternalObjectProperties", .rva = 0x3ed7},
	{.name = "StandardCleanup", .rva = 0x55bd},
	{.name = "$$VProc_ImageExportDirectory", .rva = 0x13198},
	{.name = "ResultImageWndProc", .rva = 0xff0d},
	{.name = "___security_init_cookie", .rva = 0x16a8},
	{.name = "__FindPESection", .rva = 0x12671},
	{.name = "InsertObjectDialogProc", .rva = 0xa633},
	{.name = "_g_hOleStdInst", .rva = 0x1504c},
	{.name = "__imp__EnumMetaFile_16", .rva = 0x130c},
	{.name = "___xi_a", .rva = 0x215c},
	{.name = "_OleStdInitialize_8", .rva = 0x149b},
	{.name = "___xc_a", .rva = 0x2150},
	{.name = "__imp__LoadBitmapW_8", .rva = 0x1240},
	{.name = "WrappedIOleUILinkContainer__QueryInterface", .rva = 0x114c7},
	{.name = "___xc_z", .rva = 0x2158},
	{.name = "___xi_z", .rva = 0x2164},
	{.name = "FPasteSpecialReInit", .rva = 0xec8d},
	{.name = "_string__42", .rva = 0x1418},
	{.name = "LoadLinkLB", .rva = 0xba16},
	{.name = "__imp__LoadResource_8", .rva = 0x1118},
	{.name = "__except_handler4", .rva = 0x125ec},
	{.name = "WrappedIOleUIObjInfo___WrappedIOleUIObjInfo", .rva = 0x11b51},
	{.name = "WrappedIOleUILinkInfo__UpdateLink", .rva = 0x11517},
	{.name = "DiffPrefix", .rva = 0x10b63},
	{.name = "__imp__memmove", .rva = 0x100c},
	{.name = "_string__43", .rva = 0x2718},
	{.name = "uMsgEndDialog", .rva = 0x15028},
	{.name = "_OleUIConvertA_4", .rva = 0x11663},
	{.name = "operator_new", .rva = 0x12621},
	{.name = "__imp__VirtualQuery_12", .rva = 0x1154},
	{.name = "_string__44", .rva = 0x9b80},
	{.name = "FormatStrings", .rva = 0x10a79},
	{.name = "__XcptFilter", .rva = 0x1262c},
	{.name = "__imp__GetCurrentProcess_0", .rva = 0x10cc},
	{.name = "UpdateLinkLBItem", .rva = 0xb989},
	{.name = "___security_cookie_complement", .rva = 0x15000},
	{.name = "_OleUIPasteSpecialW_4", .rva = 0xf89d},
	{.name = "__imp___lock", .rva = 0x1004},
	{.name = "__imp__SetWindowPos_28", .rva = 0x1250},
	{.name = "ReplaceCharWithNull", .rva = 0x10157},
	{.name = "CStringCache__NextString", .rva = 0xf9ed},
	{.name = "_InternalVerifyStackAvailable_4", .rva = 0x130e9},
	{.name = "__imp__free", .rva = 0x1020},
	{.name = "_SafeAllocaFreeToHeap_4", .rva = 0x1309f},
	{.name = "PointerToNthField", .rva = 0x10daa},
	{.name = "__imp__GetWindowWord_8", .rva = 0x11c8},
	{.name = "__imp__RegLoadMUIStringW_28", .rva = 0x1394},
	{.name = "_string__45", .rva = 0x27b8},
	{.name = "_OleStdLoadString_8", .rva = 0xd90a},
	{.name = "_string__46", .rva = 0x9b3c},
	{.name = "__imp__CLSIDFromProgID_8", .rva = 0x13d0},
	{.name = "__imp__DestroyMenu_4", .rva = 0x11fc},
	{.name = "_OleStdCompareTargetDevice_8", .rva = 0xfbe6},
	{.name = "__imp__GetClipboardFormatNameW_12", .rva = 0x117c},
	{.name = "__imp__LoadLibraryW_4", .rva = 0x10f8},
	{.name = "WrappedIOleUILinkInfo__SetLinkUpdateOptions", .rva = 0x11b66},
	{.name = "uMsgAddControl", .rva = 0x15014},
	{.name = "__imp__RegQueryValueW_16", .rva = 0x138c},
	{.name = "FreeListData", .rva = 0xe231},
	{.name = "WrappedIOleUILinkContainer___vftable_", .rva = 0x2820},
	{.name = "__imp__ShowCursor_4", .rva = 0x1244},
	{.name = "_string__47", .rva = 0x277c},
	{.name = "TransparentBlt", .rva = 0xfd53},
	{.name = "__imp__VirtualAlloc_16", .rva = 0x1134},
	{.name = "__imp__CoTaskMemRealloc_8", .rva = 0x13b0},
	{.name = "FPasteSpecialInit", .rva = 0xf2b2},
	{.name = "_string__48", .rva = 0x9ac0},
	{.name = "gfEnableTracing", .rva = 0x1544c},
	{.name = "WrappedIOleUILinkInfo___scalar_deleting_destructor_", .rva = 0x11e61},
	{.name = "__imp__OleMetafilePictFromIconAndLabel_16", .rva = 0x13d8},
	{.name = "_g_hOleStdResInst", .rva = 0x15058},
	{.name = "_string__49", .rva = 0x128b8},
	{.name = "__imp__TranslateMessage_4", .rva = 0x1228},
	{.name = "_WPP_SF_SdD_28", .rva = 0x12844},
	{.name = "__alloca_probe", .rva = 0x2253},
	{.name = "_string__50", .rva = 0x9b4c},
	{.name = "operator_delete", .rva = 0x12616},
	{.name = "_RegGetOtherView_4", .rva = 0x12c23},
	{.name = "_g_pfnFree", .rva = 0x15094},
	{.name = "_OleUIUpdateLinksA_16", .rva = 0x11ffb},
	{.name = "FIconBoxInitialize", .rva = 0x1a22},
	{.name = "ErrorWithFile", .rva = 0x1055d},
	{.name = "__imp__RemovePropW_8", .rva = 0x1258},
	{.name = "BusyDialogProc", .rva = 0x5163},
	{.name = "__imp__GetWindow_8", .rva = 0x1280},
	{.name = "__imp__CompareFileTime_8", .rva = 0x114c},
	{.name = "WrappedIOleUILinkContainer__CancelLink", .rva = 0x1153a},
	{.name = "WrappedIOleUILinkInfo___WrappedIOleUILinkInfo", .rva = 0x11d77},
	{.name = "_string__51", .rva = 0x12e74},
	{.name = "GnrlPropsDialogProc", .rva = 0x45aa},
	{.name = "__imp__RestoreDC_8", .rva = 0x1304},
	{.name = "__imp___wcsicmp", .rva = 0x104c},
	{.name = "__imp__CheckDlgButton_12", .rva = 0x11e4},
	{.name = "_OleUIAddVerbMenuW_36", .rva = 0xcd01},
	{.name = "_OleUIChangeIconW_4", .rva = 0x8e12},
	{.name = "_memset", .rva = 0x125d6},
	{.name = "__imp__DrawFocusRect_8", .rva = 0x11ac},
	{.name = "_string__52", .rva = 0x15e8},
	{.name = "ConvertCleanup", .rva = 0x59a3},
	{.name = "_OleUIChangeIconA_4", .rva = 0x1156c},
	{.name = "__imp__CreatePopupMenu_0", .rva = 0x1204},
	{.name = "__imp__SetClipboardViewer_4", .rva = 0x1238},
	{.name = "_string__53", .rva = 0x15b8},
	{.name = "WrappedIOleUIObjInfo__WrappedIOleUIObjInfo", .rva = 0x11e34},
	{.name = "__onexit", .rva = 0x1974},
	{.name = "__chkstk", .rva = 0x2253},
	{.name = "__imp__GetLastActivePopup_4", .rva = 0x1278},
	{.name = "__imp__iswalpha", .rva = 0x102c},
	{.name = "__imp__WaitForSingleObject_8", .rva = 0x107c},
	{.name = "__imp__RegOpenUserClassesRoot_16", .rva = 0x1378},
	{.name = "__imp__ReleaseStgMedium_4", .rva = 0x13dc},
	{.name = "StandardShowDlgItem", .rva = 0x5613},
	{.name = "__imp__TlsGetValue_4", .rva = 0x105c},
	{.name = "__imp__DialogBoxIndirectParamW_20", .rva = 0x12e0},
	{.name = "__imp__LocalAlloc_8", .rva = 0x1070},
	{.name = "__imp__FindNextFileW_8", .rva = 0x1090},
	{.name = "___dllonexit", .rva = 0x16e9},
	{.name = "__imp__GetPropW_8", .rva = 0x125c},
	{.name = "__imp__GetObjectW_12", .rva = 0x12f4},
	{.name = "__imp__CreateWindowExW_48", .rva = 0x12b0},
	{.name = "uMsgChangeSource", .rva = 0x1501c},
	{.name = "StandardInitCommonControls", .rva = 0x5677},
	{.name = "FConvertInit", .rva = 0x64a7},
	{.name = "ChopText", .rva = 0x1078f},
	{.name = "_OleUIMetafilePictExtractLabel_16", .rva = 0x78f3},
	{.name = "__imp___vsnwprintf", .rva = 0x1014},
	{.name = "_OleUIPasteSpecialA_4", .rva = 0x11181},
	{.name = "_string__54", .rva = 0x1528},
	{.name = "__imp__SystemTimeToFileTime_8", .rva = 0x1130},
	{.name = "_OleStdGetData_20", .rva = 0xd784},
	{.name = "__imp__GetDlgItem_8", .rva = 0x12b4},
	{.name = "_OleUIInitialize_8", .rva = 0x1b5d},
	{.name = "StringCbCopyW", .rva = 0xfa33},
	{.name = "__imp__ReleaseDC_8", .rva = 0x11a4},
	{.name = "__imp__RegNotifyChangeKeyValue_20", .rva = 0x13a0},
	{.name = "__imp__EtwTraceMessage", .rva = 0x1400},
	{.name = "EnumMetafileExtractLabel", .rva = 0x7397},
	{.name = "__imp__ChangeClipboardChain_8", .rva = 0x123c},
	{.name = "CStringCache__OKToUse", .rva = 0xfa28},
	{.name = "__except_handler4_common", .rva = 0x12839},
	{.name = "__imp__FileTimeToSystemTime_8", .rva = 0x1144},
	{.name = "__imp__GlobalSize_4", .rva = 0x1074},
	{.name = "__imp__SetViewportOrgEx_16", .rva = 0x1314},
	{.name = "__initterm", .rva = 0x1644},
	{.name = "WrappedIOleUILinkInfo___vftable_", .rva = 0x286c},
	{.name = "___onexitbegin", .rva = 0x15084},
	{.name = "__imp__InflateRect_12", .rva = 0x121c},
	{.name = "FillClassList", .rva = 0x5d15},
	{.name = "HourGlassOff", .rva = 0x1013e},
	{.name = "__imp__LocalFree_4", .rva = 0x1068},
	{.name = "__imp__MulDiv_12", .rva = 0x1084},
	{.name = "URefillClassList", .rva = 0x9f1f},
	{.name = "gbOKToUseCache", .rva = 0x15064},
	{.name = "__imp__GetFullPathNameW_16", .rva = 0x1150},
	{.name = "ValidatePtrsForThisProcess", .rva = 0x12505},
	{.name = "_XformWidthInHimetricToPixels_8", .rva = 0xfc20},
	{.name = "_g_cfOwnerLink", .rva = 0x15038},
	{.name = "__imp__FindResourceW_12", .rva = 0x1114},
	{.name = "__imp__GetCurrentDirectoryW_8", .rva = 0x1054},
	{.name = "_string__55", .rva = 0x9ae0},
	{.name = "__imp__RegOpenKeyW_12", .rva = 0x139c},
	{.name = "__imp__SetDlgItemInt_16", .rva = 0x12ac},
	{.name = "_g_cfEmbeddedObject", .rva = 0x15044},
	{.name = "_string__56", .rva = 0x13060},
	{.name = "__imp__UnhandledExceptionFilter_4", .rva = 0x10d0},
	{.name = "__imp__IsBadReadPtr_8", .rva = 0x1098},
	{.name = "__imp__SelectObject_8", .rva = 0x1340},
	{.name = "__imp__GetWindowTextW_12", .rva = 0x1288},
	{.name = "WrappedIOleUILinkInfo__GetLastUpdate", .rva = 0x11d57},
	{.name = "__imp__GetLastError_0", .rva = 0x116c},
	{.name = "uMsgChangeIcon", .rva = 0x1500c},
	{.name = "__imp__DeleteObject_4", .rva = 0x12ec},
	{.name = "WrappedIOleUILinkInfo__GetLinkSource", .rva = 0x11bf4},
	{.name = "__imp__OleRegGetUserType_12", .rva = 0x13e4},
	{.name = "_string__57", .rva = 0x5604},
	{.name = "AllocateScratchMem", .rva = 0xe27f},
	{.name = "___report_gsfailure", .rva = 0x1274f},
	{.name = "LpvStandardEntryHelper", .rva = 0x54e5},
	{.name = "WrappedIOleUILinkInfo__OpenLinkSource", .rva = 0x11d3a},
	{.name = "_string__58", .rva = 0x58a0},
	{.name = "__imp__GetSystemTime_4", .rva = 0x112c},
	{.name = "OpenFileError", .rva = 0x1086d},
	{.name = "CStringCache__CleanUp", .rva = 0xfaa3},
	{.name = "__imp__InterlockedCompareExchange_12", .rva = 0x10b0},
	{.name = "_string__59", .rva = 0xb980},
	{.name = "__imp__LockResource_4", .rva = 0x111c},
	{.name = "___native_startup_lock", .rva = 0x15098},
	{.name = "_string__60", .rva = 0x56d8},
	{.name = "_string__61", .rva = 0x1d9c},
	{.name = "StandardEnableDlgItem", .rva = 0x564f},
	{.name = "__imp__malloc", .rva = 0x1024},
	{.name = "InsertObjectCleanup", .rva = 0x9260},
	{.name = "__imp__GlobalLock_4", .rva = 0x1110},
	{.name = "__imp__SetPropW_12", .rva = 0x1264},
	{.name = "uMsgBrowse", .rva = 0x15018},
	{.name = "FDrawListIcon", .rva = 0x7c50},
	{.name = "FormatString2", .rva = 0x10b33},
	{.name = "___native_startup_state", .rva = 0x1507c},
	{.name = "Container_ChangeSource", .rva = 0xc3d0},
	{.name = "__imp__CharNextW_4", .rva = 0x11e8},
	{.name = "__load_config_used", .rva = 0x28c0},
	{.name = "CStringCache__FlushCache", .rva = 0xfa18},
	{.name = "__imp__DefWindowProcW_16", .rva = 0x11d8},
	{.name = "WrappedIOleUILinkContainer__SetLinkUpdateOptions", .rva = 0x11b66},
	{.name = "__imp__FindClose_4", .rva = 0x10e8},
	{.name = "_OleUIPromptUserW", .rva = 0xd268},
	{.name = "EnableChangeIconButton", .rva = 0x92b8},
	{.name = "_OleUIPromptUserA", .rva = 0x11d8c},
	{.name = "_string__62", .rva = 0x57b0},
	{.name = "__imp___3_YAXPAX_Z", .rva = 0x1030},
	{.name = "_string__63", .rva = 0x9b14},
	{.name = "IsElevatedToken", .rva = 0x12a26},
	{.name = "_memcpy", .rva = 0x125e1},
	{.name = "InitControls", .rva = 0xb6a0},
	{.name = "FViewPropsInit", .rva = 0x33a0},
	{.name = "_ULongAdd_12", .rva = 0x12eb9},
	{.name = "IsUIAccessToken", .rva = 0x12aaf},
	{.name = "_OleUICanConvertOrActivateAs_12", .rva = 0x61a1},
	{.name = "FIsDiskFile", .rva = 0x100cc},
	{.name = "_OleStdMalloc_4", .rva = 0xd842},
	{.name = "WrappedIOleUILinkInfo__QueryInterface", .rva = 0x114c7},
	{.name = "__imp__DialogBoxParamW_20", .rva = 0x120c},
	{.name = "UStandardHook", .rva = 0x558f},
	{.name = "__pRawDllMain", .rva = 0x15400},
	{.name = "ULongLongToULong", .rva = 0x2911},
	{.name = "__imp__PlayMetaFileRecord_16", .rva = 0x136c},
	{.name = "FindReverseChar", .rva = 0x101f2},
	{.name = "_string__64", .rva = 0x27fc},
	{.name = "WrappedIOleUIObjInfo___vftable_", .rva = 0x284c},
	{.name = "__imp__OleDuplicateData_12", .rva = 0x13e0},
	{.name = "__imp__SetCursor_4", .rva = 0x1248},
	{.name = "uMsgHelp", .rva = 0x15034},
	{.name = "__imp__GlobalAlloc_8", .rva = 0x110c},
	{.name = "CStringCache__Init", .rva = 0x1e0d},
	{.name = "__imp__GetTextExtentPointW_16", .rva = 0x1360},
	{.name = "WrappedIOleUILinkInfo__GetNextLink", .rva = 0x114fa},
	{.name = "__imp__PeekMessageW_20", .rva = 0x1220},
	{.name = "_string__65", .rva = 0x9bc0},
	{.name = "__imp__LoadCursorW_8", .rva = 0x11e0},
	{.name = "MyGetLongPathName", .rva = 0x7e60},
	{.name = "__imp__OleGetClipboard_4", .rva = 0x13a8},
	{.name = "PasteSpecialDialogProc", .rva = 0xf44b},
	{.name = "ChangeIcon", .rva = 0xe109},
	{.name = "_string__66", .rva = 0x10780},
	{.name = "_OleUIObjectPropertiesA_4", .rva = 0x12121},
	{.name = "__imp__CloseHandle_4", .rva = 0x109c},
	{.name = "__imp__GetBitmapBits_12", .rva = 0x12f0},
	{.name = "__imp__GetMenu_4", .rva = 0x11f4},
	{.name = "_OleStdFillObjectDescriptorFromData_12", .rva = 0xdb33},
	{.name = "_string__67", .rva = 0x1c70},
	{.name = "_string__68", .rva = 0x1564},
	{.name = "__imp__LocalFileTimeToFileTime_8", .rva = 0x1138},
	{.name = "__imp__UnregisterClassW_8", .rva = 0x11c0},
	{.name = "_string__69", .rva = 0x1c9c},
	{.name = "_string__70", .rva = 0x1d4c},
	{.name = "ULongAdd", .rva = 0x12eb9},
	{.name = "IsValidMetaPict", .rva = 0x10397},
	{.name = "__imp__BitBlt_36", .rva = 0x1354},
	{.name = "__DllMainCRTStartup_12", .rva = 0x17db},
	{.name = "__imp__InsertMenuW_20", .rva = 0x1200},
	{.name = "__imp__IsIconic_4", .rva = 0x1274},
	{.name = "WrappedIOleUILinkInfo__AddRef", .rva = 0x114e0},
	{.name = "__imp__DrawIcon_16", .rva = 0x11b0},
	{.name = "HourGlassOn", .rva = 0x10114},
	{.name = "WrappedIOleUILinkInfo__WrappedIOleUILinkInfo", .rva = 0x120f4},
	{.name = "__imp__MapWindowPoints_16", .rva = 0x1174},
	{.name = "__imp__GetDesktopWindow_0", .rva = 0x1268},
	{.name = "__imp__GetNumberFormatW_24", .rva = 0x1124},
	{.name = "__imp__RegOpenKeyExW_20", .rva = 0x1398},
	{.name = "_OleStdIsOleLink_4", .rva = 0xd98f},
	{.name = "GetFileName", .rva = 0x10d43},
	{.name = "WrappedIOleUIObjInfo__AddRef", .rva = 0x114e0},
	{.name = "_string__71", .rva = 0xde88},
	{.name = "__imp___onexit", .rva = 0x1000},
	{.name = "gbCacheInit", .rva = 0x15060},
	{.name = "GetTokenElevationType", .rva = 0x12b38},
	{.name = "__imp__EnableWindow_8", .rva = 0x1254},
	{.name = "_OleUIConvertW_4", .rva = 0x7171},
	{.name = "_g_ulMaxStackAllocSize", .rva = 0x15088},
	{.name = "_SafeAllocaInitialize_16", .rva = 0x16ff},
	{.name = "__imp__MultiByteToWideChar_24", .rva = 0x10f0},
	{.name = "WrappedIOleUILinkContainer__SetLinkSource", .rva = 0x11b86},
	{.name = "_SafeAllocaAllocateFromHeap_4", .rva = 0x130c4},
	{.name = "_string__72", .rva = 0xd684},
	{.name = "AddCommas", .rva = 0x4072},
	{.name = "AddLinkLBItem", .rva = 0xb569},
	{.name = "LinkPropsDialogProc", .rva = 0x38cf},
	{.name = "__imp__GetLocaleInfoW_16", .rva = 0x1120},
	{.name = "___dyn_tls_init_callback", .rva = 0x15404},
	{.name = "__imp___stricmp", .rva = 0x1018},
	{.name = "IsUserHiveOK", .rva = 0x12baf},
	{.name = "__imp__RtlImageNtHeader_4", .rva = 0x13f8},
	{.name = "__imp__KillTimer_8", .rva = 0x1218},
	{.name = "__imp__GetTimeFormatW_24", .rva = 0x113c},
	{.name = "BreakString", .rva = 0xb47d},
	{.name = "__imp__GetCurrentThreadId_0", .rva = 0x10bc},
	{.name = "__amsg_exit", .rva = 0x12749},
	{.name = "__imp__PostMessageW_16", .rva = 0x12c4},
	{.name = "StringCchCopyNW", .rva = 0x2a99},
	{.name = "__imp__LoadIconW_8", .rva = 0x1270},
	{.name = "UAltStandardHook", .rva = 0x558f},
	{.name = "__IsNonwritableInCurrentImage", .rva = 0x126ba},
	{.name = "__imp__GetActiveWindow_0", .rva = 0x11f8},
	{.name = "ULongSub", .rva = 0x72be},
	{.name = "WrappedIOleUIObjInfo__GetViewInfo", .rva = 0x11b02},
	{.name = "__imp__CreateCompatibleBitmap_12", .rva = 0x1300},
	{.name = "__imp__GetSystemMetrics_4", .rva = 0x11a0},
	{.name = "_string__73", .rva = 0x4128},
	{.name = "__imp___XcptFilter", .rva = 0x1038},
	{.name = "__imp__RegCloseKey_4", .rva = 0x1388},
	{.name = "__imp__RtlFreeHeap_12", .rva = 0x1404},
	{.name = "__imp__TlsFree_4", .rva = 0x1064},
	{.name = "_GUID_NULL", .rva = 0x289c},
	{.name = "__imp__OleCreateLinkToFile_28", .rva = 0x13c8},
	{.name = "uMsgConvert", .rva = 0x15024},
	{.name = "__imp__RegisterWindowMessageW_4", .rva = 0x11b8},
	{.name = "_string__74", .rva = 0x9bd8},
	{.name = "CancelLink", .rva = 0xbe7e},
	{.name = "WrappedIOleUILinkInfo__GetLinkUpdateOptions", .rva = 0x11ae2},
	{.name = "__imp__IsWindowEnabled_4", .rva = 0x128c},
	{.name = "__imp__GetParent_4", .rva = 0x12a0},
	{.name = "StringCchVPrintfW", .rva = 0xccc5},
	{.name = "SetPasteSpecialHelpResults", .rva = 0xe7f2},
	{.name = "_string__75", .rva = 0x140c},
	{.name = "__imp__GetDlgItemInt_16", .rva = 0x1290},
	{.name = "ViewPropsDialogProc", .rva = 0x495f},
	{.name = "_OleUIUpdateLinksW_16", .rva = 0xd6b7},
	{.name = "ChangeSourceHookProc", .rva = 0x2b42},
	{.name = "__imp__IsWow64Process_8", .rva = 0x1160},
	{.name = "_string__76", .rva = 0x1438},
	{.name = "__imp__SetWindowTextW_8", .rva = 0x12dc},
	{.name = "__imp__BeginPaint_8", .rva = 0x11cc},
	{.name = "_OleUIObjectPropertiesW_4", .rva = 0x4ee9},
	{.name = "Container_UpdateNow", .rva = 0xbfca},
	{.name = "__imp__InterlockedExchange_8", .rva = 0x10a8},
	{.name = "__imp__VirtualProtect_16", .rva = 0x115c},
	{.name = "MakeWindowActive", .rva = 0x5016},
	{.name = "__imp__SetDIBits_28", .rva = 0x12f8},
	{.name = "__imp__OleGetIconOfClass_12", .rva = 0x13f0},
	{.name = "__imp____dllonexit", .rva = 0x1008},
	{.name = "OleDlgIsBadWritePtr", .rva = 0x1253f},
	{.name = "_OleUIAddVerbMenuA_36", .rva = 0x10f81},
	{.name = "EditLinksDialogProc", .rva = 0xc525},
	{.name = "EnumMetafileExtractIcon", .rva = 0x744d},
	{.name = "FGnrlPropsRefresh", .rva = 0x42de},
	{.name = "_string__77", .rva = 0xd6a8},
	{.name = "__imp___2_YAPAXI_Z", .rva = 0x1034},
	{.name = "OleDlgIsBadCodePtr", .rva = 0x1257f},
	{.name = "_WPP_SF_d_20", .rva = 0x128d7},
	{.name = "_WPP_SF_D_20", .rva = 0x128d7},
	{.name = "FFillPasteList", .rva = 0xe3de},
	{.name = "_g_ulAdditionalProbeSize", .rva = 0x1508c},
	{.name = "__imp__CreateFileW_28", .rva = 0x108c},
	{.name = "ChangeListSelection", .rva = 0xe9ab},
	{.name = "__ValidateImageBase", .rva = 0x12637},
	{.name = "_string__78", .rva = 0x10f54},
	{.name = "_EtwTraceMessage", .rva = 0x13189},
	{.name = "__imp__wcschr", .rva = 0x1028},
	{.name = "FResultImageInitialize", .rva = 0x1edf},

};
static uint64_t win7_sp1_x86_oledlg_count = 676;
