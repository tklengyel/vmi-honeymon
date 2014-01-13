static char *win7_sp1_x86_ShimEng_guid[2] = {
	"4a5bdb0405000",
	"9a7a1f9dd5244586ac60d7bc5dce6f6e2"
	};
static struct symbol win7_sp1_x86_ShimEng[] = {
	{.name = "__DllMainCRTStartupForGS2_12", .rva = 0x106c},
	{.name = "___security_cookie", .rva = 0x2000},
	{.name = "__imp__QueryPerformanceCounter_4", .rva = 0x1010},
	{.name = "_DllMain_12", .rva = 0x1020},
	{.name = "__imp__GetSystemTimeAsFileTime_4", .rva = 0x100c},
	{.name = "__imp__GetTickCount_0", .rva = 0x1008},
	{.name = "__imp__GetCurrentProcessId_0", .rva = 0x1018},
	{.name = "__imp__AitLogFeatureUsageByApp_4", .rva = 0x1000},
	{.name = "_AIT_ShimEngLoaded", .rva = 0x105c},
	{.name = "$$VProc_ImageExportDirectory", .rva = 0x10f4},
	{.name = "___security_init_cookie", .rva = 0x1083},
	{.name = "___security_cookie_complement", .rva = 0x2004},
	{.name = "_AitLogFeatureUsageByApp_4", .rva = 0x10ee},
	{.name = "__imp__GetCurrentThreadId_0", .rva = 0x1014},

};
static uint64_t win7_sp1_x86_ShimEng_count = 14;
