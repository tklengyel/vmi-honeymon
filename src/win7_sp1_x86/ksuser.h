static char *win7_sp1_x86_ksuser_guid[2] = {
	"4a5bdab304000",
	"7ae6bfac128c4c57baaf1c0b79fa95b42"
	};
static struct symbol win7_sp1_x86_ksuser[] = {
	{.name = "__imp__HeapFree_12", .rva = 0x1014},
	{.name = "__imp__NtCreateFile_44", .rva = 0x100c},
	{.name = "__imp__memcpy", .rva = 0x1000},
	{.name = "_KsiCreateObjectType_24", .rva = 0x120d},
	{.name = "_DllInstanceInit_12", .rva = 0x1030},
	{.name = "$$VProc_ImageExportDirectory", .rva = 0x10e4},
	{.name = "_KsCreateTopologyNode_16", .rva = 0x1485},
	{.name = "_KsCreateClock_12", .rva = 0x140d},
	{.name = "_KsCreatePin_16", .rva = 0x1185},
	{.name = "__imp__GetProcessHeap_0", .rva = 0x1018},
	{.name = "__imp__RtlNtStatusToDosError_4", .rva = 0x1008},
	{.name = "_memcpy", .rva = 0x10dc},
	{.name = "_ULongAdd_12", .rva = 0x132b},
	{.name = "__imp__HeapAlloc_12", .rva = 0x101c},
	{.name = "_StringCbCopyW_12", .rva = 0x1068},
	{.name = "_ULongLongToULong_12", .rva = 0x103b},
	{.name = "_KsCreateAllocator_12", .rva = 0x1393},

};
static uint64_t win7_sp1_x86_ksuser_count = 17;
