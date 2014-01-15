#ifndef WIN7_SP1_X86_H
#define WIN7_SP1_X86_H
#include "win7_sp1_x86/ntdll.h"
#include "win7_sp1_x86/ntkrpamp.h"
#include "win7_sp1_x86/ntkrnlmp.h"
static const uint64_t win7_sp1_x86_config_count = 2;
static const struct config win7_sp1_x86_config[] = {
	{.name="ntdll", .guids=win7_sp1_x86_ntdll_guid, .syms=win7_sp1_x86_ntdll, .sym_count=&win7_sp1_x86_ntdll_count},
	{.name="ntkrpamp", .guids=win7_sp1_x86_ntkrpamp_guid, .syms=win7_sp1_x86_ntkrpamp, .sym_count=&win7_sp1_x86_ntkrpamp_count},
	{.name="ntkrnlmp", .guids=win7_sp1_x86_ntkrnlmp_guid, .syms=win7_sp1_x86_ntkrnlmp, .sym_count=&win7_sp1_x86_ntkrnlmp_count},
};
#endif
