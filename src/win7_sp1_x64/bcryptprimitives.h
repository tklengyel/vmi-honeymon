static char *win7_sp1_x64_bcryptprimitives_guid[2] = {
	"4ce7c4f04c000",
	"0668ac8d552c4c1d838c981b5b1b684d2"
	};
static struct symbol win7_sp1_x64_bcryptprimitives[] = {
	{.name = "SHA384Init", .rva = 0x1cfd0},
	{.name = "MSCryptAlloc", .rva = 0x2a6f0},
	{.name = "SHA512Init", .rva = 0xaf50},
	{.name = "ec_initialize", .rva = 0x11f3c},
	{.name = "fips186bignum_big_endian_bytes_to_digits", .rva = 0x284c0},
	{.name = "Kcopy_many", .rva = 0x14c34},
	{.name = "AesCreateRotatedTables", .rva = 0xed10},
	{.name = "MSCryptRsaDecrypt", .rva = 0x7120},
	{.name = "GF2_get_funcs", .rva = 0x195dc},
	{.name = "DualEcRng_Uninstantiate", .rva = 0x2a950},
	{.name = "rgbDh256DerivedKey", .rva = 0x442d0},
	{.name = "ec_NIST_P384", .rva = 0x3b870},
	{.name = "set_immediate", .rva = 0x165b0},
	{.name = "add_diff", .rva = 0xd790},
	{.name = "_string_", .rva = 0x39700},
	{.name = "MSCryptOpenRngProvider", .rva = 0x10fe0},
	{.name = "rgbAesCtrRngSeed", .rva = 0x44b90},
	{.name = "_string__2", .rva = 0x3d098},
	{.name = "rsa_export_sizes", .rva = 0xc35c},
	{.name = "_local_unwind", .rva = 0x249ac},
	{.name = "PairwiseConsistencySecretAgreement", .rva = 0x331b0},
	{.name = "two_adic_inverse", .rva = 0x4bd4},
	{.name = "ecaffine_exponentiation_via_multi_projective", .rva = 0x14214},
	{.name = "DesxEcb", .rva = 0x28220},
	{.name = "DSA_convert_pgy", .rva = 0x20840},
	{.name = "MSCryptCreateSecret", .rva = 0x30a30},
	{.name = "__imp_VirtualProtect", .rva = 0x37130},
	{.name = "Validate_PublicKey", .rva = 0x2c860},
	{.name = "rgbSha1KAT_HMAC_Answer", .rva = 0x44cd8},
	{.name = "g_fLoadCNGDone", .rva = 0x436e0},
	{.name = "possible_digit_allocate_named", .rva = 0x5c70},
	{.name = "g_hInstance", .rva = 0x41060},
	{.name = "SetMpErrno_clue1", .rva = 0x2a940},
	{.name = "__security_cookie_complement", .rva = 0x437f0},
	{.name = "DhPairWiseCheck", .rva = 0x35630},
	{.name = "fips186rng_dsa_block", .rva = 0x29150},
	{.name = "MSCryptDestroySecret", .rva = 0x2dcf0},
	{.name = "SHA256Final", .rva = 0x7ec0},
	{.name = "__imp_DeviceIoControl", .rva = 0x37120},
	{.name = "MSCryptDsaImportKeyPair", .rva = 0x323a0},
	{.name = "_string__3", .rva = 0x3ca20},
	{.name = "mod_Lucas", .rva = 0x1a864},
	{.name = "desparityonkey", .rva = 0x1b200},
	{.name = "compare_diff", .rva = 0x5490},
	{.name = "MSCryptEccSetProperty", .rva = 0x2b010},
	{.name = "ApplyPSSPaddingSalted", .rva = 0x2f660},
	{.name = "Kimmediate", .rva = 0x14de8},
	{.name = "__imp_TlsGetValue", .rva = 0x370d8},
	{.name = "Kinvert", .rva = 0x169dc},
	{.name = "__imp_BCryptGetFipsAlgorithmMode", .rva = 0x371b8},
	{.name = "GF2_square", .rva = 0x194cc},
	{.name = "A_SHAInit", .rva = 0x2a10},
	{.name = "DsaSignAndVerify", .rva = 0x35020},
	{.name = "__imp_RtlInitUnicodeString", .rva = 0x370a0},
	{.name = "digit_allocate_named", .rva = 0x4200},
	{.name = "MSCryptRsaVerifySignature", .rva = 0xdf10},
	{.name = "MSCryptGetKeyData", .rva = 0x2d2d0},
	{.name = "rgbDsa1024PrivateKey", .rva = 0x44370},
	{.name = "MSCipherFunctionTable", .rva = 0x410c0},
	{.name = "NewGenRandomEx", .rva = 0x2de30},
	{.name = "MSCryptValidateSecretHandle", .rva = 0x28600},
	{.name = "MSCryptDsaTestPairWiseTable", .rva = 0x44748},
	{.name = "Sel", .rva = 0x3bdf0},
	{.name = "rgbAesGcmAssocData", .rva = 0x44ca0},
	{.name = "des", .rva = 0x97d0},
	{.name = "MSCryptEcDsaSignHash", .rva = 0x2ae80},
	{.name = "_string__4", .rva = 0x3bba0},
	{.name = "_vsnwprintf", .rva = 0x1af00},
	{.name = "_string__5", .rva = 0x3ce70},
	{.name = "MSCryptDestroyHash", .rva = 0x12f0},
	{.name = "AesGcm", .rva = 0x1c580},
	{.name = "BCryptCloseAlgorithmProvider", .rva = 0xe240},
	{.name = "Kinitialize_polynomial2", .rva = 0x158c0},
	{.name = "RsaAlgorithmCheck", .rva = 0x2a1c0},
	{.name = "MSCryptDsaGetProperty", .rva = 0x2cd60},
	{.name = "AesCtrRng_Instantiate", .rva = 0x9620},
	{.name = "_string__6", .rva = 0x395f0},
	{.name = "EccAlgorithmCheck", .rva = 0x34840},
	{.name = "__imp_TlsAlloc", .rva = 0x370e8},
	{.name = "GF2_multiply_same", .rva = 0x1a54c},
	{.name = "TestFipsRng", .rva = 0x28630},
	{.name = "_string__7", .rva = 0x3ca1a},
	{.name = "low_prime_prod_destruction", .rva = 0x21628},
	{.name = "g_ulAdditionalProbeSize", .rva = 0x46258},
	{.name = "MaskGeneration", .rva = 0x2bb90},
	{.name = "DesxCbc", .rva = 0x28000},
	{.name = "rgbAES128KnownCiphertextCBC", .rva = 0x44c60},
	{.name = "AccumulateSquares64", .rva = 0xf460},
	{.name = "sub_diff", .rva = 0x11a30},
	{.name = "MSCryptEcDhExportKeyPair", .rva = 0x2e680},
	{.name = "rgszChainModeNameArray", .rva = 0x44a00},
	{.name = "MSCryptEcDsaVerifySignature", .rva = 0x2ad00},
	{.name = "_string__8", .rva = 0x395b0},
	{.name = "MSCryptOpenDHProvider", .rva = 0x2c540},
	{.name = "rgbAesCcmCiphertext01", .rva = 0x44bd4},
	{.name = "SHA256Magic", .rva = 0x39480},
	{.name = "InternalGenerateEccKey", .rva = 0x2f300},
	{.name = "AesCcmValidateParameters", .rva = 0x1e050},
	{.name = "mp_copybits", .rva = 0x6de8},
	{.name = "_string__9", .rva = 0x3cd50},
	{.name = "rgHashAlgorithmDefaults", .rva = 0x41240},
	{.name = "CryptAuditTranslateAlgID", .rva = 0x288f0},
	{.name = "GetSignatureInterface", .rva = 0x28d60},
	{.name = "HMACSHAInit", .rva = 0x1cc40},
	{.name = "g_SignVerifyHash", .rva = 0x442b8},
	{.name = "_string__10", .rva = 0x3cfc8},
	{.name = "ecsp_dsa", .rva = 0x14488},
	{.name = "MSCryptGetPerThreadRngState", .rva = 0x2dbd0},
	{.name = "SlavePrng", .rva = 0x9400},
	{.name = "ValidateEccKey", .rva = 0x28bf0},
	{.name = "_string__11", .rva = 0x39730},
	{.name = "MSCryptFinalizeKeyPair", .rva = 0x35aa0},
	{.name = "_string__12", .rva = 0x3ca98},
	{.name = "Rc2Ecb", .rva = 0x28140},
	{.name = "MSCryptECDHSP80056AConCatKDFTest", .rva = 0x345c0},
	{.name = "GetHashInterface", .rva = 0x7c60},
	{.name = "MSCryptEccGetProperty", .rva = 0x2e900},
	{.name = "AesCcmEncryptDecrypt", .rva = 0x1e2c0},
	{.name = "MSCryptCloseEcRngProvider", .rva = 0x2e620},
	{.name = "ValidateDSAKey", .rva = 0x27b70},
	{.name = "ec_NIST_P521", .rva = 0x3b9b0},
	{.name = "ecprojective_set_infinite", .rva = 0x12d50},
	{.name = "MSEcDsaSignFunctionTable", .rva = 0x45020},
	{.name = "ULongAdd", .rva = 0x288d0},
	{.name = "Kadder_2", .rva = 0x14f48},
	{.name = "CheckIfNeedToCalculatePublicKey", .rva = 0x28ba0},
	{.name = "GHashResult", .rva = 0x1e5c0},
	{.name = "ec_NIST_P256", .rva = 0x3b780},
	{.name = "__imp_BCryptCreateHash", .rva = 0x371b0},
	{.name = "rgbAesCcmAssocData01", .rva = 0x44c80},
	{.name = "GF2_mod_mul", .rva = 0x18060},
	{.name = "sub_immediate", .rva = 0xebfc},
	{.name = "mp_significant_bit_count", .rva = 0x424c},
	{.name = "_string__13", .rva = 0x3ce48},
	{.name = "rsa_decryption", .rva = 0x73a8},
	{.name = "MSCryptDHSecretAgreement", .rva = 0x32050},
	{.name = "divide_precondition_1", .rva = 0x61fc},
	{.name = "MSCryptProtectSecret", .rva = 0x30800},
	{.name = "MSRsaEncryptFunctionTable", .rva = 0x41120},
	{.name = "_string__14", .rva = 0x3ceb8},
	{.name = "KdfRouterMapping", .rva = 0x44df0},
	{.name = "rgbSha1KAT_HMAC_Msg", .rva = 0x44d00},
	{.name = "ecvp_dsa", .rva = 0x147e0},
	{.name = "validateMSCryptSymmAlgorithm", .rva = 0x28450},
	{.name = "accumulate", .rva = 0x4c38},
	{.name = "Accumulate", .rva = 0xf350},
	{.name = "SHA512Magic", .rva = 0x3b400},
	{.name = "MD4Init", .rva = 0x1d870},
	{.name = "g_dwPerThreadRngTlsSlot", .rva = 0x41000},
	{.name = "Test_AesCtrRng_Generate", .rva = 0x30c20},
	{.name = "fips186bignum_digits_to_big_endian_bytes", .rva = 0x28490},
	{.name = "MSCryptEcGenRandom", .rva = 0x344d0},
	{.name = "MSCryptSetKeyProperty", .rva = 0x28320},
	{.name = "BASE_INIT_PROV", .rva = 0x10d30},
	{.name = "MD5Init", .rva = 0x1dc0},
	{.name = "AesExpandKey", .rva = 0x1360},
	{.name = "DSA_build_fullkey", .rva = 0x21308},
	{.name = "memcpy", .rva = 0x1030},
	{.name = "__imp_BCryptDecrypt", .rva = 0x37180},
	{.name = "mp_thread_initialize", .rva = 0xac60},
	{.name = "MSCryptEcDhSetProperty", .rva = 0x2e6d0},
	{.name = "Spbox", .rva = 0x39890},
	{.name = "SHA256Init", .rva = 0x8b60},
	{.name = "__security_init_cookie_ex", .rva = 0x112f4},
	{.name = "rsa_prime_private_exponent", .rva = 0xeae4},
	{.name = "X931_keygen_allocate_arrays", .rva = 0x1e7d0},
	{.name = "X931_keygen_B4", .rva = 0x1e994},
	{.name = "_resetstkoflw_downlevel", .rva = 0x2a750},
	{.name = "__imp_memset", .rva = 0x37020},
	{.name = "MSCryptFreeRngState", .rva = 0x7a90},
	{.name = "EnumerateAndHashBufferType", .rva = 0x292a0},
	{.name = "TestPairWise", .rva = 0x287a0},
	{.name = "add_immediate", .rva = 0xc0a0},
	{.name = "ImportLittleModulusToKey", .rva = 0x2c600},
	{.name = "MSCryptImportDHKeyPair", .rva = 0x34cd0},
	{.name = "MSCryptAesKeyUnwrap", .rva = 0x2d010},
	{.name = "_string__15", .rva = 0x3cd80},
	{.name = "GetRsaProperty", .rva = 0x48a0},
	{.name = "RtlUnhandledExceptionFilter", .rva = 0x113a0},
	{.name = "ValidateDHAlgorithm", .rva = 0x27870},
	{.name = "MSCryptValidateSecret", .rva = 0x2a6b0},
	{.name = "desx", .rva = 0x1cbd0},
	{.name = "__C_specific_handler", .rva = 0x249a0},
	{.name = "rgbAES128KnownCiphertext", .rva = 0x44c40},
	{.name = "_string__16", .rva = 0x39630},
	{.name = "RtlCaptureContext", .rva = 0x113c4},
	{.name = "random_bytes", .rva = 0x30ed0},
	{.name = "gcdex_jacobi", .rva = 0x23ed0},
	{.name = "_string__17", .rva = 0x3c968},
	{.name = "memmove", .rva = 0xa584},
	{.name = "MSCryptEccImportKeyPair", .rva = 0x2eb50},
	{.name = "__imp_HeapFree", .rva = 0x37110},
	{.name = "MSCryptExportKey", .rva = 0x3e50},
	{.name = "SHA384Final", .rva = 0x1d050},
	{.name = "SHA512Final", .rva = 0xada0},
	{.name = "MSCryptGenerateKeyPair", .rva = 0x2cf00},
	{.name = "DSA_gen_x", .rva = 0x20034},
	{.name = "SHATransform", .rva = 0x2c40},
	{.name = "mod_sqrt", .rva = 0x18620},
	{.name = "rgbAES128Key", .rva = 0x44c30},
	{.name = "MyPrimitiveMD5", .rva = 0x27660},
	{.name = "MSCryptDsaSetProperty", .rva = 0x2cd00},
	{.name = "MSHashFunctionTable", .rva = 0x41010},
	{.name = "__GSHandlerCheckCommon", .rva = 0x24858},
	{.name = "validateMSCryptHash", .rva = 0x28300},
	{.name = "BCryptGetProperty", .rva = 0xd584},
	{.name = "_string__18", .rva = 0x3cf30},
	{.name = "GetRngInterface", .rva = 0x10fc0},
	{.name = "MSCryptGetRsaProperty", .rva = 0x4870},
	{.name = "A_SHAFinal", .rva = 0x2a50},
	{.name = "_string__19", .rva = 0x3c820},
	{.name = "_string__20", .rva = 0x3cfe8},
	{.name = "DSA_key_generation", .rva = 0x202fc},
	{.name = "DSA_exponentiator_default", .rva = 0x1f86c},
	{.name = "SafeAllocaFreeToHeap", .rva = 0x2a720},
	{.name = "__imp_RtlAllocateHeap", .rva = 0x37038},
	{.name = "from_modular", .rva = 0x6654},
	{.name = "ValidateDSAKeyBlob", .rva = 0x27a50},
	{.name = "_string__21", .rva = 0x3cd88},
	{.name = "DSA_parameter_verification", .rva = 0x2113c},
	{.name = "MSCryptDsaExportKeyPair", .rva = 0x2c940},
	{.name = "SHA256Update", .rva = 0x7fe0},
	{.name = "MSCryptPerThreadRngInitialize", .rva = 0x10e30},
	{.name = "AesInvSbox", .rva = 0x3a100},
	{.name = "_string__22", .rva = 0x3d028},
	{.name = "Rc2Cfb", .rva = 0x27dd0},
	{.name = "MSCryptDsaOpenProvider", .rva = 0x2ce40},
	{.name = "Aes4SboxXmmAsm", .rva = 0xf320},
	{.name = "Accumulate64", .rva = 0xf4a0},
	{.name = "MSCryptDeriveKey", .rva = 0x30860},
	{.name = "MSCryptEcDhDestroyKeyPair", .rva = 0x31470},
	{.name = "_string__23", .rva = 0x3ce90},
	{.name = "SetMpErrno", .rva = 0xacc0},
	{.name = "MSCryptGetDHAlgProperty", .rva = 0x29610},
	{.name = "_string__24", .rva = 0x3b748},
	{.name = "_string__25", .rva = 0x39400},
	{.name = "mp_scrambled_setup", .rva = 0x6c30},
	{.name = "mod_exp", .rva = 0x54f0},
	{.name = "Kinvert_many", .rva = 0x16aa4},
	{.name = "rgbSha1KAT_HMAC_Key", .rva = 0x44cc8},
	{.name = "__imp_NtTerminateProcess", .rva = 0x37088},
	{.name = "BCryptDecrypt", .rva = 0x113dc},
	{.name = "MSCryptCloseHashProvider", .rva = 0x8bb0},
	{.name = "_string__26", .rva = 0x371c8},
	{.name = "rgbDh1024PrivateKey_for_pairwise", .rva = 0x43820},
	{.name = "decumulate", .rva = 0x4cb4},
	{.name = "AesCbcEncrypt", .rva = 0xeff0},
	{.name = "_string__27", .rva = 0x3b6f8},
	{.name = "modmul_from_right_fastx64_asm", .rva = 0x4e20},
	{.name = "rgbDh256PrivateKey_u", .rva = 0x43eb0},
	{.name = "FIPSOutputBlockCheck", .rva = 0x30740},
	{.name = "Kmul_many", .rva = 0x14e20},
	{.name = "__imp_TlsSetValue", .rva = 0x370e0},
	{.name = "MSCryptDsaCloseProvider", .rva = 0x2cca0},
	{.name = "VerifyStackAvailable", .rva = 0x2de70},
	{.name = "MSCryptPerThreadRngTearDown", .rva = 0x79c0},
	{.name = "__imp_RtlInitializeCriticalSection", .rva = 0x37058},
	{.name = "validate_modular_data1a", .rva = 0x66d8},
	{.name = "test_primality", .rva = 0x2245c},
	{.name = "rgbEcDhDerivedKey256", .rva = 0x451d0},
	{.name = "MSCryptFree", .rva = 0x2a720},
	{.name = "Test_DualEcRng_Generate", .rva = 0x30f50},
	{.name = "rgb3DESKnownCiphertext", .rva = 0x44b88},
	{.name = "_string__28", .rva = 0x39460},
	{.name = "AesGmacInit", .rva = 0x1d1e0},
	{.name = "AesCtrRng_Update", .rva = 0x9180},
	{.name = "GF2_double_reduce_general", .rva = 0x1a688},
	{.name = "__imp_EnterCriticalSection", .rva = 0x370f8},
	{.name = "__imp__local_unwind", .rva = 0x370b0},
	{.name = "low_prime_prod_construction", .rva = 0x214c4},
	{.name = "_string__29", .rva = 0x3ca58},
	{.name = "AesXorBytes", .rva = 0x1e720},
	{.name = "AesCcm", .rva = 0x2a210},
	{.name = "partyVInfo", .rva = 0x45158},
	{.name = "Rc2Cbc", .rva = 0x27f60},
	{.name = "FIPSPreSeedCheck", .rva = 0x32c90},
	{.name = "MD4Transform", .rva = 0x1d8a0},
	{.name = "_string__30", .rva = 0x3b688},
	{.name = "_string__31", .rva = 0x3c980},
	{.name = "MSCryptGenRandom", .rva = 0x1650},
	{.name = "__imp_GetSystemInfo", .rva = 0x37138},
	{.name = "rgb3DESKey", .rva = 0x44788},
	{.name = "rgbRNGSeed", .rva = 0x44bc0},
	{.name = "g_AesCtrSafeCtx", .rva = 0x41230},
	{.name = "_string__32", .rva = 0x39740},
	{.name = "dblint_ogcd", .rva = 0x23cb0},
	{.name = "AesCtrRng_XOR", .rva = 0x28850},
	{.name = "probable_prime", .rva = 0x21c68},
	{.name = "DesxCfb", .rva = 0x27e70},
	{.name = "MSCryptImportKeyPair", .rva = 0x42e0},
	{.name = "__imp_BCryptHashData", .rva = 0x371a0},
	{.name = "DllMain", .rva = 0x7950},
	{.name = "MSCryptAesKeyWrap", .rva = 0x303e0},
	{.name = "rgbEcDhPrivKey256", .rva = 0x45280},
	{.name = "MD2Transform", .rva = 0x1d560},
	{.name = "_string__33", .rva = 0x39768},
	{.name = "_string__34", .rva = 0x3ca80},
	{.name = "ecaffine_projectivize", .rva = 0x12df0},
	{.name = "_string__35", .rva = 0x3ce98},
	{.name = "_string__36", .rva = 0x3b720},
	{.name = "Kmulpower2er_2", .rva = 0x1510c},
	{.name = "__imp___C_specific_handler", .rva = 0x370a8},
	{.name = "_string__37", .rva = 0x3d008},
	{.name = "GetAsymmetricEncryptionInterface", .rva = 0xbd40},
	{.name = "div21", .rva = 0x63c0},
	{.name = "__imp_RtlCaptureContext", .rva = 0x37068},
	{.name = "Kimmediater_2", .rva = 0x15004},
	{.name = "MSCryptHashData", .rva = 0x1040},
	{.name = "g_RsaSignVerifyHash", .rva = 0x436c0},
	{.name = "DsaDhAlgorithmCheck", .rva = 0x34f90},
	{.name = "mod_LucasUV", .rva = 0x1ab50},
	{.name = "MSCryptEcDhOpenProvider", .rva = 0x2e700},
	{.name = "MSCryptDsaGetKeyPairProperty", .rva = 0x29fa0},
	{.name = "MSCryptUnprotectSecret", .rva = 0x2dcb0},
	{.name = "_string__38", .rva = 0x39450},
	{.name = "MSCryptEcDsaGetProperty", .rva = 0x316c0},
	{.name = "CBC", .rva = 0x9c80},
	{.name = "RSA_INIT_PROV", .rva = 0x10f60},
	{.name = "__GSHandlerCheck", .rva = 0x248c4},
	{.name = "MSCryptEcDsaSetProperty", .rva = 0x2e890},
	{.name = "PRF", .rva = 0x348e0},
	{.name = "divide_immediate", .rva = 0xe6fc},
	{.name = "MSCryptSetPerThreadRngState", .rva = 0x93b0},
	{.name = "DSA_INIT_PROV", .rva = 0x10fa0},
	{.name = "random_dword_interval", .rva = 0x16e64},
	{.name = "__imp_memcmp", .rva = 0x37090},
	{.name = "trailing_zero_count", .rva = 0x16520},
	{.name = "ApplyOAEPPaddingSeeded", .rva = 0x2fb60},
	{.name = "ECC_GENERATE_RNG_STATE", .rva = 0x33040},
	{.name = "rgbEcDsaPrivKey256", .rva = 0x45210},
	{.name = "partyUInfo", .rva = 0x450e8},
	{.name = "__imp_SetThreadStackGuarantee", .rva = 0x37128},
	{.name = "MSCryptOpenRsaProvider", .rva = 0xab90},
	{.name = "__imp_BCryptCloseAlgorithmProvider", .rva = 0x371a8},
	{.name = "_string__39", .rva = 0x3d078},
	{.name = "AesGcmEncryptDecrypt", .rva = 0x1c490},
	{.name = "ECC_INIT_PROV", .rva = 0x10f80},
	{.name = "MSCryptAuditCheckSecureZero", .rva = 0x2df60},
	{.name = "_string__40", .rva = 0x3ced8},
	{.name = "A_SHAUpdate", .rva = 0x2b60},
	{.name = "desxkey", .rva = 0x1cb90},
	{.name = "MSCryptCloseRsaProvider", .rva = 0xbdf0},
	{.name = "_string__41", .rva = 0x3cde0},
	{.name = "Kzeroizer_default", .rva = 0x152a8},
	{.name = "_string__42", .rva = 0x3c9a8},
	{.name = "BCryptGenRandom", .rva = 0x6b14},
	{.name = "rgbDh1024PrivateKey", .rva = 0x44540},
	{.name = "MSCryptFinishHash", .rva = 0x10e0},
	{.name = "MSCryptEcDhSecretAgreement", .rva = 0x31480},
	{.name = "_string__43", .rva = 0x39640},
	{.name = "MSCryptDestroyDHKeyPair", .rva = 0x337a0},
	{.name = "GF2_mulk_multiplications", .rva = 0x19608},
	{.name = "__imp_RtlFreeHeap", .rva = 0x37040},
	{.name = "MSCryptGetKeyProperty", .rva = 0x283a0},
	{.name = "MSCryptDualEccRngTest", .rva = 0x31440},
	{.name = "Kiszeroer_default", .rva = 0x150d8},
	{.name = "ecaffine_set_infinite", .rva = 0x11e20},
	{.name = "MSCryptFIPS186DSAGen", .rva = 0x33c20},
	{.name = "_string__44", .rva = 0x3cee8},
	{.name = "MSCryptEncrypt", .rva = 0x2710},
	{.name = "ms_A_SHA", .rva = 0x22e94},
	{.name = "g_fUseRngLite", .rva = 0x46208},
	{.name = "g_hKsecDriver", .rva = 0x41228},
	{.name = "_string__45", .rva = 0x3ce18},
	{.name = "_string__46", .rva = 0x37230},
	{.name = "MSCryptDsaVerifySignature", .rva = 0x299b0},
	{.name = "QueryParameterList", .rva = 0x275a0},
	{.name = "_string__47", .rva = 0x3c908},
	{.name = "MSCryptEcDhTestPairWiseTable", .rva = 0x45310},
	{.name = "__imp_HeapAlloc", .rva = 0x37118},
	{.name = "MSCryptEcDhGetProperty", .rva = 0x31650},
	{.name = "add_full", .rva = 0xd6e4},
	{.name = "AesInvSboxMatrixMult", .rva = 0x3a400},
	{.name = "MSCryptRsaTestPairWiseTable", .rva = 0x41200},
	{.name = "div21_fast", .rva = 0xe870},
	{.name = "g_rgbQ", .rva = 0x3cad0},
	{.name = "MSCryptEccExportKeyPair", .rva = 0x2b330},
	{.name = "_string__48", .rva = 0x3bcb0},
	{.name = "SHA512Update", .rva = 0xa650},
	{.name = "RC2", .rva = 0x1b3e0},
	{.name = "ShutdownRNG", .rva = 0x10c10},
	{.name = "rc4", .rva = 0x3f10},
	{.name = "ms_A_SHAFinal", .rva = 0x22d98},
	{.name = "AesSbox", .rva = 0x37300},
	{.name = "__imp_SetLastError", .rva = 0x370c0},
	{.name = "DhMatchParameters", .rva = 0x277a0},
	{.name = "MSCryptDsaSetKeyPairProperty", .rva = 0x29da0},
	{.name = "random_mod", .rva = 0x16f20},
	{.name = "AesInvMatrixMult", .rva = 0x38400},
	{.name = "MSCryptEccOpenProvider", .rva = 0x2b720},
	{.name = "MSCryptGenerateSymmetricKey", .rva = 0x2930},
	{.name = "TestSha", .rva = 0x2d9e0},
	{.name = "AesInitialize", .rva = 0x1af80},
	{.name = "AesCreateDecryptionRoundKeyAsm", .rva = 0xf340},
	{.name = "PADDING", .rva = 0x3c710},
	{.name = "MSCryptGenerateRngState", .rva = 0x33dd0},
	{.name = "RC2KeyEx", .rva = 0x1b2f0},
	{.name = "InitializeRNG", .rva = 0x8c10},
	{.name = "$$VProc_ImageExportDirectory", .rva = 0x39788},
	{.name = "DSA_signature_verification", .rva = 0x20d9c},
	{.name = "BCryptOpenAlgorithmProvider", .rva = 0xc090},
	{.name = "rgbDh256PrivateKey_v", .rva = 0x43aa0},
	{.name = "validateMSCryptRsaKey", .rva = 0x27c70},
	{.name = "BCryptCreateHash", .rva = 0x1140c},
	{.name = "rgbAesCtrRngResult", .rva = 0x44be0},
	{.name = "__imp_SystemFunction041", .rva = 0x37158},
	{.name = "__imp_SystemFunction040", .rva = 0x37160},
	{.name = "AesCtrRng_Generate", .rva = 0x8f70},
	{.name = "AesCtrRng_Reseed", .rva = 0x2dd50},
	{.name = "GHashAppendDataXmm", .rva = 0x1e5e0},
	{.name = "tripledes", .rva = 0x9740},
	{.name = "RtlLookupFunctionEntry", .rva = 0x113b8},
	{.name = "MSCryptDecrypt", .rva = 0x2800},
	{.name = "MSCryptEccCloseProvider", .rva = 0x2b6d0},
	{.name = "validate_modular_data2a", .rva = 0x7870},
	{.name = "__imp_BCryptGetProperty", .rva = 0x37188},
	{.name = "MSCryptSetRsaProperty", .rva = 0xbd90},
	{.name = "mp_free_temp", .rva = 0x6630},
	{.name = "AesCtr_safe_startup", .rva = 0x10d70},
	{.name = "rgbAesCcmTag01", .rva = 0x44538},
	{.name = "rgbSha256KATAnswer", .rva = 0x44d88},
	{.name = "_string__49", .rva = 0x3c950},
	{.name = "fips186rng_dsa_destroy", .rva = 0x29100},
	{.name = "rgbAesGcmKey", .rva = 0x44c90},
	{.name = "MSCryptKDF_HMAC", .rva = 0x2fde0},
	{.name = "_string__50", .rva = 0x3ce50},
	{.name = "MSBlockEncrypt", .rva = 0x9e10},
	{.name = "NtTerminateProcess", .rva = 0x11390},
	{.name = "VerifyRsaPrivateBlob", .rva = 0xe2b0},
	{.name = "_string__51", .rva = 0x3b6b8},
	{.name = "MSCryptAesCtrGen", .rva = 0x8e80},
	{.name = "Kexponentiator1_default", .rva = 0x17640},
	{.name = "__imp_BCryptDestroyHash", .rva = 0x37198},
	{.name = "_string__52", .rva = 0x3b6d8},
	{.name = "AssignDomainParameters", .rva = 0x2ba10},
	{.name = "TestSymmetricAlgorithm", .rva = 0x2a620},
	{.name = "AesGmacUpdate", .rva = 0x1d290},
	{.name = "MSCryptEcDsaOpenProvider", .rva = 0x2e8e0},
	{.name = "MSCryptRsaPairWiseCheck", .rva = 0xcf00},
	{.name = "dblint_sqrt", .rva = 0x24754},
	{.name = "ec_useNIST", .rva = 0x11424},
	{.name = "BCryptHashData", .rva = 0x113f4},
	{.name = "add_mod", .rva = 0x4968},
	{.name = "SHA256Transform", .rva = 0x8090},
	{.name = "tripledes3key", .rva = 0x1b2a0},
	{.name = "DWORDtoByteCopy", .rva = 0x27560},
	{.name = "DhGenDhPrivKeyFromTemplate", .rva = 0x361c0},
	{.name = "mp_scrambled_store", .rva = 0x6d4c},
	{.name = "MSRngFunctionTable", .rva = 0x41080},
	{.name = "X931_keygen_free_arrays", .rva = 0x1e940},
	{.name = "TripleDesEcb", .rva = 0x281b0},
	{.name = "multiply_immediate", .rva = 0x4d34},
	{.name = "MSCryptAcquireRngState", .rva = 0x34420},
	{.name = "rsa_construction_X931", .rva = 0x1f470},
	{.name = "test_primality_check_low", .rva = 0x22500},
	{.name = "ApplyPSSPadding", .rva = 0x31760},
	{.name = "digits_to_endian_bytes", .rva = 0x4d7c},
	{.name = "_string__53", .rva = 0x3b6a0},
	{.name = "GF2_mod_mul_temps", .rva = 0x18034},
	{.name = "MSCryptDuplicateKey", .rva = 0x2a4c0},
	{.name = "MSCryptSetDHKeyPairProperty", .rva = 0x338d0},
	{.name = "ExportLittleModularDigitToBigDWORD", .rva = 0x29700},
	{.name = "_string__54", .rva = 0x3ce28},
	{.name = "MSBlockDecrypt", .rva = 0xa110},
	{.name = "AesGmacFinal", .rva = 0x1d3e0},
	{.name = "_string__55", .rva = 0x3ca38},
	{.name = "rgbSha256KAT", .rva = 0x44d80},
	{.name = "deskey", .rva = 0x1af90},
	{.name = "mp_shift", .rva = 0x16600},
	{.name = "__imp_NtQueryValueKey", .rva = 0x37048},
	{.name = "__imp_DeleteCriticalSection", .rva = 0x370c8},
	{.name = "_string__56", .rva = 0x3c938},
	{.name = "__security_check_cookie", .rva = 0x1000},
	{.name = "NewGenRandom", .rva = 0x30eb0},
	{.name = "sub_mod", .rva = 0x60c0},
	{.name = "digit_ogcd", .rva = 0x23bec},
	{.name = "mod_exp_multi", .rva = 0x233a0},
	{.name = "BenalohEstimateQuotient64", .rva = 0xf440},
	{.name = "MSCryptDsaGenerateKeyPair", .rva = 0x2cbb0},
	{.name = "_string__57", .rva = 0x395a0},
	{.name = "CheckSignaturePadding", .rva = 0xe080},
	{.name = "_string__58", .rva = 0x3b680},
	{.name = "rsa_export", .rva = 0xde28},
	{.name = "mod_mul", .rva = 0x778c},
	{.name = "BCryptFinishHash", .rva = 0x11400},
	{.name = "mp_scrambled_fetch", .rva = 0x6ca4},
	{.name = "PI_SUBST", .rva = 0x3c610},
	{.name = "DWORDToBigEndian", .rva = 0x1330},
	{.name = "rgbAesCcmKey01", .rva = 0x44c70},
	{.name = "_string__59", .rva = 0x3c8d8},
	{.name = "MSCryptEcDsaExportKeyPair", .rva = 0x2e710},
	{.name = "_string__60", .rva = 0x3cdc0},
	{.name = "Test_AesCtrRng_Reseed", .rva = 0x30ae0},
	{.name = "MSCryptEcDsaDestroyKeyPair", .rva = 0x31680},
	{.name = "_Add", .rva = 0x24950},
	{.name = "rgbAesGcmTag", .rva = 0x44cb8},
	{.name = "tripledes2key", .rva = 0x1b250},
	{.name = "MSCryptExportKeyPair", .rva = 0xdcc0},
	{.name = "rsa_encryption", .rva = 0x644c},
	{.name = "ecdsa_key_pair", .rva = 0x143b0},
	{.name = "rgbDhpartyVInfo", .rva = 0x43ea8},
	{.name = "MSCryptSetEcRngProperty", .rva = 0x33e10},
	{.name = "MSCryptEccFinalizeKeyPair", .rva = 0x2f230},
	{.name = "MyPrimitiveSHA", .rva = 0x276f0},
	{.name = "rgbDhpartyUInfo", .rva = 0x43a98},
	{.name = "MSCryptRsaSignHash", .rva = 0xd240},
	{.name = "ecaffine_is_infinite", .rva = 0x11aec},
	{.name = "__imp_GetProcessHeap", .rva = 0x37108},
	{.name = "Reduce", .rva = 0xf3c0},
	{.name = "_string__61", .rva = 0x3cf70},
	{.name = "__chkstk", .rva = 0x248e8},
	{.name = "neg_mod", .rva = 0x119c0},
	{.name = "MSCryptEccGetAlgProperty", .rva = 0x2b230},
	{.name = "AesCpuFamilyLockedOut", .rva = 0x1af10},
	{.name = "RandomFillBuffer", .rva = 0x9480},
	{.name = "mp_alloc_temp", .rva = 0x4210},
	{.name = "rsa_allocate_fields", .rva = 0x46f4},
	{.name = "_string__62", .rva = 0x3d048},
	{.name = "mp_invert", .rva = 0x170f0},
	{.name = "MSCryptSetDHProperty", .rva = 0x34180},
	{.name = "MSCryptKDF_HASH", .rva = 0x2fe30},
	{.name = "GF2_irreducible", .rva = 0x18378},
	{.name = "ms_A_SHAUpdate", .rva = 0x22c2c},
	{.name = "add_same", .rva = 0x6b20},
	{.name = "DesCfb", .rva = 0x27ec0},
	{.name = "MSCryptEcDhFinalizeKeyPair", .rva = 0x33fb0},
	{.name = "AesCfb", .rva = 0x27f10},
	{.name = "FE2IP", .rva = 0x14280},
	{.name = "MSCryptEccGenerateKeyPair", .rva = 0x316f0},
	{.name = "MsProviderStart", .rva = 0x10d00},
	{.name = "MSDsaSignFunctionTable", .rva = 0x44310},
	{.name = "MapBignumErrnoToStatus", .rva = 0x28a60},
	{.name = "AesEncrypt", .rva = 0x1b70},
	{.name = "Fips186_3GenEccPrivExpon", .rva = 0x2b8b0},
	{.name = "TestAes", .rva = 0x2d410},
	{.name = "__ecprojective_add_helper", .rva = 0x12eb4},
	{.name = "__imp_wcscpy_s", .rva = 0x37060},
	{.name = "ImportDHKeyPairWithCheck", .rva = 0x35b90},
	{.name = "_string__63", .rva = 0x3cd60},
	{.name = "AesFastBlock", .rva = 0x27d90},
	{.name = "MSCryptSetAlgProperty", .rva = 0xe690},
	{.name = "endian_bytes_to_digits", .rva = 0x40f0},
	{.name = "rgbRsa2048PrivateKey", .rva = 0x447a0},
	{.name = "Kmulsub", .rva = 0x167e0},
	{.name = "Kequaler_default", .rva = 0x14fdc},
	{.name = "MSCryptDsaFinalizeKeyPair", .rva = 0x35240},
	{.name = "compare_same", .rva = 0x4aac},
	{.name = "ecprojective_affinize", .rva = 0x12224},
	{.name = "rgbEcDhPrivKey256_s", .rva = 0x450f0},
	{.name = "_string__64", .rva = 0x39750},
	{.name = "rgbEcDhPrivKey256_e", .rva = 0x45160},
	{.name = "_string__65", .rva = 0x3c9c8},
	{.name = "MSCryptDsaGetAlgProperty", .rva = 0x2a0d0},
	{.name = "MSCryptEcDsaCloseProvider", .rva = 0x2e8c0},
	{.name = "LookupHashFunction", .rva = 0x7e20},
	{.name = "MSCryptSetRngProperty", .rva = 0x341e0},
	{.name = "MSCryptSetProperty", .rva = 0xe640},
	{.name = "LookupCipherFunction", .rva = 0xe5f0},
	{.name = "MSCryptSetHashProperty", .rva = 0x2a420},
	{.name = "Kinitialize_prime", .rva = 0x163d8},
	{.name = "MSCryptDhTestPairWiseTable", .rva = 0x44768},
	{.name = "GF2_poly_inverse", .rva = 0x1823c},
	{.name = "__imp_BCryptOpenAlgorithmProvider", .rva = 0x37190},
	{.name = "_string__66", .rva = 0x3c988},
	{.name = "significant_bit_count", .rva = 0x4298},
	{.name = "AesCbc", .rva = 0xa6d0},
	{.name = "MSCryptRsaEncrypt", .rva = 0x68a0},
	{.name = "DesCbc", .rva = 0x280a0},
	{.name = "P_Hash", .rva = 0x2fe80},
	{.name = "__imp_NtClose", .rva = 0x37050},
	{.name = "ReverseMemCopy", .rva = 0x28a30},
	{.name = "StringCchPrintfW", .rva = 0x289f0},
	{.name = "GF2_extended_GCD", .rva = 0x179b4},
	{.name = "__imp_RtlLookupFunctionEntry", .rva = 0x37070},
	{.name = "__imp_BCryptGenRandom", .rva = 0x37178},
	{.name = "BCryptAlloc", .rva = 0x2a6f0},
	{.name = "CheckEncryptionPadding", .rva = 0x72e0},
	{.name = "AesDecrypt", .rva = 0xed70},
	{.name = "SystemFunction040", .rva = 0x1e744},
	{.name = "SystemFunction041", .rva = 0x1e750},
	{.name = "_string__67", .rva = 0x371e8},
	{.name = "double_shift", .rva = 0x3c5f0},
	{.name = "SHA512Transform", .rva = 0xb000},
	{.name = "DualEcRng_Reseed", .rva = 0x2dfc0},
	{.name = "__imp_VirtualAlloc", .rva = 0x37140},
	{.name = "fips186Add", .rva = 0x274e0},
	{.name = "Kfdesc_initialize", .rva = 0x14c64},
	{.name = "Generate_PrivateKey", .rva = 0x2c700},
	{.name = "divide", .rva = 0x6ee0},
	{.name = "validateMSCryptRsaAlgorithm", .rva = 0x27c90},
	{.name = "MSCryptKDF_TLS_PRF", .rva = 0x34b10},
	{.name = "Kmuladd", .rva = 0x166e4},
	{.name = "MSCryptCloseRngProvider", .rva = 0x306c0},
	{.name = "Test_DualEcRng_Instantiate", .rva = 0x312d0},
	{.name = "uncreate_modulus", .rva = 0x65f4},
	{.name = "_string__68", .rva = 0x3d058},
	{.name = "__imp_VirtualQuery", .rva = 0x37148},
	{.name = "MSCryptEcDhGenerateKeyPair", .rva = 0x33460},
	{.name = "__imp_RtlVirtualUnwind", .rva = 0x37078},
	{.name = "BASE_GENERATE_RNG_STATE", .rva = 0x8d10},
	{.name = "mod_mul_immediate", .rva = 0x22f48},
	{.name = "ApplyOAEPPadding", .rva = 0x317b0},
	{.name = "rgbAesGcmCiphertext", .rva = 0x44cb4},
	{.name = "_string__69", .rva = 0x3cc70},
	{.name = "mod_shift", .rva = 0x510c},
	{.name = "memcmp", .rva = 0x1640},
	{.name = "sub_same", .rva = 0x5260},
	{.name = "dwg_ceil_divide", .rva = 0x16500},
	{.name = "Kmulsubfrom", .rva = 0x168e0},
	{.name = "rgbAES_IV", .rva = 0x44c50},
	{.name = "multiply", .rva = 0x76a0},
	{.name = "modmul_choices1", .rva = 0x5fa8},
	{.name = "MSCryptEcDsaFinalizeKeyPair", .rva = 0x31690},
	{.name = "DualEcRng_Hash_df_Buffers", .rva = 0x2a9a0},
	{.name = "ecaffine_on_curve", .rva = 0x11ba0},
	{.name = "random_mod_inverse", .rva = 0x23000},
	{.name = "g_ulMaxStackAllocSize", .rva = 0x46250},
	{.name = "MSRsaSignatureFunctionTable", .rva = 0x411a0},
	{.name = "AesEcb", .rva = 0x27cf0},
	{.name = "DesEcb", .rva = 0x28290},
	{.name = "OS2IP", .rva = 0x1432c},
	{.name = "mp_gcdex", .rva = 0xc840},
	{.name = "AesCtrRng_Uninstantiate", .rva = 0x7b30},
	{.name = "rgbAesCcmPlaintext01", .rva = 0x442cc},
	{.name = "MSCryptGenerateDHKeyPair", .rva = 0x2c410},
	{.name = "rsa_import", .rva = 0x4504},
	{.name = "HotPatchBuffer", .rva = 0x436f0},
	{.name = "__imp_RtlImageNtHeader", .rva = 0x37008},
	{.name = "MSCryptDestroyKeyPair", .rva = 0x6740},
	{.name = "ecprojective_double", .rva = 0x126b8},
	{.name = "__imp_RtlUnhandledExceptionFilter", .rva = 0x37080},
	{.name = "AesCcmComputeUnencryptedTag", .rva = 0x1e0a0},
	{.name = "mod_exp2006", .rva = 0x5528},
	{.name = "__imp_memcpy", .rva = 0x37018},
	{.name = "mp_invert_ntemps", .rva = 0x170dc},
	{.name = "MSCryptEcDsaImportKeyPair", .rva = 0x33480},
	{.name = "CryptAuditTranslateString", .rva = 0x2a8c0},
	{.name = "g_pAuditingFuncs", .rva = 0x46210},
	{.name = "mp_gcd", .rva = 0x217d8},
	{.name = "fips186rng_gen_block", .rva = 0x28f00},
	{.name = "GatherRandomKeyFastUserMode", .rva = 0x8c90},
	{.name = "IsModulusCreated", .rva = 0x32310},
	{.name = "BCryptGetFipsAlgorithmMode", .rva = 0x11418},
	{.name = "ecprojective_affinize_many_in_place", .rva = 0x123c8},
	{.name = "ApplySignaturePadding", .rva = 0xd3c0},
	{.name = "rgbAESKnownPlaintext", .rva = 0x44c20},
	{.name = "MSCryptEccGetKeyProperty", .rva = 0x2b0f0},
	{.name = "digit_sqrt", .rva = 0x24720},
	{.name = "estimated_quotient_1", .rva = 0x5058},
	{.name = "_string__70", .rva = 0x3c920},
	{.name = "rgbSha512KATAnswer", .rva = 0x44db0},
	{.name = "__security_cookie", .rva = 0x41008},
	{.name = "low_prime_divisibility", .rva = 0x21638},
	{.name = "g_pfnAllocate", .rva = 0x46260},
	{.name = "MSCryptGetDHKeyPairProperty", .rva = 0x32220},
	{.name = "mp_population_count", .rva = 0x4b20},
	{.name = "CFB_Ex", .rva = 0x1e410},
	{.name = "_string__71", .rva = 0x396b0},
	{.name = "BASE_FREE_RNG_STATE", .rva = 0x7ac0},
	{.name = "validateMSCryptSymmKey", .rva = 0x28470},
	{.name = "to_modular", .rva = 0x53a0},
	{.name = "Kfree", .rva = 0x14d70},
	{.name = "DualEcRng_Instantiate", .rva = 0x2e2d0},
	{.name = "_string__72", .rva = 0x396f0},
	{.name = "__imp_CloseHandle", .rva = 0x370d0},
	{.name = "AesUseXmm", .rva = 0x410b0},
	{.name = "rsa_destruction", .rva = 0x67f4},
	{.name = "random_digit_interval", .rva = 0x16da0},
	{.name = "TransformMD5", .rva = 0x1df0},
	{.name = "CheckPSSPadding", .rva = 0x2f420},
	{.name = "MSCryptDestroyKey", .rva = 0x28f0},
	{.name = "_string__73", .rva = 0x3bb80},
	{.name = "mp_remove2", .rva = 0x242b4},
	{.name = "algorithmID", .rva = 0x45018},
	{.name = "DSA_unbuild_fullkey", .rva = 0x212f4},
	{.name = "validateMSCryptRngHandle", .rva = 0x285e0},
	{.name = "MSDHSecretAgreementTable", .rva = 0x43a30},
	{.name = "MSCryptEcDhImportKeyPair", .rva = 0x33f30},
	{.name = "ValidateEccAlgorithm", .rva = 0x28c60},
	{.name = "rgbAesCcmNonce01", .rva = 0x44c88},
	{.name = "IsSelfTestEnabled", .rva = 0x10e60},
	{.name = "Test_AesCtrRng_Instantiate", .rva = 0x30db0},
	{.name = "MSCryptEccDestroyKeyPair", .rva = 0x2ea90},
	{.name = "__imp__vsnwprintf", .rva = 0x37030},
	{.name = "_string__74", .rva = 0x3cd28},
	{.name = "create_modulus", .rva = 0x5cac},
	{.name = "rgbEcDhPrivKey256_for_pairwise", .rva = 0x44fb0},
	{.name = "MSCryptGetEcRngProperty", .rva = 0x28b00},
	{.name = "GHashExpandKeyC", .rva = 0x1e550},
	{.name = "AesSboxMatrixMult", .rva = 0x37400},
	{.name = "ValidateDSAAlgorithm", .rva = 0x27bf0},
	{.name = "random_mod_nonzero", .rva = 0x1701c},
	{.name = "rgbSha512KAT", .rva = 0x44da8},
	{.name = "mp_trailing_zero_count", .rva = 0x16568},
	{.name = "MyPrimitiveHMACParam", .rva = 0x29320},
	{.name = "__security_init_cookie", .rva = 0x11348},
	{.name = "_string__75", .rva = 0x37208},
	{.name = "MSCryptCloseDHProvider", .rva = 0x2c4e0},
	{.name = "MSCryptOpenSymmetricProvider", .rva = 0xbe50},
	{.name = "__imp___chkstk", .rva = 0x37098},
	{.name = "__imp_BCryptFinishHash", .rva = 0x37170},
	{.name = "_string__76", .rva = 0x3c898},
	{.name = "MSCryptFinalizeDHKeyPair", .rva = 0x36040},
	{.name = "MSCryptEcDsaGenerateKeyPair", .rva = 0x33500},
	{.name = "_string__77", .rva = 0x39420},
	{.name = "MSECDHSecretAgreementTable", .rva = 0x45080},
	{.name = "MSCryptGetDHProperty", .rva = 0x33b30},
	{.name = "g_pfnFree", .rva = 0x46268},
	{.name = "mod_mul_no_range_checks", .rva = 0x5bb0},
	{.name = "rgbAesGcmNonce", .rva = 0x44ca8},
	{.name = "rgb3DESKnownPlaintext", .rva = 0x44b80},
	{.name = "VerifyPKCS1SigningFormat", .rva = 0xe340},
	{.name = "__imp_memmove", .rva = 0x37010},
	{.name = "_string__78", .rva = 0x3cf48},
	{.name = "_string__79", .rva = 0x3c8f0},
	{.name = "HMACSHAFinal", .rva = 0x1cf60},
	{.name = "MD2Final", .rva = 0x1d810},
	{.name = "validateAuthCipherModeInfo", .rva = 0x27cb0},
	{.name = "DualEcRng_Generate_Block", .rva = 0x2e040},
	{.name = "CheckIfNeedToCalculateDsaPublicKey", .rva = 0x27970},
	{.name = "TestEncDec", .rva = 0x284f0},
	{.name = "__imp_NtOpenKey", .rva = 0x37028},
	{.name = "Validate_Modulus", .rva = 0x29960},
	{.name = "BaseAlgorithmCheck", .rva = 0x328f0},
	{.name = "TripleDesCfb", .rva = 0x27e20},
	{.name = "AesCtr_safe_shutdown", .rva = 0x10ba0},
	{.name = "_string__80", .rva = 0x39678},
	{.name = "RtlVirtualUnwind", .rva = 0x113ac},
	{.name = "_string__81", .rva = 0x3c9e0},
	{.name = "CheckOAEPPadding", .rva = 0x2f8c0},
	{.name = "_string__82", .rva = 0x3c8d0},
	{.name = "MSCryptGetAlgProperty", .rva = 0xaa90},
	{.name = "MSCryptDuplicateHash", .rva = 0x3de0},
	{.name = "Add64", .rva = 0xf540},
	{.name = "ValidateEccObject", .rva = 0x28cf0},
	{.name = "MSCryptOpenEcRngProvider", .rva = 0x2abe0},
	{.name = "mp_mul22u", .rva = 0xe9c0},
	{.name = "mp_mul22s", .rva = 0xc1ac},
	{.name = "MSCryptDsaDestroyKeyPair", .rva = 0x30340},
	{.name = "__report_gsfailure", .rva = 0x11204},
	{.name = "MSCryptCreateHash", .rva = 0x11d0},
	{.name = "ApplyEncryptionPadding", .rva = 0x6a20},
	{.name = "ECC_FREE_RNG_STATE", .rva = 0x2aca0},
	{.name = "GetCipherInterface", .rva = 0xe5b0},
	{.name = "__imp_NtOpenFile", .rva = 0x37000},
	{.name = "MD5Final", .rva = 0x2590},
	{.name = "__imp_LeaveCriticalSection", .rva = 0x37100},
	{.name = "fips186rng_dsa_init", .rva = 0x29210},
	{.name = "MSCryptGetRsaSignProperty", .rva = 0x2cfe0},
	{.name = "MSCryptKDF_SP800_56A", .rva = 0x33520},
	{.name = "rsa_crt_constants", .rva = 0xdc10},
	{.name = "MD4Final", .rva = 0x1df80},
	{.name = "_string__83", .rva = 0x3ce38},
	{.name = "ImportBigDWORDToLittleModularDigit", .rva = 0x29810},
	{.name = "MSCryptGetRngProperty", .rva = 0x2a530},
	{.name = "mp_sqrt", .rva = 0x2435c},
	{.name = "MSCryptGetProperty", .rva = 0xa480},
	{.name = "SafeAllocaInitialize", .rva = 0x10c50},
	{.name = "Reduce64", .rva = 0xf4e0},
	{.name = "_string__84", .rva = 0x39670},
	{.name = "MSCryptGetHashProperty", .rva = 0x7b70},
	{.name = "IsDsaKeyPrivate", .rva = 0x279c0},
	{.name = "DESParityTable", .rva = 0x3c600},
	{.name = "_string__85", .rva = 0x3b710},
	{.name = "_string__86", .rva = 0x396c0},
	{.name = "ValidateDHKey", .rva = 0x302a0},
	{.name = "InternalVerifyStackAvailable", .rva = 0x28880},
	{.name = "Sub64", .rva = 0xf590},
	{.name = "MSCryptExportDHKeyPair", .rva = 0x31e40},
	{.name = "_string__87", .rva = 0x3cfb0},
	{.name = "ecaffine_exp_multi_via_projective", .rva = 0x13810},
	{.name = "MD2Update", .rva = 0x1d750},
	{.name = "HMACSHAUpdate", .rva = 0x1cf50},
	{.name = "_string__88", .rva = 0x3cf90},
	{.name = "_string__89", .rva = 0x395e0},
	{.name = "SafeAllocaAllocateFromHeap", .rva = 0x2a6f0},
	{.name = "wcscpy_s", .rva = 0x113d0},
	{.name = "MD5Update", .rva = 0x2640},
	{.name = "rgSymmAlgorithmDefaults", .rva = 0x42600},
	{.name = "mp_shift_lost", .rva = 0x4f94},
	{.name = "AesCbcDecrypt", .rva = 0xa7a0},
	{.name = "AesDetectXmmDone", .rva = 0x410b4},
	{.name = "_Sub", .rva = 0x24900},
	{.name = "_string__90", .rva = 0x3c8b0},
	{.name = "MD4Update", .rva = 0x1de20},
	{.name = "MSCryptImportKey", .rva = 0x110e0},
	{.name = "__imp_TlsFree", .rva = 0x370f0},
	{.name = "Test_DualEcRng_Reseed", .rva = 0x31150},
	{.name = "MSCryptEcDsaTestPairWiseTable", .rva = 0x452f0},
	{.name = "PairwiseConsistencySignature", .rva = 0x2e750},
	{.name = "rgbDsaRNGResult", .rva = 0x44c08},
	{.name = "MSCryptAuditPrimitiveFailure", .rva = 0x2dec0},
	{.name = "_string__91", .rva = 0x3bb90},
	{.name = "MSCryptEcDhCloseProvider", .rva = 0x2e6c0},
	{.name = "BCryptFree", .rva = 0x2a910},
	{.name = "DSA_sign", .rva = 0x20a70},
	{.name = "Ksizer_2", .rva = 0x15248},
	{.name = "rgbDhalgorithmID", .rva = 0x43a28},
	{.name = "MSCryptDsaSignHash", .rva = 0x29ba0},
	{.name = "Krandomizer_2", .rva = 0x15180},
	{.name = "ApplyPKCS1SigningFormat", .rva = 0xe460},
	{.name = "rc4_key", .rva = 0x3f70},
	{.name = "MSCryptDualEcGen", .rva = 0x32d80},
	{.name = "_DllMainCRTStartupForGS2", .rva = 0x111e4},
	{.name = "TripleDesCbc", .rva = 0x9bd0},
	{.name = "MSCryptCloseSymmetricProvider", .rva = 0x2d3c0},
	{.name = "ec_free", .rva = 0x11eb0},
	{.name = "MSCryptDHSP80056AConCatKDFTest", .rva = 0x34d20},
	{.name = "_string__92", .rva = 0x3cef8},
	{.name = "MSCryptOpenHashProvider", .rva = 0x7d30},
	{.name = "memset", .rva = 0x1324},
	{.name = "GetSecretAgreementInterface", .rva = 0x28e40},
	{.name = "ULongLongMult", .rva = 0x28d30},
	{.name = "BCryptDestroyHash", .rva = 0x113e8},
	{.name = "rgbAesGcmPlaintext", .rva = 0x44c1c},

};
static uint64_t win7_sp1_x64_bcryptprimitives_count = 815;