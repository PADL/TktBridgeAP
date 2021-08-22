/*++

Copyright (c) PADL Software Pty Ltd, All rights reserved.

Module Name:

    testing.cpp

Abstract:

    Testing functions

Environment:

    Local Security Authority (LSA)

--*/

#include "TktBridgeAP.h"

// remove this file when complete

#ifndef NDEBUG

static void
TktBridgeAPTestFunction1()
{
    krb5_error_code KrbError;
    PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity = nullptr;

    PWSTR ClientName = nullptr;
    LARGE_INTEGER ExpiryTime = { .QuadPart = 0 };
    SECURITY_STATUS SecStatus;
    krb5_data AsRep;
    krb5_keyblock AsReplyKey;

    SecStatus = SEC_E_NO_CONTEXT;
    krb5_data_zero(&AsRep);
    ZeroMemory(&AsReplyKey, sizeof(AsReplyKey));

    SecStatus = SspiEncodeStringsAsAuthIdentity(L"moonshot",
						L"AAA.PADL.COM",
						L"moonshot",
						&AuthIdentity);
    if (SecStatus != SEC_E_OK) {
	DebugTrace(WINEVENT_LEVEL_ERROR, L"Failed to encode auth identity: %08x", SecStatus);
	return;
    }

    KrbError = SspiPreauthGetInitCreds(L"KERB.PADL.COM",
				       nullptr,
				       L"tktbridge.kerb.padl.com",
				       nullptr,
				       AuthIdentity,
				       &ClientName,
				       &ExpiryTime,
				       &AsRep,
				       &AsReplyKey,
				       &SecStatus);

    DebugTrace(WINEVENT_LEVEL_INFO, L"Get init creds: KrbError %d SecStatus %08x Length %d Key %d/%d",
	       KrbError, SecStatus, AsRep.length,
	       AsReplyKey.keytype, AsReplyKey.keyvalue.length);

    krb5_data_free(&AsRep);
    krb5_free_keyblock_contents(NULL, &AsReplyKey);
    SspiFreeAuthIdentity(AuthIdentity);
}

static void
TktBridgeAPTestFunction2()
{
    UNICODE_STRING foo;

    RtlInitUnicodeString(&foo, nullptr);
    RtlFreeUnicodeString(&foo);

    SspiFreeAuthIdentity(nullptr);
    FreeContextBuffer(nullptr);


    {
	//
	// temporary stack-based storage for an SID
	//
	UCHAR sidBuffer[128];
	PISID localSid = (PISID)sidBuffer;
	SID_IDENTIFIER_AUTHORITY localSidAuthority =
	    SECURITY_NT_AUTHORITY;

	//
	// build the local system SID
	//
	RtlZeroMemory(sidBuffer, sizeof(sidBuffer));

	localSid->Revision = SID_REVISION;
	localSid->SubAuthorityCount = 1;
	localSid->IdentifierAuthority = localSidAuthority;
	localSid->SubAuthority[0] = SECURITY_LOCAL_SYSTEM_RID;
	assert(IsValidSid(localSid));

	PSID sid = nullptr;
	auto Status = RtlDuplicateSid(&sid, localSid);
	assert(NT_SUCCESS(Status));

    }

    UNICODE_STRING bar;

    RtlInitUnicodeString(&foo, L"Hello");
    RtlInitUnicodeString(&bar, NULL);

    auto Status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE, &foo, &bar);
    assert(NT_SUCCESS(Status));

    _wcsupr_s(bar.Buffer, bar.MaximumLength / 2);

    DebugTrace(WINEVENT_LEVEL_VERBOSE, L"uppercased string %s -> %s", foo.Buffer, bar.Buffer);

    RtlFreeUnicodeString(&bar);

}

static DWORD
TktBridgeAPTestFunction3()
{
    DWORD dwResult;
    wil::unique_hkey hKey;

    dwResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TKTBRIDGEAP_REGISTRY_KEY_W,
			    0, KEY_QUERY_VALUE, &hKey);
    RETURN_IF_WIN32_ERROR_EXPECTED(dwResult);

    APFlags &= ~(TKTBRIDGEAP_FLAG_USER);
    APFlags |= RegistryGetDWordValueForKey(hKey.get(), L"Flags") & TKTBRIDGEAP_FLAG_USER;
#ifndef NDEBUG
    APFlags |= TKTBRIDGEAP_FLAG_DEBUG;
#endif

    APLogLevel = RegistryGetDWordValueForKey(hKey.get(), L"LogLevel");

    WIL_FreeMemory(APKdcHostName);
    APKdcHostName = RegistryGetStringValueForKey(hKey.get(), L"KdcHostName");

    WIL_FreeMemory(APRestrictPackage);
    APRestrictPackage = RegistryGetStringValueForKey(hKey.get(), L"RestrictPackage");

    DebugTrace(WINEVENT_LEVEL_VERBOSE, L"Flags %08x Level %08x Kdc %s Restrict %s",
	       APFlags, APLogLevel, APKdcHostName, APRestrictPackage);

    return ERROR_SUCCESS;
}

extern "C"
TKTBRIDGEAP_API
VOID __cdecl TestEntryPoint(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_CHECK_ALWAYS_DF | _CRTDBG_LEAK_CHECK_DF);

    AllocConsole();

    APFlags |= TKTBRIDGEAP_FLAG_DEBUG;
    APLogLevel = 10;

    DebugTrace(WINEVENT_LEVEL_INFO, L"Starting TktBridgeAP test harness...");

    TktBridgeAPTestFunction1();
    TktBridgeAPTestFunction2();
    TktBridgeAPTestFunction3();
 
    FreeConsole();
}

#endif /* !NDEBUG */