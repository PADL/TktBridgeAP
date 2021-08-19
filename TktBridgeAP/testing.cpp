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
    SECURITY_STATUS SecStatus;
    krb5_data AsRep;
    krb5_keyblock AsReplyKey;

    SecStatus = SEC_E_NO_CONTEXT;
    krb5_data_zero(&AsRep);
    ZeroMemory(&AsReplyKey, sizeof(AsReplyKey));

    SecStatus = SspiEncodeStringsAsAuthIdentity(L"lukeh",
						L"AAA.PADL.COM",
						L"foo",
						&AuthIdentity);
    if (SecStatus != SEC_E_OK) {
	DebugTrace(WINEVENT_LEVEL_ERROR, L"Failed to encode auth identity: %08x", SecStatus);
	return;
    }

    KrbError = SspiPreauthGetInitCreds(L"LUKKTONE.COM",
				       nullptr,
				       L"rand.lukktone.com:888",
				       nullptr,
				       AuthIdentity,
				       &ClientName,
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

    PSID sid = nullptr;
    RtlFreeSid(sid);
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
 
    FreeConsole();
}
#endif