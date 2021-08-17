#include "TktBridgeAP.h"

// remove this file when complete

#ifndef NDEBUG

static void
TktBridgeAPTestFunction()
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
				       &SecStatus,
				       &AsRep,
				       &AsReplyKey);

    DebugTrace(WINEVENT_LEVEL_INFO, L"Get init creds: KrbError %d SecStatus %08x", KrbError, SecStatus);
}

extern "C"
TKTBRIDGEAP_API
VOID __cdecl EntryPoint(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_CHECK_ALWAYS_DF | _CRTDBG_LEAK_CHECK_DF);

    AllocConsole();

    APFlags |= TKTBRIDGEAP_FLAG_DEBUG;
    APLogLevel = 10;

    DebugTrace(WINEVENT_LEVEL_INFO, L"Starting TktBridgeAP test harness...");

    //TktBridgeAPTestFunction();
    _CrtDumpMemoryLeaks();

    DebugTrace(WINEVENT_LEVEL_INFO, L"Finished TktBridgeAP test harness, press any key to exit.");

    auto hIn = GetStdHandle(STD_INPUT_HANDLE);
    TCHAR buffer[2];
    DWORD dwLength = 1;
    DWORD dwRead = 0;

    ReadConsole(hIn, buffer, dwLength, &dwRead, NULL);
    CloseHandle(hIn);

    FreeConsole();
}
#endif