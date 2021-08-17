/*++

Copyright (c) PADL Software Pty Ltd, All rights reserved.

Module Name:

    dllmain.cpp

Abstract:

    Ticket Bridge Authentication Provider (AP)

Environment:

    Local Security Authority (LSA)

--*/

#include "TktBridgeAP.h"

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}

#ifndef NDEBUG
extern "C"
TKTBRIDGEAP_API
VOID __cdecl EntryPoint(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
    AllocConsole();
 
    APFlags |= TKTBRIDGEAP_FLAG_DEBUG;

    auto hIn = GetStdHandle(STD_INPUT_HANDLE);

    DebugTrace(WINEVENT_LEVEL_INFO, L"Starting TktBridgeAP test");

    TCHAR buffer[1024];
    DWORD dwLength = 1;
    DWORD dwRead = 0;

    ReadConsole(hIn, buffer, dwLength, &dwRead, NULL);
    CloseHandle(hIn);

    FreeConsole();
}
#endif