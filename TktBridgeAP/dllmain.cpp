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
