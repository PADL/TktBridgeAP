/*++

Copyright (c) PADL Software Pty Ltd, All rights reserved.

Module Name:

    tracing.cpp

Abstract:

    Tracing functions

Environment:

    Local Security Authority (LSA)

--*/

#include "TktBridgeAP.h"

static __inline PCWSTR
DebugTraceLevelString(UCHAR Level)
{
    static PCWSTR rgwszLevels[] = {
        L"LogAlways",
        L"Critical",
        L"Error",
        L"Warning",
        L"Info",
        L"Verbose",
    };

    if (Level >= sizeof(rgwszLevels) / sizeof(rgwszLevels[0]))
        return L"Unknown";
    else
        return rgwszLevels[Level];
}

VOID
__cdecl DebugTrace(UCHAR Level, PCWSTR wszFormat, ...)
{
    if (APFlags & TKTBRIDGEAP_FLAG_DEBUG) {
        WCHAR TraceMsg[BUFSIZ] = L"";
        va_list ap;
        SIZE_T cchDebugPrefix;
        EVENT_DESCRIPTOR EventDescriptor = { 0 };

        StringCchPrintfW(TraceMsg, BUFSIZ - 1,
            L"%d.%d> TktBridgeAP-%s: ",
            GetCurrentProcessId(), GetCurrentThreadId(),
            DebugTraceLevelString(Level));
        cchDebugPrefix = wcslen(TraceMsg);

        va_start(ap, wszFormat);
        StringCchVPrintfW(&TraceMsg[cchDebugPrefix],
            BUFSIZ - cchDebugPrefix - 1,
            wszFormat, ap);
        va_end(ap);

        EventDescriptor.Level = Level;
        EventDescriptor.Keyword = (ULONGLONG)0;

        if (APFlags & TKTBRIDGEAP_FLAG_DEBUG) {
            OutputDebugStringW(TraceMsg);
            OutputDebugStringW(L"\r\n");
        }

#ifndef NDEBUG
        auto hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD dwWritten;
        if (hOut) {
            WriteConsole(hOut, TraceMsg, wcslen(TraceMsg), &dwWritten, NULL);
            WriteConsole(hOut, L"\r\n", 2, &dwWritten, NULL);
            CloseHandle(hOut);
        }
#endif
    }
}



static VOID KRB5_CALLCONV
HeimLogLogCB(krb5_context KrbContext,
    PCSTR pszPrefix,
    PCSTR pszMessage,
    PVOID Context)
{
    DebugTrace(WINEVENT_LEVEL_VERBOSE, L"%s: %s", pszPrefix, pszMessage);
}

static VOID KRB5_CALLCONV
HeimLogCloseCB(PVOID Context)
{
}

krb5_error_code
HeimTracingInit(krb5_context KrbContext)
{
    krb5_error_code KrbError;

    KrbError = krb5_addlog_func(KrbContext,
        nullptr,
        0,
        APLogLevel,
        HeimLogLogCB,
        HeimLogCloseCB,
        nullptr);


    return KrbError;
}
