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
__cdecl DebugTrace(_In_ UCHAR Level, _In_z_ PCWSTR wszFormat, ...)
{
    if (EventProviderId_Context.IsEnabled ||
        (APFlags & TKTBRIDGEAP_FLAG_DEBUG)) {
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

        if (MCGEN_ENABLE_CHECK(EventProviderId_Context, EventDescriptor)) {
            EventWriteString(PADL_TktBridgeAPHandle, Level, 0, TraceMsg);
        }

        if (APFlags & TKTBRIDGEAP_FLAG_DEBUG) {
            OutputDebugStringW(TraceMsg);
            OutputDebugStringW(L"\r\n");
        }
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

static thread_local krb5_log_facility *HeimLogFacility;

krb5_error_code
HeimTracingInit(_In_ krb5_context KrbContext)
{
    krb5_error_code KrbError;

    if (HeimLogFacility == nullptr) {
        KrbError = krb5_openlog(KrbContext, "TktBridgeAP", &HeimLogFacility);
        if (KrbError != 0)
            return KrbError;
    }

    krb5_set_warn_dest(KrbContext, HeimLogFacility);
    krb5_set_log_dest(KrbContext, HeimLogFacility);
    //krb5_set_debug_dest(KrbContext, "TktBridgeAP", "STDERR");

    KrbError = krb5_addlog_func(KrbContext,
                                HeimLogFacility,
                                0,
                                APLogLevel,
                                HeimLogLogCB,
                                HeimLogCloseCB,
                                nullptr);

    return KrbError;
}
