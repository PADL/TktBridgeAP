/*
 * Copyright (c) 2021, PADL Software Pty Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of PADL Software nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL PADL SOFTWARE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#pragma once

#ifndef NDEBUG
#define _CRTDBG_MAP_ALLOC 1
#endif

#ifdef TKTBRIDGEAP_EXPORTS
#define TKTBRIDGEAP_API __declspec(dllexport)
#else
#define TKTBRIDGEAP_API __declspec(dllimport)
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif

#ifndef _SEC_WINNT_AUTH_TYPES
#define _SEC_WINNT_AUTH_TYPES
#endif

#include <strsafe.h>
#include <crtdbg.h>
#include <assert.h>

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <Windows.h>
#include <winternl.h>
#include <wincred.h>
#include <LM.h>
#include <Tracelogging.h>
#include <evntprov.h>
#include <sspi.h>
#define _NTDEF_
#include <NTSecAPI.h>
#undef _NTDEF_
#include <NTSecPkg.h>
#include <security.h>
#include <DsGetDC.h>
#include <wincrypt.h>
#include <wincred.h>

#include "ntapiext.h"
#include "KerbPrivate.h"

#include <stl.h>

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>

#include <wil/common.h>
#include <wil/resource.h>
#include <wil/win32_helpers.h>
#include <wil/registry.h>
#include <wil/nt_result_macros.h>

#include "HeimPrivate.h"
#include "TktBridgeAP-trace.h"

#define TKTBRIDGEAP_FLAG_DEBUG                  0x00000001
#define TKTBRIDGEAP_FLAG_PRIMARY_DOMAIN         0x00000002
#define TKTBRIDGEAP_FLAG_TRUSTED_DOMAINS        0x00000004
#define TKTBRIDGEAP_FLAG_NO_CLEAR_CRED_CACHE    0x00000008
#define TKTBRIDGEAP_FLAG_USER                   0x0000FFFF

#define TKTBRIDGEAP_FLAG_CLOUD_CREDS            0x00010000

#define TKTBRIDGEAP_REGISTRY_KEY_W              L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\TktBridgeAP"
#define TKTBRIDGEAP_PACKAGE_VERSION             1
#define TKTBRIDGEAP_PACKAGE_NAME_A               "TktBridgeAP"
#define TKTBRIDGEAP_PACKAGE_NAME_W              L"TktBridgeAP"
#define TKTBRIDGEAP_PACKAGE_COMMENT_W           L"TktBridge Authentication Package"

/*
 * Ticket Bridge credential structure: an AS-REP containing a TGT,
 * optionally with the initial credentials used to acquire it.
 */

typedef struct _TKTBRIDGEAP_CREDS {
    LONG RefCount;
    PWSTR ClientName;
    ULONG Reserved; // FIXME
    krb5_data AsRep;
    EncryptionKey AsReplyKey;
    LARGE_INTEGER EndTime;
    PSEC_WINNT_AUTH_IDENTITY_OPAQUE InitialCreds;
} TKTBRIDGEAP_CREDS, *PTKTBRIDGEAP_CREDS;

/*
 * WIL helpers
 */

#define RETURN_NTSTATUS_IF_NULL_ALLOC(ptr) __WI_SUPPRESS_4127_S do \
    { if ((ptr) == nullptr) { __RETURN_NTSTATUS_FAIL(STATUS_NO_MEMORY, #ptr); }} __WI_SUPPRESS_4127_E while ((void)0, 0)

/*
 * authidentity.cpp
 */

NTSTATUS _Success_(return == STATUS_SUCCESS)
ConvertLogonSubmitBufferToAuthIdentity(_In_ PLSA_CLIENT_REQUEST ClientRequest,
                                       _In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                       _In_ PVOID ClientBufferBase,
                                       _In_ ULONG SubmitBufferSize,
                                       _Out_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE *pAuthIdentity,
                                       _Out_opt_ PLUID pUnlockLogonId);

/*
 * authpackage.cpp
 */

extern PLSA_SECPKG_FUNCTION_TABLE LsaSpFunctionTable;
extern SECPKG_PARAMETERS SpParameters;

extern std::atomic<unsigned long> APFlags;
extern std::atomic<unsigned long> APLogLevel;

NTSTATUS
GetKdcHostName(std::wstring &Buffer, PCWSTR &pHostName);

NTSTATUS
GetRestrictPackage(std::wstring &Buffer, PCWSTR &pRestrictPackage);

bool
IsEnabledDomainSuffix(PCWSTR Suffix,
                      bool &Authoritative);

/*
 * errors.cpp
 */

#define RETURN_IF_KRB_FAILED(KrbError) do {                             \
    krb5_error_code _krbError = KrbError;                               \
    if (_krbError != 0) {                                               \
        return _krbError;                                               \
    }                                                                   \
} while (0)

#define RETURN_IF_KRB_FAILED_MSG(KrbError, Msg) do {                    \
    krb5_error_code _krbError = KrbError;                               \
    if (_krbError != 0) {                                               \
        auto szError = krb5_get_error_message(KrbContext, _krbError);   \
        DebugTrace(WINEVENT_LEVEL_ERROR, L"%s: %S (%d)",                \
                   Msg, szError, _krbError);                            \
        krb5_free_error_message(KrbContext, szError);                   \
        return _krbError;                                               \
    }                                                                   \
} while (0)

NTSTATUS
KrbErrorToNtStatus(_In_ krb5_error_code ret,
                   _Out_ PNTSTATUS Substatus);

krb5_error_code
SspiStatusToKrbError(_In_ SECURITY_STATUS SecStatus);

/*
 * helpers.cpp
 */

VOID
Seconds64Since1970ToTime(_In_ ULONG64 ElapsedSeconds,
                         _Out_ PLARGE_INTEGER Time);

VOID
TimeToSeconds64Since1970(_In_ PLARGE_INTEGER Time,
                         _Out_ PULONG64 ElapsedSeconds);

ULONG
GetCallAttributes(VOID);

ULONG
RegistryGetULongValueForKey(_In_ const wil::unique_hkey &hKey,
                            _In_z_ PCWSTR KeyName);

bool
RegistryGetStringValueForKey(_In_ const wil::unique_hkey &hKey,
                             _In_z_ PCWSTR KeyName,
                             _Out_ std::wstring &KeyValue);

bool
RegistryGetStringValuesForKey(_In_ const wil::unique_hkey &hKey,
                              _In_z_ PCWSTR KeyName,
                              _Out_ std::vector<std::wstring> &KeyValues);

bool
IsLocalHost(_In_ PUNICODE_STRING HostName);

NTSTATUS
UnicodeToUTF8Alloc(_In_ PCWSTR wszUnicodeString,
                   _Out_ PCHAR *pszUTF8String);

NTSTATUS
UTF8ToUnicodeAlloc(_In_ const PCHAR szUTF8String,
                   _Out_ PWSTR *pwszUnicodeString);

/*
 * kerbinterpose.cpp
 */

_Success_(return == ERROR_SUCCESS) DWORD
AttachKerbLogonInterposer(VOID);

VOID
DetachKerbLogonInterposer(VOID);

/*
 * preauth.cpp
 */

_Success_(return == 0) krb5_error_code
GssPreauthGetInitCreds(_In_z_ PCWSTR RealmName,
                       _In_opt_z_ PCWSTR PackageName,
                       _In_opt_z_ PCWSTR KdcHostName,
                       _In_opt_ PLUID pvLogonId,
                       _In_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity,
                       _Out_ PWSTR *pClientName,
                       _Out_ LARGE_INTEGER *pEndTime,
                       _Out_ krb5_data *AsRep,
                       _Out_ krb5_keyblock *AsReplyKey,
                       _Out_ SECURITY_STATUS *SecStatus);

/*
 * prf.cpp
 */

_Success_(return == 0) krb5_error_code
RFC4401PRF(_In_ krb5_context KrbContext,
           _In_ PCtxtHandle phContext,
           _In_ krb5_enctype EncryptionType,
           _In_reads_bytes_(cbPrfInput) const PBYTE pbPrfInput,
           _In_ ULONG cbPrfInput,
           _Outptr_result_bytebuffer_(*pcbPrfOutput) PBYTE *pbPrfOutput,
           _Out_ size_t *pcbPrfOutput);

/*
 * surrogate.cpp
 */

extern "C" {
    LSA_AP_LOGON_TERMINATED LsaApLogonTerminated;
    LSA_AP_PRE_LOGON_USER_SURROGATE LsaApPreLogonUserSurrogate;
    LSA_AP_POST_LOGON_USER_SURROGATE LsaApPostLogonUserSurrogate;
}

PSECPKG_SURROGATE_LOGON_ENTRY
FindSurrogateLogonCreds(_In_ PSECPKG_SURROGATE_LOGON SurrogateLogon);

/*
 * tktcreds.cpp
 */

_Success_(return == STATUS_SUCCESS) NTSTATUS
FindCredForLogonSession(_In_ const LUID &LogonId,
                        _Out_ PTKTBRIDGEAP_CREDS *TktBridgeCreds);

_Success_(return == STATUS_SUCCESS) NTSTATUS
SaveCredForLogonSession(_In_ const LUID &LogonId,
                        _In_ PTKTBRIDGEAP_CREDS TktBridgeCreds);

_Success_(return == STATUS_SUCCESS) NTSTATUS
RemoveCredForLogonSession(_In_ const LUID &LogonId);

VOID
DebugLogonCreds(VOID);

PTKTBRIDGEAP_CREDS
AllocateTktBridgeCreds(VOID);

PTKTBRIDGEAP_CREDS
ReferenceTktBridgeCreds(_Inout_ PTKTBRIDGEAP_CREDS Creds);

VOID
DereferenceTktBridgeCreds(_Inout_ PTKTBRIDGEAP_CREDS Creds);

bool
IsTktBridgeCredsExpired(_In_ PTKTBRIDGEAP_CREDS Creds);

/*
 * tracing.cpp
 */

_Success_(return == 0) krb5_error_code
HeimTracingInit(_In_ krb5_context KrbContext);

VOID
__cdecl DebugTrace(_In_ UCHAR Level, _In_z_ PCWSTR wszFormat, ...);
