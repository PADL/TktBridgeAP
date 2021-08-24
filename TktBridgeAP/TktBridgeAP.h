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
#endif /* !NDEBUG */

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

#include <windows.h>
#include <ntstatus.h>
#include <winternl.h>
#include <winreg.h>
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
#define TKTBRIDGEAP_FLAG_DISABLE_CACHE          0x00000008
#define TKTBRIDGEAP_FLAG_USER                   0x0000FFFF

#define TKTBRIDGEAP_FLAG_CLOUD_CREDS            0x00010000

#define TKTBRIDGEAP_REGISTRY_KEY_W              L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\TktBridgeAP"
#define TKTBRIDGEAP_PACKAGE_VERSION             1
#define TKTBRIDGEAP_PACKAGE_NAME_A               "TktBridgeAP"
#define TKTBRIDGEAP_PACKAGE_NAME_W              L"TktBridgeAP"
#define TKTBRIDGEAP_PACKAGE_COMMENT_W           L"TktBridge Authentication Package"

// authidentity.cpp

NTSTATUS _Success_(return == STATUS_SUCCESS)
ConvertLogonSubmitBufferToAuthIdentity(_In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                       _In_ ULONG SubmitBufferSize,
                                       _Out_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE *pAuthIdentity,
                                       _Out_opt_ PLUID pUnlockLogonID);

NTSTATUS _Success_(return == STATUS_SUCCESS)
RetypeLogonSubmitBuffer(_In_ PLSA_CLIENT_REQUEST ClientRequest,
                        _Out_writes_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                        _In_ PVOID ClientBufferBase,
                        _In_ ULONG SubmitBufferSize);

// credcache.cpp

typedef struct _TKTBRIDGEAP_CREDS {
    //
    // Reference count, used by credentials cache. Preauth creds
    // immutable and cannot be modified by the caller except to
    // retain or release.
    //
    LONG RefCount;

    //
    // Client name, as returned by QueryContextAttributes
    //
    PWSTR InitiatorName;

    //
    // Ticket expiry time
    //
    LARGE_INTEGER ExpiryTime;

    //
    // AS-REP received from bridge KDC
    //
    krb5_data AsRep;

    //
    // Reply-key derived from GSS-API pre-authentication
    //
    EncryptionKey AsReplyKey;

    //
    // TKTBRIDGEAP_CREDS_FLAG_XXX
    //
    ULONG Flags;

    //
    // Domain name from logon request
    //
    PCWSTR DomainName;

    //
    // User name from logon request
    //
    PCWSTR UserName;

    //
    // Originating logon ID
    //
    LUID LogonId;
} TKTBRIDGEAP_CREDS, *PTKTBRIDGEAP_CREDS;

#define TKTBRIDGEAP_CREDS_FLAG_CACHED       0x00000001

typedef const TKTBRIDGEAP_CREDS *PCTKTBRIDGEAP_CREDS;

NTSTATUS
LocateCachedPreauthCredentials(_In_ SECURITY_LOGON_TYPE LogonType,
                               _In_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity,
                               _In_opt_ PLUID pvLogonID,
                               _Out_ PTKTBRIDGEAP_CREDS *TktBridgeCreds,
                               _Out_ PNTSTATUS SubStatus);

NTSTATUS
CacheAddPreauthCredentials(_In_ SECURITY_LOGON_TYPE LogonType,
                           _In_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity,
                           _In_opt_ PLUID pvLogonID,
                           _In_ PCTKTBRIDGEAP_CREDS TktBridgeCreds);

NTSTATUS
CacheRemovePreauthCredentials(_In_ SECURITY_LOGON_TYPE LogonType,
                              _In_opt_ PLUID pvLogonID,
                              _In_ PCTKTBRIDGEAP_CREDS TktBridgeCreds);

bool
IsPreauthCredsExpired(_In_ PTKTBRIDGEAP_CREDS Creds);

VOID
ReferencePreauthInitCreds(_Inout_ PTKTBRIDGEAP_CREDS Creds);

VOID
DereferencePreauthInitCreds(_Inout_ PTKTBRIDGEAP_CREDS Creds);

// errors.cpp

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

// helpers.cpp

VOID
Seconds64Since1970ToTime(_In_ ULONG64 ElapsedSeconds,
                         _Out_ PLARGE_INTEGER Time);

ULONG
GetCallAttributes(VOID);

VOID
FreeLsaString(_Inout_ PLSA_STRING pLsaString);

NTSTATUS
DuplicateLsaString(_In_ PLSA_STRING Src, _Out_ PLSA_STRING *Dst);

DWORD
RegistryGetDWordValueForKey(_In_ HKEY hKey, _In_z_ PCWSTR KeyName);

PWSTR
RegistryGetStringValueForKey(_In_ HKEY hKey, _In_z_ PCWSTR KeyName);

PWSTR *
RegistryGetStringValuesForKey(_In_ HKEY hKey,
                              _In_z_ PCWSTR KeyName);

bool
IsLocalHost(_In_ PUNICODE_STRING HostName);

NTSTATUS
UnicodeToUTF8Alloc(_In_ PCWSTR wszUnicodeString,
    _Out_ PCHAR *pszUTF8String);

NTSTATUS
UTF8ToUnicodeAlloc(_In_ const PCHAR szUTF8String,
    _Out_ PWSTR *pwszUnicodeString);

// logonpkg.cpp

extern PLSA_SECPKG_FUNCTION_TABLE LsaSpFunctionTable;
extern PLSA_DISPATCH_TABLE LsaDispatchTable;
extern PLSA_SECPKG_FUNCTION_TABLE LsaSpFunctionTable;

extern PSECPKG_FUNCTION_TABLE KerbFunctionTable;

extern SECPKG_PARAMETERS SpParameters;
extern ULONG APFlags;
extern ULONG APLogLevel;
extern PWSTR APKdcHostName;
extern PWSTR APRestrictPackage;
extern PWSTR *APDomainSuffixes;

extern "C"
TKTBRIDGEAP_API NTSTATUS __cdecl
SpLsaModeInitialize(_In_ ULONG LsaVersion,
                    _Out_ PULONG PackageVersion,
                    _Out_ PSECPKG_FUNCTION_TABLE *ppTables,
                    _Out_ PULONG pcTables);

// preauth.cpp

krb5_error_code _Success_(return == 0)
GssPreauthGetInitCreds(_In_z_ PCWSTR RealmName,
                       _In_opt_z_ PCWSTR PackageName,
                       _In_opt_z_ PCWSTR KdcHostName,
                       _In_opt_ PLUID pvLogonID,
                       _In_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity,
                       _Out_ PWSTR *pClientName,
                       _Out_ LARGE_INTEGER *pExpiryTime,
                       _Out_ krb5_data *AsRep,
                       _Out_ krb5_keyblock *AsReplyKey,
                       _Out_ SECURITY_STATUS *SecStatus);

// prf.cpp

_Success_(return == 0) krb5_error_code
RFC4401PRF(_In_ krb5_context KrbContext,
           _In_ PCtxtHandle phContext,
           _In_ krb5_enctype EncryptionType,
           _In_reads_bytes_(cbPrfInput) const PBYTE pbPrfInput,
           _In_ ULONG cbPrfInput,
           _Outptr_result_bytebuffer_(*pcbPrfOutput) PBYTE * pbPrfOutput,
           _Out_ size_t * pcbPrfOutput);

// surrogate.cpp
extern "C" {
    LSA_AP_LOGON_USER_EX3 TktBridgeApLogonUserEx3;
    LSA_AP_PRE_LOGON_USER_SURROGATE PreLogonUserSurrogate;
    LSA_AP_POST_LOGON_USER_SURROGATE PostLogonUserSurrogate;
}

// tracing.cpp
_Success_(return == 0) krb5_error_code
HeimTracingInit(_In_ krb5_context KrbContext);

VOID
__cdecl DebugTrace(_In_ UCHAR Level, _In_z_ PCWSTR wszFormat, ...);

VOID
DebugSessionKey(_In_z_ PCWSTR Tag,
                _In_bytecount_(cbKey) PBYTE pbKey,
                _In_ SIZE_T cbKey);

namespace wil {
#define RETURN_NTSTATUS_IF_NULL_ALLOC(ptr) __WI_SUPPRESS_4127_S do { if ((ptr) == nullptr) { __RETURN_NTSTATUS_FAIL(STATUS_NO_MEMORY, #ptr); }} __WI_SUPPRESS_4127_E while ((void)0, 0)

    using unique_cred_handle = unique_struct<SecHandle, decltype(&::FreeCredentialsHandle), ::FreeCredentialsHandle>;

    using unique_lsa_string = unique_any<PLSA_STRING, decltype(&::FreeLsaString), ::FreeLsaString>;
    using unique_rtl_sid = unique_any<PSID, decltype(&::RtlFreeSid), ::RtlFreeSid>;
}
