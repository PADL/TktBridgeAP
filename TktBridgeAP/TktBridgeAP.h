/*++

Copyright (c) PADL Software Pty Ltd, All rights reserved.

Module Name:

    TktBridgeAP.h

Abstract:

    Ticket Bridge Authentication Provider (AP)

Environment:

    Local Security Authority (LSA)

--*/

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

//#undef _LSALOOKUP_
#include <wil/common.h>
#include <wil/resource.h>
#include <wil/win32_helpers.h>
#include <wil/registry.h>
#include <wil/nt_result_macros.h>

#include "ntapiext.h"
#include "KerbPrivate.h"
#include "HeimPrivate.h"
#include "TktBridgeAP-trace.h"

#ifndef NEGOSSP_NAME
#define NEGOSSP_NAME_W  L"Negotiate"
#endif

extern PLSA_SECPKG_FUNCTION_TABLE LsaSpFunctionTable;
extern PLSA_DISPATCH_TABLE LsaDispatchTable;
extern PLSA_SECPKG_FUNCTION_TABLE LsaSpFunctionTable;

extern SECPKG_PARAMETERS SpParameters;
extern ULONG APFlags;
extern ULONG APLogLevel;
extern PWSTR APKdcHostName;
extern PWSTR APRestrictPackage;

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
NTSTATUS
KrbErrorToNtStatus(_In_ krb5_error_code ret,
                   _Out_ PNTSTATUS Substatus);

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

bool
IsLocalHost(_In_ PUNICODE_STRING HostName);

NTSTATUS
GetLocalHostName(_In_ BOOLEAN bLsaAlloc,
                 _Inout_ PUNICODE_STRING HostName);

NTSTATUS
UnicodeToUTF8Alloc(_In_ PCWSTR wszUnicodeString,
    _Out_ PCHAR *pszUTF8String);

NTSTATUS
UTF8ToUnicodeAlloc(_In_ const PCHAR szUTF8String,
    _Out_ PWSTR *pwszUnicodeString);

// logonapi.cpp

extern "C"
TKTBRIDGEAP_API NTSTATUS __cdecl
SpLsaModeInitialize(_In_ ULONG LsaVersion,
                    _Out_ PULONG PackageVersion,
                    _Out_ PSECPKG_FUNCTION_TABLE *ppTables,
                    _Out_ PULONG pcTables);

// sspipreauth.cpp

krb5_error_code _Success_(return == 0)
SspiPreauthGetInitCreds(_In_z_ PCWSTR RealmName,
                        _In_opt_z_ PCWSTR PackageName,
                        _In_opt_z_ PCWSTR KdcHostName,
                        _In_opt_ PLUID pvLogonID,
                        _In_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity,
                        _Out_ PWSTR *pClientName,
                        _Out_ LARGE_INTEGER *pExpiryTime,
                        _Out_ krb5_data *AsRep,
                        _Out_ krb5_keyblock *AsReplyKey,
                        _Out_ SECURITY_STATUS *SecStatus);

// surrogate.cpp
extern "C" {
    LSA_AP_PRE_LOGON_USER_SURROGATE PreLogonUserSurrogate;
    LSA_AP_POST_LOGON_USER_SURROGATE PostLogonUserSurrogate;
}

// tracing.cpp
krb5_error_code
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
