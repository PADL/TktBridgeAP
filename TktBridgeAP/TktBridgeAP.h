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

#ifndef WINAPI_FAMILY
#define WINAPI_FAMILY WINAPI_FAMILY_SYSTEM
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

#include <windows.h>
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

#include <strsafe.h>
#include <crtdbg.h>
#include <assert.h>

#include "wil.h"
#include "ntapiext.h"
#include "KerbSurrogate.h"
#include "TktBridgeAP-trace.h"

#ifndef NEGOSSP_NAME
#define NEGOSSP_NAME_W  L"Negotiate"
#endif

extern "C" {
#include <krb5.h>
}

extern PLSA_SECPKG_FUNCTION_TABLE LsaSpFunctionTable;
extern PLSA_DISPATCH_TABLE LsaDispatchTable;
extern PLSA_SECPKG_FUNCTION_TABLE LsaSpFunctionTable;

extern SECPKG_PARAMETERS SpParameters;
extern ULONG APFlags;
extern ULONG APLogLevel;
extern LPWSTR APKdcHostName;
extern LPWSTR APRestrictPackage;

#define TKTBRIDGEAP_FLAG_DEBUG			0x00000001
#define TKTBRIDGEAP_FLAG_USER			0x0000FFFF

#define TKTBRIDGEAP_REGISTRY_KEY_W		L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\TktBridgeAP"
#define TKTBRIDGEAP_PACKAGE_VERSION		1
#define TKTBRIDGEAP_PACKAGE_NAME_A		 "TktBridgeAP"
#define TKTBRIDGEAP_PACKAGE_NAME_W		L"TktBridgeAP"
#define TKTBRIDGEAP_PACKAGE_COMMENT_W	L"TktBridge Authentication Package"

// credcache.cpp

typedef struct _PREAUTH_INIT_CREDS {
    //
    // Reference count, used by credentials cache
    //
    LONG RefCount;

    //
    // Client name, as returned by QueryContextAttributes
    //
    PWSTR ClientName;

    //
    // AS-REP received from bridge KDC
    //
    krb5_data AsRep;

    //
    // Reply-key derived from GSS-API pre-authentication
    //
    krb5_keyblock AsReplyKey;

    //
    // For cached credentials, the user and domain name of
    // the original logon request.
    //
    LPWSTR DomainName;
    LPWSTR UserName;
} PREAUTH_INIT_CREDS, *PPREAUTH_INIT_CREDS;

NTSTATUS
AcquireCachedPreauthCredentials(_In_ SECURITY_LOGON_TYPE LogonType,
				_In_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity,
				_In_opt_ PLUID pvLogonID,
				_Out_ PPREAUTH_INIT_CREDS *PreauthCreds);

NTSTATUS
CachePreauthCredentials(_In_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity,
			_In_opt_ PLUID pvLogonID,
			_In_ PPREAUTH_INIT_CREDS PreauthCreds);

// helpers.cpp

VOID
FreeLsaString(_Inout_ PLSA_STRING pLsaString);

NTSTATUS
DuplicateLsaString(_In_ PLSA_STRING Src, _Out_ PLSA_STRING *Dst);

DWORD
RegistryGetDWordValueForKey(_In_ HKEY hKey, _In_z_ PCWSTR KeyName);

PWSTR
RegistryGetStringValueForKey(_In_ HKEY hKey, _In_z_ PCWSTR KeyName);

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
NTSTATUS
KrbErrorToNtStatus(_In_ krb5_error_code ret);

krb5_error_code
SspiPreauthGetInitCreds(_In_z_ PCWSTR RealmName,
			_In_opt_z_ PCWSTR PackageName,
			_In_opt_z_ PCWSTR KdcHostName,
			_In_opt_ PLUID pvLogonID,
			_In_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity,
			_Out_ PWSTR *pClientName,
			_Inout_ krb5_data *AsRep,
			_Inout_ krb5_keyblock *AsReplyKey,
			_Out_ SECURITY_STATUS *SecStatus);

// surrogate.cpp
VOID
RetainPreauthInitCreds(_Inout_ PPREAUTH_INIT_CREDS Creds);

VOID
FreePreauthInitCreds(_Inout_ PPREAUTH_INIT_CREDS *Creds);

extern "C" {
    LSA_AP_PRE_LOGON_USER_SURROGATE PreLogonUserSurrogate;
    LSA_AP_POST_LOGON_USER_SURROGATE PostLogonUserSurrogate;
}

// tracing.cpp
krb5_error_code
HeimTracingInit(_In_ krb5_context KrbContext);

VOID
__cdecl DebugTrace(_In_ UCHAR Level, _In_z_ PCWSTR wszFormat, ...);

void
DebugSessionKey(_In_z_ PCWSTR Tag,
		_In_bytecount_(cbKey) PBYTE pbKey,
		_In_ SIZE_T cbKey);

namespace wil {
#define RETURN_NTSTATUS_IF_NULL_ALLOC(ptr) __WI_SUPPRESS_4127_S do { if ((ptr) == nullptr) { __RETURN_NTSTATUS_FAIL(STATUS_NO_MEMORY, #ptr); }} __WI_SUPPRESS_4127_E while ((void)0, 0)

    using unique_cred_handle = unique_struct<SecHandle, decltype(&::FreeCredentialsHandle), ::FreeCredentialsHandle>;

    using unique_lsa_string = unique_any<PLSA_STRING, decltype(&::FreeLsaString), ::FreeLsaString>;
    using unique_rtl_sid = unique_any<PSID, decltype(&::RtlFreeSid), ::RtlFreeSid>;
}
