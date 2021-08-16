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
#include <Tracelogging.h>
#include <sspi.h>
#define _NTDEF_
#include <NTSecAPI.h>
#undef _NTDEF_
#include <NTSecPkg.h>
#include <evntprov.h>
#include <strsafe.h>
#include <crtdbg.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0
#endif

#include "wil.h"
#include "ntapiext.h"
#include "KerbSurrogate.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <krb5.h>

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

// helpers.cpp

NTSTATUS
DuplicateLsaString(IN PLSA_STRING Src, OUT PLSA_STRING *Dst);

DWORD
RegistryGetDWordValueForKey(HKEY hKey, PCWSTR KeyName);

PWSTR
RegistryGetStringValueForKey(HKEY hKey, PCWSTR KeyName);

VOID
RegistryFreeValue(PWSTR Value);

// sspipreauth.cpp
NTSTATUS
KrbErrorToNtStatus(krb5_error_code ret);

krb5_error_code
SspiStatusToKrbError(SECURITY_STATUS SecStatus);

// surrogate.cpp
NTSTATUS
PreLogonUserSurrogate(
    _In_ PLSA_CLIENT_REQUEST ClientRequest,
    _In_ SECURITY_LOGON_TYPE LogonType,
    _In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
    _In_ PVOID ClientBufferBase,
    _In_ ULONG SubmitBufferSize,
    _Inout_ PSECPKG_SURROGATE_LOGON SurrogateLogon,
    _Out_ PNTSTATUS SubStatus);

NTSTATUS
PostLogonUserSurrogate(
    _In_ PLSA_CLIENT_REQUEST ClientRequest,
    _In_ SECURITY_LOGON_TYPE LogonType,
    _In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
    _In_ PVOID ClientBufferBase,
    _In_ ULONG SubmitBufferSize,
    _In_ PSECPKG_SURROGATE_LOGON SurrogateLogon,
    _In_reads_bytes_(ProfileBufferSize) PVOID ProfileBuffer,
    _In_ ULONG ProfileBufferSize,
    _In_ PLUID LogonId,
    _In_ NTSTATUS Status,
    _In_ NTSTATUS SubStatus,
    _In_ LSA_TOKEN_INFORMATION_TYPE TokenInformationType,
    _In_ PVOID TokenInformation,
    _In_ PUNICODE_STRING AccountName,
    _In_ PUNICODE_STRING AuthenticatingAuthority,
    _In_ PUNICODE_STRING MachineName,
    _In_ PSECPKG_PRIMARY_CRED PrimaryCredentials,
    _In_ PSECPKG_SUPPLEMENTAL_CRED_ARRAY SupplementalCredentials);

// tracing.cpp
krb5_error_code
HeimTracingInit(krb5_context KrbContext);

VOID
__cdecl DebugTrace(UCHAR Level, PCWSTR wszFormat, ...);

#ifdef __cplusplus
}
#endif
