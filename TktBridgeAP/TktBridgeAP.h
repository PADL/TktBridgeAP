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
HeimErrToNtStatus(krb5_error_code ret);

// tracing.cpp
krb5_error_code
InitializeHeimTracing(krb5_context KrbContext);

VOID
__cdecl DebugTrace(UCHAR Level, PCWSTR wszFormat, ...);

#ifdef __cplusplus
}
#endif
