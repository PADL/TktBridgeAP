/*++

Copyright (c) PADL Software Pty Ltd, All rights reserved.

Module Name:

    KerbPrivate.h

Abstract:

    Private Kerberos package APIs.

Environment:

    Local Security Authority (LSA)

--*/

#pragma once

#include <NTSecPKG.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// WOW64 (32-bit) client support
//

typedef struct _KERB_UNICODE_STRING32 {
    USHORT Length;
    USHORT MaximumLength;
    ULONG Buffer;
} KERB_UNICODE_STRING32;

typedef KERB_UNICODE_STRING32 *PKERB_UNICODE_STRING32;
typedef const KERB_UNICODE_STRING32 *PCKERB_UNICODE_STRING32;

typedef struct _KERB_INTERACTIVE_LOGON32 {
    KERB_LOGON_SUBMIT_TYPE MessageType;
    KERB_UNICODE_STRING32 LogonDomainName;
    KERB_UNICODE_STRING32 UserName;
    KERB_UNICODE_STRING32 Password;
} KERB_INTERACTIVE_LOGON32, *PKERB_INTERACTIVE_LOGON32;

typedef struct _KERB_INTERACTIVE_UNLOCK_LOGON32 {
    KERB_INTERACTIVE_LOGON32 Logon;
    LUID LogonId;
} KERB_INTERACTIVE_UNLOCK_LOGON32, *PKERB_INTERACTIVE_UNLOCK_LOGON32;

typedef struct _KERB_SMART_CARD_LOGON32 {
    KERB_LOGON_SUBMIT_TYPE MessageType;
    KERB_UNICODE_STRING32 Pin;
    ULONG CspDataLength;
    ULONG CspData;
} KERB_SMART_CARD_LOGON32, *PKERB_SMART_CARD_LOGON32;

typedef struct _KERB_SMART_CARD_UNLOCK_LOGON32 {
    KERB_SMART_CARD_LOGON32 Logon;
    LUID LogonId;
} KERB_SMART_CARD_UNLOCK_LOGON32, *PKERB_SMART_CARD_UNLOCK_LOGON32;

//
// Smartcard logon
// https://docs.microsoft.com/en-us/windows/win32/secauthn/kerb-smartcard-csp-info
//

#pragma pack(push, 2)
typedef struct _KERB_SMARTCARD_CSP_INFO {
    DWORD dwCspInfoLen;
    DWORD MessageType;
    union {
        PVOID   ContextInformation;
        ULONG64 SpaceHolderForWow64;
    };
    DWORD flags;
    DWORD KeySpec;
    ULONG nCardNameOffset;
    ULONG nReaderNameOffset;
    ULONG nContainerNameOffset;
    ULONG nCSPNameOffset;
    TCHAR bBuffer;
} KERB_SMARTCARD_CSP_INFO, *PKERB_SMARTCARD_CSP_INFO;
#pragma pack(pop)

//
// Surrogate AS-REP logon
//

typedef struct _KERB_AS_REP_AAD_CREDENTIAL {
    ULONG Type;
    ULONG Flags;
    ULONG TgtMessageOffset;
    ULONG TgtMessageSize;
    ULONG TgtClientKeyOffset;
    ULONG TgtClientKeySize;
    ULONG ReservedOffset;
    ULONG ReservedSize;
    ULONG TgtKeyType;
} KERB_AS_REP_AAD_CREDENTIAL;

typedef struct _KERB_AS_REP_CLOUD_CREDENTIAL {
    ULONG Type;
    ULONG Flags;
    ULONG ReservedOffset;
    ULONG ReservedSize;
    ULONG TgtMessageOffset;
    ULONG TgtMessageSize;
    ULONG TgtClientKeyOffset;
    ULONG TgtClientKeySize;
    ULONG TgtKeyType;
    ULONG CloudTgtMessageOffset;
    ULONG CloudTgtMessageSize;
    ULONG CloudTgtClientKeyOffset;
    ULONG CloudTgtClientKeySize;
    ULONG CloudTgtKeyType;
    ULONG KerberosTopLevelNamesOffset;
    ULONG KerberosTopLevelNamesSize;
    ULONG KdcProxyNameOffset;
    ULONG KdcProxyNameSize;
} KERB_AS_REP_CLOUD_CREDENTIAL;

typedef union _KERB_AS_REP_CREDENTIAL {
    KERB_AS_REP_AAD_CREDENTIAL Credential;
    KERB_AS_REP_CLOUD_CREDENTIAL CloudCredential;
} KERB_AS_REP_CREDENTIAL, *PKERB_AS_REP_CREDENTIAL;

#define KERB_AS_REP_CREDENTIAL_TYPE_AAD     1
#define KERB_AS_REP_CREDENTIAL_TYPE_CLOUD   3

typedef NTSTATUS
(NTAPI KERB_AS_REP_CALLBACK)(
    LUID LogonId,
    PVOID PackageData,
    ULONG Flags,
    PKERB_AS_REP_CREDENTIAL *ppKerbAsRepCredential);

typedef KERB_AS_REP_CALLBACK *PKERB_AS_REP_CALLBACK;

EXTERN_C __declspec(selectany) const GUID KERB_SURROGATE_LOGON_TYPE =
{ 0x045fbe6b, 0x7995, 0x4205, { 0x91, 0x11, 0x74, 0xfa, 0x9c, 0xdd, 0x3c, 0x27 } };

typedef struct _KERB_SURROGATE_LOGON_DATA {
    ULONG_PTR Reserved[10];
    PKERB_AS_REP_CALLBACK AsRepCallback;
    PVOID PackageData;
} KERB_SURROGATE_LOGON_DATA, *PKERB_SURROGATE_LOGON_DATA;

#ifdef __cplusplus
}
#endif
