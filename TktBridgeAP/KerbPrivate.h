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
    ULONG VsmBindingKeyOffset;
    ULONG VsmBindingKeySize;
    ULONG TgtKeyType;
} KERB_AS_REP_AAD_CREDENTIAL;

typedef struct _KERB_AS_REP_CLOUD_CREDENTIAL {
    ULONG Type;
    ULONG Flags;
    ULONG VsmBindingKeyOffset;
    ULONG VsmBindingKeySize;
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

#define KERB_AS_REP_CREDENTIAL_TYPE_AAD     1 // FIDO with AAD Hybrid
#define KERB_AS_REP_CREDENTIAL_TYPE_CLOUD   3 // new in 10.0.22000.0

typedef NTSTATUS
(NTAPI KERB_SURROGATE_RETRIEVE_CRED)(
    LUID LogonId,
    PVOID PackageData,
    ULONG Flags,
    PKERB_AS_REP_CREDENTIAL *ppKerbAsRepCredential);

typedef KERB_SURROGATE_RETRIEVE_CRED *PKERB_SURROGATE_RETRIEVE_CRED;

EXTERN_C __declspec(selectany) const GUID KERB_SURROGATE_LOGON_TYPE =
{ 0x045fbe6b, 0x7995, 0x4205, { 0x91, 0x11, 0x74, 0xfa, 0x9c, 0xdd, 0x3c, 0x27 } };

typedef struct _KERB_SURROGATE_LOGON_DATA {
    ULONG_PTR Reserved[10];
    PKERB_SURROGATE_RETRIEVE_CRED RetrieveAsRepCredential;
    PVOID PackageData;
} KERB_SURROGATE_LOGON_DATA, *PKERB_SURROGATE_LOGON_DATA;

#ifdef __cplusplus
}
#endif
