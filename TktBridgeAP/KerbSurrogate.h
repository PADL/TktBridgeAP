/*++

Copyright (c) PADL Software Pty Ltd, All rights reserved.

Module Name:

    KerbSurrogate.h

Abstract:

    Interface between SPM surrogate API and Kerberos package.

Environment:

    Local Security Authority (LSA)

--*/

#pragma once

#include <NTSecPKG.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _KERB_AS_REP_CREDENTIAL {
    ULONG Version;
    ULONG Flags;
    ULONG TgtMessageOffset;
    ULONG TgtMessageSize;
    ULONG TgtClientKeyOffset;
    ULONG TgtClientKeySize;
    ULONG VsmBindingPrivateKeyOffset;
    ULONG VsmBindingPrivateKeySize;
    ULONG TgtKeyType;
} KERB_AS_REP_CREDENTIAL, *PKERB_AS_REP_CREDENTIAL;

#define KERB_AS_REP_CREDENTIAL_VERSION_1        1

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