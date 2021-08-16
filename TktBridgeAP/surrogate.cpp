/*++

Copyright (c) PADL Software Pty Ltd, All rights reserved.

Module Name:

    surrogate.cpp

Abstract:

    Interface between SPM surrogate API and Kerberos package.

Environment:

    Local Security Authority (LSA)

--*/

#include "TktBridgeAP.h"

static NTSTATUS
RetrieveAsRepCredential(
    LUID LogonID,
    PVOID SurrogateData,
    ULONG dwFlags,
    PKERB_AS_REP_CREDENTIAL *pKerbAsRepCred)
{
/*
        PKERB_AS_REP_CREDENTIAL ProtectedCred = (PKERB_AS_REP_CREDENTIAL)SurrogateData;

        // copy it
        // LsaUnprotect it
        LsaSpFunctionTable->LsaProtectMemory((PUCHAR)CredCopy + TgtClientKeyOffset, TgtClientKeySize);
        *pKerbAsRepCred = CredCopy;
*/

    return STATUS_INVALID_PARAMETER;
}

NTSTATUS
PreLogonUserSurrogate(
    _In_ PLSA_CLIENT_REQUEST ClientRequest,
    _In_ SECURITY_LOGON_TYPE LogonType,
    _In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
    _In_ PVOID ClientBufferBase,
    _In_ ULONG SubmitBufferSize,
    _Inout_ PSECPKG_SURROGATE_LOGON SurrogateLogon,
    _Out_ PNTSTATUS SubStatus)
{
    return STATUS_INVALID_PARAMETER;
}

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
    _In_ PSECPKG_SUPPLEMENTAL_CRED_ARRAY SupplementalCredentials)
{
    return STATUS_INVALID_PARAMETER;
}

