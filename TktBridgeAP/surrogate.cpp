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
    /*
    // trace everything with WPPTraceLog
// validate parameters including surrogate version, logon type, return STATUS_INVALID_PARAMETER if invalid
// canonicalize logon identity to opaque auth identity
    ConvertLogonCredsToOpaqueAuthIdentity();
    // check PolicyPrimaryDomainInformation() / PolicyDnsDomainInformation / LsaQueryTrustedDomainInfoByName/ TrustedDomainNameInformation (SEC_E_NO_CREDENTIALS)
    ValidateAuthIdentity();
    // check ticket cache for username/domain name, if matches
    if (gEnableTicketCache) {
        DeriveWrapKey();
        LocateTicketCacheEntry(true);
        LockAndUnprotectTicketCacheEntry(true);
    }
    SspiFreeAuthIdentity(convertedIdentity);
    //      - try to decrypt reply key using PBKDF2(credentials)
    if (HasNotExpired(CacheEntry) && CacheEntry->WrappedReplyKeyValue) {
        KERB_CRYPTO_KEY32 TgtReplyKey;
        UnwrapKeyData(CacheEntry->WrappedReplyKeyValue, CacheEntry->WrappedReplyKeyLength, ...);
        if (TgtReplyKey->KeyType != CacheEntry->TgtKeyType)
            return STATUS_ACCESS_DENIED;
        // - if this succeeds, and cache entry hasn't expired, return those
    } else {
        // ACH(credentials); PBKDF2 to derive key; forget credentials; ISC/KDC AS-REQ
        //      - allocate surrogate entry containing AS-REP credentials
    }
    // GUIDs 0x045fbe6b 0x42057995 0xfa741191 0x273cdd9c || RetrieveKerbSupplementalCredential pointer + session key callback
    //       0x8ece955b 0x41f8e32c 0x7c953684 0x36326823 || session key
    // don't destroy surrogate logon data, needs to be reallocated if present
    if (gEnableTicketCache) {
        //      - create cache entry with TGT and PBKDF2 encrypted reply key
        ProtectAndUnlockTicketCacheEntry();
        ReleaseTicketCacheEntry();
    }

    */

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

