/*++

Copyright (c) PADL Software Pty Ltd, All rights reserved.

Module Name:

    surrogate.cpp

Abstract:

    Interface between surrogate API and Kerberos package.

Environment:

    Local Security Authority (LSA)

--*/

#include "TktBridgeAP.h"

//
// Callback function called from Kerberos package that passes TktBridgeAP-
// specific private data and retrieves a KERB_AS_REP_CREDENTIAL
// containing the AS-REP and reply key
//
extern "C"
static NTSTATUS NTAPI
RetrievePreauthInitCreds(LUID LogonID,
                         PVOID PackageData,
                         ULONG Flags,
                         PKERB_AS_REP_CREDENTIAL *pKerbAsRepCred)
{
    auto TktBridgeCreds = (PCTKTBRIDGEAP_CREDS)PackageData;
    ULONG cbKerbAsRepCred;

    if (TktBridgeCreds == nullptr)
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);

    DebugTrace(WINEVENT_LEVEL_VERBOSE,
               L"RetrievePreauthInitCreds: LogonID %08x.%08x Flags %08x "
               L"AS-REP Length %u KeyLength %u KeyType %u",
               LogonID.LowPart,
               LogonID.HighPart,
               Flags,
               TktBridgeCreds->AsRep.length,
               TktBridgeCreds->AsReplyKey.keyvalue.length,
               TktBridgeCreds->AsReplyKey.keytype);

    cbKerbAsRepCred = sizeof(KERB_AS_REP_CLOUD_CREDENTIAL) +
        (ULONG)TktBridgeCreds->AsRep.length +
        (ULONG)TktBridgeCreds->AsReplyKey.keyvalue.length;

    auto KerbAsRepCredU = (PKERB_AS_REP_CREDENTIAL)LsaSpFunctionTable->AllocateLsaHeap(cbKerbAsRepCred);
    RETURN_NTSTATUS_IF_NULL_ALLOC(KerbAsRepCredU);

    ZeroMemory(KerbAsRepCredU, sizeof(*KerbAsRepCredU));

    auto KerbAsRepCred = &KerbAsRepCredU->CloudCredential;

    KerbAsRepCred->Type                 = KERB_AS_REP_CREDENTIAL_TYPE_CLOUD;
    KerbAsRepCred->Flags                = 0;
    KerbAsRepCred->TgtMessageOffset     = sizeof(*KerbAsRepCred);
    KerbAsRepCred->TgtMessageSize       = (ULONG)TktBridgeCreds->AsRep.length;
    KerbAsRepCred->TgtClientKeyOffset   = sizeof(*KerbAsRepCred) + KerbAsRepCred->TgtMessageSize;
    KerbAsRepCred->TgtClientKeySize     = (ULONG)TktBridgeCreds->AsReplyKey.keyvalue.length;
    KerbAsRepCred->TgtKeyType           = TktBridgeCreds->AsReplyKey.keytype;

    memcpy((PBYTE)KerbAsRepCred + KerbAsRepCred->TgtMessageOffset,
           TktBridgeCreds->AsRep.data, TktBridgeCreds->AsRep.length);
    memcpy((PBYTE)KerbAsRepCred + KerbAsRepCred->TgtClientKeyOffset,
           TktBridgeCreds->AsReplyKey.keyvalue.data, TktBridgeCreds->AsReplyKey.keyvalue.length);
  
    LsaSpFunctionTable->LsaUnprotectMemory((PBYTE)KerbAsRepCred + KerbAsRepCred->TgtClientKeyOffset,
                                           KerbAsRepCred->TgtClientKeySize);


    *pKerbAsRepCred = KerbAsRepCredU;

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static PCWSTR
LogonTypeMap[] = {
    L"Undefined",
    L"Invalid",
    L"Interactive",
    L"Network",
    L"Batch",
    L"Service",
    L"Proxy",
    L"Unlock",
    L"NetworkCleartext",
    L"NewCredentials",
    L"RemoteInteractive",
    L"CachedInteractive",
    L"CachedRemoteInteractive",
    L"CachedUnlock"
};

static bool
ValidateSurrogateLogonType(_In_ SECURITY_LOGON_TYPE LogonType)
{
    if ((SpParameters.MachineState & (SECPKG_STATE_DOMAIN_CONTROLLER |
                                      SECPKG_STATE_WORKSTATION)) == 0 ||
        SpParameters.DnsDomainName.Length == 0)
        return false;

    if (LogonType < UndefinedLogonType || LogonType > CachedUnlock)
        return false;

    PCWSTR wszLogonType = LogonTypeMap[LogonType];

    switch (LogonType) {
    case Interactive:
    case Unlock:
    case RemoteInteractive:
        DebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"%s surrogate logon validated", wszLogonType);
        return true;
    case CachedInteractive:
    case CachedRemoteInteractive:
    default:
        DebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"%s surrogate logon not supported", wszLogonType);
        return false;
    }
}

static bool
ValidateSurrogateLogonDomain(_In_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity)
{
    PCWSTR wszUserName = nullptr;
    PCWSTR wszDomainName = nullptr;
    UNICODE_STRING DomainName;
    SECURITY_STATUS SecStatus;
    PDS_DOMAIN_TRUSTS Domains = nullptr;
    ULONG DomainCount;

    if (AuthIdentity == nullptr)
        return false;

    auto cleanup = wil::scope_exit([&]() {
        NetApiBufferFree(Domains);
        SspiLocalFree((PVOID)wszUserName);
        SspiLocalFree((PVOID)wszDomainName);
                                   });

    SecStatus = SspiEncodeAuthIdentityAsStrings(AuthIdentity, &wszUserName,
                                                &wszDomainName, nullptr);    
    if (SecStatus != SEC_E_OK ||
        wszDomainName == nullptr || wszDomainName[0] == L'\0')
        return false;

    RtlInitUnicodeString(&DomainName, wszDomainName);

    if (IsLocalHost(&DomainName))
        return false;

    if ((APFlags & TKTBRIDGEAP_FLAG_PRIMARY_DOMAIN) == 0) {
        if (RtlEqualUnicodeString(&SpParameters.DnsDomainName, &DomainName, TRUE) ||
            RtlEqualUnicodeString(&SpParameters.DomainName, &DomainName, TRUE))
            return false;
    }

    if ((APFlags & TKTBRIDGEAP_FLAG_TRUSTED_DOMAINS) == 0) {
        if (DsEnumerateDomainTrusts(nullptr,
                                    DS_DOMAIN_IN_FOREST | DS_DOMAIN_NATIVE_MODE,
                                    &Domains,
                                    &DomainCount) == ERROR_SUCCESS) {
            for (ULONG i = 0; i < DomainCount; i++) {
                PDS_DOMAIN_TRUSTS Domain = &Domains[i];

                if (_wcsicmp(wszDomainName, Domain->DnsDomainName) == 0 ||
                    _wcsicmp(wszDomainName, Domain->NetbiosDomainName) == 0)
                    return false;
            }
        }
    }

    return true;
}

static NTSTATUS _Success_(return == STATUS_SUCCESS)
GetPreauthInitCreds(_In_ SECURITY_LOGON_TYPE LogonType,
                    _In_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity,
                    _In_ PLUID LogonID,
                    _Out_ PTKTBRIDGEAP_CREDS *pTktBridgeCreds,
                    _Out_ PNTSTATUS SubStatus)
{
    NTSTATUS Status;
    SECURITY_STATUS SecStatus;
    PTKTBRIDGEAP_CREDS TktBridgeCreds = nullptr;
    UNICODE_STRING RealmName;

    *pTktBridgeCreds = nullptr;
    *SubStatus = STATUS_SUCCESS;

    RtlInitUnicodeString(&RealmName, NULL);

    auto cleanup = wil::scope_exit([&]() {
        DereferencePreauthInitCreds(TktBridgeCreds);
        RtlFreeUnicodeString(&RealmName);
                                   });
    TktBridgeCreds = (PTKTBRIDGEAP_CREDS)WIL_AllocateMemory(sizeof(*TktBridgeCreds));
    RETURN_NTSTATUS_IF_NULL_ALLOC(TktBridgeCreds);

    ZeroMemory(TktBridgeCreds, sizeof(*TktBridgeCreds));
    TktBridgeCreds->RefCount = 1;

    // FIXME where is RtlAllocateUnicodeString
    Status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
                                       &SpParameters.DnsDomainName, &RealmName);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = RtlUpcaseUnicodeString(&RealmName, &SpParameters.DnsDomainName, FALSE);
    RETURN_IF_NTSTATUS_FAILED(Status);

    auto KrbError = SspiPreauthGetInitCreds(RealmName.Buffer,
                                            APRestrictPackage,
                                            APKdcHostName,
                                            nullptr,
                                            AuthIdentity,
                                            &TktBridgeCreds->InitiatorName,
                                            &TktBridgeCreds->ExpiryTime,
                                            &TktBridgeCreds->AsRep,
                                            &TktBridgeCreds->AsReplyKey,
                                            &SecStatus);
    Status = KrbErrorToNtStatus(KrbError, SubStatus);
    if (NT_SUCCESS(Status)) {
        LsaSpFunctionTable->LsaProtectMemory(TktBridgeCreds->AsReplyKey.keyvalue.data,
                                             (ULONG)TktBridgeCreds->AsReplyKey.keyvalue.length);

        // save user and domain name for cache
        SecStatus = SspiEncodeAuthIdentityAsStrings(AuthIdentity,
                                                    &TktBridgeCreds->UserName,
                                                    &TktBridgeCreds->DomainName,
                                                    nullptr);
        RETURN_IF_NTSTATUS_FAILED(SecStatus);

        ReferencePreauthInitCreds(TktBridgeCreds);
        *pTktBridgeCreds = TktBridgeCreds;
    } else {
        if (SecStatus == SEC_E_NO_CREDENTIALS ||
            SecStatus == SEC_E_UNKNOWN_CREDENTIALS)
            Status = STATUS_LOGON_FAILURE;
        else if (SecStatus == SEC_E_WRONG_CREDENTIAL_HANDLE)
            Status = STATUS_WRONG_CREDENTIAL_HANDLE;
        // Otherwise, don't try to return SecStatus directly as it will not
        // surface a useful error message in the logon UI.
    }

    RETURN_NTSTATUS(Status);
}

static NTSTATUS _Success_(return == STATUS_SUCCESS)
AddSurrogateLogonEntry(_Inout_ PSECPKG_SURROGATE_LOGON SurrogateLogon,
                       _Inout_ PTKTBRIDGEAP_CREDS TktBridgeCreds)
{
    auto Entries = (PSECPKG_SURROGATE_LOGON_ENTRY)
        LsaSpFunctionTable->AllocateLsaHeap((SurrogateLogon->EntryCount + 1) *
                                            sizeof(SECPKG_SURROGATE_LOGON_ENTRY));
    RETURN_NTSTATUS_IF_NULL_ALLOC(Entries);

    if (SurrogateLogon->Entries != nullptr) {
        memcpy(Entries, SurrogateLogon->Entries,
               SurrogateLogon->EntryCount * sizeof(SECPKG_SURROGATE_LOGON_ENTRY));
        LsaSpFunctionTable->FreeLsaHeap(SurrogateLogon->Entries);
    }
    SurrogateLogon->Entries = Entries;

    auto Entry = &SurrogateLogon->Entries[SurrogateLogon->EntryCount];

    auto SurrogateLogonData = (PKERB_SURROGATE_LOGON_DATA)
        LsaSpFunctionTable->AllocateLsaHeap(sizeof(KERB_SURROGATE_LOGON_DATA));
    ZeroMemory(SurrogateLogonData, sizeof(*SurrogateLogonData));

    ReferencePreauthInitCreds(TktBridgeCreds);

    SurrogateLogonData->RetrieveAsRepCredential = RetrievePreauthInitCreds;
    SurrogateLogonData->PackageData = TktBridgeCreds;

    Entry->Type = KERB_SURROGATE_LOGON_TYPE;
    Entry->Data = SurrogateLogonData;

    SurrogateLogon->EntryCount++;

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

NTSTATUS
PreLogonUserSurrogate(_In_ PLSA_CLIENT_REQUEST ClientRequest,
                      _In_ SECURITY_LOGON_TYPE LogonType,
                      _In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                      _In_ PVOID ClientBufferBase,
                      _In_ ULONG SubmitBufferSize,
                      _Inout_ PSECPKG_SURROGATE_LOGON SurrogateLogon,
                      _Out_ PNTSTATUS SubStatus)
{
    NTSTATUS Status;
    SECURITY_STATUS SecStatus = SEC_E_NO_CONTEXT;
    PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity = nullptr;
    PTKTBRIDGEAP_CREDS TktBridgeCreds = nullptr;
    LUID UnlockLogonID;

    *SubStatus = STATUS_SUCCESS;

    auto cleanup = wil::scope_exit([&]() {
        SspiFreeAuthIdentity(AuthIdentity);
        DereferencePreauthInitCreds(TktBridgeCreds);
                                   });

    if (ProtocolSubmitBuffer == nullptr || SubmitBufferSize == 0 ||
        SubStatus == nullptr || SurrogateLogon == nullptr)
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);

    if (SurrogateLogon->Version != SECPKG_SURROGATE_LOGON_VERSION_1)
        RETURN_NTSTATUS(STATUS_UNKNOWN_REVISION);

    if (!ValidateSurrogateLogonType(LogonType))
        RETURN_NTSTATUS(STATUS_SUCCESS);

    Status = ConvertLogonSubmitBufferToAuthIdentity(ProtocolSubmitBuffer,
                                                    SubmitBufferSize,
                                                    &AuthIdentity,
                                                    &UnlockLogonID);
    RETURN_IF_NTSTATUS_FAILED(Status);

    if (!ValidateSurrogateLogonDomain(AuthIdentity))
        RETURN_NTSTATUS(STATUS_SUCCESS);

    Status = LocateCachedPreauthCredentials(LogonType, AuthIdentity,
                                            &SurrogateLogon->SurrogateLogonID,
                                            &TktBridgeCreds, SubStatus);
    if (!NT_SUCCESS(Status)) {
        Status = GetPreauthInitCreds(LogonType, AuthIdentity,
                                     &SurrogateLogon->SurrogateLogonID,
                                     &TktBridgeCreds, SubStatus);
        RETURN_IF_NTSTATUS_FAILED(Status);
    }

    Status = AddSurrogateLogonEntry(SurrogateLogon, TktBridgeCreds);
    RETURN_IF_NTSTATUS_FAILED(Status);

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static PTKTBRIDGEAP_CREDS
FindSurrogateLogonCreds(_In_ PSECPKG_SURROGATE_LOGON_ENTRY Entry)
{
    if (!IsEqualGUID(Entry->Type, KERB_SURROGATE_LOGON_TYPE))
        return nullptr; // not surrogate logon entry

    auto SurrogateLogonData = (PKERB_SURROGATE_LOGON_DATA)Entry->Data;
    if (SurrogateLogonData->RetrieveAsRepCredential != &RetrievePreauthInitCreds)
        return nullptr; // not ours

    return (PTKTBRIDGEAP_CREDS)SurrogateLogonData->PackageData;
}

NTSTATUS
PostLogonUserSurrogate(_In_ PLSA_CLIENT_REQUEST ClientRequest,
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
    //
    // Find surrogate logon entry and release, validating callback so we do
    // not release another package's credentials
    //
    if (SurrogateLogon == nullptr)
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);

    for (ULONG i = 0; i < SurrogateLogon->EntryCount; i++) {
        PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity = nullptr;
        PSECPKG_SURROGATE_LOGON_ENTRY Entry = &SurrogateLogon->Entries[i];
        auto TktBridgeCreds = FindSurrogateLogonCreds(Entry);

        if (TktBridgeCreds == nullptr)
            continue;

        if ((TktBridgeCreds->Flags & TKTBRIDGEAP_CREDS_FLAG_CACHED) == 0 &&
            NT_SUCCESS(ConvertLogonSubmitBufferToAuthIdentity(ProtocolSubmitBuffer,
                                                              SubmitBufferSize,
                                                              &AuthIdentity,
                                                              nullptr))) {
            CacheAddPreauthCredentials(LogonType,
                                       AuthIdentity,
                                       LogonId,
                                       TktBridgeCreds);
            SspiFreeAuthIdentity(AuthIdentity);
        } else if ((TktBridgeCreds->Flags & TKTBRIDGEAP_CREDS_FLAG_CACHED) &&
                (!NT_SUCCESS(Status) || IsPreauthCredsExpired(TktBridgeCreds))) {    
            CacheRemovePreauthCredentials(LogonType,
                                          LogonId,
                                          TktBridgeCreds);
        }

        DereferencePreauthInitCreds(TktBridgeCreds);

        auto SurrogateLogonData = (PKERB_SURROGATE_LOGON_DATA)Entry->Data;
        SurrogateLogonData->PackageData = nullptr;
    }

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

#if 0
NTSTATUS
LogonUserEx3(_In_ PLSA_CLIENT_REQUEST ClientRequest,
             _In_ SECURITY_LOGON_TYPE LogonType,
             _In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
             _In_ PVOID ClientBufferBase,
             _In_ ULONG SubmitBufferSize,
             _Inout_ PSECPKG_SURROGATE_LOGON SurrogateLogon,
             _Outptr_result_bytebuffer_(*ProfileBufferSize) PVOID *ProfileBuffer,
             _Out_ PULONG ProfileBufferSize,
             _Out_ PLUID LogonId,
             _Out_ PNTSTATUS SubStatus,
             _Out_ PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
             _Outptr_ PVOID  TokenInformation,
             _Out_ PUNICODE_STRING *AccountName,
             _Out_ PUNICODE_STRING *AuthenticatingAuthority,
             _Out_ PUNICODE_STRING *MachineName,
             _Out_ PSECPKG_PRIMARY_CRED PrimaryCredentials,
             _Outptr_ PSECPKG_SUPPLEMENTAL_CRED_ARRAY *SupplementalCredentials)
{
    if (SurrogateLogon == nullptr)
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);

    for (ULONG i = 0; i < SurrogateLogon->EntryCount; i++) {
        PSECPKG_SURROGATE_LOGON_ENTRY Entry = &SurrogateLogon->Entries[i];
        auto TktBridgeCreds = ValidateSurrogateLogonEntry(Entry);

        if (TktBridgeCreds == nullptr)
            continue;

        auto Status = RetypeLogonSubmitBuffer(ClientRequest,
                                              ProtocolSubmitBuffer,
                                              ClientBufferBase,
                                              SubmitBufferSize);
    }

    RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);
}
#endif
