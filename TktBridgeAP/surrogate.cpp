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
                         ULONG dwFlags,
                         PKERB_AS_REP_CREDENTIAL *pKerbAsRepCred)
{
    auto TktBridgeCreds = (PCTKTBRIDGEAP_CREDS)PackageData;
    PKERB_AS_REP_CREDENTIAL KerbAsRepCred;
    ULONG cbKerbAsRepCred;

    DebugTrace(WINEVENT_LEVEL_VERBOSE,
               L"RetrievePreauthInitCreds: LogonID %08x.%08x Flags %04x",
               LogonID.LowPart, LogonID.HighPart,
               dwFlags);

    if (TktBridgeCreds == nullptr)
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);

    cbKerbAsRepCred = sizeof(*KerbAsRepCred) +
        (ULONG)TktBridgeCreds->AsRep.length +
        (ULONG)TktBridgeCreds->AsReplyKey.keyvalue.length;

    KerbAsRepCred = (PKERB_AS_REP_CREDENTIAL)LsaSpFunctionTable->AllocateLsaHeap(cbKerbAsRepCred);
    RETURN_NTSTATUS_IF_NULL_ALLOC(KerbAsRepCred);

    ZeroMemory(KerbAsRepCred, sizeof(*KerbAsRepCred));

    KerbAsRepCred->Version              = KERB_AS_REP_CREDENTIAL_VERSION_1;
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


    *pKerbAsRepCred = KerbAsRepCred;

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
    case CachedInteractive:
    case CachedRemoteInteractive:
        DebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"%s surrogate logon validated", wszLogonType);
        return true;
    default:
        DebugTrace(WINEVENT_LEVEL_INFO,
                   L"%s surrogate logon not supported", wszLogonType);
        return false;
    }
}

// for some reason this is not getting imported with the SYSTEM partition
extern "C"
DWORD __stdcall NetApiBufferFree(_Frees_ptr_opt_ LPVOID Buffer);

static bool
ValidateSurrogateLogonDomain(_In_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity)
{
    PCWSTR wszUserName = nullptr;
    PCWSTR wszDomainName = nullptr;
    UNICODE_STRING DomainName;
    SECURITY_STATUS SecStatus;
    PDS_DOMAIN_TRUSTS Domains = nullptr;
    ULONG DomainCount;

    auto cleanup = wil::scope_exit([&]() {
        NetApiBufferFree(Domains);
        SspiLocalFree((PVOID)wszUserName);
        SspiLocalFree((PVOID)wszDomainName);
                                   });

    SecStatus = SspiEncodeAuthIdentityAsStrings(AuthIdentity, &wszUserName,
                                                &wszDomainName, nullptr);
    RETURN_IF_FAILED(SecStatus);

    if (wszDomainName == nullptr)
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

NTSTATUS _Success_(return == STATUS_SUCCESS)
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

    Status = RtlUpcaseUnicodeString(&RealmName, &SpParameters.DnsDomainName, TRUE);
    RETURN_IF_NTSTATUS_FAILED(Status);

    assert(RealmName.MaximumLength == RealmName.Length + sizeof(WCHAR));
    RealmName.Buffer[RealmName.Length / sizeof(WCHAR)] = L'\0';

    auto KrbError = SspiPreauthGetInitCreds(RealmName.Buffer,
                                            APRestrictPackage,
                                            APKdcHostName,
                                            LogonID,
                                            AuthIdentity,
                                            &TktBridgeCreds->ClientName,
                                            &TktBridgeCreds->AsRep,
                                            &TktBridgeCreds->AsReplyKey,
                                            &SecStatus);
    Status = KrbErrorToNtStatus(KrbError, SubStatus);
    if (NT_SUCCESS(Status)) {
        LsaSpFunctionTable->LsaProtectMemory(TktBridgeCreds->AsReplyKey.keyvalue.data,
                                             (ULONG)TktBridgeCreds->AsReplyKey.keyvalue.length);

        ReferencePreauthInitCreds(TktBridgeCreds);
        *pTktBridgeCreds = TktBridgeCreds;
    } else {
        if (SecStatus != SEC_E_NO_CONTEXT)
            Status = SecStatus; // FIXME is this safe to return
    }

    RETURN_NTSTATUS(Status);
}

NTSTATUS _Success_(return == STATUS_SUCCESS)
AddSurrogateLogonEntry(_Inout_ PSECPKG_SURROGATE_LOGON SurrogateLogon,
                       _In_ PTKTBRIDGEAP_CREDS TktBridgeCreds)
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

static int Flag = 0;

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

    if (Flag == 0)
        RETURN_NTSTATUS(STATUS_SUCCESS);
    
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
        PSECPKG_SURROGATE_LOGON_ENTRY Entry = &SurrogateLogon->Entries[i];

        if (!IsEqualGUID(Entry->Type, KERB_SURROGATE_LOGON_TYPE))
            continue;

        auto SurrogateLogonData = (PKERB_SURROGATE_LOGON_DATA)Entry->Data;
        if (SurrogateLogonData->RetrieveAsRepCredential != &RetrievePreauthInitCreds)
            continue; // not ours

        auto TktBridgeCreds = (PTKTBRIDGEAP_CREDS)SurrogateLogonData->PackageData;

        if (NT_SUCCESS(Status) &&
            (TktBridgeCreds->Flags & TKTBRIDGEAP_CREDS_FLAG_CACHED) == 0)
            CacheAddPreauthCredentials(AccountName,
                                       AuthenticatingAuthority,
                                       PrimaryCredentials,
                                       LogonId,
                                       TktBridgeCreds);
        else if (!NT_SUCCESS(Status) &&
                 (TktBridgeCreds->Flags & TKTBRIDGEAP_CREDS_FLAG_CACHED))
            CacheRemovePreauthCredentials(AccountName,
                                          AuthenticatingAuthority,
                                          LogonId,
                                          TktBridgeCreds);

        DereferencePreauthInitCreds(TktBridgeCreds);

        // FIXME who frees SurrogateLogonData?
    }

    RETURN_NTSTATUS(STATUS_SUCCESS);
}
