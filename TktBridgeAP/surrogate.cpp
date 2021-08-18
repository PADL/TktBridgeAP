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

VOID
FreePreauthInitCreds(_Inout_ PPREAUTH_INIT_CREDS Creds)
{
    if (Creds == nullptr)
        return;

    WIL_FreeMemory(Creds->ClientName);
    krb5_data_free(&Creds->AsRep);
    SecureZeroMemory(Creds->AsReplyKey.keyvalue.data, Creds->AsReplyKey.keyvalue.length);
    krb5_free_keyblock_contents(nullptr, &Creds->AsReplyKey);
    ZeroMemory(Creds, sizeof(*Creds));
    WIL_FreeMemory(Creds);
}

extern "C"
static NTSTATUS NTAPI
RetrievePreauthInitCreds(LUID LogonID,
                         PVOID PackageData,
                         ULONG dwFlags,
                         PKERB_AS_REP_CREDENTIAL *pKerbAsRepCred)
{
    NTSTATUS Status;
    PPREAUTH_INIT_CREDS PreauthCreds = (PPREAUTH_INIT_CREDS)PackageData;
    PKERB_AS_REP_CREDENTIAL KerbAsRepCred;
    SIZE_T cbKerbAsRepCred;

    if (PreauthCreds == nullptr)
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);

    cbKerbAsRepCred = sizeof(*KerbAsRepCred) +
        PreauthCreds->AsRep.length +
        PreauthCreds->AsReplyKey.keyvalue.length;

    KerbAsRepCred = (PKERB_AS_REP_CREDENTIAL)LsaSpFunctionTable->AllocateLsaHeap(cbKerbAsRepCred);
    RETURN_NTSTATUS_IF_NULL_ALLOC(KerbAsRepCred);

    ZeroMemory(KerbAsRepCred, sizeof(*KerbAsRepCred));

    KerbAsRepCred->Version = KERB_AS_REP_CREDENTIAL_VERSION_1;
    KerbAsRepCred->Flags = 0;
    KerbAsRepCred->TgtMessageOffset = sizeof(*KerbAsRepCred);
    KerbAsRepCred->TgtMessageSize = (ULONG)PreauthCreds->AsRep.length;
    KerbAsRepCred->TgtClientKeyOffset = sizeof(*KerbAsRepCred) + KerbAsRepCred->TgtMessageSize;
    KerbAsRepCred->TgtClientKeySize = (ULONG)PreauthCreds->AsReplyKey.keyvalue.length;
    KerbAsRepCred->TgtKeyType = PreauthCreds->AsReplyKey.keytype;

    memcpy((PBYTE)KerbAsRepCred + KerbAsRepCred->TgtMessageOffset,
           PreauthCreds->AsRep.data, PreauthCreds->AsRep.length);
    memcpy((PBYTE)KerbAsRepCred + KerbAsRepCred->TgtClientKeyOffset,
           PreauthCreds->AsReplyKey.keyvalue.data, PreauthCreds->AsReplyKey.keyvalue.length);
  
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

static NTSTATUS
ValidateSurrogateLogonType(_In_ SECURITY_LOGON_TYPE LogonType)
{
    if (LogonType < UndefinedLogonType || LogonType > CachedUnlock)
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);

    PCWSTR wszLogonType = LogonTypeMap[LogonType];

    switch (LogonType) {
    case Interactive:
    case Unlock:
    case RemoteInteractive:
    case CachedInteractive:
    case CachedRemoteInteractive:
        DebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"%s surrogate logon validated", wszLogonType);
        RETURN_NTSTATUS(STATUS_SUCCESS);
    default:
        DebugTrace(WINEVENT_LEVEL_INFO,
                   L"%s surrogate logon not supported", wszLogonType);
        RETURN_NTSTATUS(STATUS_LOGON_TYPE_NOT_GRANTED);
    }
}

static NTSTATUS
CanonicalizeSurrogateLogonAuthIdentity(_In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                       _In_ PVOID ClientBufferBase,
                                       _In_ ULONG SubmitBufferSize,
                                       _Out_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE *pAuthIdentity)
{
    *pAuthIdentity = nullptr;
    RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);
}

// for some reason this is not getting imported with the SYSTEM partition
extern "C"
DWORD __stdcall NetApiBufferFree(_Frees_ptr_opt_ LPVOID Buffer);

static NTSTATUS
ValidateSurrogateLogonDomain(_In_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity)
{
    PCWSTR wszDomainName = nullptr;
    UNICODE_STRING DomainName;
    SECURITY_STATUS SecStatus;
    PDS_DOMAIN_TRUSTS Domains = nullptr;
    ULONG DomainCount;

    auto cleanup = wil::scope_exit([&]() {
        NetApiBufferFree(Domains);
        SspiLocalFree((PVOID)wszDomainName);
                                   });

    SecStatus = SspiEncodeAuthIdentityAsStrings(AuthIdentity, nullptr,
                                                &wszDomainName, nullptr);
    RETURN_IF_FAILED(SecStatus);

    RtlInitUnicodeString(&DomainName, wszDomainName);

    if (RtlEqualUnicodeString(&SpParameters.DnsDomainName, &DomainName, TRUE) ||
        RtlEqualUnicodeString(&SpParameters.DomainName, &DomainName, TRUE))
        RETURN_NTSTATUS(STATUS_NO_SUCH_USER);
 
    if (DsEnumerateDomainTrusts(NULL,
                                DS_DOMAIN_IN_FOREST | DS_DOMAIN_NATIVE_MODE,
                                &Domains,
                                &DomainCount) == ERROR_SUCCESS) {
        for (ULONG i = 0; i < DomainCount; i++) {
            PDS_DOMAIN_TRUSTS Domain = &Domains[i];

            if (_wcsicmp(wszDomainName, Domain->DnsDomainName) == 0 ||
                _wcsicmp(wszDomainName, Domain->NetbiosDomainName) == 0)
                RETURN_NTSTATUS(STATUS_NO_SUCH_USER);
        }
    }

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
    PPREAUTH_INIT_CREDS PreauthCreds = nullptr;

    auto cleanup = wil::scope_exit([&]() {
        SspiFreeAuthIdentity(AuthIdentity);
        FreePreauthInitCreds(PreauthCreds);
                                   });

    //
    // Validate parameters: surrogate version, logon type; STATUS_INVALID_PARAMETER if invalid
    //
    if (SurrogateLogon == nullptr ||
        SurrogateLogon->Version != SECPKG_SURROGATE_LOGON_VERSION_1)
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);

    if ((SpParameters.MachineState & (SECPKG_STATE_DOMAIN_CONTROLLER |
                                      SECPKG_STATE_WORKSTATION)) == 0 ||
        SpParameters.DnsDomainName.Buffer == nullptr)
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);

    Status = ValidateSurrogateLogonType(LogonType);
    RETURN_IF_NTSTATUS_FAILED(Status);

    //
    // Canonicalize logon identity to opaque auth identity
    //
    Status = CanonicalizeSurrogateLogonAuthIdentity(ProtocolSubmitBuffer,
                                                    ClientBufferBase,
                                                    SubmitBufferSize,
                                                    &AuthIdentity);
    RETURN_IF_NTSTATUS_FAILED(Status);

    //
    // Check domain name from primary domain information and possibly trusted domains to
    // ensure that we do not try to replace native Kerberos logon
    //
    Status = ValidateSurrogateLogonDomain(AuthIdentity);
    RETURN_IF_NTSTATUS_FAILED(Status);

    //
    // If ticket cache enabled, look in local ticket cache for a partial ticket that
    // matches the auth identity and can be decrypted using the primary credentials
    // and has not expired
    //
    Status = AcquireCachedPreauthCredentials(LogonType, AuthIdentity, &PreauthCreds);
    if (!NT_SUCCESS(Status)) {
        //
        // Call SspiPreauthGetInitCreds() with the machine's primary domain and the
        // auth identity. (The primary domain is uppercased to a Kerberos realm name
        // at initialization.)
        //
        PreauthCreds = (PPREAUTH_INIT_CREDS)WIL_AllocateMemory(sizeof(*PreauthCreds));
        RETURN_NTSTATUS_IF_NULL_ALLOC(PreauthCreds);

        Status = KrbErrorToNtStatus(SspiPreauthGetInitCreds(SpParameters.DnsDomainName.Buffer,
                                                            APRestrictPackage,
                                                            APKdcHostName,
                                                            &SurrogateLogon->SurrogateLogonID,
                                                            AuthIdentity,
                                                            &PreauthCreds->ClientName,
                                                            &PreauthCreds->AsRep,
                                                            &PreauthCreds->AsReplyKey,
                                                            &SecStatus));
        if (!NT_SUCCESS(Status) && SecStatus != SEC_E_NO_CONTEXT) {
            Status = SecStatus; // FIXME do we need to map this to a NTSTATUS
        }
        RETURN_IF_NTSTATUS_FAILED(Status);

        LsaSpFunctionTable->LsaProtectMemory(PreauthCreds->AsReplyKey.keyvalue.data,
                                             PreauthCreds->AsReplyKey.keyvalue.length);

        CachePreauthCredentials(AuthIdentity, PreauthCreds);
    }

    //
    // Allocate a surrogate entry containing AS-REP credentials
    //
    auto Entries = (PSECPKG_SURROGATE_LOGON_ENTRY)
        LsaSpFunctionTable->AllocateLsaHeap((SurrogateLogon->EntryCount + 1) *
                                            sizeof(SECPKG_SURROGATE_LOGON_ENTRY));
    RETURN_NTSTATUS_IF_NULL_ALLOC(Entries);

    if (SurrogateLogon->Entries != nullptr)
        memcpy(Entries, SurrogateLogon->Entries, SurrogateLogon->EntryCount * sizeof(SECPKG_SURROGATE_LOGON_ENTRY));
    SurrogateLogon->Entries = Entries;

    auto Entry = &SurrogateLogon->Entries[SurrogateLogon->EntryCount];

    auto SurrogateLogonData = (PKERB_SURROGATE_LOGON_DATA)
        LsaSpFunctionTable->AllocateLsaHeap(sizeof(KERB_SURROGATE_LOGON_DATA));
    ZeroMemory(SurrogateLogonData, sizeof(*SurrogateLogonData));

    SurrogateLogonData->RetrieveAsRepCredential = RetrievePreauthInitCreds;
    SurrogateLogonData->PackageData = PreauthCreds;
    PreauthCreds = nullptr; // don't free on return

    Entry->Type = KERB_SURROGATE_LOGON_TYPE;
    Entry->Data = SurrogateLogonData;

    SurrogateLogon->EntryCount++;

    //
    // If ticket cache enabled, derive PBKDF2 key from primary credentials and
    // store AS-REP in ticket cache
    //

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

        FreePreauthInitCreds((PPREAUTH_INIT_CREDS)SurrogateLogonData->PackageData);
        SurrogateLogonData->PackageData = nullptr;
    }

    RETURN_NTSTATUS(STATUS_SUCCESS);
}