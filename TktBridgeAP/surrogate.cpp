/*
 * Copyright (c) 2021, PADL Software Pty Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of PADL Software nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL PADL SOFTWARE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "TktBridgeAP.h"

static _Success_(return == STATUS_SUCCESS) NTSTATUS
MaybeRefreshTktBridgeCreds(const LUID &LogonId,
                           PTKTBRIDGEAP_CREDS *pTktBridgeCreds);


/*
 * Callback function called from Kerberos package that passes TktBridgeAP-
 * specific private data and retrieves a KERB_AS_REP_CREDENTIAL
 * containing the AS-REP and reply key
 */
extern "C"
static NTSTATUS NTAPI
RetrieveTktBridgeCreds(LUID LogonId,
                       PVOID PackageData,
                       ULONG Flags,
                       PKERB_AS_REP_CREDENTIAL *pKerbAsRepCred)
{
    PTKTBRIDGEAP_CREDS TktBridgeCreds = (PTKTBRIDGEAP_CREDS)PackageData;
    ULONG cbKerbAsRepCred;
    NTSTATUS Status;

    auto cleanup = wil::scope_exit([&]() {
        DereferenceTktBridgeCreds(TktBridgeCreds);
                                   });

    if (TktBridgeCreds != nullptr) {
        ReferenceTktBridgeCreds(TktBridgeCreds);
    } else {
        Status = FindCredForLogonSession(LogonId, &TktBridgeCreds);
        RETURN_IF_NTSTATUS_FAILED(Status);

        Status = MaybeRefreshTktBridgeCreds(LogonId, &TktBridgeCreds);
        RETURN_IF_NTSTATUS_FAILED(Status);
    }

    DebugTrace(WINEVENT_LEVEL_VERBOSE,
               L"RetrieveTktBridgeCreds: LogonId %08x.%08x Flags %08x "
               L"AsRep Length %u Reply KeyLength %u KeyType %u",
               LogonId.LowPart,
               LogonId.HighPart,
               Flags,
               TktBridgeCreds->AsRep.length,
               TktBridgeCreds->AsReplyKey.keyvalue.length,
               TktBridgeCreds->AsReplyKey.keytype);

    cbKerbAsRepCred = sizeof(KERB_AS_REP_CREDENTIAL) +
        (ULONG)TktBridgeCreds->AsRep.length +
        (ULONG)TktBridgeCreds->AsReplyKey.keyvalue.length;

    auto KerbAsRepCredU = static_cast<PKERB_AS_REP_CREDENTIAL>(LsaSpFunctionTable->AllocateLsaHeap(cbKerbAsRepCred));
    RETURN_NTSTATUS_IF_NULL_ALLOC(KerbAsRepCredU);

    ZeroMemory(KerbAsRepCredU, sizeof(*KerbAsRepCredU));

    if (APFlags & TKTBRIDGEAP_FLAG_CLOUD_CREDS) {
        auto KerbAsRepCred = &KerbAsRepCredU->CloudTgtCredential;
        auto KerbAsRepCredBase = reinterpret_cast<PBYTE>(KerbAsRepCred);

        KerbAsRepCred->Type                 = KERB_AS_REP_CREDENTIAL_TYPE_CLOUD_TGT;
        KerbAsRepCred->TgtMessageOffset     = sizeof(*KerbAsRepCred);
        KerbAsRepCred->TgtMessageSize       = (ULONG)TktBridgeCreds->AsRep.length;
        KerbAsRepCred->TgtClientKeyOffset   = sizeof(*KerbAsRepCred) + KerbAsRepCred->TgtMessageSize;
        KerbAsRepCred->TgtClientKeySize     = (ULONG)TktBridgeCreds->AsReplyKey.keyvalue.length;
        KerbAsRepCred->TgtKeyType           = TktBridgeCreds->AsReplyKey.keytype;

        memcpy(KerbAsRepCredBase + KerbAsRepCred->TgtMessageOffset,
               TktBridgeCreds->AsRep.data, TktBridgeCreds->AsRep.length);
        memcpy(KerbAsRepCredBase + KerbAsRepCred->TgtClientKeyOffset,
               TktBridgeCreds->AsReplyKey.keyvalue.data, TktBridgeCreds->AsReplyKey.keyvalue.length);

        LsaSpFunctionTable->LsaUnprotectMemory(KerbAsRepCredBase + KerbAsRepCred->TgtClientKeyOffset,
                                               KerbAsRepCred->TgtClientKeySize);
    } else {
        auto KerbAsRepCred = &KerbAsRepCredU->TgtCredential;
        auto KerbAsRepCredBase = reinterpret_cast<PBYTE>(KerbAsRepCred);

        KerbAsRepCred->Type                 = KERB_AS_REP_CREDENTIAL_TYPE_TGT;
        KerbAsRepCred->TgtMessageOffset     = sizeof(*KerbAsRepCred);
        KerbAsRepCred->TgtMessageSize       = (ULONG)TktBridgeCreds->AsRep.length;
        KerbAsRepCred->TgtClientKeyOffset   = sizeof(*KerbAsRepCred) + KerbAsRepCred->TgtMessageSize;
        KerbAsRepCred->TgtClientKeySize     = (ULONG)TktBridgeCreds->AsReplyKey.keyvalue.length;
        KerbAsRepCred->TgtKeyType           = TktBridgeCreds->AsReplyKey.keytype;

        memcpy(KerbAsRepCredBase + KerbAsRepCred->TgtMessageOffset,
               TktBridgeCreds->AsRep.data, TktBridgeCreds->AsRep.length);
        memcpy(KerbAsRepCredBase + KerbAsRepCred->TgtClientKeyOffset,
               TktBridgeCreds->AsReplyKey.keyvalue.data, TktBridgeCreds->AsReplyKey.keyvalue.length);

        LsaSpFunctionTable->LsaUnprotectMemory(KerbAsRepCredBase + KerbAsRepCred->TgtClientKeyOffset,
                                               KerbAsRepCred->TgtClientKeySize);
    }

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
    if (LogonType < UndefinedLogonType || LogonType > CachedUnlock)
        return false;

    auto wszLogonType = LogonTypeMap[LogonType];

    if ((SpParameters.MachineState & (SECPKG_STATE_DOMAIN_CONTROLLER |
                                      SECPKG_STATE_WORKSTATION)) == 0 ||
        SpParameters.DnsDomainName.Length == 0) {
        DebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"%s surrogate logon unavailable on standalone workstations",
                   wszLogonType);
        return false;
    }

    switch (LogonType) {
    case Interactive:
    case Unlock:
    case RemoteInteractive:
        DebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"%s surrogate logon validated", wszLogonType);
        return true;
    case CachedInteractive:
    case CachedRemoteInteractive:
        DebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"%s surrogate logon not supported", wszLogonType);
        return false;
    default:
        return false; // don't log
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

    /*
     * If a list of domain suffixes is configured in the registry,
     * use that as authoritative.
     */
    if (APDomainSuffixes != nullptr) {
        for (PWSTR *pDomainSuffix = APDomainSuffixes;
             *pDomainSuffix != nullptr;
             pDomainSuffix++) {
            if (_wcsicmp(wszDomainName, *pDomainSuffix) == 0)
                return true;
        }

        return false;
    }

    /*
     * We don't want to get in the way of ordinary logons so by default we
     * only allow domain suffixes that are not forest domain names (i.e.
     * they must be UPN suffixes) 
     */
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
GetTktBridgeCreds(_In_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity,
                  _In_ const LUID &LogonId,
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
        DereferenceTktBridgeCreds(TktBridgeCreds);
        RtlFreeUnicodeString(&RealmName);
                                   });

    TktBridgeCreds = AllocateTktBridgeCreds();
    RETURN_NTSTATUS_IF_NULL_ALLOC(TktBridgeCreds);

    // FIXME where is RtlAllocateUnicodeString
    Status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
                                       &SpParameters.DnsDomainName, &RealmName);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = RtlUpcaseUnicodeString(&RealmName, &RealmName, FALSE);
    RETURN_IF_NTSTATUS_FAILED(Status);

    auto KrbError = GssPreauthGetInitCreds(RealmName.Buffer,
                                           APRestrictPackage,
                                           APKdcHostName,
                                           nullptr,
                                           AuthIdentity,
                                           &TktBridgeCreds->InitiatorName,
                                           &TktBridgeCreds->EndTime,
                                           &TktBridgeCreds->AsRep,
                                           &TktBridgeCreds->AsReplyKey,
                                           &SecStatus);
    Status = KrbErrorToNtStatus(KrbError, SubStatus);
    if (NT_SUCCESS(Status)) {
        LsaSpFunctionTable->LsaProtectMemory(TktBridgeCreds->AsReplyKey.keyvalue.data,
                                             (ULONG)TktBridgeCreds->AsReplyKey.keyvalue.length);

        ReferenceTktBridgeCreds(TktBridgeCreds);
        *pTktBridgeCreds = TktBridgeCreds;

        if ((APFlags & TKTBRIDGEAP_FLAG_NO_CLEAR_CRED_CACHE) == 0) {
            Status = SspiCopyAuthIdentity(AuthIdentity, &TktBridgeCreds->InitialCreds);
            RETURN_IF_NTSTATUS_FAILED(Status);

            Status = SspiEncryptAuthIdentity(TktBridgeCreds->InitialCreds);
            RETURN_IF_NTSTATUS_FAILED(Status);
        }
    } else {
        if (SecStatus == SEC_E_NO_CREDENTIALS ||
            SecStatus == SEC_E_UNKNOWN_CREDENTIALS)
            Status = STATUS_LOGON_FAILURE;
        else if (SecStatus == SEC_E_WRONG_CREDENTIAL_HANDLE)
            Status = STATUS_WRONG_CREDENTIAL_HANDLE;
        /*
         * Otherwise, don't try to return SecStatus directly as it will not
         * surface a useful error message in the logon UI.
         */
    }

    RETURN_NTSTATUS(Status);
}

static NTSTATUS _Success_(return == STATUS_SUCCESS)
AddSurrogateLogonEntry(_Inout_ PSECPKG_SURROGATE_LOGON SurrogateLogon,
                       _Inout_ PTKTBRIDGEAP_CREDS TktBridgeCreds)
{
    auto Entries = static_cast<PSECPKG_SURROGATE_LOGON_ENTRY>
        (LsaSpFunctionTable->AllocateLsaHeap((SurrogateLogon->EntryCount + 1) *
                                             sizeof(SECPKG_SURROGATE_LOGON_ENTRY)));
    RETURN_NTSTATUS_IF_NULL_ALLOC(Entries);

    if (SurrogateLogon->Entries != nullptr) {
        memcpy(Entries, SurrogateLogon->Entries,
               SurrogateLogon->EntryCount * sizeof(SECPKG_SURROGATE_LOGON_ENTRY));
        LsaSpFunctionTable->FreeLsaHeap(SurrogateLogon->Entries);
    }
    SurrogateLogon->Entries = Entries;

    auto Entry = &SurrogateLogon->Entries[SurrogateLogon->EntryCount];

    auto SurrogateLogonData = static_cast<PKERB_SURROGATE_LOGON_DATA>
        (LsaSpFunctionTable->AllocateLsaHeap(sizeof(KERB_SURROGATE_LOGON_DATA)));
    ZeroMemory(SurrogateLogonData, sizeof(*SurrogateLogonData));

    ReferenceTktBridgeCreds(TktBridgeCreds);

    SurrogateLogonData->AsRepCallback = RetrieveTktBridgeCreds;
    SurrogateLogonData->PackageData = TktBridgeCreds;

    Entry->Type = KERB_SURROGATE_LOGON_TYPE;
    Entry->Data = SurrogateLogonData;

    SurrogateLogon->EntryCount++;

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

NTSTATUS
LsaApPreLogonUserSurrogate(_In_ PLSA_CLIENT_REQUEST ClientRequest,
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
    LUID UnlockLogonId;

    *SubStatus = STATUS_SUCCESS;

    auto cleanup = wil::scope_exit([&]() {
        SspiFreeAuthIdentity(AuthIdentity);
        DereferenceTktBridgeCreds(TktBridgeCreds);
                                   });

    if (ProtocolSubmitBuffer == nullptr || SubmitBufferSize == 0 ||
        SubStatus == nullptr || SurrogateLogon == nullptr)
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);

    if (SurrogateLogon->Version != SECPKG_SURROGATE_LOGON_VERSION_1)
        RETURN_NTSTATUS(STATUS_UNKNOWN_REVISION);

    if (!ValidateSurrogateLogonType(LogonType))
        RETURN_NTSTATUS(STATUS_SUCCESS);

    Status = ConvertLogonSubmitBufferToAuthIdentity(ClientRequest,
                                                    ProtocolSubmitBuffer,
                                                    ClientBufferBase,
                                                    SubmitBufferSize,
                                                    &AuthIdentity,
                                                    &UnlockLogonId);
    RETURN_IF_NTSTATUS_FAILED(Status);

    if (!ValidateSurrogateLogonDomain(AuthIdentity))
        RETURN_NTSTATUS(STATUS_SUCCESS);

    Status = GetTktBridgeCreds(AuthIdentity,
                               SurrogateLogon->SurrogateLogonID,
                               &TktBridgeCreds,
                               SubStatus);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = AddSurrogateLogonEntry(SurrogateLogon, TktBridgeCreds);
    RETURN_IF_NTSTATUS_FAILED(Status);

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

PSECPKG_SURROGATE_LOGON_ENTRY
FindSurrogateLogonCreds(_In_ PSECPKG_SURROGATE_LOGON SurrogateLogon)
{
    if (SurrogateLogon == nullptr)
        return nullptr;

    for (ULONG i = 0; i < SurrogateLogon->EntryCount; i++) {
        PSECPKG_SURROGATE_LOGON_ENTRY Entry = &SurrogateLogon->Entries[i];

        if (!IsEqualGUID(Entry->Type, KERB_SURROGATE_LOGON_TYPE))
            continue; // not a Kerb AS-REP surrogate logon entry

        auto SurrogateLogonData = (PKERB_SURROGATE_LOGON_DATA)Entry->Data;
        if (SurrogateLogonData == nullptr ||
            SurrogateLogonData->AsRepCallback != &RetrieveTktBridgeCreds)
            continue; // must be another package

        return Entry;
    }

    return nullptr;
}

NTSTATUS
LsaApPostLogonUserSurrogate(_In_ PLSA_CLIENT_REQUEST ClientRequest,
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
    auto SurrogateEntry = FindSurrogateLogonCreds(SurrogateLogon);
    if (SurrogateEntry == nullptr)
        RETURN_NTSTATUS(STATUS_SUCCESS);

    auto SurrogateLogonData = (PKERB_SURROGATE_LOGON_DATA)SurrogateEntry->Data;
    auto TktBridgeCreds = (PTKTBRIDGEAP_CREDS)SurrogateLogonData->PackageData;
 
    if (NT_SUCCESS(Status))
        SaveCredForLogonSession(*LogonId, TktBridgeCreds);

    DereferenceTktBridgeCreds(TktBridgeCreds);
    SurrogateLogonData->PackageData = nullptr;

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

VOID
LsaApLogonTerminated(_In_ PLUID LogonId)
{
    assert(LogonId != nullptr);

    DebugTrace(WINEVENT_LEVEL_VERBOSE,
               L"LsaApLogonTerminated: LUID %08x.%08x.",
               LogonId->LowPart, LogonId->HighPart);

    RemoveCredForLogonSession(*LogonId);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
MaybeRefreshTktBridgeCreds(const LUID &LogonId,
                           PTKTBRIDGEAP_CREDS *pTktBridgeCreds)
{
    auto TktBridgeCreds = *pTktBridgeCreds;
    NTSTATUS Status, SubStatus;
    PTKTBRIDGEAP_CREDS RefreshedCreds;
    PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity = nullptr;

    auto cleanup = wil::scope_exit([&]() {
        SspiFreeAuthIdentity(AuthIdentity);
                                   });

    if (!IsTktBridgeCredsExpired(TktBridgeCreds))
        RETURN_NTSTATUS(STATUS_SUCCESS);

    if (TktBridgeCreds->InitialCreds == nullptr)
        RETURN_NTSTATUS(STATUS_NO_LOGON_SERVERS);

    Status = SspiCopyAuthIdentity(TktBridgeCreds->InitialCreds, &AuthIdentity);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = SspiDecryptAuthIdentity(AuthIdentity);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = GetTktBridgeCreds(AuthIdentity, LogonId, &RefreshedCreds, &SubStatus);
    RETURN_IF_NTSTATUS_FAILED(Status);

    SaveCredForLogonSession(LogonId, RefreshedCreds);

    DereferenceTktBridgeCreds(*pTktBridgeCreds);
    *pTktBridgeCreds = RefreshedCreds;

    RETURN_NTSTATUS(STATUS_SUCCESS);
}
