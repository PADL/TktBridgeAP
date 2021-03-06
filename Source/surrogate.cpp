/*
 * Copyright (c) 2021, PADL Software Pty Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted (subject to the limitations in the
 * disclaimer below) provided that the following conditions are met:
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
 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED
 * BY THIS LICENSE.  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "TktBridgeAP.h"

static _Success_(return == STATUS_SUCCESS) NTSTATUS
MaybeRefreshTktBridgeCreds(const LUID &LogonId,
                           PTKTBRIDGEAP_CREDS *pTktBridgeCreds);

static _Success_(return == 0) krb5_error_code
DebugValidateTktBridgeCreds(_In_ PTKTBRIDGEAP_CREDS Creds);

/*
 * Callback function called from Kerberos package that passes TktBridgeAP-
 * specific private data and retrieves a KERB_AS_REP_CREDENTIAL
 * containing the AS-REP and reply key
 */
EXTERN_C static NTSTATUS CALLBACK
RetrieveTktBridgeCreds(LUID LogonId,
                       PVOID AsRepCallbackData,
                       ULONG Flags,
                       PKERB_AS_REP_CREDENTIAL *pKerbAsRepCred)
{
    PTKTBRIDGEAP_CREDS TktBridgeCreds = (PTKTBRIDGEAP_CREDS)AsRepCallbackData;
    ULONG cbKerbAsRepCred;
    ULONG TgtMessageLength, TgtClientKeyLength;
    NTSTATUS Status;

    auto cleanup = wil::scope_exit([&]() {
        DereferenceTktBridgeCreds(TktBridgeCreds);
    });

    if (TktBridgeCreds != nullptr) {
        ReferenceTktBridgeCreds(TktBridgeCreds);
    } else {
        Status = FindCredsForLogonSession(LogonId, &TktBridgeCreds);
        RETURN_IF_NTSTATUS_FAILED(Status);

        Status = MaybeRefreshTktBridgeCreds(LogonId, &TktBridgeCreds);
        RETURN_IF_NTSTATUS_FAILED(Status);
    }

    DebugTrace(WINEVENT_LEVEL_VERBOSE,
               L"RetrieveTktBridgeCreds(%s): LogonId=%x:0x%x, Flags=%x, "
               L"Client=%s, AS-REP Length=%u, KeyLength=%u, KeyType=%u, TGT %s",
               AsRepCallbackData != nullptr ? L"CallbackData" : L"LogonId",
               LogonId.HighPart,
               LogonId.LowPart,
               Flags,
               TktBridgeCreds->ClientName,
               TktBridgeCreds->AsRep.length,
               TktBridgeCreds->AsReplyKey.keyvalue.length,
               TktBridgeCreds->AsReplyKey.keytype,
               IsTktBridgeCredsExpired(TktBridgeCreds) ? L"Expired" : L"Valid");

    if ((APFlags & TKTBRIDGEAP_FLAG_DEBUG_VALIDATE_CRED) &&
        DebugValidateTktBridgeCreds(TktBridgeCreds) != 0)
        RETURN_NTSTATUS(STATUS_INTERNAL_ERROR);

    Status = RtlSizeTToULong(TktBridgeCreds->AsRep.length, &TgtMessageLength);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = RtlSizeTToULong(TktBridgeCreds->AsReplyKey.keyvalue.length, &TgtClientKeyLength);
    RETURN_IF_NTSTATUS_FAILED(Status);

    cbKerbAsRepCred = sizeof(KERB_AS_REP_CREDENTIAL);

    Status = RtlULongAdd(cbKerbAsRepCred, TgtMessageLength, &cbKerbAsRepCred);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = RtlULongAdd(cbKerbAsRepCred, TgtClientKeyLength, &cbKerbAsRepCred);
    RETURN_IF_NTSTATUS_FAILED(Status);

    auto KerbAsRepCredU = static_cast<PKERB_AS_REP_CREDENTIAL>(LsaSpFunctionTable->AllocateLsaHeap(cbKerbAsRepCred));
    RETURN_NTSTATUS_IF_NULL_ALLOC(KerbAsRepCredU);

    ZeroMemory(KerbAsRepCredU, sizeof(*KerbAsRepCredU));

    if (APFlags & TKTBRIDGEAP_FLAG_CLOUD_CREDS) {
        auto KerbAsRepCred = &KerbAsRepCredU->CloudTgtCredential;
        auto KerbAsRepCredBase = reinterpret_cast<PBYTE>(KerbAsRepCred);

        KerbAsRepCred->Version              = KERB_AS_REP_CREDENTIAL_CLOUD_TGT_VERSION;
        KerbAsRepCred->TgtMessageOffset     = sizeof(*KerbAsRepCred);
        KerbAsRepCred->TgtMessageLength     = TgtMessageLength;
        KerbAsRepCred->TgtClientKeyOffset   = sizeof(*KerbAsRepCred) + TgtMessageLength;
        KerbAsRepCred->TgtClientKeyLength   = TgtClientKeyLength;
        KerbAsRepCred->TgtKeyType           = TktBridgeCreds->AsReplyKey.keytype;

        memcpy(KerbAsRepCredBase + KerbAsRepCred->TgtMessageOffset,
               TktBridgeCreds->AsRep.data, TktBridgeCreds->AsRep.length);
        memcpy(KerbAsRepCredBase + KerbAsRepCred->TgtClientKeyOffset,
               TktBridgeCreds->AsReplyKey.keyvalue.data, TktBridgeCreds->AsReplyKey.keyvalue.length);

        LsaSpFunctionTable->LsaUnprotectMemory(KerbAsRepCredBase + KerbAsRepCred->TgtClientKeyOffset,
                                               KerbAsRepCred->TgtClientKeyLength);
    } else {
        auto KerbAsRepCred = &KerbAsRepCredU->TgtCredential;
        auto KerbAsRepCredBase = reinterpret_cast<PBYTE>(KerbAsRepCred);

        KerbAsRepCred->Version              = KERB_AS_REP_CREDENTIAL_TGT_VERSION;
        KerbAsRepCred->TgtMessageOffset     = sizeof(*KerbAsRepCred);
        KerbAsRepCred->TgtMessageLength     = TgtMessageLength;
        KerbAsRepCred->TgtClientKeyOffset   = sizeof(*KerbAsRepCred) + TgtMessageLength;
        KerbAsRepCred->TgtClientKeyLength   = TgtClientKeyLength;
        KerbAsRepCred->TgtKeyType           = TktBridgeCreds->AsReplyKey.keytype;

        memcpy(KerbAsRepCredBase + KerbAsRepCred->TgtMessageOffset,
               TktBridgeCreds->AsRep.data, TktBridgeCreds->AsRep.length);
        memcpy(KerbAsRepCredBase + KerbAsRepCred->TgtClientKeyOffset,
               TktBridgeCreds->AsReplyKey.keyvalue.data, TktBridgeCreds->AsReplyKey.keyvalue.length);

        LsaSpFunctionTable->LsaUnprotectMemory(KerbAsRepCredBase + KerbAsRepCred->TgtClientKeyOffset,
                                               KerbAsRepCred->TgtClientKeyLength);
    }

    *pKerbAsRepCred = KerbAsRepCredU;

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static bool
ValidateSurrogateLogonType(_In_ SECURITY_LOGON_TYPE LogonType)
{
    if ((SpParameters.MachineState & (SECPKG_STATE_DOMAIN_CONTROLLER |
                                      SECPKG_STATE_WORKSTATION)) == 0 ||
        SpParameters.DnsDomainName.Length == 0) {
        DebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"Surrogate logon unavailable on standalone workstations");
        return false;
    }

    return LogonType == Interactive || LogonType == Unlock ||
        LogonType == RemoteInteractive;
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

    if (IsLocalHost(&DomainName)) {
        DebugTrace(WINEVENT_LEVEL_INFO, L"Ignoring local account %s\\%s",
                   wszDomainName, wszUserName);
        return false;
    }

    /*
     * If a list of domain suffixes is configured in the registry,
     * use that as authoritative.
     */
    bool Authoritative;
    bool UPNSuffixMatch = IsEnabledUPNSuffix(wszDomainName, &Authoritative);

    if (Authoritative) {
        DebugTrace(WINEVENT_LEVEL_INFO, L"UPN suffixes configured; %s UPN %s@%s",
                   UPNSuffixMatch ? L"validated" : L"ignoring",
                   wszUserName, wszDomainName);
        return UPNSuffixMatch;
    }

    /*
     * We don't want to get in the way of ordinary logons so by default we
     * only allow domain suffixes that are not forest domain names (i.e.
     * mapping must be through userPrincipalName or altSecurityIdentities)
     */
    if ((APFlags & TKTBRIDGEAP_FLAG_PRIMARY_DOMAIN) == 0) {
        if (RtlEqualUnicodeString(&SpParameters.DnsDomainName, &DomainName, TRUE) ||
            RtlEqualUnicodeString(&SpParameters.DomainName, &DomainName, TRUE)) {
            DebugTrace(WINEVENT_LEVEL_INFO, L"Ignoring domain UPN %s@%s",
                       wszUserName, wszDomainName);
            return false;
        }
    }

    if ((APFlags & TKTBRIDGEAP_FLAG_TRUSTED_DOMAINS) == 0) {
        if (DsEnumerateDomainTrusts(nullptr,
                                    DS_DOMAIN_IN_FOREST | DS_DOMAIN_NATIVE_MODE,
                                    &Domains,
                                    &DomainCount) == ERROR_SUCCESS) {
            for (ULONG i = 0; i < DomainCount; i++) {
                PDS_DOMAIN_TRUSTS Domain = &Domains[i];

                if (_wcsicmp(wszDomainName, Domain->DnsDomainName) == 0 ||
                    _wcsicmp(wszDomainName, Domain->NetbiosDomainName) == 0) {
                    DebugTrace(WINEVENT_LEVEL_INFO, L"Ignoring trusted domain UPN %s@%s",
                               wszUserName, wszDomainName);
                    return false;
                }
            }
        }
    }

    DebugTrace(WINEVENT_LEVEL_INFO, L"Validated UPN %s@%s", wszUserName, wszDomainName);

    return true;
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
AcquireTktBridgeCreds(_In_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity,
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

    std::wstring RestrictPackageBuffer, KdcHostNameBuffer;
    PCWSTR RestrictPackage, KdcHostName;
    ULONG Flags = 0;

    Status = GetRestrictPackage(RestrictPackageBuffer, &RestrictPackage);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = GetKdcHostName(KdcHostNameBuffer, &KdcHostName);
    RETURN_IF_NTSTATUS_FAILED(Status);

    if (APFlags & TKTBRIDGEAP_FLAG_ANON_PKINIT_FAST)
        Flags |= GSS_PREAUTH_INIT_CREDS_ANON_PKINIT_FAST;

    auto KrbError = GssPreauthGetInitCreds(RealmName.Buffer,
                                           RestrictPackage,
                                           KdcHostName,
                                           Flags,
                                           nullptr, // pvLogonId
                                           AuthIdentity,
                                           &TktBridgeCreds->ClientName,
                                           &TktBridgeCreds->EndTime,
                                           &TktBridgeCreds->AsRep,
                                           &TktBridgeCreds->AsReplyKey,
                                           &SecStatus);
    Status = KrbErrorToNtStatus(KrbError, SubStatus);
    if (NT_SUCCESS(Status)) {
        LsaSpFunctionTable->LsaProtectMemory(TktBridgeCreds->AsReplyKey.keyvalue.data,
                                             static_cast<ULONG>(TktBridgeCreds->AsReplyKey.keyvalue.length));

        *pTktBridgeCreds = ReferenceTktBridgeCreds(TktBridgeCreds);

        if ((APFlags & TKTBRIDGEAP_FLAG_NO_INIT_CREDS_CACHE) == 0) {
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

static _Success_(return == STATUS_SUCCESS) NTSTATUS
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

    /*
     * Note that CloudAP will think it owns this entry as it does not check
     * the callback matches. AsRepCallbackData must be structured in such a way
     * that CloudAP will never attempt to release it, or it must be freed
     * before CloudAP's LsaApPostLogonUserSurrogate is called.
     */
    SurrogateLogonData->AsRepCallback = RetrieveTktBridgeCreds;
    SurrogateLogonData->AsRepCallbackData = TktBridgeCreds;

    Entry->Type = KERB_SURROGATE_LOGON_TYPE;
    Entry->Data = SurrogateLogonData;

    SurrogateLogon->EntryCount++;

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

NTSTATUS NTAPI
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

    auto SurrogateEntry = FindKerbSurrogateLogonEntry(SurrogateLogon, false);
    if (SurrogateEntry != nullptr)
        RETURN_NTSTATUS(STATUS_SUCCESS); // ignore CloudAP/FIDO

    ConvertLogonSubmitBufferToAuthIdentity(ClientRequest,
                                           ProtocolSubmitBuffer,
                                           ClientBufferBase,
                                           SubmitBufferSize,
                                           &AuthIdentity);
    if (AuthIdentity == nullptr ||
        !ValidateSurrogateLogonDomain(AuthIdentity))
        RETURN_NTSTATUS(STATUS_SUCCESS);

    DebugTrace(WINEVENT_LEVEL_VERBOSE,
               L"LsaApPreLogonUserSurrogate: LogonType=%d, "
               L"SurrogateLogonId=%x:0x%x",
               LogonType,
               SurrogateLogon->SurrogateLogonID.HighPart,
               SurrogateLogon->SurrogateLogonID.LowPart);

    Status = AcquireTktBridgeCreds(AuthIdentity,
                                   SurrogateLogon->SurrogateLogonID,
                                   &TktBridgeCreds,
                                   SubStatus);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = AddSurrogateLogonEntry(SurrogateLogon, TktBridgeCreds);
    RETURN_IF_NTSTATUS_FAILED(Status);

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

PSECPKG_SURROGATE_LOGON_ENTRY
FindKerbSurrogateLogonEntry(_In_ PSECPKG_SURROGATE_LOGON SurrogateLogon,
                            _In_ bool bValidateTktBridgeCreds)
{
    if (SurrogateLogon == nullptr)
        return nullptr;

    for (ULONG i = 0; i < SurrogateLogon->EntryCount; i++) {
        PSECPKG_SURROGATE_LOGON_ENTRY Entry = &SurrogateLogon->Entries[i];

        if (!IsEqualGUID(Entry->Type, KERB_SURROGATE_LOGON_TYPE))
            continue; // not a Kerb AS-REP surrogate logon entry

        auto SurrogateLogonData = (PKERB_SURROGATE_LOGON_DATA)Entry->Data;
        if (SurrogateLogonData == nullptr)
            continue;

        if (bValidateTktBridgeCreds &&
            SurrogateLogonData->AsRepCallback != &RetrieveTktBridgeCreds)
            continue; // must be another package

        return Entry;
    }

    return nullptr;
}

NTSTATUS NTAPI
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
    auto SurrogateEntry = FindKerbSurrogateLogonEntry(SurrogateLogon, true);
    if (SurrogateEntry == nullptr)
        RETURN_NTSTATUS(STATUS_SUCCESS);

    auto SurrogateLogonData = (PKERB_SURROGATE_LOGON_DATA)SurrogateEntry->Data;
    auto TktBridgeCreds = (PTKTBRIDGEAP_CREDS)SurrogateLogonData->AsRepCallbackData;

    if (TktBridgeCreds == nullptr)
        RETURN_NTSTATUS(STATUS_SUCCESS);

    if (NT_SUCCESS(Status)) {
        DebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"LsaApPostLogonUserSurrogate: LogonType=%d/%s, "
                   L"SurrogateLogonID=%x:0x%x, Status=%x, SubStatus=%x, LogonId=%x:0x%x",
                   LogonType,
                   GetLogonSubmitTypeDescription(ProtocolSubmitBuffer, SubmitBufferSize),
                   SurrogateLogon->SurrogateLogonID.HighPart,
                   SurrogateLogon->SurrogateLogonID.LowPart,
                   Status, SubStatus,
                   LogonId->HighPart, LogonId->LowPart);
        SaveCredsForLogonSession(*LogonId, TktBridgeCreds);
    }

    DereferenceTktBridgeCreds(TktBridgeCreds);
    SurrogateLogonData->AsRepCallbackData = nullptr;

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

VOID NTAPI
LsaApLogonTerminated(_In_ PLUID LogonId)
{
    DebugTrace(WINEVENT_LEVEL_VERBOSE,
               L"LsaApLogonTerminated: LogonId=%x:0x%x",
               LogonId->HighPart, LogonId->LowPart);

    RemoveCredsForLogonSession(*LogonId);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
RefreshTktBridgeCreds(_In_ const LUID &LogonId,
                      _In_ const PTKTBRIDGEAP_CREDS ExistingCreds,
                      _Out_ PTKTBRIDGEAP_CREDS *pRefreshedCreds)
{
    NTSTATUS Status, SubStatus;
    PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity = nullptr;

    *pRefreshedCreds = nullptr;

    auto cleanup = wil::scope_exit([&]() {
        SspiFreeAuthIdentity(AuthIdentity);
    });

    Status = SspiCopyAuthIdentity(ExistingCreds->InitialCreds, &AuthIdentity);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = SspiDecryptAuthIdentity(AuthIdentity);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = AcquireTktBridgeCreds(AuthIdentity, LogonId, pRefreshedCreds, &SubStatus);
    RETURN_IF_NTSTATUS_FAILED(Status);

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
MaybeRefreshTktBridgeCreds(const LUID &LogonId,
                           PTKTBRIDGEAP_CREDS *pTktBridgeCreds)
{
    auto TktBridgeCreds = *pTktBridgeCreds;
    NTSTATUS Status;
    PTKTBRIDGEAP_CREDS RefreshedCreds = nullptr;

    if (!IsTktBridgeCredsExpired(TktBridgeCreds))
        RETURN_NTSTATUS(STATUS_SUCCESS);

    if (TktBridgeCreds->InitialCreds != nullptr)
        Status = RefreshTktBridgeCreds(LogonId, TktBridgeCreds, &RefreshedCreds);
    else
        Status = SEC_E_NO_CREDENTIALS;
    RETURN_IF_NTSTATUS_FAILED(Status);

    assert(RefreshedCreds != nullptr);

    SaveCredsForLogonSession(LogonId, RefreshedCreds);
    DereferenceTktBridgeCreds(*pTktBridgeCreds);
    *pTktBridgeCreds = RefreshedCreds;

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static _Success_(return == 0) krb5_error_code
DebugValidateTktBridgeCreds(_In_ PTKTBRIDGEAP_CREDS Creds)
{
    krb5_error_code KrbError;
    AS_REP AsRep;
    EncASRepPart AsRepPart;
    size_t Size;
    krb5_data Data;
    krb5_context KrbContext = nullptr;
    krb5_crypto KrbCrypto = nullptr;
    krb5_keyblock KrbKey;

    ZeroMemory(&AsRep, sizeof(AsRep));
    ZeroMemory(&AsRepPart, sizeof(AsRepPart));
    krb5_keyblock_zero(&KrbKey);
    krb5_data_zero(&Data);

    auto cleanup = wil::scope_exit([&]() {
        free_AS_REP(&AsRep);
        free_EncASRepPart(&AsRepPart);
        if (KrbContext != nullptr) {
            if (KrbCrypto != nullptr)
                krb5_crypto_destroy(KrbContext, KrbCrypto);
            if (KrbKey.keyvalue.data != nullptr) {
                SecureZeroMemory(KrbKey.keyvalue.data, KrbKey.keyvalue.length);
                krb5_free_keyblock_contents(KrbContext, &KrbKey);
            }
            krb5_free_context(KrbContext);
            krb5_data_free(&Data);
        }
    });

    KrbError = decode_AS_REP(static_cast<PBYTE>(Creds->AsRep.data),
                             Creds->AsRep.length,
                             &AsRep, &Size);
    RETURN_IF_KRB_FAILED_MSG(KrbError, L"Failed to decode AS-REP");

    auto szAS_REP = print_AS_REP(&AsRep, 0);
    if (szAS_REP != nullptr) {
        DebugTrace(WINEVENT_LEVEL_VERBOSE, L"AS-REP\r\n%S", szAS_REP);
        krb5_xfree(szAS_REP);
    }

    KrbError = krb5_init_context(&KrbContext);
    RETURN_IF_KRB_FAILED_MSG(KrbError, L"Failed to initialize context");

    KrbError = krb5_copy_keyblock_contents(KrbContext, &Creds->AsReplyKey, &KrbKey);
    RETURN_IF_KRB_FAILED_MSG(KrbError, L"Failed to copy key");

    LsaSpFunctionTable->LsaUnprotectMemory(KrbKey.keyvalue.data,
                                           static_cast<ULONG>(KrbKey.keyvalue.length));

    KrbError = krb5_crypto_init(KrbContext, &KrbKey, KRB5_ENCTYPE_NULL, &KrbCrypto);
    RETURN_IF_KRB_FAILED_MSG(KrbError, L"Failed to initialize crypto context");

    KrbError = krb5_decrypt_EncryptedData(KrbContext, KrbCrypto,
                                          KRB5_KU_AS_REP_ENC_PART,
                                          &AsRep.enc_part,
                                          &Data);
    RETURN_IF_KRB_FAILED_MSG(KrbError, L"Failed to decrypt AS-REP enc-part");

    KrbError = decode_EncASRepPart(static_cast<PBYTE>(Data.data),
                                   Data.length,
                                   &AsRepPart,
                                   &Size);
    RETURN_IF_KRB_FAILED_MSG(KrbError, L"Failed to decode AS-REP enc-part");

    // zero TGT session key before logging
    if (AsRepPart.key.keyvalue.data != nullptr)
        SecureZeroMemory(AsRepPart.key.keyvalue.data, AsRepPart.key.keyvalue.length);

    auto szEncASRepPart = print_EncASRepPart(&AsRepPart, 0);
    if (szEncASRepPart != nullptr) {
        DebugTrace(WINEVENT_LEVEL_VERBOSE, L"EncASRepPart\r\n%S", szEncASRepPart);
        krb5_xfree(szEncASRepPart);
    }

    return 0;
}
