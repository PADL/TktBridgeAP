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

static inline bool
IsWowClient(VOID)
{
#ifdef _WIN64
    return (GetCallAttributes() & SECPKG_CALL_WOWCLIENT) != 0;
#else
    return false;
#endif
}

static VOID
FreeUnicodeString(_Inout_ PUNICODE_STRING UnicodeString)
{
    if (UnicodeString != nullptr) {
        WIL_FreeMemory(UnicodeString->Buffer);
        RtlInitUnicodeString(UnicodeString, nullptr);
    }
}

static VOID
SecureFreeUnicodeString(_Inout_ PUNICODE_STRING UnicodeString)
{
    if (UnicodeString != nullptr && UnicodeString->Buffer != nullptr)
        SecureZeroMemory(UnicodeString->Buffer, UnicodeString->Length);
    FreeUnicodeString(UnicodeString);
}

static void
SecureFreePackedCredentials(_Inout_ PSEC_WINNT_AUTH_PACKED_CREDENTIALS PackedCreds)
{
    if (PackedCreds != nullptr) {
        SecureZeroMemory(PackedCreds, PackedCreds->cbStructureLength);
        WIL_FreeMemory(PackedCreds);
    }
}

static VOID
UnpackUnicodeString(_In_ PVOID ProtocolSubmitBuffer,
                    _In_ PCUNICODE_STRING SourceString,
                    _Inout_ PUNICODE_STRING DestinationString)
{
    DestinationString->Length        = SourceString->Length;
    DestinationString->MaximumLength = SourceString->MaximumLength;

    if (SourceString->Buffer != nullptr)
        DestinationString->Buffer = reinterpret_cast<PWSTR>
            ((static_cast<PBYTE>(ProtocolSubmitBuffer) + reinterpret_cast<ULONG_PTR>(SourceString->Buffer)));
    else
        DestinationString->Buffer = nullptr;
}

static VOID
UnpackUnicodeString32(_In_ PVOID ProtocolSubmitBuffer,
                      _In_ PCKERB_UNICODE_STRING32 SourceString,
                      _Inout_ PUNICODE_STRING DestinationString)
{
    DestinationString->Length = SourceString->Length;
    DestinationString->MaximumLength = SourceString->MaximumLength;

    if (SourceString->Buffer != 0)
        DestinationString->Buffer = reinterpret_cast<PWSTR>
            ((static_cast<PBYTE>(ProtocolSubmitBuffer) + SourceString->Buffer));
    else
        DestinationString->Buffer = nullptr;
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
UnpackUnicodeStringAllocZ(_In_ PVOID ProtocolSubmitBuffer,
                          _In_ PCUNICODE_STRING SourceString,
                          _Out_ PUNICODE_STRING DestinationString)
{
    UNICODE_STRING DestinationUS;

    RtlInitUnicodeString(&DestinationUS, nullptr);
    RtlInitUnicodeString(DestinationString, nullptr);

    UnpackUnicodeString(ProtocolSubmitBuffer, SourceString, &DestinationUS);

    auto Status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
                                            &DestinationUS, DestinationString);
    RETURN_IF_NTSTATUS_FAILED(Status);

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
UnpackUnicodeString32AllocZ(_In_ PVOID ProtocolSubmitBuffer,
                            _In_ PCKERB_UNICODE_STRING32 SourceString,
                            _Out_ PUNICODE_STRING DestinationString)
{
    UNICODE_STRING DestinationUS;

    RtlInitUnicodeString(&DestinationUS, nullptr);
    RtlInitUnicodeString(DestinationString, nullptr);

    UnpackUnicodeString32(ProtocolSubmitBuffer, SourceString, &DestinationUS);

    auto Status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
                                            &DestinationUS, DestinationString);
    RETURN_IF_NTSTATUS_FAILED(Status);

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
UnpackClientUnicodeStringAllocZ(_In_ PLSA_CLIENT_REQUEST ClientRequest,
                                _In_ PVOID ClientBufferBase,
                                _In_ PCUNICODE_STRING RelativeString,
                                _Out_ PUNICODE_STRING DestinationString)
{
    NTSTATUS Status;
    PWSTR StringBuffer = nullptr;
    USHORT cbStringBuffer;

    auto cleanup = wil::scope_exit([&]() {
        WIL_FreeMemory(StringBuffer);
    });

    Status = RtlUShortAdd(RelativeString->Length, sizeof(WCHAR), &cbStringBuffer);
    RETURN_IF_NTSTATUS_FAILED(Status);

    StringBuffer = static_cast<PWSTR>(WIL_AllocateMemory(cbStringBuffer));
    RETURN_NTSTATUS_IF_NULL_ALLOC(StringBuffer);

    Status = LsaSpFunctionTable->CopyFromClientBuffer(ClientRequest,
                                                      RelativeString->Length,
                                                      StringBuffer,
                                                      RelativeString->Buffer);
    RETURN_IF_NTSTATUS_FAILED(Status);

    StringBuffer[RelativeString->Length / sizeof(WCHAR)] = L'\0';

    DestinationString->Buffer        = StringBuffer;
    DestinationString->Length        = RelativeString->Length;
    DestinationString->MaximumLength = cbStringBuffer;

    StringBuffer = nullptr;

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
UnpackClientUnicodeString32AllocZ(_In_ PLSA_CLIENT_REQUEST ClientRequest,
                                  _In_ PVOID ClientBufferBase,
                                  _In_ PCKERB_UNICODE_STRING32 RelativeString,
                                  _Out_ PUNICODE_STRING DestinationString)
{
    NTSTATUS Status;
    PWSTR StringBuffer = nullptr;
    USHORT cbStringBuffer;

    auto cleanup = wil::scope_exit([&]() {
        WIL_FreeMemory(StringBuffer);
    });

    Status = RtlUShortAdd(RelativeString->Length, sizeof(WCHAR), &cbStringBuffer);
    RETURN_IF_NTSTATUS_FAILED(Status);

    StringBuffer = static_cast<PWSTR>(WIL_AllocateMemory(cbStringBuffer));
    RETURN_NTSTATUS_IF_NULL_ALLOC(StringBuffer);

    Status = LsaSpFunctionTable->CopyFromClientBuffer(ClientRequest,
                                                      RelativeString->Length,
                                                      StringBuffer,
                                                      reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(RelativeString->Buffer)));
    RETURN_IF_NTSTATUS_FAILED(Status);

    StringBuffer[RelativeString->Length / sizeof(WCHAR)] = L'\0';

    DestinationString->Buffer        = StringBuffer;
    DestinationString->Length        = RelativeString->Length;
    DestinationString->MaximumLength = cbStringBuffer;

    StringBuffer = nullptr;

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
ValidateOffset(_In_ ULONG cbBuffer,
               _In_ ULONG_PTR cbOffset,
               _In_ ULONG cbItem)
{
    NTSTATUS Status;
    ULONGLONG cbRequiredBuffer;

    Status = RtlULongLongAdd(cbOffset, cbItem, &cbRequiredBuffer);
    RETURN_IF_NTSTATUS_FAILED(Status);

    /* Don't use RETURN_NTSTATUS as BUFFER_TOO_SMALL is expected */
    return (cbRequiredBuffer > cbBuffer) ? STATUS_BUFFER_TOO_SMALL : STATUS_SUCCESS;
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
ValidateAndUnpackUnicodeStringAllocZ(_In_ PLSA_CLIENT_REQUEST ClientRequest,
                                     _In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                     _In_ PVOID ClientBufferBase,
                                     _In_ ULONG SubmitBufferSize,
                                     _In_ PCUNICODE_STRING RelativeString,
                                     _Out_ PUNICODE_STRING DestinationString)
{
    NTSTATUS Status;

    RtlInitUnicodeString(DestinationString, nullptr);

    Status = ValidateOffset(SubmitBufferSize,
                            reinterpret_cast<ULONG_PTR>(RelativeString->Buffer),
                            RelativeString->Length);
    if (NT_SUCCESS(Status)) {
        Status = UnpackUnicodeStringAllocZ(ProtocolSubmitBuffer,
                                           RelativeString,
                                           DestinationString);
        RETURN_IF_NTSTATUS_FAILED(Status);
    } else {
        Status = UnpackClientUnicodeStringAllocZ(ClientRequest,
                                                 ClientBufferBase,
                                                 RelativeString,
                                                 DestinationString);
        RETURN_IF_NTSTATUS_FAILED(Status);
    }

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
ValidateAndUnpackUnicodeString32AllocZ(_In_ PLSA_CLIENT_REQUEST ClientRequest,
                                       _In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                       _In_ PVOID ClientBufferBase,
                                       _In_ ULONG SubmitBufferSize,
                                       _In_ PCKERB_UNICODE_STRING32 RelativeString,
                                       _Out_ PUNICODE_STRING DestinationString)
{
    NTSTATUS Status;

    RtlInitUnicodeString(DestinationString, nullptr);

    Status = ValidateOffset(SubmitBufferSize,
                            RelativeString->Buffer,
                            RelativeString->Length);
    if (NT_SUCCESS(Status)) {
        Status = UnpackUnicodeString32AllocZ(ProtocolSubmitBuffer,
                                             RelativeString,
                                             DestinationString);
        RETURN_IF_NTSTATUS_FAILED(Status);
    } else {
        Status = UnpackClientUnicodeString32AllocZ(ClientRequest,
                                                   ClientBufferBase,
                                                   RelativeString,
                                                   DestinationString);
        RETURN_IF_NTSTATUS_FAILED(Status);
    }

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
CanonicalizeUPN(_In_ PUNICODE_STRING DomainName,
                _In_ PUNICODE_STRING UserName,
                _Out_ PUNICODE_STRING UpnSuffix)
{
    *UpnSuffix = *DomainName;

    if (UserName->Length == 0)
        RETURN_NTSTATUS(STATUS_NO_SUCH_USER);

    /*
     * Canonicalize into user and domain components as we need to filter
     * the domain name to determine whether to attempt surrogate logon.
     */
    if (DomainName->Length == 0) {
        auto wszUpnSuffix = wcschr(UserName->Buffer, L'@');
        if (wszUpnSuffix != nullptr) {
            *wszUpnSuffix = L'\0';
            wszUpnSuffix++;
        }
        RtlInitUnicodeString(UpnSuffix, wszUpnSuffix);
    } else {
        // Winlogon canonicalizes UPNSUFFIX\user to NETBIOSDOMAIN\user
        // which breaks unlock, so force UPN logons for now
        RETURN_NTSTATUS(STATUS_NO_SUCH_DOMAIN);
    }

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
UnprotectString(_In_ PUNICODE_STRING Protected,
                _Out_ PUNICODE_STRING Unprotected)
{
    NTSTATUS Status;
    CRED_PROTECTION_TYPE ProtectionType;
    PWSTR wszUnprotected = nullptr;
    DWORD cchUnprotected = 0;
    bool bImpersonatedClient = false;

    assert(Protected->MaximumLength >= Protected->Length + sizeof(WCHAR));
    assert(Protected->Buffer[Protected->Length / sizeof(WCHAR)] == L'\0');

    RtlInitUnicodeString(Unprotected, nullptr);

    auto cleanup = wil::scope_exit([&]() {
        if (bImpersonatedClient)
            RevertToSelf();

        if (wszUnprotected != nullptr) {
            SecureZeroMemory(wszUnprotected, cchUnprotected * sizeof(WCHAR));
            WIL_FreeMemory(wszUnprotected);
        }
    });

    RETURN_IF_WIN32_BOOL_FALSE(CredIsProtected(Protected->Buffer, &ProtectionType));

    if (ProtectionType == CredUnprotected)
        RETURN_NTSTATUS(STATUS_SUCCESS);
    else if (ProtectionType == CredUserProtection) {
        Status = LsaSpFunctionTable->ImpersonateClient();
        RETURN_IF_NTSTATUS_FAILED(Status);

        bImpersonatedClient = true;
    }

    if (CredUnprotect(FALSE,
                      Protected->Buffer,
                      Protected->MaximumLength / sizeof(WCHAR),
                      nullptr,
                      &cchUnprotected) == TRUE)
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);

    DWORD dwError = GetLastError();
    if (dwError != ERROR_INSUFFICIENT_BUFFER)
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);
    else if (cchUnprotected == 0)
        RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

    wszUnprotected = static_cast<PWSTR>(WIL_AllocateMemory(cchUnprotected * sizeof(WCHAR)));
    RETURN_NTSTATUS_IF_NULL_ALLOC(wszUnprotected);

    RETURN_IF_WIN32_BOOL_FALSE(CredUnprotect(FALSE,
                                             Protected->Buffer,
                                             Protected->MaximumLength / sizeof(WCHAR),
                                             wszUnprotected,
                                             &cchUnprotected));

    Status = RtlSizeTToUShort(cchUnprotected * sizeof(WCHAR), &Unprotected->MaximumLength);
    RETURN_IF_NTSTATUS_FAILED(Status);

    assert(cchUnprotected > 0);

    Unprotected->Buffer = wszUnprotected;
    wszUnprotected = nullptr;

    Unprotected->Length = Unprotected->MaximumLength - sizeof(WCHAR);

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

#define VALIDATE_UNPACK_UNICODE_STRING32(SourceString, DestinationString) do {  \
        Status = ValidateAndUnpackUnicodeString32AllocZ(ClientRequest,          \
                                                        ProtocolSubmitBuffer,   \
                                                        ClientBufferBase,       \
                                                        SubmitBufferSize,       \
                                                        &(SourceString),        \
                                                        &(DestinationString));  \
        RETURN_IF_NTSTATUS_FAILED(Status);                                      \
    } while (0)

#define VALIDATE_UNPACK_UNICODE_STRING(SourceString, DestinationString) do {    \
        Status = ValidateAndUnpackUnicodeStringAllocZ(ClientRequest,            \
                                                      ProtocolSubmitBuffer,     \
                                                      ClientBufferBase,         \
                                                      SubmitBufferSize,         \
                                                      &(SourceString),          \
                                                      &(DestinationString));    \
        RETURN_IF_NTSTATUS_FAILED(Status);                                      \
    } while (0)

static _Success_(return == STATUS_SUCCESS) NTSTATUS
ConvertKerbInteractiveLogonToAuthIdentity(_In_ PLSA_CLIENT_REQUEST ClientRequest,
                                          _In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                          _In_ PVOID ClientBufferBase,
                                          _In_ ULONG SubmitBufferSize,
                                          _Out_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE *pAuthIdentity)
{
    NTSTATUS Status;
    UNICODE_STRING DomainName, UserName, UpnSuffix;
    UNICODE_STRING Password, UnprotectedPassword;

    *pAuthIdentity = nullptr;

    RtlInitUnicodeString(&DomainName, nullptr);
    RtlInitUnicodeString(&UserName, nullptr);
    RtlInitUnicodeString(&UpnSuffix, nullptr);
    RtlInitUnicodeString(&Password, nullptr);
    RtlInitUnicodeString(&UnprotectedPassword, nullptr);

    auto cleanup = wil::scope_exit([&]() {
        FreeUnicodeString(&DomainName);
        FreeUnicodeString(&UserName);
        SecureFreeUnicodeString(&Password);
        SecureFreeUnicodeString(&UnprotectedPassword);
    });

    if (IsWowClient()) {
        PKERB_INTERACTIVE_LOGON_WOW pKIL32;

        if (SubmitBufferSize < sizeof(*pKIL32))
            RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

        pKIL32 = static_cast<PKERB_INTERACTIVE_LOGON_WOW>(ProtocolSubmitBuffer);

        VALIDATE_UNPACK_UNICODE_STRING32(pKIL32->LogonDomainName, DomainName);
        VALIDATE_UNPACK_UNICODE_STRING32(pKIL32->UserName,        UserName);
        VALIDATE_UNPACK_UNICODE_STRING32(pKIL32->Password,        Password);
    } else {
        PKERB_INTERACTIVE_LOGON pKIL;

        if (SubmitBufferSize < sizeof(*pKIL))
            RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

        pKIL = static_cast<PKERB_INTERACTIVE_LOGON>(ProtocolSubmitBuffer);

        VALIDATE_UNPACK_UNICODE_STRING(pKIL->LogonDomainName,     DomainName);
        VALIDATE_UNPACK_UNICODE_STRING(pKIL->UserName,            UserName);
        VALIDATE_UNPACK_UNICODE_STRING(pKIL->Password,            Password);
    }

    Status = CanonicalizeUPN(&DomainName, &UserName, &UpnSuffix);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = UnprotectString(&Password, &UnprotectedPassword);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = SspiEncodeStringsAsAuthIdentity(UserName.Buffer,
                                             UpnSuffix.Buffer,
                                             UnprotectedPassword.Buffer != nullptr ? UnprotectedPassword.Buffer : Password.Buffer,
                                             pAuthIdentity);
    RETURN_IF_NTSTATUS_FAILED(Status); // FIXME not NTSTATUS

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
ConvertKerbCertificateLogonToPackedCreds(_In_ PLSA_CLIENT_REQUEST ClientRequest,
                                         _In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                         _In_ PVOID ClientBufferBase,
                                         _In_ ULONG SubmitBufferSize,
                                         _In_ PUNICODE_STRING UnprotectedPin,
                                         _Out_ PSEC_WINNT_AUTH_PACKED_CREDENTIALS *ppPackedCreds)
{
    NTSTATUS Status;
    PSEC_WINNT_AUTH_PACKED_CREDENTIALS pPackedCreds = nullptr;
    SIZE_T cbPackedCreds;
    ULONG_PTR CspDataOffset;
    PBYTE CspData;
    PBYTE ClientCspData = nullptr;
    ULONG CspDataLength = 0;
    ULONG KerbCertificateLogonFlags;

    auto cleanup = wil::scope_exit([&]() {
        if (ClientCspData != nullptr) {
            SecureZeroMemory(ClientCspData, CspDataLength);
            WIL_FreeMemory(ClientCspData);
        }
        SecureFreePackedCredentials(pPackedCreds);
    });

    if (IsWowClient()) {
        auto pKCL32 = static_cast<PKERB_CERTIFICATE_LOGON_WOW>(ProtocolSubmitBuffer);
        CspDataOffset             = pKCL32->CspData;
        CspDataLength             = pKCL32->CspDataLength;
        KerbCertificateLogonFlags = pKCL32->Flags;
    } else {
        auto pKCL = static_cast<PKERB_CERTIFICATE_LOGON>(ProtocolSubmitBuffer);
        CspDataOffset             = reinterpret_cast<ULONG_PTR>(pKCL->CspData);
        CspDataLength             = pKCL->CspDataLength;
        KerbCertificateLogonFlags = pKCL->Flags;
    }

    Status = ValidateOffset(SubmitBufferSize, CspDataOffset, CspDataLength);
    if (NT_SUCCESS(Status)) {
        CspData = static_cast<PBYTE>(ProtocolSubmitBuffer) + CspDataOffset;
    } else {
        ClientCspData = static_cast<PBYTE>(WIL_AllocateMemory(CspDataLength));
        RETURN_NTSTATUS_IF_NULL_ALLOC(ClientCspData);

        Status = LsaSpFunctionTable->CopyFromClientBuffer(ClientRequest,
                                                          CspDataLength,
                                                          ClientCspData,
                                                          reinterpret_cast<PVOID>(CspDataOffset));
        RETURN_IF_NTSTATUS_FAILED(Status);

        CspData = ClientCspData;
    }

    cbPackedCreds = sizeof(SEC_WINNT_AUTH_PACKED_CREDENTIALS) + sizeof(SEC_WINNT_AUTH_NGC_DATA) +
                    CspDataLength + UnprotectedPin->Length;

    pPackedCreds = static_cast<PSEC_WINNT_AUTH_PACKED_CREDENTIALS>(WIL_AllocateMemory(cbPackedCreds));
    RETURN_NTSTATUS_IF_NULL_ALLOC(pPackedCreds);

    RtlZeroMemory(pPackedCreds, cbPackedCreds);

    pPackedCreds->cbHeaderLength    = sizeof(*pPackedCreds);

    Status = RtlSizeTToUShort(cbPackedCreds, &pPackedCreds->cbStructureLength);
    RETURN_IF_NTSTATUS_FAILED(Status);

    pPackedCreds->AuthData.CredType = SEC_WINNT_AUTH_DATA_TYPE_NGC;

    auto CredData = &pPackedCreds->AuthData.CredData;

    CredData->ByteArrayOffset = sizeof(SEC_WINNT_AUTH_PACKED_CREDENTIALS);

    Status = RtlSizeTToUShort(sizeof(SEC_WINNT_AUTH_NGC_DATA) +
                              CspDataLength + UnprotectedPin->Length, &CredData->ByteArrayLength);
    RETURN_IF_NTSTATUS_FAILED(Status);

    auto pPackedCredsBase = reinterpret_cast<PBYTE>(pPackedCreds);
    auto NgcData = reinterpret_cast<PSEC_WINNT_AUTH_NGC_DATA>(pPackedCredsBase + CredData->ByteArrayOffset);

    NgcData->Flags = NGC_DATA_FLAG_IS_SMARTCARD_DATA;
    if (KerbCertificateLogonFlags & KERB_CERTIFICATE_LOGON_FLAG_CHECK_DUPLICATES)
        NgcData->Flags |= NGC_DATA_FLAG_KERB_CERTIFICATE_LOGON_FLAG_CHECK_DUPLICATES;
    if (KerbCertificateLogonFlags & KERB_CERTIFICATE_LOGON_FLAG_USE_CERTIFICATE_INFO)
        NgcData->Flags |= NGC_DATA_FLAG_KERB_CERTIFICATE_LOGON_FLAG_USE_CERTIFICATE_INFO;

    NgcData->CspInfo.ByteArrayOffset = CredData->ByteArrayOffset + sizeof(SEC_WINNT_AUTH_NGC_DATA);

    Status = RtlSizeTToUShort(CspDataLength, &NgcData->CspInfo.ByteArrayLength);
    RETURN_IF_NTSTATUS_FAILED(Status);

    memcpy(pPackedCredsBase + NgcData->CspInfo.ByteArrayOffset, CspData, CspDataLength);

    NgcData->UserIdKeyAuthTicket.ByteArrayOffset = NgcData->CspInfo.ByteArrayOffset + CspDataLength;
    NgcData->UserIdKeyAuthTicket.ByteArrayLength = UnprotectedPin->Length;
    memcpy(pPackedCredsBase + NgcData->UserIdKeyAuthTicket.ByteArrayOffset, UnprotectedPin->Buffer, UnprotectedPin->Length);

    *ppPackedCreds = pPackedCreds;
    pPackedCreds = nullptr;

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
MakePackedCredentialsAuthIdentityEx2(_In_ PUNICODE_STRING DomainName,
                                     _In_ PUNICODE_STRING UserName,
                                     _In_ PSEC_WINNT_AUTH_PACKED_CREDENTIALS PackedCredentials,
                                     _Out_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE *pAuthIdentity)
{
    NTSTATUS Status;
    PSEC_WINNT_AUTH_IDENTITY_EX2 AuthIdentityEx2 = nullptr;
    SIZE_T cbAuthIdentityEx2 = 0;

    *pAuthIdentity = nullptr;

    auto cleanup = wil::scope_exit([&]() {
        // don't use SspiFreeAuthIdentity as it may not yet be valid
        if (AuthIdentityEx2 != nullptr) {
            SecureZeroMemory(AuthIdentityEx2, cbAuthIdentityEx2);
            LocalFree(AuthIdentityEx2);
        }
    });

    cbAuthIdentityEx2 = sizeof(*AuthIdentityEx2) +
        DomainName->Length + UserName->Length + PackedCredentials->cbStructureLength;

    // LPTR guarantees memory is zeroed
    AuthIdentityEx2 = static_cast<PSEC_WINNT_AUTH_IDENTITY_EX2>(LocalAlloc(LPTR, cbAuthIdentityEx2));
    RETURN_NTSTATUS_IF_NULL_ALLOC(AuthIdentityEx2);

    auto AuthIdentityEx2Base = reinterpret_cast<PBYTE>(AuthIdentityEx2);

    AuthIdentityEx2->Version                 = SEC_WINNT_AUTH_IDENTITY_VERSION_2;
    AuthIdentityEx2->cbHeaderLength          = sizeof(*AuthIdentityEx2);
    Status = RtlSizeTToULong(cbAuthIdentityEx2, &AuthIdentityEx2->cbStructureLength);
    RETURN_IF_NTSTATUS_FAILED(Status);

    if (UserName->Buffer != nullptr) {
        AuthIdentityEx2->UserOffset          = AuthIdentityEx2->cbHeaderLength;
        AuthIdentityEx2->UserLength          = UserName->Length;
        memcpy(AuthIdentityEx2Base + AuthIdentityEx2->UserOffset, UserName->Buffer, UserName->Length);
    }

    if (DomainName->Buffer != nullptr) {
        AuthIdentityEx2->DomainOffset        = AuthIdentityEx2->UserOffset + AuthIdentityEx2->UserLength;
        AuthIdentityEx2->DomainLength        = DomainName->Length;
        memcpy(AuthIdentityEx2Base + AuthIdentityEx2->DomainOffset, DomainName->Buffer, DomainName->Length);
    }

    AuthIdentityEx2->PackedCredentialsOffset = AuthIdentityEx2->DomainOffset + AuthIdentityEx2->DomainLength;
    AuthIdentityEx2->PackedCredentialsLength = PackedCredentials->cbStructureLength;
    memcpy(AuthIdentityEx2Base + AuthIdentityEx2->PackedCredentialsOffset, PackedCredentials, PackedCredentials->cbStructureLength);

    AuthIdentityEx2->Flags = SEC_WINNT_AUTH_IDENTITY_MARSHALLED;

    Status = SspiValidateAuthIdentity(AuthIdentityEx2);
    RETURN_IF_NTSTATUS_FAILED(Status); // FIXME not NTSTATUS

    *pAuthIdentity = static_cast<PSEC_WINNT_AUTH_IDENTITY_OPAQUE>(AuthIdentityEx2);
    AuthIdentityEx2 = nullptr; // don't free on exit

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
ConvertKerbCertificateLogonToAuthIdentity(_In_ PLSA_CLIENT_REQUEST ClientRequest,
                                          _In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                          _In_ PVOID ClientBufferBase,
                                          _In_ ULONG SubmitBufferSize,
                                          _Out_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE *pAuthIdentity)
{
    NTSTATUS Status;
    UNICODE_STRING DomainName, UserName, UpnSuffix;
    UNICODE_STRING Pin, UnprotectedPin;
    PSEC_WINNT_AUTH_PACKED_CREDENTIALS pPackedCreds = nullptr;

    *pAuthIdentity = nullptr;

    RtlInitUnicodeString(&DomainName, nullptr);
    RtlInitUnicodeString(&UserName, nullptr);
    RtlInitUnicodeString(&UpnSuffix, nullptr);
    RtlInitUnicodeString(&Pin, nullptr);
    RtlInitUnicodeString(&UnprotectedPin, nullptr);

    auto cleanup = wil::scope_exit([&]() {
        FreeUnicodeString(&DomainName);
        FreeUnicodeString(&UserName);
        SecureFreeUnicodeString(&Pin);
        SecureFreeUnicodeString(&UnprotectedPin);
        SecureFreePackedCredentials(pPackedCreds);
    });

    if (IsWowClient()) {
        PKERB_CERTIFICATE_LOGON_WOW pKCL32;

        if (SubmitBufferSize < sizeof(*pKCL32))
            RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

        pKCL32 = static_cast<PKERB_CERTIFICATE_LOGON_WOW>(ProtocolSubmitBuffer);

        VALIDATE_UNPACK_UNICODE_STRING32(pKCL32->DomainName, DomainName);
        VALIDATE_UNPACK_UNICODE_STRING32(pKCL32->UserName,   UserName);
        VALIDATE_UNPACK_UNICODE_STRING32(pKCL32->Pin,        Pin);
    } else {
        PKERB_CERTIFICATE_LOGON pKCL;

        if (SubmitBufferSize < sizeof(*pKCL))
            RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

        pKCL = static_cast<PKERB_CERTIFICATE_LOGON>(ProtocolSubmitBuffer);

        VALIDATE_UNPACK_UNICODE_STRING(pKCL->DomainName,     DomainName);
        VALIDATE_UNPACK_UNICODE_STRING(pKCL->UserName,       UserName);
        VALIDATE_UNPACK_UNICODE_STRING(pKCL->Pin,            Pin);
    }

    Status = CanonicalizeUPN(&DomainName, &UserName, &UpnSuffix);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = UnprotectString(&Pin, &UnprotectedPin);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = ConvertKerbCertificateLogonToPackedCreds(ClientRequest,
                                                      ProtocolSubmitBuffer,
                                                      ClientBufferBase,
                                                      SubmitBufferSize,
                                                      UnprotectedPin.Buffer != nullptr ? &UnprotectedPin : &Pin,
                                                      &pPackedCreds);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = MakePackedCredentialsAuthIdentityEx2(&DomainName,
                                                  &UpnSuffix,
                                                  pPackedCreds,
                                                  pAuthIdentity);
    RETURN_IF_NTSTATUS_FAILED(Status);

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static VOID
GetAuthIdentityDecryptOptions(_In_ PSEC_WINNT_AUTH_IDENTITY_EX2 AuthIdentity,
                              _Out_ PULONG pulDecryptOptions,
                              _Out_ bool *pbImpersonateRequired)
{
    // SspiUnmarshalAuthIdentity() should not have changed this
    assert(AuthIdentity->Version == SEC_WINNT_AUTH_IDENTITY_VERSION_2);

    if (AuthIdentity->Flags & SEC_WINNT_AUTH_IDENTITY_FLAGS_PROCESS_ENCRYPTED)
        *pulDecryptOptions = SEC_WINNT_AUTH_IDENTITY_ENCRYPT_SAME_PROCESS;
    else if (AuthIdentity->Flags & (SEC_WINNT_AUTH_IDENTITY_FLAGS_SYSTEM_PROTECTED |
                                    SEC_WINNT_AUTH_IDENTITY_FLAGS_USER_PROTECTED))
        *pulDecryptOptions = SEC_WINNT_AUTH_IDENTITY_ENCRYPT_SAME_LOGON;
    else if (AuthIdentity->Flags & SEC_WINNT_AUTH_IDENTITY_FLAGS_SYSTEM_ENCRYPTED)
        *pulDecryptOptions = SEC_WINNT_AUTH_IDENTITY_ENCRYPT_FOR_SYSTEM;
    else
        *pulDecryptOptions = 0;

    *pbImpersonateRequired = !!(AuthIdentity->Flags & SEC_WINNT_AUTH_IDENTITY_FLAGS_USER_PROTECTED);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
UnmarshalAndDecryptAuthIdentityEx2(_In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                   _In_ ULONG SubmitBufferSize,
                                   _Out_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE *pAuthIdentity)
{
    PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity = nullptr;
    SECURITY_STATUS SecStatus;
    ULONG ulDecryptOptions;
    bool bImpersonateRequired, bImpersonatedClient = false;

    *pAuthIdentity = nullptr;

    auto cleanup = wil::scope_exit([&]() {
        if (bImpersonatedClient)
            RevertToSelf();

        SspiFreeAuthIdentity(AuthIdentity);
    });

    SecStatus = SspiUnmarshalAuthIdentity(SubmitBufferSize,
                                          static_cast<PCHAR>(ProtocolSubmitBuffer),
                                          &AuthIdentity);
    RETURN_IF_NTSTATUS_FAILED(SecStatus);

    SecStatus = SspiValidateAuthIdentity(AuthIdentity);
    RETURN_IF_NTSTATUS_FAILED(SecStatus);

    GetAuthIdentityDecryptOptions(reinterpret_cast<PSEC_WINNT_AUTH_IDENTITY_EX2>(AuthIdentity),
                                  &ulDecryptOptions, &bImpersonateRequired);

    if (ulDecryptOptions != 0) {
        assert(SspiIsAuthIdentityEncrypted(AuthIdentity));

        if (bImpersonateRequired) {
            SecStatus = LsaSpFunctionTable->ImpersonateClient();
            RETURN_IF_NTSTATUS_FAILED(SecStatus);

            bImpersonatedClient = true;
        }

        SecStatus = SspiDecryptAuthIdentityEx(ulDecryptOptions, AuthIdentity);
        RETURN_IF_NTSTATUS_FAILED(SecStatus);
    }

    *pAuthIdentity = AuthIdentity;
    AuthIdentity = nullptr;

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

_Success_(return == STATUS_SUCCESS) NTSTATUS
ConvertLogonSubmitBufferToAuthIdentity(_In_ PLSA_CLIENT_REQUEST ClientRequest,
                                       _In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                       _In_ PVOID ClientBufferBase,
                                       _In_ ULONG SubmitBufferSize,
                                       _Out_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE *pAuthIdentity)
{
    NTSTATUS Status;

    static_assert(sizeof(ULONG) == sizeof(KERB_LOGON_SUBMIT_TYPE));

    *pAuthIdentity = nullptr;

    if (SubmitBufferSize < sizeof(KERB_LOGON_SUBMIT_TYPE))
        RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

    // FIXME can we use CredUnPackAuthenticationBuffer() instead?

    KERB_LOGON_SUBMIT_TYPE LogonSubmitType =
        *static_cast<KERB_LOGON_SUBMIT_TYPE *>(ProtocolSubmitBuffer);

    switch (LogonSubmitType) {
    case SEC_WINNT_AUTH_IDENTITY_VERSION_2:
        Status = UnmarshalAndDecryptAuthIdentityEx2(ProtocolSubmitBuffer,
                                                    SubmitBufferSize,
                                                    pAuthIdentity);
        break;
    case KerbInteractiveLogon:
    case KerbWorkstationUnlockLogon:
        Status = ConvertKerbInteractiveLogonToAuthIdentity(ClientRequest,
                                                           ProtocolSubmitBuffer,
                                                           ClientBufferBase,
                                                           SubmitBufferSize,
                                                           pAuthIdentity);
        break;
    case KerbCertificateLogon:
    case KerbCertificateUnlockLogon:
        Status = ConvertKerbCertificateLogonToAuthIdentity(ClientRequest,
                                                           ProtocolSubmitBuffer,
                                                           ClientBufferBase,
                                                           SubmitBufferSize,
                                                           pAuthIdentity);
        break;
    default:
        DebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"Ignoring unknown logon submit type %x", LogonSubmitType);
        Status = STATUS_INVALID_LOGON_TYPE;
        break;
    }

    // don't log for expected errors
    if (Status == STATUS_NO_SUCH_DOMAIN || Status == STATUS_INVALID_LOGON_TYPE)
        RETURN_IF_NTSTATUS_FAILED_EXPECTED(Status);

    RETURN_NTSTATUS(Status);
}

static PCWSTR
GetLogonSubmitTypeDescription(KERB_LOGON_SUBMIT_TYPE LogonSubmitType)
{
    PCWSTR wszLogonSubmitType;

    switch (LogonSubmitType) {
    case SEC_WINNT_AUTH_IDENTITY_VERSION_2:
        wszLogonSubmitType = L"SEC_WINNT_AUTH_IDENTITY_VERSION_2";
        break;
    case KerbInteractiveLogon:
        wszLogonSubmitType = L"KerbInteractiveLogon";
        break;
    case KerbWorkstationUnlockLogon:
        wszLogonSubmitType = L"KerbWorkstationUnlockLogon";
        break;
    case KerbSmartCardLogon:
        wszLogonSubmitType = L"KerbSmartCardLogon";
        break;
    case KerbSmartCardUnlockLogon:
        wszLogonSubmitType = L"KerbSmartCardUnlockLogon";
        break;
    case KerbCertificateLogon:
        wszLogonSubmitType = L"KerbCertificateLogon";
        break;
    case KerbCertificateUnlockLogon:
        wszLogonSubmitType = L"KerbCertificateUnlockLogon";
        break;
    default:
        wszLogonSubmitType = L"UnknownLogon";
        break;
    }

    return wszLogonSubmitType;
}

PCWSTR
GetLogonSubmitTypeDescription(_In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                              _In_ ULONG SubmitBufferSize)
{
    if (SubmitBufferSize < sizeof(KERB_LOGON_SUBMIT_TYPE))
        return L"UnparseableLogon";

    KERB_LOGON_SUBMIT_TYPE LogonSubmitType =
        *static_cast<KERB_LOGON_SUBMIT_TYPE *>(ProtocolSubmitBuffer);

    return GetLogonSubmitTypeDescription(LogonSubmitType);
}
