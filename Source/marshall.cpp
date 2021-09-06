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

static PCWSTR
GetLogonSubmitTypeDescription(KERB_LOGON_SUBMIT_TYPE LogonSubmitType);

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
                          _Out_ PWSTR *pDestinationString)
{
    UNICODE_STRING DestinationUS;
    UNICODE_STRING DestinationUSZ;

    RtlInitUnicodeString(&DestinationUS, NULL);
    RtlInitUnicodeString(&DestinationUSZ, NULL);

    UnpackUnicodeString(ProtocolSubmitBuffer, SourceString, &DestinationUS);

    auto Status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
                                            &DestinationUS, &DestinationUSZ);
    RETURN_IF_NTSTATUS_FAILED(Status);

    *pDestinationString = DestinationUSZ.Buffer;

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
UnpackUnicodeString32AllocZ(_In_ PVOID ProtocolSubmitBuffer,
                            _In_ PCKERB_UNICODE_STRING32 SourceString,
                            _Out_ PWSTR *pDestinationString)
{
    UNICODE_STRING DestinationUS;
    UNICODE_STRING DestinationUSZ;

    RtlInitUnicodeString(&DestinationUS, NULL);
    RtlInitUnicodeString(&DestinationUSZ, NULL);

    UnpackUnicodeString32(ProtocolSubmitBuffer, SourceString, &DestinationUS);

    auto Status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
                                            &DestinationUS, &DestinationUSZ);
    RETURN_IF_NTSTATUS_FAILED(Status);

    *pDestinationString = DestinationUSZ.Buffer;

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
UnpackClientUnicodeStringAllocZ(_In_ PLSA_CLIENT_REQUEST ClientRequest,
                                _In_ PVOID ClientBufferBase,
                                _In_ PCUNICODE_STRING RelativeString,
                                _Out_ PWSTR *DestinationString)
{
    NTSTATUS Status;
    PWSTR StringBuffer;

    StringBuffer = static_cast<PWSTR>(WIL_AllocateMemory(RelativeString->Length + sizeof(WCHAR)));
    RETURN_NTSTATUS_IF_NULL_ALLOC(StringBuffer);

    Status = LsaSpFunctionTable->CopyFromClientBuffer(ClientRequest,
                                                      RelativeString->Length,
                                                      StringBuffer,
                                                      RelativeString->Buffer);
    if (!NT_SUCCESS(Status)) {
        WIL_FreeMemory(StringBuffer);
        RETURN_NTSTATUS(Status);
    }

    StringBuffer[RelativeString->Length / sizeof(WCHAR)] = L'\0';

    *DestinationString = StringBuffer;

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
UnpackClientUnicodeString32AllocZ(_In_ PLSA_CLIENT_REQUEST ClientRequest,
                                  _In_ PVOID ClientBufferBase,
                                  _In_ PCKERB_UNICODE_STRING32 RelativeString,
                                  _Out_ PWSTR *DestinationString)
{
    NTSTATUS Status;
    PWSTR StringBuffer;

    StringBuffer = static_cast<PWSTR>(WIL_AllocateMemory(RelativeString->Length + sizeof(WCHAR)));
    RETURN_NTSTATUS_IF_NULL_ALLOC(StringBuffer);

    Status = LsaSpFunctionTable->CopyFromClientBuffer(ClientRequest,
                                                      RelativeString->Length,
                                                      StringBuffer,
                                                      reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(RelativeString->Buffer)));
    if (!NT_SUCCESS(Status)) {
        WIL_FreeMemory(StringBuffer);
        RETURN_NTSTATUS(Status);
    }

    StringBuffer[RelativeString->Length / sizeof(WCHAR)] = L'\0';

    *DestinationString = StringBuffer;

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
ValidateOffset(_In_ ULONG cbBuffer,
               _In_ ULONG_PTR cbOffset,
               _In_ ULONG cbItem)
{
    NTSTATUS Status;

    /* Don't use RETURN_NTSTATUS as BUFFER_TOO_SMALL is expected */
    if (cbOffset + cbItem > cbBuffer)
        Status = STATUS_BUFFER_TOO_SMALL;
    else
        Status = STATUS_SUCCESS;

    return Status;
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
ValidateAndUnpackUnicodeStringAllocZ(_In_ PLSA_CLIENT_REQUEST ClientRequest,
                                     _In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                     _In_ PVOID ClientBufferBase,
                                     _In_ ULONG SubmitBufferSize,
                                     _In_ PCUNICODE_STRING RelativeString,
                                     _Out_ PWSTR *DestinationString)
{
    NTSTATUS Status;

    *DestinationString = nullptr;

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
                                       _Out_ PWSTR *DestinationString)
{
    NTSTATUS Status;

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
UnprotectString(_In_z_ PWSTR wszProtected,
                _Out_ PWSTR *pwszUnprotected)
{
    CRED_PROTECTION_TYPE ProtectionType;

    *pwszUnprotected = nullptr;

    RETURN_IF_WIN32_BOOL_FALSE(CredIsProtected(wszProtected, &ProtectionType));

    if (ProtectionType == CredUnprotected)
        RETURN_NTSTATUS(STATUS_SUCCESS);

    size_t cchProtected = wcslen(wszProtected) + 1;
    DWORD cchUnprotected = 0;

    if (cchProtected > ULONG_MAX)
        RETURN_NTSTATUS(STATUS_BUFFER_OVERFLOW);

    if (CredUnprotect(FALSE, wszProtected, static_cast<DWORD>(cchProtected),
                      nullptr, &cchUnprotected))
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);

    DWORD dwError = GetLastError();
    if (dwError != ERROR_INSUFFICIENT_BUFFER)
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);
    else if (cchUnprotected == 0)
        RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

    *pwszUnprotected = static_cast<PWSTR>(WIL_AllocateMemory(cchUnprotected * sizeof(WCHAR)));
    RETURN_NTSTATUS_IF_NULL_ALLOC(*pwszUnprotected);

    if (!CredUnprotect(FALSE, wszProtected, static_cast<DWORD>(cchProtected),
                       *pwszUnprotected, &cchUnprotected)) {
        WIL_FreeMemory(*pwszUnprotected);
        *pwszUnprotected = nullptr;

        RETURN_LAST_ERROR(); // FIXME convert to NTSTATUS
    }

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

#define VALIDATE_UNPACK_UNICODE_STRING32(UnicodeString, WString) do {           \
        Status = ValidateAndUnpackUnicodeString32AllocZ(ClientRequest,          \
                                                        ProtocolSubmitBuffer,   \
                                                        ClientBufferBase,       \
                                                        SubmitBufferSize,       \
                                                        &(UnicodeString),       \
                                                        &(WString));            \
        RETURN_IF_NTSTATUS_FAILED(Status);                                      \
    } while (0)

#define VALIDATE_UNPACK_UNICODE_STRING(UnicodeString, WString) do {             \
        Status = ValidateAndUnpackUnicodeStringAllocZ(ClientRequest,            \
                                                      ProtocolSubmitBuffer,     \
                                                      ClientBufferBase,         \
                                                      SubmitBufferSize,         \
                                                      &(UnicodeString),         \
                                                      &(WString));              \
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
    PWSTR wszDomainName = nullptr;
    PWSTR wszUserName = nullptr;
    PWSTR wszPassword = nullptr;
    PWSTR wszUpnSuffix = nullptr;
    PWSTR wszUnprotectedPassword = nullptr;

    *pAuthIdentity = nullptr;

    auto cleanup = wil::scope_exit([&]() {
        WIL_FreeMemory(wszDomainName);
        WIL_FreeMemory(wszUserName);
        if (wszPassword != nullptr) {
            SecureZeroMemory(wszPassword, wcslen(wszPassword) * sizeof(WCHAR));
            WIL_FreeMemory(wszPassword);
        }
        if (wszUnprotectedPassword != nullptr) {
            SecureZeroMemory(wszUnprotectedPassword, wcslen(wszUnprotectedPassword) * sizeof(WCHAR));
            WIL_FreeMemory(wszUnprotectedPassword);
        }
                                   });

    if (IsWowClient()) {
        PKERB_INTERACTIVE_LOGON_WOW pKIL32;

        if (SubmitBufferSize < sizeof(*pKIL32))
            RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

        pKIL32 = static_cast<PKERB_INTERACTIVE_LOGON_WOW>(ProtocolSubmitBuffer);

        VALIDATE_UNPACK_UNICODE_STRING32(pKIL32->LogonDomainName, wszDomainName);
        VALIDATE_UNPACK_UNICODE_STRING32(pKIL32->UserName,        wszUserName);
        VALIDATE_UNPACK_UNICODE_STRING32(pKIL32->Password,        wszPassword);
    } else {
        PKERB_INTERACTIVE_LOGON pKIL;

        if (SubmitBufferSize < sizeof(*pKIL))
            RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

        pKIL = static_cast<PKERB_INTERACTIVE_LOGON>(ProtocolSubmitBuffer);

        VALIDATE_UNPACK_UNICODE_STRING(pKIL->LogonDomainName,     wszDomainName);
        VALIDATE_UNPACK_UNICODE_STRING(pKIL->UserName,            wszUserName);
        VALIDATE_UNPACK_UNICODE_STRING(pKIL->Password,            wszPassword);
    }

    /*
     * Canonicalize into user and domain components as we need to filter
     * the domain name to determine whether to attempt surrogate logon.
     */
    if (wszDomainName == nullptr || wszDomainName[0] == L'\0') {
        wszUpnSuffix = wcschr(wszUserName, L'@');
        if (wszUpnSuffix != nullptr) {
            *wszUpnSuffix = L'\0';
            wszUpnSuffix++;
        }
    } else {
        // Winlogon canonicalizes UPNSUFFIX\user to NETBIOSDOMAIN\user
        // which breaks unlock, so force UPN logons for now
        RETURN_NTSTATUS(STATUS_NO_SUCH_DOMAIN);
    }

    Status = UnprotectString(wszPassword, &wszUnprotectedPassword);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = SspiEncodeStringsAsAuthIdentity(wszUserName,
                                             wszUpnSuffix != nullptr ? wszUpnSuffix : wszDomainName,
                                             wszUnprotectedPassword != nullptr ? wszUnprotectedPassword : wszPassword,
                                             pAuthIdentity);
    RETURN_IF_NTSTATUS_FAILED(Status); // FIXME not NTSTATUS

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
ValidateTStrOffset(_In_ ULONG cbBuffer,
                   _In_ PTSTR pchBuffer,
                   _In_ ULONG cchOffset)
{
    size_t i;
    bool bNulTerminated = false;

    if (cchOffset * sizeof(TCHAR) > cbBuffer)
        RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

    auto BufferLengthCharacters = cbBuffer / sizeof(TCHAR);

    for (i = cchOffset; i < BufferLengthCharacters; i++) {
        if (pchBuffer[i] == L'\0') {
            bNulTerminated = true;
            break;
        }
    }

    if (!bNulTerminated)
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
ConvertCspDataToCertificateCredential(_In_reads_bytes_(CspDataLength) PVOID CspData,
                                      _In_ ULONG CspDataLength,
                                      _Out_ PWSTR *pMarshaledCredential)
{
    NTSTATUS Status;

    *pMarshaledCredential = nullptr;

    if (CspDataLength < sizeof(DWORD))
        RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

    auto pCspInfo = static_cast<PKERB_SMARTCARD_CSP_INFO>(CspData);

    if (CspDataLength < pCspInfo->dwCspInfoLen ||
        pCspInfo->dwCspInfoLen < sizeof(*pCspInfo) ||
        pCspInfo->MessageType != 1)
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);

    Status = ValidateTStrOffset(pCspInfo->dwCspInfoLen, &pCspInfo->bBuffer, pCspInfo->nCardNameOffset);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = ValidateTStrOffset(pCspInfo->dwCspInfoLen, &pCspInfo->bBuffer, pCspInfo->nReaderNameOffset);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = ValidateTStrOffset(pCspInfo->dwCspInfoLen, &pCspInfo->bBuffer, pCspInfo->nContainerNameOffset);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = ValidateTStrOffset(pCspInfo->dwCspInfoLen, &pCspInfo->bBuffer, pCspInfo->nCSPNameOffset);
    RETURN_IF_NTSTATUS_FAILED(Status);

    auto wszCardName      = &pCspInfo->bBuffer + pCspInfo->nCardNameOffset;
    auto wszReaderName    = &pCspInfo->bBuffer + pCspInfo->nReaderNameOffset;
    auto wszContainerName = &pCspInfo->bBuffer + pCspInfo->nContainerNameOffset;
    auto wszCspName       = &pCspInfo->bBuffer + pCspInfo->nCSPNameOffset;

    // FIXME: do we return an error if we have a non-default card/reader name
    if (wszCardName[0] || wszReaderName[0]) {
        RETURN_NTSTATUS(STATUS_SMARTCARD_NO_CARD);
    }

    HCRYPTPROV hCryptProv = 0;
    HCRYPTKEY hUserKey = 0;
    PBYTE pbCertificate = nullptr;
    DWORD cbCertificate = 0;
    PCCERT_CONTEXT CertContext = nullptr;

    auto cleanup = wil::scope_exit([&]() {
        if (CertContext != nullptr)
            CertFreeCertificateContext(CertContext);
        WIL_FreeMemory(pbCertificate);
        if (hUserKey)
            CryptDestroyKey(hUserKey);
        if (hCryptProv)
            CryptReleaseContext(hCryptProv, 0);
                                   });

    RETURN_IF_WIN32_BOOL_FALSE(CryptAcquireContext(&hCryptProv, wszContainerName, wszCspName,
                                                   PROV_RSA_FULL, CRYPT_SILENT));

    RETURN_IF_WIN32_BOOL_FALSE(CryptGetUserKey(hCryptProv, pCspInfo->KeySpec, &hUserKey));

    RETURN_IF_WIN32_BOOL_FALSE(CryptGetKeyParam(hUserKey, KP_CERTIFICATE, nullptr,
                                                &cbCertificate, 0));

    pbCertificate = static_cast<PBYTE>(WIL_AllocateMemory(cbCertificate));
    RETURN_NTSTATUS_IF_NULL_ALLOC(pbCertificate);

    RETURN_IF_WIN32_BOOL_FALSE(CryptGetKeyParam(hUserKey, KP_CERTIFICATE, pbCertificate,
                                                &cbCertificate, 0));

    CertContext = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                               pbCertificate,
                                               cbCertificate);
    RETURN_LAST_ERROR_IF_NULL(CertContext);

    CERT_CREDENTIAL_INFO CertCredentialInfo = { .cbSize = sizeof(CERT_CREDENTIAL_INFO) };
    DWORD cbHashOfCert = sizeof(CertCredentialInfo.rgbHashOfCert);

    RETURN_IF_WIN32_BOOL_FALSE(CertGetCertificateContextProperty(CertContext,
                                                                 CERT_HASH_PROP_ID,
                                                                 CertCredentialInfo.rgbHashOfCert,
                                                                 &cbHashOfCert));

    RETURN_IF_WIN32_BOOL_FALSE(CredMarshalCredential(CertCredential,
                                                     &CertCredentialInfo,
                                                     pMarshaledCredential));

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
ValidateAndUnpackCspData(_In_ PLSA_CLIENT_REQUEST ClientRequest,
                         _In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                         _In_ PVOID ClientBufferBase,
                         _In_ ULONG SubmitBufferSize,
                         _In_ ULONG_PTR CspData,
                         _In_ ULONG CspDataLength,
                         _Out_ PWSTR *pMarshaledCredential)
{
    NTSTATUS Status;

    *pMarshaledCredential = nullptr;

    Status = ValidateOffset(SubmitBufferSize, CspData, CspDataLength);
    if (NT_SUCCESS(Status)) {
        Status = ConvertCspDataToCertificateCredential(static_cast<PBYTE>(ProtocolSubmitBuffer) + CspData,
                                                       CspDataLength,
                                                       pMarshaledCredential);
        RETURN_IF_NTSTATUS_FAILED(Status);
    } else {
        PVOID ClientCspData = nullptr;

        auto cleanup = wil::scope_exit([&]() {
            WIL_FreeMemory(ClientCspData);
                });

        ClientCspData = WIL_AllocateMemory(CspDataLength);
        RETURN_NTSTATUS_IF_NULL_ALLOC(ClientCspData);

        Status = LsaSpFunctionTable->CopyFromClientBuffer(ClientRequest,
                                                          CspDataLength,
                                                          ClientCspData,
                                                          reinterpret_cast<PVOID>(CspData));
        RETURN_IF_NTSTATUS_FAILED(Status);

        Status = ConvertCspDataToCertificateCredential(ClientCspData, CspDataLength, pMarshaledCredential);
        RETURN_IF_NTSTATUS_FAILED(Status);
    }

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

#define VALIDATE_UNPACK_CSP_DATA(CspData, CspDataLength, WString) do {      \
        Status = ValidateAndUnpackCspData(ClientRequest,                    \
                                          ProtocolSubmitBuffer,             \
                                          ClientBufferBase,                 \
                                          SubmitBufferSize,                 \
                                          (CspData),                        \
                                          (CspDataLength),                  \
                                          &(WString));                      \
        RETURN_IF_NTSTATUS_FAILED(Status);                                  \
    } while (0)

static _Success_(return == STATUS_SUCCESS) NTSTATUS
ConvertKerbSmartCardLogonToAuthIdentity(_In_ PLSA_CLIENT_REQUEST ClientRequest,
                                        _In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                        _In_ PVOID ClientBufferBase,
                                        _In_ ULONG SubmitBufferSize,
                                        _Out_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE *pAuthIdentity)
{
    NTSTATUS Status;
    PWSTR wszPin = nullptr;
    PWSTR wszCspData = nullptr;
    PWSTR wszUnprotectedPin = nullptr;

    *pAuthIdentity = nullptr;

    auto cleanup = wil::scope_exit([&]() {
        if (wszPin != nullptr) {
            SecureZeroMemory(wszPin, wcslen(wszPin) * sizeof(WCHAR));
            WIL_FreeMemory(wszPin);
        }
        CredFree(wszCspData);
        if (wszUnprotectedPin != nullptr) {
            SecureZeroMemory(wszUnprotectedPin, wcslen(wszUnprotectedPin) * sizeof(WCHAR));
            WIL_FreeMemory(wszUnprotectedPin);
        }
                                   });

    if (IsWowClient()) {
        PKERB_SMART_CARD_LOGON_WOW pKSCL32;

        if (SubmitBufferSize < sizeof(*pKSCL32))
            RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

        pKSCL32 = static_cast<PKERB_SMART_CARD_LOGON_WOW>(ProtocolSubmitBuffer);

        VALIDATE_UNPACK_UNICODE_STRING32(pKSCL32->Pin, wszPin);
        VALIDATE_UNPACK_CSP_DATA(static_cast<ULONG_PTR>(pKSCL32->CspData),
                                 pKSCL32->CspDataLength,
                                 wszCspData);
    } else {
        PKERB_SMART_CARD_LOGON pKSCL;

        if (SubmitBufferSize < sizeof(*pKSCL))
            RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

        pKSCL = static_cast<PKERB_SMART_CARD_LOGON>(ProtocolSubmitBuffer);

        VALIDATE_UNPACK_UNICODE_STRING(pKSCL->Pin, wszPin);
        VALIDATE_UNPACK_CSP_DATA(reinterpret_cast<ULONG_PTR>(pKSCL->CspData),
                                 pKSCL->CspDataLength,
                                 wszCspData);
    }

    Status = UnprotectString(wszPin, &wszUnprotectedPin);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = SspiEncodeStringsAsAuthIdentity(wszCspData,
                                             nullptr,
                                             wszUnprotectedPin != nullptr ? wszUnprotectedPin : wszPin,
                                             pAuthIdentity);
    RETURN_IF_NTSTATUS_FAILED(Status); // FIXME not NTSTATUS

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
    PWSTR wszDomainName = nullptr;
    PWSTR wszUserName = nullptr;
    PWSTR wszPin = nullptr;
    PWSTR wszCspData = nullptr;
    PWSTR wszUnprotectedPin = nullptr;
    PWSTR wszUpnSuffix = nullptr;

    *pAuthIdentity = nullptr;

    auto cleanup = wil::scope_exit([&]() {
        WIL_FreeMemory(wszDomainName);
        WIL_FreeMemory(wszUserName);
        if (wszPin != nullptr) {
            SecureZeroMemory(wszPin, wcslen(wszPin) * sizeof(WCHAR));
            WIL_FreeMemory(wszPin);
        }
        CredFree(wszCspData);
        if (wszUnprotectedPin != nullptr) {
            SecureZeroMemory(wszUnprotectedPin, wcslen(wszUnprotectedPin) * sizeof(WCHAR));
            WIL_FreeMemory(wszUnprotectedPin);
        }
                                   });

    if (IsWowClient()) {
        PKERB_CERTIFICATE_LOGON_WOW pKCL32;

        if (SubmitBufferSize < sizeof(*pKCL32))
            RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

        pKCL32 = static_cast<PKERB_CERTIFICATE_LOGON_WOW>(ProtocolSubmitBuffer);

        VALIDATE_UNPACK_UNICODE_STRING32(pKCL32->DomainName, wszDomainName);
        VALIDATE_UNPACK_UNICODE_STRING32(pKCL32->UserName,   wszUserName);
        VALIDATE_UNPACK_UNICODE_STRING32(pKCL32->Pin,        wszPin);
        VALIDATE_UNPACK_CSP_DATA(static_cast<ULONG_PTR>(pKCL32->CspData),
                                 pKCL32->CspDataLength,
                                 wszCspData);
    } else {
        PKERB_CERTIFICATE_LOGON pKCL;

        if (SubmitBufferSize < sizeof(*pKCL))
            RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

        pKCL = static_cast<PKERB_CERTIFICATE_LOGON>(ProtocolSubmitBuffer);

        VALIDATE_UNPACK_UNICODE_STRING(pKCL->DomainName,     wszDomainName);
        VALIDATE_UNPACK_UNICODE_STRING(pKCL->UserName,       wszUserName);
        VALIDATE_UNPACK_UNICODE_STRING(pKCL->Pin,            wszPin);
        VALIDATE_UNPACK_CSP_DATA(reinterpret_cast<ULONG_PTR>(pKCL->CspData),
                                 pKCL->CspDataLength,
                                 wszCspData);
    }

    /*
     * Canonicalize into user and domain components as we need to filter
     * the domain name to determine whether to attempt surrogate logon.
     */
    if (wszDomainName == nullptr || wszDomainName[0] == L'\0') {
        wszUpnSuffix = wcschr(wszUserName, L'@');
        if (wszUpnSuffix != nullptr) {
            *wszUpnSuffix = L'\0';
            wszUpnSuffix++;
        }
    } else {
        // Winlogon canonicalizes UPNSUFFIX\user to NETBIOSDOMAIN\user
        // which breaks unlock, so force UPN logons for now
        RETURN_NTSTATUS(STATUS_NO_SUCH_DOMAIN);
    }

    // FIXME where do we put the user name? at least we can filter on domain

    Status = UnprotectString(wszPin, &wszUnprotectedPin);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = SspiEncodeStringsAsAuthIdentity(wszCspData,
                                             wszUpnSuffix != nullptr ? wszUpnSuffix : wszDomainName,
                                             wszUnprotectedPin != nullptr ? wszUnprotectedPin : wszPin,
                                             pAuthIdentity);
    RETURN_IF_NTSTATUS_FAILED(Status); // FIXME not NTSTATUS

    RETURN_NTSTATUS(STATUS_SUCCESS);
}


static _Success_(return == STATUS_SUCCESS) NTSTATUS
ValidateAuthIdentityEx2(PSEC_WINNT_AUTH_IDENTITY_EX2 AuthIdentityEx2)
{
    NTSTATUS Status;

    if (AuthIdentityEx2->Version != SEC_WINNT_AUTH_IDENTITY_VERSION_2)
        RETURN_NTSTATUS(STATUS_UNKNOWN_REVISION);

    if (AuthIdentityEx2->cbHeaderLength < sizeof(SEC_WINNT_AUTH_IDENTITY_EX2))
        RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

    Status = ValidateOffset(AuthIdentityEx2->cbStructureLength,
                            AuthIdentityEx2->UserOffset,
                            AuthIdentityEx2->UserLength);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = ValidateOffset(AuthIdentityEx2->cbStructureLength,
                            AuthIdentityEx2->DomainOffset,
                            AuthIdentityEx2->DomainLength);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = ValidateOffset(AuthIdentityEx2->cbStructureLength,
                            AuthIdentityEx2->PackedCredentialsOffset,
                            AuthIdentityEx2->PackedCredentialsLength);
    RETURN_IF_NTSTATUS_FAILED(Status);

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
ConvertSspiAuthIdentityToAuthIdentity(_In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                      _In_ ULONG SubmitBufferSize,
                                      _Out_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE *pAuthIdentity)
{
    PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity;
    NTSTATUS Status;
    SECURITY_STATUS SecStatus;

    *pAuthIdentity = nullptr;

    auto cleanup = wil::scope_exit([&]() {
        SspiFreeAuthIdentity(AuthIdentity);
    });

    SecStatus = SspiUnmarshalAuthIdentity(SubmitBufferSize,
                                          static_cast<PCHAR>(ProtocolSubmitBuffer),
                                          &AuthIdentity);
    if (SecStatus != SEC_E_OK)
        return SecStatus;

    Status = ValidateAuthIdentityEx2((PSEC_WINNT_AUTH_IDENTITY_EX2)AuthIdentity);
    RETURN_IF_NTSTATUS_FAILED(Status);

    if (SspiIsAuthIdentityEncrypted(AuthIdentity)) {
        SecStatus = SspiDecryptAuthIdentity(AuthIdentity);
        if (SecStatus != SEC_E_OK)
            return SecStatus;
    }

    *pAuthIdentity = AuthIdentity;
    AuthIdentity = nullptr;

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static _Success_(return == STATUS_SUCCESS) NTSTATUS
ConvertKerbLogonToAuthIdentity(_In_ PLSA_CLIENT_REQUEST ClientRequest,
                               _In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                               _In_ PVOID ClientBufferBase,
                               _In_ ULONG SubmitBufferSize,
                               _Out_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE *pAuthIdentity)
{
    KERB_LOGON_SUBMIT_TYPE LogonSubmitType =
        *(static_cast<PKERB_LOGON_SUBMIT_TYPE>(ProtocolSubmitBuffer));
    NTSTATUS Status;

    if (LogonSubmitType == KerbInteractiveLogon ||
        LogonSubmitType == KerbWorkstationUnlockLogon)
        Status = ConvertKerbInteractiveLogonToAuthIdentity(ClientRequest,
                                                           ProtocolSubmitBuffer,
                                                           ClientBufferBase,
                                                           SubmitBufferSize,
                                                           pAuthIdentity);
    else if (LogonSubmitType == KerbSmartCardLogon ||
             LogonSubmitType == KerbSmartCardUnlockLogon)
        Status = ConvertKerbSmartCardLogonToAuthIdentity(ClientRequest,
                                                         ProtocolSubmitBuffer,
                                                         ClientBufferBase,
                                                         SubmitBufferSize,
                                                         pAuthIdentity);
    else if (LogonSubmitType == KerbCertificateLogon ||
             LogonSubmitType == KerbCertificateUnlockLogon)
        Status = ConvertKerbCertificateLogonToAuthIdentity(ClientRequest,
                                                           ProtocolSubmitBuffer,
                                                           ClientBufferBase,
                                                           SubmitBufferSize,
                                                           pAuthIdentity);
    else
        Status = STATUS_INVALID_LOGON_TYPE;

    RETURN_IF_NTSTATUS_FAILED(Status);

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
        Status = ConvertSspiAuthIdentityToAuthIdentity(ProtocolSubmitBuffer,
                                                       SubmitBufferSize,
                                                       pAuthIdentity);
        break;
    case KerbInteractiveLogon:
    case KerbWorkstationUnlockLogon:
    case KerbSmartCardLogon:
    case KerbSmartCardUnlockLogon:
    case KerbCertificateLogon:
    case KerbCertificateUnlockLogon:
        Status = ConvertKerbLogonToAuthIdentity(ClientRequest,
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