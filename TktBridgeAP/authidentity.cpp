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

static VOID
UnpackUnicodeString(_In_ PVOID ProtocolSubmitBuffer,
                    _In_ PCUNICODE_STRING SourceString,
                    _Inout_ PUNICODE_STRING DestinationString)
{
    DestinationString->Length        = SourceString->Length;
    DestinationString->MaximumLength = SourceString->MaximumLength;

    if (SourceString->Buffer != nullptr)
        DestinationString->Buffer = reinterpret_cast<PWSTR>
            ((static_cast<PBYTE>(ProtocolSubmitBuffer) + (ULONG_PTR)SourceString->Buffer));
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

static NTSTATUS _Success_(return == STATUS_SUCCESS)
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

static NTSTATUS _Success_(return == STATUS_SUCCESS)
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

static NTSTATUS _Success_(return == STATUS_SUCCESS)
ValidateOffset(_In_ ULONG cbBuffer,
               _In_ ULONG_PTR cbOffset,
               _In_ ULONG cbItem)
{
    if (cbOffset + cbItem > cbBuffer)
        RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);
    else
        RETURN_NTSTATUS(STATUS_SUCCESS);
}

static NTSTATUS _Success_(return == STATUS_SUCCESS)
ValidateAndUnpackUnicodeStringAllocZ(_In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                     _In_ ULONG SubmitBufferSize,
                                     _In_ PCUNICODE_STRING RelativeString,
                                     _Out_ PWSTR *DestinationString)
{
    NTSTATUS Status;

    Status = ValidateOffset(SubmitBufferSize,
                            (ULONG_PTR)RelativeString->Buffer,
                            RelativeString->Length);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = UnpackUnicodeStringAllocZ(ProtocolSubmitBuffer, RelativeString, DestinationString);
    RETURN_IF_NTSTATUS_FAILED(Status);

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static NTSTATUS _Success_(return == STATUS_SUCCESS)
ValidateAndUnpackUnicodeString32AllocZ(_In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                       _In_ ULONG SubmitBufferSize,
                                       _In_ PCKERB_UNICODE_STRING32 RelativeString,
                                       _Out_ PWSTR *DestinationString)
{
    NTSTATUS Status;

    Status = ValidateOffset(SubmitBufferSize,
                            (ULONG_PTR)RelativeString->Buffer,
                            RelativeString->Length);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = UnpackUnicodeString32AllocZ(ProtocolSubmitBuffer, RelativeString, DestinationString);
    RETURN_IF_NTSTATUS_FAILED(Status);

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static NTSTATUS _Success_(return == STATUS_SUCCESS)
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
    
    if (CredUnprotect(FALSE, wszProtected, (DWORD)cchProtected, nullptr, &cchUnprotected))
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);

    DWORD dwError = GetLastError();
    if (dwError != ERROR_INSUFFICIENT_BUFFER)
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);
    else if (cchUnprotected == 0)
        RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

    *pwszUnprotected = static_cast<PWSTR>(WIL_AllocateMemory(cchUnprotected * sizeof(WCHAR)));
    RETURN_NTSTATUS_IF_NULL_ALLOC(*pwszUnprotected);

    if (!CredUnprotect(FALSE, wszProtected, (DWORD)cchProtected,
                       *pwszUnprotected, &cchUnprotected)) {
        WIL_FreeMemory(*pwszUnprotected);
        *pwszUnprotected = nullptr;

        RETURN_LAST_ERROR(); // XXX convert to NTSTATUS
    }

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static NTSTATUS _Success_(return == STATUS_SUCCESS)
ConvertKerbInteractiveLogonToAuthIdentity(_In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                          _In_ ULONG SubmitBufferSize,
                                          _Out_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE *pAuthIdentity)
{
    NTSTATUS Status;
    PWSTR wszDomainName = nullptr;
    PWSTR wszUserName = nullptr;
    PWSTR wszPassword = nullptr;
    PWSTR wszUpnSuffix = nullptr;
    PWSTR wszUnprotectedPassword = nullptr;
    bool IsWowClient = !!(GetCallAttributes() & SECPKG_CALL_WOWCLIENT);

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

    if (IsWowClient) {
        PKERB_INTERACTIVE_LOGON32 pKIL32;

        if (SubmitBufferSize < sizeof(*pKIL32))
            RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

        pKIL32 = static_cast<PKERB_INTERACTIVE_LOGON32>(ProtocolSubmitBuffer);

        Status = ValidateAndUnpackUnicodeString32AllocZ(ProtocolSubmitBuffer,
                                                        SubmitBufferSize,
                                                        &pKIL32->LogonDomainName,
                                                        &wszDomainName);
        RETURN_IF_NTSTATUS_FAILED(Status);

        Status = ValidateAndUnpackUnicodeString32AllocZ(ProtocolSubmitBuffer,
                                                        SubmitBufferSize,
                                                        &pKIL32->UserName,
                                                        &wszUserName);
        RETURN_IF_NTSTATUS_FAILED(Status);

        Status = ValidateAndUnpackUnicodeString32AllocZ(ProtocolSubmitBuffer,
                                                        SubmitBufferSize,
                                                        &pKIL32->Password,
                                                        &wszPassword);
        RETURN_IF_NTSTATUS_FAILED(Status);
    } else {
        PKERB_INTERACTIVE_LOGON pKIL;

        if (SubmitBufferSize < sizeof(*pKIL))
            RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

        pKIL = static_cast<PKERB_INTERACTIVE_LOGON>(ProtocolSubmitBuffer);

        Status = ValidateAndUnpackUnicodeStringAllocZ(ProtocolSubmitBuffer,
                                                      SubmitBufferSize,
                                                      &pKIL->LogonDomainName,
                                                      &wszDomainName);
        RETURN_IF_NTSTATUS_FAILED(Status);

        Status = ValidateAndUnpackUnicodeStringAllocZ(ProtocolSubmitBuffer,
                                                      SubmitBufferSize,
                                                      &pKIL->UserName,
                                                      &wszUserName);
        RETURN_IF_NTSTATUS_FAILED(Status);

        Status = ValidateAndUnpackUnicodeStringAllocZ(ProtocolSubmitBuffer,
                                                      SubmitBufferSize,
                                                      &pKIL->Password,
                                                      &wszPassword);
        RETURN_IF_NTSTATUS_FAILED(Status);
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

static NTSTATUS _Success_(return == STATUS_SUCCESS)
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

static NTSTATUS _Success_(return == STATUS_SUCCESS)
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

    // TODO: do we return an error if we have a non-default card/reader name
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

static NTSTATUS _Success_(return == STATUS_SUCCESS)
ConvertKerbSmartCardLogonToAuthIdentity(_In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                        _In_ ULONG SubmitBufferSize,
                                        _Out_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE *pAuthIdentity)
{
    NTSTATUS Status;
    bool IsWowClient = !!(GetCallAttributes() & SECPKG_CALL_WOWCLIENT);
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

    if (IsWowClient) {
        PKERB_SMART_CARD_LOGON32 pKSCL32;

        if (SubmitBufferSize < sizeof(*pKSCL32))
            RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

        pKSCL32 = static_cast<PKERB_SMART_CARD_LOGON32>(ProtocolSubmitBuffer);

        Status = ValidateAndUnpackUnicodeString32AllocZ(ProtocolSubmitBuffer,
                                                        SubmitBufferSize,
                                                        &pKSCL32->Pin,
                                                        &wszPin);
        RETURN_IF_NTSTATUS_FAILED(Status);

        Status = ValidateOffset(SubmitBufferSize, pKSCL32->CspData, pKSCL32->CspDataLength);
        RETURN_IF_NTSTATUS_FAILED(Status);

        Status = ConvertCspDataToCertificateCredential(reinterpret_cast<PBYTE>(pKSCL32) + pKSCL32->CspData,
                                                       pKSCL32->CspDataLength,
                                                       &wszCspData);
        RETURN_IF_NTSTATUS_FAILED(Status);
    } else {
        PKERB_SMART_CARD_LOGON pKSCL;

        if (SubmitBufferSize < sizeof(*pKSCL))
            RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

        pKSCL = static_cast<PKERB_SMART_CARD_LOGON>(ProtocolSubmitBuffer);

        Status = ValidateAndUnpackUnicodeStringAllocZ(ProtocolSubmitBuffer,
                                                      SubmitBufferSize,
                                                      &pKSCL->Pin,
                                                      &wszPin);
        RETURN_IF_NTSTATUS_FAILED(Status);

        Status = ValidateOffset(SubmitBufferSize, (ULONG_PTR)pKSCL->CspData,
                                pKSCL->CspDataLength);
        RETURN_IF_NTSTATUS_FAILED(Status);

        Status = ConvertCspDataToCertificateCredential(reinterpret_cast<PBYTE>(pKSCL) + (ULONG_PTR)pKSCL->CspData,
                                                       pKSCL->CspDataLength,
                                                       &wszCspData);
        RETURN_IF_NTSTATUS_FAILED(Status);
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

static NTSTATUS _Success_(return == STATUS_SUCCESS)
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

static NTSTATUS _Success_(return == STATUS_SUCCESS)
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
                                          (PCHAR)ProtocolSubmitBuffer,
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

static NTSTATUS _Success_(return == STATUS_SUCCESS)
ConvertAuthenticationBufferToAuthIdentity(_In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                          _In_ ULONG SubmitBufferSize,
                                          _Out_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE *pAuthIdentity,
                                          _Out_opt_ PLUID pUnlockLogonId)
{
    KERB_LOGON_SUBMIT_TYPE LogonSubmitType = *(KERB_LOGON_SUBMIT_TYPE *)ProtocolSubmitBuffer;
    NTSTATUS Status;

    if (pUnlockLogonId != nullptr) {
        bool IsWowClient = !!(GetCallAttributes() & SECPKG_CALL_WOWCLIENT);

        pUnlockLogonId->LowPart = 0;
        pUnlockLogonId->HighPart = 0;

        if (IsWowClient) {
            if (LogonSubmitType == KerbWorkstationUnlockLogon)
                *pUnlockLogonId = static_cast<PKERB_INTERACTIVE_UNLOCK_LOGON32>(ProtocolSubmitBuffer)->LogonId;
            else if (LogonSubmitType == KerbSmartCardUnlockLogon)
                *pUnlockLogonId = static_cast<PKERB_SMART_CARD_UNLOCK_LOGON32>(ProtocolSubmitBuffer)->LogonId;
        } else {
            if (LogonSubmitType == KerbWorkstationUnlockLogon)
                *pUnlockLogonId = static_cast<PKERB_INTERACTIVE_UNLOCK_LOGON>(ProtocolSubmitBuffer)->LogonId;
            else if (LogonSubmitType == KerbSmartCardUnlockLogon)
                *pUnlockLogonId = static_cast<PKERB_SMART_CARD_UNLOCK_LOGON>(ProtocolSubmitBuffer)->LogonId;
        }
    }

    if (LogonSubmitType == KerbInteractiveLogon ||
        LogonSubmitType == KerbWorkstationUnlockLogon)
        Status = ConvertKerbInteractiveLogonToAuthIdentity(ProtocolSubmitBuffer,
                                                           SubmitBufferSize,
                                                           pAuthIdentity);
    else if (LogonSubmitType == KerbSmartCardLogon ||
             LogonSubmitType == KerbSmartCardUnlockLogon)
        Status = ConvertKerbSmartCardLogonToAuthIdentity(ProtocolSubmitBuffer,
                                                         SubmitBufferSize,
                                                         pAuthIdentity);
    else
        Status = STATUS_INVALID_LOGON_TYPE;

    RETURN_NTSTATUS(Status);
}

NTSTATUS _Success_(return == STATUS_SUCCESS)
ConvertLogonSubmitBufferToAuthIdentity(_In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                       _In_ ULONG SubmitBufferSize,
                                       _Out_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE *pAuthIdentity,
                                       _Out_opt_ PLUID pUnlockLogonId)
{
    NTSTATUS Status;

    *pAuthIdentity = nullptr;

    if (pUnlockLogonId != nullptr) {
        pUnlockLogonId->LowPart = 0;
        pUnlockLogonId->HighPart = 0;
    }

    if (SubmitBufferSize < sizeof(KERB_LOGON_SUBMIT_TYPE))
        RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

    // FIXME can we use CredUnPackAuthenticationBuffer() instead?

    static_assert(sizeof(ULONG) == sizeof(KERB_LOGON_SUBMIT_TYPE));
    KERB_LOGON_SUBMIT_TYPE LogonSubmitType = *(KERB_LOGON_SUBMIT_TYPE *)ProtocolSubmitBuffer;

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
        Status = ConvertAuthenticationBufferToAuthIdentity(ProtocolSubmitBuffer,
                                                           SubmitBufferSize,
                                                           pAuthIdentity,
                                                           pUnlockLogonId);
        break;
    default:
        Status = STATUS_SUCCESS;
        break;
    }

    RETURN_NTSTATUS(Status);
}
