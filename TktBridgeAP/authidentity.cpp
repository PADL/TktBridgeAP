/*++

Copyright (c) PADL Software Pty Ltd, All rights reserved.

Module Name:

    authidentity.cpp

Abstract:

    Convert between auth identity types.

Environment:

    Local Security Authority (LSA)

--*/

#include "TktBridgeAP.h"

#include <ntstatus.h>

static VOID
UnpackUnicodeString(_In_ PVOID ProtocolSubmitBuffer,
                    _In_ PCUNICODE_STRING SourceString,
                    _Inout_ PUNICODE_STRING DestinationString)
{
    DestinationString->Length        = SourceString->Length;
    DestinationString->MaximumLength = SourceString->MaximumLength;

    if (SourceString->Buffer != nullptr)
        DestinationString->Buffer = (PWSTR)((PBYTE)ProtocolSubmitBuffer +
                                            (ULONG_PTR)SourceString->Buffer);
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
        RETURN_NTSTATUS(dwError);
    else if (cchUnprotected == 0)
        RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

    *pwszUnprotected = (PWSTR)WIL_AllocateMemory(cchUnprotected * sizeof(WCHAR));
    RETURN_NTSTATUS_IF_NULL_ALLOC(*pwszUnprotected);

    if (!CredUnprotect(FALSE, wszProtected, (DWORD)cchProtected,
                       *pwszUnprotected, &cchUnprotected)) {
        WIL_FreeMemory(*pwszUnprotected);
        *pwszUnprotected = nullptr;

        RETURN_NTSTATUS(GetLastError()); // XXX
    }

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static NTSTATUS _Success_(return == STATUS_SUCCESS)
ConvertKerbInteractiveLogonToAuthIdentity(_In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                          _In_ ULONG SubmitBufferSize,
                                          _Out_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE *pAuthIdentity)
{
    NTSTATUS Status;
    PKERB_INTERACTIVE_LOGON pKIL;
    PWSTR wszDomainName = nullptr;
    PWSTR wszUserName = nullptr;
    PWSTR wszPassword = nullptr;
    PWSTR wszUpnSuffix = nullptr;
    PWSTR wszUnprotectedPassword = nullptr;

    *pAuthIdentity = nullptr;

    if (SubmitBufferSize < sizeof(*pKIL))
        RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

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

    pKIL = (PKERB_INTERACTIVE_LOGON)ProtocolSubmitBuffer;

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

    if (pKIL->LogonDomainName.Length == 0) {
        // canonicalize into user and domain components as we need to filter
        // the domain before getting credentials
        wszUpnSuffix = wcschr(wszUserName, L'@');
        if (wszUpnSuffix != nullptr) {
            *wszUpnSuffix = L'\0';
            wszUpnSuffix++;
        }
    }

    Status = ValidateAndUnpackUnicodeStringAllocZ(ProtocolSubmitBuffer,
                                                  SubmitBufferSize,
                                                  &pKIL->Password,
                                                  &wszPassword);
    RETURN_IF_NTSTATUS_FAILED(Status);

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

    auto pCspInfo = (PKERB_SMARTCARD_CSP_INFO)CspData;

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

    pbCertificate = (PBYTE)WIL_AllocateMemory(cbCertificate);
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
    PKERB_SMART_CARD_LOGON pKSCL;
    NTSTATUS Status;

    *pAuthIdentity = nullptr;

    if (SubmitBufferSize < sizeof(*pKSCL))
        RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

    pKSCL = (PKERB_SMART_CARD_LOGON)ProtocolSubmitBuffer;

    PWSTR wszPin = nullptr;
    PWSTR wszCspData = nullptr;
    PWSTR wszUnprotectedPin = nullptr;
 
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

    Status = ValidateAndUnpackUnicodeStringAllocZ(ProtocolSubmitBuffer,
                                                  SubmitBufferSize,
                                                  &pKSCL->Pin,
                                                  &wszPin);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = UnprotectString(wszPin, &wszUnprotectedPin);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = ValidateOffset(SubmitBufferSize, (ULONG_PTR)pKSCL->CspData,
                            pKSCL->CspDataLength);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = ConvertCspDataToCertificateCredential(pKSCL->CspData,
                                                   pKSCL->CspDataLength,
                                                   &wszCspData);
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
                                          _Out_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE * pAuthIdentity)
{
#if 1
    KERB_LOGON_SUBMIT_TYPE LogonSubmitType = *(KERB_LOGON_SUBMIT_TYPE *)ProtocolSubmitBuffer;
    NTSTATUS Status;

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
#else
    NTSTATUS Status;
    DWORD cchlMaxUserName = 0;
    DWORD cchlMaxDomainName = 0;
    DWORD cchlMaxPassword = 0;

    *pAuthIdentity = nullptr;

    if (CredUnPackAuthenticationBuffer(CRED_PACK_PROTECTED_CREDENTIALS,
                                       ProtocolSubmitBuffer,
                                       SubmitBufferSize,
                                       nullptr,
                                       &cchlMaxUserName,
                                       nullptr,
                                       &cchlMaxDomainName,
                                       nullptr,
                                       &cchlMaxPassword) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        RETURN_NTSTATUS(STATUS_NOT_SUPPORTED);
    }

    PWSTR wszUserName = nullptr;
    PWSTR wszDomainName = nullptr;
    PWSTR wszPassword = nullptr;

    auto cleanup = wil::scope_exit([&]() {
        WIL_FreeMemory(wszUserName);
        WIL_FreeMemory(wszDomainName);
        if (wszPassword != nullptr) {
            SecureZeroMemory(wszPassword, wcslen(wszPassword) * sizeof(WCHAR));
            WIL_FreeMemory(wszPassword);
        }
                                   });

    wszUserName = (PWSTR)WIL_AllocateMemory(cchlMaxUserName * sizeof(WCHAR));
    RETURN_NTSTATUS_IF_NULL_ALLOC(wszUserName);

    wszDomainName = (PWSTR)WIL_AllocateMemory(cchlMaxDomainName * sizeof(WCHAR));
    RETURN_NTSTATUS_IF_NULL_ALLOC(wszDomainName);

    wszPassword = (PWSTR)WIL_AllocateMemory(cchlMaxPassword * sizeof(WCHAR));
    RETURN_NTSTATUS_IF_NULL_ALLOC(wszPassword);

    if (!CredUnPackAuthenticationBuffer(CRED_PACK_PROTECTED_CREDENTIALS,
                                        ProtocolSubmitBuffer,
                                        SubmitBufferSize,
                                        wszUserName,
                                        &cchlMaxUserName,
                                        wszDomainName,
                                        &cchlMaxDomainName,
                                        wszPassword,
                                        &cchlMaxPassword))
        RETURN_NTSTATUS(GetLastError()); // FIXME

    Status = SspiEncodeStringsAsAuthIdentity(wszUserName,
                                             wszDomainName,
                                             wszPassword,
                                             pAuthIdentity);
    RETURN_IF_NTSTATUS_FAILED(Status);

    RETURN_NTSTATUS(STATUS_SUCCESS);
#endif
}

NTSTATUS _Success_(return == STATUS_SUCCESS)
ConvertLogonSubmitBufferToAuthIdentity(_In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                       _In_ ULONG SubmitBufferSize,
                                       _Out_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE *pAuthIdentity,
                                       _Out_ PLUID pUnlockLogonID)
{
    NTSTATUS Status;

    *pAuthIdentity = nullptr;

    if (SubmitBufferSize < sizeof(KERB_LOGON_SUBMIT_TYPE))
        RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

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
                                                           pAuthIdentity);
        break;
    default:
        Status = STATUS_INVALID_LOGON_TYPE;
        break;
    }
    RETURN_IF_NTSTATUS_FAILED(Status);

    if (LogonSubmitType == KerbWorkstationUnlockLogon) {
        *pUnlockLogonID = ((PKERB_INTERACTIVE_UNLOCK_LOGON)ProtocolSubmitBuffer)->LogonId;
    } else if (LogonSubmitType == KerbSmartCardUnlockLogon) {
        *pUnlockLogonID = ((PKERB_SMART_CARD_UNLOCK_LOGON)ProtocolSubmitBuffer)->LogonId;
    } else {
        pUnlockLogonID->LowPart = 0;
        pUnlockLogonID->HighPart = 0;
    }

    RETURN_NTSTATUS(STATUS_SUCCESS);
}
