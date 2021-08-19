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
UnpackUnicodeString(_In_ PVOID BasePtr,
                    _In_ PCUNICODE_STRING Source,
                    _Inout_ PUNICODE_STRING Dest)
{
    Dest->Length        = Source->Length;
    Dest->MaximumLength = Source->MaximumLength;

    if (Source->Buffer != nullptr)
        Dest->Buffer = (PWSTR)((PBYTE)BasePtr + (ULONG_PTR)Source->Buffer);
    else
        Dest->Buffer = nullptr;
}

static NTSTATUS
UnpackUnicodeStringAllocZ(_In_ PVOID BasePtr,
                          _In_ PCUNICODE_STRING Source,
                          _Out_ PWSTR *Dest)
{
    UNICODE_STRING DestUS;
    UNICODE_STRING DestUSZ;

    RtlInitUnicodeString(&DestUS, NULL);
    RtlInitUnicodeString(&DestUSZ, NULL);

    UnpackUnicodeString(BasePtr, Source, &DestUS);

    auto Status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
                                            &DestUS, &DestUSZ);
    RETURN_IF_NTSTATUS_FAILED(Status);

    *Dest = DestUSZ.Buffer;

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static NTSTATUS
ValidateOffset(_In_ ULONG SubmitBufferSize,
               _In_ ULONG_PTR Offset,
               _In_ ULONG Length)
{
    if (Offset + Length > SubmitBufferSize)
        RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);
    else
        RETURN_NTSTATUS(STATUS_SUCCESS);
}

static NTSTATUS
ValidateAndUnpackUnicodeStringAllocZ(_In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                     _In_ ULONG SubmitBufferSize,
                                     _In_ PCUNICODE_STRING RelativeString,
                                     _Out_ PWSTR *Dest)
{
    NTSTATUS Status;

    Status = ValidateOffset(SubmitBufferSize,
                            (ULONG_PTR)RelativeString->Buffer,
                            RelativeString->Length);
    RETURN_IF_NTSTATUS_FAILED(Status);

    Status = UnpackUnicodeStringAllocZ(ProtocolSubmitBuffer, RelativeString, Dest);
    RETURN_IF_NTSTATUS_FAILED(Status);

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static NTSTATUS _Success_(return == STATUS_SUCCESS)
ConvertKerbInteractiveLogonToAuthIdentity(_In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                          _In_ PVOID ClientBufferBase,
                                          _In_ ULONG SubmitBufferSize,
                                          _Out_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE *pAuthIdentity)
{
    PKERB_INTERACTIVE_LOGON pKIL;
    NTSTATUS Status;

    *pAuthIdentity = nullptr;

    if (SubmitBufferSize < sizeof(*pKIL))
        RETURN_NTSTATUS(STATUS_BUFFER_TOO_SMALL);

    pKIL = (PKERB_INTERACTIVE_LOGON)ProtocolSubmitBuffer;

    PWSTR wszDomainName = nullptr;
    PWSTR wszUserName = nullptr;
    PWSTR wszPassword = nullptr;

    auto cleanup = wil::scope_exit([&]() {
        WIL_FreeMemory(wszDomainName);
        WIL_FreeMemory(wszUserName);
        if (wszPassword != nullptr) {
            SecureZeroMemory(wszPassword, wcslen(wszPassword) * sizeof(WCHAR));
            WIL_FreeMemory(wszPassword);
        }
                                   });
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

    Status = SspiEncodeStringsAsAuthIdentity(wszUserName,
                                             wszDomainName,
                                             wszPassword,
                                             pAuthIdentity);
    RETURN_IF_NTSTATUS_FAILED(Status); // FIXME not NTSTATUS

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

static NTSTATUS _Success_(return == STATUS_SUCCESS)
ConvertKerbSmartCardLogonToAuthIdentity(_In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                                        _In_ PVOID ClientBufferBase,
                                        _In_ ULONG SubmitBufferSize,
                                        _Out_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE *pAuthIdentity)
{
    *pAuthIdentity = nullptr;

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
                                      _In_ PVOID ClientBufferBase,
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

NTSTATUS _Success_(return == STATUS_SUCCESS)
ConvertKerbLogonToAuthIdentity(_In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
                               _In_ PVOID ClientBufferBase,
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

    if (LogonSubmitType == KerbInteractiveLogon ||
        LogonSubmitType == KerbWorkstationUnlockLogon) {
        Status = ConvertKerbInteractiveLogonToAuthIdentity(ProtocolSubmitBuffer,
                                                           ClientBufferBase,
                                                           SubmitBufferSize,
                                                           pAuthIdentity);
    } else if (LogonSubmitType == KerbSmartCardLogon ||
               LogonSubmitType == KerbSmartCardUnlockLogon) {
        Status = ConvertKerbSmartCardLogonToAuthIdentity(ProtocolSubmitBuffer,
                                                         ClientBufferBase,
                                                         SubmitBufferSize,
                                                         pAuthIdentity);
    } else if (LogonSubmitType == SEC_WINNT_AUTH_IDENTITY_VERSION_2) {
        Status = ConvertSspiAuthIdentityToAuthIdentity(ProtocolSubmitBuffer,
                                                       ClientBufferBase,
                                                       SubmitBufferSize,
                                                       pAuthIdentity);
    } else {
        Status = STATUS_INVALID_LOGON_TYPE;
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
