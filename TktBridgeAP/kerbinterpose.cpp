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

#include "detours.h"

static PSECPKG_FUNCTION_TABLE KerbFunctionTable;
static HMODULE hKerbPackage;

static _Success_(return == ERROR_SUCCESS) DWORD
LoadKerbPackage(VOID)
{
    NTSTATUS Status;
    ULONG PackageVersion, cTables = 0;
    SpLsaModeInitializeFn KerbLsaModeInitialize;

    auto cleanup = wil::scope_exit([&]() {
        if (hKerbPackage != nullptr && KerbFunctionTable == nullptr) {
            FreeLibrary(hKerbPackage);
            hKerbPackage = nullptr;
        }
                                   });

    hKerbPackage = LoadLibrary(L"kerberos.dll");
    if (hKerbPackage == nullptr)
        RETURN_WIN32(ERROR_DLL_NOT_FOUND);

    KerbLsaModeInitialize =
        (SpLsaModeInitializeFn)GetProcAddress(hKerbPackage,
                                              "SpLsaModeInitialize");
    if (KerbLsaModeInitialize == nullptr)
        RETURN_WIN32(ERROR_BAD_DLL_ENTRYPOINT);

    Status = KerbLsaModeInitialize(SECPKG_INTERFACE_VERSION,
                                   &PackageVersion,
                                   &KerbFunctionTable,
                                   &cTables);
    RETURN_IF_WIN32_ERROR(RtlNtStatusToDosError(Status));

    if (cTables == 0 ||
        PackageVersion < SECPKG_INTERFACE_VERSION_10 ||
        KerbFunctionTable->LogonUserEx3 == nullptr) {
        KerbFunctionTable = nullptr;
        RETURN_WIN32(ERROR_UNKNOWN_REVISION);
    }

    RETURN_WIN32(ERROR_SUCCESS);
}

/*
 * An extremely inelegant kludge to force the native Kerberos security
 * package to pick up surrogate credentials containing an AS-REP, by
 * pretending the logon was a FIDO logon. The contents of the credentials
 * are ignored so we can leave them empty.
 *
 * The interposed function is transparent to the Kerberos package if
 * TktBridgeAP-issued surrogate logon credentials cannot be found.
 *
 * The real fix would be for MS to document these APIs and not require
 * FIDO credentials to honor AS-REP credentials
 */

static NTSTATUS
KerbLogonUserEx3Interposer(_In_ PLSA_CLIENT_REQUEST ClientRequest,
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
                           _Outptr_ PVOID *TokenInformation,
                           _Out_ PUNICODE_STRING *AccountName,
                           _Out_ PUNICODE_STRING *AuthenticatingAuthority,
                           _Out_ PUNICODE_STRING *MachineName,
                           _Out_ PSECPKG_PRIMARY_CRED PrimaryCredentials,
                           _Outptr_ PSECPKG_SUPPLEMENTAL_CRED_ARRAY *SupplementalCredentials)
{
    struct _FIDO_AUTH_IDENTITY {
        SEC_WINNT_AUTH_IDENTITY_EX2 AuthIdentity;
        SEC_WINNT_AUTH_PACKED_CREDENTIALS PackedCreds;
    } FidoAuthIdentity;
    auto SurrogateLogonCreds = FindSurrogateLogonCreds(SurrogateLogon);

    DebugTrace(WINEVENT_LEVEL_VERBOSE,
               L"KerbLogonUserEx3Interposer: LogonType %d SurrogateCreds %p",
               LogonType, SurrogateLogonCreds);

    if (SurrogateLogonCreds != nullptr) {
        ZeroMemory(&FidoAuthIdentity, sizeof(FidoAuthIdentity));

        FidoAuthIdentity.AuthIdentity.Version                 = SEC_WINNT_AUTH_IDENTITY_VERSION_2;
        FidoAuthIdentity.AuthIdentity.cbHeaderLength          = sizeof(FidoAuthIdentity.AuthIdentity);
        FidoAuthIdentity.AuthIdentity.cbStructureLength       = sizeof(FidoAuthIdentity);
        FidoAuthIdentity.AuthIdentity.PackedCredentialsOffset = offsetof(struct _FIDO_AUTH_IDENTITY, PackedCreds);
        FidoAuthIdentity.AuthIdentity.PackedCredentialsLength = sizeof(FidoAuthIdentity.PackedCreds);
        FidoAuthIdentity.AuthIdentity.Flags                   = SEC_WINNT_AUTH_IDENTITY_MARSHALLED;

        FidoAuthIdentity.PackedCreds.cbHeaderLength           = sizeof(FidoAuthIdentity.PackedCreds);
        FidoAuthIdentity.PackedCreds.cbStructureLength        = sizeof(FidoAuthIdentity.PackedCreds);
        FidoAuthIdentity.PackedCreds.AuthData.CredType        = SEC_WINNT_AUTH_DATA_TYPE_FIDO;

        ProtocolSubmitBuffer = &FidoAuthIdentity;
        SubmitBufferSize = FidoAuthIdentity.AuthIdentity.cbStructureLength;
    }

    auto Status = KerbFunctionTable->LogonUserEx3(ClientRequest,
                                                  LogonType,
                                                  ProtocolSubmitBuffer,
                                                  ClientBufferBase,
                                                  SubmitBufferSize,
                                                  SurrogateLogon,
                                                  ProfileBuffer,
                                                  ProfileBufferSize,
                                                  LogonId,
                                                  SubStatus,
                                                  TokenInformationType,
                                                  TokenInformation,
                                                  AccountName,
                                                  AuthenticatingAuthority,
                                                  MachineName,
                                                  PrimaryCredentials,
                                                  SupplementalCredentials);

    /*
     * Call our PostLogonUserSurrogate before CloudAP can get to it and stomp
     * on our data.
     */
    LsaApPostLogonUserSurrogate(ClientRequest,
                                LogonType,
                                ProtocolSubmitBuffer,
                                ClientBufferBase,
                                SubmitBufferSize,
                                SurrogateLogon,
                                ProfileBuffer,
                                *ProfileBufferSize,
                                LogonId,
                                Status,
                                *SubStatus,
                                *TokenInformationType,
                                TokenInformation,
                                *AccountName,
                                *AuthenticatingAuthority,
                                *MachineName,
                                PrimaryCredentials,
                                *SupplementalCredentials);

    return Status;
}

DWORD _Success_(return == ERROR_SUCCESS)
AttachKerbLogonInterposer(VOID)
{
    DWORD dwError;
    bool BegunTransaction = false;

    auto cleanup = wil::scope_exit([&]() {
        if (dwError != ERROR_SUCCESS && BegunTransaction)
            DetourTransactionAbort();
                                   });

    dwError = LoadKerbPackage();
    RETURN_IF_WIN32_ERROR(dwError);

    dwError = DetourTransactionBegin();
    RETURN_IF_WIN32_ERROR(dwError);

    BegunTransaction = true;

    dwError = DetourUpdateThread(GetCurrentThread());
    RETURN_IF_WIN32_ERROR(dwError);

    dwError = DetourAttach(&(PVOID &)KerbFunctionTable->LogonUserEx3, KerbLogonUserEx3Interposer);
    RETURN_IF_WIN32_ERROR(dwError);

    dwError = DetourTransactionCommit();
    RETURN_IF_WIN32_ERROR(dwError);

    RETURN_WIN32(ERROR_SUCCESS);
}

VOID
DetachKerbLogonInterposer(VOID)
{
    DWORD dwError;

    if (hKerbPackage == nullptr)
        return;

    dwError = DetourTransactionBegin();
    if (dwError == ERROR_SUCCESS) {
        dwError = DetourUpdateThread(GetCurrentThread());
        if (dwError == ERROR_SUCCESS)
            DetourDetach(&(PVOID &)KerbFunctionTable->LogonUserEx3, KerbLogonUserEx3Interposer);
        if (dwError == ERROR_SUCCESS)
            DetourTransactionCommit();
        else
            DetourTransactionAbort();
    }

    FreeLibrary(hKerbPackage);
    hKerbPackage = nullptr;
    KerbFunctionTable = nullptr;
}
