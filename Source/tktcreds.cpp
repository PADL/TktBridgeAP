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

/*
 * Implements a simple credential cache for refreshing TGTs using cached
 * primary credentials of a user. Although the credentials are encrypted,
 * the user can disable this globally by setting the NO_INIT_CREDS_CACHE
 * flag in the registry. The cache is also used to lookup valid TGTs by
 * logon ID.
 *
 * Exceptions must not escape and must be translated to NTSTATUS codes.
 */

namespace TktBridgeAP {
    static LONGLONG LuidToQuadValue(const LUID &LogonId) {
        LARGE_INTEGER Value;

        Value.HighPart = LogonId.HighPart;
        Value.LowPart = LogonId.LowPart;

        return Value.QuadPart;
    };

    static auto CompareLuid = [](const LUID &A, const LUID &B) {
        return LuidToQuadValue(A) < LuidToQuadValue(B);
    };

    class Credentials {
    private:
        PTKTBRIDGEAP_CREDS m_Creds;

    public:
        Credentials(const Credentials &Creds) : Credentials(Creds.m_Creds) {}

        Credentials(PTKTBRIDGEAP_CREDS Creds) {
            this->m_Creds = ReferenceTktBridgeCreds(Creds);
        }

        ~Credentials() {
            DereferenceTktBridgeCreds(this->m_Creds);
        }

        PTKTBRIDGEAP_CREDS get() const {
            return m_Creds;
        }

        Credentials &operator=(const Credentials &Creds) {
            if (this != &Creds) {
                DereferenceTktBridgeCreds(m_Creds);
                this->m_Creds = Creds.m_Creds;
                ReferenceTktBridgeCreds(m_Creds);
            }

            return *this;
        }
    };

    static std::map<const LUID, class Credentials, decltype(CompareLuid)> CredsCache;
    static std::mutex CredsCacheLock;

    static bool IsZeroLuid(_In_ const LUID &LogonId) {
        auto pLogonId = &LogonId;
        return SecIsZeroLuid(pLogonId);
    }

    static bool EqualLuid(_In_ const LUID &A, _In_ const LUID &B) {
        auto pA = &A, pB = &B;
        return SecEqualLuid(pA, pB);
    }
}

using namespace TktBridgeAP;

/*
 * Locate credentials by logon session.
 */
_Success_(return == STATUS_SUCCESS) NTSTATUS
FindCredsForLogonSession(_In_ const LUID &LogonId,
                         _Out_ PTKTBRIDGEAP_CREDS *pTktBridgeCreds)
{
    NTSTATUS Status = STATUS_NO_SUCH_LOGON_SESSION;

    *pTktBridgeCreds = nullptr;

    if (IsZeroLuid(LogonId))
        RETURN_NTSTATUS(STATUS_NO_SUCH_LOGON_SESSION);

    try {
        std::lock_guard CredsCacheLockGuard(CredsCacheLock);
        auto CacheEntry = CredsCache.find(LogonId);

        if (CacheEntry != CredsCache.end()) {
            *pTktBridgeCreds = ReferenceTktBridgeCreds(CacheEntry->second.get());
            Status = STATUS_SUCCESS;
            assert((*pTktBridgeCreds)->RefCount > 1);
        }
    } catch (std::bad_alloc) {
        Status = STATUS_NO_MEMORY;
    } catch (std::exception) {
        Status = STATUS_UNHANDLED_EXCEPTION;
    }

    RETURN_NTSTATUS(Status);
}

/*
 * Save credentials for a logon session.
 */
_Success_(return == STATUS_SUCCESS) NTSTATUS
SaveCredsForLogonSession(_In_ const LUID &LogonId,
                         _In_ PTKTBRIDGEAP_CREDS TktBridgeCreds)
{
    NTSTATUS Status;

    if (IsZeroLuid(LogonId))
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);

    try {
        std::lock_guard CredsCacheLockGuard(CredsCacheLock);

        CredsCache.erase(LogonId);
        CredsCache.emplace(LogonId, Credentials(TktBridgeCreds));
        assert(TktBridgeCreds->RefCount > 1);
        Status = STATUS_SUCCESS;
    } catch (std::bad_alloc) {
        Status = STATUS_NO_MEMORY;
    } catch (std::exception) {
        Status = STATUS_UNHANDLED_EXCEPTION;
    }

    RETURN_NTSTATUS(Status);
}

/*
 * Remove credentials when a logon is terminated.
 */
_Success_(return == STATUS_SUCCESS) NTSTATUS
RemoveCredsForLogonSession(_In_ const LUID &LogonId)
{
    NTSTATUS Status;

    if (IsZeroLuid(LogonId))
        RETURN_NTSTATUS(STATUS_NO_SUCH_LOGON_SESSION);

    try {
        std::lock_guard CredsCacheLockGuard(CredsCacheLock);
        auto Count = CredsCache.erase(LogonId);

        Status = Count == 0 ? STATUS_NO_SUCH_LOGON_SESSION : STATUS_SUCCESS;
        RETURN_IF_NTSTATUS_FAILED_EXPECTED(Status); // logon may belong to another package
    } catch (std::bad_alloc) {
        Status = STATUS_NO_MEMORY;
    } catch (std::exception) {
        Status = STATUS_UNHANDLED_EXCEPTION;
    }

    RETURN_NTSTATUS(Status);
}

/*
 * Transfer credentials from one logon session to another.
 */
_Success_(return == STATUS_SUCCESS) NTSTATUS
TransferCredsFromLogonSession(_In_ const LUID &OriginLogonId,
                              _In_ const LUID &DestinationLogonId,
                              _In_ ULONG Flags)
{
    NTSTATUS Status = STATUS_NO_SUCH_LOGON_SESSION;

    if (IsZeroLuid(OriginLogonId))
        RETURN_NTSTATUS(STATUS_NO_SUCH_LOGON_SESSION);
    else if (IsZeroLuid(DestinationLogonId))
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);
    else if (EqualLuid(OriginLogonId, DestinationLogonId))
        RETURN_NTSTATUS(STATUS_SUCCESS);

    DebugTrace(WINEVENT_LEVEL_VERBOSE,
               L"TransferCredsFromLogonSession: OriginLogonId=%x:0x%x, "
               L"DestinationLogonId=%x:0x%x, Flags=%x",
               OriginLogonId.HighPart, OriginLogonId.LowPart,
               DestinationLogonId.HighPart, DestinationLogonId.LowPart,
               Flags);

    try {
        std::lock_guard CredsCacheLockGuard(CredsCacheLock);
        auto CacheEntry = CredsCache.find(OriginLogonId);

        if (CacheEntry != CredsCache.end()) {
            if (Flags & SECPKG_CALL_PACKAGE_TRANSFER_CRED_REQUEST_FLAG_CLEANUP_CREDENTIALS)
                CredsCache.erase(OriginLogonId);
            CredsCache.emplace(DestinationLogonId, CacheEntry->second);
            Status = STATUS_SUCCESS;
        }
    } catch (std::bad_alloc) {
        Status = STATUS_NO_MEMORY;
    } catch (std::exception) {
        Status = STATUS_UNHANDLED_EXCEPTION;
    }

    RETURN_NTSTATUS(Status);
}

PTKTBRIDGEAP_CREDS
AllocateTktBridgeCreds(VOID)
{
    auto Creds = static_cast<PTKTBRIDGEAP_CREDS>(AllocateCloudAPCallbackData());
    if (Creds == nullptr)
        return nullptr;

    Creds->RefCount = 1;

    return Creds;
}

PTKTBRIDGEAP_CREDS
ReferenceTktBridgeCreds(_Inout_ PTKTBRIDGEAP_CREDS Creds)
{
    if (Creds == nullptr)
        return nullptr;

    ValidateCloudAPCallbackData(Creds);

    if (Creds->RefCount != LONG_MAX)
        InterlockedIncrement(&Creds->RefCount);

    return Creds;
}

VOID
DereferenceTktBridgeCreds(_Inout_ PTKTBRIDGEAP_CREDS Creds)
{
    if (Creds == nullptr)
        return;

    ValidateCloudAPCallbackData(Creds);

    if (Creds->RefCount == LONG_MAX)
        return;

    auto Old = InterlockedDecrement(&Creds->RefCount) + 1;
    if (Old > 1)
        return;

    assert(Old == 1);

    WIL_FreeMemory(Creds->ClientName);
    krb5_data_free(&Creds->AsRep);

    if (Creds->AsReplyKey.keyvalue.data != nullptr) {
        SecureZeroMemory(Creds->AsReplyKey.keyvalue.data, Creds->AsReplyKey.keyvalue.length);
        krb5_free_keyblock_contents(nullptr, &Creds->AsReplyKey);
    }

    SspiFreeAuthIdentity(Creds->InitialCreds);

    ZeroMemory(Creds, sizeof(*Creds));
    LsaSpFunctionTable->FreeLsaHeap(Creds);
}

bool
IsTktBridgeCredsExpired(_In_ PTKTBRIDGEAP_CREDS Creds)
{
    FILETIME ftNow;
    LARGE_INTEGER liNow;

    GetSystemTimeAsFileTime(&ftNow);

    liNow.LowPart = ftNow.dwLowDateTime;
    liNow.HighPart = ftNow.dwHighDateTime;

    return Creds->EndTime.QuadPart < liNow.QuadPart;
}

#ifndef NDEBUG
VOID
DebugTktBridgeCredsCache(VOID)
{
    std::lock_guard CredsCacheLockGuard(CredsCacheLock);

    for (auto Iterator = CredsCache.begin();
         Iterator != CredsCache.end();
         Iterator++) {
        auto TktBridgeCreds = Iterator->second.get();

        DebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"Credential cache entry: LogonId=%x:0x%x, "
                   L"ClientName=%s, IsExpired=%d, InitialCreds=%p",
                   Iterator->first.HighPart,
                   Iterator->first.LowPart,
                   TktBridgeCreds->ClientName,
                   IsTktBridgeCredsExpired(TktBridgeCreds),
                   TktBridgeCreds->InitialCreds);
    }
}
#endif /* !NDEBUG */

NTSTATUS NTAPI
SpAcceptCredentials(_In_ SECURITY_LOGON_TYPE LogonType,
                    _In_ PUNICODE_STRING AccountName, // should be _In_opt_
                    _In_opt_ PSECPKG_PRIMARY_CRED PrimaryCredentials,
                    _In_opt_ PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials)
{
    const ULONG TransferFlags = PRIMARY_CRED_UPDATE | PRIMARY_CRED_EX | PRIMARY_CRED_TRANSFER;

    if (PrimaryCredentials == nullptr ||
        (PrimaryCredentials->Flags & TransferFlags) != TransferFlags)
        RETURN_NTSTATUS(STATUS_SUCCESS);

    auto PrimaryCredEx = reinterpret_cast<PSECPKG_PRIMARY_CRED_EX>(PrimaryCredentials);
    auto Status = TransferCredsFromLogonSession(PrimaryCredEx->PrevLogonId,
                                                PrimaryCredentials->LogonId);

    RETURN_NTSTATUS(Status);
}
