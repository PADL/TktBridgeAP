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

/*
 * Implements a simple credential cache for refreshing TGTs using cached
 * primary credentials of a user. Although the credentials are encrypted,
 * the user can disable this globally by setting the NO_CLEAR_CRED_CACHE
 * flag in the registry.
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

    static std::map<const LUID, class Credentials, decltype(CompareLuid)> CredCache;
    static std::mutex CredCacheLock;
}

using namespace TktBridgeAP;

_Success_(return == STATUS_SUCCESS) NTSTATUS
FindCredForLogonSession(_In_ const LUID &LogonID,
                        _Out_ PTKTBRIDGEAP_CREDS *pTktBridgeCreds)
{
    NTSTATUS Status = STATUS_NO_SUCH_LOGON_SESSION;
    std::lock_guard CredCacheLockGuard(CredCacheLock);

    *pTktBridgeCreds = nullptr;

    try {
        auto CacheEntry = CredCache.find(LogonID);
        if (CacheEntry != CredCache.end()) {
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

_Success_(return == STATUS_SUCCESS) NTSTATUS
SaveCredForLogonSession(_In_ const LUID &LogonID,
                        _In_ PTKTBRIDGEAP_CREDS TktBridgeCreds)
{
    NTSTATUS Status;
    std::lock_guard CredCacheLockGuard(CredCacheLock);

    try {
        CredCache.erase(LogonID);
        CredCache.emplace(LogonID, Credentials(TktBridgeCreds));
        assert(TktBridgeCreds->RefCount > 1);
        Status = STATUS_SUCCESS;
    } catch (std::bad_alloc) {
        Status = STATUS_NO_MEMORY;
    } catch (std::exception) {
        Status = STATUS_UNHANDLED_EXCEPTION;
    }

    RETURN_NTSTATUS(Status);
}

_Success_(return == STATUS_SUCCESS) NTSTATUS
RemoveCredForLogonSession(_In_ const LUID &LogonID)
{
    NTSTATUS Status;
    std::lock_guard CredCacheLockGuard(CredCacheLock);

    try {
        auto Count = CredCache.erase(LogonID);
        Status = Count == 0 ? STATUS_NO_SUCH_LOGON_SESSION : STATUS_SUCCESS;
        RETURN_IF_NTSTATUS_FAILED_EXPECTED(Status); // logon may belong to another package
    } catch (std::bad_alloc) {
        Status = STATUS_NO_MEMORY;
    } catch (std::exception) {
        Status = STATUS_UNHANDLED_EXCEPTION;
    }

    RETURN_NTSTATUS(Status);
}

VOID
DebugLogonCreds(VOID)
{
    std::lock_guard CredCacheLockGuard(CredCacheLock);

    for (auto Iterator = CredCache.begin();
         Iterator != CredCache.end();
         Iterator++) {
        auto TktBridgeCreds = Iterator->second.get();

        DebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"Credential cache entry: Logon Session %08x.%08x ClientName %s IsExpired %d InitialCreds %p",
                   Iterator->first.LowPart,
                   Iterator->first.HighPart,
                   TktBridgeCreds->ClientName,
                   IsTktBridgeCredsExpired(TktBridgeCreds),
                   TktBridgeCreds->InitialCreds);
    }
}

PTKTBRIDGEAP_CREDS
AllocateTktBridgeCreds(VOID)
{
    PTKTBRIDGEAP_CREDS TktBridgeCreds;

    TktBridgeCreds = static_cast<PTKTBRIDGEAP_CREDS>(WIL_AllocateMemory(sizeof(*TktBridgeCreds)));
    if (TktBridgeCreds == nullptr)
        return nullptr;

    ZeroMemory(TktBridgeCreds, sizeof(*TktBridgeCreds));
    TktBridgeCreds->RefCount = 1;

    return TktBridgeCreds;
}

PTKTBRIDGEAP_CREDS
ReferenceTktBridgeCreds(_Inout_ PTKTBRIDGEAP_CREDS Creds)
{
    if (Creds != nullptr &&
        Creds->RefCount != LONG_MAX)
        InterlockedIncrement(&Creds->RefCount);

    return Creds;
}

VOID
DereferenceTktBridgeCreds(_Inout_ PTKTBRIDGEAP_CREDS Creds)
{
    if (Creds == nullptr)
        return;

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
    WIL_FreeMemory(Creds);
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
