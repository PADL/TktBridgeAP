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
 * the user can disable this globally by setting the DISABLE_CRED_CACHE
 * flag in the registry.
 */

#include <map>
#include <mutex>
#include <iterator>

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

    static std::map<const LUID, wil::unique_sec_winnt_auth_identity, decltype(CompareLuid)> CredCache;
    static std::mutex CredCacheLock;

}

_Success_(return == STATUS_SUCCESS) NTSTATUS
FindCredForLogonSession(_In_ LUID &LogonID,
                        _Inout_ wil::unique_sec_winnt_auth_identity &AuthIdentity)
{
    SECURITY_STATUS SecStatus;

    TktBridgeAP::CredCacheLock.lock();

    auto CacheEntry = TktBridgeAP::CredCache.find(LogonID);
    if (CacheEntry != TktBridgeAP::CredCache.end())
        SecStatus = SspiCopyAuthIdentity(CacheEntry->second.get(), &AuthIdentity);
    else
        SecStatus = STATUS_NO_SUCH_LOGON_SESSION;

    TktBridgeAP::CredCacheLock.unlock();

    RETURN_IF_NTSTATUS_FAILED(SecStatus);

    SecStatus = SspiDecryptAuthIdentity(AuthIdentity.get());
    RETURN_IF_NTSTATUS_FAILED(SecStatus);

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

_Success_(return == STATUS_SUCCESS) NTSTATUS
SaveCredForLogonSession(_In_ PLUID LogonID,
                        _In_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity)
{
    wil::unique_sec_winnt_auth_identity EncryptedAuthIdentity;
    SECURITY_STATUS SecStatus;

    if (LogonID == nullptr)
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);

    SecStatus = SspiCopyAuthIdentity(AuthIdentity, &EncryptedAuthIdentity);
    RETURN_IF_NTSTATUS_FAILED(SecStatus);

    SecStatus = SspiEncryptAuthIdentity(EncryptedAuthIdentity.get());
    RETURN_IF_NTSTATUS_FAILED(SecStatus);

    TktBridgeAP::CredCacheLock.lock();
    TktBridgeAP::CredCache.erase(*LogonID);
    TktBridgeAP::CredCache.emplace(*LogonID, std::move(EncryptedAuthIdentity));
    TktBridgeAP::CredCacheLock.unlock();

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

_Success_(return == STATUS_SUCCESS) NTSTATUS
RemoveCredForLogonSession(_In_ PLUID LogonID)
{
    if (LogonID == nullptr)
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);

    TktBridgeAP::CredCacheLock.lock();
    auto Count = TktBridgeAP::CredCache.erase(*LogonID);
    TktBridgeAP::CredCacheLock.unlock();

    return Count == 0 ? STATUS_NO_SUCH_LOGON_SESSION : STATUS_SUCCESS;
}

VOID
DebugLogonCreds(VOID)
{
    TktBridgeAP::CredCacheLock.lock();

    for (auto Iterator = TktBridgeAP::CredCache.begin();
         Iterator != TktBridgeAP::CredCache.end();
         Iterator++) {
        PCWSTR UserName = nullptr;
        PCWSTR DomainName = nullptr;

        if (SspiEncodeAuthIdentityAsStrings(Iterator->second.get(),
                                            &UserName,
                                            &DomainName,
                                            nullptr) != SEC_E_OK)
            continue;

        DebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"Credential cache entry: LUID %08x.%08x UserName %s DomainName %s",
                   Iterator->first.LowPart,
                   Iterator->first.HighPart,
                   UserName,
                   DomainName);

        SspiLocalFree((PVOID)UserName);
        SspiLocalFree((PVOID)DomainName);
    }

    TktBridgeAP::CredCacheLock.unlock();
}

