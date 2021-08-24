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

//
// Looks in the credentials cache for a credential that matches the supplied
// auth identity, returned TktBridgeCreds with +1 reference count.
//
// Note TGT key is protected using LsaProtectMemory(), will be unprotected
// by callback
//

NTSTATUS
LocateCachedPreauthCredentials(_In_ SECURITY_LOGON_TYPE LogonType,
                               _In_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity,
                               _In_opt_ PLUID pvLogonID,
                               _Out_ PTKTBRIDGEAP_CREDS *TktBridgeCreds,
                               _Out_ PNTSTATUS SubStatus)
{
    //
    // Unpack auth identity into username, domain name and password
    //

    //
    // Look for username and password match, if found check expiry
    //
 
    //
    // Attempt to decrypt AS-REP with key
    //

    //
    // If we have a match, return a +1 of cache entry
    //

    RETURN_NTSTATUS(STATUS_NO_SUCH_LOGON_SESSION);
}

//
// Take the supplied credentials and AS-REP, decrypt the AS-REP enc-part,
// and re-encrypt them with a PBKDF2 derived key from the auth identity.
// Only works for password-based credentials.
//
// The cached credentials can be used interchangeably with preauth
// credentials
//

NTSTATUS
CacheAddPreauthCredentials(_In_ SECURITY_LOGON_TYPE LogonType,
                           _In_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity,
                           _In_opt_ PLUID pvLogonID,
                           _In_ PCTKTBRIDGEAP_CREDS TktBridgeCreds)
{
    //
    // Unpack auth identity into username, domain name and password
    //
    
    //
    // Make PBKDF2 of password
    //

    //
    // Decrypt and re-encrypt AS-REP with
    // KRB-FX-CF2(ReplyKey, PBKDF2(Password), "replykey", "primarycredentials")
    //

    //
    // Make a new entry
    //

    //
    // Add to head of cache list
    //

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

NTSTATUS
CacheRemovePreauthCredentials(_In_ SECURITY_LOGON_TYPE LogonType,
                              _In_opt_ PLUID pvLogonID,
                              _In_ PCTKTBRIDGEAP_CREDS TktBridgeCreds)
{
    RETURN_NTSTATUS(STATUS_SUCCESS);
}

VOID
ReferencePreauthInitCreds(_Inout_ PTKTBRIDGEAP_CREDS Creds)
{
    if (Creds == nullptr)
        return;

    if (Creds->RefCount == LONG_MAX)
        return;

    InterlockedIncrement(&Creds->RefCount);
}

VOID
DereferencePreauthInitCreds(_Inout_ PTKTBRIDGEAP_CREDS Creds)
{
    if (Creds == nullptr)
        return;

    if (Creds->RefCount == LONG_MAX)
        return;

    auto Old = InterlockedDecrement(&Creds->RefCount) + 1;
    if (Old > 1)
        return;

    assert(Old == 1);

    WIL_FreeMemory(Creds->InitiatorName);
    krb5_data_free(&Creds->AsRep);

    if (Creds->AsReplyKey.keyvalue.data != nullptr) {
        SecureZeroMemory(Creds->AsReplyKey.keyvalue.data, Creds->AsReplyKey.keyvalue.length);
        krb5_free_keyblock_contents(nullptr, &Creds->AsReplyKey);
    }

    SspiLocalFree((PVOID)Creds->DomainName);
    SspiLocalFree((PVOID)Creds->UserName);

    ZeroMemory(Creds, sizeof(*Creds));
    WIL_FreeMemory(Creds);
}

bool
IsPreauthCredsExpired(_In_ PTKTBRIDGEAP_CREDS Creds)
{
    FILETIME ftNow;
    LARGE_INTEGER liNow;

    GetSystemTimeAsFileTime(&ftNow);

    liNow.LowPart = ftNow.dwLowDateTime;
    liNow.HighPart = ftNow.dwHighDateTime;

    return Creds->ExpiryTime.QuadPart < liNow.QuadPart;
}
