/*++

Copyright (c) PADL Software Pty Ltd, All rights reserved.

Module Name:

    credcache.cpp

Abstract:

    Convert preauth creds into PBKDF2 creds

Environment:

    Local Security Authority (LSA)

--*/

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
    // Make PBKDF2 of password and compare protected version with TGT key
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
CacheAddPreauthCredentials(_In_ PUNICODE_STRING AccountName,
                            _In_ PUNICODE_STRING AuthenticatingAuthority,
                            _In_ PSECPKG_PRIMARY_CRED PrimaryCredentials,
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
    // Decrypt and re-encrypt AS-REP with PBKDF2
    //

    //
    // Make a new entry with PBKDF2 key and re-encrypted AS-REP, storing
    // username and domainname alongside
    //

    //
    // Add to head of cache list
    //

    RETURN_NTSTATUS(STATUS_SUCCESS);
}

NTSTATUS
CacheRemovePreauthCredentials(_In_ PUNICODE_STRING AccountName,
                              _In_ PUNICODE_STRING AuthenticatingAuthority,
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
DereferencePreauthInitCreds(_In_ PTKTBRIDGEAP_CREDS Creds)
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
    SecureZeroMemory(Creds->AsReplyKey.keyvalue.data, Creds->AsReplyKey.keyvalue.length);
    krb5_free_keyblock_contents(nullptr, &Creds->AsReplyKey);

    WIL_FreeMemory(Creds->DomainName);
    WIL_FreeMemory(Creds->UserName);

    ZeroMemory(Creds, sizeof(*Creds));
    WIL_FreeMemory(Creds);
}