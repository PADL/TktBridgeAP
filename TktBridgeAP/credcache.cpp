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
// auth identity, returned PreauthCreds with +1 reference count.
//

NTSTATUS
AcquireCachedPreauthCredentials(_In_ SECURITY_LOGON_TYPE LogonType,
                                _In_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity,
                                _In_opt_ PLUID pvLogonID,
                                _Out_ PPREAUTH_INIT_CREDS *PreauthCreds)
{
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
CachePreauthCredentials(_In_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity,
                        _In_opt_ PLUID pvLogonID,
                        _In_ PPREAUTH_INIT_CREDS PreauthCreds)
{
    RETURN_NTSTATUS(STATUS_SUCCESS);
}
