#include "TktBridgeAP.h"

NTSTATUS
AcquireCachedPreauthCredentials(_In_ SECURITY_LOGON_TYPE LogonType,
                                _In_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity,
                                _Out_ PPREAUTH_INIT_CREDS *PreauthCreds)
{
    RETURN_NTSTATUS(STATUS_NO_SUCH_LOGON_SESSION);
}

NTSTATUS
CachePreauthCredentials(_In_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity,
                        _In_ PPREAUTH_INIT_CREDS PreauthCreds)
{
    RETURN_NTSTATUS(STATUS_SUCCESS);
}
