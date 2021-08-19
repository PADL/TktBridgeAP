/*++

Copyright (c) PADL Software Pty Ltd, All rights reserved.

Module Name:

    errors.cpp

Abstract:

    Convert between error codes.

Environment:

    Local Security Authority (LSA)

--*/

#include "TktBridgeAP.h"

NTSTATUS
KrbErrorToNtStatus(_In_ krb5_error_code KrbError,
                   _Out_ PNTSTATUS SubStatus)
{
    *SubStatus = STATUS_SUCCESS;

    switch (KrbError) {
    case 0:
        return STATUS_SUCCESS;
    case KRB5_PREAUTH_BAD_TYPE:
        return STATUS_UNSUPPORTED_PREAUTH;
    case KRB5_PREAUTH_NO_KEY:
        return STATUS_NO_USER_SESSION_KEY;
    case KRB5KDC_ERR_SVC_UNAVAILABLE:
    case KRB5_KDC_UNREACH:
        return STATUS_NO_LOGON_SERVERS;
    case KRB5KDC_ERR_KEY_EXPIRED:
        *SubStatus = STATUS_PASSWORD_EXPIRED;
        return STATUS_ACCOUNT_RESTRICTION;
    case KRB5_PRINC_NOMATCH:
    case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
        return STATUS_NO_SUCH_USER;
    case KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE:
        return STATUS_DS_NAME_NOT_UNIQUE;
    case KRB5KDC_ERR_CLIENT_NOTYET:
        *SubStatus = STATUS_INVALID_LOGON_HOURS;
        return STATUS_ACCOUNT_RESTRICTION;
    case KRB5KDC_ERR_CLIENT_REVOKED:
        *SubStatus = STATUS_ACCOUNT_LOCKED_OUT;
        return STATUS_ACCOUNT_RESTRICTION;
    case KRB5KDC_ERR_POLICY:
    case KRB5KDC_ERR_BADOPTION:
    case KRB5KDC_ERR_ETYPE_NOSUPP:
    case KRB5KDC_ERR_PATH_NOT_ACCEPTED:
    case KRB5_KDC_ERR_CLIENT_NOT_TRUSTED:
        return STATUS_LOGON_FAILURE;
    case KRB5KDC_ERR_PREAUTH_FAILED:
    case KRB5KRB_AP_ERR_BAD_INTEGRITY:
        return STATUS_WRONG_PASSWORD;
    case ENOMEM:
        return STATUS_NO_MEMORY;
    default:
    case EINVAL:
        return STATUS_INVALID_PARAMETER;
    }
}