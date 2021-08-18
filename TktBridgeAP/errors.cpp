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

NTSTATUS
KrbErrorToNtStatus(_In_ krb5_error_code KrbError)
{
    switch (KrbError) {
    case 0:
        return STATUS_SUCCESS;
    case KRB5KRB_AP_ERR_BAD_INTEGRITY:
        return STATUS_WRONG_PASSWORD;
    case ENOMEM:
        return STATUS_NO_MEMORY;
    default:
    case EINVAL:
        return STATUS_INVALID_PARAMETER;
    }
}