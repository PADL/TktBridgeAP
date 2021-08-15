/*++

Copyright (c) PADL Software Pty Ltd, All rights reserved.

Module Name:

    sspipreauth.cpp

Abstract:

    SSPI to Heimdal glue

Environment:

    Local Security Authority (LSA)

--*/

#include "TktBridgeAP.h"

NTSTATUS
HeimErrToNtStatus(krb5_error_code KrbError)
{
	switch (KrbError) {
	case 0:
		return STATUS_SUCCESS;
	case ENOMEM:
		return STATUS_NO_MEMORY;
	default:
	case EINVAL:
		return STATUS_INVALID_PARAMETER;
	}
}
