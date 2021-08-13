#include "TktBridgeAP.h"

NTSTATUS
HeimdalErrToNtStatus(krb5_error_code KrbError)
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