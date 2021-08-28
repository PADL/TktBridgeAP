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

krb5_error_code
SspiStatusToKrbError(_In_ SECURITY_STATUS SecStatus)
{
    switch (SecStatus) {
    case SEC_E_OK:
        return 0;
    case SEC_I_CONTINUE_NEEDED:
        return HEIM_ERR_PA_CONTINUE_NEEDED;
    case SEC_E_LOGON_DENIED:
        return KRB5KRB_AP_ERR_BAD_INTEGRITY;
    case SEC_E_WRONG_PRINCIPAL:
        return KRB5_PRINC_NOMATCH;
    case SEC_E_NO_CREDENTIALS:
        return KRB5_CC_NOTFOUND;
    case SEC_E_CONTEXT_EXPIRED:
        return KRB5KRB_AP_ERR_TKT_EXPIRED;
    case SEC_E_NO_KERB_KEY:
        return KRB5KRB_AP_ERR_NOKEY;
    case SEC_E_INVALID_PARAMETER:
        return EINVAL;
    default:
        return KRB5KDC_ERR_PREAUTH_FAILED;
    }
}

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
