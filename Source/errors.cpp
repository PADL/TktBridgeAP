/*
 * Copyright (c) 2021, PADL Software Pty Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted (subject to the limitations in the
 * disclaimer below) provided that the following conditions are met:
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
 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED
 * BY THIS LICENSE.  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "TktBridgeAP.h"

krb5_error_code
SspiStatusToKrbError(_In_ SECURITY_STATUS SecStatus)
{
    krb5_error_code KrbError;

    switch (SecStatus) {
    case SEC_E_OK:
        KrbError = 0;
        break;
    case SEC_I_CONTINUE_NEEDED:
        KrbError = HEIM_ERR_PA_CONTINUE_NEEDED;
        break;
    case SEC_E_LOGON_DENIED:
        KrbError = KRB5KRB_AP_ERR_BAD_INTEGRITY;
        break;
    case SEC_E_WRONG_PRINCIPAL:
        KrbError = KRB5_PRINC_NOMATCH;
        break;
    case SEC_E_NO_CREDENTIALS:
        KrbError = KRB5_CC_NOTFOUND;
        break;
    case SEC_E_CONTEXT_EXPIRED:
        KrbError = KRB5KRB_AP_ERR_TKT_EXPIRED;
        break;
    case SEC_E_NO_KERB_KEY:
        KrbError = KRB5KRB_AP_ERR_NOKEY;
        break;
    case SEC_E_INVALID_PARAMETER:
        KrbError = EINVAL;
        break;
    case SEC_E_INSUFFICIENT_MEMORY:
        KrbError = ENOMEM;
        break;
    default:
        KrbError = KRB5KDC_ERR_PREAUTH_FAILED;
        break;
    }

    return KrbError;
}

NTSTATUS
KrbErrorToNtStatus(_In_ krb5_error_code KrbError,
                   _Out_ PNTSTATUS SubStatus)
{
    NTSTATUS Status;

    *SubStatus = STATUS_SUCCESS;

    switch (KrbError) {
    case 0:
        Status = STATUS_SUCCESS;
        break;
    case KRB5_PREAUTH_BAD_TYPE:
    case HEIM_ERR_NO_MORE_PA_MECHS:
        Status = STATUS_UNSUPPORTED_PREAUTH;
        break;
    case KRB5_PREAUTH_NO_KEY:
        Status = STATUS_NO_USER_SESSION_KEY;
        break;
    case KRB5KDC_ERR_SVC_UNAVAILABLE:
    case KRB5_KDC_UNREACH:
        Status = STATUS_NO_LOGON_SERVERS;
        break;
    case KRB5KDC_ERR_KEY_EXPIRED:
        *SubStatus = STATUS_PASSWORD_EXPIRED;
        Status = STATUS_ACCOUNT_RESTRICTION;
        break;
    case KRB5_PRINC_NOMATCH:
    case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
        Status = STATUS_NO_SUCH_USER;
        break;
    case KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE:
        Status = STATUS_DS_NAME_NOT_UNIQUE;
        break;
    case KRB5KDC_ERR_CLIENT_NOTYET:
        *SubStatus = STATUS_INVALID_LOGON_HOURS;
        Status = STATUS_ACCOUNT_RESTRICTION;
        break;
    case KRB5KDC_ERR_CLIENT_REVOKED:
        *SubStatus = STATUS_ACCOUNT_LOCKED_OUT;
        Status = STATUS_ACCOUNT_RESTRICTION;
        break;
    case KRB5_PREAUTH_FAILED:
    case KRB5KDC_ERR_PREAUTH_FAILED:
    case KRB5KRB_AP_ERR_BAD_INTEGRITY:
        Status = STATUS_WRONG_PASSWORD;
        break;
    case KRB5KRB_AP_ERR_SKEW:
        Status = SEC_E_TIME_SKEW;
        break;
    case KRB5KDC_ERR_BADOPTION:
        Status = STATUS_KDC_INVALID_REQUEST;
        break;
    case KRB5KDC_ERR_ETYPE_NOSUPP:
        Status = STATUS_KDC_UNKNOWN_ETYPE;
        break;
    case KRB5_KDC_ERR_REVOKED_CERTIFICATE:
        Status = STATUS_KDC_CERT_REVOKED;
        break;
    case KRB5_KDC_ERR_CANT_VERIFY_CERTIFICATE:
        Status = STATUS_ISSUING_CA_UNTRUSTED_KDC;
        break;
    case ENOMEM:
        Status = STATUS_NO_MEMORY;
        break;
    case EINVAL:
        Status = STATUS_INVALID_PARAMETER;
        break;
    case KRB5KDC_ERR_POLICY:
    case KRB5KDC_ERR_PATH_NOT_ACCEPTED:
    case KRB5_KDC_ERR_CLIENT_NOT_TRUSTED:
    default:
        Status = STATUS_LOGON_FAILURE;
        break;
    }

    return Status;
}
