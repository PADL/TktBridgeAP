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

struct krb5_gss_init_ctx_data;
typedef struct krb5_gss_init_ctx_data *krb5_gss_init_ctx;

struct gss_ctx_id_t_desc_struct;
typedef struct gss_ctx_id_t_desc_struct *gss_ctx_id_t;

struct gss_cred_id_t_desc_struct;
typedef struct gss_cred_id_t_desc_struct *gss_cred_id_t;

struct gss_OID_desc_struct;
typedef gss_OID_desc_struct *gss_OID;

typedef krb5_error_code(KRB5_LIB_CALL* krb5_gssic_step)(
    krb5_context,
    krb5_gss_init_ctx,
    const krb5_creds*,
    struct gss_ctx_id_t_desc_struct**,
    KDCOptions options,
    krb5_data*,
    krb5_data*,
    krb5_data*);

typedef krb5_error_code(KRB5_LIB_CALL* krb5_gssic_finish)(
    krb5_context,
    krb5_gss_init_ctx,
    const krb5_creds*,
    struct gss_ctx_id_t_desc_struct*,
    krb5int32,
    krb5_enctype,
    krb5_principal*,
    krb5_keyblock**);

typedef void (KRB5_LIB_CALL* krb5_gssic_release_cred)(
    krb5_context,
    krb5_gss_init_ctx,
    struct gss_cred_id_t_desc_struct*);

typedef void (KRB5_LIB_CALL* krb5_gssic_delete_sec_context)(
    krb5_context,
    krb5_gss_init_ctx,
    struct gss_ctx_id_t_desc_struct*);

#define KRB5_GSS_IC_FLAG_RELEASE_CRED 1

NTSTATUS
KrbErrorToNtStatus(krb5_error_code KrbError)
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

krb5_error_code
SspiStatusToKrbError(SECURITY_STATUS SecStatus)
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
    case SEC_E_INVALID_PARAMETER:
	return EINVAL;
    default:
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }
}

static krb5_error_code
PseudoRandomFunction(krb5_context KrbContext,
    PCtxtHandle hContext,
    const PBYTE pbPrfInput,
    ULONG pulPrfInputLength,
    ULONG ulDesiredOutputLength,
    PBYTE pbPrfOutput,
    PULONG *pulPrfOutputLength)
{
    // get session key
    // allocate desired output length
    // krb5_crypto_prf( iterator || input ) while (dol>0) where tsize = min(dol, output.length);
    // return

    return EINVAL;
}

static krb5_error_code KRB5_LIB_CALL
SspiPreauthStep(
    krb5_context KrbContext,
    krb5_gss_init_ctx GssICContext,
    const krb5_creds *KrbCred,
    gss_ctx_id_t *ContextHandle,
    KDCOptions KrbReqFlags,
    krb5_data *EncAsReq,
    krb5_data *InputToken,
    krb5_data *OutputToken)
{
    // check flags.request_anonymous
    // assert Cred Handle with _krb5_init_creds_get_gss_cred
    // make TGS name and turn into LPWSTR
    // setup cb.application_data and input token
    // call ISC
    // setup Output Token
    // if complete check mutual flag, other flags
    // map error
    return EINVAL;
}

static krb5_error_code KRB5_LIB_CALL
SspiPreauthFinish(
    krb5_context KrbContext,
    krb5_gss_init_ctx GssICContext,
    const krb5_creds *KrbCred,
    gss_ctx_id_t ContextHandle,
    krb5int32 Nonce,
    krb5_enctype KrbEncType,
    krb5_principal *pClientPrincipal,
    krb5_keyblock **pKrbReplyKey)
{
    // get initiator name
    // derive reply key
    return EINVAL;
}

static void KRB5_LIB_CALL
SspiPreauthDeleteSecContext(
    krb5_context KrbContext,
    krb5_gss_init_ctx GssICContext,
    gss_ctx_id_t ContextHandle)
{
    DeleteSecurityContext((PCtxtHandle)ContextHandle);
}

static void KRB5_LIB_CALL
SspiPreauthReleaseCred(
    krb5_context KrbContext,
    krb5_gss_init_ctx GssICContext,
    gss_cred_id_t CredHandle)
{
    FreeCredentialsHandle((PCredHandle)CredHandle);
}

