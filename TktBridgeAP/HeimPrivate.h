#pragma once

#include <sspi.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <krb5.h>

struct krb5_gss_init_ctx_data;
typedef struct krb5_gss_init_ctx_data *krb5_gss_init_ctx;

struct gss_ctx_id_t_desc_struct {
    CtxtHandle Handle;
};

typedef struct gss_ctx_id_t_desc_struct *gss_ctx_id_t;

struct gss_cred_id_t_desc_struct {
    CredHandle Handle;
};

typedef struct gss_cred_id_t_desc_struct *gss_cred_id_t;

struct gss_OID_desc_struct {
    PCWSTR Package;
};

typedef gss_OID_desc_struct *gss_OID;

typedef krb5_error_code(KRB5_LIB_CALL *krb5_gssic_step)(
    krb5_context,
    krb5_gss_init_ctx,
    const krb5_creds *,
    struct gss_ctx_id_t_desc_struct **,
    KDCOptions options,
    krb5_data *,
    krb5_data *,
    krb5_data *);

typedef krb5_error_code(KRB5_LIB_CALL *krb5_gssic_finish)(
    krb5_context,
    krb5_gss_init_ctx,
    const krb5_creds *,
    struct gss_ctx_id_t_desc_struct *,
    krb5int32,
    krb5_enctype,
    krb5_principal *,
    krb5_keyblock **);

typedef void (KRB5_LIB_CALL *krb5_gssic_release_cred)(
    krb5_context,
    krb5_gss_init_ctx,
    struct gss_cred_id_t_desc_struct *);

typedef void (KRB5_LIB_CALL *krb5_gssic_delete_sec_context)(
    krb5_context,
    krb5_gss_init_ctx,
    struct gss_ctx_id_t_desc_struct *);

#define KRB5_GSS_IC_FLAG_RELEASE_CRED 1


KRB5_LIB_FUNCTION const struct gss_cred_id_t_desc_struct *KRB5_LIB_CALL
    _krb5_init_creds_get_gss_cred(
        krb5_context /*context*/,
        krb5_gss_init_ctx /*gssic*/);

KRB5_LIB_FUNCTION const struct gss_OID_desc_struct *KRB5_LIB_CALL
    _krb5_init_creds_get_gss_mechanism(
        krb5_context /*context*/,
        krb5_gss_init_ctx /*gssic*/);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
    _krb5_init_creds_init_gss(
        krb5_context /*context*/,
        krb5_init_creds_context /*ctx*/,
        krb5_gssic_step /*step*/,
        krb5_gssic_finish /*finish*/,
        krb5_gssic_release_cred /*release_cred*/,
        krb5_gssic_delete_sec_context /*delete_sec_context*/,
        const struct gss_cred_id_t_desc_struct */*gss_cred*/,
        const struct gss_OID_desc_struct */*gss_mech*/,
        unsigned int /*flags*/);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
    _krb5_init_creds_set_gss_cred(
        krb5_context /*context*/,
        krb5_gss_init_ctx /*gssic*/,
        struct gss_cred_id_t_desc_struct */*gss_cred*/);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
    _krb5_init_creds_set_gss_mechanism(
        krb5_context /*context*/,
        krb5_gss_init_ctx /*gssic*/,
        const struct gss_OID_desc_struct */*gss_mech*/);

KRB5_LIB_FUNCTION krb5_principal KRB5_LIB_CALL
_krb5_init_creds_get_cred_client(krb5_context context, krb5_init_creds_context ctx);

#ifdef __cplusplus
}
#endif
