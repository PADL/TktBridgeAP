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

#pragma once

#include <sspi.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <krb5.h>

/*
 * Private APIs that are not exported from the Heimdal SDK and which
 * are used to implement the GSS-API pre-authentication callbacks
 * consumed by libkrb5.
 *
 * Because TktBridgeAP does not use or link against Heimdal's
 * GSS-API, we are free to define the GSS-API structures as we wish.
 */

struct krb5_gss_init_ctx_data;
typedef struct krb5_gss_init_ctx_data *krb5_gss_init_ctx;

struct gss_ctx_id_t_desc_struct {
    CtxtHandle Handle;
};

typedef struct gss_ctx_id_t_desc_struct *gss_ctx_id_t;

struct gss_cred_id_t_desc_struct {
    CredHandle Handle;
    SECURITY_STATUS LastStatus;
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
_krb5_init_creds_get_gss_cred(krb5_context /*context*/,
                              krb5_gss_init_ctx /*gssic*/);

KRB5_LIB_FUNCTION const struct gss_OID_desc_struct *KRB5_LIB_CALL
_krb5_init_creds_get_gss_mechanism(krb5_context /*context*/,
                                   krb5_gss_init_ctx /*gssic*/);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_init_creds_init_gss(krb5_context /*context*/,
                          krb5_init_creds_context /*ctx*/,
                          krb5_gssic_step /*step*/,
                          krb5_gssic_finish /*finish*/,
                          krb5_gssic_release_cred /*release_cred*/,
                          krb5_gssic_delete_sec_context /*delete_sec_context*/,
                          const struct gss_cred_id_t_desc_struct */*gss_cred*/,
                          const struct gss_OID_desc_struct */*gss_mech*/,
                          unsigned int /*flags*/);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
_krb5_init_creds_set_gss_cred(krb5_context /*context*/,
                              krb5_gss_init_ctx /*gssic*/,
                              struct gss_cred_id_t_desc_struct */*gss_cred*/);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
_krb5_init_creds_set_gss_mechanism(krb5_context /*context*/,
                                   krb5_gss_init_ctx /*gssic*/,
                                   const struct gss_OID_desc_struct */*gss_mech*/);

KRB5_LIB_FUNCTION krb5_principal KRB5_LIB_CALL
_krb5_init_creds_get_cred_client(krb5_context /*context*/,
                                 krb5_init_creds_context /*ctx*/);    

KRB5_LIB_FUNCTION krb5_timestamp KRB5_LIB_CALL
_krb5_init_creds_get_cred_endtime(krb5_context /*context*/,
                                  krb5_init_creds_context /*ctx*/);


#ifdef __cplusplus
}
#endif
