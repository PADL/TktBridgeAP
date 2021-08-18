/*++

Copyright (c) PADL Software Pty Ltd, All rights reserved.

Module Name:

    sspipreauth.cpp

Abstract:

    SSPI to Heimdal pre-authentication glue

Environment:

    Local Security Authority (LSA)

--*/

#include "TktBridgeAP.h"
#include "HeimPrivate.h"

#define RETURN_IF_KRB_FAILED(KrbError) do {                             \
    krb5_error_code _krbError = KrbError;                               \
    if (_krbError != 0) {                                               \
        return _krbError;                                               \
    }                                                                   \
} while (0)

#define RETURN_IF_KRB_FAILED_MSG(KrbError, Msg) do {                    \
    krb5_error_code _krbError = KrbError;                               \
    if (_krbError != 0) {                                               \
        auto szError = krb5_get_error_message(KrbContext, _krbError);   \
        DebugTrace(WINEVENT_LEVEL_ERROR, L"%s: %S (%d)",                \
                   Msg, szError, _krbError);                            \
        krb5_free_error_message(KrbContext, szError);                   \
        return _krbError;                                               \
    }                                                                   \
} while (0)

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

static krb5_error_code
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

static _Success_(return == 0) krb5_error_code
RFC4401PRF(_In_ krb5_context KrbContext,
           _In_ PCtxtHandle phContext,
           _In_ krb5_enctype EncryptionType,
           _In_reads_bytes_(cbPrfInput) const PBYTE pbPrfInput,
           _In_ ULONG cbPrfInput,
           _Outptr_result_bytebuffer_(*pcbPrfOutput) PBYTE *pbPrfOutput,
           _Out_ size_t *pcbPrfOutput)
{
    krb5_error_code KrbError;
    SIZE_T cbDesiredOutput;
    SECURITY_STATUS SecStatus;
    SecPkgContext_SessionKey SessionKey = {
        .SessionKeyLength = 0,
        .SessionKey = nullptr
    };
    krb5_data Input;
    krb5_crypto KrbCrypto = nullptr;
    size_t KeySize;

    krb5_data_zero(&Input);

    *pbPrfOutput = nullptr;
    *pcbPrfOutput = 0;

    auto cleanup = wil::scope_exit([&]() {
        if (SessionKey.SessionKey != nullptr) {
            SecureZeroMemory(SessionKey.SessionKey, SessionKey.SessionKeyLength);
            FreeContextBuffer(SessionKey.SessionKey);
        }
        if (KrbError != 0 && *pbPrfOutput != nullptr) {
            SecureZeroMemory(*pbPrfOutput, *pcbPrfOutput);
            WIL_FreeMemory(*pbPrfOutput);
            *pbPrfOutput = nullptr;
        }
        if (Input.data) {
            WIL_FreeMemory(Input.data);
        }
        if (KrbCrypto != nullptr) {
            krb5_crypto_destroy(KrbContext, KrbCrypto);
        }
    });

    SecStatus = QueryContextAttributes(phContext, SECPKG_ATTR_SESSION_KEY, &SessionKey);
    if (SecStatus != SEC_E_OK) {
        KrbError = SspiStatusToKrbError(SecStatus);
        return KrbError;
    }

    DebugSessionKey(L"PRF input", pbPrfInput, cbPrfInput);
    DebugSessionKey(L"SSPI session key", SessionKey.SessionKey, SessionKey.SessionKeyLength);

    //
    // Unfortunately SSPI doesn't tell use the encryption type the package
    // used, and indeed it may not even use RFC3961 encryption types. So
    // we need to take an educated guess. This will break for mechanisms
    // that don't use these encryption types, but it will work for EAP.
    //
    krb5_keyblock key;

    key.keyvalue.data = SessionKey.SessionKey;
    if (SessionKey.SessionKeyLength >= 32) {
        key.keytype = KRB5_ENCTYPE_AES256_CTS_HMAC_SHA1_96;
        key.keyvalue.length = 32;
    } else if (SessionKey.SessionKeyLength >= 16) {
        key.keytype = KRB5_ENCTYPE_AES128_CTS_HMAC_SHA1_96;
        key.keyvalue.length = 16;
    } else {
        KrbError = KRB5_BAD_KEYSIZE;
        RETURN_IF_KRB_FAILED_MSG(KrbError, "Could not map session key type");
    }

    KrbError = krb5_crypto_init(KrbContext, &key, KRB5_ENCTYPE_NULL, &KrbCrypto);
    RETURN_IF_KRB_FAILED(KrbError);

    KrbError = krb5_enctype_keysize(KrbContext, EncryptionType, &KeySize);
    RETURN_IF_KRB_FAILED(KrbError);

    *pbPrfOutput = (PBYTE)WIL_AllocateMemory(KeySize);
    if (*pbPrfOutput == nullptr) {
        KrbError = krb5_enomem(KrbContext);
        return KrbError;
    }

    *pcbPrfOutput = KeySize;

    Input.length = (SIZE_T)cbPrfInput + 4;
    Input.data = WIL_AllocateMemory((SIZE_T)cbPrfInput + 4);
    if (Input.data == nullptr) {
        KrbError = krb5_enomem(KrbContext);
        return KrbError;
    }

    memcpy(&((PBYTE)Input.data)[4], pbPrfInput, cbPrfInput);

    ULONG iPrf = 0;
    PBYTE pbPrf = (PBYTE)*pbPrfOutput;

    cbDesiredOutput = *pcbPrfOutput;

    while (cbDesiredOutput > 0) {
        SIZE_T cbPrf;
        krb5_data Output;

        krb5_data_zero(&Output);

        ((PBYTE)Input.data)[0] = (iPrf >> 24) & 0xFF;
        ((PBYTE)Input.data)[1] = (iPrf >> 16) & 0xFF;
        ((PBYTE)Input.data)[2] = (iPrf >>  8) & 0xFF;
        ((PBYTE)Input.data)[3] = (iPrf      ) & 0xFF;

        KrbError = krb5_crypto_prf(KrbContext, KrbCrypto, &Input, &Output);
        RETURN_IF_KRB_FAILED(KrbError);

        cbPrf = min(cbDesiredOutput, Output.length);
        memcpy(pbPrf, Output.data, cbPrf);
        pbPrf += cbPrf;
        cbDesiredOutput -= cbPrf;

        SecureZeroMemory(Output.data, Output.length);
        krb5_data_free(&Output);

        iPrf++;
    }

    DebugSessionKey(L"PRF output", *pbPrfOutput, *pcbPrfOutput);

    return 0;
}

static krb5_error_code
SspiPreauthDeriveKey(_In_ krb5_context KrbContext,
                     _In_ PCtxtHandle phContext,
                     _In_ LONG AsReqNonce,
                     _In_ krb5_enctype EncryptionType,
                     _Out_ krb5_keyblock **ppKeyblock)
{
    krb5_error_code KrbError;
    krb5_keyblock keyblock;
    BYTE SaltData[12] = "KRB-GSS";

    ZeroMemory(&keyblock, sizeof(keyblock));

    *ppKeyblock = nullptr;

    *((PLONG)&SaltData[8]) = AsReqNonce;
 
    keyblock.keytype = EncryptionType;

    KrbError = RFC4401PRF(KrbContext, phContext, EncryptionType,
                          SaltData, sizeof(SaltData),
                          (PBYTE *)&keyblock.keyvalue.data, &keyblock.keyvalue.length);
    if (KrbError == 0) {
        KrbError = krb5_copy_keyblock(KrbContext, &keyblock, ppKeyblock);
    }

    if (keyblock.keyvalue.data != nullptr) {
        SecureZeroMemory(keyblock.keyvalue.data, keyblock.keyvalue.length);
        WIL_FreeMemory(keyblock.keyvalue.data);
    }

    return KrbError;
}

static krb5_error_code
SspiPreauthUnparseName(_In_ krb5_context KrbContext,
                       _In_ krb5_const_principal Principal,
                       _Out_ PWSTR *pwszNameString)
{
    krb5_error_code KrbError;
    PCHAR szNameString;

    *pwszNameString = nullptr;

    if (Principal->name.name_type == KRB5_NT_ENTERPRISE_PRINCIPAL) {
        if (Principal->name.name_string.len != 1)
            return EINVAL;

        szNameString = Principal->name.name_string.val[0];
    } else {
        KrbError = krb5_unparse_name(KrbContext, Principal, &szNameString);
        RETURN_IF_KRB_FAILED(KrbError);
    }

    if (!NT_SUCCESS(UTF8ToUnicodeAlloc(szNameString, pwszNameString))) {
        KrbError = krb5_enomem(KrbContext);
    } else {
        KrbError = 0;
    }

    if (szNameString != Principal->name.name_string.val[0]) {
        krb5_xfree(szNameString);
    }

    return KrbError;
}

static krb5_error_code
SspiPreauthParseName(_In_ krb5_context KrbContext,
                     _In_z_ PCWSTR NameString,
                     _Out_ krb5_principal *pPrincipal)
{
    krb5_error_code KrbError;
    PCHAR szNameString;

    *pPrincipal = nullptr;

    if (!NT_SUCCESS(UnicodeToUTF8Alloc(NameString, &szNameString))) {
        return krb5_enomem(KrbContext);
    }

    KrbError = krb5_parse_name_flags(KrbContext, szNameString, 0, pPrincipal);

    WIL_FreeMemory(szNameString);

    return KrbError;
}

static krb5_error_code
MakeChannelBindings(_In_ krb5_context KrbContext,
                    _In_ krb5_data *EncAsReq,
                    _Out_ PSEC_CHANNEL_BINDINGS *pChannelBindings)
{
    PSEC_CHANNEL_BINDINGS ChannelBindings;

    *pChannelBindings = nullptr;

    ChannelBindings = (PSEC_CHANNEL_BINDINGS)WIL_AllocateMemory(sizeof(*ChannelBindings) + EncAsReq->length);
    if (ChannelBindings == nullptr) {
        return krb5_enomem(KrbContext);
    }

    ChannelBindings->cbApplicationDataLength = (ULONG)EncAsReq->length;
    ChannelBindings->dwApplicationDataOffset = sizeof(*ChannelBindings);
    memcpy((PBYTE)ChannelBindings + ChannelBindings->dwApplicationDataOffset,
           EncAsReq->data, EncAsReq->length);

    *pChannelBindings = ChannelBindings;
    return 0;
}

static krb5_error_code KRB5_LIB_CALL
SspiPreauthStep(krb5_context KrbContext,
                krb5_gss_init_ctx GssICContext,
                const krb5_creds *KrbCred,
                gss_ctx_id_t *GssContextHandle,
                KDCOptions KrbReqFlags,
                krb5_data *EncAsReq,
                krb5_data *InputToken,
                krb5_data *OutputToken)
{
    krb5_error_code KrbError;
    ULONG fContextReq, fContextAttr = 0;
    LPWSTR TargetName = nullptr;
    krb5_principal TgsName = nullptr;
    PSEC_CHANNEL_BINDINGS ChannelBindings = nullptr;
    SecBuffer InputBuffers[2];
    SecBuffer OutputBuffer = { .cbBuffer = 0, .pvBuffer = nullptr };
    SecBufferDesc InputBufferDesc, OutputBufferDesc;
    TimeStamp tsExpiry;
    SECURITY_STATUS SecStatus;

    auto Mech = _krb5_init_creds_get_gss_mechanism(KrbContext, GssICContext);

    assert(Mech != nullptr && Mech->Package != nullptr);
    assert(KrbCred != nullptr);
    assert(KrbCred->server != nullptr);

    krb5_data_zero(OutputToken);

    DebugTrace(WINEVENT_LEVEL_VERBOSE, L"PA stepping context %08x.%08x token length %u",
               *GssContextHandle == nullptr ? 0 : (*GssContextHandle)->Handle.dwLower,
               *GssContextHandle == nullptr ? 0 : (*GssContextHandle)->Handle.dwUpper,
               InputToken == nullptr ? 0 : InputToken->length);

    auto cleanup = wil::scope_exit([&]() {
        if (KrbError != 0 && KrbError != HEIM_ERR_PA_CONTINUE_NEEDED) {
            krb5_data_free(OutputToken);
            krb5_data_zero(OutputToken);
        }
        krb5_free_principal(KrbContext, TgsName);
        WIL_FreeMemory(TargetName);
        WIL_FreeMemory(ChannelBindings);
                                   });

    PSecPkgInfo SecurityInfo;
    SecStatus = QuerySecurityPackageInfo(const_cast<PWSTR>(Mech->Package), &SecurityInfo);
    if (SecStatus != SEC_E_OK) {
        DebugTrace(WINEVENT_LEVEL_ERROR, L"Failed to query security package info for %s: 0x%08x",
                   Mech->Package, SecStatus);
        KrbError = SspiStatusToKrbError(SecStatus);
        return KrbError;
    }

    fContextReq = ISC_REQ_MUTUAL_AUTH;
    if (KrbReqFlags.request_anonymous)
        fContextReq |= ISC_REQ_NULL_SESSION;

    auto GssCredHandle = const_cast<gss_cred_id_t>(_krb5_init_creds_get_gss_cred(KrbContext, GssICContext));
    assert(GssCredHandle != nullptr);

    KrbError = krb5_make_principal(KrbContext,
                                   &TgsName,
                                   KrbCred->server->realm,
                                   KRB5_TGS_NAME,
                                   KrbCred->server->realm,
                                   nullptr);
    RETURN_IF_KRB_FAILED(KrbError);

    KrbError = SspiPreauthUnparseName(KrbContext, TgsName, &TargetName);
    RETURN_IF_KRB_FAILED(KrbError);

    InputBufferDesc.ulVersion = SECBUFFER_VERSION;
    InputBufferDesc.cBuffers = 0;
    InputBufferDesc.pBuffers = InputBuffers;

    if (InputToken != nullptr && InputToken->length != 0) {
        DebugTrace(WINEVENT_LEVEL_VERBOSE, L"PA for package %s, using target %s", Mech->Package, TargetName);

        PSecBuffer pSecBuffer = &InputBuffers[InputBufferDesc.cBuffers++];

        pSecBuffer->BufferType = SECBUFFER_TOKEN;
        pSecBuffer->cbBuffer = (ULONG)InputToken->length;
        pSecBuffer->pvBuffer = InputToken->data;
    }

    KrbError = MakeChannelBindings(KrbContext, EncAsReq, &ChannelBindings);
    RETURN_IF_KRB_FAILED(KrbError);

    PSecBuffer pSecBuffer = &InputBuffers[InputBufferDesc.cBuffers++];
    pSecBuffer->BufferType = SECBUFFER_CHANNEL_BINDINGS;
    pSecBuffer->cbBuffer = sizeof(*ChannelBindings) + (ULONG)EncAsReq->length;
    pSecBuffer->pvBuffer = ChannelBindings;

    OutputBufferDesc.ulVersion = SECBUFFER_VERSION;
    OutputBufferDesc.cBuffers = 1;
    OutputBufferDesc.pBuffers = &OutputBuffer;

    KrbError = krb5_data_alloc(OutputToken, SecurityInfo->cbMaxToken);
    RETURN_IF_KRB_FAILED(KrbError);

    OutputBuffer.BufferType = SECBUFFER_TOKEN;
    OutputBuffer.cbBuffer = SecurityInfo->cbMaxToken;
    OutputBuffer.pvBuffer = OutputToken->data;

    PCtxtHandle InputContextHandle;
    CtxtHandle OutputContextHandle = { .dwLower = 0, .dwUpper = 0 };

    if (*GssContextHandle != nullptr)
        InputContextHandle = &(*GssContextHandle)->Handle;
    else
        InputContextHandle = nullptr;

    SecStatus = InitializeSecurityContext(const_cast<PCredHandle>(&GssCredHandle->Handle),
                                          InputContextHandle,
                                          TargetName,
                                          fContextReq,
                                          0, // Reserved1 (MBZ)
                                          SECURITY_NATIVE_DREP,
                                          &InputBufferDesc,
                                          0, // Reserved2 (MBZ)
                                          &OutputContextHandle,
                                          &OutputBufferDesc,
                                          &fContextAttr,
                                          &tsExpiry);

    if (SecStatus == SEC_E_OK || SecStatus == SEC_I_CONTINUE_NEEDED) {
        OutputToken->length = OutputBuffer.cbBuffer;
    } else {
        GssCredHandle->LastStatus = SecStatus;
    }

    if (*GssContextHandle == nullptr) {
        *GssContextHandle = (gss_ctx_id_t)WIL_AllocateMemory(sizeof(gss_ctx_id_t_desc_struct));
        if (*GssContextHandle == nullptr) {
            DeleteSecurityContext(&OutputContextHandle); // don't orphan it
            return krb5_enomem(KrbContext);
        }
    }

    (*GssContextHandle)->Handle = OutputContextHandle;

    if (SecStatus == SEC_E_OK &&
        (fContextAttr & ISC_RET_MUTUAL_AUTH) == 0)
        KrbError = KRB5_MUTUAL_FAILED;
    else
        KrbError = SspiStatusToKrbError(SecStatus);

    if (KrbError != 0 && KrbError != HEIM_ERR_PA_CONTINUE_NEEDED) {
        auto szError = krb5_get_error_message(KrbContext, KrbError);
        DebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"PA InitializeSecurityContext returned SecStatus 0x%08x / KrbError %d (%S)",
                   SecStatus, KrbError, szError);
        krb5_free_error_message(KrbContext, szError);
    }

    return KrbError;
}
  
static krb5_error_code KRB5_LIB_CALL
SspiPreauthFinish(
    krb5_context KrbContext,
    krb5_gss_init_ctx GssICContext,
    const krb5_creds *KrbCred,
    gss_ctx_id_t GssContextHandle,
    krb5int32 AsReqNonce,
    krb5_enctype KrbEncType,
    krb5_principal *pClientPrincipal,
    krb5_keyblock **ppReplyKey)
{
    krb5_error_code KrbError;
    SECURITY_STATUS SecStatus;
    SecPkgContext_NativeNames NativeNames = {
        .sClientName = nullptr,
        .sServerName = nullptr
    };

    *pClientPrincipal = nullptr;
    *ppReplyKey = nullptr;

    auto cleanup = wil::scope_exit([&]() {
        if (NativeNames.sClientName != nullptr)
            FreeContextBuffer(NativeNames.sClientName);
        if (NativeNames.sServerName != nullptr)
            FreeContextBuffer(NativeNames.sServerName);
                                   });

    SecStatus = QueryContextAttributes(&GssContextHandle->Handle,
                                       SECPKG_ATTR_NATIVE_NAMES,
                                       &NativeNames);
    if (SecStatus != SEC_E_OK)
        return SspiStatusToKrbError(SecStatus);

    KrbError = SspiPreauthParseName(KrbContext,
                                    NativeNames.sClientName,
                                    pClientPrincipal);
    RETURN_IF_KRB_FAILED_MSG(KrbError, "Failed to parse initiator name");

    KrbError = SspiPreauthDeriveKey(KrbContext,
                                    &GssContextHandle->Handle,
                                    AsReqNonce,
                                    KrbEncType,
                                    ppReplyKey);
    RETURN_IF_KRB_FAILED_MSG(KrbError, "Failed to derive reply key");

    return 0;
}

static void KRB5_LIB_CALL
SspiPreauthDeleteSecContext(
    krb5_context KrbContext,
    krb5_gss_init_ctx GssICContext,
    gss_ctx_id_t GssContextHandle)
{
    if (GssContextHandle != nullptr) {
        DeleteSecurityContext(&GssContextHandle->Handle);
        WIL_FreeMemory(GssContextHandle);
    }
}

static void KRB5_LIB_CALL
SspiPreauthReleaseCred(
    krb5_context KrbContext,
    krb5_gss_init_ctx GssICContext,
    gss_cred_id_t GssCredHandle)
{
    if (GssCredHandle != nullptr) {
        FreeCredentialsHandle(&GssCredHandle->Handle);
        WIL_FreeMemory(GssCredHandle);
    }
}

static krb5_error_code
MakeWKAnonymousName(_In_ krb5_context KrbContext,
                    _Out_ krb5_principal *pPrincipal)
{
    return krb5_make_principal(KrbContext, pPrincipal,
                               KRB5_ANON_REALM, KRB5_WELLKNOWN_NAME,
                               KRB5_ANON_NAME, nullptr);
}

static krb5_error_code
MakeWKFederatedName(_In_ krb5_context KrbContext,
                    _In_z_ PCWSTR RealmName,
                    _Out_ krb5_principal *pPrincipal)
{
    PCHAR RealmNameUTF8;

    *pPrincipal = nullptr;

    if (!NT_SUCCESS(UnicodeToUTF8Alloc(RealmName, &RealmNameUTF8)))
        return krb5_enomem(KrbContext);

    krb5_error_code KrbError = krb5_make_principal(KrbContext,
                                                   pPrincipal,
                                                   RealmNameUTF8,
                                                   KRB5_WELLKNOWN_NAME,
                                                   KRB5_FEDERATED_NAME,
                                                   nullptr);

    WIL_FreeMemory(RealmNameUTF8);

    return KrbError;
}

static krb5_error_code
AllocateSendToContext(_In_ krb5_context KrbContext,
                      _In_opt_z_ PCWSTR KdcHostName,
                      _Out_ krb5_sendto_ctx *pSendToContext)
{
    krb5_error_code KrbError;
    krb5_sendto_ctx SendToContext;

    *pSendToContext = nullptr;

    KrbError = krb5_sendto_ctx_alloc(KrbContext, &SendToContext);
    RETURN_IF_KRB_FAILED(KrbError);

    if (KdcHostName != nullptr) {
        PSTR KdcHostNameUTF8;

        if (!NT_SUCCESS(UnicodeToUTF8Alloc(KdcHostName, &KdcHostNameUTF8)))
            return krb5_enomem(KrbContext);

        DebugTrace(WINEVENT_LEVEL_VERBOSE, L"PA pinning KDC %s", KdcHostName);
        krb5_sendto_set_hostname(KrbContext, SendToContext, KdcHostNameUTF8);
        WIL_FreeMemory(KdcHostNameUTF8);
    }

    // force TCP
    krb5_sendto_ctx_add_flags(SendToContext, KRB5_KRBHST_FLAGS_LARGE_MSG);
    // looks for the _kerberos-tkt-bridge DNS SRV name
    krb5_sendto_ctx_set_type(SendToContext, KRB5_KRBHST_TKTBRIDGEAP);

    *pSendToContext = SendToContext;

    return 0;
}

//
// Acquire a TGT for a given username/domain/credential/package
//
krb5_error_code
SspiPreauthGetInitCreds(_In_z_ PCWSTR RealmName,
                        _In_opt_z_ PCWSTR PackageName,
                        _In_opt_z_ PCWSTR KdcHostName,
                        _In_opt_ PLUID pvLogonID,
                        _In_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity,
                        _Out_ PWSTR *pClientName,
                        _Inout_ krb5_data *AsRep,
                        _Inout_ krb5_keyblock *AsReplyKey,
                        _Out_ SECURITY_STATUS *pSecStatus)
{
    krb5_error_code KrbError;
    krb5_context KrbContext;
    krb5_init_creds_context InitCredsContext;
    krb5_get_init_creds_opt *InitCredsOpt = nullptr;
    krb5_principal FederatedPrinc = nullptr;
    struct gss_cred_id_t_desc_struct GssCredHandle;
    struct gss_OID_desc_struct GssMech;
    krb5_data AsReq;
    krb5_sendto_ctx SendToContext = nullptr;
    
    SECURITY_STATUS SecStatus;
    PSEC_WINNT_AUTH_IDENTITY_OPAQUE NegoAuthIdentity = nullptr;

    ZeroMemory(&GssCredHandle, sizeof(GssCredHandle));
    GssCredHandle.LastStatus = SEC_E_NO_CONTEXT;

    krb5_data_zero(&AsReq);

    *pClientName = nullptr;
    *pSecStatus = SEC_E_NO_CONTEXT;
    krb5_data_zero(AsRep);
    AsReplyKey->keytype = (krb5_enctype)ENCTYPE_NULL;
    krb5_data_zero(&AsReplyKey->keyvalue);

    // pass the package name via GssMech so we can query token size later
    if (PackageName == nullptr)
        PackageName = NEGOSSP_NAME_W;

    auto cleanup = wil::scope_exit([&] {
        // validate we never set *pSecStatus to SEC_E_OK if there was a Kerb error
        assert((KrbError == 0) == (*pSecStatus == SEC_E_OK));

        if (KrbError == 0) {
           EventWriteTKTBRIDGEAP_EVENT_AS_REQ_SUCCESS(RealmName, PackageName, KdcHostName,
                                                      *pClientName, *pSecStatus, KrbError, "");
        } else {
            auto szError = krb5_get_error_message(KrbContext, KrbError);
            EventWriteTKTBRIDGEAP_EVENT_AS_REQ_FAILURE(RealmName, PackageName, KdcHostName,
                                                       *pClientName, *pSecStatus, KrbError, szError);
            krb5_free_error_message(KrbContext, szError);
        }

        if (KrbContext != nullptr) {
            if (KrbError != 0) {
                krb5_free_keyblock_contents(KrbContext, AsReplyKey);
                krb5_data_free(AsRep);
            }
            if (SendToContext != nullptr)
                krb5_sendto_ctx_free(KrbContext, SendToContext);
            if (InitCredsContext != nullptr)
                krb5_init_creds_free(KrbContext, InitCredsContext);
            krb5_get_init_creds_opt_free(KrbContext, InitCredsOpt);           
            krb5_free_principal(KrbContext, FederatedPrinc);
            krb5_free_context(KrbContext);
            KrbContext = nullptr;
        }

        SspiFreeAuthIdentity(NegoAuthIdentity);
        FreeCredentialsHandle(&GssCredHandle.Handle);
                                   });

    // make sure we do not try to use Kerberos as a pre-auth mech
    if (wcscmp(PackageName, NEGOSSP_NAME_W) == 0) {
        SecStatus = SspiExcludePackage(AuthIdentity,
                                       MICROSOFT_KERBEROS_NAME_W,
                                       &NegoAuthIdentity);
        if (SecStatus != SEC_E_OK) {
            *pSecStatus = SecStatus;

            KrbError = SspiStatusToKrbError(SecStatus);
            return KrbError;
        }

        AuthIdentity = NegoAuthIdentity;
    }

    GssMech.Package = PackageName;

    // acquire credentials handle, only use explicitly passed credentials
    TimeStamp tsExpiry;
    SecStatus = AcquireCredentialsHandle(nullptr, // pszPrincipal
                                         const_cast<LPWSTR>(PackageName),
                                         SECPKG_CRED_AUTOLOGON_RESTRICTED | SECPKG_CRED_OUTBOUND,
                                         pvLogonID,
                                         AuthIdentity,
                                         nullptr,
                                         nullptr,
                                         &GssCredHandle.Handle,
                                         &tsExpiry);

    PCWSTR wszDomainName = nullptr;
    PCWSTR wszUserName = nullptr;

    SspiEncodeAuthIdentityAsStrings(AuthIdentity, &wszUserName, &wszDomainName, nullptr);

    DebugTrace(WINEVENT_LEVEL_VERBOSE,
               L"AcquireCredentialsHandle(%s, <%08x.%08x>, %s@%s): %08x",
               PackageName,
               pvLogonID == nullptr ? 0 : pvLogonID->LowPart,
               pvLogonID == nullptr ? 0 : pvLogonID->HighPart,
               wszUserName, wszDomainName, SecStatus);

    SspiLocalFree((PVOID)wszUserName);
    SspiLocalFree((PVOID)wszDomainName);

    if (SecStatus != SEC_E_OK) {
        *pSecStatus = SecStatus;

        KrbError = SspiStatusToKrbError(SecStatus);
        return KrbError;
    }

    KrbError = krb5_init_context(&KrbContext);
    RETURN_IF_KRB_FAILED(KrbError);

    KrbError = HeimTracingInit(KrbContext);
    RETURN_IF_KRB_FAILED_MSG(KrbError, L"Failed to initialize Heimdal tracing");

    KrbError = MakeWKFederatedName(KrbContext, RealmName, &FederatedPrinc);
    RETURN_IF_KRB_FAILED_MSG(KrbError, L"Failed to make WELLKNOWN/FEDERATED principal");

    KrbError = krb5_get_init_creds_opt_alloc(KrbContext, &InitCredsOpt);
    RETURN_IF_KRB_FAILED(KrbError);

    krb5_get_init_creds_opt_set_canonicalize(KrbContext, InitCredsOpt, TRUE);

    KrbError = krb5_init_creds_init(KrbContext, FederatedPrinc, nullptr, nullptr, 0,
                                    InitCredsOpt, &InitCredsContext);
    RETURN_IF_KRB_FAILED(KrbError);

    KrbError = krb5_init_creds_set_service(KrbContext, InitCredsContext, nullptr);
    RETURN_IF_KRB_FAILED(KrbError);

    KrbError = _krb5_init_creds_init_gss(KrbContext,
                                         InitCredsContext,
                                         SspiPreauthStep,
                                         SspiPreauthFinish,
                                         SspiPreauthReleaseCred,
                                         SspiPreauthDeleteSecContext,
                                         &GssCredHandle,
                                         &GssMech,
                                         0); // no flags, do not free cred handle
    RETURN_IF_KRB_FAILED_MSG(KrbError, L"Failed to register SSPI callbacks");

    KrbError = AllocateSendToContext(KrbContext, KdcHostName, &SendToContext);
    RETURN_IF_KRB_FAILED_MSG(KrbError, L"Failed to allocate SendToContext");

    while (1) {
        unsigned int Flags = 0;

        KrbError = krb5_init_creds_step(KrbContext, InitCredsContext,
                                        AsRep, &AsReq, nullptr, &Flags);
        if (KrbError != 0)
            *pSecStatus = GssCredHandle.LastStatus;
        RETURN_IF_KRB_FAILED_MSG(KrbError, L"Failed to advance PA conversation");

        if ((Flags & KRB5_INIT_CREDS_STEP_FLAG_CONTINUE) == 0)
            break;

        krb5_data_free(AsRep);
        krb5_data_zero(AsRep);

        // note: AsReq buffer is owned by InitCredsContext, do not free
        KrbError = krb5_sendto_context(KrbContext, SendToContext, &AsReq,
                                       FederatedPrinc->realm, AsRep);
        RETURN_IF_KRB_FAILED_MSG(KrbError, "Failed to send AS-REQ to KDC");
    }

    auto ClientName = _krb5_init_creds_get_cred_client(KrbContext, InitCredsContext);
    KrbError = SspiPreauthUnparseName(KrbContext, ClientName, pClientName);
    RETURN_IF_KRB_FAILED_MSG(KrbError, L"Failed to determine Kerberos client name");

    KrbError = krb5_init_creds_get_as_reply_key(KrbContext, InitCredsContext, AsReplyKey);
    RETURN_IF_KRB_FAILED_MSG(KrbError, L"Failed to retrieve reply key");

    *pSecStatus = SEC_E_OK;

    return 0;
}
