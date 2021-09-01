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

static krb5_error_code
GssPreauthDeriveKey(_In_ krb5_context KrbContext,
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
MakeWKFederatedName(_In_ krb5_context KrbContext,
                    _In_z_ PCWSTR RealmName,
                    _Out_ krb5_principal *pPrincipal)
{
    PCHAR RealmNameUTF8;

    *pPrincipal = nullptr;

    if (!NT_SUCCESS(UnicodeToUTF8Alloc(RealmName, &RealmNameUTF8)))
        return ENOMEM;

    auto KrbError = krb5_make_principal(KrbContext,
                                        pPrincipal,
                                        RealmNameUTF8,
                                        KRB5_WELLKNOWN_NAME,
                                        KRB5_FEDERATED_NAME,
                                        nullptr);

    WIL_FreeMemory(RealmNameUTF8);

    return KrbError;
}

static krb5_error_code
GssPreauthUnparseName(_In_ krb5_context KrbContext,
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

    KrbError = NT_SUCCESS(UTF8ToUnicodeAlloc(szNameString, pwszNameString))
               ? 0 : ENOMEM;

    if (szNameString != Principal->name.name_string.val[0])
        krb5_xfree(szNameString);

    return KrbError;
}

static krb5_error_code
GssPreauthParseName(_In_ krb5_context KrbContext,
                    _In_z_ PCWSTR NameString,
                    _Out_ krb5_principal *pPrincipal)
{
    krb5_error_code KrbError;
    PCHAR szNameString;

    *pPrincipal = nullptr;

    if (!NT_SUCCESS(UnicodeToUTF8Alloc(NameString, &szNameString)))
        return ENOMEM;

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

    ChannelBindings = static_cast<PSEC_CHANNEL_BINDINGS>
        (WIL_AllocateMemory(sizeof(*ChannelBindings) + EncAsReq->length));
    if (ChannelBindings == nullptr) {
        return ENOMEM;
    }

    ChannelBindings->cbApplicationDataLength = static_cast<ULONG>(EncAsReq->length);
    ChannelBindings->dwApplicationDataOffset = sizeof(*ChannelBindings);
    memcpy(reinterpret_cast<PBYTE>(ChannelBindings) + ChannelBindings->dwApplicationDataOffset,
           EncAsReq->data, EncAsReq->length);

    *pChannelBindings = ChannelBindings;
    return 0;
}

static krb5_error_code KRB5_LIB_CALL
GssPreauthStep(krb5_context KrbContext,
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
    PWSTR TargetName = nullptr;
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
        if (KrbError != 0 && KrbError != HEIM_ERR_PA_CONTINUE_NEEDED)
            krb5_data_free(OutputToken);
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

    KrbError = GssPreauthUnparseName(KrbContext, TgsName, &TargetName);
    RETURN_IF_KRB_FAILED(KrbError);

    InputBufferDesc.ulVersion = SECBUFFER_VERSION;
    InputBufferDesc.cBuffers = 0;
    InputBufferDesc.pBuffers = InputBuffers;

    if (InputToken != nullptr && InputToken->length != 0) {
        PSecBuffer pSecBuffer = &InputBuffers[InputBufferDesc.cBuffers++];

        pSecBuffer->BufferType = SECBUFFER_TOKEN;
        pSecBuffer->cbBuffer = static_cast<ULONG>(InputToken->length);
        pSecBuffer->pvBuffer = InputToken->data;
    } else {
        DebugTrace(WINEVENT_LEVEL_VERBOSE, L"PA for package %s, using target %s", Mech->Package, TargetName);
    }

    KrbError = MakeChannelBindings(KrbContext, EncAsReq, &ChannelBindings);
    RETURN_IF_KRB_FAILED(KrbError);

    PSecBuffer pSecBuffer = &InputBuffers[InputBufferDesc.cBuffers++];
    pSecBuffer->BufferType = SECBUFFER_CHANNEL_BINDINGS;
    pSecBuffer->cbBuffer = sizeof(*ChannelBindings) + static_cast<ULONG>(EncAsReq->length);
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
        *GssContextHandle = static_cast<gss_ctx_id_t>(WIL_AllocateMemory(sizeof(gss_ctx_id_t_desc_struct)));
        if (*GssContextHandle == nullptr) {
            DeleteSecurityContext(&OutputContextHandle); // don't orphan it
            return ENOMEM;
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
GssPreauthFinish(krb5_context KrbContext,
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

    KrbError = GssPreauthParseName(KrbContext,
                                   NativeNames.sClientName,
                                   pClientPrincipal);
    RETURN_IF_KRB_FAILED_MSG(KrbError, L"Failed to parse initiator name");

    KrbError = GssPreauthDeriveKey(KrbContext,
                                   &GssContextHandle->Handle,
                                   AsReqNonce,
                                   KrbEncType,
                                   ppReplyKey);
    RETURN_IF_KRB_FAILED_MSG(KrbError, L"Failed to derive reply key");

    return 0;
}

static void KRB5_LIB_CALL
GssPreauthDeleteSecContext(krb5_context KrbContext,
                           krb5_gss_init_ctx GssICContext,
                           gss_ctx_id_t GssContextHandle)
{
    if (GssContextHandle != nullptr) {
        DeleteSecurityContext(&GssContextHandle->Handle);
        WIL_FreeMemory(GssContextHandle);
    }
}

static void KRB5_LIB_CALL
GssPreauthReleaseCred(krb5_context KrbContext,
                      krb5_gss_init_ctx GssICContext,
                      gss_cred_id_t GssCredHandle)
{
    if (GssCredHandle != nullptr) {
        FreeCredentialsHandle(&GssCredHandle->Handle);
        WIL_FreeMemory(GssCredHandle);
    }
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
            return ENOMEM;

        DebugTrace(WINEVENT_LEVEL_VERBOSE, L"PA will prefer KDC %s", KdcHostName);
        krb5_sendto_set_hostname(KrbContext, SendToContext, KdcHostNameUTF8);
        WIL_FreeMemory(KdcHostNameUTF8);
    }

    // force TCP
    krb5_sendto_ctx_add_flags(SendToContext, KRB5_KRBHST_FLAGS_LARGE_MSG);

#ifdef KRB5_KRBHST_TKTBRIDGEAP
    // looks for the _kerberos-tkt-bridge DNS SRV name
    krb5_sendto_ctx_set_type(SendToContext, KRB5_KRBHST_TKTBRIDGEAP);
#else
#warning Heimdal does not support _kerberos-tkt-bridge DNS SRV name
#endif

    *pSendToContext = SendToContext;

    return 0;
}

/*
 * Acquire a TGT for a given username/domain/credential/package
 */
_Success_(return == 0) krb5_error_code
GssPreauthGetInitCreds(_In_z_ PCWSTR RealmName,
                       _In_opt_z_ PCWSTR PackageName,
                       _In_opt_z_ PCWSTR KdcHostName,
                       _In_ ULONG Flags,
                       _In_opt_ PLUID pvLogonId,
                       _In_ PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity,
                       _Out_ PWSTR *pClientName,
                       _Out_ LARGE_INTEGER *pEndTime,
                       _Out_ krb5_data *AsRep,
                       _Out_ krb5_keyblock *AsReplyKey,
                       _Out_ SECURITY_STATUS *pSecStatus)
{
    krb5_error_code KrbError;
    krb5_context KrbContext = nullptr;
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

    ZeroMemory(&InitCredsContext, sizeof(InitCredsContext));
    krb5_data_zero(&AsReq);

    *pClientName = nullptr;
    pEndTime->QuadPart = 0;
    krb5_data_zero(AsRep);
    AsReplyKey->keytype = KRB5_ENCTYPE_NULL;
    krb5_data_zero(&AsReplyKey->keyvalue);
    *pSecStatus = SEC_E_NO_CONTEXT;

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
                                         const_cast<PWSTR>(PackageName),
                                         SECPKG_CRED_AUTOLOGON_RESTRICTED | SECPKG_CRED_OUTBOUND,
                                         pvLogonId,
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
               pvLogonId == nullptr ? 0 : pvLogonId->LowPart,
               pvLogonId == nullptr ? 0 : pvLogonId->HighPart,
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
    RETURN_IF_KRB_FAILED_MSG(KrbError, L"Failed to allocate init creds options");

    krb5_get_init_creds_opt_set_canonicalize(KrbContext, InitCredsOpt, TRUE);

    KrbError = krb5_init_creds_init(KrbContext, FederatedPrinc, nullptr, nullptr, 0,
                                    InitCredsOpt, &InitCredsContext);
    RETURN_IF_KRB_FAILED_MSG(KrbError, L"Failed to allocate init creds context");

    KrbError = krb5_init_creds_set_service(KrbContext, InitCredsContext, nullptr);
    RETURN_IF_KRB_FAILED_MSG(KrbError, L"Failed to set TGS on init creds context");

    if (Flags & GSS_PREAUTH_INIT_CREDS_ANON_PKINIT_FAST) {
        KrbError = krb5_init_creds_set_fast_anon_pkinit(KrbContext, InitCredsContext);
        RETURN_IF_KRB_FAILED_MSG(KrbError, L"Failed to enable anonymous PKINIT FAST");
    }

    KrbError = _krb5_init_creds_init_gss(KrbContext,
                                         InitCredsContext,
                                         GssPreauthStep,
                                         GssPreauthFinish,
                                         GssPreauthReleaseCred,
                                         GssPreauthDeleteSecContext,
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

        // note: AsReq buffer is owned by InitCredsContext, do not free
        KrbError = krb5_sendto_context(KrbContext, SendToContext, &AsReq,
                                       FederatedPrinc->realm, AsRep);
        RETURN_IF_KRB_FAILED_MSG(KrbError, L"Failed to send AS-REQ to KDC");
    }

    auto ClientName = _krb5_init_creds_get_cred_client(KrbContext, InitCredsContext);
    KrbError = GssPreauthUnparseName(KrbContext, ClientName, pClientName);
    RETURN_IF_KRB_FAILED_MSG(KrbError, L"Failed to determine Kerberos client name");

    auto EndTime = _krb5_init_creds_get_cred_endtime(KrbContext, InitCredsContext);
    Seconds64Since1970ToTime(EndTime, pEndTime);

    KrbError = krb5_init_creds_get_as_reply_key(KrbContext, InitCredsContext, AsReplyKey);
    RETURN_IF_KRB_FAILED_MSG(KrbError, L"Failed to retrieve reply key");

    *pSecStatus = SEC_E_OK;

    return 0;
}
