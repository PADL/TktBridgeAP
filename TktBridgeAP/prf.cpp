/*++

Copyright (c) PADL Software Pty Ltd, All rights reserved.

Module Name:

    prf.cpp

Abstract:

    SSPI to Heimdal pre-authentication glue

Environment:

    Local Security Authority (LSA)

--*/

#include "TktBridgeAP.h"

_Success_(return == 0) krb5_error_code
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
    SecPkgContext_KeyInfo KeyInfo = {
        .sSignatureAlgorithmName = nullptr,
        .sEncryptAlgorithmName = nullptr
    };
    krb5_keyblock key;
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
        FreeContextBuffer(KeyInfo.sSignatureAlgorithmName);
        FreeContextBuffer(KeyInfo.sEncryptAlgorithmName);
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

    SecStatus = QueryContextAttributes(phContext, SECPKG_ATTR_KEY_INFO, &KeyInfo);
    if (SecStatus != SEC_E_OK) {
        KrbError = SspiStatusToKrbError(SecStatus);
        return KrbError;
    }

    key.keytype = KeyInfo.EncryptAlgorithm;
    key.keyvalue.data = SessionKey.SessionKey;
    key.keyvalue.length = SessionKey.SessionKeyLength;

    KrbError = krb5_crypto_init(KrbContext, &key, KRB5_ENCTYPE_NULL, &KrbCrypto);
    RETURN_IF_KRB_FAILED(KrbError);

    KrbError = krb5_enctype_keysize(KrbContext, EncryptionType, &KeySize);
    RETURN_IF_KRB_FAILED(KrbError);

    if (KeySize == 0)
        return KRB5_BAD_KEYSIZE;

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

    memcpy((PBYTE)Input.data + 4, pbPrfInput, cbPrfInput);

    ULONG iPrf = 0;
    PBYTE pbPrf = (PBYTE)*pbPrfOutput;

    cbDesiredOutput = *pcbPrfOutput;

    while (cbDesiredOutput > 0) {
        SIZE_T cbPrf;
        krb5_data Output;

        krb5_data_zero(&Output);

        ((PBYTE)Input.data)[0] = (iPrf >> 24) & 0xFF;
        ((PBYTE)Input.data)[1] = (iPrf >> 16) & 0xFF;
        ((PBYTE)Input.data)[2] = (iPrf >> 8) & 0xFF;
        ((PBYTE)Input.data)[3] = (iPrf) & 0xFF;

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

    return 0;
}
