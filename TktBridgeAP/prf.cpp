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
    SECURITY_STATUS SecStatus;
    SecPkgContext_SessionKey SessionKey = {
        .SessionKeyLength = 0,
        .SessionKey = nullptr
    };
    SecPkgContext_KeyInfo KeyInfo = {
        .sSignatureAlgorithmName = nullptr,
        .sEncryptAlgorithmName = nullptr
    };
    krb5_data Input;
    krb5_crypto KrbCrypto = nullptr;

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

    krb5_keyblock Key;
    size_t KeySize;

    Key.keytype         = KeyInfo.EncryptAlgorithm;
    Key.keyvalue.data   = SessionKey.SessionKey;
    Key.keyvalue.length = SessionKey.SessionKeyLength;

    KrbError = krb5_crypto_init(KrbContext, &Key, KRB5_ENCTYPE_NULL, &KrbCrypto);
    RETURN_IF_KRB_FAILED(KrbError);

    KrbError = krb5_enctype_keysize(KrbContext, EncryptionType, &KeySize);
    RETURN_IF_KRB_FAILED(KrbError);

    if (KeySize == 0)
        return KRB5_BAD_KEYSIZE;

    *pbPrfOutput = static_cast<PBYTE>(WIL_AllocateMemory(KeySize));
    if (*pbPrfOutput == nullptr) {
        KrbError = krb5_enomem(KrbContext);
        return KrbError;
    }

    *pcbPrfOutput = KeySize;

    Input.length = 4 + static_cast<SIZE_T>(cbPrfInput);
    Input.data = WIL_AllocateMemory(Input.length);
    if (Input.data == nullptr) {
        KrbError = krb5_enomem(KrbContext);
        return KrbError;
    }

    memcpy(static_cast<PBYTE>(Input.data) + 4, pbPrfInput, cbPrfInput);

    ULONG iPrf = 0;
    auto pbPrf = static_cast<PBYTE>(*pbPrfOutput);
    auto cbDesiredOutput = *pcbPrfOutput;

    while (cbDesiredOutput > 0) {
        SIZE_T cbPrf;
        krb5_data Output;

        krb5_data_zero(&Output);

        static_cast<PBYTE>(Input.data)[0] = (iPrf >> 24) & 0xFF;
        static_cast<PBYTE>(Input.data)[1] = (iPrf >> 16) & 0xFF;
        static_cast<PBYTE>(Input.data)[2] = (iPrf >>  8) & 0xFF;
        static_cast<PBYTE>(Input.data)[3] = (iPrf      ) & 0xFF;

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
