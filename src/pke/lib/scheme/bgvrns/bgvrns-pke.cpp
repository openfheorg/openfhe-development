//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
BGV implementation. See https://eprint.iacr.org/2021/204 for details.
 */

#define PROFILE

#include "cryptocontext.h"
#include "scheme/bgvrns/bgvrns-cryptoparameters.h"
#include "scheme/bgvrns/bgvrns-pke.h"

namespace lbcrypto {

DecryptResult PKEBGVRNS::Decrypt(ConstCiphertext<DCRTPoly> ciphertext, const PrivateKey<DCRTPoly> privateKey,
                                 NativePoly* plaintext) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBGVRNS>(ciphertext->GetCryptoParameters());
    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    size_t sizeQl                   = cv[0].GetParams()->GetParams().size();

    DCRTPoly b;
    NativeInteger scalingFactorInt = ciphertext->GetScalingFactorInt();
    if (cv[0].GetFormat() == Format::EVALUATION) {
        b = PKERNS::DecryptCore(cv, privateKey);
        b.SetFormat(Format::COEFFICIENT);
        if (sizeQl > 0) {
            for (size_t i = sizeQl - 1; i > 0; --i) {
                b.ModReduce(cryptoParams->GetPlaintextModulus(), cryptoParams->GettModqPrecon(),
                            cryptoParams->GetNegtInvModq(i), cryptoParams->GetNegtInvModqPrecon(i),
                            cryptoParams->GetqlInvModq(i), cryptoParams->GetqlInvModqPrecon(i));
            }
            // TODO: Use pre-computed scaling factor at level L.
            if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO ||
                cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT) {
                for (size_t i = 0; i < sizeQl - 1; ++i) {
                    NativeInteger modReduceFactor    = cryptoParams->GetModReduceFactorInt(sizeQl - 1 - i);
                    NativeInteger modReduceFactorInv = modReduceFactor.ModInverse(cryptoParams->GetPlaintextModulus());
                    scalingFactorInt = scalingFactorInt.ModMul(modReduceFactorInv, cryptoParams->GetPlaintextModulus());
                }
            }
        }
    }
    else {
        std::vector<DCRTPoly> ct(cv);
        if (sizeQl > 0) {
            for (size_t j = sizeQl - 1; j > 0; j--) {
                for (usint i = 0; i < ct.size(); i++) {
                    ct[i].ModReduce(cryptoParams->GetPlaintextModulus(), cryptoParams->GettModqPrecon(),
                                    cryptoParams->GetNegtInvModq(j), cryptoParams->GetNegtInvModqPrecon(j),
                                    cryptoParams->GetqlInvModq(j), cryptoParams->GetqlInvModqPrecon(j));
                }
            }
            if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO ||
                cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT) {
                for (size_t i = 0; i < sizeQl - 1; i++) {
                    NativeInteger modReduceFactor    = cryptoParams->GetModReduceFactorInt(sizeQl - 1 - i);
                    NativeInteger modReduceFactorInv = modReduceFactor.ModInverse(cryptoParams->GetPlaintextModulus());
                    scalingFactorInt = scalingFactorInt.ModMul(modReduceFactorInv, cryptoParams->GetPlaintextModulus());
                }
            }
        }

        b = PKERNS::DecryptCore(ct, privateKey);
        b.SetFormat(Format::COEFFICIENT);
    }

    *plaintext = b.GetElementAtIndex(0).DecryptionCRTInterpolate(cryptoParams->GetPlaintextModulus());

    return DecryptResult(plaintext->GetLength(), scalingFactorInt);
}

}  // namespace lbcrypto
