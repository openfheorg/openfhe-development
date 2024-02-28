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
CKKS implementation. If NOISE_FLOODING_DECRYPT is set, we flood the decryption bits with noise.
 */

#define PROFILE

#include "cryptocontext.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "scheme/ckksrns/ckksrns-pke.h"

namespace lbcrypto {

DecryptResult PKECKKSRNS::Decrypt(ConstCiphertext<DCRTPoly> ciphertext, const PrivateKey<DCRTPoly> privateKey,
                                  NativePoly* plaintext) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());
    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    DCRTPoly b                      = DecryptCore(cv, privateKey);
    if (cryptoParams->GetDecryptionNoiseMode() == NOISE_FLOODING_DECRYPT &&
        cryptoParams->GetExecutionMode() == EXEC_EVALUATION) {
        auto dgg = cryptoParams->GetFloodingDiscreteGaussianGenerator();
        DCRTPoly noise(dgg, cv[0].GetParams(), Format::EVALUATION);
        b += noise;
    }

    b.SetFormat(Format::COEFFICIENT);
    const size_t sizeQl = b.GetParams()->GetParams().size();

    if (sizeQl != 1) {
        OPENFHE_THROW(
            "sizeQl " + std::to_string(sizeQl) +
            "!= 1. If sizeQl = 0, consider increasing the depth. If sizeQl > 1, check parameters (this is unsupported for NativePoly).");
    }

    *plaintext = b.GetElementAtIndex(0);

    return DecryptResult(plaintext->GetLength());
}

DecryptResult PKECKKSRNS::Decrypt(ConstCiphertext<DCRTPoly> ciphertext, const PrivateKey<DCRTPoly> privateKey,
                                  Poly* plaintext) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());
    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    DCRTPoly b                      = DecryptCore(cv, privateKey);
    if (cryptoParams->GetDecryptionNoiseMode() == NOISE_FLOODING_DECRYPT &&
        cryptoParams->GetExecutionMode() == EXEC_EVALUATION) {
        auto dgg = cryptoParams->GetFloodingDiscreteGaussianGenerator();
        DCRTPoly noise(dgg, cv[0].GetParams(), Format::EVALUATION);
        b += noise;
    }

    b.SetFormat(Format::COEFFICIENT);
    const size_t sizeQl = b.GetParams()->GetParams().size();

    if (sizeQl == 0)
        OPENFHE_THROW("Decryption failure: No towers left; consider increasing the depth.");

    if (sizeQl == 1) {
        *plaintext = Poly(b.GetElementAtIndex(0), Format::COEFFICIENT);
    }
    else {
        *plaintext = b.CRTInterpolate();
    }

    return DecryptResult(plaintext->GetLength());
}

}  // namespace lbcrypto
