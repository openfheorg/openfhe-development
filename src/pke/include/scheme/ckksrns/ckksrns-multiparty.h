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

#ifndef LBCRYPTO_CRYPTO_CKKSRNS_MULTIPARTY_H
#define LBCRYPTO_CRYPTO_CKKSRNS_MULTIPARTY_H

#include "schemerns/rns-multiparty.h"
#include "ckksrns-cryptoparameters.h"

#include <string>
#include <vector>
#include <memory>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {
class MultipartyCKKSRNS : public MultipartyRNS {
public:
    virtual ~MultipartyCKKSRNS() {}

    DecryptResult MultipartyDecryptFusion(const std::vector<Ciphertext<DCRTPoly>>& ciphertextVec,
                                          Poly* plaintext) const override;

    DecryptResult MultipartyDecryptFusion(const std::vector<Ciphertext<DCRTPoly>>& ciphertextVec,
                                          NativePoly* plaintext) const override;

    Ciphertext<DCRTPoly> IntMPBootAdjustScale(ConstCiphertext<DCRTPoly> ciphertext) const override;

    Ciphertext<DCRTPoly> IntMPBootRandomElementGen(std::shared_ptr<CryptoParametersCKKSRNS> params,
                                                   const PublicKey<DCRTPoly> publicKey) const override;

    std::vector<Ciphertext<DCRTPoly>> IntMPBootDecrypt(const PrivateKey<DCRTPoly> privateKey,
                                                       ConstCiphertext<DCRTPoly> ciphertext,
                                                       ConstCiphertext<DCRTPoly> a) const override;

    std::vector<Ciphertext<DCRTPoly>> IntMPBootAdd(
        std::vector<std::vector<Ciphertext<DCRTPoly>>>& sharesPairVec) const override;

    Ciphertext<DCRTPoly> IntMPBootEncrypt(const PublicKey<DCRTPoly> publicKey,
                                          const std::vector<Ciphertext<DCRTPoly>>& sharesPair,
                                          ConstCiphertext<DCRTPoly> a,
                                          ConstCiphertext<DCRTPoly> ciphertext) const override;

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {}

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {}

    std::string SerializedObjectName() const {
        return "MultipartyCKKSRNS";
    }
};

}  // namespace lbcrypto

#endif
