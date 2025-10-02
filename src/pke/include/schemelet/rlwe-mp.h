//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2025, NJIT, Duality Technologies Inc. and other contributors
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

#include "openfhe.h"

#include <memory>
#include <vector>

namespace lbcrypto {

class SchemeletRLWEMP {
    using DggType = typename DCRTPoly::DggType;
    using DugType = typename DCRTPoly::DugType;

public:
    ~SchemeletRLWEMP() = default;

    static std::shared_ptr<ILDCRTParams<DCRTPoly::Integer>> GetElementParams(const PrivateKey<DCRTPoly>& privateKey,
                                                                             uint32_t level = 0);

    static std::vector<Poly> EncryptCoeff(std::vector<int64_t> input, const BigInteger& Q, const BigInteger& p,
                                          const PrivateKey<DCRTPoly>& privateKey,
                                          const std::shared_ptr<ILDCRTParams<DCRTPoly::Integer>>& elementParams,
                                          bool bitReverse = false);

    static std::vector<int64_t> DecryptCoeff(const std::vector<Poly>& input, const BigInteger& Q, const BigInteger& p,
                                             const PrivateKey<DCRTPoly>& privateKey,
                                             const std::shared_ptr<ILDCRTParams<DCRTPoly::Integer>>& elementParams,
                                             uint32_t numSlots, uint32_t length = 0, bool bitReverse = false);

    static void ModSwitch(std::vector<Poly>& input, const BigInteger& Q1, const BigInteger& Q2);

    static Ciphertext<DCRTPoly> ConvertRLWEToCKKS(const CryptoContextImpl<DCRTPoly>& cc,
                                                  const std::vector<Poly>& coeffs, const PublicKey<DCRTPoly>& pubKey,
                                                  const BigInteger& Bigq, uint32_t slots, uint32_t level = 0);

    static std::vector<Poly> ConvertCKKSToRLWE(ConstCiphertext<DCRTPoly>& ctxt, const BigInteger& Q);

    static BigInteger GetQPrime(const PublicKey<DCRTPoly>& pubKey, uint32_t lvls);
};

}  // namespace lbcrypto
