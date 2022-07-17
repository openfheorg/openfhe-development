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

#ifndef LBCRYPTO_CRYPTO_CKKSRNS_ADVANCEDSHE_H
#define LBCRYPTO_CRYPTO_CKKSRNS_ADVANCEDSHE_H

#include "schemerns/rns-advancedshe.h"

#include <vector>
#include <string>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

class AdvancedSHECKKSRNS : public AdvancedSHERNS {
public:
    virtual ~AdvancedSHECKKSRNS() {}

    //------------------------------------------------------------------------------
    // LINEAR WEIGHTED SUM
    //------------------------------------------------------------------------------

    Ciphertext<DCRTPoly> EvalLinearWSum(std::vector<ConstCiphertext<DCRTPoly>>& ciphertexts,
                                        const std::vector<double>& constants) const override;

    Ciphertext<DCRTPoly> EvalLinearWSumMutable(std::vector<Ciphertext<DCRTPoly>>& ciphertexts,
                                               const std::vector<double>& constants) const override;

    //------------------------------------------------------------------------------
    // EVAL POLYNOMIAL
    //------------------------------------------------------------------------------

    Ciphertext<DCRTPoly> EvalPoly(ConstCiphertext<DCRTPoly> ciphertext,
                                  const std::vector<double>& coefficients) const override;

    Ciphertext<DCRTPoly> EvalPolyLinear(ConstCiphertext<DCRTPoly> x,
                                        const std::vector<double>& coefficients) const override;

    Ciphertext<DCRTPoly> InnerEvalPolyPS(ConstCiphertext<DCRTPoly> x, const std::vector<double>& coefficients,
                                         uint32_t k, uint32_t m, std::vector<Ciphertext<DCRTPoly>>& powers,
                                         std::vector<Ciphertext<DCRTPoly>>& powers2) const;

    Ciphertext<DCRTPoly> EvalPolyPS(ConstCiphertext<DCRTPoly> x,
                                    const std::vector<double>& coefficients) const override;

    //------------------------------------------------------------------------------
    // EVAL CHEBYSHEV SERIES
    //------------------------------------------------------------------------------

    Ciphertext<DCRTPoly> EvalChebyshevSeries(ConstCiphertext<DCRTPoly> ciphertext,
                                             const std::vector<double>& coefficients, double a,
                                             double b) const override;

    Ciphertext<DCRTPoly> EvalChebyshevSeriesLinear(ConstCiphertext<DCRTPoly> ciphertext,
                                                   const std::vector<double>& coefficients, double a,
                                                   double b) const override;

    Ciphertext<DCRTPoly> InnerEvalChebyshevPS(ConstCiphertext<DCRTPoly> x, const std::vector<double>& coefficients,
                                              uint32_t k, uint32_t m, std::vector<Ciphertext<DCRTPoly>>& T,
                                              std::vector<Ciphertext<DCRTPoly>>& T2) const;

    Ciphertext<DCRTPoly> EvalChebyshevSeriesPS(ConstCiphertext<DCRTPoly> ciphertext,
                                               const std::vector<double>& coefficients, double a,
                                               double b) const override;

    //------------------------------------------------------------------------------
    // EVAL LINEAR TRANSFORMATION
    //------------------------------------------------------------------------------

    //------------------------------------------------------------------------------
    // SERIALIZATION
    //------------------------------------------------------------------------------

    template <class Archive>
    void save(Archive& ar) const {
        ar(cereal::base_class<AdvancedSHERNS>(this));
    }

    template <class Archive>
    void load(Archive& ar) {
        ar(cereal::base_class<AdvancedSHERNS>(this));
    }

    std::string SerializedObjectName() const {
        return "AdvancedSHECKKSRNS";
    }
};

}  // namespace lbcrypto

#endif
