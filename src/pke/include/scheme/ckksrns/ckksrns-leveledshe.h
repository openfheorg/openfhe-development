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

#ifndef LBCRYPTO_CRYPTO_CKKSRNS_LEVELEDSHE_H
#define LBCRYPTO_CRYPTO_CKKSRNS_LEVELEDSHE_H

#include "schemerns/rns-leveledshe.h"

#include <memory>
#include <string>
#include <map>
#include <vector>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

class LeveledSHECKKSRNS : public LeveledSHERNS {
public:
    virtual ~LeveledSHECKKSRNS() {}

    /////////////////////////////////////////
    // SHE ADDITION
    /////////////////////////////////////////

    using LeveledSHERNS::EvalAdd;
    using LeveledSHERNS::EvalAddInPlace;

    /////////////////////////////////////////
    // SHE ADDITION PLAINTEXT
    /////////////////////////////////////////

    /////////////////////////////////////////
    // SHE ADDITION CONSTANT
    /////////////////////////////////////////

    Ciphertext<DCRTPoly> EvalAdd(ConstCiphertext<DCRTPoly> ciphertext, double operand) const override;

    void EvalAddInPlace(Ciphertext<DCRTPoly>& ciphertext, double operand) const override;

    Ciphertext<DCRTPoly> EvalAdd(ConstCiphertext<DCRTPoly> ciphertext, std::complex<double> operand) const override;

    void EvalAddInPlace(Ciphertext<DCRTPoly>& ciphertext, std::complex<double> operand) const override;

    /////////////////////////////////////////
    // SHE SUBTRACTION
    /////////////////////////////////////////

    /////////////////////////////////////////
    // SHE SUBTRACTION PLAINTEXT
    /////////////////////////////////////////

    /////////////////////////////////////////
    // SHE SUBTRACTION CONSTANT
    /////////////////////////////////////////

    using LeveledSHERNS::EvalSub;
    using LeveledSHERNS::EvalSubInPlace;

    Ciphertext<DCRTPoly> EvalSub(ConstCiphertext<DCRTPoly> ciphertext, double operand) const override;

    void EvalSubInPlace(Ciphertext<DCRTPoly>& ciphertext, double operand) const override;

    /////////////////////////////////////////
    // SHE MULTIPLICATION
    /////////////////////////////////////////

    /////////////////////////////////////////
    // SHE MULTIPLICATION PLAINTEXT
    /////////////////////////////////////////

    /////////////////////////////////////////
    // SHE MULTIPLICATION CONSTANT
    /////////////////////////////////////////

    using LeveledSHEBase<DCRTPoly>::EvalMult;
    using LeveledSHEBase<DCRTPoly>::EvalMultInPlace;

    Ciphertext<DCRTPoly> EvalMult(ConstCiphertext<DCRTPoly> ciphertext, double operand) const override;

    void EvalMultInPlace(Ciphertext<DCRTPoly>& ciphertext, double operand) const override;
    void EvalMultInPlace(Ciphertext<DCRTPoly>& ciphertext, ConstPlaintext plaintext) const override;

    Ciphertext<DCRTPoly> EvalMult(ConstCiphertext<DCRTPoly> ciphertext, std::complex<double> operand) const override;

    void EvalMultInPlace(Ciphertext<DCRTPoly>& ciphertext, std::complex<double> operand) const override;

    Ciphertext<DCRTPoly> MultByInteger(ConstCiphertext<DCRTPoly> ciphertext, uint64_t integer) const override;

    void MultByIntegerInPlace(Ciphertext<DCRTPoly>& ciphertext, uint64_t integer) const override;

    /////////////////////////////////////
    // AUTOMORPHISM
    /////////////////////////////////////

    Ciphertext<DCRTPoly> EvalFastRotationExt(ConstCiphertext<DCRTPoly> ciphertext, usint index,
                                             const std::shared_ptr<std::vector<DCRTPoly>> digits, bool addFirst,
                                             const std::map<usint, EvalKey<DCRTPoly>>& evalKeys) const override;

    usint FindAutomorphismIndex(usint index, usint m) const override;

    /////////////////////////////////////
    // Mod Reduce
    /////////////////////////////////////

    /**
   * Method for scaling in-place.
   *
   * @param cipherText is the ciphertext to perform modreduce on.
   * @param levels the number of towers to drop.
   * @details \p cipherText will have modulus reduction performed in-place.
   */
    void ModReduceInternalInPlace(Ciphertext<DCRTPoly>& ciphertext, size_t levels) const override;

    /////////////////////////////////////
    // Level Reduce
    /////////////////////////////////////

    /**
   * Method for in-place Level Reduction in the CKKS scheme. It just drops
   * "levels" number of the towers of the ciphertext without changing the
   * underlying plaintext.
   *
   * @param cipherText1 is the ciphertext to be level reduced in-place
   * @param levels the number of towers to drop.
   */
    void LevelReduceInternalInPlace(Ciphertext<DCRTPoly>& ciphertext, size_t levels) const override;

    /////////////////////////////////////
    // Compress
    /////////////////////////////////////

    /////////////////////////////////////
    // CKKS Core
    /////////////////////////////////////

    void EvalMultCoreInPlace(Ciphertext<DCRTPoly>& ciphertext, double operand) const;

    void EvalMultCoreInPlace(Ciphertext<DCRTPoly>& ciphertext, std::complex<double> operand) const;

    void AdjustLevelsAndDepthInPlace(Ciphertext<DCRTPoly>& ciphertext1,
                                     Ciphertext<DCRTPoly>& ciphertext2) const override;

    void AdjustLevelsAndDepthToOneInPlace(Ciphertext<DCRTPoly>& ciphertext1,
                                          Ciphertext<DCRTPoly>& ciphertext2) const override;

    std::vector<DCRTPoly::Integer> GetElementForEvalAddOrSub(ConstCiphertext<DCRTPoly> ciphertext,
                                                             double operand) const;

    std::vector<DCRTPoly::Integer> GetElementForEvalMult(ConstCiphertext<DCRTPoly> ciphertext, double operand) const;

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar) const {
        ar(cereal::base_class<LeveledSHERNS>(this));
    }

    template <class Archive>
    void load(Archive& ar) {
        ar(cereal::base_class<LeveledSHERNS>(this));
    }

    std::string SerializedObjectName() const {
        return "LeveledSHECKKSRNS";
    }
};

}  // namespace lbcrypto

#endif
