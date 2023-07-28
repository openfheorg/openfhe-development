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

#ifndef LBCRYPTO_CRYPTO_BFVRNS_LEVELEDSHE_H
#define LBCRYPTO_CRYPTO_BFVRNS_LEVELEDSHE_H

#include "schemerns/rns-leveledshe.h"

#include <string>
#include <map>
#include <memory>
#include <vector>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

class LeveledSHEBFVRNS : public LeveledSHERNS {
public:
    virtual ~LeveledSHEBFVRNS() {}

    using LeveledSHERNS::EvalAddInPlace;

    /**
   * Virtual function to define the interface for homomorphic addition of
   * ciphertexts.
   *
   * @param ciphertext the input ciphertext.
   * @param plaintext the input plaintext.
   */
    void EvalAddInPlace(Ciphertext<DCRTPoly>& ciphertext, ConstPlaintext plaintext) const override;

    using LeveledSHERNS::EvalSubInPlace;

    /**
   * Virtual function to define the interface for homomorphic addition of
   * ciphertexts.
   *
   * @param ciphertext the input ciphertext.
   * @param plaintext the input plaintext.
   */
    void EvalSubInPlace(Ciphertext<DCRTPoly>& ciphertext, ConstPlaintext plaintext) const override;

    using LeveledSHERNS::EvalMult;
    using LeveledSHERNS::EvalMultInPlace;

    using LeveledSHERNS::EvalSquare;
    using LeveledSHERNS::EvalSquareInPlace;

    /**
   * Virtual function to define the interface for multiplicative homomorphic
   * evaluation of ciphertext.
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return the new ciphertext.
   */
    Ciphertext<DCRTPoly> EvalMult(ConstCiphertext<DCRTPoly> ciphertext1,
                                  ConstCiphertext<DCRTPoly> ciphertext2) const override;

    Ciphertext<DCRTPoly> EvalSquare(ConstCiphertext<DCRTPoly> ciphertext) const override;

    Ciphertext<DCRTPoly> EvalMult(ConstCiphertext<DCRTPoly> ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2,
                                  const EvalKey<DCRTPoly> evalKey) const override;

    void EvalMultInPlace(Ciphertext<DCRTPoly>& ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2,
                         const EvalKey<DCRTPoly> evalKey) const override;

    Ciphertext<DCRTPoly> EvalSquare(ConstCiphertext<DCRTPoly> ciphertext,
                                    const EvalKey<DCRTPoly> evalKey) const override;

    void EvalSquareInPlace(Ciphertext<DCRTPoly>& ciphertext1, const EvalKey<DCRTPoly> evalKey) const override;

    void EvalMultCoreInPlace(Ciphertext<DCRTPoly>& ciphertext, const NativeInteger& constant) const;

    /////////////////////////////////////
    // AUTOMORPHISM
    /////////////////////////////////////

    Ciphertext<DCRTPoly> EvalAutomorphism(ConstCiphertext<DCRTPoly> ciphertext, usint i,
                                          const std::map<usint, EvalKey<DCRTPoly>>& evalKeyMap,
                                          CALLER_INFO_ARGS_HDR) const override;

    Ciphertext<DCRTPoly> EvalFastRotation(ConstCiphertext<DCRTPoly> ciphertext, const usint index, const usint m,
                                          const std::shared_ptr<std::vector<DCRTPoly>> digits) const override;

    std::shared_ptr<std::vector<DCRTPoly>> EvalFastRotationPrecompute(
        ConstCiphertext<DCRTPoly> ciphertext) const override;

    usint FindAutomorphismIndex(usint index, usint m) const override;

    Ciphertext<DCRTPoly> Compress(ConstCiphertext<DCRTPoly> ciphertext, size_t towersLeft) const override;

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
        return "LeveledSHEBFVRNS";
    }

private:
    void RelinearizeCore(Ciphertext<DCRTPoly>& ciphertext, const EvalKey<DCRTPoly> evalKey) const;
};
}  // namespace lbcrypto

#endif
