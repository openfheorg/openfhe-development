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

#ifndef LBCRYPTO_CRYPTO_BGVRNS_LEVELEDSHE_H
#define LBCRYPTO_CRYPTO_BGVRNS_LEVELEDSHE_H

#include "schemerns/rns-leveledshe.h"

#include <string>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

class LeveledSHEBGVRNS : public LeveledSHERNS {
public:
    virtual ~LeveledSHEBGVRNS() {}

    /////////////////////////////////////
    // AUTOMORPHISM
    /////////////////////////////////////

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

    void LevelReduceInternalInPlace(Ciphertext<DCRTPoly>& ciphertext, size_t levels) const override;

    void EvalMultCoreInPlace(Ciphertext<DCRTPoly>& ciphertext, const NativeInteger& constant) const;

    void AdjustLevelsAndDepthInPlace(Ciphertext<DCRTPoly>& ciphertext1,
                                     Ciphertext<DCRTPoly>& ciphertext2) const override;

    void AdjustLevelsAndDepthToOneInPlace(Ciphertext<DCRTPoly>& ciphertext1,
                                          Ciphertext<DCRTPoly>& ciphertext2) const override;

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
        return "LeveledSHEBGVRNS";
    }
};

}  // namespace lbcrypto

#endif
