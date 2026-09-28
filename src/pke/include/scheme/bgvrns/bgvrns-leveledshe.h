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

#ifndef SRC_PKE_INCLUDE_SCHEME_BGVRNS_BGVRNS_LEVELEDSHE_H_
#define SRC_PKE_INCLUDE_SCHEME_BGVRNS_BGVRNS_LEVELEDSHE_H_

#include <cstdint>
#include <string>

#include "schemerns/rns-leveledshe.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief BGV implementation of the leveled SHE operations in the RNS representation: modulus switching
 * with the plaintext-modulus correction and the level/depth adjustments that track the scaling factor
 * modulo t for FLEXIBLEAUTO and FLEXIBLEAUTOEXT.
 */
class LeveledSHEBGVRNS : public LeveledSHERNS {
  public:
    virtual ~LeveledSHEBGVRNS() = default;

    /////////////////////////////////////
    // AUTOMORPHISM
    /////////////////////////////////////

    /**
     * Finds the automorphism index corresponding to a rotation index for a power-of-two cyclotomic order.
     *
     * @param index the rotation index.
     * @param m the cyclotomic order.
     * @return the automorphism index.
     */
    uint32_t FindAutomorphismIndex(uint32_t index, uint32_t m) const override;

    /////////////////////////////////////
    // Mod Reduce
    /////////////////////////////////////

    /**
     * Method for BGV modulus switching in-place: drops the last levels towers, multiplying by the inverses
     * of the dropped moduli and correcting the result so that it stays congruent modulo the plaintext
     * modulus t. The level is increased and the noise scale degree decreased by levels; for FLEXIBLEAUTO and
     * FLEXIBLEAUTOEXT the scaling factor modulo t is divided by the dropped moduli.
     *
     * @param ciphertext is the ciphertext to perform modreduce on.
     * @param levels the number of towers to drop (must be smaller than the number of towers).
     * @details \p ciphertext will have modulus reduction performed in-place.
     */
    void ModReduceInternalInPlace(Ciphertext<DCRTPoly>& ciphertext, size_t levels) const override;

    /**
     * Drops the last levels towers of the ciphertext without changing the underlying plaintext and increases
     * the level accordingly.
     *
     * @param ciphertext is the ciphertext to be level reduced in-place.
     * @param levels the number of towers to drop.
     */
    void LevelReduceInternalInPlace(Ciphertext<DCRTPoly>& ciphertext, size_t levels) const override;

    /**
     * Multiplies all polynomials of the ciphertext by an integer constant and increases the noise scale degree
     * by 1; for FLEXIBLEAUTO and FLEXIBLEAUTOEXT the scaling factor modulo t is multiplied by the constant.
     *
     * @param ciphertext the input/output ciphertext.
     * @param constant the integer to multiply by.
     */
    void EvalMultCoreInPlace(Ciphertext<DCRTPoly>& ciphertext, NativeInteger constant) const;

    /**
     * In-place homomorphic multiplication of a ciphertext by a plaintext; for FLEXIBLEAUTO and FLEXIBLEAUTOEXT
     * the scaling factor modulo t of the result is set to the square of the ciphertext scaling factor.
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    void EvalMultInPlace(Ciphertext<DCRTPoly>& ciphertext, ConstPlaintext& plaintext) const override;

    /**
     * Brings two ciphertexts to the same level and noise scale degree for addition or subtraction. The
     * ciphertext at the lower level is multiplied by the ratio of the scaling factors (modulo t) and modulus
     * switched / level reduced as needed; at the same level the ciphertext of lower depth is multiplied by its
     * own scaling factor.
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input/output ciphertext.
     */
    void AdjustLevelsAndDepthInPlace(Ciphertext<DCRTPoly>& ciphertext1,
                                     Ciphertext<DCRTPoly>& ciphertext2) const override;

    /**
     * Brings two ciphertexts to the same level and to noise scale degree 1 for multiplication: calls
     * AdjustLevelsAndDepthInPlace() and then modulus switches both ciphertexts once if they are at degree 2.
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input/output ciphertext.
     */
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

#endif  // SRC_PKE_INCLUDE_SCHEME_BGVRNS_BGVRNS_LEVELEDSHE_H_
