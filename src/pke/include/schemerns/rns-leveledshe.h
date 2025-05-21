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

#ifndef LBCRYPTO_CRYPTO_RNS_LEVELEDSHE_H
#define LBCRYPTO_CRYPTO_RNS_LEVELEDSHE_H

#include "lattice/lat-hal.h"

#include "schemebase/base-leveledshe.h"

#include <string>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Abstract interface class for LBC SHE algorithms
 * @tparam Element a ring element.
 */
class LeveledSHERNS : public LeveledSHEBase<DCRTPoly> {
public:
    virtual ~LeveledSHERNS() {}

    /////////////////////////////////////////
    // SHE NEGATION
    /////////////////////////////////////////

    /////////////////////////////////////////
    // SHE ADDITION
    /////////////////////////////////////////

    using LeveledSHEBase<DCRTPoly>::EvalAdd;
    using LeveledSHEBase<DCRTPoly>::EvalAddInPlace;
    using LeveledSHEBase<DCRTPoly>::EvalAddMutable;
    using LeveledSHEBase<DCRTPoly>::EvalAddMutableInPlace;

    /**
   * Virtual function to define the interface for homomorphic addition of
   * ciphertexts.
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return the new ciphertext.
   */
    Ciphertext<DCRTPoly> EvalAdd(ConstCiphertext<DCRTPoly> ciphertext1,
                                 ConstCiphertext<DCRTPoly> ciphertext2) const override;

    /**
   * Virtual function to define the interface for in-place homomorphic addition
   * of ciphertexts.
   *
   * @param ciphertext1 the input/output ciphertext.
   * @param ciphertext2 the input ciphertext.
   */
    void EvalAddInPlace(Ciphertext<DCRTPoly>& ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2) const override;

    /**
   * Virtual function to define the interface for homomorphic addition of
   * ciphertexts. This is the mutable version - input ciphertexts may change
   * (automatically rescaled, or towers dropped).
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return the new ciphertext.
   */
    Ciphertext<DCRTPoly> EvalAddMutable(Ciphertext<DCRTPoly>& ciphertext1,
                                        Ciphertext<DCRTPoly>& ciphertext2) const override;

    void EvalAddMutableInPlace(Ciphertext<DCRTPoly>& ciphertext1, Ciphertext<DCRTPoly>& ciphertext2) const override;

    /**
   * Virtual function to define the interface for homomorphic addition of
   * ciphertexts.
   *
   * @param ciphertext the input ciphertext.
   * @param plaintext the input plaintext.
   * @return the new ciphertext.
   */
    Ciphertext<DCRTPoly> EvalAdd(ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const override;

    /**
   * Virtual function to define the interface for homomorphic addition of
   * ciphertexts.
   *
   * @param ciphertext the input ciphertext.
   * @param plaintext the input plaintext.
   */
    void EvalAddInPlace(Ciphertext<DCRTPoly>& ciphertext, ConstPlaintext plaintext) const override;

    /**
   * Virtual function to define the interface for homomorphic addition of
   * ciphertexts. This is the mutable version - input ciphertext may change
   * (automatically rescaled, or towers dropped).
   *
   * @param ciphertext the input ciphertext.
   * @param plaintext the input plaintext.
   * @return the new ciphertext.
   */
    Ciphertext<DCRTPoly> EvalAddMutable(Ciphertext<DCRTPoly>& ciphertext, Plaintext plaintext) const override;

    /**
   * Virtual function to define the interface for homomorphic addition of
   * ciphertexts. This is the mutable version - input ciphertext may change
   * (automatically rescaled, or towers dropped).
   *
   * @param ciphertext the input ciphertext.
   * @param plaintext the input plaintext.
   * @return the new ciphertext.
   */
    void EvalAddMutableInPlace(Ciphertext<DCRTPoly>& ciphertext, Plaintext plaintext) const override;

    /////////////////////////////////////////
    // SHE SUBTRACTION
    /////////////////////////////////////////

    using LeveledSHEBase<DCRTPoly>::EvalSub;
    using LeveledSHEBase<DCRTPoly>::EvalSubInPlace;
    using LeveledSHEBase<DCRTPoly>::EvalSubMutable;
    using LeveledSHEBase<DCRTPoly>::EvalSubMutableInPlace;

    /**
   * Virtual function to define the interface for homomorphic subtraction of
   * ciphertexts.
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return the new ciphertext.
   */
    Ciphertext<DCRTPoly> EvalSub(ConstCiphertext<DCRTPoly> ciphertext1,
                                 ConstCiphertext<DCRTPoly> ciphertext2) const override;

    /**
   * Virtual function to define the interface for homomorphic subtraction of
   * ciphertexts.
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   */
    void EvalSubInPlace(Ciphertext<DCRTPoly>& ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2) const override;

    /**
   * Virtual function to define the interface for homomorphic subtraction of
   * ciphertexts. This is the mutable version - input ciphertext may change
   * (automatically rescaled, or towers dropped).
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return the new ciphertext.
   */
    Ciphertext<DCRTPoly> EvalSubMutable(Ciphertext<DCRTPoly>& ciphertext1,
                                        Ciphertext<DCRTPoly>& ciphertext2) const override;

    /**
   * Virtual function to define the interface for homomorphic subtraction of
   * ciphertexts. This is the mutable version - input ciphertext may change
   * (automatically rescaled, or towers dropped).
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return the new ciphertext.
   */
    void EvalSubMutableInPlace(Ciphertext<DCRTPoly>& ciphertext1, Ciphertext<DCRTPoly>& ciphertext2) const override;

    /**
   * Virtual function to define the interface for homomorphic subtraction of
   * ciphertexts.
   *
   * @param ciphertext the input ciphertext.
   * @param plaintext the input plaintext.
   * @return the new ciphertext.
   */
    Ciphertext<DCRTPoly> EvalSub(ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const override;

    void EvalSubInPlace(Ciphertext<DCRTPoly>& ciphertext, ConstPlaintext plaintext) const override;

    /**
   * Virtual function to define the interface for homomorphic subtraction of
   * ciphertexts. This is the mutable version - input ciphertext may change
   * (automatically rescaled, or towers dropped).
   *
   * @param ciphertext the input ciphertext.
   * @param plaintext the input plaintext.
   * @return the new ciphertext.
   */
    Ciphertext<DCRTPoly> EvalSubMutable(Ciphertext<DCRTPoly>& ciphertext, Plaintext plaintext) const override;

    /**
   * Virtual function to define the interface for homomorphic subtraction of
   * ciphertexts. This is the mutable version - input ciphertext may change
   * (automatically rescaled, or towers dropped).
   *
   * @param ciphertext the input ciphertext.
   * @param plaintext the input plaintext.
   * @return the new ciphertext.
   */
    void EvalSubMutableInPlace(Ciphertext<DCRTPoly>& ciphertext, Plaintext plaintext) const override;

    /////////////////////////////////////////
    // SHE MULTIPLICATION
    /////////////////////////////////////////

    using LeveledSHEBase<DCRTPoly>::EvalMult;
    using LeveledSHEBase<DCRTPoly>::EvalMultInPlace;
    using LeveledSHEBase<DCRTPoly>::EvalMultMutable;
    using LeveledSHEBase<DCRTPoly>::EvalMultMutableInPlace;

    Ciphertext<DCRTPoly> EvalMult(ConstCiphertext<DCRTPoly> ciphertext1,
                                  ConstCiphertext<DCRTPoly> ciphertext2) const override;

    Ciphertext<DCRTPoly> EvalMultMutable(Ciphertext<DCRTPoly>& ciphertext1,
                                         Ciphertext<DCRTPoly>& ciphertext2) const override;

    Ciphertext<DCRTPoly> EvalSquare(ConstCiphertext<DCRTPoly> ciphertext) const override;

    Ciphertext<DCRTPoly> EvalSquareMutable(Ciphertext<DCRTPoly>& ciphertext) const override;

    Ciphertext<DCRTPoly> EvalMult(ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const override;

    void EvalMultInPlace(Ciphertext<DCRTPoly>& ciphertext, ConstPlaintext plaintext) const override;

    Ciphertext<DCRTPoly> EvalMultMutable(Ciphertext<DCRTPoly>& ciphertext, Plaintext plaintext) const override;

    void EvalMultMutableInPlace(Ciphertext<DCRTPoly>& ciphertext, Plaintext plaintext) const override;

    Ciphertext<DCRTPoly> MultByMonomial(ConstCiphertext<DCRTPoly> ciphertext, usint power) const override;

    void MultByMonomialInPlace(Ciphertext<DCRTPoly>& ciphertext, usint power) const override;

    /////////////////////////////////////////
    // SHE AUTOMORPHISM
    /////////////////////////////////////////

    /////////////////////////////////////////
    // SHE LEVELED Mod Reduce
    /////////////////////////////////////////

    Ciphertext<DCRTPoly> ModReduce(ConstCiphertext<DCRTPoly> ciphertext, size_t levels) const override;

    /**
   * Method for In-place Modulus Reduction.
   *
   * @param &cipherText Ciphertext to perform mod reduce on.
   * @param levels the number of towers to drop.
   */
    void ModReduceInPlace(Ciphertext<DCRTPoly>& ciphertext, size_t levels) const override;

    /////////////////////////////////////////
    // SHE LEVELED Level Reduce
    /////////////////////////////////////////

    Ciphertext<DCRTPoly> LevelReduce(ConstCiphertext<DCRTPoly> ciphertext, const EvalKey<DCRTPoly> evalKey,
                                     size_t levels) const override;

    void LevelReduceInPlace(Ciphertext<DCRTPoly>& ciphertext, const EvalKey<DCRTPoly> evalKey,
                            size_t levels) const override;

    /////////////////////////////////////////
    // SHE LEVELED Compress
    /////////////////////////////////////////

    Ciphertext<DCRTPoly> Compress(ConstCiphertext<DCRTPoly> ciphertext, size_t towersLeft) const override;

    ////////////////////////////////////////
    // SHE LEVELED ComposedEvalMult
    ////////////////////////////////////////

    using LeveledSHEBase<DCRTPoly>::ComposedEvalMult;

    Ciphertext<DCRTPoly> ComposedEvalMult(ConstCiphertext<DCRTPoly> ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2,
                                          const EvalKey<DCRTPoly> evalKey) const override;

protected:
    /////////////////////////////////////
    // RNS Core
    /////////////////////////////////////

    /**
   * Method for rescaling.
   *
   * @param cipherText is the ciphertext to perform modreduce on.
   * @param levels the number of towers to drop.
   * @return ciphertext after the modulus reduction performed.
   */
    Ciphertext<DCRTPoly> ModReduceInternal(ConstCiphertext<DCRTPoly> ciphertext, size_t levels) const override;

    /**
   * Method for rescaling in-place.
   *
   * @param cipherText is the ciphertext to perform modreduce on.
   * @param levels the number of towers to drop.
   * @details \p cipherText will have modulus reduction performed in-place.
   */
    void ModReduceInternalInPlace(Ciphertext<DCRTPoly>& ciphertext, size_t levels) const override {
        OPENFHE_THROW("ModReduceInternalInPlace is not supported for this scheme");
    }

    /**
   * Method for Level Reduction in the CKKS scheme. It just drops "levels"
   * number of the towers of the ciphertext without changing the underlying
   * plaintext.
   *
   * @param cipherText1 is the original ciphertext to be level reduced.
   * @param levels the number of towers to drop.
   * @return resulting ciphertext.
   */
    Ciphertext<DCRTPoly> LevelReduceInternal(ConstCiphertext<DCRTPoly> ciphertext, size_t levels) const override;

    /**
   * Method for in-place Level Reduction in the CKKS scheme. It just drops
   * "levels" number of the towers of the ciphertext without changing the
   * underlying plaintext.
   *
   * @param cipherText1 is the ciphertext to be level reduced in-place
   * @param linearKeySwitchHint not used in the CKKS scheme.
   * @param levels the number of towers to drop.
   */
    void LevelReduceInternalInPlace(Ciphertext<DCRTPoly>& ciphertext, size_t levels) const override {
        OPENFHE_THROW("LevelReduceInternalInPlace is not supported for this scheme");
    }

    void AdjustLevelsInPlace(Ciphertext<DCRTPoly>& ciphertext1, Ciphertext<DCRTPoly>& ciphertext2) const override;

    void AdjustForAddOrSubInPlace(Ciphertext<DCRTPoly>& ciphertext1, Ciphertext<DCRTPoly>& ciphertext2) const override;

    void AdjustForMultInPlace(Ciphertext<DCRTPoly>& ciphertext1, Ciphertext<DCRTPoly>& ciphertext2) const override;

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar) const {
        ar(cereal::base_class<LeveledSHEBase<DCRTPoly>>(this));
    }

    template <class Archive>
    void load(Archive& ar) {
        ar(cereal::base_class<LeveledSHEBase<DCRTPoly>>(this));
    }

    std::string SerializedObjectName() const {
        return "LeveledSHERNS";
    }
};

}  // namespace lbcrypto

#endif
