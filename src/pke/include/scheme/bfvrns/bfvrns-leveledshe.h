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

#ifndef SRC_PKE_INCLUDE_SCHEME_BFVRNS_BFVRNS_LEVELEDSHE_H_
#define SRC_PKE_INCLUDE_SCHEME_BFVRNS_BFVRNS_LEVELEDSHE_H_

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "schemerns/rns-leveledshe.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief BFV implementation of the leveled SHE operations in the RNS representation. Ciphertext-ciphertext
 * multiplication is implemented with the HPS, BEHZ, HPSPOVERQ and HPSPOVERQLEVELED RNS techniques, and the
 * mutable operations are not supported since BFV performs no automatic rescaling.
 */
class LeveledSHEBFVRNS : public LeveledSHERNS {
  public:
    virtual ~LeveledSHEBFVRNS() = default;

    using LeveledSHERNS::EvalAddInPlace;

    /**
     * Virtual function to define the interface for in-place homomorphic addition of
     * a ciphertext and a plaintext.
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    void EvalAddInPlace(Ciphertext<DCRTPoly>& ciphertext, ConstPlaintext& plaintext) const override;

    using LeveledSHERNS::EvalSubInPlace;

    /**
     * Virtual function to define the interface for in-place homomorphic subtraction of
     * a plaintext from a ciphertext.
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    void EvalSubInPlace(Ciphertext<DCRTPoly>& ciphertext, ConstPlaintext& plaintext) const override;

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
    Ciphertext<DCRTPoly> EvalMult(ConstCiphertext<DCRTPoly>& ciphertext1,
                                  ConstCiphertext<DCRTPoly>& ciphertext2) const override;

    /**
     * Homomorphic squaring of a ciphertext without relinearization, using the configured multiplication
     * technique (HPS, BEHZ, HPSPOVERQ or HPSPOVERQLEVELED).
     *
     * @param ciphertext the input ciphertext.
     * @return the new ciphertext with noise scale degree increased by 1.
     */
    Ciphertext<DCRTPoly> EvalSquare(ConstCiphertext<DCRTPoly>& ciphertext) const override;

    /**
     * Homomorphic multiplication of two ciphertexts followed by relinearization with the given key.
     *
     * @param ciphertext1 first input ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @param evalKey the relinearization key.
     * @return the new ciphertext with two polynomials.
     */
    Ciphertext<DCRTPoly> EvalMult(ConstCiphertext<DCRTPoly>& ciphertext1, ConstCiphertext<DCRTPoly>& ciphertext2,
                                  const EvalKey<DCRTPoly> evalKey) const override;

    /**
     * In-place homomorphic multiplication of two ciphertexts followed by relinearization with the given key.
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @param evalKey the relinearization key.
     */
    void EvalMultInPlace(Ciphertext<DCRTPoly>& ciphertext1, ConstCiphertext<DCRTPoly>& ciphertext2,
                         const EvalKey<DCRTPoly> evalKey) const override;

    /**
     * Homomorphic squaring of a ciphertext followed by relinearization with the given key.
     *
     * @param ciphertext the input ciphertext.
     * @param evalKey the relinearization key.
     * @return the new ciphertext with two polynomials.
     */
    Ciphertext<DCRTPoly> EvalSquare(ConstCiphertext<DCRTPoly>& ciphertext,
                                    const EvalKey<DCRTPoly> evalKey) const override;

    /**
     * In-place homomorphic squaring of a ciphertext followed by relinearization with the given key.
     *
     * @param ciphertext1 the input/output ciphertext.
     * @param evalKey the relinearization key.
     */
    void EvalSquareInPlace(Ciphertext<DCRTPoly>& ciphertext1, const EvalKey<DCRTPoly> evalKey) const override;

    /**
     * Multiplies all polynomials of the ciphertext by an integer scalar and increases the noise scale degree
     * by 1.
     *
     * @param ciphertext the input/output ciphertext.
     * @param scalar the integer to multiply by.
     */
    void EvalMultCoreInPlace(Ciphertext<DCRTPoly>& ciphertext, NativeInteger scalar) const;

    // We do not need to support LeveledSHEBFVRNS::Eval*Mutable(InPlace) as no automated adjustment of ciphertexts is
    // typically done in BFV. These functions throw an exception if called
    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext1 first input ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @return never returns.
     */
    Ciphertext<DCRTPoly> EvalMultMutable(Ciphertext<DCRTPoly>& ciphertext1,
                                         Ciphertext<DCRTPoly>& ciphertext2) const override;
    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext1 first input ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @param evalKey the relinearization key.
     * @return never returns.
     */
    Ciphertext<DCRTPoly> EvalMultMutable(Ciphertext<DCRTPoly>& ciphertext1, Ciphertext<DCRTPoly>& ciphertext2,
                                         const EvalKey<DCRTPoly> evalKey) const override;
    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the input plaintext.
     * @return never returns.
     */
    Ciphertext<DCRTPoly> EvalMultMutable(Ciphertext<DCRTPoly>& ciphertext, Plaintext& plaintext) const override;
    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @param evalKey the relinearization key.
     */
    void EvalMultMutableInPlace(Ciphertext<DCRTPoly>& ciphertext1, Ciphertext<DCRTPoly>& ciphertext2,
                                const EvalKey<DCRTPoly> evalKey) const override;
    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    void EvalMultMutableInPlace(Ciphertext<DCRTPoly>& ciphertext, Plaintext& plaintext) const override;

    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext1 first input ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @return never returns.
     */
    Ciphertext<DCRTPoly> EvalAddMutable(Ciphertext<DCRTPoly>& ciphertext1,
                                        Ciphertext<DCRTPoly>& ciphertext2) const override;
    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the input plaintext.
     * @return never returns.
     */
    Ciphertext<DCRTPoly> EvalAddMutable(Ciphertext<DCRTPoly>& ciphertext, Plaintext& plaintext) const override;
    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input ciphertext.
     */
    void EvalAddMutableInPlace(Ciphertext<DCRTPoly>& ciphertext1, Ciphertext<DCRTPoly>& ciphertext2) const override;
    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    void EvalAddMutableInPlace(Ciphertext<DCRTPoly>& ciphertext, Plaintext& plaintext) const override;

    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext1 first input ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @return never returns.
     */
    Ciphertext<DCRTPoly> EvalSubMutable(Ciphertext<DCRTPoly>& ciphertext1,
                                        Ciphertext<DCRTPoly>& ciphertext2) const override;
    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the input plaintext.
     * @return never returns.
     */
    Ciphertext<DCRTPoly> EvalSubMutable(Ciphertext<DCRTPoly>& ciphertext, Plaintext& plaintext) const override;
    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input ciphertext.
     */
    void EvalSubMutableInPlace(Ciphertext<DCRTPoly>& ciphertext1, Ciphertext<DCRTPoly>& ciphertext2) const override;
    /**
     * Not supported in BFV (throws).
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    void EvalSubMutableInPlace(Ciphertext<DCRTPoly>& ciphertext, Plaintext& plaintext) const override;

    /////////////////////////////////////
    // AUTOMORPHISM
    /////////////////////////////////////

    /**
     * Evaluates the automorphism x -> x^i on a ciphertext. The ciphertext is first key switched with the key for
     * index i (which for HPSPOVERQLEVELED includes the modulus reduction to Q_l and the expansion back to Q) and
     * the automorphism is then applied to both polynomials.
     *
     * @param ciphertext the input ciphertext.
     * @param i automorphism index.
     * @param evalKeyMap reference to the map of evaluation keys generated by EvalAutomorphismKeyGen.
     * @return the resulting ciphertext.
     */
    Ciphertext<DCRTPoly> EvalAutomorphism(ConstCiphertext<DCRTPoly>& ciphertext, uint32_t i,
                                          const std::map<uint32_t, EvalKey<DCRTPoly>>& evalKeyMap,
                                          CALLER_INFO_ARGS_HDR) const override;

    /**
     * Automorphism and key switching step of hoisted rotations. The auxiliary moduli are dropped from the
     * digits for HYBRID key switching and, for HPSPOVERQLEVELED, the key switched polynomials are expanded
     * back from Q_l to Q before the automorphism is applied.
     *
     * @param ciphertext the input ciphertext to perform the automorphism on.
     * @param index the index of the rotation. Positive indices correspond to left rotations and negative
     * indices correspond to right rotations.
     * @param m is the cyclotomic order.
     * @param digits the digit decomposition created by EvalFastRotationPrecompute at the precomputation step.
     * @return the rotated ciphertext.
     */
    Ciphertext<DCRTPoly> EvalFastRotation(ConstCiphertext<DCRTPoly>& ciphertext, const uint32_t index, const uint32_t m,
                                          const std::shared_ptr<std::vector<DCRTPoly>> digits) const override;

    /**
     * Precomputation step of hoisted rotations: the digit decomposition of the second ciphertext polynomial.
     * For HPSPOVERQLEVELED with a full-modulus ciphertext, the polynomial is first scaled down to the basis Q_l
     * determined by the noise budget.
     *
     * @param ciphertext the input ciphertext on which to do the precomputation (digit decomposition).
     * @return the digit decomposition of the ciphertext.
     */
    std::shared_ptr<std::vector<DCRTPoly>> EvalFastRotationPrecompute(
            ConstCiphertext<DCRTPoly>& ciphertext) const override;

    /**
     * Finds the automorphism index corresponding to a rotation index for a power-of-two cyclotomic order.
     *
     * @param index the rotation index.
     * @param m the cyclotomic order.
     * @return the automorphism index.
     */
    uint32_t FindAutomorphismIndex(uint32_t index, uint32_t m) const override;

    /**
     * Compresses a BFV ciphertext by dropping towers (with the exact RNS rescaling by the dropped moduli) until
     * only towersLeft towers remain. Only supported for HPSPOVERQ and HPSPOVERQLEVELED with STANDARD encryption.
     *
     * @param ciphertext the input ciphertext.
     * @param towersLeft the number of RNS towers to keep.
     * @param noiseScaleDeg unused in BFV (kept for a uniform interface).
     * @return the compressed ciphertext.
     */
    Ciphertext<DCRTPoly> Compress(ConstCiphertext<DCRTPoly>& ciphertext, size_t towersLeft,
                                  size_t noiseScaleDeg) const override;

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
    /**
     * Key switches the last polynomial of the ciphertext (c_2 after a multiplication, or c_1 for a plain key
     * switch) with the given key and folds the result into (c_0, c_1). For HPSPOVERQLEVELED with a full-modulus
     * ciphertext, the polynomial is scaled down to Q_l before key switching and the result is expanded back to Q.
     *
     * @param ciphertext the input/output ciphertext with two or three polynomials.
     * @param evalKey the key switching (relinearization) key.
     */
    void RelinearizeCore(Ciphertext<DCRTPoly>& ciphertext, const EvalKey<DCRTPoly> evalKey) const;
};
}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_SCHEME_BFVRNS_BFVRNS_LEVELEDSHE_H_
