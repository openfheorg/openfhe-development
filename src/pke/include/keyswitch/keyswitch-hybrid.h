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
  Hybrid key switching: the digit decomposition of BV combined with the auxiliary modulus of GHS
  (https://eprint.iacr.org/2012/099). The RNS version was introduced in https://eprint.iacr.org/2019/688;
  see Appendix B of https://eprint.iacr.org/2021/204 for a detailed description.
 */
#ifndef SRC_PKE_INCLUDE_KEYSWITCH_KEYSWITCH_HYBRID_H_
#define SRC_PKE_INCLUDE_KEYSWITCH_KEYSWITCH_HYBRID_H_

#include <memory>
#include <string>
#include <vector>

#include "keyswitch/keyswitch-rns.h"
#include "schemebase/rlwe-cryptoparameters.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief RNS variant of hybrid key switching, which combines the digit decomposition of BV with the auxiliary
 * modulus of Gentry-Halevi-Smart (GHS).
 *
 * GHS key switching (https://eprint.iacr.org/2012/099) multiplies the element to be switched by a key defined
 * modulo QP, where the old secret key is scaled by the auxiliary modulus P, and then divides the result by P, which
 * shrinks the noise added by the key switching by a factor P. Used alone it needs P of the size of Q, which halves
 * the usable modulus. The hybrid method (RNS version in https://eprint.iacr.org/2019/688, described in Appendix B
 * of https://eprint.iacr.org/2021/204) first decomposes the element into dnum large digits, each digit being the
 * product of alpha = ceil(sizeQ / dnum) consecutive RNS limbs of Q, and then applies the GHS product in the
 * extended basis QP. The noise is proportional to the size of one digit, so P only needs to be about as large as a
 * digit (the number of limbs of P is about alpha), and the cost is 2 * dnum * (number of limbs) NTTs, linear rather
 * than quadratic as in BV. The number of digits is set by the crypto parameter numLargeDigits (dnum).
 *
 * The key holds one (b_j, a_j) pair per digit, defined modulo QP, with a_j uniformly random and
 * b_j = -a_j * sB + noiseScale * e_j + P * [sA]_{Q_j}, where [sA]_{Q_j} is the old key restricted to the limbs of
 * digit j (following https://eprint.iacr.org/2018/117 the CRT factors of the decomposition are folded into the key).
 * Key switching an element c at level l consists of: (1) splitting c into its digits, each extended from its limbs
 * to the whole basis QlP with an approximate CRT basis extension (EvalKeySwitchPrecomputeCore); (2) the inner
 * products of the digits with the two key vectors modulo QlP (EvalFastKeySwitchCoreExt); (3) the division by P with
 * rounding, an approximate modulus switching from QlP to Ql (KeySwitchDown). Steps (1) and (2) can be hoisted or
 * accumulated across several key switchings, which is what fast rotations and the linear transforms of CKKS
 * bootstrapping rely on.
 */
class KeySwitchHYBRID : public KeySwitchRNS {
    using ParmType = typename DCRTPoly::Params;
    using DugType = typename DCRTPoly::DugType;
    using DggType = typename DCRTPoly::DggType;
    using TugType = typename DCRTPoly::TugType;

  public:
    /**
     * Default constructor.
     */
    KeySwitchHYBRID() = default;

    /**
     * Virtual destructor.
     */
    virtual ~KeySwitchHYBRID() = default;

    /**
     * Generates a hybrid key switching key from oldPrivateKey to newPrivateKey: one (b_j, a_j) pair modulo QP per
     * digit, with b_j = -a_j * sB + noiseScale * e_j + P * [sA]_{Q_j}. The new key is extended from Q to QP for this
     * purpose.
     *
     * @param oldPrivateKey private key the ciphertexts to be switched are encrypted under
     * @param newPrivateKey private key the switched ciphertexts should decrypt under
     * @return the key switching key
     */
    EvalKey<DCRTPoly> KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldPrivateKey,
                                           const PrivateKey<DCRTPoly> newPrivateKey) const override;

    /**
     * Generates a hybrid key switching key from oldPrivateKey to newPrivateKey reusing the "a" components of
     * evalKey (threshold FHE); see KeySwitchBase::KeySwitchGenInternal.
     *
     * @param oldPrivateKey private key the ciphertexts to be switched are encrypted under
     * @param newPrivateKey private key the switched ciphertexts should decrypt under
     * @param evalKey key switching key whose "a" components are reused; if null, fresh components are sampled
     * @return the key switching key
     */
    EvalKey<DCRTPoly> KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldPrivateKey,
                                           const PrivateKey<DCRTPoly> newPrivateKey,
                                           const EvalKey<DCRTPoly> evalKey) const override;

    /**
     * Generates a hybrid key switching key from oldPrivateKey to the secret key of newPublicKey by encrypting
     * P * [sA]_{Q_j} for every digit with the public key, modulo QP (proxy re-encryption).
     *
     * @param oldPrivateKey private key the ciphertexts to be switched are encrypted under
     * @param newPublicKey public key of the party the switched ciphertexts should decrypt for
     * @return the key switching key
     */
    EvalKey<DCRTPoly> KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldPrivateKey,
                                           const PublicKey<DCRTPoly> newPublicKey) const override;

    /**
     * Key switches a ciphertext in place; see KeySwitchBase::KeySwitchInPlace.
     *
     * @param ciphertext ciphertext to be key switched; holds the result
     * @param evalKey key switching key
     */
    void KeySwitchInPlace(Ciphertext<DCRTPoly>& ciphertext, const EvalKey<DCRTPoly> evalKey) const override;

    /**
     * Raises a ciphertext from basis Ql to the extended basis QlP by multiplying its elements by P; see
     * KeySwitchBase::KeySwitchExt.
     *
     * @param ciphertext ciphertext in basis Ql
     * @param addFirst if true, the first element c0 is raised as well; if false, it is set to zero
     * @return the ciphertext in basis QlP
     */
    Ciphertext<DCRTPoly> KeySwitchExt(ConstCiphertext<DCRTPoly> ciphertext, bool addFirst) const override;

    /**
     * Divides a two-element ciphertext in basis QlP by P with rounding, returning it in basis Ql; see
     * KeySwitchBase::KeySwitchDown.
     *
     * @param ciphertext ciphertext in basis QlP
     * @return the ciphertext in basis Ql
     */
    Ciphertext<DCRTPoly> KeySwitchDown(ConstCiphertext<DCRTPoly> ciphertext) const override;

    /**
     * Divides the first element of a ciphertext in basis QlP by P with rounding, returning it in basis Ql.
     *
     * @param ciphertext ciphertext in basis QlP
     * @return the first element switched to basis Ql
     */
    DCRTPoly KeySwitchDownFirstElement(ConstCiphertext<DCRTPoly> ciphertext) const override;

    /////////////////////////////////////////
    // CORE OPERATIONS
    /////////////////////////////////////////

    /**
     * Key switches a single ring element: digit decomposition, inner products with the key, and division by P.
     *
     * @param a ring element to be key switched, in basis Ql
     * @param evalKey key switching key
     * @return the pair (b', a') in basis Ql such that b' + a' * sB = a * sA + noise
     */
    std::vector<DCRTPoly> KeySwitchCore(const DCRTPoly& a, const EvalKey<DCRTPoly> evalKey) const override;

    /**
     * Splits a ring element into its digits and extends every digit from its own limbs to the whole basis QlP. The
     * number of digits is ceil(sizeQl / alpha), capped by the number of digits of the key; the last digit may hold
     * fewer than alpha limbs at lower levels. The basis extension is the approximate (non-exact) CRT conversion,
     * whose small overflow is accounted for in the noise analysis.
     *
     * @param c ring element to be decomposed, in basis Ql
     * @param cryptoParamsBase crypto parameters holding the partition of Q into digits and the extension tables
     * @return the digits of c, each in basis QlP
     */
    std::shared_ptr<std::vector<DCRTPoly>> EvalKeySwitchPrecomputeCore(
            const DCRTPoly& c, std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParamsBase) const override;

    /**
     * Computes the inner products of the digits with the two key vectors modulo QlP (EvalFastKeySwitchCoreExt) and
     * divides the two results by P with rounding to return them in basis Ql.
     *
     * @param digits digits of the element computed by EvalKeySwitchPrecomputeCore
     * @param evalKey key switching key
     * @param paramsQl parameters of the basis Ql of the element (its current level)
     * @return the pair (b', a') in basis Ql such that b' + a' * sB = a * sA + noise
     */
    std::vector<DCRTPoly> EvalFastKeySwitchCore(const std::shared_ptr<std::vector<DCRTPoly>> digits,
                                                const EvalKey<DCRTPoly> evalKey,
                                                const std::shared_ptr<ParmType> paramsQl) const override;

    /**
     * Computes the inner products of the digits with the two key vectors modulo QlP and leaves the result in the
     * extended basis; only the limbs of the key that correspond to Ql and P are used. See
     * KeySwitchBase::EvalFastKeySwitchCoreExt for how the result is accumulated and switched down.
     *
     * @param digits digits of the element computed by EvalKeySwitchPrecomputeCore
     * @param evalKey key switching key
     * @param paramsQl parameters of the basis Ql of the element (its current level)
     * @return the pair (b', a') in basis QlP such that b' + a' * sB = P * a * sA + noise
     */
    std::vector<DCRTPoly> EvalFastKeySwitchCoreExt(const std::shared_ptr<std::vector<DCRTPoly>> digits,
                                                   const EvalKey<DCRTPoly> evalKey,
                                                   const std::shared_ptr<ParmType> paramsQl) const override;

    /////////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////////

    /**
     * Serializes the object (no state of its own beyond the base class).
     *
     * @param ar archive to write to
     */
    template <class Archive>
    void save(Archive& ar) const {
        ar(cereal::base_class<KeySwitchRNS>(this));
    }

    /**
     * Deserializes the object.
     *
     * @param ar archive to read from
     */
    template <class Archive>
    void load(Archive& ar) {
        ar(cereal::base_class<KeySwitchRNS>(this));
    }

    /**
     * Name used to identify the class in serialized objects.
     *
     * @return the name of the class
     */
    std::string SerializedObjectName() const override {
        return "KeySwitchHYBRID";
    }
};

}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_KEYSWITCH_KEYSWITCH_HYBRID_H_
