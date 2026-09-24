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

#ifndef SRC_PKE_INCLUDE_KEYSWITCH_KEYSWITCH_BV_H_
#define SRC_PKE_INCLUDE_KEYSWITCH_KEYSWITCH_BV_H_

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
 * @brief RNS variant of the Brakerski-Vaikuntanathan (BV) key switching method.
 *
 * The method was introduced in [Fully Homomorphic Encryption from Ring-LWE and Security for Key Dependent
 * Messages](https://www.wisdom.weizmann.ac.il/~zvikab/localpapers/IdealHom.pdf); see Appendix B of
 * https://eprint.iacr.org/2021/204 for the RNS description used here.
 *
 * The element to be switched is decomposed digit by digit and the digits are multiplied by encryptions of the
 * corresponding multiples of the old secret key, so that the noise added by the key switching is proportional to
 * the size of a digit instead of the size of the ciphertext modulus. In RNS the digits are the CRT residues of the
 * element (one digit per RNS limb q_i of the current modulus Ql), and the key holds one (b_i, a_i) pair per limb of
 * Q, where b_i encrypts the i-th CRT component of the old key under the new key. Following
 * https://eprint.iacr.org/2018/117, the factors (Q/q_i)^{-1} mod q_i of the decomposition are folded into the key, so
 * the digits are obtained for free. When the crypto parameters set a digit size, every residue is further
 * decomposed in radix base 2^digitSize, which reduces the noise at the cost of more key components and more NTTs.
 *
 * Key switching runs entirely in the basis Ql (no auxiliary modulus P), so it does not reduce the usable ciphertext
 * modulus, but it costs a quadratic number of NTTs in the number of limbs, which makes it slower than hybrid key
 * switching for large parameters. The extended-basis operations (KeySwitchExt, KeySwitchDown,
 * EvalFastKeySwitchCoreExt) are not supported.
 */
class KeySwitchBV : public KeySwitchRNS {
    using ParmType = typename DCRTPoly::Params;
    using DugType = typename DCRTPoly::DugType;
    using DggType = typename DCRTPoly::DggType;
    using TugType = typename DCRTPoly::TugType;

  public:
    /**
   * Default constructor.
   */
    KeySwitchBV() = default;

    /**
   * Virtual destructor.
   */
    virtual ~KeySwitchBV() = default;

    /**
   * Generates a BV key switching key from oldPrivateKey to newPrivateKey. The key has one (b_i, a_i) pair per RNS
   * limb of the old key (or per radix digit of every limb when a digit size is set), with a_i uniformly random and
   * b_i = -a_i * sB + noiseScale * e_i + [sA]_{q_i} placed in limb i.
   *
   * @param oldPrivateKey private key the ciphertexts to be switched are encrypted under
   * @param newPrivateKey private key the switched ciphertexts should decrypt under
   * @return the key switching key
   */
    EvalKey<DCRTPoly> KeySwitchGenInternal(const PrivateKey<DCRTPoly> oldPrivateKey,
                                           const PrivateKey<DCRTPoly> newPrivateKey) const override;

    /**
   * Generates a BV key switching key from oldPrivateKey to newPrivateKey reusing the "a" components of evalKey
   * (threshold FHE); see KeySwitchBase::KeySwitchGenInternal.
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
   * Generates a BV key switching key from oldPrivateKey to the secret key of newPublicKey by encrypting every CRT
   * component of the old key with the public key (proxy re-encryption).
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

    /////////////////////////////////////////
    // CORE OPERATIONS
    /////////////////////////////////////////

    /**
   * Key switches a single ring element: digit decomposition followed by EvalFastKeySwitchCore.
   *
   * @param a ring element to be key switched, in basis Ql
   * @param evalKey key switching key
   * @return the pair (b', a') in basis Ql such that b' + a' * sB = a * sA + noise
   */
    std::vector<DCRTPoly> KeySwitchCore(const DCRTPoly& a, const EvalKey<DCRTPoly> evalKey) const override;

    /**
   * Computes the BV digits of a ring element: its CRT decomposition (one digit per RNS limb, each extended to the
   * whole basis Ql), further split in radix base 2^digitSize when the crypto parameters set a digit size.
   *
   * @param c ring element to be decomposed, in basis Ql
   * @param cryptoParamsBase crypto parameters (used for the digit size)
   * @return the digits of c
   */
    std::shared_ptr<std::vector<DCRTPoly>> EvalKeySwitchPrecomputeCore(
            const DCRTPoly& c, std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParamsBase) const override;

    /**
   * Computes the inner products of the digits with the two component vectors of the key switching key, limb by
   * limb in the basis Ql. Only the key components that correspond to the limbs of Ql are used.
   *
   * @param digits digits of the element computed by EvalKeySwitchPrecomputeCore
   * @param evalKey key switching key
   * @param paramsQl parameters of the basis Ql of the element (its current level)
   * @return the pair (b', a') in basis Ql such that b' + a' * sB = a * sA + noise
   */
    std::vector<DCRTPoly> EvalFastKeySwitchCore(const std::shared_ptr<std::vector<DCRTPoly>> digits,
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
        return "KeySwitchBV";
    }
};

}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_KEYSWITCH_KEYSWITCH_BV_H_
