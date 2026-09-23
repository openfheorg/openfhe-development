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

#ifndef SRC_PKE_INCLUDE_SCHEMERNS_RNS_PKE_H_
#define SRC_PKE_INCLUDE_SCHEMERNS_RNS_PKE_H_

#include <memory>
#include <string>
#include <vector>

#include "lattice/lat-hal.h"
#include "schemebase/base-pke.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Abstract interface for encryption algorithm
 */
class PKERNS : public PKEBase<DCRTPoly> {
    using ParmType = typename DCRTPoly::Params;
    using IntType = typename DCRTPoly::Integer;
    using DugType = typename DCRTPoly::DugType;
    using DggType = typename DCRTPoly::DggType;
    using TugType = typename DCRTPoly::TugType;

  public:
    virtual ~PKERNS() = default;

    /**
   * Method for encrypting plaintext using LBC
   *
   * @param plaintext copy of the plaintext element. NOTE a copy is passed!
   * That is NOT an error!
   * @param publicKey public key used for encryption.
   * @return ciphertext which results from encryption.
   */
    Ciphertext<DCRTPoly> Encrypt(DCRTPoly plaintext, const PublicKey<DCRTPoly> publicKey) const override;

    /**
   * Method for encrypting plaintext using LBC
   *
   * @param plaintext copy of the plaintext input. NOTE a copy is passed! That
   * is NOT an error!
   * @param privateKey private key used for encryption.
   * @return ciphertext which results from encryption.
   */
    Ciphertext<DCRTPoly> Encrypt(DCRTPoly plaintext, const PrivateKey<DCRTPoly> privateKey) const override;

    /**
   * Method for decrypting plaintext using LBC
   *
   * @param ciphertext ciphertext to be decrypted.
   * @param privateKey private key used for decryption.
   * @param plaintext the plaintext output.
   * @return the decoding result.
   */
    DecryptResult Decrypt(ConstCiphertext<DCRTPoly> ciphertext, const PrivateKey<DCRTPoly> privateKey,
                          NativePoly* plaintext) const override;

    /**
   * Method for decrypting plaintext using LBC
   *
   * @param ciphertext ciphertext to be decrypted.
   * @param privateKey private key used for decryption.
   * @param plaintext the plaintext output.
   * @return the decoding result.
   */
    DecryptResult Decrypt(ConstCiphertext<DCRTPoly> ciphertext, const PrivateKey<DCRTPoly> privateKey,
                          Poly* plaintext) const override;

    /////////////////////////////////////
    // CORE OPERATIONS
    /////////////////////////////////////

    /**
   * Generates a secret-key encryption of zero, i.e., the pair (a*s + ns*e, -a) for a uniformly random a and a
   * Gaussian error e, where ns is the noise scale of the scheme.
   *
   * @param privateKey the secret key.
   * @param params the element parameters of the ciphertext; if fewer towers than the key has are requested,
   * only the needed towers of the key are used. nullptr selects the full modulus chain.
   * @return the two ciphertext polynomials.
   */
    std::shared_ptr<std::vector<DCRTPoly>> EncryptZeroCore(const PrivateKey<DCRTPoly> privateKey,
                                                           const std::shared_ptr<ParmType> params) const override;

    /**
   * Generates a public-key encryption of zero, i.e., the pair (p0*v + ns*e0, p1*v + ns*e1) for a fresh
   * ephemeral key v drawn from the secret key distribution and Gaussian errors e0, e1, where ns is the noise
   * scale of the scheme.
   *
   * @param publicKey the public key (p0, p1).
   * @param params the element parameters of the ciphertext; if fewer towers than the key has are requested,
   * only the needed towers of the public key are used. nullptr selects the full modulus chain.
   * @return the two ciphertext polynomials.
   */
    std::shared_ptr<std::vector<DCRTPoly>> EncryptZeroCore(const PublicKey<DCRTPoly> publicKey,
                                                           const std::shared_ptr<ParmType> params) const override;

    /**
   * Computes the decryption polynomial c_0 + c_1*s + c_2*s^2 + ... in EVALUATION format, using only the
   * towers of the secret key that the ciphertext still has.
   *
   * @param cv the ciphertext polynomials.
   * @param privateKey the secret key.
   * @return the noisy scaled plaintext polynomial.
   */
    DCRTPoly DecryptCore(const std::vector<DCRTPoly>& cv, const PrivateKey<DCRTPoly> privateKey) const override;

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar) const {
        ar(cereal::base_class<PKEBase<DCRTPoly>>(this));
    }

    template <class Archive>
    void load(Archive& ar) {
        ar(cereal::base_class<PKEBase<DCRTPoly>>(this));
    }

    std::string SerializedObjectName() const {
        return "PKERNS";
    }
};

}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_SCHEMERNS_RNS_PKE_H_
