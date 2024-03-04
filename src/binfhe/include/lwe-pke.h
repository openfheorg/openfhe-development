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

#ifndef _LWE_PKE_H_
#define _LWE_PKE_H_

#include "binfhe-constants.h"
#include "lwe-ciphertext.h"
#include "lwe-keyswitchkey.h"
#include "lwe-privatekey.h"
#include "lwe-publickey.h"
#include "lwe-keypair.h"
#include "lwe-cryptoparameters.h"

#include <memory>

namespace lbcrypto {

/**
 * @brief Additive public-key LWE scheme
 */
class LWEEncryptionScheme {
    NativeInteger RoundqQ(const NativeInteger& v, const NativeInteger& q, const NativeInteger& Q) const;

public:
    LWEEncryptionScheme() = default;

    /**
   * Generates a secret key of dimension n using modulus q
   *
   * @param size lattice parameter for the additive LWE scheme
   * @param modulus the modulus for the secret key
   * @return a shared pointer to the secret key
   */
    LWEPrivateKey KeyGen(usint size, const NativeInteger& modulus) const;

    /**
   * Generates a secret key of dimension n using modulus q
   *
   * @param size lattice parameter for the additive LWE scheme
   * @param modulus the modulus for the secret key
   * @return a shared pointer to the secret key
   */
    LWEPrivateKey KeyGenGaussian(usint size, const NativeInteger& modulus) const;

    /**
   * Generates a public key of dimension N and modulus Q, secret key of dimension n using modulus q pair
   * @param params a shared pointer to LWE scheme parameters
   * @return a shared pointer to the public key, secret key pair
   */
    LWEKeyPair KeyGenPair(const std::shared_ptr<LWECryptoParams>& params) const;

    /**
   * Generates a public key corresponding to a secret key of dimension N using modulus Q
   *
   * @param params a shared pointer to LWE scheme parameters
   * @param skN a secret key of dimension N
   * @return a shared pointer to the public key
   */
    LWEPublicKey PubKeyGen(const std::shared_ptr<LWECryptoParams>& params, ConstLWEPrivateKey& skN) const;

    /**
   * Encrypts a bit using a secret key (symmetric key encryption)
   *
   * @param params a shared pointer to LWE scheme parameters
   * @param sk the secret key
   * @param m the plaintext
   * @param p the plaintext space
   * @param mod the ciphertext modulus to encrypt with; by default m_q in params
   * @return a shared pointer to the ciphertext
   */
    LWECiphertext Encrypt(const std::shared_ptr<LWECryptoParams>& params, ConstLWEPrivateKey& sk, LWEPlaintext m,
                          LWEPlaintextModulus p = 4, NativeInteger mod = 0) const;

    /**
   * Encrypts a bit using a public key (asymmetric key encryption)
   *
   * @param params a shared pointer to LWE scheme parameters
   * @param pk the public key
   * @param m the plaintext
   * @param p the plaintext space
   * @param mod the ciphertext modulus to encrypt with; by default m_q in params
   * @return a shared pointer to the ciphertext
   */
    LWECiphertext EncryptN(const std::shared_ptr<LWECryptoParams>& params, ConstLWEPublicKey& pk, LWEPlaintext m,
                           LWEPlaintextModulus p = 4, NativeInteger mod = 0) const;

    /**
   * Converts a ciphertext (public key encryption) with modulus Q and dimension N to ciphertext with q and n
   *
   * @param ksk the key switching key from secret key of dimension N to secret key of dimension n
   * @param ct the ciphertext to convert
   * @return a shared pointer to the ciphertext
   */
    LWECiphertext SwitchCTtoqn(const std::shared_ptr<LWECryptoParams>& params, ConstLWESwitchingKey& ksk,
                               ConstLWECiphertext& ct) const;

    /**
   * Decrypts the ciphertext using secret key sk
   *
   * @param params a shared pointer to LWE scheme parameters
   * @param sk the secret key
   * @param ct the ciphertext
   * @param result plaintext result
   * @param p the plaintext space
   */
    void Decrypt(const std::shared_ptr<LWECryptoParams>& params, ConstLWEPrivateKey& sk, ConstLWECiphertext& ct,
                 LWEPlaintext* result, LWEPlaintextModulus p = 4) const;

    /**
   * Adds the second ciphertext to the first ciphertext
   *
   * @param ct1 the ciphertext which will hold the sum
   * @param ct2 the ciphertext to add
   */
    void EvalAddEq(LWECiphertext& ct1, ConstLWECiphertext& ct2) const;

    /**
   * Adds the a constant to the ciphertext
   *
   * @param ct the ciphertext which will hold the sum
   * @param cnst the constant to add
   */
    void EvalAddConstEq(LWECiphertext& ct, NativeInteger cnst) const;

    /**
   * Subtracts the second ciphertext from the first ciphertext, the result is held in the first ciphertext
   *
   * @param ct1 the ciphertext which will hold the difference
   * @param ct2 the ciphertext to subtract
   */
    void EvalSubEq(LWECiphertext& ct1, ConstLWECiphertext& ct2) const;

    /**
   * Subtracts the second ciphertext from the first ciphertext, the result is held in the first ciphertext
   *
   * @param ct1 the ciphertext from which to subtract
   * @param ct2 the ciphertext to subtract, will hold the difference
   */
    void EvalSubEq2(ConstLWECiphertext& ct1, LWECiphertext& ct2) const;

    /**
   * Subtracts the constant from the ciphertext
   *
   * @param ct1 the ciphertext which will hold the difference
   * @param ct2 the constant to subtract
   */
    void EvalSubConstEq(LWECiphertext& ct, NativeInteger cnst) const;

    /**
   * Multiplies a ciphertext by a constant
   *
   * @param ct1 the ciphertext which will hold the product
   * @param ct2 the constant to multiply by
   */
    void EvalMultConstEq(LWECiphertext& ct, NativeInteger cnst) const;

    /**
   * Changes an LWE ciphertext modulo Q into an LWE ciphertext modulo q
   *
   * @param q modulus to
   * @param ctQ the input ciphertext
   * @return resulting ciphertext
   */
    LWECiphertext ModSwitch(NativeInteger q, ConstLWECiphertext& ctQ) const;

    /**
   * Generates a switching key to go from a secret key with (Q,N) to a secret
   * key with (q,n)
   *
   * @param params a shared pointer to LWE scheme parameters
   * @param sk new secret key
   * @param skN old secret key
   * @return a shared pointer to the switching key
   */
    LWESwitchingKey KeySwitchGen(const std::shared_ptr<LWECryptoParams>& params, ConstLWEPrivateKey& sk,
                                 ConstLWEPrivateKey& skN) const;

    /**
   * Switches ciphertext from (Q,N) to (Q,n)
   *
   * @param params a shared pointer to LWE scheme parameters
   * @param K switching key
   * @param ctQN input ciphertext
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext KeySwitch(const std::shared_ptr<LWECryptoParams>& params, ConstLWESwitchingKey& K,
                            ConstLWECiphertext& ctQN) const;

    /**
   * Embeds a plaintext bit without noise or encryption
   *
   * @param params a shared pointer to LWE scheme parameters
   * @param m - the plaintext
   * @return a shared pointer to the ciphertext
   */
    LWECiphertext NoiselessEmbedding(const std::shared_ptr<LWECryptoParams>& params, LWEPlaintext m) const;
};

}  // namespace lbcrypto

#endif
