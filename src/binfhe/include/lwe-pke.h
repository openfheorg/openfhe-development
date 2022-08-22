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

#include <memory>

#include "binfhe-constants.h"
#include "lwe-ciphertext.h"
#include "lwe-keyswitchkey.h"
#include "lwe-privatekey.h"
#include "lwe-cryptoparameters.h"

namespace lbcrypto {

/**
 * @brief Additive LWE scheme
 */
class LWEEncryptionScheme {
public:
    LWEEncryptionScheme() {}

    /**
   * Generates a secret key of dimension n using modulus q
   *
   * @param params a shared pointer to LWE scheme parameters
   * @return a shared pointer to the secret key
   */
    LWEPrivateKey KeyGen(const std::shared_ptr<LWECryptoParams> params) const;

    /**
   * Generates a secret key of dimension N using modulus Q
   *
   * @param params a shared pointer to LWE scheme parameters
   * @return a shared pointer to the secret key
   */
    LWEPrivateKey KeyGenN(const std::shared_ptr<LWECryptoParams> params) const;

    /**
   * Encrypts a bit using a secret key (symmetric key encryption)
   *
   * @param params a shared pointer to LWE scheme parameters
   * @param sk - the secret key
   * @param &m - the plaintext
   * @param &p - the plaintext space
   * @return a shared pointer to the ciphertext
   */
    LWECiphertext Encrypt(const std::shared_ptr<LWECryptoParams> params, ConstLWEPrivateKey sk, const LWEPlaintext& m,
                          const LWEPlaintextModulus& p = 4) const;

    /**
   * Decrypts the ciphertext using secret key sk
   *
   * @param params a shared pointer to LWE scheme parameters
   * @param sk the secret key
   * @param ct the ciphertext
   * @param &p the plaintext space
   * @param *result plaintext result
   */
    void Decrypt(const std::shared_ptr<LWECryptoParams> params, ConstLWEPrivateKey sk, ConstLWECiphertext ct,
                 LWEPlaintext* result, const LWEPlaintextModulus& p = 4) const;

    /**
   * Changes an LWE ciphertext modulo Q into an LWE ciphertext modulo q
   *
   * @param q modulus to
   * @param ctQ the input ciphertext
   * @return resulting ciphertext
   */
    LWECiphertext ModSwitch(NativeInteger q, ConstLWECiphertext ctQ) const;

    /**
   * Generates a switching key to go from a secret key with (Q,N) to a secret
   * key with (q,n)
   *
   * @param params a shared pointer to LWE scheme parameters
   * @param sk new secret key
   * @param skN old secret key
   * @return a shared pointer to the switching key
   */
    LWESwitchingKey KeySwitchGen(const std::shared_ptr<LWECryptoParams> params, ConstLWEPrivateKey sk,
                                 ConstLWEPrivateKey skN) const;

    /**
   * Switches ciphertext from (Q,N) to (Q,n)
   *
   * @param params a shared pointer to LWE scheme parameters
   * @param K switching key
   * @param ctQN input ciphertext
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext KeySwitch(const std::shared_ptr<LWECryptoParams> params, ConstLWESwitchingKey K,
                            ConstLWECiphertext ctQN) const;

    /**
   * Embeds a plaintext bit without noise or encryption
   *
   * @param params a shared pointer to LWE scheme parameters
   * @param &m - the plaintext
   * @return a shared pointer to the ciphertext
   */
    LWECiphertext NoiselessEmbedding(const std::shared_ptr<LWECryptoParams> params, const LWEPlaintext& m) const;
};

NativeInteger RoundqQ(const NativeInteger& v, const NativeInteger& q, const NativeInteger& Q);

}  // namespace lbcrypto

#endif
