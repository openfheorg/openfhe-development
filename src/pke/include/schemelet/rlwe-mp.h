//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2025, NJIT, Duality Technologies Inc. and other contributors
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

#ifndef SRC_PKE_INCLUDE_SCHEMELET_RLWE_MP_H_
#define SRC_PKE_INCLUDE_SCHEMELET_RLWE_MP_H_

#include <cstdint>
#include <memory>
#include <vector>

#include "ciphertext-fwd.h"
#include "cryptocontext-fwd.h"
#include "key/keypair.h"
#include "openfhecore.h"

namespace lbcrypto {

/**
 * @brief Helper ("schemelet") for RLWE ciphertexts with a message in the coefficients, used together with the
 * CKKS functional bootstrapping (EvalFBT)
 *
 * An RLWE ciphertext is represented as a pair {b, a} of Poly modulo a ciphertext modulus Q such that
 * b + a*s = (Q/p)*m + e for the CKKS secret key s, a plaintext modulus p and an integer message vector m stored in
 * the polynomial coefficients (BFV-style scaling). The static methods encrypt and decrypt such ciphertexts under
 * the CKKS secret key with arbitrary Q and p, switch their modulus, and convert them to and from CKKS ciphertexts
 * so that EvalFBT can evaluate a function on the encrypted values and return an exact RLWE ciphertext.
 */
class SchemeletRLWEMP {
    using DggType = typename DCRTPoly::DggType;
    using DugType = typename DCRTPoly::DugType;

  public:
    ~SchemeletRLWEMP() = default;

    /**
     * Returns the RNS element parameters of the secret key's crypto context with the towers of the given number of
     * levels removed from the end. One level corresponds to one tower, except that under COMPOSITESCALINGAUTO and
     * COMPOSITESCALINGMANUAL every level consists of compositeDegree towers and under FLEXIBLEAUTOEXT one extra
     * tower is removed. The modulus of the result is the modulus Q' that EncryptCoeff() samples its encryption of
     * zero over.
     *
     * @param privateKey the CKKS secret key whose crypto context supplies the element parameters
     * @param level number of levels to remove from the full parameters (0 keeps all towers)
     * @return the reduced element parameters
     */
    static std::shared_ptr<ILDCRTParams<DCRTPoly::Integer>> GetElementParams(const PrivateKey<DCRTPoly>& privateKey,
                                                                             uint32_t level = 0);

    /**
     * Encrypts a vector of integers as the coefficients of an RLWE ciphertext under the CKKS secret key.
     * An RLWE encryption of zero is sampled over the modulus of elementParams, switched to Q, and the message scaled
     * by Q/p is added. With N the ring dimension, the entries are placed at a stride of N/(2*input.size()); when the
     * stride is greater than 1 the same values are repeated in the second half of the coefficient vector, and when
     * the input has more than N/2 entries they are placed consecutively (at most N of them are used).
     *
     * @param input the integer message; every entry is reduced modulo p as a signed value
     * @param Q ciphertext modulus of the returned RLWE ciphertext
     * @param p plaintext modulus
     * @param privateKey the CKKS secret key
     * @param elementParams RNS parameters whose modulus Q' the encryption of zero is generated over
     *        (see GetElementParams())
     * @param bitReverse if true, the input is permuted in bit-reversed order before encoding (each half separately
     *        when the input has more than N/2 entries); this matches the slot order of the CKKS conversions when
     *        rotations are applied in the CKKS domain
     * @return the RLWE ciphertext as the pair {b, a} of polynomials modulo Q
     */
    static std::vector<Poly> EncryptCoeff(std::vector<int64_t> input, const BigInteger& Q, const BigInteger& p,
                                          const PrivateKey<DCRTPoly>& privateKey,
                                          const std::shared_ptr<ILDCRTParams<DCRTPoly::Integer>>& elementParams,
                                          bool bitReverse = false);

    /**
     * Decrypts an RLWE ciphertext {b, a} modulo Q (as produced by EncryptCoeff() or ConvertCKKSToRLWE()) with the
     * CKKS secret key. The ciphertext is switched to the modulus of elementParams, b + a*s is computed, switched
     * back to Q and rounded to the plaintext modulus p, and the message coefficients are read at a stride of
     * N/(2*numSlots) (N = ring dimension) as signed integers in (-p/2, p/2].
     *
     * @param input the RLWE ciphertext {b, a} modulo Q
     * @param Q ciphertext modulus of the input
     * @param p plaintext modulus
     * @param privateKey the CKKS secret key
     * @param elementParams RNS parameters used for the decryption (see GetElementParams())
     * @param numSlots number of slots used in the CKKS computation; determines the stride between message
     *        coefficients
     * @param length number of values to return (0 means numSlots)
     * @param bitReverse if true, the bit-reversal permutation applied at encryption is undone (each half separately
     *        when numSlots is less than length)
     * @return the decrypted integer values
     */
    static std::vector<int64_t> DecryptCoeff(const std::vector<Poly>& input, const BigInteger& Q, const BigInteger& p,
                                             const PrivateKey<DCRTPoly>& privateKey,
                                             const std::shared_ptr<ILDCRTParams<DCRTPoly::Integer>>& elementParams,
                                             uint32_t numSlots, uint32_t length = 0, bool bitReverse = false);

    /**
     * Switches an RLWE ciphertext {b, a} from modulus Q2 to modulus Q1 in place by scaling both polynomials by
     * Q1/Q2 with rounding.
     *
     * @param input the ciphertext polynomials, currently modulo Q2; replaced by the polynomials modulo Q1
     * @param Q1 the target modulus
     * @param Q2 the current modulus
     */
    static void ModSwitch(std::vector<Poly>& input, const BigInteger& Q1, const BigInteger& Q2);

    /**
     * Embeds an RLWE ciphertext {b, a} modulo Bigq into a CKKS ciphertext so that EvalFBT can process it.
     * A CKKS ciphertext with the requested number of slots is created at the given level by encrypting zero under
     * the public key (this supplies the ciphertext metadata), and its two elements are replaced by the RLWE
     * polynomials scaled and switched from Bigq to the CKKS modulus at that level. The level is adjusted for the
     * scaling technique in the same way as in GetElementParams().
     *
     * @param cc the CKKS crypto context
     * @param coeffs the RLWE ciphertext {b, a}
     * @param pubKey CKKS public key used for the encryption of zero
     * @param Bigq modulus of the RLWE ciphertext
     * @param slots number of slots recorded in the CKKS ciphertext
     * @param level level of the resulting CKKS ciphertext
     * @return a CKKS ciphertext whose elements are the modulus-switched RLWE polynomials
     */
    static Ciphertext<DCRTPoly> ConvertRLWEToCKKS(const CryptoContextImpl<DCRTPoly>& cc,
                                                  const std::vector<Poly>& coeffs, const PublicKey<DCRTPoly>& pubKey,
                                                  const BigInteger& Bigq, uint32_t slots, uint32_t level = 0);

    /**
     * Extracts an RLWE ciphertext {b, a} modulo Q from a CKKS ciphertext: both elements are brought to coefficient
     * representation, CRT-interpolated to polynomials over the CKKS modulus and scaled and switched to Q with
     * rounding.
     *
     * @param ctxt the CKKS ciphertext (two elements)
     * @param Q the target modulus of the RLWE ciphertext
     * @return the pair {b, a} of polynomials modulo Q
     */
    static std::vector<Poly> ConvertCKKSToRLWE(ConstCiphertext<DCRTPoly>& ctxt, const BigInteger& Q);

    /**
     * Computes the product of the first lvls+1 RNS moduli q_0, ..., q_lvls of the public key's element parameters.
     *
     * @param pubKey a CKKS public key supplying the RNS moduli
     * @param lvls number of moduli after q_0 to include in the product
     * @return q_0 * q_1 * ... * q_lvls
     */
    static BigInteger GetQPrime(const PublicKey<DCRTPoly>& pubKey, uint32_t lvls);
};

}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_SCHEMELET_RLWE_MP_H_
