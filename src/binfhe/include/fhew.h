// @file fhew.h - FHEW scheme header file
// The scheme is described in https://eprint.iacr.org/2014/816 and in
// Daniele Micciancio and Yuriy Polyakov, "Bootstrapping in FHEW-like
// Cryptosystems", Cryptology ePrint Archive, Report 2020/086,
// https://eprint.iacr.org/2020/086.
//
// Full reference to https://eprint.iacr.org/2014/816:
// @misc{cryptoeprint:2014:816,
//   author = {Leo Ducas and Daniele Micciancio},
//   title = {FHEW: Bootstrapping Homomorphic Encryption in less than a second},
//   howpublished = {Cryptology ePrint Archive, Report 2014/816},
//   year = {2014},
//   note = {\url{https://eprint.iacr.org/2014/816}},
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, Duality Technologies Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef BINFHE_FHEW_H
#define BINFHE_FHEW_H

#include "lwe.h"
#include "ringcore.h"

namespace lbcrypto {

/**
 * @brief Ring GSW accumulator schemes described in
 * https://eprint.iacr.org/2014/816 and "Bootstrapping in FHEW-like
 * Cryptosystems"
 */
class RingGSWAccumulatorScheme {
 public:
  RingGSWAccumulatorScheme() {}

  /**
   * Generates a refreshing key
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param lwescheme a shared pointer to additive LWE scheme
   * @param LWEsk a shared pointer to the secret key of the underlying additive
   * LWE scheme
   * @return a shared pointer to the refreshing key
   */
  RingGSWEvalKey KeyGen(
      const std::shared_ptr<RingGSWCryptoParams> params,
      const std::shared_ptr<LWEEncryptionScheme> lwescheme,
      const std::shared_ptr<const LWEPrivateKeyImpl> LWEsk) const;

  /**
   * Evaluates a binary gate (calls bootstrapping as a subroutine)
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param gate the gate; can be AND, OR, NAND, NOR, XOR, or XOR
   * @param &EK a shared pointer to the bootstrapping keys
   * @param ct1 first ciphertext
   * @param ct2 second ciphertext
   * @param lwescheme a shared pointer to additive LWE scheme
   * @return a shared pointer to the resulting ciphertext
   */
  std::shared_ptr<LWECiphertextImpl> EvalBinGate(
      const std::shared_ptr<RingGSWCryptoParams> params, const BINGATE gate,
      const RingGSWEvalKey &EK,
      const std::shared_ptr<const LWECiphertextImpl> ct1,
      const std::shared_ptr<const LWECiphertextImpl> ct2,
      const std::shared_ptr<LWEEncryptionScheme> LWEscheme) const;

  /**
   * Evaluates NOT gate
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param ct1 the input ciphertext
   * @return a shared pointer to the resulting ciphertext
   */
  std::shared_ptr<LWECiphertextImpl> EvalNOT(
      const std::shared_ptr<RingGSWCryptoParams> params,
      const std::shared_ptr<const LWECiphertextImpl> ct1) const;

  /**
   * Bootstraps a fresh ciphertext
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &EK a shared pointer to the bootstrapping keys
   * @param ct1 input ciphertext
   * @param lwescheme a shared pointer to additive LWE scheme
   * @return a shared pointer to the resulting ciphertext
   */
  std::shared_ptr<LWECiphertextImpl> Bootstrap(
      const std::shared_ptr<RingGSWCryptoParams> params,
      const RingGSWEvalKey &EK,
      const std::shared_ptr<const LWECiphertextImpl> ct1,
      const std::shared_ptr<LWEEncryptionScheme> LWEscheme) const;

 private:
  /**
   * Generates a refreshing key - GINX variant
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param lwescheme a shared pointer to additive LWE scheme
   * @param LWEsk a shared pointer to the secret key of the underlying additive
   * LWE scheme
   * @return a shared pointer to the refreshing key
   */
  RingGSWEvalKey KeyGenGINX(
      const std::shared_ptr<RingGSWCryptoParams> params,
      const std::shared_ptr<LWEEncryptionScheme> lwescheme,
      const std::shared_ptr<const LWEPrivateKeyImpl> LWEsk) const;

  /**
   * Generates a refreshing key - AP variant
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param lwescheme a shared pointer to additive LWE scheme
   * @param LWEsk a shared pointer to the secret key of the underlying additive
   * LWE scheme
   * @return a shared pointer to the refreshing key
   */
  RingGSWEvalKey KeyGenAP(
      const std::shared_ptr<RingGSWCryptoParams> params,
      const std::shared_ptr<LWEEncryptionScheme> lwescheme,
      const std::shared_ptr<const LWEPrivateKeyImpl> LWEsk) const;

  /**
   * Internal RingGSW encryption used in generating the refreshing key - AP
   * variant
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param skFFT secret key polynomial in the EVALUATION representation
   * @param m plaintext (corresponds to a lookup entry for the LWE scheme secret
   * key)
   * @return a shared pointer to the resulting ciphertext
   */
  std::shared_ptr<RingGSWCiphertext> EncryptAP(
      const std::shared_ptr<RingGSWCryptoParams> params,
      const NativePoly &skFFT, const LWEPlaintext &m) const;

  /**
   * Internal RingGSW encryption used in generating the refreshing key - GINX
   * variant
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param skFFT secret key polynomial in the EVALUATION representation
   * @param m plaintext (corresponds to a lookup entry for the LWE scheme secret
   * key)
   * @return a shared pointer to the resulting ciphertext
   */
  std::shared_ptr<RingGSWCiphertext> EncryptGINX(
      const std::shared_ptr<RingGSWCryptoParams> params,
      const NativePoly &skFFT, const LWEPlaintext &m) const;

  /**
   * Main accumulator function used in bootstrapping - AP variant
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &input input ciphertext
   * @param acc previous value of the accumulator
   */
  void AddToACCAP(const std::shared_ptr<RingGSWCryptoParams> params,
                  const RingGSWCiphertext &input,
                  std::shared_ptr<RingGSWCiphertext> acc) const;

  /**
   * Main accumulator function used in bootstrapping - GINX variant
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &input input ciphertext
   * @param &a integer a in each step of GINX accumulation
   * @param acc previous value of the accumulator
   */
  void AddToACCGINX(const std::shared_ptr<RingGSWCryptoParams> params,
                    const RingGSWCiphertext &input, const NativeInteger &a,
                    std::shared_ptr<RingGSWCiphertext> acc) const;

  /**
   * Takes an RLWE ciphertext input and outputs a vector of its digits, i.e., an
   * RLWE' ciphertext
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &input input RLWE ciphertext
   * @param *output input RLWE ciphertext
   */
  inline void SignedDigitDecompose(
      const std::shared_ptr<RingGSWCryptoParams> params,
      const std::vector<NativePoly> &input,
      std::vector<NativePoly> *output) const;

  /**
   * Core bootstrapping operation
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &EK a shared pointer to the bootstrapping keys
   * @param gate the gate; can be AND, OR, NAND, NOR, XOR, or XOR
   * @param &a first part of the input LWE ciphertext
   * @param &b second part of the input LWE ciphertext
   * @param lwescheme a shared pointer to additive LWE scheme
   * @return the output RingLWE accumulator
   */
  std::shared_ptr<RingGSWCiphertext> BootstrapCore(
      const std::shared_ptr<RingGSWCryptoParams> params, const BINGATE gate,
      const RingGSWEvalKey &EK, const NativeVector &a, const NativeInteger &b,
      const std::shared_ptr<LWEEncryptionScheme> LWEscheme) const;
};

}  // namespace lbcrypto

#endif
