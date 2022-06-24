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

#ifndef LBCRYPTO_CRYPTO_BASE_FHE_H
#define LBCRYPTO_CRYPTO_BASE_FHE_H

#include "key/allkey.h"
#include "ciphertext.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Abstract interface class for LBC PRE algorithms
 * @tparam Element a ring element.
 */
template <class Element>
class FHEBase {
 public:

  virtual ~FHEBase() {}

  /**
   * Bootstrap functionality:
   * There are three methods that have to be called in this specific order:
   * 1. EvalBTSetup: computes and encodes the coefficients for encoding and
   * decoding and stores the necessary parameters
   * 2. EvalBTKeyGen: computes and stores the keys for rotations and conjugation
   * 3. EvalBT: refreshes the given ciphertext
   */

  /**
   * Sets all parameters for the linear method for the FFT-like method
   *
   * @param levelBudget - vector of budgets for the amount of levels in encoding
   * and decoding
   * @param dim1 - vector of inner dimension in the baby-step giant-step routine
   * for encoding and decoding
   * @param slots - number of slots to be bootstrapped
   * @param debugFlag - set to 1 when debugging encoding/decoding only
   * @param precomp - do linear transform precomputations
   */
  virtual void EvalBootstrapSetup(
      const CryptoContextImpl<Element> &cc,
      std::vector<uint32_t> levelBudget = {5, 4},
      std::vector<uint32_t> dim1 = {0, 0}, uint32_t slots = 0) {
    OPENFHE_THROW(not_implemented_error, "Not supported");
  }

  virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalLTKeyGen(
        const PrivateKey<Element> privateKey, uint32_t dim1,
        int32_t bootstrapFlag, int32_t conjFlag) {
    OPENFHE_THROW(not_implemented_error, "Not supported");
  }

  /**
   * Virtual function to define the generation of all automorphism keys for EvalBT (with FFT evaluation).
   * EvalBTKeyGen uses the baby-step/giant-step strategy.
   *
   * @param privateKey private key.
   * @param bootstrapFlag - when set to 1, generates extra automorphism keys for sparse bootstrapping.
   * @return the dictionary of evaluation key indices.
   */
  virtual std::shared_ptr<std::map<usint, EvalKey<Element>>>
  EvalBootstrapKeyGen(const PrivateKey<Element> privateKey,
      int32_t bootstrapFlag = 0) {
    OPENFHE_THROW(not_implemented_error, "Not supported");
  }

  /**
   * Defines the bootstrapping evaluation of ciphertext
   *
   * @param ciphertext the input ciphertext.
   * @return the refreshed ciphertext.
   */
  virtual Ciphertext<Element> EvalBootstrap(
      ConstCiphertext<Element> ciphertext) const {
    OPENFHE_THROW(not_implemented_error,
        "EvalBootstrap is not implemented for this scheme");
  }

  virtual void EvalBootstrapPrecompute(
      const CryptoContextImpl<Element> &cc,
      uint32_t debugFlag) {
    OPENFHE_THROW(not_implemented_error,
        "EvalBootstrapPrecompute is not implemented for this scheme");
  }

  virtual EvalKey<Element> ConjugateKeyGen(
      const PrivateKey<Element> privateKey) const {
    OPENFHE_THROW(not_implemented_error, "Not supported");
  }

};

}  // namespace lbcrypto

#endif
