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
   * Defines the bootstrapping evaluation of ciphertext
   *
   * @param ciphertext the input ciphertext.
   * @return the refreshed ciphertext.
   */
  virtual Ciphertext<Element> EvalBootstrap(ConstCiphertext<Element> ciphertext) const {
    OPENFHE_THROW(not_implemented_error,
        "EvalBootstrap is not implemented for this scheme");
  }


  /**
   * Virtual function to define the bootstrapping evaluation of ciphertext using either the FFT-like method
   * or the linear method
   *
   * @param ciphertext the input ciphertext.
   * @return the refreshed ciphertext.
   */
  virtual Ciphertext<Element> EvalBT(ConstCiphertext<Element> ciphertext) const {
    OPENFHE_THROW(not_implemented_error, "Not supported");
  }

  /**
   * Virtual function to do all precomputations for bootstrapping using the linear method
   *
   * @param cc current cryptocontext
   * @param dim1 - inner dimension in the baby-step giant-step routine
   * @param slots - number of slots to be bootstrapped
   */
  virtual void EvalBTSetup(const CryptoContextImpl<Element>& cc, uint32_t dim1 = 0, uint32_t slots = 0) {
    OPENFHE_THROW(not_implemented_error, "Not supported");
  }

  /**
   * Virtual function to do all precomputations for bootstrapping using the FFT-like method
   *
   * @param cc - current cryptocontext
   * @param levelBudget - vector of budgets for the amount of levels in encoding and decoding
   * @param dim1 - vector of inner dimension in the baby-step giant-step routine for encoding and decoding
   * @param slots - number of slots to be bootstrapped
   *
   */
  virtual void EvalBTSetup(const CryptoContextImpl<Element>& cc,
                           const std::vector<uint32_t>& levelBudget = {5, 4},
                           const std::vector<uint32_t>& dim1 = {0, 0}, uint32_t slots = 0) {
    OPENFHE_THROW(not_implemented_error, "Not supported");
  }

  /**
   * Virtual function to do all precomputations for bootstrapping using the FFT-like method
   *
   * @param cc - current cryptocontext
         * @param debugFlag - set to 1 when debugging encoding/decoding only
   *
   */
  virtual void EvalBTPrecompute(const CryptoContextImpl<Element>& cc, uint32_t debugFlag = 0) {
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
  virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalBTKeyGen(const PrivateKey<Element> privateKey,
                                                                       int32_t bootstrapFlag = 0) {
    OPENFHE_THROW(not_implemented_error, "Not supported");
  }

  /**
   * Function to calculate Bootstrapping automorphism indices
   * @param bootstrapFlag
   * @param m
   * @return
   */
  virtual std::vector<int32_t> FindBTRotationIndices(int32_t bootstrapFlag = 0, uint32_t m = 0,
                                                uint32_t blockDimension = 0) {
    OPENFHE_THROW(not_implemented_error, "Not supported");
  }

  /**
   * Generate conjugation key
   * @param privateKey
   * @return
   */
  virtual EvalKey<Element> ConjugateKeyGen(const PrivateKey<Element> privateKey) const {
    OPENFHE_THROW(not_implemented_error, "Not supported");
  }

 /**
  * Function to get the number of rotations in one level for homomorphic encoding
  * @return the number of rotations
  */
  virtual uint32_t GetNumRotationsEnc() const {
        OPENFHE_THROW(not_implemented_error, "Not supported");
    }

  /**
   * Function to get the giant step in the baby-step giant-step strategy for homomorphic encoding
   * @return the giant step
   */
  virtual uint32_t GetGiantStepEnc() const {
      OPENFHE_THROW(not_implemented_error, "Not supported");
  }

  /**
   * Function to get the number of rotations in the remaining level for homomorphic encoding
   * @return the number of rotations
   */
  virtual uint32_t GetNumRotationsRemEnc() const {
      OPENFHE_THROW(not_implemented_error, "Not supported");
  }

  /**
   * Function to get the giant step in the baby-step giant-step strategy for the remaining level
   * for homomorphic encoding
   * @return the giant step
   */
  virtual uint32_t GetGiantStepRemEnc() const {
      OPENFHE_THROW(not_implemented_error, "Not supported");
  }

  /**
   * Function to get the number of rotations in one level for homomorphic decoding
   * @return the number of rotations
   */
  virtual uint32_t GetNumRotationsDec() const {
      OPENFHE_THROW(not_implemented_error, "Not supported");
  }

  /**
   * Function to get the giant step in the baby-step giant-step strategy for homomorphic decoding
   * @return the giant step
   */
  virtual uint32_t GetGiantStepDec() const {
      OPENFHE_THROW(not_implemented_error, "Not supported");
  }

  /**
   * Function to get the number of rotations in the remaining level for homomorphic decoding
   * @return the number of rotations
   */
  virtual uint32_t GetNumRotationsRemDec() const {
      OPENFHE_THROW(not_implemented_error, "Not supported");
  }

  /**
   * Function to get the giant step in the baby-step giant-step strategy for the remaining level
   * for homomorphic decoding
   * @return the giant step
   */
  virtual uint32_t GetGiantStepRemDec() const {
      OPENFHE_THROW(not_implemented_error, "Not supported");
  }

  /**
   * Function to get the FFT rotation indices
   * @return the number of rotation indices
   */
  virtual const std::vector<int32_t>& GetRotationIndicesBT() const {
      OPENFHE_THROW(not_implemented_error, "Not supported");
  }

  /**
   * Function to get the number of FFT rotation indices
   * @return the number of rotation indices
   */
  virtual uint32_t GetNumberOfRotationIndicesBT() const {
      OPENFHE_THROW(not_implemented_error, "Not supported");
  }

  /**
   * Function to get the linear evaluation rotation indices
   * @return the number of rotation indices
   */
  virtual const std::vector<int32_t>& GetRotationIndicesLT() const {
      OPENFHE_THROW(not_implemented_error, "Not supported");
  }

  /**
   * Function to get the number of linear evaluation rotation indices
   * @return the number of rotation indices
   */
  virtual uint32_t GetNumberOfRotationIndicesLT() const {
      OPENFHE_THROW(not_implemented_error, "Not supported");
  }
};

}  // namespace lbcrypto

#endif
