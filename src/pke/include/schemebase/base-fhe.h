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

#include "key/privatekey-fwd.h"
#include "key/evalkey-fwd.h"
#include "ciphertext-fwd.h"
#include "cryptocontext-fwd.h"
#include "utils/exception.h"

// Andreea: Temporary include for the SecurityLevel, BINFHE_PARAMSET
#include "lattice/stdlatticeparms.h"
// #include "../../binfhe/include/binfhe-constants.h"
#include "../../binfhe/include/binfhecontext.h"
#include "key/keypair.h"

#include <memory>
#include <vector>
#include <map>
#include <utility>

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
   * 1. EvalBootstrapSetup: computes and encodes the coefficients for encoding and
   * decoding and stores the necessary parameters
   * 2. EvalBootstrapKeyGen: computes and stores the keys for rotations and conjugation
   * 3. EvalBootstrap: refreshes the given ciphertext
   */

    /**
   * Sets all parameters for the linear method for the FFT-like method
   *
   * @param levelBudget - vector of budgets for the amount of levels in encoding
   * and decoding
   * @param dim1 - vector of inner dimension in the baby-step giant-step routine
   * for encoding and decoding
   * @param slots - number of slots to be bootstrapped
   * @param correctionFactor - value to rescale message by to improve precision. If set to 0, we use the default logic. This value is only used when NATIVE_SIZE=64.
   */
    virtual void EvalBootstrapSetup(const CryptoContextImpl<Element>& cc, std::vector<uint32_t> levelBudget,
                                    std::vector<uint32_t> dim1, uint32_t slots, uint32_t correctionFactor) {
        OPENFHE_THROW(not_implemented_error, "Not supported");
    }

    /**
   * Virtual function to define the generation of all automorphism keys for EvalBT (with FFT evaluation).
   * EvalBTKeyGen uses the baby-step/giant-step strategy.
   *
   * @param privateKey private key.
   * @param slots - number of slots to be bootstrapped
   * @return the dictionary of evaluation key indices.
   */
    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalBootstrapKeyGen(const PrivateKey<Element> privateKey,
                                                                                   uint32_t slots) {
        OPENFHE_THROW(not_implemented_error, "Not supported");
    }

    /**
   * Defines the bootstrapping evaluation of ciphertext
   *
   * The flavor of bootstrapping that uses the numIterations and precision parameters is described
   * in the Meta-BTS paper.
   * Source: Bae Y., Cheon J., Cho W., Kim J., and Kim T. META-BTS: Bootstrapping Precision
   * Beyond the Limit. Cryptology ePrint Archive, Report
   * 2022/1167. (https://eprint.iacr.org/2022/1167.pdf)
   *
   * @param ciphertext the input ciphertext.
   * @param numIterations number of iterations to run iterative bootstrapping (Meta-BTS). Increasing the iterations increases the precision of bootstrapping.
   * @param precision precision of initial bootstrapping algorithm. This value is
   * determined by the user experimentally by first running EvalBootstrap with numIterations = 1 and precision = 0 (unused).
   * @return the refreshed ciphertext.
   */
    virtual Ciphertext<Element> EvalBootstrap(ConstCiphertext<Element> ciphertext, uint32_t numIterations,
                                              uint32_t precision) const {
        OPENFHE_THROW(not_implemented_error, "EvalBootstrap is not implemented for this scheme");
    }

    /**
   * Scheme switching functionality: // Andreea: to modify
   */

    virtual void EvalSchemeSwitchingSetup(const CryptoContextImpl<Element>& cc, std::vector<uint32_t> levelBudget,
                                          std::vector<uint32_t> dim1, uint32_t slots, uint32_t correctionFactor) {
        OPENFHE_THROW(not_implemented_error, "Not supported");
    }

    virtual void EvalSchemeSwitchingKeyGen(const PrivateKey<Element> privateKey, uint32_t slots) {
        OPENFHE_THROW(not_implemented_error, "Not supported");
    }

    virtual void EvalSchemeSwitching(ConstCiphertext<Element> ciphertext, uint32_t numIterations,
                                     uint32_t precision) const {
        OPENFHE_THROW(not_implemented_error, "EvalSchemeSwitching is not implemented for this scheme");
    }

    /**
   * Sets all parameters for switching from CKKS to FHEW
   *
   * @param dynamic whether to use dynamic mode for FHEW
   * @param logQ preicions of large-precision sign evaluation based on FHEW
   * @param sl security level
   * @param numSlotsCKKS number of slots in CKKS encryption
   * @return the FHEW cryptocontext and its secret key (if a method from extracting the binfhecontext
   * from the secret key is created, then we can only return the secret key)
   */
    virtual std::pair<BinFHEContext, LWEPrivateKey> EvalCKKStoFHEWSetup(const CryptoContextImpl<DCRTPoly>& cc,
                                                                        bool dynamic, uint32_t logQ, SecurityLevel sl,
                                                                        uint32_t numSlotsCKKS) {
        OPENFHE_THROW(not_implemented_error, "Not supported");
    }

    /**
   * Virtual function to define the generation of all keys for scheme switching between CKKS and FHEW:
   * the rotation keys for the baby-step/giant-step strategy,
   * conjugation keys, switching key from CKKS to FHEW
   * @param keypair CKKS key pair
   * @param lwesk FHEW secret key   */
    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalCKKStoFHEWKeyGen(const KeyPair<Element>& keyPair,
                                                                                    LWEPrivateKey& lwesk) {
        OPENFHE_THROW(not_implemented_error, "Not supported");
    }

    /**
   * Performs the scheme switching on a CKKS ciphertext
   * @param ciphertext CKKS ciphertext to switch
   * @param scale factor to multiply the plaintext encoded into the ciphertext
   * @param numCtxts number of coefficients to extract from the CKKS ciphertext. If it is zero, it defaults to number of slots
   * @return a vector of LWE ciphertexts of length the numCtxts
   */
    virtual std::vector<std::shared_ptr<LWECiphertextImpl>> EvalCKKStoFHEW(ConstCiphertext<Element> ciphertext,
                                                                           double scale, uint32_t numCtxts) const {
        OPENFHE_THROW(not_implemented_error, "EvalCKKStoFHEW is not implemented for this scheme");
    }
};

}  // namespace lbcrypto

#endif
