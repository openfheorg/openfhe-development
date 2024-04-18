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

#include "binfhecontext.h"
#include "key/keypair.h"
#include "scheme/scheme-swch-params.h"

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
   * @param correctionFactor - value to rescale message by to improve precision. If set to 0, we use the default logic. This value is only used when NATIVE_SIZE=64
   * @param precompute - flag specifying whether to precompute the plaintexts for encoding and decoding.
   */
    virtual void EvalBootstrapSetup(const CryptoContextImpl<Element>& cc, std::vector<uint32_t> levelBudget,
                                    std::vector<uint32_t> dim1, uint32_t slots, uint32_t correctionFactor,
                                    bool precompute) {
        OPENFHE_THROW("Not supported");
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
        OPENFHE_THROW("Not supported");
    }

    /**
   * Computes the plaintexts for encoding and decoding for both linear and FFT-like methods. Supported in CKKS only.
   *
   * @param slots - number of slots to be bootstrapped
   */
    virtual void EvalBootstrapPrecompute(const CryptoContextImpl<Element>& cc, uint32_t slots) {
        OPENFHE_THROW("Not supported");
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
        OPENFHE_THROW("EvalBootstrap is not implemented for this scheme");
    }

    /**
   * Sets all parameters for switching from CKKS to FHEW
   *
   * @param params objects holding all necessary paramters
   * @return the FHEW secret key
   */
    virtual LWEPrivateKey EvalCKKStoFHEWSetup(const SchSwchParams& params) {
        OPENFHE_THROW("EvalCKKStoFHEWSetup is not supported for this scheme");
    }

    /**
   * Virtual function to define the generation of all keys for scheme switching between CKKS and FHEW:
   * the rotation keys for the baby-step/giant-step strategy,
   * conjugation keys, switching key from CKKS to FHEW
   * @param keypair CKKS key pair
   * @param lwesk FHEW secret key
   */
    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalCKKStoFHEWKeyGen(const KeyPair<Element>& keyPair,
                                                                                    ConstLWEPrivateKey& lwesk) {
        OPENFHE_THROW("EvalCKKStoFHEWKeyGen is not supported for this scheme");
    }

    /**
   * Performs precomputations for the homomorphic decoding in CKKS. Given as a separate method than EvalCKKStoFHEWSetup
   * to allow the user to specify a scale that depends on the CKKS and FHEW cryptocontexts
   *
   * @param cc the CKKS cryptocontext from which to switch
   * @param scale factor with which to scale the matrix in the linear transform
   * @param dim1 baby-step for the linear transform
   * @param L level on which the hom. decoding matrix should be. We want the hom. decoded ciphertext to be on the last level
   */
    virtual void EvalCKKStoFHEWPrecompute(const CryptoContextImpl<Element>& cc, double scale) {
        OPENFHE_THROW("EvalCKKStoFHEWPrecompute is not supported for this scheme");
    }

    /**
   * Performs the scheme switching on a CKKS ciphertext
   * @param ciphertext CKKS ciphertext to switch
   * @param numCtxts number of coefficients to extract from the CKKS ciphertext. If it is zero, it defaults to number of slots
   * @return a vector of LWE ciphertexts of length the numCtxts
   */
    virtual std::vector<std::shared_ptr<LWECiphertextImpl>> EvalCKKStoFHEW(ConstCiphertext<Element> ciphertext,
                                                                           uint32_t numCtxts) {
        OPENFHE_THROW("EvalCKKStoFHEW is not implemented for this scheme");
    }

    /**
   * Sets all parameters for switching from FHEW to CKKS. The CKKS cryptocontext to switch to is
   * already generated.
   *
   * @param ccCKKS the CKKS cryptocontext to switch to
   * @param ccLWE the FHEW cryptocontext from which to switch
   * @param numSlotsCKKS number of FHEW ciphertexts that becomes the number of slots in CKKS encryption
   * @param logQ the logarithm of a ciphertext modulus in FHEW
   */
    virtual void EvalFHEWtoCKKSSetup(const CryptoContextImpl<Element>& ccCKKS,
                                     const std::shared_ptr<BinFHEContext>& ccLWE, uint32_t numSlotsCKKS,
                                     uint32_t logQ) {
        OPENFHE_THROW("EvalFHEWtoCKKSSetup is not supported for this scheme");
    }

    /**
   * Generates all keys for scheme switching: the rotation keys for the baby-step/giant-step strategy
   * in the linear transform for the partial decryption, the switching key from FHEW to CKKS
   *
   * @param keypair CKKS key pair
   * @param lwesk FHEW secret key
   * @param numSlots number of slots for the CKKS encryption of the FHEW secret key
   * @param numCtxts number of values to encrypt from the LWE ciphertexts in the new CKKS ciphertext
   * @param dim1 baby-step for the linear transform
   * @param L level on which the hom. decoding matrix should be. We want the hom. decoded ciphertext to be on the last level
   */
    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalFHEWtoCKKSKeyGen(const KeyPair<Element>& keyPair,
                                                                                    ConstLWEPrivateKey& lwesk,
                                                                                    uint32_t numSlots = 0,
                                                                                    uint32_t numCtxts = 0,
                                                                                    uint32_t dim1 = 0, uint32_t L = 0) {
        OPENFHE_THROW("EvalFHEWtoCKKSKeyGen is not supported for this scheme");
    }

    /**
   * Performs precomputations for the homomorphic decoding in CKKS. Given as a separate method than EvalSchemeSwitchingSetup
   * to allow the user to specify a scale that depends on the CKKS and FHEW cryptocontexts
   *
   * @param cc the CKKS cryptocontext from which to switch
   * @param pLWE the desired plaintext modulus for the new FHEW ciphertexts
   * @param scaleSign factor to multiply the CKKS ciphertext when switching to FHEW in case the messages are too small;
   * the resulting FHEW ciphertexts will encrypt values modulo pLWE, so scaleSign should account for this
   * @param unit whether the input messages are normalized to the unit circle
   */
    virtual void EvalCompareSwitchPrecompute(const CryptoContextImpl<Element>& ccCKKS, uint32_t pLWE, double scaleSign,
                                             bool unit) {
        OPENFHE_THROW(not_implemented_error, "EvalCompareSwitchPrecompute is not supported for this scheme");
    }

    /**
   * Performs the scheme switching on a vector of FHEW ciphertexts
   *
   * @param LWECiphertexts FHEW/LWE ciphertexts to switch
   * @param numCtxts number of values to encrypt from the LWE ciphertexts in the new CKKS ciphertext
   * @param numSlots number of slots to encode in the new CKKS/RLWE ciphertext
   * @param p plaintext modulus to use to decide postscaling, by default p = 4
   * @param pmin, pmax plaintext space of the resulting messages (by default [0,2] assuming
   * the LWE ciphertext had plaintext modulus p = 4 and only bits were encrypted)
   * @param dim1 baby-step for the linear transform, necessary only for argmin
   * @return a CKKS ciphertext encrypting in its slots the messages in the LWE ciphertexts
   */
    virtual Ciphertext<Element> EvalFHEWtoCKKS(std::vector<std::shared_ptr<LWECiphertextImpl>>& LWECiphertexts,
                                               uint32_t numCtxts, uint32_t numSlots, uint32_t p, double pmin,
                                               double pmax, uint32_t dim1) const {
        OPENFHE_THROW("EvalFHEWtoCKKS is not implemented for this scheme");
    }

    /**
   * Sets all parameters for switching from CKKS to FHEW and back
   *
   * @param params objects holding all necessary paramters
   * @return the FHEW secret key
   * TODO: add an overload for when BinFHEContext is already generated and fed as a parameter
   */
    virtual LWEPrivateKey EvalSchemeSwitchingSetup(const SchSwchParams& params) {
        OPENFHE_THROW("EvalSchemeSwitchingSetup is not supported for this scheme");
    }

    /**
   * Generates all keys for scheme switching: the rotation keys for the baby-step/giant-step strategy
   * in the linear transform for the homomorphic encoding and partial decryption, the switching key from
   * FHEW to CKKS
   *
   * @param keypair CKKS key pair
   * @param lwesk FHEW secret key
   */
    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalSchemeSwitchingKeyGen(
        const KeyPair<Element>& keyPair, ConstLWEPrivateKey& lwesk) {
        OPENFHE_THROW("EvalSchemeSwitchingKeyGen is not supported for this scheme");
    }

    /**
   * Performs the scheme switching on the difference of two CKKS ciphertexts to compare, evaluates the sign function
   * over the resulting FHEW ciphertexts, then performs the scheme switching back to a CKKS ciphertext
   *
   * @param ciphertext1, ciphertext2 CKKS ciphertexts of messages that need to be compared
   * @param numCtxts number of coefficients to extract from the CKKS ciphertext. If it is zero, it defaults to number of slots
   * @param numSlots number of slots to encode the new CKKS ciphertext with
   * @param pLWE the desired plaintext modulus for the new FHEW ciphertexts. If it is zero, it defaults to the large precision
   * plaintext modulus Q/2beta
   * @param scaleSign factor to multiply the CKKS ciphertext when switching to FHEW in case the messages are too small;
   * the resulting FHEW ciphertexts will encrypt values modulo pLWE, so scaleSign should account for this
   * @param unit whether the input messages are normalized to the unit circle
   * @return a CKKS ciphertext encrypting in its slots the sign of  messages in the LWE ciphertexts
   */
    virtual Ciphertext<Element> EvalCompareSchemeSwitching(ConstCiphertext<Element> ciphertext1,
                                                           ConstCiphertext<Element> ciphertext2, uint32_t numCtxts,
                                                           uint32_t numSlots, uint32_t pLWE, double scaleSign,
                                                           bool unit) {
        OPENFHE_THROW("EvalCompareSchemeSwitching is not supported for this scheme");
    }

    /**
   * Computes the minimum and argument of the first numValues packed in a CKKS ciphertext via repeated
   * scheme switchings to FHEW and back.
   *
   * @param ciphertext CKKS ciphertexts of values that need to be compared
   * @param publicKey public key of the CKKS cryptocontext
   * @param numValues number of values to extract from the CKKS ciphertext. We always assume for the moment numValues is a power of two
   * @param numSlots number of slots to encode the new CKKS ciphertext with
   * @param pLWE the desired plaintext modulus for the new FHEW ciphertexts
   * @param scaleSign factor to multiply the CKKS ciphertext when switching to FHEW in case the messages are too small;
   * the resulting FHEW ciphertexts will encrypt values modulo pLWE, so scaleSign should account for this
   * pLWE and scaleSign are given here only if the homomorphic decoding matrix is not scaled with the desired values
   * @return a vector of two CKKS ciphertexts where the first encrypts the minimum value and the second encrypts the
   * index (in the representation specified by oneHot). The ciphertexts have junk after the first slot in the first ciphertext
   * and after numValues in the second ciphertext if oneHot=true and after the first slot if oneHot=false.
   */
    virtual std::vector<Ciphertext<Element>> EvalMinSchemeSwitching(ConstCiphertext<Element> ciphertext,
                                                                    PublicKey<Element> publicKey, uint32_t numValues,
                                                                    uint32_t numSlots, uint32_t pLWE,
                                                                    double scaleSign) {
        OPENFHE_THROW("EvalMinSchemeSwitching is not supported for this scheme");
    }

    /**
     * Performs more operations in FHEW than in CKKS. Slightly better precision but slower.
    */
    virtual std::vector<Ciphertext<Element>> EvalMinSchemeSwitchingAlt(ConstCiphertext<Element> ciphertext,
                                                                       PublicKey<Element> publicKey, uint32_t numValues,
                                                                       uint32_t numSlots, uint32_t pLWE,
                                                                       double scaleSign) {
        OPENFHE_THROW("EvalMinSchemeSwitchingAlt is not supported for this scheme");
    }

    /**
   * Computes the maximum and argument of the first numValues packed in a CKKS ciphertext via repeated
   * scheme switchings to FHEW and back.
   *
   * @param ciphertext CKKS ciphertexts of values that need to be compared
   * @param publicKey public key of the CKKS cryptocontext
   * @param numValues number of values to extract from the CKKS ciphertext. We always assume for the moment numValues is a power of two
   * @param numSlots number of slots to encode the new CKKS ciphertext with
   * @param pLWE the desired plaintext modulus for the new FHEW ciphertexts
   * @param scaleSign factor to multiply the CKKS ciphertext when switching to FHEW in case the messages are too small;
   * the resulting FHEW ciphertexts will encrypt values modulo pLWE, so scaleSign should account for this
   * pLWE and scaleSign are given here only if the homomorphic decoding matrix is not scaled with the desired values
   * @return a vector of two CKKS ciphertexts where the first encrypts the maximum value and the second encrypts the
   * index (in the representation specified by oneHot). The ciphertexts have junk after the first slot in the first ciphertext
   * and after numValues in the second ciphertext if oneHot=true and after the first slot if oneHot=false.
   */
    virtual std::vector<Ciphertext<Element>> EvalMaxSchemeSwitching(ConstCiphertext<Element> ciphertext,
                                                                    PublicKey<Element> publicKey, uint32_t numValues,
                                                                    uint32_t numSlots, uint32_t pLWE,
                                                                    double scaleSign) {
        OPENFHE_THROW("EvalMaxSchemeSwitching is not supported for this scheme");
    }

    /**
     * Performs more operations in FHEW than in CKKS. Slightly better precision but slower.
    */
    virtual std::vector<Ciphertext<Element>> EvalMaxSchemeSwitchingAlt(ConstCiphertext<Element> ciphertext,
                                                                       PublicKey<Element> publicKey, uint32_t numValues,
                                                                       uint32_t numSlots, uint32_t pLWE,
                                                                       double scaleSign) {
        OPENFHE_THROW("EvalMaxSchemeSwitchingAlt is not supported for this scheme");
    }

    /**
     * Getter and setter for the binFHE cryptocontext used in scheme switching
    */
    virtual std::shared_ptr<lbcrypto::BinFHEContext> GetBinCCForSchemeSwitch() {
        OPENFHE_THROW("GetBinCCForSchemeSwitch is not supported for this scheme");
    }
    virtual void SetBinCCForSchemeSwitch(std::shared_ptr<lbcrypto::BinFHEContext> ccLWE) {
        OPENFHE_THROW("SetBinCCForSchemeSwitch is not supported for this scheme");
    }

    /**
     * Getter and setter for the switching key between FHEW to CKKS
    */
    virtual Ciphertext<Element> GetSwkFC() {
        OPENFHE_THROW("GetSwkFC is not supported for this scheme");
    }
    virtual void SetSwkFC(Ciphertext<Element> FHEWtoCKKSswk) {
        OPENFHE_THROW("SetSwkFC is not supported for this scheme");
    }

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar) const {}

    template <class Archive>
    void load(Archive& ar) {}
};

}  // namespace lbcrypto

#endif
