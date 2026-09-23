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

#ifndef SRC_PKE_INCLUDE_SCHEMEBASE_BASE_FHE_H_
#define SRC_PKE_INCLUDE_SCHEMEBASE_BASE_FHE_H_

#include <complex>
#include <cstdint>
#include <map>
#include <memory>
#include <tuple>
#include <utility>
#include <vector>

#include "binfhecontext.h"
#include "ciphertext-fwd.h"
#include "cryptocontext-fwd.h"
#include "key/evalkey-fwd.h"
#include "key/keypair.h"
#include "key/privatekey-fwd.h"
#include "scheme/scheme-swch-params.h"
#include "utils/exception.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Abstract interface class for LBC FHE (bootstrapping and scheme switching) algorithms
 * @tparam Element a ring element.
 */
template <class Element>
class FHEBase {
    // TODO: should we use just one error message instead of a few (see below)
    constexpr static std::string_view NOT_IMPLEMENTED_ERROR = "Not implemented for this scheme";
    constexpr static std::string_view NOT_SUPPORTED_ERROR = "Not supported for this scheme";
    constexpr static std::string_view NOT_SUPPORTED_SIMPLE_ERROR = "Not supported";

  public:
    virtual ~FHEBase() = default;

    /**
   * Clear scheme-level bootstrap precomputations, if this FHE component
   * caches any. The default implementation is a no-op.
   */
    virtual void ClearBootstrapPrecom() noexcept {}

    /**
   * Clear scheme-switch precomputations, if this FHE component owns any.
   * The default implementation is a no-op.
   */
    virtual void ClearSchemeSwitchPrecom() noexcept {}

    /**
   * Bootstrap functionality:
   * There are three methods that have to be called in this specific order:
   * 1. EvalBootstrapSetup: computes and encodes the coefficients for encoding and
   * decoding and stores the necessary parameters
   * 2. EvalBootstrapKeyGen: computes and stores the keys for rotations and conjugation
   * 3. EvalBootstrap: refreshes the given ciphertext
   */

    /**
   * Sets all parameters for both the linear and the FFT-like bootstrapping methods
   *
   * @param cc the crypto context the bootstrapping parameters are set up for
   * @param levelBudget - vector of budgets for the amount of levels in encoding
   * and decoding
   * @param dim1 - vector of inner dimension in the baby-step giant-step routine
   * for encoding and decoding
   * @param slots - number of slots to be bootstrapped
   * @param correctionFactor - value to rescale message by to improve precision. If set to 0, we use the default
   * logic. This value is only used when NATIVE_SIZE=64
   * @param precompute - flag specifying whether to precompute the plaintexts for encoding and decoding.
   * @param BTSlotsEncoding - flag specifying whether the approximate modular reduction happens over the message
   * being in slots or coefficients.
   */
    virtual void EvalBootstrapSetup(const CryptoContextImpl<Element>& cc, std::vector<uint32_t> levelBudget,
                                    std::vector<uint32_t> dim1, uint32_t slots, uint32_t correctionFactor,
                                    bool precompute, bool BTSlotsEncoding) {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
   * Virtual function to define the generation of all automorphism keys for EvalBT (with FFT evaluation).
   * EvalBTKeyGen uses the baby-step/giant-step strategy.
   *
   * @param privateKey private key.
   * @param slots - number of slots to be bootstrapped
   * @return the map of generated evaluation keys.
   */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> EvalBootstrapKeyGen(
            const PrivateKey<Element> privateKey, uint32_t slots) {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
   * Returns the eval-key map indices required to serialize bootstrap keys.
   *
   * @param cc crypto context.
   * @param slots - number of slots to be bootstrapped
   * @return the list of eval-key map indices.
   */
    virtual std::vector<uint32_t> EvalBootstrapKeyMapIndices(const CryptoContext<Element>& cc, uint32_t slots) {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
   * Computes the plaintexts for encoding and decoding for both linear and FFT-like methods. Supported in CKKS only.
   *
   * @param cc the crypto context the precomputation is done for
   * @param slots - number of slots to be bootstrapped
   */
    virtual void EvalBootstrapPrecompute(const CryptoContextImpl<Element>& cc, uint32_t slots) {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
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
   * @param numIterations number of iterations to run iterative bootstrapping (Meta-BTS). Increasing the iterations
   * increases the precision of bootstrapping.
   * @param precision precision of initial bootstrapping algorithm. This value is
   * determined by the user experimentally by first running EvalBootstrap with numIterations = 1 and
   * precision = 0 (unused).
   * @return the refreshed ciphertext.
   */
    virtual Ciphertext<Element> EvalBootstrap(ConstCiphertext<Element>& ciphertext, uint32_t numIterations,
                                              uint32_t precision) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
   * Bootstrapping variant that runs SlotsToCoeffs first and then the modulus raise, CoeffsToSlots and
   * the approximate modular reduction, so that the modular reduction is applied to the message as encoded
   * in the slots rather than in the coefficients (the BTSlotsEncoding mode of EvalBootstrapSetup).
   * EvalBootstrap dispatches here when the precomputation was set up with BTSlotsEncoding = true.
   * Supported in CKKS only.
   *
   * @param ciphertext the input ciphertext.
   * @param numIterations number of iterations to run iterative bootstrapping (Meta-BTS); 1 or 2.
   * @param precision precision of the initial bootstrapping algorithm (used only when numIterations = 2).
   * @return the refreshed ciphertext.
   */
    virtual Ciphertext<Element> EvalBootstrapStCFirst(ConstCiphertext<Element>& ciphertext, uint32_t numIterations,
                                                      uint32_t precision) const {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
   * Precomputes the encoding/decoding plaintexts for FE (Fourier extension) functional bootstrapping.
   * Supported only in CKKS, with HYBRID key switching. Shares the bootstrapping precomputation slot
   * for \p numSlots with EvalBootstrapSetup and EvalFBTSetup.
   *
   * @param cc the crypto context the precomputation is done for.
   * @param levelBudget levels spent on CoeffsToSlots and SlotsToCoeffs.
   * @param dim1 baby-step dimensions for the two linear transforms (0 = choose automatically).
   * @param numSlots number of slots to be bootstrapped (0 = full packing).
   */
    virtual void EvalFEFuncBootstrapSetup(const CryptoContextImpl<DCRTPoly>& cc,
                                          const std::vector<uint32_t>& levelBudget, const std::vector<uint32_t>& dim1,
                                          uint32_t numSlots) {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
   * Refreshes a ciphertext and evaluates a function on it in one pass, by evaluating the Fourier
   * extension of the function over the bootstrapped message. The input slot values must lie in
   * [-1/2, 1/2) and the result is real-valued. Supported only in CKKS.
   *
   * @param ciphertext the input ciphertext, with slot values in [-1/2, 1/2).
   * @param coefficients Fourier coefficients c_j of the target function, c_0 first.
   * @return the refreshed ciphertext holding the function values.
   */
    virtual Ciphertext<Element> EvalFEFuncBootstrap(ConstCiphertext<Element>& ciphertext,
                                                    const std::vector<std::complex<double>>& coefficients) const {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
   * Runs the function-independent part of FE functional bootstrapping (SlotsToCoeffs, modulus raise,
   * CoeffsToSlots and the complex exponential) and returns the powers of the complex exponential, so
   * that several functions can be evaluated on one bootstrapped ciphertext with
   * EvalFEFuncBootstrapWithPrecomp. Supported only in CKKS.
   *
   * @param ciphertext the input ciphertext, with slot values in [-1/2, 1/2).
   * @param coefficients Fourier coefficients of the longest series to be evaluated, c_0 first; they fix
   * the Paterson-Stockmeyer shape and thus the maximum degree of the series evaluated later.
   * @return the powers of the complex exponential.
   */
    virtual std::shared_ptr<seriesPowers<Element>> EvalFEFuncBootstrapPrecompute(
            ConstCiphertext<Element>& ciphertext, const std::vector<std::complex<double>>& coefficients) const {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
   * Evaluates the Fourier series of one function against the powers returned by
   * EvalFEFuncBootstrapPrecompute. Supported only in CKKS.
   *
   * @param powers the powers returned by EvalFEFuncBootstrapPrecompute.
   * @param coefficients Fourier coefficients c_j of this function, c_0 first.
   * @return the refreshed ciphertext holding the function values.
   */
    virtual Ciphertext<Element> EvalFEFuncBootstrapWithPrecomp(
            const std::shared_ptr<seriesPowers<Element>>& powers,
            const std::vector<std::complex<double>>& coefficients) const {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
   * Sets up CKKS functional bootstrapping of an RLWE ciphertext with plaintext modulus PIn that was
   * converted to a CKKS ciphertext (SchemeletRLWEMP::ConvertRLWEToCKKS): precomputes the homomorphic
   * encoding/decoding (CoeffsToSlots/SlotsToCoeffs) plaintexts for numSlots slots, including the
   * scalings needed to interpret the input and produce the output modulus. This overload takes
   * complex interpolation coefficients. Supported only in CKKS with HYBRID key switching.
   *
   * @param cc the crypto context the precomputation is done for.
   * @param coeffs trigonometric Hermite interpolation coefficients of the function to evaluate
   * (from GetHermiteTrigCoefficients, or [f(1), f(0)-f(1)] for a first-order Boolean function);
   * they determine the depth of the bootstrapping.
   * @param numSlots number of slots (0 = full packing).
   * @param PIn plaintext modulus of the input RLWE ciphertext.
   * @param POut plaintext modulus of the output.
   * @param Bigq ciphertext modulus of the input RLWE ciphertext.
   * @param pubKey public key of the CKKS crypto context (its element parameters are used).
   * @param dim1 baby-step dimensions for CoeffsToSlots and SlotsToCoeffs (0 = choose automatically).
   * @param levelBudget levels spent on CoeffsToSlots and SlotsToCoeffs.
   * @param lvlsAfterBoot number of levels that remain available after bootstrapping.
   * @param depthLeveledComputation depth of the leveled computation applied between
   * EvalFBTNoDecoding (or EvalMVBNoDecoding) and EvalHomDecoding.
   * @param order order of the trigonometric Hermite interpolation (1, 2 or 3).
   */
    virtual void EvalFBTSetup(const CryptoContextImpl<Element>& cc, const std::vector<std::complex<double>>& coeffs,
                              uint32_t numSlots, const BigInteger& PIn, const BigInteger& POut, const BigInteger& Bigq,
                              const PublicKey<DCRTPoly>& pubKey, const std::vector<uint32_t>& dim1,
                              const std::vector<uint32_t>& levelBudget, uint32_t lvlsAfterBoot = 0,
                              uint32_t depthLeveledComputation = 0, size_t order = 1) {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }
    /**
   * Sets up CKKS functional bootstrapping of an RLWE ciphertext with plaintext modulus PIn that was
   * converted to a CKKS ciphertext (SchemeletRLWEMP::ConvertRLWEToCKKS): precomputes the homomorphic
   * encoding/decoding (CoeffsToSlots/SlotsToCoeffs) plaintexts for numSlots slots, including the
   * scalings needed to interpret the input and produce the output modulus. This overload takes
   * integer interpolation coefficients. Supported only in CKKS with HYBRID key switching.
   *
   * @param cc the crypto context the precomputation is done for.
   * @param coeffs trigonometric Hermite interpolation coefficients of the function to evaluate
   * (from GetHermiteTrigCoefficients, or [f(1), f(0)-f(1)] for a first-order Boolean function);
   * they determine the depth of the bootstrapping.
   * @param numSlots number of slots (0 = full packing).
   * @param PIn plaintext modulus of the input RLWE ciphertext.
   * @param POut plaintext modulus of the output.
   * @param Bigq ciphertext modulus of the input RLWE ciphertext.
   * @param pubKey public key of the CKKS crypto context (its element parameters are used).
   * @param dim1 baby-step dimensions for CoeffsToSlots and SlotsToCoeffs (0 = choose automatically).
   * @param levelBudget levels spent on CoeffsToSlots and SlotsToCoeffs.
   * @param lvlsAfterBoot number of levels that remain available after bootstrapping.
   * @param depthLeveledComputation depth of the leveled computation applied between
   * EvalFBTNoDecoding (or EvalMVBNoDecoding) and EvalHomDecoding.
   * @param order order of the trigonometric Hermite interpolation (1, 2 or 3).
   */
    virtual void EvalFBTSetup(const CryptoContextImpl<Element>& cc, const std::vector<int64_t>& coeffs,
                              uint32_t numSlots, const BigInteger& PIn, const BigInteger& POut, const BigInteger& Bigq,
                              const PublicKey<DCRTPoly>& pubKey, const std::vector<uint32_t>& dim1,
                              const std::vector<uint32_t>& levelBudget, uint32_t lvlsAfterBoot = 0,
                              uint32_t depthLeveledComputation = 0, size_t order = 1) {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
   * Functional bootstrapping of a CKKS ciphertext obtained from an RLWE ciphertext with complex interpolation
   * coefficients: modulus raise, CoeffsToSlots, complex exponential and its powers, evaluation of the
   * trigonometric Hermite interpolation of the function, SlotsToCoeffs and the final scalings.
   * Supported only in CKKS; requires EvalFBTSetup.
   *
   * @param ciphertext the input ciphertext (from SchemeletRLWEMP::ConvertRLWEToCKKS).
   * @param coeffs trigonometric Hermite interpolation coefficients of the function.
   * @param digitBitSize bit size of the input plaintext modulus (or of the digit being processed in
   * chained multi-precision evaluation).
   * @param initialScaling scaling at which the input coefficients are given (the modulus of the
   * imported RLWE ciphertext).
   * @param postScaling integer the result is multiplied by after decoding (typically the scale by
   * which the Hermite coefficients were divided).
   * @param levelToReduce number of levels to drop before SlotsToCoeffs.
   * @param order order of the trigonometric Hermite interpolation (1, 2 or 3).
   * @return the ciphertext encrypting the function values in its coefficients.
   */
    virtual Ciphertext<Element> EvalFBT(ConstCiphertext<DCRTPoly>& ciphertext,
                                        const std::vector<std::complex<double>>& coeffs, uint32_t digitBitSize,
                                        const BigInteger& initialScaling, uint64_t postScaling,
                                        uint32_t levelToReduce = 0, size_t order = 1) {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }
    /**
   * Functional bootstrapping of a CKKS ciphertext obtained from an RLWE ciphertext with integer interpolation
   * coefficients: modulus raise, CoeffsToSlots, complex exponential and its powers, evaluation of the
   * trigonometric Hermite interpolation of the function, SlotsToCoeffs and the final scalings.
   * Supported only in CKKS; requires EvalFBTSetup.
   *
   * @param ciphertext the input ciphertext (from SchemeletRLWEMP::ConvertRLWEToCKKS).
   * @param coeffs trigonometric Hermite interpolation coefficients of the function.
   * @param digitBitSize bit size of the input plaintext modulus (or of the digit being processed in
   * chained multi-precision evaluation).
   * @param initialScaling scaling at which the input coefficients are given (the modulus of the
   * imported RLWE ciphertext).
   * @param postScaling integer the result is multiplied by after decoding (typically the scale by
   * which the Hermite coefficients were divided).
   * @param levelToReduce number of levels to drop before SlotsToCoeffs.
   * @param order order of the trigonometric Hermite interpolation (1, 2 or 3).
   * @return the ciphertext encrypting the function values in its coefficients.
   */
    virtual Ciphertext<Element> EvalFBT(ConstCiphertext<DCRTPoly>& ciphertext, const std::vector<int64_t>& coeffs,
                                        uint32_t digitBitSize, const BigInteger& initialScaling, uint64_t postScaling,
                                        uint32_t levelToReduce = 0, size_t order = 1) {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
   * Functional bootstrapping with complex interpolation coefficients that stops before SlotsToCoeffs: the
   * function values are left in the slots (bit-reversed if several levels are used for encoding) so that
   * a leveled computation can be applied before EvalHomDecoding. Supported only in CKKS.
   *
   * @param ciphertext the input ciphertext (from SchemeletRLWEMP::ConvertRLWEToCKKS).
   * @param coeffs trigonometric Hermite interpolation coefficients of the function.
   * @param digitBitSize bit size of the input plaintext modulus (or of the digit being processed in
   * chained multi-precision evaluation).
   * @param initialScaling scaling at which the input coefficients are given (the modulus of the
   * imported RLWE ciphertext).
   * @param order order of the trigonometric Hermite interpolation (1, 2 or 3).
   * @return the ciphertext with the function values in its slots.
   */
    virtual Ciphertext<Element> EvalFBTNoDecoding(ConstCiphertext<DCRTPoly>& ciphertext,
                                                  const std::vector<std::complex<double>>& coeffs,
                                                  uint32_t digitBitSize, const BigInteger& initialScaling,
                                                  size_t order = 1) {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }
    /**
   * Functional bootstrapping with integer interpolation coefficients that stops before SlotsToCoeffs: the
   * function values are left in the slots (bit-reversed if several levels are used for encoding) so that
   * a leveled computation can be applied before EvalHomDecoding. Supported only in CKKS.
   *
   * @param ciphertext the input ciphertext (from SchemeletRLWEMP::ConvertRLWEToCKKS).
   * @param coeffs trigonometric Hermite interpolation coefficients of the function.
   * @param digitBitSize bit size of the input plaintext modulus (or of the digit being processed in
   * chained multi-precision evaluation).
   * @param initialScaling scaling at which the input coefficients are given (the modulus of the
   * imported RLWE ciphertext).
   * @param order order of the trigonometric Hermite interpolation (1, 2 or 3).
   * @return the ciphertext with the function values in its slots.
   */
    virtual Ciphertext<Element> EvalFBTNoDecoding(ConstCiphertext<DCRTPoly>& ciphertext,
                                                  const std::vector<int64_t>& coeffs, uint32_t digitBitSize,
                                                  const BigInteger& initialScaling, size_t order = 1) {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
   * Homomorphic decoding step of functional bootstrapping: drops \p levelToReduce levels if requested,
   * applies SlotsToCoeffs, multiplies by \p postScaling and rescales to noise scale degree 1, producing
   * a ciphertext with the values in its coefficients (the RLWE convention). Supported only in CKKS.
   *
   * @param ciphertext the input ciphertext with the values in its slots.
   * @param postScaling integer the result is multiplied by after decoding (typically the scale by
   * which the Hermite coefficients were divided).
   * @param levelToReduce number of levels to drop before SlotsToCoeffs.
   * @return the ciphertext encrypting the values in its coefficients.
   */
    virtual Ciphertext<Element> EvalHomDecoding(ConstCiphertext<DCRTPoly>& ciphertext, uint64_t postScaling,
                                                uint32_t levelToReduce = 0) {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
   * Function-independent part of multi-value functional bootstrapping with complex interpolation coefficients:
   * modulus raise, CoeffsToSlots, complex exponential and its powers, which are shared by all functions
   * later evaluated with EvalMVB or EvalMVBNoDecoding. Those functions must be interpolated with the same
   * shape (plaintext modulus and order; for degree < 5 also the same sparsity) as \p coeffs.
   * Supported only in CKKS.
   *
   * @param ciphertext the input ciphertext (from SchemeletRLWEMP::ConvertRLWEToCKKS).
   * @param coeffs trigonometric Hermite interpolation coefficients fixing the shape of the series.
   * @param digitBitSize bit size of the input plaintext modulus (or of the digit being processed in
   * chained multi-precision evaluation).
   * @param initialScaling scaling at which the input coefficients are given (the modulus of the
   * imported RLWE ciphertext).
   * @param order order of the trigonometric Hermite interpolation (1, 2 or 3).
   * @return the powers of the complex exponential.
   */
    virtual std::shared_ptr<seriesPowers<DCRTPoly>> EvalMVBPrecompute(ConstCiphertext<DCRTPoly>& ciphertext,
                                                                      const std::vector<std::complex<double>>& coeffs,
                                                                      uint32_t digitBitSize,
                                                                      const BigInteger& initialScaling,
                                                                      size_t order = 1) {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
   * Function-independent part of multi-value functional bootstrapping with integer interpolation coefficients:
   * modulus raise, CoeffsToSlots, complex exponential and its powers, which are shared by all functions
   * later evaluated with EvalMVB or EvalMVBNoDecoding. Those functions must be interpolated with the same
   * shape (plaintext modulus and order; for degree < 5 also the same sparsity) as \p coeffs.
   * Supported only in CKKS.
   *
   * @param ciphertext the input ciphertext (from SchemeletRLWEMP::ConvertRLWEToCKKS).
   * @param coeffs trigonometric Hermite interpolation coefficients fixing the shape of the series.
   * @param digitBitSize bit size of the input plaintext modulus (or of the digit being processed in
   * chained multi-precision evaluation).
   * @param initialScaling scaling at which the input coefficients are given (the modulus of the
   * imported RLWE ciphertext).
   * @param order order of the trigonometric Hermite interpolation (1, 2 or 3).
   * @return the powers of the complex exponential.
   */
    virtual std::shared_ptr<seriesPowers<DCRTPoly>> EvalMVBPrecompute(ConstCiphertext<DCRTPoly>& ciphertext,
                                                                      const std::vector<int64_t>& coeffs,
                                                                      uint32_t digitBitSize,
                                                                      const BigInteger& initialScaling,
                                                                      size_t order = 1) {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
   * Evaluates one function with complex interpolation coefficients on the powers of the complex exponential
   * returned by EvalMVBPrecompute and applies the homomorphic decoding (EvalHomDecoding).
   * Supported only in CKKS.
   *
   * @param ciphertexts the powers of the complex exponential returned by EvalMVBPrecompute.
   * @param coeffs trigonometric Hermite interpolation coefficients of the function.
   * @param digitBitSize bit size of the input plaintext modulus (or of the digit being processed in
   * chained multi-precision evaluation).
   * @param postScaling integer the result is multiplied by after decoding (typically the scale by
   * which the Hermite coefficients were divided).
   * @param levelToReduce number of levels to drop before SlotsToCoeffs.
   * @param order order of the trigonometric Hermite interpolation (1, 2 or 3).
   * @return the ciphertext encrypting the function values in its coefficients.
   */
    virtual Ciphertext<Element> EvalMVB(const std::shared_ptr<seriesPowers<DCRTPoly>> ciphertexts,
                                        const std::vector<std::complex<double>>& coeffs, uint32_t digitBitSize,
                                        const uint64_t postScaling, uint32_t levelToReduce = 0, size_t order = 1) {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }
    /**
   * Evaluates one function with integer interpolation coefficients on the powers of the complex exponential
   * returned by EvalMVBPrecompute and applies the homomorphic decoding (EvalHomDecoding).
   * Supported only in CKKS.
   *
   * @param ciphertexts the powers of the complex exponential returned by EvalMVBPrecompute.
   * @param coeffs trigonometric Hermite interpolation coefficients of the function.
   * @param digitBitSize bit size of the input plaintext modulus (or of the digit being processed in
   * chained multi-precision evaluation).
   * @param postScaling integer the result is multiplied by after decoding (typically the scale by
   * which the Hermite coefficients were divided).
   * @param levelToReduce number of levels to drop before SlotsToCoeffs.
   * @param order order of the trigonometric Hermite interpolation (1, 2 or 3).
   * @return the ciphertext encrypting the function values in its coefficients.
   */
    virtual Ciphertext<Element> EvalMVB(const std::shared_ptr<seriesPowers<DCRTPoly>> ciphertexts,
                                        const std::vector<int64_t>& coeffs, uint32_t digitBitSize,
                                        const uint64_t postScaling, uint32_t levelToReduce = 0, size_t order = 1) {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
   * Evaluates one function with complex interpolation coefficients on the powers of the complex exponential
   * returned by EvalMVBPrecompute, leaving the function values in the slots for a leveled computation
   * before EvalHomDecoding. Supported only in CKKS.
   *
   * @param ciphertexts the powers of the complex exponential returned by EvalMVBPrecompute.
   * @param coeffs trigonometric Hermite interpolation coefficients of the function.
   * @param digitBitSize bit size of the input plaintext modulus (or of the digit being processed in
   * chained multi-precision evaluation).
   * @param order order of the trigonometric Hermite interpolation (1, 2 or 3).
   * @return the ciphertext with the function values in its slots.
   */
    virtual Ciphertext<Element> EvalMVBNoDecoding(const std::shared_ptr<seriesPowers<DCRTPoly>> ciphertexts,
                                                  const std::vector<std::complex<double>>& coeffs,
                                                  uint32_t digitBitSize, size_t order = 1) {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }
    /**
   * Evaluates one function with integer interpolation coefficients on the powers of the complex exponential
   * returned by EvalMVBPrecompute, leaving the function values in the slots for a leveled computation
   * before EvalHomDecoding. Supported only in CKKS.
   *
   * @param ciphertexts the powers of the complex exponential returned by EvalMVBPrecompute.
   * @param coeffs trigonometric Hermite interpolation coefficients of the function.
   * @param digitBitSize bit size of the input plaintext modulus (or of the digit being processed in
   * chained multi-precision evaluation).
   * @param order order of the trigonometric Hermite interpolation (1, 2 or 3).
   * @return the ciphertext with the function values in its slots.
   */
    virtual Ciphertext<Element> EvalMVBNoDecoding(const std::shared_ptr<seriesPowers<DCRTPoly>> ciphertexts,
                                                  const std::vector<int64_t>& coeffs, uint32_t digitBitSize,
                                                  size_t order = 1) {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
   * Evaluates a trigonometric Hermite interpolation with complex coefficients: approximates exp(i*Pi*x/2) on
   * [a,b] with the Chebyshev series \p coefficientsCheb, squares twice (double-angle) to obtain
   * exp(2*Pi*i*x), evaluates the power series \p coefficientsHerm in it and takes the real part.
   * Supported only in CKKS.
   *
   * @param ciphertext the input ciphertext.
   * @param coefficientsCheb Chebyshev coefficients of exp(i*Pi*x/2) on [a,b].
   * @param a lower bound of the argument for which the Chebyshev coefficients were found.
   * @param b upper bound of the argument for which the Chebyshev coefficients were found.
   * @param coefficientsHerm coefficients of the Hermite power series in exp(2*Pi*i*x) (divided by 2).
   * @param precomp reuse of the complex exponential cached in the bootstrapping precomputation: 0 or 1
   * compute it and store it in the first or second cache entry; 2 reuses the first entry and any other
   * value reuses the second entry without recomputing it.
   * @return the result of the evaluation.
   */
    virtual Ciphertext<DCRTPoly> EvalHermiteTrigSeries(ConstCiphertext<DCRTPoly>& ciphertext,
                                                       const std::vector<std::complex<double>>& coefficientsCheb,
                                                       double a, double b,
                                                       const std::vector<std::complex<double>>& coefficientsHerm,
                                                       size_t precomp = 0) {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }
    /**
   * Evaluates a trigonometric Hermite interpolation with integer coefficients: approximates exp(i*Pi*x/2) on
   * [a,b] with the Chebyshev series \p coefficientsCheb, squares twice (double-angle) to obtain
   * exp(2*Pi*i*x), evaluates the power series \p coefficientsHerm in it and takes the real part.
   * Supported only in CKKS.
   *
   * @param ciphertext the input ciphertext.
   * @param coefficientsCheb Chebyshev coefficients of exp(i*Pi*x/2) on [a,b].
   * @param a lower bound of the argument for which the Chebyshev coefficients were found.
   * @param b upper bound of the argument for which the Chebyshev coefficients were found.
   * @param coefficientsHerm coefficients of the Hermite power series in exp(2*Pi*i*x) (divided by 2).
   * @param precomp reuse of the complex exponential cached in the bootstrapping precomputation: 0 or 1
   * compute it and store it in the first or second cache entry; 2 reuses the first entry and any other
   * value reuses the second entry without recomputing it.
   * @return the result of the evaluation.
   */
    virtual Ciphertext<DCRTPoly> EvalHermiteTrigSeries(ConstCiphertext<DCRTPoly>& ciphertext,
                                                       const std::vector<std::complex<double>>& coefficientsCheb,
                                                       double a, double b, const std::vector<int64_t>& coefficientsHerm,
                                                       size_t precomp = 0) {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
   * Returns the correction factor by which the message is scaled during CKKS bootstrapping to improve
   * precision (see EvalBootstrapSetup).
   *
   * @return the correction factor.
   */
    virtual uint32_t GetCKKSBootCorrectionFactor() const {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
   * Sets the correction factor by which the message is scaled during CKKS bootstrapping to improve
   * precision (see EvalBootstrapSetup).
   *
   * @param cf the correction factor.
   */
    virtual void SetCKKSBootCorrectionFactor(uint32_t cf) {
        OPENFHE_THROW(NOT_SUPPORTED_SIMPLE_ERROR);
    }

    /**
   * Sets all parameters for switching from CKKS to FHEW
   *
   * @param params object holding all necessary parameters
   * @return the FHEW secret key
   */
    virtual LWEPrivateKey EvalCKKStoFHEWSetup(const SchSwchParams& params) {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
   * Virtual function to define the generation of all keys for scheme switching between CKKS and FHEW:
   * the rotation keys for the baby-step/giant-step strategy,
   * conjugation keys, switching key from CKKS to FHEW
   * @param keyPair CKKS key pair
   * @param lwesk FHEW secret key
   * @return the map of generated automorphism keys
   */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> EvalCKKStoFHEWKeyGen(const KeyPair<Element>& keyPair,
                                                                                       ConstLWEPrivateKey& lwesk) {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
   * Performs precomputations for the homomorphic decoding in CKKS. Given as a separate method than EvalCKKStoFHEWSetup
   * to allow the user to specify a scale that depends on the CKKS and FHEW cryptocontexts
   *
   * @param cc the CKKS cryptocontext from which to switch
   * @param scale factor with which to scale the matrix in the linear transform
   */
    virtual void EvalCKKStoFHEWPrecompute(const CryptoContextImpl<Element>& cc, double scale) {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
   * Performs the scheme switching on a CKKS ciphertext
   * @param ciphertext CKKS ciphertext to switch
   * @param numCtxts number of coefficients to extract from the CKKS ciphertext. If it is zero, it defaults to
   * number of slots
   * @return a vector of LWE ciphertexts of length the numCtxts
   */
    virtual std::vector<std::shared_ptr<LWECiphertextImpl>> EvalCKKStoFHEW(ConstCiphertext<Element> ciphertext,
                                                                           uint32_t numCtxts) {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
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
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
   * Generates all keys for scheme switching: the rotation keys for the baby-step/giant-step strategy
   * in the linear transform for the partial decryption, the switching key from FHEW to CKKS
   *
   * @param keyPair CKKS key pair
   * @param lwesk FHEW secret key
   * @param numSlots number of slots for the CKKS encryption of the FHEW secret key
   * @param numCtxts number of values to encrypt from the LWE ciphertexts in the new CKKS ciphertext
   * @param dim1 baby-step for the linear transform
   * @param L level on which the hom. decoding matrix should be. We want the hom. decoded ciphertext to be on the
   * last level
   * @return the map of generated automorphism keys
   */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> EvalFHEWtoCKKSKeyGen(
            const KeyPair<Element>& keyPair, ConstLWEPrivateKey& lwesk, uint32_t numSlots = 0, uint32_t numCtxts = 0,
            uint32_t dim1 = 0, uint32_t L = 0) {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
   * Performs precomputations for the homomorphic decoding in CKKS. Given as a separate method than
   * EvalSchemeSwitchingSetup
   * to allow the user to specify a scale that depends on the CKKS and FHEW cryptocontexts
   *
   * @param ccCKKS the CKKS cryptocontext from which to switch
   * @param pLWE the desired plaintext modulus for the new FHEW ciphertexts
   * @param scaleSign factor to multiply the CKKS ciphertext when switching to FHEW in case the messages are too small;
   * the resulting FHEW ciphertexts will encrypt values modulo pLWE, so scaleSign should account for this
   * @param unit whether the input messages are normalized to the unit circle
   */
    virtual void EvalCompareSwitchPrecompute(const CryptoContextImpl<Element>& ccCKKS, uint32_t pLWE, double scaleSign,
                                             bool unit) {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
   * Performs the scheme switching on a vector of FHEW ciphertexts
   *
   * @param LWECiphertexts FHEW/LWE ciphertexts to switch
   * @param numCtxts number of values to encrypt from the LWE ciphertexts in the new CKKS ciphertext
   * @param numSlots number of slots to encode in the new CKKS/RLWE ciphertext
   * @param p plaintext modulus to use to decide postscaling, by default p = 4
   * @param pmin lower bound of the plaintext space of the resulting messages (by default 0, assuming
   * the LWE ciphertext had plaintext modulus p = 4 and only bits were encrypted)
   * @param pmax upper bound of the plaintext space of the resulting messages (by default 2)
   * @param dim1 baby-step for the linear transform, necessary only for argmin
   * @return a CKKS ciphertext encrypting in its slots the messages in the LWE ciphertexts
   */
    virtual Ciphertext<Element> EvalFHEWtoCKKS(std::vector<std::shared_ptr<LWECiphertextImpl>>& LWECiphertexts,
                                               uint32_t numCtxts, uint32_t numSlots, uint32_t p, double pmin,
                                               double pmax, uint32_t dim1) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
   * Sets all parameters for switching from CKKS to FHEW and back
   *
   * @param params object holding all necessary parameters
   * @return the FHEW secret key
   * TODO: add an overload for when BinFHEContext is already generated and fed as a parameter
   */
    virtual LWEPrivateKey EvalSchemeSwitchingSetup(const SchSwchParams& params) {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
   * Generates all keys for scheme switching: the rotation keys for the baby-step/giant-step strategy
   * in the linear transform for the homomorphic encoding and partial decryption, the switching key from
   * FHEW to CKKS
   *
   * @param keyPair CKKS key pair
   * @param lwesk FHEW secret key
   * @return the map of generated automorphism keys
   */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> EvalSchemeSwitchingKeyGen(
            const KeyPair<Element>& keyPair, ConstLWEPrivateKey& lwesk) {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
   * Performs the scheme switching on the difference of two CKKS ciphertexts to compare, evaluates the sign function
   * over the resulting FHEW ciphertexts, then performs the scheme switching back to a CKKS ciphertext
   *
   * @param ciphertext1 first CKKS ciphertext of messages that need to be compared
   * @param ciphertext2 second CKKS ciphertext of messages that need to be compared
   * @param numCtxts number of coefficients to extract from the CKKS ciphertext. If it is zero, it defaults to
   * number of slots
   * @param numSlots number of slots to encode the new CKKS ciphertext with
   * @param pLWE the desired plaintext modulus for the new FHEW ciphertexts. If it is zero, it defaults to the
   * large precision
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
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
   * Computes the minimum and argument of the first numValues packed in a CKKS ciphertext via repeated
   * scheme switchings to FHEW and back.
   *
   * @param ciphertext CKKS ciphertexts of values that need to be compared
   * @param publicKey public key of the CKKS cryptocontext
   * @param numValues number of values to extract from the CKKS ciphertext. We always assume for the moment
   * numValues is a power of two
   * @param numSlots number of slots to encode the new CKKS ciphertext with
   * @param pLWE the desired plaintext modulus for the new FHEW ciphertexts
   * @param scaleSign factor to multiply the CKKS ciphertext when switching to FHEW in case the messages are too small;
   * the resulting FHEW ciphertexts will encrypt values modulo pLWE, so scaleSign should account for this
   * pLWE and scaleSign are given here only if the homomorphic decoding matrix is not scaled with the desired values
   * @return a vector of two CKKS ciphertexts where the first encrypts the minimum value and the second encrypts the
   * index (in the representation specified by oneHot). The ciphertexts have junk after the first slot in the
   * first ciphertext
   * and after numValues in the second ciphertext if oneHot=true and after the first slot if oneHot=false.
   */
    virtual std::vector<Ciphertext<Element>> EvalMinSchemeSwitching(ConstCiphertext<Element> ciphertext,
                                                                    PublicKey<Element> publicKey, uint32_t numValues,
                                                                    uint32_t numSlots, uint32_t pLWE,
                                                                    double scaleSign) {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Computes the minimum and argument of the first numValues packed in a CKKS ciphertext.
     * Performs more operations in FHEW than in CKKS. Slightly better precision but slower.
     *
     * @param ciphertext CKKS ciphertext of values that need to be compared
     * @param publicKey public key of the CKKS cryptocontext
     * @param numValues number of values to extract from the CKKS ciphertext
     * @param numSlots number of slots to encode the new CKKS ciphertext with
     * @param pLWE the desired plaintext modulus for the new FHEW ciphertexts
     * @param scaleSign factor to multiply the CKKS ciphertext when switching to FHEW
     * @return a vector of two CKKS ciphertexts: [min, argmin]
    */
    virtual std::vector<Ciphertext<Element>> EvalMinSchemeSwitchingAlt(ConstCiphertext<Element> ciphertext,
                                                                       PublicKey<Element> publicKey, uint32_t numValues,
                                                                       uint32_t numSlots, uint32_t pLWE,
                                                                       double scaleSign) {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
   * Computes the maximum and argument of the first numValues packed in a CKKS ciphertext via repeated
   * scheme switchings to FHEW and back.
   *
   * @param ciphertext CKKS ciphertexts of values that need to be compared
   * @param publicKey public key of the CKKS cryptocontext
   * @param numValues number of values to extract from the CKKS ciphertext. We always assume for the moment
   * numValues is a power of two
   * @param numSlots number of slots to encode the new CKKS ciphertext with
   * @param pLWE the desired plaintext modulus for the new FHEW ciphertexts
   * @param scaleSign factor to multiply the CKKS ciphertext when switching to FHEW in case the messages are too small;
   * the resulting FHEW ciphertexts will encrypt values modulo pLWE, so scaleSign should account for this
   * pLWE and scaleSign are given here only if the homomorphic decoding matrix is not scaled with the desired values
   * @return a vector of two CKKS ciphertexts where the first encrypts the maximum value and the second encrypts the
   * index (in the representation specified by oneHot). The ciphertexts have junk after the first slot in the
   * first ciphertext
   * and after numValues in the second ciphertext if oneHot=true and after the first slot if oneHot=false.
   */
    virtual std::vector<Ciphertext<Element>> EvalMaxSchemeSwitching(ConstCiphertext<Element> ciphertext,
                                                                    PublicKey<Element> publicKey, uint32_t numValues,
                                                                    uint32_t numSlots, uint32_t pLWE,
                                                                    double scaleSign) {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Computes the maximum and argument of the first numValues packed in a CKKS ciphertext.
     * Performs more operations in FHEW than in CKKS. Slightly better precision but slower.
     *
     * @param ciphertext CKKS ciphertext of values that need to be compared
     * @param publicKey public key of the CKKS cryptocontext
     * @param numValues number of values to extract from the CKKS ciphertext
     * @param numSlots number of slots to encode the new CKKS ciphertext with
     * @param pLWE the desired plaintext modulus for the new FHEW ciphertexts
     * @param scaleSign factor to multiply the CKKS ciphertext when switching to FHEW
     * @return a vector of two CKKS ciphertexts: [max, argmax]
    */
    virtual std::vector<Ciphertext<Element>> EvalMaxSchemeSwitchingAlt(ConstCiphertext<Element> ciphertext,
                                                                       PublicKey<Element> publicKey, uint32_t numValues,
                                                                       uint32_t numSlots, uint32_t pLWE,
                                                                       double scaleSign) {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Returns the BinFHE crypto context used in scheme switching.
     *
     * @return the BinFHE crypto context.
     */
    virtual std::shared_ptr<lbcrypto::BinFHEContext> GetBinCCForSchemeSwitch() {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Sets the BinFHE crypto context used in scheme switching.
     *
     * @param ccLWE the BinFHE crypto context.
     */
    virtual void SetBinCCForSchemeSwitch(std::shared_ptr<lbcrypto::BinFHEContext> ccLWE) {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Returns the FHEW-to-CKKS switching key, stored as a CKKS ciphertext.
     *
     * @return the switching key ciphertext.
     */
    virtual Ciphertext<Element> GetSwkFC() {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Sets the FHEW-to-CKKS switching key, stored as a CKKS ciphertext.
     *
     * @param FHEWtoCKKSswk the switching key ciphertext.
     */
    virtual void SetSwkFC(Ciphertext<Element> FHEWtoCKKSswk) {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
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

#endif  // SRC_PKE_INCLUDE_SCHEMEBASE_BASE_FHE_H_
