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

#ifndef SRC_PKE_INCLUDE_SCHEME_CKKSRNS_CKKSRNS_ADVANCEDSHE_H_
#define SRC_PKE_INCLUDE_SCHEME_CKKSRNS_CKKSRNS_ADVANCEDSHE_H_

#include <complex>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "schemerns/rns-advancedshe.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief CKKS implementation of the advanced SHE capability: linear weighted sums and evaluation of polynomials
 * in the power and Chebyshev bases with real, complex or integer coefficients. The polynomial evaluation methods
 * use a binary tree of powers (or Chebyshev polynomials) below degree 5 and the Paterson-Stockmeyer algorithm
 * otherwise, and rescale automatically according to the scaling technique.
 */
class AdvancedSHECKKSRNS : public AdvancedSHERNS {
  public:
    virtual ~AdvancedSHECKKSRNS() = default;

    //------------------------------------------------------------------------------
    // LINEAR WEIGHTED SUM
    //------------------------------------------------------------------------------

    Ciphertext<DCRTPoly> EvalLinearWSum(std::vector<ReadOnlyCiphertext<DCRTPoly>>& ciphertexts,
                                        const std::vector<int64_t>& constants) const override;
    /**
   * Computes the linear weighted sum of ciphertexts with real constants, leaving the inputs unchanged; the
   * products are accumulated and the sum is rescaled once at the end.
   *
   * @param ciphertexts the input ciphertexts
   * @param constants the real weights, one per ciphertext
   * @return the weighted sum
   */
    Ciphertext<DCRTPoly> EvalLinearWSum(std::vector<ReadOnlyCiphertext<DCRTPoly>>& ciphertexts,
                                        const std::vector<double>& constants) const override;
    /**
   * Computes the linear weighted sum of ciphertexts with complex constants, leaving the inputs unchanged; the
   * products are accumulated and the sum is rescaled once at the end.
   *
   * @param ciphertexts the input ciphertexts
   * @param constants the complex weights, one per ciphertext
   * @return the weighted sum
   */
    Ciphertext<DCRTPoly> EvalLinearWSum(std::vector<ReadOnlyCiphertext<DCRTPoly>>& ciphertexts,
                                        const std::vector<std::complex<double>>& constants) const override;

    Ciphertext<DCRTPoly> EvalLinearWSumMutable(std::vector<Ciphertext<DCRTPoly>>& ciphertexts,
                                               const std::vector<int64_t>& constants) const override;
    /**
   * Computes the linear weighted sum of ciphertexts with real constants; the inputs are first brought to the
   * same level and noise scale degree (they are modified) and the sum is rescaled once at the end.
   *
   * @param ciphertexts the input ciphertexts
   * @param constants the real weights, one per ciphertext
   * @return the weighted sum
   */
    Ciphertext<DCRTPoly> EvalLinearWSumMutable(std::vector<Ciphertext<DCRTPoly>>& ciphertexts,
                                               const std::vector<double>& constants) const override;
    /**
   * Computes the linear weighted sum of ciphertexts with complex constants; the inputs are first brought to the
   * same level and noise scale degree (they are modified) and the sum is rescaled once at the end.
   *
   * @param ciphertexts the input ciphertexts
   * @param constants the complex weights, one per ciphertext
   * @return the weighted sum
   */
    Ciphertext<DCRTPoly> EvalLinearWSumMutable(std::vector<Ciphertext<DCRTPoly>>& ciphertexts,
                                               const std::vector<std::complex<double>>& constants) const override;

    //------------------------------------------------------------------------------
    // EVAL POLYNOMIAL
    //------------------------------------------------------------------------------

    std::shared_ptr<seriesPowers<DCRTPoly>> EvalPowers(ConstCiphertext<DCRTPoly>& x,
                                                       const std::vector<int64_t>& coefficients) const override;
    /**
   * Computes the powers of a ciphertext needed to evaluate a polynomial in the power basis with real
   * coefficients: a binary tree of powers below degree 5, or the Paterson-Stockmeyer power basis otherwise.
   *
   * @param x the input ciphertext
   * @param coefficients coefficients of the polynomial; their number (degree + 1) determines the powers
   * @return the powers of x
   */
    std::shared_ptr<seriesPowers<DCRTPoly>> EvalPowers(ConstCiphertext<DCRTPoly>& x,
                                                       const std::vector<double>& coefficients) const override;
    /**
   * Computes the powers of a ciphertext needed to evaluate a polynomial in the power basis with complex
   * coefficients: a binary tree of powers below degree 5, or the Paterson-Stockmeyer power basis otherwise.
   *
   * @param x the input ciphertext
   * @param coefficients coefficients of the polynomial; their number (degree + 1) determines the powers
   * @return the powers of x
   */
    std::shared_ptr<seriesPowers<DCRTPoly>> EvalPowers(
            ConstCiphertext<DCRTPoly>& x, const std::vector<std::complex<double>>& coefficients) const override;

    Ciphertext<DCRTPoly> EvalPoly(ConstCiphertext<DCRTPoly>& ciphertext,
                                  const std::vector<int64_t>& coefficients) const override;
    /**
   * Evaluates a polynomial with real coefficients in the power basis: EvalPolyLinear below degree 5,
   * EvalPolyPS otherwise.
   *
   * @param ciphertext the input ciphertext
   * @param coefficients coefficients of the polynomial, constant term first (size = degree + 1)
   * @return the value of the polynomial
   */
    Ciphertext<DCRTPoly> EvalPoly(ConstCiphertext<DCRTPoly>& ciphertext,
                                  const std::vector<double>& coefficients) const override;
    /**
   * Evaluates a polynomial with complex coefficients in the power basis: EvalPolyLinear below degree 5,
   * EvalPolyPS otherwise.
   *
   * @param ciphertext the input ciphertext
   * @param coefficients coefficients of the polynomial, constant term first (size = degree + 1)
   * @return the value of the polynomial
   */
    Ciphertext<DCRTPoly> EvalPoly(ConstCiphertext<DCRTPoly>& ciphertext,
                                  const std::vector<std::complex<double>>& coefficients) const override;

    /**
   * Evaluates a polynomial with integer coefficients in the power basis using powers precomputed by EvalPowers;
   * the powers are left unchanged so that several polynomials of the same shape can share them.
   *
   * @param powers the powers of the input ciphertext returned by EvalPowers
   * @param coefficients coefficients of the polynomial, constant term first; the degree may not exceed the one
   * the powers were computed for
   * @return the value of the polynomial
   */
    Ciphertext<DCRTPoly> EvalPolyWithPrecomp(std::shared_ptr<seriesPowers<DCRTPoly>> powers,
                                             const std::vector<int64_t>& coefficients) const override;
    /**
   * Evaluates a polynomial with real coefficients in the power basis using powers precomputed by EvalPowers;
   * the powers are left unchanged so that several polynomials of the same shape can share them.
   *
   * @param powers the powers of the input ciphertext returned by EvalPowers
   * @param coefficients coefficients of the polynomial, constant term first; the degree may not exceed the one
   * the powers were computed for
   * @return the value of the polynomial
   */
    Ciphertext<DCRTPoly> EvalPolyWithPrecomp(std::shared_ptr<seriesPowers<DCRTPoly>> powers,
                                             const std::vector<double>& coefficients) const override;
    /**
   * Evaluates a polynomial with complex coefficients in the power basis using powers precomputed by EvalPowers;
   * the powers are left unchanged so that several polynomials of the same shape can share them.
   *
   * @param powers the powers of the input ciphertext returned by EvalPowers
   * @param coefficients coefficients of the polynomial, constant term first; the degree may not exceed the one
   * the powers were computed for
   * @return the value of the polynomial
   */
    Ciphertext<DCRTPoly> EvalPolyWithPrecomp(std::shared_ptr<seriesPowers<DCRTPoly>> powers,
                                             const std::vector<std::complex<double>>& coefficients) const override;

    Ciphertext<DCRTPoly> EvalPolyLinear(ConstCiphertext<DCRTPoly>& x,
                                        const std::vector<int64_t>& coefficients) const override;
    /**
   * Evaluates a polynomial with real coefficients in the power basis using a binary tree of powers (intended
   * for degrees below 5).
   *
   * @param x the input ciphertext
   * @param coefficients coefficients of the polynomial, constant term first (size = degree + 1)
   * @return the value of the polynomial
   */
    Ciphertext<DCRTPoly> EvalPolyLinear(ConstCiphertext<DCRTPoly>& x,
                                        const std::vector<double>& coefficients) const override;
    /**
   * Evaluates a polynomial with complex coefficients in the power basis using a binary tree of powers (intended
   * for degrees below 5).
   *
   * @param x the input ciphertext
   * @param coefficients coefficients of the polynomial, constant term first (size = degree + 1)
   * @return the value of the polynomial
   */
    Ciphertext<DCRTPoly> EvalPolyLinear(ConstCiphertext<DCRTPoly>& x,
                                        const std::vector<std::complex<double>>& coefficients) const override;

    Ciphertext<DCRTPoly> EvalPolyPS(ConstCiphertext<DCRTPoly>& x,
                                    const std::vector<int64_t>& coefficients) const override;
    /**
   * Evaluates a polynomial with real coefficients in the power basis using the Paterson-Stockmeyer algorithm.
   *
   * @param x the input ciphertext
   * @param coefficients coefficients of the polynomial, constant term first (size = degree + 1)
   * @return the value of the polynomial
   */
    Ciphertext<DCRTPoly> EvalPolyPS(ConstCiphertext<DCRTPoly>& x,
                                    const std::vector<double>& coefficients) const override;
    /**
   * Evaluates a polynomial with complex coefficients in the power basis using the Paterson-Stockmeyer algorithm.
   *
   * @param x the input ciphertext
   * @param coefficients coefficients of the polynomial, constant term first (size = degree + 1)
   * @return the value of the polynomial
   */
    Ciphertext<DCRTPoly> EvalPolyPS(ConstCiphertext<DCRTPoly>& x,
                                    const std::vector<std::complex<double>>& coefficients) const override;

    //------------------------------------------------------------------------------
    // EVAL CHEBYSHEV SERIES
    //------------------------------------------------------------------------------

    std::shared_ptr<seriesPowers<DCRTPoly>> EvalChebyPolys(ConstCiphertext<DCRTPoly>& x,
                                                           const std::vector<int64_t>& coefficients, double a,
                                                           double b) const override;
    /**
   * Computes the Chebyshev polynomials of a ciphertext needed to evaluate a Chebyshev series with real
   * coefficients over [a, b]: a binary tree below degree 5, or the Paterson-Stockmeyer Chebyshev basis otherwise.
   * The input is first mapped from [a, b] to [-1, 1].
   *
   * @param x the input ciphertext
   * @param coefficients coefficients of the Chebyshev series; their number (degree + 1) determines the polynomials
   * @param a lower bound of the interpolation interval
   * @param b upper bound of the interpolation interval
   * @return the Chebyshev polynomials of the mapped input
   */
    std::shared_ptr<seriesPowers<DCRTPoly>> EvalChebyPolys(ConstCiphertext<DCRTPoly>& x,
                                                           const std::vector<double>& coefficients, double a,
                                                           double b) const override;
    /**
   * Computes the Chebyshev polynomials of a ciphertext needed to evaluate a Chebyshev series with complex
   * coefficients over [a, b]: a binary tree below degree 5, or the Paterson-Stockmeyer Chebyshev basis otherwise.
   * The input is first mapped from [a, b] to [-1, 1].
   *
   * @param x the input ciphertext
   * @param coefficients coefficients of the Chebyshev series; their number (degree + 1) determines the polynomials
   * @param a lower bound of the interpolation interval
   * @param b upper bound of the interpolation interval
   * @return the Chebyshev polynomials of the mapped input
   */
    std::shared_ptr<seriesPowers<DCRTPoly>> EvalChebyPolys(ConstCiphertext<DCRTPoly>& x,
                                                           const std::vector<std::complex<double>>& coefficients,
                                                           double a, double b) const override;

    Ciphertext<DCRTPoly> EvalChebyshevSeries(ConstCiphertext<DCRTPoly>& ciphertext,
                                             const std::vector<int64_t>& coefficients, double a,
                                             double b) const override;
    /**
   * Evaluates a Chebyshev series with real coefficients over [a, b]: the input is mapped to [-1, 1] and the
   * series is evaluated with EvalChebyshevSeriesLinear below degree 5, EvalChebyshevSeriesPS otherwise.
   *
   * @param ciphertext the input ciphertext, with values in [a, b]
   * @param coefficients coefficients of the Chebyshev series (size = degree + 1)
   * @param a lower bound of the interpolation interval
   * @param b upper bound of the interpolation interval
   * @return the value of the series
   */
    Ciphertext<DCRTPoly> EvalChebyshevSeries(ConstCiphertext<DCRTPoly>& ciphertext,
                                             const std::vector<double>& coefficients, double a,
                                             double b) const override;
    /**
   * Evaluates a Chebyshev series with complex coefficients over [a, b]: the input is mapped to [-1, 1] and the
   * series is evaluated with EvalChebyshevSeriesLinear below degree 5, EvalChebyshevSeriesPS otherwise.
   *
   * @param ciphertext the input ciphertext, with values in [a, b]
   * @param coefficients coefficients of the Chebyshev series (size = degree + 1)
   * @param a lower bound of the interpolation interval
   * @param b upper bound of the interpolation interval
   * @return the value of the series
   */
    Ciphertext<DCRTPoly> EvalChebyshevSeries(ConstCiphertext<DCRTPoly>& ciphertext,
                                             const std::vector<std::complex<double>>& coefficients, double a,
                                             double b) const override;

    /**
   * Evaluates a Chebyshev series with integer coefficients using the Chebyshev polynomials precomputed by
   * EvalChebyPolys; the polynomials are left unchanged so that several series of the same shape can share them.
   *
   * @param polys the Chebyshev polynomials returned by EvalChebyPolys
   * @param coefficients coefficients of the Chebyshev series; the degree may not exceed the one the polynomials
   * were computed for
   * @return the value of the series
   */
    Ciphertext<DCRTPoly> EvalChebyshevSeriesWithPrecomp(std::shared_ptr<seriesPowers<DCRTPoly>> polys,
                                                        const std::vector<int64_t>& coefficients) const override;
    /**
   * Evaluates a Chebyshev series with real coefficients using the Chebyshev polynomials precomputed by
   * EvalChebyPolys; the polynomials are left unchanged so that several series of the same shape can share them.
   *
   * @param polys the Chebyshev polynomials returned by EvalChebyPolys
   * @param coefficients coefficients of the Chebyshev series; the degree may not exceed the one the polynomials
   * were computed for
   * @return the value of the series
   */
    Ciphertext<DCRTPoly> EvalChebyshevSeriesWithPrecomp(std::shared_ptr<seriesPowers<DCRTPoly>> polys,
                                                        const std::vector<double>& coefficients) const override;
    /**
   * Evaluates a Chebyshev series with complex coefficients using the Chebyshev polynomials precomputed by
   * EvalChebyPolys; the polynomials are left unchanged so that several series of the same shape can share them.
   *
   * @param polys the Chebyshev polynomials returned by EvalChebyPolys
   * @param coefficients coefficients of the Chebyshev series; the degree may not exceed the one the polynomials
   * were computed for
   * @return the value of the series
   */
    Ciphertext<DCRTPoly> EvalChebyshevSeriesWithPrecomp(
            std::shared_ptr<seriesPowers<DCRTPoly>> polys,
            const std::vector<std::complex<double>>& coefficients) const override;

    /**
   * Evaluates a Chebyshev series with integer coefficients over [a, b] using a binary tree of Chebyshev
   * polynomials (intended for degrees below 5).
   *
   * @param ciphertext the input ciphertext, with values in [a, b]
   * @param coefficients coefficients of the Chebyshev series (size = degree + 1)
   * @param a lower bound of the interpolation interval
   * @param b upper bound of the interpolation interval
   * @return the value of the series
   */
    Ciphertext<DCRTPoly> EvalChebyshevSeriesLinear(ConstCiphertext<DCRTPoly>& ciphertext,
                                                   const std::vector<int64_t>& coefficients, double a,
                                                   double b) const override;
    /**
   * Evaluates a Chebyshev series with real coefficients over [a, b] using a binary tree of Chebyshev
   * polynomials (intended for degrees below 5).
   *
   * @param ciphertext the input ciphertext, with values in [a, b]
   * @param coefficients coefficients of the Chebyshev series (size = degree + 1)
   * @param a lower bound of the interpolation interval
   * @param b upper bound of the interpolation interval
   * @return the value of the series
   */
    Ciphertext<DCRTPoly> EvalChebyshevSeriesLinear(ConstCiphertext<DCRTPoly>& ciphertext,
                                                   const std::vector<double>& coefficients, double a,
                                                   double b) const override;
    /**
   * Evaluates a Chebyshev series with complex coefficients over [a, b] using a binary tree of Chebyshev
   * polynomials (intended for degrees below 5).
   *
   * @param ciphertext the input ciphertext, with values in [a, b]
   * @param coefficients coefficients of the Chebyshev series (size = degree + 1)
   * @param a lower bound of the interpolation interval
   * @param b upper bound of the interpolation interval
   * @return the value of the series
   */
    Ciphertext<DCRTPoly> EvalChebyshevSeriesLinear(ConstCiphertext<DCRTPoly>& ciphertext,
                                                   const std::vector<std::complex<double>>& coefficients, double a,
                                                   double b) const override;

    /**
   * Evaluates a Chebyshev series with integer coefficients over [a, b] using the Paterson-Stockmeyer algorithm
   * in the Chebyshev basis.
   *
   * @param ciphertext the input ciphertext, with values in [a, b]
   * @param coefficients coefficients of the Chebyshev series (size = degree + 1)
   * @param a lower bound of the interpolation interval
   * @param b upper bound of the interpolation interval
   * @return the value of the series
   */
    Ciphertext<DCRTPoly> EvalChebyshevSeriesPS(ConstCiphertext<DCRTPoly>& ciphertext,
                                               const std::vector<int64_t>& coefficients, double a,
                                               double b) const override;
    /**
   * Evaluates a Chebyshev series with real coefficients over [a, b] using the Paterson-Stockmeyer algorithm
   * in the Chebyshev basis.
   *
   * @param ciphertext the input ciphertext, with values in [a, b]
   * @param coefficients coefficients of the Chebyshev series (size = degree + 1)
   * @param a lower bound of the interpolation interval
   * @param b upper bound of the interpolation interval
   * @return the value of the series
   */
    Ciphertext<DCRTPoly> EvalChebyshevSeriesPS(ConstCiphertext<DCRTPoly>& ciphertext,
                                               const std::vector<double>& coefficients, double a,
                                               double b) const override;
    /**
   * Evaluates a Chebyshev series with complex coefficients over [a, b] using the Paterson-Stockmeyer algorithm
   * in the Chebyshev basis.
   *
   * @param ciphertext the input ciphertext, with values in [a, b]
   * @param coefficients coefficients of the Chebyshev series (size = degree + 1)
   * @param a lower bound of the interpolation interval
   * @param b upper bound of the interpolation interval
   * @return the value of the series
   */
    Ciphertext<DCRTPoly> EvalChebyshevSeriesPS(ConstCiphertext<DCRTPoly>& ciphertext,
                                               const std::vector<std::complex<double>>& coefficients, double a,
                                               double b) const override;

    //------------------------------------------------------------------------------
    // EVAL LINEAR TRANSFORMATION
    //------------------------------------------------------------------------------

    //------------------------------------------------------------------------------
    // SERIALIZATION
    //------------------------------------------------------------------------------

    template <class Archive>
    void save(Archive& ar) const {
        ar(cereal::base_class<AdvancedSHERNS>(this));
    }

    template <class Archive>
    void load(Archive& ar) {
        ar(cereal::base_class<AdvancedSHERNS>(this));
    }

    std::string SerializedObjectName() const {
        return "AdvancedSHECKKSRNS";
    }
};

}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_SCHEME_CKKSRNS_CKKSRNS_ADVANCEDSHE_H_
