
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

#ifndef LBCRYPTO_INC_MATH_HERMITE_H
#define LBCRYPTO_INC_MATH_HERMITE_H

#include <complex>
#include <cstdint>
#include <functional>
#include <vector>

namespace lbcrypto {

/** Interpolation used by CKKS functional bootstrapping. */
enum class DiscreteCKKSInterpolationMethod { AKP, SPARSE_THI, BKSS, BKSS_NEW, FULL_THI };

/**
 * Calculates Hermite trigonometric interpolation coefficients for an input function.
 * AKP supports orders 1, 2, and 3; Sparse-THI supports positive orders with a
 * power-of-two modulus p >= 2, except p = 2 with order = 1, which must use AKP.
 * Full-THI supports orders 1–3 with p >= 4 and is evaluated without taking 2*Re.
 * BKSS and BKSS_NEW support order 1 and p >= 4, using a packed four-block
 * coefficient layout consumed only by the matching FBT evaluator (see below).
 * Existing calls default to AKP. AKP/Sparse-THI coefficients can be input into
 * EvalPoly over ciphertexts encrypting exp(2*Pi*x) to evaluate the function.
 * The coefficients are divided by 2 to account for the fact that the real part
 * of the output of EvalPoly needs to be taken in order to get the Hermite
 * Trigonometric Interpolation result.
 *
 *
 * @param func is the function to be approximated
 * @param order interpolation order
 * @param scale output normalization: twice the real part evaluates to func(x)/scale
 * @param method interpolation method, defaulting to AKP
 * @param p number of interpolation points
 * @return the coefficients of the intermediate Hermite trigonometric interpolation.
 */

// TODO: templatize this
std::vector<std::complex<double>> GetHermiteTrigCoefficients(
    std::function<int64_t(int64_t)> func, uint32_t p, size_t order, double scale,
    DiscreteCKKSInterpolationMethod method = DiscreteCKKSInterpolationMethod::AKP);

/** BKSS coefficient layout: four length-p blocks followed by the constant term.
 * BKSS_NEW stores its Nyquist correction in the first entry of the second block.
 * Both require real LUTs, a power-of-two p >= 4, and order 1.
 * These are evaluator-specific layouts, not ordinary EvalPoly coefficients.
 */
std::vector<std::complex<double>> GetHermiteTrigCoefficientsBKSS(
    std::function<int64_t(int64_t)> func, uint32_t p, double scale);
std::vector<std::complex<double>> GetHermiteTrigCoefficientsBKSSNew(
    std::function<int64_t(int64_t)> func, uint32_t p, double scale);

/** Full holomorphic THI (CKKL), orders 1–3. Evaluate directly, without 2*Re. */
std::vector<std::complex<double>> GetHermiteTrigCoefficientsFullTHI(
    std::function<int64_t(int64_t)> func, uint32_t p, size_t order, double scale);
std::vector<std::complex<double>> GetHermiteTrigCoefficientsFullTHIForComplexLUT(
    std::function<std::complex<double>(int64_t)> func, uint32_t p, size_t order, double scale);

}  // namespace lbcrypto

#endif
