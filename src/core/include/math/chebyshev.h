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

/*
 * This code provides Chebyshev approximation utilities.
 */

#ifndef LBCRYPTO_INC_MATH_CHEBYSHEV_H
#define LBCRYPTO_INC_MATH_CHEBYSHEV_H

#include <cstdint>
#include <functional>
#include <vector>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * Method for calculating Chebyshev coefficients for an input function
 * over the range [a,b]. These coefficents are used in EValChebyshevSeries
 * to approximate the function func as
 *   func(x) ~ coeffs[0]/2 + sum_{i=1}^{degree} coeffs[i] * T_{i}(x),
 * where T_{i}(x) are Chebyshev polynomials of the first kind. (Note that
 * the 1st coeffiicent is divided by two.)
 * @param func is the function to be approximated
 * @param a - lower bound of argument for which the coefficients were found
 * @param b - upper bound of argument for which the coefficients were found
 * @param degree Desired degree of approximation
 * @return the coefficients of the Chebyshev approximation.
 */
std::vector<double> EvalChebyshevCoefficients(std::function<double(double)> func, double a, double b, uint32_t degree);

/**
 * A cleartext version of CryptoContext<...>::EvalChebyshevFunction(...).
 * It evaluates an approximation of func via Chebyshev polynomials of a
 * bounded degree, over a specified interval [a,b].
 *
 * @param func is the function to be approximated
 * @param ptxt is a vector of plaintext inputs
 * @param a is the bottom of the interval over chichfunc is approximated
 * @param b is the top of the interval over chichfunc is approximated
 * @param degree is the desired degree of approximation
 * @return Evaluation of the approximated function over the plaintexts.
 */
std::vector<double> EvalChebyshevFunctionPtxt(std::function<double(double)> func, const std::vector<double> ptxt, double a, double b, size_t degree);

}  // namespace lbcrypto

#endif
