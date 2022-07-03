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

#ifndef LBCRYPTO_DUALITY_UTILS_POLYNOMIALS_H
#define LBCRYPTO_DUALITY_UTILS_POLYNOMIALS_H

#include <vector>
#include <stdint.h>

/**
 * Gets the degree of a polynomial specified by its coefficients.
 *
 * @param &coefficients vector of coefficients of a polynomial.
 * @return the integer degree of the polynomial.
 */
uint32_t Degree(const std::vector<double> &coefficients);

struct longDiv{
	std::vector<double> q;
	std::vector<double> r;
};

/**
 * Computes the quotient and remainder of the long division of two polynomials in the power series basis.
 *
 * @param &f the vector of coefficients of the dividend.
 * @param &g the vector of coefficients of the divisor.
 * @return a struct with the coefficients for the quotient and remainder.
 */
longDiv *LongDivisionPoly(
	const std::vector<double> &f,
	const std::vector<double> &g);


/**
 * Computes the quotient and remainder of the long division of two polynomials in the Chebyshev series basis
 *
 * @param &f the vector of coefficients of the dividend.
 * @param &g the vector of coefficients of the divisor.
 * @return a struct with the coefficients for the quotient and remainder.
 */
longDiv *LongDivisionChebyshev(
	const std::vector<double> &f,
	const std::vector<double> &g);

/**
 * Computes the values of the internal degrees k and m needed in the Paterson-Stockmeyer algorithm
 * such that k(2^m - 1} > n and k close to sqrt(n/2).
 *
 * @param n the degree of a polynomial.
 * @return a vector containing k and m.
 */
std::vector<uint32_t> ComputeDegreesPS(const uint32_t n);

#endif
