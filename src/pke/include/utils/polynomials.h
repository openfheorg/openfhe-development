/***
 * © 2020 Duality Technologies, Inc. All rights reserved.
 * This is a proprietary software product of Duality Technologies, Inc. protected under copyright laws
 * and international copyright treaties, patent law, trade secret law and other intellectual property
 * rights of general applicability.
 * Any use of this software is strictly prohibited absent a written agreement executed by Duality
 * Technologies, Inc., which provides certain limited rights to use this software.
 * You may not copy, distribute, make publicly available, publicly perform, disassemble, de-compile or
 * reverse engineer any part of this software, breach its security, or circumvent, manipulate, impair or
 * disrupt its operation.
 ***/
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
