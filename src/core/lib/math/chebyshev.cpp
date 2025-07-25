
//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
  This code provides Chebyshev approximation utilities
 */

#include "math/chebyshev.h"
#include "utils/exception.h"

#include <cmath>
#include <cstdint>
#include <functional>
#include <vector>

namespace lbcrypto {

std::vector<double> EvalChebyshevCoefficients(std::function<double(double)> func, double a, double b, uint32_t degree) {
    if (degree == 0)
        OPENFHE_THROW("The degree of approximation can not be zero");
    // the number of coefficients to be generated should be degree+1 as zero is also included
    size_t coeffTotal{degree + 1};
    double bMinusA = 0.5 * (b - a);
    double bPlusA  = 0.5 * (b + a);
    double PiByDeg = M_PI / static_cast<double>(coeffTotal);
    std::vector<double> functionPoints(coeffTotal);
    for (size_t i = 0; i < coeffTotal; ++i)
        functionPoints[i] = func(std::cos(PiByDeg * (i + 0.5)) * bMinusA + bPlusA);

    double multFactor = 2.0 / static_cast<double>(coeffTotal);
    std::vector<double> coefficients(coeffTotal);
    for (size_t i = 0; i < coeffTotal; ++i) {
        for (size_t j = 0; j < coeffTotal; ++j)
            coefficients[i] += functionPoints[j] * std::cos(PiByDeg * i * (j + 0.5));
        coefficients[i] *= multFactor;
    }
    return coefficients;
}

// A cleartext version of CryptoContext<...>::EvalChebyshevFunction(...)
std::vector<double> EvalChebyshevFunctionPtxt(std::function<double(double)> func, const std::vector<double>& ptxt,
                                              double a, double b, size_t degree) {
    auto coeffs = EvalChebyshevCoefficients(func, a, b, degree);

    // The standard practice is to halve the 1st coefficient.
    // See, for example, the Chebyshev Series section at
    // https://www.cfm.brown.edu/people/dobrush/am34/Mathematica/ch5/chebyshev.html
    // and derivation of Eq. (6) in https://arxiv.org/pdf/1810.04282.
    // The halving requirement follows from the discrete orthogonality relation for Chebyshev polynomials,
    // i.e., Eq. (4) in https://arxiv.org/pdf/1810.04282.
    coeffs[0] /= 2.0;

    // Special case for trivial case of a degee-0 approximation
    if (degree == 0)
        return std::vector<double>(ptxt.size(), coeffs[0]);

    // If [a,b] is different than [-1,1] then need to scale the input
    double scaleFactor = 2.0 / (b - a);
    double offset      = (b + a) * scaleFactor / -2.0;

    std::vector<double> result(ptxt.size());
    for (size_t i = 0; i < ptxt.size(); i++) {
        double x  = ptxt[i] * scaleFactor + offset;
        double x2 = 2 * x;

        double t_prev = 1.0;  // T0(x) = 1
        double t_j    = x;    // T1(x) = x
        double y      = coeffs[0] + coeffs[1] * x;
        // Use the recursive formula T_{i+1}(X) = 2x T_i(x) - T_{i-1}(x)
        for (size_t j = 2; j < coeffs.size(); j++) {
            // Compute T_j(x) and add it to the approximation
            double t_next = x2 * t_j - t_prev;
            t_prev        = t_j;
            t_j           = t_next;
            y += coeffs[j] * t_next;
        }
        result[i] = y;
    }
    return result;
}

}  // namespace lbcrypto
