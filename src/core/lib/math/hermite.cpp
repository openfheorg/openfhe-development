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

#include "math/hermite.h"
#include "utils/exception.h"

#include <cmath>
#include <complex>
#include <cstdint>
#include <functional>
#include <vector>

static bool IsNotEqualZero(std::complex<double> v) {
    constexpr double delta = 0x1p-30;  // 2**-30
    return (std::fabs(v.real()) >= delta) || (std::fabs(v.imag()) >= delta);
}

//  Populate statically the parameter m for the Paterson-Stockmeyer algorithm up to the degree value of upperBoundDegree
enum { UPPER_BOUND_PS = 2204 };

// Populate the conversion table Degree-to-Multiplicative Depth
enum {
    LOWER_BOUND_DEGREE = 5,
    UPPER_BOUND_DEGREE = 261631,
};

// clang-format off
static std::vector<uint32_t> GenerateDepthByDegreeTable() {
    std::vector<uint32_t> depthTable(UPPER_BOUND_DEGREE + 1);

    std::fill(depthTable.begin(),        depthTable.begin() + 5,     3);  // degree in [0,4], depth = 3 - the Paterson-Stockmeyer algorithm is not used when degree < 5
    std::fill(depthTable.begin() + 5,    depthTable.begin() + 6,     4);  // degree in [5],         depth = 4
    std::fill(depthTable.begin() + 6,    depthTable.begin() + 14,    5);  // degree in [6,13],      depth = 5
    std::fill(depthTable.begin() + 14,   depthTable.begin() + 28,    6);  // degree in [14,27],     depth = 6
    std::fill(depthTable.begin() + 28,   depthTable.begin() + 60,    7);  // degree in [28,59],     depth = 7
    std::fill(depthTable.begin() + 60,   depthTable.begin() + 120,   8);  // degree in [60,119],    depth = 8
    std::fill(depthTable.begin() + 120,  depthTable.begin() + 248,   9);  // degree in [120,247],   depth = 9
    std::fill(depthTable.begin() + 248,  depthTable.begin() + 496,  10);  // degree in [248,495],   depth = 10
    std::fill(depthTable.begin() + 496,  depthTable.begin() + 1008, 11);  // degree in [496,1007],  depth = 11
    std::fill(depthTable.begin() + 1008, depthTable.begin() + 2031, 12);  // degree in [1008,2031], depth = 12
    std::fill(depthTable.begin() + 2032, depthTable.begin() + 4031, 13);  // degree in [2031,4031], depth = 13
    std::fill(depthTable.begin() + 4032, depthTable.begin() + 8127, 14);  // degree in [4032,8127], depth = 14
    std::fill(depthTable.begin() + 8128, depthTable.begin() + 16255, 15);  // degree in [8128, 16255], depth = 15
    std::fill(depthTable.begin() + 16256, depthTable.begin() + 32639, 16);  // degree in [16256, 32639], depth = 16
    std::fill(depthTable.begin() + 32640, depthTable.begin() + 65279, 17);  // degree in [32640, 65279], depth = 17
    std::fill(depthTable.begin() + 65280, depthTable.begin() + 130815, 18);  // degree in [65280, 130815], depth = 18
    std::fill(depthTable.begin() + 130816, depthTable.end(), 19);  // degree in [130816, 261631], depth = 19

    return depthTable;
}
// clang-format on

static uint32_t GetDepthByDegree(size_t degree) {
    if (degree >= LOWER_BOUND_DEGREE && degree <= UPPER_BOUND_DEGREE)
        return GenerateDepthByDegreeTable()[degree];

    std::string errMsg("Polynomial degree is supported from " + std::to_string(LOWER_BOUND_DEGREE) + " to " +
                       std::to_string(UPPER_BOUND_DEGREE) + " inclusive. Its current value is ");
    errMsg += std::to_string(degree);
    OPENFHE_THROW(errMsg);
}

namespace lbcrypto {

std::vector<std::complex<double>> GetHermiteTrigCoefficients(std::function<int64_t(int64_t)> func, uint32_t p,
                                                             size_t order, double scale) {
    using namespace std::complex_literals;
    if (p == 0)
        OPENFHE_THROW("The degree of approximation can not be zero");

    switch (order) {
        case 1: {
            uint32_t degree = 0;
            std::vector<std::complex<double>> coeffs(p);

            for (uint32_t i = 0; i < p; ++i) {
                for (uint32_t j = 0; j < p; ++j)
                    coeffs[i] += static_cast<double>(func(j)) * std::exp((-2. * M_PI * i * j / p) * 1i);
                // No multiplication by 2 is to account for taking the real part
                coeffs[i] *= static_cast<double>(p - i) / static_cast<double>(p * p) / scale;
                if (IsNotEqualZero(coeffs[i]))
                    degree = i;
            }
            coeffs[0] /= 2.0;
            coeffs.resize(degree + 1);
            return coeffs;
        } break;
        case 2: {
            uint32_t pby2{p >> 1};
            uint32_t coeffTotal{p + pby2 + 1};
            std::vector<std::complex<double>> coeffs(coeffTotal);
            std::vector<std::complex<double>> alpha(p);
            std::vector<std::complex<double>> beta(pby2);
            std::vector<double> gamma(pby2);
            std::vector<std::complex<double>> delta(pby2);
            std::vector<std::complex<double>> omega(pby2);

            for (uint32_t i = 0; i < p; ++i) {
                for (uint32_t j = 0; j < p; ++j)
                    alpha[i] += static_cast<double>(func(j)) * std::exp((-2. * M_PI * i * j / p) * 1i);
                // The last /2 is to account for taking the real part
                alpha[i] *= 2. * static_cast<double>(p - i) / static_cast<double>(p * p) / 2. / scale;
            }
            alpha[0] /= 2.0;

            if ((p & 1) == 0)
                gamma.back() = 1.0;

            double factor = 1.0;
            for (uint32_t i = 1; i <= pby2; ++i) {
                for (uint32_t j = 0; j < p; ++j) {
                    auto y = static_cast<double>(func(j));
                    beta[i - 1] += y * std::exp((-2. * M_PI * i * j / p) * 1i);
                    delta[i - 1] += y * std::exp((-2. * M_PI * (p + i) * j / p) * 1i);
                    omega[i - 1] += y * std::exp((-2. * M_PI * (p - i) * j / p) * 1i);
                }
                // The last /2 is to account for taking the real part
                // factor = (2. - gamma[i - 1]) * i * static_cast<double>(p - i) / static_cast<double>(p * p * p) / 2. / scale;
                factor = (2. - gamma[i - 1]) * i * static_cast<double>(p - i) / static_cast<double>(p * p) /
                         static_cast<double>(p) / 2. /
                         scale;  // for large p, p*p*p overflows, so we separate the division
                beta[i - 1] *= factor;
                delta[i - 1] *= factor / 2.;
                omega[i - 1] *= factor / 2.;
            }

            uint32_t degree = 0;
            coeffs[0]       = alpha[0];
            for (uint32_t i = 1; i < coeffTotal; ++i) {
                if (i < p)
                    coeffs[i] = alpha[i];
                if (i <= pby2)
                    coeffs[i] += beta[i - 1];
                if (pby2 <= i && i < p)
                    coeffs[i] -= omega[p - i - 1];
                if (i > p)
                    coeffs[i] -= delta[i - p - 1];
                if (IsNotEqualZero(coeffs[i]))
                    degree = i;
            }
            coeffs.resize(degree + 1);
            return coeffs;
        } break;
        case 3: {
            uint32_t coeffTotal{p + p};
            std::vector<std::complex<double>> coeffs(coeffTotal);
            std::vector<std::complex<double>> alpha(p);
            std::vector<std::complex<double>> beta(p - 1);
            std::vector<std::complex<double>> delta(p - 1);
            std::vector<std::complex<double>> omega(p - 1);

            for (uint32_t i = 0; i < p; ++i) {
                for (uint32_t j = 0; j < p; ++j)
                    alpha[i] += static_cast<double>(func(j)) * std::exp((-2. * M_PI * i * j / p) * 1i);
                // The last /2 is to account for taking the real part
                alpha[i] *= 2. * static_cast<double>(p - i) / static_cast<double>(p * p) / 2. / scale;
            }
            alpha[0] /= 2.0;

            double factor = 1.0;
            for (uint32_t i = 1; i <= p - 1; ++i) {
                for (uint32_t j = 0; j < p; ++j) {
                    auto y = static_cast<double>(func(j));
                    beta[i - 1] += y * std::exp((-2. * M_PI * i * j / p) * 1i);
                    delta[i - 1] += y * std::exp((-2. * M_PI * (p + i) * j / p) * 1i);
                    omega[i - 1] += y * std::exp((-2. * M_PI * (p - i) * j / p) * 1i);
                }
                // The last /2 is to account for taking the real part
                factor = 2. * i * static_cast<double>(p - i) * static_cast<double>(2. * p - i) / 3. /
                         static_cast<double>(p * p) / static_cast<double>(p * p) / 2. /
                         scale;  // for large p, p*p*p*p overflows, so we separate the division
                beta[i - 1] *= factor;
                delta[i - 1] *= factor / 2.;
                omega[i - 1] *= factor / 2.;
            }

            uint32_t degree = 0;
            coeffs[0]       = alpha[0];
            for (uint32_t i = 1; i < coeffTotal; ++i) {
                if (i < p)
                    coeffs[i] = alpha[i];
                if (i <= p - 1)
                    coeffs[i] += beta[i - 1];
                if (1 <= i && i < p)
                    coeffs[i] -= omega[p - i - 1];
                if (i > p)
                    coeffs[i] -= delta[i - p - 1];
                if (IsNotEqualZero(coeffs[i]))
                    degree = i;
            }
            coeffs.resize(degree + 1);
            return coeffs;
        } break;
        default:
            OPENFHE_THROW("Order must be 1, 2, or 3");
    }
}

uint32_t GetMultiplicativeDepthByCoeffVector(const std::vector<std::complex<double>>& vec, bool isNormalized) {
    if (vec.size() == 0)
        OPENFHE_THROW("Cannot perform operation on empty vector. vec.size() == 0");
    return GetDepthByDegree(vec.size() - 1) - isNormalized;
}

}  // namespace lbcrypto
