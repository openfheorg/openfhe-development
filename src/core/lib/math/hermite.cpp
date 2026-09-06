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
    // TODO: tune this delta value during the fbt refactor
    constexpr double delta = 0x1p-32;  // 2**-32
    return (std::fabs(v.real()) >= delta) || (std::fabs(v.imag()) >= delta);
}

namespace lbcrypto {

static std::vector<std::complex<double>> GetHermiteTrigCoefficientsAKP(std::function<int64_t(int64_t)> func, uint32_t p,
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

// Theorem 6 of https://eprint.iacr.org/2026/1026. Normalized products avoid
// forming factorial(n) and p^n separately. Unused frequency bands remain zero.
static std::vector<std::complex<double>> GetHermiteTrigCoefficientsSparseTHI(
    const std::function<int64_t(int64_t)>& func, uint32_t p, size_t order, double scale) {
    if (p == 2 && order == 1)
        OPENFHE_THROW("Sparse-THI does not support p = 2 with order = 1; use DiscreteCKKSInterpolationMethod::AKP instead");
    if (p < 2 || (p & (p - 1)) != 0 || order == 0)
        OPENFHE_THROW("Sparse-THI requires a power-of-two modulus >= 2 and positive order");
    if (!std::isfinite(scale) || scale == 0)
        OPENFHE_THROW("Sparse-THI requires a finite nonzero scale");
    std::vector<double> values(p);
    for (uint32_t j = 0; j < p; ++j)
        values[j] = static_cast<double>(func(j));
    std::vector<std::complex<double>> coeffs(order * p + p / 2 + 1);
    for (uint32_t k = 0; k <= p / 2; ++k) {
        std::complex<double> frequency{0.0, 0.0};
        for (uint32_t j = 0; j < p; ++j)
            frequency += values[j] * std::polar(1.0, -2.0 * M_PI * (double(k) * j / p));
        frequency /= double(p);
        frequency /= scale;
        if (k == 0) {
            coeffs[0] = frequency.real() / 2.0;
            continue;
        }
        if (k == p / 2)
            frequency = frequency.real() / 2.0;
        for (size_t ell = 0; ell <= order; ++ell) {
            long double weight = 1.0;
            for (size_t j = 0; j <= order; ++j) {
                if (j != ell)
                    weight *= (static_cast<long double>(j) + static_cast<long double>(k) / p) /
                              (static_cast<long double>(j) - static_cast<long double>(ell));
            }
            auto value          = static_cast<double>(weight) * frequency;
            coeffs[ell * p + k] = value;
        }
    }
    return coeffs;
}

std::vector<std::complex<double>> GetHermiteTrigCoefficients(std::function<int64_t(int64_t)> func, uint32_t p,
                                                             size_t order, double scale,
                                                             DiscreteCKKSInterpolationMethod method) {
    switch (method) {
        case DiscreteCKKSInterpolationMethod::AKP:
            return GetHermiteTrigCoefficientsAKP(func, p, order, scale);
        case DiscreteCKKSInterpolationMethod::SPARSE_THI:
            return GetHermiteTrigCoefficientsSparseTHI(func, p, order, scale);
        default:
            OPENFHE_THROW("Unknown interpolation method");
    }
}

}  // namespace lbcrypto
