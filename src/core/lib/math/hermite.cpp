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

#include <cmath>
#include <complex>
#include <cstdint>
#include <functional>
#include <vector>

#include "math/dftransform.h"
#include "utils/exception.h"

namespace {

bool IsNotEqualZero(std::complex<double> v) {
    // TODO: tune this delta value during the fbt refactor
    constexpr double delta = 0x1p-32;  // 2**-32
    return (std::fabs(v.real()) >= delta) || (std::fabs(v.imag()) >= delta);
}

void TrimTrailingZeros(std::vector<std::complex<double>>& coeffs) {
    size_t degree = 0;
    for (size_t i = 1; i < coeffs.size(); ++i) {
        if (IsNotEqualZero(coeffs[i]))
            degree = i;
    }
    coeffs.resize(degree + 1);
}

// F[k] = sum_j f(j) exp(-2 pi i j k / p) for k = 0..p-1
std::vector<std::complex<double>> FunctionDFT(const std::function<int64_t(int64_t)>& func, uint32_t p) {
    std::vector<std::complex<double>> samples(p);
    for (uint32_t j = 0; j < p; ++j)
        samples[j] = static_cast<double>(func(j));
    constexpr uint32_t kMaxFFTLength = 1U << 18;
    if ((p & (p - 1)) == 0 && p <= kMaxFFTLength)
        return lbcrypto::DiscreteFourierTransform::FFTForwardTransform(samples);
    std::vector<std::complex<double>> F(p);
    for (uint32_t k = 0; k < p; ++k) {
        for (uint32_t j = 0; j < p; ++j)
            F[k] += samples[j] * std::polar(1.0, -2. * M_PI * static_cast<double>(k) * j / p);
    }
    return F;
}

}  // namespace

namespace lbcrypto {

std::vector<std::complex<double>> GetHermiteTrigCoefficients(std::function<int64_t(int64_t)> func, uint32_t p,
                                                             size_t order, double scale) {
    if (p == 0)
        OPENFHE_THROW("The degree of approximation can not be zero");
    if (order < 1 || order > 3)
        OPENFHE_THROW("Order must be 1, 2, or 3");

    // G[k] is the DFT of the function samples normalised by p and by the caller's scale. Every weight below is a
    // polynomial in t = k / p, so no intermediate grows with p. Halving the constant term and the wrapped terms
    // accounts for taking the real part of EvalPoly's output.
    std::vector<std::complex<double>> G = FunctionDFT(func, p);
    const double norm = static_cast<double>(p) * scale;
    for (auto& g : G)
        g /= norm;

    const auto t = [p](uint32_t k) {
        return static_cast<double>(k) / static_cast<double>(p);
    };

    if (order == 1) {
        // Fejer weights: (1 - t) on the p frequencies.
        std::vector<std::complex<double>> coeffs(p);
        for (uint32_t k = 0; k < p; ++k)
            coeffs[k] = G[k] * (1.0 - t(k));
        coeffs[0] /= 2.0;
        TrimTrailingZeros(coeffs);
        return coeffs;
    }

    // Orders 2 and 3 add a second weight w(t) on the lower frequencies, subtract half of it on the frequencies
    // reflected about p, and subtract half of it on the frequencies wrapped past p (where G is periodic).
    const uint32_t extra = (order == 2) ? (p >> 1) : (p - 1);  // frequencies carrying the second weight
    const uint32_t half = p >> 1;
    const auto w = [&](uint32_t k) {
        if (order == 2) {
            // The Nyquist frequency of an even p enters once instead of twice.
            const double nyquist = ((p & 1) == 0 && k == half) ? 1.0 : 0.0;
            return (2.0 - nyquist) * t(k) * (1.0 - t(k)) / 2.0;
        }
        return t(k) * (1.0 - t(k)) * (2.0 - t(k)) / 3.0;
    };

    std::vector<std::complex<double>> coeffs(p + extra + 1);
    coeffs[0] = G[0] / 2.0;
    for (uint32_t i = 1; i < coeffs.size(); ++i) {
        if (i < p)
            coeffs[i] = G[i] * (1.0 - t(i));
        if (i <= extra)
            coeffs[i] += G[i] * w(i);
        if (p - extra <= i && i < p)
            coeffs[i] -= G[i] * w(p - i) / 2.0;
        if (i > p)
            coeffs[i] -= G[i - p] * w(i - p) / 2.0;
    }
    TrimTrailingZeros(coeffs);
    return coeffs;
}

}  // namespace lbcrypto
