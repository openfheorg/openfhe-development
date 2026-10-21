//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
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
  Tests for the Hermite trigonometric interpolation coefficients: agreement with a direct evaluation of the
  defining sums, scale linearity, the non-power-of-two path, and a 16-bit LUT (p = 65536), whose normalisation
  overflowed 32-bit arithmetic before.
 */

#include <algorithm>
#include <cmath>
#include <complex>
#include <cstdint>
#include <functional>
#include <vector>

#include "gtest/gtest.h"
#include "math/hermite.h"

using namespace lbcrypto;

namespace {

// The defining sums, evaluated directly: alpha, beta, delta and omega as separate O(p^2) DFT sums at frequencies
// k, k, p + k and p - k, combined with the original weights. The reference for the FFT-based implementation.
std::vector<std::complex<double>> ReferenceHermite(const std::function<int64_t(int64_t)>& func, uint32_t p,
                                                   size_t order, double scale) {
    using namespace std::complex_literals;
    auto dft = [&](uint32_t k) {
        std::complex<double> acc{0.0, 0.0};
        for (uint32_t j = 0; j < p; ++j)
            acc += static_cast<double>(func(j)) * std::exp((-2. * M_PI * static_cast<double>(k) * j / p) * 1i);
        return acc;
    };
    const double pd = static_cast<double>(p);
    std::vector<std::complex<double>> alpha(p);
    for (uint32_t i = 0; i < p; ++i)
        alpha[i] = dft(i) * (pd - i) / (pd * pd) / scale;
    alpha[0] /= 2.0;
    if (order == 1)
        return alpha;

    const uint32_t extra = (order == 2) ? (p >> 1) : (p - 1);
    std::vector<std::complex<double>> coeffs(p + extra + 1);
    coeffs[0] = alpha[0];
    for (uint32_t i = 1; i <= extra; ++i) {
        double factor;
        if (order == 2) {
            const double gamma = ((p & 1) == 0 && i == (p >> 1)) ? 1.0 : 0.0;
            factor = (2. - gamma) * i * (pd - i) / (pd * pd * pd) / 2. / scale;
        } else {
            factor = 2. * i * (pd - i) * (2. * pd - i) / 3. / (pd * pd * pd * pd) / 2. / scale;
        }
        const auto beta = dft(i) * factor;
        const auto delta = dft(p + i) * factor / 2.;
        const auto omega = dft(p - i) * factor / 2.;
        coeffs[i] += beta;
        coeffs[p - i] -= omega;
        coeffs[p + i] -= delta;
    }
    for (uint32_t i = 1; i < p; ++i)
        coeffs[i] += alpha[i];
    return coeffs;
}

double MaxAbs(const std::vector<std::complex<double>>& v) {
    double m = 0.0;
    for (const auto& c : v)
        m = std::max(m, std::abs(c));
    return m;
}

// Compares the two series up to the longer length, treating missing trailing coefficients as zero.
void ExpectSeriesEqual(const std::vector<std::complex<double>>& got, const std::vector<std::complex<double>>& ref,
                       double tol) {
    const size_t n = std::max(got.size(), ref.size());
    for (size_t i = 0; i < n; ++i) {
        const auto g = i < got.size() ? got[i] : std::complex<double>{0.0, 0.0};
        const auto r = i < ref.size() ? ref[i] : std::complex<double>{0.0, 0.0};
        EXPECT_LT(std::abs(g - r), tol) << "coefficient " << i;
    }
}

std::function<int64_t(int64_t)> Sawtooth(uint32_t p) {
    const int64_t pi = p;
    return [pi](int64_t x) {
        return (x % pi - pi / 2) % pi;
    };
}

std::function<int64_t(int64_t)> Step(uint32_t p) {
    const int64_t pi = p;
    return [pi](int64_t x) {
        return (x % pi) >= pi / 2 ? 1 : 0;
    };
}

}  // namespace

TEST(UTHermite, MatchesDirectSums) {
    for (uint32_t p : {2u, 4u, 8u, 16u, 64u, 256u}) {
        for (size_t order : {1u, 2u, 3u}) {
            for (const auto& f : {Sawtooth(p), Step(p)}) {
                const auto ref = ReferenceHermite(f, p, order, 32.0);
                const auto got = GetHermiteTrigCoefficients(f, p, order, 32.0);
                ExpectSeriesEqual(got, ref, 1e-12 * std::max(1.0, MaxAbs(ref)));
            }
        }
    }
}

TEST(UTHermite, NonPowerOfTwoLength) {
    for (uint32_t p : {3u, 6u, 12u, 100u}) {
        for (size_t order : {1u, 2u, 3u}) {
            const auto ref = ReferenceHermite(Sawtooth(p), p, order, 1.0);
            const auto got = GetHermiteTrigCoefficients(Sawtooth(p), p, order, 1.0);
            ExpectSeriesEqual(got, ref, 1e-12 * std::max(1.0, MaxAbs(ref)));
        }
    }
}

TEST(UTHermite, ScaleDividesCoefficients) {
    const uint32_t p = 256;
    const auto one = GetHermiteTrigCoefficients(Sawtooth(p), p, 1, 1.0);
    const auto scaled = GetHermiteTrigCoefficients(Sawtooth(p), p, 1, 32.0);
    ASSERT_EQ(one.size(), scaled.size());
    for (size_t i = 0; i < one.size(); ++i)
        EXPECT_LT(std::abs(one[i] / 32.0 - scaled[i]), 1e-15 * std::max(1.0, std::abs(one[i])));
}

TEST(UTHermite, SixteenBitLUT) {
    const uint32_t p = 1U << 16;
    const auto coeffs = GetHermiteTrigCoefficients(Sawtooth(p), p, 1, 16384.0);
    ASSERT_GT(coeffs.size(), 1u);
    for (const auto& c : coeffs) {
        EXPECT_TRUE(std::isfinite(c.real()) && std::isfinite(c.imag()));
    }
    EXPECT_GT(MaxAbs(coeffs), 0.0);
}
