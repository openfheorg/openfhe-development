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
  This code provides generation of gaussian distributions of discrete values. Discrete uniform generator relies on
  the built-in C++ generator for 32-bit unsigned integers defined in <random>
 */

#ifndef LBCRYPTO_INC_MATH_DISCRETEGAUSSIANGENERATOR_IMPL_H_
#define LBCRYPTO_INC_MATH_DISCRETEGAUSSIANGENERATOR_IMPL_H_

#include "math/discretegaussiangenerator.h"
#include "utils/exception.h"

#include <cmath>
#include <memory>
#include <string>
#include <vector>

namespace lbcrypto {

template <typename VecType>
DiscreteGaussianGeneratorImpl<VecType>::DiscreteGaussianGeneratorImpl(double std) {
    SetStd(std);
}

template <typename VecType>
bool DiscreteGaussianGeneratorImpl<VecType>::IsInitialized() const {
    return m_std > 1.000000001;
}

template <typename VecType>
void DiscreteGaussianGeneratorImpl<VecType>::SetStd(double std) {
    if (log2(m_std) > 59) {
        //    if (lbcrypto::GetMSB(static_cast<uint64_t>(std)) > 59) {
        std::string errorMsg(std::string("Standard deviation cannot exceed 59 bits"));
        OPENFHE_THROW(errorMsg);
    }

    if ((peikert = ((m_std = std) < KARNEY_THRESHOLD)))
        this->Initialize();
}

template <typename VecType>
double DiscreteGaussianGeneratorImpl<VecType>::GetStd() const {
    return m_std;
}

template <typename VecType>
void DiscreteGaussianGeneratorImpl<VecType>::Initialize() {
    // usually the bound of m_std * M is used, where M = 12 .. 40
    // we use M = 12 here, which corresponds to the probability of roughly 2^(-100)
    constexpr double acc{5e-32};
    constexpr double M{noexcept(sqrt(-2 * log(acc)))};
    int fin{static_cast<int>(ceil(m_std * M))};

    m_vals.clear();
    m_vals.reserve(fin);
    double variance{2 * m_std * m_std};
    double cusum{0.0};
    for (int x = 1; x <= fin; ++x) {
        cusum += exp(-(static_cast<double>(x * x) / variance));
        m_vals.push_back(cusum);
    }
    m_a = 1.0 / (2 * cusum + 1.0);

    for (int x = 0; x < fin; ++x)
        m_vals[x] *= m_a;
}

template <typename VecType>
int32_t DiscreteGaussianGeneratorImpl<VecType>::GenerateInt() const {
    // we need to use the binary uniform generator rather than regular continuous
    // distribution; see DG14 for details
    double seed = std::uniform_real_distribution<double>(0.0, 1.0)(PseudoRandomNumberGenerator::GetPRNG()) - 0.5;
    double tmp  = std::abs(seed) - m_a / 2;
    if (tmp <= 0)
        return 0;
    return static_cast<int32_t>(FindInVector(m_vals, tmp)) * (seed > 0 ? 1 : -1);
}

template <typename VecType>
std::shared_ptr<int64_t> DiscreteGaussianGeneratorImpl<VecType>::GenerateIntVector(uint32_t size) const {
    std::shared_ptr<int64_t> ans(new int64_t[size], std::default_delete<int64_t[]>());

    if (!peikert) {
        for (uint32_t i = 0; i < size; ++i)
            (ans.get())[i] = GenerateIntegerKarney(0, m_std);
        return ans;
    }

    std::uniform_real_distribution<double> distribution(0.0, 1.0);
    for (uint32_t i = 0; i < size; ++i) {
        // we need to use the binary uniform generator rather than regular
        // continuous distribution; see DG14 for details
        double seed = distribution(PseudoRandomNumberGenerator::GetPRNG()) - 0.5;
        double tmp  = std::abs(seed) - m_a / 2;
        int64_t val = 0;
        if (tmp > 0)
            val = static_cast<int64_t>(FindInVector(m_vals, tmp)) * (seed > 0 ? 1 : -1);
        (ans.get())[i] = val;
    }
    return ans;
}

template <typename VecType>
uint32_t DiscreteGaussianGeneratorImpl<VecType>::FindInVector(const std::vector<double>& S, double search) const {
    // STL binary search implementation
    auto lower = std::lower_bound(S.begin(), S.end(), search);
    if (lower != S.end()) {
        return lower - S.begin() + 1;
    }
    OPENFHE_THROW("DGG Inversion Sampling. FindInVector value not found: " + std::to_string(search));
}

template <typename VecType>
typename VecType::Integer DiscreteGaussianGeneratorImpl<VecType>::GenerateInteger(
    const typename VecType::Integer& modulus) const {
    double seed = std::uniform_real_distribution<double>(0.0, 1.0)(PseudoRandomNumberGenerator::GetPRNG()) - 0.5;
    double tmp  = std::abs(seed) - m_a / 2;
    if (tmp <= 0)
        return typename VecType::Integer(0);
    auto val = static_cast<int32_t>(FindInVector(m_vals, tmp)) * (seed > 0 ? 1 : -1);
    if (val < 0)
        return modulus - typename VecType::Integer(-val);
    return typename VecType::Integer(val);
}

template <typename VecType>
VecType DiscreteGaussianGeneratorImpl<VecType>::GenerateVector(const uint32_t size,
                                                               const typename VecType::Integer& modulus) const {
    auto result = GenerateIntVector(size);
    VecType ans(size, modulus);
    for (uint32_t i = 0; i < size; ++i) {
        int32_t v = (result.get())[i];
        if (v < 0)
            ans[i] = modulus - typename VecType::Integer(-v);
        else
            ans[i] = typename VecType::Integer(v);
    }
    return ans;
}

template <typename VecType>
typename VecType::Integer DiscreteGaussianGeneratorImpl<VecType>::GenerateInteger(
    double mean, double stddev, size_t n, const typename VecType::Integer& modulus) const {
    double t = log2(n) * stddev;

    std::uniform_int_distribution<int32_t> uniform_int(floor(mean - t), ceil(mean + t));
    std::uniform_real_distribution<double> uniform_real(0.0, 1.0);

    int32_t x;
    do {
        x = uniform_int(PseudoRandomNumberGenerator::GetPRNG());
    } while (uniform_real(PseudoRandomNumberGenerator::GetPRNG()) > UnnormalizedGaussianPDF(mean, stddev, x));

    if (x < 0)
        return modulus - typename VecType::Integer(-x);
    return typename VecType::Integer(x);
}

///////////

template <typename VecType>
int32_t DiscreteGaussianGeneratorImpl<VecType>::GenerateInteger(double mean, double stddev, size_t n) const {
    if (std::isinf(mean))
        OPENFHE_THROW("DiscreteGaussianGeneratorImpl called with mean == +-inf");
    if (std::isinf(stddev))
        OPENFHE_THROW("DiscreteGaussianGeneratorImpl called with stddev == +-inf");

    // this representation of log_2 is used for Visual Studio
    double t = log2(n) * stddev;
    std::uniform_int_distribution<int32_t> uniform_int(floor(mean - t), ceil(mean + t));
    std::uniform_real_distribution<double> uniform_real(0.0, 1.0);

    double sigmaFactor   = 1 / (-2. * stddev * stddev);
    uint32_t count       = 0;
    const uint32_t limit = 10000;

    int32_t x;
    bool flagSuccess = false;
    while (!flagSuccess) {
        //  pick random int
        x = uniform_int(PseudoRandomNumberGenerator::GetPRNG());
        //  roll the uniform dice
        auto dice = uniform_real(PseudoRandomNumberGenerator::GetPRNG());
        //  check if dice land below pdf
        flagSuccess = (dice <= UnnormalizedGaussianPDFOptimized(mean, sigmaFactor, x));
        if (++count > limit)
            OPENFHE_THROW("GenerateInteger could not find success after repeated attempts");
    }
    return x;
}

template <typename VecType>
int64_t DiscreteGaussianGeneratorImpl<VecType>::GenerateIntegerKarney(double mean, double stddev) {
    std::uniform_int_distribution<int64_t> uniform_sign(0, 1);
    std::uniform_int_distribution<int64_t> uniform_j(0, ceil(stddev) - 1);

    PRNG& g = PseudoRandomNumberGenerator::GetPRNG();

    while (true) {
        // STEP D1
        int32_t k = AlgorithmG(g);

        // STEP D2
        if (!AlgorithmP(g, k * (k - 1)))
            continue;

        // STEP D3
        int64_t s = uniform_sign(g);
        if (s == 0)
            s = -1;

        // STEP D4
        double di0 = stddev * k + s * mean;
        int64_t i0 = std::ceil(di0);
        double x0  = (i0 - di0) / stddev;
        int64_t j  = uniform_j(g);

        double x = x0 + j / stddev;

        // STEPS D5 and D6
        if (!(x < 1) || (x == 0 && s < 0 && k == 0))
            continue;

        // STEP D7
        int32_t h = k + 1;
        while (h-- && AlgorithmB(g, k, x)) {
        }
        if (!(h < 0))
            continue;

        // STEP D8
        return (s * (i0 + j));
    }
}

template <typename VecType>
bool DiscreteGaussianGeneratorImpl<VecType>::AlgorithmP(PRNG& g, int n) {
    while (n-- && AlgorithmH(g)) {
    }
    return n < 0;
}

template <typename VecType>
int32_t DiscreteGaussianGeneratorImpl<VecType>::AlgorithmG(PRNG& g) {
    int n = 0;
    while (AlgorithmH(g))
        ++n;
    return n;
}

// Use single floating-point precision in most cases; if a situation w/ not
// enough precision is encountered, call the double-precision algorithm
template <typename VecType>
bool DiscreteGaussianGeneratorImpl<VecType>::AlgorithmH(PRNG& g) {
    std::uniform_real_distribution<float> dist(0, 1);
    float h_a, h_b;
    h_a = dist(g);

    // less than the half
    if (h_a > 0.5)
        return true;
    if (h_a < 0.5) {
        for (;;) {
            h_b = dist(g);
            if (h_b > h_a)
                return false;
            else if (h_b < h_a)
                h_a = dist(g);
            else  // numbers are equal - need higher precision
                return AlgorithmHDouble(g);
            if (h_a > h_b)
                return true;
            else if (h_a == h_b)  // numbers are equal - need higher precision
                return AlgorithmHDouble(g);
        }
    }
    else {  // numbers are equal - need higher precision
        return AlgorithmHDouble(g);
    }
}

template <typename VecType>
bool DiscreteGaussianGeneratorImpl<VecType>::AlgorithmHDouble(PRNG& g) {
    std::uniform_real_distribution<double> dist(0, 1);
    double h_a, h_b;
    h_a = dist(g);
    // less than the half
    if (!(h_a < 0.5))
        return true;
    for (;;) {
        h_b = dist(g);
        if (!(h_b < h_a))
            return false;
        else
            h_a = dist(g);
        if (!(h_a < h_b))
            return true;
    }
}

template <typename VecType>
bool DiscreteGaussianGeneratorImpl<VecType>::AlgorithmB(PRNG& g, int32_t k, double x) {
    std::uniform_real_distribution<float> dist(0.0, 1.0);

    float y   = x;
    int32_t n = 0, m = 2 * k + 2;
    float z, r;
    float rTemp;

    for (;; ++n) {
        z = dist(g);
        if (z > y) {
            break;
        }
        else if (z < y) {
            r     = dist(g);
            rTemp = (2 * k + x) / m;
            if (r > rTemp)
                break;
            else if (r < rTemp)
                y = z;
            else  // r == Temp - need double precision
                return AlgorithmBDouble(g, k, x);
        }
        else {  // z == x - need double precision
            return AlgorithmBDouble(g, k, x);
        }
    }

    return (n % 2) == 0;
}

template <typename VecType>
bool DiscreteGaussianGeneratorImpl<VecType>::AlgorithmBDouble(PRNG& g, int32_t k, double x) {
    std::uniform_real_distribution<double> dist(0.0, 1.0);

    double y  = x;
    int32_t n = 0, m = 2 * k + 2;
    double z, r;

    for (;; ++n) {
        z = dist(g);
        if (!(z < y))
            break;
        r = dist(g);
        if (!(r < (2 * k + x) / m))
            break;
        y = z;
    }

    return (n % 2) == 0;
}

}  // namespace lbcrypto

#endif
