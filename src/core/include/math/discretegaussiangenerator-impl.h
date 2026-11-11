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

#ifndef SRC_CORE_INCLUDE_MATH_DISCRETEGAUSSIANGENERATOR_IMPL_H_
#define SRC_CORE_INCLUDE_MATH_DISCRETEGAUSSIANGENERATOR_IMPL_H_

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <memory>
#include <random>
#include <string>
#include <typeinfo>
#include <vector>

#include "math/discretegaussiangenerator.h"
#include "utils/exception.h"
#include "utils/prng/blake2engine.h"

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
    if (std::log2((m_std = std)) > 59)
        OPENFHE_THROW("Standard deviation cannot exceed 59 bits");
    if ((m_peikert = (m_std < KARNEY_THRESHOLD)))
        this->Initialize();
}

template <typename VecType>
double DiscreteGaussianGeneratorImpl<VecType>::GetStd() const {
    return m_std;
}

template <typename VecType>
void DiscreteGaussianGeneratorImpl<VecType>::Initialize() {
    // usually the bound of m_std * M is used, where M = 12 .. 40
    // we use M = std::sqrt(-2. * std::log(5e-32)) = 12.0061 here,
    // which corresponds to the probability of roughly 2^(-100)
    double M{12.00610553538285};
    int64_t fin{static_cast<int64_t>(std::ceil(m_std * M))};
    m_vals.resize(fin);
    double variance{2 * m_std * m_std};
    double cusum{0.0};
    for (int64_t x = 1; x <= fin; ++x)
        m_vals[x - 1] = (cusum += std::exp(-(static_cast<double>(x * x) / variance)));
    m_a = 1.0 / (2 * cusum + 1.0);
    for (int64_t x = 0; x < fin; ++x)
        m_vals[x] *= m_a;
}

template <typename VecType>
int64_t DiscreteGaussianGeneratorImpl<VecType>::GenerateInt() const {
    return GenerateInt(PseudoRandomNumberGenerator::GetPRNG());
}

template <typename VecType>
int64_t DiscreteGaussianGeneratorImpl<VecType>::GenerateInt(PRNG& g) const {
    const uint32_t w0{g()};
    const uint32_t w1{g()};
    return InversionSample(w0, w1);
}

template <typename VecType>
int64_t DiscreteGaussianGeneratorImpl<VecType>::InversionSample(uint32_t w0, uint32_t w1) const {
    static_assert(PRNG::min() == 0 && PRNG::max() == std::numeric_limits<uint32_t>::max(),
                  "PRNG words must be uniform over all 32-bit values");
    // we need to use the binary uniform generator rather than regular continuous
    // distribution; see DG14 for details
    const double u{(static_cast<double>(w1) * 0x1p32 + static_cast<double>(w0)) * 0x1p-64};
    const double seed{std::min(u, LARGEST_BELOW_ONE) - 0.5};
    const double tmp{std::abs(seed) - m_a / 2};
    const size_t head{std::min(m_vals.size(), HEAD_SIZE)};
    size_t below{0};
    for (size_t i = 0; i < head; ++i)
        below += static_cast<size_t>(m_vals[i] < tmp);
    if (below == head)
        below += std::lower_bound(m_vals.begin() + head, m_vals.end(), tmp) - (m_vals.begin() + head);
    if (below == m_vals.size() && tmp > 0.0)
        OPENFHE_THROW("DGG Inversion Sampling. Value not found: " + std::to_string(tmp));
    const int64_t mag{(tmp <= 0.0) ? 0 : static_cast<int64_t>(below) + 1};
    return (seed > 0.0) ? mag : -mag;
}

template <typename VecType>
template <typename Store>
void DiscreteGaussianGeneratorImpl<VecType>::ForEachSample(uint32_t size, Store&& store) const {
    auto& g = PseudoRandomNumberGenerator::GetPRNG();
    if (!m_peikert) {
        for (uint32_t i = 0; i < size; ++i)
            store(i, GenerateIntegerKarney(0, m_std, g));
    } else if (typeid(g) == typeid(default_prng::Blake2Engine)) {
        auto& blake = static_cast<default_prng::Blake2Engine&>(g);
        for (uint32_t i = 0; i < size; ++i) {
            const uint32_t w0{blake.default_prng::Blake2Engine::operator()()};
            const uint32_t w1{blake.default_prng::Blake2Engine::operator()()};
            store(i, InversionSample(w0, w1));
        }
    } else {
        for (uint32_t i = 0; i < size; ++i)
            store(i, GenerateInt(g));
    }
}

template <typename VecType>
std::vector<int64_t> DiscreteGaussianGeneratorImpl<VecType>::GenerateIntVector(uint32_t size) const {
    std::vector<int64_t> ans(size);
    ForEachSample(size, [&ans](uint32_t i, int64_t val) { ans[i] = val; });
    return ans;
}

template <typename VecType>
typename VecType::Integer DiscreteGaussianGeneratorImpl<VecType>::GenerateInteger(
        const typename VecType::Integer& modulus) const {
    return Residue(m_peikert ? GenerateInt() : GenerateIntegerKarney(0, m_std), modulus);
}

template <typename VecType>
VecType DiscreteGaussianGeneratorImpl<VecType>::GenerateVector(uint32_t size,
                                                               const typename VecType::Integer& modulus) const {
    VecType ans(size, modulus);
    const typename VecType::Integer q{modulus};
    ForEachSample(size, [&ans, &q](uint32_t i, int64_t val) { ans[i] = Residue(val, q); });
    return ans;
}

template <typename VecType>
typename VecType::Integer DiscreteGaussianGeneratorImpl<VecType>::GenerateInteger(
        double mean, double stddev, size_t n, const typename VecType::Integer& modulus) const {
    double t = std::log2(n) * stddev;

    std::uniform_int_distribution<int32_t> uniform_int(std::floor(mean - t), std::ceil(mean + t));
    std::uniform_real_distribution<double> uniform_real(0.0, 1.0);

    int32_t x;
    do {
        x = uniform_int(PseudoRandomNumberGenerator::GetPRNG());
    } while (uniform_real(PseudoRandomNumberGenerator::GetPRNG()) > UnnormalizedGaussianPDF(mean, stddev, x));

    if (x < 0)
        return modulus - typename VecType::Integer(-x);
    return typename VecType::Integer(x);
}

template <typename VecType>
int32_t DiscreteGaussianGeneratorImpl<VecType>::GenerateInteger(double mean, double stddev, size_t n) const {
    if (std::isinf(mean))
        OPENFHE_THROW("DiscreteGaussianGeneratorImpl called with mean == +-inf");
    if (std::isinf(stddev))
        OPENFHE_THROW("DiscreteGaussianGeneratorImpl called with stddev == +-inf");

    // this representation of log_2 is used for Visual Studio
    double t = std::log2(n) * stddev;
    std::uniform_int_distribution<int32_t> uniform_int(std::floor(mean - t), std::ceil(mean + t));
    std::uniform_real_distribution<double> uniform_real(0.0, 1.0);

    double sigmaFactor = 1 / (-2. * stddev * stddev);
    uint32_t count = 0;
    constexpr uint32_t limit = 10000;

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
    return GenerateIntegerKarney(mean, stddev, PseudoRandomNumberGenerator::GetPRNG());
}

template <typename VecType>
int64_t DiscreteGaussianGeneratorImpl<VecType>::GenerateIntegerKarney(double mean, double stddev, PRNG& g) {
    std::uniform_int_distribution<int64_t> uniform_sign(0, 1);
    std::uniform_int_distribution<int64_t> uniform_j(0, std::ceil(stddev) - 1);

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
        double x0 = (i0 - di0) / stddev;
        int64_t j = uniform_j(g);

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
    } else {  // numbers are equal - need higher precision
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

    float y = x;
    int32_t n = 0, m = 2 * k + 2;
    float z, r;
    float rTemp;

    for (;; ++n) {
        z = dist(g);
        if (z > y) {
            break;
        } else if (z < y) {
            r = dist(g);
            rTemp = (2 * k + x) / m;
            if (r > rTemp)
                break;
            else if (r < rTemp)
                y = z;
            else  // r == Temp - need double precision
                return AlgorithmBDouble(g, k, x);
        } else {  // z == x - need double precision
            return AlgorithmBDouble(g, k, x);
        }
    }

    return (n % 2) == 0;
}

template <typename VecType>
bool DiscreteGaussianGeneratorImpl<VecType>::AlgorithmBDouble(PRNG& g, int32_t k, double x) {
    std::uniform_real_distribution<double> dist(0.0, 1.0);

    double y = x;
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

#endif  // SRC_CORE_INCLUDE_MATH_DISCRETEGAUSSIANGENERATOR_IMPL_H_
