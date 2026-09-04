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
  This code provides generation of uniform distributions of discrete values. Discrete uniform generator relies on
  the built-in C++ generator for 32-bit unsigned integers defined in <random>
 */

#ifndef LBCRYPTO_INC_MATH_DISCRETEUNIFORMGENERATOR_IMPL_H_
#define LBCRYPTO_INC_MATH_DISCRETEUNIFORMGENERATOR_IMPL_H_

#include "math/discreteuniformgenerator.h"
#include "math/distributiongenerator.h"
#include "utils/exception.h"

namespace lbcrypto {

template <typename VecType>
DiscreteUniformGeneratorImpl<VecType>::DiscreteUniformGeneratorImpl(const typename VecType::Integer& modulus) {
    SetModulus(modulus);
}

template <typename VecType>
void DiscreteUniformGeneratorImpl<VecType>::SetModulus(const typename VecType::Integer& modulus) {
    m_modulus = modulus;
    if (m_modulus == typename VecType::Integer(0)) {
        m_chunks = 0;  // GenerateInteger/GenerateVector throw on a zero modulus before sampling
        return;
    }
    m_chunks = (m_modulus.GetMSB() + DUG_CHUNK_WIDTH - 1) / DUG_CHUNK_WIDTH;

    // all-ones over the draw domain;
    typename VecType::Integer dmax{DUG_CHUNK_MAX};
    for (uint32_t i{1}; i < m_chunks; ++i)
        dmax = (dmax << DUG_CHUNK_WIDTH) + typename VecType::Integer{DUG_CHUNK_MAX};
    m_limit = (dmax / m_modulus) * m_modulus;
}

template <typename VecType>
typename VecType::Integer DiscreteUniformGeneratorImpl<VecType>::GenerateIntegerWith(
    PRNG& prng, std::uniform_int_distribution<uint32_t>& dist) const {
    // Draw ceil(MSB/32) raw 32-bit words, reject draws at or above the largest contained
    // multiple of the modulus, and reduce: every residue then appears exactly
    // floor(2^(32c)/q) times, so the result is exactly uniform. The rejection probability
    // (2^(32c) mod q) / 2^(32c) is at most a few percent and a retry is just another cheap
    // draw; raw full-range words avoid the per-sample division a bounded top-chunk draw
    // pays inside std::uniform_int_distribution.
    while (true) {
        typename VecType::Integer x{};
        for (uint32_t i{0}, shift{0}; i < m_chunks; ++i, shift += DUG_CHUNK_WIDTH)
            x += typename VecType::Integer{dist(prng)} << shift;
        if (x < m_limit)
            return x.ModEq(m_modulus);
    }
}

template <typename VecType>
typename VecType::Integer DiscreteUniformGeneratorImpl<VecType>::GenerateInteger() const {
    if (m_modulus == typename VecType::Integer(0))
        OPENFHE_THROW("0 modulus?");
    std::uniform_int_distribution<uint32_t> dist(DUG_CHUNK_MIN, DUG_CHUNK_MAX);
    return GenerateIntegerWith(PseudoRandomNumberGenerator::GetPRNG(), dist);
}

template <typename VecType>
VecType DiscreteUniformGeneratorImpl<VecType>::GenerateVector(const uint32_t size) const {
    if (m_modulus == typename VecType::Integer(0))
        OPENFHE_THROW("0 modulus?");
    VecType v(size, m_modulus);
    auto& prng = PseudoRandomNumberGenerator::GetPRNG();
    std::uniform_int_distribution<uint32_t> dist(DUG_CHUNK_MIN, DUG_CHUNK_MAX);
    for (uint32_t i = 0; i < size; ++i)
        v[i] = GenerateIntegerWith(prng, dist);
    return v;
}

template <typename VecType>
VecType DiscreteUniformGeneratorImpl<VecType>::GenerateVector(const uint32_t size,
                                                              const typename VecType::Integer& modulus) {
    SetModulus(modulus);
    return GenerateVector(size);
}

}  // namespace lbcrypto

#endif
