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
  This code provides generation of a uniform distribution of binary values (modulus 2)
 */

#ifndef LBCRYPTO_INC_MATH_TERNARYUNIFORMGENERATOR_IMPL_H_
#define LBCRYPTO_INC_MATH_TERNARYUNIFORMGENERATOR_IMPL_H_

#include "math/binaryuniformgenerator.h"
#include "math/ternaryuniformgenerator.h"

#include "utils/inttypes.h"

#include <memory>
#include <random>
#include <vector>

namespace lbcrypto {

template <typename VecType>
std::uniform_int_distribution<int32_t> TernaryUniformGeneratorImpl<VecType>::m_distribution =
    std::uniform_int_distribution<int32_t>(-1, 1);

template <typename VecType>
VecType TernaryUniformGeneratorImpl<VecType>::GenerateVector(uint32_t size, const typename VecType::Integer& modulus,
                                                             uint32_t h) const {
    if (h == 0) {
        // regular ternary distribution
        VecType v(size, modulus, modulus - typename VecType::Integer(1));
        for (uint32_t i = 0; i < size; ++i) {
            if (auto rn = m_distribution(PseudoRandomNumberGenerator::GetPRNG()); rn >= 0)
                v[i] = typename VecType::Integer(rn);
        }
        return v;
    }

    if (h > size)
        h = size;

    VecType v(size, modulus);

    auto distrHWT = std::uniform_int_distribution<int32_t>(0, size - 1);
    BinaryUniformGeneratorImpl<VecType> bug;
    uint32_t counterPlus = 0;

    // makes sure the +1's and -1's are roughly evenly distributed
    while ((counterPlus < h / 2 - 1) || (counterPlus > h / 2 + 1)) {
        // initializes all values
        counterPlus = 0;
        for (uint32_t k = 0; k < size; ++k)
            v[k] = typename VecType::Integer(0);

        uint32_t i = 0;
        while (i < h) {
            // random index in the vector
            auto randomIndex = distrHWT(PseudoRandomNumberGenerator::GetPRNG());
            if (v[randomIndex] == typename VecType::Integer(0)) {
                if (bug.GenerateInteger() == typename VecType::Integer(0)) {
                    v[randomIndex] = modulus - typename VecType::Integer(1);
                }
                else {
                    v[randomIndex] = typename VecType::Integer(1);
                    ++counterPlus;
                }
                ++i;
            }
        }
    }
    return v;
}

template <typename VecType>
std::vector<int32_t> TernaryUniformGeneratorImpl<VecType>::GenerateIntVector(uint32_t size, uint32_t h) const {
    if (h == 0) {
        std::vector<int32_t> v(size);
        for (uint32_t i = 0; i < size; ++i)
            v[i] = m_distribution(PseudoRandomNumberGenerator::GetPRNG());
        return v;
    }

    if (h > size)
        h = size;

    std::vector<int32_t> v(size);

    auto distrHWT = std::uniform_int_distribution<int32_t>(0, size - 1);
    BinaryUniformGeneratorImpl<VecType> bug;
    uint32_t counterPlus = 0;

    // makes sure the +1's and -1's are roughly evenly distributed
    while ((counterPlus < h / 2 - 1) || (counterPlus > h / 2 + 1)) {
        // initializes all values
        counterPlus = 0;
        for (uint32_t k = 0; k < size; ++k)
            v[k] = 0;

        uint32_t i = 0;
        while (i < h) {
            // random index in the vector
            auto randomIndex = distrHWT(PseudoRandomNumberGenerator::GetPRNG());
            if (v[randomIndex] == 0) {
                if (bug.GenerateInteger() == typename VecType::Integer(0)) {
                    v[randomIndex] = -1;
                }
                else {
                    v[randomIndex] = 1;
                    ++counterPlus;
                }
                ++i;
            }
        }
    }
    return v;
}

}  // namespace lbcrypto

#endif
