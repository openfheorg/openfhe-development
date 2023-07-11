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

#ifndef LBCRYPTO_INC_MATH_TERNARYUNIFORMGENERATOR_H_
#define LBCRYPTO_INC_MATH_TERNARYUNIFORMGENERATOR_H_

#include "math/distributiongenerator.h"
#include "math/math-hal.h"

#include <memory>
#include <random>

namespace lbcrypto {

/**
 * @brief A generator of the Ternary Uniform Distribution.
 */
template <typename VecType>
class TernaryUniformGeneratorImpl {
public:
    /**
   * @brief Basic constructor for Binary Uniform Generator.
   */
    TernaryUniformGeneratorImpl()  = default;
    ~TernaryUniformGeneratorImpl() = default;

    typename VecType::Integer GenerateInteger(const typename VecType::Integer&) const {
        return 0;
    }

    /**
   * @brief  Generates a vector of random values within the Ternary Uniform
   * Distribution.
   * @param size length of the vector.
   * @param modulus the modulus applied to all values of the vector.
   * @param h - Hamming weight for sparse ternary distribution (by default, when
   * h = 0, the distribution is NOT sparse)
   * @return A vector of random values within the Ternary Uniform Distribution.
   */
    VecType GenerateVector(usint size, const typename VecType::Integer& modulus, usint h = 0) const;

    /**
   * @brief      Returns a generated vector of integers.
   * @param size The number of values to return.
   * @param h - Hamming weight for sparse ternary distribution (by default, when
   * h = 0, the distribution is NOT sparse)
   * @return     A pointer to an array of integer values generated with the
   * distribution.
   */
    std::shared_ptr<int32_t> GenerateIntVector(usint size, usint h = 0) const;

private:
    static std::uniform_int_distribution<int> m_distribution;
};

}  // namespace lbcrypto

#endif  // LBCRYPTO_INC_MATH_TERNARYUNIFORMGENERATOR_H_
