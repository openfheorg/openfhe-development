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

#ifndef SRC_CORE_INCLUDE_MATH_TERNARYUNIFORMGENERATOR_H_
#define SRC_CORE_INCLUDE_MATH_TERNARYUNIFORMGENERATOR_H_

#include <cstdint>
#include <memory>
#include <random>
#include <type_traits>
#include <vector>

#include "math/distributiongenerator.h"
#include "math/math-hal.h"

namespace lbcrypto {

/**
 * @brief A generator of the Ternary Uniform Distribution.
 */
template <typename VecType>
class TernaryUniformGeneratorImpl {
  public:
    /**
     * @brief Basic constructor for Ternary Uniform Generator.
     */
    TernaryUniformGeneratorImpl() = default;
    ~TernaryUniformGeneratorImpl() = default;

    /**
     * @brief Generates a single value uniformly from {-1, 0, 1}, as GenerateVector does for each entry when h = 0.
     * @param modulus the modulus -1 is represented under
     * @return 0, 1 or modulus - 1
     */
    typename VecType::Integer GenerateInteger(const typename VecType::Integer& modulus) const;

    /**
     * @brief  Generates a vector of random values within the Ternary Uniform
     * Distribution.
     * @param size length of the vector.
     * @param modulus the modulus applied to all values of the vector.
     * @param h - Hamming weight for sparse ternary distribution (by default, when
     * h = 0, the distribution is NOT sparse)
     * @return A vector of random values within the Ternary Uniform Distribution.
     */
    VecType GenerateVector(uint32_t size, const typename VecType::Integer& modulus, uint32_t h = 0) const;

    /**
     * @brief      Returns a generated vector of integers.
     * @param size The number of values to return.
     * @param h - Hamming weight for sparse ternary distribution (by default, when
     * h = 0, the distribution is NOT sparse)
     * @return     vector of integer values generated with the distribution
     */
    std::vector<int32_t> GenerateIntVector(uint32_t size, uint32_t h = 0) const;

  private:
    /**
     * @brief Uniform draws from {0, 1, 2}: the base-3 digits of uniform 32-bit words below 3^20, 20 draws per word;
     * words at or above 3^20 are rejected.
     */
    class Draws {
      public:
        explicit Draws(PRNG& prng) : m_prng{prng} {}

        uint32_t operator()() {
            if (m_digitsLeft == 0) {
                do {
                    m_word = m_prng();
                } while (m_word >= WORD_BOUND);
                m_digitsLeft = DIGITS_PER_WORD;
            }
            --m_digitsLeft;
            const uint32_t digit{m_word % 3};
            m_word /= 3;
            return digit;
        }

      private:
        static constexpr uint32_t DIGITS_PER_WORD{20};
        static constexpr uint32_t WORD_BOUND{3486784401u};  // 3^DIGITS_PER_WORD
        PRNG& m_prng;
        uint32_t m_word{0};
        uint32_t m_digitsLeft{0};
    };

    static constexpr bool NATIVE_VECTOR{std::is_same_v<VecType, intnat::NativeVectorT<typename VecType::Integer>>};

    /**
     * @brief Maps a draw from Draws to the residue of draw - 1 modulo modulus without a branch on the draw.
     *
     * @param draw a value in {0, 1, 2}.
     * @param modulus the modulus, as a native word.
     * @return modulus - 1, 0 or 1.
     */
    template <typename NInt>
    static NInt MaskedResidue(uint32_t draw, NInt modulus) {
        const NInt s{draw};
        const NInt zeroMask{NInt(0) - NInt(s == 0)};
        return s - 1 + (modulus & zeroMask);
    }
};

}  // namespace lbcrypto

#endif  // SRC_CORE_INCLUDE_MATH_TERNARYUNIFORMGENERATOR_H_
