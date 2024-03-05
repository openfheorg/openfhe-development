// clang-format off
//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
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
  PRNG engine based on BLAKE2b
 */

#ifndef _SRC_LIB_UTILS_BLAKE2ENGINE_H
#define _SRC_LIB_UTILS_BLAKE2ENGINE_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <array>
#include <limits>

#include "blake2.h"

#include "utils/exception.h"

namespace lbcrypto {

// the buffer stores 1024 samples of 32-bit integers
const uint32_t PRNG_BUFFER_SIZE = 1024;

/**
 * @brief Defines the PRNG engine used by OpenFHE. It is based on BLAKE2. Use
 * this as a template for adding other PRNG engines to OpenFHE.
 */
class Blake2Engine {
 public:
  // all C++11 distributions used in OpenFHE work by default with uint32_t
  // a different data type can be specified if needed for a particular
  // architecture
  using result_type = uint32_t;

  /**
   * @brief Constructor using a small seed - used for generating a large seed
   */
  explicit Blake2Engine(result_type seed)
      : m_counter(0), m_buffer({}), m_bufferIndex(0) {
    m_seed[0] = seed;
  }

  /**
   * @brief Main constructor taking a vector of 16 integers as a seed
   */
  explicit Blake2Engine(const std::array<result_type, 16>& seed)
      : m_counter(0), m_seed(seed), m_buffer({}), m_bufferIndex(0) {}

  /**
   * @brief Main constructor taking a vector of 16 integers as a seed and a
   * counter
   */
  explicit Blake2Engine(const std::array<result_type, 16>& seed,
                        result_type counter)
      : m_counter(counter), m_seed(seed), m_buffer({}), m_bufferIndex(0) {}

  /**
   * @brief minimum value used by C+11 distribution generators when no lower
   * bound is explicitly specified by the user
   */
  static constexpr result_type min() {
    return std::numeric_limits<result_type>::min();
  }

  /**
   * @brief maximum value used by C+11 distribution generators when no upper
   * bound is explicitly specified by the user
   */
  static constexpr result_type max() {
    return std::numeric_limits<result_type>::max();
  }

  /**
   * @brief main call to the PRNG
   */
  result_type operator()() {
    result_type result;

    if (m_bufferIndex == PRNG_BUFFER_SIZE) m_bufferIndex = 0;

    // makes a call to the BLAKE2 generator only when the currently buffered
    // values are all consumed precomputations are done only once for the
    // current buffer
    if (m_bufferIndex == 0) Generate();

    result = m_buffer[m_bufferIndex];

    m_bufferIndex++;

    return result;
  }

  Blake2Engine(const Blake2Engine& other) {
    m_counter = other.m_counter;
    m_seed = other.m_seed;
    m_buffer = other.m_buffer;
    m_bufferIndex = other.m_bufferIndex;
  }

  void operator=(const Blake2Engine& other) {
    m_counter = other.m_counter;
    m_seed = other.m_seed;
    m_buffer = other.m_buffer;
    m_bufferIndex = other.m_bufferIndex;
  }

 private:
  /**
   * @brief The main call to blake2xb function
   */
  void Generate() {
    // m_counter is the input to the hash function
    // m_buffer is the output
    if (blake2xb(m_buffer.begin(), m_buffer.size() * sizeof(result_type),
                 &m_counter, sizeof(m_counter), m_seed.cbegin(),
                 m_seed.size() * sizeof(result_type)) != 0) {
      OPENFHE_THROW(math_error, "PRNG: blake2xb failed");
    }
    m_counter++;
    return;
  }

  // counter used as input to the BLAKE2 hash function
  // gets incremented after each call
  uint64_t m_counter = 0;

  // the seed for the BLAKE2 hash function
  std::array<result_type, 16> m_seed{};

  // The vector that stores random samples generated using the hash function
  std::array<result_type, PRNG_BUFFER_SIZE> m_buffer{};

  // Index in m_buffer corresponding to the current PRNG sample
  uint16_t m_bufferIndex = 0;
};

}  // namespace lbcrypto

#endif
// clang-format on
