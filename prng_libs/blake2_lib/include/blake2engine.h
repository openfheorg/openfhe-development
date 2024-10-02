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

#include "prng.h"
#include "blake2.h"

#include <stdexcept>
#include <array>
#include <limits>
#include <memory>
#include <cstdint>
#include <chrono>
#include <thread>
#include <random>


// the buffer stores 1024 samples of 32-bit integers
const uint32_t PRNG_BUFFER_SIZE = 1024;

/**
 * @brief Defines the PRNG engine used by OpenFHE. It is based on BLAKE2. Use
 * this as a template for adding other PRNG engines to OpenFHE.
 */
class Blake2Engine : public PRNG {
 public:
  enum {MAX_SEED_GENS = 16};

  /**
   * @brief Constructor using a small seed - used for generating a large seed
   */
  explicit Blake2Engine(PRNG::result_type seed)
      : PRNG(seed), m_counter(0), m_buffer({}), m_bufferIndex(0) {
    m_seed[0] = seed;
  }

  // TODO (dsuponit): commented the constructor below and added a default paramter value to the next contructor
  // /**
  //  * @brief Main constructor taking a vector of MAX_SEED_GENS integers as a seed
  //  */
  // explicit Blake2Engine(const std::array<PRNG::result_type, MAX_SEED_GENS>& seed)
  //     : m_counter(0), m_seed(seed), m_buffer({}), m_bufferIndex(0) {}

  /**
   * @brief Main constructor taking a vector of MAX_SEED_GENS integers as a seed and a
   * counter
   */
  explicit Blake2Engine(const std::array<PRNG::result_type, MAX_SEED_GENS>& seed,
                        PRNG::result_type counter = 0)
      : m_counter(counter), m_seed(seed), m_buffer({}), m_bufferIndex(0) {}

  /**
   * @brief main call to the PRNG
   */
  PRNG::result_type operator()() override {
    PRNG::result_type result;

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
    if (blake2xb(m_buffer.begin(), m_buffer.size() * sizeof(PRNG::result_type),
                 &m_counter, sizeof(m_counter), m_seed.cbegin(),
                 m_seed.size() * sizeof(PRNG::result_type)) != 0) {
      throw std::runtime_error("PRNG: blake2xb failed");
    }
    m_counter++;
    return;
  }

  // counter used as input to the BLAKE2 hash function
  // gets incremented after each call
  uint64_t m_counter = 0;

  // the seed for the BLAKE2 hash function
  std::array<PRNG::result_type, MAX_SEED_GENS> m_seed{};

  // The vector that stores random samples generated using the hash function
  std::array<PRNG::result_type, PRNG_BUFFER_SIZE> m_buffer{};

  // Index in m_buffer corresponding to the current PRNG sample
  uint16_t m_bufferIndex = 0;
};

// the code calling createEngineInstance() should clean the memory allocated by createEngineInstance()
// TODO (dsuponit): check with Jack if createEngineInstance() can return an object instead of a pointer. We can do it
// for Blake2Engine
extern "C" {
  Blake2Engine* createEngineInstance();
}
// extern "C" Blake2Engine* createEngineInstance() {
// // initialization of PRNGs
// constexpr size_t maxGens = Blake2Engine::MAX_SEED_GENS;
// #pragma omp critical
//         std::array<uint32_t, maxGens> initKey{};
//         initKey[0] = std::chrono::high_resolution_clock::now().time_since_epoch().count();
//         initKey[1] = std::hash<std::thread::id>{}(std::this_thread::get_id());
// #if !defined(__arm__) && !defined(__EMSCRIPTEN__)
//         if (sizeof(size_t) == 8)
//             initKey[2] = (std::hash<std::thread::id>{}(std::this_thread::get_id()) >> 32);
// #endif
//         void* mem        = malloc(1);
//         uint32_t counter = reinterpret_cast<long long>(mem);  // NOLINT
//         free(mem);

//         Blake2Engine gen(initKey, counter);

//         std::uniform_int_distribution<uint32_t> distribution(0);
//         std::array<uint32_t, maxGens> seed{};
//         for (uint32_t i = 0; i < maxGens; i++) {
//             seed[i] = distribution(gen);
//         }

//         std::array<uint32_t, maxGens> rdseed{};
//         size_t attempts  = 3;
//         bool rdGenPassed = false;
//         for(size_t i = 0; i < attempts && !rdGenPassed; ++i) {
//             try {
//                 std::random_device genR;
//                 for (uint32_t i = 0; i < maxGens; i++) {
//                     rdseed[i] = distribution(genR);
//                 }
//                 rdGenPassed = true;
//             }
//             catch (std::exception& e) {
//             }
//         }
//         for (uint32_t i = 0; i < maxGens; i++) {
//             seed[i] += rdseed[i];
//         }

//         return new Blake2Engine(seed);
// }

#endif
// clang-format on
