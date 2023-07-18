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
  This code provides basic structure for distribution generators. This should be inherited by
  all other distribution generators
 */

#ifndef LBCRYPTO_INC_MATH_DISTRIBUTIONGENERATOR_H_
#define LBCRYPTO_INC_MATH_DISTRIBUTIONGENERATOR_H_

// #include "math/math-hal.h"

#include "utils/parallel.h"
#include "utils/prng/blake2engine.h"

#include <chrono>
#include <memory>
// #include <mutex>
#include <random>
#include <thread>

// #define FIXED_SEED // if defined, then uses a fixed seed number for
// reproducible results during debug. Use only one OMP thread to ensure
// reproducibility

namespace lbcrypto {

// Defines the PRNG implementation used by OpenFHE.
// The cryptographically secure PRNG used by OpenFHE is based on BLAKE2 hash
// functions. A user can replace it with a different PRNG if desired by defining
// the same methods as for the Blake2Engine class.
typedef Blake2Engine PRNG;

/**
 * @brief The class providing the PRNG capability to all random distribution
 * generators in OpenFHE. THe security of Ring Learning With Errors (used for
 * all crypto capabilities in OpenFHE) depends on the randomness of uniform,
 * ternary, and Gaussian distributions, which derive their randomness from the
 * PRNG.
 */
class PseudoRandomNumberGenerator {
public:
    /**
   * @brief  Returns a reference to the PRNG engine
   */

    // TODO: there may be an issue here
    static void InitPRNG() {
        int threads = OpenFHEParallelControls.GetNumThreads();
        if (threads == 0) {
            threads = 1;
        }
#pragma omp parallel for num_threads(threads)
        for (int i = 0; i < threads; ++i) {
            GetPRNG();
        }
    }

    static PRNG& GetPRNG() {
        // initialization of PRNGs
        if (m_prng == nullptr) {
#pragma omp critical
            {
#if defined(FIXED_SEED)
                // Only used for debugging in the single-threaded mode.
                std::cerr << "**FOR DEBUGGING ONLY!!!!  Using fixed initializer for "
                             "PRNG. Use a single thread only, e.g., OMP_NUM_THREADS=1!"
                          << std::endl;

                std::array<uint32_t, 16> seed{};
                seed[0] = 1;
                m_prng  = std::make_shared<PRNG>(seed);
#else
                // A 512-bit seed is generated for each thread (this roughly corresponds
                // to 256 bits of security). The seed is the sum of a random sample
                // generated using std::random_device (typically works correctly in
                // Linux, MacOS X, and MinGW starting with GCC 9.2) and a BLAKE2 sample
                // seeded from current time stamp, a hash of the current thread, and a
                // memory location of a heap variable. The BLAKE2 sample is added in
                // case random_device is deterministic (happens on MinGW with GCC
                // below 9.2). All future calls to PRNG use the seed generated here.

                // The code below derives randomness from time, thread id, and a memory
                // location of a heap variable. This seed is relevant only if the
                // implementation of random_device is deterministic (as in older
                // versions of GCC in MinGW)
                std::array<uint32_t, 16> initKey{};
                // high-resolution clock typically has a nanosecond tick period
                // Arguably this may give up to 32 bits of entropy as the clock gets
                // recycled every 4.3 seconds
                initKey[0] = std::chrono::high_resolution_clock::now().time_since_epoch().count();
                // A thread id is often close to being random (on most systems)
                initKey[1] = std::hash<std::thread::id>{}(std::this_thread::get_id());
                    // On a 64-bit machine, the thread id is 64 bits long
                    // skip on 32-bit arm architectures
    #if !defined(__arm__) && !defined(__EMSCRIPTEN__)
                if (sizeof(size_t) == 8)
                    initKey[2] = (std::hash<std::thread::id>{}(std::this_thread::get_id()) >> 32);
    #endif

                // heap variable; we are going to use the least 32 bits of its memory
                // location as the counter for BLAKE2 This will increase the entropy of
                // the BLAKE2 sample
                void* mem        = malloc(1);
                uint32_t counter = reinterpret_cast<long long>(mem);  // NOLINT
                free(mem);

                PRNG gen(initKey, counter);

                std::uniform_int_distribution<uint32_t> distribution(0);
                std::array<uint32_t, 16> seed{};
                for (uint32_t i = 0; i < 16; i++) {
                    seed[i] = distribution(gen);
                }

                std::array<uint32_t, 16> rdseed{};
                size_t attempts  = 3;
                bool rdGenPassed = false;
                size_t idx       = 0;
                while (!rdGenPassed && idx < attempts) {
                    try {
                        std::random_device genR;
                        for (uint32_t i = 0; i < 16; i++) {
                            // we use the fact that there is no overflow for unsigned integers
                            // (from C++ standard) i.e., arithmetic mod 2^32 is performed. For
                            // the seed to be random, it is sufficient for one of the two
                            // samples below to be random. In almost all practical cases,
                            // distribution(genR) is random. We add distribution(gen) just in
                            // case there is an implementation issue with random_device (as in
                            // older MinGW systems).
                            rdseed[i] = distribution(genR);
                        }
                        rdGenPassed = true;
                    }
                    catch (std::exception& e) {
                    }
                    idx++;
                }

                for (uint32_t i = 0; i < 16; i++) {
                    seed[i] += rdseed[i];
                }

                m_prng = std::make_shared<PRNG>(seed);
#endif
            }
        }
        return *m_prng;
    }

private:
    // shared pointer to a thread-specific PRNG engine
    static std::shared_ptr<PRNG> m_prng;

#if !defined(FIXED_SEED)
        // avoid contention on m_prng
        // local copies of m_prng are created for each thread
    #pragma omp threadprivate(m_prng)
#endif
};

}  // namespace lbcrypto

#endif  // LBCRYPTO_INC_MATH_DISTRIBUTIONGENERATOR_H_
