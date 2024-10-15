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

#ifndef __DISTRIBUTIONGENERATOR_H__
#define __DISTRIBUTIONGENERATOR_H__

#include "config_core.h"
#include "utils/prng/prng.h"
#include "utils/prng/blake2engine.h"
#include "utils/exception.h"

#include <chrono>
#include <dlfcn.h>
#include <memory>
#include <random>
#include <string>
#include <stdlib.h>
#include <thread>
#include <iostream> // TODO (dsuponit): delete after testing

namespace lbcrypto {
// if FIXED_SEED is defined, then PRNG uses a fixed seed number for reproducible results during debug.
// Use only one OMP thread to ensure reproducibility
// #define FIXED_SEED


/**
 * @brief PseudoRandomNumberGenerator provides the PRNG capability to all random distribution generators in OpenFHE.
 * The security of Ring Learning With Errors (used for all crypto capabilities in OpenFHE) depends on
 * the randomness of uniform, ternary, and Gaussian distributions, which derive their randomness from the PRNG.
 */
class PseudoRandomNumberGenerator {
public:
    /**
   * @brief  Returns a reference to the PRNG engine
   */
    static PRNG& GetPRNG() {
        // initialization of PRNGs
        if (m_prng == nullptr) {
#pragma omp critical
            {
    #ifdef EXTERNAL_PRNG_LIB
                // prepare to get the engine from the engine's shared library
                std::cerr << "PRNG library call" << std::endl;
                const std::string engineLibName{std::string("lib") + PRNG::PRNGLibName + ".so"};
                void* libraryHandle             = dlopen(engineLibName.c_str(), RTLD_LAZY);
                if (!libraryHandle)
                    OPENFHE_THROW("Cannot open " + engineLibName);

                CreateEngineFuncPtrType createEngine = (CreateEngineFuncPtrType)dlsym(libraryHandle, PRNG::engineFuncName);
    #else
                std::cerr << "PRNG default call" << std::endl;
                CreateEngineFuncPtrType createEngine = default_prng::createEngineInstance;
    #endif
                if (!createEngine) {
                    std::string errMsg{std::string("Cannot load symbol ") + PRNG::engineFuncName};
    #ifdef EXTERNAL_PRNG_LIB
                    const char* dlsym_error = dlerror();
                    if (dlsym_error) {
                        errMsg += ": ";
                        errMsg += dlsym_error;
                    }
                    dlclose(libraryHandle);
    #endif
                    OPENFHE_THROW(errMsg);
                }

                std::array<uint32_t, PRNG::MAX_SEED_GENS> seed{};
#if defined(FIXED_SEED)
                // Only used for debugging in the single-threaded mode.
                std::cerr << "**FOR DEBUGGING ONLY!!!!  Using fixed initializer for PRNG. "
                             "Use a single thread only, e.g., OMP_NUM_THREADS=1!"
                          << std::endl;

                seed[0] = 1;
#else
                // A 512-bit seed is generated for each thread (this roughly corresponds
                // to 256 bits of security). The seed is the sum of a random sample
                // generated using std::random_device (typically works correctly in
                // Linux, MacOS X, and MinGW starting with GCC 9.2) and a PRNG sample
                // seeded from current time stamp, a hash of the current thread, and a
                // memory location of a heap variable. The PRNG sample is added in
                // case random_device is deterministic (happens on MinGW with GCC
                // below 9.2). All future calls to PRNG use the seed generated here.

                // The code below derives randomness from time, thread id, and a memory
                // location of a heap variable. This seed is relevant only if the
                // implementation of random_device is deterministic (as in older
                // versions of GCC in MinGW)
                std::array<uint32_t, PRNG::MAX_SEED_GENS> initKey{};
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
                // location as the counter. This will increase the entropy of the PRNG sample
                void* mem        = malloc(1);
                uint32_t counter = reinterpret_cast<long long>(mem);  // NOLINT
                free(mem);

                std::uniform_int_distribution<uint32_t> distribution(0);
                // the code below is wrapped in to {} as we want to get rid of gen immediately after the loop
                {
                    // "PRNG* gen" points at a dynamically allocated (using c++'s new()) memory!!!
                    std::unique_ptr<PRNG> gen(createEngine(initKey, counter));
                    for (auto& s : seed)
                        s = distribution(*gen);
                }

                std::array<uint32_t, PRNG::MAX_SEED_GENS> rdseed{};
                size_t attempts  = 3;
                bool rdGenPassed = false;
                for (size_t i = 0; i < attempts && !rdGenPassed; ++i) {
                    try {
                        std::random_device genR;
                        for (auto& rds : rdseed) {
                            // we use the fact that there is no overflow for unsigned integers
                            // (from C++ standard) i.e., arithmetic mod 2^32 is performed. For
                            // the seed to be random, it is sufficient for one of the two
                            // samples below to be random. In almost all practical cases,
                            // distribution(genR) is random. We add distribution(gen) just in
                            // case there is an implementation issue with random_device (as in
                            // older MinGW systems).
                            rds = distribution(genR);
                        }
                        rdGenPassed = true;
                    }
                    catch (std::exception& e) {
                    }
                }
                for (uint32_t i = 0; i < PRNG::MAX_SEED_GENS; ++i)
                    seed[i] += rdseed[i];
#endif // FIXED_SEED
                m_prng.reset(createEngine(seed, 0));
                // cleanup: close the shared library
    #ifdef EXTERNAL_PRNG_LIB
                dlclose(libraryHandle);
    #endif

                if (!m_prng)
                    OPENFHE_THROW("Cannot create a PRNG engine");
            } // pragma omp critical
        }
        return *m_prng;
    }

private:
    // shared pointer to a thread-specific PRNG engine
    static std::shared_ptr<PRNG> m_prng;
    using CreateEngineFuncPtrType = PRNG* (*)(const std::array<PRNG::result_type, PRNG::MAX_SEED_GENS>&,
                                              PRNG::result_type counter);

#if !defined(FIXED_SEED)
    // avoid contention on m_prng: local copies of m_prng are created for each thread
    #pragma omp threadprivate(m_prng)
#endif
};

}  // namespace lbcrypto

#endif  // __DISTRIBUTIONGENERATOR_H__
