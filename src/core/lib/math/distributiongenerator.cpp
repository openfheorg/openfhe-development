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

#include "math/distributiongenerator.h"
#include "utils/prng/blake2engine.h"
#include "utils/memory.h"
#include "utils/exception.h"

#include <chrono>
#include <cstdint>
#include <random>
#include <thread>
#include <iostream>
#if (defined(__linux__) || defined(__unix__)) && !defined(__APPLE__) && defined(__GNUC__) && !defined(__clang__)
    #include <dlfcn.h>
#endif

namespace lbcrypto {

std::shared_ptr<PRNG> PseudoRandomNumberGenerator::m_prng = nullptr;
PseudoRandomNumberGenerator::GenPRNGEngineFuncPtr PseudoRandomNumberGenerator::genPRNGEngine = nullptr;

void PseudoRandomNumberGenerator::InitPRNGEngine(const std::string& libPath) {
    if(genPRNGEngine) // if genPRNGEngine has already been initialized
      return;

    if(libPath.empty()) {
        // use the default OpenFHE PRNG that comes with the library 
        genPRNGEngine = default_prng::createEngineInstance;
        if (!genPRNGEngine)
            OPENFHE_THROW("Cannot find symbol: default_prng::createEngineInstance");
        // std::cerr << "InitPRNGEngine: using local PRNG" << std::endl;
    }
    else {
        #if (defined(__linux__) || defined(__unix__)) && !defined(__APPLE__) && defined(__GNUC__) && !defined(__clang__)
            // enable this code for g++ on Linux only
            // do not close libraryHandle, your application will crash if you do
            void* libraryHandle = dlopen(libPath.c_str(), RTLD_LAZY);
            if (!libraryHandle) {
                std::string errMsg{std::string("Cannot open ") + libPath + ": "};
                const char* dlsym_error = dlerror();
                errMsg += dlsym_error;
                OPENFHE_THROW(errMsg);
            }
            genPRNGEngine = (GenPRNGEngineFuncPtr)dlsym(libraryHandle, "createEngineInstance");
            if (!genPRNGEngine) {
                std::string errMsg{std::string("Cannot load symbol createEngineInstance() from ") + libPath};
                const char* dlsym_error = dlerror();
                errMsg += ": ";
                errMsg += dlsym_error;
                dlclose(libraryHandle);
                OPENFHE_THROW(errMsg);
            }
            std::cerr << __FUNCTION__ << ": using external PRNG" << std::endl;
        #else
            OPENFHE_THROW("OpenFHE may use an external PRNG library linked with g++ on Linux only");
        #endif
    }
} 

PRNG& PseudoRandomNumberGenerator::GetPRNG() {
    // initialization of PRNGs
    if (m_prng == nullptr) {
#pragma omp critical
        {
            // we would like to believe that the block of code below is a good defense line 
            if (!genPRNGEngine)
                InitPRNGEngine();
            if (!genPRNGEngine)
                OPENFHE_THROW("Failure to initialize the PRNG engine");

            PRNG::seed_array_t seed{};
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
            PRNG::seed_array_t initKey{};
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
            uint64_t counter = reinterpret_cast<uint64_t>(mem);
            free(mem);

            std::uniform_int_distribution<uint32_t> distribution(0);
            // the code below is wrapped in to {} as we want to get rid of gen immediately after the loop
            {
                // "PRNG* gen" points at a dynamically allocated (using c++'s new()) memory!!!
                std::unique_ptr<PRNG> gen(genPRNGEngine(initKey, counter));
                for (auto& s : seed)
                    s = distribution(*gen);
            }

            PRNG::seed_array_t rdseed{};
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

            // re-init rdseed for security reasons
            const size_t bytes_to_clear = (rdseed.size()*sizeof(rdseed[0]));
            secure_memset(rdseed.data(), 0, bytes_to_clear);
  #endif  // FIXED_SEED
            m_prng = std::shared_ptr<PRNG>(genPRNGEngine(seed, 0));
            // re-init seed for security reasons
            secure_memset(seed.data(), 0, bytes_to_clear);
            if (!m_prng)
                OPENFHE_THROW("Cannot create a PRNG engine");
        } // pragma omp critical
    }
    return *m_prng;
}

}  // namespace lbcrypto
