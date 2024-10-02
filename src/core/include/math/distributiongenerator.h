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


// #include "utils/parallel.h"
#include "utils/exception.h"

#include "prng.h"

#include <memory>
// #include <mutex>
// #include <random>
// #include <thread>
// #include <mutex>
#include <dlfcn.h>

namespace lbcrypto {

// Defines the PRNG implementation used by OpenFHE.
// The cryptographically secure PRNG used by OpenFHE is based on BLAKE2 hash
// functions. A user can replace it with a different PRNG if desired by defining
// the same methods as for the Blake2Engine class.
// typedef Blake2Engine PRNG;


class PseudoRandomNumberGenerator {
public:
    // static PseudoRandomNumberGenerator& getInstance() {
    //     std::call_once(initInstanceFlag, &PseudoRandomNumberGenerator::createInstance);
    //     return *instance;
    // }

    static PRNG& GetPRNG() {
        std::cerr << __FILE__ << ":l." << __LINE__ << "In PseudoRandomNumberGenerator:: GetPRNG()" << std::endl;
        // I commented getInstance() as we use GetPRNG() instead of getInstance() and initialized this singleton class
        // in GetPRNG(). TODO (dsuponit): i am curious if we may be able to get rid of
        // std::unique_ptr<PseudoRandomNumberGenerator> PseudoRandomNumberGenerator::instance  :)))
        std::call_once(initInstanceFlag, &PseudoRandomNumberGenerator::createInstance);
        return *engine;
    }

private:
    PseudoRandomNumberGenerator() = default;
    ~PseudoRandomNumberGenerator() {
        if (engine) {
            delete engine;
            engine = nullptr;
        }
        if (singletonHandle) {
            dlclose(singletonHandle);
            singletonHandle = nullptr;
        }
    }
    
    static void createInstance() {
        instance.reset(new PseudoRandomNumberGenerator);

        const std::string engineLibName  = "libengine.so";
        void* handle = dlopen(engineLibName.c_str(), RTLD_LAZY);
        if (!handle) {
            OPENFHE_THROW("Cannot open " + engineLibName);
        }

        // get the factory function
        using CreateInstanceFunc = PRNG*(*)();
        const std::string engineLoadFuncName  = "createEngineInstance";
        CreateInstanceFunc func = (CreateInstanceFunc)dlsym(handle, engineLoadFuncName.c_str());
        if (!func) {
            std::string errMsg{"Cannot load symbol " + engineLoadFuncName};
            const char* dlsym_error = dlerror();
            if (dlsym_error) {
                errMsg += ": ";
                errMsg += dlsym_error;
            }
            // dlclose(handle); - destructor will call it
            OPENFHE_THROW(errMsg);
        }
        // create the engine instance
        engine = func();
        if (!engine) {
            // dlclose(handle); - destructor will call it
            OPENFHE_THROW("Cannot create a PRNG engine");
        }
        singletonHandle = handle; // store handle for dlclose
    }

    static std::unique_ptr<PseudoRandomNumberGenerator> instance; // Pointer to the instance
    static std::once_flag initInstanceFlag; // Flag for thread-safe initialization
    static PRNG* engine; // Pointer to the engine
    static void* singletonHandle; // Handle for the shared library
};

//==================================================================
// class PseudoRandomNumberGenerator {
// public:
//     static PRNG& GetPRNG() {
//         // initialization of PRNGs
//         if (m_prng == nullptr) {
// #pragma omp critical
//             {
//                 std::array<uint32_t, 16> initKey{};
//                 initKey[0] = std::chrono::high_resolution_clock::now().time_since_epoch().count();
//                 initKey[1] = std::hash<std::thread::id>{}(std::this_thread::get_id());
//     #if !defined(__arm__) && !defined(__EMSCRIPTEN__)
//                 if (sizeof(size_t) == 8)
//                     initKey[2] = (std::hash<std::thread::id>{}(std::this_thread::get_id()) >> 32);
//     #endif
//                 void* mem        = malloc(1);
//                 uint32_t counter = reinterpret_cast<long long>(mem);  // NOLINT
//                 free(mem);

//                 PRNG gen(initKey, counter);

//                 std::uniform_int_distribution<uint32_t> distribution(0);
//                 std::array<uint32_t, 16> seed{};
//                 for (uint32_t i = 0; i < 16; i++) {
//                     seed[i] = distribution(gen);
//                 }

//                 std::array<uint32_t, 16> rdseed{};
//                 size_t attempts  = 3;
//                 bool rdGenPassed = false;
//                 size_t idx       = 0;
//                 while (!rdGenPassed && idx < attempts) {
//                     try {
//                         std::random_device genR;
//                         for (uint32_t i = 0; i < 16; i++) {
//                             rdseed[i] = distribution(genR);
//                         }
//                         rdGenPassed = true;
//                     }
//                     catch (std::exception& e) {
//                     }
//                     idx++;
//                 }

//                 for (uint32_t i = 0; i < 16; i++) {
//                     seed[i] += rdseed[i];
//                 }

//                 m_prng = std::make_shared<PRNG>(seed);
//             }
//         }
//         return *m_prng;
//     }

// private:
//     // shared pointer to a thread-specific PRNG engine
//     static std::shared_ptr<PRNG> m_prng;

//         // avoid contention on m_prng
//         // local copies of m_prng are created for each thread
//     #pragma omp threadprivate(m_prng)
// };

}  // namespace lbcrypto

#endif  // LBCRYPTO_INC_MATH_DISTRIBUTIONGENERATOR_H_
