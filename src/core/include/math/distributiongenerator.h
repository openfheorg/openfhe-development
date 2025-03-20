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

#include "utils/prng/prng.h"
#include "config_core.h"

#include <memory>
#include <string>

namespace lbcrypto {

/**
 * @brief PseudoRandomNumberGenerator provides the PRNG capability to all random distribution generators in OpenFHE.
 * The security of Ring Learning With Errors (used for all crypto capabilities in OpenFHE) depends on
 * the randomness of uniform, ternary, and Gaussian distributions, which derive their randomness from the PRNG.
 */

class PseudoRandomNumberGenerator {
public:
    /**
    * @brief InitPRNGEngine() initializes the PRNG generator
    * @param libPath a string with the absolute path to an external PRNG library ("/path/to/libprng.so").
    *        If the string is empty, then the default (OpenFHE's built-in PRNG) library will be used.
    * @note this function should be called at the beginning of main() if an external library to be used and
    *       prints a trace in this case. There is no trace for the built-in PRNG
    */
    static void InitPRNGEngine(const std::string& libPath = std::string());

    /**
     * @brief Returns a reference to the PRNG engine
     */
    static PRNG& GetPRNG();

private:
    using GenPRNGEngineFuncPtr = PRNG* (*)();

#if defined(WITH_OPENMP)
    // shared pointer to a thread-specific PRNG engine
    static std::shared_ptr<PRNG> m_prng;
    #if !defined(FIXED_SEED)
        // avoid contention on m_prng: local copies of m_prng are created for each thread
        #pragma omp threadprivate(m_prng)
    #endif
#endif
    // pointer to the function generating PRNG
    static GenPRNGEngineFuncPtr genPRNGEngine;
};

}  // namespace lbcrypto

#endif  // __DISTRIBUTIONGENERATOR_H__
