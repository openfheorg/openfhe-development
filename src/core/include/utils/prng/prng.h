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

/**
 * DISCLAIMER: IMPORTANT NOTICE ABOUT FILE MODIFICATIONS
 *
 * This file is used in OpenFHE's built-in PRNG and ANY EXTERNAL PRNG.
 * The file is critical to the functionality and the security of the library.
 *
 * Modifications should only be performed by personnel who understand the potential impacts.
 *
 * By proceeding with changes to this file, you acknowledge that you understand the risks involved and
 * accept full responsibility for any resulting issues.
 */

/**
 * Abstract base class for any PRNG engine.
 */

#ifndef __PRNG_H__
#define __PRNG_H__

#include <cstdint>
#include <limits>

// ATTENTION (VERY IMPORTANT):
//    for any engine class derived from the PRNG class there must be a C function named "createEngineInstance"
//    returning a dynamically allocated object of that derived class (see how it is done in blake2engine.h)
class PRNG {
public:
    // all C++11 distributions used in OpenFHE work with uint32_t by default.
    // a different data type can be specified if needed for a particular architecture
    using result_type = uint32_t;

    /**
     * @brief minimum value used by C++11 distribution generators when no lower
     * bound is explicitly specified by the user
     */
    static constexpr result_type min() {
        return std::numeric_limits<result_type>::min();
    }

    /**
     * @brief maximum value used by C++11 distribution generators when no upper
     * bound is explicitly specified by the user
     */
    static constexpr result_type max() {
        return std::numeric_limits<result_type>::max();
    }

    virtual result_type operator()() = 0;
    virtual ~PRNG()                  = default;

protected:
    PRNG() = default;
};
#endif  // __PRNG_H__
