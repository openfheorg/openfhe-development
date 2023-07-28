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
  parameter factory
 */

#ifndef SRC_CORE_INC_UTILS_PARMFACTORY_H_
#define SRC_CORE_INC_UTILS_PARMFACTORY_H_

// useful for testing

// #include "lattice/lat-hal.h"
#include "lattice/ildcrtparams.h"

// #include "math/math-hal.h"
#include "math/distrgen.h"

#include "utils/debug.h"
#include "utils/exception.h"
#include "utils/inttypes.h"

#include <memory>
#include <vector>

using namespace lbcrypto;

/**
 * Generate an ILDCRTParams with a given number of parms, with cyphertext moduli
 * of at least a given size
 * @param m - order
 * @param numOfTower - # of polynomials
 * @param pbits - number of bits in the prime, to start with
 * @return
 */
template <typename I>
inline std::shared_ptr<ILDCRTParams<I>> GenerateDCRTParams(usint m, usint numOfTower, usint pbits) {
    OPENFHE_DEBUG_FLAG(false);
    OPENFHE_DEBUG("in GenerateDCRTParams");
    OPENFHE_DEBUGEXP(m);
    OPENFHE_DEBUGEXP(numOfTower);
    OPENFHE_DEBUGEXP(pbits);
    if (numOfTower == 0) {
        OPENFHE_THROW(math_error, "Can't make parms with numOfTower == 0");
    }

    std::vector<NativeInteger> moduli(numOfTower);
    std::vector<NativeInteger> rootsOfUnity(numOfTower);

    NativeInteger q = FirstPrime<NativeInteger>(pbits, m);
    I modulus(1);

    usint j = 0;
    OPENFHE_DEBUGEXP(q);

    for (;;) {
        moduli[j]       = q;
        rootsOfUnity[j] = RootOfUnity(m, q);
        modulus         = modulus * I(q.ConvertToInt());
        OPENFHE_DEBUG("j " << j << " modulus " << q << " rou " << rootsOfUnity[j]);
        if (++j == numOfTower)
            break;

        q = NextPrime(q, m);
    }

    auto params = std::make_shared<ILDCRTParams<I>>(m, moduli, rootsOfUnity);

    return params;
}

#endif
