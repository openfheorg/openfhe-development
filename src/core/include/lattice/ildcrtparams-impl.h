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
  parameters for generalized double-crt parameters
 */

#ifndef LBCRYPTO_INC_LATTICE_ILDCRTPARAMS_IMPL_H
#define LBCRYPTO_INC_LATTICE_ILDCRTPARAMS_IMPL_H

#include "lattice/elemparams.h"
#include "lattice/ildcrtparams.h"

#include "math/hal.h"
#include "math/nbtheory-impl.h"

#include "utils/exception.h"
#include "utils/inttypes.h"

#include <memory>

namespace lbcrypto {

template <typename IntType>
ILDCRTParams<IntType>::ILDCRTParams(usint order, usint depth, usint bits) : ElemParams<IntType>(order, 0) {
    if (order == 0)
        return;
    if (depth == 0)
        OPENFHE_THROW(config_error, "Invalid depth for ILDCRTParams");
    if (bits == 0 || bits > 64)
        OPENFHE_THROW(config_error, "Invalid bits for ILDCRTParams");

    m_parms.resize(depth);
    this->ciphertextModulus = IntType(0);

    NativeInteger q = FirstPrime<NativeInteger>(bits, order);

    for (size_t j = 0;;) {
        NativeInteger root = RootOfUnity<NativeInteger>(order, q);
        m_parms[j]         = std::make_shared<ILNativeParams>(order, q, root);

        if (++j >= depth)
            break;

        q = NextPrime<NativeInteger>(q, order);
    }

    RecalculateModulus();
}

}  // namespace lbcrypto

#endif
