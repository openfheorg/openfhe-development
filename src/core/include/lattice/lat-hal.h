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
  This file contains the functionality to switch between lattice backends
 */

#ifndef LBCRYPTO_INC_LATTICE_LAT_HAL_H
#define LBCRYPTO_INC_LATTICE_LAT_HAL_H

#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"

namespace lbcrypto {

#ifdef WITH_BE2
using M2Params     = ILParamsImpl<M2Integer>;
using M2DCRTParams = ILDCRTParams<M2Integer>;
#endif

#ifdef WITH_BE4
using M4Params     = ILParamsImpl<M4Integer>;
using M4DCRTParams = ILDCRTParams<M4Integer>;
#endif

#ifdef WITH_NTL
using M6Params     = ILParamsImpl<M6Integer>;
using M6DCRTParams = ILDCRTParams<M6Integer>;
#endif

using ILNativeParams = ILParamsImpl<NativeInteger>;
using ILParams       = ILParamsImpl<BigInteger>;

}  // namespace lbcrypto

#include "lattice/hal/lat-backend.h"

#endif  // __LAT_HAL_H__
