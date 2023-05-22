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
  This file contains the functionality to switch between lattice backends
 */

#ifndef __LAT_HAL_H__
#define __LAT_HAL_H__

#if defined(WITH_INTEL_HEXL)
    #include "lattice/hal/hexl/lat-backend-hexl.h"
#else  // default
    #include "lattice/hal/default/lat-backend-default.h"
#endif

namespace lbcrypto {

using M2Poly = PolyImpl<M2Vector>;
using M4Poly = PolyImpl<M4Vector>;
#ifdef WITH_NTL
using M6Poly = PolyImpl<M6Vector>;
#endif

using NativePoly = PolyImpl<NativeVector>;

using NativePoly64 = NativePoly;

using M2Params = ILParamsImpl<M2Integer>;
using M4Params = ILParamsImpl<M4Integer>;
#ifdef WITH_NTL
using M6Params = ILParamsImpl<M6Integer>;
#endif

using ILNativeParams = ILParamsImpl<NativeInteger>;

// the default for the backend...
using ILParams = ILParamsImpl<BigInteger>;
using Poly     = PolyImpl<BigVector>;

using M2DCRTParams = ILDCRTParams<M2Integer>;
using M4DCRTParams = ILDCRTParams<M4Integer>;
#ifdef WITH_NTL
using M6DCRTParams = ILDCRTParams<M6Integer>;
#endif

}  // namespace lbcrypto

#endif  // __LAT_HAL_H__
