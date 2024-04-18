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
  Defines aliases for the lattice default backend
 */

#ifndef LBCRYPTO_INC_LATTICE_HAL_LAT_BACKEND_H
#define LBCRYPTO_INC_LATTICE_HAL_LAT_BACKEND_H

#define ILPARAMS_IMPLEMENTATION     "lattice/hal/default/ilparams.h"
#define ILDCRTPARAMS_IMPLEMENTATION "lattice/hal/default/ildcrtparams.h"
#define POLY_IMPLEMENTATION         "lattice/hal/default/poly-impl.h"
#define DCRTPOLY_IMPLEMENTATION     "lattice/hal/default/dcrtpoly-impl.h"

#define MAKE_ILPARAMS_TYPE(T)     template class ILParamsImpl<T>;
#define MAKE_ILDCRTPARAMS_TYPE(T) template class ILDCRTParams<T>;
#define MAKE_POLY_TYPE(T)         template class PolyImpl<T>;
#define MAKE_DCRTPOLY_TYPE(T)     template class DCRTPolyImpl<T>;

#include "lattice/hal/default/ilparams.h"
#include "lattice/hal/default/ildcrtparams.h"
#include "lattice/hal/default/poly.h"
#include "lattice/hal/default/dcrtpoly.h"

namespace lbcrypto {

using ILNativeParams = ILParamsImpl<NativeInteger>;
using ILParams       = ILParamsImpl<BigInteger>;
using Poly           = PolyImpl<BigVector>;
using NativePoly     = PolyImpl<NativeVector>;
using DCRTPoly       = DCRTPolyImpl<BigVector>;

#ifdef WITH_BE2
using M2Params     = ILParamsImpl<M2Integer>;
using M2DCRTParams = ILDCRTParams<M2Integer>;
using M2Poly       = PolyImpl<M2Vector>;
using M2DCRTPoly   = DCRTPolyImpl<M2Vector>;
#else
using M2Params     = void;
using M2DCRTParams = void;
using M2Poly       = void;
using M2DCRTPoly   = void;
#endif

#ifdef WITH_BE4
using M4Params     = ILParamsImpl<M4Integer>;
using M4DCRTParams = ILDCRTParams<M4Integer>;
using M4Poly       = PolyImpl<M4Vector>;
using M4DCRTPoly   = DCRTPolyImpl<M4Vector>;
#else
using M4Params     = void;
using M4DCRTParams = void;
using M4Poly       = void;
using M4DCRTPoly   = void;
#endif

#ifdef WITH_NTL
using M6Params     = ILParamsImpl<M6Integer>;
using M6DCRTParams = ILDCRTParams<M6Integer>;
using M6Poly       = PolyImpl<M6Vector>;
using M6DCRTPoly   = DCRTPolyImpl<M6Vector>;
#else
using M6Params     = void;
using M6DCRTParams = void;
using M6Poly       = void;
using M6DCRTPoly   = void;
#endif

}  // namespace lbcrypto

#endif
