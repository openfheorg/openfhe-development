// @file backend.h This file contains the functionality to switch between
// lattice backends
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef LBCRYPTO_LATTICE_BACKEND_H
#define LBCRYPTO_LATTICE_BACKEND_H

#include "lattice/elemparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "lattice/ilparams.h"

#include "lattice/poly.h"

namespace lbcrypto {

template <typename IntType>
class ILParamsImpl;
template <typename VecType>
class PolyImpl;

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
using Poly = PolyImpl<BigVector>;

}  // namespace lbcrypto

#include "lattice/dcrtpoly.h"

namespace lbcrypto {

template <typename IntType>
class ILDCRTParams;
template <typename VecType>
class DCRTPolyImpl;

using M2DCRTPoly = DCRTPolyImpl<M2Vector>;
using M4DCRTPoly = DCRTPolyImpl<M4Vector>;
#ifdef WITH_NTL
using M6DCRTPoly = DCRTPolyImpl<M6Vector>;
#endif

using M2DCRTParams = ILDCRTParams<M2Integer>;
using M4DCRTParams = ILDCRTParams<M4Integer>;
#ifdef WITH_NTL
using M6DCRTParams = ILDCRTParams<M6Integer>;
#endif

// the default for the backend...
using DCRTPoly = DCRTPolyImpl<BigVector>;

}  // namespace lbcrypto

#endif

#ifdef WITH_NTL
#define RUN_BIG_POLYS(FUNCTION, MESSAGE) \
  {                                      \
    if (TestB2) {                        \
      using V = M2Poly;                  \
      FUNCTION<V>("BE2Poly " MESSAGE);   \
    }                                    \
    if (TestB4) {                        \
      using V = M4Poly;                  \
      FUNCTION<V>("BE4Poly " MESSAGE);   \
    }                                    \
    if (TestB6) {                        \
      using V = M6Poly;                  \
      FUNCTION<V>("BE6Poly " MESSAGE);   \
    }                                    \
  }

#define RUN_BIG_DCRTPOLYS(FUNCTION, MESSAGE) \
  {                                          \
    if (TestB2) {                            \
      using V = M2DCRTPoly;                  \
      FUNCTION<V>("BE2DCRTPoly " MESSAGE);   \
    }                                        \
    if (TestB4) {                            \
      using V = M4DCRTPoly;                  \
      FUNCTION<V>("BE4DCRTPoly " MESSAGE);   \
    }                                        \
    if (TestB6) {                            \
      using V = M6DCRTPoly;                  \
      FUNCTION<V>("BE6DCRTPoly " MESSAGE);   \
    }                                        \
  }
#else
#define RUN_BIG_POLYS(FUNCTION, MESSAGE) \
  {                                      \
    if (TestB2) {                        \
      using V = M2Poly;                  \
      FUNCTION<V>("BE2Poly " MESSAGE);   \
    }                                    \
    if (TestB4) {                        \
      using V = M4Poly;                  \
      FUNCTION<V>("BE4Poly " MESSAGE);   \
    }                                    \
  }

#define RUN_BIG_DCRTPOLYS(FUNCTION, MESSAGE) \
  {                                          \
    if (TestB2) {                            \
      using V = M2DCRTPoly;                  \
      FUNCTION<V>("BE2DCRTPoly " MESSAGE);   \
    }                                        \
    if (TestB4) {                            \
      using V = M4DCRTPoly;                  \
      FUNCTION<V>("BE4DCRTPoly " MESSAGE);   \
    }                                        \
  }
#endif

#define RUN_ALL_POLYS(FUNCTION, MESSAGE) \
  {                                      \
    RUN_BIG_POLYS(FUNCTION, MESSAGE)     \
    if (TestNative) {                    \
      using V = NativePoly;              \
      FUNCTION<V>("Native " MESSAGE);    \
    }                                    \
  }
