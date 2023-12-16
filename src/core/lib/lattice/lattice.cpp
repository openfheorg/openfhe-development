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
  implementation of the integer lattice
 */

#include "config_core.h"

#include "lattice/field2n-impl.h"
#include "lattice/lat-hal.h"
#include "lattice/matrix-lattice-impl.h"

#include "math/matrix-impl.h"
#include "math/nbtheory-impl.h"

#include "math/ternaryuniformgenerator-impl.h"
#include "math/discreteuniformgenerator-impl.h"
#include "math/discretegaussiangenerator-impl.h"
#include "math/binaryuniformgenerator-impl.h"

#include ILPARAMS_IMPLEMENTATION
#include ILDCRTPARAMS_IMPLEMENTATION
#include POLY_IMPLEMENTATION
#include DCRTPOLY_IMPLEMENTATION

//---------------------------------------------------------------------------------------------
namespace lbcrypto {

template class ElemParams<NativeInteger>;

MAKE_ILPARAMS_TYPE(NativeInteger)
MAKE_POLY_TYPE(NativeVector)

template class Matrix<NativePoly>;
SPLIT64_FOR_TYPE(NativePoly)
SPLIT64ALT_FOR_TYPE(NativePoly)
SPLIT32ALT_FOR_TYPE(NativePoly)
template Matrix<NativeVector> RotateVecResult(Matrix<NativePoly> const& inMat);
template Matrix<NativeInteger> Rotate(Matrix<NativePoly> const& inMat);

template class Matrix<Field2n>;

}  // namespace lbcrypto

CEREAL_CLASS_VERSION(lbcrypto::ElemParams<NativeInteger>, lbcrypto::ElemParams<NativeInteger>::SerializedVersion());
CEREAL_CLASS_VERSION(lbcrypto::ILNativeParams, lbcrypto::ILNativeParams::SerializedVersion());
CEREAL_CLASS_VERSION(lbcrypto::NativePoly, lbcrypto::NativePoly::SerializedVersion());
CEREAL_CLASS_VERSION(lbcrypto::Field2n, lbcrypto::Field2n::SerializedVersion());

//---------------------------------------------------------------------------------------------
#ifdef WITH_BE2
namespace lbcrypto {

template class ElemParams<M2Integer>;

MAKE_ILPARAMS_TYPE(M2Integer)
MAKE_ILDCRTPARAMS_TYPE(M2Integer)
MAKE_POLY_TYPE(M2Vector)
MAKE_DCRTPOLY_TYPE(M2Vector)

template class Matrix<M2Poly>;
SPLIT64_FOR_TYPE(M2Poly)
SPLIT64ALT_FOR_TYPE(M2Poly)
SPLIT32ALT_FOR_TYPE(M2Poly)
template Matrix<M2Vector> RotateVecResult(Matrix<M2Poly> const& inMat);
template Matrix<M2Integer> Rotate(Matrix<M2Poly> const& inMat);

template class Matrix<M2DCRTPoly>;
SPLIT64_FOR_TYPE(M2DCRTPoly)
SPLIT64ALT_FOR_TYPE(M2DCRTPoly)
SPLIT32ALT_FOR_TYPE(M2DCRTPoly)
template Matrix<M2Vector> RotateVecResult(Matrix<M2DCRTPoly> const& inMat);
template Matrix<M2Integer> Rotate(Matrix<M2DCRTPoly> const& inMat);

}  // namespace lbcrypto

CEREAL_CLASS_VERSION(lbcrypto::ElemParams<M2Integer>, lbcrypto::ElemParams<M2Integer>::SerializedVersion());
CEREAL_CLASS_VERSION(lbcrypto::M2Params, lbcrypto::M2Params::SerializedVersion());
CEREAL_CLASS_VERSION(lbcrypto::M2DCRTParams, lbcrypto::M2DCRTParams::SerializedVersion());
CEREAL_CLASS_VERSION(lbcrypto::M2Poly, lbcrypto::M2Poly::SerializedVersion());
CEREAL_CLASS_VERSION(lbcrypto::M2DCRTPoly, lbcrypto::M2DCRTPoly::SerializedVersion());
#endif

//---------------------------------------------------------------------------------------------
#ifdef WITH_BE4
namespace lbcrypto {

template class ElemParams<M4Integer>;

MAKE_ILPARAMS_TYPE(M4Integer)
MAKE_ILDCRTPARAMS_TYPE(M4Integer)
MAKE_POLY_TYPE(M4Vector)
MAKE_DCRTPOLY_TYPE(M4Vector)

template class Matrix<M4Poly>;
SPLIT64_FOR_TYPE(M4Poly)
SPLIT64ALT_FOR_TYPE(M4Poly)
SPLIT32ALT_FOR_TYPE(M4Poly)
template Matrix<M4Vector> RotateVecResult(Matrix<M4Poly> const& inMat);
template Matrix<M4Integer> Rotate(Matrix<M4Poly> const& inMat);

template class Matrix<M4DCRTPoly>;
SPLIT64_FOR_TYPE(M4DCRTPoly)
SPLIT64ALT_FOR_TYPE(M4DCRTPoly)
SPLIT32ALT_FOR_TYPE(M4DCRTPoly)
template Matrix<M4Vector> RotateVecResult(Matrix<M4DCRTPoly> const& inMat);
template Matrix<M4Integer> Rotate(Matrix<M4DCRTPoly> const& inMat);

}  // namespace lbcrypto

CEREAL_CLASS_VERSION(lbcrypto::ElemParams<M4Integer>, lbcrypto::ElemParams<M4Integer>::SerializedVersion());
CEREAL_CLASS_VERSION(lbcrypto::M4Params, lbcrypto::M4Params::SerializedVersion());
CEREAL_CLASS_VERSION(lbcrypto::M4DCRTParams, lbcrypto::M4DCRTParams::SerializedVersion());
CEREAL_CLASS_VERSION(lbcrypto::M4Poly, lbcrypto::M4Poly::SerializedVersion());
CEREAL_CLASS_VERSION(lbcrypto::M4DCRTPoly, lbcrypto::M4DCRTPoly::SerializedVersion());
#endif

//---------------------------------------------------------------------------------------------
#ifdef WITH_NTL
namespace lbcrypto {

template class ElemParams<M6Integer>;

MAKE_ILPARAMS_TYPE(M6Integer)
MAKE_ILDCRTPARAMS_TYPE(M6Integer)
MAKE_POLY_TYPE(M6Vector)
MAKE_DCRTPOLY_TYPE(M6Vector)

template class Matrix<M6Poly>;
SPLIT64_FOR_TYPE(M6Poly)
SPLIT64ALT_FOR_TYPE(M6Poly)
SPLIT32ALT_FOR_TYPE(M6Poly)
template Matrix<M6Vector> RotateVecResult(Matrix<M6Poly> const& inMat);
template Matrix<M6Integer> Rotate(Matrix<M6Poly> const& inMat);

template class Matrix<M6DCRTPoly>;
SPLIT64_FOR_TYPE(M6DCRTPoly)
SPLIT64ALT_FOR_TYPE(M6DCRTPoly)
SPLIT32ALT_FOR_TYPE(M6DCRTPoly)
template Matrix<M6Vector> RotateVecResult(Matrix<M6DCRTPoly> const& inMat);
template Matrix<M6Integer> Rotate(Matrix<M6DCRTPoly> const& inMat);

}  // namespace lbcrypto

CEREAL_CLASS_VERSION(lbcrypto::ElemParams<M6Integer>, lbcrypto::ElemParams<M6Integer>::SerializedVersion());
CEREAL_CLASS_VERSION(lbcrypto::M6Params, lbcrypto::M6Params::SerializedVersion());
CEREAL_CLASS_VERSION(lbcrypto::M6DCRTParams, lbcrypto::M6DCRTParams::SerializedVersion());
CEREAL_CLASS_VERSION(lbcrypto::M6Poly, lbcrypto::M6Poly::SerializedVersion());
CEREAL_CLASS_VERSION(lbcrypto::M6DCRTPoly, lbcrypto::M6DCRTPoly::SerializedVersion());
#endif
