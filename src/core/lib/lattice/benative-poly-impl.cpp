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
  native integer implementation
 */

#define BLOCK_VECTOR_IMPLEMENT
#include "lattice/lat-hal.h"
#include "math/matrix.cpp"          // NOLINT
#include "matrix-lattice-impl.cpp"  // NOLINT

#include "elemparams.cpp"  // NOLINT
#include "ilparams.cpp"    // NOLINT
#include "poly.cpp"        // NOLINT

namespace lbcrypto {

template class ElemParams<NativeInteger>;
template class ILParamsImpl<NativeInteger>;
template class PolyImpl<NativeVector>;

template class Matrix<NativePoly>;
SPLIT64_FOR_TYPE(NativePoly)
SPLIT64ALT_FOR_TYPE(NativePoly)
SPLIT32ALT_FOR_TYPE(NativePoly)
template Matrix<NativeVector> RotateVecResult(Matrix<NativePoly> const& inMat);
template Matrix<NativeInteger> Rotate(Matrix<NativePoly> const& inMat);

// native poly version
template <>
PolyImpl<NativeVector> PolyImpl<NativeVector>::ToNativePoly() const {
    return *this;
}

}  // namespace lbcrypto

CEREAL_CLASS_VERSION(lbcrypto::NativePoly, lbcrypto::NativePoly::SerializedVersion());
