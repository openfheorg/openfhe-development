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
  This file contains template instantiations for all classes using math be4
 */

#include "lattice/lat-hal.h"
#include "math/matrix.cpp"          // NOLINT
#include "matrix-lattice-impl.cpp"  // NOLINT

#include "elemparams.cpp"  // NOLINT
#include "ilparams.cpp"    // NOLINT
#include "poly.cpp"        // NOLINT

namespace lbcrypto {

template class ElemParams<M2Integer>;
template class ILParamsImpl<M2Integer>;
template class PolyImpl<M2Vector>;
// template class DCRTPolyImpl<M2Vector>;

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

// biginteger version
template <>
PolyImpl<NativeVector> PolyImpl<M2Vector>::ToNativePoly() const {
    PolyImpl<NativeVector> interp(std::make_shared<ILParamsImpl<NativeInteger>>(
                                      this->GetCyclotomicOrder(), std::numeric_limits<uint64_t>::max(), 1),
                                  this->GetFormat(), true);

    for (usint i = 0; i < this->GetLength(); i++) {
        interp[i] = (*this)[i].ConvertToInt();
    }

    return interp;
}

}  // namespace lbcrypto

CEREAL_CLASS_VERSION(lbcrypto::M2Poly, lbcrypto::M2Poly::SerializedVersion());
CEREAL_CLASS_VERSION(lbcrypto::M2DCRTPoly, lbcrypto::M2DCRTPoly::SerializedVersion());
