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
  This file contains template instantiations for all classes using math be6
 */

//==================================================================================
// This file is included only if WITH_NTL is set to ON in CMakeLists.txt
//==================================================================================
#include "config_core.h"
#ifdef WITH_NTL

    #include "lattice/lat-hal.h"
    #include "math/matrix.cpp"          // NOLINT
    #include "matrix-lattice-impl.cpp"  // NOLINT

    #include "elemparams.cpp"  // NOLINT
    #include "ilparams.cpp"    // NOLINT
    #include "poly.cpp"        // NOLINT

namespace lbcrypto {

template class ElemParams<M6Integer>;
template class ILParamsImpl<M6Integer>;
template class PolyImpl<M6Vector>;
// template class DCRTPolyImpl<M6Vector>;

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

// biginteger version
template <>
PolyImpl<NativeVector> PolyImpl<M6Vector>::ToNativePoly() const {
    PolyImpl<NativeVector> interp(std::make_shared<ILParamsImpl<NativeInteger>>(
                                      this->GetCyclotomicOrder(), std::numeric_limits<uint64_t>::max(), 1),
                                  this->GetFormat(), true);

    for (usint i = 0; i < this->GetLength(); i++) {
        interp[i] = (*this)[i].ConvertToInt();
    }

    return interp;
}

}  // namespace lbcrypto

CEREAL_CLASS_VERSION(lbcrypto::M6Poly, lbcrypto::M6Poly::SerializedVersion());
CEREAL_CLASS_VERSION(lbcrypto::M6DCRTPoly, lbcrypto::M6DCRTPoly::SerializedVersion());

#endif  // WITH_NTL
