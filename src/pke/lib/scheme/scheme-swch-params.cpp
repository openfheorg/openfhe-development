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
#include "scheme/scheme-swch-params.h"

#include <iostream>

namespace lbcrypto {

// clang-format off
std::ostream& operator<<(std::ostream& os, const SchSwchParams& obj) {
    os  << "securityLevelCKKS: " << obj.securityLevelCKKS
        << "; securityLevelFHEW: " << obj.securityLevelFHEW
        << "; numSlotsCKKS: " << obj.numSlotsCKKS
        << "; numValues: " << obj.numValues
        << "; ctxtModSizeFHEWLargePrec: " << obj.ctxtModSizeFHEWLargePrec
        << "; ctxtModSizeFHEWIntermedSwch: " << obj.ctxtModSizeFHEWIntermedSwch
        << "; bStepLTrCKKStoFHEW: " << obj.bStepLTrCKKStoFHEW
        << "; bStepLTrFHEWtoCKKS: " << obj.bStepLTrFHEWtoCKKS
        << "; levelLTrCKKStoFHEW: " << obj.levelLTrCKKStoFHEW
        << "; levelLTrFHEWtoCKKS: " << obj.levelLTrFHEWtoCKKS
        << "; arbitraryFunctionEvaluation: " << obj.arbitraryFunctionEvaluation
        << "; useDynamicModeFHEW:" << obj.useDynamicModeFHEW
        << "; computeArgmin: " << obj.computeArgmin
        << "; oneHotEncoding: " << obj.oneHotEncoding
        << "; useAltArgmin: " << obj.useAltArgmin
        << "; PARAMS SET UP INTERNALLY FROM CRYPTOCONTEXT:"
        << "  initialCKKSModulus: " << obj.initialCKKSModulus
        << "; ringDimension: " << obj.ringDimension
        << "; scalingModSize: " << obj.scalingModSize
        << "; batchSize: " << obj.batchSize;

    return os;
}
// clang-format on

}  // namespace lbcrypto
