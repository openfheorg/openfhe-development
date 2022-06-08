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

#include "UnitTestCCParams.h"
#include <sstream>
#include <ostream>


std::string UnitTestCCParams::toString() const {
    std::stringstream ss;
    ss << "schemeId [" << schemeId << "], "
        << "ringDimension [" << ringDimension << "], "
        << "multiplicativeDepth [" << multiplicativeDepth << "], "
        << "scalingFactorBits [" << scalingFactorBits << "], "
        << "digitSize [" << digitSize << "], "
        << "batchSize [" << batchSize << "], "
        << "mode [" << mode << "], "
        << "maxDepth [" << maxDepth << "], "
        << "firstModSize [" << firstModSize << "], "
        << "securityLevel [" << securityLevel << "], "
        << "ksTech [" << ksTech << "], "
        << "rsTech [" << rsTech << "], "
        << "numLargeDigits [" << numLargeDigits << "], "
        << "plaintextModulus [" << plaintextModulus << "], "
        << "standardDeviation [" << standardDeviation << "], "
        << "evalAddCount [" << evalAddCount << "], "
        << "evalMultCount [" << evalMultCount << "], "
        << "keySwitchCount [" << keySwitchCount << "], "
        << "multiplicationTechnique [" << multiplicationTechnique << "], "
        ;
    return ss.str();
}
//===========================================================================================================
std::ostream& operator<<(std::ostream& os, const UnitTestCCParams& params) {
    return os << params.toString();
}
