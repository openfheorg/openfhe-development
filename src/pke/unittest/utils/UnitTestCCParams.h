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

#ifndef __UNITTESTCCPARAMS_H__
#define __UNITTESTCCPARAMS_H__

#include <iosfwd>
#include <string>
#include <cmath>
#include "scheme/scheme-id.h"  // SCHEME

enum { DFLT = -999 };  // enum for test cases if you want to use the default value for the parameter

//===========================================================================================================
struct UnitTestCCParams {
    lbcrypto::SCHEME schemeId = lbcrypto::INVALID_SCHEME;  // mandatory field indicating what scheme is used

    // all double values are just data holders. Having them we can use parameters' default values
    double ringDimension           = DFLT;  // CKKSRNS, BFVRNS, BGVRNS
    double multiplicativeDepth     = DFLT;  // CKKSRNS, BGVRNS
    double scalingModSize          = DFLT;  // CKKSRNS, BFVRNS, BGVRNS
    double digitSize               = DFLT;  // CKKSRNS, BFVRNS, BGVRNS
    double batchSize               = DFLT;  // CKKSRNS, BFVRNS, BGVRNS
    double secretKeyDist           = DFLT;  // CKKSRNS, BFVRNS, BGVRNS
    double maxRelinSkDeg           = DFLT;  // CKKSRNS, BFVRNS, BGVRNS
    double firstModSize            = DFLT;  // BGVRNS
    double securityLevel           = DFLT;  // BFVRNS, BGVRNS
    double ksTech                  = DFLT;  // CKKSRNS, BGVRNS
    double scalTech                = DFLT;  // CKKSRNS, BGVRNS
    double numLargeDigits          = DFLT;  // CKKSRNS, BGVRNS
    double plaintextModulus        = DFLT;  // BFVRNS, BGVRNS
    double standardDeviation       = DFLT;  // BFVRNS, BGVRNS
    double evalAddCount            = DFLT;  // BFVRNS,
    double keySwitchCount          = DFLT;  // BFVRNS,
    double multiplicationTechnique = DFLT;  // BFVRNS,
    double encryptionTechnique     = DFLT;  // BFVRNS,
    double PREMode                 = DFLT;  // BGVRNS, BFVRNS, CKKSRNS
    double multipartyMode          = DFLT;  // BGVRNS, BFVRNS
    double decryptionNoiseMode     = DFLT;  // CKKSRNS
    double executionMode           = DFLT;  // CKKSRNS
    double noiseEstimate           = DFLT;  // CKKSRNS

    std::string toString() const;
};
//===========================================================================================================
std::ostream& operator<<(std::ostream& os, const UnitTestCCParams& params);
//===========================================================================================================
inline bool isDefaultValue(double val) {
    return (DFLT == std::round(val));
}
//===========================================================================================================

#endif  // __UNITTESTCCPARAMS_H__
