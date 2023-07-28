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
  Definitions for scheme parameter default class
 */

#include "scheme/cryptocontextparams-base.h"
#include "scheme/cryptocontextparams-defaults.h"
#include "utils/exception.h"

#include <string>
#include <ostream>

namespace lbcrypto {

//====================================================================================================================
#define SET_TO_SCHEME_DEFAULT(SCHEME, var) this->var = SCHEME##_DEFAULTS::var  // see cryptocontextparams-defaults.h
#define SET_TO_SCHEME_DEFAULTS(SCHEME)                          \
    {                                                           \
        SET_TO_SCHEME_DEFAULT(SCHEME, scheme);                  \
        SET_TO_SCHEME_DEFAULT(SCHEME, ptModulus);               \
        SET_TO_SCHEME_DEFAULT(SCHEME, digitSize);               \
        SET_TO_SCHEME_DEFAULT(SCHEME, standardDeviation);       \
        SET_TO_SCHEME_DEFAULT(SCHEME, secretKeyDist);           \
        SET_TO_SCHEME_DEFAULT(SCHEME, maxRelinSkDeg);           \
        SET_TO_SCHEME_DEFAULT(SCHEME, ksTech);                  \
        SET_TO_SCHEME_DEFAULT(SCHEME, scalTech);                \
        SET_TO_SCHEME_DEFAULT(SCHEME, batchSize);               \
        SET_TO_SCHEME_DEFAULT(SCHEME, firstModSize);            \
        SET_TO_SCHEME_DEFAULT(SCHEME, numLargeDigits);          \
        SET_TO_SCHEME_DEFAULT(SCHEME, multiplicativeDepth);     \
        SET_TO_SCHEME_DEFAULT(SCHEME, scalingModSize);          \
        SET_TO_SCHEME_DEFAULT(SCHEME, securityLevel);           \
        SET_TO_SCHEME_DEFAULT(SCHEME, ringDim);                 \
        SET_TO_SCHEME_DEFAULT(SCHEME, evalAddCount);            \
        SET_TO_SCHEME_DEFAULT(SCHEME, keySwitchCount);          \
        SET_TO_SCHEME_DEFAULT(SCHEME, encryptionTechnique);     \
        SET_TO_SCHEME_DEFAULT(SCHEME, multiplicationTechnique); \
        SET_TO_SCHEME_DEFAULT(SCHEME, multiHopModSize);         \
        SET_TO_SCHEME_DEFAULT(SCHEME, PREMode);                 \
        SET_TO_SCHEME_DEFAULT(SCHEME, multipartyMode);          \
        SET_TO_SCHEME_DEFAULT(SCHEME, executionMode);           \
        SET_TO_SCHEME_DEFAULT(SCHEME, decryptionNoiseMode);     \
        SET_TO_SCHEME_DEFAULT(SCHEME, noiseEstimate);           \
        SET_TO_SCHEME_DEFAULT(SCHEME, desiredPrecision);        \
        SET_TO_SCHEME_DEFAULT(SCHEME, statisticalSecurity);     \
        SET_TO_SCHEME_DEFAULT(SCHEME, numAdversarialQueries);   \
        SET_TO_SCHEME_DEFAULT(SCHEME, thresholdNumOfParties);   \
    }
void Params::SetToDefaults(SCHEME scheme) {
    switch (scheme) {
        case CKKSRNS_SCHEME:
            SET_TO_SCHEME_DEFAULTS(CKKSRNS_SCHEME);
            break;
        case BFVRNS_SCHEME:
            SET_TO_SCHEME_DEFAULTS(BFVRNS_SCHEME);
            break;
        case BGVRNS_SCHEME:
            SET_TO_SCHEME_DEFAULTS(BGVRNS_SCHEME);
            break;
        default:
            std::string errorMsg(std::string("Invalid scheme id: ") + std::to_string(scheme));
            OPENFHE_THROW(config_error, errorMsg);
            break;
    }
}
//====================================================================================================================
void Params::ValidateRingDim(usint ringDim) {
    if (!IsPowerOfTwo(ringDim)) {
        std::string errorMsg(std::string("Invalid ringDim [") + std::to_string(ringDim) +
                             "]. Ring dimension must be a power of 2.");
        OPENFHE_THROW(config_error, errorMsg);
    }
}
// clang-format off
std::ostream& operator<<(std::ostream& os, const Params& obj) {
    os  << "scheme: " << obj.scheme
        << "; ptModulus: " << obj.ptModulus
        << "; digitSize: " << obj.digitSize
        << "; standardDeviation: " << obj.standardDeviation
        << "; secretKeyDist: " << obj.secretKeyDist
        << "; maxRelinSkDeg: " << obj.maxRelinSkDeg
        << "; ksTech: " << obj.ksTech
        << "; scalTech: " << obj.scalTech
        << "; batchSize: " << obj.batchSize
        << "; firstModSize: " << obj.firstModSize
        << "; numLargeDigits: " << obj.numLargeDigits
        << "; multiplicativeDepth:" << obj.multiplicativeDepth
        << "; scalingModSize: " << obj.scalingModSize
        << "; securityLevel: " << obj.securityLevel
        << "; ringDim: " << obj.ringDim
        << "; evalAddCount: " << obj.evalAddCount
        << "; keySwitchCount: " << obj.keySwitchCount
        << "; encryptionTechnique: " << obj.encryptionTechnique
        << "; multiplicationTechnique: " << obj.multiplicationTechnique
        << "; multiHopModSize: " << obj.multiHopModSize
        << "; PREMode: " << obj.PREMode
        << "; multipartyMode: " << obj.multipartyMode
        << "; executionMode: " << obj.executionMode
        << "; decryptionNoiseMode: " << obj.decryptionNoiseMode
        << "; noiseEstimate: " << obj.noiseEstimate
        << "; desiredPrecision: " << obj.desiredPrecision
        << "; statisticalSecurity: " << obj.statisticalSecurity
        << "; numAdversarialQueries: " << obj.numAdversarialQueries
        << "; ThresholdNumOfParties: " << obj.thresholdNumOfParties;

    return os;
}
// clang-format on
//====================================================================================================================

}  // namespace lbcrypto
