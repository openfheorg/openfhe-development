//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2024, NJIT, Duality Technologies Inc. and other contributors
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
#include "scheme/gen-cryptocontext-params-validation.h"
#include "utils/utilities.h"

namespace lbcrypto {

void validateParametersForCryptocontext(const Params& parameters) {
    SCHEME scheme = parameters.GetScheme();
    if (isCKKS(scheme)) {
        if (NORESCALE == parameters.GetScalingTechnique()) {
            OPENFHE_THROW("NORESCALE is not supported in CKKSRNS");
        }
        if (NOISE_FLOODING_HRA == parameters.GetPREMode()) {
            OPENFHE_THROW("NOISE_FLOODING_HRA is not supported in CKKSRNS");
        }
        if (NOISE_FLOODING_MULTIPARTY == parameters.GetMultipartyMode()) {
            OPENFHE_THROW("NOISE_FLOODING_MULTIPARTY is not supported in CKKSRNS");
        }
#if NATIVEINT == 64
        if (59 < parameters.GetScalingModSize()) {
            OPENFHE_THROW("scalingModSize > 59 is not supported in CKKSRNS for NATIVEINT=64");
        }
#endif
    }
    else if (isBFVRNS(scheme)) {
        if (0 == parameters.GetPlaintextModulus()) {
            OPENFHE_THROW("PlaintextModulus is not set. It should be set to a non-zero value");
        }
        if (NOISE_FLOODING_HRA == parameters.GetPREMode()) {
            OPENFHE_THROW("NOISE_FLOODING_HRA is not supported in BFVRNS");
        }
    }
    else if (isBGVRNS(scheme)) {
        if (0 == parameters.GetPlaintextModulus()) {
            OPENFHE_THROW("PlaintextModulus is not set. It should be set to a non-zero value");
        }
        if (NORESCALE == parameters.GetScalingTechnique()) {
            OPENFHE_THROW("NORESCALE is not supported in BGVRNS");
        }
        if (0 != parameters.GetFirstModSize()) {
            if (FIXEDMANUAL != parameters.GetScalingTechnique()) {
                OPENFHE_THROW("firstModSize is allowed for scalingTechnique == FIXEDMANUAL only");
            }
        }
        if (0 != parameters.GetMultiHopModSize()) {
            if (NOISE_FLOODING_MULTIPARTY != parameters.GetMultipartyMode()) {
                OPENFHE_THROW("multiHopModSize is allowed for multipartyMode == NOISE_FLOODING_MULTIPARTY only");
            }
        }
    }
    else {
        std::string errMsg(std::string("Unknown schemeId: ") + std::to_string(scheme));
        OPENFHE_THROW(errMsg);
    }

    //====================================================================================================================
    // general validations
    if (parameters.GetRingDim() && !IsPowerOfTwo(parameters.GetRingDim())) {
        std::string errorMsg(std::string("Invalid ringDim [") + std::to_string(parameters.GetRingDim()) +
                             "]. Ring dimension must be a power of 2.");
        OPENFHE_THROW(errorMsg);
    }
    //====================================================================================================================
    constexpr usint maxMultiplicativeDepthValue = 1000;
    if (parameters.GetMultiplicativeDepth() > maxMultiplicativeDepthValue) {
        std::string errorMsg(std::string("The provided multiplicative depth [") +
                             std::to_string(parameters.GetMultiplicativeDepth()) +
                             "] is not computationally feasible. Use a smaller value.");
        OPENFHE_THROW(errorMsg);
    }
    //====================================================================================================================
}

}  // namespace lbcrypto
