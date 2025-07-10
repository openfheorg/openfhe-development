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
#include "utils/exception.h"
#include "utils/utilities.h"

namespace lbcrypto {

void validateParametersForCryptocontext(const Params& parameters) {
    SCHEME scheme = parameters.GetScheme();
    if (isCKKS(scheme)) {
        if (NORESCALE == parameters.GetScalingTechnique()) {
            OPENFHE_THROW("NORESCALE is not supported in CKKSRNS");
        }
        else if (COMPOSITESCALINGAUTO == parameters.GetScalingTechnique()) {
            if (1 != parameters.GetCompositeDegree()) {
                OPENFHE_THROW("Composite degree can be set for COMPOSITESCALINGMANUAL only.");
            }
        }
        else if (COMPOSITESCALINGMANUAL == parameters.GetScalingTechnique()) {
            if (parameters.GetCompositeDegree() < 1 || parameters.GetCompositeDegree() > 4) {
                OPENFHE_THROW("Composite degree valid values: 1, 2, 3, and 4.");
            }
        }
        if (NOISE_FLOODING_HRA == parameters.GetPREMode()) {
            OPENFHE_THROW("NOISE_FLOODING_HRA is not supported in CKKSRNS");
        }
        if (NOISE_FLOODING_MULTIPARTY == parameters.GetMultipartyMode()) {
            OPENFHE_THROW(
                "NOISE_FLOODING_MULTIPARTY is not supported in CKKSRNS. Use NOISE_FLOODING_DECRYPT and EXEC_EVALUATION instead.");
        }
        if (COMPOSITESCALINGAUTO == parameters.GetScalingTechnique() || COMPOSITESCALINGMANUAL == parameters.GetScalingTechnique()) {
            if (COMPOSITESCALING_MAX_MODULUS_SIZE <= parameters.GetScalingModSize() || 15 > parameters.GetScalingModSize()) {
                OPENFHE_THROW(
                    "scalingModSize should be greater than 15 and less than " + std::to_string(COMPOSITESCALING_MAX_MODULUS_SIZE));
            }
        }
        else {
            if (MAX_MODULUS_SIZE <= parameters.GetScalingModSize() || 15 > parameters.GetScalingModSize()) {
                OPENFHE_THROW(
                    "scalingModSize should be greater than 15 and less than " + std::to_string(MAX_MODULUS_SIZE));
            }
        }
        if (30 != parameters.GetStatisticalSecurity()) {
            if (NOISE_FLOODING_MULTIPARTY != parameters.GetMultipartyMode()) {
                OPENFHE_THROW("statisticalSecurity is allowed for multipartyMode == NOISE_FLOODING_MULTIPARTY only");
            }
        }
        if (1 != parameters.GetNumAdversarialQueries()) {
            if (NOISE_FLOODING_MULTIPARTY != parameters.GetMultipartyMode()) {
                OPENFHE_THROW("numAdversarialQueries is allowed for multipartyMode == NOISE_FLOODING_MULTIPARTY only");
            }
        }
        if (parameters.GetExecutionMode() == EXEC_NOISE_ESTIMATION && parameters.GetCKKSDataType() == COMPLEX) {
            OPENFHE_THROW("EXEC_NOISE_ESTIMATION mode is not compatible with complex data types.");
        }
        if (parameters.GetFirstModSize() < parameters.GetScalingModSize()) {
            OPENFHE_THROW("firstModSize cannot be less than scalingModSize");
        }
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
        if (NOISE_FLOODING_HRA == parameters.GetPREMode()) {
            if (FIXEDMANUAL != parameters.GetScalingTechnique()) {
                OPENFHE_THROW("NOISE_FLOODING_HRA is allowed for scalingTechnique == FIXEDMANUAL only");
            }
            if (0 == parameters.GetPRENumHops()) {
                OPENFHE_THROW("PRENumHops should be set to a value > 0 for PREMode == NOISE_FLOODING_HRA");
            }
            if (0 != parameters.GetMultiplicativeDepth()) {
                OPENFHE_THROW("multiplicativeDepth should be set to 0 for PREMode == NOISE_FLOODING_HRA");
            }
            if (0 != parameters.GetFirstModSize()) {
                OPENFHE_THROW("firstModSize is not supported for PREMode == NOISE_FLOODING_HRA");
            }
            if (0 != parameters.GetScalingModSize()) {
                OPENFHE_THROW("scalingModSize is not supported for PREMode == NOISE_FLOODING_HRA");
            }
            if (0 == parameters.GetRingDim()) {
                OPENFHE_THROW("ringDim should be set to a value > 0 for PREMode == NOISE_FLOODING_HRA");
            }
        }
        if (0 != parameters.GetFirstModSize()) {
            if (FIXEDMANUAL != parameters.GetScalingTechnique()) {
                OPENFHE_THROW("firstModSize is allowed for scalingTechnique == FIXEDMANUAL only");
            }
        }
        if (0 != parameters.GetScalingModSize()) {
            if (FIXEDMANUAL != parameters.GetScalingTechnique()) {
                OPENFHE_THROW("scalingModSize is allowed for scalingTechnique == FIXEDMANUAL only");
            }
        }
        if (0 != parameters.GetPRENumHops()) {
            if (NOISE_FLOODING_HRA != parameters.GetPREMode()) {
                OPENFHE_THROW("PRENumHops is allowed for PREMode == NOISE_FLOODING_HRA only");
            }
        }
        if (30 != parameters.GetStatisticalSecurity()) {
            if (NOISE_FLOODING_HRA != parameters.GetPREMode()) {
                OPENFHE_THROW("statisticalSecurity is allowed for PREMode == NOISE_FLOODING_HRA only");
            }
        }
        if (1 != parameters.GetNumAdversarialQueries()) {
            if (NOISE_FLOODING_HRA != parameters.GetPREMode()) {
                OPENFHE_THROW("numAdversarialQueries is allowed for PREMode == NOISE_FLOODING_HRA only");
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
    if (BV == parameters.GetKeySwitchTechnique()) {
        const uint32_t maxDigitSize = uint32_t(std::ceil(MAX_MODULUS_SIZE / 2));
        if (maxDigitSize < parameters.GetDigitSize()) {
            OPENFHE_THROW("digitSize should not be greater than " + std::to_string(maxDigitSize) +
                          " for keySwitchTechnique == BV");
        }
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
