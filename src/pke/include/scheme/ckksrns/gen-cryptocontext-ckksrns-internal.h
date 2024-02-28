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
  API to generate CKKS crypto context. MUST NOT (!) be used without a wrapper function
 */

#ifndef _GEN_CRYPTOCONTEXT_CKKSRNS_INTERNAL_H_
#define _GEN_CRYPTOCONTEXT_CKKSRNS_INTERNAL_H_

#include "encoding/encodingparams.h"
#include "constants.h"
#include "utils/exception.h"
#include "scheme/scheme-utils.h"
#include "scheme/scheme-id.h"

#include <memory>

namespace lbcrypto {

// forward declarations (don't include headers as compilation fails when you do)
template <typename T>
class CCParams;

template <typename ContextGeneratorType, typename Element>
typename ContextGeneratorType::ContextType genCryptoContextCKKSRNSInternal(
    const CCParams<ContextGeneratorType>& parameters) {
#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
    if (parameters.GetScalingTechnique() == FLEXIBLEAUTO || parameters.GetScalingTechnique() == FLEXIBLEAUTOEXT) {
        OPENFHE_THROW("128-bit CKKS is not supported for the FLEXIBLEAUTO or FLEXIBLEAUTOEXT methods.");
    }
#endif
    using ParmType                   = typename Element::Params;
    constexpr float assuranceMeasure = 36.0f;

    auto ep = std::make_shared<ParmType>();

    usint scalingModSize    = parameters.GetScalingModSize();
    usint firstModSize      = parameters.GetFirstModSize();
    double floodingNoiseStd = 0;
    if (parameters.GetDecryptionNoiseMode() == NOISE_FLOODING_DECRYPT &&
        parameters.GetExecutionMode() == EXEC_EVALUATION) {
        if (parameters.GetNoiseEstimate() == 0) {
            OPENFHE_THROW(
                "Noise estimate must be set in the combination of NOISE_FLOODING_DECRYPT and EXEC_EVALUATION modes.");
        }
        double logstd =
            parameters.GetStatisticalSecurity() / 2 + log2(sqrt(12 * parameters.GetNumAdversarialQueries()));
        floodingNoiseStd = pow(2, logstd + parameters.GetNoiseEstimate());
#if NATIVEINT == 128
        scalingModSize = parameters.GetDesiredPrecision() + parameters.GetNoiseEstimate() + logstd +
                         0.5 * log2(parameters.GetRingDim());
        firstModSize = scalingModSize + 11;
#else
        scalingModSize = MAX_MODULUS_SIZE - 1;
        firstModSize   = MAX_MODULUS_SIZE;
        if (logstd + parameters.GetNoiseEstimate() > scalingModSize - 3) {
            OPENFHE_THROW("Precision of less than 3 bits is not supported. logstd " + std::to_string(logstd) +
                          " + noiseEstimate " + std::to_string(parameters.GetNoiseEstimate()) + " must be 56 or less.");
        }
#endif
    }
    EncodingParams encodingParams(std::make_shared<EncodingParamsImpl>(scalingModSize, parameters.GetBatchSize()));

    // clang-format off
    auto params = std::make_shared<typename ContextGeneratorType::CryptoParams>(
        ep,
        encodingParams,
        parameters.GetStandardDeviation(),
        assuranceMeasure,
        parameters.GetSecurityLevel(),
        parameters.GetDigitSize(),
        parameters.GetSecretKeyDist(),
        parameters.GetMaxRelinSkDeg(),
        parameters.GetKeySwitchTechnique(),
        parameters.GetScalingTechnique(),
        parameters.GetEncryptionTechnique(),
        parameters.GetMultiplicationTechnique(),
        parameters.GetPREMode(),
        parameters.GetMultipartyMode(),
        parameters.GetExecutionMode(),
        parameters.GetDecryptionNoiseMode(),
        1,  // noise scale: TODO (dsuponit): this should be reviewed as we also call SetNoiseScale(1) (see below)
        parameters.GetStatisticalSecurity(),
        parameters.GetNumAdversarialQueries(),
        parameters.GetThresholdNumOfParties(),
        parameters.GetInteractiveBootCompressionLevel());

    // for CKKS scheme noise scale is always set to 1
    params->SetNoiseScale(1);
    params->SetFloodingDistributionParameter(floodingNoiseStd);

    uint32_t numLargeDigits =
        ComputeNumLargeDigits(parameters.GetNumLargeDigits(), parameters.GetMultiplicativeDepth());

    auto scheme = std::make_shared<typename ContextGeneratorType::PublicKeyEncryptionScheme>();
    scheme->SetKeySwitchingTechnique(parameters.GetKeySwitchTechnique());
    scheme->ParamsGenCKKSRNS(
        params,
        2 * parameters.GetRingDim(),
        parameters.GetMultiplicativeDepth() + 1,
        scalingModSize,
        firstModSize,
        numLargeDigits,
        parameters.GetInteractiveBootCompressionLevel());
    // clang-format on

    auto cc = ContextGeneratorType::Factory::GetContext(params, scheme);
    cc->setSchemeId(SCHEME::CKKSRNS_SCHEME);
    return cc;
}
}  // namespace lbcrypto

#endif  // _GEN_CRYPTOCONTEXT_CKKSRNS_INTERNAL_H_
