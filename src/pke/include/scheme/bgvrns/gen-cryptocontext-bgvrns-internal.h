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
  API to generate BGVRNS crypto context. MUST NOT (!) be used without a wrapper function
 */

#ifndef __GEN_CRYPTOCONTEXT_BGVRNS_INTERNAL_H__
#define __GEN_CRYPTOCONTEXT_BGVRNS_INTERNAL_H__

#include "encoding/encodingparams.h"
#include "scheme/scheme-utils.h"
#include "scheme/scheme-id.h"

#include <memory>

namespace lbcrypto {

// forward declarations (don't include headers as compilation fails when you do)
template <typename T>
class CCParams;

template <typename ContextGeneratorType, typename Element>
typename ContextGeneratorType::ContextType genCryptoContextBGVRNSInternal(
    const CCParams<ContextGeneratorType>& parameters) {
    using ParmType                   = typename Element::Params;
    constexpr float assuranceMeasure = 36.0f;

    auto ep = std::make_shared<ParmType>();
    EncodingParams encodingParams(
        std::make_shared<EncodingParamsImpl>(parameters.GetPlaintextModulus(), parameters.GetBatchSize()));

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
        parameters.GetPlaintextModulus(),
        parameters.GetStatisticalSecurity(),
        parameters.GetNumAdversarialQueries(),
        parameters.GetThresholdNumOfParties());

    // for BGV scheme noise scale is always set to plaintext modulus
    params->SetNoiseScale(parameters.GetPlaintextModulus());

    auto numLargeDigits = (parameters.GetMultiplicativeDepth() == 0) ?
                              ComputeNumLargeDigitsPRE(parameters.GetNumLargeDigits(), parameters.GetPRENumHops()) :
                              ComputeNumLargeDigits(parameters.GetNumLargeDigits(), parameters.GetMultiplicativeDepth());

    auto scheme = std::make_shared<typename ContextGeneratorType::PublicKeyEncryptionScheme>();
    scheme->SetKeySwitchingTechnique(parameters.GetKeySwitchTechnique());
    scheme->ParamsGenBGVRNS(
        params,
        parameters.GetEvalAddCount(),
        parameters.GetKeySwitchCount(),
        2 * parameters.GetRingDim(),
        parameters.GetMultiplicativeDepth() + 1,
        parameters.GetFirstModSize(),
        parameters.GetScalingModSize(),
        numLargeDigits,
        parameters.GetPRENumHops());
    // clang-format on

    auto cc = ContextGeneratorType::Factory::GetContext(params, scheme);
    cc->setSchemeId(SCHEME::BGVRNS_SCHEME);
    return cc;
}

}  // namespace lbcrypto

#endif  // __GEN_CRYPTOCONTEXT_BGVRNS_INTERNAL_H__
