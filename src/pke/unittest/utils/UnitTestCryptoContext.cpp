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

#include "UnitTestCryptoContext.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"
#include "scheme/bfvrns/gen-cryptocontext-bfvrns.h"
#include "scheme/bgvrns/gen-cryptocontext-bgvrns.h"
#include "gen-cryptocontext.h"

using namespace lbcrypto;

template <typename U>
static void setCryptoContextParametersFromUnitTestCCParams(const UnitTestCCParams& params, U& parameters) {
    if (!isDefaultValue(params.ringDimension)) {
        parameters.SetRingDim(static_cast<usint>(std::round(params.ringDimension)));
    }
    if (!isDefaultValue(params.multiplicativeDepth)) {
        parameters.SetMultiplicativeDepth(static_cast<usint>(std::round(params.multiplicativeDepth)));
    }
    if (!isDefaultValue(params.scalingModSize)) {
        parameters.SetScalingModSize(static_cast<usint>(std::round(params.scalingModSize)));
    }
    if (!isDefaultValue(params.digitSize)) {
        parameters.SetDigitSize(static_cast<usint>(std::round(params.digitSize)));
    }
    if (!isDefaultValue(params.batchSize)) {
        parameters.SetBatchSize(static_cast<usint>(std::round(params.batchSize)));
    }
    if (!isDefaultValue(params.secretKeyDist)) {
        parameters.SetSecretKeyDist(static_cast<SecretKeyDist>(std::round(params.secretKeyDist)));
    }
    if (!isDefaultValue(params.maxRelinSkDeg)) {
        parameters.SetMaxRelinSkDeg(static_cast<int>(std::round(params.maxRelinSkDeg)));
    }
    if (!isDefaultValue(params.firstModSize)) {
        parameters.SetFirstModSize(static_cast<usint>(std::round(params.firstModSize)));
    }
    if (!isDefaultValue(params.securityLevel)) {
        parameters.SetSecurityLevel(static_cast<SecurityLevel>(std::round(params.securityLevel)));
    }
    if (!isDefaultValue(params.ksTech)) {
        parameters.SetKeySwitchTechnique(static_cast<KeySwitchTechnique>(std::round(params.ksTech)));
    }
    if (!isDefaultValue(params.scalTech)) {
        parameters.SetScalingTechnique(static_cast<ScalingTechnique>(std::round(params.scalTech)));
    }
    if (!isDefaultValue(params.numLargeDigits)) {
        parameters.SetNumLargeDigits(static_cast<uint32_t>(std::round(params.numLargeDigits)));
    }
    if (!isDefaultValue(params.plaintextModulus)) {
        parameters.SetPlaintextModulus(static_cast<PlaintextModulus>(std::round(params.plaintextModulus)));
    }
    if (!isDefaultValue(params.standardDeviation)) {
        parameters.SetStandardDeviation(params.standardDeviation);
    }
    if (!isDefaultValue(params.multiplicationTechnique)) {
        parameters.SetMultiplicationTechnique(
            static_cast<MultiplicationTechnique>(std::round(params.multiplicationTechnique)));
    }
    if (!isDefaultValue(params.encryptionTechnique)) {
        parameters.SetEncryptionTechnique(static_cast<EncryptionTechnique>(std::round(params.encryptionTechnique)));
    }
    if (!isDefaultValue(params.evalAddCount)) {
        parameters.SetEvalAddCount(static_cast<usint>(std::round(params.evalAddCount)));
    }
    if (!isDefaultValue(params.keySwitchCount)) {
        parameters.SetKeySwitchCount(static_cast<usint>(std::round(params.keySwitchCount)));
    }
    if (!isDefaultValue(params.PREMode)) {
        parameters.SetPREMode(static_cast<ProxyReEncryptionMode>(std::round(params.PREMode)));
    }
    if (!isDefaultValue(params.multipartyMode)) {
        parameters.SetMultipartyMode(static_cast<MultipartyMode>(std::round(params.multipartyMode)));
    }
    if (!isDefaultValue(params.decryptionNoiseMode)) {
        parameters.SetDecryptionNoiseMode(static_cast<DecryptionNoiseMode>(std::round(params.decryptionNoiseMode)));
    }
    if (!isDefaultValue(params.executionMode)) {
        parameters.SetExecutionMode(static_cast<ExecutionMode>(std::round(params.executionMode)));
    }
    if (!isDefaultValue(params.noiseEstimate)) {
        parameters.SetNoiseEstimate(params.noiseEstimate);
    }
}
//===========================================================================================================
CryptoContext<Element> UnitTestGenerateContext(const UnitTestCCParams& params) {
    CryptoContext<Element> cc(nullptr);
    if (CKKSRNS_SCHEME == params.schemeId) {
        CCParams<CryptoContextCKKSRNS> parameters;
        setCryptoContextParametersFromUnitTestCCParams(params, parameters);

        cc = GenCryptoContext(parameters);
    }
    else if (BFVRNS_SCHEME == params.schemeId) {
        CCParams<CryptoContextBFVRNS> parameters;
        setCryptoContextParametersFromUnitTestCCParams(params, parameters);

        cc = GenCryptoContext(parameters);
    }
    else if (BGVRNS_SCHEME == params.schemeId) {
        CCParams<CryptoContextBGVRNS> parameters;
        setCryptoContextParametersFromUnitTestCCParams(params, parameters);

        cc = GenCryptoContext(parameters);
    }

    if (!cc)
        OPENFHE_THROW("Error generating crypto context.");

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(PRE);
    cc->Enable(FHE);
    cc->Enable(MULTIPARTY);

    return cc;
}

//===========================================================================================================
CryptoContext<Element> UnitTestGenerateContext(const BaseTestCase& testCase) {
    CryptoContext<Element> cc(nullptr);
    auto paramOverrides       = testCase.getCryptoContextParamOverrides();
    lbcrypto::SCHEME schemeId = lbcrypto::convertToSCHEME(*paramOverrides.begin());
    if (CKKSRNS_SCHEME == schemeId) {
        CCParams<CryptoContextCKKSRNS> parameters(paramOverrides);
        cc = GenCryptoContext(parameters);
    }
    else if (BFVRNS_SCHEME == schemeId) {
        CCParams<CryptoContextBFVRNS> parameters(paramOverrides);
        cc = GenCryptoContext(parameters);
    }
    else if (BGVRNS_SCHEME == schemeId) {
        CCParams<CryptoContextBGVRNS> parameters(paramOverrides);
        cc = GenCryptoContext(parameters);
    }

    if (!cc)
        OPENFHE_THROW("Error generating crypto context.");

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(PRE);
    cc->Enable(FHE);
    cc->Enable(MULTIPARTY);

    return cc;
}
