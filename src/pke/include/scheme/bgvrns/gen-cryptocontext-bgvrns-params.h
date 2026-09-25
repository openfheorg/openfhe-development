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
  Parameter class to generate BGVRNS crypto context
 */

#ifndef SRC_PKE_INCLUDE_SCHEME_BGVRNS_GEN_CRYPTOCONTEXT_BGVRNS_PARAMS_H_
#define SRC_PKE_INCLUDE_SCHEME_BGVRNS_GEN_CRYPTOCONTEXT_BGVRNS_PARAMS_H_

#include <cstdint>
#include <string>
#include <vector>

#include "scheme/gen-cryptocontext-params.h"

namespace lbcrypto {

class CryptoContextBGVRNS;

// every CCParams class should include the following forward declaration as there is
// no general CCParams class template. This way we may create scheme specific classes
// derived from Params or have them completely independent.
template <typename T>
class CCParams;
//====================================================================================================================
template <>
/**
 * @brief Parameters for generating a BGV crypto context. Initializes the BGV defaults and disables the
 * setters that do not apply to BGV (they throw when called).
 */
class CCParams<CryptoContextBGVRNS> : public Params {
  public:
    CCParams() : Params(BGVRNS_SCHEME) {}
    /**
     * Constructor from string values; to be used by unit tests only.
     *
     * @param vals vector with override values in the order given by Params::getAllParamsDataMembers().
     */
    explicit CCParams(const std::vector<std::string>& vals) : Params(vals) {}
    CCParams(const CCParams& obj) = default;
    CCParams(CCParams&& obj) = default;
    ~CCParams() = default;

    //================================================================================================================
    // DISABLE FUNCTIONS that are not applicable to BGVRNS
    //================================================================================================================
    /**
     * Not applicable to BGVRNS (throws).
     *
     * @param encryptionTechnique0 ignored.
     */
    void SetEncryptionTechnique(EncryptionTechnique encryptionTechnique0) override {
        DISABLED_FOR_BGVRNS;
    }
    /**
     * Not applicable to BGVRNS (throws).
     *
     * @param multiplicationTechnique0 ignored.
     */
    void SetMultiplicationTechnique(MultiplicationTechnique multiplicationTechnique0) override {
        DISABLED_FOR_BGVRNS;
    }
    /**
     * Not applicable to BGVRNS (throws).
     *
     * @param executionMode0 ignored.
     */
    void SetExecutionMode(ExecutionMode executionMode0) override {
        DISABLED_FOR_BGVRNS;
    }
    /**
     * Not applicable to BGVRNS (throws).
     *
     * @param decryptionNoiseMode0 ignored.
     */
    void SetDecryptionNoiseMode(DecryptionNoiseMode decryptionNoiseMode0) override {
        DISABLED_FOR_BGVRNS;
    }
    /**
     * Not applicable to BGVRNS (throws).
     *
     * @param noiseEstimate0 ignored.
     */
    void SetNoiseEstimate(double noiseEstimate0) override {
        DISABLED_FOR_BGVRNS;
    }
    /**
     * Not applicable to BGVRNS (throws).
     *
     * @param desiredPrecision0 ignored.
     */
    void SetDesiredPrecision(double desiredPrecision0) override {
        DISABLED_FOR_BGVRNS;
    }
    /**
     * Not applicable to BGVRNS (throws).
     *
     * @param interactiveBootCompressionLevel0 ignored.
     */
    void SetInteractiveBootCompressionLevel(CompressionLevel interactiveBootCompressionLevel0) override {
        DISABLED_FOR_BGVRNS;
    }
    /**
     * Not applicable to BGVRNS (throws).
     *
     * @param compositeDegree0 ignored.
     */
    void SetCompositeDegree(uint32_t compositeDegree0) override {
        DISABLED_FOR_BGVRNS;
    }
    /**
     * Not applicable to BGVRNS (throws).
     *
     * @param registerWordSize0 ignored.
     */
    void SetRegisterWordSize(uint32_t registerWordSize0) override {
        DISABLED_FOR_BGVRNS;
    }
    /**
     * Not applicable to BGVRNS (throws).
     *
     * @param ckksDataType0 ignored.
     */
    void SetCKKSDataType(CKKSDataType ckksDataType0) override {
        DISABLED_FOR_BGVRNS;
    }
};
//====================================================================================================================

}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_SCHEME_BGVRNS_GEN_CRYPTOCONTEXT_BGVRNS_PARAMS_H_
