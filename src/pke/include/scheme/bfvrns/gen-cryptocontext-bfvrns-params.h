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
  Parameter class to generate BFVRNS crypto context
 */

#ifndef SRC_PKE_INCLUDE_SCHEME_BFVRNS_GEN_CRYPTOCONTEXT_BFVRNS_PARAMS_H_
#define SRC_PKE_INCLUDE_SCHEME_BFVRNS_GEN_CRYPTOCONTEXT_BFVRNS_PARAMS_H_

#include <cstdint>
#include <string>
#include <vector>

#include "scheme/gen-cryptocontext-params.h"

namespace lbcrypto {

class CryptoContextBFVRNS;

// TODO (dsuponit): review class CCParams<> as we may need to add a class template CCParams<> (see the comments below)
// every CCParams class should include the following forward declaration as there is
// no general CCParams class template. This way we may create scheme specific classes
// derived from Params or have them completely independent.
template <typename T>
class CCParams;
//====================================================================================================================
template <>
/**
 * @brief Parameters for generating a BFV crypto context. Initializes the BFV defaults and disables the
 * setters that do not apply to BFV (they throw when called).
 */
class CCParams<CryptoContextBFVRNS> : public Params {
  public:
    CCParams() : Params(BFVRNS_SCHEME) {}
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
    // DISABLE FUNCTIONS that are not applicable to BFVRNS
    //================================================================================================================
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param scalTech0 ignored.
     */
    void SetScalingTechnique(ScalingTechnique scalTech0) override {
        DISABLED_FOR_BFVRNS;
    }
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param firstModSize0 ignored.
     */
    void SetFirstModSize(uint32_t firstModSize0) override {
        DISABLED_FOR_BFVRNS;
    }
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param PRENumHops0 ignored.
     */
    void SetPRENumHops(uint32_t PRENumHops0) override {
        DISABLED_FOR_BFVRNS;
    }
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param executionMode0 ignored.
     */
    void SetExecutionMode(ExecutionMode executionMode0) override {
        DISABLED_FOR_BFVRNS;
    }
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param decryptionNoiseMode0 ignored.
     */
    void SetDecryptionNoiseMode(DecryptionNoiseMode decryptionNoiseMode0) override {
        DISABLED_FOR_BFVRNS;
    }
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param noiseEstimate0 ignored.
     */
    void SetNoiseEstimate(double noiseEstimate0) override {
        DISABLED_FOR_BFVRNS;
    }
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param desiredPrecision0 ignored.
     */
    void SetDesiredPrecision(double desiredPrecision0) override {
        DISABLED_FOR_BFVRNS;
    }
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param statisticalSecurity0 ignored.
     */
    void SetStatisticalSecurity(uint32_t statisticalSecurity0) override {
        DISABLED_FOR_BFVRNS;
    }
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param numAdversarialQueries0 ignored.
     */
    void SetNumAdversarialQueries(uint32_t numAdversarialQueries0) override {
        DISABLED_FOR_BFVRNS;
    }
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param interactiveBootCompressionLevel0 ignored.
     */
    void SetInteractiveBootCompressionLevel(CompressionLevel interactiveBootCompressionLevel0) override {
        DISABLED_FOR_BFVRNS;
    }
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param compositeDegree0 ignored.
     */
    void SetCompositeDegree(uint32_t compositeDegree0) override {
        DISABLED_FOR_BFVRNS;
    }
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param registerWordSize0 ignored.
     */
    void SetRegisterWordSize(uint32_t registerWordSize0) override {
        DISABLED_FOR_BFVRNS;
    }
    /**
     * Not applicable to BFVRNS (throws).
     *
     * @param ckksDataType0 ignored.
     */
    void SetCKKSDataType(CKKSDataType ckksDataType0) override {
        DISABLED_FOR_BFVRNS;
    }
};
//====================================================================================================================

}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_SCHEME_BFVRNS_GEN_CRYPTOCONTEXT_BFVRNS_PARAMS_H_
