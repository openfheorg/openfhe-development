// @file gen-cryptocontext-ckks-internal.h -- API to generate CKKS crypto context. MUST NOT (!) be used without a wrapper function.
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT))
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef _GEN_CRYPTOCONTEXT_CKKS_INTERNAL_H_
#define _GEN_CRYPTOCONTEXT_CKKS_INTERNAL_H_

#include "constants.h"
#include "utils/exception.h"
#include "encoding/encodingparams.h"

namespace lbcrypto {

// forward declarations (don't include headers as compilation fails when you do)
template <typename T>
class CCParams;

template <class Element>
class LPCryptoParametersCKKS;


template<template<typename> typename ContextGeneratorType, typename Element>
typename ContextGeneratorType<Element>::ContextType genCryptoContextCKKSInternal(const CCParams<ContextGeneratorType<Element>>& parameters) {
#if NATIVEINT == 128
    if (parameters.GetRescalingTechnique() == EXACTRESCALE) {
        PALISADE_THROW(config_error, "128-bit CKKS is not supported for the EXACTRESCALE method.");
    }
#endif
    using ParmType = typename Element::Params;
    using IntType = typename Element::Integer;

    auto ep = std::make_shared<ParmType>(0, IntType(0), IntType(0));
    // In CKKS, the plaintext modulus is equal to the scaling factor.
    EncodingParams encodingParams(std::make_shared<EncodingParamsImpl>(parameters.GetScalingFactorBits()));
    encodingParams->SetBatchSize(parameters.GetBatchSize());

    auto params = std::make_shared<typename ContextGeneratorType<Element>::CryptoParams>(
        ep,
        encodingParams,
        parameters.GetStandardDeviation(),
        parameters.GetAssuranceMeasure(),
        parameters.GetRootHermiteFactor(),
        parameters.GetRelinWindow(),
        parameters.GetMode(),
        parameters.GetDepth(),
        parameters.GetMaxDepth());
    params->SetStdLevel(parameters.GetSecurityLevel());

    uint32_t numLargeDigits = parameters.GetNumLargeDigits();
    if (!numLargeDigits) {  // Choose one of the default values
        if (parameters.GetMultiplicativeDepth() > 3)        // If more than 4 towers, use 3 digits
            numLargeDigits = 3;
        else if (parameters.GetMultiplicativeDepth() == 0)  // if there is only 1 tower, use one digit
            numLargeDigits = 1;
        else                                // If 2, 3 or 4 towers, use 2 digits (1 <= multiplicativeDepth <=3 )
            numLargeDigits = 2;
    }

    auto scheme = std::make_shared<typename ContextGeneratorType<Element>::PublicKeyEncryptionScheme>();
    scheme->ParamsGen(
        params,
        2 * parameters.GetRingDim(),
        parameters.GetMultiplicativeDepth() + 1,
        parameters.GetScalingFactorBits(),
        parameters.GetRelinWindow(),
        parameters.GetMode(),
        parameters.GetKeySwitchTechnique(),
        parameters.GetFirstModSize(),
        parameters.GetRescalingTechnique(),
        numLargeDigits);

    auto cc = ContextGeneratorType<Element>::Factory::GetContext(params, scheme);
    cc->setSchemeId("CKKS");  // TODO: do we need this?? (dsuponit) we could just "return DltCryptoContextFactory<Element>::GetContext(params, schemeCKKS);"
    return cc;
}
}  // namespace lbcrypto

#endif // _GEN_CRYPTOCONTEXT_CKKS_INTERNAL_H_

