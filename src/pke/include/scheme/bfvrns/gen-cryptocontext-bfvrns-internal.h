// @file gen-cryptocontext-bfvrns-internal.h -- API to generate BFVRNS crypto context. MUST NOT (!) be used without a wrapper function.
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

#ifndef _GEN_CRYPTOCONTEXT_BFVRNS_INTERNAL_H_
#define _GEN_CRYPTOCONTEXT_BFVRNS_INTERNAL_H_

#include "encoding/encodingparams.h"

namespace lbcrypto {

// forward declarations (don't include headers as compilation fails when you do)
template <typename T>
class CCParams;

template<template<typename> typename ContextGeneratorType, typename Element>
typename ContextGeneratorType<Element>::ContextType genCryptoContextBFVRNSInternal(const CCParams<ContextGeneratorType<Element>>& parameters) {

    using ParmType = typename Element::Params;
    using IntType = typename Element::Integer;

	auto ep = std::make_shared<ParmType>(0, IntType(0), IntType(0));
	EncodingParams encodingParams(
		std::make_shared<EncodingParamsImpl>(parameters.GetPlaintextModulus(), parameters.GetBatchSize()));
	// use rootHermiteFactor as securityLevel if it is set
	auto params = parameters.IsValidRootHermiteFactor() ?
		std::make_shared<typename ContextGeneratorType<Element>::CryptoParams>(
			ep,
			encodingParams,
			parameters.GetStandardDeviation(),
			parameters.GetAssuranceMeasure(),
			parameters.GetRootHermiteFactor(),  // TODO (dsuponit): find a way to get securityLevel of different types
			parameters.GetRelinWindow(),
			parameters.GetMode(),
			parameters.GetDepth(),
			parameters.GetMaxDepth()) :
		std::make_shared<typename ContextGeneratorType<Element>::CryptoParams>(
			ep,
			encodingParams,
			parameters.GetStandardDeviation(),
			parameters.GetAssuranceMeasure(),
			parameters.GetSecurityLevel(),
			parameters.GetRelinWindow(),
			parameters.GetMode(),
			parameters.GetDepth(),
			parameters.GetMaxDepth());

	auto scheme = std::make_shared<typename ContextGeneratorType<Element>::PublicKeyEncryptionScheme>();
	scheme->ParamsGen(
		params,
		parameters.GetEvalAddCount(),
		parameters.GetEvalMultCount(),
		parameters.GetKeySwitchCount(),
		parameters.GetFirstModSize(),
		parameters.GetRingDim());

	return ContextGeneratorType<Element>::Factory::GetContext(params, scheme);
};

}  // namespace lbcrypto

#endif // _GEN_CRYPTOCONTEXT_BFVRNS_INTERNAL_H_

