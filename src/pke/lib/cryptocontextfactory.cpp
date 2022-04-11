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

#ifndef LBCRYPTO_CRYPTO_CRYPTOCONTEXTFACTORY_C
#define LBCRYPTO_CRYPTO_CRYPTOCONTEXTFACTORY_C

#include "cryptocontext.h"
#include "cryptocontextfactory.h"

namespace lbcrypto {

template <typename Element>
std::vector<CryptoContext<Element>> CryptoContextFactory<Element>::AllContexts;

template <typename Element>
void CryptoContextFactory<Element>::ReleaseAllContexts() {
  AllContexts.clear();
}

template <typename Element>
int CryptoContextFactory<Element>::GetContextCount() {
  return AllContexts.size();
}

template <typename Element>
CryptoContext<Element> CryptoContextFactory<Element>::GetSingleContext() {
  if (GetContextCount() == 1) return AllContexts[0];
  PALISADE_THROW(config_error, "More than one context");
}

template <typename Element>
CryptoContext<Element> CryptoContextFactory<Element>::GetContext(
    std::shared_ptr<CryptoParametersBase<Element>> params,
    std::shared_ptr<SchemeBase<Element>> scheme,
    const std::string& schemeId) {
  for (CryptoContext<Element> cc : CryptoContextFactory<Element>::AllContexts) {
    if (*cc->GetScheme().get() == *scheme.get() &&
        *cc->GetCryptoParameters().get() == *params.get()) {
      return cc;
    }
  }

  CryptoContext<Element> cc(
      std::make_shared<CryptoContextImpl<Element>>(params, scheme, schemeId));
  AllContexts.push_back(cc);

  if (cc->GetEncodingParams()->GetPlaintextRootOfUnity() != 0) {
    PackedEncoding::SetParams(cc->GetCyclotomicOrder(),
                              cc->GetEncodingParams());
  }

  return cc;
}

template <typename Element>
CryptoContext<Element> CryptoContextFactory<Element>::GetContextForPointer(
    CryptoContextImpl<Element>* cc) {
  for (CryptoContext<Element> ctx : AllContexts) {
    if (ctx.get() == cc) return ctx;
  }
  return 0;
}

template <typename T>
const std::vector<CryptoContext<T>>& CryptoContextFactory<T>::GetAllContexts() {
  return AllContexts;
}

// factory methods for the different schemes

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBFVrns(
    const PlaintextModulus plaintextModulus, float securityLevel, float dist,
    unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches,
    MODE mode, int maxDepth, uint32_t relinWindow, size_t dcrtBits,
    uint32_t n, MultiplicationTechnique multTech) {
  int nonZeroCount = 0;

  if (numAdds > 0) nonZeroCount++;
  if (numMults > 0) nonZeroCount++;
  if (numKeyswitches > 0) nonZeroCount++;

  if (nonZeroCount > 1)
    PALISADE_THROW(config_error,
                   "only one of (numAdds,numMults,numKeyswitches) can be "
                   "nonzero in BFVrns context constructor");

  auto ep = std::make_shared<ParmType>(0, IntType(0), IntType(0));

  auto params = std::make_shared<CryptoParametersBFVRNS>(
      ep,
      EncodingParams(std::make_shared<EncodingParamsImpl>(plaintextModulus)),
      dist, 36.0, securityLevel, relinWindow, mode, 1, maxDepth);
  // for BFV scheme noise scale is always set to 1
  params->SetNoiseScale(1);

  auto scheme = std::make_shared<SchemeBFVRNS>();
  scheme->SetKeySwitchingTechnique(BV);

  scheme->ParamsGenBFVRNS(params, numAdds, numMults, numKeyswitches, dcrtBits, n,
      BV, FIXEDMANUAL, STANDARD, multTech);

  return CryptoContextFactory<T>::GetContext(params, scheme);
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBFVrns(
    const PlaintextModulus plaintextModulus, SecurityLevel securityLevel,
    float dist, unsigned int numAdds, unsigned int numMults,
    unsigned int numKeyswitches, MODE mode, int maxDepth, uint32_t relinWindow,
    size_t dcrtBits, uint32_t n, MultiplicationTechnique multTech) {
  EncodingParams encodingParams(
      std::make_shared<EncodingParamsImpl>(plaintextModulus));

  return genCryptoContextBFVrns(encodingParams, securityLevel, dist, numAdds,
                                numMults, numKeyswitches, mode, maxDepth,
                                relinWindow, dcrtBits, n, multTech);
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBFVrns(
    EncodingParams encodingParams, float securityLevel, float dist,
    unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches,
    MODE mode, int maxDepth, uint32_t relinWindow, size_t dcrtBits,
    uint32_t n, MultiplicationTechnique multTech) {
  int nonZeroCount = 0;

  if (numAdds > 0) nonZeroCount++;
  if (numMults > 0) nonZeroCount++;
  if (numKeyswitches > 0) nonZeroCount++;

  if (nonZeroCount > 1)
    PALISADE_THROW(config_error,
                   "only one of (numAdds,numMults,numKeyswitches) can be "
                   "nonzero in BFVrns context constructor");

  auto ep = std::make_shared<ParmType>(0, IntType(0), IntType(0));

  auto params = std::make_shared< CryptoParametersBFVRNS>(
      ep, encodingParams, dist, 36.0, securityLevel, relinWindow, mode, 1,
      maxDepth);
  // for BFV scheme noise scale is always set to 1
  params->SetNoiseScale(1);

  auto scheme = std::make_shared<SchemeBFVRNS>();
  scheme->SetKeySwitchingTechnique(BV);

  scheme->ParamsGenBFVRNS(params, numAdds, numMults, numKeyswitches, dcrtBits, n,
      BV, FIXEDMANUAL, STANDARD, multTech);

  return CryptoContextFactory<T>::GetContext(params, scheme);
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBFVrns(
    EncodingParams encodingParams, SecurityLevel securityLevel, float dist,
    unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches,
    MODE mode, int maxDepth, uint32_t relinWindow, size_t dcrtBits,
    uint32_t n, MultiplicationTechnique multTech) {
  int nonZeroCount = 0;

  if (numAdds > 0) nonZeroCount++;
  if (numMults > 0) nonZeroCount++;
  if (numKeyswitches > 0) nonZeroCount++;

  if (nonZeroCount > 1)
    PALISADE_THROW(config_error,
                   "only one of (numAdds,numMults,numKeyswitches) can be "
                   "nonzero in BFVrns context constructor");

  auto ep = std::make_shared<ParmType>(0, IntType(0), IntType(0));

  auto params = std::make_shared< CryptoParametersBFVRNS>(
      ep, encodingParams, dist, 36.0, securityLevel, relinWindow, mode, 1,
      maxDepth);
  // for BFV scheme noise scale is always set to 1
  params->SetNoiseScale(1);

  auto scheme = std::make_shared<SchemeBFVRNS>();
  scheme->SetKeySwitchingTechnique(BV);

  scheme->ParamsGenBFVRNS(params, numAdds, numMults, numKeyswitches, dcrtBits, n,
      BV, FIXEDMANUAL, STANDARD, multTech);

  return CryptoContextFactory<T>::GetContext(params, scheme);
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBGVrns(
    std::shared_ptr<ParmType> ep, const PlaintextModulus plaintextmodulus,
    usint relinWindow, float stDev, MODE mode, int depth, int maxDepth,
    enum KeySwitchTechnique ksTech, enum RescalingTechnique rsTech) {
  auto params = std::make_shared<CryptoParametersBGVRNS>(
      ep, plaintextmodulus, stDev,
      9,            // assuranceMeasure,
      1.006,        // securityLevel,
      relinWindow,  // Relinearization Window
      mode, depth, maxDepth, ksTech, rsTech);
  // for BGV scheme noise scale is always set to plaintext modulus
  params->SetNoiseScale(params->GetPlaintextModulus());

  params->PrecomputeCRTTables(ksTech);

  auto scheme = std::make_shared<SchemeBGVRNS>();
  scheme->SetKeySwitchingTechnique(ksTech);

  auto cc = CryptoContextFactory<T>::GetContext(params, scheme);

  cc->setSchemeId("BGVRNS");

  return cc;
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBGVrns(
    std::shared_ptr<ParmType> ep, EncodingParams encodingParams, usint relinWindow,
    float stDev, MODE mode, int depth, int maxDepth,
    enum KeySwitchTechnique ksTech, enum RescalingTechnique rsTech) {
  auto params = std::make_shared<CryptoParametersBGVRNS>(
      ep, encodingParams, stDev,
      9,            // assuranceMeasure,
      1.006,        // securityLevel,
      relinWindow,  // Relinearization Window
      mode, depth, maxDepth, ksTech, rsTech);
  // for BGV scheme noise scale is always set to plaintext modulus
  params->SetNoiseScale(params->GetPlaintextModulus());

  params->PrecomputeCRTTables(ksTech);

  auto scheme = std::make_shared<SchemeBGVRNS>();
  scheme->SetKeySwitchingTechnique(ksTech);

  auto cc = CryptoContextFactory<T>::GetContext(params, scheme);

  cc->setSchemeId("BGVRNS");

  return cc;
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBGVrnsWithParamsGen(
    usint cyclOrder, usint numPrimes, usint ptm, usint relinWindow, MODE mode,
    int depth, int maxDepth, enum KeySwitchTechnique ksTech, usint firstModSize,
    usint dcrtBits, uint32_t numLargeDigits, usint batchSize,
    enum RescalingTechnique rsTech, usint multihopQBound) {
  float stdDev = 3.2;

  auto ep = std::make_shared<ParmType>(0, IntType(0), IntType(0));

  EncodingParams encodingParams(std::make_shared<EncodingParamsImpl>(ptm));
  encodingParams->SetBatchSize(batchSize);

  auto params = std::make_shared<CryptoParametersBGVRNS>(
      ep, encodingParams, stdDev,
      9,            // assuranceMeasure,
      1.006,        // securityLevel,
      relinWindow,  // Relinearization Window
      mode, depth, maxDepth, ksTech, rsTech);
  // for BGV scheme noise scale is always set to plaintext modulus
  params->SetNoiseScale(params->GetPlaintextModulus());

  auto schemeBGVrns = std::make_shared<SchemeBGVRNS>();
  schemeBGVrns->SetKeySwitchingTechnique(ksTech);

  schemeBGVrns->ParamsGenBGVRNS(params, cyclOrder, ptm, numPrimes, relinWindow, mode,
                          firstModSize, dcrtBits, numLargeDigits,
                          multihopQBound, ksTech);

  auto cc = CryptoContextFactory<T>::GetContext(params, schemeBGVrns);

  cc->setSchemeId("BGVRNS");

  return cc;
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBGVrns(
    usint multiplicativeDepth, usint ptm, SecurityLevel stdLevel, float stdDev,
    int maxDepth, MODE mode, enum KeySwitchTechnique ksTech, usint ringDim,
    uint32_t numLargeDigits, usint firstModSize, usint dcrtBits,
    usint relinWindow, usint batchSize, enum RescalingTechnique rsTech,
    usint multihopQBound) {
  auto ep = std::make_shared<ParmType>(0, IntType(0), IntType(0));

  EncodingParams encodingParams(std::make_shared<EncodingParamsImpl>(ptm));
  encodingParams->SetBatchSize(batchSize);

  auto params = std::make_shared<CryptoParametersBGVRNS>(
      ep, encodingParams, stdDev,
      9,            // assuranceMeasure,
      1.006,        // securityLevel,
      relinWindow,  // Relinearization Window
      mode,
      1,  // depth
      maxDepth, ksTech, rsTech);
  // for BGV scheme noise scale is always set to plaintext modulus
  params->SetNoiseScale(params->GetPlaintextModulus());

  params->SetStdLevel(stdLevel);

  // Setting the default value for numLargeDigits for HYBRID
  if (numLargeDigits == 0) {      // Choose one of the default values
    if (multiplicativeDepth > 3)  // If more than 4 towers, use 3 digits
      numLargeDigits = 3;
    else if ((multiplicativeDepth >= 1) &&
             (multiplicativeDepth <= 3))  // If 2, 3 or 4 towers, use 2 digits
      numLargeDigits = 2;
    else  // if there is only 1 tower, use one digit
      numLargeDigits = 1;
  }

  auto schemeBGVrns = std::make_shared<SchemeBGVRNS>();
  schemeBGVrns->SetKeySwitchingTechnique(ksTech);

  schemeBGVrns->ParamsGenBGVRNS(params, 2 * ringDim, ptm, multiplicativeDepth + 1,
                          relinWindow, mode, firstModSize, dcrtBits,
                          numLargeDigits, multihopQBound, ksTech, rsTech);

  auto cc = CryptoContextFactory<T>::GetContext(params, schemeBGVrns);

  cc->setSchemeId("BGVRNS");

  return cc;
}


template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextCKKSrns(
    std::shared_ptr<ParmType> ep, EncodingParams encodingParams, usint relinWindow,
    float stDev, MODE mode, int depth, int maxDepth, KeySwitchTechnique ksTech,
    RescalingTechnique rsTech) {
#if NATIVEINT == 128
  if (rsTech == FLEXIBLEAUTO)
    PALISADE_THROW(
        config_error,
        "128-bit CKKS is not supported for the FLEXIBLEAUTO method.");
#endif
  auto params = std::make_shared<CryptoParametersCKKSRNS>(
      ep, encodingParams, stDev,
      9,            // assuranceMeasure,
      1.006,        // securityLevel,
      relinWindow,  // Relinearization Window
      mode, depth, maxDepth);
  // for CKKS scheme noise scale is always set to 1
  params->SetNoiseScale(1);

  params->PrecomputeCRTTables(ksTech, rsTech);

  auto scheme = std::make_shared<SchemeCKKSRNS>();
  scheme->SetKeySwitchingTechnique(ksTech);

  auto cc = CryptoContextFactory<T>::GetContext(params, scheme);

  cc->setSchemeId("CKKSRNS");

  return cc;
}

}  // namespace lbcrypto

#endif
