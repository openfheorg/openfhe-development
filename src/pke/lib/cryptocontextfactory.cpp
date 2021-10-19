// @file cryptocontextfactory.cpp -- Factory implementation
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

#include "cryptocontext.h"
#include "utils/serial.h"

namespace lbcrypto {

template <typename Element>
vector<CryptoContext<Element>> CryptoContextFactory<Element>::AllContexts;

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
    shared_ptr<LPCryptoParameters<Element>> params,
    shared_ptr<LPPublicKeyEncryptionScheme<Element>> scheme,
    const string& schemeId) {
  for (CryptoContext<Element> cc : CryptoContextFactory<Element>::AllContexts) {
    if (*cc->GetEncryptionAlgorithm().get() == *scheme.get() &&
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
const vector<CryptoContext<T>>& CryptoContextFactory<T>::GetAllContexts() {
  return AllContexts;
}

// factory methods for the different schemes

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBFV(
    shared_ptr<ParmType> ep, const PlaintextModulus plaintextmodulus,
    usint relinWindow, float stDev, const std::string& delta, MODE mode,
    const std::string& bigmodulus, const std::string& bigrootofunity, int depth,
    int assuranceMeasure, float securityLevel, const std::string& bigmodulusarb,
    const std::string& bigrootofunityarb, int maxDepth) {
  auto params = std::make_shared<LPCryptoParametersBFV<T>>(
      ep, plaintextmodulus, stDev, assuranceMeasure, securityLevel, relinWindow,
      IntType(delta), mode, IntType(bigmodulus), IntType(bigrootofunity),
      IntType(bigmodulusarb), IntType(bigrootofunityarb), depth, maxDepth);

  auto scheme = std::make_shared<LPPublicKeyEncryptionSchemeBFV<T>>();

  return CryptoContextFactory<T>::GetContext(params, scheme);
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBFV(
    shared_ptr<ParmType> ep, EncodingParams encodingParams, usint relinWindow,
    float stDev, const std::string& delta, MODE mode,
    const std::string& bigmodulus, const std::string& bigrootofunity, int depth,
    int assuranceMeasure, float securityLevel, const std::string& bigmodulusarb,
    const std::string& bigrootofunityarb, int maxDepth) {
  auto params = std::make_shared<LPCryptoParametersBFV<T>>(
      ep, encodingParams, stDev, assuranceMeasure, securityLevel, relinWindow,
      IntType(delta), mode, IntType(bigmodulus), IntType(bigrootofunity),
      IntType(bigmodulusarb), IntType(bigrootofunityarb), depth, maxDepth);

  auto scheme = std::make_shared<LPPublicKeyEncryptionSchemeBFV<T>>();

  return CryptoContextFactory<T>::GetContext(params, scheme);
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBFV(
    const PlaintextModulus plaintextModulus, float securityLevel,
    usint relinWindow, float dist, unsigned int numAdds, unsigned int numMults,
    unsigned int numKeyswitches, MODE mode, int maxDepth, uint32_t n) {
  EncodingParams encodingParams(
      std::make_shared<EncodingParamsImpl>(plaintextModulus));

  return genCryptoContextBFV(encodingParams, securityLevel, relinWindow, dist,
                             numAdds, numMults, numKeyswitches, mode, maxDepth,
                             n);
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBFV(
    EncodingParams encodingParams, float securityLevel, usint relinWindow,
    float dist, unsigned int numAdds, unsigned int numMults,
    unsigned int numKeyswitches, MODE mode, int maxDepth, uint32_t n) {
  int nonZeroCount = 0;

  if (numAdds > 0) nonZeroCount++;
  if (numMults > 0) nonZeroCount++;
  if (numKeyswitches > 0) nonZeroCount++;

  if (nonZeroCount > 1)
    PALISADE_THROW(config_error,
                   "only one of (numAdds,numMults,numKeyswitches) can be "
                   "nonzero in BFV context constructor");

  auto ep = std::make_shared<ParmType>(0, IntType(0), IntType(0));

  auto params = std::make_shared<LPCryptoParametersBFV<T>>(
      ep, encodingParams, dist, 36.0, securityLevel, relinWindow, IntType(0),
      mode, IntType(0), IntType(0), IntType(0), IntType(0), 1, maxDepth);

  auto scheme = std::make_shared<LPPublicKeyEncryptionSchemeBFV<T>>();

  scheme->ParamsGen(params, numAdds, numMults, numKeyswitches, n);

  return CryptoContextFactory<T>::GetContext(params, scheme);
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBFV(
    EncodingParams encodingParams, SecurityLevel securityLevel,
    usint relinWindow, float dist, unsigned int numAdds, unsigned int numMults,
    unsigned int numKeyswitches, MODE mode, int maxDepth, uint32_t n) {
  int nonZeroCount = 0;

  if (numAdds > 0) nonZeroCount++;
  if (numMults > 0) nonZeroCount++;
  if (numKeyswitches > 0) nonZeroCount++;

  if (nonZeroCount > 1)
    PALISADE_THROW(config_error,
                   "only one of (numAdds,numMults,numKeyswitches) can be "
                   "nonzero in BFV context constructor");

  auto ep = std::make_shared<ParmType>(0, IntType(0), IntType(0));

  auto params = std::make_shared<LPCryptoParametersBFV<T>>(
      ep, encodingParams, dist, 36.0, securityLevel, relinWindow, IntType(0),
      mode, IntType(0), IntType(0), IntType(0), IntType(0), 1, maxDepth);

  auto scheme = std::make_shared<LPPublicKeyEncryptionSchemeBFV<T>>();

  scheme->ParamsGen(params, numAdds, numMults, numKeyswitches, n);

  return CryptoContextFactory<T>::GetContext(params, scheme);
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBFVrns(
    const PlaintextModulus plaintextModulus, float securityLevel, float dist,
    unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches,
    MODE mode, int maxDepth, uint32_t relinWindow, size_t dcrtBits,
    uint32_t n) {
  int nonZeroCount = 0;

  if (numAdds > 0) nonZeroCount++;
  if (numMults > 0) nonZeroCount++;
  if (numKeyswitches > 0) nonZeroCount++;

  if (nonZeroCount > 1)
    PALISADE_THROW(config_error,
                   "only one of (numAdds,numMults,numKeyswitches) can be "
                   "nonzero in BFVrns context constructor");

  auto ep = std::make_shared<ParmType>(0, IntType(0), IntType(0));

  auto params = std::make_shared<LPCryptoParametersBFVrns<T>>(
      ep,
      EncodingParams(std::make_shared<EncodingParamsImpl>(plaintextModulus)),
      dist, 36.0, securityLevel, relinWindow, mode, 1, maxDepth);
  auto scheme = std::make_shared<LPPublicKeyEncryptionSchemeBFVrns<T>>();

  scheme->ParamsGen(params, numAdds, numMults, numKeyswitches, dcrtBits, n);

  return CryptoContextFactory<T>::GetContext(params, scheme);
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBFVrns(
    const PlaintextModulus plaintextModulus, SecurityLevel securityLevel,
    float dist, unsigned int numAdds, unsigned int numMults,
    unsigned int numKeyswitches, MODE mode, int maxDepth, uint32_t relinWindow,
    size_t dcrtBits, uint32_t n) {
  EncodingParams encodingParams(
      std::make_shared<EncodingParamsImpl>(plaintextModulus));

  return genCryptoContextBFVrns(encodingParams, securityLevel, dist, numAdds,
                                numMults, numKeyswitches, mode, maxDepth,
                                relinWindow, dcrtBits, n);
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBFVrns(
    EncodingParams encodingParams, float securityLevel, float dist,
    unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches,
    MODE mode, int maxDepth, uint32_t relinWindow, size_t dcrtBits,
    uint32_t n) {
  int nonZeroCount = 0;

  if (numAdds > 0) nonZeroCount++;
  if (numMults > 0) nonZeroCount++;
  if (numKeyswitches > 0) nonZeroCount++;

  if (nonZeroCount > 1)
    PALISADE_THROW(config_error,
                   "only one of (numAdds,numMults,numKeyswitches) can be "
                   "nonzero in BFVrns context constructor");

  auto ep = std::make_shared<ParmType>(0, IntType(0), IntType(0));

  auto params = std::make_shared<LPCryptoParametersBFVrns<T>>(
      ep, encodingParams, dist, 36.0, securityLevel, relinWindow, mode, 1,
      maxDepth);

  auto scheme = std::make_shared<LPPublicKeyEncryptionSchemeBFVrns<T>>();

  scheme->ParamsGen(params, numAdds, numMults, numKeyswitches, dcrtBits, n);

  return CryptoContextFactory<T>::GetContext(params, scheme);
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBFVrns(
    EncodingParams encodingParams, SecurityLevel securityLevel, float dist,
    unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches,
    MODE mode, int maxDepth, uint32_t relinWindow, size_t dcrtBits,
    uint32_t n) {
  int nonZeroCount = 0;

  if (numAdds > 0) nonZeroCount++;
  if (numMults > 0) nonZeroCount++;
  if (numKeyswitches > 0) nonZeroCount++;

  if (nonZeroCount > 1)
    PALISADE_THROW(config_error,
                   "only one of (numAdds,numMults,numKeyswitches) can be "
                   "nonzero in BFVrns context constructor");

  auto ep = std::make_shared<ParmType>(0, IntType(0), IntType(0));

  auto params = std::make_shared<LPCryptoParametersBFVrns<T>>(
      ep, encodingParams, dist, 36.0, securityLevel, relinWindow, mode, 1,
      maxDepth);

  auto scheme = std::make_shared<LPPublicKeyEncryptionSchemeBFVrns<T>>();

  scheme->ParamsGen(params, numAdds, numMults, numKeyswitches, dcrtBits, n);

  return CryptoContextFactory<T>::GetContext(params, scheme);
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBFVrnsB(
    const PlaintextModulus plaintextModulus, float securityLevel, float dist,
    unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches,
    MODE mode, int maxDepth, uint32_t relinWindow, size_t dcrtBits,
    uint32_t n) {
  int nonZeroCount = 0;

  if (numAdds > 0) nonZeroCount++;
  if (numMults > 0) nonZeroCount++;
  if (numKeyswitches > 0) nonZeroCount++;

  if (nonZeroCount > 1)
    PALISADE_THROW(config_error,
                   "only one of (numAdds,numMults,numKeyswitches) can be "
                   "nonzero in BFVrnsB context constructor");

  auto ep = std::make_shared<ParmType>(0, IntType(0), IntType(0));

  auto params = std::make_shared<LPCryptoParametersBFVrnsB<T>>(
      ep,
      EncodingParams(std::make_shared<EncodingParamsImpl>(plaintextModulus)),
      dist, 36.0, securityLevel, relinWindow, mode, 1, maxDepth);
  auto scheme = std::make_shared<LPPublicKeyEncryptionSchemeBFVrnsB<T>>();

  scheme->ParamsGen(params, numAdds, numMults, numKeyswitches, dcrtBits, n);

  return CryptoContextFactory<T>::GetContext(params, scheme);
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBFVrnsB(
    const PlaintextModulus plaintextModulus, SecurityLevel securityLevel,
    float dist, unsigned int numAdds, unsigned int numMults,
    unsigned int numKeyswitches, MODE mode, int maxDepth, uint32_t relinWindow,
    size_t dcrtBits, uint32_t n) {
  EncodingParams encodingParams(
      std::make_shared<EncodingParamsImpl>(plaintextModulus));

  return genCryptoContextBFVrnsB(encodingParams, securityLevel, dist, numAdds,
                                 numMults, numKeyswitches, mode, maxDepth,
                                 relinWindow, dcrtBits, n);
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBFVrnsB(
    EncodingParams encodingParams, float securityLevel, float dist,
    unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches,
    MODE mode, int maxDepth, uint32_t relinWindow, size_t dcrtBits,
    uint32_t n) {
  int nonZeroCount = 0;

  if (numAdds > 0) nonZeroCount++;
  if (numMults > 0) nonZeroCount++;
  if (numKeyswitches > 0) nonZeroCount++;

  if (nonZeroCount > 1)
    PALISADE_THROW(config_error,
                   "only one of (numAdds,numMults,numKeyswitches) can be "
                   "nonzero in BFVrnsB context constructor");

  auto ep = std::make_shared<ParmType>(0, IntType(0), IntType(0));

  auto params = std::make_shared<LPCryptoParametersBFVrnsB<T>>(
      ep, encodingParams, dist, 36.0, securityLevel, relinWindow, mode, 1,
      maxDepth);

  auto scheme = std::make_shared<LPPublicKeyEncryptionSchemeBFVrnsB<T>>();

  scheme->ParamsGen(params, numAdds, numMults, numKeyswitches, dcrtBits, n);

  return CryptoContextFactory<T>::GetContext(params, scheme);
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBFVrnsB(
    EncodingParams encodingParams, SecurityLevel securityLevel, float dist,
    unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches,
    MODE mode, int maxDepth, uint32_t relinWindow, size_t dcrtBits,
    uint32_t n) {
  int nonZeroCount = 0;

  if (numAdds > 0) nonZeroCount++;
  if (numMults > 0) nonZeroCount++;
  if (numKeyswitches > 0) nonZeroCount++;

  if (nonZeroCount > 1)
    PALISADE_THROW(config_error,
                   "only one of (numAdds,numMults,numKeyswitches) can be "
                   "nonzero in BFVrnsB context constructor");

  auto ep = std::make_shared<ParmType>(0, IntType(0), IntType(0));

  auto params = std::make_shared<LPCryptoParametersBFVrnsB<T>>(
      ep, encodingParams, dist, 36.0, securityLevel, relinWindow, mode, 1,
      maxDepth);

  auto scheme = std::make_shared<LPPublicKeyEncryptionSchemeBFVrnsB<T>>();

  scheme->ParamsGen(params, numAdds, numMults, numKeyswitches, dcrtBits, n);

  return CryptoContextFactory<T>::GetContext(params, scheme);
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextCKKS(
    shared_ptr<ParmType> ep, const PlaintextModulus plaintextmodulus,
    usint relinWindow, float stDev, MODE mode, int depth, int maxDepth,
    KeySwitchTechnique ksTech, RescalingTechnique rsTech) {
#if NATIVEINT == 128
  if (rsTech == EXACTRESCALE)
    PALISADE_THROW(
        config_error,
        "128-bit CKKS is not supported for the EXACTRESCALE method.");
#endif
  auto params = std::make_shared<LPCryptoParametersCKKS<T>>(
      ep, plaintextmodulus, stDev,
      9,            // assuranceMeasure,
      1.006,        // securityLevel,
      relinWindow,  // Relinearization Window
      mode, depth, maxDepth);

  params->PrecomputeCRTTables(ksTech, rsTech);

  auto scheme = std::make_shared<LPPublicKeyEncryptionSchemeCKKS<T>>();

  auto cc = CryptoContextFactory<T>::GetContext(params, scheme);

  cc->setSchemeId("CKKS");

  return cc;
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextCKKS(
    shared_ptr<ParmType> ep, EncodingParams encodingParams, usint relinWindow,
    float stDev, MODE mode, int depth, int maxDepth, KeySwitchTechnique ksTech,
    RescalingTechnique rsTech) {
#if NATIVEINT == 128
  if (rsTech == EXACTRESCALE)
    PALISADE_THROW(
        config_error,
        "128-bit CKKS is not supported for the EXACTRESCALE method.");
#endif
  auto params = std::make_shared<LPCryptoParametersCKKS<T>>(
      ep, encodingParams, stDev,
      9,            // assuranceMeasure,
      1.006,        // securityLevel,
      relinWindow,  // Relinearization Window
      mode, depth, maxDepth);

  params->PrecomputeCRTTables(ksTech, rsTech);

  auto scheme = std::make_shared<LPPublicKeyEncryptionSchemeCKKS<T>>();

  auto cc = CryptoContextFactory<T>::GetContext(params, scheme);

  cc->setSchemeId("CKKS");

  return cc;
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBGVrns(
    shared_ptr<ParmType> ep, const PlaintextModulus plaintextmodulus,
    usint relinWindow, float stDev, MODE mode, int depth, int maxDepth,
    enum KeySwitchTechnique ksTech, enum ModSwitchMethod msMethod) {
  auto params = std::make_shared<LPCryptoParametersBGVrns<T>>(
      ep, plaintextmodulus, stDev,
      9,            // assuranceMeasure,
      1.006,        // securityLevel,
      relinWindow,  // Relinearization Window
      mode, depth, maxDepth, ksTech, msMethod);

  params->PrecomputeCRTTables(ksTech);

  auto scheme = std::make_shared<LPPublicKeyEncryptionSchemeBGVrns<T>>();

  auto cc = CryptoContextFactory<T>::GetContext(params, scheme);

  cc->setSchemeId("BGVrns");

  return cc;
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBGVrns(
    shared_ptr<ParmType> ep, EncodingParams encodingParams, usint relinWindow,
    float stDev, MODE mode, int depth, int maxDepth,
    enum KeySwitchTechnique ksTech, enum ModSwitchMethod msMethod) {
  auto params = std::make_shared<LPCryptoParametersBGVrns<T>>(
      ep, encodingParams, stDev,
      9,            // assuranceMeasure,
      1.006,        // securityLevel,
      relinWindow,  // Relinearization Window
      mode, depth, maxDepth, ksTech, msMethod);

  params->PrecomputeCRTTables(ksTech);

  auto scheme = std::make_shared<LPPublicKeyEncryptionSchemeBGVrns<T>>();

  auto cc = CryptoContextFactory<T>::GetContext(params, scheme);

  cc->setSchemeId("BGVrns");

  return cc;
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBGVrnsWithParamsGen(
    usint cyclOrder, usint numPrimes, usint ptm, usint relinWindow, MODE mode,
    int depth, int maxDepth, enum KeySwitchTechnique ksTech, usint firstModSize,
    usint dcrtBits, uint32_t numLargeDigits, usint batchSize,
    enum ModSwitchMethod msMethod) {
  float stdDev = 3.2;

  auto ep = std::make_shared<ParmType>(0, IntType(0), IntType(0));

  EncodingParams encodingParams(std::make_shared<EncodingParamsImpl>(ptm));
  encodingParams->SetBatchSize(batchSize);

  auto params = std::make_shared<LPCryptoParametersBGVrns<T>>(
      ep, encodingParams, stdDev,
      9,            // assuranceMeasure,
      1.006,        // securityLevel,
      relinWindow,  // Relinearization Window
      mode, depth, maxDepth, ksTech, msMethod);

  auto schemeBGVrns = std::make_shared<LPPublicKeyEncryptionSchemeBGVrns<T>>();
  schemeBGVrns->ParamsGen(params, cyclOrder, ptm, numPrimes, relinWindow, mode,
                          ksTech, firstModSize, dcrtBits, numLargeDigits);

  auto cc = CryptoContextFactory<T>::GetContext(params, schemeBGVrns);

  cc->setSchemeId("BGVrns");

  return cc;
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextBGVrns(
    usint multiplicativeDepth, usint ptm, SecurityLevel stdLevel, float stdDev,
    int maxDepth, MODE mode, enum KeySwitchTechnique ksTech, usint ringDim,
    uint32_t numLargeDigits, usint firstModSize, usint dcrtBits,
    usint relinWindow, usint batchSize, ModSwitchMethod msMethod) {
  auto ep = std::make_shared<ParmType>(0, IntType(0), IntType(0));

  EncodingParams encodingParams(std::make_shared<EncodingParamsImpl>(ptm));
  encodingParams->SetBatchSize(batchSize);

  auto params = std::make_shared<LPCryptoParametersBGVrns<T>>(
      ep, encodingParams, stdDev,
      9,            // assuranceMeasure,
      1.006,        // securityLevel,
      relinWindow,  // Relinearization Window
      mode,
      1,  // depth
      maxDepth, ksTech, msMethod);

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

  auto schemeBGVrns = std::make_shared<LPPublicKeyEncryptionSchemeBGVrns<T>>();
  schemeBGVrns->ParamsGen(params, 2 * ringDim, ptm, multiplicativeDepth + 1,
                          relinWindow, mode, ksTech, firstModSize, dcrtBits,
                          numLargeDigits);

  auto cc = CryptoContextFactory<T>::GetContext(params, schemeBGVrns);

  cc->setSchemeId("BGVrns");

  return cc;
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextCKKSWithParamsGen(
    usint cyclOrder, usint numPrimes, usint scaleExp, usint relinWindow,
    usint batchSize, MODE mode, int depth, int maxDepth, usint firstModSize,
    KeySwitchTechnique ksTech, RescalingTechnique rsTech,
    uint32_t numLargeDigits) {
#if NATIVEINT == 128
  if (rsTech == EXACTRESCALE)
    PALISADE_THROW(
        config_error,
        "128-bit CKKS is not supported for the EXACTRESCALE method.");
#endif

  uint64_t p = scaleExp;
  float stdDev = 3.19;

  auto ep = std::make_shared<ParmType>(0, IntType(0), IntType(0));

  EncodingParams encodingParams(std::make_shared<EncodingParamsImpl>(p));
  encodingParams->SetBatchSize(batchSize);

  auto params = std::make_shared<LPCryptoParametersCKKS<T>>(
      ep, encodingParams, stdDev,
      9,            // assuranceMeasure,
      1.006,        // securityLevel,
      relinWindow,  // Relinearization Window
      mode, depth, maxDepth);

  auto scheme = std::make_shared<LPPublicKeyEncryptionSchemeCKKS<T>>();
  scheme->ParamsGen(params, cyclOrder, numPrimes, scaleExp, relinWindow, mode,
                    ksTech, firstModSize, rsTech, numLargeDigits);

  auto cc = CryptoContextFactory<T>::GetContext(params, scheme);

  cc->setSchemeId("CKKS");

  return cc;
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextCKKS(
    usint multiplicativeDepth, usint scalingFactorBits, usint batchSize,
    SecurityLevel stdLevel, usint ringDim, RescalingTechnique rsTech,
    KeySwitchTechnique ksTech, uint32_t numLargeDigits, int maxDepth,
    usint firstModSize, usint relinWindow, MODE mode) {
#if NATIVEINT == 128
  if (rsTech == EXACTRESCALE)
    PALISADE_THROW(
        config_error,
        "128-bit CKKS is not supported for the EXACTRESCALE method.");
#endif

  float stdDev = 3.19;

  auto ep = std::make_shared<ParmType>(0, IntType(0), IntType(0));

  // In CKKS, the plaintext modulus is equal to the scaling factor.
  EncodingParams encodingParams(
      std::make_shared<EncodingParamsImpl>(scalingFactorBits));
  encodingParams->SetBatchSize(batchSize);

  auto params = std::make_shared<LPCryptoParametersCKKS<T>>(
      ep, encodingParams, stdDev,
      9,            // assuranceMeasure,
      1.006,        // securityLevel,
      relinWindow,  // Relinearization Window
      mode,
      1,  // depth
      maxDepth);

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

  auto schemeCKKS = std::make_shared<LPPublicKeyEncryptionSchemeCKKS<T>>();
  schemeCKKS->ParamsGen(params, 2 * ringDim, multiplicativeDepth + 1,
                        scalingFactorBits, relinWindow, mode, ksTech,
                        firstModSize, rsTech, numLargeDigits);

  auto cc = CryptoContextFactory<T>::GetContext(params, schemeCKKS);

  cc->setSchemeId("CKKS");

  return cc;
}

template <>
CryptoContext<DCRTPoly> CryptoContextFactory<DCRTPoly>::genCryptoContextNull(
    unsigned int m, const PlaintextModulus ptModulus) {
  vector<NativeInteger> moduli = {ptModulus};
  vector<NativeInteger> roots = {1};
  auto ep = std::make_shared<ParmType>(m, moduli, roots);
  auto params =
      std::make_shared<LPCryptoParametersNull<DCRTPoly>>(ep, ptModulus);
  auto scheme = std::make_shared<LPPublicKeyEncryptionSchemeNull<DCRTPoly>>();

  return CryptoContextFactory<DCRTPoly>::GetContext(params, scheme);
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextNull(
    unsigned int m, const PlaintextModulus ptModulus) {
  auto ep = std::make_shared<ParmType>(m, IntType(ptModulus), 1);
  auto params = std::make_shared<LPCryptoParametersNull<T>>(ep, ptModulus);
  auto scheme = std::make_shared<LPPublicKeyEncryptionSchemeNull<T>>();
  return CryptoContextFactory<T>::GetContext(params, scheme);
}

template <>
CryptoContext<DCRTPoly> CryptoContextFactory<DCRTPoly>::genCryptoContextNull(
    unsigned int m, EncodingParams encodingParams) {
  vector<NativeInteger> moduli = {encodingParams->GetPlaintextModulus()};
  vector<NativeInteger> roots = {1};
  auto ep = std::make_shared<ParmType>(m, moduli, roots);
  auto params =
      std::make_shared<LPCryptoParametersNull<DCRTPoly>>(ep, encodingParams);
  auto scheme = std::make_shared<LPPublicKeyEncryptionSchemeNull<DCRTPoly>>();
  return CryptoContextFactory<DCRTPoly>::GetContext(params, scheme);
}

template <typename T>
CryptoContext<T> CryptoContextFactory<T>::genCryptoContextNull(
    unsigned int m, EncodingParams encodingParams) {
  auto ep =
      std::make_shared<ParmType>(m, encodingParams->GetPlaintextModulus(), 1);
  auto params = std::make_shared<LPCryptoParametersNull<T>>(ep, encodingParams);
  auto scheme = std::make_shared<LPPublicKeyEncryptionSchemeNull<T>>();

  return CryptoContextFactory<T>::GetContext(params, scheme);
}
}  // namespace lbcrypto
