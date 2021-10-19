// @file bfv.cpp - implementation of the BFV scheme.
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
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
/*
Description:

 This code implements the Fan-Vercauteren (BFV) homomorphic encryption scheme.
 The BFV scheme is introduced in https://eprint.iacr.org/2012/144.pdf and
originally implemented in https://eprint.iacr.org/2014/062.pdf (this paper has
optimized correctness constraints, which are used here as well).

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution. THIS SOFTWARE IS PROVIDED BY THE
COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 */

#ifndef LBCRYPTO_CRYPTO_BFV_C
#define LBCRYPTO_CRYPTO_BFV_C

#include <fstream>
#include <iostream>
#include "scheme/bfv/bfv.h"

namespace lbcrypto {

template <class Element>
LPCryptoParametersBFV<Element>::LPCryptoParametersBFV()
    : LPCryptoParametersRLWE<Element>() {
  m_delta = IntType(0);
  m_bigModulus = IntType(0);
  m_bigRootOfUnity = IntType(0);
  m_bigModulusArb = IntType(0);
  m_bigRootOfUnityArb = IntType(0);
}

template <class Element>
LPCryptoParametersBFV<Element>::LPCryptoParametersBFV(
    const LPCryptoParametersBFV &rhs)
    : LPCryptoParametersRLWE<Element>(rhs) {
  m_delta = rhs.m_delta;
  m_bigModulus = rhs.m_bigModulus;
  m_bigRootOfUnity = rhs.m_bigRootOfUnity;
  m_bigModulusArb = rhs.m_bigModulusArb;
  m_bigRootOfUnityArb = rhs.m_bigRootOfUnityArb;
}

template <class Element>
LPCryptoParametersBFV<Element>::LPCryptoParametersBFV(
    shared_ptr<ParmType> params, const PlaintextModulus &plaintextModulus,
    float distributionParameter, float assuranceMeasure, float securityLevel,
    usint relinWindow, const IntType &delta, MODE mode,
    const IntType &bigModulus, const IntType &bigRootOfUnity,
    const IntType &bigModulusArb, const IntType &bigRootOfUnityArb, int depth,
    int maxDepth)
    : LPCryptoParametersRLWE<Element>(
          params,
          EncodingParams(
              std::make_shared<EncodingParamsImpl>(plaintextModulus)),
          distributionParameter, assuranceMeasure, securityLevel, relinWindow,
          depth, maxDepth, mode) {
  m_delta = delta;
  m_bigModulus = bigModulus;
  m_bigRootOfUnity = bigRootOfUnity;
  m_bigModulusArb = bigModulusArb;
  m_bigRootOfUnityArb = bigRootOfUnityArb;
}

template <class Element>
LPCryptoParametersBFV<Element>::LPCryptoParametersBFV(
    shared_ptr<ParmType> params, EncodingParams encodingParams,
    float distributionParameter, float assuranceMeasure, float securityLevel,
    usint relinWindow, const IntType &delta, MODE mode,
    const IntType &bigModulus, const IntType &bigRootOfUnity,
    const IntType &bigModulusArb, const IntType &bigRootOfUnityArb, int depth,
    int maxDepth)
    : LPCryptoParametersRLWE<Element>(
          params, encodingParams, distributionParameter, assuranceMeasure,
          securityLevel, relinWindow, depth, maxDepth, mode) {
  m_delta = delta;
  m_bigModulus = bigModulus;
  m_bigRootOfUnity = bigRootOfUnity;
  m_bigModulusArb = bigModulusArb;
  m_bigRootOfUnityArb = bigRootOfUnityArb;
}

template <class Element>
LPCryptoParametersBFV<Element>::LPCryptoParametersBFV(
    shared_ptr<ParmType> params, EncodingParams encodingParams,
    float distributionParameter, float assuranceMeasure,
    SecurityLevel securityLevel, usint relinWindow, const IntType &delta,
    MODE mode, const IntType &bigModulus, const IntType &bigRootOfUnity,
    const IntType &bigModulusArb, const IntType &bigRootOfUnityArb, int depth,
    int maxDepth)
    : LPCryptoParametersRLWE<Element>(
          params, encodingParams, distributionParameter, assuranceMeasure,
          securityLevel, relinWindow, depth, maxDepth, mode) {
  m_delta = delta;
  m_bigModulus = bigModulus;
  m_bigRootOfUnity = bigRootOfUnity;
  m_bigModulusArb = bigModulusArb;
  m_bigRootOfUnityArb = bigRootOfUnityArb;
}

template <class Element>
bool LPAlgorithmParamsGenBFV<Element>::ParamsGen(
    shared_ptr<LPCryptoParameters<Element>> cryptoParams, int32_t evalAddCount,
    int32_t evalMultCount, int32_t keySwitchCount, size_t dcrtBits,
    uint32_t nCustom) const {
  if (!cryptoParams) return false;

  const auto cryptoParamsBFV =
      std::static_pointer_cast<LPCryptoParametersBFV<Element>>(cryptoParams);

  double sigma = cryptoParamsBFV->GetDistributionParameter();
  double alpha = cryptoParamsBFV->GetAssuranceMeasure();
  double hermiteFactor = cryptoParamsBFV->GetSecurityLevel();
  double p = cryptoParamsBFV->GetPlaintextModulus();
  uint32_t r = cryptoParamsBFV->GetRelinWindow();
  SecurityLevel stdLevel = cryptoParamsBFV->GetStdLevel();

  // Bound of the Gaussian error polynomial
  double Berr = sigma * sqrt(alpha);

  // Bound of the key polynomial
  double Bkey;

  DistributionType distType;

  // supports both discrete Gaussian (RLWE) and ternary uniform distribution
  // (OPTIMIZED) cases
  if (cryptoParamsBFV->GetMode() == RLWE) {
    Bkey = sigma * sqrt(alpha);
    distType = HEStd_error;
  } else {
    Bkey = 1;
    distType = HEStd_ternary;
  }

  // expansion factor delta
  auto delta = [](uint32_t n) -> double { return 2 * sqrt(n); };

  // norm of fresh ciphertext polynomial
  auto Vnorm = [&](uint32_t n) -> double {
    return Berr * (1 + 2 * delta(n) * Bkey);
  };

  // RLWE security constraint
  auto nRLWE = [&](double q) -> double {
    if (stdLevel == HEStd_NotSet) {
      return log2(q / sigma) / (4 * log2(hermiteFactor));
    } else {
      return StdLatticeParm::FindRingDim(distType, stdLevel,
                                         (uint32_t)std::ceil(log2(q)));
    }
  };

  // initial values
  uint32_t n;

  if (nCustom > 0)
    n = nCustom;
  else
    n = 512;

  double q = 0;

  // only public key encryption and EvalAdd (optional when evalAddCount = 0)
  // operations are supported the correctness constraint from section 3.5 of
  // https://eprint.iacr.org/2014/062.pdf is used
  if ((evalMultCount == 0) && (keySwitchCount == 0)) {
    // Correctness constraint
    auto qBFV = [&](uint32_t n) -> double {
      return p * (2 * ((evalAddCount + 1) * Vnorm(n) + evalAddCount * p) + p);
    };

    // initial value
    q = qBFV(n);

    if ((nRLWE(q) > n) && (nCustom > 0))
      PALISADE_THROW(config_error,
                     "Ring dimension n specified by the user does not meet the "
                     "security requirement. Please increase it.");

    while (nRLWE(q) > n) {
      n = 2 * n;
      q = qBFV(n);
    }
  } else if ((evalMultCount == 0) && (keySwitchCount > 0) &&
             (evalAddCount == 0)) {
    // this case supports automorphism w/o any other operations

    // base for relinearization
    double w = pow(2, r);

    // Correctness constraint
    auto qBFV = [&](uint32_t n, double qPrev) -> double {
      return p * (2 * (Vnorm(n) + keySwitchCount * delta(n) *
                                      (floor(log2(qPrev) / r) + 1) * w * Berr) +
                  p);
    };

    // initial values
    double qPrev = 1e6;
    q = qBFV(n, qPrev);
    qPrev = q;

    if ((nRLWE(q) > n) && (nCustom > 0))
      PALISADE_THROW(config_error,
                     "Ring dimension n specified by the user does not meet the "
                     "security requirement. Please increase it.");

    // this "while" condition is needed in case the iterative solution for q
    // changes the requirement for n, which is rare but still theoretically
    // possible
    while (nRLWE(q) > n) {
      while (nRLWE(q) > n) {
        n = 2 * n;
        q = qBFV(n, qPrev);
        qPrev = q;
      }

      q = qBFV(n, qPrev);

      while (std::abs(q - qPrev) > 0.001 * q) {
        qPrev = q;
        q = qBFV(n, qPrev);
      }
    }
  } else if ((evalAddCount == 0) && (evalMultCount > 0) &&
             (keySwitchCount == 0)) {
    // Only EvalMult operations are used in the correctness constraint
    // the correctness constraint from section 3.5 of
    // https://eprint.iacr.org/2014/062.pdf is used

    // base for relinearization
    double w = pow(2, r);

    // function used in the EvalMult constraint
    auto epsilon1 = [&](uint32_t n) -> double { return 4 / (delta(n) * Bkey); };

    // function used in the EvalMult constraint
    auto C1 = [&](uint32_t n) -> double {
      return (1 + epsilon1(n)) * delta(n) * delta(n) * p * Bkey;
    };

    // function used in the EvalMult constraint
    auto C2 = [&](uint32_t n, double qPrev) -> double {
      return delta(n) * delta(n) * Bkey * (Bkey + p * p) +
             delta(n) * (floor(log2(qPrev) / r) + 1) * w * Berr;
    };

    // main correctness constraint
    auto qBFV = [&](uint32_t n, double qPrev) -> double {
      return p * (2 * (pow(C1(n), evalMultCount) * Vnorm(n) +
                       evalMultCount * pow(C1(n), evalMultCount - 1) *
                           C2(n, qPrev)) +
                  p);
    };

    // initial values
    double qPrev = 1e6;
    q = qBFV(n, qPrev);
    qPrev = q;

    if ((nRLWE(q) > n) && (nCustom > 0))
      PALISADE_THROW(config_error,
                     "Ring dimension n specified by the user does not meet the "
                     "security requirement. Please increase it.");

    // this "while" condition is needed in case the iterative solution for q
    // changes the requirement for n, which is rare but still theortically
    // possible
    while (nRLWE(q) > n) {
      while (nRLWE(q) > n) {
        n = 2 * n;
        q = qBFV(n, qPrev);
        qPrev = q;
      }

      q = qBFV(n, qPrev);

      while (std::abs(q - qPrev) > 0.001 * q) {
        qPrev = q;
        q = qBFV(n, qPrev);
      }
    }
  }

  if (ceil(log2(q)) + 1 > 125)
    PALISADE_THROW(math_error,
                   "BFV cannot autogenerate parameters for this case, please "
                   "use BFVrns instead.");

  const EncodingParams encodingParams = cryptoParamsBFV->GetEncodingParams();
  if (encodingParams->GetBatchSize() > n)
    PALISADE_THROW(config_error,
                   "The batch size cannot be larger than the ring dimension.");

  IntType qPrime = FirstPrime<IntType>(ceil(log2(q)) + 1, 2 * n);
  IntType rootOfUnity = RootOfUnity<IntType>(2 * n, qPrime);

  // reserves enough digits to avoid wrap-around when evaluating p*(c1*c2+c3*c4)
  IntType qPrime2 =
      FirstPrime<IntType>(2 * (ceil(log2(q)) + 1) + ceil(log2(p)) + 3, 2 * n);
  IntType rootOfUnity2 = RootOfUnity<IntType>(2 * n, qPrime2);

  cryptoParamsBFV->SetBigModulus(qPrime2);
  cryptoParamsBFV->SetBigRootOfUnity(rootOfUnity2);

  auto ilParams = std::make_shared<ParmType>(2 * n, qPrime, rootOfUnity);
  cryptoParamsBFV->SetElementParams(ilParams);

  cryptoParamsBFV->SetDelta(
      qPrime.DividedBy(cryptoParamsBFV->GetPlaintextModulus()));

  return true;
}

// makeSparse is not used by this scheme
template <class Element>
LPKeyPair<Element> LPAlgorithmBFV<Element>::KeyGen(CryptoContext<Element> cc,
                                                   bool makeSparse) {
  LPKeyPair<Element> kp(std::make_shared<LPPublicKeyImpl<Element>>(cc),
                        std::make_shared<LPPrivateKeyImpl<Element>>(cc));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersRLWE<Element>>(
          cc->GetCryptoParameters());

  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();

  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  DugType dug;
  TugType tug;

  // Generate the element "a" of the public key
  Element a(dug, elementParams, Format::EVALUATION);

  // Generate the secret key
  Element s;

  // Done in two steps not to use a random polynomial from a pre-computed pool
  // Supports both discrete Gaussian (RLWE) and ternary uniform distribution
  // (OPTIMIZED) cases
  if (cryptoParams->GetMode() == RLWE) {
    s = Element(dgg, elementParams, Format::COEFFICIENT);
  } else {
    s = Element(tug, elementParams, Format::COEFFICIENT);
  }
  s.SetFormat(Format::EVALUATION);

  kp.secretKey->SetPrivateElement(s);

  // Done in two steps not to use a discrete Gaussian polynomial from a
  // pre-computed pool
  Element e(dgg, elementParams, Format::COEFFICIENT);
  e.SetFormat(Format::EVALUATION);

  Element b(elementParams, Format::EVALUATION, true);
  b -= e;
  b -= (a * s);

  kp.publicKey->SetPublicElementAtIndex(0, std::move(b));
  kp.publicKey->SetPublicElementAtIndex(1, std::move(a));

  return kp;
}

template <class Element>
Ciphertext<Element> LPAlgorithmBFV<Element>::Encrypt(
    const LPPublicKey<Element> publicKey, Element ptxt) const {
  Ciphertext<Element> ciphertext(
      std::make_shared<CiphertextImpl<Element>>(publicKey));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBFV<Element>>(
          publicKey->GetCryptoParameters());

  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();

  ptxt.SetFormat(Format::EVALUATION);

  const IntType &delta = cryptoParams->GetDelta();

  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  TugType tug;

  const Element &p0 = publicKey->GetPublicElements().at(0);
  const Element &p1 = publicKey->GetPublicElements().at(1);

  Element u;

  // Supports both discrete Gaussian (RLWE) and ternary uniform distribution
  // (OPTIMIZED) cases
  if (cryptoParams->GetMode() == RLWE)
    u = Element(dgg, elementParams, Format::EVALUATION);
  else
    u = Element(tug, elementParams, Format::EVALUATION);

  Element e1(dgg, elementParams, Format::EVALUATION);
  Element e2(dgg, elementParams, Format::EVALUATION);

  Element c0(elementParams);
  Element c1(elementParams);

  c0 = p0 * u + e1 + delta * ptxt;

  c1 = p1 * u + e2;

  ciphertext->SetElements({std::move(c0), std::move(c1)});

  return ciphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmBFV<Element>::Encrypt(
    const LPPrivateKey<Element> privateKey, Element ptxt) const {
  Ciphertext<Element> ciphertext(
      std::make_shared<CiphertextImpl<Element>>(privateKey));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBFV<Element>>(
          privateKey->GetCryptoParameters());

  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();

  ptxt.SwitchFormat();

  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  DugType dug;
  const IntType &delta = cryptoParams->GetDelta();

  Element a(dug, elementParams, Format::EVALUATION);
  const Element &s = privateKey->GetPrivateElement();
  Element e(dgg, elementParams, Format::EVALUATION);

  Element c0(a * s + e + delta * ptxt);
  Element c1(elementParams, Format::EVALUATION, true);
  c1 -= a;

  ciphertext->SetElements({std::move(c0), std::move(c1)});

  return ciphertext;
}

template <class Element>
DecryptResult LPAlgorithmBFV<Element>::Decrypt(
    const LPPrivateKey<Element> privateKey, ConstCiphertext<Element> ciphertext,
    NativePoly *plaintext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBFV<Element>>(
          privateKey->GetCryptoParameters());
  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();

  const std::vector<Element> &c = ciphertext->GetElements();

  const Element &s = privateKey->GetPrivateElement();
  Element sPower = s;

  Element b = c[0];
  b.SetFormat(Format::EVALUATION);

  Element cTemp;
  for (size_t i = 1; i <= ciphertext->GetDepth(); i++) {
    cTemp = c[i];
    cTemp.SetFormat(Format::EVALUATION);

    b += sPower * cTemp;
    sPower *= s;
  }

  b.SwitchFormat();

  const auto p = cryptoParams->GetPlaintextModulus();

  const IntType &delta = cryptoParams->GetDelta();
  Element ans = b.DivideAndRound(delta).Mod(p);

  *plaintext = ans.DecryptionCRTInterpolate(p);

  return DecryptResult(plaintext->GetLength());
}

template <class Element>
void LPAlgorithmSHEBFV<Element>::EvalAddInPlace(
    Ciphertext<Element> &ciphertext1,
    ConstCiphertext<Element> ciphertext2) const {
  if (!(ciphertext1->GetCryptoParameters() ==
        ciphertext2->GetCryptoParameters())) {
    std::string errMsg =
        "LPAlgorithmSHEBFV::EvalAddInPlace crypto parameters are not the same";
    PALISADE_THROW(config_error, errMsg);
  }

  std::vector<Element> &cv1 = ciphertext1->GetElements();
  const std::vector<Element> &cv2 = ciphertext2->GetElements();

  size_t c1Size = cv1.size();
  size_t c2Size = cv2.size();
  size_t cSmallSize = std::min(c1Size, c2Size);

  if (c1Size < c2Size) {
    ciphertext1->SetDepth(ciphertext2->GetDepth());
  }

  for (size_t i = 0; i < cSmallSize; i++) {
    cv1[i] += cv2[i];
  }
  if (c1Size < c2Size) {
    cv1.reserve(c2Size);
    for (size_t i = c1Size; i < c2Size; i++) {
      cv1.emplace_back(cv2[i]);
    }
  }
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBFV<Element>::EvalAdd(
    ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const {
  Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();
  newCiphertext->SetDepth(ciphertext->GetDepth());

  const std::vector<Element> &cipherTextElements = ciphertext->GetElements();

  const Element &ptElement = plaintext->GetElement<Element>();

  std::vector<Element> c(cipherTextElements.size());

  auto bfvParams = std::static_pointer_cast<LPCryptoParametersBFV<Element>>(
      ciphertext->GetCryptoParameters());
  auto &delta = bfvParams->GetDelta();

  c[0] = cipherTextElements[0] + delta * ptElement;

  for (size_t i = 1; i < cipherTextElements.size(); i++) {
    c[i] = cipherTextElements[i];
  }

  newCiphertext->SetElements(std::move(c));

  return newCiphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBFV<Element>::EvalSub(
    ConstCiphertext<Element> ciphertext1,
    ConstCiphertext<Element> ciphertext2) const {
  if (!(ciphertext1->GetCryptoParameters() ==
        ciphertext2->GetCryptoParameters())) {
    std::string errMsg =
        "LPAlgorithmSHEBFV::EvalSub crypto parameters are not the same";
    PALISADE_THROW(config_error, errMsg);
  }

  Ciphertext<Element> newCiphertext = ciphertext1->CloneEmpty();

  const std::vector<Element> &cipherText1Elements = ciphertext1->GetElements();
  const std::vector<Element> &cipherText2Elements = ciphertext2->GetElements();

  size_t cipherTextRElementsSize;
  size_t cipherTextSmallElementsSize;

  bool isCipherText1Small;
  if (cipherText1Elements.size() > cipherText2Elements.size()) {
    isCipherText1Small = false;
    cipherTextRElementsSize = cipherText1Elements.size();
    cipherTextSmallElementsSize = cipherText2Elements.size();
    newCiphertext->SetDepth(ciphertext1->GetDepth());
  } else {
    isCipherText1Small = true;
    cipherTextRElementsSize = cipherText2Elements.size();
    cipherTextSmallElementsSize = cipherText1Elements.size();
    newCiphertext->SetDepth(ciphertext2->GetDepth());
  }

  std::vector<Element> c(cipherTextRElementsSize);

  for (size_t i = 0; i < cipherTextSmallElementsSize; i++)
    c[i] = cipherText1Elements[i] - cipherText2Elements[i];

  for (size_t i = cipherTextSmallElementsSize; i < cipherTextRElementsSize;
       i++) {
    if (isCipherText1Small == true)
      c[i] = cipherText2Elements[i];
    else
      c[i] = cipherText1Elements[i];
  }

  newCiphertext->SetElements(std::move(c));

  return newCiphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBFV<Element>::EvalSub(
    ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const {
  //  if (!(ciphertext1->GetCryptoParameters() ==
  // ciphertext2->GetCryptoParameters())) {     std::string errMsg =
  // "LPAlgorithmSHEBFV::EvalSub crypto parameters are not the same";
  //    PALISADE_THROW(config_error, errMsg);
  //  }

  Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();
  newCiphertext->SetDepth(ciphertext->GetDepth());

  const std::vector<Element> &cipherTextElements = ciphertext->GetElements();

  plaintext->SetFormat(Format::EVALUATION);
  const Element &ptElement = plaintext->GetElement<Element>();

  std::vector<Element> c(cipherTextElements.size());

  auto bfvParams = std::static_pointer_cast<LPCryptoParametersBFV<Element>>(
      ciphertext->GetCryptoParameters());
  auto &delta = bfvParams->GetDelta();

  c[0] = cipherTextElements[0] - delta * ptElement;

  for (size_t i = 1; i < cipherTextElements.size(); i++) {
    c[i] = cipherTextElements[i];
  }

  newCiphertext->SetElements(std::move(c));

  return newCiphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBFV<Element>::EvalNegate(
    ConstCiphertext<Element> ciphertext) const {
  Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();

  const std::vector<Element> &cipherTextElements = ciphertext->GetElements();

  Element c0 = cipherTextElements[0].Negate();
  Element c1 = cipherTextElements[1].Negate();

  newCiphertext->SetElements({std::move(c0), std::move(c1)});
  return newCiphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBFV<Element>::EvalMult(
    ConstCiphertext<Element> ciphertext1,
    ConstCiphertext<Element> ciphertext2) const {
  bool isCiphertext1FormatCoeff = false;
  bool isCiphertext2FormatCoeff = false;

  if (ciphertext1->GetElements()[0].GetFormat() == Format::COEFFICIENT)
    isCiphertext1FormatCoeff = true;

  if (ciphertext2->GetElements()[0].GetFormat() == Format::COEFFICIENT)
    isCiphertext2FormatCoeff = true;

  if (!(ciphertext1->GetCryptoParameters() ==
        ciphertext2->GetCryptoParameters())) {
    std::string errMsg =
        "LPAlgorithmSHEBFV::EvalMult crypto parameters are not the same";
    PALISADE_THROW(config_error, errMsg);
  }

  Ciphertext<Element> newCiphertext = ciphertext1->CloneEmpty();

  const auto cryptoParamsLWE =
      std::static_pointer_cast<LPCryptoParametersBFV<Element>>(
          ciphertext1->GetCryptoContext()->GetCryptoParameters());

  const auto p = cryptoParamsLWE->GetPlaintextModulus();

  const shared_ptr<ParmType> elementParams =
      cryptoParamsLWE->GetElementParams();
  const IntType &q = elementParams->GetModulus();

  const IntType &bigModulus = cryptoParamsLWE->GetBigModulus();
  const IntType &bigRootOfUnity = cryptoParamsLWE->GetBigRootOfUnity();
  const IntType &bigModulusArb = cryptoParamsLWE->GetBigModulusArb();
  const IntType &bigRootOfUnityArb = cryptoParamsLWE->GetBigRootOfUnityArb();
  // Get the ciphertext elements
  std::vector<Element> cipherText1Elements = ciphertext1->GetElements();
  std::vector<Element> cipherText2Elements = ciphertext2->GetElements();

  // converts the ciphertext elements to coefficient format so that the modulus
  // switching can be done
  size_t cipherText1ElementsSize = cipherText1Elements.size();
  size_t cipherText2ElementsSize = cipherText2Elements.size();
  size_t cipherTextRElementsSize =
      cipherText1ElementsSize + cipherText2ElementsSize - 1;

  std::vector<Element> c(cipherTextRElementsSize);

  if (isCiphertext1FormatCoeff != true) {
    for (size_t i = 0; i < cipherText1ElementsSize; i++)
      cipherText1Elements[i].SetFormat(Format::COEFFICIENT);
  }

  if (isCiphertext2FormatCoeff != true) {
    for (size_t i = 0; i < cipherText2ElementsSize; i++)
      cipherText2Elements[i].SetFormat(Format::COEFFICIENT);
  }

  // switches the modulus to a larger value so that polynomial multiplication
  // w/o mod q can be performed
  for (size_t i = 0; i < cipherText1ElementsSize; i++)
    cipherText1Elements[i].SwitchModulus(bigModulus, bigRootOfUnity,
                                         bigModulusArb, bigRootOfUnityArb);

  for (size_t i = 0; i < cipherText2ElementsSize; i++)
    cipherText2Elements[i].SwitchModulus(bigModulus, bigRootOfUnity,
                                         bigModulusArb, bigRootOfUnityArb);

  // converts the ciphertext elements back to Format::EVALUATION representation
  for (size_t i = 0; i < cipherText1ElementsSize; i++)
    cipherText1Elements[i].SetFormat(Format::EVALUATION);

  for (size_t i = 0; i < cipherText2ElementsSize; i++)
    cipherText2Elements[i].SetFormat(Format::EVALUATION);

  bool *isFirstAdd = new bool[cipherTextRElementsSize];
  std::fill_n(isFirstAdd, cipherTextRElementsSize, true);

  for (size_t i = 0; i < cipherText1ElementsSize; i++) {
    for (size_t j = 0; j < cipherText2ElementsSize; j++) {
      if (isFirstAdd[i + j] == true) {
        c[i + j] = cipherText1Elements[i] * cipherText2Elements[j];
        isFirstAdd[i + j] = false;
      } else {
        c[i + j] += cipherText1Elements[i] * cipherText2Elements[j];
      }
    }
  }

  delete[] isFirstAdd;

  // converts to coefficient representation before rounding
  for (size_t i = 0; i < cipherTextRElementsSize; i++)
    c[i].SetFormat(Format::COEFFICIENT);

  for (size_t i = 0; i < cipherTextRElementsSize; i++)
    c[i] = c[i].MultiplyAndRound(p, q);

  // switch the modulus back to the original value
  for (size_t i = 0; i < cipherTextRElementsSize; i++)
    c[i].SwitchModulus(q, elementParams->GetRootOfUnity(),
                       elementParams->GetBigModulus(),
                       elementParams->GetBigRootOfUnity());

  newCiphertext->SetElements(std::move(c));
  newCiphertext->SetDepth((ciphertext1->GetDepth() + ciphertext2->GetDepth()));

  return newCiphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBFV<Element>::EvalMult(
    ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const {
  Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();

  std::vector<Element> cipherTextElements = ciphertext->GetElements();
  plaintext->SetFormat(Format::EVALUATION);
  const Element &ptElement = plaintext->GetElement<Element>();

  if (ciphertext->GetElements()[0].GetFormat() == Format::COEFFICIENT ||
      plaintext->GetElement<Element>().GetFormat() == Format::COEFFICIENT) {
    PALISADE_THROW(
        type_error,
        "LPAlgorithmSHEBFV::EvalMult cannot multiply in COEFFICIENT domain.");
  }

  Element c0 = cipherTextElements[0] * ptElement;
  Element c1 = cipherTextElements[1] * ptElement;

  newCiphertext->SetElements({std::move(c0), std::move(c1)});

  return newCiphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBFV<Element>::EvalMultMany(
    const vector<Ciphertext<Element>> &cipherTextList,
    const vector<LPEvalKey<Element>> &evalKeys) const {
  const size_t inSize = cipherTextList.size();
  const size_t lim = inSize * 2 - 2;
  vector<Ciphertext<Element>> cipherTextResults;
  cipherTextResults.resize(inSize - 1);
  size_t ctrIndex = 0;

  for (size_t i = 0; i < lim; i = i + 2) {
    cipherTextResults[ctrIndex++] = this->EvalMultAndRelinearize(
        i < inSize ? cipherTextList[i] : cipherTextResults[i - inSize],
        i + 1 < inSize ? cipherTextList[i + 1]
                       : cipherTextResults[i + 1 - inSize],
        evalKeys);
  }

  return cipherTextResults.back();
}

template <class Element>
void LPAlgorithmSHEBFV<Element>::KeySwitchInPlace(
    const LPEvalKey<Element> ek, Ciphertext<Element>& cipherText) const {

  const auto cryptoParamsLWE =
      std::static_pointer_cast<LPCryptoParametersBFV<Element>>(
          ek->GetCryptoParameters());
  usint relinWindow = cryptoParamsLWE->GetRelinWindow();

  LPEvalKeyRelin<Element> evalKey =
      std::static_pointer_cast<LPEvalKeyRelinImpl<Element>>(ek);

  std::vector<Element> &c = cipherText->GetElements();

  const std::vector<Element> &b = evalKey->GetAVector();
  const std::vector<Element> &a = evalKey->GetBVector();

  std::vector<Element> digitsC2;


  // in the case of EvalMult, c[0] is initially in coefficient format and needs
  // to be switched to Format::EVALUATION format
  if (c.size() > 2) c[0].SetFormat(Format::EVALUATION);


  if (c.size() == 2) {  // case of automorphism
    digitsC2 = c[1].BaseDecompose(relinWindow);
    c[1] = digitsC2[0] * a[0];
  } else {  // case of EvalMult
    digitsC2 = c[2].BaseDecompose(relinWindow);
    // Convert ct1 to Format::EVALUATION representation
    c[1].SetFormat(Format::EVALUATION);
    c[1] += digitsC2[0] * a[0];
  }

  c[0] += digitsC2[0] * b[0];

  for (usint i = 1; i < digitsC2.size(); ++i) {
    c[0] += digitsC2[i] * b[i];
    c[1] += digitsC2[i] * a[i];
  }

  Ciphertext<Element> newCiphertext = cipherText->CloneEmpty();
  newCiphertext->SetElements({std::move(c[0]), std::move(c[1])});
  cipherText = std::move(newCiphertext);
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBFV<Element>::EvalMult(
    ConstCiphertext<Element> ciphertext1, ConstCiphertext<Element> ciphertext2,
    const LPEvalKey<Element> ek) const {
  Ciphertext<Element> newCiphertext = this->EvalMult(ciphertext1, ciphertext2);

  KeySwitchInPlace(ek, newCiphertext);
  return newCiphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBFV<Element>::EvalMultAndRelinearize(
    ConstCiphertext<Element> ciphertext1, ConstCiphertext<Element> ciphertext2,
    const vector<LPEvalKey<Element>> &ek) const {
  // TODO add a plaintext method for this
  //  if(!ciphertext2->GetIsEncrypted()) {
  //    return EvalMultPlain(ciphertext1, ciphertext2);
  //  }
  // Perform a multiplication
  Ciphertext<Element> cipherText = this->EvalMult(ciphertext1, ciphertext2);

  const auto cryptoParamsLWE =
      std::static_pointer_cast<LPCryptoParametersBFV<Element>>(
          ek[0]->GetCryptoParameters());
  usint relinWindow = cryptoParamsLWE->GetRelinWindow();

  Ciphertext<Element> newCiphertext = cipherText->CloneEmpty();

  std::vector<Element> c = cipherText->GetElements();

  if (c[0].GetFormat() == Format::COEFFICIENT) {
    for (size_t i = 0; i < c.size(); i++) c[i].SwitchFormat();
  }

  Element ct0(c[0]);
  Element ct1(c[1]);
  // Perform a keyswitching operation to result of the multiplication. It does
  // it until it reaches to 2 elements.
  // TODO: Maybe we can change the number of keyswitching and terminate early.
  // For instance; perform keyswitching until 4 elements left.
  for (size_t j = 0; j <= cipherText->GetDepth() - 2; j++) {
    size_t index = cipherText->GetDepth() - 2 - j;
    LPEvalKeyRelin<Element> evalKey =
        std::static_pointer_cast<LPEvalKeyRelinImpl<Element>>(ek[index]);

    const std::vector<Element> &b = evalKey->GetAVector();
    const std::vector<Element> &a = evalKey->GetBVector();

    std::vector<Element> digitsC2 = c[index + 2].BaseDecompose(relinWindow);

    for (usint i = 0; i < digitsC2.size(); ++i) {
      ct0 += digitsC2[i] * b[i];
      ct1 += digitsC2[i] * a[i];
    }
  }

  newCiphertext->SetElements({std::move(ct0), std::move(ct1)});

  return newCiphertext;
}

template <class Element>
LPEvalKey<Element> LPAlgorithmSHEBFV<Element>::KeySwitchGen(
    const LPPrivateKey<Element> originalPrivateKey,
    const LPPrivateKey<Element> newPrivateKey) const {
  LPEvalKey<Element> ek(std::make_shared<LPEvalKeyRelinImpl<Element>>(
      newPrivateKey->GetCryptoContext()));

  const auto cryptoParamsLWE =
      std::static_pointer_cast<LPCryptoParametersBFV<Element>>(
          newPrivateKey->GetCryptoParameters());
  const shared_ptr<ParmType> elementParams =
      cryptoParamsLWE->GetElementParams();
  const Element &s = newPrivateKey->GetPrivateElement();

  const DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();
  DugType dug;

  usint relinWindow = cryptoParamsLWE->GetRelinWindow();

  std::vector<Element> evalKeyElements(
      originalPrivateKey->GetPrivateElement().PowersOfBase(relinWindow));
  std::vector<Element> evalKeyElementsGenerated;

  for (usint i = 0; i < (evalKeyElements.size()); i++) {
    // Generate a_i vectors
    Element a(dug, elementParams, Format::EVALUATION);
    evalKeyElementsGenerated.push_back(a);

    // Generate a_i * s + e - PowerOfBase(s^2)
    Element e(dgg, elementParams, Format::EVALUATION);
    evalKeyElements.at(i) -= (a * s + e);
  }

  ek->SetAVector(std::move(evalKeyElements));
  ek->SetBVector(std::move(evalKeyElementsGenerated));

  return ek;
}

template <class Element>
LPEvalKey<Element> LPAlgorithmSHEBFV<Element>::EvalMultKeyGen(
    const LPPrivateKey<Element> originalPrivateKey) const {
  LPPrivateKey<Element> originalPrivateKeySquared(
      std::make_shared<LPPrivateKeyImpl<Element>>(
          originalPrivateKey->GetCryptoContext()));

  Element sSquare(originalPrivateKey->GetPrivateElement() *
                  originalPrivateKey->GetPrivateElement());

  originalPrivateKeySquared->SetPrivateElement(std::move(sSquare));

  return this->KeySwitchGen(originalPrivateKeySquared, originalPrivateKey);
}

template <class Element>
vector<LPEvalKey<Element>> LPAlgorithmSHEBFV<Element>::EvalMultKeysGen(
    const LPPrivateKey<Element> originalPrivateKey) const {
  const auto cryptoParamsLWE =
      std::static_pointer_cast<LPCryptoParametersRLWE<Element>>(
          originalPrivateKey->GetCryptoParameters());

  LPPrivateKey<Element> originalPrivateKeyPowered(
      std::make_shared<LPPrivateKeyImpl<Element>>(
          originalPrivateKey->GetCryptoContext()));

  vector<LPEvalKey<Element>> evalMultKeys;

  std::vector<Element> sPower(cryptoParamsLWE->GetMaxDepth());
  std::vector<LPEvalKey<Element>> ek(cryptoParamsLWE->GetMaxDepth());
  // Create powers of original key to be used in keyswitching as evaluation keys
  // after they are encrypted.
  sPower[0] = originalPrivateKey->GetPrivateElement() *
              originalPrivateKey->GetPrivateElement();
  for (size_t i = 1; i < cryptoParamsLWE->GetMaxDepth() - 1; i++)
    sPower[i] = sPower[i - 1] * originalPrivateKey->GetPrivateElement();

  for (size_t i = 0; i < cryptoParamsLWE->GetMaxDepth() - 1; i++) {
    originalPrivateKeyPowered->SetPrivateElement(std::move(sPower[i]));
    ek[i] = this->KeySwitchGen(originalPrivateKeyPowered, originalPrivateKey);
    evalMultKeys.push_back(ek[i]);
  }

  return evalMultKeys;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBFV<Element>::EvalAutomorphism(
    ConstCiphertext<Element> ciphertext, usint i,
    const std::map<usint, LPEvalKey<Element>> &evalKeys,
    CALLER_INFO_ARGS_CPP) const {
  if (nullptr == ciphertext) {
    std::string errorMsg(std::string("Input ciphertext is nullptr") +
                         CALLER_INFO);
    PALISADE_THROW(type_error, errorMsg);
  }
  if (evalKeys.empty()) {
    std::string errorMsg(std::string("Empty input key map") + CALLER_INFO);
    PALISADE_THROW(type_error, errorMsg);
  }
  auto key = evalKeys.find(i);
  if (key == evalKeys.end()) {
    std::string errorMsg(std::string("Could not find an EvalKey for index ") +
                         std::to_string(i) + CALLER_INFO);
    PALISADE_THROW(type_error, errorMsg);
  }
  auto fk = key->second;
  if (nullptr == fk) {
    std::string errorMsg(std::string("Invalid evalKey") + CALLER_INFO);
    PALISADE_THROW(type_error, errorMsg);
  }
  if (ciphertext->GetCryptoContext() != fk->GetCryptoContext()) {
    std::string errorMsg(
        std::string("Items were not created in the same CryptoContextImpl") +
        CALLER_INFO);
    PALISADE_THROW(type_error, errorMsg);
  }
  if (ciphertext->GetKeyTag() != fk->GetKeyTag()) {
    std::string errorMsg(
        std::string("Items were not encrypted with same keys") + CALLER_INFO);
    PALISADE_THROW(type_error, errorMsg);
  }

  const std::vector<Element> &c = ciphertext->GetElements();
  if (c.size() < 2) {
    std::string errorMsg(
        std::string("Insufficient number of elements in ciphertext: ") +
        std::to_string(c.size()) + CALLER_INFO);
    PALISADE_THROW(config_error, errorMsg);
  }

  Ciphertext<Element> permutedCiphertext(
      std::make_shared<CiphertextImpl<Element>>(*ciphertext));
  permutedCiphertext->SetElements({std::move(c[0].AutomorphismTransform(i)),
                                   std::move(c[1].AutomorphismTransform(i))});

  KeySwitchInPlace(fk, permutedCiphertext);
  return permutedCiphertext;
}

template <class Element>
shared_ptr<std::map<usint, LPEvalKey<Element>>>
LPAlgorithmSHEBFV<Element>::EvalAutomorphismKeyGen(
    const LPPrivateKey<Element> privateKey,
    const std::vector<usint> &indexList) const {
  const Element &privateKeyElement = privateKey->GetPrivateElement();

  usint n = privateKeyElement.GetRingDimension();

  LPPrivateKey<Element> tempPrivateKey(
      std::make_shared<LPPrivateKeyImpl<Element>>(
          privateKey->GetCryptoContext()));

  auto evalKeys = std::make_shared<std::map<usint, LPEvalKey<Element>>>();

  if (indexList.size() > n - 1) {
    PALISADE_THROW(math_error, "size exceeds the ring dimension");
  } else {
    for (usint i = 0; i < indexList.size(); i++) {
      Element permutedPrivateKeyElement =
          privateKeyElement.AutomorphismTransform(indexList[i]);

      tempPrivateKey->SetPrivateElement(permutedPrivateKeyElement);

      (*evalKeys)[indexList[i]] =
          this->KeySwitchGen(tempPrivateKey, privateKey);
    }
  }

  return evalKeys;
}

// Currently DISABLED at the scheme level
template <class Element>
LPEvalKey<Element> LPAlgorithmPREBFV<Element>::ReKeyGen(
    const LPPrivateKey<Element> newSK,
    const LPPrivateKey<Element> origPrivateKey) const {
  return origPrivateKey->GetCryptoContext()
      ->GetEncryptionAlgorithm()
      ->KeySwitchGen(origPrivateKey, newSK);
}

template <class Element>
LPEvalKey<Element> LPAlgorithmPREBFV<Element>::ReKeyGen(
    const LPPublicKey<Element> newPK,
    const LPPrivateKey<Element> origPrivateKey) const {
  // Get crypto context of new public key.
  auto cc = newPK->GetCryptoContext();

  // Create an evaluation key that will contain all the re-encryption key
  // elements.
  LPEvalKeyRelin<Element> ek(std::make_shared<LPEvalKeyRelinImpl<Element>>(cc));

  // Get crypto and elements parameters
  const auto cryptoParamsLWE =
      std::static_pointer_cast<LPCryptoParametersRLWE<Element>>(
          newPK->GetCryptoParameters());
  const shared_ptr<ParmType> elementParams =
      cryptoParamsLWE->GetElementParams();

  const auto BFVcryptoParamsLWE =
      std::static_pointer_cast<LPCryptoParametersBFV<Element>>(
          newPK->GetCryptoParameters());

  // Get parameters needed for PRE key gen
  // r = relinWindow
  usint relinWin = cryptoParamsLWE->GetRelinWindow();
  // nBits = log2(q), where q: ciphertext modulus
  usint nBits = elementParams->GetModulus().GetLengthForBase(2);
  // K = log2(q)/r, i.e., number of digits in PRE decomposition
  usint K = 1;
  if (relinWin > 0) {
    K = nBits / relinWin;
    if (nBits % relinWin > 0) K++;
  }

  Element s = origPrivateKey->GetPrivateElement();

  std::vector<Element> evalKeyElementsA(K);
  std::vector<Element> evalKeyElementsB(K);

  for (usint i = 0; i < K; i++) {
    NativeInteger b = NativeInteger(1) << i * relinWin;

    s.SetFormat(Format::EVALUATION);

    const DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();
    TugType tug;

    const Element &p0 = newPK->GetPublicElements().at(0);
    const Element &p1 = newPK->GetPublicElements().at(1);

    Element u;

    if (cryptoParamsLWE->GetMode() == RLWE)
      u = Element(dgg, elementParams, Format::EVALUATION);
    else
      u = Element(tug, elementParams, Format::EVALUATION);

    Element e1(dgg, elementParams, Format::EVALUATION);
    Element e2(dgg, elementParams, Format::EVALUATION);

    Element c0(elementParams);
    Element c1(elementParams);

    c0 = p0 * u + e1 + s * b;

    c1 = p1 * u + e2;

    evalKeyElementsA[i] = c0;
    evalKeyElementsB[i] = c1;
  }

  ek->SetAVector(std::move(evalKeyElementsA));
  ek->SetBVector(std::move(evalKeyElementsB));

  return std::move(ek);
}

// Function for re-encypting ciphertext using the arrays generated by ReKeyGen
template <class Element>
Ciphertext<Element> LPAlgorithmPREBFV<Element>::ReEncrypt(
    const LPEvalKey<Element> EK, ConstCiphertext<Element> ciphertext,
    const LPPublicKey<Element> publicKey) const {
  if (publicKey == nullptr) {  // Sender PK is not provided - CPA-secure PRE
    Ciphertext<Element> c =
        ciphertext->GetCryptoContext()->GetEncryptionAlgorithm()->KeySwitch(
            EK, ciphertext);
    return c;
  } else {  // Sender PK provided - HRA-secure PRE
    // Get crypto and elements parameters
    const auto cryptoParamsLWE =
        std::static_pointer_cast<LPCryptoParametersRLWE<Element>>(
            publicKey->GetCryptoParameters());
    const shared_ptr<ParmType> elementParams =
        cryptoParamsLWE->GetElementParams();

    const DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();
    TugType tug;

    PlaintextEncodings encType = ciphertext->GetEncodingType();

    Ciphertext<Element> zeroCiphertext(
        std::make_shared<CiphertextImpl<Element>>(publicKey));
    zeroCiphertext->SetEncodingType(encType);

    const Element &p0 = publicKey->GetPublicElements().at(0);
    const Element &p1 = publicKey->GetPublicElements().at(1);

    Element u;

    if (cryptoParamsLWE->GetMode() == RLWE)
      u = Element(dgg, elementParams, Format::EVALUATION);
    else
      u = Element(tug, elementParams, Format::EVALUATION);

    Element e1(dgg, elementParams, Format::EVALUATION);
    Element e2(dgg, elementParams, Format::EVALUATION);

    Element c0 = p0 * u + e1;
    Element c1 = p1 * u + e2;

    zeroCiphertext->SetElements({std::move(c0), std::move(c1)});

    // Add the encryption of zero for re-randomization purposes
    auto c = ciphertext->GetCryptoContext()->GetEncryptionAlgorithm()->EvalAdd(
        ciphertext, zeroCiphertext);

    ciphertext->GetCryptoContext()->GetEncryptionAlgorithm()->KeySwitchInPlace(
        EK, c);
    return c;
  }
}

// makeSparse is not used by this scheme
template <class Element>
LPKeyPair<Element> LPAlgorithmMultipartyBFV<Element>::MultipartyKeyGen(
    CryptoContext<Element> cc, const vector<LPPrivateKey<Element>> &secretKeys,
    bool makeSparse) {
  LPKeyPair<Element> kp(std::make_shared<LPPublicKeyImpl<Element>>(cc),
                        std::make_shared<LPPrivateKeyImpl<Element>>(cc));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersRLWE<Element>>(
          cc->GetCryptoParameters());

  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();

  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  DugType dug;
  TugType tug;

  // Generate the element "a" of the public key
  Element a(dug, elementParams, Format::EVALUATION);

  // Generate the secret key
  Element s(elementParams, Format::EVALUATION, true);

  // Supports both discrete Gaussian (RLWE) and ternary uniform distribution
  // (OPTIMIZED) cases

  size_t numKeys = secretKeys.size();
  for (size_t i = 0; i < numKeys; i++) {
    LPPrivateKey<Element> sk1 = secretKeys[i];
    Element s1 = sk1->GetPrivateElement();
    s += s1;
  }

  kp.secretKey->SetPrivateElement(s);

  // Done in two steps not to use a discrete Gaussian polynomial from a
  // pre-computed pool
  Element e(dgg, elementParams, Format::COEFFICIENT);
  e.SetFormat(Format::EVALUATION);

  Element b(elementParams, Format::EVALUATION, true);
  b -= e;
  b -= (a * s);

  kp.publicKey->SetPublicElementAtIndex(0, std::move(b));
  kp.publicKey->SetPublicElementAtIndex(1, std::move(a));

  return kp;
}

// makeSparse is not used by this scheme
template <class Element>
LPKeyPair<Element> LPAlgorithmMultipartyBFV<Element>::MultipartyKeyGen(
    CryptoContext<Element> cc, const LPPublicKey<Element> pk1, bool makeSparse,
    bool fresh) {
  LPKeyPair<Element> kp(std::make_shared<LPPublicKeyImpl<Element>>(cc),
                        std::make_shared<LPPrivateKeyImpl<Element>>(cc));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersRLWE<Element>>(
          cc->GetCryptoParameters());

  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();

  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  DugType dug;
  TugType tug;

  // Generate the element "a" of the public key
  Element a = pk1->GetPublicElements()[1];

  // Generate the secret key
  Element s;

  // Done in two steps not to use a random polynomial from a pre-computed pool
  // Supports both discrete Gaussian (RLWE) and ternary uniform distribution
  // (OPTIMIZED) cases
  if (cryptoParams->GetMode() == RLWE) {
    s = Element(dgg, elementParams, Format::COEFFICIENT);
  } else {
    // PALISADE_THROW(palisade_error, "FusedKeyGen operation has not been
    // enabled for OPTIMIZED cases");
    s = Element(tug, elementParams, Format::COEFFICIENT);
  }
  s.SetFormat(Format::EVALUATION);

  kp.secretKey->SetPrivateElement(s);

  Element e(dgg, elementParams, Format::COEFFICIENT);
  e.SetFormat(Format::EVALUATION);

  Element b(elementParams, Format::EVALUATION, true);
  b -= e;
  b -= (a * s);
  // When PRE is not used, a joint key is computed
  if (!fresh) b += pk1->GetPublicElements()[0];

  kp.publicKey->SetPublicElementAtIndex(0, std::move(b));
  kp.publicKey->SetPublicElementAtIndex(1, std::move(a));

  return kp;
}

template <class Element>
Ciphertext<Element> LPAlgorithmMultipartyBFV<Element>::MultipartyDecryptMain(
    const LPPrivateKey<Element> privateKey,
    ConstCiphertext<Element> ciphertext) const {
  const shared_ptr<LPCryptoParameters<Element>> cryptoParams =
      privateKey->GetCryptoParameters();
  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();

  const std::vector<Element> &c = ciphertext->GetElements();

  const Element &s = privateKey->GetPrivateElement();

  DggType dgg(MP_SD);
  Element e(dgg, elementParams, Format::EVALUATION);

  Element b = s * c[1] + e;
  b.SwitchFormat();

  Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();
  newCiphertext->SetElements({std::move(b)});

  return newCiphertext;
}

template <class Element>
Ciphertext<Element> LPAlgorithmMultipartyBFV<Element>::MultipartyDecryptLead(
    const LPPrivateKey<Element> privateKey,
    ConstCiphertext<Element> ciphertext) const {
  const shared_ptr<LPCryptoParameters<Element>> cryptoParams =
      privateKey->GetCryptoParameters();
  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();

  const std::vector<Element> &c = ciphertext->GetElements();

  const Element &s = privateKey->GetPrivateElement();

  DggType dgg(MP_SD);
  Element e(dgg, elementParams, Format::EVALUATION);

  Element b = c[0] + s * c[1] + e;
  b.SwitchFormat();

  Ciphertext<Element> newCiphertext = ciphertext->CloneEmpty();
  newCiphertext->SetElements({std::move(b)});

  return newCiphertext;
}

template <class Element>
DecryptResult LPAlgorithmMultipartyBFV<Element>::MultipartyDecryptFusion(
    const vector<Ciphertext<Element>> &ciphertextVec,
    NativePoly *plaintext) const {
  const auto cryptoParams = ciphertextVec[0]->GetCryptoParameters();
  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();
  const auto p = cryptoParams->GetPlaintextModulus();
  const IntType &q = elementParams->GetModulus();

  const std::vector<Element> &cElem = ciphertextVec[0]->GetElements();
  Element b = cElem[0];

  size_t numCipher = ciphertextVec.size();
  for (size_t i = 1; i < numCipher; i++) {
    const std::vector<Element> &c2 = ciphertextVec[i]->GetElements();
    b += c2[0];
  }

  Element ans = b.MultiplyAndRound(p, q).Mod(p);
  *plaintext = ans.DecryptionCRTInterpolate(p);

  return DecryptResult(plaintext->GetLength());
}

template <class Element>
LPEvalKey<Element> LPAlgorithmMultipartyBFV<Element>::MultiKeySwitchGen(
    const LPPrivateKey<Element> originalPrivateKey,
    const LPPrivateKey<Element> newPrivateKey,
    const LPEvalKey<Element> ek) const {
  const auto cryptoParams =
      std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(
          originalPrivateKey->GetCryptoParameters());

  const shared_ptr<ParmType> originalKeyParams =
      cryptoParams->GetElementParams();

  LPEvalKey<Element> keySwitchHintRelin(
      new LPEvalKeyRelinImpl<Element>(originalPrivateKey->GetCryptoContext()));

  // Getting a reference to the polynomials of new private key.
  const Element &sNew = newPrivateKey->GetPrivateElement();

  // Getting a reference to the polynomials of original private key.
  const Element &s = originalPrivateKey->GetPrivateElement();

  // Getting a refernce to discrete gaussian distribution generator.
  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

  // Relinearization window is used to calculate the base exponent.
  usint relinWindow = cryptoParams->GetRelinWindow();

  // Pushes the powers of base exponent of original key polynomial onto
  // evalKeyElements.
  std::vector<Element> evalKeyElements(s.PowersOfBase(relinWindow));

  // evalKeyElementsGenerated hold the generated noise distribution.
  std::vector<Element> evalKeyElementsGenerated;

  const std::vector<Element> &a = ek->GetBVector();

  for (usint i = 0; i < (evalKeyElements.size()); i++) {
    evalKeyElementsGenerated.push_back(a[i]);  // alpha's of i

    // Generate -(a_i * newSK + e) + PowerOfBase(oldSK)
    Element e(dgg, originalKeyParams, Format::EVALUATION);

    evalKeyElements.at(i) -= (a[i] * sNew + e);
  }

  keySwitchHintRelin->SetAVector(std::move(evalKeyElements));

  keySwitchHintRelin->SetBVector(std::move(evalKeyElementsGenerated));

  return keySwitchHintRelin;
}

template <class Element>
shared_ptr<std::map<usint, LPEvalKey<Element>>>
LPAlgorithmMultipartyBFV<Element>::MultiEvalAutomorphismKeyGen(
    const LPPrivateKey<Element> privateKey,
    const shared_ptr<std::map<usint, LPEvalKey<Element>>> eAuto,
    const std::vector<usint> &indexList) const {
  const Element &privateKeyElement = privateKey->GetPrivateElement();

  usint n = privateKeyElement.GetRingDimension();

  LPPrivateKey<Element> tempPrivateKey(
      new LPPrivateKeyImpl<Element>(privateKey->GetCryptoContext()));

  auto evalKeys = std::make_shared<std::map<usint, LPEvalKey<Element>>>();

  if (indexList.size() > n - 1) {
    PALISADE_THROW(math_error, "size exceeds the ring dimension");
  }

  for (usint i = 0; i < indexList.size(); i++) {
    Element permutedPrivateKeyElement =
        privateKeyElement.AutomorphismTransform(indexList[i]);

    tempPrivateKey->SetPrivateElement(permutedPrivateKeyElement);

    (*evalKeys)[indexList[i]] = MultiKeySwitchGen(
        tempPrivateKey, privateKey, eAuto->find(indexList[i])->second);
  }

  return evalKeys;
}

template <class Element>
shared_ptr<std::map<usint, LPEvalKey<Element>>>
LPAlgorithmMultipartyBFV<Element>::MultiEvalSumKeyGen(
    const LPPrivateKey<Element> privateKey,
    const shared_ptr<std::map<usint, LPEvalKey<Element>>> eSum) const {
  const shared_ptr<LPCryptoParameters<Element>> cryptoParams =
      privateKey->GetCryptoParameters();
  const EncodingParams encodingParams = cryptoParams->GetEncodingParams();
  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();

  usint batchSize = encodingParams->GetBatchSize();
  usint m = elementParams->GetCyclotomicOrder();

  // stores automorphism indices needed for EvalSum
  std::vector<usint> indices;

  if (batchSize > 1) {
    usint g = 5;
    for (int i = 0; i < ceil(log2(batchSize)) - 1; i++) {
      indices.push_back(g);
      g = (g * g) % m;
    }
    if (2 * batchSize < m)
      indices.push_back(g);
    else
      indices.push_back(m - 1);
  }

  return MultiEvalAutomorphismKeyGen(privateKey, eSum, indices);
}

template <class Element>
LPEvalKey<Element> LPAlgorithmMultipartyBFV<Element>::MultiMultEvalKey(
    LPEvalKey<Element> evalKey, LPPrivateKey<Element> sk) const {
  const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParams =
      std::static_pointer_cast<LPCryptoParametersRLWE<Element>>(
          evalKey->GetCryptoContext()->GetCryptoParameters());
  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();

  LPEvalKey<Element> evalKeyResult(
      new LPEvalKeyRelinImpl<Element>(evalKey->GetCryptoContext()));

  const std::vector<Element> &a0 = evalKey->GetBVector();
  const std::vector<Element> &b0 = evalKey->GetAVector();

  const Element &s = sk->GetPrivateElement();

  std::vector<Element> a;
  std::vector<Element> b;

  for (usint i = 0; i < a0.size(); i++) {
    Element f1(dgg, elementParams, Format::COEFFICIENT);
    f1.SetFormat(Format::EVALUATION);

    Element f2(dgg, elementParams, Format::COEFFICIENT);
    f2.SetFormat(Format::EVALUATION);

    a.push_back(a0[i] * s + f1);
    b.push_back(b0[i] * s + f2);
  }

  evalKeyResult->SetAVector(std::move(b));

  evalKeyResult->SetBVector(std::move(a));

  return evalKeyResult;
}

template <class Element>
LPEvalKey<Element> LPAlgorithmMultipartyBFV<Element>::MultiAddEvalKeys(
    LPEvalKey<Element> evalKey1, LPEvalKey<Element> evalKey2) const {
  LPEvalKey<Element> evalKeySum(
      new LPEvalKeyRelinImpl<Element>(evalKey1->GetCryptoContext()));

  const std::vector<Element> &a = evalKey1->GetBVector();

  const std::vector<Element> &b1 = evalKey1->GetAVector();
  const std::vector<Element> &b2 = evalKey2->GetAVector();

  std::vector<Element> b;

  for (usint i = 0; i < b1.size(); i++) {
    b.push_back(b1[i] + b2[i]);
  }

  evalKeySum->SetAVector(std::move(b));

  evalKeySum->SetBVector(a);

  return evalKeySum;
}

// Enable for LPPublicKeyEncryptionSchemeBFV
template <class Element>
void LPPublicKeyEncryptionSchemeBFV<Element>::Enable(PKESchemeFeature feature) {
  switch (feature) {
    case ENCRYPTION:
      if (this->m_algorithmEncryption == nullptr)
        this->m_algorithmEncryption =
            std::make_shared<LPAlgorithmBFV<Element>>();
      break;
    case SHE:
      if (this->m_algorithmEncryption == nullptr)
        this->m_algorithmEncryption =
            std::make_shared<LPAlgorithmBFV<Element>>();
      if (this->m_algorithmSHE == nullptr)
        this->m_algorithmSHE = std::make_shared<LPAlgorithmSHEBFV<Element>>();
      break;
    case PRE:
      if (this->m_algorithmEncryption == nullptr)
        this->m_algorithmEncryption =
            std::make_shared<LPAlgorithmBFV<Element>>();
      if (this->m_algorithmSHE == nullptr)
        this->m_algorithmSHE = std::make_shared<LPAlgorithmSHEBFV<Element>>();
      if (this->m_algorithmPRE == nullptr)
        this->m_algorithmPRE = std::make_shared<LPAlgorithmPREBFV<Element>>();
      break;
    case MULTIPARTY:
      if (this->m_algorithmEncryption == nullptr)
        this->m_algorithmEncryption =
            std::make_shared<LPAlgorithmBFV<Element>>();
      if (this->m_algorithmPRE == nullptr)
        this->m_algorithmPRE = std::make_shared<LPAlgorithmPREBFV<Element>>();
      if (this->m_algorithmSHE == nullptr)
        this->m_algorithmSHE = std::make_shared<LPAlgorithmSHEBFV<Element>>();
      if (this->m_algorithmMultiparty == nullptr)
        this->m_algorithmMultiparty =
            std::make_shared<LPAlgorithmMultipartyBFV<Element>>();
      break;
    case FHE:
      PALISADE_THROW(not_implemented_error,
                     "FHE feature not supported for BFV scheme");
    case LEVELEDSHE:
      PALISADE_THROW(not_implemented_error,
                     "LEVELEDSHE feature not supported for BFV scheme");
    case ADVANCEDSHE:
      PALISADE_THROW(not_implemented_error,
                     "ADVANCEDSHE feature not supported for BFV scheme");
  }
}

}  // namespace lbcrypto

#endif
