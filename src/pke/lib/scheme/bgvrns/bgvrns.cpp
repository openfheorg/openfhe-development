// @file bgvrns.cpp - BGVrns scheme implementation.
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

This code implements an RNS variant of the Brakerski-Gentry-Vaikuntanathan
scheme.

The BGV scheme is introduced in the following paper:
- Zvika Brakerski, Craig Gentry, and Vinod Vaikuntanathan. (leveled) fully
homomorphic encryption without bootstrapping. ACM Transactions on Computation
Theory (TOCT), 6(3):13, 2014.

 Our implementation builds from the designs here:
 - Craig Gentry, Shai Halevi, and Nigel P Smart. Homomorphic evaluation of the
aes circuit. In Advances in Cryptology–CRYPTO 2012, pages 850–867. Springer,
2012.
 - Andrey Kim, Yuriy Polyakov, and Vincent Zucca. Revisiting homomorphic
encryption schemes for finite fields. Cryptology ePrint Archive, Report
2021/204, 2021. https://eprint.iacr.org/2021/204.
 */

#ifndef LBCRYPTO_CRYPTO_BGVRNS_C
#define LBCRYPTO_CRYPTO_BGVRNS_C

#include "scheme/bgvrns/bgvrns.h"

namespace lbcrypto {

// makeSparse is not used by this scheme
template <class Element>
LPKeyPair<Element> LPAlgorithmBGVrns<Element>::KeyGen(CryptoContext<Element> cc,
                                                      bool makeSparse) {
  LPKeyPair<Element> kp(std::make_shared<LPPublicKeyImpl<Element>>(cc),
                        std::make_shared<LPPrivateKeyImpl<Element>>(cc));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<Element>>(
          cc->GetCryptoParameters());

  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();

  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  DugType dug;
  TugType tug;

  // Generate the element "a" of the public key
  Element a(dug, elementParams, Format::EVALUATION);
  // Generate the secret key
  Element s;
  // Get the plaintext modulus
  const auto t = cryptoParams->GetPlaintextModulus();

  // Done in two steps not to use a random polynomial from a pre-computed pool
  // Supports discrete Gaussian (RLWE), ternary uniform distribution
  // (OPTIMIZED), and sparse distribution (SPARSE) cases
  switch (cryptoParams->GetMode()) {
    case RLWE:
      s = Element(dgg, elementParams, Format::COEFFICIENT);
      break;
    case OPTIMIZED:
      s = Element(tug, elementParams, Format::COEFFICIENT);
      break;
    case SPARSE:
      s = Element(tug, elementParams, Format::COEFFICIENT, 64);
      break;
    default:
      break;
  }
  s.SetFormat(Format::EVALUATION);

  // public key is generated and set
  // privateKey->MakePublicKey(a, publicKey);
  Element e(dgg, elementParams, Format::COEFFICIENT);
  e.SetFormat(Format::EVALUATION);

  Element b = t * e - a * s;

  kp.secretKey->SetPrivateElement(std::move(s));
  kp.publicKey->SetPublicElementAtIndex(0, std::move(b));
  kp.publicKey->SetPublicElementAtIndex(1, std::move(a));

  return kp;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBGVrns<Element>::EvalAddCore(
    ConstCiphertext<Element> ciphertext1,
    ConstCiphertext<Element> ciphertext2) const {
  Ciphertext<Element> result = ciphertext1->Clone();
  EvalAddCoreInPlace(result, ciphertext2);
  return result;
}

template <class Element>
void LPAlgorithmSHEBGVrns<Element>::EvalAddCoreInPlace(
    Ciphertext<Element> &ciphertext1,
    ConstCiphertext<Element> ciphertext2) const {
  if (ciphertext1->GetLevel() != ciphertext2->GetLevel()) {
    PALISADE_THROW(config_error,
                   "EvalAddCore cannot add ciphertexts with different number "
                   "of CRT components.");
  }

  std::vector<Element> &cv1 = ciphertext1->GetElements();
  const std::vector<Element> &cv2 = ciphertext2->GetElements();

  size_t c1Size = cv1.size();
  size_t c2Size = cv2.size();
  size_t cSmallSize = std::min(c1Size, c2Size);

  for (size_t i = 0; i < cSmallSize; i++) {
    cv1[i] += cv2[i];
  }
  if (c1Size < c2Size) {
    cv1.reserve(c2Size);
    for (size_t i = c1Size; i < c2Size; i++) {
      cv1.emplace_back(cv2[i]);
    }
  }

  ciphertext1->SetDepth(
      std::max(ciphertext1->GetDepth(), ciphertext2->GetDepth()));
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBGVrns<Element>::EvalAddCore(
    ConstCiphertext<Element> ciphertext, Element ptxt) const {
  Ciphertext<Element> result = ciphertext->CloneEmpty();

  const std::vector<Element> &cv = ciphertext->GetElements();

  ptxt.SetFormat(Format::EVALUATION);

  std::vector<Element> cvAdd(cv);
  cvAdd[0] += ptxt;

  result->SetElements(std::move(cvAdd));

  result->SetDepth(ciphertext->GetDepth());
  result->SetLevel(ciphertext->GetLevel());

  return result;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBGVrns<Element>::EvalSubCore(
    ConstCiphertext<Element> ciphertext1,
    ConstCiphertext<Element> ciphertext2) const {
  if (ciphertext1->GetLevel() != ciphertext2->GetLevel()) {
    PALISADE_THROW(config_error,
                   "EvalSubCore cannot sub ciphertexts with different number "
                   "of CRT components.");
  }

  Ciphertext<Element> result = ciphertext1->CloneEmpty();

  const std::vector<Element> &cv1 = ciphertext1->GetElements();
  const std::vector<Element> &cv2 = ciphertext2->GetElements();

  size_t c1Size = cv1.size();
  size_t c2Size = cv2.size();
  size_t cSmallSize, cLargeSize;
  if (c1Size < c2Size) {
    cSmallSize = c1Size;
    cLargeSize = c2Size;
  } else {
    cSmallSize = c2Size;
    cLargeSize = c1Size;
  }

  std::vector<Element> cvSub;

  for (size_t i = 0; i < cSmallSize; i++) {
    cvSub.push_back(std::move(cv1[i] - cv2[i]));
  }
  for (size_t i = cSmallSize; i < cLargeSize; i++) {
    if (c1Size < c2Size)
      cvSub.push_back(std::move(cv2[i].Negate()));
    else
      cvSub.push_back(cv1[i]);
  }

  result->SetElements(std::move(cvSub));

  result->SetDepth(std::max(ciphertext1->GetDepth(), ciphertext2->GetDepth()));
  result->SetLevel(ciphertext1->GetLevel());

  return result;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBGVrns<Element>::EvalSubCore(
    ConstCiphertext<Element> ciphertext, Element ptxt) const {
  Ciphertext<Element> result = ciphertext->CloneEmpty();

  const std::vector<Element> &cv = ciphertext->GetElements();

  ptxt.SetFormat(Format::EVALUATION);

  std::vector<Element> cvAdd(cv);
  cvAdd[0] -= ptxt;

  result->SetElements(std::move(cvAdd));

  result->SetDepth(ciphertext->GetDepth());
  result->SetLevel(ciphertext->GetLevel());

  return result;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBGVrns<Element>::EvalMultCore(
    ConstCiphertext<Element> ciphertext1,
    ConstCiphertext<Element> ciphertext2) const {
  if (ciphertext1->GetElements()[0].GetFormat() == Format::COEFFICIENT ||
      ciphertext2->GetElements()[0].GetFormat() == Format::COEFFICIENT) {
    PALISADE_THROW(not_available_error,
                   "EvalMult cannot multiply in COEFFICIENT domain.");
  }

  if (ciphertext1->GetLevel() != ciphertext2->GetLevel()) {
    PALISADE_THROW(config_error,
                   "EvalMultCore cannot multiply ciphertexts with different "
                   "number of CRT components.");
  }

  Ciphertext<Element> result = ciphertext1->CloneEmpty();

  const std::vector<Element> &cv1 = ciphertext1->GetElements();
  const std::vector<Element> &cv2 = ciphertext2->GetElements();

  size_t cResultSize = cv1.size() + cv2.size() - 1;

  std::vector<Element> cvMult(cResultSize);

  bool isFirstAdd[cResultSize];
  std::fill_n(isFirstAdd, cResultSize, true);

  for (size_t i = 0; i < cv1.size(); i++) {
    for (size_t j = 0; j < cv2.size(); j++) {
      if (isFirstAdd[i + j] == true) {
        cvMult[i + j] = cv1[i] * cv2[j];
        isFirstAdd[i + j] = false;
      } else {
        cvMult[i + j] += cv1[i] * cv2[j];
      }
    }
  }

  result->SetElements(std::move(cvMult));

  result->SetDepth(ciphertext1->GetDepth() + ciphertext2->GetDepth());
  result->SetLevel(ciphertext1->GetLevel());

  return result;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBGVrns<Element>::EvalMultCore(
    ConstCiphertext<Element> ciphertext, Element ptxt) const {
  Ciphertext<Element> result = ciphertext->CloneEmpty();

  const std::vector<Element> &cv = ciphertext->GetElements();

  ptxt.SetFormat(EVALUATION);

  std::vector<Element> cvMult;

  cvMult.push_back(std::move(cv[0] * ptxt));
  cvMult.push_back(std::move(cv[1] * ptxt));

  result->SetElements(std::move(cvMult));
  result->SetDepth(ciphertext->GetDepth() + 1);
  result->SetLevel(ciphertext->GetLevel());

  return result;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBGVrns<Element>::EvalNegate(
    ConstCiphertext<Element> ciphertext) const {
  Ciphertext<Element> result = ciphertext->CloneEmpty();

  const std::vector<Element> &cv = ciphertext->GetElements();

  std::vector<Element> cvNegate;

  for (size_t i = 0; i < cv.size(); i++) cvNegate.push_back(cv[i].Negate());

  result->SetElements(std::move(cvNegate));

  result->SetDepth(ciphertext->GetDepth());
  result->SetLevel(ciphertext->GetLevel());

  return result;
}

template <class Element>
LPEvalKey<Element> LPAlgorithmSHEBGVrns<Element>::EvalMultKeyGen(
    const LPPrivateKey<Element> privateKey) const {
  LPPrivateKey<Element> privateKeySquared(
      std::make_shared<LPPrivateKeyImpl<Element>>(
          privateKey->GetCryptoContext()));

  Element sSquare(privateKey->GetPrivateElement() *
                  privateKey->GetPrivateElement());

  privateKeySquared->SetPrivateElement(std::move(sSquare));

  return this->KeySwitchGen(privateKeySquared, privateKey);
}

template <class Element>
vector<LPEvalKey<Element>> LPAlgorithmSHEBGVrns<Element>::EvalMultKeysGen(
    const LPPrivateKey<Element> privateKey) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<Element>>(
          privateKey->GetCryptoParameters());

  LPPrivateKey<Element> privateKeyPowered(
      std::make_shared<LPPrivateKeyImpl<Element>>(
          privateKey->GetCryptoContext()));

  vector<LPEvalKey<Element>> evalMultKeys;

  const Element &s = privateKey->GetPrivateElement();

  usint maxDepth = cryptoParams->GetMaxDepth();
  std::vector<Element> sPower(maxDepth);
  std::vector<LPEvalKey<Element>> ek(maxDepth);
  // Create powers of original key to be used in keyswitching as evaluation keys
  // after they are encrypted.
  sPower[0] = s * s;
  for (size_t i = 1; i < maxDepth - 1; i++) sPower[i] = sPower[i - 1] * s;

  for (size_t i = 0; i < maxDepth - 1; i++) {
    privateKeyPowered->SetPrivateElement(std::move(sPower[i]));
    ek[i] = KeySwitchGen(privateKeyPowered, privateKey);
    evalMultKeys.push_back(ek[i]);
  }

  return evalMultKeys;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBGVrns<Element>::EvalMult(
    ConstCiphertext<Element> ciphertext1, ConstCiphertext<Element> ciphertext2,
    const LPEvalKey<Element> ek) const {
  Ciphertext<Element> cMult = EvalMult(ciphertext1, ciphertext2);
  KeySwitchInPlace(ek, cMult);
  return cMult;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBGVrns<Element>::EvalMultMutable(
    Ciphertext<Element> &ciphertext1, Ciphertext<Element> &ciphertext2,
    const LPEvalKey<Element> ek) const {
  Ciphertext<Element> cMult = EvalMultMutable(ciphertext1, ciphertext2);
  KeySwitchInPlace(ek, cMult);
  return cMult;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHEBGVrns<Element>::EvalAutomorphism(
    ConstCiphertext<Element> ciphertext, usint i,
    const std::map<usint, LPEvalKey<Element>> &evalKeys,
    CALLER_INFO_ARGS_CPP) const {
  if (nullptr == ciphertext) {
    std::string errorMsg("Input ciphertext is nullptr");
    PALISADE_THROW(type_error, errorMsg + CALLER_INFO);
  }
  if (evalKeys.empty()) {
    std::string errorMsg("Empty input key map");
    PALISADE_THROW(type_error, errorMsg + CALLER_INFO);
  }
  auto key = evalKeys.find(i);
  if (key == evalKeys.end()) {
    std::string errorMsg(std::string("Could not find an EvalKey for index ") +
                         std::to_string(i));
    PALISADE_THROW(type_error, errorMsg + CALLER_INFO);
  }
  auto fk = key->second;
  if (nullptr == fk) {
    std::string errorMsg("Invalid evalKey");
    PALISADE_THROW(type_error, errorMsg + CALLER_INFO);
  }
  if (ciphertext->GetCryptoContext() != fk->GetCryptoContext()) {
    std::string errorMsg(
        "Items were not created in the same CryptoContextImpl");
    PALISADE_THROW(type_error, errorMsg + CALLER_INFO);
  }
  if (ciphertext->GetKeyTag() != fk->GetKeyTag()) {
    std::string errorMsg("Items were not encrypted with same keys");
    PALISADE_THROW(type_error, errorMsg + CALLER_INFO);
  }

  const std::vector<Element> &c = ciphertext->GetElements();
  if (c.size() < 2) {
    std::string errorMsg(
        std::string("Insufficient number of elements in ciphertext: ") +
        std::to_string(c.size()));
    PALISADE_THROW(config_error, errorMsg + CALLER_INFO);
  }

  usint n = ciphertext->GetElements()[0].GetRingDimension();
  std::vector<usint> map(n);
  PrecomputeAutoMap(n, i, &map);

  Ciphertext<Element> permutedCiphertext = ciphertext->CloneEmpty();
  permutedCiphertext->SetElements({std::move(c[0].AutomorphismTransform(i, map)),
                                   std::move(c[1].AutomorphismTransform(i, map))});
  permutedCiphertext->SetDepth(ciphertext->GetDepth());
  permutedCiphertext->SetLevel(ciphertext->GetLevel());

  KeySwitchInPlace(fk, permutedCiphertext);
  return permutedCiphertext;
}

template <class Element>
shared_ptr<std::map<usint, LPEvalKey<Element>>>
LPAlgorithmSHEBGVrns<Element>::EvalAutomorphismKeyGen(
    const LPPrivateKey<Element> privateKey,
    const std::vector<usint> &indexList) const {
  const Element &s = privateKey->GetPrivateElement();

  usint n = s.GetRingDimension();

  LPPrivateKey<Element> privateKeyPermuted(
      std::make_shared<LPPrivateKeyImpl<Element>>(
          privateKey->GetCryptoContext()));

  auto evalKeys = std::make_shared<std::map<usint, LPEvalKey<Element>>>();

  if (indexList.size() > n - 1)
    PALISADE_THROW(config_error, "size exceeds the ring dimension");

  for (usint i = 0; i < indexList.size(); i++) {
    Element sPermuted = s.AutomorphismTransform(indexList[i]);

    privateKeyPermuted->SetPrivateElement(sPermuted);

    (*evalKeys)[indexList[i]] = KeySwitchGen(privateKeyPermuted, privateKey);
  }

  return evalKeys;
}

// makeSparse is not used by this scheme
template <class Element>
LPKeyPair<Element> LPAlgorithmMultipartyBGVrns<Element>::MultipartyKeyGen(
    CryptoContext<Element> cc, const vector<LPPrivateKey<Element>> &secretKeys,
    bool makeSparse) {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<Element>>(
          cc->GetCryptoParameters());

  LPKeyPair<Element> kp(std::make_shared<LPPublicKeyImpl<Element>>(cc),
                        std::make_shared<LPPrivateKeyImpl<Element>>(cc));

  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();
  const auto t = cryptoParams->GetPlaintextModulus();
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
    LPPrivateKey<Element> ski = secretKeys[i];
    Element si = ski->GetPrivateElement();
    s += si;
  }
  // s.SwitchFormat();

  // public key is generated and set
  // privateKey->MakePublicKey(a, publicKey);
  Element e(dgg, elementParams, Format::COEFFICIENT);
  e.SetFormat(Format::EVALUATION);

  Element b = t * e - a * s;

  kp.secretKey->SetPrivateElement(std::move(s));
  kp.publicKey->SetPublicElementAtIndex(0, std::move(b));
  kp.publicKey->SetPublicElementAtIndex(1, std::move(a));

  return kp;
}

// makeSparse is not used by this scheme
template <class Element>
LPKeyPair<Element> LPAlgorithmMultipartyBGVrns<Element>::MultipartyKeyGen(
    CryptoContext<Element> cc, const LPPublicKey<Element> publicKey,
    bool makeSparse, bool fresh) {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<Element>>(
          cc->GetCryptoParameters());

  LPKeyPair<Element> kp(std::make_shared<LPPublicKeyImpl<Element>>(cc),
                        std::make_shared<LPPrivateKeyImpl<Element>>(cc));

  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();
  const auto t = cryptoParams->GetPlaintextModulus();
  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  DugType dug;
  TugType tug;

  // Generate the element "a" of the public key
  Element a = publicKey->GetPublicElements()[1];
  // Generate the secret key
  Element s;

  // Supports discrete Gaussian (RLWE), ternary uniform distribution
  // (OPTIMIZED), and sparse distribution (SPARSE) cases
  switch (cryptoParams->GetMode()) {
    case RLWE:
      s = Element(dgg, elementParams, Format::COEFFICIENT);
      break;
    case OPTIMIZED:
      s = Element(tug, elementParams, Format::COEFFICIENT);
      break;
    case SPARSE:
      s = Element(tug, elementParams, Format::COEFFICIENT, 64);
      break;
    default:
      break;
  }
  s.SetFormat(Format::EVALUATION);

  // public key is generated and set
  // privateKey->MakePublicKey(a, publicKey);
  Element e(dgg, elementParams, Format::COEFFICIENT);
  e.SetFormat(Format::EVALUATION);
  // a.SwitchFormat();

  Element b;

  // When PRE is not used, a joint key is computed
  if (!fresh)
    b = t * e - a * s + publicKey->GetPublicElements()[0];
  else
    b = t * e - a * s;

  kp.secretKey->SetPrivateElement(std::move(s));
  kp.publicKey->SetPublicElementAtIndex(0, std::move(b));
  kp.publicKey->SetPublicElementAtIndex(1, std::move(a));

  return kp;
}

template <class Element>
Ciphertext<Element> LPAlgorithmMultipartyBGVrns<Element>::MultipartyDecryptLead(
    const LPPrivateKey<Element> privateKey,
    ConstCiphertext<Element> ciphertext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<Element>>(
          privateKey->GetCryptoParameters());
  const auto t = cryptoParams->GetPlaintextModulus();

  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();

  const std::vector<Element> &cv = ciphertext->GetElements();
  const Element &s = privateKey->GetPrivateElement();

  DggType dgg(MP_SD);
  Element e(dgg, elementParams, Format::EVALUATION);

  Element b = cv[0] + s * cv[1] + t * e;

  Ciphertext<Element> result = ciphertext->CloneEmpty();
  result->SetElements({std::move(b)});

  return result;
}

template <class Element>
Ciphertext<Element> LPAlgorithmMultipartyBGVrns<Element>::MultipartyDecryptMain(
    const LPPrivateKey<Element> privateKey,
    ConstCiphertext<Element> ciphertext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<Element>>(
          privateKey->GetCryptoParameters());
  const auto t = cryptoParams->GetPlaintextModulus();

  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();

  const std::vector<Element> &cv = ciphertext->GetElements();
  const Element &s = privateKey->GetPrivateElement();

  DggType dgg(MP_SD);
  Element e(dgg, elementParams, Format::EVALUATION);

  Element b = s * cv[1] + t * e;

  Ciphertext<Element> result = ciphertext->CloneEmpty();
  result->SetElements({std::move(b)});

  return result;
}

template <class Element>
DecryptResult LPAlgorithmMultipartyBGVrns<Element>::MultipartyDecryptFusion(
    const vector<Ciphertext<Element>> &ciphertextVec,
    NativePoly *plaintext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<Element>>(
          ciphertextVec[0]->GetCryptoParameters());

  const auto t = cryptoParams->GetPlaintextModulus();

  const std::vector<Element> &cv0 = ciphertextVec[0]->GetElements();
  Element b = cv0[0];

  size_t numCipher = ciphertextVec.size();
  for (size_t i = 1; i < numCipher; i++) {
    const std::vector<Element> &cvi = ciphertextVec[i]->GetElements();
    b += cvi[0];
  }

  b.SwitchFormat();

  *plaintext = b.DecryptionCRTInterpolate(t);

  return DecryptResult(plaintext->GetLength());
}

template <class Element>
LPEvalKey<Element> LPAlgorithmMultipartyBGVrns<Element>::MultiKeySwitchGen(
    const LPPrivateKey<Element> originalPrivateKey,
    const LPPrivateKey<Element> newPrivateKey,
    const LPEvalKey<Element> ek) const {
  const shared_ptr<LPCryptoParametersBGVrns<Element>> cryptoParamsLWE =
      std::dynamic_pointer_cast<LPCryptoParametersBGVrns<Element>>(
          ek->GetCryptoParameters());

  const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParams =
      std::dynamic_pointer_cast<LPCryptoParametersRLWE<Element>>(
          originalPrivateKey->GetCryptoParameters());

  const shared_ptr<typename Element::Params> originalKeyParams =
      cryptoParams->GetElementParams();

  const auto &p = cryptoParams->GetPlaintextModulus();

  LPEvalKey<Element> keySwitchHintRelin(
      new LPEvalKeyRelinImpl<Element>(originalPrivateKey->GetCryptoContext()));

  // Getting a reference to the polynomials of new private key.
  const Element &sNew = newPrivateKey->GetPrivateElement();

  // Getting a reference to the polynomials of original private key.
  const Element &s = originalPrivateKey->GetPrivateElement();

  // Getting a refernce to discrete gaussian distribution generator.
  const typename Element::DggType &dgg =
      cryptoParams->GetDiscreteGaussianGenerator();

  // Relinearization window is used to calculate the base exponent.
  usint relinWindow = cryptoParams->GetRelinWindow();

  // Pushes the powers of base exponent of original key polynomial onto
  // evalKeyElements.
  std::vector<Element> evalKeyElements(s.PowersOfBase(relinWindow));

  // evalKeyElementsGenerated hold the generated noise distribution.
  std::vector<Element> evalKeyElementsGenerated;

  const std::vector<Element> &a = ek->GetAVector();

  for (usint i = 0; i < (evalKeyElements.size()); i++) {
    evalKeyElementsGenerated.push_back(a[i]);  // alpha's of i

    // Generate a_i * newSK + p * e - PowerOfBase(oldSK)
    Element e(dgg, originalKeyParams, Format::EVALUATION);

    evalKeyElements.at(i) = evalKeyElements.at(i) - (a[i] * sNew + p * e);
  }

  keySwitchHintRelin->SetAVector(std::move(evalKeyElementsGenerated));

  keySwitchHintRelin->SetBVector(std::move(evalKeyElements));

  return keySwitchHintRelin;
}

template <class Element>
shared_ptr<std::map<usint, LPEvalKey<Element>>>
LPAlgorithmMultipartyBGVrns<Element>::MultiEvalAutomorphismKeyGen(
    const LPPrivateKey<Element> privateKey,
    const shared_ptr<std::map<usint, LPEvalKey<Element>>> eAuto,
    const std::vector<usint> &indexList) const {
  const shared_ptr<LPCryptoParametersBGVrns<Element>> cryptoParamsLWE =
      std::dynamic_pointer_cast<LPCryptoParametersBGVrns<Element>>(
          privateKey->GetCryptoParameters());

  const Element &privateKeyElement = privateKey->GetPrivateElement();

  usint n = privateKeyElement.GetRingDimension();

  LPPrivateKey<Element> tempPrivateKey(
      new LPPrivateKeyImpl<Element>(privateKey->GetCryptoContext()));

  shared_ptr<std::map<usint, LPEvalKey<Element>>> evalKeys(
      new std::map<usint, LPEvalKey<Element>>());

  if (indexList.size() > n - 1) {
    PALISADE_THROW(config_error, "size exceeds the ring dimension");
  } else {
    for (usint i = 0; i < indexList.size(); i++) {
      Element permutedPrivateKeyElement =
          privateKeyElement.AutomorphismTransform(indexList[i]);

      tempPrivateKey->SetPrivateElement(permutedPrivateKeyElement);

      (*evalKeys)[indexList[i]] = MultiKeySwitchGen(
          tempPrivateKey, privateKey, eAuto->find(indexList[i])->second);
    }
  }

  return evalKeys;
}

template <class Element>
shared_ptr<std::map<usint, LPEvalKey<Element>>>
LPAlgorithmMultipartyBGVrns<Element>::MultiEvalSumKeyGen(
    const LPPrivateKey<Element> privateKey,
    const shared_ptr<std::map<usint, LPEvalKey<Element>>> eSum) const {
  const shared_ptr<LPCryptoParametersBGVrns<Element>> cryptoParamsLWE =
      std::dynamic_pointer_cast<LPCryptoParametersBGVrns<Element>>(
          privateKey->GetCryptoParameters());

  const shared_ptr<LPCryptoParameters<Element>> cryptoParams =
      privateKey->GetCryptoParameters();
  const EncodingParams encodingParams = cryptoParams->GetEncodingParams();
  const shared_ptr<typename Element::Params> elementParams =
      cryptoParams->GetElementParams();

  usint batchSize = encodingParams->GetBatchSize();
  usint m = elementParams->GetCyclotomicOrder();

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
LPEvalKey<Element> LPAlgorithmMultipartyBGVrns<Element>::MultiMultEvalKey(
    LPEvalKey<Element> evalKey, LPPrivateKey<Element> sk) const {
  const shared_ptr<LPCryptoParametersBGVrns<Element>> cryptoParamsLWE =
      std::dynamic_pointer_cast<LPCryptoParametersBGVrns<Element>>(
          evalKey->GetCryptoParameters());

  const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParams =
      std::static_pointer_cast<LPCryptoParametersRLWE<Element>>(
          evalKey->GetCryptoContext()->GetCryptoParameters());
  const typename Element::DggType &dgg =
      cryptoParams->GetDiscreteGaussianGenerator();
  const shared_ptr<typename Element::Params> elementParams =
      cryptoParams->GetElementParams();

  const auto &p = cryptoParams->GetPlaintextModulus();

  LPEvalKey<Element> evalKeyResult(
      new LPEvalKeyRelinImpl<Element>(evalKey->GetCryptoContext()));

  const std::vector<Element> &a0 = evalKey->GetAVector();
  const std::vector<Element> &b0 = evalKey->GetBVector();

  const Element &s = sk->GetPrivateElement();

  std::vector<Element> a;
  std::vector<Element> b;

  for (usint i = 0; i < a0.size(); i++) {
    Element f1(dgg, elementParams, Format::COEFFICIENT);
    f1.SetFormat(Format::EVALUATION);

    Element f2(dgg, elementParams, Format::COEFFICIENT);
    f2.SetFormat(Format::EVALUATION);

    a.push_back(a0[i] * s + p * f1);
    b.push_back(b0[i] * s + p * f2);
  }

  evalKeyResult->SetAVector(std::move(a));

  evalKeyResult->SetBVector(std::move(b));

  return evalKeyResult;
}

// Enable for LPPublicKeyEncryptionSchemeBGVrns
template <class Element>
void LPPublicKeyEncryptionSchemeBGVrns<Element>::Enable(
    PKESchemeFeature feature) {
  switch (feature) {
    case ENCRYPTION:
      if (this->m_algorithmEncryption == nullptr)
        this->m_algorithmEncryption =
            std::make_shared<LPAlgorithmBGVrns<Element>>();
      break;
    case PRE:
      if (this->m_algorithmEncryption == nullptr)
        this->m_algorithmEncryption =
            std::make_shared<LPAlgorithmBGVrns<Element>>();
      if (this->m_algorithmPRE == nullptr)
        this->m_algorithmPRE =
            std::make_shared<LPAlgorithmPREBGVrns<Element>>();
      break;
    case SHE:
      if (this->m_algorithmEncryption == nullptr)
        this->m_algorithmEncryption =
            std::make_shared<LPAlgorithmBGVrns<Element>>();
      if (this->m_algorithmSHE == nullptr)
        this->m_algorithmSHE =
            std::make_shared<LPAlgorithmSHEBGVrns<Element>>();
      break;
    case LEVELEDSHE:
      if (this->m_algorithmEncryption == nullptr)
        this->m_algorithmEncryption =
            std::make_shared<LPAlgorithmBGVrns<Element>>();
      if (this->m_algorithmLeveledSHE == nullptr)
        this->m_algorithmLeveledSHE =
            std::make_shared<LPLeveledSHEAlgorithmBGVrns<Element>>();
      break;
    case MULTIPARTY:
      if (this->m_algorithmEncryption == nullptr)
        this->m_algorithmEncryption =
            std::make_shared<LPAlgorithmBGVrns<Element>>();
      if (this->m_algorithmMultiparty == nullptr)
        this->m_algorithmMultiparty =
            std::make_shared<LPAlgorithmMultipartyBGVrns<Element>>();
      break;
    case FHE:
      PALISADE_THROW(not_implemented_error,
                     "FHE feature not supported for BGVrns scheme");
    case ADVANCEDSHE:
      PALISADE_THROW(not_implemented_error,
                     "ADVANCEDSHE feature not supported for BGVrns scheme");
  }
}

}  // namespace lbcrypto

#endif
