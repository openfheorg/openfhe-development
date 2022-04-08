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
Description:

This code implements RNS variants of the Cheon-Kim-Kim-Song scheme.

The CKKS scheme is introduced in the following paper:
- Jung Hee Cheon, Andrey Kim, Miran Kim, and Yongsoo Song. Homomorphic
encryption for arithmetic of approximate numbers. Cryptology ePrint Archive,
Report 2016/421, 2016. https://eprint.iacr.org/2016/421.

 Our implementation builds from the designs here:
 - Marcelo Blatt, Alexander Gusev, Yuriy Polyakov, Kurt Rohloff, and Vinod
Vaikuntanathan. Optimized homomorphic encryption solution for secure genomewide
association studies. Cryptology ePrint Archive, Report 2019/223, 2019.
https://eprint.iacr.org/2019/223.
 - Andrey Kim, Antonis Papadimitriou, and Yuriy Polyakov. Approximate
homomorphic encryption with reduced approximation error. Cryptology ePrint
Archive, Report 2020/1118, 2020. https://eprint.iacr.org/2020/
1118.
 */

#ifndef LBCRYPTO_CRYPTO_BASE_LEVELEDSHE_C
#define LBCRYPTO_CRYPTO_BASE_LEVELEDSHE_C

#include "cryptocontext.h"
#include "schemebase/base-leveledshe.h"

namespace lbcrypto {

/////////////////////////////////////////
// SHE NEGATION
/////////////////////////////////////////

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalNegate(
    ConstCiphertext<Element> ciphertext) const {
  auto result = ciphertext->Clone();
  EvalNegateInPlace(result);
  return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalNegateInPlace(
    Ciphertext<Element> &ciphertext) const {
  std::vector<Element> &cv = ciphertext->GetElements();

  for (size_t i = 0; i < cv.size(); i++) {
    cv[i] = cv[i].Negate();
  }
}

/////////////////////////////////////////
// SHE ADDITION
/////////////////////////////////////////

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalAdd(
    ConstCiphertext<Element> ciphertext1,
    ConstCiphertext<Element> ciphertext2) const {
  auto result = ciphertext1->Clone();
  EvalAddInPlace(result, ciphertext2);
  return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalAddInPlace(
    Ciphertext<Element> &ciphertext1,
    ConstCiphertext<Element> ciphertext2) const {
  EvalAddCoreInPlace(ciphertext1, ciphertext2);
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalAdd(
    ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const {
  auto result = ciphertext->Clone();
  EvalAddInPlace(result, plaintext);
  return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalAddInPlace(Ciphertext<Element> &ciphertext,
                                             ConstPlaintext plaintext) const {
  std::vector<Element> &cv = ciphertext->GetElements();
  Element pt = plaintext->GetElement<Element>();
  pt.SetFormat(cv[0].GetFormat());

  cv[0] += pt;
}

/////////////////////////////////////////
// SHE SUBTRACTION
/////////////////////////////////////////

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalSub(
    ConstCiphertext<Element> ciphertext1,
    ConstCiphertext<Element> ciphertext2) const {
  auto result = ciphertext1->Clone();
  EvalSubInPlace(result, ciphertext2);
  return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalSubInPlace(
    Ciphertext<Element> &ciphertext1,
    ConstCiphertext<Element> ciphertext2) const {
  EvalSubCoreInPlace(ciphertext1, ciphertext2);
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalSub(
    ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const {
  auto result = ciphertext->Clone();
  EvalSubInPlace(result, plaintext);
  return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalSubInPlace(Ciphertext<Element> &ciphertext,
                                             ConstPlaintext plaintext) const {
  std::vector<Element> &cv = ciphertext->GetElements();
  Element pt = plaintext->GetElement<Element>();
  pt.SetFormat(cv[0].GetFormat());

  cv[0] -= pt;
}

/////////////////////////////////////////
// SHE MULTIPLICATION
/////////////////////////////////////////

template <class Element>
EvalKey<Element> LeveledSHEBase<Element>::EvalMultKeyGen(
    const PrivateKey<Element> privateKey) const {
  const auto cc = privateKey->GetCryptoContext();

  PrivateKey<Element> privateKeySquared =
      std::make_shared<PrivateKeyImpl<Element>>(cc);

  const Element &s = privateKey->GetPrivateElement();

  Element ss = s * s;

  privateKeySquared->SetPrivateElement(std::move(ss));

  auto algo = cc->GetScheme();
  return algo->KeySwitchGen(privateKeySquared, privateKey);
}

template <class Element>
std::vector<EvalKey<Element>> LeveledSHEBase<Element>::EvalMultKeysGen(
    const PrivateKey<Element> privateKey) const {
  const auto cc = privateKey->GetCryptoContext();
  const auto cryptoParams = privateKey->GetCryptoParameters();

  PrivateKey<Element> privateKeyPower =
      std::make_shared<PrivateKeyImpl<Element>>(cc);

  const Element &s = privateKey->GetPrivateElement();

  std::vector<EvalKey<Element>> evalKeyVec;

  usint maxDepth = cryptoParams->GetMaxDepth();
  std::vector<Element> sPower(maxDepth - 1);

  sPower[0] = s * s;
  for (size_t i = 1; i < maxDepth - 1; i++) {
    sPower[i] = sPower[i - 1] * s;
  }

  auto algo = cc->GetScheme();

  for (size_t i = 0; i < maxDepth - 1; i++) {
    privateKeyPower->SetPrivateElement(std::move(sPower[i]));
    evalKeyVec.push_back(algo->KeySwitchGen(privateKeyPower, privateKey));
  }

  return evalKeyVec;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalMult(
    ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const {
  Ciphertext<Element> result = ciphertext->Clone();
  EvalMultInPlace(result, plaintext);
  return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalMultInPlace(Ciphertext<Element> &ciphertext,
                                              ConstPlaintext plaintext) const {
  std::vector<Element> &cv = ciphertext->GetElements();
  Element pt = plaintext->GetElement<Element>();
  pt.SetFormat(Format::EVALUATION);

  for (auto &c : cv) {
    c *= pt;
  }
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalMult(
    ConstCiphertext<Element> ciphertext1,
    ConstCiphertext<Element> ciphertext2,
    const EvalKey<Element> evalKey) const {
  Ciphertext<Element> ciphertext = EvalMult(ciphertext1, ciphertext2);

  std::vector<Element> &cv = ciphertext->GetElements();
  for (auto &c : cv) c.SetFormat(Format::EVALUATION);

  auto algo = ciphertext->GetCryptoContext()->GetScheme();

  std::shared_ptr<std::vector<Element>> ab =
      algo->KeySwitchCore(cv[2], evalKey);

  cv[0] += (*ab)[0];
  cv[1] += (*ab)[1];

  cv.resize(2);

  return ciphertext;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalMultMutable(
    Ciphertext<Element> &ciphertext1, Ciphertext<Element> &ciphertext2,
    const EvalKey<Element> evalKey) const {
  Ciphertext<Element> ciphertext = EvalMultMutable(ciphertext1, ciphertext2);

  std::vector<Element> &cv = ciphertext->GetElements();
  for (auto &c : cv) c.SetFormat(Format::EVALUATION);

  auto algo = ciphertext->GetCryptoContext()->GetScheme();

  std::shared_ptr<std::vector<Element>> ab =
      algo->KeySwitchCore(cv[2], evalKey);

  cv[0] += (*ab)[0];
  cv[1] += (*ab)[1];

  cv.resize(2);

  return ciphertext;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalMultAndRelinearize(
    ConstCiphertext<Element> ciphertext1, ConstCiphertext<Element> ciphertext2,
    const std::vector<EvalKey<Element>> &evalKeyVec) const {
  Ciphertext<Element> result = EvalMult(ciphertext1, ciphertext2);
  RelinearizeInPlace(result, evalKeyVec);
  return result;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::Relinearize(
    ConstCiphertext<Element> ciphertext,
    const std::vector<EvalKey<Element>> &evalKeyVec) const {
  Ciphertext<Element> result = ciphertext->Clone();
  RelinearizeInPlace(result, evalKeyVec);
  return result;
}

template <class Element>
void LeveledSHEBase<Element>::RelinearizeInPlace(
    Ciphertext<Element> &ciphertext,
    const std::vector<EvalKey<Element>> &evalKeyVec) const {
  std::vector<Element> &cv = ciphertext->GetElements();
  for (auto &c : cv) c.SetFormat(Format::EVALUATION);

  auto algo = ciphertext->GetCryptoContext()->GetScheme();

  for (size_t j = 2; j < cv.size(); j++) {
    std::shared_ptr<std::vector<Element>> ab =
        algo->KeySwitchCore(cv[j], evalKeyVec[j - 2]);
    cv[0] += (*ab)[0];
    cv[1] += (*ab)[1];
  }
  cv.resize(2);
}

/////////////////////////////////////////
// SHE AUTOMORPHISM
/////////////////////////////////////////

template <class Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>>
LeveledSHEBase<Element>::EvalAutomorphismKeyGen(
    const PrivateKey<Element> privateKey,
    const std::vector<usint> &indexList) const {

// we already have checks on higher level?
//  auto it = std::find(indexList.begin(), indexList.end(), 2 * n - 1);
//  if (it != indexList.end())
//    PALISADE_THROW(not_available_error, "conjugation is disabled");

  const auto cc = privateKey->GetCryptoContext();
  auto algo = cc->GetScheme();

  const Element &s = privateKey->GetPrivateElement();
  usint N = s.GetRingDimension();

// we already have checks on higher level?
//  if (indexList.size() > N - 1)
//    PALISADE_THROW(math_error, "size exceeds the ring dimension");

  auto evalKeys = std::make_shared<std::map<usint, EvalKey<Element>>>();

// TODO pragma omp currently gives concurrent error
//#pragma omp parallel for if (indexList.size() >= 4)
  for (usint i = 0; i < indexList.size(); i++) {
    PrivateKey<Element> privateKeyPermuted =
        std::make_shared<PrivateKeyImpl<Element>>(cc);

    usint index = NativeInteger(indexList[i]).ModInverse(2 * N).ConvertToInt();
    std::vector<usint> map(N);
    PrecomputeAutoMap(N, index, &map);

    Element sPermuted = s.AutomorphismTransform(index, map);
    privateKeyPermuted->SetPrivateElement(sPermuted);
    (*evalKeys)[indexList[i]] = algo->KeySwitchGen(privateKey,
        privateKeyPermuted);
  }

  return evalKeys;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalAutomorphism(
    ConstCiphertext<Element> ciphertext, usint i,
    const std::map<usint, EvalKey<Element>> &evalKeyMap,
    CALLER_INFO_ARGS_CPP) const {
  const std::vector<Element> &cv = ciphertext->GetElements();

  // we already have checks on higher level?
//  if (cv.size() < 2) {
//    std::string errorMsg(
//        std::string("Insufficient number of elements in ciphertext: ") +
//        std::to_string(cv.size()) + CALLER_INFO);
//    PALISADE_THROW(config_error, errorMsg);
//  }

  usint N = cv[0].GetRingDimension();

//  if (i == 2 * N - 1)
//    PALISADE_THROW(not_available_error,
//                   "conjugation is disabled " + CALLER_INFO);

//  if (i > 2 * N - 1)
//    PALISADE_THROW(
//        not_available_error,
//        "automorphism indices higher than 2*n are not allowed " + CALLER_INFO);

  std::vector<usint> map(N);
  PrecomputeAutoMap(N, i, &map);

  auto algo = ciphertext->GetCryptoContext()->GetScheme();

  Ciphertext<Element> result = ciphertext->Clone();

  algo->KeySwitchInPlace(result, evalKeyMap.at(i));

  std::vector<Element> &rcv = result->GetElements();

  rcv[0] = rcv[0].AutomorphismTransform(i, map);
  rcv[1] = rcv[1].AutomorphismTransform(i, map);

  return result;
}

template <class Element>
std::shared_ptr<std::vector<Element>> LeveledSHEBase<Element>::EvalFastRotationPrecompute(
    ConstCiphertext<Element> ciphertext) const {
  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  auto algo = ciphertext->GetCryptoContext()->GetScheme();

  return algo->EvalKeySwitchPrecomputeCore(cv[1], ciphertext->GetCryptoParameters());
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalFastRotation(
    ConstCiphertext<Element> ciphertext, const usint index, const usint m,
    const std::shared_ptr<std::vector<Element>> digits) const {
  if (index == 0) {
    Ciphertext<Element> result = ciphertext->Clone();
    return result;
  }

  const auto cc = ciphertext->GetCryptoContext();
  const auto cryptoParams = ciphertext->GetCryptoParameters();

  usint autoIndex = (cc->getSchemeId() == "CKKSRNS")
                        ? FindAutomorphismIndex2nComplex(index, m)
                        : FindAutomorphismIndex2n(index, m);

  auto algo = cc->GetScheme();

  auto evalKey = cc->GetEvalAutomorphismKeyMap(ciphertext->GetKeyTag())
                     .find(autoIndex)->second;

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();

  std::shared_ptr<std::vector<Element>> ba =
      algo->EvalFastKeySwitchCore(digits, evalKey, cv[0].GetParams());

  usint N = cryptoParams->GetElementParams()->GetRingDimension();
  std::vector<usint> map(N);
  PrecomputeAutoMap(N, autoIndex, &map);

  (*ba)[0] += cv[0];

  (*ba)[0] = (*ba)[0].AutomorphismTransform(autoIndex, map);
  (*ba)[1] = (*ba)[1].AutomorphismTransform(autoIndex, map);

  Ciphertext<Element> result = ciphertext->Clone();

  result->SetElements({std::move((*ba)[0]), std::move((*ba)[1])});

  return result;
}

template <class Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>>
LeveledSHEBase<Element>::EvalAtIndexKeyGen(
    const PublicKey<Element> publicKey, const PrivateKey<Element> privateKey,
    const std::vector<int32_t> &indexList) const {
  const auto cc = privateKey->GetCryptoContext();

  usint M = privateKey->GetCryptoParameters()
      ->GetElementParams()->GetCyclotomicOrder();

  std::vector<uint32_t> autoIndices(indexList.size());
  for (size_t i = 0; i < indexList.size(); i++) {
    autoIndices[i] = (cc->getSchemeId() == "CKKSRNS")
            ? FindAutomorphismIndex2nComplex(indexList[i], M)
            : FindAutomorphismIndex2n(indexList[i], M);
  }

  // we use only power of two cyclotomics now
//  if (IsPowerOfTwo(m)) {  // power-of-two cyclotomics
//  } else {  // cyclic groups
//    for (size_t i = 0; i < indexList.size(); i++)
//      autoIndices[i] = FindAutomorphismIndexCyclic(
//          indexList[i], m, encodingParams->GetPlaintextGenerator());
//  }

  if (publicKey)
    // NTRU-based scheme
    return EvalAutomorphismKeyGen(publicKey, privateKey, autoIndices);
  else
    // RLWE-based scheme
    return EvalAutomorphismKeyGen(privateKey, autoIndices);
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalAtIndex(
    ConstCiphertext<Element> ciphertext, int32_t index,
    const std::map<usint, EvalKey<Element>> &evalKeyMap) const {
  const auto cc = ciphertext->GetCryptoContext();

  usint M = ciphertext->GetCryptoParameters()
      ->GetElementParams()->GetCyclotomicOrder();

  uint32_t autoIndex = (cc->getSchemeId() == "CKKSRNS")
                  ? FindAutomorphismIndex2nComplex(index, M)
                  : FindAutomorphismIndex2n(index, M);

  // we use only power of two cyclotomics
//  // power-of-two cyclotomics
//  if (IsPowerOfTwo(m)) {
//  } else {  // cyclic-group cyclotomics
//    autoIndex = FindAutomorphismIndexCyclic(
//        index, m, encodingParams->GetPlaintextGenerator());
//  }

  return EvalAutomorphism(ciphertext, autoIndex, evalKeyMap);
}

/////////////////////////////////////////
// SHE LEVELED Mod Reduce
/////////////////////////////////////////

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::ComposedEvalMult(
    ConstCiphertext<Element> ciphertext1, ConstCiphertext<Element> ciphertext2,
    const EvalKey<Element> evalKey) const {
  auto algo = ciphertext1->GetCryptoContext()->GetScheme();
  Ciphertext<Element> ciphertext = EvalMult(ciphertext1, ciphertext2);
  algo->KeySwitchInPlace(ciphertext, evalKey);
  ModReduceInPlace(ciphertext);
  return ciphertext;
}

/////////////////////////////////////////
// SHE LEVELED Level Reduce
/////////////////////////////////////////

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::LevelReduce(
    ConstCiphertext<Element> ciphertext,
    const EvalKey<Element> evalKey, size_t levels) const {
  auto result = ciphertext->Clone();
  LevelReduceInPlace(result, evalKey, levels);
  return result;
}

/////////////////////////////////////////
// CORE OPERATION
/////////////////////////////////////////

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalAddCore(
    ConstCiphertext<Element> ciphertext1,
    ConstCiphertext<Element> ciphertext2) const {
  auto result = ciphertext1->Clone();
  EvalAddCoreInPlace(result, ciphertext2);
  return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalAddCoreInPlace(
    Ciphertext<Element> &ciphertext1,
    ConstCiphertext<Element> ciphertext2) const {
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
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalSubCore(
    ConstCiphertext<Element> ciphertext1,
    ConstCiphertext<Element> ciphertext2) const {
  auto result = ciphertext1->Clone();
  EvalSubCoreInPlace(result, ciphertext2);
  return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalSubCoreInPlace(
    Ciphertext<Element> &ciphertext1,
    ConstCiphertext<Element> ciphertext2) const {
  std::vector<Element> &cv1 = ciphertext1->GetElements();
  const std::vector<Element> &cv2 = ciphertext2->GetElements();

  size_t c1Size = cv1.size();
  size_t c2Size = cv2.size();
  size_t cSmallSize = std::min(c1Size, c2Size);

  for (size_t i = 0; i < cSmallSize; i++) {
    cv1[i] -= cv2[i];
  }

  if (c1Size < c2Size) {
    cv1.reserve(c2Size);
    for (size_t i = c1Size; i < c2Size; i++) {
      cv1.emplace_back(cv2[i].Negate());
    }
  }
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalMultCore(
    ConstCiphertext<Element> ciphertext1,
    ConstCiphertext<Element> ciphertext2) const {
  Ciphertext<Element> result = ciphertext1->Clone();

  std::vector<Element> cv1 = ciphertext1->GetElements();
  const std::vector<Element> &cv2 = ciphertext2->GetElements();

  size_t cResultSize = cv1.size() + cv2.size() - 1;
  std::vector<Element> cvMult(cResultSize);

  if (cv1.size() == 2 && cv2.size() == 2) {
    cvMult[2] = (cv1[1] * cv2[1]);
    cvMult[1] = (cv1[1] *= cv2[0]);
    cvMult[0] = (cv2[0] * cv1[0]);
    cvMult[1] += (cv1[0] *= cv2[1]);
  } else {
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
  }

  result->SetElements(std::move(cvMult));
  result->SetDepth(ciphertext1->GetDepth() + ciphertext2->GetDepth());
  result->SetScalingFactor(ciphertext1->GetScalingFactor() * ciphertext2->GetScalingFactor());
  return result;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalAddCore(
    ConstCiphertext<Element> ciphertext,
    Element pt) const{
  Ciphertext<Element> result = ciphertext->Clone();
  EvalAddCoreInPlace(result, pt);
  return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalAddCoreInPlace(
    Ciphertext<Element> &ciphertext,
    const Element pt) const {
  std::vector<Element> &cv = ciphertext->GetElements();
  cv[0] += pt;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalSubCore(
    ConstCiphertext<Element> ciphertext,
    const Element pt) const {
  Ciphertext<Element> result = ciphertext->Clone();
  EvalSubCoreInPlace(result, pt);
  return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalSubCoreInPlace(
    Ciphertext<Element> &ciphertext,
    const Element pt) const {
  std::vector<Element> &cv = ciphertext->GetElements();
  cv[0] -= pt;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalMultCore(
    ConstCiphertext<Element> ciphertext,
    const Element pt) const {
  Ciphertext<Element> result = ciphertext->Clone();
  EvalMultCoreInPlace(result, pt);
  return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalMultCoreInPlace(
    Ciphertext<Element> &ciphertext,
    const Element pt) const {
  std::vector<Element> &cv = ciphertext->GetElements();
  for (auto &c : cv) {
    c *= pt;
  }
}

}  // namespace lbcrypto

#endif
