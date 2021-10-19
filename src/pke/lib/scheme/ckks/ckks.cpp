// @file ckks.cpp - CKKS scheme implementation.
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, Duality Technologies Inc.
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
 - Andrey Kim, Antonis Papadimitriou, and Yuriy Polyakov. Approximate homomorphic
encryption with reduced approximation error. Cryptology ePrint
Archive, Report 2020/1118, 2020. https://eprint.iacr.org/2020/
1118.
 */

#ifndef LBCRYPTO_CRYPTO_CKKS_C
#define LBCRYPTO_CRYPTO_CKKS_C

#include "scheme/ckks/ckks.h"

namespace lbcrypto {

// makeSparse is not used by this scheme
template <class Element>
LPKeyPair<Element> LPAlgorithmCKKS<Element>::KeyGen(CryptoContext<Element> cc,
                                                    bool makeSparse) {
  LPKeyPair<Element> kp(std::make_shared<LPPublicKeyImpl<Element>>(cc),
                        std::make_shared<LPPrivateKeyImpl<Element>>(cc));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<Element>>(
          cc->GetCryptoParameters());

  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();

  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  DugType dug;
  TugType tug;

  // Generate the element "a" of the public key
  Element a(dug, elementParams, Format::EVALUATION);
  // Generate the secret key
  Element s;

  // Done in two steps not to use a random polynomial  from a pre-computed pool
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

  Element b = e - a * s;

  kp.secretKey->SetPrivateElement(std::move(s));
  kp.publicKey->SetPublicElementAtIndex(0, std::move(b));
  kp.publicKey->SetPublicElementAtIndex(1, std::move(a));

  return kp;
}

template <class Element>
LPEvalKey<Element> LPAlgorithmSHECKKS<Element>::KeySwitchGHSGen(
    const LPPrivateKey<DCRTPoly> oldKey, const LPPrivateKey<DCRTPoly> newKey,
    const LPEvalKey<DCRTPoly> ek) const {
  std::string errMsg =
      "LPAlgorithmSHECKKS::KeySwitchGHSGen is only supported for DCRTPoly.";
  PALISADE_THROW(not_implemented_error, errMsg);
}

template <class Element>
void LPAlgorithmSHECKKS<Element>::KeySwitchGHSInPlace(
    const LPEvalKey<Element> keySwitchHint,
    Ciphertext<Element> &ciphertext) const {
  std::string errMsg =
      "LPAlgorithmSHECKKS::KeySwitchGHSInPlace is only supported for DCRTPoly.";
  PALISADE_THROW(not_implemented_error, errMsg);
}

template <class Element>
vector<shared_ptr<ConstCiphertext<Element>>>
LPAlgorithmSHECKKS<Element>::AutomaticLevelReduce(
    ConstCiphertext<Element> ciphertext1,
    ConstCiphertext<Element> ciphertext2) const {
  std::string errMsg =
      "LPAlgorithmSHECKKS::AutomaticLevelReduce is only supported for "
      "DCRTPoly.";
  PALISADE_THROW(not_implemented_error, errMsg);
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalAddCore(
    ConstCiphertext<Element> ciphertext1,
    ConstCiphertext<Element> ciphertext2) const {
  Ciphertext<Element> result = ciphertext1->Clone();
  EvalAddCoreInPlace(result, ciphertext2);
  return result;
}

template <class Element>
void LPAlgorithmSHECKKS<Element>::EvalAddCoreInPlace(
    Ciphertext<Element> &ciphertext1,
    ConstCiphertext<Element> ciphertext2) const {
  if (ciphertext1->GetDepth() != ciphertext2->GetDepth()) {
    PALISADE_THROW(config_error, "Depths of two ciphertexts do not match.");
  }

  if (ciphertext1->GetLevel() < ciphertext2->GetLevel()) {
    PALISADE_THROW(config_error,
                   "EvalAddCoreInPlace cannot add ciphertexts with ciphertext1 "
                   "level less than ciphertext2 level.");
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
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalSubCore(
    ConstCiphertext<Element> ciphertext1,
    ConstCiphertext<Element> ciphertext2) const {
  if (ciphertext1->GetDepth() != ciphertext2->GetDepth()) {
    PALISADE_THROW(config_error,
                   "LPAlgorithmSHECKKS<Element>::EvalSubCore - Depths of two "
                   "ciphertexts do not match.");
  }

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

  result->SetDepth(ciphertext1->GetDepth());
  result->SetScalingFactor(ciphertext1->GetScalingFactor());
  result->SetLevel(ciphertext1->GetLevel());

  return result;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalMultCore(
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

  std::vector<Element> cv1 = ciphertext1->GetElements();
  const std::vector<Element> &cv2 = ciphertext2->GetElements();

  size_t cResultSize = cv1.size() + cv2.size() - 1;
  std::vector<Element> cvMult(cResultSize);

  if (cv1.size() == 2 && cv2.size() == 2) {
    // cvMult[0] = cv1[0] * cv2[0];
    // cvMult[1] = (cv1[0] *= cv2[1]) + (cv2[0] * cv1[1]);
    // cvMult[2] = (cv1[1] *= cv2[1]);
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
  result->SetScalingFactor(ciphertext1->GetScalingFactor() *
                           ciphertext2->GetScalingFactor());
  result->SetLevel(ciphertext1->GetLevel());

  return result;
}

template <class Element>
void LPAlgorithmSHECKKS<Element>::EvalAddInPlace(
    Ciphertext<Element> &ciphertext1,
    ConstCiphertext<Element> ciphertext2) const {
  if (ciphertext1->GetDepth() != ciphertext2->GetDepth()) {
    PALISADE_THROW(config_error, "Depths of two ciphertexts do not match.");
  }

  if (ciphertext1->GetLevel() != ciphertext2->GetLevel()) {
    PALISADE_THROW(
        config_error,
        "EvalAddInPlace cannot add ciphertexts with different number "
        "of CRT components.");
  }

  LPAlgorithmSHECKKS<Element>::EvalAddCoreInPlace(ciphertext1, ciphertext2);
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalAdd(
    ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const {
  Ciphertext<Element> result = ciphertext->CloneEmpty();

  const std::vector<Element> &cv = ciphertext->GetElements();

  plaintext->SetFormat(Format::EVALUATION);
  const Element &pt = plaintext->GetElement<Element>();

  std::vector<Element> cvAdd;

  cvAdd.push_back(std::move(cv[0] + pt));

  for (size_t i = 1; i < cv.size(); i++) cvAdd.push_back(std::move(cv[i]));

  result->SetElements(std::move(cvAdd));

  result->SetDepth(ciphertext->GetDepth());

  return result;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalAdd(
    ConstCiphertext<Element> ciphertext, double constant) const {
  Ciphertext<Element> result = ciphertext->CloneEmpty();

  const std::vector<Element> &cv = ciphertext->GetElements();

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<Element>>(
          ciphertext->GetCryptoParameters());
  const auto p = cryptoParams->GetPlaintextModulus();

  int32_t depth = ciphertext->GetDepth();

  // TODO EvalAdd does not work for depth > 1 because of
  // overflow. We need BigIntegers to handle this case.
  // For now, we address this issue in the DCRTPoly
  // implementation of EvalAdd, by doing the operation
  // in CRT.
  if (depth > 2)
    PALISADE_THROW(
        not_implemented_error,
        "LPAlgorithmSHECKKS<Element>::EvalAdd is supported only for DCRTPoly.");

  double powP = pow(2, p * depth);

  IntType scaledConstant = std::llround(constant * powP);

  std::vector<Element> cvAdd;

  cvAdd.push_back(std::move(cv[0] + scaledConstant));

  for (size_t i = 1; i < cv.size(); i++) cvAdd.push_back(std::move(cv[i]));

  result->SetElements(std::move(cvAdd));

  result->SetDepth(ciphertext->GetDepth());

  return result;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalSub(
    ConstCiphertext<Element> ciphertext1,
    ConstCiphertext<Element> ciphertext2) const {
  return LPAlgorithmSHECKKS<Element>::EvalSubCore(ciphertext1, ciphertext2);
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalSub(
    ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const {
  Ciphertext<Element> result = ciphertext->CloneEmpty();

  const std::vector<Element> &cv = ciphertext->GetElements();

  plaintext->SetFormat(Format::EVALUATION);
  const Element &pt = plaintext->GetElement<Element>();

  std::vector<Element> cvSub;

  cvSub.push_back(std::move(cv[0] - pt));

  for (size_t i = 1; i < cv.size(); i++) cvSub.push_back(std::move(cv[i]));

  result->SetElements(std::move(cvSub));

  result->SetDepth(ciphertext->GetDepth());

  return result;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalSub(
    ConstCiphertext<Element> ciphertext, double constant) const {
  Ciphertext<Element> result = ciphertext->CloneEmpty();

  const std::vector<Element> &cv = ciphertext->GetElements();

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<Element>>(
          ciphertext->GetCryptoParameters());
  const auto p = cryptoParams->GetPlaintextModulus();

  int32_t depth = ciphertext->GetDepth();

  // TODO EvalSub does not work for depth > 1 because of
  // overflow. We need BigIntegers to handle this case.
  // For now, we address this issue in the DCRTPoly
  // implementation of EvalSub, by doing the operation
  // in CRT.
  if (depth > 2)
    PALISADE_THROW(
        not_implemented_error,
        "LPAlgorithmSHECKKS<Element>::EvalSub is supported only for DCRTPoly.");

  double powP = pow(2, p * depth);

  IntType scaledConstant = std::llround(constant * powP);

  std::vector<Element> cvSub;

  cvSub.push_back(std::move(cv[0] - scaledConstant));

  for (size_t i = 1; i < cv.size(); i++) cvSub.push_back(std::move(cv[i]));

  result->SetElements(std::move(cvSub));

  result->SetDepth(ciphertext->GetDepth());

  return result;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalMult(
    ConstCiphertext<Element> ciphertext1,
    ConstCiphertext<Element> ciphertext2) const {
  return LPAlgorithmSHECKKS<Element>::EvalMultCore(ciphertext1, ciphertext2);
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalMult(
    ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const {
  PALISADE_THROW(not_implemented_error,
                 "EvalMult is onlly implemented in DCRTPoly.");
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalMult(
    ConstCiphertext<Element> ciphertext, double constant) const {
  Ciphertext<Element> result = ciphertext->CloneEmpty();

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<Element>>(
          ciphertext->GetCryptoParameters());

  // Works only for APPROXRESCALE
  if (cryptoParams->GetRescalingTechnique() == APPROXRESCALE) {
    const std::vector<Element> &cv = ciphertext->GetElements();

    double scFactor = cryptoParams->GetScalingFactorOfLevel();

    int64_t scaledConstant = std::llround(constant * scFactor);

    std::vector<Element> cvMult;

    for (size_t i = 0; i < cv.size(); i++)
      cvMult.push_back(std::move(cv[i] * scaledConstant));

    result->SetElements(std::move(cvMult));

    result->SetDepth(ciphertext->GetDepth() + ciphertext->GetDepth());
    result->SetScalingFactor(ciphertext->GetScalingFactor() * scFactor);
    result->SetLevel(ciphertext->GetLevel());

    return result;
  } else {
    Ciphertext<Element> c;
    // First, rescale to bring ciphertext to depth 1
    if (ciphertext->GetDepth() > 2) {
      PALISADE_THROW(
          not_available_error,
          "Exact rescaling works for ciphertexts of depth 1 and 2 only.");
    }

    uint32_t depth = ciphertext->GetDepth();
    uint32_t level = ciphertext->GetLevel();
    double scalingFactor = ciphertext->GetScalingFactor();

    if (ciphertext->GetDepth() == 2) {
      CryptoContext<Element> cc = ciphertext->GetCryptoContext();
      c = cc->ModReduce(ciphertext);

      depth = c->GetDepth();
      level = c->GetLevel();
      scalingFactor = c->GetScalingFactor();
    }

    const std::vector<Element> &cv = (ciphertext->GetDepth() == 2)
                                         ? c->GetElements()
                                         : ciphertext->GetElements();

    int64_t scaledConstant = std::llround(constant * scalingFactor);

    std::vector<Element> cvMult;

    for (size_t i = 0; i < cv.size(); i++)
      cvMult.push_back(std::move(cv[i] * scaledConstant));

    result->SetElements(std::move(cvMult));

    // For EXACTRESCALING, depth always expected to be 2
    result->SetDepth(2 * depth);
    // For EXACTRESCALING, scaling factor always expected to be squared
    result->SetScalingFactor(scalingFactor * scalingFactor);
    // For EXACTRESCALING, level will change with ModReduce above, but not with
    // multiplication.
    result->SetLevel(level);

    return result;
  }
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalMultApprox(
    ConstCiphertext<Element> ciphertext, double constant) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<Element>>(
          ciphertext->GetCryptoParameters());

  const std::vector<Element> &cv = ciphertext->GetElements();

  double scFactor =
      cryptoParams->GetScalingFactorOfLevel(ciphertext->GetLevel());

  int64_t scConstant = static_cast<int64_t>(constant * scFactor + 0.5);

  std::vector<Element> cvMult(cv.size());

  for (size_t i = 0; i < cv.size(); i++) {
    cvMult[i] = cv[i] * scConstant;
  }

  Ciphertext<Element> result = ciphertext->CloneEmpty();

  result->SetElements(std::move(cvMult));

  result->SetDepth(ciphertext->GetDepth() + 1);
  result->SetScalingFactor(ciphertext->GetScalingFactor() * scFactor);
  result->SetLevel(ciphertext->GetLevel());

  return result;
}

template <class Element>
LPEvalKey<Element> LPAlgorithmSHECKKS<Element>::KeySwitchGen(
    const LPPrivateKey<Element> oldKey,
    const LPPrivateKey<Element> newKey) const {
  LPEvalKeyRelin<Element> ek(std::make_shared<LPEvalKeyRelinImpl<Element>>(
      newKey->GetCryptoContext()));

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<Element>>(
          newKey->GetCryptoParameters());
  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();
  const Element &sNew = newKey->GetPrivateElement();
  const Element &sOld = oldKey->GetPrivateElement();

  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  DugType dug;

  usint relinWindow = cryptoParams->GetRelinWindow();

  std::vector<Element> bv(sOld.PowersOfBase(relinWindow));
  std::vector<Element> av;

  for (usint i = 0; i < bv.size(); i++) {
    // Generate a_i vectors
    Element a(dug, elementParams, Format::EVALUATION);
    av.push_back(a);

    // Generate a_i * s + e - PowerOfBase(s^2)
    Element e(dgg, elementParams, Format::EVALUATION);
    bv.at(i) -= (a * sNew + e);
  }

  ek->SetAVector(std::move(av));
  ek->SetBVector(std::move(bv));

  return ek;
}

template <class Element>
void LPAlgorithmSHECKKS<Element>::KeySwitchInPlace(
    const LPEvalKey<Element> ek, Ciphertext<Element> &ciphertext) const {
  Ciphertext<Element> result = ciphertext->Clone();

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<Element>>(
          ek->GetCryptoParameters());
  usint relinWindow = cryptoParams->GetRelinWindow();

  LPEvalKeyRelin<Element> evalKey =
      std::static_pointer_cast<LPEvalKeyRelinImpl<Element>>(ek);

  const std::vector<Element> &cv = ciphertext->GetElements();

  const std::vector<Element> &bv = evalKey->GetBVector();
  const std::vector<Element> &av = evalKey->GetAVector();

  std::vector<Element> digitsC2;

  Element ct0(cv[0]);

  // in the case of EvalMult, c[0] is initially in coefficient format and needs
  // to be switched to Format::EVALUATION format
  ct0.SetFormat(Format::EVALUATION);

  Element ct1;

  if (cv.size() == 2) {  // case of PRE or automorphism
    digitsC2 = cv[1].BaseDecompose(relinWindow);
    ct1 = digitsC2[0] * av[0];
  } else {  // case of EvalMult
    digitsC2 = cv[2].BaseDecompose(relinWindow);
    ct1 = cv[1];
    // Convert ct1 to Format::EVALUATION representation
    ct1.SetFormat(Format::EVALUATION);
    ct1 += digitsC2[0] * av[0];
  }

  ct0 += (digitsC2[0] *= bv[0]);

  for (usint i = 1; i < digitsC2.size(); ++i) {
    ct0 += digitsC2[i] * bv[i];
    ct1 += (digitsC2[i] *= av[i]);
  }

  result->SetElements({std::move(ct0), std::move(ct1)});

  result->SetDepth(ciphertext->GetDepth());
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalMult(
    ConstCiphertext<Element> ciphertext1, ConstCiphertext<Element> ciphertext2,
    const LPEvalKey<Element> ek) const {
  Ciphertext<Element> cMult = EvalMult(ciphertext1, ciphertext2);
  KeySwitchInPlace(ek, cMult);
  return cMult;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalMultMutable(
    Ciphertext<Element> &ciphertext1, Ciphertext<Element> &ciphertext2,
    const LPEvalKey<Element> ek) const {
  Ciphertext<Element> cMult = EvalMultMutable(ciphertext1, ciphertext2);
  KeySwitchInPlace(ek, cMult);
  return cMult;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalNegate(
    ConstCiphertext<Element> ciphertext) const {
  Ciphertext<Element> result = ciphertext->CloneEmpty();

  const std::vector<Element> &cv = ciphertext->GetElements();

  std::vector<Element> cvNegate;

  for (size_t i = 0; i < cv.size(); i++) cvNegate.push_back(cv[i].Negate());

  result->SetElements(std::move(cvNegate));

  result->SetDepth(ciphertext->GetDepth());
  result->SetLevel(ciphertext->GetLevel());
  result->SetScalingFactor(ciphertext->GetScalingFactor());

  return result;
}

template <class Element>
LPEvalKey<Element> LPAlgorithmSHECKKS<Element>::EvalMultKeyGen(
    const LPPrivateKey<Element> privateKey) const {
  LPPrivateKey<Element> privateKeySquared(
      std::make_shared<LPPrivateKeyImpl<Element>>(
          privateKey->GetCryptoContext()));

  const Element &s = privateKey->GetPrivateElement();

  Element sSquare(s * s);

  privateKeySquared->SetPrivateElement(std::move(sSquare));

  return KeySwitchGen(privateKeySquared, privateKey);
}

template <class Element>
vector<LPEvalKey<Element>> LPAlgorithmSHECKKS<Element>::EvalMultKeysGen(
    const LPPrivateKey<Element> privateKey) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<Element>>(
          privateKey->GetCryptoParameters());

  LPPrivateKey<Element> privateKeyPowered(
      std::make_shared<LPPrivateKeyImpl<Element>>(
          privateKey->GetCryptoContext()));

  const Element &s = privateKey->GetPrivateElement();

  vector<LPEvalKey<Element>> evalMultKeys;

  usint maxDepth = cryptoParams->GetMaxDepth();
  std::vector<Element> sPower(maxDepth);
  std::vector<LPEvalKey<Element>> ek(maxDepth);
  // Create powers of original key to be used in keyswitching as evaluation keys
  // after they are encrypted.
  sPower[0] = s * s;
  for (size_t i = 1; i < maxDepth - 1; i++) sPower[i] = sPower[i - 1] * s;

  for (size_t i = 0; i < maxDepth - 1; i++) {
    privateKeyPowered->SetPrivateElement(std::move(sPower[i]));
    ek[i] = this->KeySwitchGen(privateKeyPowered, privateKey);
    evalMultKeys.push_back(ek[i]);
  }

  return evalMultKeys;
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalAutomorphism(
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

  if (i == 2 * ciphertext->GetElements()[0].GetRingDimension() - 1)
    PALISADE_THROW(not_available_error,
                   "conjugation is disabled in CKKS " + CALLER_INFO);

  if (i > 2 * ciphertext->GetElements()[0].GetRingDimension() - 1)
    PALISADE_THROW(
        not_available_error,
        "automorphism indices higher than 2*n are not allowed " + CALLER_INFO);

  usint n = ciphertext->GetElements()[0].GetRingDimension();
  std::vector<usint> map(n);
  PrecomputeAutoMap(n, i, &map);

  Ciphertext<Element> permutedCiphertext = this->KeySwitch(fk, ciphertext);

  permutedCiphertext->SetElements(
      {permutedCiphertext->GetElements()[0].AutomorphismTransform(i, map),
       permutedCiphertext->GetElements()[1].AutomorphismTransform(i, map)});

  return permutedCiphertext;
}

template <class Element>
shared_ptr<std::map<usint, LPEvalKey<Element>>>
LPAlgorithmSHECKKS<Element>::EvalAutomorphismKeyGen(
    const LPPrivateKey<Element> privateKey,
    const std::vector<usint> &indexList) const {
  const Element &s = privateKey->GetPrivateElement();

  usint n = s.GetRingDimension();

  std::vector<LPEvalKey<Element>> keysVector(indexList.size());

  auto it = std::find(indexList.begin(), indexList.end(), 2 * n - 1);
  if (it != indexList.end())
    PALISADE_THROW(not_available_error, "conjugation is disabled in CKKS");

  if (indexList.size() > n - 1)
    PALISADE_THROW(math_error, "size exceeds the ring dimension");
#pragma omp parallel for if (indexList.size() >= 4)
  for (usint i = 0; i < indexList.size(); i++) {
    LPPrivateKey<Element> privateKeyPermuted(
        std::make_shared<LPPrivateKeyImpl<Element>>(
            privateKey->GetCryptoContext()));
    // Element sPermuted = s.AutomorphismTransform(indexList[i]);
    usint index = NativeInteger(indexList[i]).ModInverse(2 * n).ConvertToInt();
    std::vector<usint> map(n);
    PrecomputeAutoMap(n, index, &map);

    Element sPermuted = s.AutomorphismTransform(index, map);
    privateKeyPermuted->SetPrivateElement(sPermuted);

    keysVector[i] = this->KeySwitchGen(privateKey, privateKeyPermuted);
  }

  auto evalKeys = std::make_shared<std::map<usint, LPEvalKey<Element>>>();
  for (usint i = 0; i < indexList.size(); i++) {
    (*evalKeys)[indexList[i]] = keysVector[i];
  }

  return evalKeys;
}

template <class Element>
LPEvalKey<Element> LPAlgorithmPRECKKS<Element>::ReKeyGen(
    const LPPublicKey<Element> newPk, const LPPrivateKey<Element> oldSk) const {
  // Get crypto context of new public key.
  auto cc = newPk->GetCryptoContext();

  // Create an evaluation key that will contain all the re-encryption key
  // elements.
  LPEvalKeyRelin<Element> ek(std::make_shared<LPEvalKeyRelinImpl<Element>>(cc));

  // Get crypto and elements parameters
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<Element>>(
          newPk->GetCryptoParameters());

  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();

  // Get parameters needed for PRE key gen
  // r = relinWindow
  usint relinWin = cryptoParams->GetRelinWindow();
  // nBits = log2(q), where q: ciphertext modulus
  usint nBits = elementParams->GetModulus().GetLengthForBase(2);
  // K = log2(q)/r, i.e., number of digits in PRE decomposition
  usint K = 1;
  if (relinWin > 0) {
    K = nBits / relinWin;
    if (nBits % relinWin > 0) K++;
  }

  Element s = oldSk->GetPrivateElement();

  std::vector<Element> av(K);
  std::vector<Element> bv(K);

  for (usint i = 0; i < K; i++) {
    NativeInteger b = NativeInteger(1) << i * relinWin;

    s.SetFormat(Format::EVALUATION);

    const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
    TugType tug;

    const Element &p0 = newPk->GetPublicElements().at(0);
    const Element &p1 = newPk->GetPublicElements().at(1);

    Element u;

    if (cryptoParams->GetMode() == RLWE)
      u = Element(dgg, elementParams, Format::EVALUATION);
    else
      u = Element(tug, elementParams, Format::EVALUATION);

    Element e0(dgg, elementParams, Format::EVALUATION);
    Element e1(dgg, elementParams, Format::EVALUATION);

    Element c0(elementParams);
    Element c1(elementParams);

    c0 = p0 * u + e0 + s * b;
    c1 = p1 * u + e1;

    av[i] = c0;
    bv[i] = c1;
  }

  ek->SetAVector(std::move(av));
  ek->SetBVector(std::move(bv));

  return std::move(ek);
}

template <class Element>
Ciphertext<Element> LPAlgorithmPRECKKS<Element>::ReEncrypt(
    const LPEvalKey<Element> EK, ConstCiphertext<Element> ciphertext,
    const LPPublicKey<Element> publicKey) const {
  Ciphertext<Element> c =
      ciphertext->GetCryptoContext()->GetEncryptionAlgorithm()->KeySwitch(
          EK, ciphertext);

  if (publicKey == nullptr) {  // Recipient PK is not provided - CPA-secure PRE
    return c;
  } else {  // Recipient PK provided - HRA-secure PRE
    auto c =
        ciphertext->GetCryptoContext()->GetEncryptionAlgorithm()->KeySwitch(
            EK, ciphertext);

    if (publicKey ==
        nullptr) {  // Recipient PK is not provided - CPA-secure PRE
      return c;
    } else {
      // Recipient PK provided - HRA-secure PRE
      // To obtain HRA security, we a fresh encryption of zero to the result
      // with noise scaled by K (=log2(q)/relinWin).
      CryptoContext<Element> cc = publicKey->GetCryptoContext();

      // Creating the correct plaintext of zeroes, based on the
      // encoding type of the ciphertext.
      PlaintextEncodings encType = c->GetEncodingType();

      // Encrypting with noise scaled by K
      const auto cryptoParams =
          std::static_pointer_cast<LPCryptoParametersCKKS<Element>>(
              publicKey->GetCryptoParameters());
      const shared_ptr<ParmType> elementParams =
          cryptoParams->GetElementParams();

      usint relinWin = cryptoParams->GetRelinWindow();
      usint nBits = elementParams->GetModulus().GetLengthForBase(2);
      // K = log2(q)/r, i.e., number of digits in PRE decomposition
      usint K = 1;
      if (relinWin > 0) {
        K = nBits / relinWin;
        if (nBits % relinWin > 0) K++;
      }

      Ciphertext<Element> zeroCiphertext(
          std::make_shared<CiphertextImpl<Element>>(publicKey));
      zeroCiphertext->SetEncodingType(encType);

      const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
      TugType tug;
      // Scaling the distribution standard deviation by K for HRA-security
      auto stdDev = cryptoParams->GetDistributionParameter();
      DggType dgg_err(K * stdDev);

      const Element &p0 = publicKey->GetPublicElements().at(0);
      const Element &p1 = publicKey->GetPublicElements().at(1);

      Element u;

      if (cryptoParams->GetMode() == RLWE)
        u = Element(dgg, elementParams, Format::EVALUATION);
      else
        u = Element(tug, elementParams, Format::EVALUATION);

      Element e1(dgg_err, elementParams, Format::EVALUATION);
      Element e2(dgg_err, elementParams, Format::EVALUATION);

      Element c0(elementParams);
      Element c1(elementParams);

      c0 = p0 * u + e1;
      c1 = p1 * u + e2;

      zeroCiphertext->SetElements({std::move(c0), std::move(c1)});

      c->SetKeyTag(zeroCiphertext->GetKeyTag());

      // Add the encryption of zeroes to the re-encrypted ciphertext
      // and return the result.
      return cc->EvalAdd(c, zeroCiphertext);
    }
  }
}

template <class Element>
void LPLeveledSHEAlgorithmCKKS<Element>::ModReduceInPlace(
    Ciphertext<Element> &ciphertext, size_t levels) const {
  std::string errMsg =
      "LPAlgorithmSHECKKS::ModReduceInPlace is only supported for DCRTPoly.";
  PALISADE_THROW(not_implemented_error, errMsg);
}

template <class Element>
Ciphertext<Element> LPLeveledSHEAlgorithmCKKS<Element>::LevelReduce(
    ConstCiphertext<Element> ciphertext,
    const LPEvalKey<Element> linearKeySwitchHint, size_t levels) const {
  std::string errMsg =
      "LPAlgorithmSHECKKS::LevelReduce is only supported for DCRTPoly.";
  PALISADE_THROW(not_implemented_error, errMsg);
}

// makeSparse is not used by this scheme
template <class Element>
LPKeyPair<Element> LPAlgorithmMultipartyCKKS<Element>::MultipartyKeyGen(
    CryptoContext<Element> cc, const vector<LPPrivateKey<Element>> &secretKeys,
    bool makeSparse) {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<Element>>(
          cc->GetCryptoParameters());

  LPKeyPair<Element> kp(std::make_shared<LPPublicKeyImpl<Element>>(cc),
                        std::make_shared<LPPrivateKeyImpl<Element>>(cc));

  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();
  // const auto p = cryptoParams->GetPlaintextModulus();
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

  Element b = e - a * s;

  kp.secretKey->SetPrivateElement(std::move(s));
  kp.publicKey->SetPublicElementAtIndex(0, std::move(b));
  kp.publicKey->SetPublicElementAtIndex(1, std::move(a));

  return kp;
}

// makeSparse is not used by this scheme
template <class Element>
LPKeyPair<Element> LPAlgorithmMultipartyCKKS<Element>::MultipartyKeyGen(
    CryptoContext<Element> cc, const LPPublicKey<Element> publicKey,
    bool makeSparse, bool fresh) {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<Element>>(
          cc->GetCryptoParameters());

  LPKeyPair<Element> kp(std::make_shared<LPPublicKeyImpl<Element>>(cc),
                        std::make_shared<LPPrivateKeyImpl<Element>>(cc));

  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();
  // const auto p = cryptoParams->GetPlaintextModulus();
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
    b = e - a * s + publicKey->GetPublicElements()[0];
  else
    b = e - a * s;

  kp.secretKey->SetPrivateElement(std::move(s));
  kp.publicKey->SetPublicElementAtIndex(0, std::move(b));
  kp.publicKey->SetPublicElementAtIndex(1, std::move(a));

  return kp;
}

template <class Element>
Ciphertext<Element> LPAlgorithmMultipartyCKKS<Element>::MultipartyDecryptLead(
    const LPPrivateKey<Element> privateKey,
    ConstCiphertext<Element> ciphertext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<Element>>(
          privateKey->GetCryptoParameters());
  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();

  const std::vector<Element> &cv = ciphertext->GetElements();
  const Element &s = privateKey->GetPrivateElement();

  DggType dgg(MP_SD);
  Element e(dgg, elementParams, Format::EVALUATION);

  // e is added to do noise flooding
  Element b = cv[0] + s * cv[1] + e;

  Ciphertext<Element> result = ciphertext->CloneEmpty();
  result->SetElements({std::move(b)});

  return result;
}

template <class Element>
Ciphertext<Element> LPAlgorithmMultipartyCKKS<Element>::MultipartyDecryptMain(
    const LPPrivateKey<Element> privateKey,
    ConstCiphertext<Element> ciphertext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<Element>>(
          privateKey->GetCryptoParameters());
  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();

  const std::vector<Element> &cv = ciphertext->GetElements();
  const Element &s = privateKey->GetPrivateElement();

  DggType dgg(MP_SD);
  Element e(dgg, elementParams, Format::EVALUATION);

  // e is added to do noise flooding
  Element b = s * cv[1] + e;

  Ciphertext<Element> result = ciphertext->CloneEmpty();

  result->SetElements({std::move(b)});

  return result;
}

template <class Element>
DecryptResult LPAlgorithmMultipartyCKKS<Element>::MultipartyDecryptFusion(
    const vector<Ciphertext<Element>> &ciphertextVec,
    NativePoly *plaintext) const {
  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<Element>>(
          ciphertextVec[0]->GetCryptoParameters());

  const std::vector<Element> &cv0 = ciphertextVec[0]->GetElements();
  Element b = cv0[0];

  size_t numCipher = ciphertextVec.size();
  for (size_t i = 1; i < numCipher; i++) {
    const std::vector<Element> &cvi = ciphertextVec[i]->GetElements();
    b += cvi[0];
  }

  b.SwitchFormat();

  *plaintext = b.ToNativePoly();

  return DecryptResult(plaintext->GetLength());
}

template <class Element>
LPEvalKey<Element> LPAlgorithmMultipartyCKKS<Element>::MultiKeySwitchGen(
    const LPPrivateKey<Element> originalPrivateKey,
    const LPPrivateKey<Element> newPrivateKey,
    const LPEvalKey<Element> ek) const {
  const shared_ptr<LPCryptoParametersCKKS<Element>> cryptoParamsLWE =
      std::dynamic_pointer_cast<LPCryptoParametersCKKS<Element>>(
          ek->GetCryptoParameters());

  const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParams =
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

  const std::vector<Element> &a = ek->GetAVector();

  for (usint i = 0; i < evalKeyElements.size(); i++) {
    evalKeyElementsGenerated.push_back(a[i]);  // alpha's of i

    // Generate a_i * newSK + p * e - PowerOfBase(oldSK)
    Element e(dgg, originalKeyParams, Format::EVALUATION);

    evalKeyElements.at(i) = evalKeyElements.at(i) - (a[i] * sNew + e);
  }

  keySwitchHintRelin->SetAVector(std::move(evalKeyElementsGenerated));

  keySwitchHintRelin->SetBVector(std::move(evalKeyElements));

  return keySwitchHintRelin;
}

template <class Element>
shared_ptr<std::map<usint, LPEvalKey<Element>>>
LPAlgorithmMultipartyCKKS<Element>::MultiEvalAutomorphismKeyGen(
    const LPPrivateKey<Element> privateKey,
    const shared_ptr<std::map<usint, LPEvalKey<Element>>> eAuto,
    const std::vector<usint> &indexList) const {
  const shared_ptr<LPCryptoParametersCKKS<Element>> cryptoParamsLWE =
      std::dynamic_pointer_cast<LPCryptoParametersCKKS<Element>>(
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
      usint index =
          NativeInteger(indexList[i]).ModInverse(2 * n).ConvertToInt();
      std::vector<usint> map(n);
      PrecomputeAutoMap(n, index, &map);

      Element sPermuted = privateKeyElement.AutomorphismTransform(index, map);
      tempPrivateKey->SetPrivateElement(sPermuted);

      (*evalKeys)[indexList[i]] = MultiKeySwitchGen(
          privateKey, tempPrivateKey, eAuto->find(indexList[i])->second);
    }
  }

  return evalKeys;
}

template <class Element>
shared_ptr<std::map<usint, LPEvalKey<Element>>>
LPAlgorithmMultipartyCKKS<Element>::MultiEvalSumKeyGen(
    const LPPrivateKey<Element> privateKey,
    const shared_ptr<std::map<usint, LPEvalKey<Element>>> eSum) const {
  const shared_ptr<LPCryptoParametersCKKS<Element>> cryptoParamsLWE =
      std::dynamic_pointer_cast<LPCryptoParametersCKKS<Element>>(
          privateKey->GetCryptoParameters());

  const shared_ptr<LPCryptoParameters<Element>> cryptoParams =
      privateKey->GetCryptoParameters();
  const EncodingParams encodingParams = cryptoParams->GetEncodingParams();
  const shared_ptr<typename Element::Params> elementParams =
      cryptoParams->GetElementParams();

  size_t max = ceil(log2(encodingParams->GetBatchSize()));
  std::vector<usint> indices(max);
  usint m = elementParams->GetCyclotomicOrder();

  // generator
  int32_t g = 5;
  usint gFinal = g;

  for (size_t j = 0; j < max; j++) {
    indices[j] = gFinal;
    g = (g * g) % m;

    gFinal = g;
  }

  return MultiEvalAutomorphismKeyGen(privateKey, eSum, indices);
}

template <class Element>
LPEvalKey<Element> LPAlgorithmMultipartyCKKS<Element>::MultiMultEvalKey(
    LPEvalKey<Element> evalKey, LPPrivateKey<Element> sk) const {
  const shared_ptr<LPCryptoParametersCKKS<Element>> cryptoParamsLWE =
      std::dynamic_pointer_cast<LPCryptoParametersCKKS<Element>>(
          evalKey->GetCryptoParameters());

  const shared_ptr<LPCryptoParametersRLWE<Element>> cryptoParams =
      std::static_pointer_cast<LPCryptoParametersRLWE<Element>>(
          evalKey->GetCryptoContext()->GetCryptoParameters());
  const typename Element::DggType &dgg =
      cryptoParams->GetDiscreteGaussianGenerator();
  const shared_ptr<typename Element::Params> elementParams =
      cryptoParams->GetElementParams();

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

    a.push_back(a0[i] * s + f1);
    b.push_back(b0[i] * s + f2);
  }

  evalKeyResult->SetAVector(std::move(a));

  evalKeyResult->SetBVector(std::move(b));

  return evalKeyResult;
}

template <class Element>
shared_ptr<vector<Element>>
LPAlgorithmSHECKKS<Element>::EvalFastRotationPrecomputeBV(
    ConstCiphertext<Element> ciphertext) const {
  std::string errMsg =
      "CKKS EvalFastRotationPrecomputeBV supports only DCRTPoly.";
  PALISADE_THROW(not_implemented_error, errMsg);
}

template <class Element>
shared_ptr<vector<Element>>
LPAlgorithmSHECKKS<Element>::EvalFastRotationPrecomputeGHS(
    ConstCiphertext<Element> ciphertext) const {
  std::string errMsg =
      "CKKS EvalFastRotationPrecomputeGHS supports only DCRTPoly.";
  PALISADE_THROW(not_implemented_error, errMsg);
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalFastRotationBV(
    ConstCiphertext<Element> ciphertext, const usint index, const usint m,
    const shared_ptr<vector<Element>> digits,
    LPEvalKey<DCRTPoly> evalKey) const {
  std::string errMsg = "CKKS EvalFastRotationBV supports only DCRTPoly.";
  PALISADE_THROW(not_implemented_error, errMsg);
}

template <class Element>
Ciphertext<Element> LPAlgorithmSHECKKS<Element>::EvalFastRotationGHS(
    ConstCiphertext<Element> ciphertext, const usint index, const usint m,
    const shared_ptr<vector<Element>> expandedCiphertext,
    LPEvalKey<DCRTPoly> evalKey) const {
  std::string errMsg = "CKKS EvalFastRotationGHS supports only DCRTPoly.";
  PALISADE_THROW(not_available_error, errMsg);
}

// Enable for LPPublicKeyEncryptionSchemeLTV
template <class Element>
void LPPublicKeyEncryptionSchemeCKKS<Element>::Enable(
    PKESchemeFeature feature) {
  switch (feature) {
    case ENCRYPTION:
      if (this->m_algorithmEncryption == nullptr)
        this->m_algorithmEncryption =
            std::make_shared<LPAlgorithmCKKS<Element>>();
      break;
    case PRE:
      if (this->m_algorithmEncryption == nullptr)
        this->m_algorithmEncryption =
            std::make_shared<LPAlgorithmCKKS<Element>>();
      if (this->m_algorithmPRE == nullptr)
        this->m_algorithmPRE = std::make_shared<LPAlgorithmPRECKKS<Element>>();
      break;
    case SHE:
      if (this->m_algorithmEncryption == nullptr)
        this->m_algorithmEncryption =
            std::make_shared<LPAlgorithmCKKS<Element>>();
      if (this->m_algorithmSHE == nullptr)
        this->m_algorithmSHE = std::make_shared<LPAlgorithmSHECKKS<Element>>();
      break;
    case LEVELEDSHE:
      if (this->m_algorithmEncryption == nullptr)
        this->m_algorithmEncryption =
            std::make_shared<LPAlgorithmCKKS<Element>>();
      if (this->m_algorithmLeveledSHE == nullptr)
        this->m_algorithmLeveledSHE =
            std::make_shared<LPLeveledSHEAlgorithmCKKS<Element>>();
      break;
    case MULTIPARTY:
      if (this->m_algorithmEncryption == nullptr)
        this->m_algorithmEncryption =
            std::make_shared<LPAlgorithmCKKS<Element>>();
      if (this->m_algorithmMultiparty == nullptr)
        this->m_algorithmMultiparty =
            std::make_shared<LPAlgorithmMultipartyCKKS<Element>>();
      break;
    case FHE:
      PALISADE_THROW(not_implemented_error,
                     "FHE feature not supported for CKKS scheme");
    case ADVANCEDSHE:
      PALISADE_THROW(not_implemented_error,
                     "ADVANCEDSHE feature not supported for CKKS scheme");
  }
}
}  // namespace lbcrypto

#endif
