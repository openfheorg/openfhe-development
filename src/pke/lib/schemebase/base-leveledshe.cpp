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

#include "cryptocontext.h"
#include "key/privatekey.h"
#include "schemebase/base-leveledshe.h"
#include "schemebase/base-scheme.h"

#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {

/////////////////////////////////////////
// SHE NEGATION
/////////////////////////////////////////

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalNegate(ConstCiphertext<Element>& ciphertext) const {
    auto result = ciphertext->Clone();
    EvalNegateInPlace(result);
    return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalNegateInPlace(Ciphertext<Element>& ciphertext) const {
    for (auto& c : ciphertext->GetElements())
        c = c.Negate();
}

/////////////////////////////////////////
// SHE ADDITION
/////////////////////////////////////////

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalAdd(ConstCiphertext<Element>& ciphertext1,
                                                     ConstCiphertext<Element>& ciphertext2) const {
    auto result = ciphertext1->Clone();
    EvalAddInPlace(result, ciphertext2);
    return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalAddInPlace(Ciphertext<Element>& ciphertext1,
                                             ConstCiphertext<Element>& ciphertext2) const {
    EvalAddCoreInPlace(ciphertext1, ciphertext2);
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalAdd(ConstCiphertext<Element>& ciphertext,
                                                     ConstPlaintext& plaintext) const {
    auto result = ciphertext->Clone();
    EvalAddInPlace(result, plaintext);
    return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalAddInPlace(Ciphertext<Element>& ciphertext, ConstPlaintext& plaintext) const {
    auto& cv = ciphertext->GetElements();
    auto pt  = plaintext->GetElement<Element>();
    pt.SetFormat(cv[0].GetFormat());
    cv[0] += pt;
}

/////////////////////////////////////////
// SHE SUBTRACTION
/////////////////////////////////////////

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalSub(ConstCiphertext<Element>& ciphertext1,
                                                     ConstCiphertext<Element>& ciphertext2) const {
    auto result = ciphertext1->Clone();
    EvalSubInPlace(result, ciphertext2);
    return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalSubInPlace(Ciphertext<Element>& ciphertext1,
                                             ConstCiphertext<Element>& ciphertext2) const {
    EvalSubCoreInPlace(ciphertext1, ciphertext2);
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalSub(ConstCiphertext<Element>& ciphertext,
                                                     ConstPlaintext& plaintext) const {
    auto result = ciphertext->Clone();
    EvalSubInPlace(result, plaintext);
    return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalSubInPlace(Ciphertext<Element>& ciphertext, ConstPlaintext& plaintext) const {
    auto& cv = ciphertext->GetElements();
    auto pt  = plaintext->GetElement<Element>();
    pt.SetFormat(cv[0].GetFormat());
    cv[0] -= pt;
}

/////////////////////////////////////////
// SHE MULTIPLICATION
/////////////////////////////////////////

template <class Element>
EvalKey<Element> LeveledSHEBase<Element>::EvalMultKeyGen(const PrivateKey<Element> privateKey) const {
    const auto cc = privateKey->GetCryptoContext();
    const auto& s = privateKey->GetPrivateElement();

    auto privateKeySquared = std::make_shared<PrivateKeyImpl<Element>>(cc);
    privateKeySquared->SetPrivateElement(s * s);

    return cc->GetScheme()->KeySwitchGen(privateKeySquared, privateKey);
}

template <class Element>
std::vector<EvalKey<Element>> LeveledSHEBase<Element>::EvalMultKeysGen(const PrivateKey<Element> privateKey) const {
    const auto cc = privateKey->GetCryptoContext();
    const auto& s = privateKey->GetPrivateElement();

    auto privateKeyPower = std::make_shared<PrivateKeyImpl<Element>>(cc);
    privateKeyPower->SetPrivateElement(s);

    size_t maxRelinSkDeg = privateKey->GetCryptoParameters()->GetMaxRelinSkDeg() - 1;
    std::vector<EvalKey<Element>> evalKeyVec;
    evalKeyVec.reserve(maxRelinSkDeg);
    for (size_t i = 0; i < maxRelinSkDeg; ++i) {
        privateKeyPower->SetPrivateElement(s * privateKeyPower->GetPrivateElement());
        evalKeyVec.emplace_back(cc->GetScheme()->KeySwitchGen(privateKeyPower, privateKey));
    }

    return evalKeyVec;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalMult(ConstCiphertext<Element>& ciphertext,
                                                      ConstPlaintext& plaintext) const {
    auto result = ciphertext->Clone();
    EvalMultInPlace(result, plaintext);
    return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalMultInPlace(Ciphertext<Element>& ciphertext, ConstPlaintext& plaintext) const {
    auto pt = plaintext->GetElement<Element>();
    pt.SetFormat(Format::EVALUATION);
    for (auto& c : ciphertext->GetElements())
        c *= pt;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalMult(ConstCiphertext<Element>& ciphertext1,
                                                      ConstCiphertext<Element>& ciphertext2,
                                                      const EvalKey<Element> evalKey) const {
    auto ciphertext = EvalMult(ciphertext1, ciphertext2);

    auto& cv = ciphertext->GetElements();
    for (auto& c : cv)
        c.SetFormat(Format::EVALUATION);

    auto ab = ciphertext->GetCryptoContext()->GetScheme()->KeySwitchCore(cv[2], evalKey);

    cv[0] += (*ab)[0];
    cv[1] += (*ab)[1];

    cv.resize(2);

    return ciphertext;
}

template <class Element>
void LeveledSHEBase<Element>::EvalMultInPlace(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2,
                                              const EvalKey<Element> evalKey) const {
    ciphertext1 = EvalMult(ciphertext1, ciphertext2);

    auto& cv = ciphertext1->GetElements();
    for (auto& c : cv)
        c.SetFormat(Format::EVALUATION);

    auto ab = ciphertext1->GetCryptoContext()->GetScheme()->KeySwitchCore(cv[2], evalKey);

    cv[0] += (*ab)[0];
    cv[1] += (*ab)[1];

    cv.resize(2);
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalMultMutable(Ciphertext<Element>& ciphertext1,
                                                             Ciphertext<Element>& ciphertext2,
                                                             const EvalKey<Element> evalKey) const {
    auto ciphertext = EvalMultMutable(ciphertext1, ciphertext2);

    auto& cv = ciphertext->GetElements();
    for (auto& c : cv)
        c.SetFormat(Format::EVALUATION);

    auto ab = ciphertext->GetCryptoContext()->GetScheme()->KeySwitchCore(cv[2], evalKey);

    cv[0] += (*ab)[0];
    cv[1] += (*ab)[1];

    cv.resize(2);

    return ciphertext;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalSquare(ConstCiphertext<Element>& ciphertext,
                                                        const EvalKey<Element> evalKey) const {
    auto csquare = EvalSquare(ciphertext);

    auto& cv = csquare->GetElements();
    for (auto& c : cv)
        c.SetFormat(Format::EVALUATION);

    auto ab = csquare->GetCryptoContext()->GetScheme()->KeySwitchCore(cv[2], evalKey);

    cv[0] += (*ab)[0];
    cv[1] += (*ab)[1];

    cv.resize(2);

    return csquare;
}

template <class Element>
void LeveledSHEBase<Element>::EvalSquareInPlace(Ciphertext<Element>& ciphertext, const EvalKey<Element> evalKey) const {
    ciphertext = EvalSquare(ciphertext);

    auto& cv = ciphertext->GetElements();
    for (auto& c : cv)
        c.SetFormat(Format::EVALUATION);

    auto ab = ciphertext->GetCryptoContext()->GetScheme()->KeySwitchCore(cv[2], evalKey);

    cv[0] += (*ab)[0];
    cv[1] += (*ab)[1];

    cv.resize(2);
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalSquareMutable(Ciphertext<Element>& ciphertext,
                                                               const EvalKey<Element> evalKey) const {
    auto csquare = EvalSquareMutable(ciphertext);

    auto& cv = csquare->GetElements();
    for (auto& c : cv)
        c.SetFormat(Format::EVALUATION);

    auto ab = csquare->GetCryptoContext()->GetScheme()->KeySwitchCore(cv[2], evalKey);

    cv[0] += (*ab)[0];
    cv[1] += (*ab)[1];

    cv.resize(2);

    return csquare;
}

template <class Element>
void LeveledSHEBase<Element>::EvalMultMutableInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2,
                                                     const EvalKey<Element> evalKey) const {
    ciphertext1 = EvalMultMutable(ciphertext1, ciphertext2);

    auto& cv = ciphertext1->GetElements();
    for (auto& c : cv)
        c.SetFormat(Format::EVALUATION);

    auto ab = ciphertext1->GetCryptoContext()->GetScheme()->KeySwitchCore(cv[2], evalKey);

    cv[0] += (*ab)[0];
    cv[1] += (*ab)[1];

    cv.resize(2);
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalMultAndRelinearize(
    ConstCiphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2,
    const std::vector<EvalKey<Element>>& evalKeyVec) const {
    auto result = EvalMult(ciphertext1, ciphertext2);
    RelinearizeInPlace(result, evalKeyVec);
    return result;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::Relinearize(ConstCiphertext<Element>& ciphertext,
                                                         const std::vector<EvalKey<Element>>& evalKeyVec) const {
    auto result = ciphertext->Clone();
    RelinearizeInPlace(result, evalKeyVec);
    return result;
}

template <class Element>
void LeveledSHEBase<Element>::RelinearizeInPlace(Ciphertext<Element>& ciphertext,
                                                 const std::vector<EvalKey<Element>>& evalKeyVec) const {
    auto& cv = ciphertext->GetElements();
    for (auto& c : cv)
        c.SetFormat(Format::EVALUATION);

    auto algo = ciphertext->GetCryptoContext()->GetScheme();

    for (size_t j = 2; j < cv.size(); ++j) {
        auto ab = algo->KeySwitchCore(cv[j], evalKeyVec[j - 2]);
        cv[0] += (*ab)[0];
        cv[1] += (*ab)[1];
    }
    cv.resize(2);
}

/////////////////////////////////////////
// SHE AUTOMORPHISM
/////////////////////////////////////////

template <class Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> LeveledSHEBase<Element>::EvalAutomorphismKeyGen(
    const PrivateKey<Element> privateKey, const std::vector<uint32_t>& indexList) const {
    // we already have checks on higher level?
    //  auto it = std::find(indexList.begin(), indexList.end(), 2 * n - 1);
    //  if (it != indexList.end())
    //    OPENFHE_THROW("conjugation is disabled");

    const auto cc = privateKey->GetCryptoContext();
    const auto& s = privateKey->GetPrivateElement();

    uint32_t N = s.GetRingDimension();
    uint32_t M = 2 * N;

    // we already have checks on higher level?
    //  if (indexList.size() > N - 1)
    //    OPENFHE_THROW("size exceeds the ring dimension");

    // create and initialize the key map (key is a value from indexList, EvalKey is nullptr). in this case
    // we should be able to assign values to the map without using "omp critical" as all evalKeys' elements would
    // have already been created
    auto evalKeys = std::make_shared<std::map<uint32_t, EvalKey<Element>>>();
    for (auto indx : indexList) {
        (*evalKeys)[indx];
    }
    const size_t sz = indexList.size();
#pragma omp parallel for
    for (size_t i = 0; i < sz; ++i) {
        auto privateKeyPermuted = std::make_shared<PrivateKeyImpl<Element>>(cc);

        uint32_t index = NativeInteger(indexList[i]).ModInverse(M).ConvertToInt();
        std::vector<uint32_t> vec(N);
        PrecomputeAutoMap(N, index, &vec);

        privateKeyPermuted->SetPrivateElement(s.AutomorphismTransform(index, vec));
        (*evalKeys)[indexList[i]] = cc->GetScheme()->KeySwitchGen(privateKey, privateKeyPermuted);
    }

    return evalKeys;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalAutomorphism(ConstCiphertext<Element>& ciphertext, uint32_t i,
                                                              const std::map<uint32_t, EvalKey<Element>>& evalKeyMap,
                                                              CALLER_INFO_ARGS_CPP) const {
    // this operation can be performed on 2-element ciphertexts only
    if (ciphertext->NumberCiphertextElements() != 2)
        OPENFHE_THROW("Ciphertext should be relinearized before.");

    // verify if the key i exists in the evalKeyMap
    auto evalKeyIterator = evalKeyMap.find(i);
    if (evalKeyIterator == evalKeyMap.end())
        OPENFHE_THROW("EvalKey for index [" + std::to_string(i) + "] is not found." + CALLER_INFO);

    // we already have checks on higher level?
    //  if (cv.size() < 2) {
    //    std::string errorMsg(
    //        std::string("Insufficient number of elements in ciphertext: ") +
    //        std::to_string(cv.size()) + CALLER_INFO);
    //    OPENFHE_THROW( errorMsg);
    //  }

    uint32_t N = ciphertext->GetElements()[0].GetRingDimension();

    //  if (i == 2 * N - 1)
    //    OPENFHE_THROW(
    //                   "conjugation is disabled " + CALLER_INFO);

    //  if (i > 2 * N - 1)
    //    OPENFHE_THROW(
    //        "automorphism indices higher than 2*n are not allowed " + CALLER_INFO);

    auto result = ciphertext->Clone();
    ciphertext->GetCryptoContext()->GetScheme()->KeySwitchInPlace(result, evalKeyIterator->second);

    std::vector<uint32_t> vec(N);
    PrecomputeAutoMap(N, i, &vec);

    auto& rcv = result->GetElements();
    rcv[0]    = rcv[0].AutomorphismTransform(i, vec);
    rcv[1]    = rcv[1].AutomorphismTransform(i, vec);
    return result;
}

template <class Element>
std::shared_ptr<std::vector<Element>> LeveledSHEBase<Element>::EvalFastRotationPrecompute(
    ConstCiphertext<Element>& ciphertext) const {
    const auto& cv = ciphertext->GetElements();
    auto& algo     = ciphertext->GetCryptoContext()->GetScheme();
    return algo->EvalKeySwitchPrecomputeCore(cv[1], ciphertext->GetCryptoParameters());
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalFastRotation(
    ConstCiphertext<Element>& ciphertext, const uint32_t index, const uint32_t m,
    const std::shared_ptr<std::vector<Element>> digits) const {
    if (index == 0)
        return ciphertext->Clone();

    uint32_t autoIndex   = FindAutomorphismIndex(index, m);
    const auto cc        = ciphertext->GetCryptoContext();
    auto evalKeyMap      = cc->GetEvalAutomorphismKeyMap(ciphertext->GetKeyTag());
    auto evalKeyIterator = evalKeyMap.find(autoIndex);
    if (evalKeyIterator == evalKeyMap.end())
        OPENFHE_THROW("EvalKey for index [" + std::to_string(autoIndex) + "] is not found.");
    auto evalKey = evalKeyIterator->second;

    const auto cryptoParams = ciphertext->GetCryptoParameters();

    uint32_t N = cryptoParams->GetElementParams()->GetRingDimension();
    std::vector<uint32_t> vec(N);
    PrecomputeAutoMap(N, autoIndex, &vec);

    const auto& cv = ciphertext->GetElements();

    auto ba = cc->GetScheme()->EvalFastKeySwitchCore(digits, evalKey, cv[0].GetParams());
    (*ba)[0] += cv[0];
    (*ba)[0] = (*ba)[0].AutomorphismTransform(autoIndex, vec);
    (*ba)[1] = (*ba)[1].AutomorphismTransform(autoIndex, vec);

    auto result = ciphertext->Clone();
    result->SetElements({std::move((*ba)[0]), std::move((*ba)[1])});
    return result;
}

template <class Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> LeveledSHEBase<Element>::EvalAtIndexKeyGen(
    const PublicKey<Element> publicKey, const PrivateKey<Element> privateKey,
    const std::vector<int32_t>& indexList) const {
    uint32_t M = privateKey->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder();
    std::vector<uint32_t> autoIndices(indexList.size());
    for (size_t i = 0; i < indexList.size(); i++)
        autoIndices[i] = FindAutomorphismIndex(indexList[i], M);
    return EvalAutomorphismKeyGen(privateKey, autoIndices);
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalAtIndex(ConstCiphertext<Element>& ciphertext, int32_t index,
                                                         const std::map<uint32_t, EvalKey<Element>>& evalKeyMap) const {
    uint32_t M = ciphertext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder();
    return EvalAutomorphism(ciphertext, FindAutomorphismIndex(index, M), evalKeyMap);
}

/////////////////////////////////////////
// SHE LEVELED Mod Reduce
/////////////////////////////////////////

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::ComposedEvalMult(ConstCiphertext<Element>& ciphertext1,
                                                              ConstCiphertext<Element>& ciphertext2,
                                                              const EvalKey<Element> evalKey) const {
    auto ciphertext = EvalMult(ciphertext1, ciphertext2);
    ciphertext->GetCryptoContext()->GetScheme()->KeySwitchInPlace(ciphertext, evalKey);
    ModReduceInPlace(ciphertext, BASE_NUM_LEVELS_TO_DROP);
    return ciphertext;
}

/////////////////////////////////////////
// SHE LEVELED Level Reduce
/////////////////////////////////////////

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::LevelReduce(ConstCiphertext<Element>& ciphertext,
                                                         const EvalKey<Element> evalKey, size_t levels) const {
    auto result = ciphertext->Clone();
    LevelReduceInPlace(result, evalKey, levels);
    return result;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::MorphPlaintext(ConstPlaintext& plaintext,
                                                            ConstCiphertext<Element>& ciphertext) const {
    auto elem = plaintext->GetElement<Element>();
    elem.SetFormat(EVALUATION);

    auto result = ciphertext->CloneEmpty();
    result->SetElement(std::move(elem));
    result->SetSlots(plaintext->GetSlots());
    result->SetLevel(plaintext->GetLevel());
    result->SetNoiseScaleDeg(plaintext->GetNoiseScaleDeg());
    result->SetScalingFactor(plaintext->GetScalingFactor());
    result->SetScalingFactorInt(plaintext->GetScalingFactorInt());
    return result;
}

/////////////////////////////////////////
// CORE OPERATION
/////////////////////////////////////////

template <class Element>
void LeveledSHEBase<Element>::VerifyNumOfTowers(ConstCiphertext<Element>& ciphertext1,
                                                ConstCiphertext<Element>& ciphertext2, CALLER_INFO_ARGS_CPP) const {
    uint32_t numTowers1 = ciphertext1->GetElements()[0].GetNumOfElements();
    uint32_t numTowers2 = ciphertext2->GetElements()[0].GetNumOfElements();
    if (numTowers1 != numTowers2) {
        std::string errorMsg(std::string("Number of towers is not the same for ciphertext1 [") +
                             std::to_string(numTowers1) + "] and for ciphertext2 [" + std::to_string(numTowers2) +
                             "] " + CALLER_INFO);
        OPENFHE_THROW(errorMsg);
    }
}
template <class Element>
void LeveledSHEBase<Element>::VerifyNumOfTowers(ConstCiphertext<Element>& ciphertext, const Element& plaintext,
                                                CALLER_INFO_ARGS_CPP) const {
    uint32_t numTowersCtxt = ciphertext->GetElements()[0].GetNumOfElements();
    uint32_t numTowersPtxt = plaintext.GetNumOfElements();
    if (numTowersCtxt != numTowersPtxt) {
        std::string errorMsg(std::string("Number of towers is not the same for ciphertext[") +
                             std::to_string(numTowersCtxt) + "] and for plaintext[" + std::to_string(numTowersPtxt) +
                             "]" + CALLER_INFO);
        OPENFHE_THROW(errorMsg);
    }
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalAddCore(ConstCiphertext<Element>& ciphertext1,
                                                         ConstCiphertext<Element>& ciphertext2) const {
    auto result = ciphertext1->Clone();
    EvalAddCoreInPlace(result, ciphertext2);
    return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalAddCoreInPlace(Ciphertext<Element>& ciphertext1,
                                                 ConstCiphertext<Element>& ciphertext2) const {
    VerifyNumOfTowers(ciphertext1, ciphertext2);
    auto& cv1 = ciphertext1->GetElements();
    auto& cv2 = ciphertext2->GetElements();

    uint32_t c1Size     = cv1.size();
    uint32_t c2Size     = cv2.size();
    uint32_t cSmallSize = std::min(c1Size, c2Size);

    cv1.reserve(c2Size);
    uint32_t i = 0;
    for (; i < cSmallSize; ++i)
        cv1[i] += cv2[i];
    for (; i < c2Size; ++i)
        cv1.emplace_back(cv2[i]);
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalSubCore(ConstCiphertext<Element>& ciphertext1,
                                                         ConstCiphertext<Element>& ciphertext2) const {
    auto result = ciphertext1->Clone();
    EvalSubCoreInPlace(result, ciphertext2);
    return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalSubCoreInPlace(Ciphertext<Element>& ciphertext1,
                                                 ConstCiphertext<Element>& ciphertext2) const {
    VerifyNumOfTowers(ciphertext1, ciphertext2);
    auto& cv1 = ciphertext1->GetElements();
    auto& cv2 = ciphertext2->GetElements();

    uint32_t c1Size     = cv1.size();
    uint32_t c2Size     = cv2.size();
    uint32_t cSmallSize = std::min(c1Size, c2Size);

    cv1.reserve(c2Size);
    uint32_t i = 0;
    for (; i < cSmallSize; ++i)
        cv1[i] -= cv2[i];
    for (; i < c2Size; ++i)
        cv1.emplace_back(cv2[i].Negate());
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalMultCore(ConstCiphertext<Element>& ctxt1,
                                                          ConstCiphertext<Element>& ctxt2) const {
    VerifyNumOfTowers(ctxt1, ctxt2);
    auto& cv1 = ctxt1->GetElements();
    auto& cv2 = ctxt2->GetElements();

    uint32_t n1 = cv1.size();
    uint32_t n2 = cv2.size();
    uint32_t nr = n1 + n2 - 1;

    std::vector<DCRTPoly> cvr;
    cvr.reserve(nr);
    if (n1 == 2 && n2 == 2) {
        cvr.emplace_back(cv1[0] * cv2[0]);
        cvr.emplace_back((cv1[0] * cv2[1]) += (cv1[1] * cv2[0]));
        cvr.emplace_back(cv1[1] * cv2[1]);
    }
    else {
        uint32_t m = 0;
        for (uint32_t i = 0; i < n1; ++i) {
            auto& cv1i = cv1[i];
            for (uint32_t j = 0, k = i; j < n2; ++j, ++k) {
                if (k == m) {
                    cvr.emplace_back(cv1i * cv2[j]);
                    ++m;
                }
                else {
                    cvr[k] += (cv1i * cv2[j]);
                }
            }
        }
    }

    auto result = ctxt1->CloneEmpty();
    result->SetElements(std::move(cvr));
    result->SetNoiseScaleDeg(ctxt1->GetNoiseScaleDeg() + ctxt2->GetNoiseScaleDeg());
    result->SetScalingFactor(ctxt1->GetScalingFactor() * ctxt2->GetScalingFactor());
    result->SetScalingFactorInt(ctxt1->GetScalingFactorInt().ModMul(
        ctxt2->GetScalingFactorInt(), ctxt1->GetCryptoParameters()->GetPlaintextModulus()));
    return result;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalSquareCore(ConstCiphertext<Element>& ctxt) const {
    const auto& cv = ctxt->GetElements();

    uint32_t n  = cv.size();
    uint32_t nr = (n << 1) - 1;

    std::vector<DCRTPoly> cvr;
    cvr.reserve(nr);
    if (n == 2) {
        cvr.emplace_back(cv[0] * cv[0]);
        cvr.emplace_back(cv[0] * cv[1]);
        cvr.back() += cvr.back();
        cvr.emplace_back(cv[1] * cv[1]);
    }
    else {
        DCRTPoly cvt;
        uint32_t m = 0;
        for (uint32_t i = 0; i < n; ++i) {
            auto& cvi = cv[i];
            for (uint32_t j = i, k = 2 * i; j < n; ++j, ++k) {
                if (j == i) {
                    if (k == m) {
                        cvr.emplace_back(cvi * cvi);
                        ++m;
                    }
                    else {
                        cvr[k] += (cvi * cvi);
                    }
                }
                else {
                    if (k == m) {
                        cvr.emplace_back(cvi * cv[j]);
                        cvr.back() += cvr.back();
                        ++m;
                    }
                    else {
                        cvt = (cvi * cv[j]);
                        cvr[k] += (cvt += cvt);
                    }
                }
            }
        }
    }

    auto result = ctxt->CloneEmpty();
    result->SetElements(std::move(cvr));
    result->SetNoiseScaleDeg(2 * ctxt->GetNoiseScaleDeg());
    result->SetScalingFactor(ctxt->GetScalingFactor() * ctxt->GetScalingFactor());
    result->SetScalingFactorInt(ctxt->GetScalingFactorInt().ModMul(ctxt->GetScalingFactorInt(),
                                                                   ctxt->GetCryptoParameters()->GetPlaintextModulus()));
    return result;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalAddCore(ConstCiphertext<Element>& ciphertext,
                                                         const Element& pt) const {
    auto result = ciphertext->Clone();
    EvalAddCoreInPlace(result, pt);
    return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalAddCoreInPlace(Ciphertext<Element>& ciphertext, const Element& pt) const {
    VerifyNumOfTowers(ciphertext, pt);
    ciphertext->GetElements()[0] += pt;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalSubCore(ConstCiphertext<Element>& ciphertext,
                                                         const Element& pt) const {
    auto result = ciphertext->Clone();
    EvalSubCoreInPlace(result, pt);
    return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalSubCoreInPlace(Ciphertext<Element>& ciphertext, const Element& pt) const {
    VerifyNumOfTowers(ciphertext, pt);
    ciphertext->GetElements()[0] -= pt;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalMultCore(ConstCiphertext<Element>& ciphertext,
                                                          const Element& pt) const {
    auto result = ciphertext->Clone();
    EvalMultCoreInPlace(result, pt);
    return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalMultCoreInPlace(Ciphertext<Element>& ciphertext, const Element& pt) const {
    VerifyNumOfTowers(ciphertext, pt);
    for (auto& c : ciphertext->GetElements())
        c *= pt;
}

}  // namespace lbcrypto

// the code below is from base-leveledshe-impl.cpp
namespace lbcrypto {

// template class LeveledSHEBase<Poly>;
// template class LeveledSHEBase<NativePoly>;
template class LeveledSHEBase<DCRTPoly>;

}  // namespace lbcrypto
