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

#include "schemebase/base-leveledshe.h"

#include "key/privatekey.h"
#include "cryptocontext.h"
#include "schemebase/base-scheme.h"

namespace lbcrypto {

/////////////////////////////////////////
// SHE NEGATION
/////////////////////////////////////////

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalNegate(ConstCiphertext<Element> ciphertext) const {
    auto result = ciphertext->Clone();
    EvalNegateInPlace(result);
    return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalNegateInPlace(Ciphertext<Element>& ciphertext) const {
    std::vector<Element>& cv = ciphertext->GetElements();

    for (size_t i = 0; i < cv.size(); i++) {
        cv[i] = cv[i].Negate();
    }
}

/////////////////////////////////////////
// SHE ADDITION
/////////////////////////////////////////

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalAdd(ConstCiphertext<Element> ciphertext1,
                                                     ConstCiphertext<Element> ciphertext2) const {
    auto result = ciphertext1->Clone();
    EvalAddInPlace(result, ciphertext2);
    return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalAddInPlace(Ciphertext<Element>& ciphertext1,
                                             ConstCiphertext<Element> ciphertext2) const {
    EvalAddCoreInPlace(ciphertext1, ciphertext2);
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalAdd(ConstCiphertext<Element> ciphertext,
                                                     ConstPlaintext plaintext) const {
    auto result = ciphertext->Clone();
    EvalAddInPlace(result, plaintext);
    return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalAddInPlace(Ciphertext<Element>& ciphertext, ConstPlaintext plaintext) const {
    std::vector<Element>& cv = ciphertext->GetElements();
    Element pt               = plaintext->GetElement<Element>();
    pt.SetFormat(cv[0].GetFormat());

    cv[0] += pt;
}

/////////////////////////////////////////
// SHE SUBTRACTION
/////////////////////////////////////////

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalSub(ConstCiphertext<Element> ciphertext1,
                                                     ConstCiphertext<Element> ciphertext2) const {
    auto result = ciphertext1->Clone();
    EvalSubInPlace(result, ciphertext2);
    return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalSubInPlace(Ciphertext<Element>& ciphertext1,
                                             ConstCiphertext<Element> ciphertext2) const {
    EvalSubCoreInPlace(ciphertext1, ciphertext2);
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalSub(ConstCiphertext<Element> ciphertext,
                                                     ConstPlaintext plaintext) const {
    auto result = ciphertext->Clone();
    EvalSubInPlace(result, plaintext);
    return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalSubInPlace(Ciphertext<Element>& ciphertext, ConstPlaintext plaintext) const {
    std::vector<Element>& cv = ciphertext->GetElements();
    Element pt               = plaintext->GetElement<Element>();
    pt.SetFormat(cv[0].GetFormat());

    cv[0] -= pt;
}

/////////////////////////////////////////
// SHE MULTIPLICATION
/////////////////////////////////////////

template <class Element>
EvalKey<Element> LeveledSHEBase<Element>::EvalMultKeyGen(const PrivateKey<Element> privateKey) const {
    const auto cc = privateKey->GetCryptoContext();

    PrivateKey<Element> privateKeySquared = std::make_shared<PrivateKeyImpl<Element>>(cc);

    const Element& s = privateKey->GetPrivateElement();

    Element ss = s * s;

    privateKeySquared->SetPrivateElement(std::move(ss));

    auto algo = cc->GetScheme();
    return algo->KeySwitchGen(privateKeySquared, privateKey);
}

template <class Element>
std::vector<EvalKey<Element>> LeveledSHEBase<Element>::EvalMultKeysGen(const PrivateKey<Element> privateKey) const {
    const auto cc           = privateKey->GetCryptoContext();
    const auto cryptoParams = privateKey->GetCryptoParameters();

    PrivateKey<Element> privateKeyPower = std::make_shared<PrivateKeyImpl<Element>>(cc);

    const Element& s = privateKey->GetPrivateElement();

    size_t maxRelinSkDeg = cryptoParams->GetMaxRelinSkDeg() - 1;
    std::vector<Element> sPower(maxRelinSkDeg);

    sPower[0] = s * s;
    for (size_t i = 1; i < maxRelinSkDeg; i++) {
        sPower[i] = sPower[i - 1] * s;
    }

    auto algo = cc->GetScheme();

    std::vector<EvalKey<Element>> evalKeyVec;
    evalKeyVec.reserve(maxRelinSkDeg);

    for (size_t i = 0; i < maxRelinSkDeg; i++) {
        privateKeyPower->SetPrivateElement(std::move(sPower[i]));
        evalKeyVec.push_back(algo->KeySwitchGen(privateKeyPower, privateKey));
    }

    return evalKeyVec;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalMult(ConstCiphertext<Element> ciphertext,
                                                      ConstPlaintext plaintext) const {
    Ciphertext<Element> result = ciphertext->Clone();
    EvalMultInPlace(result, plaintext);
    return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalMultInPlace(Ciphertext<Element>& ciphertext, ConstPlaintext plaintext) const {
    std::vector<Element>& cv = ciphertext->GetElements();
    Element pt               = plaintext->GetElement<Element>();
    pt.SetFormat(Format::EVALUATION);

    for (auto& c : cv) {
        c *= pt;
    }
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalMult(ConstCiphertext<Element> ciphertext1,
                                                      ConstCiphertext<Element> ciphertext2,
                                                      const EvalKey<Element> evalKey) const {
    Ciphertext<Element> ciphertext = EvalMult(ciphertext1, ciphertext2);

    std::vector<Element>& cv = ciphertext->GetElements();
    for (auto& c : cv)
        c.SetFormat(Format::EVALUATION);

    auto algo = ciphertext->GetCryptoContext()->GetScheme();

    std::shared_ptr<std::vector<Element>> ab = algo->KeySwitchCore(cv[2], evalKey);

    cv[0] += (*ab)[0];
    cv[1] += (*ab)[1];

    cv.resize(2);

    return ciphertext;
}

template <class Element>
void LeveledSHEBase<Element>::EvalMultInPlace(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element> ciphertext2,
                                              const EvalKey<Element> evalKey) const {
    ciphertext1 = EvalMult(ciphertext1, ciphertext2);

    std::vector<Element>& cv = ciphertext1->GetElements();
    for (auto& c : cv)
        c.SetFormat(Format::EVALUATION);

    auto algo = ciphertext1->GetCryptoContext()->GetScheme();

    std::shared_ptr<std::vector<Element>> ab = algo->KeySwitchCore(cv[2], evalKey);

    cv[0] += (*ab)[0];
    cv[1] += (*ab)[1];

    cv.resize(2);
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalMultMutable(Ciphertext<Element>& ciphertext1,
                                                             Ciphertext<Element>& ciphertext2,
                                                             const EvalKey<Element> evalKey) const {
    Ciphertext<Element> ciphertext = EvalMultMutable(ciphertext1, ciphertext2);

    std::vector<Element>& cv = ciphertext->GetElements();
    for (auto& c : cv)
        c.SetFormat(Format::EVALUATION);

    auto algo = ciphertext->GetCryptoContext()->GetScheme();

    std::shared_ptr<std::vector<Element>> ab = algo->KeySwitchCore(cv[2], evalKey);

    cv[0] += (*ab)[0];
    cv[1] += (*ab)[1];

    cv.resize(2);

    return ciphertext;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalSquare(ConstCiphertext<Element> ciphertext,
                                                        const EvalKey<Element> evalKey) const {
    Ciphertext<Element> csquare = EvalSquare(ciphertext);

    std::vector<Element>& cv = csquare->GetElements();
    for (auto& c : cv)
        c.SetFormat(Format::EVALUATION);

    auto algo = csquare->GetCryptoContext()->GetScheme();

    std::shared_ptr<std::vector<Element>> ab = algo->KeySwitchCore(cv[2], evalKey);

    cv[0] += (*ab)[0];
    cv[1] += (*ab)[1];

    cv.resize(2);

    return csquare;
}

template <class Element>
void LeveledSHEBase<Element>::EvalSquareInPlace(Ciphertext<Element>& ciphertext, const EvalKey<Element> evalKey) const {
    ciphertext = EvalSquare(ciphertext);

    std::vector<Element>& cv = ciphertext->GetElements();
    for (auto& c : cv)
        c.SetFormat(Format::EVALUATION);

    auto algo = ciphertext->GetCryptoContext()->GetScheme();

    std::shared_ptr<std::vector<Element>> ab = algo->KeySwitchCore(cv[2], evalKey);

    cv[0] += (*ab)[0];
    cv[1] += (*ab)[1];

    cv.resize(2);
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalSquareMutable(Ciphertext<Element>& ciphertext,
                                                               const EvalKey<Element> evalKey) const {
    Ciphertext<Element> csquare = EvalSquareMutable(ciphertext);

    std::vector<Element>& cv = csquare->GetElements();
    for (auto& c : cv)
        c.SetFormat(Format::EVALUATION);

    auto algo = csquare->GetCryptoContext()->GetScheme();

    std::shared_ptr<std::vector<Element>> ab = algo->KeySwitchCore(cv[2], evalKey);

    cv[0] += (*ab)[0];
    cv[1] += (*ab)[1];

    cv.resize(2);

    return csquare;
}

template <class Element>
void LeveledSHEBase<Element>::EvalMultMutableInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2,
                                                     const EvalKey<Element> evalKey) const {
    ciphertext1 = EvalMultMutable(ciphertext1, ciphertext2);

    std::vector<Element>& cv = ciphertext1->GetElements();
    for (auto& c : cv)
        c.SetFormat(Format::EVALUATION);

    auto algo = ciphertext1->GetCryptoContext()->GetScheme();

    std::shared_ptr<std::vector<Element>> ab = algo->KeySwitchCore(cv[2], evalKey);

    cv[0] += (*ab)[0];
    cv[1] += (*ab)[1];

    cv.resize(2);
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalMultAndRelinearize(
    ConstCiphertext<Element> ciphertext1, ConstCiphertext<Element> ciphertext2,
    const std::vector<EvalKey<Element>>& evalKeyVec) const {
    Ciphertext<Element> result = EvalMult(ciphertext1, ciphertext2);
    RelinearizeInPlace(result, evalKeyVec);
    return result;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::Relinearize(ConstCiphertext<Element> ciphertext,
                                                         const std::vector<EvalKey<Element>>& evalKeyVec) const {
    Ciphertext<Element> result = ciphertext->Clone();
    RelinearizeInPlace(result, evalKeyVec);
    return result;
}

template <class Element>
void LeveledSHEBase<Element>::RelinearizeInPlace(Ciphertext<Element>& ciphertext,
                                                 const std::vector<EvalKey<Element>>& evalKeyVec) const {
    std::vector<Element>& cv = ciphertext->GetElements();
    for (auto& c : cv)
        c.SetFormat(Format::EVALUATION);

    auto algo = ciphertext->GetCryptoContext()->GetScheme();

    for (size_t j = 2; j < cv.size(); j++) {
        std::shared_ptr<std::vector<Element>> ab = algo->KeySwitchCore(cv[j], evalKeyVec[j - 2]);
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
    auto algo     = cc->GetScheme();

    const Element& s = privateKey->GetPrivateElement();
    uint32_t N       = s.GetRingDimension();

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
    size_t sz = indexList.size();
#pragma omp parallel for if (sz >= 4)
    for (size_t i = 0; i < sz; ++i) {
        PrivateKey<Element> privateKeyPermuted = std::make_shared<PrivateKeyImpl<Element>>(cc);

        uint32_t index = NativeInteger(indexList[i]).ModInverse(2 * N).ConvertToInt();
        std::vector<uint32_t> vec(N);
        PrecomputeAutoMap(N, index, &vec);

        privateKeyPermuted->SetPrivateElement(s.AutomorphismTransform(index, vec));
        (*evalKeys)[indexList[i]] = algo->KeySwitchGen(privateKey, privateKeyPermuted);
    }

    return evalKeys;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalAutomorphism(ConstCiphertext<Element> ciphertext, usint i,
                                                              const std::map<usint, EvalKey<Element>>& evalKeyMap,
                                                              CALLER_INFO_ARGS_CPP) const {
    // this operation can be performed on 2-element ciphertexts only
    if (ciphertext->NumberCiphertextElements() != 2) {
        OPENFHE_THROW("Ciphertext should be relinearized before.");
    }

    // verify if the key i exists in the evalKeyMap
    auto evalKeyIterator = evalKeyMap.find(i);
    if (evalKeyIterator == evalKeyMap.end()) {
        OPENFHE_THROW("EvalKey for index [" + std::to_string(i) + "] is not found." + CALLER_INFO);
    }
    const std::vector<Element>& cv = ciphertext->GetElements();

    // we already have checks on higher level?
    //  if (cv.size() < 2) {
    //    std::string errorMsg(
    //        std::string("Insufficient number of elements in ciphertext: ") +
    //        std::to_string(cv.size()) + CALLER_INFO);
    //    OPENFHE_THROW( errorMsg);
    //  }

    usint N = cv[0].GetRingDimension();

    //  if (i == 2 * N - 1)
    //    OPENFHE_THROW(
    //                   "conjugation is disabled " + CALLER_INFO);

    //  if (i > 2 * N - 1)
    //    OPENFHE_THROW(
    //        "automorphism indices higher than 2*n are not allowed " + CALLER_INFO);

    std::vector<usint> vec(N);
    PrecomputeAutoMap(N, i, &vec);

    auto algo = ciphertext->GetCryptoContext()->GetScheme();

    Ciphertext<Element> result = ciphertext->Clone();

    algo->KeySwitchInPlace(result, evalKeyIterator->second);

    std::vector<Element>& rcv = result->GetElements();

    rcv[0] = rcv[0].AutomorphismTransform(i, vec);
    rcv[1] = rcv[1].AutomorphismTransform(i, vec);

    return result;
}

template <class Element>
std::shared_ptr<std::vector<Element>> LeveledSHEBase<Element>::EvalFastRotationPrecompute(
    ConstCiphertext<Element> ciphertext) const {
    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    auto algo                       = ciphertext->GetCryptoContext()->GetScheme();

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

    usint autoIndex = FindAutomorphismIndex(index, m);

    auto evalKeyMap = cc->GetEvalAutomorphismKeyMap(ciphertext->GetKeyTag());
    // verify if the key autoIndex exists in the evalKeyMap
    auto evalKeyIterator = evalKeyMap.find(autoIndex);
    if (evalKeyIterator == evalKeyMap.end()) {
        OPENFHE_THROW("EvalKey for index [" + std::to_string(autoIndex) + "] is not found.");
    }
    auto evalKey = evalKeyIterator->second;

    auto algo                       = cc->GetScheme();
    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();

    std::shared_ptr<std::vector<Element>> ba = algo->EvalFastKeySwitchCore(digits, evalKey, cv[0].GetParams());

    const auto cryptoParams = ciphertext->GetCryptoParameters();

    usint N = cryptoParams->GetElementParams()->GetRingDimension();
    std::vector<usint> vec(N);
    PrecomputeAutoMap(N, autoIndex, &vec);

    (*ba)[0] += cv[0];

    (*ba)[0] = (*ba)[0].AutomorphismTransform(autoIndex, vec);
    (*ba)[1] = (*ba)[1].AutomorphismTransform(autoIndex, vec);

    Ciphertext<Element> result = ciphertext->Clone();

    result->SetElements({std::move((*ba)[0]), std::move((*ba)[1])});

    return result;
}

template <class Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> LeveledSHEBase<Element>::EvalAtIndexKeyGen(
    const PublicKey<Element> publicKey, const PrivateKey<Element> privateKey,
    const std::vector<int32_t>& indexList) const {
    const auto cc = privateKey->GetCryptoContext();

    usint M = privateKey->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder();

    std::vector<uint32_t> autoIndices(indexList.size());
    for (size_t i = 0; i < indexList.size(); i++) {
        autoIndices[i] = FindAutomorphismIndex(indexList[i], M);
    }

    return EvalAutomorphismKeyGen(privateKey, autoIndices);
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalAtIndex(ConstCiphertext<Element> ciphertext, int32_t index,
                                                         const std::map<usint, EvalKey<Element>>& evalKeyMap) const {
    const auto cc = ciphertext->GetCryptoContext();

    usint M = ciphertext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder();

    uint32_t autoIndex = FindAutomorphismIndex(index, M);

    return EvalAutomorphism(ciphertext, autoIndex, evalKeyMap);
}

/////////////////////////////////////////
// SHE LEVELED Mod Reduce
/////////////////////////////////////////

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::ComposedEvalMult(ConstCiphertext<Element> ciphertext1,
                                                              ConstCiphertext<Element> ciphertext2,
                                                              const EvalKey<Element> evalKey) const {
    auto algo                      = ciphertext1->GetCryptoContext()->GetScheme();
    Ciphertext<Element> ciphertext = EvalMult(ciphertext1, ciphertext2);
    algo->KeySwitchInPlace(ciphertext, evalKey);
    ModReduceInPlace(ciphertext, BASE_NUM_LEVELS_TO_DROP);
    return ciphertext;
}

/////////////////////////////////////////
// SHE LEVELED Level Reduce
/////////////////////////////////////////

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::LevelReduce(ConstCiphertext<Element> ciphertext,
                                                         const EvalKey<Element> evalKey, size_t levels) const {
    auto result = ciphertext->Clone();
    LevelReduceInPlace(result, evalKey, levels);
    return result;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::MorphPlaintext(ConstPlaintext plaintext,
                                                            ConstCiphertext<Element> ciphertext) const {
    auto result = ciphertext->CloneEmpty();

    result->SetNoiseScaleDeg(plaintext->GetNoiseScaleDeg());
    result->SetLevel(plaintext->GetLevel());
    result->SetScalingFactor(plaintext->GetScalingFactor());
    result->SetScalingFactorInt(plaintext->GetScalingFactorInt());
    result->SetSlots(plaintext->GetSlots());

    Element pt = plaintext->GetElement<Element>();
    pt.SetFormat(EVALUATION);
    result->SetElements({pt});

    return result;
}

/////////////////////////////////////////
// CORE OPERATION
/////////////////////////////////////////
template <class Element>
void LeveledSHEBase<Element>::VerifyNumOfTowers(const ConstCiphertext<Element>& ciphertext1,
                                                const ConstCiphertext<Element>& ciphertext2,
                                                CALLER_INFO_ARGS_CPP) const {
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
void LeveledSHEBase<Element>::VerifyNumOfTowers(const ConstCiphertext<Element>& ciphertext, const Element& plaintext,
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
Ciphertext<Element> LeveledSHEBase<Element>::EvalAddCore(ConstCiphertext<Element> ciphertext1,
                                                         ConstCiphertext<Element> ciphertext2) const {
    auto result = ciphertext1->Clone();
    EvalAddCoreInPlace(result, ciphertext2);
    return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalAddCoreInPlace(Ciphertext<Element>& ciphertext1,
                                                 ConstCiphertext<Element> ciphertext2) const {
    VerifyNumOfTowers(ciphertext1, ciphertext2);
    std::vector<Element>& cv1       = ciphertext1->GetElements();
    const std::vector<Element>& cv2 = ciphertext2->GetElements();

    size_t c1Size     = cv1.size();
    size_t c2Size     = cv2.size();
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
Ciphertext<Element> LeveledSHEBase<Element>::EvalSubCore(ConstCiphertext<Element> ciphertext1,
                                                         ConstCiphertext<Element> ciphertext2) const {
    auto result = ciphertext1->Clone();
    EvalSubCoreInPlace(result, ciphertext2);
    return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalSubCoreInPlace(Ciphertext<Element>& ciphertext1,
                                                 ConstCiphertext<Element> ciphertext2) const {
    VerifyNumOfTowers(ciphertext1, ciphertext2);
    std::vector<Element>& cv1       = ciphertext1->GetElements();
    const std::vector<Element>& cv2 = ciphertext2->GetElements();

    size_t c1Size     = cv1.size();
    size_t c2Size     = cv2.size();
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
Ciphertext<Element> LeveledSHEBase<Element>::EvalMultCore(ConstCiphertext<Element> ciphertext1,
                                                          ConstCiphertext<Element> ciphertext2) const {
    VerifyNumOfTowers(ciphertext1, ciphertext2);
    Ciphertext<Element> result = ciphertext1->CloneZero();

    std::vector<Element> cv1        = ciphertext1->GetElements();
    const std::vector<Element>& cv2 = ciphertext2->GetElements();

    size_t cResultSize = cv1.size() + cv2.size() - 1;
    std::vector<Element> cvMult(cResultSize);

    if (cv1.size() == 2 && cv2.size() == 2) {
        cvMult[2] = (cv1[1] * cv2[1]);
        cvMult[1] = (cv1[1] *= cv2[0]);
        cvMult[0] = (cv2[0] * cv1[0]);
        cvMult[1] += (cv1[0] *= cv2[1]);
    }
    else {
        std::vector<bool> isFirstAdd(cResultSize, true);

        for (size_t i = 0; i < cv1.size(); i++) {
            for (size_t j = 0; j < cv2.size(); j++) {
                if (isFirstAdd[i + j] == true) {
                    cvMult[i + j]     = cv1[i] * cv2[j];
                    isFirstAdd[i + j] = false;
                }
                else {
                    cvMult[i + j] += cv1[i] * cv2[j];
                }
            }
        }
    }

    result->SetElements(std::move(cvMult));
    result->SetNoiseScaleDeg(ciphertext1->GetNoiseScaleDeg() + ciphertext2->GetNoiseScaleDeg());
    result->SetScalingFactor(ciphertext1->GetScalingFactor() * ciphertext2->GetScalingFactor());
    const auto plainMod = ciphertext1->GetCryptoParameters()->GetPlaintextModulus();
    result->SetScalingFactorInt(
        ciphertext1->GetScalingFactorInt().ModMul(ciphertext2->GetScalingFactorInt(), plainMod));
    return result;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalSquareCore(ConstCiphertext<Element> ciphertext) const {
    Ciphertext<Element> result = ciphertext->CloneZero();

    const std::vector<Element>& cv = ciphertext->GetElements();

    size_t cResultSize = 2 * cv.size() - 1;
    std::vector<Element> cvSquare(cResultSize);
    Element cvtemp;
    if (cv.size() == 2) {
        cvSquare[0] = cv[0] * cv[0];
        cvSquare[2] = cv[1] * cv[1];
        cvtemp      = cv[0] * cv[1];
        cvSquare[1] = cvtemp;
        cvSquare[1] += cvtemp;
    }
    else {
        std::vector<bool> isFirstAdd(cResultSize, true);

        for (size_t i = 0; i < cv.size(); i++) {
            for (size_t j = i; j < cv.size(); j++) {
                if (isFirstAdd[i + j] == true) {
                    if (j == i) {
                        cvSquare[i + j] = cv[i] * cv[j];
                    }
                    else {
                        cvtemp          = cv[i] * cv[j];
                        cvSquare[i + j] = cvtemp;
                        cvSquare[i + j] += cvtemp;
                    }
                    isFirstAdd[i + j] = false;
                }
                else {
                    if (j == i) {
                        cvSquare[i + j] += cv[i] * cv[j];
                    }
                    else {
                        cvtemp = cv[i] * cv[j];
                        cvSquare[i + j] += cvtemp;
                        cvSquare[i + j] += cvtemp;
                    }
                }
            }
        }
    }

    result->SetElements(std::move(cvSquare));
    result->SetNoiseScaleDeg(2 * ciphertext->GetNoiseScaleDeg());
    result->SetScalingFactor(ciphertext->GetScalingFactor() * ciphertext->GetScalingFactor());
    const auto plainMod = ciphertext->GetCryptoParameters()->GetPlaintextModulus();
    result->SetScalingFactorInt(ciphertext->GetScalingFactorInt().ModMul(ciphertext->GetScalingFactorInt(), plainMod));
    return result;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalAddCore(ConstCiphertext<Element> ciphertext, const Element& pt) const {
    Ciphertext<Element> result = ciphertext->Clone();
    EvalAddCoreInPlace(result, pt);
    return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalAddCoreInPlace(Ciphertext<Element>& ciphertext, const Element& pt) const {
    VerifyNumOfTowers(ciphertext, pt);
    std::vector<Element>& cv = ciphertext->GetElements();
    cv[0] += pt;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalSubCore(ConstCiphertext<Element> ciphertext, const Element& pt) const {
    Ciphertext<Element> result = ciphertext->Clone();
    EvalSubCoreInPlace(result, pt);
    return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalSubCoreInPlace(Ciphertext<Element>& ciphertext, const Element& pt) const {
    VerifyNumOfTowers(ciphertext, pt);
    std::vector<Element>& cv = ciphertext->GetElements();
    cv[0] -= pt;
}

template <class Element>
Ciphertext<Element> LeveledSHEBase<Element>::EvalMultCore(ConstCiphertext<Element> ciphertext,
                                                          const Element& pt) const {
    Ciphertext<Element> result = ciphertext->Clone();
    EvalMultCoreInPlace(result, pt);
    return result;
}

template <class Element>
void LeveledSHEBase<Element>::EvalMultCoreInPlace(Ciphertext<Element>& ciphertext, const Element& pt) const {
    VerifyNumOfTowers(ciphertext, pt);
    std::vector<Element>& cv = ciphertext->GetElements();
    for (auto& c : cv) {
        c *= pt;
    }
}

}  // namespace lbcrypto

// the code below is from base-leveledshe-impl.cpp
namespace lbcrypto {

// template class LeveledSHEBase<Poly>;
// template class LeveledSHEBase<NativePoly>;
template class LeveledSHEBase<DCRTPoly>;

}  // namespace lbcrypto
