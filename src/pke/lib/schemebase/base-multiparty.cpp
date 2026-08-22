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
#include "key/evalkey.h"
#include "key/evalkeyrelin.h"
#include "key/privatekey.h"
#include "key/publickey.h"
#include "schemebase/base-multiparty.h"
#include "schemebase/base-pke.h"
#include "schemebase/base-scheme.h"
#include "schemebase/rlwe-cryptoparameters.h"

#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <utility>
#include <vector>

namespace lbcrypto {

// makeSparse is not used by this scheme
template <class Element>
KeyPair<Element> MultipartyBase<Element>::MultipartyKeyGen(CryptoContext<Element> cc,
                                                           const std::vector<PrivateKey<Element>>& privateKeyVec,
                                                           bool makeSparse) {
    const auto cryptoParams  = std::dynamic_pointer_cast<CryptoParametersRLWE<Element>>(cc->GetCryptoParameters());
    const auto elementParams = cryptoParams->GetElementParams();

    // Private Key Generation

    Element s(elementParams, Format::EVALUATION, true);
    for (auto& pk : privateKeyVec)
        s += pk->GetPrivateElement();

    // Public Key Generation

    DugType dug;
    Element a(dug, elementParams, Format::EVALUATION);

    Element e(cryptoParams->GetDiscreteGaussianGenerator(), elementParams, Format::EVALUATION);
    NativeInteger ns = cryptoParams->GetNoiseScale();

    // b = ns * e - a * s
    if (ns != 1)
        e *= ns;
    Element b(std::move(e -= a * s));

    KeyPair<Element> keyPair(std::make_shared<PublicKeyImpl<Element>>(cc),
                             std::make_shared<PrivateKeyImpl<Element>>(cc));
    keyPair.secretKey->SetPrivateElement(std::move(s));
    std::vector<Element> pkElems;
    pkElems.reserve(2);
    pkElems.push_back(std::move(b));
    pkElems.push_back(std::move(a));
    keyPair.publicKey->SetPublicElements(std::move(pkElems));
    return keyPair;
}

template <class Element>
KeyPair<Element> MultipartyBase<Element>::MultipartyKeyGen(CryptoContext<Element> cc,
                                                           const PublicKey<Element> publicKey, bool makeSparse,
                                                           bool fresh) {
    const auto cryptoParams  = std::dynamic_pointer_cast<CryptoParametersRLWE<Element>>(cc->GetCryptoParameters());
    const auto elementParams = cryptoParams->GetElementParams();
    const auto paramsPK      = cryptoParams->GetParamsPK();
    if (!paramsPK)
        OPENFHE_THROW("PrecomputeCRTTables() must be called before using precomputed params.");

    const DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
    TugType tug;

    Element s;
    switch (cryptoParams->GetSecretKeyDist()) {
        case GAUSSIAN:
            s = Element(dgg, paramsPK, Format::EVALUATION);
            break;
        case UNIFORM_TERNARY:
            s = Element(tug, paramsPK, Format::EVALUATION);
            break;
        case SPARSE_TERNARY:
        case SPARSE_ENCAPSULATED:
            s = Element(tug, paramsPK, Format::EVALUATION, 192);
            break;
        default:
            OPENFHE_THROW("Unknown SecretKeyDist.");
    }

    const auto& pk = publicKey->GetPublicElements();
    Element a(pk[1]);
    Element e(dgg, paramsPK, Format::EVALUATION);
    NativeInteger ns = cryptoParams->GetNoiseScale();

    // b = ns * e - a * s
    // When PRE is not used, a joint key is computed
    if (ns != 1)
        e *= ns;
    Element b(std::move(e -= a * s));
    if (!fresh)
        b += pk[0];

    auto sizeQ  = elementParams->GetParams().size();
    auto sizePK = paramsPK->GetParams().size();
    if (sizePK > sizeQ)
        s.DropLastElements(sizePK - sizeQ);

    KeyPair<Element> keyPair(std::make_shared<PublicKeyImpl<Element>>(cc),
                             std::make_shared<PrivateKeyImpl<Element>>(cc));
    keyPair.secretKey->SetPrivateElement(std::move(s));
    std::vector<Element> pkElems;
    pkElems.reserve(2);
    pkElems.push_back(std::move(b));
    pkElems.push_back(std::move(a));
    keyPair.publicKey->SetPublicElements(std::move(pkElems));
    return keyPair;
}

template <class Element>
EvalKey<Element> MultipartyBase<Element>::MultiKeySwitchGen(const PrivateKey<Element> oldPrivateKey,
                                                            const PrivateKey<Element> newPrivateKey,
                                                            const EvalKey<Element> evalKey) const {
    return oldPrivateKey->GetCryptoContext()->GetScheme()->KeySwitchGen(oldPrivateKey, newPrivateKey, evalKey);
}

template <class Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> MultipartyBase<Element>::MultiEvalAutomorphismKeyGen(
    const PrivateKey<Element> privateKey, const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> evalKeyMap,
    const std::vector<uint32_t>& indexList) const {
    const Element& s = privateKey->GetPrivateElement();
    uint32_t N       = s.GetRingDimension();

    if (indexList.size() > N - 1)
        OPENFHE_THROW("size exceeds the ring dimension");

    const auto cc = privateKey->GetCryptoContext();

    // deduplicated work list; the base keys are looked up (and missing ones reported) before
    // the parallel loop because an exception may not cross an OpenMP region boundary
    const std::set<uint32_t> indexSet(indexList.begin(), indexList.end());
    const std::vector<uint32_t> indices(indexSet.begin(), indexSet.end());
    const uint32_t sz = indices.size();
    std::vector<EvalKey<Element>> baseKeys(sz);
    for (uint32_t i = 0; i < sz; ++i) {
        auto evalKeyIterator = evalKeyMap->find(indices[i]);
        if (evalKeyIterator == evalKeyMap->end()) {
            OPENFHE_THROW("EvalKey for index [" + std::to_string(indices[i]) + "] is not found.");
        }
        baseKeys[i] = evalKeyIterator->second;
    }

    // pre-created map slots so the parallel loop assigns without a critical section
    auto result = std::make_shared<std::map<uint32_t, EvalKey<Element>>>();
    for (auto indx : indices)
        (*result)[indx];

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sz))
    for (uint32_t i = 0; i < sz; ++i) {
        uint32_t index = NativeInteger(indices[i]).ModInverse(2 * N).ConvertToInt();
        std::vector<uint32_t> vec(N);
        PrecomputeAutoMap(N, index, &vec);

        auto privateKeyPermuted = std::make_shared<PrivateKeyImpl<Element>>(cc);
        privateKeyPermuted->SetPrivateElement(s.AutomorphismTransform(index, vec));

        (*result)[indices[i]] = MultiKeySwitchGen(privateKey, privateKeyPermuted, baseKeys[i]);
    }
    return result;
}

template <class Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> MultipartyBase<Element>::MultiEvalAtIndexKeyGen(
    const PrivateKey<Element> privateKey, const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> evalKeyMap,
    const std::vector<int32_t>& indexList) const {
    std::vector<uint32_t> autoIndices(indexList.size());
    const auto cc    = privateKey->GetCryptoContext();
    const uint32_t M = privateKey->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder();
    for (size_t i = 0; i < indexList.size(); i++)
        autoIndices[i] = cc->GetScheme()->FindAutomorphismIndex(indexList[i], M);
    return MultiEvalAutomorphismKeyGen(privateKey, evalKeyMap, autoIndices);
}

template <class Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> MultipartyBase<Element>::MultiEvalSumKeyGen(
    const PrivateKey<Element> privateKey,
    const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> evalKeyMap) const {
    const std::set<uint32_t> indexSet{AdvancedSHEBase<Element>::GenerateIndexListForEvalSum(privateKey)};
    std::vector<uint32_t> indices(indexSet.begin(), indexSet.end());
    return MultiEvalAutomorphismKeyGen(privateKey, evalKeyMap, indices);
}

template <class Element>
Ciphertext<Element> MultipartyBase<Element>::MultipartyDecryptLead(ConstCiphertext<Element> ciphertext,
                                                                   const PrivateKey<Element> privateKey) const {
    const auto cryptoParams =
        std::dynamic_pointer_cast<CryptoParametersRLWE<Element>>(privateKey->GetCryptoParameters());

    const std::shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();
    const auto ns                                 = cryptoParams->GetNoiseScale();

    const std::vector<Element>& cv = ciphertext->GetElements();
    const Element& s               = privateKey->GetPrivateElement();

    DggType dgg(NoiseFlooding::MP_SD);
    Element e(dgg, elementParams, Format::EVALUATION);
    if (ns != 1)
        e *= typename Element::Integer(ns);
    auto result = ciphertext->CloneEmpty();
    result->SetElement(cv[0] + s * cv[1] + e);
    return result;
}

template <class Element>
Ciphertext<Element> MultipartyBase<Element>::MultipartyDecryptMain(ConstCiphertext<Element> ciphertext,
                                                                   const PrivateKey<Element> privateKey) const {
    const auto cryptoParams =
        std::dynamic_pointer_cast<CryptoParametersRLWE<Element>>(privateKey->GetCryptoParameters());

    const std::shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();
    const auto es                                 = cryptoParams->GetNoiseScale();

    const std::vector<Element>& cv = ciphertext->GetElements();
    const Element& s               = privateKey->GetPrivateElement();

    DggType dgg(NoiseFlooding::MP_SD);
    Element e(dgg, elementParams, Format::EVALUATION);
    if (es != 1)
        e *= typename Element::Integer(es);
    auto result = ciphertext->CloneEmpty();
    result->SetElement(s * cv[1] + e);
    return result;
}

template <class Element>
DecryptResult MultipartyBase<Element>::MultipartyDecryptFusion(const std::vector<Ciphertext<Element>>& ciphertextVec,
                                                               NativePoly* plaintext) const {
    Element b = (ciphertextVec.size() > 1) ? ciphertextVec[0]->GetElements()[0] + ciphertextVec[1]->GetElements()[0] :
                                             ciphertextVec[0]->GetElements()[0];
    for (size_t i = 2; i < ciphertextVec.size(); i++)
        b += ciphertextVec[i]->GetElements()[0];
    b.SetFormat(Format::COEFFICIENT);

    *plaintext = b.ToNativePoly();

    return DecryptResult(plaintext->GetLength());
}

template <class Element>
PublicKey<Element> MultipartyBase<Element>::MultiAddPubKeys(PublicKey<Element> publicKey1,
                                                            PublicKey<Element> publicKey2) const {
    PublicKey<Element> publicKeySum = std::make_shared<PublicKeyImpl<Element>>(publicKey1->GetCryptoContext());

    const Element& b1 = publicKey1->GetPublicElements()[0];
    const Element& b2 = publicKey2->GetPublicElements()[0];
    const Element& a  = publicKey1->GetPublicElements()[1];
    std::vector<Element> pkElems;
    pkElems.reserve(2);
    pkElems.push_back(b1 + b2);
    pkElems.push_back(a);
    publicKeySum->SetPublicElements(std::move(pkElems));

    return publicKeySum;
}

template <class Element>
EvalKey<Element> MultipartyBase<Element>::MultiAddEvalKeys(EvalKey<Element> evalKey1, EvalKey<Element> evalKey2) const {
    const auto cc = evalKey1->GetCryptoContext();

    EvalKey<Element> evalKeySum = std::make_shared<EvalKeyRelinImpl<Element>>(cc);

    const std::vector<Element>& a  = evalKey1->GetAVector();
    const std::vector<Element>& b1 = evalKey1->GetBVector();
    const std::vector<Element>& b2 = evalKey2->GetBVector();

    std::vector<Element> b;
    b.reserve(a.size());

    for (uint32_t i = 0; i < a.size(); i++) {
        b.push_back(b1[i] + b2[i]);
    }

    evalKeySum->SetAVector(a);
    evalKeySum->SetBVector(std::move(b));
    return evalKeySum;
}

template <class Element>
EvalKey<Element> MultipartyBase<Element>::MultiAddEvalMultKeys(EvalKey<Element> evalKey1,
                                                               EvalKey<Element> evalKey2) const {
    const auto cc = evalKey1->GetCryptoContext();

    EvalKey<Element> evalKeySum = std::make_shared<EvalKeyRelinImpl<Element>>(cc);

    const std::vector<Element>& a1 = evalKey1->GetAVector();
    const std::vector<Element>& a2 = evalKey2->GetAVector();
    const std::vector<Element>& b1 = evalKey1->GetBVector();
    const std::vector<Element>& b2 = evalKey2->GetBVector();

    std::vector<Element> a;
    a.reserve(a1.size());
    std::vector<Element> b;
    b.reserve(a1.size());

    for (uint32_t i = 0; i < a1.size(); i++) {
        a.push_back(a1[i] + a2[i]);
        b.push_back(b1[i] + b2[i]);
    }

    evalKeySum->SetAVector(std::move(a));
    evalKeySum->SetBVector(std::move(b));
    return evalKeySum;
}

template <class Element>
EvalKey<Element> MultipartyBase<Element>::MultiMultEvalKey(PrivateKey<Element> privateKey,
                                                           EvalKey<Element> evalKey) const {
    const auto cc = evalKey->GetCryptoContext();

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRLWE<Element>>(cc->GetCryptoParameters());

    const DggType& dgg       = cryptoParams->GetDiscreteGaussianGenerator();
    const auto elementParams = cryptoParams->GetElementParams();

    EvalKey<Element> evalKeyResult = std::make_shared<EvalKeyRelinImpl<Element>>(cc);

    const std::vector<Element>& a0 = evalKey->GetAVector();
    const std::vector<Element>& b0 = evalKey->GetBVector();

    const Element& s = privateKey->GetPrivateElement();
    const auto ns    = cryptoParams->GetNoiseScale();

    std::vector<Element> a;
    a.reserve(a0.size());
    std::vector<Element> b;
    b.reserve(a0.size());

    for (uint32_t i = 0; i < a0.size(); i++) {
        Element ea(dgg, elementParams, Format::EVALUATION);
        if (ns != 1)
            ea *= typename Element::Integer(ns);
        a.push_back(std::move(ea += a0[i] * s));
        Element eb(dgg, elementParams, Format::EVALUATION);
        if (ns != 1)
            eb *= typename Element::Integer(ns);
        b.push_back(std::move(eb += b0[i] * s));
    }

    evalKeyResult->SetAVector(std::move(a));
    evalKeyResult->SetBVector(std::move(b));
    return evalKeyResult;
}

template <class Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> MultipartyBase<Element>::MultiAddEvalAutomorphismKeys(
    const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> evalKeyMap1,
    const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> evalKeyMap2) const {
    auto evalKeyMapAuto = std::make_shared<std::map<uint32_t, EvalKey<Element>>>();

    for (auto it = evalKeyMap1->begin(); it != evalKeyMap1->end(); ++it) {
        auto it2 = evalKeyMap2->find(it->first);
        if (it2 != evalKeyMap2->end())
            (*evalKeyMapAuto)[it->first] = MultiAddEvalKeys(it->second, it2->second);
    }

    return evalKeyMapAuto;
}

template <class Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> MultipartyBase<Element>::MultiAddEvalSumKeys(
    const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> evalKeyMap1,
    const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> evalKeyMap2) const {
    return MultiAddEvalAutomorphismKeys(evalKeyMap1, evalKeyMap2);
}

}  // namespace lbcrypto

// the code below is from base-multiparty-impl.cpp
namespace lbcrypto {
template class MultipartyBase<DCRTPoly>;
}  // namespace lbcrypto
