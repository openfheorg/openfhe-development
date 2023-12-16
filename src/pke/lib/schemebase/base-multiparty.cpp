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
#include "schemebase/base-multiparty.h"

#include "cryptocontext.h"
#include "key/privatekey.h"
#include "key/publickey.h"
#include "key/evalkey.h"
#include "key/evalkeyrelin.h"
#include "schemebase/base-pke.h"
#include "schemebase/rlwe-cryptoparameters.h"

#include "schemebase/base-scheme.h"

namespace lbcrypto {

// makeSparse is not used by this scheme
template <class Element>
KeyPair<Element> MultipartyBase<Element>::MultipartyKeyGen(CryptoContext<Element> cc,
                                                           const std::vector<PrivateKey<Element>>& privateKeyVec,
                                                           bool makeSparse) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRLWE<Element>>(cc->GetCryptoParameters());

    KeyPair<Element> keyPair(std::make_shared<PublicKeyImpl<Element>>(cc),
                             std::make_shared<PrivateKeyImpl<Element>>(cc));

    const std::shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();
    const auto ns                                 = cryptoParams->GetNoiseScale();

    const DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
    DugType dug;

    // Private Key Generation

    Element s(elementParams, Format::EVALUATION, true);

    for (auto& pk : privateKeyVec) {
        const Element& si = pk->GetPrivateElement();
        s += si;
    }

    // Public Key Generation
    Element a(dug, elementParams, Format::EVALUATION);
    Element e(dgg, elementParams, Format::EVALUATION);

    Element b = ns * e - a * s;

    keyPair.secretKey->SetPrivateElement(std::move(s));

    keyPair.publicKey->SetPublicElementAtIndex(0, std::move(b));
    keyPair.publicKey->SetPublicElementAtIndex(1, std::move(a));

    return keyPair;
}

template <class Element>
KeyPair<Element> MultipartyBase<Element>::MultipartyKeyGen(CryptoContext<Element> cc,
                                                           const PublicKey<Element> publicKey, bool makeSparse,
                                                           bool fresh) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRLWE<Element>>(cc->GetCryptoParameters());

    KeyPair<Element> keyPair(std::make_shared<PublicKeyImpl<Element>>(cc),
                             std::make_shared<PrivateKeyImpl<Element>>(cc));

    const std::shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();
    const std::shared_ptr<ParmType> paramsPK      = cryptoParams->GetParamsPK();

    const auto ns = cryptoParams->GetNoiseScale();

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
            s = Element(tug, paramsPK, Format::EVALUATION, 192);
            break;
        default:
            break;
    }

    const std::vector<Element>& pk = publicKey->GetPublicElements();

    Element a = pk[1];
    Element e(dgg, paramsPK, Format::EVALUATION);

    // When PRE is not used, a joint key is computed
    Element b = fresh ? (ns * e - a * s) : (ns * e - a * s + pk[0]);

    usint sizeQ  = elementParams->GetParams().size();
    usint sizePK = paramsPK->GetParams().size();
    if (sizePK > sizeQ) {
        s.DropLastElements(sizePK - sizeQ);
    }

    keyPair.secretKey->SetPrivateElement(std::move(s));

    keyPair.publicKey->SetPublicElementAtIndex(0, std::move(b));
    keyPair.publicKey->SetPublicElementAtIndex(1, std::move(a));

    return keyPair;
}

template <class Element>
EvalKey<Element> MultipartyBase<Element>::MultiKeySwitchGen(const PrivateKey<Element> oldPrivateKey,
                                                            const PrivateKey<Element> newPrivateKey,
                                                            const EvalKey<Element> evalKey) const {
    return oldPrivateKey->GetCryptoContext()->GetScheme()->KeySwitchGen(oldPrivateKey, newPrivateKey, evalKey);
}

template <class Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> MultipartyBase<Element>::MultiEvalAutomorphismKeyGen(
    const PrivateKey<Element> privateKey, const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap,
    const std::vector<usint>& indexList) const {
    const Element& s = privateKey->GetPrivateElement();
    usint N          = s.GetRingDimension();

    if (indexList.size() > N - 1)
        OPENFHE_THROW(math_error, "size exceeds the ring dimension");

    const auto cc = privateKey->GetCryptoContext();

    auto result = std::make_shared<std::map<usint, EvalKey<Element>>>();

    // #pragma omp parallel for if (indexList.size() >= 4)
    for (usint i = 0; i < indexList.size(); i++) {
        PrivateKey<Element> privateKeyPermuted = std::make_shared<PrivateKeyImpl<Element>>(cc);

        usint index = NativeInteger(indexList[i]).ModInverse(2 * N).ConvertToInt();
        std::vector<usint> vec(N);
        PrecomputeAutoMap(N, index, &vec);

        Element sPermuted = s.AutomorphismTransform(index, vec);
        privateKeyPermuted->SetPrivateElement(sPermuted);

        // verify if the key indexList[i] exists in the evalKeyMap
        auto evalKeyIterator = evalKeyMap->find(indexList[i]);
        if (evalKeyIterator == evalKeyMap->end()) {
            OPENFHE_THROW(openfhe_error, "EvalKey for index [" + std::to_string(indexList[i]) + "] is not found.");
        }

        (*result)[indexList[i]] = MultiKeySwitchGen(privateKey, privateKeyPermuted, evalKeyIterator->second);
    }

    return result;
}

template <class Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> MultipartyBase<Element>::MultiEvalAtIndexKeyGen(
    const PrivateKey<Element> privateKey, const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap,
    const std::vector<int32_t>& indexList) const {
    const auto cc = privateKey->GetCryptoContext();

    usint M = privateKey->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder();

    std::vector<uint32_t> autoIndices(indexList.size());

    for (size_t i = 0; i < indexList.size(); i++) {
        autoIndices[i] = (cc->getSchemeId() == SCHEME::CKKSRNS_SCHEME) ?
                             FindAutomorphismIndex2nComplex(indexList[i], M) :
                             FindAutomorphismIndex2n(indexList[i], M);
    }

    return MultiEvalAutomorphismKeyGen(privateKey, evalKeyMap, autoIndices);
}

template <class Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> MultipartyBase<Element>::MultiEvalSumKeyGen(
    const PrivateKey<Element> privateKey, const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap) const {
    const auto cryptoParams = privateKey->GetCryptoParameters();

    usint batchSize = cryptoParams->GetEncodingParams()->GetBatchSize();
    usint M         = cryptoParams->GetElementParams()->GetCyclotomicOrder();

    std::vector<usint> indices;

    if (batchSize > 1) {
        usint g = 5;
        for (int i = 0; i < ceil(log2(batchSize)) - 1; i++) {
            indices.push_back(g);
            g = (g * g) % M;
        }
        if (2 * batchSize < M)
            indices.push_back(g);
        else
            indices.push_back(M - 1);
    }

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

    const Element& s = privateKey->GetPrivateElement();

    DggType dgg(NOISE_FLOODING::MP_SD);
    Element e(dgg, elementParams, Format::EVALUATION);

    Element b = cv[0] + s * cv[1] + ns * e;
    //  b.SwitchFormat();

    Ciphertext<Element> result = ciphertext->CloneEmpty();
    result->SetElements({std::move(b)});
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

    DggType dgg(NOISE_FLOODING::MP_SD);
    Element e(dgg, elementParams, Format::EVALUATION);

    // e is added to do noise flooding
    Element b = s * cv[1] + es * e;

    Ciphertext<Element> result = ciphertext->CloneEmpty();
    result->SetElements({std::move(b)});
    return result;
}

template <class Element>
DecryptResult MultipartyBase<Element>::MultipartyDecryptFusion(const std::vector<Ciphertext<Element>>& ciphertextVec,
                                                               NativePoly* plaintext) const {
    const auto cryptoParams =
        std::dynamic_pointer_cast<CryptoParametersRLWE<Element>>(ciphertextVec[0]->GetCryptoParameters());

    const std::vector<Element>& cv0 = ciphertextVec[0]->GetElements();

    Element b = cv0[0];
    for (size_t i = 1; i < ciphertextVec.size(); i++) {
        const std::vector<Element>& cvi = ciphertextVec[i]->GetElements();
        b += cvi[0];
    }
    b.SetFormat(Format::COEFFICIENT);

    *plaintext = b.ToNativePoly();

    return DecryptResult(plaintext->GetLength());
}

template <class Element>
PublicKey<Element> MultipartyBase<Element>::MultiAddPubKeys(PublicKey<Element> publicKey1,
                                                            PublicKey<Element> publicKey2) const {
    const auto cc = publicKey1->GetCryptoContext();

    PublicKey<Element> publicKeySum = std::make_shared<PublicKeyImpl<Element>>(cc);

    const Element& a = publicKey1->GetPublicElements()[1];

    const Element& b1 = publicKey1->GetPublicElements()[0];
    const Element& b2 = publicKey2->GetPublicElements()[0];

    publicKeySum->SetPublicElementAtIndex(0, std::move(b1 + b2));
    publicKeySum->SetPublicElementAtIndex(1, a);

    return publicKeySum;
}

template <class Element>
EvalKey<Element> MultipartyBase<Element>::MultiAddEvalKeys(EvalKey<Element> evalKey1, EvalKey<Element> evalKey2) const {
    const auto cc = evalKey1->GetCryptoContext();

    EvalKey<Element> evalKeySum = std::make_shared<EvalKeyRelinImpl<Element>>(cc);

    const std::vector<Element>& a = evalKey1->GetAVector();

    const std::vector<Element>& b1 = evalKey1->GetBVector();
    const std::vector<Element>& b2 = evalKey2->GetBVector();

    std::vector<Element> b;

    for (usint i = 0; i < a.size(); i++) {
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
    std::vector<Element> b;

    for (usint i = 0; i < a1.size(); i++) {
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
    std::vector<Element> b;

    for (usint i = 0; i < a0.size(); i++) {
        Element e1(dgg, elementParams, Format::EVALUATION);
        Element e2(dgg, elementParams, Format::EVALUATION);

        a.push_back(a0[i] * s + ns * e1);
        b.push_back(b0[i] * s + ns * e2);
    }

    evalKeyResult->SetAVector(std::move(a));
    evalKeyResult->SetBVector(std::move(b));

    return evalKeyResult;
}

template <class Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> MultipartyBase<Element>::MultiAddEvalAutomorphismKeys(
    const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap1,
    const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap2) const {
    auto evalKeyMapAuto = std::make_shared<std::map<usint, EvalKey<Element>>>();

    for (auto it = evalKeyMap1->begin(); it != evalKeyMap1->end(); ++it) {
        auto it2 = evalKeyMap2->find(it->first);
        if (it2 != evalKeyMap2->end())
            (*evalKeyMapAuto)[it->first] = MultiAddEvalKeys(it->second, it2->second);
    }

    return evalKeyMapAuto;
}

template <class Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> MultipartyBase<Element>::MultiAddEvalSumKeys(
    const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap1,
    const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap2) const {
    auto EvalKeyMapSum = std::make_shared<std::map<usint, EvalKey<Element>>>();

    for (auto it = evalKeyMap1->begin(); it != evalKeyMap1->end(); ++it) {
        auto it2 = evalKeyMap2->find(it->first);
        if (it2 != evalKeyMap2->end())
            (*EvalKeyMapSum)[it->first] = MultiAddEvalKeys(it->second, it2->second);
    }

    return EvalKeyMapSum;
}

template <class Element>
Ciphertext<Element> MultipartyBase<Element>::IntMPBootAdjustScale(ConstCiphertext<Element> ciphertext) const {
    OPENFHE_THROW(config_error, std::string(__func__) + " is not supported");
}

template <class Element>
Ciphertext<Element> MultipartyBase<Element>::IntMPBootRandomElementGen(std::shared_ptr<CryptoParametersCKKSRNS> params,
                                                                       const PublicKey<Element> publicKey) const {
    OPENFHE_THROW(config_error, std::string(__func__) + " is not supported");
}

template <class Element>
std::vector<Ciphertext<Element>> MultipartyBase<Element>::IntMPBootDecrypt(const PrivateKey<Element> privateKey,
                                                                           ConstCiphertext<Element> ciphertext,
                                                                           ConstCiphertext<Element> a) const {
    OPENFHE_THROW(config_error, std::string(__func__) + " is not supported");
}

template <class Element>
std::vector<Ciphertext<Element>> MultipartyBase<Element>::IntMPBootAdd(
    std::vector<std::vector<Ciphertext<Element>>>& sharesPairVec) const {
    OPENFHE_THROW(config_error, std::string(__func__) + " is not supported");
}

template <class Element>
Ciphertext<Element> MultipartyBase<Element>::IntMPBootEncrypt(const PublicKey<Element> publicKey,
                                                              const std::vector<Ciphertext<Element>>& sharesPair,
                                                              ConstCiphertext<Element> a,
                                                              ConstCiphertext<Element> ciphertext) const {
    OPENFHE_THROW(config_error, std::string(__func__) + " is not supported");
}

}  // namespace lbcrypto

// the code below is from base-multiparty-impl.cpp
namespace lbcrypto {
template class MultipartyBase<DCRTPoly>;
}  // namespace lbcrypto
