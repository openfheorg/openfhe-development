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
  Control for encryption operations
 */

#include "cryptocontext.h"

#include "key/privatekey.h"
#include "key/publickey.h"
#include "math/chebyshev.h"
#include "schemerns/rns-scheme.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"

namespace lbcrypto {

template <typename Element>
std::map<std::string, std::vector<EvalKey<Element>>> CryptoContextImpl<Element>::s_evalMultKeyMap{};
template <typename Element>
std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>>
    CryptoContextImpl<Element>::s_evalAutomorphismKeyMap{};

template <typename Element>
void CryptoContextImpl<Element>::SetKSTechniqueInScheme() {
    // check if the scheme is an RNS scheme
    auto schemeRNSPtr = dynamic_cast<SchemeRNS*>(&(*scheme));
    if (schemeRNSPtr != nullptr) {
        // check if the parameter object is RNS-based
        auto elPtr = dynamic_cast<const CryptoParametersRNS*>(&(*params));
        if (elPtr != nullptr) {
            schemeRNSPtr->SetKeySwitchingTechnique(elPtr->GetKeySwitchTechnique());
            return;
        }
        OPENFHE_THROW("Cannot set KeySwitchingTechnique as the parameter object is not RNS-based");
    }
}

/////////////////////////////////////////
// SHE MULTIPLICATION
/////////////////////////////////////////
template <typename Element>
void CryptoContextImpl<Element>::EvalMultKeyGen(const PrivateKey<Element> key) {
    ValidateKey(key);

    if (CryptoContextImpl<Element>::s_evalMultKeyMap.find(key->GetKeyTag()) ==
        CryptoContextImpl<Element>::s_evalMultKeyMap.end()) {
        // the key is not found in the map, so the key has to be generated
        EvalKey<Element> k                                           = GetScheme()->EvalMultKeyGen(key);
        CryptoContextImpl<Element>::s_evalMultKeyMap[k->GetKeyTag()] = {k};
    }
}

template <typename Element>
void CryptoContextImpl<Element>::EvalMultKeysGen(const PrivateKey<Element> key) {
    ValidateKey(key);

    if (CryptoContextImpl<Element>::s_evalMultKeyMap.find(key->GetKeyTag()) ==
        CryptoContextImpl<Element>::s_evalMultKeyMap.end()) {
        // the key is not found in the map, so the key has to be generated
        const std::vector<EvalKey<Element>>& evalKeys                  = GetScheme()->EvalMultKeysGen(key);
        CryptoContextImpl<Element>::s_evalMultKeyMap[key->GetKeyTag()] = evalKeys;
    }
}

template <typename Element>
void CryptoContextImpl<Element>::ClearEvalMultKeys() {
    CryptoContextImpl<Element>::s_evalMultKeyMap.clear();
}

template <typename Element>
void CryptoContextImpl<Element>::ClearEvalMultKeys(const std::string& id) {
    auto kd = CryptoContextImpl<Element>::s_evalMultKeyMap.find(id);
    if (kd != CryptoContextImpl<Element>::s_evalMultKeyMap.end())
        CryptoContextImpl<Element>::s_evalMultKeyMap.erase(kd);
}

template <typename Element>
void CryptoContextImpl<Element>::ClearEvalMultKeys(const CryptoContext<Element> cc) {
    for (auto it = CryptoContextImpl<Element>::s_evalMultKeyMap.begin();
         it != CryptoContextImpl<Element>::s_evalMultKeyMap.end();) {
        if (it->second[0]->GetCryptoContext() == cc) {
            it = CryptoContextImpl<Element>::s_evalMultKeyMap.erase(it);
        }
        else {
            ++it;
        }
    }
}

template <typename Element>
void CryptoContextImpl<Element>::InsertEvalMultKey(const std::vector<EvalKey<Element>>& vectorToInsert,
                                                   const std::string& keyTag) {
    const std::string tag = (keyTag.empty()) ? vectorToInsert[0]->GetKeyTag() : keyTag;
    if (CryptoContextImpl<Element>::s_evalMultKeyMap.find(tag) != CryptoContextImpl<Element>::s_evalMultKeyMap.end()) {
        // we do not allow to override the existing key vector if its keyTag is identical to the keyTag of the new keys
        OPENFHE_THROW("Can not save a EvalMultKeys vector as there is a key vector for the given keyTag");
    }

    CryptoContextImpl<Element>::s_evalMultKeyMap[tag] = vectorToInsert;
}

/////////////////////////////////////////
// ADVANCED SHE
/////////////////////////////////////////

template <typename Element>
void CryptoContextImpl<Element>::EvalSumKeyGen(const PrivateKey<Element> privateKey,
                                               const PublicKey<Element> publicKey) {
    ValidateKey(privateKey);
    if (publicKey != nullptr && privateKey->GetKeyTag() != publicKey->GetKeyTag()) {
        OPENFHE_THROW("Public key passed to EvalSumKeyGen does not match private key");
    }

    auto evalKeys = GetScheme()->EvalSumKeyGen(privateKey, publicKey);
    CryptoContextImpl<Element>::InsertEvalAutomorphismKey(evalKeys, privateKey->GetKeyTag());
}

template <typename Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> CryptoContextImpl<Element>::EvalSumRowsKeyGen(
    const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey, usint rowSize, usint subringDim) {
    ValidateKey(privateKey);
    if (publicKey != nullptr && privateKey->GetKeyTag() != publicKey->GetKeyTag()) {
        OPENFHE_THROW("Public key passed to EvalSumKeyGen does not match private key");
    }

    std::vector<usint> indices;
    auto evalKeys = GetScheme()->EvalSumRowsKeyGen(privateKey, rowSize, subringDim, indices);
    CryptoContextImpl<Element>::InsertEvalAutomorphismKey(evalKeys, privateKey->GetKeyTag());

    return CryptoContextImpl<Element>::GetPartialEvalAutomorphismKeyMapPtr(privateKey->GetKeyTag(), indices);
}

template <typename Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> CryptoContextImpl<Element>::EvalSumColsKeyGen(
    const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey) {
    ValidateKey(privateKey);
    if (publicKey != nullptr && privateKey->GetKeyTag() != publicKey->GetKeyTag()) {
        OPENFHE_THROW("Public key passed to EvalSumKeyGen does not match private key");
    }

    std::vector<usint> indices;
    auto evalKeys = GetScheme()->EvalSumColsKeyGen(privateKey, indices);
    CryptoContextImpl<Element>::InsertEvalAutomorphismKey(evalKeys, privateKey->GetKeyTag());

    return CryptoContextImpl<Element>::GetPartialEvalAutomorphismKeyMapPtr(privateKey->GetKeyTag(), indices);
}

template <typename Element>
const std::map<usint, EvalKey<Element>>& CryptoContextImpl<Element>::GetEvalSumKeyMap(const std::string& keyID) {
    return CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(keyID);
}

template <typename Element>
std::map<std::string, std::vector<EvalKey<Element>>>& CryptoContextImpl<Element>::GetAllEvalMultKeys() {
    return CryptoContextImpl<Element>::s_evalMultKeyMap;
}

template <typename Element>
const std::vector<EvalKey<Element>>& CryptoContextImpl<Element>::GetEvalMultKeyVector(const std::string& keyID) {
    auto ekv = CryptoContextImpl<Element>::s_evalMultKeyMap.find(keyID);
    if (ekv == CryptoContextImpl<Element>::s_evalMultKeyMap.end()) {
        std::string errMsg(std::string("Call EvalMultKeyGen() to have EvalMultKey available for ID [") + keyID + "].");
        OPENFHE_THROW(errMsg);
    }
    return ekv->second;
}

template <typename Element>
std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>>&
CryptoContextImpl<Element>::GetAllEvalAutomorphismKeys() {
    return CryptoContextImpl<Element>::s_evalAutomorphismKeyMap;
}

template <typename Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> CryptoContextImpl<Element>::GetEvalAutomorphismKeyMapPtr(
    const std::string& keyID) {
    auto ekv = CryptoContextImpl<Element>::s_evalAutomorphismKeyMap.find(keyID);
    if (ekv == CryptoContextImpl<Element>::s_evalAutomorphismKeyMap.end()) {
        OPENFHE_THROW("EvalAutomorphismKeys are not generated for ID [" + keyID + "].");
    }
    return ekv->second;
}

template <typename Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> CryptoContextImpl<Element>::GetPartialEvalAutomorphismKeyMapPtr(
    const std::string& keyID, const std::vector<uint32_t>& indexList) {
    if (!indexList.size())
        OPENFHE_THROW("indexList is empty");

    std::shared_ptr<std::map<usint, EvalKey<Element>>> keyMap =
        CryptoContextImpl<Element>::GetEvalAutomorphismKeyMapPtr(keyID);

    // create a return map if specific indices are provided
    std::map<usint, EvalKey<Element>> retMap;
    for (uint32_t indx : indexList) {
        const auto it = keyMap->find(indx);
        if (it == keyMap->end()) {
            OPENFHE_THROW("Key is not generated for index [" + std::to_string(indx) + "] and keyID [" + keyID + "]");
        }
        retMap.emplace(indx, it->second);
    }
    return std::make_shared<std::map<usint, EvalKey<Element>>>(retMap);
}

template <typename Element>
std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>>&
CryptoContextImpl<Element>::GetAllEvalSumKeys() {
    return CryptoContextImpl<Element>::GetAllEvalAutomorphismKeys();
}

template <typename Element>
void CryptoContextImpl<Element>::ClearEvalSumKeys() {
    CryptoContextImpl<Element>::ClearEvalAutomorphismKeys();
}

/**
 * ClearEvalMultKeys - flush EvalMultKey cache for a given id
 * @param id
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalSumKeys(const std::string& id) {
    CryptoContextImpl<Element>::ClearEvalAutomorphismKeys(id);
}

/**
 * ClearEvalMultKeys - flush EvalMultKey cache for a given context
 * @param cc
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalSumKeys(const CryptoContext<Element> cc) {
    CryptoContextImpl<Element>::ClearEvalAutomorphismKeys(cc);
}

/////////////////////////////////////////
// SHE AUTOMORPHISM
/////////////////////////////////////////

template <typename Element>
void CryptoContextImpl<Element>::EvalAtIndexKeyGen(const PrivateKey<Element> privateKey,
                                                   const std::vector<int32_t>& indexList,
                                                   const PublicKey<Element> publicKey) {
    ValidateKey(privateKey);
    if (publicKey != nullptr && privateKey->GetKeyTag() != publicKey->GetKeyTag()) {
        OPENFHE_THROW("Public key passed to EvalAtIndexKeyGen does not match private key");
    }

    auto evalKeys = GetScheme()->EvalAtIndexKeyGen(publicKey, privateKey, indexList);
    CryptoContextImpl<Element>::InsertEvalAutomorphismKey(evalKeys, privateKey->GetKeyTag());
}

template <typename Element>
void CryptoContextImpl<Element>::ClearEvalAutomorphismKeys() {
    CryptoContextImpl<Element>::s_evalAutomorphismKeyMap.clear();
}

/**
 * ClearEvalAutomorphismKeys - flush EvalAutomorphismKey cache for a given id
 * @param id
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalAutomorphismKeys(const std::string& id) {
    auto kd = CryptoContextImpl<Element>::s_evalAutomorphismKeyMap.find(id);
    if (kd != CryptoContextImpl<Element>::s_evalAutomorphismKeyMap.end())
        CryptoContextImpl<Element>::s_evalAutomorphismKeyMap.erase(kd);
}

/**
 * ClearEvalAutomorphismKeys - flush EvalAutomorphismKey cache for a given
 * context
 * @param cc
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalAutomorphismKeys(const CryptoContext<Element> cc) {
    for (auto it = CryptoContextImpl<Element>::s_evalAutomorphismKeyMap.begin();
         it != CryptoContextImpl<Element>::s_evalAutomorphismKeyMap.end();) {
        if (it->second->begin()->second->GetCryptoContext() == cc) {
            it = CryptoContextImpl<Element>::s_evalAutomorphismKeyMap.erase(it);
        }
        else {
            ++it;
        }
    }
}

template <typename Element>
std::set<uint32_t> CryptoContextImpl<Element>::GetExistingEvalAutomorphismKeyIndices(const std::string& keyTag) {
    auto keyMapIt = CryptoContextImpl<Element>::s_evalAutomorphismKeyMap.find(keyTag);
    if (keyMapIt == CryptoContextImpl<Element>::s_evalAutomorphismKeyMap.end())
        // there is no keys for the given id, return empty vector
        return std::set<uint32_t>();

    // get all inidices from the existing automorphism key map
    auto& keyMap = *(keyMapIt->second);
    std::set<uint32_t> indices;
    for (const auto& [key, _] : keyMap) {
        indices.insert(key);
    }

    return indices;
}

template <typename Element>
std::set<uint32_t> CryptoContextImpl<Element>::GetUniqueValues(const std::set<uint32_t>& oldValues,
                                                               const std::set<uint32_t>& newValues) {
    std::set<uint32_t> newUniqueValues;
    std::set_difference(newValues.begin(), newValues.end(), oldValues.begin(), oldValues.end(),
                        std::inserter(newUniqueValues, newUniqueValues.begin()));

    return newUniqueValues;
}

template <typename Element>
void CryptoContextImpl<Element>::InsertEvalAutomorphismKey(
    const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> mapToInsert, const std::string& keyTag) {
    // check if the map is empty
    if (mapToInsert->empty()) {
        return;
    }

    auto mapToInsertIt   = mapToInsert->begin();
    const std::string id = (keyTag.empty()) ? mapToInsertIt->second->GetKeyTag() : keyTag;
    std::set<uint32_t> existingIndices{CryptoContextImpl<Element>::GetExistingEvalAutomorphismKeyIndices(id)};
    if (existingIndices.empty()) {
        // there is no keys for the given id, so we insert full mapToInsert
        CryptoContextImpl<Element>::s_evalAutomorphismKeyMap[id] = mapToInsert;
    }
    else {
        // get all indices from mapToInsert
        std::set<uint32_t> newIndices;
        for (const auto& [key, _] : *mapToInsert) {
            newIndices.insert(key);
        }

        // find all indices in mapToInsert that are not in the exising map and
        // insert those new indices and their corresponding keys to the existing map
        std::set<uint32_t> indicesToInsert{CryptoContextImpl<Element>::GetUniqueValues(existingIndices, newIndices)};
        auto keyMapIt = CryptoContextImpl<Element>::s_evalAutomorphismKeyMap.find(id);
        auto& keyMap  = *(keyMapIt->second);
        for (uint32_t indx : indicesToInsert) {
            keyMap[indx] = (*mapToInsert)[indx];
        }
    }
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalSum(ConstCiphertext<Element> ciphertext, usint batchSize) const {
    ValidateCiphertext(ciphertext);

    auto evalSumKeys = CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(ciphertext->GetKeyTag());
    auto rv          = GetScheme()->EvalSum(ciphertext, batchSize, evalSumKeys);
    return rv;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalSumRows(ConstCiphertext<Element> ciphertext, usint numRows,
                                                            const std::map<usint, EvalKey<Element>>& evalSumKeys,
                                                            usint subringDim) const {
    ValidateCiphertext(ciphertext);

    auto rv = GetScheme()->EvalSumRows(ciphertext, numRows, evalSumKeys, subringDim);
    return rv;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalSumCols(
    ConstCiphertext<Element> ciphertext, usint numCols,
    const std::map<usint, EvalKey<Element>>& evalSumKeysRight) const {
    ValidateCiphertext(ciphertext);

    auto evalSumKeys = CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(ciphertext->GetKeyTag());
    auto rv          = GetScheme()->EvalSumCols(ciphertext, numCols, evalSumKeys, evalSumKeysRight);
    return rv;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalAtIndex(ConstCiphertext<Element> ciphertext, int32_t index) const {
    ValidateCiphertext(ciphertext);

    // If the index is zero, no rotation is needed, copy the ciphertext and return
    // This is done after the keyMap so that it is protected if there's not a
    // valid key.
    if (0 == index) {
        auto rv = ciphertext->Clone();
        return rv;
    }

    auto evalAutomorphismKeys = CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(ciphertext->GetKeyTag());

    auto rv = GetScheme()->EvalAtIndex(ciphertext, index, evalAutomorphismKeys);
    return rv;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalMerge(
    const std::vector<Ciphertext<Element>>& ciphertextVector) const {
    ValidateCiphertext(ciphertextVector[0]);

    auto evalAutomorphismKeys = CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(ciphertextVector[0]->GetKeyTag());

    auto rv = GetScheme()->EvalMerge(ciphertextVector, evalAutomorphismKeys);

    return rv;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalInnerProduct(ConstCiphertext<Element> ct1,
                                                                 ConstCiphertext<Element> ct2, usint batchSize) const {
    ValidateCiphertext(ct1);
    if (ct2 == nullptr || ct1->GetKeyTag() != ct2->GetKeyTag())
        OPENFHE_THROW(
            "Information passed to EvalInnerProduct was not generated "
            "with this crypto context");

    auto evalSumKeys = CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(ct1->GetKeyTag());
    auto ek          = CryptoContextImpl<Element>::GetEvalMultKeyVector(ct1->GetKeyTag());

    auto rv = GetScheme()->EvalInnerProduct(ct1, ct2, batchSize, evalSumKeys, ek[0]);
    return rv;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalInnerProduct(ConstCiphertext<Element> ct1, ConstPlaintext ct2,
                                                                 usint batchSize) const {
    ValidateCiphertext(ct1);
    if (ct2 == nullptr)
        OPENFHE_THROW(
            "Information passed to EvalInnerProduct was not generated "
            "with this crypto context");

    auto evalSumKeys = CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(ct1->GetKeyTag());

    auto rv = GetScheme()->EvalInnerProduct(ct1, ct2, batchSize, evalSumKeys);
    return rv;
}

template <typename Element>
Plaintext CryptoContextImpl<Element>::GetPlaintextForDecrypt(PlaintextEncodings pte, std::shared_ptr<ParmType> evp,
                                                             EncodingParams ep) {
    auto vp = std::make_shared<typename NativePoly::Params>(evp->GetCyclotomicOrder(), ep->GetPlaintextModulus(), 1);

    if (pte == CKKS_PACKED_ENCODING)
        return PlaintextFactory::MakePlaintext(pte, evp, ep);

    return PlaintextFactory::MakePlaintext(pte, vp, ep);
}

template <typename Element>
DecryptResult CryptoContextImpl<Element>::Decrypt(ConstCiphertext<Element> ciphertext,
                                                  const PrivateKey<Element> privateKey, Plaintext* plaintext) {
    if (ciphertext == nullptr)
        OPENFHE_THROW("ciphertext passed to Decrypt is empty");
    if (plaintext == nullptr)
        OPENFHE_THROW("plaintext passed to Decrypt is empty");
    ValidateKey(privateKey);

    // determine which type of plaintext that you need to decrypt into
    // Plaintext decrypted =
    // CryptoContextImpl<Element>::GetPlaintextForDecrypt(ciphertext->GetEncodingType(),
    // this->GetElementParams(), this->GetEncodingParams());
    Plaintext decrypted = CryptoContextImpl<Element>::GetPlaintextForDecrypt(
        ciphertext->GetEncodingType(), ciphertext->GetElements()[0].GetParams(), this->GetEncodingParams());

    DecryptResult result;

    if ((ciphertext->GetEncodingType() == CKKS_PACKED_ENCODING) && (typeid(Element) != typeid(NativePoly))) {
        result = GetScheme()->Decrypt(ciphertext, privateKey, &decrypted->GetElement<Poly>());
    }
    else {
        result = GetScheme()->Decrypt(ciphertext, privateKey, &decrypted->GetElement<NativePoly>());
    }

    if (result.isValid == false)  // TODO (dsuponit): why don't we throw an exception here?
        return result;

    decrypted->SetScalingFactorInt(result.scalingFactorInt);

    if (ciphertext->GetEncodingType() == CKKS_PACKED_ENCODING) {
        auto decryptedCKKS = std::dynamic_pointer_cast<CKKSPackedEncoding>(decrypted);
        decryptedCKKS->SetNoiseScaleDeg(ciphertext->GetNoiseScaleDeg());
        decryptedCKKS->SetLevel(ciphertext->GetLevel());
        decryptedCKKS->SetScalingFactor(ciphertext->GetScalingFactor());
        decryptedCKKS->SetSlots(ciphertext->GetSlots());

        const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());

        decryptedCKKS->Decode(ciphertext->GetNoiseScaleDeg(), ciphertext->GetScalingFactor(),
                              cryptoParamsCKKS->GetScalingTechnique(), cryptoParamsCKKS->GetExecutionMode());
    }
    else {
        decrypted->Decode();
    }

    *plaintext = std::move(decrypted);
    return result;
}

//------------------------------------------------------------------------------
// Advanced SHE CHEBYSHEV SERIES EXAMPLES
//------------------------------------------------------------------------------

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalChebyshevFunction(std::function<double(double)> func,
                                                                      ConstCiphertext<Element> ciphertext, double a,
                                                                      double b, uint32_t degree) const {
    std::vector<double> coefficients = EvalChebyshevCoefficients(func, a, b, degree);
    return EvalChebyshevSeries(ciphertext, coefficients, a, b);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalSin(ConstCiphertext<Element> ciphertext, double a, double b,
                                                        uint32_t degree) const {
    return EvalChebyshevFunction([](double x) -> double { return std::sin(x); }, ciphertext, a, b, degree);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalCos(ConstCiphertext<Element> ciphertext, double a, double b,
                                                        uint32_t degree) const {
    return EvalChebyshevFunction([](double x) -> double { return std::cos(x); }, ciphertext, a, b, degree);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalLogistic(ConstCiphertext<Element> ciphertext, double a, double b,
                                                             uint32_t degree) const {
    return EvalChebyshevFunction([](double x) -> double { return 1 / (1 + std::exp(-x)); }, ciphertext, a, b, degree);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalDivide(ConstCiphertext<Element> ciphertext, double a, double b,
                                                           uint32_t degree) const {
    return EvalChebyshevFunction([](double x) -> double { return 1 / x; }, ciphertext, a, b, degree);
}

}  // namespace lbcrypto

// the code below is from cryptocontext-impl.cpp
namespace lbcrypto {

template <>
Plaintext CryptoContextImpl<DCRTPoly>::GetPlaintextForDecrypt(PlaintextEncodings pte, std::shared_ptr<ParmType> evp,
                                                              EncodingParams ep) {
    if ((pte == CKKS_PACKED_ENCODING) && (evp->GetParams().size() > 1)) {
        auto vp = std::make_shared<typename Poly::Params>(evp->GetCyclotomicOrder(), ep->GetPlaintextModulus(), 1);
        return PlaintextFactory::MakePlaintext(pte, vp, ep);
    }
    else {
        auto vp =
            std::make_shared<typename NativePoly::Params>(evp->GetCyclotomicOrder(), ep->GetPlaintextModulus(), 1);
        return PlaintextFactory::MakePlaintext(pte, vp, ep);
    }
}

template <>
DecryptResult CryptoContextImpl<DCRTPoly>::Decrypt(ConstCiphertext<DCRTPoly> ciphertext,
                                                   const PrivateKey<DCRTPoly> privateKey, Plaintext* plaintext) {
    if (ciphertext == nullptr)
        OPENFHE_THROW("ciphertext passed to Decrypt is empty");
    if (plaintext == nullptr)
        OPENFHE_THROW("plaintext passed to Decrypt is empty");
    if (privateKey == nullptr || Mismatched(privateKey->GetCryptoContext()))
        OPENFHE_THROW(
            "Information passed to Decrypt was not generated with "
            "this crypto context");

    // determine which type of plaintext that you need to decrypt into
    // Plaintext decrypted =
    // CryptoContextImpl<Element>::GetPlaintextForDecrypt(ciphertext->GetEncodingType(),
    // this->GetElementParams(), this->GetEncodingParams());
    Plaintext decrypted = CryptoContextImpl<DCRTPoly>::GetPlaintextForDecrypt(
        ciphertext->GetEncodingType(), ciphertext->GetElements()[0].GetParams(), this->GetEncodingParams());

    DecryptResult result;

    if ((ciphertext->GetEncodingType() == CKKS_PACKED_ENCODING) &&
        (ciphertext->GetElements()[0].GetParams()->GetParams().size() > 1))  // more than one tower in DCRTPoly
        result = GetScheme()->Decrypt(ciphertext, privateKey, &decrypted->GetElement<Poly>());
    else
        result = GetScheme()->Decrypt(ciphertext, privateKey, &decrypted->GetElement<NativePoly>());

    if (result.isValid == false)
        return result;

    decrypted->SetScalingFactorInt(result.scalingFactorInt);

    if (ciphertext->GetEncodingType() == CKKS_PACKED_ENCODING) {
        auto decryptedCKKS = std::dynamic_pointer_cast<CKKSPackedEncoding>(decrypted);
        decryptedCKKS->SetNoiseScaleDeg(ciphertext->GetNoiseScaleDeg());
        decryptedCKKS->SetLevel(ciphertext->GetLevel());
        decryptedCKKS->SetScalingFactor(ciphertext->GetScalingFactor());
        decryptedCKKS->SetSlots(ciphertext->GetSlots());

        const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(this->GetCryptoParameters());

        decryptedCKKS->Decode(ciphertext->GetNoiseScaleDeg(), ciphertext->GetScalingFactor(),
                              cryptoParamsCKKS->GetScalingTechnique(), cryptoParamsCKKS->GetExecutionMode());
    }
    else {
        decrypted->Decode();
    }

    *plaintext = std::move(decrypted);
    return result;
}

template <>
DecryptResult CryptoContextImpl<DCRTPoly>::MultipartyDecryptFusion(
    const std::vector<Ciphertext<DCRTPoly>>& partialCiphertextVec, Plaintext* plaintext) const {
    DecryptResult result;

    // Make sure we're processing ciphertexts.
    size_t last_ciphertext = partialCiphertextVec.size();
    if (last_ciphertext < 1)
        return result;

    for (size_t i = 0; i < last_ciphertext; i++) {
        ValidateCiphertext(partialCiphertextVec[i]);
        if (partialCiphertextVec[i]->GetEncodingType() != partialCiphertextVec[0]->GetEncodingType())
            OPENFHE_THROW(
                "Ciphertexts passed to MultipartyDecryptFusion have "
                "mismatched encoding types");
    }

    // determine which type of plaintext that you need to decrypt into
    Plaintext decrypted = CryptoContextImpl<DCRTPoly>::GetPlaintextForDecrypt(
        partialCiphertextVec[0]->GetEncodingType(), partialCiphertextVec[0]->GetElements()[0].GetParams(),
        this->GetEncodingParams());

    if ((partialCiphertextVec[0]->GetEncodingType() == CKKS_PACKED_ENCODING) &&
        (partialCiphertextVec[0]->GetElements()[0].GetParams()->GetParams().size() > 1))
        result = GetScheme()->MultipartyDecryptFusion(partialCiphertextVec, &decrypted->GetElement<Poly>());
    else
        result = GetScheme()->MultipartyDecryptFusion(partialCiphertextVec, &decrypted->GetElement<NativePoly>());

    if (result.isValid == false)
        return result;

    decrypted->SetScalingFactorInt(result.scalingFactorInt);

    if (partialCiphertextVec[0]->GetEncodingType() == CKKS_PACKED_ENCODING) {
        auto decryptedCKKS = std::dynamic_pointer_cast<CKKSPackedEncoding>(decrypted);
        decryptedCKKS->SetSlots(partialCiphertextVec[0]->GetSlots());
        const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(this->GetCryptoParameters());
        decryptedCKKS->Decode(partialCiphertextVec[0]->GetNoiseScaleDeg(), partialCiphertextVec[0]->GetScalingFactor(),
                              cryptoParamsCKKS->GetScalingTechnique(), cryptoParamsCKKS->GetExecutionMode());
    }
    else {
        decrypted->Decode();
    }

    *plaintext = std::move(decrypted);

    return result;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::IntMPBootAdjustScale(ConstCiphertext<Element> ciphertext) const {
    return GetScheme()->IntMPBootAdjustScale(ciphertext);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::IntMPBootRandomElementGen(const PublicKey<Element> publicKey) const {
    const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(this->GetCryptoParameters());
    return GetScheme()->IntMPBootRandomElementGen(cryptoParamsCKKS, publicKey);
}

template <typename Element>
std::vector<Ciphertext<Element>> CryptoContextImpl<Element>::IntMPBootDecrypt(const PrivateKey<Element> privateKey,
                                                                              ConstCiphertext<Element> ciphertext,
                                                                              ConstCiphertext<Element> a) const {
    return GetScheme()->IntMPBootDecrypt(privateKey, ciphertext, a);
}

template <typename Element>
std::vector<Ciphertext<Element>> CryptoContextImpl<Element>::IntMPBootAdd(
    std::vector<std::vector<Ciphertext<Element>>>& sharesPairVec) const {
    return GetScheme()->IntMPBootAdd(sharesPairVec);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::IntMPBootEncrypt(const PublicKey<Element> publicKey,
                                                                 const std::vector<Ciphertext<Element>>& sharesPair,
                                                                 ConstCiphertext<Element> a,
                                                                 ConstCiphertext<Element> ciphertext) const {
    return GetScheme()->IntMPBootEncrypt(publicKey, sharesPair, a, ciphertext);
}

// Function for sharing and recovery of secret for Threshold FHE with aborts
template <>
std::unordered_map<uint32_t, DCRTPoly> CryptoContextImpl<DCRTPoly>::ShareKeys(const PrivateKey<DCRTPoly>& sk, usint N,
                                                                              usint threshold, usint index,
                                                                              const std::string& shareType) const {
    // conditions on N and threshold for security with aborts
    if (N < 2)
        OPENFHE_THROW("Number of parties needs to be at least 3 for aborts");

    if (threshold <= N / 2)
        OPENFHE_THROW("Threshold required to be majority (more than N/2)");

    const auto cryptoParams = sk->GetCryptoContext()->GetCryptoParameters();
    auto elementParams      = cryptoParams->GetElementParams();
    auto vecSize            = elementParams->GetParams().size();
    auto ring_dimension     = elementParams->GetRingDimension();

    // condition for inverse in lagrange coeff to exist.
    for (usint k = 0; k < vecSize; k++) {
        auto modq_k = elementParams->GetParams()[k]->GetModulus();
        if (N >= modq_k)
            OPENFHE_THROW("Number of parties N needs to be less than DCRTPoly moduli");
    }

    // secret sharing
    const usint num_of_shares = N - 1;
    std::unordered_map<uint32_t, DCRTPoly> SecretShares;

    if (shareType == "additive") {
        // generate a random share of N-2 elements and create the last share as sk - (sk_1 + ... + sk_N-2)
        typename DCRTPoly::DugType dug;
        DCRTPoly rsum(dug, elementParams, Format::EVALUATION);

        std::vector<DCRTPoly> SecretSharesVec;
        SecretSharesVec.reserve(num_of_shares);
        SecretSharesVec.push_back(rsum);
        for (size_t i = 1; i < num_of_shares - 1; ++i) {
            DCRTPoly r(dug, elementParams, Format::EVALUATION);  // should re-generate uniform r for each share
            rsum += r;
            SecretSharesVec.push_back(std::move(r));
        }
        SecretSharesVec.push_back(sk->GetPrivateElement() - rsum);

        usint ctr = 0;
        for (size_t i = 1; i <= N; i++) {
            if (i != index) {
                SecretShares[i] = SecretSharesVec[ctr];
                ctr++;
            }
        }
    }
    else if (shareType == "shamir") {
        // vector to store columnwise randomly generated coefficients for polynomial f from Z_q for every secret key entry
        std::vector<DCRTPoly> fs;
        fs.reserve(threshold);

        // set constant term of polynomial f_i to s_i
        DCRTPoly ske = sk->GetPrivateElement();
        // set the secret element in coefficient format
        ske.SetFormat(Format::COEFFICIENT);

        fs.push_back(std::move(ske));
        // generate random coefficients
        typename DCRTPoly::DugType dug;
        for (size_t i = 1; i < threshold; i++) {
            fs.push_back(DCRTPoly(dug, elementParams, Format::COEFFICIENT));
        }

        // evaluate the polynomial at the index of the parties 1 to N

        for (size_t i = 1; i <= N; i++) {
            if (i != index) {
                DCRTPoly feval(elementParams, Format::COEFFICIENT, true);
                for (size_t k = 0; k < vecSize; k++) {
                    auto modq_k = elementParams->GetParams()[k]->GetModulus();

                    NativeVector powtempvec(ring_dimension, modq_k);
                    NativePoly powtemppoly(elementParams->GetParams()[k], Format::COEFFICIENT);
                    NativePoly fevalpoly(elementParams->GetParams()[k], Format::COEFFICIENT, true);

                    NativeInteger powtemp(1);
                    for (size_t t = 1; t < threshold; t++) {
                        powtemp = powtemp.ModMul(i, modq_k);

                        for (size_t d = 0; d < ring_dimension; d++) {
                            powtempvec.at(d) = powtemp;
                        }

                        powtemppoly.SetValues(powtempvec, Format::COEFFICIENT);

                        auto fst = fs[t].GetElementAtIndex(k);

                        for (size_t l = 0; l < ring_dimension; l++) {
                            fevalpoly.at(l) += powtemppoly.at(l).ModMul(fst.at(l), modq_k);
                        }
                    }
                    fevalpoly += fs[0].GetElementAtIndex(k);

                    fevalpoly.SetFormat(Format::COEFFICIENT);
                    feval.SetElementAtIndex(k, fevalpoly);
                }
                // assign fi
                SecretShares[i] = feval;
            }
        }
    }
    return SecretShares;
}

template <>
void CryptoContextImpl<DCRTPoly>::RecoverSharedKey(PrivateKey<DCRTPoly>& sk,
                                                   std::unordered_map<uint32_t, DCRTPoly>& sk_shares, usint N,
                                                   usint threshold, const std::string& shareType) const {
    if (sk_shares.size() < threshold)
        OPENFHE_THROW("Number of shares available less than threshold of the sharing scheme");

    // conditions on N and threshold for security with aborts
    if (N < 2)
        OPENFHE_THROW("Number of parties needs to be at least 3 for aborts");

    if (threshold <= N / 2)
        OPENFHE_THROW("Threshold required to be majority (more than N/2)");

    const auto& cryptoParams  = sk->GetCryptoContext()->GetCryptoParameters();
    const auto& elementParams = cryptoParams->GetElementParams();
    size_t ring_dimension     = elementParams->GetRingDimension();
    size_t vecSize            = elementParams->GetParams().size();

    // condition for inverse in lagrange coeff to exist.
    for (size_t k = 0; k < vecSize; k++) {
        auto modq_k = elementParams->GetParams()[k]->GetModulus();
        if (N >= modq_k)
            OPENFHE_THROW("Number of parties N needs to be less than DCRTPoly moduli");
    }

    // vector of indexes of the clients
    std::vector<uint32_t> client_indexes;
    client_indexes.reserve(N);
    for (uint32_t i = 1; i <= N; ++i) {
        if (sk_shares.find(i) != sk_shares.end())
            client_indexes.push_back(i);
    }
    const uint32_t client_indexes_size = client_indexes.size();

    if (client_indexes_size < threshold)
        OPENFHE_THROW("Not enough shares to recover the secret");

    if (shareType == "additive") {
        DCRTPoly sum_of_elems(elementParams, Format::EVALUATION, true);
        for (uint32_t i = 0; i < threshold; ++i) {
            sum_of_elems += sk_shares[client_indexes[i]];
        }
        sk->SetPrivateElement(sum_of_elems);
    }
    else if (shareType == "shamir") {
        // use lagrange interpolation to recover the secret
        // vector of lagrange coefficients L_j = Pdt_i ne j (i (i-j)^-1)
        std::vector<DCRTPoly> Lagrange_coeffs(client_indexes_size, DCRTPoly(elementParams, Format::EVALUATION));

        // recovery of the secret with lagrange coefficients and the secret shares
        for (uint32_t j = 0; j < client_indexes_size; j++) {
            auto cj = client_indexes[j];
            for (size_t k = 0; k < vecSize; k++) {
                auto modq_k = elementParams->GetParams()[k]->GetModulus();
                NativePoly multpoly(elementParams->GetParams()[k], Format::COEFFICIENT, true);
                multpoly.AddILElementOne();
                for (uint32_t i = 0; i < client_indexes_size; i++) {
                    auto ci = client_indexes[i];
                    if (ci != cj) {
                        auto&& denominator = (cj < ci) ? NativeInteger(ci - cj) : modq_k - NativeInteger(cj - ci);
                        auto denom_inv{denominator.ModInverse(modq_k)};
                        for (size_t d = 0; d < ring_dimension; ++d)
                            multpoly[d].ModMulFastEq(NativeInteger(ci).ModMul(denom_inv, modq_k), modq_k);
                    }
                }
                multpoly.SetFormat(Format::EVALUATION);
                Lagrange_coeffs[j].SetElementAtIndex(k, multpoly);
            }
            Lagrange_coeffs[j].SetFormat(Format::COEFFICIENT);
        }

        DCRTPoly lagrange_sum_of_elems(elementParams, Format::COEFFICIENT, true);
        for (size_t k = 0; k < vecSize; ++k) {
            NativePoly lagrange_sum_of_elems_poly(elementParams->GetParams()[k], Format::COEFFICIENT, true);
            for (uint32_t i = 0; i < client_indexes_size; ++i) {
                const auto& coeff = Lagrange_coeffs[i].GetAllElements()[k];
                const auto& share = sk_shares[client_indexes[i]].GetAllElements()[k];
                lagrange_sum_of_elems_poly += coeff.TimesNoCheck(share);
            }
            lagrange_sum_of_elems.SetElementAtIndex(k, lagrange_sum_of_elems_poly);
        }
        lagrange_sum_of_elems.SetFormat(Format::EVALUATION);
        sk->SetPrivateElement(lagrange_sum_of_elems);
    }
}

template class CryptoContextImpl<DCRTPoly>;

}  // namespace lbcrypto
