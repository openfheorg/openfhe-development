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
        OPENFHE_THROW(type_error, "Cannot set KeySwitchingTechnique as the parameter object is not RNS-based");
    }
}

/////////////////////////////////////////
// SHE MULTIPLICATION
/////////////////////////////////////////

template <typename Element>
void CryptoContextImpl<Element>::EvalMultKeyGen(const PrivateKey<Element> key) {
    if (key == nullptr || Mismatched(key->GetCryptoContext()))
        OPENFHE_THROW(config_error,
                      "Key passed to EvalMultKeyGen were not generated with this "
                      "crypto context");

    EvalKey<Element> k = GetScheme()->EvalMultKeyGen(key);

    GetAllEvalMultKeys()[k->GetKeyTag()] = {k};
}

template <typename Element>
void CryptoContextImpl<Element>::EvalMultKeysGen(const PrivateKey<Element> key) {
    if (key == nullptr || Mismatched(key->GetCryptoContext()))
        OPENFHE_THROW(config_error,
                      "Key passed to EvalMultsKeyGen were not generated with this "
                      "crypto context");

    const std::vector<EvalKey<Element>>& evalKeys = GetScheme()->EvalMultKeysGen(key);

    GetAllEvalMultKeys()[evalKeys[0]->GetKeyTag()] = evalKeys;
}

template <typename Element>
const std::vector<EvalKey<Element>>& CryptoContextImpl<Element>::GetEvalMultKeyVector(const std::string& keyID) {
    auto ekv = GetAllEvalMultKeys().find(keyID);
    if (ekv == GetAllEvalMultKeys().end())
        OPENFHE_THROW(not_available_error,
                      "You need to use EvalMultKeyGen so that you have an "
                      "EvalMultKey available for this ID");
    return ekv->second;
}

template <typename Element>
std::map<std::string, std::vector<EvalKey<Element>>>& CryptoContextImpl<Element>::GetAllEvalMultKeys() {
    return evalMultKeyMap();
}

template <typename Element>
void CryptoContextImpl<Element>::ClearEvalMultKeys() {
    GetAllEvalMultKeys().clear();
}

/**
 * ClearEvalMultKeys - flush EvalMultKey cache for a given id
 * @param id
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalMultKeys(const std::string& id) {
    auto kd = GetAllEvalMultKeys().find(id);
    if (kd != GetAllEvalMultKeys().end())
        GetAllEvalMultKeys().erase(kd);
}

/**
 * ClearEvalMultKeys - flush EvalMultKey cache for a given context
 * @param cc
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalMultKeys(const CryptoContext<Element> cc) {
    for (auto it = GetAllEvalMultKeys().begin(); it != GetAllEvalMultKeys().end();) {
        if (it->second[0]->GetCryptoContext() == cc) {
            it = GetAllEvalMultKeys().erase(it);
        }
        else {
            ++it;
        }
    }
}

template <typename Element>
void CryptoContextImpl<Element>::InsertEvalMultKey(const std::vector<EvalKey<Element>>& vectorToInsert) {
    GetAllEvalMultKeys()[vectorToInsert[0]->GetKeyTag()] = vectorToInsert;
}

/////////////////////////////////////////
// ADVANCED SHE
/////////////////////////////////////////

template <typename Element>
void CryptoContextImpl<Element>::EvalSumKeyGen(const PrivateKey<Element> privateKey,
                                               const PublicKey<Element> publicKey) {
    if (privateKey == nullptr || Mismatched(privateKey->GetCryptoContext())) {
        OPENFHE_THROW(config_error,
                      "Private key passed to EvalSumKeyGen were not generated "
                      "with this crypto context");
    }

    if (publicKey != nullptr && privateKey->GetKeyTag() != publicKey->GetKeyTag()) {
        OPENFHE_THROW(config_error, "Public key passed to EvalSumKeyGen does not match private key");
    }

    auto evalKeys = GetScheme()->EvalSumKeyGen(privateKey, publicKey);

    GetAllEvalSumKeys()[privateKey->GetKeyTag()] = evalKeys;
}

template <typename Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> CryptoContextImpl<Element>::EvalSumRowsKeyGen(
    const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey, usint rowSize, usint subringDim) {
    if (privateKey == nullptr || Mismatched(privateKey->GetCryptoContext())) {
        OPENFHE_THROW(config_error,
                      "Private key passed to EvalSumKeyGen were not generated "
                      "with this crypto context");
    }

    if (publicKey != nullptr && privateKey->GetKeyTag() != publicKey->GetKeyTag()) {
        OPENFHE_THROW(config_error, "Public key passed to EvalSumKeyGen does not match private key");
    }

    auto evalKeys = GetScheme()->EvalSumRowsKeyGen(privateKey, publicKey, rowSize, subringDim);

    return evalKeys;
}

template <typename Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> CryptoContextImpl<Element>::EvalSumColsKeyGen(
    const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey) {
    if (privateKey == nullptr || Mismatched(privateKey->GetCryptoContext())) {
        OPENFHE_THROW(config_error,
                      "Private key passed to EvalSumKeyGen were not generated "
                      "with this crypto context");
    }

    if (publicKey != nullptr && privateKey->GetKeyTag() != publicKey->GetKeyTag()) {
        OPENFHE_THROW(config_error, "Public key passed to EvalSumKeyGen does not match private key");
    }

    auto evalKeys = GetScheme()->EvalSumColsKeyGen(privateKey, publicKey);

    return evalKeys;
}

template <typename Element>
const std::map<usint, EvalKey<Element>>& CryptoContextImpl<Element>::GetEvalSumKeyMap(const std::string& keyID) {
    auto ekv = GetAllEvalSumKeys().find(keyID);
    if (ekv == GetAllEvalSumKeys().end())
        OPENFHE_THROW(not_available_error,
                      "You need to use EvalSumKeyGen so that you have EvalSumKeys "
                      "available for this ID");
    return *ekv->second;
}

template <typename Element>
std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>>&
CryptoContextImpl<Element>::GetAllEvalSumKeys() {
    return evalSumKeyMap();
}

template <typename Element>
void CryptoContextImpl<Element>::ClearEvalSumKeys() {
    GetAllEvalSumKeys().clear();
}

/**
 * ClearEvalMultKeys - flush EvalMultKey cache for a given id
 * @param id
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalSumKeys(const std::string& id) {
    auto kd = GetAllEvalSumKeys().find(id);
    if (kd != GetAllEvalSumKeys().end())
        GetAllEvalSumKeys().erase(kd);
}

/**
 * ClearEvalMultKeys - flush EvalMultKey cache for a given context
 * @param cc
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalSumKeys(const CryptoContext<Element> cc) {
    for (auto it = GetAllEvalSumKeys().begin(); it != GetAllEvalSumKeys().end();) {
        if (it->second->begin()->second->GetCryptoContext() == cc) {
            it = GetAllEvalSumKeys().erase(it);
        }
        else {
            ++it;
        }
    }
}

template <typename Element>
void CryptoContextImpl<Element>::InsertEvalSumKey(
    const std::shared_ptr<std::map<usint, EvalKey<Element>>> mapToInsert) {
    // find the tag
    if (!mapToInsert->empty()) {
        auto onekey                                      = mapToInsert->begin();
        GetAllEvalSumKeys()[onekey->second->GetKeyTag()] = mapToInsert;
    }
}

/////////////////////////////////////////
// SHE AUTOMORPHISM
/////////////////////////////////////////

template <typename Element>
void CryptoContextImpl<Element>::EvalAtIndexKeyGen(const PrivateKey<Element> privateKey,
                                                   const std::vector<int32_t>& indexList,
                                                   const PublicKey<Element> publicKey) {
    if (privateKey == nullptr || Mismatched(privateKey->GetCryptoContext())) {
        OPENFHE_THROW(config_error,
                      "Private key passed to EvalAtIndexKeyGen were not generated "
                      "with this crypto context");
    }

    if (publicKey != nullptr && privateKey->GetKeyTag() != publicKey->GetKeyTag()) {
        OPENFHE_THROW(config_error, "Public key passed to EvalAtIndexKeyGen does not match private key");
    }

    auto evalKeys = GetScheme()->EvalAtIndexKeyGen(publicKey, privateKey, indexList);

    auto ekv = GetAllEvalAutomorphismKeys().find(privateKey->GetKeyTag());
    if (ekv == GetAllEvalAutomorphismKeys().end()) {
        GetAllEvalAutomorphismKeys()[privateKey->GetKeyTag()] = evalKeys;
    }
    else {
        auto& currRotMap = GetEvalAutomorphismKeyMap(privateKey->GetKeyTag());
        auto iterRowKeys = evalKeys->begin();
        while (iterRowKeys != evalKeys->end()) {
            auto idx = iterRowKeys->first;
            // Search current rotation key map and add key
            // only if it doesn't exist
            if (currRotMap.find(idx) == currRotMap.end()) {
                currRotMap.insert(*iterRowKeys);
            }
            iterRowKeys++;
        }
    }

    //  evalAutomorphismKeyMap()[privateKey->GetKeyTag()] = evalKeys;
}

template <typename Element>
std::map<usint, EvalKey<Element>>& CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(const std::string& keyID) {
    auto ekv = evalAutomorphismKeyMap().find(keyID);
    if (ekv == evalAutomorphismKeyMap().end())
        OPENFHE_THROW(not_available_error,
                      "You need to use EvalAutomorphismKeyGen so that you have "
                      "EvalAutomorphismKeys available for this ID");
    return *ekv->second;
}

template <typename Element>
std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>>&
CryptoContextImpl<Element>::GetAllEvalAutomorphismKeys() {
    return evalAutomorphismKeyMap();
}

template <typename Element>
void CryptoContextImpl<Element>::ClearEvalAutomorphismKeys() {
    evalAutomorphismKeyMap().clear();
}

/**
 * ClearEvalAutomorphismKeys - flush EvalAutomorphismKey cache for a given id
 * @param id
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalAutomorphismKeys(const std::string& id) {
    auto kd = evalAutomorphismKeyMap().find(id);
    if (kd != evalAutomorphismKeyMap().end())
        evalAutomorphismKeyMap().erase(kd);
}

/**
 * ClearEvalAutomorphismKeys - flush EvalAutomorphismKey cache for a given
 * context
 * @param cc
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalAutomorphismKeys(const CryptoContext<Element> cc) {
    for (auto it = evalAutomorphismKeyMap().begin(); it != evalAutomorphismKeyMap().end();) {
        if (it->second->begin()->second->GetCryptoContext() == cc) {
            it = evalAutomorphismKeyMap().erase(it);
        }
        else {
            ++it;
        }
    }
}

template <typename Element>
void CryptoContextImpl<Element>::InsertEvalAutomorphismKey(
    const std::shared_ptr<std::map<usint, EvalKey<Element>>> mapToInsert) {
    // find the tag
    auto onekey                                           = mapToInsert->begin();
    evalAutomorphismKeyMap()[onekey->second->GetKeyTag()] = mapToInsert;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalSum(ConstCiphertext<Element> ciphertext, usint batchSize) const {
    if (ciphertext == nullptr || Mismatched(ciphertext->GetCryptoContext()))
        OPENFHE_THROW(config_error,
                      "Information passed to EvalSum was not generated with this "
                      "crypto context");

    auto evalSumKeys = CryptoContextImpl<Element>::GetEvalSumKeyMap(ciphertext->GetKeyTag());
    auto rv          = GetScheme()->EvalSum(ciphertext, batchSize, evalSumKeys);
    return rv;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalSumRows(ConstCiphertext<Element> ciphertext, usint rowSize,
                                                            const std::map<usint, EvalKey<Element>>& evalSumKeys,
                                                            usint subringDim) const {
    if (ciphertext == nullptr || Mismatched(ciphertext->GetCryptoContext()))
        OPENFHE_THROW(config_error,
                      "Information passed to EvalSum was not generated with this "
                      "crypto context");

    auto rv = GetScheme()->EvalSumRows(ciphertext, rowSize, evalSumKeys, subringDim);
    return rv;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalSumCols(
    ConstCiphertext<Element> ciphertext, usint rowSize,
    const std::map<usint, EvalKey<Element>>& evalSumKeysRight) const {
    if (ciphertext == nullptr || Mismatched(ciphertext->GetCryptoContext()))
        OPENFHE_THROW(config_error,
                      "Information passed to EvalSum was not generated with this "
                      "crypto context");

    auto evalSumKeys = CryptoContextImpl<Element>::GetEvalSumKeyMap(ciphertext->GetKeyTag());

    auto rv = GetScheme()->EvalSumCols(ciphertext, rowSize, evalSumKeys, evalSumKeysRight);
    return rv;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalAtIndex(ConstCiphertext<Element> ciphertext, int32_t index) const {
    if (ciphertext == nullptr || Mismatched(ciphertext->GetCryptoContext()))
        OPENFHE_THROW(config_error,
                      "Information passed to EvalAtIndex was not generated with "
                      "this crypto context");

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
    if (ciphertextVector[0] == nullptr || Mismatched(ciphertextVector[0]->GetCryptoContext()))
        OPENFHE_THROW(config_error,
                      "Information passed to EvalMerge was not generated with "
                      "this crypto context");

    auto evalAutomorphismKeys = CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(ciphertextVector[0]->GetKeyTag());

    auto rv = GetScheme()->EvalMerge(ciphertextVector, evalAutomorphismKeys);

    return rv;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalInnerProduct(ConstCiphertext<Element> ct1,
                                                                 ConstCiphertext<Element> ct2, usint batchSize) const {
    if (ct1 == nullptr || ct2 == nullptr || ct1->GetKeyTag() != ct2->GetKeyTag() || Mismatched(ct1->GetCryptoContext()))
        OPENFHE_THROW(config_error,
                      "Information passed to EvalInnerProduct was not generated "
                      "with this crypto context");

    auto evalSumKeys = CryptoContextImpl<Element>::GetEvalSumKeyMap(ct1->GetKeyTag());
    auto ek          = GetEvalMultKeyVector(ct1->GetKeyTag());

    auto rv = GetScheme()->EvalInnerProduct(ct1, ct2, batchSize, evalSumKeys, ek[0]);
    return rv;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalInnerProduct(ConstCiphertext<Element> ct1, ConstPlaintext ct2,
                                                                 usint batchSize) const {
    if (ct1 == nullptr || ct2 == nullptr || Mismatched(ct1->GetCryptoContext()))
        OPENFHE_THROW(config_error,
                      "Information passed to EvalInnerProduct was not generated "
                      "with this crypto context");

    auto evalSumKeys = CryptoContextImpl<Element>::GetEvalSumKeyMap(ct1->GetKeyTag());

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
        OPENFHE_THROW(config_error, "ciphertext passed to Decrypt is empty");
    if (plaintext == nullptr)
        OPENFHE_THROW(config_error, "plaintext passed to Decrypt is empty");
    if (privateKey == nullptr || Mismatched(privateKey->GetCryptoContext()))
        OPENFHE_THROW(config_error,
                      "Information passed to Decrypt was not generated with "
                      "this crypto context");

    // determine which type of plaintext that you need to decrypt into
    // Plaintext decrypted =
    // GetPlaintextForDecrypt(ciphertext->GetEncodingType(),
    // this->GetElementParams(), this->GetEncodingParams());
    Plaintext decrypted = GetPlaintextForDecrypt(ciphertext->GetEncodingType(),
                                                 ciphertext->GetElements()[0].GetParams(), this->GetEncodingParams());

    DecryptResult result;

    if ((ciphertext->GetEncodingType() == CKKS_PACKED_ENCODING) && (typeid(Element) != typeid(NativePoly))) {
        result = GetScheme()->Decrypt(ciphertext, privateKey, &decrypted->GetElement<Poly>());
    }
    else {
        result = GetScheme()->Decrypt(ciphertext, privateKey, &decrypted->GetElement<NativePoly>());
    }

    if (result.isValid == false)
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

template <typename Element>
DecryptResult CryptoContextImpl<Element>::MultipartyDecryptFusion(
    const std::vector<Ciphertext<Element>>& partialCiphertextVec, Plaintext* plaintext) const {
    DecryptResult result;

    // Make sure we're processing ciphertexts.
    size_t last_ciphertext = partialCiphertextVec.size();
    if (last_ciphertext < 1)
        return result;

    for (size_t i = 0; i < last_ciphertext; i++) {
        if (partialCiphertextVec[i] == nullptr || Mismatched(partialCiphertextVec[i]->GetCryptoContext()))
            OPENFHE_THROW(config_error,
                          "A ciphertext passed to MultipartyDecryptFusion was not "
                          "generated with this crypto context");
        if (partialCiphertextVec[i]->GetEncodingType() != partialCiphertextVec[0]->GetEncodingType())
            OPENFHE_THROW(type_error,
                          "Ciphertexts passed to MultipartyDecryptFusion have "
                          "mismatched encoding types");
    }

    // determine which type of plaintext that you need to decrypt into
    Plaintext decrypted =
        GetPlaintextForDecrypt(partialCiphertextVec[0]->GetEncodingType(),
                               partialCiphertextVec[0]->GetElements()[0].GetParams(), this->GetEncodingParams());

    if ((partialCiphertextVec[0]->GetEncodingType() == CKKS_PACKED_ENCODING) && (typeid(Element) != typeid(NativePoly)))
        result = GetScheme()->MultipartyDecryptFusion(partialCiphertextVec, &decrypted->GetElement<Poly>());
    else
        result = GetScheme()->MultipartyDecryptFusion(partialCiphertextVec, &decrypted->GetElement<NativePoly>());

    if (result.isValid == false)
        return result;

    if (partialCiphertextVec[0]->GetEncodingType() == CKKS_PACKED_ENCODING) {
        auto decryptedCKKS = std::dynamic_pointer_cast<CKKSPackedEncoding>(decrypted);
        decryptedCKKS->SetSlots(partialCiphertextVec[0]->GetSlots());
        const auto cryptoParamsCKKS = std::dynamic_pointer_cast<CryptoParametersRNS>(this->GetCryptoParameters());
        decryptedCKKS->Decode(partialCiphertextVec[0]->GetNoiseScaleDeg(), partialCiphertextVec[0]->GetScalingFactor(),
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

//------------------------------------------------------------------------------
// Advanced SHE LINEAR TRANSFORMATION
//------------------------------------------------------------------------------

// TODO Andrey add from bootstrapping

//------------------------------------------------------------------------------
// FHE Bootstrap Methods
//------------------------------------------------------------------------------

template <typename Element>
void CryptoContextImpl<Element>::EvalBootstrapSetup(std::vector<uint32_t> levelBudget, std::vector<uint32_t> dim1,
                                                    uint32_t numSlots, uint32_t correctionFactor) {
    GetScheme()->EvalBootstrapSetup(*this, levelBudget, dim1, numSlots, correctionFactor);
}

template <typename Element>
void CryptoContextImpl<Element>::EvalBootstrapKeyGen(const PrivateKey<Element> privateKey, uint32_t slots) {
    if (privateKey == NULL || this->Mismatched(privateKey->GetCryptoContext())) {
        OPENFHE_THROW(config_error,
                      "Private key passed to EvalBootstapKeyGen was not generated with this crypto context");
    }

    auto evalKeys = GetScheme()->EvalBootstrapKeyGen(privateKey, slots);

    auto ekv = GetAllEvalAutomorphismKeys().find(privateKey->GetKeyTag());
    if (ekv == GetAllEvalAutomorphismKeys().end()) {
        GetAllEvalAutomorphismKeys()[privateKey->GetKeyTag()] = evalKeys;
    }
    else {
        auto& currRotMap = GetEvalAutomorphismKeyMap(privateKey->GetKeyTag());
        auto iterRowKeys = evalKeys->begin();
        while (iterRowKeys != evalKeys->end()) {
            auto idx = iterRowKeys->first;
            // Search current rotation key map and add key
            // only if it doesn't exist
            if (currRotMap.find(idx) == currRotMap.end()) {
                currRotMap.insert(*iterRowKeys);
            }
            iterRowKeys++;
        }
    }
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalBootstrap(ConstCiphertext<Element> ciphertext,
                                                              uint32_t numIterations, uint32_t precision) const {
    return GetScheme()->EvalBootstrap(ciphertext, numIterations, precision);
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
        OPENFHE_THROW(config_error, "ciphertext passed to Decrypt is empty");
    if (plaintext == nullptr)
        OPENFHE_THROW(config_error, "plaintext passed to Decrypt is empty");
    if (privateKey == nullptr || Mismatched(privateKey->GetCryptoContext()))
        OPENFHE_THROW(config_error,
                      "Information passed to Decrypt was not generated with "
                      "this crypto context");

    // determine which type of plaintext that you need to decrypt into
    // Plaintext decrypted =
    // GetPlaintextForDecrypt(ciphertext->GetEncodingType(),
    // this->GetElementParams(), this->GetEncodingParams());
    Plaintext decrypted = GetPlaintextForDecrypt(ciphertext->GetEncodingType(),
                                                 ciphertext->GetElements()[0].GetParams(), this->GetEncodingParams());

    DecryptResult result;

    if ((ciphertext->GetEncodingType() == CKKS_PACKED_ENCODING) &&
        (ciphertext->GetElements()[0].GetParams()->GetParams().size() > 1))  // only one tower in DCRTPoly
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
        if (partialCiphertextVec[i] == nullptr || Mismatched(partialCiphertextVec[i]->GetCryptoContext()))
            OPENFHE_THROW(config_error,
                          "A ciphertext passed to MultipartyDecryptFusion was not "
                          "generated with this crypto context");
        if (partialCiphertextVec[i]->GetEncodingType() != partialCiphertextVec[0]->GetEncodingType())
            OPENFHE_THROW(type_error,
                          "Ciphertexts passed to MultipartyDecryptFusion have "
                          "mismatched encoding types");
    }

    // determine which type of plaintext that you need to decrypt into
    Plaintext decrypted =
        GetPlaintextForDecrypt(partialCiphertextVec[0]->GetEncodingType(),
                               partialCiphertextVec[0]->GetElements()[0].GetParams(), this->GetEncodingParams());

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

template class CryptoContextImpl<DCRTPoly>;

}  // namespace lbcrypto
