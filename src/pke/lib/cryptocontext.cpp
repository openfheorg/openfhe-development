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
#include "schemerns/rns-scheme.h"

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
void CryptoContextImpl<Element>::EvalMultKeysGen(
    const PrivateKey<Element> key) {
  if (key == nullptr || Mismatched(key->GetCryptoContext()))
    OPENFHE_THROW(config_error,
                   "Key passed to EvalMultsKeyGen were not generated with this "
                   "crypto context");

  const std::vector<EvalKey<Element>>& evalKeys =
      GetScheme()->EvalMultKeysGen(key);

  GetAllEvalMultKeys()[evalKeys[0]->GetKeyTag()] = evalKeys;
}

template <typename Element>
const std::vector<EvalKey<Element>>&
CryptoContextImpl<Element>::GetEvalMultKeyVector(const std::string& keyID) {
  auto ekv = GetAllEvalMultKeys().find(keyID);
  if (ekv == GetAllEvalMultKeys().end())
    OPENFHE_THROW(not_available_error,
                   "You need to use EvalMultKeyGen so that you have an "
                   "EvalMultKey available for this ID");
  return ekv->second;
}

template <typename Element>
std::map<std::string, std::vector<EvalKey<Element>>>&
CryptoContextImpl<Element>::GetAllEvalMultKeys() {
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
  if (kd != GetAllEvalMultKeys().end()) GetAllEvalMultKeys().erase(kd);
}

/**
 * ClearEvalMultKeys - flush EvalMultKey cache for a given context
 * @param cc
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalMultKeys(
    const CryptoContext<Element> cc) {
  for (auto it = GetAllEvalMultKeys().begin();
       it != GetAllEvalMultKeys().end();) {
    if (it->second[0]->GetCryptoContext() == cc) {
      it = GetAllEvalMultKeys().erase(it);
    } else {
      ++it;
    }
  }
}

template <typename Element>
void CryptoContextImpl<Element>::InsertEvalMultKey(
    const std::vector<EvalKey<Element>>& vectorToInsert) {
  GetAllEvalMultKeys()[vectorToInsert[0]->GetKeyTag()] = vectorToInsert;
}

/////////////////////////////////////////
// ADVANCED SHE
/////////////////////////////////////////

template <typename Element>
void CryptoContextImpl<Element>::EvalSumKeyGen(
    const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey) {
  if (privateKey == nullptr || Mismatched(privateKey->GetCryptoContext())) {
    OPENFHE_THROW(config_error,
                   "Private key passed to EvalSumKeyGen were not generated "
                   "with this crypto context");
  }

  if (publicKey != nullptr &&
      privateKey->GetKeyTag() != publicKey->GetKeyTag()) {
    OPENFHE_THROW(
        config_error,
        "Public key passed to EvalSumKeyGen does not match private key");
  }

  auto evalKeys = GetScheme()->EvalSumKeyGen(privateKey, publicKey);

  GetAllEvalSumKeys()[privateKey->GetKeyTag()] = evalKeys;
}

template <typename Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>>
CryptoContextImpl<Element>::EvalSumRowsKeyGen(
    const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey,
    usint rowSize, usint subringDim) {
  if (privateKey == nullptr || Mismatched(privateKey->GetCryptoContext())) {
    OPENFHE_THROW(config_error,
                   "Private key passed to EvalSumKeyGen were not generated "
                   "with this crypto context");
  }

  if (publicKey != nullptr &&
      privateKey->GetKeyTag() != publicKey->GetKeyTag()) {
    OPENFHE_THROW(
        config_error,
        "Public key passed to EvalSumKeyGen does not match private key");
  }

  auto evalKeys = GetScheme()->EvalSumRowsKeyGen(
      privateKey, publicKey, rowSize, subringDim);

  return evalKeys;
}

template <typename Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>>
CryptoContextImpl<Element>::EvalSumColsKeyGen(
    const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey) {
  if (privateKey == nullptr || Mismatched(privateKey->GetCryptoContext())) {
    OPENFHE_THROW(config_error,
                   "Private key passed to EvalSumKeyGen were not generated "
                   "with this crypto context");
  }

  if (publicKey != nullptr &&
      privateKey->GetKeyTag() != publicKey->GetKeyTag()) {
    OPENFHE_THROW(
        config_error,
        "Public key passed to EvalSumKeyGen does not match private key");
  }

  auto evalKeys =
      GetScheme()->EvalSumColsKeyGen(privateKey, publicKey);

  return evalKeys;
}

template <typename Element>
const std::map<usint, EvalKey<Element>>&
CryptoContextImpl<Element>::GetEvalSumKeyMap(const std::string& keyID) {
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
  if (kd != GetAllEvalSumKeys().end()) GetAllEvalSumKeys().erase(kd);
}

/**
 * ClearEvalMultKeys - flush EvalMultKey cache for a given context
 * @param cc
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalSumKeys(
    const CryptoContext<Element> cc) {
  for (auto it = GetAllEvalSumKeys().begin();
       it != GetAllEvalSumKeys().end();) {
    if (it->second->begin()->second->GetCryptoContext() == cc) {
      it = GetAllEvalSumKeys().erase(it);
    } else {
      ++it;
    }
  }
}

template <typename Element>
void CryptoContextImpl<Element>::InsertEvalSumKey(
    const std::shared_ptr<std::map<usint, EvalKey<Element>>> mapToInsert) {
  // find the tag
  if (!mapToInsert->empty()) {
    auto onekey = mapToInsert->begin();
    GetAllEvalSumKeys()[onekey->second->GetKeyTag()] = mapToInsert;
  }
}

/////////////////////////////////////////
// SHE AUTOMORPHISM
/////////////////////////////////////////

template <typename Element>
void CryptoContextImpl<Element>::EvalAtIndexKeyGen(
    const PrivateKey<Element> privateKey, const std::vector<int32_t>& indexList,
    const PublicKey<Element> publicKey) {
  if (privateKey == nullptr || Mismatched(privateKey->GetCryptoContext())) {
    OPENFHE_THROW(config_error,
                   "Private key passed to EvalAtIndexKeyGen were not generated "
                   "with this crypto context");
  }

  if (publicKey != nullptr &&
      privateKey->GetKeyTag() != publicKey->GetKeyTag()) {
    OPENFHE_THROW(
        config_error,
        "Public key passed to EvalAtIndexKeyGen does not match private key");
  }

  auto evalKeys = GetScheme()->EvalAtIndexKeyGen(
      publicKey, privateKey, indexList);

  evalAutomorphismKeyMap()[privateKey->GetKeyTag()] = evalKeys;
}

template <typename Element>
const std::map<usint, EvalKey<Element>>&
CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(const std::string& keyID) {
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
  if (kd != evalAutomorphismKeyMap().end()) evalAutomorphismKeyMap().erase(kd);
}

/**
 * ClearEvalAutomorphismKeys - flush EvalAutomorphismKey cache for a given
 * context
 * @param cc
 */
template <typename Element>
void CryptoContextImpl<Element>::ClearEvalAutomorphismKeys(
    const CryptoContext<Element> cc) {
  for (auto it = evalAutomorphismKeyMap().begin();
       it != evalAutomorphismKeyMap().end();) {
    if (it->second->begin()->second->GetCryptoContext() == cc) {
      it = evalAutomorphismKeyMap().erase(it);
    } else {
      ++it;
    }
  }
}

template <typename Element>
void CryptoContextImpl<Element>::InsertEvalAutomorphismKey(
    const std::shared_ptr<std::map<usint, EvalKey<Element>>> mapToInsert) {
  // find the tag
  auto onekey = mapToInsert->begin();
  evalAutomorphismKeyMap()[onekey->second->GetKeyTag()] = mapToInsert;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalSum(
    ConstCiphertext<Element> ciphertext, usint batchSize) const {
  if (ciphertext == nullptr || Mismatched(ciphertext->GetCryptoContext()))
    OPENFHE_THROW(config_error,
                   "Information passed to EvalSum was not generated with this "
                   "crypto context");

  auto evalSumKeys =
      CryptoContextImpl<Element>::GetEvalSumKeyMap(ciphertext->GetKeyTag());
  auto rv =
      GetScheme()->EvalSum(ciphertext, batchSize, evalSumKeys);
  return rv;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalSumRows(
    ConstCiphertext<Element> ciphertext, usint rowSize,
    const std::map<usint, EvalKey<Element>>& evalSumKeys,
    usint subringDim) const {
  if (ciphertext == nullptr || Mismatched(ciphertext->GetCryptoContext()))
    OPENFHE_THROW(config_error,
                   "Information passed to EvalSum was not generated with this "
                   "crypto context");

  auto rv = GetScheme()->EvalSumRows(ciphertext, rowSize,
                                                  evalSumKeys, subringDim);
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

  auto evalSumKeys =
      CryptoContextImpl<Element>::GetEvalSumKeyMap(ciphertext->GetKeyTag());

  auto rv = GetScheme()->EvalSumCols(
      ciphertext, rowSize, evalSumKeys, evalSumKeysRight);
  return rv;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalAtIndex(
    ConstCiphertext<Element> ciphertext, int32_t index) const {
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

  auto evalAutomorphismKeys =
      CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(
          ciphertext->GetKeyTag());

  auto rv = GetScheme()->EvalAtIndex(ciphertext, index,
                                                  evalAutomorphismKeys);
  return rv;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalMerge(
    const std::vector<Ciphertext<Element>>& ciphertextVector) const {
  if (ciphertextVector[0] == nullptr ||
      Mismatched(ciphertextVector[0]->GetCryptoContext()))
    OPENFHE_THROW(config_error,
                   "Information passed to EvalMerge was not generated with "
                   "this crypto context");

  auto evalAutomorphismKeys =
      CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(
          ciphertextVector[0]->GetKeyTag());

  auto rv = GetScheme()->EvalMerge(ciphertextVector,
                                                evalAutomorphismKeys);

  return rv;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalInnerProduct(
    ConstCiphertext<Element> ct1, ConstCiphertext<Element> ct2,
    usint batchSize) const {
  if (ct1 == nullptr || ct2 == nullptr ||
      ct1->GetKeyTag() != ct2->GetKeyTag() ||
      Mismatched(ct1->GetCryptoContext()))
    OPENFHE_THROW(config_error,
                   "Information passed to EvalInnerProduct was not generated "
                   "with this crypto context");

  auto evalSumKeys =
      CryptoContextImpl<Element>::GetEvalSumKeyMap(ct1->GetKeyTag());
  auto ek = GetEvalMultKeyVector(ct1->GetKeyTag());

  auto rv = GetScheme()->EvalInnerProduct(ct1, ct2, batchSize,
                                                       evalSumKeys, ek[0]);
  return rv;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalInnerProduct(
    ConstCiphertext<Element> ct1, ConstPlaintext ct2, usint batchSize) const {
  if (ct1 == nullptr || ct2 == nullptr || Mismatched(ct1->GetCryptoContext()))
    OPENFHE_THROW(config_error,
                   "Information passed to EvalInnerProduct was not generated "
                   "with this crypto context");

  auto evalSumKeys =
      CryptoContextImpl<Element>::GetEvalSumKeyMap(ct1->GetKeyTag());

  auto rv = GetScheme()->EvalInnerProduct(ct1, ct2, batchSize,
                                                       evalSumKeys);
  return rv;
}

template <typename Element>
Plaintext CryptoContextImpl<Element>::GetPlaintextForDecrypt(
    PlaintextEncodings pte, std::shared_ptr<ParmType> evp, EncodingParams ep) {
  auto vp = std::make_shared<typename NativePoly::Params>(
      evp->GetCyclotomicOrder(), ep->GetPlaintextModulus(), 1);

  if (pte == CKKSPacked) return PlaintextFactory::MakePlaintext(pte, evp, ep);

  return PlaintextFactory::MakePlaintext(pte, vp, ep);
}

template <typename Element>
DecryptResult CryptoContextImpl<Element>::Decrypt(
    ConstCiphertext<Element> ciphertext, const PrivateKey<Element> privateKey,
    Plaintext* plaintext) {
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
  Plaintext decrypted = GetPlaintextForDecrypt(
      ciphertext->GetEncodingType(), ciphertext->GetElements()[0].GetParams(),
      this->GetEncodingParams());

  DecryptResult result;

  if ((ciphertext->GetEncodingType() == CKKSPacked) &&
      (typeid(Element) != typeid(NativePoly))) {
    result = GetScheme()->Decrypt(ciphertext, privateKey,
                                               &decrypted->GetElement<Poly>());
  } else {
    result = GetScheme()->Decrypt(
        ciphertext, privateKey, &decrypted->GetElement<NativePoly>());
  }

  if (result.isValid == false) return result;

  decrypted->SetScalingFactorInt(result.scalingFactorInt);

  if (ciphertext->GetEncodingType() == CKKSPacked) {
    auto decryptedCKKS =
        std::static_pointer_cast<CKKSPackedEncoding>(decrypted);
    decryptedCKKS->SetDepth(ciphertext->GetDepth());
    decryptedCKKS->SetLevel(ciphertext->GetLevel());
    decryptedCKKS->SetScalingFactor(ciphertext->GetScalingFactor());
    decryptedCKKS->SetSlots(ciphertext->GetSlots());

    const auto cryptoParamsCKKS =
        std::dynamic_pointer_cast<CryptoParametersRNS>(
            this->GetCryptoParameters());

    decryptedCKKS->Decode(ciphertext->GetDepth(),
                          ciphertext->GetScalingFactor(),
                          cryptoParamsCKKS->GetRescalingTechnique());

  } else {
    decrypted->Decode();
  }

  *plaintext = std::move(decrypted);
  return result;
}

template <typename Element>
DecryptResult CryptoContextImpl<Element>::MultipartyDecryptFusion(
    const std::vector<Ciphertext<Element>>& partialCiphertextVec,
    Plaintext* plaintext) const {
  DecryptResult result;

  // Make sure we're processing ciphertexts.
  size_t last_ciphertext = partialCiphertextVec.size();
  if (last_ciphertext < 1) return result;

  for (size_t i = 0; i < last_ciphertext; i++) {
    if (partialCiphertextVec[i] == nullptr ||
        Mismatched(partialCiphertextVec[i]->GetCryptoContext()))
      OPENFHE_THROW(config_error,
                     "A ciphertext passed to MultipartyDecryptFusion was not "
                     "generated with this crypto context");
    if (partialCiphertextVec[i]->GetEncodingType() !=
        partialCiphertextVec[0]->GetEncodingType())
      OPENFHE_THROW(type_error,
                     "Ciphertexts passed to MultipartyDecryptFusion have "
                     "mismatched encoding types");
  }

  // determine which type of plaintext that you need to decrypt into
  Plaintext decrypted = GetPlaintextForDecrypt(
      partialCiphertextVec[0]->GetEncodingType(),
      partialCiphertextVec[0]->GetElements()[0].GetParams(),
      this->GetEncodingParams());

  if ((partialCiphertextVec[0]->GetEncodingType() == CKKSPacked) &&
      (typeid(Element) != typeid(NativePoly)))
    result = GetScheme()->MultipartyDecryptFusion(
        partialCiphertextVec, &decrypted->GetElement<Poly>());
  else
    result = GetScheme()->MultipartyDecryptFusion(
        partialCiphertextVec, &decrypted->GetElement<NativePoly>());

  if (result.isValid == false) return result;

  if (partialCiphertextVec[0]->GetEncodingType() == CKKSPacked) {
    auto decryptedCKKS =
        std::static_pointer_cast<CKKSPackedEncoding>(decrypted);
    decryptedCKKS->SetSlots(partialCiphertextVec[0]->GetSlots());
    const auto cryptoParamsCKKS =
        std::dynamic_pointer_cast<CryptoParametersRNS>(
            this->GetCryptoParameters());
    decryptedCKKS->Decode(partialCiphertextVec[0]->GetDepth(),
                          partialCiphertextVec[0]->GetScalingFactor(),
                          cryptoParamsCKKS->GetRescalingTechnique());
  } else {
    decrypted->Decode();
  }

  *plaintext = std::move(decrypted);

  return result;
}

template <typename Element>
void CryptoContextImpl<Element>::EvalLTKeyGen(const PrivateKey<Element> privateKey, uint32_t dim1,
                                                 int32_t bootstrapFlag, int32_t conjFlag) {
  if (privateKey == NULL || this->Mismatched(privateKey->GetCryptoContext())) {
    OPENFHE_THROW(config_error, "Private key passed to EvalLTKeyGen was not generated with this crypto context");
  }

  auto evalKeys = this->GetScheme()
                      ->EvalLTKeyGen(privateKey, dim1, bootstrapFlag,
                                     conjFlag);  // if it is just for LT/encoding, we need
                                                 // to pass dim1 too

  auto ekv = GetAllEvalRotationKeys().find(privateKey->GetKeyTag());
  if (ekv == GetAllEvalRotationKeys().end()) {
    GetAllEvalRotationKeys()[privateKey->GetKeyTag()] = evalKeys;
  } else {
    auto& currRotMap = GetEvalRotationKeyMap(privateKey->GetKeyTag());
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
  // EvalAtIndexKeyGen(privateKey, indexList);
}

template <typename Element>
std::vector<int32_t> CryptoContextImpl<Element>::FindLTRotationIndices(uint32_t dim1, int32_t bootstrapFlag, uint32_t m) {
    // if it is just for LT/encoding, we need to pass dim1 too
    return GetScheme()->FindLTRotationIndices(dim1, bootstrapFlag, m, m_blockDimension);

}

//#pragma clang diagnostic push
//#pragma ide diagnostic ignored "openmp-use-default-none"
template <typename Element>
std::vector<ConstPlaintext> CryptoContextImpl<Element>::EvalLTPrecompute(
    const std::vector<std::vector<std::complex<double>>>& A, uint32_t dim1, double scale, uint32_t L) const {
  if (A[0].size() != A.size()) {
    OPENFHE_THROW(math_error, "The matrix passed to EvalLTPrecompute is not square");
  }

  uint32_t slots = A.size();
  uint32_t m = this->GetCyclotomicOrder();

  // Computing the baby-step bStep and the giant-step gStep.
  int bStep = (dim1 == 0) ? ceil(sqrt(slots)) : dim1;
  int gStep = ceil(static_cast<double>(slots) / bStep);

  // make sure the plaintext is created only with the necessary amount of moduli

  const shared_ptr<CryptoParametersCKKSRNS> cryptoParamsCKKS =
      std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(this->GetCryptoParameters());

  ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParamsCKKS->GetElementParams());

  uint32_t towersToDrop = 0;
  if (L != 0) {
    towersToDrop = elementParams.GetParams().size() - L - 1;
    for (uint32_t i = 0; i < towersToDrop; i++) elementParams.PopLastParam();
  }

  auto paramsQ = elementParams.GetParams();
  usint sizeQ = paramsQ.size();
  auto paramsP = cryptoParamsCKKS->GetParamsP()->GetParams();
  usint sizeP = paramsP.size();

  std::vector<NativeInteger> moduli(sizeQ + sizeP);
  std::vector<NativeInteger> roots(sizeQ + sizeP);
  for (size_t i = 0; i < sizeQ; i++) {
    moduli[i] = paramsQ[i]->GetModulus();
    roots[i] = paramsQ[i]->GetRootOfUnity();
  }

  for (size_t i = 0; i < sizeP; i++) {
      moduli[sizeQ + i] = paramsP[i]->GetModulus();
      roots[sizeQ + i] = paramsP[i]->GetRootOfUnity();
  }

  auto elementParamsPtr = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(m, moduli, roots);
  auto elementParamsPtr2 = std::dynamic_pointer_cast<typename Element::Params>(elementParamsPtr);
  std::vector<ConstPlaintext> result(slots);
#pragma omp parallel for
  for (int j = 0; j < gStep; j++) {
      int offset = -bStep * j;
      for (int i = 0; i < bStep; i++) {
      if (bStep*j + i < static_cast<int>(slots)) {
        auto diag = ExtractShiftedDiagonal(A, bStep*j + i);
        for (uint32_t k = 0; k < diag.size(); k++) diag[k] *= scale;

        result[bStep * j + i] =
          this->MakeCKKSPackedPlaintext(Rotate(Fill(diag, m / 4), offset), 1, towersToDrop, elementParamsPtr2);
      }
    }
  }

  return result;
}
//#pragma clang diagnostic pop

template <typename Element>
std::vector<ConstPlaintext> CryptoContextImpl<Element>::EvalLTPrecompute(
    const std::vector<std::vector<std::complex<double>>>& A, const std::vector<std::vector<std::complex<double>>>& B,
    uint32_t dim1, uint32_t orientation, double scale, uint32_t L) const {
  uint32_t slots = A.size();
  uint32_t m = this->GetCyclotomicOrder();

  // Computing the baby-step bStep and the giant-step gStep.
  int bStep = (dim1 == 0) ? ceil(sqrt(slots)) : dim1;
  int gStep = ceil(static_cast<double>(slots) / bStep);

  // make sure the plaintext is created only with the necessary amount of moduli

  const shared_ptr<CryptoParametersCKKSRNS> cryptoParamsCKKS =
      std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(this->GetCryptoParameters());

  ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParamsCKKS->GetElementParams());

  uint32_t towersToDrop = 0;
  if (L != 0) {
    towersToDrop = elementParams.GetParams().size() - L - 1;
    for (uint32_t i = 0; i < towersToDrop; i++) elementParams.PopLastParam();
  }

  auto paramsQ = elementParams.GetParams();
  usint sizeQ = paramsQ.size();
  auto paramsP = cryptoParamsCKKS->GetParamsP()->GetParams();
  usint sizeP = paramsP.size();

  std::vector<NativeInteger> moduli(sizeQ + sizeP);
  std::vector<NativeInteger> roots(sizeQ + sizeP);
  for (size_t i = 0; i < sizeQ; i++) {
    moduli[i] = paramsQ[i]->GetModulus();
    roots[i] = paramsQ[i]->GetRootOfUnity();
  }

  for (size_t i = 0; i < sizeP; i++) {
    moduli[sizeQ + i] = paramsP[i]->GetModulus();
    roots[sizeQ + i] = paramsP[i]->GetRootOfUnity();
  }

  auto elementParamsPtr = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(m, moduli, roots);
  auto elementParamsPtr2 = std::dynamic_pointer_cast<typename Element::Params>(elementParamsPtr);
  std::vector<ConstPlaintext> result(slots);
  if (orientation == 0) {  // vertical concatenation - used during homomorphic encoding
    // #pragma omp parallel for
    for (int j = 0; j < gStep; j++) {
      int offset = -bStep * j;
      for (int i = 0; i < bStep; i++) {
        if (bStep * j + i < static_cast<int>(slots)) {
          auto vecA = ExtractShiftedDiagonal(A, bStep * j + i);
          auto vecB = ExtractShiftedDiagonal(B, bStep * j + i);

          vecA.insert(vecA.end(), vecB.begin(), vecB.end());
          for (uint32_t k = 0; k < vecA.size(); k++) vecA[k] *= scale;

          result[bStep * j + i] =
            this->MakeCKKSPackedPlaintext(Rotate(Fill(vecA, m / 4), offset), 1, towersToDrop, elementParamsPtr2);
        }
      }
    }
  } else {  // horizontal concatenation - used during homomorphic decoding
    std::vector<std::vector<std::complex<double>>> newA(slots);

    //  A and B are concatenated horizontally
    for (uint32_t i = 0; i < A.size(); i++) {
      auto vecA = A[i];
      auto vecB = B[i];
      vecA.insert(vecA.end(), vecB.begin(), vecB.end());
      newA[i] = vecA;
    }

#pragma omp parallel for
    for (int j = 0; j < gStep; j++) {
        int offset = -bStep*j;
        for (int i = 0; i < bStep; i++) {
        if (bStep*j + i < static_cast<int>(slots)) {
          // shifted diagonal is computed for rectangular map newA of dimension
          // slots x 2*slots
          auto vec = ExtractShiftedDiagonal(newA, bStep * j + i);
          for (uint32_t k = 0; k < vec.size(); k++) vec[k] *= scale;

          result[bStep * j + i] =
              this->MakeCKKSPackedPlaintext(Rotate(Fill(vec, m / 4), offset), 1, towersToDrop, elementParamsPtr2);
        }
      }
    }
  }

  return result;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalLTWithPrecomp(const std::vector<ConstPlaintext>& A,
                                                                     ConstCiphertext<Element> ct, uint32_t dim1) {
  uint32_t slots = A.size();

  // Computing the baby-step bStep and the giant-step gStep.
  uint32_t bStep = (dim1 == 0) ? ceil(sqrt(slots)) : dim1;
  uint32_t gStep = ceil(static_cast<double>(slots) / bStep);

  uint32_t m = this->GetCyclotomicOrder();
  uint32_t n = this->GetRingDimension();

  // computes the NTTs for each CRT limb (for the hoisted automorphisms used
  // later on)
  auto digits = this->EvalFastRotationPrecompute(ct);

  std::vector<Ciphertext<Element>> fastRotation(bStep - 1);

  // hoisted automorphisms
#pragma omp parallel for
  for (uint32_t j = 1; j < bStep; j++) {
    fastRotation[j - 1] = this->EvalFastRotationExt(ct, j, digits, true);
  }

  Ciphertext<Element> result;
  Element first;

  for (uint32_t j = 0; j < gStep; j++) {
    Ciphertext<Element> inner = this->EvalMult(KeySwitchExt(ct, true), A[bStep * j]);
    for (uint32_t i = 1; i < bStep; i++) {
      if (bStep * j + i < slots) {
        inner = this->EvalAdd(inner, this->EvalMult(A[bStep * j + i], fastRotation[i - 1]));
      }
    }

    if (j == 0) {
      first = KeySwitchDownFirstElement(inner);
      auto elements = inner->GetElements();
      elements[0].SetValuesToZero();
      inner->SetElements(elements);
      result = inner;
    } else {
      inner = KeySwitchDown(inner);
      // Find the automorphism index that corresponds to rotation index index.
      usint autoIndex = FindAutomorphismIndex2nComplex(bStep * j, m);
      std::vector<usint> map(n);
      PrecomputeAutoMap(n, autoIndex, &map);
      Element firstCurrent = inner->GetElements()[0].AutomorphismTransform(autoIndex, map);
      first += firstCurrent;

      auto innerDigits = this->EvalFastRotationPrecompute(inner);
      result = this->EvalAdd(result, EvalFastRotationExt(inner, bStep * j, innerDigits, false));
    }
  }

  result = KeySwitchDown(result);
  auto elements = result->GetElements();
  elements[0] += first;
  result->SetElements(elements);

  return result;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalLT(const std::vector<std::vector<std::complex<double>>>& A,
                                                          ConstCiphertext<Element> ct, uint32_t dim1, double scale) {
  auto precomputedA = this->EvalLTPrecompute(A, dim1, scale);

  return EvalLTWithPrecomp(precomputedA, ct, dim1);
}

//#pragma clang diagnostic push
//#pragma ide diagnostic ignored "openmp-use-default-none"
template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalLTWithPrecomp(const std::vector<Plaintext>& A,
                                                                     ConstCiphertext<Element> ct, uint32_t dim1) {

    uint32_t slots = A.size();
//    cout<<"DIM1: "<<dim1<<endl;
//    cout<<"SLOTS: "<<slots<<endl;

    // Computing the baby-step g and the giant-step h.
    uint32_t g = (dim1 == 0) ? ceil(sqrt(slots)) : dim1;
//    uint32_t g = (dim1 == 0) ? 4 : dim1;
    uint32_t h = ceil(static_cast<double>(slots) / g);

    uint32_t m = this->GetCyclotomicOrder();
    uint32_t n = this->GetRingDimension();

    // computes the NTTs for each CRT limb (for the hoisted automorphisms used
    // later on)
    auto digits = this->EvalFastRotationPrecompute(ct);

    std::vector<Ciphertext<Element>> fastRotation(g - 1);

    // hoisted automorphisms
#pragma omp parallel for
for (uint32_t j = 1; j < g; j++) {
    fastRotation[j - 1] = this->EvalFastRotationExt(ct, j, digits, true);
}

Ciphertext<Element> result;
Element first;

for (uint32_t j = 0; j < h; j++) {
    Ciphertext<Element> inner = this->EvalMult(KeySwitchExt(ct, true), A[g * j]);
    for (uint32_t i = 1; i < g; i++) {
        if (g * j + i < slots) {
            inner = this->EvalAdd(inner, this->EvalMult(A[g * j + i], fastRotation[i - 1]));
        }
    }

    if (j == 0) {
        first = KeySwitchDownFirstElement(inner);
        auto elements = inner->GetElements();
        elements[0].SetValuesToZero();
        inner->SetElements(elements);
        result = inner;
    } else {
        inner = KeySwitchDown(inner);
        // Find the automorphism index that corresponds to rotation index index.
        usint autoIndex = FindAutomorphismIndex2nComplex(g * j, m);
        std::vector<usint> map(n);
        PrecomputeAutoMap(n, autoIndex, &map);
        Element firstCurrent = inner->GetElements()[0].AutomorphismTransform(autoIndex, map);
        first += firstCurrent;

        auto innerDigits = this->EvalFastRotationPrecompute(inner);
        result = this->EvalAdd(result, EvalFastRotationExt(inner, g * j, innerDigits, false));
    }
}

result = KeySwitchDown(result);
auto elements = result->GetElements();
elements[0] += first;
result->SetElements(elements);

return result;
}
//#pragma clang diagnostic pop

// -----------THE CODE FOR LINEAR TRANSFORM ENDS HERE----------

template <typename Element>
void CryptoContextImpl<Element>::EvalBTSetup(uint32_t dim1, uint32_t numSlots, uint32_t debugFlag, bool precomp) {
  GetScheme()->EvalBTSetup(*this, dim1, numSlots, debugFlag, precomp);
}

template <typename Element>
void CryptoContextImpl<Element>::EvalBTSetup(std::vector<uint32_t> levelBudget, std::vector<uint32_t> dim1,
                                                uint32_t numSlots, uint32_t debugFlag, bool precomp) {
  GetScheme()->EvalBTSetup(*this, levelBudget, dim1, numSlots, debugFlag, precomp);
}

template <typename Element>
void CryptoContextImpl<Element>::EvalBTPrecompute(uint32_t debugFlag) {
  GetScheme()->EvalBTPrecompute(*this, debugFlag);
}

template <typename Element>
void CryptoContextImpl<Element>::EvalBTKeyGen(const PrivateKey<Element> privateKey, int32_t bootstrapFlag) {
  if (privateKey == NULL || this->Mismatched(privateKey->GetCryptoContext())) {
    OPENFHE_THROW(config_error, "Private key passed to EvalBTKeyGen was not generated with this crypto context");
  }

  auto evalKeys = GetScheme()->EvalBTKeyGen(privateKey, bootstrapFlag);

  auto ekv = GetAllEvalRotationKeys().find(privateKey->GetKeyTag());
  if (ekv == GetAllEvalRotationKeys().end()) {
    GetAllEvalRotationKeys()[privateKey->GetKeyTag()] = evalKeys;
  } else {
    auto& currRotMap = GetEvalRotationKeyMap(privateKey->GetKeyTag());
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
EvalKey<Element> CryptoContextImpl<Element>::ConjugateKeyGen(
        const PrivateKey<Element> privateKey) const{
    return GetScheme()->ConjugateKeyGen(privateKey);
}

template <typename Element>
std::vector<int32_t> CryptoContextImpl<Element>::FindBTRotationIndices(int32_t bootstrapFlag, uint32_t m, uint32_t blockDimension) {
    return GetScheme()->FindBTRotationIndices(bootstrapFlag, m, blockDimension);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalBT(ConstCiphertext<Element> ciphertext) const {
  return GetScheme()->EvalBT(ciphertext);
}

template <typename Element>
uint32_t CryptoContextImpl<Element>::GetNumRotationsEnc() const {
  return GetScheme()->GetNumRotationsEnc();
}

template <typename Element>
uint32_t CryptoContextImpl<Element>::GetGiantStepEnc() const {
  return GetScheme()->GetGiantStepEnc();
}

template <typename Element>
uint32_t CryptoContextImpl<Element>::GetNumRotationsRemEnc() const {
  return GetScheme()->GetNumRotationsRemEnc();
}

template <typename Element>
uint32_t CryptoContextImpl<Element>::GetGiantStepRemEnc() const {
  return GetScheme()->GetGiantStepRemEnc();
}

template <typename Element>
uint32_t CryptoContextImpl<Element>::GetNumRotationsDec() const {
  return GetScheme()->GetNumRotationsDec();
}

template <typename Element>
uint32_t CryptoContextImpl<Element>::GetGiantStepDec() const {
  return GetScheme()->GetGiantStepDec();
}

template <typename Element>
uint32_t CryptoContextImpl<Element>::GetNumRotationsRemDec() const {
  return GetScheme()->GetNumRotationsRemDec();
}

template <typename Element>
uint32_t CryptoContextImpl<Element>::GetGiantStepRemDec() const {
  return GetScheme()->GetGiantStepRemDec();
}

template <typename Element>
const std::vector<int32_t>& CryptoContextImpl<Element>::GetRotationIndicesBT() const {
  return GetScheme()->GetRotationIndicesBT();
}

template <typename Element>
uint32_t CryptoContextImpl<Element>::GetNumberOfRotationIndicesBT() const {
  return GetScheme()->GetNumberOfRotationIndicesBT();
}

template <typename Element>
const std::vector<int32_t>& CryptoContextImpl<Element>::GetRotationIndicesLT() const {
  return GetScheme()->GetRotationIndicesLT();
}

template <typename Element>
uint32_t CryptoContextImpl<Element>::GetNumberOfRotationIndicesLT() const {
  return ->GetNumberOfRotationIndicesLT();
}

// -----------THE CODE FOR LINEAR TRANSFORM USINF FFT-LIKE METHODS ENDS
// HERE----------

template <typename Element>
void CryptoContextImpl<Element>::EvalPermuteFullKeyGen(const PrivateKey<Element> privateKey, int slots) {
  if (privateKey == NULL || this->Mismatched(privateKey->GetCryptoContext())) {
    OPENFHE_THROW(config_error,
                   "Private key passed to EvalPermuteFullKeyGen was not generated with this crypto context");
  }

  usint ringN = this->GetRingDimension() / 2;
  std::set<int, std::greater<int>> offsetSet;
  // Using a double loop to identify all the possible rotations
  // that can be performed during a permutation. The possible
  // rotations are kept in offsetSet.
  for (int i = 0; i < slots; i++) {
    for (int j = 0; j < slots; j++) {
      // If the rotation offset is negative (right rotation)
      // we translate it to a positive rotation by adding the
      // ring dimension.
      if (j - i < 0) {
        if (offsetSet.find(ringN + j - i) == offsetSet.end()) offsetSet.insert(ringN + j - i);
      } else {
        if (offsetSet.find(j - i) == offsetSet.end()) offsetSet.insert(j - i);
      }
    }
  }

  // For every rotation offset we identified, we add an entry in the
  // index list.
  std::vector<int32_t> indexList(offsetSet.size());
  int j = 0;
  for (auto it = offsetSet.begin(); it != offsetSet.end(); ++it) {
    indexList[j] = *it;
    j++;
  }

  this->EvalRotateKeyGen(privateKey, indexList);
}

template <typename Element>
void CryptoContextImpl<Element>::EvalPermuteBGStepKeyGen(const PrivateKey<Element> privateKey, int slots) {
  if (privateKey == NULL || this->Mismatched(privateKey->GetCryptoContext())) {
    OPENFHE_THROW(config_error,
                   "Private key passed to EvalPermuteBGStepKeyGen was not generated with this crypto context");
  }

  // Computing the baby-step bStep and the giant-step gStep.
  int bStep = ceil(sqrt(slots));

  usint ringN = this->GetRingDimension() / 2;
  std::set<int, std::greater<int>> babyOffsetSet;
  std::set<int, std::greater<int>> giantOffsetSet;
  // Using a double loop to identify all the possible rotations
  // that can be performed during a permutation. The baby/giant
  // steps of the possible rotations are kept in babyOffsetSet
  // and giantOffsetSet.
  for (int i = 0; i < slots; i++) {
    for (int j = 0; j < slots; j++) {
      int gIdx = (j - i) % bStep;
      int hIdx = (j - i) / bStep;
      hIdx = bStep * hIdx;

      // If baby/giant rotation steps are negative (right rotation)
      // we translate it to a positive rotation by adding the
      // ring dimension.
      if (gIdx < 0) {
        if (babyOffsetSet.find(ringN + gIdx) == babyOffsetSet.end()) babyOffsetSet.insert(ringN + gIdx);
      } else if (gIdx > 0) {
        if (babyOffsetSet.find(gIdx) == babyOffsetSet.end()) babyOffsetSet.insert(gIdx);
      }

      if (bStep * hIdx < 0) {
        if (giantOffsetSet.find(ringN + hIdx) == giantOffsetSet.end()) giantOffsetSet.insert(ringN + hIdx);
      } else if (bStep * hIdx > 0) {
        if (giantOffsetSet.find(hIdx) == giantOffsetSet.end()) giantOffsetSet.insert(hIdx);
      }
    }
  }

  // For every rotation offset we identified, we add an entry in the
  // index list.
  std::vector<int32_t> indexList(babyOffsetSet.size() + giantOffsetSet.size());
  int j = 0;
  for (auto it = babyOffsetSet.begin(); it != babyOffsetSet.end(); ++it) {
    indexList[j] = *it;
    j++;
  }
  for (auto it = giantOffsetSet.begin(); it != giantOffsetSet.end(); ++it) {
    indexList[j] = *it;
    j++;
  }

  this->EvalRotateKeyGen(privateKey, indexList);
}

template <typename Element>
void CryptoContextImpl<Element>::EvalPermuteBBHKeyGen(const PrivateKey<Element> privateKey, int slots) {
  if (privateKey == NULL || this->Mismatched(privateKey->GetCryptoContext())) {
    OPENFHE_THROW(config_error,
                   "Private key passed to EvalPermuteBGStepKeyGen was not generated with this crypto context");
  }

  // Computing the baby-step bStep and the giant-step gStep.
  int bStep = ceil(sqrt(slots));

  std::set<int, std::greater<int>> babyOffsetSet;
  std::set<int, std::greater<int>> giantOffsetSet;
  // Using a double loop to identify all the possible rotations
  // that can be performed during a permutation. The baby/giant
  // steps of the possible rotations are kept in babyOffsetSet
  // and giantOffsetSet.
  for (int i = 0; i < slots; i++) {
    for (int j = 0; j < slots; j++) {
      int gIdx = (j - i) % bStep;
      int hIdx = (j - i) / bStep;
      hIdx = bStep * hIdx;

      if (gIdx != 0 && babyOffsetSet.find(gIdx) == babyOffsetSet.end()) babyOffsetSet.insert(gIdx);

      if (hIdx != 0 && giantOffsetSet.find(hIdx) == giantOffsetSet.end()) giantOffsetSet.insert(hIdx);
    }
  }

  // For every rotation offset we identified, we add an entry in the
  // index list.
  std::vector<int32_t> indexList(babyOffsetSet.size() + giantOffsetSet.size());
  int j = 0;
  for (auto it = babyOffsetSet.begin(); it != babyOffsetSet.end(); ++it) {
    indexList[j] = *it;
    j++;
  }
  for (auto it = giantOffsetSet.begin(); it != giantOffsetSet.end(); ++it) {
    indexList[j] = *it;
    j++;
  }

  EvalRotateKeyGen(privateKey, indexList);
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalAtIndexBGStep(ConstCiphertext<Element> ciphertext, int32_t index,
                                                                     int32_t slots) const {
  if (ciphertext == NULL || this->Mismatched(ciphertext->GetCryptoContext()))
    OPENFHE_THROW(config_error, "Information passed to EvalAtIndexBGStep was not generated with this crypto context");

  auto tag = ciphertext->GetKeyTag();
  auto evalAutomorphismKeys = CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(tag);

  return GetScheme()->EvalAtIndexBGStep(ciphertext, index, slots, evalAutomorphismKeys);
}

}  // namespace lbcrypto

// the code below is from cryptocontext-impl.cpp
namespace lbcrypto {

    template <>
    Plaintext CryptoContextImpl<DCRTPoly>::GetPlaintextForDecrypt(
        PlaintextEncodings pte, std::shared_ptr<ParmType> evp, EncodingParams ep) {
        if ((pte == CKKSPacked) && (evp->GetParams().size() > 1)) {
            auto vp = std::make_shared<typename Poly::Params>(
                evp->GetCyclotomicOrder(), ep->GetPlaintextModulus(), 1);
            return PlaintextFactory::MakePlaintext(pte, vp, ep);
        }
        else {
            auto vp = std::make_shared<typename NativePoly::Params>(
                evp->GetCyclotomicOrder(), ep->GetPlaintextModulus(), 1);
            return PlaintextFactory::MakePlaintext(pte, vp, ep);
        }
    }

    template <>
    DecryptResult CryptoContextImpl<DCRTPoly>::Decrypt(
        ConstCiphertext<DCRTPoly> ciphertext,
        const PrivateKey<DCRTPoly> privateKey,
        Plaintext* plaintext) {
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
        Plaintext decrypted = GetPlaintextForDecrypt(
            ciphertext->GetEncodingType(), ciphertext->GetElements()[0].GetParams(),
            this->GetEncodingParams());

        DecryptResult result;

        if ((ciphertext->GetEncodingType() == CKKSPacked) &&
            (ciphertext->GetElements()[0].GetParams()->GetParams().size() >
                1))  // only one tower in DCRTPoly
            result = GetScheme()->Decrypt(ciphertext, privateKey,
                &decrypted->GetElement<Poly>());
        else
            result = GetScheme()->Decrypt(
                ciphertext, privateKey, &decrypted->GetElement<NativePoly>());

        if (result.isValid == false) return result;
        
        decrypted->SetScalingFactorInt(result.scalingFactorInt);

        if (ciphertext->GetEncodingType() == CKKSPacked) {
            auto decryptedCKKS =
                std::static_pointer_cast<CKKSPackedEncoding>(decrypted);
            decryptedCKKS->SetDepth(ciphertext->GetDepth());
            decryptedCKKS->SetLevel(ciphertext->GetLevel());
            decryptedCKKS->SetScalingFactor(ciphertext->GetScalingFactor());
            decryptedCKKS->SetSlots(ciphertext->GetSlots());

            const auto cryptoParamsCKKS =
                std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(
                    this->GetCryptoParameters());

            decryptedCKKS->Decode(ciphertext->GetDepth(),
                ciphertext->GetScalingFactor(),
                cryptoParamsCKKS->GetRescalingTechnique());

        }
        else {
            decrypted->Decode();
        }

        *plaintext = std::move(decrypted);
        return result;
    }

    template <>
    DecryptResult CryptoContextImpl<DCRTPoly>::MultipartyDecryptFusion(
        const std::vector<Ciphertext<DCRTPoly>>& partialCiphertextVec,
        Plaintext* plaintext) const {
        DecryptResult result;

        // Make sure we're processing ciphertexts.
        size_t last_ciphertext = partialCiphertextVec.size();
        if (last_ciphertext < 1) return result;

        for (size_t i = 0; i < last_ciphertext; i++) {
            if (partialCiphertextVec[i] == nullptr ||
                Mismatched(partialCiphertextVec[i]->GetCryptoContext()))
                OPENFHE_THROW(config_error,
                    "A ciphertext passed to MultipartyDecryptFusion was not "
                    "generated with this crypto context");
            if (partialCiphertextVec[i]->GetEncodingType() !=
                partialCiphertextVec[0]->GetEncodingType())
                OPENFHE_THROW(type_error,
                    "Ciphertexts passed to MultipartyDecryptFusion have "
                    "mismatched encoding types");
        }

        // determine which type of plaintext that you need to decrypt into
        Plaintext decrypted = GetPlaintextForDecrypt(
            partialCiphertextVec[0]->GetEncodingType(),
            partialCiphertextVec[0]->GetElements()[0].GetParams(),
            this->GetEncodingParams());

        if ((partialCiphertextVec[0]->GetEncodingType() == CKKSPacked) &&
            (partialCiphertextVec[0]
                ->GetElements()[0]
                .GetParams()
                ->GetParams()
                .size() > 1))
            result = GetScheme()->MultipartyDecryptFusion(
                partialCiphertextVec, &decrypted->GetElement<Poly>());
        else
            result = GetScheme()->MultipartyDecryptFusion(
                partialCiphertextVec, &decrypted->GetElement<NativePoly>());

        if (result.isValid == false) return result;

        decrypted->SetScalingFactorInt(result.scalingFactorInt);

        if (partialCiphertextVec[0]->GetEncodingType() == CKKSPacked) {
            auto decryptedCKKS =
                std::static_pointer_cast<CKKSPackedEncoding>(decrypted);
            decryptedCKKS->SetSlots(partialCiphertextVec[0]->GetSlots());
            const auto cryptoParamsCKKS =
                std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(
                    this->GetCryptoParameters());
            decryptedCKKS->Decode(partialCiphertextVec[0]->GetDepth(),
                partialCiphertextVec[0]->GetScalingFactor(),
                cryptoParamsCKKS->GetRescalingTechnique());
        }
        else {
            decrypted->Decode();
        }

        *plaintext = std::move(decrypted);

        return result;
    }

    //template class CryptoContextImpl<Poly>;
    //template class CryptoContextImpl<NativePoly>;
    template class CryptoContextImpl<DCRTPoly>;

}  // namespace lbcrypto

