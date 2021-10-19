// @file cryptocontext-poly-impl.cpp - cryptocontext poly implementation
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
#include "cryptocontext.cpp"
#include "cryptocontextfactory.cpp"

namespace lbcrypto {

template <>
Plaintext CryptoContextImpl<DCRTPoly>::GetPlaintextForDecrypt(
    PlaintextEncodings pte, shared_ptr<ParmType> evp, EncodingParams ep) {
  if ((pte == CKKSPacked) && (evp->GetParams().size() > 1)) {
    auto vp = std::make_shared<typename Poly::Params>(
        evp->GetCyclotomicOrder(), ep->GetPlaintextModulus(), 1);
    return PlaintextFactory::MakePlaintext(pte, vp, ep);
  } else {
    auto vp = std::make_shared<typename NativePoly::Params>(
        evp->GetCyclotomicOrder(), ep->GetPlaintextModulus(), 1);
    return PlaintextFactory::MakePlaintext(pte, vp, ep);
  }
}

template <>
DecryptResult CryptoContextImpl<DCRTPoly>::Decrypt(
    const LPPrivateKey<DCRTPoly> privateKey,
    ConstCiphertext<DCRTPoly> ciphertext, Plaintext* plaintext) {
    if (ciphertext == nullptr)
        PALISADE_THROW(config_error, "ciphertext passed to Decrypt is empty");
    if (plaintext == nullptr)
        PALISADE_THROW(config_error, "plaintext passed to Decrypt is empty");
    if (privateKey == nullptr || Mismatched(privateKey->GetCryptoContext()))
    PALISADE_THROW(config_error,
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
    result = GetEncryptionAlgorithm()->Decrypt(privateKey, ciphertext,
                                               &decrypted->GetElement<Poly>());
  else
    result = GetEncryptionAlgorithm()->Decrypt(
        privateKey, ciphertext, &decrypted->GetElement<NativePoly>());

  if (result.isValid == false) return result;

  if (ciphertext->GetEncodingType() == CKKSPacked) {
    auto decryptedCKKS =
        std::static_pointer_cast<CKKSPackedEncoding>(decrypted);
    decryptedCKKS->SetDepth(ciphertext->GetDepth());
    decryptedCKKS->SetLevel(ciphertext->GetLevel());
    decryptedCKKS->SetScalingFactor(ciphertext->GetScalingFactor());

    const auto cryptoParamsCKKS =
        std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
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

template <>
DecryptResult CryptoContextImpl<DCRTPoly>::MultipartyDecryptFusion(
    const vector<Ciphertext<DCRTPoly>>& partialCiphertextVec,
    Plaintext* plaintext) const {
  DecryptResult result;

  // Make sure we're processing ciphertexts.
  size_t last_ciphertext = partialCiphertextVec.size();
  if (last_ciphertext < 1) return result;

  for (size_t i = 0; i < last_ciphertext; i++) {
    if (partialCiphertextVec[i] == nullptr ||
        Mismatched(partialCiphertextVec[i]->GetCryptoContext()))
      PALISADE_THROW(config_error,
                     "A ciphertext passed to MultipartyDecryptFusion was not "
                     "generated with this crypto context");
    if (partialCiphertextVec[i]->GetEncodingType() !=
        partialCiphertextVec[0]->GetEncodingType())
      PALISADE_THROW(type_error,
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
    result = GetEncryptionAlgorithm()->MultipartyDecryptFusion(
        partialCiphertextVec, &decrypted->GetElement<Poly>());
  else
    result = GetEncryptionAlgorithm()->MultipartyDecryptFusion(
        partialCiphertextVec, &decrypted->GetElement<NativePoly>());

  if (result.isValid == false) return result;

  if (partialCiphertextVec[0]->GetEncodingType() == CKKSPacked) {
    auto decryptedCKKS =
        std::static_pointer_cast<CKKSPackedEncoding>(decrypted);
    const auto cryptoParamsCKKS =
        std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
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

template class CryptoContextFactory<Poly>;
template class CryptoContextImpl<Poly>;
template class CryptoObject<Poly>;

template class CryptoContextFactory<NativePoly>;
template class CryptoContextImpl<NativePoly>;
template class CryptoObject<NativePoly>;

template class CryptoContextFactory<DCRTPoly>;
template class CryptoContextImpl<DCRTPoly>;
template class CryptoObject<DCRTPoly>;

}  // namespace lbcrypto

