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
CKKS implementation. See https://eprint.iacr.org/2020/1118 for details.
 */

#define PROFILE

#include "scheme/ckksrns/ckksrns-multiparty.h"

#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "ciphertext.h"
#include "cryptocontext.h"

namespace lbcrypto {

DecryptResult MultipartyCKKSRNS::MultipartyDecryptFusion(const std::vector<Ciphertext<DCRTPoly>>& ciphertextVec,
                                                         Poly* plaintext) const {
    const auto cryptoParams =
        std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertextVec[0]->GetCryptoParameters());
    const std::vector<DCRTPoly>& cv0 = ciphertextVec[0]->GetElements();

    DCRTPoly b = cv0[0];
    for (size_t i = 1; i < ciphertextVec.size(); i++) {
        const std::vector<DCRTPoly>& cvi = ciphertextVec[i]->GetElements();
        b += cvi[0];
    }
    b.SetFormat(Format::COEFFICIENT);

    *plaintext = b.CRTInterpolate();

    //  size_t sizeQl = b.GetParams()->GetParams().size();
    //  if (sizeQl > 1) {
    //    *plaintext = b.CRTInterpolate();
    //  } else if (sizeQl == 1) {
    //    *plaintext = Poly(b.GetElementAtIndex(0), Format::COEFFICIENT);
    //  } else {
    //    OPENFHE_THROW(
    //        math_error,
    //        "Decryption failure: No towers left; consider increasing the depth.");
    //  }

    return DecryptResult(plaintext->GetLength());
}

DecryptResult MultipartyCKKSRNS::MultipartyDecryptFusion(const std::vector<Ciphertext<DCRTPoly>>& ciphertextVec,
                                                         NativePoly* plaintext) const {
    const auto cryptoParams =
        std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertextVec[0]->GetCryptoParameters());

    const std::vector<DCRTPoly>& cv0 = ciphertextVec[0]->GetElements();

    DCRTPoly b = cv0[0];
    for (size_t i = 1; i < ciphertextVec.size(); i++) {
        const std::vector<DCRTPoly>& cvi = ciphertextVec[i]->GetElements();
        b += cvi[0];
    }
    b.SetFormat(Format::COEFFICIENT);

    //  const size_t sizeQl = b.GetParams()->GetParams().size();
    //  if (sizeQl == 1)
    //    *plaintext = b.GetElementAtIndex(0);
    //  else
    //    OPENFHE_THROW(
    //        math_error,
    //        "Decryption failure: No towers left; consider increasing the depth.");

    *plaintext = b.GetElementAtIndex(0);

    return DecryptResult(plaintext->GetLength());
}

Ciphertext<DCRTPoly> MultipartyCKKSRNS::IntMPBootAdjustScale( ConstCiphertext<DCRTPoly> ciphertext) const {

  if (ciphertext->GetElements().size() == 0) {
     std::string msg =
 	  "IntMPBootAdjustScale: no polynomials in the input ciphertext.";
     OPENFHE_THROW(openfhe_error, msg);
  }

  const auto cryptoParams = std::dynamic_pointer_cast<MultipartyCKKSRNS>(ciphertext->GetCryptoParameters());

	auto cc = ciphertext->GetCryptoContext();

	// TODO:: fix this
//	auto compressionLevel = std::dynamic_pointer_cast<DltCryptoContextImpl
//			<DCRTPoly>>(cc)->GetMMpIntBootCiphertextCompressionLevel();

	size_t compressionLevel = 3;

	// Compress ctxt and reduce it to numPrimesToKeep towers
	// 1 is for the message itself (assuming 1 tower (60-bit) for msg)
	size_t scalingFactorBits = cc->GetEncodingParams()->GetPlaintextModulus();
	size_t firstModulusSize = std::ceil(std::log2(ciphertext->GetElements()[0].
				GetAllElements()[0].GetParams()->GetModulus().ConvertToInt()));
	size_t numTowersToKeep = ( scalingFactorBits / firstModulusSize + 1) + compressionLevel;

#if 0
  if (cryptoParams->GetRescalingTechnique() == EXACTRESCALE) {

      if (ciphertext->GetElements()[0].GetNumOfElements()<3) {
	string msg =
	  "IntMPBootAdjustScale: not enough towers in the input polynomial.";
	PALISADE_THROW(config_error, msg);
      }

      auto ciphertextAdjusted = Compress(ciphertext, numTowersToKeep+1);

      double targetSF = cryptoParams->GetScalingFactorOfLevel(0);
      double sourceSF = ciphertextAdjusted->GetScalingFactor();
      uint32_t numTowers = ciphertextAdjusted->GetElements()[0].GetNumOfElements();
      double modToDrop = cryptoParams->GetElementParams()->GetParams()[numTowers-1]->GetModulus().ConvertToDouble();
      double adjustmentFactor = (targetSF/sourceSF)*(modToDrop/sourceSF);

      // in the case of EXACTRESCALE, we need to bring the ciphertext to the right scale using a
      // a scaling multiplication. Note the at currently EXACTRESCALE is only supported for NATIVEINT = 64.

      ciphertextAdjusted = EvalMult(ciphertextAdjusted, adjustmentFactor);

      ciphertextAdjusted = ModReduceInternal(ciphertextAdjusted);
      ciphertextAdjusted->SetScalingFactor(targetSF);
      return ciphertextAdjusted;

  } else {

      if (ciphertext->GetElements()[0].GetNumOfElements()<numTowersToKeep) {
	string msg =
	  "IntMPBootAdjustScale: not enough towers in the input polynomial.";
	PALISADE_THROW(palisade_error, msg);
      }

      return Compress(ciphertext,numTowersToKeep);
#endif

  if (ciphertext->GetElements()[0].GetNumOfElements()<numTowersToKeep) {
		std::string msg = "IntMPBootAdjustScale: not enough towers in the input polynomial.";
		OPENFHE_THROW(openfhe_error, msg);
	}

  return cc->Compress(ciphertext, numTowersToKeep);
}

}  // namespace lbcrypto
