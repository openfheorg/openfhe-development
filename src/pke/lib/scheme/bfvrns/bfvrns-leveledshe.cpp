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
 - Andrey Kim, Antonis Papadimitriou, and Yuriy Polyakov. Approximate
homomorphic encryption with reduced approximation error. Cryptology ePrint
Archive, Report 2020/1118, 2020. https://eprint.iacr.org/2020/
1118.
 */

#define PROFILE

#include "cryptocontext.h"
#include "scheme/bfvrns/bfvrns-leveledshe.h"

namespace lbcrypto {

void LeveledSHEBFVRNS::EvalAddInPlace(
    Ciphertext<DCRTPoly> &ciphertext, ConstPlaintext plaintext) const {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersBFVRNS>(
          ciphertext->GetCryptoParameters());
  std::vector<DCRTPoly> &cv = ciphertext->GetElements();

  DCRTPoly pt = plaintext->GetElement<DCRTPoly>();
  pt.SetFormat(EVALUATION);
  cv[0] += pt.Times(cryptoParams->GetQDivtModq());
}

void LeveledSHEBFVRNS::EvalSubInPlace(
    Ciphertext<DCRTPoly> &ciphertext, ConstPlaintext plaintext) const {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersBFVRNS>(
          ciphertext->GetCryptoParameters());
  std::vector<DCRTPoly> &cv = ciphertext->GetElements();

  DCRTPoly pt = plaintext->GetElement<DCRTPoly>();
  pt.SetFormat(EVALUATION);
  cv[0] -= pt.Times(cryptoParams->GetQDivtModq());
}

Ciphertext<DCRTPoly> LeveledSHEBFVRNS::EvalMult(
    ConstCiphertext<DCRTPoly> ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2) const {
  if (!(ciphertext1->GetCryptoParameters() ==
        ciphertext2->GetCryptoParameters())) {
    std::string errMsg =
        "AlgorithmSHEBFVrns::EvalMult crypto parameters are not the same";
    OpenFHE_THROW(config_error, errMsg);
  }

  Ciphertext<DCRTPoly> ciphertextMult = ciphertext1->CloneEmpty();

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersBFVRNS>(
          ciphertext1->GetCryptoContext()->GetCryptoParameters());

  std::vector<DCRTPoly> cv1 = ciphertext1->GetElements();
  std::vector<DCRTPoly> cv2 = ciphertext2->GetElements();

  size_t cv1Size = cv1.size();
  size_t cv2Size = cv2.size();
  size_t cvMultSize = cv1Size + cv2Size - 1;

  std::vector<DCRTPoly> cvMult(cvMultSize);

  if (cryptoParams->GetMultiplicationTechnique() == HPS) {
    for (size_t i = 0; i < cv1Size; i++) {
      cv1[i].ExpandCRTBasis(
          cryptoParams->GetParamsQlRl(0),
          cryptoParams->GetParamsRl(0),
          cryptoParams->GetQlHatInvModq(0),
          cryptoParams->GetQlHatInvModqPrecon(0),
          cryptoParams->GetQlHatModr(0),
          cryptoParams->GetalphaQlModr(0),
          cryptoParams->GetModrBarrettMu(),
          cryptoParams->GetqInv());
    }

    for (size_t i = 0; i < cv2Size; i++) {
      cv2[i].ExpandCRTBasis(
          cryptoParams->GetParamsQlRl(0),
          cryptoParams->GetParamsRl(0),
          cryptoParams->GetQlHatInvModq(0),
          cryptoParams->GetQlHatInvModqPrecon(0),
          cryptoParams->GetQlHatModr(0),
          cryptoParams->GetalphaQlModr(0),
          cryptoParams->GetModrBarrettMu(),
          cryptoParams->GetqInv());
    }
  } else {
    for (size_t i = 0; i < cv1Size; i++) {
      cv1[i].FastBaseConvqToBskMontgomery(
          cryptoParams->GetParamsBsk(),
          cryptoParams->GetModuliQ(),
          cryptoParams->GetModuliBsk(),
          cryptoParams->GetModbskBarrettMu(),
          cryptoParams->GetmtildeQHatInvModq(),
          cryptoParams->GetmtildeQHatInvModqPrecon(),
          cryptoParams->GetQHatModbsk(),
          cryptoParams->GetQHatModmtilde(),
          cryptoParams->GetQModbsk(),
          cryptoParams->GetQModbskPrecon(),
          cryptoParams->GetNegQInvModmtilde(),
          cryptoParams->GetmtildeInvModbsk(),
          cryptoParams->GetmtildeInvModbskPrecon());

      cv1[i].SetFormat(Format::EVALUATION);
    }

    for (size_t i = 0; i < cv2Size; i++) {
      cv2[i].FastBaseConvqToBskMontgomery(
          cryptoParams->GetParamsBsk(),
          cryptoParams->GetModuliQ(),
          cryptoParams->GetModuliBsk(),
          cryptoParams->GetModbskBarrettMu(),
          cryptoParams->GetmtildeQHatInvModq(),
          cryptoParams->GetmtildeQHatInvModqPrecon(),
          cryptoParams->GetQHatModbsk(),
          cryptoParams->GetQHatModmtilde(),
          cryptoParams->GetQModbsk(),
          cryptoParams->GetQModbskPrecon(),
          cryptoParams->GetNegQInvModmtilde(),
          cryptoParams->GetmtildeInvModbsk(),
          cryptoParams->GetmtildeInvModbskPrecon());

      cv2[i].SetFormat(Format::EVALUATION);
    }
  }

#ifdef USE_KARATSUBA

  if (cv1Size == 2 && cv2Size == 2) {
    // size of each ciphertxt = 2, use Karatsuba
    cvMult[0] = cv1[0] * cv2[0];  // a
    cvMult[2] = cv1[1] * cv2[1];  // b

    cvMult[1] = cv1[0] + cv1[1];
    cvMult[1] *= (cv2[0] + cv2[1]);
    cvMult[1] -= cvMult[2];
    cvMult[1] -= cvMult[0];

  } else {  // if size of any of the ciphertexts > 2
    bool *isFirstAdd = new bool[cvMultSize];
    std::fill_n(isFirstAdd, cvMultSize, true);

    for (size_t i = 0; i < cv1Size; i++) {
      for (size_t j = 0; j < cv2Size; j++) {
        if (isFirstAdd[i + j] == true) {
          cvMult[i + j] = cv1[i] * cv2[j];
          isFirstAdd[i + j] = false;
        } else {
          cvMult[i + j] += cv1[i] * cv2[j];
        }
      }
    }

    delete[] isFirstAdd;
  }
#else
  bool *isFirstAdd = new bool[cvMultSize];
  std::fill_n(isFirstAdd, cvMultSize, true);

  for (size_t i = 0; i < cv1Size; i++) {
    for (size_t j = 0; j < cv2Size; j++) {
      if (isFirstAdd[i + j] == true) {
        cvMult[i + j] = cv1[i] * cv2[j];
        isFirstAdd[i + j] = false;
      } else {
        cvMult[i + j] += cv1[i] * cv2[j];
      }
    }
  }

  delete[] isFirstAdd;
#endif

  if (cryptoParams->GetMultiplicationTechnique() == HPS) {
    for (size_t i = 0; i < cvMultSize; i++) {
      // converts to coefficient representation before rounding
      cvMult[i].SetFormat(Format::COEFFICIENT);
      // Performs the scaling by t/Q followed by rounding; the result is in the
      // CRT basis P
      cvMult[i] = cvMult[i].ScaleAndRound(
          cryptoParams->GetParamsRl(0),
          cryptoParams->GettRSHatInvModsDivsModr(),
          cryptoParams->GettRSHatInvModsDivsFrac(),
          cryptoParams->GetModrBarrettMu());

      // Converts from the CRT basis P to Q
      cvMult[i] = cvMult[i].SwitchCRTBasis(
          cryptoParams->GetElementParams(),
          cryptoParams->GetRlHatInvModr(0),
          cryptoParams->GetRlHatInvModrPrecon(0),
          cryptoParams->GetRlHatModq(0),
          cryptoParams->GetalphaRlModq(0),
          cryptoParams->GetModqBarrettMu(),
          cryptoParams->GetrInv());
    }
  } else {
    const NativeInteger &t = cryptoParams->GetPlaintextModulus();
    for (size_t i = 0; i < cvMultSize; i++) {
      // converts to Format::COEFFICIENT representation before rounding
      cvMult[i].SetFormat(Format::COEFFICIENT);
      // Performs the scaling by t/Q followed by rounding; the result is in the
      // CRT basis {Bsk}
      cvMult[i].FastRNSFloorq(t,
          cryptoParams->GetModuliQ(),
          cryptoParams->GetModuliBsk(),
          cryptoParams->GetModbskBarrettMu(),
          cryptoParams->GettQHatInvModq(),
          cryptoParams->GettQHatInvModqPrecon(),
          cryptoParams->GetQHatModbsk(),
          cryptoParams->GetqInvModbsk(),
          cryptoParams->GettQInvModbsk(),
          cryptoParams->GettQInvModbskPrecon());

      // Converts from the CRT basis {Bsk} to {Q}
      cvMult[i].FastBaseConvSK(
          cryptoParams->GetModuliQ(),
          cryptoParams->GetModqBarrettMu(),
          cryptoParams->GetModuliBsk(),
          cryptoParams->GetModbskBarrettMu(),
          cryptoParams->GetBHatInvModb(),
          cryptoParams->GetBHatInvModbPrecon(),
          cryptoParams->GetBHatModmsk(),
          cryptoParams->GetBInvModmsk(),
          cryptoParams->GetBInvModmskPrecon(),
          cryptoParams->GetBHatModq(),
          cryptoParams->GetBModq(),
          cryptoParams->GetBModqPrecon());
    }
  }

  ciphertextMult->SetElements(std::move(cvMult));
  ciphertextMult->SetDepth((ciphertext1->GetDepth() + ciphertext2->GetDepth()));

  return ciphertextMult;
}

void LeveledSHEBFVRNS::EvalMultCoreInPlace(Ciphertext<DCRTPoly> &ciphertext, const NativeInteger& constant) const {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersBFVRNS>(
          ciphertext->GetCryptoParameters());

  std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  for (usint i = 0; i < cv.size(); ++i) {
    cv[i] *= constant;
  }
  const NativeInteger t(cryptoParams->GetPlaintextModulus());

  ciphertext->SetDepth(ciphertext->GetDepth() + 1);
  ciphertext->SetScalingFactorInt(ciphertext->GetScalingFactorInt().ModMul(constant, t));
}

}
