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
  pt.SetFormat(COEFFICIENT);
  const NativeInteger &NegQModt = cryptoParams->GetNegQModt();
  const NativeInteger &NegQModtPrecon = cryptoParams->GetNegQModtPrecon();
  const std::vector<NativeInteger> &tInvModq = cryptoParams->GettInvModq();
  const NativeInteger t = cryptoParams->GetPlaintextModulus();
  pt.TimesQovert(cryptoParams->GetElementParams(), tInvModq, t, NegQModt, NegQModtPrecon);
  pt.SetFormat(EVALUATION);
  cv[0] += pt;
}

void LeveledSHEBFVRNS::EvalSubInPlace(
    Ciphertext<DCRTPoly> &ciphertext, ConstPlaintext plaintext) const {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersBFVRNS>(
          ciphertext->GetCryptoParameters());
  std::vector<DCRTPoly> &cv = ciphertext->GetElements();

  DCRTPoly pt = plaintext->GetElement<DCRTPoly>();
  pt.SetFormat(COEFFICIENT);
  const NativeInteger &NegQModt = cryptoParams->GetNegQModt();
  const NativeInteger &NegQModtPrecon = cryptoParams->GetNegQModtPrecon();
  const std::vector<NativeInteger> &tInvModq = cryptoParams->GettInvModq();
  const NativeInteger t = cryptoParams->GetPlaintextModulus();
  pt.TimesQovert(cryptoParams->GetElementParams(), tInvModq, t, NegQModt, NegQModtPrecon);
  pt.SetFormat(EVALUATION);
  cv[0] -= pt;
}

uint32_t FindLevelsToDrop(usint evalMultCount,
                          std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams,
                          uint32_t dcrtBits, bool keySwitch = false) {
  const auto cryptoParamsBFVrns =
      std::static_pointer_cast<CryptoParametersBFVRNS>(cryptoParams);
  double sigma = cryptoParamsBFVrns->GetDistributionParameter();
  double alpha = cryptoParamsBFVrns->GetAssuranceMeasure();
  double p = static_cast<double>(cryptoParamsBFVrns->GetPlaintextModulus());
  uint32_t n = cryptoParamsBFVrns->GetElementParams()->GetRingDimension();
  uint32_t relinWindow = cryptoParamsBFVrns->GetDigitSize();
  KeySwitchTechnique rsTechnique = cryptoParamsBFVrns->GetKeySwitchTechnique();

  uint32_t k = cryptoParamsBFVrns->GetNumPerPartQ();
  uint32_t numPartQ = cryptoParamsBFVrns->GetNumPartQ();
  const double Bkey = 1.0;

  double w = relinWindow == 0 ? pow(2, dcrtBits) : pow(2, relinWindow);

  // Bound of the Gaussian error polynomial
  double Berr = sigma * sqrt(alpha);

  // expansion factor delta
  auto delta = [](uint32_t n) -> double { return (2. * sqrt(n)); };

  // norm of fresh ciphertext polynomial
  auto Vnorm = [&](uint32_t n) -> double {
    return Berr * (1. + 2. * delta(n) * Bkey);
  };

  auto noiseKS = [&](uint32_t n, double logqPrev, double w) -> double {
	if (rsTechnique == HYBRID)
      return  k * ( numPartQ * delta(n) * Berr + delta(n) * Bkey + 1.0 )/2;
	else
	  return delta(n) *
              (floor(logqPrev / (log(2) * dcrtBits)) + 1) * w * Berr;
  };

  // function used in the EvalMult constraint
  auto C1 = [&](uint32_t n) -> double {
    return delta(n) * delta(n) * p * Bkey;
  };

  // function used in the EvalMult constraint
  auto C2 = [&](uint32_t n, double logqPrev) -> double {
    return delta(n) * delta(n) * Bkey * Bkey / 2.0 +
  		  noiseKS(n, logqPrev, w);
  };

  // main correctness constraint
  auto logqBFV = [&](uint32_t n, double logqPrev) -> double {
    if (evalMultCount > 0) {
      return log(4 * p) + (evalMultCount - 1) * log(C1(n)) +
      log(C1(n) * Vnorm(n) + evalMultCount * C2(n, logqPrev));
    }
    return log(p * (4 * (Vnorm(n))));
  };

  // initial values
  double logqPrev = 6. * log(10);
  double logq = logqBFV(n, logqPrev);

  while (fabs(logq - logqPrev) > log(1.001)) {
    logqPrev = logq;
    logq = logqBFV(n, logqPrev);
  }

  // get an estimate of the error q / (4t)
  double loge = logq / log(2) - 2 - log2(p);

  double logExtra = keySwitch ? log2(noiseKS(n, logq, w)) : log2(delta(n));

  // error should be at least 2^10 * delta(n) larger than the levels we are dropping
  int32_t levels = std::floor((loge - 30 - logExtra) / dcrtBits);
  size_t sizeQ = cryptoParamsBFVrns->GetElementParams()->GetParams().size();

  if (levels < 0)
    levels = 0;
  else if (levels > static_cast<int32_t>(sizeQ) - 1)
    levels = sizeQ - 1;
  
  return levels;

};

Ciphertext<DCRTPoly> LeveledSHEBFVRNS::EvalMult(
    ConstCiphertext<DCRTPoly> ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2) const {
  if (!(ciphertext1->GetCryptoParameters() ==
        ciphertext2->GetCryptoParameters())) {
    std::string errMsg =
        "AlgorithmSHEBFVrns::EvalMult crypto parameters are not the same";
    OPENFHE_THROW(config_error, errMsg);
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
  size_t sizeQ = cv1[0].GetNumOfElements();
  size_t l = 0;

  std::vector<DCRTPoly> cvMult(cvMultSize);

  if (cryptoParams->GetMultiplicationTechnique() == HPS) {
    for (size_t i = 0; i < cv1Size; i++) {
      cv1[i].ExpandCRTBasis(
          cryptoParams->GetParamsQlRl(),
          cryptoParams->GetParamsRl(),
          cryptoParams->GetQlHatInvModq(),
          cryptoParams->GetQlHatInvModqPrecon(),
          cryptoParams->GetQlHatModr(),
          cryptoParams->GetalphaQlModr(),
          cryptoParams->GetModrBarrettMu(),
          cryptoParams->GetqInv(),
          Format::EVALUATION);
    }

    for (size_t i = 0; i < cv2Size; i++) {
      cv2[i].ExpandCRTBasis(
          cryptoParams->GetParamsQlRl(),
          cryptoParams->GetParamsRl(),
          cryptoParams->GetQlHatInvModq(),
          cryptoParams->GetQlHatInvModqPrecon(),
          cryptoParams->GetQlHatModr(),
          cryptoParams->GetalphaQlModr(),
          cryptoParams->GetModrBarrettMu(),
          cryptoParams->GetqInv(),
          Format::EVALUATION);
    }
  } else if (cryptoParams->GetMultiplicationTechnique() == HPSPOVERQ) {
    for (size_t i = 0; i < cv1Size; i++) {
      // Expand ciphertext1 from basis Q to PQ.
      cv1[i].ExpandCRTBasis(
          cryptoParams->GetParamsQlRl(sizeQ - 1),
          cryptoParams->GetParamsRl(sizeQ - 1),
          cryptoParams->GetQlHatInvModq(sizeQ - 1),
          cryptoParams->GetQlHatInvModqPrecon(sizeQ - 1),
          cryptoParams->GetQlHatModr(sizeQ - 1),
          cryptoParams->GetalphaQlModr(sizeQ - 1),
          cryptoParams->GetModrBarrettMu(),
          cryptoParams->GetqInv(),
          Format::EVALUATION);
    }

    size_t sizeQ = cv2[0].GetNumOfElements();
    
    DCRTPoly::CRTBasisExtensionPrecomputations basisPQ(
        cryptoParams->GetParamsQlRl(sizeQ - 1),
        cryptoParams->GetParamsRl(sizeQ - 1),
        cryptoParams->GetParamsQl(sizeQ - 1),
        cryptoParams->GetmNegRlQHatInvModq(sizeQ - 1),
        cryptoParams->GetmNegRlQHatInvModqPrecon(sizeQ - 1),
        cryptoParams->GetqInvModr(),
        cryptoParams->GetModrBarrettMu(),
        cryptoParams->GetRlHatInvModr(sizeQ - 1),
        cryptoParams->GetRlHatInvModrPrecon(sizeQ - 1),
        cryptoParams->GetRlHatModq(sizeQ - 1),
        cryptoParams->GetalphaRlModq(sizeQ - 1),
        cryptoParams->GetModqBarrettMu(),
        cryptoParams->GetrInv()
    );

    for (size_t i = 0; i < cv2Size; i++) {
      cv2[i].SetFormat(Format::COEFFICIENT);
      // Switch ciphertext2 from basis Q to P to PQ.
      cv2[i].FastExpandCRTBasisPloverQ(basisPQ);
      cv2[i].SetFormat(Format::EVALUATION);
    }
  } else if (cryptoParams->GetMultiplicationTechnique() == HPSPOVERQLEVELED) {
    size_t c1depth = ciphertext1->GetDepth();
    size_t c2depth = ciphertext2->GetDepth();

    size_t levels = std::max(c1depth, c2depth) - 1;
    double dcrtBits = cv1[0].GetElementAtIndex(0).GetModulus().GetMSB();

    //how many levels to drop
    uint32_t levelsDropped = FindLevelsToDrop(levels, cryptoParams, dcrtBits, false);
    l = levelsDropped > 0 ? sizeQ - 1 - levelsDropped: sizeQ - 1;

    for (size_t i = 0; i < cv1Size; i++) {
      cv1[i].SetFormat(Format::COEFFICIENT);
      if(l < sizeQ - 1) {
        // Drop from basis Q to Q_l.
        cv1[i] = cv1[i].ScaleAndRound(
            cryptoParams->GetParamsQl(l),
            cryptoParams->GetQlQHatInvModqDivqModq(l),
            cryptoParams->GetQlQHatInvModqDivqFrac(l),
            cryptoParams->GetModqBarrettMu());
      }
      // Expand ciphertext1 from basis Q_l to PQ_l.
      cv1[i].ExpandCRTBasis(
          cryptoParams->GetParamsQlRl(l),
          cryptoParams->GetParamsRl(l),
          cryptoParams->GetQlHatInvModq(l),
          cryptoParams->GetQlHatInvModqPrecon(l),
          cryptoParams->GetQlHatModr(l),
          cryptoParams->GetalphaQlModr(l),
          cryptoParams->GetModrBarrettMu(),
          cryptoParams->GetqInv(),
          Format::EVALUATION);
    }

    DCRTPoly::CRTBasisExtensionPrecomputations basisPQ(
        cryptoParams->GetParamsQlRl(l),
        cryptoParams->GetParamsRl(l),
        cryptoParams->GetParamsQl(l),
        cryptoParams->GetmNegRlQHatInvModq(l),
        cryptoParams->GetmNegRlQHatInvModqPrecon(l),
        cryptoParams->GetqInvModr(),
        cryptoParams->GetModrBarrettMu(),
        cryptoParams->GetRlHatInvModr(l),
        cryptoParams->GetRlHatInvModrPrecon(l),
        cryptoParams->GetRlHatModq(l),
        cryptoParams->GetalphaRlModq(l),
        cryptoParams->GetModqBarrettMu(),
        cryptoParams->GetrInv()
    );
    for (size_t i = 0; i < cv2Size; i++) {
      cv2[i].SetFormat(Format::COEFFICIENT);
      // Switch ciphertext2 from basis Q to P to PQ.
      cv2[i].FastExpandCRTBasisPloverQ(basisPQ);
      cv2[i].SetFormat(Format::EVALUATION);
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
          cryptoParams->GetParamsRl(),
          cryptoParams->GettRSHatInvModsDivsModr(),
          cryptoParams->GettRSHatInvModsDivsFrac(),
          cryptoParams->GetModrBarrettMu());

      // Converts from the CRT basis P to Q
      cvMult[i] = cvMult[i].SwitchCRTBasis(
          cryptoParams->GetElementParams(),
          cryptoParams->GetRlHatInvModr(),
          cryptoParams->GetRlHatInvModrPrecon(),
          cryptoParams->GetRlHatModq(),
          cryptoParams->GetalphaRlModq(),
          cryptoParams->GetModqBarrettMu(),
          cryptoParams->GetrInv());
    }
  } else if (cryptoParams->GetMultiplicationTechnique() == HPSPOVERQ) {
    for (size_t i = 0; i < cvMultSize; i++) {
      cvMult[i].SetFormat(COEFFICIENT);
      // Performs the scaling by t/P followed by rounding; the result is in the
      // CRT basis Q
      cvMult[i] = cvMult[i].ScaleAndRound(
          cryptoParams->GetElementParams(), cryptoParams->GettQlSlHatInvModsDivsModq(0),
          cryptoParams->GettQlSlHatInvModsDivsFrac(0),
          cryptoParams->GetModqBarrettMu());
    }
  } else if (cryptoParams->GetMultiplicationTechnique() == HPSPOVERQLEVELED) {
    for (size_t i = 0; i < cvMultSize; i++) {
      cvMult[i].SetFormat(COEFFICIENT);
      // Performs the scaling by t/P followed by rounding; the result is in the
      // CRT basis Q
      cvMult[i] = cvMult[i].ScaleAndRound(
          cryptoParams->GetParamsQl(l), cryptoParams->GettQlSlHatInvModsDivsModq(l),
          cryptoParams->GettQlSlHatInvModsDivsFrac(l),
          cryptoParams->GetModqBarrettMu());

      if(l < sizeQ - 1) {
        // Expand back to basis Q.
        cvMult[i].ExpandCRTBasisQlHat(cryptoParams->GetElementParams(),
            cryptoParams->GetQlHatModq(l),
            cryptoParams->GetQlHatModqPrecon(l), sizeQ);
      }
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
          cryptoParams->GetElementParams(),
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
  ciphertextMult->SetDepth(std::max(ciphertext1->GetDepth(), ciphertext2->GetDepth()) + 1);

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
}

}
