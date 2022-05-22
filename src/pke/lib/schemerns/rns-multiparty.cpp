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
#include "schemerns/rns-pke.h"
#include "schemerns/rns-multiparty.h"

namespace lbcrypto {

Ciphertext<DCRTPoly> MultipartyRNS::MultipartyDecryptLead(
    ConstCiphertext<DCRTPoly> ciphertext,
    const PrivateKey<DCRTPoly> privateKey) const {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersRNS>(
          privateKey->GetCryptoParameters());

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  const auto ns = cryptoParams->GetNoiseScale();

  auto s(privateKey->GetPrivateElement());

  size_t sizeQ = s.GetParams()->GetParams().size();
  size_t sizeQl = cv[0].GetParams()->GetParams().size();
  size_t diffQl = sizeQ - sizeQl;

  s.DropLastElements(diffQl);

  DggType dgg(MP_SD);
  DCRTPoly e(dgg, cv[0].GetParams(), Format::EVALUATION);

  // e is added to do noise flooding
  DCRTPoly b = cv[0] + s * cv[1] + ns * e;

  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();

  result->SetElements({std::move(b)});

  result->SetDepth(ciphertext->GetDepth());
  result->SetLevel(ciphertext->GetLevel());
  result->SetScalingFactor(ciphertext->GetScalingFactor());
  result->SetScalingFactorInt(ciphertext->GetScalingFactorInt());
  result->SetSlots(ciphertext->GetSlots());

  return result;
}

Ciphertext<DCRTPoly> MultipartyRNS::MultipartyDecryptMain(
    ConstCiphertext<DCRTPoly> ciphertext,
    const PrivateKey<DCRTPoly> privateKey) const {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersRNS>(
          privateKey->GetCryptoParameters());
  const auto ns = cryptoParams->GetNoiseScale();

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();

  auto s(privateKey->GetPrivateElement());

  size_t sizeQ = s.GetParams()->GetParams().size();
  size_t sizeQl = cv[0].GetParams()->GetParams().size();
  size_t diffQl = sizeQ - sizeQl;

  s.DropLastElements(diffQl);

  DggType dgg(MP_SD);
  DCRTPoly e(dgg, cv[0].GetParams(), Format::EVALUATION);

  // e is added to do noise flooding
  DCRTPoly b = s * cv[1] + ns * e;

  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();

  result->SetElements({std::move(b)});

  result->SetDepth(ciphertext->GetDepth());
  result->SetLevel(ciphertext->GetLevel());
  result->SetScalingFactor(ciphertext->GetScalingFactor());
  result->SetScalingFactorInt(ciphertext->GetScalingFactorInt());
  result->SetSlots(ciphertext->GetSlots());

  return result;
}

EvalKey<DCRTPoly> MultipartyRNS::MultiMultEvalKey(
    PrivateKey<DCRTPoly> privateKey, EvalKey<DCRTPoly> evalKey) const {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersRNS>(
          evalKey->GetCryptoContext()->GetCryptoParameters());
  const auto ns = cryptoParams->GetNoiseScale();

  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  const auto elementParams = cryptoParams->GetElementParams();

  EvalKey<DCRTPoly> evalKeyResult(
      new EvalKeyRelinImpl<DCRTPoly>(evalKey->GetCryptoContext()));

  const std::vector<DCRTPoly> &a0 = evalKey->GetAVector();
  const std::vector<DCRTPoly> &b0 = evalKey->GetBVector();

  std::vector<DCRTPoly> a;
  std::vector<DCRTPoly> b;

  if (cryptoParams->GetKeySwitchTechnique() == BV) {
    const DCRTPoly &s = privateKey->GetPrivateElement();

    for (usint i = 0; i < a0.size(); i++) {
      DCRTPoly e0(dgg, elementParams, Format::EVALUATION);
      DCRTPoly e1(dgg, elementParams, Format::EVALUATION);
      a.push_back(a0[i] * s + ns * e0);
      b.push_back(b0[i] * s + ns * e1);
    }
  } else {
    const std::shared_ptr<ParmType> paramsQ = cryptoParams->GetElementParams();
    const std::shared_ptr<ParmType> paramsQP = cryptoParams->GetParamsQP();

    usint sizeQ = paramsQ->GetParams().size();
    usint sizeQP = paramsQP->GetParams().size();

    DCRTPoly s = privateKey->GetPrivateElement().Clone();

    s.SetFormat(Format::COEFFICIENT);
    DCRTPoly sExt(paramsQP, Format::COEFFICIENT, true);

    for (usint i = 0; i < sizeQ; i++) {
      sExt.SetElementAtIndex(i, s.GetElementAtIndex(i));
    }

    for (usint j = sizeQ; j < sizeQP; j++) {
      NativeInteger pj = paramsQP->GetParams()[j]->GetModulus();
      NativeInteger rooti = paramsQP->GetParams()[j]->GetRootOfUnity();
      auto sNew0 = s.GetElementAtIndex(0);
      sNew0.SwitchModulus(pj, rooti, 0, 0);
      sExt.SetElementAtIndex(j, std::move(sNew0));
    }
    sExt.SetFormat(Format::EVALUATION);

    for (usint i = 0; i < a0.size(); i++) {
      DCRTPoly e0(dgg, paramsQP, Format::EVALUATION);
      DCRTPoly e1(dgg, paramsQP, Format::EVALUATION);

      a.push_back(a0[i] * sExt + ns * e0);
      b.push_back(b0[i] * sExt + ns * e1);
    }
  }

  evalKeyResult->SetAVector(std::move(a));
  evalKeyResult->SetBVector(std::move(b));

  return evalKeyResult;
}

}  // namespace lbcrypto
