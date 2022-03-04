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
  CKKS scheme implementation
 */

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
#include "keyswitch/keyswitch-bv.h"

namespace lbcrypto {

EvalKey<DCRTPoly> KeySwitchBV::KeySwitchGen(
    const PrivateKey<DCRTPoly> oldKey,
    const PrivateKey<DCRTPoly> newKey) const {
  EvalKeyRelin<DCRTPoly> ek(
      std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(newKey->GetCryptoContext()));

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersRNS>(
          newKey->GetCryptoParameters());

  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();
  const DCRTPoly &sNew = newKey->GetPrivateElement();
  const DCRTPoly &sOld = oldKey->GetPrivateElement();

  const auto ns = cryptoParams->GetNoiseScale();
  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  DugType dug;

  usint relinWindow = cryptoParams->GetRelinWindow();

  std::vector<DCRTPoly> av;
  std::vector<DCRTPoly> bv;

  if (relinWindow > 0) {
    for (usint i = 0; i < sOld.GetNumOfElements(); i++) {
      vector<DCRTPoly::PolyType> sOldDecomposed =
          sOld.GetElementAtIndex(i).PowersOfBase(relinWindow);

      for (usint k = 0; k < sOldDecomposed.size(); k++) {
        DCRTPoly filtered(elementParams, Format::EVALUATION, true);
        filtered.SetElementAtIndex(i, sOldDecomposed[k]);

        DCRTPoly a(dug, elementParams, Format::EVALUATION);
        DCRTPoly e(dgg, elementParams, Format::EVALUATION);

        av.push_back(a);
        bv.push_back(filtered - a * sNew + ns * e);
      }
    }
  } else {
    for (usint i = 0; i < sOld.GetNumOfElements(); i++) {
      DCRTPoly filtered(elementParams, Format::EVALUATION, true);
      filtered.SetElementAtIndex(i, sOld.GetElementAtIndex(i));

      DCRTPoly a(dug, elementParams, Format::EVALUATION);
      DCRTPoly e(dgg, elementParams, Format::EVALUATION);

      av.push_back(a);
      bv.push_back(filtered - a * sNew + ns * e);
    }
  }

  ek->SetAVector(std::move(av));
  ek->SetBVector(std::move(bv));

  return ek;
}

EvalKey<DCRTPoly> KeySwitchBV::KeySwitchGen(const PrivateKey<DCRTPoly> oldKey,
                                            const PrivateKey<DCRTPoly> newKey,
                                            const EvalKey<DCRTPoly> ek) const {
  EvalKey<DCRTPoly> evalKey(
      std::make_shared<EvalKeyImpl<DCRTPoly>>(newKey->GetCryptoContext()));

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersRLWE<DCRTPoly>>(
          oldKey->GetCryptoParameters());

  const shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();
  const DCRTPoly &sOld = oldKey->GetPrivateElement();
  const DCRTPoly &sNew = newKey->GetPrivateElement();

  const auto ns = cryptoParams->GetNoiseScale();
  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

  usint relinWindow = cryptoParams->GetRelinWindow();

  const std::vector<DCRTPoly> &a = ek->GetAVector();

  std::vector<DCRTPoly> av;
  std::vector<DCRTPoly> bv;

  if (relinWindow > 0) {
    for (usint i = 0; i < sOld.GetNumOfElements(); i++) {
      vector<DCRTPoly::PolyType> sOldDecomposed =
          sOld.GetElementAtIndex(i).PowersOfBase(relinWindow);

      for (usint k = 0; k < sOldDecomposed.size(); k++) {
        DCRTPoly filtered(elementParams, Format::EVALUATION, true);
        filtered.SetElementAtIndex(i, sOldDecomposed[k]);

        DCRTPoly e(dgg, elementParams, Format::EVALUATION);

        av.push_back(a[i * sOldDecomposed.size() + k]);
        bv.push_back(filtered - a[i * sOldDecomposed.size() + k] * sNew + ns * e);
      }
    }
  } else {
    for (usint i = 0; i < sOld.GetNumOfElements(); i++) {
      DCRTPoly filtered(elementParams, Format::EVALUATION, true);
      filtered.SetElementAtIndex(i, sOld.GetElementAtIndex(i));

      DCRTPoly e(dgg, elementParams, Format::EVALUATION);

      av.push_back(a[i]);
      bv.push_back(filtered - a[i] * sNew + ns * e);
    }
  }

  evalKey->SetAVector(std::move(av));
  evalKey->SetBVector(std::move(bv));

  return evalKey;
}

EvalKey<DCRTPoly> KeySwitchBV::KeySwitchGen(
    const PrivateKey<DCRTPoly> oldSk,
    const PublicKey<DCRTPoly> newPk) const {
  // Get crypto context of new public key.
  auto cc = newPk->GetCryptoContext();

  EvalKeyRelin<DCRTPoly> ek =
      std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(cc);

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersRNS>(
          newPk->GetCryptoParameters());

  const shared_ptr<DCRTPoly::Params> elementParams =
      cryptoParams->GetElementParams();

  const auto ns = cryptoParams->GetNoiseScale();
  const DCRTPoly::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  DCRTPoly::DugType dug;
  DCRTPoly::TugType tug;

  const DCRTPoly &sOld = oldSk->GetPrivateElement();

  std::vector<DCRTPoly> av;
  std::vector<DCRTPoly> bv;

  uint32_t relinWindow = cryptoParams->GetRelinWindow();

  const DCRTPoly &newp0 = newPk->GetPublicElements().at(0);
  const DCRTPoly &newp1 = newPk->GetPublicElements().at(1);

  if (relinWindow > 0) {
    for (usint i = 0; i < sOld.GetNumOfElements(); i++) {
      vector<DCRTPoly::PolyType> sOldDecomposed =
          sOld.GetElementAtIndex(i).PowersOfBase(relinWindow);

      for (size_t k = 0; k < sOldDecomposed.size(); k++) {
        // Creates an element with all zeroes
        DCRTPoly filtered(elementParams, Format::EVALUATION, true);
        filtered.SetElementAtIndex(i, sOldDecomposed[k]);

        DCRTPoly u = (cryptoParams->GetMode() == RLWE) ?
            DCRTPoly(dgg, elementParams, Format::EVALUATION) :
            DCRTPoly(tug, elementParams, Format::EVALUATION);

        DCRTPoly e0(dgg, elementParams, Format::EVALUATION);
        DCRTPoly e1(dgg, elementParams, Format::EVALUATION);

        DCRTPoly c0 = newp0 * u + ns * e0 + filtered;
        DCRTPoly c1 = newp1 * u + ns * e1;

        av.push_back(std::move(c1));
        bv.push_back(std::move(c0));
      }
    }
   } else {
     for (usint i = 0; i < sOld.GetNumOfElements(); i++) {
      // Creates an element with all zeroes
      DCRTPoly filtered(elementParams, Format::EVALUATION, true);
      filtered.SetElementAtIndex(i, sOld.GetElementAtIndex(i));

      DCRTPoly u = (cryptoParams->GetMode() == RLWE) ?
          DCRTPoly(dgg, elementParams, Format::EVALUATION) :
          DCRTPoly(tug, elementParams, Format::EVALUATION);

      DCRTPoly e0(dgg, elementParams, Format::EVALUATION);
      DCRTPoly e1(dgg, elementParams, Format::EVALUATION);

      DCRTPoly c0 = newp0 * u + ns * e0 + filtered;
      DCRTPoly c1 = newp1 * u + ns * e1;

      av.push_back(std::move(c1));
      bv.push_back(std::move(c0));
    }
  }

  ek->SetAVector(std::move(av));
  ek->SetBVector(std::move(bv));

  return ek;
}

void KeySwitchBV::KeySwitchInPlace(
    Ciphertext<DCRTPoly> &ciphertext, const EvalKey<DCRTPoly> ek) const {
  std::vector<DCRTPoly> &cv = ciphertext->GetElements();

  shared_ptr<vector<DCRTPoly>> ba = (cv.size() == 2) ?
      KeySwitchCore(cv[1], ek) :
      KeySwitchCore(cv[2], ek);

  cv[0].SetFormat((*ba)[0].GetFormat());
  cv[0] += (*ba)[0];

  cv[1].SetFormat((*ba)[1].GetFormat());
  if (cv.size() > 2) {
    cv[1] += (*ba)[1];
  } else {
    cv[1] = (*ba)[1];
  }
  cv.resize(2);
}

shared_ptr<vector<DCRTPoly>> KeySwitchBV::KeySwitchCore(
    DCRTPoly a, const EvalKey<DCRTPoly> evalKey) const {
  const auto cryptoParamsBase = evalKey->GetCryptoParameters();
  shared_ptr<vector<DCRTPoly>> digits = EvalKeySwitchPrecomputeCore(a, cryptoParamsBase);
  shared_ptr<vector<DCRTPoly>> result = EvalFastKeySwitchCore(digits, evalKey, a.GetParams());
  return result;
}

shared_ptr<vector<DCRTPoly>> KeySwitchBV::EvalKeySwitchPrecomputeCore(
    DCRTPoly c, shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParamsBase) const {
  const auto cryptoParams =
        std::static_pointer_cast<CryptoParametersRNS>(
            cryptoParamsBase);

  uint32_t relinWindow = cryptoParams->GetRelinWindow();

  auto decomposed = c.CRTDecompose(relinWindow);
  return std::make_shared<vector<DCRTPoly>>(decomposed);
}

shared_ptr<vector<DCRTPoly>> KeySwitchBV::EvalFastKeySwitchCore(
    const shared_ptr<vector<DCRTPoly>> digits, const EvalKey<DCRTPoly> evalKey,
    const shared_ptr<ParmType> paramsQl) const {
  std::vector<DCRTPoly> bv(evalKey->GetBVector());
  std::vector<DCRTPoly> av(evalKey->GetAVector());

  auto sizeQ = bv[0].GetParams()->GetParams().size();
  auto sizeQl = paramsQl->GetParams().size();
  size_t diffQl = sizeQ - sizeQl;

  for (size_t k = 0; k < bv.size(); k++) {
    av[k].DropLastElements(diffQl);
    bv[k].DropLastElements(diffQl);
  }

  DCRTPoly ct1 = (*digits)[0] * av[0];
  DCRTPoly ct0 = (*digits)[0] * bv[0];

  for (usint i = 1; i < (*digits).size(); ++i) {
    ct0 += (*digits)[i] * bv[i];
    ct1 += (*digits)[i] * av[i];
  }

  return std::make_shared<std::vector<DCRTPoly>>(std::initializer_list<DCRTPoly>{std::move(ct0), std::move(ct1)});
}

}  // namespace lbcrypto
