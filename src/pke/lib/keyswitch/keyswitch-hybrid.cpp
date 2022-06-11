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

/**
 * The implementation uses a mix of the GHS key-switching with the BV key-switching to
       produce more efficient key-switching.
 * This method was introduced in "Homomorphic Evaluation of the AES Circuit(GHS Scheme)"
        https://eprint.iacr.org/2012/099.pdf
 */
#define PROFILE

#include "cryptocontext.h"
#include "keyswitch/keyswitch-hybrid.h"

namespace lbcrypto {

EvalKey<DCRTPoly> KeySwitchHYBRID::KeySwitchGen(
    const PrivateKey<DCRTPoly> oldKey,
    const PrivateKey<DCRTPoly> newKey) const {
  auto cc = newKey->GetCryptoContext();
  EvalKeyRelin<DCRTPoly> ek =
      std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(cc);

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersRNS>(
          newKey->GetCryptoParameters());

  const std::shared_ptr<ParmType> paramsQ = cryptoParams->GetElementParams();
  const std::shared_ptr<ParmType> paramsQP = cryptoParams->GetParamsQP();

  usint sizeQ = paramsQ->GetParams().size();
  usint sizeQP = paramsQP->GetParams().size();

  DCRTPoly sOld = oldKey->GetPrivateElement();
  DCRTPoly sNew = newKey->GetPrivateElement().Clone();

  // skNew is currently in basis Q. This extends it to basis QP.
  sNew.SetFormat(Format::COEFFICIENT);

  DCRTPoly sNewExt(paramsQP, Format::COEFFICIENT, true);

  // The part with basis Q
  for (usint i = 0; i < sizeQ; i++) {
    sNewExt.SetElementAtIndex(i, sNew.GetElementAtIndex(i));
  }

  // The part with basis P
  for (usint j = sizeQ; j < sizeQP; j++) {
    const NativeInteger &pj = paramsQP->GetParams()[j]->GetModulus();
    const NativeInteger &rootj = paramsQP->GetParams()[j]->GetRootOfUnity();
    auto sNew0 = sNew.GetElementAtIndex(0);
    sNew0.SwitchModulus(pj, rootj, 0, 0);
    sNewExt.SetElementAtIndex(j, std::move(sNew0));
  }

  sNewExt.SetFormat(Format::EVALUATION);

  const auto ns = cryptoParams->GetNoiseScale();
  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  DugType dug;

  auto numPartQ = cryptoParams->GetNumPartQ();

  std::vector<DCRTPoly> av(numPartQ);
  std::vector<DCRTPoly> bv(numPartQ);

  std::vector<NativeInteger> PModq = cryptoParams->GetPModq();
  std::vector<std::vector<NativeInteger>> PartQHatModq = cryptoParams->GetPartQHatModq();

  for (usint part = 0; part < numPartQ; part++) {
    DCRTPoly a = DCRTPoly(dug, paramsQP, Format::EVALUATION);
    DCRTPoly e(dgg, paramsQP, Format::EVALUATION);
    DCRTPoly b(paramsQP, Format::EVALUATION, true);

    // The part with basis Q
    for (usint i = 0; i < sizeQ; i++) {
      const NativeInteger &qi = paramsQ->GetParams()[i]->GetModulus();
      auto ai = a.GetElementAtIndex(i);
      auto ei = e.GetElementAtIndex(i);
      auto sNewi = sNewExt.GetElementAtIndex(i);
      auto sOldi = sOld.GetElementAtIndex(i);
      auto factor = PModq[i].ModMulFast(PartQHatModq[part][i], qi);
      b.SetElementAtIndex(i, -ai * sNewi + factor * sOldi + ns * ei);
    }

    // The part with basis P
    for (usint j = sizeQ; j < sizeQP; j++) {
      auto aj = a.GetElementAtIndex(j);
      auto ej = e.GetElementAtIndex(j);
      auto sNewExtj = sNewExt.GetElementAtIndex(j);
      b.SetElementAtIndex(j, -aj * sNewExtj + ns * ej);
    }

    av[part] = a;
    bv[part] = b;
  }

  ek->SetAVector(std::move(av));
  ek->SetBVector(std::move(bv));

  return ek;
}

EvalKey<DCRTPoly> KeySwitchHYBRID::KeySwitchGen(
    const PrivateKey<DCRTPoly> oldKey, const PrivateKey<DCRTPoly> newKey,
    const EvalKey<DCRTPoly> ekPrev) const {
  auto cc = newKey->GetCryptoContext();
  EvalKeyRelin<DCRTPoly> ek(std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(cc));

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersRNS>(
          newKey->GetCryptoParameters());

  const std::shared_ptr<ParmType> paramsQ = cryptoParams->GetElementParams();
  const std::shared_ptr<ParmType> paramsQP = cryptoParams->GetParamsQP();

  usint sizeQ = paramsQ->GetParams().size();
  usint sizeQP = paramsQP->GetParams().size();

  DCRTPoly sOld = oldKey->GetPrivateElement();
  DCRTPoly sNew = newKey->GetPrivateElement().Clone();

  // skNew is currently in basis Q. This extends it to basis QP.
  sNew.SetFormat(Format::COEFFICIENT);

  DCRTPoly sNewExt(paramsQP, Format::COEFFICIENT, true);

  // The part with basis Q
  for (usint i = 0; i < sizeQ; i++) {
    sNewExt.SetElementAtIndex(i, sNew.GetElementAtIndex(i));
  }

  // The part with basis P
  for (usint j = sizeQ; j < sizeQP; j++) {
    const NativeInteger &pj = paramsQP->GetParams()[j]->GetModulus();
    const NativeInteger &rootj = paramsQP->GetParams()[j]->GetRootOfUnity();
    auto sNew0 = sNew.GetElementAtIndex(0);
    sNew0.SwitchModulus(pj, rootj, 0, 0);
    sNewExt.SetElementAtIndex(j, std::move(sNew0));
  }

  sNewExt.SetFormat(Format::EVALUATION);

  const auto ns = cryptoParams->GetNoiseScale();
  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  DugType dug;

  auto numPartQ = cryptoParams->GetNumPartQ();

  std::vector<DCRTPoly> av(numPartQ);
  std::vector<DCRTPoly> bv(numPartQ);

  std::vector<NativeInteger> PModq = cryptoParams->GetPModq();
  std::vector<std::vector<NativeInteger>> PartQHatModq = cryptoParams->GetPartQHatModq();

  for (usint part = 0; part < numPartQ; part++) {
    DCRTPoly a = ekPrev == nullptr ? DCRTPoly(dug, paramsQP, Format::EVALUATION)
                                   :              // single-key HE
                     ekPrev->GetAVector()[part];  // threshold HE
    DCRTPoly e(dgg, paramsQP, Format::EVALUATION);
    DCRTPoly b(paramsQP, Format::EVALUATION, true);

    // The part with basis Q
    for (usint i = 0; i < sizeQ; i++) {
      const NativeInteger &qi = paramsQ->GetParams()[i]->GetModulus();
      auto ai = a.GetElementAtIndex(i);
      auto ei = e.GetElementAtIndex(i);
      auto sNewi = sNewExt.GetElementAtIndex(i);
      auto sOldi = sOld.GetElementAtIndex(i);
      auto factor = PModq[i].ModMulFast(PartQHatModq[part][i], qi);
      b.SetElementAtIndex(i, -ai * sNewi + factor * sOldi + ns * ei);
    }

    // The part with basis P
    for (usint j = sizeQ; j < sizeQP; j++) {
      auto aj = a.GetElementAtIndex(j);
      auto ej = e.GetElementAtIndex(j);
      auto sNewExtj = sNewExt.GetElementAtIndex(j);
      b.SetElementAtIndex(j, -aj * sNewExtj + ns * ej);
    }

    av[part] = a;
    bv[part] = b;
  }

  ek->SetAVector(std::move(av));
  ek->SetBVector(std::move(bv));

  return ek;
}

EvalKey<DCRTPoly> KeySwitchHYBRID::KeySwitchGen(
    const PrivateKey<DCRTPoly> oldKey,
    const PublicKey<DCRTPoly> newKey) const {
  auto cc = newKey->GetCryptoContext();
  EvalKeyRelin<DCRTPoly> ek =
      std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(cc);

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersRNS>(
          newKey->GetCryptoParameters());

  const std::shared_ptr<ParmType> paramsQ = cryptoParams->GetElementParams();
  const std::shared_ptr<ParmType> paramsQP = cryptoParams->GetParamsQP();

  usint sizeQ = paramsQ->GetParams().size();
  usint sizeQP = paramsQP->GetParams().size();

  DCRTPoly sOld = oldKey->GetPrivateElement();

  DCRTPoly newp0 = newKey->GetPublicElements().at(0);
  DCRTPoly newp1 = newKey->GetPublicElements().at(1);

  const auto ns = cryptoParams->GetNoiseScale();
  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  DugType dug;
  TugType tug;

  auto numPartQ = cryptoParams->GetNumPartQ();

  std::vector<DCRTPoly> av(numPartQ);
  std::vector<DCRTPoly> bv(numPartQ);

  std::vector<NativeInteger> PModq = cryptoParams->GetPModq();
  std::vector<std::vector<NativeInteger>> PartQHatModq = cryptoParams->GetPartQHatModq();

  for (usint part = 0; part < numPartQ; part++) {
    DCRTPoly u = (cryptoParams->GetMode() == RLWE) ?
        DCRTPoly(dgg, paramsQP, Format::EVALUATION) :
        DCRTPoly(tug, paramsQP, Format::EVALUATION);

    DCRTPoly e0(dgg, paramsQP, Format::EVALUATION);
    DCRTPoly e1(dgg, paramsQP, Format::EVALUATION);

    DCRTPoly a(paramsQP, Format::EVALUATION, true);
    DCRTPoly b(paramsQP, Format::EVALUATION, true);

    // The part with basis Q
    for (usint i = 0; i < sizeQ; i++) {
      const NativeInteger &qi = paramsQ->GetParams()[i]->GetModulus();
      auto e0i = e0.GetElementAtIndex(i);
      auto e1i = e1.GetElementAtIndex(i);

      auto ui = u.GetElementAtIndex(i);

      auto newp0i = newp0.GetElementAtIndex(i);
      auto newp1i = newp1.GetElementAtIndex(i);

      auto sOldi = sOld.GetElementAtIndex(i);
      auto factor = PModq[i].ModMulFast(PartQHatModq[part][i], qi);

      a.SetElementAtIndex(i, newp1i * ui + ns * e1i);
      b.SetElementAtIndex(i, newp0i * ui + ns * e0i + factor * sOldi);
    }

    // The part with basis P
    for (usint j = sizeQ; j < sizeQP; j++) {
      auto e0j = e0.GetElementAtIndex(j);
      auto e1j = e1.GetElementAtIndex(j);

      auto uj = u.GetElementAtIndex(j);

      auto newp0j = newp0.GetElementAtIndex(j);
      auto newp1j = newp1.GetElementAtIndex(j);

      a.SetElementAtIndex(j, newp1j * uj + ns * e1j);
      b.SetElementAtIndex(j, newp0j * uj + ns * e0j);
    }

    av[part] = a;
    bv[part] = b;
  }

  ek->SetAVector(std::move(av));
  ek->SetBVector(std::move(bv));

  return ek;
}

void KeySwitchHYBRID::KeySwitchInPlace(Ciphertext<DCRTPoly> &ciphertext,
                                       const EvalKey<DCRTPoly> ek) const {
  std::vector<DCRTPoly> &cv = ciphertext->GetElements();

  std::shared_ptr<std::vector<DCRTPoly>> ba = (cv.size() == 2) ?
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

Ciphertext<DCRTPoly> KeySwitchHYBRID::KeySwitchDown(
    ConstCiphertext<DCRTPoly> ciphertext) const {

  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();
  const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

  const auto paramsP = cryptoParams->GetParamsP();
  const auto paramsQlP = ciphertext->GetElements()[0].GetParams();

  // TODO : (Andrey) precompute paramsQl in cryptoparameters
  usint sizeQ = paramsQlP->GetParams().size() - paramsP->GetParams().size();
  std::vector<NativeInteger> moduliQ(sizeQ);
  std::vector<NativeInteger> rootsQ(sizeQ);
  for (size_t i = 0; i < sizeQ; i++) {
    moduliQ[i] = paramsQlP->GetParams()[i]->GetModulus();
    rootsQ[i] = paramsQlP->GetParams()[i]->GetRootOfUnity();
  }
  auto paramsQl = std::make_shared<typename DCRTPoly::Params>(2*paramsQlP->GetRingDimension(),
                                                  moduliQ, rootsQ);

  auto cTilda = ciphertext->GetElements();

  PlaintextModulus t = (cryptoParams->GetNoiseScale() == 1) ? 0 : cryptoParams->GetPlaintextModulus();

  DCRTPoly ct0 = cTilda[0].ApproxModDown(
      paramsQl, cryptoParams->GetParamsP(), cryptoParams->GetPInvModq(),
      cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
      cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
      cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
      cryptoParams->GettInvModpPrecon(), t,
      cryptoParams->GettModqPrecon());

  DCRTPoly ct1 = cTilda[0].ApproxModDown(
      paramsQl, cryptoParams->GetParamsP(), cryptoParams->GetPInvModq(),
      cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
      cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
      cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
      cryptoParams->GettInvModpPrecon(), t,
      cryptoParams->GettModqPrecon());

  result->SetElements({ct0, ct1});

  result->SetDepth(ciphertext->GetDepth());
  result->SetLevel(ciphertext->GetLevel());
  result->SetScalingFactor(ciphertext->GetScalingFactor());

  return result;

}

DCRTPoly KeySwitchHYBRID::KeySwitchDownFirstElement(
    ConstCiphertext<DCRTPoly> ciphertext) const {
  const auto cryptoParams =
      std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(
      ciphertext->GetCryptoParameters());

  const auto paramsP = cryptoParams->GetParamsP();
  const auto paramsQlP = ciphertext->GetElements()[0].GetParams();

  // TODO : (Andrey) precompute paramsQl in cryptoparameters
  usint sizeQ = paramsQlP->GetParams().size() - paramsP->GetParams().size();
  std::vector<NativeInteger> moduliQ(sizeQ);
  std::vector<NativeInteger> rootsQ(sizeQ);
  for (size_t i = 0; i < sizeQ; i++) {
    moduliQ[i] = paramsQlP->GetParams()[i]->GetModulus();
    rootsQ[i] = paramsQlP->GetParams()[i]->GetRootOfUnity();
  }
  auto paramsQl = std::make_shared<typename DCRTPoly::Params>(2*paramsQlP->GetRingDimension(),
                                                  moduliQ, rootsQ);

  auto c0 = ciphertext->GetElements()[0];

  PlaintextModulus t = (cryptoParams->GetNoiseScale() == 1) ? 0 : cryptoParams->GetPlaintextModulus();

  DCRTPoly ct0 = c0.ApproxModDown(
      paramsQl, cryptoParams->GetParamsP(), cryptoParams->GetPInvModq(),
      cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
      cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
      cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
      cryptoParams->GettInvModpPrecon(), t,
      cryptoParams->GettModqPrecon());

  return ct0;
}

Ciphertext<DCRTPoly> KeySwitchHYBRID::KeySwitchExt(
    ConstCiphertext<DCRTPoly> ciphertext, bool addFirst) const {

  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();

  const auto cryptoParams =
      std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(
          ciphertext->GetCryptoParameters());

  const auto paramsQl = ciphertext->GetElements()[0].GetParams();
  const auto paramsP = cryptoParams->GetParamsP();
  const auto paramsQlP = ciphertext->GetElements()[0].GetExtendedCRTBasis(paramsP);

  size_t sizeQl = paramsQl->GetParams().size();

  usint sizeCt = ciphertext->GetElements().size();
  std::vector<DCRTPoly> resultElements(sizeCt);
  const std::vector<DCRTPoly> &c = ciphertext->GetElements();
  for (usint k = 0; k < sizeCt; k++) {
      resultElements[k] = DCRTPoly(paramsQlP, Format::EVALUATION, true);
      if ((addFirst) || (k > 0)) {
  auto cMult = c[k].Times(cryptoParams->GetPModq());
  for (usint i = 0; i < sizeQl; i++) {
      resultElements[k].SetElementAtIndex(i,cMult.GetElementAtIndex(i));
  }
      }
  }

  result->SetElements(resultElements);

  result->SetDepth(ciphertext->GetDepth());
  result->SetLevel(ciphertext->GetLevel());
  result->SetScalingFactor(ciphertext->GetScalingFactor());

  return result;

}

std::shared_ptr<std::vector<DCRTPoly>> KeySwitchHYBRID::KeySwitchCore(
    DCRTPoly a, const EvalKey<DCRTPoly> evalKey) const {
  const auto cryptoParamsBase = evalKey->GetCryptoParameters();
  std::shared_ptr<std::vector<DCRTPoly>> digits = EvalKeySwitchPrecomputeCore(a, cryptoParamsBase);
  std::shared_ptr<std::vector<DCRTPoly>> result = EvalFastKeySwitchCore(digits, evalKey, a.GetParams());
  return result;
}

std::shared_ptr<std::vector<DCRTPoly>> KeySwitchHYBRID::EvalKeySwitchPrecomputeCore(
    DCRTPoly c, std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParamsBase) const {
  const auto cryptoParams =
        std::static_pointer_cast<CryptoParametersRNS>(
            cryptoParamsBase);

  const std::shared_ptr<ParmType> paramsQl = c.GetParams();
  const std::shared_ptr<ParmType> paramsP = cryptoParams->GetParamsP();
  const std::shared_ptr<ParmType> paramsQlP = c.GetExtendedCRTBasis(paramsP);

  size_t sizeQl = paramsQl->GetParams().size();
  size_t sizeP = paramsP->GetParams().size();
  size_t sizeQlP = sizeQl + sizeP;

  uint32_t alpha = cryptoParams->GetNumPerPartQ();
  // The number of digits of the current ciphertext
  uint32_t numPartQl = ceil((static_cast<double>(sizeQl)) / alpha);
  if (numPartQl > cryptoParams->GetNumberOfQPartitions())
    numPartQl = cryptoParams->GetNumberOfQPartitions();

  std::vector<DCRTPoly> partsCt(numPartQl);

  // Digit decomposition
  // Zero-padding and split
  for (uint32_t part = 0; part < numPartQl; part++) {
    if (part == numPartQl - 1) {
      auto paramsPartQ = cryptoParams->GetParamsPartQ(part);

      uint32_t sizePartQl = sizeQl - alpha * part;

      std::vector<NativeInteger> moduli(sizePartQl);
      std::vector<NativeInteger> roots(sizePartQl);

      for (uint32_t i = 0; i < sizePartQl; i++) {
        moduli[i] = paramsPartQ->GetParams()[i]->GetModulus();
        roots[i] = paramsPartQ->GetParams()[i]->GetRootOfUnity();
      }

      auto params = DCRTPoly::Params(paramsPartQ->GetCyclotomicOrder(), moduli,
                                     roots, {}, {}, 0);

      partsCt[part] = DCRTPoly(std::make_shared<ParmType>(params),
                               Format::EVALUATION, true);

    } else {
      partsCt[part] = DCRTPoly(cryptoParams->GetParamsPartQ(part),
                               Format::EVALUATION, true);
    }

    const std::vector<NativeInteger> &QHatInvModq =
        cryptoParams->GetPartQHatInvModq(part);

    usint sizePartQl = partsCt[part].GetNumOfElements();
    usint startPartIdx = alpha * part;
    for (uint32_t i = 0, idx = startPartIdx; i < sizePartQl; i++, idx++) {
      auto tmp = c.GetElementAtIndex(idx).Times(QHatInvModq[idx]);
      partsCt[part].SetElementAtIndex(i, std::move(tmp));
    }
  }

  std::vector<DCRTPoly> partsCtCompl(numPartQl);
  std::vector<DCRTPoly> partsCtExt(numPartQl);

  for (uint32_t part = 0; part < numPartQl; part++) {
    auto partCtClone = partsCt[part].Clone();
    partCtClone.SetFormat(Format::COEFFICIENT);

    uint32_t sizePartQl = partsCt[part].GetNumOfElements();
    partsCtCompl[part] = partCtClone.ApproxSwitchCRTBasis(
        cryptoParams->GetParamsPartQ(part),
        cryptoParams->GetParamsComplPartQ(sizeQl - 1, part),
        cryptoParams->GetPartQlHatInvModq(part, sizePartQl - 1),
        cryptoParams->GetPartQlHatInvModqPrecon(part, sizePartQl - 1),
        cryptoParams->GetPartQlHatModp(sizeQl - 1, part),
        cryptoParams->GetmodComplPartqBarrettMu(sizeQl - 1, part));

    partsCtCompl[part].SetFormat(Format::EVALUATION);

    partsCtExt[part] = DCRTPoly(paramsQlP, Format::EVALUATION, true);

    usint startPartIdx = alpha * part;
    usint endPartIdx = startPartIdx + sizePartQl;
    for (usint i = 0; i < startPartIdx; i++) {
      partsCtExt[part].SetElementAtIndex(
          i, partsCtCompl[part].GetElementAtIndex(i));
    }
    for (usint i = startPartIdx, idx = 0; i < endPartIdx; i++, idx++) {
      partsCtExt[part].SetElementAtIndex(i,
                                         partsCt[part].GetElementAtIndex(idx));
    }
    for (usint i = endPartIdx; i < sizeQlP; ++i) {
      partsCtExt[part].SetElementAtIndex(
          i, partsCtCompl[part].GetElementAtIndex(i - sizePartQl));
    }
  }

  return std::make_shared<std::vector<DCRTPoly>>(std::move(partsCtExt));
}

std::shared_ptr<std::vector<DCRTPoly>> KeySwitchHYBRID::EvalFastKeySwitchCore(
    const std::shared_ptr<std::vector<DCRTPoly>> digits, const EvalKey<DCRTPoly> evalKey,
    const std::shared_ptr<ParmType> paramsQl) const {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersRNS>(
          evalKey->GetCryptoParameters());

  std::shared_ptr<std::vector<DCRTPoly>> cTilda = EvalFastKeySwitchExtCore(digits, evalKey, paramsQl);

  PlaintextModulus t = (cryptoParams->GetNoiseScale() == 1) ? 0 : cryptoParams->GetPlaintextModulus();

  DCRTPoly ct0 = (*cTilda)[0].ApproxModDown(
      paramsQl, cryptoParams->GetParamsP(), cryptoParams->GetPInvModq(),
      cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
      cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
      cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
      cryptoParams->GettInvModpPrecon(), t,
      cryptoParams->GettModqPrecon());

  DCRTPoly ct1 = (*cTilda)[1].ApproxModDown(
      paramsQl, cryptoParams->GetParamsP(), cryptoParams->GetPInvModq(),
      cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
      cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
      cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
      cryptoParams->GettInvModpPrecon(), t,
      cryptoParams->GettModqPrecon());

  // ct0.SetFormat(Format::EVALUATION);
  // ct1.SetFormat(Format::EVALUATION);

  return std::make_shared<std::vector<DCRTPoly>>(std::initializer_list<DCRTPoly>{std::move(ct0), std::move(ct1)});
}

std::shared_ptr<std::vector<DCRTPoly>> KeySwitchHYBRID::EvalFastKeySwitchExtCore(
    const std::shared_ptr<std::vector<DCRTPoly>> digits, const EvalKey<DCRTPoly> evalKey,
    const std::shared_ptr<ParmType> paramsQl) const {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersRNS>(
          evalKey->GetCryptoParameters());
  const std::vector<DCRTPoly> &bv = evalKey->GetBVector();
  const std::vector<DCRTPoly> &av = evalKey->GetAVector();

  const std::shared_ptr<ParmType> paramsP = cryptoParams->GetParamsP();
  const std::shared_ptr<ParmType> paramsQlP = (*digits)[0].GetParams();

  size_t sizeQl = paramsQl->GetParams().size();
  size_t sizeQlP = paramsQlP->GetParams().size();
  size_t sizeQ = cryptoParams->GetElementParams()->GetParams().size();

  DCRTPoly cTilda0(paramsQlP, Format::EVALUATION, true);
  DCRTPoly cTilda1(paramsQlP, Format::EVALUATION, true);

  for (uint32_t j = 0; j < digits->size(); j++) {
    const DCRTPoly &cj = (*digits)[j];
    const DCRTPoly &bj = bv[j];
    const DCRTPoly &aj = av[j];

    for (usint i = 0; i < sizeQl; i++) {
      const auto &cji = cj.GetElementAtIndex(i);
      const auto &aji = aj.GetElementAtIndex(i);
      const auto &bji = bj.GetElementAtIndex(i);

      cTilda0.SetElementAtIndex(i, cTilda0.GetElementAtIndex(i) + cji * bji);
      cTilda1.SetElementAtIndex(i, cTilda1.GetElementAtIndex(i) + cji * aji);
    }
    for (usint i = sizeQl, idx = sizeQ; i < sizeQlP; i++, idx++) {
      const auto &cji = cj.GetElementAtIndex(i);
      const auto &aji = aj.GetElementAtIndex(idx);
      const auto &bji = bj.GetElementAtIndex(idx);

      cTilda0.SetElementAtIndex(i, cTilda0.GetElementAtIndex(i) + cji * bji);
      cTilda1.SetElementAtIndex(i, cTilda1.GetElementAtIndex(i) + cji * aji);
    }
  }

  // cTilda0.SetFormat(Format::COEFFICIENT);
  // cTilda1.SetFormat(Format::COEFFICIENT);

  return std::make_shared<std::vector<DCRTPoly>>(std::initializer_list<DCRTPoly>{std::move(cTilda0), std::move(cTilda1)});
}

}  // namespace lbcrypto
