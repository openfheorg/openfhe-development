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
#include "scheme/bgvrns/bgvrns-leveledshe.h"
//#include "cryptocontext.h"

namespace lbcrypto {

void LeveledSHEBGVRNS::ModReduceInternalInPlace(
    Ciphertext<DCRTPoly> &ciphertext, size_t levels) const {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersBGVRNS>(
          ciphertext->GetCryptoParameters());

  const auto t = ciphertext->GetCryptoParameters()->GetPlaintextModulus();

  std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  usint sizeQl = cv[0].GetNumOfElements();

  for (auto &c : cv) {
    for (size_t l = sizeQl - 1; l >= sizeQl - levels; --l) {
      c.ModReduce(t,
          cryptoParams->GettModqPrecon(),
          cryptoParams->GetNegtInvModq(l),
          cryptoParams->GetNegtInvModqPrecon(l),
          cryptoParams->GetqlInvModq(l),
          cryptoParams->GetqlInvModqPrecon(l));
    }
  }

  ciphertext->SetLevel(ciphertext->GetLevel() + levels);
  ciphertext->SetDepth(ciphertext->GetDepth() - levels);

  for (usint i = 0; i < levels; ++i) {
    NativeInteger modReduceFactor = cryptoParams->GetModReduceFactorInt(sizeQl - 1 + i);
    NativeInteger modReduceFactorInv = modReduceFactor.ModInverse(t);
    ciphertext->SetScalingFactorInt(ciphertext->GetScalingFactorInt().ModMul(modReduceFactorInv, t));
  }
}

void LeveledSHEBGVRNS::LevelReduceInternalInPlace(Ciphertext<DCRTPoly> &ciphertext, size_t levels) const {
  std::vector<DCRTPoly> &elements = ciphertext->GetElements();
  for (auto &element : elements) {
    element.DropLastElements(levels);
  }
  ciphertext->SetLevel(ciphertext->GetLevel() + levels);
}

void LeveledSHEBGVRNS::AdjustLevelsAndDepthInPlace(Ciphertext<DCRTPoly> &ciphertext1,
                                 Ciphertext<DCRTPoly> &ciphertext2) const {
  const auto cryptoParams =
        std::static_pointer_cast<CryptoParametersBGVRNS>(ciphertext1->GetCryptoParameters());

  const NativeInteger t(cryptoParams->GetPlaintextModulus());

  usint c1lvl = ciphertext1->GetLevel();
  usint c2lvl = ciphertext2->GetLevel();
  usint c1depth = ciphertext1->GetDepth();
  usint c2depth = ciphertext2->GetDepth();
  auto sizeQl1 = ciphertext1->GetElements()[0].GetNumOfElements();
  auto sizeQl2 = ciphertext2->GetElements()[0].GetNumOfElements();

  if (c1lvl < c2lvl) {
    if (c1depth == 2) {
      if (c2depth == 2) {
        NativeInteger scf1 = ciphertext1->GetScalingFactorInt();
        NativeInteger scf2 = ciphertext2->GetScalingFactorInt();
        NativeInteger scf = cryptoParams->GetScalingFactorInt(c1lvl);
        NativeInteger ql1Modt = cryptoParams->GetModReduceFactorInt(sizeQl1 - 1);
        NativeInteger scf1Inv = scf1.ModInverse(t);
        NativeInteger scfInv = scf.ModInverse(t);

        EvalMultCoreInPlace(ciphertext1, scf2.ModMul(scf1Inv, t).ModMul(ql1Modt, t).ModMul(scfInv, t).ConvertToInt());
        ModReduceInternalInPlace(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
        if (c1lvl + 1 < c2lvl) {
          LevelReduceInternalInPlace(ciphertext1, c2lvl - c1lvl - 1);
        }
        ciphertext1->SetScalingFactorInt(ciphertext2->GetScalingFactorInt());
      } else {
        if (c1lvl + 1 == c2lvl) {
          ModReduceInternalInPlace(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
        } else {
          NativeInteger scf1 = ciphertext1->GetScalingFactorInt();
          NativeInteger scf2 = cryptoParams->GetScalingFactorIntBig(c2lvl - 1);
          NativeInteger scf = cryptoParams->GetScalingFactorInt(c1lvl);
          NativeInteger ql1Modt = cryptoParams->GetModReduceFactorInt(sizeQl1 - 1);
          NativeInteger scf1Inv = scf1.ModInverse(t);
          NativeInteger scfInv = scf.ModInverse(t);

          EvalMultCoreInPlace(ciphertext1, scf2.ModMul(scf1Inv, t).ModMul(ql1Modt, t).ModMul(scfInv, t).ConvertToInt());
          ModReduceInternalInPlace(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
          if (c1lvl + 2 < c2lvl) {
            LevelReduceInternalInPlace(ciphertext1, c2lvl - c1lvl - 2);
          }
          ModReduceInternalInPlace(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
          ciphertext1->SetScalingFactorInt(ciphertext2->GetScalingFactorInt());
        }
      }
    } else {
      if (c2depth == 2) {
        NativeInteger scf1 = ciphertext1->GetScalingFactorInt();
        NativeInteger scf2 = ciphertext2->GetScalingFactorInt();
        NativeInteger scf = cryptoParams->GetScalingFactorInt(c1lvl);
        NativeInteger scf1Inv = scf1.ModInverse(t);
        NativeInteger scfInv = scf.ModInverse(t);

        EvalMultCoreInPlace(ciphertext1, scf2.ModMul(scf1Inv, t).ModMul(scfInv, t).ConvertToInt());
        LevelReduceInternalInPlace(ciphertext1, c2lvl - c1lvl);
        ciphertext1->SetScalingFactorInt(scf2);
      } else {
        NativeInteger scf1 = ciphertext1->GetScalingFactorInt();
        NativeInteger scf2 = cryptoParams->GetScalingFactorInt(c2lvl - 1);
        NativeInteger scf = cryptoParams->GetScalingFactorInt(c1lvl);
        NativeInteger scf1Inv = scf1.ModInverse(t);
        NativeInteger scfInv = scf.ModInverse(t);

        EvalMultCoreInPlace(ciphertext1, scf2.ModMul(scf1Inv, t).ModMul(scfInv, t).ConvertToInt());
        if (c1lvl + 1 < c2lvl) {
          LevelReduceInternalInPlace(ciphertext1, c2lvl - c1lvl - 1);
        }
        ModReduceInternalInPlace(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
        ciphertext1->SetScalingFactorInt(ciphertext2->GetScalingFactorInt());
      }
    }
  } else if (c1lvl > c2lvl) {
    if (c2depth == 2) {
      if (c1depth == 2) {
        NativeInteger scf2 = ciphertext2->GetScalingFactorInt();
        NativeInteger scf1 = ciphertext1->GetScalingFactorInt();
        NativeInteger scf = cryptoParams->GetScalingFactorInt(c2lvl);
        NativeInteger ql2Modt = cryptoParams->GetModReduceFactorInt(sizeQl2 - 1);
        NativeInteger scf2Inv = scf2.ModInverse(t);
        NativeInteger scfInv = scf.ModInverse(t);

        EvalMultInPlace(ciphertext2, scf1.ModMul(scf2Inv, t).ModMul(ql2Modt, t).ModMul(scfInv, t).ConvertToInt());
        ModReduceInternalInPlace(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
        if (c2lvl + 1 < c1lvl) {
          LevelReduceInternalInPlace(ciphertext2, c1lvl - c2lvl - 1);
        }
        ciphertext2->SetScalingFactorInt(ciphertext1->GetScalingFactorInt());
      } else {
        if (c2lvl + 1 == c1lvl) {
          ModReduceInternalInPlace(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
        } else {
          NativeInteger scf2 = ciphertext2->GetScalingFactorInt();
          NativeInteger scf1 = cryptoParams->GetScalingFactorIntBig(c1lvl - 1);
          NativeInteger scf = cryptoParams->GetScalingFactorInt(c2lvl);
          NativeInteger ql2Modt = cryptoParams->GetModReduceFactorInt(sizeQl2 - 1);
          NativeInteger scf2Inv = scf2.ModInverse(t);
          NativeInteger scfInv = scf.ModInverse(t);

          EvalMultCoreInPlace(ciphertext2,scf1.ModMul(scf2Inv, t).ModMul(ql2Modt, t).ModMul(scfInv, t).ConvertToInt());
          ModReduceInternalInPlace(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
          if (c2lvl + 2 < c1lvl) {
            LevelReduceInternalInPlace(ciphertext2, c1lvl - c2lvl - 2);
          }
          ModReduceInternalInPlace(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
          ciphertext2->SetScalingFactorInt(ciphertext1->GetScalingFactorInt());
        }
      }
    } else {
      if (c1depth == 2) {
        NativeInteger scf2 = ciphertext2->GetScalingFactorInt();
        NativeInteger scf1 = ciphertext1->GetScalingFactorInt();
        NativeInteger scf = cryptoParams->GetScalingFactorInt(c2lvl);
        NativeInteger scf2Inv = scf2.ModInverse(t);
        NativeInteger scfInv = scf.ModInverse(t);

        EvalMultCoreInPlace(ciphertext2, scf1.ModMul(scf2Inv, t).ModMul(scfInv, t).ConvertToInt());
        LevelReduceInternalInPlace(ciphertext2, c1lvl - c2lvl);
        ciphertext2->SetScalingFactorInt(scf1);
      } else {
        NativeInteger scf2 = ciphertext2->GetScalingFactorInt();
        NativeInteger scf1 = cryptoParams->GetScalingFactorIntBig(c1lvl - 1);
        NativeInteger scf = cryptoParams->GetScalingFactorInt(c2lvl);
        NativeInteger scf2Inv = scf2.ModInverse(t);
        NativeInteger scfInv = scf.ModInverse(t);

        EvalMultCoreInPlace(ciphertext2, scf1.ModMul(scf2Inv, t).ModMul(scfInv, t).ConvertToInt());
        if (c2lvl + 1 < c1lvl) {
          LevelReduceInternalInPlace(ciphertext2, c1lvl - c2lvl - 1);
        }
        ModReduceInternalInPlace(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
        ciphertext2->SetScalingFactorInt(ciphertext1->GetScalingFactorInt());
      }
    }
  } else {
    if (c1depth < c2depth) {
      ciphertext1->SetDepth(2);
    } else if (c2depth < c1depth) {
      ciphertext2->SetDepth(2);
    }
  }
}

void LeveledSHEBGVRNS::AdjustLevelsAndDepthToOneInPlace(Ciphertext<DCRTPoly> &ciphertext1,
                                 Ciphertext<DCRTPoly> &ciphertext2) const {
  AdjustLevelsAndDepthInPlace(ciphertext1, ciphertext2);

  if (ciphertext1->GetDepth() == 2) {
    ModReduceInternalInPlace(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
    ModReduceInternalInPlace(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
  }
}

DCRTPoly LeveledSHEBGVRNS::AdjustLevelsAndDepthInPlace(
    Ciphertext<DCRTPoly> &ciphertext, ConstPlaintext plaintext) const {
  DCRTPoly ptxt = plaintext->GetElement<DCRTPoly>();

  auto sizeQlc = ciphertext->GetElements()[0].GetNumOfElements();
  auto sizeQlp = ptxt.GetNumOfElements();

  if (sizeQlc < sizeQlp) {
    // Ciphertext remains the same
    // Level reduce the plaintext
    ptxt.DropLastElements(sizeQlp - sizeQlc);
  } else if (sizeQlc > sizeQlp) {
    // Plaintext remains same
    // Level reduce the ciphertext
    ciphertext = LevelReduceInternal(ciphertext, sizeQlc - sizeQlp);
  } // else do nothing
  ptxt.SetFormat(Format::EVALUATION);
  return ptxt;
}


DCRTPoly LeveledSHEBGVRNS::AdjustLevelsAndDepthToOneInPlace(
    Ciphertext<DCRTPoly> &ciphertext, ConstPlaintext plaintext) const {
  if(ciphertext->GetDepth() == 2) {
      ModReduceInternalInPlace(ciphertext, BASE_NUM_LEVELS_TO_DROP);
  }
  return AdjustLevelsAndDepthInPlace(ciphertext, plaintext);
}

void LeveledSHEBGVRNS::EvalMultCoreInPlace(Ciphertext<DCRTPoly> &ciphertext, const NativeInteger& constant) const {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersBGVRNS>(
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
