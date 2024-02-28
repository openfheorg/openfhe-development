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
BGV implementation. See https://eprint.iacr.org/2021/204 for details.
 */

#define PROFILE

#include "scheme/bgvrns/bgvrns-leveledshe.h"

#include "scheme/bgvrns/bgvrns-cryptoparameters.h"
#include "ciphertext.h"

namespace lbcrypto {

void LeveledSHEBGVRNS::ModReduceInternalInPlace(Ciphertext<DCRTPoly>& ciphertext, size_t levels) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBGVRNS>(ciphertext->GetCryptoParameters());

    const auto t = ciphertext->GetCryptoParameters()->GetPlaintextModulus();

    std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    usint sizeQl              = cv[0].GetNumOfElements();

    if (sizeQl > levels && sizeQl > 0) {
        for (auto& c : cv) {
            for (size_t i = sizeQl - 1; i >= sizeQl - levels; --i) {
                c.ModReduce(t, cryptoParams->GettModqPrecon(), cryptoParams->GetNegtInvModq(i),
                            cryptoParams->GetNegtInvModqPrecon(i), cryptoParams->GetqlInvModq(i),
                            cryptoParams->GetqlInvModqPrecon(i));
            }
        }
    }
    else {
        std::string errMsg = "ERROR: Not enough towers to support ModReduce.";
        OPENFHE_THROW(errMsg);
    }

    ciphertext->SetLevel(ciphertext->GetLevel() + levels);
    ciphertext->SetNoiseScaleDeg(ciphertext->GetNoiseScaleDeg() - levels);

    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT) {
        for (usint i = 0; i < levels; ++i) {
            NativeInteger modReduceFactor    = cryptoParams->GetModReduceFactorInt(sizeQl - 1 - i);
            NativeInteger modReduceFactorInv = modReduceFactor.ModInverse(t);
            ciphertext->SetScalingFactorInt(ciphertext->GetScalingFactorInt().ModMul(modReduceFactorInv, t));
        }
    }
}

void LeveledSHEBGVRNS::LevelReduceInternalInPlace(Ciphertext<DCRTPoly>& ciphertext, size_t levels) const {
    std::vector<DCRTPoly>& elements = ciphertext->GetElements();
    for (auto& element : elements) {
        element.DropLastElements(levels);
    }
    ciphertext->SetLevel(ciphertext->GetLevel() + levels);
}

void LeveledSHEBGVRNS::AdjustLevelsAndDepthInPlace(Ciphertext<DCRTPoly>& ciphertext1,
                                                   Ciphertext<DCRTPoly>& ciphertext2) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBGVRNS>(ciphertext1->GetCryptoParameters());

    const NativeInteger t(cryptoParams->GetPlaintextModulus());

    usint c1lvl   = ciphertext1->GetLevel();
    usint c2lvl   = ciphertext2->GetLevel();
    usint c1depth = ciphertext1->GetNoiseScaleDeg();
    usint c2depth = ciphertext2->GetNoiseScaleDeg();
    auto sizeQl1  = ciphertext1->GetElements()[0].GetNumOfElements();
    auto sizeQl2  = ciphertext2->GetElements()[0].GetNumOfElements();

    if (c1lvl < c2lvl) {
        if (c1depth == 2) {
            if (c2depth == 2) {
                NativeInteger scf1    = ciphertext1->GetScalingFactorInt();
                NativeInteger scf2    = ciphertext2->GetScalingFactorInt();
                NativeInteger ql1Modt = cryptoParams->GetModReduceFactorInt(sizeQl1 - 1);
                NativeInteger scf1Inv = scf1.ModInverse(t);

                EvalMultCoreInPlace(ciphertext1, scf2.ModMul(scf1Inv, t).ModMul(ql1Modt, t).ConvertToInt());
                ModReduceInternalInPlace(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
                if (c1lvl + 1 < c2lvl) {
                    LevelReduceInternalInPlace(ciphertext1, c2lvl - c1lvl - 1);
                }
                ciphertext1->SetScalingFactorInt(ciphertext2->GetScalingFactorInt());
            }
            else {
                if (c1lvl + 1 == c2lvl) {
                    ModReduceInternalInPlace(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
                }
                else {
                    NativeInteger scf1    = ciphertext1->GetScalingFactorInt();
                    NativeInteger scf2    = cryptoParams->GetScalingFactorIntBig(c2lvl - 1);
                    NativeInteger ql1Modt = cryptoParams->GetModReduceFactorInt(sizeQl1 - 1);
                    NativeInteger scf1Inv = scf1.ModInverse(t);

                    EvalMultCoreInPlace(ciphertext1, scf2.ModMul(scf1Inv, t).ModMul(ql1Modt, t).ConvertToInt());
                    ModReduceInternalInPlace(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
                    if (c1lvl + 2 < c2lvl) {
                        LevelReduceInternalInPlace(ciphertext1, c2lvl - c1lvl - 2);
                    }
                    ModReduceInternalInPlace(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
                    ciphertext1->SetScalingFactorInt(ciphertext2->GetScalingFactorInt());
                }
            }
        }
        else {
            if (c2depth == 2) {
                NativeInteger scf1    = ciphertext1->GetScalingFactorInt();
                NativeInteger scf2    = ciphertext2->GetScalingFactorInt();
                NativeInteger scf1Inv = scf1.ModInverse(t);

                EvalMultCoreInPlace(ciphertext1, scf2.ModMul(scf1Inv, t).ConvertToInt());
                LevelReduceInternalInPlace(ciphertext1, c2lvl - c1lvl);
                ciphertext1->SetScalingFactorInt(scf2);
            }
            else {
                NativeInteger scf1    = ciphertext1->GetScalingFactorInt();
                NativeInteger scf2    = cryptoParams->GetScalingFactorIntBig(c2lvl - 1);
                NativeInteger scf1Inv = scf1.ModInverse(t);

                EvalMultCoreInPlace(ciphertext1, scf2.ModMul(scf1Inv, t).ConvertToInt());
                if (c1lvl + 1 < c2lvl) {
                    LevelReduceInternalInPlace(ciphertext1, c2lvl - c1lvl - 1);
                }
                ModReduceInternalInPlace(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
                ciphertext1->SetScalingFactorInt(ciphertext2->GetScalingFactorInt());
            }
        }
    }
    else if (c1lvl > c2lvl) {
        if (c2depth == 2) {
            if (c1depth == 2) {
                NativeInteger scf2    = ciphertext2->GetScalingFactorInt();
                NativeInteger scf1    = ciphertext1->GetScalingFactorInt();
                NativeInteger ql2Modt = cryptoParams->GetModReduceFactorInt(sizeQl2 - 1);
                NativeInteger scf2Inv = scf2.ModInverse(t);

                EvalMultCoreInPlace(ciphertext2, scf1.ModMul(scf2Inv, t).ModMul(ql2Modt, t).ConvertToInt());
                ModReduceInternalInPlace(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
                if (c2lvl + 1 < c1lvl) {
                    LevelReduceInternalInPlace(ciphertext2, c1lvl - c2lvl - 1);
                }
                ciphertext2->SetScalingFactorInt(ciphertext1->GetScalingFactorInt());
            }
            else {
                if (c2lvl + 1 == c1lvl) {
                    ModReduceInternalInPlace(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
                }
                else {
                    NativeInteger scf2    = ciphertext2->GetScalingFactorInt();
                    NativeInteger scf1    = cryptoParams->GetScalingFactorIntBig(c1lvl - 1);
                    NativeInteger ql2Modt = cryptoParams->GetModReduceFactorInt(sizeQl2 - 1);
                    NativeInteger scf2Inv = scf2.ModInverse(t);

                    EvalMultCoreInPlace(ciphertext2, scf1.ModMul(scf2Inv, t).ModMul(ql2Modt, t).ConvertToInt());
                    ModReduceInternalInPlace(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
                    if (c2lvl + 2 < c1lvl) {
                        LevelReduceInternalInPlace(ciphertext2, c1lvl - c2lvl - 2);
                    }
                    ModReduceInternalInPlace(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
                    ciphertext2->SetScalingFactorInt(ciphertext1->GetScalingFactorInt());
                }
            }
        }
        else {
            if (c1depth == 2) {
                NativeInteger scf2    = ciphertext2->GetScalingFactorInt();
                NativeInteger scf1    = ciphertext1->GetScalingFactorInt();
                NativeInteger scf2Inv = scf2.ModInverse(t);

                EvalMultCoreInPlace(ciphertext2, scf1.ModMul(scf2Inv, t).ConvertToInt());
                LevelReduceInternalInPlace(ciphertext2, c1lvl - c2lvl);
                ciphertext2->SetScalingFactorInt(scf1);
            }
            else {
                NativeInteger scf2    = ciphertext2->GetScalingFactorInt();
                NativeInteger scf1    = cryptoParams->GetScalingFactorIntBig(c1lvl - 1);
                NativeInteger scf2Inv = scf2.ModInverse(t);

                EvalMultCoreInPlace(ciphertext2, scf1.ModMul(scf2Inv, t).ConvertToInt());
                if (c2lvl + 1 < c1lvl) {
                    LevelReduceInternalInPlace(ciphertext2, c1lvl - c2lvl - 1);
                }
                ModReduceInternalInPlace(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
                ciphertext2->SetScalingFactorInt(ciphertext1->GetScalingFactorInt());
            }
        }
    }
    else {
        if (c1depth < c2depth) {
            NativeInteger scf = ciphertext1->GetScalingFactorInt();
            EvalMultCoreInPlace(ciphertext1, scf.ConvertToInt());
        }
        else if (c2depth < c1depth) {
            NativeInteger scf = ciphertext2->GetScalingFactorInt();
            EvalMultCoreInPlace(ciphertext2, scf.ConvertToInt());
        }
    }
}

void LeveledSHEBGVRNS::AdjustLevelsAndDepthToOneInPlace(Ciphertext<DCRTPoly>& ciphertext1,
                                                        Ciphertext<DCRTPoly>& ciphertext2) const {
    AdjustLevelsAndDepthInPlace(ciphertext1, ciphertext2);

    if (ciphertext1->GetNoiseScaleDeg() == 2) {
        ModReduceInternalInPlace(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
        ModReduceInternalInPlace(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
    }
}

void LeveledSHEBGVRNS::EvalMultCoreInPlace(Ciphertext<DCRTPoly>& ciphertext, const NativeInteger& constant) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBGVRNS>(ciphertext->GetCryptoParameters());

    std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    for (usint i = 0; i < cv.size(); ++i) {
        cv[i] *= constant;
    }
    const NativeInteger t(cryptoParams->GetPlaintextModulus());

    ciphertext->SetNoiseScaleDeg(ciphertext->GetNoiseScaleDeg() + 1);
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT) {
        ciphertext->SetScalingFactorInt(ciphertext->GetScalingFactorInt().ModMul(constant, t));
    }
}

usint LeveledSHEBGVRNS::FindAutomorphismIndex(usint index, usint m) const {
    return FindAutomorphismIndex2n(index, m);
}

}  // namespace lbcrypto
