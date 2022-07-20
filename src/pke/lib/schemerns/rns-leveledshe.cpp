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

#define PROFILE

#include "cryptocontext.h"
#include "schemerns/rns-leveledshe.h"

namespace lbcrypto {

/////////////////////////////////////////
// SHE ADDITION
/////////////////////////////////////////

Ciphertext<DCRTPoly> LeveledSHERNS::EvalAdd(ConstCiphertext<DCRTPoly> ciphertext1,
                                            ConstCiphertext<DCRTPoly> ciphertext2) const {
    Ciphertext<DCRTPoly> result = ciphertext1->Clone();
    EvalAddInPlace(result, ciphertext2);
    return result;
}

void LeveledSHERNS::EvalAddInPlace(Ciphertext<DCRTPoly>& ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext1->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE) {
        EvalAddCoreInPlace(ciphertext1, ciphertext2);
        return;
    }

    Ciphertext<DCRTPoly> c2 = ciphertext2->Clone();

    if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
        AdjustLevelsInPlace(ciphertext1, c2);
    }
    else {
        AdjustLevelsAndDepthInPlace(ciphertext1, c2);
    }

    EvalAddCoreInPlace(ciphertext1, c2);
}

Ciphertext<DCRTPoly> LeveledSHERNS::EvalAddMutable(Ciphertext<DCRTPoly>& ciphertext1,
                                                   Ciphertext<DCRTPoly>& ciphertext2) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext1->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE) {
        return EvalAddCore(ciphertext1, ciphertext2);
    }

    if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
        Ciphertext<DCRTPoly> c1 = ciphertext1->Clone();
        Ciphertext<DCRTPoly> c2 = ciphertext2->Clone();
        AdjustLevelsInPlace(c1, c2);
        return EvalAddCore(c1, c2);
    }

    AdjustLevelsAndDepthInPlace(ciphertext1, ciphertext2);
    return EvalAddCore(ciphertext1, ciphertext2);
}

void LeveledSHERNS::EvalAddMutableInPlace(Ciphertext<DCRTPoly>& ciphertext1, Ciphertext<DCRTPoly>& ciphertext2) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext1->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE) {
        EvalAddCoreInPlace(ciphertext1, ciphertext2);
        return;
    }

    if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
        Ciphertext<DCRTPoly> c2 = ciphertext2->Clone();
        AdjustLevelsInPlace(ciphertext1, c2);
        EvalAddCoreInPlace(ciphertext1, c2);
        return;
    }

    AdjustLevelsAndDepthInPlace(ciphertext1, ciphertext2);
    EvalAddCoreInPlace(ciphertext1, ciphertext2);
}

/////////////////////////////////////////
// SHE ADDITION PLAINTEXT
/////////////////////////////////////////

Ciphertext<DCRTPoly> LeveledSHERNS::EvalAdd(ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const {
    Ciphertext<DCRTPoly> result = ciphertext->Clone();
    EvalAddInPlace(result, plaintext);
    return result;
}

void LeveledSHERNS::EvalAddInPlace(Ciphertext<DCRTPoly>& ciphertext, ConstPlaintext plaintext) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE) {
        DCRTPoly pt = plaintext->GetElement<DCRTPoly>();
        pt.SetFormat(EVALUATION);
        EvalAddCoreInPlace(ciphertext, pt);
        return;
    }

    DCRTPoly pt = cryptoParams->GetScalingTechnique() == FIXEDMANUAL ?
                      AdjustLevelsInPlace(ciphertext, plaintext) :
                      AdjustLevelsAndDepthInPlace(ciphertext, plaintext);

    EvalAddCoreInPlace(ciphertext, pt);
}

Ciphertext<DCRTPoly> LeveledSHERNS::EvalAddMutable(Ciphertext<DCRTPoly>& ciphertext, Plaintext plaintext) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE) {
        DCRTPoly pt = plaintext->GetElement<DCRTPoly>();
        pt.SetFormat(EVALUATION);
        return EvalAddCore(ciphertext, pt);
    }

    DCRTPoly pt = cryptoParams->GetScalingTechnique() == FIXEDMANUAL ?
                      AdjustLevelsInPlace(ciphertext, plaintext) :
                      AdjustLevelsAndDepthInPlace(ciphertext, plaintext);

    return EvalAddCore(ciphertext, pt);
}

void LeveledSHERNS::EvalAddMutableInPlace(Ciphertext<DCRTPoly>& ciphertext, Plaintext plaintext) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE) {
        DCRTPoly pt = plaintext->GetElement<DCRTPoly>();
        pt.SetFormat(EVALUATION);
        EvalAddCoreInPlace(ciphertext, pt);
        return;
    }

    DCRTPoly pt = cryptoParams->GetScalingTechnique() == FIXEDMANUAL ?
                      AdjustLevelsInPlace(ciphertext, plaintext) :
                      AdjustLevelsAndDepthInPlace(ciphertext, plaintext);

    EvalAddCoreInPlace(ciphertext, pt);
}

/////////////////////////////////////////
// SHE SUBTRACTION
/////////////////////////////////////////

Ciphertext<DCRTPoly> LeveledSHERNS::EvalSub(ConstCiphertext<DCRTPoly> ciphertext1,
                                            ConstCiphertext<DCRTPoly> ciphertext2) const {
    Ciphertext<DCRTPoly> result = ciphertext1->Clone();
    EvalSubInPlace(result, ciphertext2);
    return result;
}

void LeveledSHERNS::EvalSubInPlace(Ciphertext<DCRTPoly>& ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext1->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE) {
        EvalSubCoreInPlace(ciphertext1, ciphertext2);
        return;
    }

    Ciphertext<DCRTPoly> c2 = ciphertext2->Clone();

    if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
        AdjustLevelsInPlace(ciphertext1, c2);
    }
    else {
        AdjustLevelsAndDepthInPlace(ciphertext1, c2);
    }

    EvalSubCoreInPlace(ciphertext1, c2);
}

Ciphertext<DCRTPoly> LeveledSHERNS::EvalSubMutable(Ciphertext<DCRTPoly>& ciphertext1,
                                                   Ciphertext<DCRTPoly>& ciphertext2) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext1->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE) {
        return EvalSubCore(ciphertext1, ciphertext2);
    }

    if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
        Ciphertext<DCRTPoly> c1 = ciphertext1->Clone();
        Ciphertext<DCRTPoly> c2 = ciphertext2->Clone();
        AdjustLevelsInPlace(c1, c2);
        return EvalSubCore(c1, c2);
    }

    AdjustLevelsAndDepthInPlace(ciphertext1, ciphertext2);
    return EvalSubCore(ciphertext1, ciphertext2);
}

void LeveledSHERNS::EvalSubMutableInPlace(Ciphertext<DCRTPoly>& ciphertext1, Ciphertext<DCRTPoly>& ciphertext2) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext1->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE) {
        EvalSubCoreInPlace(ciphertext1, ciphertext2);
        return;
    }

    if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
        Ciphertext<DCRTPoly> c2 = ciphertext2->Clone();
        AdjustLevelsInPlace(ciphertext1, c2);
        EvalSubCoreInPlace(ciphertext1, c2);
        return;
    }

    AdjustLevelsAndDepthInPlace(ciphertext1, ciphertext2);
    EvalSubCoreInPlace(ciphertext1, ciphertext2);
}

/////////////////////////////////////////
// SHE SUBTRACTION PLAINTEXT
/////////////////////////////////////////

Ciphertext<DCRTPoly> LeveledSHERNS::EvalSub(ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const {
    Ciphertext<DCRTPoly> result = ciphertext->Clone();
    EvalSubInPlace(result, plaintext);
    return result;
}

void LeveledSHERNS::EvalSubInPlace(Ciphertext<DCRTPoly>& ciphertext, ConstPlaintext plaintext) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE) {
        DCRTPoly pt = plaintext->GetElement<DCRTPoly>();
        pt.SetFormat(EVALUATION);
        EvalSubCoreInPlace(ciphertext, pt);
        return;
    }

    DCRTPoly pt = cryptoParams->GetScalingTechnique() == FIXEDMANUAL ?
                      AdjustLevelsInPlace(ciphertext, plaintext) :
                      AdjustLevelsAndDepthInPlace(ciphertext, plaintext);

    EvalSubCoreInPlace(ciphertext, pt);
}

Ciphertext<DCRTPoly> LeveledSHERNS::EvalSubMutable(Ciphertext<DCRTPoly>& ciphertext, Plaintext plaintext) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE) {
        DCRTPoly pt = plaintext->GetElement<DCRTPoly>();
        pt.SetFormat(EVALUATION);
        return EvalSubCore(ciphertext, pt);
    }

    if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
        Ciphertext<DCRTPoly> c = ciphertext->Clone();
        DCRTPoly pt            = AdjustLevelsInPlace(c, plaintext);
        return EvalSubCore(c, pt);
    }

    DCRTPoly pt = AdjustLevelsAndDepthInPlace(ciphertext, plaintext);
    return EvalSubCore(ciphertext, pt);
}

void LeveledSHERNS::EvalSubMutableInPlace(Ciphertext<DCRTPoly>& ciphertext, Plaintext plaintext) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE) {
        DCRTPoly pt = plaintext->GetElement<DCRTPoly>();
        pt.SetFormat(EVALUATION);
        EvalSubCoreInPlace(ciphertext, pt);
        return;
    }

    if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
        DCRTPoly pt = AdjustLevelsInPlace(ciphertext, plaintext);
        EvalSubCoreInPlace(ciphertext, pt);
        return;
    }

    DCRTPoly pt = AdjustLevelsAndDepthInPlace(ciphertext, plaintext);
    EvalSubCoreInPlace(ciphertext, pt);
}

/////////////////////////////////////////
// SHE MULTIPLICATION
/////////////////////////////////////////

Ciphertext<DCRTPoly> LeveledSHERNS::EvalMult(ConstCiphertext<DCRTPoly> ciphertext1,
                                             ConstCiphertext<DCRTPoly> ciphertext2) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext1->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE) {
        return EvalMultCore(ciphertext1, ciphertext2);
    }

    Ciphertext<DCRTPoly> c1 = ciphertext1->Clone();
    Ciphertext<DCRTPoly> c2 = ciphertext2->Clone();

    if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
        AdjustLevelsInPlace(c1, c2);
    }
    else {
        AdjustLevelsAndDepthToOneInPlace(c1, c2);
    }

    return EvalMultCore(c1, c2);
}

Ciphertext<DCRTPoly> LeveledSHERNS::EvalMultMutable(Ciphertext<DCRTPoly>& ciphertext1,
                                                    Ciphertext<DCRTPoly>& ciphertext2) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext1->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE) {
        return EvalMultCore(ciphertext1, ciphertext2);
    }

    if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
        Ciphertext<DCRTPoly> c1 = ciphertext1->Clone();
        Ciphertext<DCRTPoly> c2 = ciphertext2->Clone();
        AdjustLevelsInPlace(c1, c2);
        return EvalMultCore(c1, c2);
    }

    AdjustLevelsAndDepthToOneInPlace(ciphertext1, ciphertext2);
    return EvalMultCore(ciphertext1, ciphertext2);
}

Ciphertext<DCRTPoly> LeveledSHERNS::EvalSquare(ConstCiphertext<DCRTPoly> ciphertext) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE) {
        return EvalSquareCore(ciphertext);
    }

    Ciphertext<DCRTPoly> c = ciphertext->Clone();

    if ((cryptoParams->GetScalingTechnique() != FIXEDMANUAL) && (c->GetDepth() == 2)) {
        ModReduceInternalInPlace(c, 1);
    }

    return EvalSquareCore(c);
}

Ciphertext<DCRTPoly> LeveledSHERNS::EvalSquareMutable(Ciphertext<DCRTPoly>& ciphertext) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE) {
        return EvalSquareCore(ciphertext);
    }

    if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
        Ciphertext<DCRTPoly> c = ciphertext->Clone();
        return EvalSquareCore(c);
    }
    if (ciphertext->GetDepth() == 2) {
        ModReduceInternalInPlace(ciphertext, 1);
    }
    return EvalSquareCore(ciphertext);
}

Ciphertext<DCRTPoly> LeveledSHERNS::EvalMult(ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const {
    Ciphertext<DCRTPoly> result = ciphertext->Clone();
    EvalMultInPlace(result, plaintext);
    return result;
}

void LeveledSHERNS::EvalMultInPlace(Ciphertext<DCRTPoly>& ciphertext, ConstPlaintext plaintext) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE) {
        DCRTPoly pt = plaintext->GetElement<DCRTPoly>();
        pt.SetFormat(EVALUATION);
        EvalMultCoreInPlace(ciphertext, pt);
        return;
    }

    if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
        DCRTPoly pt = AdjustLevelsInPlace(ciphertext, plaintext);
        EvalMultCoreInPlace(ciphertext, pt);
        ciphertext->SetDepth(ciphertext->GetDepth() + plaintext->GetDepth());
        ciphertext->SetScalingFactor(ciphertext->GetScalingFactor() * plaintext->GetScalingFactor());
        return;
    }

    DCRTPoly pt = AdjustLevelsAndDepthToOneInPlace(ciphertext, plaintext);
    EvalMultCoreInPlace(ciphertext, pt);
    ciphertext->SetDepth(ciphertext->GetDepth() + 1);
    ciphertext->SetScalingFactor(ciphertext->GetScalingFactor() * ciphertext->GetScalingFactor());
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT) {
        const auto plainMod = ciphertext->GetCryptoParameters()->GetPlaintextModulus();
        ciphertext->SetScalingFactorInt(
            ciphertext->GetScalingFactorInt().ModMul(ciphertext->GetScalingFactorInt(), plainMod));
    }
    return;
}

Ciphertext<DCRTPoly> LeveledSHERNS::EvalMultMutable(Ciphertext<DCRTPoly>& ciphertext, Plaintext plaintext) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE) {
        DCRTPoly pt = plaintext->GetElement<DCRTPoly>();
        pt.SetFormat(EVALUATION);
        return EvalMultCore(ciphertext, pt);
    }

    if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
        Ciphertext<DCRTPoly> c = ciphertext->Clone();
        DCRTPoly pt            = AdjustLevelsInPlace(c, plaintext);
        auto result            = EvalMultCore(c, pt);
        result->SetScalingFactor(c->GetScalingFactor() * plaintext->GetScalingFactor());
        result->SetDepth(c->GetDepth() + plaintext->GetDepth());
        return result;
    }

    DCRTPoly pt = AdjustLevelsAndDepthToOneInPlace(ciphertext, plaintext);

    auto result = EvalMultCore(ciphertext, pt);
    result->SetDepth(ciphertext->GetDepth() + 1);
    result->SetScalingFactor(ciphertext->GetScalingFactor() *
                             cryptoParams->GetScalingFactorReal(ciphertext->GetLevel()));
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT) {
        const auto plainMod = ciphertext->GetCryptoParameters()->GetPlaintextModulus();
        result->SetScalingFactorInt(ciphertext->GetScalingFactorInt().ModMul(
            cryptoParams->GetScalingFactorInt(ciphertext->GetLevel()), plainMod));
    }
    return result;
}

void LeveledSHERNS::EvalMultMutableInPlace(Ciphertext<DCRTPoly>& ciphertext, Plaintext plaintext) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE) {
        DCRTPoly pt = plaintext->GetElement<DCRTPoly>();
        pt.SetFormat(EVALUATION);
        EvalMultCoreInPlace(ciphertext, pt);
        return;
    }

    if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
        DCRTPoly pt = AdjustLevelsInPlace(ciphertext, plaintext);
        EvalMultCoreInPlace(ciphertext, pt);
        ciphertext->SetDepth(ciphertext->GetDepth() + plaintext->GetDepth());
        ciphertext->SetScalingFactor(ciphertext->GetScalingFactor() * plaintext->GetScalingFactor());
        return;
    }

    DCRTPoly pt = AdjustLevelsAndDepthToOneInPlace(ciphertext, plaintext);
    EvalMultCoreInPlace(ciphertext, pt);
    ciphertext->SetDepth(ciphertext->GetDepth() + 1);
    ciphertext->SetScalingFactor(ciphertext->GetScalingFactor() *
                                 cryptoParams->GetScalingFactorReal(ciphertext->GetLevel()));
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT) {
        const auto plainMod = ciphertext->GetCryptoParameters()->GetPlaintextModulus();
        ciphertext->SetScalingFactorInt(ciphertext->GetScalingFactorInt().ModMul(
            cryptoParams->GetScalingFactorInt(ciphertext->GetLevel()), plainMod));
    }
    return;
}

Ciphertext<DCRTPoly> LeveledSHERNS::MultByMonomial(ConstCiphertext<DCRTPoly> ciphertext, usint power) const {
    Ciphertext<DCRTPoly> result = ciphertext->Clone();
    MultByMonomialInPlace(result, power);
    return result;
}

void LeveledSHERNS::MultByMonomialInPlace(Ciphertext<DCRTPoly>& ciphertext, usint power) const {
    std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    const auto elemParams     = cv[0].GetParams();
    auto paramsNative         = elemParams->GetParams()[0];
    usint N                   = elemParams->GetRingDimension();
    usint M                   = 2 * N;

    NativePoly monomial(paramsNative, Format::COEFFICIENT, true);

    usint powerReduced = power % M;
    usint index        = power % N;
    monomial[index]    = powerReduced < N ? NativeInteger(1) : paramsNative->GetModulus() - NativeInteger(1);

    DCRTPoly monomialDCRT(elemParams, Format::COEFFICIENT, true);
    monomialDCRT = monomial;
    monomialDCRT.SetFormat(Format::EVALUATION);

    for (usint i = 0; i < ciphertext->GetElements().size(); i++) {
        cv[i] *= monomialDCRT;
    }
}

/////////////////////////////////////////
// SHE AUTOMORPHISM
/////////////////////////////////////////

/////////////////////////////////////
// SHE LEVELED Mod Reduce
/////////////////////////////////////

Ciphertext<DCRTPoly> LeveledSHERNS::ModReduce(ConstCiphertext<DCRTPoly> ciphertext, size_t levels) const {
    Ciphertext<DCRTPoly> result = ciphertext->Clone();
    ModReduceInPlace(result, levels);
    return result;
}

void LeveledSHERNS::ModReduceInPlace(Ciphertext<DCRTPoly>& ciphertext, size_t levels) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
        ModReduceInternalInPlace(ciphertext, levels);
    }
}

/////////////////////////////////////
// SHE LEVELED Level Reduce
/////////////////////////////////////

Ciphertext<DCRTPoly> LeveledSHERNS::LevelReduce(ConstCiphertext<DCRTPoly> ciphertext, const EvalKey<DCRTPoly> evalKey,
                                                size_t levels) const {
    Ciphertext<DCRTPoly> result = ciphertext->Clone();
    LevelReduceInPlace(result, evalKey, levels);
    return result;
}

void LeveledSHERNS::LevelReduceInPlace(Ciphertext<DCRTPoly>& ciphertext, const EvalKey<DCRTPoly> evalKey,
                                       size_t levels) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE) {
        OPENFHE_THROW(not_implemented_error, "LevelReduce is not implemented for NORESCALE rescaling technique");
    }

    if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL && levels > 0) {
        LevelReduceInternalInPlace(ciphertext, levels);
    }
}

/////////////////////////////////////////
// SHE LEVELED Compress
/////////////////////////////////////////

Ciphertext<DCRTPoly> LeveledSHERNS::Compress(ConstCiphertext<DCRTPoly> ciphertext, size_t towersLeft) const {
    Ciphertext<DCRTPoly> result = std::make_shared<CiphertextImpl<DCRTPoly>>(*ciphertext);

    while (result->GetDepth() > 1) {
        ModReduceInternalInPlace(result, BASE_NUM_LEVELS_TO_DROP);
    }
    const std::vector<DCRTPoly>& cv = result->GetElements();
    usint sizeQl                    = cv[0].GetNumOfElements();

    if (towersLeft >= sizeQl) {
        return result;
    }

    //  if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO) {
    //    const std::shared_ptr<ParmType> paramsQ = cryptoParams->GetElementParams();
    //    usint sizeQ = paramsQ->GetParams().size();
    //    AdjustLevelWithRescaleInPlace(result, sizeQ - towersLeft);
    //    return result;
    //  }

    LevelReduceInternalInPlace(result, sizeQl - towersLeft);
    return result;
}

/////////////////////////////////////////
// SHE CORE OPERATION
/////////////////////////////////////////

Ciphertext<DCRTPoly> LeveledSHERNS::ModReduceInternal(ConstCiphertext<DCRTPoly> ciphertext, size_t levels) const {
    auto result = ciphertext->Clone();
    ModReduceInternalInPlace(result, levels);
    return result;
}

Ciphertext<DCRTPoly> LeveledSHERNS::LevelReduceInternal(ConstCiphertext<DCRTPoly> ciphertext, size_t levels) const {
    auto result = ciphertext->Clone();
    LevelReduceInternalInPlace(result, levels);
    return result;
}

void LeveledSHERNS::AdjustLevelsInPlace(Ciphertext<DCRTPoly>& ciphertext1, Ciphertext<DCRTPoly>& ciphertext2) const {
    auto sizeQl1 = ciphertext1->GetElements()[0].GetNumOfElements();
    auto sizeQl2 = ciphertext2->GetElements()[0].GetNumOfElements();

    if (sizeQl1 < sizeQl2) {
        LevelReduceInternalInPlace(ciphertext2, sizeQl2 - sizeQl1);
    }
    else if (sizeQl1 > sizeQl2) {
        LevelReduceInternalInPlace(ciphertext1, sizeQl1 - sizeQl2);
    }
}

DCRTPoly LeveledSHERNS::AdjustLevelsInPlace(Ciphertext<DCRTPoly>& ciphertext, ConstPlaintext plaintext) const {
    auto sizeQlc = ciphertext->GetElements()[0].GetNumOfElements();
    DCRTPoly pt  = plaintext->GetElement<DCRTPoly>();
    auto sizeQlp = pt.GetNumOfElements();

    if (sizeQlc < sizeQlp) {
        pt.DropLastElements(sizeQlp - sizeQlc);
    }
    else if (sizeQlc > sizeQlp) {
        LevelReduceInternalInPlace(ciphertext, sizeQlc - sizeQlp);
    }
    pt.SetFormat(Format::EVALUATION);
    return pt;
}

}  // namespace lbcrypto
