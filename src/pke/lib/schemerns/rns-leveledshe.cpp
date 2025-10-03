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

#include <memory>
#include <vector>

namespace lbcrypto {

/////////////////////////////////////////
// SHE ADDITION
/////////////////////////////////////////

Ciphertext<DCRTPoly> LeveledSHERNS::EvalAdd(ConstCiphertext<DCRTPoly>& ciphertext1,
                                            ConstCiphertext<DCRTPoly>& ciphertext2) const {
    auto result = ciphertext1->Clone();
    EvalAddInPlace(result, ciphertext2);
    return result;
}

void LeveledSHERNS::EvalAddInPlace(Ciphertext<DCRTPoly>& ciphertext1, ConstCiphertext<DCRTPoly>& ciphertext2) const {
    auto st = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext1->GetCryptoParameters())->GetScalingTechnique();
    if (st == NORESCALE) {
        EvalAddCoreInPlace(ciphertext1, ciphertext2);
    }
    else {
        auto c2 = ciphertext2->Clone();
        AdjustForAddOrSubInPlace(ciphertext1, c2);
        EvalAddCoreInPlace(ciphertext1, c2);
    }
}

Ciphertext<DCRTPoly> LeveledSHERNS::EvalAddMutable(Ciphertext<DCRTPoly>& ciphertext1,
                                                   Ciphertext<DCRTPoly>& ciphertext2) const {
    AdjustForAddOrSubInPlace(ciphertext1, ciphertext2);
    return EvalAddCore(ciphertext1, ciphertext2);
}

void LeveledSHERNS::EvalAddMutableInPlace(Ciphertext<DCRTPoly>& ciphertext1, Ciphertext<DCRTPoly>& ciphertext2) const {
    AdjustForAddOrSubInPlace(ciphertext1, ciphertext2);
    EvalAddCoreInPlace(ciphertext1, ciphertext2);
}

/////////////////////////////////////////
// SHE ADDITION PLAINTEXT
/////////////////////////////////////////

Ciphertext<DCRTPoly> LeveledSHERNS::EvalAdd(ConstCiphertext<DCRTPoly>& ciphertext, ConstPlaintext& plaintext) const {
    auto result = ciphertext->Clone();
    EvalAddInPlace(result, plaintext);
    return result;
}

void LeveledSHERNS::EvalAddInPlace(Ciphertext<DCRTPoly>& ciphertext, ConstPlaintext& plaintext) const {
    auto st = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters())->GetScalingTechnique();
    if (st == NORESCALE) {
        EvalAddCoreInPlace(ciphertext, plaintext->GetElement<DCRTPoly>());
    }
    else {
        auto ctmorphed = MorphPlaintext(plaintext, ciphertext);
        AdjustForAddOrSubInPlace(ciphertext, ctmorphed);
        EvalAddCoreInPlace(ciphertext, ctmorphed->GetElements()[0]);
    }
}

Ciphertext<DCRTPoly> LeveledSHERNS::EvalAddMutable(Ciphertext<DCRTPoly>& ciphertext, Plaintext& plaintext) const {
    auto ctmorphed = MorphPlaintext(plaintext, ciphertext);
    AdjustForAddOrSubInPlace(ciphertext, ctmorphed);
    return EvalAddCore(ciphertext, ctmorphed->GetElements()[0]);
}

void LeveledSHERNS::EvalAddMutableInPlace(Ciphertext<DCRTPoly>& ciphertext, Plaintext& plaintext) const {
    auto ctmorphed = MorphPlaintext(plaintext, ciphertext);
    AdjustForAddOrSubInPlace(ciphertext, ctmorphed);
    EvalAddCoreInPlace(ciphertext, ctmorphed->GetElements()[0]);
}

/////////////////////////////////////////
// SHE SUBTRACTION
/////////////////////////////////////////

Ciphertext<DCRTPoly> LeveledSHERNS::EvalSub(ConstCiphertext<DCRTPoly>& ciphertext1,
                                            ConstCiphertext<DCRTPoly>& ciphertext2) const {
    auto result = ciphertext1->Clone();
    EvalSubInPlace(result, ciphertext2);
    return result;
}

void LeveledSHERNS::EvalSubInPlace(Ciphertext<DCRTPoly>& ciphertext1, ConstCiphertext<DCRTPoly>& ciphertext2) const {
    auto st = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext1->GetCryptoParameters())->GetScalingTechnique();
    if (st == NORESCALE) {
        EvalSubCoreInPlace(ciphertext1, ciphertext2);
    }
    else {
        auto c2 = ciphertext2->Clone();
        AdjustForAddOrSubInPlace(ciphertext1, c2);
        EvalSubCoreInPlace(ciphertext1, c2);
    }
}

Ciphertext<DCRTPoly> LeveledSHERNS::EvalSubMutable(Ciphertext<DCRTPoly>& ciphertext1,
                                                   Ciphertext<DCRTPoly>& ciphertext2) const {
    AdjustForAddOrSubInPlace(ciphertext1, ciphertext2);
    return EvalSubCore(ciphertext1, ciphertext2);
}

void LeveledSHERNS::EvalSubMutableInPlace(Ciphertext<DCRTPoly>& ciphertext1, Ciphertext<DCRTPoly>& ciphertext2) const {
    AdjustForAddOrSubInPlace(ciphertext1, ciphertext2);
    EvalSubCoreInPlace(ciphertext1, ciphertext2);
}

/////////////////////////////////////////
// SHE SUBTRACTION PLAINTEXT
/////////////////////////////////////////

Ciphertext<DCRTPoly> LeveledSHERNS::EvalSub(ConstCiphertext<DCRTPoly>& ciphertext, ConstPlaintext& plaintext) const {
    auto result = ciphertext->Clone();
    EvalSubInPlace(result, plaintext);
    return result;
}

void LeveledSHERNS::EvalSubInPlace(Ciphertext<DCRTPoly>& ciphertext, ConstPlaintext& plaintext) const {
    auto st = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters())->GetScalingTechnique();
    if (st == NORESCALE) {
        EvalAddCoreInPlace(ciphertext, plaintext->GetElement<DCRTPoly>());
    }
    else {
        auto ctmorphed = MorphPlaintext(plaintext, ciphertext);
        AdjustForAddOrSubInPlace(ciphertext, ctmorphed);
        EvalSubCoreInPlace(ciphertext, ctmorphed->GetElements()[0]);
    }
}

Ciphertext<DCRTPoly> LeveledSHERNS::EvalSubMutable(Ciphertext<DCRTPoly>& ciphertext, Plaintext& plaintext) const {
    auto ctmorphed = MorphPlaintext(plaintext, ciphertext);
    AdjustForAddOrSubInPlace(ciphertext, ctmorphed);
    return EvalSubCore(ciphertext, ctmorphed->GetElements()[0]);
}

void LeveledSHERNS::EvalSubMutableInPlace(Ciphertext<DCRTPoly>& ciphertext, Plaintext& plaintext) const {
    auto ctmorphed = MorphPlaintext(plaintext, ciphertext);
    AdjustForAddOrSubInPlace(ciphertext, ctmorphed);
    EvalSubCoreInPlace(ciphertext, ctmorphed->GetElements()[0]);
}

/////////////////////////////////////////
// SHE MULTIPLICATION
/////////////////////////////////////////

Ciphertext<DCRTPoly> LeveledSHERNS::EvalMult(ConstCiphertext<DCRTPoly>& ciphertext1,
                                             ConstCiphertext<DCRTPoly>& ciphertext2) const {
    auto st = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext1->GetCryptoParameters())->GetScalingTechnique();
    if (st == NORESCALE)
        return EvalMultCore(ciphertext1, ciphertext2);

    auto c1 = ciphertext1->Clone();
    auto c2 = ciphertext2->Clone();
    AdjustForMultInPlace(c1, c2);
    return EvalMultCore(c1, c2);
}

Ciphertext<DCRTPoly> LeveledSHERNS::EvalMultMutable(Ciphertext<DCRTPoly>& ciphertext1,
                                                    Ciphertext<DCRTPoly>& ciphertext2) const {
    AdjustForMultInPlace(ciphertext1, ciphertext2);
    return EvalMultCore(ciphertext1, ciphertext2);
}

Ciphertext<DCRTPoly> LeveledSHERNS::EvalSquare(ConstCiphertext<DCRTPoly>& ciphertext) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    auto st = cryptoParams->GetScalingTechnique();
    if (st == NORESCALE || st == FIXEDMANUAL || ciphertext->GetNoiseScaleDeg() == 1)
        return EvalSquareCore(ciphertext);

    size_t lvls = (st == COMPOSITESCALINGAUTO || st == COMPOSITESCALINGMANUAL) ? cryptoParams->GetCompositeDegree() :
                                                                                 BASE_NUM_LEVELS_TO_DROP;
    return EvalSquareCore(ModReduceInternal(ciphertext, lvls));
}

Ciphertext<DCRTPoly> LeveledSHERNS::EvalSquareMutable(Ciphertext<DCRTPoly>& ciphertext) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    auto st = cryptoParams->GetScalingTechnique();
    if (st != NORESCALE && st != FIXEDMANUAL && ciphertext->GetNoiseScaleDeg() == 2) {
        size_t lvls = (st == COMPOSITESCALINGAUTO || st == COMPOSITESCALINGMANUAL) ?
                          cryptoParams->GetCompositeDegree() :
                          BASE_NUM_LEVELS_TO_DROP;
        ModReduceInternalInPlace(ciphertext, lvls);
    }

    return EvalSquareCore(ciphertext);
}

Ciphertext<DCRTPoly> LeveledSHERNS::EvalMult(ConstCiphertext<DCRTPoly>& ciphertext, ConstPlaintext& plaintext) const {
    auto result = ciphertext->Clone();
    EvalMultInPlace(result, plaintext);
    return result;
}

void LeveledSHERNS::EvalMultInPlace(Ciphertext<DCRTPoly>& ciphertext, ConstPlaintext& plaintext) const {
    auto st = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters())->GetScalingTechnique();
    if (st == NORESCALE) {
        EvalMultCoreInPlace(ciphertext, plaintext->GetElement<DCRTPoly>());
    }
    else {
        auto ctmorphed = MorphPlaintext(plaintext, ciphertext);
        AdjustForMultInPlace(ciphertext, ctmorphed);
        EvalMultCoreInPlace(ciphertext, ctmorphed->GetElements()[0]);
        ciphertext->SetNoiseScaleDeg(ciphertext->GetNoiseScaleDeg() + ctmorphed->GetNoiseScaleDeg());
    }
}

Ciphertext<DCRTPoly> LeveledSHERNS::EvalMultMutable(Ciphertext<DCRTPoly>& ciphertext, Plaintext& plaintext) const {
    auto ctmorphed = MorphPlaintext(plaintext, ciphertext);
    AdjustForMultInPlace(ciphertext, ctmorphed);
    auto result = EvalMultCore(ciphertext, ctmorphed->GetElements()[0]);

    result->SetNoiseScaleDeg(ciphertext->GetNoiseScaleDeg() + ctmorphed->GetNoiseScaleDeg());
    // TODO (Andrey) : This part is only used in CKKS scheme
    result->SetScalingFactor(ciphertext->GetScalingFactor() * ctmorphed->GetScalingFactor());
    // TODO (Andrey) : This part is only used in BGV scheme
    auto st = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters())->GetScalingTechnique();
    if (st == FLEXIBLEAUTO || st == FLEXIBLEAUTOEXT)
        result->SetScalingFactorInt(ciphertext->GetScalingFactorInt().ModMul(
            ctmorphed->GetScalingFactorInt(), ciphertext->GetCryptoParameters()->GetPlaintextModulus()));
    return result;
}

// TODO (Andrey) : currently do same as EvalMultInPlace, as Plaintext element is immutable
void LeveledSHERNS::EvalMultMutableInPlace(Ciphertext<DCRTPoly>& ciphertext, Plaintext& plaintext) const {
    auto ctmorphed = MorphPlaintext(plaintext, ciphertext);
    AdjustForMultInPlace(ciphertext, ctmorphed);
    EvalMultCoreInPlace(ciphertext, ctmorphed->GetElements()[0]);

    ciphertext->SetNoiseScaleDeg(ciphertext->GetNoiseScaleDeg() + ctmorphed->GetNoiseScaleDeg());
    // TODO (Andrey) : This part is only used in CKKS scheme
    ciphertext->SetScalingFactor(ciphertext->GetScalingFactor() * ctmorphed->GetScalingFactor());
    // TODO (Andrey) : This part is only used in BGV scheme
    auto st = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters())->GetScalingTechnique();
    if (st == FLEXIBLEAUTO || st == FLEXIBLEAUTOEXT)
        ciphertext->SetScalingFactorInt(ciphertext->GetScalingFactorInt().ModMul(
            ctmorphed->GetScalingFactorInt(), ciphertext->GetCryptoParameters()->GetPlaintextModulus()));
}

Ciphertext<DCRTPoly> LeveledSHERNS::MultByMonomial(ConstCiphertext<DCRTPoly>& ciphertext, uint32_t power) const {
    auto result = ciphertext->Clone();
    MultByMonomialInPlace(result, power);
    return result;
}

void LeveledSHERNS::MultByMonomialInPlace(Ciphertext<DCRTPoly>& ciphertext, uint32_t power) const {
    auto& cv          = ciphertext->GetElements();
    auto elemParams   = cv[0].GetParams();
    auto paramsNative = elemParams->GetParams()[0];
    uint32_t N        = elemParams->GetRingDimension();
    uint32_t M        = 2 * N;

    NativePoly monomial(paramsNative, Format::COEFFICIENT, true);

    uint32_t powerReduced = power % M;
    monomial[power % N]   = powerReduced < N ? NativeInteger(1) : paramsNative->GetModulus() - NativeInteger(1);

    DCRTPoly monomialDCRT(elemParams, Format::COEFFICIENT, true);
    monomialDCRT = monomial;
    monomialDCRT.SetFormat(Format::EVALUATION);

    for (uint32_t i = 0; i < ciphertext->NumberCiphertextElements(); ++i)
        cv[i] *= monomialDCRT;
}

/////////////////////////////////////////
// SHE AUTOMORPHISM
/////////////////////////////////////////

/////////////////////////////////////
// SHE LEVELED Mod Reduce
/////////////////////////////////////

Ciphertext<DCRTPoly> LeveledSHERNS::ModReduce(ConstCiphertext<DCRTPoly>& ciphertext, size_t levels) const {
    auto result = ciphertext->Clone();
    ModReduceInPlace(result, levels);
    return result;
}

void LeveledSHERNS::ModReduceInPlace(Ciphertext<DCRTPoly>& ciphertext, size_t levels) const {
    auto st = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters())->GetScalingTechnique();
    if (st == FIXEDMANUAL)
        ModReduceInternalInPlace(ciphertext, levels);
}

/////////////////////////////////////
// SHE LEVELED Level Reduce
/////////////////////////////////////

// TODO (Andrey) : remove evalKey as unused
Ciphertext<DCRTPoly> LeveledSHERNS::LevelReduce(ConstCiphertext<DCRTPoly>& ciphertext, const EvalKey<DCRTPoly> evalKey,
                                                size_t levels) const {
    auto result = ciphertext->Clone();
    LevelReduceInPlace(result, evalKey, levels);
    return result;
}

// TODO (Andrey) : remove evalKey as unused
void LeveledSHERNS::LevelReduceInPlace(Ciphertext<DCRTPoly>& ciphertext, const EvalKey<DCRTPoly> evalKey,
                                       size_t levels) const {
    auto st = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters())->GetScalingTechnique();
    if (st == NORESCALE)
        OPENFHE_THROW("LevelReduceInPlace is not implemented for NORESCALE rescaling technique");
    if (st == FIXEDMANUAL && levels > 0)
        LevelReduceInternalInPlace(ciphertext, levels);
}

/////////////////////////////////////////
// SHE LEVELED Compress
/////////////////////////////////////////

/*
 * On COMPOSITESCALING technique, the number of towers to drop passed
 * must be a multiple of composite degree.
 */
Ciphertext<DCRTPoly> LeveledSHERNS::Compress(ConstCiphertext<DCRTPoly>& ciphertext, size_t towersLeft,
                                             size_t noiseScaleDeg) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    uint32_t levelsToDrop = BASE_NUM_LEVELS_TO_DROP;
    if (cryptoParams->GetScalingTechnique() == COMPOSITESCALINGAUTO ||
        cryptoParams->GetScalingTechnique() == COMPOSITESCALINGMANUAL) {
        uint32_t compositeDegree = cryptoParams->GetCompositeDegree();
        levelsToDrop             = compositeDegree;
        if (towersLeft % compositeDegree != 0)
            OPENFHE_THROW("Number of towers to drop must be a multiple of composite degree.");
    }

    auto result = std::make_shared<CiphertextImpl<DCRTPoly>>(*ciphertext);
    while (result->GetNoiseScaleDeg() > noiseScaleDeg)
        ModReduceInternalInPlace(result, levelsToDrop);

    size_t sizeQl = result->GetElements()[0].GetNumOfElements();
    if (towersLeft < sizeQl)
        LevelReduceInternalInPlace(result, sizeQl - towersLeft);

    return result;
}

/////////////////////////////////////////
// SHE CORE OPERATION
/////////////////////////////////////////

Ciphertext<DCRTPoly> LeveledSHERNS::ModReduceInternal(ConstCiphertext<DCRTPoly>& ciphertext, size_t levels) const {
    auto result = ciphertext->Clone();
    ModReduceInternalInPlace(result, levels);
    return result;
}

Ciphertext<DCRTPoly> LeveledSHERNS::LevelReduceInternal(ConstCiphertext<DCRTPoly>& ciphertext, size_t levels) const {
    auto result = ciphertext->Clone();
    LevelReduceInternalInPlace(result, levels);
    return result;
}

void LeveledSHERNS::AdjustLevelsInPlace(Ciphertext<DCRTPoly>& ciphertext1, Ciphertext<DCRTPoly>& ciphertext2) const {
    auto sizeQl1 = ciphertext1->GetElements()[0].GetNumOfElements();
    auto sizeQl2 = ciphertext2->GetElements()[0].GetNumOfElements();
    if (sizeQl1 < sizeQl2)
        LevelReduceInternalInPlace(ciphertext2, sizeQl2 - sizeQl1);
    if (sizeQl1 > sizeQl2)
        LevelReduceInternalInPlace(ciphertext1, sizeQl1 - sizeQl2);
}

void LeveledSHERNS::AdjustForAddOrSubInPlace(Ciphertext<DCRTPoly>& ciphertext1,
                                             Ciphertext<DCRTPoly>& ciphertext2) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext1->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
        AdjustLevelsInPlace(ciphertext1, ciphertext2);

        double scFactor = cryptoParams->GetScalingFactorReal();

        // supported only for CKKS
        if (scFactor == 0.0)
            return;

        DCRTPoly ptxt;
        uint32_t ptxtDepth = 0;
        uint32_t ctxtDepth = 0;
        uint32_t sizeQl    = 0;
        uint32_t ptxtIndex = 0;

        // Get moduli chain to create CRT representation of powP
        std::vector<DCRTPoly::Integer> moduli;

        if (ciphertext1->NumberCiphertextElements() == 1) {
            ptxt      = ciphertext1->GetElements()[0];
            ptxtDepth = ciphertext1->GetNoiseScaleDeg();
            ctxtDepth = ciphertext2->GetNoiseScaleDeg();
            sizeQl    = ciphertext2->GetElements()[0].GetNumOfElements();
            moduli.resize(sizeQl);
            for (uint32_t i = 0; i < sizeQl; i++) {
                moduli[i] = ciphertext2->GetElements()[0].GetElementAtIndex(i).GetModulus();
            }
            ptxtIndex = 1;
        }
        else if (ciphertext2->NumberCiphertextElements() == 1) {
            ptxt      = ciphertext2->GetElements()[0];
            ptxtDepth = ciphertext2->GetNoiseScaleDeg();
            ctxtDepth = ciphertext1->GetNoiseScaleDeg();
            sizeQl    = ciphertext1->GetElements()[0].GetNumOfElements();
            moduli.resize(sizeQl);
            for (uint32_t i = 0; i < sizeQl; i++) {
                moduli[i] = ciphertext1->GetElements()[0].GetElementAtIndex(i).GetModulus();
            }
            ptxtIndex = 2;
        }
        else
            return;

        // Bring to same depth if not already same
        if (ptxtDepth < ctxtDepth) {
            // Find out how many levels to scale plaintext up.
            size_t diffDepth = ctxtDepth - ptxtDepth;

            DCRTPoly::Integer intSF = static_cast<NativeInteger::Integer>(scFactor + 0.5);
            std::vector<DCRTPoly::Integer> crtSF(sizeQl, intSF);
            auto crtPowSF = crtSF;
            for (uint32_t j = 0; j < diffDepth - 1; j++) {
                crtPowSF = CKKSPackedEncoding::CRTMult(crtPowSF, crtSF, moduli);
            }

            if (ptxtIndex == 1) {
                ciphertext1->SetElements(std::vector<DCRTPoly>{ptxt.Times(crtPowSF)});
                ciphertext1->SetNoiseScaleDeg(ctxtDepth);
            }
            else {
                ciphertext2->SetElements(std::vector<DCRTPoly>{ptxt.Times(crtPowSF)});
                ciphertext2->SetNoiseScaleDeg(ctxtDepth);
            }
        }
        else if (ptxtDepth > ctxtDepth) {
            OPENFHE_THROW("plaintext cannot be encoded at a larger depth than that of the ciphertext.");
        }
    }
    else if (cryptoParams->GetScalingTechnique() != NORESCALE) {
        AdjustLevelsAndDepthInPlace(ciphertext1, ciphertext2);
    }
}

void LeveledSHERNS::AdjustForMultInPlace(Ciphertext<DCRTPoly>& ciphertext1, Ciphertext<DCRTPoly>& ciphertext2) const {
    auto st = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext1->GetCryptoParameters())->GetScalingTechnique();
    if (st == FIXEDMANUAL)
        AdjustLevelsInPlace(ciphertext1, ciphertext2);
    else if (st != NORESCALE)
        AdjustLevelsAndDepthToOneInPlace(ciphertext1, ciphertext2);
}

Ciphertext<DCRTPoly> LeveledSHERNS::ComposedEvalMult(ConstCiphertext<DCRTPoly>& ciphertext1,
                                                     ConstCiphertext<DCRTPoly>& ciphertext2,
                                                     const EvalKey<DCRTPoly> evalKey) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext1->GetCryptoParameters());

    auto st     = cryptoParams->GetScalingTechnique();
    size_t lvls = (st == COMPOSITESCALINGAUTO || st == COMPOSITESCALINGMANUAL) ? cryptoParams->GetCompositeDegree() :
                                                                                 BASE_NUM_LEVELS_TO_DROP;

    auto ciphertext = EvalMult(ciphertext1, ciphertext2);
    ciphertext->GetCryptoContext()->GetScheme()->KeySwitchInPlace(ciphertext, evalKey);
    ModReduceInPlace(ciphertext, lvls);
    return ciphertext;
}

}  // namespace lbcrypto
