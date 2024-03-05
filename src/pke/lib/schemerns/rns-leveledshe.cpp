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

Ciphertext<DCRTPoly> LeveledSHERNS::EvalAdd(ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const {
    Ciphertext<DCRTPoly> result = ciphertext->Clone();
    EvalAddInPlace(result, plaintext);
    return result;
}

void LeveledSHERNS::EvalAddInPlace(Ciphertext<DCRTPoly>& ciphertext, ConstPlaintext plaintext) const {
    auto ctmorphed = MorphPlaintext(plaintext, ciphertext);
    AdjustForAddOrSubInPlace(ciphertext, ctmorphed);
    EvalAddCoreInPlace(ciphertext, ctmorphed->GetElements()[0]);
}

Ciphertext<DCRTPoly> LeveledSHERNS::EvalAddMutable(Ciphertext<DCRTPoly>& ciphertext, Plaintext plaintext) const {
    auto ctmorphed = MorphPlaintext(plaintext, ciphertext);
    AdjustForAddOrSubInPlace(ciphertext, ctmorphed);
    return EvalAddCore(ciphertext, ctmorphed->GetElements()[0]);
}

void LeveledSHERNS::EvalAddMutableInPlace(Ciphertext<DCRTPoly>& ciphertext, Plaintext plaintext) const {
    auto ctmorphed = MorphPlaintext(plaintext, ciphertext);
    AdjustForAddOrSubInPlace(ciphertext, ctmorphed);
    EvalAddCoreInPlace(ciphertext, ctmorphed->GetElements()[0]);
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

Ciphertext<DCRTPoly> LeveledSHERNS::EvalSub(ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const {
    Ciphertext<DCRTPoly> result = ciphertext->Clone();
    EvalSubInPlace(result, plaintext);
    return result;
}

void LeveledSHERNS::EvalSubInPlace(Ciphertext<DCRTPoly>& ciphertext, ConstPlaintext plaintext) const {
    auto ctmorphed = MorphPlaintext(plaintext, ciphertext);
    AdjustForAddOrSubInPlace(ciphertext, ctmorphed);
    EvalSubCoreInPlace(ciphertext, ctmorphed->GetElements()[0]);
}

Ciphertext<DCRTPoly> LeveledSHERNS::EvalSubMutable(Ciphertext<DCRTPoly>& ciphertext, Plaintext plaintext) const {
    auto ctmorphed = MorphPlaintext(plaintext, ciphertext);
    AdjustForAddOrSubInPlace(ciphertext, ctmorphed);
    return EvalSubCore(ciphertext, ctmorphed->GetElements()[0]);
}

void LeveledSHERNS::EvalSubMutableInPlace(Ciphertext<DCRTPoly>& ciphertext, Plaintext plaintext) const {
    auto ctmorphed = MorphPlaintext(plaintext, ciphertext);
    AdjustForAddOrSubInPlace(ciphertext, ctmorphed);
    EvalSubCoreInPlace(ciphertext, ctmorphed->GetElements()[0]);
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

Ciphertext<DCRTPoly> LeveledSHERNS::EvalSquare(ConstCiphertext<DCRTPoly> ciphertext) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE || cryptoParams->GetScalingTechnique() == FIXEDMANUAL ||
        ciphertext->GetNoiseScaleDeg() == 1) {
        return EvalSquareCore(ciphertext);
    }

    auto c = ciphertext->Clone();
    ModReduceInternalInPlace(c, BASE_NUM_LEVELS_TO_DROP);

    return EvalSquareCore(c);
}

Ciphertext<DCRTPoly> LeveledSHERNS::EvalSquareMutable(Ciphertext<DCRTPoly>& ciphertext) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() != NORESCALE && cryptoParams->GetScalingTechnique() != FIXEDMANUAL &&
        ciphertext->GetNoiseScaleDeg() == 2) {
        ModReduceInternalInPlace(ciphertext, BASE_NUM_LEVELS_TO_DROP);
    }

    return EvalSquareCore(ciphertext);
}

Ciphertext<DCRTPoly> LeveledSHERNS::EvalMult(ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const {
    Ciphertext<DCRTPoly> result = ciphertext->Clone();
    EvalMultInPlace(result, plaintext);
    return result;
}

void LeveledSHERNS::EvalMultInPlace(Ciphertext<DCRTPoly>& ciphertext, ConstPlaintext plaintext) const {
    auto ctmorphed = MorphPlaintext(plaintext, ciphertext);
    AdjustForMultInPlace(ciphertext, ctmorphed);
    EvalMultCoreInPlace(ciphertext, ctmorphed->GetElements()[0]);

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());
    ciphertext->SetNoiseScaleDeg(ciphertext->GetNoiseScaleDeg() + ctmorphed->GetNoiseScaleDeg());
    // TODO (Andrey) : This part is only used in CKKS scheme
    ciphertext->SetScalingFactor(ciphertext->GetScalingFactor() * ctmorphed->GetScalingFactor());
    // TODO (Andrey) : This part is only used in BGV scheme
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT) {
        const auto plainMod = ciphertext->GetCryptoParameters()->GetPlaintextModulus();
        ciphertext->SetScalingFactorInt(
            ciphertext->GetScalingFactorInt().ModMul(ctmorphed->GetScalingFactorInt(), plainMod));
    }
}

Ciphertext<DCRTPoly> LeveledSHERNS::EvalMultMutable(Ciphertext<DCRTPoly>& ciphertext, Plaintext plaintext) const {
    auto ctmorphed = MorphPlaintext(plaintext, ciphertext);
    AdjustForMultInPlace(ciphertext, ctmorphed);
    auto result = EvalMultCore(ciphertext, ctmorphed->GetElements()[0]);

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());
    result->SetNoiseScaleDeg(ciphertext->GetNoiseScaleDeg() + ctmorphed->GetNoiseScaleDeg());
    // TODO (Andrey) : This part is only used in CKKS scheme
    result->SetScalingFactor(ciphertext->GetScalingFactor() * ctmorphed->GetScalingFactor());
    // TODO (Andrey) : This part is only used in BGV scheme
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT) {
        const auto plainMod = ciphertext->GetCryptoParameters()->GetPlaintextModulus();
        result->SetScalingFactorInt(
            ciphertext->GetScalingFactorInt().ModMul(ctmorphed->GetScalingFactorInt(), plainMod));
    }

    return result;
}

// TODO (Andrey) : currently do same as EvalMultInPlace, as Plaintext element is immutable
void LeveledSHERNS::EvalMultMutableInPlace(Ciphertext<DCRTPoly>& ciphertext, Plaintext plaintext) const {
    auto ctmorphed = MorphPlaintext(plaintext, ciphertext);
    AdjustForMultInPlace(ciphertext, ctmorphed);
    EvalMultCoreInPlace(ciphertext, ctmorphed->GetElements()[0]);

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());
    ciphertext->SetNoiseScaleDeg(ciphertext->GetNoiseScaleDeg() + ctmorphed->GetNoiseScaleDeg());
    // TODO (Andrey) : This part is only used in CKKS scheme
    ciphertext->SetScalingFactor(ciphertext->GetScalingFactor() * ctmorphed->GetScalingFactor());
    // TODO (Andrey) : This part is only used in BGV scheme
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT) {
        const auto plainMod = ciphertext->GetCryptoParameters()->GetPlaintextModulus();
        ciphertext->SetScalingFactorInt(
            ciphertext->GetScalingFactorInt().ModMul(ctmorphed->GetScalingFactorInt(), plainMod));
    }
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

    for (usint i = 0; i < ciphertext->NumberCiphertextElements(); i++) {
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

// TODO (Andrey) : remove evalKey as unused
Ciphertext<DCRTPoly> LeveledSHERNS::LevelReduce(ConstCiphertext<DCRTPoly> ciphertext, const EvalKey<DCRTPoly> evalKey,
                                                size_t levels) const {
    Ciphertext<DCRTPoly> result = ciphertext->Clone();
    LevelReduceInPlace(result, evalKey, levels);
    return result;
}

// TODO (Andrey) : remove evalKey as unused
void LeveledSHERNS::LevelReduceInPlace(Ciphertext<DCRTPoly>& ciphertext, const EvalKey<DCRTPoly> evalKey,
                                       size_t levels) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE) {
        OPENFHE_THROW("LevelReduceInPlace is not implemented for NORESCALE rescaling technique");
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

    while (result->GetNoiseScaleDeg() > 1) {
        ModReduceInternalInPlace(result, BASE_NUM_LEVELS_TO_DROP);
    }
    const std::vector<DCRTPoly>& cv = result->GetElements();
    usint sizeQl                    = cv[0].GetNumOfElements();

    if (towersLeft < sizeQl) {
        LevelReduceInternalInPlace(result, sizeQl - towersLeft);
    }

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
        usint sizeQl       = 0;
        uint32_t ptxtIndex = 0;

        // Get moduli chain to create CRT representation of powP
        std::vector<DCRTPoly::Integer> moduli;

        if (ciphertext1->NumberCiphertextElements() == 1) {
            ptxt      = ciphertext1->GetElements()[0];
            ptxtDepth = ciphertext1->GetNoiseScaleDeg();
            ctxtDepth = ciphertext2->GetNoiseScaleDeg();
            sizeQl    = ciphertext2->GetElements()[0].GetNumOfElements();
            moduli.resize(sizeQl);
            for (usint i = 0; i < sizeQl; i++) {
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
            for (usint i = 0; i < sizeQl; i++) {
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
            for (usint j = 0; j < diffDepth - 1; j++) {
                crtPowSF = CKKSPackedEncoding::CRTMult(crtPowSF, crtSF, moduli);
            }

            ptxt = ptxt.Times(crtPowSF);

            if (ptxtIndex == 1) {
                ciphertext1->SetElements({ptxt});
                ciphertext1->SetNoiseScaleDeg(ctxtDepth);
            }
            else {
                ciphertext2->SetElements({ptxt});
                ciphertext2->SetNoiseScaleDeg(ctxtDepth);
            }
        }
        else if (ptxtDepth > ctxtDepth) {
            OPENFHE_THROW(
                "LPAlgorithmSHERNS<DCRTPoly>::AdjustForAddOrSubInPlace "
                "- plaintext cannot be encoded at a larger depth than that "
                "of the ciphertext.");
        }
    }
    else if (cryptoParams->GetScalingTechnique() != NORESCALE) {
        AdjustLevelsAndDepthInPlace(ciphertext1, ciphertext2);
    }
}

void LeveledSHERNS::AdjustForMultInPlace(Ciphertext<DCRTPoly>& ciphertext1, Ciphertext<DCRTPoly>& ciphertext2) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext1->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
        AdjustLevelsInPlace(ciphertext1, ciphertext2);
    }
    else if (cryptoParams->GetScalingTechnique() != NORESCALE) {
        AdjustLevelsAndDepthToOneInPlace(ciphertext1, ciphertext2);
    }
}

}  // namespace lbcrypto
