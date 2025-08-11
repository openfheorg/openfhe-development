//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2025, NJIT, Duality Technologies Inc. and other contributors
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
CKKS implementation. See https://eprint.iacr.org/2020/1118 for details.
 */

#include "cryptocontext.h"
#include "math/hal/basicint.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "scheme/ckksrns/ckksrns-leveledshe.h"
#include "schemebase/base-scheme.h"

#include <algorithm>
#include <map>
#include <memory>
#include <utility>
#include <vector>

namespace lbcrypto {

/////////////////////////////////////////
// SHE ADDITION CONSTANT
/////////////////////////////////////////

Ciphertext<DCRTPoly> LeveledSHECKKSRNS::EvalAdd(ConstCiphertext<DCRTPoly>& ciphertext, double operand) const {
    auto result = ciphertext->Clone();
    EvalAddInPlace(result, operand);
    return result;
}

void LeveledSHECKKSRNS::EvalAddInPlace(Ciphertext<DCRTPoly>& ciphertext, double operand) const {
    auto& cv = ciphertext->GetElements();
    cv[0]    = cv[0] + GetElementForEvalAddOrSub(ciphertext, operand);
}

Ciphertext<DCRTPoly> LeveledSHECKKSRNS::EvalAdd(ConstCiphertext<DCRTPoly>& ciphertext,
                                                std::complex<double> operand) const {
    auto result = ciphertext->Clone();
    EvalAddInPlace(result, operand);
    return result;
}

void LeveledSHECKKSRNS::EvalAddInPlace(Ciphertext<DCRTPoly>& ciphertext, std::complex<double> operand) const {
    auto& cv       = ciphertext->GetElements();
    auto elemsRe   = GetElementForEvalAddOrSub(ciphertext, std::fabs(operand.real()));
    auto elemsIm   = GetElementForEvalAddOrSub(ciphertext, std::fabs(operand.imag()));
    uint32_t N     = cv[0].GetLength();
    uint32_t Nhalf = N >> 1;
    auto posreal   = operand.real() > 0.;
    auto posimag   = operand.imag() > 0.;

    DCRTPoly elemsComplex(cv[0].GetParams(), Format::COEFFICIENT, true);
    uint32_t sizeQl = elemsComplex.GetNumOfElements();
    for (uint32_t i = 0; i < sizeQl; ++i) {
        auto element = cv[0].GetElementAtIndex(i);
        auto modulus = element.GetModulus();
        NativeVector vec(N, modulus.ConvertToInt<BasicInteger>());
        vec[0]     = posreal ? NativeInteger(elemsRe[i].Mod(modulus)) : modulus.ModSub(elemsRe[i], modulus);
        vec[Nhalf] = posimag ? NativeInteger(elemsIm[i].Mod(modulus)) : modulus.ModSub(elemsIm[i], modulus);
        element.SetValues(std::move(vec), Format::COEFFICIENT);
        elemsComplex.SetElementAtIndex(i, std::move(element));
    }
    elemsComplex.SetFormat(Format::EVALUATION);

    cv[0] += elemsComplex;
}

/////////////////////////////////////////
// SHE SUBTRACTION CONSTANT
/////////////////////////////////////////

Ciphertext<DCRTPoly> LeveledSHECKKSRNS::EvalSub(ConstCiphertext<DCRTPoly>& ciphertext, double operand) const {
    auto result = ciphertext->Clone();
    EvalSubInPlace(result, operand);
    return result;
}

void LeveledSHECKKSRNS::EvalSubInPlace(Ciphertext<DCRTPoly>& ciphertext, double operand) const {
    auto& cv = ciphertext->GetElements();
    cv[0]    = cv[0] - GetElementForEvalAddOrSub(ciphertext, operand);
}

/////////////////////////////////////////
// SHE MULTIPLICATION
/////////////////////////////////////////

Ciphertext<DCRTPoly> LeveledSHECKKSRNS::EvalMult(ConstCiphertext<DCRTPoly>& ciphertext, double operand) const {
    auto result = ciphertext->Clone();
    EvalMultInPlace(result, operand);
    return result;
}

void LeveledSHECKKSRNS::EvalMultInPlace(Ciphertext<DCRTPoly>& ciphertext, double operand) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());
    if (cryptoParams->GetScalingTechnique() != FIXEDMANUAL) {
        if (ciphertext->GetNoiseScaleDeg() == 2)
            ModReduceInternalInPlace(ciphertext, cryptoParams->GetCompositeDegree());
    }
    EvalMultCoreInPlace(ciphertext, operand);
}

Ciphertext<DCRTPoly> LeveledSHECKKSRNS::EvalMult(ConstCiphertext<DCRTPoly>& ciphertext,
                                                 std::complex<double> operand) const {
    Ciphertext<DCRTPoly> result = ciphertext->Clone();
    EvalMultInPlace(result, operand);
    return result;
}

void LeveledSHECKKSRNS::EvalMultInPlace(Ciphertext<DCRTPoly>& ciphertext, std::complex<double> operand) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());
    if (cryptoParams->GetScalingTechnique() != FIXEDMANUAL) {
        if (ciphertext->GetNoiseScaleDeg() == 2)
            ModReduceInternalInPlace(ciphertext, cryptoParams->GetCompositeDegree());
    }
    EvalMultCoreInPlace(ciphertext, operand);
}

void LeveledSHECKKSRNS::EvalMultInPlace(Ciphertext<DCRTPoly>& ciphertext, ConstPlaintext& plaintext) const {
    LeveledSHERNS::EvalMultInPlace(ciphertext, plaintext);
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());
    if (cryptoParams->GetScalingTechnique() != NORESCALE)
        ciphertext->SetScalingFactor(ciphertext->GetScalingFactor() * ciphertext->GetScalingFactor());
}

/////////////////////////////////////////
// SHE MULTIPLICATION PLAINTEXT
/////////////////////////////////////////

/////////////////////////////////////
// Mod Reduce
/////////////////////////////////////

void LeveledSHECKKSRNS::ModReduceInternalInPlace(Ciphertext<DCRTPoly>& ciphertext, size_t levels) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    auto& cv = ciphertext->GetElements();

    size_t sizeQ  = cryptoParams->GetElementParams()->GetParams().size();
    size_t sizeQl = cv[0].GetNumOfElements();
    size_t diffQl = sizeQ - sizeQl;

    for (size_t l = 0; l < levels; ++l) {
        for (size_t i = 0; i < cv.size(); ++i) {
            cv[i].DropLastElementAndScale(cryptoParams->GetQlQlInvModqlDivqlModq(diffQl + l),
                                          cryptoParams->GetqlInvModq(diffQl + l));
        }
    }

    ciphertext->SetNoiseScaleDeg(ciphertext->GetNoiseScaleDeg() - levels / cryptoParams->GetCompositeDegree());
    ciphertext->SetLevel(ciphertext->GetLevel() + levels);

    for (size_t i = 0; i < levels; ++i) {
        double modReduceFactor = cryptoParams->GetModReduceFactor(sizeQl - 1 - i);
        ciphertext->SetScalingFactor(ciphertext->GetScalingFactor() / modReduceFactor);
    }
}

/////////////////////////////////////
// Level Reduce
/////////////////////////////////////

void LeveledSHECKKSRNS::LevelReduceInternalInPlace(Ciphertext<DCRTPoly>& ciphertext, size_t levels) const {
    for (auto& element : ciphertext->GetElements())
        element.DropLastElements(levels);
    ciphertext->SetLevel(ciphertext->GetLevel() + levels);
}

/////////////////////////////////////
// Compress
/////////////////////////////////////

/////////////////////////////////////
// CKKS Core
/////////////////////////////////////

#if NATIVEINT == 128
std::vector<DCRTPoly::Integer> LeveledSHECKKSRNS::GetElementForEvalAddOrSub(ConstCiphertext<DCRTPoly>& ciphertext,
                                                                            double operand) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    uint32_t precision = 52;
    double powP        = std::pow(2, precision);

    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    uint32_t numTowers              = cv[0].GetNumOfElements();
    std::vector<DCRTPoly::Integer> moduli(numTowers);

    for (uint32_t i = 0; i < numTowers; i++) {
        moduli[i] = cv[0].GetElementAtIndex(i).GetModulus();
    }

    // the idea is to break down real numbers
    // expressed as input_mantissa * 2^input_exponent
    // into (input_mantissa * 2^52) * 2^(p - 52 + input_exponent)
    // to preserve 52-bit precision of doubles
    // when converting to 128-bit numbers
    int32_t n1       = 0;
    int64_t scaled64 = std::llround(static_cast<double>(std::frexp(operand, &n1)) * powP);

    int32_t pCurrent   = cryptoParams->GetPlaintextModulus() - precision;
    int32_t pRemaining = pCurrent + n1;

    DCRTPoly::Integer scaledConstant;
    if (pRemaining < 0) {
        scaledConstant = NativeInteger(((uint128_t)scaled64) >> (-pRemaining));
    }
    else {
        int128_t ppRemaining = ((int128_t)1) << pRemaining;
        scaledConstant       = NativeInteger((int128_t)scaled64 * ppRemaining);
    }

    DCRTPoly::Integer intPowP;
    uint64_t powp64 = (static_cast<uint64_t>(1)) << precision;
    if (pCurrent < 0) {
        intPowP = NativeInteger((uint128_t)powp64 >> (-pCurrent));
    }
    else {
        intPowP = NativeInteger((uint128_t)powp64 << pCurrent);
    }

    std::vector<DCRTPoly::Integer> crtPowP(numTowers, intPowP);
    std::vector<DCRTPoly::Integer> currPowP(numTowers, scaledConstant);

    // multiply c*powP with powP a total of (depth-1) times to get c*powP^d
    for (size_t i = 0; i < ciphertext->GetNoiseScaleDeg() - 1; i++) {
        currPowP = CKKSPackedEncoding::CRTMult(currPowP, crtPowP, moduli);
    }

    return currPowP;
}
#else  // NATIVEINT == 64
std::vector<DCRTPoly::Integer> LeveledSHECKKSRNS::GetElementForEvalAddOrSub(ConstCiphertext<DCRTPoly>& ciphertext,
                                                                            double operand) const {
    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    uint32_t sizeQl                 = cv[0].GetNumOfElements();
    std::vector<DCRTPoly::Integer> moduli(sizeQl);
    for (uint32_t i = 0; i < sizeQl; i++) {
        moduli[i] = cv[0].GetElementAtIndex(i).GetModulus();
    }

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    double scFactor = 0;
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT && ciphertext->GetLevel() == 0) {
        scFactor = cryptoParams->GetScalingFactorRealBig(ciphertext->GetLevel());
    }
    else {
        scFactor = cryptoParams->GetScalingFactorReal(ciphertext->GetLevel());
    }

    // Compute approxFactor, a value to scale down by, in case the value exceeds a 64-bit integer.

    // the logic below was added as the code crashes when linked with clang++ in the Debug mode and
    // with the following flags and res is ZERO:
    // -O2
    // -g
    // -fsanitize-trap=all
    // -fsanitize=alignment,return,returns-nonnull-attribute,vla-bound,unreachable,float-cast-overflow
    // -fsanitize=null
    // -gz=zlib
    // -fno-asynchronous-unwind-tables
    // -fno-optimize-sibling-calls
    // -fsplit-dwarf-inlining
    // -gsimple-template-names
    // -gsplit-dwarf
    int32_t logApprox = 0;
    // Duhyeong: We need to take account the 64-bit overflow for both operand * scFactor and scFactor
    double res = std::fabs(operand * scFactor);
    if (cryptoParams->GetScalingTechnique() == COMPOSITESCALINGAUTO ||
        cryptoParams->GetScalingTechnique() == COMPOSITESCALINGMANUAL) {
        res = std::max(res, std::fabs(scFactor));
    }
    if (res > 0) {
        int32_t logSF    = static_cast<int32_t>(std::ceil(std::log2(res)));
        int32_t logValid = (logSF <= LargeScalingFactorConstants::MAX_BITS_IN_WORD) ?
                               logSF :
                               LargeScalingFactorConstants::MAX_BITS_IN_WORD;
        logApprox        = logSF - logValid;
    }
    int32_t logApprox_cp = logApprox;
    double approxFactor  = pow(2, logApprox);

    DCRTPoly::Integer scConstant = static_cast<uint64_t>(operand * scFactor / approxFactor + 0.5);
    std::vector<DCRTPoly::Integer> crtConstant(sizeQl, scConstant);

    // Scale back up by approxFactor within the CRT multiplications.
    if (logApprox > 0) {
        int32_t logStep = (logApprox <= LargeScalingFactorConstants::MAX_LOG_STEP) ?
                              logApprox :
                              LargeScalingFactorConstants::MAX_LOG_STEP;
        auto intStep    = static_cast<DCRTPoly::Integer>(1) << logStep;
        std::vector<DCRTPoly::Integer> crtApprox(sizeQl, intStep);
        logApprox -= logStep;

        while (logApprox > 0) {
            int32_t logStep = (logApprox <= LargeScalingFactorConstants::MAX_LOG_STEP) ?
                                  logApprox :
                                  LargeScalingFactorConstants::MAX_LOG_STEP;
            auto intStep    = static_cast<DCRTPoly::Integer>(1) << logStep;
            std::vector<DCRTPoly::Integer> crtSF(sizeQl, intStep);
            crtApprox = CKKSPackedEncoding::CRTMult(crtApprox, crtSF, moduli);
            logApprox -= logStep;
        }
        crtConstant = CKKSPackedEncoding::CRTMult(crtConstant, crtApprox, moduli);
    }

    // In FLEXIBLEAUTOEXT mode at level 0, we don't use the depth to calculate the scaling factor,
    // so we return the value before taking the depth into account.
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT && ciphertext->GetLevel() == 0) {
        return crtConstant;
    }

    // COMPOSITESCALING support to 128-bit scaling factor
    if (cryptoParams->GetScalingTechnique() == COMPOSITESCALINGAUTO ||
        cryptoParams->GetScalingTechnique() == COMPOSITESCALINGMANUAL) {
        int32_t logSF_cp = static_cast<int32_t>(std::ceil(std::log2(res)));
        if (logSF_cp < 64) {
            DCRTPoly::Integer intScFactor = static_cast<uint64_t>(scFactor + 0.5);
            std::vector<DCRTPoly::Integer> crtScFactor(sizeQl, intScFactor);
            for (uint32_t i = 1; i < ciphertext->GetNoiseScaleDeg(); i++) {
                crtConstant = CKKSPackedEncoding::CRTMult(crtConstant, crtScFactor, moduli);
            }
        }
        else {
            // Multiply scFactor in two steps: scFactor / approxFactor and then approxFactor
            DCRTPoly::Integer intScFactor = static_cast<uint64_t>(scFactor / approxFactor + 0.5);
            std::vector<DCRTPoly::Integer> crtScFactor(sizeQl, intScFactor);
            for (uint32_t i = 1; i < ciphertext->GetNoiseScaleDeg(); i++) {
                crtConstant = CKKSPackedEncoding::CRTMult(crtConstant, crtScFactor, moduli);
            }
            if (logApprox_cp > 0) {
                int32_t logStep           = (logApprox_cp <= LargeScalingFactorConstants::MAX_LOG_STEP) ?
                                                logApprox_cp :
                                                LargeScalingFactorConstants::MAX_LOG_STEP;
                DCRTPoly::Integer intStep = static_cast<uint64_t>(1) << logStep;
                std::vector<DCRTPoly::Integer> crtApprox(sizeQl, intStep);
                logApprox_cp -= logStep;

                while (logApprox_cp > 0) {
                    int32_t logStep           = (logApprox_cp <= LargeScalingFactorConstants::MAX_LOG_STEP) ?
                                                    logApprox_cp :
                                                    LargeScalingFactorConstants::MAX_LOG_STEP;
                    DCRTPoly::Integer intStep = static_cast<uint64_t>(1) << logStep;
                    std::vector<DCRTPoly::Integer> crtSF(sizeQl, intStep);
                    crtApprox = CKKSPackedEncoding::CRTMult(crtApprox, crtSF, moduli);
                    logApprox_cp -= logStep;
                }
                for (uint32_t i = 1; i < ciphertext->GetNoiseScaleDeg(); i++) {
                    crtConstant = CKKSPackedEncoding::CRTMult(crtConstant, crtApprox, moduli);
                }
            }
        }
    }
    else {
        DCRTPoly::Integer intScFactor = static_cast<uint64_t>(scFactor + 0.5);
        std::vector<DCRTPoly::Integer> crtScFactor(sizeQl, intScFactor);

        for (uint32_t i = 1; i < ciphertext->GetNoiseScaleDeg(); i++) {
            crtConstant = CKKSPackedEncoding::CRTMult(crtConstant, crtScFactor, moduli);
        }
    }

    return crtConstant;
}
#endif

#if NATIVEINT == 128
std::vector<DCRTPoly::Integer> LeveledSHECKKSRNS::GetElementForEvalMult(ConstCiphertext<DCRTPoly>& ciphertext,
                                                                        double operand) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    uint32_t precision = 52;
    double powP        = std::pow(2, precision);

    // the idea is to break down real numbers
    // expressed as input_mantissa * 2^input_exponent
    // into (input_mantissa * 2^52) * 2^(p - 52 + input_exponent)
    // to preserve 52-bit precision of doubles
    // when converting to 128-bit numbers
    int32_t n1         = 0;
    int64_t scaled64   = std::llround(static_cast<double>(std::frexp(operand, &n1)) * powP);
    int32_t pCurrent   = cryptoParams->GetPlaintextModulus() - precision;
    int32_t pRemaining = pCurrent + n1;
    int128_t scaled128 = 0;

    if (pRemaining < 0) {
        scaled128 = scaled64 >> (-pRemaining);
    }
    else {
        int128_t ppRemaining = ((int128_t)1) << pRemaining;
        scaled128            = ppRemaining * scaled64;
    }

    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    uint32_t numTowers              = cv[0].GetNumOfElements();
    std::vector<DCRTPoly::Integer> factors(numTowers);

    for (uint32_t i = 0; i < numTowers; i++) {
        DCRTPoly::Integer modulus = cv[0].GetElementAtIndex(i).GetModulus();

        if (scaled128 < 0) {
            DCRTPoly::Integer reducedUnsigned = static_cast<BasicInteger>(-scaled128);
            reducedUnsigned.ModEq(modulus);
            factors[i] = modulus - reducedUnsigned;
        }
        else {
            DCRTPoly::Integer reducedUnsigned = static_cast<BasicInteger>(scaled128);
            reducedUnsigned.ModEq(modulus);
            factors[i] = reducedUnsigned;
        }
    }
    return factors;
}
#else  // NATIVEINT == 64
std::vector<DCRTPoly::Integer> LeveledSHECKKSRNS::GetElementForEvalMult(ConstCiphertext<DCRTPoly>& ciphertext,
                                                                        double operand) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    uint32_t numTowers              = cv[0].GetNumOfElements();
    std::vector<DCRTPoly::Integer> moduli(numTowers);
    for (uint32_t i = 0; i < numTowers; i++) {
        moduli[i] = cv[0].GetElementAtIndex(i).GetModulus();
    }

    double scFactor = cryptoParams->GetScalingFactorReal(ciphertext->GetLevel());

    #if defined(HAVE_INT128)
    typedef int128_t DoubleInteger;
    int32_t MAX_BITS_IN_WORD_LOCAL = 125;
    #else
    typedef int64_t DoubleInteger;
    int32_t MAX_BITS_IN_WORD_LOCAL = LargeScalingFactorConstants::MAX_BITS_IN_WORD;
    #endif

    // Compute approxFactor, a value to scale down by, in case the value exceeds a 64-bit integer.

    // the logic below was added as the code crashes when linked with clang++ in the Debug mode and
    // with the following flags and res is ZERO:
    // -O2
    // -g
    // -fsanitize-trap=all
    // -fsanitize=alignment,return,returns-nonnull-attribute,vla-bound,unreachable,float-cast-overflow
    // -fsanitize=null
    // -gz=zlib
    // -fno-asynchronous-unwind-tables
    // -fno-optimize-sibling-calls
    // -fsplit-dwarf-inlining
    // -gsimple-template-names
    // -gsplit-dwarf
    int32_t logApprox = 0;
    const double res  = std::fabs(operand * scFactor);
    if (res > 0) {
        int32_t logSF    = static_cast<int32_t>(std::ceil(std::log2(res)));
        int32_t logValid = (logSF <= MAX_BITS_IN_WORD_LOCAL) ? logSF : MAX_BITS_IN_WORD_LOCAL;
        logApprox        = logSF - logValid;
    }
    double approxFactor = pow(2, logApprox);

    DoubleInteger large     = static_cast<DoubleInteger>(operand / approxFactor * scFactor + 0.5);
    DoubleInteger large_abs = (large < 0 ? -large : large);
    DoubleInteger bound     = static_cast<uint64_t>(1) << 63;

    std::vector<DCRTPoly::Integer> factors(numTowers);

    if (large_abs >= bound) {
        for (uint32_t i = 0; i < numTowers; i++) {
            DoubleInteger reduced = large % moduli[i].ConvertToInt();

            factors[i] = (reduced < 0) ? static_cast<uint64_t>(reduced + moduli[i].ConvertToInt()) :
                                         static_cast<uint64_t>(reduced);
        }
    }
    else {
        int64_t scConstant = static_cast<int64_t>(large);
        for (uint32_t i = 0; i < numTowers; i++) {
            int64_t reduced = scConstant % static_cast<int64_t>(moduli[i].ConvertToInt());

            factors[i] = (reduced < 0) ? reduced + moduli[i].ConvertToInt() : reduced;
        }
    }

    // Scale back up by approxFactor within the CRT multiplications.
    if (logApprox > 0) {
        int32_t logStep           = (logApprox <= LargeScalingFactorConstants::MAX_LOG_STEP) ?
                                        logApprox :
                                        LargeScalingFactorConstants::MAX_LOG_STEP;
        DCRTPoly::Integer intStep = static_cast<uint64_t>(1) << logStep;
        std::vector<DCRTPoly::Integer> crtApprox(numTowers, intStep);
        logApprox -= logStep;

        while (logApprox > 0) {
            int32_t logStep           = (logApprox <= LargeScalingFactorConstants::MAX_LOG_STEP) ?
                                            logApprox :
                                            LargeScalingFactorConstants::MAX_LOG_STEP;
            DCRTPoly::Integer intStep = static_cast<uint64_t>(1) << logStep;
            std::vector<DCRTPoly::Integer> crtSF(numTowers, intStep);
            crtApprox = CKKSPackedEncoding::CRTMult(crtApprox, crtSF, moduli);
            logApprox -= logStep;
        }
        factors = CKKSPackedEncoding::CRTMult(factors, crtApprox, moduli);
    }

    return factors;
}

#endif

Ciphertext<DCRTPoly> LeveledSHECKKSRNS::EvalFastRotationExt(
    ConstCiphertext<DCRTPoly>& ciphertext, uint32_t index, const std::shared_ptr<std::vector<DCRTPoly>> digits,
    bool addFirst, const std::map<uint32_t, EvalKey<DCRTPoly>>& evalKeys) const {
    //  if (index == 0) {
    //    Ciphertext<DCRTPoly> result = ciphertext->Clone();
    //    return result;
    //  }

    const auto cc = ciphertext->GetCryptoContext();

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    uint32_t N = cryptoParams->GetElementParams()->GetRingDimension();
    uint32_t M = cryptoParams->GetElementParams()->GetCyclotomicOrder();

    // Find the automorphism index that corresponds to rotation index index.
    uint32_t autoIndex = FindAutomorphismIndex2nComplex(index, M);

    // Retrieve the automorphism key that corresponds to the auto index.
    auto evalKeyIterator = evalKeys.find(autoIndex);
    if (evalKeyIterator == evalKeys.end()) {
        OPENFHE_THROW("EvalKey for index [" + std::to_string(autoIndex) + "] is not found.");
    }
    auto evalKey = evalKeyIterator->second;

    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    const auto paramsQl             = cv[0].GetParams();

    auto algo = cc->GetScheme();

    std::shared_ptr<std::vector<DCRTPoly>> cTilda = algo->EvalFastKeySwitchCoreExt(digits, evalKey, paramsQl);

    if (addFirst) {
        const auto paramsQlP = (*cTilda)[0].GetParams();
        size_t sizeQl        = paramsQl->GetParams().size();
        DCRTPoly psiC0       = DCRTPoly(paramsQlP, Format::EVALUATION, true);
        auto cMult           = ciphertext->GetElements()[0].TimesNoCheck(cryptoParams->GetPModq());
        for (uint32_t i = 0; i < sizeQl; i++) {
            psiC0.SetElementAtIndex(i, std::move(cMult.GetElementAtIndex(i)));
        }
        (*cTilda)[0] += psiC0;
    }

    std::vector<uint32_t> vec(N);
    PrecomputeAutoMap(N, autoIndex, &vec);

    (*cTilda)[0] = (*cTilda)[0].AutomorphismTransform(autoIndex, vec);
    (*cTilda)[1] = (*cTilda)[1].AutomorphismTransform(autoIndex, vec);

    auto result = ciphertext->CloneEmpty();
    result->SetElements({std::move((*cTilda)[0]), std::move((*cTilda)[1])});
    return result;
}

Ciphertext<DCRTPoly> LeveledSHECKKSRNS::MultByInteger(ConstCiphertext<DCRTPoly>& ciphertext, uint64_t integer) const {
    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();

    std::vector<DCRTPoly> resultDCRT;
    resultDCRT.reserve(cv.size());
    for (const auto& elem : cv)
        resultDCRT.push_back(elem.Times(NativeInteger(integer)));

    auto result = ciphertext->CloneEmpty();
    result->SetElements(std::move(resultDCRT));
    return result;
}

void LeveledSHECKKSRNS::MultByIntegerInPlace(Ciphertext<DCRTPoly>& ciphertext, uint64_t integer) const {
    std::vector<DCRTPoly>& cv = ciphertext->GetElements();

    for (uint32_t i = 0; i < cv.size(); i++)
        cv[i] = cv[i].Times(NativeInteger(integer));
}

void LeveledSHECKKSRNS::AdjustLevelsAndDepthInPlace(Ciphertext<DCRTPoly>& ciphertext1,
                                                    Ciphertext<DCRTPoly>& ciphertext2) const {
    const auto cryptoParams  = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext1->GetCryptoParameters());
    uint32_t c1lvl           = ciphertext1->GetLevel();
    uint32_t c2lvl           = ciphertext2->GetLevel();
    uint32_t c1depth         = ciphertext1->GetNoiseScaleDeg();
    uint32_t c2depth         = ciphertext2->GetNoiseScaleDeg();
    auto sizeQl1             = ciphertext1->GetElements()[0].GetNumOfElements();
    auto sizeQl2             = ciphertext2->GetElements()[0].GetNumOfElements();
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    if (c1lvl < c2lvl) {
        if (c1depth == 2) {
            if (c2depth == 2) {
                double scf1 = ciphertext1->GetScalingFactor();
                double scf2 = ciphertext2->GetScalingFactor();
                double scf  = cryptoParams->GetScalingFactorReal(c1lvl);
                double q1   = cryptoParams->GetModReduceFactor(sizeQl1 - 1);
                for (uint32_t j = 1; j < compositeDegree; j++) {
                    q1 *= cryptoParams->GetModReduceFactor(sizeQl1 - j - 1);
                }
                EvalMultCoreInPlace(ciphertext1, scf2 / scf1 * q1 / scf);
                ModReduceInternalInPlace(ciphertext1, compositeDegree);
                if (c1lvl + compositeDegree < c2lvl) {
                    LevelReduceInternalInPlace(ciphertext1, c2lvl - c1lvl - compositeDegree);
                }
                ciphertext1->SetScalingFactor(ciphertext2->GetScalingFactor());
            }
            else {
                if (c1lvl + compositeDegree == c2lvl) {
                    ModReduceInternalInPlace(ciphertext1, compositeDegree);
                }
                else {
                    double scf1 = ciphertext1->GetScalingFactor();
                    double scf2 = cryptoParams->GetScalingFactorRealBig(c2lvl - compositeDegree);
                    double scf  = cryptoParams->GetScalingFactorReal(c1lvl);
                    double q1   = cryptoParams->GetModReduceFactor(sizeQl1 - 1);
                    for (uint32_t j = 1; j < compositeDegree; j++) {
                        q1 *= cryptoParams->GetModReduceFactor(sizeQl1 - j - 1);
                    }
                    EvalMultCoreInPlace(ciphertext1, scf2 / scf1 * q1 / scf);
                    ModReduceInternalInPlace(ciphertext1, compositeDegree);
                    if (c1lvl + 2 * compositeDegree < c2lvl) {
                        LevelReduceInternalInPlace(ciphertext1, c2lvl - c1lvl - 2 * compositeDegree);
                    }
                    ModReduceInternalInPlace(ciphertext1, compositeDegree);
                    ciphertext1->SetScalingFactor(ciphertext2->GetScalingFactor());
                }
            }
        }
        else {
            if (c2depth == 2) {
                double scf1 = ciphertext1->GetScalingFactor();
                double scf2 = ciphertext2->GetScalingFactor();
                double scf  = cryptoParams->GetScalingFactorReal(c1lvl);
                EvalMultCoreInPlace(ciphertext1, scf2 / scf1 / scf);
                LevelReduceInternalInPlace(ciphertext1, c2lvl - c1lvl);
                ciphertext1->SetScalingFactor(scf2);
            }
            else {
                double scf1 = ciphertext1->GetScalingFactor();
                double scf2 = cryptoParams->GetScalingFactorRealBig(c2lvl - compositeDegree);
                double scf  = cryptoParams->GetScalingFactorReal(c1lvl);
                EvalMultCoreInPlace(ciphertext1, scf2 / scf1 / scf);
                if (c1lvl + compositeDegree < c2lvl) {
                    LevelReduceInternalInPlace(ciphertext1, c2lvl - c1lvl - compositeDegree);
                }
                ModReduceInternalInPlace(ciphertext1, compositeDegree);
                ciphertext1->SetScalingFactor(ciphertext2->GetScalingFactor());
            }
        }
    }
    else if (c1lvl > c2lvl) {
        if (c2depth == 2) {
            if (c1depth == 2) {
                double scf2 = ciphertext2->GetScalingFactor();
                double scf1 = ciphertext1->GetScalingFactor();
                double scf  = cryptoParams->GetScalingFactorReal(c2lvl);
                double q2   = cryptoParams->GetModReduceFactor(sizeQl2 - 1);
                for (uint32_t j = 1; j < compositeDegree; j++) {
                    q2 *= cryptoParams->GetModReduceFactor(sizeQl2 - j - 1);
                }
                EvalMultCoreInPlace(ciphertext2, scf1 / scf2 * q2 / scf);
                ModReduceInternalInPlace(ciphertext2, compositeDegree);
                if (c2lvl + compositeDegree < c1lvl) {
                    LevelReduceInternalInPlace(ciphertext2, c1lvl - c2lvl - compositeDegree);
                }
                ciphertext2->SetScalingFactor(ciphertext1->GetScalingFactor());
            }
            else {
                if (c2lvl + compositeDegree == c1lvl) {
                    ModReduceInternalInPlace(ciphertext2, compositeDegree);
                }
                else {
                    double scf2 = ciphertext2->GetScalingFactor();
                    double scf1 = cryptoParams->GetScalingFactorRealBig(c1lvl - compositeDegree);
                    double scf  = cryptoParams->GetScalingFactorReal(c2lvl);
                    double q2   = cryptoParams->GetModReduceFactor(sizeQl2 - 1);
                    for (uint32_t j = 1; j < compositeDegree; j++) {
                        q2 *= cryptoParams->GetModReduceFactor(sizeQl2 - j - 1);
                    }
                    EvalMultCoreInPlace(ciphertext2, scf1 / scf2 * q2 / scf);
                    ModReduceInternalInPlace(ciphertext2, compositeDegree);
                    if (c2lvl + 2 * compositeDegree < c1lvl) {
                        LevelReduceInternalInPlace(ciphertext2, c1lvl - c2lvl - 2 * compositeDegree);
                    }
                    ModReduceInternalInPlace(ciphertext2, compositeDegree);
                    ciphertext2->SetScalingFactor(ciphertext1->GetScalingFactor());
                }
            }
        }
        else {
            if (c1depth == 2) {
                double scf2 = ciphertext2->GetScalingFactor();
                double scf1 = ciphertext1->GetScalingFactor();
                double scf  = cryptoParams->GetScalingFactorReal(c2lvl);
                EvalMultCoreInPlace(ciphertext2, scf1 / scf2 / scf);
                LevelReduceInternalInPlace(ciphertext2, c1lvl - c2lvl);
                ciphertext2->SetScalingFactor(scf1);
            }
            else {
                double scf2 = ciphertext2->GetScalingFactor();
                double scf1 = cryptoParams->GetScalingFactorRealBig(c1lvl - compositeDegree);
                double scf  = cryptoParams->GetScalingFactorReal(c2lvl);
                EvalMultCoreInPlace(ciphertext2, scf1 / scf2 / scf);
                if (c2lvl + compositeDegree < c1lvl) {
                    LevelReduceInternalInPlace(ciphertext2, c1lvl - c2lvl - compositeDegree);
                }
                ModReduceInternalInPlace(ciphertext2, compositeDegree);
                ciphertext2->SetScalingFactor(ciphertext1->GetScalingFactor());
            }
        }
    }
    else {
        if (c1depth < c2depth) {
            EvalMultCoreInPlace(ciphertext1, 1.0);
        }
        else if (c2depth < c1depth) {
            EvalMultCoreInPlace(ciphertext2, 1.0);
        }
    }
}

void LeveledSHECKKSRNS::AdjustLevelsAndDepthToOneInPlace(Ciphertext<DCRTPoly>& ciphertext1,
                                                         Ciphertext<DCRTPoly>& ciphertext2) const {
    AdjustLevelsAndDepthInPlace(ciphertext1, ciphertext2);

    if (ciphertext1->GetNoiseScaleDeg() == 2) {
        const auto cryptoParams =
            std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext1->GetCryptoParameters());
        ModReduceInternalInPlace(ciphertext1, cryptoParams->GetCompositeDegree());
        ModReduceInternalInPlace(ciphertext2, cryptoParams->GetCompositeDegree());
    }
}

void LeveledSHECKKSRNS::EvalMultCoreInPlace(Ciphertext<DCRTPoly>& ciphertext, double operand) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    auto factors = GetElementForEvalMult(ciphertext, operand);
    auto& cv     = ciphertext->GetElements();
    uint32_t len = cv.size();
    for (uint32_t i = 0; i < len; ++i)
        cv[i] = cv[i] * factors;
    ciphertext->SetNoiseScaleDeg(ciphertext->GetNoiseScaleDeg() + 1);

    double scFactor = cryptoParams->GetScalingFactorReal(ciphertext->GetLevel());
    ciphertext->SetScalingFactor(ciphertext->GetScalingFactor() * scFactor);
}

void LeveledSHECKKSRNS::EvalMultCoreInPlace(Ciphertext<DCRTPoly>& ciphertext, std::complex<double> operand) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    double operandRe = operand.real();
    double operandIm = operand.imag();

    auto factorsRe = GetElementForEvalMult(ciphertext, operandRe);
    auto factorsIm = GetElementForEvalMult(ciphertext, operandIm);
    auto& cv       = ciphertext->GetElements();
    std::vector<DCRTPoly> cvRe;
    cvRe.reserve(cv.size());
    std::vector<DCRTPoly> cvIm;
    cvIm.reserve(cv.size());
    for (uint32_t i = 0; i < cv.size(); ++i) {
        cvRe.emplace_back(cv[i] * factorsRe);
        cvIm.emplace_back(cv[i] * factorsIm);
    }

    // MultByMonomialInPlace
    const auto& elemParams   = cv[0].GetParams();
    const auto& paramsNative = elemParams->GetParams()[0];
    uint32_t N               = elemParams->GetRingDimension();
    uint32_t M               = 2 * N;

    NativePoly monomial(paramsNative, Format::COEFFICIENT, true);

    uint32_t power        = M / 4;
    uint32_t powerReduced = power % M;
    uint32_t index        = power % N;
    monomial[index]       = powerReduced < N ? NativeInteger(1) : paramsNative->GetModulus() - NativeInteger(1);

    DCRTPoly monomialDCRT(elemParams, Format::COEFFICIENT, true);
    monomialDCRT = monomial;
    monomialDCRT.SetFormat(Format::EVALUATION);

    for (uint32_t i = 0; i < cv.size(); ++i) {
        cvIm[i] *= monomialDCRT;
        cv[i] = cvRe[i] + cvIm[i];
    }

    ciphertext->SetNoiseScaleDeg(ciphertext->GetNoiseScaleDeg() + 1);

    double scFactor = cryptoParams->GetScalingFactorReal(ciphertext->GetLevel());
    ciphertext->SetScalingFactor(ciphertext->GetScalingFactor() * scFactor);
}

uint32_t LeveledSHECKKSRNS::FindAutomorphismIndex(uint32_t index, uint32_t m) const {
    return FindAutomorphismIndex2nComplex(index, m);
}

}  // namespace lbcrypto
