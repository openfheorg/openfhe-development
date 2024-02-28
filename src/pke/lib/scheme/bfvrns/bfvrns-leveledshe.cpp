//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2024, NJIT, Duality Technologies Inc. and other contributors
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
BFV implementation. See https://eprint.iacr.org/2021/204 for details.
 */

#define PROFILE

#include "scheme/bfvrns/bfvrns-leveledshe.h"

#include "scheme/bfvrns/bfvrns-cryptoparameters.h"
#include "schemebase/base-scheme.h"
#include "cryptocontext.h"
#include "ciphertext.h"

namespace lbcrypto {

void LeveledSHEBFVRNS::EvalAddInPlace(Ciphertext<DCRTPoly>& ciphertext, ConstPlaintext plaintext) const {
    const auto cryptoParams   = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(ciphertext->GetCryptoParameters());
    std::vector<DCRTPoly>& cv = ciphertext->GetElements();

    DCRTPoly pt = plaintext->GetElement<DCRTPoly>();
    pt.SetFormat(COEFFICIENT);
    const NativeInteger& NegQModt              = cryptoParams->GetNegQModt();
    const NativeInteger& NegQModtPrecon        = cryptoParams->GetNegQModtPrecon();
    const std::vector<NativeInteger>& tInvModq = cryptoParams->GettInvModq();
    const NativeInteger t                      = cryptoParams->GetPlaintextModulus();
    pt.TimesQovert(cryptoParams->GetElementParams(), tInvModq, t, NegQModt, NegQModtPrecon);
    pt.SetFormat(EVALUATION);
    cv[0] += pt;
}

void LeveledSHEBFVRNS::EvalSubInPlace(Ciphertext<DCRTPoly>& ciphertext, ConstPlaintext plaintext) const {
    const auto cryptoParams   = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(ciphertext->GetCryptoParameters());
    std::vector<DCRTPoly>& cv = ciphertext->GetElements();

    DCRTPoly pt = plaintext->GetElement<DCRTPoly>();
    pt.SetFormat(COEFFICIENT);
    const NativeInteger& NegQModt              = cryptoParams->GetNegQModt();
    const NativeInteger& NegQModtPrecon        = cryptoParams->GetNegQModtPrecon();
    const std::vector<NativeInteger>& tInvModq = cryptoParams->GettInvModq();
    const NativeInteger t                      = cryptoParams->GetPlaintextModulus();
    pt.TimesQovert(cryptoParams->GetElementParams(), tInvModq, t, NegQModt, NegQModtPrecon);
    pt.SetFormat(EVALUATION);
    cv[0] -= pt;
}

uint32_t FindLevelsToDrop(usint multiplicativeDepth, std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams,
                          uint32_t dcrtBits, bool keySwitch = false) {
    const auto cryptoParamsBFVrns    = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(cryptoParams);
    double sigma                     = cryptoParamsBFVrns->GetDistributionParameter();
    double alpha                     = cryptoParamsBFVrns->GetAssuranceMeasure();
    double p                         = static_cast<double>(cryptoParamsBFVrns->GetPlaintextModulus());
    uint32_t n                       = cryptoParamsBFVrns->GetElementParams()->GetRingDimension();
    uint32_t relinWindow             = cryptoParamsBFVrns->GetDigitSize();
    KeySwitchTechnique scalTechnique = cryptoParamsBFVrns->GetKeySwitchTechnique();
    EncryptionTechnique encTech      = cryptoParamsBFVrns->GetEncryptionTechnique();

    uint32_t k                = cryptoParamsBFVrns->GetNumPerPartQ();
    uint32_t numPartQ         = cryptoParamsBFVrns->GetNumPartQ();
    uint32_t thresholdParties = cryptoParamsBFVrns->GetThresholdNumOfParties();

    // Bound of the Gaussian error polynomial
    double Berr = sigma * sqrt(alpha);

    // Bkey set to thresholdParties * 1 for ternary distribution
    const double Bkey =
        (cryptoParamsBFVrns->GetSecretKeyDist() == GAUSSIAN) ? sqrt(thresholdParties) * Berr : thresholdParties;

    double w = relinWindow == 0 ? pow(2, dcrtBits) : pow(2, relinWindow);

    // expansion factor delta
    auto delta = [](uint32_t n) -> double {
        return (2. * sqrt(n));
    };

    // norm of fresh ciphertext polynomial (for EXTENDED the noise is reduced to modulus switching noise)
    auto Vnorm = [&](uint32_t n) -> double {
        if (encTech == EXTENDED)
            return (1. + delta(n) * Bkey) / 2.;
        else
            return Berr * (1. + 2. * delta(n) * Bkey);
    };

    auto noiseKS = [&](uint32_t n, double logqPrev, double w) -> double {
        if (scalTechnique == HYBRID)
            return k * (numPartQ * delta(n) * Berr + delta(n) * Bkey + 1.0) / 2;
        else
            return delta(n) * (floor(logqPrev / (log(2) * dcrtBits)) + 1) * w * Berr;
    };

    // function used in the EvalMult constraint
    auto C1 = [&](uint32_t n) -> double {
        return delta(n) * delta(n) * p * Bkey;
    };

    // function used in the EvalMult constraint
    auto C2 = [&](uint32_t n, double logqPrev) -> double {
        return delta(n) * delta(n) * Bkey * Bkey / 2.0 + noiseKS(n, logqPrev, w);
    };

    // main correctness constraint
    auto logqBFV = [&](uint32_t n, double logqPrev) -> double {
        if (multiplicativeDepth > 0) {
            return log(4 * p) + (multiplicativeDepth - 1) * log(C1(n)) +
                   log(C1(n) * Vnorm(n) + multiplicativeDepth * C2(n, logqPrev));
        }
        return log(p * (4 * (Vnorm(n))));
    };

    // initial values
    double logqPrev = 6. * log(10);
    double logq     = logqBFV(n, logqPrev);

    while (std::fabs(logq - logqPrev) > log(1.001)) {
        logqPrev = logq;
        logq     = logqBFV(n, logqPrev);
    }

    // get an estimate of the error q / (4t)
    double loge = logq / log(2) - 2 - log2(p);

    double logExtra = keySwitch ? log2(noiseKS(n, logq, w)) : log2(delta(n));

    // adding the cushon to the error (see Appendix D of https://eprint.iacr.org/2021/204.pdf for details)
    // adjusted empirical parameter to 16 from 4 for threshold scenarios to work correctly, this might need to
    // be further refined
    int32_t levels = std::floor((loge - 2 * multiplicativeDepth - 16 - logExtra) / dcrtBits);
    size_t sizeQ   = cryptoParamsBFVrns->GetElementParams()->GetParams().size();

    if (levels < 0)
        levels = 0;
    else if (levels > static_cast<int32_t>(sizeQ) - 1)
        levels = sizeQ - 1;

    return levels;
};

Ciphertext<DCRTPoly> LeveledSHEBFVRNS::EvalMult(ConstCiphertext<DCRTPoly> ciphertext1,
                                                ConstCiphertext<DCRTPoly> ciphertext2) const {
    if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
        std::string errMsg = "AlgorithmSHEBFVrns::EvalMult crypto parameters are not the same";
        OPENFHE_THROW(errMsg);
    }

    Ciphertext<DCRTPoly> ciphertextMult = ciphertext1->CloneEmpty();

    const auto cryptoParams =
        std::dynamic_pointer_cast<CryptoParametersBFVRNS>(ciphertext1->GetCryptoContext()->GetCryptoParameters());

    std::vector<DCRTPoly> cv1 = ciphertext1->GetElements();
    std::vector<DCRTPoly> cv2 = ciphertext2->GetElements();

    size_t cv1Size    = cv1.size();
    size_t cv2Size    = cv2.size();
    size_t cvMultSize = cv1Size + cv2Size - 1;
    size_t sizeQ      = cv1[0].GetNumOfElements();

    // l is index corresponding to leveled parameters in cryptoParameters precomputations in HPSPOVERQLEVELED
    size_t l = 0;

    std::vector<DCRTPoly> cvMult(cvMultSize);

    if (cryptoParams->GetMultiplicationTechnique() == HPS) {
        for (size_t i = 0; i < cv1Size; i++) {
            cv1[i].ExpandCRTBasis(cryptoParams->GetParamsQlRl(), cryptoParams->GetParamsRl(),
                                  cryptoParams->GetQlHatInvModq(), cryptoParams->GetQlHatInvModqPrecon(),
                                  cryptoParams->GetQlHatModr(), cryptoParams->GetalphaQlModr(),
                                  cryptoParams->GetModrBarrettMu(), cryptoParams->GetqInv(), Format::EVALUATION);
        }

        for (size_t i = 0; i < cv2Size; i++) {
            cv2[i].ExpandCRTBasis(cryptoParams->GetParamsQlRl(), cryptoParams->GetParamsRl(),
                                  cryptoParams->GetQlHatInvModq(), cryptoParams->GetQlHatInvModqPrecon(),
                                  cryptoParams->GetQlHatModr(), cryptoParams->GetalphaQlModr(),
                                  cryptoParams->GetModrBarrettMu(), cryptoParams->GetqInv(), Format::EVALUATION);
        }
    }
    else if (cryptoParams->GetMultiplicationTechnique() == HPSPOVERQ) {
        for (size_t i = 0; i < cv1Size; i++) {
            // Expand ciphertext1 from basis Q to PQ.
            cv1[i].ExpandCRTBasis(cryptoParams->GetParamsQlRl(sizeQ - 1), cryptoParams->GetParamsRl(sizeQ - 1),
                                  cryptoParams->GetQlHatInvModq(sizeQ - 1),
                                  cryptoParams->GetQlHatInvModqPrecon(sizeQ - 1), cryptoParams->GetQlHatModr(sizeQ - 1),
                                  cryptoParams->GetalphaQlModr(sizeQ - 1), cryptoParams->GetModrBarrettMu(),
                                  cryptoParams->GetqInv(), Format::EVALUATION);
        }

        size_t sizeQ = cv2[0].GetNumOfElements();

        DCRTPoly::CRTBasisExtensionPrecomputations basisPQ(
            cryptoParams->GetParamsQlRl(sizeQ - 1), cryptoParams->GetParamsRl(sizeQ - 1),
            cryptoParams->GetParamsQl(sizeQ - 1), cryptoParams->GetmNegRlQHatInvModq(sizeQ - 1),
            cryptoParams->GetmNegRlQHatInvModqPrecon(sizeQ - 1), cryptoParams->GetqInvModr(),
            cryptoParams->GetModrBarrettMu(), cryptoParams->GetRlHatInvModr(sizeQ - 1),
            cryptoParams->GetRlHatInvModrPrecon(sizeQ - 1), cryptoParams->GetRlHatModq(sizeQ - 1),
            cryptoParams->GetalphaRlModq(sizeQ - 1), cryptoParams->GetModqBarrettMu(), cryptoParams->GetrInv());

        for (size_t i = 0; i < cv2Size; i++) {
            cv2[i].SetFormat(Format::COEFFICIENT);
            // Switch ciphertext2 from basis Q to P to PQ.
            cv2[i].FastExpandCRTBasisPloverQ(basisPQ);
            cv2[i].SetFormat(Format::EVALUATION);
        }
    }
    else if (cryptoParams->GetMultiplicationTechnique() == HPSPOVERQLEVELED) {
        size_t c1depth = ciphertext1->GetNoiseScaleDeg();
        size_t c2depth = ciphertext2->GetNoiseScaleDeg();

        size_t levels   = std::max(c1depth, c2depth) - 1;
        double dcrtBits = cv1[0].GetElementAtIndex(0).GetModulus().GetMSB();

        // how many levels to drop
        uint32_t levelsDropped = FindLevelsToDrop(levels, cryptoParams, dcrtBits, false);
        l                      = levelsDropped > 0 ? sizeQ - 1 - levelsDropped : sizeQ - 1;

        for (size_t i = 0; i < cv1Size; i++) {
            cv1[i].SetFormat(Format::COEFFICIENT);
            if (l < sizeQ - 1) {
                // Drop from basis Q to Q_l.
                cv1[i] =
                    cv1[i].ScaleAndRound(cryptoParams->GetParamsQl(l), cryptoParams->GetQlQHatInvModqDivqModq(l),
                                         cryptoParams->GetQlQHatInvModqDivqFrac(l), cryptoParams->GetModqBarrettMu());
            }
            // Expand ciphertext1 from basis Q_l to PQ_l.
            cv1[i].ExpandCRTBasis(cryptoParams->GetParamsQlRl(l), cryptoParams->GetParamsRl(l),
                                  cryptoParams->GetQlHatInvModq(l), cryptoParams->GetQlHatInvModqPrecon(l),
                                  cryptoParams->GetQlHatModr(l), cryptoParams->GetalphaQlModr(l),
                                  cryptoParams->GetModrBarrettMu(), cryptoParams->GetqInv(), Format::EVALUATION);
        }

        DCRTPoly::CRTBasisExtensionPrecomputations basisPQ(
            cryptoParams->GetParamsQlRl(l), cryptoParams->GetParamsRl(l), cryptoParams->GetParamsQl(l),
            cryptoParams->GetmNegRlQHatInvModq(l), cryptoParams->GetmNegRlQHatInvModqPrecon(l),
            cryptoParams->GetqInvModr(), cryptoParams->GetModrBarrettMu(), cryptoParams->GetRlHatInvModr(l),
            cryptoParams->GetRlHatInvModrPrecon(l), cryptoParams->GetRlHatModq(l), cryptoParams->GetalphaRlModq(l),
            cryptoParams->GetModqBarrettMu(), cryptoParams->GetrInv());

        for (size_t i = 0; i < cv2Size; i++) {
            cv2[i].SetFormat(Format::COEFFICIENT);
            // Switch ciphertext2 from basis Q to P to PQ.
            cv2[i].FastExpandCRTBasisPloverQ(basisPQ);
            cv2[i].SetFormat(Format::EVALUATION);
        }
    }
    else {
        for (size_t i = 0; i < cv1Size; i++) {
            cv1[i].FastBaseConvqToBskMontgomery(
                cryptoParams->GetParamsQBsk(), cryptoParams->GetModuliQ(), cryptoParams->GetModuliBsk(),
                cryptoParams->GetModbskBarrettMu(), cryptoParams->GetmtildeQHatInvModq(),
                cryptoParams->GetmtildeQHatInvModqPrecon(), cryptoParams->GetQHatModbsk(),
                cryptoParams->GetQHatModmtilde(), cryptoParams->GetQModbsk(), cryptoParams->GetQModbskPrecon(),
                cryptoParams->GetNegQInvModmtilde(), cryptoParams->GetmtildeInvModbsk(),
                cryptoParams->GetmtildeInvModbskPrecon());
            cv1[i].SetFormat(Format::EVALUATION);
        }

        for (size_t i = 0; i < cv2Size; i++) {
            cv2[i].FastBaseConvqToBskMontgomery(
                cryptoParams->GetParamsQBsk(), cryptoParams->GetModuliQ(), cryptoParams->GetModuliBsk(),
                cryptoParams->GetModbskBarrettMu(), cryptoParams->GetmtildeQHatInvModq(),
                cryptoParams->GetmtildeQHatInvModqPrecon(), cryptoParams->GetQHatModbsk(),
                cryptoParams->GetQHatModmtilde(), cryptoParams->GetQModbsk(), cryptoParams->GetQModbskPrecon(),
                cryptoParams->GetNegQInvModmtilde(), cryptoParams->GetmtildeInvModbsk(),
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
    }
    else {  // if size of any of the ciphertexts > 2
        std::vector<bool> isFirstAdd(cvMultSize, true);

        for (size_t i = 0; i < cv1Size; i++) {
            for (size_t j = 0; j < cv2Size; j++) {
                if (isFirstAdd[i + j] == true) {
                    cvMult[i + j]     = cv1[i] * cv2[j];
                    isFirstAdd[i + j] = false;
                }
                else {
                    cvMult[i + j] += cv1[i] * cv2[j];
                }
            }
        }
    }
#else
    std::vector<bool> isFirstAdd(cvMultSize, true);
    for (size_t i = 0; i < cv1Size; i++) {
        for (size_t j = 0; j < cv2Size; j++) {
            if (isFirstAdd[i + j] == true) {
                cvMult[i + j]     = cv1[i] * cv2[j];
                isFirstAdd[i + j] = false;
            }
            else {
                cvMult[i + j] += cv1[i] * cv2[j];
            }
        }
    }
#endif

    if (cryptoParams->GetMultiplicationTechnique() == HPS) {
        for (size_t i = 0; i < cvMultSize; i++) {
            // converts to coefficient representation before rounding
            cvMult[i].SetFormat(Format::COEFFICIENT);
            // Performs the scaling by t/Q followed by rounding; the result is in the
            // CRT basis P
            cvMult[i] =
                cvMult[i].ScaleAndRound(cryptoParams->GetParamsRl(), cryptoParams->GettRSHatInvModsDivsModr(),
                                        cryptoParams->GettRSHatInvModsDivsFrac(), cryptoParams->GetModrBarrettMu());

            // Converts from the CRT basis P to Q
            cvMult[i] = cvMult[i].SwitchCRTBasis(cryptoParams->GetElementParams(), cryptoParams->GetRlHatInvModr(),
                                                 cryptoParams->GetRlHatInvModrPrecon(), cryptoParams->GetRlHatModq(),
                                                 cryptoParams->GetalphaRlModq(), cryptoParams->GetModqBarrettMu(),
                                                 cryptoParams->GetrInv());
        }
    }
    else if (cryptoParams->GetMultiplicationTechnique() == HPSPOVERQ) {
        for (size_t i = 0; i < cvMultSize; i++) {
            cvMult[i].SetFormat(COEFFICIENT);
            // Performs the scaling by t/P followed by rounding; the result is in the
            // CRT basis Q
            cvMult[i] =
                cvMult[i].ScaleAndRound(cryptoParams->GetElementParams(), cryptoParams->GettQlSlHatInvModsDivsModq(0),
                                        cryptoParams->GettQlSlHatInvModsDivsFrac(0), cryptoParams->GetModqBarrettMu());
        }
    }
    else if (cryptoParams->GetMultiplicationTechnique() == HPSPOVERQLEVELED) {
        for (size_t i = 0; i < cvMultSize; i++) {
            cvMult[i].SetFormat(COEFFICIENT);
            // Performs the scaling by t/P followed by rounding; the result is in the
            // CRT basis Q
            cvMult[i] =
                cvMult[i].ScaleAndRound(cryptoParams->GetParamsQl(l), cryptoParams->GettQlSlHatInvModsDivsModq(l),
                                        cryptoParams->GettQlSlHatInvModsDivsFrac(l), cryptoParams->GetModqBarrettMu());

            if (l < sizeQ - 1) {
                // Expand back to basis Q.
                cvMult[i].ExpandCRTBasisQlHat(cryptoParams->GetElementParams(), cryptoParams->GetQlHatModq(l),
                                              cryptoParams->GetQlHatModqPrecon(l), sizeQ);
            }
        }
    }
    else {
        const NativeInteger& t = cryptoParams->GetPlaintextModulus();
        for (size_t i = 0; i < cvMultSize; i++) {
            // converts to Format::COEFFICIENT representation before rounding
            cvMult[i].SetFormat(Format::COEFFICIENT);
            // Performs the scaling by t/Q followed by rounding; the result is in the
            // CRT basis {Bsk}
            cvMult[i].FastRNSFloorq(
                t, cryptoParams->GetModuliQ(), cryptoParams->GetModuliBsk(), cryptoParams->GetModbskBarrettMu(),
                cryptoParams->GettQHatInvModq(), cryptoParams->GettQHatInvModqPrecon(), cryptoParams->GetQHatModbsk(),
                cryptoParams->GetqInvModbsk(), cryptoParams->GettQInvModbsk(), cryptoParams->GettQInvModbskPrecon());

            // Converts from the CRT basis {Bsk} to {Q}
            cvMult[i].FastBaseConvSK(cryptoParams->GetElementParams(), cryptoParams->GetModqBarrettMu(),
                                     cryptoParams->GetModuliBsk(), cryptoParams->GetModbskBarrettMu(),
                                     cryptoParams->GetBHatInvModb(), cryptoParams->GetBHatInvModbPrecon(),
                                     cryptoParams->GetBHatModmsk(), cryptoParams->GetBInvModmsk(),
                                     cryptoParams->GetBInvModmskPrecon(), cryptoParams->GetBHatModq(),
                                     cryptoParams->GetBModq(), cryptoParams->GetBModqPrecon());
        }
    }

    ciphertextMult->SetElements(std::move(cvMult));
    ciphertextMult->SetNoiseScaleDeg(std::max(ciphertext1->GetNoiseScaleDeg(), ciphertext2->GetNoiseScaleDeg()) + 1);
    return ciphertextMult;
}

Ciphertext<DCRTPoly> LeveledSHEBFVRNS::EvalSquare(ConstCiphertext<DCRTPoly> ciphertext) const {
    Ciphertext<DCRTPoly> ciphertextSq = ciphertext->CloneEmpty();

    const auto cryptoParams =
        std::dynamic_pointer_cast<CryptoParametersBFVRNS>(ciphertext->GetCryptoContext()->GetCryptoParameters());

    std::vector<DCRTPoly> cv = ciphertext->GetElements();

    size_t cvSize   = cv.size();
    size_t cvSqSize = 2 * cvSize - 1;
    size_t sizeQ    = cv[0].GetNumOfElements();
    // l is index corresponding to leveled parameters in cryptoParameters precomputations in HPSPOVERQLEVELED
    size_t l = 0;

    std::vector<DCRTPoly> cvPoverQ;
    if (cryptoParams->GetMultiplicationTechnique() == HPS) {
        for (size_t i = 0; i < cvSize; i++) {
            cv[i].ExpandCRTBasis(cryptoParams->GetParamsQlRl(), cryptoParams->GetParamsRl(),
                                 cryptoParams->GetQlHatInvModq(), cryptoParams->GetQlHatInvModqPrecon(),
                                 cryptoParams->GetQlHatModr(), cryptoParams->GetalphaQlModr(),
                                 cryptoParams->GetModrBarrettMu(), cryptoParams->GetqInv(), Format::EVALUATION);
        }
    }
    else if (cryptoParams->GetMultiplicationTechnique() == HPSPOVERQ) {
        cvPoverQ = cv;
        for (size_t i = 0; i < cvSize; i++) {
            // Expand ciphertext1 from basis Q to PQ.
            cv[i].ExpandCRTBasis(cryptoParams->GetParamsQlRl(sizeQ - 1), cryptoParams->GetParamsRl(sizeQ - 1),
                                 cryptoParams->GetQlHatInvModq(sizeQ - 1),
                                 cryptoParams->GetQlHatInvModqPrecon(sizeQ - 1), cryptoParams->GetQlHatModr(sizeQ - 1),
                                 cryptoParams->GetalphaQlModr(sizeQ - 1), cryptoParams->GetModrBarrettMu(),
                                 cryptoParams->GetqInv(), Format::EVALUATION);
        }

        DCRTPoly::CRTBasisExtensionPrecomputations basisPQ(
            cryptoParams->GetParamsQlRl(sizeQ - 1), cryptoParams->GetParamsRl(sizeQ - 1),
            cryptoParams->GetParamsQl(sizeQ - 1), cryptoParams->GetmNegRlQHatInvModq(sizeQ - 1),
            cryptoParams->GetmNegRlQHatInvModqPrecon(sizeQ - 1), cryptoParams->GetqInvModr(),
            cryptoParams->GetModrBarrettMu(), cryptoParams->GetRlHatInvModr(sizeQ - 1),
            cryptoParams->GetRlHatInvModrPrecon(sizeQ - 1), cryptoParams->GetRlHatModq(sizeQ - 1),
            cryptoParams->GetalphaRlModq(sizeQ - 1), cryptoParams->GetModqBarrettMu(), cryptoParams->GetrInv());

        for (size_t i = 0; i < cvSize; i++) {
            cvPoverQ[i].SetFormat(Format::COEFFICIENT);
            // Switch ciphertext2 from basis Q to P to PQ.
            cvPoverQ[i].FastExpandCRTBasisPloverQ(basisPQ);
            cvPoverQ[i].SetFormat(Format::EVALUATION);
        }
    }
    else if (cryptoParams->GetMultiplicationTechnique() == HPSPOVERQLEVELED) {
        size_t cdepth   = ciphertext->GetNoiseScaleDeg();
        size_t levels   = cdepth - 1;
        double dcrtBits = cv[0].GetElementAtIndex(0).GetModulus().GetMSB();

        // how many levels to drop
        uint32_t levelsDropped = FindLevelsToDrop(levels, cryptoParams, dcrtBits, false);
        l                      = levelsDropped > 0 ? sizeQ - 1 - levelsDropped : sizeQ - 1;

        for (size_t i = 0; i < cvSize; i++) {
            cv[i].SetFormat(Format::COEFFICIENT);
        }

        cvPoverQ = cv;

        for (size_t i = 0; i < cvSize; i++) {
            if (l < sizeQ - 1) {
                // Drop from basis Q to Q_l.
                cv[i] =
                    cv[i].ScaleAndRound(cryptoParams->GetParamsQl(l), cryptoParams->GetQlQHatInvModqDivqModq(l),
                                        cryptoParams->GetQlQHatInvModqDivqFrac(l), cryptoParams->GetModqBarrettMu());
            }
            // Expand ciphertext1 from basis Q_l to PQ_l.
            cv[i].ExpandCRTBasis(cryptoParams->GetParamsQlRl(l), cryptoParams->GetParamsRl(l),
                                 cryptoParams->GetQlHatInvModq(l), cryptoParams->GetQlHatInvModqPrecon(l),
                                 cryptoParams->GetQlHatModr(l), cryptoParams->GetalphaQlModr(l),
                                 cryptoParams->GetModrBarrettMu(), cryptoParams->GetqInv(), Format::EVALUATION);
        }

        DCRTPoly::CRTBasisExtensionPrecomputations basisPQ(
            cryptoParams->GetParamsQlRl(l), cryptoParams->GetParamsRl(l), cryptoParams->GetParamsQl(l),
            cryptoParams->GetmNegRlQHatInvModq(l), cryptoParams->GetmNegRlQHatInvModqPrecon(l),
            cryptoParams->GetqInvModr(), cryptoParams->GetModrBarrettMu(), cryptoParams->GetRlHatInvModr(l),
            cryptoParams->GetRlHatInvModrPrecon(l), cryptoParams->GetRlHatModq(l), cryptoParams->GetalphaRlModq(l),
            cryptoParams->GetModqBarrettMu(), cryptoParams->GetrInv());

        for (size_t i = 0; i < cvSize; i++) {
            cvPoverQ[i].FastExpandCRTBasisPloverQ(basisPQ);
            cvPoverQ[i].SetFormat(Format::EVALUATION);
        }
    }
    else {
        for (size_t i = 0; i < cvSize; i++) {
            cv[i].FastBaseConvqToBskMontgomery(
                cryptoParams->GetParamsQBsk(), cryptoParams->GetModuliQ(), cryptoParams->GetModuliBsk(),
                cryptoParams->GetModbskBarrettMu(), cryptoParams->GetmtildeQHatInvModq(),
                cryptoParams->GetmtildeQHatInvModqPrecon(), cryptoParams->GetQHatModbsk(),
                cryptoParams->GetQHatModmtilde(), cryptoParams->GetQModbsk(), cryptoParams->GetQModbskPrecon(),
                cryptoParams->GetNegQInvModmtilde(), cryptoParams->GetmtildeInvModbsk(),
                cryptoParams->GetmtildeInvModbskPrecon());

            cv[i].SetFormat(Format::EVALUATION);
        }
    }

    std::vector<DCRTPoly> cvSquare(cvSqSize);
#ifdef USE_KARATSUBA
    if (cvSize == 2) {
        if (cryptoParams->GetMultiplicationTechnique() == HPS || cryptoParams->GetMultiplicationTechnique() == BEHZ) {
            // size of each ciphertxt = 2, use Karatsuba
            cvSquare[0] = cv[0] * cv[0];  // a
            cvSquare[2] = cv[1] * cv[1];  // b

            cvSquare[1] = cv1[0] * cv1[1];
            cvSquare[1] += cvSquare[1];
        }
        else {
            // size of each ciphertxt = 2, use Karatsuba
            cvSquare[0] = cv[0] * cvPoverQ[0];  // a
            cvSquare[2] = cv[1] * cvPoverQ[1];  // b

            cvSquare[1] = cv[0] + cv[1];
            cvSquare[1] *= (cvPoverQ[0] + cvPoverQ[1]);
            cvSquare[1] -= cvSquare[2];
            cvSquare[1] -= cvSquare[0];
        }
    }
    else {
        std::vector<bool> isFirstAdd(cvSqSize, true);
        DCRTPoly cvtemp;

        if (cryptoParams->GetMultiplicationTechnique() == HPS || cryptoParams->GetMultiplicationTechnique() == BEHZ) {
            for (size_t i = 0; i < cv.size(); i++) {
                for (size_t j = i; j < cv.size(); j++) {
                    if (isFirstAdd[i + j] == true) {
                        if (j == i) {
                            cvSquare[i + j] = cv[i] * cv[j];
                        }
                        else {
                            cvtemp          = cv[i] * cv[j];
                            cvSquare[i + j] = cvtemp;
                            cvSquare[i + j] += cvtemp;
                        }
                        isFirstAdd[i + j] = false;
                    }
                    else {
                        if (j == i) {
                            cvSquare[i + j] += cv[i] * cv[j];
                        }
                        else {
                            cvtemp = cv[i] * cv[j];
                            cvSquare[i + j] += cvtemp;
                            cvSquare[i + j] += cvtemp;
                        }
                    }
                }
            }
        }
        else {
            for (size_t i = 0; i < cvSize; i++) {
                for (size_t j = 0; j < cvSize; j++) {
                    if (isFirstAdd[i + j] == true) {
                        cvSquare[i + j]   = cv[i] * cvPoverQ[j];
                        isFirstAdd[i + j] = false;
                    }
                    else {
                        cvSquare[i + j] += cv[i] * cvPoverQ[j];
                    }
                }
            }
        }
    }
#else
    std::vector<bool> isFirstAdd(cvSqSize, true);
    DCRTPoly cvtemp;

    if (cryptoParams->GetMultiplicationTechnique() == HPS || cryptoParams->GetMultiplicationTechnique() == BEHZ) {
        for (size_t i = 0; i < cv.size(); i++) {
            for (size_t j = i; j < cv.size(); j++) {
                if (isFirstAdd[i + j] == true) {
                    if (j == i) {
                        cvSquare[i + j] = cv[i] * cv[j];
                    }
                    else {
                        cvtemp          = cv[i] * cv[j];
                        cvSquare[i + j] = cvtemp;
                        cvSquare[i + j] += cvtemp;
                    }
                    isFirstAdd[i + j] = false;
                }
                else {
                    if (j == i) {
                        cvSquare[i + j] += cv[i] * cv[j];
                    }
                    else {
                        cvtemp = cv[i] * cv[j];
                        cvSquare[i + j] += cvtemp;
                        cvSquare[i + j] += cvtemp;
                    }
                }
            }
        }
    }
    else {
        for (size_t i = 0; i < cvSize; i++) {
            for (size_t j = 0; j < cvSize; j++) {
                if (isFirstAdd[i + j] == true) {
                    cvSquare[i + j]   = cv[i] * cvPoverQ[j];
                    isFirstAdd[i + j] = false;
                }
                else {
                    cvSquare[i + j] += cv[i] * cvPoverQ[j];
                }
            }
        }
    }
#endif

    if (cryptoParams->GetMultiplicationTechnique() == HPS) {
        for (size_t i = 0; i < cvSqSize; i++) {
            // converts to coefficient representation before rounding
            cvSquare[i].SetFormat(Format::COEFFICIENT);
            // Performs the scaling by t/Q followed by rounding; the result is in the
            // CRT basis P
            cvSquare[i] =
                cvSquare[i].ScaleAndRound(cryptoParams->GetParamsRl(), cryptoParams->GettRSHatInvModsDivsModr(),
                                          cryptoParams->GettRSHatInvModsDivsFrac(), cryptoParams->GetModrBarrettMu());

            // Converts from the CRT basis P to Q
            cvSquare[i] = cvSquare[i].SwitchCRTBasis(cryptoParams->GetElementParams(), cryptoParams->GetRlHatInvModr(),
                                                     cryptoParams->GetRlHatInvModrPrecon(),
                                                     cryptoParams->GetRlHatModq(), cryptoParams->GetalphaRlModq(),
                                                     cryptoParams->GetModqBarrettMu(), cryptoParams->GetrInv());
        }
    }
    else if (cryptoParams->GetMultiplicationTechnique() == HPSPOVERQ) {
        for (size_t i = 0; i < cvSqSize; i++) {
            cvSquare[i].SetFormat(COEFFICIENT);
            // Performs the scaling by t/P followed by rounding; the result is in the
            // CRT basis Q
            cvSquare[i] = cvSquare[i].ScaleAndRound(
                cryptoParams->GetElementParams(), cryptoParams->GettQlSlHatInvModsDivsModq(0),
                cryptoParams->GettQlSlHatInvModsDivsFrac(0), cryptoParams->GetModqBarrettMu());
        }
    }
    else if (cryptoParams->GetMultiplicationTechnique() == HPSPOVERQLEVELED) {
        for (size_t i = 0; i < cvSqSize; i++) {
            cvSquare[i].SetFormat(COEFFICIENT);
            // Performs the scaling by t/P followed by rounding; the result is in the
            // CRT basis Q
            cvSquare[i] = cvSquare[i].ScaleAndRound(
                cryptoParams->GetParamsQl(l), cryptoParams->GettQlSlHatInvModsDivsModq(l),
                cryptoParams->GettQlSlHatInvModsDivsFrac(l), cryptoParams->GetModqBarrettMu());

            if (l < sizeQ - 1) {
                // Expand back to basis Q.
                cvSquare[i].ExpandCRTBasisQlHat(cryptoParams->GetElementParams(), cryptoParams->GetQlHatModq(l),
                                                cryptoParams->GetQlHatModqPrecon(l), sizeQ);
            }
        }
    }
    else {
        const NativeInteger& t = cryptoParams->GetPlaintextModulus();
        for (size_t i = 0; i < cvSqSize; i++) {
            // converts to Format::COEFFICIENT representation before rounding
            cvSquare[i].SetFormat(Format::COEFFICIENT);
            // Performs the scaling by t/Q followed by rounding; the result is in the
            // CRT basis {Bsk}
            cvSquare[i].FastRNSFloorq(
                t, cryptoParams->GetModuliQ(), cryptoParams->GetModuliBsk(), cryptoParams->GetModbskBarrettMu(),
                cryptoParams->GettQHatInvModq(), cryptoParams->GettQHatInvModqPrecon(), cryptoParams->GetQHatModbsk(),
                cryptoParams->GetqInvModbsk(), cryptoParams->GettQInvModbsk(), cryptoParams->GettQInvModbskPrecon());

            // Converts from the CRT basis {Bsk} to {Q}
            cvSquare[i].FastBaseConvSK(cryptoParams->GetElementParams(), cryptoParams->GetModqBarrettMu(),
                                       cryptoParams->GetModuliBsk(), cryptoParams->GetModbskBarrettMu(),
                                       cryptoParams->GetBHatInvModb(), cryptoParams->GetBHatInvModbPrecon(),
                                       cryptoParams->GetBHatModmsk(), cryptoParams->GetBInvModmsk(),
                                       cryptoParams->GetBInvModmskPrecon(), cryptoParams->GetBHatModq(),
                                       cryptoParams->GetBModq(), cryptoParams->GetBModqPrecon());
        }
    }

    ciphertextSq->SetElements(std::move(cvSquare));
    ciphertextSq->SetNoiseScaleDeg(ciphertext->GetNoiseScaleDeg() + 1);

    return ciphertextSq;
}

Ciphertext<DCRTPoly> LeveledSHEBFVRNS::EvalMult(ConstCiphertext<DCRTPoly> ciphertext1,
                                                ConstCiphertext<DCRTPoly> ciphertext2,
                                                const EvalKey<DCRTPoly> evalKey) const {
    Ciphertext<DCRTPoly> ciphertext = EvalMult(ciphertext1, ciphertext2);
    RelinearizeCore(ciphertext, evalKey);
    return ciphertext;
}

void LeveledSHEBFVRNS::EvalMultInPlace(Ciphertext<DCRTPoly>& ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2,
                                       const EvalKey<DCRTPoly> evalKey) const {
    ciphertext1 = EvalMult(ciphertext1, ciphertext2);
    RelinearizeCore(ciphertext1, evalKey);
}

Ciphertext<DCRTPoly> LeveledSHEBFVRNS::EvalSquare(ConstCiphertext<DCRTPoly> ciphertext,
                                                  const EvalKey<DCRTPoly> evalKey) const {
    Ciphertext<DCRTPoly> csquare = EvalSquare(ciphertext);
    RelinearizeCore(csquare, evalKey);
    return csquare;
}

void LeveledSHEBFVRNS::EvalSquareInPlace(Ciphertext<DCRTPoly>& ciphertext, const EvalKey<DCRTPoly> evalKey) const {
    ciphertext = EvalSquare(ciphertext);
    RelinearizeCore(ciphertext, evalKey);
}

void LeveledSHEBFVRNS::EvalMultCoreInPlace(Ciphertext<DCRTPoly>& ciphertext, const NativeInteger& constant) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(ciphertext->GetCryptoParameters());

    std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    for (usint i = 0; i < cv.size(); ++i) {
        cv[i] *= constant;
    }
    const NativeInteger t(cryptoParams->GetPlaintextModulus());

    ciphertext->SetNoiseScaleDeg(ciphertext->GetNoiseScaleDeg() + 1);
}

Ciphertext<DCRTPoly> LeveledSHEBFVRNS::EvalAutomorphism(ConstCiphertext<DCRTPoly> ciphertext, usint i,
                                                        const std::map<usint, EvalKey<DCRTPoly>>& evalKeyMap,
                                                        CALLER_INFO_ARGS_CPP) const {
    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();

    usint N = cv[0].GetRingDimension();

    std::vector<usint> vec(N);
    PrecomputeAutoMap(N, i, &vec);

    auto algo = ciphertext->GetCryptoContext()->GetScheme();

    Ciphertext<DCRTPoly> result = ciphertext->Clone();

    RelinearizeCore(result, evalKeyMap.at(i));

    std::vector<DCRTPoly>& rcv = result->GetElements();

    rcv[0] = rcv[0].AutomorphismTransform(i, vec);
    rcv[1] = rcv[1].AutomorphismTransform(i, vec);

    return result;
}

std::shared_ptr<std::vector<DCRTPoly>> LeveledSHEBFVRNS::EvalFastRotationPrecompute(
    ConstCiphertext<DCRTPoly> ciphertext) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(ciphertext->GetCryptoParameters());
    auto algo               = ciphertext->GetCryptoContext()->GetScheme();

    if (cryptoParams->GetMultiplicationTechnique() != HPSPOVERQLEVELED) {
        return algo->EvalKeySwitchPrecomputeCore(ciphertext->GetElements()[1], ciphertext->GetCryptoParameters());
    }

    DCRTPoly c1     = ciphertext->GetElements()[1];
    size_t levels   = ciphertext->GetNoiseScaleDeg() - 1;
    size_t sizeQ    = c1.GetNumOfElements();
    double dcrtBits = c1.GetElementAtIndex(0).GetModulus().GetMSB();
    // how many levels to drop
    uint32_t levelsDropped = FindLevelsToDrop(levels, cryptoParams, dcrtBits, true);
    // l is index corresponding to leveled parameters in cryptoParameters precomputations in HPSPOVERQLEVELED
    uint32_t l = levelsDropped > 0 ? sizeQ - 1 - levelsDropped : sizeQ - 1;
    c1.SetFormat(COEFFICIENT);
    c1 = c1.ScaleAndRound(cryptoParams->GetParamsQl(l), cryptoParams->GetQlQHatInvModqDivqModq(l),
                          cryptoParams->GetQlQHatInvModqDivqFrac(l), cryptoParams->GetModqBarrettMu());
    c1.SetFormat(EVALUATION);

    return algo->EvalKeySwitchPrecomputeCore(c1, ciphertext->GetCryptoParameters());
}

Ciphertext<DCRTPoly> LeveledSHEBFVRNS::EvalFastRotation(ConstCiphertext<DCRTPoly> ciphertext, const usint index,
                                                        const usint m,
                                                        const std::shared_ptr<std::vector<DCRTPoly>> digits) const {
    if (index == 0) {
        return ciphertext->Clone();
    }

    const auto cc = ciphertext->GetCryptoContext();

    usint autoIndex = FindAutomorphismIndex(index, m);

    auto evalKeyMap = cc->GetEvalAutomorphismKeyMap(ciphertext->GetKeyTag());
    // verify if the key autoIndex exists in the evalKeyMap
    auto evalKeyIterator = evalKeyMap.find(autoIndex);
    if (evalKeyIterator == evalKeyMap.end()) {
        OPENFHE_THROW("EvalKey for index [" + std::to_string(autoIndex) + "] is not found.");
    }
    auto evalKey = evalKeyIterator->second;

    auto algo                       = cc->GetScheme();
    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(ciphertext->GetCryptoParameters());

    /* In the HPSOVERQLEVELED mode, we do modulus switching to a smaller modulus before we start key switching.
    The modulus switching was already done when computing the ciphertext digits using EvalFastRotationPrecompute.
    The goal of the "if branch" below is to extract the current modulus Ql from the element parameters of one of
    the digit polynomials (by removing the auxiliary moduli added for hybrid key switching).
    ATTN: elemParams should not be a shared_ptr because it would modify digits. */
    // TODO (dsuponit): wrap the lines below in a function to return elemParams as an object
    auto elemParams = *((*digits)[0].GetParams());
    if (cryptoParams->GetMultiplicationTechnique() == HPSPOVERQLEVELED) {
        if (cryptoParams->GetKeySwitchTechnique() == HYBRID) {
            size_t sizeP = cryptoParams->GetParamsP()->GetParams().size();
            for (size_t i = 0; i < sizeP; ++i) {
                elemParams.PopLastParam();
            }
        }
    }

    std::shared_ptr<std::vector<DCRTPoly>> ba =
        algo->EvalFastKeySwitchCore(digits, evalKey, std::make_shared<DCRTPoly::Params>(elemParams));

    if (cryptoParams->GetMultiplicationTechnique() == HPSPOVERQLEVELED) {
        size_t sizeQ = cv[0].GetNumOfElements();
        // l is index corresponding to leveled parameters in cryptoParameters precomputations in HPSPOVERQLEVELED, after the level dropping
        uint32_t l = elemParams.GetParams().size() - 1;

        (*ba)[0].ExpandCRTBasisQlHat(cryptoParams->GetElementParams(), cryptoParams->GetQlHatModq(l),
                                     cryptoParams->GetQlHatModqPrecon(l), sizeQ);
        (*ba)[1].ExpandCRTBasisQlHat(cryptoParams->GetElementParams(), cryptoParams->GetQlHatModq(l),
                                     cryptoParams->GetQlHatModqPrecon(l), sizeQ);
    }

    usint N = cryptoParams->GetElementParams()->GetRingDimension();
    std::vector<usint> vec(N);
    PrecomputeAutoMap(N, autoIndex, &vec);

    (*ba)[0] += cv[0];

    (*ba)[0] = (*ba)[0].AutomorphismTransform(autoIndex, vec);
    (*ba)[1] = (*ba)[1].AutomorphismTransform(autoIndex, vec);

    Ciphertext<DCRTPoly> result = ciphertext->Clone();

    result->SetElements({std::move((*ba)[0]), std::move((*ba)[1])});

    return result;
}

usint LeveledSHEBFVRNS::FindAutomorphismIndex(usint index, usint m) const {
    return FindAutomorphismIndex2n(index, m);
}

void LeveledSHEBFVRNS::RelinearizeCore(Ciphertext<DCRTPoly>& ciphertext, const EvalKey<DCRTPoly> evalKey) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(ciphertext->GetCryptoParameters());
    // l is index corresponding to leveled parameters in cryptoParameters precomputations in HPSPOVERQLEVELED
    uint32_t l = 0;

    std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    bool isKeySwitch          = (cv.size() == 2);
    auto algo                 = ciphertext->GetCryptoContext()->GetScheme();
    size_t sel                = 1 + !isKeySwitch;

    if (cryptoParams->GetMultiplicationTechnique() == HPSPOVERQLEVELED) {
        size_t levels   = ciphertext->GetNoiseScaleDeg() - 1;
        size_t sizeQ    = cv[0].GetNumOfElements();
        double dcrtBits = cv[0].GetElementAtIndex(0).GetModulus().GetMSB();

        // how many levels to drop
        l = sizeQ - 1 - FindLevelsToDrop(levels, cryptoParams, dcrtBits, isKeySwitch);

        cv[sel].SetFormat(COEFFICIENT);
        cv[sel] = cv[sel].ScaleAndRound(cryptoParams->GetParamsQl(l), cryptoParams->GetQlQHatInvModqDivqModq(l),
                                        cryptoParams->GetQlQHatInvModqDivqFrac(l), cryptoParams->GetModqBarrettMu());
    }

    cv[sel].SetFormat(Format::EVALUATION);
    auto ab = algo->KeySwitchCore(cv[sel], evalKey);

    if (cryptoParams->GetMultiplicationTechnique() == HPSPOVERQLEVELED) {
        size_t sizeQ = cv[0].GetNumOfElements();
        (*ab)[0].ExpandCRTBasisQlHat(cryptoParams->GetElementParams(), cryptoParams->GetQlHatModq(l),
                                     cryptoParams->GetQlHatModqPrecon(l), sizeQ);
        (*ab)[1].ExpandCRTBasisQlHat(cryptoParams->GetElementParams(), cryptoParams->GetQlHatModq(l),
                                     cryptoParams->GetQlHatModqPrecon(l), sizeQ);
    }

    cv[0].SetFormat(Format::EVALUATION);
    cv[0] += (*ab)[0];

    if (isKeySwitch) {
        cv[1] = std::move((*ab)[1]);
    }
    else {
        cv[1].SetFormat(Format::EVALUATION);
        cv[1] += (*ab)[1];
    }

    cv.resize(2);
}

Ciphertext<DCRTPoly> LeveledSHEBFVRNS::Compress(ConstCiphertext<DCRTPoly> ciphertext, size_t towersLeft) const {
    if (towersLeft != 1) {
        OPENFHE_THROW(
            "BFV Compress is currently supported only for the case when one RNS tower is left after compression.");
    }

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(ciphertext->GetCryptoParameters());

    if (cryptoParams->GetMultiplicationTechnique() == BEHZ) {
        OPENFHE_THROW("BFV Compress is not currently supported for BEHZ. Use one of the HPS* methods instead.");
    }

    Ciphertext<DCRTPoly> result = std::make_shared<CiphertextImpl<DCRTPoly>>(*ciphertext);

    std::vector<DCRTPoly>& cv = result->GetElements();

    size_t sizeQ  = cryptoParams->GetElementParams()->GetParams().size();
    size_t sizeQl = cv[0].GetNumOfElements();
    size_t diffQl = sizeQ - sizeQl;
    size_t levels = sizeQl - towersLeft;

    for (size_t l = 0; l < levels; ++l) {
        for (size_t i = 0; i < cv.size(); ++i) {
            cv[i].DropLastElementAndScale(cryptoParams->GetQlQlInvModqlDivqlModq(diffQl + l),
                                          cryptoParams->GetqlInvModq(diffQl + l));
        }
    }

    return result;
}

}  // namespace lbcrypto
