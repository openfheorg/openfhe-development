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

#include "ciphertext.h"
#include "cryptocontext.h"
#include "key/evalkeyrelin.h"
#include "key/privatekey.h"
#include "lattice/lat-hal.h"
#include "math/hal/basicint.h"
#include "math/dftransform.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "scheme/ckksrns/ckksrns-fhe.h"
#include "scheme/ckksrns/ckksrns-utils.h"
#include "schemebase/base-scheme.h"
#include "utils/exception.h"
#include "utils/parallel.h"
#include "utils/utilities.h"

#include <algorithm>
#include <cmath>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#ifdef BOOTSTRAPTIMING
    #include <ostream>
#endif
#include <set>
#include <string>
#include <utility>
#include <vector>

#ifdef BOOTSTRAPTIMING
    #define PROFILE
#endif

namespace {
// GetBigModulus() calculates the big modulus as the product of
// the "compositeDegree" number of parameter modulus
double GetBigModulus(const std::shared_ptr<lbcrypto::CryptoParametersCKKSRNS> cryptoParams) {
    double qDouble           = 1.0;
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();
    for (uint32_t j = 0; j < compositeDegree; ++j) {
        qDouble *= cryptoParams->GetElementParams()->GetParams()[j]->GetModulus().ConvertToDouble();
    }
    return qDouble;
}

}  // namespace

namespace lbcrypto {

//------------------------------------------------------------------------------
// Bootstrap Wrapper
//------------------------------------------------------------------------------

void FHECKKSRNS::EvalBootstrapSetup(const CryptoContextImpl<DCRTPoly>& cc, std::vector<uint32_t> levelBudget,
                                    std::vector<uint32_t> dim1, uint32_t numSlots, uint32_t correctionFactor,
                                    bool precompute) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW("CKKS Bootstrapping is only supported for the Hybrid key switching method.");
#if NATIVEINT == 128
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        OPENFHE_THROW("128-bit CKKS Bootstrapping is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
#endif

    uint32_t M     = cc.GetCyclotomicOrder();
    uint32_t slots = (numSlots == 0) ? M / 4 : numSlots;

    // Set correction factor by default, if it is not already set.
    if (correctionFactor == 0) {
        auto st = cryptoParams->GetScalingTechnique();
        if (st == FLEXIBLEAUTO || st == FLEXIBLEAUTOEXT || st == COMPOSITESCALINGAUTO || st == COMPOSITESCALINGMANUAL) {
            // The default correction factors chosen yielded the best precision in our experiments.
            // We chose the best fit line from our experiments by running ckks-bootstrapping-precision.cpp.
            // The spreadsheet with our experiments is here:
            // https://docs.google.com/spreadsheets/d/1WqmwBUMNGlX6Uvs9qLXt5yeddtCyWPP55BbJPu5iPAM/edit?usp=sharing
            uint32_t tmp(std::round(-0.265 * (2 * std::log2(M / 2) + std::log2(slots)) + 19.1));
            m_correctionFactor = std::clamp<uint32_t>(tmp, 7, 13);
        }
        else {
            m_correctionFactor = 9;
        }
    }
    else {
        m_correctionFactor = correctionFactor;
    }

    m_bootPrecomMap[slots] = std::make_shared<CKKSBootstrapPrecom>();

    auto& precom    = m_bootPrecomMap[slots];
    precom->m_slots = slots;
    precom->m_dim1  = dim1[0];

    // even for the case of a single slot we need one level for rescaling
    uint32_t logSlots = (slots < 3) ? 1 : std::log2(slots);

    // Perform some checks on the level budget and compute parameters
    std::vector<uint32_t> newBudget = levelBudget;
    if (newBudget[0] > logSlots) {
        std::cerr << "\nWarning, the level budget for encoding is too large. Setting it to " << logSlots << std::endl;
        newBudget[0] = logSlots;
    }
    if (newBudget[0] < 1) {
        std::cerr << "\nWarning, the level budget for encoding can not be zero. Setting it to 1" << std::endl;
        newBudget[0] = 1;
    }
    if (newBudget[1] > logSlots) {
        std::cerr << "\nWarning, the level budget for decoding is too large. Setting it to " << logSlots << std::endl;
        newBudget[1] = logSlots;
    }
    if (newBudget[1] < 1) {
        std::cerr << "\nWarning, the level budget for decoding can not be zero. Setting it to 1" << std::endl;
        newBudget[1] = 1;
    }

    precom->m_paramsEnc = GetCollapsedFFTParams(slots, newBudget[0], dim1[0]);
    precom->m_paramsDec = GetCollapsedFFTParams(slots, newBudget[1], dim1[1]);

    if (precompute) {
        uint32_t m     = 4 * slots;
        uint32_t mmask = m - 1;  // assumes m is power of 2
        bool isSparse  = (M != m);

        // computes indices for all primitive roots of unity
        std::vector<uint32_t> rotGroup(slots);
        uint32_t fivePows = 1;
        for (uint32_t i = 0; i < slots; ++i) {
            rotGroup[i] = fivePows;
            fivePows *= 5;
            fivePows &= mmask;
        }

        // computes all powers of a primitive root of unity exp(2 * M_PI/m)
        std::vector<std::complex<double>> ksiPows(m + 1);
        double ak = 2 * M_PI / m;
        for (uint32_t j = 0; j < m; ++j) {
            double angle = ak * j;
            ksiPows[j].real(std::cos(angle));
            ksiPows[j].imag(std::sin(angle));
        }
        ksiPows[m] = ksiPows[0];

        double k;
        switch (cryptoParams->GetSecretKeyDist()) {
            case UNIFORM_TERNARY:
                k = 1.0;
                break;
            case SPARSE_TERNARY:
                k = K_SPARSE;
                break;
            case SPARSE_ENCAPSULATED:
                k = K_SPARSE_ENCAPSULATED;
                break;
            default:
                OPENFHE_THROW("Unsupported SecretKeyDist.");
        }

        uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

        double qDouble  = GetBigModulus(cryptoParams);
        double factor   = static_cast<uint128_t>(1) << static_cast<uint32_t>(std::round(std::log2(qDouble)));
        double pre      = (compositeDegree > 1) ? 1.0 : qDouble / factor;
        double scaleEnc = pre / k;
        // TODO: YSP Can be extended to FLEXIBLE* scaling techniques as well as the closeness of 2^p to moduli is no longer needed
        double scaleDec = (compositeDegree > 1) ? qDouble / cryptoParams->GetScalingFactorReal(0) : 1.0 / pre;

        uint32_t approxModDepth = GetModDepthInternal(cryptoParams->GetSecretKeyDist());

        uint32_t depthBT = approxModDepth + precom->m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET] +
                           precom->m_paramsDec[CKKS_BOOT_PARAMS::LEVEL_BUDGET];

        // compute # of levels to remain when encoding the coefficients
        // for FLEXIBLEAUTOEXT we do not need extra modulus in auxiliary plaintexts
        auto st     = cryptoParams->GetScalingTechnique();
        uint32_t L0 = cryptoParams->GetElementParams()->GetParams().size() - (st == FLEXIBLEAUTOEXT);

        uint32_t lEnc = L0 - compositeDegree * (precom->m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET] + 1);
        uint32_t lDec = L0 - compositeDegree * depthBT;

        bool isLTBootstrap = (precom->m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET] == 1) &&
                             (precom->m_paramsDec[CKKS_BOOT_PARAMS::LEVEL_BUDGET] == 1);

        if (isLTBootstrap) {
            // allocate all vectors
            std::vector<std::vector<std::complex<double>>> U0(slots, std::vector<std::complex<double>>(slots));
            std::vector<std::vector<std::complex<double>>> U1(slots, std::vector<std::complex<double>>(slots));
            std::vector<std::vector<std::complex<double>>> U0hatT(slots, std::vector<std::complex<double>>(slots));
            std::vector<std::vector<std::complex<double>>> U1hatT(slots, std::vector<std::complex<double>>(slots));

            for (uint32_t i = 0; i < slots; i++) {
                for (uint32_t j = 0; j < slots; j++) {
                    U0[i][j]     = ksiPows[(j * rotGroup[i]) & mmask];
                    U0hatT[j][i] = std::conj(U0[i][j]);
                    U1[i][j]     = std::complex<double>(0, 1) * U0[i][j];
                    U1hatT[j][i] = std::conj(U1[i][j]);
                }
            }

            if (!isSparse) {
                precom->m_U0hatTPre = EvalLinearTransformPrecompute(cc, U0hatT, scaleEnc, lEnc);
                precom->m_U0Pre     = EvalLinearTransformPrecompute(cc, U0, scaleDec, lDec);
            }
            else {
                precom->m_U0hatTPre = EvalLinearTransformPrecompute(cc, U0hatT, U1hatT, 0, scaleEnc, lEnc);
                precom->m_U0Pre     = EvalLinearTransformPrecompute(cc, U0, U1, 1, scaleDec, lDec);
            }
        }
        else {
            precom->m_U0hatTPreFFT = EvalCoeffsToSlotsPrecompute(cc, ksiPows, rotGroup, false, scaleEnc, lEnc);
            precom->m_U0PreFFT     = EvalSlotsToCoeffsPrecompute(cc, ksiPows, rotGroup, false, scaleDec, lDec);
        }
    }
}

std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>> FHECKKSRNS::EvalBootstrapKeyGen(
    const PrivateKey<DCRTPoly> privateKey, uint32_t slots) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(privateKey->GetCryptoParameters());

    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW("CKKS Bootstrapping is only supported for the Hybrid key switching method.");
#if NATIVEINT == 128
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        OPENFHE_THROW("128-bit CKKS Bootstrapping is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
#endif

    auto cc   = privateKey->GetCryptoContext();
    auto algo = cc->GetScheme();
    auto M    = cc->GetCyclotomicOrder();

    if (slots == 0)
        slots = M / 4;

    // computing all indices for baby-step giant-step procedure
    auto evalKeys = algo->EvalAtIndexKeyGen(nullptr, privateKey, FindBootstrapRotationIndices(slots, M));

    auto conjKey       = ConjugateKeyGen(privateKey);
    (*evalKeys)[M - 1] = conjKey;

    if (cryptoParams->GetSecretKeyDist() == SPARSE_ENCAPSULATED) {
        DCRTPoly::TugType tug;
        DCRTPoly sNew(tug, cryptoParams->GetElementParams(), Format::EVALUATION, 32);

        // sparse key used for the modraising step
        auto skNew = std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc);
        skNew->SetPrivateElement(std::move(sNew));

        // we reserve M-4 and M-2 for the sparse encapsulation switching keys
        // Even autorphism indices are not possible, so there will not be any conflict
        (*evalKeys)[M - 4] = KeySwitchGenSparse(privateKey, skNew);
        (*evalKeys)[M - 2] = algo->KeySwitchGen(skNew, privateKey);
    }

    return evalKeys;
}

void FHECKKSRNS::EvalBootstrapPrecompute(const CryptoContextImpl<DCRTPoly>& cc, uint32_t numSlots) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW("CKKS Bootstrapping is only supported for the Hybrid key switching method.");
#if NATIVEINT == 128
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        OPENFHE_THROW("128-bit CKKS Bootstrapping is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
#endif

    uint32_t M     = cc.GetCyclotomicOrder();
    uint32_t slots = (numSlots == 0) ? M / 4 : numSlots;

    auto& p = GetBootPrecom(slots);
    std::vector<uint32_t> dim1{p.m_dim1, static_cast<uint32_t>(p.m_paramsDec[CKKS_BOOT_PARAMS::GIANT_STEP])};
    std::vector<uint32_t> newBudget{static_cast<uint32_t>(p.m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET]),
                                    static_cast<uint32_t>(p.m_paramsDec[CKKS_BOOT_PARAMS::LEVEL_BUDGET])};
    p.m_paramsEnc = GetCollapsedFFTParams(slots, newBudget[0], dim1[0]);
    p.m_paramsDec = GetCollapsedFFTParams(slots, newBudget[1], dim1[1]);

    uint32_t m     = 4 * slots;
    uint32_t mmask = m - 1;  // assumes m is power of 2
    bool isSparse  = (M != m);

    // computes indices for all primitive roots of unity
    std::vector<uint32_t> rotGroup(slots);
    uint32_t fivePows = 1;
    for (uint32_t i = 0; i < slots; ++i) {
        rotGroup[i] = fivePows;
        fivePows *= 5;
        fivePows &= mmask;
    }

    // computes all powers of a primitive root of unity exp(2 * M_PI/m)
    std::vector<std::complex<double>> ksiPows(m + 1);
    double ak = 2 * M_PI / m;
    for (uint32_t j = 0; j < m; ++j) {
        double angle = ak * j;
        ksiPows[j].real(std::cos(angle));
        ksiPows[j].imag(std::sin(angle));
    }
    ksiPows[m] = ksiPows[0];

    double k;
    switch (cryptoParams->GetSecretKeyDist()) {
        case UNIFORM_TERNARY:
            k = 1.0;
            break;
        case SPARSE_TERNARY:
            k = K_SPARSE;
            break;
        case SPARSE_ENCAPSULATED:
            k = K_SPARSE_ENCAPSULATED;
            break;
        default:
            OPENFHE_THROW("Unsupported SecretKeyDist.");
    }

    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    double qDouble  = GetBigModulus(cryptoParams);
    double factor   = static_cast<uint128_t>(1) << static_cast<uint32_t>(std::round(std::log2(qDouble)));
    double pre      = (compositeDegree > 1) ? 1.0 : qDouble / factor;
    double scaleEnc = pre / k;
    // TODO: YSP Can be extended to FLEXIBLE* scaling techniques as well as the closeness of 2^p to moduli is no longer needed
    double scaleDec = (compositeDegree > 1) ? qDouble / cryptoParams->GetScalingFactorReal(0) : 1.0 / pre;

    uint32_t approxModDepth = GetModDepthInternal(cryptoParams->GetSecretKeyDist());

    uint32_t depthBT =
        approxModDepth + p.m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET] + p.m_paramsDec[CKKS_BOOT_PARAMS::LEVEL_BUDGET];

    // compute # of levels to remain when encoding the coefficients
    // for FLEXIBLEAUTOEXT we do not need extra modulus in auxiliary plaintexts
    auto st     = cryptoParams->GetScalingTechnique();
    uint32_t L0 = cryptoParams->GetElementParams()->GetParams().size() - (st == FLEXIBLEAUTOEXT);

    uint32_t lEnc = L0 - compositeDegree * (p.m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET] + 1);
    uint32_t lDec = L0 - compositeDegree * depthBT;

    bool isLTBootstrap =
        (p.m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET] == 1) && (p.m_paramsDec[CKKS_BOOT_PARAMS::LEVEL_BUDGET] == 1);

    if (isLTBootstrap) {
        // allocate all vectors
        std::vector<std::vector<std::complex<double>>> U0(slots, std::vector<std::complex<double>>(slots));
        std::vector<std::vector<std::complex<double>>> U1(slots, std::vector<std::complex<double>>(slots));
        std::vector<std::vector<std::complex<double>>> U0hatT(slots, std::vector<std::complex<double>>(slots));
        std::vector<std::vector<std::complex<double>>> U1hatT(slots, std::vector<std::complex<double>>(slots));

        for (size_t i = 0; i < slots; i++) {
            for (size_t j = 0; j < slots; j++) {
                U0[i][j]     = ksiPows[(j * rotGroup[i]) & mmask];
                U0hatT[j][i] = std::conj(U0[i][j]);
                U1[i][j]     = std::complex<double>(0, 1) * U0[i][j];
                U1hatT[j][i] = std::conj(U1[i][j]);
            }
        }

        if (!isSparse) {
            p.m_U0hatTPre = EvalLinearTransformPrecompute(cc, U0hatT, scaleEnc, lEnc);
            p.m_U0Pre     = EvalLinearTransformPrecompute(cc, U0, scaleDec, lDec);
        }
        else {
            p.m_U0hatTPre = EvalLinearTransformPrecompute(cc, U0hatT, U1hatT, 0, scaleEnc, lEnc);
            p.m_U0Pre     = EvalLinearTransformPrecompute(cc, U0, U1, 1, scaleDec, lDec);
        }
    }
    else {
        p.m_U0hatTPreFFT = EvalCoeffsToSlotsPrecompute(cc, ksiPows, rotGroup, false, scaleEnc, lEnc);
        p.m_U0PreFFT     = EvalSlotsToCoeffsPrecompute(cc, ksiPows, rotGroup, false, scaleDec, lDec);
    }
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalBootstrap(ConstCiphertext<DCRTPoly>& ciphertext, uint32_t numIterations,
                                               uint32_t precision) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW("CKKS Bootstrapping only supported with Hybrid key switching.");
    auto st = cryptoParams->GetScalingTechnique();
#if NATIVEINT == 128
    if (st == FLEXIBLEAUTO || st == FLEXIBLEAUTOEXT)
        OPENFHE_THROW("128-bit CKKS Bootstrapping only supported for FIXEDMANUAL and FIXEDAUTO.");
#endif
    if (numIterations != 1 && numIterations != 2)
        OPENFHE_THROW("CKKS Bootstrapping only supported for 1 or 2 iterations.");

#ifdef BOOTSTRAPTIMING
    TimeVar t;
    double timeEncode(0.0);
    double timeModReduce(0.0);
    double timeDecode(0.0);
#endif

    auto cc                  = ciphertext->GetCryptoContext();
    uint32_t L0              = cryptoParams->GetElementParams()->GetParams().size();
    auto initSizeQ           = ciphertext->GetElements()[0].GetNumOfElements();
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    if (numIterations > 1) {
        // Step 1: Get the input.
        uint32_t powerOfTwoModulus = 1 << precision;

        // Step 2: Scale up by powerOfTwoModulus, and extend the modulus to powerOfTwoModulus * q.
        // Note that we extend the modulus implicitly without any code calls because the value always stays 0.
        // We multiply by powerOfTwoModulus, and leave the last CRT value to be 0 (mod powerOfTwoModulus).
        auto ctScaledUp = cc->EvalMultNoCheck(ciphertext, powerOfTwoModulus);
        ctScaledUp->SetLevel(L0 - ctScaledUp->GetElements()[0].GetNumOfElements());

        // Step 3: Bootstrap the initial ciphertext.
        auto ctInitialBootstrap = cc->EvalBootstrap(ciphertext, numIterations - 1, precision);
        cc->GetScheme()->ModReduceInternalInPlace(ctInitialBootstrap, compositeDegree);

        // Step 4: Scale up by powerOfTwoModulus.
        cc->GetScheme()->MultByIntegerInPlace(ctInitialBootstrap, powerOfTwoModulus);

        // Step 5: Mod-down to powerOfTwoModulus * q
        // We mod down, and leave the last CRT value to be 0 because it's divisible by powerOfTwoModulus.
        auto ctBootstrappedScaledDown = ctInitialBootstrap->Clone();
        auto bootstrappingSizeQ       = ctBootstrappedScaledDown->GetElements()[0].GetNumOfElements();

        // If we start with more towers, than we obtain from bootstrapping, return the original ciphertext.
        if (bootstrappingSizeQ <= initSizeQ) {
            return ciphertext->Clone();
        }

        // TODO: YSP Can be removed for FLEXIBLE* scaling techniques as well as the closeness of 2^p to moduli is no longer needed
        if (st != COMPOSITESCALINGAUTO && st != COMPOSITESCALINGMANUAL) {
            for (auto& cv : ctBootstrappedScaledDown->GetElements())
                cv.DropLastElements(bootstrappingSizeQ - initSizeQ);
            ctBootstrappedScaledDown->SetLevel(L0 - ctBootstrappedScaledDown->GetElements()[0].GetNumOfElements());
        }

        // Step 6 and 7: Calculate the bootstrapping error by subtracting the original ciphertext from the bootstrapped ciphertext. Mod down to q is done implicitly.
        auto ctBootstrappingError = cc->EvalSub(ctBootstrappedScaledDown, ctScaledUp);

        // Step 8: Bootstrap the error.
        auto ctBootstrappedError = cc->EvalBootstrap(ctBootstrappingError, 1, 0);
        cc->GetScheme()->ModReduceInternalInPlace(ctBootstrappedError, compositeDegree);

        // Step 9: Subtract the bootstrapped error from the initial bootstrap to get even lower error.
        auto finalCiphertext = cc->EvalSub(ctInitialBootstrap, ctBootstrappedError);

        // Step 10: Scale back down by powerOfTwoModulus to get the original message.
        cc->EvalMultInPlace(finalCiphertext, 1.0 / powerOfTwoModulus);
        return finalCiphertext;
    }

    uint32_t slots = ciphertext->GetSlots();

    auto elementParamsRaised = *(cryptoParams->GetElementParams());
    // For FLEXIBLEAUTOEXT we raised ciphertext does not include extra modulus
    // as it is multiplied by auxiliary plaintext
    if (st == FLEXIBLEAUTOEXT)
        elementParamsRaised.PopLastParam();

    auto paramsQ   = elementParamsRaised.GetParams();
    uint32_t sizeQ = paramsQ.size();
    std::vector<NativeInteger> moduli(sizeQ);
    std::vector<NativeInteger> roots(sizeQ);
    for (uint32_t i = 0; i < sizeQ; ++i) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i]  = paramsQ[i]->GetRootOfUnity();
    }
    auto elementParamsRaisedPtr =
        std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(cc->GetCyclotomicOrder(), moduli, roots);

    double qDouble = GetBigModulus(cryptoParams);
    double powP    = std::pow(2, cryptoParams->GetPlaintextModulus());
    int32_t deg    = std::round(std::log2(qDouble / powP));
#if NATIVEINT != 128
    if (deg > static_cast<int32_t>(m_correctionFactor) && st != COMPOSITESCALINGAUTO && st != COMPOSITESCALINGMANUAL) {
        OPENFHE_THROW("Degree [" + std::to_string(deg) + "] must be less than or equal to the correction factor [" +
                      std::to_string(m_correctionFactor) + "].");
    }
#endif
    uint32_t correction = m_correctionFactor - deg;
    double post         = std::pow(2, static_cast<double>(deg));

    // TODO: YSP Can be extended to FLEXIBLE* scaling techniques as well as the closeness of 2^p to moduli is no longer needed
    double pre      = (compositeDegree > 1) ? cryptoParams->GetScalingFactorReal(0) / qDouble : 1. / post;
    uint64_t scalar = std::llround(post);

    //------------------------------------------------------------------------------
    // RAISING THE MODULUS
    //------------------------------------------------------------------------------

    // In FLEXIBLEAUTO, raising the ciphertext to a larger number
    // of towers is a bit more complex, because we need to adjust
    // it's scaling factor to the one that corresponds to the level
    // it's being raised to.
    // Increasing the modulus

    auto raised = ciphertext->Clone();
    auto algo   = cc->GetScheme();
    algo->ModReduceInternalInPlace(raised, compositeDegree * (raised->GetNoiseScaleDeg() - 1));
    AdjustCiphertext(raised, correction);

    uint32_t N = cc->GetRingDimension();
    if (compositeDegree > 1) {
        // RNS basis extension from level 0 RNS limbs to the raised RNS basis
        auto& ctxtDCRT = raised->GetElements();
        ExtendCiphertext(ctxtDCRT, *cc, elementParamsRaisedPtr);
        raised->SetLevel(L0 - ctxtDCRT[0].GetNumOfElements());
    }
    else {
        if (cryptoParams->GetSecretKeyDist() == SPARSE_ENCAPSULATED) {
            auto evalKeyMap = cc->GetEvalAutomorphismKeyMap(raised->GetKeyTag());

            // transform from a denser secret to a sparser one
            raised = KeySwitchSparse(raised, evalKeyMap.at(2 * N - 4));

            // Only level 0 ciphertext used here. Other towers ignored to make CKKS bootstrapping faster.
            auto& ctxtDCRT = raised->GetElements();
            for (auto& poly : ctxtDCRT) {
                poly.SetFormat(COEFFICIENT);
                DCRTPoly temp(elementParamsRaisedPtr, COEFFICIENT);
                temp = poly.GetElementAtIndex(0);
                temp.SetFormat(EVALUATION);
                poly = std::move(temp);
            }
            raised->SetLevel(L0 - ctxtDCRT[0].GetNumOfElements());

            // go back to a denser secret
            algo->KeySwitchInPlace(raised, evalKeyMap.at(2 * N - 2));
        }
        else {
            // Only level 0 ciphertext used here. Other towers ignored to make CKKS bootstrapping faster.
            auto& ctxtDCRT = raised->GetElements();
            for (auto& poly : ctxtDCRT) {
                poly.SetFormat(COEFFICIENT);
                DCRTPoly temp(elementParamsRaisedPtr, COEFFICIENT);
                temp = poly.GetElementAtIndex(0);
                temp.SetFormat(EVALUATION);
                poly = std::move(temp);
            }
            raised->SetLevel(L0 - ctxtDCRT[0].GetNumOfElements());
        }
    }

#ifdef BOOTSTRAPTIMING
    std::cerr << "\nNumber of levels at the beginning of bootstrapping: "
              << raised->GetElements()[0].GetNumOfElements() - 1 << std::endl;
#endif

    //------------------------------------------------------------------------------
    // SETTING PARAMETERS FOR APPROXIMATE MODULAR REDUCTION
    //------------------------------------------------------------------------------

    // Coefficients of the Chebyshev series interpolating 1/(2 Pi) Sin(2 Pi K x)
    std::vector<double> coefficients;
    double k = 0;

    if (cryptoParams->GetSecretKeyDist() == SPARSE_TERNARY) {
        coefficients = g_coefficientsSparse;
        // k = K_SPARSE;
        k = 1.0;  // do not divide by k as we already did it during precomputation
    }
    else if (cryptoParams->GetSecretKeyDist() == SPARSE_ENCAPSULATED) {
        coefficients = g_coefficientsSparseEncapsulated;
        k            = 1.0;  // do not divide by k as we already did it during precomputation
    }
    else {
        // For larger composite degrees, larger K used to achieve a reasonable probability of failure
        if ((compositeDegree == 1) || ((compositeDegree == 2) && (N < (1 << 17)))) {
            coefficients = g_coefficientsUniform;
            k            = K_UNIFORM;
        }
        else {
            coefficients = g_coefficientsUniformExt;
            k            = K_UNIFORMEXT;
        }
    }

    cc->EvalMultInPlace(raised, pre * (1.0 / (k * N)));

    // no linear transformations are needed for Chebyshev series as the range has been normalized to [-1,1]
    double coeffLowerBound = -1;
    double coeffUpperBound = 1;

    auto& p = GetBootPrecom(slots);

    bool isLTBootstrap =
        (p.m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET] == 1) && (p.m_paramsDec[CKKS_BOOT_PARAMS::LEVEL_BUDGET] == 1);

    Ciphertext<DCRTPoly> ctxtDec;
    if (slots == cc->GetCyclotomicOrder() / 4) {
        //------------------------------------------------------------------------------
        // FULLY PACKED CASE
        //------------------------------------------------------------------------------

#ifdef BOOTSTRAPTIMING
        TIC(t);
#endif

        //------------------------------------------------------------------------------
        // Running CoeffToSlot
        //------------------------------------------------------------------------------

        // need to call internal modular reduction so it also works for FLEXIBLEAUTO
        algo->ModReduceInternalInPlace(raised, compositeDegree);

        // only one linear transform is needed as the other one can be derived
        auto ctxtEnc =
            (isLTBootstrap) ? EvalLinearTransform(p.m_U0hatTPre, raised) : EvalCoeffsToSlots(p.m_U0hatTPreFFT, raised);

        auto evalKeyMap = cc->GetEvalAutomorphismKeyMap(ctxtEnc->GetKeyTag());
        auto conj       = Conjugate(ctxtEnc, evalKeyMap);
        auto ctxtEncI   = cc->EvalSub(ctxtEnc, conj);
        algo->MultByMonomialInPlace(ctxtEncI, 3 * slots);
        cc->EvalAddInPlaceNoCheck(ctxtEnc, conj);

        if (st == FIXEDMANUAL) {
            while (ctxtEnc->GetNoiseScaleDeg() > 1) {
                cc->ModReduceInPlace(ctxtEnc);
                cc->ModReduceInPlace(ctxtEncI);
            }
        }
        else {
            if (ctxtEnc->GetNoiseScaleDeg() == 2) {
                algo->ModReduceInternalInPlace(ctxtEnc, compositeDegree);
                algo->ModReduceInternalInPlace(ctxtEncI, compositeDegree);
            }
        }

        //------------------------------------------------------------------------------
        // Running Approximate Mod Reduction
        //------------------------------------------------------------------------------

        // Evaluate Chebyshev series for the sine wave
        ctxtEnc  = cc->EvalChebyshevSeries(ctxtEnc, coefficients, coeffLowerBound, coeffUpperBound);
        ctxtEncI = cc->EvalChebyshevSeries(ctxtEncI, coefficients, coeffLowerBound, coeffUpperBound);

        // Double-angle iterations
        if (st != FIXEDMANUAL) {
            algo->ModReduceInternalInPlace(ctxtEnc, compositeDegree);
            algo->ModReduceInternalInPlace(ctxtEncI, compositeDegree);
        }
        uint32_t numIter;
        if (cryptoParams->GetSecretKeyDist() == UNIFORM_TERNARY)
            numIter = R_UNIFORM;
        else
            numIter = R_SPARSE;
        ApplyDoubleAngleIterations(ctxtEnc, numIter);
        ApplyDoubleAngleIterations(ctxtEncI, numIter);

        algo->MultByMonomialInPlace(ctxtEncI, slots);
        cc->EvalAddInPlaceNoCheck(ctxtEnc, ctxtEncI);

        if (st != COMPOSITESCALINGAUTO && st != COMPOSITESCALINGMANUAL) {
            // scale the message back up after Chebyshev interpolation
            algo->MultByIntegerInPlace(ctxtEnc, scalar);
        }

#ifdef BOOTSTRAPTIMING
        timeModReduce = TOC(t);
        std::cerr << "Approximate modular reduction time: " << timeModReduce / 1000.0 << " s" << std::endl;
        // Running SlotToCoeff
        TIC(t);
#endif

        //------------------------------------------------------------------------------
        // Running SlotToCoeff
        //------------------------------------------------------------------------------

        // In the case of FLEXIBLEAUTO, we need one extra tower
        // TODO: See if we can remove the extra level in FLEXIBLEAUTO
        if (st != FIXEDMANUAL)
            algo->ModReduceInternalInPlace(ctxtEnc, compositeDegree);

        // Only one linear transform is needed
        ctxtDec = (isLTBootstrap) ? EvalLinearTransform(p.m_U0Pre, ctxtEnc) : EvalSlotsToCoeffs(p.m_U0PreFFT, ctxtEnc);
    }
    else {
        //------------------------------------------------------------------------------
        // SPARSELY PACKED CASE
        //------------------------------------------------------------------------------

        //------------------------------------------------------------------------------
        // Running PartialSum
        //------------------------------------------------------------------------------

        for (uint32_t j = 1; j < N / (2 * slots); j <<= 1)
            cc->EvalAddInPlaceNoCheck(raised, cc->EvalRotate(raised, j * slots));

#ifdef BOOTSTRAPTIMING
        TIC(t);
#endif

        //------------------------------------------------------------------------------
        // Running CoeffsToSlots
        //------------------------------------------------------------------------------

        algo->ModReduceInternalInPlace(raised, compositeDegree);

        auto ctxtEnc =
            (isLTBootstrap) ? EvalLinearTransform(p.m_U0hatTPre, raised) : EvalCoeffsToSlots(p.m_U0hatTPreFFT, raised);

        auto evalKeyMap = cc->GetEvalAutomorphismKeyMap(ctxtEnc->GetKeyTag());
        auto conj       = Conjugate(ctxtEnc, evalKeyMap);
        cc->EvalAddInPlaceNoCheck(ctxtEnc, conj);

        if (st == FIXEDMANUAL) {
            while (ctxtEnc->GetNoiseScaleDeg() > 1) {
                cc->ModReduceInPlace(ctxtEnc);
            }
        }
        else {
            if (ctxtEnc->GetNoiseScaleDeg() == 2) {
                algo->ModReduceInternalInPlace(ctxtEnc, compositeDegree);
            }
        }

#ifdef BOOTSTRAPTIMING
        timeEncode = TOC(t);
        std::cerr << "\nEncoding time: " << timeEncode / 1000.0 << " s" << std::endl;
        // Running Approximate Mod Reduction
        TIC(t);
#endif

        //------------------------------------------------------------------------------
        // Running Approximate Mod Reduction
        //------------------------------------------------------------------------------

        // Evaluate Chebyshev series for the sine wave
        ctxtEnc = cc->EvalChebyshevSeries(ctxtEnc, coefficients, coeffLowerBound, coeffUpperBound);

        // Double-angle iterations
        if (st != FIXEDMANUAL)
            algo->ModReduceInternalInPlace(ctxtEnc, compositeDegree);
        uint32_t numIter = (cryptoParams->GetSecretKeyDist() == UNIFORM_TERNARY) ? R_UNIFORM : R_SPARSE;
        ApplyDoubleAngleIterations(ctxtEnc, numIter);

        // TODO: YSP Can be extended to FLEXIBLE* scaling techniques as well as the closeness of 2^p to moduli is no longer needed
        if (st != COMPOSITESCALINGAUTO && st != COMPOSITESCALINGMANUAL) {
            // scale the message back up after Chebyshev interpolation
            algo->MultByIntegerInPlace(ctxtEnc, scalar);
        }

#ifdef BOOTSTRAPTIMING
        timeModReduce = TOC(t);
        std::cerr << "Approximate modular reduction time: " << timeModReduce / 1000.0 << " s" << std::endl;
        // Running SlotToCoeff
        TIC(t);
#endif

        //------------------------------------------------------------------------------
        // Running SlotsToCoeffs
        //------------------------------------------------------------------------------

        // In the case of FLEXIBLEAUTO, we need one extra tower
        // TODO: See if we can remove the extra level in FLEXIBLEAUTO
        if (st != FIXEDMANUAL)
            algo->ModReduceInternalInPlace(ctxtEnc, compositeDegree);

        // linear transform for decoding
        ctxtDec = (isLTBootstrap) ? EvalLinearTransform(p.m_U0Pre, ctxtEnc) : EvalSlotsToCoeffs(p.m_U0PreFFT, ctxtEnc);
        cc->EvalAddInPlaceNoCheck(ctxtDec, cc->EvalRotate(ctxtDec, slots));
    }

#if NATIVEINT != 128
    // 64-bit only: scale back the message to its original scale.
    uint64_t corFactor = static_cast<uint64_t>(1) << std::llround(correction);
    algo->MultByIntegerInPlace(ctxtDec, corFactor);
#endif

#ifdef BOOTSTRAPTIMING
    timeDecode = TOC(t);

    std::cout << "Decoding time: " << timeDecode / 1000.0 << " s" << std::endl;
#endif

    // If we start with more towers, than we obtain from bootstrapping, return the original ciphertext.
    if (ctxtDec->GetElements()[0].GetNumOfElements() <= initSizeQ)
        return ciphertext->Clone();
    return ctxtDec;
}

//------------------------------------------------------------------------------
// Find Rotation Indices
//------------------------------------------------------------------------------

std::vector<int32_t> FHECKKSRNS::FindBootstrapRotationIndices(uint32_t slots, uint32_t M) {
    auto& p = GetBootPrecom(slots);
    bool isLTBootstrap =
        (p.m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET] == 1) && (p.m_paramsDec[CKKS_BOOT_PARAMS::LEVEL_BUDGET] == 1);

    std::vector<uint32_t> fullIndexList;
    if (isLTBootstrap) {
        fullIndexList = FindLinearTransformRotationIndices(slots, M);
    }
    else {
        fullIndexList = FindCoeffsToSlotsRotationIndices(slots, M);

        std::vector<uint32_t> indexListStC{FindSlotsToCoeffsRotationIndices(slots, M)};
        fullIndexList.insert(fullIndexList.end(), std::make_move_iterator(indexListStC.begin()),
                             std::make_move_iterator(indexListStC.end()));
    }

    // Remove possible duplicates and remove automorphisms corresponding to 0 and M/4 by using std::set
    std::set<uint32_t> s(fullIndexList.begin(), fullIndexList.end());
    s.erase(0);
    s.erase(M / 4);

    return std::vector<int32_t>(s.begin(), s.end());
}

// ATTN: This function is a helper methods to be called in FindBootstrapRotationIndices() only.
// so it DOES NOT remove possible duplicates and automorphisms corresponding to 0 and M/4.
// This method completely depends on FindBootstrapRotationIndices() to do that.
std::vector<uint32_t> FHECKKSRNS::FindLinearTransformRotationIndices(uint32_t slots, uint32_t M) {
    // Computing the baby-step g and the giant-step h.
    auto& p    = GetBootPrecom(slots);
    uint32_t g = (p.m_dim1 == 0) ? static_cast<uint32_t>(std::ceil(std::sqrt(slots))) : p.m_dim1;
    uint32_t h = static_cast<uint32_t>(std::ceil(static_cast<double>(slots) / g));

    std::vector<uint32_t> indexList;
    // To avoid overflowing uint32_t variables, we do some math operations below in a specific order
    // computing all indices for baby-step giant-step procedure
    int32_t indexListSz = static_cast<int32_t>(g) + h + M - 2;
    if (indexListSz < 0)
        OPENFHE_THROW("indexListSz can not be negative");

    indexList.reserve(indexListSz);
    for (size_t i = 1; i <= g; ++i)
        indexList.emplace_back(i);
    for (size_t i = 2; i < h; ++i)
        indexList.emplace_back(g * i);

    // additional automorphisms are needed for sparse bootstrapping
    uint32_t m = slots * 4;
    if (m != M) {
        for (size_t j = 1; j < M / m; j <<= 1) {
            indexList.emplace_back(j * slots);
        }
    }

    return indexList;
}

// ATTN: This function is a helper methods to be called in FindBootstrapRotationIndices() only.
// so it DOES NOT remove possible duplicates and automorphisms corresponding to 0 and M/4.
// This method completely depends on FindBootstrapRotationIndices() to do that.
std::vector<uint32_t> FHECKKSRNS::FindCoeffsToSlotsRotationIndices(uint32_t slots, uint32_t M) {
    auto& p = GetBootPrecom(slots);

    uint32_t levelBudget     = p.m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET];
    uint32_t layersCollapse  = p.m_paramsEnc[CKKS_BOOT_PARAMS::LAYERS_COLL];
    uint32_t remCollapse     = p.m_paramsEnc[CKKS_BOOT_PARAMS::LAYERS_REM];
    uint32_t numRotations    = p.m_paramsEnc[CKKS_BOOT_PARAMS::NUM_ROTATIONS];
    uint32_t b               = p.m_paramsEnc[CKKS_BOOT_PARAMS::BABY_STEP];
    uint32_t g               = p.m_paramsEnc[CKKS_BOOT_PARAMS::GIANT_STEP];
    uint32_t numRotationsRem = p.m_paramsEnc[CKKS_BOOT_PARAMS::NUM_ROTATIONS_REM];
    uint32_t bRem            = p.m_paramsEnc[CKKS_BOOT_PARAMS::BABY_STEP_REM];
    uint32_t gRem            = p.m_paramsEnc[CKKS_BOOT_PARAMS::GIANT_STEP_REM];

    uint32_t flagRem = (remCollapse == 0) ? 0 : 1;

    std::vector<uint32_t> indexList;
    // To avoid overflowing uint32_t variables, we do some math operations below in a specific order
    // Computing all indices for baby-step giant-step procedure for encoding and decoding
    int32_t indexListSz = static_cast<int32_t>(b) + g - 2 + bRem + gRem - 2 + 1 + M;
    if (indexListSz < 0)
        OPENFHE_THROW("indexListSz can not be negative");
    indexList.reserve(indexListSz);

    for (int32_t s = static_cast<int32_t>(levelBudget) - 1; s >= static_cast<int32_t>(flagRem); --s) {
        const uint32_t scalingFactor = 1U << ((s - flagRem) * layersCollapse + remCollapse);
        const int32_t halfRots       = (1 - (numRotations + 1) / 2);
        for (int32_t j = halfRots; j < static_cast<int32_t>(g + halfRots); ++j) {
            indexList.emplace_back(ReduceRotation(j * scalingFactor, slots));
        }
        for (size_t i = 0; i < b; i++) {
            indexList.emplace_back(ReduceRotation((g * i) * scalingFactor, M / 4));
        }
    }

    if (flagRem) {
        const int32_t halfRots = (1 - (numRotationsRem + 1) / 2);
        for (int32_t j = halfRots; j < static_cast<int32_t>(gRem + halfRots); ++j) {
            indexList.emplace_back(ReduceRotation(j, slots));
        }
        for (size_t i = 0; i < bRem; i++) {
            indexList.emplace_back(ReduceRotation(gRem * i, M / 4));
        }
    }

    uint32_t m = slots * 4;
    // additional automorphisms are needed for sparse bootstrapping
    if (m != M) {
        for (size_t j = 1; j < M / m; j <<= 1) {
            indexList.emplace_back(j * slots);
        }
    }

    return indexList;
}

std::vector<uint32_t> FHECKKSRNS::FindSlotsToCoeffsRotationIndices(uint32_t slots, uint32_t M) {
    auto& p = GetBootPrecom(slots);

    uint32_t levelBudget     = p.m_paramsDec[CKKS_BOOT_PARAMS::LEVEL_BUDGET];
    uint32_t layersCollapse  = p.m_paramsDec[CKKS_BOOT_PARAMS::LAYERS_COLL];
    uint32_t remCollapse     = p.m_paramsDec[CKKS_BOOT_PARAMS::LAYERS_REM];
    uint32_t numRotations    = p.m_paramsDec[CKKS_BOOT_PARAMS::NUM_ROTATIONS];
    uint32_t b               = p.m_paramsDec[CKKS_BOOT_PARAMS::BABY_STEP];
    uint32_t g               = p.m_paramsDec[CKKS_BOOT_PARAMS::GIANT_STEP];
    uint32_t numRotationsRem = p.m_paramsDec[CKKS_BOOT_PARAMS::NUM_ROTATIONS_REM];
    uint32_t bRem            = p.m_paramsDec[CKKS_BOOT_PARAMS::BABY_STEP_REM];
    uint32_t gRem            = p.m_paramsDec[CKKS_BOOT_PARAMS::GIANT_STEP_REM];

    uint32_t flagRem = (remCollapse == 0) ? 0 : 1;
    if (levelBudget < flagRem)
        OPENFHE_THROW("levelBudget can not be less than flagRem");

    std::vector<uint32_t> indexList;
    // To avoid overflowing uint32_t variables, we do some math operations below in a specific order
    // Computing all indices for baby-step giant-step procedure for encoding and decoding
    int32_t indexListSz = static_cast<int32_t>(b) + g - 2 + bRem + gRem - 2 + 1 + M;
    if (indexListSz < 0)
        OPENFHE_THROW("indexListSz can not be negative");
    indexList.reserve(indexListSz);

    for (size_t s = 0; s < (levelBudget - flagRem); ++s) {
        const uint32_t scalingFactor = 1U << (s * layersCollapse);
        const int32_t halfRots       = (1 - (numRotations + 1) / 2);
        for (int32_t j = halfRots; j < static_cast<int32_t>(g + halfRots); ++j) {
            indexList.emplace_back(ReduceRotation(j * scalingFactor, M / 4));
        }
        for (size_t i = 0; i < b; ++i) {
            indexList.emplace_back(ReduceRotation((g * i) * scalingFactor, M / 4));
        }
    }

    if (flagRem) {
        uint32_t s                   = levelBudget - flagRem;
        const uint32_t scalingFactor = 1U << (s * layersCollapse);
        const int32_t halfRots       = (1 - (numRotationsRem + 1) / 2);
        for (int32_t j = halfRots; j < static_cast<int32_t>(gRem + halfRots); ++j) {
            indexList.emplace_back(ReduceRotation(j * scalingFactor, M / 4));
        }
        for (size_t i = 0; i < bRem; ++i) {
            indexList.emplace_back(ReduceRotation((gRem * i) * scalingFactor, M / 4));
        }
    }

    uint32_t m = slots * 4;
    // additional automorphisms are needed for sparse bootstrapping
    if (m != M) {
        for (size_t j = 1; j < M / m; j <<= 1) {
            indexList.emplace_back(j * slots);
        }
    }

    return indexList;
}

//------------------------------------------------------------------------------
// Precomputations for CoeffsToSlots and SlotsToCoeffs
//------------------------------------------------------------------------------

std::vector<ReadOnlyPlaintext> FHECKKSRNS::EvalLinearTransformPrecompute(
    const CryptoContextImpl<DCRTPoly>& cc, const std::vector<std::vector<std::complex<double>>>& A, double scale,
    uint32_t L) const {
    uint32_t slots = A.size();
    if (slots != A[0].size())
        OPENFHE_THROW("The matrix passed to EvalLTPrecompute is not square");

    // make sure the plaintext is created only with the necessary amount of moduli
    auto cryptoParams     = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());
    auto compositeDegree  = cryptoParams->GetCompositeDegree();
    auto elementParams    = *(cryptoParams->GetElementParams());
    uint32_t towersToDrop = (L == 0) ? 0 : elementParams.GetParams().size() - L - compositeDegree;
    for (uint32_t i = 0; i < towersToDrop; ++i)
        elementParams.PopLastParam();

    auto paramsQ   = elementParams.GetParams();
    uint32_t sizeQ = paramsQ.size();
    auto paramsP   = cryptoParams->GetParamsP()->GetParams();
    uint32_t sizeP = paramsP.size();
    std::vector<NativeInteger> moduli(sizeQ + sizeP);
    std::vector<NativeInteger> roots(sizeQ + sizeP);
    for (uint32_t i = 0; i < sizeQ; ++i) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i]  = paramsQ[i]->GetRootOfUnity();
    }
    for (uint32_t i = 0; i < sizeP; ++i) {
        moduli[sizeQ + i] = paramsP[i]->GetModulus();
        roots[sizeQ + i]  = paramsP[i]->GetRootOfUnity();
    }
    auto elementParamsPtr = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(cc.GetCyclotomicOrder(), moduli, roots);

    // Computing the baby-step bStep and the giant-step gStep.
    auto& p   = GetBootPrecom(slots);
    int bStep = (p.m_dim1 == 0) ? std::ceil(std::sqrt(slots)) : p.m_dim1;
    int gStep = std::ceil(static_cast<double>(slots) / bStep);

    std::vector<ReadOnlyPlaintext> result(slots);
// parallelizing the loop (below) with OMP causes a segfault on MinGW
// see https://github.com/openfheorg/openfhe-development/issues/176
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for
#endif
    for (int j = 0; j < gStep; j++) {
        int offset = -bStep * j;
        for (int i = 0; i < bStep; i++) {
            if (bStep * j + i < static_cast<int>(slots)) {
                auto diag = ExtractShiftedDiagonal(A, bStep * j + i);
                for (uint32_t k = 0; k < diag.size(); k++)
                    diag[k] *= scale;

                result[bStep * j + i] =
                    MakeAuxPlaintext(cc, elementParamsPtr, Rotate(diag, offset), 1, towersToDrop, diag.size());
            }
        }
    }
    return result;
}

std::vector<ReadOnlyPlaintext> FHECKKSRNS::EvalLinearTransformPrecompute(
    const CryptoContextImpl<DCRTPoly>& cc, const std::vector<std::vector<std::complex<double>>>& A,
    const std::vector<std::vector<std::complex<double>>>& B, uint32_t orientation, double scale, uint32_t L) const {
    // make sure the plaintext is created only with the necessary amount of moduli
    const auto cryptoParams  = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();
    auto elementParams       = *(cryptoParams->GetElementParams());

    uint32_t towersToDrop = (L == 0) ? 0 : elementParams.GetParams().size() - L - compositeDegree;
    for (uint32_t i = 0; i < towersToDrop; ++i)
        elementParams.PopLastParam();

    auto paramsQ   = elementParams.GetParams();
    uint32_t sizeQ = paramsQ.size();
    auto paramsP   = cryptoParams->GetParamsP()->GetParams();
    uint32_t sizeP = paramsP.size();
    std::vector<NativeInteger> moduli(sizeQ + sizeP);
    std::vector<NativeInteger> roots(sizeQ + sizeP);
    for (uint32_t i = 0; i < sizeQ; ++i) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i]  = paramsQ[i]->GetRootOfUnity();
    }
    for (uint32_t i = 0; i < sizeP; ++i) {
        moduli[sizeQ + i] = paramsP[i]->GetModulus();
        roots[sizeQ + i]  = paramsP[i]->GetRootOfUnity();
    }
    auto elementParamsPtr = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(cc.GetCyclotomicOrder(), moduli, roots);

    uint32_t slots = A.size();

    // Computing the baby-step bStep and the giant-step gStep.
    auto& p   = GetBootPrecom(slots);
    int bStep = (p.m_dim1 == 0) ? ceil(sqrt(slots)) : p.m_dim1;
    int gStep = ceil(static_cast<double>(slots) / bStep);

    std::vector<ReadOnlyPlaintext> result(slots);

    if (orientation == 0) {
        // vertical concatenation - used during homomorphic encoding
        // #pragma omp parallel for
        for (int j = 0; j < gStep; j++) {
            int offset = -bStep * j;
            for (int i = 0; i < bStep; i++) {
                if (bStep * j + i < static_cast<int>(slots)) {
                    auto vecA = ExtractShiftedDiagonal(A, bStep * j + i);
                    auto vecB = ExtractShiftedDiagonal(B, bStep * j + i);

                    vecA.insert(vecA.end(), vecB.begin(), vecB.end());
                    for (uint32_t k = 0; k < vecA.size(); k++)
                        vecA[k] *= scale;

                    result[bStep * j + i] =
                        MakeAuxPlaintext(cc, elementParamsPtr, Rotate(vecA, offset), 1, towersToDrop, vecA.size());
                }
            }
        }
    }
    else {
        // horizontal concatenation - used during homomorphic decoding
        std::vector<std::vector<std::complex<double>>> newA(slots);

        //  A and B are concatenated horizontally
        for (uint32_t i = 0; i < slots; ++i) {
            newA[i].reserve(A[i].size() + B[i].size());
            newA[i].insert(newA[i].end(), A[i].begin(), A[i].end());
            newA[i].insert(newA[i].end(), B[i].begin(), B[i].end());
        }

#pragma omp parallel for
        for (int j = 0; j < gStep; j++) {
            int offset = -bStep * j;
            for (int i = 0; i < bStep; i++) {
                if (bStep * j + i < static_cast<int>(slots)) {
                    // shifted diagonal is computed for rectangular map newA of dimension
                    // slots x 2*slots
                    auto vec = ExtractShiftedDiagonal(newA, bStep * j + i);
                    for (uint32_t k = 0; k < vec.size(); k++)
                        vec[k] *= scale;

                    result[bStep * j + i] =
                        MakeAuxPlaintext(cc, elementParamsPtr, Rotate(vec, offset), 1, towersToDrop, vec.size());
                }
            }
        }
    }

    return result;
}

std::vector<std::vector<ReadOnlyPlaintext>> FHECKKSRNS::EvalCoeffsToSlotsPrecompute(
    const CryptoContextImpl<DCRTPoly>& cc, const std::vector<std::complex<double>>& A,
    const std::vector<uint32_t>& rotGroup, bool flag_i, double scale, uint32_t L) const {
    uint32_t slots = rotGroup.size();

    auto& p = GetBootPrecom(slots);

    int32_t levelBudget     = p.m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET];
    int32_t layersCollapse  = p.m_paramsEnc[CKKS_BOOT_PARAMS::LAYERS_COLL];
    int32_t remCollapse     = p.m_paramsEnc[CKKS_BOOT_PARAMS::LAYERS_REM];
    int32_t numRotations    = p.m_paramsEnc[CKKS_BOOT_PARAMS::NUM_ROTATIONS];
    int32_t b               = p.m_paramsEnc[CKKS_BOOT_PARAMS::BABY_STEP];
    int32_t g               = p.m_paramsEnc[CKKS_BOOT_PARAMS::GIANT_STEP];
    int32_t numRotationsRem = p.m_paramsEnc[CKKS_BOOT_PARAMS::NUM_ROTATIONS_REM];
    int32_t bRem            = p.m_paramsEnc[CKKS_BOOT_PARAMS::BABY_STEP_REM];
    int32_t gRem            = p.m_paramsEnc[CKKS_BOOT_PARAMS::GIANT_STEP_REM];

    int32_t stop    = -1;
    int32_t flagRem = 0;

    if (remCollapse != 0) {
        stop    = 0;
        flagRem = 1;
    }

    // result is the rotated plaintext version of the coefficients
    std::vector<std::vector<ReadOnlyPlaintext>> result(levelBudget, std::vector<ReadOnlyPlaintext>(numRotations));
    if (flagRem == 1 && levelBudget >= 1) {
        // remainder corresponds to index 0 in encoding and to last index in decoding
        result[0].resize(numRotationsRem);
    }

    // make sure the plaintext is created only with the necessary amount of moduli
    const auto cryptoParams  = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    auto elementParams = *(cryptoParams->GetElementParams());

    uint32_t towersToDrop = (L == 0) ? 0 : elementParams.GetParams().size() - L - compositeDegree * levelBudget;
    for (uint32_t i = 0; i < towersToDrop; ++i)
        elementParams.PopLastParam();

    uint32_t level0 = towersToDrop + compositeDegree * (levelBudget - 1);

    auto paramsQ   = elementParams.GetParams();
    uint32_t sizeQ = paramsQ.size();
    auto paramsP   = cryptoParams->GetParamsP()->GetParams();
    uint32_t sizeP = paramsP.size();

    std::vector<NativeInteger> moduli(sizeQ + sizeP);
    std::vector<NativeInteger> roots(sizeQ + sizeP);
    for (uint32_t i = 0; i < sizeQ; ++i) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i]  = paramsQ[i]->GetRootOfUnity();
    }

    for (uint32_t i = 0; i < sizeP; ++i) {
        moduli[sizeQ + i] = paramsP[i]->GetModulus();
        roots[sizeQ + i]  = paramsP[i]->GetRootOfUnity();
    }

    // we need to pre-compute the plaintexts in the extended basis P*Q
    uint32_t M = cc.GetCyclotomicOrder();
    std::vector<std::shared_ptr<ILDCRTParams<BigInteger>>> paramsVector(levelBudget - stop);
    for (int32_t s = levelBudget - 1; s >= stop; s--) {
        paramsVector[s - stop] = std::make_shared<ILDCRTParams<BigInteger>>(M, moduli, roots);
        for (uint32_t j = 0; j < compositeDegree; ++j, --sizeQ) {
            moduli.erase(moduli.begin() + sizeQ - 1);
            roots.erase(roots.begin() + sizeQ - 1);
        }
    }

    if (slots == M / 4) {
        //------------------------------------------------------------------------------
        // fully-packed mode
        //------------------------------------------------------------------------------

        auto coeff = CoeffEncodingCollapse(A, rotGroup, levelBudget, flag_i);

        for (int32_t s = levelBudget - 1; s > stop; s--) {
            for (int32_t i = 0; i < b; i++) {
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for
#endif
                for (int32_t j = 0; j < g; j++) {
                    if (g * i + j != static_cast<int32_t>(numRotations)) {
                        uint32_t rot =
                            ReduceRotation(-g * i * (1 << ((s - flagRem) * layersCollapse + remCollapse)), slots);
                        if ((flagRem == 0) && (s == stop + 1)) {
                            // do the scaling only at the last set of coefficients
                            for (uint32_t k = 0; k < slots; k++) {
                                coeff[s][g * i + j][k] *= scale;
                            }
                        }

                        auto rotateTemp = Rotate(coeff[s][g * i + j], rot);

                        result[s][g * i + j] = MakeAuxPlaintext(cc, paramsVector[s - stop], rotateTemp, 1,
                                                                level0 - compositeDegree * s, rotateTemp.size());
                    }
                }
            }
        }

        if (flagRem) {
            for (int32_t i = 0; i < bRem; i++) {
#pragma omp parallel for
                for (int32_t j = 0; j < gRem; j++) {
                    if (gRem * i + j != static_cast<int32_t>(numRotationsRem)) {
                        uint32_t rot = ReduceRotation(-gRem * i, slots);
                        for (uint32_t k = 0; k < slots; k++) {
                            coeff[stop][gRem * i + j][k] *= scale;
                        }

                        auto rotateTemp = Rotate(coeff[stop][gRem * i + j], rot);
                        result[stop][gRem * i + j] =
                            MakeAuxPlaintext(cc, paramsVector[0], rotateTemp, 1, level0, rotateTemp.size());
                    }
                }
            }
        }
    }
    else {
        //------------------------------------------------------------------------------
        // sparsely-packed mode
        //------------------------------------------------------------------------------

        auto coeff  = CoeffEncodingCollapse(A, rotGroup, levelBudget, false);
        auto coeffi = CoeffEncodingCollapse(A, rotGroup, levelBudget, true);

        for (int32_t s = levelBudget - 1; s > stop; s--) {
            for (int32_t i = 0; i < b; i++) {
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for
#endif
                for (int32_t j = 0; j < g; j++) {
                    if (g * i + j != static_cast<int32_t>(numRotations)) {
                        uint32_t rot =
                            ReduceRotation(-g * i * (1 << ((s - flagRem) * layersCollapse + remCollapse)), M / 4);
                        // concatenate the coefficients horizontally on their third dimension, which corresponds to the # of slots
                        auto clearTemp  = coeff[s][g * i + j];
                        auto clearTempi = coeffi[s][g * i + j];
                        clearTemp.insert(clearTemp.end(), clearTempi.begin(), clearTempi.end());
                        if ((flagRem == 0) && (s == stop + 1)) {
                            // do the scaling only at the last set of coefficients
                            for (uint32_t k = 0; k < clearTemp.size(); k++) {
                                clearTemp[k] *= scale;
                            }
                        }

                        auto rotateTemp      = Rotate(clearTemp, rot);
                        result[s][g * i + j] = MakeAuxPlaintext(cc, paramsVector[s - stop], rotateTemp, 1,
                                                                level0 - compositeDegree * s, rotateTemp.size());
                    }
                }
            }
        }

        if (flagRem) {
            for (int32_t i = 0; i < bRem; i++) {
#pragma omp parallel for
                for (int32_t j = 0; j < gRem; j++) {
                    if (gRem * i + j != static_cast<int32_t>(numRotationsRem)) {
                        uint32_t rot = ReduceRotation(-gRem * i, M / 4);
                        // concatenate the coefficients on their third dimension, which corresponds to the # of slots
                        auto clearTemp  = coeff[stop][gRem * i + j];
                        auto clearTempi = coeffi[stop][gRem * i + j];
                        clearTemp.insert(clearTemp.end(), clearTempi.begin(), clearTempi.end());
                        for (uint32_t k = 0; k < clearTemp.size(); k++) {
                            clearTemp[k] *= scale;
                        }

                        auto rotateTemp = Rotate(clearTemp, rot);
                        result[stop][gRem * i + j] =
                            MakeAuxPlaintext(cc, paramsVector[0], rotateTemp, 1, level0, rotateTemp.size());
                    }
                }
            }
        }
    }
    return result;
}

std::vector<std::vector<ReadOnlyPlaintext>> FHECKKSRNS::EvalSlotsToCoeffsPrecompute(
    const CryptoContextImpl<DCRTPoly>& cc, const std::vector<std::complex<double>>& A,
    const std::vector<uint32_t>& rotGroup, bool flag_i, double scale, uint32_t L) const {
    uint32_t slots = rotGroup.size();

    auto& p = GetBootPrecom(slots);

    int32_t levelBudget     = p.m_paramsDec[CKKS_BOOT_PARAMS::LEVEL_BUDGET];
    int32_t layersCollapse  = p.m_paramsDec[CKKS_BOOT_PARAMS::LAYERS_COLL];
    int32_t remCollapse     = p.m_paramsDec[CKKS_BOOT_PARAMS::LAYERS_REM];
    int32_t numRotations    = p.m_paramsDec[CKKS_BOOT_PARAMS::NUM_ROTATIONS];
    int32_t b               = p.m_paramsDec[CKKS_BOOT_PARAMS::BABY_STEP];
    int32_t g               = p.m_paramsDec[CKKS_BOOT_PARAMS::GIANT_STEP];
    int32_t numRotationsRem = p.m_paramsDec[CKKS_BOOT_PARAMS::NUM_ROTATIONS_REM];
    int32_t bRem            = p.m_paramsDec[CKKS_BOOT_PARAMS::BABY_STEP_REM];
    int32_t gRem            = p.m_paramsDec[CKKS_BOOT_PARAMS::GIANT_STEP_REM];

    int32_t flagRem = (remCollapse == 0) ? 0 : 1;

    // result is the rotated plaintext version of coeff
    std::vector<std::vector<ReadOnlyPlaintext>> result(levelBudget, std::vector<ReadOnlyPlaintext>(numRotations));
    if (flagRem == 1 && levelBudget >= 1) {
        // remainder corresponds to index 0 in encoding and to last index in decoding
        result[levelBudget - 1].resize(numRotationsRem);
    }

    // make sure the plaintext is created only with the necessary amount of moduli

    const auto cryptoParams  = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();
    auto elementParams       = *(cryptoParams->GetElementParams());

    uint32_t towersToDrop = (L == 0) ? 0 : elementParams.GetParams().size() - L - compositeDegree * levelBudget;
    for (uint32_t i = 0; i < towersToDrop; ++i)
        elementParams.PopLastParam();

    uint32_t level0 = towersToDrop;

    auto paramsQ   = elementParams.GetParams();
    uint32_t sizeQ = paramsQ.size();
    auto paramsP   = cryptoParams->GetParamsP()->GetParams();
    uint32_t sizeP = paramsP.size();
    std::vector<NativeInteger> moduli(sizeQ + sizeP);
    std::vector<NativeInteger> roots(sizeQ + sizeP);
    for (uint32_t i = 0; i < sizeQ; ++i) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i]  = paramsQ[i]->GetRootOfUnity();
    }
    for (uint32_t i = 0; i < sizeP; ++i) {
        moduli[sizeQ + i] = paramsP[i]->GetModulus();
        roots[sizeQ + i]  = paramsP[i]->GetRootOfUnity();
    }

    // we need to pre-compute the plaintexts in the extended basis P*Q
    std::vector<std::shared_ptr<ILDCRTParams<BigInteger>>> paramsVector(levelBudget - flagRem + 1);
    for (int32_t s = 0; s < levelBudget - flagRem + 1; ++s) {
        paramsVector[s] = std::make_shared<ILDCRTParams<BigInteger>>(cc.GetCyclotomicOrder(), moduli, roots);
        for (uint32_t i = 0; i < compositeDegree; ++i, --sizeQ) {
            moduli.erase(moduli.begin() + sizeQ - 1);
            roots.erase(roots.begin() + sizeQ - 1);
        }
    }

    uint32_t M4 = cc.GetCyclotomicOrder() / 4;
    if (slots == M4) {
        // fully-packed
        auto coeff = CoeffDecodingCollapse(A, rotGroup, levelBudget, flag_i);

        for (int32_t s = 0; s < levelBudget - flagRem; s++) {
            for (int32_t i = 0; i < b; i++) {
#pragma omp parallel for
                for (int32_t j = 0; j < g; j++) {
                    if (g * i + j != static_cast<int32_t>(numRotations)) {
                        uint32_t rot = ReduceRotation(-g * i * (1 << (s * layersCollapse)), slots);
                        if ((flagRem == 0) && (s == levelBudget - flagRem - 1)) {
                            // do the scaling only at the last set of coefficients
                            for (uint32_t k = 0; k < slots; k++) {
                                coeff[s][g * i + j][k] *= scale;
                            }
                        }

                        auto rotateTemp      = Rotate(coeff[s][g * i + j], rot);
                        result[s][g * i + j] = MakeAuxPlaintext(cc, paramsVector[s], rotateTemp, 1,
                                                                level0 + compositeDegree * s, rotateTemp.size());
                    }
                }
            }
        }

        if (flagRem) {
            int32_t s = levelBudget - flagRem;
            for (int32_t i = 0; i < bRem; i++) {
#pragma omp parallel for
                for (int32_t j = 0; j < gRem; j++) {
                    if (gRem * i + j != static_cast<int32_t>(numRotationsRem)) {
                        uint32_t rot = ReduceRotation(-gRem * i * (1 << (s * layersCollapse)), slots);
                        for (uint32_t k = 0; k < slots; k++) {
                            coeff[s][gRem * i + j][k] *= scale;
                        }

                        auto rotateTemp         = Rotate(coeff[s][gRem * i + j], rot);
                        result[s][gRem * i + j] = MakeAuxPlaintext(cc, paramsVector[s], rotateTemp, 1,
                                                                   level0 + compositeDegree * s, rotateTemp.size());
                    }
                }
            }
        }
    }
    else {
        //------------------------------------------------------------------------------
        // sparsely-packed mode
        //------------------------------------------------------------------------------

        auto coeff  = CoeffDecodingCollapse(A, rotGroup, levelBudget, false);
        auto coeffi = CoeffDecodingCollapse(A, rotGroup, levelBudget, true);

        for (int32_t s = 0; s < levelBudget - flagRem; s++) {
            for (int32_t i = 0; i < b; i++) {
#pragma omp parallel for
                for (int32_t j = 0; j < g; j++) {
                    if (g * i + j != static_cast<int32_t>(numRotations)) {
                        uint32_t rot = ReduceRotation(-g * i * (1 << (s * layersCollapse)), M4);
                        // concatenate the coefficients horizontally on their third dimension, which corresponds to the # of slots
                        auto clearTemp  = coeff[s][g * i + j];
                        auto clearTempi = coeffi[s][g * i + j];
                        clearTemp.insert(clearTemp.end(), clearTempi.begin(), clearTempi.end());
                        if ((flagRem == 0) && (s == levelBudget - flagRem - 1)) {
                            // do the scaling only at the last set of coefficients
                            for (uint32_t k = 0; k < clearTemp.size(); k++) {
                                clearTemp[k] *= scale;
                            }
                        }

                        auto rotateTemp      = Rotate(clearTemp, rot);
                        result[s][g * i + j] = MakeAuxPlaintext(cc, paramsVector[s], rotateTemp, 1,
                                                                level0 + compositeDegree * s, rotateTemp.size());
                    }
                }
            }
        }

        if (flagRem) {
            int32_t s = levelBudget - flagRem;
            for (int32_t i = 0; i < bRem; i++) {
#pragma omp parallel for
                for (int32_t j = 0; j < gRem; j++) {
                    if (gRem * i + j != static_cast<int32_t>(numRotationsRem)) {
                        uint32_t rot = ReduceRotation(-gRem * i * (1 << (s * layersCollapse)), M4);
                        // concatenate the coefficients horizontally on their third dimension, which corresponds to the # of slots
                        auto clearTemp  = coeff[s][gRem * i + j];
                        auto clearTempi = coeffi[s][gRem * i + j];
                        clearTemp.insert(clearTemp.end(), clearTempi.begin(), clearTempi.end());
                        for (uint32_t k = 0; k < clearTemp.size(); k++) {
                            clearTemp[k] *= scale;
                        }

                        auto rotateTemp         = Rotate(clearTemp, rot);
                        result[s][gRem * i + j] = MakeAuxPlaintext(cc, paramsVector[s], rotateTemp, 1,
                                                                   level0 + compositeDegree * s, rotateTemp.size());
                    }
                }
            }
        }
    }
    return result;
}

//------------------------------------------------------------------------------
// EVALUATION: CoeffsToSlots and SlotsToCoeffs
//------------------------------------------------------------------------------

Ciphertext<DCRTPoly> FHECKKSRNS::EvalLinearTransform(const std::vector<ReadOnlyPlaintext>& A,
                                                     ConstCiphertext<DCRTPoly>& ct) const {
    // Computing the baby-step bStep and the giant-step gStep.
    uint32_t slots = A.size();
    auto& p        = GetBootPrecom(slots);
    uint32_t bStep = (p.m_dim1 == 0) ? ceil(sqrt(slots)) : p.m_dim1;
    uint32_t gStep = ceil(static_cast<double>(slots) / bStep);

    auto cc    = ct->GetCryptoContext();
    uint32_t M = cc->GetCyclotomicOrder();
    uint32_t N = cc->GetRingDimension();

    // computes the NTTs for each CRT limb (for the hoisted automorphisms used
    // later on)
    auto digits = cc->EvalFastRotationPrecompute(ct);

    std::vector<Ciphertext<DCRTPoly>> fastRotation(bStep - 1);

    // hoisted automorphisms
#pragma omp parallel for
    for (uint32_t j = 1; j < bStep; ++j)
        fastRotation[j - 1] = cc->EvalFastRotationExt(ct, j, digits, true);

    Ciphertext<DCRTPoly> result;
    DCRTPoly first;
    for (uint32_t j = 0; j < gStep; ++j) {
        auto inner = EvalMultExt(cc->KeySwitchExt(ct, true), A[bStep * j]);
        for (uint32_t i = 1; i < bStep; ++i) {
            if (bStep * j + i < slots)
                EvalAddExtInPlace(inner, EvalMultExt(fastRotation[i - 1], A[bStep * j + i]));
        }

        if (j == 0) {
            first         = cc->KeySwitchDownFirstElement(inner);
            auto elements = inner->GetElements();
            elements[0].SetValuesToZero();
            inner->SetElements(std::move(elements));
            result = std::move(inner);
        }
        else {
            inner = cc->KeySwitchDown(inner);
            // Find the automorphism index that corresponds to rotation index index.
            uint32_t autoIndex = FindAutomorphismIndex2nComplex(bStep * j, M);
            std::vector<uint32_t> map(N);
            PrecomputeAutoMap(N, autoIndex, &map);
            first += inner->GetElements()[0].AutomorphismTransform(autoIndex, map);

            auto&& innerDigits = cc->EvalFastRotationPrecompute(inner);
            EvalAddExtInPlace(result, cc->EvalFastRotationExt(inner, bStep * j, innerDigits, false));
        }
    }
    result = cc->KeySwitchDown(result);
    result->GetElements()[0] += first;
    return result;
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalCoeffsToSlots(const std::vector<std::vector<ReadOnlyPlaintext>>& A,
                                                   ConstCiphertext<DCRTPoly>& ctxt) const {
    uint32_t slots = ctxt->GetSlots();

    auto& p = GetBootPrecom(slots);

    int32_t levelBudget     = p.m_paramsEnc[CKKS_BOOT_PARAMS::LEVEL_BUDGET];
    int32_t layersCollapse  = p.m_paramsEnc[CKKS_BOOT_PARAMS::LAYERS_COLL];
    int32_t remCollapse     = p.m_paramsEnc[CKKS_BOOT_PARAMS::LAYERS_REM];
    int32_t numRotations    = p.m_paramsEnc[CKKS_BOOT_PARAMS::NUM_ROTATIONS];
    int32_t b               = p.m_paramsEnc[CKKS_BOOT_PARAMS::BABY_STEP];
    int32_t g               = p.m_paramsEnc[CKKS_BOOT_PARAMS::GIANT_STEP];
    int32_t numRotationsRem = p.m_paramsEnc[CKKS_BOOT_PARAMS::NUM_ROTATIONS_REM];
    int32_t bRem            = p.m_paramsEnc[CKKS_BOOT_PARAMS::BABY_STEP_REM];
    int32_t gRem            = p.m_paramsEnc[CKKS_BOOT_PARAMS::GIANT_STEP_REM];

    int32_t stop    = -1;
    int32_t flagRem = 0;

    auto cc                  = ctxt->GetCryptoContext();
    auto algo                = cc->GetScheme();
    const auto cryptoParams  = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    if (remCollapse != 0) {
        stop    = 0;
        flagRem = 1;
    }

    // precompute the inner and outer rotations
    std::vector<std::vector<int32_t>> rot_in(levelBudget, std::vector<int32_t>(numRotations + 1));
    if (flagRem == 1) {
        // remainder corresponds to index 0 in encoding and to last index in decoding
        rot_in[0].resize(numRotationsRem + 1);
    }
    std::vector<std::vector<int32_t>> rot_out(levelBudget, std::vector<int32_t>(b + bRem));

    uint32_t M = cc->GetCyclotomicOrder();
    for (int32_t s = levelBudget - 1; s > stop; --s) {
        for (int32_t j = 0; j < g; ++j) {
            rot_in[s][j] = ReduceRotation((j - static_cast<int32_t>((numRotations + 1) / 2) + 1) *
                                              (1 << ((s - flagRem) * layersCollapse + remCollapse)),
                                          slots);
        }
        for (int32_t i = 0; i < b; ++i)
            rot_out[s][i] = ReduceRotation((g * i) * (1 << ((s - flagRem) * layersCollapse + remCollapse)), M / 4);
    }

    if (flagRem) {
        for (int32_t j = 0; j < gRem; ++j)
            rot_in[stop][j] = ReduceRotation((j - static_cast<int32_t>((numRotationsRem + 1) / 2) + 1), slots);
        for (int32_t i = 0; i < bRem; ++i)
            rot_out[stop][i] = ReduceRotation((gRem * i), M / 4);
    }

    uint32_t N  = cc->GetRingDimension();
    auto result = ctxt->Clone();

    // hoisted automorphisms
    for (int32_t s = levelBudget - 1; s > stop; --s) {
        if (s != levelBudget - 1)
            algo->ModReduceInternalInPlace(result, compositeDegree);

        // computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
        auto digits = cc->EvalFastRotationPrecompute(result);

        std::vector<Ciphertext<DCRTPoly>> fastRotation(g);
#pragma omp parallel for
        for (int32_t j = 0; j < g; j++) {
            if (rot_in[s][j] != 0)
                fastRotation[j] = cc->EvalFastRotationExt(result, rot_in[s][j], digits, true);
            else
                fastRotation[j] = cc->KeySwitchExt(result, true);
        }

        Ciphertext<DCRTPoly> outer;
        DCRTPoly first;
        for (int32_t i = 0; i < b; i++) {
            // for the first iteration with j=0:
            int32_t G  = g * i;
            auto inner = EvalMultExt(fastRotation[0], A[s][G]);
            // continue the loop
            for (int32_t j = 1; j < g; ++j) {
                if ((G + j) != static_cast<int32_t>(numRotations))
                    EvalAddExtInPlace(inner, EvalMultExt(fastRotation[j], A[s][G + j]));
            }

            if (i == 0) {
                first         = cc->KeySwitchDownFirstElement(inner);
                auto elements = inner->GetElements();
                elements[0].SetValuesToZero();
                inner->SetElements(std::move(elements));
                outer = std::move(inner);
            }
            else {
                if (rot_out[s][i] != 0) {
                    inner = cc->KeySwitchDown(inner);
                    // Find the automorphism index that corresponds to rotation index index.
                    uint32_t autoIndex = FindAutomorphismIndex2nComplex(rot_out[s][i], M);
                    std::vector<uint32_t> map(N);
                    PrecomputeAutoMap(N, autoIndex, &map);
                    first += inner->GetElements()[0].AutomorphismTransform(autoIndex, map);
                    auto&& innerDigits = cc->EvalFastRotationPrecompute(inner);
                    EvalAddExtInPlace(outer, cc->EvalFastRotationExt(inner, rot_out[s][i], innerDigits, false));
                }
                else {
                    first += cc->KeySwitchDownFirstElement(inner);
                    auto elements = inner->GetElements();
                    elements[0].SetValuesToZero();
                    inner->SetElements(std::move(elements));
                    EvalAddExtInPlace(outer, inner);
                }
            }
        }
        result = cc->KeySwitchDown(outer);
        result->GetElements()[0] += first;
    }

    if (flagRem) {
        algo->ModReduceInternalInPlace(result, compositeDegree);

        // computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
        auto digits = cc->EvalFastRotationPrecompute(result);
        std::vector<Ciphertext<DCRTPoly>> fastRotation(gRem);

#pragma omp parallel for
        for (int32_t j = 0; j < gRem; ++j) {
            if (rot_in[stop][j] != 0)
                fastRotation[j] = cc->EvalFastRotationExt(result, rot_in[stop][j], digits, true);
            else
                fastRotation[j] = cc->KeySwitchExt(result, true);
        }

        Ciphertext<DCRTPoly> outer;
        DCRTPoly first;
        for (int32_t i = 0; i < bRem; i++) {
            // for the first iteration with j=0:
            int32_t GRem = gRem * i;
            auto inner   = EvalMultExt(fastRotation[0], A[stop][GRem]);
            // continue the loop
            for (int32_t j = 1; j < gRem; ++j) {
                if ((GRem + j) != static_cast<int32_t>(numRotationsRem))
                    EvalAddExtInPlace(inner, EvalMultExt(fastRotation[j], A[stop][GRem + j]));
            }

            if (i == 0) {
                first         = cc->KeySwitchDownFirstElement(inner);
                auto elements = inner->GetElements();
                elements[0].SetValuesToZero();
                inner->SetElements(std::move(elements));
                outer = std::move(inner);
            }
            else {
                if (rot_out[stop][i] != 0) {
                    inner = cc->KeySwitchDown(inner);
                    // Find the automorphism index that corresponds to rotation index index.
                    uint32_t autoIndex = FindAutomorphismIndex2nComplex(rot_out[stop][i], M);
                    std::vector<uint32_t> map(N);
                    PrecomputeAutoMap(N, autoIndex, &map);
                    first += inner->GetElements()[0].AutomorphismTransform(autoIndex, map);
                    auto&& innerDigits = cc->EvalFastRotationPrecompute(inner);
                    EvalAddExtInPlace(outer, cc->EvalFastRotationExt(inner, rot_out[stop][i], innerDigits, false));
                }
                else {
                    first += cc->KeySwitchDownFirstElement(inner);
                    auto elements = inner->GetElements();
                    elements[0].SetValuesToZero();
                    inner->SetElements(std::move(elements));
                    EvalAddExtInPlace(outer, inner);
                }
            }
        }
        result = cc->KeySwitchDown(outer);
        result->GetElements()[0] += first;
    }
    return result;
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalSlotsToCoeffs(const std::vector<std::vector<ReadOnlyPlaintext>>& A,
                                                   ConstCiphertext<DCRTPoly>& ctxt) const {
    uint32_t slots = ctxt->GetSlots();

    auto& p = GetBootPrecom(slots);

    int32_t levelBudget     = p.m_paramsDec[CKKS_BOOT_PARAMS::LEVEL_BUDGET];
    int32_t layersCollapse  = p.m_paramsDec[CKKS_BOOT_PARAMS::LAYERS_COLL];
    int32_t remCollapse     = p.m_paramsDec[CKKS_BOOT_PARAMS::LAYERS_REM];
    int32_t numRotations    = p.m_paramsDec[CKKS_BOOT_PARAMS::NUM_ROTATIONS];
    int32_t b               = p.m_paramsDec[CKKS_BOOT_PARAMS::BABY_STEP];
    int32_t g               = p.m_paramsDec[CKKS_BOOT_PARAMS::GIANT_STEP];
    int32_t numRotationsRem = p.m_paramsDec[CKKS_BOOT_PARAMS::NUM_ROTATIONS_REM];
    int32_t bRem            = p.m_paramsDec[CKKS_BOOT_PARAMS::BABY_STEP_REM];
    int32_t gRem            = p.m_paramsDec[CKKS_BOOT_PARAMS::GIANT_STEP_REM];

    auto cc                  = ctxt->GetCryptoContext();
    auto algo                = cc->GetScheme();
    const auto cryptoParams  = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    int32_t flagRem = (remCollapse == 0) ? 0 : 1;

    // precompute the inner and outer rotations
    std::vector<std::vector<int32_t>> rot_in(levelBudget, std::vector<int32_t>(numRotations + 1));
    if (flagRem == 1) {
        // remainder corresponds to index 0 in encoding and to last index in decoding
        rot_in[levelBudget - 1].resize(numRotationsRem + 1);
    }
    std::vector<std::vector<int32_t>> rot_out(levelBudget, std::vector<int32_t>(b + bRem));

    uint32_t M = cc->GetCyclotomicOrder();
    for (int32_t s = 0; s < levelBudget - flagRem; ++s) {
        for (int32_t j = 0; j < g; ++j)
            rot_in[s][j] = ReduceRotation(
                (j - static_cast<int32_t>((numRotations + 1) / 2) + 1) * (1 << (s * layersCollapse)), M / 4);
        for (int32_t i = 0; i < b; i++)
            rot_out[s][i] = ReduceRotation((g * i) * (1 << (s * layersCollapse)), M / 4);
    }

    if (flagRem) {
        int32_t s = levelBudget - flagRem;
        for (int32_t j = 0; j < gRem; ++j)
            rot_in[s][j] = ReduceRotation(
                (j - static_cast<int32_t>((numRotationsRem + 1) / 2) + 1) * (1 << (s * layersCollapse)), M / 4);
        for (int32_t i = 0; i < bRem; ++i)
            rot_out[s][i] = ReduceRotation((gRem * i) * (1 << (s * layersCollapse)), M / 4);
    }

    //  No need for Encrypted Bit Reverse
    auto result = ctxt->Clone();
    uint32_t N  = cc->GetRingDimension();

    // hoisted automorphisms
    for (int32_t s = 0; s < levelBudget - flagRem; ++s) {
        if (s != 0)
            algo->ModReduceInternalInPlace(result, compositeDegree);

        // computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
        auto digits = cc->EvalFastRotationPrecompute(result);

        std::vector<Ciphertext<DCRTPoly>> fastRotation(g);
#pragma omp parallel for
        for (int32_t j = 0; j < g; ++j) {
            if (rot_in[s][j] != 0)
                fastRotation[j] = cc->EvalFastRotationExt(result, rot_in[s][j], digits, true);
            else
                fastRotation[j] = cc->KeySwitchExt(result, true);
        }

        Ciphertext<DCRTPoly> outer;
        DCRTPoly first;
        for (int32_t i = 0; i < b; ++i) {
            // for the first iteration with j=0:
            int32_t G  = g * i;
            auto inner = EvalMultExt(fastRotation[0], A[s][G]);
            // continue the loop
            for (int32_t j = 1; j < g; ++j) {
                if ((G + j) != static_cast<int32_t>(numRotations))
                    EvalAddExtInPlace(inner, EvalMultExt(fastRotation[j], A[s][G + j]));
            }

            if (i == 0) {
                first         = cc->KeySwitchDownFirstElement(inner);
                auto elements = inner->GetElements();
                elements[0].SetValuesToZero();
                inner->SetElements(std::move(elements));
                outer = std::move(inner);
            }
            else {
                if (rot_out[s][i] != 0) {
                    inner = cc->KeySwitchDown(inner);
                    // Find the automorphism index that corresponds to rotation index index.
                    uint32_t autoIndex = FindAutomorphismIndex2nComplex(rot_out[s][i], M);
                    std::vector<uint32_t> map(N);
                    PrecomputeAutoMap(N, autoIndex, &map);
                    first += inner->GetElements()[0].AutomorphismTransform(autoIndex, map);
                    auto&& innerDigits = cc->EvalFastRotationPrecompute(inner);
                    EvalAddExtInPlace(outer, cc->EvalFastRotationExt(inner, rot_out[s][i], innerDigits, false));
                }
                else {
                    first += cc->KeySwitchDownFirstElement(inner);
                    auto elements = inner->GetElements();
                    elements[0].SetValuesToZero();
                    inner->SetElements(std::move(elements));
                    EvalAddExtInPlace(outer, inner);
                }
            }
        }
        result = cc->KeySwitchDown(outer);
        result->GetElements()[0] += first;
    }

    if (flagRem) {
        algo->ModReduceInternalInPlace(result, compositeDegree);
        // computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
        auto digits = cc->EvalFastRotationPrecompute(result);
        std::vector<Ciphertext<DCRTPoly>> fastRotation(gRem);

        int32_t s = levelBudget - flagRem;
#pragma omp parallel for
        for (int32_t j = 0; j < gRem; ++j) {
            if (rot_in[s][j] != 0)
                fastRotation[j] = cc->EvalFastRotationExt(result, rot_in[s][j], digits, true);
            else
                fastRotation[j] = cc->KeySwitchExt(result, true);
        }

        Ciphertext<DCRTPoly> outer;
        DCRTPoly first;
        for (int32_t i = 0; i < bRem; i++) {
            // for the first iteration with j=0:
            int32_t GRem = gRem * i;
            auto inner   = EvalMultExt(fastRotation[0], A[s][GRem]);
            // continue the loop
            for (int32_t j = 1; j < gRem; ++j) {
                if ((GRem + j) != static_cast<int32_t>(numRotationsRem))
                    EvalAddExtInPlace(inner, EvalMultExt(fastRotation[j], A[s][GRem + j]));
            }

            if (i == 0) {
                first         = cc->KeySwitchDownFirstElement(inner);
                auto elements = inner->GetElements();
                elements[0].SetValuesToZero();
                inner->SetElements(std::move(elements));
                outer = std::move(inner);
            }
            else {
                if (rot_out[s][i] != 0) {
                    inner = cc->KeySwitchDown(inner);
                    // Find the automorphism index that corresponds to rotation index index.
                    uint32_t autoIndex = FindAutomorphismIndex2nComplex(rot_out[s][i], M);
                    std::vector<uint32_t> map(N);
                    PrecomputeAutoMap(N, autoIndex, &map);
                    first += inner->GetElements()[0].AutomorphismTransform(autoIndex, map);
                    auto innerDigits = cc->EvalFastRotationPrecompute(inner);
                    EvalAddExtInPlace(outer, cc->EvalFastRotationExt(inner, rot_out[s][i], innerDigits, false));
                }
                else {
                    first += cc->KeySwitchDownFirstElement(inner);
                    auto elements = inner->GetElements();
                    elements[0].SetValuesToZero();
                    inner->SetElements(std::move(elements));
                    EvalAddExtInPlace(outer, inner);
                }
            }
        }
        result = cc->KeySwitchDown(outer);
        result->GetElements()[0] += first;
    }
    return result;
}

uint32_t FHECKKSRNS::GetBootstrapDepth(uint32_t approxModDepth, const std::vector<uint32_t>& levelBudget,
                                       SecretKeyDist secretKeyDist) {
    if (secretKeyDist == UNIFORM_TERNARY)
        approxModDepth += R_UNIFORM - 1;
    return approxModDepth + levelBudget[0] + levelBudget[1];
}

uint32_t FHECKKSRNS::GetBootstrapDepth(const std::vector<uint32_t>& levelBudget, SecretKeyDist secretKeyDist) {
    uint32_t approxModDepth = GetModDepthInternal(secretKeyDist);
    return approxModDepth + levelBudget[0] + levelBudget[1];
}

//------------------------------------------------------------------------------
// Auxiliary Bootstrap Functions
//------------------------------------------------------------------------------
uint32_t FHECKKSRNS::GetBootstrapDepthInternal(uint32_t approxModDepth, const std::vector<uint32_t>& levelBudget,
                                               const CryptoContextImpl<DCRTPoly>& cc) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());
    return GetBootstrapDepth(approxModDepth, levelBudget, cryptoParams->GetSecretKeyDist());
}

uint32_t FHECKKSRNS::GetModDepthInternal(SecretKeyDist secretKeyDist) {
    if (secretKeyDist == UNIFORM_TERNARY)
        return GetMultiplicativeDepthByCoeffVector(g_coefficientsUniform, false) + R_UNIFORM;
    return GetMultiplicativeDepthByCoeffVector(g_coefficientsSparse, false) + R_SPARSE;
}

void FHECKKSRNS::AdjustCiphertext(Ciphertext<DCRTPoly>& ciphertext, double correction) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    auto cc                  = ciphertext->GetCryptoContext();
    auto algo                = cc->GetScheme();
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT ||
        cryptoParams->GetScalingTechnique() == COMPOSITESCALINGAUTO ||
        cryptoParams->GetScalingTechnique() == COMPOSITESCALINGMANUAL) {
        uint32_t lvl       = cryptoParams->GetScalingTechnique() != FLEXIBLEAUTOEXT ? 0 : 1;
        double targetSF    = cryptoParams->GetScalingFactorReal(lvl);
        double sourceSF    = ciphertext->GetScalingFactor();
        uint32_t numTowers = ciphertext->GetElements()[0].GetNumOfElements();
        double modToDrop = cryptoParams->GetElementParams()->GetParams()[numTowers - 1]->GetModulus().ConvertToDouble();
        for (uint32_t j = 2; j <= compositeDegree; ++j) {
            modToDrop *= cryptoParams->GetElementParams()->GetParams()[numTowers - j]->GetModulus().ConvertToDouble();
        }

        // in the case of FLEXIBLEAUTO, we need to bring the ciphertext to the right scale using a
        // a scaling multiplication. Note the at currently FLEXIBLEAUTO is only supported for NATIVEINT = 64.
        // So the other branch is for future purposes (in case we decide to add add the FLEXIBLEAUTO support
        // for NATIVEINT = 128.
#if NATIVEINT != 128
        // Scaling down the message by a correction factor to emulate using a larger q0.
        // This step is needed so we could use a scaling factor of up to 2^59 with q9 ~= 2^60.
        double adjustmentFactor = (targetSF / sourceSF) * (modToDrop / sourceSF) * std::pow(2, -correction);
#else
        double adjustmentFactor = (targetSF / sourceSF) * (modToDrop / sourceSF);
#endif
        cc->EvalMultInPlace(ciphertext, adjustmentFactor);

        algo->ModReduceInternalInPlace(ciphertext, compositeDegree);
        ciphertext->SetScalingFactor(targetSF);
    }
    else {
#if NATIVEINT != 128
        // Scaling down the message by a correction factor to emulate using a larger q0.
        // This step is needed so we could use a scaling factor of up to 2^59 with q9 ~= 2^60.
        cc->EvalMultInPlace(ciphertext, std::pow(2, -correction));
        algo->ModReduceInternalInPlace(ciphertext, compositeDegree);
#endif
    }
}

void FHECKKSRNS::AdjustCiphertextFBT(Ciphertext<DCRTPoly>& ciphertext, double correction) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        OPENFHE_THROW("This version of AdjustCiphertext is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
#if NATIVEINT != 128
    // Scaling down the message by a correction factor to emulate using a larger q0.
    // This step is needed so we could use a scaling factor of up to 2^59 with q9 ~= 2^60.
    auto cc = ciphertext->GetCryptoContext();
    cc->EvalMultInPlace(ciphertext, correction);
    cc->GetScheme()->ModReduceInternalInPlace(ciphertext, BASE_NUM_LEVELS_TO_DROP);
#endif
}

void FHECKKSRNS::ExtendCiphertext(std::vector<DCRTPoly>& ctxtDCRT, const CryptoContextImpl<DCRTPoly>& cc,
                                  const std::shared_ptr<DCRTPoly::Params> elementParamsRaisedPtr) const {
    // TODO: YSP We should be able to use one of the DCRTPoly methods for this; If not, we can define a new method there and use it here

    // CompositeDegree = 2: [a]_q0q1     =     [a*q1^-1]_q0 *     q1 + [a*q0^-1]_q1 *q0
    // CompositeDegree = 3: [a]_q0q1q2   =   [a*q1q2^-1]_q0 *   q1q2 + [a*q0q2^-1]_q1 *q0q2 + [a*q0q1^-1]_q2 *q0q1
    // CompositeDegree = 4: [a]_q0q1q2q3 = [a*q1q2q3^-1]_q0 * q1q2q3 + [a*q0q2q3^-1]_q1 * q0q2q3 + [a*q0q1q3^-1]_q2 * q0q1q3 + [a*q0q1q2^-1]_q3 * q0q1q2

    const auto cryptoParams  = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    std::vector<NativeInteger> qj(compositeDegree);
    for (uint32_t j = 0; j < compositeDegree; ++j) {
        qj[j] = elementParamsRaisedPtr->GetParams()[j]->GetModulus().ConvertToInt();
    }

    std::vector<NativeInteger> qhat_modqj(compositeDegree);
    qhat_modqj[0] = qj[1].Mod(qj[0]);
    qhat_modqj[1] = qj[0].Mod(qj[1]);

    std::vector<NativeInteger> qhat_inv_modqj(compositeDegree);

    for (uint32_t d = 2; d < compositeDegree; d++) {
        for (uint32_t j = 0; j < d; ++j) {
            qhat_modqj[j] = qj[d].ModMul(qhat_modqj[j], qj[j]);
        }
        qhat_modqj[d] = qj[1].ModMul(qj[0], qj[d]);
        for (uint32_t j = 2; j < d; ++j) {
            qhat_modqj[d] = qj[j].ModMul(qhat_modqj[d], qj[d]);
        }
    }

    for (uint32_t j = 0; j < compositeDegree; ++j) {
        qhat_inv_modqj[j] = qhat_modqj[j].ModInverse(qj[j]);
    }

    NativeInteger qjProduct =
        std::accumulate(qj.begin() + 1, qj.end(), NativeInteger{1}, std::multiplies<NativeInteger>());
    uint32_t init_element_index = compositeDegree;
    for (size_t i = 0; i < ctxtDCRT.size(); i++) {
        std::vector<DCRTPoly> temp(compositeDegree + 1, DCRTPoly(elementParamsRaisedPtr, COEFFICIENT));
        std::vector<DCRTPoly> ctxtDCRT_modq(compositeDegree, DCRTPoly(elementParamsRaisedPtr, COEFFICIENT));

        ctxtDCRT[i].SetFormat(COEFFICIENT);
        for (size_t j = 0; j < ctxtDCRT[i].GetNumOfElements(); j++) {
            for (size_t k = 0; k < compositeDegree; k++)
                ctxtDCRT_modq[k].SetElementAtIndex(j, ctxtDCRT[i].GetElementAtIndex(j) * qhat_inv_modqj[k]);
        }
        //=========================================================================================================
        temp[0] = ctxtDCRT_modq[0].GetElementAtIndex(0);
        for (auto& el : temp[0].GetAllElements()) {
            el *= qjProduct;
        }
        //=========================================================================================================
        for (size_t d = 1; d < compositeDegree; d++) {
            temp[init_element_index] = ctxtDCRT_modq[d].GetElementAtIndex(d);

            for (size_t k = 0; k < compositeDegree; k++) {
                if (k != d) {
                    temp[d].SetElementAtIndex(k, temp[0].GetElementAtIndex(k) * qj[k]);
                }
            }
            //=========================================================================================================
            NativeInteger qjProductD{1};
            for (size_t k = 0; k < compositeDegree; k++) {
                if (k != d)
                    qjProductD *= qj[k];
            }

            for (size_t j = compositeDegree; j < elementParamsRaisedPtr->GetParams().size(); j++) {
                auto value = temp[init_element_index].GetElementAtIndex(j) * qjProductD;
                temp[d].SetElementAtIndex(j, value);
            }
            //=========================================================================================================
            {
                auto value = temp[init_element_index].GetElementAtIndex(d) * qjProductD;
                temp[d].SetElementAtIndex(d, value);
            }
            //=========================================================================================================
            temp[0] += temp[d];
        }

        temp[0].SetFormat(EVALUATION);
        ctxtDCRT[i] = temp[0];
    }
}

void FHECKKSRNS::ApplyDoubleAngleIterations(Ciphertext<DCRTPoly>& ciphertext, uint32_t numIter) const {
    auto cc = ciphertext->GetCryptoContext();

    const int32_t r = numIter;
    for (int32_t j = 1; j <= r; ++j) {
        cc->EvalSquareInPlace(ciphertext);
        ciphertext    = cc->EvalAdd(ciphertext, ciphertext);
        double scalar = -1.0 / std::pow((2.0 * M_PI), std::pow(2.0, j - r));
        cc->EvalAddInPlace(ciphertext, scalar);
        cc->ModReduceInPlace(ciphertext);
    }
}

#if NATIVEINT == 128
Plaintext FHECKKSRNS::MakeAuxPlaintext(const CryptoContextImpl<DCRTPoly>& cc, const std::shared_ptr<ParmType> params,
                                       const std::vector<std::complex<double>>& value, size_t noiseScaleDeg,
                                       uint32_t level, uint32_t slots) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    double scFact = cryptoParams->GetScalingFactorReal(level);

    Plaintext p = Plaintext(std::make_shared<CKKSPackedEncoding>(params, cc.GetEncodingParams(), value, noiseScaleDeg,
                                                                 level, scFact, slots, COMPLEX));

    DCRTPoly& plainElement = p->GetElement<DCRTPoly>();

    uint32_t N = cc.GetRingDimension();

    std::vector<std::complex<double>> inverse = value;

    inverse.resize(slots);

    DiscreteFourierTransform::FFTSpecialInv(inverse, N * 2);
    uint64_t pBits = cc.GetEncodingParams()->GetPlaintextModulus();

    double powP      = std::pow(2.0, MAX_DOUBLE_PRECISION);
    int32_t pCurrent = pBits - MAX_DOUBLE_PRECISION;

    std::vector<int128_t> temp(2 * slots);
    for (size_t i = 0; i < slots; ++i) {
        // extract the mantissa of real part and multiply it by 2^52
        int32_t n1 = 0;
        double dre = std::frexp(inverse[i].real(), &n1) * powP;
        // extract the mantissa of imaginary part and multiply it by 2^52
        int32_t n2 = 0;
        double dim = std::frexp(inverse[i].imag(), &n2) * powP;

        // Check for possible overflow
        if (is128BitOverflow(dre) || is128BitOverflow(dim)) {
            DiscreteFourierTransform::FFTSpecial(inverse, N * 2);

            double invLen = static_cast<double>(inverse.size());
            double factor = 2 * M_PI * i;

            double realMax = -1, imagMax = -1;
            uint32_t realMaxIdx = -1, imagMaxIdx = -1;

            for (uint32_t idx = 0; idx < inverse.size(); idx++) {
                // exp( j*2*pi*n*k/N )
                std::complex<double> expFactor = {cos((factor * idx) / invLen), sin((factor * idx) / invLen)};

                // X[k] * exp( j*2*pi*n*k/N )
                std::complex<double> prodFactor = inverse[idx] * expFactor;

                double realVal = prodFactor.real();
                double imagVal = prodFactor.imag();

                if (realVal > realMax) {
                    realMax    = realVal;
                    realMaxIdx = idx;
                }
                if (imagVal > imagMax) {
                    imagMax    = imagVal;
                    imagMaxIdx = idx;
                }
            }

            auto scaledInputSize = ceil(log2(dre));

            std::stringstream buffer;
            buffer << std::endl
                   << "Overflow in data encoding - scaled input is too large to fit "
                      "into a NativeInteger (60 bits). Try decreasing scaling factor."
                   << std::endl;
            buffer << "Overflow at slot number " << i << std::endl;
            buffer << "- Max real part contribution from input[" << realMaxIdx << "]: " << realMax << std::endl;
            buffer << "- Max imaginary part contribution from input[" << imagMaxIdx << "]: " << imagMax << std::endl;
            buffer << "Scaling factor is " << ceil(log2(powP)) << " bits " << std::endl;
            buffer << "Scaled input is " << scaledInputSize << " bits " << std::endl;
            OPENFHE_THROW(buffer.str());
        }

        int64_t re64       = std::llround(dre);
        int32_t pRemaining = pCurrent + n1;
        int128_t re        = 0;
        if (pRemaining < 0) {
            re = re64 >> (-pRemaining);
        }
        else {
            int128_t pPowRemaining = ((int128_t)1) << pRemaining;
            re                     = pPowRemaining * re64;
        }

        int64_t im64 = std::llround(dim);
        pRemaining   = pCurrent + n2;
        int128_t im  = 0;
        if (pRemaining < 0) {
            im = im64 >> (-pRemaining);
        }
        else {
            int128_t pPowRemaining = (static_cast<int64_t>(1)) << pRemaining;
            im                     = pPowRemaining * im64;
        }

        temp[i]         = (re < 0) ? Max128BitValue() + re : re;
        temp[i + slots] = (im < 0) ? Max128BitValue() + im : im;

        if (is128BitOverflow(temp[i]) || is128BitOverflow(temp[i + slots])) {
            OPENFHE_THROW("Overflow, try to decrease scaling factor");
        }
    }

    const std::shared_ptr<ILDCRTParams<BigInteger>> bigParams        = plainElement.GetParams();
    const std::vector<std::shared_ptr<ILNativeParams>>& nativeParams = bigParams->GetParams();

    for (size_t i = 0; i < nativeParams.size(); i++) {
        NativeVector nativeVec(N, nativeParams[i]->GetModulus());
        FitToNativeVector(N, temp, Max128BitValue(), &nativeVec);
        NativePoly element = plainElement.GetElementAtIndex(i);
        element.SetValues(std::move(nativeVec), Format::COEFFICIENT);
        plainElement.SetElementAtIndex(i, std::move(element));
    }

    uint32_t numTowers = nativeParams.size();
    std::vector<DCRTPoly::Integer> moduli(numTowers);
    for (uint32_t i = 0; i < numTowers; i++) {
        moduli[i] = nativeParams[i]->GetModulus();
    }

    DCRTPoly::Integer intPowP = NativeInteger(1) << pBits;
    std::vector<DCRTPoly::Integer> crtPowP(numTowers, intPowP);

    auto currPowP = crtPowP;

    // We want to scale temp by 2^(pd), and the loop starts from j=2
    // because temp is already scaled by 2^p in the re/im loop above,
    // and currPowP already is 2^p.
    for (size_t i = 2; i < noiseScaleDeg; i++) {
        currPowP = CKKSPackedEncoding::CRTMult(currPowP, crtPowP, moduli);
    }

    if (noiseScaleDeg > 1) {
        plainElement = plainElement.Times(currPowP);
    }

    p->SetFormat(Format::EVALUATION);
    p->SetScalingFactor(pow(p->GetScalingFactor(), noiseScaleDeg));

    return p;
}
#else
Plaintext FHECKKSRNS::MakeAuxPlaintext(const CryptoContextImpl<DCRTPoly>& cc, const std::shared_ptr<ParmType> params,
                                       const std::vector<std::complex<double>>& value, size_t noiseScaleDeg,
                                       uint32_t level, uint32_t slots) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    double scFact = cryptoParams->GetScalingFactorReal(level);

    Plaintext p = Plaintext(std::make_shared<CKKSPackedEncoding>(params, cc.GetEncodingParams(), value, noiseScaleDeg,
                                                                 level, scFact, slots, COMPLEX));

    DCRTPoly& plainElement = p->GetElement<DCRTPoly>();

    uint32_t N = cc.GetRingDimension();

    std::vector<std::complex<double>> inverse = value;

    inverse.resize(slots);

    DiscreteFourierTransform::FFTSpecialInv(inverse, N * 2);
    double powP = scFact;

    // Compute approxFactor, a value to scale down by, in case the value exceeds a 64-bit integer.
    constexpr int32_t MAX_BITS_IN_WORD = 61;

    int32_t logc = std::numeric_limits<int32_t>::min();
    for (uint32_t i = 0; i < slots; ++i) {
        inverse[i] *= powP;
        if (inverse[i].real() != 0) {
            int32_t logci = static_cast<int32_t>(ceil(log2(std::abs(inverse[i].real()))));
            if (logc < logci)
                logc = logci;
        }
        if (inverse[i].imag() != 0) {
            int32_t logci = static_cast<int32_t>(ceil(log2(std::abs(inverse[i].imag()))));
            if (logc < logci)
                logc = logci;
        }
    }
    logc = (logc == std::numeric_limits<int32_t>::min()) ? 0 : logc;
    if (logc < 0)
        OPENFHE_THROW("Scaling factor too small");

    int32_t logValid    = (logc <= MAX_BITS_IN_WORD) ? logc : MAX_BITS_IN_WORD;
    int32_t logApprox   = logc - logValid;
    double approxFactor = pow(2, logApprox);

    std::vector<int64_t> temp(2 * slots);

    for (size_t i = 0; i < slots; ++i) {
        // Scale down by approxFactor in case the value exceeds a 64-bit integer.
        double dre = inverse[i].real() / approxFactor;
        double dim = inverse[i].imag() / approxFactor;

        // Check for possible overflow
        if (is64BitOverflow(dre) || is64BitOverflow(dim)) {
            DiscreteFourierTransform::FFTSpecial(inverse, N * 2);

            double invLen = static_cast<double>(inverse.size());
            double factor = 2 * M_PI * i;

            double realMax = -1, imagMax = -1;
            uint32_t realMaxIdx = -1, imagMaxIdx = -1;

            for (uint32_t idx = 0; idx < inverse.size(); idx++) {
                // exp( j*2*pi*n*k/N )
                std::complex<double> expFactor = {cos((factor * idx) / invLen), sin((factor * idx) / invLen)};

                // X[k] * exp( j*2*pi*n*k/N )
                std::complex<double> prodFactor = inverse[idx] * expFactor;

                double realVal = prodFactor.real();
                double imagVal = prodFactor.imag();

                if (realVal > realMax) {
                    realMax    = realVal;
                    realMaxIdx = idx;
                }
                if (imagVal > imagMax) {
                    imagMax    = imagVal;
                    imagMaxIdx = idx;
                }
            }

            auto scaledInputSize = ceil(log2(dre));

            std::stringstream buffer;
            buffer << std::endl
                   << "Overflow in data encoding - scaled input is too large to fit "
                      "into a NativeInteger (60 bits). Try decreasing scaling factor."
                   << std::endl;
            buffer << "Overflow at slot number " << i << std::endl;
            buffer << "- Max real part contribution from input[" << realMaxIdx << "]: " << realMax << std::endl;
            buffer << "- Max imaginary part contribution from input[" << imagMaxIdx << "]: " << imagMax << std::endl;
            buffer << "Scaling factor is " << ceil(log2(powP)) << " bits " << std::endl;
            buffer << "Scaled input is " << scaledInputSize << " bits " << std::endl;
            OPENFHE_THROW(buffer.str());
        }

        int64_t re = std::llround(dre);
        int64_t im = std::llround(dim);

        temp[i]         = (re < 0) ? Max64BitValue() + re : re;
        temp[i + slots] = (im < 0) ? Max64BitValue() + im : im;
    }

    const std::shared_ptr<ILDCRTParams<BigInteger>> bigParams        = plainElement.GetParams();
    const std::vector<std::shared_ptr<ILNativeParams>>& nativeParams = bigParams->GetParams();

    for (size_t i = 0; i < nativeParams.size(); i++) {
        NativeVector nativeVec(N, nativeParams[i]->GetModulus());
        FitToNativeVector(N, temp, Max64BitValue(), &nativeVec);
        NativePoly element = plainElement.GetElementAtIndex(i);
        element.SetValues(std::move(nativeVec), Format::COEFFICIENT);
        plainElement.SetElementAtIndex(i, std::move(element));
    }

    uint32_t numTowers = nativeParams.size();
    std::vector<DCRTPoly::Integer> moduli(numTowers);
    for (uint32_t i = 0; i < numTowers; i++) {
        moduli[i] = nativeParams[i]->GetModulus();
    }

    std::vector<DCRTPoly::Integer> crtPowP;
    if (cryptoParams->GetScalingTechnique() == COMPOSITESCALINGAUTO ||
        cryptoParams->GetScalingTechnique() == COMPOSITESCALINGMANUAL) {
        // Duhyeong: Support the case powP > 2^64
        //           Later we might need to use the NATIVE_INT=128 version of FHECKKSRNS::MakeAuxPlaintext for higher precision
        int32_t logPowP = static_cast<int32_t>(ceil(log2(fabs(powP))));

        if (logPowP > 64) {
            // Compute approxFactor, a value to scale down by, in case the value exceeds a 64-bit integer.
            logValid               = (logPowP <= LargeScalingFactorConstants::MAX_BITS_IN_WORD) ?
                                         logPowP :
                                         LargeScalingFactorConstants::MAX_BITS_IN_WORD;
            int32_t logApprox_PowP = logPowP - logValid;
            if (logApprox_PowP > 0) {
                int32_t logStep           = (logApprox <= LargeScalingFactorConstants::MAX_LOG_STEP) ?
                                                logApprox_PowP :
                                                LargeScalingFactorConstants::MAX_LOG_STEP;
                DCRTPoly::Integer intStep = static_cast<uint64_t>(1) << logStep;
                std::vector<DCRTPoly::Integer> crtApprox(numTowers, intStep);
                logApprox_PowP -= logStep;
                while (logApprox_PowP > 0) {
                    int32_t logStep           = (logApprox <= LargeScalingFactorConstants::MAX_LOG_STEP) ?
                                                    logApprox :
                                                    LargeScalingFactorConstants::MAX_LOG_STEP;
                    DCRTPoly::Integer intStep = static_cast<uint64_t>(1) << logStep;
                    std::vector<DCRTPoly::Integer> crtStep(numTowers, intStep);
                    crtApprox = CKKSPackedEncoding::CRTMult(crtApprox, crtStep, moduli);
                    logApprox_PowP -= logStep;
                }
                crtPowP = CKKSPackedEncoding::CRTMult(crtPowP, crtApprox, moduli);
            }
            else {
                double approxFactor = pow(2, logApprox_PowP);
                DCRTPoly::Integer intPowP{static_cast<uint64_t>(std::llround(powP / approxFactor))};
                crtPowP = std::vector<DCRTPoly::Integer>(numTowers, intPowP);
            }
        }
        else {
            DCRTPoly::Integer intPowP{static_cast<uint64_t>(std::llround(powP))};
            crtPowP = std::vector<DCRTPoly::Integer>(numTowers, intPowP);
        }
    }
    else {
        DCRTPoly::Integer intPowP{static_cast<uint64_t>(std::llround(powP))};
        crtPowP = std::vector<DCRTPoly::Integer>(numTowers, intPowP);
    }

    auto currPowP = crtPowP;

    // We want to scale temp by 2^(pd), and the loop starts from j=2
    // because temp is already scaled by 2^p in the re/im loop above,
    // and currPowP already is 2^p.
    for (size_t i = 2; i < noiseScaleDeg; i++)
        currPowP = CKKSPackedEncoding::CRTMult(currPowP, crtPowP, moduli);
    if (noiseScaleDeg > 1)
        plainElement = plainElement.Times(currPowP);

    // Scale back up by the approxFactor to get the correct encoding.
    if (logApprox > 0) {
        int32_t logStep = (logApprox <= MAX_LOG_STEP) ? logApprox : MAX_LOG_STEP;
        auto intStep    = DCRTPoly::Integer(static_cast<uint64_t>(1) << logStep);
        std::vector<DCRTPoly::Integer> crtApprox(numTowers, intStep);
        logApprox -= logStep;

        while (logApprox > 0) {
            logStep = (logApprox <= MAX_LOG_STEP) ? logApprox : MAX_LOG_STEP;
            intStep = DCRTPoly::Integer(static_cast<uint64_t>(1) << logStep);
            std::vector<DCRTPoly::Integer> crtSF(numTowers, intStep);
            crtApprox = CKKSPackedEncoding::CRTMult(crtApprox, crtSF, moduli);
            logApprox -= logStep;
        }
        plainElement = plainElement.Times(crtApprox);
    }

    p->SetFormat(Format::EVALUATION);
    p->SetScalingFactor(pow(p->GetScalingFactor(), noiseScaleDeg));
    return p;
}
#endif

Ciphertext<DCRTPoly> FHECKKSRNS::EvalMultExt(ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const {
    auto pt = plaintext->GetElement<DCRTPoly>();
    pt.SetFormat(Format::EVALUATION);

    auto result = ciphertext->Clone();
    for (auto& c : result->GetElements())
        c *= pt;
    result->SetNoiseScaleDeg(result->GetNoiseScaleDeg() + plaintext->GetNoiseScaleDeg());
    result->SetScalingFactor(result->GetScalingFactor() * plaintext->GetScalingFactor());
    return result;
}

void FHECKKSRNS::EvalAddExtInPlace(Ciphertext<DCRTPoly>& ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2) const {
    auto& cv1  = ciphertext1->GetElements();
    auto& cv2  = ciphertext2->GetElements();
    uint32_t n = cv1.size();
    for (uint32_t i = 0; i < n; ++i)
        cv1[i] += cv2[i];
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalAddExt(ConstCiphertext<DCRTPoly> ciphertext1,
                                            ConstCiphertext<DCRTPoly> ciphertext2) const {
    auto result = ciphertext1->Clone();
    EvalAddExtInPlace(result, ciphertext2);
    return result;
}

EvalKey<DCRTPoly> FHECKKSRNS::ConjugateKeyGen(const PrivateKey<DCRTPoly> privateKey) const {
    uint32_t N = privateKey->GetPrivateElement().GetRingDimension();
    std::vector<uint32_t> vec(N);
    PrecomputeAutoMap(N, 2 * N - 1, &vec);

    const auto cc   = privateKey->GetCryptoContext();
    auto pkPermuted = std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc);
    pkPermuted->SetPrivateElement(privateKey->GetPrivateElement().AutomorphismTransform(2 * N - 1, vec));
    pkPermuted->SetKeyTag(privateKey->GetKeyTag());

    return cc->GetScheme()->KeySwitchGen(privateKey, pkPermuted);
}

Ciphertext<DCRTPoly> FHECKKSRNS::Conjugate(ConstCiphertext<DCRTPoly> ciphertext,
                                           const std::map<uint32_t, EvalKey<DCRTPoly>>& evalKeyMap) const {
    uint32_t N = ciphertext->GetElements()[0].GetRingDimension();
    std::vector<uint32_t> vec(N);
    PrecomputeAutoMap(N, 2 * N - 1, &vec);

    auto result = ciphertext->Clone();

    auto algo = ciphertext->GetCryptoContext()->GetScheme();
    algo->KeySwitchInPlace(result, evalKeyMap.at(2 * N - 1));

    auto& rcv = result->GetElements();
    rcv[0]    = rcv[0].AutomorphismTransform(2 * N - 1, vec);
    rcv[1]    = rcv[1].AutomorphismTransform(2 * N - 1, vec);
    return result;
}

void FHECKKSRNS::FitToNativeVector(uint32_t ringDim, const std::vector<int64_t>& vec, int64_t bigBound,
                                   NativeVector* nativeVec) const {
    if (nativeVec == nullptr)
        OPENFHE_THROW("The passed native vector is empty.");
    NativeInteger bigValueHf(bigBound >> 1);
    NativeInteger modulus(nativeVec->GetModulus());
    NativeInteger diff = bigBound - modulus;
    uint32_t dslots    = vec.size();
    uint32_t gap       = ringDim / dslots;
    for (uint32_t i = 0; i < vec.size(); i++) {
        NativeInteger n(vec[i]);
        if (n > bigValueHf) {
            (*nativeVec)[gap * i] = n.ModSub(diff, modulus);
        }
        else {
            (*nativeVec)[gap * i] = n.Mod(modulus);
        }
    }
}

#if NATIVEINT == 128
void FHECKKSRNS::FitToNativeVector(uint32_t ringDim, const std::vector<int128_t>& vec, int128_t bigBound,
                                   NativeVector* nativeVec) const {
    if (nativeVec == nullptr)
        OPENFHE_THROW("The passed native vector is empty.");
    NativeInteger bigValueHf((uint128_t)bigBound >> 1);
    NativeInteger modulus(nativeVec->GetModulus());
    NativeInteger diff = NativeInteger((uint128_t)bigBound) - modulus;
    uint32_t dslots    = vec.size();
    uint32_t gap       = ringDim / dslots;
    for (uint32_t i = 0; i < vec.size(); i++) {
        NativeInteger n((uint128_t)vec[i]);
        if (n > bigValueHf) {
            (*nativeVec)[gap * i] = n.ModSub(diff, modulus);
        }
        else {
            (*nativeVec)[gap * i] = n.Mod(modulus);
        }
    }
}
#endif

template <typename VectorDataType>
void FHECKKSRNS::EvalFBTSetupInternal(const CryptoContextImpl<DCRTPoly>& cc, const std::vector<VectorDataType>& coeffs,
                                      uint32_t numSlots, const BigInteger& PIn, const BigInteger& POut,
                                      const BigInteger& Bigq, const PublicKey<DCRTPoly>& pubKey,
                                      const std::vector<uint32_t>& dim1, const std::vector<uint32_t>& levelBudget,
                                      uint32_t lvlsAfterBoot, uint32_t depthLeveledComputation, size_t order) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        OPENFHE_THROW("CKKS Functional Bootstrapping is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW("CKKS Functional Bootstrapping is only supported for the Hybrid key switching method.");

    uint32_t M     = cc.GetCyclotomicOrder();
    uint32_t slots = (numSlots == 0) ? M / 4 : numSlots;

    m_bootPrecomMap[slots] = std::make_shared<CKKSBootstrapPrecom>();
    auto& precom           = m_bootPrecomMap[slots];

    precom->m_slots = slots;
    precom->m_dim1  = dim1[0];
    precom->m_gs    = dim1[1];

    // even for the case of a single slot we need one level for rescaling
    uint32_t logSlots = (slots < 3) ? 1 : std::log2(slots);

    // Perform some checks on the level budget. Because the level budget is used outside this function,
    // changing it here leads to exceptions later. Alternatively, move this check outside or update all
    // the uses of levelBudget.
    if (levelBudget[0] > logSlots || levelBudget[1] > logSlots)
        OPENFHE_THROW("The level budget is too large. Please set it to be at least one and at most log(slots).");
    if (levelBudget[0] < 1 || levelBudget[1] < 1)
        OPENFHE_THROW("The level budget cannot be zero. Please set it to be at least one and at most log(slots).");

    precom->m_levelEnc  = levelBudget[0];
    precom->m_levelDec  = levelBudget[1];
    precom->m_paramsEnc = GetCollapsedFFTParams(slots, levelBudget[0], dim1[0]);
    precom->m_paramsDec = GetCollapsedFFTParams(slots, levelBudget[1], dim1[1]);

    uint32_t m     = 4 * slots;
    uint32_t mmask = m - 1;  // assumes m is power of 2

    // computes indices for all primitive roots of unity
    std::vector<uint32_t> rotGroup(slots);
    uint32_t fivePows = 1;
    for (uint32_t i = 0; i < slots; ++i) {
        rotGroup[i] = fivePows;
        fivePows *= 5;
        fivePows &= mmask;
    }

    // computes all powers of a primitive root of unity exp(2 * M_PI/m)
    std::vector<std::complex<double>> ksiPows(m + 1);
    double ak = 2 * M_PI / m;
    for (uint32_t j = 0; j < m; ++j) {
        double angle = ak * j;
        ksiPows[j].real(std::cos(angle));
        ksiPows[j].imag(std::sin(angle));
    }
    ksiPows[m] = ksiPows[0];

    double k;
    auto skd = cryptoParams->GetSecretKeyDist();
    switch (skd) {
        case UNIFORM_TERNARY:
            k = 1.0;
            break;
        case SPARSE_TERNARY:
            k = K_SPARSE_ALT;
            break;
        case SPARSE_ENCAPSULATED:
            k = K_SPARSE_ENCAPSULATED;
            break;
        default:
            OPENFHE_THROW("Unsupported SecretKeyDist.");
    }

    auto& params = pubKey->GetPublicElements()[0].GetParams()->GetParams();
    uint32_t cnt = 0;

    BigInteger QPrime = params[0]->GetModulus();
    while (lvlsAfterBoot-- > 0)
        QPrime *= params[++cnt]->GetModulus();

    BigInteger q    = cryptoParams->GetElementParams()->GetParams()[0]->GetModulus().ConvertToInt();
    auto qDouble    = q.ConvertToLongDouble();
    double factor   = static_cast<uint128_t>(1) << static_cast<uint32_t>(std::round(std::log2(qDouble)));
    double pre      = qDouble / factor;
    double scaleEnc = pre / k;
    double scaleMod = QPrime.ConvertToLongDouble() / (Bigq.ConvertToLongDouble() * POut.ConvertToDouble());
    double scaleDec = scaleMod / pre;

    uint32_t depthBT = depthLeveledComputation + GetFBTDepth(levelBudget, coeffs, PIn, order, skd);

    // compute # of levels to remain when encoding the coefficients
    uint32_t L0   = cryptoParams->GetElementParams()->GetParams().size();
    uint32_t lEnc = L0 - levelBudget[0] - 1;
    uint32_t lDec = L0 - depthBT;

    bool isLTBootstrap = (levelBudget[0] == 1) && (levelBudget[1] == 1);
    if (isLTBootstrap) {
        // allocate all vectors
        std::vector<std::vector<std::complex<double>>> U0(slots, std::vector<std::complex<double>>(slots));
        std::vector<std::vector<std::complex<double>>> U1(slots, std::vector<std::complex<double>>(slots));
        std::vector<std::vector<std::complex<double>>> U0hatT(slots, std::vector<std::complex<double>>(slots));
        std::vector<std::vector<std::complex<double>>> U1hatT(slots, std::vector<std::complex<double>>(slots));

        for (uint32_t i = 0; i < slots; ++i) {
            for (uint32_t j = 0; j < slots; ++j) {
                U0[i][j]     = ksiPows[(j * rotGroup[i]) & mmask];
                U0hatT[j][i] = std::conj(U0[i][j]);
                U1[i][j]     = std::complex<double>(0, 1) * U0[i][j];
                U1hatT[j][i] = std::conj(U1[i][j]);
            }
        }

        if (M == m) {
            precom->m_U0hatTPre = EvalLinearTransformPrecompute(cc, U0hatT, scaleEnc, lEnc);
            precom->m_U0Pre     = EvalLinearTransformPrecompute(cc, U0, scaleDec, lDec);
        }
        else {
            precom->m_U0hatTPre = EvalLinearTransformPrecompute(cc, U0hatT, U1hatT, 0, scaleEnc, lEnc);
            precom->m_U0Pre     = EvalLinearTransformPrecompute(cc, U0, U1, 1, scaleDec, lDec);
        }
    }
    else {
        precom->m_U0hatTPreFFT = EvalCoeffsToSlotsPrecompute(cc, ksiPows, rotGroup, false, scaleEnc, lEnc);
        precom->m_U0PreFFT     = EvalSlotsToCoeffsPrecompute(cc, ksiPows, rotGroup, false, scaleDec, lDec);
    }
}

void FHECKKSRNS::EvalFBTSetup(const CryptoContextImpl<DCRTPoly>& cc,
                              const std::vector<std::complex<double>>& coefficients, uint32_t numSlots,
                              const BigInteger& PIn, const BigInteger& POut, const BigInteger& Bigq,
                              const PublicKey<DCRTPoly>& pubKey, const std::vector<uint32_t>& dim1,
                              const std::vector<uint32_t>& levelBudget, uint32_t lvlsAfterBoot,
                              uint32_t depthLeveledComputation, size_t order) {
    EvalFBTSetupInternal(cc, coefficients, numSlots, PIn, POut, Bigq, pubKey, dim1, levelBudget, lvlsAfterBoot,
                         depthLeveledComputation, order);
}

void FHECKKSRNS::EvalFBTSetup(const CryptoContextImpl<DCRTPoly>& cc, const std::vector<int64_t>& coefficients,
                              uint32_t numSlots, const BigInteger& PIn, const BigInteger& POut, const BigInteger& Bigq,
                              const PublicKey<DCRTPoly>& pubKey, const std::vector<uint32_t>& dim1,
                              const std::vector<uint32_t>& levelBudget, uint32_t lvlsAfterBoot,
                              uint32_t depthLeveledComputation, size_t order) {
    EvalFBTSetupInternal(cc, coefficients, numSlots, PIn, POut, Bigq, pubKey, dim1, levelBudget, lvlsAfterBoot,
                         depthLeveledComputation, order);
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalHomDecoding(ConstCiphertext<DCRTPoly>& ciphertext, uint64_t postScaling,
                                                 uint32_t levelToReduce) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    auto ctxtEnc = ciphertext->Clone();

    // Drop levels if needed
    auto cc = ciphertext->GetCryptoContext();
    if (levelToReduce > 0)
        cc->LevelReduceInPlace(ctxtEnc, nullptr, levelToReduce);

    //------------------------------------------------------------------------------
    // Running SlotsToCoeffs
    //------------------------------------------------------------------------------

    // In the case of FLEXIBLEAUTO, we need one extra tower
    if (cryptoParams->GetScalingTechnique() != FIXEDMANUAL)
        cc->GetScheme()->ModReduceInternalInPlace(ctxtEnc, BASE_NUM_LEVELS_TO_DROP);

    // linear transform for decoding
    auto slots   = ciphertext->GetSlots();
    auto& p      = GetBootPrecom(slots);
    auto isLTBS  = (p.m_levelEnc == 1) && (p.m_levelDec == 1);
    auto ctxtDec = (isLTBS) ? EvalLinearTransform(p.m_U0Pre, ctxtEnc) : EvalSlotsToCoeffs(p.m_U0PreFFT, ctxtEnc);

    if (slots != cc->GetCyclotomicOrder() / 4) {
        //------------------------------------------------------------------------------
        // SPARSELY PACKED CASE
        //------------------------------------------------------------------------------
        cc->EvalAddInPlaceNoCheck(ctxtDec, cc->EvalRotate(ctxtDec, slots));
    }

    // Because the linear transform might be scaled differently, we might need to scale up the result separately
    // Often, this scaling addreesses the previous division in the trigonometric Hermite coefficients
    if (postScaling > 1)
        cc->GetScheme()->MultByIntegerInPlace(ctxtDec, postScaling);

    cc->ModReduceInPlace(ctxtDec);
    // 64-bit only: No need to scale back the message to its original scale.
    return ctxtDec;
}

template <typename VectorDataType>
std::shared_ptr<seriesPowers<DCRTPoly>> FHECKKSRNS::EvalMVBPrecomputeInternal(
    ConstCiphertext<DCRTPoly>& ciphertext, const std::vector<VectorDataType>& coefficients, uint32_t digitBitSize,
    const BigInteger& initialScaling, size_t order) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        OPENFHE_THROW("CKKS Functional Bootstrapping is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW("CKKS Bootstrapping is only supported for the Hybrid key switching method.");

    auto paramsQ   = cryptoParams->GetElementParams()->GetParams();
    uint32_t sizeQ = paramsQ.size();
    std::vector<NativeInteger> moduli(sizeQ);
    std::vector<NativeInteger> roots(sizeQ);
    for (uint32_t i = 0; i < sizeQ; ++i) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i]  = paramsQ[i]->GetRootOfUnity();
    }

    auto cc = ciphertext->GetCryptoContext();
    auto M  = cc->GetCyclotomicOrder();
    auto N  = cc->GetRingDimension();

    auto elementParamsRaisedPtr = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(M, moduli, roots);

    // We don't need the type of scaling and correction as in the standard CKKS bootstrapping
    // because the message doesn't have to be scaled down.
    // Instead, we need to correct the encoding if it originates from a different ciphertext
    // (not typical CKKS).
    double correction = cryptoParams->GetScalingFactorRealBig(0) / initialScaling.ConvertToDouble();

    //------------------------------------------------------------------------------
    // RAISING THE MODULUS
    //------------------------------------------------------------------------------

    auto raised = ciphertext->Clone();
    auto algo   = cc->GetScheme();
    algo->ModReduceInternalInPlace(raised, raised->GetNoiseScaleDeg() - 1);

    // If correction ~ 1, we should not do this adjustment and save a level
    if (std::llround(correction) != 1.0)
        AdjustCiphertextFBT(raised, correction);

    uint32_t L0 = cryptoParams->GetElementParams()->GetParams().size();
    if (cryptoParams->GetSecretKeyDist() == SPARSE_ENCAPSULATED) {
        auto evalKeyMap = cc->GetEvalAutomorphismKeyMap(raised->GetKeyTag());

        // transform from a denser secret to a sparser one
        raised = KeySwitchSparse(raised, evalKeyMap.at(2 * N - 4));

        // Only level 0 ciphertext used here. Other towers ignored to make CKKS bootstrapping faster.
        auto& ctxtDCRT = raised->GetElements();
        for (auto& poly : ctxtDCRT) {
            poly.SetFormat(COEFFICIENT);
            DCRTPoly temp(elementParamsRaisedPtr, COEFFICIENT);
            temp = poly.GetElementAtIndex(0);
            temp.SetFormat(EVALUATION);
            poly = std::move(temp);
        }
        raised->SetLevel(L0 - ctxtDCRT[0].GetNumOfElements());

        // go back to a denser secret
        algo->KeySwitchInPlace(raised, evalKeyMap.at(2 * N - 2));
    }
    else {
        // Only level 0 ciphertext used here. Other towers ignored to make CKKS bootstrapping faster.
        auto& ctxtDCRT = raised->GetElements();
        for (auto& poly : ctxtDCRT) {
            poly.SetFormat(COEFFICIENT);
            DCRTPoly temp(elementParamsRaisedPtr, COEFFICIENT);
            temp = poly.GetElementAtIndex(0);
            temp.SetFormat(EVALUATION);
            poly = std::move(temp);
        }
        raised->SetLevel(L0 - ctxtDCRT[0].GetNumOfElements());
    }

#ifdef BOOTSTRAPTIMING
    std::cerr << "\nNumber of levels at the beginning of bootstrapping: "
              << raised->GetElements()[0].GetNumOfElements() - 1 << std::endl;
#endif

    //------------------------------------------------------------------------------
    // SETTING PARAMETERS FOR APPROXIMATE MODULAR REDUCTION
    //------------------------------------------------------------------------------

    auto skd = cryptoParams->GetSecretKeyDist();
    double k = (skd == SPARSE_TERNARY || skd == SPARSE_ENCAPSULATED) ? 1.0 : K_UNIFORM;

    double constantEvalMult = 1.0 / (k * N);
    cc->EvalMultInPlace(raised, constantEvalMult);

    // no linear transformations are needed for Chebyshev series as the range has been normalized to [-1,1]
    double coeffLowerBound = -1.0;
    double coeffUpperBound = 1.0;

    auto slots         = ciphertext->GetSlots();
    auto& p            = GetBootPrecom(slots);
    bool isLTBootstrap = (p.m_levelEnc == 1) && (p.m_levelDec == 1);

    std::vector<Ciphertext<DCRTPoly>> ctxtEnc;
    std::shared_ptr<seriesPowers<DCRTPoly>> ctxtPowers;

    if (slots == M / 4) {
        //------------------------------------------------------------------------------
        // FULLY PACKED CASE
        //------------------------------------------------------------------------------

        //------------------------------------------------------------------------------
        // Running CoeffToSlot
        //------------------------------------------------------------------------------

        // need to call internal modular reduction so it also works for FLEXIBLEAUTO
        algo->ModReduceInternalInPlace(raised, BASE_NUM_LEVELS_TO_DROP);

        // only one linear transform is needed as the other one can be derived
        ctxtEnc.emplace_back((isLTBootstrap) ? EvalLinearTransform(p.m_U0hatTPre, raised) :
                                               EvalCoeffsToSlots(p.m_U0hatTPreFFT, raised));

        auto conj = Conjugate(ctxtEnc[0], cc->GetEvalAutomorphismKeyMap(ctxtEnc[0]->GetKeyTag()));

        ctxtEnc.emplace_back(cc->EvalSub(ctxtEnc[0], conj));
        cc->EvalAddInPlaceNoCheck(ctxtEnc[0], conj);
        algo->MultByMonomialInPlace(ctxtEnc[1], 3 * M / 4);

        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            while (ctxtEnc[0]->GetNoiseScaleDeg() > 1) {
                cc->ModReduceInPlace(ctxtEnc[0]);
                cc->ModReduceInPlace(ctxtEnc[1]);
            }
        }
        else {
            if (ctxtEnc[0]->GetNoiseScaleDeg() == 2) {
                algo->ModReduceInternalInPlace(ctxtEnc[0], BASE_NUM_LEVELS_TO_DROP);
                algo->ModReduceInternalInPlace(ctxtEnc[1], BASE_NUM_LEVELS_TO_DROP);
            }
        }

        //------------------------------------------------------------------------------
        // Computing the powers for Approximate Mod Reduction
        //------------------------------------------------------------------------------

        if (digitBitSize == 1 && order == 1) {
            auto& coeff_cos = (skd == SPARSE_ENCAPSULATED) ? coeff_cos_16_double : coeff_cos_25_double;

            ctxtEnc[0] = cc->EvalChebyshevSeries(ctxtEnc[0], coeff_cos, coeffLowerBound, coeffUpperBound);
            ctxtEnc[1] = cc->EvalChebyshevSeries(ctxtEnc[1], coeff_cos, coeffLowerBound, coeffUpperBound);

            // Double angle-iterations to get cos(pi*x)
            cc->EvalSquareInPlace(ctxtEnc[0]);
            cc->EvalAddInPlaceNoCheck(ctxtEnc[0], ctxtEnc[0]);
            cc->EvalSubInPlace(ctxtEnc[0], 1.0);
            cc->ModReduceInPlace(ctxtEnc[0]);  // cos(pi x)
            cc->EvalSquareInPlace(ctxtEnc[1]);
            cc->EvalAddInPlaceNoCheck(ctxtEnc[1], ctxtEnc[1]);
            cc->EvalSubInPlace(ctxtEnc[1], 1.0);
            cc->ModReduceInPlace(ctxtEnc[1]);  // cos(pi x)

            cc->EvalSquareInPlace(ctxtEnc[0]);
            cc->ModReduceInPlace(ctxtEnc[0]);  // cos^2(pi x)
            cc->EvalSquareInPlace(ctxtEnc[1]);
            cc->ModReduceInPlace(ctxtEnc[1]);  // cos^2(pi x)
        }
        else {
            auto& coeff_exp = (skd == SPARSE_ENCAPSULATED) ? coeff_exp_16_double_46 :
                              (digitBitSize > 10)          ? coeff_exp_25_double_66 :
                                                             coeff_exp_25_double_58;

            // Obtain exp(Pi/2*i*x) approximation via Chebyshev Basis Polynomial Interpolation
            ctxtEnc[0] = cc->EvalChebyshevSeries(ctxtEnc[0], coeff_exp, coeffLowerBound, coeffUpperBound);
            ctxtEnc[1] = cc->EvalChebyshevSeries(ctxtEnc[1], coeff_exp, coeffLowerBound, coeffUpperBound);

            // Double angle-iterations to get exp(2*Pi*i*x)
            cc->EvalSquareInPlace(ctxtEnc[0]);
            cc->ModReduceInPlace(ctxtEnc[0]);
            cc->EvalSquareInPlace(ctxtEnc[0]);
            cc->ModReduceInPlace(ctxtEnc[0]);

            cc->EvalSquareInPlace(ctxtEnc[1]);
            cc->ModReduceInPlace(ctxtEnc[1]);
            cc->EvalSquareInPlace(ctxtEnc[1]);
            cc->ModReduceInPlace(ctxtEnc[1]);
        }

        auto ctxtPowersRe = cc->EvalPowers(ctxtEnc[0], coefficients);
        auto ctxtPowersIm = cc->EvalPowers(ctxtEnc[1], coefficients);
        if (ctxtPowersRe->powers2Re.size() == 0) {
            ctxtPowers = std::make_shared<seriesPowers<DCRTPoly>>(ctxtPowersRe->powersRe, ctxtPowersIm->powersRe);
        }
        else {
            ctxtPowers = std::make_shared<seriesPowers<DCRTPoly>>(
                ctxtPowersRe->powersRe, ctxtPowersRe->powers2Re, ctxtPowersRe->power2km1Re, ctxtPowersRe->k,
                ctxtPowersRe->m, ctxtPowersIm->powersRe, ctxtPowersIm->powers2Re, ctxtPowersIm->power2km1Re);
        }
    }
    else {
        //------------------------------------------------------------------------------
        // SPARSELY PACKED CASE
        //------------------------------------------------------------------------------

        //------------------------------------------------------------------------------
        // Running PartialSum
        //------------------------------------------------------------------------------

        for (uint32_t j = 1; j < N / (2 * slots); j <<= 1)
            cc->EvalAddInPlaceNoCheck(raised, cc->EvalRotate(raised, j * slots));

        //------------------------------------------------------------------------------
        // Running CoeffsToSlots
        //------------------------------------------------------------------------------

        algo->ModReduceInternalInPlace(raised, BASE_NUM_LEVELS_TO_DROP);

        ctxtEnc.emplace_back((isLTBootstrap) ? EvalLinearTransform(p.m_U0hatTPre, raised) :
                                               EvalCoeffsToSlots(p.m_U0hatTPreFFT, raised));

        auto evalKeyMap = cc->GetEvalAutomorphismKeyMap(ctxtEnc[0]->GetKeyTag());
        auto conj       = Conjugate(ctxtEnc[0], evalKeyMap);
        cc->EvalAddInPlaceNoCheck(ctxtEnc[0], conj);

        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            while (ctxtEnc[0]->GetNoiseScaleDeg() > 1)
                cc->ModReduceInPlace(ctxtEnc[0]);
        }
        else {
            if (ctxtEnc[0]->GetNoiseScaleDeg() == 2)
                algo->ModReduceInternalInPlace(ctxtEnc[0], BASE_NUM_LEVELS_TO_DROP);
        }

        //------------------------------------------------------------------------------
        // Running Approximate Mod Reduction
        //------------------------------------------------------------------------------

        if (digitBitSize == 1 && order == 1) {
            auto& coeff_cos = (skd == SPARSE_ENCAPSULATED) ? coeff_cos_16_double : coeff_cos_25_double;

            ctxtEnc[0] = cc->EvalChebyshevSeries(ctxtEnc[0], coeff_cos, coeffLowerBound, coeffUpperBound);

            // Double angle-iterations to get cos(pi*x)
            cc->EvalSquareInPlace(ctxtEnc[0]);
            cc->EvalAddInPlaceNoCheck(ctxtEnc[0], ctxtEnc[0]);
            cc->EvalSubInPlace(ctxtEnc[0], 1.0);
            cc->ModReduceInPlace(ctxtEnc[0]);  // cos(pi x)

            cc->EvalSquareInPlace(ctxtEnc[0]);
            cc->ModReduceInPlace(ctxtEnc[0]);  // cos^2(pi x)
        }
        else {
            auto& coeff_exp = (skd == SPARSE_ENCAPSULATED) ? coeff_exp_16_double_46 :
                              (digitBitSize > 10)          ? coeff_exp_25_double_66 :
                                                             coeff_exp_25_double_58;

            // Obtain exp(Pi/2*i*x) approximation via Chebyshev Basis Polynomial Interpolation
            ctxtEnc[0] = cc->EvalChebyshevSeries(ctxtEnc[0], coeff_exp, coeffLowerBound, coeffUpperBound);

            // Double angle-iterations to get exp(2*Pi*i*x)
            cc->EvalSquareInPlace(ctxtEnc[0]);
            cc->ModReduceInPlace(ctxtEnc[0]);
            cc->EvalSquareInPlace(ctxtEnc[0]);
            cc->ModReduceInPlace(ctxtEnc[0]);
        }

        // No need to scale the message back up after Chebyshev interpolation
        ctxtPowers = cc->EvalPowers(ctxtEnc[0], coefficients);
    }

    // 64-bit only: No need to scale back the message to its original scale.
    return ctxtPowers;
}

std::shared_ptr<seriesPowers<DCRTPoly>> FHECKKSRNS::EvalMVBPrecompute(
    ConstCiphertext<DCRTPoly>& ciphertext, const std::vector<std::complex<double>>& coefficients, uint32_t digitBitSize,
    const BigInteger& initialScaling, size_t order) {
    return EvalMVBPrecomputeInternal(ciphertext, coefficients, digitBitSize, initialScaling, order);
}
std::shared_ptr<seriesPowers<DCRTPoly>> FHECKKSRNS::EvalMVBPrecompute(ConstCiphertext<DCRTPoly>& ciphertext,
                                                                      const std::vector<int64_t>& coefficients,
                                                                      uint32_t digitBitSize,
                                                                      const BigInteger& initialScaling, size_t order) {
    return EvalMVBPrecomputeInternal(ciphertext, coefficients, digitBitSize, initialScaling, order);
}

template <typename VectorDataType>
Ciphertext<DCRTPoly> FHECKKSRNS::EvalMVBNoDecodingInternal(const std::shared_ptr<seriesPowers<DCRTPoly>> ciphertexts,
                                                           const std::vector<VectorDataType>& coefficients,
                                                           uint32_t digitBitSize, size_t order) {
    const auto cryptoParams =
        std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertexts->powersRe[0]->GetCryptoParameters());
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        OPENFHE_THROW("CKKS Functional Bootstrapping is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW("CKKS Bootstrapping is only supported for the Hybrid key switching method.");

    auto cc        = ciphertexts->powersRe[0]->GetCryptoContext();
    uint32_t M     = cc->GetCyclotomicOrder();
    uint32_t slots = ciphertexts->powersRe[0]->GetSlots();
    auto algo      = cc->GetScheme();

    Ciphertext<DCRTPoly> ctxtEnc;

    if (slots == M / 4) {
        //------------------------------------------------------------------------------
        // FULLY PACKED CASE
        //------------------------------------------------------------------------------
        if (ciphertexts->powersIm.size() == 0)
            OPENFHE_THROW("Full packing requires powers for both the real and imaginary parts.");
        Ciphertext<DCRTPoly> ctxtEncI;

        //------------------------------------------------------------------------------
        // Running Approximate Mod Reduction using the complex explonential
        //------------------------------------------------------------------------------

        if (digitBitSize == 1 && order == 1) {
            ctxtEnc  = ciphertexts->powersRe[0];
            ctxtEncI = ciphertexts->powersIm[0];
            // Assumes the function is integer and real!
            if (ToReal(coefficients[1]) > 0) {  // MultByInteger only works with positive integers
                algo->MultByIntegerInPlace(ctxtEnc, ToReal(coefficients[1]));
                cc->EvalAddInPlace(ctxtEnc, ToReal(coefficients[0]));
                algo->MultByIntegerInPlace(ctxtEncI, ToReal(coefficients[1]));
                cc->EvalAddInPlace(ctxtEncI, ToReal(coefficients[0]));
            }
            else {
                algo->MultByIntegerInPlace(ctxtEnc, -ToReal(coefficients[1]));
                ctxtEnc = cc->EvalSub(ToReal(coefficients[0]), ctxtEnc);
                algo->MultByIntegerInPlace(ctxtEncI, -ToReal(coefficients[1]));
                ctxtEncI = cc->EvalSub(ToReal(coefficients[0]), ctxtEncI);
            }
        }
        else {
            // Obtain the complex Hermite Trigonometric Interpolation via Power Basis Polynomial Interpolation
            // Coefficients are divided by 2
            std::shared_ptr<seriesPowers<DCRTPoly>> ctxtPowersRe, ctxtPowersIm;
            if (ciphertexts->powers2Re.size() == 0) {
                ctxtPowersRe = std::make_shared<seriesPowers<DCRTPoly>>(ciphertexts->powersRe);
                ctxtPowersIm = std::make_shared<seriesPowers<DCRTPoly>>(ciphertexts->powersIm);
            }
            else {
                ctxtPowersRe =
                    std::make_shared<seriesPowers<DCRTPoly>>(ciphertexts->powersRe, ciphertexts->powers2Re,
                                                             ciphertexts->power2km1Re, ciphertexts->k, ciphertexts->m);
                ctxtPowersIm =
                    std::make_shared<seriesPowers<DCRTPoly>>(ciphertexts->powersIm, ciphertexts->powers2Im,
                                                             ciphertexts->power2km1Im, ciphertexts->k, ciphertexts->m);
            }

            // Take the real part
            // Division by 2 was already performed
            ctxtEnc = cc->EvalPolyWithPrecomp(ctxtPowersRe, coefficients);
            cc->EvalAddInPlaceNoCheck(ctxtEnc, Conjugate(ctxtEnc, cc->GetEvalAutomorphismKeyMap(ctxtEnc->GetKeyTag())));
            ctxtEncI = cc->EvalPolyWithPrecomp(ctxtPowersIm, coefficients);
            cc->EvalAddInPlaceNoCheck(ctxtEncI,
                                      Conjugate(ctxtEncI, cc->GetEvalAutomorphismKeyMap(ctxtEnc->GetKeyTag())));
        }

        algo->MultByMonomialInPlace(ctxtEncI, M / 4);
        cc->EvalAddInPlaceNoCheck(ctxtEnc, ctxtEncI);
        // No need to scale the message back up after Chebyshev interpolation
    }
    else {
        //------------------------------------------------------------------------------
        // SPARSELY PACKED CASE
        //------------------------------------------------------------------------------

        //------------------------------------------------------------------------------
        // Running Approximate Mod Reduction using the complex exponential
        //------------------------------------------------------------------------------

        if (digitBitSize == 1 && order == 1) {
            ctxtEnc = ciphertexts->powersRe[0];
            // Assumes the function is integer and real!
            if (ToReal(coefficients[1]) > 0) {  // MultByInteger only works with positive integers
                algo->MultByIntegerInPlace(ctxtEnc, ToReal(coefficients[1]));
                cc->EvalAddInPlace(ctxtEnc, ToReal(coefficients[0]));
            }
            else {
                algo->MultByIntegerInPlace(ctxtEnc, -ToReal(coefficients[1]));
                ctxtEnc = cc->EvalSub(ToReal(coefficients[0]), ctxtEnc);
            }
        }
        else {
            // Obtain the complex Hermite Trigonometric Interpolation via Power Basis Polynomial Interpolation
            // Coefficients are divided by 2
            std::shared_ptr<seriesPowers<DCRTPoly>> ctxtPowersRe;
            if (ciphertexts->powers2Re.size() == 0) {
                ctxtPowersRe = std::make_shared<seriesPowers<DCRTPoly>>(ciphertexts->powersRe);
            }
            else {
                ctxtPowersRe =
                    std::make_shared<seriesPowers<DCRTPoly>>(ciphertexts->powersRe, ciphertexts->powers2Re,
                                                             ciphertexts->power2km1Re, ciphertexts->k, ciphertexts->m);
            }
            ctxtEnc = cc->EvalPolyWithPrecomp(ctxtPowersRe, coefficients);

            // Take the real part
            // Division by 2 was already performed
            cc->EvalAddInPlaceNoCheck(ctxtEnc, Conjugate(ctxtEnc, cc->GetEvalAutomorphismKeyMap(ctxtEnc->GetKeyTag())));
        }

        // No need to scale the message back up after Chebyshev interpolation
    }

    // // 64-bit only: No need to scale back the message to its original scale.
    return ctxtEnc;
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalFBT(ConstCiphertext<DCRTPoly>& ciphertext,
                                         const std::vector<std::complex<double>>& coefficients, uint32_t digitBitSize,
                                         const BigInteger& initialScaling, uint64_t postScaling, uint32_t levelToReduce,
                                         size_t order) {
    return EvalHomDecoding(EvalMVBNoDecodingInternal(
                               EvalMVBPrecomputeInternal(ciphertext, coefficients, digitBitSize, initialScaling, order),
                               coefficients, digitBitSize, order),
                           postScaling, levelToReduce);
}
Ciphertext<DCRTPoly> FHECKKSRNS::EvalFBT(ConstCiphertext<DCRTPoly>& ciphertext,
                                         const std::vector<int64_t>& coefficients, uint32_t digitBitSize,
                                         const BigInteger& initialScaling, uint64_t postScaling, uint32_t levelToReduce,
                                         size_t order) {
    return EvalHomDecoding(EvalMVBNoDecodingInternal(
                               EvalMVBPrecomputeInternal(ciphertext, coefficients, digitBitSize, initialScaling, order),
                               coefficients, digitBitSize, order),
                           postScaling, levelToReduce);
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalFBTNoDecoding(ConstCiphertext<DCRTPoly>& ciphertext,
                                                   const std::vector<std::complex<double>>& coefficients,
                                                   uint32_t digitBitSize, const BigInteger& initialScaling,
                                                   size_t order) {
    return EvalMVBNoDecodingInternal(
        EvalMVBPrecomputeInternal(ciphertext, coefficients, digitBitSize, initialScaling, order), coefficients,
        digitBitSize, order);
}
Ciphertext<DCRTPoly> FHECKKSRNS::EvalFBTNoDecoding(ConstCiphertext<DCRTPoly>& ciphertext,
                                                   const std::vector<int64_t>& coefficients, uint32_t digitBitSize,
                                                   const BigInteger& initialScaling, size_t order) {
    return EvalMVBNoDecodingInternal(
        EvalMVBPrecomputeInternal(ciphertext, coefficients, digitBitSize, initialScaling, order), coefficients,
        digitBitSize, order);
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalMVB(const std::shared_ptr<seriesPowers<DCRTPoly>> ciphertexts,
                                         const std::vector<std::complex<double>>& coefficients, uint32_t digitBitSize,
                                         uint64_t postScaling, uint32_t levelToReduce, size_t order) {
    return EvalHomDecoding(EvalMVBNoDecodingInternal(ciphertexts, coefficients, digitBitSize, order), postScaling,
                           levelToReduce);
}
Ciphertext<DCRTPoly> FHECKKSRNS::EvalMVB(const std::shared_ptr<seriesPowers<DCRTPoly>> ciphertexts,
                                         const std::vector<int64_t>& coefficients, uint32_t digitBitSize,
                                         uint64_t postScaling, uint32_t levelToReduce, size_t order) {
    return EvalHomDecoding(EvalMVBNoDecodingInternal(ciphertexts, coefficients, digitBitSize, order), postScaling,
                           levelToReduce);
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalMVBNoDecoding(const std::shared_ptr<seriesPowers<DCRTPoly>> ciphertexts,
                                                   const std::vector<std::complex<double>>& coefficients,
                                                   uint32_t digitBitSize, size_t order) {
    return EvalMVBNoDecodingInternal(ciphertexts, coefficients, digitBitSize, order);
}
Ciphertext<DCRTPoly> FHECKKSRNS::EvalMVBNoDecoding(const std::shared_ptr<seriesPowers<DCRTPoly>> ciphertexts,
                                                   const std::vector<int64_t>& coefficients, uint32_t digitBitSize,
                                                   size_t order) {
    return EvalMVBNoDecodingInternal(ciphertexts, coefficients, digitBitSize, order);
}

template <typename VectorDataType>
Ciphertext<DCRTPoly> FHECKKSRNS::EvalHermiteTrigSeriesInternal(
    ConstCiphertext<DCRTPoly>& ciphertext, const std::vector<std::complex<double>>& coefficientsCheb, double a,
    double b, const std::vector<VectorDataType>& coefficientsHerm, size_t precomp) {
    auto cc    = ciphertext->GetCryptoContext();
    auto slots = ciphertext->GetSlots();
    auto& p    = GetBootPrecom(slots);

    auto& ctxt_exp = (precomp == 0 || precomp == 2) ? p.m_precompExp : p.m_precompExpI;
    if (precomp == 0 || precomp == 1) {
        // Obtain exp(Pi/2*i*x) approximation via Chebyshev Basis Polynomial Interpolation
        ctxt_exp = cc->EvalChebyshevSeries(ciphertext, coefficientsCheb, a, b);

        // Double angle-iterations to get exp(2*Pi*i*x)
        cc->EvalSquareInPlace(ctxt_exp);
        cc->ModReduceInPlace(ctxt_exp);
        cc->EvalSquareInPlace(ctxt_exp);
        cc->ModReduceInPlace(ctxt_exp);
    }

    // Obtain the complex Hermite Trigonometric Interpolation via Power Basis Polynomial Interpolation
    // Coefficients are divided by 2
    auto result = cc->EvalPoly(ctxt_exp, coefficientsHerm);

    // Take the real part
    // Division by 2 was already performed
    cc->EvalAddInPlaceNoCheck(result, Conjugate(result, cc->GetEvalAutomorphismKeyMap(result->GetKeyTag())));

    return result;
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalHermiteTrigSeries(ConstCiphertext<DCRTPoly>& ciphertext,
                                                       const std::vector<std::complex<double>>& coefficientsCheb,
                                                       double a, double b,
                                                       const std::vector<std::complex<double>>& coefficientsHerm,
                                                       size_t precomp) {
    return EvalHermiteTrigSeriesInternal(ciphertext, coefficientsCheb, a, b, coefficientsHerm, precomp);
}
Ciphertext<DCRTPoly> FHECKKSRNS::EvalHermiteTrigSeries(ConstCiphertext<DCRTPoly>& ciphertext,
                                                       const std::vector<std::complex<double>>& coefficientsCheb,
                                                       double a, double b, const std::vector<int64_t>& coefficientsHerm,
                                                       size_t precomp) {
    return EvalHermiteTrigSeriesInternal(ciphertext, coefficientsCheb, a, b, coefficientsHerm, precomp);
}

template <typename VectorDataType>
uint32_t FHECKKSRNS::AdjustDepthFBT(const std::vector<VectorDataType>& coefficients, const BigInteger& PInput,
                                    size_t order, SecretKeyDist skd) {
    auto& coeff_cos = (skd == SPARSE_ENCAPSULATED) ? coeff_cos_16_double : coeff_cos_25_double;
    auto& coeff_exp = (skd == SPARSE_ENCAPSULATED)   ? coeff_exp_16_double_46 :
                      (PInput.ConvertToInt() > 1024) ? coeff_exp_25_double_66 :
                                                       coeff_exp_25_double_58;
    uint32_t depth  = 0;
    switch (PInput.ConvertToInt()) {
        case 2:
            if (order > 1) {
                depth += 3;
            }
            depth += GetMultiplicativeDepthByCoeffVector(coeff_cos, false);
            break;
        case 4:
            if (order == 1) {
                depth += 3;
            }
            else {
                depth += GetMultiplicativeDepthByCoeffVector(coefficients, true);
            }
            depth += GetMultiplicativeDepthByCoeffVector(coeff_exp, false);
            break;
        default:
            depth += GetMultiplicativeDepthByCoeffVector(coefficients, true);
            depth += GetMultiplicativeDepthByCoeffVector(coeff_exp, false);
            break;
    }
    depth += 2;  // the number of double-angle iterations is fixed to 2
    return depth;
}

template uint32_t FHECKKSRNS::AdjustDepthFBT(const std::vector<int64_t>& coefficients, const BigInteger& PInput,
                                             size_t order, SecretKeyDist skd);
template uint32_t FHECKKSRNS::AdjustDepthFBT(const std::vector<std::complex<double>>& coefficients,
                                             const BigInteger& PInput, size_t order, SecretKeyDist skd);

template <typename VectorDataType>
uint32_t FHECKKSRNS::GetFBTDepth(const std::vector<uint32_t>& levelBudget,
                                 const std::vector<VectorDataType>& coefficients, const BigInteger& PInput,
                                 size_t order, SecretKeyDist skd) {
    return levelBudget[0] + levelBudget[1] + AdjustDepthFBT(coefficients, PInput, order, skd);
}

template uint32_t FHECKKSRNS::GetFBTDepth(const std::vector<uint32_t>& levelBudget,
                                          const std::vector<int64_t>& coefficients, const BigInteger& PInput,
                                          size_t order, SecretKeyDist skd);
template uint32_t FHECKKSRNS::GetFBTDepth(const std::vector<uint32_t>& levelBudget,
                                          const std::vector<std::complex<double>>& coefficients,
                                          const BigInteger& PInput, size_t order, SecretKeyDist skd);

EvalKey<DCRTPoly> FHECKKSRNS::KeySwitchGenSparse(const PrivateKey<DCRTPoly>& oldPrivateKey,
                                                 const PrivateKey<DCRTPoly>& newPrivateKey) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(newPrivateKey->GetCryptoParameters());

    const auto paramsQ = cryptoParams->GetElementParams();
    const auto paramsP = cryptoParams->GetParamsP();

    // Build params for p*q (used for sparse encapsulation)
    std::vector<NativeInteger> moduli{paramsQ->GetParams()[0]->GetModulus(), paramsP->GetParams()[0]->GetModulus()};
    std::vector<NativeInteger> roots{paramsQ->GetParams()[0]->GetRootOfUnity(),
                                     paramsP->GetParams()[0]->GetRootOfUnity()};

    auto paramsqp = std::make_shared<typename DCRTPoly::Params>(2 * paramsQ->GetRingDimension(), moduli, roots);

    const DCRTPoly& sOld = oldPrivateKey->GetPrivateElement();
    const DCRTPoly& sNew = newPrivateKey->GetPrivateElement();

    // creates the old key in pq
    auto polysOld = sOld.GetElementAtIndex(0);
    polysOld.SetFormat(COEFFICIENT);
    DCRTPoly sOldExt(paramsqp, Format::COEFFICIENT, true);
    sOldExt.SetElementAtIndex(0, polysOld);
    polysOld.SwitchModulus(moduli[1], roots[1], 0, 0);
    sOldExt.SetElementAtIndex(1, std::move(polysOld));
    sOldExt.SetFormat(Format::EVALUATION);

    // creates the new key in pq
    auto polysNew = sNew.GetElementAtIndex(0);
    polysNew.SetFormat(COEFFICIENT);
    DCRTPoly sNewExt(paramsqp, Format::COEFFICIENT, true);
    sNewExt.SetElementAtIndex(0, polysNew);
    polysNew.SwitchModulus(moduli[1], roots[1], 0, 0);
    sNewExt.SetElementAtIndex(1, std::move(polysNew));
    sNewExt.SetFormat(Format::EVALUATION);

    DugType dug;
    DCRTPoly a(dug, paramsqp, Format::EVALUATION);
    DCRTPoly e(cryptoParams->GetDiscreteGaussianGenerator(), paramsqp, Format::EVALUATION);
    DCRTPoly b(paramsqp, Format::EVALUATION, true);

    NativeInteger pModq = moduli[1].Mod(moduli[0]);

    // computes the switching key for the GHS case
    b.SetElementAtIndex(0, -a.GetElementAtIndex(0) * sNewExt.GetElementAtIndex(0) + pModq * sOld.GetElementAtIndex(0) +
                               e.GetElementAtIndex(0));
    b.SetElementAtIndex(1, -a.GetElementAtIndex(1) * sNewExt.GetElementAtIndex(1) + e.GetElementAtIndex(1));

    auto ek(std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(newPrivateKey->GetCryptoContext()));
    ek->SetAVector({std::move(a)});
    ek->SetBVector({std::move(b)});
    ek->SetKeyTag(newPrivateKey->GetKeyTag());
    return ek;
}

Ciphertext<DCRTPoly> FHECKKSRNS::KeySwitchSparse(Ciphertext<DCRTPoly>& ciphertext, const EvalKey<DCRTPoly>& ek) {
    auto paramsqp = ek->GetAVector()[0].GetParams();
    auto modulusq = paramsqp->GetParams()[0]->GetModulus();
    auto rootq    = paramsqp->GetParams()[0]->GetRootOfUnity();
    auto modulusp = paramsqp->GetParams()[1]->GetModulus();
    auto rootp    = paramsqp->GetParams()[1]->GetRootOfUnity();

    auto& cv = ciphertext->GetElements();
    // extend cv[1] from q to qp
    DCRTPoly c1Ext(paramsqp, Format::EVALUATION, true);
    c1Ext.SetElementAtIndex(0, cv[1].GetElementAtIndex(0));
    auto poly = cv[1].GetElementAtIndex(0);
    poly.SetFormat(Format::COEFFICIENT);
    poly.SwitchModulus(modulusp, rootp, 0, 0);
    poly.SetFormat(Format::EVALUATION);
    c1Ext.SetElementAtIndex(1, std::move(poly));

    // multiply by the evaluation key
    std::vector<DCRTPoly> cvRes{c1Ext * ek->GetBVector()[0], c1Ext * ek->GetAVector()[0]};

    NativeInteger pModInvq = modulusp.ModInverse(modulusq);

    // modswitch cvRes from p*q to q, i.e., compute round(cvRes/p) mod q
    // In RNS, we use the technique described in Appendix B.2.2 of https://eprint.iacr.org/2021/204 for the BFV case, i.e., for t=1.
    for (uint32_t i = 0; i < 2; ++i) {
        auto polyP = cvRes[i].GetElementAtIndex(1);
        polyP.SetFormat(Format::COEFFICIENT);
        polyP.SwitchModulus(modulusq, rootq, 0, 0);
        polyP.SetFormat(Format::EVALUATION);
        cvRes[i].DropLastElement();
        auto polyQ = cvRes[i].GetElementAtIndex(0);
        polyQ -= polyP;
        polyQ *= pModInvq;
        cvRes[i].SetElementAtIndex(0, std::move(polyQ));
    }

    // add to the original ciphertext
    cvRes[0] += cv[0];

    auto result = ciphertext->CloneEmpty();
    result->SetElements(std::move(cvRes));
    return result;
}

}  // namespace lbcrypto
