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
  Regression tests that COMPOSITESCALINGAUTO (CS) does not lose precision relative to
  FLEXIBLEAUTO (FA) for the bugs that were repaired on this branch. Each test runs the same
  computation under FA and under CS and asserts the CS precision is within a small tolerance
  of the FA precision. These configurations were verified to FAIL at the pre-fix commit
  452b94f (CS lagged FA by 4-18 bits) and to PASS after the fixes.

  Covered fixes:
    1. FullPackingBootstrap_HybridKeySwitch - the HYBRID key-switching fix (rns-cryptoparameters.cpp:
       widen the P/Q margin for composite). The roundoff only becomes visible once the modulus chain
       is deep enough to make the digit margin tight, so this test needs ring 2^14; sparse packing
       (1024 slots) keeps it cheap. Pre-fix gap ~4 bits.
    2. SparseBootstrapModRaiseHeadroom - the bootstrapping fix that applies the pre/post 1/(kN)
       scaling the same way as FA. The bug only triggers when firstModSize > scalingModSize + 1
       (modraise headroom deg > 1); FA at 64 bits caps firstMod at 60, so we expose deg = 4 with
       scalingModSize = 56, firstModSize = 60 at 8 slots / ring 2^12. Pre-fix gap ~7 bits.
       (NOTE: the fix closes deg <= 4 cleanly; deg >= 6 still leaves CS ~10 bits below FA - a
       separate, currently-unfixed large-headroom limitation - so this test stays at deg = 4.)
    3. DeepComputationWithFillers - the canonical-scaling-factor fix for plaintext multiplication.
       A deep filler chain followed by a sharp Chebyshev impulse makes CS diverge from FA by many
       orders of magnitude. Pre-fix gap ~18 bits at D = 20.

  The remaining two branch fixes (ExtendCiphertext and composite prime modulation) do not need
  dedicated tests per the issue.
*/

#include "openfhe.h"
#include "gtest/gtest.h"

#include <algorithm>
#include <cmath>
#include <vector>
#include <iostream>

using namespace lbcrypto;

#if NATIVEINT == 64
//===========================================================================================================
namespace {

constexpr uint32_t REGISTER_WORD = 32;  // composite degree 2 for the scaling-factor sizes used here
constexpr SecretKeyDist SK_DIST  = UNIFORM_TERNARY;

// Builds a CKKS context for the requested scaling technique. COMPOSITESCALINGAUTO additionally sets
// the register word size; everything else is identical so FA and CS are a fair comparison.
CryptoContext<DCRTPoly> BuildContext(ScalingTechnique scalTech, uint32_t ringDim, uint32_t multDepth,
                                     uint32_t scalingModSize, uint32_t firstModSize, uint32_t numLargeDigits) {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecretKeyDist(SK_DIST);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(ringDim);
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scalingModSize);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetScalingTechnique(scalTech);
    if (numLargeDigits > 0)
        parameters.SetNumLargeDigits(numLargeDigits);
    if (scalTech == COMPOSITESCALINGAUTO)
        parameters.SetRegisterWordSize(REGISTER_WORD);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);
    return cc;
}

double MaxAbsError(const std::vector<double>& a, const std::vector<double>& b, size_t n) {
    double maxErr = 0.0;
    for (size_t i = 0; i < n; ++i)
        maxErr = std::max(maxErr, std::abs(a[i] - b[i]));
    return maxErr;
}

// Precision in bits (-log2 of the error); a tiny floor avoids +inf when the error is ~0.
double PrecisionBits(double maxErr) {
    return -std::log2(std::max(maxErr, 1e-18));
}

}  // namespace
//===========================================================================================================
class UTCKKSRNSCSvsFA : public ::testing::Test {
protected:
    void SetUp() override {
        OpenFHEParallelControls.UnitTestStart();
    }
    void TearDown() override {
        CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
        CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
        OpenFHEParallelControls.UnitTestStop();
    }

    // Bootstraps a freshly-encrypted (bottom-level) vector and returns the achieved precision in bits.
    double BootstrapPrecisionBits(ScalingTechnique scalTech, uint32_t ringDim, uint32_t scalingModSize,
                                  uint32_t firstModSize, const std::vector<uint32_t>& levelBudget, uint32_t numSlots,
                                  uint32_t levelsAfterBootstrap, uint32_t numLargeDigits) {
        uint32_t depth = levelsAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, SK_DIST);
        auto cc        = BuildContext(scalTech, ringDim, depth, scalingModSize, firstModSize, numLargeDigits);
        auto cp        = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
        uint32_t cd    = cp->GetCompositeDegree();

        cc->EvalBootstrapSetup(levelBudget, {0, 0}, numSlots);
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        cc->EvalBootstrapKeyGen(keys.secretKey, numSlots);

        // Deterministic input in (0,1) so FA and CS see the same signal.
        std::vector<double> x(numSlots);
        for (uint32_t i = 0; i < numSlots; ++i)
            x[i] = 0.25 + 0.5 * (0.5 * std::sin(0.3 * static_cast<double>(i) + 1.0) + 0.5);

        Plaintext pt = cc->MakeCKKSPackedPlaintext(x, 1, cd * (depth - 1), nullptr, numSlots);
        auto ct      = cc->Encrypt(keys.publicKey, pt);
        auto ctAfter = cc->EvalBootstrap(ct);

        Plaintext result;
        cc->Decrypt(keys.secretKey, ctAfter, &result);
        result->SetLength(numSlots);
        return PrecisionBits(MaxAbsError(result->GetRealPackedValue(), x, numSlots));
    }

    // Bootstraps a spike vector, applies `fillerLevels` plaintext multiplications by 1 (each rescales),
    // then evaluates a sharp Gaussian impulse via a degree-119 Chebyshev approximation. Returns the
    // background-slot leakage precision in bits (how close the background slots stay to impulse(-1)).
    double DeepComputationBgPrecisionBits(ScalingTechnique scalTech, uint32_t ringDim, uint32_t fillerLevels) {
        constexpr double kSpike      = -0.75;
        constexpr double kBackground = -1.0;
        constexpr double kSigma      = 0.04;
        constexpr uint32_t kChebDeg  = 119;

        uint32_t chebDepth            = static_cast<uint32_t>(std::ceil(std::log2(static_cast<double>(kChebDeg)))) + 1;
        uint32_t levelsAfterBootstrap = fillerLevels + chebDepth + 6;
        uint32_t depth                = levelsAfterBootstrap + FHECKKSRNS::GetBootstrapDepth({3, 3}, SK_DIST);

        auto cc     = BuildContext(scalTech, ringDim, depth, 59, 60, 0);
        auto cp     = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
        uint32_t cd = cp->GetCompositeDegree();

        uint32_t numSlots = ringDim / 2;
        cc->EvalBootstrapSetup({3, 3}, {0, 0}, numSlots);
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        cc->EvalBootstrapKeyGen(keys.secretKey, numSlots);

        std::vector<double> x(numSlots, kBackground);
        x[0] = kSpike;

        Plaintext ptx = cc->MakeCKKSPackedPlaintext(x, 1, cd * (depth - 1), nullptr, numSlots);
        auto ct       = cc->EvalBootstrap(cc->Encrypt(keys.publicKey, ptx));

        std::vector<double> ones(numSlots, 1.0);
        for (uint32_t i = 0; i < fillerLevels; ++i) {
            auto pt1 = cc->MakeCKKSPackedPlaintext(ones, 1, ct->GetLevel(), nullptr, numSlots);
            ct       = cc->EvalMult(ct, pt1);
        }

        auto impulse = [=](double v) {
            double z = (v - kSpike) / kSigma;
            return std::exp(-z * z / 2);
        };
        auto ind = cc->EvalChebyshevFunction(impulse, ct, -1.0, 1.0, kChebDeg);

        Plaintext result;
        cc->Decrypt(keys.secretKey, ind, &result);
        auto vo = result->GetRealPackedValue();

        double bgLeak = 0.0;
        for (uint32_t i = 1; i < numSlots; ++i)
            bgLeak = std::max(bgLeak, std::abs(vo[i] - impulse(kBackground)));
        return PrecisionBits(bgLeak);
    }
};

//===========================================================================================================
// Scenario 1: bootstrapping with HYBRID key switching (NumLargeDigits = 3). Fixed by widening the P/Q
// margin for composite scaling. Needs ring 2^14 for the digit margin to become tight (verified to not
// reproduce at 2^12/2^13); sparse 1024-slot packing keeps the test cheap. Pre-fix: CS ~4 bits below FA.
TEST_F(UTCKKSRNSCSvsFA, FullPackingBootstrap_HybridKeySwitch) {
    const uint32_t ringDim                  = 1 << 14;
    const std::vector<uint32_t> levelBudget = {4, 4};
    const uint32_t numSlots                 = 1024;
    const uint32_t levelsAfterBootstrap     = 10;
    const uint32_t numLargeDigits           = 3;

    double faBits = BootstrapPrecisionBits(FLEXIBLEAUTO, ringDim, 59, 60, levelBudget, numSlots, levelsAfterBootstrap,
                                           numLargeDigits);
    double csBits = BootstrapPrecisionBits(COMPOSITESCALINGAUTO, ringDim, 59, 60, levelBudget, numSlots,
                                           levelsAfterBootstrap, numLargeDigits);

    std::cout << "[ cs-vs-fa ] hybrid-keyswitch bootstrap: FA=" << faBits << " bits, CS=" << csBits << " bits\n";
    EXPECT_GT(csBits, 6.0) << "CS bootstrap precision unexpectedly low (" << csBits << " bits)";
    EXPECT_GE(csBits, faBits - 2.0) << "CS lags FA by >2 bits (CS=" << csBits << ", FA=" << faBits
                                    << ") - HYBRID key-switching regression";
}

//===========================================================================================================
// Scenario 2: sparse (8-slot) bootstrapping with modraise headroom deg = firstMod - scalingMod = 4.
// Fixed by applying the pre/post 1/(kN) scaling as an exact power-of-two, the same way as FA. The bug
// only triggers when firstModSize > scalingModSize + 1. Pre-fix: CS ~7 bits below FA.
TEST_F(UTCKKSRNSCSvsFA, SparseBootstrapModRaiseHeadroom) {
    const uint32_t ringDim                  = 1 << 12;
    const std::vector<uint32_t> levelBudget = {3, 3};
    const uint32_t numSlots                 = 8;
    const uint32_t levelsAfterBootstrap     = 2;

    double faBits =
        BootstrapPrecisionBits(FLEXIBLEAUTO, ringDim, 56, 60, levelBudget, numSlots, levelsAfterBootstrap, 0);
    double csBits =
        BootstrapPrecisionBits(COMPOSITESCALINGAUTO, ringDim, 56, 60, levelBudget, numSlots, levelsAfterBootstrap, 0);

    std::cout << "[ cs-vs-fa ] 8-slot deg=4 bootstrap: FA=" << faBits << " bits, CS=" << csBits << " bits\n";
    EXPECT_GT(csBits, 6.0) << "CS 8-slot bootstrap precision unexpectedly low (" << csBits << " bits)";
    EXPECT_GE(csBits, faBits - 3.0) << "CS lags FA by >3 bits (CS=" << csBits << ", FA=" << faBits
                                    << ") - bootstrap pre/post scaling (deg>1) regression";
}

//===========================================================================================================
// Scenario 3: deep computation (filler plaintext mults + sharp Chebyshev impulse) at ring 2^12, full
// packing. Fixed by setting the post-mult scaling factor from the canonical table instead of tracked^2.
// CS used to diverge from FA by many orders of magnitude as the filler depth grows. Pre-fix: CS ~18 bits
// below FA at D = 20. (D = 30 is excluded - its residual is approximate-keyswitch noise, not this fix.)
TEST_F(UTCKKSRNSCSvsFA, DeepComputationWithFillers) {
    const uint32_t ringDim = 1 << 12;
    const uint32_t D       = 20;

    double faBits = DeepComputationBgPrecisionBits(FLEXIBLEAUTO, ringDim, D);
    double csBits = DeepComputationBgPrecisionBits(COMPOSITESCALINGAUTO, ringDim, D);

    std::cout << "[ cs-vs-fa ] deep computation D=" << D << ": FA=" << faBits << " bits, CS=" << csBits << " bits\n";
    // CS background-leak precision must stay within 5 bits of FA (pre-fix the gap was ~18 bits).
    EXPECT_GE(csBits, faBits - 5.0) << "CS background leakage worse than FA by >5 bits at filler depth D=" << D
                                    << " (CS=" << csBits << " bits, FA=" << faBits << " bits)";
}
//===========================================================================================================
#endif  // NATIVEINT == 64
