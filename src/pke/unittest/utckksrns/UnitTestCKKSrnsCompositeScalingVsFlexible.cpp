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
    2b. SparseBootstrapLargeModRaiseHeadroom - same fix at the larger headroom deg = 6
       (scalingModSize = 54, firstModSize = 60). This regime was only half-fixed by the original
       decomposition (it depended on the chosen primes - "good" at some ring dimensions, ~10 bits
       below FA at others). It is fully closed by folding the exact 2^-deg shrink into the
       CoeffsToSlots matrix so the CtS rotations stay on the full-magnitude message (their key-switch
       noise then scales down with the signal instead of being amplified by 2^deg). Pre-fix gap ~10 bits.
    3. DeepComputationWithFillers - the canonical-scaling-factor fix for plaintext multiplication.
       A deep filler chain followed by a sharp Chebyshev impulse makes CS diverge from FA by many
       orders of magnitude. Pre-fix gap ~18 bits at D = 20.

  The remaining two branch fixes (ExtendCiphertext and composite prime modulation) do not need
  dedicated tests per the issue.

  Tolerances (kGapTol, one per test)
  ----------------------------------
  Each test compares one CS run against one FA run, both with unseeded randomness, so the gap
  (faBits - csBits) is a random variable, not a fixed quantity. Measured over 200 runs per test
  (52 for the two expensive scenarios) on x86_64 / GCC 13, NATIVE_SIZE = 64:

    FullPackingBootstrap_HybridKeySwitch          gap -1.50 +/- 0.22
    SparseBootstrapModRaiseHeadroom               gap -1.64 +/- 0.62
    SparseBootstrapLargeModRaiseHeadroom          gap  1.30 +/- 0.71
    StCFirstSparseBootstrap                       gap  1.06 +/- 0.72
    StCFirstSparseBootstrapLargeModRaiseHeadroom  gap  1.33 +/- 0.69
    StCFirstBootstrap1024Slots                    gap -0.56 +/- 0.33
    StCFirstSparseBootstrapWithExtraLevels        gap -0.09 +/- 0.63
    DeepComputationWithFillers                    gap -0.55 +/- 1.21

  Each kGapTol sits at least 5 standard deviations above its measured mean, so a false failure
  is under 1e-6 per run, and at most half of the pre-fix gap the test guards against, so it
  still separates noise from signal in both directions. The tolerance is deliberately per-test:
  the spread differs by 6x across scenarios, so a single shared value would be either flaky for
  the noisy tests or blind for the quiet ones. At the original uniform 3.0 the three tests with
  a positive mean gap sat only ~2.4 sd out and failed about one run in 200 (issue #1290) - the
  failures were not CS precision losses but FA reference runs that happened to land high.
*/

#include "openfhe.h"
#include "gtest/gtest.h"

#include <algorithm>
#include <cmath>
#include <vector>

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

    // Bootstraps a freshly-encrypted vector and returns the achieved precision in bits. With stcFirst the
    // SlotsToCoeffs-first ("BTSlotsEncoding") variant is used, whose input must keep levelBudget[1] levels for
    // the initial SlotsToCoeffs; extraLevels additionally leaves the input that many levels above the
    // minimum, exercising the level adjustment performed before SlotsToCoeffs.
    double BootstrapPrecisionBits(ScalingTechnique scalTech, uint32_t ringDim, uint32_t scalingModSize,
                                  uint32_t firstModSize, const std::vector<uint32_t>& levelBudget, uint32_t numSlots,
                                  uint32_t levelsAfterBootstrap, uint32_t numLargeDigits, bool stcFirst = false,
                                  uint32_t extraLevels = 0) {
        uint32_t depth = levelsAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, SK_DIST);
        auto cc        = BuildContext(scalTech, ringDim, depth, scalingModSize, firstModSize, numLargeDigits);
        auto cp        = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
        uint32_t cd    = cp->GetCompositeDegree();

        cc->EvalBootstrapSetup(levelBudget, {0, 0}, numSlots, 0, true, stcFirst);
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        cc->EvalBootstrapKeyGen(keys.secretKey, numSlots);

        // Deterministic input in (0,1) so FA and CS see the same signal.
        std::vector<double> x(numSlots);
        for (uint32_t i = 0; i < numSlots; ++i)
            x[i] = 0.25 + 0.5 * (0.5 * std::sin(0.3 * static_cast<double>(i) + 1.0) + 0.5);

        uint32_t inputLevel = depth - 1 - ((stcFirst) ? levelBudget[1] : 0) - extraLevels;
        Plaintext pt        = cc->MakeCKKSPackedPlaintext(x, 1, cd * inputLevel, nullptr, numSlots);
        auto ct             = cc->Encrypt(keys.publicKey, pt);
        auto ctAfter        = cc->EvalBootstrap(ct);

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
    constexpr double kGapTol                = 2.0;  // measured gap -1.50 +/- 0.22; pre-fix gap ~4
    const uint32_t ringDim                  = 1 << 14;
    const std::vector<uint32_t> levelBudget = {4, 4};
    const uint32_t numSlots                 = 1024;
    const uint32_t levelsAfterBootstrap     = 10;
    const uint32_t numLargeDigits           = 3;

    double faBits = BootstrapPrecisionBits(FLEXIBLEAUTO, ringDim, 59, 60, levelBudget, numSlots, levelsAfterBootstrap,
                                           numLargeDigits);
    double csBits = BootstrapPrecisionBits(COMPOSITESCALINGAUTO, ringDim, 59, 60, levelBudget, numSlots,
                                           levelsAfterBootstrap, numLargeDigits);

    EXPECT_GT(csBits, 6.0) << "CS bootstrap precision unexpectedly low (" << csBits << " bits)";
    EXPECT_GE(csBits, faBits - kGapTol) << "CS lags FA by >" << kGapTol << " bits (CS=" << csBits << ", FA=" << faBits
                                        << ") - HYBRID key-switching regression";
}

//===========================================================================================================
// Scenario 2: sparse (8-slot) bootstrapping with modraise headroom deg = firstMod - scalingMod = 4.
// Fixed by applying the pre/post 1/(kN) scaling as an exact power-of-two, the same way as FA. The bug
// only triggers when firstModSize > scalingModSize + 1. Pre-fix: CS ~7 bits below FA.
TEST_F(UTCKKSRNSCSvsFA, SparseBootstrapModRaiseHeadroom) {
    constexpr double kGapTol                = 3.0;  // measured gap -1.64 +/- 0.62; pre-fix gap ~7
    const uint32_t ringDim                  = 1 << 12;
    const std::vector<uint32_t> levelBudget = {3, 3};
    const uint32_t numSlots                 = 8;
    const uint32_t levelsAfterBootstrap     = 2;

    double faBits =
        BootstrapPrecisionBits(FLEXIBLEAUTO, ringDim, 56, 60, levelBudget, numSlots, levelsAfterBootstrap, 0);
    double csBits =
        BootstrapPrecisionBits(COMPOSITESCALINGAUTO, ringDim, 56, 60, levelBudget, numSlots, levelsAfterBootstrap, 0);

    EXPECT_GT(csBits, 6.0) << "CS 8-slot bootstrap precision unexpectedly low (" << csBits << " bits)";
    EXPECT_GE(csBits, faBits - kGapTol) << "CS lags FA by >" << kGapTol << " bits (CS=" << csBits << ", FA=" << faBits
                                        << ") - bootstrap pre/post scaling (deg>1) regression";
}

//===========================================================================================================
// Scenario 2b: sparse (8-slot) bootstrapping with the larger modraise headroom deg = 6 (scalingModSize = 54,
// firstModSize = 60) at ring 2^12 - the case from issue-1181. The original decomposition fix only half-closed
// this regime (prime-dependent: CS landed ~10 bits below FA at this ring); folding the exact 2^-deg shrink
// into the CoeffsToSlots matrix closes it (CS now within ~1.5 bits of FA, ~17 vs ~18.5). Pre-fix: CS ~8 bits
// (gap ~10).
TEST_F(UTCKKSRNSCSvsFA, SparseBootstrapLargeModRaiseHeadroom) {
    constexpr double kGapTol                = 5.0;  // measured gap 1.30 +/- 0.71; pre-fix gap ~10
    const uint32_t ringDim                  = 1 << 12;
    const std::vector<uint32_t> levelBudget = {3, 3};
    const uint32_t numSlots                 = 8;
    const uint32_t levelsAfterBootstrap     = 2;

    double faBits =
        BootstrapPrecisionBits(FLEXIBLEAUTO, ringDim, 54, 60, levelBudget, numSlots, levelsAfterBootstrap, 0);
    double csBits =
        BootstrapPrecisionBits(COMPOSITESCALINGAUTO, ringDim, 54, 60, levelBudget, numSlots, levelsAfterBootstrap, 0);

    EXPECT_GT(csBits, 12.0) << "CS 8-slot deg=6 bootstrap precision unexpectedly low (" << csBits << " bits)";
    EXPECT_GE(csBits, faBits - kGapTol) << "CS lags FA by >" << kGapTol << " bits (CS=" << csBits << ", FA=" << faBits
                                        << ") - large modraise headroom (deg=6) regression";
}

//===========================================================================================================
// Scenario 4: SlotsToCoeffs-first ("BTSlotsEncoding") bootstrapping. Composite scaling support for this mode
// required (a) counting the towers consumed by the initial SlotsToCoeffs in units of compositeDegree, so the
// input level matches the level at which the StC matrix is encoded (previously a modulus mismatch), and
// (b) using the level-adjustment formula of AdjustLevelsAndDepthInPlace when the input arrives with extra
// levels (the current and target levels were mixed up, which is invisible for FA but cost ~10 bits for CS).
// CS is expected to be within a few bits of FA in this mode, like in the ModRaise-first mode.
TEST_F(UTCKKSRNSCSvsFA, StCFirstSparseBootstrap) {
    constexpr double kGapTol                = 5.0;  // measured gap 1.06 +/- 0.72; pre-fix gap ~10
    const uint32_t ringDim                  = 1 << 12;
    const std::vector<uint32_t> levelBudget = {2, 2};
    const uint32_t numSlots                 = 8;
    const uint32_t levelsAfterBootstrap     = 2;

    double faBits =
        BootstrapPrecisionBits(FLEXIBLEAUTO, ringDim, 59, 60, levelBudget, numSlots, levelsAfterBootstrap, 0, true);
    double csBits = BootstrapPrecisionBits(COMPOSITESCALINGAUTO, ringDim, 59, 60, levelBudget, numSlots,
                                           levelsAfterBootstrap, 0, true);

    EXPECT_GT(csBits, 12.0) << "CS StC-first 8-slot bootstrap precision unexpectedly low (" << csBits << " bits)";
    EXPECT_GE(csBits, faBits - kGapTol) << "CS lags FA by >" << kGapTol << " bits (CS=" << csBits << ", FA=" << faBits
                                        << ") - StC-first composite scaling regression";
}

TEST_F(UTCKKSRNSCSvsFA, StCFirstSparseBootstrapLargeModRaiseHeadroom) {
    constexpr double kGapTol                = 5.0;  // measured gap 1.33 +/- 0.69; pre-fix gap ~10
    const uint32_t ringDim                  = 1 << 12;
    const std::vector<uint32_t> levelBudget = {2, 2};
    const uint32_t numSlots                 = 8;
    const uint32_t levelsAfterBootstrap     = 2;

    double faBits =
        BootstrapPrecisionBits(FLEXIBLEAUTO, ringDim, 54, 60, levelBudget, numSlots, levelsAfterBootstrap, 0, true);
    double csBits = BootstrapPrecisionBits(COMPOSITESCALINGAUTO, ringDim, 54, 60, levelBudget, numSlots,
                                           levelsAfterBootstrap, 0, true);

    EXPECT_GT(csBits, 12.0) << "CS StC-first deg=6 bootstrap precision unexpectedly low (" << csBits << " bits)";
    EXPECT_GE(csBits, faBits - kGapTol) << "CS lags FA by >" << kGapTol << " bits (CS=" << csBits << ", FA=" << faBits
                                        << ") - StC-first large modraise headroom regression";
}

TEST_F(UTCKKSRNSCSvsFA, StCFirstBootstrap1024Slots) {
    constexpr double kGapTol                = 3.0;  // measured gap -0.56 +/- 0.33; pre-fix gap ~10
    const uint32_t ringDim                  = 1 << 12;
    const std::vector<uint32_t> levelBudget = {3, 3};
    const uint32_t numSlots                 = 1024;
    const uint32_t levelsAfterBootstrap     = 2;

    double faBits =
        BootstrapPrecisionBits(FLEXIBLEAUTO, ringDim, 59, 60, levelBudget, numSlots, levelsAfterBootstrap, 0, true);
    double csBits = BootstrapPrecisionBits(COMPOSITESCALINGAUTO, ringDim, 59, 60, levelBudget, numSlots,
                                           levelsAfterBootstrap, 0, true);

    EXPECT_GT(csBits, 12.0) << "CS StC-first 1024-slot bootstrap precision unexpectedly low (" << csBits << " bits)";
    EXPECT_GE(csBits, faBits - kGapTol) << "CS lags FA by >" << kGapTol << " bits (CS=" << csBits << ", FA=" << faBits
                                        << ") - StC-first composite scaling regression";
}

// Input arrives with 2 more levels than the StC-first minimum, so the level adjustment before SlotsToCoeffs
// runs. Pre-fix: CS ~15 bits vs FA ~25 bits at ring 2^6.
TEST_F(UTCKKSRNSCSvsFA, StCFirstSparseBootstrapWithExtraLevels) {
    constexpr double kGapTol                = 5.0;  // measured gap -0.09 +/- 0.63; pre-fix gap ~10
    const uint32_t ringDim                  = 1 << 12;
    const std::vector<uint32_t> levelBudget = {2, 2};
    const uint32_t numSlots                 = 8;
    const uint32_t levelsAfterBootstrap     = 2;
    const uint32_t extraLevels              = 2;

    double faBits = BootstrapPrecisionBits(FLEXIBLEAUTO, ringDim, 59, 60, levelBudget, numSlots, levelsAfterBootstrap,
                                           0, true, extraLevels);
    double csBits = BootstrapPrecisionBits(COMPOSITESCALINGAUTO, ringDim, 59, 60, levelBudget, numSlots,
                                           levelsAfterBootstrap, 0, true, extraLevels);

    EXPECT_GT(csBits, 12.0) << "CS StC-first bootstrap precision with extra input levels unexpectedly low (" << csBits
                            << " bits)";
    EXPECT_GE(csBits, faBits - kGapTol) << "CS lags FA by >" << kGapTol << " bits (CS=" << csBits << ", FA=" << faBits
                                        << ") - StC-first level adjustment regression";
}

//===========================================================================================================
// Scenario 3: deep computation (filler plaintext mults + sharp Chebyshev impulse) at ring 2^12, full
// packing. Fixed by setting the post-mult scaling factor from the canonical table instead of tracked^2.
// CS used to diverge from FA by many orders of magnitude as the filler depth grows. Pre-fix: CS ~18 bits
// below FA at D = 20. (D = 30 is excluded - its residual is approximate-keyswitch noise, not this fix.)
TEST_F(UTCKKSRNSCSvsFA, DeepComputationWithFillers) {
    if (MATHBACKEND == 2)
        GTEST_SKIP() << "Disabled for MATHBACKEND 2: the coefficient modulus at filler depth D = 20 is too large "
                        "for the default BACKEND 2 configuration.";

    constexpr double kGapTol = 7.0;  // measured gap -0.55 +/- 1.21; pre-fix gap ~18
    const uint32_t ringDim   = 1 << 12;
    const uint32_t D         = 20;

    double faBits = DeepComputationBgPrecisionBits(FLEXIBLEAUTO, ringDim, D);
    double csBits = DeepComputationBgPrecisionBits(COMPOSITESCALINGAUTO, ringDim, D);

    // This scenario has the widest run-to-run spread in the file (sd 1.25 bits, ~2x the sparse
    // bootstrap tests), so it needs the widest tolerance; the pre-fix gap of ~18 bits leaves room.
    EXPECT_GE(csBits, faBits - kGapTol) << "CS background leakage worse than FA by >" << kGapTol
                                        << " bits at filler depth D=" << D << " (CS=" << csBits
                                        << " bits, FA=" << faBits << " bits)";
}
//===========================================================================================================
#endif  // NATIVEINT == 64
