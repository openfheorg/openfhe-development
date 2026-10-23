//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
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
  ModRaise-first bootstrapping without the level of the correction step. The step before the modulus raise scales
  the message down by 2^-c and brings it to the scaling factor of the raised level with a multiplication and a
  rescale, which needs an input one level above the bottom one. When no correction is needed, that is, when the
  first modulus is at least 2^correctionFactor times the scaling modulus (composite scaling, or a small scaling
  modulus, or an explicit correction factor equal to the ratio), the step is skipped and the input may be at the
  very bottom level, with the same precision as an input one level above it. When a correction is needed, the caller
  can fold the scaling by 2^-c into its last multiplication and pass correctionApplied to EvalBootstrap, which then
  skips the step (the result is scaled back up by 2^c as usual) and saves the level in the same way. The 128-bit
  build supports FIXEDMANUAL and FIXEDAUTO only, and its larger moduli always give a zero correction.
 */
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <vector>

#include "gtest/gtest.h"
#include "openfhe.h"

using namespace lbcrypto;

namespace {

constexpr uint32_t RING_DIM = 1 << 11;
constexpr uint32_t SLOTS = RING_DIM / 2;
const std::vector<uint32_t> LEVEL_BUDGET = {2, 2};
constexpr uint32_t LEVELS_AFTER = 1;

struct Config {
    ScalingTechnique st;
    uint32_t scalingModSize;
    uint32_t firstModSize;
    uint32_t correctionFactor;  // passed to EvalBootstrapSetup (0: default)
    uint32_t registerWordSize;  // composite scaling only
};

CryptoContext<DCRTPoly> MakeContext(const Config& c, uint32_t depth) {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecretKeyDist(SPARSE_ENCAPSULATED);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(RING_DIM);
    parameters.SetScalingModSize(c.scalingModSize);
    parameters.SetFirstModSize(c.firstModSize);
    parameters.SetScalingTechnique(c.st);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetBatchSize(SLOTS);
    parameters.SetMultiplicativeDepth(depth);
    if (c.st == COMPOSITESCALINGAUTO)
        parameters.SetRegisterWordSize(c.registerWordSize);
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);
    return cc;
}

std::vector<double> TestVector() {
    std::vector<double> x(SLOTS);
    for (uint32_t i = 0; i < SLOTS; ++i)
        x[i] = std::sin(0.37 * i + 0.11);  // values in [-1, 1]
    return x;
}

// precision in bits of the bootstrapping of a ciphertext encrypted at the given level (noise degree 1), or of the
// product of two such ciphertexts (noise degree 2, pending rescale) when square is set
double BootstrapPrecision(const CryptoContext<DCRTPoly>& cc, const KeyPair<DCRTPoly>& keyPair, uint32_t level,
                          bool square = false) {
    auto x = TestVector();
    auto ct = cc->Encrypt(keyPair.publicKey, cc->MakeCKKSPackedPlaintext(x, 1, level, nullptr, SLOTS));
    if (square) {
        ct = cc->EvalMult(ct, ct);
        for (auto& v : x)
            v *= v;
    }
    auto ctBoot = cc->EvalBootstrap(ct);
    Plaintext result;
    cc->Decrypt(keyPair.secretKey, ctBoot, &result);
    result->SetLength(SLOTS);
    const auto y = result->GetRealPackedValue();
    double maxErr = 0.0;
    for (uint32_t i = 0; i < SLOTS; ++i)
        maxErr = std::max(maxErr, std::abs(y[i] - x[i]));
    return -std::log2(std::max(maxErr, 1e-18));
}

// A configuration whose correction is zero: the input at the bottom level bootstraps with the precision of an input
// one level above it, and so does a product at the level above with its rescale pending.
void CheckBottomLevelInput(const Config& c) {
    const uint32_t depth = LEVELS_AFTER + FHECKKSRNS::GetBootstrapDepth(LEVEL_BUDGET, SPARSE_ENCAPSULATED);
    auto cc = MakeContext(c, depth);
    cc->EvalBootstrapSetup(LEVEL_BUDGET, {0, 0}, SLOTS, c.correctionFactor);
    auto kp = cc->KeyGen();
    cc->EvalMultKeyGen(kp.secretKey);
    cc->EvalBootstrapKeyGen(kp.secretKey, SLOTS);
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    const uint32_t d = cryptoParams->GetCompositeDegree();
    // the bottom level has compositeDegree towers (FLEXIBLEAUTOEXT has one more tower than the depth implies)
    const uint32_t bottomLevel = cryptoParams->GetElementParams()->GetParams().size() - d;

    const double above = BootstrapPrecision(cc, kp, bottomLevel - d);
    const double bottom = BootstrapPrecision(cc, kp, bottomLevel);
    EXPECT_GT(bottom, 10.0);
    EXPECT_NEAR(bottom, above, 1.5);
    if (c.st != FIXEDMANUAL) {
        // the pending rescale of the product lands on the bottom level
        const double pending = BootstrapPrecision(cc, kp, bottomLevel - d, true);
        EXPECT_GT(pending, 10.0);
    }
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
}

#if NATIVEINT == 128
TEST(UTCKKSRNS_BOOT_ZERO_CORRECTION, BottomLevelInputFixedAuto) {
    CheckBottomLevelInput({FIXEDAUTO, 78, 89, 0, 128});
}
TEST(UTCKKSRNS_BOOT_ZERO_CORRECTION, BottomLevelInputFixedManual) {
    CheckBottomLevelInput({FIXEDMANUAL, 78, 89, 0, 128});
}
#else
// first modulus 2^10 times the scaling modulus: the explicit correction factor 10 equals deg, so c = 0
TEST(UTCKKSRNS_BOOT_ZERO_CORRECTION, BottomLevelInputFlexibleAuto) {
    CheckBottomLevelInput({FLEXIBLEAUTO, 50, 60, 10, 64});
}
TEST(UTCKKSRNS_BOOT_ZERO_CORRECTION, BottomLevelInputFlexibleAutoExt) {
    CheckBottomLevelInput({FLEXIBLEAUTOEXT, 50, 60, 10, 64});
}
TEST(UTCKKSRNS_BOOT_ZERO_CORRECTION, BottomLevelInputFixedAuto) {
    CheckBottomLevelInput({FIXEDAUTO, 50, 60, 10, 64});
}
TEST(UTCKKSRNS_BOOT_ZERO_CORRECTION, BottomLevelInputFixedManual) {
    CheckBottomLevelInput({FIXEDMANUAL, 50, 60, 10, 64});
}
// composite scaling: deg exceeds the default correction factor
TEST(UTCKKSRNS_BOOT_ZERO_CORRECTION, BottomLevelInputCompositeScaling) {
    CheckBottomLevelInput({COMPOSITESCALINGAUTO, 50, 60, 0, 32});
}
#endif

#if NATIVEINT != 128
// A nonzero correction still needs the level: an input at the bottom level is rejected with a clear exception, and
// the input one level above it is bootstrapped as before.
TEST(UTCKKSRNS_BOOT_ZERO_CORRECTION, NonzeroCorrectionNeedsTheLevel) {
    const Config c{FLEXIBLEAUTO, 59, 60, 0, 64};
    const uint32_t depth = LEVELS_AFTER + FHECKKSRNS::GetBootstrapDepth(LEVEL_BUDGET, SPARSE_ENCAPSULATED);
    auto cc = MakeContext(c, depth);
    cc->EvalBootstrapSetup(LEVEL_BUDGET, {0, 0}, SLOTS);
    auto kp = cc->KeyGen();
    cc->EvalMultKeyGen(kp.secretKey);
    cc->EvalBootstrapKeyGen(kp.secretKey, SLOTS);

    auto ct = cc->Encrypt(kp.publicKey, cc->MakeCKKSPackedPlaintext(TestVector(), 1, depth, nullptr, SLOTS));
    EXPECT_THROW(cc->EvalBootstrap(ct), OpenFHEException);
    EXPECT_GT(BootstrapPrecision(cc, kp, depth - 1), 10.0);
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
}

// precision in bits of a * x bootstrapped from the product of x (encrypted at the given level) by the constant
// a * 2^-c with the rescale of the product pending (or done for FIXEDMANUAL), bootstrapped with correctionApplied
double CallerCorrectionPrecision(const CryptoContext<DCRTPoly>& cc, const KeyPair<DCRTPoly>& keyPair, uint32_t level,
                                 bool rescale) {
    constexpr double a = 0.75;
    const uint32_t c = cc->GetCKKSBootCorrection();
    auto x = TestVector();
    auto ct = cc->Encrypt(keyPair.publicKey, cc->MakeCKKSPackedPlaintext(x, 1, level, nullptr, SLOTS));
    ct = cc->EvalMult(ct, a * std::ldexp(1.0, -static_cast<int32_t>(c)));
    if (rescale)
        cc->ModReduceInPlace(ct);
    auto ctBoot = cc->EvalBootstrap(ct, 1, 0, true);
    Plaintext result;
    cc->Decrypt(keyPair.secretKey, ctBoot, &result);
    result->SetLength(SLOTS);
    const auto y = result->GetRealPackedValue();
    double maxErr = 0.0;
    for (uint32_t i = 0; i < SLOTS; ++i)
        maxErr = std::max(maxErr, std::abs(y[i] - a * x[i]));
    return -std::log2(std::max(maxErr, 1e-18));
}

// A nonzero correction applied by the caller: the product by a * 2^-c one level above the bottom (its rescale
// landing on the bottom level) bootstraps to a * x with the precision of the standard path, which needs the level.
void CheckCallerCorrection(const Config& c) {
    // one more level than needed: the reference input, two levels above the bottom, must have fewer towers than
    // the bootstrapped output (otherwise bootstrapping returns the input)
    const uint32_t depth = LEVELS_AFTER + 1 + FHECKKSRNS::GetBootstrapDepth(LEVEL_BUDGET, SPARSE_ENCAPSULATED);
    auto cc = MakeContext(c, depth);
    cc->EvalBootstrapSetup(LEVEL_BUDGET, {0, 0}, SLOTS, c.correctionFactor);
    auto kp = cc->KeyGen();
    cc->EvalMultKeyGen(kp.secretKey);
    cc->EvalBootstrapKeyGen(kp.secretKey, SLOTS);
    EXPECT_GT(cc->GetCKKSBootCorrection(), 0u);
    const uint32_t bottomLevel = cc->GetCryptoParameters()->GetElementParams()->GetParams().size() - 1;

    // the standard path: the product one level above the bottom goes through the correction step of bootstrapping
    const double standard = BootstrapPrecision(cc, kp, bottomLevel - 2, true);
    const bool manual = (c.st == FIXEDMANUAL);
    const double applied = CallerCorrectionPrecision(cc, kp, bottomLevel - 1, manual);
    EXPECT_GT(applied, 10.0);
    EXPECT_NEAR(applied, standard, 1.5);
    // a bottom-level input is still rejected without the flag
    auto ct = cc->Encrypt(kp.publicKey, cc->MakeCKKSPackedPlaintext(TestVector(), 1, bottomLevel, nullptr, SLOTS));
    EXPECT_THROW(cc->EvalBootstrap(ct), OpenFHEException);
    // the flag is for a single iteration of the ModRaise-first variant
    EXPECT_THROW(cc->EvalBootstrap(ct, 2, 20, true), OpenFHEException);
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
}

TEST(UTCKKSRNS_BOOT_ZERO_CORRECTION, CallerCorrectionFlexibleAuto) {
    CheckCallerCorrection({FLEXIBLEAUTO, 59, 60, 0, 64});
}
TEST(UTCKKSRNS_BOOT_ZERO_CORRECTION, CallerCorrectionFlexibleAutoExt) {
    CheckCallerCorrection({FLEXIBLEAUTOEXT, 59, 60, 0, 64});
}
TEST(UTCKKSRNS_BOOT_ZERO_CORRECTION, CallerCorrectionFixedAuto) {
    CheckCallerCorrection({FIXEDAUTO, 59, 60, 0, 64});
}
TEST(UTCKKSRNS_BOOT_ZERO_CORRECTION, CallerCorrectionFixedManual) {
    CheckCallerCorrection({FIXEDMANUAL, 59, 60, 0, 64});
}
#endif

}  // namespace
