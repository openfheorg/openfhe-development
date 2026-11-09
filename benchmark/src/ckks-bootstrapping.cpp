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
  Benchmarks for CKKS bootstrapping (EvalBootstrap) in its ModRaise-first (CKKSBoot) and SlotsToCoeffs-first
  (CKKSBootStC) variants, see CKKS_BOOTSTRAPPING.md
 */

#include <cmath>
#include <cstdint>
#include <exception>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "benchmark/benchmark.h"
#include "config_core.h"
#include "cryptocontext.h"
#include "gen-cryptocontext.h"
#include "scheme/ckksrns/ckksrns-fhe.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"

using namespace lbcrypto;

namespace {

struct boot_config {
    uint32_t ringDim;
    uint32_t slots;
    uint32_t dcrtBits;
    uint32_t firstMod;
    uint32_t numDigits;
    uint32_t levels;  // levels an application can spend between two bootstrappings
    uint32_t iters;
    std::vector<uint32_t> lvlb;
    SecretKeyDist skdst;
    ScalingTechnique stech;
    uint32_t precision;  // single-round precision handed to the second iteration
};

[[maybe_unused]] constexpr ScalingTechnique FA = FLEXIBLEAUTO;
[[maybe_unused]] constexpr ScalingTechnique FM = FIXEDMANUAL;
[[maybe_unused]] constexpr ScalingTechnique CS = COMPOSITESCALINGAUTO;
[[maybe_unused]] constexpr SecretKeyDist HT = HYBRID_TERNARY;
[[maybe_unused]] constexpr SecretKeyDist UT = UNIFORM_TERNARY;
[[maybe_unused]] constexpr SecretKeyDist SE = SPARSE_ENCAPSULATED;

// the security table that matches the secret key distribution (see CKKS_BOOTSTRAPPING.md)
SecurityLevel SecurityLevelFor(SecretKeyDist skd) {
    return (skd == SPARSE_ENCAPSULATED || skd == SPARSE_TERNARY) ? HE_SPARSE_H192_128 : HEORG24_128;
}

// All rows use HYBRID_TERNARY secrets under HEORG24_128 (the security table of the 2024 guidelines; the library
// checks the bound at context generation and a non-compliant row is skipped), except the uniform-ternary reference
// row. `levels` counts the levels an application can spend between two bootstrappings: the chain has
// levels + GetBootstrapDepth (+ 1 per further iteration) levels, and the output keeps, on top of `levels`, what
// the next bootstrapping needs at the bottom (lvlb[1] levels for the SlotsToCoeffs of the StC-first variant, one
// level for the correction of the plain ModRaise-first flow of two iterations, none when the correction is applied
// by the caller as CKKSBoot does for one iteration). Both variants run every row. The scaling modulus, level
// budget and digits of each row are the fastest combination measured at 36 threads (StC-first time, which is the
// faster variant on every row) among the configurations that keep the row's precision.
// clang-format off
const std::vector<boot_config> boot_configs = {
    // ringDim,  slots, dcrtBits, firstMod, numDigits, levels, iters,   lvlb, skdst, stech, precision
    // 2^16, full packing, one iteration: four levels, then the most levels that fit the bound (ten)
    { 1 << 16, 1 << 15,       59,       60,         4,      4,     1, {5, 3},    HT,    FA,  0},
    { 1 << 16, 1 << 15,       54,       60,         7,     10,     1, {4, 3},    HT,    FA,  0},
    // two iterations (the second refines the first round's precision, given in the last column): 8 and 9 levels
    { 1 << 16, 1 << 15,       50,       56,         6,      8,     2, {4, 3},    HT,    FA,  7},
    { 1 << 16, 1 << 15,       50,       56,         6,      9,     2, {4, 3},    HT,    FA,  7},
    // two iterations with FIXEDMANUAL scaling: 7 and 8 levels
    { 1 << 16, 1 << 15,       52,       58,         5,      7,     2, {4, 3},    HT,    FM, 10},
    { 1 << 16, 1 << 15,       52,       58,         6,      8,     2, {4, 3},    HT,    FM, 10},
    // sparse packing: 2^12 and 2^5 slots, four levels and the most levels that fit
    { 1 << 16, 1 << 12,       59,       60,         3,      4,     1, {3, 3},    HT,    FA,  0},
    { 1 << 16, 1 << 12,       59,       60,         6,      8,     1, {3, 3},    HT,    FA,  0},
    { 1 << 16,  1 << 5,       59,       60,         3,      4,     1, {1, 1},    HT,    FA,  0},
    { 1 << 16,  1 << 5,       59,       60,         6,     12,     1, {1, 1},    HT,    FA,  0},
    // uniform ternary secrets: Set II of the homomorphic encryption security guidelines (cic.iacr.org/p/1/4/26,
    // Table 5.8) with four levels, which is what fits the library's bound
    { 1 << 16, 1 << 15,       58,       60,         8,      4,     1, {3, 3},    UT,    FA,  0},
    // 2^17, full packing, one iteration: four levels, then fourteen
    { 1 << 17, 1 << 16,       59,       60,         4,      4,     1, {5, 4},    HT,    FA,  0},
    { 1 << 17, 1 << 16,       59,       60,         4,     14,     1, {5, 4},    HT,    FA,  0},
    // two iterations, 9 levels
    { 1 << 17, 1 << 16,       59,       60,         3,      9,     2, {5, 4},    HT,    FA, 13},
    // sparse packing: 2^5 slots
    { 1 << 17,  1 << 5,       59,       60,         3,      4,     1, {1, 1},    HT,    FA,  0},
    // composite scaling, two iterations, 9 levels
    { 1 << 17, 1 << 16,       78,       96,         3,      9,     2, {5, 4},    HT,    CS,  0},
};

// GPU-leaning rows, one per row above: the fastest configuration of the smallest GPU memory tier (16 / 24 / 48 GB,
// for about 1.5 x the key bytes) that is within 25% of the row's time at the same precision, with fewer digits where
// it is a tie, or the CPU row itself where there is none. Registered as CKKSBoot-GPU/... and CKKSBootStC-GPU/... so
// that --benchmark_filter selects either table.
const std::vector<boot_config> boot_configs_gpu = {
    // ringDim,  slots, dcrtBits, firstMod, numDigits, levels, iters,   lvlb, skdst, stech, precision
    { 1 << 16, 1 << 15,       59,       60,         3,      4,     1, {4, 3},    HT,    FA,  0},
    { 1 << 16, 1 << 15,       56,       60,         7,     10,     1, {3, 3},    HT,    FA,  0},
    { 1 << 16, 1 << 15,       52,       58,         7,      8,     2, {3, 3},    HT,    FA, 10},
    { 1 << 16, 1 << 15,       50,       56,         6,      9,     2, {4, 3},    HT,    FA,  7},
    { 1 << 16, 1 << 15,       52,       58,         5,      7,     2, {4, 3},    HT,    FM, 10},
    { 1 << 16, 1 << 15,       52,       58,         6,      8,     2, {4, 3},    HT,    FM, 10},
    { 1 << 16, 1 << 12,       59,       60,         3,      4,     1, {3, 3},    HT,    FA,  0},
    { 1 << 16, 1 << 12,       59,       60,         6,      8,     1, {3, 3},    HT,    FA,  0},
    { 1 << 16,  1 << 5,       59,       60,         3,      4,     1, {1, 1},    HT,    FA,  0},
    { 1 << 16,  1 << 5,       59,       60,         6,     12,     1, {1, 1},    HT,    FA,  0},
    { 1 << 16, 1 << 15,       58,       60,         8,      4,     1, {3, 3},    UT,    FA,  0},
    { 1 << 17, 1 << 16,       59,       60,         2,      4,     1, {5, 4},    HT,    FA,  0},
    { 1 << 17, 1 << 16,       59,       60,         2,     14,     1, {5, 4},    HT,    FA,  0},
    { 1 << 17, 1 << 16,       59,       60,         2,      9,     2, {4, 4},    HT,    FA, 13},
    { 1 << 17,  1 << 5,       59,       60,         3,      4,     1, {1, 1},    HT,    FA,  0},
    { 1 << 17, 1 << 16,       78,       96,         3,      9,     2, {5, 4},    HT,    CS,  0},
};
// clang-format on

uint32_t GetDepth(const boot_config& t, bool stcFirst) {
    uint32_t depth = t.levels + FHECKKSRNS::GetBootstrapDepth(t.lvlb, t.skdst) + (t.iters - 1);
    return (stcFirst || t.iters == 1) ? depth : depth + 1;
}

CryptoContext<DCRTPoly> GenBootContext(const boot_config& t, uint32_t depth) {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecretKeyDist(t.skdst);
    parameters.SetSecurityLevel(SecurityLevelFor(t.skdst));
    parameters.SetRingDim(t.ringDim);
    parameters.SetScalingModSize(t.dcrtBits);
    parameters.SetFirstModSize(t.firstMod);
    parameters.SetNumLargeDigits(t.numDigits);
    parameters.SetScalingTechnique(t.stech);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetMultiplicativeDepth(depth);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);
    return cc;
}

std::vector<double> BuildInput(uint32_t slots) {
    std::vector<double> input(slots);
    for (uint32_t i = 0; i < slots; ++i)
        input[i] = -1.0 + 2.0 * i / slots;
    return input;
}

double MeanPrecisionBits(const std::vector<double>& expected, const std::vector<double>& actual) {
    double sumError = 0.0;
    for (size_t i = 0; i < expected.size(); ++i)
        sumError += std::abs(expected[i] - actual[i]);
    const double meanError = sumError / expected.size();
    return (meanError == 0.0) ? std::numeric_limits<double>::infinity() : -std::log2(meanError);
}

[[maybe_unused]] void CKKSBootstrap(benchmark::State& state, const boot_config& t, bool stcFirst) {
    const uint32_t depth = GetDepth(t, stcFirst);
    CryptoContext<DCRTPoly> cc;
    try {
        cc = GenBootContext(t, depth);  // throws when the row does not meet the security bound of its level
    } catch (const std::exception& e) {
        state.SkipWithError(e.what());
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
        return;
    }

    cc->EvalBootstrapSetup(t.lvlb, {0, 0}, t.slots, 0, true, stcFirst);

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    cc->EvalBootstrapKeyGen(keyPair.secretKey, t.slots);

    // One iteration of ModRaise-first bootstrapping takes its input at the bottom level: the scaling by 2^-c that
    // precedes the modulus raise (c = GetCKKSBootCorrection) is folded into the input, here into the encoding and
    // in an application into its last multiplication, and EvalBootstrap is told so (correctionApplied). Two
    // iterations use the plain flow, with the input one level above the bottom; the StC-first variant takes its
    // input lvlb[1] levels above the bottom, for its SlotsToCoeffs.
    const bool correctionApplied = !stcFirst && t.iters == 1;
    const uint32_t correction = correctionApplied ? cc->GetCKKSBootCorrection() : 0;
    const uint32_t reserve = stcFirst ? t.lvlb[1] : correctionApplied ? 0 : 1;

    auto x = BuildInput(t.slots);
    std::vector<double> input(x);
    for (auto& v : input)
        v = std::ldexp(v, -static_cast<int>(correction));
    auto ptxt = cc->MakeCKKSPackedPlaintext(input, 1, depth - reserve, nullptr, t.slots);
    ptxt->SetLength(t.slots);
    auto ctxt = cc->Encrypt(keyPair.publicKey, ptxt);

    Ciphertext<DCRTPoly> ctxtAfter;
    for (auto _ : state)
        ctxtAfter = cc->EvalBootstrap(ctxt, t.iters, t.precision, correctionApplied);

    Plaintext result;
    cc->Decrypt(keyPair.secretKey, ctxtAfter, &result);
    result->SetLength(t.slots);
    state.counters["precision"] = MeanPrecisionBits(x, result->GetRealPackedValue());
    state.counters["levels"] = depth - ctxtAfter->GetLevel() - (ctxtAfter->GetNoiseScaleDeg() - 1) - reserve;

    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
}

std::string RowName(const boot_config& t) {
    return std::string(t.stech == FA ? "FA" :
                       t.stech == FM ? "FM" :
                                       "CS") +
           (t.skdst == HT ? "" :
            t.skdst == UT ? "/UT" :
                            "/SE") +
           "/logN:" + std::to_string(static_cast<uint32_t>(std::log2(t.ringDim))) +
           "/logSlots:" + std::to_string(static_cast<uint32_t>(std::log2(t.slots))) +
           "/sf:" + std::to_string(t.dcrtBits) + "/first:" + std::to_string(t.firstMod) +
           "/levels:" + std::to_string(t.levels) + "/iters:" + std::to_string(t.iters) +
           "/dnum:" + std::to_string(t.numDigits);
}

}  // namespace

int main(int argc, char** argv) {
    for (const auto& [suffix, table] :
         {std::pair<const char*, const std::vector<boot_config>*>{"/", &boot_configs},
          std::pair<const char*, const std::vector<boot_config>*>{"-GPU/", &boot_configs_gpu}}) {
        for (const auto& t : *table) {
            benchmark::RegisterBenchmark("CKKSBoot" + std::string(suffix) + RowName(t), CKKSBootstrap, t, false)
                    ->Unit(benchmark::kSecond)
                    ->Iterations(4);
            benchmark::RegisterBenchmark("CKKSBootStC" + std::string(suffix) + RowName(t), CKKSBootstrap, t, true)
                    ->Unit(benchmark::kSecond)
                    ->Iterations(4);
        }
    }

    benchmark::Initialize(&argc, argv);
    if (benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}
