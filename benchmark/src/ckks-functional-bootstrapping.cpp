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

#include <algorithm>
#include <complex>
#include <cstdint>
#include <exception>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "benchmark/benchmark.h"
#include "config_core.h"
#include "cryptocontext.h"
#include "gen-cryptocontext.h"
#include "gtest/gtest.h"
#include "math/hermite.h"
#include "scheme/ckksrns/ckksrns-fhe.h"
#include "scheme/ckksrns/ckksrns-utils.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"
#include "schemelet/rlwe-mp.h"

using namespace lbcrypto;

struct fbt_config {
    SecretKeyDist skd;
    ScalingTechnique scalTech;
    BigInteger QBFVInit;
    BigInteger PInput;
    BigInteger POutput;
    BigInteger Q;
    BigInteger Bigq;
    double scaleTHI;
    double scaleStepTHI;
    size_t order;
    uint32_t numSlots;
    uint32_t ringDim;
    uint32_t dnum;
    std::vector<uint32_t> lvlb;
};

using fbt_table = std::map<std::pair<uint32_t, ScalingTechnique>, fbt_config>;

[[maybe_unused]] const BigInteger Q1(BigInteger(1) << 1);
[[maybe_unused]] const BigInteger Q2(BigInteger(1) << 2);
[[maybe_unused]] const BigInteger Q4(BigInteger(1) << 4);
[[maybe_unused]] const BigInteger Q6(BigInteger(1) << 6);
[[maybe_unused]] const BigInteger Q8(BigInteger(1) << 8);
[[maybe_unused]] const BigInteger Q10(BigInteger(1) << 10);
[[maybe_unused]] const BigInteger Q12(BigInteger(1) << 12);
[[maybe_unused]] const BigInteger Q14(BigInteger(1) << 14);
[[maybe_unused]] const BigInteger Q16(BigInteger(1) << 16);
[[maybe_unused]] const BigInteger Q27(BigInteger(1) << 27);
[[maybe_unused]] const BigInteger Q31(BigInteger(1) << 31);
[[maybe_unused]] const BigInteger Q32(BigInteger(1) << 32);
[[maybe_unused]] const BigInteger Q33(BigInteger(1) << 33);
[[maybe_unused]] const BigInteger Q34(BigInteger(1) << 34);
[[maybe_unused]] const BigInteger Q35(BigInteger(1) << 35);
[[maybe_unused]] const BigInteger Q38(BigInteger(1) << 38);
[[maybe_unused]] const BigInteger Q39(BigInteger(1) << 39);
[[maybe_unused]] const BigInteger Q44(BigInteger(1) << 44);
[[maybe_unused]] const BigInteger Q46(BigInteger(1) << 46);
[[maybe_unused]] const BigInteger Q47(BigInteger(1) << 47);
[[maybe_unused]] const BigInteger Q48(BigInteger(1) << 48);
[[maybe_unused]] const BigInteger Q51(BigInteger(1) << 51);
[[maybe_unused]] const BigInteger Q52(BigInteger(1) << 52);
[[maybe_unused]] const BigInteger Q53(BigInteger(1) << 53);
[[maybe_unused]] const BigInteger Q56(BigInteger(1) << 56);
[[maybe_unused]] const BigInteger Q60(BigInteger(1) << 60);
[[maybe_unused]] const BigInteger Q71(BigInteger(1) << 71);
[[maybe_unused]] const BigInteger Q80(BigInteger(1) << 80);

// clang-format off
[[maybe_unused]] constexpr SecretKeyDist    HT = HYBRID_TERNARY;
[[maybe_unused]] constexpr SecretKeyDist    SE = SPARSE_ENCAPSULATED;
[[maybe_unused]] constexpr ScalingTechnique FM = FIXEDMANUAL;
[[maybe_unused]] constexpr ScalingTechnique FA = FLEXIBLEAUTO;

// the security table that matches the secret key distribution (see CKKS_BOOTSTRAPPING.md)
SecurityLevel SecurityLevelFor(SecretKeyDist skd) {
    return (skd == SPARSE_ENCAPSULATED || skd == SPARSE_TERNARY) ? HE_SPARSE_H192_128 : HEORG24_128;
}

// Keyed by (log p, scaling technique). All rows use HYBRID_TERNARY secrets under HEORG24_128 (the security table of
// the 2024 guidelines: 868 / 1747 / 3523 bits of log(Q'_L P') at N = 2^15 / 2^16 / 2^17; the library checks the
// bound at context generation and a non-compliant row is skipped). The order-1 rows (1 to 12 bits for both
// techniques, 14 and 16 bits for FLEXIBLEAUTO) use, among the level budgets and dnum values at the ring dimension,
// the configuration with the fastest FBT at 36 threads among those that keep the FBT output error below Q/(2p)
// with probability 2^-40 per ciphertext (measured over all N coefficients on inputs covering every residue of p),
// at the smallest scaling factor (Q) that passes there with at least half a bit of margin. Against the
// SPARSE_ENCAPSULATED rows this benchmark used before, the FLEXIBLEAUTO rows need 3 to 4 more bits of Q for the
// rescaling noise of the dense secret, while the FIXEDMANUAL rows pass at the same Q.
// The 14- and 16-bit rows rely on the degree-66 exp approximation that SPARSE_ENCAPSULATED and HYBRID_TERNARY use
// above 12 bits.
// No FIXEDMANUAL configuration meets the criterion at 14 or 16 bits within the 59-bit limit on scaling primes.
// UNIFORM_TERNARY rows are left out until subring secret encapsulation (eprint 2025/1594) is implemented.
[[maybe_unused]] const fbt_table arblut_configs = {
    // {log p, scalTech}, {skd, scalTech, QBFVInit, PInput, POutput, Q, Bigq, scaleTHI, scaleStepTHI, order,
    //                     numSlots, ringDim, dnum, lvlBudget}
    {{1, FM},  {HT, FM, Q60,  Q1,  Q1, Q34, Q34,    1.0,  1.0, 1, 1 << 15, 1 << 15, 4, {5, 3}}},
    {{1, FA},  {HT, FA, Q60,  Q1,  Q1, Q27, Q27,    1.0,  1.0, 1, 1 << 15, 1 << 15, 2, {4, 3}}},
    {{2, FM},  {HT, FM, Q60,  Q2,  Q2, Q33, Q33,   16.0,  1.0, 1, 1 << 15, 1 << 15, 3, {4, 3}}},
    {{2, FA},  {HT, FA, Q60,  Q2,  Q2, Q27, Q27,   16.0,  1.0, 1, 1 << 15, 1 << 15, 2, {4, 3}}},
    {{4, FM},  {HT, FM, Q60,  Q4,  Q4, Q38, Q38,   32.0,  1.0, 1, 1 << 16, 1 << 16, 2, {5, 3}}},
    {{4, FA},  {HT, FA, Q60,  Q4,  Q4, Q31, Q31,   32.0,  1.0, 1, 1 << 15, 1 << 15, 3, {3, 3}}},
    {{6, FM},  {HT, FM, Q60,  Q6,  Q6, Q44, Q44,   32.0,  1.0, 1, 1 << 16, 1 << 16, 2, {5, 3}}},
    {{6, FA},  {HT, FA, Q60,  Q6,  Q6, Q35, Q35,   32.0,  1.0, 1, 1 << 16, 1 << 16, 2, {5, 4}}},
    {{8, FM},  {HT, FM, Q60,  Q8,  Q8, Q46, Q46,   32.0,  1.0, 1, 1 << 16, 1 << 16, 4, {5, 3}}},
    {{8, FA},  {HT, FA, Q60,  Q8,  Q8, Q39, Q39,   32.0,  1.0, 1, 1 << 16, 1 << 16, 2, {4, 3}}},
    {{10, FM}, {HT, FM, Q60, Q10, Q10, Q52, Q52,  256.0,  1.0, 1, 1 << 17, 1 << 17, 3, {4, 3}}},
    {{10, FA}, {HT, FA, Q60, Q10, Q10, Q44, Q44,  256.0,  1.0, 1, 1 << 16, 1 << 16, 3, {5, 3}}},
    {{12, FM}, {HT, FM, Q80, Q12, Q12, Q56, Q56, 2000.0,  1.0, 1, 1 << 17, 1 << 17, 3, {4, 3}}},
    {{12, FA}, {HT, FA, Q60, Q12, Q12, Q48, Q48, 2000.0,  1.0, 1, 1 << 16, 1 << 16, 4, {3, 3}}},
    {{14, FA}, {HT, FA, Q60, Q14, Q14, Q53, Q53, 4096.0,  1.0, 1, 1 << 17, 1 << 17, 3, {5, 2}}},
    {{16, FA}, {HT, FA, Q80, Q16, Q16, Q56, Q56, 16384.0, 1.0, 1, 1 << 17, 1 << 17, 2, {5, 2}}},
    {{32, FM}, {HT, FM, Q80, Q32,  Q4, Q71, Q47,  256.0, 16.0, 1, 1 << 16, 1 << 16, 4, {3, 3}}}
};

// GPU-leaning rows, one per row above: the configuration with the fewest key-switching digits (fewer kernel launches
// per key switch and smaller keys on a GPU) among those within 25% of the row's time that meet the same criterion,
// or the row itself where there is none. Registered as FBTArbLUT-GPU/FM and FBTArbLUT-GPU/FA so that
// --benchmark_filter selects either table.
[[maybe_unused]] const fbt_table arblut_configs_gpu = {
    {{1, FM},  {HT, FM, Q60,  Q1,  Q1, Q34, Q34,    1.0,  1.0, 1, 1 << 15, 1 << 15, 2, {3, 3}}},
    {{1, FA},  {HT, FA, Q60,  Q1,  Q1, Q27, Q27,    1.0,  1.0, 1, 1 << 15, 1 << 15, 2, {4, 3}}},
    {{2, FM},  {HT, FM, Q60,  Q2,  Q2, Q33, Q33,   16.0,  1.0, 1, 1 << 15, 1 << 15, 3, {4, 3}}},
    {{2, FA},  {HT, FA, Q60,  Q2,  Q2, Q27, Q27,   16.0,  1.0, 1, 1 << 15, 1 << 15, 2, {4, 3}}},
    {{4, FM},  {HT, FM, Q60,  Q4,  Q4, Q38, Q38,   32.0,  1.0, 1, 1 << 16, 1 << 16, 2, {5, 3}}},
    {{4, FA},  {HT, FA, Q60,  Q4,  Q4, Q31, Q31,   32.0,  1.0, 1, 1 << 15, 1 << 15, 3, {3, 3}}},
    {{6, FM},  {HT, FM, Q60,  Q6,  Q6, Q44, Q44,   32.0,  1.0, 1, 1 << 16, 1 << 16, 2, {5, 3}}},
    {{6, FA},  {HT, FA, Q60,  Q6,  Q6, Q35, Q35,   32.0,  1.0, 1, 1 << 16, 1 << 16, 2, {5, 4}}},
    {{8, FM},  {HT, FM, Q60,  Q8,  Q8, Q46, Q46,   32.0,  1.0, 1, 1 << 16, 1 << 16, 2, {3, 3}}},
    {{8, FA},  {HT, FA, Q60,  Q8,  Q8, Q39, Q39,   32.0,  1.0, 1, 1 << 16, 1 << 16, 2, {4, 3}}},
    {{10, FM}, {HT, FM, Q60, Q10, Q10, Q52, Q52,  256.0,  1.0, 1, 1 << 17, 1 << 17, 2, {5, 3}}},
    {{10, FA}, {HT, FA, Q60, Q10, Q10, Q44, Q44,  256.0,  1.0, 1, 1 << 16, 1 << 16, 3, {5, 3}}},
    {{12, FM}, {HT, FM, Q80, Q12, Q12, Q56, Q56, 2000.0,  1.0, 1, 1 << 17, 1 << 17, 2, {5, 3}}},
    {{12, FA}, {HT, FA, Q60, Q12, Q12, Q48, Q48, 2000.0,  1.0, 1, 1 << 16, 1 << 16, 4, {3, 3}}},
    {{14, FA}, {HT, FA, Q60, Q14, Q14, Q53, Q53, 4096.0,  1.0, 1, 1 << 17, 1 << 17, 2, {5, 3}}},
    {{16, FA}, {HT, FA, Q80, Q16, Q16, Q56, Q56, 16384.0, 1.0, 1, 1 << 17, 1 << 17, 2, {5, 2}}},
    {{32, FM}, {HT, FM, Q80, Q32,  Q4, Q71, Q47,  256.0, 16.0, 1, 1 << 16, 1 << 16, 4, {3, 3}}}
};
// clang-format on

[[maybe_unused]] static void ArbLUTBitsFM(benchmark::internal::Benchmark* b) {
    for (uint32_t bits : {12, 10, 8, 6, 4, 2, 1})
        b->ArgName("bits")->Arg(bits);
}

[[maybe_unused]] static void ArbLUTBitsFA(benchmark::internal::Benchmark* b) {
    for (uint32_t bits : {16, 14, 12, 10, 8, 6, 4, 2, 1})
        b->ArgName("bits")->Arg(bits);
}

// throws when the row does not meet the security bound of its level
static CryptoContext<DCRTPoly> GenFBTContext(const fbt_config& t, uint32_t numSlotsCKKS, uint32_t depth) {
    uint32_t dcrtBits = t.Bigq.GetMSB() - 1;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecretKeyDist(t.skd);
    parameters.SetSecurityLevel(SecurityLevelFor(t.skd));
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(t.scalTech);
    parameters.SetFirstModSize(dcrtBits);
    parameters.SetNumLargeDigits(t.dnum);
    parameters.SetBatchSize(numSlotsCKKS);
    parameters.SetRingDim(t.ringDim);
    parameters.SetMultiplicativeDepth(depth);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);
    return cc;
}

[[maybe_unused]] static void FBTSetup(benchmark::State& state) {
    auto t = arblut_configs.at({12, FM});

    bool flagSP = (t.numSlots <= t.ringDim / 2);  // sparse packing

    auto numSlotsCKKS = flagSP ? t.numSlots : t.numSlots / 2;

    auto a = t.PInput.ConvertToInt<int64_t>();
    auto b = t.POutput.ConvertToInt<int64_t>();
    auto f = [a, b](int64_t x) -> int64_t {
        return (x % a - a / 2) % b;
    };

    std::vector<int64_t> x = {
            (t.PInput.ConvertToInt<int64_t>() / 2), (t.PInput.ConvertToInt<int64_t>() / 2) + 1, 0, 3, 16, 33, 64,
            (t.PInput.ConvertToInt<int64_t>() - 1)};
    if (x.size() < t.numSlots)
        x = Fill<int64_t>(x, t.numSlots);

    std::vector<int64_t> coeffint;
    std::vector<std::complex<double>> coeffcomp;
    bool binaryLUT = (t.PInput.ConvertToInt() == 2) && (t.order == 1);
    if (binaryLUT)  // coeffs for [1, cos^2(pi x)], not [1, cos(2pi x)]
        coeffint = {f(1), f(0) - f(1)};
    else  // divided by 2
        coeffcomp = GetHermiteTrigCoefficients(f, t.PInput.ConvertToInt(), t.order, t.scaleTHI);

    uint32_t depth = 0;
    if (binaryLUT)
        depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffint, t.PInput, t.order, t.skd);
    else
        depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffcomp, t.PInput, t.order, t.skd);

    CryptoContext<DCRTPoly> cc;
    try {
        cc = GenFBTContext(t, numSlotsCKKS, depth);
    } catch (const std::exception& e) {
        state.SkipWithError(e.what());
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
        return;
    }

    auto keyPair = cc->KeyGen();

    while (state.KeepRunning()) {
        if (binaryLUT)
            cc->EvalFBTSetup(coeffint, numSlotsCKKS, t.PInput, t.POutput, t.Bigq, keyPair.publicKey, {0, 0}, t.lvlb, 0,
                             0, t.order, t.numSlots);
        else
            cc->EvalFBTSetup(coeffcomp, numSlotsCKKS, t.PInput, t.POutput, t.Bigq, keyPair.publicKey, {0, 0}, t.lvlb, 0,
                             0, t.order, t.numSlots);
    }

    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
}

[[maybe_unused]] static void FBTKeyGen(benchmark::State& state) {
    auto t = arblut_configs.at({12, FM});

    bool flagSP = (t.numSlots <= t.ringDim / 2);  // sparse packing

    auto numSlotsCKKS = flagSP ? t.numSlots : t.numSlots / 2;

    auto a = t.PInput.ConvertToInt<int64_t>();
    auto b = t.POutput.ConvertToInt<int64_t>();
    auto f = [a, b](int64_t x) -> int64_t {
        return (x % a - a / 2) % b;
    };

    std::vector<int64_t> x = {
            (t.PInput.ConvertToInt<int64_t>() / 2), (t.PInput.ConvertToInt<int64_t>() / 2) + 1, 0, 3, 16, 33, 64,
            (t.PInput.ConvertToInt<int64_t>() - 1)};
    if (x.size() < t.numSlots)
        x = Fill<int64_t>(x, t.numSlots);

    std::vector<int64_t> coeffint;
    std::vector<std::complex<double>> coeffcomp;
    bool binaryLUT = (t.PInput.ConvertToInt() == 2) && (t.order == 1);
    if (binaryLUT)  // coeffs for [1, cos^2(pi x)], not [1, cos(2pi x)]
        coeffint = {f(1), f(0) - f(1)};
    else  // divided by 2
        coeffcomp = GetHermiteTrigCoefficients(f, t.PInput.ConvertToInt(), t.order, t.scaleTHI);

    uint32_t depth = 0;
    if (binaryLUT)
        depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffint, t.PInput, t.order, t.skd);
    else
        depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffcomp, t.PInput, t.order, t.skd);

    CryptoContext<DCRTPoly> cc;
    try {
        cc = GenFBTContext(t, numSlotsCKKS, depth);
    } catch (const std::exception& e) {
        state.SkipWithError(e.what());
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
        return;
    }

    auto keyPair = cc->KeyGen();

    if (binaryLUT)
        cc->EvalFBTSetup(coeffint, numSlotsCKKS, t.PInput, t.POutput, t.Bigq, keyPair.publicKey, {0, 0}, t.lvlb, 0, 0,
                         t.order, t.numSlots);
    else
        cc->EvalFBTSetup(coeffcomp, numSlotsCKKS, t.PInput, t.POutput, t.Bigq, keyPair.publicKey, {0, 0}, t.lvlb, 0, 0,
                         t.order, t.numSlots);

    for (auto _ : state) {
        state.PauseTiming();
        CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();
        CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
        state.ResumeTiming();
        cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlotsCKKS);
        cc->EvalMultKeyGen(keyPair.secretKey);
    }

    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
}

[[maybe_unused]] static void FBTArbLUT(benchmark::State& state, ScalingTechnique scalTech, const fbt_table* table) {
    auto t = table->at({static_cast<uint32_t>(state.range(0)), scalTech});

    bool flagSP = (t.numSlots <= t.ringDim / 2);  // sparse packing

    auto numSlotsCKKS = flagSP ? t.numSlots : t.numSlots / 2;

    auto a = t.PInput.ConvertToInt<int64_t>();
    auto b = t.POutput.ConvertToInt<int64_t>();
    auto f = [a, b](int64_t x) -> int64_t {
        return (x % a - a / 2) % b;
    };

    std::vector<int64_t> x = {
            (t.PInput.ConvertToInt<int64_t>() / 2), (t.PInput.ConvertToInt<int64_t>() / 2) + 1, 0, 3, 16, 33, 64,
            (t.PInput.ConvertToInt<int64_t>() - 1)};
    if (x.size() < t.numSlots)
        x = Fill<int64_t>(x, t.numSlots);

    std::vector<int64_t> coeffint;
    std::vector<std::complex<double>> coeffcomp;
    bool binaryLUT = (t.PInput.ConvertToInt() == 2) && (t.order == 1);
    if (binaryLUT)  // coeffs for [1, cos^2(pi x)], not [1, cos(2pi x)]
        coeffint = {f(1), f(0) - f(1)};
    else  // divided by 2
        coeffcomp = GetHermiteTrigCoefficients(f, t.PInput.ConvertToInt(), t.order, t.scaleTHI);

    uint32_t depth = 0;
    if (binaryLUT)
        depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffint, t.PInput, t.order, t.skd);
    else
        depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffcomp, t.PInput, t.order, t.skd);

    CryptoContext<DCRTPoly> cc;
    try {
        cc = GenFBTContext(t, numSlotsCKKS, depth);
    } catch (const std::exception& e) {
        state.SkipWithError(e.what());
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
        return;
    }

    auto keyPair = cc->KeyGen();

    if (binaryLUT)
        cc->EvalFBTSetup(coeffint, numSlotsCKKS, t.PInput, t.POutput, t.Bigq, keyPair.publicKey, {0, 0}, t.lvlb, 0, 0,
                         t.order, t.numSlots);
    else
        cc->EvalFBTSetup(coeffcomp, numSlotsCKKS, t.PInput, t.POutput, t.Bigq, keyPair.publicKey, {0, 0}, t.lvlb, 0, 0,
                         t.order, t.numSlots);

    cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlotsCKKS);
    cc->EvalMultKeyGen(keyPair.secretKey);

    auto ep = SchemeletRLWEMP::GetElementParams(keyPair.secretKey, depth);

    auto ctxtBFV = SchemeletRLWEMP::EncryptCoeff(x, t.QBFVInit, t.PInput, keyPair.secretKey, ep);

    SchemeletRLWEMP::ModSwitch(ctxtBFV, t.Q, t.QBFVInit);

    auto ctxt = SchemeletRLWEMP::ConvertRLWEToCKKS(*cc, ctxtBFV, keyPair.publicKey, t.Bigq, numSlotsCKKS, depth);

    while (state.KeepRunning()) {
        Ciphertext<DCRTPoly> ctxtAfterFBT;
        if (binaryLUT)
            ctxtAfterFBT = cc->EvalFBT(ctxt, coeffint, t.PInput.GetMSB() - 1, ep->GetModulus(), t.scaleTHI, 0, t.order);
        else
            ctxtAfterFBT =
                    cc->EvalFBT(ctxt, coeffcomp, t.PInput.GetMSB() - 1, ep->GetModulus(), t.scaleTHI, 0, t.order);
        ctxtAfterFBT.reset();
    }

    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
}

[[maybe_unused]] static void FBTSignDigit32(benchmark::State& state) {
    auto t = arblut_configs.at({32, FM});

    bool flagSP = (t.numSlots <= t.ringDim / 2);  // sparse packing

    auto numSlotsCKKS = flagSP ? t.numSlots : t.numSlots / 2;

    auto a = t.PInput.ConvertToInt<int64_t>();
    auto b = t.POutput.ConvertToInt<int64_t>();

    auto funcMod = [b](int64_t x) -> int64_t {
        return (x % b);
    };
    auto funcStep = [a, b](int64_t x) -> int64_t {
        return (x % a) >= (b / 2);
    };

    std::vector<int64_t> x = {
            t.PInput.ConvertToInt<int64_t>() / 2, t.PInput.ConvertToInt<int64_t>() / 2 + 1, 0, 3, 16, 33, 64,
            t.PInput.ConvertToInt<int64_t>() - 1};
    if (x.size() < t.numSlots)
        x = Fill<int64_t>(x, t.numSlots);

    auto exact(x);
    std::transform(x.begin(), x.end(), exact.begin(),
                   [&](int64_t elem) { return (elem >= t.PInput.ConvertToDouble() / 2.); });

    std::vector<int64_t> coeffintMod;
    std::vector<std::complex<double>> coeffcompMod;
    std::vector<std::complex<double>> coeffcompStep;
    bool binaryLUT = (t.POutput.ConvertToInt() == 2) && (t.order == 1);
    if (binaryLUT) {
        coeffintMod = {funcMod(1), funcMod(0) - funcMod(1)};  // coeffs for [1, cos^2(pi x)], not [1, cos(2pi x)]
    } else {
        coeffcompMod =
                GetHermiteTrigCoefficients(funcMod, t.POutput.ConvertToInt(), t.order, t.scaleTHI);  // divided by 2
        coeffcompStep = GetHermiteTrigCoefficients(funcStep, t.POutput.ConvertToInt(), t.order,
                                                   t.scaleStepTHI);  // divided by 2
    }

    uint32_t dcrtBits = t.Bigq.GetMSB() - 1;

    uint32_t depth = 0;
    if (binaryLUT)
        depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffintMod, t.PInput, t.order, t.skd);
    else
        depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffcompMod, t.PInput, t.order, t.skd);

    CryptoContext<DCRTPoly> cc;
    try {
        cc = GenFBTContext(t, numSlotsCKKS, depth);
    } catch (const std::exception& e) {
        state.SkipWithError(e.what());
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
        return;
    }

    auto keyPair = cc->KeyGen();

    if (binaryLUT)
        cc->EvalFBTSetup(coeffintMod, numSlotsCKKS, t.POutput, t.PInput, t.Bigq, keyPair.publicKey, {0, 0}, t.lvlb, 0,
                         0, t.order, t.numSlots);
    else
        cc->EvalFBTSetup(coeffcompMod, numSlotsCKKS, t.POutput, t.PInput, t.Bigq, keyPair.publicKey, {0, 0}, t.lvlb, 0,
                         0, t.order, t.numSlots);

    cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlotsCKKS);
    cc->EvalMultKeyGen(keyPair.secretKey);

    auto ep = SchemeletRLWEMP::GetElementParams(keyPair.secretKey, depth);

    std::vector<int64_t> coeffint;
    std::vector<std::complex<double>> coeffcomp;
    if (binaryLUT)
        coeffint = coeffintMod;
    else
        coeffcomp = coeffcompMod;

    while (state.KeepRunning()) {
        auto ctxtBFV = SchemeletRLWEMP::EncryptCoeff(x, t.QBFVInit, t.PInput, keyPair.secretKey, ep);

        SchemeletRLWEMP::ModSwitch(ctxtBFV, t.Q, t.QBFVInit);

        uint32_t QBFVBits = t.Q.GetMSB() - 1;

        auto Q = t.Q;
        auto PInput = t.PInput;

        BigInteger QNew;

        const bool checkgt2 = t.POutput.ConvertToInt() > 2;
        const uint32_t pDigitBits = t.POutput.GetMSB() - 1;

        uint64_t scaleTHI = t.scaleTHI;
        bool step = false;
        bool go = QBFVBits > dcrtBits;
        size_t levelsToDrop = 0;
        uint32_t postScalingBits = 0;

        // For arbitrary digit size, pNew > 2, the last iteration needs to evaluate step pNew not mod pNew.
        // Currently this only works when log(pNew) divides log(p).
        while (go) {
            auto encryptedDigit = ctxtBFV;

            // Apply mod q
            encryptedDigit[0].SwitchModulus(t.Bigq, 1, 0, 0);
            encryptedDigit[1].SwitchModulus(t.Bigq, 1, 0, 0);

            auto ctxt = SchemeletRLWEMP::ConvertRLWEToCKKS(*cc, encryptedDigit, keyPair.publicKey, t.Bigq, numSlotsCKKS,
                                                           depth);

            // Bootstrap the digit.
            Ciphertext<DCRTPoly> ctxtAfterFBT;
            if (binaryLUT)
                ctxtAfterFBT = cc->EvalFBT(ctxt, coeffint, pDigitBits, ep->GetModulus(),
                                           scaleTHI * (1 << postScalingBits), levelsToDrop, t.order);
            else
                ctxtAfterFBT = cc->EvalFBT(ctxt, coeffcomp, pDigitBits, ep->GetModulus(),
                                           scaleTHI * (1 << postScalingBits), levelsToDrop, t.order);

            auto polys = SchemeletRLWEMP::ConvertCKKSToRLWE(ctxtAfterFBT, Q);

            if (!step) {
                QNew = Q >> pDigitBits;

                // Subtract digit and switch mod from Q to QNew for BFV ciphertext
                ctxtBFV[0] = (ctxtBFV[0] - polys[0]).MultiplyAndRound(QNew, Q);
                ctxtBFV[0].SwitchModulus(QNew, 1, 0, 0);
                ctxtBFV[1] = (ctxtBFV[1] - polys[1]).MultiplyAndRound(QNew, Q);
                ctxtBFV[1].SwitchModulus(QNew, 1, 0, 0);
                Q >>= pDigitBits;
                PInput >>= pDigitBits;
                QBFVBits -= pDigitBits;
                postScalingBits += pDigitBits;
            } else {
                ctxtBFV[0] = std::move(polys[0]);
                ctxtBFV[1] = std::move(polys[1]);
            }

            go = QBFVBits > dcrtBits;

            if (checkgt2 && !go && !step) {
                if (!binaryLUT)
                    coeffcomp = coeffcompStep;
                scaleTHI = t.scaleStepTHI;
                step = true;
                go = true;
                int64_t lvlsToDrop = GetMultiplicativeDepthByCoeffVector(coeffcompMod, true) -
                                     GetMultiplicativeDepthByCoeffVector(coeffcompStep, true);
                if (coeffcompMod.size() > 4 && lvlsToDrop > 0)
                    levelsToDrop = lvlsToDrop;
            }
        }
    }

    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
}

int main(int argc, char** argv) {
    for (const auto& [prefix, table] :
         {std::pair<const char*, const fbt_table*>{"FBTArbLUT/", &arblut_configs},
          std::pair<const char*, const fbt_table*>{"FBTArbLUT-GPU/", &arblut_configs_gpu}}) {
        benchmark::RegisterBenchmark(std::string(prefix) + "FM", FBTArbLUT, FM, table)
                ->Unit(benchmark::kSecond)
                ->Iterations(4)
                ->Apply(ArbLUTBitsFM);
        benchmark::RegisterBenchmark(std::string(prefix) + "FA", FBTArbLUT, FA, table)
                ->Unit(benchmark::kSecond)
                ->Iterations(4)
                ->Apply(ArbLUTBitsFA);
    }
    benchmark::RegisterBenchmark("FBTSignDigit32", FBTSignDigit32)->Unit(benchmark::kSecond)->Iterations(4);
    benchmark::RegisterBenchmark("FBTSetup", FBTSetup)->Unit(benchmark::kSecond)->Iterations(10);
    benchmark::RegisterBenchmark("FBTKeyGen", FBTKeyGen)->Unit(benchmark::kSecond)->Iterations(4);

    benchmark::Initialize(&argc, argv);
    if (benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}
