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

#include "benchmark/benchmark.h"
#include "config_core.h"
#include "cryptocontext.h"
#include "gen-cryptocontext.h"
#include "gtest/gtest.h"
#include "scheme/ckksrns/ckksrns-fhe.h"
#include "scheme/ckksrns/ckksrns-utils.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"

#include <vector>

using namespace lbcrypto;

struct boot_config {
    uint32_t ringDim;
    uint32_t slots;
    uint32_t dcrtBits;
    uint32_t firstMod;
    uint32_t numDigits;
    uint32_t lvlsAfter;
    uint32_t iters;
    std::vector<uint32_t> lvlb;
    SecretKeyDist skdst;
    ScalingTechnique stech;
};

// clang-format off
[[maybe_unused]] std::vector<boot_config> boot_configs = {
    // ringDm,   slots, dcrtBits, firstMod, numDigits, lvlsAfter, iters,   lvlb,                skdst,                stech
    { 1 << 16, 1 << 15,       54,       60,        15,         9,     1, {3, 3},      UNIFORM_TERNARY,         FLEXIBLEAUTO},
    { 1 << 16, 1 << 15,       50,       57,        11,         9,     2, {3, 3},      UNIFORM_TERNARY,         FLEXIBLEAUTO},
    { 1 << 16, 1 << 15,       50,       57,        16,        10,     2, {3, 3},      UNIFORM_TERNARY,         FLEXIBLEAUTO},
    { 1 << 16, 1 << 15,       52,       57,        10,         8,     2, {3, 3},      UNIFORM_TERNARY,          FIXEDMANUAL},
    { 1 << 16, 1 << 15,       52,       57,        16,         9,     2, {3, 3},      UNIFORM_TERNARY,          FIXEDMANUAL},
    { 1 << 17, 1 << 16,       59,       60,         0,         5,     1, {4, 4},       SPARSE_TERNARY,         FLEXIBLEAUTO},
    { 1 << 17, 1 << 16,       59,       60,         0,         5,     1, {4, 4},  SPARSE_ENCAPSULATED,         FLEXIBLEAUTO},
    { 1 << 16,  1 << 5,       59,       60,         0,         5,     1, {1, 1},       SPARSE_TERNARY,         FLEXIBLEAUTO},
    { 1 << 16,  1 << 5,       59,       60,         0,         5,     1, {1, 1},  SPARSE_ENCAPSULATED,         FLEXIBLEAUTO},
    { 1 << 17,  1 << 5,       59,       60,         0,         5,     1, {1, 1},       SPARSE_TERNARY,         FLEXIBLEAUTO},
    { 1 << 17,  1 << 5,       59,       60,         0,         5,     1, {1, 1},  SPARSE_ENCAPSULATED,         FLEXIBLEAUTO},
    { 1 << 17, 1 << 16,       59,       60,         0,        10,     1, {4, 4},  SPARSE_ENCAPSULATED,         FLEXIBLEAUTO},
    { 1 << 17,  1 << 5,       59,       60,         0,        10,     1, {1, 1},  SPARSE_ENCAPSULATED,         FLEXIBLEAUTO},
    { 1 << 17, 1 << 16,       59,       60,         0,        10,     2, {4, 4},  SPARSE_ENCAPSULATED,         FLEXIBLEAUTO},
    { 1 << 17,  1 << 5,       59,       60,         0,        10,     2, {1, 1},  SPARSE_ENCAPSULATED,         FLEXIBLEAUTO},
    { 1 << 17, 1 << 16,       78,       96,         0,        10,     2, {4, 4},       SPARSE_TERNARY, COMPOSITESCALINGAUTO},
};
// clang-format on

[[maybe_unused]] static void BootConfigs(benchmark::internal::Benchmark* b) {
    for (uint32_t i = 0; i < boot_configs.size(); ++i)
        b->ArgName("Config")->Arg(i);
}

[[maybe_unused]] static void CKKSBoot(benchmark::State& state) {
    auto t = boot_configs[state.range(0)];

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetRingDim(t.ringDim);
    parameters.SetScalingModSize(t.dcrtBits);
    parameters.SetFirstModSize(t.firstMod);
    parameters.SetNumLargeDigits(t.numDigits);
    parameters.SetSecretKeyDist(t.skdst);
    parameters.SetScalingTechnique(t.stech);
    parameters.SetKeySwitchTechnique(HYBRID);
    uint32_t depth = t.lvlsAfter + FHECKKSRNS::GetBootstrapDepth(t.lvlb, t.skdst) + (t.iters - 1);
    parameters.SetMultiplicativeDepth(depth);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    cc->EvalBootstrapSetup(t.lvlb, {0, 0}, t.slots);

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    cc->EvalBootstrapKeyGen(keyPair.secretKey, t.slots);

    std::vector<double> x = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};

    auto ptxt = cc->MakeCKKSPackedPlaintext(x, 1, depth - 1, nullptr, t.slots);
    ptxt->SetLength(t.slots);

    auto ctxt = cc->Encrypt(keyPair.publicKey, ptxt);

    while (state.KeepRunning())
        auto ctxtAfter = cc->EvalBootstrap(ctxt, t.iters);

    cc->ClearStaticMapsAndVectors();
}

BENCHMARK(CKKSBoot)->Unit(benchmark::kSecond)->Iterations(4)->Apply(BootConfigs);

BENCHMARK_MAIN();
