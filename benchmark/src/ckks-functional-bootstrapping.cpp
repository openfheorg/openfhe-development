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
#include "math/hermite.h"
#include "scheme/ckksrns/ckksrns-fhe.h"
#include "scheme/ckksrns/ckksrns-utils.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"
#include "schemelet/rlwe-mp.h"

#include <complex>
#include <map>
#include <vector>

using namespace lbcrypto;

struct fbt_config {
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

[[maybe_unused]] const BigInteger Q1(BigInteger(1) << 1);
[[maybe_unused]] const BigInteger Q2(BigInteger(1) << 2);
[[maybe_unused]] const BigInteger Q4(BigInteger(1) << 4);
[[maybe_unused]] const BigInteger Q8(BigInteger(1) << 8);
[[maybe_unused]] const BigInteger Q12(BigInteger(1) << 12);
[[maybe_unused]] const BigInteger Q32(BigInteger(1) << 32);
[[maybe_unused]] const BigInteger Q33(BigInteger(1) << 33);
[[maybe_unused]] const BigInteger Q35(BigInteger(1) << 35);
[[maybe_unused]] const BigInteger Q38(BigInteger(1) << 38);
[[maybe_unused]] const BigInteger Q47(BigInteger(1) << 47);
[[maybe_unused]] const BigInteger Q55(BigInteger(1) << 55);
[[maybe_unused]] const BigInteger Q60(BigInteger(1) << 60);
[[maybe_unused]] const BigInteger Q71(BigInteger(1) << 71);
[[maybe_unused]] const BigInteger Q80(BigInteger(1) << 80);

// clang-format off
[[maybe_unused]] std::map<uint32_t, fbt_config> arblut_configs = {
    //      QBFVInit, PInput, POutput,   Q, Bigq, scaleTHI, scaleStepTHI, order, numSlots, ringDim, dnum, lvlBudget
    {1, {        Q60,     Q1,      Q1, Q33,  Q33,      1.0,          1.0,     1,  1 << 15, 1 << 15,    3, {3, 3}}},
    {2, {        Q60,     Q2,      Q2, Q35,  Q35,     16.0,          1.0,     1,  1 << 16, 1 << 16,    3, {4, 4}}},
    {4, {        Q60,     Q4,      Q4, Q38,  Q38,     32.0,          1.0,     1,  1 << 16, 1 << 16,    3, {4, 4}}},
    {8, {        Q60,     Q8,      Q8, Q47,  Q47,     32.0,          1.0,     1,  1 << 16, 1 << 16,    4, {3, 3}}},
    {12, {       Q80,    Q12,     Q12, Q55,  Q55,   2000.0,          1.0,     1,  1 << 17, 1 << 17,    3, {4, 4}}},
    {32, {       Q80,    Q32,      Q4, Q71,  Q47,    256.0,         16.0,     1,  1 << 16, 1 << 16,    4, {3, 3}}}
};
// clang-format on

[[maybe_unused]] static void ArbLUTBits(benchmark::internal::Benchmark* b) {
    for (uint32_t bits : {12, 8, 4, 2, 1})
        b->ArgName("bits")->Arg(bits);
}

[[maybe_unused]] static void FBTSetup(benchmark::State& state) {
    auto t = arblut_configs[12];

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

    uint32_t dcrtBits = t.Bigq.GetMSB() - 1;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecretKeyDist(SPARSE_ENCAPSULATED);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetFirstModSize(dcrtBits);
    parameters.SetNumLargeDigits(t.dnum);
    parameters.SetBatchSize(numSlotsCKKS);
    parameters.SetRingDim(t.ringDim);

    uint32_t depth = 0;
    if (binaryLUT)
        depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffint, t.PInput, t.order, SPARSE_ENCAPSULATED);
    else
        depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffcomp, t.PInput, t.order, SPARSE_ENCAPSULATED);
    parameters.SetMultiplicativeDepth(depth);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    auto keyPair = cc->KeyGen();

    while (state.KeepRunning()) {
        if (binaryLUT)
            cc->EvalFBTSetup(coeffint, numSlotsCKKS, t.PInput, t.POutput, t.Bigq, keyPair.publicKey, {0, 0}, t.lvlb, 0,
                             0, t.order);
        else
            cc->EvalFBTSetup(coeffcomp, numSlotsCKKS, t.PInput, t.POutput, t.Bigq, keyPair.publicKey, {0, 0}, t.lvlb, 0,
                             0, t.order);
    }

    cc->ClearStaticMapsAndVectors();
}

[[maybe_unused]] static void FBTKeyGen(benchmark::State& state) {
    auto t = arblut_configs[12];

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

    uint32_t dcrtBits = t.Bigq.GetMSB() - 1;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecretKeyDist(SPARSE_ENCAPSULATED);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetFirstModSize(dcrtBits);
    parameters.SetNumLargeDigits(t.dnum);
    parameters.SetBatchSize(numSlotsCKKS);
    parameters.SetRingDim(t.ringDim);

    uint32_t depth = 0;
    if (binaryLUT)
        depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffint, t.PInput, t.order, SPARSE_ENCAPSULATED);
    else
        depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffcomp, t.PInput, t.order, SPARSE_ENCAPSULATED);
    parameters.SetMultiplicativeDepth(depth);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    auto keyPair = cc->KeyGen();

    if (binaryLUT)
        cc->EvalFBTSetup(coeffint, numSlotsCKKS, t.PInput, t.POutput, t.Bigq, keyPair.publicKey, {0, 0}, t.lvlb, 0, 0,
                         t.order);
    else
        cc->EvalFBTSetup(coeffcomp, numSlotsCKKS, t.PInput, t.POutput, t.Bigq, keyPair.publicKey, {0, 0}, t.lvlb, 0, 0,
                         t.order);

    while (state.KeepRunning()) {
        cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlotsCKKS);
        cc->EvalMultKeyGen(keyPair.secretKey);
    }

    cc->ClearStaticMapsAndVectors();
}

[[maybe_unused]] static void FBTArbLUT(benchmark::State& state) {
    auto t = arblut_configs[state.range(0)];

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

    uint32_t dcrtBits = t.Bigq.GetMSB() - 1;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecretKeyDist(SPARSE_ENCAPSULATED);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetFirstModSize(dcrtBits);
    parameters.SetNumLargeDigits(t.dnum);
    parameters.SetBatchSize(numSlotsCKKS);
    parameters.SetRingDim(t.ringDim);

    uint32_t depth = 0;
    if (binaryLUT)
        depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffint, t.PInput, t.order, SPARSE_ENCAPSULATED);
    else
        depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffcomp, t.PInput, t.order, SPARSE_ENCAPSULATED);
    parameters.SetMultiplicativeDepth(depth);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    auto keyPair = cc->KeyGen();

    if (binaryLUT)
        cc->EvalFBTSetup(coeffint, numSlotsCKKS, t.PInput, t.POutput, t.Bigq, keyPair.publicKey, {0, 0}, t.lvlb, 0, 0,
                         t.order);
    else
        cc->EvalFBTSetup(coeffcomp, numSlotsCKKS, t.PInput, t.POutput, t.Bigq, keyPair.publicKey, {0, 0}, t.lvlb, 0, 0,
                         t.order);

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

    cc->ClearStaticMapsAndVectors();
}

[[maybe_unused]] static void FBTSignDigit32(benchmark::State& state) {
    auto t = arblut_configs[32];

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
                   [&](const int64_t& elem) { return (elem >= t.PInput.ConvertToDouble() / 2.); });

    std::vector<int64_t> coeffintMod;
    std::vector<std::complex<double>> coeffcompMod;
    std::vector<std::complex<double>> coeffcompStep;
    bool binaryLUT = (t.POutput.ConvertToInt() == 2) && (t.order == 1);
    if (binaryLUT) {
        coeffintMod = {funcMod(1), funcMod(0) - funcMod(1)};  // coeffs for [1, cos^2(pi x)], not [1, cos(2pi x)]
    }
    else {
        coeffcompMod =
            GetHermiteTrigCoefficients(funcMod, t.POutput.ConvertToInt(), t.order, t.scaleTHI);  // divided by 2
        coeffcompStep = GetHermiteTrigCoefficients(funcStep, t.POutput.ConvertToInt(), t.order,
                                                   t.scaleStepTHI);  // divided by 2
    }

    uint32_t dcrtBits = t.Bigq.GetMSB() - 1;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecretKeyDist(SPARSE_ENCAPSULATED);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetFirstModSize(dcrtBits);
    parameters.SetNumLargeDigits(t.dnum);
    parameters.SetBatchSize(numSlotsCKKS);
    parameters.SetRingDim(t.ringDim);

    uint32_t depth = 0;
    if (binaryLUT)
        depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffintMod, t.PInput, t.order, SPARSE_ENCAPSULATED);
    else
        depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffcompMod, t.PInput, t.order, SPARSE_ENCAPSULATED);
    parameters.SetMultiplicativeDepth(depth);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    auto keyPair = cc->KeyGen();

    if (binaryLUT)
        cc->EvalFBTSetup(coeffintMod, numSlotsCKKS, t.POutput, t.PInput, t.Bigq, keyPair.publicKey, {0, 0}, t.lvlb, 0,
                         0, t.order);
    else
        cc->EvalFBTSetup(coeffcompMod, numSlotsCKKS, t.POutput, t.PInput, t.Bigq, keyPair.publicKey, {0, 0}, t.lvlb, 0,
                         0, t.order);

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

        auto Q      = t.Q;
        auto PInput = t.PInput;

        BigInteger QNew;

        const bool checkgt2       = t.POutput.ConvertToInt() > 2;
        const uint32_t pDigitBits = t.POutput.GetMSB() - 1;

        uint64_t scaleTHI        = t.scaleTHI;
        bool step                = false;
        bool go                  = QBFVBits > dcrtBits;
        size_t levelsToDrop      = 0;
        uint32_t postScalingBits = 0;

        // For arbitrary digit size, pNew > 2, the last iteration needs to evaluate step pNew not mod pNew.
        // Currently this only works when log(pNew) divides log(p).
        while (go) {
            auto encryptedDigit = ctxtBFV;

            // Apply mod q
            encryptedDigit[0].SwitchModulus(t.Bigq, 1, 0, 0);
            encryptedDigit[1].SwitchModulus(t.Bigq, 1, 0, 0);

            auto ctxt =
                SchemeletRLWEMP::ConvertRLWEToCKKS(*cc, encryptedDigit, keyPair.publicKey, t.Bigq, numSlotsCKKS, depth);

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
            }
            else {
                ctxtBFV[0] = std::move(polys[0]);
                ctxtBFV[1] = std::move(polys[1]);
            }

            go = QBFVBits > dcrtBits;

            if (checkgt2 && !go && !step) {
                if (!binaryLUT)
                    coeffcomp = coeffcompStep;
                scaleTHI           = t.scaleStepTHI;
                step               = true;
                go                 = true;
                int64_t lvlsToDrop = GetMultiplicativeDepthByCoeffVector(coeffcompMod, true) -
                                     GetMultiplicativeDepthByCoeffVector(coeffcompStep, true);
                if (coeffcompMod.size() > 4 && lvlsToDrop > 0)
                    levelsToDrop = lvlsToDrop;
            }
        }
    }

    cc->ClearStaticMapsAndVectors();
}

BENCHMARK(FBTArbLUT)->Unit(benchmark::kSecond)->Iterations(4)->Apply(ArbLUTBits);
BENCHMARK(FBTSignDigit32)->Unit(benchmark::kSecond)->Iterations(4);
BENCHMARK(FBTSetup)->Unit(benchmark::kSecond)->Iterations(10);
BENCHMARK(FBTKeyGen)->Unit(benchmark::kSecond)->Iterations(4);

BENCHMARK_MAIN();
