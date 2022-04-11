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

#define _USE_MATH_DEFINES
#include "benchmark/benchmark.h"

bool runOnlyOnce = true;  // TODO (dsuponit): do we need runOnlyOnce???

#include "palisade.h"
#include "encoding/encodings.h"
#include "lattice/elemparamfactory.h"
#include "scheme/ckksrns/cryptocontext-ckksrns.h"
#include "gen-cryptocontext.h"

#include <iostream>
#include <random>

using namespace lbcrypto;

void BM_encoding_CoefPacked(benchmark::State& state) {
    Plaintext plaintext;
    usint m              = 1024;
    PlaintextModulus ptm = 128;

    std::shared_ptr<ILParams> lp = ElemParamFactory::GenElemParams<ILParams>(m);
    EncodingParams ep(new EncodingParamsImpl(ptm));

    std::vector<int64_t> intvec;
    PlaintextModulus half = ptm / 2;
    // for (usint ii = 0; ii < m / 2; ii++)
    //    intvec.push_back(rand() % half);

    std::random_device rd;
    std::mt19937_64 gen(rd());
    // We must use "unsigned long long" instead of uint64_t as the template argument to define the number generator.
    // Otherwise, the result may be undefined as per https://en.cppreference.com/w/cpp/numeric/random/uniform_int_distribution
    std::uniform_int_distribution<unsigned long long> dis(0, half - 1);  // NOLINT
    for (usint ii = 0; ii < m / 2; ii++)
        intvec.push_back(dis(gen));

    while (state.KeepRunning()) {
        plaintext.reset(new CoefPackedEncoding(lp, ep, intvec));
        plaintext->Encode();
    }
}

BENCHMARK(BM_encoding_CoefPacked);

void BM_encoding_PackedIntPlaintext(benchmark::State& state) {
    Plaintext plaintext;
    std::shared_ptr<ILParams> lp;
    EncodingParams ep;

    std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8, 0, 0};

    usint m            = 22;
    PlaintextModulus p = 89;
    BigInteger modulusP(p);
    BigInteger modulusQ("955263939794561");
    BigInteger squareRootOfRoot("941018665059848");
    BigInteger bigmodulus("80899135611688102162227204937217");
    BigInteger bigroot("77936753846653065954043047918387");

    auto cycloPoly = GetCyclotomicPolynomial<BigVector>(m, modulusQ);
    ChineseRemainderTransformArb<BigVector>().SetCylotomicPolynomial(cycloPoly, modulusQ);

    lp.reset(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));
    ep.reset(new EncodingParamsImpl(p, 8));

    while (state.KeepRunning()) {
        plaintext.reset(new PackedEncoding(lp, ep, vectorOfInts1));

        plaintext->Encode();
    }
}

BENCHMARK(BM_encoding_PackedIntPlaintext);

void BM_encoding_PackedIntPlaintext_SetParams(benchmark::State& state) {
    Plaintext plaintext;
    std::shared_ptr<ILParams> lp;
    EncodingParams ep;

    usint m            = 22;
    PlaintextModulus p = 89;
    BigInteger modulusP(p);

    std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8, 0, 0};

    if (state.thread_index == 0) {
        BigInteger modulusQ("955263939794561");
        BigInteger squareRootOfRoot("941018665059848");
        BigInteger bigmodulus("80899135611688102162227204937217");
        BigInteger bigroot("77936753846653065954043047918387");

        auto cycloPoly = GetCyclotomicPolynomial<BigVector>(m, modulusQ);
        ChineseRemainderTransformArb<BigVector>().SetCylotomicPolynomial(cycloPoly, modulusQ);

        lp.reset(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));
        ep.reset(new EncodingParamsImpl(p, 8));
    }

    while (state.KeepRunning()) {
        PackedEncoding::SetParams(m, ep);
        state.PauseTiming();
        PackedEncoding::Destroy();
        state.ResumeTiming();
    }
}

BENCHMARK(BM_encoding_PackedIntPlaintext_SetParams);

void BM_Encoding_String(benchmark::State& state) {  // benchmark
    Plaintext plaintext;

    usint m              = 1024;
    PlaintextModulus ptm = 256;

    std::shared_ptr<ILParams> lp = ElemParamFactory::GenElemParams<ILParams>(m);
    EncodingParams ep(new EncodingParamsImpl(ptm));

    auto randchar = []() -> char {
        const char charset[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";
        const size_t max_index = (sizeof(charset) - 1);
        return charset[rand() % max_index];
    };

    std::string fullStr(m / 2, 0);
    std::generate_n(fullStr.begin(), m / 2, randchar);

    while (state.KeepRunning()) {
        plaintext.reset(new StringEncoding(lp, ep, fullStr));
        plaintext->Encode();
    }
}

BENCHMARK(BM_Encoding_String);

void BM_encoding_PackedCKKSPlaintext(benchmark::State& state) {
    Plaintext plaintext;
    std::shared_ptr<ILDCRTParams<BigInteger>> lp;
    EncodingParams ep;

    std::vector<std::complex<double>> vectorOfComplex = {{1, 0}, {2, 0}, {3, 0}, {4, 0}, {5, 0},
                                                         {6, 0}, {7, 0}, {8, 0}, {0, 0}, {0, 0}};

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetRingDim(4096);
    parameters.SetScalingFactorBits(50);
    parameters.SetBatchSize(8);
    parameters.SetKeySwitchTechnique(BV);
    parameters.SetRescalingTechnique(FIXEDMANUAL);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(MULTIPARTY);

    lp                 = cc->GetElementParams();
    ep                 = cc->GetEncodingParams();
    auto scalingFactor = cc->GetEncodingParams()->GetPlaintextModulus();

    while (state.KeepRunning()) {
        plaintext.reset(new CKKSPackedEncoding(lp, ep, vectorOfComplex, 1, 0, scalingFactor));
        plaintext->Encode();
    }
}

BENCHMARK(BM_encoding_PackedCKKSPlaintext);

// execute the benchmarks
BENCHMARK_MAIN();
