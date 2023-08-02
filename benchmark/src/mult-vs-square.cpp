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
 * Compares the performance of Mult and Square for BGV, BFV and CKKS
 * using EvalMult and EvalSquare operations.
 */

#include "scheme/bfvrns/gen-cryptocontext-bfvrns.h"
#include "scheme/bgvrns/gen-cryptocontext-bgvrns.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"
#include "gen-cryptocontext.h"

#include "benchmark/benchmark.h"

#include <iostream>
#include <fstream>
#include <limits>
#include <iterator>
#include <random>

using namespace lbcrypto;

static std::vector<usint> depths({1, 2, 4, 8, 12});

/*
 * Context setup utility methods
 */
CryptoContext<DCRTPoly> GenerateBGVrnsContext(usint ptm, usint multDepth) {
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(ptm);
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetScalingTechnique(FIXEDAUTO);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    return cc;
}

CryptoContext<DCRTPoly> GenerateBFVrnsContext(usint ptm, usint multDepth) {
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(ptm);
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(60);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetMultiplicationTechnique(HPS);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    return cc;
}

CryptoContext<DCRTPoly> GenerateCKKSContext(usint multDepth) {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetScalingModSize(48);
    parameters.SetBatchSize(8);
    parameters.SetMultiplicativeDepth(multDepth);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    return cc;
}

static void DepthArguments(benchmark::internal::Benchmark* b) {
    for (usint t : depths) {
        b->ArgName("depths")->Arg(t);
    }
}

/*
 * EvalMult benchmarks for Power of 2
 */
void BGVrns_EvalPo2WithMult_P2(benchmark::State& state) {
    usint ptm                  = 2;
    usint depth                = state.range(0);
    CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext(ptm, depth);

    // KeyGen
    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<int64_t> vectorOfInts = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Plaintext plaintext               = cc->MakeCoefPackedPlaintext(vectorOfInts);
    Ciphertext<DCRTPoly> ciphertext   = cc->Encrypt(keyPair.publicKey, plaintext);

    Ciphertext<DCRTPoly> ciphertextPo2;

    while (state.KeepRunning()) {
        ciphertextPo2 = cc->EvalMult(ciphertext, ciphertext);
        for (usint i = 2; i < depth; ++i) {
            ciphertextPo2 = cc->EvalMult(ciphertextPo2, ciphertextPo2);
        }
    }

    Plaintext plaintextDec;
    cc->Decrypt(keyPair.secretKey, ciphertextPo2, &plaintextDec);
    plaintextDec->SetLength(plaintext->GetLength());

    if (plaintext != plaintextDec) {
        std::cout << "Error: Original plaintext should be equal to evaluated plaintext" << std::endl;
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintextDec << std::endl;
    }
}

BENCHMARK(BGVrns_EvalPo2WithMult_P2)->Unit(benchmark::kMicrosecond)->Apply(DepthArguments)->MinTime(10.0);

/*
 * EvalSquare benchmarks for Power of 2
 */
void BGVrns_EvalPo2WithSquare_P2(benchmark::State& state) {
    usint ptm                  = 2;
    usint depth                = state.range(0);
    CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext(ptm, depth);

    // KeyGen
    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<int64_t> vectorOfInts = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Plaintext plaintext               = cc->MakeCoefPackedPlaintext(vectorOfInts);
    Ciphertext<DCRTPoly> ciphertext   = cc->Encrypt(keyPair.publicKey, plaintext);

    Ciphertext<DCRTPoly> ciphertextPo2;

    while (state.KeepRunning()) {
        ciphertextPo2 = cc->EvalSquare(ciphertext);
        for (usint i = 2; i < depth; ++i) {
            ciphertextPo2 = cc->EvalSquare(ciphertextPo2);
        }
    }

    Plaintext plaintextDec;
    cc->Decrypt(keyPair.secretKey, ciphertextPo2, &plaintextDec);
    plaintextDec->SetLength(plaintext->GetLength());

    if (plaintext != plaintextDec) {
        std::cout << "Error: Original plaintext should be equal to evaluated plaintext" << std::endl;
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintextDec << std::endl;
    }
}

BENCHMARK(BGVrns_EvalPo2WithSquare_P2)->Unit(benchmark::kMicrosecond)->Apply(DepthArguments)->MinTime(10.0);

/*
 * EvalMult benchmarks for Power of 2
 */
void BFVrns_EvalPo2WithMult_P2(benchmark::State& state) {
    usint ptm                  = 2;
    usint depth                = state.range(0);
    CryptoContext<DCRTPoly> cc = GenerateBFVrnsContext(ptm, depth);

    // KeyGen
    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<int64_t> vectorOfInts = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Plaintext plaintext               = cc->MakeCoefPackedPlaintext(vectorOfInts);
    Ciphertext<DCRTPoly> ciphertext   = cc->Encrypt(keyPair.publicKey, plaintext);

    Ciphertext<DCRTPoly> ciphertextPo2;

    while (state.KeepRunning()) {
        ciphertextPo2 = cc->EvalMult(ciphertext, ciphertext);
        for (usint i = 2; i < depth; ++i) {
            ciphertextPo2 = cc->EvalMult(ciphertextPo2, ciphertextPo2);
        }
    }

    Plaintext plaintextDec;
    cc->Decrypt(keyPair.secretKey, ciphertextPo2, &plaintextDec);
    plaintextDec->SetLength(plaintext->GetLength());

    if (plaintext != plaintextDec) {
        std::cout << "Error: Original plaintext should be equal to evaluated plaintext" << std::endl;
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintextDec << std::endl;
    }
}

BENCHMARK(BFVrns_EvalPo2WithMult_P2)->Unit(benchmark::kMicrosecond)->Apply(DepthArguments)->MinTime(10.0);

/*
 * EvalSquare benchmarks for Power of 2
 */
void BFVrns_EvalPo2WithSquare_P2(benchmark::State& state) {
    usint ptm                  = 2;
    usint depth                = state.range(0);
    CryptoContext<DCRTPoly> cc = GenerateBFVrnsContext(ptm, depth);

    // KeyGen
    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<int64_t> vectorOfInts = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Plaintext plaintext               = cc->MakeCoefPackedPlaintext(vectorOfInts);
    Ciphertext<DCRTPoly> ciphertext   = cc->Encrypt(keyPair.publicKey, plaintext);

    Ciphertext<DCRTPoly> ciphertextPo2;

    while (state.KeepRunning()) {
        ciphertextPo2 = cc->EvalSquare(ciphertext);
        for (usint i = 2; i < depth; ++i) {
            ciphertextPo2 = cc->EvalSquare(ciphertextPo2);
        }
    }

    Plaintext plaintextDec;
    cc->Decrypt(keyPair.secretKey, ciphertextPo2, &plaintextDec);
    plaintextDec->SetLength(plaintext->GetLength());

    if (plaintext != plaintextDec) {
        std::cout << "Error: Original plaintext should be equal to evaluated plaintext" << std::endl;
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintextDec << std::endl;
    }
}

BENCHMARK(BFVrns_EvalPo2WithSquare_P2)->Unit(benchmark::kMicrosecond)->Apply(DepthArguments)->MinTime(10.0);

/*
 * EvalMult benchmarks for Power of 2
 */
void BGVrns_EvalPo2WithMult_P65537(benchmark::State& state) {
    usint ptm                  = 65537;
    usint depth                = state.range(0);
    CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext(ptm, depth);

    // KeyGen
    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<int64_t> vectorOfInts = {1, 0, 0, 1, 0, 0, 1, 1};
    Plaintext plaintext               = cc->MakePackedPlaintext(vectorOfInts);
    Ciphertext<DCRTPoly> ciphertext   = cc->Encrypt(keyPair.publicKey, plaintext);

    Ciphertext<DCRTPoly> ciphertextPo2;

    while (state.KeepRunning()) {
        ciphertextPo2 = cc->EvalMult(ciphertext, ciphertext);
        for (usint i = 2; i < depth; ++i) {
            ciphertextPo2 = cc->EvalMult(ciphertextPo2, ciphertextPo2);
        }
    }

    Plaintext plaintextDec;
    cc->Decrypt(keyPair.secretKey, ciphertextPo2, &plaintextDec);
    plaintextDec->SetLength(plaintext->GetLength());

    if (plaintext != plaintextDec) {
        std::cout << "Error: Original plaintext should be equal to evaluated plaintext" << std::endl;
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintextDec << std::endl;
    }
}

BENCHMARK(BGVrns_EvalPo2WithMult_P65537)->Unit(benchmark::kMicrosecond)->Apply(DepthArguments)->MinTime(10.0);

/*
 * EvalSquare benchmarks for Power of 2
 */
void BGVrns_EvalPo2WithSquare_P65537(benchmark::State& state) {
    usint ptm                  = 65537;
    usint depth                = state.range(0);
    CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext(ptm, depth);

    // KeyGen
    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<int64_t> vectorOfInts = {1, 0, 0, 1, 0, 0, 1, 1};
    Plaintext plaintext               = cc->MakePackedPlaintext(vectorOfInts);
    Ciphertext<DCRTPoly> ciphertext   = cc->Encrypt(keyPair.publicKey, plaintext);

    Ciphertext<DCRTPoly> ciphertextPo2;

    while (state.KeepRunning()) {
        ciphertextPo2 = cc->EvalSquare(ciphertext);
        for (usint i = 2; i < depth; ++i) {
            cc->EvalSquareInPlace(ciphertextPo2);
        }
    }

    Plaintext plaintextDec;
    cc->Decrypt(keyPair.secretKey, ciphertextPo2, &plaintextDec);
    plaintextDec->SetLength(plaintext->GetLength());

    if (plaintext != plaintextDec) {
        std::cout << "Error: Original plaintext should be equal to evaluated plaintext" << std::endl;
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintextDec << std::endl;
    }
}

BENCHMARK(BGVrns_EvalPo2WithSquare_P65537)->Unit(benchmark::kMicrosecond)->Apply(DepthArguments)->MinTime(10.0);

/*
 * EvalMult benchmarks for Power of 2
 */
void BFVrns_EvalPo2WithMult_P65537(benchmark::State& state) {
    usint ptm                  = 65537;
    usint depth                = state.range(0);
    CryptoContext<DCRTPoly> cc = GenerateBFVrnsContext(ptm, depth);

    // KeyGen
    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<int64_t> vectorOfInts = {1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0};
    Plaintext plaintext               = cc->MakePackedPlaintext(vectorOfInts);
    Ciphertext<DCRTPoly> ciphertext   = cc->Encrypt(keyPair.publicKey, plaintext);

    Ciphertext<DCRTPoly> ciphertextPo2;

    while (state.KeepRunning()) {
        ciphertextPo2 = cc->EvalMult(ciphertext, ciphertext);
        for (usint i = 2; i < depth; ++i) {
            ciphertextPo2 = cc->EvalMult(ciphertextPo2, ciphertextPo2);
        }
    }

    Plaintext plaintextDec;
    cc->Decrypt(keyPair.secretKey, ciphertextPo2, &plaintextDec);
    plaintextDec->SetLength(plaintext->GetLength());

    if (plaintext != plaintextDec) {
        std::cout << "Error: Original plaintext should be equal to evaluated plaintext" << std::endl;
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintextDec << std::endl;
    }
}

BENCHMARK(BFVrns_EvalPo2WithMult_P65537)->Unit(benchmark::kMicrosecond)->Apply(DepthArguments)->MinTime(10.0);

/*
 * EvalSquare benchmarks for Power of 2
 */
void BFVrns_EvalPo2WithSquare_P65537(benchmark::State& state) {
    usint ptm                  = 65537;
    usint depth                = state.range(0);
    CryptoContext<DCRTPoly> cc = GenerateBFVrnsContext(ptm, depth);

    // KeyGen
    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<int64_t> vectorOfInts = {1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0};
    Plaintext plaintext               = cc->MakePackedPlaintext(vectorOfInts);
    Ciphertext<DCRTPoly> ciphertext   = cc->Encrypt(keyPair.publicKey, plaintext);

    Ciphertext<DCRTPoly> ciphertextPo2;

    while (state.KeepRunning()) {
        ciphertextPo2 = cc->EvalSquare(ciphertext);
        for (usint i = 2; i < depth; ++i) {
            ciphertextPo2 = cc->EvalSquare(ciphertextPo2);
        }
    }

    Plaintext plaintextDec;
    cc->Decrypt(keyPair.secretKey, ciphertextPo2, &plaintextDec);
    plaintextDec->SetLength(plaintext->GetLength());

    if (plaintext != plaintextDec) {
        std::cout << "Error: Original plaintext should be equal to evaluated plaintext" << std::endl;
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintextDec << std::endl;
    }
}

BENCHMARK(BFVrns_EvalPo2WithSquare_P65537)->Unit(benchmark::kMicrosecond)->Apply(DepthArguments)->MinTime(10.0);

/*
 * EvalMult benchmarks for Power of 2
 */
void CKKSrns_EvalPo2WithMult(benchmark::State& state) {
    usint depth                = state.range(0);
    CryptoContext<DCRTPoly> cc = GenerateCKKSContext(depth);

    // KeyGen
    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<double> vectorOfDoubles = {1., 0., 0., 1., 0., 0., 1., 1.};
    Plaintext plaintext                 = cc->MakeCKKSPackedPlaintext(vectorOfDoubles);
    Ciphertext<DCRTPoly> ciphertext     = cc->Encrypt(keyPair.publicKey, plaintext);

    Ciphertext<DCRTPoly> ciphertextPo2;

    while (state.KeepRunning()) {
        ciphertextPo2 = cc->EvalMult(ciphertext, ciphertext);
        for (usint i = 2; i < depth; ++i) {
            ciphertextPo2 = cc->EvalMult(ciphertextPo2, ciphertextPo2);
        }
    }

    Plaintext plaintextDec;
    cc->Decrypt(keyPair.secretKey, ciphertextPo2, &plaintextDec);
    plaintextDec->SetLength(plaintext->GetLength());
    bool equal = std::equal(plaintext->GetCKKSPackedValue().begin(), plaintext->GetCKKSPackedValue().end(),
                            plaintextDec->GetCKKSPackedValue().begin(),
                            [](std::complex<double> value1, std::complex<double> value2) {
                                constexpr double epsilon = 0.0001;
                                return std::fabs(value1.real() - value2.real()) < epsilon;
                            });
    if (!equal) {
        std::cout << "Error: Original plaintext should be equal to evaluated plaintext" << std::endl;
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintextDec << std::endl;
    }
}

BENCHMARK(CKKSrns_EvalPo2WithMult)->Unit(benchmark::kMicrosecond)->Apply(DepthArguments)->MinTime(10.0);

/*
 * EvalSquare benchmarks for Power of 2
 */
void CKKSrns_EvalPo2WithSquare(benchmark::State& state) {
    usint depth                = state.range(0);
    CryptoContext<DCRTPoly> cc = GenerateCKKSContext(depth);

    // KeyGen
    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<double> vectorOfDoubles = {1., 0., 0., 1., 0., 0., 1., 1.};
    Plaintext plaintext                 = cc->MakeCKKSPackedPlaintext(vectorOfDoubles);
    Ciphertext<DCRTPoly> ciphertext     = cc->Encrypt(keyPair.publicKey, plaintext);

    Ciphertext<DCRTPoly> ciphertextPo2;

    while (state.KeepRunning()) {
        ciphertextPo2 = cc->EvalSquare(ciphertext);
        for (usint i = 2; i < depth; ++i) {
            ciphertextPo2 = cc->EvalSquare(ciphertextPo2);
        }
    }

    Plaintext plaintextDec;
    cc->Decrypt(keyPair.secretKey, ciphertextPo2, &plaintextDec);
    plaintextDec->SetLength(plaintext->GetLength());
    bool equal = std::equal(plaintext->GetCKKSPackedValue().begin(), plaintext->GetCKKSPackedValue().end(),
                            plaintextDec->GetCKKSPackedValue().begin(),
                            [](std::complex<double> value1, std::complex<double> value2) {
                                constexpr double epsilon = 0.0001;
                                return std::fabs(value1.real() - value2.real()) < epsilon;
                            });
    if (!equal) {
        std::cout << "Error: Original plaintext should be equal to evaluated plaintext" << std::endl;
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintextDec << std::endl;
    }
}

BENCHMARK(CKKSrns_EvalPo2WithSquare)->Unit(benchmark::kMicrosecond)->Apply(DepthArguments)->MinTime(10.0);

BENCHMARK_MAIN();
