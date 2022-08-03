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

#include "benchmark/benchmark.h"

#include "openfhe.h"

#include "scheme/bgvrns/cryptocontext-bgvrns.h"
#include "gen-cryptocontext.h"

#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>
#include <getopt.h>

using namespace std;
using namespace lbcrypto;

// 0 - CPA secure PRE, 1 - fixed 20 bits noise, 2 - provable secure HRA noise flooding with BV key switching,
// 3 - provable secure HRA noise flooding with Hybrid key switching, 4 - provably secure HRA without noise flooding
usint SECURITY_MODEL = 0;

lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cryptoContext;

lbcrypto::EvalKey<DCRTPoly> reencryptionKey;
lbcrypto::KeyPair<lbcrypto::DCRTPoly> keyPairproducer, keyPairconsumer;
lbcrypto::Ciphertext<DCRTPoly> ciphertext, reEncryptedCT;
Plaintext plaintextDecproducer, plaintextDecconsumer;

void usage() {
    std::cout
        << "-m security model (0 CPA secure PRE, 1 Fixed 20 bits noise, 2 Provable secure HRA with BV, 3 Provable secure HRA with Hybrid)"
        << std::endl;
}

void PRE_keygen(benchmark::State& state) {
    for (auto _ : state) {
        keyPairproducer = cryptoContext->KeyGen();
    }

    if (!keyPairproducer.good()) {
        OPENFHE_THROW(math_error, "Key generation failed!");
    }
}

void PRE_Encrypt(benchmark::State& state) {
    auto ringsize         = cryptoContext->GetRingDimension();
    auto plaintextModulus = cryptoContext->GetCryptoParameters()->GetPlaintextModulus();

    vector<int64_t> vectorOfInts;
    for (size_t i = 0; i < ringsize; i++) {  // generate a random array of ringsize
        if (plaintextModulus == 2) {
            vectorOfInts.push_back(std::rand() % plaintextModulus);
        }
        else {
            vectorOfInts.push_back((std::rand() % plaintextModulus) - ((plaintextModulus / 2) - 1));
        }
    }

    auto plaintext = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts);
    ////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////
    for (auto _ : state) {
        ciphertext = cryptoContext->Encrypt(keyPairproducer.publicKey, plaintext);
    }
}

void PRE_DecryptBeforeReEncrypt(benchmark::State& state) {
    for (auto _ : state) {
        cryptoContext->Decrypt(keyPairproducer.secretKey, ciphertext, &plaintextDecproducer);
    }
}

void PRE_Rekeygen(benchmark::State& state) {
    keyPairconsumer = cryptoContext->KeyGen();

    for (auto _ : state) {
        benchmark::DoNotOptimize(reencryptionKey =
                                     cryptoContext->ReKeyGen(keyPairproducer.secretKey, keyPairconsumer.publicKey));
    }
}

void PRE_ReEncrypt(benchmark::State& state) {
    lbcrypto::Ciphertext<DCRTPoly> reEncryptedCT1;
    for (auto _ : state) {
        switch (SECURITY_MODEL) {
            case 0:
                // CPA secure PRE
                benchmark::DoNotOptimize(reEncryptedCT = cryptoContext->ReEncrypt(ciphertext, reencryptionKey));
            case 1:
                // Fixed noise (20 bits) practically secure PRE
                benchmark::DoNotOptimize(
                    reEncryptedCT = cryptoContext->ReEncrypt(ciphertext, reencryptionKey, keyPairproducer.publicKey));
            case 2:
                // Provable HRA secure PRE with noise flooding with BV switching
                benchmark::DoNotOptimize(
                    reEncryptedCT1 = cryptoContext->ReEncrypt(ciphertext, reencryptionKey, keyPairproducer.publicKey));
                benchmark::DoNotOptimize(
                    reEncryptedCT = cryptoContext->ModReduce(reEncryptedCT1));  // mod reduction for noise flooding
            case 3:
                // Provable HRA secure PRE with noise flooding with Hybrid switching
                benchmark::DoNotOptimize(
                    reEncryptedCT1 = cryptoContext->ReEncrypt(ciphertext, reencryptionKey, keyPairproducer.publicKey));
                benchmark::DoNotOptimize(
                    reEncryptedCT = cryptoContext->ModReduce(reEncryptedCT1));  // mod reduction for noise flooding
            default:
                OPENFHE_THROW(config_error, "Not a valid security mode");
        }
    }
}

void PRE_DecryptAfterReEncrypt(benchmark::State& state) {
    for (auto _ : state) {
        cryptoContext->Decrypt(keyPairconsumer.secretKey, reEncryptedCT, &plaintextDecconsumer);
    }
}

int main(int argc, char** argv) {
    char opt(0);
    static struct option long_options[] = {
        {"Security model", required_argument, NULL, 'm'}, {"help", no_argument, NULL, 'h'}, {NULL, 0, NULL, 0}};

    const char* optstring = "m:h";
    while ((opt = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
        std::cerr << "opt1: " << opt << "; optarg: " << optarg << std::endl;
        switch (opt) {
            case 'm':
                SECURITY_MODEL = atoi(optarg);
                break;
            case 'h':
                usage();
            default:
                SECURITY_MODEL = 0;
        }
    }

    // Default set to IND-CPA parameters
    // The parameters ring_dimension, digitsize, qmodulus are chosen for a plaintext modulus of 2 to allow upto 10 hops
    // without breaking decryption. Changing the plaintext modulus would require updating these other parameters for correctness.
    lbcrypto::CCParams<lbcrypto::CryptoContextBGVRNS> parameters;

    int plaintextModulus        = 2;
    uint32_t multDepth          = 0;
    double sigma                = 3.2;
    SecurityLevel securityLevel = HEStd_128_classic;
    usint ringDimension         = 1024;
    usint digitSize             = 9;
    usint dcrtbits              = 0;

    usint qmodulus  = 27;
    usint firstqmod = 27;

    // 0 - CPA secure PRE, 1 - fixed 20 bits noise, 2 - provable secure HRA noise flooding with BV switching,
    // 3 - provable secure HRA noise flooding with Hybrid switching
    if (SECURITY_MODEL == 0) {
        plaintextModulus = 2;
        multDepth        = 0;
        sigma            = 3.2;
        securityLevel    = HEStd_128_classic;
        ringDimension    = 1024;
        digitSize        = 9;
        dcrtbits         = 0;

        qmodulus  = 27;
        firstqmod = 27;
        parameters.SetPREMode(INDCPA);
        parameters.SetKeySwitchTechnique(BV);
    }
    else if (SECURITY_MODEL == 1) {
        plaintextModulus = 2;
        multDepth        = 0;
        sigma            = 3.2;
        securityLevel    = HEStd_128_classic;
        ringDimension    = 2048;
        digitSize        = 18;
        dcrtbits         = 0;

        qmodulus  = 54;
        firstqmod = 54;
        parameters.SetPREMode(FIXED_NOISE_HRA);
        parameters.SetKeySwitchTechnique(BV);
    }
    else if (SECURITY_MODEL == 2) {
        plaintextModulus = 2;
        multDepth        = 0;
        sigma            = 3.2;
        securityLevel    = HEStd_128_classic;
        ringDimension    = 16384;
        digitSize        = 1;
        dcrtbits         = 30;

        qmodulus  = 438;
        firstqmod = 60;
        parameters.SetPREMode(NOISE_FLOODING_HRA);
        parameters.SetKeySwitchTechnique(BV);
    }
    else if (SECURITY_MODEL == 3) {
        ringDimension = 16384;
        digitSize     = 0;
        dcrtbits      = 30;

        qmodulus      = 438;
        firstqmod     = 60;
        uint32_t dnum = 3;
        parameters.SetPREMode(NOISE_FLOODING_HRA);
        parameters.SetKeySwitchTechnique(HYBRID);
        parameters.SetNumLargeDigits(dnum);
    }

    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetPlaintextModulus(plaintextModulus);
    parameters.SetSecurityLevel(securityLevel);
    parameters.SetStandardDeviation(sigma);
    parameters.SetSecretKeyDist(UNIFORM_TERNARY);
    parameters.SetRingDim(ringDimension);
    parameters.SetFirstModSize(firstqmod);
    parameters.SetScalingModSize(dcrtbits);
    parameters.SetDigitSize(digitSize);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetMultiHopModSize(qmodulus);

    cryptoContext = GenCryptoContext(parameters);

    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(PRE);

    std::cerr << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cerr << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2
              << std::endl;
    std::cerr << "log2 q = "
              << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;
    std::cerr << "r = " << cryptoContext->GetCryptoParameters()->GetDigitSize() << std::endl;

    std::cerr << "security model = " << SECURITY_MODEL << std::endl;

    int num_of_repetitions = 100;

    ::benchmark::Initialize(&argc, argv);
    ::benchmark::RegisterBenchmark("Keygen", &PRE_keygen)
        ->ReportAggregatesOnly(true)
        ->Repetitions(num_of_repetitions)
        ->Unit(benchmark::kMillisecond);
    ::benchmark::RegisterBenchmark("Encrypt", &PRE_Encrypt)
        ->ReportAggregatesOnly(true)
        ->Repetitions(num_of_repetitions)
        ->Unit(benchmark::kMillisecond);
    ::benchmark::RegisterBenchmark("DecryptBefore", &PRE_DecryptBeforeReEncrypt)
        ->ReportAggregatesOnly(true)
        ->Repetitions(num_of_repetitions)
        ->Unit(benchmark::kMillisecond);
    ::benchmark::RegisterBenchmark("ReKeygen", &PRE_Rekeygen)
        ->ReportAggregatesOnly(true)
        ->Repetitions(num_of_repetitions)
        ->Unit(benchmark::kMillisecond);
    ::benchmark::RegisterBenchmark("ReEncrypt", &PRE_ReEncrypt)
        ->ReportAggregatesOnly(true)
        ->Repetitions(num_of_repetitions)
        ->Unit(benchmark::kMillisecond);
    ::benchmark::RegisterBenchmark("DecryptAfter", &PRE_DecryptAfterReEncrypt)
        ->ReportAggregatesOnly(true)
        ->Repetitions(num_of_repetitions)
        ->Unit(benchmark::kMillisecond);

    ::benchmark::RunSpecifiedBenchmarks();

    std::vector<int64_t> unpackedPT    = plaintextDecproducer->GetCoefPackedValue();
    std::vector<int64_t> unpackedDecPT = plaintextDecconsumer->GetCoefPackedValue();
    for (unsigned int j = 0; j < unpackedPT.size(); j++) {
        if (unpackedPT[j] != unpackedDecPT[j]) {
            OPENFHE_THROW(math_error, "Decryption failure");
        }
    }

    ::benchmark::Shutdown();
    return 0;
}
