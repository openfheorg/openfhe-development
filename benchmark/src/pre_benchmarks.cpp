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

int num_of_hops=1; //number of hops
usint security_model = 0; //0 - CPA secure PRE, 1 - fixed 20 bits noise, 2 - provable secure HRA noise flooding with BV key switching,
                          // 3 - provable secure HRA noise flooding with Hybrid key switching, 4 - provably secure HRA without noise flooding

void usage() {
  std::cout << "-m security model (0 CPA secure PRE, 1 Fixed 20 bits noise, 2 Provable secure HRA)"
            << "-d number of hops"
            << std::endl;
}


//Default set to IND-CPA parameters
//The parameters ring_dimension, relinWindow, qmodulus are chosen for a plaintext modulus of 2 to allow upto 10 hops 
//without breaking decryption. Changing the plaintext modulus would require updating these other parameters for correctness.
lbcrypto::CCParams<lbcrypto::CryptoContextBGVRNS> parameters;

int plaintextModulus = 2;
uint32_t multDepth = 0;
double sigma = 3.2;		
SecurityLevel securityLevel = HEStd_128_classic;
usint ringDimension = 1024;
usint relinWindow = 3;
usint dcrtbits = 0;

usint qmodulus = 27;
usint firstqmod = 27;
  
lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cryptoContext;
// Initialize Key Pair Containers
lbcrypto::KeyPair<lbcrypto::DCRTPoly> keyPairproducer, keyPairconsumer;

vector<int64_t> vectorOfInts;
unsigned int nShort=0;
int ringsize=0;

Plaintext plaintext, plaintextDecproducer, plaintextDecconsumer;
lbcrypto::Ciphertext<DCRTPoly> ciphertext1, reEncryptedCT1, reEncryptedCT;

lbcrypto::EvalKey<DCRTPoly> reencryptionKey;

void PRE_keygen(benchmark::State &state) {
    //std::cout << "\nRunning key generation (used for source data)..."
    //            << std::endl;

    for (auto _ : state) {
        keyPairproducer = cryptoContext->KeyGen();
    }

    if (!keyPairproducer.good()) {
        std::cout << "Key generation failed!" << std::endl;
        exit(1);
    }
}
void PRE_Encrypt(benchmark::State &state) {
    //std::cout << "\nRunning encrypt (used for source data)..."
    //            << std::endl;
    ringsize = cryptoContext->GetRingDimension();
    nShort = ringsize;
    for (size_t i = 0; i < nShort; i++){ //generate a random array of shorts
        if(plaintextModulus==2) {
            vectorOfInts.push_back(std::rand() % plaintextModulus);
        }
        else {
            vectorOfInts.push_back((std::rand() % plaintextModulus) - (std::floor(plaintextModulus/2)-1));
        }
    }

    plaintext = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts);
    ////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////
    for (auto _ : state) {
        ciphertext1 = cryptoContext->Encrypt(keyPairproducer.publicKey, plaintext);
    }
}

void PRE_DecryptBeforeReEncrypt(benchmark::State &state) {
    for (auto _ : state) {
        cryptoContext->Decrypt(keyPairproducer.secretKey, ciphertext1, &plaintextDecproducer);
    }
    plaintextDecproducer->SetLength(plaintext->GetLength());
}

void PRE_Rekeygen(benchmark::State &state) {
    keyPairconsumer = cryptoContext->KeyGen();

    for (auto _ : state) {
        benchmark::DoNotOptimize(reencryptionKey =
            cryptoContext->ReKeyGen(keyPairproducer.secretKey, keyPairconsumer.publicKey));
    }
}

void PRE_ReEncrypt(benchmark::State &state) {
    for (auto _ : state) {
        if (security_model == 0) {
            //std::cout << "CPA secure PRE" << std::endl;
            benchmark::DoNotOptimize(reEncryptedCT = cryptoContext->ReEncrypt(ciphertext1, reencryptionKey)); //IND-CPA secure
        }
        else if (security_model == 1) {
            //std::cout << "Fixed noise (20 bits) practically secure PRE" << std::endl;
            benchmark::DoNotOptimize(reEncryptedCT = cryptoContext->ReEncrypt(ciphertext1, reencryptionKey, keyPairproducer.publicKey)); //fixed bits noise HRA secure
        } else if ((security_model == 2) || (security_model == 3)) {
            //std::cout << "Provable HRA secure PRE" << std::endl;
            benchmark::DoNotOptimize(reEncryptedCT1 = cryptoContext->ReEncrypt(ciphertext1, reencryptionKey, keyPairproducer.publicKey)); //HRA secure noiseflooding
            benchmark::DoNotOptimize(reEncryptedCT = cryptoContext->ModReduce(reEncryptedCT1)); //mod reduction for noise flooding
        } else {
            std::cerr << "Not a valid security mode" << std::endl;
            exit(EXIT_FAILURE);
        }
    }
}

void PRE_DecryptAfterReEncrypt(benchmark::State &state) {
    for (auto _ : state) {
        cryptoContext->Decrypt(keyPairconsumer.secretKey, reEncryptedCT, &plaintextDecconsumer);
    }
    plaintextDecconsumer->SetLength(plaintext->GetLength());
}


int main(int argc, char** argv)
{
   char opt(0);
    static struct option long_options[] =
    {
        {"Security model",       required_argument, NULL, 'm'},
        {"Number of hops",       required_argument, NULL, 'd'},
        {"help",                 no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    const char* optstring = "m:d:h";
    while ((opt = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
        std::cerr << "opt1: " << opt << "; optarg: " << optarg << std::endl;
        switch (opt) {
        case 'm':
            security_model = atoi(optarg);
            break;
        case 'd':
            num_of_hops = atoi(optarg);
            break;
        case 'h':
            usage();
        default:
            return false;
        }
    }

    //0 - CPA secure PRE, 1 - fixed 20 bits noise, 2 - provable secure HRA noise flooding
    parameters.SetPREMode(INDCPA);
    parameters.SetKeySwitchTechnique(BV);
     if (security_model == 0) {
       plaintextModulus = 2;
       multDepth = 0;
       sigma = 3.2;		
       securityLevel = HEStd_128_classic;
       ringDimension = 1024;
       relinWindow = 3;
       dcrtbits = 0;

       qmodulus = 27;
       firstqmod = 27;
       security_model = 0;
       parameters.SetPREMode(INDCPA);
    } else if (security_model == 1) {
        plaintextModulus = 2;
        multDepth = 0;
        sigma = 3.2;		
        securityLevel = HEStd_128_classic;
        ringDimension = 2048;
        relinWindow = 18;
        dcrtbits = 0;

        qmodulus = 54;
        firstqmod = 54;
        security_model = 1; 
        parameters.SetPREMode(FIXED_NOISE_HRA);
    } else if (security_model == 2) {
        plaintextModulus = 2;
        multDepth = 0;
        sigma = 3.2;		
        securityLevel = HEStd_128_classic;
        ringDimension = 16384;
        relinWindow = 1;
        dcrtbits = 30;

        qmodulus = 438;
        firstqmod = 60;
        security_model = 2;
        parameters.SetPREMode(NOISE_FLOODING_HRA);
    } else if (security_model == 3) {
        ringDimension = 16384;
        relinWindow = 0;
        dcrtbits = 30;

        qmodulus = 438;
        firstqmod = 60;
        uint32_t dnum = 3;
        parameters.SetPREMode(NOISE_FLOODING_HRA);
        parameters.SetKeySwitchTechnique(HYBRID);
        parameters.SetNumLargeDigits(dnum);
    }

    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetPlaintextModulus(plaintextModulus);
	parameters.SetSecurityLevel(securityLevel);
	parameters.SetStandardDeviation(sigma);
	parameters.SetMaxDepth(2);
    parameters.SetMode(OPTIMIZED);
    parameters.SetRingDim(ringDimension);
    parameters.SetFirstModSize(firstqmod);
    parameters.SetScalingFactorBits(dcrtbits);
    parameters.SetRelinWindow(relinWindow);
    parameters.SetRescalingTechnique(FIXEDMANUAL);
    parameters.SetMultiHopQModulusLowerBound(qmodulus);

    cryptoContext = GenCryptoContext(parameters);
            
        // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(PRE);


    std::cout << "p = "
                << cryptoContext->GetCryptoParameters()->GetPlaintextModulus()
                << std::endl;
    std::cout << "n = "
                << cryptoContext->GetCryptoParameters()
                        ->GetElementParams()
                        ->GetCyclotomicOrder() /
                    2
                << std::endl;
    std::cout << "log2 q = "
                << log2(cryptoContext->GetCryptoParameters()
                            ->GetElementParams()
                            ->GetModulus()
                            .ConvertToDouble())
                << std::endl;
    std::cout << "r = " << cryptoContext->GetCryptoParameters()->GetRelinWindow()
                << std::endl;

    int num_of_repetitions = 100;
    ::benchmark::Initialize(&argc, argv);
    ::benchmark::RegisterBenchmark("Keygen", &PRE_keygen)->ReportAggregatesOnly(true)->Repetitions(num_of_repetitions)->Unit(benchmark::kMillisecond);
    ::benchmark::RegisterBenchmark("Encrypt", &PRE_Encrypt)->ReportAggregatesOnly(true)->Repetitions(num_of_repetitions)->Unit(benchmark::kMillisecond);
    ::benchmark::RegisterBenchmark("DecryptBefore", &PRE_DecryptBeforeReEncrypt)->ReportAggregatesOnly(true)->Repetitions(num_of_repetitions)->Unit(benchmark::kMillisecond);
    ::benchmark::RegisterBenchmark("ReKeygen", &PRE_Rekeygen)->ReportAggregatesOnly(true)->Repetitions(num_of_repetitions)->Unit(benchmark::kMillisecond);
    ::benchmark::RegisterBenchmark("ReEncrypt", &PRE_ReEncrypt)->ReportAggregatesOnly(true)->Repetitions(num_of_repetitions)->Unit(benchmark::kMillisecond);
    ::benchmark::RegisterBenchmark("DecryptAfter", &PRE_DecryptAfterReEncrypt)->ReportAggregatesOnly(true)->Repetitions(num_of_repetitions)->Unit(benchmark::kMillisecond);
    
    ::benchmark::RunSpecifiedBenchmarks();

    vector<int64_t> unpackedPT, unpackedDecPT;
    unpackedPT = plaintextDecproducer->GetCoefPackedValue();
    unpackedDecPT = plaintextDecconsumer->GetCoefPackedValue();
    for (unsigned int j = 0; j < unpackedPT.size(); j++) {
        if (unpackedPT[j] != unpackedDecPT[j]) {
            std::cout << "Decryption failure" << std::endl;
            std::cout << j << ", " << unpackedPT[j] << ", "
                        << unpackedDecPT[j] << std::endl;
        }
    }

    ::benchmark::Shutdown();
    return 0;
}


//BENCHMARK_MAIN();