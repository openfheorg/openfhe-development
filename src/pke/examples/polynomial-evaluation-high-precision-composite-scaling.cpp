//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2025, Duality Technologies Inc. and other contributors
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
  Example of polynomial evaluation using CKKS.
 */

#define PROFILE  // turns on the reporting of timing results

#include "openfhe.h"

#include <vector>
#include <iostream>

using namespace lbcrypto;

void printPrimeModuliChain(const DCRTPoly& poly) {
    int num_primes       = poly.GetNumOfElements();
    double total_bit_len = 0.0;
    for (int i = 0; i < num_primes; i++) {
        auto qi = poly.GetParams()->GetParams()[i]->GetModulus();
        std::cout << "q_" << i << ": " << qi << ",  log q_" << i << ": " << log(qi.ConvertToDouble()) / log(2)
                  << std::endl;
        total_bit_len += log(qi.ConvertToDouble()) / log(2);
    }
    std::cout << "Total bit length: " << total_bit_len << std::endl;
}

double getScaleApproxError(const DCRTPoly& poly, uint32_t numPrimes, uint32_t compositeDegree, uint32_t firstModSize,
                           uint32_t scalingModSize) {
    double delta0 = std::pow(2.0, static_cast<double>(firstModSize));
    double delta  = std::pow(2.0, static_cast<double>(scalingModSize));
    // uint32_t numPrimes = poly.GetNumOfElements();
    auto q = poly.GetParams()->GetParams();

    std::cout << "numPrimes=" << numPrimes << " compositeDegree=" << compositeDegree << " firstModSize=" << firstModSize
              << " scalingModSize=" << scalingModSize << std::endl;

    double prod = q[0]->GetModulus().ConvertToDouble();
    std::cout << "q0_0: " << prod;
    for (uint32_t d = 1; d < compositeDegree; ++d) {
        std::cout << " q0_" << d << ": " << q[d]->GetModulus().ConvertToDouble();
        prod *= q[d]->GetModulus().ConvertToDouble();
    }
    std::cout << "\n";
    double cumApproxError = std::abs(delta0 - prod);

    std::cout << "q0: " << prod << " delta0: " << delta0 << " approxErr=" << std::abs(delta0 - prod) << std::endl;

    for (uint32_t i = compositeDegree; i < numPrimes; i += compositeDegree) {
        prod = q[i]->GetModulus().ConvertToDouble();
        std::cout << "q" << i / compositeDegree << "_0: " << prod;
        for (uint32_t d = 1; d < compositeDegree; ++d) {
            std::cout << " q" << i / compositeDegree << "_" << d << ": " << q[i + d]->GetModulus().ConvertToDouble();
            prod *= q[i + d]->GetModulus().ConvertToDouble();
        }
        std::cout << "\n";
        cumApproxError += std::abs(delta - prod);
        std::cout << "q" << i / compositeDegree << ": " << prod << " delta: " << delta
                  << " approxErr=" << std::abs(delta - prod) << std::endl;
    }

    std::cout << "Average distance to scaling factor: "
              << cumApproxError / ((numPrimes - compositeDegree) / compositeDegree) << std::endl;

    return cumApproxError / ((numPrimes - compositeDegree) / compositeDegree);
}

int main(int argc, char* argv[]) {
    TimeVar t;

    double timeEvalPoly1(0.0), timeEvalPoly2(0.0);
    // Parameters for d=4
    // uint32_t firstModSize     = 106;
    // uint32_t scalingModSize   = 104;
    // uint32_t registerWordSize = 32;
    // Parameters for d=3
    uint32_t firstModSize     = 96;
    uint32_t scalingModSize   = 80;
    uint32_t registerWordSize = 32;

    std::cout << "\n======EXAMPLE FOR EVALPOLY========\n" << std::endl;

    uint32_t multDepth = 6;
    int argcCount      = 1;
    if (argc > 1) {
        while (argcCount < argc) {
            uint32_t paramValue = atoi(argv[argcCount]);
            switch (argcCount) {
                case 1:
                    firstModSize = paramValue;
                    std::cout << "Setting First Mod Size: " << firstModSize << std::endl;
                    break;
                case 2:
                    scalingModSize = paramValue;
                    std::cout << "Setting Scaling Mod Size: " << scalingModSize << std::endl;
                    break;
                case 3:
                    registerWordSize = paramValue;
                    std::cout << "Setting Register Word Size: " << registerWordSize << std::endl;
                    break;
                case 4:
                    multDepth = paramValue;
                    std::cout << "Setting Multiplicative Depth: " << multDepth << std::endl;
                    break;
                default:
                    std::cout << "Invalid option" << std::endl;
                    break;
            }
            argcCount += 1;
        }

        std::cout << "Completed reading input parameters!" << std::endl;
    }
    else {
        std::cout << "Using default parameters" << std::endl;
        std::cout << "First Mod Size: " << firstModSize << std::endl;
        std::cout << "Scaling Mod Size: " << scalingModSize << std::endl;
        std::cout << "Register Word Size: " << registerWordSize << std::endl;
        std::cout << "Multiplicative Depth: " << multDepth << std::endl;
        std::cout << "Usage: " << argv[0] << " [firstModSize] [scalingModSize] [registerWordSize] [multDepth]"
                  << std::endl;
    }

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingModSize(scalingModSize);

    parameters.SetRegisterWordSize(registerWordSize);
    parameters.SetScalingTechnique(COMPOSITESCALINGAUTO);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    const auto cryptoParamsCKKSRNS = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    uint32_t compositeDegree       = cryptoParamsCKKSRNS->GetCompositeDegree();

    std::cout << "-----------------------------------------------------------------" << std::endl;
    std::cout << "Composite Degree: " << compositeDegree << "\nPrime Moduli Size: "
              << static_cast<float>(scalingModSize) / cryptoParamsCKKSRNS->GetCompositeDegree()
              << "\nRegister Word Size: " << registerWordSize << std::endl;
    std::cout << "-----------------------------------------------------------------" << std::endl;

    std::vector<std::complex<double>> input({0.5, 0.7, 0.9, 0.95, 0.93});

    size_t encodedLength = input.size();

    std::vector<double> coefficients1({0.15, 0.75, 0, 1.25, 0, 0, 1, 0, 1, 2, 0, 1, 0, 0, 0, 0, 1});
    std::vector<double> coefficients2({1,   2,   3,   4,   5,   -1,   -2,   -3,   -4,   -5,
                                       0.1, 0.2, 0.3, 0.4, 0.5, -0.1, -0.2, -0.3, -0.4, -0.5,
                                       0.1, 0.2, 0.3, 0.4, 0.5, -0.1, -0.2, -0.3, -0.4, -0.5});

    Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(input);

    auto keyPair = cc->KeyGen();

    std::cout << "Generating evaluation key for homomorphic multiplication...";
    cc->EvalMultKeyGen(keyPair.secretKey);
    std::cout << "Completed." << std::endl;

    const std::vector<DCRTPoly>& ckkspk = keyPair.publicKey->GetPublicElements();
    std::cout << "Moduli chain of pk: " << std::endl;
    printPrimeModuliChain(ckkspk[0]);

    double avgScaleError = getScaleApproxError(ckkspk[0], (multDepth + 1) * compositeDegree, compositeDegree,
                                               firstModSize, scalingModSize);
    std::cout << "Average Scale Error: " << avgScaleError << std::endl;

    auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);

    TIC(t);

    auto result = cc->EvalPoly(ciphertext1, coefficients1);

    timeEvalPoly1 = TOC(t);

    TIC(t);

    auto result2 = cc->EvalPoly(ciphertext1, coefficients2);

    timeEvalPoly2 = TOC(t);

    Plaintext plaintextDec;

    cc->Decrypt(keyPair.secretKey, result, &plaintextDec);

    plaintextDec->SetLength(encodedLength);

    Plaintext plaintextDec2;

    cc->Decrypt(keyPair.secretKey, result2, &plaintextDec2);

    plaintextDec2->SetLength(encodedLength);

    std::cout << std::setprecision(15) << std::endl;

    std::cout << "\n Original Plaintext #1: \n";
    std::cout << plaintext1 << std::endl;

    std::cout << "\n Result of evaluating a polynomial with coefficients " << coefficients1 << " \n";
    std::cout << plaintextDec << std::endl;

    std::cout << "\n Expected result: (0.70519107, 1.38285078, 3.97211180, "
                 "5.60215665, 4.86357575) "
              << std::endl;

    std::cout << "\n Evaluation time: " << timeEvalPoly1 << " ms" << std::endl;

    std::cout << "\n Result of evaluating a polynomial with coefficients " << coefficients2 << " \n";
    std::cout << plaintextDec2 << std::endl;

    std::cout << "\n Expected result: (3.4515092326, 5.3752765397, 4.8993108833, "
                 "3.2495023573, 4.0485229982) "
              << std::endl;

    std::cout << "\n Evaluation time: " << timeEvalPoly2 << " ms" << std::endl;

    return 0;
}
