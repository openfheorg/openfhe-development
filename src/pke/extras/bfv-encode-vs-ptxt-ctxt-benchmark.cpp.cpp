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
  Compares the performance of BFV plaintext encode vs plaintext-ciphertext multiplication,
  both are heavly used operations
 */

#define PROFILE

#include <chrono>
#include <iostream>
#include <vector>

#include "openfhe.h"

using namespace lbcrypto;

int main() {
    // Sample Program: Step 1: Set CryptoContext
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(5);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetMultiplicationTechnique(HPSPOVERQLEVELED);
    parameters.SetKeySwitchTechnique(BV);
    parameters.SetRingDim((1 << 14));

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    std::cout << "Element parameters: \n" << *cryptoContext->GetElementParams() << "\n";

    usint ringDim = cryptoContext->GetRingDimension();
    std::cout << "BFVrns scheme is using ring dimension " << ringDim << std::endl << std::endl;

    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    // Sample Program: Step 2: Key Generation

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    // Sample Program: Step 3: Encryption
    std::vector<int64_t> payload = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    // Second plaintext vector is encoded
    std::vector<int64_t> payload2 = {3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext ptxt2               = cryptoContext->MakePackedPlaintext(payload2, 1, 3);

    // Number of iterations for benchmarking
    int numIterations = 1000;

    // Variables to store total times
    TimeVar t;
    double totalEncodeTime = 0.0;
    double totalMultTime   = 0.0;

    auto ctxtGT = cryptoContext->Encrypt(keyPair.publicKey, ptxt2);

    // Benchmark loop
    for (int i = 0; i < numIterations; ++i) {
        TIC(t);
        Plaintext ptxt1 = cryptoContext->MakePackedPlaintext(payload, 1, 3);
        totalEncodeTime += TOC_NS(t);

        auto ctxt2 = cryptoContext->Encrypt(keyPair.publicKey, ptxt2);

        TIC(t);
        auto ctxtRes = cryptoContext->EvalMult(ctxt2, ptxt1);
        totalMultTime += TOC_NS(t);
        ctxtGT = ctxtRes;
    }

    // Calculate and report average times
    double avgEncodeTime = totalEncodeTime / numIterations / 1e6;
    double avgMultTime   = totalMultTime / numIterations / 1e6;

    // Average time to encode
    std::cout << "encode took: " << avgEncodeTime << " ms" << std::endl;
    // Average time to compute evalmult(ctxt, ptxt)
    std::cout << "ptxt-ctxt took: " << avgMultTime << " ms" << std::endl;

    Plaintext plaintextMult;
    cryptoContext->Decrypt(keyPair.secretKey, ctxtGT, &plaintextMult);

    plaintextMult->SetLength(payload.size());

    // Output results
    std::cout << "\nResults of homomorphic computations" << std::endl;
    std::cout << "plaintextMult: " << plaintextMult << std::endl;

    return 0;
}
