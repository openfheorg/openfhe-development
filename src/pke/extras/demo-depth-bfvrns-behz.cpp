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
  BEHZ demo for a homomorphic multiplication of depth 6 and three different approaches for depth-3 multiplications
 */

#define PROFILE

#include <iostream>

#include "openfhe.h"
#include "utils/debug.h"

using namespace lbcrypto;

int main(int argc, char* argv[]) {
    ////////////////////////////////////////////////////////////
    // Set-up of parameters
    TimeVar t;
    double processingTime(0.0);

    int numkeys = 1 << 4;
    int numruns = 1 << 4;

    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(3);
    parameters.SetDigitSize(1);
    parameters.SetScalingModSize(60);
    parameters.SetMultiplicationTechnique(BEHZ);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    std::cout << "\np = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2
              << std::endl;
    std::cout << "log2 q = "
              << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    std::cout << "\nMeasuring Multiplicative Depth:\n";
    TIC(t);

    std::vector<int64_t> vectorOfInts1 = {1};
    Plaintext plaintext                = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts1);
    Plaintext dec(plaintext);
    Ciphertext<DCRTPoly> ciphertext;
    std::vector<int> depth(numruns, 0);
    std::vector<int> min(numkeys, 0);

    for (int i = 0; i < numkeys; i++) {
        keyPair = cryptoContext->KeyGen();
        cryptoContext->EvalMultKeysGen(keyPair.secretKey);

        std::cout << "Key " << i << ": ";

        for (int j = 0; j < numruns; j++) {
            ciphertext = cryptoContext->Encrypt(keyPair.publicKey, plaintext);

            dec = plaintext;

            depth[j] = 0;
            while (dec == plaintext) {
                ciphertext = cryptoContext->EvalMult(ciphertext, ciphertext);
                cryptoContext->Decrypt(keyPair.secretKey, ciphertext, &dec);

                depth[j]++;
            }
            depth[j]--;
            std::cerr << depth[j] << " ";
        }
        min[i] = depth[0];
        for (int j = 1; j < numruns; j++)
            if (min[i] > depth[j])
                min[i] = depth[j];
        std::cout << "--> " << min[i] << "\n";
    }
    std::cout << "\n";

    int MIN = min[0];
    for (int i = 1; i < numkeys; i++)
        if (MIN > min[i])
            MIN = min[i];
    std::cout << "Smallest depth = " << MIN;

    processingTime = TOC(t);
    std::cout << " in " << processingTime / 1000. << "s\n" << std::endl;

    return 0;
}
