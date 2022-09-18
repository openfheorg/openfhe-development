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
  Example for the FHEW scheme large precision sign evaluation
 */

#define PROFILE
#include "binfhecontext.h"

using namespace lbcrypto;

int main() {
    // Sample Program: Step 1: Set CryptoContext

    auto cc = BinFHEContext();

    // Set the ciphertext modulus to be 1 << 17
    // Note that normally we do not use this way to obtain the input ciphertext.
    // Instead, we assume that an LWE ciphertext with large ciphertext
    // modulus is already provided (e.g., by extracting from a CKKS ciphertext).
    // However, we do not provide such a step in this example.
    // Therefore, we use a brute force way to create a large LWE ciphertext.
    uint32_t logQ = 17;
    cc.GenerateBinFHEContext(STD128, false, logQ, 0, GINX, false);

    uint32_t Q = 1 << logQ;

    int q      = 4096;                                               // q
    int factor = 1 << int(logQ - log2(q));                           // Q/q
    int p      = cc.GetMaxPlaintextSpace().ConvertToInt() * factor;  // Obtain the maximum plaintext space

    // Sample Program: Step 2: Key Generation
    // Generate the secret key
    auto sk = cc.KeyGen();

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(sk);

    std::cout << "Completed the key generation." << std::endl;

    // Sample Program: Step 3: Extract the MSB and decrypt to check the result
    // Note that we check for 8 different numbers
    for (int i = 0; i < 8; i++) {
        // We first encrypt with large Q
        auto ct1 = cc.Encrypt(sk, p / 2 + i - 3, FRESH, p, Q);

        // Get the MSB
        ct1 = cc.EvalSign(ct1);

        LWEPlaintext result;
        cc.Decrypt(sk, ct1, &result, 2);
        std::cout << "Input: " << i << ". Expected sign: " << (i >= 3)
                  << ". "
                     "Evaluated Sign: "
                  << result << std::endl;
    }

    return 0;
}
