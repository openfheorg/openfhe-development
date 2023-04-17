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
  Example for the FHEW scheme homomorphic digit decomposition
 */

#include "binfhecontext.h"
#include <chrono>

using namespace lbcrypto;

int main() {
    // Sample Program: Step 1: Set CryptoContext

    auto cc = BinFHEContext();

    // Set the ciphertext modulus to be 1 << 23
    // Note that normally we do not use this way to obtain the input ciphertext.
    // Instead, we assume that an LWE ciphertext with large ciphertext
    // modulus is already provided (e.g., by extracting from a CKKS ciphertext).
    // However, we do not provide such a step in this example.
    // Therefore, we use a brute force way to create a large LWE ciphertext.
    uint32_t logQ = 23;
    cc.GenerateBinFHEContext(STD128, false, logQ, 0, GINX, false);

    uint32_t Q = 1 << logQ;

    int q      = 4096;                                               // q
    int factor = 1 << int(logQ - log2(q));                           // Q/q
    uint64_t P = cc.GetMaxPlaintextSpace().ConvertToInt() * factor;  // Obtain the maximum plaintext space

    // Sample Program: Step 2: Key Generation
    // Generate the secret key
    auto sk = cc.KeyGen();

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(sk);

    std::cout << "Completed the key generation." << std::endl;

    // Sample Program: Step 3: Encryption
    auto ct1 = cc.Encrypt(sk, P / 2 + 1, FRESH, P, Q);
    std::cout << "Encrypted value: " << P / 2 + 1 << std::endl;

    // Sample Program: Step 4: Evaluation
    // Decompose the large ciphertext into small ciphertexts that fit in q
    auto decomp = cc.EvalDecomp(ct1);

    // Sample Program: Step 5: Decryption
    uint64_t p = cc.GetMaxPlaintextSpace().ConvertToInt();
    std::cout << "Decomposed value: ";
    for (size_t i = 0; i < decomp.size(); i++) {
        ct1 = decomp[i];
        LWEPlaintext result;
        if (i == decomp.size() - 1) {
            // after every evalfloor, the least significant digit is dropped so the last modulus is computed as log p = (log P) mod (log GetMaxPlaintextSpace)
            auto logp = GetMSB(P - 1) % GetMSB(p - 1);
            p         = 1 << logp;
        }
        cc.Decrypt(sk, ct1, &result, p);
        std::cout << "(" << result << " * " << cc.GetMaxPlaintextSpace() << "^" << i << ")";
        if (i != decomp.size() - 1) {
            std::cout << " + ";
        }
    }
    std::cout << std::endl;
    return 0;
}
