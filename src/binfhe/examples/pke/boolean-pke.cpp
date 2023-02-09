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
  Example for the FHEW scheme using the default bootstrapping method (GINX)
 */

#include "binfhecontext.h"

using namespace lbcrypto;

int main() {
    // Sample Program: Step 1: Set CryptoContext

    auto cc = BinFHEContext();

    // STD128 is the security level of 128 bits of security based on LWE Estimator
    // and HE standard. Other common options are TOY, MEDIUM, STD192, and STD256.
    // MEDIUM corresponds to the level of more than 100 bits for both quantum and
    // classical computer attacks.
    cc.GenerateBinFHEContext(STD128);

    // verifying public key encrypt and decrypt without bootstrap
    // Generate the secret, public key pair
    auto kp = cc.KeyGenPair();

    // LARGE_DIM specifies the dimension of the output ciphertext
    auto ctp = cc.Encrypt(kp->publicKey, 1, LARGE_DIM);

    LWEPlaintext result;

    // decryption check before computation
    cc.Decrypt(kp->secretKey, ctp, &result);

    std::cout << "Result of encrypted ciphertext of 1 = " << result << std::endl;

    // Sample Program: Step 2: Key Generation

    // Generate the secret key
    auto sk = cc.KeyGen();

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    // Generate the bootstrapping keys (refresh, switching and public keys)
    cc.BTKeyGen(sk, PUB_ENCRYPT);

    std::cout << "Completed the key generation." << std::endl;

    // Sample Program: Step 3: Encryption

    // Encrypt two ciphertexts representing Boolean True (1).
    // By default, freshly encrypted ciphertexts are bootstrapped.
    // If you wish to get a fresh encryption without bootstrapping, write
    // auto   ct1 = cc.Encrypt(sk, 1, FRESH);
    auto ct1 = cc.Encrypt(cc.GetPublicKey(), 1);
    auto ct2 = cc.Encrypt(cc.GetPublicKey(), 1);

    // decryption check before computation
    cc.Decrypt(sk, ct1, &result);

    std::cout << "Result of encrypted ciphertext of 1 = " << result << std::endl;

    // Sample Program: Step 4: Evaluation

    // Compute (1 AND 1) = 1; Other binary gate options are OR, NAND, and NOR
    LWEPlaintext result1;
    auto ctAND1 = cc.EvalBinGate(AND, ct1, ct2);

    cc.Decrypt(sk, ctAND1, &result1);

    std::cout << "Result of encrypted computation of (1 AND 1) = " << result1 << std::endl;

    // Compute (NOT 1) = 0
    auto ct2Not = cc.EvalNOT(ct2);

    cc.Decrypt(sk, ct2Not, &result);

    std::cout << "Result of encrypted computation of (NOT 1) = " << result << std::endl;

    // Compute (1 AND (NOT 1)) = 0
    auto ctAND2 = cc.EvalBinGate(AND, ct2Not, ct1);

    cc.Decrypt(sk, ctAND2, &result);

    std::cout << "Result of encrypted computation of (1 AND (NOT 1)) = " << result << std::endl;

    // Computes OR of the results in ctAND1 and ctAND2 = 1
    auto ctResult = cc.EvalBinGate(OR, ctAND1, ctAND2);

    // Sample Program: Step 5: Decryption
    cc.Decrypt(sk, ctResult, &result);

    std::cout << "Result of encrypted computation of (1 AND 1) OR (1 AND (NOT 1)) = " << result << std::endl;

    return 0;
}
