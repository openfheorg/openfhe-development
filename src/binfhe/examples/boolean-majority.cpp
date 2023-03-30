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

    // Sample Program: Step 2: Key Generation

    // Generate the secret key
    auto sk = cc.KeyGen();

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(sk);

    std::cout << "Completed the key generation." << std::endl;

    // Sample Program: Step 3: Encryption

    // Encrypt two ciphertexts representing Boolean True (1).
    // By default, freshly encrypted ciphertexts are bootstrapped.
    // If you wish to get a fresh encryption without bootstrapping, write
    // auto   ct1 = cc.Encrypt(sk, 1, FRESH);
    auto ct1 = cc.Encrypt(sk, 1);
    auto ct2 = cc.Encrypt(sk, 1);
    auto ct3 = cc.Encrypt(sk, 1);
    auto ct4 = cc.Encrypt(sk, 0);
    auto ct5 = cc.Encrypt(sk, 0);

    // Sample Program: Step 4: Evaluation

    // Compute (1 AND 1) = 1; Other binary gate options are OR, NAND, and NOR
    auto ctAND = cc.EvalBinGate(AND, ct1, ct2);

    //1, 1, 0, 1
    auto ctMajority1 = cc.EvalBinGateFourInput(MAJORITY, ct1, ct2, ct4, ct3);
    //1, 0, 0
    auto ctMajority0 = cc.EvalBinGateThreeInput(MAJORITY, ct3, ct4, ct5);

    //1, 0, 1
    auto ctCMUX1 = cc.EvalBinGateThreeInput(CMUX, ct3, ct4, ct2);
    
    //1, 0, 0
    auto ctCMUX0 = cc.EvalBinGateThreeInput(CMUX, ct3, ct4, ct5);

    // Sample Program: Step 5: Decryption

    LWEPlaintext result;

    cc.Decrypt(sk, ctMajority1, &result);

    std::cout << "Result of encrypted computation of Majority(1, 1, 0, 1) = " << result << std::endl;

    cc.Decrypt(sk, ctMajority0, &result);

    std::cout << "Result of encrypted computation of Majority(1, 0, 0) = " << result << std::endl;

    cc.Decrypt(sk, ctCMUX1, &result);

    std::cout << "Result of encrypted computation of CMUX(1, 0, 0) = " << result << std::endl;

    cc.Decrypt(sk, ctCMUX0, &result);

    std::cout << "Result of encrypted computation of CMUX(1, 0, 1) = " << result << std::endl;

    cc.Decrypt(sk, ctAND, &result);

    std::cout << "Result of encrypted computation of 1 AND 1 = " << result << std::endl;

    return 0;
}
