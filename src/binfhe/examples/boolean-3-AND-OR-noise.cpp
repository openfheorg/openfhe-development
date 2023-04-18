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
    TimeVar t;
    auto cc = BinFHEContext();

    // STD128 is the security level of 128 bits of security based on LWE Estimator
    // and HE standard. Other common options are TOY, MEDIUM, STD192, and STD256.
    // MEDIUM corresponds to the level of more than 100 bits for both quantum and
    // classical computer attacks.

    cc.GenerateBinFHEContext(STD128_en_3_1);
    //cc.GenerateBinFHEContext(STD256Q_3, AP);
    //cc.GenerateBinFHEContext(STD128_3);

    // Sample Program: Step 2: Key Generation

    // Generate the secret key
    auto sk = cc.KeyGen();
    
    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(sk);

    // Sample Program: Step 3: Encryption

    // Encrypt two ciphertexts representing Boolean True (1).
    // By default, freshly encrypted ciphertexts are bootstrapped.
    // If you wish to get a fresh encryption without bootstrapping, write
    // auto   ct1 = cc.Encrypt(sk, 1, FRESH);
    auto p = 6;
    auto ct1 = cc.Encrypt(sk, 1, SMALL_DIM, p);
    auto ct2 = cc.Encrypt(sk, 1, SMALL_DIM, p);
    auto ct3 = cc.Encrypt(sk, 0, SMALL_DIM, p);
    auto ct4 = cc.Encrypt(sk, 0, SMALL_DIM, p);
    auto ct5 = cc.Encrypt(sk, 1, SMALL_DIM, p);
    auto ct6 = cc.Encrypt(sk, 0, SMALL_DIM, p);


    //1, 0
    //auto ctORmix = cc.EvalBinGate(OR, ct1, ct3);
    //0, 0
    //auto ctANDmix = cc.EvalBinGate(AND, ct3, ct4);

    //auto ctANDmix = cc.EvalBinGateFourInput(AND3, ct1, ct2, ct3, ct4);
    // Sample Program: Step 4: Evaluation
    // Compute (1 AND 1 AND 1) = 1; Other binary gate options are OR, NAND, and NOR

    //1, 0, 0
    auto ctAND1 = cc.EvalBinGateThreeInput(AND3, ct1, ct3, ct4);
    //1, 1, 0
    auto ctAND2 = cc.EvalBinGateThreeInput(AND3, ct1, ct2, ct3);

    //1, 1, 1
    auto ctAND3 = cc.EvalBinGateThreeInput(AND3, ct1, ct2, ct5);

    //0, 0, 0
    auto ctAND4 = cc.EvalBinGateThreeInput(AND3, ct3, ct4, ct6);

    //1, 0, 0
    auto ctOR1 = cc.EvalBinGateThreeInput(OR3, ct1, ct3, ct4);
    //1, 1, 0
    auto ctOR2 = cc.EvalBinGateThreeInput(OR3, ct1, ct2, ct3);

    //1, 1, 1
    auto ctOR3 = cc.EvalBinGateThreeInput(OR3, ct1, ct2, ct5);

    //1, 1, 1
    auto ctOR4 = cc.EvalBinGateThreeInput(OR3, ct3, ct4, ct6);

    
    // Sample Program: Step 5: Decryption

    LWEPlaintext result;

    cc.Decrypt(sk, ctAND1, &result);
    cc.Decrypt(sk, ctAND2, &result);
    cc.Decrypt(sk, ctAND3, &result);
    if (result != 1)
      OPENFHE_THROW(math_error, "Decryption failure");

    std::cout << "Result of encrypted computation of AND(1, 1, 1) = " << result << std::endl;

    cc.Decrypt(sk, ctAND4, &result);
    if (result != 0)
      OPENFHE_THROW(math_error, "Decryption failure");

    std::cout << "Result of encrypted computation of AND(0, 0, 0) = " << result << std::endl;

    cc.Decrypt(sk, ctOR1, &result);
    if (result != 1)
      OPENFHE_THROW(math_error, "Decryption failure");

    std::cout << "Result of encrypted computation of OR(1, 0, 0) = " << result << std::endl;

    cc.Decrypt(sk, ctOR2, &result);
    if (result != 1)
      OPENFHE_THROW(math_error, "Decryption failure");

    std::cout << "Result of encrypted computation of OR(1, 1, 0) = " << result << std::endl;

    cc.Decrypt(sk, ctOR3, &result);
    if (result != 1)
      OPENFHE_THROW(math_error, "Decryption failure");

    std::cout << "Result of encrypted computation of OR(1, 1, 1) = " << result << std::endl;

    cc.Decrypt(sk, ctOR4, &result);
    if (result != 0)
      OPENFHE_THROW(math_error, "Decryption failure");

    std::cout << "Result of encrypted computation of OR(0, 0, 0) = " << result << std::endl;

    return 0;
}
