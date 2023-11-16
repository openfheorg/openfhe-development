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
  Example for the FHEW scheme; it prints out the truth tables for all supported binary gates
 */

#include "binfhecontext.h"

using namespace lbcrypto;

int main() {
    // Sample Program: Step 1: Set CryptoContext
    auto cc = BinFHEContext();

    std::cerr << "Generate cryptocontext" << std::endl;

    // STD128 is the security level of 128 bits of security based on LWE Estimator
    // and HE standard. Other options are TOY, MEDIUM, STD192, and STD256. MEDIUM
    // corresponds to the level of more than 100 bits for both quantum and
    // classical computer attacks.
    cc.GenerateBinFHEContext(STD128);

    std::cerr << "Finished generating cryptocontext" << std::endl;

    // Sample Program: Step 2: Key Generation

    // Generate the secret key
    auto sk = cc.KeyGen();

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    // Generate the bootstrapping keys (refresh, switching and public keys)
    cc.BTKeyGen(sk, PUB_ENCRYPT);

    auto pk = cc.GetPublicKey();

    std::cout << "Completed the key generation."
              << "\n"
              << std::endl;

    // Sample Program: Step 3: Encryption

    // Encrypt two ciphertexts representing Boolean True (1)
    auto ct10 = cc.Encrypt(pk, 1);
    auto ct11 = cc.Encrypt(pk, 1);

    // Encrypt two ciphertexts representing Boolean False (0)
    auto ct00 = cc.Encrypt(pk, 0);
    auto ct01 = cc.Encrypt(pk, 0);

    // Sample Program: Step 4: Evaluation of NAND gates

    auto ctNAND1 = cc.EvalBinGate(NAND, ct10, ct11);
    auto ctNAND2 = cc.EvalBinGate(NAND, ct10, ct01);
    auto ctNAND3 = cc.EvalBinGate(NAND, ct00, ct01);
    auto ctNAND4 = cc.EvalBinGate(NAND, ct00, ct11);

    LWEPlaintext result;

    cc.Decrypt(sk, ctNAND1, &result);
    std::cout << "1 NAND 1 = " << result << std::endl;

    cc.Decrypt(sk, ctNAND2, &result);
    std::cout << "1 NAND 0 = " << result << std::endl;

    cc.Decrypt(sk, ctNAND3, &result);
    std::cout << "0 NAND 0 = " << result << std::endl;

    cc.Decrypt(sk, ctNAND4, &result);
    std::cout << "0 NAND 1 = " << result << "\n" << std::endl;

    // Sample Program: Step 5: Evaluation of AND gates

    auto ctAND1 = cc.EvalBinGate(AND, ct10, ct11);
    auto ctAND2 = cc.EvalBinGate(AND, ct10, ct01);
    auto ctAND3 = cc.EvalBinGate(AND, ct00, ct01);
    auto ctAND4 = cc.EvalBinGate(AND, ct00, ct11);

    cc.Decrypt(sk, ctAND1, &result);
    std::cout << "1 AND 1 = " << result << std::endl;

    cc.Decrypt(sk, ctAND2, &result);
    std::cout << "1 AND 0 = " << result << std::endl;

    cc.Decrypt(sk, ctAND3, &result);
    std::cout << "0 AND 0 = " << result << std::endl;

    cc.Decrypt(sk, ctAND4, &result);
    std::cout << "0 AND 1 = " << result << "\n" << std::endl;

    // Sample Program: Step 6: Evaluation of OR gates

    auto ctOR1 = cc.EvalBinGate(OR, ct10, ct11);
    auto ctOR2 = cc.EvalBinGate(OR, ct10, ct01);
    auto ctOR3 = cc.EvalBinGate(OR, ct00, ct01);
    auto ctOR4 = cc.EvalBinGate(OR, ct00, ct11);

    cc.Decrypt(sk, ctOR1, &result);
    std::cout << "1 OR 1 = " << result << std::endl;

    cc.Decrypt(sk, ctOR2, &result);
    std::cout << "1 OR 0 = " << result << std::endl;

    cc.Decrypt(sk, ctOR3, &result);
    std::cout << "0 OR 0 = " << result << std::endl;

    cc.Decrypt(sk, ctOR4, &result);
    std::cout << "0 OR 1 = " << result << "\n" << std::endl;

    // Sample Program: Step 7: Evaluation of NOR gates

    auto ctNOR1 = cc.EvalBinGate(NOR, ct10, ct11);
    auto ctNOR2 = cc.EvalBinGate(NOR, ct10, ct01);
    auto ctNOR3 = cc.EvalBinGate(NOR, ct00, ct01);
    auto ctNOR4 = cc.EvalBinGate(NOR, ct00, ct11);

    cc.Decrypt(sk, ctNOR1, &result);
    std::cout << "1 NOR 1 = " << result << std::endl;

    cc.Decrypt(sk, ctNOR2, &result);
    std::cout << "1 NOR 0 = " << result << std::endl;

    cc.Decrypt(sk, ctNOR3, &result);
    std::cout << "0 NOR 0 = " << result << std::endl;

    cc.Decrypt(sk, ctNOR4, &result);
    std::cout << "0 NOR 1 = " << result << "\n" << std::endl;

    // Sample Program: Step 8: Evaluation of XOR gates

    auto ctXOR1 = cc.EvalBinGate(XOR, ct10, ct11);
    auto ctXOR2 = cc.EvalBinGate(XOR, ct10, ct01);
    auto ctXOR3 = cc.EvalBinGate(XOR, ct00, ct01);
    auto ctXOR4 = cc.EvalBinGate(XOR, ct00, ct11);

    cc.Decrypt(sk, ctXOR1, &result);
    std::cout << "1 XOR 1 = " << result << std::endl;

    cc.Decrypt(sk, ctXOR2, &result);
    std::cout << "1 XOR 0 = " << result << std::endl;

    cc.Decrypt(sk, ctXOR3, &result);
    std::cout << "0 XOR 0 = " << result << std::endl;

    cc.Decrypt(sk, ctXOR4, &result);
    std::cout << "0 XOR 1 = " << result << "\n" << std::endl;

    // Sample Program: Step 9: Evaluation of XNOR gates

    auto ctXNOR1 = cc.EvalBinGate(XNOR, ct10, ct11);
    auto ctXNOR2 = cc.EvalBinGate(XNOR, ct10, ct01);
    auto ctXNOR3 = cc.EvalBinGate(XNOR, ct00, ct01);
    auto ctXNOR4 = cc.EvalBinGate(XNOR, ct00, ct11);

    cc.Decrypt(sk, ctXNOR1, &result);
    std::cout << "1 XNOR 1 = " << result << std::endl;

    cc.Decrypt(sk, ctXNOR2, &result);
    std::cout << "1 XNOR 0 = " << result << std::endl;

    cc.Decrypt(sk, ctXNOR3, &result);
    std::cout << "0 XNOR 0 = " << result << std::endl;

    cc.Decrypt(sk, ctXNOR4, &result);
    std::cout << "0 XNOR 1 = " << result << "\n" << std::endl;

    return 0;
}
