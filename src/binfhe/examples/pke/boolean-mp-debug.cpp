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
  Example for the FHEW scheme using the multiparty bootstrapping method with 5 parties
 */

#include "binfhecontext.h"

using namespace lbcrypto;

int main() {
    // Sample Program: Step 1: Set CryptoContext

    auto cc                 = BinFHEContext();
    uint32_t num_of_parties = 3;

    // STD128 is the security level of 128 bits of security based on LWE Estimator
    // and HE standard. Other common options are TOY, MEDIUM, STD192, and STD256.
    // MEDIUM corresponds to the level of more than 100 bits for both quantum and
    // classical computer attacks.
    cc.GenerateBinFHEContext(TOY, LMKCDEY, num_of_parties);  // number of parties is 5

    // Generate the secret keys s1, z1
    auto sk1 = cc.KeyGen();
    // generate RGSW secret key z_1, ..., z_5
    auto z1 = cc.RGSWKeygen();

    // generate public key, key switching key for the secrets
    cc.MultiPartyKeyGen(sk1, z1, cc.GetPublicKey(), cc.GetSwitchKey(), true);
    auto pk1 = cc.GetPublicKey();

    //**********************************
    // z1.SetFormat(COEFFICIENT);
    LWEPrivateKey sk1Nc = std::make_shared<LWEPrivateKeyImpl>(LWEPrivateKeyImpl(z1.GetValues()));
    auto sk1N           = cc.KeyGenN();

    std::cout << "sk1Nc conv modulus " << sk1Nc->GetModulus() << std::endl;
    std::cout << "sk1Nc conv dimension " << sk1Nc->GetLength() << std::endl;

    std::cout << "keygenN modulus " << sk1N->GetModulus() << std::endl;
    std::cout << "keygenN dimension " << sk1N->GetLength() << std::endl;

    auto pk1Nc = cc.PubKeyGen(sk1Nc);
    auto pk1N  = cc.PubKeyGen(sk1N);

    auto ct1Nc = cc.Encrypt(pk1Nc, 1, LARGE_DIM);
    auto ct1N  = cc.Encrypt(pk1N, 1, LARGE_DIM);
    LWEPlaintext result1, result2;

    cc.Decrypt(sk1Nc, ct1Nc, &result1);
    cc.Decrypt(sk1N, ct1N, &result2);

    std::cout << "Result of encrypted computation of 1 direct conv = " << result1 << std::endl;
    std::cout << "Result of encrypted computation of 1 direct= " << result2 << std::endl;

    auto kp = cc.KeyGenPair();

    // LARGE_DIM specifies the dimension of the output ciphertext
    auto ctp = cc.Encrypt(kp->publicKey, 1, LARGE_DIM);

    LWEPlaintext resultp;

    // decryption check before computation
    cc.Decrypt(kp->secretKey, ctp, &resultp);

    std::cout << "keypair Result of encrypted ciphertext of 1 = " << resultp << std::endl;

    return 0;
}
