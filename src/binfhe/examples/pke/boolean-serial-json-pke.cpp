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
  Example for FHEW with JSON serialization
 */

#include "binfhecontext-ser.h"

using namespace lbcrypto;

// path where files will be written to
const std::string DATAFOLDER = "demoData";

int main() {
    // Generating the crypto context

    auto cc1 = BinFHEContext();

    cc1.GenerateBinFHEContext(TOY);

    std::cout << "Generating keys." << std::endl;

    // Generating the secret key
    auto sk1 = cc1.KeyGen();

    // Generate the bootstrapping keys and public key
    cc1.BTKeyGen(sk1, PUB_ENCRYPT);

    auto pk1 = cc1.GetPublicKey();

    std::cout << "Done generating all keys." << std::endl;

    // Encryption for a ciphertext that will be serialized
    auto ct1 = cc1.Encrypt(pk1, 1);

    // CODE FOR SERIALIZATION

    // Serializing key-independent crypto context

    if (!Serial::SerializeToFile(DATAFOLDER + "/cryptoContext.txt", cc1, SerType::JSON)) {
        std::cerr << "Error serializing the cryptocontext" << std::endl;
        return 1;
    }
    std::cout << "The cryptocontext has been serialized." << std::endl;

    // Serializing refreshing and key switching keys (needed for bootstrapping)

    if (!Serial::SerializeToFile(DATAFOLDER + "/refreshKey.txt", cc1.GetRefreshKey(), SerType::JSON)) {
        std::cerr << "Error serializing the refreshing key" << std::endl;
        return 1;
    }
    std::cout << "The refreshing key has been serialized." << std::endl;

    if (!Serial::SerializeToFile(DATAFOLDER + "/ksKey.txt", cc1.GetSwitchKey(), SerType::JSON)) {
        std::cerr << "Error serializing the switching key" << std::endl;
        return 1;
    }
    std::cout << "The key switching key has been serialized." << std::endl;

    // Serializing private keys

    if (!Serial::SerializeToFile(DATAFOLDER + "/sk1.txt", sk1, SerType::JSON)) {
        std::cerr << "Error serializing sk1" << std::endl;
        return 1;
    }
    std::cout << "The secret key sk1 key been serialized." << std::endl;

    // Serializing public keys

    if (!Serial::SerializeToFile(DATAFOLDER + "/pk1.txt", pk1, SerType::JSON)) {
        std::cerr << "Error serializing pk1" << std::endl;
        return 1;
    }
    std::cout << "The public key pk1 key been serialized." << std::endl;

    // Serializing a ciphertext

    if (!Serial::SerializeToFile(DATAFOLDER + "/ct1.txt", ct1, SerType::JSON)) {
        std::cerr << "Error serializing ct1" << std::endl;
        return 1;
    }
    std::cout << "A ciphertext has been serialized." << std::endl;

    // CODE FOR DESERIALIZATION

    // Deserializing the cryptocontext

    BinFHEContext cc;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/cryptoContext.txt", cc, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the cryptocontext" << std::endl;
        return 1;
    }
    std::cout << "The cryptocontext has been deserialized." << std::endl;

    // deserializing the refreshing and switching keys (for bootstrapping)

    RingGSWACCKey refreshKey;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/refreshKey.txt", refreshKey, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the refresh key" << std::endl;
        return 1;
    }
    std::cout << "The refresh key has been deserialized." << std::endl;

    LWESwitchingKey ksKey;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/ksKey.txt", ksKey, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the switching key" << std::endl;
        return 1;
    }
    std::cout << "The switching key has been deserialized." << std::endl;

    // Loading the keys in the cryptocontext
    cc.BTKeyLoad({refreshKey, ksKey});

    // Deserializing the secret key

    LWEPrivateKey sk;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/sk1.txt", sk, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the secret key" << std::endl;
        return 1;
    }
    std::cout << "The secret key has been deserialized." << std::endl;

    LWEPublicKey pk;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/pk1.txt", pk, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the public key" << std::endl;
        return 1;
    }
    std::cout << "The public key has been deserialized." << std::endl;

    // Deserializing a previously serialized ciphertext

    LWECiphertext ct;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/ct1.txt", ct, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the ciphertext" << std::endl;
        return 1;
    }
    std::cout << "The ciphertext has been deserialized." << std::endl;

    // OPERATIONS WITH DESERIALIZED KEYS AND CIPHERTEXTS

    auto ct2 = cc.Encrypt(pk, 1);

    std::cout << "Running the computation" << std::endl;

    auto ctResult = cc.EvalBinGate(AND, ct, ct2);

    std::cout << "The computation has completed" << std::endl;

    LWEPlaintext result;

    cc.Decrypt(sk, ctResult, &result);

    std::cout << "result of 1 AND 1 = " << result << std::endl;

    return 0;
}
