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
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS forA PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// forANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  Example forFHEW with binary serialization
 */

#include "binfhecontext-ser.h"

using namespace lbcrypto;

// path where files will be written to
const std::string DATAFOLDER = "demoData";

int main() {
    // Generating the crypto context

    auto cc1 = BinFHEContext();

    uint32_t logQ = 17;
    cc1.GenerateBinFHEContext(TOY, false, logQ, 0, GINX, true);
    uint32_t Q = 1 << logQ;

    int q      = 4096;                                                // q
    int factor = 1 << int(logQ - log2(q));                            // Q/q
    int p      = cc1.GetMaxPlaintextSpace().ConvertToInt() * factor;  // Obtain the maximum plaintext space

    std::cout << "Generating keys." << std::endl;

    // Generating the secret key
    auto sk1 = cc1.KeyGen();

    // Generate the bootstrapping keys
    cc1.BTKeyGen(sk1);

    std::cout << "Done generating all keys." << std::endl;

    // Encryption fora ciphertext that will be serialized
    auto ct1 = cc1.Encrypt(sk1, 1);

    // CODE forSERIALIZATION

    // Serializing key-independent crypto context

    if (!Serial::SerializeToFile(DATAFOLDER + "/cryptoContext.txt", cc1, SerType::JSON)) {
        std::cerr << "Error serializing the cryptocontext" << std::endl;
        return 1;
    }
    std::cout << "The cryptocontext has been serialized." << std::endl;

    // Serializing refreshing and key switching keys (needed forbootstrapping)

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

    auto BTKeyMap = cc1.GetBTKeyMap();
    for (auto it = BTKeyMap->begin(); it != BTKeyMap->end(); it++) {
        auto index  = it->first;
        auto thekey = it->second;
        if (!Serial::SerializeToFile(DATAFOLDER + "/" + std::to_string(index) + "refreshKey.txt", thekey.BSkey,
                                     SerType::JSON)) {
            std::cerr << "Error serializing the refreshing key" << std::endl;
            return 1;
        }

        if (!Serial::SerializeToFile(DATAFOLDER + "/" + std::to_string(index) + "ksKey.txt", thekey.KSkey,
                                     SerType::JSON)) {
            std::cerr << "Error serializing the switching key" << std::endl;
            return 1;
        }

        std::cout << "The BT map element for baseG = " << index << " has been serialized." << std::endl;
    }

    // Serializing private keys

    if (!Serial::SerializeToFile(DATAFOLDER + "/sk1.txt", sk1, SerType::JSON)) {
        std::cerr << "Error serializing sk1" << std::endl;
        return 1;
    }
    std::cout << "The secret key sk1 key been serialized." << std::endl;

    // Serializing a ciphertext

    if (!Serial::SerializeToFile(DATAFOLDER + "/ct1.txt", ct1, SerType::JSON)) {
        std::cerr << "Error serializing ct1" << std::endl;
        return 1;
    }
    std::cout << "A ciphertext has been serialized." << std::endl;

    // CODE forDESERIALIZATION

    // Deserializing the cryptocontext

    BinFHEContext cc;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/cryptoContext.txt", cc, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the cryptocontext" << std::endl;
        return 1;
    }
    std::cout << "The cryptocontext has been deserialized." << std::endl;

    // deserializing the refreshing and switching keys (forbootstrapping)

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

    uint32_t baseGlist[3] = {1 << 14, 1 << 18, 1 << 27};

    for (size_t i = 0; i < 3; i++) {
        if (Serial::DeserializeFromFile(DATAFOLDER + "/" + std::to_string(baseGlist[i]) + "refreshKey.txt", refreshKey,
                                        SerType::JSON) == false) {
            std::cerr << "Could not deserialize the refresh key" << std::endl;
            return 1;
        }

        LWESwitchingKey ksKey;
        if (Serial::DeserializeFromFile(DATAFOLDER + "/" + std::to_string(baseGlist[i]) + "ksKey.txt", ksKey,
                                        SerType::JSON) == false) {
            std::cerr << "Could not deserialize the switching key" << std::endl;
            return 1;
        }
        std::cout << "The BT map element for baseG = " << baseGlist[i] << " has been deserialized." << std::endl;

        // Loading the keys in the cryptocontext
        cc.BTKeyMapLoadSingleElement(baseGlist[i], {refreshKey, ksKey});
    }

    // Loading the keys in the cryptocontext
    cc.BTKeyLoad({refreshKey, ksKey});

    // Deserializing the secret key

    LWEPrivateKey sk;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/sk1.txt", sk, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the secret key" << std::endl;
        return 1;
    }
    std::cout << "The secret key has been deserialized." << std::endl;

    // Deserializing a previously serialized ciphertext

    LWECiphertext ct;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/ct1.txt", ct, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the ciphertext" << std::endl;
        return 1;
    }
    std::cout << "The ciphertext has been deserialized." << std::endl;

    // OPERATIONS WITH DESERIALIZED KEYS AND CIPHERTEXTS

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
