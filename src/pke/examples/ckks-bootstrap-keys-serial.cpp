//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
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
  Example for serializing and deserializing CKKS bootstrap evaluation keys.
 */

#include "openfhe.h"

// Header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace lbcrypto;

const std::string DATAFOLDER           = "demoData";
const std::string ccLocation           = "/bootstrap-cryptocontext.txt";
const std::string publicKeyLocation    = "/bootstrap-public-key.txt";
const std::string secretKeyLocation    = "/bootstrap-secret-key.txt";
const std::string ciphertextLocation   = "/bootstrap-ciphertext.txt";
const std::string multKeyLocation      = "/bootstrap-eval-mult-keys.txt";
const std::string bootstrapKeyLocation = "/bootstrap-eval-keys.txt";

void ErrorCheck(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << message << std::endl;
        std::exit(1);
    }
}

int main() {
    std::cout << "This program requires the `" << DATAFOLDER << "' directory to exist." << std::endl;

    CCParams<CryptoContextCKKSRNS> parameters;
    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1 << 12);

#if NATIVEINT == 128
    ScalingTechnique rescaleTech = FIXEDAUTO;
    uint32_t dcrtBits            = 78;
    uint32_t firstMod            = 89;
#else
    ScalingTechnique rescaleTech = FLEXIBLEAUTO;
    uint32_t dcrtBits            = 59;
    uint32_t firstMod            = 60;
#endif

    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetFirstModSize(firstMod);

    std::vector<uint32_t> levelBudget      = {4, 4};
    uint32_t levelsAvailableAfterBootstrap = 10;
    uint32_t depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);
    parameters.SetMultiplicativeDepth(depth);

    CryptoContext<DCRTPoly> serverCC = GenCryptoContext(parameters);
    serverCC->Enable(PKE);
    serverCC->Enable(KEYSWITCH);
    serverCC->Enable(LEVELEDSHE);
    serverCC->Enable(ADVANCEDSHE);
    serverCC->Enable(FHE);

    uint32_t numSlots = serverCC->GetRingDimension() / 2;
    serverCC->EvalBootstrapSetup(levelBudget, {0, 0}, numSlots);

    auto keyPair = serverCC->KeyGen();
    serverCC->EvalMultKeyGen(keyPair.secretKey);
    serverCC->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

    std::vector<double> x = {0.25, 0.5, 0.75, 1.0};
    auto plaintext        = serverCC->MakeCKKSPackedPlaintext(x, 1, depth - 1);
    plaintext->SetLength(x.size());
    auto ciphertext = serverCC->Encrypt(keyPair.publicKey, plaintext);

    ErrorCheck(Serial::SerializeToFile(DATAFOLDER + ccLocation, serverCC, SerType::BINARY),
               "Error serializing crypto context");
    ErrorCheck(Serial::SerializeToFile(DATAFOLDER + publicKeyLocation, keyPair.publicKey, SerType::BINARY),
               "Error serializing public key");
    ErrorCheck(Serial::SerializeToFile(DATAFOLDER + secretKeyLocation, keyPair.secretKey, SerType::BINARY),
               "Error serializing secret key");
    ErrorCheck(Serial::SerializeToFile(DATAFOLDER + ciphertextLocation, ciphertext, SerType::BINARY),
               "Error serializing ciphertext");

    std::ofstream multKeyOut(DATAFOLDER + multKeyLocation, std::ios::out | std::ios::binary);
    ErrorCheck(multKeyOut.is_open(), "Error opening eval-mult key output file");
    ErrorCheck(serverCC->SerializeEvalMultKey(multKeyOut, SerType::BINARY), "Error serializing eval-mult keys");
    multKeyOut.close();

    std::ofstream bootstrapKeyOut(DATAFOLDER + bootstrapKeyLocation, std::ios::out | std::ios::binary);
    ErrorCheck(bootstrapKeyOut.is_open(), "Error opening bootstrap eval-key output file");
    ErrorCheck(serverCC->SerializeEvalBootstrapKey(bootstrapKeyOut, SerType::BINARY, serverCC,
                                                   keyPair.secretKey->GetKeyTag(), numSlots),
               "Error serializing bootstrap eval keys");
    bootstrapKeyOut.close();

    serverCC->ClearEvalMultKeys();
    serverCC->ClearEvalAutomorphismKeys();
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();

    CryptoContext<DCRTPoly> clientCC;
    PublicKey<DCRTPoly> publicKey;
    PrivateKey<DCRTPoly> secretKey;
    Ciphertext<DCRTPoly> clientCiphertext;

    ErrorCheck(Serial::DeserializeFromFile(DATAFOLDER + ccLocation, clientCC, SerType::BINARY),
               "Error deserializing crypto context");
    ErrorCheck(Serial::DeserializeFromFile(DATAFOLDER + publicKeyLocation, publicKey, SerType::BINARY),
               "Error deserializing public key");
    ErrorCheck(Serial::DeserializeFromFile(DATAFOLDER + secretKeyLocation, secretKey, SerType::BINARY),
               "Error deserializing secret key");
    ErrorCheck(Serial::DeserializeFromFile(DATAFOLDER + ciphertextLocation, clientCiphertext, SerType::BINARY),
               "Error deserializing ciphertext");
    clientCC->EvalBootstrapSetup(levelBudget, {0, 0}, numSlots);
    const auto bootstrapKeyIndices = clientCC->GetScheme()->EvalBootstrapKeyMapIndices(clientCC, numSlots);

    std::ifstream multKeyIn(DATAFOLDER + multKeyLocation, std::ios::in | std::ios::binary);
    ErrorCheck(multKeyIn.is_open(), "Error opening eval-mult key input file");
    ErrorCheck(clientCC->DeserializeEvalMultKey(multKeyIn, SerType::BINARY), "Error deserializing eval-mult keys");
    multKeyIn.close();

    std::ifstream bootstrapKeyIn(DATAFOLDER + bootstrapKeyLocation, std::ios::in | std::ios::binary);
    ErrorCheck(bootstrapKeyIn.is_open(), "Error opening bootstrap eval-key input file");
    ErrorCheck(clientCC->DeserializeEvalBootstrapKey(bootstrapKeyIn, SerType::BINARY, clientCC,
                                                     secretKey->GetKeyTag(), numSlots),
               "Error deserializing bootstrap eval keys");
    bootstrapKeyIn.close();

    std::ifstream bootstrapKeyInByIndex(DATAFOLDER + bootstrapKeyLocation, std::ios::in | std::ios::binary);
    ErrorCheck(bootstrapKeyInByIndex.is_open(), "Error opening bootstrap eval-key input file");
    ErrorCheck(clientCC->DeserializeEvalBootstrapKey(bootstrapKeyInByIndex, SerType::BINARY, secretKey->GetKeyTag(),
                                                     bootstrapKeyIndices),
               "Error deserializing bootstrap eval keys by index list");
    bootstrapKeyInByIndex.close();

    auto ciphertextAfter = clientCC->EvalBootstrap(clientCiphertext);

    Plaintext result;
    clientCC->Decrypt(secretKey, ciphertextAfter, &result);
    result->SetLength(x.size());

    std::cout << "Input: " << plaintext << std::endl;
    std::cout << "Output after deserialized-key bootstrapping: " << result << std::endl;

    clientCC->ClearStaticMapsAndVectors();

    return 0;
}
