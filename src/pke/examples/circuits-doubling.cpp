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
  Doubling circuit example
 */

#include "openfhe.h"

#include <string>
#include <fstream>
#include <streambuf>

using namespace lbcrypto;

const std::string DATAFOLDER = "demoData";

int main() {
    // Sample Program: Set CryptoContext
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetRingDim(8192);

    std::string fileName = DATAFOLDER + "/doubling.tsv";

    std::cout << "circuit used during parameter/key generation = " << fileName << std::endl;

    std::ifstream file(fileName);
    std::string circuit((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    parameters.SetEvalCircuit(circuit);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    std::cout << "Crypto Parameters: " << *cryptoContext->GetCryptoParameters() << std::endl;

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    std::cout << "\nValidating addition circuit" << std::endl;

    std::string fileNameValidate = DATAFOLDER + "/addition.tsv";
    std::ifstream fileValidate(fileNameValidate);
    std::string circuitAddition((std::istreambuf_iterator<char>(fileValidate)), std::istreambuf_iterator<char>());

    cryptoContext->ValidateCircuit(circuitAddition);

    std::cout << "\nValidating doubling circuit" << std::endl;

    std::string fileNameValidate2 = DATAFOLDER + "/doubling.tsv";
    std::ifstream fileValidate2(fileNameValidate2);
    std::string circuitDoubling((std::istreambuf_iterator<char>(fileValidate2)), std::istreambuf_iterator<char>());

    cryptoContext->ValidateCircuit(circuitDoubling);

    // Sample Program: Encryption

    // First plaintext vector is encoded
    std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    Plaintext plaintext1               = cryptoContext->MakePackedPlaintext(vectorOfInts1);

    // Ciphertext for the addition circuit
    size_t count = count_lines(circuitAddition);
    std::vector<Ciphertext<DCRTPoly>> vecCtxt(count);
    for (size_t i = 0; i < count; i++) {
        vecCtxt[i] = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    }

    // Ciphertext for the doubling circuit
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);

    std::cout << "\nEvaluating addition circuit" << std::endl;

    // Homomorphic additions for addition
    auto ciphertextAddResult1 = cryptoContext->EvaluateCircuit(circuitAddition, vecCtxt);

    std::cout << "\nEvaluating doubling circuit" << std::endl;

    // Homomorphic additions for doubling
    auto ciphertextAddResult2 = cryptoContext->EvaluateCircuit(circuitDoubling, {ciphertext1});

    std::cout << "\nPlaintext #1: " << plaintext1 << std::endl;

    if (ciphertextAddResult1 != nullptr) {
        // Decrypt the result of additions
        Plaintext plaintextAddResult;
        cryptoContext->Decrypt(keyPair.secretKey, ciphertextAddResult1, &plaintextAddResult);

        // Output results
        std::cout << "\nResult of addition circuit" << std::endl;
        std::cout << "44 additions mod t: " << plaintextAddResult << std::endl;
    }

    if (ciphertextAddResult2 != nullptr) {
        // Decrypt the result of additions
        Plaintext plaintextAddResult;
        cryptoContext->Decrypt(keyPair.secretKey, ciphertextAddResult2, &plaintextAddResult);

        // Output results
        std::cout << "\nResult of doubling circuit" << std::endl;
        std::cout << "44 additions mod t: " << plaintextAddResult << std::endl;
    }

    return 0;
}
