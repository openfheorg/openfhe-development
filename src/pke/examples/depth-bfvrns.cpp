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
  Example of a computation circuit of depth 3.
  BFVrns demo for a homomorphic multiplication of depth 6 and three different approaches for depth-3 multiplications
 */

#define PROFILE

#include <iostream>

#include "openfhe.h"

using namespace lbcrypto;

int main(int argc, char* argv[]) {
    ////////////////////////////////////////////////////////////
    // Set-up of parameters
    ////////////////////////////////////////////////////////////

    std::cout << "\nThis code demonstrates the use of the BFVrns scheme for "
                 "homomorphic multiplication. "
              << std::endl;
    std::cout << "This code shows how to auto-generate parameters during run-time "
                 "based on desired plaintext moduli and security levels. "
              << std::endl;
    std::cout << "In this demonstration we use three input plaintext and show "
                 "how to both add them together and multiply them together. "
              << std::endl;

    // benchmarking variables
    TimeVar t;
    double processingTime(0.0);

    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(536903681);
    parameters.SetMultiplicativeDepth(3);
    parameters.SetMaxRelinSkDeg(3);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);

    std::cout << "\np = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2
              << std::endl;
    std::cout << "log2 q = "
              << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    std::cout << "\nRunning key generation (used for source data)..." << std::endl;

    TIC(t);

    keyPair = cryptoContext->KeyGen();

    processingTime = TOC(t);
    std::cout << "Key generation time: " << processingTime << "ms" << std::endl;

    if (!keyPair.good()) {
        std::cout << "Key generation failed!" << std::endl;
        exit(1);
    }

    std::cout << "Running key generation for homomorphic multiplication "
                 "evaluation keys..."
              << std::endl;

    TIC(t);

    cryptoContext->EvalMultKeysGen(keyPair.secretKey);

    processingTime = TOC(t);
    std::cout << "Key generation time for homomorphic multiplication evaluation keys: " << processingTime << "ms"
              << std::endl;

    // cryptoContext->EvalMultKeyGen(keyPair.secretKey);

    ////////////////////////////////////////////////////////////
    // Encode source data
    ////////////////////////////////////////////////////////////

    std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext1               = cryptoContext->MakePackedPlaintext(vectorOfInts1);

    std::vector<int64_t> vectorOfInts2 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext2               = cryptoContext->MakePackedPlaintext(vectorOfInts2);

    std::vector<int64_t> vectorOfInts3 = {2, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext3               = cryptoContext->MakePackedPlaintext(vectorOfInts3);

    std::vector<int64_t> vectorOfInts4 = {2, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext4               = cryptoContext->MakePackedPlaintext(vectorOfInts4);

    std::vector<int64_t> vectorOfInts5 = {3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext5               = cryptoContext->MakePackedPlaintext(vectorOfInts5);

    std::vector<int64_t> vectorOfInts6 = {3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext6               = cryptoContext->MakePackedPlaintext(vectorOfInts6);

    std::vector<int64_t> vectorOfInts7 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext7               = cryptoContext->MakePackedPlaintext(vectorOfInts7);

    std::cout << "\nOriginal Plaintext #1: \n";
    std::cout << plaintext1 << std::endl;

    std::cout << "\nOriginal Plaintext #2: \n";
    std::cout << plaintext2 << std::endl;

    std::cout << "\nOriginal Plaintext #3: \n";
    std::cout << plaintext3 << std::endl;

    std::cout << "\nOriginal Plaintext #4: \n";
    std::cout << plaintext4 << std::endl;

    std::cout << "\nOriginal Plaintext #5: \n";
    std::cout << plaintext5 << std::endl;

    std::cout << "\nOriginal Plaintext #6: \n";
    std::cout << plaintext6 << std::endl;

    std::cout << "\nOriginal Plaintext #7: \n";
    std::cout << plaintext7 << std::endl;

    ////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////

    std::cout << "\nRunning encryption of all plaintexts... ";

    std::vector<Ciphertext<DCRTPoly>> ciphertexts;

    TIC(t);

    ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext1));
    ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext2));
    ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext3));
    ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext4));
    ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext5));
    ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext6));
    ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext7));

    processingTime = TOC(t);

    std::cout << "Completed\n";

    std::cout << "\nAverage encryption time: " << processingTime / 7 << "ms" << std::endl;

    ////////////////////////////////////////////////////////////
    // Homomorphic multiplication of 2 ciphertexts
    ////////////////////////////////////////////////////////////

    TIC(t);

    auto ciphertextMult = cryptoContext->EvalMult(ciphertexts[0], ciphertexts[1]);

    processingTime = TOC(t);
    std::cout << "\nTotal time of multiplying 2 ciphertexts using EvalMult w/ "
                 "relinearization: "
              << processingTime << "ms" << std::endl;

    Plaintext plaintextDecMult;

    TIC(t);

    cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult, &plaintextDecMult);

    processingTime = TOC(t);
    std::cout << "\nDecryption time: " << processingTime << "ms" << std::endl;

    plaintextDecMult->SetLength(plaintext1->GetLength());

    std::cout << "\nResult of homomorphic multiplication of ciphertexts #1 and #2: \n";
    std::cout << plaintextDecMult << std::endl;

    ////////////////////////////////////////////////////////////
    // Homomorphic multiplication of 7 ciphertexts
    ////////////////////////////////////////////////////////////

    std::cout << "\nRunning a binary-tree multiplication of 7 ciphertexts...";

    TIC(t);

    auto ciphertextMult7 = cryptoContext->EvalMultMany(ciphertexts);

    processingTime = TOC(t);

    std::cout << "Completed\n";

    std::cout << "\nTotal time of multiplying 7 ciphertexts using EvalMultMany: " << processingTime << "ms"
              << std::endl;

    Plaintext plaintextDecMult7;

    cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult7, &plaintextDecMult7);

    plaintextDecMult7->SetLength(plaintext1->GetLength());

    std::cout << "\nResult of 6 homomorphic multiplications: \n";
    std::cout << plaintextDecMult7 << std::endl;

    ////////////////////////////////////////////////////////////
    // Homomorphic multiplication of 3 ciphertexts where relinearization is done
    // at the end
    ////////////////////////////////////////////////////////////

    std::cout << "\nRunning a depth-3 multiplication w/o relinearization until the "
                 "very end...";

    TIC(t);

    auto ciphertextMult12 = cryptoContext->EvalMultNoRelin(ciphertexts[0], ciphertexts[1]);

    processingTime = TOC(t);

    std::cout << "Completed\n";

    std::cout << "Time of multiplying 2 ciphertexts w/o relinearization: " << processingTime << "ms" << std::endl;

    auto ciphertextMult123 = cryptoContext->EvalMultAndRelinearize(ciphertextMult12, ciphertexts[2]);

    Plaintext plaintextDecMult123;

    cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult123, &plaintextDecMult123);

    plaintextDecMult123->SetLength(plaintext1->GetLength());

    std::cout << "\nResult of 3 homomorphic multiplications: \n";
    std::cout << plaintextDecMult123 << std::endl;

    ////////////////////////////////////////////////////////////
    // Homomorphic multiplication of 3 ciphertexts w/o any relinearization
    ////////////////////////////////////////////////////////////

    std::cout << "\nRunning a depth-3 multiplication w/o relinearization...";

    ciphertextMult12  = cryptoContext->EvalMultNoRelin(ciphertexts[0], ciphertexts[1]);
    ciphertextMult123 = cryptoContext->EvalMultNoRelin(ciphertextMult12, ciphertexts[2]);

    std::cout << "Completed\n";

    cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult123, &plaintextDecMult123);

    plaintextDecMult123->SetLength(plaintext1->GetLength());

    std::cout << "\nResult of 3 homomorphic multiplications: \n";
    std::cout << plaintextDecMult123 << std::endl;

    ////////////////////////////////////////////////////////////
    // Homomorphic multiplication of 3 ciphertexts w/ relinearization after each
    // multiplication
    ////////////////////////////////////////////////////////////

    std::cout << "\nRunning a depth-3 multiplication w/ relinearization after each "
                 "multiplication...";

    TIC(t);

    ciphertextMult12 = cryptoContext->EvalMult(ciphertexts[0], ciphertexts[1]);

    processingTime = TOC(t);
    std::cout << "Completed\n";
    std::cout << "Time of multiplying 2 ciphertexts w/ relinearization: " << processingTime << "ms" << std::endl;

    ciphertextMult123 = cryptoContext->EvalMult(ciphertextMult12, ciphertexts[2]);

    cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult123, &plaintextDecMult123);

    plaintextDecMult123->SetLength(plaintext1->GetLength());

    std::cout << "\nResult of 3 homomorphic multiplications: \n";
    std::cout << plaintextDecMult123 << std::endl;

    return 0;
}
