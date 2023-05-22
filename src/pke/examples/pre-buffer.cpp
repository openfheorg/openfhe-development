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
  Example of Proxy Re-Encryption on a packed vector.
  Example software for multiparty proxy-reencryption of an integer buffer using BFV rns scheme.
 */

#define PROFILE  // for TIC TOC
#include "openfhe.h"

using namespace lbcrypto;

using CT = Ciphertext<DCRTPoly>;  // ciphertext
using PT = Plaintext;             // plaintext

using vecInt  = std::vector<int64_t>;  // vector of ints
using vecChar = std::vector<char>;     // vector of characters

bool run_demo_pre(void);

int main(int argc, char* argv[]) {
    ////////////////////////////////////////////////////////////
    // Set-up of parameters
    ////////////////////////////////////////////////////////////

    bool passed = run_demo_pre();

    if (!passed) {  // there could be an error
        exit(1);
    }
    exit(0);  // successful return
}

bool run_demo_pre(void) {
    // Generate parameters.
    TimeVar t;  // timer for tic toc
    std::cout << "setting up BFV RNS crypto system" << std::endl;
    TIC(t);
    // int plaintextModulus = 786433; //plaintext prime modulus
    int plaintextModulus = 65537;  // can encode shorts

    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(plaintextModulus);
    parameters.SetScalingModSize(60);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    std::cout << "\nParam generation time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    // Turn on features
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(PRE);

    std::cout << "p = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cout << "n = " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
    std::cout << "log2 q = " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;
    std::cout << "r = " << cc->GetCryptoParameters()->GetDigitSize() << std::endl;

    auto ringsize = cc->GetRingDimension();
    std::cout << "Alice can encrypt " << ringsize * 2 << " bytes of data" << std::endl;
    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    // Initialize Key Pair Containers
    KeyPair<DCRTPoly> keyPair1;

    std::cout << "\nRunning Alice key generation (used for source data)..." << std::endl;

    TIC(t);
    keyPair1 = cc->KeyGen();
    std::cout << "Key generation time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;

    if (!keyPair1.good()) {
        std::cout << "Alice Key generation failed!" << std::endl;
        return (false);
    }

    ////////////////////////////////////////////////////////////
    // Encode source data
    ////////////////////////////////////////////////////////////

    unsigned int nshort = ringsize;

    vecInt vShorts;

    for (size_t i = 0; i < nshort; i++)
        vShorts.push_back(std::rand() % 65536);

    PT pt = cc->MakePackedPlaintext(vShorts);

    ////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////

    TIC(t);
    auto ct1 = cc->Encrypt(keyPair1.publicKey, pt);
    std::cout << "Encryption time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;

    ////////////////////////////////////////////////////////////
    // Decryption of Ciphertext
    ////////////////////////////////////////////////////////////

    PT ptDec1;

    TIC(t);
    cc->Decrypt(keyPair1.secretKey, ct1, &ptDec1);
    std::cout << "Decryption time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;

    ptDec1->SetLength(pt->GetLength());

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    // Initialize Key Pair Containers
    KeyPair<DCRTPoly> keyPair2;

    std::cout << "Bob Running key generation ..." << std::endl;

    TIC(t);
    keyPair2 = cc->KeyGen();
    std::cout << "Key generation time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;

    if (!keyPair2.good()) {
        std::cout << "Bob Key generation failed!" << std::endl;
        return (false);
    }

    ////////////////////////////////////////////////////////////
    // Perform the proxy re-encryption key generation operation.
    // This generates the keys which are used to perform the key switching.
    ////////////////////////////////////////////////////////////

    std::cout << "\n"
              << "Generating proxy re-encryption key..." << std::endl;

    EvalKey<DCRTPoly> reencryptionKey12;

    TIC(t);
    reencryptionKey12 = cc->ReKeyGen(keyPair1.secretKey, keyPair2.publicKey);
    std::cout << "Key generation time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;

    ////////////////////////////////////////////////////////////
    // Re-Encryption
    ////////////////////////////////////////////////////////////

    TIC(t);
    auto ct2 = cc->ReEncrypt(ct1, reencryptionKey12);
    std::cout << "Re-Encryption time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;

    ////////////////////////////////////////////////////////////
    // Decryption of Ciphertext
    ////////////////////////////////////////////////////////////

    PT ptDec2;

    TIC(t);
    cc->Decrypt(keyPair2.secretKey, ct2, &ptDec2);
    std::cout << "Decryption time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;

    ptDec2->SetLength(pt->GetLength());

    auto unpacked0 = pt->GetPackedValue();
    auto unpacked1 = ptDec1->GetPackedValue();
    auto unpacked2 = ptDec2->GetPackedValue();
    bool good      = true;

    // note that OpenFHE assumes that plaintext is in the range of -p/2..p/2
    // to recover 0...q simply add q if the unpacked value is negative
    for (unsigned int j = 0; j < pt->GetLength(); j++) {
        if (unpacked1[j] < 0)
            unpacked1[j] += plaintextModulus;
        if (unpacked2[j] < 0)
            unpacked2[j] += plaintextModulus;
    }

    // compare all the results for correctness
    for (unsigned int j = 0; j < pt->GetLength(); j++) {
        if ((unpacked0[j] != unpacked1[j]) || (unpacked0[j] != unpacked2[j])) {
            std::cout << j << ", " << unpacked0[j] << ", " << unpacked1[j] << ", " << unpacked2[j] << std::endl;
            good = false;
        }
    }
    if (good) {
        std::cout << "PRE passes" << std::endl;
    }
    else {
        std::cout << "PRE fails" << std::endl;
    }

    ////////////////////////////////////////////////////////////
    // Done
    ////////////////////////////////////////////////////////////

    std::cout << "Execution Completed." << std::endl;

    return good;
}
