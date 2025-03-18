//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2025, Duality Technologies Inc. and other contributors
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
 Example for Interactive Bootstrapping
*/

#include "openfhe.h"

#include <memory>
#include <map>
#include <vector>
#include <iostream>

using namespace lbcrypto;

void Decrypt();
void Encrypt();

int main(int argc, char* argv[]) {
    Decrypt();
    Encrypt();
    return 0;
}

void Decrypt() {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(1);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(16);
    parameters.SetScalingTechnique(FIXEDMANUAL);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    // enable features that you wish to use
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);

    std::vector<std::complex<double>> input({-0.9, -0.8, -0.6, -0.4, -0.2, 0., 0.2, 0.4, 0.6, 0.8, 0.9});

    Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(input);

    auto keyPair = cc->KeyGen();

    auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);

    auto sk = keyPair.secretKey;

    auto s = keyPair.secretKey->GetPrivateElement();
    sk->SetPrivateElement(2 * s);

    auto ciphertextOutput = cc->IntBootDecrypt(sk, ciphertext1);

    auto cPolyRNS = ciphertextOutput->GetElements()[0];

    auto cPolyRNSInterpolated = cPolyRNS.CRTInterpolate();

    auto c = ciphertext1->GetElements();

    auto cs = 2 * c[1] * s + c[0];

    cs.SetFormat(Format::COEFFICIENT);

    auto cPoly = cs.CRTInterpolate();

    auto Q       = cPoly.GetModulus();
    auto Qhalf   = Q / 2;
    auto Q1quart = Q / 4;
    auto Q3quart = 3 * Q / 4;

    for (usint i = 0; i < cPoly.GetRingDimension(); i++) {
        if ((cPoly[i] > Q1quart) && (cPoly[i] <= Q3quart)) {
            cPoly[i].ModAdd(Qhalf, Q);
        }
        if (cPoly[i] != cPolyRNSInterpolated[i]) {
            std::cerr << "Mismatch: " << cPoly[i] << " vs " << cPolyRNSInterpolated[i] << std::endl;
        }
    }

    std::cerr << "IntBootDecrypt Succeeded" << std::endl;
}

void Encrypt() {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(1);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(16);
    parameters.SetScalingTechnique(FIXEDMANUAL);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    // enable features that you wish to use
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);

    std::vector<std::complex<double>> input({-0.9, -0.8, -0.6, -0.4, -0.2, 0., 0.2, 0.4, 0.6, 0.8, 0.9});

    Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(input);

    auto keyPair = cc->KeyGen();

    auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);

    ciphertext1 = cc->Compress(ciphertext1, 2);
    std::cerr << "Compress Succeeded" << std::endl;

    auto ciphertextOutput = cc->IntBootDecrypt(keyPair.secretKey, ciphertext1);
    std::cerr << "IntBootDecrypt Succeeded" << std::endl;
    ciphertextOutput = cc->IntBootEncrypt(keyPair.publicKey, ciphertextOutput);
    std::cerr << "IntBootEncrypt Succeeded" << std::endl;

    Plaintext plaintextDec;

    cc->Decrypt(keyPair.secretKey, ciphertextOutput, &plaintextDec);

    std::cerr << "Decrypt Succeeded" << std::endl;

    plaintextDec->SetLength(input.size());

    std::cout << "Original plaintext \n\t" << plaintext1->GetCKKSPackedValue() << std::endl;
    std::cout << "Result after bootstrapping \n\t" << plaintextDec->GetCKKSPackedValue() << std::endl;
}
