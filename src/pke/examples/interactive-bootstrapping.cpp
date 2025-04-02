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
 Examples for 2-party Interactive Bootstrapping
*/

#include "openfhe.h"

#include <memory>
#include <map>
#include <vector>
#include <iostream>

using namespace lbcrypto;

void ThresholdFHE(enum ScalingTechnique rescaleTech);
void Chebyshev(enum ScalingTechnique rescaleTech);

int main(int argc, char* argv[]) {
    // the scaling technigue can be changed to FIXEDMANUAL, FIXEDAUTO, or FLEXIBLEAUTOEXT
    ThresholdFHE(FLEXIBLEAUTO);
    Chebyshev(FLEXIBLEAUTO);
    return 0;
}

void ThresholdFHE(enum ScalingTechnique rescaleTech) {
    std::cout << "\nThreshold FHE example " << rescaleTech << std::endl;

    CCParams<CryptoContextCKKSRNS> parameters;

    // 1 extra level needs to be added for FIXED* modes (2 extra levels for FLEXIBLE* modes) to the multiplicative depth
    // to support 2-party interactive bootstrapping
    uint32_t depth = 7;
    parameters.SetMultiplicativeDepth(depth);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(16);
    parameters.SetScalingTechnique(rescaleTech);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    // enable features that you wish to use
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> kp1;
    KeyPair<DCRTPoly> kp2;

    KeyPair<DCRTPoly> kpMultiparty;

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    std::cout << "Running key generation (used for source data)..." << std::endl;

    // Round 1 (party A)

    std::cout << "Round 1 (party A) started." << std::endl;

    kp1 = cc->KeyGen();

    // Generate evalmult key part for A
    auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);

    std::cout << "Round 1 of key generation completed." << std::endl;

    // Round 2 (party B)

    std::cout << "Round 2 (party B) started." << std::endl;

    std::cout << "Joint public key for (s_a + s_b) is generated..." << std::endl;
    kp2 = cc->MultipartyKeyGen(kp1.publicKey);

    std::vector<std::complex<double>> input({-0.9, -0.8, -0.6, -0.4, -0.2, 0., 0.2, 0.4, 0.6, 0.8, 0.9});

    // This plaintext only has 3 RNS limbs, the minimum needed to perform 2-party interactive bootstrapping
    // for FLEXIBLEAUTO
    Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(input, 1, depth - 2);

    auto ciphertext1 = cc->Encrypt(kp2.publicKey, plaintext1);

    // INTERACTIVE BOOTSTRAPPING STARTS

    // under the hood it reduces to two towers
    ciphertext1 = cc->IntBootAdjustScale(ciphertext1);
    std::cout << "IntBootAdjustScale Succeeded" << std::endl;

    // masked decryption on the server: c0 = b + a*s0
    auto ciphertextOutput1 = cc->IntBootDecrypt(kp1.secretKey, ciphertext1);
    std::cout << "IntBootDecrypt on Server Succeeded" << std::endl;

    auto ciphertext2 = ciphertext1->Clone();
    ciphertext2->SetElements({ciphertext2->GetElements()[1]});

    // masked decryption on the client: c1 = a*s1
    auto ciphertextOutput2 = cc->IntBootDecrypt(kp2.secretKey, ciphertext2);
    std::cout << "IntBootDecrypt on Client Succeeded" << std::endl;

    // Encryption of masked decryption c1 = a*s1
    ciphertextOutput2 = cc->IntBootEncrypt(kp2.publicKey, ciphertextOutput2);
    std::cout << "IntBootEncrypt on Client Succeeded" << std::endl;

    // Compute Enc(c1) + c0
    auto ciphertextOutput = cc->IntBootAdd(ciphertextOutput2, ciphertextOutput1);
    std::cout << "IntBootAdd on Server Succeeded" << std::endl;

    // INTERACTIVE BOOTSTRAPPING ENDS

    // distributed decryption

    auto ciphertextPartial1 = cc->MultipartyDecryptLead({ciphertextOutput}, kp1.secretKey);

    auto ciphertextPartial2 = cc->MultipartyDecryptMain({ciphertextOutput}, kp2.secretKey);

    std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
    partialCiphertextVec.push_back(ciphertextPartial1[0]);
    partialCiphertextVec.push_back(ciphertextPartial2[0]);

    Plaintext plaintextMultiparty;

    cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultiparty);

    plaintextMultiparty->SetLength(input.size());

    std::cout << "Original plaintext \n\t" << plaintext1->GetCKKSPackedValue() << std::endl;
    std::cout << "Result after bootstrapping \n\t" << plaintextMultiparty->GetCKKSPackedValue() << std::endl;
}

void Chebyshev(enum ScalingTechnique rescaleTech) {
    std::cout << "\nThreshold FHE example " << rescaleTech << std::endl;

    CCParams<CryptoContextCKKSRNS> parameters;

    // 1 extra level needs to be added for FIXED* modes (2 extra levels for FLEXIBLE* modes) to the multiplicative depth
    // to support 2-party interactive bootstrapping
    parameters.SetMultiplicativeDepth(8);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(16);
    parameters.SetScalingTechnique(rescaleTech);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    // enable features that you wish to use
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> kp1;
    KeyPair<DCRTPoly> kp2;

    KeyPair<DCRTPoly> kpMultiparty;

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    std::cout << "Running key generation (used for source data)..." << std::endl;

    // Round 1 (party A)

    std::cout << "Round 1 (party A) started." << std::endl;

    kp1 = cc->KeyGen();

    // Generate evalmult key part for A
    auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);

    // Generate evalsum key part for A
    cc->EvalSumKeyGen(kp1.secretKey);
    auto evalSumKeys =
        std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));

    std::cout << "Round 1 of key generation completed." << std::endl;

    // Round 2 (party B)

    std::cout << "Round 2 (party B) started." << std::endl;

    std::cout << "Joint public key for (s_a + s_b) is generated..." << std::endl;
    kp2 = cc->MultipartyKeyGen(kp1.publicKey);

    auto evalMultKey2 = cc->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);

    std::cout << "Joint evaluation multiplication key for (s_a + s_b) is generated..." << std::endl;
    auto evalMultAB = cc->MultiAddEvalKeys(evalMultKey, evalMultKey2, kp2.publicKey->GetKeyTag());

    std::cout << "Joint evaluation multiplication key (s_a + s_b) is transformed "
                 "into s_b*(s_a + s_b)..."
              << std::endl;
    auto evalMultBAB = cc->MultiMultEvalKey(kp2.secretKey, evalMultAB, kp2.publicKey->GetKeyTag());

    auto evalSumKeysB = cc->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys, kp2.publicKey->GetKeyTag());

    std::cout << "Joint evaluation summation key for (s_a + s_b) is generated..." << std::endl;
    auto evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB, kp2.publicKey->GetKeyTag());

    cc->InsertEvalSumKey(evalSumKeysJoin);

    std::cout << "Round 2 of key generation completed." << std::endl;

    std::cout << "Round 3 (party A) started." << std::endl;

    std::cout << "Joint key (s_a + s_b) is transformed into s_a*(s_a + s_b)..." << std::endl;
    auto evalMultAAB = cc->MultiMultEvalKey(kp1.secretKey, evalMultAB, kp2.publicKey->GetKeyTag());

    std::cout << "Computing the final evaluation multiplication key for (s_a + "
                 "s_b)*(s_a + s_b)..."
              << std::endl;
    auto evalMultFinal = cc->MultiAddEvalMultKeys(evalMultAAB, evalMultBAB, evalMultAB->GetKeyTag());

    cc->InsertEvalMultKey({evalMultFinal});

    std::cout << "Round 3 of key generation completed." << std::endl;

    std::vector<std::complex<double>> input({-4.0, -3.0, -2.0, -1.0, 0.0, 1.0, 2.0, 3.0, 4.0});

    std::vector<double> coefficients({1.0, 0.558971, 0.0, -0.0943712, 0.0, 0.0215023, 0.0, -0.00505348, 0.0, 0.00119324,
                                      0.0, -0.000281928, 0.0, 0.0000664347, 0.0, -0.0000148709});

    double a = -4;
    double b = 4;

    Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(input);

    auto ciphertext1 = cc->Encrypt(kp2.publicKey, plaintext1);

    // The Chebyshev series interpolation requires 6 levels
    ciphertext1 = cc->EvalChebyshevSeries(ciphertext1, coefficients, a, b);
    std::cout << "Ran Chebyshev interpolation" << std::endl;

    // INTERACTIVE BOOTSTRAPPING STARTS

    ciphertext1 = cc->IntBootAdjustScale(ciphertext1);
    std::cout << "IntBootAdjustScale Succeeded" << std::endl;

    // masked decryption on the server: c0 = b + a*s0
    auto ciphertextOutput1 = cc->IntBootDecrypt(kp1.secretKey, ciphertext1);
    std::cout << "IntBootDecrypt on Server Succeeded" << std::endl;

    auto ciphertext2 = ciphertext1->Clone();
    ciphertext2->SetElements({ciphertext2->GetElements()[1]});

    // masked decryption on the client: c1 = a*s1
    auto ciphertextOutput2 = cc->IntBootDecrypt(kp2.secretKey, ciphertext2);
    std::cout << "IntBootDecrypt on Client Succeeded" << std::endl;

    // Encryption of masked decryption c1 = a*s1
    ciphertextOutput2 = cc->IntBootEncrypt(kp2.publicKey, ciphertextOutput2);
    std::cout << "IntBootEncrypt on Client Succeeded" << std::endl;

    // Compute Enc(c1) + c0
    auto ciphertextOutput = cc->IntBootAdd(ciphertextOutput2, ciphertextOutput1);
    std::cout << "IntBootAdd on Server Succeeded" << std::endl;

    // INTERACTIVE BOOTSTRAPPING ENDS

    // distributed decryption

    auto ciphertextPartial1 = cc->MultipartyDecryptLead({ciphertextOutput}, kp1.secretKey);

    auto ciphertextPartial2 = cc->MultipartyDecryptMain({ciphertextOutput}, kp2.secretKey);

    std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
    partialCiphertextVec.push_back(ciphertextPartial1[0]);
    partialCiphertextVec.push_back(ciphertextPartial2[0]);

    Plaintext plaintextMultiparty;

    cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultiparty);

    plaintextMultiparty->SetLength(input.size());

    std::cout << "\n Original Plaintext #1: \n";
    std::cout << plaintext1 << std::endl;

    std::cout << "\n Results of evaluating the polynomial with coefficients " << coefficients << " \n";
    std::cout << "\n Ciphertext result:" << plaintextMultiparty << std::endl;

    std::cout
        << "\n Plaintext result: ( 0.0179885, 0.0474289, 0.119205, 0.268936, 0.5, 0.731064, 0.880795, 0.952571, 0.982011 ) \n";

    std::cout
        << "\n Exact result: ( 0.0179862, 0.0474259, 0.119203, 0.268941, 0.5, 0.731059, 0.880797, 0.952574, 0.982014 ) \n";

    std::cout << "\n Another round of Chebyshev interpolation after interactive bootstrapping: \n";

    ciphertextOutput = cc->EvalChebyshevSeries(ciphertextOutput, coefficients, a, b);
    std::cout << "Ran Chebyshev interpolation" << std::endl;

    // distributed decryption

    ciphertextPartial1 = cc->MultipartyDecryptLead({ciphertextOutput}, kp1.secretKey);

    ciphertextPartial2 = cc->MultipartyDecryptMain({ciphertextOutput}, kp2.secretKey);

    partialCiphertextVec.resize(0);
    partialCiphertextVec.push_back(ciphertextPartial1[0]);
    partialCiphertextVec.push_back(ciphertextPartial2[0]);

    cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultiparty);

    plaintextMultiparty->SetLength(input.size());

    std::cout << "\n Ciphertext result:" << plaintextMultiparty << std::endl;

    std::cout
        << "\n Plaintext result: ( 0.504497, 0.511855, 0.529766, 0.566832, 0.622459, 0.675039, 0.706987, 0.721632, 0.727508 ) \n";
}
