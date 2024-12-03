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
  Examples of threshold FHE for BGVrns, BFVrns and CKKS
 */

#include "openfhe.h"

using namespace lbcrypto;

void RunBFVrns();
void EvalNoiseBFV(PrivateKey<DCRTPoly> privateKey, ConstCiphertext<DCRTPoly> ciphertext, Plaintext ptxt, usint ptm,
                  double& noise, double& logQ, EncryptionTechnique encMethod);

int main(int argc, char* argv[]) {
    std::cout << "\n=================RUNNING FOR BFVrns=====================" << std::endl;

    RunBFVrns();

    return 0;
}

void RunBFVrns() {
    int plaintextModulus                  = 65537;
    double sigma                          = 3.2;
    lbcrypto::SecurityLevel securityLevel = lbcrypto::SecurityLevel::HEStd_128_classic;

    usint batchSize = 16;
    usint multDepth = 4;
    usint digitSize = 30;
    usint dcrtBits  = 60;

    lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> parameters;

    parameters.SetPlaintextModulus(plaintextModulus);
    parameters.SetSecurityLevel(securityLevel);
    parameters.SetStandardDeviation(sigma);
    parameters.SetSecretKeyDist(UNIFORM_TERNARY);
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetBatchSize(batchSize);
    parameters.SetDigitSize(digitSize);
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetMultiplicationTechnique(HPSPOVERQLEVELED);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    // enable features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);

    ////////////////////////////////////////////////////////////
    // Set-up of parameters
    ////////////////////////////////////////////////////////////

    // Output the generated parameters
    std::cout << "p = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cout << "n = " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
    std::cout << "log2 q = " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;

    // Initialize Public Key Containers for two parties A and B
    KeyPair<DCRTPoly> kp1;
    KeyPair<DCRTPoly> kp2;

    KeyPair<DCRTPoly> kpMultiparty;

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    std::cout << "Running key generation (used for source data)..." << std::endl;

    // Round 1 (party A)

    std::cout << "Round 1 (party A) started." << std::endl;

    kp1      = cc->KeyGen();
    kp2      = cc->MultipartyKeyGen(kp1.publicKey);
    auto kp3 = cc->MultipartyKeyGen(kp2.publicKey);
    auto kp4 = cc->MultipartyKeyGen(kp3.publicKey);
    auto kp5 = cc->MultipartyKeyGen(kp4.publicKey);

    // Generate evalmult key part for A
    auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);

    auto evalMultKey2 = cc->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);

    auto evalMultKey3 = cc->MultiKeySwitchGen(kp3.secretKey, kp3.secretKey, evalMultKey);

    auto evalMultKey4 = cc->MultiKeySwitchGen(kp4.secretKey, kp4.secretKey, evalMultKey);

    auto evalMultKey5 = cc->MultiKeySwitchGen(kp5.secretKey, kp5.secretKey, evalMultKey);

    auto evalMultAB = cc->MultiAddEvalKeys(evalMultKey, evalMultKey2, kp2.publicKey->GetKeyTag());

    auto evalMultABC = cc->MultiAddEvalKeys(evalMultAB, evalMultKey3, kp3.publicKey->GetKeyTag());

    auto evalMultABCD = cc->MultiAddEvalKeys(evalMultABC, evalMultKey4, kp4.publicKey->GetKeyTag());

    auto evalMultABCDE = cc->MultiAddEvalKeys(evalMultABCD, evalMultKey5, kp5.publicKey->GetKeyTag());

    auto evalMultEABCDE = cc->MultiMultEvalKey(kp5.secretKey, evalMultABCDE, kp5.publicKey->GetKeyTag());

    auto evalMultDABCDE = cc->MultiMultEvalKey(kp4.secretKey, evalMultABCDE, kp5.publicKey->GetKeyTag());

    auto evalMultCABCDE = cc->MultiMultEvalKey(kp3.secretKey, evalMultABCDE, kp5.publicKey->GetKeyTag());

    auto evalMultBABCDE = cc->MultiMultEvalKey(kp2.secretKey, evalMultABCDE, kp5.publicKey->GetKeyTag());

    auto evalMultAABCDE = cc->MultiMultEvalKey(kp1.secretKey, evalMultABCDE, kp5.publicKey->GetKeyTag());

    auto evalMultDEABCDE = cc->MultiAddEvalMultKeys(evalMultEABCDE, evalMultDABCDE, evalMultEABCDE->GetKeyTag());

    auto evalMultCDEABCDE = cc->MultiAddEvalMultKeys(evalMultCABCDE, evalMultDEABCDE, evalMultCABCDE->GetKeyTag());

    auto evalMultBCDEABCDE = cc->MultiAddEvalMultKeys(evalMultBABCDE, evalMultCDEABCDE, evalMultBABCDE->GetKeyTag());

    auto evalMultFinal = cc->MultiAddEvalMultKeys(evalMultAABCDE, evalMultBCDEABCDE, kp5.publicKey->GetKeyTag());
    cc->InsertEvalMultKey({evalMultFinal});

    //---------------------------------------------------
    std::cout << "Running evalsum key generation (used for source data)..." << std::endl;
    // Generate evalsum key part for A
    cc->EvalSumKeyGen(kp1.secretKey);
    auto evalSumKeys =
        std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));

    auto evalSumKeysB = cc->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys, kp2.publicKey->GetKeyTag());

    auto evalSumKeysC = cc->MultiEvalSumKeyGen(kp3.secretKey, evalSumKeys, kp3.publicKey->GetKeyTag());

    auto evalSumKeysD = cc->MultiEvalSumKeyGen(kp4.secretKey, evalSumKeys, kp4.publicKey->GetKeyTag());

    auto evalSumKeysE = cc->MultiEvalSumKeyGen(kp5.secretKey, evalSumKeys, kp5.publicKey->GetKeyTag());

    auto evalSumKeysAB = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB, kp2.publicKey->GetKeyTag());

    auto evalSumKeysABC = cc->MultiAddEvalSumKeys(evalSumKeysC, evalSumKeysAB, kp3.publicKey->GetKeyTag());

    auto evalSumKeysABCD = cc->MultiAddEvalSumKeys(evalSumKeysABC, evalSumKeysD, kp4.publicKey->GetKeyTag());

    auto evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeysE, evalSumKeysABCD, kp5.publicKey->GetKeyTag());

    cc->InsertEvalSumKey(evalSumKeysJoin);

    ////////////////////////////////////////////////////////////
    // Encode source data
    ////////////////////////////////////////////////////////////
    std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1, 0};
    std::vector<int64_t> vectorOfInts2 = {1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0};
    std::vector<int64_t> vectorOfInts3 = {2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0};

    Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
    Plaintext plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);
    Plaintext plaintext3 = cc->MakePackedPlaintext(vectorOfInts3);

    ////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////

    Ciphertext<DCRTPoly> ciphertext1;
    Ciphertext<DCRTPoly> ciphertext2;
    Ciphertext<DCRTPoly> ciphertext3;

    ciphertext1 = cc->Encrypt(kp5.publicKey, plaintext1);
    ciphertext2 = cc->Encrypt(kp5.publicKey, plaintext2);
    ciphertext3 = cc->Encrypt(kp5.publicKey, plaintext3);

    ////////////////////////////////////////////////////////////
    // Homomorphic Operations
    ////////////////////////////////////////////////////////////

    Ciphertext<DCRTPoly> ciphertextAdd12;
    Ciphertext<DCRTPoly> ciphertextAdd123;

    ciphertextAdd12  = cc->EvalAdd(ciphertext1, ciphertext2);
    ciphertextAdd123 = cc->EvalAdd(ciphertextAdd12, ciphertext3);

    auto ciphertextMult1 = cc->EvalMult(ciphertext1, ciphertext1);
    auto ciphertextMult2 = cc->EvalMult(ciphertextMult1, ciphertext1);
    auto ciphertextMult3 = cc->EvalMult(ciphertextMult2, ciphertext1);
    auto ciphertextMult  = cc->EvalMult(ciphertextMult3, ciphertext1);

    auto ciphertextEvalSum = cc->EvalSum(ciphertext3, batchSize);

    ////////////////////////////////////////////////////////////
    // Decryption after Accumulation Operation on Encrypted Data with Multiparty
    ////////////////////////////////////////////////////////////

    Plaintext plaintextAddNew1;
    Plaintext plaintextAddNew2;
    Plaintext plaintextAddNew3;

    DCRTPoly partialPlaintext1;
    DCRTPoly partialPlaintext2;
    DCRTPoly partialPlaintext3;

    Plaintext plaintextMultipartyNew;

    const std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams = kp1.secretKey->GetCryptoParameters();
    const std::shared_ptr<typename DCRTPoly::Params> elementParams     = cryptoParams->GetElementParams();

    // Distributed decryption
    // partial decryption by party A
    auto ciphertextPartial1 = cc->MultipartyDecryptLead({ciphertextAdd123}, kp1.secretKey);

    // partial decryption by party B
    auto ciphertextPartial2 = cc->MultipartyDecryptMain({ciphertextAdd123}, kp2.secretKey);

    // partial decryption by party C
    auto ciphertextPartial3 = cc->MultipartyDecryptMain({ciphertextAdd123}, kp3.secretKey);

    // partial decryption by party D
    auto ciphertextPartial4 = cc->MultipartyDecryptMain({ciphertextAdd123}, kp4.secretKey);

    // partial decryption by party E
    auto ciphertextPartial5 = cc->MultipartyDecryptMain({ciphertextAdd123}, kp5.secretKey);

    std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
    partialCiphertextVec.push_back(ciphertextPartial1[0]);
    partialCiphertextVec.push_back(ciphertextPartial2[0]);
    partialCiphertextVec.push_back(ciphertextPartial3[0]);
    partialCiphertextVec.push_back(ciphertextPartial4[0]);
    partialCiphertextVec.push_back(ciphertextPartial5[0]);

    // Two partial decryptions are combined
    cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);

    std::cout << "\n Original Plaintext: \n" << std::endl;
    std::cout << plaintext1 << std::endl;
    std::cout << plaintext2 << std::endl;
    std::cout << plaintext3 << std::endl;

    plaintextMultipartyNew->SetLength(plaintext1->GetLength());

    std::cout << "\n Resulting Fused Plaintext: \n" << std::endl;
    std::cout << plaintextMultipartyNew << std::endl;

    std::cout << "\n";

    Plaintext plaintextMultipartyMult;

    ciphertextPartial1 = cc->MultipartyDecryptLead({ciphertextMult}, kp1.secretKey);

    ciphertextPartial2 = cc->MultipartyDecryptMain({ciphertextMult}, kp2.secretKey);

    // partial decryption by party C
    ciphertextPartial3 = cc->MultipartyDecryptMain({ciphertextMult}, kp3.secretKey);

    // partial decryption by party D
    ciphertextPartial4 = cc->MultipartyDecryptMain({ciphertextMult}, kp4.secretKey);

    // partial decryption by party E
    ciphertextPartial5 = cc->MultipartyDecryptMain({ciphertextMult}, kp5.secretKey);

    std::vector<Ciphertext<DCRTPoly>> partialCiphertextVecMult;
    partialCiphertextVecMult.push_back(ciphertextPartial1[0]);
    partialCiphertextVecMult.push_back(ciphertextPartial2[0]);
    partialCiphertextVecMult.push_back(ciphertextPartial3[0]);
    partialCiphertextVecMult.push_back(ciphertextPartial4[0]);
    partialCiphertextVecMult.push_back(ciphertextPartial5[0]);

    cc->MultipartyDecryptFusion(partialCiphertextVecMult, &plaintextMultipartyMult);

    plaintextMultipartyMult->SetLength(plaintext1->GetLength());

    std::cout << "\n Resulting Fused Plaintext after Multiplication of plaintexts 1 "
                 "and 3: \n"
              << std::endl;
    std::cout << plaintextMultipartyMult << std::endl;

    std::cout << "\n";

    Plaintext plaintextMultipartyEvalSum;

    ciphertextPartial1 = cc->MultipartyDecryptLead({ciphertextEvalSum}, kp1.secretKey);

    ciphertextPartial2 = cc->MultipartyDecryptMain({ciphertextEvalSum}, kp2.secretKey);

    ciphertextPartial3 = cc->MultipartyDecryptMain({ciphertextEvalSum}, kp3.secretKey);

    ciphertextPartial4 = cc->MultipartyDecryptMain({ciphertextEvalSum}, kp4.secretKey);

    ciphertextPartial5 = cc->MultipartyDecryptMain({ciphertextEvalSum}, kp5.secretKey);

    std::vector<Ciphertext<DCRTPoly>> partialCiphertextVecEvalSum;
    partialCiphertextVecEvalSum.push_back(ciphertextPartial1[0]);
    partialCiphertextVecEvalSum.push_back(ciphertextPartial2[0]);
    partialCiphertextVecEvalSum.push_back(ciphertextPartial3[0]);
    partialCiphertextVecEvalSum.push_back(ciphertextPartial4[0]);
    partialCiphertextVecEvalSum.push_back(ciphertextPartial5[0]);

    cc->MultipartyDecryptFusion(partialCiphertextVecEvalSum, &plaintextMultipartyEvalSum);

    plaintextMultipartyEvalSum->SetLength(plaintext1->GetLength());

    std::cout << "\n Fused result after summation of ciphertext 3: \n" << std::endl;
    std::cout << plaintextMultipartyEvalSum << std::endl;
}
