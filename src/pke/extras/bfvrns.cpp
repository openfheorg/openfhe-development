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
  Example of basic SHE operations. Demo software for BFV multiparty operations
 */

#include <iostream>

#include "openfhe.h"
#include "scheme/bfvrns/cryptocontext-bfvrns.h"
#include "gen-cryptocontext.h"

using namespace lbcrypto;

int main(int argc, char *argv[]) {
  ////////////////////////////////////////////////////////////
  // Set-up of parameters
  ////////////////////////////////////////////////////////////

  std::cout << "\nThis code demonstrates the use of the BFVrns scheme for "
               "basic homomorphic encryption operations. "
            << std::endl;
  std::cout
      << "This code shows how to auto-generate parameters during run-time "
         "based on desired plaintext moduli and security levels. "
      << std::endl;
  std::cout << "In this demonstration we use three input plaintext and show "
               "how to both add them together and multiply them together. "
            << std::endl;

  // Generate parameters.
  double diff, start, finish;

  CCParams<CryptoContextBFVRNS> parameters;
  parameters.SetPlaintextModulus(256);
  parameters.SetRootHermiteFactor(1.006);
  parameters.SetStandardDeviation(4);
  parameters.SetEvalMultCount(5);
  parameters.SetMaxDepth(6);
  parameters.SetScalingFactorBits(60);

  CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
  // enable features that you wish to use
  cryptoContext->Enable(PKE);
  cryptoContext->Enable(KEYSWITCH);
  cryptoContext->Enable(LEVELEDSHE);
  cryptoContext->Enable(ADVANCEDSHE);

  std::cout << "p = "
            << cryptoContext->GetCryptoParameters()->GetPlaintextModulus()
            << std::endl;
  std::cout << "n = "
            << cryptoContext->GetCryptoParameters()
                       ->GetElementParams()
                       ->GetCyclotomicOrder() /
                   2
            << std::endl;
  std::cout << "log2 q = "
            << log2(cryptoContext->GetCryptoParameters()
                        ->GetElementParams()
                        ->GetModulus()
                        .ConvertToDouble())
            << std::endl;

  // Initialize Public Key Containers
  KeyPair<DCRTPoly> keyPair;

  ////////////////////////////////////////////////////////////
  // Perform Key Generation Operation
  ////////////////////////////////////////////////////////////

  std::cout << "Running key generation (used for source data)..." << std::endl;

  start = currentDateTime();

  keyPair = cryptoContext->KeyGen();

  // Create evaluation key vector to be used in keyswitching
  cryptoContext->EvalMultKeysGen(keyPair.secretKey);

  finish = currentDateTime();
  diff = finish - start;
  std::cout << "Key generation time: "
       << "\t" << diff << " ms" << std::endl;

  if (!keyPair.good()) {
    std::cout << "Key generation failed!" << std::endl;
    exit(1);
  }

  ////////////////////////////////////////////////////////////
  // Encode source data
  ////////////////////////////////////////////////////////////

  std::vector<int64_t> vectorOfInts1 = {5, 4, 3, 2, 1, 0, 5, 4, 3, 2, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  std::vector<int64_t> vectorOfInts3 = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  std::vector<int64_t> vectorOfInts4 = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  std::vector<int64_t> vectorOfInts5 = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  std::vector<int64_t> vectorOfInts6 = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  Plaintext plaintext1 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts1);
  Plaintext plaintext2 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts2);
  Plaintext plaintext3 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts3);
  Plaintext plaintext4 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts4);
  Plaintext plaintext5 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts5);
  Plaintext plaintext6 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts6);

  ////////////////////////////////////////////////////////////
  // Encryption
  ////////////////////////////////////////////////////////////

  Ciphertext<DCRTPoly> ciphertext1;
  Ciphertext<DCRTPoly> ciphertext2;
  Ciphertext<DCRTPoly> ciphertext3;
  Ciphertext<DCRTPoly> ciphertext4;
  Ciphertext<DCRTPoly> ciphertext5;
  Ciphertext<DCRTPoly> ciphertext6;

  start = currentDateTime();

  ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
  ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
  ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext3);
  ciphertext4 = cryptoContext->Encrypt(keyPair.publicKey, plaintext4);
  ciphertext5 = cryptoContext->Encrypt(keyPair.publicKey, plaintext5);
  ciphertext6 = cryptoContext->Encrypt(keyPair.publicKey, plaintext6);

  finish = currentDateTime();
  diff = finish - start;
  std::cout << "Encryption time: "
       << "\t" << diff << " ms" << std::endl;

  ////////////////////////////////////////////////////////////
  // Decryption of Ciphertext
  ////////////////////////////////////////////////////////////

  Plaintext plaintext1Dec;
  Plaintext plaintext2Dec;
  Plaintext plaintext3Dec;
  Plaintext plaintext4Dec;
  Plaintext plaintext5Dec;
  Plaintext plaintext6Dec;

  start = currentDateTime();

  cryptoContext->Decrypt(keyPair.secretKey, ciphertext1, &plaintext1Dec);
  cryptoContext->Decrypt(keyPair.secretKey, ciphertext2, &plaintext2Dec);
  cryptoContext->Decrypt(keyPair.secretKey, ciphertext3, &plaintext3Dec);
  cryptoContext->Decrypt(keyPair.secretKey, ciphertext4, &plaintext4Dec);
  cryptoContext->Decrypt(keyPair.secretKey, ciphertext5, &plaintext5Dec);
  cryptoContext->Decrypt(keyPair.secretKey, ciphertext6, &plaintext6Dec);

  finish = currentDateTime();
  diff = finish - start;
  std::cout << "Decryption time: "
       << "\t" << diff << " ms" << std::endl;

  std::cout << "\n Original Plaintext: \n";
  std::cout << *plaintext1 << std::endl;
  std::cout << *plaintext2 << std::endl;
  std::cout << *plaintext3 << std::endl;
  std::cout << *plaintext4 << std::endl;
  std::cout << *plaintext5 << std::endl;
  std::cout << *plaintext6 << std::endl;

  std::cout << "\n Resulting Decryption of Ciphertext: \n";
  std::cout << *plaintext1Dec << std::endl;
  std::cout << *plaintext2Dec << std::endl;
  std::cout << *plaintext3Dec << std::endl;
  std::cout << *plaintext4Dec << std::endl;
  std::cout << *plaintext5Dec << std::endl;
  std::cout << *plaintext6Dec << std::endl;

  std::cout << "\n";

  ////////////////////////////////////////////////////////////
  // EvalMult Operation
  ////////////////////////////////////////////////////////////

  Ciphertext<DCRTPoly> ciphertextMul12;
  Ciphertext<DCRTPoly> ciphertextMul123;
  Ciphertext<DCRTPoly> ciphertextMul1234;
  Ciphertext<DCRTPoly> ciphertextMul12345;
  Ciphertext<DCRTPoly> ciphertextMul123456;

  start = currentDateTime();
  // Perform consecutive multiplications and do a keyswtiching at the end.
  ciphertextMul12 = cryptoContext->EvalMultNoRelin(ciphertext1, ciphertext2);
  ciphertextMul123 =
      cryptoContext->EvalMultNoRelin(ciphertextMul12, ciphertext3);
  ciphertextMul1234 =
      cryptoContext->EvalMultNoRelin(ciphertextMul123, ciphertext4);
  ciphertextMul12345 =
      cryptoContext->EvalMultNoRelin(ciphertextMul1234, ciphertext5);
  ciphertextMul123456 =
      cryptoContext->EvalMultAndRelinearize(ciphertextMul12345, ciphertext6);

  finish = currentDateTime();
  diff = finish - start;
  std::cout << "EvalMult time: "
       << "\t" << diff << " ms" << std::endl;

  ////////////////////////////////////////////////////////////
  // Decryption after Accumulation Operation on Re-Encrypted Data
  ////////////////////////////////////////////////////////////

  Plaintext plaintextMul1;
  Plaintext plaintextMul2;
  Plaintext plaintextMul3;
  Plaintext plaintextMul4;
  Plaintext plaintextMul5;

  start = currentDateTime();

  cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul12, &plaintextMul1);
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul123, &plaintextMul2);
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul1234, &plaintextMul3);
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul12345, &plaintextMul4);
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul123456,
                         &plaintextMul5);

  finish = currentDateTime();
  diff = finish - start;

  // std::cin.get();

  std::cout << "\n Original Plaintext: \n";
  std::cout << *plaintext1 << std::endl;
  std::cout << *plaintext2 << std::endl;
  std::cout << *plaintext3 << std::endl;
  std::cout << *plaintext4 << std::endl;
  std::cout << *plaintext5 << std::endl;
  std::cout << *plaintext6 << std::endl;

  std::cout << "\n Resulting Plaintext (after polynomial multiplication): \n";
  std::cout << *plaintextMul1 << std::endl;
  std::cout << *plaintextMul2 << std::endl;
  std::cout << *plaintextMul3 << std::endl;
  std::cout << *plaintextMul4 << std::endl;
  std::cout << *plaintextMul5 << std::endl;

  std::cout << "\n";

  ////////////////////////////////////////////////////////////
  // EvalAdd Operation
  ////////////////////////////////////////////////////////////

  Ciphertext<DCRTPoly> ciphertextAdd12;
  Ciphertext<DCRTPoly> ciphertextAdd123;

  start = currentDateTime();

  ciphertextAdd12 = cryptoContext->EvalAdd(ciphertextMul12, ciphertextMul12345);
  ciphertextAdd123 = cryptoContext->EvalAdd(ciphertextAdd12, ciphertextMul123);

  finish = currentDateTime();
  diff = finish - start;
  std::cout << "EvalAdd time: "
       << "\t" << diff << " ms" << std::endl;

  ////////////////////////////////////////////////////////////
  // Decryption after Accumulation Operation
  ////////////////////////////////////////////////////////////

  Plaintext plaintextAdd1;
  Plaintext plaintextAdd2;

  start = currentDateTime();

  cryptoContext->Decrypt(keyPair.secretKey, ciphertextAdd12, &plaintextAdd1);
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextAdd123, &plaintextAdd2);

  finish = currentDateTime();
  diff = finish - start;

  std::cout << "\n Original Plaintext: \n";
  std::cout << *plaintextMul1 << std::endl;
  std::cout << *plaintextMul4 << std::endl;
  std::cout << *plaintextMul5 << std::endl;

  std::cout << "\n Resulting Added Plaintext: \n";
  std::cout << *plaintextAdd1 << std::endl;
  std::cout << *plaintextAdd2 << std::endl;

  std::cout << "\n";

  ////////////////////////////////////////////////////////////
  // Done
  ////////////////////////////////////////////////////////////
  Ciphertext<DCRTPoly> ciphertextMul1234567;
  std::vector<Ciphertext<DCRTPoly>> cipherTextList;

  cipherTextList.push_back(ciphertext1);
  cipherTextList.push_back(ciphertext2);
  cipherTextList.push_back(ciphertext3);
  cipherTextList.push_back(ciphertext4);
  cipherTextList.push_back(ciphertext5);

  ciphertextMul1234567 = cryptoContext->EvalMultMany(cipherTextList);

  Plaintext plaintextMul7;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul1234567,
                         &plaintextMul7);

  std::cout << *plaintextMul7 << std::endl;

  std::cout << "Execution Completed." << std::endl;

  return 0;
}
