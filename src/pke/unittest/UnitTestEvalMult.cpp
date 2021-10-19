// @file
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <fstream>
#include <iostream>
#include "UnitTestUtils.h"
#include "gtest/gtest.h"

#include "cryptocontext.h"

#include "encoding/encodings.h"
#include <exception>


using namespace std;
using namespace lbcrypto;

namespace {
    class UnitTestEvalMult : public ::testing::Test {
        protected:
            virtual void SetUp() {}

            virtual void TearDown() {
                CryptoContextFactory<Poly>::ReleaseAllContexts();
                CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
            }

        public:
    };

    enum TEST_ESTIMATED_RESULT {
        SUCCESS,
        INVALID_MAX_DEPTH,
        INVALID_PRIVATE_KEY,
        INVALID_PUBLIC_KEY,
        INVALID_PLAINTEXT_ENCRYPT,
        INVALID_CIPHERTEXT_ERROR1,
        INVALID_CIPHERTEXT_ERROR2,
        INVALID_CIPHERTEXT_ERROR3,
        INVALID_CIPHERTEXT_ERROR4,
        INVALID_CIPHERTEXT_DECRYPT,
        INVALID_PLAINTEXT_DECRYPT,
        INVALID_PRIVATE_KEY_DECRYPT,
        INVALID_CIPHER_TEXT_LIST
    };

    static CryptoContext<Poly> MakeBFVPolyCC(TEST_ESTIMATED_RESULT testResult = SUCCESS) {
        int relWindow = 8;
        int plaintextModulus = 256;
        double sigma = 4;
        double rootHermiteFactor = 1.6;
        uint64_t maxDepth = (testResult != INVALID_MAX_DEPTH) ? 4 : 3;

        // Set Crypto Parameters
        CryptoContext<Poly> cryptoContext =
            CryptoContextFactory<Poly>::genCryptoContextBFV(
                    plaintextModulus, rootHermiteFactor, relWindow, sigma, 0, 3, 0,
                    OPTIMIZED, maxDepth);

        cryptoContext->Enable(ENCRYPTION);
        cryptoContext->Enable(SHE);

        return cryptoContext;
    }
    static CryptoContext<DCRTPoly> MakeBFVrnsDCRTPolyCC(TEST_ESTIMATED_RESULT testResult = SUCCESS) {
        int plaintextModulus = 256;
        double sigma = 4;
        double rootHermiteFactor = 1.03;
        uint64_t maxDepth = (testResult != INVALID_MAX_DEPTH) ? 4 : 3;

        // Set Crypto Parameters
        CryptoContext<DCRTPoly> cryptoContext =
            CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
                    plaintextModulus, rootHermiteFactor, sigma, 0, 3, 0, OPTIMIZED, maxDepth);

        cryptoContext->Enable(ENCRYPTION);
        cryptoContext->Enable(SHE);

        return cryptoContext;
    }

    static CryptoContext<DCRTPoly> MakeBGVrnsDCRTPolyCC(TEST_ESTIMATED_RESULT testResult = SUCCESS) {
          /*
          usint multiplicativeDepth, usint ptm,
                SecurityLevel stdLevel = HEStd_128_classic, float stdDev = 3.19,
                      int maxDepth = 2, MODE mode = OPTIMIZED,
                            enum KeySwitchTechnique ksTech = HYBRID, usint ringDim = 0,
                            */

        uint32_t multDepth = 4;
        int plaintextModulus = 65537;
        SecurityLevel securityLevel = HEStd_NotSet;
        float stdDev = 3.19;
        //int maxDepth = 4;
        int maxDepth = (testResult != INVALID_MAX_DEPTH) ? 4 : 3;
        MODE mode = OPTIMIZED;
        KeySwitchTechnique ksTech = HYBRID;
        usint ringDim = 16;

        // Set Crypto Parameters
        CryptoContext<DCRTPoly> cryptoContext =
            CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(multDepth,
                                                                   plaintextModulus,
                                                                   securityLevel,
                                                                   stdDev,
                                                                   maxDepth,
                                                                   mode,
                                                                   ksTech,
                                                                   ringDim);

        cryptoContext->Enable(ENCRYPTION);
        cryptoContext->Enable(SHE);
        cryptoContext->Enable(LEVELEDSHE);

        return cryptoContext;
    }

    static CryptoContext<DCRTPoly> MakeCKKSDCRTPolyCC(TEST_ESTIMATED_RESULT testResult = SUCCESS) {
        uint32_t multDepth = 4;
        uint32_t batchSize = 8;
        SecurityLevel securityLevel = HEStd_NotSet;
        usint ringDim = 16; 

#if NATIVEINT == 128
        uint32_t scaleFactorBits = 78;
        // Set Crypto Parameters
        CryptoContext<DCRTPoly> cryptoContext =
            CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
                    multDepth, scaleFactorBits, batchSize, securityLevel, ringDim,
		    APPROXAUTO,HYBRID,0,3);
#else
        uint32_t scaleFactorBits = 50;
        // Set Crypto Parameters
        CryptoContext<DCRTPoly> cryptoContext =
            CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
                    multDepth, scaleFactorBits, batchSize, securityLevel, ringDim,
		    EXACTRESCALE,HYBRID,0,3);
#endif

        cryptoContext->Enable(ENCRYPTION);
        cryptoContext->Enable(SHE);
        cryptoContext->Enable(LEVELEDSHE);

        return cryptoContext;
    }


    template <typename Element>
        static void RunEvalMultManyTest(CryptoContext<Element> cryptoContext,
                TEST_ESTIMATED_RESULT testResult = SUCCESS) {
            ////////////////////////////////////////////////////////////
            // Perform the key generation operation.
            ////////////////////////////////////////////////////////////
            auto keyPair = cryptoContext->KeyGen();
            ASSERT_TRUE(keyPair.good()) << "Key generation failed!";
            // Create evaluation key vector to be used in keyswitching
            if( INVALID_PRIVATE_KEY == testResult )
                cryptoContext->EvalMultKeysGen(nullptr);
            else
                cryptoContext->EvalMultKeysGen(keyPair.secretKey);

            ////////////////////////////////////////////////////////////
            // Plaintext
            ////////////////////////////////////////////////////////////

            std::vector<int64_t> vectorOfInts1 = {5, 4, 3, 2, 1, 0, 5, 4, 3, 2, 1, 0};
            std::vector<int64_t> vectorOfInts2 = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            std::vector<int64_t> vectorOfInts3 = {3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            std::vector<int64_t> vectorOfInts4 = {4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

            std::vector<int64_t> vectorOfInts5 = {10, 8, 6, 4, 2, 0,
                10, 8, 6, 4, 2, 0};
            std::vector<int64_t> vectorOfInts6 = {30, 24, 18, 12, 6, 0,
                30, 24, 18, 12, 6, 0};
            std::vector<int64_t> vectorOfInts7 = {120, 96, 72, 48, 24, 0,
                120, 96, 72, 48, 24, 0};
            Plaintext plaintext1 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts1);
            Plaintext plaintext2 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts2);
            Plaintext plaintext3 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts3);
            Plaintext plaintext4 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts4);

            Plaintext plaintextResult1 =
                cryptoContext->MakeCoefPackedPlaintext(vectorOfInts5);
            Plaintext plaintextResult2 =
                cryptoContext->MakeCoefPackedPlaintext(vectorOfInts6);
            Plaintext plaintextResult3 =
                cryptoContext->MakeCoefPackedPlaintext(vectorOfInts7);

            ////////////////////////////////////////////////////////////
            // Encryption
            ////////////////////////////////////////////////////////////
            auto ciphertext1 = (INVALID_PUBLIC_KEY == testResult) ?
                cryptoContext->Encrypt(nullptr, plaintext1) :
                cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
            auto ciphertext2 = (INVALID_PLAINTEXT_ENCRYPT == testResult) ?
                cryptoContext->Encrypt(keyPair.publicKey, nullptr) :
                cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
            auto ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext3);
            auto ciphertext4 = cryptoContext->Encrypt(keyPair.publicKey, plaintext4);

            ////////////////////////////////////////////////////////////
            // EvalMult Operation
            ////////////////////////////////////////////////////////////
            // Perform consecutive multiplications and do a keyswtiching at the end.
            auto ciphertextMul12 = (INVALID_CIPHERTEXT_ERROR1 == testResult) ?
                cryptoContext->EvalMultNoRelin(nullptr, ciphertext2) :
                cryptoContext->EvalMultNoRelin(ciphertext1, ciphertext2);
            auto ciphertextMul123 = (INVALID_CIPHERTEXT_ERROR2 == testResult) ?
                cryptoContext->EvalMultNoRelin(ciphertextMul12, nullptr) :
                cryptoContext->EvalMultNoRelin(ciphertextMul12, ciphertext3);
            Ciphertext<Element> ciphertextMul1234 = nullptr;
            if(INVALID_CIPHERTEXT_ERROR3 == testResult)
                ciphertextMul1234 = cryptoContext->EvalMultAndRelinearize(nullptr, ciphertext4);
            else if(INVALID_CIPHERTEXT_ERROR4 == testResult)
                ciphertextMul1234 = cryptoContext->EvalMultAndRelinearize(ciphertextMul123, nullptr);
            else
                ciphertextMul1234 = cryptoContext->EvalMultAndRelinearize(ciphertextMul123, ciphertext4);

            ////////////////////////////////////////////////////////////
            // Decryption of multiplicative results with and without keyswtiching (depends
            // on the level)
            ////////////////////////////////////////////////////////////

            Plaintext plaintextMul1;
            Plaintext plaintextMul2;
            Plaintext plaintextMul3;
            if(INVALID_CIPHERTEXT_DECRYPT == testResult)
                cryptoContext->Decrypt(keyPair.secretKey, nullptr, &plaintextMul1);
            else if(INVALID_PLAINTEXT_DECRYPT == testResult)
                cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul12, nullptr);
            else if(INVALID_PRIVATE_KEY_DECRYPT == testResult)
                cryptoContext->Decrypt(nullptr, ciphertextMul12, &plaintextMul1);
            else
                cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul12, &plaintextMul1);
            cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul123, &plaintextMul2);
            cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul1234, &plaintextMul3);

            ////////////////////////////////////////////////////////////
            // Prepare EvalMultMany
            ////////////////////////////////////////////////////////////

            vector<Ciphertext<Element>> cipherTextList =
            { ciphertext1, ciphertext2, ciphertext3, ciphertext4 };

            ////////////////////////////////////////////////////////////
            // Compute EvalMultMany
            ////////////////////////////////////////////////////////////

            auto ciphertextMul12345 = (INVALID_CIPHER_TEXT_LIST == testResult) ?
                cryptoContext->EvalMultMany(vector<Ciphertext<Element>>()) :
                cryptoContext->EvalMultMany(cipherTextList);

            ////////////////////////////////////////////////////////////
            // Decrypt EvalMultMany
            ////////////////////////////////////////////////////////////

            Plaintext plaintextMulMany;
            cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul12345,
                    &plaintextMulMany);

            plaintextResult1->SetLength(plaintextMul1->GetLength());
            plaintextResult2->SetLength(plaintextMul2->GetLength());
            plaintextResult3->SetLength(plaintextMul3->GetLength());

            EXPECT_EQ(*plaintextMul1, *plaintextResult1)
                << ".EvalMult gives incorrect results.\n";
            EXPECT_EQ(*plaintextMul2, *plaintextResult2)
                << ".EvalMult gives incorrect results.\n";
            EXPECT_EQ(*plaintextMul3, *plaintextResult3)
                << ".EvalMultAndRelinearize gives incorrect results.\n";
            EXPECT_EQ(*plaintextMulMany, *plaintextResult3)
                << ".EvalMultMany gives incorrect results.\n";
        }

    template <typename Element>
        static void RunEvalMultTestCKKS(CryptoContext<Element> cryptoContext,
                TEST_ESTIMATED_RESULT testResult = SUCCESS) {
            ////////////////////////////////////////////////////////////
            // Perform the key generation operation.
            ////////////////////////////////////////////////////////////
            auto keyPair = cryptoContext->KeyGen();
            ASSERT_TRUE(keyPair.good()) << "Key generation failed!";
            // Create evaluation key vector to be used in keyswitching
            if( INVALID_PRIVATE_KEY == testResult )
                cryptoContext->EvalMultKeyGen(nullptr);
            else
                cryptoContext->EvalMultKeyGen(keyPair.secretKey);

            ////////////////////////////////////////////////////////////
            // Plaintext
            ////////////////////////////////////////////////////////////

            std::vector<std::complex<double>> vectorOfInts1 = { 0, 1, 2, 3, 4, 5, 6, 7 };
            std::vector<std::complex<double>> vectorOfInts2 = { 7, 6, 5, 4, 3, 2, 1, 0 };

            std::vector<std::complex<double>> vectorOfIntsResult = { 0, 6, 10, 12, 12, 10, 6, 0 };

            Plaintext plaintext1 = cryptoContext->MakeCKKSPackedPlaintext(vectorOfInts1);
            Plaintext plaintext2 = cryptoContext->MakeCKKSPackedPlaintext(vectorOfInts2);

            Plaintext plaintextResult =
                cryptoContext->MakeCKKSPackedPlaintext(vectorOfIntsResult);

            ////////////////////////////////////////////////////////////
            // Encryption
            ////////////////////////////////////////////////////////////
            auto ciphertext1 = (INVALID_PUBLIC_KEY == testResult) ?
                cryptoContext->Encrypt(nullptr, plaintext1) :
                cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
            auto ciphertext2 = (INVALID_PLAINTEXT_ENCRYPT == testResult) ?
                cryptoContext->Encrypt(keyPair.publicKey, nullptr) :
                cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
            ////////////////////////////////////////////////////////////
            // EvalMult Operation
            ////////////////////////////////////////////////////////////
            // Perform consecutive multiplications and do a keyswtiching at the end.
            Ciphertext<Element> ciphertextMul12 = nullptr;
            if(INVALID_CIPHERTEXT_ERROR1 == testResult)
                ciphertextMul12 = cryptoContext->EvalMultNoRelin(nullptr, ciphertext2);
            else if(INVALID_CIPHERTEXT_ERROR2 == testResult)
                ciphertextMul12 = cryptoContext->EvalMultNoRelin(ciphertext1, nullptr);
            else
                ciphertextMul12 = cryptoContext->EvalMultNoRelin(ciphertext1, ciphertext2);

            Ciphertext<Element> ciphertextMult = (INVALID_CIPHERTEXT_ERROR3 == testResult) ?
                cryptoContext->Relinearize(nullptr) :
                cryptoContext->Relinearize(ciphertextMul12);

            ////////////////////////////////////////////////////////////
            // Decryption of multiplicative results with and without keyswtiching (depends
            // on the level)
            ////////////////////////////////////////////////////////////

            Plaintext plaintextMult;

            if(INVALID_CIPHERTEXT_DECRYPT == testResult)
                cryptoContext->Decrypt(keyPair.secretKey, nullptr, &plaintextMult);
            else if(INVALID_PLAINTEXT_DECRYPT == testResult)
                cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult, nullptr);
            else if(INVALID_PRIVATE_KEY_DECRYPT == testResult)
                cryptoContext->Decrypt(nullptr, ciphertextMult, &plaintextMult);
            else
                cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult, &plaintextMult);

            plaintextResult->SetLength(plaintextMult->GetLength());

            EXPECT_TRUE(checkEquality(plaintextMult->GetCKKSPackedValue(),
                        plaintextResult->GetCKKSPackedValue()));
        }

    template <typename Element>
        static void RunEvalMultTestBGVrns(CryptoContext<Element> cryptoContext,
                TEST_ESTIMATED_RESULT testResult = SUCCESS) {
            ////////////////////////////////////////////////////////////
            // Perform the key generation operation.
            ////////////////////////////////////////////////////////////
            auto keyPair = cryptoContext->KeyGen();
            ASSERT_TRUE(keyPair.good()) << "Key generation failed!";
            // Create evaluation key vector to be used in keyswitching
            if( INVALID_PRIVATE_KEY == testResult )
                cryptoContext->EvalMultKeyGen(nullptr);
            else
                cryptoContext->EvalMultKeyGen(keyPair.secretKey);

            ////////////////////////////////////////////////////////////
            // Plaintext
            ////////////////////////////////////////////////////////////

            std::vector<int64_t> vectorOfInts1 = { 0, 1, 2, 3, 4, 5, 6, 7 };
            std::vector<int64_t> vectorOfInts2 = { 7, 6, 5, 4, 3, 2, 1, 0 };

            std::vector<int64_t> vectorOfIntsResult = { 0, 6, 10, 12, 12, 10, 6, 0 };

            Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);
            Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);

            Plaintext plaintextResult =
                cryptoContext->MakePackedPlaintext(vectorOfIntsResult);

            ////////////////////////////////////////////////////////////
            // Encryption
            ////////////////////////////////////////////////////////////
            auto ciphertext1 = (INVALID_PUBLIC_KEY == testResult) ?
                cryptoContext->Encrypt(nullptr, plaintext1) :
                cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
            auto ciphertext2 = (INVALID_PLAINTEXT_ENCRYPT == testResult) ?
                cryptoContext->Encrypt(keyPair.publicKey, nullptr) :
                cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
            ////////////////////////////////////////////////////////////
            // EvalMult Operation
            ////////////////////////////////////////////////////////////
            // Perform consecutive multiplications and do a keyswtiching at the end.
            Ciphertext<Element> ciphertextMul12 = nullptr;
            if(INVALID_CIPHERTEXT_ERROR1 == testResult)
                ciphertextMul12 = cryptoContext->EvalMultNoRelin(nullptr, ciphertext2);
            else if(INVALID_CIPHERTEXT_ERROR2 == testResult)
                ciphertextMul12 = cryptoContext->EvalMultNoRelin(ciphertext1, nullptr);
            else
                ciphertextMul12 = cryptoContext->EvalMultNoRelin(ciphertext1, ciphertext2);

            Ciphertext<Element> ciphertextMult = (INVALID_CIPHERTEXT_ERROR3 == testResult) ?
                cryptoContext->Relinearize(nullptr) :
                cryptoContext->Relinearize(ciphertextMul12);

            ////////////////////////////////////////////////////////////
            // Decryption of multiplicative results with and without keyswtiching (depends
            // on the level)
            ////////////////////////////////////////////////////////////

            Plaintext plaintextMult;

            if(INVALID_CIPHERTEXT_DECRYPT == testResult)
                cryptoContext->Decrypt(keyPair.secretKey, nullptr, &plaintextMult);
            else if(INVALID_PLAINTEXT_DECRYPT == testResult)
                cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult, nullptr);
            else if(INVALID_PRIVATE_KEY_DECRYPT == testResult)
                cryptoContext->Decrypt(nullptr, ciphertextMult, &plaintextMult);
            else
                cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult, &plaintextMult);

            plaintextResult->SetLength(plaintextMult->GetLength());

            EXPECT_TRUE(checkEquality(plaintextMult->GetPackedValue(),
                        plaintextResult->GetPackedValue()));
        }

    template <typename Element>
        static void RunRelinTestBGVrns(CryptoContext<Element> cryptoContext,
                TEST_ESTIMATED_RESULT testResult = SUCCESS) {
            ////////////////////////////////////////////////////////////
            // Perform the key generation operation.
            ////////////////////////////////////////////////////////////
            auto keyPair = cryptoContext->KeyGen();
            ASSERT_TRUE(keyPair.good()) << "Key generation failed!";
            // Create evaluation key vector to be used in keyswitching
            cryptoContext->EvalMultKeysGen(keyPair.secretKey);

            ////////////////////////////////////////////////////////////
            // Plaintext
            ////////////////////////////////////////////////////////////

            std::vector<int64_t> vectorOfInts1 = { 0, 1, 2, 3, 4, 5, 6, 7 };
            std::vector<int64_t> vectorOfInts2 = { 7, 6, 5, 4, 3, 2, 1, 0 };

            std::vector<int64_t> vectorOfIntsResult = { 0, 6, 10, 12, 12, 10, 6, 0 };
            std::vector<int64_t> vectorOfIntsResult2 = { 0, 6, 20, 36, 48, 50, 36, 0 };

            Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);
            Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);

            Plaintext plaintextResult =
                cryptoContext->MakePackedPlaintext(vectorOfIntsResult);

            Plaintext plaintextResult2 =
                cryptoContext->MakePackedPlaintext(vectorOfIntsResult2);

            ////////////////////////////////////////////////////////////
            // Encryption
            ////////////////////////////////////////////////////////////
            auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
            auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
            ////////////////////////////////////////////////////////////
            // EvalMult Operation
            ////////////////////////////////////////////////////////////
            // Perform consecutive multiplications and do a keyswtiching at the end.
            auto  ciphertextMul12 = cryptoContext->EvalMultNoRelin(ciphertext1, ciphertext2);

            auto ciphertextMult = cryptoContext->Relinearize(ciphertextMul12);

            ////////////////////////////////////////////////////////////
            // Decryption of multiplicative results with and without keyswtiching (depends
            // on the level)
            ////////////////////////////////////////////////////////////

            Plaintext plaintextMult;

            cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult, &plaintextMult);

            plaintextMult->SetLength(plaintextResult->GetLength());

            EXPECT_TRUE(checkEquality(plaintextMult->GetPackedValue(),
                        plaintextResult->GetPackedValue()))
                 << ".Relinearization after one multiplication failed.\n";

            ciphertextMult = ciphertextMul12;

            cryptoContext->Relinearize(ciphertextMult);

            cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult, &plaintextMult);

            plaintextMult->SetLength(plaintextResult->GetLength());

            EXPECT_TRUE(checkEquality(plaintextMult->GetPackedValue(),
                        plaintextResult->GetPackedValue()))
                 << ".In-place relinearization after one multiplication failed.\n";

            // Perform consecutive multiplications and do a keyswtiching at the end.
            auto  ciphertextMul123 = cryptoContext->EvalMultNoRelin(ciphertext1, ciphertextMul12);

            auto ciphertextMult2 = cryptoContext->Relinearize(ciphertextMul123);

            ////////////////////////////////////////////////////////////
            // Decryption of multiplicative results with and without keyswtiching (depends
            // on the level)
            ////////////////////////////////////////////////////////////

            Plaintext plaintextMult2;

            cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult2, &plaintextMult2);

            plaintextMult2->SetLength(plaintextResult2->GetLength());

            EXPECT_TRUE(checkEquality(plaintextMult2->GetPackedValue(),
                        plaintextResult2->GetPackedValue()))
            << ".Relinearization after two multiplications failed.\n";

            ciphertextMult2 = ciphertextMul123;

            cryptoContext->Relinearize(ciphertextMult2);

            cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult2, &plaintextMult2);

            plaintextMult2->SetLength(plaintextResult2->GetLength());

            EXPECT_TRUE(checkEquality(plaintextMult2->GetPackedValue(),
                        plaintextResult2->GetPackedValue()))
            << ".In-place relinearization after two multiplications failed.\n";

        }

    template <typename Element>
         static void RunRelinTestCKKS(CryptoContext<Element> cryptoContext,
                 TEST_ESTIMATED_RESULT testResult = SUCCESS) {
             ////////////////////////////////////////////////////////////
             // Perform the key generation operation.
             ////////////////////////////////////////////////////////////
             auto keyPair = cryptoContext->KeyGen();
             ASSERT_TRUE(keyPair.good()) << "Key generation failed!";
             // Create evaluation key vector to be used in keyswitching
             cryptoContext->EvalMultKeysGen(keyPair.secretKey);

             ////////////////////////////////////////////////////////////
             // Plaintext
             ////////////////////////////////////////////////////////////

             std::vector<std::complex<double>> vectorOfInts1 = { 0, 1, 2, 3, 4, 5, 6, 7 };
             std::vector<std::complex<double>> vectorOfInts2 = { 7, 6, 5, 4, 3, 2, 1, 0 };

             std::vector<std::complex<double>> vectorOfIntsResult = { 0, 6, 10, 12, 12, 10, 6, 0 };
             std::vector<std::complex<double>> vectorOfIntsResult2 = { 0, 6, 20, 36, 48, 50, 36, 0 };

             Plaintext plaintext1 = cryptoContext->MakeCKKSPackedPlaintext(vectorOfInts1);
             Plaintext plaintext2 = cryptoContext->MakeCKKSPackedPlaintext(vectorOfInts2);

             Plaintext plaintextResult =
                 cryptoContext->MakeCKKSPackedPlaintext(vectorOfIntsResult);

             Plaintext plaintextResult2 =
                 cryptoContext->MakeCKKSPackedPlaintext(vectorOfIntsResult2);

             ////////////////////////////////////////////////////////////
             // Encryption
             ////////////////////////////////////////////////////////////
             auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
             auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
             ////////////////////////////////////////////////////////////
             // EvalMult Operation
             ////////////////////////////////////////////////////////////
             // Perform consecutive multiplications and do a keyswtiching at the end.
             auto  ciphertextMul12 = cryptoContext->EvalMultNoRelin(ciphertext1, ciphertext2);

             auto ciphertextMult = cryptoContext->Relinearize(ciphertextMul12);

             ////////////////////////////////////////////////////////////
             // Decryption of multiplicative results with and without keyswtiching (depends
             // on the level)
             ////////////////////////////////////////////////////////////

             Plaintext plaintextMult;

             cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult, &plaintextMult);

             plaintextMult->SetLength(plaintextResult->GetLength());

             EXPECT_TRUE(checkEquality(plaintextMult->GetCKKSPackedValue(),
                         plaintextResult->GetCKKSPackedValue()))
                  << ".Relinearization after one multiplication failed.\n";

             ciphertextMult = ciphertextMul12;

             cryptoContext->Relinearize(ciphertextMult);

             cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult, &plaintextMult);

             plaintextMult->SetLength(plaintextResult->GetLength());

             EXPECT_TRUE(checkEquality(plaintextMult->GetCKKSPackedValue(),
                         plaintextResult->GetCKKSPackedValue()))
                  << ".In-place relinearization after one multiplication failed.\n";

             // Perform consecutive multiplications and do a keyswtiching at the end.
             auto  ciphertextMul123 = cryptoContext->EvalMultNoRelin(ciphertext1, ciphertextMul12);

             auto ciphertextMult2 = cryptoContext->Relinearize(ciphertextMul123);

             ////////////////////////////////////////////////////////////
             // Decryption of multiplicative results with and without keyswtiching (depends
             // on the level)
             ////////////////////////////////////////////////////////////

             Plaintext plaintextMult2;

             cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult2, &plaintextMult2);

             plaintextMult2->SetLength(plaintextResult2->GetLength());

             EXPECT_TRUE(checkEquality(plaintextMult2->GetCKKSPackedValue(),
                         plaintextResult2->GetCKKSPackedValue()))
             << ".Relinearization after two multiplications failed.\n";

             ciphertextMult2 = ciphertextMul123;

             cryptoContext->Relinearize(ciphertextMult2);

             cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult2, &plaintextMult2);

             plaintextMult2->SetLength(plaintextResult2->GetLength());

             EXPECT_TRUE(checkEquality(plaintextMult2->GetCKKSPackedValue(),
                         plaintextResult2->GetCKKSPackedValue()))
             << ".In-place relinearization after two multiplications failed.\n";

         }


} // anonymous namespace

//===================================================================
TEST_F(UnitTestEvalMult, Test_BFV_Eval_Mult_Many) {
    PackedEncoding::Destroy();
    RunEvalMultManyTest(MakeBFVPolyCC());
}
TEST_F(UnitTestEvalMult, Test_BFV_Eval_Mult_Many_INVALID_MAX_DEPTH) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultManyTest(MakeBFVPolyCC(INVALID_MAX_DEPTH)));
}
TEST_F(UnitTestEvalMult, Test_BFV_Eval_Mult_Many_INVALID_PRIVATE_KEY) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultManyTest(MakeBFVPolyCC(), INVALID_PRIVATE_KEY));
}
TEST_F(UnitTestEvalMult, Test_BFV_Eval_Mult_Many_INVALID_PUBLIC_KEY) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultManyTest(MakeBFVPolyCC(), INVALID_PUBLIC_KEY));
}
TEST_F(UnitTestEvalMult, Test_BFV_Eval_Mult_Many_INVALID_PLAINTEXT_ENCRYPT) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultManyTest(MakeBFVPolyCC(), INVALID_PLAINTEXT_ENCRYPT));
}
TEST_F(UnitTestEvalMult, Test_BFV_Eval_Mult_Many_INVALID_CIPHERTEXT_ERROR1) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultManyTest(MakeBFVPolyCC(), INVALID_CIPHERTEXT_ERROR1));
}
TEST_F(UnitTestEvalMult, Test_BFV_Eval_Mult_Many_INVALID_CIPHERTEXT_ERROR2) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultManyTest(MakeBFVPolyCC(), INVALID_CIPHERTEXT_ERROR2));
}
TEST_F(UnitTestEvalMult, Test_BFV_Eval_Mult_Many_INVALID_CIPHERTEXT_ERROR3) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultManyTest(MakeBFVPolyCC(), INVALID_CIPHERTEXT_ERROR3));
}
TEST_F(UnitTestEvalMult, Test_BFV_Eval_Mult_Many_INVALID_CIPHERTEXT_ERROR4) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultManyTest(MakeBFVPolyCC(), INVALID_CIPHERTEXT_ERROR4));
}
TEST_F(UnitTestEvalMult, Test_BFV_Eval_Mult_Many_INVALID_CIPHER_TEXT_LIST) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultManyTest(MakeBFVPolyCC(), INVALID_CIPHER_TEXT_LIST));
}
TEST_F(UnitTestEvalMult, Test_BFV_Eval_Mult_Many_INVALID_CIPHERTEXT_DECRYPT) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultManyTest(MakeBFVPolyCC(), INVALID_CIPHERTEXT_DECRYPT));
}
TEST_F(UnitTestEvalMult, Test_BFV_Eval_Mult_Many_INVALID_PLAINTEXT_DECRYPT) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultManyTest(MakeBFVPolyCC(), INVALID_PLAINTEXT_DECRYPT));
}
TEST_F(UnitTestEvalMult, Test_BFV_Eval_Mult_Many_INVALID_PRIVATE_KEY_DECRYPT) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultManyTest(MakeBFVPolyCC(), INVALID_PRIVATE_KEY_DECRYPT));
}
//===================================================================
TEST_F(UnitTestEvalMult, Test_BFVrns_Eval_Mult_Many) {
    PackedEncoding::Destroy();
    RunEvalMultManyTest(MakeBFVrnsDCRTPolyCC());
}
TEST_F(UnitTestEvalMult, Test_BFVrns_Eval_Mult_Many_INVALID_PRIVATE_KEY) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultManyTest(MakeBFVrnsDCRTPolyCC(), INVALID_PRIVATE_KEY));
}
TEST_F(UnitTestEvalMult, Test_BFVrns_Eval_Mult_Many_INVALID_PUBLIC_KEY) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultManyTest(MakeBFVrnsDCRTPolyCC(), INVALID_PUBLIC_KEY));
}
TEST_F(UnitTestEvalMult, Test_BFVrns_Eval_Mult_Many_INVALID_PLAINTEXT_ENCRYPT) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultManyTest(MakeBFVrnsDCRTPolyCC(), INVALID_PLAINTEXT_ENCRYPT));
}
TEST_F(UnitTestEvalMult, Test_BFVrns_Eval_Mult_Many_INVALID_CIPHERTEXT_ERROR1) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultManyTest(MakeBFVrnsDCRTPolyCC(), INVALID_CIPHERTEXT_ERROR1));
}
TEST_F(UnitTestEvalMult, Test_BFVrns_Eval_Mult_Many_INVALID_CIPHERTEXT_ERROR2) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultManyTest(MakeBFVrnsDCRTPolyCC(), INVALID_CIPHERTEXT_ERROR2));
}
TEST_F(UnitTestEvalMult, Test_BFVrns_Eval_Mult_Many_INVALID_CIPHERTEXT_ERROR3) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultManyTest(MakeBFVrnsDCRTPolyCC(), INVALID_CIPHERTEXT_ERROR3));
}
TEST_F(UnitTestEvalMult, Test_BFVrns_Eval_Mult_Many_INVALID_CIPHERTEXT_ERROR4) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultManyTest(MakeBFVrnsDCRTPolyCC(), INVALID_CIPHERTEXT_ERROR4));
}
TEST_F(UnitTestEvalMult, Test_BFVrns_Eval_Mult_Many_INVALID_CIPHER_TEXT_LIST) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultManyTest(MakeBFVrnsDCRTPolyCC(), INVALID_CIPHER_TEXT_LIST));
}
TEST_F(UnitTestEvalMult, Test_BFVrns_Eval_Mult_Many_INVALID_CIPHERTEXT_DECRYPT) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultManyTest(MakeBFVrnsDCRTPolyCC(), INVALID_CIPHERTEXT_DECRYPT));
}
TEST_F(UnitTestEvalMult, Test_BFVrns_Eval_Mult_Many_INVALID_PLAINTEXT_DECRYPT) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultManyTest(MakeBFVrnsDCRTPolyCC(), INVALID_PLAINTEXT_DECRYPT));
}
TEST_F(UnitTestEvalMult, Test_BFVrns_Eval_Mult_Many_INVALID_PRIVATE_KEY_DECRYPT) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultManyTest(MakeBFVrnsDCRTPolyCC(), INVALID_PRIVATE_KEY_DECRYPT));
}
//===================================================================
TEST_F(UnitTestEvalMult, Test_CKKS_Eval_Mult) {
    PackedEncoding::Destroy();
    RunEvalMultTestCKKS(MakeCKKSDCRTPolyCC());
}
TEST_F(UnitTestEvalMult, Test_CKKS_Eval_Mult_INVALID_PRIVATE_KEY) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultTestCKKS(MakeCKKSDCRTPolyCC(), INVALID_PRIVATE_KEY));
}
TEST_F(UnitTestEvalMult, Test_CKKS_Eval_Mult_INVALID_PUBLIC_KEY) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultTestCKKS(MakeCKKSDCRTPolyCC(), INVALID_PUBLIC_KEY));
}
TEST_F(UnitTestEvalMult, Test_CKKS_Eval_Mult_INVALID_PLAINTEXT_ENCRYPT) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultTestCKKS(MakeCKKSDCRTPolyCC(), INVALID_PLAINTEXT_ENCRYPT));
}
TEST_F(UnitTestEvalMult, Test_CKKS_Eval_Mult_INVALID_CIPHERTEXT_ERROR1) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultTestCKKS(MakeCKKSDCRTPolyCC(), INVALID_CIPHERTEXT_ERROR1));
}
TEST_F(UnitTestEvalMult, Test_CKKS_Eval_Mult_INVALID_CIPHERTEXT_ERROR2) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultTestCKKS(MakeCKKSDCRTPolyCC(), INVALID_CIPHERTEXT_ERROR2));
}
TEST_F(UnitTestEvalMult, Test_CKKS_Eval_Mult_INVALID_CIPHERTEXT_ERROR3) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultTestCKKS(MakeCKKSDCRTPolyCC(), INVALID_CIPHERTEXT_ERROR3));
}
TEST_F(UnitTestEvalMult, Test_CKKS_Eval_Mult_INVALID_CIPHERTEXT_DECRYPT) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultTestCKKS(MakeCKKSDCRTPolyCC(), INVALID_CIPHERTEXT_DECRYPT));
}
TEST_F(UnitTestEvalMult, Test_CKKS_Eval_Mult_INVALID_PLAINTEXT_DECRYPT) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultTestCKKS(MakeCKKSDCRTPolyCC(), INVALID_PLAINTEXT_DECRYPT));
}
TEST_F(UnitTestEvalMult, Test_CKKS_Eval_Mult_INVALID_PRIVATE_KEY_DECRYPT) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultTestCKKS(MakeCKKSDCRTPolyCC(), INVALID_PRIVATE_KEY_DECRYPT));
}
//===================================================================
TEST_F(UnitTestEvalMult, Test_BGVrns_Eval_Mult) {
    PackedEncoding::Destroy();
    RunEvalMultTestBGVrns(MakeBGVrnsDCRTPolyCC());
}
TEST_F(UnitTestEvalMult, Test_BGVrns_Eval_Mult_INVALID_PRIVATE_KEY) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultTestBGVrns(MakeBGVrnsDCRTPolyCC(), INVALID_PRIVATE_KEY));
}
TEST_F(UnitTestEvalMult, Test_BGVrns_Eval_Mult_INVALID_PUBLIC_KEY) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultTestBGVrns(MakeBGVrnsDCRTPolyCC(), INVALID_PUBLIC_KEY));
}
TEST_F(UnitTestEvalMult, Test_BGVrns_Eval_Mult_INVALID_PLAINTEXT_ENCRYPT) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultTestBGVrns(MakeBGVrnsDCRTPolyCC(), INVALID_PLAINTEXT_ENCRYPT));
}
TEST_F(UnitTestEvalMult, Test_BGVrns_Eval_Mult_INVALID_CIPHERTEXT_ERROR1) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultTestBGVrns(MakeBGVrnsDCRTPolyCC(), INVALID_CIPHERTEXT_ERROR1));
}
TEST_F(UnitTestEvalMult, Test_BGVrns_Eval_Mult_INVALID_CIPHERTEXT_ERROR2) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultTestBGVrns(MakeBGVrnsDCRTPolyCC(), INVALID_CIPHERTEXT_ERROR2));
}
TEST_F(UnitTestEvalMult, Test_BGVrns_Eval_Mult_INVALID_CIPHERTEXT_ERROR3) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultTestBGVrns(MakeBGVrnsDCRTPolyCC(), INVALID_CIPHERTEXT_ERROR3));
}
TEST_F(UnitTestEvalMult, Test_BGVrns_Eval_Mult_INVALID_CIPHERTEXT_DECRYPT) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultTestBGVrns(MakeBGVrnsDCRTPolyCC(), INVALID_CIPHERTEXT_DECRYPT));
}
TEST_F(UnitTestEvalMult, Test_BGVrns_Eval_Mult_INVALID_PLAINTEXT_DECRYPT) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultTestBGVrns(MakeBGVrnsDCRTPolyCC(), INVALID_PLAINTEXT_DECRYPT));
}
TEST_F(UnitTestEvalMult, Test_BGVrns_Eval_Mult_INVALID_PRIVATE_KEY_DECRYPT) {
    UT_EXPECT_THROW_SIMPLE(RunEvalMultTestBGVrns(MakeBGVrnsDCRTPolyCC(), INVALID_PRIVATE_KEY_DECRYPT));
}
//===================================================================
TEST_F(UnitTestEvalMult, Test_BGVrns_Relin) {
    PackedEncoding::Destroy();
    RunRelinTestBGVrns(MakeBGVrnsDCRTPolyCC());
}
TEST_F(UnitTestEvalMult, Test_CKKS_Relin) {
    PackedEncoding::Destroy();
    RunRelinTestCKKS(MakeCKKSDCRTPolyCC());
}
