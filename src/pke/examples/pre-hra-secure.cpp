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
  Example of HRA-secure Proxy Re-Encryption with 13 hops.
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
    std::cout << "setting up the HRA-secure BGV PRE cryptosystem" << std::endl;
    TIC(t);

    double t1;

    uint32_t plaintextModulus = 2;  // can encode shorts

    uint32_t numHops = 13;

    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(plaintextModulus);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetPRENumHops(numHops);
    parameters.SetStatisticalSecurity(40);
    parameters.SetNumAdversarialQueries(1048576);
    parameters.SetRingDim(32768);
    parameters.SetPREMode(NOISE_FLOODING_HRA);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetMultiplicativeDepth(0);
    // parameters.SetNumLargeDigits(3);
    // parameters.SetKeySwitchTechnique(BV);
    // parameters.SetDigitSize(15);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    std::cout << "\nParam generation time: "
              << "\t" << TOC_US(t) << " ms" << std::endl;
    // Turn on features
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(PRE);

    std::cout << "p = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cout << "n = " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
    std::cout << "log2 q = " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;
    // std::cout << "crypto parameters = " << *cc->GetCryptoParameters() << std::endl;
    const auto cryptoParamsBGV = std::dynamic_pointer_cast<CryptoParametersBGVRNS>(cc->GetCryptoParameters());
    std::cout << "log QP = " << cryptoParamsBGV->GetParamsQP()->GetModulus().GetMSB() << std::endl;
    // std::cout << "RNS parameters = " << *cryptoParamsBGV->GetParamsQP() << std::endl;

    auto ringsize = cc->GetRingDimension();
    std::cout << "Alice can encrypt " << ringsize / 8 << " bytes of data" << std::endl;
    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    // Initialize Key Pair Containers
    KeyPair<DCRTPoly> keyPair1;

    std::cout << "\nRunning Alice key generation (used for source data)..." << std::endl;

    TIC(t);
    keyPair1 = cc->KeyGen();
    t1       = TOC_US(t);
    std::cout << "Key generation time: "
              << "\t" << t1 / 1000.0 << " ms" << std::endl;

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
        vShorts.push_back(std::rand() % plaintextModulus);

    PT pt = cc->MakeCoefPackedPlaintext(vShorts);

    ////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////

    TIC(t);
    auto ct1 = cc->Encrypt(keyPair1.publicKey, pt);
    t1       = TOC_US(t);
    std::cout << "Encryption time: "
              << "\t" << t1 / 1000.0 << " ms" << std::endl;

    ////////////////////////////////////////////////////////////
    // Decryption of Ciphertext
    ////////////////////////////////////////////////////////////

    PT ptDec1;

    TIC(t);
    cc->Decrypt(keyPair1.secretKey, ct1, &ptDec1);
    t1 = TOC_US(t);
    std::cout << "Decryption time: "
              << "\t" << t1 / 1000.0 << " ms" << std::endl;

    ptDec1->SetLength(pt->GetLength());

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    // Initialize Key Pair Containers
    std::vector<KeyPair<DCRTPoly>> keyPairVector(numHops);
    std::vector<EvalKey<DCRTPoly>> reencryptionKeyVector(numHops);

    std::cout << "Generating keys for " << numHops << " parties" << std::endl;

    for (unsigned int i = 0; i < numHops; i++) {
        TIC(t);
        keyPairVector[i] = cc->KeyGen();
        t1               = TOC_US(t);
        if (i == 1)
            std::cout << "Key generation time: "
                      << "\t" << t1 / 1000.0 << " ms" << std::endl;

        if (!keyPairVector[i].good()) {
            std::cout << "Bob Key generation failed!" << std::endl;
            return (false);
        }

        ////////////////////////////////////////////////////////////
        // Perform the proxy re-encryption key generation operation.
        // This generates the keys which are used to perform the key switching.
        ////////////////////////////////////////////////////////////
        if (i == 0) {
            reencryptionKeyVector[i] = cc->ReKeyGen(keyPair1.secretKey, keyPairVector[i].publicKey);
        }
        else {
            TIC(t);
            reencryptionKeyVector[i] = cc->ReKeyGen(keyPairVector[i - 1].secretKey, keyPairVector[i].publicKey);
            t1                       = TOC_US(t);
            if (i == 1)
                std::cout << "Re-encryption key generation time: "
                          << "\t" << t1 / 1000.0 << " ms" << std::endl;
        }
    }

    ////////////////////////////////////////////////////////////
    // Re-Encryption
    ////////////////////////////////////////////////////////////
    bool good = true;
    for (unsigned int i = 0; i < numHops; i++) {
        TIC(t);
        ct1 = cc->ReEncrypt(ct1, reencryptionKeyVector[i]);
        t1  = TOC_US(t);
        std::cout << "Re-Encryption time at hop " << i + 1 << "\t" << t1 / 1000.0 << " ms" << std::endl;

        if (i < numHops - 1)
            cc->ModReduceInPlace(ct1);

        ////////////////////////////////////////////////////////////
        // Decryption of Ciphertext
        ////////////////////////////////////////////////////////////

        PT ptDec2;

        TIC(t);
        cc->Decrypt(keyPairVector[i].secretKey, ct1, &ptDec2);
        t1 = TOC_US(t);
        std::cout << "Decryption time: "
                  << "\t" << t1 / 1000.0 << " ms" << std::endl;

        ptDec2->SetLength(pt->GetLength());

        auto unpacked0 = pt->GetCoefPackedValue();
        auto unpacked1 = ptDec1->GetCoefPackedValue();
        auto unpacked2 = ptDec2->GetCoefPackedValue();

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
                // std::cout << j << ", " << unpacked0[j] << ", " << unpacked1[j] << ", " << unpacked2[j] << std::endl;
                good = false;
            }
        }
        if (good) {
            std::cout << "PRE passes" << std::endl;
        }
        else {
            std::cout << "PRE fails" << std::endl;
        }
    }

    ////////////////////////////////////////////////////////////
    // Done
    ////////////////////////////////////////////////////////////

    std::cout << "Execution Completed." << std::endl;

    return good;
}
