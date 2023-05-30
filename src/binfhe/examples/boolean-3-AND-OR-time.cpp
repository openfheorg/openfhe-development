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
  Example for the FHEW scheme using the default bootstrapping method (GINX)
 */
#define PROFILE

#include "binfhecontext.h"
#include "utils/sertype.h"
#include "utils/serial.h"
#include <getopt.h>

using namespace lbcrypto;

usint dim_n  = 0;
int64_t Qks  = 0;
usint dim_N  = 0;
usint ctmodq = 0;
usint logQ   = 0;
usint B_g    = 0;
usint B_ks   = 0;
usint B_rk   = 32;
usint sigma  = 3.19;

void usage() {
    std::cout << "-n Lattice Dimension"
              << "-N Ring dimension"
              << "-q ct modulus"
              << "-Q size of ring modulus"
              << "-k Size of kew switching mod Qks"
              << "-g Digit base B_g"
              << "-r Refreshing key base B_rk"
              << "-b Key switching base B_ks"
              << "-s sigma (standard deviation)" << std::endl;
}
int main(int argc, char* argv[]) {
    // Sample Program: Step 1: Set CryptoContext
    TimeVar t;
    auto cc = BinFHEContext();

    char opt(0);
    //*********************
    static struct option long_options[] = {{"Lattice dimension", required_argument, NULL, 'n'},
                                           {"Ring dimension", required_argument, NULL, 'N'},
                                           {"ct modulus", required_argument, NULL, 'q'},
                                           {"size of ring modulus", required_argument, NULL, 'Q'},
                                           {"size of kew switching mod Qks", required_argument, NULL, 'k'},
                                           {"Digit base B_g", required_argument, NULL, 'g'},
                                           {"Refreshing key base B_rk", required_argument, NULL, 'r'},
                                           {"Key switching base B_ks", required_argument, NULL, 'b'},
                                           {"sigma (standard deviation)", required_argument, NULL, 's'},
                                           {"help", no_argument, NULL, 'h'},
                                           {NULL, 0, NULL, 0}};

    const char* optstring = "n:N:q:Q:k:g:r:b:s:h";
    while ((opt = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
        std::cout << "opt1: " << opt << "; optarg: " << optarg << std::endl;
        switch (opt) {
            case 'n':
                dim_n = atoi(optarg);
                break;
            case 'N':
                dim_N = atoi(optarg);
                break;
            case 'Q':
                logQ = atoi(optarg);
                break;
            case 'q':
                ctmodq = atoi(optarg);
                break;
            case 'k':
                std::stringstream(optarg) >> Qks;
                break;
            case 'g':
                B_g = atoi(optarg);
                break;
            case 'b':
                B_ks = atoi(optarg);
                break;
            case 'r':
                B_rk = atoi(optarg);
                break;
            case 's':
                sigma = atoi(optarg);
                break;
            case 'h':
                usage();
            default:
                return false;
        }
    }

    BinFHEContextParams paramset;
    paramset.cyclOrder    = 2 * dim_N;
    paramset.modKS        = Qks;
    paramset.gadgetBase   = B_g;
    paramset.baseKS       = B_ks;
    paramset.baseRK       = B_rk;
    paramset.mod          = ctmodq;
    paramset.numberBits   = logQ;
    paramset.stdDev       = sigma;
    paramset.latticeParam = dim_n;

    // ********************
    // STD128 is the security level of 128 bits of security based on LWE Estimator
    // and HE standard. Other common options are TOY, MEDIUM, STD192, and STD256.
    // MEDIUM corresponds to the level of more than 100 bits for both quantum and
    // classical computer attacks.
    // cc.GenerateBinFHEContext(STD128_AP_3, AP);

    std::cout << "parameters from commandline dim_n, dim_N, logQ, q, Qks, B_g, B_ks: "
              << " " << dim_n << " " << dim_N << " " << logQ << " " << ctmodq << " " << Qks << " " << B_g << " " << B_ks
              << std::endl;
    cc.GenerateBinFHEContext(paramset);

    // Sample Program: Step 2: Key Generation

    // Generate the secret key
    auto sk = cc.KeyGen();

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    TIC(t);
    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(sk);

    auto es = TOC_MS(t);
    std::cout << "time for bootstrapping key generation " << es << " milliseconds" << std::endl;

    auto bkey  = cc.GetRefreshKey();
    auto kskey = cc.GetSwitchKey();
    std::ostringstream bkeystring;
    lbcrypto::Serial::Serialize(bkey, bkeystring, lbcrypto::SerType::BINARY);
    std::cout << "bootstrapping key size: " << bkeystring.str().size() << std::endl;

    std::ostringstream kskeystring;
    lbcrypto::Serial::Serialize(kskey, kskeystring, lbcrypto::SerType::BINARY);
    std::cout << "key switching key size: " << kskeystring.str().size() << std::endl;

    std::cout << "Completed the key generation." << std::endl;

    // Sample Program: Step 3: Encryption

    // Encrypt two ciphertexts representing Boolean True (1).
    // By default, freshly encrypted ciphertexts are bootstrapped.
    // If you wish to get a fresh encryption without bootstrapping, write
    // auto   ct1 = cc.Encrypt(sk, 1, FRESH);
    auto p   = 6;
    auto ct1 = cc.Encrypt(sk, 1, SMALL_DIM, p);
    auto ct2 = cc.Encrypt(sk, 1, SMALL_DIM, p);
    auto ct3 = cc.Encrypt(sk, 0, SMALL_DIM, p);
    auto ct4 = cc.Encrypt(sk, 0, SMALL_DIM, p);
    auto ct5 = cc.Encrypt(sk, 1, SMALL_DIM, p);
    auto ct6 = cc.Encrypt(sk, 0, SMALL_DIM, p);

    std::ostringstream ctstring;
    lbcrypto::Serial::Serialize(ct1, ctstring, lbcrypto::SerType::BINARY);
    std::cout << "ciphertext size: " << ctstring.str().size() << std::endl;
    std::cout << "ciphertext modulus: " << ct1->GetModulus() << std::endl;
    std::cout << "ciphertext dimension n: " << ct1->GetLength() << std::endl;

    // Sample Program: Step 4: Evaluation
    TIC(t);
    // 1, 0, 0
    auto ctAND1 = cc.EvalBinGateThreeInput(AND3, ct1, ct3, ct4);

    // 1, 1, 0
    auto ctAND2 = cc.EvalBinGateThreeInput(AND3, ct1, ct2, ct3);

    // 1, 1, 1
    auto ctAND3 = cc.EvalBinGateThreeInput(AND3, ct1, ct2, ct5);

    // 0, 0, 0
    auto ctAND4 = cc.EvalBinGateThreeInput(AND3, ct3, ct4, ct6);

    // 1, 0, 0
    auto ctOR1 = cc.EvalBinGateThreeInput(OR3, ct1, ct3, ct4);
    // 1, 1, 0
    auto ctOR2 = cc.EvalBinGateThreeInput(OR3, ct1, ct2, ct3);

    // 1, 1, 1
    auto ctOR3 = cc.EvalBinGateThreeInput(OR3, ct1, ct2, ct5);

    // 1, 1, 1
    auto ctOR4 = cc.EvalBinGateThreeInput(OR3, ct3, ct4, ct6);

    es = TOC_MS(t);
    std::cout << "time for gate evaluation " << es << " milliseconds" << std::endl;

    LWEPlaintext result;

    cc.Decrypt(sk, ctAND1, &result, p);
    std::cout << "Result of encrypted computation of AND(1, 0, 0) = " << result << std::endl;
    if (result != 0)
        OPENFHE_THROW(math_error, "Decryption failure");

    cc.Decrypt(sk, ctAND2, &result, p);
    std::cout << "Result of encrypted computation of AND(1, 1, 0) = " << result << std::endl;
    if (result != 0)
        OPENFHE_THROW(math_error, "Decryption failure");

    cc.Decrypt(sk, ctAND3, &result, p);
    std::cout << "Result of encrypted computation of AND(1, 1, 1) = " << result << std::endl;
    if (result != 1)
        OPENFHE_THROW(math_error, "Decryption failure");

    cc.Decrypt(sk, ctAND4, &result, p);
    std::cout << "Result of encrypted computation of AND(0, 0, 0) = " << result << std::endl;
    if (result != 0)
        OPENFHE_THROW(math_error, "Decryption failure");

    cc.Decrypt(sk, ctOR1, &result, p);
    std::cout << "Result of encrypted computation of OR(1, 0, 0) = " << result << std::endl;
    if (result != 1)
        OPENFHE_THROW(math_error, "Decryption failure");

    cc.Decrypt(sk, ctOR2, &result, p);
    std::cout << "Result of encrypted computation of OR(1, 1, 0) = " << result << std::endl;
    if (result != 1)
        OPENFHE_THROW(math_error, "Decryption failure");

    cc.Decrypt(sk, ctOR3, &result, p);
    std::cout << "Result of encrypted computation of OR(1, 1, 1) = " << result << std::endl;
    if (result != 1)
        OPENFHE_THROW(math_error, "Decryption failure");

    cc.Decrypt(sk, ctOR4, &result, p);
    std::cout << "Result of encrypted computation of OR(0, 0, 0) = " << result << std::endl;
    if (result != 0)
        OPENFHE_THROW(math_error, "Decryption failure");

    return 0;
}
