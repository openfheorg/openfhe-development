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
  Simple examples for CKKS
 */

#define PROFILE

#include "openfhe.h"

using namespace lbcrypto;

//extern "C" void moncontrol(int);

int main() {

	std::cout << "main MS started ... \n\n";

    // Step 1: Setup CryptoContext

	// multdepth is the longest chain of multiplications
    uint32_t multDepth = 32; // to ensure L=33 = multdepth + 1, 1 for encryption level
    uint32_t scaleModSize = 78; // precision if the fixed-point machinery
    uint32_t firstModSize = 89; // first prime (q_0) in Q, must be > scaleModSize

    CCParams<CryptoContextCKKSRNS> parameters;

    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingModSize(scaleModSize);

    parameters.SetSecurityLevel(HEStd_NotSet); // use HEStd_128_classic for 128-bit security level;
    parameters.SetRingDim(16); // set ring dimension (N) for fast runtime
    parameters.SetScalingTechnique(FIXEDMANUAL);

    // HKS with dnum
    // Q is the ciphertext coefficient modulus
    // P is an auxiliary RNS modulus used in intermediate computations (mainly, rounding and scaling)
    usint dnum = 3; // P = Q/dnum
    parameters.SetKeySwitchTechnique(KeySwitchTechnique::HYBRID);
	parameters.SetNumLargeDigits(dnum); //

//    // BV
//    parameters.SetKeySwitchTechnique(KeySwitchTechnique::HYBRID);
//    parameters.SetNumLargeDigits(33); // no P
    // or
//    parameters.SetKeySwitchTechnique(KeySwitchTechnique::BV);

//    // GHS
//    parameters.SetKeySwitchTechnique(KeySwitchTechnique::HYBRID);
//    parameters.SetNumLargeDigits(1); // Q ~= P

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

    // Step 2: Key Generation
    auto keys = cc->KeyGen(); // generate encryption key pair (pk, sk)
    cc->EvalMultKeyGen(keys.secretKey); // generate multiplication key

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<double> vec1 = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8};
    std::vector<double> vec2 = {1, 1, 0, 0, 1, 0, 0, 1};

    // Encoding as plaintexts and encrypt
    Plaintext ptxt1            = cc->MakeCKKSPackedPlaintext(vec1);
    Plaintext ptxt2            = cc->MakeCKKSPackedPlaintext(vec2);

    std::cout << "Input x1: " << ptxt1 << std::endl;
    std::cout << "Input x2: " << ptxt2 << std::endl;

	// Encrypt the encoded vector
    Ciphertext<DCRTPoly> ciph1 = cc->Encrypt(keys.publicKey, ptxt1);
    Ciphertext<DCRTPoly> ciph2 = cc->Encrypt(keys.publicKey, ptxt2);

	// Step 4: Evaluation
    Ciphertext<DCRTPoly> cmult_depth2 = cc->EvalMult(ciph1, ciph2);
    Ciphertext<DCRTPoly> cmult_depth1 = cc->Rescale(cmult_depth2);
    Ciphertext<DCRTPoly> ciphResult = cmult_depth1;

    // Step 5: Decryption and output
    Plaintext result;
    // We set the cout precision to 8 decimal digits for a nicer output.
    // If you want to see the error/noise introduced by CKKS, bump it up
    // to 15 and it should become visible.
    std::cout.precision(8);

    std::cout << std::endl << "Results of homomorphic computations: " << std::endl;

    cc->Decrypt(keys.secretKey, ciphResult, &result);
    // Decrypt input for sanity check
    std::cout << "Input x1:      " << ptxt1;
    std::cout << "Input x2:      " << ptxt2;
	std::cout << "Estimated precision in bits: " << result->GetLogPrecision() << std::endl;

    std::cout << "cMult results: " << result << "\n";

    std::cout << "main MS terminated gracefully!\n\n";

    return 0;
}
