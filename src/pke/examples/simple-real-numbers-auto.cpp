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
    std::cout << "main HKS started ... \n\n";

    // Step 1: Setup CryptoContext
    // multdepth is the longest chain of multiplications
    uint32_t multDepth = 32; // to ensure L=33 = multdepth + 1, 1 for encryption level

#if NATIVEINT == 128
    // Currently, only FIXEDMANUAL and FIXEDAUTO modes are supported for 128-bit CKKS bootstrapping.
    ScalingTechnique rescaleTech = FIXEDAUTO;
    usint scaleModSize               = 78;
    usint firstModSize               = 89;
#else
    // All modes are supported for 64-bit CKKS bootstrapping.
    ScalingTechnique rescaleTech = FLEXIBLEAUTO;
    usint scaleModSize               = 59;
    usint firstModSize               = 60;
#endif


    CCParams<CryptoContextCKKSRNS> parameters;

    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetSecurityLevel(HEStd_NotSet); // use HEStd_128_classic for 128-bit security level;
    parameters.SetRingDim(16); // set ring dimension (N) for fast runtime
    // HKS with dnum
    // Q is the ciphertext coefficient modulus
    // P is an auxiliary RNS modulus used in intermediate computations (mainly, rounding and scaling)
    usint dnum = 3; // P = Q/dnum
    parameters.SetKeySwitchTechnique(KeySwitchTechnique::HYBRID);
    parameters.SetNumLargeDigits(dnum); //
//    // BV
//    parameters.SetKeySwitchTechnique(KeySwitchTechnique::HYBRID);
//    parameters.SetNumLargeDigits(multDepth + 1); // no P
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
    cc->EvalRotateKeyGen(keys.secretKey,
        {1}); // Generate the rotation keys
    //     {0,1,2,3,4,5,6,7,8,-1,-2,-3,-4,-5,-6,-7,-8}); // Generate the rotation keys

        auto print_moduli_chain = [](const DCRTPoly& poly){
        int num_primes = poly.GetNumOfElements();
        double total_bit_len = 0.0;
        for (int i = 0; i < num_primes; i++) {
            auto qi = poly.GetParams()->GetParams()[i]->GetModulus();
            std::cout << "q_" << i << ": " 
                        << qi
                        << ",  log q_" << i <<": " << log(qi.ConvertToDouble()) / log(2)
                        << std::endl;
            total_bit_len += log(qi.ConvertToDouble()) / log(2);
        }   
        std::cout << "Total bit length: " << total_bit_len << std::endl;
    };
    const std::vector<DCRTPoly>& ckks_pk = keys.publicKey->GetPublicElements();
    std::cout << "Moduli chain of pk: " << std::endl;
    print_moduli_chain(ckks_pk[0]);

    std::cout << "user input parameters: \n" << parameters << "\n";

    std::cout << "cc->crypto parameters: \n" << *cc->GetCryptoParameters() << "\n";
    
    // Step 3: Encoding and encryption of inputs
    // Input
    std::vector<double> x1 = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};
    
    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
    std::cout << "Input x1: " << ptxt1 << std::endl;
    
    // Encrypt the encoded vector
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
    
    // Step 4: Evaluation
    // positive rotation indix rotate left
    // negative rotation index rotate right
    auto cRot1 = cc->EvalRotate(c1, 1);
    
    // Step 5: Decryption and output
    Plaintext result;
    
    // We set the cout precision to 8 decimal digits for a nicer output.
    // If you want to see the error/noise introduced by CKKS, bump it up
    // to 15 and it should become visible.
    std::cout.precision(8);
    std::cout << std::endl << "Results of homomorphic computations: " << std::endl;

    // Decrypt the result of rotations
    cc->Decrypt(keys.secretKey, cRot1, &result);

    std::cout << "x1 = \n" << ptxt1;
    std::cout << "Estimated precision in bits: " << result->GetLogPrecision() << std::endl;
    std::cout << std::endl << "In rotations, very small outputs (~10^-10 here) correspond to 0's:" << std::endl;
    std::cout << "x1 rotated by 1 = \n" << result << std::endl;
    std::cout << "main HKS terminated gracefully!\n\n";
    return 0;
}
