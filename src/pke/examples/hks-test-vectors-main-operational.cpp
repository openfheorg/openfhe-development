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
  Simple example for operational HKS as executed in real-world applications.
  This example simulates the case were HKS is called consecutively for levels L, L-1, ... , 1  
  The examples creates a ciphertext ct_x = {1,2,3,4}
  multiplies it by a ciphertext of ones ct_ones = {1,1,1,1,...}
  multiplication by 1 calls rescale to retain the original scale factor of x
  rescale removes 1 tower from the input ciphertext ct_x
 */

#define PROFILE

// #include <gperftools/profiler.h>

#include "openfhe.h"

using namespace lbcrypto;

int main() {

    std::cout << "HKS-test-vectors-main-operational started ..." << std::endl;

    // HKS parameters (changeable parameters to test for different ring dimensions and multiplicative depth)
    uint32_t multDepth    = 20; // change this to set number of towers: num_towers = multDepth+1
    uint32_t ringDim      = 1<<13; // ring dimension (N)
    uint32_t dnum         = 3; // number of digits in HKS

    // I do not think you should change the parameters below, but if you want smaller numbers for easier debugging and tracking, change the moduli sizes below
    uint32_t scaleModSize = 50; // change this to set the bit width of moduli q1 to q_L in ciphertext modulus Q
    usint firstModSize    = 60; // change this to set the bit width of moduli q0 in ciphertext modulus Q

    uint32_t batchSize    = ringDim/2;  // number of slots
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);
    parameters.SetRingDim(ringDim);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetKeySwitchTechnique(KeySwitchTechnique::HYBRID);
    parameters.SetNumLargeDigits(dnum);  //

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

    std::cout << "crypto params: " << *cc->GetCryptoParameters() << std::endl;
    std::cout << "parameters: \n" << parameters << "\n";

    auto keys = cc->KeyGen();

    auto print_moduli_chain = [](const DCRTPoly& poly) {
        int num_primes       = poly.GetNumOfElements();
        double total_bit_len = 0.0;
        for (int i = 0; i < num_primes; i++) {
            auto qi = poly.GetParams()->GetParams()[i]->GetModulus();
            std::cout << "q_" << i << ": " << qi << ",  log q_" << i << ": " << log(qi.ConvertToDouble()) / log(2)
                      << std::endl;
            total_bit_len += log(qi.ConvertToDouble()) / log(2);
        }
        std::cout << "Total bit length: " << total_bit_len << std::endl;
    };
    const std::vector<DCRTPoly>& ckks_pk = keys.publicKey->GetPublicElements();
    std::cout << "The entire set of moduli including Q's moduli and P's moduli: " << std::endl;
    print_moduli_chain(ckks_pk[0]);

    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalRotateKeyGen(keys.secretKey, {1});

    // Inputs
    std::vector<double> x;
    std::vector<double> ones;

    for (uint32_t i = 0; i < batchSize ; i++)
    {
      x.push_back((double)i);
      ones.push_back(1.0);
    }

    // Encoding as plaintexts
    Plaintext pt_x = cc->MakeCKKSPackedPlaintext(x);
    Plaintext pt_ones = cc->MakeCKKSPackedPlaintext(ones);

    std::cout << "Input x: " << pt_x << std::endl;
    std::cout << "Input ones: " << pt_ones << std::endl;

    // Encrypt the encoded vectors
    auto ct_x = cc->Encrypt(keys.publicKey, pt_x);
    auto ct_ones = cc->Encrypt(keys.publicKey, pt_ones);
    
    std::cout << "\n\n\n<<<<<>>>>> Evaluation logic starts here\n\n\n";

    std::cout << "ctxt levels after fresh enc: " << ct_x->GetLevel() << std::endl;
    std::cout << "ctxt k fresh enc: " << ct_x->GetElements()[0].GetAllElements().size() << std::endl;
    std::cout << "Initial number of levels remaining: " << multDepth - ct_x->GetLevel() << std::endl;

    std::cout << "Ctxt data before KS: " << std::endl;
    std::cout << "ctxt0: " << ct_x->GetElements()[0] << std::endl;
    std::cout << "ctxt1: " << ct_x->GetElements()[1] << std::endl;

    // HKS will be called inside this multiplication function
    // Recall, HKS is a maintenance operation
    // Ciphertext manipulation:
    // 1.  Logical lest rotation (by 1).
    // 2.  Hybrid Key Switching (HKS) to correct the resulting ciphertext structure.
    // Note: OpenFHE internally reverses this order, performing HKS-related mixing before rotation.
    //      This pre-mixing ensures the subsequent rotation's internal mixing cancels the initial adjustment.
    for (uint32_t l = multDepth ; l > 1 ; l--)
    {
      std::cout << "Multiplication at l = " << l << std::endl;

      std::cout << "ct_x level: " << ct_x->GetLevel() << std::endl;
      std::cout << "k (# towers) in ct_x: " << ct_x->GetElements()[0].GetAllElements().size() << std::endl;
      std::cout << "Initial number of levels remaining: " << multDepth - ct_x->GetLevel() << std::endl;

      std::cout << "Ctxt data before KS: " << std::endl;
      std::cout << "ctxt0: " << ct_x->GetElements()[0] << std::endl;
      std::cout << "ctxt1: " << ct_x->GetElements()[1] << std::endl;

      // HKS switching is called inside EvalMult 
      std::cout << "HKS is called here" << std::endl;
      auto t1 = cc->EvalMult(ct_x, ct_ones);
      // rescale will drop one tower from input ct_x
      ct_x = cc->Rescale(t1);

      std::cout << "Ctxt data after Rotation: " << std::endl;
      std::cout << "ctxt0: " << ct_x->GetElements()[0] << std::endl;
      std::cout << "ctxt1: " << ct_x->GetElements()[1] << std::endl;

    }

    // Step 5: Decryption and output
    Plaintext result;
    // We set the cout precision to 8 decimal digits for a nicer output.
    // If you want to see the error/noise introduced by CKKS, bump it up
    // to 15 and it should become visible.
    std::cout.precision(8);

    std::cout << std::endl << "Results of homomorphic computations: " << std::endl;

    cc->Decrypt(keys.secretKey, ct_x, &result);
    result->SetLength(batchSize);
    std::cout << "\nx times 1 = " << result << std::endl;
    std::cout << "HKS-test-vectors-main-operational terminated gracefully!" << std::endl;

    return 0;
}
