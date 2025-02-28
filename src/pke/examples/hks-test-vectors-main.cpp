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
  Simple examples for HKS
 */

#define PROFILE

// #include <gperftools/profiler.h>

#include "openfhe.h"

using namespace lbcrypto;

int main() {
    uint32_t multDepth    = 8;
    uint32_t scaleModSize = 10;
    usint firstModSize    = 10;
    uint32_t batchSize    = 4;
    uint32_t ringDim      = 2 * batchSize;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);
    parameters.SetRingDim(ringDim);
    usint dnum = 3;
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
    std::vector<double> x1 = {1.0, 2.0, 3.0, 4.0};

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);

    std::cout << "Input x1: " << ptxt1 << std::endl;

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);

    std::cout << "ctxt levels after fresh enc: " << c1->GetLevel() << std::endl;
    std::cout << "ctxt k fresh enc: " << c1->GetElements()[0].GetAllElements().size() << std::endl;
    std::cout << "Initial number of levels remaining: " << multDepth - c1->GetLevel() << std::endl;

    std::cout << "Ctxt data before KS: " << std::endl;
    std::cout << "ctxt0: " << c1->GetElements()[0] << std::endl;
    std::cout << "ctxt1: " << c1->GetElements()[1] << std::endl;

    // HKS will be called inside this function
    // Recall, HKS is a maintenance operation
    // Ciphertext manipulation:
    // 1.  Logical lest rotation (by 1).
    // 2.  Hybrid Key Switching (HKS) to correct the resulting ciphertext structure.
    // Note: OpenFHE internally reverses this order, performing HKS-related mixing before rotation.
    //      This pre-mixing ensures the subsequent rotation's internal mixing cancels the initial adjustment.
    auto cRot1 = cc->EvalRotate(c1, 1);

    std::cout << "Ctxt data after KS: " << std::endl;
    std::cout << "ctxt0: " << cRot1->GetElements()[0] << std::endl;
    std::cout << "ctxt1: " << cRot1->GetElements()[1] << std::endl;

    // Step 5: Decryption and output
    Plaintext result;
    // We set the cout precision to 8 decimal digits for a nicer output.
    // If you want to see the error/noise introduced by CKKS, bump it up
    // to 15 and it should become visible.
    std::cout.precision(8);

    std::cout << std::endl << "Results of homomorphic computations: " << std::endl;

    cc->Decrypt(keys.secretKey, c1, &result);
    result->SetLength(batchSize);
    std::cout << "x1 = " << result;
    std::cout << "Estimated precision in bits: " << result->GetLogPrecision() << std::endl;

    // Decrypt the result of rotations

    cc->Decrypt(keys.secretKey, cRot1, &result);
    result->SetLength(batchSize);
    std::cout << std::endl << "In rotations, very small outputs (~10^-10 here) correspond to 0's:" << std::endl;
    std::cout << "x1 rotate by 1 = " << result << std::endl;

    return 0;
}
