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
  Example for the FHEW scheme using the multiparty bootstrapping method with 5 parties
 */

#include "binfhecontext.h"

using namespace lbcrypto;

int main() {
    // Crypto context generation
    auto cc                 = BinFHEContext();
    uint32_t num_of_parties = 2;
    // cc.GenerateBinFHEContext(TOY, LMKCDEY, num_of_parties);  // number of parties is 2
    cc.GenerateBinFHEContext(STD128Q_LMKCDEY_T, LMKCDEY, num_of_parties);  // number of parties is 2

    std::cout << "Q = " << cc.GetParams()->GetLWEParams()->GetQ() << std::endl;

    // DISTRIBUTED KEY GENERATION STARTS

    // PARTY 1

    // Generation of secret keys by party 1
    // Generate LWE key
    auto sk1 = cc.KeyGen();
    // Generate RGSW secret key z_1
    auto z1    = cc.RGSWKeygen();
    auto zLWE1 = std::make_shared<LWEPrivateKeyImpl>(z1.GetValues());

    // Generate public key, key switching key for the secrets
    cc.MultiPartyKeyGen(sk1, z1, cc.GetPublicKey(), cc.GetSwitchKey(), true);

    auto pk1  = cc.GetPublicKey();
    auto ksk1 = cc.GetSwitchKey();

    // PARTY 2

    // Generate secret keys for party 2
    auto sk2   = cc.KeyGen();
    auto z2    = cc.RGSWKeygen();
    auto zLWE2 = std::make_shared<LWEPrivateKeyImpl>(z2.GetValues());

    // Generate public key, key switching key for the secrets
    cc.MultiPartyKeyGen(sk2, z2, pk1, ksk1, false);

    // Common Lwe public key and key switching keys
    auto pk    = cc.GetPublicKey();
    auto kskey = cc.GetSwitchKey();

    // Switches the RGSW keys to EVALUATION representation for future operations
    cc.RGSWKeySet(z1, EVALUATION);
    cc.RGSWKeySet(z2, EVALUATION);

    // *****************************

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    // distributed generation of RGSW_{z_*}(1)
    // generate a_{crs}
    auto acrs    = cc.GenerateCRS();
    auto rgsw1_1 = cc.RGSWEncrypt(acrs, z1, 1, true);
    auto rgsw1_2 = cc.RGSWEncrypt(acrs, z2, 1);

    // create btkey with RSGW encryption of 1 for every element of the secret
    uint32_t n  = sk1->GetElement().GetLength();
    auto rgsw1  = cc.RGSWEvalAdd(rgsw1_1, rgsw1_2);
    auto rgswe1 = cc.RGSWClone(rgsw1, n);

    // distributed generation of RGSW_{z_*}(0) will be done while computing the bootstrapping key

    // generate acrs for rgsw encryptions of 0 for re-randomization
    auto acrs0 = cc.GenerateCRSMatrix(num_of_parties, n);

    // this vector is only to simulate the exchange of rgswencrypt with zi in the loop as every node
    // exchanges the rgswencrypt(0) with respect to its key. In a real implementation, this vector zvec does not exist
    std::vector<NativePoly> zvec;
    zvec.push_back(z1);
    zvec.push_back(z2);

    // generate encryptions of 0 for multiparty btkeygen
    std::vector<std::vector<RingGSWEvalKey>> rgswenc0(num_of_parties, std::vector<RingGSWEvalKey>(n));
    for (uint32_t i = 0; i < num_of_parties; i++) {  // for gen of encryption of 0 at one iteration
        for (uint32_t j = 0; j < n; j++) {           // dimension of secret
            RingGSWEvalKey rgsw0_1 = cc.RGSWEncrypt(acrs0[i][j], zvec[0], 0, true);
            RingGSWEvalKey rgswadd = rgsw0_1;
            for (uint32_t k = 1; k < num_of_parties; k++) {
                auto rgsw0_i     = cc.RGSWEncrypt(acrs0[i][j], zvec[k], 0);
                auto rgswaddtemp = cc.RGSWEvalAdd(rgsw0_i, rgswadd);
                rgswadd          = rgswaddtemp;
            }
            rgswenc0[i][j] = rgswadd;
        }
    }

    // generate acrs for rgsw encryptions of 0 for automorphism keygen
    // need to be sure this is the same value as in rgsw-acc-lmkcdey.h
    auto acrsauto = cc.GenerateCRSVector();

    // Generate the bootstrapping keys (refresh, switching and public keys)
    cc.MultipartyBTKeyGen(sk1, rgswe1, z1, acrsauto, rgswenc0[0], kskey, true);
    cc.MultipartyBTKeyGen(sk2, cc.GetRefreshKey(), z2, acrsauto, rgswenc0[1], kskey);

    std::cout << "Completed the key generation." << std::endl;

    // DISTRIBUTED KEY GENERATION ENDS

    LWEPlaintext result;
    uint32_t iterations = 250;
    for (uint32_t i = 0; i < iterations; i++) {
        // Encryption of data
        auto ct1 = cc.Encrypt(pk, 1);
        auto ct2 = cc.Encrypt(pk, 1);

        // Evaluation
        // Compute (1 AND 1) = 1; Other binary gate options are OR, NAND, and NOR
        // When the last boolean flag is set to true, extended parameters are used
        // i.e., no key switching and modulus switching is done,
        // which is required for threshold FHE (to support noise flooding)
        auto ctAND1 = cc.EvalBinGate(AND, ct1, ct2, true);

        // decryption check before computation
        std::vector<LWECiphertext> pct;
        auto pct1 = cc.MultipartyDecryptLead(zLWE1, ctAND1);
        auto pct2 = cc.MultipartyDecryptMain(zLWE2, ctAND1);

        pct.push_back(pct1);
        pct.push_back(pct2);

        cc.MultipartyDecryptFusion(pct, &result);

        std::cout << "Result of encrypted computation of (1 AND 1) mpbtkeygen = " << result << std::endl;
    }

    return 0;
}
