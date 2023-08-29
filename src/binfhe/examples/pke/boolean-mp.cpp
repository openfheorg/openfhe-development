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
    // Sample Program: Step 1: Set CryptoContext

    auto cc                 = BinFHEContext();
    uint32_t num_of_parties = 5;

    // STD128 is the security level of 128 bits of security based on LWE Estimator
    // and HE standard. Other common options are TOY, MEDIUM, STD192, and STD256.
    // MEDIUM corresponds to the level of more than 100 bits for both quantum and
    // classical computer attacks.
    cc.GenerateBinFHEContext(TOY, LMKCDEY, num_of_parties);  // number of parties is 5

    // Generate the secret keys s1, z1
    auto sk1 = cc.KeyGen();
    // generate RGSW secret key z_1
    auto z1 = cc.RGSWKeygen();

    // generate public key, key switching key for the secrets
    cc.MultiPartyKeyGen(sk1, z1, cc.GetPublicKey(), cc.GetSwitchKey(), true);
    auto pk1  = cc.GetPublicKey();
    auto ct11 = cc.Encrypt(pk1, 1);

    auto sk2 = cc.KeyGen();
    auto z2  = cc.RGSWKeygen();

    // generate public key, key switching key for the secrets
    cc.MultiPartyKeyGen(sk2, z2, cc.GetPublicKey(), cc.GetSwitchKey(), false);
    auto pk2  = cc.GetPublicKey();
    auto ct22 = cc.Encrypt(pk2, 0);

    auto sk3 = cc.KeyGen();
    auto z3  = cc.RGSWKeygen();

    // generate public key, key switching key for the secrets
    cc.MultiPartyKeyGen(sk3, z3, cc.GetPublicKey(), cc.GetSwitchKey(), false);
    auto pk3 = cc.GetPublicKey();

    auto sk4 = cc.KeyGen();
    auto z4  = cc.RGSWKeygen();

    // generate public key, key switching key for the secrets
    cc.MultiPartyKeyGen(sk4, z4, cc.GetPublicKey(), cc.GetSwitchKey(), false);

    auto sk5 = cc.KeyGen();
    auto z5  = cc.RGSWKeygen();

    // generate public key, key switching key for the secrets
    cc.MultiPartyKeyGen(sk5, z5, cc.GetPublicKey(), cc.GetSwitchKey(), false);

    // common lwe public key
    auto pk    = cc.GetPublicKey();
    auto kskey = cc.GetSwitchKey();

    z1.SetFormat(EVALUATION);
    z2.SetFormat(EVALUATION);
    z3.SetFormat(EVALUATION);
    z4.SetFormat(EVALUATION);
    z5.SetFormat(EVALUATION);

    auto ct1 = cc.Encrypt(pk, 1);
    auto ct2 = cc.Encrypt(pk, 0);

    std::cout << "Generating the bootstrapping keys..." << std::endl;
    // distributed generation of RGSW_{z_*}(1)
    // generate a_{crs}

    auto acrs = cc.Generateacrs();

    auto rgsw1_1 = cc.RGSWEncrypt(acrs, z1, 1, true);
    auto rgsw1_2 = cc.RGSWEncrypt(acrs, z2, 1);
    auto rgsw1_3 = cc.RGSWEncrypt(acrs, z3, 1);
    auto rgsw1_4 = cc.RGSWEncrypt(acrs, z4, 1);
    auto rgsw1_5 = cc.RGSWEncrypt(acrs, z5, 1);

    auto rgsw12   = cc.RGSWEvalAdd(rgsw1_1, rgsw1_2);
    auto rgsw123  = cc.RGSWEvalAdd(rgsw12, rgsw1_3);
    auto rgsw1234 = cc.RGSWEvalAdd(rgsw123, rgsw1_4);
    auto rgsw1    = cc.RGSWEvalAdd(rgsw1234, rgsw1_5);

    // create btkey with RSGW encryption of 1 for every element of the secret
    uint32_t n = sk1->GetElement().GetLength();

    RingGSWACCKey rgswe1 = std::make_shared<RingGSWACCKeyImpl>(1, 2, n);
    for (size_t i = 0; i < n; i++) {
        (*rgswe1)[0][0][i] = rgsw1;
    }
    // distributed generation of RGSW_{z_*}(0) will be done while computing the bootstrapping key

    // generate acrs for rgsw encryptions of 0 for re-randomization
    std::vector<std::vector<std::vector<NativePoly>>> acrs0(
        num_of_parties, std::vector<std::vector<NativePoly>>(num_of_parties, std::vector<NativePoly>(n)));
    for (uint32_t i = 0; i < num_of_parties; i++) {      // number of iterations in sequence
        for (uint32_t j = 0; j < num_of_parties; j++) {  // for gen of encryption of 0 at one iteration
            for (uint32_t k = 0; k < n; k++) {           // dimension of secret
                acrs0[i][j][k] = cc.Generateacrs();
            }
        }
    }

    // this vector is only to simulate the exchange of rgswencrypt with zi in the loop as every node
    // exchanges the rgswencrypt(0) with respect to its key. In a real implementation, this vector zvec does not exist
    std::vector<NativePoly> zvec;
    zvec.push_back(z1);
    zvec.push_back(z2);
    zvec.push_back(z3);
    zvec.push_back(z4);
    zvec.push_back(z5);

    // generate encryptions of 0 for multiparty btkeygen
    std::vector<std::vector<RingGSWEvalKey>> rgswenc0(num_of_parties, std::vector<RingGSWEvalKey>(n));
    for (uint32_t i = 0; i < num_of_parties; i++) {  // for gen of encryption of 0 at one iteration
        for (uint32_t j = 0; j < n; j++) {           // dimension of secret
            RingGSWEvalKey rgsw0_1 = cc.RGSWEncrypt(acrs0[0][1][i], zvec[0], 0, true);
            RingGSWEvalKey rgswadd = rgsw0_1;
            for (uint32_t k = 1; k < num_of_parties; k++) {
                auto rgsw0_i = cc.RGSWEncrypt(acrs0[0][1][i], zvec[k], 0);
                rgswadd      = cc.RGSWEvalAdd(rgsw0_i, rgswadd);
            }
            rgswenc0[i][j] = rgswadd;
        }
    }

    // generate acrs for rgsw encryptions of 0 for automorphism keygen
    uint32_t digitsG  = cc.GetParams()->GetRingGSWParams()->GetDigitsG();
    uint32_t m_window = 10;  // need to be sure this is the same value in rgsw-acc-lmkcdey.h
    std::vector<std::vector<NativePoly>> acrsauto(m_window + 1, std::vector<NativePoly>(digitsG));
    for (uint32_t i = 0; i < m_window + 1; i++) {
        for (uint32_t j = 0; j < digitsG; j++) {
            acrsauto[i][j] = cc.Generateacrs();
        }
    }

    // Generate the bootstrapping keys (refresh, switching and public keys)
    cc.MultipartyBTKeyGen(sk1, rgswe1, z1, acrsauto, rgswenc0[0], kskey);

    cc.MultipartyBTKeyGen(sk2, cc.GetRefreshKey(), z2, acrsauto, rgswenc0[1], kskey);

    cc.MultipartyBTKeyGen(sk3, cc.GetRefreshKey(), z3, acrsauto, rgswenc0[2], kskey);

    cc.MultipartyBTKeyGen(sk4, cc.GetRefreshKey(), z4, acrsauto, rgswenc0[3], kskey);

    cc.MultipartyBTKeyGen(sk5, cc.GetRefreshKey(), z5, acrsauto, rgswenc0[4], kskey);

    // cc.insertRefreshKey(rgswp5);

    std::cout << "Completed the key generation." << std::endl;

    // Sample Program: Step 4: Evaluation

    // Compute (1 AND 1) = 1; Other binary gate options are OR, NAND, and NOR
    auto ctAND1 = cc.EvalBinGate(AND, ct1, ct2);

    LWEPlaintext result;

    // decryption check before computation
    std::vector<LWECiphertext> pct;
    auto pct1 = cc.MultipartyDecryptLead(sk1, ctAND1);
    auto pct2 = cc.MultipartyDecryptMain(sk2, ctAND1);
    auto pct3 = cc.MultipartyDecryptMain(sk3, ctAND1);
    auto pct4 = cc.MultipartyDecryptMain(sk4, ctAND1);
    auto pct5 = cc.MultipartyDecryptMain(sk5, ctAND1);

    pct.push_back(pct1);
    pct.push_back(pct2);
    pct.push_back(pct3);
    pct.push_back(pct4);
    pct.push_back(pct5);

    cc.MultipartyDecryptFusion(pct, &result);

    std::cout << "Result of encrypted computation of (1 AND 0) = " << result << std::endl;

    return 0;
}
