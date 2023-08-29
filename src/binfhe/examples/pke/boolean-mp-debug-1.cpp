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
    uint32_t num_of_parties = 2;

    // STD128 is the security level of 128 bits of security based on LWE Estimator
    // and HE standard. Other common options are TOY, MEDIUM, STD192, and STD256.
    // MEDIUM corresponds to the level of more than 100 bits for both quantum and
    // classical computer attacks.
    // cc.GenerateBinFHEContext(TOY, LMKCDEY, num_of_parties);  // number of parties is 5
    cc.GenerateBinFHEContext(TOY, AP, num_of_parties);  // number of parties is 5

    // Generate the secret keys s1, z1
    auto sk1 = cc.KeyGen();
    // generate RGSW secret key z_1
    auto z1 = cc.RGSWKeygen();

    // generate public key, key switching key for the secrets
    cc.MultiPartyKeyGen(sk1, z1, cc.GetPublicKey(), cc.GetSwitchKey(), true);
    auto pk1  = cc.GetPublicKey();
    auto ksk1 = cc.GetSwitchKey();
    auto ct11 = cc.Encrypt(pk1, 1);
    auto ct10 = cc.Encrypt(pk1, 0);

    auto sk2 = cc.KeyGen();
    auto z2  = cc.RGSWKeygen();

    // generate public key, key switching key for the secrets
    cc.MultiPartyKeyGen(sk2, z2, pk1, ksk1, false);

    // common lwe public key
    auto pk    = cc.GetPublicKey();
    auto kskey = cc.GetSwitchKey();

    z1.SetFormat(EVALUATION);
    z2.SetFormat(EVALUATION);

    // LARGE_DIM specifies the dimension of the output ciphertext
    auto ctN  = cc.Encrypt(pk, 1, LARGE_DIM);
    auto ct0N = cc.Encrypt(pk, 0, LARGE_DIM);
    auto ct1  = cc.Encrypt(pk, 1);
    auto ct2  = cc.Encrypt(pk, 0);

    //**********************************
    z1.SetFormat(COEFFICIENT);
    z2.SetFormat(COEFFICIENT);

    LWEPlaintext result1;
    LWEPrivateKey sk1N = std::make_shared<LWEPrivateKeyImpl>(LWEPrivateKeyImpl(z1.GetValues()));
    LWEPrivateKey sk2N = std::make_shared<LWEPrivateKeyImpl>(LWEPrivateKeyImpl(z2.GetValues()));

    auto skv          = sk1N->GetElement() + sk2N->GetElement();
    LWEPrivateKey ska = std::make_shared<LWEPrivateKeyImpl>(skv);
    // ska->SetElement(skv);
    cc.Decrypt(ska, ctN, &result1);

    std::cout << "Result of encrypted computation of (1) ska = " << result1 << std::endl;

    LWEPlaintext result2;

    std::vector<LWECiphertext> pct0Nt;
    auto pct10 = cc.MultipartyDecryptLead(sk1N, ct0N);
    auto pct20 = cc.MultipartyDecryptMain(sk2N, ct0N);

    pct0Nt.push_back(pct10);
    pct0Nt.push_back(pct10);

    cc.MultipartyDecryptFusion(pct0Nt, &result2);

    std::cout << "Result of encrypted computation of (0) distdec N = " << result2 << std::endl;

    LWEPlaintext result3;
    cc.Decrypt(sk1, ct11, &result3);

    std::cout << "Result of encrypted computation of (1) sk1 = " << result3 << std::endl;

    LWEPlaintext result4;

    // decryption check before computation
    std::cout << "ciphertext dimension " << ct1->GetLength() << std::endl;
    std::cout << "ciphertext modulus " << ct1->GetModulus() << std::endl;
    std::vector<LWECiphertext> pct1t;
    auto pct11 = cc.MultipartyDecryptLead(sk1, ct1);
    auto pct21 = cc.MultipartyDecryptMain(sk2, ct1);

    pct1t.push_back(pct11);
    pct1t.push_back(pct21);

    cc.MultipartyDecryptFusion(pct1t, &result4);

    std::cout << "Result of encrypted computation of (1) = " << result4 << std::endl;

    LWEPlaintext result5;
    std::vector<LWECiphertext> pct2t;
    auto pct211 = cc.MultipartyDecryptLead(sk1, ct2);
    auto pct221 = cc.MultipartyDecryptMain(sk2, ct2);

    pct2t.push_back(pct211);
    pct2t.push_back(pct221);

    cc.MultipartyDecryptFusion(pct2t, &result5);

    std::cout << "Result of encrypted computation of (0) dist sk1+sk2 = " << result5 << std::endl;

    z1.SetFormat(EVALUATION);
    z2.SetFormat(EVALUATION);
    // *****************************

    // distributed generation of RGSW_{z_*}(1)
    // generate a_{crs}

    auto acrs = cc.Generateacrs();

    auto rgsw1_1 = cc.RGSWEncrypt(acrs, z1, 1, true);
    auto rgsw1_2 = cc.RGSWEncrypt(acrs, z2, 1);

    auto rgsw1 = cc.RGSWEvalAdd(rgsw1_1, rgsw1_2);

#if 0
    // *****************************
    auto rgsw1chk = cc.RGSWEncrypt(acrs, z1+z2, 1, true);
    auto rgsw0chk = cc.RGSWEncrypt(acrs, z1+z2, 0, true);
    // auto chkelements = rgsw1->GetElements();
    auto chk1elements = rgsw1chk->GetElements();
    auto chk0elements = rgsw0chk->GetElements();
    // std::cout << "chkelemsize " << chkelements.size() << std::endl;
    // std::cout << "actelemsize " << actelements.size() << std::endl;
    // std::cout << "chkelemsize[0] " << chkelements[0].size() << std::endl;
    // std::cout << "actelemsize[0] " << actelements[0].size() << std::endl;


    for (size_t i = 0; i < chk1elements.size(); i++) {
        for (size_t j = 0; j < chk1elements[0].size(); j++) {
            std::cout << "j " << j << std::endl;
            std::cout << "chk1elem[" << i << "][" << j << "] = " << chk1elements[i][j] << std::endl;
            std::cout << "chk0elem[" << i << "][" << j << "] = " << chk0elements[i][j] << std::endl;
        }
    }
#endif
    // *****************************

    // create btkey with RSGW encryption of 1 for every element of the secret
    uint32_t n = sk1->GetElement().GetLength();

#if 0
    // for lmkcdey
    RingGSWACCKey rgswe1 = std::make_shared<RingGSWACCKeyImpl>(1, 2, n);
    for (size_t i = 0; i < n; i++) {
        (*rgswe1)[0][0][i] = rgsw1;
    }
#endif

    // for dm
    uint32_t baseR                            = cc.GetParams()->GetRingGSWParams()->GetBaseR();
    const std::vector<NativeInteger>& digitsR = cc.GetParams()->GetRingGSWParams()->GetDigitsR();
    RingGSWACCKey rgswe1                      = std::make_shared<RingGSWACCKeyImpl>(n, baseR, digitsR.size());
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 1; j < baseR; ++j) {
            for (size_t k = 0; k < digitsR.size(); ++k) {
                (*rgswe1)[i][j][k] = rgsw1;
            }
        }
    }

    // distributed generation of RGSW_{z_*}(0) will be done while computing the bootstrapping key
    // Sample Program: Step 2: Key Generation

    std::cout << "Generating the bootstrapping keys..." << std::endl;

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

    // generate encryptions of 0 for multiparty btkeygen
    std::vector<std::vector<RingGSWEvalKey>> rgswenc0(num_of_parties, std::vector<RingGSWEvalKey>(n));
    for (uint32_t i = 0; i < num_of_parties; i++) {  // for gen of encryption of 0 at one iteration
        for (uint32_t j = 0; j < n; j++) {           // dimension of secret
            RingGSWEvalKey rgsw0_1 = cc.RGSWEncrypt(acrs0[i][0][j], zvec[0], 0, true);
            RingGSWEvalKey rgswadd = rgsw0_1;
            for (uint32_t k = 1; k < num_of_parties; k++) {
                auto rgsw0_i = cc.RGSWEncrypt(acrs0[i][k][j], zvec[k], 0);
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

    std::cout << "secret key sk mod in example: " << sk1->GetModulus() << std::endl;
    // std::cout << "refresh key before: " << (*cc.GetRefreshKey())[0][0][0] << std::endl;
    // Generate the bootstrapping keys (refresh, switching and public keys)
    cc.MultipartyBTKeyGen(sk1, rgswe1, z1, acrsauto, rgswenc0[0], kskey, true);

    cc.MultipartyBTKeyGen(sk2, cc.GetRefreshKey(), z2, acrsauto, rgswenc0[1], kskey);

    // check the refrsh key
    std::cout << "refresh key mp: " << (*(*cc.GetRefreshKey())[0][1][0])[0][0] << std::endl;
    auto sk12v         = sk1->GetElement() + sk2->GetElement();
    LWEPrivateKey sk12 = std::make_shared<LWEPrivateKeyImpl>(sk12v);
    cc.MultipartyBTKeyGen(sk12, rgswe1, z1 + z2, acrsauto, rgswenc0[1], kskey, true);
    std::cout << "refresh key sk1 + sk2: " << (*(*cc.GetRefreshKey())[0][1][0])[0][0] << std::endl;
    std::cout << "Completed the key generation." << std::endl;

    // Sample Program: Step 4: Evaluation

    // Compute (1 AND 1) = 1; Other binary gate options are OR, NAND, and NOR
    auto ctAND1  = cc.EvalBinGate(AND, ct1, ct2);
    auto ct1AND1 = cc.EvalBinGate(AND, ct11, ct10);

    LWEPlaintext result;

    // decryption check before computation
    std::vector<LWECiphertext> pct;
    auto pct1 = cc.MultipartyDecryptLead(sk1, ctAND1);
    auto pct2 = cc.MultipartyDecryptMain(sk2, ctAND1);

    pct.push_back(pct1);
    pct.push_back(pct2);

    cc.MultipartyDecryptFusion(pct, &result);

    std::cout << "Result of encrypted computation of (1 AND 0) = " << result << std::endl;

    LWEPlaintext pt1;
    cc.Decrypt(sk1, ct1AND1, &pt1);
    std::cout << "Result of encrypted computation of (1 AND 0) sk1 = " << pt1 << std::endl;

    return 0;
}
