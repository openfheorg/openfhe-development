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
    cc.GenerateBinFHEContext(TOY, LMKCDEY, num_of_parties);  // number of parties is 2

    auto nlwe   = cc.GetParams()->GetLWEParams()->Getn();
    auto qkslwe = cc.GetParams()->GetLWEParams()->GetqKS();
    // Generate the secret keys s1, z1
    // auto sk1 = cc.KeyGen();
    // DiscreteGaussianGeneratorImpl<NativeVector> dgg;
    // NativeVector sk1v = dgg.GenerateVector(nlwe, qkslwe);
    NativeVector sk1v(nlwe, qkslwe);
    for (size_t i = 0; i < nlwe; ++i) {
        sk1v[i] = 0;
    }

    LWEPrivateKey sk1 = std::make_shared<LWEPrivateKeyImpl>(sk1v);

    // generate RGSW secret key z_1
    auto z1 = cc.RGSWKeygen();

    // generate public key, key switching key for the secrets
    cc.MultiPartyKeyGen(sk1, z1, cc.GetPublicKey(), cc.GetSwitchKey(), true);
    auto pk1  = cc.GetPublicKey();
    auto ksk1 = cc.GetSwitchKey();
    auto ct11 = cc.Encrypt(pk1, 1);
    auto ct10 = cc.Encrypt(pk1, 0);

    // auto sk2 = cc.KeyGen();
    NativeVector sk2v(nlwe, qkslwe);
    for (size_t i = 0; i < nlwe; ++i) {
        sk2v[i] = 0;
    }
    LWEPrivateKey sk2 = std::make_shared<LWEPrivateKeyImpl>(sk2v);
    auto z2           = cc.RGSWKeygen();

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

    std::cout << "Result of encrypted computation of (1) dist sk1 + sk2 = " << result4 << std::endl;

    LWEPlaintext result5;
    std::vector<LWECiphertext> pct2t;
    auto pct211 = cc.MultipartyDecryptLead(sk1, ct2);
    auto pct221 = cc.MultipartyDecryptMain(sk2, ct2);

    pct2t.push_back(pct211);
    pct2t.push_back(pct221);

    cc.MultipartyDecryptFusion(pct2t, &result5);

    std::cout << "Result of encrypted computation of (0) dist sk1+sk2 = " << result5 << std::endl;

    // *****************************

    // distributed generation of RGSW_{z_*}(1)
    // generate a_{crs}

    auto acrs = cc.Generateacrs();

    auto rgsw1_1 = cc.RGSWEncrypt(acrs, z1, 1, true);
    auto rgsw1_2 = cc.RGSWEncrypt(acrs, z2, 1);

    auto rgsw1 = cc.RGSWEvalAdd(rgsw1_1, rgsw1_2);

    std::cout << "rgsw decrypt z1 + z2: " << cc.RGSWDecrypt(rgsw1, z1 + z2) << std::endl;

    // create btkey with RSGW encryption of 1 for every element of the secret
    uint32_t n = sk1->GetElement().GetLength();

    // for lmkcdey - 2nd index 0 for btkey, 2nd index 1 for auto key
    RingGSWACCKey rgswe1 = std::make_shared<RingGSWACCKeyImpl>(1, 2, n);
    for (size_t j = 0; j < 2; j++) {
        for (size_t i = 0; i < n; i++) {
            (*rgswe1)[0][j][i] = rgsw1;
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
                auto rgsw0_i     = cc.RGSWEncrypt(acrs0[i][0][j], zvec[k], 0);
                auto rgswaddtemp = cc.RGSWEvalAdd(rgsw0_i, rgswadd);
                rgswadd          = rgswaddtemp;
            }
            rgswenc0[i][j] = rgswadd;
        }
    }

    std::cout << "rgsw decrypt 0 z1 + z2: " << cc.RGSWDecrypt(rgswenc0[0][0], z1 + z2) << std::endl;
    // generate acrs for rgsw encryptions of 0 for automorphism keygen
    uint32_t digitsG  = cc.GetParams()->GetRingGSWParams()->GetDigitsG();
    uint32_t m_window = 10;  // need to be sure this is the same value in rgsw-acc-lmkcdey.h
    std::vector<std::vector<NativePoly>> acrsauto(m_window + 1, std::vector<NativePoly>(digitsG));
    for (uint32_t i = 0; i < m_window + 1; i++) {
        for (uint32_t j = 0; j < digitsG; j++) {
            acrsauto[i][j] = cc.Generateacrs();
        }
    }

    std::cout << "********************************" << std::endl;
    std::cout << "sk1[0]: " << sk1->GetElement()[0] << std::endl;
    std::cout << "sk2[0]: " << sk2->GetElement()[0] << std::endl;

    (*rgsw1)[0][0].SetFormat(COEFFICIENT);
    std::cout << "rgsw1: " << (*rgsw1)[0][0] << std::endl;
    //-----------------------------------
    // Generate the bootstrapping keys (refresh, switching and public keys)
    cc.MultipartyBTKeyGen(sk1, rgswe1, z1, acrsauto, rgswenc0[0], kskey, true);
    // (*(*cc.GetRefreshKey())[0][1][0])[0][0].SetFormat(COEFFICIENT);
    // std::cout << "refresh key sk1 MultipartyBTKeyGen: " << (*(*cc.GetRefreshKey())[0][1][0])[0][0] << std::endl;
    // (*(*cc.GetRefreshKey())[0][1][0])[0][0].SetFormat(EVALUATION);

    cc.MultipartyBTKeyGen(sk2, cc.GetRefreshKey(), z2, acrsauto, rgswenc0[1], kskey);
    (*(*cc.GetRefreshKey())[0][0][0])[0][0].SetFormat(COEFFICIENT);
    std::cout << "refresh key sk1+sk2 with MultipartyBTKeyGen: " << (*(*cc.GetRefreshKey())[0][0][0])[0][0]
              << std::endl;
    (*(*cc.GetRefreshKey())[0][0][0])[0][0].SetFormat(EVALUATION);

    auto mprefkey = cc.GetRefreshKey();

    std::cout << "Completed the key generation." << std::endl;

    // check if the switching keys are the same before and after btkeygen
    auto kskeyc = cc.GetSwitchKey();

    auto kskeychkbool = (kskey == kskeyc);
    std::cout << "kskey check: " << kskeychkbool << std::endl;
    // Sample Program: Step 4: Evaluation

    // Compute (1 AND 1) = 1; Other binary gate options are OR, NAND, and NOR
    auto ctAND1 = cc.EvalBinGate(AND, ct1, ct2);
    // auto ct1AND1 = cc.EvalBinGate(AND, ct11, ct10);

    LWEPlaintext result;

    // decryption check before computation
    std::vector<LWECiphertext> pct;
    auto pct1 = cc.MultipartyDecryptLead(sk1, ctAND1);
    auto pct2 = cc.MultipartyDecryptMain(sk2, ctAND1);

    pct.push_back(pct1);
    pct.push_back(pct2);

    cc.MultipartyDecryptFusion(pct, &result);

    std::cout << "Result of encrypted computation of (1 AND 0) mpbtkeygen = " << result << std::endl;

    auto sk12v         = sk1->GetElement() + sk2->GetElement();
    LWEPrivateKey sk12 = std::make_shared<LWEPrivateKeyImpl>(sk12v);
    cc.BTKeyGenTest(sk12, z1 + z2, acrs, kskey);
    (*(*cc.GetRefreshKey())[0][0][0])[0][0].SetFormat(COEFFICIENT);
    std::cout << "refresh key sk1 + sk2 BTKeyGenTest 1st : " << (*(*cc.GetRefreshKey())[0][0][0])[0][0] << std::endl;
    (*(*cc.GetRefreshKey())[0][0][0])[0][0].SetFormat(EVALUATION);

    auto srefkey = cc.GetRefreshKey();
    auto ctAND2  = cc.EvalBinGate(AND, ct1, ct2);

    LWEPlaintext result1c;

    // decryption check before computation
    std::vector<LWECiphertext> pct1c;
    auto pct11c = cc.MultipartyDecryptLead(sk1, ctAND2);
    auto pct21c = cc.MultipartyDecryptMain(sk2, ctAND2);

    pct1c.push_back(pct11c);
    pct1c.push_back(pct21c);

    cc.MultipartyDecryptFusion(pct1c, &result1c);

    std::cout << "Result of encrypted computation of (1 AND 0) single = " << result1c << std::endl;

    // verify refreshkeys from mpkeygen and singlekeygen functions
    auto digitsG2 = digitsG * 2;

    for (size_t i = 0; i < 2; i++) {
        for (size_t j = 1; j < n; ++j) {
            for (uint32_t l = 0; i < digitsG2; i++) {
                for (uint32_t m = 0; j < 2; j++) {
                    (*(*srefkey)[0][i][j])[l][m].SetFormat(COEFFICIENT);
                    (*(*mprefkey)[0][i][j])[l][m].SetFormat(COEFFICIENT);
                    if ((*(*srefkey)[0][i][j])[l][m] != (*(*mprefkey)[0][i][j])[l][m]) {
                        std::cout << "indexes of [n baseR digitR digitsG2 rgswcol]: " << i << " " << j << " " << l
                                  << " " << m << std::endl;

                        std::cout << "refresh key sk1+sk2 with MultipartyBTKeyGen not matching: "
                                  << (*(*srefkey)[0][i][j])[l][m] << std::endl;
                        std::cout << "refresh key sk1+sk2 with MultipartyBTKeyGen not matching: "
                                  << (*(*mprefkey)[0][i][j])[l][m] << std::endl;
                    }
                    (*(*srefkey)[0][i][j])[l][m].SetFormat(EVALUATION);
                    (*(*mprefkey)[0][i][j])[l][m].SetFormat(EVALUATION);
                }
            }
        }
    }
    // LWEPlaintext pt1;
    // cc.Decrypt(sk1, ct1AND1, &pt1);
    // std::cout << "Result of encrypted computation of (1 AND 0) sk1 = " << pt1 << std::endl;

    return 0;
}
