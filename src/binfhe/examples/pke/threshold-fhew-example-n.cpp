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

constexpr uint32_t num_of_parties = 5;
constexpr uint32_t iterations = 25;

void setup(BinFHEContext& cc, uint32_t parties, LWEPublicKey& pk, std::vector<LWEPrivateKey>& zLWEKeys) {
    std::cout << "Q = " << cc.GetParams()->GetLWEParams()->GetQ() << std::endl;

    zLWEKeys.reserve(parties);

    std::vector<LWEPrivateKey> sk;
    sk.reserve(parties);

    std::vector<NativePoly> zvec;
    zvec.reserve(parties);

    LWESwitchingKey kskey = cc.GetSwitchKey();

    for (uint32_t i = 0; i < parties; ++i) {
        sk.emplace_back(cc.KeyGen());
        zvec.emplace_back(cc.RGSWKeygen());
        zLWEKeys.emplace_back(std::make_shared<LWEPrivateKeyImpl>(zvec.back().GetValues()));

        cc.MultiPartyKeyGen(sk.back(), zvec.back(), pk, kskey, (i == 0));
        cc.RGSWKeySet(zvec.back(), EVALUATION);

        pk    = cc.GetPublicKey();
        kskey = cc.GetSwitchKey();
    }

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    auto acrs = cc.GenerateCRS();
    auto rgsw = cc.RGSWEncrypt(acrs, zvec[0], 1, true);
    for (uint32_t i = 1; i < parties; ++i)
        rgsw = cc.RGSWEvalAdd(rgsw, cc.RGSWEncrypt(acrs, zvec[i], 1));

    uint32_t n  = sk[0]->GetElement().GetLength();
    auto rgswe  = cc.RGSWClone(rgsw, n);
    auto acrs0  = cc.GenerateCRSMatrix(parties, n);

    std::vector<std::vector<RingGSWEvalKey>> rgswenc0(parties);
    for (uint32_t i = 0; i < parties; ++i) {
        rgswenc0[i].reserve(n);
        for (uint32_t j = 0; j < n; ++j) {
            rgswenc0[i].emplace_back(cc.RGSWEncrypt(acrs0[i][j], zvec[0], 0, true));
            for (uint32_t k = 1; k < parties; ++k) {
                rgswenc0[i][j] = cc.RGSWEvalAdd(rgswenc0[i][j], cc.RGSWEncrypt(acrs0[i][j], zvec[k], 0));
            }
        }
    }

    auto acrsauto = cc.GenerateCRSVector();
    cc.MultipartyBTKeyGen(sk[0], rgswe, zvec[0], acrsauto, rgswenc0[0], kskey, true);
    for (uint32_t i = 1; i < parties; ++i)
        cc.MultipartyBTKeyGen(sk[i], cc.GetRefreshKey(), zvec[i], acrsauto, rgswenc0[i], kskey);

    std::cout << "Completed the key generation." << std::endl;
}

int main() {
    auto cc                 = BinFHEContext();
    auto pk = cc.GetPublicKey();
    std::vector<LWEPrivateKey> zLWEKeys;

    // cc.GenerateBinFHEContext(TOY, LMKCDEY, num_of_parties);
    cc.GenerateBinFHEContext(STD128Q_LMKCDEY_T, LMKCDEY, num_of_parties);


    setup(cc, num_of_parties, pk, zLWEKeys);


    LWEPlaintext result;
    std::vector<LWECiphertext> pct;
    pct.reserve(num_of_parties);
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
        pct.clear();
        pct.emplace_back(cc.MultipartyDecryptLead(zLWEKeys[0], ctAND1));
        for (uint32_t i = 1; i < num_of_parties; ++i)
            pct.emplace_back(cc.MultipartyDecryptMain(zLWEKeys[i], ctAND1));
        cc.MultipartyDecryptFusion(pct, &result);

        std::cout << "Result of encrypted computation of (1 AND 1) mpbtkeygen = " << result << std::endl;
    }

    return 0;
}
