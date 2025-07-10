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

#include "openfhe.h"

#include <vector>
#include <iostream>

using namespace lbcrypto;

void BootstrapExample(uint32_t ring_dim);

int main(int argc, char* argv[]) {
    BootstrapExample(1 << 17);
}

void BootstrapExample(uint32_t ring_dim) {
    uint32_t batch_size = ring_dim >> 1;

    ScalingTechnique rescale_tech = FLEXIBLEAUTO;
    auto dcrt_bits                = 59;
    auto first_mod                = 60;
    SecretKeyDist secret_key_dist = UNIFORM_TERNARY;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecretKeyDist(secret_key_dist);
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetRingDim(ring_dim);
    parameters.SetNumLargeDigits(3);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetScalingModSize(dcrt_bits);
    parameters.SetScalingTechnique(rescale_tech);
    parameters.SetFirstModSize(first_mod);
    parameters.SetBatchSize(batch_size);

    std::vector<uint32_t> level_budget        = {4, 4};
    uint32_t levels_available_after_bootstrap = 20;
    uint32_t depth_bootstrap                  = FHECKKSRNS::GetBootstrapDepth(level_budget, secret_key_dist);
    uint32_t depth                            = levels_available_after_bootstrap + depth_bootstrap;
    parameters.SetMultiplicativeDepth(depth);

    CryptoContext<DCRTPoly> cryptocontext = GenCryptoContext(parameters);
    cryptocontext->Enable(PKE);
    cryptocontext->Enable(KEYSWITCH);
    cryptocontext->Enable(LEVELEDSHE);
    cryptocontext->Enable(ADVANCEDSHE);
    cryptocontext->Enable(FHE);

    int64_t num_slots = batch_size;
    auto key_pair     = cryptocontext->KeyGen();
    cryptocontext->EvalMultKeyGen(key_pair.secretKey);
    cryptocontext->EvalBootstrapSetup(level_budget, {0, 0}, num_slots);
    cryptocontext->EvalBootstrapKeyGen(key_pair.secretKey, num_slots);

    std::vector<double> x;
    x.reserve(num_slots);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(-1.0, 1.0);
    for (auto i = 0; i < num_slots; ++i)
        x.push_back(dis(gen));

    //    std::vector<double> x(num_slots);
    //    for (uint32_t i = 0; i < num_slots; ++i)
    //        x[i] = (i & 0x1) ? -1. : 1.;

    std::cout << "Input Result:\n";
    for (auto i = 0; i < 10; ++i)
        std::cout << "  " << x[i];
    std::cout << "\n\n";

    auto ptx = cryptocontext->MakeCKKSPackedPlaintext(x, 1, depth - 1, nullptr, num_slots);
    ptx->SetLength(num_slots);

    //    std::cout << "ptx\n" << ptx << "\n";

    auto ctx = cryptocontext->Encrypt(key_pair.publicKey, ptx);

    // std::cout << "ctx\n" << ctx << "\n";

    std::cout << ctx->GetLevel() << " " << (depth - ctx->GetLevel()) << "\n";

    auto ctx_refreshed = cryptocontext->EvalBootstrap(ctx);

    //    std::cout << "ctx_refreshed\n" << ctx_refreshed << "\n";

    Plaintext res_ptx;
    cryptocontext->Decrypt(key_pair.secretKey, ctx_refreshed, &res_ptx);
    res_ptx->SetLength(batch_size);

    //    std::cout << "res_ptx\n" << res_ptx << "\n";

    auto res_vec = res_ptx->GetRealPackedValue();

    std::cout << "Decrypted Result:\n";
    for (auto i = 0; i < 10; ++i)
        std::cout << "  " << res_vec[i];
    std::cout << "\n\n";

    double sumx = 0.;
    for (auto i = 0; i < num_slots; ++i)
        sumx += std::abs(x[i] - res_vec[i]);
    std::cout << "Total Error: " << sumx;
    std::cout << "\nMean Error: " << (sumx / num_slots) << "\n";
}
