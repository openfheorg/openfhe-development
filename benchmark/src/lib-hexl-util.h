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
 * Context setup utility methods
 */

#ifndef __LIB_HEXL_UTIL_H__
#define __LIB_HEXL_UTIL_H__

#include "scheme/ckksrns/cryptocontext-ckksrns.h"
#include "scheme/bfvrns/cryptocontext-bfvrns.h"
#include "scheme/bgvrns/cryptocontext-bgvrns.h"
#include "gen-cryptocontext.h"

// Macros defining parameters to be passed to benchmarks in
// lib-hexl-benchmark.cpp
#define ADD_MICRO_HE_ARGS \
  Args({16384, 3})->Args({16384, 4})->Args({32768, 3})->Args({32768, 4})

#define ADD_MICRO_NTT_ARGS Arg(2048)->Arg(4096)->Arg(8192)->Arg(16384)

#define HEXL_BENCHMARK(BENCHMARK_NAME) \
  BENCHMARK(BENCHMARK_NAME)->Unit(benchmark::kMicrosecond)->ADD_MICRO_HE_ARGS

#define HEXL_NTT_BENCHMARK(BENCHMARK_NAME) \
  BENCHMARK(BENCHMARK_NAME)->Unit(benchmark::kMicrosecond)->ADD_MICRO_NTT_ARGS

namespace lbcrypto {
    CryptoContext<DCRTPoly> GenerateBFVrnsContext(uint32_t poly_modulus_degree,
        uint32_t numTowers) {
        CCParams<CryptoContextBFVRNS> parameters;
        parameters.SetPlaintextModulus(65537);
        parameters.SetStandardDeviation(3.19);
        parameters.SetEvalMultCount(numTowers - 1);
        parameters.SetMaxDepth(5);
        parameters.SetRelinWindow(30);
        parameters.SetScalingFactorBits(47);
        parameters.SetRingDim(poly_modulus_degree);

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
        // Enable features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);

        return cc;
    }

    CryptoContext<DCRTPoly> GenerateCKKSContext(uint32_t poly_modulus_degree, uint32_t numTowers) {
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(numTowers - 1);
        parameters.SetScalingFactorBits(47);
        parameters.SetBatchSize(poly_modulus_degree / 2);
        parameters.SetRingDim(poly_modulus_degree);
        parameters.SetRescalingTechnique(FIXEDMANUAL);
        parameters.SetMaxDepth(5);
        parameters.SetFirstModSize(60);

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
        // Enable features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);

        return cc;
    }

    CryptoContext<DCRTPoly> GenerateBGVrnsContext(uint32_t poly_modulus_degree, uint32_t numTowers) {
        CCParams<CryptoContextBGVRNS> parameters;
        parameters.SetMultiplicativeDepth(numTowers - 1);
        parameters.SetPlaintextModulus(65537);
        parameters.SetMaxDepth(5);
        parameters.SetRingDim(poly_modulus_degree);
        parameters.SetFirstModSize(60);
        parameters.SetRescalingTechnique(FIXEDMANUAL);

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
        // Enable features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);

        return cc;
    }

} // namespace lbcrypto

#endif // __LIB_HEXL_UTIL_H__