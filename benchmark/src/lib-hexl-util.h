/*
 * @file lib-benchmark : library benchmark routines for comparison by build
 * @author TPOC: contact@palisade-crypto.org
 *
 * @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution. THIS SOFTWARE IS
 * PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * Context setup utility methods
 */

// Macros defining parameters to be passed to benchmarks in
// lib-hexl-benchmark.cpp
#define ADD_MICRO_HE_ARGS \
  Args({16384, 3})->Args({16384, 4})->Args({32768, 3})->Args({32768, 4})

#define ADD_MICRO_NTT_ARGS Arg(2048)->Arg(4096)->Arg(8192)->Arg(16384)

#define HEXL_BENCHMARK(BENCHMARK_NAME) \
  BENCHMARK(BENCHMARK_NAME)->Unit(benchmark::kMicrosecond)->ADD_MICRO_HE_ARGS

#define HEXL_NTT_BENCHMARK(BENCHMARK_NAME) \
  BENCHMARK(BENCHMARK_NAME)->Unit(benchmark::kMicrosecond)->ADD_MICRO_NTT_ARGS

CryptoContext<DCRTPoly> GenerateBFVrnsContext(uint32_t poly_modulus_degree,
                                              uint32_t numTowers) {
  // Set the main parameters
  uint32_t ptxtModulus = 65537;
  SecurityLevel securityLevel = HEStd_128_classic;
  double sigma = 3.19;
  uint32_t numAdds = 0;
  uint32_t numMults = numTowers - 1;
  uint32_t numKeyswitches = 0;
  uint32_t maxDepth = 5;
  uint32_t relinWindow = 30;
  uint32_t dcrtBits = 47;
  uint32_t n = poly_modulus_degree;

  // Instantiate the crypto context
  auto cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
      ptxtModulus, securityLevel, sigma, numAdds, numMults, numKeyswitches,
      MODE::OPTIMIZED, maxDepth, relinWindow, dcrtBits, n);

  // Enable features that you wish to use
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

  return cc;
}

CryptoContext<DCRTPoly> GenerateCKKSContext(uint32_t poly_modulus_degree,
                                            uint32_t numTowers) {
  // Set the main parameters
  uint32_t multDepth = numTowers - 1;
  uint32_t scaleFactorBits = 47;
  uint32_t batchSize = poly_modulus_degree / 2;
  SecurityLevel securityLevel = HEStd_128_classic;
  uint32_t ringDim = poly_modulus_degree;
  uint32_t numLargeDigits = 0;
  uint32_t maxDepth = 5;
  uint32_t firstModSize = 60;
  uint32_t relinWindow = 0;

  // Instantiate the crypto context
  auto cc = CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
      multDepth, scaleFactorBits, batchSize, securityLevel, ringDim,
      APPROXRESCALE, KeySwitchTechnique::HYBRID, numLargeDigits, maxDepth,
      firstModSize, relinWindow);

  // Enable features that you wish to use
  cc->Enable(PKESchemeFeature::ENCRYPTION);
  cc->Enable(PKESchemeFeature::SHE);
  cc->Enable(PKESchemeFeature::LEVELEDSHE);

  return cc;
}

CryptoContext<DCRTPoly> GenerateBGVrnsContext(uint32_t poly_modulus_degree,
                                              uint32_t numTowers) {
  // Set the main parameters
  uint32_t multDepth = numTowers - 1;
  uint32_t ptxtModulus = 65537;
  SecurityLevel securityLevel = HEStd_128_classic;
  double sigma = 3.19;
  uint32_t maxDepth = 5;
  uint32_t ringDim = poly_modulus_degree;
  uint32_t numLargeDigits = 0;
  uint32_t firstModSize = 60;
  uint32_t dcrtBits = 0;
  uint32_t relinWindow = 0;
  uint32_t batchSize = 0;

  // Instantiate the crypto context
  auto cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(
      multDepth, ptxtModulus, securityLevel, sigma, maxDepth, MODE::OPTIMIZED,
      KeySwitchTechnique::HYBRID, ringDim, numLargeDigits, firstModSize,
      dcrtBits, relinWindow, batchSize, ModSwitchMethod::MANUAL);

  // Enable features that you wish to use
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(LEVELEDSHE);

  return cc;
}
