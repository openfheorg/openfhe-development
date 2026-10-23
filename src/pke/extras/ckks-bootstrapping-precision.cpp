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
  Measures CKKS bootstrapping precision against the correction factor and fits the quantities the
  default factor is derived from.

  One-iteration precision against the factor cf is the tent p1(cf) = min(2*cf + A, B - cf): the rising
  side is the approximation error of the modular reduction (universal), and the falling side is the
  noise floor B amplified by the restoring 2^cf (configuration-dependent). The default factor is the
  crossing (B - A)/3, rounded up half a unit because the tent is asymmetric (see
  FHECKKSRNS::EstimateBootstrapNoiseFloor for the fitted B this tool calibrates).

  For each slot count the tool builds one cryptocontext and key set, re-runs EvalBootstrapSetup per
  factor (the keys stay valid), and encrypts a fresh random input per trial (bootstrapping a fixed
  ciphertext is deterministic, so repeated trials of one input measure nothing). It prints CSV rows

      logN,mode,tech,slots,cf,trial,p1,p2

  with p2 the two-iteration precision at precision input floor(p1) - 5, and a per-configuration
  summary estimating A (mean of p1 - 2*cf on the rising side), B (mean of p1 + cf on the falling side),
  the derived default max(clamp(round((B - A)/3 + 1/2), 6, 15), deg) and the measured optima. To
  refit the floor model, run this across ring dimensions, both bootstrapping orders, techniques and
  secret distributions, and regress the printed B.

  Usage: ckks-bootstrapping-precision [<logN> <stc|mr> <fa|faext|fm>
             [uniform|sparse|encap|hybrid] [lb0] [lb1] [smod] [fmod] [slots (0 = 8/128/N/2)]
             [cfMin cfMax]]
  Defaults: uniform secret, level budget {3, 3}, 59/60-bit moduli, factors 5..15. Run without
  arguments for a self-contained demonstration (N = 2^12, StC-first, FLEXIBLEAUTO, 128 slots,
  factors 5..18 so both tent sides are visible; a few minutes). Example configurations:

      ckks-bootstrapping-precision                                    the no-argument demonstration
      ckks-bootstrapping-precision 15 stc fa                          N = 2^15, slot counts 8/128/N/2
      ckks-bootstrapping-precision 14 mr fm                           ModRaise-first, FIXEDMANUAL
      ckks-bootstrapping-precision 13 stc fa sparse                   sparse secret
      ckks-bootstrapping-precision 13 stc fa encap 3 3 59 60 8 5 19   encapsulated secret, 8 slots,
                                                                      widened factors (small-ring
                                                                      optima sit high on the axis)
      ckks-bootstrapping-precision 13 stc fa uniform 3 3 50 60        50-bit scaling: deg = 10 floors
                                                                      the legal factor range
      ckks-bootstrapping-precision 14 stc fa uniform 2 2              level budget {2, 2}
*/

#include <algorithm>
#include <cmath>
#include <complex>
#include <cstdint>
#include <iostream>
#include <map>
#include <random>
#include <string>
#include <vector>

#include "openfhe.h"

using namespace lbcrypto;

namespace {

// precision as the negative base-2 logarithm of the mean L1 error, as recommended in footnote 23 of
// Security Guidelines for Implementing Homomorphic Encryption (https://cic.iacr.org/p/1/4/26/pdf)
[[maybe_unused]] double Precision(const std::vector<std::complex<double>>& result,
                                  const std::vector<std::complex<double>>& expected) {
    double accError = 0;
    for (size_t i = 0; i < result.size(); ++i)
        accError += std::abs(result[i] - expected[i]);
    return std::abs(std::log2(accError / result.size()));
}

}  // namespace

int main(int argc, char* argv[]) {
#if NATIVEINT == 64
    if (argc != 1 && (argc < 4 || argc > 12)) {
        std::cerr << "usage: " << argv[0]
                  << " [<logN> <stc|mr> <fa|faext|fm> [uniform|sparse|encap|hybrid] [lb0] [lb1] [smod] [fmod]"
                  << " [slots (0 = 8/128/N/2)] [cfMin cfMax]]\n"
                  << "no arguments = the demonstration configuration (see the comment at the top of the source)\n";
        return 1;
    }
    const bool demo = (argc == 1);
    const uint32_t logN = demo ? 12 : std::stoul(argv[1]);
    const bool stcFirst = demo ? true : std::string(argv[2]) == "stc";
    const std::string techName = demo ? "fa" : argv[3];
    const ScalingTechnique tech = (techName == "fa")    ? FLEXIBLEAUTO :
                                  (techName == "faext") ? FLEXIBLEAUTOEXT :
                                                          FIXEDMANUAL;
    const std::string skdName = (argc > 4) ? argv[4] : "uniform";
    const SecretKeyDist skd = (skdName == "sparse") ? SPARSE_TERNARY :
                              (skdName == "encap")  ? SPARSE_ENCAPSULATED :
                              (skdName == "hybrid") ? HYBRID_TERNARY :
                                                      UNIFORM_TERNARY;
    const uint32_t lb0 = (argc > 5) ? std::stoul(argv[5]) : 3;
    const uint32_t lb1 = (argc > 6) ? std::stoul(argv[6]) : 3;
    const uint32_t smod = (argc > 7) ? std::stoul(argv[7]) : 59;
    const uint32_t fmod = (argc > 8) ? std::stoul(argv[8]) : 60;
    const uint32_t slotsOverride = demo ? 128 : ((argc > 9) ? std::stoul(argv[9]) : 0);
    const uint32_t cfMin = (argc > 10) ? std::stoul(argv[10]) : 5;
    const uint32_t cfMax = demo ? 18 : ((argc > 11) ? std::stoul(argv[11]) : 15);
    constexpr uint32_t trials = 3;

    const uint32_t N = 1u << logN;
    std::vector<uint32_t> slotsList = {8, 128, N / 2};
    if (slotsOverride)
        slotsList = {slotsOverride};
    const std::vector<uint32_t> levelBudget = {lb0, lb1};
    const std::string modeName = stcFirst ? "stc" : "mr";
    const int32_t deg = static_cast<int32_t>(fmod) - static_cast<int32_t>(smod);

    for (uint32_t slots : slotsList) {
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetSecretKeyDist(skd);
        parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetRingDim(N);
        parameters.SetScalingModSize(smod);
        parameters.SetFirstModSize(fmod);
        parameters.SetScalingTechnique(tech);
        uint32_t depth;
        if (stcFirst) {
            depth = 10 + levelBudget[1] + FHECKKSRNS::GetBootstrapDepth({levelBudget[0], 0}, skd);
        } else {
            depth = 10 + FHECKKSRNS::GetBootstrapDepth(9, levelBudget, skd);
        }
        parameters.SetMultiplicativeDepth(depth);

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
        cc->Enable(FHE);

        // the library default for this configuration, for the summary
        cc->EvalBootstrapSetup(levelBudget, {0, 0}, slots, 0, true, stcFirst);
        const uint32_t libraryDefault = cc->GetCKKSBootCorrectionFactor();

        auto keyPair = cc->KeyGen();
        cc->EvalMultKeyGen(keyPair.secretKey);
        cc->EvalBootstrapKeyGen(keyPair.secretKey, slots);

        // one fresh input per trial, shared across factors so the factor columns stay comparable
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_real_distribution<double> dis(0.0, 1.0);
        const uint32_t encodeLevel = stcFirst ? depth - levelBudget[1] : depth - 1;
        std::vector<Plaintext> ptxts(trials);
        std::vector<Ciphertext<DCRTPoly>> ciphs(trials);
        for (uint32_t t = 0; t < trials; ++t) {
            std::vector<double> x(slots);
            for (auto& v : x)
                v = dis(gen);
            ptxts[t] = cc->MakeCKKSPackedPlaintext(x, 1, encodeLevel, nullptr, slots);
            ptxts[t]->SetLength(slots);
            ciphs[t] = cc->Encrypt(keyPair.publicKey, ptxts[t]);
        }

        std::map<uint32_t, double> p1Mean, p2Mean;
        for (uint32_t cf = cfMin; cf <= cfMax; ++cf) {
            if (static_cast<int32_t>(cf) < deg)
                continue;  // factors below deg are rejected at evaluation
            cc->EvalBootstrapSetup(levelBudget, {0, 0}, slots, cf, true, stcFirst);
            double s1 = 0, s2 = 0;
            uint32_t n2 = 0;
            for (uint32_t t = 0; t < trials; ++t) {
                double p1 = std::nan(""), p2 = std::nan("");
                try {
                    Plaintext result;
                    cc->Decrypt(keyPair.secretKey, cc->EvalBootstrap(ciphs[t]), &result);
                    result->SetLength(slots);
                    p1 = Precision(result->GetCKKSPackedValue(), ptxts[t]->GetCKKSPackedValue());
                    uint32_t precision = static_cast<uint32_t>(std::floor(p1)) - 5;
                    cc->Decrypt(keyPair.secretKey, cc->EvalBootstrap(ciphs[t], 2, precision), &result);
                    result->SetLength(slots);
                    p2 = Precision(result->GetCKKSPackedValue(), ptxts[t]->GetCKKSPackedValue());
                    s2 += p2;
                    ++n2;
                } catch (const std::exception& e) {
                    std::cerr << "FAIL cf " << cf << ": " << e.what() << std::endl;
                }
                s1 += std::isnan(p1) ? 0 : p1;
                std::cout << logN << "," << modeName << "," << techName << "," << slots << "," << cf << "," << t << ","
                          << p1 << "," << p2 << std::endl;
            }
            p1Mean[cf] = s1 / trials;
            if (n2)
                p2Mean[cf] = s2 / n2;
        }

        if (p1Mean.size() < 5)
            continue;
        const uint32_t best1 = std::max_element(p1Mean.begin(), p1Mean.end(), [](const auto& a, const auto& b) {
                                   return a.second < b.second;
                               })->first;
        double sumA = 0, sumB = 0;
        uint32_t nA = 0, nB = 0;
        for (const auto& [cf, p1] : p1Mean) {
            if (cf + 2 <= best1) {
                sumA += p1 - 2.0 * cf;
                ++nA;
            }
            if (cf >= best1 + 2) {
                sumB += p1 + cf;
                ++nB;
            }
        }
        std::cerr << "# " << modeName << " " << techName << " " << skdName << " N=2^" << logN << " slots=" << slots
                  << ": measured best p1 at " << best1;
        if (!p2Mean.empty()) {
            const uint32_t best2 = std::max_element(p2Mean.begin(), p2Mean.end(), [](const auto& a, const auto& b) {
                                       return a.second < b.second;
                                   })->first;
            std::cerr << ", best p2 at " << best2;
        }
        if (nA && nB) {
            const double A = sumA / nA;
            const double B = sumB / nB;
            const uint32_t crossing = static_cast<uint32_t>(std::round((B - A) / 3 + 0.5));
            const uint32_t derived =
                    std::max(std::clamp<uint32_t>(crossing, 6, 15), static_cast<uint32_t>(std::max(deg, 0)));
            std::cerr << "; A=" << A << " B=" << B << " derived default " << derived;
        } else {
            std::cerr << "; tent sides not both visible in [" << cfMin << "," << cfMax
                      << "] - widen the factor range to estimate A and B";
        }
        std::cerr << " (library default " << libraryDefault << ")" << std::endl;

        cc->ClearStaticMapsAndVectors();
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }
#else
    std::cerr << "ckks-bootstrapping-precision is 64-bit only: the 128-bit build applies no correction." << std::endl;
#endif
    return 0;
}
