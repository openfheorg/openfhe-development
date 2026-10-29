// Drop-threshold margin of the CI real-FFT level products (item 0.4 of PLAN_PHASE2.md).
// For every intermediate product F[t] * P built by CIBuildRealLevels (same layer split), prints the smallest
// kept and the largest dropped diagonal max, relative to the largest entry of the product, and whether the
// old absolute rule (max < 1e-13) and the new relative rule (max <= 1e-13 x largest entry) disagree.
// Build (ICELAKE, from the source root):
//   g++ -O2 -std=c++17 -Isrc/core/include ci-ckks-paper/tools/ci-sparse-margin.cpp src/core/lib/math/ci-realfft.cpp
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <utility>
#include <vector>

#include "math/ci-realfft.h"

using namespace lbcrypto;

int main() {
    for (uint32_t logN = 12; logN <= 16; ++logN) {
        const uint32_t N = 1u << logN;
        const auto& F = GetCIRealFFTPlan(N).F;
        const uint32_t l = static_cast<uint32_t>(F.size());
        for (uint32_t lb : {2u, 3u, 4u}) {
            double minKept = 1.0, maxDrop = 0.0, minAbsKept = 1e300;
            size_t disagree = 0, steps = 0;
            std::vector<size_t> counts;
            uint32_t k = 0;
            for (uint32_t g = 0; g < lb; ++g) {
                const uint32_t sz = l / lb + (g < l % lb ? 1 : 0);
                CISparse P = F[k];
                for (uint32_t t = k + 1; t < k + sz; ++t) {
                    const CISparse& A = F[t];
                    CISparse C;  // C = A * P without dropping (same arithmetic as CISparseMul)
                    for (auto& [a, da] : A)
                        for (auto& [b, db] : P) {
                            auto& dc = C[(a + b) % N];
                            if (dc.empty())
                                dc.assign(N, 0.0);
                            for (uint32_t p = 0; p < N; ++p)
                                dc[p] += da[p] * db[(p + a) % N];
                        }
                    std::vector<std::pair<uint32_t, double>> mx;
                    double gmax = 0.0;
                    for (auto& [kk, d] : C) {
                        double m = 0.0;
                        for (double v : d)
                            m = std::max(m, std::abs(v));
                        mx.emplace_back(kk, m);
                        gmax = std::max(gmax, m);
                    }
                    for (auto& [kk, m] : mx) {
                        const bool dropRel = m <= 1e-13 * gmax, dropAbs = m < 1e-13;
                        disagree += (dropRel != dropAbs);
                        if (dropRel) {
                            maxDrop = std::max(maxDrop, m / gmax);
                            C.erase(kk);
                        } else {
                            minKept = std::min(minKept, m / gmax);
                            minAbsKept = std::min(minAbsKept, m);
                        }
                    }
                    // the library product must give the same pattern
                    const CISparse L = CISparseMul(A, P, N);
                    bool same = L.size() == C.size();
                    for (auto& kv : C)
                        same = same && L.count(kv.first);
                    if (!same)
                        std::printf("MISMATCH logN=%u lb=%u t=%u\n", logN, lb, t);
                    P = std::move(C);
                    ++steps;
                }
                counts.push_back(P.size());
                k += sz;
            }
            std::printf("MARGIN logN=%u lb=%u layers=%u steps=%zu diags=", logN, lb, l, steps);
            for (size_t i = 0; i < counts.size(); ++i)
                std::printf("%s%zu", i ? "/" : "", counts[i]);
            std::printf(" min_kept_rel=%.3e max_dropped_rel=%.3e min_kept_abs=%.3e abs_vs_rel_disagree=%zu\n", minKept,
                        maxDrop, minAbsKept, disagree);
        }
    }
    return 0;
}
