// BSGS plans of the CI real-FFT levels (item 2.2 of PLAN_PHASE2.md). For every level of the CtS / StC split
// built like CIBuildRealLevels (same layer split; StC levels are transposes, apply order), prints the window, the
// fixed-ratio plan (n1 = ceil(2 sqrt(span)), the rule before 2.2) and the cost-model plan (CIPlanBsgsMinCost
// with CIBsgsGiantCost(digits)) for 1..3 key-switching digits, with their baby / giant counts and modelled cost
// (in hoisted-baby units). With "sweep" also prints the modelled cost of every n1 for each level.
// Build and run (ICELAKE, from the source root):
//   g++ -O2 -std=c++17 -Isrc/core/include ci-ckks-paper/tools/ci-bsgs-plan.cpp src/core/lib/math/ci-realfft.cpp \
//       -o ../scratch/ci-bsgs-plan && ../scratch/ci-bsgs-plan 12 16 [sweep]
#include "math/ci-realfft.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <vector>

using namespace lbcrypto;

int main(int argc, char** argv) {
    const uint32_t lo = argc > 1 ? std::atoi(argv[1]) : 12, hi = argc > 2 ? std::atoi(argv[2]) : 16;
    const bool sweep = argc > 3 && std::strcmp(argv[3], "sweep") == 0;
    for (uint32_t logN = lo; logN <= hi; ++logN) {
        const uint32_t N = 1u << logN;
        const auto& F    = GetCIRealFFTPlan(N).F;
        const uint32_t l = static_cast<uint32_t>(F.size());
        for (uint32_t lb = 2; lb <= 5; ++lb) {
            std::vector<std::pair<uint32_t, uint32_t>> rg;
            for (uint32_t i = 0, k = 0; i < lb; ++i) {
                const uint32_t sz = l / lb + (i < l % lb ? 1 : 0);
                rg.emplace_back(k, k + sz);
                k += sz;
            }
            std::vector<CISparse> enc, dec;
            for (auto& [a, b] : rg) {
                CISparse P = F[a];
                for (uint32_t t = a + 1; t < b; ++t)
                    P = CISparseMul(F[t], P, N);
                enc.push_back(P);
            }
            for (auto it = enc.rbegin(); it != enc.rend(); ++it)
                dec.push_back(CISparseTranspose(*it, N));
            for (int e = 0; e < 2; ++e) {
                const auto& lv = e ? dec : enc;
                for (size_t s = 0; s < lv.size(); ++s) {
                    const auto& A = lv[s];
                    const auto o  = CIPlanBsgsRatio(A, N, 2.0);
                    std::printf("logN=%u lb=%u %s level=%zu diags=%zu h=%u span=%u | ratio2 n1=%u n2=%u b=%u g=%u", logN,
                                lb, e ? "StC" : "CtS", s, A.size(), o.h, o.span, o.n1, o.n2, o.babies, o.giants);
                    for (uint32_t D = 1; D <= 3; ++D) {
                        const double c = CIBsgsGiantCost(D);
                        const auto p   = CIPlanBsgsMinCost(A, N, c);
                        const double co = o.babies + c * o.giants, cp = p.babies + c * p.giants;
                        std::printf(" | D=%u rho=%.2f model n1=%u n2=%u b=%u g=%u cost %.1f->%.1f (%+.1f%%)", D, c,
                                    p.n1, p.n2, p.babies, p.giants, co, cp, 100.0 * (cp - co) / co);
                    }
                    std::printf("\n");
                    if (sweep) {
                        const double c = CIBsgsGiantCost(1);
                        std::printf("   sweep(D=1):");
                        for (uint32_t n1 = 1; n1 <= o.span && n1 <= 64; ++n1) {
                            const auto p = CIPlanBsgsN1(A, N, n1);
                            std::printf(" %u:%ub%ug=%.1f", n1, p.babies, p.giants, p.babies + c * p.giants);
                        }
                        std::printf("\n");
                    }
                }
            }
        }
    }
    return 0;
}
