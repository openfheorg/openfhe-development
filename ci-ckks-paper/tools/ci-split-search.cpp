// Layer-split search for the CI real-FFT CtS / StC levels (item 2.3 of PLAN_PHASE2.md).
// A split of the l = log2 N FFT layers into lb levels is a composition [n_0, ..., n_{lb-1}] in layer order (F_1
// first). CtS level s is the product of the layers of part s (applied first to last); StC applies the transposes
// in reverse order, so StC level s is the transpose of part lb-1-s. For every split this tool computes each level's
// nonzero diagonals from the numeric product (CISparseMul, as CIBuildRealLevels; the sumset of the layers'
// offsets overcounts: the 3L offsets of adjacent layers cancel exactly), its BSGS plan (CIPlanBsgsMinCost, the item 2.2 rule) at the level's key-switching digits, and a
// (diagonals x limbs) cost: QlP towers x per-tower cost of the level's ops (item 2.1 [LT] per-op times at 2^16, ms
// per QlP tower):
//   (g + 1) ModUps 2.35 D + (b + g) key switches 0.63 D + 0.40 + (g + 2) ModDown polys 2.45
//   + d plaintext mults 0.646 + (d + g) extended adds 0.15
// Towers follow the chain shape of CIBsgsLevelDigits (ckksrns-fhe.cpp): CtS level s has L0 - 1 - s Q towers, StC
// level s L0 - (lbEnc + modDepth + s), L0 = lbEnc + modDepth + lbDec + after + 1; D = min(dnum, ceil(Ql / alpha)).
// Prints the default split (even, larger parts first) and the top K CtS and StC splits, with their Galois keys.
// Build and run (ICELAKE, from the source root):
//   g++ -O2 -std=c++17 -Isrc/core/include ci-ckks-paper/tools/ci-split-search.cpp src/core/lib/math/ci-realfft.cpp \
//       -o ../scratch/ci-split-search && ../scratch/ci-split-search logN lbEnc lbDec [topK] [after modDepth alpha dnum P]
#include "math/ci-realfft.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <string>
#include <vector>

using namespace lbcrypto;

namespace {
uint32_t gN, gL;
std::vector<std::vector<uint32_t>> layerOffs;  // offsets of F_t
// sym[a][b]: symbolic offsets of F_{b-1} ... F_a (b > a)
std::vector<std::vector<CISparse>> sym;

CISparse SymTranspose(const CISparse& A) {
    CISparse T;
    for (auto& kv : A)
        T[(gN - kv.first) % gN];
    return T;
}

struct LevelCost {
    double perTower = 0;
    CIBsgsPlan p{};
    size_t d = 0;
};

LevelCost CostOf(const CISparse& A, uint32_t D) {
    LevelCost c;
    c.p                = CIPlanBsgsMinCost(A, gN, CIBsgsGiantCost(D));
    c.d                = A.size();
    const double b = c.p.babies, g = c.p.giants, d = static_cast<double>(c.d);
    c.perTower = (g + 1) * 2.35 * D + (b + g) * (0.63 * D + 0.40) + (g + 2) * 2.45 + d * 0.646 + (d + g) * 0.15;
    return c;
}

void GaloisOf(const CISparse& A, const CIBsgsPlan& bp, std::set<uint32_t>& out) {
    const uint32_t T = gN / bp.h;
    for (const auto& kv : A) {
        const uint32_t u = (kv.first / bp.h + T - bp.t0) % T;
        const uint32_t i = u % bp.n1, j = u / bp.n1;
        if (i != 0)
            out.insert(bp.h * i % gN);
        const uint32_t G = static_cast<uint32_t>((static_cast<uint64_t>(bp.h) * (bp.t0 + bp.n1 * j)) % gN);
        if (G != 0)
            out.insert(G);
    }
}

struct Cand {
    std::vector<uint32_t> parts;
    double ms = 0;  // modelled time, ms
    std::string detail;
    std::set<uint32_t> shifts;
};

std::string Str(const std::vector<uint32_t>& v) {
    std::string s = "[";
    for (size_t i = 0; i < v.size(); ++i)
        s += (i ? "," : "") + std::to_string(v[i]);
    return s + "]";
}

void Enumerate(uint32_t left, uint32_t parts, std::vector<uint32_t>& cur, std::vector<std::vector<uint32_t>>& out) {
    if (parts == 1) {
        cur.push_back(left);
        out.push_back(cur);
        cur.pop_back();
        return;
    }
    for (uint32_t x = 1; x + parts - 1 <= left; ++x) {
        cur.push_back(x);
        Enumerate(left - x, parts - 1, cur, out);
        cur.pop_back();
    }
}
}  // namespace

int main(int argc, char** argv) {
    if (argc < 4) {
        std::fprintf(stderr, "usage: logN lbEnc lbDec [topK] [after modDepth alpha dnum P]\n");
        return 1;
    }
    const uint32_t logN = std::atoi(argv[1]), lbEnc = std::atoi(argv[2]), lbDec = std::atoi(argv[3]);
    const uint32_t topK = argc > 4 ? std::atoi(argv[4]) : 10;
    const uint32_t after = argc > 5 ? std::atoi(argv[5]) : 2, modDepth = argc > 6 ? std::atoi(argv[6]) : 10;
    const uint32_t alpha = argc > 7 ? std::atoi(argv[7]) : 7, dnum = argc > 8 ? std::atoi(argv[8]) : 3;
    const uint32_t Pt = argc > 9 ? std::atoi(argv[9]) : 7;
    gN               = 1u << logN;
    const auto& F    = GetCIRealFFTPlan(gN).F;
    gL               = static_cast<uint32_t>(F.size());
    const uint32_t L0 = lbEnc + modDepth + lbDec + after + 1;
    std::printf("N=2^%u l=%u layers, lbEnc=%u lbDec=%u, L0=%u Q towers, modDepth=%u, alpha=%u dnum=%u P=%u\n", logN, gL,
                lbEnc, lbDec, L0, modDepth, alpha, dnum, Pt);
    for (uint32_t t = 0; t < gL; ++t) {
        std::printf("layer %2u: %zu diags:", t, F[t].size());
        for (auto& kv : F[t])
            std::printf(" %d", kv.first > gN / 2 ? static_cast<int>(kv.first) - static_cast<int>(gN)
                                                 : static_cast<int>(kv.first));
        std::printf("\n");
    }
    // Numeric products of every layer range (as CIBuildRealLevels builds them); keys only. A range is not
    // extended past maxDiags diagonals (denser ranges are never competitive).
    const size_t maxDiags = 1100;
    sym.assign(gL + 1, std::vector<CISparse>(gL + 1));
    std::vector<std::vector<char>> dense(gL + 1, std::vector<char>(gL + 1, 1));
    for (uint32_t a = 0; a < gL; ++a) {
        CISparse P = F[a];
        for (uint32_t b = a + 1; b <= gL; ++b) {
            if (b > a + 1)
                P = CISparseMul(F[b - 1], P, gN);
            if (P.size() > maxDiags)
                break;
            dense[a][b] = 0;
            CISparse S;
            for (auto& kv : P)
                S[kv.first];
            sym[a][b] = std::move(S);
        }
        std::fprintf(stderr, "ranges from layer %u done\n", a);
    }
    auto digitsOf = [&](uint32_t Ql) { return std::min(dnum, (Ql + alpha - 1) / alpha); };

    for (int e = 0; e < 2; ++e) {
        const bool enc   = e == 0;
        const uint32_t lb = enc ? lbEnc : lbDec;
        std::vector<std::vector<uint32_t>> comps;
        std::vector<uint32_t> cur;
        Enumerate(gL, lb, cur, comps);
        std::vector<uint32_t> def;
        for (uint32_t i = 0; i < lb; ++i)
            def.push_back(gL / lb + (i < gL % lb ? 1 : 0));
        std::vector<Cand> cands;
        for (auto& c : comps) {
            std::vector<std::pair<uint32_t, uint32_t>> rg;
            for (uint32_t i = 0, k = 0; i < lb; ++i) {
                rg.emplace_back(k, k + c[i]);
                k += c[i];
            }
            Cand cd;
            cd.parts = c;
            bool tooDense = false;
            for (uint32_t s = 0; s < lb; ++s) {
                const auto& r     = enc ? rg[s] : rg[lb - 1 - s];
                if (dense[r.first][r.second]) {
                    tooDense = true;
                    break;
                }
                const CISparse A  = enc ? sym[r.first][r.second] : SymTranspose(sym[r.first][r.second]);
                const uint32_t Ql = enc ? L0 - 1 - s : L0 - (lbEnc + modDepth + s);
                const uint32_t D  = digitsOf(Ql);
                const auto lc     = CostOf(A, D);
                cd.ms += (Ql + Pt) * lc.perTower;
                GaloisOf(A, lc.p, cd.shifts);
                char buf[160];
                std::snprintf(buf, sizeof buf, " L%u(%u+%u,D%u):d%zu n1=%u b%u g%u %.2fs", s, Ql, Pt, D, lc.d, lc.p.n1,
                              lc.p.babies, lc.p.giants, (Ql + Pt) * lc.perTower / 1000.0);
                cd.detail += buf;
            }
            if (!tooDense)
                cands.push_back(std::move(cd));
        }
        std::sort(cands.begin(), cands.end(), [](const Cand& x, const Cand& y) { return x.ms < y.ms; });
        double defMs = 0;
        size_t defRank = 0;
        for (size_t i = 0; i < cands.size(); ++i)
            if (cands[i].parts == def) {
                defMs   = cands[i].ms;
                defRank = i + 1;
            }
        std::printf("\n%s lb=%u: %zu splits (layer order, F_1 first); default %s model %.2f s, rank %zu\n",
                    enc ? "CtS" : "StC", lb, cands.size(), Str(def).c_str(), defMs / 1000.0, defRank);
        for (size_t i = 0; i < cands.size(); ++i)
            if (i < topK || cands[i].parts == def)
                std::printf("%s #%zu %-18s model %.2f s (%+.2f s vs default) shifts %zu |%s\n", enc ? "CtS" : "StC", i + 1,
                            Str(cands[i].parts).c_str(), cands[i].ms / 1000.0, (cands[i].ms - defMs) / 1000.0,
                            cands[i].shifts.size(), cands[i].detail.c_str());
    }
    return 0;
}
