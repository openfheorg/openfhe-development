//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
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

#include "math/ci-realfft.h"

#include <algorithm>
#include <cmath>
#include <complex>
#include <memory>
#include <mutex>
#include <numeric>
#include <tuple>
#include <utility>

namespace lbcrypto {

namespace {
void CIAddEntry(CISparse& A, uint32_t N, uint32_t row, uint32_t col, double v) {
    if (v == 0.0)
        return;
    auto& d = A[(col + N - row) % N];
    if (d.empty())
        d.assign(N, 0.0);
    d[row] += v;
}

// Real FFT factors F_1..F_l (apply order) in g=5 order; sigma[p] = sqrt(2N) * S[p] (sqrt2 at p=0, else 1).
std::vector<CISparse> CIBuildRealFFT(uint32_t N, std::vector<double>& sigma, std::vector<uint32_t>& pos) {
    const uint64_t M = 4ULL * N;
    std::vector<uint64_t> p5(N);
    {
        uint64_t f = 1;
        for (uint32_t j = 0; j < N; ++j) {
            p5[j] = f;
            f = (f * 5) % M;
        }
    }
    auto zeta = [&](int64_t e) {
        int64_t mm = static_cast<int64_t>(M);
        e %= mm;
        if (e < 0)
            e += mm;
        double a = 2.0 * M_PI * static_cast<double>(e) / static_cast<double>(M);
        return std::complex<double>(std::cos(a), std::sin(a));
    };
    struct Seg {
        bool pair;
        uint32_t r, s, len;
    };
    std::vector<Seg> segs{{false, 0, 0, N}};
    const double sq2 = std::sqrt(2.0);
    std::vector<CISparse> F;
    for (uint32_t m = 1; m < N; m <<= 1) {
        const uint32_t L = N / (2 * m);
        std::vector<double> Din(N, 1.0), Dout(N, 1.0);
        for (auto& g : segs)
            if (g.pair)
                std::fill(Din.begin() + g.s, Din.begin() + g.s + 2 * g.len, sq2);
        std::vector<std::tuple<uint32_t, uint32_t, double>> T;
        std::vector<Seg> nsegs;
        for (auto& g : segs) {
            const uint32_t s = g.s, r = g.r;
            if (!g.pair && r == 0) {
                for (uint32_t j = 0; j < L; ++j) {
                    T.emplace_back(s + j, s + j, 1.0);
                    T.emplace_back(s + j, s + L + j, 1.0);
                    T.emplace_back(s + L + j, s + j, 1.0);
                    T.emplace_back(s + L + j, s + L + j, -1.0);
                }
                nsegs.push_back({false, 0, s, L});
                nsegs.push_back({false, m, s + L, L});
            } else if (!g.pair) {  // r == m/2: real -> pair(r)
                for (uint32_t j = 0; j < L; ++j) {
                    auto w = zeta(-static_cast<int64_t>(r) *
                                  (static_cast<int64_t>(p5[j + L]) - static_cast<int64_t>(p5[j])));
                    T.emplace_back(s + j, s + j, 1.0);
                    T.emplace_back(s + j, s + L + j, w.real());
                    T.emplace_back(s + L + j, s + L + j, w.imag());
                }
                nsegs.push_back({true, r, s, L});
            } else {  // pair r (1 <= r < m/2): Re at [s, s+2L), Im at [s+2L, s+4L)
                for (uint32_t j = 0; j < L; ++j) {
                    auto w = zeta(-static_cast<int64_t>(r) *
                                  (static_cast<int64_t>(p5[j + L]) - static_cast<int64_t>(p5[j])));
                    const double al = w.real(), be = w.imag();
                    const uint32_t a = s + j, b = s + L + j, c = s + 2 * L + j, d = s + 3 * L + j;
                    T.emplace_back(s + j, a, 1.0);
                    T.emplace_back(s + j, b, al);
                    T.emplace_back(s + j, d, -be);
                    T.emplace_back(s + L + j, c, 1.0);
                    T.emplace_back(s + L + j, b, be);
                    T.emplace_back(s + L + j, d, al);
                    T.emplace_back(s + 2 * L + j, a, 1.0);
                    T.emplace_back(s + 2 * L + j, b, -al);
                    T.emplace_back(s + 2 * L + j, d, be);
                    T.emplace_back(s + 3 * L + j, c, -1.0);
                    T.emplace_back(s + 3 * L + j, b, be);
                    T.emplace_back(s + 3 * L + j, d, al);
                }
                nsegs.push_back({true, r, s, L});
                nsegs.push_back({true, m - r, s + 2 * L, L});
            }
        }
        for (auto& g : nsegs)
            if (g.pair)
                std::fill(Dout.begin() + g.s, Dout.begin() + g.s + 2 * g.len, sq2);
        CISparse Fi;
        for (auto& [row, col, v] : T)
            CIAddEntry(Fi, N, row, col, v * Dout[row] / Din[col] / sq2);
        F.push_back(std::move(Fi));
        segs = std::move(nsegs);
    }
    // Merge the final phase removal into F_l: each pair (s, s+1) gets the orthogonal 2x2
    // [[cos, sin], [sin, -cos]], theta = pi r / (2N); real sub-vectors are left as is.
    {
        CISparse& Fl = F.back();
        auto row = [&](uint32_t p) {
            std::vector<std::pair<uint32_t, double>> e;
            for (auto& [k, d] : Fl)
                if (d[p] != 0.0)
                    e.emplace_back((p + k) % N, d[p]);
            return e;
        };
        CISparse G;
        for (auto& g : segs) {
            if (!g.pair) {
                for (auto& [c, v] : row(g.s))
                    CIAddEntry(G, N, g.s, c, v);
                continue;
            }
            const double th = M_PI * g.r / (2.0 * N), cs = std::cos(th), sn = std::sin(th);
            auto r0 = row(g.s), r1 = row(g.s + 1);
            for (auto& [c, v] : r0) {
                CIAddEntry(G, N, g.s, c, cs * v);
                CIAddEntry(G, N, g.s + 1, c, sn * v);
            }
            for (auto& [c, v] : r1) {
                CIAddEntry(G, N, g.s, c, sn * v);
                CIAddEntry(G, N, g.s + 1, c, -cs * v);
            }
        }
        Fl = std::move(G);
    }
    sigma.assign(N, 1.0);
    sigma[0] = sq2;
    pos.assign(N, 0);
    for (auto& g : segs) {
        pos[g.r] = g.s;
        if (g.pair)
            pos[N - g.r] = g.s + 1;
    }
    return F;
}

}  // namespace

// C = A * B (B applied first), in cyclic-diagonal form. Drops numerically-zero diagonals
// (max |entry| <= 1e-13 x the largest entry of C).
CISparse CISparseMul(const CISparse& A, const CISparse& B, uint32_t N) {
    CISparse C;
    for (auto& [a, da] : A)
        for (auto& [b, db] : B) {
            auto& dc = C[(a + b) % N];
            if (dc.empty())
                dc.assign(N, 0.0);
            for (uint32_t p = 0; p < N; ++p)
                dc[p] += da[p] * db[(p + a) % N];
        }
    // Drop diagonals that are zero up to round-off, relative to the largest entry of C (scale-invariant).
    std::map<uint32_t, double> dmax;
    double gmax = 0.0;
    for (auto& [k, d] : C) {
        double mx = 0.0;
        for (double v : d)
            mx = std::max(mx, std::abs(v));
        dmax[k] = mx;
        gmax = std::max(gmax, mx);
    }
    const double tol = 1e-13 * gmax;
    for (auto it = C.begin(); it != C.end();)
        it = (dmax[it->first] <= tol) ? C.erase(it) : std::next(it);
    return C;
}

CISparse CISparseTranspose(const CISparse& A, uint32_t N) {
    CISparse T;
    for (auto& [k, d] : A) {
        const uint32_t kk = (N - k) % N;
        auto& dt = T[kk];
        dt.assign(N, 0.0);
        for (uint32_t p = 0; p < N; ++p)
            dt[p] = d[(p + kk) % N];
    }
    return T;
}

namespace {
// Offsets of A as window indices t = k / h, the gcd h, and the smallest circular window holding them.
struct CIBsgsWindow {
    uint32_t h, T, t0, span;
    std::vector<uint32_t> ts;
};

CIBsgsWindow CIBsgsGetWindow(const CISparse& A, uint32_t N) {
    CIBsgsWindow w;
    w.h = N;
    for (auto& kv : A)
        w.h = std::gcd(w.h, kv.first);
    w.T = N / w.h;
    for (auto& kv : A)
        w.ts.push_back(kv.first / w.h);  // ascending (map order)
    w.t0 = w.ts.empty() ? 0 : w.ts[0];
    w.span = 1;
    if (w.ts.size() > 1) {
        uint32_t bestGap = w.ts[0] + w.T - w.ts.back(), bestIdx = static_cast<uint32_t>(w.ts.size()) - 1;
        for (uint32_t i = 0; i + 1 < w.ts.size(); ++i)
            if (w.ts[i + 1] - w.ts[i] > bestGap) {
                bestGap = w.ts[i + 1] - w.ts[i];
                bestIdx = i;
            }
        w.t0 = w.ts[(bestIdx + 1) % w.ts.size()];
        w.span = w.T - bestGap + 1;
    }
    return w;
}

CIBsgsPlan CIBsgsMake(const CIBsgsWindow& w, uint32_t n1) {
    n1 = std::max<uint32_t>(1, std::min(n1, w.span));
    uint32_t t0 = w.t0, span = w.span;
    // Align the window so that offset 0 starts a giant block: that block needs no rotation, so the level
    // does one giant rotation fewer. Move the start back by r < n1 (the extra window positions hold no
    // diagonals); skip when 0 is outside the window or the longer window would wrap around Z_T.
    const uint32_t d = (w.T - t0) % w.T;  // window position of offset 0
    const uint32_t r = (n1 - d % n1) % n1;
    if (d < span && r != 0 && span + r <= w.T) {
        t0 = (t0 + w.T - r) % w.T;
        span += r;
    }
    const uint32_t n2 = (span + n1 - 1) / n1;
    std::vector<char> bu(n1, 0), gu(n2, 0);
    for (uint32_t t : w.ts) {
        const uint32_t u = (t + w.T - t0) % w.T;
        bu[u % n1] = 1;
        gu[u / n1] = 1;
    }
    uint32_t babies = 0, giants = 0;
    for (uint32_t i = 1; i < n1; ++i)
        babies += bu[i];
    for (uint32_t j = 0; j < n2; ++j)
        giants += (gu[j] && (t0 + static_cast<uint64_t>(n1) * j) % w.T != 0) ? 1 : 0;
    return {w.h, t0, span, n1, n2, babies, giants};
}
}  // namespace

CIBsgsPlan CIPlanBsgsN1(const CISparse& A, uint32_t N, uint32_t n1) {
    return CIBsgsMake(CIBsgsGetWindow(A, N), n1);
}

CIBsgsPlan CIPlanBsgsRatio(const CISparse& A, uint32_t N, double ratio) {
    const auto w = CIBsgsGetWindow(A, N);
    return CIBsgsMake(w, static_cast<uint32_t>(std::ceil(std::sqrt(static_cast<double>(w.span)) * ratio)));
}

CIBsgsPlan CIPlanBsgsMinCost(const CISparse& A, uint32_t N, double giantCost) {
    const auto w = CIBsgsGetWindow(A, N);
    CIBsgsPlan best{};
    double bestCost = 0.0;
    for (uint32_t n1 = 1; n1 <= w.span; ++n1) {
        const auto p = CIBsgsMake(w, n1);
        const double c = p.babies + giantCost * p.giants;
        if (n1 == 1 || c < bestCost - 1e-9) {
            best = p;
            bestCost = c;
        }
    }
    return best;
}

double CIBsgsGiantCost(uint32_t digits) {
    const double D = std::max<uint32_t>(1, digits);
    const double baby = 0.63 * D + 0.40;
    return (baby + 2.35 * D + 2.45 + 0.15) / baby;
}

const CIRealFFTPlan& GetCIRealFFTPlan(uint32_t N) {
    static std::map<uint32_t, std::unique_ptr<CIRealFFTPlan>> cache;
    static std::mutex mtx;
    std::lock_guard<std::mutex> lk(mtx);
    auto& slot = cache[N];
    if (!slot) {
        auto plan = std::make_unique<CIRealFFTPlan>();
        plan->N = N;
        std::vector<double> sigma;
        plan->F = CIBuildRealFFT(N, sigma, plan->pos);
        plan->S.resize(N);
        const double inv = 1.0 / std::sqrt(2.0 * N);
        for (uint32_t p = 0; p < N; ++p)
            plan->S[p] = sigma[p] * inv;
        // g=5 position -> natural CI slot index (5^p mod 4N folded to 4t+1)
        plan->perm.resize(N);
        const uint64_t M = 4ULL * N;
        uint64_t r = 1;
        for (uint32_t p = 0; p < N; ++p) {
            uint64_t rr = (r % 4 == 3) ? (M - r) % M : r;
            plan->perm[p] = static_cast<uint32_t>((rr - 1) / 4);
            r = (r * 5) % M;
        }
        slot = std::move(plan);
    }
    return *slot;
}

namespace {
// y = A x
void ApplySparse(const CISparse& A, const std::vector<double>& x, std::vector<double>& y, uint32_t N) {
    std::fill(y.begin(), y.end(), 0.0);
    for (auto& [k, d] : A)
        for (uint32_t p = 0; p < N; ++p)
            y[p] += d[p] * x[(p + k) & (N - 1)];
}
// y = A^T x
void ApplySparseT(const CISparse& A, const std::vector<double>& x, std::vector<double>& y, uint32_t N) {
    std::fill(y.begin(), y.end(), 0.0);
    for (auto& [k, d] : A)
        for (uint32_t p = 0; p < N; ++p)
            y[(p + k) & (N - 1)] += d[p] * x[p];
}
}  // namespace

void CIRealFFTEncode(uint32_t N, const std::vector<double>& slots, std::vector<double>& coeffs) {
    const auto& pl = GetCIRealFFTPlan(N);
    std::vector<double> a(N), b(N);
    for (uint32_t p = 0; p < N; ++p)
        a[p] = slots[pl.perm[p]];
    for (auto& F : pl.F) {
        ApplySparse(F, a, b, N);
        a.swap(b);
    }
    coeffs.resize(N);
    for (uint32_t j = 0; j < N; ++j)
        coeffs[j] = pl.S[pl.pos[j]] * a[pl.pos[j]];
}

void CIRealFFTDecode(uint32_t N, const std::vector<double>& coeffs, std::vector<double>& slots) {
    const auto& pl = GetCIRealFFTPlan(N);
    std::vector<double> a(N), b(N);
    for (uint32_t j = 0; j < N; ++j)
        a[pl.pos[j]] = coeffs[j] / pl.S[pl.pos[j]];
    for (auto it = pl.F.rbegin(); it != pl.F.rend(); ++it) {
        ApplySparseT(*it, a, b, N);
        a.swap(b);
    }
    slots.resize(N);
    for (uint32_t p = 0; p < N; ++p)
        slots[pl.perm[p]] = a[p];
}

}  // namespace lbcrypto
