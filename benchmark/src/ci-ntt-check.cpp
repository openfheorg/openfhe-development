// Validate + time the CI NTT (fused fold/first-stage kernels, item 4.1) against the reference
// implementation, the previous twisted CI NTT (kept here for the A/B) and the standard negacyclic NTT.
// Usage: ci-ntt-check [reps_2^16 (default 200)] [rounds (default 5)]
#include "openfhe.h"
#include "math/ci-transform.h"
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <random>
#include <vector>
using namespace lbcrypto;

namespace {
// The twisted CI NTT before item 4.1: folded twist b_i = a_i wm^{-i} + a_{N-i} wm^{-N-i}
// (NativeInteger Shoup ops), then the negacyclic NTT with psi = wm^2; inverse backwards.
struct OldCI {
    uint32_t N;
    NativeInteger q;
    NativeVector psiRev, psiRevPre, psiInvRev, psiInvRevPre;
    NativeInteger Ninv, NinvPre, mid, midPre;
    std::vector<NativeInteger> T1, T1p, T2, T2p, C1, C1p, C2, C2p;
    OldCI(uint32_t n, const NativeInteger& mod, const NativeInteger& wm) : N(n), q(mod) {
        const uint32_t m = 4 * N;
        std::vector<NativeInteger> wp(m);
        wp[0] = 1;
        for (uint32_t k = 1; k < m; ++k)
            wp[k] = wp[k - 1].ModMul(wm, q);
        auto W = [&](int64_t e) {
            e %= static_cast<int64_t>(m);
            if (e < 0)
                e += m;
            return wp[e];
        };
        uint32_t logN = 0;
        while ((1u << logN) < N)
            ++logN;
        psiRev = psiRevPre = psiInvRev = psiInvRevPre = NativeVector(N, q);
        for (uint32_t i = 0; i < N; ++i) {
            uint32_t r = 0;
            for (uint32_t b = 0; b < logN; ++b)
                r |= ((i >> b) & 1u) << (logN - 1 - b);
            psiRev[r]       = W(2 * int64_t(i));
            psiRevPre[r]    = psiRev[r].PrepModMulConst(q);
            psiInvRev[r]    = W(-2 * int64_t(i));
            psiInvRevPre[r] = psiInvRev[r].PrepModMulConst(q);
        }
        Ninv          = NativeInteger(N).ModInverse(q);
        NinvPre       = Ninv.PrepModMulConst(q);
        NativeInteger detInv = W(N).ModMul(NativeInteger(2), q).ModInverse(q);
        T1.resize(N), T2.resize(N), C1.resize(N), C2.resize(N);
        T1p.resize(N), T2p.resize(N), C1p.resize(N), C2p.resize(N);
        for (uint32_t i = 0; i < N; ++i) {
            T1[i]  = W(-int64_t(i));
            T2[i]  = W(-int64_t(N) - i);
            C1[i]  = W(int64_t(N) + i).ModMul(detInv, q);
            C2[i]  = W(int64_t(N) - i).ModMul(detInv, q);
            T1p[i] = T1[i].PrepModMulConst(q);
            T2p[i] = T2[i].PrepModMulConst(q);
            C1p[i] = C1[i].PrepModMulConst(q);
            C2p[i] = C2[i].PrepModMulConst(q);
        }
        mid    = W(N).ModMul(W(N / 2).ModAdd(W(-int64_t(N / 2)), q).ModInverse(q), q);
        midPre = mid.PrepModMulConst(q);
    }
    void Fwd(NativeVector& v) const {
        for (uint32_t i = 1; i <= N / 2; ++i) {
            const uint32_t k        = N - i;
            const NativeInteger ai = v[i], ak = v[k];
            v[i] = ai.ModMulFastConst(T1[i], q, T1p[i]).ModAddFast(ak.ModMulFastConst(T2[i], q, T2p[i]), q);
            if (k != i)
                v[k] = ak.ModMulFastConst(T1[k], q, T1p[k]).ModAddFast(ai.ModMulFastConst(T2[k], q, T2p[k]), q);
        }
        intnat::NumberTheoreticTransformNat<NativeVector>().ForwardTransformToBitReverseInPlace(psiRev, psiRevPre, &v);
    }
    void Inv(NativeVector& v) const {
        intnat::NumberTheoreticTransformNat<NativeVector>().InverseTransformFromBitReverseInPlace(
            psiInvRev, psiInvRevPre, Ninv, NinvPre, &v);
        for (uint32_t i = 1; i < N / 2; ++i) {
            const uint32_t k        = N - i;
            const NativeInteger bi = v[i], bk = v[k];
            v[i] = bi.ModMulFastConst(C1[i], q, C1p[i]).ModSubFast(bk.ModMulFastConst(C2[i], q, C2p[i]), q);
            v[k] = bk.ModMulFastConst(C1[k], q, C1p[k]).ModSubFast(bi.ModMulFastConst(C2[k], q, C2p[k]), q);
        }
        v[N / 2] = v[N / 2].ModMulFastConst(mid, q, midPre);
    }
};

double Median(std::vector<double> v) {
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}
}  // namespace

int main(int argc, char** argv) {
    const int reps16 = (argc > 1) ? std::atoi(argv[1]) : 200;
    const int rounds = (argc > 2) ? std::atoi(argv[2]) : 5;
    bool allOk       = true;
    for (uint32_t logN : {2u, 3u, 4u, 5u, 10u, 12u, 13u, 14u, 15u, 16u}) {
        const uint32_t N = 1u << logN;
        // 50-bit (lazy CT schedule), 59- and 60-bit primes (the bootstrap chain; non-lazy at large N)
        for (uint32_t bits : {50u, 59u, 60u}) {
            auto q  = LastPrime<NativeInteger>(bits, 4 * N);
            auto wm = RootOfUnity<NativeInteger>(4 * N, q);
            ClearCIModuli();
            RegisterCIModulus(q, N, wm);
            std::mt19937_64 g(logN * 100 + bits);
            bool ok = true;
            for (int trial = 0; trial < 3 && ok; ++trial) {
                NativeVector a(N, q);
                for (uint32_t i = 0; i < N; ++i)
                    a[i] = NativeInteger(trial == 0 ? q.ConvertToInt() - 1 - (g() % 3) : g() % q.ConvertToInt());
                NativeVector f1 = a, f2 = a;
                CIForwardTransform(f1);
                CIForwardTransformRef(f2);
                NativeVector i1 = f1, i2 = f1;
                CIInverseTransform(i1);
                CIInverseTransformRef(i2);
                ok = (f1 == f2) && (i1 == i2) && (i1 == a);
            }
            allOk = allOk && ok;
            std::cout << "NTTCHECK logN=" << logN << " qbits=" << bits << " match=" << ok;
            if (logN < 12 || bits != 59) {
                std::cout << std::endl;
                continue;
            }
            // timing, 59-bit prime only: new CI, old CI, standard negacyclic, interleaved rounds
            const int reps = std::max(5, reps16 << (16 - logN));
            OldCI old(N, q, wm);
            auto psi = RootOfUnity<NativeInteger>(2 * N, q);
            ChineseRemainderTransformFTT<NativeVector>().PreCompute(psi, 2 * N, q);
            NativeVector a(N, q);
            for (uint32_t i = 0; i < N; ++i)
                a[i] = NativeInteger(g() % q.ConvertToInt());
            // per-rep interleaving (new, old, std back to back) so that clock/speed-state changes of the
            // laptop hit all three alike; medians of the per-rep times and of the per-rep ratios
            std::vector<double> tNew, tOld, tStd, rNS, rOS;
            NativeVector v1 = a, v2 = a, v3 = a;
            auto now        = [] { return std::chrono::steady_clock::now(); };
            auto sec        = [](auto d) { return std::chrono::duration<double>(d).count(); };
            for (int r = 0; r < reps * rounds; ++r) {
                auto t0 = now();
                CIForwardTransform(v1);
                CIInverseTransform(v1);
                auto t1 = now();
                old.Fwd(v2);
                old.Inv(v2);
                auto t2 = now();
                ChineseRemainderTransformFTT<NativeVector>().ForwardTransformToBitReverseInPlace(psi, 2 * N, &v3);
                ChineseRemainderTransformFTT<NativeVector>().InverseTransformFromBitReverseInPlace(psi, 2 * N, &v3);
                auto t3 = now();
                tNew.push_back(sec(t1 - t0));
                tOld.push_back(sec(t2 - t1));
                tStd.push_back(sec(t3 - t2));
                rNS.push_back(sec(t1 - t0) / sec(t3 - t2));
                rOS.push_back(sec(t2 - t1) / sec(t3 - t2));
            }
            if (!(v1 == a && v2 == a && v3 == a))
                allOk = false;
            const double mn = Median(tNew), mo = Median(tOld), ms = Median(tStd);
            std::cout << " reps=" << reps << "x" << rounds << " roundtrip_us new=" << mn * 1e6 << " old=" << mo * 1e6
                      << " std=" << ms * 1e6 << " new/std=" << mn / ms << " old/std=" << mo / ms
                      << " old/new=" << mo / mn << " med(new/std)=" << Median(rNS) << " med(old/std)=" << Median(rOS)
                      << std::endl;
        }
    }
    std::cout << "NTTCHECK all_match=" << allOk << std::endl;
    return allOk ? 0 : 1;
}
