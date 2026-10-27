//==================================================================================
// BSD 2-Clause License
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
// All rights reserved.
//==================================================================================

#include "math/ci-transform.h"
#include "math/hal/intnat/transformnat.h"
#include "utils/exception.h"

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

// Twisted CI NTT. Evaluates a CI element a = a_0 + sum_i a_i (X^i + X^{-i}) at the N points
// wm^{4j+1} (wm a primitive 4N-th root), j = 0..N-1 in natural order. Implemented as
//   b_i = a_i * wm^{-i} + a_{N-i} * wm^{-N-i}            (folded twist, Shoup constants)
//   E   = negacyclic NTT of b with psi = wm^2             (OpenFHE's optimized in-place NTT)
//   the eval vector stays in bit-reversed node order (no permutation pass).
// The inverse runs the same steps backwards. The registry is published copy-on-write so the
// per-transform lookups are lock-free.

namespace lbcrypto {

namespace {

struct CITables {
    uint32_t N = 0;
    CINativeInteger q;
    CINativeInteger wm;
    CINativeVector psiRev, psiRevPre;        // psi^i at bit-reversed i, psi = wm^2 (forward NTT)
    CINativeVector psiInvRev, psiInvRevPre;  // psi^{-i} at bit-reversed i (inverse NTT)
    CINativeInteger Ninv, NinvPre;
    std::vector<CINativeInteger> T1, T1p, T2, T2p;  // forward twist: wm^{-i}, wm^{-N-i}
    std::vector<CINativeInteger> C1, C1p, C2, C2p;  // inverse untwist: wm^{N+i}/d, wm^{N-i}/d, d = 2 wm^N
    CINativeInteger mid, midPre;                    // i = N/2: wm^N / (wm^{N/2} + wm^{-N/2})
    std::vector<uint32_t> brev;
    // reference (slow) tables
    std::vector<CINativeInteger> wmPow;
    CINativeVector rootN, rootNinv;
    CINativeInteger detInv;
};

using Registry = std::map<uint64_t, std::shared_ptr<const CITables>>;
std::atomic<const Registry*> g_reg{nullptr};
std::mutex g_regMutex;
std::vector<std::unique_ptr<Registry>>& Retired() {  // keep old snapshots alive (readers may hold refs)
    static std::vector<std::unique_ptr<Registry>> r;
    return r;
}

const CITables* Find(uint64_t q) {
    const Registry* r = g_reg.load(std::memory_order_acquire);
    if (r == nullptr)
        return nullptr;
    auto it = r->find(q);
    return (it == r->end()) ? nullptr : it->second.get();
}

const CITables& Lookup(const CINativeInteger& q) {
    const CITables* t = Find(q.ConvertToInt());
    if (t == nullptr)
        OPENFHE_THROW("CI transform requested for an unregistered modulus");
    return *t;
}

inline uint32_t RevBits(uint32_t x, uint32_t bits) {
    uint32_t r = 0;
    for (uint32_t b = 0; b < bits; ++b)
        r |= ((x >> b) & 1u) << (bits - 1 - b);
    return r;
}

}  // namespace

void RegisterCIModulus(const CINativeInteger& modulus, uint32_t N, const CINativeInteger& wm) {
    std::lock_guard<std::mutex> lk(g_regMutex);
    uint64_t key = modulus.ConvertToInt();
    if (Find(key) != nullptr)
        return;
    auto t      = std::make_shared<CITables>();
    const auto& q = modulus;
    t->N        = N;
    t->q        = q;
    t->wm       = wm;
    const uint32_t m = 4 * N;
    t->wmPow.resize(m);
    t->wmPow[0] = CINativeInteger(1);
    for (uint32_t k = 1; k < m; ++k)
        t->wmPow[k] = t->wmPow[k - 1].ModMul(wm, q);
    auto W = [&](int64_t e) -> const CINativeInteger& {
        e %= static_cast<int64_t>(m);
        if (e < 0)
            e += m;
        return t->wmPow[static_cast<size_t>(e)];
    };
    uint32_t logN = 0;
    while ((1u << logN) < N)
        ++logN;
    t->brev.resize(N);
    for (uint32_t i = 0; i < N; ++i)
        t->brev[i] = RevBits(i, logN);
    t->psiRev       = CINativeVector(N, q);
    t->psiRevPre    = CINativeVector(N, q);
    t->psiInvRev    = CINativeVector(N, q);
    t->psiInvRevPre = CINativeVector(N, q);
    for (uint32_t i = 0; i < N; ++i) {
        const uint32_t r = t->brev[i];
        t->psiRev[r]       = W(2 * static_cast<int64_t>(i));
        t->psiRevPre[r]    = t->psiRev[r].PrepModMulConst(q);
        t->psiInvRev[r]    = W(-2 * static_cast<int64_t>(i));
        t->psiInvRevPre[r] = t->psiInvRev[r].PrepModMulConst(q);
    }
    t->Ninv    = CINativeInteger(N).ModInverse(q);
    t->NinvPre = t->Ninv.PrepModMulConst(q);
    t->detInv  = W(N).ModMul(CINativeInteger(2), q).ModInverse(q);
    auto pre   = [&](std::vector<CINativeInteger>& v, std::vector<CINativeInteger>& vp) {
        vp.resize(v.size());
        for (size_t i = 0; i < v.size(); ++i)
            vp[i] = v[i].PrepModMulConst(q);
    };
    t->T1.resize(N);
    t->T2.resize(N);
    t->C1.resize(N);
    t->C2.resize(N);
    for (uint32_t i = 0; i < N; ++i) {
        t->T1[i] = W(-static_cast<int64_t>(i));
        t->T2[i] = W(-static_cast<int64_t>(N) - i);
        t->C1[i] = W(static_cast<int64_t>(N) + i).ModMul(t->detInv, q);
        t->C2[i] = W(static_cast<int64_t>(N) - i).ModMul(t->detInv, q);
    }
    pre(t->T1, t->T1p);
    pre(t->T2, t->T2p);
    pre(t->C1, t->C1p);
    pre(t->C2, t->C2p);
    t->mid    = W(N).ModMul(W(N / 2).ModAdd(W(-static_cast<int64_t>(N / 2)), q).ModInverse(q), q);
    t->midPre = t->mid.PrepModMulConst(q);
    t->rootN    = CINativeVector(N, q);
    t->rootNinv = CINativeVector(N, q);
    for (uint32_t k = 0; k < N; ++k) {
        t->rootN[k]    = W(4 * static_cast<int64_t>(k));
        t->rootNinv[k] = W(-4 * static_cast<int64_t>(k));
    }
    const Registry* old = g_reg.load(std::memory_order_acquire);
    auto next           = std::make_unique<Registry>(old ? *old : Registry());
    (*next)[key]        = std::move(t);
    g_reg.store(next.get(), std::memory_order_release);
    Retired().push_back(std::move(next));
}

bool IsCIModulus(const CINativeInteger& modulus) {
    return Find(modulus.ConvertToInt()) != nullptr;
}

void ClearCIModuli() {
    std::lock_guard<std::mutex> lk(g_regMutex);
    auto next = std::make_unique<Registry>();
    g_reg.store(next.get(), std::memory_order_release);
    Retired().push_back(std::move(next));
}

void CIForwardTransform(CINativeVector& vals) {
    const CITables& t = Lookup(vals.GetModulus());
    const uint32_t N  = t.N;
    const auto& q     = t.q;
    if (vals.GetLength() != N)
        OPENFHE_THROW("CIForwardTransform: length mismatch with registered ring dimension");
    // folded twist, pairwise in place: b_i = a_i T1_i + a_{N-i} T2_i
    for (uint32_t i = 1; i <= N / 2; ++i) {
        const uint32_t k = N - i;
        const CINativeInteger ai = vals[i], ak = vals[k];
        vals[i] = ai.ModMulFastConst(t.T1[i], q, t.T1p[i]).ModAddFast(ak.ModMulFastConst(t.T2[i], q, t.T2p[i]), q);
        if (k != i)
            vals[k] = ak.ModMulFastConst(t.T1[k], q, t.T1p[k]).ModAddFast(ai.ModMulFastConst(t.T2[k], q, t.T2p[k]), q);
    }
    intnat::NumberTheoreticTransformNat<CINativeVector>().ForwardTransformToBitReverseInPlace(t.psiRev, t.psiRevPre,
                                                                                            &vals);
    // output stays in bit-reversed node order (PrecomputeAutoMapCI accounts for it)
}

void CIInverseTransform(CINativeVector& vals) {
    const CITables& t = Lookup(vals.GetModulus());
    const uint32_t N  = t.N;
    const auto& q     = t.q;
    if (vals.GetLength() != N)
        OPENFHE_THROW("CIInverseTransform: length mismatch with registered ring dimension");
    // input is in bit-reversed node order
    intnat::NumberTheoreticTransformNat<CINativeVector>().InverseTransformFromBitReverseInPlace(
            t.psiInvRev, t.psiInvRevPre, t.Ninv, t.NinvPre, &vals);
    // untwist, pairwise in place: a_i = b_i C1_i - b_{N-i} C2_i
    for (uint32_t i = 1; i < N / 2; ++i) {
        const uint32_t k = N - i;
        const CINativeInteger bi = vals[i], bk = vals[k];
        vals[i] = bi.ModMulFastConst(t.C1[i], q, t.C1p[i]).ModSubFast(bk.ModMulFastConst(t.C2[i], q, t.C2p[i]), q);
        vals[k] = bk.ModMulFastConst(t.C1[k], q, t.C1p[k]).ModSubFast(bi.ModMulFastConst(t.C2[k], q, t.C2p[k]), q);
    }
    vals[N / 2] = vals[N / 2].ModMulFastConst(t.mid, q, t.midPre);
}

// ---- reference (original) implementation, kept for validation ----
void CIForwardTransformRef(CINativeVector& vals) {
    const CITables& t = Lookup(vals.GetModulus());
    const uint32_t N  = t.N;
    const uint32_t m  = 4 * N;
    const CINativeInteger& q = t.q;
    CINativeVector at(N, q);
    at[0] = vals[0] % q;
    for (uint32_t i = 1; i < N; ++i)
        at[i] = vals[i].ModMul(t.wmPow[i], q).ModAdd(vals[N - i].ModMul(t.wmPow[m - (N - i)], q), q);
    CINativeVector result(N, q);
    intnat::NumberTheoreticTransformNat<CINativeVector>().ForwardTransformIterative(at, t.rootN, &result);
    for (uint32_t j = 0; j < N; ++j)  // bit-reversed node order, matching CIForwardTransform
        vals[t.brev[j]] = result[j];
}

void CIInverseTransformRef(CINativeVector& vals) {
    const CITables& t = Lookup(vals.GetModulus());
    const uint32_t N  = t.N;
    const uint32_t m  = 4 * N;
    const CINativeInteger& q = t.q;
    CINativeVector nat(N, q), at(N, q);
    for (uint32_t j = 0; j < N; ++j)  // from bit-reversed node order
        nat[j] = vals[t.brev[j]];
    intnat::NumberTheoreticTransformNat<CINativeVector>().ForwardTransformIterative(nat, t.rootNinv, &at);
    for (uint32_t i = 0; i < N; ++i)
        at[i] = at[i].ModMul(t.Ninv, q);
    CINativeVector a(N, q);
    a[0] = at[0];
    for (uint32_t i = 1; i < N; ++i) {
        uint32_t k = N - i;
        if (i < k) {
            a[i] = at[i].ModMul(t.wmPow[N - i], q).ModSub(t.wmPow[m - (N - i)].ModMul(at[k], q), q).ModMul(t.detInv, q);
            a[k] = t.wmPow[i].ModMul(at[k], q).ModSub(at[i].ModMul(t.wmPow[m - i], q), q).ModMul(t.detInv, q);
        }
        else if (i == k) {
            CINativeInteger d = t.wmPow[i].ModAdd(t.wmPow[m - i], q);
            a[i]              = at[i].ModMul(d.ModInverse(q), q);
        }
    }
    vals = a;
}

}  // namespace lbcrypto
