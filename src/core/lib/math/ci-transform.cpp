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

// CI NTT. Evaluates a CI element a = a_0 + sum_i a_i (X^i + X^{-i}) at the N points wm^{4j+1}
// (wm a primitive 4N-th root), j = 0..N-1. Since x^{-i} = -wm^N x^{N-i} at those points, this is
// the NTT modulo X^N - wm^N of the fold g_i = a_i - wm^N a_{N-i} (g_0 = a_0). The CT tree of
// X^N - wm^N has node multipliers wm^{e_k}: e_1 = N/2, e_{2k} = e_k/2, e_{2k+1} = e_k/2 + N.
// The fold is fused with the first CT stage and the unfold (with the 1/2) with the last GS
// stage, as raw-word loops in NumberTheoreticTransformNat (CIForwardTransformToBitReverseInPlace,
// CIInverseTransformFromBitReverseInPlace); the eval vector is in bit-reversed node order (no
// permutation pass). The registry is published copy-on-write so the per-transform lookups are
// lock-free.

namespace lbcrypto {

namespace {

struct CITables {
    uint32_t N = 0;
    CINativeInteger q;
    CINativeInteger wm;
    CINativeVector root, rootPre;        // CT node multipliers wm^{e_k} of X^N - wm^N (forward)
    CINativeVector rootInv, rootInvPre;  // wm^{-e_k} (inverse; [2], [3] times wm^{N/2} c)
    CINativeVector fwdK, fwdKPre;        // {wm^N, -wm^{3N/2}, wm^{N/2} - wm^{3N/2}}
    CINativeVector invK, invKPre;        // {c, wm^N, wm^N c, wm^{-N/2}, wm^{N/2}, 2c, 2c wm^{-N/2} / (1 - wm^N)}, c = (2N)^{-1}
    CINativeInteger Ninv;
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
    // node multiplier exponents of the CT tree of X^N - wm^N (index 0 unused)
    std::vector<int64_t> ex(N, 0);
    if (N >= 2)
        ex[1] = N / 2;
    for (uint32_t k = 1; 2 * k + 1 < N; ++k) {
        ex[2 * k]     = ex[k] / 2;
        ex[2 * k + 1] = ex[k] / 2 + N;
    }
    auto prep = [&](CINativeVector& v, CINativeVector& vp) {
        vp = CINativeVector(v.GetLength(), q);
        for (size_t i = 0; i < v.GetLength(); ++i)
            vp[i] = v[i].PrepModMulConst(q);
    };
    t->root    = CINativeVector(N, q);
    t->rootInv = CINativeVector(N, q);
    for (uint32_t k = 0; k < N; ++k) {
        t->root[k]    = W(ex[k]);
        t->rootInv[k] = W(-ex[k]);
    }
    prep(t->root, t->rootPre);
    prep(t->rootInv, t->rootInvPre);
    const int64_t Ni = N;
    t->Ninv          = CINativeInteger(N).ModInverse(q);
    const CINativeInteger c = CINativeInteger(2 * static_cast<uint64_t>(N)).ModInverse(q);
    t->fwdK          = CINativeVector(3, q);
    t->fwdK[0]       = W(Ni);
    t->fwdK[1]       = W(7 * Ni / 2);  // -wm^{3N/2}
    t->fwdK[2]       = W(Ni / 2).ModAdd(W(7 * Ni / 2), q);
    prep(t->fwdK, t->fwdKPre);
    t->invK    = CINativeVector(7, q);
    t->invK[0] = c;
    t->invK[1] = W(Ni);
    t->invK[2] = W(Ni).ModMul(c, q);
    t->invK[3] = W(-Ni / 2);
    t->invK[4] = W(Ni / 2);
    t->invK[5] = t->Ninv;
    t->invK[6] = t->Ninv.ModMul(W(-Ni / 2), q).ModMul(CINativeInteger(1).ModSub(W(Ni), q).ModInverse(q), q);
    prep(t->invK, t->invKPre);
    // second-to-last GS stage carries mu = wm^{N/2} c (absorbed in the fused last stage)
    if (N >= 4) {
        const CINativeInteger mu = W(Ni / 2).ModMul(c, q);
        for (uint32_t k : {2u, 3u}) {
            t->rootInv[k]    = t->rootInv[k].ModMul(mu, q);
            t->rootInvPre[k] = t->rootInv[k].PrepModMulConst(q);
        }
    }
    t->detInv = W(N).ModMul(CINativeInteger(2), q).ModInverse(q);
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
    if (vals.GetLength() != t.N)
        OPENFHE_THROW("CIForwardTransform: length mismatch with registered ring dimension");
    if (t.N < 4) {
        CIForwardTransformRef(vals);
        return;
    }
    intnat::NumberTheoreticTransformNat<CINativeVector>().CIForwardTransformToBitReverseInPlace(
        t.root, t.rootPre, t.fwdK, t.fwdKPre, &vals);
    // output stays in bit-reversed node order (PrecomputeAutoMapCI accounts for it)
}

void CIInverseTransform(CINativeVector& vals) {
    const CITables& t = Lookup(vals.GetModulus());
    if (vals.GetLength() != t.N)
        OPENFHE_THROW("CIInverseTransform: length mismatch with registered ring dimension");
    if (t.N < 4) {
        CIInverseTransformRef(vals);
        return;
    }
    // input is in bit-reversed node order
    intnat::NumberTheoreticTransformNat<CINativeVector>().CIInverseTransformFromBitReverseInPlace(
        t.rootInv, t.rootInvPre, t.invK, t.invKPre, &vals);
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
