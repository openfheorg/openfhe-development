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
#include <mutex>
#include <vector>

namespace lbcrypto {

namespace {

// Lock-free fast path: standard (non-CI) contexts never register a CI modulus, so this
// stays false and IsCIModulus() returns immediately on the NTT hot path -- no lock, no
// map lookup -- keeping standard CKKS/BGV/BFV arithmetic unregressed.
std::atomic<bool> g_anyCI{false};

struct CITables {
    uint32_t N = 0;
    CINativeInteger q;
    CINativeInteger wm;                  // primitive 4N-th root mod q
    std::vector<CINativeInteger> wmPow;  // wm^k, k = 0 .. 4N-1
    CINativeInteger Ninv;                // N^{-1} mod q
    CINativeInteger detInv;              // (2 wm^N)^{-1} mod q  (untwiddle 2x2 determinant)
    CINativeVector rootN;                // w_N^k = wm^{4k},      k = 0 .. N-1  (cyclic NTT)
    CINativeVector rootNinv;             // w_N^{-k} = wm^{-4k},  k = 0 .. N-1  (cyclic INTT)
};

std::map<uint64_t, CITables>& Registry() {
    static std::map<uint64_t, CITables> r;
    return r;
}
std::mutex& RegistryMutex() {
    static std::mutex m;
    return m;
}

const CITables& Lookup(const CINativeInteger& q) {
    auto it = Registry().find(q.ConvertToInt());
    if (it == Registry().end())
        OPENFHE_THROW("CI transform requested for an unregistered modulus");
    return it->second;
}

}  // namespace

void RegisterCIModulus(const CINativeInteger& modulus, uint32_t N, const CINativeInteger& wm) {
    std::lock_guard<std::mutex> lk(RegistryMutex());
    uint64_t key = modulus.ConvertToInt();
    if (Registry().count(key))
        return;
    CITables t;
    t.N  = N;
    t.q  = modulus;
    t.wm = wm;
    const uint32_t m = 4 * N;
    t.wmPow.resize(m);
    t.wmPow[0] = CINativeInteger(1);
    for (uint32_t k = 1; k < m; ++k)
        t.wmPow[k] = t.wmPow[k - 1].ModMul(wm, modulus);
    t.Ninv   = CINativeInteger(N).ModInverse(modulus);
    t.detInv = t.wmPow[N].ModMul(CINativeInteger(2), modulus).ModInverse(modulus);
    t.rootN    = CINativeVector(N, modulus);
    t.rootNinv = CINativeVector(N, modulus);
    for (uint32_t k = 0; k < N; ++k) {
        t.rootN[k]    = t.wmPow[(4 * k) % m];
        t.rootNinv[k] = t.wmPow[(m - (4 * k) % m) % m];
    }
    Registry().emplace(key, std::move(t));
    g_anyCI.store(true, std::memory_order_relaxed);
}

bool IsCIModulus(const CINativeInteger& modulus) {
    if (!g_anyCI.load(std::memory_order_relaxed))
        return false;  // fast path: no CI moduli anywhere -> no lock
    std::lock_guard<std::mutex> lk(RegistryMutex());
    return Registry().count(modulus.ConvertToInt()) != 0;
}

void ClearCIModuli() {
    std::lock_guard<std::mutex> lk(RegistryMutex());
    Registry().clear();
    g_anyCI.store(false, std::memory_order_relaxed);
}

// COEFFICIENT -> EVALUATION: twiddle, then cyclic N-point NTT (w_N = wm^4).
void CIForwardTransform(CINativeVector& vals) {
    const CITables& t = Lookup(vals.GetModulus());
    const uint32_t N  = t.N;
    const uint32_t m  = 4 * N;
    const CINativeInteger& q = t.q;
    if (vals.GetLength() != N)
        OPENFHE_THROW("CIForwardTransform: length mismatch with registered ring dimension");

    CINativeVector at(N, q);
    at[0] = vals[0] % q;
    for (uint32_t i = 1; i < N; ++i) {
        // atilde_i = a_i * wm^i + a_{N-i} * wm^{-(N-i)}
        at[i] = vals[i].ModMul(t.wmPow[i], q).ModAdd(vals[N - i].ModMul(t.wmPow[m - (N - i)], q), q);
    }
    CINativeVector result(N, q);
    intnat::NumberTheoreticTransformNat<CINativeVector>().ForwardTransformIterative(at, t.rootN, &result);
    vals = result;
}

// EVALUATION -> COEFFICIENT: cyclic N-point INTT, then untwiddle.
void CIInverseTransform(CINativeVector& vals) {
    const CITables& t = Lookup(vals.GetModulus());
    const uint32_t N  = t.N;
    const uint32_t m  = 4 * N;
    const CINativeInteger& q = t.q;
    if (vals.GetLength() != N)
        OPENFHE_THROW("CIInverseTransform: length mismatch with registered ring dimension");

    CINativeVector at(N, q);
    intnat::NumberTheoreticTransformNat<CINativeVector>().ForwardTransformIterative(vals, t.rootNinv, &at);
    for (uint32_t i = 0; i < N; ++i)
        at[i] = at[i].ModMul(t.Ninv, q);

    CINativeVector a(N, q);
    a[0] = at[0];
    for (uint32_t i = 1; i < N; ++i) {
        uint32_t k = N - i;
        if (i < k) {
            // [wm^i        wm^{-(N-i)}] [a_i  ]   [at_i ]      det = 2 wm^N
            // [wm^{-i}     wm^{N-i}   ] [a_{N-i}] = [at_{N-i}]
            a[i] = at[i].ModMul(t.wmPow[N - i], q)
                       .ModSub(t.wmPow[m - (N - i)].ModMul(at[k], q), q)
                       .ModMul(t.detInv, q);
            a[k] = t.wmPow[i].ModMul(at[k], q)
                       .ModSub(at[i].ModMul(t.wmPow[m - i], q), q)
                       .ModMul(t.detInv, q);
        }
        else if (i == k) {  // self-paired i = N/2: at_i = a_i (wm^{N/2} + wm^{-N/2})
            CINativeInteger d = t.wmPow[i].ModAdd(t.wmPow[m - i], q);
            a[i] = at[i].ModMul(d.ModInverse(q), q);
        }
    }
    vals = a;
}

}  // namespace lbcrypto
