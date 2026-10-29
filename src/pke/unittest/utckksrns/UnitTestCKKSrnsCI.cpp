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
// AND ANY EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED. ...
//==================================================================================

//
// Native conjugate-invariant (real) CKKS bootstrap -- foundational tests.
// This milestone (C2) covers the REAL_CI enum plumbing and the q = 1 mod 4N prime
// supply that the CI NTT requires (plan risk R6). The twisted CI NTT, encode/decode,
// rotations, and the bootstrap driver land in subsequent milestones (C3, C4) and are
// verified against the Phase-0 golden vectors under reference/golden/.
//

#include "constants.h"
#include "math/nbtheory.h"
#include "math/math-hal.h"
#include "math/dftransform.h"
#include "math/ci-transform.h"
#include "lattice/lat-hal.h"
#include "openfhe.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "gtest/gtest.h"

#include <cmath>
#include <complex>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using namespace lbcrypto;

// ---- CI embedding helpers (mirror reference/ci_ckks; double precision) ------------
namespace {
// Analytic CI decode matrix U[slot j][coeff i]: U[j][0]=1, else 2 cos(pi(4j+1)i/2N).
double DenseU(uint32_t N, uint32_t j, uint32_t i) {
    if (i == 0)
        return 1.0;
    return 2.0 * std::cos(M_PI * static_cast<double>((4 * j + 1) * i) / (2.0 * N));
}
// CIBasisScale on the coefficient index: 1 for the constant column, 2 otherwise.
double CIBasisScale(uint32_t i) {
    return (i == 0) ? 1.0 : 2.0;
}
// Q = inverse of the g=5 slot permutation P (cyclic position k -> natural index t,
// where 5^k mod 4N == +-(4t+1)).
std::vector<uint32_t> SlotPermQ(uint32_t N) {
    const uint32_t m = 4 * N;
    std::vector<uint32_t> Q(N);
    uint32_t five = 1;
    for (uint32_t k = 0; k < N; ++k) {
        uint32_t r = five;
        if (r % 4 == 3)
            r = (m - r) % m;
        uint32_t t = (r - 1) / 4;
        Q[t] = k;
        five = (five * 5) % m;
    }
    return Q;
}

// ---- Integer twisted CI NTT over Z_q (q = 1 mod 4N); spec = reference/ci_ckks/ci_ntt.py
// wm is a primitive 4N-th root of unity mod q. Exponents are reduced mod 4N (ord(wm)).
NativeInteger CIWPow(const NativeInteger& wm, int64_t e, uint32_t N, const NativeInteger& q) {
    int64_t m = 4 * static_cast<int64_t>(N);
    int64_t r = ((e % m) + m) % m;
    return wm.ModExp(NativeInteger(static_cast<uint64_t>(r)), q);
}

// Direct: ahat[j] = a(wm^{4j+1}) = a_0 + sum_{i>=1} a_i (wm^{(4j+1)i} + wm^{-(4j+1)i}).
std::vector<NativeInteger> CINTTForwardDirect(const std::vector<NativeInteger>& a, uint32_t N,
                                              const NativeInteger& q, const NativeInteger& wm) {
    std::vector<NativeInteger> ahat(N);
    for (uint32_t j = 0; j < N; ++j) {
        int64_t node = 4 * static_cast<int64_t>(j) + 1;
        NativeInteger acc = a[0] % q;
        for (uint32_t i = 1; i < N; ++i) {
            NativeInteger sum = CIWPow(wm, node * i, N, q).ModAdd(CIWPow(wm, -node * (int64_t)i, N, q), q);
            acc = acc.ModAdd(a[i].ModMul(sum, q), q);
        }
        ahat[j] = acc;
    }
    return ahat;
}

// Kim-Song s4.3 fast: twiddle then N-point cyclic NTT (w_N = wm^4).
std::vector<NativeInteger> CINTTForwardFast(const std::vector<NativeInteger>& a, uint32_t N,
                                            const NativeInteger& q, const NativeInteger& wm) {
    std::vector<NativeInteger> at(N);
    at[0] = a[0] % q;
    for (uint32_t i = 1; i < N; ++i)
        at[i] = a[i].ModMul(CIWPow(wm, (int64_t)i, N, q), q)
                    .ModAdd(a[N - i].ModMul(CIWPow(wm, -(int64_t)(N - i), N, q), q), q);
    std::vector<NativeInteger> ahat(N);
    for (uint32_t j = 0; j < N; ++j) {
        NativeInteger acc(0);
        for (uint32_t i = 0; i < N; ++i)
            acc = acc.ModAdd(at[i].ModMul(CIWPow(wm, 4 * (int64_t)((i * j) % N), N, q), q), q);
        ahat[j] = acc;
    }
    return ahat;
}

// Inverse of the fast forward: N-point INTT then untwiddle (2x2 solve per (i,N-i) pair).
std::vector<NativeInteger> CINTTInverseFast(const std::vector<NativeInteger>& ahat, uint32_t N,
                                            const NativeInteger& q, const NativeInteger& wm) {
    std::vector<NativeInteger> at(N);
    NativeInteger Ninv = NativeInteger(N).ModInverse(q);
    for (uint32_t i = 0; i < N; ++i) {
        NativeInteger acc(0);
        for (uint32_t j = 0; j < N; ++j)
            acc = acc.ModAdd(ahat[j].ModMul(CIWPow(wm, -4 * (int64_t)((i * j) % N), N, q), q), q);
        at[i] = acc.ModMul(Ninv, q);
    }
    std::vector<NativeInteger> a(N);
    a[0] = at[0];
    NativeInteger detInv = CIWPow(wm, (int64_t)N, N, q).ModMul(NativeInteger(2), q).ModInverse(q);
    for (uint32_t i = 1; i < N; ++i) {
        uint32_t k = N - i;
        if (i < k) {
            // a_i = (at_i wm^{N-i} - wm^{-(N-i)} at_{N-i}) / det ; det = 2 wm^N
            a[i] = at[i].ModMul(CIWPow(wm, (int64_t)(N - i), N, q), q)
                       .ModSub(CIWPow(wm, -(int64_t)(N - i), N, q).ModMul(at[k], q), q)
                       .ModMul(detInv, q);
            a[k] = CIWPow(wm, (int64_t)i, N, q).ModMul(at[k], q)
                       .ModSub(at[i].ModMul(CIWPow(wm, -(int64_t)i, N, q), q), q)
                       .ModMul(detInv, q);
        }
        else if (i == k) {  // self-paired (i = N/2): at_i = a_i (wm^{N/2}+wm^{-N/2})
            NativeInteger d = CIWPow(wm, (int64_t)i, N, q).ModAdd(CIWPow(wm, -(int64_t)i, N, q), q);
            a[i] = at[i].ModMul(d.ModInverse(q), q);
        }
    }
    return a;
}

// Independent CI-mult oracle: Laurent lift (X^i+X^-i = X^i - X^{2N-i}) + negacyclic conv.
std::vector<NativeInteger> CIRingMultNegacyclic(const std::vector<NativeInteger>& a,
                                                const std::vector<NativeInteger>& b, uint32_t N,
                                                const NativeInteger& q) {
    uint32_t M = 2 * N;
    auto lift = [&](const std::vector<NativeInteger>& v) {
        std::vector<NativeInteger> A(M, NativeInteger(0));
        A[0] = v[0] % q;
        for (uint32_t i = 1; i < N; ++i) {
            A[i] = A[i].ModAdd(v[i], q);
            A[M - i] = A[M - i].ModSub(v[i], q);
        }
        return A;
    };
    std::vector<NativeInteger> A = lift(a), B = lift(b), C(M, NativeInteger(0));
    for (uint32_t u = 0; u < M; ++u) {
        if (A[u] == NativeInteger(0))
            continue;
        for (uint32_t w = 0; w < M; ++w) {
            NativeInteger prod = A[u].ModMul(B[w], q);
            uint32_t k = u + w;
            if (k < M)
                C[k] = C[k].ModAdd(prod, q);
            else
                C[k - M] = C[k - M].ModSub(prod, q);  // X^{2N} = -1
        }
    }
    std::vector<NativeInteger> c(N);
    c[0] = C[0];
    for (uint32_t i = 1; i < N; ++i)
        c[i] = C[i];
    return c;
}

// Cleartext CI automorphism oracle a -> a(X^k) on CI coefficients: Laurent lift
// (b_i = X^i - X^{2N-i}), permute X^e -> X^{ek} (negacyclic, X^{2N}=-1), extract.
std::vector<NativeInteger> CIAutomorphismOracle(const std::vector<NativeInteger>& a, uint32_t k,
                                                uint32_t N, const NativeInteger& q) {
    uint32_t M = 2 * N;
    std::vector<NativeInteger> A(M, NativeInteger(0)), B(M, NativeInteger(0));
    A[0] = a[0] % q;
    for (uint32_t i = 1; i < N; ++i) {
        A[i]     = A[i].ModAdd(a[i], q);
        A[M - i] = A[M - i].ModSub(a[i], q);
    }
    for (uint32_t e = 0; e < M; ++e) {
        if (A[e] == NativeInteger(0))
            continue;
        uint64_t ek   = static_cast<uint64_t>(e) * k;
        uint32_t p    = static_cast<uint32_t>(ek % M);
        bool negative = ((ek / M) % 2) != 0;  // X^{2N} = -1
        B[p] = negative ? B[p].ModSub(A[e], q) : B[p].ModAdd(A[e], q);
    }
    std::vector<NativeInteger> c(N);
    c[0] = B[0];
    for (uint32_t i = 1; i < N; ++i)
        c[i] = B[i];
    return c;
}
}  // namespace

// ---- REAL_CI enum plumbing round-trips through all three converters --------------
TEST(UTCKKSrnsCI, EnumConvertersRoundTrip) {
    EXPECT_EQ(convertToCKKSDataType(std::string("REAL")), REAL);
    EXPECT_EQ(convertToCKKSDataType(std::string("COMPLEX")), COMPLEX);
    EXPECT_EQ(convertToCKKSDataType(std::string("REAL_CI")), REAL_CI);

    EXPECT_EQ(convertToCKKSDataType(static_cast<uint32_t>(REAL_CI)), REAL_CI);

    std::ostringstream os;
    os << REAL_CI;
    EXPECT_EQ(os.str(), std::string("REAL_CI"));

    // REAL_CI is a new, distinct value (does not collide with REAL/COMPLEX).
    EXPECT_NE(static_cast<int>(REAL_CI), static_cast<int>(REAL));
    EXPECT_NE(static_cast<int>(REAL_CI), static_cast<int>(COMPLEX));
}

TEST(UTCKKSrnsCI, UnknownDataTypeStillThrows) {
    EXPECT_THROW(convertToCKKSDataType(std::string("NOT_A_TYPE")), OpenFHEException);
    EXPECT_THROW(convertToCKKSDataType(static_cast<uint32_t>(999)), OpenFHEException);
}

// ---- q = 1 mod 4N prime supply (CI NTT requirement; plan risk R6) ----------------
// The CI ring needs NTT-friendly primes q = 1 (mod 4N) instead of the standard
// q = 1 (mod 2N). This halves prime density; confirm a deep modulus chain is still
// available at the target ring dimensions without exhaustion.
static void CheckPrimeChainModulo4N(uint32_t N, uint32_t numPrimes, uint32_t bits) {
    const uint64_t fourN = 4ULL * N;
    std::set<uint64_t> seen;
    NativeInteger q = FirstPrime<NativeInteger>(bits, fourN);
    for (uint32_t i = 0; i < numPrimes; ++i) {
        uint64_t qi = q.ConvertToInt();
        EXPECT_EQ(qi % fourN, 1ULL) << "prime " << qi << " is not 1 mod 4N=" << fourN
                                    << " at N=" << N;
        EXPECT_TRUE(seen.insert(qi).second) << "duplicate prime " << qi << " at N=" << N;
        q = PreviousPrime<NativeInteger>(q, fourN);
    }
    EXPECT_EQ(seen.size(), numPrimes) << "prime exhaustion at N=" << N;
}

TEST(UTCKKSrnsCI, PrimeSupplyModulo4N_N4096) {
    CheckPrimeChainModulo4N(1u << 12, 24, 50);
}
TEST(UTCKKSrnsCI, PrimeSupplyModulo4N_N32768) {
    CheckPrimeChainModulo4N(1u << 15, 24, 55);
}
TEST(UTCKKSrnsCI, PrimeSupplyModulo4N_N65536) {
    CheckPrimeChainModulo4N(1u << 16, 24, 59);
}

// ---- C2b: OpenFHE FFTSpecial@4N reproduces the CI embedding (Derivation A in C++) -
// The CI decode is the restriction of the complex special-FFT at cyclotomic order 4N
// to the conjugation-fixed subspace:
//     (U @ coeffs)[t] = Re( FFTSpecial_4N( Dscale @ coeffs )[ Q[t] ] ).
// This bridges the Phase-0 oracle (reference/) to the OpenFHE transform the CI
// encode/decode will use, BEFORE the twisted integer NTT lands (a pure encode/decode
// round-trip cancels through NTT/INTT regardless of CI-ness; multiplication needs the
// twist, handled in a later milestone).
static void CheckFFTSpecialReproducesU(uint32_t N, double tol) {
    DiscreteFourierTransform::Initialize(4 * N, N);
    std::vector<uint32_t> Q = SlotPermQ(N);
    for (uint32_t c = 0; c < N; ++c) {
        std::vector<std::complex<double>> vals(N, std::complex<double>(0.0, 0.0));
        vals[c] = std::complex<double>(CIBasisScale(c), 0.0);  // unit coeff e_c, scaled
        DiscreteFourierTransform::FFTSpecial(vals, 4 * N);
        // The CI decode is the REAL part (restriction to the conjugation-fixed
        // subspace); the imaginary part is the discarded antisymmetric (sine) component.
        for (uint32_t t = 0; t < N; ++t) {
            double got = vals[Q[t]].real();
            double want = DenseU(N, t, c);
            EXPECT_NEAR(got, want, tol) << "U[" << t << "][" << c << "] mismatch, N=" << N;
        }
    }
}

TEST(UTCKKSrnsCI, FFTSpecial4N_ReproducesCIEmbedding) {
    for (uint32_t logN = 2; logN <= 7; ++logN)
        CheckFFTSpecialReproducesU(1u << logN, 1e-9);
}

// ---- C3b: integer twisted CI NTT over Z_q matches the reference spec ---------------
// q = 1 mod 4N. RootOfUnity(4N, q) gives a primitive 4N-th root. We verify the s4.3
// fast factorization == direct node evaluation, the fast inverse round-trips, and the
// forward is a ring homomorphism: forward(a*b) == forward(a) (x) forward(b) elementwise
// (the property that makes Hadamard product = CI ring multiplication for homomorphic
// mult), cross-checked against an independent negacyclic-convolution CI-mult oracle.
struct CINttCase {
    uint32_t N;
    uint64_t q;
};
static const CINttCase kCINttCases[] = {
    {4, 257}, {8, 257}, {16, 257}, {32, 257}, {16, 769}, {64, 769},
};

static std::vector<NativeInteger> RandVec(uint32_t N, uint64_t q, uint32_t seed) {
    std::mt19937_64 rng(seed);
    std::vector<NativeInteger> v(N);
    for (uint32_t i = 0; i < N; ++i)
        v[i] = NativeInteger(rng() % q);
    return v;
}

TEST(UTCKKSrnsCI, CINTT_FastEqualsDirect) {
    for (const auto& c : kCINttCases) {
        NativeInteger q(c.q), wm = RootOfUnity<NativeInteger>(4 * c.N, q);
        auto a = RandVec(c.N, c.q, 7 + c.N);
        EXPECT_EQ(CINTTForwardFast(a, c.N, q, wm), CINTTForwardDirect(a, c.N, q, wm))
            << "N=" << c.N << " q=" << c.q;
    }
}

TEST(UTCKKSrnsCI, CINTT_ForwardInverseIdentity) {
    for (const auto& c : kCINttCases) {
        NativeInteger q(c.q), wm = RootOfUnity<NativeInteger>(4 * c.N, q);
        auto a = RandVec(c.N, c.q, 11 + c.N);
        EXPECT_EQ(CINTTInverseFast(CINTTForwardFast(a, c.N, q, wm), c.N, q, wm), a)
            << "N=" << c.N << " q=" << c.q;
    }
}

TEST(UTCKKSrnsCI, CINTT_IsRingHomomorphism_HadamardIsCIMult) {
    for (const auto& c : kCINttCases) {
        NativeInteger q(c.q), wm = RootOfUnity<NativeInteger>(4 * c.N, q);
        auto a = RandVec(c.N, c.q, 23 + c.N);
        auto b = RandVec(c.N, c.q, 71 + c.N);
        auto ah = CINTTForwardDirect(a, c.N, q, wm);
        auto bh = CINTTForwardDirect(b, c.N, q, wm);
        std::vector<NativeInteger> had(c.N);
        for (uint32_t i = 0; i < c.N; ++i)
            had[i] = ah[i].ModMul(bh[i], q);
        auto cprod = CIRingMultNegacyclic(a, b, c.N, q);
        EXPECT_EQ(CINTTForwardDirect(cprod, c.N, q, wm), had) << "N=" << c.N << " q=" << c.q;
        // and the inverse recovers the product coefficients
        EXPECT_EQ(CINTTInverseFast(had, c.N, q, wm), cprod) << "N=" << c.N << " q=" << c.q;
    }
}

// ---- C3c: the LIBRARY ci-transform (math/ci-transform.h) on NativeVector matches the
// validated in-test reference and the CI-mult oracle, via OpenFHE's cyclic NTT primitive.
static NativeVector ToNativeVector(const std::vector<NativeInteger>& v, const NativeInteger& q) {
    NativeVector out(v.size(), q);
    for (size_t i = 0; i < v.size(); ++i)
        out[i] = v[i];
    return out;
}
static std::vector<NativeInteger> FromNativeVector(const NativeVector& v) {
    std::vector<NativeInteger> out(v.GetLength());
    for (size_t i = 0; i < v.GetLength(); ++i)
        out[i] = v[i];
    return out;
}

TEST(UTCKKSrnsCI, CITransform_LibraryMatchesReference) {
    for (const auto& c : kCINttCases) {
        ClearCIModuli();  // test cases reuse some primes across N; a prime maps to one N
        NativeInteger q(c.q), wm = RootOfUnity<NativeInteger>(4 * c.N, q);
        RegisterCIModulus(q, c.N, wm);
        EXPECT_TRUE(IsCIModulus(q));

        auto a = RandVec(c.N, c.q, 31 + c.N);
        NativeVector av = ToNativeVector(a, q);
        CIForwardTransform(av);
        // the optimized CI NTT keeps the eval vector in bit-reversed node order
        auto direct = CINTTForwardDirect(a, c.N, q, wm);
        std::vector<NativeInteger> directRev(c.N);
        uint32_t logN = 0;
        while ((1u << logN) < c.N)
            ++logN;
        for (uint32_t j = 0; j < c.N; ++j)
            directRev[ReverseBits(j, logN)] = direct[j];
        EXPECT_EQ(FromNativeVector(av), directRev) << "fwd N=" << c.N;
        NativeVector ar = ToNativeVector(a, q);
        CIForwardTransformRef(ar);
        EXPECT_EQ(FromNativeVector(ar), directRev) << "ref fwd N=" << c.N;
        CIInverseTransform(av);
        EXPECT_EQ(FromNativeVector(av), a) << "round-trip N=" << c.N;

        // CI ring multiply through the library transform == negacyclic oracle.
        auto b = RandVec(c.N, c.q, 91 + c.N);
        NativeVector af = ToNativeVector(a, q), bf = ToNativeVector(b, q);
        CIForwardTransform(af);
        CIForwardTransform(bf);
        NativeVector cf(c.N, q);
        for (uint32_t i = 0; i < c.N; ++i)
            cf[i] = af[i].ModMul(bf[i], q);
        CIInverseTransform(cf);
        EXPECT_EQ(FromNativeVector(cf), CIRingMultNegacyclic(a, b, c.N, q)) << "mult N=" << c.N;
    }
    ClearCIModuli();
}

// ---- C3c: CI ring multiply through the REAL PolyImpl::SwitchFormat dispatch path -----
// Builds native Polys over a registered CI modulus, switches to EVALUATION via the
// dispatched CI transform, multiplies pointwise, switches back, and checks against the
// negacyclic CI-mult oracle. This is the integration that makes the whole DCRTPoly
// scheme stack (Enc/Dec/Mult/KeySwitch) operate on CI ring elements.
TEST(UTCKKSrnsCI, PolyImpl_SwitchFormat_CIRingMult) {
    struct PCase { uint32_t N; uint64_t q; };
    const PCase cases[] = {{4, 257}, {8, 257}, {16, 769}, {32, 7681}};
    for (const auto& c : cases) {
        ClearCIModuli();
        NativeInteger q(c.q), wm = RootOfUnity<NativeInteger>(4 * c.N, q);
        RegisterCIModulus(q, c.N, wm);
        // ILNativeParams: cyclotomic order 2N -> ring dimension N; root unused on CI path.
        auto params = std::make_shared<ILNativeParams>(2 * c.N, q, NativeInteger(1));

        auto a = RandVec(c.N, c.q, 41 + c.N);
        auto b = RandVec(c.N, c.q, 53 + c.N);
        NativePoly pa(params, Format::COEFFICIENT, true), pb(params, Format::COEFFICIENT, true);
        for (uint32_t i = 0; i < c.N; ++i) {
            pa[i] = a[i];
            pb[i] = b[i];
        }
        pa.SwitchFormat();  // COEFFICIENT -> EVALUATION (CI)
        pb.SwitchFormat();
        NativePoly pc = pa * pb;          // pointwise (Hadamard) in EVALUATION
        pc.SwitchFormat();                // EVALUATION -> COEFFICIENT (CI)

        std::vector<NativeInteger> got(c.N);
        for (uint32_t i = 0; i < c.N; ++i)
            got[i] = pc[i];
        EXPECT_EQ(got, CIRingMultNegacyclic(a, b, c.N, q)) << "N=" << c.N << " q=" << c.q;

        // round-trip identity through SwitchFormat
        NativePoly pr(params, Format::COEFFICIENT, true);
        for (uint32_t i = 0; i < c.N; ++i)
            pr[i] = a[i];
        pr.SwitchFormat();
        pr.SwitchFormat();
        std::vector<NativeInteger> rt(c.N);
        for (uint32_t i = 0; i < c.N; ++i)
            rt[i] = pr[i];
        EXPECT_EQ(rt, a) << "round-trip N=" << c.N;
    }
    ClearCIModuli();
}

// ---- C3g: PrecomputeAutoMapCI is correct -- AutomorphismTransform(k, CImap) in the CI
// eval domain equals the cleartext CI automorphism a -> a(X^k). Includes k = 4N-1 (=-1),
// which is the identity on the CI ring (conjugation X->X^{-1} fixes R).
TEST(UTCKKSrnsCI, CIAutomorphismMap_MatchesOracle) {
    struct ACase { uint32_t N; uint64_t q; };
    const ACase cases[] = {{8, 257}, {16, 769}, {32, 7681}, {64, 7681}};
    for (const auto& c : cases) {
        ClearCIModuli();
        NativeInteger q(c.q), wm = RootOfUnity<NativeInteger>(4 * c.N, q);
        RegisterCIModulus(q, c.N, wm);
        auto params = std::make_shared<ILNativeParams>(2 * c.N, q, NativeInteger(1));
        auto a      = RandVec(c.N, c.q, 17 + c.N);

        // Galois elements 5^r mod 4N (the CI rotation generator powers) and -1.
        std::vector<uint32_t> ks;
        uint32_t five = 1, m = 4 * c.N;
        for (int r = 0; r < 5; ++r) { ks.push_back(five); five = (five * 5) % m; }
        ks.push_back(m - 1);  // -1 mod 4N -> identity on CI

        for (uint32_t k : ks) {
            std::vector<uint32_t> cimap(c.N);
            PrecomputeAutoMapCI(c.N, k, &cimap);

            NativePoly pa(params, Format::COEFFICIENT, true);
            for (uint32_t i = 0; i < c.N; ++i)
                pa[i] = a[i];
            pa.SwitchFormat();                          // COEFFICIENT -> EVALUATION (CI)
            NativePoly pAuto = pa.AutomorphismTransform(k, cimap);
            pAuto.SwitchFormat();                        // EVALUATION -> COEFFICIENT (CI)

            std::vector<NativeInteger> got(c.N);
            for (uint32_t i = 0; i < c.N; ++i)
                got[i] = pAuto[i];
            EXPECT_EQ(got, CIAutomorphismOracle(a, k, c.N, q))
                << "N=" << c.N << " k=" << k;
        }
    }
    ClearCIModuli();
}

// ---- C3h: native CI homomorphic linear transform (the CtS/StC engine). The CI Galois
// rotations {5^t} act simply transitively on the N slots, so ANY matrix M decomposes as
//   M v = sum_t D_t (x) rot_t(v),   D_t[j] = M[j][precomp_t[j]],
// evaluated homomorphically with CI rotations + plaintext diagonals (LT / O(N)-rotation
// path; BSGS collapse is a later optimization). Validated against cleartext M v.
// Slot-level CI rotation map: X -> X^k sends decoded slot j to slot fold((4j+1)k mod 4N), i.e.
// rotated[j] = msg[map[j]]. (PrecomputeAutoMapCI is the EVALUATION-domain map, which the optimized
// CI NTT keeps in bit-reversed node order, so it is not the slot permutation.)
static void CISlotRotationMap(uint32_t N, uint32_t k, std::vector<uint32_t>* out) {
    const uint64_t m = 4ULL * N;
    out->resize(N);
    for (uint32_t j = 0; j < N; ++j) {
        uint64_t r = ((4ULL * j + 1) * k) % m;
        if (r % 4 == 3)
            r = m - r;
        (*out)[j] = static_cast<uint32_t>((r - 1) / 4);
    }
}

TEST(UTCKKSrnsCI, CIHomomorphicLinearTransform) {
    ClearCIModuli();
    const uint32_t N = 1u << 6;  // N=64 (O(N) rotations -> small N for the correctness test)
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetCKKSDataType(REAL_CI);
    parameters.SetRingDim(N);
    parameters.SetMultiplicativeDepth(2);
    parameters.SetScalingModSize(50);
    parameters.SetFirstModSize(60);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetSecurityLevel(HEStd_NotSet);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    auto keys = cc->KeyGen();

    // a small random real transform M and input v
    std::mt19937_64 rng(99);
    std::vector<std::vector<double>> M(N, std::vector<double>(N));
    std::vector<double> v(N);
    for (uint32_t i = 0; i < N; ++i) {
        v[i] = (double)(rng() % 2000) / 1000.0 - 1.0;
        for (uint32_t j = 0; j < N; ++j)
            M[i][j] = (double)(rng() % 200) / 1000.0 - 0.1;
    }

    // Galois keys for all 5^t (t=1..N-1)
    const uint32_t m = 4 * N;
    std::vector<uint32_t> ks;
    std::vector<uint32_t> fivePow(N);
    fivePow[0] = 1;
    for (uint32_t t = 1; t < N; ++t) {
        fivePow[t] = (fivePow[t - 1] * 5) % m;
        ks.push_back(fivePow[t]);
    }
    auto keyMap = cc->EvalAutomorphismKeyGen(keys.secretKey, ks);

    Plaintext pv = cc->MakeCKKSPackedPlaintext(v, 1, 0, nullptr, N);
    auto ct      = cc->Encrypt(keys.publicKey, pv);

    Ciphertext<DCRTPoly> result;
    for (uint32_t t = 0; t < N; ++t) {
        auto rotated = (t == 0) ? ct : cc->EvalAutomorphism(ct, fivePow[t], *keyMap);
        std::vector<uint32_t> precomp(N);
        CISlotRotationMap(N, fivePow[t], &precomp);
        std::vector<double> Dt(N);
        for (uint32_t j = 0; j < N; ++j)
            Dt[j] = M[j][precomp[j]];
        Plaintext pDt = cc->MakeCKKSPackedPlaintext(Dt, 1, 0, nullptr, N);
        auto term     = cc->EvalMult(rotated, pDt);
        result        = (t == 0) ? term : cc->EvalAdd(result, term);
    }
    result = cc->ModReduce(result);

    Plaintext pr;
    cc->Decrypt(keys.secretKey, result, &pr);
    pr->SetLength(N);
    // cleartext M v
    double maxerr = 0;
    for (uint32_t j = 0; j < N; ++j) {
        double mv = 0;
        for (uint32_t i = 0; i < N; ++i)
            mv += M[j][i] * v[i];
        maxerr = std::max(maxerr, std::abs(pr->GetCKKSPackedValue()[j].real() - mv));
    }
    std::cout << "[CIdiag] homomorphic LT maxerr=" << maxerr << " (" << -std::log2(maxerr) << " bits)\n";
    EXPECT_LT(maxerr, 1e-2) << "CI homomorphic linear transform error (max=" << maxerr << ")";
    ClearCIModuli();
}

// ---- Phase-0 routing (fix plan E0.1): final slot precision of the CI bootstrap over the level budgets
// {1,1}..{8,8}, side by side with std CKKS at the same N and scale. (The post-EvalMod coefficient-recovery probe of
// Phase 0 read a library debug hook that item 6.2 removed.)
TEST(UTCKKSrnsCI, CIPhase0RouteScaleAndRecovery) {
    const uint32_t N = 1u << 8;  // log2N=8
    uint32_t levelsAfter = 6;
    SecretKeyDist skd    = UNIFORM_TERNARY;
    std::vector<double> x(N);
    for (uint32_t i = 0; i < N; ++i)
        x[i] = std::sin(0.05 * (i + 1));  // [-1,1]

    for (auto lb : std::vector<uint32_t>{1, 2, 4, 8}) {
        ClearCIModuli();
        std::vector<uint32_t> levelBudget = {lb, lb};
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetCKKSDataType(REAL_CI);
        parameters.SetRingDim(N);
        parameters.SetSecretKeyDist(skd);
        parameters.SetScalingTechnique(FIXEDMANUAL);
        parameters.SetScalingModSize(59);
        parameters.SetFirstModSize(60);
        parameters.SetSecurityLevel(HEStd_NotSet);
        uint32_t depth = levelsAfter + FHECKKSRNS::GetBootstrapDepth(levelBudget, skd);
        parameters.SetMultiplicativeDepth(depth);
        auto cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
        cc->Enable(FHE);
        cc->EvalBootstrapSetup(levelBudget, {0, 0}, N);
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        cc->EvalBootstrapKeyGen(keys.secretKey, N);
        auto pt = cc->MakeCKKSPackedPlaintext(x, 1, depth - 1, nullptr, N);
        auto ct = cc->Encrypt(keys.publicKey, pt);

        auto ctA = cc->EvalBootstrap(ct);

        Plaintext res;
        cc->Decrypt(keys.secretKey, ctA, &res);
        res->SetLength(N);
        double slotErr = 0;
        for (uint32_t i = 0; i < N; ++i)
            slotErr = std::max(slotErr, std::abs(res->GetCKKSPackedValue()[i].real() - x[i]));
        std::cerr << "[CIroute] lvlb={" << lb << "," << lb << "} depth=" << depth << " : final slot = " << std::fixed
                  << std::setprecision(1) << (slotErr > 0 ? -std::log2(slotErr) : 60.0) << " bits\n";
    }

    // E0.1 side-by-side: does STANDARD CKKS collapse CLIMB at the same N/scale? (COMPLEX, N/2 slots)
    for (auto lb : std::vector<uint32_t>{2, 4, 8}) {
      try {
        std::vector<uint32_t> levelBudget = {lb, lb};
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetRingDim(N);  // default COMPLEX
        parameters.SetSecretKeyDist(skd);
        parameters.SetScalingTechnique(FIXEDMANUAL);
        parameters.SetScalingModSize(59);
        parameters.SetFirstModSize(60);
        parameters.SetSecurityLevel(HEStd_NotSet);
        uint32_t depth = levelsAfter + FHECKKSRNS::GetBootstrapDepth(levelBudget, skd);
        parameters.SetMultiplicativeDepth(depth);
        auto cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
        cc->Enable(FHE);
        uint32_t slots = N / 2;
        cc->EvalBootstrapSetup(levelBudget, {0, 0}, slots);
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        cc->EvalBootstrapKeyGen(keys.secretKey, slots);
        std::vector<double> xs(slots);
        for (uint32_t i = 0; i < slots; ++i)
            xs[i] = std::sin(0.05 * (i + 1));
        auto pt  = cc->MakeCKKSPackedPlaintext(xs, 1, depth - 1, nullptr, slots);
        auto ct  = cc->Encrypt(keys.publicKey, pt);
        auto ctA = cc->EvalBootstrap(ct);
        Plaintext res;
        cc->Decrypt(keys.secretKey, ctA, &res);
        res->SetLength(slots);
        double e = 0;
        for (uint32_t i = 0; i < slots; ++i)
            e = std::max(e, std::abs(res->GetCKKSPackedValue()[i].real() - xs[i]));
        std::cerr << "[STDroute] lvlb={" << lb << "," << lb << "} depth=" << depth
                  << " : final slot = " << std::fixed << std::setprecision(1) << (e > 0 ? -std::log2(e) : 60.0)
                  << " bits\n";
      }
      catch (const std::exception& ex) {
        std::cerr << "[STDroute] lvlb={" << lb << "," << lb << "} : FAILED (" << ex.what() << ")\n";
      }
    }
}

// ---- C4: native CI bootstrap end-to-end. Refresh a depleted CI ciphertext encrypting N
// real numbers: ModRaise -> CI-CtS(U^{-1}) -> EvalMod(Chebyshev, reused) -> CI-StC(U), no
// ring switch (rank N throughout). Decrypt(Boot(ct)) ~ Decrypt(ct).
TEST(UTCKKSrnsCI, CINativeBootstrap) {
    ClearCIModuli();
    const uint32_t N = 1u << 8;   // N=256 real slots (log2N=8)
    std::vector<uint32_t> levelBudget = {4, 4};  // hoisted 2-channel collapsed CI real-DFT (4 | log2N)
    uint32_t levelsAfter = 6;
    SecretKeyDist skd    = UNIFORM_TERNARY;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetCKKSDataType(REAL_CI);
    parameters.SetRingDim(N);
    parameters.SetSecretKeyDist(skd);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetScalingModSize(50);
    parameters.SetFirstModSize(60);
    parameters.SetSecurityLevel(HEStd_NotSet);
    uint32_t depth = levelsAfter + FHECKKSRNS::GetBootstrapDepth(levelBudget, skd);
    parameters.SetMultiplicativeDepth(depth);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    cc->EvalBootstrapSetup(levelBudget, {0, 0}, N);
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalBootstrapKeyGen(keys.secretKey, N);

    std::vector<double> x(N);
    for (uint32_t i = 0; i < N; ++i)
        x[i] = std::sin(0.05 * (i + 1));  // spans [-1,1], the CKKS bootstrap input range
    Plaintext pt = cc->MakeCKKSPackedPlaintext(x, 1, depth - 1, nullptr, N);  // near the bottom level
    auto ct      = cc->Encrypt(keys.publicKey, pt);

    // DIAGNOSTIC: plain encrypt->decrypt round-trip precision at THIS config (no bootstrap), to
    // check whether the CI encode/decode itself caps precision.
    {
        Plaintext rt;
        cc->Decrypt(keys.secretKey, ct, &rt);
        rt->SetLength(N);
        double e = 0;
        for (uint32_t i = 0; i < N; ++i)
            e = std::max(e, std::abs(rt->GetCKKSPackedValue()[i].real() - x[i]));
        std::cerr << "[CIdiag] CI encode/enc/dec round-trip maxerr=" << e << " (" << -std::log2(e) << " bits)\n";
    }
    auto ctAfter = cc->EvalBootstrap(ct);
    EXPECT_GT(ctAfter->GetLevel() < ct->GetLevel() ? 1 : 0, 0) << "bootstrap should add levels";

    Plaintext res;
    cc->Decrypt(keys.secretKey, ctAfter, &res);
    res->SetLength(N);
    double maxerr = 0, maxerrNo0 = 0;
    for (uint32_t i = 0; i < N; ++i) {
        double e = std::abs(res->GetCKKSPackedValue()[i].real() - x[i]);
        maxerr   = std::max(maxerr, e);
        if (i != 0)
            maxerrNo0 = std::max(maxerrNo0, e);
    }
    std::cerr << "[CIboot] slot0: got=" << res->GetCKKSPackedValue()[0].real() << " want=" << x[0]
              << " | maxerr=" << maxerr << " (" << -std::log2(maxerr) << " bits)"
              << " | maxerr_excl_slot0=" << maxerrNo0 << " (" << -std::log2(maxerrNo0) << " bits)\n";
    EXPECT_LT(maxerr, 1e-1) << "CI bootstrap refresh error too large (max=" << maxerr << ")";
    ClearCIModuli();
}

// ---- C4 guard (A2.4): the no-ring-switch invariant. Every ring in a REAL_CI context
// (Q towers, auxiliary P towers, extended QP) stays at rank N -- a degree-2N ring is
// never instantiated. Fault-injection confirms ILDCRTParams(4N) would be rank 2N (caught).
TEST(UTCKKSrnsCI, CINoRingSwitchInvariant) {
    ClearCIModuli();
    const uint32_t N = 1u << 12;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetCKKSDataType(REAL_CI);
    parameters.SetRingDim(N);
    parameters.SetMultiplicativeDepth(3);
    parameters.SetScalingModSize(50);
    parameters.SetFirstModSize(60);
    parameters.SetSecurityLevel(HEStd_NotSet);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->KeyGen();  // builds QP key-switching basis

    auto rns = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
    ASSERT_NE(rns, nullptr);
    EXPECT_EQ(rns->GetElementParams()->GetRingDimension(), N);   // Q towers
    EXPECT_EQ(rns->GetParamsP()->GetRingDimension(), N);          // auxiliary P towers
    EXPECT_EQ(rns->GetParamsQP()->GetRingDimension(), N);         // extended QP basis
    for (const auto& t : rns->GetParamsQP()->GetParams())
        EXPECT_EQ(t->GetRingDimension(), N) << "a QP tower exceeds rank N (ring switch!)";

    // Fault injection: a genuine degree-2N ring would be ILDCRTParams(4N) -> totient 2N.
    NativeInteger q = rns->GetElementParams()->GetParams()[0]->GetModulus();
    NativeInteger root = rns->GetElementParams()->GetParams()[0]->GetRootOfUnity();
    auto degree2N = std::make_shared<ILDCRTParams<BigInteger>>(4 * N, std::vector<NativeInteger>{q},
                                                               std::vector<NativeInteger>{root});
    EXPECT_EQ(degree2N->GetRingDimension(), 2 * N) << "sanity: ILDCRTParams(4N) is the degree-2N ring";
    EXPECT_NE(degree2N->GetRingDimension(), N) << "the CI path must never build this ring";
    ClearCIModuli();
}

// ---- C3d-param: a REAL_CI CryptoContext constructs at rank N with N real slots, every
// ciphertext-modulus tower is a registered CI tower, and KeyGen succeeds. KeyGen computes
// b = -a*s + e, so its a*s exercises CI ring multiplication through the dispatched
// SwitchFormat -- i.e. the native CI ring arithmetic now drives the actual PKE layer.
TEST(UTCKKSrnsCI, CIContext_ConstructsRankN_AndKeyGen) {
    ClearCIModuli();
    const uint32_t N = 1u << 12;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetCKKSDataType(REAL_CI);
    parameters.SetRingDim(N);
    parameters.SetMultiplicativeDepth(2);
    parameters.SetScalingModSize(40);
    parameters.SetFirstModSize(45);
    parameters.SetSecurityLevel(HEStd_NotSet);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    EXPECT_EQ(cc->GetRingDimension(), N) << "CI ring dimension must equal N (no degree-2N ring)";
    EXPECT_EQ(cc->GetEncodingParams()->GetBatchSize(), N) << "CI full packing = N real slots";

    // Every ciphertext-modulus (Q) tower is a registered CI tower with q = 1 mod 4N.
    auto elemParams = cc->GetCryptoParameters()->GetElementParams();
    for (const auto& tower : elemParams->GetParams()) {
        NativeInteger q = tower->GetModulus();
        EXPECT_TRUE(IsCIModulus(q)) << "Q tower modulus not registered CI: " << q;
        EXPECT_EQ(q.ConvertToInt() % (4ULL * N), 1ULL) << "Q tower modulus not 1 mod 4N";
    }

    // KeyGen does ring multiplication (a*s) via the CI SwitchFormat path.
    auto keys = cc->KeyGen();
    EXPECT_NE(keys.secretKey, nullptr);
    EXPECT_NE(keys.publicKey, nullptr);
    ClearCIModuli();
}

// ---- C3e-leveled: native CI CKKS encrypts N real numbers, round-trips them, and adds
// them slot-wise -- the end-to-end leveled scheme on real data (full N-slot packing).
// (EvalMult/rotations additionally need CI-aware auxiliary P-basis key-switching, the
// next integration milestone; tested in CILeveled_EvalMult once that lands.)
TEST(UTCKKSrnsCI, CILeveled_EncDec_Add) {
    ClearCIModuli();
    const uint32_t N = 1u << 12;  // N=4096 real slots
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetCKKSDataType(REAL_CI);
    parameters.SetRingDim(N);
    parameters.SetMultiplicativeDepth(2);
    parameters.SetScalingModSize(50);
    parameters.SetFirstModSize(60);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetSecurityLevel(HEStd_NotSet);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    auto keys = cc->KeyGen();
    ASSERT_EQ(cc->GetEncodingParams()->GetBatchSize(), N);

    std::mt19937_64 rng(12345);
    std::vector<double> a(N), b(N);
    for (uint32_t i = 0; i < N; ++i) {
        a[i] = (double)(rng() % 2000) / 1000.0 - 1.0;  // in [-1,1)
        b[i] = (double)(rng() % 2000) / 1000.0 - 1.0;
    }
    Plaintext pa = cc->MakeCKKSPackedPlaintext(a, 1, 0, nullptr, N);
    Plaintext pb = cc->MakeCKKSPackedPlaintext(b, 1, 0, nullptr, N);

    // encode/decode round-trip of N=4096 real numbers
    auto ctA = cc->Encrypt(keys.publicKey, pa);
    auto ctB = cc->Encrypt(keys.publicKey, pb);
    Plaintext pr;
    cc->Decrypt(keys.secretKey, ctA, &pr);
    pr->SetLength(N);
    double maxerr_rt = 0;
    for (uint32_t i = 0; i < N; ++i)
        maxerr_rt = std::max(maxerr_rt, std::abs(pr->GetCKKSPackedValue()[i].real() - a[i]));
    EXPECT_LT(maxerr_rt, 1e-6) << "CI Enc/Dec round-trip error (max=" << maxerr_rt << ")";

    // homomorphic slot-wise add
    auto ctAdd = cc->EvalAdd(ctA, ctB);
    Plaintext pAdd;
    cc->Decrypt(keys.secretKey, ctAdd, &pAdd);
    pAdd->SetLength(N);
    double maxerr_add = 0;
    for (uint32_t i = 0; i < N; ++i)
        maxerr_add = std::max(maxerr_add, std::abs(pAdd->GetCKKSPackedValue()[i].real() - (a[i] + b[i])));
    EXPECT_LT(maxerr_add, 1e-6) << "CI EvalAdd slot-wise error (max=" << maxerr_add << ")";

    ClearCIModuli();
}

// ---- C3f: native CI EvalMult -- slot-wise product of N real numbers, exercising
// HYBRID key-switching (relinearization) across the CI-aware extended QP basis.
TEST(UTCKKSrnsCI, CILeveled_EvalMult) {
    ClearCIModuli();
    const uint32_t N = 1u << 12;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetCKKSDataType(REAL_CI);
    parameters.SetRingDim(N);
    parameters.SetMultiplicativeDepth(3);
    parameters.SetScalingModSize(50);
    parameters.SetFirstModSize(60);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetSecurityLevel(HEStd_NotSet);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    std::mt19937_64 rng(2024);
    std::vector<double> a(N), b(N);
    for (uint32_t i = 0; i < N; ++i) {
        a[i] = (double)(rng() % 2000) / 1000.0 - 1.0;
        b[i] = (double)(rng() % 2000) / 1000.0 - 1.0;
    }
    Plaintext pa = cc->MakeCKKSPackedPlaintext(a, 1, 0, nullptr, N);
    Plaintext pb = cc->MakeCKKSPackedPlaintext(b, 1, 0, nullptr, N);
    auto ctA = cc->Encrypt(keys.publicKey, pa);
    auto ctB = cc->Encrypt(keys.publicKey, pb);

    auto ctMul = cc->EvalMult(ctA, ctB);  // relinearizes via CI-aware QP key-switching
    Plaintext pMul;
    cc->Decrypt(keys.secretKey, ctMul, &pMul);
    pMul->SetLength(N);
    double maxerr_mul = 0;
    for (uint32_t i = 0; i < N; ++i)
        maxerr_mul = std::max(maxerr_mul, std::abs(pMul->GetCKKSPackedValue()[i].real() - (a[i] * b[i])));
    std::cout << "[CIdiag] EvalMult maxerr=" << maxerr_mul << " (" << -std::log2(maxerr_mul) << " bits)\n";
    EXPECT_LT(maxerr_mul, 1e-3) << "CI EvalMult slot-wise error (max=" << maxerr_mul << ")";

    ClearCIModuli();
}

// ---- DIAGNOSTIC: double-angle chain (x -> 2x^2-1, the EvalMod kernel) precision, CI vs std.
// If CI degrades much faster than std through the depth, the bootstrap precision floor is the
// CI key-switching at depth (EvalMod), not the CtS/StC linear transform.
TEST(UTCKKSrnsCI, CIDoubleAngleChainVsStd) {
    auto runChain = [](CKKSDataType dt, uint32_t N, uint32_t depth) {
        ClearCIModuli();
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetCKKSDataType(dt);
        parameters.SetRingDim(N);
        parameters.SetMultiplicativeDepth(2 * depth + 1);  // 2 mults per double-angle iteration
        parameters.SetScalingModSize(50);
        parameters.SetFirstModSize(60);
        parameters.SetScalingTechnique(FIXEDMANUAL);
        parameters.SetSecurityLevel(HEStd_NotSet);
        auto cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        uint32_t slots = (dt == REAL_CI) ? N : N / 2;
        std::vector<double> x(slots);
        std::mt19937_64 rng(7);
        for (uint32_t i = 0; i < slots; ++i)
            x[i] = (double)(rng() % 1000) / 1000.0 * 1.6 - 0.8;  // in [-0.8,0.8]
        auto pt = cc->MakeCKKSPackedPlaintext(x, 1, 0, nullptr, slots);
        auto ct = cc->Encrypt(keys.publicKey, pt);
        std::vector<double> ref = x;
        for (uint32_t d = 0; d < depth; ++d) {
            ct = cc->EvalMult(ct, ct);
            cc->ModReduceInPlace(ct);
            ct = cc->EvalMult(ct, 2.0);
            ct = cc->EvalSub(ct, 1.0);
            cc->ModReduceInPlace(ct);
            for (uint32_t i = 0; i < slots; ++i)
                ref[i] = 2.0 * ref[i] * ref[i] - 1.0;
        }
        Plaintext res;
        cc->Decrypt(keys.secretKey, ct, &res);
        res->SetLength(slots);
        double maxerr = 0;
        for (uint32_t i = 0; i < slots; ++i)
            maxerr = std::max(maxerr, std::abs(res->GetCKKSPackedValue()[i].real() - ref[i]));
        ClearCIModuli();
        return maxerr;
    };
    const uint32_t N = 1u << 12, depth = 6;
    double eCI  = runChain(REAL_CI, N, depth);
    double eStd = runChain(COMPLEX, N, depth);
    std::cout << "[CIdiag] double-angle chain depth=" << depth << " N=" << N
              << ": CI maxerr=" << eCI << " (" << -std::log2(eCI) << " bits)"
              << " | std maxerr=" << eStd << " (" << -std::log2(eStd) << " bits)\n";
}

// ---- C3g(2/2): native CI rotation end-to-end. EvalAutomorphism by a CI Galois element
// k = 5^r mod 4N permutes the decoded slots exactly per PrecomputeAutoMapCI; k = 4N-1
// (= -1) is the identity (conjugation fixes R).
TEST(UTCKKSrnsCI, CIRotation_EvalAutomorphism) {
    ClearCIModuli();
    const uint32_t N = 1u << 11;  // N=2048 real slots
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetCKKSDataType(REAL_CI);
    parameters.SetRingDim(N);
    parameters.SetMultiplicativeDepth(2);
    parameters.SetScalingModSize(50);
    parameters.SetFirstModSize(60);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetSecurityLevel(HEStd_NotSet);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    auto keys = cc->KeyGen();

    std::vector<double> msg(N);
    for (uint32_t i = 0; i < N; ++i)
        msg[i] = std::sin(0.1 * (i + 1));
    Plaintext pm = cc->MakeCKKSPackedPlaintext(msg, 1, 0, nullptr, N);
    auto ct      = cc->Encrypt(keys.publicKey, pm);

    const uint32_t m = 4 * N;
    std::vector<uint32_t> ks = {5u, (5u * 5u) % m, m - 1};  // 5^1, 5^2, -1 (identity)
    auto keyMap = cc->EvalAutomorphismKeyGen(keys.secretKey, ks);

    for (uint32_t k : ks) {
        auto ctRot = cc->EvalAutomorphism(ct, k, *keyMap);
        Plaintext pr;
        cc->Decrypt(keys.secretKey, ctRot, &pr);
        pr->SetLength(N);

        std::vector<uint32_t> precomp(N);
        CISlotRotationMap(N, k, &precomp);
        double maxerr = 0;
        for (uint32_t j = 0; j < N; ++j)
            maxerr = std::max(maxerr, std::abs(pr->GetCKKSPackedValue()[j].real() - msg[precomp[j]]));
        EXPECT_LT(maxerr, 1e-3) << "CI rotation k=" << k << " slot-permutation error (max=" << maxerr << ")";
        if (k == m - 1) {  // -1 is the identity on the CI ring
            double idErr = 0;
            for (uint32_t j = 0; j < N; ++j)
                idErr = std::max(idErr, std::abs(pr->GetCKKSPackedValue()[j].real() - msg[j]));
            EXPECT_LT(idErr, 1e-3) << "CI automorphism by -1 must be the identity";
        }
    }
    ClearCIModuli();
}

// ---- Paper-style real FFT (Liu-Ma-Wang-Wang, ePrint 2026/2618): O(N log N) CI encode/decode must
// equal the dense U^{-1} / U, and the native bootstrap built on the sparse real factors must refresh
// with real precision for several level budgets, both scaling modes and both secret distributions.
#include "math/ci-realfft.h"

TEST(UTCKKSrnsCI, CIRealFFT_EncodeDecodeMatchDense) {
    for (uint32_t N : {8u, 16u, 64u, 512u}) {
        std::mt19937_64 g(N);
        std::uniform_real_distribution<double> U(-1.0, 1.0);
        std::vector<double> x(N), c(N);
        for (auto& v : x)
            v = U(g);
        for (auto& v : c)
            v = U(g);
        auto Ud = [N](uint32_t a, uint32_t b) {
            return (b == 0) ? 1.0 : 2.0 * std::cos(M_PI * (4.0 * a + 1.0) * b / (2.0 * N));
        };
        std::vector<double> enc, dec;
        CIRealFFTEncode(N, x, enc);
        CIRealFFTDecode(N, c, dec);
        double eEnc = 0, eDec = 0;
        for (uint32_t b = 0; b < N; ++b) {  // U^{-1} = diag(1/N, 1/2N, ...) U^T
            double acc = 0;
            for (uint32_t a = 0; a < N; ++a)
                acc += Ud(a, b) * x[a];
            acc /= (b == 0) ? N : 2.0 * N;
            eEnc = std::max(eEnc, std::abs(acc - enc[b]));
        }
        for (uint32_t a = 0; a < N; ++a) {
            double acc = 0;
            for (uint32_t b = 0; b < N; ++b)
                acc += Ud(a, b) * c[b];
            eDec = std::max(eDec, std::abs(acc - dec[a]));
        }
        EXPECT_LT(eEnc, 1e-13) << "encode N=" << N;
        EXPECT_LT(eDec, 1e-11 * N) << "decode N=" << N;
        // every factor has at most 7 cyclic diagonals (Lemma 4 of the paper)
        for (const auto& F : GetCIRealFFTPlan(N).F)
            EXPECT_LE(F.size(), 7u) << "N=" << N;
    }
}

static double CIBootPrecisionBits(uint32_t logN, std::vector<uint32_t> budget, ScalingTechnique st,
                                  SecretKeyDist skd) {
    ClearCIModuli();
    const uint32_t N = 1u << logN;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetCKKSDataType(REAL_CI);
    parameters.SetRingDim(N);
    parameters.SetSecretKeyDist(skd);
    parameters.SetScalingTechnique(st);
    parameters.SetScalingModSize(59);
    parameters.SetFirstModSize(60);
    parameters.SetSecurityLevel(HEStd_NotSet);
    uint32_t depth = 2 + FHECKKSRNS::GetBootstrapDepth(budget, skd);
    parameters.SetMultiplicativeDepth(depth);
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);
    cc->EvalBootstrapSetup(budget, {0, 0}, N);
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalBootstrapKeyGen(keys.secretKey, N);
    std::vector<double> x(N);
    std::mt19937_64 g(logN);
    std::uniform_real_distribution<double> U(-1.0, 1.0);
    for (auto& v : x)
        v = U(g);
    auto ct  = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(x, 1, depth - 1, nullptr, N));
    auto out = cc->EvalBootstrap(ct);
    Plaintext res;
    cc->Decrypt(keys.secretKey, out, &res);
    res->SetLength(N);
    double e = 0;
    for (uint32_t i = 0; i < N; ++i)
        e = std::max(e, std::abs(res->GetCKKSPackedValue()[i].real() - x[i]));
    ClearCIModuli();
    return -std::log2(e);
}

TEST(UTCKKSrnsCI, CIRealFFTBootstrap_Uniform) {
    EXPECT_GT(CIBootPrecisionBits(10, {2, 2}, FLEXIBLEAUTO, UNIFORM_TERNARY), 13.0);
    EXPECT_GT(CIBootPrecisionBits(10, {3, 3}, FLEXIBLEAUTO, UNIFORM_TERNARY), 13.0);
    EXPECT_GT(CIBootPrecisionBits(10, {4, 3}, FIXEDMANUAL, UNIFORM_TERNARY), 11.0);
}

TEST(UTCKKSrnsCI, CIRealFFTBootstrap_SparseEncapsulated) {
    EXPECT_GT(CIBootPrecisionBits(10, {3, 3}, FLEXIBLEAUTO, SPARSE_ENCAPSULATED), 16.0);
}

// Item 6.3: EvalBootstrapKeyMapIndices lists exactly the CI bootstrap keys (real-FFT set, no conjugation key, plus the
// sparse encapsulation keys), so SerializeEvalBootstrapKey / DeserializeEvalBootstrapKey round-trip them; the
// deserialized context (ring type CI) bootstraps to the same ciphertext as the original. Both orderings.
static void CIBootstrapSerialRoundTrip(bool stcFirst) {
    ClearCIModuli();
    const uint32_t logN = 10, N = 1u << logN;
    const std::vector<uint32_t> budget = {3, 3};
    const SecretKeyDist skd = SPARSE_ENCAPSULATED;
    const uint32_t depth    = 2 + FHECKKSRNS::GetBootstrapDepth(budget, skd);
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetCKKSDataType(REAL_CI);
    parameters.SetRingDim(N);
    parameters.SetSecretKeyDist(skd);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetScalingModSize(59);
    parameters.SetFirstModSize(60);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetMultiplicativeDepth(depth);
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);
    cc->EvalBootstrapSetup(budget, {0, 0}, N, 0, true, stcFirst);
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalBootstrapKeyGen(keys.secretKey, N);
    const std::string tag = keys.secretKey->GetKeyTag();

    std::set<uint32_t> generated;
    for (const auto& kv : cc->GetEvalAutomorphismKeyMap(tag))
        generated.insert(kv.first);
    const auto idx = cc->GetScheme()->EvalBootstrapKeyMapIndices(cc, N);
    ASSERT_EQ(std::set<uint32_t>(idx.begin(), idx.end()), generated);
    EXPECT_EQ(generated.count(cc->GetCyclotomicOrder() - 1), 0u);  // no conjugation key on the CI ring

    std::vector<double> x(N);
    std::mt19937_64 g(63);
    std::uniform_real_distribution<double> U(-1.0, 1.0);
    for (auto& v : x)
        v = U(g);
    const uint32_t encLevel = stcFirst ? depth - budget[1] - 1 : depth - 1;
    auto ct  = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(x, 1, encLevel, nullptr, N));
    auto ref = cc->EvalBootstrap(ct);

    std::stringstream sCC, sSK, sCT, sMult, sBoot;
    Serial::Serialize(cc, sCC, SerType::BINARY);
    Serial::Serialize(keys.secretKey, sSK, SerType::BINARY);
    Serial::Serialize(ct, sCT, SerType::BINARY);
    ASSERT_TRUE(cc->SerializeEvalMultKey(sMult, SerType::BINARY, tag));
    ASSERT_TRUE(cc->SerializeEvalBootstrapKey(sBoot, SerType::BINARY, cc, tag, N));
    cc->ClearEvalMultKeys();
    cc->ClearEvalAutomorphismKeys();
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    ClearCIModuli();

    CryptoContext<DCRTPoly> cc2;
    PrivateKey<DCRTPoly> sk2;
    Ciphertext<DCRTPoly> ct2;
    Serial::Deserialize(cc2, sCC, SerType::BINARY);
    Serial::Deserialize(sk2, sSK, SerType::BINARY);
    Serial::Deserialize(ct2, sCT, SerType::BINARY);
    ASSERT_EQ(cc2->GetCKKSDataType(), REAL_CI);
    for (const auto& p : cc2->GetCryptoParameters()->GetElementParams()->GetParams())
        EXPECT_TRUE(p->IsConjugateInvariant());
    cc2->EvalBootstrapSetup(budget, {0, 0}, N, 0, true, stcFirst);
    ASSERT_TRUE(cc2->DeserializeEvalMultKey(sMult, SerType::BINARY));
    ASSERT_TRUE(cc2->DeserializeEvalBootstrapKey(sBoot, SerType::BINARY, cc2, sk2->GetKeyTag(), N));
    std::set<uint32_t> loaded;
    for (const auto& kv : cc2->GetEvalAutomorphismKeyMap(sk2->GetKeyTag()))
        loaded.insert(kv.first);
    EXPECT_EQ(loaded, generated);

    auto out = cc2->EvalBootstrap(ct2);
    EXPECT_TRUE(out->GetElements() == ref->GetElements());
    Plaintext res;
    cc2->Decrypt(sk2, out, &res);
    res->SetLength(N);
    double e = 0;
    for (uint32_t i = 0; i < N; ++i)
        e = std::max(e, std::abs(res->GetCKKSPackedValue()[i].real() - x[i]));
    EXPECT_GT(-std::log2(e), 12.0);
    cc2->ClearStaticMapsAndVectors();
    ClearCIModuli();
}

TEST(UTCKKSrnsCI, CIBootstrapKeySerialization_CtSFirst) {
    CIBootstrapSerialRoundTrip(false);
}

TEST(UTCKKSrnsCI, CIBootstrapKeySerialization_StCFirst) {
    CIBootstrapSerialRoundTrip(true);
}
