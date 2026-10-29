//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2025, NJIT, Duality Technologies Inc. and other contributors
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

#ifdef BOOTSTRAPTIMING
    #define PROFILE
#endif

#include "scheme/ckksrns/ckksrns-fhe.h"

#include <algorithm>
#include <cmath>
#include <chrono>
#include <complex>
#include <cstdint>
#include <functional>
#include <iostream>
#include <limits>
#include <map>
#include <mutex>
#include <memory>
#include <tuple>
#ifdef BOOTSTRAPTIMING
    #include <ostream>
#endif
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "ciphertext.h"
#include "cryptocontext.h"
#include "key/evalkeyrelin.h"
#include "key/privatekey.h"
#include "lattice/lat-hal.h"
#include "math/ci-realfft.h"
#include "math/dftransform.h"
#include "math/hal/basicint.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "scheme/ckksrns/ckksrns-utils.h"
#include "schemebase/base-scheme.h"
#include "utils/diagnostic_output.h"
#include "utils/exception.h"
#include "utils/parallel.h"
#include "utils/utilities.h"

namespace {
// GetBigModulus() calculates the big modulus as the product of
// the "compositeDegree" number of parameter modulus
double GetBigModulus(const std::shared_ptr<lbcrypto::CryptoParametersCKKSRNS>& cryptoParams) {
    const auto& params = cryptoParams->GetElementParams()->GetParams();
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();
    double qDouble = 1.0;
    for (uint32_t j = 0; j < compositeDegree; ++j) {
        qDouble *= params[j]->GetModulus().ConvertToDouble();
    }
    return qDouble;
}

// num/den as a double, without forming an intermediate that overflows the exponent range: both operands
// are shifted down to 53 bits (so each converts exactly) and the shift is restored with ldexp.
double RatioToDouble(const lbcrypto::BigInteger& num, const lbcrypto::BigInteger& den) {
    constexpr uint32_t keep = 53;
    const uint32_t nb = num.GetMSB(), db = den.GetMSB();
    const uint32_t ns = (nb > keep) ? nb - keep : 0;
    const uint32_t ds = (db > keep) ? db - keep : 0;
    const double n = (ns ? num.RShift(static_cast<uint16_t>(ns)) : num).ConvertToDouble();
    const double d = (ds ? den.RShift(static_cast<uint16_t>(ds)) : den).ConvertToDouble();
    return std::ldexp(n / d, static_cast<int>(ns) - static_cast<int>(ds));
}
}  // namespace

namespace lbcrypto {

namespace {
// SPARSE_ENCAPSULATED with the denser sparse secret (Hamming weight 64: first modulus above 60 bits) uses the K = 28
// approximations of SPARSE_TERNARY instead of the K = 16 ones
bool UsesLargeSparseKey(SecretKeyDist skd, uint32_t sparseKSHammingWeight) {
    return (skd == SPARSE_ENCAPSULATED) && (sparseKSHammingWeight > 32);
}

// Linear-transform instrumentation, compiled only with -DBOOTSTRAPTIMING -DBOOTSTRAPTIMING_LT: per BSGS level of CtS /
// StC (CI and std), one "[LT]" line with the number and the time of
//   modUp   digit decompositions (EvalFastRotationPrecompute / EvalKeySwitchPrecomputeCore),
//   baby    hoisted rotations (key inner product + automorphism, no ModUp/ModDown; `ext` = the identity),
//   giant   giant-step key inner products (+ automorphisms) after their own ModUp,
//   modDown polynomial ModDowns QlP -> Ql (a KeySwitchDown counts 2),
//   ptMult  extended-basis plaintext multiplications, add = extended-basis additions.
// Serial runs only (OMP_NUM_THREADS=1): the counters are not atomic; parallel baby loops are timed as a whole.
// In every other build LTRun is a plain call and LTLevel / LTAdd do nothing.
struct LTStats {
    uint32_t modUp = 0, baby = 0, ext = 0, giant = 0, modDown = 0, ptMult = 0, add = 0;
    double tModUp = 0, tBaby = 0, tGiant = 0, tModDown = 0, tPtMult = 0, tAdd = 0;
};
#if defined(BOOTSTRAPTIMING) && defined(BOOTSTRAPTIMING_LT)
LTStats* g_lt = nullptr;  // non-null while an instrumented level runs
// Runs f(); when a level is instrumented, adds n to the counter and the elapsed time to the timer.
template <class F>
decltype(auto) LTRun(uint32_t LTStats::*cnt, double LTStats::*acc, uint32_t n, F&& f) {
    if (g_lt == nullptr)
        return f();
    struct Tm {
        double LTStats::*acc;
        std::chrono::steady_clock::time_point t0 = std::chrono::steady_clock::now();
        ~Tm() {
            if (g_lt)
                g_lt->*acc += std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        }
    } tm{acc};
    g_lt->*cnt += n;
    return f();
}
// Adds n to a counter of the instrumented level (no timing).
inline void LTAdd(uint32_t LTStats::*cnt, uint32_t n) {
    if (g_lt)
        g_lt->*cnt += n;
}
// One instrumented level: counts from construction to Print().
class LTLevel {
public:
    LTLevel(const char* tag, int32_t lvl, uint32_t diags, uint32_t towersQl, uint32_t towersP)
        : tag_(tag), lvl_(lvl), diags_(diags), towersQl_(towersQl), towersP_(towersP) {
        g_lt = &st_;
    }
    ~LTLevel() {
        if (g_lt == &st_)
            g_lt = nullptr;
    }
    void Print() {
        if (g_lt != &st_)
            return;
        g_lt         = nullptr;
        const double t  = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0_).count();
        const auto& s   = st_;
        const double ot = t - s.tModUp - s.tBaby - s.tGiant - s.tModDown - s.tPtMult - s.tAdd;
        std::ostringstream o;
        o.setf(std::ios::fixed);
        o.precision(4);
        o << "[LT] " << tag_ << " level=" << lvl_ << " diags=" << diags_ << " towers=" << towersQl_ << "+" << towersP_
          << " rot=" << (s.baby + s.giant) << " (baby " << s.baby << " + giant " << s.giant << ") 2sqrt(d)="
          << 2.0 * std::sqrt(static_cast<double>(diags_)) << " ext=" << s.ext << " modUp=" << s.modUp
          << " modDown=" << s.modDown << " ptMult=" << s.ptMult << " add=" << s.add << " | t=" << t
          << " modUp=" << s.tModUp << " baby=" << s.tBaby << " giant=" << s.tGiant << " modDown=" << s.tModDown
          << " ptMult=" << s.tPtMult << " add=" << s.tAdd << " other=" << ot << "\n";
        OPENFHE_DIAGNOSTIC_ERR << o.str();
    }

private:
    const char* tag_;
    int32_t lvl_;
    uint32_t diags_, towersQl_, towersP_;
    LTStats st_;
    std::chrono::steady_clock::time_point t0_ = std::chrono::steady_clock::now();
};
#else
template <class F>
inline decltype(auto) LTRun(uint32_t LTStats::*, double LTStats::*, uint32_t, F&& f) {
    return f();
}
inline void LTAdd(uint32_t LTStats::*, uint32_t) {}
struct LTLevel {
    LTLevel(const char*, int32_t, uint32_t, uint32_t, uint32_t) {}
    void Print() {}
};
#endif
}  // namespace

double FHECKKSRNS::GetModRaiseOverflowBound(const std::shared_ptr<CryptoParametersCKKSRNS>& cryptoParams,
                                            double uniformK) {
    switch (cryptoParams->GetSecretKeyDist()) {
        case UNIFORM_TERNARY:
            return uniformK;
        case SPARSE_TERNARY:
            return K_SPARSE;
        case SPARSE_ENCAPSULATED:
            // CI: h nonzero CI-basis coefficients give a weight ~2h power-basis secret -> the K = 28 table
            if (cryptoParams->GetCKKSDataType() == REAL_CI)
                return K_SPARSE;
            // K = 28 for the denser sparse secret (Hamming weight 64: first modulus above 60 bits)
            return UsesLargeSparseKey(SPARSE_ENCAPSULATED, cryptoParams->GetSparseKSHammingWeight()) ?
                           K_SPARSE :
                           K_SPARSE_ENCAPSULATED;
        default:
            OPENFHE_THROW("Unsupported SecretKeyDist.");
    }
}

// Looks up the automorphism key, index and O(N) permutation map for a constant Horner giant
// stride. Hoisted out of the accumulation loop so these loop-invariant quantities are built once
// per stride instead of being re-derived by every EvalFastRotationExt call.
EvalKey<DCRTPoly> FHECKKSRNS::GetGiantStepRotation(ConstCiphertext<DCRTPoly> ct, int32_t stride, uint32_t& autoIndex,
                                                   std::vector<uint32_t>& map) {
    auto cc = ct->GetCryptoContext();
    const uint32_t M = cc->GetCyclotomicOrder();
    const uint32_t N = cc->GetRingDimension();
    autoIndex = FindAutomorphismIndex2nComplex(stride, M);
    auto evalKeyMap = cc->GetEvalAutomorphismKeyMap(ct->GetKeyTag());
    auto evalKeyIt = evalKeyMap.find(autoIndex);
    if (evalKeyIt == evalKeyMap.end())
        OPENFHE_THROW("EvalKey for index [" + std::to_string(autoIndex) + "] is not found.");
    map.resize(N);
    PrecomputeAutoMap(N, autoIndex, &map);
    return evalKeyIt->second;
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalHornerGiantRotate(ConstCiphertext<DCRTPoly> outer, uint32_t autoIndex,
                                                       const std::vector<uint32_t>& map,
                                                       const EvalKey<DCRTPoly>& giantKey) {
    auto cc = outer->GetCryptoContext();
    auto algo = cc->GetScheme();
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(outer->GetCryptoParameters());
    const auto& cvExt = outer->GetElements();
    const auto paramsP = cryptoParams->GetParamsP();
    const auto paramsQlP = cvExt[0].GetParams();
    const uint32_t sizeQlP = paramsQlP->GetParams().size();
    const uint32_t sizeQl = sizeQlP - paramsP->GetParams().size();
    const auto paramsQl = cryptoParams->GetParamsQlHybrid(sizeQl);
    const PlaintextModulus t = (cryptoParams->GetNoiseScale() == 1) ? 0 : cryptoParams->GetPlaintextModulus();

    DCRTPoly c1Std = LTRun(&LTStats::modDown, &LTStats::tModDown, 1, [&] {
        return cvExt[1].ApproxModDown(paramsQl, paramsP, cryptoParams->GetPInvModq(), cryptoParams->GetPInvModqPrecon(),
                                      cryptoParams->GetPHatInvModp(), cryptoParams->GetPHatInvModpPrecon(),
                                      cryptoParams->GetPHatModq(), cryptoParams->GetModqBarrettMu(),
                                      cryptoParams->GettInvModp(), cryptoParams->GettInvModpPrecon(), t,
                                      cryptoParams->GettModqPrecon());
    });

    auto digits = LTRun(&LTStats::modUp, &LTStats::tModUp, 1,
                        [&] { return algo->EvalKeySwitchPrecomputeCore(c1Std, cryptoParams); });
    auto cTilda = LTRun(&LTStats::giant, &LTStats::tGiant, 1,
                        [&] { return algo->EvalFastKeySwitchCoreExt(digits, giantKey, paramsQl); });

    // cTilda[0] += cvExt[0]; element 0 is already extended, fold it in directly.
    LTRun(&LTStats::add, &LTStats::tAdd, 1, [&] {
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQlP))
        for (uint32_t i = 0; i < sizeQlP; ++i)
            cTilda[0].GetAllElements()[i] += cvExt[0].GetAllElements()[i];
        return 0;
    });

    // the automorphisms belong to the giant step (count 0: already counted above)
    LTRun(&LTStats::giant, &LTStats::tGiant, 0, [&] {
        cTilda[0] = cTilda[0].AutomorphismTransform(autoIndex, map);
        cTilda[1] = cTilda[1].AutomorphismTransform(autoIndex, map);
        return 0;
    });

    auto rotated = outer->CloneEmpty();
    rotated->SetElements(std::move(cTilda));
    return rotated;
}

//------------------------------------------------------------------------------
// Bootstrap Wrapper
//------------------------------------------------------------------------------

namespace {
// Native conjugate-invariant (CI) bootstrap helpers (double precision).
// CI decode matrix U[slot a][coeff b]: U[a][0]=1, else 2 cos(pi(4a+1)b/(2N)).
inline double CIBootU(uint32_t N, uint32_t a, uint32_t b) {
    return (b == 0) ? 1.0
                    : 2.0 * std::cos(M_PI * (4.0 * static_cast<double>(a) + 1.0) * static_cast<double>(b) /
                                     (2.0 * static_cast<double>(N)));
}
// CI automorphism (X->X^k) eval-index permutation: result[j]=input[precomp[j]].
inline uint32_t CIBootPrecomp(uint32_t N, uint32_t k, uint32_t j) {
    uint64_t m = 4ULL * N;
    uint64_t r = ((4ULL * j + 1) * static_cast<uint64_t>(k)) % m;
    if (r % 4 == 3)
        r = m - r;
    return static_cast<uint32_t>((r - 1) / 4);
}

// ---- Paper-style REAL FFT CtS/StC (Liu-Ma-Wang-Wang, ePrint 2026/2618); factors in math/ci-realfft ----
// Collapsed CtS / StC levels in APPLY order (g=5 basis), stored WITHOUT the bootstrap scalars:
//   CtS = scaleEnc * N * S * F_l ... F_1          (= scaleEnc * N * Q * V^{-1})
//   StC = scaleDec * F_1^T ... F_l^T * S^{-1}     (= scaleDec * V * Q^T)
// The stored levels hold N * S * F_l ... F_1 and F_1^T ... F_l^T * S^{-1}; the constants N/sqrt(2N) and
// sqrt(2N) are spread evenly over the levels and the sigma row/column scale goes on the outermost level.
// scaleEnc / scaleDec are applied at encode time as the per-level scalars CIRealLevelScalar(scale, #levels).
struct CIRealLevels {
    std::vector<CISparse> enc, dec;
};

// Per-level share of a bootstrap scalar spread evenly over `levels` levels.
inline double CIRealLevelScalar(double scale, size_t levels) {
    return std::pow(scale, 1.0 / static_cast<double>(levels));
}

// Item 2.3: layer split (layers per level, layer order, F_1 first) of the CtS (enc) or StC (!enc) transform for
// l = log2 N layers and lb levels. The table holds the splits with the lowest modelled cost (diagonals x towers,
// item 2.2 BSGS plans; ci-ckks-paper/tools/ci-split-search.cpp) at 2^12..2^16; the best split did not depend on
// the other transform's budget. The first layers are cheaper (k of them have 2^k diagonals, a k-layer range
// further in has 2^(k+2) - 2), and levels high in the chain cost more per diagonal, so the best splits are uneven.
// Other (l, lb): the even split, larger parts first.
std::vector<uint32_t> CIDefaultLayerSplit(uint32_t l, uint32_t lb, bool enc) {
    struct Entry {
        uint32_t l, lb;
        bool enc;
        std::vector<uint32_t> parts;
    };
    static const std::vector<Entry> table = {
        {12, 3, true, {5, 3, 4}},       {12, 4, true, {4, 2, 3, 3}},    {12, 5, true, {4, 2, 2, 2, 2}},
        {12, 3, false, {6, 3, 3}},      {12, 4, false, {5, 3, 2, 2}},   {13, 5, true, {4, 2, 2, 2, 3}},
        {13, 3, false, {6, 4, 3}},      {13, 4, false, {5, 3, 3, 2}},   {14, 3, true, {6, 4, 4}},
        {14, 4, true, {5, 3, 3, 3}},    {14, 5, true, {4, 2, 2, 3, 3}}, {14, 3, false, {6, 4, 4}},
        {14, 4, false, {5, 3, 3, 3}},   {15, 3, true, {6, 4, 5}},       {15, 4, true, {5, 3, 3, 4}},
        {15, 5, true, {4, 2, 3, 3, 3}}, {15, 3, false, {7, 4, 4}},      {15, 4, false, {6, 3, 3, 3}},
        {16, 4, true, {5, 3, 4, 4}},    {16, 3, false, {7, 5, 4}},      {16, 4, false, {6, 4, 3, 3}},
    };
    for (const auto& e : table)
        if (e.l == l && e.lb == lb && e.enc == enc)
            return e.parts;
    std::vector<uint32_t> parts;
    for (uint32_t i = 0; i < lb; ++i)
        parts.push_back(l / lb + (i < l % lb ? 1 : 0));
    return parts;
}

CIRealLevels CIBuildRealLevels(uint32_t N, uint32_t lbEnc, uint32_t lbDec) {
    const auto& plan = GetCIRealFFTPlan(N);
    const auto& F    = plan.F;
    std::vector<double> sigma(N);
    for (uint32_t q = 0; q < N; ++q)
        sigma[q] = plan.S[q] * std::sqrt(2.0 * N);
    const uint32_t l = static_cast<uint32_t>(F.size());
    // Layer split of each transform: parts[i] = number of FFT layers in level i, layer order (F_1 first). CtS level s
    // is part s; StC level s is the transpose of part lb-1-s, from CIDefaultLayerSplit (item 2.3 model search).
    auto split = [&](uint32_t lb, bool enc) {
        lb               = std::max<uint32_t>(1, std::min(lb, l));
        const auto parts = CIDefaultLayerSplit(l, lb, enc);
        std::vector<std::pair<uint32_t, uint32_t>> r;  // [start, end) layer ranges, layer 0 first
        uint32_t k = 0;
        for (auto x : parts) {
            r.emplace_back(k, k + x);
            k += x;
        }
        return r;
    };
    auto product = [&](uint32_t a, uint32_t b) {
        CISparse P = F[a];
        for (uint32_t t = a + 1; t < b; ++t)
            P = CISparseMul(F[t], P, N);
        return P;
    };
    auto scaleAll = [&](CISparse& A, double c) {
        for (auto& [k, d] : A)
            for (auto& v : d)
                v *= c;
    };
    CIRealLevels out;
    {
        auto rg        = split(lbEnc, true);
        const double c = std::pow(N / std::sqrt(2.0 * N), 1.0 / rg.size());
        for (auto& [a, b] : rg) {
            out.enc.push_back(product(a, b));
            scaleAll(out.enc.back(), c);
        }
        for (auto& [k, d] : out.enc.back())  // rows *= sigma
            for (uint32_t p = 0; p < N; ++p)
                d[p] *= sigma[p];
    }
    {
        auto rg        = split(lbDec, false);
        const double c = std::pow(std::sqrt(2.0 * N), 1.0 / rg.size());
        for (auto it = rg.rbegin(); it != rg.rend(); ++it) {
            out.dec.push_back(CISparseTranspose(product(it->first, it->second), N));
            scaleAll(out.dec.back(), c);
        }
        for (auto& [k, d] : out.dec.front())  // columns *= 1/sigma
            for (uint32_t p = 0; p < N; ++p)
                d[p] /= sigma[(p + k) % N];
    }
    return out;
}

// BSGS plan of one sparse CI level (CIBsgsPlan, math/ci-realfft.h) for an input with `digits` key-switching
// digits. Item 2.2: n1 minimizes the modelled level cost babies + CIBsgsGiantCost(digits) * giants (exact counts
// after window alignment) instead of the fixed rule n1 = ceil(2 sqrt(span)) (CIPlanBsgsRatio with ratio 2, the
// pre-2.2 plan).
CIBsgsPlan CIPlanBsgs(const CISparse& A, uint32_t N, uint32_t digits) {
    return CIPlanBsgsMinCost(A, N, CIBsgsGiantCost(digits));
}

// Q towers and key-switching digits of the input of every CI CtS / StC level (apply order), from the chain shape:
// CtS level s starts with L0 - cd (1 + s) towers (after the ModRaise rescale), StC level s with
// L0 - cd (lbEnc + modDepth + s) (modDepth = GetModDepthInternal; checked against the runtime tower counts for
// encapsulated and uniform secrets at 2^10..2^16, item 2.2). StC-first (BTSlotsEncoding, item 2.5): StC runs at the
// bottom of the chain, before the ModRaise, on an input with cd (lbDec + 2) (+1 for FLEXIBLEAUTOEXT) towers, so StC
// level s starts with cd (lbDec + 2 - s) (+1) towers; the CtS towers are the same. Keygen and the evaluator plan from
// these numbers, not from the runtime tower count, so that their rotation sets agree by construction.
struct CILevelDigits {
    std::vector<uint32_t> towersEnc, towersDec, enc, dec;
};

CILevelDigits CIBsgsLevelDigits(const CryptoParametersCKKSRNS& cp, uint32_t lbEnc, uint32_t lbDec, uint32_t modDepth,
                                bool stcFirst) {
    const int64_t cd    = cp.GetCompositeDegree();
    const int64_t L0    = static_cast<int64_t>(cp.GetElementParams()->GetParams().size()) -
                       (cp.GetScalingTechnique() == FLEXIBLEAUTOEXT ? 1 : 0);
    const uint32_t alpha = std::max<uint32_t>(1, cp.GetNumPerPartQ());
    const uint32_t dnum  = std::max<uint32_t>(1, cp.GetNumPartQ());
    CILevelDigits r;
    auto add = [&](int64_t towers, std::vector<uint32_t>& tw, std::vector<uint32_t>& dg) {
        const uint32_t t = static_cast<uint32_t>(std::max<int64_t>(1, towers));
        tw.push_back(t);
        dg.push_back(std::min(dnum, (t + alpha - 1) / alpha));
    };
    for (uint32_t s = 0; s < lbEnc; ++s)
        add(L0 - cd * (1 + s), r.towersEnc, r.enc);
    const int64_t ext = (cp.GetScalingTechnique() == FLEXIBLEAUTOEXT) ? 1 : 0;
    for (uint32_t s = 0; s < lbDec; ++s)
        add(stcFirst ? cd * (lbDec + 2 - s) + ext : L0 - cd * (lbEnc + modDepth + s), r.towersDec, r.dec);
    return r;
}

inline uint32_t CIDigitsAt(const std::vector<uint32_t>& v, size_t s) {
    return v.empty() ? 1 : v[std::min(s, v.size() - 1)];
}

inline uint32_t CIGaloisForShift(uint32_t shift, uint32_t N) {  // 5^shift mod 4N
    const uint64_t m = 4ULL * N;
    uint64_t r = 1, b = 5, e = shift % N;
    while (e) {
        if (e & 1)
            r = r * b % m;
        b = b * b % m;
        e >>= 1;
    }
    return static_cast<uint32_t>(r);
}

// One unscaled cache entry per (N, lbEnc, lbDec), shared by keygen (Galois set) and evaluation.
const CIRealLevels& GetCIRealLevels(uint32_t N, uint32_t lbEnc, uint32_t lbDec) {
    static std::map<std::tuple<uint32_t, uint32_t, uint32_t>, CIRealLevels> cache;
    static std::mutex mtx;
    std::lock_guard<std::mutex> lk(mtx);
    auto key = std::make_tuple(N, lbEnc, lbDec);
    auto it  = cache.find(key);
    if (it == cache.end())
        it = cache.emplace(key, CIBuildRealLevels(N, lbEnc, lbDec)).first;
    return it->second;
}

// Galois elements needed by the sparse CI CtS/StC levels (same BSGS plan as the evaluator). Only the
// rotations the evaluator performs: for each nonzero diagonal at offset k = h * (t0 + n1 * j + i), the baby
// shift h * i (i > 0) and the giant shift h * (t0 + n1 * j) (when nonzero). EvalBootstrap checks that the
// rotations it performs equal this set.
std::vector<uint32_t> CIRealFFTGaloisElements(uint32_t N, uint32_t lbEnc, uint32_t lbDec, const CILevelDigits& dg) {
    const auto& lv = GetCIRealLevels(N, lbEnc, lbDec);
    std::set<uint32_t> elts;
    for (const bool enc : {true, false})
        for (size_t s = 0; s < (enc ? lv.enc : lv.dec).size(); ++s) {
            const CISparse& A = (enc ? lv.enc : lv.dec)[s];
            const auto bp     = CIPlanBsgs(A, N, CIDigitsAt(enc ? dg.enc : dg.dec, s));
            const uint32_t T = N / bp.h;
            for (const auto& kv : A) {
                const uint32_t u = (kv.first / bp.h + T - bp.t0) % T;  // position in the BSGS window
                const uint32_t i = u % bp.n1, j = u / bp.n1;
                if (i != 0)
                    elts.insert(CIGaloisForShift(bp.h * i, N));
                const uint32_t G = static_cast<uint32_t>((static_cast<uint64_t>(bp.h) * (bp.t0 + bp.n1 * j)) % N);
                if (G != 0)
                    elts.insert(CIGaloisForShift(G, N));
            }
        }
    return std::vector<uint32_t>(elts.begin(), elts.end());
}

// ---- Item 2.4: CI CtS / StC diagonal plaintexts, encoded once at setup ----
// CtS / StC bootstrap scalars of the native CI bootstrap (FLEXIBLE* / FIXED*, composite degree 1). The ModRaise
// overflow bound kBoot is folded into the CtS matrix.
std::pair<double, double> CIBootScales(double qDouble, double kBoot) {
    const double factorBoot = std::pow(2.0, std::round(std::log2(qDouble)));
    return {qDouble / factorBoot / kBoot, factorBoot / qDouble};
}

// The input of every CI level holds a prefix of the Q towers (ModRaise to the full chain, then one rescale per
// level), so its extended basis is the first `towers` Q moduli followed by the P moduli (the basis KeySwitchExt
// builds) and its level is |Q| - towers (as set by ModRaiseInPlace).
std::shared_ptr<DCRTPoly::Params> CIParamsQlP(const CryptoParametersCKKSRNS& cp, uint32_t towers) {
    const auto& q  = cp.GetElementParams()->GetParams();
    const auto& pp = cp.GetParamsP()->GetParams();
    std::vector<NativeInteger> moduli, roots;
    for (uint32_t i = 0; i < towers && i < q.size(); ++i) {
        moduli.push_back(q[i]->GetModulus());
        roots.push_back(q[i]->GetRootOfUnity());
    }
    for (const auto& x : pp) {
        moduli.push_back(x->GetModulus());
        roots.push_back(x->GetRootOfUnity());
    }
    auto params = std::make_shared<DCRTPoly::Params>(cp.GetElementParams()->GetCyclotomicOrder(), moduli, roots);
    params->SetRingType(cp.GetElementParams()->GetRingType());
    return params;
}

inline uint32_t CILevelOf(const CryptoParametersCKKSRNS& cp, uint32_t towers) {
    return static_cast<uint32_t>(cp.GetElementParams()->GetParams().size()) - towers;
}

// One diagonal (natural slot order) CI-encoded in the extended basis of a level input with `towers` Q towers.
ReadOnlyPlaintext CIEncodeDiagonal(const CryptoParametersCKKSRNS& cp, const std::shared_ptr<DCRTPoly::Params>& qlp,
                                   uint32_t towers, const std::vector<std::complex<double>>& cval) {
    const uint32_t lvl = CILevelOf(cp, towers);
    auto enc           = std::make_shared<CKKSPackedEncoding>(qlp, cp.GetEncodingParams(), cval, 1, lvl,
                                                    cp.GetScalingFactorReal(lvl),
                                                    static_cast<uint32_t>(cval.size()), REAL_CI);
    enc->Encode();
    return enc;
}

// Diagonal plaintexts of one sparse CI level in its BSGS layout: entry u = n1 * j + i holds the diagonal at offset
// h * (t0 + u), scaled by sc and pre-rotated by the giant shift -G_j (G_j = h * (t0 + n1 * j)), in natural slot
// order; nullptr marks a zero diagonal. The encodes run in parallel.
std::vector<ReadOnlyPlaintext> CIEncodeSparseLevel(const CryptoParametersCKKSRNS& cp, const CISparse& A, uint32_t N,
                                                   const CIBsgsPlan& bp, double sc, uint32_t towers) {
    const auto& perm = GetCIRealFFTPlan(N).perm;
    const auto qlp   = CIParamsQlP(cp, towers);
    std::vector<ReadOnlyPlaintext> store(static_cast<size_t>(bp.n1) * bp.n2);
    std::vector<std::pair<uint32_t, const std::vector<double>*>> jobs;
    for (uint32_t u = 0; u < bp.span; ++u) {
        auto it = A.find(static_cast<uint32_t>((static_cast<uint64_t>(bp.h) * (bp.t0 + u)) % N));
        if (it != A.end())
            jobs.emplace_back(u, &it->second);
    }
#pragma omp parallel for schedule(dynamic) num_threads(OpenFHEParallelControls.GetThreadLimit(jobs.size()))
    for (size_t t = 0; t < jobs.size(); ++t) {
        const uint32_t u = jobs[t].first;
        const uint32_t G = static_cast<uint32_t>((static_cast<uint64_t>(bp.h) * (bp.t0 + bp.n1 * (u / bp.n1))) % N);
        const auto& d    = *jobs[t].second;
        std::vector<std::complex<double>> cval(N);
        for (uint32_t q = 0; q < N; ++q)
            cval[perm[q]] = std::complex<double>(sc * d[(q + N - G) % N], 0.0);
        store[u] = CIEncodeDiagonal(cp, qlp, towers, cval);
    }
    return store;
}

// Dense single-level CI transform (budget {1,1}, small N): CtS = scaleEnc * N * U^-1 = scaleEnc * diag(1,.5..) * U^T,
// StC = scaleDec * U. Entry (a, b) of the matrix.
inline double CIDenseEntry(bool enc, double scale, uint32_t N, uint32_t a, uint32_t b) {
    return enc ? scale * ((a == 0) ? 1.0 : 0.5) * CIBootU(N, b, a) : scale * CIBootU(N, a, b);
}

// BSGS shape of the dense transform: n1 = 2^ceil(logN / 2) baby steps, n2 = N / n1 giant blocks.
inline uint32_t CIDenseN1(uint32_t N) {
    const uint32_t logN = static_cast<uint32_t>(std::round(std::log2(N)));
    return 1u << ((logN + 1) / 2);
}

// Diagonal plaintexts of the dense transform in its BSGS layout: entry n1 * j + i holds diagonal k = n1 * j + i
// (Galois 5^k) pre-rotated by the giant step 5^{-n1 j}; nullptr marks an all-zero diagonal.
std::vector<ReadOnlyPlaintext> CIEncodeDenseLevel(const CryptoParametersCKKSRNS& cp, uint32_t N, uint32_t towers,
                                                  bool enc, double scale) {
    const uint64_t m4 = 4ULL * N;
    const uint32_t n1 = CIDenseN1(N), n2 = N / n1;
    const auto qlp    = CIParamsQlP(cp, towers);
    std::vector<ReadOnlyPlaintext> store(static_cast<size_t>(n1) * n2);
#pragma omp parallel for schedule(dynamic) num_threads(OpenFHEParallelControls.GetThreadLimit(n2))
    for (uint32_t j = 0; j < n2; ++j) {
        const uint32_t gj0   = CIGaloisForShift(n1 * j, N);  // 5^{n1 j}
        const uint32_t gjInv = (j == 0) ? 1 : NativeInteger(gj0).ModInverse(m4).ConvertToInt<uint32_t>();
        uint32_t fk          = gj0;  // 5^{n1 j + i}
        std::vector<double> diag(N);
        for (uint32_t i = 0; i < n1; ++i, fk = static_cast<uint32_t>((static_cast<uint64_t>(fk) * 5) % m4)) {
            double maxabs = 0.0;
            for (uint32_t s = 0; s < N; ++s) {
                const uint32_t sp = (j == 0) ? s : CIBootPrecomp(N, gjInv, s);
                diag[s]           = CIDenseEntry(enc, scale, N, sp, CIBootPrecomp(N, fk, sp));
                maxabs            = std::max(maxabs, std::abs(diag[s]));
            }
            if (maxabs < 1e-14)  // sparse stage: skip all-zero diagonals
                continue;
            std::vector<std::complex<double>> cval(N);
            for (uint32_t s = 0; s < N; ++s)
                cval[s] = std::complex<double>(diag[s], 0.0);
            store[static_cast<size_t>(j) * n1 + i] = CIEncodeDiagonal(cp, qlp, towers, cval);
        }
    }
    return store;
}

// True when `store` was encoded for a level input with `towers` Q towers (size, level and extended basis of its
// first plaintext). A mismatch (no setup precompute, or a chain the tower model does not cover) makes EvalBootstrap
// encode the level locally for that call instead.
bool CIStoreMatches(const CryptoParametersCKKSRNS& cp, const std::vector<ReadOnlyPlaintext>& store, size_t size,
                    uint32_t towers) {
    if (store.size() != size)
        return false;
    const size_t sizeP = cp.GetParamsP()->GetParams().size();
    for (const auto& pd : store)
        if (pd)
            return pd->GetLevel() == CILevelOf(cp, towers) &&
                   pd->GetElement<DCRTPoly>().GetNumOfElements() == towers + sizeP;
    return true;  // all-zero level
}

// All CI CtS / StC diagonal plaintexts for the level budgets in `p`: one store per level of the real FFT
// (p.m_U0hatTPreFFT, p.m_U0PreFFT; budget > 1) or the dense transform (p.m_U0hatTPre, p.m_U0Pre; budget {1,1}).
// The towers of every level come from the chain shape (CIBsgsLevelDigits, as keygen); EvalBootstrap only reads.
void CIBootstrapPrecompute(const CryptoParametersCKKSRNS& cp, CKKSBootstrapPrecom& p, uint32_t N, double scaleEnc,
                           double scaleDec, uint32_t modDepth) {
    const uint32_t lbEnc = p.m_paramsEnc.lvlb, lbDec = p.m_paramsDec.lvlb;
    const auto dg        = CIBsgsLevelDigits(cp, lbEnc, lbDec, modDepth, p.BTSlotsEncoding);
    p.m_U0hatTPreFFT.clear();
    p.m_U0PreFFT.clear();
    p.m_U0hatTPre.clear();
    p.m_U0Pre.clear();
    if (lbEnc > 1 || lbDec > 1) {
        const auto& lv = GetCIRealLevels(N, lbEnc, lbDec);
        auto build     = [&](const std::vector<CISparse>& levels, double scale, const std::vector<uint32_t>& digits,
                         const std::vector<uint32_t>& towers) {
            std::vector<std::vector<ReadOnlyPlaintext>> out(levels.size());
            const double sc = CIRealLevelScalar(scale, levels.size());
            for (size_t s = 0; s < levels.size(); ++s)
                out[s] = CIEncodeSparseLevel(cp, levels[s], N, CIPlanBsgs(levels[s], N, CIDigitsAt(digits, s)), sc,
                                             CIDigitsAt(towers, s));
            return out;
        };
        p.m_U0hatTPreFFT = build(lv.enc, scaleEnc, dg.enc, dg.towersEnc);
        p.m_U0PreFFT     = build(lv.dec, scaleDec, dg.dec, dg.towersDec);
    }
    else {
        p.m_U0hatTPre = CIEncodeDenseLevel(cp, N, CIDigitsAt(dg.towersEnc, 0), true, scaleEnc);
        p.m_U0Pre     = CIEncodeDenseLevel(cp, N, CIDigitsAt(dg.towersDec, 0), false, scaleDec);
    }
}
}  // namespace

void FHECKKSRNS::EvalBootstrapSetup(const CryptoContextImpl<DCRTPoly>& cc, std::vector<uint32_t> levelBudget,
                                    std::vector<uint32_t> dim1, uint32_t numSlots, uint32_t correctionFactor,
                                    bool precompute, bool BTSlotsEncoding) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW("CKKS Bootstrapping is only supported for the Hybrid key switching method.");
#if NATIVEINT == 128
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        OPENFHE_THROW("128-bit CKKS Bootstrapping is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
#endif
    // REAL_CI with BTSlotsEncoding: StC-first native CI bootstrap (StC at the bottom of the chain, ModRaise, CtS,
    // EvalMod; item 2.5), evaluated by the CI branch of EvalBootstrap.

    uint32_t M = cc.GetCyclotomicOrder();
    uint32_t slots = (numSlots == 0) ? M / 4 : numSlots;

    // Set correction factor by default, if it is not already set.
    if (correctionFactor == 0) {
        auto st = cryptoParams->GetScalingTechnique();
        if (st == FLEXIBLEAUTO || st == FLEXIBLEAUTOEXT || st == COMPOSITESCALINGAUTO || st == COMPOSITESCALINGMANUAL) {
            // The default correction factors chosen yielded the best precision in our experiments.
            // We chose the best fit line from our experiments by running ckks-bootstrapping-precision.cpp.
            // The spreadsheet with our experiments is here:
            // https://docs.google.com/spreadsheets/d/1p6-ZG9rBEE9SrkKIt0JjU1aJiYHevzblKOTuhLFW27U
            // REAL_CI (N real slots): evaluate the fit at the complex-equivalent count N/2 and use one bit less.
            // Measured (FLEXIBLEAUTO, CtS-first, sparse encapsulation, ci-ckks-paper/PHASE2_LOG.md item 0.2):
            // at an equal correction factor CI is 1.0-1.4 bits below std, and each bit less gains ~1 bit for
            // both schemes, so this gives CI the precision of std at the std default (2^16: CI 7 vs std 8).
            // StC-first (BTSlotsEncoding): CI and std give the same precision at an equal correction factor (item 2.5,
            // 2^15: the sine argument is the message itself for both), so CI uses std's StC-first default.
            const bool isCI      = (cc.GetCKKSDataType() == REAL_CI);
            const double fitLog2 = std::log2(isCI ? std::max<uint32_t>(1, slots / 2) : slots);
            int32_t tmp = BTSlotsEncoding ? std::round(-0.1887 * (2 * std::log2(M / 2) + fitLog2) + 19.763) :
                                            std::round(-0.2419 * (2 * std::log2(M / 2) + fitLog2) + 19.081);
            m_correctionFactor = std::clamp<int32_t>(tmp - ((isCI && !BTSlotsEncoding) ? 1 : 0), 7, 14);
        } else {
            uint32_t tmp = BTSlotsEncoding ? std::round(-0.0645 * (2 * std::log2(M / 2) + std::log2(slots)) + 13.855) :
                                             std::round(-0.1516 * (2 * std::log2(M / 2) + std::log2(slots)) + 14.284);
            m_correctionFactor = std::clamp<uint32_t>(tmp, 6, 13);
        }
    } else {
        m_correctionFactor = correctionFactor;
    }

    m_bootPrecomMap[slots] = std::make_shared<CKKSBootstrapPrecom>();
    auto& precom = m_bootPrecomMap[slots];
    precom->m_slots = slots;
    precom->BTSlotsEncoding = BTSlotsEncoding;
    precom->m_variant = CKKSBootstrapPrecom::BOOTSTRAP;

    // even for the case of a single slot we need one level for rescaling
    uint32_t logSlots = (slots < 3) ? 1 : std::log2(slots);

    // Perform some checks on the level budget and compute parameters
    uint32_t newBudget0 = levelBudget[0];
    if (newBudget0 > logSlots) {
        OPENFHE_DIAGNOSTIC_ERR << "\nWarning, level budget for encoding too large. Setting it to " << logSlots << "\n";
        newBudget0 = logSlots;
    }
    if (newBudget0 < 1) {
        OPENFHE_DIAGNOSTIC_ERR << "\nWarning, level budget for encoding can not be zero. Setting it to 1\n";
        newBudget0 = 1;
    }
    uint32_t newBudget1 = levelBudget[1];
    if (newBudget1 > logSlots) {
        OPENFHE_DIAGNOSTIC_ERR << "\nWarning, level budget for decoding too large. Setting it to " << logSlots << "\n";
        newBudget1 = logSlots;
    }
    if (newBudget1 < 1) {
        OPENFHE_DIAGNOSTIC_ERR << "\nWarning, level budget for decoding can not be zero. Setting it to 1\n";
        newBudget1 = 1;
    }

    precom->m_paramsEnc = GetCollapsedFFTParams(slots, newBudget0, dim1[0]);
    precom->m_paramsDec = GetCollapsedFFTParams(slots, newBudget1, dim1[1]);

    // Native CI bootstrap: the real-FFT (or dense {1,1}) CtS/StC diagonals are encoded here, in parallel, in the
    // extended QlP basis of each level (item 2.4); EvalBootstrap only reads them.
    if (cc.GetCKKSDataType() == REAL_CI) {
        if (precompute) {
            const auto sc =
                CIBootScales(GetBigModulus(cryptoParams), GetModRaiseOverflowBound(cryptoParams, K_UNIFORM));
            CIBootstrapPrecompute(*cryptoParams, *precom, slots, sc.first, sc.second,
                                  GetModDepthInternal(cryptoParams->GetSecretKeyDist()));
        }
        return;
    }

    if (precompute) {
        uint32_t m = 4 * slots;
        uint32_t mmask = m - 1;  // assumes m is power of 2
        bool isSparse = (M != m);

        // computes indices for all primitive roots of unity
        std::vector<uint32_t> rotGroup(slots);
        uint32_t fivePows = 1;
        for (uint32_t i = 0; i < slots; ++i) {
            rotGroup[i] = fivePows;
            fivePows *= 5;
            fivePows &= mmask;
        }

        // computes all powers of a primitive root of unity exp(2 * M_PI/m)
        std::vector<std::complex<double>> ksiPows(m + 1);
        double ak = 2 * M_PI / m;
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(2))
        for (uint32_t j = 0; j < m; ++j) {
            double angle = ak * j;
            ksiPows[j].real(std::cos(angle));
            ksiPows[j].imag(std::sin(angle));
        }
        ksiPows[m] = ksiPows[0];

        double k = GetModRaiseOverflowBound(cryptoParams, K_UNIFORM);

        uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

        double qDouble = GetBigModulus(cryptoParams);
        double factor = std::ldexp(1.0, static_cast<int>(std::round(std::log2(qDouble))));
        // For composite scaling, capture the (inexact) overflow normalization SF0/qDouble as a coefficient
        // close to 1, SF0*post/qDouble, which the CoeffsToSlots/SlotsToCoeffs matrices encode at full
        // precision and telescope away (scaleDec = 1/scaleEnc*1/k cancels it). The exact power-of-two part
        // 1/post is applied as the shrink and restored by the integer "scalar" in EvalBootstrap. This
        // mirrors the FLEXIBLEAUTO scaling structure and avoids the precision loss of folding a tiny
        // non-power-of-two constant into a single plaintext multiply.
        double pre;
        double post = 1.0;
        if (compositeDegree > 1) {
            double powP = std::pow(2, cryptoParams->GetPlaintextModulus());
            post = std::pow(2, std::round(std::log2(qDouble / powP)));
            pre = cryptoParams->GetScalingFactorReal(0) * post / qDouble;
        } else {
            pre = qDouble / factor;
        }
        // For composite scaling, fold the exact power-of-two 2^-deg = 1/post shrink into the
        // CoeffsToSlots matrix (scaleEnc) instead of applying it as a scalar before CoeffsToSlots (see
        // EvalBootstrap). This keeps the CtS rotations operating on the full-magnitude message, so the
        // key-switch noise they add scales down together with the signal (2^deg is restored by the
        // integer "scalar" after the sine) rather than being amplified by 2^deg. scaleDec inverts the
        // residual c1 only; the exact 2^deg telescopes against the integer restore.
        double scaleEnc = ((compositeDegree > 1) ? pre / post : pre) / k;
        double scaleDec = 1.0 / pre;

        // compute # of levels to remain when encoding the coefficients
        // for FLEXIBLEAUTOEXT we do not need extra modulus in auxiliary plaintexts
        auto st = cryptoParams->GetScalingTechnique();
        uint32_t L0 = cryptoParams->GetElementParams()->GetParams().size() - (st == FLEXIBLEAUTOEXT);

        uint32_t lEnc = L0 - compositeDegree * (precom->m_paramsEnc.lvlb + 1);
        uint32_t lDec;
        if (precom->BTSlotsEncoding) {
            lDec = (2 + (st == FLEXIBLEAUTOEXT)) * compositeDegree;
        } else {
            uint32_t depthBT = GetModDepthInternal(cryptoParams->GetSecretKeyDist()) + precom->m_paramsEnc.lvlb +
                               precom->m_paramsDec.lvlb;
            lDec = L0 - compositeDegree * depthBT;
        }

        bool isLTBootstrap = (precom->m_paramsEnc.lvlb == 1) && (precom->m_paramsDec.lvlb == 1);

        if (isLTBootstrap) {
            if (isSparse) {
                std::vector<std::vector<std::complex<double>>> U0(slots, std::vector<std::complex<double>>(slots));
                std::vector<std::vector<std::complex<double>>> U0hatT(slots, std::vector<std::complex<double>>(slots));
                std::vector<std::vector<std::complex<double>>> U1(slots, std::vector<std::complex<double>>(slots));
                std::vector<std::vector<std::complex<double>>> U1hatT(slots, std::vector<std::complex<double>>(slots));
                for (uint32_t i = 0; i < slots; ++i) {
                    for (uint32_t j = 0; j < slots; ++j) {
                        U0[i][j] = ksiPows[(j * rotGroup[i]) & mmask];
                        U0hatT[j][i] = std::conj(U0[i][j]);
                        U1[i][j] = std::complex<double>(0, 1) * U0[i][j];
                        U1hatT[j][i] = std::conj(U1[i][j]);
                    }
                }
                if (cc.GetCKKSDataType() == REAL || !precom->BTSlotsEncoding) {
                    precom->m_U0Pre = EvalLinearTransformPrecompute(cc, U0, U1, 1, scaleDec, lDec);
                    precom->m_U0hatTPre = EvalLinearTransformPrecompute(cc, U0hatT, U1hatT, 0, scaleEnc, lEnc);
                } else {
                    precom->m_U0Pre = EvalLinearTransformPrecompute(cc, U0, scaleDec, lDec);
                    precom->m_U0hatTPre = EvalLinearTransformPrecompute(cc, U0hatT, scaleEnc, lEnc);
                }
            } else {
                std::vector<std::vector<std::complex<double>>> U0(slots, std::vector<std::complex<double>>(slots));
                std::vector<std::vector<std::complex<double>>> U0hatT(slots, std::vector<std::complex<double>>(slots));
                for (uint32_t i = 0; i < slots; ++i) {
                    for (uint32_t j = 0; j < slots; ++j) {
                        U0[i][j] = ksiPows[(j * rotGroup[i]) & mmask];
                        U0hatT[j][i] = std::conj(U0[i][j]);
                    }
                }
                precom->m_U0Pre = EvalLinearTransformPrecompute(cc, U0, scaleDec, lDec);
                precom->m_U0hatTPre = EvalLinearTransformPrecompute(cc, U0hatT, scaleEnc, lEnc);
            }
        } else {
            bool flagPack = !(cc.GetCKKSDataType() == REAL || !precom->BTSlotsEncoding);
            precom->m_U0PreFFT = EvalSlotsToCoeffsPrecompute(cc, ksiPows, rotGroup, false, scaleDec, lDec, flagPack);
            precom->m_U0hatTPreFFT =
                    EvalCoeffsToSlotsPrecompute(cc, ksiPows, rotGroup, false, scaleEnc, lEnc, flagPack);
        }
    }
}

std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>> FHECKKSRNS::EvalBootstrapKeyGen(
        const PrivateKey<DCRTPoly> privateKey, uint32_t slots) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(privateKey->GetCryptoParameters());

    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW("CKKS Bootstrapping is only supported for the Hybrid key switching method.");
#if NATIVEINT == 128
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        OPENFHE_THROW("128-bit CKKS Bootstrapping is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
#endif

    auto cc = privateKey->GetCryptoContext();
    auto algo = cc->GetScheme();
    auto M = cc->GetCyclotomicOrder();

    // Native CI bootstrap: slots == N (full real packing); generate Galois keys for the
    // CI rotation set {5^t mod 4N : t=1..N-1} used by the CI CtS/StC linear transforms.
    // No conjugation key is needed (conjugation is the identity on the CI ring).
    if (cryptoParams->GetCKKSDataType() == REAL_CI) {
        uint32_t N = cc->GetRingDimension();
        uint64_t mm = 4ULL * N;
        // Sparse encapsulation keys (even indices M-4, M-2 never collide with odd CI Galois elements).
        auto addSparseKeys = [&](std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>> ek) {
            if (cryptoParams->GetSecretKeyDist() == SPARSE_ENCAPSULATED) {
                DCRTPoly::TugType tug;
                auto skNew = std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc);
                skNew->SetPrivateElement(DCRTPoly(tug, cryptoParams->GetElementParams(), Format::EVALUATION,
                                                  cryptoParams->GetSparseKSHammingWeight()));
                (*ek)[M - 4] = KeySwitchGenSparse(privateKey, skNew);
                (*ek)[M - 2] = algo->KeySwitchGen(skNew, privateKey);
            }
            return ek;
        };
        {
            auto pit = m_bootPrecomMap.find(N);
            if (pit != m_bootPrecomMap.end()) {
                const uint32_t lbE = pit->second->m_paramsEnc.lvlb, lbD = pit->second->m_paramsDec.lvlb;
                if (lbE > 1 || lbD > 1) {
                    const auto dg = CIBsgsLevelDigits(*cryptoParams, lbE, lbD,
                                                      GetModDepthInternal(cryptoParams->GetSecretKeyDist()),
                                                      pit->second->BTSlotsEncoding);
                    return addSparseKeys(
                            algo->EvalAutomorphismKeyGen(privateKey, CIRealFFTGaloisElements(N, lbE, lbD, dg)));
                }
            }
        }
        // Baby-step/giant-step rotation set for the CI linear transform: baby {5^i : i<n1}
        // and giant {(5^{n1})^j : j<n2}, with n1*n2 = N. ~2 sqrt(N) keys instead of N-1.
        uint32_t logN = static_cast<uint32_t>(std::round(std::log2(N)));
        uint32_t n1   = 1u << ((logN + 1) / 2);
        uint32_t n2   = N / n1;
        std::set<uint32_t> elts;
        uint32_t fi = 1;
        for (uint32_t i = 1; i < n1; ++i) {
            fi = static_cast<uint32_t>((static_cast<uint64_t>(fi) * 5) % mm);
            elts.insert(fi);
        }
        uint32_t g = 1;
        for (uint32_t t = 0; t < n1; ++t)
            g = static_cast<uint32_t>((static_cast<uint64_t>(g) * 5) % mm);  // g = 5^{n1}
        uint32_t gj = g;
        for (uint32_t j = 1; j < n2; ++j) {
            elts.insert(gj);
            gj = static_cast<uint32_t>((static_cast<uint64_t>(gj) * g) % mm);
        }
        std::vector<uint32_t> ciGaloisElts(elts.begin(), elts.end());
        return addSparseKeys(algo->EvalAutomorphismKeyGen(privateKey, ciGaloisElts));
    }

    slots = (slots == 0) ? M / 4 : slots;

    // computing all indices for baby-step giant-step procedure
    auto evalKeys = algo->EvalAtIndexKeyGen(privateKey, FindBootstrapRotationIndices(slots, M));

    (*evalKeys)[M - 1] = ConjugateKeyGen(privateKey);

    if (cryptoParams->GetSecretKeyDist() == SPARSE_ENCAPSULATED) {
        // sparse key used for the modraising step (Hamming weight 32, or 64 for bottom moduli above 60 bits)
        DCRTPoly::TugType tug;
        auto skNew = std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc);
        skNew->SetPrivateElement(DCRTPoly(tug, cryptoParams->GetElementParams(), Format::EVALUATION,
                                          cryptoParams->GetSparseKSHammingWeight()));

        // we reserve M-4 and M-2 for the sparse encapsulation switching keys
        // Even autorphism indices are not possible, so there will not be any conflict
        (*evalKeys)[M - 4] = KeySwitchGenSparse(privateKey, skNew);
        (*evalKeys)[M - 2] = algo->KeySwitchGen(skNew, privateKey);
    }

    return evalKeys;
}

std::vector<uint32_t> FHECKKSRNS::EvalBootstrapKeyMapIndices(const CryptoContext<DCRTPoly>& cc, uint32_t slots) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    if (!cryptoParams)
        OPENFHE_THROW("Invalid crypto parameters: expected CryptoParametersCKKSRNS");

    auto M = cc->GetCyclotomicOrder();
    slots = (slots == 0) ? M / 4 : slots;

    const auto bootstrapRotationsIndices = FindBootstrapRotationIndices(slots, M);

    std::set<uint32_t> indexList;
    for (const auto rotationIndex : bootstrapRotationsIndices)
        indexList.insert(FindAutomorphismIndex2nComplex(rotationIndex, M));

    indexList.insert(M - 1);

    if (cryptoParams->GetSecretKeyDist() == SPARSE_ENCAPSULATED) {
        indexList.insert(M - 2);
        indexList.insert(M - 4);
    }

    return std::vector<uint32_t>(indexList.begin(), indexList.end());
}

void FHECKKSRNS::EvalBootstrapPrecompute(const CryptoContextImpl<DCRTPoly>& cc, uint32_t numSlots) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW("CKKS Bootstrapping is only supported for the Hybrid key switching method.");
#if NATIVEINT == 128
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        OPENFHE_THROW("128-bit CKKS Bootstrapping is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
#endif

    uint32_t M = cc.GetCyclotomicOrder();
    uint32_t slots = (numSlots == 0) ? M / 4 : numSlots;

    // Only a regular-bootstrapping precomputation may be recomputed here: rebuilding an FBT or FEFBT
    // entry would fold the regular-bootstrapping K_UNIFORM into its matrices while keeping the rest of
    // its state (BTSlotsEncoding, level budgets, no correction factor). A deserialized precomputation
    // loads with the default BOOTSTRAP tag, so the documented deserialize-then-recompute flow passes.
    auto& p = GetBootPrecom(slots, CKKSBootstrapPrecom::BOOTSTRAP);

    p.m_paramsEnc = GetCollapsedFFTParams(slots, p.m_paramsEnc.lvlb, p.m_paramsEnc.g);
    p.m_paramsDec = GetCollapsedFFTParams(slots, p.m_paramsDec.lvlb, p.m_paramsDec.g);

    if (cc.GetCKKSDataType() == REAL_CI) {
        const auto sc = CIBootScales(GetBigModulus(cryptoParams), GetModRaiseOverflowBound(cryptoParams, K_UNIFORM));
        CIBootstrapPrecompute(*cryptoParams, p, slots, sc.first, sc.second,
                              GetModDepthInternal(cryptoParams->GetSecretKeyDist()));
        return;
    }

    uint32_t m = 4 * slots;
    uint32_t mmask = m - 1;  // assumes m is power of 2
    bool isSparse = (M != m);

    // computes indices for all primitive roots of unity
    std::vector<uint32_t> rotGroup(slots);
    uint32_t fivePows = 1;
    for (uint32_t i = 0; i < slots; ++i) {
        rotGroup[i] = fivePows;
        fivePows *= 5;
        fivePows &= mmask;
    }

    // computes all powers of a primitive root of unity exp(2 * M_PI/m)
    std::vector<std::complex<double>> ksiPows(m + 1);
    double ak = 2 * M_PI / m;
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(2))
    for (uint32_t j = 0; j < m; ++j) {
        double angle = ak * j;
        ksiPows[j].real(std::cos(angle));
        ksiPows[j].imag(std::sin(angle));
    }
    ksiPows[m] = ksiPows[0];

    double k = GetModRaiseOverflowBound(cryptoParams, K_UNIFORM);

    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    double qDouble = GetBigModulus(cryptoParams);
    double factor = std::ldexp(1.0, static_cast<int>(std::round(std::log2(qDouble))));
    // For composite scaling, capture the (inexact) overflow normalization SF0/qDouble as a coefficient
    // close to 1, SF0*post/qDouble, encoded at full precision in the CoeffsToSlots/SlotsToCoeffs matrices
    // and telescoped away; the exact power-of-two 1/post is applied as the shrink/scalar (see EvalBootstrap).
    double pre;
    double post = 1.0;
    if (compositeDegree > 1) {
        double powP = std::pow(2, cryptoParams->GetPlaintextModulus());
        post = std::pow(2, std::round(std::log2(qDouble / powP)));
        pre = cryptoParams->GetScalingFactorReal(0) * post / qDouble;
    } else {
        pre = qDouble / factor;
    }
    // For composite scaling, fold the exact power-of-two 2^-deg = 1/post shrink into the CoeffsToSlots
    // matrix (scaleEnc) instead of applying it as a scalar before CoeffsToSlots (see EvalBootstrap), so
    // the CtS rotations act on the full-magnitude message and their key-switch noise scales down with
    // the signal rather than being amplified by 2^deg. scaleDec inverts the residual c1 only.
    double scaleEnc = ((compositeDegree > 1) ? pre / post : pre) / k;
    double scaleDec = 1.0 / pre;

    // compute # of levels to remain when encoding the coefficients
    // for FLEXIBLEAUTOEXT we do not need extra modulus in auxiliary plaintexts
    auto st = cryptoParams->GetScalingTechnique();
    uint32_t L0 = cryptoParams->GetElementParams()->GetParams().size() - (st == FLEXIBLEAUTOEXT);

    uint32_t lEnc = L0 - compositeDegree * (p.m_paramsEnc.lvlb + 1);
    uint32_t lDec;
    if (p.BTSlotsEncoding) {
        lDec = (2 + (st == FLEXIBLEAUTOEXT)) * compositeDegree;
    } else {
        uint32_t depthBT =
                GetModDepthInternal(cryptoParams->GetSecretKeyDist()) + p.m_paramsEnc.lvlb + p.m_paramsDec.lvlb;
        lDec = L0 - compositeDegree * depthBT;
    }

    bool isLTBootstrap = (p.m_paramsEnc.lvlb == 1) && (p.m_paramsDec.lvlb == 1);

    if (isLTBootstrap) {
        if (isSparse) {
            std::vector<std::vector<std::complex<double>>> U0(slots, std::vector<std::complex<double>>(slots));
            std::vector<std::vector<std::complex<double>>> U0hatT(slots, std::vector<std::complex<double>>(slots));
            std::vector<std::vector<std::complex<double>>> U1(slots, std::vector<std::complex<double>>(slots));
            std::vector<std::vector<std::complex<double>>> U1hatT(slots, std::vector<std::complex<double>>(slots));
            for (uint32_t i = 0; i < slots; ++i) {
                for (uint32_t j = 0; j < slots; ++j) {
                    U0[i][j] = ksiPows[(j * rotGroup[i]) & mmask];
                    U0hatT[j][i] = std::conj(U0[i][j]);
                    U1[i][j] = std::complex<double>(0, 1) * U0[i][j];
                    U1hatT[j][i] = std::conj(U1[i][j]);
                }
            }
            if (cc.GetCKKSDataType() == REAL || !p.BTSlotsEncoding) {
                p.m_U0Pre = EvalLinearTransformPrecompute(cc, U0, U1, 1, scaleDec, lDec);
                p.m_U0hatTPre = EvalLinearTransformPrecompute(cc, U0hatT, U1hatT, 0, scaleEnc, lEnc);
            } else {
                p.m_U0Pre = EvalLinearTransformPrecompute(cc, U0, scaleDec, lDec);
                p.m_U0hatTPre = EvalLinearTransformPrecompute(cc, U0hatT, scaleEnc, lEnc);
            }
        } else {
            std::vector<std::vector<std::complex<double>>> U0(slots, std::vector<std::complex<double>>(slots));
            std::vector<std::vector<std::complex<double>>> U0hatT(slots, std::vector<std::complex<double>>(slots));
            for (uint32_t i = 0; i < slots; ++i) {
                for (uint32_t j = 0; j < slots; ++j) {
                    U0[i][j] = ksiPows[(j * rotGroup[i]) & mmask];
                    U0hatT[j][i] = std::conj(U0[i][j]);
                }
            }
            p.m_U0Pre = EvalLinearTransformPrecompute(cc, U0, scaleDec, lDec);
            p.m_U0hatTPre = EvalLinearTransformPrecompute(cc, U0hatT, scaleEnc, lEnc);
        }
    } else {
        bool flagPack = !(cc.GetCKKSDataType() == REAL || !p.BTSlotsEncoding);
        p.m_U0PreFFT = EvalSlotsToCoeffsPrecompute(cc, ksiPows, rotGroup, false, scaleDec, lDec, flagPack);
        p.m_U0hatTPreFFT = EvalCoeffsToSlotsPrecompute(cc, ksiPows, rotGroup, false, scaleEnc, lEnc, flagPack);
    }
}

static_assert(PARTIAL_SUM_RADIX >= 2 && (PARTIAL_SUM_RADIX & (PARTIAL_SUM_RADIX - 1)) == 0,
              "PARTIAL_SUM_RADIX must be a power of two >= 2");

void FHECKKSRNS::EvalPartialSumInPlace(Ciphertext<DCRTPoly>& raised, uint32_t slots) {
    const uint32_t N = raised->GetCryptoContext()->GetRingDimension();
    EvalPartialSumInPlace(raised, slots, N / (2 * slots), PARTIAL_SUM_RADIX);
}

void FHECKKSRNS::EvalPartialSumInPlace(Ciphertext<DCRTPoly>& ct, uint32_t stride, uint32_t size) {
    if (size <= 1)
        return;

    const auto cc = ct->GetCryptoContext();
    const uint32_t N = cc->GetRingDimension();
    const uint32_t M = cc->GetCyclotomicOrder();

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ct->GetCryptoParameters());
    if (cryptoParams->GetKeySwitchTechnique() != HYBRID) {
        for (uint32_t s = 1; s < size; s <<= 1)
            cc->EvalAddInPlace(ct, cc->EvalRotate(ct, stride * s));
        return;
    }

    const auto algo = cc->GetScheme();
    auto evalKeyMap = cc->GetEvalAutomorphismKeyMap(ct->GetKeyTag());

    std::vector<DCRTPoly>& cv = ct->GetElements();
    const auto paramsQl = cv[0].GetParams();
    const auto paramsP = cryptoParams->GetParamsP();
    const auto paramsQlP = cv[0].GetExtendedCRTBasis(paramsP);
    const uint32_t sizeQl = paramsQl->GetParams().size();
    const uint32_t sizeQlP = paramsQlP->GetParams().size();

    const PlaintextModulus t = (cryptoParams->GetNoiseScale() == 1) ? 0 : cryptoParams->GetPlaintextModulus();

    DCRTPoly acc(paramsQlP, Format::EVALUATION, true);
    auto cMult = cv[0].TimesNoCheck(cryptoParams->GetPModq());
    for (uint32_t i = 0; i < sizeQl; ++i)
        acc.SetElementAtIndex(i, std::move(cMult.GetElementAtIndex(i)));

    std::vector<uint32_t> vec(N);
    for (uint32_t s = 1; s < size; s <<= 1) {
        uint32_t autoIndex = FindAutomorphismIndex2nComplex(stride * s, M);
        auto evalKeyIterator = evalKeyMap.find(autoIndex);
        if (evalKeyIterator == evalKeyMap.end())
            OPENFHE_THROW("EvalKey for index [" + std::to_string(autoIndex) + "] is not found.");

        PrecomputeAutoMap(N, autoIndex, &vec);

        auto digits = algo->EvalKeySwitchPrecomputeCore(cv[1], cryptoParams);
        auto ba = algo->EvalFastKeySwitchCoreExt(digits, evalKeyIterator->second, paramsQl);

        // ba[0] += acc;
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQlP))
        for (uint32_t i = 0; i < sizeQlP; ++i)
            ba[0].GetAllElements()[i] += acc.GetAllElements()[i];

        ba[0] = ba[0].AutomorphismTransform(autoIndex, vec);

        // acc += ba[0];
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQlP))
        for (uint32_t i = 0; i < sizeQlP; ++i)
            acc.GetAllElements()[i] += ba[0].GetAllElements()[i];

        // Element 1 is settled every level: the next rotation needs its digit decomposition.
        cv[1] += ba[1].AutomorphismTransform(autoIndex, vec)
                         .ApproxModDown(paramsQl, paramsP, cryptoParams->GetPInvModq(),
                                        cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
                                        cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
                                        cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
                                        cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());
    }

    cv[0] = acc.ApproxModDown(paramsQl, paramsP, cryptoParams->GetPInvModq(), cryptoParams->GetPInvModqPrecon(),
                              cryptoParams->GetPHatInvModp(), cryptoParams->GetPHatInvModpPrecon(),
                              cryptoParams->GetPHatModq(), cryptoParams->GetModqBarrettMu(),
                              cryptoParams->GettInvModp(), cryptoParams->GettInvModpPrecon(), t,
                              cryptoParams->GettModqPrecon());
}

void FHECKKSRNS::EvalPartialSumInPlace(Ciphertext<DCRTPoly>& ct, uint32_t stride, uint32_t size, uint32_t radix) {
    if (size <= 1)
        return;
    if (radix == 2)
        return EvalPartialSumInPlace(ct, stride, size);

    const auto cc = ct->GetCryptoContext();
    const uint32_t N = cc->GetRingDimension();
    const uint32_t M = cc->GetCyclotomicOrder();

    const uint32_t logRadix = lbcrypto::GetMSB(radix) - 1;
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ct->GetCryptoParameters());
    if (cryptoParams->GetKeySwitchTechnique() != HYBRID) {
        for (uint32_t s = 1; s < size; s <<= logRadix) {
            auto base = ct->Clone();
            auto digits = cc->EvalFastRotationPrecompute(base);
            for (uint32_t idx = stride * s; idx < stride * size && idx < radix * stride * s; idx += stride * s)
                cc->EvalAddInPlace(ct, cc->EvalFastRotation(base, idx, M, digits));
        }
        return;
    }

    const auto algo = cc->GetScheme();
    auto evalKeyMap = cc->GetEvalAutomorphismKeyMap(ct->GetKeyTag());

    std::vector<DCRTPoly>& cv = ct->GetElements();
    const auto paramsQl = cv[0].GetParams();
    const auto paramsP = cryptoParams->GetParamsP();
    const auto paramsQlP = cv[0].GetExtendedCRTBasis(paramsP);
    const uint32_t sizeQl = paramsQl->GetParams().size();
    const uint32_t sizeQlP = paramsQlP->GetParams().size();

    const PlaintextModulus t = (cryptoParams->GetNoiseScale() == 1) ? 0 : cryptoParams->GetPlaintextModulus();

    DCRTPoly acc(paramsQlP, Format::EVALUATION, true);
    auto cMult = cv[0].TimesNoCheck(cryptoParams->GetPModq());
    for (uint32_t i = 0; i < sizeQl; ++i)
        acc.SetElementAtIndex(i, std::move(cMult.GetElementAtIndex(i)));

    std::vector<uint32_t> vec(N);
    for (uint32_t s = 1; s < size; s <<= logRadix) {
        // One digit decomposition per level, shared by all of the level's rotations.
        auto digits = algo->EvalKeySwitchPrecomputeCore(cv[1], cryptoParams);

        // Per-level sums; the pre-level accumulator is folded into every rotation of the level.
        DCRTPoly lvl0(paramsQlP, Format::EVALUATION, true);
        DCRTPoly lvl1(paramsQlP, Format::EVALUATION, true);

        for (uint32_t idx = stride * s; idx < stride * size && idx < radix * stride * s; idx += stride * s) {
            uint32_t autoIndex = FindAutomorphismIndex2nComplex(idx, M);
            auto evalKeyIterator = evalKeyMap.find(autoIndex);
            if (evalKeyIterator == evalKeyMap.end())
                OPENFHE_THROW("EvalKey for index [" + std::to_string(autoIndex) + "] is not found.");

            PrecomputeAutoMap(N, autoIndex, &vec);

            auto ba = algo->EvalFastKeySwitchCoreExt(digits, evalKeyIterator->second, paramsQl);

            // ba[0] += acc;
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQlP))
            for (uint32_t i = 0; i < sizeQlP; ++i)
                ba[0].GetAllElements()[i] += acc.GetAllElements()[i];

            ba[0] = ba[0].AutomorphismTransform(autoIndex, vec);
            ba[1] = ba[1].AutomorphismTransform(autoIndex, vec);

            // lvl0 += ba[0]; lvl1 += ba[1];
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQlP))
            for (uint32_t i = 0; i < sizeQlP; ++i) {
                lvl0.GetAllElements()[i] += ba[0].GetAllElements()[i];
                lvl1.GetAllElements()[i] += ba[1].GetAllElements()[i];
            }
        }

        // acc += lvl0;
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQlP))
        for (uint32_t i = 0; i < sizeQlP; ++i)
            acc.GetAllElements()[i] += lvl0.GetAllElements()[i];

        // Element 1 settles once per level from the level's extended sum: the next level's
        // rotations need its digit decomposition.
        cv[1] += lvl1.ApproxModDown(paramsQl, paramsP, cryptoParams->GetPInvModq(), cryptoParams->GetPInvModqPrecon(),
                                    cryptoParams->GetPHatInvModp(), cryptoParams->GetPHatInvModpPrecon(),
                                    cryptoParams->GetPHatModq(), cryptoParams->GetModqBarrettMu(),
                                    cryptoParams->GettInvModp(), cryptoParams->GettInvModpPrecon(), t,
                                    cryptoParams->GettModqPrecon());
    }

    cv[0] = acc.ApproxModDown(paramsQl, paramsP, cryptoParams->GetPInvModq(), cryptoParams->GetPInvModqPrecon(),
                              cryptoParams->GetPHatInvModp(), cryptoParams->GetPHatInvModpPrecon(),
                              cryptoParams->GetPHatModq(), cryptoParams->GetModqBarrettMu(),
                              cryptoParams->GettInvModp(), cryptoParams->GettInvModpPrecon(), t,
                              cryptoParams->GettModqPrecon());
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalBootstrap(ConstCiphertext<DCRTPoly>& ciphertext, uint32_t numIterations,
                                               uint32_t precision) const {
    uint32_t slots = ciphertext->GetSlots();
    auto& p = GetBootPrecom(slots, CKKSBootstrapPrecom::BOOTSTRAP);

    // REAL_CI: both orderings are evaluated below (ciStcFirst).
    if (p.BTSlotsEncoding && ciphertext->GetCryptoContext()->GetCKKSDataType() != REAL_CI) {
        return EvalBootstrapStCFirst(ciphertext, numIterations, precision);
        // AA: Note that in the FIXEDMANUAL case, EvalBootstrap and EvalBootstrapStCFirst return ciphertexts with different NoiseDeg.
    }

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW("CKKS Bootstrapping only supported with Hybrid key switching.");

    auto st = cryptoParams->GetScalingTechnique();
#if NATIVEINT == 128
    if (st == FLEXIBLEAUTO || st == FLEXIBLEAUTOEXT)
        OPENFHE_THROW("128-bit CKKS Bootstrapping only supported for FIXEDMANUAL and FIXEDAUTO.");
#endif

    if (numIterations != 1 && numIterations != 2)
        OPENFHE_THROW("CKKS Bootstrapping only supported for 1 or 2 iterations.");

#ifdef BOOTSTRAPTIMING
    TimeVar t;
    double timeEncode(0.0);
    double timeModReduce(0.0);
    double timeDecode(0.0);
#endif

    auto cc = ciphertext->GetCryptoContext();
    uint32_t L0 = cryptoParams->GetElementParams()->GetParams().size();
    auto initSizeQ = ciphertext->GetElements()[0].GetNumOfElements();
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    if (numIterations > 1) {
        // Step 1: Get the input.
        uint32_t powerOfTwoModulus = 1 << precision;

        // The standard bootstrap returns noise scale degree 2 and is rescaled here. The native CI bootstrap
        // (CtS-first: its StC output is already rescaled) returns degree 1, so it is rescaled only if its degree
        // is above 1 (item 3.2: the unconditional rescale left the CI bootstrapping error at 1 tower, and its
        // ModRaise threw). Std is unchanged.
        const bool ciRescaled = (cc->GetCKKSDataType() == REAL_CI);
        auto rescaleOutput    = [&](Ciphertext<DCRTPoly>& c) {
            if (!ciRescaled || c->GetNoiseScaleDeg() > 1)
                cc->GetScheme()->ModReduceInternalInPlace(c, compositeDegree);
        };

        // Step 3: Bootstrap the initial ciphertext.
        auto ctInitialBootstrap = EvalBootstrap(ciphertext, numIterations - 1, 0);
        rescaleOutput(ctInitialBootstrap);

        // Step 4: Scale up by powerOfTwoModulus.
        cc->GetScheme()->MultByIntegerInPlace(ctInitialBootstrap, powerOfTwoModulus);

        // If we start with more towers than we obtain from bootstrapping, return the original ciphertext.
        auto bootstrappingSizeQ = ctInitialBootstrap->GetElements()[0].GetNumOfElements();
        if (bootstrappingSizeQ <= initSizeQ)
            return ciphertext->Clone();

        // Step 2: Scale up by powerOfTwoModulus, and extend the modulus to powerOfTwoModulus * q.
        // Note that we extend the modulus implicitly without any code calls because the value always stays 0.
        auto ctScaledUp = ciphertext->Clone();
        if (st == FIXEDMANUAL) {
            cc->GetScheme()->ModReduceInternalInPlace(ctScaledUp, ctScaledUp->GetNoiseScaleDeg() - 1);
        }
        // We multiply by powerOfTwoModulus, and leave the last CRT value to be 0 (mod powerOfTwoModulus).
        cc->GetScheme()->MultByIntegerInPlace(ctScaledUp, powerOfTwoModulus);

        // Step 5: Mod-down to powerOfTwoModulus * q
        // We mod down, and leave the last CRT value to be 0 because it's divisible by powerOfTwoModulus.
        auto ctBootstrappedScaledDown = ctInitialBootstrap->Clone();
        if (st == FIXEDAUTO) {
            for (auto& cv : ctBootstrappedScaledDown->GetElements())
                cv.DropLastElements(bootstrappingSizeQ - initSizeQ);
            ctBootstrappedScaledDown->SetLevel(L0 - ctBootstrappedScaledDown->GetElements()[0].GetNumOfElements());
        }

        // Step 6 and 7: Calculate the bootstrapping error by subtracting the original ciphertext from the bootstrapped ciphertext. Mod down to q is done implicitly.
        auto ctBootstrappingError = cc->EvalSub(ctBootstrappedScaledDown, ctScaledUp);

        // Step 8: Bootstrap the error.
        auto ctBootstrappedError = EvalBootstrap(ctBootstrappingError, 1, 0);
        rescaleOutput(ctBootstrappedError);

        // Step 9: Subtract the bootstrapped error from the initial bootstrap to get even lower error.
        auto finalCiphertext = cc->EvalSub(ctInitialBootstrap, ctBootstrappedError);

        // Step 10: Scale back down by powerOfTwoModulus to get the original message.
        cc->EvalMultInPlace(finalCiphertext, 1.0 / powerOfTwoModulus);

        return finalCiphertext;
    }

    auto elementParamsRaised = *(cryptoParams->GetElementParams());
    // For FLEXIBLEAUTOEXT we raised ciphertext does not include extra modulus
    // as it is multiplied by auxiliary plaintext
    if (st == FLEXIBLEAUTOEXT)
        elementParamsRaised.PopLastParam();

    const auto& paramsQ = elementParamsRaised.GetParams();
    uint32_t sizeQ = paramsQ.size();
    std::vector<NativeInteger> moduli(sizeQ);
    std::vector<NativeInteger> roots(sizeQ);
    for (uint32_t i = 0; i < sizeQ; ++i) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i] = paramsQ[i]->GetRootOfUnity();
    }
    auto elementParamsRaisedPtr =
            std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(cc->GetCyclotomicOrder(), moduli, roots);
    elementParamsRaisedPtr->SetRingType(paramsQ[0]->GetRingType());

    double qDouble = GetBigModulus(cryptoParams);
    double powP = std::pow(2, cryptoParams->GetPlaintextModulus());
    int32_t deg = std::round(std::log2(qDouble / powP));
#if NATIVEINT != 128
    if (deg > static_cast<int32_t>(m_correctionFactor) && st != COMPOSITESCALINGAUTO && st != COMPOSITESCALINGMANUAL) {
        OPENFHE_THROW("Degree [" + std::to_string(deg) + "] must be less than or equal to the correction factor [" +
                      std::to_string(m_correctionFactor) + "].");
    }
#endif
    // For composite scaling, deg may exceed the correction factor (the check above is skipped, since with
    // larger composite degrees the first modulus is typically much larger than the scaling factor); in that
    // case no correction is applied instead of letting the unsigned subtraction wrap around.
    uint32_t correction = (deg < static_cast<int32_t>(m_correctionFactor)) ? m_correctionFactor - deg : 0;
    double post = std::pow(2, static_cast<double>(deg));

    // For FLEXIBLE* the exact power-of-two 1/post is applied here as the shrink before CoeffsToSlots and
    // restored by the integer "scalar" after the sine. For composite scaling the entire overflow
    // normalization (the exact 2^-deg = 1/post AND the residual c1) is carried by the CoeffsToSlots/
    // SlotsToCoeffs matrix coefficients (see EvalBootstrapSetup), so no shrink is applied here; this
    // keeps the CtS rotations on the full-magnitude message and avoids amplifying their noise by 2^deg.
    double pre = (compositeDegree > 1) ? 1.0 : 1. / post;
    uint64_t scalar = std::llround(post);

    //------------------------------------------------------------------------------
    // RAISING THE MODULUS
    //------------------------------------------------------------------------------

    // In FLEXIBLEAUTO, raising the ciphertext to a larger number
    // of towers is a bit more complex, because we need to adjust
    // it's scaling factor to the one that corresponds to the level
    // it's being raised to.
    // Increasing the modulus

    // StC-first native CI bootstrap (precomputation with BTSlotsEncoding, item 2.5): the CI branch below runs StC
    // on the input first and raises its output; the input is not raised here.
    const bool ciStcFirst = (cc->GetCKKSDataType() == REAL_CI) && p.BTSlotsEncoding;
    auto algo = cc->GetScheme();
    uint32_t lvl = cryptoParams->GetScalingTechnique() != FLEXIBLEAUTOEXT ? 0 : 1;
    auto raiseInPlace = [&](Ciphertext<DCRTPoly>& r) {
        algo->ModReduceInternalInPlace(r, compositeDegree * (r->GetNoiseScaleDeg() - 1));
        AdjustCiphertext(r, std::pow(2, -static_cast<int32_t>(correction)), lvl);
        ModRaiseInPlace(r, elementParamsRaisedPtr);
    };
    auto raised = ciphertext->Clone();
    uint32_t N = cc->GetRingDimension();
    if (!ciStcFirst)
        raiseInPlace(raised);

#ifdef BOOTSTRAPTIMING
    auto numTowers = raised->GetElements()[0].GetNumOfElements() - 1;
    OPENFHE_DIAGNOSTIC_ERR << "\nNumber of levels at the beginning of bootstrapping: " << numTowers << "\n";
#endif

    //------------------------------------------------------------------------------
    // SETTING PARAMETERS FOR APPROXIMATE MODULAR REDUCTION
    //------------------------------------------------------------------------------

    // Coefficients of the Chebyshev series interpolating 1/(2 Pi) Sin(2 Pi K x). The overflow bound K
    // itself is folded into the CoeffsToSlots matrix (see GetModRaiseOverflowBound), so only the exact 1/N
    // normalization is applied here.
    std::vector<double> coefficients;

    if (cryptoParams->GetSecretKeyDist() == SPARSE_TERNARY) {
        coefficients = g_coefficientsSparse;
    } else if (cryptoParams->GetSecretKeyDist() == SPARSE_ENCAPSULATED) {
        // K = 28 (the SPARSE_TERNARY table) for the denser sparse secret (Hamming weight 64: first modulus above
        // 60 bits), K = 16 otherwise
        coefficients = (cryptoParams->GetSparseKSHammingWeight() > 32) ? g_coefficientsSparse :
                                                                         g_coefficientsSparseEncapsulated;
    } else {
        coefficients = g_coefficientsUniform;
    }

    if (!ciStcFirst)
        cc->EvalMultInPlace(raised, pre / N);

    // no linear transformations are needed for Chebyshev series as the range has been normalized to [-1,1]
    double coeffLowerBound = -1.0;
    double coeffUpperBound = 1.0;

    bool isLTBootstrap = (p.m_paramsEnc.lvlb == 1) && (p.m_paramsDec.lvlb == 1);

    //------------------------------------------------------------------------------
    // NATIVE CONJUGATE-INVARIANT (CI) BOOTSTRAP: ModRaise -> CI-CtS -> EvalMod -> CI-StC
    //------------------------------------------------------------------------------
    if (cc->GetCKKSDataType() == REAL_CI) {
        if (cryptoParams->GetSecretKeyDist() == SPARSE_TERNARY)
            OPENFHE_THROW("Native CI bootstrap supports UNIFORM_TERNARY and SPARSE_ENCAPSULATED secrets.");
        // CI sparse encapsulation: a weight-h CI-basis key behaves like a weight-~2h power-basis key,
        // so the K = 28 (SPARSE_TERNARY) sine table is used (its depth is what GetBootstrapDepth budgets).
        if (cryptoParams->GetSecretKeyDist() == SPARSE_ENCAPSULATED)
            coefficients = g_coefficientsSparse;
        const uint32_t Nn = slots;          // full real packing: slots == ring dimension N
        // scaleEnc/scaleDec mirror EvalBootstrapSetup (NOT the eval-stage `pre`=1/post). Since OpenFHE
        // v1.6 the ModRaise overflow bound K is folded into the CtS matrix (raised is only scaled by
        // pre/N above), so scaleEnc = pre_setup / K, scaleDec = 1 / pre_setup.
        const auto ciScales   = CIBootScales(qDouble, GetModRaiseOverflowBound(cryptoParams, K_UNIFORM));
        const double scaleEnc = ciScales.first;
        const double scaleDec = ciScales.second;
        // Item 2.4: the diagonal plaintexts are encoded in EvalBootstrapSetup (CIBootstrapPrecompute) and only read
        // here. If a store does not match the level input (EvalBootstrapSetup with precompute = false, or a chain
        // the tower model does not cover), that level is encoded locally for this call; `ciLocalEncodes` counts them.
        [[maybe_unused]] uint32_t ciLocalEncodes = 0;

        // Apply the dense real matrix (budget {1,1}) via the CI homomorphic linear transform
        // M v = sum_k D_k (x) rot_{5^k}(v), D_k[s]=M[s][precomp_k[s]]. Baby-step/giant-step: k = n1*j + i, g = 5^{n1}:
        //   out = sum_j psi_{g^j}( sum_i psi_{g^-j}(D_{n1 j+i}) (x) bx[i] ),  bx[i]=psi_{5^i}(v).
        // ~n1+n2 = 2 sqrt(N) rotations (key-switches); diagonal plaintexts from CIEncodeDenseLevel.
        // HOISTED, EXTENDED-BASIS BSGS linear transform (mirrors EvalCoeffsToSlots): baby
        // rotations 5^i are hoisted (one EvalFastRotationPrecompute, reused) and accumulated in
        // the extended QlP basis; a giant block ModDowns only its element 1 (EvalHornerGiantRotate) and
        // one KeySwitchDown ends the level (vs a ModDown per rotation in the old EvalAutomorphism path) --
        // this is the noise reduction that lets the level-collapse rescaling actually deliver precision. The N-term
        // diagonal sum is sparse-skipped (collapsed stages); diagonals are CI-encoded in the QlP
        // basis (CKKSPackedEncoding REAL_CI). Galois element 5^k passed directly (CI EvalFastRotationExt).
        auto applyCILT = [&](Ciphertext<DCRTPoly> ct, const std::vector<ReadOnlyPlaintext>& store, bool enc,
                             double scale) {
            const uint64_t m4 = 4ULL * Nn;
            const uint32_t n1 = CIDenseN1(Nn);
            const uint32_t n2 = Nn / n1;
            uint32_t gstep    = 1;
            for (uint32_t t = 0; t < n1; ++t)
                gstep = static_cast<uint32_t>((static_cast<uint64_t>(gstep) * 5) % m4);  // g = 5^{n1}
            const uint32_t towers = ct->GetElements()[0].GetNumOfElements();
            const std::vector<ReadOnlyPlaintext>* pts = &store;
            std::vector<ReadOnlyPlaintext> local;
            if (!CIStoreMatches(*cryptoParams, store, static_cast<size_t>(n1) * n2, towers)) {
                local = CIEncodeDenseLevel(*cryptoParams, Nn, towers, enc, scale);
                pts   = &local;
                ++ciLocalEncodes;
            }

            // Hoisted baby rotations in the extended basis: bx[i] = ext(psi_{5^i}(ct)).
            auto digits = cc->EvalFastRotationPrecompute(ct);
            std::vector<Ciphertext<DCRTPoly>> bx(n1);
            bx[0]       = cc->KeySwitchExt(ct, true);  // i=0: identity, extend to QlP
            uint32_t fi = 1;
            for (uint32_t i = 1; i < n1; ++i) {
                fi    = static_cast<uint32_t>((static_cast<uint64_t>(fi) * 5) % m4);
                bx[i] = cc->EvalFastRotationExt(ct, fi, digits, true);  // CI: 5^i used directly
            }

            Ciphertext<DCRTPoly> outer;  // extended-basis accumulator
            const auto& autoKeys = cc->GetEvalAutomorphismKeyMap(ct->GetKeyTag());
            uint32_t gj          = 1;  // 5^{n1 j}
            std::vector<uint32_t> map(Nn);
            for (uint32_t j = 0; j < n2; ++j) {
                uint32_t gj0 = gj;  // 5^{n1 j} (giant Galois element for this block)
                Ciphertext<DCRTPoly> inner;
                for (uint32_t i = 0; i < n1; ++i) {
                    const auto& pd = (*pts)[static_cast<size_t>(j) * n1 + i];
                    if (pd == nullptr)
                        continue;
                    Ciphertext<DCRTPoly> term = EvalMultExt(bx[i], pd);  // extended-basis plaintext mult
                    if (inner == nullptr)
                        inner = term;
                    else
                        EvalAddExtInPlace(inner, term);
                }
                gj = static_cast<uint32_t>((static_cast<uint64_t>(gj) * gstep) % m4);
                if (inner == nullptr)
                    continue;  // empty giant block (all diagonals zero)
                if (j != 0) {
                    // giant step in the extended basis (EvalHornerGiantRotate): only element 1 is ModDown'd
                    // and key-switched; element 0 is rotated in QlP and reaches Ql in the final KeySwitchDown.
                    auto kit = autoKeys.find(gj0);
                    if (kit == autoKeys.end())
                        OPENFHE_THROW("EvalKey for index [" + std::to_string(gj0) + "] is not found.");
                    PrecomputeAutoMapCI(Nn, gj0, &map);
                    inner = EvalHornerGiantRotate(inner, gj0, map, kit->second);
                }
                if (outer == nullptr)
                    outer = inner;
                else
                    EvalAddExtInPlace(outer, inner);
            }
            if (outer == nullptr)
                return Ciphertext<DCRTPoly>();
            return cc->KeySwitchDown(outer);
        };

        // CI CtS/StC dispatch on the level budget:
        //   {1,1}        -> dense single-level BSGS LT (CtS = scaleEnc*N*U^-1, StC = scaleDec*U); small N only.
        //   any budget>1 -> paper real FFT (ePrint 2026/2618): sparse real orthogonal factors collapsed to the
        //                   budget, one rescale per level, evaluated by the sparse hoisted BSGS (applyCISparse).
        auto rescale1 = [&](Ciphertext<DCRTPoly>& c) {
            if (st == FIXEDMANUAL) {
                while (c->GetNoiseScaleDeg() > 1)
                    cc->ModReduceInPlace(c);
            }
            else if (c->GetNoiseScaleDeg() == 2) {
                algo->ModReduceInternalInPlace(c, compositeDegree);
            }
        };
        // Paper real FFT (single channel, sparse diagonals) whenever a level budget > 1 is requested;
        // budget {1,1} keeps the dense single-level BSGS transform.
        const uint32_t lbEnc  = p.m_paramsEnc.lvlb;
        const uint32_t lbDec  = p.m_paramsDec.lvlb;
        const bool useRealFFT = (lbEnc > 1 || lbDec > 1);
        // Sparse hoisted BSGS: only the nonzero diagonals of A, baby/giant steps over their offset window.
        // Galois elements of the rotations the sparse levels actually perform (checked against keygen below).
        std::set<uint32_t> ciGalUsed;
        // Modelled towers / key-switching digits per level (the BSGS plan input; same numbers as keygen).
        const auto ciDigits = CIBsgsLevelDigits(*cryptoParams, lbEnc, lbDec,
                                                GetModDepthInternal(cryptoParams->GetSecretKeyDist()), ciStcFirst);
        // store: the level's diagonal plaintexts from CIBootstrapPrecompute (BSGS layout of CIEncodeSparseLevel);
        // sc: per-level scalar applied to the stored (unscaled) diagonals, used only for a local encode.
        auto applyCISparse = [&](Ciphertext<DCRTPoly> ct, const std::vector<ReadOnlyPlaintext>& store,
                                 const CISparse& A, double sc, uint32_t ksDigits) {
            const auto bp         = CIPlanBsgs(A, Nn, ksDigits);
            const uint32_t towers = ct->GetElements()[0].GetNumOfElements();
            const std::vector<ReadOnlyPlaintext>* pts = &store;
            std::vector<ReadOnlyPlaintext> local;
            if (!CIStoreMatches(*cryptoParams, store, static_cast<size_t>(bp.n1) * bp.n2, towers)) {
                local = CIEncodeSparseLevel(*cryptoParams, A, Nn, bp, sc, towers);
                pts   = &local;
                ++ciLocalEncodes;
            }
            auto offsetOf = [&](uint32_t u) {  // u = n1*j + i
                return static_cast<uint32_t>((static_cast<uint64_t>(bp.h) * (bp.t0 + u)) % Nn);
            };
            std::vector<char> babyUsed(bp.n1, 0);
            for (uint32_t u = 0; u < bp.span; ++u)
                if (A.count(offsetOf(u)))
                    babyUsed[u % bp.n1] = 1;
            auto digits =
                LTRun(&LTStats::modUp, &LTStats::tModUp, 1, [&] { return cc->EvalFastRotationPrecompute(ct); });
            std::vector<Ciphertext<DCRTPoly>> bx(bp.n1);
            std::vector<uint32_t> babyList;
            for (uint32_t i = 0; i < bp.n1; ++i)
                if (babyUsed[i])
                    babyList.push_back(i);
            const uint32_t nThrBaby = static_cast<uint32_t>(OpenFHEParallelControls.GetThreadLimit(babyList.size()));
            if (nThrBaby > 1) {
                // Multi-threaded: the hoisted baby rotations run in parallel (as std's EvalCoeffsToSlots); each
                // rotation's own tower loops then run on one thread.
                uint32_t nb = 0;
                for (uint32_t i : babyList)
                    if (i != 0) {
                        ciGalUsed.insert(CIGaloisForShift(bp.h * i, Nn));
                        ++nb;
                    }
                LTRun(&LTStats::baby, &LTStats::tBaby, nb, [&] {
#pragma omp parallel for schedule(dynamic) num_threads(nThrBaby)
                    for (size_t k = 0; k < babyList.size(); ++k) {
                        const uint32_t i = babyList[k];
                        bx[i] = (i != 0) ?
                                    cc->EvalFastRotationExt(ct, CIGaloisForShift(bp.h * i, Nn), digits, true) :
                                    cc->KeySwitchExt(ct, true);
                    }
                    return 0;
                });
                if (babyUsed[0])
                    LTAdd(&LTStats::ext, 1);
            }
            for (uint32_t i = 0; i < bp.n1 && nThrBaby <= 1; ++i) {
                if (!babyUsed[i])
                    continue;
                if (i != 0) {
                    ciGalUsed.insert(CIGaloisForShift(bp.h * i, Nn));
                    bx[i] = LTRun(&LTStats::baby, &LTStats::tBaby, 1, [&] {
                        return cc->EvalFastRotationExt(ct, CIGaloisForShift(bp.h * i, Nn), digits, true);
                    });
                }
                else {
                    bx[i] = LTRun(&LTStats::ext, &LTStats::tBaby, 1, [&] { return cc->KeySwitchExt(ct, true); });
                }
            }
            Ciphertext<DCRTPoly> outer;
            std::vector<uint32_t> map(Nn);
            const auto& autoKeys = cc->GetEvalAutomorphismKeyMap(ct->GetKeyTag());
            std::vector<uint32_t> blockDiags;
            for (uint32_t j = 0; j < bp.n2; ++j) {
                const uint32_t G = offsetOf(bp.n1 * j);
                Ciphertext<DCRTPoly> inner;
                blockDiags.clear();
                for (uint32_t i = 0; i < bp.n1; ++i) {
                    const uint32_t u = bp.n1 * j + i;
                    if (u >= bp.span)
                        break;
                    if ((*pts)[u] != nullptr)
                        blockDiags.push_back(i);
                }
                // >= 2 diagonals per thread; the sums are exact mod q, so the result does not depend on the threads
                const uint32_t nThrAcc =
                    static_cast<uint32_t>(OpenFHEParallelControls.GetThreadLimit(blockDiags.size() / 2));
                if (nThrAcc > 1) {
                    // Multi-threaded: per-thread partial sums of the block's plaintext products in the extended
                    // basis (a contiguous run of diagonals per thread), reduced once per giant block.
                    const size_t nd = blockDiags.size();
                    std::vector<Ciphertext<DCRTPoly>> part(nThrAcc);
                    LTRun(&LTStats::ptMult, &LTStats::tPtMult, static_cast<uint32_t>(nd), [&] {
#pragma omp parallel for schedule(static, 1) num_threads(nThrAcc)
                        for (uint32_t t = 0; t < nThrAcc; ++t) {
                            const size_t k0 = nd * t / nThrAcc, k1 = nd * (t + 1) / nThrAcc;
                            for (size_t k = k0; k < k1; ++k) {
                                const uint32_t i = blockDiags[k];
                                auto pt          = (*pts)[bp.n1 * j + i]->GetElement<DCRTPoly>();
                                pt.SetFormat(Format::EVALUATION);
                                if (part[t] == nullptr) {
                                    part[t] = bx[i]->Clone();
                                    for (auto& c : part[t]->GetElements())
                                        c *= pt;
                                    part[t]->SetNoiseScaleDeg(part[t]->GetNoiseScaleDeg() +
                                                              (*pts)[bp.n1 * j + i]->GetNoiseScaleDeg());
                                    part[t]->SetScalingFactor(part[t]->GetScalingFactor() *
                                                              (*pts)[bp.n1 * j + i]->GetScalingFactor());
                                }
                                else {
                                    const auto& src = bx[i]->GetElements();
                                    auto& dst       = part[t]->GetElements();
                                    for (size_t e = 0; e < dst.size(); ++e) {
                                        DCRTPoly prod = src[e];
                                        prod *= pt;
                                        dst[e] += prod;
                                    }
                                }
                            }
                        }
                        return 0;
                    });
                    for (auto& pc : part) {
                        if (pc == nullptr)
                            continue;
                        if (inner == nullptr)
                            inner = pc;
                        else
                            EvalAddExtInPlace(inner, pc);
                    }
                    LTAdd(&LTStats::add, static_cast<uint32_t>(nd) - nThrAcc);  // in-thread adds (reduction counted)
                }
                else {
                    for (uint32_t i : blockDiags) {
                        Ciphertext<DCRTPoly> term = EvalMultExt(bx[i], (*pts)[bp.n1 * j + i]);
                        if (inner == nullptr)
                            inner = term;
                        else
                            EvalAddExtInPlace(inner, term);
                    }
                }
                if (inner == nullptr)
                    continue;
                // Giant step in the extended basis (as std's EvalHornerGiantRotate): only element 1 is ModDown'd,
                // key-switched and rotated; element 0 stays in QlP, is rotated there and reaches Ql in the single
                // final KeySwitchDown. The block at offset 0 (CIPlanBsgs aligns one) needs no rotation.
                if (G != 0) {
                    const uint32_t gal = CIGaloisForShift(G, Nn);
                    ciGalUsed.insert(gal);
                    auto kit = autoKeys.find(gal);
                    if (kit == autoKeys.end())
                        OPENFHE_THROW("EvalKey for index [" + std::to_string(gal) + "] is not found.");
                    PrecomputeAutoMapCI(Nn, gal, &map);
                    inner = EvalHornerGiantRotate(inner, gal, map, kit->second);
                }
                if (outer == nullptr)
                    outer = inner;
                else
                    EvalAddExtInPlace(outer, inner);
            }
            return LTRun(&LTStats::modDown, &LTStats::tModDown, 2, [&] { return cc->KeySwitchDown(outer); });
        };
#ifdef BOOTSTRAPTIMING
        // Stage times ("[CI-BT] CtS / EvalMod / StC <s> s", as std's "Encoding / Approximate modular reduction /
        // Decoding time") on the diagnostic error stream.
        auto ciNow = [] { return std::chrono::steady_clock::now(); };
        auto ciSec = [](std::chrono::steady_clock::time_point t0) {
            return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        };
#endif
        // Apply sparse g=5-basis levels (apply order), one rescale per level; `scale` (scaleEnc or scaleDec)
        // is spread evenly over the levels at encode time.
        auto applyReal = [&](Ciphertext<DCRTPoly> in, const std::vector<CISparse>& levels,
                             const std::vector<std::vector<ReadOnlyPlaintext>>& stores, double scale,
                             const char* tag, const std::vector<uint32_t>& digits,
                             [[maybe_unused]] const std::vector<uint32_t>& towersModel) {
            static const std::vector<ReadOnlyPlaintext> noStore;
            const double sc = CIRealLevelScalar(scale, levels.size());
            for (size_t s = 0; s < levels.size(); ++s) {
                const CISparse& A = levels[s];
#if defined(BOOTSTRAPTIMING) && defined(BOOTSTRAPTIMING_LT)
                auto tl                 = ciNow();
                const uint32_t towersIn = in->GetElements()[0].GetNumOfElements();
#endif
                LTLevel ltl(tag, static_cast<int32_t>(s), static_cast<uint32_t>(A.size()),
                            in->GetElements()[0].GetNumOfElements(), cryptoParams->GetParamsP()->GetParams().size());
                in = applyCISparse(in, (s < stores.size()) ? stores[s] : noStore, A, sc, CIDigitsAt(digits, s));
                ltl.Print();
#if defined(BOOTSTRAPTIMING) && defined(BOOTSTRAPTIMING_LT)
                {  // BSGS plan of the level, its runtime and modelled input towers
                    auto bp = CIPlanBsgs(A, Nn, CIDigitsAt(digits, s));
                    OPENFHE_DIAGNOSTIC_ERR << "[CI-BT] level " << s << " diags=" << A.size() << " h=" << bp.h
                                           << " span=" << bp.span << " n1=" << bp.n1 << " n2=" << bp.n2
                                           << " babies=" << bp.babies << " giants=" << bp.giants
                                           << " digits=" << CIDigitsAt(digits, s) << " towers=" << towersIn
                                           << " (model " << CIDigitsAt(towersModel, s) << ") t=" << ciSec(tl)
                                           << "s\n";
                }
#endif
                rescale1(in);
            }
            return in;
        };

#ifdef BOOTSTRAPTIMING
        auto tStage = ciNow();
#endif
        if (ciStcFirst) {
            // StC-first (the paper's ordering): the input holds the message in its slots. Drop it to the StC input
            // level (cd (lbDec + 2) towers, as std's EvalBootstrapStCFirst), apply StC (U: slots -> coefficients),
            // ModRaise its output and continue with CtS and EvalMod; no StC after EvalMod. The scalars are those
            // of CtS-first (scaleDec on StC, scaleEnc on CtS): the q0 I overflow only meets scaleEnc, and the
            // message gets scaleDec * scaleEnc before the sine instead of scaleEnc before and scaleDec after it.
            auto dep = ciphertext->Clone();
            const uint32_t expectedLevel = L0 - compositeDegree * (lbDec + 2) - (st == FLEXIBLEAUTOEXT ? 1 : 0);
            if (dep->GetLevel() + compositeDegree * (dep->GetNoiseScaleDeg() - 1) > expectedLevel)
                OPENFHE_THROW("Not enough levels to perform StC-first CI bootstrapping: the input needs " +
                              std::to_string(L0 - expectedLevel) + " towers.");
            algo->ModReduceInternalInPlace(dep, compositeDegree * (dep->GetNoiseScaleDeg() - 1));
            const uint32_t depLevel = dep->GetLevel();
            if (depLevel < expectedLevel) {
                if (st == FIXEDMANUAL || st == FIXEDAUTO) {
                    algo->LevelReduceInternalInPlace(dep, expectedLevel - depLevel);
                }
                else {
                    // as EvalBootstrapStCFirst: one constant multiply + rescale lands on the exact scaling factor
                    // of expectedLevel
                    double scf2      = dep->GetScalingFactor();
                    double scf1      = cryptoParams->GetScalingFactorRealBig(expectedLevel - compositeDegree);
                    double scf       = cryptoParams->GetScalingFactorReal(depLevel);
                    double targetScf = cryptoParams->GetScalingFactorReal(expectedLevel);
                    dep              = cc->EvalMult(dep, scf1 / scf2 / scf);
                    if (depLevel + compositeDegree < expectedLevel)
                        algo->LevelReduceInternalInPlace(dep, expectedLevel - depLevel - compositeDegree);
                    algo->ModReduceInternalInPlace(dep, compositeDegree);
                    dep->SetScalingFactor(targetScf);
                }
            }
            if (useRealFFT) {
                dep = applyReal(dep, GetCIRealLevels(Nn, lbEnc, lbDec).dec, p.m_U0PreFFT, scaleDec, "ci-StC",
                                ciDigits.dec, ciDigits.towersDec);
            }
            else {
                dep = applyCILT(dep, p.m_U0Pre, false, scaleDec);
                rescale1(dep);
            }
#ifdef BOOTSTRAPTIMING
            OPENFHE_DIAGNOSTIC_ERR << "[CI-BT] StC " << ciSec(tStage) << " s (StC-first)\n";
            tStage = ciNow();
#endif
            raised = dep;
            raiseInPlace(raised);
            cc->EvalMultInPlace(raised, pre / N);
        }

        // CoeffsToSlots (U^{-1}).
        algo->ModReduceInternalInPlace(raised, compositeDegree);
        Ciphertext<DCRTPoly> ctxtEnc;
        if (useRealFFT) {
            ctxtEnc = applyReal(raised, GetCIRealLevels(Nn, lbEnc, lbDec).enc, p.m_U0hatTPreFFT, scaleEnc, "ci-CtS",
                                ciDigits.enc, ciDigits.towersEnc);
        }
        else {
            // CtS = scaleEnc * N * U^-1 = scaleEnc * diag(1,.5..) * U^T. With decoded(raised)=U*t/N
            // this gives post-CtS slots = scaleEnc * t (the standard EvalMod input scale, k=1).
            ctxtEnc = applyCILT(raised, p.m_U0hatTPre, true, scaleEnc);
            rescale1(ctxtEnc);
        }

#ifdef BOOTSTRAPTIMING
        OPENFHE_DIAGNOSTIC_ERR << "[CI-BT] CtS " << ciSec(tStage) << " s\n";
        tStage = ciNow();
#endif
        // Approximate modular reduction (reused unchanged): single pass, no real/imag split.
        ctxtEnc = algo->EvalChebyshevSeries(ctxtEnc, coefficients, coeffLowerBound, coeffUpperBound);
        if (st != FIXEDMANUAL)
            algo->ModReduceInternalInPlace(ctxtEnc, compositeDegree);
        uint32_t numIter = (cryptoParams->GetSecretKeyDist() == UNIFORM_TERNARY) ? R_UNIFORM : R_SPARSE;
        ApplyDoubleAngleIterations(ctxtEnc, numIter);
        algo->MultByIntegerInPlace(ctxtEnc, scalar);
        if (st != FIXEDMANUAL && !ciStcFirst)
            algo->ModReduceInternalInPlace(ctxtEnc, compositeDegree);
#ifdef BOOTSTRAPTIMING
        OPENFHE_DIAGNOSTIC_ERR << "[CI-BT] EvalMod " << ciSec(tStage) << " s\n";
        tStage = ciNow();
#endif
        // SlotsToCoeffs (U); StC-first: already applied before the ModRaise.
        Ciphertext<DCRTPoly> ctxtDecCI;
        if (ciStcFirst) {
            ctxtDecCI = ctxtEnc;
        }
        else if (useRealFFT) {
            ctxtDecCI = applyReal(ctxtEnc, GetCIRealLevels(Nn, lbEnc, lbDec).dec, p.m_U0PreFFT, scaleDec, "ci-StC",
                                  ciDigits.dec, ciDigits.towersDec);
        }
        else {
            ctxtDecCI = applyCILT(ctxtEnc, p.m_U0Pre, false, scaleDec);
            rescale1(ctxtDecCI);
        }

#ifdef BOOTSTRAPTIMING
        if (!ciStcFirst)
            OPENFHE_DIAGNOSTIC_ERR << "[CI-BT] StC " << ciSec(tStage) << " s\n";
#endif
        if (useRealFFT) {
            // Keygen/evaluator consistency: the real-FFT Galois keys generated by EvalBootstrapKeyGen must be
            // exactly the rotations performed above (a missing key fails the rotation; an extra key is waste).
            const auto kg = CIRealFFTGaloisElements(Nn, lbEnc, lbDec, ciDigits);
            if (!std::equal(kg.begin(), kg.end(), ciGalUsed.begin(), ciGalUsed.end())) {
                std::set<uint32_t> kgs(kg.begin(), kg.end());
                size_t onlyEval = 0, onlyKeygen = 0;
                for (auto g : ciGalUsed)
                    onlyEval += kgs.count(g) ? 0 : 1;
                for (auto g : kg)
                    onlyKeygen += ciGalUsed.count(g) ? 0 : 1;
                OPENFHE_THROW("CI real-FFT bootstrap: the keygen Galois set (" + std::to_string(kg.size()) +
                              " elements) differs from the evaluator's rotation set (" +
                              std::to_string(ciGalUsed.size()) + "): " + std::to_string(onlyEval) +
                              " used but not generated, " + std::to_string(onlyKeygen) + " generated but unused.");
            }
#ifdef BOOTSTRAPTIMING
            OPENFHE_DIAGNOSTIC_ERR << "[CI-BT] Galois check: " << ciGalUsed.size() << " rotations == keygen set\n";
#endif
        }
#ifdef BOOTSTRAPTIMING
        OPENFHE_DIAGNOSTIC_ERR << "[CI-BT] local diagonal encodes: " << ciLocalEncodes
                               << " levels (0 = all precomputed)\n";
#endif
#if NATIVEINT != 128
        uint64_t corFactor = static_cast<uint64_t>(1) << std::llround(correction);
        algo->MultByIntegerInPlace(ctxtDecCI, corFactor);
#endif
        if (ctxtDecCI->GetElements()[0].GetNumOfElements() <= initSizeQ)
            return ciphertext->Clone();
        return ctxtDecCI;
    }

    Ciphertext<DCRTPoly> ctxtDec;
    if (slots == cc->GetCyclotomicOrder() / 4) {
        //------------------------------------------------------------------------------
        // FULLY PACKED CASE
        //------------------------------------------------------------------------------

#ifdef BOOTSTRAPTIMING
        TIC(t);
#endif

        //------------------------------------------------------------------------------
        // Running CoeffToSlot
        //------------------------------------------------------------------------------

        // need to call internal modular reduction so it also works for FLEXIBLEAUTO
        algo->ModReduceInternalInPlace(raised, compositeDegree);

        // only one linear transform is needed as the other one can be derived
        auto ctxtEnc = (isLTBootstrap) ? EvalLinearTransform(p.m_U0hatTPre, raised) :
                                         EvalCoeffsToSlots(p.m_U0hatTPreFFT, raised);

        auto& evalKeyMap = cc->GetEvalAutomorphismKeyMap(ctxtEnc->GetKeyTag());
        auto conj = Conjugate(ctxtEnc, evalKeyMap);
        auto ctxtEncI = cc->EvalSub(ctxtEnc, conj);
        cc->EvalAddInPlace(ctxtEnc, conj);
        algo->MultByMonomialInPlace(ctxtEncI, 3 * slots);

        if (st == FIXEDMANUAL) {
            while (ctxtEnc->GetNoiseScaleDeg() > 1) {
                cc->ModReduceInPlace(ctxtEnc);
                cc->ModReduceInPlace(ctxtEncI);
            }
        } else {
            if (ctxtEnc->GetNoiseScaleDeg() == 2) {
                algo->ModReduceInternalInPlace(ctxtEnc, compositeDegree);
                algo->ModReduceInternalInPlace(ctxtEncI, compositeDegree);
            }
        }

#ifdef BOOTSTRAPTIMING
        timeEncode = TOC(t);
        OPENFHE_DIAGNOSTIC_ERR << "Encoding time: " << timeEncode / 1000.0 << " s\n";
        // Running Approximate Mod Reduction
        TIC(t);
#endif

        //------------------------------------------------------------------------------
        // Running Approximate Mod Reduction
        //------------------------------------------------------------------------------

        // Evaluate Chebyshev series for the sine wave
        ctxtEnc = algo->EvalChebyshevSeries(ctxtEnc, coefficients, coeffLowerBound, coeffUpperBound);
        ctxtEncI = algo->EvalChebyshevSeries(ctxtEncI, coefficients, coeffLowerBound, coeffUpperBound);

        // Double-angle iterations
        if (st != FIXEDMANUAL) {
            algo->ModReduceInternalInPlace(ctxtEnc, compositeDegree);
            algo->ModReduceInternalInPlace(ctxtEncI, compositeDegree);
        }
        uint32_t numIter;
        if (cryptoParams->GetSecretKeyDist() == UNIFORM_TERNARY)
            numIter = R_UNIFORM;
        else
            numIter = R_SPARSE;
        ApplyDoubleAngleIterations(ctxtEnc, numIter);
        ApplyDoubleAngleIterations(ctxtEncI, numIter);

        algo->MultByMonomialInPlace(ctxtEncI, slots);
        cc->EvalAddInPlaceNoCheck(ctxtEnc, ctxtEncI);

        // scale the message back up after Chebyshev interpolation; for composite scaling this restores
        // the exact power-of-two 2^deg via an integer multiply (the residual ~1 coefficient lives in the
        // StC matrix, see EvalBootstrapSetup)
        algo->MultByIntegerInPlace(ctxtEnc, scalar);

#ifdef BOOTSTRAPTIMING
        timeModReduce = TOC(t);
        OPENFHE_DIAGNOSTIC_ERR << "Approximate modular reduction time: " << timeModReduce / 1000.0 << " s\n";
        // Running SlotToCoeff
        TIC(t);
#endif

        //------------------------------------------------------------------------------
        // Running SlotToCoeff
        //------------------------------------------------------------------------------

        // In the case of FLEXIBLEAUTO, we need one extra tower
        // TODO: See if we can remove the extra level in FLEXIBLEAUTO
        if (st != FIXEDMANUAL)
            algo->ModReduceInternalInPlace(ctxtEnc, compositeDegree);

        // Only one linear transform is needed
        ctxtDec = (isLTBootstrap) ? EvalLinearTransform(p.m_U0Pre, ctxtEnc) : EvalSlotsToCoeffs(p.m_U0PreFFT, ctxtEnc);
    } else {
        //------------------------------------------------------------------------------
        // SPARSELY PACKED CASE
        //------------------------------------------------------------------------------

        //------------------------------------------------------------------------------
        // Running PartialSum
        //------------------------------------------------------------------------------

        EvalPartialSumInPlace(raised, slots);

#ifdef BOOTSTRAPTIMING
        TIC(t);
#endif

        //------------------------------------------------------------------------------
        // Running CoeffsToSlots
        //------------------------------------------------------------------------------

        algo->ModReduceInternalInPlace(raised, compositeDegree);

        auto ctxtEnc = (isLTBootstrap) ? EvalLinearTransform(p.m_U0hatTPre, raised) :
                                         EvalCoeffsToSlots(p.m_U0hatTPreFFT, raised);

        auto& evalKeyMap = cc->GetEvalAutomorphismKeyMap(ctxtEnc->GetKeyTag());
        cc->EvalAddInPlace(ctxtEnc, Conjugate(ctxtEnc, evalKeyMap));

        if (st == FIXEDMANUAL) {
            while (ctxtEnc->GetNoiseScaleDeg() > 1) {
                cc->ModReduceInPlace(ctxtEnc);
            }
        } else {
            if (ctxtEnc->GetNoiseScaleDeg() == 2) {
                algo->ModReduceInternalInPlace(ctxtEnc, compositeDegree);
            }
        }

#ifdef BOOTSTRAPTIMING
        timeEncode = TOC(t);
        OPENFHE_DIAGNOSTIC_ERR << "Encoding time: " << timeEncode / 1000.0 << " s\n";
        // Running Approximate Mod Reduction
        TIC(t);
#endif

        //------------------------------------------------------------------------------
        // Running Approximate Mod Reduction
        //------------------------------------------------------------------------------

        // Evaluate Chebyshev series for the sine wave
        ctxtEnc = algo->EvalChebyshevSeries(ctxtEnc, coefficients, coeffLowerBound, coeffUpperBound);

        // Double-angle iterations
        if (st != FIXEDMANUAL)
            algo->ModReduceInternalInPlace(ctxtEnc, compositeDegree);
        uint32_t numIter = (cryptoParams->GetSecretKeyDist() == UNIFORM_TERNARY) ? R_UNIFORM : R_SPARSE;
        ApplyDoubleAngleIterations(ctxtEnc, numIter);

        // scale the message back up after Chebyshev interpolation; for composite scaling this restores
        // the exact power-of-two 2^deg via an integer multiply (the residual ~1 coefficient lives in the
        // StC matrix, see EvalBootstrapSetup)
        algo->MultByIntegerInPlace(ctxtEnc, scalar);

#ifdef BOOTSTRAPTIMING
        timeModReduce = TOC(t);
        OPENFHE_DIAGNOSTIC_ERR << "Approximate modular reduction time: " << timeModReduce / 1000.0 << " s\n";
        // Running SlotToCoeff
        TIC(t);
#endif

        //------------------------------------------------------------------------------
        // Running SlotsToCoeffs
        //------------------------------------------------------------------------------

        // In the case of FLEXIBLEAUTO, we need one extra tower
        // TODO: See if we can remove the extra level in FLEXIBLEAUTO
        if (st != FIXEDMANUAL)
            algo->ModReduceInternalInPlace(ctxtEnc, compositeDegree);

        // linear transform for decoding
        ctxtDec = (isLTBootstrap) ? EvalLinearTransform(p.m_U0Pre, ctxtEnc) : EvalSlotsToCoeffs(p.m_U0PreFFT, ctxtEnc);
        cc->EvalAddInPlaceNoCheck(ctxtDec, cc->EvalRotate(ctxtDec, slots));
    }

#if NATIVEINT != 128
    // 64-bit only: scale back the message to its original scale.
    uint64_t corFactor = static_cast<uint64_t>(1) << std::llround(correction);
    algo->MultByIntegerInPlace(ctxtDec, corFactor);
#endif

#ifdef BOOTSTRAPTIMING
    timeDecode = TOC(t);
    OPENFHE_DIAGNOSTIC_ERR << "Decoding time: " << timeDecode / 1000.0 << " s\n";
#endif

    // If we start with more towers, than we obtain from bootstrapping, return the original ciphertext.
    if (ctxtDec->GetElements()[0].GetNumOfElements() <= initSizeQ)
        return ciphertext->Clone();
    return ctxtDec;
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalBootstrapStCFirst(ConstCiphertext<DCRTPoly>& ciphertext, uint32_t numIterations,
                                                       uint32_t precision) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    // REAL_CI: the StC-first CI bootstrap is the CI branch of EvalBootstrap; it needs a precomputation (diagonal
    // towers, Galois keys) set up for that ordering.
    if (cryptoParams->GetCKKSDataType() == REAL_CI) {
        if (!GetBootPrecom(ciphertext->GetSlots(), CKKSBootstrapPrecom::BOOTSTRAP).BTSlotsEncoding)
            OPENFHE_THROW(
                "EvalBootstrapStCFirst for REAL_CI needs EvalBootstrapSetup(..., BTSlotsEncoding = true) "
                "(the CtS-first precomputation and keys do not fit the StC-first chain); use EvalBootstrap.");
        return EvalBootstrap(ciphertext, numIterations, precision);
    }

    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW("CKKS Bootstrapping only supported with Hybrid key switching.");

    auto st = cryptoParams->GetScalingTechnique();
#if NATIVEINT == 128
    if (st == FLEXIBLEAUTO || st == FLEXIBLEAUTOEXT)
        OPENFHE_THROW("128-bit CKKS Bootstrapping only supported for FIXEDMANUAL and FIXEDAUTO.");
#endif

    if (numIterations != 1 && numIterations != 2)
        OPENFHE_THROW("CKKS Bootstrapping only supported for 1 or 2 iterations.");

#ifdef BOOTSTRAPTIMING
    TimeVar t;
    double timeEncode(0.0);
    double timeModReduce(0.0);
    double timeDecode(0.0);
#endif

    auto cc = ciphertext->GetCryptoContext();
    uint32_t L0 = cryptoParams->GetElementParams()->GetParams().size();
    auto initSizeQ = ciphertext->GetElements()[0].GetNumOfElements();
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    if (numIterations > 1) {
        // Step 1: Get the input.
        uint32_t powerOfTwoModulus = 1 << precision;

        // Step 3: Bootstrap the initial ciphertext.
        auto ctInitialBootstrap = EvalBootstrapStCFirst(ciphertext, numIterations - 1, 0);
        cc->GetScheme()->ModReduceInternalInPlace(ctInitialBootstrap,
                                                  compositeDegree * (ctInitialBootstrap->GetNoiseScaleDeg() - 1));

        // Step 4: Scale up by powerOfTwoModulus.
        cc->GetScheme()->MultByIntegerInPlace(ctInitialBootstrap, powerOfTwoModulus);

        // // If we start with more towers than we obtain from bootstrapping, return the original ciphertext.
        auto bootstrappingSizeQ = ctInitialBootstrap->GetElements()[0].GetNumOfElements();
        if (bootstrappingSizeQ <= initSizeQ)
            return ciphertext->Clone();

        // Step 2: Scale up by powerOfTwoModulus, and extend the modulus to powerOfTwoModulus * q.
        // Note that we extend the modulus implicitly without any code calls because the value always stays 0.
        auto ctScaledUp = ciphertext->Clone();
        if (st == FIXEDMANUAL) {
            cc->GetScheme()->ModReduceInternalInPlace(ctScaledUp, ctScaledUp->GetNoiseScaleDeg() - 1);
        }
        // We multiply by powerOfTwoModulus, and leave the last CRT value to be 0 (mod powerOfTwoModulus).
        cc->GetScheme()->MultByIntegerInPlace(ctScaledUp, powerOfTwoModulus);

        // Step 5: Mod-down to powerOfTwoModulus * q
        // We mod down, and leave the last CRT value to be 0 because it's divisible by powerOfTwoModulus.
        auto ctBootstrappedScaledDown = ctInitialBootstrap->Clone();

        if (st == FIXEDAUTO) {
            for (auto& cv : ctBootstrappedScaledDown->GetElements())
                cv.DropLastElements(bootstrappingSizeQ - initSizeQ);
            ctBootstrappedScaledDown->SetLevel(L0 - ctBootstrappedScaledDown->GetElements()[0].GetNumOfElements());
        }

        // Step 6 and 7: Calculate the bootstrapping error by subtracting the original ciphertext from the bootstrapped ciphertext. Mod down to q is done implicitly.
        auto ctBootstrappingError = cc->EvalSub(ctBootstrappedScaledDown, ctScaledUp);

        // Step 8: Bootstrap the error.
        auto ctBootstrappedError = EvalBootstrapStCFirst(ctBootstrappingError, 1, 0);
        cc->GetScheme()->ModReduceInternalInPlace(ctBootstrappedError,
                                                  compositeDegree * (ctBootstrappedError->GetNoiseScaleDeg() - 1));

        // Step 9: Subtract the bootstrapped error from the initial bootstrap to get even lower error.
        auto finalCiphertext = cc->EvalSub(ctInitialBootstrap, ctBootstrappedError);

        // Step 10: Scale back down by powerOfTwoModulus to get the original message.
        cc->EvalMultInPlace(finalCiphertext, 1.0 / powerOfTwoModulus);

        return finalCiphertext;
    }

    uint32_t slots = ciphertext->GetSlots();
    auto elementParamsRaised = *(cryptoParams->GetElementParams());
    // For FLEXIBLEAUTOEXT we raised ciphertext does not include extra modulus
    // as it is multiplied by auxiliary plaintext
    if (st == FLEXIBLEAUTOEXT)
        elementParamsRaised.PopLastParam();

    const auto& paramsQ = elementParamsRaised.GetParams();
    uint32_t sizeQ = paramsQ.size();
    std::vector<NativeInteger> moduli(sizeQ);
    std::vector<NativeInteger> roots(sizeQ);
    for (uint32_t i = 0; i < sizeQ; ++i) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i] = paramsQ[i]->GetRootOfUnity();
    }
    auto elementParamsRaisedPtr =
            std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(cc->GetCyclotomicOrder(), moduli, roots);
    elementParamsRaisedPtr->SetRingType(paramsQ[0]->GetRingType());

    double qDouble = GetBigModulus(cryptoParams);
    double powP = std::pow(2, cryptoParams->GetPlaintextModulus());
    int32_t deg = std::round(std::log2(qDouble / powP));
#if NATIVEINT != 128
    if (deg > static_cast<int32_t>(m_correctionFactor) && st != COMPOSITESCALINGAUTO && st != COMPOSITESCALINGMANUAL) {
        OPENFHE_THROW("Degree [" + std::to_string(deg) + "] must be less than or equal to the correction factor [" +
                      std::to_string(m_correctionFactor) + "].");
    }
#endif
    // For composite scaling, deg may exceed the correction factor (the check above is skipped, since with
    // larger composite degrees the first modulus is typically much larger than the scaling factor); in that
    // case no correction is applied instead of letting the unsigned subtraction wrap around.
    uint32_t correction = (deg < static_cast<int32_t>(m_correctionFactor)) ? m_correctionFactor - deg : 0;
    double post = std::pow(2, static_cast<double>(deg));

    // For FLEXIBLE* the exact power-of-two 1/post is applied here as the shrink before CoeffsToSlots and
    // restored by the integer "scalar" after the sine. For composite scaling the entire overflow
    // normalization (the exact 2^-deg = 1/post AND the residual c1) is carried by the CoeffsToSlots/
    // SlotsToCoeffs matrix coefficients (see EvalBootstrapSetup), so no shrink is applied here; this
    // keeps the CtS rotations on the full-magnitude message and avoids amplifying their noise by 2^deg.
    double pre = (compositeDegree > 1) ? 1.0 : 1. / post;
    uint64_t scalar = std::llround(post);

    //------------------------------------------------------------------------------
    // SETTING PARAMETERS FOR APPROXIMATE MODULAR REDUCTION
    //------------------------------------------------------------------------------

    auto algo = cc->GetScheme();
    auto N = cc->GetRingDimension();
    auto& p = GetBootPrecom(slots, CKKSBootstrapPrecom::BOOTSTRAP);

    // Coefficients of the Chebyshev series interpolating 1/(2 Pi) Sin(2 Pi K x). The overflow bound K
    // itself is folded into the CoeffsToSlots matrix (see GetModRaiseOverflowBound), so only the exact 1/N
    // normalization is applied here.
    std::vector<double> coefficients;

    if (cryptoParams->GetSecretKeyDist() == SPARSE_TERNARY) {
        coefficients = g_coefficientsSparse;
    } else if (cryptoParams->GetSecretKeyDist() == SPARSE_ENCAPSULATED) {
        // K = 28 (the SPARSE_TERNARY table) for the denser sparse secret (Hamming weight 64: first modulus above
        // 60 bits), K = 16 otherwise
        coefficients = (cryptoParams->GetSparseKSHammingWeight() > 32) ? g_coefficientsSparse :
                                                                         g_coefficientsSparseEncapsulated;
    } else {
        coefficients = g_coefficientsUniform;
    }

    // no linear transformations are needed for Chebyshev series as the range has been normalized to [-1,1]
    double coeffLowerBound = -1.0;
    double coeffUpperBound = 1.0;

    bool isLTBootstrap = (p.m_paramsEnc.lvlb == 1) && (p.m_paramsDec.lvlb == 1);

    //------------------------------------------------------------------------------
    // Dropping Unnecessary Towers
    //------------------------------------------------------------------------------
    // Only work with the minimum number of required levels.
    auto ctxtDepleted = ciphertext->Clone();

    // The SlotsToCoeffs matrix is encoded for an input with compositeDegree * (lvlb + 2) towers
    // remaining (lDec in EvalBootstrapSetup), so each level below costs compositeDegree towers.
    // FLEXIBLEAUTOEXT (one extra tower) and composite scaling are mutually exclusive.
    auto expectedLevel = L0 - compositeDegree * (p.m_paramsDec.lvlb + 2) - (st == FLEXIBLEAUTOEXT);

    if (ctxtDepleted->GetLevel() + compositeDegree * (ctxtDepleted->GetNoiseScaleDeg() - 1) > expectedLevel) {
        OPENFHE_THROW("Not enough levels to perform Bootstrapping.");
    }

    algo->ModReduceInternalInPlace(ctxtDepleted, compositeDegree * (ctxtDepleted->GetNoiseScaleDeg() - 1));
    auto ctxtLevel = ctxtDepleted->GetLevel();

    if (st == FIXEDMANUAL || st == FIXEDAUTO) {
        if (ctxtDepleted->GetLevel() < expectedLevel) {
            cc->GetScheme()->LevelReduceInternalInPlace(ctxtDepleted, expectedLevel - ctxtDepleted->GetLevel());
        }
    } else {
        if (ctxtLevel < expectedLevel) {
            // Bring the (noise degree 1) ciphertext down to expectedLevel with the exact scaling factor of
            // that level, using the same maneuver as AdjustLevelsAndDepthInPlace: multiply by a constant
            // (encoded at the scaling factor of the current level) so that one rescaling by the moduli of
            // the target level lands exactly on GetScalingFactorReal(expectedLevel). Mixing up the current
            // and target levels here is harmless for FLEXIBLEAUTO (its per-level scaling factors agree to
            // ~2^-30) but costs ~15 bits for composite scaling, whose per-level products of small primes
            // deviate from each other much more.
            double scf2 = ctxtDepleted->GetScalingFactor();
            double scf1 = cryptoParams->GetScalingFactorRealBig(expectedLevel - compositeDegree);
            double scf = cryptoParams->GetScalingFactorReal(ctxtLevel);
            double targetScf = cryptoParams->GetScalingFactorReal(expectedLevel);
            ctxtDepleted = cc->EvalMult(ctxtDepleted, scf1 / scf2 / scf);
            if (ctxtLevel + compositeDegree < expectedLevel) {
                cc->GetScheme()->LevelReduceInternalInPlace(ctxtDepleted, expectedLevel - ctxtLevel - compositeDegree);
            }
            algo->ModReduceInternalInPlace(ctxtDepleted, compositeDegree);
            ctxtDepleted->SetScalingFactor(targetScf);
        }
    }

    Ciphertext<DCRTPoly> ctxtEnc;
#ifdef BOOTSTRAPTIMING
    TIC(t);
#endif

    //------------------------------------------------------------------------------
    // Running SlotToCoeff
    //------------------------------------------------------------------------------

    // Linear transform for decoding
    ctxtDepleted = (isLTBootstrap) ? EvalLinearTransform(p.m_U0Pre, ctxtDepleted) :
                                     EvalSlotsToCoeffs(p.m_U0PreFFT, ctxtDepleted);

    if (slots != N / 2 && cc->GetCKKSDataType() == REAL) {
        //------------------------------------------------------------------------------
        // SPARSELY PACKED CASE
        //------------------------------------------------------------------------------
        cc->EvalAddInPlaceNoCheck(ctxtDepleted, cc->EvalRotate(ctxtDepleted, slots));
    }

#ifdef BOOTSTRAPTIMING
    timeDecode = TOC(t);
    OPENFHE_DIAGNOSTIC_ERR << "Decoding time: " << timeDecode / 1000.0 << " s\n";
#endif

    //------------------------------------------------------------------------------
    // RAISING THE MODULUS
    //------------------------------------------------------------------------------

    // In FLEXIBLEAUTO, raising the ciphertext to a larger number
    // of towers is a bit more complex, because we need to adjust
    // it's scaling factor to the one that corresponds to the level
    // it's being raised to.
    // Increasing the modulus

    auto raised = ctxtDepleted->Clone();
    algo->ModReduceInternalInPlace(raised, compositeDegree * (raised->GetNoiseScaleDeg() - 1));
    uint32_t lvl = cryptoParams->GetScalingTechnique() != FLEXIBLEAUTOEXT ? 0 : 1;
    AdjustCiphertext(raised, std::pow(2, -static_cast<int32_t>(correction)), lvl);

    ModRaiseInPlace(raised, elementParamsRaisedPtr);

#ifdef BOOTSTRAPTIMING
    auto numTowers = raised->GetElements()[0].GetNumOfElements() - 1;
    OPENFHE_DIAGNOSTIC_ERR << "\nNumber of levels after mod raise: " << numTowers << "\n";
#endif
    double normalization = pre / N;
    // Scaling adjustment before Coefficient to Slots
    cc->EvalMultInPlace(raised, normalization);

    if (slots != N / 2) {
        //------------------------------------------------------------------------------
        // SPARSELY PACKED CASE
        //------------------------------------------------------------------------------
        //------------------------------------------------------------------------------
        // Running PartialSum
        //------------------------------------------------------------------------------

        EvalPartialSumInPlace(raised, slots);
    }

#ifdef BOOTSTRAPTIMING
    TIC(t);
#endif

    //------------------------------------------------------------------------------
    // Running CoeffsToSlots
    //------------------------------------------------------------------------------

    algo->ModReduceInternalInPlace(raised, compositeDegree);

    ctxtEnc =
            (isLTBootstrap) ? EvalLinearTransform(p.m_U0hatTPre, raised) : EvalCoeffsToSlots(p.m_U0hatTPreFFT, raised);

    auto& evalKeyMap = cc->GetEvalAutomorphismKeyMap(ctxtEnc->GetKeyTag());
    auto conj = Conjugate(ctxtEnc, evalKeyMap);
    Ciphertext<DCRTPoly> ctxtEncI;
    if (cc->GetCKKSDataType() == COMPLEX) {
        ctxtEncI = cc->EvalSub(ctxtEnc, conj);
        algo->MultByMonomialInPlace(ctxtEncI, 3 * N / 2);
    }
    cc->EvalAddInPlace(ctxtEnc, conj);

    if (st == FIXEDMANUAL) {
        while (ctxtEnc->GetNoiseScaleDeg() > 1) {
            cc->ModReduceInPlace(ctxtEnc);
            if (cc->GetCKKSDataType() == COMPLEX)
                cc->ModReduceInPlace(ctxtEncI);
        }
    } else {
        if (ctxtEnc->GetNoiseScaleDeg() == 2) {
            algo->ModReduceInternalInPlace(ctxtEnc, compositeDegree);
            if (cc->GetCKKSDataType() == COMPLEX)
                algo->ModReduceInternalInPlace(ctxtEncI, compositeDegree);
        }
    }

#ifdef BOOTSTRAPTIMING
    timeEncode = TOC(t);
    OPENFHE_DIAGNOSTIC_ERR << "Encoding time: " << timeEncode / 1000.0 << " s\n";
    // Running Approximate Mod Reduction
    TIC(t);
#endif

    //------------------------------------------------------------------------------
    // Running Approximate Mod Reduction
    //------------------------------------------------------------------------------

    // Evaluate Chebyshev series for the sine wave
    ctxtEnc = algo->EvalChebyshevSeries(ctxtEnc, coefficients, coeffLowerBound, coeffUpperBound);
    // AA: Note that for sparse complex, we currently evaluate the polynomial over two ciphertexts.
    // This can be optimized to a single ciphertext (without additional consumed levels) if the last
    // multiplication of the EvalChebyshevSeries separates the real and imaginary parts and is
    // combined with a multiplicative masking.
    if (cc->GetCKKSDataType() == COMPLEX)
        ctxtEncI = algo->EvalChebyshevSeries(ctxtEncI, coefficients, coeffLowerBound, coeffUpperBound);

    // Double-angle iterations
    if (st != FIXEDMANUAL) {
        algo->ModReduceInternalInPlace(ctxtEnc, compositeDegree * (ctxtEnc->GetNoiseScaleDeg() - 1));
        if (cc->GetCKKSDataType() == COMPLEX)
            algo->ModReduceInternalInPlace(ctxtEncI, compositeDegree);
    }
    uint32_t numIter = (cryptoParams->GetSecretKeyDist() == UNIFORM_TERNARY) ? R_UNIFORM : R_SPARSE;
    ApplyDoubleAngleIterations(ctxtEnc, numIter);

    if (cc->GetCKKSDataType() == COMPLEX) {
        ApplyDoubleAngleIterations(ctxtEncI, numIter);
        algo->MultByMonomialInPlace(ctxtEncI, N / 2);
        cc->EvalAddInPlaceNoCheck(ctxtEnc, ctxtEncI);
    }

    // scale the message back up after Chebyshev interpolation; for composite scaling this restores
    // the exact power-of-two 2^deg via an integer multiply (the residual ~1 coefficient lives in the
    // StC matrix, see EvalBootstrapSetup)
    algo->MultByIntegerInPlace(ctxtEnc, scalar);

#ifdef BOOTSTRAPTIMING
    timeModReduce = TOC(t);
    OPENFHE_DIAGNOSTIC_ERR << "Approximate modular reduction time: " << timeModReduce / 1000.0 << " s\n";
#endif

#if NATIVEINT != 128
    // 64-bit only: scale back the message to its original scale.
    uint64_t corFactor = static_cast<uint64_t>(1) << std::llround(correction);
    algo->MultByIntegerInPlace(ctxtEnc, corFactor);
#endif

    // If we start with more towers, than we obtain from bootstrapping, return the original ciphertext.
    if (ctxtEnc->GetElements()[0].GetNumOfElements() <= initSizeQ)
        return ciphertext->Clone();

    return ctxtEnc;
}

void FHECKKSRNS::EvalFEFuncBootstrapSetup(const CryptoContextImpl<DCRTPoly>& cc,
                                          const std::vector<uint32_t>& levelBudget, const std::vector<uint32_t>& dim1,
                                          uint32_t numSlots) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW("CKKS FE functional bootstrapping is only supported for the Hybrid key switching method.");
#if NATIVEINT == 128
    OPENFHE_THROW("128-bit CKKS FE functional bootstrapping is not supported.");
#endif
    // FE functional bootstrapping runs the StC-first pipeline, which has no conjugate-invariant branch.
    if (cc.GetCKKSDataType() == REAL_CI)
        OPENFHE_THROW("CKKS FE functional bootstrapping is not supported for the REAL_CI data type.");

    uint32_t M = cc.GetCyclotomicOrder();
    uint32_t slots = (numSlots == 0) ? M / 4 : numSlots;

    m_bootPrecomMap[slots] = std::make_shared<CKKSBootstrapPrecom>();
    auto& precom = m_bootPrecomMap[slots];
    precom->m_slots = slots;
    precom->BTSlotsEncoding = true;
    precom->m_variant = CKKSBootstrapPrecom::FEFBT;

    // even for the case of a single slot we need one level for rescaling
    uint32_t logSlots = (slots < 3) ? 1 : std::log2(slots);

    // Perform some checks on the level budget and compute parameters
    uint32_t newBudget0 = levelBudget[0];
    if (newBudget0 > logSlots) {
        OPENFHE_DIAGNOSTIC_ERR << "\nWarning, level budget for encoding too large. Setting it to " << logSlots << "\n";
        newBudget0 = logSlots;
    }
    if (newBudget0 < 1) {
        OPENFHE_DIAGNOSTIC_ERR << "\nWarning, level budget for encoding can not be zero. Setting it to 1\n";
        newBudget0 = 1;
    }
    uint32_t newBudget1 = levelBudget[1];
    if (newBudget1 > logSlots) {
        OPENFHE_DIAGNOSTIC_ERR << "\nWarning, level budget for decoding too large. Setting it to " << logSlots << "\n";
        newBudget1 = logSlots;
    }
    if (newBudget1 < 1) {
        OPENFHE_DIAGNOSTIC_ERR << "\nWarning, level budget for decoding can not be zero. Setting it to 1\n";
        newBudget1 = 1;
    }

    precom->m_paramsEnc = GetCollapsedFFTParams(slots, newBudget0, dim1[0]);
    precom->m_paramsDec = GetCollapsedFFTParams(slots, newBudget1, dim1[1]);

    uint32_t m = 4 * slots;
    uint32_t mmask = m - 1;  // assumes m is power of 2
    bool isSparse = (M != m);

    // computes indices for all primitive roots of unity
    std::vector<uint32_t> rotGroup(slots);
    uint32_t fivePows = 1;
    for (uint32_t i = 0; i < slots; ++i) {
        rotGroup[i] = fivePows;
        fivePows *= 5;
        fivePows &= mmask;
    }

    // computes all powers of a primitive root of unity exp(2 * M_PI/m)
    std::vector<std::complex<double>> ksiPows(m + 1);
    double ak = 2 * M_PI / m;
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(2))
    for (uint32_t j = 0; j < m; ++j) {
        double angle = ak * j;
        ksiPows[j].real(std::cos(angle));
        ksiPows[j].imag(std::sin(angle));
    }
    ksiPows[m] = ksiPows[0];

    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    // K must match the range of the complex-exponential Chebyshev table selected in EvalFEFuncBootstrap;
    // K_UNIFORM_FEFBT covers all composite degrees and ring dimensions, as in regular bootstrapping
    double k = GetModRaiseOverflowBound(cryptoParams, K_UNIFORM_FEFBT);

    double qDouble = GetBigModulus(cryptoParams);
    double factor = std::ldexp(1.0, static_cast<int>(std::round(std::log2(qDouble))));
    // Same folding as EvalBootstrapSetup: for composite scaling the (inexact) overflow normalization
    // SF0*post/qDouble is captured as a coefficient close to 1 that the CoeffsToSlots/SlotsToCoeffs
    // matrices encode at full precision and telescope away, and the exact power-of-two shrink 1/post is
    // folded into the CoeffsToSlots matrix so the CtS rotations act on the full-magnitude message.
    // Unlike regular bootstrapping, nothing is restored after the approximate evaluation: the 2^-deg
    // shrink (deg = 1, enforced in EvalFEFuncBootstrap) is exactly the half-period embedding of the
    // message into the argument of the Fourier series.
    double pre;
    double post = 1.0;
    if (compositeDegree > 1) {
        double powP = std::pow(2, cryptoParams->GetPlaintextModulus());
        post = std::pow(2, std::round(std::log2(qDouble / powP)));
        pre = cryptoParams->GetScalingFactorReal(0) * post / qDouble;
    } else {
        pre = qDouble / factor;
    }
    double scaleEnc = ((compositeDegree > 1) ? pre / post : pre) / k;
    double scaleDec = 1.0 / pre;

    // compute # of levels to remain when encoding the coefficients
    // for FLEXIBLEAUTOEXT we do not need extra modulus in auxiliary plaintexts
    auto st = cryptoParams->GetScalingTechnique();
    uint32_t L0 = cryptoParams->GetElementParams()->GetParams().size() - (st == FLEXIBLEAUTOEXT);

    uint32_t lEnc = L0 - compositeDegree * (precom->m_paramsEnc.lvlb + 1);
    uint32_t lDec = (2 + (st == FLEXIBLEAUTOEXT)) * compositeDegree;

    bool isLTBootstrap = (precom->m_paramsEnc.lvlb == 1) && (precom->m_paramsDec.lvlb == 1);

    if (isLTBootstrap) {
        if (isSparse) {
            std::vector<std::vector<std::complex<double>>> U0(slots, std::vector<std::complex<double>>(slots));
            std::vector<std::vector<std::complex<double>>> U0hatT(slots, std::vector<std::complex<double>>(slots));
            std::vector<std::vector<std::complex<double>>> U1(slots, std::vector<std::complex<double>>(slots));
            std::vector<std::vector<std::complex<double>>> U1hatT(slots, std::vector<std::complex<double>>(slots));
            for (uint32_t i = 0; i < slots; ++i) {
                for (uint32_t j = 0; j < slots; ++j) {
                    U0[i][j] = ksiPows[(j * rotGroup[i]) & mmask];
                    U0hatT[j][i] = std::conj(U0[i][j]);
                    U1[i][j] = std::complex<double>(0, 1) * U0[i][j];
                    U1hatT[j][i] = std::conj(U1[i][j]);
                }
            }
            if (cc.GetCKKSDataType() == REAL) {
                precom->m_U0Pre = EvalLinearTransformPrecompute(cc, U0, U1, 1, scaleDec, lDec);
                precom->m_U0hatTPre = EvalLinearTransformPrecompute(cc, U0hatT, U1hatT, 0, scaleEnc, lEnc);
            } else {
                precom->m_U0Pre = EvalLinearTransformPrecompute(cc, U0, scaleDec, lDec);
                precom->m_U0hatTPre = EvalLinearTransformPrecompute(cc, U0hatT, scaleEnc, lEnc);
            }
        } else {
            std::vector<std::vector<std::complex<double>>> U0(slots, std::vector<std::complex<double>>(slots));
            std::vector<std::vector<std::complex<double>>> U0hatT(slots, std::vector<std::complex<double>>(slots));
            for (uint32_t i = 0; i < slots; ++i) {
                for (uint32_t j = 0; j < slots; ++j) {
                    U0[i][j] = ksiPows[(j * rotGroup[i]) & mmask];
                    U0hatT[j][i] = std::conj(U0[i][j]);
                }
            }
            precom->m_U0Pre = EvalLinearTransformPrecompute(cc, U0, scaleDec, lDec);
            precom->m_U0hatTPre = EvalLinearTransformPrecompute(cc, U0hatT, scaleEnc, lEnc);
        }
    } else {
        bool flagPack = !(cc.GetCKKSDataType() == REAL);
        precom->m_U0PreFFT = EvalSlotsToCoeffsPrecompute(cc, ksiPows, rotGroup, false, scaleDec, lDec, flagPack);
        precom->m_U0hatTPreFFT = EvalCoeffsToSlotsPrecompute(cc, ksiPows, rotGroup, false, scaleEnc, lEnc, flagPack);
    }
}

// Everything in FE functional bootstrapping that does not depend on the target function: SlotsToCoeffs,
// modulus raise, CoeffsToSlots, and the complex exponential. The result encrypts exp(2*Pi*i*t) with
// t = mu/2 the message embedded into half of the Fourier series period, which is the variable that every
// target function's series is then evaluated at.
Ciphertext<DCRTPoly> FHECKKSRNS::EvalFEFuncBootstrapExp(ConstCiphertext<DCRTPoly>& ciphertext) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW("CKKS FE functional bootstrapping is only supported for the Hybrid key switching method.");
#if NATIVEINT == 128
    OPENFHE_THROW("128-bit CKKS FE functional bootstrapping is not supported.");
#endif

#ifdef BOOTSTRAPTIMING
    TimeVar t;
    double timeStC(0.0);
    double timeCtS(0.0);
    double timeExp(0.0);
#endif

    auto cc = ciphertext->GetCryptoContext();
    auto algo = cc->GetScheme();
    uint32_t N = cc->GetRingDimension();
    uint32_t L0 = cryptoParams->GetElementParams()->GetParams().size();
    uint32_t slots = ciphertext->GetSlots();
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();
    auto st = cryptoParams->GetScalingTechnique();
    auto skd = cryptoParams->GetSecretKeyDist();

    auto& p = GetBootPrecom(slots, CKKSBootstrapPrecom::FEFBT);
    bool isLTBootstrap = (p.m_paramsEnc.lvlb == 1) && (p.m_paramsDec.lvlb == 1);

    auto elementParamsRaised = *(cryptoParams->GetElementParams());
    // For FLEXIBLEAUTOEXT the raised ciphertext does not include the extra modulus
    // as it is multiplied by auxiliary plaintext
    if (st == FLEXIBLEAUTOEXT)
        elementParamsRaised.PopLastParam();

    const auto& paramsQ = elementParamsRaised.GetParams();
    uint32_t sizeQ = paramsQ.size();
    std::vector<NativeInteger> moduli(sizeQ);
    std::vector<NativeInteger> roots(sizeQ);
    for (uint32_t i = 0; i < sizeQ; ++i) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i] = paramsQ[i]->GetRootOfUnity();
    }
    auto elementParamsRaisedPtr =
            std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(cc->GetCyclotomicOrder(), moduli, roots);
    elementParamsRaisedPtr->SetRingType(paramsQ[0]->GetRingType());

    // The Fourier series argument is the message embedded into half of its [-1/2, 1/2) period (t = mu/2),
    // realized by the exact 2^-deg shrink with deg = 1. Unlike regular bootstrapping, the shrink cannot
    // be restored after the approximate evaluation (it determines the argument of the complex
    // exponential), so deg must be exactly 1 and no correction factor is applied.
    double qDouble = GetBigModulus(cryptoParams);
    double powP = std::pow(2, cryptoParams->GetPlaintextModulus());
    int32_t deg = std::round(std::log2(qDouble / powP));
    if (deg != 1)
        OPENFHE_THROW(
                "CKKS FE functional bootstrapping requires the first level modulus to be twice the scaling "
                "factor (FirstModSize = ScalingModSize + 1); log2(q0/SF) = " +
                std::to_string(deg) + ".");
    // For composite scaling the shrink is folded into the CoeffsToSlots matrix (see EvalFEFuncBootstrapSetup)
    double pre = (compositeDegree > 1) ? 1.0 : std::pow(2, -deg);

    // complex-exponential Chebyshev table matching the K folded into the CoeffsToSlots matrix at setup; the K = 28
    // table of SPARSE_TERNARY is also used for SPARSE_ENCAPSULATED with the denser sparse secret (Hamming weight 64)
    const bool smallSparseKey = (skd == SPARSE_ENCAPSULATED) && (cryptoParams->GetSparseKSHammingWeight() == 32);
    const auto& coeffExp = (skd == UNIFORM_TERNARY) ? coeff_exp_696_double_27 :
                           smallSparseKey           ? coeff_exp_16_double_23 :
                                                      coeff_exp_28_double_48;
    const uint32_t rFunc = (skd == UNIFORM_TERNARY) ? R_func_696_double_27 :
                           smallSparseKey           ? R_func_16_double_23 :
                                                      R_func_28_double_48;

    //------------------------------------------------------------------------------
    // Dropping Unnecessary Towers
    //------------------------------------------------------------------------------
    // Only work with the minimum number of required levels.
    auto ctxtDepleted = ciphertext->Clone();

    // The SlotsToCoeffs matrix is encoded for an input with compositeDegree * (lvlb + 2) towers
    // remaining (lDec in EvalFEFuncBootstrapSetup), so each level below costs compositeDegree towers.
    // FLEXIBLEAUTOEXT (one extra tower) and composite scaling are mutually exclusive.
    auto expectedLevel = L0 - compositeDegree * (p.m_paramsDec.lvlb + 2) - (st == FLEXIBLEAUTOEXT);

    if (ctxtDepleted->GetLevel() + compositeDegree * (ctxtDepleted->GetNoiseScaleDeg() - 1) > expectedLevel) {
        OPENFHE_THROW("Not enough levels to perform FE functional bootstrapping.");
    }

    algo->ModReduceInternalInPlace(ctxtDepleted, compositeDegree * (ctxtDepleted->GetNoiseScaleDeg() - 1));
    auto ctxtLevel = ctxtDepleted->GetLevel();

    if (st == FIXEDMANUAL || st == FIXEDAUTO) {
        if (ctxtDepleted->GetLevel() < expectedLevel) {
            cc->GetScheme()->LevelReduceInternalInPlace(ctxtDepleted, expectedLevel - ctxtDepleted->GetLevel());
        }
    } else {
        if (ctxtLevel < expectedLevel) {
            // Bring the (noise degree 1) ciphertext down to expectedLevel with the exact scaling factor of
            // that level, using the same maneuver as AdjustLevelsAndDepthInPlace (see EvalBootstrapStCFirst).
            double scf2 = ctxtDepleted->GetScalingFactor();
            double scf1 = cryptoParams->GetScalingFactorRealBig(expectedLevel - compositeDegree);
            double scf = cryptoParams->GetScalingFactorReal(ctxtLevel);
            double targetScf = cryptoParams->GetScalingFactorReal(expectedLevel);
            ctxtDepleted = cc->EvalMult(ctxtDepleted, scf1 / scf2 / scf);
            if (ctxtLevel + compositeDegree < expectedLevel) {
                cc->GetScheme()->LevelReduceInternalInPlace(ctxtDepleted, expectedLevel - ctxtLevel - compositeDegree);
            }
            algo->ModReduceInternalInPlace(ctxtDepleted, compositeDegree);
            ctxtDepleted->SetScalingFactor(targetScf);
        }
    }

#ifdef BOOTSTRAPTIMING
    TIC(t);
#endif

    //------------------------------------------------------------------------------
    // Running SlotsToCoeffs
    //------------------------------------------------------------------------------

    // Linear transform for decoding
    ctxtDepleted = (isLTBootstrap) ? EvalLinearTransform(p.m_U0Pre, ctxtDepleted) :
                                     EvalSlotsToCoeffs(p.m_U0PreFFT, ctxtDepleted);

    if (slots != N / 2 && cc->GetCKKSDataType() == REAL) {
        //------------------------------------------------------------------------------
        // SPARSELY PACKED CASE
        //------------------------------------------------------------------------------
        cc->EvalAddInPlaceNoCheck(ctxtDepleted, cc->EvalRotate(ctxtDepleted, slots));
    }

#ifdef BOOTSTRAPTIMING
    timeStC = TOC(t);
    OPENFHE_DIAGNOSTIC_ERR << "\nSlotsToCoeffs time: " << timeStC / 1000.0 << " s\n";
    TIC(t);
#endif

    //------------------------------------------------------------------------------
    // RAISING THE MODULUS
    //------------------------------------------------------------------------------

    auto raised = ctxtDepleted;
    algo->ModReduceInternalInPlace(raised, compositeDegree * (raised->GetNoiseScaleDeg() - 1));
    uint32_t lvl = (st != FLEXIBLEAUTOEXT) ? 0 : 1;
    // correction factor 1: the argument of the complex exponential must stay at the exact message scale
    AdjustCiphertext(raised, 1.0, lvl);

    ModRaiseInPlace(raised, elementParamsRaisedPtr);

    // Scaling adjustment before CoeffsToSlots: K is folded into the CoeffsToSlots matrix for every secret
    // distribution (see EvalFEFuncBootstrapSetup), so the runtime normalization is the exact power of two 2^-deg/N
    double normalization = pre / N;
    cc->EvalMultInPlace(raised, normalization);

    if (slots != N / 2) {
        //------------------------------------------------------------------------------
        // SPARSELY PACKED CASE: Running PartialSum
        //------------------------------------------------------------------------------
        EvalPartialSumInPlace(raised, slots);
    }

    //------------------------------------------------------------------------------
    // Running CoeffsToSlots
    //------------------------------------------------------------------------------

    algo->ModReduceInternalInPlace(raised, compositeDegree);

    auto ctxtEnc =
            (isLTBootstrap) ? EvalLinearTransform(p.m_U0hatTPre, raised) : EvalCoeffsToSlots(p.m_U0hatTPreFFT, raised);

    // Keep only the real channel: for CKKSDataType REAL the encoding matrices pack both coefficient halves
    // into it (flagPack is false in EvalFEFuncBootstrapSetup), and for COMPLEX the imaginary half of the
    // message is dropped, the Fourier series result being real-valued either way.
    auto& evalKeyMap = cc->GetEvalAutomorphismKeyMap(ctxtEnc->GetKeyTag());
    auto conj = Conjugate(ctxtEnc, evalKeyMap);
    cc->EvalAddInPlace(ctxtEnc, conj);

    if (st == FIXEDMANUAL) {
        while (ctxtEnc->GetNoiseScaleDeg() > 1) {
            cc->ModReduceInPlace(ctxtEnc);
        }
    } else {
        if (ctxtEnc->GetNoiseScaleDeg() == 2) {
            algo->ModReduceInternalInPlace(ctxtEnc, compositeDegree);
        }
    }

#ifdef BOOTSTRAPTIMING
    timeCtS = TOC(t);
    OPENFHE_DIAGNOSTIC_ERR << "CoeffsToSlots time: " << timeCtS / 1000.0 << " s\n";
    TIC(t);
#endif

    //------------------------------------------------------------------------------
    // Running the Complex Exponential Evaluation
    //------------------------------------------------------------------------------

    auto ctxtExp = algo->EvalChebyshevSeries(ctxtEnc, coeffExp, -1, 1);
    // double-angle iterations for the complex exponential: each squaring doubles the argument
    for (uint32_t i = 0; i < rFunc; ++i) {
        cc->EvalSquareInPlace(ctxtExp);
        cc->ModReduceInPlace(ctxtExp);
    }

#ifdef BOOTSTRAPTIMING
    timeExp = TOC(t);
    OPENFHE_DIAGNOSTIC_ERR << "EvalExp time: " << timeExp / 1000.0 << " s\n";
#endif

    return ctxtExp;
}

// Twice the real part of an evaluated Fourier series, which is the FE functional bootstrapping output
//   f(t) = 2*Re(c_0 + sum_{j>=1} c_j z^j).
// The constant term c_0 stays in the polynomial handed to EvalPoly, which applies it as a single plaintext
// addition after the Paterson-Stockmeyer tree, and the conjugate-add doubles its real part along with the
// rest of the series.
Ciphertext<DCRTPoly> FHECKKSRNS::TwiceRealPart(const Ciphertext<DCRTPoly>& ctxtSeries) {
    auto cc = ctxtSeries->GetCryptoContext();
    return cc->EvalAdd(ctxtSeries, Conjugate(ctxtSeries, cc->GetEvalAutomorphismKeyMap(ctxtSeries->GetKeyTag())));
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalFEFuncBootstrap(ConstCiphertext<DCRTPoly>& ciphertext,
                                                     const std::vector<std::complex<double>>& coefficients) const {
    auto ctxtExp = EvalFEFuncBootstrapExp(ciphertext);
    auto algo = ctxtExp->GetCryptoContext()->GetScheme();

#ifdef BOOTSTRAPTIMING
    TimeVar t;
    double timeSeries(0.0);
    TIC(t);
#endif

    auto result = TwiceRealPart(algo->EvalPoly(ctxtExp, coefficients));

#ifdef BOOTSTRAPTIMING
    timeSeries = TOC(t);
    OPENFHE_DIAGNOSTIC_ERR << "EvalSeries time: " << timeSeries / 1000.0 << " s\n";
#endif

    return result;
}

std::shared_ptr<seriesPowers<DCRTPoly>> FHECKKSRNS::EvalFEFuncBootstrapPrecompute(
        ConstCiphertext<DCRTPoly>& ciphertext, const std::vector<std::complex<double>>& coefficients) const {
    // Below degree 5 EvalPowers builds only those powers the given coefficient vector actually needs and
    // leaves the rest of the basis unset, so the result is specific to one function and cannot be shared.
    // Fourier extensions of useful functions are far above this bound.
    if (Degree(coefficients) < 5)
        OPENFHE_THROW(
                "CKKS FE functional bootstrapping needs a series of degree 5 or more to precompute shareable "
                "complex-exponential powers; use EvalFEFuncBootstrap for a shorter series.");

    auto ctxtExp = EvalFEFuncBootstrapExp(ciphertext);
    auto algo = ctxtExp->GetCryptoContext()->GetScheme();

#ifdef BOOTSTRAPTIMING
    TimeVar t;
    double timePowers(0.0);
    TIC(t);
#endif

    auto powers = algo->EvalPowers(ctxtExp, coefficients);

#ifdef BOOTSTRAPTIMING
    timePowers = TOC(t);
    OPENFHE_DIAGNOSTIC_ERR << "EvalPowers time: " << timePowers / 1000.0 << " s\n";
#endif

    return powers;
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalFEFuncBootstrapWithPrecomp(
        const std::shared_ptr<seriesPowers<DCRTPoly>>& powers,
        const std::vector<std::complex<double>>& coefficients) const {
    if (powers == nullptr || powers->powersRe.empty() || powers->powers2Re.empty())
        OPENFHE_THROW("The series powers were not produced by EvalFEFuncBootstrapPrecompute.");
    if (coefficients.size() < 2)
        OPENFHE_THROW("The coefficients vector should contain at least 2 elements");

    const uint32_t degree = Degree(coefficients);
    if (degree == 0)
        OPENFHE_THROW("The Fourier series has no nonzero coefficient above the constant term.");
    const std::vector<std::complex<double>> trimmed(coefficients.cbegin(), coefficients.cbegin() + degree + 1);

    if (degree < 5) {
        // EvalPolyWithPrecomp evaluates a short series straight from the power basis, leaving the powers
        // intact for the next function. It reads the first "degree" powers, and the basis left behind by
        // the precomputation is only as wide as that series' Paterson-Stockmeyer k.
        if (degree > powers->powersRe.size())
            OPENFHE_THROW("The Fourier series has degree " + std::to_string(degree) + ", above the maximum of " +
                          std::to_string(powers->powersRe.size()) +
                          " spanned by the precomputed complex-exponential powers.");
    } else {
        // The Paterson-Stockmeyer shape (k, m) fixed at precomputation spans degrees up to k*(2^m - 1) - 1,
        // the top coefficient of that range being reserved by the algorithm itself.
        const uint32_t capacity = powers->k * ((1U << powers->m) - 1);
        if (degree >= capacity)
            OPENFHE_THROW("The Fourier series has degree " + std::to_string(degree) + ", above the maximum of " +
                          std::to_string(capacity - 1) + " spanned by the precomputed complex-exponential powers.");
    }

#ifdef BOOTSTRAPTIMING
    TimeVar t;
    double timeSeries(0.0);
    TIC(t);
#endif

    auto algo = powers->powersRe.front()->GetCryptoContext()->GetScheme();
    auto result = TwiceRealPart(algo->EvalPolyWithPrecomp(powers, trimmed));

#ifdef BOOTSTRAPTIMING
    timeSeries = TOC(t);
    OPENFHE_DIAGNOSTIC_ERR << "EvalSeries time (precomputed powers): " << timeSeries / 1000.0 << " s\n";
#endif

    return result;
}

//------------------------------------------------------------------------------
// Find Rotation Indices
//------------------------------------------------------------------------------

std::vector<int32_t> FHECKKSRNS::FindBootstrapRotationIndices(uint32_t slots, uint32_t M) {
    const auto& p = GetBootPrecom(slots);

    // Remove possible duplicates and remove automorphisms corresponding to 0 and M/4 by using std::set
    std::set<uint32_t> s;
    if (p.m_paramsEnc.lvlb == 1 && p.m_paramsDec.lvlb == 1) {
        auto tmp = FindLinearTransformRotationIndices(slots, M);
        s.insert(tmp.begin(), tmp.end());
    } else {
        auto tmp = FindCoeffsToSlotsRotationIndices(slots, M);
        s.insert(tmp.begin(), tmp.end());
        tmp = FindSlotsToCoeffsRotationIndices(slots, M);
        s.insert(tmp.begin(), tmp.end());
    }
    s.insert(static_cast<uint32_t>(slots));
    s.erase(0);
    s.erase(M / 4);

    return std::vector<int32_t>(s.begin(), s.end());
}

// ATTN: This function is a helper methods to be called in FindBootstrapRotationIndices() only.
// so it DOES NOT remove possible duplicates and automorphisms corresponding to 0 and M/4.
// This method completely depends on FindBootstrapRotationIndices() to do that.
std::vector<uint32_t> FHECKKSRNS::FindLinearTransformRotationIndices(uint32_t slots, uint32_t M) {
    const auto& p = GetBootPrecom(slots);
    const uint32_t g = (p.m_paramsEnc.g == 0) ? std::ceil(std::sqrt(slots)) : p.m_paramsEnc.g;

    // +32 is fixed upper bound for the log2((M/4)/slots) sparse-packing indices
    std::vector<uint32_t> indexList;
    indexList.reserve(g + 32);

    for (uint32_t i = 1; i <= g; ++i)
        indexList.emplace_back(i);

    // additional automorphisms are needed for sparse bootstrapping: the rotation indices of
    // the radix-configured EvalPartialSumInPlace fold, {i*slots*radix^level : i in [1, radix)}
    if (uint32_t m = slots * 4; m != M) {
        constexpr uint32_t radix = PARTIAL_SUM_RADIX;
        const uint32_t size = M / m;
        for (uint32_t s = 1; s < size; s *= radix)
            for (uint32_t idx = slots * s; idx < slots * size && idx < radix * slots * s; idx += slots * s)
                indexList.emplace_back(idx);
    }

    return indexList;
}

// ATTN: This function is a helper methods to be called in FindBootstrapRotationIndices() only.
// so it DOES NOT remove possible duplicates and automorphisms corresponding to 0 and M/4.
// This method completely depends on FindBootstrapRotationIndices() to do that.
std::vector<uint32_t> FHECKKSRNS::FindCoeffsToSlotsRotationIndices(uint32_t slots, uint32_t M) {
    const auto& p = GetBootPrecom(slots).m_paramsEnc;

    // lvlb*(g+1)+gRem sizes the per-level baby/giant rotations
    // +32 is fixed upper bound for the log2((M/4)/slots) sparse-packing indices + correction key
    std::vector<uint32_t> indexList;
    indexList.reserve(p.lvlb * (p.g + 1) + p.gRem + 32);

    // additional automorphisms are needed for sparse bootstrapping: the rotation indices of
    // the radix-configured EvalPartialSumInPlace fold, {i*slots*radix^level : i in [1, radix)}
    if (uint32_t m = slots * 4; m != M) {
        constexpr uint32_t radix = PARTIAL_SUM_RADIX;
        const uint32_t size = M / m;
        for (uint32_t s = 1; s < size; s *= radix)
            for (uint32_t idx = slots * s; idx < slots * size && idx < radix * slots * s; idx += slots * s)
                indexList.emplace_back(idx);
    }

    M >>= 2;
    // clamp all indices to [0, 2*slots)
    const uint32_t reduceMod = std::min(M, 2 * slots);
    const int32_t flagRem = (p.remCollapse == 0) ? 0 : 1;
    for (int32_t s = -1 + p.lvlb; s >= flagRem; --s) {
        const uint32_t scalingFactor = 1U << ((s - flagRem) * p.layersCollapse + p.remCollapse);
        for (uint32_t j = 1; j < p.g; ++j)
            indexList.emplace_back(ReduceRotation(j * scalingFactor, reduceMod));
        if (p.b > 1)
            indexList.emplace_back(ReduceRotation(p.g * scalingFactor, reduceMod));
    }

    if (flagRem == 1) {
        for (uint32_t j = 1; j < p.gRem; ++j)
            indexList.emplace_back(ReduceRotation(j, reduceMod));
        if (p.bRem > 1)
            indexList.emplace_back(ReduceRotation(p.gRem, reduceMod));
    }

    // StC correction key Aut_{-(slots-1)} (CtS correction is now absorbed into plaintexts)
    indexList.emplace_back(ReduceRotation(-static_cast<int32_t>(slots - 1), reduceMod));

    return indexList;
}

std::vector<uint32_t> FHECKKSRNS::FindSlotsToCoeffsRotationIndices(uint32_t slots, uint32_t M) {
    const auto& p = GetBootPrecom(slots).m_paramsDec;

    // lvlb*(g+1)+gRem sizes the per-level baby/giant rotations
    // +32 is fixed upper bound for the log2((M/4)/slots) sparse-packing indices
    std::vector<uint32_t> indexList;
    indexList.reserve(p.lvlb * (p.g + 1) + p.gRem + 32);

    // additional automorphisms are needed for sparse bootstrapping: the rotation indices of
    // the radix-configured EvalPartialSumInPlace fold, {i*slots*radix^level : i in [1, radix)}
    if (uint32_t m = slots * 4; m != M) {
        constexpr uint32_t radix = PARTIAL_SUM_RADIX;
        const uint32_t size = M / m;
        for (uint32_t s = 1; s < size; s *= radix)
            for (uint32_t idx = slots * s; idx < slots * size && idx < radix * slots * s; idx += slots * s)
                indexList.emplace_back(idx);
    }

    M >>= 2;
    // clamp all indices to [0, 2*slots)
    const uint32_t reduceMod = std::min(M, 2 * slots);
    const uint32_t flagRem = (p.remCollapse == 0) ? 0 : 1;
    const uint32_t smax = p.lvlb - flagRem;
    for (uint32_t s = 0; s < smax; ++s) {
        const uint32_t scalingFactor = 1U << (s * p.layersCollapse);
        for (uint32_t j = 1; j < p.g; ++j)
            indexList.emplace_back(ReduceRotation(j * scalingFactor, reduceMod));
        if (p.b > 1)
            indexList.emplace_back(ReduceRotation(p.g * scalingFactor, reduceMod));
    }

    if (flagRem == 1) {
        const uint32_t scalingFactor = 1U << (smax * p.layersCollapse);
        for (uint32_t j = 1; j < p.gRem; ++j)
            indexList.emplace_back(ReduceRotation(j * scalingFactor, reduceMod));
        if (p.bRem > 1)
            indexList.emplace_back(ReduceRotation(p.gRem * scalingFactor, reduceMod));
    }

    return indexList;
}

//------------------------------------------------------------------------------
// Precomputations for CoeffsToSlots and SlotsToCoeffs
//------------------------------------------------------------------------------

std::vector<ReadOnlyPlaintext> FHECKKSRNS::EvalLinearTransformPrecompute(
        const CryptoContextImpl<DCRTPoly>& cc, const std::vector<std::vector<std::complex<double>>>& A, double scale,
        uint32_t L) const {
    const int32_t slots = A.size();
    if (slots != static_cast<int32_t>(A[0].size()))
        OPENFHE_THROW("The matrix passed to EvalLTPrecompute is not square");

    // make sure the plaintext is created only with the necessary amount of moduli
    auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());
    auto compositeDegree = cryptoParams->GetCompositeDegree();
    auto elementParams = *(cryptoParams->GetElementParams());
    uint32_t towersToDrop = (L == 0) ? 0 : elementParams.GetParams().size() - L - compositeDegree;
    for (uint32_t i = 0; i < towersToDrop; ++i)
        elementParams.PopLastParam();

    const auto& paramsQ = elementParams.GetParams();
    uint32_t sizeQ = paramsQ.size();
    const auto& paramsP = cryptoParams->GetParamsP()->GetParams();
    uint32_t sizeP = paramsP.size();
    std::vector<NativeInteger> moduli(sizeQ + sizeP);
    std::vector<NativeInteger> roots(sizeQ + sizeP);
    for (uint32_t i = 0; i < sizeQ; ++i) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i] = paramsQ[i]->GetRootOfUnity();
    }
    for (uint32_t i = 0; i < sizeP; ++i) {
        moduli[sizeQ + i] = paramsP[i]->GetModulus();
        roots[sizeQ + i] = paramsP[i]->GetRootOfUnity();
    }
    auto elementParamsPtr = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(cc.GetCyclotomicOrder(), moduli, roots);
    elementParamsPtr->SetRingType(paramsQ[0]->GetRingType());

    auto g = GetBootPrecom(slots).m_paramsEnc.g;

    const int32_t step = (g == 0) ? std::ceil(std::sqrt(slots)) : g;

    std::vector<ReadOnlyPlaintext> result(slots);
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(slots))
#endif
    for (int32_t ji = 0; ji < slots; ++ji) {
        auto diag = ExtractShiftedDiagonal(A, ji);
        for (auto& d : diag)
            d *= scale;
        result[ji] =
                MakeAuxPlaintext(cc, elementParamsPtr, Rotate(diag, -step * (ji / step)), 1, towersToDrop, diag.size());
    }
    return result;
}

std::vector<ReadOnlyPlaintext> FHECKKSRNS::EvalLinearTransformPrecompute(
        const CryptoContextImpl<DCRTPoly>& cc, const std::vector<std::vector<std::complex<double>>>& A,
        const std::vector<std::vector<std::complex<double>>>& B, uint32_t orientation, double scale, uint32_t L) const {
    // make sure the plaintext is created only with the necessary amount of moduli
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();
    auto elementParams = *(cryptoParams->GetElementParams());

    uint32_t towersToDrop = (L == 0) ? 0 : elementParams.GetParams().size() - L - compositeDegree;
    for (uint32_t i = 0; i < towersToDrop; ++i)
        elementParams.PopLastParam();

    const auto& paramsQ = elementParams.GetParams();
    uint32_t sizeQ = paramsQ.size();
    const auto& paramsP = cryptoParams->GetParamsP()->GetParams();
    uint32_t sizeP = paramsP.size();
    std::vector<NativeInteger> moduli(sizeQ + sizeP);
    std::vector<NativeInteger> roots(sizeQ + sizeP);
    for (uint32_t i = 0; i < sizeQ; ++i) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i] = paramsQ[i]->GetRootOfUnity();
    }
    for (uint32_t i = 0; i < sizeP; ++i) {
        moduli[sizeQ + i] = paramsP[i]->GetModulus();
        roots[sizeQ + i] = paramsP[i]->GetRootOfUnity();
    }
    auto elementParamsPtr = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(cc.GetCyclotomicOrder(), moduli, roots);
    elementParamsPtr->SetRingType(paramsQ[0]->GetRingType());

    const int32_t slots = static_cast<int32_t>(A.size());

    auto g = GetBootPrecom(slots).m_paramsEnc.g;

    const int32_t step = (g == 0) ? std::ceil(std::sqrt(slots)) : g;

    std::vector<ReadOnlyPlaintext> result(slots);

    if (orientation == 0) {
        // vertical concatenation - used during homomorphic encoding
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(slots))
#endif
        for (int32_t ji = 0; ji < slots; ++ji) {
            auto vecA = ExtractShiftedDiagonal(A, ji);
            auto vecB = ExtractShiftedDiagonal(B, ji);
            vecA.insert(vecA.end(), vecB.begin(), vecB.end());
            for (auto& v : vecA)
                v *= scale;
            result[ji] = MakeAuxPlaintext(cc, elementParamsPtr, Rotate(vecA, -step * (ji / step)), 1, towersToDrop,
                                          vecA.size());
        }
    } else {
        // horizontal concatenation - used during homomorphic decoding
        std::vector<std::vector<std::complex<double>>> newA(slots);

        //  A and B are concatenated horizontally
        for (int32_t i = 0; i < slots; ++i) {
            newA[i].reserve(A[i].size() + B[i].size());
            newA[i].insert(newA[i].end(), A[i].begin(), A[i].end());
            newA[i].insert(newA[i].end(), B[i].begin(), B[i].end());
        }

#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(slots))
#endif
        for (int32_t ji = 0; ji < slots; ++ji) {
            // shifted diagonal is computed for rectangular map newA of dimension
            // slots x 2*slots
            auto vec = ExtractShiftedDiagonal(newA, ji);
            for (auto& v : vec)
                v *= scale;
            result[ji] = MakeAuxPlaintext(cc, elementParamsPtr, Rotate(vec, -step * (ji / step)), 1, towersToDrop,
                                          vec.size());
        }
    }

    return result;
}

std::vector<std::vector<ReadOnlyPlaintext>> FHECKKSRNS::EvalCoeffsToSlotsPrecompute(
        const CryptoContextImpl<DCRTPoly>& cc, const std::vector<std::complex<double>>& A,
        const std::vector<uint32_t>& rotGroup, bool flag_i, double scale, uint32_t L, bool flagStCComplex) const {
    const uint32_t slots = rotGroup.size();

    const auto& p = GetBootPrecom(slots).m_paramsEnc;

    // result is the rotated plaintext version of the coefficients
    std::vector<std::vector<ReadOnlyPlaintext>> result(p.lvlb, std::vector<ReadOnlyPlaintext>(p.numRotations));

    int32_t stop = -1;
    int32_t flagRem = 0;
    if (p.remCollapse != 0) {
        stop = 0;
        flagRem = 1;

        // remainder corresponds to index 0 in encoding and to last index in decoding
        result[0].resize(p.numRotationsRem);
    }

    // make sure the plaintext is created only with the necessary amount of moduli
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    auto elementParams = *(cryptoParams->GetElementParams());

    uint32_t towersToDrop = (L == 0) ? 0 : elementParams.GetParams().size() - L - compositeDegree * p.lvlb;
    for (uint32_t i = 0; i < towersToDrop; ++i)
        elementParams.PopLastParam();

    uint32_t level0 = towersToDrop + compositeDegree * (p.lvlb - 1);

    const auto& paramsQ = elementParams.GetParams();
    uint32_t sizeQ = paramsQ.size();
    const auto& paramsP = cryptoParams->GetParamsP()->GetParams();
    uint32_t sizeP = paramsP.size();
    std::vector<NativeInteger> moduli(sizeQ + sizeP);
    std::vector<NativeInteger> roots(sizeQ + sizeP);
    for (uint32_t i = 0; i < sizeQ; ++i) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i] = paramsQ[i]->GetRootOfUnity();
    }
    for (uint32_t i = 0; i < sizeP; ++i) {
        moduli[sizeQ + i] = paramsP[i]->GetModulus();
        roots[sizeQ + i] = paramsP[i]->GetRootOfUnity();
    }

    // we need to pre-compute the plaintexts in the extended basis P*Q
    uint32_t M = cc.GetCyclotomicOrder();
    std::vector<std::shared_ptr<ILDCRTParams<BigInteger>>> paramsVector(p.lvlb - stop);
    for (int32_t s = p.lvlb - 1; s >= stop; --s) {
        paramsVector[s - stop] = std::make_shared<ILDCRTParams<BigInteger>>(M, moduli, roots);
        paramsVector[s - stop]->SetRingType(elementParams.GetRingType());
        sizeQ -= compositeDegree;
        moduli.erase(moduli.begin() + sizeQ, moduli.begin() + sizeQ + compositeDegree);
        roots.erase(roots.begin() + sizeQ, roots.begin() + sizeQ + compositeDegree);
    }

    // zero-based inner indices require shifting the pre-rotation by +offset*scale
    const int32_t offset = static_cast<int32_t>((p.numRotations + 1) / 2) - 1;
    const int32_t offsetRem = static_cast<int32_t>((p.numRotationsRem + 1) / 2) - 1;
    // running accumulated correction; plaintexts pre-absorb the per-level Aut_{-delta_s}
    int32_t runningAcc = 0;

    if (uint32_t M4 = M / 4; slots == M4 || flagStCComplex) {
        //------------------------------------------------------------------------------
        // fully-packed mode
        //------------------------------------------------------------------------------

        auto coeff = CoeffEncodingCollapse(A, rotGroup, p.lvlb, flag_i);

        for (int32_t s = -1 + p.lvlb; s > stop; --s) {
            const int32_t shiftScale = 1 << ((s - flagRem) * p.layersCollapse + p.remCollapse);
            const int32_t rotScale = shiftScale * static_cast<int32_t>(p.g);
            const uint32_t limit = p.b * p.g;
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(limit))
#endif
            for (uint32_t ij = 0; ij < limit; ++ij) {
                if (ij != p.numRotations) {
                    if ((flagRem == 0) && (s == stop + 1)) {
                        for (auto& c : coeff[s][ij])
                            c *= scale;
                    }

                    auto rot = Rotate(coeff[s][ij],
                                      ReduceRotation(-rotScale * (ij / p.g) + offset * shiftScale + runningAcc, slots));

                    result[s][ij] = MakeAuxPlaintext(cc, paramsVector[s - stop], rot, 1, level0 - compositeDegree * s,
                                                     rot.size());
                }
            }
            runningAcc += offset * shiftScale;
        }

        if (flagRem == 1) {
            const uint32_t limit = p.bRem * p.gRem;
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(limit))
#endif
            for (uint32_t ij = 0; ij < limit; ++ij) {
                if (ij != p.numRotationsRem) {
                    for (auto& c : coeff[stop][ij])
                        c *= scale;

                    auto rot = Rotate(coeff[stop][ij], ReduceRotation(-static_cast<int32_t>(p.gRem) * (ij / p.gRem) +
                                                                              offsetRem + runningAcc,
                                                                      slots));

                    result[stop][ij] = MakeAuxPlaintext(cc, paramsVector[0], rot, 1, level0, rot.size());
                }
            }
        }
    } else {
        //------------------------------------------------------------------------------
        // sparsely-packed mode
        //------------------------------------------------------------------------------

        auto coeff = CoeffEncodingCollapse(A, rotGroup, p.lvlb, false);
        auto coeffi = CoeffEncodingCollapse(A, rotGroup, p.lvlb, true);

        for (int32_t s = -1 + p.lvlb; s > stop; --s) {
            const int32_t shiftScale = 1 << ((s - flagRem) * p.layersCollapse + p.remCollapse);
            const int32_t rotScale = shiftScale * static_cast<int32_t>(p.g);
            const uint32_t limit = p.b * p.g;
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(limit))
#endif
            for (uint32_t ij = 0; ij < limit; ++ij) {
                if (ij != p.numRotations) {
                    // concatenate the coefficients horizontally on their third dimension, which corresponds to the # of slots
                    auto clearTmp = coeff[s][ij];
                    auto& clearTmpi = coeffi[s][ij];
                    clearTmp.insert(clearTmp.end(), clearTmpi.begin(), clearTmpi.end());
                    if ((flagRem == 0) && (s == stop + 1)) {
                        for (auto& c : clearTmp)
                            c *= scale;
                    }

                    auto rot = Rotate(
                            clearTmp,
                            ReduceRotation(-rotScale * (ij / p.g) + offset * shiftScale + runningAcc, 2 * slots));

                    result[s][ij] = MakeAuxPlaintext(cc, paramsVector[s - stop], rot, 1, level0 - compositeDegree * s,
                                                     rot.size());
                }
            }
            runningAcc += offset * shiftScale;
        }

        if (flagRem == 1) {
            const uint32_t limit = p.bRem * p.gRem;
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(limit))
#endif
            for (uint32_t ij = 0; ij < limit; ++ij) {
                if (ij != p.numRotationsRem) {
                    // concatenate the coefficients on their third dimension, which corresponds to the # of slots
                    auto clearTmp = coeff[stop][ij];
                    auto& clearTmpi = coeffi[stop][ij];
                    clearTmp.insert(clearTmp.end(), clearTmpi.begin(), clearTmpi.end());
                    for (auto& c : clearTmp)
                        c *= scale;

                    auto rot = Rotate(clearTmp,
                                      ReduceRotation(-p.gRem * (ij / p.gRem) + offsetRem + runningAcc, 2 * slots));

                    result[stop][ij] = MakeAuxPlaintext(cc, paramsVector[0], rot, 1, level0, rot.size());
                }
            }
        }
    }
    return result;
}

std::vector<std::vector<ReadOnlyPlaintext>> FHECKKSRNS::EvalSlotsToCoeffsPrecompute(
        const CryptoContextImpl<DCRTPoly>& cc, const std::vector<std::complex<double>>& A,
        const std::vector<uint32_t>& rotGroup, bool flag_i, double scale, uint32_t L, bool flagStCComplex) const {
    const uint32_t slots = rotGroup.size();

    const auto& p = GetBootPrecom(slots).m_paramsDec;

    const int32_t flagRem = (p.remCollapse == 0) ? 0 : 1;

    // result is the rotated plaintext version of coeff
    std::vector<std::vector<ReadOnlyPlaintext>> result(p.lvlb, std::vector<ReadOnlyPlaintext>(p.numRotations));
    if (flagRem == 1) {
        // remainder corresponds to index 0 in encoding and to last index in decoding
        result[p.lvlb - 1].resize(p.numRotationsRem);
    }

    // make sure the plaintext is created only with the necessary amount of moduli

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();
    auto elementParams = *(cryptoParams->GetElementParams());

    const uint32_t towersToDrop = (L == 0) ? 0 : elementParams.GetParams().size() - L - compositeDegree * p.lvlb;
    for (uint32_t i = 0; i < towersToDrop; ++i)
        elementParams.PopLastParam();

    const auto& paramsQ = elementParams.GetParams();
    uint32_t sizeQ = paramsQ.size();
    const auto& paramsP = cryptoParams->GetParamsP()->GetParams();
    uint32_t sizeP = paramsP.size();
    std::vector<NativeInteger> moduli(sizeQ + sizeP);
    std::vector<NativeInteger> roots(sizeQ + sizeP);
    for (uint32_t i = 0; i < sizeQ; ++i) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i] = paramsQ[i]->GetRootOfUnity();
    }
    for (uint32_t i = 0; i < sizeP; ++i) {
        moduli[sizeQ + i] = paramsP[i]->GetModulus();
        roots[sizeQ + i] = paramsP[i]->GetRootOfUnity();
    }

    // we need to pre-compute the plaintexts in the extended basis P*Q
    const uint32_t pvlen = p.lvlb + 1 - flagRem;
    std::vector<std::shared_ptr<ILDCRTParams<BigInteger>>> paramsVector(pvlen);
    for (uint32_t s = 0; s < pvlen; ++s) {
        paramsVector[s] = std::make_shared<ILDCRTParams<BigInteger>>(cc.GetCyclotomicOrder(), moduli, roots);
        paramsVector[s]->SetRingType(elementParams.GetRingType());
        for (uint32_t i = 0; i < compositeDegree; ++i, --sizeQ) {
            moduli.erase(moduli.begin() + sizeQ - 1);
            roots.erase(roots.begin() + sizeQ - 1);
        }
    }

    // zero-based inner indices require shifting the pre-rotation by +offset*shiftScale
    const int32_t offset = static_cast<int32_t>((p.numRotations + 1) / 2) - 1;
    const int32_t offsetRem = static_cast<int32_t>((p.numRotationsRem + 1) / 2) - 1;
    // CtS output now carries no extra rotation (absorbed into CtS precompute), so start at 0
    int32_t runningAcc = 0;

    if (uint32_t M4 = cc.GetCyclotomicOrder() / 4; M4 == slots || flagStCComplex) {
        auto coeff = CoeffDecodingCollapse(A, rotGroup, p.lvlb, flag_i);

        const uint32_t smax = p.lvlb - flagRem;
        for (uint32_t s = 0; s < smax; ++s) {
            const int32_t shiftScale = 1 << (s * p.layersCollapse);
            const int32_t rotScale = shiftScale * static_cast<int32_t>(p.g);
            const uint32_t limit = p.b * p.g;
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(limit))
#endif
            for (uint32_t ij = 0; ij < limit; ++ij) {
                if (ij != p.numRotations) {
                    if ((flagRem == 0) && (s + 1 == smax)) {
                        for (auto& c : coeff[s][ij])
                            c *= scale;
                    }

                    auto rot = Rotate(coeff[s][ij],
                                      ReduceRotation(-rotScale * (ij / p.g) + offset * shiftScale + runningAcc, slots));

                    result[s][ij] = MakeAuxPlaintext(cc, paramsVector[s], rot, 1, towersToDrop + compositeDegree * s,
                                                     rot.size());
                }
            }
            runningAcc += offset * shiftScale;
        }

        if (flagRem == 1) {
            const int32_t shiftScaleRem = 1 << (smax * p.layersCollapse);
            const int32_t rotScale = shiftScaleRem * static_cast<int32_t>(p.gRem);
            const uint32_t limit = p.bRem * p.gRem;
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(limit))
#endif
            for (uint32_t ij = 0; ij < limit; ++ij) {
                if (ij != p.numRotationsRem) {
                    for (auto& c : coeff[smax][ij])
                        c *= scale;

                    auto rot = Rotate(
                            coeff[smax][ij],
                            ReduceRotation(-rotScale * (ij / p.gRem) + offsetRem * shiftScaleRem + runningAcc, slots));

                    result[smax][ij] = MakeAuxPlaintext(cc, paramsVector[smax], rot, 1,
                                                        towersToDrop + compositeDegree * smax, rot.size());
                }
            }
        }
    } else {
        //------------------------------------------------------------------------------
        // sparsely-packed mode
        //------------------------------------------------------------------------------

        auto coeff = CoeffDecodingCollapse(A, rotGroup, p.lvlb, false);
        auto coeffi = CoeffDecodingCollapse(A, rotGroup, p.lvlb, true);

        const uint32_t smax = p.lvlb - flagRem;
        for (uint32_t s = 0; s < smax; ++s) {
            const int32_t shiftScale = 1 << (s * p.layersCollapse);
            const int32_t rotScale = shiftScale * static_cast<int32_t>(p.g);
            const uint32_t limit = p.b * p.g;
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(limit))
#endif
            for (uint32_t ij = 0; ij < limit; ++ij) {
                if (ij != p.numRotations) {
                    // concatenate the coefficients horizontally on their third dimension, which corresponds to the # of slots
                    auto clearTmp = coeff[s][ij];
                    auto& clearTmpi = coeffi[s][ij];
                    clearTmp.insert(clearTmp.end(), clearTmpi.begin(), clearTmpi.end());
                    if ((flagRem == 0) && (s + 1 == smax)) {
                        // do the scaling only at the last set of coefficients
                        for (auto& c : clearTmp)
                            c *= scale;
                    }

                    auto rot = Rotate(
                            clearTmp,
                            ReduceRotation(-rotScale * (ij / p.g) + offset * shiftScale + runningAcc, 2 * slots));

                    result[s][ij] = MakeAuxPlaintext(cc, paramsVector[s], rot, 1, towersToDrop + compositeDegree * s,
                                                     rot.size());
                }
            }
            runningAcc += offset * shiftScale;
        }

        if (flagRem == 1) {
            const int32_t shiftScaleRem = 1 << (smax * p.layersCollapse);
            const int32_t rotScale = shiftScaleRem * static_cast<int32_t>(p.gRem);
            const uint32_t limit = p.bRem * p.gRem;
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(limit))
#endif
            for (uint32_t ij = 0; ij < limit; ++ij) {
                if (ij != p.numRotationsRem) {
                    // concatenate the coefficients on their third dimension, which corresponds to the # of slots
                    auto clearTmp = coeff[smax][ij];
                    auto& clearTmpi = coeffi[smax][ij];
                    clearTmp.insert(clearTmp.end(), clearTmpi.begin(), clearTmpi.end());
                    for (auto& c : clearTmp)
                        c *= scale;

                    auto rot = Rotate(clearTmp,
                                      ReduceRotation(-rotScale * (ij / p.gRem) + offsetRem * shiftScaleRem + runningAcc,
                                                     2 * slots));

                    result[smax][ij] = MakeAuxPlaintext(cc, paramsVector[smax], rot, 1,
                                                        towersToDrop + compositeDegree * smax, rot.size());
                }
            }
        }
    }
    return result;
}

//------------------------------------------------------------------------------
// EVALUATION: CoeffsToSlots and SlotsToCoeffs
//------------------------------------------------------------------------------

Ciphertext<DCRTPoly> FHECKKSRNS::EvalLinearTransform(const std::vector<ReadOnlyPlaintext>& A,
                                                     ConstCiphertext<DCRTPoly>& ct) const {
    // Computing the baby-step bStep and the giant-step gStep.
    const int32_t slots = A.size();
    const auto& p = GetBootPrecom(slots);
    const int32_t bStep = (p.m_paramsEnc.g == 0) ? std::ceil(std::sqrt(slots)) : p.m_paramsEnc.g;
    const int32_t gStep = std::ceil(static_cast<double>(slots) / bStep);

    auto cc = ct->GetCryptoContext();
    auto digits = cc->EvalFastRotationPrecompute(ct);

    std::vector<Ciphertext<DCRTPoly>> fastRotation(bStep - 1);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(bStep - 1))
    for (int32_t j = 1; j < bStep; ++j)
        fastRotation[j - 1] = cc->EvalFastRotationExt(ct, j, digits, true);

    auto ctExt = cc->KeySwitchExt(ct, true);

    uint32_t autoIndex = 0;
    std::vector<uint32_t> map;
    EvalKey<DCRTPoly> giantKey;
    if (gStep > 1)
        giantKey = GetGiantStepRotation(ct, bStep, autoIndex, map);

    // Horner backward accumulation with a single giant stride t = bStep.
    const int32_t Gtop = (gStep - 1) * bStep;
    Ciphertext<DCRTPoly> outer = EvalMultExt(ctExt, A[Gtop]);
    for (int32_t i = 1; i < bStep; ++i)
        if (Gtop + i < slots)
            EvalAddExtInPlace(outer, EvalMultExt(fastRotation[i - 1], A[Gtop + i]));

    for (int32_t j = gStep - 2; j >= 0; --j) {
        outer = EvalHornerGiantRotate(outer, autoIndex, map, giantKey);
        const int32_t G = j * bStep;
        auto inner = EvalMultExt(ctExt, A[G]);
        for (int32_t i = 1; i < bStep; ++i)
            EvalAddExtInPlace(inner, EvalMultExt(fastRotation[i - 1], A[G + i]));
        EvalAddExtInPlace(outer, inner);
    }
    return cc->KeySwitchDown(outer);
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalCoeffsToSlots(const std::vector<std::vector<ReadOnlyPlaintext>>& A,
                                                   ConstCiphertext<DCRTPoly>& ctxt) const {
    const uint32_t slots = ctxt->GetSlots();

    const auto& p = GetBootPrecom(slots).m_paramsEnc;

    int32_t stop = -1;
    int32_t flagRem = 0;
    if (p.remCollapse != 0) {
        stop = 0;
        flagRem = 1;
    }

    auto cc = ctxt->GetCryptoContext();

    const uint32_t M4 = cc->GetCyclotomicOrder() / 4;
    const uint32_t reduceMod = std::min(M4, 2 * slots);

    auto result = ctxt->Clone();

    auto algo = cc->GetScheme();
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    // the per-level accumulated rotation to undo so the output is in standard slot ordering;
    // folded into the final level's Horner output while it is still in the extended basis
    const int32_t CtSDelta = ReduceRotation(-static_cast<int32_t>(slots - 1), reduceMod);

    // hoisted automorphisms
    const int32_t smax = -1 + p.lvlb;
    for (int32_t s = smax; s > stop; --s) {
        if (s != smax)
            algo->ModReduceInternalInPlace(result, compositeDegree);

        const int32_t scale = 1 << ((s - flagRem) * p.layersCollapse + p.remCollapse);

        LTLevel ltl("std-CtS", smax - s, p.numRotations, result->GetElements()[0].GetNumOfElements(),
                    cryptoParams->GetParamsP()->GetParams().size());
        auto digits =
                LTRun(&LTStats::modUp, &LTStats::tModUp, 1, [&] { return cc->EvalFastRotationPrecompute(result); });
        std::vector<Ciphertext<DCRTPoly>> fastRotation(p.g);
        LTRun(&LTStats::baby, &LTStats::tBaby, p.g - 1, [&] {
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(p.g))
            for (uint32_t j = 0; j < p.g; ++j)
                fastRotation[j] =
                        (j != 0) ? cc->EvalFastRotationExt(result, ReduceRotation(scale * j, reduceMod), digits, true) :
                                   cc->KeySwitchExt(result, true);
            return 0;
        });
        LTAdd(&LTStats::ext, 1);

        // Horner backward accumulation with single giant stride t = g * scale
        const int32_t t = ReduceRotation(scale * p.g, reduceMod);

        const int32_t bLast = static_cast<int32_t>(p.b) - 1;

        uint32_t giantAutoIndex = 0;
        std::vector<uint32_t> giantMap;
        EvalKey<DCRTPoly> giantKey;
        if (t != 0 && bLast > 0)
            giantKey = GetGiantStepRotation(result, t, giantAutoIndex, giantMap);

        const uint32_t Gtop = p.g * bLast;
        Ciphertext<DCRTPoly> outer = EvalMultExt(fastRotation[0], A[s][Gtop]);
        for (uint32_t j = 1; j < p.g; ++j)
            if ((Gtop + j) != p.numRotations)
                EvalAddExtInPlace(outer, EvalMultExt(fastRotation[j], A[s][Gtop + j]));

        for (int32_t i = bLast - 1; i >= 0; --i) {
            if (t != 0)
                outer = EvalHornerGiantRotate(outer, giantAutoIndex, giantMap, giantKey);
            const uint32_t G = p.g * i;
            auto inner = EvalMultExt(fastRotation[0], A[s][G]);
            for (uint32_t j = 1; j < p.g; ++j)
                EvalAddExtInPlace(inner, EvalMultExt(fastRotation[j], A[s][G + j]));
            EvalAddExtInPlace(outer, inner);
        }
        if (s == stop + 1 && flagRem == 0 && CtSDelta != 0) {
            uint32_t deltaAutoIndex = 0;
            std::vector<uint32_t> deltaMap;
            auto deltaKey = GetGiantStepRotation(result, CtSDelta, deltaAutoIndex, deltaMap);
            outer = EvalHornerGiantRotate(outer, deltaAutoIndex, deltaMap, deltaKey);
        }
        result = LTRun(&LTStats::modDown, &LTStats::tModDown, 2, [&] { return cc->KeySwitchDown(outer); });
        ltl.Print();
    }

    if (flagRem == 1) {
        algo->ModReduceInternalInPlace(result, compositeDegree);

        LTLevel ltl("std-CtS", smax - stop, p.numRotationsRem, result->GetElements()[0].GetNumOfElements(),
                    cryptoParams->GetParamsP()->GetParams().size());
        auto digits =
                LTRun(&LTStats::modUp, &LTStats::tModUp, 1, [&] { return cc->EvalFastRotationPrecompute(result); });
        std::vector<Ciphertext<DCRTPoly>> fastRotationRem(p.gRem);
        LTRun(&LTStats::baby, &LTStats::tBaby, p.gRem - 1, [&] {
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(p.gRem))
            for (uint32_t j = 0; j < p.gRem; ++j)
                fastRotationRem[j] = (j != 0) ?
                                             cc->EvalFastRotationExt(result, ReduceRotation(j, reduceMod), digits, true) :
                                             cc->KeySwitchExt(result, true);
            return 0;
        });
        LTAdd(&LTStats::ext, 1);

        // Remainder scale is 1 in CtS; Horner giant stride = gRem
        const int32_t tRem = ReduceRotation(p.gRem, reduceMod);

        const int32_t bLast = static_cast<int32_t>(p.bRem) - 1;

        uint32_t giantAutoIndex = 0;
        std::vector<uint32_t> giantMap;
        EvalKey<DCRTPoly> giantKey;
        if (tRem != 0 && bLast > 0)
            giantKey = GetGiantStepRotation(result, tRem, giantAutoIndex, giantMap);

        const uint32_t GtopRem = p.gRem * bLast;
        Ciphertext<DCRTPoly> outer = EvalMultExt(fastRotationRem[0], A[stop][GtopRem]);
        for (uint32_t j = 1; j < p.gRem; ++j)
            if ((GtopRem + j) != p.numRotationsRem)
                EvalAddExtInPlace(outer, EvalMultExt(fastRotationRem[j], A[stop][GtopRem + j]));

        for (int32_t i = bLast - 1; i >= 0; --i) {
            if (tRem != 0)
                outer = EvalHornerGiantRotate(outer, giantAutoIndex, giantMap, giantKey);
            const uint32_t GRem = p.gRem * i;
            auto inner = EvalMultExt(fastRotationRem[0], A[stop][GRem]);
            for (uint32_t j = 1; j < p.gRem; ++j)
                EvalAddExtInPlace(inner, EvalMultExt(fastRotationRem[j], A[stop][GRem + j]));
            EvalAddExtInPlace(outer, inner);
        }
        if (CtSDelta != 0) {
            uint32_t deltaAutoIndex = 0;
            std::vector<uint32_t> deltaMap;
            auto deltaKey = GetGiantStepRotation(result, CtSDelta, deltaAutoIndex, deltaMap);
            outer = EvalHornerGiantRotate(outer, deltaAutoIndex, deltaMap, deltaKey);
        }
        result = LTRun(&LTStats::modDown, &LTStats::tModDown, 2, [&] { return cc->KeySwitchDown(outer); });
        ltl.Print();
    }

    return result;
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalSlotsToCoeffs(const std::vector<std::vector<ReadOnlyPlaintext>>& A,
                                                   ConstCiphertext<DCRTPoly>& ctxt) const {
    const uint32_t slots = ctxt->GetSlots();

    const auto& p = GetBootPrecom(slots).m_paramsDec;

    const int32_t flagRem = (p.remCollapse == 0) ? 0 : 1;

    auto cc = ctxt->GetCryptoContext();

    const uint32_t M4 = cc->GetCyclotomicOrder() / 4;
    const uint32_t reduceMod = std::min(M4, 2 * slots);
    const int32_t smax = p.lvlb - flagRem;

    auto result = ctxt->Clone();

    auto algo = cc->GetScheme();
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    // the StC accumulated correction Aut_{-Delta} where Delta = slots-1; folded into the
    // final level's Horner output while it is still in the extended basis
    const int32_t StCDelta = ReduceRotation(-static_cast<int32_t>(slots - 1), reduceMod);

    for (int32_t s = 0; s < smax; ++s) {
        if (s != 0)
            algo->ModReduceInternalInPlace(result, compositeDegree);

        const int32_t scale = 1 << (s * p.layersCollapse);

        LTLevel ltl("std-StC", s, p.numRotations, result->GetElements()[0].GetNumOfElements(),
                    cryptoParams->GetParamsP()->GetParams().size());
        auto digits =
                LTRun(&LTStats::modUp, &LTStats::tModUp, 1, [&] { return cc->EvalFastRotationPrecompute(result); });
        std::vector<Ciphertext<DCRTPoly>> fastRotation(p.g);
        LTRun(&LTStats::baby, &LTStats::tBaby, p.g - 1, [&] {
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(p.g))
            for (uint32_t j = 0; j < p.g; ++j)
                fastRotation[j] =
                        (j != 0) ? cc->EvalFastRotationExt(result, ReduceRotation(scale * j, reduceMod), digits, true) :
                                   cc->KeySwitchExt(result, true);
            return 0;
        });
        LTAdd(&LTStats::ext, 1);

        // Horner backward accumulation with single giant stride t = g * scale
        const int32_t t = ReduceRotation(scale * p.g, reduceMod);

        const int32_t bLast = static_cast<int32_t>(p.b) - 1;

        uint32_t giantAutoIndex = 0;
        std::vector<uint32_t> giantMap;
        EvalKey<DCRTPoly> giantKey;
        if (t != 0 && bLast > 0)
            giantKey = GetGiantStepRotation(result, t, giantAutoIndex, giantMap);

        const uint32_t Gtop = p.g * bLast;
        Ciphertext<DCRTPoly> outer = EvalMultExt(fastRotation[0], A[s][Gtop]);
        for (uint32_t j = 1; j < p.g; ++j)
            if ((Gtop + j) != p.numRotations)
                EvalAddExtInPlace(outer, EvalMultExt(fastRotation[j], A[s][Gtop + j]));

        for (int32_t i = bLast - 1; i >= 0; --i) {
            if (t != 0)
                outer = EvalHornerGiantRotate(outer, giantAutoIndex, giantMap, giantKey);
            const uint32_t G = p.g * i;
            auto inner = EvalMultExt(fastRotation[0], A[s][G]);
            for (uint32_t j = 1; j < p.g; ++j)
                EvalAddExtInPlace(inner, EvalMultExt(fastRotation[j], A[s][G + j]));
            EvalAddExtInPlace(outer, inner);
        }
        if (s == smax - 1 && flagRem == 0 && StCDelta != 0) {
            uint32_t deltaAutoIndex = 0;
            std::vector<uint32_t> deltaMap;
            auto deltaKey = GetGiantStepRotation(result, StCDelta, deltaAutoIndex, deltaMap);
            outer = EvalHornerGiantRotate(outer, deltaAutoIndex, deltaMap, deltaKey);
        }
        result = LTRun(&LTStats::modDown, &LTStats::tModDown, 2, [&] { return cc->KeySwitchDown(outer); });
        ltl.Print();
    }

    if (flagRem == 1) {
        algo->ModReduceInternalInPlace(result, compositeDegree);

        const int32_t scaleRem = 1 << (smax * p.layersCollapse);

        LTLevel ltl("std-StC", smax, p.numRotationsRem, result->GetElements()[0].GetNumOfElements(),
                    cryptoParams->GetParamsP()->GetParams().size());
        auto digits =
                LTRun(&LTStats::modUp, &LTStats::tModUp, 1, [&] { return cc->EvalFastRotationPrecompute(result); });
        std::vector<Ciphertext<DCRTPoly>> fastRotationRem(p.gRem);
        LTRun(&LTStats::baby, &LTStats::tBaby, p.gRem - 1, [&] {
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(p.gRem))
            for (uint32_t j = 0; j < p.gRem; ++j)
                fastRotationRem[j] =
                        (j != 0) ? cc->EvalFastRotationExt(result, ReduceRotation(scaleRem * j, reduceMod), digits, true) :
                                   cc->KeySwitchExt(result, true);
            return 0;
        });
        LTAdd(&LTStats::ext, 1);

        // Horner giant stride for remainder: g_rem * scale_rem
        const int32_t tRem = ReduceRotation(scaleRem * p.gRem, reduceMod);

        const int32_t bLast = static_cast<int32_t>(p.bRem) - 1;

        uint32_t giantAutoIndex = 0;
        std::vector<uint32_t> giantMap;
        EvalKey<DCRTPoly> giantKey;
        if (tRem != 0 && bLast > 0)
            giantKey = GetGiantStepRotation(result, tRem, giantAutoIndex, giantMap);

        const uint32_t GtopRem = p.gRem * bLast;
        Ciphertext<DCRTPoly> outer = EvalMultExt(fastRotationRem[0], A[smax][GtopRem]);
        for (uint32_t j = 1; j < p.gRem; ++j)
            if ((GtopRem + j) != p.numRotationsRem)
                EvalAddExtInPlace(outer, EvalMultExt(fastRotationRem[j], A[smax][GtopRem + j]));

        for (int32_t i = bLast - 1; i >= 0; --i) {
            if (tRem != 0)
                outer = EvalHornerGiantRotate(outer, giantAutoIndex, giantMap, giantKey);
            const uint32_t GRem = p.gRem * i;
            auto inner = EvalMultExt(fastRotationRem[0], A[smax][GRem]);
            for (uint32_t j = 1; j < p.gRem; ++j)
                EvalAddExtInPlace(inner, EvalMultExt(fastRotationRem[j], A[smax][GRem + j]));
            EvalAddExtInPlace(outer, inner);
        }
        if (StCDelta != 0) {
            uint32_t deltaAutoIndex = 0;
            std::vector<uint32_t> deltaMap;
            auto deltaKey = GetGiantStepRotation(result, StCDelta, deltaAutoIndex, deltaMap);
            outer = EvalHornerGiantRotate(outer, deltaAutoIndex, deltaMap, deltaKey);
        }
        result = LTRun(&LTStats::modDown, &LTStats::tModDown, 2, [&] { return cc->KeySwitchDown(outer); });
        ltl.Print();
    }

    return result;
}

uint32_t FHECKKSRNS::GetBootstrapDepth(uint32_t approxModDepth, const std::vector<uint32_t>& levelBudget,
                                       SecretKeyDist secretKeyDist) {
    if (secretKeyDist == UNIFORM_TERNARY)
        approxModDepth += R_UNIFORM - 1;
    return approxModDepth + levelBudget[0] + levelBudget[1];
}

uint32_t FHECKKSRNS::GetBootstrapDepth(const std::vector<uint32_t>& levelBudget, SecretKeyDist secretKeyDist) {
    uint32_t approxModDepth = GetModDepthInternal(secretKeyDist);
    // AA: note that the scalings by double constants are not captured here.
    // One extra level is consumed before ModRaise (correction factor), and another is consumed after ModRaise (normalization).
    return approxModDepth + levelBudget[0] + levelBudget[1];
}

//------------------------------------------------------------------------------
// Auxiliary Bootstrap Functions
//------------------------------------------------------------------------------
uint32_t FHECKKSRNS::GetBootstrapDepthInternal(uint32_t approxModDepth, const std::vector<uint32_t>& levelBudget,
                                               const CryptoContextImpl<DCRTPoly>& cc) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());
    return GetBootstrapDepth(approxModDepth, levelBudget, cryptoParams->GetSecretKeyDist());
}

uint32_t FHECKKSRNS::GetModDepthInternal(SecretKeyDist secretKeyDist) {
    if (secretKeyDist == UNIFORM_TERNARY)
        return GetMultiplicativeDepthByCoeffVector(g_coefficientsUniform, false) + R_UNIFORM;
    return GetMultiplicativeDepthByCoeffVector(g_coefficientsSparse, false) + R_SPARSE;
}

void FHECKKSRNS::AdjustCiphertext(Ciphertext<DCRTPoly>& ciphertext, double correction, uint32_t lvl,
                                  bool modReduce) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    auto cc = ciphertext->GetCryptoContext();
    auto algo = cc->GetScheme();
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT ||
        cryptoParams->GetScalingTechnique() == COMPOSITESCALINGAUTO ||
        cryptoParams->GetScalingTechnique() == COMPOSITESCALINGMANUAL) {
        double targetSF = cryptoParams->GetScalingFactorReal(lvl);
        double sourceSF = ciphertext->GetScalingFactor();
        uint32_t numTowers = ciphertext->GetElements()[0].GetNumOfElements();
        double modToDrop = cryptoParams->GetElementParams()->GetParams()[numTowers - 1]->GetModulus().ConvertToDouble();
        for (uint32_t j = 2; j <= compositeDegree; ++j) {
            modToDrop *= cryptoParams->GetElementParams()->GetParams()[numTowers - j]->GetModulus().ConvertToDouble();
        }

        // in the case of FLEXIBLEAUTO, we need to bring the ciphertext to the right scale using a
        // a scaling multiplication. Note the at currently FLEXIBLEAUTO is only supported for NATIVEINT = 64.
        // So the other branch is for future purposes (in case we decide to add add the FLEXIBLEAUTO support
        // for NATIVEINT = 128.
#if NATIVEINT != 128
        // Scaling down the message by a correction factor to emulate using a larger q0.
        // This step is needed so we could use a scaling factor of up to 2^59 with q9 ~= 2^60.
        double adjustmentFactor = (targetSF / sourceSF) * (modToDrop / sourceSF) * correction;
#else
        double adjustmentFactor = (targetSF / sourceSF) * (modToDrop / sourceSF);
#endif
        cc->EvalMultInPlace(ciphertext, adjustmentFactor);
        if (modReduce) {
            algo->ModReduceInternalInPlace(ciphertext, compositeDegree);
            ciphertext->SetScalingFactor(targetSF);
        }
    } else {
#if NATIVEINT != 128
        // Scaling down the message by a correction factor to emulate using a larger q0.
        // This step is needed so we could use a scaling factor of up to 2^59 with q9 ~= 2^60.
        cc->EvalMultInPlace(ciphertext, correction);
        if (modReduce) {
            algo->ModReduceInternalInPlace(ciphertext, compositeDegree);
        }
#endif
    }
}

void FHECKKSRNS::AdjustCiphertextFBT(Ciphertext<DCRTPoly>& ciphertext, double correction) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        OPENFHE_THROW("This version of AdjustCiphertext is supported for FIXEDMANUAL and FIXEDAUTO methods only.");
#if NATIVEINT != 128
    // Scaling down the message by a correction factor to emulate using a larger q0.
    // This step is needed so we could use a scaling factor of up to 2^59 with q9 ~= 2^60.
    auto cc = ciphertext->GetCryptoContext();
    cc->EvalMultInPlace(ciphertext, correction);
    cc->GetScheme()->ModReduceInternalInPlace(ciphertext, BASE_NUM_LEVELS_TO_DROP);
#endif
}

void FHECKKSRNS::ExtendCiphertext(std::vector<DCRTPoly>& ctxtDCRTs, const CryptoContextImpl<DCRTPoly>& cc,
                                  const std::shared_ptr<DCRTPoly::Params> elementParamsRaisedPtr) const {
    // Raise each ciphertext polynomial from the small bottom RNS basis Ql = {q_0, ..., q_{compositeDegree-1}}
    // (the moduli remaining in the depleted ciphertext) to the full raised basis Q. We use the exact
    // DCRTPoly::ExpandCRTBasis (CRT reconstruction with the integer-overflow / "alpha" correction), which
    // produces the balanced representative of [c]_Ql in (-Ql/2, Ql/2].
    // All CRT tables are precomputed in CryptoParametersCKKSRNS::PrecomputeCRTTables (at cryptocontext
    // instantiation), so this function stays in full RNS.

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());
    const uint32_t sizeQl = cryptoParams->GetCompositeDegree();  // bottom moduli: source basis Ql

    const auto& paramsComplQl = cryptoParams->GetParamsModRaiseComplQl();
    if (nullptr == paramsComplQl)
        OPENFHE_THROW("The modulus-raise tables are not available (they are precomputed for compositeDegree > 1).");
    if (elementParamsRaisedPtr->GetParams().size() != sizeQl + paramsComplQl->GetParams().size())
        OPENFHE_THROW("The raised element parameters do not match the precomputed modulus-raise tables.");

    for (auto& dcrt : ctxtDCRTs) {
        // CKKS modulus raise only uses the bottom (level-0) modulus q0 = product of the first compositeDegree
        // primes (analogous to the single-prime path, which keeps only index 0). If the input ciphertext still
        // carries more towers, keep just the bottom sizeQl before extending, so the source basis matches the
        // precomputed tables (otherwise ExpandCRTBasis would index the tables out of bounds, corrupting memory).
        if (dcrt.GetNumOfElements() > sizeQl)
            dcrt.DropLastElements(dcrt.GetNumOfElements() - sizeQl);
        dcrt.ExpandCRTBasis(elementParamsRaisedPtr, paramsComplQl, cryptoParams->GetModRaiseQlHatInvModq(),
                            cryptoParams->GetModRaiseQlHatInvModqPrecon(), cryptoParams->GetModRaiseQlHatModComplq(),
                            cryptoParams->GetModRaiseAlphaQlModComplq(), cryptoParams->GetModRaiseModComplqBarrettMu(),
                            cryptoParams->GetModRaiseqInv(), Format::EVALUATION);
    }
}

void FHECKKSRNS::ApplyDoubleAngleIterations(Ciphertext<DCRTPoly>& ciphertext, uint32_t numIter) const {
    constexpr double twoPi = 2.0 * M_PI;

    auto cc = ciphertext->GetCryptoContext();

    for (int32_t i = 1 - numIter; i <= 0; ++i) {
        double scalar = -std::pow(twoPi, -std::pow(2.0, i));
        cc->EvalSquareInPlace(ciphertext);
        cc->EvalAddInPlace(ciphertext, cc->EvalAdd(ciphertext, scalar));
        cc->ModReduceInPlace(ciphertext);
    }
}

#if NATIVEINT == 128
Plaintext FHECKKSRNS::MakeAuxPlaintext(const CryptoContextImpl<DCRTPoly>& cc, const std::shared_ptr<ParmType> params,
                                       const std::vector<std::complex<double>>& value, size_t noiseScaleDeg,
                                       uint32_t level, uint32_t slots) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    double scFact = cryptoParams->GetScalingFactorReal(level);

    Plaintext p = Plaintext(std::make_shared<CKKSPackedEncoding>(params, cc.GetEncodingParams(), value, noiseScaleDeg,
                                                                 level, scFact, slots, COMPLEX));

    DCRTPoly& plainElement = p->GetElement<DCRTPoly>();

    uint32_t N = cc.GetRingDimension();

    std::vector<std::complex<double>> inverse = value;

    inverse.resize(slots);

    DiscreteFourierTransform::FFTSpecialInv(inverse, N * 2);
    uint64_t pBits = cc.GetEncodingParams()->GetPlaintextModulus();

    double powP = std::pow(2.0, MAX_DOUBLE_PRECISION);
    int32_t pCurrent = pBits - MAX_DOUBLE_PRECISION;

    std::vector<int128_t> tmp(2 * slots);
    for (uint32_t i = 0; i < slots; ++i) {
        // extract the mantissa of real part and multiply it by 2^52
        int32_t n1 = 0;
        double dre = std::frexp(inverse[i].real(), &n1) * powP;
        // extract the mantissa of imaginary part and multiply it by 2^52
        int32_t n2 = 0;
        double dim = std::frexp(inverse[i].imag(), &n2) * powP;

        // Check for possible overflow
        if (is128BitOverflow(dre) || is128BitOverflow(dim)) {
            DiscreteFourierTransform::FFTSpecial(inverse, N * 2);

            double invLen = static_cast<double>(inverse.size());
            double factor = 2 * M_PI * i;

            double realMax = -1, imagMax = -1;
            uint32_t realMaxIdx = -1, imagMaxIdx = -1;

            for (uint32_t idx = 0; idx < inverse.size(); idx++) {
                // exp( j*2*pi*n*k/N )
                std::complex<double> expFactor = {cos((factor * idx) / invLen), sin((factor * idx) / invLen)};

                // X[k] * exp( j*2*pi*n*k/N )
                std::complex<double> prodFactor = inverse[idx] * expFactor;

                double realVal = prodFactor.real();
                double imagVal = prodFactor.imag();

                if (realVal > realMax) {
                    realMax = realVal;
                    realMaxIdx = idx;
                }
                if (imagVal > imagMax) {
                    imagMax = imagVal;
                    imagMaxIdx = idx;
                }
            }

            auto scaledInputSize = std::ceil(std::log2(dre));

            std::stringstream buffer;
            buffer << std::endl
                   << "Overflow in data encoding - scaled input is too large to fit "
                      "into a NativeInteger (60 bits). Try decreasing scaling factor."
                   << std::endl;
            buffer << "Overflow at slot number " << i << std::endl;
            buffer << "- Max real part contribution from input[" << realMaxIdx << "]: " << realMax << std::endl;
            buffer << "- Max imaginary part contribution from input[" << imagMaxIdx << "]: " << imagMax << std::endl;
            buffer << "Scaling factor is " << std::ceil(std::log2(powP)) << " bits " << std::endl;
            buffer << "Scaled input is " << scaledInputSize << " bits " << std::endl;
            OPENFHE_THROW(buffer.str());
        }

        int128_t re = CKKSPackedEncoding::ScaleByPowerOfTwo(std::llround(dre), pCurrent + n1);
        int128_t im = CKKSPackedEncoding::ScaleByPowerOfTwo(std::llround(dim), pCurrent + n2);

        tmp[i] = (re < 0) ? Max128BitValue() + re : re;
        tmp[i + slots] = (im < 0) ? Max128BitValue() + im : im;

        if (is128BitOverflow(tmp[i]) || is128BitOverflow(tmp[i + slots])) {
            OPENFHE_THROW("Overflow, try to decrease scaling factor");
        }
    }

    const std::shared_ptr<ILDCRTParams<BigInteger>> bigParams = plainElement.GetParams();
    const std::vector<std::shared_ptr<ILNativeParams>>& nativeParams = bigParams->GetParams();

    for (size_t i = 0; i < nativeParams.size(); i++) {
        NativeVector nativeVec(N, nativeParams[i]->GetModulus());
        FitToNativeVector(N, tmp, Max128BitValue(), &nativeVec);
        NativePoly element = plainElement.GetElementAtIndex(i);
        element.SetValues(std::move(nativeVec), Format::COEFFICIENT);
        plainElement.SetElementAtIndex(i, std::move(element));
    }

    uint32_t numTowers = nativeParams.size();
    std::vector<DCRTPoly::Integer> moduli(numTowers);
    for (uint32_t i = 0; i < numTowers; i++) {
        moduli[i] = nativeParams[i]->GetModulus();
    }

    DCRTPoly::Integer intPowP = NativeInteger(1) << pBits;
    std::vector<DCRTPoly::Integer> crtPowP(numTowers, intPowP);

    auto currPowP = crtPowP;

    // We want to scale tmp by 2^(pd), and the loop starts from j=2
    // because tmp is already scaled by 2^p in the re/im loop above,
    // and currPowP already is 2^p.
    for (size_t i = 2; i < noiseScaleDeg; i++) {
        currPowP = CKKSPackedEncoding::CRTMult(currPowP, crtPowP, moduli);
    }

    if (noiseScaleDeg > 1) {
        plainElement = plainElement.Times(currPowP);
    }

    p->SetFormat(Format::EVALUATION);
    p->SetScalingFactor(std::pow(p->GetScalingFactor(), noiseScaleDeg));

    return p;
}
#else
Plaintext FHECKKSRNS::MakeAuxPlaintext(const CryptoContextImpl<DCRTPoly>& cc, const std::shared_ptr<ParmType> params,
                                       const std::vector<std::complex<double>>& value, size_t noiseScaleDeg,
                                       uint32_t level, uint32_t slots) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

    const double scFact = cryptoParams->GetScalingFactorReal(level);

    Plaintext p = Plaintext(std::make_shared<CKKSPackedEncoding>(params, cc.GetEncodingParams(), value, noiseScaleDeg,
                                                                 level, scFact, slots, COMPLEX));

    DCRTPoly& plainElement = p->GetElement<DCRTPoly>();

    uint32_t N = cc.GetRingDimension();

    std::vector<std::complex<double>> inverse = value;
    inverse.resize(slots);

    DiscreteFourierTransform::FFTSpecialInv(inverse, N * 2);
    double powP = scFact;

    // Compute approxFactor, a value to scale down by, in case the value exceeds a 64-bit integer.
    constexpr int32_t MAX_BITS_IN_WORD = 61;

    int32_t logc = std::numeric_limits<int32_t>::min();
    for (uint32_t i = 0; i < slots; ++i) {
        inverse[i] *= powP;
        if (inverse[i].real() != 0) {
            int32_t logci = static_cast<int32_t>(std::ceil(std::log2(std::abs(inverse[i].real()))));
            if (logc < logci)
                logc = logci;
        }
        if (inverse[i].imag() != 0) {
            int32_t logci = static_cast<int32_t>(std::ceil(std::log2(std::abs(inverse[i].imag()))));
            if (logc < logci)
                logc = logci;
        }
    }
    logc = (logc == std::numeric_limits<int32_t>::min()) ? 0 : logc;
    if (logc < 0)
        OPENFHE_THROW("Scaling factor too small");

    int32_t logValid = (logc <= MAX_BITS_IN_WORD) ? logc : MAX_BITS_IN_WORD;
    int32_t logApprox = logc - logValid;
    double approxFactor = std::pow(2, logApprox);

    std::vector<int64_t> tmp(2 * slots);

    for (uint32_t i = 0; i < slots; ++i) {
        // Scale down by approxFactor in case the value exceeds a 64-bit integer.
        double dre = inverse[i].real() / approxFactor;
        double dim = inverse[i].imag() / approxFactor;

        // Check for possible overflow
        if (is64BitOverflow(dre) || is64BitOverflow(dim)) {
            DiscreteFourierTransform::FFTSpecial(inverse, N * 2);

            double invLen = static_cast<double>(inverse.size());
            double factor = 2 * M_PI * i;

            double realMax = -1, imagMax = -1;
            uint32_t realMaxIdx = -1, imagMaxIdx = -1;

            for (uint32_t idx = 0; idx < inverse.size(); ++idx) {
                // X[k] * exp( j*2*pi*n*k/N )
                auto prodFactor = inverse[idx] * std::complex<double>{std::cos((factor * idx) / invLen),
                                                                      std::sin((factor * idx) / invLen)};

                if (prodFactor.real() > realMax) {
                    realMax = prodFactor.real();
                    realMaxIdx = idx;
                }
                if (prodFactor.imag() > imagMax) {
                    imagMax = prodFactor.imag();
                    imagMaxIdx = idx;
                }
            }

            auto scaledInputSize = std::ceil(std::log2(dre));

            std::stringstream buffer;
            buffer << std::endl
                   << "Overflow in data encoding - scaled input is too large to fit "
                      "into a NativeInteger (60 bits). Try decreasing scaling factor."
                   << std::endl;
            buffer << "Overflow at slot number " << i << std::endl;
            buffer << "- Max real part contribution from input[" << realMaxIdx << "]: " << realMax << std::endl;
            buffer << "- Max imaginary part contribution from input[" << imagMaxIdx << "]: " << imagMax << std::endl;
            buffer << "Scaling factor is " << std::ceil(std::log2(powP)) << " bits " << std::endl;
            buffer << "Scaled input is " << scaledInputSize << " bits " << std::endl;
            OPENFHE_THROW(buffer.str());
        }

        int64_t re = std::llround(dre);
        tmp[i] = (re < 0) ? Max64BitValue() + re : re;

        int64_t im = std::llround(dim);
        tmp[i + slots] = (im < 0) ? Max64BitValue() + im : im;
    }

    const auto& bigParams = plainElement.GetParams();
    const auto& nativeParams = bigParams->GetParams();

    for (size_t i = 0; i < nativeParams.size(); ++i) {
        NativeVector nativeVec(N, nativeParams[i]->GetModulus());
        FitToNativeVector(N, tmp, Max64BitValue(), &nativeVec);
        NativePoly element = plainElement.GetElementAtIndex(i);
        element.SetValues(std::move(nativeVec), Format::COEFFICIENT);
        plainElement.SetElementAtIndex(i, std::move(element));
    }

    uint32_t numTowers = nativeParams.size();
    std::vector<DCRTPoly::Integer> moduli(numTowers);
    for (uint32_t i = 0; i < numTowers; ++i) {
        moduli[i] = nativeParams[i]->GetModulus();
    }

    std::vector<DCRTPoly::Integer> crtPowP;
    if (cryptoParams->GetScalingTechnique() == COMPOSITESCALINGAUTO ||
        cryptoParams->GetScalingTechnique() == COMPOSITESCALINGMANUAL) {
        // Duhyeong: Support the case powP > 2^64
        //           Later we might need to use the NATIVE_INT=128 version of FHECKKSRNS::MakeAuxPlaintext for higher precision
        int32_t logPowP = static_cast<int32_t>(std::ceil(std::log2(std::abs(powP))));

        if (logPowP > 64) {
            // Compute approxFactor, a value to scale down by, in case the value exceeds a 64-bit integer.
            logValid = (logPowP <= LargeScalingFactorConstants::MAX_BITS_IN_WORD) ?
                               logPowP :
                               LargeScalingFactorConstants::MAX_BITS_IN_WORD;
            int32_t logApprox_PowP = logPowP - logValid;
            if (logApprox_PowP > 0) {
                int32_t logStep = (logApprox <= LargeScalingFactorConstants::MAX_LOG_STEP) ?
                                          logApprox_PowP :
                                          LargeScalingFactorConstants::MAX_LOG_STEP;
                auto intStep = DCRTPoly::Integer(1) << logStep;
                std::vector<DCRTPoly::Integer> crtApprox(numTowers, intStep);
                logApprox_PowP -= logStep;
                while (logApprox_PowP > 0) {
                    int32_t logStep = (logApprox <= LargeScalingFactorConstants::MAX_LOG_STEP) ?
                                              logApprox :
                                              LargeScalingFactorConstants::MAX_LOG_STEP;
                    auto intStep = DCRTPoly::Integer(1) << logStep;
                    std::vector<DCRTPoly::Integer> crtStep(numTowers, intStep);
                    crtApprox = CKKSPackedEncoding::CRTMult(crtApprox, crtStep, moduli);
                    logApprox_PowP -= logStep;
                }
                crtPowP = CKKSPackedEncoding::CRTMult(crtPowP, crtApprox, moduli);
            } else {
                double approxFactor = std::pow(2, logApprox_PowP);
                DCRTPoly::Integer intPowP{static_cast<uint64_t>(std::llround(powP / approxFactor))};
                crtPowP = std::vector<DCRTPoly::Integer>(numTowers, intPowP);
            }
        } else {
            DCRTPoly::Integer intPowP{static_cast<uint64_t>(std::llround(powP))};
            crtPowP = std::vector<DCRTPoly::Integer>(numTowers, intPowP);
        }
    } else {
        DCRTPoly::Integer intPowP{static_cast<uint64_t>(std::llround(powP))};
        crtPowP = std::vector<DCRTPoly::Integer>(numTowers, intPowP);
    }

    auto currPowP = crtPowP;

    // We want to scale tmp by 2^(pd), and the loop starts from j=2
    // because tmp is already scaled by 2^p in the re/im loop above,
    // and currPowP already is 2^p.
    for (size_t i = 2; i < noiseScaleDeg; ++i)
        currPowP = CKKSPackedEncoding::CRTMult(currPowP, crtPowP, moduli);
    if (noiseScaleDeg > 1)
        plainElement = plainElement.Times(currPowP);

    // Scale back up by the approxFactor to get the correct encoding.
    if (logApprox > 0) {
        int32_t logStep = (logApprox <= MAX_LOG_STEP) ? logApprox : MAX_LOG_STEP;
        auto intStep = DCRTPoly::Integer(1) << logStep;
        std::vector<DCRTPoly::Integer> crtApprox(numTowers, intStep);
        logApprox -= logStep;

        while (logApprox > 0) {
            logStep = (logApprox <= MAX_LOG_STEP) ? logApprox : MAX_LOG_STEP;
            intStep = DCRTPoly::Integer(1) << logStep;
            std::vector<DCRTPoly::Integer> crtSF(numTowers, intStep);
            crtApprox = CKKSPackedEncoding::CRTMult(crtApprox, crtSF, moduli);
            logApprox -= logStep;
        }
        plainElement = plainElement.Times(crtApprox);
    }

    p->SetFormat(Format::EVALUATION);
    p->SetScalingFactor(std::pow(p->GetScalingFactor(), noiseScaleDeg));
    return p;
}
#endif

Ciphertext<DCRTPoly> FHECKKSRNS::EvalMultExt(ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) {
    return LTRun(&LTStats::ptMult, &LTStats::tPtMult, 1, [&] {
        auto pt = plaintext->GetElement<DCRTPoly>();
        pt.SetFormat(Format::EVALUATION);
        auto result = ciphertext->Clone();
        for (auto& c : result->GetElements())
            c *= pt;
        result->SetNoiseScaleDeg(result->GetNoiseScaleDeg() + plaintext->GetNoiseScaleDeg());
        result->SetScalingFactor(result->GetScalingFactor() * plaintext->GetScalingFactor());
        return result;
    });
}

void FHECKKSRNS::EvalAddExtInPlace(Ciphertext<DCRTPoly>& ciphertext1, ConstCiphertext<DCRTPoly> ciphertext2) {
    LTRun(&LTStats::add, &LTStats::tAdd, 1, [&] {
        auto& cv1  = ciphertext1->GetElements();
        auto& cv2  = ciphertext2->GetElements();
        uint32_t n = cv1.size();
        for (uint32_t i = 0; i < n; ++i)
            cv1[i] += cv2[i];
        return 0;
    });
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalAddExt(ConstCiphertext<DCRTPoly> ciphertext1,
                                            ConstCiphertext<DCRTPoly> ciphertext2) {
    auto result = ciphertext1->Clone();
    EvalAddExtInPlace(result, ciphertext2);
    return result;
}

EvalKey<DCRTPoly> FHECKKSRNS::ConjugateKeyGen(const PrivateKey<DCRTPoly> privateKey) {
    uint32_t N = privateKey->GetPrivateElement().GetRingDimension();
    std::vector<uint32_t> vec(N);
    PrecomputeAutoMap(N, 2 * N - 1, &vec);
    const auto cc = privateKey->GetCryptoContext();
    auto pkPermuted = std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc);
    pkPermuted->SetPrivateElement(privateKey->GetPrivateElement().AutomorphismTransform(2 * N - 1, vec));
    pkPermuted->SetKeyTag(privateKey->GetKeyTag());
    return cc->GetScheme()->KeySwitchGen(privateKey, pkPermuted);
}

Ciphertext<DCRTPoly> FHECKKSRNS::Conjugate(ConstCiphertext<DCRTPoly> ciphertext,
                                           const std::map<uint32_t, EvalKey<DCRTPoly>>& evalKeyMap) {
    uint32_t N = ciphertext->GetElements()[0].GetRingDimension();
    auto algo = ciphertext->GetCryptoContext()->GetScheme();
    return algo->EvalAutomorphism(ciphertext, 2 * N - 1, evalKeyMap);
}

void FHECKKSRNS::FitToNativeVector(uint32_t ringDim, const std::vector<int64_t>& vec, int64_t bigBound,
                                   NativeVector* nativeVec) {
    if (nativeVec == nullptr)
        OPENFHE_THROW("The passed native vector is empty.");
    NativeInteger bigValueHf(bigBound >> 1);
    NativeInteger modulus(nativeVec->GetModulus());
    NativeInteger diff = bigBound - modulus;
    uint32_t dslots = vec.size();
    uint32_t gap = ringDim / dslots;
#if defined(HAVE_INT128) && NATIVEINT == 64
    // word-scaled-reciprocal reduction (one multiply per element instead of a divide);
    // unlike ComputeMu/ModMu Barrett it is valid for the full 64-bit input range.
    // The biased values are nonnegative, so the int64 -> uint64 conversion is value-preserving.
    const uint64_t q{modulus.ConvertToInt<uint64_t>()};
    const int64_t e{static_cast<int64_t>(GetMSB(q)) - 2};
    if (e >= 1) {
        const uint64_t half{static_cast<uint64_t>(bigBound) >> 1};
        const uint64_t diffR{(static_cast<uint64_t>(bigBound) - q) % q};
        const uint64_t mu{static_cast<uint64_t>((static_cast<unsigned __int128>(1) << (64 + e)) / q)};
        for (uint32_t i = 0; i < dslots; ++i) {
            const uint64_t v{static_cast<uint64_t>(vec[i])};
            uint64_t av{v};
            if (av >= q) {
                av -= static_cast<uint64_t>((static_cast<unsigned __int128>(v) * mu) >> 64 >> e) * q;
                if (av >= q)
                    av -= q;
            }
            uint64_t t{av - (diffR & (0 - static_cast<uint64_t>(v > half)))};
            t += q & (0 - (t >> 63));
            (*nativeVec)[gap * i] = t;
        }
        return;
    }
#endif
    for (uint32_t i = 0; i < dslots; ++i) {
        NativeInteger n(vec[i]);
        if (n > bigValueHf) {
            (*nativeVec)[gap * i] = n.ModSub(diff, modulus);
        } else {
            (*nativeVec)[gap * i] = n.Mod(modulus);
        }
    }
}

#if NATIVEINT == 128
void FHECKKSRNS::FitToNativeVector(uint32_t ringDim, const std::vector<int128_t>& vec, int128_t bigBound,
                                   NativeVector* nativeVec) {
    if (nativeVec == nullptr)
        OPENFHE_THROW("The passed native vector is empty.");
    NativeInteger bigValueHf((uint128_t)bigBound >> 1);
    NativeInteger modulus(nativeVec->GetModulus());
    NativeInteger diff = NativeInteger((uint128_t)bigBound) - modulus;
    uint32_t dslots = vec.size();
    uint32_t gap = ringDim / dslots;
    for (uint32_t i = 0; i < dslots; ++i) {
        NativeInteger n((uint128_t)vec[i]);
        if (n > bigValueHf) {
            (*nativeVec)[gap * i] = n.ModSub(diff, modulus);
        } else {
            (*nativeVec)[gap * i] = n.Mod(modulus);
        }
    }
}
#endif

// CKKS Functional Bootstrapping implements the tower-drop and rescaling conventions only for the
// techniques below. Composite scaling is not supported yet: it needs a level-specific scaling-factor
// chain whose rescalings are multiples of the composite degree, which the tower drops here do not follow.
// The whole 128-bit build is rejected as well, for every scaling technique: functional bootstrapping has
// no counterpart to the correction-factor scaling path that standard CKKS bootstrapping implements for
// 128 bits, and enabling the unit tests on a 128-bit build shows every case, the FIXED* modes included,
// producing silently wrong results. Supporting it is future work.
static void ValidateFBTScalingTechnique([[maybe_unused]] const std::shared_ptr<CryptoParametersCKKSRNS>& cryptoParams) {
#if NATIVEINT == 128
    OPENFHE_THROW("CKKS Functional Bootstrapping is not supported for the 128-bit build (NATIVE_SIZE == 128).");
#else
    auto st = cryptoParams->GetScalingTechnique();
    if (st != FIXEDMANUAL && st != FIXEDAUTO && st != FLEXIBLEAUTO && st != FLEXIBLEAUTOEXT &&
        st != COMPOSITESCALINGAUTO && st != COMPOSITESCALINGMANUAL)
        OPENFHE_THROW(
                "CKKS Functional Bootstrapping is supported for the FIXEDMANUAL, FIXEDAUTO, FLEXIBLEAUTO, "
                "FLEXIBLEAUTOEXT, COMPOSITESCALINGAUTO, and COMPOSITESCALINGMANUAL methods only.");
#endif
}

template <typename VectorDataType>
void FHECKKSRNS::EvalFBTSetupInternal(const CryptoContextImpl<DCRTPoly>& cc, const std::vector<VectorDataType>& coeffs,
                                      uint32_t numSlots, const BigInteger& PIn, const BigInteger& POut,
                                      const BigInteger& Bigq, const PublicKey<DCRTPoly>& pubKey,
                                      const std::vector<uint32_t>& dim1, const std::vector<uint32_t>& levelBudget,
                                      uint32_t lvlsAfterBoot, uint32_t depthLeveledComputation, size_t order) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());
    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW("CKKS Functional Bootstrapping is only supported for the Hybrid key switching method.");
    ValidateFBTScalingTechnique(cryptoParams);

    uint32_t M = cc.GetCyclotomicOrder();
    uint32_t slots = (numSlots == 0) ? M / 4 : numSlots;

    m_bootPrecomMap[slots] = std::make_shared<CKKSBootstrapPrecom>();
    auto& precom = m_bootPrecomMap[slots];

    precom->m_slots = slots;
    precom->m_variant = CKKSBootstrapPrecom::FBT;

    // even for the case of a single slot we need one level for rescaling
    uint32_t logSlots = (slots < 3) ? 1 : std::log2(slots);

    // Perform some checks on the level budget. Because the level budget is used outside this function,
    // changing it here leads to exceptions later. Alternatively, move this check outside or update all
    // the uses of levelBudget.
    if (levelBudget[0] > logSlots || levelBudget[1] > logSlots)
        OPENFHE_THROW("The level budget is too large. Please set it to be at least one and at most log(slots).");
    if (levelBudget[0] < 1 || levelBudget[1] < 1)
        OPENFHE_THROW("The level budget cannot be zero. Please set it to be at least one and at most log(slots).");

    precom->m_paramsEnc = GetCollapsedFFTParams(slots, levelBudget[0], dim1[0]);
    precom->m_paramsDec = GetCollapsedFFTParams(slots, levelBudget[1], dim1[1]);

    uint32_t m = 4 * slots;
    uint32_t mmask = m - 1;  // assumes m is power of 2

    // computes indices for all primitive roots of unity
    std::vector<uint32_t> rotGroup(slots);
    uint32_t fivePows = 1;
    for (uint32_t i = 0; i < slots; ++i) {
        rotGroup[i] = fivePows;
        fivePows *= 5;
        fivePows &= mmask;
    }

    // computes all powers of a primitive root of unity exp(2 * M_PI/m)
    std::vector<std::complex<double>> ksiPows(m + 1);
    double ak = 2 * M_PI / m;
    for (uint32_t j = 0; j < m; ++j) {
        double angle = ak * j;
        ksiPows[j].real(std::cos(angle));
        ksiPows[j].imag(std::sin(angle));
    }
    ksiPows[m] = ksiPows[0];

    auto skd = cryptoParams->GetSecretKeyDist();
    double k = GetModRaiseOverflowBound(cryptoParams, K_UNIFORM_FBT);

    auto& params = pubKey->GetPublicElements()[0].GetParams()->GetParams();
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    // The output of functional bootstrapping keeps 1 + lvlsAfterBoot levels (compositeDegree towers each), so
    // the modulus chain has to be long enough to provide them. Without this check the loop below reads past
    // the end of the params vector and the level arithmetic further down wraps around.
    uint32_t outTowers = compositeDegree * (1 + lvlsAfterBoot);
    if (outTowers > params.size())
        OPENFHE_THROW("lvlsAfterBoot (" + std::to_string(lvlsAfterBoot) +
                      ") is too large: it must be less than the number of levels (" +
                      std::to_string(params.size() / compositeDegree) + ").");

    BigInteger QPrime = params[0]->GetModulus();
    for (uint32_t i = 1; i < outTowers; ++i)
        QPrime *= params[i]->GetModulus();

    auto st = cryptoParams->GetScalingTechnique();
    uint32_t L0 = cryptoParams->GetElementParams()->GetParams().size();
    // the modes that track level-specific scaling factors (see EvalMVBPrecompute)
    const bool tracksLevelSF =
            (st == FLEXIBLEAUTO || st == FLEXIBLEAUTOEXT || st == COMPOSITESCALINGAUTO || st == COMPOSITESCALINGMANUAL);

    // pre = q / 2^round(log2 q) is the ratio between the modulus of the bottom level and the closest power of two.
    // In the FIXED* modes the message imported from RLWE keeps this ratio (the modulus switching to q is not
    // compensated), so it is folded into the encoding matrix and undone in the decoding matrix. In the modes
    // that track level-specific scaling factors, the ratio is instead removed exactly by the correction
    // 2^p/initialScaling applied after ModRaise (see EvalMVBPrecompute), so it must not be applied again here:
    // for a single prime q the difference is ~2^-30 and hence invisible, but for composite scaling q is a
    // product of small primes and can be off from a power of two by ~2^-10, which would otherwise multiply the
    // integer overflows of the modulus raise and corrupt the approximate modular reduction.
    double pre = 1.0;
    if (!tracksLevelSF) {
        // the modulus of the bottom level: a single prime, or the product of compositeDegree primes
        BigInteger q = params[0]->GetModulus();
        for (uint32_t i = 1; i < compositeDegree; ++i)
            q *= params[i]->GetModulus();
        const double qDouble = q.ConvertToDouble();
        pre = qDouble / std::ldexp(1.0, static_cast<int>(std::round(std::log2(qDouble))));
    }
    double scaleEnc = pre / k;
    double scaleMod = RatioToDouble(QPrime, Bigq * POut);
    double scaleDec = scaleMod / pre;

    // the depth of the functional bootstrapping itself, with the approximation tables of SPARSE_ENCAPSULATED
    // selected by the actual Hamming weight of its sparse secret (the same selection as in EvalMVBPrecompute)
    uint32_t depthBT = depthLeveledComputation + levelBudget[0] + levelBudget[1] +
                       AdjustDepthFBTInternal(coeffs, PIn, order, skd, cryptoParams->GetSparseKSHammingWeight());

    // compute # of levels to remain when encoding the coefficients
    // for FLEXIBLEAUTOEXT the raised ciphertext does not include the extra modulus
    if (tracksLevelSF) {
        // In the FLEXIBLE* and COMPOSITESCALING* modes, the ciphertext right after ModRaise is declared to
        // carry the exact level-specific scaling factor (so that all subsequent operations stay on the
        // precomputed scaling-factor chain), while the FBT scale bookkeeping above is done in terms of the
        // nominal power-of-two scaling factor 2^p. The two ratios below convert between the conventions:
        // - scaleEnc absorbs SF(raised level)/2^p so the values entering the Chebyshev interpolation
        //   match the nominal convention exactly;
        // - scaleDec absorbs 2^p/SF(final level) so the decoded RLWE output lands at the exact absolute
        //   scale QPrime/POut regardless of the level-specific scaling factor at the output level.
        double pow2p = std::pow(2.0, static_cast<double>(cryptoParams->GetPlaintextModulus()));
        uint32_t raisedLevel = (st == FLEXIBLEAUTOEXT) ? 1 : 0;
        // the output of functional bootstrapping has outTowers towers remaining
        uint32_t finalLevel = L0 - outTowers;
        scaleEnc *= cryptoParams->GetScalingFactorReal(raisedLevel) / pow2p;
        scaleDec *= pow2p / cryptoParams->GetScalingFactorReal(finalLevel);
    }

    L0 -= (st == FLEXIBLEAUTOEXT);

    // The encoding and decoding matrices are precomputed at the levels below, which have to exist on the
    // chain. Checking here reports the parameter that is actually wrong, instead of letting the unsigned
    // subtractions wrap and failing later inside the plaintext encoding with an unrelated message.
    if (compositeDegree * (levelBudget[0] + 1) > L0)
        OPENFHE_THROW("The encoding level budget (" + std::to_string(levelBudget[0]) +
                      ") is too large for the available number of levels (" + std::to_string(L0 / compositeDegree) +
                      ").");
    if (compositeDegree * depthBT > L0)
        OPENFHE_THROW("The functional bootstrapping depth (" + std::to_string(depthBT) +
                      ") exceeds the available number of levels (" + std::to_string(L0 / compositeDegree) +
                      "). Increase the multiplicative depth, or reduce the level budget or "
                      "depthLeveledComputation.");

    // each level consists of compositeDegree towers
    uint32_t lEnc = L0 - compositeDegree * (levelBudget[0] + 1);
    uint32_t lDec = L0 - compositeDegree * depthBT;

    bool isLTBootstrap = (levelBudget[0] == 1) && (levelBudget[1] == 1);
    if (isLTBootstrap) {
        // allocate all vectors
        std::vector<std::vector<std::complex<double>>> U0(slots, std::vector<std::complex<double>>(slots));
        std::vector<std::vector<std::complex<double>>> U1(slots, std::vector<std::complex<double>>(slots));
        std::vector<std::vector<std::complex<double>>> U0hatT(slots, std::vector<std::complex<double>>(slots));
        std::vector<std::vector<std::complex<double>>> U1hatT(slots, std::vector<std::complex<double>>(slots));

        for (uint32_t i = 0; i < slots; ++i) {
            for (uint32_t j = 0; j < slots; ++j) {
                U0[i][j] = ksiPows[(j * rotGroup[i]) & mmask];
                U0hatT[j][i] = std::conj(U0[i][j]);
                U1[i][j] = std::complex<double>(0, 1) * U0[i][j];
                U1hatT[j][i] = std::conj(U1[i][j]);
            }
        }

        if (M == m) {
            precom->m_U0hatTPre = EvalLinearTransformPrecompute(cc, U0hatT, scaleEnc, lEnc);
            precom->m_U0Pre = EvalLinearTransformPrecompute(cc, U0, scaleDec, lDec);
        } else {
            precom->m_U0hatTPre = EvalLinearTransformPrecompute(cc, U0hatT, U1hatT, 0, scaleEnc, lEnc);
            precom->m_U0Pre = EvalLinearTransformPrecompute(cc, U0, U1, 1, scaleDec, lDec);
        }
    } else {
        precom->m_U0hatTPreFFT = EvalCoeffsToSlotsPrecompute(cc, ksiPows, rotGroup, false, scaleEnc, lEnc);
        precom->m_U0PreFFT = EvalSlotsToCoeffsPrecompute(cc, ksiPows, rotGroup, false, scaleDec, lDec);
    }
}

void FHECKKSRNS::EvalFBTSetup(const CryptoContextImpl<DCRTPoly>& cc,
                              const std::vector<std::complex<double>>& coefficients, uint32_t numSlots,
                              const BigInteger& PIn, const BigInteger& POut, const BigInteger& Bigq,
                              const PublicKey<DCRTPoly>& pubKey, const std::vector<uint32_t>& dim1,
                              const std::vector<uint32_t>& levelBudget, uint32_t lvlsAfterBoot,
                              uint32_t depthLeveledComputation, size_t order) {
    EvalFBTSetupInternal(cc, coefficients, numSlots, PIn, POut, Bigq, pubKey, dim1, levelBudget, lvlsAfterBoot,
                         depthLeveledComputation, order);
}

void FHECKKSRNS::EvalFBTSetup(const CryptoContextImpl<DCRTPoly>& cc, const std::vector<int64_t>& coefficients,
                              uint32_t numSlots, const BigInteger& PIn, const BigInteger& POut, const BigInteger& Bigq,
                              const PublicKey<DCRTPoly>& pubKey, const std::vector<uint32_t>& dim1,
                              const std::vector<uint32_t>& levelBudget, uint32_t lvlsAfterBoot,
                              uint32_t depthLeveledComputation, size_t order) {
    EvalFBTSetupInternal(cc, coefficients, numSlots, PIn, POut, Bigq, pubKey, dim1, levelBudget, lvlsAfterBoot,
                         depthLeveledComputation, order);
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalHomDecoding(ConstCiphertext<DCRTPoly>& ciphertext, uint64_t postScaling,
                                                 uint32_t levelToReduce) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());
    ValidateFBTScalingTechnique(cryptoParams);

    auto ctxtEnc = ciphertext->Clone();

    // Drop levels if needed
    auto cc = ciphertext->GetCryptoContext();
    auto st = cryptoParams->GetScalingTechnique();
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();
    if (levelToReduce > 0) {
        if (st == FIXEDMANUAL) {
            cc->LevelReduceInPlace(ctxtEnc, nullptr, levelToReduce);
        } else if (st == FLEXIBLEAUTO || st == FLEXIBLEAUTOEXT || st == COMPOSITESCALINGAUTO ||
                   st == COMPOSITESCALINGMANUAL) {
            // In the FLEXIBLE* and COMPOSITESCALING* modes, towers cannot simply be dropped because the
            // ciphertext has to stay on the chain of level-specific scaling factors. As in
            // AdjustLevelsAndDepthInPlace, a single scalar multiplication adjusts the value to the scaling
            // factor of the destination level, the remaining towers are dropped directly, and the destination
            // scaling factor is set explicitly. Note that for a degree-2 input, EvalMultInPlace first rescales
            // (consuming one level, i.e., compositeDegree towers). Levels are counted in towers here.
            uint32_t dstLevel = ctxtEnc->GetLevel() + compositeDegree * levelToReduce;
            uint32_t curLevel = ctxtEnc->GetLevel() + compositeDegree * (ctxtEnc->GetNoiseScaleDeg() == 2);
            // The level-specific scaling factors are precomputed only up to the second-to-last level
            // (the accessors silently fall back for larger indices), and the rescale before
            // SlotsToCoeffs consumes one more level anyway.
            uint32_t sizeQ = cryptoParams->GetElementParams()->GetParams().size();
            if (dstLevel > sizeQ - 2 * compositeDegree)
                OPENFHE_THROW("levelToReduce is too large: the level after reduction (" + std::to_string(dstLevel) +
                              ") must be at most " + std::to_string(sizeQ - 2 * compositeDegree) + ".");
            cc->EvalMultInPlace(ctxtEnc, cryptoParams->GetScalingFactorRealBig(dstLevel) /
                                                 cryptoParams->GetScalingFactorRealBig(curLevel));
            if (dstLevel > ctxtEnc->GetLevel())
                cc->GetScheme()->LevelReduceInternalInPlace(ctxtEnc, dstLevel - ctxtEnc->GetLevel());
            ctxtEnc->SetScalingFactor(cryptoParams->GetScalingFactorRealBig(dstLevel));
        } else {
            // FIXEDAUTO uses the same scaling factor at every level, so towers can be dropped directly
            // (the public LevelReduce is a no-op for the AUTO modes).
            cc->GetScheme()->LevelReduceInternalInPlace(ctxtEnc, levelToReduce);
        }
    }

    //------------------------------------------------------------------------------
    // Running SlotsToCoeffs
    //------------------------------------------------------------------------------

    // In the case of FLEXIBLEAUTO, we need one extra tower
    if (st != FIXEDMANUAL)
        cc->GetScheme()->ModReduceInternalInPlace(ctxtEnc, compositeDegree);

    // linear transform for decoding
    auto slots = ciphertext->GetSlots();
    auto& p = GetBootPrecom(slots, CKKSBootstrapPrecom::FBT);
    auto isLTBS = (p.m_paramsEnc.lvlb == 1) && (p.m_paramsDec.lvlb == 1);
    auto ctxtDec = (isLTBS) ? EvalLinearTransform(p.m_U0Pre, ctxtEnc) : EvalSlotsToCoeffs(p.m_U0PreFFT, ctxtEnc);

    if (slots != cc->GetCyclotomicOrder() / 4) {
        //------------------------------------------------------------------------------
        // SPARSELY PACKED CASE
        //------------------------------------------------------------------------------
        cc->EvalAddInPlaceNoCheck(ctxtDec, cc->EvalRotate(ctxtDec, slots));
    }

    // Because the linear transform might be scaled differently, we might need to scale up the result separately
    // Often, this scaling addreesses the previous division in the trigonometric Hermite coefficients
    if (postScaling > 1)
        cc->GetScheme()->MultByIntegerInPlace(ctxtDec, postScaling);

    // The public ModReduce is a no-op for the AUTO scaling techniques, so the internal rescaling is
    // called explicitly to bring the result to noise degree 1 (the RLWE output convention).
    if (st == FIXEDMANUAL)
        cc->ModReduceInPlace(ctxtDec);
    else
        cc->GetScheme()->ModReduceInternalInPlace(ctxtDec, compositeDegree);

    // 64-bit only: No need to scale back the message to its original scale.
    return ctxtDec;
}

template <typename VectorDataType>
std::shared_ptr<seriesPowers<DCRTPoly>> FHECKKSRNS::EvalMVBPrecomputeInternal(
        ConstCiphertext<DCRTPoly>& ciphertext, const std::vector<VectorDataType>& coefficients, uint32_t digitBitSize,
        const BigInteger& initialScaling, size_t order) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());
    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW("CKKS Bootstrapping is only supported for the Hybrid key switching method.");

    ValidateFBTScalingTechnique(cryptoParams);
    auto st = cryptoParams->GetScalingTechnique();
    const uint32_t compositeDegree = cryptoParams->GetCompositeDegree();
    // The FLEXIBLE* and COMPOSITESCALING* modes track level-specific scaling factors and share the same
    // handling below (the correction is folded into the multiplication after ModRaise, and the raised
    // ciphertext is declared to carry the scaling factor of its level).
    const bool isFlexible =
            (st == FLEXIBLEAUTO || st == FLEXIBLEAUTOEXT || st == COMPOSITESCALINGAUTO || st == COMPOSITESCALINGMANUAL);

    // The RLWE-imported payload must not include the FLEXIBLEAUTOEXT extra modulus, so the input has
    // to be imported at least one level deep (SchemeletRLWEMP applies this offset automatically).
    if (st == FLEXIBLEAUTOEXT && ciphertext->GetLevel() == 0)
        OPENFHE_THROW(
                "For FLEXIBLEAUTOEXT, the input to CKKS Functional Bootstrapping must be at level 1 or deeper so that it "
                "does not include the extra modulus.");

    // For FLEXIBLEAUTOEXT the raised ciphertext does not include the extra modulus
    auto elementParamsRaised = *(cryptoParams->GetElementParams());
    if (st == FLEXIBLEAUTOEXT)
        elementParamsRaised.PopLastParam();

    const auto& paramsQ = elementParamsRaised.GetParams();
    uint32_t sizeQ = paramsQ.size();
    std::vector<NativeInteger> moduli(sizeQ);
    std::vector<NativeInteger> roots(sizeQ);
    for (uint32_t i = 0; i < sizeQ; ++i) {
        moduli[i] = paramsQ[i]->GetModulus();
        roots[i] = paramsQ[i]->GetRootOfUnity();
    }

    auto cc = ciphertext->GetCryptoContext();
    auto M = cc->GetCyclotomicOrder();
    auto N = cc->GetRingDimension();

    auto elementParamsRaisedPtr = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(M, moduli, roots);
    elementParamsRaisedPtr->SetRingType(paramsQ[0]->GetRingType());

    // We don't need the type of scaling and correction as in the standard CKKS bootstrapping
    // because the message doesn't have to be scaled down.
    // Instead, we need to correct the encoding if it originates from a different ciphertext
    // (not typical CKKS).
    // For FLEXIBLE* the correction is expressed w.r.t. the nominal power-of-two scaling factor 2^p
    // (the residual ratio between 2^p and the level-specific scaling factor is folded into the
    // homomorphic encoding/decoding matrices in EvalFBTSetup).
    double nominalSF = (isFlexible) ? std::pow(2.0, static_cast<double>(cryptoParams->GetPlaintextModulus())) :
                                      cryptoParams->GetScalingFactorReal(0);
    double correction = nominalSF / initialScaling.ConvertToDouble();

    //------------------------------------------------------------------------------
    // RAISING THE MODULUS
    //------------------------------------------------------------------------------

    auto raised = ciphertext->Clone();
    auto algo = cc->GetScheme();
    algo->ModReduceInternalInPlace(raised, compositeDegree * (raised->GetNoiseScaleDeg() - 1));

    // If correction ~ 1, we should not do this adjustment and save a level
    // AA: make the check more granular (around 1.0000x?)
    // For FLEXIBLE* the correction is instead folded into the multiplication by 1/(k*N) after ModRaise,
    // which does not consume an extra level.
    if (!isFlexible) {
        if (std::llround(correction) != 1.0)
            AdjustCiphertextFBT(raised, correction);
    } else {
        // The modulus raise below keeps only tower 0, so a multi-tower input (an initialScaling that
        // spans several RNS limbs, e.g. when levels are available before bootstrapping) must first be
        // brought down to a single tower by rounded rescaling. Each rescale divides the raw payload by
        // the dropped modulus, which correction absorbs, so the residual w.r.t. the nominal 2^p is
        // still folded in exactly after ModRaise. The noise scale degree is restored because the raw
        // payload is not on the CKKS scaling convention.
        while (raised->GetElements()[0].GetNumOfElements() > compositeDegree) {
            uint32_t deg = raised->GetNoiseScaleDeg();
            const auto& moduli = raised->GetElements()[0].GetParams()->GetParams();
            const size_t sizeQl = moduli.size();
            for (uint32_t j = 0; j < compositeDegree; ++j)
                correction *= moduli[sizeQl - 1 - j]->GetModulus().ConvertToDouble();
            algo->ModReduceInternalInPlace(raised, compositeDegree);
            raised->SetNoiseScaleDeg(deg);
        }
    }

    ModRaiseInPlace(raised, elementParamsRaisedPtr);

    // In the FLEXIBLE* and COMPOSITESCALING* modes, declare the raised ciphertext to carry the exact scaling
    // factor of its level, so all subsequent operations track the precomputed chain of level-specific
    // scaling factors. The ratio between this scaling factor and the nominal 2^p is compensated in the
    // homomorphic encoding matrix (see EvalFBTSetup).
    if (isFlexible)
        raised->SetScalingFactor(cryptoParams->GetScalingFactorReal(raised->GetLevel()));

#ifdef BOOTSTRAPTIMING
    auto numTowers = raised->GetElements()[0].GetNumOfElements() - 1;
    OPENFHE_DIAGNOSTIC_ERR << "\nNumber of levels at the beginning of bootstrapping: " << numTowers << "\n";
#endif

    //------------------------------------------------------------------------------
    // SETTING PARAMETERS FOR APPROXIMATE MODULAR REDUCTION
    //------------------------------------------------------------------------------

    auto skd = cryptoParams->GetSecretKeyDist();
    // the denser sparse secret of SPARSE_ENCAPSULATED (Hamming weight 64: first modulus
    // above 60 bits) uses the K = 28 approximations of SPARSE_TERNARY
    if (UsesLargeSparseKey(skd, cryptoParams->GetSparseKSHammingWeight()))
        skd = SPARSE_TERNARY;
    // number of double-angle iterations for the approximate modular reduction
    uint32_t numIter = (skd == UNIFORM_TERNARY) ? R_UNIFORM_FBT : R_SPARSE_FBT;

    // The division by the overflow bound K is part of the CoeffsToSlots matrix (see EvalFBTSetup), so only the
    // 1/N normalization of the homomorphic encoding is applied here. For the modes tracking level-specific
    // scaling factors the initial-scaling correction is folded in as well, so no extra level is consumed.
    cc->EvalMultInPlace(raised, ((isFlexible) ? correction : 1.0) / N);

    // no linear transformations are needed for Chebyshev series as the range has been normalized to [-1,1]
    double coeffLowerBound = -1.0;
    double coeffUpperBound = 1.0;

    auto slots = ciphertext->GetSlots();
    auto& p = GetBootPrecom(slots, CKKSBootstrapPrecom::FBT);
    bool isLTBootstrap = (p.m_paramsEnc.lvlb == 1) && (p.m_paramsDec.lvlb == 1);

    std::vector<Ciphertext<DCRTPoly>> ctxtEnc;
    ctxtEnc.reserve(2);
    std::shared_ptr<seriesPowers<DCRTPoly>> ctxtPowers;

    if (slots == M / 4) {
        //------------------------------------------------------------------------------
        // FULLY PACKED CASE
        //------------------------------------------------------------------------------

        //------------------------------------------------------------------------------
        // Running CoeffToSlot
        //------------------------------------------------------------------------------

        // need to call internal modular reduction so it also works for FLEXIBLEAUTO
        algo->ModReduceInternalInPlace(raised, compositeDegree);

        // only one linear transform is needed as the other one can be derived
        ctxtEnc.emplace_back((isLTBootstrap) ? EvalLinearTransform(p.m_U0hatTPre, raised) :
                                               EvalCoeffsToSlots(p.m_U0hatTPreFFT, raised));

        auto conj = Conjugate(ctxtEnc[0], cc->GetEvalAutomorphismKeyMap(ctxtEnc[0]->GetKeyTag()));

        ctxtEnc.emplace_back(cc->EvalSub(ctxtEnc[0], conj));
        cc->EvalAddInPlaceNoCheck(ctxtEnc[0], conj);
        algo->MultByMonomialInPlace(ctxtEnc[1], 3 * M / 4);

        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            while (ctxtEnc[0]->GetNoiseScaleDeg() > 1) {
                cc->ModReduceInPlace(ctxtEnc[0]);
                cc->ModReduceInPlace(ctxtEnc[1]);
            }
        } else {
            if (ctxtEnc[0]->GetNoiseScaleDeg() == 2) {
                algo->ModReduceInternalInPlace(ctxtEnc[0], compositeDegree);
                algo->ModReduceInternalInPlace(ctxtEnc[1], compositeDegree);
            }
        }

        //------------------------------------------------------------------------------
        // Computing the powers for Approximate Mod Reduction
        //------------------------------------------------------------------------------

        if (digitBitSize == 1 && order == 1) {
            auto& coeff_cos = (skd == UNIFORM_TERNARY)     ? coeff_cos_672_double_104 :
                              (skd == SPARSE_ENCAPSULATED) ? coeff_cos_16_double_50 :
                                                             coeff_cos_28_double_68;

            ctxtEnc[0] = algo->EvalChebyshevSeries(ctxtEnc[0], coeff_cos, coeffLowerBound, coeffUpperBound);
            ctxtEnc[1] = algo->EvalChebyshevSeries(ctxtEnc[1], coeff_cos, coeffLowerBound, coeffUpperBound);

            for (auto& ctxt : ctxtEnc) {
                // Double angle-iterations to get cos(pi*x)
                for (uint32_t i = 1; i < numIter; ++i) {
                    cc->EvalSquareInPlace(ctxt);
                    cc->EvalAddInPlaceNoCheck(ctxt, ctxt);
                    cc->EvalSubInPlace(ctxt, 1.0);
                    cc->ModReduceInPlace(ctxt);
                }
                // cos(pi x) after the loop above; square once more to get cos^2(pi x)
                cc->EvalSquareInPlace(ctxt);
                cc->ModReduceInPlace(ctxt);  // cos^2(pi x)
            }
        } else {
            auto& coeff_exp = (skd == UNIFORM_TERNARY)     ? coeff_exp_672_double_104 :
                              (skd == SPARSE_ENCAPSULATED) ? coeff_exp_16_double_46 :
                                                             coeff_exp_28_double_69;

            // Obtain the exp(2*Pi*i*x/2^numIter) approximation via Chebyshev Basis Polynomial Interpolation
            ctxtEnc[0] = algo->EvalChebyshevSeries(ctxtEnc[0], coeff_exp, coeffLowerBound, coeffUpperBound);
            ctxtEnc[1] = algo->EvalChebyshevSeries(ctxtEnc[1], coeff_exp, coeffLowerBound, coeffUpperBound);

            for (auto& ctxt : ctxtEnc) {
                // Double angle-iterations to get exp(2*Pi*i*x)
                for (uint32_t i = 0; i < numIter; ++i) {
                    cc->EvalSquareInPlace(ctxt);
                    cc->ModReduceInPlace(ctxt);
                }
            }
        }

        auto ctxtPowersRe = algo->EvalPowers(ctxtEnc[0], coefficients);
        auto ctxtPowersIm = algo->EvalPowers(ctxtEnc[1], coefficients);

        if (ctxtPowersRe->powers2Re.size() == 0) {
            ctxtPowers = std::make_shared<seriesPowers<DCRTPoly>>(ctxtPowersRe->powersRe, ctxtPowersIm->powersRe);
        } else {
            ctxtPowers = std::make_shared<seriesPowers<DCRTPoly>>(
                    ctxtPowersRe->powersRe, ctxtPowersRe->powers2Re, ctxtPowersRe->power2km1Re, ctxtPowersRe->k,
                    ctxtPowersRe->m, ctxtPowersIm->powersRe, ctxtPowersIm->powers2Re, ctxtPowersIm->power2km1Re);
        }
    } else {
        //------------------------------------------------------------------------------
        // SPARSELY PACKED CASE
        //------------------------------------------------------------------------------

        //------------------------------------------------------------------------------
        // Running PartialSum
        //------------------------------------------------------------------------------

        EvalPartialSumInPlace(raised, slots);

        //------------------------------------------------------------------------------
        // Running CoeffsToSlots
        //------------------------------------------------------------------------------

        algo->ModReduceInternalInPlace(raised, compositeDegree);

        ctxtEnc.emplace_back((isLTBootstrap) ? EvalLinearTransform(p.m_U0hatTPre, raised) :
                                               EvalCoeffsToSlots(p.m_U0hatTPreFFT, raised));

        auto& evalKeyMap = cc->GetEvalAutomorphismKeyMap(ctxtEnc[0]->GetKeyTag());
        cc->EvalAddInPlace(ctxtEnc[0], Conjugate(ctxtEnc[0], evalKeyMap));

        if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
            while (ctxtEnc[0]->GetNoiseScaleDeg() > 1)
                cc->ModReduceInPlace(ctxtEnc[0]);
        } else {
            if (ctxtEnc[0]->GetNoiseScaleDeg() == 2)
                algo->ModReduceInternalInPlace(ctxtEnc[0], compositeDegree);
        }

        //------------------------------------------------------------------------------
        // Running Approximate Mod Reduction
        //------------------------------------------------------------------------------

        if (digitBitSize == 1 && order == 1) {
            auto& coeff_cos = (skd == UNIFORM_TERNARY)     ? coeff_cos_672_double_104 :
                              (skd == SPARSE_ENCAPSULATED) ? coeff_cos_16_double_50 :
                                                             coeff_cos_28_double_68;

            ctxtEnc[0] = algo->EvalChebyshevSeries(ctxtEnc[0], coeff_cos, coeffLowerBound, coeffUpperBound);

            // Double angle-iterations to get cos(pi*x)
            for (uint32_t i = 1; i < numIter; ++i) {
                cc->EvalSquareInPlace(ctxtEnc[0]);
                cc->EvalAddInPlaceNoCheck(ctxtEnc[0], ctxtEnc[0]);
                cc->EvalSubInPlace(ctxtEnc[0], 1.0);
                cc->ModReduceInPlace(ctxtEnc[0]);
            }
            // cos(pi x) after the loop above; square once more to get cos^2(pi x)
            cc->EvalSquareInPlace(ctxtEnc[0]);
            cc->ModReduceInPlace(ctxtEnc[0]);  // cos^2(pi x)
        } else {
            auto& coeff_exp = (skd == UNIFORM_TERNARY)     ? coeff_exp_672_double_104 :
                              (skd == SPARSE_ENCAPSULATED) ? coeff_exp_16_double_46 :
                                                             coeff_exp_28_double_69;

            // Obtain the exp(2*Pi*i*x/2^numIter) approximation via Chebyshev Basis Polynomial Interpolation
            ctxtEnc[0] = algo->EvalChebyshevSeries(ctxtEnc[0], coeff_exp, coeffLowerBound, coeffUpperBound);

            // Double angle-iterations to get exp(2*Pi*i*x)
            for (uint32_t i = 0; i < numIter; ++i) {
                cc->EvalSquareInPlace(ctxtEnc[0]);
                cc->ModReduceInPlace(ctxtEnc[0]);
            }
        }

        // No need to scale the message back up after Chebyshev interpolation
        ctxtPowers = algo->EvalPowers(ctxtEnc[0], coefficients);
    }

    // 64-bit only: No need to scale back the message to its original scale.
    return ctxtPowers;
}

std::shared_ptr<seriesPowers<DCRTPoly>> FHECKKSRNS::EvalMVBPrecompute(
        ConstCiphertext<DCRTPoly>& ciphertext, const std::vector<std::complex<double>>& coefficients,
        uint32_t digitBitSize, const BigInteger& initialScaling, size_t order) {
    return EvalMVBPrecomputeInternal(ciphertext, coefficients, digitBitSize, initialScaling, order);
}
std::shared_ptr<seriesPowers<DCRTPoly>> FHECKKSRNS::EvalMVBPrecompute(ConstCiphertext<DCRTPoly>& ciphertext,
                                                                      const std::vector<int64_t>& coefficients,
                                                                      uint32_t digitBitSize,
                                                                      const BigInteger& initialScaling, size_t order) {
    return EvalMVBPrecomputeInternal(ciphertext, coefficients, digitBitSize, initialScaling, order);
}

template <typename VectorDataType>
Ciphertext<DCRTPoly> FHECKKSRNS::EvalMVBNoDecodingInternal(const std::shared_ptr<seriesPowers<DCRTPoly>>& ciphertexts,
                                                           const std::vector<VectorDataType>& coefficients,
                                                           uint32_t digitBitSize, size_t order) {
    const auto cryptoParams =
            std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertexts->powersRe[0]->GetCryptoParameters());
    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW("CKKS Bootstrapping is only supported for the Hybrid key switching method.");
    ValidateFBTScalingTechnique(cryptoParams);

    auto cc = ciphertexts->powersRe[0]->GetCryptoContext();
    uint32_t M4 = cc->GetCyclotomicOrder() / 4;
    uint32_t slots = ciphertexts->powersRe[0]->GetSlots();
    auto algo = cc->GetScheme();

    Ciphertext<DCRTPoly> ctxtEnc;

    if (slots == M4) {
        //------------------------------------------------------------------------------
        // FULLY PACKED CASE
        //------------------------------------------------------------------------------
        if (ciphertexts->powersIm.size() == 0)
            OPENFHE_THROW("Full packing requires powers for both the real and imaginary parts.");
        Ciphertext<DCRTPoly> ctxtEncI;

        //------------------------------------------------------------------------------
        // Running Approximate Mod Reduction using the complex explonential
        //------------------------------------------------------------------------------

        if (digitBitSize == 1 && order == 1) {
            ctxtEnc = ciphertexts->powersRe[0]->Clone();
            ctxtEncI = ciphertexts->powersIm[0]->Clone();
            // Assumes the function is integer and real!
            if (ToReal(coefficients[1]) > 0) {  // MultByInteger only works with positive integers
                algo->MultByIntegerInPlace(ctxtEnc, ToReal(coefficients[1]));
                cc->EvalAddInPlace(ctxtEnc, ToReal(coefficients[0]));
                algo->MultByIntegerInPlace(ctxtEncI, ToReal(coefficients[1]));
                cc->EvalAddInPlace(ctxtEncI, ToReal(coefficients[0]));
            } else {
                algo->MultByIntegerInPlace(ctxtEnc, -ToReal(coefficients[1]));
                ctxtEnc = cc->EvalSub(ToReal(coefficients[0]), ctxtEnc);
                algo->MultByIntegerInPlace(ctxtEncI, -ToReal(coefficients[1]));
                ctxtEncI = cc->EvalSub(ToReal(coefficients[0]), ctxtEncI);
            }
        } else {
            // Obtain the complex Hermite Trigonometric Interpolation via Power Basis Polynomial Interpolation
            // Coefficients are divided by 2
            // The repackaging below shares the precomputed ciphertexts with the caller. EvalPolyWithPrecomp
            // leaves them unmodified, so the same precomputation serves every function evaluated against it.
            std::shared_ptr<seriesPowers<DCRTPoly>> ctxtPowersRe, ctxtPowersIm;
            if (ciphertexts->powers2Re.size() == 0) {
                ctxtPowersRe = std::make_shared<seriesPowers<DCRTPoly>>(ciphertexts->powersRe);
                ctxtPowersIm = std::make_shared<seriesPowers<DCRTPoly>>(ciphertexts->powersIm);
            } else {
                ctxtPowersRe = std::make_shared<seriesPowers<DCRTPoly>>(ciphertexts->powersRe, ciphertexts->powers2Re,
                                                                        ciphertexts->power2km1Re, ciphertexts->k,
                                                                        ciphertexts->m);
                ctxtPowersIm = std::make_shared<seriesPowers<DCRTPoly>>(ciphertexts->powersIm, ciphertexts->powers2Im,
                                                                        ciphertexts->power2km1Im, ciphertexts->k,
                                                                        ciphertexts->m);
            }

            // Take the real part
            // Division by 2 was already performed
            ctxtEnc = cc->EvalPolyWithPrecomp(ctxtPowersRe, coefficients);
            cc->EvalAddInPlace(ctxtEnc, Conjugate(ctxtEnc, cc->GetEvalAutomorphismKeyMap(ctxtEnc->GetKeyTag())));
            ctxtEncI = cc->EvalPolyWithPrecomp(ctxtPowersIm, coefficients);
            cc->EvalAddInPlace(ctxtEncI, Conjugate(ctxtEncI, cc->GetEvalAutomorphismKeyMap(ctxtEnc->GetKeyTag())));
        }

        algo->MultByMonomialInPlace(ctxtEncI, M4);
        cc->EvalAddInPlace(ctxtEnc, ctxtEncI);
        // No need to scale the message back up after Chebyshev interpolation
    } else {
        //------------------------------------------------------------------------------
        // SPARSELY PACKED CASE
        //------------------------------------------------------------------------------

        //------------------------------------------------------------------------------
        // Running Approximate Mod Reduction using the complex exponential
        //------------------------------------------------------------------------------

        if (digitBitSize == 1 && order == 1) {
            ctxtEnc = ciphertexts->powersRe[0]->Clone();
            // Assumes the function is integer and real!
            if (ToReal(coefficients[1]) > 0) {  // MultByInteger only works with positive integers
                algo->MultByIntegerInPlace(ctxtEnc, ToReal(coefficients[1]));
                cc->EvalAddInPlace(ctxtEnc, ToReal(coefficients[0]));
            } else {
                algo->MultByIntegerInPlace(ctxtEnc, -ToReal(coefficients[1]));
                ctxtEnc = cc->EvalSub(ToReal(coefficients[0]), ctxtEnc);
            }
        } else {
            // Obtain the complex Hermite Trigonometric Interpolation via Power Basis Polynomial Interpolation
            // Coefficients are divided by 2
            std::shared_ptr<seriesPowers<DCRTPoly>> ctxtPowersRe;
            if (ciphertexts->powers2Re.size() == 0) {
                ctxtPowersRe = std::make_shared<seriesPowers<DCRTPoly>>(ciphertexts->powersRe);
            } else {
                ctxtPowersRe = std::make_shared<seriesPowers<DCRTPoly>>(ciphertexts->powersRe, ciphertexts->powers2Re,
                                                                        ciphertexts->power2km1Re, ciphertexts->k,
                                                                        ciphertexts->m);
            }
            ctxtEnc = cc->EvalPolyWithPrecomp(ctxtPowersRe, coefficients);

            // Take the real part
            // Division by 2 was already performed
            cc->EvalAddInPlaceNoCheck(ctxtEnc, Conjugate(ctxtEnc, cc->GetEvalAutomorphismKeyMap(ctxtEnc->GetKeyTag())));
        }

        // No need to scale the message back up after Chebyshev interpolation
    }

    // // 64-bit only: No need to scale back the message to its original scale.
    return ctxtEnc;
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalFBT(ConstCiphertext<DCRTPoly>& ciphertext,
                                         const std::vector<std::complex<double>>& coefficients, uint32_t digitBitSize,
                                         const BigInteger& initialScaling, uint64_t postScaling, uint32_t levelToReduce,
                                         size_t order) {
    return EvalHomDecoding(EvalMVBNoDecodingInternal(EvalMVBPrecomputeInternal(ciphertext, coefficients, digitBitSize,
                                                                               initialScaling, order),
                                                     coefficients, digitBitSize, order),
                           postScaling, levelToReduce);
}
Ciphertext<DCRTPoly> FHECKKSRNS::EvalFBT(ConstCiphertext<DCRTPoly>& ciphertext,
                                         const std::vector<int64_t>& coefficients, uint32_t digitBitSize,
                                         const BigInteger& initialScaling, uint64_t postScaling, uint32_t levelToReduce,
                                         size_t order) {
    return EvalHomDecoding(EvalMVBNoDecodingInternal(EvalMVBPrecomputeInternal(ciphertext, coefficients, digitBitSize,
                                                                               initialScaling, order),
                                                     coefficients, digitBitSize, order),
                           postScaling, levelToReduce);
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalFBTNoDecoding(ConstCiphertext<DCRTPoly>& ciphertext,
                                                   const std::vector<std::complex<double>>& coefficients,
                                                   uint32_t digitBitSize, const BigInteger& initialScaling,
                                                   size_t order) {
    return EvalMVBNoDecodingInternal(
            EvalMVBPrecomputeInternal(ciphertext, coefficients, digitBitSize, initialScaling, order), coefficients,
            digitBitSize, order);
}
Ciphertext<DCRTPoly> FHECKKSRNS::EvalFBTNoDecoding(ConstCiphertext<DCRTPoly>& ciphertext,
                                                   const std::vector<int64_t>& coefficients, uint32_t digitBitSize,
                                                   const BigInteger& initialScaling, size_t order) {
    return EvalMVBNoDecodingInternal(
            EvalMVBPrecomputeInternal(ciphertext, coefficients, digitBitSize, initialScaling, order), coefficients,
            digitBitSize, order);
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalMVB(const std::shared_ptr<seriesPowers<DCRTPoly>> ciphertexts,
                                         const std::vector<std::complex<double>>& coefficients, uint32_t digitBitSize,
                                         uint64_t postScaling, uint32_t levelToReduce, size_t order) {
    return EvalHomDecoding(EvalMVBNoDecodingInternal(ciphertexts, coefficients, digitBitSize, order), postScaling,
                           levelToReduce);
}
Ciphertext<DCRTPoly> FHECKKSRNS::EvalMVB(const std::shared_ptr<seriesPowers<DCRTPoly>> ciphertexts,
                                         const std::vector<int64_t>& coefficients, uint32_t digitBitSize,
                                         uint64_t postScaling, uint32_t levelToReduce, size_t order) {
    return EvalHomDecoding(EvalMVBNoDecodingInternal(ciphertexts, coefficients, digitBitSize, order), postScaling,
                           levelToReduce);
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalMVBNoDecoding(const std::shared_ptr<seriesPowers<DCRTPoly>> ciphertexts,
                                                   const std::vector<std::complex<double>>& coefficients,
                                                   uint32_t digitBitSize, size_t order) {
    return EvalMVBNoDecodingInternal(ciphertexts, coefficients, digitBitSize, order);
}
Ciphertext<DCRTPoly> FHECKKSRNS::EvalMVBNoDecoding(const std::shared_ptr<seriesPowers<DCRTPoly>> ciphertexts,
                                                   const std::vector<int64_t>& coefficients, uint32_t digitBitSize,
                                                   size_t order) {
    return EvalMVBNoDecodingInternal(ciphertexts, coefficients, digitBitSize, order);
}

template <typename VectorDataType>
Ciphertext<DCRTPoly> FHECKKSRNS::EvalHermiteTrigSeriesInternal(
        ConstCiphertext<DCRTPoly>& ciphertext, const std::vector<std::complex<double>>& coefficientsCheb, double a,
        double b, const std::vector<VectorDataType>& coefficientsHerm, size_t precomp) {
    auto cc = ciphertext->GetCryptoContext();
    auto& p = GetBootPrecom(ciphertext->GetSlots());

    auto& ctxt_exp = (precomp == 0 || precomp == 2) ? p.m_precompExp : p.m_precompExpI;
    if (precomp == 0 || precomp == 1) {
        // Obtain exp(Pi/2*i*x) approximation via Chebyshev Basis Polynomial Interpolation
        ctxt_exp = cc->EvalChebyshevSeries(ciphertext, coefficientsCheb, a, b);

        // Double angle-iterations to get exp(2*Pi*i*x)
        cc->EvalSquareInPlace(ctxt_exp);
        cc->ModReduceInPlace(ctxt_exp);
        cc->EvalSquareInPlace(ctxt_exp);
        cc->ModReduceInPlace(ctxt_exp);
    }

    // Obtain the complex Hermite Trigonometric Interpolation via Power Basis Polynomial Interpolation
    // Coefficients are divided by 2
    auto result = cc->EvalPoly(ctxt_exp, coefficientsHerm);
    // Take the real part
    // Division by 2 was already performed
    cc->EvalAddInPlaceNoCheck(result, Conjugate(result, cc->GetEvalAutomorphismKeyMap(result->GetKeyTag())));

    return result;
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalHermiteTrigSeries(ConstCiphertext<DCRTPoly>& ciphertext,
                                                       const std::vector<std::complex<double>>& coefficientsCheb,
                                                       double a, double b,
                                                       const std::vector<std::complex<double>>& coefficientsHerm,
                                                       size_t precomp) {
    return EvalHermiteTrigSeriesInternal(ciphertext, coefficientsCheb, a, b, coefficientsHerm, precomp);
}
Ciphertext<DCRTPoly> FHECKKSRNS::EvalHermiteTrigSeries(ConstCiphertext<DCRTPoly>& ciphertext,
                                                       const std::vector<std::complex<double>>& coefficientsCheb,
                                                       double a, double b, const std::vector<int64_t>& coefficientsHerm,
                                                       size_t precomp) {
    return EvalHermiteTrigSeriesInternal(ciphertext, coefficientsCheb, a, b, coefficientsHerm, precomp);
}

template <typename VectorDataType>
uint32_t FHECKKSRNS::AdjustDepthFBTInternal(const std::vector<VectorDataType>& coefficients, const BigInteger& PInput,
                                            size_t order, SecretKeyDist skd, uint32_t sparseKSHammingWeight) {
    // the denser sparse secret of SPARSE_ENCAPSULATED (Hamming weight 64: first modulus above 60 bits) uses the
    // K = 28 approximations of SPARSE_TERNARY
    if (UsesLargeSparseKey(skd, sparseKSHammingWeight))
        skd = SPARSE_TERNARY;
    auto& coeff_cos = (skd == UNIFORM_TERNARY)     ? coeff_cos_672_double_104 :
                      (skd == SPARSE_ENCAPSULATED) ? coeff_cos_16_double_50 :
                                                     coeff_cos_28_double_68;
    auto& coeff_exp = (skd == UNIFORM_TERNARY)     ? coeff_exp_672_double_104 :
                      (skd == SPARSE_ENCAPSULATED) ? coeff_exp_16_double_46 :
                                                     coeff_exp_28_double_69;
    uint32_t depth = 0;
    switch (PInput.ConvertToInt()) {
        case 2:
            if (order > 1) {
                depth += 3;
            }
            depth += GetMultiplicativeDepthByCoeffVector(coeff_cos, false);
            break;
        case 4:
            if (order == 1) {
                depth += 3;
            } else {
                depth += GetMultiplicativeDepthByCoeffVector(coefficients, true);
            }
            depth += GetMultiplicativeDepthByCoeffVector(coeff_exp, false);
            break;
        default:
            depth += GetMultiplicativeDepthByCoeffVector(coefficients, true);
            depth += GetMultiplicativeDepthByCoeffVector(coeff_exp, false);
            break;
    }
    // the number of double-angle iterations: 2 for the sparse distributions and 6 for UNIFORM_TERNARY
    depth += (skd == UNIFORM_TERNARY) ? R_UNIFORM_FBT : R_SPARSE_FBT;
    return depth;
}

template uint32_t FHECKKSRNS::AdjustDepthFBTInternal(const std::vector<int64_t>& coefficients, const BigInteger& PInput,
                                                     size_t order, SecretKeyDist skd, uint32_t sparseKSHammingWeight);
template uint32_t FHECKKSRNS::AdjustDepthFBTInternal(const std::vector<std::complex<double>>& coefficients,
                                                     const BigInteger& PInput, size_t order, SecretKeyDist skd,
                                                     uint32_t sparseKSHammingWeight);

template <typename VectorDataType>
uint32_t FHECKKSRNS::AdjustDepthFBT(const std::vector<VectorDataType>& coefficients, const BigInteger& PInput,
                                    size_t order, SecretKeyDist skd, uint32_t firstModSize) {
    return AdjustDepthFBTInternal(coefficients, PInput, order, skd,
                                  CryptoParametersCKKSRNS::SparseKSHammingWeight(firstModSize));
}

template uint32_t FHECKKSRNS::AdjustDepthFBT(const std::vector<int64_t>& coefficients, const BigInteger& PInput,
                                             size_t order, SecretKeyDist skd, uint32_t firstModSize);
template uint32_t FHECKKSRNS::AdjustDepthFBT(const std::vector<std::complex<double>>& coefficients,
                                             const BigInteger& PInput, size_t order, SecretKeyDist skd,
                                             uint32_t firstModSize);

template <typename VectorDataType>
uint32_t FHECKKSRNS::GetFBTDepth(const std::vector<uint32_t>& levelBudget,
                                 const std::vector<VectorDataType>& coefficients, const BigInteger& PInput,
                                 size_t order, SecretKeyDist skd, uint32_t firstModSize) {
    return levelBudget[0] + levelBudget[1] + AdjustDepthFBT(coefficients, PInput, order, skd, firstModSize);
}

template uint32_t FHECKKSRNS::GetFBTDepth(const std::vector<uint32_t>& levelBudget,
                                          const std::vector<int64_t>& coefficients, const BigInteger& PInput,
                                          size_t order, SecretKeyDist skd, uint32_t firstModSize);
template uint32_t FHECKKSRNS::GetFBTDepth(const std::vector<uint32_t>& levelBudget,
                                          const std::vector<std::complex<double>>& coefficients,
                                          const BigInteger& PInput, size_t order, SecretKeyDist skd,
                                          uint32_t firstModSize);

void FHECKKSRNS::ModRaiseInPlace(Ciphertext<DCRTPoly>& raised,
                                 const std::shared_ptr<DCRTPoly::Params>& elementParamsRaisedPtr) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(raised->GetCryptoParameters());
    auto cc = raised->GetCryptoContext();
    const uint32_t N = cc->GetRingDimension();
    const uint32_t L0 = cryptoParams->GetElementParams()->GetParams().size();
    const bool isEncapsulated = (cryptoParams->GetSecretKeyDist() == SPARSE_ENCAPSULATED);

    auto* evalKeyMap = isEncapsulated ? &cc->GetEvalAutomorphismKeyMap(raised->GetKeyTag()) : nullptr;
    if (isEncapsulated) {
        // transform from a denser secret to a sparser one (over the bottom basis)
        raised = KeySwitchSparse(raised, evalKeyMap->at(2 * N - 4));
    }

    auto& ctxtDCRTs = raised->GetElements();
    if (cryptoParams->GetCompositeDegree() > 1) {
        // exact RNS basis extension from the compositeDegree bottom RNS limbs to the raised RNS basis
        ExtendCiphertext(ctxtDCRTs, *cc, elementParamsRaisedPtr);
    } else {
        // Only level 0 ciphertext used here. Other towers ignored to make CKKS bootstrapping faster.
        for (auto& dcrt : ctxtDCRTs) {
            dcrt.SetFormat(COEFFICIENT);
            DCRTPoly tmp(dcrt.GetElementAtIndex(0), elementParamsRaisedPtr);
            tmp.SetFormat(EVALUATION);
            dcrt = std::move(tmp);
        }
    }
    raised->SetLevel(L0 - ctxtDCRTs[0].GetNumOfElements());

    if (isEncapsulated) {
        // go back to a denser secret (KeySwitchSparse preserves the key tag, so the map above still applies)
        cc->GetScheme()->KeySwitchInPlace(raised, evalKeyMap->at(2 * N - 2));
    }
}

namespace {
// Extends a polynomial given over (at least) the bottom basis Ql = {q_0, ..., q_{d-1}} of sparse encapsulation
// to the auxiliary basis P'. For a single limb the centered lift (SwitchModulus) is the exact CRT basis
// extension; for several limbs the exact (HPS-style) CRT basis switch is used. Returns the P' limbs in
// EVALUATION format.
DCRTPoly ExtendSparseKSToP(const DCRTPoly& xBottom, const std::shared_ptr<CryptoParametersCKKSRNS>& cryptoParams) {
    const auto& paramsP = cryptoParams->GetSparseKSParamsP();
    const auto& paramsQl = cryptoParams->GetSparseKSParamsQ();
    const size_t sizeQl = paramsQl->GetParams().size();
    const size_t sizeP = paramsP->GetParams().size();

    DCRTPoly xQl(xBottom);
    xQl.SetFormat(Format::COEFFICIENT, DCRTPoly::THREADS_CRT_BASIS_SWITCH);

    DCRTPoly xP;
    if (sizeQl == 1) {
        xP = DCRTPoly(paramsP, Format::COEFFICIENT, false);
        auto poly = xQl.GetElementAtIndex(0);
        for (size_t j = 0; j < sizeP; ++j) {
            auto polyP = poly;
            polyP.SwitchModulus(paramsP->GetParams()[j]->GetModulus(), paramsP->GetParams()[j]->GetRootOfUnity(), 0, 0);
            xP.SetElementAtIndex(j, std::move(polyP));
        }
    } else {
        // [(Ql/q_i)^{-1}]_{q_i} and 1/q_i are shared with the composite scaling modulus raise
        const auto& QlHatInvModq = cryptoParams->GetModRaiseQlHatInvModq();
        if (QlHatInvModq.size() != sizeQl)
            OPENFHE_THROW("The modulus-raise tables needed for the sparse key switching are not available.");
        xP = xQl.SwitchCRTBasis(paramsP, QlHatInvModq, cryptoParams->GetModRaiseQlHatInvModqPrecon(),
                                cryptoParams->GetSparseKSQlHatModp(), cryptoParams->GetSparseKSAlphaQlModp(),
                                cryptoParams->GetSparseKSModpBarrettMu(), cryptoParams->GetModRaiseqInv());
    }
    xP.SetFormat(Format::EVALUATION, DCRTPoly::THREADS_CRT_BASIS_SWITCH);
    return xP;
}

// Builds the element over Ql*P' whose Ql limbs are the bottom limbs of x and whose P' limbs are the
// exact extension of x to P' (all in EVALUATION format).
DCRTPoly ExtendSparseKSToQP(const DCRTPoly& x, const std::shared_ptr<CryptoParametersCKKSRNS>& cryptoParams) {
    const auto& paramsqp = cryptoParams->GetSparseKSParamsQP();
    const size_t sizeQl = cryptoParams->GetSparseKSParamsQ()->GetParams().size();
    const size_t sizeQP = paramsqp->GetParams().size();

    DCRTPoly xQl = x.CloneTowers(0, static_cast<uint32_t>(sizeQl) - 1);
    DCRTPoly xP = ExtendSparseKSToP(xQl, cryptoParams);
    xQl.SetFormat(Format::EVALUATION, DCRTPoly::THREADS_CRT_BASIS_SWITCH);

    DCRTPoly xExt(paramsqp, Format::EVALUATION, false);
    auto& ext = xExt.GetAllElements();
    for (size_t i = 0; i < sizeQl; ++i)
        ext[i] = std::move(xQl.GetAllElements()[i]);
    for (size_t j = sizeQl; j < sizeQP; ++j)
        ext[j] = std::move(xP.GetAllElements()[j - sizeQl]);
    return xExt;
}
}  // namespace

template <typename VectorDataType>
uint32_t FHECKKSRNS::GetFEFBTDepth(const std::vector<uint32_t>& levelBudget,
                                   const std::vector<VectorDataType>& coefficients, SecretKeyDist skd,
                                   uint32_t firstModSize) {
    // the denser sparse secret of SPARSE_ENCAPSULATED (Hamming weight 64: first modulus
    // above 60 bits) uses the K = 28 exponential table of SPARSE_TERNARY (see EvalFEFuncBootstrapSetup)
    const bool sparseTable = (skd == SPARSE_TERNARY) ||
                             UsesLargeSparseKey(skd, CryptoParametersCKKSRNS::SparseKSHammingWeight(firstModSize));
    const auto& coeff_exp = (skd == UNIFORM_TERNARY) ? coeff_exp_696_double_27 :
                            sparseTable              ? coeff_exp_28_double_48 :
                                                       coeff_exp_16_double_23;
    const uint32_t expDepth = GetMultiplicativeDepthByCoeffVector(coeff_exp, false);
    const uint32_t rFunc = (skd == UNIFORM_TERNARY) ? R_func_696_double_27 :
                           sparseTable              ? R_func_28_double_48 :
                                                      R_func_16_double_23;
    return levelBudget[0] + levelBudget[1] + expDepth + rFunc + GetMultiplicativeDepthByCoeffVector(coefficients, true);
}

template uint32_t FHECKKSRNS::GetFEFBTDepth(const std::vector<uint32_t>& levelBudget,
                                            const std::vector<int64_t>& coefficients, SecretKeyDist skd,
                                            uint32_t firstModSize);
template uint32_t FHECKKSRNS::GetFEFBTDepth(const std::vector<uint32_t>& levelBudget,
                                            const std::vector<std::complex<double>>& coefficients, SecretKeyDist skd,
                                            uint32_t firstModSize);

EvalKey<DCRTPoly> FHECKKSRNS::KeySwitchGenSparse(const PrivateKey<DCRTPoly>& oldPrivateKey,
                                                 const PrivateKey<DCRTPoly>& newPrivateKey) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(newPrivateKey->GetCryptoParameters());

    // Params for Ql*P', where Ql is the bottom basis (compositeDegree limbs) and P' is the auxiliary
    // modulus for sparse encapsulation (generated in CryptoParametersCKKSRNS::PrecomputeCRTTables)
    const auto& paramsqp = cryptoParams->GetSparseKSParamsQP();
    if (nullptr == paramsqp)
        OPENFHE_THROW("The sparse key switching tables are only precomputed for SPARSE_ENCAPSULATED.");

    const size_t sizeQl = cryptoParams->GetSparseKSParamsQ()->GetParams().size();
    const size_t sizeQP = paramsqp->GetParams().size();
    const auto& PModq = cryptoParams->GetSparseKSPModq();

    // creates the old and new keys in Ql*P'
    DCRTPoly sOldExt = ExtendSparseKSToQP(oldPrivateKey->GetPrivateElement(), cryptoParams);
    DCRTPoly sNewExt = ExtendSparseKSToQP(newPrivateKey->GetPrivateElement(), cryptoParams);

    DugType dug;
    DCRTPoly a(dug, paramsqp, Format::EVALUATION);
    DCRTPoly e(cryptoParams->GetDiscreteGaussianGenerator(), paramsqp, Format::EVALUATION);
    DCRTPoly b(paramsqp, Format::EVALUATION, false);

    // computes the switching key for the GHS case: b = -a*sNew + P'*sOld + e over Ql*P';
    // as [P']_{p'_j} = 0, the P'*sOld term only contributes modulo the limbs of Ql
    for (size_t i = 0; i < sizeQl; ++i)
        b.SetElementAtIndex(i, -a.GetElementAtIndex(i) * sNewExt.GetElementAtIndex(i) +
                                       PModq[i] * sOldExt.GetElementAtIndex(i) + e.GetElementAtIndex(i));
    for (size_t j = sizeQl; j < sizeQP; ++j)
        b.SetElementAtIndex(j, -a.GetElementAtIndex(j) * sNewExt.GetElementAtIndex(j) + e.GetElementAtIndex(j));

    auto ek(std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(newPrivateKey->GetCryptoContext()));
    std::vector<DCRTPoly> avExt;
    avExt.push_back(std::move(a));
    ek->SetAVector(std::move(avExt));
    std::vector<DCRTPoly> bvExt;
    bvExt.push_back(std::move(b));
    ek->SetBVector(std::move(bvExt));
    ek->SetKeyTag(newPrivateKey->GetKeyTag());
    return ek;
}

Ciphertext<DCRTPoly> FHECKKSRNS::KeySwitchSparse(Ciphertext<DCRTPoly>& ciphertext, const EvalKey<DCRTPoly>& ek) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertext->GetCryptoParameters());

    const auto& paramsP = cryptoParams->GetSparseKSParamsP();
    const auto& paramsQl = cryptoParams->GetSparseKSParamsQ();
    if (nullptr == paramsP)
        OPENFHE_THROW("The sparse key switching tables are only precomputed for SPARSE_ENCAPSULATED.");

    const size_t sizeP = paramsP->GetParams().size();
    const size_t sizeQl = paramsQl->GetParams().size();

    auto& cv = ciphertext->GetElements();

    // only the bottom basis Ql of the ciphertext is used (the other towers are ignored, as in the modulus raise)
    DCRTPoly c0Ql = cv[0].CloneTowers(0, static_cast<uint32_t>(sizeQl) - 1);
    c0Ql.SetFormat(Format::EVALUATION);

    // extend cv[1] from Ql to Ql*P'
    DCRTPoly c1Ext = ExtendSparseKSToQP(cv[1], cryptoParams);

    // multiply by the evaluation key
    std::vector<DCRTPoly> cvRes{c1Ext * ek->GetBVector()[0], c1Ext * ek->GetAVector()[0]};

    // modswitch cvRes from Ql*P' to Ql, i.e., compute round(cvRes/P') mod Ql.
    // In RNS, we use the technique described in Appendix B.2.2 of https://eprint.iacr.org/2021/204
    // for the BFV case, i.e., for t=1. The balanced representative of [cvRes]_{P'} is computed
    // with the exact (HPS-style) CRT basis switch, which applies the floating-point overflow
    // correction instead of dropping the alpha*P' term, so the modulus switch only adds the
    // centered rounding noise.
    const auto& PInvModq = cryptoParams->GetSparseKSPInvModq();
    for (uint32_t i = 0; i < 2; ++i) {
        DCRTPoly partP(paramsP, Format::COEFFICIENT, false);
        for (size_t j = 0; j < sizeP; ++j) {
            auto polyP = cvRes[i].GetElementAtIndex(sizeQl + j);
            polyP.SetFormat(Format::COEFFICIENT);
            partP.SetElementAtIndex(j, std::move(polyP));
        }
        // exact switch of the balanced [cvRes]_{P'} to the basis Ql
        auto partPModq = partP.SwitchCRTBasis(
                paramsQl, cryptoParams->GetSparseKSPHatInvModp(), cryptoParams->GetSparseKSPHatInvModpPrecon(),
                cryptoParams->GetSparseKSPHatModq(), cryptoParams->GetSparseKSAlphaPModq(),
                cryptoParams->GetSparseKSModqBarrettMu(), cryptoParams->GetSparseKSpInv());
        partPModq.SetFormat(Format::EVALUATION, DCRTPoly::THREADS_CRT_BASIS_SWITCH);

        cvRes[i].DropLastElements(sizeP);
        auto& res = cvRes[i].GetAllElements();
        const auto& partQ = partPModq.GetAllElements();
        for (size_t l = 0; l < sizeQl; ++l) {
            res[l] -= partQ[l];
            res[l] *= PInvModq[l];
        }
    }

    // add to the original ciphertext
    cvRes[0] += c0Ql;

    auto result = ciphertext->CloneEmpty();
    result->SetElements(std::move(cvRes));
    return result;
}

}  // namespace lbcrypto
