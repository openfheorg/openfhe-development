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

/*
  Tests that the approximate CRT basis conversions of DCRTPoly use signed remainders (issue 913)
 */

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "lattice/lat-hal.h"
#include "math/math-hal.h"
#include "math/nbtheory.h"
#include "utils/parallel.h"

using namespace lbcrypto;

namespace {

BigInteger Big(const NativeInteger& x) {
    return BigInteger(std::to_string(x.ConvertToInt<uint64_t>()));
}

// the count largest primes below 2^bits that are 1 modulo m and smaller than below (if below is not zero)
std::vector<NativeInteger> Primes(uint32_t count, uint32_t bits, uint64_t m, const NativeInteger& below = 0) {
    std::vector<NativeInteger> v;
    NativeInteger x =
            (below == NativeInteger(0)) ? LastPrime<NativeInteger>(bits, m) : PreviousPrime<NativeInteger>(below, m);
    for (uint32_t i = 0; i < count; ++i) {
        v.push_back(x);
        x = PreviousPrime<NativeInteger>(x, m);
    }
    return v;
}

// uniform residues from a fixed seed
DCRTPoly RandomPoly(const std::shared_ptr<DCRTPoly::Params>& params, uint64_t seed) {
    DCRTPoly x(params, Format::COEFFICIENT, true);
    std::mt19937_64 g(seed);
    const uint32_t n = params->GetRingDimension();
    for (uint32_t i = 0; i < x.GetNumOfElements(); ++i) {
        NativePoly t(x.GetElementAtIndex(i));
        const uint64_t qi = t.GetModulus().ConvertToInt<uint64_t>();
        for (uint32_t r = 0; r < n; ++r)
            t[r] = NativeInteger(g() % qi);
        x.SetElementAtIndex(i, t);
    }
    return x;
}

std::vector<DoubleNativeInt> BarrettMu128(const std::vector<NativeInteger>& p) {
    std::vector<DoubleNativeInt> mu;
    for (const auto& pj : p)
        mu.push_back(~static_cast<DoubleNativeInt>(0) / pj.ConvertToInt<uint64_t>());
    return mu;
}

}  // namespace

// ApproxSwitchCRTBasis returns X + e * Q, with X the centered representative of the input and e the overflow of the
// conversion. With l source towers and signed remainders, |e| <= floor(l/2) and e has no mean; unsigned remainders
// give e in [0, l] with mean l/2. The routine has two code paths chosen by the thread count, which must agree.
TEST(UTCRTBasisExtension, ApproxSwitchCRTBasis_centered) {
    const uint32_t n = 1 << 10;
    const uint64_t m = 2 * n;
    // source towers, target towers, source bits, target bits
    const std::vector<std::vector<uint32_t>> shapes{{1, 3, 60, 60}, {2, 4, 60, 60}, {3, 8, 60, 60},
                                                    {5, 5, 60, 60}, {8, 6, 60, 60}, {16, 4, 60, 60},
                                                    {4, 3, 60, 30}, {7, 2, 30, 60}, {6, 3, 45, 35}};
    for (const auto& shape : shapes) {
        const uint32_t l = shape[0], k = shape[1];
        const std::string msg = "source towers " + std::to_string(l) + ", target towers " + std::to_string(k) +
                                ", bits " + std::to_string(shape[2]) + " -> " + std::to_string(shape[3]);
        const auto q = Primes(l, shape[2], m);
        const auto p = Primes(k, shape[3], m, (shape[2] == shape[3]) ? q.back() : NativeInteger(0));
        auto paramsQ = std::make_shared<DCRTPoly::Params>(m, q);
        auto paramsP = std::make_shared<DCRTPoly::Params>(m, p);

        std::vector<NativeInteger> QHatModq(l), QHatInvModq(l), QHatInvModqPrecon(l);
        std::vector<std::vector<NativeInteger>> QHatModp(l, std::vector<NativeInteger>(k));
        for (uint32_t i = 0; i < l; ++i) {
            QHatModq[i] = 1;
            for (uint32_t t = 0; t < l; ++t)
                if (t != i)
                    QHatModq[i] = QHatModq[i].ModMul(q[t].Mod(q[i]), q[i]);
            QHatInvModq[i] = QHatModq[i].ModInverse(q[i]);
            QHatInvModqPrecon[i] = QHatInvModq[i].PrepModMulConst(q[i]);
            for (uint32_t j = 0; j < k; ++j) {
                QHatModp[i][j] = 1;
                for (uint32_t t = 0; t < l; ++t)
                    if (t != i)
                        QHatModp[i][j] = QHatModp[i][j].ModMul(q[t].Mod(p[j]), p[j]);
            }
        }
        const auto mu = BarrettMu128(p);

        // coefficients 0 and 1 sit on the two sides of the sign threshold in every tower: the scaled residue
        // [x_i * (Q/q_i)^-1]_{q_i} is floor(q_i/2) in coefficient 0 and floor(q_i/2) + 1 in coefficient 1
        DCRTPoly x = RandomPoly(paramsQ, 913 + 100 * l + k);
        for (uint32_t i = 0; i < l; ++i) {
            NativePoly t(x.GetElementAtIndex(i));
            const NativeInteger half(q[i] >> 1);
            t[0] = half.ModMul(QHatModq[i], q[i]);
            t[1] = (half + NativeInteger(1)).ModMul(QHatModq[i], q[i]);
            x.SetElementAtIndex(i, t);
        }

        const int threads = OpenFHEParallelControls.GetNumThreads();
        OpenFHEParallelControls.SetNumThreads(1);
        const DCRTPoly y1 = x.ApproxSwitchCRTBasis(paramsQ, paramsP, QHatInvModq, QHatInvModqPrecon, QHatModp, mu);
        OpenFHEParallelControls.SetNumThreads(threads);
        const DCRTPoly y = x.ApproxSwitchCRTBasis(paramsQ, paramsP, QHatInvModq, QHatInvModqPrecon, QHatModp, mu);
        EXPECT_EQ(y1, y) << msg << ": the result depends on the number of threads";

        const auto big = x.CRTInterpolate();
        const BigInteger Q = big.GetModulus();
        const BigInteger halfQ = Q >> 1;
        std::vector<BigInteger> pBig(k);
        std::vector<NativeInteger> QModp(k), QInvModp(k);
        for (uint32_t j = 0; j < k; ++j) {
            pBig[j] = Big(p[j]);
            QModp[j] = NativeInteger(Q.Mod(pBig[j]).ConvertToInt<uint64_t>());
            QInvModp[j] = QModp[j].ModInverse(p[j]);
        }
        const int64_t bound = l / 2;
        double sum = 0;
        uint32_t outside = 0, inconsistent = 0;
        for (uint32_t r = 0; r < n; ++r) {
            const BigInteger X = big[r];
            const bool negative = X > halfQ;
            int64_t e = 0;
            for (uint32_t j = 0; j < k; ++j) {
                NativeInteger c(X.Mod(pBig[j]).ConvertToInt<uint64_t>());
                if (negative)
                    c.ModSubEq(QModp[j], p[j]);
                const uint64_t pj = p[j].ConvertToInt<uint64_t>();
                const uint64_t eu =
                        y.GetElementAtIndex(j)[r].ModSub(c, p[j]).ModMul(QInvModp[j], p[j]).ConvertToInt<uint64_t>();
                const int64_t ej = (eu > (pj >> 1)) ? -static_cast<int64_t>(pj - eu) : static_cast<int64_t>(eu);
                if (j == 0)
                    e = ej;
                else if (ej != e)
                    ++inconsistent;
            }
            if (std::llabs(e) > bound)
                ++outside;
            if (r > 1)
                sum += static_cast<double>(e);
        }
        EXPECT_EQ(inconsistent, 0U) << msg << ": the target towers do not hold one integer";
        EXPECT_EQ(outside, 0U) << msg << ": overflow beyond floor(l/2)";
        EXPECT_LT(std::fabs(sum / (n - 2)), 0.25) << msg << ": the overflow has a mean";
    }
}

// ApproxScaleAndRound returns t/Q * X minus the fractional parts it drops, sum_i x_i * theta_i over the towers of Q
// with theta_i in [0, 1). With signed residues x_i that error is within (sum_i q_i)/2 in size and has no mean;
// unsigned residues give an error in [0, sum_i q_i).
TEST(UTCRTBasisExtension, ApproxScaleAndRound_centered) {
    const uint32_t n = 1 << 10;
    const uint64_t m = 2 * n;
    const NativeInteger t(65537);
    for (uint32_t sizeQ : {1, 2, 4}) {
        const uint32_t sizeP = sizeQ + 2;
        const std::string msg = "towers of Q " + std::to_string(sizeQ);
        auto s = Primes(sizeQ + sizeP, 60, m);
        const std::vector<NativeInteger> p(s.begin() + sizeQ, s.end());
        auto paramsQP = std::make_shared<DCRTPoly::Params>(m, s);
        auto paramsP = std::make_shared<DCRTPoly::Params>(m, p);

        BigInteger Q(1), P(1);
        double halfSumQ = 0;
        for (uint32_t i = 0; i < sizeQ; ++i) {
            Q = Q * Big(s[i]);
            halfSumQ += s[i].ConvertToDouble() / 2;
        }
        for (const auto& pj : p)
            P = P * Big(pj);
        const BigInteger S = Q * P;
        const BigInteger tP = Big(t) * P;

        // table[j][i] = floor(t * P * [(S/s_i)^-1]_{s_i} / s_i) mod p_j for the towers of Q, and the same (exact)
        // quotient for tower j of P in the last entry
        std::vector<std::vector<NativeInteger>> table(sizeP, std::vector<NativeInteger>(sizeQ + 1));
        for (uint32_t j = 0; j < sizeP; ++j) {
            for (uint32_t i = 0; i <= sizeQ; ++i) {
                const NativeInteger& si = (i < sizeQ) ? s[i] : p[j];
                const NativeInteger SHatModsi((S.DividedBy(Big(si))).Mod(Big(si)).ConvertToInt<uint64_t>());
                const BigInteger quotient = (tP * Big(SHatModsi.ModInverse(si))).DividedBy(Big(si));
                table[j][i] = NativeInteger(quotient.Mod(Big(p[j])).ConvertToInt<uint64_t>());
            }
        }

        const DCRTPoly x = RandomPoly(paramsQP, 237 + sizeQ);
        const DCRTPoly y = x.ApproxScaleAndRound(paramsP, table, BarrettMu128(p));

        // t * X - Q * y = Q * error modulo Q * P
        const auto bigX = x.CRTInterpolate();
        const auto bigY = y.CRTInterpolate();
        const BigInteger halfS = S >> 1;
        const double scale = Q.ConvertToDouble() * halfSumQ;
        double sum = 0;
        uint32_t outside = 0;
        for (uint32_t r = 0; r < n; ++r) {
            const BigInteger d = (Big(t) * bigX[r]).Mod(S).ModSub((Q * bigY[r]).Mod(S), S);
            const double e = (d > halfS) ? -(S - d).ConvertToDouble() / scale : d.ConvertToDouble() / scale;
            if (std::fabs(e) > 1.0 + 1e-9)
                ++outside;
            sum += e;
        }
        EXPECT_EQ(outside, 0U) << msg << ": error beyond half the sum of the moduli of Q";
        EXPECT_LT(std::fabs(sum / n), 0.1) << msg << ": the error has a mean";
    }
}
