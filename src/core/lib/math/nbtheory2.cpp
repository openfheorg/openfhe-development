//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
  This code provides number theory utilities that are not templated by Integer or Vector
 */

#define _USE_MATH_DEFINES

#include "config_core.h"

#include "math/math-hal.h"
#include "math/distributiongenerator.h"
#include "math/nbtheory.h"

#include "utils/debug.h"

// #include <time.h>
// #include <chrono>
#include <cmath>
// #include <sstream>
#include <vector>

namespace lbcrypto {

#ifdef WITH_NTL
// native NTL version
NTL::myZZ RNG(const NTL::myZZ& modulus) {
    return RandomBnd(modulus);
}

// define an NTL native implementation
NTL::myZZ GreatestCommonDivisor(const NTL::myZZ& a, const NTL::myZZ& b) {
    return GCD(a, b);
}

// NTL native version
bool MillerRabinPrimalityTest(const NTL::myZZ& p, const usint niter) {
    if (p < NTL::myZZ(2) || ((p != NTL::myZZ(2)) && (p.Mod(NTL::myZZ(2)) == NTL::myZZ(0))))
        return false;
    if (p == NTL::myZZ(2) || p == NTL::myZZ(3) || p == NTL::myZZ(5))
        return true;
    return static_cast<bool>(ProbPrime(p, niter));  // TODO: check to see if niter >maxint
}
#endif

/*
        Finds multiplicative inverse using the Extended Euclid Algorithms
*/
usint ModInverse(usint a, usint b) {
    // usint b0 = b;
    usint t, q;
    usint x0 = 0, x1 = 1;
    if (b == 1)
        return 1;
    while (a > 1) {
        q = a / b;
        t = b, b = a % b, a = t;
        t = x0, x0 = x1 - q * x0, x1 = t;
    }
    // if (x1 < 0) x1 += b0;
    // TODO: x1 is never < 0

    return x1;
}

uint64_t GetTotient(const uint64_t n) {
    std::set<NativeInteger> factors;
    NativeInteger enn(n);
    PrimeFactorize(enn, factors);

    NativeInteger primeProd(1);
    NativeInteger numerator(1);
    for (auto& r : factors) {
        numerator = numerator * (r - 1);
        primeProd = primeProd * r;
    }

    primeProd = (enn / primeProd) * numerator;
    return primeProd.ConvertToInt();
}

std::vector<int> GetCyclotomicPolynomialRecursive(usint m) {
    auto IsPrime = [](usint val) {
        if (val % 2 == 0)
            return false;
        for (usint i = 3; i < val; i += 2) {
            if (val % i == 0)
                return false;
        }
        return true;
    };

    auto GetDivisibleNumbers = [](usint val) {
        std::vector<usint> div;
        for (usint i = 1; i < val; i++) {
            if (val % i == 0)
                div.push_back(i);
        }
        return div;
    };

    auto PolyMult = [](const std::vector<int>& a, const std::vector<int>& b) {
        usint degreeA(a.size());
        usint degreeB(b.size());
        usint degreeResultant(degreeA + degreeB - 1);
        std::vector<int> product(degreeResultant, 0);
        for (usint i = 0; i < degreeA; ++i) {
            for (usint j = 0; j < degreeB; ++j)
                product[i + j] += a[i] * b[j];
        }
        return product;
    };

    auto PolyQuotient = [](const std::vector<int>& dividend, const std::vector<int>& divisor) {
        usint divisorLength(divisor.size());
        usint dividendLength(dividend.size());
        usint runs(dividendLength - divisorLength + 1);
        std::vector<int> quotient(runs + 1);
        std::vector<int> runningDividend(dividend);
        for (usint i = 0; i < runs; ++i) {
            // get the highest degree coeff
            int divConst     = runningDividend[dividendLength - 1];
            usint divisorPtr = divisorLength - 1;
            for (usint j = 0; j < dividendLength - i - 1; ++j) {
                auto& rdtmp1 = runningDividend[dividendLength - 1 - j];
                rdtmp1       = runningDividend[dividendLength - 2 - j];
                if (divisorPtr > j)
                    rdtmp1 -= (divisor[divisorPtr - 1 - j] * divConst);
            }
            quotient[i + 1] = runningDividend[dividendLength - 1];
        }
        // under the assumption that both dividend and divisor are monic
        quotient[0] = 1;
        quotient.pop_back();
        return quotient;
    };

    if (m == 1)
        return std::vector<int>{-1, 1};
    if (m == 2)
        return std::vector<int>{1, 1};
    if (IsPrime(m))
        return std::vector<int>(m, 1);

    auto divisibleNumbers = GetDivisibleNumbers(m);

    std::vector<int> product{1};

    for (usint i = 0; i < divisibleNumbers.size(); i++) {
        auto P  = GetCyclotomicPolynomialRecursive(divisibleNumbers[i]);
        product = PolyMult(product, P);
    }

    // make big poly = x^m - 1
    std::vector<int> bigPoly(m + 1, 0);
    bigPoly[0] = -1;
    bigPoly[m] = 1;
    return PolyQuotient(bigPoly, product);
}

uint32_t FindAutomorphismIndex2n(int32_t i, uint32_t m) {
    if (i == 0) {
        return 1;
    }

    uint32_t n = GetTotient(m);
    uint32_t f1, f2;
    if (i < 0) {
        f1 = NativeInteger(5).ModInverse(m).ConvertToInt();
        f2 = NativeInteger(m - 1).ModInverse(m).ConvertToInt();
    }
    else {
        f1 = 5;
        f2 = m - 1;
    }

    uint32_t i_unsigned = (uint32_t)std::abs(i);

    uint32_t g0 = f1;
    uint32_t g;

    if (i_unsigned < n / 2) {
        g = f1;
        for (size_t j = 1; j < i_unsigned; j++) {
            g = (g * g0) % m;
        }
    }
    else {
        g = f2;
        for (size_t j = n / 2; j < i_unsigned; j++) {
            g = (g * g0) % m;
        }
    }
    return g;
}

uint32_t FindAutomorphismIndexCyclic(int32_t i, uint32_t m, uint32_t g) {
    if (i == 0) {
        return 1;
    }

    int32_t n        = GetTotient(m);
    int32_t i_signed = i % n;
    if (i_signed <= 0) {
        i_signed += n;
    }

    uint32_t i_unsigned = (uint32_t)i_signed;
    uint32_t k          = g;
    for (size_t ii = 2; ii < i_unsigned; ii++) {
        k = (k * g) % m;
    }
    return k;
}

uint32_t FindAutomorphismIndex2nComplex(int32_t i, uint32_t m) {
    if (i == 0) {
        return 1;
    }

    // conjugation automorphism
    if (i == int32_t(m - 1)) {
        return uint32_t(i);
    }
    else {
        // generator
        int32_t g0;

        if (i < 0) {
            g0 = NativeInteger(5).ModInverse(m).ConvertToInt();
        }
        else {
            g0 = 5;
        }
        uint32_t i_unsigned = (uint32_t)std::abs(i);

        int32_t g = g0;
        for (size_t j = 1; j < i_unsigned; j++) {
            g = (g * g0) % m;
        }
        return uint32_t(g);
    }
}

void PrecomputeAutoMap(uint32_t n, uint32_t k, std::vector<uint32_t>* precomp) {
    uint32_t m    = n << 1;  // cyclOrder
    uint32_t logm = std::round(log2(m));
    uint32_t logn = std::round(log2(n));
    for (uint32_t j = 0; j < n; j++) {
        uint32_t jTmp    = ((j << 1) + 1);
        usint idx        = ((jTmp * k) - (((jTmp * k) >> logm) << logm)) >> 1;
        usint jrev       = ReverseBits(j, logn);
        usint idxrev     = ReverseBits(idx, logn);
        (*precomp)[jrev] = idxrev;
    }
}

}  // namespace lbcrypto
