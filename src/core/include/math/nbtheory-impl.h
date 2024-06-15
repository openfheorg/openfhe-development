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
  This code provides number theory utilities
 */

#ifndef LBCRYPTO_INC_MATH_NBTHEORY_IMPL_H
#define LBCRYPTO_INC_MATH_NBTHEORY_IMPL_H

#define _USE_MATH_DEFINES

#include "math/distributiongenerator.h"
#include "math/nbtheory.h"

#include "utils/debug.h"
#include "utils/exception.h"
#include "utils/inttypes.h"

#include <cmath>
#include <limits>
#include <set>
#include <string>
#include <type_traits>
#include <vector>

namespace lbcrypto {

/*
 Generates a random number between 0 and n.
 Input: BigInteger n.
 Output: Randomly generated BigInteger  between 0 and n.
 */
template <typename IntType>
static IntType RNG(const IntType& modulus) {
    constexpr uint32_t chunk_min{0};
    constexpr uint32_t chunk_max{std::numeric_limits<uint32_t>::max()};
    constexpr uint32_t chunk_width{std::numeric_limits<uint32_t>::digits};
    static std::uniform_int_distribution<uint32_t> distribution(chunk_min, chunk_max);

    uint32_t chunksPerValue{(modulus.GetMSB() - 1) / chunk_width};
    uint32_t shiftChunk{chunksPerValue * chunk_width};
    std::uniform_int_distribution<uint32_t>::param_type bound(chunk_min, (modulus >> shiftChunk).ConvertToInt());

    while (true) {
        IntType result{};
        for (uint32_t i{0}, shift{0}; i < chunksPerValue; ++i, shift += chunk_width)
            result += IntType{distribution(PseudoRandomNumberGenerator::GetPRNG())} << shift;
        result += IntType{distribution(PseudoRandomNumberGenerator::GetPRNG(), bound)} << shiftChunk;
        if (result < modulus)
            return result;
    }
}
/*
 A witness function used for the Miller-Rabin Primality test.
 Inputs: a is a randomly generated witness between 2 and p-1,
 p is the number to be tested for primality,
 s and d satisfy p-1 = ((2^s) * d), d is odd.
 Output: true if p is composite,
 false if p is likely prime
 */
template <typename IntType>
static bool WitnessFunction(const IntType& a, const IntType& d, usint s, const IntType& p) {
    IntType mod  = a.ModExp(d, p);
    bool prevMod = false;
    for (usint i = 0; i < s; ++i) {
        prevMod = (mod != IntType(1) && mod != p - IntType(1));
        mod.ModMulFastEq(mod, p);
        if (mod == IntType(1) && prevMod)
            return true;
    }
    return (mod != IntType(1));
}

/*
 A helper function to RootOfUnity function. This finds a generator for a given
 prime q. Input: BigInteger q which is a prime. Output: A generator of prime q
 */
template <typename IntType>
static IntType FindGenerator(const IntType& q) {
    IntType qm1(q - IntType(1));
    IntType qm2(q - IntType(2));
    std::set<IntType> primeFactors;
    PrimeFactorize<IntType>(qm1, primeFactors);
    usint cnt;
    IntType gen;
    do {
        cnt = 0;
        gen = RNG(qm2) + IntType(1);
        for (auto it = primeFactors.begin(); it != primeFactors.end(); ++it, ++cnt) {
            if (gen.ModExp(qm1 / (*it), q) == IntType(1))
                break;
        }
    } while (cnt != primeFactors.size());
    return gen;
}

/*
 A helper function for arbitrary cyclotomics. This finds a generator for any
 composite q (cyclic group). Input: BigInteger q (cyclic group). Output: A
 generator of q
 */
template <typename IntType>
IntType FindGeneratorCyclic(const IntType& q) {
    IntType phi_q(GetTotient(q.ConvertToInt()));
    IntType phi_q_m1(GetTotient(q.ConvertToInt()));
    std::set<IntType> primeFactors;
    PrimeFactorize<IntType>(phi_q, primeFactors);
    usint cnt;
    IntType gen;
    do {
        cnt = 0;
        gen = RNG(phi_q_m1) + IntType(1);  // gen is random in [1, phi(q)]

        // Generator must lie in the group!
        if (GreatestCommonDivisor<IntType>(gen, q) != IntType(1))
            continue;

        // Order of a generator cannot divide any co-factor
        for (auto it = primeFactors.begin(); it != primeFactors.end(); ++it, ++cnt) {
            if (gen.ModExp(phi_q / (*it), q) == IntType(1))
                break;
        }
    } while (cnt != primeFactors.size());
    return gen;
}

/*
 A helper function for arbitrary cyclotomics. Checks if g is a generator of q
 (supports any cyclic group, not just prime-modulus groups) Input: Candidate
 generator g and modulus q Output: returns true if g is a generator for q
 */
template <typename IntType>
bool IsGenerator(const IntType& g, const IntType& q) {
    IntType qm1(GetTotient(q.ConvertToInt()));
    std::set<IntType> primeFactors;
    PrimeFactorize<IntType>(qm1, primeFactors);
    usint cnt = 0;
    for (auto it = primeFactors.begin(); it != primeFactors.end(); ++it, ++cnt) {
        if (g.ModExp(qm1 / (*it), q) == IntType(1))
            break;
    }
    return cnt == primeFactors.size();
}

/*
 finds roots of unity for given input.  Assumes the the input is a power of two.
 Mostly likely does not give correct results otherwise. input:  m as number
 which is cyclotomic(in format of int), modulo which is used to find generator
 (in format of BigInteger)

 output:  root of unity (in format of BigInteger)
 */
template <typename IntType>
IntType RootOfUnity(usint m, const IntType& modulo) {
    IntType M(m);
    if ((modulo - IntType(1)).Mod(M) != IntType(0)) {
        std::string errMsg =
            "Please provide a primeModulus(q) and a cyclotomic number(m) "
            "satisfying the condition: (q-1)/m is an integer. The values of "
            "primeModulus = " +
            modulo.ToString() + " and m = " + std::to_string(m) + " do not satisfy this condition";
        OPENFHE_THROW(errMsg);
    }

    IntType gen    = FindGenerator(modulo);
    IntType result = gen.ModExp((modulo - IntType(1)).DividedBy(M), modulo);
    if (result == IntType(1))
        result = RootOfUnity(m, modulo);

    /*
   * At this point, result contains a primitive root of unity. However,
   * we want to return the minimum root of unity, to avoid different
   * crypto contexts having different roots of unity for the same
   * cyclotomic order and moduli. Therefore, we are going to cycle over
   * all primitive roots of unity and select the smallest one (minRU).
   *
   * To cycle over all primitive roots of unity, we raise the root of
   * unity in result to all the powers that are co-prime to the
   * cyclotomic order. In power-of-two cyclotomics, this will be the
   * set of all odd powers, but here we use a more general routine
   * to support arbitrary cyclotomics.
   *
   */

    IntType mu(modulo.ComputeMu());
    IntType x(1);
    x.ModMulEq(result, modulo, mu);

    std::vector<IntType> coprimes = GetTotientList<IntType>(m);
    IntType minRU(x);
    IntType curPowIdx(1);
    for (size_t i = 0; i < coprimes.size(); ++i) {
        auto nextPowIdx = coprimes[i];
        IntType diffPow(nextPowIdx - curPowIdx);
        for (IntType j(0); j < diffPow; j += IntType(1))
            x.ModMulEq(result, modulo, mu);
        if (x < minRU && x != IntType(1))
            minRU = x;
        curPowIdx = nextPowIdx;
    }
    return minRU;
}

template <typename IntType>
std::vector<IntType> RootsOfUnity(usint m, const std::vector<IntType>& moduli) {
    std::vector<IntType> rootsOfUnity(moduli.size());
    for (size_t i = 0; i < moduli.size(); ++i)
        rootsOfUnity[i] = RootOfUnity(m, moduli[i]);
    return rootsOfUnity;
}

template <typename IntType>
IntType GreatestCommonDivisor(const IntType& a, const IntType& b) {
    static const IntType ZERO(0);
    auto m_a(a);
    auto m_b(b);
    while (m_b != ZERO) {
        auto tmp(m_b);
        m_b = m_a % m_b;
        m_a = tmp;
    }
    return m_a;
}

/*
 The Miller-Rabin Primality Test
 Input: p the number to be tested for primality.
 Output: true if p is prime,
 false if p is not prime
 */
template <typename IntType>
bool MillerRabinPrimalityTest(const IntType& p, const usint niter) {
    static const IntType ZERO(0);
    static const IntType TWO(2);
    static const IntType THREE(3);
    static const IntType FIVE(5);

    if (p == TWO || p == THREE || p == FIVE)
        return true;
    if (p < TWO || (p.Mod(TWO) == ZERO))
        return false;

    IntType d(p - IntType(1));
    usint s(0);
    while (d.Mod(TWO) == ZERO) {
        // d.DividedByEq(TWO);
        d.RShiftEq(1);
        ++s;
    }
    for (usint i = 0; i < niter; ++i) {
        if (WitnessFunction(RNG(p - THREE).ModAdd(TWO, p), d, s, p))
            return false;
    }
    return true;
}

/*
 The Pollard Rho factorization of a number n.
 Input: n the number to be factorized.
 Output: a factor of n.
 */
template <typename IntType>
const IntType PollardRhoFactorization(const IntType& n) {
    if (n.Mod(IntType(2)) == IntType(0))
        return IntType(2);
    IntType divisor(1);
    IntType c(RNG(n));
    IntType x(RNG(n));
    IntType xx(x);
    IntType mu(n.ComputeMu());
    do {
        x       = x.ModMul(x, n, mu).ModAdd(c, n, mu);
        xx      = xx.ModMul(xx, n, mu).ModAdd(c, n, mu);
        xx      = xx.ModMul(xx, n, mu).ModAdd(c, n, mu);
        divisor = GreatestCommonDivisor((x > xx) ? x - xx : xx - x, n);
    } while (divisor == IntType(1));
    return divisor;
}

/*
 Recursively factorizes and find the distinct primefactors of a number
 Input: n is the number to be prime factorized,
 primeFactors is a set of prime factors of n.
 */
template <typename IntType>
void PrimeFactorize(IntType n, std::set<IntType>& primeFactors) {
    if (n == IntType(0) || n == IntType(1))
        return;
    if (MillerRabinPrimalityTest(n)) {
        primeFactors.insert(n);
        return;
    }

    IntType divisor(PollardRhoFactorization(n));
    PrimeFactorize(divisor, primeFactors);
    PrimeFactorize(n / divisor, primeFactors);
}

template <typename IntType>
IntType FirstPrime(uint32_t nBits, uint32_t m) {
    if constexpr (std::is_same_v<IntType, NativeInteger>) {
        if (nBits > MAX_MODULUS_SIZE)
            OPENFHE_THROW(std::string(__func__) + ": Requested bit length " + std::to_string(nBits) +
                          " exceeds maximum allowed length " + std::to_string(MAX_MODULUS_SIZE));
    }

    IntType M(m);
    IntType q(IntType(1) << nBits);
    IntType r(q.Mod(M));
    IntType qNew(q + IntType(1) - r);
    if (r > IntType(0))
        qNew += M;
    while (!MillerRabinPrimalityTest(qNew)) {
        if ((qNew += M) < q)
            OPENFHE_THROW(std::string(__func__) + ": overflow growing candidate");
    }
    return qNew;
}

template <typename IntType>
IntType LastPrime(uint32_t nBits, uint32_t m) {
    if constexpr (std::is_same_v<IntType, NativeInteger>) {
        if (nBits > MAX_MODULUS_SIZE)
            OPENFHE_THROW(std::string(__func__) + ": Requested bit length " + std::to_string(nBits) +
                          " exceeds maximum allowed length " + std::to_string(MAX_MODULUS_SIZE));
    }

    IntType M(m);
    IntType q(IntType(1) << nBits);
    IntType r(q.Mod(M));
    IntType qNew(q + IntType(1) - r);
    if (r < IntType(2))
        qNew -= M;
    while (!MillerRabinPrimalityTest(qNew)) {
        if ((qNew -= M) > q)
            OPENFHE_THROW(std::string(__func__) + ": overflow shrinking candidate");
    }

    if (qNew.GetMSB() != nBits)
        OPENFHE_THROW(std::string(__func__) + ": Requested " + std::to_string(nBits) + " bits, but returned " +
                      std::to_string(qNew.GetMSB()) + ". Please adjust parameters.");

    return qNew;
}

template <typename IntType>
IntType NextPrime(const IntType& q, uint32_t m) {
    IntType M(m), qNew(q + M);
    while (!MillerRabinPrimalityTest(qNew)) {
        if ((qNew += M) < q)
            OPENFHE_THROW(std::string(__func__) + ": overflow growing candidate");
    }
    return qNew;
}

template <typename IntType>
IntType PreviousPrime(const IntType& q, uint32_t m) {
    IntType M(m), qNew(q - M);
    while (!MillerRabinPrimalityTest(qNew)) {
        if ((qNew -= M) > q)
            OPENFHE_THROW(std::string(__func__) + ": overflow shrinking candidate");
    }
    return qNew;
}

template <typename IntType>
IntType NextPowerOfTwo(IntType n) {
    usint result = ceil(log2(n));
    return result;
}

/*Naive Loop to find coprimes to n*/
template <typename IntType>
std::vector<IntType> GetTotientList(const IntType& n) {
    std::vector<IntType> result;
    static const IntType one(1);
    for (IntType i = one; i < n; i = i + one) {
        if (GreatestCommonDivisor(i, n) == one)
            result.push_back(i);
    }
    return result;
}

/* Calculate the remainder from polynomial division */
template <typename IntVector>
IntVector PolyMod(const IntVector& dividend, const IntVector& divisor, const typename IntVector::Integer& modulus) {
    auto mu(modulus.ComputeMu());
    usint divisorLength(divisor.GetLength());
    usint dividendLength(dividend.GetLength());
    usint runs(dividendLength - divisorLength + 1);
    IntVector runningDividend(dividend);
    for (usint i = 0; i < runs; ++i) {
        // get the highest degree coeff
        auto divConst(runningDividend[dividendLength - 1]);
        usint divisorPtr(divisorLength - 1);
        for (usint j = 0; j < dividendLength - i - 1; j++) {
            auto& rdtmp1 = runningDividend[dividendLength - 1 - j];
            rdtmp1       = runningDividend[dividendLength - 2 - j];
            if (divisorPtr > j)
                rdtmp1.ModSubEq(divisor[divisorPtr - 1 - j] * divConst, modulus, mu);
        }
    }

    IntVector result(divisorLength - 1, modulus);
    for (usint i = 0, j = runs; i < divisorLength - 1; ++i, ++j)
        result[i] = runningDividend[j];
    return result;
}

template <typename IntVector>
IntVector PolynomialMultiplication(const IntVector& a, const IntVector& b) {
    usint degreeA(a.GetLength());
    usint degreeB(b.GetLength());
    usint degreeResultant(degreeA + degreeB - 1);
    const auto& modulus = a.GetModulus();
    IntVector result(degreeResultant, modulus);
    for (usint i = 0; i < degreeA; i++) {
        for (usint j = 0; j < degreeB; j++) {
            result[i + j].ModAddEq(a[i] * b[j], modulus);
        }
    }
    return result;
}

template <typename IntVector>
IntVector GetCyclotomicPolynomial(usint m, const typename IntVector::Integer& modulus) {
    auto intCP = GetCyclotomicPolynomialRecursive(m);
    IntVector result(intCP.size(), modulus);
    for (usint i = 0; i < intCP.size(); i++) {
        auto val = intCP[i];
        if (val > -1) {
            result[i] = typename IntVector::Integer(val);
        }
        else {
            result[i] = modulus - typename IntVector::Integer(-val);
        }
    }
    return result;
}

template <typename IntVector>
typename IntVector::Integer SyntheticRemainder(const IntVector& dividend, const typename IntVector::Integer& a,
                                               const typename IntVector::Integer& modulus) {
    auto mu  = modulus.ComputeMu();
    auto val = dividend[dividend.GetLength() - 1];
    for (int i = dividend.GetLength() - 2; i >= 0; --i)
        val = (dividend[i] + a * val).Mod(modulus, mu);
    return val;
}

template <typename IntVector>
IntVector SyntheticPolyRemainder(const IntVector& dividend, const IntVector& aList,
                                 const typename IntVector::Integer& modulus) {
    IntVector result(aList.GetLength(), modulus);
    for (usint i = 0; i < aList.GetLength(); ++i)
        result[i] = SyntheticRemainder(dividend, aList[i], modulus);
    return result;
}

template <typename IntVector>
IntVector PolynomialPower(const IntVector& input, usint power) {
    usint finalDegree = (input.GetLength() - 1) * power;
    IntVector finalPoly(finalDegree + 1, input.GetModulus());
    for (usint i = 0; i < input.GetLength(); ++i)
        finalPoly[i * power] = input[i];
    return finalPoly;
}

template <typename IntVector>
IntVector SyntheticPolynomialDivision(const IntVector& dividend, const typename IntVector::Integer& a,
                                      const typename IntVector::Integer& modulus) {
    auto mu(modulus.ComputeMu());
    usint n(dividend.GetLength() - 1);
    IntVector result(n, modulus);
    result[n - 1] = dividend[n];
    auto val(dividend[n]);
    for (int i = n - 1; i > 0; i--) {
        val           = (val * a + dividend[i]).Mod(modulus, mu);
        result[i - 1] = val;
    }
    return result;
}

}  // namespace lbcrypto

#endif
