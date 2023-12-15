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
 * This code provides number theory utilities.
 *   NBTHEORY is set set of functions that will be used to calculate following:
 *    - If two numbers are coprime.
 *    - GCD of two numbers
 *    - If number i Prime
 *    - witnesss function to test if number is prime
 *    - Roots of unit for provided cyclotomic integer
 *    - Eulers Totient function phin(n)
 *    - Generator algorithm
 */

#ifndef LBCRYPTO_INC_MATH_NBTHEORY_H
#define LBCRYPTO_INC_MATH_NBTHEORY_H

#include "math/hal/basicint.h"

#include "utils/inttypes.h"
#include "utils/exception.h"

#include <memory>
#include <random>
#include <set>
// #include <string>
#include <vector>

#if defined(HAVE_INT128)
namespace {  // to define local (or C-style static) functions here

inline int clz_u128(uint128_t u) {
    uint64_t hi(u >> 64), lo(u);
    return hi ? __builtin_clzll(hi) : lo ? __builtin_clzll(lo) + 64 : 128;
}

};  // namespace
#endif

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * Finds roots of unity for given input.  Assumes the the input is a power of
 * two.
 *
 * @param m as number which is cyclotomic(in format of int).
 * @param &modulo which is used to find generator.
 *
 * @return a root of unity.
 */
template <typename IntType>
IntType RootOfUnity(usint m, const IntType& modulo);

/**
 * Finds roots of unity for given input.  Assumes the the input cyclotomicorder
 * is a power of two.
 *
 * @param m as number which is cyclotomic(in format of int).
 * @param moduli vector of modulus
 *
 * @returns a vector of roots of unity corresponding to each modulus.
 */
template <typename IntType>
std::vector<IntType> RootsOfUnity(usint m, const std::vector<IntType>& moduli);

/**
 * Method to reverse bits of num and return an unsigned int, for all bits up to
 * an including the designated most significant bit.
 *
 * @param input an unsigned int
 * @param msb the most significant bit.  All larger bits are disregarded.
 *
 * @return an unsigned integer that represents the reversed bits.
 */

// precomputed reverse of a byte

inline static unsigned char reverse_byte(unsigned char x) {
    static const unsigned char table[] = {
        0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0, 0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0, 0x08, 0x88,
        0x48, 0xc8, 0x28, 0xa8, 0x68, 0xe8, 0x18, 0x98, 0x58, 0xd8, 0x38, 0xb8, 0x78, 0xf8, 0x04, 0x84, 0x44, 0xc4,
        0x24, 0xa4, 0x64, 0xe4, 0x14, 0x94, 0x54, 0xd4, 0x34, 0xb4, 0x74, 0xf4, 0x0c, 0x8c, 0x4c, 0xcc, 0x2c, 0xac,
        0x6c, 0xec, 0x1c, 0x9c, 0x5c, 0xdc, 0x3c, 0xbc, 0x7c, 0xfc, 0x02, 0x82, 0x42, 0xc2, 0x22, 0xa2, 0x62, 0xe2,
        0x12, 0x92, 0x52, 0xd2, 0x32, 0xb2, 0x72, 0xf2, 0x0a, 0x8a, 0x4a, 0xca, 0x2a, 0xaa, 0x6a, 0xea, 0x1a, 0x9a,
        0x5a, 0xda, 0x3a, 0xba, 0x7a, 0xfa, 0x06, 0x86, 0x46, 0xc6, 0x26, 0xa6, 0x66, 0xe6, 0x16, 0x96, 0x56, 0xd6,
        0x36, 0xb6, 0x76, 0xf6, 0x0e, 0x8e, 0x4e, 0xce, 0x2e, 0xae, 0x6e, 0xee, 0x1e, 0x9e, 0x5e, 0xde, 0x3e, 0xbe,
        0x7e, 0xfe, 0x01, 0x81, 0x41, 0xc1, 0x21, 0xa1, 0x61, 0xe1, 0x11, 0x91, 0x51, 0xd1, 0x31, 0xb1, 0x71, 0xf1,
        0x09, 0x89, 0x49, 0xc9, 0x29, 0xa9, 0x69, 0xe9, 0x19, 0x99, 0x59, 0xd9, 0x39, 0xb9, 0x79, 0xf9, 0x05, 0x85,
        0x45, 0xc5, 0x25, 0xa5, 0x65, 0xe5, 0x15, 0x95, 0x55, 0xd5, 0x35, 0xb5, 0x75, 0xf5, 0x0d, 0x8d, 0x4d, 0xcd,
        0x2d, 0xad, 0x6d, 0xed, 0x1d, 0x9d, 0x5d, 0xdd, 0x3d, 0xbd, 0x7d, 0xfd, 0x03, 0x83, 0x43, 0xc3, 0x23, 0xa3,
        0x63, 0xe3, 0x13, 0x93, 0x53, 0xd3, 0x33, 0xb3, 0x73, 0xf3, 0x0b, 0x8b, 0x4b, 0xcb, 0x2b, 0xab, 0x6b, 0xeb,
        0x1b, 0x9b, 0x5b, 0xdb, 0x3b, 0xbb, 0x7b, 0xfb, 0x07, 0x87, 0x47, 0xc7, 0x27, 0xa7, 0x67, 0xe7, 0x17, 0x97,
        0x57, 0xd7, 0x37, 0xb7, 0x77, 0xf7, 0x0f, 0x8f, 0x4f, 0xcf, 0x2f, 0xaf, 0x6f, 0xef, 0x1f, 0x9f, 0x5f, 0xdf,
        0x3f, 0xbf, 0x7f, 0xff,
    };
    return table[x];
}

static int shift_trick[] = {0, 7, 6, 5, 4, 3, 2, 1};

/* Function to reverse bits of num */
inline usint ReverseBits(usint num, usint msb) {
    usint msbb = (msb >> 3) + (msb & 0x7 ? 1 : 0);
    switch (msbb) {
        case 1:
            return (reverse_byte((num)&0xff) >> shift_trick[msb & 0x7]);

        case 2:
            return (reverse_byte((num)&0xff) << 8 | reverse_byte((num >> 8) & 0xff)) >> shift_trick[msb & 0x7];

        case 3:
            return (reverse_byte((num)&0xff) << 16 | reverse_byte((num >> 8) & 0xff) << 8 |
                    reverse_byte((num >> 16) & 0xff)) >>
                   shift_trick[msb & 0x7];
        case 4:
            return (reverse_byte((num)&0xff) << 24 | reverse_byte((num >> 8) & 0xff) << 16 |
                    reverse_byte((num >> 16) & 0xff) << 8 | reverse_byte((num >> 24) & 0xff)) >>
                   shift_trick[msb & 0x7];
        default:
            return -1;
            // OPENFHE_THROW(math_error, "msbb value not handled:" +
            // std::to_string(msbb));
    }
}

/**
 * Get MSB of an integer.
 *
 * @param x the input to find MSB of.
 *
 * @return the index of the MSB bit location.
 */
template <typename T, std::enable_if_t<std::is_integral_v<T>, bool> = true>
inline constexpr usint GetMSB(T x) {
    if constexpr (sizeof(T) <= 8) {
        if (x == 0)
            return 0;
#if defined(_MSC_VER)
        unsigned long msb;  // NOLINT
        _BitScanReverse64(&msb, uint64_t(x));
        return msb + 1;
#else
        // a wrapper for GCC
        return 64 -
               (sizeof(unsigned long) == 8 ? __builtin_clzl(uint64_t(x)) : __builtin_clzll(uint64_t(x)));  // NOLINT
#endif
    }
#if defined(HAVE_INT128)
    else if constexpr (sizeof(T) == 16) {
    #if defined(_MSC_VER)
        static_assert(false, "MSVC doesn't support 128-bit integers");
    #endif
        return 128 - clz_u128(uint128_t(x));
    }
#endif
    else {
        OPENFHE_THROW(math_error, "Unsupported int type (GetMSB() supports 32-, 64- and 128-bit integers only)");
        return 0;
    }
}

/**
 * Get MSB of an unsigned 64 bit integer.
 *
 * @param x the input to find MSB of.
 *
 * @return the index of the MSB bit location.
 */
inline constexpr usint GetMSB64(uint64_t x) {
    return GetMSB(x);
}

template <typename IntType>
std::shared_ptr<std::vector<int64_t>> GetDigits(const IntType& u, uint64_t base, uint32_t k) {
    auto u_vec = std::make_shared<std::vector<int64_t>>(k);

    size_t baseDigits = (uint32_t)(std::round(log2(base)));  // ?

    // if (!(base & (base - 1)))
    IntType uu = u;
    IntType uTemp;
    for (size_t i = 0; i < k; i++) {  // ****************4/1/2018 This loop is correct.
        uTemp       = uu >> baseDigits;
        (*u_vec)[i] = (uu - (uTemp << baseDigits)).ConvertToInt();
        uu          = uTemp;
    }
    return u_vec;
}

/**
 * Return greatest common divisor of two big binary integers.
 *
 * @param a one integer to find greatest common divisor of.
 * @param b another integer to find greatest common divisor of.
 *
 * @return the greatest common divisor.
 */
template <typename IntType>
IntType GreatestCommonDivisor(const IntType& a, const IntType& b);

/**
 * Perform the MillerRabin primality test on an IntType.
 * This approach to primality testing is iterative and randomized.
 * It returns false if evidence of non-primality is found, and true if no
 * evidence is found after multiple rounds of testing. The const parameter
 * PRIMALITY_NO_OF_ITERATIONS determines how many rounds are used ( set in
 * nbtheory.h).
 *
 * @param p the candidate prime to test.
 * @param niter Number of iterations used for primality
 *              testing (default = 100.
 *
 * @return false if evidence of non-primality is found.  True is no evidence of
 * non-primality is found.
 */
template <typename IntType>
bool MillerRabinPrimalityTest(const IntType& p, const usint niter = 100);

/**
 * Perform the PollardRho factorization of a IntType.
 * Returns IntType::ONE if no factorization is found.
 *
 * @param n the value to perform a factorization on.
 * @return a factor of n, and IntType::ONE if no other factor is found.
 */
template <typename IntType>
const IntType PollardRhoFactorization(const IntType& n);

/**
 * Recursively factorizes to find the distinct primefactors of a number.
 * @param &n the value to factorize. [note the value of n is destroyed]
 * @param &primeFactors set of factors found [must begin cleared]
 */
template <typename IntType>
void PrimeFactorize(IntType n, std::set<IntType>& primeFactors);

/**
 * Finds the first prime q that satisfies q = 1 mod m with at least (nBits + 1) bits.
 *
 * @param nBits the bit parameter.
 * @param m the ring parameter (cyclotomic order).
 *
 * @return the first prime modulus.
 */
template <typename IntType>
IntType FirstPrime(uint32_t nBits, uint32_t m);

/**
 * Finds the max prime q that satisfies q = 1 mod m with at most nBits bits.
 *
 * @param nBits the bit parameter.
 * @param m the ring parameter (cyclotomic order).
 *
 * @return the last prime modulus
 */
template <typename IntType>
IntType LastPrime(uint32_t nBits, uint32_t m);

/**
 * Finds the next prime that satisfies q = 1 mod m
 *
 * @param &q is the prime number to start from (the number itself is not
 * included)
 * @param m the ring parameter (cyclotomic order).
 *
 * @return the next prime modulus.
 */
template <typename IntType>
IntType NextPrime(const IntType& q, uint32_t m);

/**
 * Finds the previous prime that satisfies q = 1 mod m
 *
 * @param &q is the prime number to start from (the number itself is not
 * included)
 * @param m the ring parameter (cyclotomic order).
 *
 * @return the previous prime modulus.
 */
template <typename IntType>
IntType PreviousPrime(const IntType& q, uint32_t m);

/**
 * Multiplicative inverse for primitive unsigned integer data types
 *
 * @param a the number we need the inverse of.
 * @param b the modulus we are working with.
 *
 * @return the multiplicative inverse
 */
usint ModInverse(usint a, usint b);

/**
 * Returns the next power of 2 that is greater than the input number.
 *
 * @param &n is the input value for which next power of 2 needs to be computed.
 * @return Next power of 2 that is greater or equal to n.
 */
template <typename IntType>
IntType NextPowerOfTwo(IntType n);

/**
 * Returns the totient value phi of a number n.
 *
 * @param &n the input number.
 * @return phi of n which is the number of integers m coprime to n such that 1 <= m <=
 * n.
 */
uint64_t GetTotient(const uint64_t n);

/**
 * Returns the list of coprimes to number n in ascending order.
 *
 * @param &n the input number.
 * @return vector of mi's such that 1 <= mi <= n and gcd(mi,n)==1.
 */
template <typename IntType>
std::vector<IntType> GetTotientList(const IntType& n);

/**
 * Returns the polynomial modulus.
 *
 * @param &dividend the input dividend polynomial with degree >= degree of
 * divisor.
 * @param &divisor the input divisor polynomial with degree <= degree of
 * dividend and divisor is a monic polynomial.
 * @param &modulus the working modulus.
 * @return resultant polynomial vector s.t. return = divident mod
 * (divisor,modulus).
 */
template <typename IntVector>
IntVector PolyMod(const IntVector& dividend, const IntVector& divisor, const typename IntVector::Integer& modulus);

/**
 * Returns the polynomial multiplication of the input operands.
 *
 * @param &a the input polynomial.
 * @param &b the input polynomial.
 * a and b must have the same modulus.
 * @return resultant polynomial s.t. return = a*b and coefficinet ci =
 * ci%modulus.
 */
template <typename IntVector>
IntVector PolynomialMultiplication(const IntVector& a, const IntVector& b);

/**
 * Returns the m-th cyclotomic polynomial.
 * Added as a wrapper to GetCyclotomicPolynomialRecursive
 * @param &m the input cyclotomic order.
 * @param &modulus is the working modulus.
 * @return resultant m-th cyclotomic polynomial with coefficients in modulus.
 */
template <typename IntVector>
IntVector GetCyclotomicPolynomial(usint m, const typename IntVector::Integer& modulus);

/**
 * Returns the m-th cyclotomic polynomial.
 *
 * @param &m the input cyclotomic order.
 * @return resultant m-th cyclotomic polynomial.
 */
std::vector<int> GetCyclotomicPolynomialRecursive(usint m);

/**
 * Returns the remainder after polynomial division of dividend with divisor =
 * x-a. Uses synthetic division algorithm.
 * @param &dividend is the input polynomial dividend in lower to higher
 * coefficient form.
 * @param &a is the integer in divisor[x-a].
 * @return remainder after division with x-a.
 */
template <typename IntVector>
typename IntVector::Integer SyntheticRemainder(const IntVector& dividend, const typename IntVector::Integer& a,
                                               const typename IntVector::Integer& modulus);

/**
 * Returns the remainder vector after polynomial division of dividend with
 * divisor = x-aList[i]. Uses synthetic division algorithm.
 * @param &dividend is the input polynomial dividend in lower to higher
 * coefficient form.
 * @param &aList is the integer vector for divisor[x-aList[i]].
 * @return remainder vector after division with x-aList[i].
 */
template <typename IntVector>
IntVector SyntheticPolyRemainder(const IntVector& dividend, const IntVector& aList,
                                 const typename IntVector::Integer& modulus);

/**
 * Returns the polynomial after raising it by exponent = power.
 * Returns input^power.Uses Frobenius mapping.
 * @param &input is operand polynomial which needs to be exponentiated.
 * @param &power is the exponent.
 * @return exponentiated polynomial.
 */
template <typename IntVector>
IntVector PolynomialPower(const IntVector& input, usint power);

/**
 * Returns the quotient after polynomial division of dividend with divisor =
 * x-a. Uses synthetic division algorithm.
 * @param &dividend is the input polynomial dividend in lower to higher
 * coefficient form.
 * @param &a is the integer in divisor[x-a].
 * @return quotient after division with x-a.
 */
template <typename IntVector>
IntVector SyntheticPolynomialDivision(const IntVector& dividend, const typename IntVector::Integer& a,
                                      const typename IntVector::Integer& modulus);

/**
 * Checkes if g is a generator for any cyclic group with modulus q (non-prime
 * moduli are supported); currently q up to 64 bits only are supported
 * @param &g is candidate generator
 * @param &q is the modulus ( 2, 4, p^k, or 2*p^k where p^k is a power of an odd
 * prime number )
 * @return true if g is a generator
 */
template <typename IntType>
bool IsGenerator(const IntType& g, const IntType& q);

/**
 * Finds a generator for any cyclic group with modulus q (non-prime moduli are
 * supported); currently q up to 64 bits only are supported
 * @param &q is the modulus ( 2, 4, p^k, or 2*p^k where p^k is a power of an odd
 * prime number )
 * @return true if g is a generator
 */
template <typename IntType>
IntType FindGeneratorCyclic(const IntType& q);

/**
 * Find an automorphism index for a power-of-two cyclotomic order
 * @param i is the plaintext array index
 * @param m is the cyclotomic order
 * @return the automorphism index
 */
uint32_t FindAutomorphismIndex2n(int32_t i, uint32_t m);

/**
 * @see FindAutomorphismIndex2n() version for CKKS
 */
uint32_t FindAutomorphismIndex2nComplex(int32_t i, uint32_t m);

/**
 * Find an automorhism index for cyclic groups
 * @param i is the plaintext array index
 * @param m is the cyclotomic order
 * @param g is the generator
 * @return the automorphism index
 */
uint32_t FindAutomorphismIndexCyclic(int32_t i, uint32_t m, uint32_t g);

/**
 * Precompute a bit reversal map for a specific automorphism
 * @param n ring dimension
 * @param k automorphism index
 * @param *precomp the vector where the precomputed table is stored
 */
void PrecomputeAutoMap(uint32_t n, uint32_t k, std::vector<uint32_t>* precomp);

}  // namespace lbcrypto

#endif
