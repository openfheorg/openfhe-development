//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
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
  This file contains template instantiations for all math classes & functions using math be6
 */

#include "math/hal.h"
#include "math/binaryuniformgenerator.cpp"     // NOLINT
#include "math/discretegaussiangenerator.cpp"  // NOLINT
#include "math/discreteuniformgenerator.cpp"   // NOLINT
#include "math/matrix.cpp"                     // NOLINT
#include "math/matrix.h"
#include "math/nbtheory.cpp"                 // NOLINT
#include "math/ternaryuniformgenerator.cpp"  // NOLINT
#include "math/hal/transform.h"

namespace lbcrypto {

template class DiscreteGaussianGeneratorImpl<NativeVector>;
template class BinaryUniformGeneratorImpl<NativeVector>;
template class TernaryUniformGeneratorImpl<NativeVector>;
template class DiscreteUniformGeneratorImpl<NativeVector>;

template NativeInteger RootOfUnity<NativeInteger>(usint m, const NativeInteger& modulo);
template std::vector<NativeInteger> RootsOfUnity(usint m, const std::vector<NativeInteger> moduli);
template NativeInteger GreatestCommonDivisor(const NativeInteger& a, const NativeInteger& b);
template bool MillerRabinPrimalityTest(const NativeInteger& p, const usint niter);
template const NativeInteger PollardRhoFactorization(const NativeInteger& n);
template void PrimeFactorize(NativeInteger n, std::set<NativeInteger>& primeFactors);
template NativeInteger FirstPrime(uint64_t nBits, uint64_t m);
template NativeInteger NextPrime(const NativeInteger& q, uint64_t cyclotomicOrder);
template NativeInteger PreviousPrime(const NativeInteger& q, uint64_t cyclotomicOrder);

template std::vector<NativeInteger> GetTotientList(const NativeInteger& n);
template std::vector<usint> GetTotientList(const usint& n);

template NativeVector PolyMod(const NativeVector& dividend, const NativeVector& divisor, const NativeInteger& modulus);
template NativeVector PolynomialMultiplication(const NativeVector& a, const NativeVector& b);
template NativeVector GetCyclotomicPolynomial(usint m, const NativeInteger& modulus);
template NativeInteger SyntheticRemainder(const NativeVector& dividend, const NativeInteger& a,
                                          const NativeInteger& modulus);
template NativeVector SyntheticPolyRemainder(const NativeVector& dividend, const NativeVector& aList,
                                             const NativeInteger& modulus);
template NativeVector PolynomialPower<NativeVector>(const NativeVector& input, usint power);
template NativeVector SyntheticPolynomialDivision(const NativeVector& dividend, const NativeInteger& a,
                                                  const NativeInteger& modulus);
template NativeInteger FindGeneratorCyclic(const NativeInteger& modulo);
template bool IsGenerator(const NativeInteger& g, const NativeInteger& modulo);
template std::shared_ptr<std::vector<int64_t>> GetDigits(const NativeInteger& u, uint64_t base, uint32_t k);

template class Matrix<NativeInteger>;
template class Matrix<NativeVector>;

}  // namespace lbcrypto

CEREAL_CLASS_VERSION(NativeInteger, NativeInteger::SerializedVersion());
CEREAL_CLASS_VERSION(NativeVector, NativeVector::SerializedVersion());
