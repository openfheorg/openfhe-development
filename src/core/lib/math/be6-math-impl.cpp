// @file be6-math-impl.cpp This file contains template instantiations for all
// math classes & functions using math be6
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "math/backend.h"

#ifdef WITH_NTL
#include "math/binaryuniformgenerator.cpp"
#include "math/discretegaussiangenerator.cpp"
#include "math/discreteuniformgenerator.cpp"
#include "math/matrix.cpp"
#include "math/matrix.h"
#include "math/nbtheory.cpp"
#include "math/ternaryuniformgenerator.cpp"
#include "math/transfrm.cpp"

namespace lbcrypto {

template class DiscreteGaussianGeneratorImpl<M6Vector>;
template class BinaryUniformGeneratorImpl<M6Vector>;
template class TernaryUniformGeneratorImpl<M6Vector>;
template class DiscreteUniformGeneratorImpl<M6Vector>;
template class ChineseRemainderTransformFTT<M6Vector>;
template class ChineseRemainderTransformArb<M6Vector>;

template M6Integer RootOfUnity<M6Integer>(usint m, const M6Integer &modulo);
template std::vector<M6Integer> RootsOfUnity(
    usint m, const std::vector<M6Integer> moduli);
template M6Integer GreatestCommonDivisor(const M6Integer &a,
                                         const M6Integer &b);
template bool MillerRabinPrimalityTest(const M6Integer &p, const usint niter);
template const M6Integer PollardRhoFactorization(const M6Integer &n);
template void PrimeFactorize(M6Integer n, std::set<M6Integer> &primeFactors);
template M6Integer FirstPrime(uint64_t nBits, uint64_t m);
template M6Integer NextPrime(const M6Integer &q, uint64_t cyclotomicOrder);
template M6Integer PreviousPrime(const M6Integer &q, uint64_t cyclotomicOrder);
template std::vector<M6Integer> GetTotientList(const M6Integer &n);
template M6Vector PolyMod(const M6Vector &dividend, const M6Vector &divisor,
                          const M6Integer &modulus);
template M6Vector PolynomialMultiplication(const M6Vector &a,
                                           const M6Vector &b);
template M6Vector GetCyclotomicPolynomial(usint m, const M6Integer &modulus);
template M6Integer SyntheticRemainder(const M6Vector &dividend,
                                      const M6Integer &a,
                                      const M6Integer &modulus);
template M6Vector SyntheticPolyRemainder(const M6Vector &dividend,
                                         const M6Vector &aList,
                                         const M6Integer &modulus);
template M6Vector PolynomialPower<M6Vector>(const M6Vector &input, usint power);
template M6Vector SyntheticPolynomialDivision(const M6Vector &dividend,
                                              const M6Integer &a,
                                              const M6Integer &modulus);
template M6Integer FindGeneratorCyclic(const M6Integer &modulo);
template bool IsGenerator(const M6Integer &g, const M6Integer &modulo);
template std::shared_ptr<std::vector<int64_t>> GetDigits(const M6Integer &u,
                                                         uint64_t base,
                                                         uint32_t k);

template class Matrix<M6Integer>;
ONES_FOR_TYPE(M6Integer)
IDENTITY_FOR_TYPE(M6Integer)
GADGET_FOR_TYPE(M6Integer)

template class Matrix<M6Vector>;
ONES_FOR_TYPE(M6Vector)
IDENTITY_FOR_TYPE(M6Vector)
GADGET_FOR_TYPE(M6Vector)

}  // namespace lbcrypto

CEREAL_CLASS_VERSION(M6Integer, M6Integer::SerializedVersion());
CEREAL_CLASS_VERSION(M6Vector, M6Vector::SerializedVersion());

#endif
