// @file be2-math-impl.cpp This file contains template instantiations for all
// math classes & functions using math be2
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
#include "math/binaryuniformgenerator.cpp"
#include "math/discretegaussiangenerator.cpp"
#include "math/discreteuniformgenerator.cpp"
#include "math/nbtheory.cpp"
#include "math/ternaryuniformgenerator.cpp"
#include "math/transfrm.cpp"

namespace lbcrypto {

template class DiscreteGaussianGeneratorImpl<M2Vector>;
template class BinaryUniformGeneratorImpl<M2Vector>;
template class TernaryUniformGeneratorImpl<M2Vector>;
template class DiscreteUniformGeneratorImpl<M2Vector>;
template class ChineseRemainderTransformFTT<M2Vector>;
template class ChineseRemainderTransformArb<M2Vector>;

template M2Integer RootOfUnity<M2Integer>(usint m, const M2Integer &modulo);
template std::vector<M2Integer> RootsOfUnity(
    usint m, const std::vector<M2Integer> moduli);
template M2Integer GreatestCommonDivisor(const M2Integer &a,
                                         const M2Integer &b);
template bool MillerRabinPrimalityTest(const M2Integer &p, const usint niter);
template const M2Integer PollardRhoFactorization(const M2Integer &n);
template void PrimeFactorize(M2Integer n, std::set<M2Integer> &primeFactors);
template M2Integer FirstPrime(uint64_t nBits, uint64_t m);
template M2Integer NextPrime(const M2Integer &q, uint64_t cyclotomicOrder);
template M2Integer PreviousPrime(const M2Integer &q, uint64_t cyclotomicOrder);
template std::vector<M2Integer> GetTotientList(const M2Integer &n);
template M2Vector PolyMod(const M2Vector &dividend, const M2Vector &divisor,
                          const M2Integer &modulus);
template M2Vector PolynomialMultiplication(const M2Vector &a,
                                           const M2Vector &b);
template M2Vector GetCyclotomicPolynomial(usint m, const M2Integer &modulus);
template M2Integer SyntheticRemainder(const M2Vector &dividend,
                                      const M2Integer &a,
                                      const M2Integer &modulus);
template M2Vector SyntheticPolyRemainder(const M2Vector &dividend,
                                         const M2Vector &aList,
                                         const M2Integer &modulus);
template M2Vector PolynomialPower<M2Vector>(const M2Vector &input, usint power);
template M2Vector SyntheticPolynomialDivision(const M2Vector &dividend,
                                              const M2Integer &a,
                                              const M2Integer &modulus);
template M2Integer FindGeneratorCyclic(const M2Integer &modulo);
template bool IsGenerator(const M2Integer &g, const M2Integer &modulo);
template std::shared_ptr<std::vector<int64_t>> GetDigits(const M2Integer &u,
                                                         uint64_t base,
                                                         uint32_t k);
}  // namespace lbcrypto

#include "math/matrix.h"

#include "math/matrix.cpp"

namespace lbcrypto {

template class Matrix<M2Integer>;
ONES_FOR_TYPE(M2Integer)
IDENTITY_FOR_TYPE(M2Integer)
GADGET_FOR_TYPE(M2Integer)

template class Matrix<M2Vector>;
ONES_FOR_TYPE(M2Vector)
IDENTITY_FOR_TYPE(M2Vector)
GADGET_FOR_TYPE(M2Vector)

}  // namespace lbcrypto

CEREAL_CLASS_VERSION(M2Integer, M2Integer::SerializedVersion());
CEREAL_CLASS_VERSION(M2Vector, M2Vector::SerializedVersion());
