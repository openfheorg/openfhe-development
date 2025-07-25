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
CKKS implementation. See https://eprint.iacr.org/2020/1118 for details.
 */

#define PROFILE

#include "cryptocontext.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "scheme/ckksrns/ckksrns-advancedshe.h"
#include "scheme/ckksrns/ckksrns-utils.h"
#include "schemebase/base-scheme.h"

#include <complex>
#include <vector>

namespace lbcrypto {

Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalMultMany(const std::vector<Ciphertext<DCRTPoly>>& ciphertextVec,
                                                      const std::vector<EvalKey<DCRTPoly>>& evalKeys) const {
    const size_t inSize = ciphertextVec.size();

    if (inSize == 0)
        OPENFHE_THROW("Input ciphertext vector is empty.");

    if (inSize == 1)
        return ciphertextVec[0];

    const size_t lim = inSize * 2 - 2;
    std::vector<Ciphertext<DCRTPoly>> ciphertextMultVec;
    ciphertextMultVec.resize(inSize - 1);

    auto algo               = ciphertextVec[0]->GetCryptoContext()->GetScheme();
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertextVec[0]->GetCryptoParameters());
    uint32_t levelsToDrop   = cryptoParams->GetCompositeDegree();

    size_t ctrIndex = 0;
    size_t i        = 0;
    for (; i < (inSize - 1); i += 2) {
        ciphertextMultVec[ctrIndex] = algo->EvalMultAndRelinearize(ciphertextVec[i], ciphertextVec[(i + 1)], evalKeys);
        algo->ModReduceInPlace(ciphertextMultVec[ctrIndex++], levelsToDrop);
    }
    if (i < inSize) {
        ciphertextMultVec[ctrIndex] =
            algo->EvalMultAndRelinearize(ciphertextVec[i], ciphertextMultVec[i + 1 - inSize], evalKeys);
        algo->ModReduceInPlace(ciphertextMultVec[ctrIndex++], levelsToDrop);
        i += 2;
    }
    for (; i < lim; i += 2) {
        ciphertextMultVec[ctrIndex] =
            algo->EvalMultAndRelinearize(ciphertextMultVec[i - inSize], ciphertextMultVec[i + 1 - inSize], evalKeys);
        algo->ModReduceInPlace(ciphertextMultVec[ctrIndex++], levelsToDrop);
    }

    return ciphertextMultVec.back();
}

//------------------------------------------------------------------------------
// LINEAR WEIGHTED SUM
//------------------------------------------------------------------------------

template <typename VectorDataType>
static inline Ciphertext<DCRTPoly> internalEvalLinearWSum(std::vector<ReadOnlyCiphertext<DCRTPoly>>& ciphertexts,
                                                          const std::vector<VectorDataType>& constants) {
    std::vector<Ciphertext<DCRTPoly>> cts(ciphertexts.size());
    for (uint32_t i = 0; i < ciphertexts.size(); i++)
        cts[i] = ciphertexts[i]->Clone();
    return internalEvalLinearWSumMutable(cts, constants);
}

template <typename VectorDataType>
static inline Ciphertext<DCRTPoly> internalEvalLinearWSumMutable(std::vector<Ciphertext<DCRTPoly>>& ciphertexts,
                                                                 const std::vector<VectorDataType>& constants) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(ciphertexts[0]->GetCryptoParameters());

    auto cc = ciphertexts[0]->GetCryptoContext();

    if (cryptoParams->GetScalingTechnique() != FIXEDMANUAL) {
        // Check to see if input ciphertexts are of same level
        // and adjust if needed to the max level among them
        uint32_t maxLevel = ciphertexts[0]->GetLevel();
        uint32_t maxIdx   = 0;
        for (uint32_t i = 1; i < ciphertexts.size(); ++i) {
            if ((ciphertexts[i]->GetLevel() > maxLevel) ||
                ((ciphertexts[i]->GetLevel() == maxLevel) && (ciphertexts[i]->GetNoiseScaleDeg() == 2))) {
                maxLevel = ciphertexts[i]->GetLevel();
                maxIdx   = i;
            }
        }

        auto algo = cc->GetScheme();
        for (uint32_t i = 0; i < maxIdx; ++i)
            algo->AdjustLevelsAndDepthInPlace(ciphertexts[i], ciphertexts[maxIdx]);
        for (uint32_t i = maxIdx + 1; i < ciphertexts.size(); ++i)
            algo->AdjustLevelsAndDepthInPlace(ciphertexts[i], ciphertexts[maxIdx]);

        uint32_t compositeDegree = cryptoParams->GetCompositeDegree();
        if (ciphertexts[maxIdx]->GetNoiseScaleDeg() == 2) {
            for (uint32_t i = 0; i < ciphertexts.size(); ++i) {
                algo->ModReduceInternalInPlace(ciphertexts[i], compositeDegree);
            }
        }
    }

    Ciphertext<DCRTPoly> weightedSum = cc->EvalMult(ciphertexts[0], constants[0]);

    Ciphertext<DCRTPoly> tmp;
    for (uint32_t i = 1; i < ciphertexts.size(); i++) {
        tmp = cc->EvalMult(ciphertexts[i], constants[i]);
        cc->EvalAddInPlace(weightedSum, tmp);
    }

    cc->ModReduceInPlace(weightedSum);

    return weightedSum;
}

Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalLinearWSum(std::vector<ReadOnlyCiphertext<DCRTPoly>>& ciphertexts,
                                                        const std::vector<int64_t>& constants) const {
    return internalEvalLinearWSum(ciphertexts, constants);
}
Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalLinearWSum(std::vector<ReadOnlyCiphertext<DCRTPoly>>& ciphertexts,
                                                        const std::vector<double>& constants) const {
    return internalEvalLinearWSum(ciphertexts, constants);
}
Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalLinearWSum(std::vector<ReadOnlyCiphertext<DCRTPoly>>& ciphertexts,
                                                        const std::vector<std::complex<double>>& constants) const {
    return internalEvalLinearWSum(ciphertexts, constants);
}

Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalLinearWSumMutable(std::vector<Ciphertext<DCRTPoly>>& ciphertexts,
                                                               const std::vector<int64_t>& constants) const {
    return internalEvalLinearWSumMutable(ciphertexts, constants);
}
Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalLinearWSumMutable(std::vector<Ciphertext<DCRTPoly>>& ciphertexts,
                                                               const std::vector<double>& constants) const {
    return internalEvalLinearWSumMutable(ciphertexts, constants);
}
Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalLinearWSumMutable(
    std::vector<Ciphertext<DCRTPoly>>& ciphertexts, const std::vector<std::complex<double>>& constants) const {
    return internalEvalLinearWSumMutable(ciphertexts, constants);
}

//------------------------------------------------------------------------------
// EVAL POLYNOMIAL
//------------------------------------------------------------------------------

template <typename VectorDataType>
std::shared_ptr<seriesPowers<DCRTPoly>> internalEvalPowersLinear(ConstCiphertext<DCRTPoly>& x,
                                                                 const std::vector<VectorDataType>& coefficients) {
    uint32_t k = coefficients.size() - 1;
    std::vector<int32_t> indices(k);
    // set the indices for the powers of x that need to be computed to 1
    for (uint32_t i = k; i > 0; --i) {
        if (!(i & (i - 1))) {
            // if i is a power of 2
            indices[i - 1] = 1;
        }
        else {
            // non-power of 2
            if (IsNotEqualZero(coefficients[i])) {
                indices[i - 1]   = 1;
                int64_t powerOf2 = int64_t(1) << static_cast<int64_t>(std::floor(std::log2(i)));
                int64_t rem      = i % powerOf2;
                if (indices[rem - 1] == 0)
                    indices[rem - 1] = 1;

                // while rem is not a power of 2
                // set indices required to compute rem to 1
                while ((rem & (rem - 1))) {
                    powerOf2 = 1 << static_cast<int64_t>(std::floor(std::log2(rem)));
                    rem      = rem % powerOf2;
                    if (indices[rem - 1] == 0)
                        indices[rem - 1] = 1;
                }
            }
        }
    }

    std::vector<Ciphertext<DCRTPoly>> powers(k);
    powers[0]                = x->Clone();
    auto cc                  = x->GetCryptoContext();
    auto cryptoParams        = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(x->GetCryptoParameters());
    uint32_t compositeDegree = cryptoParams->GetCompositeDegree();

    // computes all powers up to k for x
    for (uint32_t i = 2; i <= k; ++i) {
        if (!(i & (i - 1))) {
            // if i is a power of two
            powers[i - 1] = cc->EvalMult(powers[i / 2 - 1], powers[i / 2 - 1]);
            cc->ModReduceInPlace(powers[i - 1]);
        }
        else {
            if (indices[i - 1] == 1) {
                // non-power of 2
                int64_t powerOf2   = int64_t(1) << static_cast<int64_t>(std::floor(std::log2(i)));
                int64_t rem        = i % powerOf2;
                uint32_t levelDiff = powers[powerOf2 - 1]->GetLevel() - powers[rem - 1]->GetLevel();
                cc->LevelReduceInPlace(powers[rem - 1], nullptr, levelDiff / compositeDegree);

                powers[i - 1] = cc->EvalMult(powers[powerOf2 - 1], powers[rem - 1]);
                cc->ModReduceInPlace(powers[i - 1]);
            }
        }
    }

    // brings all powers of x to the same level
    for (uint32_t i = 1; i < k; ++i) {
        if (indices[i - 1] == 1) {
            uint32_t levelDiff = powers[k - 1]->GetLevel() - powers[i - 1]->GetLevel();
            cc->LevelReduceInPlace(powers[i - 1], nullptr, levelDiff / compositeDegree);
        }
    }

    return std::make_shared<seriesPowers<DCRTPoly>>(powers);
}

template <typename VectorDataType>
std::shared_ptr<seriesPowers<DCRTPoly>> internalEvalPowersPS(ConstCiphertext<DCRTPoly>& x,
                                                             const std::vector<VectorDataType>& coefficients) {
    auto n     = Degree(coefficients);
    auto degs  = ComputeDegreesPS(n);
    uint32_t k = degs[0];
    uint32_t m = degs[1];

    std::vector<Ciphertext<DCRTPoly>> powers;
    powers.reserve(k);
    powers.push_back(x->Clone());

    auto cc = x->GetCryptoContext();
    uint32_t compositeDegree =
        std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(x->GetCryptoParameters())->GetCompositeDegree();

    // computes all powers up to k for x
    uint32_t powerOf2 = 2;
    uint32_t rem      = 0;
    for (uint32_t i = 2; i <= k; i++) {
        if (rem == 0) {
            powers.push_back(cc->EvalSquare(powers[(powerOf2 >> 1) - 1]));
        }
        else {
            uint32_t levelDiff = powers[powerOf2 - 1]->GetLevel() - powers[rem - 1]->GetLevel();
            cc->LevelReduceInPlace(powers[rem - 1], nullptr, levelDiff / compositeDegree);
            powers.push_back(cc->EvalMult(powers[powerOf2 - 1], powers[rem - 1]));
        }
        cc->ModReduceInPlace(powers[powerOf2 - 1 + rem]);
        if (++rem == powerOf2) {
            powerOf2 <<= 1;
            rem = 0;
        }
    }

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(powers[k - 1]->GetCryptoParameters());
    auto algo               = cc->GetScheme();

    if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
        // brings all powers of x to the same level
        for (size_t i = 1; i < k; i++) {
            uint32_t levelDiff = powers[k - 1]->GetLevel() - powers[i - 1]->GetLevel();
            cc->LevelReduceInPlace(powers[i - 1], nullptr, levelDiff);
        }
    }
    else {
        for (size_t i = 1; i < k; i++) {
            algo->AdjustLevelsAndDepthInPlace(powers[i - 1], powers[k - 1]);
        }
    }

    // computes powers of form k*2^i for x and the product of the powers in power2, that yield x^{k(2*m - 1)}
    std::vector<Ciphertext<DCRTPoly>> powers2;
    powers2.reserve(m);
    powers2.push_back(powers.back()->Clone());
    auto power2km1 = powers.back()->Clone();

    for (uint32_t i = 1; i < m; i++) {
        powers2.push_back(cc->EvalSquare(powers2[i - 1]));
        cc->ModReduceInPlace(powers2[i]);
        power2km1 = cc->EvalMult(power2km1, powers2.back());
        cc->ModReduceInPlace(power2km1);
    }

    return std::make_shared<seriesPowers<DCRTPoly>>(powers, powers2, power2km1, k, m);
}

std::shared_ptr<seriesPowers<DCRTPoly>> AdvancedSHECKKSRNS::EvalPowers(ConstCiphertext<DCRTPoly>& x,
                                                                       const std::vector<int64_t>& coefficients) const {
    return (Degree(coefficients) < 5) ? internalEvalPowersLinear(x, coefficients) :
                                        internalEvalPowersPS(x, coefficients);
}
std::shared_ptr<seriesPowers<DCRTPoly>> AdvancedSHECKKSRNS::EvalPowers(ConstCiphertext<DCRTPoly>& x,
                                                                       const std::vector<double>& coefficients) const {
    return (Degree(coefficients) < 5) ? internalEvalPowersLinear(x, coefficients) :
                                        internalEvalPowersPS(x, coefficients);
}
std::shared_ptr<seriesPowers<DCRTPoly>> AdvancedSHECKKSRNS::EvalPowers(
    ConstCiphertext<DCRTPoly>& x, const std::vector<std::complex<double>>& coefficients) const {
    return (Degree(coefficients) < 5) ? internalEvalPowersLinear(x, coefficients) :
                                        internalEvalPowersPS(x, coefficients);
}

template <typename VectorDataType>
static inline Ciphertext<DCRTPoly> internalEvalPolyLinearWithPrecomp(std::vector<Ciphertext<DCRTPoly>>& powers,
                                                                     const std::vector<VectorDataType>& coefficients) {
    uint32_t k = coefficients.size() - 1;
    if (k <= 1)
        OPENFHE_THROW("The coefficients vector should contain at least 2 elements");

    if (!IsNotEqualZero(coefficients[k]))
        OPENFHE_THROW("EvalPolyLinear: The highest-order coefficient cannot be set to 0.");

    auto cc = powers[0]->GetCryptoContext();

    // perform scalar multiplication for the highest-order term
    auto result = cc->EvalMult(powers[k - 1], coefficients[k]);

    // perform scalar multiplication for all other terms and sum them up
    for (uint32_t i = 0; i < k - 1; ++i) {
        if (IsNotEqualZero(coefficients[i + 1])) {
            cc->EvalMultInPlace(powers[i], coefficients[i + 1]);
            cc->EvalAddInPlace(result, powers[i]);
        }
    }

    // Do rescaling after scalar multiplication
    cc->ModReduceInPlace(result);

    // adds the free term (at x^0)
    cc->EvalAddInPlace(result, coefficients[0]);

    return result;
}

template <typename VectorDataType>
static Ciphertext<DCRTPoly> InnerEvalPolyPS(ConstCiphertext<DCRTPoly>& x,
                                            const std::vector<VectorDataType>& coefficients, uint32_t k, uint32_t m,
                                            std::vector<Ciphertext<DCRTPoly>>& powers,
                                            std::vector<Ciphertext<DCRTPoly>>& powers2) {
    auto cc = x->GetCryptoContext();

    // Compute k*2^m because we use it often
    uint32_t k2m2k = k * (1 << (m - 1)) - k;

    // Divide coefficients by x^{k*2^{m-1}}
    std::vector<VectorDataType> xkm(static_cast<int32_t>(k2m2k + k) + 1, 0.0);
    xkm.back() = 1;

    auto divqr = LongDivisionPoly(coefficients, xkm);

    // Subtract x^{k(2^{m-1} - 1)} from r
    auto r2 = divqr->r;
    if (static_cast<int32_t>(k2m2k - Degree(divqr->r)) <= 0) {
        r2[static_cast<int32_t>(k2m2k)] -= 1;
        r2.resize(Degree(r2) + 1);
    }
    else {
        r2.resize(static_cast<int32_t>(k2m2k + 1), 0.0);
        r2.back() = -1;
    }

    // Divide r2 by q
    auto divcs = LongDivisionPoly(r2, divqr->q);

    // Add x^{k(2^{m-1} - 1)} to s
    auto s2 = divcs->r;
    s2.resize(static_cast<int32_t>(k2m2k + 1), 0.0);
    s2.back() = 1;

    Ciphertext<DCRTPoly> cu;
    uint32_t dc = Degree(divcs->q);
    bool flag_c = false;

    if (dc >= 1) {
        if (dc == 1) {
            if (IsNotEqualOne(divcs->q[1])) {
                cu = cc->EvalMult(powers.front(), divcs->q[1]);
                cc->ModReduceInPlace(cu);
            }
            else {
                cu = powers.front()->Clone();
            }
        }
        else {
            std::vector<Ciphertext<DCRTPoly>> ctxs(dc);
            std::vector<VectorDataType> weights(dc);

            for (uint32_t i = 0; i < dc; i++) {
                ctxs[i]    = powers[i];
                weights[i] = divcs->q[i + 1];
            }

            cu = cc->EvalLinearWSumMutable(ctxs, weights);
        }

        // adds the free term (at x^0)
        cc->EvalAddInPlace(cu, divcs->q.front());
        flag_c = true;
    }

    // Evaluate q and s2 at u. If their degrees are larger than k, then recursively apply the Paterson-Stockmeyer algorithm.
    Ciphertext<DCRTPoly> qu;

    if (Degree(divqr->q) > k) {
        qu = InnerEvalPolyPS(x, divqr->q, k, m - 1, powers, powers2);
    }
    else {
        // dq = k from construction
        // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
        auto qcopy = divqr->q;
        qcopy.resize(k);
        if (Degree(qcopy) > 0) {
            std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(qcopy));
            std::vector<VectorDataType> weights(Degree(qcopy));

            for (uint32_t i = 0; i < Degree(qcopy); i++) {
                ctxs[i]    = powers[i];
                weights[i] = divqr->q[i + 1];
            }

            qu = cc->EvalLinearWSumMutable(ctxs, weights);
            // the highest order term will always be 1 because q is monic
            cc->EvalAddInPlace(qu, powers[k - 1]);
        }
        else {
            qu = powers[k - 1]->Clone();
        }
        // adds the free term (at x^0)
        cc->EvalAddInPlace(qu, divqr->q.front());
    }

    uint32_t ds = Degree(s2);
    Ciphertext<DCRTPoly> su;

    if (std::equal(s2.begin(), s2.end(), divqr->q.begin())) {
        su = qu->Clone();
    }
    else {
        if (ds > k) {
            su = InnerEvalPolyPS(x, s2, k, m - 1, powers, powers2);
        }
        else {
            // ds = k from construction
            // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
            auto scopy = s2;
            scopy.resize(k);
            if (Degree(scopy) > 0) {
                std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(scopy));
                std::vector<VectorDataType> weights(Degree(scopy));

                for (uint32_t i = 0; i < Degree(scopy); ++i) {
                    ctxs[i]    = powers[i];
                    weights[i] = s2[i + 1];
                }

                su = cc->EvalLinearWSumMutable(ctxs, weights);
                // the highest order term will always be 1 because q is monic
                cc->EvalAddInPlace(su, powers[k - 1]);
            }
            else {
                su = powers[k - 1]->Clone();
            }
            // adds the free term (at x^0)
            cc->EvalAddInPlace(su, s2.front());
        }
    }

    Ciphertext<DCRTPoly> result;

    if (flag_c) {
        result = cc->EvalAdd(powers2[m - 1], cu);
    }
    else {
        result = cc->EvalAdd(powers2[m - 1], divcs->q.front());
    }

    result = cc->EvalMult(result, qu);
    cc->ModReduceInPlace(result);
    cc->EvalAddInPlace(result, su);

    return result;
}

template <typename VectorDataType>
static inline Ciphertext<DCRTPoly> internalEvalPolyPSWithPrecomp(std::shared_ptr<seriesPowers<DCRTPoly>> ctxtPowers,
                                                                 const std::vector<VectorDataType>& coefficients) {
    auto f2 = coefficients;
    auto n  = Degree(f2);
    f2.resize(n + 1);

    auto powers    = ctxtPowers->powersRe;
    auto powers2   = ctxtPowers->powers2Re;
    auto power2km1 = ctxtPowers->power2km1Re;
    auto k         = ctxtPowers->k;
    auto m         = ctxtPowers->m;

    // Compute k*2^{m-1}-k because we use it a lot
    uint32_t k2m2k = k * (1 << (m - 1)) - k;

    // Add x^{k(2^m - 1)} to the polynomial that has to be evaluated
    // std::vector<double> f2 = coefficients;
    f2.resize(2 * k2m2k + k + 1, 0.0);
    f2.back() = 1;

    // Divide f2 by x^{k*2^{m-1}}
    std::vector<VectorDataType> xkm(static_cast<int32_t>(k2m2k + k) + 1);
    xkm.back() = 1;
    auto divqr = LongDivisionPoly(f2, xkm);

    // Subtract x^{k(2^{m-1} - 1)} from r
    auto r2 = divqr->r;
    if (static_cast<int32_t>(k2m2k - Degree(divqr->r)) <= 0) {
        r2[static_cast<int32_t>(k2m2k)] -= 1;
        r2.resize(Degree(r2) + 1);
    }
    else {
        r2.resize(static_cast<int32_t>(k2m2k + 1), 0.0);
        r2.back() = -1;
    }

    // Divide r2 by q
    auto divcs = LongDivisionPoly(r2, divqr->q);

    // Add x^{k(2^{m-1} - 1)} to s
    auto s2 = divcs->r;
    s2.resize(static_cast<int32_t>(k2m2k + 1), 0.0);
    s2.back() = 1;

    auto cc = powers[0]->GetCryptoContext();

    // Evaluate c at u
    Ciphertext<DCRTPoly> cu;
    uint32_t dc = Degree(divcs->q);
    bool flag_c = false;

    if (dc >= 1) {
        if (dc == 1) {
            if (IsNotEqualOne(divcs->q[1])) {
                cu = cc->EvalMult(powers.front(), divcs->q[1]);
                // Do rescaling after scalar multiplication
                cc->ModReduceInPlace(cu);
            }
            else {
                cu = powers.front()->Clone();
            }
        }
        else {
            std::vector<Ciphertext<DCRTPoly>> ctxs(dc);
            std::vector<VectorDataType> weights(dc);

            for (uint32_t i = 0; i < dc; i++) {
                ctxs[i]    = powers[i];
                weights[i] = divcs->q[i + 1];
            }

            cu = cc->EvalLinearWSumMutable(ctxs, weights);
        }

        // adds the free term (at x^0)
        cc->EvalAddInPlace(cu, divcs->q.front());
        flag_c = true;
    }

    // Evaluate q and s2 at u. If their degrees are larger than k, then recursively apply the Paterson-Stockmeyer algorithm.
    Ciphertext<DCRTPoly> qu;

    if (Degree(divqr->q) > k) {
        qu = InnerEvalPolyPS(powers[0], divqr->q, k, m - 1, powers, powers2);
    }
    else {
        // dq = k from construction
        // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
        auto qcopy = divqr->q;
        qcopy.resize(k);
        if (Degree(qcopy) > 0) {
            std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(qcopy));
            std::vector<VectorDataType> weights(Degree(qcopy));

            for (uint32_t i = 0; i < Degree(qcopy); i++) {
                ctxs[i]    = powers[i];
                weights[i] = divqr->q[i + 1];
            }

            qu = cc->EvalLinearWSumMutable(ctxs, weights);
            // the highest order term will always be 1 because q is monic
            cc->EvalAddInPlace(qu, powers[k - 1]);
        }
        else {
            qu = powers[k - 1]->Clone();
        }
        // adds the free term (at x^0)
        cc->EvalAddInPlace(qu, divqr->q.front());
    }

    uint32_t ds = Degree(s2);
    Ciphertext<DCRTPoly> su;

    if (std::equal(s2.begin(), s2.end(), divqr->q.begin())) {
        su = qu->Clone();
    }
    else {
        if (ds > k) {
            su = InnerEvalPolyPS(powers[0], s2, k, m - 1, powers, powers2);
        }
        else {
            // ds = k from construction
            // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
            auto scopy = s2;
            scopy.resize(k);
            if (Degree(scopy) > 0) {
                std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(scopy));
                std::vector<VectorDataType> weights(Degree(scopy));

                for (uint32_t i = 0; i < Degree(scopy); i++) {
                    ctxs[i]    = powers[i];
                    weights[i] = s2[i + 1];
                }

                su = cc->EvalLinearWSumMutable(ctxs, weights);
                // the highest order term will always be 1 because q is monic
                cc->EvalAddInPlace(su, powers[k - 1]);
            }
            else {
                su = powers[k - 1]->Clone();
            }
            // adds the free term (at x^0)
            cc->EvalAddInPlace(su, s2.front());
        }
    }

    Ciphertext<DCRTPoly> result;

    if (flag_c) {
        result = cc->EvalAdd(powers2[m - 1], cu);
    }
    else {
        result = cc->EvalAdd(powers2[m - 1], divcs->q.front());
    }

    result = cc->EvalMult(result, qu);
    cc->ModReduceInPlace(result);
    cc->EvalAddInPlace(result, su);
    cc->EvalSubInPlace(result, power2km1);

    return result;
}

Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalPoly(ConstCiphertext<DCRTPoly>& x,
                                                  const std::vector<int64_t>& coeffs) const {
    return (Degree(coeffs) < 5) ? EvalPolyLinear(x, coeffs) : EvalPolyPS(x, coeffs);
}
Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalPoly(ConstCiphertext<DCRTPoly>& x,
                                                  const std::vector<double>& coeffs) const {
    return (Degree(coeffs) < 5) ? EvalPolyLinear(x, coeffs) : EvalPolyPS(x, coeffs);
}
Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalPoly(ConstCiphertext<DCRTPoly>& x,
                                                  const std::vector<std::complex<double>>& coeffs) const {
    return (Degree(coeffs) < 5) ? EvalPolyLinear(x, coeffs) : EvalPolyPS(x, coeffs);
}

Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalPolyWithPrecomp(std::shared_ptr<seriesPowers<DCRTPoly>> ctxtPowers,
                                                             const std::vector<int64_t>& coeffs) const {
    return (Degree(coeffs) < 5) ? internalEvalPolyLinearWithPrecomp(ctxtPowers->powersRe, coeffs) :
                                  internalEvalPolyPSWithPrecomp(ctxtPowers, coeffs);
}
Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalPolyWithPrecomp(std::shared_ptr<seriesPowers<DCRTPoly>> ctxtPowers,
                                                             const std::vector<double>& coeffs) const {
    return (Degree(coeffs) < 5) ? internalEvalPolyLinearWithPrecomp(ctxtPowers->powersRe, coeffs) :
                                  internalEvalPolyPSWithPrecomp(ctxtPowers, coeffs);
}
Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalPolyWithPrecomp(std::shared_ptr<seriesPowers<DCRTPoly>> ctxtPowers,
                                                             const std::vector<std::complex<double>>& coeffs) const {
    return (Degree(coeffs) < 5) ? internalEvalPolyLinearWithPrecomp(ctxtPowers->powersRe, coeffs) :
                                  internalEvalPolyPSWithPrecomp(ctxtPowers, coeffs);
}

Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalPolyLinear(ConstCiphertext<DCRTPoly>& x,
                                                        const std::vector<int64_t>& coeffs) const {
    return internalEvalPolyLinearWithPrecomp(internalEvalPowersLinear(x, coeffs)->powersRe, coeffs);
}
Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalPolyLinear(ConstCiphertext<DCRTPoly>& x,
                                                        const std::vector<double>& coeffs) const {
    return internalEvalPolyLinearWithPrecomp(internalEvalPowersLinear(x, coeffs)->powersRe, coeffs);
}
Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalPolyLinear(ConstCiphertext<DCRTPoly>& x,
                                                        const std::vector<std::complex<double>>& coeffs) const {
    return internalEvalPolyLinearWithPrecomp(internalEvalPowersLinear(x, coeffs)->powersRe, coeffs);
}

Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalPolyPS(ConstCiphertext<DCRTPoly>& x,
                                                    const std::vector<int64_t>& coeffs) const {
    return internalEvalPolyPSWithPrecomp(internalEvalPowersPS(x, coeffs), coeffs);
}
Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalPolyPS(ConstCiphertext<DCRTPoly>& x,
                                                    const std::vector<double>& coeffs) const {
    return internalEvalPolyPSWithPrecomp(internalEvalPowersPS(x, coeffs), coeffs);
}
Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalPolyPS(ConstCiphertext<DCRTPoly>& x,
                                                    const std::vector<std::complex<double>>& coeffs) const {
    return internalEvalPolyPSWithPrecomp(internalEvalPowersPS(x, coeffs), coeffs);
}

//------------------------------------------------------------------------------
// EVAL CHEBYSHEV SERIES
//------------------------------------------------------------------------------

template <typename VectorDataType>
std::shared_ptr<seriesPowers<DCRTPoly>> internalEvalChebyPolysLinear(ConstCiphertext<DCRTPoly>& x,
                                                                     const std::vector<VectorDataType>& coefficients,
                                                                     double a, double b) {
    auto cc    = x->GetCryptoContext();
    uint32_t k = coefficients.size() - 1;
    std::vector<Ciphertext<DCRTPoly>> T(k);

    // computes linear transformation y = -1 + 2 (x-a)/(b-a)
    // consumes one level when a <> -1 && b <> 1
    if ((a - std::round(a) < 1e-10) && (b - std::round(b) < 1e-10) && (std::round(a) == -1.0) &&
        (std::round(b) == 1.0)) {
        T[0] = x->Clone();
    }
    else {
        // linear transformation is needed
        double alpha = 2 / (b - a);
        double beta  = 2 * a / (b - a);

        T[0] = cc->EvalMult(x, alpha);
        cc->ModReduceInPlace(T[0]);
        cc->EvalAddInPlace(T[0], -1.0 - beta);
    }

    Ciphertext<DCRTPoly> yReduced = T[0]->Clone();
    uint32_t compositeDegree =
        std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(x->GetCryptoParameters())->GetCompositeDegree();

    // Computes Chebyshev polynomials up to degree k
    // for y: T_1(y) = y, T_2(y), ... , T_k(y)
    // uses binary tree multiplication
    for (uint32_t i = 2; i <= k; ++i) {
        // if i is a power of two
        if (!(i & (i - 1))) {
            // compute T_{2i}(y) = 2*T_i(y)^2 - 1
            auto square = cc->EvalSquare(T[i / 2 - 1]);
            T[i - 1]    = cc->EvalAdd(square, square);
            cc->ModReduceInPlace(T[i - 1]);
            cc->EvalAddInPlace(T[i - 1], -1.0);
            // TODO: (Andrey) Do we need this?
            if (i == 2) {
                cc->LevelReduceInPlace(T[i / 2 - 1], nullptr);
                cc->LevelReduceInPlace(yReduced, nullptr);
            }
            cc->LevelReduceInPlace(yReduced, nullptr);  // depth log_2 i + 1

            // i/2 will now be used only at a lower level
            if (i / 2 > 1) {
                cc->LevelReduceInPlace(T[i / 2 - 1], nullptr);
            }
            // TODO: (Andrey) until here.
            // If we need it, we can also add it in EvalChebyshevSeriesPS
        }
        else {
            // non-power of 2
            if (i % 2 == 1) {
                // if i is odd
                // compute T_{2i+1}(y) = 2*T_i(y)*T_{i+1}(y) - y
                auto prod = cc->EvalMult(T[i / 2 - 1], T[i / 2]);
                T[i - 1]  = cc->EvalAdd(prod, prod);
                cc->ModReduceInPlace(T[i - 1]);
                cc->EvalSubInPlace(T[i - 1], yReduced);
            }
            else {
                // i is even but not power of 2
                // compute T_{2i}(y) = 2*T_i(y)^2 - 1
                auto square = cc->EvalSquare(T[i / 2 - 1]);
                T[i - 1]    = cc->EvalAdd(square, square);
                cc->ModReduceInPlace(T[i - 1]);
                cc->EvalAddInPlace(T[i - 1], -1.0);
            }
        }
    }
    for (uint32_t i = 1; i < k; ++i) {
        uint32_t levelDiff = T[k - 1]->GetLevel() - T[i - 1]->GetLevel();
        cc->LevelReduceInPlace(T[i - 1], nullptr, levelDiff / compositeDegree);
    }
    return std::make_shared<seriesPowers<DCRTPoly>>(T);
}

template <typename VectorDataType>
static inline Ciphertext<DCRTPoly> internalEvalChebyshevSeriesLinearWithPrecomp(
    std::vector<Ciphertext<DCRTPoly>>& T, const std::vector<VectorDataType>& coefficients) {
    auto cc    = T[0]->GetCryptoContext();
    uint32_t k = coefficients.size() - 1;

    // perform scalar multiplication for the highest-order term
    auto result = cc->EvalMult(T[k - 1], coefficients[k]);

    // perform scalar multiplication for all other terms and sum them up
    for (uint32_t i = 0; i < k - 1; ++i) {
        if (IsNotEqualZero(coefficients[i + 1])) {
            cc->EvalMultInPlace(T[i], coefficients[i + 1]);
            cc->EvalAddInPlace(result, T[i]);
        }
    }

    // Do rescaling after scalar multiplication
    cc->ModReduceInPlace(result);

    // adds the free term (at x^0)
    cc->EvalAddInPlace(result, coefficients[0] / 2.0);

    return result;
}

template <typename VectorDataType>
static Ciphertext<DCRTPoly> InnerEvalChebyshevPS(ConstCiphertext<DCRTPoly>& x,
                                                 const std::vector<VectorDataType>& coefficients, uint32_t k,
                                                 uint32_t m, std::vector<Ciphertext<DCRTPoly>>& T,
                                                 std::vector<Ciphertext<DCRTPoly>>& T2) {
    auto cc = x->GetCryptoContext();
    uint32_t compositeDegree =
        std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(x->GetCryptoParameters())->GetCompositeDegree();

    // Compute k*2^{m-1}-k because we use it a lot
    uint32_t k2m2k = k * (1 << (m - 1)) - k;

    // Divide coefficients by T^{k*2^{m-1}}
    std::vector<VectorDataType> Tkm(static_cast<int32_t>(k2m2k + k) + 1);
    Tkm.back() = 1;
    auto divqr = LongDivisionChebyshev(coefficients, Tkm);

    // Subtract x^{k(2^{m-1} - 1)} from r
    auto r2 = divqr->r;
    if (static_cast<int32_t>(k2m2k - Degree(divqr->r)) <= 0) {
        r2[static_cast<int32_t>(k2m2k)] -= 1;
        r2.resize(Degree(r2) + 1);
    }
    else {
        r2.resize(static_cast<int32_t>(k2m2k + 1));
        r2.back() = -1;
    }

    // Divide r2 by q
    auto divcs = LongDivisionChebyshev(r2, divqr->q);

    // Add x^{k(2^{m-1} - 1)} to s
    auto s2 = divcs->r;
    s2.resize(static_cast<int32_t>(k2m2k + 1), 0.0);
    s2.back() = 1;

    // Evaluate c at u
    Ciphertext<DCRTPoly> cu;
    uint32_t dc = Degree(divcs->q);
    bool flag_c = false;
    if (dc >= 1) {
        if (dc == 1) {
            if (IsNotEqualOne(divcs->q[1])) {
                cu = cc->EvalMult(T.front(), divcs->q[1]);
                cc->ModReduceInPlace(cu);
            }
            else {
                cu = T.front()->Clone();
            }
        }
        else {
            std::vector<Ciphertext<DCRTPoly>> ctxs(dc);
            std::vector<VectorDataType> weights(dc);

            for (uint32_t i = 0; i < dc; ++i) {
                ctxs[i]    = T[i];
                weights[i] = divcs->q[i + 1];
            }

            cu = internalEvalLinearWSumMutable(ctxs, weights);
        }

        // adds the free term (at x^0)
        cc->EvalAddInPlace(cu, divcs->q.front() / 2.0);
        // Need to reduce levels up to the level of T2[m-1].
        uint32_t levelDiff = T2[m - 1]->GetLevel() - cu->GetLevel();
        cc->LevelReduceInPlace(cu, nullptr, levelDiff / compositeDegree);

        flag_c = true;
    }

    // Evaluate q and s2 at u. If their degrees are larger than k, then recursively apply the Paterson-Stockmeyer algorithm.
    Ciphertext<DCRTPoly> qu;

    if (Degree(divqr->q) > k) {
        qu = InnerEvalChebyshevPS(x, divqr->q, k, m - 1, T, T2);
    }
    else {
        // dq = k from construction
        // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
        auto qcopy = divqr->q;
        qcopy.resize(k);
        if (Degree(qcopy) > 0) {
            std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(qcopy));
            std::vector<VectorDataType> weights(Degree(qcopy));

            for (uint32_t i = 0; i < Degree(qcopy); i++) {
                ctxs[i]    = T[i];
                weights[i] = divqr->q[i + 1];
            }

            qu = cc->EvalLinearWSumMutable(ctxs, weights);
            // the highest order coefficient will always be a power of two up to 2^{m-1} because q is "monic" but the Chebyshev rule adds a factor of 2
            // we don't need to increase the depth by multiplying the highest order coefficient, but instead checking and summing, since we work with m <= 4.
            Ciphertext<DCRTPoly> sum = T[k - 1]->Clone();
            uint32_t limit           = log2(ToReal(divqr->q.back()));
            for (uint32_t i = 0; i < limit; ++i) {
                sum = cc->EvalAdd(sum, sum);
            }
            cc->EvalAddInPlace(qu, sum);
        }
        else {
            Ciphertext<DCRTPoly> sum = T[k - 1]->Clone();
            uint32_t limit           = log2(ToReal(divqr->q.back()));
            for (uint32_t i = 0; i < limit; ++i) {
                sum = cc->EvalAdd(sum, sum);
            }
            qu = sum;
        }

        // adds the free term (at x^0)
        cc->EvalAddInPlace(qu, divqr->q.front() / 2.0);
        // The number of levels of qu is the same as the number of levels of T[k-1] or T[k-1] + 1.
        // No need to reduce it to T2[m-1] because it only reaches here when m = 2.
    }

    Ciphertext<DCRTPoly> su;

    if (Degree(s2) > k) {
        su = InnerEvalChebyshevPS(x, s2, k, m - 1, T, T2);
    }
    else {
        // ds = k from construction
        // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
        auto scopy = s2;
        scopy.resize(k);
        if (Degree(scopy) > 0) {
            std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(scopy));
            std::vector<VectorDataType> weights(Degree(scopy));

            for (uint32_t i = 0; i < Degree(scopy); i++) {
                ctxs[i]    = T[i];
                weights[i] = s2[i + 1];
            }

            su = cc->EvalLinearWSumMutable(ctxs, weights);
            // the highest order coefficient will always be 1 because s2 is monic.
            cc->EvalAddInPlace(su, T[k - 1]);
        }
        else {
            su = T[k - 1]->Clone();
        }

        // adds the free term (at x^0)
        cc->EvalAddInPlace(su, s2.front() / 2.0);
        // The number of levels of su is the same as the number of levels of T[k-1] or T[k-1] + 1. Need to reduce it to T2[m-1] + 1.
        // su = cc->LevelReduce(su, nullptr, su->GetElements()[0].GetNumOfElements() - Lm + 1) ;
        cc->LevelReduceInPlace(su, nullptr);
    }

    Ciphertext<DCRTPoly> result;

    if (flag_c) {
        result = cc->EvalAdd(T2[m - 1], cu);
    }
    else {
        result = cc->EvalAdd(T2[m - 1], divcs->q.front() / 2.0);
    }

    result = cc->EvalMult(result, qu);
    cc->ModReduceInPlace(result);

    cc->EvalAddInPlace(result, su);

    return result;
}

template <typename VectorDataType>
std::shared_ptr<seriesPowers<DCRTPoly>> internalEvalChebyPolysPS(ConstCiphertext<DCRTPoly>& x,
                                                                 const std::vector<VectorDataType>& coefficients,
                                                                 double a, double b) {
    auto n     = Degree(coefficients);
    auto degs  = ComputeDegreesPS(n);
    uint32_t k = degs[0];
    uint32_t m = degs[1];

    // computes linear transformation y = -1 + 2 (x-a)/(b-a)
    // consumes one level when a <> -1 && b <> 1
    auto cc = x->GetCryptoContext();
    std::vector<Ciphertext<DCRTPoly>> T(k);
    if ((a - std::round(a) < 1e-10) && (b - std::round(b) < 1e-10) && (std::round(a) == -1.0) &&
        (std::round(b) == 1.0)) {
        // no linear transformation is needed if a = -1, b = 1
        // T_1(y) = y
        T[0] = x->Clone();
    }
    else {
        // linear transformation is needed
        double alpha = 2 / (b - a);
        double beta  = 2 * a / (b - a);

        T[0] = cc->EvalMult(x, alpha);
        cc->ModReduceInPlace(T[0]);
        cc->EvalAddInPlace(T[0], -1.0 - beta);
    }

    Ciphertext<DCRTPoly> y = T[0]->Clone();

    // Computes Chebyshev polynomials up to degree k
    // for y: T_1(y) = y, T_2(y), ... , T_k(y)
    // uses binary tree multiplication
    for (uint32_t i = 2; i <= k; ++i) {
        // if i is a power of two
        if (!(i & (i - 1))) {
            // compute T_{2i}(y) = 2*T_i(y)^2 - 1
            auto square = cc->EvalSquare(T[i / 2 - 1]);
            T[i - 1]    = cc->EvalAdd(square, square);
            cc->ModReduceInPlace(T[i - 1]);
            cc->EvalAddInPlace(T[i - 1], -1.0);
        }
        else {
            // non-power of 2
            if (i % 2 == 1) {
                // if i is odd
                // compute T_{2i+1}(y) = 2*T_i(y)*T_{i+1}(y) - y
                auto prod = cc->EvalMult(T[i / 2 - 1], T[i / 2]);
                T[i - 1]  = cc->EvalAdd(prod, prod);

                cc->ModReduceInPlace(T[i - 1]);
                cc->EvalSubInPlace(T[i - 1], y);
            }
            else {
                // i is even but not power of 2
                // compute T_{2i}(y) = 2*T_i(y)^2 - 1
                auto square = cc->EvalSquare(T[i / 2 - 1]);
                T[i - 1]    = cc->EvalAdd(square, square);
                cc->ModReduceInPlace(T[i - 1]);
                cc->EvalAddInPlace(T[i - 1], -1.0);
            }
        }
    }

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(T[k - 1]->GetCryptoParameters());

    auto algo = cc->GetScheme();

    if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
        // brings all powers of x to the same level
        for (uint32_t i = 1; i < k; ++i) {
            uint32_t levelDiff = T[k - 1]->GetLevel() - T[i - 1]->GetLevel();
            cc->LevelReduceInPlace(T[i - 1], nullptr, levelDiff);
        }
    }
    else {
        for (uint32_t i = 1; i < k; ++i) {
            algo->AdjustLevelsAndDepthInPlace(T[i - 1], T[k - 1]);
        }
    }

    std::vector<Ciphertext<DCRTPoly>> T2(m);
    // Compute the Chebyshev polynomials T_k(y), T_{2k}(y), T_{4k}(y), ... , T_{2^{m-1}k}(y)
    // T2[0] is used as a placeholder
    T2.front() = T.back();
    for (uint32_t i = 1; i < m; i++) {
        auto square = cc->EvalSquare(T2[i - 1]);
        T2[i]       = cc->EvalAdd(square, square);
        cc->ModReduceInPlace(T2[i]);
        cc->EvalAddInPlace(T2[i], -1.0);
    }

    // computes T_{k(2*m - 1)}(y)
    auto T2km1 = T2.front();
    for (uint32_t i = 1; i < m; i++) {
        // compute T_{k(2*m - 1)} = 2*T_{k(2^{m-1}-1)}(y)*T_{k*2^{m-1}}(y) - T_k(y)
        auto prod = cc->EvalMult(T2km1, T2[i]);
        T2km1     = cc->EvalAdd(prod, prod);
        cc->ModReduceInPlace(T2km1);
        cc->EvalSubInPlace(T2km1, T2.front());
    }

    // We also need to reduce the number of levels of T[k-1] and of T2[0] by another level.
    //  cc->LevelReduceInPlace(T[k-1], nullptr);
    //  cc->LevelReduceInPlace(T2.front(), nullptr);

    return std::make_shared<seriesPowers<DCRTPoly>>(T, T2, T2km1, k, m);
}

template <typename VectorDataType>
static inline Ciphertext<DCRTPoly> internalEvalChebyshevSeriesPSWithPrecomp(
    std::shared_ptr<seriesPowers<DCRTPoly>> ctxtPolys, const std::vector<VectorDataType>& coefficients) {
    auto f2 = coefficients;
    auto n  = Degree(f2);
    f2.resize(n + 1);

    auto T     = ctxtPolys->powersRe;
    auto T2    = ctxtPolys->powers2Re;
    auto T2km1 = ctxtPolys->power2km1Re;
    auto k     = ctxtPolys->k;
    auto m     = ctxtPolys->m;

    // Compute k*2^{m-1}-k because we use it a lot
    uint32_t k2m2k = k * (1 << (m - 1)) - k;

    // Add T^{k(2^m - 1)}(y) to the polynomial that has to be evaluated
    f2.resize(2 * k2m2k + k + 1, 0.0);
    f2.back() = 1;

    // Divide f2 by T^{k*2^{m-1}}
    std::vector<VectorDataType> Tkm(k2m2k + k + 1);
    Tkm.back() = 1;
    auto divqr = LongDivisionChebyshev(f2, Tkm);

    // Subtract x^{k(2^{m-1} - 1)} from r
    auto r2 = divqr->r;
    if (static_cast<int32_t>(k2m2k - Degree(r2)) <= 0) {
        r2[static_cast<int32_t>(k2m2k)] -= 1;
        r2.resize(Degree(r2) + 1);
    }
    else {
        r2.resize(static_cast<int32_t>(k2m2k + 1));
        r2.back() = -1;
    }

    // Divide r2 by q
    auto divcs = LongDivisionChebyshev(r2, divqr->q);

    // Add x^{k(2^{m-1} - 1)} to s
    auto s2 = divcs->r;
    s2.resize(k2m2k + 1);
    s2.back() = 1;

    auto cc = T[0]->GetCryptoContext();

    // Evaluate c at u
    Ciphertext<DCRTPoly> cu;
    uint32_t dc = Degree(divcs->q);
    bool flag_c = false;
    if (dc >= 1) {
        if (dc == 1) {
            if (IsNotEqualOne(divcs->q[1])) {
                cu = cc->EvalMult(T.front(), divcs->q[1]);
                cc->ModReduceInPlace(cu);
            }
            else {
                cu = T.front()->Clone();
            }
        }
        else {
            std::vector<Ciphertext<DCRTPoly>> ctxs(dc);
            std::vector<VectorDataType> weights(dc);

            for (uint32_t i = 0; i < dc; i++) {
                ctxs[i]    = T[i];
                weights[i] = divcs->q[i + 1];
            }

            cu = cc->EvalLinearWSumMutable(ctxs, weights);
        }

        // adds the free term (at x^0)
        cc->EvalAddInPlace(cu, divcs->q.front() / 2.0);
        // TODO : Andrey why not T2[m-1]->GetLevel() instead?
        // Need to reduce levels to the level of T2[m-1].
        //    uint32_t levelDiff = y->GetLevel() - cu->GetLevel() + ceil(log2(k)) + m - 1;
        //    cc->LevelReduceInPlace(cu, nullptr, levelDiff);

        flag_c = true;
    }

    // Evaluate q and s2 at u. If their degrees are larger than k, then recursively apply the Paterson-Stockmeyer algorithm.
    Ciphertext<DCRTPoly> qu;

    if (Degree(divqr->q) > k) {
        qu = InnerEvalChebyshevPS(T[0], divqr->q, k, m - 1, T, T2);
    }
    else {
        // dq = k from construction
        // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
        auto qcopy = divqr->q;
        qcopy.resize(k);
        if (Degree(qcopy) > 0) {
            std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(qcopy));
            std::vector<VectorDataType> weights(Degree(qcopy));

            for (uint32_t i = 0; i < Degree(qcopy); ++i) {
                ctxs[i]    = T[i];
                weights[i] = divqr->q[i + 1];
            }
            qu = internalEvalLinearWSumMutable(ctxs, weights);
            // the highest order coefficient will always be a power of two up to 2^{m-1} because q is "monic" but the Chebyshev rule adds a factor of 2
            // we don't need to increase the depth by multiplying the highest order coefficient, but instead checking and summing, since we work with m <= 4.
            Ciphertext<DCRTPoly> sum = T[k - 1]->Clone();
            uint32_t limit           = log2(ToReal(divqr->q.back()));
            for (uint32_t i = 0; i < limit; ++i) {
                sum = cc->EvalAdd(sum, sum);
            }
            cc->EvalAddInPlace(qu, sum);
        }
        else {
            Ciphertext<DCRTPoly> sum = T[k - 1]->Clone();
            uint32_t limit           = log2(ToReal(divqr->q.back()));
            for (uint32_t i = 0; i < limit; ++i) {
                sum = cc->EvalAdd(sum, sum);
            }
            qu = sum;
        }

        // adds the free term (at x^0)
        cc->EvalAddInPlace(qu, divqr->q.front() / 2.0);
        // The number of levels of qu is the same as the number of levels of T[k-1] + 1.
        // Will only get here when m = 2, so the number of levels of qu and T2[m-1] will be the same.
    }

    Ciphertext<DCRTPoly> su;

    if (Degree(s2) > k) {
        su = InnerEvalChebyshevPS(T[0], s2, k, m - 1, T, T2);
    }
    else {
        // ds = k from construction
        // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
        auto scopy = s2;
        scopy.resize(k);
        if (Degree(scopy) > 0) {
            std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(scopy));
            std::vector<VectorDataType> weights(Degree(scopy));

            for (uint32_t i = 0; i < Degree(scopy); ++i) {
                ctxs[i]    = T[i];
                weights[i] = s2[i + 1];
            }

            su = cc->EvalLinearWSumMutable(ctxs, weights);
            // the highest order coefficient will always be 1 because s2 is monic.
            cc->EvalAddInPlace(su, T[k - 1]);
        }
        else {
            su = T[k - 1];
        }

        // adds the free term (at x^0)
        cc->EvalAddInPlace(su, s2.front() / 2.0);
        // The number of levels of su is the same as the number of levels of T[k-1] + 1.
        // Will only get here when m = 2, so need to reduce the number of levels by 1.
    }

    // TODO : Andrey : here is different from 895 line
    // Reduce number of levels of su to number of levels of T2km1.
    //  cc->LevelReduceInPlace(su, nullptr);

    Ciphertext<DCRTPoly> result;

    if (flag_c) {
        result = cc->EvalAdd(T2[m - 1], cu);
    }
    else {
        result = cc->EvalAdd(T2[m - 1], divcs->q.front() / 2.0);
    }

    result = cc->EvalMult(result, qu);
    cc->ModReduceInPlace(result);

    cc->EvalAddInPlace(result, su);
    cc->EvalSubInPlace(result, T2km1);

    return result;
}

std::shared_ptr<seriesPowers<DCRTPoly>> AdvancedSHECKKSRNS::EvalChebyPolys(ConstCiphertext<DCRTPoly>& x,
                                                                           const std::vector<int64_t>& coefficients,
                                                                           double a, double b) const {
    return (Degree(coefficients) < 5) ? internalEvalChebyPolysLinear(x, coefficients, a, b) :
                                        internalEvalChebyPolysPS(x, coefficients, a, b);
}
std::shared_ptr<seriesPowers<DCRTPoly>> AdvancedSHECKKSRNS::EvalChebyPolys(ConstCiphertext<DCRTPoly>& x,
                                                                           const std::vector<double>& coefficients,
                                                                           double a, double b) const {
    return (Degree(coefficients) < 5) ? internalEvalChebyPolysLinear(x, coefficients, a, b) :
                                        internalEvalChebyPolysPS(x, coefficients, a, b);
}
std::shared_ptr<seriesPowers<DCRTPoly>> AdvancedSHECKKSRNS::EvalChebyPolys(
    ConstCiphertext<DCRTPoly>& x, const std::vector<std::complex<double>>& coefficients, double a, double b) const {
    return (Degree(coefficients) < 5) ? internalEvalChebyPolysLinear(x, coefficients, a, b) :
                                        internalEvalChebyPolysPS(x, coefficients, a, b);
}

Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalChebyshevSeries(ConstCiphertext<DCRTPoly>& x,
                                                             const std::vector<int64_t>& coeffs, double a,
                                                             double b) const {
    return (Degree(coeffs) < 5) ? EvalChebyshevSeriesLinear(x, coeffs, a, b) : EvalChebyshevSeriesPS(x, coeffs, a, b);
}
Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalChebyshevSeries(ConstCiphertext<DCRTPoly>& x,
                                                             const std::vector<double>& coeffs, double a,
                                                             double b) const {
    return (Degree(coeffs) < 5) ? EvalChebyshevSeriesLinear(x, coeffs, a, b) : EvalChebyshevSeriesPS(x, coeffs, a, b);
}
Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalChebyshevSeries(ConstCiphertext<DCRTPoly>& x,
                                                             const std::vector<std::complex<double>>& coeffs, double a,
                                                             double b) const {
    return (Degree(coeffs) < 5) ? EvalChebyshevSeriesLinear(x, coeffs, a, b) : EvalChebyshevSeriesPS(x, coeffs, a, b);
}

Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalChebyshevSeriesWithPrecomp(
    std::shared_ptr<seriesPowers<DCRTPoly>> ctxtPowers, const std::vector<int64_t>& coeffs) const {
    return (Degree(coeffs) < 5) ? internalEvalChebyshevSeriesLinearWithPrecomp(ctxtPowers->powersRe, coeffs) :
                                  internalEvalPolyPSWithPrecomp(ctxtPowers, coeffs);
}
Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalChebyshevSeriesWithPrecomp(
    std::shared_ptr<seriesPowers<DCRTPoly>> ctxtPowers, const std::vector<double>& coeffs) const {
    return (Degree(coeffs) < 5) ? internalEvalChebyshevSeriesLinearWithPrecomp(ctxtPowers->powersRe, coeffs) :
                                  internalEvalPolyPSWithPrecomp(ctxtPowers, coeffs);
}
Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalChebyshevSeriesWithPrecomp(
    std::shared_ptr<seriesPowers<DCRTPoly>> ctxtPowers, const std::vector<std::complex<double>>& coeffs) const {
    return (Degree(coeffs) < 5) ? internalEvalChebyshevSeriesLinearWithPrecomp(ctxtPowers->powersRe, coeffs) :
                                  internalEvalChebyshevSeriesPSWithPrecomp(ctxtPowers, coeffs);
}

Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalChebyshevSeriesLinear(ConstCiphertext<DCRTPoly>& x,
                                                                   const std::vector<int64_t>& coeffs, double a,
                                                                   double b) const {
    return internalEvalChebyshevSeriesLinearWithPrecomp(internalEvalChebyPolysLinear(x, coeffs, a, b)->powersRe,
                                                        coeffs);
}
Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalChebyshevSeriesLinear(ConstCiphertext<DCRTPoly>& x,
                                                                   const std::vector<double>& coeffs, double a,
                                                                   double b) const {
    return internalEvalChebyshevSeriesLinearWithPrecomp(internalEvalChebyPolysLinear(x, coeffs, a, b)->powersRe,
                                                        coeffs);
}
Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalChebyshevSeriesLinear(ConstCiphertext<DCRTPoly>& x,
                                                                   const std::vector<std::complex<double>>& coeffs,
                                                                   double a, double b) const {
    return internalEvalChebyshevSeriesLinearWithPrecomp(internalEvalChebyPolysLinear(x, coeffs, a, b)->powersRe,
                                                        coeffs);
}

Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalChebyshevSeriesPS(ConstCiphertext<DCRTPoly>& x,
                                                               const std::vector<int64_t>& coeffs, double a,
                                                               double b) const {
    return internalEvalChebyshevSeriesPSWithPrecomp(internalEvalChebyPolysPS(x, coeffs, a, b), coeffs);
}
Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalChebyshevSeriesPS(ConstCiphertext<DCRTPoly>& x,
                                                               const std::vector<double>& coeffs, double a,
                                                               double b) const {
    return internalEvalChebyshevSeriesPSWithPrecomp(internalEvalChebyPolysPS(x, coeffs, a, b), coeffs);
}
Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalChebyshevSeriesPS(ConstCiphertext<DCRTPoly>& x,
                                                               const std::vector<std::complex<double>>& coeffs,
                                                               double a, double b) const {
    return internalEvalChebyshevSeriesPSWithPrecomp(internalEvalChebyPolysPS(x, coeffs, a, b), coeffs);
}

//------------------------------------------------------------------------------
// EVAL LINEAR TRANSFORMATION
//------------------------------------------------------------------------------

}  // namespace lbcrypto
