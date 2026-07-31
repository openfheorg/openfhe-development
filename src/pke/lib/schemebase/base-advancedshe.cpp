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

#include "cryptocontext.h"
#include "key/privatekey.h"
#include "math/nbtheory.h"
#include "schemebase/base-advancedshe.h"
#include "schemebase/base-scheme.h"
#include "schemerns/rns-cryptoparameters.h"
#include "utils/parallel.h"

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace lbcrypto {

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalAddMany(const std::vector<Ciphertext<Element>>& ciphertextVec) const {
    const uint32_t size = ciphertextVec.size();
    if (size == 0)
        OPENFHE_THROW("Input ciphertext vector is empty.");

    uint32_t first = 0;
    while (first < size && ciphertextVec[first] == nullptr)
        ++first;
    if (first == size)
        OPENFHE_THROW("Input ciphertext vector has no non-null entries.");

    auto result = ciphertextVec[first]->Clone();
    auto algo   = result->GetCryptoContext()->GetScheme();
    for (uint32_t i = first + 1; i < size; ++i) {
        if (ciphertextVec[i] != nullptr)
            algo->EvalAddInPlace(result, ciphertextVec[i]);
    }

    return result;
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalAddManyInPlace(
    std::vector<Ciphertext<Element>>& ciphertextVec) const {
    const uint32_t size = ciphertextVec.size();
    if (size == 0)
        OPENFHE_THROW("Input ciphertext vector is empty.");

    uint32_t first = 0;
    while (first < size && ciphertextVec[first] == nullptr)
        ++first;
    if (first == size)
        OPENFHE_THROW("Input ciphertext vector has no non-null entries.");

    auto algo = ciphertextVec[first]->GetCryptoContext()->GetScheme();
    for (uint32_t i = first + 1; i < size; ++i) {
        if (ciphertextVec[i] != nullptr)
            algo->EvalAddInPlace(ciphertextVec[first], ciphertextVec[i]);
    }

    if (first != 0)
        ciphertextVec[0] = ciphertextVec[first];

    return ciphertextVec[0];
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalMultMany(const std::vector<Ciphertext<Element>>& ciphertextVec,
                                                           const std::vector<EvalKey<Element>>& evalKeys) const {
    const uint32_t size = ciphertextVec.size();
    if (size == 0)
        OPENFHE_THROW("Input ciphertext vector is empty.");

    if (size == 1)
        return ciphertextVec[0]->Clone();

    const uint32_t lim = size * 2 - 2;
    std::vector<Ciphertext<Element>> ciphertextMultVec(size - 1);

    // BASE_NUM_LEVELS_TO_DROP everywhere except composite-scaling CKKS.
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertextVec[0]->GetCryptoParameters());
    const uint32_t levelsToDrop = cryptoParams ? cryptoParams->GetCompositeDegree() : BASE_NUM_LEVELS_TO_DROP;

    auto algo = ciphertextVec[0]->GetCryptoContext()->GetScheme();

    uint32_t i = 0, j = 0;
    // input x input
    for (; i < (size - 1); i += 2) {
        ciphertextMultVec[j] = algo->EvalMultAndRelinearize(ciphertextVec[i], ciphertextVec[i + 1], evalKeys);
        algo->ModReduceInPlace(ciphertextMultVec[j++], levelsToDrop);
    }
    // odd size: the last input pairs with the first partial
    if (i < size) {
        ciphertextMultVec[j] =
            algo->EvalMultAndRelinearize(ciphertextVec[i], ciphertextMultVec[i + 1 - size], evalKeys);
        algo->ModReduceInPlace(ciphertextMultVec[j++], levelsToDrop);
        ciphertextMultVec[i + 1 - size].reset();
        i += 2;
    }
    // partial x partial
    for (; i < lim; i += 2) {
        ciphertextMultVec[j] =
            algo->EvalMultAndRelinearize(ciphertextMultVec[i - size], ciphertextMultVec[i + 1 - size], evalKeys);
        algo->ModReduceInPlace(ciphertextMultVec[j++], levelsToDrop);
        ciphertextMultVec[i - size].reset();
        ciphertextMultVec[i + 1 - size].reset();
    }

    return ciphertextMultVec.back();
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::AddRandomNoise(ConstCiphertext<Element> ciphertext) const {
    if (!ciphertext)
        OPENFHE_THROW("Input ciphertext is nullptr");

    std::uniform_real_distribution<double> distribution(0.0, 1.0);

    std::string kID           = ciphertext->GetKeyTag();
    const auto cryptoParams   = ciphertext->GetCryptoParameters();
    const auto encodingParams = cryptoParams->GetEncodingParams();
    const auto elementParams  = cryptoParams->GetElementParams();

    uint32_t n = elementParams->GetRingDimension();

    auto cc = ciphertext->GetCryptoContext();

    Plaintext plaintext;

    if (ciphertext->GetEncodingType() == CKKS_PACKED_ENCODING) {
        std::vector<std::complex<double>> randomIntVector(n);

        // first plaintext slot does not need to change
        randomIntVector[0].real(0);

        for (uint32_t i = 0; i < n - 1; i++) {
            randomIntVector[i + 1].real(distribution(PseudoRandomNumberGenerator::GetPRNG()));
        }

        plaintext = cc->MakeCKKSPackedPlaintext(randomIntVector, ciphertext->GetNoiseScaleDeg(), 0, nullptr,
                                                ciphertext->GetSlots());
    }
    else {
        DiscreteUniformGeneratorImpl<typename Element::Vector> dug;
        auto randomVector{dug.GenerateVector(n - 1, encodingParams->GetPlaintextModulus())};

        std::vector<int64_t> randomIntVector(n);

        // first plaintext slot does not need to change
        randomIntVector[0] = 0;

        for (uint32_t i = 0; i < n - 1; i++) {
            randomIntVector[i + 1] = randomVector[i].ConvertToInt();
        }

        plaintext = cc->MakePackedPlaintext(randomIntVector);
    }

    plaintext->Encode();
    plaintext->GetElement<Element>().SetFormat(EVALUATION);
    auto algo = cc->GetScheme();
    return algo->EvalAdd(ciphertext, plaintext);
}

template <class Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> AdvancedSHEBase<Element>::EvalSumKeyGen(
    const PrivateKey<Element> privateKey) const {
    if (!privateKey)
        OPENFHE_THROW("Input private key is nullptr");

    // get automorphism indices and convert them to a vector
    std::set<uint32_t> indx_set{GenerateIndexListForEvalSum(privateKey)};
    std::vector<uint32_t> indices(indx_set.begin(), indx_set.end());

    auto algo = privateKey->GetCryptoContext()->GetScheme();
    return algo->EvalAutomorphismKeyGen(privateKey, indices);
}

template <class Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> AdvancedSHEBase<Element>::EvalSumRowsKeyGen(
    const PrivateKey<Element> privateKey, uint32_t rowSize, uint32_t subringDim, std::vector<uint32_t>& indices) const {
    auto cc = privateKey->GetCryptoContext();

    if (!isCKKS(cc->getSchemeId()))
        OPENFHE_THROW("Matrix summation of row-vectors is only supported for CKKSPackedEncoding.");

    uint32_t m =
        (subringDim == 0) ? privateKey->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() : subringDim;

    if (!IsPowerOfTwo(m))
        OPENFHE_THROW("Matrix summation of row-vectors is not supported for arbitrary cyclotomics.");

    std::set<uint32_t> rowsIndices{GenerateIndices2nComplexRows(rowSize, m)};
    indices.reserve(indices.size() + rowsIndices.size());
    indices.insert(indices.end(), rowsIndices.begin(), rowsIndices.end());

    auto algo = cc->GetScheme();
    return algo->EvalAutomorphismKeyGen(privateKey, indices);
}

template <class Element>
std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> AdvancedSHEBase<Element>::EvalSumColsKeyGen(
    const PrivateKey<Element> privateKey, std::vector<uint32_t>& indices) const {
    auto cc = privateKey->GetCryptoContext();

    if (!isCKKS(cc->getSchemeId()))
        OPENFHE_THROW("Matrix summation of column-vectors is only supported for CKKSPackedEncoding.");

    const auto cryptoParams = privateKey->GetCryptoParameters();
    uint32_t M              = cryptoParams->GetElementParams()->GetCyclotomicOrder();
    if (!IsPowerOfTwo(M))
        OPENFHE_THROW("Matrix summation of column-vectors is not supported for arbitrary cyclotomics.");

    uint32_t batchSize = cryptoParams->GetEncodingParams()->GetBatchSize();

    // get indices for EvalSumCols() and merge them with the indices for EvalSum()
    std::set<uint32_t> evalSumColsIndices = GenerateIndices2nComplexCols(batchSize, M);
    std::set<uint32_t> evalSumIndices     = GenerateIndexListForEvalSum(privateKey);
    evalSumColsIndices.merge(evalSumIndices);
    indices.reserve(indices.size() + evalSumColsIndices.size());
    indices.insert(indices.end(), evalSumColsIndices.begin(), evalSumColsIndices.end());

    auto algo = cc->GetScheme();
    return algo->EvalAutomorphismKeyGen(privateKey, indices);
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalSum(ConstCiphertext<Element> ciphertext, uint32_t batchSize,
                                                      const std::map<uint32_t, EvalKey<Element>>& evalKeyMap) const {
    const auto cryptoParams   = ciphertext->GetCryptoParameters();
    const auto encodingParams = cryptoParams->GetEncodingParams();

    if ((encodingParams->GetBatchSize() == 0))
        OPENFHE_THROW(
            "Packed encoding parameters 'batch size' is not set; "
            "Please check the EncodingParams passed to the crypto context.");

    uint32_t m = cryptoParams->GetElementParams()->GetCyclotomicOrder();

    Ciphertext<Element> newCiphertext = ciphertext->Clone();

    if (IsPowerOfTwo(m)) {
        if (ciphertext->GetEncodingType() == CKKS_PACKED_ENCODING)
            newCiphertext = EvalSum2nComplex(newCiphertext, batchSize, m, evalKeyMap);
        else
            newCiphertext = EvalSum_2n(newCiphertext, batchSize, m, evalKeyMap);
    }
    else {  // Arbitrary cyclotomics
        if (encodingParams->GetPlaintextGenerator() == 0) {
            OPENFHE_THROW(
                "Packed encoding parameters 'plaintext "
                "generator' is not set; Please check the "
                "EncodingParams passed to the crypto context.");
        }
        else {
            auto algo = ciphertext->GetCryptoContext()->GetScheme();

            uint32_t g = encodingParams->GetPlaintextGenerator();
            for (int i = 0; i < std::floor(std::log2(batchSize)); i++) {
                newCiphertext = algo->EvalAdd(newCiphertext, algo->EvalAutomorphism(newCiphertext, g, evalKeyMap));
                g             = (g * g) % m;
            }
        }
    }

    return newCiphertext;
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalSumRows(ConstCiphertext<Element> ciphertext, uint32_t numRows,
                                                          const std::map<uint32_t, EvalKey<Element>>& evalSumKeys,
                                                          uint32_t subringDim) const {
    if (ciphertext->GetEncodingType() != CKKS_PACKED_ENCODING)
        OPENFHE_THROW("Matrix summation of row-vectors is only supported for CKKS packed encoding.");

    const auto cryptoParams   = ciphertext->GetCryptoParameters();
    const auto encodingParams = cryptoParams->GetEncodingParams();
    if ((encodingParams->GetBatchSize() == 0))
        OPENFHE_THROW(
            "Packed encoding parameters 'batch size' is not set. Please check the EncodingParams passed to the crypto context.");

    uint32_t m = (subringDim == 0) ? cryptoParams->GetElementParams()->GetCyclotomicOrder() : subringDim;
    if (!IsPowerOfTwo(m))
        OPENFHE_THROW("Matrix summation of row-vectors is not supported for arbitrary cyclotomics.");

    return EvalSum2nComplexRows(ciphertext->Clone(), numRows, m, evalSumKeys);
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalSumCols(
    ConstCiphertext<Element> ciphertext, uint32_t numCols, const std::map<uint32_t, EvalKey<Element>>& evalSumKeyMap,
    const std::map<uint32_t, EvalKey<Element>>& evalSumColsKeyMap) const {
    if (!ciphertext)
        OPENFHE_THROW("Input ciphertext is nullptr");
    if (!evalSumKeyMap.size())
        OPENFHE_THROW("Input evalKeys map is empty");
    if (!evalSumColsKeyMap.size())
        OPENFHE_THROW("Input rightEvalKeys map is empty");
    if (ciphertext->GetEncodingType() != CKKS_PACKED_ENCODING)
        OPENFHE_THROW("Matrix summation of column-vectors is only supported for CKKS packed encoding.");

    const uint32_t slots = ciphertext->GetSlots();
    if (slots < numCols)
        OPENFHE_THROW("The number of columns ca not be greater than the number of slots.");

    const auto cryptoParams   = ciphertext->GetCryptoParameters();
    const auto encodingParams = cryptoParams->GetEncodingParams();
    if ((encodingParams->GetBatchSize() == 0))
        OPENFHE_THROW(
            "Packed encoding parameters 'batch size' is not set. Please check the EncodingParams passed to the crypto context.");

    const auto elementParams = cryptoParams->GetElementParams();
    uint32_t m               = elementParams->GetCyclotomicOrder();
    if (!IsPowerOfTwo(m))
        OPENFHE_THROW("Matrix summation of column-vectors is not supported for arbitrary cyclotomics.");

    std::vector<std::complex<double>> mask(slots, 0);  // create a mask vector and set all its elements to zero
    for (size_t i = 0; i < mask.size(); i++) {
        if (i % numCols == 0)
            mask[i] = 1;
    }

    Ciphertext<Element> newCiphertext = EvalSum2nComplex(ciphertext->Clone(), numCols, m, evalSumKeyMap);
    auto cc                           = ciphertext->GetCryptoContext();
    auto algo                         = cc->GetScheme();
    Plaintext plaintext               = cc->MakeCKKSPackedPlaintext(mask, 1, 0, nullptr, slots);
    algo->EvalMultInPlace(newCiphertext, plaintext);

    return EvalSum2nComplexCols(newCiphertext, numCols, m, evalSumColsKeyMap);
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalInnerProduct(
    ConstCiphertext<Element> ciphertext1, ConstCiphertext<Element> ciphertext2, uint32_t batchSize,
    const std::map<uint32_t, EvalKey<Element>>& evalSumKeyMap, const EvalKey<Element> evalMultKey) const {
    auto algo = ciphertext1->GetCryptoContext()->GetScheme();

    Ciphertext<Element> result = algo->EvalMult(ciphertext1, ciphertext2, evalMultKey);

    result = EvalSum(result, batchSize, evalSumKeyMap);

    // add a random number to all slots except for the first one so that no
    // information is leaked
    // if (ciphertext1->GetEncodingType() != CKKS_PACKED_ENCODING)
    //   result = AddRandomNoise(result);
    return result;
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalInnerProduct(
    ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext, uint32_t batchSize,
    const std::map<uint32_t, EvalKey<Element>>& evalSumKeyMap) const {
    auto algo = ciphertext->GetCryptoContext()->GetScheme();

    Ciphertext<Element> result = algo->EvalMult(ciphertext, plaintext);

    result = EvalSum(result, batchSize, evalSumKeyMap);

    // add a random number to all slots except for the first one so that no
    // information is leaked
    // if (ciphertext1->GetEncodingType() != CKKS_PACKED_ENCODING)
    //   result = AddRandomNoise(result);
    return result;
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalMerge(const std::vector<Ciphertext<Element>>& ciphertextVec,
                                                        const std::map<uint32_t, EvalKey<Element>>& evalKeyMap) const {
    if (ciphertextVec.size() == 0)
        OPENFHE_THROW("the vector of ciphertexts to be merged cannot be empty");

    const std::shared_ptr<CryptoParametersBase<Element>> cryptoParams = ciphertextVec[0]->GetCryptoParameters();
    Ciphertext<Element> ciphertextMerged(std::make_shared<CiphertextImpl<Element>>(*(ciphertextVec[0])));

    auto cc = ciphertextVec[0]->GetCryptoContext();

    Plaintext plaintext;
    if (ciphertextVec[0]->GetEncodingType() == CKKS_PACKED_ENCODING) {
        std::vector<std::complex<double>> mask({{1, 0}, {0, 0}});
        plaintext = cc->MakeCKKSPackedPlaintext(mask, 1, 0, nullptr, ciphertextVec[0]->GetSlots());
    }
    else {
        std::vector<int64_t> mask = {1, 0};
        plaintext                 = cc->MakePackedPlaintext(mask);
    }
    auto algo = ciphertextVec[0]->GetCryptoContext()->GetScheme();

    ciphertextMerged = algo->EvalMult(ciphertextMerged, plaintext);

    for (size_t i = 1; i < ciphertextVec.size(); i++) {
        ciphertextMerged = algo->EvalAdd(
            ciphertextMerged,
            algo->EvalAtIndex(algo->EvalMult(ciphertextVec[i], plaintext), -static_cast<int32_t>(i), evalKeyMap));
    }

    return ciphertextMerged;
}

static_assert(PARTIAL_SUM_RADIX >= 2 && (PARTIAL_SUM_RADIX & (PARTIAL_SUM_RADIX - 1)) == 0,
              "PARTIAL_SUM_RADIX must be a power of two >= 2");

template <class Element>
std::set<uint32_t> AdvancedSHEBase<Element>::GenerateEvalSumIndices(uint32_t g0, uint32_t size, uint32_t m) {
    constexpr uint32_t radix = PARTIAL_SUM_RADIX;
    std::set<uint32_t> indices;
    uint64_t g = g0;
    for (uint32_t s = 1; s < size; s *= radix) {
        // Level automorphisms g^i = g0^(i * s) for the level's up to radix-1 rotations.
        uint64_t gi = g;
        for (uint32_t i = 1; i < radix && i * s < size; ++i) {
            indices.insert(static_cast<uint32_t>(gi));
            gi = gi * g % m;
        }
        for (uint32_t r = radix; r > 1; r >>= 1)
            g = g * g % m;
    }

    return indices;
}

template <class Element>
std::set<uint32_t> AdvancedSHEBase<Element>::GenerateIndices_2n(uint32_t batchSize, uint32_t m) {
    std::set<uint32_t> indices;
    if (batchSize > 1) {
        if (2 * batchSize < m)
            return GenerateEvalSumIndices(5, batchSize, m);

        indices = GenerateEvalSumIndices(5, batchSize / 2, m);
        indices.insert(m - 1);
    }

    return indices;
}

template <class Element>
std::set<uint32_t> AdvancedSHEBase<Element>::GenerateIndices2nComplex(uint32_t batchSize, uint32_t m) {
    return GenerateEvalSumIndices(5, batchSize, m);
}

template <class Element>
std::set<uint32_t> AdvancedSHEBase<Element>::GenerateIndices2nComplexRows(uint32_t rowSize, uint32_t m) {
    const uint32_t colSize = m / (4 * rowSize);
    const uint32_t g0      = (NativeInteger(5).ModExp(rowSize, m)).ConvertToInt<uint32_t>();
    return GenerateEvalSumIndices(g0, colSize, m);
}

template <class Element>
std::set<uint32_t> AdvancedSHEBase<Element>::GenerateIndices2nComplexCols(uint32_t batchSize, uint32_t m) {
    const uint32_t g0 = NativeInteger(5).ModInverse(m).ConvertToInt<uint32_t>();
    return GenerateEvalSumIndices(g0, batchSize, m);
}

template <class Element>
std::set<uint32_t> AdvancedSHEBase<Element>::GenerateIndexListForEvalSum(const PrivateKey<Element>& privateKey) {
    const auto cryptoParams   = privateKey->GetCryptoParameters();
    const auto encodingParams = cryptoParams->GetEncodingParams();
    const auto elementParams  = cryptoParams->GetElementParams();

    uint32_t batchSize = encodingParams->GetBatchSize();
    uint32_t m         = elementParams->GetCyclotomicOrder();

    std::set<uint32_t> indices;
    if (IsPowerOfTwo(m)) {
        auto ccInst = privateKey->GetCryptoContext();
        // CKKS Packing
        indices =
            isCKKS(ccInst->getSchemeId()) ? GenerateIndices2nComplex(batchSize, m) : GenerateIndices_2n(batchSize, m);
    }
    else {
        // Arbitrary cyclotomics
        auto isize = static_cast<size_t>(std::floor(std::log2(batchSize)));
        uint32_t g = encodingParams->GetPlaintextGenerator();
        for (size_t i = 0; i < isize; i++) {
            indices.insert(g);
            g = (g * g) % m;
        }
    }

    return indices;
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalSumRadixFold(
    ConstCiphertext<Element>& ciphertext, uint32_t g0, uint32_t size, uint32_t m,
    const std::map<uint32_t, EvalKey<Element>>& evalKeyMap) const {
    Ciphertext<Element> result = ciphertext->Clone();
    if (size <= 1)
        return result;

    constexpr uint32_t radix = PARTIAL_SUM_RADIX;
    auto algo                = ciphertext->GetCryptoContext()->GetScheme();
    const auto cryptoParams  = std::dynamic_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());

    if (!cryptoParams || cryptoParams->GetKeySwitchTechnique() != HYBRID) {
        uint64_t g = g0;
        for (uint32_t s = 1; s < size; s *= radix) {
            Ciphertext<Element> base = result->Clone();
            auto digits              = algo->EvalFastRotationPrecompute(base);
            uint64_t gi              = g;
            for (uint32_t i = 1; i < radix && i * s < size; ++i) {
                const auto autoIndex = static_cast<uint32_t>(gi);
                auto evalKeyIterator = evalKeyMap.find(autoIndex);
                if (evalKeyIterator == evalKeyMap.end())
                    OPENFHE_THROW("EvalKey for index [" + std::to_string(autoIndex) + "] is not found.");
                result =
                    algo->EvalAdd(result, algo->EvalAutomorphismCore(base, autoIndex, digits, evalKeyIterator->second));
                gi = gi * g % m;
            }
            for (uint32_t r = radix; r > 1; r >>= 1)
                g = g * g % m;
        }
        return result;
    }

    const uint32_t N         = ciphertext->GetCryptoContext()->GetRingDimension();
    std::vector<Element>& cv = result->GetElements();
    const auto paramsQl      = cv[0].GetParams();
    const auto paramsP       = cryptoParams->GetParamsP();
    const auto paramsQlP     = cv[0].GetExtendedCRTBasis(paramsP);
    const uint32_t sizeQl    = paramsQl->GetParams().size();
    const uint32_t sizeQlP   = paramsQlP->GetParams().size();

    const PlaintextModulus t = (cryptoParams->GetNoiseScale() == 1) ? 0 : cryptoParams->GetPlaintextModulus();

    Element acc(paramsQlP, Format::EVALUATION, true);
    auto cMult = cv[0].TimesNoCheck(cryptoParams->GetPModq());
    for (uint32_t i = 0; i < sizeQl; ++i)
        acc.SetElementAtIndex(i, std::move(cMult.GetElementAtIndex(i)));

    std::vector<uint32_t> vec(N);
    uint64_t g = g0;
    for (uint32_t s = 1; s < size; s *= radix) {
        auto digits = algo->EvalKeySwitchPrecomputeCore(cv[1], cryptoParams);

        Element lvl0(paramsQlP, Format::EVALUATION, true);
        Element lvl1(paramsQlP, Format::EVALUATION, true);

        uint64_t gi = g;
        for (uint32_t i = 1; i < radix && i * s < size; ++i) {
            const auto autoIndex = static_cast<uint32_t>(gi);
            auto evalKeyIterator = evalKeyMap.find(autoIndex);
            if (evalKeyIterator == evalKeyMap.end())
                OPENFHE_THROW("EvalKey for index [" + std::to_string(autoIndex) + "] is not found.");

            PrecomputeAutoMap(N, autoIndex, &vec);

            auto ba = algo->EvalFastKeySwitchCoreExt(digits, evalKeyIterator->second, paramsQl);

            // ba[0] += acc;
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQlP))
            for (uint32_t j = 0; j < sizeQlP; ++j)
                ba[0].GetAllElements()[j] += acc.GetAllElements()[j];

            ba[0] = ba[0].AutomorphismTransform(autoIndex, vec);
            ba[1] = ba[1].AutomorphismTransform(autoIndex, vec);

            // lvl0 += ba[0]; lvl1 += ba[1];
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQlP))
            for (uint32_t j = 0; j < sizeQlP; ++j) {
                lvl0.GetAllElements()[j] += ba[0].GetAllElements()[j];
                lvl1.GetAllElements()[j] += ba[1].GetAllElements()[j];
            }

            gi = gi * g % m;
        }

        // acc += lvl0;
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQlP))
        for (uint32_t j = 0; j < sizeQlP; ++j)
            acc.GetAllElements()[j] += lvl0.GetAllElements()[j];

        // Element 1 settles once per level from the level's extended sum: the next level's
        // rotations need its digit decomposition.
        cv[1] += lvl1.ApproxModDown(paramsQl, paramsP, cryptoParams->GetPInvModq(), cryptoParams->GetPInvModqPrecon(),
                                    cryptoParams->GetPHatInvModp(), cryptoParams->GetPHatInvModpPrecon(),
                                    cryptoParams->GetPHatModq(), cryptoParams->GetModqBarrettMu(),
                                    cryptoParams->GettInvModp(), cryptoParams->GettInvModpPrecon(), t,
                                    cryptoParams->GettModqPrecon());

        for (uint32_t r = radix; r > 1; r >>= 1)
            g = g * g % m;
    }

    cv[0] =
        acc.ApproxModDown(paramsQl, paramsP, cryptoParams->GetPInvModq(), cryptoParams->GetPInvModqPrecon(),
                          cryptoParams->GetPHatInvModp(), cryptoParams->GetPHatInvModpPrecon(),
                          cryptoParams->GetPHatModq(), cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
                          cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());

    return result;
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalSum_2n(ConstCiphertext<Element> ciphertext, uint32_t batchSize,
                                                         uint32_t m,
                                                         const std::map<uint32_t, EvalKey<Element>>& evalKeys) const {
    if (batchSize <= 1)
        return ciphertext->Clone();

    if (2 * batchSize < m)
        return EvalSumRadixFold(ciphertext, 5, batchSize, m, evalKeys);

    auto result = EvalSumRadixFold(ciphertext, 5, batchSize / 2, m, evalKeys);
    auto algo   = ciphertext->GetCryptoContext()->GetScheme();
    return algo->EvalAdd(result, algo->EvalAutomorphism(result, m - 1, evalKeys));
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalSum2nComplex(
    ConstCiphertext<Element> ciphertext, uint32_t batchSize, uint32_t m,
    const std::map<uint32_t, EvalKey<Element>>& evalKeys) const {
    return EvalSumRadixFold(ciphertext, 5, batchSize, m, evalKeys);
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalSum2nComplexRows(
    ConstCiphertext<Element> ciphertext, uint32_t rowSize, uint32_t m,
    const std::map<uint32_t, EvalKey<Element>>& evalKeys) const {
    const uint32_t colSize = m / (4 * rowSize);
    const uint32_t g0      = (NativeInteger(5).ModExp(rowSize, m)).ConvertToInt<uint32_t>();
    return EvalSumRadixFold(ciphertext, g0, colSize, m, evalKeys);
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalSum2nComplexCols(
    ConstCiphertext<Element> ciphertext, uint32_t batchSize, uint32_t m,
    const std::map<uint32_t, EvalKey<Element>>& evalKeys) const {
    const uint32_t g0 = NativeInteger(5).ModInverse(m).ConvertToInt<uint32_t>();
    return EvalSumRadixFold(ciphertext, g0, batchSize, m, evalKeys);
}

}  // namespace lbcrypto

// the code below is from base-advancedshe-impl.cpp
namespace lbcrypto {

template class AdvancedSHEBase<DCRTPoly>;

}  // namespace lbcrypto
