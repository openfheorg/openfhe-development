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
#include "schemebase/base-advancedshe.h"

#include "key/privatekey.h"
#include "cryptocontext.h"
#include "schemebase/base-scheme.h"

namespace lbcrypto {

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalAddMany(const std::vector<Ciphertext<Element>>& ciphertextVec) const {
    const size_t inSize = ciphertextVec.size();

    if (ciphertextVec.size() < 1)
        OPENFHE_THROW(config_error, "Input ciphertext vector size should be 1 or more");

    const size_t lim = inSize * 2 - 2;
    std::vector<Ciphertext<Element>> ciphertextSumVec;
    ciphertextSumVec.resize(inSize - 1);
    size_t ctrIndex = 0;

    auto algo = ciphertextVec[0]->GetCryptoContext()->GetScheme();

    for (size_t i = 0; i < lim; i = i + 2) {
        ciphertextSumVec[ctrIndex++] =
            algo->EvalAdd(i < inSize ? ciphertextVec[i] : ciphertextSumVec[i - inSize],
                          i + 1 < inSize ? ciphertextVec[i + 1] : ciphertextSumVec[i + 1 - inSize]);
    }

    return ciphertextSumVec.back();
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalAddManyInPlace(
    std::vector<Ciphertext<Element>>& ciphertextVec) const {
    if (ciphertextVec.size() < 1)
        OPENFHE_THROW(config_error, "Input ciphertext vector size should be 1 or more");

    auto algo = ciphertextVec[0]->GetCryptoContext()->GetScheme();

    for (size_t j = 1; j < ciphertextVec.size(); j = j * 2) {
        for (size_t i = 0; i < ciphertextVec.size(); i = i + 2 * j) {
            if ((i + j) < ciphertextVec.size()) {
                if (ciphertextVec[i] != nullptr && ciphertextVec[i + j] != nullptr) {
                    ciphertextVec[i] = algo->EvalAdd(ciphertextVec[i], ciphertextVec[i + j]);
                }
                else if (ciphertextVec[i] == nullptr && ciphertextVec[i + j] != nullptr) {
                    ciphertextVec[i] = ciphertextVec[i + j];
                }
            }
        }
    }

    Ciphertext<Element> result(std::make_shared<CiphertextImpl<Element>>(*(ciphertextVec[0])));

    return result;
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalMultMany(const std::vector<Ciphertext<Element>>& ciphertextVec,
                                                           const std::vector<EvalKey<Element>>& evalKeys) const {
    if (ciphertextVec.size() < 1)
        OPENFHE_THROW(config_error, "Input ciphertext vector size should be 1 or more");

    const size_t inSize = ciphertextVec.size();
    const size_t lim    = inSize * 2 - 2;
    std::vector<Ciphertext<Element>> ciphertextMultVec;
    ciphertextMultVec.resize(inSize - 1);
    size_t ctrIndex = 0;

    auto algo = ciphertextVec[0]->GetCryptoContext()->GetScheme();

    for (size_t i = 0; i < lim; i = i + 2) {
        ciphertextMultVec[ctrIndex] = algo->EvalMultAndRelinearize(
            i < inSize ? ciphertextVec[i] : ciphertextMultVec[i - inSize],
            i + 1 < inSize ? ciphertextVec[i + 1] : ciphertextMultVec[i + 1 - inSize], evalKeys);
        algo->ModReduceInPlace(ciphertextMultVec[ctrIndex++], 1);
    }

    return ciphertextMultVec.back();
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::AddRandomNoise(ConstCiphertext<Element> ciphertext) const {
    if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

    std::uniform_real_distribution<double> distribution(0.0, 1.0);

    std::string kID           = ciphertext->GetKeyTag();
    const auto cryptoParams   = ciphertext->GetCryptoParameters();
    const auto encodingParams = cryptoParams->GetEncodingParams();
    const auto elementParams  = cryptoParams->GetElementParams();

    usint n = elementParams->GetRingDimension();

    auto cc = ciphertext->GetCryptoContext();

    Plaintext plaintext;

    if (ciphertext->GetEncodingType() == CKKS_PACKED_ENCODING) {
        std::vector<std::complex<double>> randomIntVector(n);

        // first plaintext slot does not need to change
        randomIntVector[0].real(0);

        for (usint i = 0; i < n - 1; i++) {
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

        for (usint i = 0; i < n - 1; i++) {
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
std::shared_ptr<std::map<usint, EvalKey<Element>>> AdvancedSHEBase<Element>::EvalSumKeyGen(
    const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey) const {
    if (!privateKey)
        OPENFHE_THROW(config_error, "Input private key is nullptr");
    /*
   * we don't validate publicKey as it is needed by NTRU-based scheme only
   * NTRU-based scheme only and it is checked for null later.
   */
    const auto cryptoParams   = privateKey->GetCryptoParameters();
    const auto encodingParams = cryptoParams->GetEncodingParams();
    const auto elementParams  = cryptoParams->GetElementParams();

    usint batchSize = encodingParams->GetBatchSize();
    usint m         = elementParams->GetCyclotomicOrder();

    // stores automorphism indices needed for EvalSum
    std::vector<usint> indices;

    if (IsPowerOfTwo(m)) {
        auto ccInst = privateKey->GetCryptoContext();
        // CKKS Packing
        indices = ccInst->getSchemeId() == SCHEME::CKKSRNS_SCHEME ? GenerateIndices2nComplex(batchSize, m) :
                                                                    GenerateIndices_2n(batchSize, m);
    }
    else {  // Arbitrary cyclotomics
        usint g = encodingParams->GetPlaintextGenerator();
        for (int i = 0; i < floor(log2(batchSize)); i++) {
            indices.push_back(g);
            g = (g * g) % m;
        }
    }

    auto algo = privateKey->GetCryptoContext()->GetScheme();
    return algo->EvalAutomorphismKeyGen(privateKey, indices);
}

template <class Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> AdvancedSHEBase<Element>::EvalSumRowsKeyGen(
    const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey, usint rowSize, usint subringDim) const {
    auto cc = privateKey->GetCryptoContext();

    if (cc->getSchemeId() != SCHEME::CKKSRNS_SCHEME)
        OPENFHE_THROW(config_error,
                      "Matrix summation of row-vectors is only supported for "
                      "CKKSPackedEncoding.");

    usint m =
        (subringDim == 0) ? privateKey->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() : subringDim;

    if (!IsPowerOfTwo(m))
        OPENFHE_THROW(config_error,
                      "Matrix summation of row-vectors is not supported for "
                      "arbitrary cyclotomics.");

    // stores automorphism indices needed for EvalSum
    std::vector<usint> indices = GenerateIndices2nComplexRows(rowSize, m);

    auto algo = cc->GetScheme();

    return algo->EvalAutomorphismKeyGen(privateKey, indices);
}

template <class Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> AdvancedSHEBase<Element>::EvalSumColsKeyGen(
    const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey) const {
    auto cc = privateKey->GetCryptoContext();

    if (cc->getSchemeId() != SCHEME::CKKSRNS_SCHEME)
        OPENFHE_THROW(config_error,
                      "Matrix summation of column-vectors is only supported for "
                      "CKKSPackedEncoding.");

    const auto cryptoParams = privateKey->GetCryptoParameters();
    usint M                 = cryptoParams->GetElementParams()->GetCyclotomicOrder();
    if (!IsPowerOfTwo(M))
        OPENFHE_THROW(config_error,
                      "Matrix summation of column-vectors is not supported "
                      "for arbitrary cyclotomics.");

    usint batchSize            = cryptoParams->GetEncodingParams()->GetBatchSize();
    std::vector<usint> indices = GenerateIndices2nComplexCols(batchSize, M);

    auto algo = cc->GetScheme();

    return algo->EvalAutomorphismKeyGen(privateKey, indices);
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalSum(ConstCiphertext<Element> ciphertext, usint batchSize,
                                                      const std::map<usint, EvalKey<Element>>& evalKeyMap) const {
    const auto cryptoParams   = ciphertext->GetCryptoParameters();
    const auto encodingParams = cryptoParams->GetEncodingParams();

    if ((encodingParams->GetBatchSize() == 0))
        OPENFHE_THROW(config_error,
                      "EvalSum: Packed encoding parameters 'batch size' is not set; "
                      "Please "
                      "check the EncodingParams passed to the crypto context.");

    usint m = cryptoParams->GetElementParams()->GetCyclotomicOrder();

    Ciphertext<Element> newCiphertext = ciphertext->Clone();

    if (IsPowerOfTwo(m)) {
        if (ciphertext->GetEncodingType() == CKKS_PACKED_ENCODING)
            newCiphertext = EvalSum2nComplex(newCiphertext, batchSize, m, evalKeyMap);
        else
            newCiphertext = EvalSum_2n(newCiphertext, batchSize, m, evalKeyMap);
    }
    else {  // Arbitrary cyclotomics
        if (encodingParams->GetPlaintextGenerator() == 0) {
            OPENFHE_THROW(config_error,
                          "EvalSum: Packed encoding parameters 'plaintext "
                          "generator' is not set; Please check the "
                          "EncodingParams passed to the crypto context.");
        }
        else {
            auto algo = ciphertext->GetCryptoContext()->GetScheme();

            usint g = encodingParams->GetPlaintextGenerator();
            for (int i = 0; i < floor(log2(batchSize)); i++) {
                auto ea       = algo->EvalAutomorphism(newCiphertext, g, evalKeyMap);
                newCiphertext = algo->EvalAdd(newCiphertext, ea);
                g             = (g * g) % m;
            }
        }
    }

    return newCiphertext;
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalSumRows(ConstCiphertext<Element> ciphertext, usint rowSize,
                                                          const std::map<usint, EvalKey<Element>>& evalKeyMap,
                                                          usint subringDim) const {
    if (ciphertext->GetEncodingType() != CKKS_PACKED_ENCODING)
        OPENFHE_THROW(config_error,
                      "Matrix summation of row-vectors is only supported "
                      "for CKKS packed encoding.");

    const auto cryptoParams   = ciphertext->GetCryptoParameters();
    const auto encodingParams = cryptoParams->GetEncodingParams();

    if ((encodingParams->GetBatchSize() == 0))
        OPENFHE_THROW(config_error,
                      "EvalSum: Packed encoding parameters 'batch size' is not set; "
                      "Please "
                      "check the EncodingParams passed to the crypto context.");

    usint m = (subringDim == 0) ? cryptoParams->GetElementParams()->GetCyclotomicOrder() : subringDim;

    if (!IsPowerOfTwo(m))
        OPENFHE_THROW(config_error,
                      "Matrix summation of row-vectors is not supported for "
                      "arbitrary cyclotomics.");

    return EvalSum2nComplexRows(ciphertext->Clone(), rowSize, m, evalKeyMap);
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalSumCols(
    ConstCiphertext<Element> ciphertext, usint batchSize, const std::map<usint, EvalKey<Element>>& evalSumKeyMap,
    const std::map<usint, EvalKey<Element>>& evalSumColsKeyMap) const {
    if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
    if (!evalSumKeyMap.size())
        OPENFHE_THROW(config_error, "Input evalKeys map is empty");
    if (!evalSumColsKeyMap.size())
        OPENFHE_THROW(config_error, "Input rightEvalKeys map is empty");

    if (ciphertext->GetEncodingType() != CKKS_PACKED_ENCODING)
        OPENFHE_THROW(config_error,
                      "Matrix summation of column-vectors is only supported "
                      "for CKKS packed encoding.");

    const auto cryptoParams   = ciphertext->GetCryptoParameters();
    const auto encodingParams = cryptoParams->GetEncodingParams();

    if ((encodingParams->GetBatchSize() == 0))
        OPENFHE_THROW(config_error,
                      "EvalSumCols: Packed encoding parameters 'batch size' is not set; "
                      "Please check the EncodingParams passed to the crypto context.");

    const auto elementParams = cryptoParams->GetElementParams();
    usint m                  = elementParams->GetCyclotomicOrder();

    if (!IsPowerOfTwo(m))
        OPENFHE_THROW(config_error,
                      "Matrix summation of column-vectors is not supported "
                      "for arbitrary cyclotomics.");

    Ciphertext<Element> newCiphertext = EvalSum2nComplex(ciphertext->Clone(), batchSize, m, evalSumKeyMap);

    std::vector<std::complex<double>> mask(m / 4);
    for (size_t i = 0; i < mask.size(); i++) {
        if (i % batchSize == 0)
            mask[i] = 1;
        else
            mask[i] = 0;
    }
    auto cc   = ciphertext->GetCryptoContext();
    auto algo = cc->GetScheme();

    Plaintext plaintext = cc->MakeCKKSPackedPlaintext(mask, 1, 0, nullptr, ciphertext->GetSlots());
    algo->EvalMultInPlace(newCiphertext, plaintext);

    return EvalSum2nComplexCols(newCiphertext, batchSize, m, evalSumColsKeyMap);
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalInnerProduct(ConstCiphertext<Element> ciphertext1,
                                                               ConstCiphertext<Element> ciphertext2, usint batchSize,
                                                               const std::map<usint, EvalKey<Element>>& evalSumKeyMap,
                                                               const EvalKey<Element> evalMultKey) const {
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
    ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext, usint batchSize,
    const std::map<usint, EvalKey<Element>>& evalSumKeyMap) const {
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
                                                        const std::map<usint, EvalKey<Element>>& evalKeyMap) const {
    if (ciphertextVec.size() == 0)
        OPENFHE_THROW(math_error,
                      "EvalMerge: the vector of ciphertexts to be merged "
                      "cannot be empty");

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
            ciphertextMerged, algo->EvalAtIndex(algo->EvalMult(ciphertextVec[i], plaintext), -(int32_t)i, evalKeyMap));
    }

    return ciphertextMerged;
}

template <class Element>
std::vector<usint> AdvancedSHEBase<Element>::GenerateIndices_2n(usint batchSize, usint m) const {
    // stores automorphism indices needed for EvalSum
    std::vector<usint> indices;

    if (batchSize > 1) {
        usint g = 5;
        for (int i = 0; i < ceil(log2(batchSize)) - 1; i++) {
            indices.push_back(g);
            g = (g * g) % m;
        }
        if (2 * batchSize < m)
            indices.push_back(g);
        else
            indices.push_back(m - 1);
    }

    return indices;
}

template <class Element>
std::vector<usint> AdvancedSHEBase<Element>::GenerateIndices2nComplex(usint batchSize, usint m) const {
    // stores automorphism indices needed for EvalSum
    std::vector<usint> indices;

    // generator
    usint g = 5;

    for (size_t j = 0; j < ceil(log2(batchSize)); j++) {
        indices.push_back(g);
        g = (g * g) % m;
    }

    return indices;
}

template <class Element>
std::vector<usint> AdvancedSHEBase<Element>::GenerateIndices2nComplexRows(usint rowSize, usint m) const {
    // stores automorphism indices needed for EvalSum
    std::vector<usint> indices;

    usint colSize = m / (4 * rowSize);

    // generator
    int32_t g0 = 5;
    usint g    = 0;

    int32_t f = (NativeInteger(g0).ModExp(rowSize, m)).ConvertToInt();

    for (size_t j = 0; j < ceil(log2(colSize)); j++) {
        g = f;

        indices.push_back(g);

        f = (f * f) % m;
    }

    return indices;
}

template <class Element>
std::vector<usint> AdvancedSHEBase<Element>::GenerateIndices2nComplexCols(usint batchSize, usint m) const {
    // stores automorphism indices needed for EvalSum
    std::vector<usint> indices;

    // generator
    int32_t g    = NativeInteger(5).ModInverse(m).ConvertToInt();
    usint gFinal = g;

    for (size_t j = 0; j < ceil(log2(batchSize)); j++) {
        indices.push_back(gFinal);
        g = (g * g) % m;

        gFinal = g;
    }

    return indices;
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalSum_2n(ConstCiphertext<Element> ciphertext, usint batchSize, usint m,
                                                         const std::map<usint, EvalKey<Element>>& evalKeys) const {
    Ciphertext<Element> newCiphertext(std::make_shared<CiphertextImpl<Element>>(*ciphertext));
    auto algo = ciphertext->GetCryptoContext()->GetScheme();

    if (batchSize > 1) {
        usint g = 5;
        for (int i = 0; i < ceil(log2(batchSize)) - 1; i++) {
            newCiphertext = algo->EvalAdd(newCiphertext, algo->EvalAutomorphism(newCiphertext, g, evalKeys));
            g             = (g * g) % m;
        }
        if (2 * batchSize < m)
            newCiphertext = algo->EvalAdd(newCiphertext, algo->EvalAutomorphism(newCiphertext, g, evalKeys));
        else
            newCiphertext = algo->EvalAdd(newCiphertext, algo->EvalAutomorphism(newCiphertext, m - 1, evalKeys));
    }

    return newCiphertext;
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalSum2nComplex(
    ConstCiphertext<Element> ciphertext, usint batchSize, usint m,
    const std::map<usint, EvalKey<Element>>& evalKeys) const {
    Ciphertext<Element> newCiphertext(std::make_shared<CiphertextImpl<Element>>(*ciphertext));

    // generator
    int32_t g    = 5;
    usint gFinal = g;
    auto algo    = ciphertext->GetCryptoContext()->GetScheme();

    for (int i = 0; i < ceil(log2(batchSize)); i++) {
        newCiphertext = algo->EvalAdd(newCiphertext, algo->EvalAutomorphism(newCiphertext, gFinal, evalKeys));
        g             = (g * g) % m;

        gFinal = g;
    }

    return newCiphertext;
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalSum2nComplexRows(
    ConstCiphertext<Element> ciphertext, usint rowSize, usint m,
    const std::map<usint, EvalKey<Element>>& evalKeys) const {
    Ciphertext<Element> newCiphertext(std::make_shared<CiphertextImpl<Element>>(*ciphertext));

    usint colSize = m / (4 * rowSize);

    // generator
    int32_t g0 = 5;
    usint g    = 0;
    int32_t f  = (NativeInteger(g0).ModExp(rowSize, m)).ConvertToInt();

    auto algo = ciphertext->GetCryptoContext()->GetScheme();
    for (size_t j = 0; j < ceil(log2(colSize)); j++) {
        g = f;

        newCiphertext = algo->EvalAdd(newCiphertext, algo->EvalAutomorphism(newCiphertext, g, evalKeys));

        f = (f * f) % m;
    }

    return newCiphertext;
}

template <class Element>
Ciphertext<Element> AdvancedSHEBase<Element>::EvalSum2nComplexCols(
    ConstCiphertext<Element> ciphertext, usint batchSize, usint m,
    const std::map<usint, EvalKey<Element>>& evalKeys) const {
    Ciphertext<Element> newCiphertext(std::make_shared<CiphertextImpl<Element>>(*ciphertext));

    // generator
    int32_t g    = NativeInteger(5).ModInverse(m).ConvertToInt();
    usint gFinal = g;

    auto algo = ciphertext->GetCryptoContext()->GetScheme();

    for (int i = 0; i < ceil(log2(batchSize)); i++) {
        newCiphertext = algo->EvalAdd(newCiphertext, algo->EvalAutomorphism(newCiphertext, gFinal, evalKeys));
        g             = (g * g) % m;

        gFinal = g;
    }

    return newCiphertext;
}

}  // namespace lbcrypto

// the code below is from base-advancedshe-impl.cpp
namespace lbcrypto {

template class AdvancedSHEBase<DCRTPoly>;

}  // namespace lbcrypto
