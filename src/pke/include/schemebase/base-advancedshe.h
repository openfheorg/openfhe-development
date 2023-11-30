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

#ifndef LBCRYPTO_CRYPTO_BASE_ADVANCEDSHE_H
#define LBCRYPTO_CRYPTO_BASE_ADVANCEDSHE_H

#include "key/privatekey-fwd.h"
#include "key/publickey-fwd.h"
#include "key/evalkey-fwd.h"
#include "encoding/plaintext-fwd.h"
#include "ciphertext-fwd.h"
#include "utils/inttypes.h"
#include "utils/exception.h"

#include <memory>
#include <vector>
#include <string>
#include <map>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Abstract base class for derived HE algorithms
 * @tparam Element a ring element.
 */
template <class Element>
class AdvancedSHEBase {
    using ParmType = typename Element::Params;
    using IntType  = typename Element::Integer;
    using DugType  = typename Element::DugType;
    using DggType  = typename Element::DggType;
    using TugType  = typename Element::TugType;

public:
    virtual ~AdvancedSHEBase() {}

    /**
   * Virtual function for evaluating addition of a list of ciphertexts.
   *
   * @param ciphertextVec
   * @return
   */
    virtual Ciphertext<Element> EvalAddMany(const std::vector<Ciphertext<Element>>& ciphertextVec) const;

    /**
   * Virtual function for evaluating addition of a list of ciphertexts.
   * This version uses no additional space, other than the vector provided.
   *
   * @param ciphertextVec  is the ciphertext list.
   * @param *newCiphertext the new resulting ciphertext.
   */
    virtual Ciphertext<Element> EvalAddManyInPlace(std::vector<Ciphertext<Element>>& ciphertextVec) const;

    /**
   * Virtual function for evaluating multiplication of a ciphertext list which
   * each multiplication is followed by relinearization operation.
   *
   * @param cipherTextList  is the ciphertext list.
   * @param evalKeys is the evaluation key to make the newCiphertext
   *  decryptable by the same secret key as that of ciphertext list.
   * @param *newCiphertext the new resulting ciphertext.
   */
    virtual Ciphertext<Element> EvalMultMany(const std::vector<Ciphertext<Element>>& ciphertextVec,
                                             const std::vector<EvalKey<Element>>& evalKeyVec) const;

    //------------------------------------------------------------------------------
    // LINEAR WEIGHTED SUM
    //------------------------------------------------------------------------------

    /**
   * Virtual function for computing the linear weighted sum of a
   * vector of ciphertexts.
   *
   * @param ciphertexts vector of input ciphertexts.
   * @param constants vector containing double weights.
   * @return A ciphertext containing the linear weighted sum.
   */
    virtual Ciphertext<Element> EvalLinearWSum(std::vector<ConstCiphertext<Element>>& ciphertextVec,
                                               const std::vector<double>& weights) const {
        std::string errMsg = "EvalLinearWSum is not implemented for this scheme.";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    /**
   * Function for computing the linear weighted sum of a
   * vector of ciphertexts. This is a mutable method,
   * meaning that the level/depth of input ciphertexts may change.
   *
   * @param ciphertexts vector of input ciphertexts.
   * @param constants vector containing double weights.
   * @return A ciphertext containing the linear weighted sum.
   */
    virtual Ciphertext<Element> EvalLinearWSumMutable(std::vector<Ciphertext<Element>>& ciphertextVec,
                                                      const std::vector<double>& weights) const {
        std::string errMsg = "EvalLinearWSumMutable is not implemented for this scheme.";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    //------------------------------------------------------------------------------
    // EVAL POLYNOMIAL
    //------------------------------------------------------------------------------

    /**
   * Method for polynomial evaluation for polynomials represented in the power
   * series. This uses a binary tree computation of
   * the polynomial powers.
   *
   * @param &cipherText input ciphertext
   * @param &coefficients is the vector of coefficients in the polynomial; the
   * size of the vector is the degree of the polynomial + 1
   * @return the result of polynomial evaluation.
   */
    virtual Ciphertext<Element> EvalPoly(ConstCiphertext<Element> ciphertext,
                                         const std::vector<double>& coefficients) const {
        OPENFHE_THROW(config_error, "EvalPoly is not supported for the scheme.");
    }

    /**
   * Method for polynomial evaluation for polynomials represented in the power
   * series. This uses a binary tree computation of
   * the polynomial powers.
   *
   * @param &cipherText input ciphertext
   * @param &coefficients is the vector of coefficients in the polynomial; the
   * size of the vector is the degree of the polynomial + 1
   * @return the result of polynomial evaluation.
   */
    virtual Ciphertext<Element> EvalPolyLinear(ConstCiphertext<Element> ciphertext,
                                               const std::vector<double>& coefficients) const {
        OPENFHE_THROW(config_error, "EvalPolyLinear is not supported for the scheme.");
    }

    virtual Ciphertext<Element> EvalPolyPS(ConstCiphertext<Element> x, const std::vector<double>& coefficients) const {
        OPENFHE_THROW(config_error, "EvalPolyPS is not supported for the scheme.");
    }

    //------------------------------------------------------------------------------
    // EVAL CHEBYSHEV SERIES
    //------------------------------------------------------------------------------

    /**
   * Method for evaluating Chebyshev polynomial interpolation;
   * first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2
   * (x-a)/(b-a) If the degree of the polynomial is less than 5, use
   * EvalChebyshevSeriesLinear, otherwise, use EvalChebyshevSeriesPS.
   *
   * @param &cipherText input ciphertext
   * @param &coefficients is the vector of coefficients in Chebyshev expansion
   * @param a - lower bound of argument for which the coefficients were found
   * @param b - upper bound of argument for which the coefficients were found
   * @return the result of polynomial evaluation.
   */
    virtual Ciphertext<Element> EvalChebyshevSeries(ConstCiphertext<Element> ciphertext,
                                                    const std::vector<double>& coefficients, double a, double b) const {
        OPENFHE_THROW(config_error, "EvalChebyshevSeries is not supported for the scheme.");
    }

    virtual Ciphertext<Element> EvalChebyshevSeriesLinear(ConstCiphertext<Element> ciphertext,
                                                          const std::vector<double>& coefficients, double a,
                                                          double b) const {
        OPENFHE_THROW(config_error, "EvalChebyshevSeriesLinear is not supported for the scheme.");
    }

    virtual Ciphertext<Element> EvalChebyshevSeriesPS(ConstCiphertext<Element> ciphertext,
                                                      const std::vector<double>& coefficients, double a,
                                                      double b) const {
        OPENFHE_THROW(config_error, "EvalChebyshevSeriesPS is not supported for the scheme.");
    }

    //------------------------------------------------------------------------------
    // Advanced SHE EVAL SUM
    //------------------------------------------------------------------------------

    /**
   * Virtual function to generate the automorphism keys for EvalSum; works
   * only for packed encoding
   *
   * @param privateKey private key.
   * @return returns the evaluation keys
   */
    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalSumKeyGen(const PrivateKey<Element> privateKey,
                                                                             const PublicKey<Element> publicKey) const;

    /**
   * Virtual function to generate the automorphism keys for EvalSumRows; works
   * only for packed encoding
   *
   * @param privateKey private key.
   * @param publicKey public key.
   * @param rowSize size of rows in the matrix
   * @param subringDim subring dimension (set to cyclotomic order if set to 0)
   * @return returns the evaluation keys
   */
    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalSumRowsKeyGen(const PrivateKey<Element> privateKey,
                                                                                 const PublicKey<Element> publicKey,
                                                                                 usint rowSize, usint subringDim) const;

    /**
   * Virtual function to generate the automorphism keys for EvalSumCols; works
   * only for packed encoding
   *
   * @param privateKey private key.
   * @param publicKey public key.
   * @return returns the evaluation keys
   */
    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalSumColsKeyGen(
        const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey) const;

    /**
   * Sums all elements in log (batch size) time - works only with packed
   * encoding
   *
   * @param ciphertext the input ciphertext.
   * @param batchSize size of the batch to be summed up
   * @param &evalKeys - reference to the map of evaluation keys generated by
   * EvalAutomorphismKeyGen.
   * @return resulting ciphertext
   */
    virtual Ciphertext<Element> EvalSum(ConstCiphertext<Element> ciphertext, usint batchSize,
                                        const std::map<usint, EvalKey<Element>>& evalSumKeyMap) const;

    /**
   * Sums all elements over row-vectors in a matrix - works only with packed
   * encoding
   *
   * @param ciphertext the input ciphertext.
   * @param rowSize size of rows in the matrix
   * @param &evalKeys - reference to the map of evaluation keys generated by
   * @param subringDim the current cyclotomic order/subring dimension. If set to
   * 0, we use the full cyclotomic order. EvalAutomorphismKeyGen.
   * @return resulting ciphertext
   */
    virtual Ciphertext<Element> EvalSumRows(ConstCiphertext<Element> ciphertext, usint rowSize,
                                            const std::map<usint, EvalKey<Element>>& evalSumRowsKeyMap,
                                            usint subringDim) const;

    /**
   * Sums all elements over column-vectors in a matrix - works only with
   * packed encoding
   *
   * @param ciphertext the input ciphertext.
   * @param rowSize size of rows in the matrixs
   * @param &evalKeys - reference to the map of evaluation keys generated by
   * EvalAutomorphismKeyGen.
   * @return resulting ciphertext
   */
    virtual Ciphertext<Element> EvalSumCols(ConstCiphertext<Element> ciphertext, usint batchSize,
                                            const std::map<usint, EvalKey<Element>>& evalSumColsKeyMap,
                                            const std::map<usint, EvalKey<Element>>& rightEvalKeys) const;

    //------------------------------------------------------------------------------
    // Advanced SHE EVAL INNER PRODUCT
    //------------------------------------------------------------------------------

    /**
   * Evaluates inner product in batched encoding
   *
   * @param ciphertext1 first vector.
   * @param ciphertext2 second vector.
   * @param batchSize size of the batch to be summed up
   * @param &evalSumKeys - reference to the map of evaluation keys generated
   * by EvalAutomorphismKeyGen.
   * @param &evalMultKey - reference to the evaluation key generated by
   * EvalMultKeyGen.
   * @return resulting ciphertext
   */
    virtual Ciphertext<Element> EvalInnerProduct(ConstCiphertext<Element> ciphertext1,
                                                 ConstCiphertext<Element> ciphertext2, usint batchSize,
                                                 const std::map<usint, EvalKey<Element>>& evalKeyMap,
                                                 const EvalKey<Element> evalMultKey) const;

    /**
   * Evaluates inner product in batched encoding
   *
   * @param ciphertext1 first vector.
   * @param plaintext plaintext.
   * @param batchSize size of the batch to be summed up
   * @param &evalSumKeys - reference to the map of evaluation keys generated
   * by EvalAutomorphismKeyGen.
   * @param &evalMultKey - reference to the evaluation key generated by
   * EvalMultKeyGen.
   * @return resulting ciphertext
   */
    virtual Ciphertext<Element> EvalInnerProduct(ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext,
                                                 usint batchSize,
                                                 const std::map<usint, EvalKey<Element>>& evalKeyMap) const;

    /**
   * Function to add random noise to all plaintext slots except for the first
   * one; used in EvalInnerProduct
   *
   * @param &ciphertext the input ciphertext.
   * @return modified ciphertext
   */
    virtual Ciphertext<Element> AddRandomNoise(ConstCiphertext<Element> ciphertext) const;

    /**
   * Merges multiple ciphertexts with encrypted results in slot 0 into a
   * single ciphertext The slot assignment is done based on the order of
   * ciphertexts in the vector
   *
   * @param ciphertextVector vector of ciphertexts to be merged.
   * @param &evalKeys - reference to the map of evaluation keys generated by
   * EvalAutomorphismKeyGen.
   * @return resulting ciphertext
   */
    virtual Ciphertext<Element> EvalMerge(const std::vector<Ciphertext<Element>>& ciphertextVector,
                                          const std::map<usint, EvalKey<Element>>& evalKeyMap) const;

    //------------------------------------------------------------------------------
    // LINEAR TRANSFORMATION
    //------------------------------------------------------------------------------

    //------------------------------------------------------------------------------
    // Other Methods for Bootstrap
    //------------------------------------------------------------------------------

protected:
    std::vector<usint> GenerateIndices_2n(usint batchSize, usint m) const;

    std::vector<usint> GenerateIndices2nComplex(usint batchSize, usint m) const;

    std::vector<usint> GenerateIndices2nComplexRows(usint rowSize, usint m) const;

    std::vector<usint> GenerateIndices2nComplexCols(usint batchSize, usint m) const;

    Ciphertext<Element> EvalSum_2n(ConstCiphertext<Element> ciphertext, usint batchSize, usint m,
                                   const std::map<usint, EvalKey<Element>>& evalKeyMap) const;

    Ciphertext<Element> EvalSum2nComplex(ConstCiphertext<Element> ciphertext, usint batchSize, usint m,
                                         const std::map<usint, EvalKey<Element>>& evalKeyMap) const;

    Ciphertext<Element> EvalSum2nComplexRows(ConstCiphertext<Element> ciphertext, usint rowSize, usint m,
                                             const std::map<usint, EvalKey<Element>>& evalKeyMap) const;

    Ciphertext<Element> EvalSum2nComplexCols(ConstCiphertext<Element> ciphertext, usint batchSize, usint m,
                                             const std::map<usint, EvalKey<Element>>& evalKeyMap) const;
};

}  // namespace lbcrypto

#endif
