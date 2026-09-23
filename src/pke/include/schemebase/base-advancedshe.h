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

#ifndef SRC_PKE_INCLUDE_SCHEMEBASE_BASE_ADVANCEDSHE_H_
#define SRC_PKE_INCLUDE_SCHEMEBASE_BASE_ADVANCEDSHE_H_

#include <complex>
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "ciphertext-fwd.h"
#include "encoding/plaintext-fwd.h"
#include "key/evalkey-fwd.h"
#include "key/privatekey-fwd.h"
#include "key/publickey-fwd.h"
#include "utils/exception.h"
#include "utils/inttypes.h"

namespace lbcrypto {

template <class Element>
class MultipartyBase;

template <class Element>
class AdvancedSHEBase {
    using ParmType = typename Element::Params;
    using IntType = typename Element::Integer;
    using DugType = typename Element::DugType;
    using DggType = typename Element::DggType;
    using TugType = typename Element::TugType;

    constexpr static std::string_view NOT_IMPLEMENTED_ERROR = "Not implemented for this scheme";

    friend class MultipartyBase<Element>;

  public:
    virtual ~AdvancedSHEBase() = default;

    /**
   * Virtual function for evaluating addition of a list of ciphertexts.
   *
   * @param ciphertextVec is the ciphertext list.
   * @return the new resulting ciphertext.
   */
    virtual Ciphertext<Element> EvalAddMany(const std::vector<Ciphertext<Element>>& ciphertextVec) const;

    /**
   * Virtual function for evaluating addition of a list of ciphertexts.
   * This version uses no additional space, other than the vector provided.
   *
   * @param ciphertextVec  is the ciphertext list (modified in place to store intermediate results).
   * @return the new resulting ciphertext.
   */
    virtual Ciphertext<Element> EvalAddManyInPlace(std::vector<Ciphertext<Element>>& ciphertextVec) const;

    /**
   * Virtual function for evaluating multiplication of a ciphertext list which
   * each multiplication is followed by relinearization operation.
   *
   * @param ciphertextVec  is the ciphertext list.
   * @param evalKeyVec are the evaluation keys to make the new ciphertext
   *  decryptable by the same secret key as that of ciphertext list.
   * @return the new resulting ciphertext.
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
   * @param ciphertextVec vector of input ciphertexts.
   * @param weights vector containing the weights.
   * @return A ciphertext containing the linear weighted sum.
   */
    virtual Ciphertext<Element> EvalLinearWSum(std::vector<ReadOnlyCiphertext<Element>>& ciphertextVec,
                                               const std::vector<int64_t>& weights) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }
    virtual Ciphertext<Element> EvalLinearWSum(std::vector<ReadOnlyCiphertext<Element>>& ciphertextVec,
                                               const std::vector<double>& weights) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }
    virtual Ciphertext<Element> EvalLinearWSum(std::vector<ReadOnlyCiphertext<Element>>& ciphertextVec,
                                               const std::vector<std::complex<double>>& weights) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
   * Function for computing the linear weighted sum of a
   * vector of ciphertexts. This is a mutable method,
   * meaning that the level/depth of input ciphertexts may change.
   *
   * @param ciphertextVec vector of input ciphertexts.
   * @param weights vector containing the weights.
   * @return A ciphertext containing the linear weighted sum.
   */
    virtual Ciphertext<Element> EvalLinearWSumMutable(std::vector<Ciphertext<Element>>& ciphertextVec,
                                                      const std::vector<int64_t>& weights) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }
    virtual Ciphertext<Element> EvalLinearWSumMutable(std::vector<Ciphertext<Element>>& ciphertextVec,
                                                      const std::vector<double>& weights) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }
    virtual Ciphertext<Element> EvalLinearWSumMutable(std::vector<Ciphertext<Element>>& ciphertextVec,
                                                      const std::vector<std::complex<double>>& weights) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    //------------------------------------------------------------------------------
    // EVAL POLYNOMIAL
    //------------------------------------------------------------------------------

    /**
   * Method for computing the powers of a ciphertext to be used when evaluating a polynomial
   * represented in the power series. Uses a binary tree computation of the powers for low
   * polynomial degrees (degree < 5), or the Paterson-Stockmeyer power basis for higher degrees.
   *
   * @param ciphertext input ciphertext
   * @param coefficients is the vector of coefficients in the polynomial; the
   * size of the vector is the degree of the polynomial + 1
   * @return the resulting data structure of powers.
   */
    virtual std::shared_ptr<seriesPowers<Element>> EvalPowers(ConstCiphertext<Element>& ciphertext,
                                                              const std::vector<int64_t>& coefficients) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }
    virtual std::shared_ptr<seriesPowers<Element>> EvalPowers(ConstCiphertext<Element>& ciphertext,
                                                              const std::vector<double>& coefficients) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }
    virtual std::shared_ptr<seriesPowers<Element>> EvalPowers(
            ConstCiphertext<Element>& ciphertext, const std::vector<std::complex<double>>& coefficients) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
   * Method for polynomial evaluation for polynomials represented in the power series.
   * Uses EvalPolyLinear() for low polynomial degrees (degree < 5), or EvalPolyPS() for higher degrees.
   *
   * @param ciphertext input ciphertext
   * @param coefficients is the vector of coefficients in the polynomial; the
   * size of the vector is the degree of the polynomial + 1
   * @return the result of polynomial evaluation.
   */
    virtual Ciphertext<Element> EvalPoly(ConstCiphertext<Element>& ciphertext,
                                         const std::vector<int64_t>& coefficients) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }
    virtual Ciphertext<Element> EvalPoly(ConstCiphertext<Element>& ciphertext,
                                         const std::vector<double>& coefficients) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }
    virtual Ciphertext<Element> EvalPoly(ConstCiphertext<Element>& ciphertext,
                                         const std::vector<std::complex<double>>& coefficients) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    virtual Ciphertext<Element> EvalPolyWithPrecomp(std::shared_ptr<seriesPowers<Element>> powers,
                                                    const std::vector<int64_t>& coefficients) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }
    virtual Ciphertext<Element> EvalPolyWithPrecomp(std::shared_ptr<seriesPowers<Element>> powers,
                                                    const std::vector<double>& coefficients) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }
    virtual Ciphertext<Element> EvalPolyWithPrecomp(std::shared_ptr<seriesPowers<Element>> powers,
                                                    const std::vector<std::complex<double>>& coefficients) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
   * Method for polynomial evaluation for polynomials represented in the power
   * series. This uses a binary tree computation of
   * the polynomial powers.
   *
   * @param ciphertext input ciphertext
   * @param coefficients is the vector of coefficients in the polynomial; the
   * size of the vector is the degree of the polynomial + 1
   * @return the result of polynomial evaluation.
   */
    virtual Ciphertext<Element> EvalPolyLinear(ConstCiphertext<Element>& ciphertext,
                                               const std::vector<int64_t>& coefficients) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }
    virtual Ciphertext<Element> EvalPolyLinear(ConstCiphertext<Element>& ciphertext,
                                               const std::vector<double>& coefficients) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }
    virtual Ciphertext<Element> EvalPolyLinear(ConstCiphertext<Element>& ciphertext,
                                               const std::vector<std::complex<double>>& coefficients) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
   * Method for polynomial evaluation for polynomials represented in the power
   * series. This uses the Paterson-Stockmeyer algorithm.
   *
   * @param x input ciphertext
   * @param coefficients is the vector of coefficients in the polynomial; the
   * size of the vector is the degree of the polynomial + 1
   * @return the result of polynomial evaluation.
   */
    virtual Ciphertext<Element> EvalPolyPS(ConstCiphertext<Element>& x,
                                           const std::vector<int64_t>& coefficients) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }
    virtual Ciphertext<Element> EvalPolyPS(ConstCiphertext<Element>& x, const std::vector<double>& coefficients) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }
    virtual Ciphertext<Element> EvalPolyPS(ConstCiphertext<Element>& x,
                                           const std::vector<std::complex<double>>& coefficients) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    //------------------------------------------------------------------------------
    // EVAL CHEBYSHEV SERIES
    //------------------------------------------------------------------------------

    /**
   * Method for computing the Chebyshev polynomials to be used in polynomial interpolation via the Chebyshev series.
   * Uses a binary tree computation of the Chebyshev polynomials for low degrees (degree < 5),
   * or the Paterson-Stockmeyer Chebyshev basis for higher degrees.
   *
   * @param ciphertext input ciphertext
   * @param coefficients is the vector of coefficients in the Chebyshev series; the
   * size of the vector is the degree of the polynomial + 1
   * @param a - lower bound of argument for which the coefficients were found
   * @param b - upper bound of argument for which the coefficients were found
   * @return the resulting data structure of Chebyshev polynomials.
   */
    virtual std::shared_ptr<seriesPowers<Element>> EvalChebyPolys(ConstCiphertext<Element>& ciphertext,
                                                                  const std::vector<int64_t>& coefficients, double a,
                                                                  double b) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }
    virtual std::shared_ptr<seriesPowers<Element>> EvalChebyPolys(ConstCiphertext<Element>& ciphertext,
                                                                  const std::vector<double>& coefficients, double a,
                                                                  double b) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }
    virtual std::shared_ptr<seriesPowers<Element>> EvalChebyPolys(ConstCiphertext<Element>& ciphertext,
                                                                  const std::vector<std::complex<double>>& coefficients,
                                                                  double a, double b) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
   * Method for evaluating Chebyshev polynomial interpolation;
   * first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2
   * (x-a)/(b-a) If the degree of the polynomial is less than 5, use
   * EvalChebyshevSeriesLinear, otherwise, use EvalChebyshevSeriesPS.
   *
   * @param ciphertext input ciphertext
   * @param coefficients is the vector of coefficients in Chebyshev expansion
   * @param a - lower bound of argument for which the coefficients were found
   * @param b - upper bound of argument for which the coefficients were found
   * @return the result of polynomial evaluation.
   */
    virtual Ciphertext<Element> EvalChebyshevSeries(ConstCiphertext<Element>& ciphertext,
                                                    const std::vector<int64_t>& coefficients, double a,
                                                    double b) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }
    virtual Ciphertext<Element> EvalChebyshevSeries(ConstCiphertext<Element>& ciphertext,
                                                    const std::vector<double>& coefficients, double a, double b) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }
    virtual Ciphertext<Element> EvalChebyshevSeries(ConstCiphertext<Element>& ciphertext,
                                                    const std::vector<std::complex<double>>& coefficients, double a,
                                                    double b) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    virtual Ciphertext<Element> EvalChebyshevSeriesWithPrecomp(std::shared_ptr<seriesPowers<Element>> polys,
                                                               const std::vector<int64_t>& coefficients) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }
    virtual Ciphertext<Element> EvalChebyshevSeriesWithPrecomp(std::shared_ptr<seriesPowers<Element>> polys,
                                                               const std::vector<double>& coefficients) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }
    virtual Ciphertext<Element> EvalChebyshevSeriesWithPrecomp(
            std::shared_ptr<seriesPowers<Element>> polys, const std::vector<std::complex<double>>& coefficients) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    virtual Ciphertext<Element> EvalChebyshevSeriesLinear(ConstCiphertext<Element>& ciphertext,
                                                          const std::vector<int64_t>& coefficients, double a,
                                                          double b) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }
    virtual Ciphertext<Element> EvalChebyshevSeriesLinear(ConstCiphertext<Element>& ciphertext,
                                                          const std::vector<double>& coefficients, double a,
                                                          double b) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }
    virtual Ciphertext<Element> EvalChebyshevSeriesLinear(ConstCiphertext<Element>& ciphertext,
                                                          const std::vector<std::complex<double>>& coefficients,
                                                          double a, double b) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    virtual Ciphertext<Element> EvalChebyshevSeriesPS(ConstCiphertext<Element>& ciphertext,
                                                      const std::vector<int64_t>& coefficients, double a,
                                                      double b) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }
    virtual Ciphertext<Element> EvalChebyshevSeriesPS(ConstCiphertext<Element>& ciphertext,
                                                      const std::vector<double>& coefficients, double a,
                                                      double b) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }
    virtual Ciphertext<Element> EvalChebyshevSeriesPS(ConstCiphertext<Element>& ciphertext,
                                                      const std::vector<std::complex<double>>& coefficients, double a,
                                                      double b) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
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
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> EvalSumKeyGen(
            const PrivateKey<Element> privateKey) const;

    /**
   * Virtual function to generate the automorphism keys for EvalSumRows; works
   * only for packed encoding
   *
   * @param privateKey private key.
   * @param rowSize size of rows in the matrix
   * @param subringDim subring dimension (set to cyclotomic order if set to 0)
   * @param indices automorphism indices to generate keys for; the indices needed for
   * EvalSumRows are appended to it
   * @return returns the evaluation keys
   */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> EvalSumRowsKeyGen(
            const PrivateKey<Element> privateKey, uint32_t rowSize, uint32_t subringDim,
            std::vector<uint32_t>& indices) const;

    /**
   * Virtual function to generate the automorphism keys for EvalSumCols; works
   * only for packed encoding
   *
   * @param privateKey private key.
   * @param indices automorphism indices to generate keys for; the indices needed for
   * EvalSumCols and EvalSum are appended to it
   * @return returns the evaluation keys
   */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> EvalSumColsKeyGen(
            const PrivateKey<Element> privateKey, std::vector<uint32_t>& indices) const;

    /**
    * @brief Sums all elements in log (batch size) time - works only with packed encoding
    * @param ciphertext the input ciphertext.
    * @param batchSize size of the batch to be summed up
    * @param evalSumKeyMap - reference to the map of evaluation keys generated by EvalSumKeyGen.
    * @return resulting ciphertext
    */
    virtual Ciphertext<Element> EvalSum(ConstCiphertext<Element> ciphertext, uint32_t batchSize,
                                        const std::map<uint32_t, EvalKey<Element>>& evalSumKeyMap) const;

    /**
    * @brief Sums all elements over row-vectors in a matrix - works only with packed encoding.
    * @param ciphertext the input ciphertext.
    * @param numRows number of rows in the matrix
    * @param evalSumKeys - reference to the map of evaluation keys generated by EvalSumRowsKeyGen.
    * @param subringDim the current cyclotomic order/subring dimension. If set to 0, we use the full cyclotomic order.
    * @return resulting ciphertext
    */
    virtual Ciphertext<Element> EvalSumRows(ConstCiphertext<Element> ciphertext, uint32_t numRows,
                                            const std::map<uint32_t, EvalKey<Element>>& evalSumKeys,
                                            uint32_t subringDim) const;

    /**
    * @brief Sums all elements over column-vectors in a matrix - works only with packed encoding. The code is
    *        implemented according to the specifications in https://eprint.iacr.org/2018/662.pdf
    * @param ciphertext the input ciphertext.
    * @param numCols number of columns in the matrix
    * @param evalSumKeys - reference to the map of evaluation keys generated by EvalSumKeyGen.
    * @param rightEvalKeys - reference to the map of evaluation keys generated by EvalSumColsKeyGen.
    * @return resulting ciphertext
    */
    virtual Ciphertext<Element> EvalSumCols(ConstCiphertext<Element> ciphertext, uint32_t numCols,
                                            const std::map<uint32_t, EvalKey<Element>>& evalSumKeys,
                                            const std::map<uint32_t, EvalKey<Element>>& rightEvalKeys) const;

    //------------------------------------------------------------------------------
    // Advanced SHE EVAL INNER PRODUCT
    //------------------------------------------------------------------------------

    /**
    * @brief Evaluates inner product in batched encoding
    * @param ciphertext1 first vector.
    * @param ciphertext2 second vector.
    * @param batchSize size of the batch to be summed up
    * @param evalKeyMap - reference to the map of evaluation keys generated by EvalSumKeyGen.
    * @param evalMultKey - reference to the evaluation key generated by EvalMultKeyGen.
    * @return resulting ciphertext
    */
    virtual Ciphertext<Element> EvalInnerProduct(ConstCiphertext<Element> ciphertext1,
                                                 ConstCiphertext<Element> ciphertext2, uint32_t batchSize,
                                                 const std::map<uint32_t, EvalKey<Element>>& evalKeyMap,
                                                 const EvalKey<Element> evalMultKey) const;

    /**
    * @brief Evaluates inner product in batched encoding
    * @param ciphertext first vector.
    * @param plaintext plaintext.
    * @param batchSize size of the batch to be summed up
    * @param evalKeyMap - reference to the map of evaluation keys generated by EvalSumKeyGen.
    * @return resulting ciphertext
    */
    virtual Ciphertext<Element> EvalInnerProduct(ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext,
                                                 uint32_t batchSize,
                                                 const std::map<uint32_t, EvalKey<Element>>& evalKeyMap) const;

    /**
   * Function to add random noise to all plaintext slots except for the first
   * one; used in EvalInnerProduct
   *
   * @param ciphertext the input ciphertext.
   * @return modified ciphertext
   */
    virtual Ciphertext<Element> AddRandomNoise(ConstCiphertext<Element> ciphertext) const;

    /**
   * Merges multiple ciphertexts with encrypted results in slot 0 into a
   * single ciphertext The slot assignment is done based on the order of
   * ciphertexts in the vector
   *
   * @param ciphertextVector vector of ciphertexts to be merged.
   * @param evalKeyMap - reference to the map of evaluation keys generated by
   * EvalAutomorphismKeyGen.
   * @return resulting ciphertext
   */
    virtual Ciphertext<Element> EvalMerge(const std::vector<Ciphertext<Element>>& ciphertextVector,
                                          const std::map<uint32_t, EvalKey<Element>>& evalKeyMap) const;

    //------------------------------------------------------------------------------
    // LINEAR TRANSFORMATION
    //------------------------------------------------------------------------------

    //------------------------------------------------------------------------------
    // Other Methods for Bootstrap
    //------------------------------------------------------------------------------

  protected:
    static std::set<uint32_t> GenerateIndices_2n(uint32_t batchSize, uint32_t m);

    static std::set<uint32_t> GenerateIndices2nComplex(uint32_t batchSize, uint32_t m);

    static std::set<uint32_t> GenerateIndices2nComplexRows(uint32_t rowSize, uint32_t m);

    static std::set<uint32_t> GenerateIndices2nComplexCols(uint32_t batchSize, uint32_t m);

    /**
   * Automorphism-index set of the radix-configured EvalSum fold (compile-time
   * PARTIAL_SUM_RADIX): {g0^(i*radix^level) mod m : i in [1, radix)}, bounded so the
   * fold covers size slots. Power-of-two m only.
   */
    static std::set<uint32_t> GenerateEvalSumIndices(uint32_t g0, uint32_t size, uint32_t m);

    /**
   * Radix-configured EvalSum rotation fold (compile-time PARTIAL_SUM_RADIX): per level,
   * one hoisted digit decomposition is shared by the level's up to radix-1 automorphisms
   * of the running sum. Generator g0 selects the flavor (5, 5^rowSize, or 5^-1 mod m);
   * covers size slots. Power-of-two m only.
   */
    Ciphertext<Element> EvalSumRadixFold(ConstCiphertext<Element>& ciphertext, uint32_t g0, uint32_t size, uint32_t m,
                                         const std::map<uint32_t, EvalKey<Element>>& evalKeyMap) const;

    static std::set<uint32_t> GenerateIndexListForEvalSum(const PrivateKey<Element>& privateKey);

    Ciphertext<Element> EvalSum_2n(ConstCiphertext<Element> ciphertext, uint32_t batchSize, uint32_t m,
                                   const std::map<uint32_t, EvalKey<Element>>& evalKeyMap) const;

    Ciphertext<Element> EvalSum2nComplex(ConstCiphertext<Element> ciphertext, uint32_t batchSize, uint32_t m,
                                         const std::map<uint32_t, EvalKey<Element>>& evalKeyMap) const;

    Ciphertext<Element> EvalSum2nComplexRows(ConstCiphertext<Element> ciphertext, uint32_t rowSize, uint32_t m,
                                             const std::map<uint32_t, EvalKey<Element>>& evalKeyMap) const;

    Ciphertext<Element> EvalSum2nComplexCols(ConstCiphertext<Element> ciphertext, uint32_t batchSize, uint32_t m,
                                             const std::map<uint32_t, EvalKey<Element>>& evalKeyMap) const;
};

}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_SCHEMEBASE_BASE_ADVANCEDSHE_H_
