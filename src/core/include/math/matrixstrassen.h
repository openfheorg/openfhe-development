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
  matrix strassen operations
 */

#ifndef LBCRYPTO_INC_MATH_MATRIXSTRASSEN_H
#define LBCRYPTO_INC_MATH_MATRIXSTRASSEN_H

#include "lattice/lat-hal.h"

#include "utils/exception.h"
#include "utils/parallel.h"

// #include <cmath>
#include <functional>
// #include <iostream>
#include <memory>
#include <utility>
#include <vector>

namespace lbcrypto {

template <class Element>
class MatrixStrassen {  // TODO : public Serializable {
public:
    typedef std::vector<std::vector<Element>> data_t;
    typedef std::vector<Element> lineardata_t;
    typedef typename std::vector<Element>::iterator it_lineardata_t;
    typedef std::function<Element(void)> alloc_func;

    /**
   * Constructor that initializes matrix values using a zero allocator
   *
   * @param &allocZero lambda function for zero initialization.
   * @param &rows number of rows.
   * @param &rows number of columns.
   */
    MatrixStrassen(alloc_func allocZero, size_t rows, size_t cols)
        : data(), rows(rows), cols(cols), allocZero(allocZero) {
        data.resize(rows);
        for (auto row = data.begin(); row != data.end(); ++row) {
            row->reserve(cols);
            for (size_t col = 0; col < cols; ++col) {
                row->push_back(allocZero());
            }
        }
    }

    /**
   * Constructor that initializes matrix values using a distribution generation
   * allocator
   *
   * @param &allocZero lambda function for zero initialization (used for
   * initializing derived matrix objects)
   * @param &rows number of rows.
   * @param &rows number of columns.
   * @param &allocGen lambda function for intialization using a distribution
   * generator.
   */
    MatrixStrassen(alloc_func allocZero, size_t rows, size_t cols, alloc_func allocGen);

    /**
   * Constructor of an empty matrix; SetSize must be called on this matrix to
   * use it Basically this exists to support deserializing
   *
   * @param &allocZero lambda function for zero initialization.
   */
    explicit MatrixStrassen(alloc_func allocZero) : data(), rows(0), cols(0), allocZero(allocZero) {}

    void SetSize(size_t rows, size_t cols) {
        if (this->rows != 0 || this->cols != 0) {
            OPENFHE_THROW("You cannot SetSize on a non-empty matrix");
        }

        this->rows = rows;
        this->cols = cols;

        data.resize(rows);
        for (auto row = data.begin(); row != data.end(); ++row) {
            row->reserve(cols);
            for (size_t col = 0; col < cols; ++col) {
                row->push_back(allocZero());
            }
        }
    }

    /**
   * Copy constructor
   *
   * @param &other the matrix object to be copied
   */
    MatrixStrassen(const MatrixStrassen<Element>& other)
        : data(), rows(other.rows), cols(other.cols), allocZero(other.allocZero) {
        deepCopyData(other.data);
    }

    /**
   * Assignment operator
   *
   * @param &other the matrix object whose values are to be copied
   * @return the resulting matrix
   */
    inline MatrixStrassen<Element>& operator=(const MatrixStrassen<Element>& other);

    /**
   * In-place change of the current matrix to a matrix of all ones
   *
   * @return the resulting matrix
   */
    inline MatrixStrassen<Element>& Ones();

    /**
   * Fill matrix using the same element
   *
   * @param &val the element the matrix is filled by
   *
   * @return the resulting matrix
   */
    inline MatrixStrassen<Element>& Fill(const Element& val);

    /**
   * In-place change of the current matrix to Identity matrix
   *
   * @return the resulting matrix
   */
    inline MatrixStrassen<Element>& Identity();

    /**
   * Sets the first row to be powers of two
   *
   * @return the resulting matrix
   */
    inline MatrixStrassen<Element> GadgetVector(int32_t base = 2) const;

    /**
   * Computes the infinity norm
   *
   * @return the norm in double format
   */
    inline double Norm() const;

    /**
   * Operator for matrix multiplication
   *
   * @param &other the multiplier matrix
   * @return the result of multiplication
   */
    inline MatrixStrassen<Element> operator*(MatrixStrassen<Element> const& other) const {
        return Mult(other);
    }

    /**
   * Multiplication of matrix by a scalar
   *
   * @param &other the multiplier element
   * @return the result of multiplication
   */
    inline MatrixStrassen<Element> ScalarMult(Element const& other) const {
        MatrixStrassen<Element> result(*this);
#pragma omp parallel for
        for (int32_t col = 0; col < result.cols; ++col) {
            for (int32_t row = 0; row < result.rows; ++row) {
                *result.data[row][col] = *result.data[row][col] * other;
            }
        }
        return result;
    }

    /**
   * Operator for scalar multiplication
   *
   * @param &other the multiplier element
   * @return the result of multiplication
   */
    inline MatrixStrassen<Element> operator*(Element const& other) const {
        return ScalarMult(other);
    }

    /**
   * Equality check
   *
   * @param &other the matrix object to compare to
   * @return the boolean result
   */
    inline bool Equal(MatrixStrassen<Element> const& other) const {
        if (rows != other.rows || cols != other.cols) {
            return false;
        }

        for (size_t i = 0; i < rows; ++i) {
            for (size_t j = 0; j < cols; ++j) {
                if (data[i][j] != other.data[i][j]) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
   * Operator for equality check
   *
   * @param &other the matrix object to compare to
   * @return the boolean result
   */
    inline bool operator==(MatrixStrassen<Element> const& other) const {
        return Equal(other);
    }

    /**
   * Operator for non-equality check
   *
   * @param &other the matrix object to compare to
   * @return the boolean result
   */
    inline bool operator!=(MatrixStrassen<Element> const& other) const {
        return !Equal(other);
    }

    /**
   * Get property to access the data as a vector of vectors
   *
   * @return the data as vector of vectors
   */
    const data_t& GetData() const {
        return data;
    }

    /**
   * Get property to access the number of rows in the matrix
   *
   * @return the number of rows
   */
    size_t GetRows() const {
        return rows;
    }

    /**
   * Get property to access the number of columns in the matrix
   *
   * @return the number of columns
   */
    size_t GetCols() const {
        return cols;
    }

    /**
   * Get property to access the zero allocator for the matrix
   *
   * @return the lambda function corresponding to the element zero allocator
   */
    alloc_func GetAllocator() const {
        return allocZero;
    }

    /**
   * Sets the evaluation or coefficient representation for all ring elements
   * that support the SetFormat method
   *
   * @param &format the enum value corresponding to coefficient or evaluation
   * representation
   */
    void SetFormat(Format format);

    /**
   * MatrixStrassen addition
   *
   * @param &other the matrix to be added
   * @return the resulting matrix
   */
    inline MatrixStrassen<Element> Add(MatrixStrassen<Element> const& other) const {
        if (rows != other.rows || cols != other.cols) {
            OPENFHE_THROW("Addition operands have incompatible dimensions");
        }
        MatrixStrassen<Element> result(*this);
#pragma omp parallel for
        for (int32_t j = 0; j < cols; ++j) {
            for (int32_t i = 0; i < rows; ++i) {
                *result.data[i][j] += *other.data[i][j];
            }
        }

        return result;
    }

    /**
   * Operator for matrix addition
   *
   * @param &other the matrix to be added
   * @return the resulting matrix
   */
    inline MatrixStrassen<Element> operator+(MatrixStrassen<Element> const& other) const {
        return this->Add(other);
    }

    /**
   * Operator for in-place addition
   *
   * @param &other the matrix to be added
   * @return the resulting matrix (same object)
   */
    inline MatrixStrassen<Element>& operator+=(MatrixStrassen<Element> const& other);

    /**
   * MatrixStrassen substraction
   *
   * @param &other the matrix to be substracted
   * @return the resulting matrix
   */
    inline MatrixStrassen<Element> Sub(MatrixStrassen<Element> const& other) const {
        if (rows != other.rows || cols != other.cols) {
            OPENFHE_THROW("Subtraction operands have incompatible dimensions");
        }
        MatrixStrassen<Element> result(allocZero, rows, other.cols);
#pragma omp parallel for
        for (int32_t j = 0; j < cols; ++j) {
            for (int32_t i = 0; i < rows; ++i) {
                *result.data[i][j] = *data[i][j] - *other.data[i][j];
            }
        }

        return result;
    }

    /**
   * Operator for matrix substraction
   *
   * @param &other the matrix to be substracted
   * @return the resulting matrix
   */
    inline MatrixStrassen<Element> operator-(MatrixStrassen<Element> const& other) const {
        return this->Sub(other);
    }

    /**
   * Operator for in-place matrix substraction
   *
   * @param &other the matrix to be substracted
   * @return the resulting matrix (same object)
   */
    inline MatrixStrassen<Element>& operator-=(MatrixStrassen<Element> const& other);

    /**
   * MatrixStrassen transposition
   *
   * @return the resulting matrix
   */
    inline MatrixStrassen<Element> Transpose() const;

    // YSP The signature of this method needs to be changed in the future
    /**
   * MatrixStrassen determinant - found using Laplace formula with complexity
   * O(d!), where d is the dimension
   *
   * @param *result where the result is stored
   */
    inline void Determinant(Element* result) const;

    /**
   * Cofactor matrix - the matrix of determinants of the minors A_{ij}
   * multiplied by -1^{i+j}
   *
   * @return the cofactor matrix for the given matrix
   */
    inline MatrixStrassen<Element> CofactorMatrixStrassen() const;

    /**
   * Add rows to bottom of the matrix
   *
   * @param &other the matrix to be added to the bottom of current matrix
   * @return the resulting matrix
   */
    inline MatrixStrassen<Element>& VStack(MatrixStrassen<Element> const& other);

    /**
   * Add columns the right of the matrix
   *
   * @param &other the matrix to be added to the right of current matrix
   * @return the resulting matrix
   */
    inline MatrixStrassen<Element>& HStack(MatrixStrassen<Element> const& other);

    /**
   * MatrixStrassen indexing operator - writeable instance of the element
   *
   * @param &row row index
   * @param &col column index
   * @return the element at the index
   */
    inline Element& operator()(size_t row, size_t col) {
        return data[row][col];
    }

    /**
   * MatrixStrassen indexing operator - read-only instance of the element
   *
   * @param &row row index
   * @param &col column index
   * @return the element at the index
   */
    inline Element const& operator()(size_t row, size_t col) const {
        return data[row][col];
    }

    /**
   * MatrixStrassen row extractor
   *
   * @param &row row index
   * @return the row at the index
   */
    inline MatrixStrassen<Element> ExtractRow(size_t row) const {
        MatrixStrassen<Element> result(this->allocZero, 1, this->cols);
        int i = 0;
        for (auto elem = this->GetData()[row].begin(); elem != this->GetData()[row].end(); ++elem) {
            result(0, i) = **elem;
            i++;
        }
        return result;
        // return *this;
    }

    /**
   * Call switch format for each (ring) element
   *
   */
    inline void SwitchFormat();

    /**
   * MatrixStrassen multiplication
   *
   * @param &other the multiplier matrix
   * @return the result of multiplication
   */
    MatrixStrassen<Element> Mult(const MatrixStrassen<Element>& other, int nrec = 0, int pad = -1) const;

    /*
   * Multiply the matrix by a vector whose elements are all 1's.  This causes
   * the elements of each row of the matrix to be added and placed into the
   * corresponding position in the output vector.
   */
    MatrixStrassen<Element> MultByUnityVector() const;

    /*
   * Multiply the matrix by a vector of random 1's and 0's, which is the same as
   * adding select elements in each row together. Return a vector that is a rows
   * x 1 matrix.
   */
    MatrixStrassen<Element> MultByRandomVector(std::vector<int> ranvec) const;

private:
    struct MatDescriptor {
        int lda;
        int nrec;
        int nproc;
        int nprocr;
        int nprocc;
        int nproc_summa;
        int bs;
    };
    const int DESC_SIZE = 7;  // number of ints that make up a MatDescriptor
    const int rank = 0, base = 0;

    mutable data_t data;
    size_t rows;
    mutable int rowpad = 0;
    size_t cols;
    mutable int colpad = 0;
    alloc_func allocZero;
    mutable char* pattern = nullptr;
    mutable int numAdd    = 0;
    mutable int numMult   = 0;
    mutable int numSub    = 0;
    mutable MatDescriptor desc;
    mutable Element zeroUniquePtr = allocZero();
    mutable int NUM_THREADS       = 1;

    void multiplyInternalCAPS(it_lineardata_t A, it_lineardata_t B, it_lineardata_t C, MatDescriptor desc,
                              it_lineardata_t work) const;
    void strassenDFSCAPS(it_lineardata_t A, it_lineardata_t B, it_lineardata_t C, MatDescriptor desc,
                         it_lineardata_t workPassThrough) const;
    void block_multiplyCAPS(it_lineardata_t A, it_lineardata_t B, it_lineardata_t C, MatDescriptor d,
                            it_lineardata_t workPassThrough) const;
    void LinearizeDataCAPS(lineardata_t* lineardataPtr) const;
    void UnlinearizeDataCAPS(lineardata_t* lineardataPtr) const;
    int getRank() const;
    void verifyDescriptor(MatDescriptor desc);
    long long numEntriesPerProc(MatDescriptor desc) const;  // NOLINT
    // deep copy of data - used for copy constructor
    void deepCopyData(data_t const& src);
    void getData(const data_t& Adata, const data_t& Bdata, const data_t& Cdata, int row, int inner, int col) const;

    void smartSubtractionCAPS(it_lineardata_t result, it_lineardata_t A, it_lineardata_t B) const;
    void smartAdditionCAPS(it_lineardata_t result, it_lineardata_t A, it_lineardata_t B) const;
    void addMatricesCAPS(int numEntries, it_lineardata_t C, it_lineardata_t A, it_lineardata_t B) const;
    void addSubMatricesCAPS(int numEntries, it_lineardata_t T1, it_lineardata_t S11, it_lineardata_t S12,
                            it_lineardata_t T2, it_lineardata_t S21, it_lineardata_t S22) const;
    void subMatricesCAPS(int numEntries, it_lineardata_t C, it_lineardata_t A, it_lineardata_t B) const;
    void tripleAddMatricesCAPS(int numEntries, it_lineardata_t T1, it_lineardata_t S11, it_lineardata_t S12,
                               it_lineardata_t T2, it_lineardata_t S21, it_lineardata_t S22, it_lineardata_t T3,
                               it_lineardata_t S31, it_lineardata_t S32) const;
    void tripleSubMatricesCAPS(int numEntries, it_lineardata_t T1, it_lineardata_t S11, it_lineardata_t S12,
                               it_lineardata_t T2, it_lineardata_t S21, it_lineardata_t S22, it_lineardata_t T3,
                               it_lineardata_t S31, it_lineardata_t S32) const;

    void distributeFrom1ProcCAPS(MatDescriptor desc, it_lineardata_t O, it_lineardata_t I) const;
    void collectTo1ProcCAPS(MatDescriptor desc, it_lineardata_t O, it_lineardata_t I) const;
    void sendBlockCAPS(int rank, int target, it_lineardata_t O, int bs, int source, it_lineardata_t I, int ldi) const;
    void receiveBlockCAPS(int rank, int target, it_lineardata_t O, int bs, int source, it_lineardata_t I,
                          int ldo) const;
    void distributeFrom1ProcRecCAPS(MatDescriptor desc, it_lineardata_t O, it_lineardata_t I, int ldi) const;
    void collectTo1ProcRecCAPS(MatDescriptor desc, it_lineardata_t O, it_lineardata_t I, int ldo) const;
};

/**
 * Operator for scalar multiplication of matrix
 *
 * @param &e element
 * @param &M matrix
 * @return the resulting matrix
 */
template <class Element>
inline MatrixStrassen<Element> operator*(Element const& e, MatrixStrassen<Element> const& M) {
    return M.ScalarMult(e);
}

/**
 * Generates a matrix of rotations. See pages 7-8 of
 * https://eprint.iacr.org/2013/297
 *
 * @param &inMat the matrix of power-of-2 cyclotomic ring elements to be rotated
 * @return the resulting matrix of big binary integers
 */
inline MatrixStrassen<BigInteger> Rotate(MatrixStrassen<Poly> const& inMat);

/**
 *  Each element becomes a square matrix with columns of that element's
 *  rotations in coefficient form. See pages 7-8 of
 * https://eprint.iacr.org/2013/297
 *
 * @param &inMat the matrix of power-of-2 cyclotomic ring elements to be rotated
 * @return the resulting matrix of big binary integers
 */
inline MatrixStrassen<BigVector> RotateVecResult(MatrixStrassen<Poly> const& inMat);

/**
 *  Stream output operator
 *
 * @param &os stream
 * @param &m matrix to be outputted
 * @return the chained stream
 */
template <class Element>
inline std::ostream& operator<<(std::ostream& os, const MatrixStrassen<Element>& m);

/**
 * Gives the Choleshky decomposition of the input matrix.
 * The assumption is that covariance matrix does not have large coefficients
 * because it is formed by discrete gaussians e and s; this implies int32_t can
 * be used This algorithm can be further improved - see the Darmstadt paper
 * section 4.4 http://eprint.iacr.org/2013/297.pdf
 *
 * @param &input the matrix for which the Cholesky decomposition is to be
 * computed
 * @return the resulting matrix of floating-point numbers
 */
inline MatrixStrassen<double> Cholesky(const MatrixStrassen<int32_t>& input);

/**
 * Convert a matrix of integers from BigInteger to int32_t
 * Convert from Z_q to [-q/2, q/2]
 *
 * @param &input the input matrix
 * @param &modulus the ring modulus
 * @return the resulting matrix of int32_t
 */
inline MatrixStrassen<int32_t> ConvertToInt32(const MatrixStrassen<BigInteger>& input, const BigInteger& modulus);

/**
 * Convert a matrix of BigVector to int32_t
 * Convert from Z_q to [-q/2, q/2]
 *
 * @param &input the input matrix
 * @param &modulus the ring modulus
 * @return the resulting matrix of int32_t
 */
inline MatrixStrassen<int32_t> ConvertToInt32(const MatrixStrassen<BigVector>& input, const BigInteger& modulus);

/**
 * Split a vector of int32_t into a vector of ring elements with ring dimension
 * n
 *
 * @param &other the input matrix
 * @param &n the ring dimension
 * @param &params Poly element params
 * @return the resulting matrix of Poly
 */
inline MatrixStrassen<Poly> SplitInt32IntoPolyElements(MatrixStrassen<int32_t> const& other, size_t n,
                                                       const std::shared_ptr<ILParams> params);

/**
 * Another method for splitting a vector of int32_t into a vector of ring
 * elements with ring dimension n
 *
 * @param &other the input matrix
 * @param &n the ring dimension
 * @param &params Poly element params
 * @return the resulting matrix of Poly
 */
inline MatrixStrassen<Poly> SplitInt32AltIntoPolyElements(MatrixStrassen<int32_t> const& other, size_t n,
                                                          const std::shared_ptr<ILParams> params);
}  // namespace lbcrypto

#endif  // LBCRYPTO_INC_MATH_MATRIXSTRASSEN_H
