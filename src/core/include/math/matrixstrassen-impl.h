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

#ifndef LBCRYPTO_INC_MATH_MATRIXSTRASSEN_IMPL_H
#define LBCRYPTO_INC_MATH_MATRIXSTRASSEN_IMPL_H

#include "math/matrixstrassen.h"

#include "utils/parallel.h"

#include <assert.h>
#include <memory>
#include <utility>
#include <vector>

namespace lbcrypto {

template <class Element>
MatrixStrassen<Element>::MatrixStrassen(alloc_func allocZero, size_t rows, size_t cols, alloc_func allocGen)
    : data(), rows(rows), cols(cols), allocZero(allocZero) {
    data.resize(rows);
    for (auto& row : data) {
        for (size_t col = 0; col < cols; ++col) {
            row.push_back(allocGen());
        }
    }
}

template <class Element>
MatrixStrassen<Element>& MatrixStrassen<Element>::operator=(const MatrixStrassen<Element>& other) {
    rows = other.rows;
    cols = other.cols;
    deepCopyData(other.data);
    return *this;
}

template <class Element>
MatrixStrassen<Element>& MatrixStrassen<Element>::Ones() {
    for (size_t row = 0; row < rows; ++row) {
        for (size_t col = 0; col < cols; ++col) {
            *data[row][col] = 1;
        }
    }
    return *this;
}

template <class Element>
MatrixStrassen<Element>& MatrixStrassen<Element>::Fill(const Element& val) {
    for (size_t row = 0; row < rows; ++row) {
        for (size_t col = 0; col < cols; ++col) {
            *data[row][col] = val;
        }
    }
    return *this;
}

template <class Element>
MatrixStrassen<Element>& MatrixStrassen<Element>::Identity() {
    for (size_t row = 0; row < rows; ++row) {
        for (size_t col = 0; col < cols; ++col) {
            if (row == col) {
                data[row][col] = 1;
            }
            else {
                data[row][col] = 0;
            }
        }
    }
    return *this;
}

template <class Element>
MatrixStrassen<Element> MatrixStrassen<Element>::GadgetVector(int32_t base) const {
    MatrixStrassen<Element> g(allocZero, rows, cols);
    // auto two = allocZero();
    auto base_matrix = allocZero();
    *base_matrix     = base;
    g(0, 0)          = 1;
    for (size_t col = 1; col < cols; ++col) {
        //  g(0, col) = g(0, col-1) * *two;
        g(0, col) = g(0, col - 1) * *base_matrix;
    }
    return g;
}

template <class Element>
double MatrixStrassen<Element>::Norm() const {
    double retVal = 0.0;
    double locVal = 0.0;

    for (size_t row = 0; row < rows; ++row) {
        for (size_t col = 0; col < cols; ++col) {
            locVal = data[row][col]->Norm();
            if (locVal > retVal) {
                retVal = locVal;
            }
        }
    }

    return retVal;
}

template <class Element>
void MatrixStrassen<Element>::SetFormat(Format format) {
    for (size_t row = 0; row < rows; ++row) {
        for (size_t col = 0; col < cols; ++col) {
            data[row][col].SetFormat(format);
        }
    }
}

template <class Element>
MatrixStrassen<Element>& MatrixStrassen<Element>::operator+=(MatrixStrassen<Element> const& other) {
    if (rows != other.rows || cols != other.cols) {
        OPENFHE_THROW(math_error, "Addition operands have incompatible dimensions");
    }
#pragma omp parallel for
    for (size_t j = 0; j < cols; ++j) {
        for (size_t i = 0; i < rows; ++i) {
            data[i][j] += other.data[i][j];
        }
    }
    return *this;
}

template <class Element>
inline MatrixStrassen<Element>& MatrixStrassen<Element>::operator-=(MatrixStrassen<Element> const& other) {
    if (rows != other.rows || cols != other.cols) {
        OPENFHE_THROW(math_error, "Subtraction operands have incompatible dimensions");
    }
#pragma omp parallel for
    for (size_t j = 0; j < cols; ++j) {
        for (size_t i = 0; i < rows; ++i) {
            data[i][j] -= other.data[i][j];
        }
    }

    return *this;
}

template <class Element>
MatrixStrassen<Element> MatrixStrassen<Element>::Transpose() const {
    MatrixStrassen<Element> result(allocZero, cols, rows);
    for (size_t row = 0; row < rows; ++row) {
        for (size_t col = 0; col < cols; ++col) {
            result(col, row) = (*this)(row, col);
        }
    }
    return result;
}

// YSP The signature of this method needs to be changed in the future
// Laplace's formula is used to find the determinant
// Complexity is O(d!), where d is the dimension
// The determinant of a matrix is expressed in terms of its minors
// recursive implementation
// There are O(d^3) decomposition algorithms that can be implemented to support
// larger dimensions. Examples include the LU decomposition, the QR
// decomposition or the Cholesky decomposition(for positive definite matrices).
template <class Element>
void MatrixStrassen<Element>::Determinant(Element* determinant) const {
    if (rows != cols)
        OPENFHE_THROW(math_error, "Supported only for square matrix");
    // auto determinant = *allocZero();
    if (rows < 1)
        OPENFHE_THROW(math_error, "Dimension should be at least one");

    if (rows == 1) {
        *determinant = *data[0][0];
    }
    else if (rows == 2) {
        *determinant = *data[0][0] * (*data[1][1]) - *data[1][0] * (*data[0][1]);
    }
    else {
        size_t j1, j2;
        size_t n = rows;

        MatrixStrassen<Element> result(allocZero, rows - 1, cols - 1);

        // for each column in sub-matrix
        for (j1 = 0; j1 < n; j1++) {
            // build sub-matrix with minor elements excluded
            for (size_t i = 1; i < n; i++) {
                j2 = 0;  // start at first sum-matrix column position
                // loop to copy source matrix less one column
                for (size_t j = 0; j < n; j++) {
                    if (j == j1)
                        continue;  // don't copy the minor column element

                    *result.data[i - 1][j2] = *data[i][j];  // copy source element into new sub-matrix
                                                            // i-1 because new sub-matrix is one row
                                                            // (and column) smaller with excluded minors
                    j2++;                                   // move to next sub-matrix column position
                }
            }

            auto tempDeterminant = *allocZero();
            result.Determinant(&tempDeterminant);

            if (j1 % 2 == 0)
                *determinant = *determinant + (*data[0][j1]) * tempDeterminant;
            else
                *determinant = *determinant - (*data[0][j1]) * tempDeterminant;

            // if (j1 % 2 == 0)
            //  determinant = determinant + (*data[0][j1]) *
            // result.Determinant(); else   determinant = determinant -
            // (*data[0][j1]) * result.Determinant();
        }
    }
    // return determinant;
    return;
}

// The cofactor matrix is the matrix of determinants of the minors A_{ij}
// multiplied by -1^{i+j} The determinant subroutine is used
template <class Element>
MatrixStrassen<Element> MatrixStrassen<Element>::CofactorMatrixStrassen() const {
    if (rows != cols)
        OPENFHE_THROW(math_error, "Supported only for square matrix");

    size_t ii, jj, iNew, jNew;

    size_t n = rows;

    MatrixStrassen<Element> result(allocZero, rows, cols);

    for (size_t j = 0; j < n; j++) {
        for (size_t i = 0; i < n; i++) {
            MatrixStrassen<Element> c(allocZero, rows - 1, cols - 1);

            /* Form the adjoint a_ij */
            iNew = 0;
            for (ii = 0; ii < n; ii++) {
                if (ii == i)
                    continue;
                jNew = 0;
                for (jj = 0; jj < n; jj++) {
                    if (jj == j)
                        continue;
                    *c.data[iNew][jNew] = *data[ii][jj];
                    jNew++;
                }
                iNew++;
            }

            /* Calculate the determinant */
            auto determinant = allocZero();
            c.Determinant(&determinant);
            // auto determinant = c.Determinant();

            /* Fill in the elements of the cofactor */
            if ((i + j) % 2 == 0)
                result.data[i][j] = determinant;
            else
                result.data[i][j] = -determinant;
        }
    }

    return result;
}

//  add rows to bottom of the matrix
template <class Element>
MatrixStrassen<Element>& MatrixStrassen<Element>::VStack(MatrixStrassen<Element> const& other) {
    if (cols != other.cols) {
        OPENFHE_THROW(math_error, "VStack rows not equal size");
    }
    for (size_t row = 0; row < other.rows; ++row) {
        std::vector<std::unique_ptr<Element>> rowElems;
        for (auto elem : other.data[row]) {
            rowElems.push_back(Element(*elem));
        }
        data.push_back(std::move(rowElems));
    }
    rows += other.rows;
    return *this;
}

//  add cols to right of the matrix
template <class Element>
inline MatrixStrassen<Element>& MatrixStrassen<Element>::HStack(MatrixStrassen<Element> const& other) {
    if (rows != other.rows) {
        OPENFHE_THROW(math_error, "HStack cols not equal size");
    }
    for (size_t row = 0; row < rows; ++row) {
        std::vector<std::unique_ptr<Element>> rowElems;
        for (auto elem = other.data[row].begin(); elem != other.data[row].end(); ++elem) {
            rowElems.push_back(Element(*elem));
        }
        MoveAppend(data[row], rowElems);
    }
    cols += other.cols;
    return *this;
}

template <class Element>
void MatrixStrassen<Element>::SwitchFormat() {
    for (size_t row = 0; row < rows; ++row) {
        for (size_t col = 0; col < cols; ++col) {
            data[row][col].SwitchFormat();
        }
    }
}

template <class Element>
void MatrixStrassen<Element>::LinearizeDataCAPS(lineardata_t* lineardataPtr) const {
    lineardataPtr->clear();

    for (size_t row = 0; row < data.size(); ++row) {
        for (auto elem = data[row].begin(); elem != data[row].end(); ++elem) {
            lineardataPtr->push_back(std::move(*elem));
        }
        data[row].clear();
        // Now add the padded columns for each row
        for (int i = 0; i < colpad; i++) {
            lineardataPtr->push_back(zeroUniquePtr);  // Should point to 0
        }
    }
    // Now add the padded rows
    int numelem = rowpad * (cols + colpad);

    for (int i = 0; i < numelem; i++) {
        lineardataPtr->push_back(zeroUniquePtr);  // Should point to 0
    }
}

template <class Element>
void MatrixStrassen<Element>::UnlinearizeDataCAPS(lineardata_t* lineardataPtr) const {
    int datasize = cols;

    size_t row  = 0;
    int counter = 0;
    data[row].clear();
    data[row].reserve(datasize);
    for (auto elem = lineardataPtr->begin(); elem != lineardataPtr->end(); ++elem) {
        data[row].push_back(std::move(*elem));

        counter++;
        if (counter % rows == 0) {
            // Eat next colpad elements
            for (int i = 0; i < colpad; i++) {
                ++elem;
            }

            row++;
            if (row < rows) {
                data[row].clear();
                data[row].reserve(datasize);
            }
            else {
                break;  // Get rid of padded rows
            }
        }
    }
    lineardataPtr->clear();
}

template <class Element>
void MatrixStrassen<Element>::deepCopyData(data_t const& src) {
    data.clear();
    data.resize(src.size());
    for (size_t row = 0; row < src.size(); ++row) {
        for (auto elem = src[row].begin(); elem != src[row].end(); ++elem) {
            data[row].push_back(Element(*elem));
        }
    }
}

inline MatrixStrassen<BigInteger> Rotate(MatrixStrassen<Poly> const& inMat) {
    MatrixStrassen<Poly> mat(inMat);
    mat.SetFormat(Format::COEFFICIENT);
    size_t n                  = mat(0, 0).GetLength();
    BigInteger const& modulus = mat(0, 0).GetModulus();
    size_t rows               = mat.GetRows() * n;
    size_t cols               = mat.GetCols() * n;
    MatrixStrassen<BigInteger> result(BigInteger::Allocator, rows, cols);
    for (size_t row = 0; row < mat.GetRows(); ++row) {
        for (size_t col = 0; col < mat.GetCols(); ++col) {
            for (size_t rotRow = 0; rotRow < n; ++rotRow) {
                for (size_t rotCol = 0; rotCol < n; ++rotCol) {
                    result(row * n + rotRow, col * n + rotCol) =
                        mat(row, col).GetValues().at((rotRow - rotCol + n) % n);
                    //  negate (mod q) upper-right triangle to account for
                    //  (mod x^n + 1)
                    if (rotRow < rotCol) {
                        result(row * n + rotRow, col * n + rotCol) =
                            modulus.ModSub(result(row * n + rotRow, col * n + rotCol), modulus);
                    }
                }
            }
        }
    }
    return result;
}

/**
 *  Each element becomes a square matrix with columns of that element's
 *  rotations in Format::COEFFICIENT form.
 */
MatrixStrassen<BigVector> RotateVecResult(MatrixStrassen<Poly> const& inMat) {
    MatrixStrassen<Poly> mat(inMat);
    mat.SetFormat(Format::COEFFICIENT);
    size_t n                  = mat(0, 0).GetLength();
    BigInteger const& modulus = mat(0, 0).GetModulus();
    BigVector zero(1, modulus);
    size_t rows                = mat.GetRows() * n;
    size_t cols                = mat.GetCols() * n;
    auto singleElemBinVecAlloc = [=]() {
        return BigVector(1, modulus);
    };
    MatrixStrassen<BigVector> result(singleElemBinVecAlloc, rows, cols);
    for (size_t row = 0; row < mat.GetRows(); ++row) {
        for (size_t col = 0; col < mat.GetCols(); ++col) {
            for (size_t rotRow = 0; rotRow < n; ++rotRow) {
                for (size_t rotCol = 0; rotCol < n; ++rotCol) {
                    BigVector& elem = result(row * n + rotRow, col * n + rotCol);
                    elem.at(0)      = mat(row, col).GetValues().at((rotRow - rotCol + n) % n);
                    //  negate (mod q) upper-right triangle to account for
                    //  (mod x^n + 1)
                    if (rotRow < rotCol) {
                        result(row * n + rotRow, col * n + rotCol) = zero.ModSub(elem);
                    }
                }
            }
        }
    }
    return result;
}

template <class Element>
inline std::ostream& operator<<(std::ostream& os, const MatrixStrassen<Element>& m) {
    os << "[ ";
    for (size_t row = 0; row < m.GetRows(); ++row) {
        os << "[ ";
        for (size_t col = 0; col < m.GetCols(); ++col) {
            os << m(row, col) << " ";
        }
        os << "]\n";
    }
    os << " ]\n";
    return os;
}

// YSP removed the MatrixStrassen class because it is not defined for all
// possible data types needs to be checked to make sure input matrix is used in
// the right places the assumption is that covariance matrix does not have large
// coefficients because it is formed by discrete gaussians e and s; this implies
// int32_t can be used This algorithm can be further improved - see the
// Darmstadt paper section 4.4
MatrixStrassen<double> Cholesky(const MatrixStrassen<int32_t>& input) {
    //  http://eprint.iacr.org/2013/297.pdf
    if (input.GetRows() != input.GetCols()) {
        OPENFHE_THROW(math_error, "not square");
    }
    size_t rows = input.GetRows();
    MatrixStrassen<double> result([]() { return 0; }, rows, rows);

    for (size_t i = 0; i < rows; ++i) {
        for (size_t j = 0; j < rows; ++j) {
            result(i, j) = input(i, j);
        }
    }

    for (size_t k = 0; k < rows; ++k) {
        result(k, k) = sqrt(input(k, k));

        for (size_t i = k + 1; i < rows; ++i) {
            // result(i, k) = input(i, k) / result(k, k);
            result(i, k) = result(i, k) / result(k, k);
            //  zero upper-right triangle
            result(k, i) = 0;
        }
        for (size_t j = k + 1; j < rows; ++j) {
            for (size_t i = j; i < rows; ++i) {
                if (result(i, k) != 0 && result(j, k) != 0) {
                    result(i, j) = result(i, j) - result(i, k) * result(j, k);
                    // result(i, j) = input(i, j) - result(i, k) * result(j, k);
                }
            }
        }
    }
    return result;
}

//  Convert from Z_q to [-q/2, q/2]
MatrixStrassen<int32_t> ConvertToInt32(const MatrixStrassen<BigInteger>& input, const BigInteger& modulus) {
    size_t rows = input.GetRows();
    size_t cols = input.GetCols();
    BigInteger negativeThreshold(modulus / BigInteger(2));
    MatrixStrassen<int32_t> result([]() { return 0; }, rows, cols);
    for (size_t i = 0; i < rows; ++i) {
        for (size_t j = 0; j < cols; ++j) {
            if (input(i, j) > negativeThreshold) {
                result(i, j) = -1 * (modulus - input(i, j)).ConvertToInt();
            }
            else {
                result(i, j) = input(i, j).ConvertToInt();
            }
        }
    }
    return result;
}

MatrixStrassen<int32_t> ConvertToInt32(const MatrixStrassen<BigVector>& input, const BigInteger& modulus) {
    size_t rows = input.GetRows();
    size_t cols = input.GetCols();
    BigInteger negativeThreshold(modulus / BigInteger(2));
    MatrixStrassen<int32_t> result([]() { return 0; }, rows, cols);
    for (size_t i = 0; i < rows; ++i) {
        for (size_t j = 0; j < cols; ++j) {
            const BigInteger& elem = input(i, j).at(0);
            if (elem > negativeThreshold) {
                result(i, j) = -1 * (modulus - elem).ConvertToInt();
            }
            else {
                result(i, j) = elem.ConvertToInt();
            }
        }
    }
    return result;
}

//  split a vector of int32_t into a vector of ring elements with ring dimension
//  n
MatrixStrassen<Poly> SplitInt32IntoPolyElements(MatrixStrassen<int32_t> const& other, size_t n,
                                                const std::shared_ptr<ILParams> params) {
    auto zero_alloc = Poly::Allocator(params, Format::COEFFICIENT);

    size_t rows = other.GetRows() / n;

    MatrixStrassen<Poly> result(zero_alloc, rows, 1);

    for (size_t row = 0; row < rows; ++row) {
        BigVector tempBBV(n, params->GetModulus());

        for (size_t i = 0; i < n; ++i) {
            BigInteger tempBBI;
            uint32_t tempInteger;
            if (other(row * n + i, 0) < 0) {
                tempInteger = -other(row * n + i, 0);
                tempBBI     = params->GetModulus() - BigInteger(tempInteger);
            }
            else {
                tempInteger = other(row * n + i, 0);
                tempBBI     = BigInteger(tempInteger);
            }
            tempBBV.at(i) = tempBBI;
        }

        result(row, 0).SetValues(std::move(tempBBV), Format::COEFFICIENT);
    }

    return result;
}

//  split a vector of BBI into a vector of ring elements with ring dimension n
MatrixStrassen<Poly> SplitInt32AltIntoPolyElements(MatrixStrassen<int32_t> const& other, size_t n,
                                                   const std::shared_ptr<ILParams> params) {
    auto zero_alloc = Poly::Allocator(params, Format::COEFFICIENT);

    size_t rows = other.GetRows();

    MatrixStrassen<Poly> result(zero_alloc, rows, 1);

    for (size_t row = 0; row < rows; ++row) {
        BigVector tempBBV(n, params->GetModulus());

        for (size_t i = 0; i < n; ++i) {
            BigInteger tempBBI;
            uint32_t tempInteger;
            if (other(row, i) < 0) {
                tempInteger = -other(row, i);
                tempBBI     = params->GetModulus() - BigInteger(tempInteger);
            }
            else {
                tempInteger = other(row, i);
                tempBBI     = BigInteger(tempInteger);
            }

            tempBBV.at(i) = tempBBI;
        }

        result(row, 0).SetValues(std::move(tempBBV), Format::COEFFICIENT);
    }

    return result;
}

template <class Element>
MatrixStrassen<Element> MatrixStrassen<Element>::Mult(MatrixStrassen<Element> const& other, int nrec, int pad) const {
    int allrows = rows;

    NUM_THREADS = ParallelControls().GetMachineThreads();

    if (pad == -1) {
        // int allcols = cols;

        /*
     * Calculate the optimal number of padding rows and padding columns.  (Note
     * that these do not need to be the same, allowing rectangular matrices to
     * be handled.)
     *
     * The amount of padding in a dimension needs to support the number of
     * levels of recursion that are passed to this routine.  For instance, if
     * the original number of columns is 93, and nrec = 1. then only 1 column of
     * padding must be added.  (93 + 1)/2 is an integer. However, (93 + 1)/2/2
     * is not an integer, so a single column of padding will not support 2
     * levels of recursion.  The algorithm given here will determine that a
     * 93x93 matrix needs to be padded to 96x96 to support 2 levels of
     * recursion, as 96/(2^2) is an integer.
     */
        double powtemp = pow(2, nrec);
        rowpad         = ceil(rows / powtemp) * static_cast<int>(powtemp) - rows;
        colpad         = ceil(cols / powtemp) * static_cast<int>(powtemp) - cols;
        allrows        = rows + rowpad;
        // allcols = cols + colpad;
    }
    else {
        /* Apply the indicated padding rows and columns.  (For now they are equal,
     * assuming square matrices.  Note that the dimension of the matrix after
     * padding must support the number of levels of recursion.  For instance, if
     * a 93x93 matrix is padded out to 94x94, this supports only 1 level of
     * recursion, since 94/2 is integral, while 47/2 is not.  The assertions
     * catch this problem.  Note that the user should not need to provide a
     * padding value, as setting the padding value to -1 will cause this code to
     * caluclate the optimal padding for the number of levels of recursion.
     */

        rowpad  = pad;
        colpad  = pad;
        allrows = rows + pad;
        // allrows/(2^nrec) and allcols/(2^nrec) must be integers
#if !defined(NDEBUG)
        int allcols = cols + pad;
        double temp = allrows / pow(2, nrec);
        assert(static_cast<int>(temp) == ceil(temp));
        temp = allcols / pow(2, nrec);
        assert(static_cast<int>(temp) == ceil(temp));
#endif
    }

    numAdd  = 0;
    numSub  = 0;
    numMult = 0;

    size_t len       = (allrows * allrows);
    desc.lda         = static_cast<int>(allrows);
    desc.nrec        = nrec;
    desc.bs          = 1;
    desc.nproc       = 1;
    desc.nproc_summa = 1;
    desc.nprocc      = 1;
    desc.nprocr      = 1;

    MatrixStrassen<Element> result(allocZero, rows, other.cols);

    other.rowpad  = rowpad;
    result.rowpad = rowpad;
    other.colpad  = colpad;
    result.colpad = colpad;
    lineardata_t lineardataPtr;
    lineardata_t otherlineardataPtr;
    lineardata_t resultlineardataPtr;
    this->LinearizeDataCAPS(&lineardataPtr);
    other.LinearizeDataCAPS(&otherlineardataPtr);
    result.LinearizeDataCAPS(&resultlineardataPtr);

    lineardata_t thisdata;
    lineardata_t otherdata;
    lineardata_t resultdata;
    lineardata_t tempdata;

    for (size_t elem = 0; elem < len; ++elem) {
        resultdata.push_back(allocZero());
    }

    tempdata.resize(len);
    thisdata.resize(len);
    otherdata.resize(len);

    distributeFrom1ProcCAPS(desc, thisdata.begin(), lineardataPtr.begin());

    distributeFrom1ProcCAPS(desc, otherdata.begin(), otherlineardataPtr.begin());

    // multiplyInternalCAPS(otherdata.begin(), thisdata.begin(),
    // resultdata.begin() /*,&(result.lineardata[0])*/, desc,
    // (it_lineardata_t)0);//&(result.lineardata[0])
    multiplyInternalCAPS(otherdata.begin(), thisdata.begin(), resultdata.begin() /*,&(result.lineardata[0])*/, desc,
                         lineardataPtr.begin());  // &(result.lineardata[0])

    collectTo1ProcCAPS(desc, resultlineardataPtr.begin(), resultdata.begin());
    resultdata.clear();

    result.UnlinearizeDataCAPS(&resultlineardataPtr);
    resultlineardataPtr.clear();

    collectTo1ProcCAPS(desc, lineardataPtr.begin(), thisdata.begin());
    thisdata.clear();

    this->UnlinearizeDataCAPS(&lineardataPtr);
    lineardataPtr.clear();

    collectTo1ProcCAPS(desc, otherlineardataPtr.begin(), otherdata.begin());
    otherdata.clear();

    other.UnlinearizeDataCAPS(&otherlineardataPtr);
    otherlineardataPtr.clear();

    return result;
}

// nproc is the number of processors that share the matrices, and will be
// involved in the multiplication
template <class Element>
void MatrixStrassen<Element>::multiplyInternalCAPS(it_lineardata_t A, it_lineardata_t B, it_lineardata_t C,
                                                   MatDescriptor desc, it_lineardata_t work) const {
    // (planned) out of recursion in the data layout, do a regular matrix
    // multiply.  The matrix is now in a 2d block cyclic layout
    if (desc.nrec == 0) {
        // A 2d block cyclic layout with 1 processor still has blocks to deal with
        // run a 1-proc non-strassen
        block_multiplyCAPS(A, B, C, desc, work);
    }
    else {
        if (pattern == nullptr) {
            strassenDFSCAPS(A, B, C, desc, work);
        }
        else {
            if (pattern[0] == 'D' || pattern[0] == 'd') {
                pattern++;

                strassenDFSCAPS(A, B, C, desc, work);
                pattern--;
            }
        }
    }
}

template <class Element>
void MatrixStrassen<Element>::addMatricesCAPS(int numEntries, it_lineardata_t C, it_lineardata_t A,
                                              it_lineardata_t B) const {
#pragma omp parallel for schedule(static, (numEntries + NUM_THREADS - 1) / NUM_THREADS)
    for (int i = 0; i < numEntries; i++) {
        smartAdditionCAPS(C + i, A + i, B + i);
    }
}

template <class Element>
void MatrixStrassen<Element>::subMatricesCAPS(int numEntries, it_lineardata_t C, it_lineardata_t A,
                                              it_lineardata_t B) const {
#pragma omp parallel for schedule(static, (numEntries + NUM_THREADS - 1) / NUM_THREADS)
    for (int i = 0; i < numEntries; i++) {
        smartSubtractionCAPS(C + i, A + i, B + i);
    }
}

template <class Element>
void MatrixStrassen<Element>::smartSubtractionCAPS(it_lineardata_t result, it_lineardata_t A, it_lineardata_t B) const {
    Element temp;

    if (*A != zeroUniquePtr && *B != zeroUniquePtr) {
        temp = *A - *B;
        numSub++;
    }
    else if (*A == zeroUniquePtr && *B != zeroUniquePtr) {
        temp = zeroUniquePtr - *B;
        numSub++;
    }
    else if (*A != zeroUniquePtr && *B == zeroUniquePtr) {
        temp = *A;
    }
    else {
        temp = zeroUniquePtr;
    }

    *result = temp;
    return;
}

template <class Element>
void MatrixStrassen<Element>::smartAdditionCAPS(it_lineardata_t result, it_lineardata_t A, it_lineardata_t B) const {
    Element temp;

    if (*A != zeroUniquePtr && *B != zeroUniquePtr) {
        temp = *A + *B;
        numAdd++;
    }
    else if (*A == zeroUniquePtr && *B != zeroUniquePtr) {
        temp = *B;
    }
    else if (*A != zeroUniquePtr && *B == zeroUniquePtr) {
        temp = *A;
    }
    else {
        temp = zeroUniquePtr;
    }

    *result = temp;
    return;
}
// useful to improve cache behavior if there is some overlap.  It is safe for
// T_i to be the same as S_j* as long as i<j.  That is, operations will happen
// in the order specified
template <class Element>
void MatrixStrassen<Element>::tripleSubMatricesCAPS(int numEntries, it_lineardata_t T1, it_lineardata_t S11,
                                                    it_lineardata_t S12, it_lineardata_t T2, it_lineardata_t S21,
                                                    it_lineardata_t S22, it_lineardata_t T3, it_lineardata_t S31,
                                                    it_lineardata_t S32) const {
#pragma omp parallel for schedule(static, (numEntries + NUM_THREADS - 1) / NUM_THREADS)
    for (int i = 0; i < numEntries; i++) {
        smartSubtractionCAPS(T1 + i, S11 + i, S12 + i);

        smartSubtractionCAPS(T2 + i, S21 + i, S22 + i);

        smartSubtractionCAPS(T3 + i, S31 + i, S32 + i);
    }
}

template <class Element>
void MatrixStrassen<Element>::tripleAddMatricesCAPS(int numEntries, it_lineardata_t T1, it_lineardata_t S11,
                                                    it_lineardata_t S12, it_lineardata_t T2, it_lineardata_t S21,
                                                    it_lineardata_t S22, it_lineardata_t T3, it_lineardata_t S31,
                                                    it_lineardata_t S32) const {
#pragma omp parallel for schedule(static, (numEntries + NUM_THREADS - 1) / NUM_THREADS)
    for (int i = 0; i < numEntries; i++) {
        smartAdditionCAPS(T1 + i, S11 + i, S12 + i);

        smartAdditionCAPS(T2 + i, S21 + i, S22 + i);

        smartAdditionCAPS(T3 + i, S31 + i, S32 + i);
    }
}

template <class Element>
void MatrixStrassen<Element>::addSubMatricesCAPS(int numEntries, it_lineardata_t T1, it_lineardata_t S11,
                                                 it_lineardata_t S12, it_lineardata_t T2, it_lineardata_t S21,
                                                 it_lineardata_t S22) const {
#pragma omp parallel for schedule(static, (numEntries + NUM_THREADS - 1) / NUM_THREADS)
    for (int i = 0; i < numEntries; i++) {
        smartAdditionCAPS(T1 + i, S11 + i, S12 + i);

        smartSubtractionCAPS(T2 + i, S21 + i, S22 + i);
    }
    // COUNTERS stopTimer(TIMER_ADD);
}

template <class Element>
void MatrixStrassen<Element>::strassenDFSCAPS(it_lineardata_t A, it_lineardata_t B, it_lineardata_t C,
                                              MatDescriptor desc, it_lineardata_t workPassThrough) const {
#ifdef SANITY_CHECKS
    verifyDescriptor(desc);
#endif
    MatDescriptor halfDesc = desc;
    halfDesc.lda /= 2;
    halfDesc.nrec -= 1;
#ifdef SANITY_CHECKS
    verifyDescriptor(halfDesc);
#endif

    // submatrices; these are described by halfDesc;
    size_t numEntriesHalf = numEntriesPerProc(halfDesc);

    // printf("numEntriesHalf = %lld\n",numEntriesHalf);
    it_lineardata_t A11 = A;
    it_lineardata_t A21 = A + numEntriesHalf;
    it_lineardata_t A12 = A + 2 * numEntriesHalf;
    it_lineardata_t A22 = A + 3 * numEntriesHalf;
    it_lineardata_t B11 = B;
    it_lineardata_t B21 = B + numEntriesHalf;
    it_lineardata_t B12 = B + 2 * numEntriesHalf;
    it_lineardata_t B22 = B + 3 * numEntriesHalf;
    it_lineardata_t C11 = C;
    it_lineardata_t C21 = C + numEntriesHalf;
    it_lineardata_t C12 = C + 2 * numEntriesHalf;
    it_lineardata_t C22 = C + 3 * numEntriesHalf;

    lineardata_t R2data;
    lineardata_t R5data;

    for (size_t elem = 0; elem < numEntriesHalf; ++elem) {
        R2data.push_back(allocZero());

        R5data.push_back(allocZero());
    }

    // six registers.  halfDesc is the descriptor for these
    it_lineardata_t R1 = C21;
    it_lineardata_t R2 = R2data.begin();
    it_lineardata_t R3 = C11;
    it_lineardata_t R4 = C22;
    it_lineardata_t R5 = R5data.begin();
    it_lineardata_t R6 = C12;

    it_lineardata_t S5 = R1;
    it_lineardata_t S3 = R2;
    it_lineardata_t S4 = R3;
    tripleSubMatricesCAPS(numEntriesHalf, S5, B22, B12, S3, B12, B11, S4, B22, S3);
    it_lineardata_t T5 = R4;
    it_lineardata_t T3 = R6;  // was R1
    addSubMatricesCAPS(numEntriesHalf, T3, A21, A22, T5, A11, A21);
    it_lineardata_t Q5 = R5;
    multiplyInternalCAPS(T5, S5, Q5, halfDesc, workPassThrough);
    it_lineardata_t Q3 = R4;
    multiplyInternalCAPS(T3, S3, Q3, halfDesc, workPassThrough);
    it_lineardata_t T4 = R6;
    subMatricesCAPS(numEntriesHalf, T4, T3, A11);
    it_lineardata_t Q4 = R2;
    multiplyInternalCAPS(T4, S4, Q4, halfDesc, workPassThrough);
    it_lineardata_t T6 = R6;
    subMatricesCAPS(numEntriesHalf, T6, A12, T4);
    it_lineardata_t S7 = R3;
    subMatricesCAPS(numEntriesHalf, S7, S4, B21);
    it_lineardata_t Q7 = R1;
    multiplyInternalCAPS(A22, S7, Q7, halfDesc, workPassThrough);
    it_lineardata_t Q1 = R3;
    multiplyInternalCAPS(A11, B11, Q1, halfDesc, workPassThrough);
    it_lineardata_t U1 = R2;
    it_lineardata_t U2 = R5;
    it_lineardata_t U3 = R2;
    tripleAddMatricesCAPS(numEntriesHalf, U1, Q1, Q4, U2, U1, Q5, U3, U1, Q3);
    addSubMatricesCAPS(numEntriesHalf, C22, U2, Q3, C21, U2, Q7);
    it_lineardata_t Q2 = R5;
    multiplyInternalCAPS(A12, B21, Q2, halfDesc, workPassThrough);
    addMatricesCAPS(numEntriesHalf, C11, Q1, Q2);
    it_lineardata_t Q6 = R5;
    multiplyInternalCAPS(T6, B22, Q6, halfDesc, workPassThrough);
    addMatricesCAPS(numEntriesHalf, C12, U3, Q6);

    R2data.clear();
    R5data.clear();
}

template <class Element>
void MatrixStrassen<Element>::block_multiplyCAPS(it_lineardata_t A, it_lineardata_t B, it_lineardata_t C,
                                                 MatDescriptor d, it_lineardata_t work) const {
#pragma omp parallel for
    for (int32_t row = 0; row < d.lda; row++) {
        Element Aval;
        Element Bval;
        for (int32_t col = 0; col < d.lda; col++) {
            Element temp;
            int uninitializedTemp = 1;

            for (int32_t i = 0; i < d.lda; i++) {
                it_lineardata_t Aelem = A + row + i * d.lda;
                it_lineardata_t Belem = B + i + d.lda * col;

                if (*Aelem == zeroUniquePtr) {
                    continue;
                }
                if (*Belem == zeroUniquePtr) {
                    continue;
                }
                Aval = *(A + row + i * d.lda);  // **(A + d.lda * row + i);
                Bval = *(B + i + d.lda * col);  //  **(B + i * d.lda + col);
                numMult++;
                if (uninitializedTemp == 1) {
                    uninitializedTemp = 0;
                    temp              = (Aval * Bval);
                }
                else {
                    numAdd++;
                    temp += (Aval * Bval);
                }
            }

            if (uninitializedTemp == 1) {  // Because of nulls, temp never got value.
                *(C + row + d.lda * col) = 0;
            }
            else {
                *(C + row + d.lda * col) = temp;
            }
        }
    }
}

// get the communicators used for gather and scatter when collapsing/expanding a
// column or a row

template <class Element>
void MatrixStrassen<Element>::sendBlockCAPS(/*MPI_Comm comm,*/ int rank, int target, it_lineardata_t O, int bs,
                                            int source, it_lineardata_t I, int ldi) const {
    if (source == target) {
        if (rank == source) {
            for (int c = 0; c < bs; c++) {
                for (int i = 0; i < bs; i++) {
                    *O = std::move(*I);
                    O++;  // New
                    I++;
                }

                I += ldi - bs;  // New
            }
        }
    }
}

template <class Element>
void MatrixStrassen<Element>::receiveBlockCAPS(int rank, int target, it_lineardata_t O, int bs, int source,
                                               it_lineardata_t I, int ldo) const {
    if (source == target) {
        if (rank == source) {
            for (int c = 0; c < bs; c++) {
                for (int i = 0; i < bs; i++) {
                    *O = std::move(*I);

                    I++;
                    O++;  // New
                }

                O += ldo - bs;  // New
            }
        }
    }
}

template <class Element>
void MatrixStrassen<Element>::distributeFrom1ProcRecCAPS(MatDescriptor desc, it_lineardata_t O, it_lineardata_t I,
                                                         int ldi) const {
    if (desc.nrec == 0) {  // base case; put the matrix block-cyclic layout
        // MPI_Comm comm = getComm();
        int rank      = getRank();
        int bs        = desc.bs;
        int numBlocks = desc.lda / bs;
        assert(numBlocks % desc.nprocr == 0);
        assert(numBlocks % desc.nprocc == 0);
        assert((numBlocks / desc.nprocr) % desc.nproc_summa == 0);
        int nBlocksPerProcRow = numBlocks / desc.nprocr / desc.nproc_summa;
        int nBlocksPerProcCol = numBlocks / desc.nprocc;
        int nBlocksPerBase    = numBlocks / desc.nproc_summa;

        for (int sp = 0; sp < desc.nproc_summa; sp++) {
            for (int i = 0; i < nBlocksPerProcRow; i++) {
                for (int rproc = 0; rproc < desc.nprocr; rproc++) {
                    for (int j = 0; j < nBlocksPerProcCol; j++) {
                        for (int cproc = 0; cproc < desc.nprocc; cproc++) {
                            int source = 0;
                            int target = cproc + rproc * desc.nprocc + sp * base;
                            // row and column of the beginning of the block in I
                            int row          = j * (desc.nprocc * bs) + cproc * bs;
                            int col          = i * (desc.nprocr * bs) + rproc * bs + sp * nBlocksPerBase * bs;
                            int offsetSource = row + col * ldi;
                            int offsetTarget = (j + i * nBlocksPerProcCol) * bs * bs;
                            sendBlockCAPS(/*comm,*/ rank, target, O + offsetTarget, bs, source, I + offsetSource, ldi);
                        }
                    }
                }
            }
        }
    }
    else {  // recursively call on each of four submatrices
        desc.nrec -= 1;
        desc.lda /= 2;
        int entriesPerQuarter = numEntriesPerProc(desc);
        // top left
        distributeFrom1ProcRecCAPS(desc, O, I, ldi);
        // bottom left
        distributeFrom1ProcRecCAPS(desc, O + entriesPerQuarter, I + desc.lda, ldi);
        // top right
        distributeFrom1ProcRecCAPS(desc, O + 2 * entriesPerQuarter, I + desc.lda * ldi, ldi);
        // bottom right
        distributeFrom1ProcRecCAPS(desc, O + 3 * entriesPerQuarter, I + desc.lda * ldi + desc.lda, ldi);
    }
}

template <class Element>
void MatrixStrassen<Element>::distributeFrom1ProcCAPS(MatDescriptor desc, it_lineardata_t O, it_lineardata_t I) const {
    distributeFrom1ProcRecCAPS(desc, O, I, desc.lda);
}

template <class Element>
void MatrixStrassen<Element>::collectTo1ProcRecCAPS(MatDescriptor desc, it_lineardata_t O, it_lineardata_t I,
                                                    int ldo) const {
    if (desc.nrec == 0) {  // base case; put the matrix block-cyclic layout
        // MPI_Comm comm = getComm();
        int rank      = getRank();
        int bs        = desc.bs;
        int numBlocks = desc.lda / bs;
        assert(numBlocks % desc.nprocr == 0);
        assert(numBlocks % desc.nprocc == 0);
        assert((numBlocks / desc.nprocr) % desc.nproc_summa == 0);
        int nBlocksPerProcRow = numBlocks / desc.nprocr / desc.nproc_summa;
        int nBlocksPerProcCol = numBlocks / desc.nprocc;
        int nBlocksPerBase    = numBlocks / desc.nproc_summa;
        for (int sp = 0; sp < desc.nproc_summa; sp++) {
            for (int i = 0; i < nBlocksPerProcRow; i++) {
                for (int rproc = 0; rproc < desc.nprocr; rproc++) {
                    for (int j = 0; j < nBlocksPerProcCol; j++) {
                        for (int cproc = 0; cproc < desc.nprocc; cproc++) {
                            int target = 0;
                            int source = cproc + rproc * desc.nprocc + sp * base;
                            // row and column of the beginning of the block in I
                            int row          = j * (desc.nprocc * bs) + cproc * bs;
                            int col          = i * (desc.nprocr * bs) + rproc * bs + sp * nBlocksPerBase * bs;
                            int offsetTarget = row + col * ldo;
                            int offsetSource = (j + i * nBlocksPerProcCol) * bs * bs;
                            receiveBlockCAPS(/*comm,*/ rank, target, O + offsetTarget, bs, source, I + offsetSource,
                                             ldo);
                        }
                    }
                }
            }
        }
    }
    else {  // recursively call on each of four submatrices
        desc.nrec -= 1;
        desc.lda /= 2;
        int entriesPerQuarter = numEntriesPerProc(desc);
        // top left
        collectTo1ProcRecCAPS(desc, O, I, ldo);
        // bottom left
        collectTo1ProcRecCAPS(desc, O + desc.lda, I + entriesPerQuarter, ldo);
        // top right
        collectTo1ProcRecCAPS(desc, O + desc.lda * ldo, I + 2 * entriesPerQuarter, ldo);
        // bottom right
        collectTo1ProcRecCAPS(desc, O + desc.lda * ldo + desc.lda, I + 3 * entriesPerQuarter, ldo);
    }
}

template <class Element>
void MatrixStrassen<Element>::collectTo1ProcCAPS(MatDescriptor desc, it_lineardata_t O, it_lineardata_t I) const {
    collectTo1ProcRecCAPS(desc, O, I, desc.lda);
}

template <class Element>
void MatrixStrassen<Element>::getData(const data_t& Adata, const data_t& Bdata, const data_t& Cdata, int row, int inner,
                                      int col) const {
    printf("Adata[3][0] = %d\n", static_cast<int>(*Adata[3][0]));
    printf("Bdata[3][0] = %d\n", static_cast<int>(*Bdata[3][0]));
    printf("Cdata[3][0] = %d\n", static_cast<int>(*Cdata[3][0]));
    printf("row = %d inner = %d col = %d\n", row, inner, col);

#pragma omp parallel for
    for (int i = 0; i < row; i++) {
        for (int k = 0; k < inner; k++) {
            for (int j = 0; j < col; j++) {
                *(Cdata[i][j]) += *(Adata[i][k]) * *(Bdata[k][j]);
            }
        }
    }
}

/*
 * Multiply the matrix by a vector of 1's, which is the same as adding all the
 * elements in the row together.
 * Return a vector that is a rows x 1 matrix.
 */
template <class Element>
MatrixStrassen<Element> MatrixStrassen<Element>::MultByUnityVector() const {
    MatrixStrassen<Element> result(allocZero, rows, 1);

#pragma omp parallel for
    for (int32_t row = 0; row < result.rows; ++row) {
        for (int32_t col = 0; col < cols; ++col) {
            *result.data[row][0] += *data[row][col];
        }
    }

    return result;
}

/*
 * Multiply the matrix by a vector of random 1's and 0's, which is the same as
 * adding select elements in each row together. Return a vector that is a rows x
 * 1 matrix.
 */
template <class Element>
MatrixStrassen<Element> MatrixStrassen<Element>::MultByRandomVector(std::vector<int> ranvec) const {
    MatrixStrassen<Element> result(allocZero, rows, 1);
#pragma omp parallel for
    for (int32_t row = 0; row < result.rows; ++row) {
        for (int32_t col = 0; col < cols; ++col) {
            if (ranvec[col] == 1)
                *result.data[row][0] += *data[row][col];
        }
    }
    return result;
}

template <class Element>
int MatrixStrassen<Element>::getRank() const {
    return rank;
}

template <class Element>
void MatrixStrassen<Element>::verifyDescriptor(MatDescriptor desc) {
    assert(desc.lda % ((1 << desc.nrec) * desc.bs * desc.nprocr) == 0);
    assert(desc.lda % ((1 << desc.nrec) * desc.bs * desc.nprocc) == 0);
    assert(desc.nprocr * desc.nprocc == desc.nproc);
}

template <class Element>
long long MatrixStrassen<Element>::numEntriesPerProc(MatDescriptor desc) const {  // NOLINT
    long long lda = desc.lda;                                                     // NOLINT
    return ((lda * lda) / desc.nproc / desc.nproc_summa);
}

}  // namespace lbcrypto

#endif
