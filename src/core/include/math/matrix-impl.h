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
  This code provide a templated matrix implementation
 */

#ifndef LBCRYPTO_INC_MATH_MATRIX_IMP_H
#define LBCRYPTO_INC_MATH_MATRIX_IMP_H

#include "math/matrix.h"

#include "utils/exception.h"
#include "utils/parallel.h"

#include <utility>
#include <vector>

namespace lbcrypto {

template <class Element>
Matrix<Element>::Matrix(alloc_func allocZero, size_t rows, size_t cols, alloc_func allocGen)
    : data(), rows(rows), cols(cols), allocZero(allocZero) {
    data.resize(rows);
    for (auto row = data.begin(); row != data.end(); ++row) {
        for (size_t col = 0; col < cols; ++col) {
            row->push_back(allocGen());
        }
    }
}

template <class Element>
Matrix<Element>& Matrix<Element>::operator=(const Matrix<Element>& other) {
    rows = other.rows;
    cols = other.cols;
    deepCopyData(other.data);
    return *this;
}

template <class Element>
Matrix<Element>& Matrix<Element>::Fill(const Element& val) {
    for (size_t row = 0; row < rows; ++row) {
        for (size_t col = 0; col < cols; ++col) {
            data[row][col] = val;
        }
    }
    return *this;
}

template <class Element>
Matrix<Element> Matrix<Element>::Mult(Matrix<Element> const& other) const {
    // NUM_THREADS = omp_get_max_threads();

    if (cols != other.rows) {
        OPENFHE_THROW(math_error, "incompatible matrix multiplication");
    }
    Matrix<Element> result(allocZero, rows, other.cols);
    if (rows == 1) {
#pragma omp parallel for
        for (size_t col = 0; col < result.cols; ++col) {
            for (size_t i = 0; i < cols; ++i) {
                result.data[0][col] += data[0][i] * other.data[i][col];
            }
        }
    }
    else {
#pragma omp parallel for
        for (size_t row = 0; row < result.rows; ++row) {
            for (size_t i = 0; i < cols; ++i) {
                for (size_t col = 0; col < result.cols; ++col) {
                    result.data[row][col] += data[row][i] * other.data[i][col];
                }
            }
        }
    }
    return result;
}

template <class Element>
Matrix<Element>& Matrix<Element>::operator+=(Matrix<Element> const& other) {
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
Matrix<Element>& Matrix<Element>::operator-=(Matrix<Element> const& other) {
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
Matrix<Element> Matrix<Element>::Transpose() const {
    Matrix<Element> result(allocZero, cols, rows);
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
void Matrix<Element>::Determinant(Element* determinant) const {
    if (rows != cols)
        OPENFHE_THROW(math_error, "Supported only for square matrix");
    // auto determinant = *allocZero();
    if (rows < 1)
        OPENFHE_THROW(math_error, "Dimension should be at least one");

    if (rows == 1) {
        *determinant = data[0][0];
    }
    else if (rows == 2) {
        *determinant = data[0][0] * (data[1][1]) - data[1][0] * (data[0][1]);
    }
    else {
        size_t j1, j2;
        size_t n = rows;

        Matrix<Element> result(allocZero, rows - 1, cols - 1);

        // for each column in sub-matrix
        for (j1 = 0; j1 < n; j1++) {
            // build sub-matrix with minor elements excluded
            for (size_t i = 1; i < n; i++) {
                j2 = 0;  // start at first sum-matrix column position
                // loop to copy source matrix less one column
                for (size_t j = 0; j < n; j++) {
                    if (j == j1)
                        continue;  // don't copy the minor column element

                    // copy source element into new sub-matrix i-1 because new sub-matrix
                    // is one row (and column) smaller with excluded minors
                    result.data[i - 1][j2] = data[i][j];
                    j2++;  // move to next sub-matrix column position
                }
            }

            auto tempDeterminant(allocZero());
            result.Determinant(&tempDeterminant);

            if (j1 % 2 == 0)
                *determinant = *determinant + (data[0][j1]) * tempDeterminant;
            else
                *determinant = *determinant - (data[0][j1]) * tempDeterminant;

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
Matrix<Element> Matrix<Element>::CofactorMatrix() const {
    if (rows != cols)
        OPENFHE_THROW(not_available_error, "Supported only for square matrix");

    size_t ii, jj, iNew, jNew;

    size_t n = rows;

    Matrix<Element> result(allocZero, rows, cols);

    for (size_t j = 0; j < n; j++) {
        for (size_t i = 0; i < n; i++) {
            Matrix<Element> c(allocZero, rows - 1, cols - 1);

            /* Form the adjoint a_ij */
            iNew = 0;
            for (ii = 0; ii < n; ii++) {
                if (ii == i)
                    continue;
                jNew = 0;
                for (jj = 0; jj < n; jj++) {
                    if (jj == j)
                        continue;
                    c.data[iNew][jNew] = data[ii][jj];
                    jNew++;
                }
                iNew++;
            }

            /* Calculate the determinant */
            Element determinant(allocZero());
            c.Determinant(&determinant);
            // TODO: This will be set to zero if Element is BigInteger
            Element negDeterminant = -determinant;

            /* Fill in the elements of the cofactor */
            if ((i + j) % 2 == 0)
                result.data[i][j] = determinant;
            else
                result.data[i][j] = negDeterminant;
        }
    }

    return result;
}

//  add rows to bottom of the matrix
template <class Element>
Matrix<Element>& Matrix<Element>::VStack(Matrix<Element> const& other) {
    if (cols != other.cols) {
        OPENFHE_THROW(math_error, "VStack rows not equal size");
    }
    for (size_t row = 0; row < other.rows; ++row) {
        data_row_t rowElems;
        for (auto elem = other.data[row].begin(); elem != other.data[row].end(); ++elem) {
            rowElems.push_back(*elem);
        }
        data.push_back(std::move(rowElems));
    }
    rows += other.rows;
    return *this;
}

//  add cols to right of the matrix
template <class Element>
inline Matrix<Element>& Matrix<Element>::HStack(Matrix<Element> const& other) {
    if (rows != other.rows) {
        OPENFHE_THROW(math_error, "HStack cols not equal size");
    }
    for (size_t row = 0; row < rows; ++row) {
        data_row_t rowElems;
        for (auto& elem : other.data[row]) {
            rowElems.push_back(elem);
        }
        MoveAppend(data[row], rowElems);
    }
    cols += other.cols;
    return *this;
}

// template<class Element>
// void Matrix<Element>::deepCopyData(data_t const& src) {
//    data.clear();
//    data.resize(src.size());
//    for (size_t row = 0; row < src.size(); ++row) {
//        for (auto elem = src[row].begin(); elem != src[row].end(); ++elem) {
//            data[row].push_back(*elem);
//        }
//    }
//}

/*
 * Multiply the matrix by a vector of 1's, which is the same as adding all the
 * elements in the row together.
 * Return a vector that is a rows x 1 matrix.
 */
template <class Element>
Matrix<Element> Matrix<Element>::MultByUnityVector() const {
    Matrix<Element> result(allocZero, rows, 1);

#pragma omp parallel for
    for (size_t row = 0; row < result.rows; ++row) {
        for (size_t col = 0; col < cols; ++col) {
            result.data[row][0] += data[row][col];
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
Matrix<Element> Matrix<Element>::MultByRandomVector(std::vector<int> ranvec) const {
    Matrix<Element> result(allocZero, rows, 1);

#pragma omp parallel for
    for (size_t row = 0; row < result.rows; ++row) {
        for (size_t col = 0; col < cols; ++col) {
            if (ranvec[col] == 1)
                result.data[row][0] += data[row][col];
        }
    }
    return result;
}

}  // namespace lbcrypto

#endif
