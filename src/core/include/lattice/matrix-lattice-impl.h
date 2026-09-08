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
  matrix class implementations and type specific implementations
 */

#ifndef LBCRYPTO_INC_LATTICE_MATRIX_IMPL_H
#define LBCRYPTO_INC_LATTICE_MATRIX_IMPL_H

#include "math/matrix-impl.h"
#include "math/matrix-utils.h"

#include "utils/parallel.h"

#include <memory>

// this is the implementation of matrixes of things that are in core
// and that need template specializations

namespace lbcrypto {

template <typename Element>
Matrix<typename Element::Integer> Rotate(Matrix<Element> const& inMat) {
    Matrix<Element> mat(inMat);
    mat.SetFormat(Format::COEFFICIENT);
    size_t n                                 = mat(0, 0).GetLength();
    typename Element::Integer const& modulus = mat(0, 0).GetModulus();
    size_t rows                              = mat.GetRows() * n;
    size_t cols                              = mat.GetCols() * n;
    Matrix<typename Element::Integer> result(Element::Integer::Allocator, rows, cols);
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
template <typename Element>
Matrix<typename Element::Vector> RotateVecResult(Matrix<Element> const& inMat) {
    Matrix<Element> mat(inMat);
    mat.SetFormat(Format::COEFFICIENT);
    size_t n                                 = mat(0, 0).GetLength();
    typename Element::Integer const& modulus = mat(0, 0).GetModulus();
    typename Element::Vector zero(1, modulus);
    size_t rows                = mat.GetRows() * n;
    size_t cols                = mat.GetCols() * n;
    auto singleElemBinVecAlloc = [=]() {
        return typename Element::Vector(1, modulus);
    };
    Matrix<typename Element::Vector> result(singleElemBinVecAlloc, rows, cols);
    for (size_t row = 0; row < mat.GetRows(); ++row) {
        for (size_t col = 0; col < mat.GetCols(); ++col) {
            for (size_t rotRow = 0; rotRow < n; ++rotRow) {
                for (size_t rotCol = 0; rotCol < n; ++rotCol) {
                    typename Element::Vector& elem = result(row * n + rotRow, col * n + rotCol);
                    elem.at(0)                     = mat(row, col).GetValues().at((rotRow - rotCol + n) % n);
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

template <typename Element>
void Matrix<Element>::SetFormat(Format format) {
    if (data[0][0].GetFormat() != format)
        this->SwitchFormat();
}

template <typename Element>
void Matrix<Element>::SwitchFormat() {
    if (rows == 1) {
        // TODO: figure out why this is causing a segfault with GCC10
        // #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(cols))
        for (size_t col = 0; col < cols; ++col) {
            data[0][col].SwitchFormat();
        }
    }
    else {
        // #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(rows))
        for (size_t row = 0; row < rows; ++row) {
            for (size_t col = 0; col < cols; ++col) {
                data[row][col].SwitchFormat();
            }
        }
    }
}

//  Convert from Z_q to (-q/2, q/2]
template <typename T>
Matrix<int32_t> ConvertToInt32(const Matrix<T>& input, const T& modulus) {
    size_t rows = input.GetRows();
    size_t cols = input.GetCols();
    Matrix<int32_t> result([]() { return 0; }, rows, cols);
    const CenteredToInt32ConverterImpl<T> converter(modulus);
    for (size_t i = 0; i < rows; ++i) {
        const auto& inputRow = input.GetData()[i];
        for (size_t j = 0; j < cols; ++j) {
            result(i, j) = converter.Convert(inputRow[j]);
        }
    }
    return result;
}

template <typename V>
Matrix<int32_t> ConvertToInt32(const Matrix<V>& input, const typename V::Integer& modulus) {
    size_t rows = input.GetRows();
    size_t cols = input.GetCols();
    Matrix<int32_t> result([]() { return 0; }, rows, cols);
    const CenteredToInt32ConverterImpl<typename V::Integer> converter(modulus);
    for (size_t i = 0; i < rows; ++i) {
        const auto& inputRow = input.GetData()[i];
        for (size_t j = 0; j < cols; ++j) {
            result(i, j) = converter.Convert(inputRow[j][0]);
        }
    }
    return result;
}

}  // namespace lbcrypto

#endif
