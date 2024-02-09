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
  implementation of the power-of-2 fields
 */

#ifndef LBCRYPTO_INC_LATTICE_FIELD2N_IMPL_H
#define LBCRYPTO_INC_LATTICE_FIELD2N_IMPL_H

#include "lattice/field2n.h"
#include "lattice/lat-hal.h"

#include "math/dftransform.h"
#include "math/math-hal.h"

#include "utils/exception.h"
#include "utils/inttypes.h"

#include <complex>
#include <vector>

namespace lbcrypto {

// Constructor from ring element
Field2n::Field2n(const Poly& element) : format(Format::COEFFICIENT) {
    if (element.GetFormat() != Format::COEFFICIENT)
        OPENFHE_THROW("Poly not in Format::COEFFICIENT representation");
    size_t size = element.GetLength();
    this->std::vector<std::complex<double>>::reserve(size);
    // the value of element[i] is usually small - so a 64-bit integer is more
    // than enough this approach is much faster than BigInteger::ConvertToDouble
    BigInteger negativeThreshold(element.GetModulus() / Poly::Integer(2));
    for (size_t i = 0; i < size; ++i) {
        if (element[i] > negativeThreshold)
            this->std::vector<std::complex<double>>::push_back(
                static_cast<double>(static_cast<int64_t>(-1 * (element.GetModulus() - element[i]).ConvertToInt())));
        else
            this->std::vector<std::complex<double>>::push_back(
                static_cast<double>(static_cast<int64_t>(element[i].ConvertToInt())));
    }
}

// Constructor from ring element
Field2n::Field2n(const NativePoly& element) : format(Format::COEFFICIENT) {
    if (element.GetFormat() != Format::COEFFICIENT)
        OPENFHE_THROW("Poly not in Format::COEFFICIENT representation");
    size_t size = element.GetLength();
    this->std::vector<std::complex<double>>::reserve(size);
    // the value of element[i] is usually small - so a 64-bit integer is more
    // than enough this approach is much faster than BigInteger::ConvertToDouble
    NativeInteger negativeThreshold(element.GetModulus() / 2);
    for (size_t i = 0; i < size; ++i) {
        if (element[i] > negativeThreshold)
            this->std::vector<std::complex<double>>::push_back(
                static_cast<double>(static_cast<int64_t>(-1 * (element.GetModulus() - element[i]).ConvertToInt())));
        else
            this->std::vector<std::complex<double>>::push_back(
                static_cast<double>(static_cast<int64_t>(element[i].ConvertToInt())));
    }
}

// Constructor from DCRTPoly ring element
Field2n::Field2n(const DCRTPoly& DCRTelement) : format(Format::COEFFICIENT) {
    if (DCRTelement.GetFormat() != Format::COEFFICIENT)
        OPENFHE_THROW("DCRTPoly not in Format::COEFFICIENT representation");
    // the value of element[i] is usually small - so a 64-bit integer is more
    // than enough Also it is assumed that the prime moduli are large enough (60
    // bits or more) - so the CRT interpolation is not needed this approach is
    // much faster than BigInteger::ConvertToDouble
    typename DCRTPoly::PolyType element = DCRTelement.GetElementAtIndex(0);
    size_t size                         = element.GetLength();
    this->std::vector<std::complex<double>>::reserve(size);
    NativeInteger negativeThreshold(element.GetModulus() / 2);
    for (size_t i = 0; i < size; ++i) {
        if (element[i] > negativeThreshold)
            this->std::vector<std::complex<double>>::push_back(
                static_cast<double>(static_cast<int64_t>(-1 * (element.GetModulus() - element[i]).ConvertToInt())));
        else
            this->std::vector<std::complex<double>>::push_back(
                static_cast<double>(static_cast<int64_t>(element[i].ConvertToInt())));
    }
}

// Constructor from a ring element matrix
Field2n::Field2n(const Matrix<int64_t>& element) : format(Format::COEFFICIENT) {
    size_t size = element.GetRows();
    this->std::vector<std::complex<double>>::reserve(size);
    for (size_t i = 0; i < size; ++i)
        this->std::vector<std::complex<double>>::push_back(element(i, 0));
}

// Inverse operation for the field elements
Field2n Field2n::Inverse() const {
    if (format == Format::COEFFICIENT)
        OPENFHE_THROW("Polynomial not in Format::EVALUATION representation");
    Field2n inverse(*this);
    for (size_t i = 0; i < inverse.size(); ++i) {
        auto real{inverse[i].real()};
        auto imag{inverse[i].imag()};
        auto quotient{real * real + imag * imag};
        inverse[i] = std::complex<double>(real / quotient, -imag / quotient);
    }
    return inverse;
}

// Addition operation for field elements
Field2n Field2n::Plus(const Field2n& rhs) const {
    if (format != rhs.GetFormat())
        OPENFHE_THROW("Operands are not in the same format");
    Field2n sum(*this);
    for (size_t i = 0; i < rhs.size(); ++i)
        sum[i] += rhs[i];
    return sum;
}

// Scalar addition operation for field elements
Field2n Field2n::Plus(double scalar) const {
    if (format != Format::COEFFICIENT)
        OPENFHE_THROW(
            "Field2n scalar addition is currently supported only for "
            "Format::COEFFICIENT representation");
    Field2n sum(*this);
    sum.at(0) += scalar;
    return sum;
}

// Substraction operation for field elements
Field2n Field2n::Minus(const Field2n& rhs) const {
    if (format != rhs.GetFormat())
        OPENFHE_THROW("Operands are not in the same format");
    Field2n difference(*this);
    for (size_t i = 0; i < rhs.size(); ++i)
        difference[i] -= rhs[i];
    return difference;
}

// Multiplication operation for field elements
Field2n Field2n::Times(const Field2n& rhs) const {
    if (format != Format::EVALUATION && rhs.GetFormat() != Format::EVALUATION)
        OPENFHE_THROW(
            "At least one of the polynomials is not in "
            "Format::EVALUATION representation");
    Field2n result(*this);
    for (size_t i = 0; i < rhs.size(); ++i)
        result[i] *= rhs[i];
    return result;
}

// Right shift operation for the field element
Field2n Field2n::ShiftRight() {
    if (format != Format::COEFFICIENT)
        OPENFHE_THROW("Polynomial not in Format::COEFFICIENT representation");
    Field2n result(*this);
    size_t i = this->std::vector<std::complex<double>>::size() - 1;
    auto tmp = std::complex<double>(-1., 0.) * result[i];
    for (; i != 0; --i)
        result[i] = result[i - 1];
    result[i] = tmp;
    return result;
}

// Performs an automorphism transform operation and returns the result.
Field2n Field2n::AutomorphismTransform(size_t i) const {
    if (format != Format::EVALUATION)
        OPENFHE_THROW(
            "Field2n Automorphism is only implemented for "
            "Format::EVALUATION format");
    if (i % 2 == 0)
        OPENFHE_THROW("automorphism index should be odd\n");
    Field2n result(*this);
    size_t m = this->std::vector<std::complex<double>>::size() * 2;
    for (size_t j = 1; j < m; j += 2) {
        size_t idx{(j * i) % m};
        result[(idx + 1) / 2 - 1] = this->std::vector<std::complex<double>>::operator[]((j + 1) / 2 - 1);
    }
    return result;
}

// Transpose operation defined in section VI.B4 of
// https://eprint.iacr.org/2017/844.pdf
Field2n Field2n::Transpose() const {
    size_t size = this->std::vector<std::complex<double>>::size();
    if (format != Format::COEFFICIENT)
        return AutomorphismTransform(size * 2 - 1);
    constexpr auto negone = std::complex<double>(-1., 0.);
    Field2n transpose(size, Format::COEFFICIENT, true);
    transpose[0] = this->std::vector<std::complex<double>>::operator[](0);
    for (size_t i = 1; i < size; ++i)
        transpose[i] = negone * this->std::vector<std::complex<double>>::operator[](size - i);
    return transpose;
}

// Function for extracting odd factors of the field element
Field2n Field2n::ExtractOdd() const {
    if (format != Format::COEFFICIENT)
        OPENFHE_THROW("Polynomial not in Format::COEFFICIENT representation");
    size_t size = this->std::vector<std::complex<double>>::size();
    Field2n odds(size / 2, Format::COEFFICIENT, true);
    for (size_t i = 0; i < odds.size(); ++i)
        odds[i] = this->std::vector<std::complex<double>>::operator[](1 + 2 * i);
    return odds;
}

// Function for extracting even factors of the field element
Field2n Field2n::ExtractEven() const {
    if (format != Format::COEFFICIENT)
        OPENFHE_THROW("Polynomial not in Format::COEFFICIENT representation");
    size_t size = this->std::vector<std::complex<double>>::size();
    Field2n evens(size / 2, Format::COEFFICIENT, true);
    for (size_t i = 0; i < evens.size(); ++i)
        evens[i] = this->std::vector<std::complex<double>>::operator[](0 + 2 * i);
    return evens;
}

// Permutation operation defined in Algorithm 4 of
// https://eprint.iacr.org/2017/844.pdf
Field2n Field2n::Permute() const {
    if (format != Format::COEFFICIENT)
        OPENFHE_THROW("Polynomial not in Format::COEFFICIENT representation");
    size_t size{this->std::vector<std::complex<double>>::size()};
    Field2n permuted(size, Format::COEFFICIENT, true);
    size_t evenPtr{0}, oddPtr{size / 2};
    for (size_t i = 0; i < size;) {
        permuted[evenPtr++] = this->std::vector<std::complex<double>>::operator[](i++);
        permuted[oddPtr++]  = this->std::vector<std::complex<double>>::operator[](i++);
    }
    return permuted;
}

// Inverse operation for permutation operation defined in
// Algorithm 4 of https://eprint.iacr.org/2017/844.pdf
Field2n Field2n::InversePermute() const {
    if (format != Format::COEFFICIENT)
        OPENFHE_THROW("Polynomial not in Format::COEFFICIENT representation");
    size_t size{this->std::vector<std::complex<double>>::size()};
    Field2n invpermuted(size, Format::COEFFICIENT, true);
    size_t evenPtr{0}, oddPtr{size / 2};
    for (size_t i = 0; i < size;) {
        invpermuted[i++] = this->std::vector<std::complex<double>>::operator[](evenPtr++);
        invpermuted[i++] = this->std::vector<std::complex<double>>::operator[](oddPtr++);
    }
    return invpermuted;
}

// Operation for scalar multiplication
Field2n Field2n::ScalarMult(double d) {
    size_t size{this->std::vector<std::complex<double>>::size()};
    Field2n scaled(size, format, true);
    for (size_t i = 0; i < size; ++i)
        scaled[i] = d * this->std::vector<std::complex<double>>::operator[](i);
    return scaled;
}

// Method for switching format of the field elements
void Field2n::SwitchFormat() {
    auto r = (format == Format::COEFFICIENT) ? DiscreteFourierTransform::ForwardTransform(*this) :
                                               DiscreteFourierTransform::InverseTransform(*this);
    format = (format == Format::COEFFICIENT) ? Format::EVALUATION : Format::COEFFICIENT;
    for (size_t i = 0; i < r.size(); ++i)
        this->std::vector<std::complex<double>>::operator[](i) = r[i];
}

}  // namespace lbcrypto

#endif
