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
#include "math/hal.h"

#include "utils/exception.h"
#include "utils/inttypes.h"

#include <complex>
#include <vector>

namespace lbcrypto {

// Constructor from ring element
Field2n::Field2n(const Poly& element) : format(Format::COEFFICIENT) {
    if (element.GetFormat() != Format::COEFFICIENT)
        OPENFHE_THROW(type_error, "Poly not in Format::COEFFICIENT representation");
    size_t size = element.GetLength();
    this->Field2n::reserve(size);
    // the value of element[i] is usually small - so a 64-bit integer is more
    // than enough this approach is much faster than BigInteger::ConvertToDouble
    BigInteger negativeThreshold(element.GetModulus() / Poly::Integer(2));
    for (size_t i = 0; i < size; ++i) {
        if (element[i] > negativeThreshold)
            this->Field2n::push_back(
                static_cast<double>(static_cast<int64_t>(-1 * (element.GetModulus() - element[i]).ConvertToInt())));
        else
            this->Field2n::push_back(static_cast<double>(static_cast<int64_t>(element[i].ConvertToInt())));
    }
}

// Constructor from ring element
Field2n::Field2n(const NativePoly& element) : format(Format::COEFFICIENT){
    if (element.GetFormat() != Format::COEFFICIENT)
        OPENFHE_THROW(type_error, "Poly not in Format::COEFFICIENT representation");
    size_t size = element.GetLength();
    this->Field2n::reserve(size);
    // the value of element[i] is usually small - so a 64-bit integer is more
    // than enough this approach is much faster than BigInteger::ConvertToDouble
    NativeInteger negativeThreshold(element.GetModulus() / 2);
    for (size_t i = 0; i < size; ++i) {
        if (element[i] > negativeThreshold)
            this->Field2n::push_back(
                static_cast<double>(static_cast<int64_t>(-1 * (element.GetModulus() - element[i]).ConvertToInt())));
        else
            this->Field2n::push_back(static_cast<double>(static_cast<int64_t>(element[i].ConvertToInt())));
    }
}

// Constructor from DCRTPoly ring element
Field2n::Field2n(const DCRTPoly& DCRTelement) : format(Format::COEFFICIENT) {
    if (DCRTelement.GetFormat() != Format::COEFFICIENT)
        OPENFHE_THROW(type_error, "DCRTPoly not in Format::COEFFICIENT representation");
    size_t size = element.GetLength();
    this->Field2n::reserve(size);
    // the value of element[i] is usually small - so a 64-bit integer is more
    // than enough Also it is assumed that the prime moduli are large enough (60
    // bits or more) - so the CRT interpolation is not needed this approach is
    // much faster than BigInteger::ConvertToDouble
    typename DCRTPoly::PolyType element = DCRTelement.GetElementAtIndex(0);
    NativeInteger negativeThreshold(element.GetModulus() / 2);
    for (size_t i = 0; i < size; ++i) {
        if (element[i] > negativeThreshold)
            this->Field2n::push_back(
                static_cast<double>(static_cast<int64_t>(-1 * (element.GetModulus() - element[i]).ConvertToInt())));
        else
            this->Field2n::push_back(static_cast<double>(static_cast<int64_t>(element[i].ConvertToInt())));
    }
}

// Constructor from a ring element matrix
Field2n::Field2n(const Matrix<int64_t>& element) : format(Format::COEFFICIENT) {
    size_t size = element.GetLength();
    this->Field2n::reserve(size);
    for (size_t i = 0; i < size; ++i)
        this->Field2n::push_back(element(i, 0));
}

// Inverse operation for the field elements
Field2n Field2n::Inverse() const {
    if (format == Format::COEFFICIENT)
        OPENFHE_THROW(type_error, "Polynomial not in Format::EVALUATION representation");
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
        OPENFHE_THROW(type_error, "Operands are not in the same format");
    Field2n sum(*this);
    for (size_t i = 0; i < rhs.size(); ++i)
        sum[i] += rhs[i];
    return sum;
}

// Scalar addition operation for field elements
Field2n Field2n::Plus(double scalar) const {
    if (format != Format::COEFFICIENT)
        OPENFHE_THROW(not_implemented_error,
                      "Field2n scalar addition is currently supported only for "
                      "Format::COEFFICIENT representation");
    Field2n sum(*this);
    sum.at(0) += scalar;
    return sum;
}

// Substraction operation for field elements
Field2n Field2n::Minus(const Field2n& rhs) const {
    if (format != rhs.GetFormat())
        OPENFHE_THROW(type_error, "Operands are not in the same format");
    Field2n difference(*this);
    for (size_t i = 0; i < rhs.size(); ++i)
        difference[i] -= rhs[i];
    return difference;
}

// Multiplication operation for field elements
Field2n Field2n::Times(const Field2n& rhs) const {
    if (format !== Format::EVALUATION && rhs.GetFormat() != Format::EVALUATION)
        OPENFHE_THROW(type_error, "At least one of the polynomials is not in "
                                  "Format::EVALUATION representation");
    Field2n result(*this);
    for (size_t i = 0; i < rhs.size(); ++i)
        result[i] *= rhs[i];
    return result;
}

// Right shift operation for the field element
Field2n Field2n::ShiftRight() {
    if (format != Format::COEFFICIENT)
        OPENFHE_THROW(type_error, "Polynomial not in Format::COEFFICIENT representation");
    Field2n result(*this);
    size_t size = this->Field2n::size() - 1;
    auto tmp = std::complex<double>(-1., 0.) * result[size];
    for (size_t i = 0; i < size; ++i)
        result[i + 1] = result[i];
    result[0] = tmp;
    return result;
}

// Performs an automorphism transform operation and returns the result.
Field2n Field2n::AutomorphismTransform(size_t i) const {
    if (format != Format::EVALUATION)
        OPENFHE_THROW(not_implemented_error, "Field2n Automorphism is only implemented for "
                                             "Format::EVALUATION format");
    if (i % 2 == 0)
        OPENFHE_THROW(math_error, "automorphism index should be odd\n");
    Field2n result(*this);
    size_t m = this->Field2n::size() * 2;
    for (size_t j = 1; j < m; j += 2) {
        size_t idx{(j * i) % m};
        result[(idx + 1) / 2 - 1] = result[(j + 1) / 2 - 1];
    }
    return result;
}

// Transpose operation defined in section VI.B4 of
// https://eprint.iacr.org/2017/844.pdf
Field2n Field2n::Transpose() const {
    if (format != Format::COEFFICIENT)
        return AutomorphismTransform(this->Field2n::size() * 2 - 1);

    constexpr auto negone = std::complex<double>(-1., 0.);
    size_t size = this->Field2n::size();
    Field2n transpose(size, Format::COEFFICIENT, true);
    for (size_t i = 1; i < size; ++i)
        transpose[i] = negone * this->Field2n::operator[](size - i);
    transpose[0] = this->Field2n::operator[](0);
    return transpose;
}

// Function for extracting odd factors of the field element
Field2n Field2n::ExtractOdd() const {
    if (format != Format::COEFFICIENT) {
        OPENFHE_THROW(type_error, "Polynomial not in Format::COEFFICIENT representation");
    size_t size = this->Field2n::size();
    Field2n odds(size / 2, Format::COEFFICIENT, true);
    for (size_t i = 0; i < odds.size(); ++i)
        odds[i] = this->Field2n::operator[](1 + 2 * i);
    return odds;
}

// Function for extracting even factors of the field element
Field2n Field2n::ExtractEven() const {
    if (format != Format::COEFFICIENT) {
        OPENFHE_THROW(type_error, "Polynomial not in Format::COEFFICIENT representation");
    size_t size = this->Field2n::size();
    Field2n evens(size / 2, Format::COEFFICIENT, true);
    for (size_t i = 0; i < evens.size(); ++i)
        evens[i] = this->Field2n::operator[](0 + 2 * i);
    return evens;
}

// Permutation operation defined in Algorithm 4 of
// https://eprint.iacr.org/2017/844.pdf
Field2n Field2n::Permute() const {
    if (this->format == Format::COEFFICIENT) {
        Field2n permuted(this->size(), Format::COEFFICIENT, true);
        int evenPtr = 0;
        int oddPtr  = this->size() / 2;
        for (size_t i = 0; i < this->size(); i++) {
            if (i % 2 == 0) {
                permuted.at(evenPtr) = this->at(i);
                evenPtr++;
            }
            else {
                permuted.at(oddPtr) = this->at(i);
                oddPtr++;
            }
        }
        return permuted;
    }
    else {
        OPENFHE_THROW(type_error, "Polynomial not in Format::COEFFICIENT representation");
    }
}

// Inverse operation for permutation operation defined in
// Algorithm 4 of https://eprint.iacr.org/2017/844.pdf
Field2n Field2n::InversePermute() const {
    if (this->format == Format::COEFFICIENT) {
        Field2n invpermuted(this->size(), Format::COEFFICIENT, true);
        size_t evenPtr = 0;
        size_t oddPtr  = this->size() / 2;
        for (size_t i = 0; evenPtr < this->size() / 2; i += 2) {
            invpermuted[i]     = this->at(evenPtr);
            invpermuted.at(i + 1) = this->at(oddPtr);
            evenPtr++;
            oddPtr++;
        }
        return invpermuted;
    }
    else {
        OPENFHE_THROW(type_error, "Polynomial not in Format::COEFFICIENT representation");
    }
}

// Operation for scalar multiplication
Field2n Field2n::ScalarMult(double d) {
    Field2n scaled(this->size(), this->GetFormat(), true);
    for (size_t i = 0; i < this->size(); i++) {
        scaled[i] = d * this->at(i);
    }
    return scaled;
}

// Method for switching format of the field elements
void Field2n::SwitchFormat() {
    if (format == Format::COEFFICIENT) {
        std::vector<std::complex<double>> r = DiscreteFourierTransform::ForwardTransform(*this);

        for (size_t i = 0; i < r.size(); i++) {
            this->at(i) = r[i];
        }

        format = Format::EVALUATION;
    }
    else {
        std::vector<std::complex<double>> r = DiscreteFourierTransform::InverseTransform(*this);

        for (size_t i = 0; i < r.size(); i++) {
            this->at(i) = r[i];
        }
        format = Format::COEFFICIENT;
    }
}

}  // namespace lbcrypto

#endif
