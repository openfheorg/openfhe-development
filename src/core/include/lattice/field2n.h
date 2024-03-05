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
  Represents and defines power-of-2 fields
 */

#ifndef LBCRYPTO_INC_LATTICE_FIELD2N_H
#define LBCRYPTO_INC_LATTICE_FIELD2N_H

#include "lattice/lat-hal.h"

#include "math/matrix.h"

#include "utils/exception.h"
#include "utils/inttypes.h"
#include "utils/serializable.h"

#include <complex>
#include <limits>
#include <string>
#include <vector>

namespace lbcrypto {
/**
 * @class Field2n
 * @brief A class to represent field elements with power-of-2 dimension.
 */
class Field2n : public std::vector<std::complex<double>>, public Serializable {
private:
    // Format of the field element
    Format format{Format::COEFFICIENT};

public:
    /**
   * @brief Default Constructor
   */
    Field2n() noexcept = default;

    explicit Field2n(Format f) : format(f) {}

    /**
   * @brief Constructor for field element
   * @param size element size
   * @param f format/representation of the element.  Initially set to
   * Format::EVALUATION representation.
   * @param initializeElementToZero flag for initializing values to zero.  It is
   * set to false by default.
   */
    Field2n(usint size, Format f = Format::EVALUATION, bool initializeElementToZero = false)  // NOLINT
        : std::vector<std::complex<double>>(size, initializeElementToZero ? 0 : -std::numeric_limits<double>::max()),
          format(f) {}

    /**
   * @brief Constructor from ring element
   * @param & element ring element
   */
    explicit Field2n(const Poly& element);

    /**
   * @brief Constructor from ring element
   * @param & element ring element
   */
    explicit Field2n(const NativePoly& element);

    /**
   * @brief Constructor from DCRTPoly ring element
   * @param & element ring element
   */
    explicit Field2n(const DCRTPoly& element);

    /**
   * @brief Constructor from a ring element matrix
   * @param &element ring element matrix
   */
    explicit Field2n(const Matrix<int64_t>& element);

    /**
   * @brief Method for getting the format/representation of the element
   *
   * @return format/representation of the field element
   */
    Format GetFormat() const {
        return format;
    }

    /**
   * @brief Inverse operation for the field elements
   *
   * @return the inverse field element
   */
    Field2n Inverse() const;

    /**
   * @brief Addition operation for field elements
   *
   * @param &rhs right hand side element for operation
   * @return result of the operation
   */
    Field2n Plus(const Field2n& rhs) const;

    /**
   * @brief Scalar addition operation for field elements
   *
   * @param &rhs right hand side element for operation
   * @return result of the operation
   */
    Field2n Plus(double rhs) const;

    /**
   * @brief Substraction operation for field elements
   *
   * @param &rhs right hand side element for operation
   * @return result of the operation
   */
    Field2n Minus(const Field2n& rhs) const;

    /**
   * @brief Multiplication operation for field elements
   *
   * @param &rhs right hand side element for operation
   * @return result of the operation
   */
    Field2n Times(const Field2n& rhs) const;

    /**
   * @brief Right shift operation for the field element
   *
   * @return the shifted field element
   */
    Field2n ShiftRight();

    /**
   * @brief Performs an automorphism transform operation and returns the result.
   *
   * @param &i is the element to perform the automorphism transform with.
   * @return is the result of the automorphism transform.
   */
    Field2n AutomorphismTransform(size_t i) const;

    /**
   * @brief Transpose operation defined in section VI.B4 of
   * https://eprint.iacr.org/2017/844.pdf
   *
   * @return the transpose of the element
   */
    Field2n Transpose() const;

    /**
   * @brief Function for extracting odd factors of the field element
   *
   * @return the field element with odd parts of the initial element
   */
    Field2n ExtractOdd() const;

    /**
   * @brief Function for extracting even factors of the field element
   *
   * @return the field element with even parts of the initial element
   */
    Field2n ExtractEven() const;

    /**
   * @brief Permutation operation defined in Algorithm 4 of
   * https://eprint.iacr.org/2017/844.pdf
   *
   * @return permuted new field element
   */
    Field2n Permute() const;

    /**
   * @brief Inverse operation for permutation operation defined in
   * Algorithm 4 of https://eprint.iacr.org/2017/844.pdf
   *
   * @return non permuted version of the element
   */
    Field2n InversePermute() const;

    /**
   * @brief Operation for scalar multiplication
   *
   * @param d scalar for multiplication
   * @return the field element with the scalar multiplication
   */
    Field2n ScalarMult(double d);

    /**
   * @brief Method for switching format of the field elements
   */
    void SwitchFormat();

    /**
   * @brief Sets the evaluation or coefficient representation of the field
   * elements
   * @param &format the enum value corresponding to coefficient or evaluation
   * representation
   */
    inline void SetFormat(Format f) {
        if (format != f)
            SwitchFormat();
    }

    /**
   * @brief Method for getting the size of the element
   *
   * @return the size of the element
   */
    size_t Size() const {
        return this->std::vector<std::complex<double>>::size();
    }

    /**
   * @brief Indexing operator for field elements
   *
   * @param idx index of the element
   * @return element at the index
   */
    inline std::complex<double>& operator[](size_t idx) {
        return this->std::vector<std::complex<double>>::operator[](idx);
    }

    /**
   * @brief Indexing operator for field elements
   *
   * @param idx index of the element
   * @return element at the index
   */
    inline const std::complex<double>& operator[](size_t idx) const {
        return this->std::vector<std::complex<double>>::operator[](idx);
    }

    /**
   * @brief In-place addition operation for field elements
   *
   * @param &element  right hand side element for operation
   * @return result of the operation
   */
    Field2n& operator+=(const Field2n& element) {
        return *this = this->Plus(element);
    }

    /**
   * @brief In-place subtraction operation for field elements
   *
   * @param &element  right hand side element for operation
   * @return result of the operation
   */
    Field2n& operator-=(const Field2n& element) {
        return *this = this->Minus(element);
    }

    /**
   * @brief Unary minus on a field element.
   * @return negation of the field element.
   */
    Field2n operator-() const {
        return Field2n(size(), this->GetFormat(), true) - *this;
    }

    /**
   * @brief Substraction operator for field elements
   *
   * @param &a left hand side field element
   * @param &b right hand side field element
   * @return result of the substraction operation
   */
    friend inline Field2n operator-(const Field2n& a, const Field2n& b) {
        return a.Minus(b);
    }

    /**
   * @brief Addition operator for field elements
   *
   * @param &a left hand side field element
   * @param &b right hand side field element
   * @return result of the addition operation
   */
    friend inline Field2n operator+(const Field2n& a, const Field2n& b) {
        return a.Plus(b);
    }

    /**
   * @brief Scalar addition operator for field elements
   *
   * @param &a left hand side field element
   * @param &b  the scalar to be added
   * @return result of the addition operation
   */
    friend inline Field2n operator+(const Field2n& a, double scalar) {
        return a.Plus(scalar);
    }

    /**
   * @brief Multiplication operator for field elements
   *
   * @param &a left hand side field element
   * @param &b right hand side field element
   * @return result of the multiplication operation
   */
    friend inline Field2n operator*(const Field2n& a, const Field2n& b) {
        return a.Times(b);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::base_class<std::vector<std::complex<double>>>(this));
        ar(::cereal::make_nvp("f", format));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::base_class<std::vector<std::complex<double>>>(this));
        ar(::cereal::make_nvp("f", format));
    }

    std::string SerializedObjectName() const override {
        return "Field2n";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }
};

/**
 * @brief Stream output operator
 *
 * @param &os stream
 * @param &m matrix to be outputted
 * @return the chained stream
 */
inline std::ostream& operator<<(std::ostream& os, const Field2n& m) {
    os << "[ ";
    for (size_t row = 0; row < m.size(); ++row)
        os << m.at(row) << " ";
    os << " ]\n";
    return os;
}

}  // namespace lbcrypto

#endif
