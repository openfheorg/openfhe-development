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

/*
  This file contains the vector manipulation functionality
 */

#include "config_core.h"
#ifdef WITH_BE2

    #ifndef LBCRYPTO_MATH_HAL_BIGINTFXD_MUBINVECFXD_H
        #define LBCRYPTO_MATH_HAL_BIGINTFXD_MUBINVECFXD_H

        #include <iostream>
        #include <string>

        #include "utils/inttypes.h"
        #include "utils/serializable.h"

        #include "math/hal/bigintfxd/ubintfxd.h"

/**
 * @namespace bigintfxd
 * The namespace of bigintfxd
 */
namespace bigintfxd {

// Forward declare this class for aliases
template <typename IntegerType>
class BigVectorFixedT;

using BigVector = BigVectorFixedT<BigInteger>;

/**
 * @brief The class for representing vectors of big binary integers.
 */
template <class IntegerType>
class BigVectorFixedT final : public lbcrypto::BigVectorInterface<BigVectorFixedT<IntegerType>, IntegerType>,
                              public lbcrypto::Serializable {
public:
    ~BigVectorFixedT() {
        delete[] m_data;
    }

    /**
   * Basic constructor.
   */
    BigVectorFixedT();

    static inline BigVectorFixedT Single(const IntegerType& val, const IntegerType& modulus) {
        BigVectorFixedT vec(1, modulus);
        vec[0] = val;
        return vec;
    }

    /**
   * Basic constructor for specifying the length of the vector and the modulus.
   *
   * @param length is the length of the big binary vector, in terms of the
   * number of entries.
   * @param modulus is the modulus of the ring.
   */
    explicit BigVectorFixedT(usint length, const IntegerType& modulus = 0);

    BigVectorFixedT(usint length, const IntegerType& modulus, const IntegerType& value)
        : m_data(new IntegerType[length]()), m_length{length}, m_modulus{modulus} {
        std::fill(m_data, m_data + m_length, value);
    }

    /**
   * Basic constructor for copying a vector
   *
   * @param bigVector is the big binary vector to be copied.
   */
    BigVectorFixedT(const BigVectorFixedT& bigVector);

    /**
   * Basic move constructor for moving a vector
   *
   * @param &&bigVector is the big binary vector to be moved.
   */
    BigVectorFixedT(BigVectorFixedT&& bigVector);  // move copy constructor

    /**
   * Basic constructor for specifying the length of the vector
   * the modulus and an initializer list.
   *
   * @param length is the length of the big binary vector, in terms of the
   * number of entries.
   * @param modulus is the modulus of the ring.
   * @param rhs is an initializer list of strings
   */

    BigVectorFixedT(usint length, const IntegerType& modulus, std::initializer_list<std::string> rhs);

    /**
   * Basic constructor for specifying the length of the vector
   * the modulus and an initializer list.
   *
   * @param length is the length of the big binary vector, in terms of the
   * number of entries.
   * @param modulus is the modulus of the ring.
   * @param rhs is an initializer list of usint
   */
    BigVectorFixedT(usint length, const IntegerType& modulus, std::initializer_list<uint64_t> rhs);

    /**
   * Assignment operator to assign value from rhs
   *
   * @param &rhs is the big binary vector to be assigned from.
   * @return Assigned BigVectorFixedT.
   */
    BigVectorFixedT& operator=(const BigVectorFixedT& rhs);

    /**
   * Move assignment operator
   *
   * @param &&rhs is the big binary vector to be moved.
   * @return moved BigVectorFixedT object
   */
    BigVectorFixedT& operator=(BigVectorFixedT&& rhs);

    /**
   * Initializer list for BigVectorFixedT.
   *
   * @param &&rhs is the list of strings containing integers to be assigned to
   * the BBV.
   * @return BigVectorFixedT object
   */
    BigVectorFixedT& operator=(std::initializer_list<std::string> rhs);

    /**
   * Initializer list for BigVectorFixedT.
   *
   * @param &&rhs is the list of integers to be assigned to the BBV.
   * @return BigVectorFixedT object
   */
    BigVectorFixedT& operator=(std::initializer_list<uint64_t> rhs);

    /**
   * Assignment operator to assign value val to first entry, 0 for the rest of
   * entries.
   *
   * @param val is the value to be assigned at the first entry.
   * @return Assigned BigVectorFixedT.
   */
    BigVectorFixedT& operator=(uint64_t val) {
        this->m_data[0] = val;
        if (this->m_modulus != 0) {
            this->m_data[0] %= this->m_modulus;
        }
        for (size_t i = 1; i < GetLength(); ++i) {
            this->m_data[i] = 0;
        }
        return *this;
    }

    // ACCESSORS

    /**
   * Sets/gets a value at an index.
   * This method is slower than operator[] as it checks if index out of range
   *
   * @param index is the index to set a value at.
   */
    IntegerType& at(size_t i) {
        if (!this->IndexCheck(i)) {
            OPENFHE_THROW("BigVector index out of range");
        }
        return this->m_data[i];
    }

    const IntegerType& at(size_t i) const {
        if (!this->IndexCheck(i)) {
            OPENFHE_THROW("BigVector index out of range");
        }
        return this->m_data[i];
    }

    /**
   * operators to get a value at an index.
   * @param idx is the index to get a value at.
   * @return is the value at the index.
   */
    IntegerType& operator[](size_t idx) {
        return (this->m_data[idx]);
    }

    const IntegerType& operator[](size_t idx) const {
        return (this->m_data[idx]);
    }

    /**
   * Sets the vector modulus.
   *
   * @param value is the value to set.
   * @param value is the modulus value to set.
   */
    void SetModulus(const IntegerType& value);

    /**
   * Sets the vector modulus and changes the values to match the new modulus.
   *
   * @param value is the value to set.
   */
    void SwitchModulus(const IntegerType& value);

    /**
   * Gets the vector modulus.
   *
   * @return the vector modulus.
   */
    const IntegerType& GetModulus() const {
        return this->m_modulus;
    }

    /**
   * Gets the vector length.
   *
   * @return vector length.
   */
    size_t GetLength() const {
        return this->m_length;
    }

    // MODULAR ARITHMETIC OPERATIONS

    /**
   * Vector modulus operator.
   *
   * @param &modulus is the modulus to perform on the current vector entries.
   * @return is the result of the modulus operation on current vector.
   */
    BigVectorFixedT Mod(const IntegerType& modulus) const;

    /**
   * Vector modulus operator. In-place variant.
   *
   * @param &modulus is the modulus to perform on the current vector entries.
   * @return is the result of the modulus operation on current vector.
   */
    BigVectorFixedT& ModEq(const IntegerType& modulus);

    /**
   * Scalar-to-vector modulus addition operation.
   *
   * @param &b is the scalar to perform operation with.
   * @return is the result of the modulus addition operation.
   */
    BigVectorFixedT ModAdd(const IntegerType& b) const;

    /**
   * Scalar-to-vector modulus addition operation. In-place variant.
   *
   * @param &b is the scalar to perform operation with.
   * @return is the result of the modulus addition operation.
   */
    BigVectorFixedT& ModAddEq(const IntegerType& b);

    /**
   * Scalar modulus addition at a particular index.
   *
   * @param i is the index of the entry to add.
   * @param &b is the scalar to add.
   * @return is the result of the modulus addition operation.
   */
    BigVectorFixedT ModAddAtIndex(usint i, const IntegerType& b) const;

    /**
   * Scalar modulus addition at a particular index. In-place variant.
   *
   * @param i is the index of the entry to add.
   * @param &b is the scalar to add.
   * @return is the result of the modulus addition operation.
   */
    BigVectorFixedT& ModAddAtIndexEq(usint i, const IntegerType& b);

    /**
   * Vector component wise modulus addition.
   *
   * @param &b is the vector to perform operation with.
   * @return is the result of the component wise modulus addition operation.
   */
    BigVectorFixedT ModAdd(const BigVectorFixedT& b) const;

    /**
   * Vector component wise modulus addition. In-place variant.
   *
   * @param &b is the vector to perform operation with.
   * @return is the result of the component wise modulus addition operation.
   */
    BigVectorFixedT& ModAddEq(const BigVectorFixedT& b);
    BigVectorFixedT& ModAddNoCheckEq(const BigVectorFixedT& b);

    /**
   * Scalar-from-vector modulus subtraction operation.
   *
   * @param &b is the scalar to perform operation with.
   * @return is the result of the modulus subtraction operation.
   */
    BigVectorFixedT ModSub(const IntegerType& b) const;

    /**
   * Scalar-from-vector modulus subtraction operation. In-place variant.
   *
   * @param &b is the scalar to perform operation with.
   * @return is the result of the modulus subtraction operation.
   */
    BigVectorFixedT& ModSubEq(const IntegerType& b);

    /**
   * Vector component wise modulus subtraction.
   *
   * @param &b is the vector to perform operation with.
   * @return is the result of the component wise modulus subtraction operation.
   */
    BigVectorFixedT ModSub(const BigVectorFixedT& b) const;

    /**
   * Vector component wise modulus subtraction. In-place variant.
   *
   * @param &b is the vector to perform operation with.
   * @return is the result of the component wise modulus subtraction operation.
   */
    BigVectorFixedT& ModSubEq(const BigVectorFixedT& b);

    /**
   * Scalar-to-vector modulus multiplication operation.
   * Generalized Barrett modulo reduction algorithm.
   *
   * @param &b is the scalar to perform operation with.
   * @return is the result of the modulus multiplication operation.
   */
    BigVectorFixedT ModMul(const IntegerType& b) const;

    /**
   * Scalar-to-vector modulus multiplication operation. In-place variant.
   * Generalized Barrett modulo reduction algorithm.
   *
   * @param &b is the scalar to perform operation with.
   * @return is the result of the modulus multiplication operation.
   */
    BigVectorFixedT& ModMulEq(const IntegerType& b);

    /**
   * Vector component wise modulus multiplication.
   *
   * @param &b is the vector to perform operation with.
   * @return is the result of the component wise modulus multiplication
   * operation.
   */
    BigVectorFixedT ModMul(const BigVectorFixedT& b) const;

    /**
   * Vector component wise modulus multiplication. In-place variant.
   *
   * @param &b is the vector to perform operation with.
   * @return is the result of the component wise modulus multiplication
   * operation.
   */
    BigVectorFixedT& ModMulEq(const BigVectorFixedT& b);
    BigVectorFixedT& ModMulNoCheckEq(const BigVectorFixedT& b);

    /**
   * Scalar modulus exponentiation operation.
   *
   * @param &b is the scalar to perform operation with.
   * @return is the result of the modulus exponentiation operation.
   */
    BigVectorFixedT ModExp(const IntegerType& b) const;

    /**
   * Scalar modulus exponentiation operation. In-place variant.
   *
   * @param &b is the scalar to perform operation with.
   * @return is the result of the modulus exponentiation operation.
   */
    BigVectorFixedT& ModExpEq(const IntegerType& b);

    /**
   * Modulus inverse operation.
   *
   * @return is the result of the component wise modulus inverse operation.
   */
    BigVectorFixedT ModInverse() const;

    /**
   * Modulus inverse operation. In-place variant.
   *
   * @return is the result of the component wise modulus inverse operation.
   */
    BigVectorFixedT& ModInverseEq();

    /**
   * Modulus 2 operation, also a least significant bit.
   *
   * @return is the result of the component wise modulus 2 operation, also a
   * least significant bit.
   */
    BigVectorFixedT ModByTwo() const;

    /**
   * Modulus 2 operation, also a least significant bit. In-place variant.
   *
   * @return is the result of the component wise modulus 2 operation, also a
   * least significant bit.
   */
    BigVectorFixedT& ModByTwoEq();

    /**
   * Vector multiplication without applying the modulus operation.
   *
   * @param &b is the vector to multiply.
   * @return is the result of the multiplication operation.
   */
    BigVectorFixedT MultWithOutMod(const BigVectorFixedT& b) const;

    /**
   * Vector multiplication without applying the modulus operation. In-place
   * variant.
   *
   * @param &b is the vector to multiply.
   * @return is the result of the multiplication operation.
   */
    BigVectorFixedT& MultWithOutModEq(const BigVectorFixedT& b);

    /**
   * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
   * operation.
   *
   * @param &p is the numerator to be multiplied.
   * @param &q is the denominator to be divided.
   * @return is the result of multiply and round operation.
   */
    BigVectorFixedT MultiplyAndRound(const IntegerType& p, const IntegerType& q) const;

    /**
   * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
   * operation. In-place variant.
   *
   * @param &p is the numerator to be multiplied.
   * @param &q is the denominator to be divided.
   * @return is the result of multiply and round operation.
   */
    BigVectorFixedT& MultiplyAndRoundEq(const IntegerType& p, const IntegerType& q);

    /**
   * Divide and Rounding operation. Returns [x/q] where [] is the rounding
   * operation.
   *
   * @param &q is the denominator to be divided.
   * @return is the result of divide and round operation.
   */
    BigVectorFixedT DivideAndRound(const IntegerType& q) const;

    /**
   * Divide and Rounding operation. Returns [x/q] where [] is the rounding
   * operation. In-place variant.
   *
   * @param &q is the denominator to be divided.
   * @return is the result of divide and round operation.
   */
    BigVectorFixedT& DivideAndRoundEq(const IntegerType& q);

    // OTHER FUNCTIONS

    /**
   * Digit vector at a specific index for all entries for a given number base.
   * Warning: only power-of-2 bases are currently supported.
   * Example: for vector (83, 1, 45), index 2 and base 4 we have:
   *
   *                           index:0,1,2,3
   * |83|                           |3,0,1,1|                 |1|
   * |1 | --base 4 decomposition--> |1,0,0,0| --at index 2--> |0|
   * |45|                           |1,3,2,0|                 |2|
   *
   * The return vector is (1,0,2)
   *
   * @param index is the index to return the digit from in all entries.
   * @param base is the base to use for the operation.
   * @return is the digit at a specific index for all entries for a given number
   * base
   */
    BigVectorFixedT GetDigitAtIndexForBase(usint index, usint base) const;

    // STRINGS & STREAMS

    /**
   * ostream operator to output vector values to console
   *
   * @param os is the std ostream object.
   * @param &ptr_obj is the BigVectorFixedT object to be printed.
   * @return std ostream object which captures the vector values.
   */
    template <class IntegerType_c>
    friend std::ostream& operator<<(std::ostream& os, const BigVectorFixedT<IntegerType_c>& ptr_obj) {
        auto len = ptr_obj.m_length;
        os << "[";
        for (usint i = 0; i < len; i++) {
            os << ptr_obj.m_data[i];
            os << ((i == (len - 1)) ? "]" : " ");
        }
        os << " modulus: " << ptr_obj.m_modulus;
        return os;
    }

    // SERIALIZATION

    template <class Archive>
    typename std::enable_if<!cereal::traits::is_text_archive<Archive>::value, void>::type save(
        Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("m", m_modulus));
        ar(::cereal::make_nvp("l", m_length));
        ar(::cereal::binary_data(m_data, sizeof(IntegerType) * m_length));
    }

    template <class Archive>
    typename std::enable_if<cereal::traits::is_text_archive<Archive>::value, void>::type save(
        Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("m", m_modulus));
        ar(::cereal::make_nvp("l", m_length));
        for (size_t i = 0; i < m_length; i++) {
            ar(m_data[i]);
        }
    }

    template <class Archive>
    typename std::enable_if<!cereal::traits::is_text_archive<Archive>::value, void>::type load(
        Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("m", m_modulus));
        ar(::cereal::make_nvp("l", m_length));
        m_data = new IntegerType[m_length]();
        ar(::cereal::binary_data(m_data, sizeof(IntegerType) * m_length));
    }

    template <class Archive>
    typename std::enable_if<cereal::traits::is_text_archive<Archive>::value, void>::type load(
        Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("m", m_modulus));
        ar(::cereal::make_nvp("l", m_length));
        m_data = new IntegerType[m_length]();
        for (size_t i = 0; i < m_length; i++) {
            ar(m_data[i]);
        }
    }

    std::string SerializedObjectName() const {
        return "FXDInteger";
    }

    static uint32_t SerializedVersion() {
        return 1;
    }

private:
    // m_data is a pointer to the vector
    IntegerType* m_data;
    // m_length stores the length of the vector
    usint m_length;
    // m_modulus stores the internal modulus of the vector.
    IntegerType m_modulus = 0;

    // function to check if the index is a valid index.
    bool IndexCheck(usint length) const {
        return length < m_length;
    }
};

}  // namespace bigintfxd

    #endif  // LBCRYPTO_MATH_HAL_BIGINTFXD_MUBINVECFXD_H

#endif
