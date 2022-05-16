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
 * This file contains the vector manipulation functionality for native integers
 */

#ifndef LBCRYPTO_MATH_HAL_INTNAT_MUBINTVECNAT_H
#define LBCRYPTO_MATH_HAL_INTNAT_MUBINTVECNAT_H

#include <initializer_list>
#include <iostream>
#include <string>
#include <vector>

#include "math/hal/intnat/ubintnat.h"
#include "math/hal/vector.h"

#include "utils/inttypes.h"
#include "utils/serializable.h"
#include "utils/blockAllocator/xvector.h"

// the following should be set to 1 in order to have native vector use block
// allocations then determine if you want dynamic or static allocations by
// settingdefining STAIC_POOLS on line 24 of
// xallocator.cpp
#define BLOCK_VECTOR_ALLOCATION 0  // set to 1 to use block allocations

/**
 * @namespace intnat
 * The namespace of intnat
 */
namespace intnat {

// Forward declare class and give it an alias for the expected type
template <typename IntType>
class NativeVectorT;
using NativeVector = NativeVectorT<NativeInteger>;

/**
 * @brief The class for representing vectors of native integers.
 */

#if 0  // allocator that reports bytes used.
template <class Tp>
struct NAlloc {
    typedef Tp value_type;
    NAlloc() = default;
    template <class T> NAlloc(const NAlloc<T>&) {}
    Tp* allocate(std::size_t n) {
        n *= sizeof(Tp);
        return static_cast<Tp*>(::operator new(n));
    }
    void deallocate(Tp* p, std::size_t n) {
        std::cout << "deallocating " << n*sizeof*p << " bytes\n";
        ::operator delete(p);
    }
};
template <class T, class U>
bool operator==(const NAlloc<T>&, const NAlloc<U>&) { return true; }
template <class T, class U>
bool operator!=(const NAlloc<T>&, const NAlloc<U>&) { return false; }
#endif

#if 0  // allocator that reports bytes used.
template <class Tp>
struct NAlloc {
    typedef Tp value_type;
    NAlloc() = default;
    template <class T> NAlloc(const NAlloc<T>&) {}
    Tp* allocate(std::size_t n) {
        n *= sizeof(Tp);
        std::cout << "allocating   " << n << " bytes\n";
        return static_cast<Tp*>(::operator new(n));
    }
    void deallocate(Tp* p, std::size_t n) {
        std::cout << "deallocating " << n*sizeof*p << " bytes\n";
        ::operator delete(p);
    }
};
template <class T, class U>
bool operator==(const NAlloc<T>&, const NAlloc<U>&) { return true; }
template <class T, class U>
bool operator!=(const NAlloc<T>&, const NAlloc<U>&) { return false; }
#endif

template <class IntegerType>
class NativeVectorT : public lbcrypto::BigVectorInterface<NativeVectorT<IntegerType>, IntegerType>,
                      public lbcrypto::Serializable {
public:
    typedef IntegerType BVInt;

    // CONSTRUCTORS

    /**
   * Basic constructor.
   */
    NativeVectorT();

    static inline NativeVectorT Single(const IntegerType& val, const IntegerType& modulus) {
        NativeVectorT vec(1, modulus);
        vec[0] = val;
        return vec;
    }

    /**
   * Basic constructor for specifying the length of the vector.
   *
   * @param length is the length of the native vector, in terms of the number of
   * entries.
   */
    explicit NativeVectorT(usint length);

    /**
   * Basic constructor for specifying the length of the vector and the modulus.
   *
   * @param length is the length of the native vector, in terms of the number of
   * entries.
   * @param modulus is the modulus of the ring.
   */
    NativeVectorT(usint length, const IntegerType& modulus);

    /**
   * Basic constructor for copying a vector
   *
   * @param bigVector is the native vector to be copied.
   */
    NativeVectorT(const NativeVectorT& bigVector);

    /**
   * Basic move constructor for moving a vector
   *
   * @param &&bigVector is the native vector to be moved.
   */
    NativeVectorT(NativeVectorT&& bigVector);  // move copy constructor

    /**
   * Basic constructor for specifying the length of the vector
   * the modulus and an initializer list.
   *
   * @param length is the length of the native vector, in terms of the number of
   * entries.
   * @param modulus is the modulus of the ring.
   * @param rhs is an initializer list of strings
   */

    NativeVectorT(usint length, const IntegerType& modulus, std::initializer_list<std::string> rhs);

    /**
   * Basic constructor for specifying the length of the vector
   * the modulus and an initializer list.
   *
   * @param length is the length of the native vector, in terms of the number of
   * entries.
   * @param modulus is the modulus of the ring.
   * @param rhs is an initializer list of usint
   */
    NativeVectorT(usint length, const IntegerType& modulus, std::initializer_list<uint64_t> rhs);

    /**
   * Destructor.
   */
    virtual ~NativeVectorT();

    // ASSIGNMENT OPERATORS

    /**
   * Assignment operator to assign value from rhs
   *
   * @param &rhs is the native vector to be assigned from.
   * @return Assigned NativeVectorT.
   */
    const NativeVectorT& operator=(const NativeVectorT& rhs);

    /**
   * Move assignment operator
   *
   * @param &&rhs is the native vector to be moved.
   * @return moved NativeVectorT object
   */
    NativeVectorT& operator=(NativeVectorT&& rhs);

    /**
   * Initializer list for NativeVectorT.
   *
   * @param &&rhs is the list of strings containing integers to be assigned to
   * the BBV.
   * @return NativeVectorT object
   */
    const NativeVectorT& operator=(std::initializer_list<std::string> rhs);

    /**
   * Initializer list for NativeVectorT.
   *
   * @param &&rhs is the list of integers to be assigned to the BBV.
   * @return NativeVectorT object
   */
    const NativeVectorT& operator=(std::initializer_list<uint64_t> rhs);

    /**
   * Assignment operator to assign value val to first entry, 0 for the rest of
   * entries.
   *
   * @param val is the value to be assigned at the first entry.
   * @return Assigned NativeVectorT.
   */
    inline const NativeVectorT& operator=(uint64_t val) {
        this->m_data[0] = val;
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
            OPENFHE_THROW(lbcrypto::math_error, "NativeVectorT index out of range");
        }
        return this->m_data[i];
    }

    const IntegerType& at(size_t i) const {
        if (!this->IndexCheck(i)) {
            OPENFHE_THROW(lbcrypto::math_error, "NativeVectorT index out of range");
        }
        return this->m_data[i];
    }

    /**
   * operators to get a value at an index.
   * @param idx is the index to get a value at.
   * @return is the value at the index. return nullptr if invalid index.
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
    const IntegerType& GetModulus() const;

    /**
   * Gets the vector length.
   *
   * @return vector length.
   */
    size_t GetLength() const {
        return this->m_data.size();
    }

    // MODULAR ARITHMETIC OPERATIONS

    /**
   * Vector Modulus operator.
   *
   * @param modulus is the modulus to perform on the current vector entries.
   * @return is the result after the modulus operation on current vector.
   */
    NativeVectorT Mod(const IntegerType& modulus) const;

    /**
   * Vector Modulus operator. In-place variant.
   *
   * @param modulus is the modulus to perform on the current vector entries.
   * @return is the result after the modulus operation on current vector.
   */
    const NativeVectorT& ModEq(const IntegerType& modulus);

    /**
   * Scalar modulus addition.
   *
   * After addition modulus operation is performed with the current vector
   * modulus.
   * @return is the result of the modulus addition operation.
   */
    NativeVectorT ModAdd(const IntegerType& b) const;

    /**
   * Scalar modulus addition. In-place variant.
   *
   * After addition modulus operation is performed with the current vector
   * modulus.
   * @return is the result of the modulus addition operation.
   */
    const NativeVectorT& ModAddEq(const IntegerType& b);

    /**
   * Scalar modulus addition at a particular index.
   *
   * @param i is the index of the entry to add.
   * @param &b is the scalar to add.
   * @return is the result of the modulus addition operation.
   */
    NativeVectorT ModAddAtIndex(usint i, const IntegerType& b) const;

    /**
   * Scalar modulus addition at a particular index. In-place variant.
   *
   * @param i is the index of the entry to add.
   * @param &b is the scalar to add.
   * @return is the result of the modulus addition operation.
   */
    const NativeVectorT& ModAddAtIndexEq(usint i, const IntegerType& b);

    /**
   * vector modulus addition.
   *
   * @param &b is the vector to add at all locations.
   * @return is the result of the modulus addition operation.
   */
    NativeVectorT ModAdd(const NativeVectorT& b) const;

    /**
   * vector modulus addition. In-place variant.
   *
   * @param &b is the vector to add at all locations.
   * @return is the result of the modulus addition operation.
   */
    const NativeVectorT& ModAddEq(const NativeVectorT& b);

    /**
   * Scalar modulus subtraction.
   * After substraction modulus operation is performed with the current vector
   * modulus.
   * @param &b is the scalar to subtract from all locations.
   * @return is the result of the modulus substraction operation.
   */
    NativeVectorT ModSub(const IntegerType& b) const;

    /**
   * Scalar modulus subtraction. In-place variant.
   * After substraction modulus operation is performed with the current vector
   * modulus.
   * @param &b is the scalar to subtract from all locations.
   * @return is the result of the modulus substraction operation.
   */
    const NativeVectorT& ModSubEq(const IntegerType& b);

    /**
   * Vector Modulus subtraction.
   *
   * @param &b is the vector to subtract.
   * @return is the result of the modulus subtraction operation.
   */
    NativeVectorT ModSub(const NativeVectorT& b) const;

    /**
   * Vector Modulus subtraction. In-place variant.
   *
   * @param &b is the vector to subtract.
   * @return is the result of the modulus subtraction operation.
   */
    const NativeVectorT& ModSubEq(const NativeVectorT& b);

    /**
   * Scalar modular multiplication.
   * See the comments in the cpp files for details of the implementation.
   *
   * @param &b is the scalar to multiply at all locations.
   * @return is the result of the modulus multiplication operation.
   */
    NativeVectorT ModMul(const IntegerType& b) const;

    /**
   * Scalar modular multiplication. In-place variant.
   * See the comments in the cpp files for details of the implementation.
   *
   * @param &b is the scalar to multiply at all locations.
   * @return is the result of the modulus multiplication operation.
   */
    const NativeVectorT& ModMulEq(const IntegerType& b);

    /**
   * Vector modulus multiplication.
   *
   * @param &b is the vector to multiply.
   * @return is the result of the modulus multiplication operation.
   */
    NativeVectorT ModMul(const NativeVectorT& b) const;

    /**
   * Vector modulus multiplication. In-place variant.
   *
   * @param &b is the vector to multiply.
   * @return is the result of the modulus multiplication operation.
   */
    const NativeVectorT& ModMulEq(const NativeVectorT& b);

    /**
   * Vector multiplication without applying the modulus operation.
   *
   * @param &b is the vector to multiply.
   * @return is the result of the multiplication operation.
   */
    NativeVectorT MultWithOutMod(const NativeVectorT& b) const;

    /**
   * Scalar modulus exponentiation.
   *
   * @param &b is the scalar to exponentiate at all locations.
   * @return a new vector which is the result of the modulus exponentiation
   * operation.
   */
    NativeVectorT ModExp(const IntegerType& b) const;

    /**
   * Scalar modulus exponentiation. In-place variant.
   *
   * @param &b is the scalar to exponentiate at all locations.
   * @return a new vector which is the result of the modulus exponentiation
   * operation.
   */
    const NativeVectorT& ModExpEq(const IntegerType& b);

    /**
   * Modulus inverse.
   *
   * @return a new vector which is the result of the modulus inverse operation.
   */
    NativeVectorT ModInverse() const;

    /**
   * Modulus inverse. In-place variant.
   *
   * @return a new vector which is the result of the modulus inverse operation.
   */
    const NativeVectorT& ModInverseEq();

    /**
   * Perform a modulus by 2 operation.  Returns the least significant bit.
   *
   * @return a new vector which is the return value of the modulus by 2, also
   * the least significant bit.
   */
    NativeVectorT ModByTwo() const;

    /**
   * Perform a modulus by 2 operation.  Returns the least significant bit.
   * In-place variant.
   *
   * @return a new vector which is the return value of the modulus by 2, also
   * the least significant bit.
   */
    const NativeVectorT& ModByTwoEq();

    /**
   * Multiply and Rounding operation on a BigInteger x. Returns [x*p/q] where []
   * is the rounding operation.
   *
   * @param p is the numerator to be multiplied.
   * @param q is the denominator to be divided.
   * @return the result of multiply and round.
   */
    NativeVectorT MultiplyAndRound(const IntegerType& p, const IntegerType& q) const;

    /**
   * Multiply and Rounding operation on a BigInteger x. Returns [x*p/q] where []
   * is the rounding operation. In-place variant.
   *
   * @param p is the numerator to be multiplied.
   * @param q is the denominator to be divided.
   * @return the result of multiply and round.
   */
    const NativeVectorT& MultiplyAndRoundEq(const IntegerType& p, const IntegerType& q);

    /**
   * Divide and Rounding operation on a BigInteger x. Returns [x/q] where [] is
   * the rounding operation.
   *
   * @param q is the denominator to be divided.
   * @return the result of divide and round.
   */
    NativeVectorT DivideAndRound(const IntegerType& q) const;

    /**
   * Divide and Rounding operation on a BigInteger x. Returns [x/q] where [] is
   * the rounding operation. In-place variant.
   *
   * @param q is the denominator to be divided.
   * @return the result of divide and round.
   */
    const NativeVectorT& DivideAndRoundEq(const IntegerType& q);

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
    NativeVectorT GetDigitAtIndexForBase(usint index, usint base) const;

    // STRINGS & STREAMS

    /**
   * ostream operator to output vector values to console
   *
   * @param os is the std ostream object.
   * @param &ptr_obj is the NativeVectorT object to be printed.
   * @return std ostream object which captures the vector values.
   */
    template <class IntegerType_c>
    friend std::ostream& operator<<(std::ostream& os, const NativeVectorT<IntegerType_c>& ptr_obj) {
        auto len = ptr_obj.m_data.size();
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
        ::cereal::size_type size = m_data.size();
        ar(size);
        if (size > 0) {
            ar(::cereal::binary_data(m_data.data(), size * sizeof(IntegerType)));
        }
        ar(m_modulus);
    }

    template <class Archive>
    typename std::enable_if<cereal::traits::is_text_archive<Archive>::value, void>::type save(
        Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("v", m_data));
        ar(::cereal::make_nvp("m", m_modulus));
    }

    template <class Archive>
    typename std::enable_if<!cereal::traits::is_text_archive<Archive>::value, void>::type load(
        Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(lbcrypto::deserialize_error, "serialized object version " + std::to_string(version) +
                                                            " is from a later version of the library");
        }
        ::cereal::size_type size;
        ar(size);
        m_data.resize(size);
        if (size > 0) {
            auto* data = reinterpret_cast<IntegerType*>(malloc(size * sizeof(IntegerType)));
            ar(::cereal::binary_data(data, size * sizeof(IntegerType)));
            for (::cereal::size_type i = 0; i < size; i++) {
                m_data[i] = data[i];
            }
            free(data);
        }
        ar(m_modulus);
    }

    template <class Archive>
    typename std::enable_if<cereal::traits::is_text_archive<Archive>::value, void>::type load(
        Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(lbcrypto::deserialize_error, "serialized object version " + std::to_string(version) +
                                                            " is from a later version of the library");
        }
        ar(::cereal::make_nvp("v", m_data));
        ar(::cereal::make_nvp("m", m_modulus));
    }


    static uint32_t SerializedVersion() {
        return 1;
    }

private:
    // m_data is a pointer to the vector

#if BLOCK_VECTOR_ALLOCATION != 1
    std::vector<IntegerType> m_data;
#else
    xvector<IntegerType> m_data;
#endif
    // m_modulus stores the internal modulus of the vector.
    IntegerType m_modulus = 0;

    // function to check if the index is a valid index.
    bool IndexCheck(size_t length) const {
        if (length > this->m_data.size()) {
            return false;
        }
        return true;
    }
};

}  // namespace intnat

namespace cereal {

//! Serialization for vector of NativeInteger

template <class Archive, class A>
inline void CEREAL_SAVE_FUNCTION_NAME(Archive& ar, std::vector<intnat::NativeIntegerT<uint64_t>, A> const& vec) {
    ar(make_size_tag(static_cast<cereal::size_type>(vec.size())));  // number of elements
    for (const auto& v : vec) {
        ar(v.ConvertToInt());
    }
}

#if defined(HAVE_INT128)
template <class Archive, class A>
inline void CEREAL_SAVE_FUNCTION_NAME(Archive& ar,
                                      std::vector<intnat::NativeIntegerT<unsigned __int128>, A> const& vec) {
    ar(make_size_tag(static_cast<cereal::size_type>(vec.size())));  // number of elements
    constexpr unsigned __int128 mask = (static_cast<unsigned __int128>(1) << 64) - 1;
    for (const auto& v : vec) {
        uint64_t vec[2];
        unsigned __int128 int128 = v.ConvertToInt();
        vec[0]                   = int128 & mask;  // least significant word
        vec[1]                   = int128 >> 64;   // most significant word
        ar(vec);
    }
}
#endif

//! Deserialization for vector of NativeInteger

template <class Archive, class A>
inline void CEREAL_LOAD_FUNCTION_NAME(Archive& ar, std::vector<intnat::NativeIntegerT<uint64_t>, A>& vec) {
    cereal::size_type size;
    ar(make_size_tag(size));
    vec.resize(static_cast<size_t>(size));
    for (auto& v : vec) {
        uint64_t b;
        ar(b);
        v = b;
    }
}

#if defined(HAVE_INT128)
template <class Archive, class A>
inline void CEREAL_LOAD_FUNCTION_NAME(Archive& ar, std::vector<intnat::NativeIntegerT<unsigned __int128>, A>& vec) {
    cereal::size_type size;
    ar(make_size_tag(size));
    vec.resize(static_cast<size_t>(size));
    for (auto& v : vec) {
        uint64_t vec[2];
        ar(vec);
        v = vec[1];  // most significant word
        v <<= 64;
        v += vec[0];  // least significant word
    }
}
#endif
}  // namespace cereal

#endif  // LBCRYPTO_MATH_HAL_INTNAT_MUBINTVECNAT_H
