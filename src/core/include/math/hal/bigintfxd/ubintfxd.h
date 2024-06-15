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
 * This file contains the vector manipulation functionality.
 * This file contains the main class for big integers: BigIntegerFixedT. Big integers
 * are represented as arrays of native usigned integers. The native integer type
 * is supplied as a template parameter. Currently implementations based on
 * uint8_t, uint16_t, and uint32_t are supported. The second template parameter
 * is the maximum bitwidth for the big integer.
 */

#include "config_core.h"
#ifdef WITH_BE2

    #ifndef LBCRYPTO_MATH_HAL_BIGINTFXD_UBINTFXD_H
        #define LBCRYPTO_MATH_HAL_BIGINTFXD_UBINTFXD_H

        #include <cstdlib>
        #include <cstring>
        #include <fstream>
        #include <functional>
        #include <iostream>
        #include <limits>
        #include <memory>
        #include <string>
        #include <type_traits>
        #include <typeinfo>
        #include <vector>

        #include "math/hal/basicint.h"
        #include "math/hal/integer.h"

        #include "utils/exception.h"
        #include "utils/inttypes.h"
        #include "utils/memory.h"
        #include "utils/openfhebase64.h"
        #include "utils/serializable.h"
        #include "utils/utilities.h"

////////// bigintfxd code
typedef uint32_t integral_dtype;

        /** Define the mapping for BigIntegerFixedT
    3500 is the maximum bit width supported by BigIntegers, large enough for
most use cases The bitwidth can be decreased to the least value still supporting
BigIntegerFixedT operations for a specific application - to achieve smaller runtimes
**/
        #ifndef BigIntegerBitLength
            #if (NATIVEINT < 128)
                #define BigIntegerBitLength 3500  // for 32-bit and 64-bit native backend
            #else
                #define BigIntegerBitLength 8000  // for 128-bit native backend
            #endif
        #endif

        #if BigIntegerBitLength < 600
            #error "BigIntegerBitLength is too small"
        #endif

/**
 * @namespace bigintfxd
 * The namespace of bigintfxd
 */
namespace bigintfxd {

using U64BITS = uint64_t;
        #if defined(HAVE_INT128)
using U128BITS = uint128_t;
        #endif

// forward declaration for aliases
template <typename uint_type, usint BITLENGTH>
class BigIntegerFixedT;

// Create default type for the MATHBACKEND 2 integer
using BigInteger = BigIntegerFixedT<integral_dtype, BigIntegerBitLength>;

/**The following structs are needed for initialization of BigIntegerFixedT at the
 *preprocessing stage. The structs compute certain values using template
 *metaprogramming approach and mostly follow recursion to calculate value(s).
 */

/**
 * @brief  Struct to find log value of N.
 *Needed in the preprocessing step of BigIntegerFixedT to determine bitwidth.
 *
 * @tparam N bitwidth.
 */
template <usint N>
struct Log2 {
    static const usint value = 1 + Log2<N / 2>::value;
};

/**
 * @brief Struct to find log value of N.
 *Base case for recursion.
 *Needed in the preprocessing step of BigIntegerFixedT to determine bitwidth.
 */
template <>
struct Log2<2> {
    static const usint value = 1;
};

/**
 * @brief Struct to find log value of U where U is a primitive datatype.
 *Needed in the preprocessing step of BigIntegerFixedT to determine bitwidth.
 *
 * @tparam U primitive data type.
 */
template <typename U>
struct LogDtype {
    static const usint value = Log2<8 * sizeof(U)>::value;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t,
 * uint32_t}
 *
 * @tparam Dtype primitive datatype.
 */
template <typename Dtype>
struct DataTypeChecker {
    static const bool value = false;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t,
 * uint32_t}. sets value true if datatype is unsigned integer 8 bit.
 */
template <>
struct DataTypeChecker<uint8_t> {
    static const bool value = true;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t,
 * uint32_t}. sets value true if datatype is unsigned integer 16 bit.
 */
template <>
struct DataTypeChecker<uint16_t> {
    static const bool value = true;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t,
 * uint32_t}. sets value true if datatype is unsigned integer 32 bit.
 */
template <>
struct DataTypeChecker<uint32_t> {
    static const bool value = true;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t,
 * uint32_t}. sets value true if datatype is unsigned integer 64 bit.
 */
template <>
struct DataTypeChecker<uint64_t> {
    static const bool value = true;
};

/**
 * @brief Struct for calculating bit width from data type.
 * Sets value to the bitwidth of uint_type
 *
 * @tparam uint_type native integer data type.
 */
template <typename uint_type>
struct UIntBitWidth {
    static const int value = 8 * sizeof(uint_type);
};

/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * sets T as of type void for default case
 *
 * @tparam utype primitive integer data type.
 */
template <typename utype>
struct DoubleDataType {
    typedef void T;
};

/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * Sets T as of type unsigned integer 16 bit if integral datatype is 8bit
 */
template <>
struct DoubleDataType<uint8_t> {
    typedef uint16_t T;
};

/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * sets T as of type unsigned integer 32 bit if integral datatype is 16bit
 */
template <>
struct DoubleDataType<uint16_t> {
    typedef uint32_t T;
};

/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * sets T as of type unsigned integer 64 bit if integral datatype is 32bit
 */
template <>
struct DoubleDataType<uint32_t> {
    typedef uint64_t T;
};

/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * sets T as of type unsigned integer 128 bit if integral datatype is 64bit
 */
template <>
struct DoubleDataType<uint64_t> {
        #if defined(HAVE_INT128)
    typedef uint128_t T;
        #else
    typedef uint64_t T;
        #endif
};

constexpr double LOG2_10 = 3.32192809;  //!< @brief A pre-computed constant of Log base 2 of 10.

/**
 * @brief Main class for big integers represented as an array of native
 * (primitive) unsigned integers
 * @tparam uint_type native unsigned integer type
 * @tparam BITLENGTH maximum bitwidth supported for big integers
 */
template <typename uint_type, usint BITLENGTH>
class BigIntegerFixedT : public lbcrypto::BigIntegerInterface<BigIntegerFixedT<uint_type, BITLENGTH>> {
public:
    // CONSTRUCTORS

    /**
   * Default constructor.
   */
    BigIntegerFixedT();

    /**
   * Copy constructor.
   *
   * @param &val is the big binary integer to be copied.
   */
    BigIntegerFixedT(const BigIntegerFixedT& val);

    /**
   * Move constructor.
   *
   * @param &&val is the big binary integer to be copied.
   */
    BigIntegerFixedT(BigIntegerFixedT&& val);

    /**
   * Constructor from a string.
   *
   * @param &strval is the initial integer represented as a string.
   */
    explicit BigIntegerFixedT(const std::string& strval);
    BigIntegerFixedT(const char* strval) : BigIntegerFixedT(std::string(strval)) {}  // NOLINT
    BigIntegerFixedT(const char val) : BigIntegerFixedT(uint64_t(val)) {}            // NOLINT

    /**
   * Constructor from an unsigned integer.
   *
   * @param val is the initial integer represented as a uint64_t.
   */
    BigIntegerFixedT(uint64_t val);  // NOLINT
        #if defined(HAVE_INT128)
    BigIntegerFixedT(U128BITS val);  // NOLINT
        #endif

    /**
   * Constructors from smaller basic types
   *
   * @param val is the initial integer represented as a basic integer type.
   */
    BigIntegerFixedT(int val) : BigIntegerFixedT(uint64_t(val)) {}        // NOLINT
    BigIntegerFixedT(uint32_t val) : BigIntegerFixedT(uint64_t(val)) {}   // NOLINT
    BigIntegerFixedT(long val) : BigIntegerFixedT(uint64_t(val)) {}       // NOLINT
    BigIntegerFixedT(long long val) : BigIntegerFixedT(uint64_t(val)) {}  // NOLINT

    /**
   * Constructor for all other types that have not already got their own constructors.
   * These other data types must have a member function ConvertToInt() defined.
   *
   * @param &val is the initial integer represented as a big integer.
   */
    template <typename T, typename std::enable_if<
                              !std::is_same<T, int>::value && !std::is_same<T, uint32_t>::value &&
                                  !std::is_same<T, uint64_t>::value && !std::is_same<T, long>::value &&  // NOLINT
                                  !std::is_same<T, long long>::value &&                                  // NOLINT
        #if defined(HAVE_INT128)
                                  !std::is_same<T, U128BITS>::value &&
        #endif
                                  !std::is_same<T, const std::string>::value && !std::is_same<T, const char*>::value &&
                                  !std::is_same<T, const char>::value && !std::is_same<T, BigIntegerFixedT>::value &&
                                  !std::is_same<T, double>::value,
                              bool>::type = true>
    BigIntegerFixedT(const T& val) : BigIntegerFixedT(val.ConvertToInt()) {  // NOLINT
    }

    /**
   * Constructor from double is not permitted
   *
   * @param val
   */
    BigIntegerFixedT(double val) __attribute__((deprecated("Cannot construct from a double")));  // NOLINT

    ~BigIntegerFixedT() {}

    // ASSIGNMENT OPERATORS

    /**
   * Copy assignment operator
   *
   * @param &val is the big binary integer to be assigned from.
   * @return assigned BigIntegerFixedT ref.
   */
    BigIntegerFixedT& operator=(const BigIntegerFixedT& val);

    /**
   * Move assignment operator
   *
   * @param &val is the big binary integer to be assigned from.
   * @return assigned BigIntegerFixedT ref.
   */
    BigIntegerFixedT& operator=(BigIntegerFixedT&& val);

    /**
   * Assignment operator for all other types that have not already got their own
   * assignment operators.
   * @param &val is the value to be assign from
   * @return the assigned BigIntegerFixedT ref.
   */
    BigIntegerFixedT& operator=(const std::string strval) {
        *this = BigIntegerFixedT(strval);
        return *this;
    }

    template <typename T, typename std::enable_if<!std::is_same<T, BigIntegerFixedT>::value &&
                                                      !std::is_same<T, const BigIntegerFixedT>::value,
                                                  bool>::type = true>
    BigIntegerFixedT& operator=(const T& val) {
        return (*this = BigIntegerFixedT(val));
    }

    // ACCESSORS

    /**
   * Basic set method for setting the value of a big binary integer
   *
   * @param strval is the string representation of the big binary integer to be
   * copied.
   */
    void SetValue(const std::string& strval);

    /**
   * Basic set method for setting the value of a big binary integer
   *
   * @param val is the big binary integer representation of the big binary
   * integer to be assigned.
   */
    void SetValue(const BigIntegerFixedT& val);

    /**
   *  Set this int to 1.
   */
    void SetIdentity() {
        *this = 1;
    }

    /**
   * Sets the int value at the specified index.
   *
   * @param index is the index of the int to set in the uint array.
   */
    void SetIntAtIndex(usint idx, uint_type value);

    // ARITHMETIC OPERATIONS

    /**
   * Addition operation.
   *
   * @param &b is the value to add.
   * @return result of the addition operation.
   */
    BigIntegerFixedT Add(const BigIntegerFixedT& b) const;

    /**
   * Addition operation. In-place variant.
   *
   * @param &b is the value to add.
   * @return result of the addition operation.
   */
    BigIntegerFixedT& AddEq(const BigIntegerFixedT& b);

    /**
   * Subtraction operation.
   *
   * @param &b is the value to subtract.
   * @return is the result of the subtraction operation.
   */
    BigIntegerFixedT Sub(const BigIntegerFixedT& b) const;

    /**
   * Subtraction operation. In-place variant.
   *
   * @param &b is the value to subtract.
   * @return is the result of the subtraction operation.
   */
    BigIntegerFixedT& SubEq(const BigIntegerFixedT& b);

    /**
   * Operator for unary minus
   * @return
   */
    BigIntegerFixedT operator-() const {
        return BigIntegerFixedT(0).Sub(*this);
    }

    /**
   * Multiplication operation.
   *
   * @param &b is the value to multiply with.
   * @return is the result of the multiplication operation.
   */
    BigIntegerFixedT Mul(const BigIntegerFixedT& b) const;

    /**
   * Multiplication operation. In-place variant.
   *
   * @param &b is the value to multiply with.
   * @return is the result of the multiplication operation.
   */
    BigIntegerFixedT& MulEq(const BigIntegerFixedT& b);

    /**
   * Division operation.
   *
   * @param &b is the value to divide by.
   * @return is the result of the division operation.
   */
    BigIntegerFixedT DividedBy(const BigIntegerFixedT& b) const;

    /**
   * Division operation. In-place variant.
   *
   * @param &b is the value to divide by.
   * @return is the result of the division operation.
   */
    BigIntegerFixedT& DividedByEq(const BigIntegerFixedT& b);

    /**
   * Exponentiation operation. Returns x^p.
   *
   * @param p the exponent.
   * @return is the result of the exponentiation operation.
   */
    BigIntegerFixedT Exp(usint p) const;

    /**
   * Exponentiation operation. Returns x^p. In-place variant.
   *
   * @param p the exponent.
   * @return is the result of the exponentiation operation.
   */
    BigIntegerFixedT& ExpEq(usint p);

    /**
   * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
   * operation.
   *
   * @param &p is the numerator to be multiplied.
   * @param &q is the denominator to be divided.
   * @return is the result of multiply and round operation.
   */
    BigIntegerFixedT MultiplyAndRound(const BigIntegerFixedT& p, const BigIntegerFixedT& q) const;

    /**
   * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
   * operation. In-place variant.
   *
   * @param &p is the numerator to be multiplied.
   * @param &q is the denominator to be divided.
   * @return is the result of multiply and round operation.
   */
    BigIntegerFixedT& MultiplyAndRoundEq(const BigIntegerFixedT& p, const BigIntegerFixedT& q);

    /**
   * Divide and Rounding operation. Returns [x/q] where [] is the rounding
   * operation.
   *
   * @param &q is the denominator to be divided.
   * @return is the result of divide and round operation.
   */
    BigIntegerFixedT DivideAndRound(const BigIntegerFixedT& q) const;

    /**
   * Divide and Rounding operation. Returns [x/q] where [] is the rounding
   * operation. In-place variant.
   *
   * @param &q is the denominator to be divided.
   * @return is the result of divide and round operation.
   */
    BigIntegerFixedT& DivideAndRoundEq(const BigIntegerFixedT& q);

    // MODULAR ARITHMETIC OPERATIONS

    /**
   * Naive modulus operation.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus operation.
   */
    BigIntegerFixedT Mod(const BigIntegerFixedT& modulus) const;

    /**
   * Naive modulus operation. In-place variant.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus operation.
   */
    BigIntegerFixedT& ModEq(const BigIntegerFixedT& modulus);

    /**
   * Pre-computes the mu factor that is used in Barrett modulo reduction
   *
   * @return the value of mu
   */
    BigIntegerFixedT ComputeMu() const;

    /**
   * Barrett modulus operation.
   * Implements generalized Barrett modular reduction algorithm. Uses one
   * precomputed value of mu.
   *
   * @param &modulus is the modulus to perform.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus operation.
   */
    BigIntegerFixedT Mod(const BigIntegerFixedT& modulus, const BigIntegerFixedT& mu) const;

    /**
   * Barrett modulus operation. In-place variant.
   * Implements generalized Barrett modular reduction algorithm. Uses one
   * precomputed value of mu.
   *
   * @param &modulus is the modulus to perform.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus operation.
   */
    BigIntegerFixedT& ModEq(const BigIntegerFixedT& modulus, const BigIntegerFixedT& mu);

    /**
   * Modulus addition operation.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
    BigIntegerFixedT ModAdd(const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) const;

    /**
   * Modulus addition operation. In-place variant.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
    BigIntegerFixedT& ModAddEq(const BigIntegerFixedT& b, const BigIntegerFixedT& modulus);

    /**
   * Modulus addition where operands are < modulus.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
    BigIntegerFixedT ModAddFast(const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) const;

    /**
   * Modulus addition where operands are < modulus. In-place variant.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
    BigIntegerFixedT& ModAddFastEq(const BigIntegerFixedT& b, const BigIntegerFixedT& modulus);

    /**
   * Barrett modulus addition operation.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus addition operation.
   */
    BigIntegerFixedT ModAdd(const BigIntegerFixedT& b, const BigIntegerFixedT& modulus,
                            const BigIntegerFixedT& mu) const;

    /**
   * Barrett modulus addition operation. In-place variant.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus addition operation.
   */
    BigIntegerFixedT& ModAddEq(const BigIntegerFixedT& b, const BigIntegerFixedT& modulus, const BigIntegerFixedT& mu);

    /**
   * Modulus subtraction operation.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
    BigIntegerFixedT ModSub(const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) const;

    /**
   * Modulus subtraction operation. In-place variant.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
    BigIntegerFixedT& ModSubEq(const BigIntegerFixedT& b, const BigIntegerFixedT& modulus);

    /**
   * Modulus subtraction where operands are < modulus.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
    BigIntegerFixedT ModSubFast(const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) const;

    /**
   * Modulus subtraction where operands are < modulus. In-place variant.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
    BigIntegerFixedT& ModSubFastEq(const BigIntegerFixedT& b, const BigIntegerFixedT& modulus);

    /**
   * Barrett modulus subtraction operation.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus subtraction operation.
   */
    BigIntegerFixedT ModSub(const BigIntegerFixedT& b, const BigIntegerFixedT& modulus,
                            const BigIntegerFixedT& mu) const;

    /**
   * Barrett modulus subtraction operation. In-place variant.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus subtraction operation.
   */
    BigIntegerFixedT& ModSubEq(const BigIntegerFixedT& b, const BigIntegerFixedT& modulus, const BigIntegerFixedT& mu);

    /**
   * Modulus multiplication operation.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
    BigIntegerFixedT ModMul(const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) const;

    /**
   * Modulus multiplication operation. In-place variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
    BigIntegerFixedT& ModMulEq(const BigIntegerFixedT& b, const BigIntegerFixedT& modulus);

    /**
   * Barrett modulus multiplication.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
    BigIntegerFixedT ModMul(const BigIntegerFixedT& b, const BigIntegerFixedT& modulus,
                            const BigIntegerFixedT& mu) const;

    /**
   * Barrett modulus multiplication. In-place variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
    BigIntegerFixedT& ModMulEq(const BigIntegerFixedT& b, const BigIntegerFixedT& modulus, const BigIntegerFixedT& mu);

    /**
   * Modulus multiplication that assumes the operands are < modulus.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
    BigIntegerFixedT ModMulFast(const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) const;

    /**
   * Modulus multiplication that assumes the operands are < modulus. In-place
   * variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
    BigIntegerFixedT& ModMulFastEq(const BigIntegerFixedT& b, const BigIntegerFixedT& modulus);

    /**
   * Barrett modulus multiplication that assumes the operands are < modulus.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
    BigIntegerFixedT ModMulFast(const BigIntegerFixedT& b, const BigIntegerFixedT& modulus,
                                const BigIntegerFixedT& mu) const;

    /**
   * Barrett modulus multiplication that assumes the operands are < modulus.
   * In-place variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
    BigIntegerFixedT& ModMulFastEq(const BigIntegerFixedT& b, const BigIntegerFixedT& modulus,
                                   const BigIntegerFixedT& mu);

    BigIntegerFixedT ModMulFastConst(const BigIntegerFixedT& b, const BigIntegerFixedT& modulus,
                                     const BigIntegerFixedT& bInv) const {
        OPENFHE_THROW("ModMulFastConst is not implemented for backend 2");
    }

    BigIntegerFixedT& ModMulFastConstEq(const BigIntegerFixedT& b, const BigIntegerFixedT& modulus,
                                        const BigIntegerFixedT& bInv) {
        OPENFHE_THROW("ModMulFastConstEq is not implemented for backend 2");
    }

    /**
   * Modulus exponentiation operation. Square-and-multiply algorithm is used.
   *
   * @param &b is the scalar to exponentiate at all locations.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus exponentiation operation.
   */
    BigIntegerFixedT ModExp(const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) const;

    /**
   * Modulus exponentiation operation. Square-and-multiply algorithm is used.
   * In-place variant.
   *
   * @param &b is the scalar to exponentiate at all locations.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus exponentiation operation.
   */
    BigIntegerFixedT& ModExpEq(const BigIntegerFixedT& b, const BigIntegerFixedT& modulus);

    /**
   * Modulus inverse operation.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus inverse operation.
   */
    BigIntegerFixedT ModInverse(const BigIntegerFixedT& modulus) const;

    /**
   * Modulus inverse operation. In-place variant.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus inverse operation.
   */
    BigIntegerFixedT& ModInverseEq(const BigIntegerFixedT& modulus);

    // SHIFT OPERATIONS

    /**
   * Left shift operation.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
    BigIntegerFixedT LShift(usshort shift) const;

    /**
   * Left shift operation. In-place variant.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
    BigIntegerFixedT& LShiftEq(usshort shift);

    /**
   * Right shift operation.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
    BigIntegerFixedT RShift(usshort shift) const;

    /**
   * Right shift operation. In-place variant.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
    BigIntegerFixedT& RShiftEq(usshort shift);

    // COMPARE

    /**
   * Compares the current BigIntegerFixedT to BigIntegerFixedT a.
   *
   * @param a is the BigIntegerFixedT to be compared with.
   * @return  -1 for strictly less than, 0 for equal to and 1 for strictly
   * greater than conditons.
   */
    int Compare(const BigIntegerFixedT& a) const;

    // CONVERTERS

    /**
   * Converts the value to an int.
   *
   * @return the int representation of the value as uint64_t.
   */
    // TODO (dsuponit): make ConvertToInt() a template utility function
    template <typename T             = BasicInteger,
              std::enable_if_t<std::is_integral_v<T> || std::is_same_v<T, int128_t> || std::is_same_v<T, uint128_t>,
                               bool> = true>
    T ConvertToInt() const {
        constexpr usint bits = sizeof(T) * CHAR_BIT;
        T result             = 0;
        // set num to number of equisized chunks
        usint num     = bits / m_uintBitLength;
        usint ceilInt = m_nSize - ceilIntByUInt(m_MSB);
        // copy the values by shift and add
        for (usint i = 0; i < num && (m_nSize - i - 1) >= ceilInt; i++) {
            result += ((T)this->m_value[m_nSize - i - 1] << (m_uintBitLength * i));
        }
        if (this->m_MSB > bits) {
            OPENFHE_THROW(std::string("MSB cannot be bigger than ") + std::to_string(bits));
        }
        return result;
    }

    /**
   * Converts the value to an double.
   *
   * @return double representation of the value.
   */
    double ConvertToDouble() const;

    /**
   * Convert a value from an int to a BigIntegerFixedT.
   *
   * @param m the value to convert from.
   * @return int represented as a big binary int.
   */
    static BigIntegerFixedT intToBigInteger(usint m);

    /**
   * Convert a string representation of a binary number to a decimal BigIntegerFixedT.
   *
   * @param bitString the binary num in string.
   * @return the binary number represented as a big binary int.
   */
    static BigIntegerFixedT FromBinaryString(const std::string& bitString);

    // OTHER FUNCTIONS

    /**
   * Returns the MSB location of the value.
   *
   * @return the index of the most significant bit.
   */
    usint GetMSB() const;

    /**
   * Get the number of digits using a specific base - support for arbitrary base
   * may be needed.
   *
   * @param base is the base with which to determine length in.
   * @return the length of the representation in a specific base.
   */
    usint GetLengthForBase(usint base) const {
        return GetMSB();
    }

    /**
   * Get a specific digit at "digit" index; big integer is seen as an array of
   * digits, where a 0 <= digit < base Warning: only power-of-2 bases are
   * currently supported. Example: for number 83, index 2 and base 4 we have:
   *
   *                         index:0,1,2,3
   * 83 --base 4 decomposition--> (3,0,1,1) --at index 2--> 1
   *
   * The return number is 1.
   *
   * @param index is the "digit" index of the requested digit
   * @param base is the base with which to determine length in.
   * @return is the requested digit
   */
    usint GetDigitAtIndexForBase(usint index, usint base) const;

    /**
   * Tests whether the BigIntegerFixedT is a power of 2.
   *
   * @param m_numToCheck is the value to check.
   * @return true if the input is a power of 2, false otherwise.
   */
    bool CheckIfPowerOfTwo(const BigIntegerFixedT& m_numToCheck);

    /**
   * Gets the bit at the specified index.
   *
   * @param index is the index of the bit to get.
   * @return resulting bit.
   */
    uschar GetBitAtIndex(usint index) const;

    /**
   * A zero allocator that is called by the Matrix class. It is used to
   * initialize a Matrix of BigIntegerFixedT objects.
   */
    static BigIntegerFixedT Allocator() {
        return BigIntegerFixedT(0);
    }

    // STRINGS & STREAMS

    /**
   * Stores the based 10 equivalent/Decimal value of the BigIntegerFixedT in a string
   * object and returns it.
   *
   * @return value of this BigIntegerFixedT in base 10 represented as a string.
   */
    const std::string ToString() const;

    static const std::string IntegerTypeName() {
        return "UBFIXINT";
    }

    /**
   * Delivers value of the internal limb storage
   * Used primarily for debugging
   * @return STL vector of uint_type
   */
    std::string GetInternalRepresentation(void) const {
        std::string ret("");
        size_t ceilInt  = ceilIntByUInt(this->m_MSB);  // max limb used
        size_t minIndex = static_cast<size_t>(m_nSize - ceilInt);

        for (size_t i = m_nSize - 1; i >= minIndex; i--) {
            ret += std::to_string(m_value[i]);
            if (i != minIndex)
                ret += " ";
        }
        return ret;
    }

    /**
   * Console output operation.
   *
   * @param os is the std ostream object.
   * @param ptr_obj is BigIntegerFixedT to be printed.
   * @return is the ostream object.
   */
    template <typename uint_type_c, usint BITLENGTH_c>
    friend std::ostream& operator<<(std::ostream& os, const BigIntegerFixedT<uint_type_c, BITLENGTH_c>& ptr_obj) {
        usint counter;
        // initiate to object to be printed
        auto print_obj = new BigIntegerFixedT<uint_type_c, BITLENGTH_c>(ptr_obj);
        // print_VALUE array stores the decimal value in the array
        uschar* print_VALUE = new uschar[ptr_obj.m_numDigitInPrintval];
        for (size_t i = 0; i < ptr_obj.m_numDigitInPrintval; i++) {
            // reset to zero
            *(print_VALUE + i) = 0;
        }
        // starts the conversion from base r to decimal value
        for (size_t i = print_obj->m_MSB; i > 0; i--) {
            // print_VALUE = print_VALUE*2
            BigIntegerFixedT<uint_type_c, BITLENGTH_c>::double_bitVal(print_VALUE);
            // adds the bit value to the print_VALUE
            BigIntegerFixedT<uint_type_c, BITLENGTH_c>::add_bitVal(print_VALUE, print_obj->GetBitAtIndex(i));
        }
        // find the first occurence of non-zero value in print_VALUE
        for (counter = 0; counter < ptr_obj.m_numDigitInPrintval - 1; counter++) {
            if (static_cast<int>(print_VALUE[counter]) != 0) {
                break;
            }
        }
        // start inserting values into the ostream object
        for (; counter < ptr_obj.m_numDigitInPrintval; counter++) {
            os << static_cast<int>(print_VALUE[counter]);
        }
        // deallocate the memory since values are inserted into the ostream object
        delete[] print_VALUE;
        delete print_obj;
        return os;
    }

    // SERIALIZATION

    template <class Archive>
    typename std::enable_if<!cereal::traits::is_text_archive<Archive>::value, void>::type save(
        Archive& ar, std::uint32_t const version) const {
        ar(::cereal::binary_data(m_value, sizeof(m_value)));
        ar(::cereal::binary_data(&m_MSB, sizeof(m_MSB)));
    }

    template <class Archive>
    typename std::enable_if<cereal::traits::is_text_archive<Archive>::value, void>::type save(
        Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("v", m_value));
        ar(::cereal::make_nvp("m", m_MSB));
    }

    template <class Archive>
    typename std::enable_if<!cereal::traits::is_text_archive<Archive>::value, void>::type load(
        Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::binary_data(m_value, sizeof(m_value)));
        ar(::cereal::binary_data(&m_MSB, sizeof(m_MSB)));
    }

    template <class Archive>
    typename std::enable_if<cereal::traits::is_text_archive<Archive>::value, void>::type load(
        Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("v", m_value));
        ar(::cereal::make_nvp("m", m_MSB));
    }

    std::string SerializedObjectName() const {
        return "FXDInteger";
    }

    static uint32_t SerializedVersion() {
        return 1;
    }

protected:
    /**
   * Converts the string v into base-r integer where r is equal to 2^bitwidth of
   * integral data type.
   *
   * @param v The input string
   */
    void AssignVal(const std::string& v);

    /**
   * Sets the MSB to the correct value from the BigIntegerFixedT.
   */
    void SetMSB();

    /**
   * Sets the MSB to the correct value from the BigIntegerFixedT.
   * @param guessIdxChar is the hint of the MSB position.
   */
    void SetMSB(usint guessIdxChar);

private:
    // array storing the native integers.
    // array size is the ceiling of BITLENGTH/(bits in the integral data type)
    uint_type m_value[(BITLENGTH + 8 * sizeof(uint_type) - 1) / (8 * sizeof(uint_type))];

    // variable that stores the MOST SIGNIFICANT BIT position in the number.
    usshort m_MSB;

    // variable to store the bit width of the integral data type.
    static const uschar m_uintBitLength;

    // variable to store the maximum value of the integral data type.
    static const uint_type m_uintMax;

    // variable to store the log(base 2) of the number of bits in the integral
    // data type.
    static const uschar m_logUintBitLength;

    // variable to store the size of the data array.
    static const usint m_nSize;

    // The maximum number of digits in BigIntegerFixedT. It is used by the cout(ostream)
    // function for printing the bigbinarynumber.
    static const usint m_numDigitInPrintval;

    /**
   * function to return the ceiling of the number divided by the number of bits
   * in the integral data type.
   * @param Number is the number to be divided.
   * @return the ceiling of Number/(bits in the integral data type)
   */
    static uint_type ceilIntByUInt(const uint_type Number);

    // currently unused array
    static const BigIntegerFixedT* m_modChain;

    /**
   * function to return the MSB of number.
   * @param x is the number.
   * @return the MSB position in the number x.
   */

    static usint GetMSBUint_type(uint_type x);

    // Duint_type is the data type that has twice as many bits in the integral
    // data type.
    typedef typename DoubleDataType<uint_type>::T Duint_type;

    /**
   * function to return the MSB of number that is of type Duint_type.
   * @param x is the number.
   * @return the MSB position in the number x.
   */
    static usint GetMSBDUint_type(Duint_type x);

    /**
   * function that returns the BigIntegerFixedT after multiplication by a uint.
   * @param b is the number to be multiplied.
   * @return the BigIntegerFixedT after the multiplication.
   */
    BigIntegerFixedT MulByUint(const uint_type b) const;

    /**
   * function that returns the BigIntegerFixedT after multiplication by a uint.
   * @param b is the number to be multiplied.
   * @return the BigIntegerFixedT after the multiplication.
   */
    void MulByUintToInt(const uint_type b, BigIntegerFixedT* ans) const;

    /**
   * function that returns the decimal value from the binary array a.
   * @param a is a pointer to the binary array.
   * @return the decimal value.
   */
    static uint_type UintInBinaryToDecimal(uschar* a);

    /**
   * function that mutiplies by 2 to the binary array.
   * @param a is a pointer to the binary array.
   */
    static void double_bitVal(uschar* a);

    /**
   * function that adds bit b to the binary array.
   * @param a is a pointer to the binary array.
   * @param b is a bit value to be added.
   */
    static void add_bitVal(uschar* a, uschar b);
};

}  // namespace bigintfxd

    #endif  // LBCRYPTO_MATH_HAL_BIGINTFXD_UBINTFXD_H

#endif
