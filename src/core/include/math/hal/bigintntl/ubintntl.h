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
  This file contains the C++ code for implementing the main class for big integers:
  gmpint which replaces BBI and uses NTL
 */

//==================================================================================
// This file is included only if WITH_NTL is set to ON in CMakeLists.txt
//==================================================================================
#include "config_core.h"
#ifdef WITH_NTL

    #ifndef LBCRYPTO_MATH_HAL_BIGINTNTL_UBINTNTL_H
        #define LBCRYPTO_MATH_HAL_BIGINTNTL_UBINTNTL_H

        #include <NTL/ZZ.h>
        #include <NTL/ZZ_limbs.h>

        #include "math/hal/basicint.h"
        #include "math/hal/integer.h"

        #include "utils/openfhebase64.h"
        #include "utils/parallel.h"
        #include "utils/serializable.h"
        #include "utils/exception.h"
        #include "utils/inttypes.h"
        #include "utils/memory.h"
        #include "utils/debug.h"

        #include <exception>
        #include <fstream>
        #include <functional>
        #include <iostream>
        #include <limits>
        #include <memory>
        #include <sstream>
        #include <string>
        #include <type_traits>
        #include <typeinfo>
        #include <vector>

/**
 *@namespace NTL
 * The namespace of this code
 */
namespace NTL {

// forward declaration for aliases
class myZZ;

// Create default type for the MATHBACKEND 6 integer
using BigInteger = myZZ;

// log2 constants
/**
 * @brief  Struct to find log value of N.
 *Needed in the preprocessing step of ubint to determine bitwidth.
 *
 * @tparam N bitwidth.
 */
template <usint N>
struct Log2 {
    static const usint value = 1 + Log2<N / 2>::value;
};

/**
 * @brief Struct to find log 2 value of N.
 *Base case for recursion.
 *Needed in the preprocessing step of ubint to determine bitwidth.
 */
template <>
struct Log2<2> {
    static const usint value = 1;
};

class myZZ : public NTL::ZZ, public lbcrypto::BigIntegerInterface<myZZ> {
public:
    // CONSTRUCTORS

    /**
   * Default constructor.
   */
    myZZ();

    /**
   * Copy constructor.
   *
   * @param &val is the ZZ to be copied.
   */
    myZZ(const NTL::ZZ& val);  // NOLINT

    /**
   * Move constructor.
   *
   * @param &&val is the ZZ to be copied.
   */
    myZZ(NTL::ZZ&& val);  // NOLINT

    // TODO: figure out how to do && for wrapper
    // myZZ(NTL::myZZ_p &&a);

    /**
   * Constructor from a string.
   *
   * @param &strval is the initial integer represented as a string.
   */
    explicit myZZ(const std::string& strval);
    explicit myZZ(const char* strval) : myZZ(std::string(strval)) {}

    /**
   * Constructor from an unsigned integer.
   *
   * @param val is the initial integer represented as a uint64_t.
   */
    myZZ(uint64_t val);  // NOLINT
        #if defined(HAVE_INT128)
    myZZ(uint128_t val);  // NOLINT
        #endif

    /**
   * Constructors from smaller basic types
   *
   * @param val is the initial integer represented as a basic integer type.
   */
    myZZ(int val) : myZZ(uint64_t(val)) {}        // NOLINT
    myZZ(uint32_t val) : myZZ(uint64_t(val)) {}   // NOLINT
    myZZ(long val) : myZZ(uint64_t(val)) {}       // NOLINT
    myZZ(long long val) : myZZ(uint64_t(val)) {}  // NOLINT

    /**
   * Constructor from a NativeInteger
   *
   * @param &val is the initial integer represented as a native integer.
   */
    template <typename T,
              typename std::enable_if<
                  !std::is_same<T, int>::value && !std::is_same<T, uint32_t>::value &&
                      !std::is_same<T, uint64_t>::value && !std::is_same<T, long>::value &&                // NOLINT
                      !std::is_same<T, long long>::value && !std::is_same<T, const std::string>::value &&  // NOLINT
                      !std::is_same<T, const char*>::value && !std::is_same<T, const char>::value &&
                      !std::is_same<T, myZZ>::value && !std::is_same<T, double>::value,
                  bool>::type = true>
    myZZ(const T& val) : myZZ(val.ConvertToInt()) {}  // NOLINT

    /**
   * Constructor from double is not permitted
   *
   * @param val
   */
    myZZ(double val) __attribute__((deprecated("Cannot construct from a double")));  // NOLINT

    // ASSIGNMENT OPERATORS

    /**
   * Copy assignment operator
   *
   * @param &val is the myZZ to be assigned from.
   * @return assigned myZZ ref.
   */
    myZZ& operator=(const myZZ& val);

    // TODO move assignment operator?

    /**
   * Assignment operator from string
   *
   * @param strval is the string to be assigned from
   * @return the assigned myZZ ref.
   */
    inline const myZZ& operator=(std::string strval) {
        *this = myZZ(strval);
        return *this;
    }

    /**
   * Assignment operator from unsigned integer
   *
   * @param val is the unsigned integer to be assigned from.
   * @return the assigned myZZ ref.
   */
    myZZ& operator=(uint64_t val) {
        *this = myZZ(val);
        return *this;
    }

    // ACCESSORS

    /**
   * Basic set method for setting the value of a myZZ
   *
   * @param strval is the string representation of the ubint to be copied.
   */
    void SetValue(const std::string& strval);

    /**
   * Basic set method for setting the value of a myZZ
   *
   * @param a is the unsigned big int representation to be assigned.
   */
    void SetValue(const myZZ& val);

    void SetIdentity() {
        *this = 1;
    }

    // ARITHMETIC OPERATIONS

    /**
   * Addition operation.
   *
   * @param &b is the value to add.
   * @return result of the addition operation.
   */
    myZZ Add(const myZZ& b) const {
        return *static_cast<const ZZ*>(this) + static_cast<const ZZ&>(b);
    }

    /**
   * Addition operation. In-place variant.
   *
   * @param &b is the value to add.
   * @return result of the addition operation.
   */
    myZZ& AddEq(const myZZ& b) {
        *static_cast<ZZ*>(this) += static_cast<const ZZ&>(b);
        return *this;
    }

    /**
   * Subtraction operation.
   * Note that in Sub we return 0, if a<b
   *
   * @param &b is the value to subtract.
   * @return is the result of the subtraction operation.
   */
    myZZ Sub(const myZZ& b) const {
        return (*this < b) ? ZZ(0) : (*static_cast<const ZZ*>(this) - static_cast<const ZZ&>(b));
    }

    /**
   * Subtraction operation. In-place variant.
   * Note that in Sub we return 0, if a<b
   *
   * @param &b is the value to subtract.
   * @return is the result of the subtraction operation.
   */
    myZZ& SubEq(const myZZ& b) {
        if (*this < b) {
            *this = ZZ(0);
        }
        else {
            *static_cast<ZZ*>(this) -= static_cast<const ZZ&>(b);
        }
        return *this;
    }

    /**
   * Multiplication operation.
   *
   * @param &b is the value to multiply with.
   * @return is the result of the multiplication operation.
   */
    myZZ Mul(const myZZ& b) const {
        return *static_cast<const ZZ*>(this) * static_cast<const ZZ&>(b);
    }

    /**
   * Multiplication operation. In-place variant.
   *
   * @param &b is the value to multiply with.
   * @return is the result of the multiplication operation.
   */
    myZZ& MulEq(const myZZ& b) {
        *static_cast<ZZ*>(this) *= static_cast<const ZZ&>(b);
        return *this;
    }

    /**
   * Division operation.
   *
   * @param &b is the value to divide by.
   * @return is the result of the division operation.
   */
    myZZ DividedBy(const myZZ& b) const {
        return *static_cast<const ZZ*>(this) / static_cast<const ZZ&>(b);
    }

    /**
   * Division operation. In-place variant.
   *
   * @param &b is the value to divide by.
   * @return is the result of the division operation.
   */
    myZZ& DividedByEq(const myZZ& b) {
        *static_cast<ZZ*>(this) /= static_cast<const ZZ&>(b);
        return *this;
    }

    /**
   * Exponentiation operation. Returns x^p.
   *
   * @param p the exponent.
   * @return is the result of the exponentiation operation.
   */
    myZZ Exp(const usint p) const {
        return power(*this, p);
    }

    /**
   * Exponentiation operation. Returns x^p. In-place variant.
   *
   * @param p the exponent.
   * @return is the result of the exponentiation operation.
   */
    myZZ& ExpEq(const usint p) {
        *this = power(*this, p);
        return *this;
    }

    /**
   * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
   * operation.
   *
   * @param &p is the numerator to be multiplied.
   * @param &q is the denominator to be divided.
   * @return is the result of multiply and round operation.
   */
    myZZ MultiplyAndRound(const myZZ& p, const myZZ& q) const;

    /**
   * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
   * operation. In-place variant.
   *
   * @param &p is the numerator to be multiplied.
   * @param &q is the denominator to be divided.
   * @return is the result of multiply and round operation.
   */
    myZZ& MultiplyAndRoundEq(const myZZ& p, const myZZ& q);

    /**
   * Divide and Rounding operation. Returns [x/q] where [] is the rounding
   * operation.
   *
   * @param &q is the denominator to be divided.
   * @return is the result of divide and round operation.
   */
    myZZ DivideAndRound(const myZZ& q) const;

    /**
   * Divide and Rounding operation. Returns [x/q] where [] is the rounding
   * operation. In-place variant.
   *
   * @param &q is the denominator to be divided.
   * @return is the result of divide and round operation.
   */
    myZZ& DivideAndRoundEq(const myZZ& q);

    // MODULAR ARITHMETIC OPERATIONS

    /**
   * Naive modulus operation.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus operation.
   */
    myZZ Mod(const myZZ& modulus) const {
        return *static_cast<const ZZ*>(this) % static_cast<const ZZ&>(modulus);
    }

    /**
   * Naive modulus operation. In-place variant.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus operation.
   */
    myZZ& ModEq(const myZZ& modulus) {
        *static_cast<ZZ*>(this) %= static_cast<const ZZ&>(modulus);
        return *this;
    }

    /**
   * Pre-computes the mu factor that is used in Barrett modulo reduction
   *
   * @return the value of mu
   */
    myZZ ComputeMu() const {
        myZZ temp(1);
        temp <<= (2 * this->GetMSB() + 3);
        return temp.DividedBy(*this);
        return temp;
    }

    /**
   * Barrett modulus operation.
   * Implements generalized Barrett modular reduction algorithm. Uses one
   * precomputed value of mu.
   *
   * @param &modulus is the modulus to perform.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus operation.
   */
    myZZ Mod(const myZZ& modulus, const myZZ& mu) const {
        return *static_cast<const ZZ*>(this) % static_cast<const ZZ&>(modulus);
    }

    /**
   * Barrett modulus operation. In-place variant.
   * Implements generalized Barrett modular reduction algorithm. Uses one
   * precomputed value of mu.
   *
   * @param &modulus is the modulus to perform.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus operation.
   */
    myZZ& ModEq(const myZZ& modulus, const myZZ& mu) {
        *static_cast<ZZ*>(this) %= static_cast<const ZZ&>(modulus);
        return *this;
    }

    /**
   * Modulus addition operation.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
    myZZ ModAdd(const myZZ& b, const myZZ& modulus) const {
        return AddMod(this->Mod(modulus), b.Mod(modulus), modulus);
    }

    /**
   * Modulus addition operation. In-place variant.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
    myZZ& ModAddEq(const myZZ& b, const myZZ& modulus) {
        AddMod(*this, this->Mod(modulus), b.Mod(modulus), modulus);
        return *this;
    }

    /**
   * Modulus addition where operands are < modulus.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
    myZZ ModAddFast(const myZZ& b, const myZZ& modulus) const {
        return AddMod(*this, b, modulus);
    }

    /**
   * Modulus addition where operands are < modulus. In-place variant.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
    myZZ& ModAddFastEq(const myZZ& b, const myZZ& modulus) {
        *this = AddMod(*this, b, modulus);
        return *this;
    }

    /**
   * Barrett modulus addition operation.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus addition operation.
   */
    myZZ ModAdd(const myZZ& b, const myZZ& modulus, const myZZ& mu) const {
        return AddMod(*this, b, modulus);
    }

    /**
   * Barrett modulus addition operation. In-place variant.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus addition operation.
   */
    myZZ& ModAddEq(const myZZ& b, const myZZ& modulus, const myZZ& mu) {
        *this = AddMod(*this, b, modulus);
        return *this;
    }

    /**
   * Modulus subtraction operation.
   * NOTE ModSub needs to return signed modulus (i.e. -1/2..q/2) in order
   * to be consistent with BE 2
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
    myZZ ModSub(const myZZ& b, const myZZ& modulus) const {
        myZZ newthis(*this % modulus);
        myZZ newb(b % modulus);
        if (newthis >= newb) {
            myZZ tmp(SubMod(newthis, newb, modulus));  // normal mod sub
            return tmp;
        }
        else {
            myZZ tmp(newthis + modulus - newb);  // signed mod
            return tmp;
        }
    }

    /**
   * Modulus subtraction operation. In-place variant.
   * NOTE ModSub needs to return signed modulus (i.e. -1/2..q/2) in order
   * to be consistent with BE 2
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
    myZZ& ModSubEq(const myZZ& b, const myZZ& modulus) {
        this->ModEq(modulus);
        myZZ newb(b % modulus);
        if (*this >= newb) {
            SubMod(*this, *this, newb, modulus);  // normal mod sub
            return *this;
        }
        else {
            this->AddEq(modulus);
            this->SubEq(newb);  // signed mod
            return *this;
        }
    }

    /**
   * Modulus subtraction where operands are < modulus.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
    myZZ ModSubFast(const myZZ& b, const myZZ& modulus) const {
        if (*this >= b) {
            return SubMod(*this, b, modulus);  // normal mod sub
        }
        else {
            return (*this + modulus - b);  // signed mod
        }
    }

    /**
   * Modulus subtraction where operands are < modulus. In-place variant.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
    myZZ& ModSubFastEq(const myZZ& b, const myZZ& modulus) {
        if (*this >= b) {
            return *this = SubMod(*this, b, modulus);  // normal mod sub
        }
        else {
            return *this = (*this + modulus - b);  // signed mod
        }
    }

    /**
   * Barrett modulus subtraction operation.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus subtraction operation.
   */
    myZZ ModSub(const myZZ& b, const myZZ& modulus, const myZZ& mu) const {
        myZZ newthis(*this % modulus);
        myZZ newb(b % modulus);
        if (newthis >= newb) {
            myZZ tmp(SubMod(newthis, newb, modulus));  // normal mod sub
            return tmp;
        }
        else {
            myZZ tmp(newthis + modulus - newb);  // signed mod
            return tmp;
        }
    }

    /**
   * Barrett modulus subtraction operation. In-place variant.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus subtraction operation.
   */
    myZZ& ModSubEq(const myZZ& b, const myZZ& modulus, const myZZ& mu) {
        this->ModEq(modulus);
        myZZ newb(b % modulus);
        if (*this >= newb) {
            SubMod(*this, *this, newb, modulus);  // normal mod sub
            return *this;
        }
        else {
            this->AddEq(modulus);
            this->SubEq(newb);  // signed mod
            return *this;
        }
    }

    /**
   * Modulus multiplication operation.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
    myZZ ModMul(const myZZ& b, const myZZ& modulus) const {
        return MulMod(this->Mod(modulus), b.Mod(modulus), modulus);
    }

    /**
   * Modulus multiplication operation. In-place variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
    myZZ& ModMulEq(const myZZ& b, const myZZ& modulus) {
        MulMod(*this, this->Mod(modulus), b.Mod(modulus), modulus);
        return *this;
    }

    /**
   * Barrett modulus multiplication.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
    myZZ ModMul(const myZZ& b, const myZZ& modulus, const myZZ& mu) const {
        return MulMod(this->Mod(modulus), b.Mod(modulus), modulus);
    }

    /**
   * Barrett modulus multiplication. In-place variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
    myZZ& ModMulEq(const myZZ& b, const myZZ& modulus, const myZZ& mu) {
        MulMod(*this, this->Mod(modulus), b.Mod(modulus), modulus);
        return *this;
    }

    /**
   * Modulus multiplication that assumes the operands are < modulus.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
    inline myZZ ModMulFast(const myZZ& b, const myZZ& modulus) const {
        return MulMod(*this, b, modulus);
    }

    /**
   * Modulus multiplication that assumes the operands are < modulus. In-place
   * variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
    myZZ& ModMulFastEq(const myZZ& b, const myZZ& modulus) {
        *this = MulMod(*this, b, modulus);
        return *this;
    }

    /**
   * Barrett modulus multiplication that assumes the operands are < modulus.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
    inline myZZ ModMulFast(const myZZ& b, const myZZ& modulus, const myZZ& mu) const {
        return MulMod(*this, b, modulus);
    }

    /**
   * Barrett modulus multiplication that assumes the operands are < modulus.
   * In-place variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
    myZZ& ModMulFastEq(const myZZ& b, const myZZ& modulus, const myZZ& mu) {
        *this = MulMod(*this, b, modulus);
        return *this;
    }

    myZZ ModMulFastConst(const myZZ& b, const myZZ& modulus, const myZZ& bInv) const {
        OPENFHE_THROW(lbcrypto::not_implemented_error, "ModMulFastConst is not implemented for backend 6");
    }

    myZZ& ModMulFastConstEq(const myZZ& b, const myZZ& modulus, const myZZ& bInv) {
        OPENFHE_THROW(lbcrypto::not_implemented_error, "ModMulFastConstEq is not implemented for backend 6");
    }

    /**
   * Modulus exponentiation operation.
   *
   * @param &b is the scalar to exponentiate at all locations.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus exponentiation operation.
   */
    inline myZZ ModExp(const myZZ& b, const myZZ& modulus) const {
        myZZ res;
        PowerMod(res, *this, b, modulus);
        return res;
    }

    /**
   * Modulus exponentiation operation. In-place variant.
   *
   * @param &b is the scalar to exponentiate at all locations.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus exponentiation operation.
   */
    myZZ& ModExpEq(const myZZ& b, const myZZ& modulus) {
        PowerMod(*this, *this, b, modulus);
        return *this;
    }

    /**
   * Modulus inverse operation.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus inverse operation.
   */
    myZZ ModInverse(const myZZ& modulus) const {
        if (modulus == myZZ(0)) {
            OPENFHE_THROW(lbcrypto::math_error, "zero has no inverse");
        }
        myZZ tmp(0);
        try {
            tmp = InvMod(*this % modulus, modulus);
        }
        catch (InvModErrorObject& e) {  // note this code requires NTL Excptions coto be turned
                                        // on. TODO: provide alternative when that is off.
            std::stringstream errmsg;
            errmsg << "ModInverse exception "
                   << " this: " << *this << " modulus: " << modulus << "GCD(" << e.get_a() << "," << e.get_n() << "!=1"
                   << std::endl;
            OPENFHE_THROW(lbcrypto::math_error, errmsg.str());
        }
        return tmp;
    }

    /**
   * Modulus inverse operation. In-place variant.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus inverse operation.
   */
    myZZ& ModInverseEq(const myZZ& modulus) {
        if (modulus == myZZ(0)) {
            OPENFHE_THROW(lbcrypto::math_error, "zero has no inverse");
        }
        try {
            *this = InvMod(*this % modulus, modulus);
        }
        catch (InvModErrorObject& e) {  // note this code requires NTL Excptions coto be turned
                                        // on. TODO: provide alternative when that is off.
            std::stringstream errmsg;
            errmsg << "ModInverse exception "
                   << " this: " << *this << " modulus: " << modulus << "GCD(" << e.get_a() << "," << e.get_n() << "!=1"
                   << std::endl;
            OPENFHE_THROW(lbcrypto::math_error, errmsg.str());
        }
        return *this;
    }

    /**
   * Left shift operation.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
    myZZ LShift(usshort shift) const {
        return *static_cast<const ZZ*>(this) << shift;
    }

    /**
   * Left shift operation. In-place variant.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
    myZZ& LShiftEq(usshort shift) {
        *static_cast<ZZ*>(this) <<= shift;
        return *this;
    }

    /**
   * Right shift operation.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
    myZZ RShift(usshort shift) const {
        return *static_cast<const ZZ*>(this) >> shift;
    }

    /**
   * Right shift operation. In-place variant.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
    myZZ& RShiftEq(usshort shift) {
        *static_cast<ZZ*>(this) >>= shift;
        return *this;
    }

    // COMPARE

    // comparison method inline for speed
    int Compare(const myZZ& a) const {
        return compare(*this, a);
    }

    // CONVERTING

    // OpenFHE conversion methods
    template <typename T = BasicInteger>
    T ConvertToInt() const {
        std::stringstream s;  // slower
        s << *this;
        T result;
        s >> result;

        if ((this->GetMSB() > (sizeof(T) * 8)) || (this->GetMSB() > NTL_ZZ_NBITS)) {
            std::cerr << "Warning myZZ::ConvertToInt() Loss of precision. " << std::endl;
            std::cerr << "input  " << *this << std::endl;
            std::cerr << "result  " << result << std::endl;
        }
        return result;
    }
    uint64_t ConvertToUint64() const;
    double ConvertToDouble() const;

    /**
   * Convert a string representation of a binary number to a myZZ.
   * Note: needs renaming to a generic form since the variable type name is
   * embedded in the function name. Suggest FromBinaryString()
   * @param bitString the binary num in string.
   * @return the  number represented as a ubint.
   */
    static myZZ FromBinaryString(const std::string& bitString);

    // OTHER FUNCTIONS

    // adapter kit that wraps ZZ with BACKEND 2 functionality

    static const myZZ& zero();

    usint GetMSB() const;

    /**
   * Get the number of digits using a specific base - support for
   * arbitrary base may be needed.
   *
   * @param base is the base with which to determine length in.
   * @return the length of the representation in a specific base.
   */
    usint GetLengthForBase(usint base) const {
        return GetMSB();
    }

    /**
   * Get the integer value of the of a subfield of bits. Where the length of
   * the field is specifice by a power of two base
   * Warning: only power-of-2 bases are currently supported.
   * Example: for number 83, index 2 and base 4 we have:
   *
   *                         index:0,1,2,3
   * 83 --base 4 decomposition--> (3,0,1,1) --at index 2--> 1
   *
   * The return number is 1.
   *
   * @param index is the bit location (lsb)
   * @param base such that log2(base)+1 is the bitwidth of the subfield
   * @return the unsigned integer value of the subfield
   */
    usint GetDigitAtIndexForBase(usint index, usint base) const;

    // variable to store the log(base 2) of the number of bits in the
    // limb data type.
    static const usint m_log2LimbBitLength;

    /**
   * Gets a subset of bits of a given length with LSB at specified index.
   * optimized for speed in backend 6
   * @param index of the set of bit to get. LSB=1
   * @param length of the set of bits to get. LSB=1
   * @return resulting unsigned in formed by set of bits.
   */
    usint GetBitRangeAtIndex(usint index, usint length) const;

    /**
   * Gets the bit at the specified index.
   *
   * @param index of the bit to get. LSB=1
   * @return resulting bit.
   */
    uschar GetBitAtIndex(usint index) const;

    /**
   * A zero allocator that is called by the Matrix class. It is used to
   * initialize a Matrix of myZZ objects.
   */
    static myZZ Allocator() {
        return 0;
    }

    // STRINGS & STREAMS

    // OpenFHE string conversion
    const std::string ToString() const;

    static const std::string IntegerTypeName() {
        return "UBNTLINT";
    }

    // big integer stream output
    friend std::ostream& operator<<(std::ostream& os, const myZZ& ptr_obj);

    /**
   * Gets a copy of the  internal limb storage
   * Used primarily for debugging
   */
    std::string GetInternalRepresentation(void) const {
        std::string ret("");
        const ZZ_limb_t* zlp = ZZ_limbs_get(*this);

        size_t max = static_cast<size_t>(this->size());
        for (size_t i = 0; i < max; i++) {
            ret += std::to_string(zlp[i]);
            if (i < (max - 1)) {
                ret += " ";
            }
        }
        return ret;
    }

    /// SERIALIZATION

    template <class Archive>
    typename std::enable_if<!cereal::traits::is_text_archive<Archive>::value, void>::type save(
        Archive& ar, std::uint32_t const version) const {
        void* data              = this->rep.rep;
        ::cereal::size_type len = 0;
        if (data == nullptr) {
            ar(::cereal::binary_data(&len, sizeof(len)));
        }
        else {
            len = _ntl_ALLOC(this->rep.rep);

            ar(::cereal::binary_data(&len, sizeof(len)));
            ar(::cereal::binary_data(data, len * sizeof(_ntl_gbigint)));
            ar(::cereal::make_nvp("mb", m_MSB));
        }
    }

    template <class Archive>
    typename std::enable_if<cereal::traits::is_text_archive<Archive>::value, void>::type save(
        Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("v", ToString()));
    }

    template <class Archive>
    typename std::enable_if<!cereal::traits::is_text_archive<Archive>::value, void>::type load(
        Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(lbcrypto::deserialize_error, "serialized object version " + std::to_string(version) +
                                                           " is from a later version of the library");
        }
        ::cereal::size_type len;
        ar(::cereal::binary_data(&len, sizeof(len)));
        if (len == 0) {
            *this = 0;
            return;
        }

        void* mem = malloc(len * sizeof(_ntl_gbigint));
        ar(::cereal::binary_data(mem, len * sizeof(_ntl_gbigint)));
        WrappedPtr<_ntl_gbigint_body, Deleter> newrep;
        newrep.rep = reinterpret_cast<_ntl_gbigint_body*>(mem);
        _ntl_gswap(&this->rep, &newrep);

        ar(::cereal::make_nvp("mb", m_MSB));
    }

    template <class Archive>
    typename std::enable_if<cereal::traits::is_text_archive<Archive>::value, void>::type load(
        Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(lbcrypto::deserialize_error, "serialized object version " + std::to_string(version) +
                                                           " is from a later version of the library");
        }
        std::string s;
        ar(::cereal::make_nvp("v", s));
        *this = s;
    }

    std::string SerializedObjectName() const {
        return "NTLInteger";
    }

    static uint32_t SerializedVersion() {
        return 1;
    }

private:
    // adapter kits
    void SetMSB();

    /**
   * function to return the ceiling of the input number divided by
   * the number of bits in the limb data type.  DBC this is to
   * determine how many limbs are needed for an input bitsize.
   * @param Number is the number to be divided.
   * @return the ceiling of Number/(bits in the limb data type)
   */
    // todo: rename to MSB2NLimbs()
    static usint ceilIntByUInt(const ZZ_limb_t Number);

    mutable ::cereal::size_type m_MSB;
    usint GetMSBLimb_t(ZZ_limb_t x) const;
};
// class ends

NTL_DECLARE_RELOCATABLE((myZZ*))
}  // namespace NTL

    #endif  // LBCRYPTO_MATH_HAL_BIGINTNTL_UBINTNTL_H

#endif  // WITH_NTL
