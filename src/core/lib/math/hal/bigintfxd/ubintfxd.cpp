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
  This class provides a class for big integers
 */

#include "config_core.h"
#ifdef WITH_BE2

    #include "math/math-hal.h"

    #include "utils/exception.h"
    #include "utils/serializable.h"

namespace bigintfxd {

// MOST REQUIRED STATIC CONSTANTS INITIALIZATION

// constant static member variable initialization of m_uintBitLength which is
// equal to number of bits in the unit data type permitted values: 8,16,32
template <typename uint_type, usint BITLENGTH>
const uschar BigIntegerFixedT<uint_type, BITLENGTH>::m_uintBitLength = UIntBitWidth<uint_type>::value;

template <typename uint_type, usint BITLENGTH>
const usint BigIntegerFixedT<uint_type, BITLENGTH>::m_numDigitInPrintval = BITLENGTH / bigintfxd::LOG2_10;

// constant static member variable initialization of m_logUintBitLength which is
// equal to log of number of bits in the unit data type permitted values: 3,4,5
template <typename uint_type, usint BITLENGTH>
const uschar BigIntegerFixedT<uint_type, BITLENGTH>::m_logUintBitLength = LogDtype<uint_type>::value;

// constant static member variable initialization of m_nSize which is size of
// the array of unit data type
template <typename uint_type, usint BITLENGTH>
const usint BigIntegerFixedT<uint_type, BITLENGTH>::m_nSize =
    BITLENGTH % m_uintBitLength == 0 ? BITLENGTH / m_uintBitLength : BITLENGTH / m_uintBitLength + 1;

// constant static member variable initialization of m_uintMax which is maximum
// value of unit data type
template <typename uint_type, usint BITLENGTH>
const uint_type BigIntegerFixedT<uint_type, BITLENGTH>::m_uintMax = std::numeric_limits<uint_type>::max();

// CONSTRUCTORS

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>::BigIntegerFixedT() {
    memset(this->m_value, 0, sizeof(this->m_value));
    this->m_MSB = 0;  // MSB set to zero since value set to 0
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>::BigIntegerFixedT(const BigIntegerFixedT& val) {
    m_MSB = val.m_MSB;
    for (size_t i = 0; i < m_nSize; ++i) {  // copy array values
        m_value[i] = val.m_value[i];
    }
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>::BigIntegerFixedT(BigIntegerFixedT&& val) {
    m_MSB = std::move(val.m_MSB);
    for (size_t i = 0; i < m_nSize; ++i) {
        m_value[i] = std::move(val.m_value[i]);
    }
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>::BigIntegerFixedT(const std::string& strval) {
    AssignVal(strval);  // setting the array values from the string
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>::BigIntegerFixedT(uint64_t val) {
    usint msb   = lbcrypto::GetMSB64(val);
    this->m_MSB = msb;

    uint_type ceilInt = ceilIntByUInt(msb);
    int i             = m_nSize - 1;

    for (; i >= static_cast<int>(m_nSize - ceilInt); i--) {  // setting the values of the array
        this->m_value[i] = (uint_type)val;
        val >>= m_uintBitLength;
    }
    for (; i >= 0; i--) {
        this->m_value[i] = 0;
    }
}

    #if defined(HAVE_INT128)
template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>::BigIntegerFixedT(U128BITS val) {
    m_MSB = lbcrypto::GetMSB(val);

    uint_type ceilInt = ceilIntByUInt(m_MSB);
    int i             = m_nSize - 1;
    for (; i >= static_cast<int>(m_nSize - ceilInt); i--) {
        this->m_value[i] = (uint_type)val;
        val >>= m_uintBitLength;
    }
    for (; i >= 0; i--) {
        this->m_value[i] = 0;
    }
}
    #endif

/*
template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>::BigIntegerFixedT(const NativeInteger &val)
    : BigIntegerFixedT(val.ConvertToInt()) {}
*/

// ASSIGNMENT OPERATORS

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::operator=(const BigIntegerFixedT& val) {
    if (this != &val) {
        this->m_MSB = val.m_MSB;
        for (size_t i = 0; i < m_nSize; ++i) {
            m_value[i] = val.m_value[i];
        }
    }
    return *this;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::operator=(BigIntegerFixedT&& val) {
    if (this != &val) {
        this->m_MSB = std::move(val.m_MSB);
        for (size_t i = 0; i < m_nSize; i++) {
            this->m_value[i] = std::move(val.m_value[i]);
        }
    }
    return *this;
}

// ACCESSORS

template <typename uint_type, usint BITLENGTH>
void BigIntegerFixedT<uint_type, BITLENGTH>::SetValue(const std::string& str) {
    AssignVal(str);
}

template <typename uint_type, usint BITLENGTH>
void BigIntegerFixedT<uint_type, BITLENGTH>::SetValue(const BigIntegerFixedT& a) {
    *this = a;
}

template <typename uint_type, usint BITLENGTH>
void BigIntegerFixedT<uint_type, BITLENGTH>::SetIntAtIndex(usint idx, uint_type value) {
    if (idx >= m_nSize) {
        OPENFHE_THROW(lbcrypto::math_error, "Index invalid");
    }
    this->m_value[idx] = value;
}

// ARITHMETIC OPERATIONS

/* Addition operation:
 *  Algorithm used is usual school book sum and carry-over, expect for that
 * radix is 2^m_bitLength.
 */
template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::Add(const BigIntegerFixedT& b) const {
    // two operands A and B for addition, A is the greater one, B is the smaller
    // one
    const BigIntegerFixedT* A = nullptr;
    const BigIntegerFixedT* B = nullptr;

    // Assignment of pointers, A assigned the higher value and B assigned the
    // lower value
    if (*this > b) {
        A = this;
        B = &b;
    }
    else {
        A = &b;
        B = this;
    }

    if (B->m_MSB == 0) {
        return BigIntegerFixedT(*A);
    }

    BigIntegerFixedT result;
    Duint_type ofl     = 0;                        // overflow variable
    uint_type ceilIntA = ceilIntByUInt(A->m_MSB);  // position from A to start addition
    uint_type ceilIntB = ceilIntByUInt(B->m_MSB);  // position from B to start addition
    size_t i;                                      // counter
    // DTS: TODO: verify that the sign/unsigned compare is valid here. it seems to
    // have the same form as the bugs fixed above, but i did not observe any
    // crashes in this function (perhaps it was never exercised) a safer
    // alternative would be something like what follows (the loops i fixed above
    // could use the same structure; note all variables become unsigned and all
    // loop indices start from zero): for (usint j = 0; j < m_nSize - CeilIntB
    // /*&& j < m_nSize*/; ++j) {
    //    usint i = m_nSize - 1 -j ;
    //    ...
    // }
    for (i = m_nSize - 1; i >= m_nSize - ceilIntB; i--) {
        ofl = (Duint_type)A->m_value[i] + (Duint_type)B->m_value[i] + ofl;  // sum of the two int and the carry over
        result.m_value[i] = (uint_type)ofl;
        ofl >>= m_uintBitLength;  // current overflow
    }

    if (ofl) {
        for (; i >= m_nSize - ceilIntA; i--) {
            ofl               = (Duint_type)A->m_value[i] + ofl;  // sum of the two int and the carry over
            result.m_value[i] = (uint_type)ofl;
            ofl >>= m_uintBitLength;  // current overflow
        }

        if (ofl) {  // in the end if overflow is set it indicates MSB is one greater
                    // than the one we started with
            result.m_value[m_nSize - ceilIntA - 1] = 1;
            result.m_MSB                           = A->m_MSB + 1;
        }
        else {
            result.m_MSB = (m_nSize - i - 2) * m_uintBitLength;
            result.m_MSB += GetMSBUint_type(result.m_value[++i]);
        }
    }
    else {
        for (; i >= m_nSize - ceilIntA; i--) {
            result.m_value[i] = A->m_value[i];
        }
        result.m_MSB = (m_nSize - i - 2) * m_uintBitLength;
        result.m_MSB += GetMSBUint_type(result.m_value[++i]);
    }
    return result;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::AddEq(const BigIntegerFixedT& b) {
    // check for trivial conditions
    if (b.m_MSB == 0) {
        return *this;
    }
    if (this->m_MSB == 0) {
        return *this = b;
    }

    Duint_type ofl = 0;  // overflow variable
    uint_type firstLoopCeil, secondLoopCeil;
    size_t i;  // counter

    const BigIntegerFixedT* larger = nullptr;
    if (*this > b) {
        larger         = this;
        firstLoopCeil  = ceilIntByUInt(b.m_MSB);
        secondLoopCeil = ceilIntByUInt(this->m_MSB);
    }
    else {
        larger         = &b;
        firstLoopCeil  = ceilIntByUInt(this->m_MSB);
        secondLoopCeil = ceilIntByUInt(b.m_MSB);
    }

    for (i = m_nSize - 1; i >= m_nSize - firstLoopCeil; i--) {
        ofl = (Duint_type)this->m_value[i] + (Duint_type)b.m_value[i] + ofl;  // sum of the two int and the carry over
        this->m_value[i] = (uint_type)ofl;
        ofl >>= m_uintBitLength;  // current overflow
    }

    if (ofl) {
        for (; i >= m_nSize - secondLoopCeil; i--) {
            ofl              = (Duint_type)larger->m_value[i] + ofl;  // sum of the two int and the carry over
            this->m_value[i] = (uint_type)ofl;
            ofl >>= m_uintBitLength;  // current overflow
        }

        if (ofl) {  // in the end if overflow is set it indicates MSB is one greater
                    // than the one we started with
            this->m_value[m_nSize - secondLoopCeil - 1] = 1;
            this->m_MSB                                 = larger->m_MSB + 1;
        }
        else {
            this->m_MSB = (m_nSize - i - 2) * m_uintBitLength;
            this->m_MSB += GetMSBUint_type(this->m_value[++i]);
        }
    }
    else {
        for (; i >= m_nSize - secondLoopCeil; i--) {
            this->m_value[i] = larger->m_value[i];
        }
        this->m_MSB = (m_nSize - i - 2) * m_uintBitLength;
        this->m_MSB += GetMSBUint_type(this->m_value[++i]);
    }
    return *this;
}

/* Subtraction operation:
 *  Algorithm used is usual school book borrow and subtract, except for that
 * radix is 2^m_bitLength.
 */
template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::Sub(const BigIntegerFixedT& b) const {
    // return 0 if b is higher than *this as there is no support for negative
    // number
    if (!(*this > b)) {
        //    OPENFHE_THROW(lbcrypto::not_implemented_error,
        //        "there is no support if the minuend is smaller
        // than the subtrahend");
        return 0;
    }

    // DTS: note: these variables are confusing. if you look close you will find
    // (a) they are only inside the inner if block (cntr=0 is superfluous); (b)
    // current simply equals i (neither changes after the current=i assignment);
    // and (c) the while loop needs to check cntr >= 0 (when m_value[] == 0...)
    int cntr = 0, current = 0;
    // DTS: (see Add(), above) this function uses [signed] int for endValA and
    // endValB, unlike all the similar loops in the previous functions
    BigIntegerFixedT result(*this);
    // array position in A to end subtraction
    volatile int endValA = m_nSize - ceilIntByUInt(this->m_MSB);
    // array position in B to end subtraction
    int endValB = m_nSize - ceilIntByUInt(b.m_MSB);
    int i;
    for (i = m_nSize - 1; i >= endValB; i--) {
        // carryover condtion
        if (result.m_value[i] < b.m_value[i]) {
            current = i;
            cntr    = current - 1;
            // assigning carryover value
            // DTS: added check against cntr being < 0 (I think)
            while (cntr >= 0 && result.m_value[cntr] == 0) {
                result.m_value[cntr] = m_uintMax;
                cntr--;
            }
            // DTS: probably need to check cntr >= 0 here, too
            result.m_value[cntr]--;
            result.m_value[i] = result.m_value[i] + m_uintMax + 1 - b.m_value[i];
        }
        else {
            // usual subtraction condition
            result.m_value[i] = result.m_value[i] - b.m_value[i];
        }
        cntr = 0;
    }
    while (result.m_value[endValA] == 0) {
        endValA++;
    }
    // reset the MSB after subtraction
    result.m_MSB = (m_nSize - endValA - 1) * m_uintBitLength + GetMSBUint_type(result.m_value[endValA]);
    // return the result
    return result;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::SubEq(const BigIntegerFixedT& b) {
    // return 0 if b is higher than *this as there is no support for negative
    // number
    if (!(*this > b)) {
        //    OPENFHE_THROW(lbcrypto::not_implemented_error,
        //        "there is no support if the minuend is smaller
        // than the subtrahend");
        *this = BigIntegerFixedT(0);
        return *this;
    }
    // DTS: note: these variables are confusing. if you look close you will find
    // (a) they are only inside the inner if block (cntr=0 is superfluous); (b)
    // current simply equals i (neither changes after the current=i assignment);
    // and (c) the while loop needs to check cntr >= 0 (when m_value[] == 0...)
    int cntr = 0, current = 0;
    // array position in A to end subtraction
    volatile int endValA = m_nSize - ceilIntByUInt(this->m_MSB);
    // array position in B to end subtraction
    int endValB = m_nSize - ceilIntByUInt(b.m_MSB);
    int i;
    for (i = m_nSize - 1; i >= endValB; i--) {
        // carryover condtion
        if (this->m_value[i] < b.m_value[i]) {
            current = i;
            cntr    = current - 1;
            // assigning carryover value
            // DTS: added check against cntr being < 0 (I think)
            while (cntr >= 0 && this->m_value[cntr] == 0) {
                this->m_value[cntr] = m_uintMax;
                cntr--;
            }
            // DTS: probably need to check cntr >= 0 here, too
            this->m_value[cntr]--;
            this->m_value[i] = this->m_value[i] + m_uintMax + 1 - b.m_value[i];
        }
        else {
            // usual subtraction condition
            this->m_value[i] = this->m_value[i] - b.m_value[i];
        }
        cntr = 0;
    }
    while (this->m_value[endValA] == 0) {
        endValA++;
    }
    // reset the MSB after subtraction
    this->m_MSB = (m_nSize - endValA - 1) * m_uintBitLength + GetMSBUint_type(this->m_value[endValA]);
    return *this;
}

/* Multiplication operation:
 *  Algorithm used is usual school book shift and add after multiplication,
 * except for that radix is 2^m_bitLength.
 */
template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::Mul(const BigIntegerFixedT& b) const {
    // check for trivial conditions
    if (b.m_MSB == 0 || this->m_MSB == 0) {
        return 0;
    }
    BigIntegerFixedT ans;
    if (b.m_MSB == 1) {
        ans = *this;
        return ans;
    }
    if (this->m_MSB == 1) {
        ans = b;
        return ans;
    }

    uint_type ceilInt = ceilIntByUInt(b.m_MSB);  // position of B in the array where the
                                                 // multiplication should start
    // Multiplication is done by getting a uint_type from b and multiplying it
    // with *this after multiplication the result is shifted and added to the
    // final answer
    BigIntegerFixedT temp;
    for (size_t i = m_nSize - 1; i >= m_nSize - ceilInt; i--) {
        this->MulByUintToInt(b.m_value[i], &temp);
        ans += temp <<= (m_nSize - 1 - i) * m_uintBitLength;
    }
    return ans;
}

// TODO reconsider operation
template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::MulEq(const BigIntegerFixedT& b) {
    return *this = this->Mul(b);
}

/* Division operation:
 *  Algorithm used is usual school book long division , except for that radix is
 * 2^m_bitLength. Optimization done: Uses bit shift operation for logarithmic
 * convergence.
 */
template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::DividedBy(
    const BigIntegerFixedT& b) const {
    // check for trivial conditions
    if (b == 0) {
        OPENFHE_THROW(lbcrypto::math_error, "Division by zero");
    }
    if (b > *this) {
        return 0;
    }
    if (b == *this) {
        return 1;
    }

    BigIntegerFixedT ans;

    BigIntegerFixedT normalised_dividend(this->Sub(this->Mod(b)));  // normalised_dividend = result*quotient
    uint_type ncharInDivisor = ceilIntByUInt(b.m_MSB);              // Number of array elements in Divisor
    uint_type ncharInNormalised_dividend =
        ceilIntByUInt(normalised_dividend.m_MSB);  // Number of array elements in Normalised_dividend
    BigIntegerFixedT running_dividend;             // variable to store the running dividend
    BigIntegerFixedT runningRemainder;             // variable to store the running remainder
    BigIntegerFixedT expectedProd;
    BigIntegerFixedT estimateFinder;

    // Initialize the running dividend
    for (usint i = 0; i < ncharInDivisor; i++) {
        running_dividend.m_value[m_nSize - ncharInDivisor + i] =
            normalised_dividend.m_value[m_nSize - ncharInNormalised_dividend + i];
    }
    running_dividend.m_MSB =
        GetMSBUint_type(running_dividend.m_value[m_nSize - ncharInDivisor]) + (ncharInDivisor - 1) * m_uintBitLength;

    uint_type estimate = 0;
    uint_type maskBit  = 0;
    uint_type shifts   = 0;
    usint ansCtr       = m_nSize - ncharInNormalised_dividend + ncharInDivisor - 1;
    // Long Division Computation to determine quotient
    for (usint i = ncharInNormalised_dividend - ncharInDivisor;;) {
        runningRemainder = running_dividend.Mod(b);              // Get the remainder from the Modulus operation
        expectedProd     = running_dividend - runningRemainder;  // Compute the expected product from the
                                                                 // running dividend and remainder
        estimateFinder = expectedProd;
        estimate       = 0;
        // compute the quotient
        if (expectedProd > b) {
            while (estimateFinder.m_MSB > 0) {
                shifts = estimateFinder.m_MSB - b.m_MSB;
                if (shifts == m_uintBitLength) {
                    maskBit = (uint_type)1 << (m_uintBitLength - 1);
                }
                else {
                    maskBit = (uint_type)1 << (shifts);
                }

                if ((b.MulByUint(maskBit)) > estimateFinder) {
                    maskBit >>= 1;
                    estimateFinder -= b << (shifts - 1);
                }
                else if (shifts == m_uintBitLength) {
                    estimateFinder -= b << (shifts - 1);
                }
                else {
                    estimateFinder -= b << shifts;
                }
                estimate |= maskBit;
            }
        }
        else if (expectedProd.m_MSB == 0) {
            estimate = 0;
        }
        else {
            estimate = 1;
        }

        ans.m_value[ansCtr] = estimate;  // assigning the quotient in the result array
        ansCtr++;
        if (i == 0) {
            break;
        }
        // Get the next uint element from the divisor and proceed with long division
        if (running_dividend.m_MSB == 0) {
            running_dividend.m_MSB = GetMSBUint_type(normalised_dividend.m_value[m_nSize - i]);
        }
        else {
            running_dividend = runningRemainder << m_uintBitLength;
        }
        running_dividend.m_value[m_nSize - 1] = normalised_dividend.m_value[m_nSize - i];
        if (running_dividend.m_MSB == 0) {
            running_dividend.m_MSB = GetMSBUint_type(normalised_dividend.m_value[m_nSize - i]);
        }
        i--;
    }
    ansCtr = m_nSize - ncharInNormalised_dividend + ncharInDivisor - 1;
    // Loop to the MSB position
    while (ans.m_value[ansCtr] == 0) {
        ansCtr++;
    }
    ans.m_MSB =
        GetMSBUint_type(ans.m_value[ansCtr]) + (m_nSize - 1 - ansCtr) * m_uintBitLength;  // Computation of MSB value
    return ans;
}

// TODO reconsider operation
template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::DividedByEq(const BigIntegerFixedT& b) {
    return *this = this->DividedBy(b);
}

// Recursive Exponentiation function
template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::Exp(usint p) const {
    if (p == 0) {
        return 1;
    }
    BigIntegerFixedT x(*this);
    if (p == 1) {
        return x;
    }
    BigIntegerFixedT tmp = x.Exp(p / 2);
    if (p % 2 == 0) {
        return tmp * tmp;
    }
    else {
        return tmp * tmp * x;
    }
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::ExpEq(usint p) {
    if (p == 0) {
        return *this = 1;
    }
    if (p == 1) {
        return *this;
    }
    BigIntegerFixedT tmp = this->Exp(p / 2);
    if (p % 2 == 0) {
        *this = tmp * tmp;
        return *this;
    }
    else {
        *this *= (tmp * tmp);
        return *this;
    }
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::MultiplyAndRound(
    const BigIntegerFixedT& p, const BigIntegerFixedT& q) const {
    BigIntegerFixedT ans(*this);
    ans.MulEq(p);
    ans.DivideAndRoundEq(q);
    return ans;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::MultiplyAndRoundEq(
    const BigIntegerFixedT& p, const BigIntegerFixedT& q) {
    this->MulEq(p);
    this->DivideAndRoundEq(q);
    return *this;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::DivideAndRound(
    const BigIntegerFixedT& q) const {
    // check for garbage initialization and 0 condition
    if (q == 0) {
        OPENFHE_THROW(lbcrypto::math_error, "Division by zero");
    }
    BigIntegerFixedT halfQ(q >> 1);
    if (*this < q) {
        if (*this <= halfQ) {
            return 0;
        }
        else {
            return 1;
        }
    }
    BigIntegerFixedT ans;
    BigIntegerFixedT normalised_dividend(*this);        // normalised_dividend = result*quotient
    uint_type ncharInDivisor = ceilIntByUInt(q.m_MSB);  // Number of array elements in Divisor
    uint_type ncharInNormalised_dividend =
        ceilIntByUInt(normalised_dividend.m_MSB);  // Number of array elements in Normalised_dividend
    BigIntegerFixedT running_dividend;             // variable to store the running dividend
    BigIntegerFixedT runningRemainder;             // variable to store the running remainder
    BigIntegerFixedT expectedProd;
    BigIntegerFixedT estimateFinder;

    // Initialize the running dividend
    for (usint i = 0; i < ncharInDivisor; i++) {
        running_dividend.m_value[m_nSize - ncharInDivisor + i] =
            normalised_dividend.m_value[m_nSize - ncharInNormalised_dividend + i];
    }
    running_dividend.m_MSB =
        GetMSBUint_type(running_dividend.m_value[m_nSize - ncharInDivisor]) + (ncharInDivisor - 1) * m_uintBitLength;

    uint_type estimate = 0;
    uint_type maskBit  = 0;
    uint_type shifts   = 0;
    usint ansCtr       = m_nSize - ncharInNormalised_dividend + ncharInDivisor - 1;
    // Long Division Computation to determine quotient
    for (usint i = ncharInNormalised_dividend - ncharInDivisor;;) {
        runningRemainder = running_dividend.Mod(q);              // Get the remainder from the Modulus operation
        expectedProd     = running_dividend - runningRemainder;  // Compute the expected product from the
                                                                 // running dividend and remainder
        estimateFinder = expectedProd;
        estimate       = 0;
        // compute the quotient
        if (expectedProd > q) {
            while (estimateFinder.m_MSB > 0) {
                shifts = estimateFinder.m_MSB - q.m_MSB;
                if (shifts == m_uintBitLength) {
                    maskBit = 1 << (m_uintBitLength - 1);
                }
                else {
                    maskBit = 1 << (shifts);
                }

                if ((q.MulByUint(maskBit)) > estimateFinder) {
                    maskBit >>= 1;
                    estimateFinder -= q << (shifts - 1);
                }
                else if (shifts == m_uintBitLength) {
                    estimateFinder -= q << (shifts - 1);
                }
                else {
                    estimateFinder -= q << shifts;
                }
                estimate |= maskBit;
            }
        }
        else if (expectedProd.m_MSB == 0) {
            estimate = 0;
        }
        else {
            estimate = 1;
        }
        // assgning the quotient in the result array
        ans.m_value[ansCtr] = estimate;
        ansCtr++;
        if (i == 0) {
            break;
        }
        // Get the next uint element from the divisor and proceed with long division
        if (running_dividend.m_MSB == 0) {
            running_dividend.m_MSB = GetMSBUint_type(normalised_dividend.m_value[m_nSize - i]);
        }
        else {
            running_dividend = runningRemainder << m_uintBitLength;
        }

        running_dividend.m_value[m_nSize - 1] = normalised_dividend.m_value[m_nSize - i];
        if (running_dividend.m_MSB == 0) {
            running_dividend.m_MSB = GetMSBUint_type(normalised_dividend.m_value[m_nSize - i]);
        }
        i--;
    }
    ansCtr = m_nSize - ncharInNormalised_dividend + ncharInDivisor - 1;
    // Loop to the MSB position
    while (ans.m_value[ansCtr] == 0) {
        ansCtr++;
    }
    ans.m_MSB =
        GetMSBUint_type(ans.m_value[ansCtr]) + (m_nSize - 1 - ansCtr) * m_uintBitLength;  // Computation of MSB value
    // Rounding operation from running remainder
    if (!(runningRemainder <= halfQ)) {
        ans += 1;
    }
    return ans;
}

// TODO reconsider the method
template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::DivideAndRoundEq(
    const BigIntegerFixedT& q) {
    return *this = this->DivideAndRound(q);
}

// MODULAR ARITHMETIC OPERATIONS

// Algorithm used: Repeated subtraction by a multiple of modulus, which will be
// referred to as "Classical Modulo Reduction Algorithm" Complexity:
// O(log(*this)-log(modulus))
template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::Mod(
    const BigIntegerFixedT& modulus) const {
    // return the same value if value is less than modulus
    if (*this < modulus) {
        return BigIntegerFixedT(*this);
    }
    // masking operation if modulus is 2
    if (modulus.m_MSB == 2 && modulus.m_value[m_nSize - 1] == 2) {
        if (this->m_value[m_nSize - 1] % 2 == 0) {
            return 0;
        }
        else {
            return 1;
        }
    }
    Duint_type initial_shift = 0;
    // No of initial left shift that can be performed which will make it
    // comparable to the current value.
    if (this->m_MSB > modulus.m_MSB) {
        initial_shift = this->m_MSB - modulus.m_MSB - 1;
    }
    BigIntegerFixedT j = modulus << initial_shift;
    BigIntegerFixedT result(*this);
    BigIntegerFixedT temp;
    // TODO true -> result < modulus
    while (true) {
        // exit criteria
        if (result < modulus) {
            break;
        }
        if (result.m_MSB > j.m_MSB) {
            temp = j << 1;
            if (result.m_MSB == j.m_MSB + 1) {
                if (result > temp) {
                    j = temp;
                }
            }
        }
        result -= j;  // subtracting the running remainder by a multiple of modulus
        initial_shift = j.m_MSB - result.m_MSB + 1;
        if (result.m_MSB - 1 >= modulus.m_MSB) {
            j >>= initial_shift;
        }
        else {
            j = modulus;
        }
    }
    return result;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::ModEq(const BigIntegerFixedT& modulus) {
    // return the same value if value is less than modulus
    if (*this < modulus) {
        return *this;
    }
    // masking operation if modulus is 2
    if (modulus.m_MSB == 2 && modulus.m_value[m_nSize - 1] == 2) {
        if (this->m_value[m_nSize - 1] % 2 == 0) {
            return *this = 0;
        }
        else {
            return *this = 1;
        }
    }
    Duint_type initial_shift = 0;
    // No of initial left shift that can be performed which will make it
    // comparable to the current value.
    if (this->m_MSB > modulus.m_MSB) {
        initial_shift = this->m_MSB - modulus.m_MSB - 1;
    }
    BigIntegerFixedT j = modulus << initial_shift;
    BigIntegerFixedT temp;
    // TODO true -> *this < modulus
    while (true) {
        // exit criteria
        if (*this < modulus) {
            break;
        }
        if (this->m_MSB > j.m_MSB) {
            temp = j << 1;
            if (this->m_MSB == j.m_MSB + 1) {
                if (*this > temp) {
                    j = temp;
                }
            }
        }
        *this -= j;  // subtracting the running remainder by a multiple of modulus
        initial_shift = j.m_MSB - this->m_MSB + 1;
        if (this->m_MSB - 1 >= modulus.m_MSB) {
            j >>= initial_shift;
        }
        else {
            j = modulus;
        }
    }
    return *this;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::ComputeMu() const {
    BigIntegerFixedT temp(1);
    temp <<= (2 * this->GetMSB() + 3);
    return temp.DividedBy(*this);
    return temp;
}

/*
 Source: http://homes.esat.kuleuven.be/~fvercaut/papers/bar_mont.pdf
 @article{knezevicspeeding,
 title={Speeding Up Barrett and Montgomery Modular Multiplications},
 author={Knezevic, Miroslav and Vercauteren, Frederik and Verbauwhede, Ingrid}
 }
 We use the Generalized Barrett modular reduction algorithm described in
 Algorithm 2 of the Source. The algorithm was originally proposed in J.-F. Dhem.
 Modified version of the Barrett algorithm. Technical report, 1994 and described
 in more detail in the PhD thesis of the author published at
 http://users.belgacom.net/dhem/these/these_public.pdf (Section 2.2.4).
 We take \alpha equal to n + 3. So in our case, \mu = 2^(n + \alpha) = 2^(2*n +
 3). Generally speaking, the value of \alpha should be \ge \gamma + 1, where
 \gamma + n is the number of digits in the dividend. We use the upper bound of
 dividend assuming that none of the dividends will be larger than 2^(2*n + 3).
 The value of \mu is computed by BigVector::ModMult.
 */
template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::Mod(const BigIntegerFixedT& modulus,
                                                                                   const BigIntegerFixedT& mu) const {
    if (*this < modulus) {
        return BigIntegerFixedT(*this);
    }

    BigIntegerFixedT z(*this);
    BigIntegerFixedT q(*this);

    unsigned int n     = modulus.m_MSB;
    unsigned int alpha = n + 3;
    int beta           = -2;

    q >>= n + beta;
    q = q * mu;
    q >>= alpha - beta;
    z -= q * modulus;

    if (!(z < modulus)) {
        z -= modulus;
    }
    return z;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::ModEq(const BigIntegerFixedT& modulus,
                                                                                      const BigIntegerFixedT& mu) {
    if (*this < modulus) {
        return *this;
    }

    BigIntegerFixedT q(*this);

    unsigned int n     = modulus.m_MSB;
    unsigned int alpha = n + 3;
    int beta           = -2;

    q >>= n + beta;
    q = q * mu;
    q >>= alpha - beta;
    (*this) -= q * modulus;

    if (!(*this < modulus)) {
        *this -= modulus;
    }
    return *this;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::ModAdd(
    const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) const {
    BigIntegerFixedT a(*this);
    BigIntegerFixedT bb(b);
    if (a >= modulus) {
        a.ModEq(modulus);
    }
    if (bb >= modulus) {
        bb.ModEq(modulus);
    }
    a.AddEq(bb);
    a.ModEq(modulus);
    return a;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::ModAddEq(
    const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) {
    BigIntegerFixedT bb(b);
    if (*this >= modulus) {
        this->ModEq(modulus);
    }
    if (bb >= modulus) {
        bb.ModEq(modulus);
    }
    this->AddEq(bb);
    this->ModEq(modulus);
    return *this;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::ModAddFast(
    const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) const {
    BigIntegerFixedT a(*this);
    a.AddEq(b);
    a.ModEq(modulus);
    return a;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::ModAddFastEq(
    const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) {
    this->AddEq(b);
    this->ModEq(modulus);
    return *this;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::ModAdd(
    const BigIntegerFixedT& b, const BigIntegerFixedT& modulus, const BigIntegerFixedT& mu) const {
    BigIntegerFixedT a(*this);
    a.AddEq(b);
    a.ModEq(modulus, mu);
    return a;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::ModAddEq(
    const BigIntegerFixedT& b, const BigIntegerFixedT& modulus, const BigIntegerFixedT& mu) {
    this->AddEq(b);
    this->ModEq(modulus, mu);
    return *this;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::ModSub(
    const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) const {
    BigIntegerFixedT a(*this);
    BigIntegerFixedT b_op(b);
    if (a >= modulus) {
        a.ModEq(modulus);
    }
    if (b >= modulus) {
        b_op.ModEq(modulus);
    }
    if (a >= b_op) {
        a.SubEq(b_op);
        a.ModEq(modulus);
    }
    else {
        a.AddEq(modulus);
        a.SubEq(b_op);
    }
    return a;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::ModSubEq(
    const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) {
    BigIntegerFixedT b_op(b);
    if (*this >= modulus) {
        this->ModEq(modulus);
    }
    if (b >= modulus) {
        b_op.ModEq(modulus);
    }
    if (*this >= b_op) {
        this->SubEq(b_op);
        this->ModEq(modulus);
    }
    else {
        this->AddEq(modulus);
        this->SubEq(b_op);
    }
    return *this;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::ModSubFast(
    const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) const {
    BigIntegerFixedT a(*this);
    if (a >= b) {
        a.SubEq(b);
        a.ModEq(modulus);
    }
    else {
        a.AddEq(modulus);
        a.SubEq(b);
    }
    return a;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::ModSubFastEq(
    const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) {
    if (*this >= b) {
        this->SubEq(b);
        this->ModEq(modulus);
    }
    else {
        this->AddEq(modulus);
        this->SubEq(b);
    }
    return *this;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::ModSub(
    const BigIntegerFixedT& b, const BigIntegerFixedT& modulus, const BigIntegerFixedT& mu) const {
    BigIntegerFixedT a(*this);
    BigIntegerFixedT b_op(b);
    // reduce this to a value lower than modulus
    if (a >= modulus) {
        a.ModEq(modulus, mu);
    }
    // reduce b to a value lower than modulus
    if (b >= modulus) {
        b_op.ModEq(modulus, mu);
    }
    if (a >= b_op) {
        a.SubEq(b_op);
        a.ModEq(modulus, mu);
    }
    else {
        a.AddEq(modulus);
        a.SubEq(b_op);
    }
    return a;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::ModSubEq(
    const BigIntegerFixedT& b, const BigIntegerFixedT& modulus, const BigIntegerFixedT& mu) {
    BigIntegerFixedT b_op(b);
    // reduce this to a value lower than modulus
    if (*this >= modulus) {
        this->ModEq(modulus, mu);
    }
    // reduce b to a value lower than modulus
    if (b >= modulus) {
        b_op.ModEq(modulus, mu);
    }
    if (*this >= b_op) {
        this->SubEq(b_op);
        this->ModEq(modulus, mu);
    }
    else {
        this->AddEq(modulus);
        this->SubEq(b_op);
    }
    return *this;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::ModMul(
    const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) const {
    BigIntegerFixedT a(*this);
    BigIntegerFixedT bb(b);
    if (a >= modulus) {
        a.ModEq(modulus);
    }
    if (b >= modulus) {
        bb.ModEq(modulus);
    }
    a.MulEq(bb);
    return a.ModEq(modulus);
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::ModMulEq(
    const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) {
    BigIntegerFixedT bb(b);
    if (*this >= modulus) {
        this->ModEq(modulus);
    }
    if (b >= modulus) {
        bb.ModEq(modulus);
    }
    this->MulEq(bb);
    this->ModEq(modulus);
    return *this;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::ModMul(
    const BigIntegerFixedT& b, const BigIntegerFixedT& modulus, const BigIntegerFixedT& mu) const {
    BigIntegerFixedT a(*this);
    BigIntegerFixedT bb(b);
    if (a >= modulus) {
        a.ModEq(modulus, mu);
    }
    if (b >= modulus) {
        bb.ModEq(modulus, mu);
    }
    a.MulEq(bb);
    a.ModEq(modulus, mu);
    return a;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::ModMulEq(
    const BigIntegerFixedT& b, const BigIntegerFixedT& modulus, const BigIntegerFixedT& mu) {
    BigIntegerFixedT bb(b);
    if (*this >= modulus) {
        this->ModEq(modulus, mu);
    }
    if (b >= modulus) {
        bb.ModEq(modulus, mu);
    }
    this->MulEq(bb);
    this->ModEq(modulus, mu);
    return *this;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::ModMulFast(
    const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) const {
    BigIntegerFixedT a(*this);
    a.MulEq(b);
    a.ModEq(modulus);
    return a;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::ModMulFastEq(
    const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) {
    this->MulEq(b);
    this->ModEq(modulus);
    return *this;
}

/*
 Source: http://homes.esat.kuleuven.be/~fvercaut/papers/bar_mont.pdf
 @article{knezevicspeeding,
 title={Speeding Up Barrett and Montgomery Modular Multiplications},
 author={Knezevic, Miroslav and Vercauteren, Frederik and Verbauwhede, Ingrid}
 }
 We use the Generalized Barrett modular reduction algorithm described in
 Algorithm 2 of the Source. The algorithm was originally proposed in J.-F. Dhem.
 Modified version of the Barrett algorithm. Technical report, 1994 and described
 in more detail in the PhD thesis of the author published at
 http://users.belgacom.net/dhem/these/these_public.pdf (Section 2.2.4).
 We take \alpha equal to n + 3. So in our case, \mu = 2^(n + \alpha) = 2^(2*n +
 3). Generally speaking, the value of \alpha should be \ge \gamma + 1, where
 \gamma + n is the number of digits in the dividend. We use the upper bound of
 dividend assuming that none of the dividends will be larger than 2^(2*n + 3).

 Multiplication and modulo reduction are NOT INTERLEAVED.

 Potential improvements:
 Our implementation makes the modulo operation essentially equivalent to two
 multiplications. If sparse moduli are selected, it can be replaced with a
 single multiplication. The interleaved version of modular multiplication for
 this case is listed in Algorithm 6 of the source. This algorithm would most
 like give the biggest improvement but it sets constraints on moduli.
 */
template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::ModMulFast(
    const BigIntegerFixedT& b, const BigIntegerFixedT& modulus, const BigIntegerFixedT& mu) const {
    BigIntegerFixedT a(*this);
    a.MulEq(b);
    a.ModEq(modulus, mu);
    return a;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::ModMulFastEq(
    const BigIntegerFixedT& b, const BigIntegerFixedT& modulus, const BigIntegerFixedT& mu) {
    this->MulEq(b);
    this->ModEq(modulus, mu);
    return *this;
}

// Modular Multiplication using Square and Multiply Algorithm
// reference:http://guan.cse.nsysu.edu.tw/note/expn.pdf
template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::ModExp(
    const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) const {
    BigIntegerFixedT mid = this->Mod(modulus);  // mid is intermidiate value that calculates mid^2%q
    BigIntegerFixedT product(1);                // product calculates the running product of mod
                                                // values
    BigIntegerFixedT Exp(b);                    // Exp is used for spliting b to bit values/ bit
                                                // extraction

    BigIntegerFixedT temp(1);
    temp <<= 2 * modulus.GetMSB() + 3;
    BigIntegerFixedT mu = temp.DividedBy(modulus);  // Precompute the Barrett mu parameter

    while (true) {
        // product is multiplied only if bitvalue is 1
        if (Exp.m_value[m_nSize - 1] % 2 == 1) {
            product = product * mid;
        }
        // running product is calculated
        if (product > modulus) {
            product.ModEq(modulus, mu);
        }
        Exp = Exp >> 1;  // divide by 2 and check even to odd to find bit value
        if (Exp == 0) {
            break;
        }
        mid = mid * mid;
        mid.ModEq(modulus, mu);  // mid calculates mid^2%q
    }
    return product;
}

// TODO method should be reconsidered
template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::ModExpEq(
    const BigIntegerFixedT& b, const BigIntegerFixedT& modulus) {
    return *this = this->ModExp(b, modulus);
}

// Extended Euclid algorithm used to find the multiplicative inverse
template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::ModInverse(
    const BigIntegerFixedT& modulus) const {
    BigIntegerFixedT second;
    if (*this > modulus) {
        second = Mod(modulus);
    }
    else {
        second = *this;
    }

    if (second == 0) {
        OPENFHE_THROW(lbcrypto::math_error, "Zero does not have a ModInverse");
    }
    if (second == 1) {
        return 1;
    }

    // NORTH ALGORITHM
    BigIntegerFixedT first(modulus);
    BigIntegerFixedT mod_back = first.Mod(second);
    std::vector<BigIntegerFixedT> quotient{first.DividedBy(second)};

    // the max number of iterations should be < 2^k where k ==  min(bitsize
    // (inputs))
    // TODO: consider breaking out of the loop if this limit exceeded. the only
    // issue is that the loop counter could would need to be an ubint.
    while (mod_back != 1) {
        if (mod_back == 0) {
            OPENFHE_THROW(lbcrypto::math_error,
                          this->ToString() + " does not have a ModInverse using " + modulus.ToString());
        }
        first  = second;
        second = mod_back;
        // second != 0, since we throw if mod_back == 0
        quotient.push_back(first.DividedBy(second));
        mod_back = first.Mod(second);
    }

    // SOUTH ALGORITHM
    first  = 0;
    second = 1;
    for (int i = quotient.size() - 1; i >= 0; i--) {
        mod_back = quotient[i] * second + first;
        first    = second;
        second   = mod_back;
    }
    if (quotient.size() % 2 == 1) {
        return modulus - mod_back;
    }
    return mod_back;
}

// Extended Euclid algorithm used to find the multiplicative inverse
template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::ModInverseEq(
    const BigIntegerFixedT& modulus) {
    *this = ModInverse(modulus);
    return *this;
}

/*
 *  Left Shift is done by splitting the number of shifts into
 *1. Multiple of the bit length of uint data type.
 *  Shifting is done by the shifting the uint type numbers.
 *2. Shifts between 1 to bit length of uint data type.
 *   Shifting is done by using bit shift operations and carry over propagation.
 */
template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::LShift(usshort shift) const {
    if (this->m_MSB == 0) {
        return 0;
    }
    if ((this->m_MSB + shift) > BITLENGTH) {
        OPENFHE_THROW(lbcrypto::math_error, "shift overflow");
    }
    BigIntegerFixedT ans(*this);

    usint shiftByUint = shift >> m_logUintBitLength;
    usshort remShift  = (shift & (m_uintBitLength - 1));

    if (remShift != 0) {
        uint_type endVal = m_nSize - ceilIntByUInt(m_MSB);
        uint_type oFlow  = 0;
        Duint_type temp  = 0;
        int i;
        // DTS- BUG FIX!!!!! (signed < unsigned(0) is always true)
        for (i = m_nSize - 1; i >= static_cast<int>(endVal); i--) {
            temp = ans.m_value[i];
            temp <<= remShift;
            ans.m_value[i] = (uint_type)temp + oFlow;
            oFlow          = temp >> m_uintBitLength;
        }
        if (i > -1) {
            ans.m_value[i] = oFlow;
        }
        ans.m_MSB += remShift;
    }
    if (shiftByUint != 0) {
        usint i = m_nSize - ceilIntByUInt(ans.m_MSB);
        for (; i < m_nSize; i++) {
            ans.m_value[i - shiftByUint] = ans.m_value[i];
        }
        for (usint j = 0; j < shiftByUint; j++) {
            ans.m_value[m_nSize - 1 - j] = 0;
        }
    }
    ans.m_MSB += shiftByUint * m_uintBitLength;
    return ans;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::LShiftEq(usshort shift) {
    if (this->m_MSB == 0) {
        return *this;
    }
    if (this->m_MSB + shift > BITLENGTH) {
        OPENFHE_THROW(lbcrypto::math_error, "shift overflow");
    }
    usint shiftByUint = shift >> m_logUintBitLength;  // calculate the no.of
                                                      // shifts
    uint_type remShift = (shift & (m_uintBitLength - 1));
    if (remShift != 0) {
        uint_type endVal = m_nSize - ceilIntByUInt(this->m_MSB);
        uint_type oFlow  = 0;
        Duint_type temp  = 0;
        int i;
        // DTS- BUG FIX!!!!! (endVal may be computed <0)
        for (i = m_nSize - 1; i >= static_cast<int>(endVal); i--) {
            temp = this->m_value[i];
            temp <<= remShift;
            this->m_value[i] = (uint_type)temp + oFlow;
            oFlow            = temp >> m_uintBitLength;
        }
        if (i > -1) {
            this->m_value[i] = oFlow;
        }
        this->m_MSB += remShift;
    }
    if (shiftByUint != 0) {
        usint i = m_nSize - ceilIntByUInt(this->m_MSB);
        for (; i < m_nSize; i++) {
            this->m_value[i - shiftByUint] = this->m_value[i];
        }
        for (usint ii = 0; ii < shiftByUint; ii++) {
            this->m_value[m_nSize - 1 - ii] = 0;
        }
    }
    this->m_MSB += shiftByUint * m_uintBitLength;
    return *this;
}

/*Right Shift is done by splitting the number of shifts into
 *1. Multiple of the bit length of uint data type.
 *  Shifting is done by the shifting the uint type numbers in the array to
 *the right.
 *2. Shifts between 1 to bit length of uint data type.
 *   Shifting is done by using bit shift operations and carry over propagation.
 */
template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::RShift(usshort shift) const {
    // trivial cases
    if (this->m_MSB == 0 || this->m_MSB <= shift) {
        return BigIntegerFixedT(0);
    }
    BigIntegerFixedT ans(*this);
    usint shiftByUint  = shift >> m_logUintBitLength;      // no of array shifts
    uint_type remShift = (shift & (m_uintBitLength - 1));  // no of bit shifts
    if (shiftByUint != 0) {
        // termination index counter
        usint endVal = m_nSize - ceilIntByUInt(ans.m_MSB);
        usint j      = endVal;
        // array shifting operation
        for (int i = m_nSize - 1 - shiftByUint; i >= static_cast<int>(endVal); i--) {
            ans.m_value[i + shiftByUint] = ans.m_value[i];
        }
        ans.m_MSB -= shiftByUint << m_logUintBitLength;  // msb adjusted to show the shifts
        // nullptring the removed uints from the array
        while (shiftByUint > 0) {
            ans.m_value[j] = 0;
            shiftByUint--;
            j++;
        }
    }
    // bit shifts
    if (remShift != 0) {
        uint_type overFlow = 0;
        uint_type oldVal;
        uint_type maskVal      = ((uint_type)1 << (remShift)) - 1;
        uint_type compShiftVal = m_uintBitLength - remShift;
        usint startVal         = m_nSize - ceilIntByUInt(ans.m_MSB);
        // perform shifting by bits by calculating the overflow
        // oveflow is added after the shifting operation
        for (; startVal < m_nSize; startVal++) {
            oldVal                = ans.m_value[startVal];
            ans.m_value[startVal] = (ans.m_value[startVal] >> remShift) + overFlow;
            overFlow              = (oldVal & maskVal);
            overFlow <<= compShiftVal;
        }
        ans.m_MSB -= remShift;
    }
    return ans;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH>& BigIntegerFixedT<uint_type, BITLENGTH>::RShiftEq(usshort shift) {
    if (this->m_MSB == 0) {
        return *this;
    }
    else if (this->m_MSB <= shift) {
        *this = 0;
        return *this;
    }
    int shiftByUint = shift >> m_logUintBitLength;      // no of array shifts
    uschar remShift = (shift & (m_uintBitLength - 1));  // no of bit shifts
    // perform shifting in arrays
    if (shiftByUint != 0) {
        int endVal = m_nSize - ceilIntByUInt(this->m_MSB);
        int j      = endVal;
        for (int i = m_nSize - 1 - shiftByUint; i >= endVal; i--) {
            this->m_value[i + shiftByUint] = this->m_value[i];
        }
        this->m_MSB -= shiftByUint << m_logUintBitLength;  // adjust shift to reflect left shifting
        while (shiftByUint > 0) {
            this->m_value[j] = 0;
            shiftByUint--;
            j++;
        }
    }
    // perform shift by bits if any
    if (remShift != 0) {
        uint_type overFlow = 0;
        uint_type oldVal;
        uint_type maskVal      = ((uint_type)1 << (remShift)) - 1;
        uint_type compShiftVal = m_uintBitLength - remShift;
        usint startVal         = m_nSize - ceilIntByUInt(this->m_MSB);
        // shift and add the overflow from the previous position
        for (; startVal < m_nSize; startVal++) {
            oldVal                  = this->m_value[startVal];
            this->m_value[startVal] = (this->m_value[startVal] >> remShift) + overFlow;
            overFlow                = (oldVal & maskVal);
            overFlow <<= compShiftVal;
        }
        this->m_MSB -= remShift;
    }
    return *this;
}

// COMPARE

// Compares the current object with the BigIntegerFixedT a.
// Uses MSB comparision to output requisite value.
template <typename uint_type, usint BITLENGTH>
int BigIntegerFixedT<uint_type, BITLENGTH>::Compare(const BigIntegerFixedT& a) const {
    if (this->m_MSB < a.m_MSB) {
        return -1;
    }
    if (this->m_MSB > a.m_MSB) {
        return 1;
    }
    if (this->m_MSB == a.m_MSB) {
        uschar ceilInt = ceilIntByUInt(this->m_MSB);
        for (usint i = m_nSize - ceilInt; i < m_nSize; i++) {
            auto testChar = int64_t(this->m_value[i]) - int64_t(a.m_value[i]);
            if (testChar < 0)
                return -1;
            if (testChar > 0)
                return 1;
        }
    }
    return 0;
}

// CONVERTERS

template <typename uint_type, usint BITLENGTH>
inline double BigIntegerFixedT<uint_type, BITLENGTH>::ConvertToDouble() const {
    double result = 0.0;
    usint ceilInt = m_nSize - ceilIntByUInt(m_MSB);
    double factor = pow(2.0, m_uintBitLength);
    double power  = 1.0;
    // copy the values by shift and add
    for (usint i = 0; (m_nSize - i - 1) >= ceilInt; i++) {
        result += static_cast<double>(this->m_value[m_nSize - i - 1]) * power;
        power *= factor;
    }
    return result;
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::FromBinaryString(
    const std::string& bitString) {
    BigIntegerFixedT value;
    usint len  = bitString.length();
    usint cntr = ceilIntByUInt(len);
    std::string val;
    Duint_type partial_value = 0;
    for (usint i = 0; i < cntr; i++) {
        if (len >= ((i + 1) * m_uintBitLength)) {  // modified -- the fix by ES
            val = bitString.substr((len - (i + 1) * m_uintBitLength), m_uintBitLength);
        }
        else {
            val = bitString.substr(0, len % m_uintBitLength);
        }
        for (usint j = 0; j < val.length(); j++) {
            partial_value += std::stoi(val.substr(j, 1));
            partial_value <<= 1;
        }
        partial_value >>= 1;
        value.m_value[m_nSize - 1 - i] = (uint_type)partial_value;
        partial_value                  = 0;
    }
    usint i = m_nSize - cntr;
    while (GetMSBUint_type(value.m_value[i]) == 0 && i < m_nSize - 1) {
        i++;
    }
    value.m_MSB = GetMSBUint_type(value.m_value[i]);
    value.m_MSB += (m_uintBitLength * (m_nSize - i - 1));
    return value;
}

/*
 This method can be used to convert int to BigIntegerFixedT
 */
template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::intToBigInteger(usint m) {
    return BigIntegerFixedT(m);
}

// OTHER OPERATIONS

template <typename uint_type, usint BITLENGTH>
usint BigIntegerFixedT<uint_type, BITLENGTH>::GetMSB() const {
    return m_MSB;
}

template <typename uint_type, usint BITLENGTH>
bool BigIntegerFixedT<uint_type, BITLENGTH>::CheckIfPowerOfTwo(const BigIntegerFixedT& m_numToCheck) {
    usint m_MSB = m_numToCheck.m_MSB;
    for (int i = m_MSB - 1; i > 0; i--) {
        if (static_cast<int>(m_numToCheck.GetBitAtIndex(i)) == 1) {
            return false;
        }
    }
    return true;
}

template <typename uint_type, usint BITLENGTH>
usint BigIntegerFixedT<uint_type, BITLENGTH>::GetDigitAtIndexForBase(usint index, usint base) const {
    usint DigitLen = ceil(log2(base));
    usint digit    = 0;
    usint newIndex = 1 + (index - 1) * DigitLen;
    for (usint i = 1; i < base; i = i * 2) {
        digit += GetBitAtIndex(newIndex) * i;
        newIndex++;
    }
    return digit;
}

template <typename uint_type, usint BITLENGTH>
uschar BigIntegerFixedT<uint_type, BITLENGTH>::GetBitAtIndex(usint index) const {
    if (index <= 0) {
        return 0;
    }
    else if (index > m_MSB) {
        return 0;
    }
    uint_type result;
    // idx is the index of the character array
    int idx        = m_nSize - ceilIntByUInt(index);
    uint_type temp = this->m_value[idx];
    // bmask is the bit number in the 8 bit array
    uint_type bmask_counter = index % m_uintBitLength == 0 ? m_uintBitLength : index % m_uintBitLength;
    uint_type bmask         = 1;
    for (size_t i = 1; i < bmask_counter; i++) {
        bmask <<= 1;  // generate the bitmask number
    }
    result = temp & bmask;         // finds the bit in  bit format
    result >>= bmask_counter - 1;  // shifting operation gives bit either 1 or 0
    return (uschar)result;
}

// STRINGS & STREAMS

template <typename uint_type, usint BITLENGTH>
const std::string BigIntegerFixedT<uint_type, BITLENGTH>::ToString() const {
    std::string bbiString;  // this string object will store this BigIntegerFixedT's value
    usint counter;

    // print_VALUE array stores the decimal value in the array
    // NOLINTNEXTLINE
    uschar* print_VALUE = new uschar[m_numDigitInPrintval];
    for (size_t i = 0; i < m_numDigitInPrintval; i++) {  // reset to zero
        *(print_VALUE + i) = 0;
    }
    // starts the conversion from base r to decimal value
    for (size_t i = this->m_MSB; i > 0; i--) {
        // print_VALUE = print_VALUE*2
        BigIntegerFixedT<uint_type, BITLENGTH>::double_bitVal(print_VALUE);

        // adds the bit value to the print_VALUE
        BigIntegerFixedT<uint_type, BITLENGTH>::add_bitVal(print_VALUE, this->GetBitAtIndex(i));
    }
    // find the first occurrence of non-zero value in print_VALUE
    for (counter = 0; counter < m_numDigitInPrintval - 1; counter++) {
        if (static_cast<int>(print_VALUE[counter]) != 0) {
            break;
        }
    }
    // append this BigIntegerFixedT's digits to this method's returned string object
    for (; counter < m_numDigitInPrintval; counter++) {
        bbiString += std::to_string(print_VALUE[counter]);
    }
    delete[] print_VALUE;
    return bbiString;
}

// Initializes the array of uint_array from the string equivalent of BigIntegerFixedT
// Algorithm used is repeated division by 2
// Reference:http://pctechtips.org/convert-from-decimal-to-binary-with-recursion-in-java/
template <typename uint_type, usint BITLENGTH>
void BigIntegerFixedT<uint_type, BITLENGTH>::AssignVal(const std::string& v) {
    int arrSize      = v.length();
    uschar* DecValue = new uschar[arrSize];  // memory allocated for decimal array
    for (int i = 0; i < arrSize; i++) {      // store the string to decimal array
        DecValue[i] = (uschar)atoi(v.substr(i, 1).c_str());
    }
    int zptr = 0;
    // index of highest non-zero number in decimal number
    // define  bit register array
    uschar* bitArr = new uschar[m_uintBitLength]();

    int bitValPtr = m_nSize - 1;
    // bitValPtr is a pointer to the Value char array, initially pointed to the
    // last char we increment the pointer to the next char when we get the
    // complete value of the char array

    int cnt = m_uintBitLength - 1;
    // cnt8 is a pointer to the bit position in bitArr, when bitArr is complete it
    // is ready to be transfered to Value
    while (zptr != arrSize) {
        bitArr[cnt] = DecValue[arrSize - 1] % 2;
        // start divide by 2 in the DecValue array
        for (int i = zptr; i < arrSize - 1; i++) {
            DecValue[i + 1] = (DecValue[i] % 2) * 10 + DecValue[i + 1];
            DecValue[i] >>= 1;
        }
        DecValue[arrSize - 1] >>= 1;
        // division ends here
        cnt--;
        if (cnt == -1) {  // cnt = -1 indicates bitArr is ready for transfer
            if (bitValPtr < 0) {
                OPENFHE_THROW(lbcrypto::math_error, "string " + v + " cannot fit into BigIntegerFixedT");
            }

            cnt = m_uintBitLength - 1;
            m_value[bitValPtr--] =
                UintInBinaryToDecimal(bitArr);  // UintInBinaryToDecimal converts bitArr to decimal and
                                                // resets the content of bitArr.
        }

        if (DecValue[zptr] == 0) {
            zptr++;  // division makes Most significant digit zero, hence we increment
                     // zptr to next value
        }
        if (zptr == arrSize && DecValue[arrSize - 1] == 0) {
            if (bitValPtr < 0) {
                OPENFHE_THROW(lbcrypto::math_error, "string " + v + " cannot fit into BigIntegerFixedT");
            }
            m_value[bitValPtr] = UintInBinaryToDecimal(bitArr);  // Value assignment
        }
    }
    SetMSB(bitValPtr);
    delete[] bitArr;
    delete[] DecValue;  // deallocate memory
}

template <typename uint_type, usint BITLENGTH>
void BigIntegerFixedT<uint_type, BITLENGTH>::SetMSB() {
    m_MSB = 0;
    for (usint i = 0; i < m_nSize; i++) {  // loops to find first nonzero number in char array
        if ((Duint_type)m_value[i] != 0) {
            m_MSB = (m_nSize - i - 1) * m_uintBitLength;
            m_MSB += GetMSBUint_type(m_value[i]);
            break;
        }
    }
}

// guessIdx is the index of largest uint_type number in array.
template <typename uint_type, usint BITLENGTH>
void BigIntegerFixedT<uint_type, BITLENGTH>::SetMSB(usint guessIdxChar) {
    m_MSB = (m_nSize - guessIdxChar - 1) * m_uintBitLength;
    m_MSB += GetMSBUint_type(m_value[guessIdxChar]);
}

// DTS:
// this seems to be the traditional "round up to the next power of two"
// function, except that ceilIntByUInt(0) == 1
//
// ((number+(1<<m_uintBitLength)-1)>>m_uintBitLength);
// where m_uintBitLength = 8*sizeof(uint_type)
//
// optimized ceiling function after division by number of bits in the interal
// data type.
template <typename uint_type, usint BITLENGTH>
uint_type BigIntegerFixedT<uint_type, BITLENGTH>::ceilIntByUInt(const uint_type Number) {
    // mask to perform bitwise AND
    // static uint_type mask = m_uintBitLength-1;
    uint_type mask = m_uintBitLength - 1;
    if ((Number & mask) != 0) {
        return (Number >> m_logUintBitLength) + 1;
    }
    else if (!Number) {
        return 1;
    }
    else {
        return Number >> m_logUintBitLength;
    }
}

template <typename uint_type, usint BITLENGTH>
usint BigIntegerFixedT<uint_type, BITLENGTH>::GetMSBUint_type(uint_type x) {
    return lbcrypto::GetMSB64(x);
}

template <typename uint_type, usint BITLENGTH>
usint BigIntegerFixedT<uint_type, BITLENGTH>::GetMSBDUint_type(Duint_type x) {
    return lbcrypto::GetMSB64(x);
}

template <typename uint_type, usint BITLENGTH>
BigIntegerFixedT<uint_type, BITLENGTH> BigIntegerFixedT<uint_type, BITLENGTH>::MulByUint(const uint_type b) const {
    BigIntegerFixedT ans;
    MulByUintToInt(b, &ans);
    return ans;
}

/* Mul operation:
 *  Algorithm used is usual school book multiplication.
 *  This function is used in the Multiplication of two BigIntegerFixedT objects
 */
template <typename uint_type, usint BITLENGTH>
void BigIntegerFixedT<uint_type, BITLENGTH>::MulByUintToInt(const uint_type b, BigIntegerFixedT* ans) const {
    // check for trivial conditions
    if (b == 0 || this->m_MSB == 0) {
        *ans = 0;
        return;
    }

    // position in the array to start multiplication
    usint endVal = m_nSize - ceilIntByUInt(m_MSB);
    // variable to capture the overflow
    Duint_type temp = 0;
    // overflow value
    uint_type ofl = 0;
    size_t i      = m_nSize - 1;

    for (; i >= endVal; i--) {
        temp            = ((Duint_type)m_value[i] * (Duint_type)b) + ofl;
        ans->m_value[i] = (uint_type)temp;
        ofl             = temp >> m_uintBitLength;
    }
    // check if there is any final overflow
    if (ofl) {
        ans->m_value[i] = ofl;
    }
    ans->m_MSB = (m_nSize - 1 - endVal) * m_uintBitLength;
    // set the MSB after the final computation
    ans->m_MSB += GetMSBDUint_type(temp);
    return;
}

// Algoritm used is shift and add
template <typename uint_type, usint BITLENGTH>
uint_type BigIntegerFixedT<uint_type, BITLENGTH>::UintInBinaryToDecimal(uschar* a) {
    uint_type Val = 0;
    uint_type one = 1;
    for (int i = m_uintBitLength - 1; i >= 0; i--) {
        Val += one * *(a + i);
        one <<= 1;
        *(a + i) = 0;
    }
    return Val;
}

template <typename uint_type, usint BITLENGTH>
void BigIntegerFixedT<uint_type, BITLENGTH>::double_bitVal(uschar* a) {
    uschar ofl = 0;
    for (int i = m_numDigitInPrintval - 1; i > -1; i--) {
        *(a + i) <<= 1;
        if (*(a + i) > 9) {
            *(a + i) = *(a + i) - 10 + ofl;
            ofl      = 1;
        }
        else {
            *(a + i) = *(a + i) + ofl;
            ofl      = 0;
        }
    }
}

template <typename uint_type, usint BITLENGTH>
void BigIntegerFixedT<uint_type, BITLENGTH>::add_bitVal(uschar* a, uschar b) {
    uschar ofl = 0;
    *(a + m_numDigitInPrintval - 1) += b;
    for (int i = m_numDigitInPrintval - 1; i > -1; i--) {
        *(a + i) += ofl;
        if (*(a + i) > 9) {
            *(a + i) = 0;
            ofl      = 1;
        }
    }
}

template class BigIntegerFixedT<integral_dtype, BigIntegerBitLength>;

}  // namespace bigintfxd

#endif
