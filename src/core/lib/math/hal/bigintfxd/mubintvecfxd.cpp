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

    #include "math/math-hal.h"
    #include "math/hal/bigintfxd/mubintvecfxd.h"
    #include "math/nbtheory.h"
    #include "utils/debug.h"
    #include "utils/serializable.h"

namespace bigintfxd {

template <class IntegerType>
BigVectorFixedT<IntegerType>::BigVectorFixedT() {
    this->m_length  = 0;
    this->m_modulus = 0;
    m_data          = nullptr;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>::BigVectorFixedT(usint length, const IntegerType& modulus) {
    this->m_length  = length;
    this->m_modulus = modulus;
    this->m_data    = new IntegerType[m_length]();
}

template <class IntegerType>
BigVectorFixedT<IntegerType>::BigVectorFixedT(const BigVectorFixedT& bigVector) {
    m_length  = bigVector.m_length;
    m_modulus = bigVector.m_modulus;
    m_data    = new IntegerType[m_length];
    for (usint i = 0; i < m_length; i++) {
        m_data[i] = bigVector.m_data[i];
    }
}

template <class IntegerType>
BigVectorFixedT<IntegerType>::BigVectorFixedT(BigVectorFixedT&& bigVector) {
    if (this != &bigVector) {
        m_data              = bigVector.m_data;
        m_length            = bigVector.m_length;
        m_modulus           = bigVector.m_modulus;
        bigVector.m_data    = nullptr;
        bigVector.m_length  = 0;
        bigVector.m_modulus = 0;
    }
}

template <class IntegerType>
BigVectorFixedT<IntegerType>::BigVectorFixedT(usint length, const IntegerType& modulus,
                                              std::initializer_list<std::string> rhs) {
    this->m_length  = length;
    this->m_modulus = modulus;
    this->m_data    = new IntegerType[m_length]();
    usint len       = rhs.size();
    for (usint i = 0; i < m_length; i++) {  // this loops over each entry
        if (i < len) {
            m_data[i] = IntegerType(*(rhs.begin() + i)) % m_modulus;
        }
        else {
            m_data[i] = 0;
        }
    }
}

template <class IntegerType>
BigVectorFixedT<IntegerType>::BigVectorFixedT(usint length, const IntegerType& modulus,
                                              std::initializer_list<uint64_t> rhs) {
    this->m_length  = length;
    this->m_modulus = modulus;
    this->m_data    = new IntegerType[m_length]();
    usint len       = rhs.size();
    for (usint i = 0; i < m_length; i++) {  // this loops over each entry
        if (i < len) {
            m_data[i] = IntegerType(*(rhs.begin() + i)) % m_modulus;
        }
        else {
            m_data[i] = 0;
        }
    }
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::operator=(const BigVectorFixedT& rhs) {
    if (this != &rhs) {
        if (this->m_length == rhs.m_length) {
            for (size_t i = 0; i < m_length; i++) {
                this->m_data[i] = rhs.m_data[i];
            }
        }
        else {
            delete[] m_data;
            m_length  = rhs.m_length;
            m_modulus = rhs.m_modulus;
            m_data    = new IntegerType[m_length];
            for (size_t i = 0; i < m_length; i++) {
                m_data[i] = rhs.m_data[i];
            }
        }
        this->m_modulus = rhs.m_modulus;
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::operator=(BigVectorFixedT&& rhs) {
    if (this != &rhs) {
        delete[] m_data;
        m_data     = rhs.m_data;
        m_length   = rhs.m_length;
        m_modulus  = rhs.m_modulus;
        rhs.m_data = nullptr;
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::operator=(std::initializer_list<std::string> rhs) {
    size_t len = rhs.size();
    for (size_t i = 0; i < m_length; i++) {
        if (i < len) {
            if (m_modulus != 0) {
                m_data[i] = IntegerType(*(rhs.begin() + i)) % m_modulus;
            }
            else {
                m_data[i] = IntegerType(*(rhs.begin() + i));
            }
        }
        else {
            m_data[i] = 0;
        }
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::operator=(std::initializer_list<uint64_t> rhs) {
    size_t len = rhs.size();
    for (size_t i = 0; i < m_length; i++) {
        if (i < len) {
            if (m_modulus != 0) {
                m_data[i] = IntegerType(*(rhs.begin() + i)) % m_modulus;
            }
            else {
                m_data[i] = IntegerType(*(rhs.begin() + i));
            }
        }
        else {
            m_data[i] = 0;
        }
    }
    return *this;
}

// ACCESSORS

template <class IntegerType>
void BigVectorFixedT<IntegerType>::SetModulus(const IntegerType& value) {
    this->m_modulus = value;
}

/**Switches the integers in the vector to values corresponding to the new
 * modulus Algorithm: Integer i, Old Modulus om, New Modulus nm, delta =
 * abs(om-nm): Case 1: om < nm if i > i > om/2 i' = i + delta Case 2: om > nm i
 * > om/2 i' = i-delta
 */
template <class IntegerType>
void BigVectorFixedT<IntegerType>::SwitchModulus(const IntegerType& newModulus) {
    IntegerType oldModulus(this->m_modulus);
    IntegerType n;
    IntegerType oldModulusByTwo(oldModulus >> 1);
    IntegerType diff((oldModulus > newModulus) ? (oldModulus - newModulus) : (newModulus - oldModulus));
    for (usint i = 0; i < this->m_length; i++) {
        n = this->at(i);
        if (oldModulus < newModulus) {
            if (n > oldModulusByTwo) {
                this->at(i) = n.ModAdd(diff, newModulus);
            }
            else {
                this->at(i) = n.Mod(newModulus);
            }
        }
        else {
            if (n > oldModulusByTwo) {
                this->at(i) = n.ModSub(diff, newModulus);
            }
            else {
                this->at(i) = n.Mod(newModulus);
            }
        }
    }
    this->SetModulus(newModulus);
}

// MODULAR ARITHMETIC OPERATIONS

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::Mod(const IntegerType& modulus) const {
    BigVectorFixedT ans(*this);
    ans.ModEq(modulus);
    return ans;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::ModEq(const IntegerType& modulus) {
    if (modulus == 2) {
        return this->ModByTwoEq();
    }
    else {
        IntegerType halfQ(this->GetModulus() >> 1);
        for (usint i = 0; i < this->GetLength(); i++) {
            if (this->m_data[i] > halfQ) {
                this->m_data[i].ModSubEq(this->GetModulus(), modulus);
            }
            else {
                this->m_data[i].ModEq(modulus);
            }
        }
        return *this;
    }
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::ModAdd(const IntegerType& b) const {
    BigVectorFixedT ans(*this);
    ans.ModAddEq(b);
    return ans;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::ModAddEq(const IntegerType& b) {
    IntegerType bb = b.Mod(this->m_modulus);
    for (usint i = 0; i < this->m_length; i++) {
        this->m_data[i].ModAddFastEq(bb, this->m_modulus);
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::ModAddAtIndex(usint i, const IntegerType& b) const {
    BigVectorFixedT ans(*this);
    ans.ModAddAtIndexEq(i, b);
    return ans;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::ModAddAtIndexEq(usint i, const IntegerType& b) {
    if (i > this->GetLength() - 1) {
        OPENFHE_THROW(lbcrypto::math_error,
                      "mubintvecfxd::ModAddAtIndex. Index is out of range. i = " + std::to_string(i));
    }
    this->m_data[i].ModAddEq(b, this->m_modulus);
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::ModAdd(const BigVectorFixedT& b) const {
    BigVectorFixedT ans(*this);
    ans.ModAddEq(b);
    return ans;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::ModAddEq(const BigVectorFixedT& b) {
    if ((this->m_length != b.m_length) || this->m_modulus != b.m_modulus) {
        OPENFHE_THROW(lbcrypto::math_error, "ModAddEq called on BigVectorFixedT's with different parameters.");
    }
    for (usint i = 0; i < this->m_length; i++) {
        this->m_data[i].ModAddFastEq(b.m_data[i], this->m_modulus);
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::ModAddNoCheckEq(const BigVectorFixedT& b) {
    for (usint i = 0; i < m_length; ++i)
        m_data[i].ModAddFastEq(b.m_data[i], m_modulus);
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::ModSub(const IntegerType& b) const {
    BigVectorFixedT ans(*this);
    ans.ModSubEq(b);
    return ans;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::ModSubEq(const IntegerType& b) {
    IntegerType bb = b.Mod(this->m_modulus);
    for (usint i = 0; i < this->m_length; i++) {
        this->m_data[i].ModSubFastEq(bb, this->m_modulus);
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::ModSub(const BigVectorFixedT& b) const {
    BigVectorFixedT ans(*this);
    ans.ModSubEq(b);
    return ans;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::ModSubEq(const BigVectorFixedT& b) {
    if ((this->m_length != b.m_length) || this->m_modulus != b.m_modulus) {
        OPENFHE_THROW(lbcrypto::math_error, "ModSubEq called on BigVectorFixedT's with different parameters.");
    }
    for (usint i = 0; i < this->m_length; i++) {
        this->m_data[i].ModSubFastEq(b.m_data[i], this->m_modulus);
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::ModMul(const IntegerType& b) const {
    BigVectorFixedT ans(*this);
    ans.ModMulEq(b);
    return ans;
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

 Potential improvements:
 Our implementation makes the modulo operation essentially equivalent to two
 multiplications. If sparse moduli are selected, it can be replaced with a
 single multiplication. The interleaved version of modular multiplication for
 this case is listed in Algorithm 6 of the source. This algorithm would most
 like give the biggest improvement but it sets constraints on moduli.
 */
template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::ModMulEq(const IntegerType& b) {
    IntegerType bb = b.Mod(this->m_modulus);
    IntegerType mu = this->m_modulus.ComputeMu();  // Precompute the Barrett mu parameter
    for (usint i = 0; i < this->m_length; i++) {
        this->m_data[i].ModMulEq(bb, this->m_modulus, mu);
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::ModMul(const BigVectorFixedT& b) const {
    BigVectorFixedT ans(*this);
    ans.ModMulEq(b);
    return ans;
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

 Potential improvements:
 Our implementation makes the modulo operation essentially equivalent to two
 multiplications. If sparse moduli are selected, it can be replaced with a
 single multiplication. The interleaved version of modular multiplication for
 this case is listed in Algorithm 6 of the source. This algorithm would most
 like give the biggest improvement but it sets constraints on moduli.
 */
template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::ModMulEq(const BigVectorFixedT& b) {
    if ((this->m_length != b.m_length) || this->m_modulus != b.m_modulus) {
        OPENFHE_THROW(lbcrypto::math_error, "ModMulEq called on BigVectorFixedT's with different parameters.");
    }
    IntegerType mu = this->m_modulus.ComputeMu();
    // Precompute the Barrett mu parameter
    for (usint i = 0; i < this->m_length; i++) {
        this->m_data[i].ModMulEq(b.m_data[i], this->m_modulus, mu);
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::ModMulNoCheckEq(const BigVectorFixedT& b) {
    auto mu{m_modulus.ComputeMu()};
    for (usint i = 0; i < m_length; ++i)
        m_data[i].ModMulEq(b[i], m_modulus, mu);
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::ModExp(const IntegerType& b) const {
    BigVectorFixedT ans(*this);
    ans.ModExpEq(b);
    return ans;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::ModExpEq(const IntegerType& b) {
    for (usint i = 0; i < this->m_length; i++) {
        this->m_data[i].ModExpEq(b, this->m_modulus);
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::ModInverse() const {
    BigVectorFixedT ans(*this);
    ans.ModInverseEq();
    return ans;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::ModInverseEq() {
    for (usint i = 0; i < this->m_length; i++) {
        this->m_data[i].ModInverseEq(this->m_modulus);
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::ModByTwo() const {
    BigVectorFixedT ans(*this);
    ans.ModByTwoEq();
    return ans;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::ModByTwoEq() {
    IntegerType halfQ(this->GetModulus() >> 1);
    for (usint i = 0; i < this->GetLength(); i++) {
        if (this->m_data[i] > halfQ) {
            if (this->m_data[i].Mod(2) == 1) {
                this->m_data[i] = IntegerType(0);
            }
            else {
                this->m_data[i] = 1;
            }
        }
        else {
            if (this->m_data[i].Mod(2) == 1) {
                this->m_data[i] = 1;
            }
            else {
                this->m_data[i] = IntegerType(0);
            }
        }
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::MultWithOutMod(const BigVectorFixedT& b) const {
    BigVectorFixedT ans(*this);
    ans.MultWithOutModEq(b);
    return ans;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::MultWithOutModEq(const BigVectorFixedT& b) {
    if ((this->m_length != b.m_length) || this->m_modulus != b.m_modulus) {
        OPENFHE_THROW(lbcrypto::type_error, "MultWithOutMod called on BigVectorFixedT's with different parameters.");
    }
    for (usint i = 0; i < this->m_length; i++) {
        this->m_data[i].MulEq(b.m_data[i]);
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::MultiplyAndRound(const IntegerType& p,
                                                                            const IntegerType& q) const {
    BigVectorFixedT ans(*this);
    ans.MultiplyAndRoundEq(p, q);
    return ans;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::MultiplyAndRoundEq(const IntegerType& p,
                                                                               const IntegerType& q) {
    IntegerType halfQ(this->m_modulus >> 1);
    IntegerType temp;
    for (usint i = 0; i < this->m_length; i++) {
        if (this->m_data[i] > halfQ) {
            temp            = this->m_modulus - this->m_data[i];
            this->m_data[i] = this->m_modulus - temp.MultiplyAndRound(p, q);
        }
        else {
            this->m_data[i].MultiplyAndRoundEq(p, q);
            this->m_data[i].ModEq(this->m_modulus);
        }
    }
    return *this;
}

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::DivideAndRound(const IntegerType& q) const {
    BigVectorFixedT ans(*this);
    ans.DivideAndRoundEq(q);
    return ans;
}

template <class IntegerType>
BigVectorFixedT<IntegerType>& BigVectorFixedT<IntegerType>::DivideAndRoundEq(const IntegerType& q) {
    IntegerType halfQ(this->m_modulus >> 1);
    IntegerType temp;
    for (usint i = 0; i < this->m_length; i++) {
        if (this->m_data[i] > halfQ) {
            temp            = this->m_modulus - this->m_data[i];
            this->m_data[i] = this->m_modulus - temp.DivideAndRound(q);
        }
        else {
            this->m_data[i].DivideAndRoundEq(q);
        }
    }
    return *this;
}

// OTHER OPERATIONS

template <class IntegerType>
BigVectorFixedT<IntegerType> BigVectorFixedT<IntegerType>::GetDigitAtIndexForBase(usint index, usint base) const {
    BigVectorFixedT ans(*this);
    for (usint i = 0; i < this->m_length; i++) {
        ans.m_data[i] = IntegerType(ans.m_data[i].GetDigitAtIndexForBase(index, base));
    }
    return ans;
}

template class BigVectorFixedT<BigIntegerFixedT<integral_dtype, BigIntegerBitLength>>;

}  // namespace bigintfxd

#endif
