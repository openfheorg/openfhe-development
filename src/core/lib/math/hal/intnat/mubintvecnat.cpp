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
  This code provides basic arithmetic functionality for vectors of native integers
 */

#include "math/hal.h"
#include "math/hal/intnat/mubintvecnat.h"
#include "math/nbtheory-impl.h"

#include "utils/exception.h"

namespace intnat {

// CONSTRUCTORS

template <class IntegerType>
NativeVectorT<IntegerType>::NativeVectorT() {}

template <class IntegerType>
NativeVectorT<IntegerType>::NativeVectorT(usint length) {
    this->m_data.resize(length);
}

template <class IntegerType>
NativeVectorT<IntegerType>::NativeVectorT(usint length, const IntegerType& modulus) {
    if (modulus.GetMSB() > MAX_MODULUS_SIZE) {
        OPENFHE_THROW(lbcrypto::not_available_error,
                      "Modulus size " + std::to_string(modulus.GetMSB()) +
                          " is too large. NativeVectorT supports only modulus size <=  " +
                          std::to_string(MAX_MODULUS_SIZE) + " bits");
    }
    this->SetModulus(modulus);
    this->m_data.resize(length);
}

template <class IntegerType>
NativeVectorT<IntegerType>::NativeVectorT(const NativeVectorT& bigVector) {
    m_modulus = bigVector.m_modulus;
    m_data    = bigVector.m_data;
}

template <class IntegerType>
NativeVectorT<IntegerType>::NativeVectorT(NativeVectorT&& bigVector) {
    m_data    = std::move(bigVector.m_data);
    m_modulus = bigVector.m_modulus;
}

template <class IntegerType>
NativeVectorT<IntegerType>::NativeVectorT(usint length, const IntegerType& modulus,
                                          std::initializer_list<std::string> rhs) {
    this->SetModulus(modulus);
    this->m_data.resize(length);
    usint len = rhs.size();
    for (usint i = 0; i < m_data.size(); i++) {  // this loops over each entry
        if (i < len) {
            m_data[i] = IntegerType(*(rhs.begin() + i)) % m_modulus;
        }
        else {
            m_data[i] = IntegerType(0);
        }
    }
}

template <class IntegerType>
NativeVectorT<IntegerType>::NativeVectorT(usint length, const IntegerType& modulus,
                                          std::initializer_list<uint64_t> rhs) {
    this->SetModulus(modulus);
    this->m_data.resize(length);
    usint len = rhs.size();
    for (usint i = 0; i < m_data.size(); i++) {  // this loops over each entry
        if (i < len) {
            m_data[i] = IntegerType(*(rhs.begin() + i)) % m_modulus;
        }
        else {
            m_data[i] = IntegerType(0);
        }
    }
}

template <class IntegerType>
NativeVectorT<IntegerType>::~NativeVectorT() {}

// ASSIGNMENT OPERATORS

template <class IntegerType>
const NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::operator=(const NativeVectorT& rhs) {
    if (this != &rhs) {
        if (this->m_data.size() == rhs.m_data.size()) {
            for (usint i = 0; i < m_data.size(); i++) {
                this->m_data[i] = rhs.m_data[i];
            }
        }
        else {
            m_data = rhs.m_data;
        }
        m_modulus = rhs.m_modulus;
    }
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::operator=(NativeVectorT&& rhs) {
    if (this != &rhs) {
        m_data    = std::move(rhs.m_data);
        m_modulus = rhs.m_modulus;
    }
    return *this;
}

template <class IntegerType>
const NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::operator=(std::initializer_list<std::string> rhs) {
    usint len = rhs.size();
    for (usint i = 0; i < m_data.size(); i++) {  // this loops over each tower
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
const NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::operator=(std::initializer_list<uint64_t> rhs) {
    usint len = rhs.size();
    for (usint i = 0; i < m_data.size(); i++) {  // this loops over each tower
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
void NativeVectorT<IntegerType>::SetModulus(const IntegerType& value) {
    if (value.GetMSB() > MAX_MODULUS_SIZE) {
        OPENFHE_THROW(lbcrypto::not_available_error,
                      "NativeVectorT supports only modulus size <=  " + std::to_string(MAX_MODULUS_SIZE) + " bits");
    }
    this->m_modulus = value;
}

/**Switches the integers in the vector to values corresponding to the new
 * modulus.
 * Algorithm: Integer i, Old Modulus om, New Modulus nm,
 * delta = abs(om-nm):
 *  Case 1: om < nm
 *    if i > om/2
 *      i' = i + delta
 *  Case 2: om > nm
 *    i > om/2 i' = i-delta
 */
template <class IntegerType>
void NativeVectorT<IntegerType>::SwitchModulus(const IntegerType& newModulus) {
    IntegerType oldModulus(this->m_modulus);
    IntegerType oldModulusByTwo(oldModulus >> 1);
    IntegerType diff((oldModulus > newModulus) ? (oldModulus - newModulus) : (newModulus - oldModulus));

    if (newModulus > oldModulus) {
        for (usint i = 0; i < this->m_data.size(); i++) {
            IntegerType n = this->m_data[i];
            if (n > oldModulusByTwo) {
                this->m_data[i] += diff;
            }
        }
    }
    else {  // newModulus <= oldModulus
        for (usint i = 0; i < this->m_data.size(); i++) {
            IntegerType n        = this->m_data[i];
            IntegerType sub_diff = (n > oldModulusByTwo) ? diff : 0;
            this->m_data[i]      = n.ModSub(sub_diff, newModulus);
        }
    }
    this->SetModulus(newModulus);
}

template <class IntegerType>
const IntegerType& NativeVectorT<IntegerType>::GetModulus() const {
    return this->m_modulus;
}

// MODULAR ARITHMETIC OPERATIONS

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::Mod(const IntegerType& modulus) const {
    if (modulus == 2) {
        return this->ModByTwo();
    }
    else {
        NativeVectorT ans(this->GetLength(), this->GetModulus());
        IntegerType halfQ(this->GetModulus() >> 1);
        for (size_t i = 0; i < ans.GetLength(); i++) {
            if (this->m_data[i] > halfQ) {
                ans[i] = this->m_data[i].ModSub(this->GetModulus(), modulus);
            }
            else {
                ans[i] = this->m_data[i].Mod(modulus);
            }
        }
        return ans;
    }
}

template <class IntegerType>
const NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModEq(const IntegerType& modulus) {
    if (modulus == 2) {
        return this->ModByTwoEq();
    }
    else {
        IntegerType halfQ(this->GetModulus() >> 1);
        for (size_t i = 0; i < this->GetLength(); i++) {
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
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModAdd(const IntegerType& b) const {
    IntegerType modulus = this->m_modulus;
    IntegerType bLocal  = b;
    NativeVectorT ans(*this);
    if (bLocal > m_modulus) {
        bLocal.ModEq(modulus);
    }
    for (usint i = 0; i < this->m_data.size(); i++) {
        ans.m_data[i].ModAddFastEq(bLocal, modulus);
    }
    return ans;
}

template <class IntegerType>
const NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModAddEq(const IntegerType& b) {
    IntegerType modulus = this->m_modulus;
    IntegerType bLocal  = b;
    if (bLocal > m_modulus) {
        bLocal.ModEq(modulus);
    }
    for (usint i = 0; i < this->m_data.size(); i++) {
        this->m_data[i].ModAddFastEq(bLocal, modulus);
    }
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModAddAtIndex(usint i, const IntegerType& b) const {
    if (i > this->GetLength() - 1) {
        std::string errMsg = "ubintnat::ModAddAtIndex. Index is out of range. i = " + std::to_string(i);
        OPENFHE_THROW(lbcrypto::math_error, errMsg);
    }
    NativeVectorT ans(*this);
    ans.m_data[i].ModAddEq(b, this->m_modulus);
    return ans;
}

template <class IntegerType>
const NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModAddAtIndexEq(usint i, const IntegerType& b) {
    if (i > this->GetLength() - 1) {
        std::string errMsg = "ubintnat::ModAddAtIndex. Index is out of range. i = " + std::to_string(i);
        OPENFHE_THROW(lbcrypto::math_error, errMsg);
    }
    this->m_data[i].ModAddEq(b, this->m_modulus);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModAdd(const NativeVectorT& b) const {
    if ((this->m_data.size() != b.m_data.size()) || this->m_modulus != b.m_modulus) {
        OPENFHE_THROW(lbcrypto::math_error, "ModAdd called on NativeVectorT's with different parameters.");
    }
    NativeVectorT ans(*this);
    IntegerType modulus = this->m_modulus;
    for (usint i = 0; i < ans.m_data.size(); i++) {
        ans.m_data[i].ModAddFastEq(b[i], modulus);
    }
    return ans;
}

template <class IntegerType>
const NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModAddEq(const NativeVectorT& b) {
    if ((this->m_data.size() != b.m_data.size()) || this->m_modulus != b.m_modulus) {
        OPENFHE_THROW(lbcrypto::math_error, "ModAddEq called on NativeVectorT's with different parameters.");
    }
    IntegerType modulus = this->m_modulus;
    for (usint i = 0; i < this->m_data.size(); i++) {
        this->m_data[i].ModAddFastEq(b[i], modulus);
    }
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModSub(const IntegerType& b) const {
    NativeVectorT ans(*this);
    for (usint i = 0; i < this->m_data.size(); i++) {
        ans.m_data[i].ModSubEq(b, this->m_modulus);
    }
    return ans;
}

template <class IntegerType>
const NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModSubEq(const IntegerType& b) {
    for (usint i = 0; i < this->m_data.size(); i++) {
        this->m_data[i].ModSubEq(b, this->m_modulus);
    }
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModSub(const NativeVectorT& b) const {
    if ((this->m_data.size() != b.m_data.size()) || this->m_modulus != b.m_modulus) {
        OPENFHE_THROW(lbcrypto::math_error, "ModSub called on NativeVectorT's with different parameters.");
    }
    NativeVectorT ans(*this);
    for (usint i = 0; i < ans.m_data.size(); i++) {
        ans.m_data[i].ModSubFastEq(b.m_data[i], this->m_modulus);
    }
    return ans;
}

template <class IntegerType>
const NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModSubEq(const NativeVectorT& b) {
    if ((this->m_data.size() != b.m_data.size()) || this->m_modulus != b.m_modulus) {
        OPENFHE_THROW(lbcrypto::math_error, "ModSubEq called on NativeVectorT's with different parameters.");
    }
    for (usint i = 0; i < this->m_data.size(); i++) {
        this->m_data[i].ModSubFastEq(b.m_data[i], this->m_modulus);
    }
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModMul(const IntegerType& b) const {
    NativeVectorT ans(*this);
    IntegerType modulus = this->m_modulus;
    IntegerType bLocal  = b;
    if (bLocal >= modulus) {
        bLocal.ModEq(modulus);
    }
    IntegerType bPrec = bLocal.PrepModMulConst(modulus);
    for (usint i = 0; i < this->m_data.size(); i++) {
        ans.m_data[i].ModMulFastConstEq(bLocal, modulus, bPrec);
    }
    return ans;
}

template <class IntegerType>
const NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModMulEq(const IntegerType& b) {
    IntegerType modulus = this->m_modulus;
    IntegerType bLocal  = b;
    if (bLocal >= modulus) {
        bLocal.ModEq(modulus);
    }
    IntegerType bPrec = bLocal.PrepModMulConst(modulus);
    for (usint i = 0; i < this->m_data.size(); i++) {
        this->m_data[i].ModMulFastConstEq(bLocal, modulus, bPrec);
    }
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModMul(const NativeVectorT& b) const {
    if ((this->m_data.size() != b.m_data.size()) || this->m_modulus != b.m_modulus) {
        OPENFHE_THROW(lbcrypto::math_error, "ModMul called on NativeVectorT's with different parameters.");
    }
    NativeVectorT ans(*this);

    IntegerType modulus = this->m_modulus;
    IntegerType mu      = modulus.ComputeMu();
    for (usint i = 0; i < this->m_data.size(); i++) {
        ans.m_data[i].ModMulFastEq(b[i], modulus, mu);
    }
    return ans;
}

template <class IntegerType>
const NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModMulEq(const NativeVectorT& b) {
    if ((this->m_data.size() != b.m_data.size()) || this->m_modulus != b.m_modulus) {
        OPENFHE_THROW(lbcrypto::math_error, "ModMulEq called on NativeVectorT's with different parameters.");
    }

    IntegerType modulus = this->m_modulus;
    IntegerType mu      = modulus.ComputeMu();
    for (usint i = 0; i < this->m_data.size(); i++) {
        this->m_data[i].ModMulFastEq(b[i], modulus, mu);
    }
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModByTwo() const {
    NativeVectorT ans(*this);
    ans.ModByTwoEq();
    return ans;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModExp(const IntegerType& b) const {
    NativeVectorT ans(*this);
    for (usint i = 0; i < this->m_data.size(); i++) {
        ans.m_data[i].ModExpEq(b, this->m_modulus);
    }
    return ans;
}

template <class IntegerType>
const NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModExpEq(const IntegerType& b) {
    for (usint i = 0; i < this->m_data.size(); i++) {
        this->m_data[i].ModExpEq(b, this->m_modulus);
    }
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModInverse() const {
    NativeVectorT ans(*this);
    for (usint i = 0; i < this->m_data.size(); i++) {
        ans.m_data[i].ModInverseEq(this->m_modulus);
    }
    return ans;
}

template <class IntegerType>
const NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModInverseEq() {
    for (usint i = 0; i < this->m_data.size(); i++) {
        this->m_data[i].ModInverseEq(this->m_modulus);
    }
    return *this;
}

template <class IntegerType>
const NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModByTwoEq() {
    IntegerType halfQ(this->GetModulus() >> 1);
    for (size_t i = 0; i < this->GetLength(); i++) {
        if (this->operator[](i) > halfQ) {
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
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::MultWithOutMod(const NativeVectorT& b) const {
    if ((this->m_data.size() != b.m_data.size()) || this->m_modulus != b.m_modulus) {
        OPENFHE_THROW(lbcrypto::math_error, "ModMul called on NativeVectorT's with different parameters.");
    }
    NativeVectorT ans(*this);
    for (usint i = 0; i < ans.m_data.size(); i++) {
        ans.m_data[i].MulEq(b.m_data[i]);
    }
    return ans;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::MultiplyAndRound(const IntegerType& p,
                                                                        const IntegerType& q) const {
    NativeVectorT ans(*this);
    IntegerType halfQ(this->m_modulus >> 1);
    for (usint i = 0; i < this->m_data.size(); i++) {
        if (ans.m_data[i] > halfQ) {
            IntegerType temp = this->m_modulus - ans.m_data[i];
            ans.m_data[i]    = this->m_modulus - temp.MultiplyAndRound(p, q);
        }
        else {
            ans.m_data[i].MultiplyAndRoundEq(p, q);
            ans.m_data[i].ModEq(this->m_modulus);
        }
    }
    return ans;
}

template <class IntegerType>
const NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::MultiplyAndRoundEq(const IntegerType& p,
                                                                                 const IntegerType& q) {
    IntegerType halfQ(this->m_modulus >> 1);
    for (usint i = 0; i < this->m_data.size(); i++) {
        if (this->m_data[i] > halfQ) {
            IntegerType temp = this->m_modulus - this->m_data[i];
            this->m_data[i]  = this->m_modulus - temp.MultiplyAndRound(p, q);
        }
        else {
            this->m_data[i].MultiplyAndRoundEq(p, q);
            this->ModEq(this->m_modulus);
        }
    }
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::DivideAndRound(const IntegerType& q) const {
    NativeVectorT ans(*this);
    IntegerType halfQ(this->m_modulus >> 1);
    for (usint i = 0; i < this->m_data.size(); i++) {
        if (ans.m_data[i] > halfQ) {
            IntegerType temp = this->m_modulus - ans.m_data[i];
            ans.m_data[i]    = this->m_modulus - temp.DivideAndRound(q);
        }
        else {
            ans.m_data[i].DivideAndRoundEq(q);
        }
    }
    return ans;
}

template <class IntegerType>
const NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::DivideAndRoundEq(const IntegerType& q) {
    IntegerType halfQ(this->m_modulus >> 1);
    for (usint i = 0; i < this->m_data.size(); i++) {
        if (this->m_data[i] > halfQ) {
            IntegerType temp = this->m_modulus - this->m_data[i];
            this->m_data[i]  = this->m_modulus - temp.DivideAndRound(q);
        }
        else {
            this->m_data[i].DivideAndRoundEq(q);
        }
    }
    return *this;
}

// OTHER FUNCTIONS

// Gets the ind
template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::GetDigitAtIndexForBase(usint index, usint base) const {
    NativeVectorT ans(*this);
    for (usint i = 0; i < this->m_data.size(); i++) {
        ans.m_data[i] = IntegerType(ans.m_data[i].GetDigitAtIndexForBase(index, base));
    }
    return ans;
}

template class NativeVectorT<NativeInteger>;

}  // namespace intnat
