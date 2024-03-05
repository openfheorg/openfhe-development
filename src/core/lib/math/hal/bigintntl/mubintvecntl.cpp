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
  This file contains the cpp implementation of mgmpintvec, a <vector> of gmpint, with associated math operators
 */

//==================================================================================
// This file is included only if WITH_NTL is set to ON in CMakeLists.txt
//==================================================================================

#include "config_core.h"
#ifdef WITH_NTL

    #define FASTNLOOSE
    #define FORCE_NORMALIZATION

    #include <chrono>
    #include "math/math-hal.h"
    #include "math/hal/bigintntl/mubintvecntl.h"
    #include "time.h"
    #include "utils/debug.h"
    #include "utils/serializable.h"

namespace NTL {

// CONSTRUCTORS

// constructors without moduli
//&&&
// copy ctor with vector inputs
// creation ctors without moduli are marked GARBAGE
template <class myT>
myVecP<myT>::myVecP(const myVecP<myT>& a) : Vec<myT>(INIT_SIZE, a.length()) {
    int rv = this->CopyModulus(a);
    if (rv == -1) {
    #ifdef WARN_BAD_MODULUS
        std::cerr << "in myVecP(myVecP) Bad CopyModulus" << std::endl;
    #endif
    }
    *this = a;
}

// movecopy ctor
template <class myT>
myVecP<myT>::myVecP(myVecP<myT>&& a) : Vec<myT>(INIT_SIZE, a.length()) {
    int rv = this->CopyModulus(a);
    if (rv == -1) {
    #ifdef WARN_BAD_MODULUS
        std::cerr << "in myVecP(myVecP &&) Bad CopyModulus" << std::endl;
    #endif
    }
    this->move(a);
}

// constructors with moduli
// ctor myT moduli
template <class myT>
myVecP<myT>::myVecP(const long n, const myT& q) : Vec<myT>(INIT_SIZE, n) {  // NOLINT
    this->SetModulus(q);
}

// constructors with moduli and initializer list
// ctor myT moduli
template <class myT>
myVecP<myT>::myVecP(const long n, const myT& q, std::initializer_list<uint64_t> rhs)  // NOLINT
    : Vec<myT>(INIT_SIZE, n) {                                                        // NOLINT
    this->SetModulus(q);
    usint len = rhs.size();
    for (size_t i = 0; i < size_t(n); i++) {  // this loops over each entry
        if (i < len) {
            (*this)[i] = myT(*(rhs.begin() + i)) % m_modulus;
        }
        else {
            (*this)[i] = myT(0);
        }
    }
}

template <class myT>
myVecP<myT>::myVecP(const long n, const myT& q, std::initializer_list<std::string> rhs)  // NOLINT
    : Vec<myT>(INIT_SIZE, n) {                                                           // NOLINT
    this->SetModulus(q);
    usint len = rhs.size();
    for (size_t i = 0; i < size_t(n); i++) {  // this loops over each entry
        if (i < len) {
            (*this)[i] = myT(*(rhs.begin() + i)) % m_modulus;
        }
        else {
            (*this)[i] = myT(0);
        }
    }
}

template <class myT>
myVecP<myT>::myVecP(const myVecP<myT>& a, const myT& q) : Vec<myT>(a) {
    this->SetModulus(q);
    (*this) %= q;
}

// ctor with string moduli
template <class myT>
myVecP<myT>::myVecP(size_t n, const std::string& sq) : Vec<myT>(INIT_SIZE, n) {
    this->SetModulus(myT(sq));
}

// copy with char * moduli
template <class myT>
myVecP<myT>::myVecP(const myVecP<myT>& a, const std::string& sq) : Vec<myT>(a) {
    this->SetModulus(myT(sq));
}

// ctor with uint64_t moduli
template <class myT>
myVecP<myT>::myVecP(size_t n, uint64_t q) : Vec<myT>(INIT_SIZE, n) {
    this->SetModulus(q);
}

// copy with unsigned int moduli
template <class myT>
myVecP<myT>::myVecP(const myVecP<myT>& a, const uint64_t q) : Vec<myT>(a) {
    this->SetModulus(q);
    for (size_t i = 0; i < this->GetLength(); i++) {
        (*this)[i] %= myT(q);
    }
}

// constructor specifying the myvec as a vector of strings
template <class myT>
myVecP<myT>::myVecP(std::vector<std::string>& s) {
    usint len = s.size();
    this->resize(len);
    for (size_t i = 0; i < len; i++) {
        (*this)[i] = myT(s[i]);
    }
    this->m_modulus_state = GARBAGE;
}

// constructor specifying the myvec as a vector of strings with modulus
template <class myT>
myVecP<myT>::myVecP(std::vector<std::string>& s, const myT& q) {
    usint len = s.size();
    this->resize(len);
    this->SetModulus(q);
    for (size_t i = 0; i < len; i++) {
        (*this)[i] = myT(s[i]) % q;
    }
}

// constructor specifying the myvec as a vector of strings with modulus
template <class myT>
myVecP<myT>::myVecP(std::vector<std::string>& s, const char* sq) {
    usint len = s.size();
    this->resize(len);
    myT zzq(sq);
    this->SetModulus(zzq);
    for (size_t i = 0; i < len; i++) {
        (*this)[i] = myT(s[i]) % zzq;
    }
}

// constructor specifying the myvec as a vector of strings with modulus
template <class myT>
myVecP<myT>::myVecP(std::vector<std::string>& s, const uint64_t q) {
    usint len = s.size();
    this->resize(len);
    myT zzq(q);
    this->SetModulus(zzq);
    for (size_t i = 0; i < len; i++) {
        (*this)[i] = myT(s[i]) % zzq;
    }
}

// ASSIGNMENT OPERATORS

// Assignment with initializer list of uint64_ts
// keeps current modulus

template <class myT>
myVecP<myT>& myVecP<myT>::operator=(std::initializer_list<uint64_t> rhs) {
    size_t len = rhs.size();
    if (this->GetLength() < len) {
        this->resize(len);
    }

    for (size_t i = 0; i < this->GetLength(); i++) {  // this loops over each entry
        if (i < len) {
    #ifdef FORCE_NORMALIZATION
            if (isModulusSet())
                (*this)[i] = myT(*(rhs.begin() + i)) % m_modulus;
            else
                // must be set directly
    #endif
                (*this)[i] = myT(*(rhs.begin() + i));
        }
        else {
            (*this)[i] = myT(0);
        }
    }
    return *this;
}

// for some dumb reason they coded this., it is dangerous
template <class myT>
myVecP<myT>& myVecP<myT>::operator=(std::initializer_list<int32_t> rhs) {
    size_t len = rhs.size();
    if (this->GetLength() < len) {
        this->resize(len);
    }

    for (size_t i = 0; i < this->GetLength(); i++) {  // this loops over each entry
        if (i < len) {
            int tmp = *(rhs.begin() + i);
            if (tmp < 0) {
                std::cout << "warning trying to assign negative integer value" << std::endl;
            }
    #ifdef FORCE_NORMALIZATION
            if (isModulusSet())
                (*this)[i] = myT(tmp) % m_modulus;
            else
                // must be set directly
    #endif
                (*this)[i] = myT(tmp);
        }
        else {
            (*this)[i] = myT(0);
        }
    }
    return *this;
}

// Assignment with initializer list of strings
// keeps current modulus
template <class myT>
myVecP<myT>& myVecP<myT>::operator=(std::initializer_list<std::string> rhs) {
    size_t len = rhs.size();
    if (this->GetLength() < len) {
        this->resize(len);
    }

    for (size_t i = 0; i < this->GetLength(); i++) {  // this loops over each entry
        if (i < len) {
    #ifdef FORCE_NORMALIZATION
            if (isModulusSet())
                (*this)[i] = myT(*(rhs.begin() + i)) % m_modulus;
            else
                // must be set directly
    #endif
                (*this)[i] = myT(*(rhs.begin() + i));
        }
        else {
            (*this)[i] = myT(0);
        }
    }
    return *this;
}

// keeps current modulus
// note this only assigns to the first element!!
template <class myT>
myVecP<myT>& myVecP<myT>::operator=(uint64_t val) {
    (*this)[0] = myT(val);
    #ifdef FORCE_NORMALIZATION
    if (isModulusSet())
        (*this)[0] %= m_modulus;
    #endif

    for (size_t i = 1; i < GetLength(); ++i) {
        (*this)[i] = myT(0);
    }
    return *this;
}

// do not keep current modulus but copies from rhs.
template <class myT>
myVecP<myT>& myVecP<myT>::operator=(const myVecP<myT>& rhs) {
    this->resize(rhs.GetLength());
    int rv = this->CopyModulus(rhs);
    if (rv == -1) {
    #ifdef WARN_BAD_MODULUS
        std::cerr << "in operator=(myVecP) Bad CopyModulus" << std::endl;
    #endif
    }
    for (size_t i = 0; i < rhs.GetLength(); i++) {
        (*this)[i] = rhs[i];
    }
    return *this;
}

// move copy do not keep current modulus but copies from rhs.
template <class myT>
myVecP<myT>& myVecP<myT>::operator=(myVecP<myT>&& rhs) {
    if (this != &rhs) {
        this->resize(rhs.GetLength());
        int rv = this->CopyModulus(rhs);
        if (rv == -1) {
    #ifdef WARN_BAD_MODULUS
            std::cerr << "in operator=(myVecP) Bad CopyModulus" << std::endl;
    #endif
        }
        this->move(rhs);
    }
    return *this;
}

template <class myT>
void myVecP<myT>::clear(myVecP<myT>& x) {
    size_t n = x.GetLength();
    for (size_t i = 0; i < n; i++) {
        NTL_NAMESPACE::clear(x[i]);
    }
    NTL_NAMESPACE::clear(x.m_modulus);
}

// not enabled yet

// ACCESSORS

// Switches the integers in the vector to values corresponding to the new
// modulus
//*  Algorithm: Integer i, Old Modulus om, New Modulus nm, delta = abs(om-nm):
// *  Case 1: om < nm
// *  if i > i > om/2
// *  i' = i + delta
// *  Case 2: om > nm
// *  i > om/2
// *  i' = i-delta
//
template <class myT>
void myVecP<myT>::SwitchModulus(const myT& newModulus) {
    myT oldModulus(this->m_modulus);
    myT n;
    myT oldModulusByTwo(oldModulus >> 1);
    myT diff((oldModulus > newModulus) ? (oldModulus - newModulus) : (newModulus - oldModulus));
    for (size_t i = 0; i < this->GetLength(); i++) {
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

// MODULAR ARITHMETIC FUNCTIONS

template <class myT>
myVecP<myT> myVecP<myT>::Mod(const myT& modulus) const {
    if (modulus == myT(2)) {
        return this->ModByTwo();
    }
    else {
        myT thisMod(this->GetModulus());
        myVecP ans(this->GetLength(), thisMod);  // zeroed out
        myT halfQ(thisMod >> 1);
        for (size_t i = 0; i < this->GetLength(); i++) {
            if ((*this)[i] > halfQ) {
                ans[i] = (*this)[i].ModSub(thisMod, modulus);
            }
            else {
                ans[i] = (*this)[i].Mod(modulus);
            }
        }
        return ans;
    }
}

template <class myT>
myVecP<myT>& myVecP<myT>::ModEq(const myT& modulus) {
    if (modulus == myT(2)) {
        return this->ModByTwoEq();
    }
    else {
        myT thisMod(this->GetModulus());
        myT halfQ(thisMod >> 1);
        for (size_t i = 0; i < this->GetLength(); i++) {
            if (this->operator[](i) > halfQ) {
                this->operator[](i).ModSubEq(thisMod, modulus);
            }
            else {
                this->operator[](i).ModEq(modulus);
            }
        }
        return *this;
    }
}

// method to add scalar to vector element at index i
template <class myT>
myVecP<myT> myVecP<myT>::ModAddAtIndex(size_t i, const myT& b) const {
    if (i > this->GetLength() - 1) {
        std::string errMsg = "myVecP::ModAddAtIndex. Index is out of range. i = " + std::to_string(i);
        OPENFHE_THROW(lbcrypto::math_error, errMsg);
    }
    myVecP ans(*this);  // copy vector
    ModulusCheck("myVecP::ModAddAtIndex");
    ans[i] = ans[i].ModAdd(b, this->m_modulus);
    return ans;
}

template <class myT>
myVecP<myT>& myVecP<myT>::ModAddAtIndexEq(size_t i, const myT& b) {
    if (i > this->GetLength() - 1) {
        std::string errMsg = "myVecP::ModAddAtIndex. Index is out of range. i = " + std::to_string(i);
        OPENFHE_THROW(lbcrypto::math_error, errMsg);
    }
    ModulusCheck("myVecP::ModAddAtIndex");
    (*this)[i] = (*this)[i].ModAdd(b, this->m_modulus);
    return *this;
}

// procedural addition
// todo make modulus explicit.
template <class myT>
inline void myVecP<myT>::modadd_p(myVecP<myT>& x, myVecP<myT> const& a, myVecP<myT> const& b) const {
    a.ArgCheckVector(b, "myVecP::modadd()");
    size_t n = a.GetLength();
    if (b.GetLength() != n)
        LogicError("myVecP<>vector add: dimension mismatch");

    x.resize(n);
    for (size_t i = 0; i < n; i++) {
    #ifndef FASTNLOOSE
        x[i] = a[i].ModAdd(b[i], m_modulus);  // modulo add
    #else
        x[i] = a[i].ModAddFast(b[i], m_modulus);  // modulo add
    #endif
    }
}

// procedural subtraction
// todo make modulus explicit.

template <class myT>
void myVecP<myT>::modsub_p(myVecP<myT>& x, myVecP<myT> const& a, myVecP<myT> const& b) const {
    a.ArgCheckVector(b, "myVecP::sub()");
    size_t n = a.GetLength();
    if (b.GetLength() != n)
        LogicError("myVecP<>vector sub: dimension mismatch");
    x.resize(n);
    for (size_t i = 0; i < n; i++) {
    #ifndef FASTNLOOSE
        x[i] = a[i].ModSub(b[i], m_modulus);  // inmplicit modulo sub
    #else
        x[i] = a[i].ModSubFast(b[i], m_modulus);  // inmplicit modulo sub
    #endif
    }
}

// todo make modulus explicit.
template <class myT>
inline void myVecP<myT>::modmul_p(myVecP<myT>& x, myVecP<myT> const& a, myVecP<myT> const& b) const {
    a.ArgCheckVector(b, "myVecP::mul()");
    unsigned int n = a.GetLength();
    if (b.GetLength() != n)
        LogicError("myVecP<>vector sub: dimension mismatch");

    x.resize(n);
    unsigned int i;
    for (i = 0; i < n; i++) {
    #ifndef FASTNLOOSE
        x[i] = a[i].ModMul(b[i], m_modulus);  // inmplicit modulo mul
    #else
        x[i] = a[i].ModMulFast(b[i], m_modulus);  // inmplicit modulo mul
    #endif
    }
}

template <class myT>
myVecP<myT> myVecP<myT>::ModExp(const myT& b) const {
    myVecP ans(*this);
    ModulusCheck("myVecP::ModExp");
    for (size_t i = 0; i < this->GetLength(); i++) {
        ans[i] = ans[i].ModExp(b % m_modulus, ans.m_modulus);
    }
    return ans;
}

template <class myT>
myVecP<myT>& myVecP<myT>::ModExpEq(const myT& b) {
    ModulusCheck("myVecP::ModExp");
    for (size_t i = 0; i < this->GetLength(); i++) {
        (*this)[i] = (*this)[i].ModExp(b % m_modulus, this->m_modulus);
    }
    return *this;
}

template <class myT>
myVecP<myT> myVecP<myT>::ModInverse(void) const {
    ModulusCheck("myVecP::ModInverse");
    myVecP ans(*this);
    for (size_t i = 0; i < this->GetLength(); i++) {
        ans[i] = ans[i].ModInverse(this->m_modulus);
    }
    return ans;
}

template <class myT>
myVecP<myT>& myVecP<myT>::ModInverseEq(void) {
    ModulusCheck("myVecP::ModInverse");
    for (size_t i = 0; i < this->GetLength(); i++) {
        (*this)[i] = (*this)[i].ModInverse(this->m_modulus);
    }
    return *this;
}

template <class myT>
myVecP<myT> myVecP<myT>::ModByTwo() const {
    myVecP ans(*this);
    ans.ModByTwoEq();
    return ans;
}

// method to mod by two
template <class myT>
myVecP<myT>& myVecP<myT>::ModByTwoEq() {
    myT halfQ(this->GetModulus() >> 1);
    for (size_t i = 0; i < this->GetLength(); i++) {
        if (this->operator[](i) > halfQ) {
            if (this->operator[](i).Mod(myT(2)) == myT(1)) {
                this->operator[](i) = 0;
            }
            else {
                this->operator[](i) = 1;
            }
        }
        else {
            if (this->operator[](i).Mod(myT(2)) == myT(1)) {
                this->operator[](i) = 1;
            }
            else {
                this->operator[](i) = 0;
            }
        }
    }
    return *this;
}

template <class myT>
myVecP<myT> myVecP<myT>::MultiplyAndRound(const myT& p, const myT& q) const {
    ModulusCheck("myVecP::MultiplyAndRound");
    myVecP ans(*this);
    myT halfQ(this->m_modulus >> 1);
    for (size_t i = 0; i < this->GetLength(); i++) {
        if (ans[i] > halfQ) {
            myT temp = this->m_modulus - ans[i];
            ans[i]   = this->m_modulus - temp.MultiplyAndRound(p, q);
        }
        else {
            ans[i] = ans[i].MultiplyAndRound(p, q).Mod(this->m_modulus);
        }
    }
    return ans;
}

template <class myT>
myVecP<myT>& myVecP<myT>::MultiplyAndRoundEq(const myT& p, const myT& q) {
    ModulusCheck("myVecP::MultiplyAndRound");
    myT halfQ(this->m_modulus >> 1);
    for (size_t i = 0; i < this->GetLength(); i++) {
        if ((*this)[i] > halfQ) {
            myT temp   = this->m_modulus - (*this)[i];
            (*this)[i] = this->m_modulus - temp.MultiplyAndRound(p, q);
        }
        else {
            (*this)[i] = (*this)[i].MultiplyAndRound(p, q).Mod(this->m_modulus);
        }
    }
    return *this;
}

template <class myT>
myVecP<myT> myVecP<myT>::DivideAndRound(const myT& q) const {
    ModulusCheck("myVecP::DivideAndRound");
    myVecP ans(*this);
    myT halfQ(this->m_modulus >> 1);
    for (size_t i = 0; i < this->GetLength(); i++) {
        if (ans[i] > halfQ) {
            myT temp = this->m_modulus - ans[i];
            ans[i]   = this->m_modulus - temp.DivideAndRound(q);
        }
        else {
            ans[i] = ans[i].DivideAndRound(q);
        }
    }
    return ans;
}

template <class myT>
myVecP<myT>& myVecP<myT>::DivideAndRoundEq(const myT& q) {
    ModulusCheck("myVecP::DivideAndRound");
    myT halfQ(this->m_modulus >> 1);
    for (size_t i = 0; i < this->GetLength(); i++) {
        if ((*this)[i] > halfQ) {
            myT temp   = this->m_modulus - (*this)[i];
            (*this)[i] = this->m_modulus - temp.DivideAndRound(q);
        }
        else {
            (*this)[i] = (*this)[i].DivideAndRound(q);
        }
    }
    return *this;
}

// OTHER FUNCTIONS

// not sure what this does..
template <class myT>
myVecP<myT> myVecP<myT>::GetDigitAtIndexForBase(size_t index, usint base) const {
    myVecP ans(*this);
    for (size_t i = 0; i < this->GetLength(); i++) {
        ans[i] = ans[i].GetDigitAtIndexForBase(index, base);
    }
    return ans;
}

template class myVecP<myZZ>;

}  // namespace NTL

#endif
