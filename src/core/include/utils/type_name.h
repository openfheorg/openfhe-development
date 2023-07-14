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
#ifndef __TYPE_NAME_H__
#define __TYPE_NAME_H__

#include "utils/demangle.h"
#include <typeinfo>
#include <iostream>
#include <memory>
#include <string>

// define my own "is_shared_pointer"
template <typename T>
struct is_shared_pointer : std::false_type {};
template <typename T>
struct is_shared_pointer<std::shared_ptr<T>> : std::true_type {};
template <typename T>
struct is_shared_pointer<std::shared_ptr<T const>> : std::true_type {};
//=============================================================================
// sharedPtr() returns true if the argument is a shared_ptr or false otherwise
template <typename T>
bool sharedPtr(const T& t) {
    return is_shared_pointer<T>::value;
}
//=============================================================================
// even the code is the same for both versions of typeName() below,
// I did decide to have 2 functions (for pointers and for objects) for now
// typeName() for objects
template <typename T,
          typename std::enable_if<!std::is_pointer<T>::value && !is_shared_pointer<T>::value, bool>::type = true>
std::string typeName(const T& obj) {
    return demangle(typeid(obj).name());
}
//=============================================================================
// typeName() for pointers
template <typename T,
          typename std::enable_if<std::is_pointer<T>::value || is_shared_pointer<T>::value, bool>::type = true>
std::string typeName(const T& ptr) {
    return demangle(typeid(ptr).name());
}
//=============================================================================
// getObjectType() takes either a regular pointer or a shared_ptr as the argument and
// returns the actual type of the object ptr points to.
template <typename T,
          typename std::enable_if<std::is_pointer<T>::value || is_shared_pointer<T>::value, bool>::type = true>
std::string objectTypeName(const T& ptr) {
    return demangle(typeid(*ptr).name());
}
//=============================================================================

#endif  // __TYPE_NAME_H__
