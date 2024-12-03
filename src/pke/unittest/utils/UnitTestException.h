//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2024, NJIT, Duality Technologies Inc. and other contributors
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

#ifndef __UNIT_TEST_EXCEPTION_H__
#define __UNIT_TEST_EXCEPTION_H__

#include "gtest/gtest.h"
#include "utils/demangle.h"
#include <iostream>
#include <string>

// TODO (dsuponit): demangle separately for linux, MacOS and Windows. see some links below
// https://stackoverflow.com/questions/142508/how-do-i-check-os-with-a-preprocessor-directive
// https://docs.microsoft.com/en-us/windows/win32/debug/retrieving-undecorated-symbol-names
#if defined(__EMSCRIPTEN__)
    #define UNIT_TEST_EXCEPTION_TYPE_NAME "EMSCRIPTEN_UNKNOWN";
#else
    #define UNIT_TEST_EXCEPTION_TYPE_NAME demangle(__cxxabiv1::__cxa_current_exception_type()->name())
#endif

// UNIT_TEST_HANDLE_ALL_EXCEPTIONS must always fail
#define UNIT_TEST_HANDLE_ALL_EXCEPTIONS                                                                        \
    std::string name(UNIT_TEST_EXCEPTION_TYPE_NAME);                                                           \
    std::cerr << "Unknown exception of type \"" << name << "\" thrown from " << __func__ << "()" << std::endl; \
    EXPECT_TRUE(0 == 1) << failmsg;

#endif  // __UNIT_TEST_EXCEPTION_H__

