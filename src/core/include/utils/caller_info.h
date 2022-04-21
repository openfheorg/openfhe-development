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
  This file contains macros to help access caller function information
 */

#ifndef __CALLER_INFO_H__
#define __CALLER_INFO_H__

#include <string>

/*
 *  ATTN: the caller information is accessible if BUILTIN_INFO_AVAILABLE is defined in CMakeLists.txt.
 *        Currently, USE_BUILTIN_INFO is defined for GCC only.
 *  Instructions how to use the macros defined below:
 *  if you want to access the caller information from within a function
 *  you should add CALLER_INFO_ARGS_HDR as the last argument to your function
 *  in the header file where the function is declared and add
 *  CALLER_INFO_ARGS_CPP as the last argument to your function in the source
 *  file where it is implemented. if you have the function definition only then
 *  CALLER_INFO_ARGS_HDR should be added. After that you can use the string
 *  CALLER_INFO inside the function.
 *
 *  Example:
 *  before adding caller information
 *  *.h:
 *      void foo(int x);
 *  *.cpp:
 *      void foo(int x) {
 *          std::cout << "foo() input: " << x << std::endl;
 *      }
 *
 *  after adding caller information
 *  *.h:
 *      void foo(int x, CALLER_INFO_ARGS_HDR);
 *  *.cpp:
 *      void foo(int x, CALLER_INFO_ARGS_CPP) {
 *          std::cout << "foo() input: " << x << CALLER_INFO << std::endl;
 *      }
 */

#ifdef BUILTIN_INFO_AVAILABLE

    #define CALLER_INFO_ARGS_HDR                                                                  \
        const char *callerFile = __builtin_FILE(), const char *callerFunc = __builtin_FUNCTION(), \
                   size_t callerLine = __builtin_LINE()

    #define CALLER_INFO \
        std::string(" [called from: ") + callerFile + ":" + callerFunc + "():l." + std::to_string(callerLine) + "]"

#else

    #define CALLER_INFO_ARGS_HDR const char *callerFile = "", const char *callerFunc = "", size_t callerLine = 0

    #define CALLER_INFO std::string("")

#endif  // BUILTIN_INFO_AVAILABLE

#define CALLER_INFO_ARGS_CPP const char *callerFile, const char *callerFunc, size_t callerLine

#endif  // __CALLER_INFO_H__
