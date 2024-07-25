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
  Helper functions for unittests
 */

#ifndef _UNIT_TEST_UTILS_H_
#define _UNIT_TEST_UTILS_H_

#include "gtest/gtest.h"
#include "UnitTestException.h"
#include <vector>
#include <string>
#include <algorithm>
#include <csignal>
#include <complex>

// some functions are inlined in this files to avoid link errors
//===========================================================================================================
// simple macro for in cases with exceptions
#define UT_EXPECT_THROW_SIMPLE(func)  \
    PackedEncoding::Destroy();        \
    try {                             \
        func;                         \
        EXPECT_EQ(0, 1);              \
    }                                 \
    catch (const std::exception& e) { \
        EXPECT_EQ(1, 1);              \
    }
//===========================================================================================================
constexpr double EPSILON = 0.00000001;

constexpr double EPSILON_HIGH = 0.0001;

/**
 * Function to check equality of 2 numeric values
 *
 * @param a      first value to compare
 * @param b      second value to compare
 * @param eps    minimum precision to consider a and b equal. Default is EPSILON
 */
template <typename T>
bool checkEquality(const T& a, const T& b, const double eps = EPSILON) {
    return (abs(a - b) <= eps);
}

/**
 * Function to check equality of 2 numeric vectors
 *
 * @param a      first vector to compare
 * @param b      second vector to compare
 * @param eps    minimum precision to consider a and b equal. Default is EPSILON
 */
template <typename V>
bool checkEquality(const std::vector<V>& a, const std::vector<V>& b, const double eps = EPSILON) {
    if (a.size() != b.size())
        return false;

    return std::equal(a.begin(), a.end(), b.begin(),
                      [&eps](const V& a, const V& b) { return checkEquality(a, b, eps); });
}

/**
 * Function to check equality of 2 numeric vectors
 *
 * @param a      first vector to compare
 * @param b      second vector to compare
 * @param errMsg Debug message to display upon failure
 * @param eps    minimum precision to consider a and b equal. Default is EPSILON
 */
template <typename V>
void checkEquality(const std::vector<V>& a, const std::vector<V>& b, const double eps, const std::string& errMsg) {
    EXPECT_TRUE(checkEquality(a, b, eps)) << errMsg;
}
//===========================================================================================================
// typename T can be any numeric type or float/double
template <typename T>
std::vector<std::complex<double>> toComplexDoubleVec(const std::vector<T>& v) {
    std::vector<std::complex<double>> vec(v.size());
    std::transform(v.begin(), v.end(), vec.begin(), [](T elem) { return std::complex<double>(elem, 0); });

    return vec;
}

//// typename T can be any integral type
// template<typename T>
// std::vector<int64_t> integerVec2int64Vec(const std::vector<T>& v) {
//    std::vector<int64_t> vec(v.size());
//    std::transform(v.begin(), v.end(), vec.begin(), [](T elem) { return static_cast<int64_t>(elem); });
//
//    return vec;
// }
//===========================================================================================================
// Helper function to check automorphism
inline bool CheckAutomorphism(const std::vector<int64_t>& result, const std::vector<int64_t>& init) {
    for (const auto& val : init) {
        if (!(std::find(result.begin(), result.end(), val) != result.end())) {
            return false;
        }
    }

    return true;
}
//===========================================================================================================
// generate a random printable string of length outStrLength
inline std::string RandomString(uint64_t outStringLength) {
    auto getRandomChar = []() -> char {
        const char charset[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";
        const size_t max_index = (sizeof(charset) - 1);
        return charset[rand() % max_index];
    };

    std::string retString(outStringLength, 0);
    std::generate_n(retString.begin(), outStringLength, getRandomChar);

    return retString;
}
//===========================================================================================================
// check if a string is empty
inline bool isEmpty(const std::string& str) {
    const std::string whitespace = " \t\n\r\v\f";
    if (str.empty() || str.find_first_not_of(whitespace) == std::string::npos)
        return true;

    return false;
}
//===========================================================================================================
inline void sighandler(int signum) {
    std::cerr << "Execution stopped after processing signal [" << signum;
    switch (signum) {
        case SIGTERM:
            std::cerr << "] - termination request, sent to the program" << std::endl;
            break;
        case SIGSEGV:
            std::cerr << "] - invalid memory access (segmentation fault)" << std::endl;
            break;
        case SIGINT:
            std::cerr << "] - external interrupt, usually initiated by the user" << std::endl;
            break;
        case SIGILL:
            std::cerr << "] - invalid program image, such as invalid instruction" << std::endl;
            break;
        case SIGABRT:
            std::cerr << "] - abnormal termination condition, as is e.g. initiated by std::abort()" << std::endl;
            break;
        case SIGFPE:
            std::cerr << "] - erroneous arithmetic operation such as divide by zero" << std::endl;
            break;
        default:
            std::cerr << "]" << std::endl;
            break;
    }
    exit(1);
}

// setupSignals() should be included in to every unit test as it may help if a unit test crashes
inline void setupSignals() {
    std::signal(SIGINT, sighandler);
    std::signal(SIGABRT, sighandler);
    std::signal(SIGFPE, sighandler);
    std::signal(SIGILL, sighandler);
    std::signal(SIGSEGV, sighandler);
    std::signal(SIGTERM, sighandler);
}

#endif  // _UNIT_TEST_UTILS_H_
