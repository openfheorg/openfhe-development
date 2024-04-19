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
  framework for exceptions in OpenFHE
 */

#ifndef SRC_CORE_LIB_UTILS_EXCEPTION_H_
#define SRC_CORE_LIB_UTILS_EXCEPTION_H_

#include "utils/get-call-stack.h"
#include <exception>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

namespace lbcrypto {

// Exceptions thrown inside of a critical region, or inside of an omp thread,
// must be caught in the same thread where thrown, or Bad Things Happen
//
// This class is used to catch and rethrow exceptions from threads/critical
// regions (thank you stack overflow)
class ThreadException {
    std::exception_ptr Ptr;
    std::mutex Lock;

public:
    ThreadException() : Ptr(nullptr) {}
    ~ThreadException() {}
    void Rethrow() {
        if (this->Ptr)
            std::rethrow_exception(this->Ptr);
    }
    void CaptureException() {
        std::unique_lock<std::mutex> guard(this->Lock);
        this->Ptr = std::current_exception();
    }

    template <typename Function, typename... Parameters>
    void Run(Function f, Parameters... params) {
        try {
            f(params...);
        }
        catch (...) {
            CaptureException();
        }
    }
};

// how  to use ThreadException
// To use this, declare an instance of the object before the critical
// region/thread, catch exceptions in thread with CaptureException, then after
// the region call object.Rethrow()
// #pragma omp parallel for
// for (unsigned i = 0; i < rv.size(); i++) try {
//     rv.polys[i] = (polys[i].*f)();
//   } catch (...) {
//     e.CaptureException();
//   }
// e.Rethrow();
//
// // use of Run looks like:
// ThreadException e;
// #pragma omp parallel for
// for (int i = 0; i < n; i++) {
//   e.Run([=] {
//     // code that might throw
//     // ...
//   });
// }
// e.Rethrow();

class OpenFHEException : public std::exception {
    std::string m_errorDescription;
    std::string m_fileName;
    std::string m_funcName;
    size_t m_lineNumber;

    std::string m_errorMessage;
    std::vector<std::string> m_callStack;

public:
    OpenFHEException(const std::string errorDescription, const std::string fileName = __builtin_FILE(),
                     const std::string funcName = __builtin_FUNCTION(), size_t lineNumber = __builtin_LINE())
        : m_errorDescription(errorDescription), m_fileName(fileName), m_funcName(funcName), m_lineNumber(lineNumber) {
        m_errorMessage =
            m_fileName + ":l." + std::to_string(m_lineNumber) + ":" + m_funcName + "(): " + m_errorDescription;
        m_callStack = get_call_stack();
    }

    OpenFHEException(const OpenFHEException& ex) = default;

    const char* what() const noexcept {
        return m_errorMessage.c_str();
    }

    std::vector<std::string> getCallStackAsVector() {
        return m_callStack;
    }

    // getCallStackAsString() was added to be used by JSON logger. the implementtion will follow
    std::string getCallStackAsString() {
        return std::string();
    }
};

#define OPENFHE_THROW(expr) throw lbcrypto::OpenFHEException(expr)

}  // namespace lbcrypto

#endif /* SRC_CORE_LIB_UTILS_EXCEPTION_H_ */
