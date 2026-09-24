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

#ifndef SRC_CORE_INCLUDE_UTILS_EXCEPTION_H_
#define SRC_CORE_INCLUDE_UTILS_EXCEPTION_H_

#include <cstddef>
#include <exception>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "utils/get-call-stack.h"

namespace lbcrypto {

/**
 * @brief Captures an exception thrown inside an OpenMP parallel region or thread so it can be rethrown in the
 * calling thread after the region ends.
 *
 * Exceptions thrown inside a critical region or an OpenMP thread must be caught in the thread where they were
 * thrown. Declare an instance before the region, call CaptureException() from a catch(...) block inside it (or
 * wrap the body in Run()), and call Rethrow() after the region; see the usage example below the class.
 */
class ThreadException {
    std::exception_ptr Ptr;
    std::mutex Lock;

  public:
    ThreadException() : Ptr(nullptr) {}
    ~ThreadException() {}
    /**
   * @brief Rethrows the captured exception, if any, in the calling thread; does nothing when none was captured.
   */
    void Rethrow() {
        if (this->Ptr)
            std::rethrow_exception(this->Ptr);
    }
    /**
   * @brief Stores the exception currently being handled (call from inside a catch block); thread-safe, the last
   * captured exception wins.
   */
    void CaptureException() {
        std::unique_lock<std::mutex> guard(this->Lock);
        this->Ptr = std::current_exception();
    }

    /**
   * @brief Invokes f(params...) and captures any exception it throws instead of letting it escape the thread.
   * @param f callable to run
   * @param params arguments forwarded to f
   */
    template <typename Function, typename... Parameters>
    void Run(Function f, Parameters... params) {
        try {
            f(params...);
        } catch (...) {
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

/**
 * @brief Exception type thrown by OpenFHE, normally through the OPENFHE_THROW macro. Records the error
 * description together with the throw site (file, function, line) and the call stack at construction; what()
 * returns "file:l.line:function(): description".
 */
class OpenFHEException : public std::exception {
    // clang-format off
    std::string m_errorDescription;
    std::string m_fileName;
    std::string m_funcName;
    size_t m_lineNumber{0};

    std::string m_errorMessage;
    std::vector<std::string> m_callStack;

    static std::string buildErrorMessage(const std::string& file,
                                         const std::string& func,
                                         std::size_t line,
                                         const std::string& desc) {
        return file + ":l." + std::to_string(line) + ":" + func + "(): " + desc;
    }

public:
    /**
     * @brief Constructs the exception and captures the call stack.
     * @param errorDescription description of the error
     * @param fileName source file of the throw site (__FILE__)
     * @param funcName function of the throw site (__func__)
     * @param lineNumber line of the throw site (__LINE__)
     */
    explicit OpenFHEException(const std::string_view errorDescription,
                              const std::string fileName,
                              const std::string funcName,
                              size_t lineNumber)
        : m_errorDescription(errorDescription),
          m_fileName(fileName),
          m_funcName(funcName),
          m_lineNumber(lineNumber),
          m_errorMessage(buildErrorMessage(m_fileName, m_funcName, m_lineNumber, m_errorDescription)),
          m_callStack(get_call_stack()) {}
    // clang-format on

    ~OpenFHEException() override = default;
    OpenFHEException(const OpenFHEException&) = default;
    OpenFHEException& operator=(const OpenFHEException&) = default;

    /**
   * @brief Returns the formatted error message "file:l.line:function(): description".
   * @return the error message
   */
    const char* what() const noexcept override {
        return m_errorMessage.c_str();
    }

    /**
   * @brief Returns the call stack captured when the exception was constructed, one frame per entry (empty when
   * call-stack capture is not available in this build).
   * @return the call stack frames
   */
    std::vector<std::string> getCallStackAsVector() const {
        return m_callStack;
    }

    // getCallStackAsString() was added to be used by JSON logger. the implementtion will follow
    /**
   * @brief Placeholder for a single-string rendering of the call stack intended for a JSON logger.
   * @return an empty string; the implementation is not yet provided
   */
    std::string getCallStackAsString() const {
        return std::string();

        // if (m_callStack.empty())
        //     return {};

        // std::string ret = m_callStack.front();
        // for (std::size_t i = 1; i < m_callStack.size(); ++i) {
        //     ret += '\n';
        //     ret += m_callStack[i];
        // }
        // return ret;
    }
};

/**
 * @brief Throws an OpenFHEException with the given description, tagged with the current file, function, and line.
 * @param desc error description (anything convertible to std::string_view)
 */
#define OPENFHE_THROW(desc) throw lbcrypto::OpenFHEException((desc), __FILE__, __func__, __LINE__)

}  // namespace lbcrypto

#endif  // SRC_CORE_INCLUDE_UTILS_EXCEPTION_H_
