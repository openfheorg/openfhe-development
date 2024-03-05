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

#include <exception>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>

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
class openfhe_error : public std::runtime_error {
    std::string filename;
    int linenum;
    std::string message;

public:
    openfhe_error(const std::string& file, int line, const std::string& what)
        : std::runtime_error(what), filename(file), linenum(line) {
        message = filename + ":" + std::to_string(linenum) + " " + what;
    }

    const char* what() const throw() {
        return message.c_str();
    }

    const std::string& GetFilename() const {
        return filename;
    }
    int GetLinenum() const {
        return linenum;
    }
};

class config_error : public openfhe_error {
public:
    config_error(const std::string& file, int line, const std::string& what) : openfhe_error(file, line, what) {}
};

class math_error : public openfhe_error {
public:
    math_error(const std::string& file, int line, const std::string& what) : openfhe_error(file, line, what) {}
};

class not_implemented_error : public openfhe_error {
public:
    not_implemented_error(const std::string& file, int line, const std::string& what)
        : openfhe_error(file, line, what) {}
};

class not_available_error : public openfhe_error {
public:
    not_available_error(const std::string& file, int line, const std::string& what) : openfhe_error(file, line, what) {}
};

class type_error : public openfhe_error {
public:
    type_error(const std::string& file, int line, const std::string& what) : openfhe_error(file, line, what) {}
};

// use this error when serializing openfhe objects
class serialize_error : public openfhe_error {
public:
    serialize_error(const std::string& file, int line, const std::string& what) : openfhe_error(file, line, what) {}
};

// use this error when deserializing openfhe objects
class deserialize_error : public openfhe_error {
public:
    deserialize_error(const std::string& file, int line, const std::string& what) : openfhe_error(file, line, what) {}
};

#define OPENFHE_THROW(exc, expr) throw exc(__FILE__, __LINE__, (expr))

}  // namespace lbcrypto

#endif /* SRC_CORE_LIB_UTILS_EXCEPTION_H_ */
