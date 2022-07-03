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

/**
 * @file testcasegen.h Helper methods for serialization.
 */

#ifndef SRC_CORE_LIB_UTILS_TESTCASEGEN_H_
#define SRC_CORE_LIB_UTILS_TESTCASEGEN_H_

#define GENERATE_PKE_TEST_CASE(TOPNAME, FUNC, ELEMENT, SCHEME, ORD, PTM, FIRST_MOD) \
  TEST_F(TOPNAME, FUNC##_##ELEMENT##_##SCHEME) {                                    \
    CryptoContext<ELEMENT> cc;                                                   \
    try {                                                                           \
      cc = GenTestCryptoContext<ELEMENT>(#SCHEME, ORD, PTM, FIRST_MOD);             \
    } catch (const not_implemented_error&) {                                        \
      return;                                                                       \
    } catch (const not_available_error&) {                                          \
      return;                                                                       \
    } catch (const std::exception& ex) {                                            \
      std::cerr << "Exception occurred: " << ex.what() << std::endl;                \
    } catch (...) {                                                                 \
      std::cerr << "Unknown failure occurred." << std::endl;                        \
    }                                                                               \
    FUNC<ELEMENT>(cc, #SCHEME);                                                     \
  }

#define GENERATE_PKE_TEST_CASE_BITS(TOPNAME, FUNC, ELEMENT, SCHEME, ORD, PTM, FIRST_MOD, BITS) \
  TEST_F(TOPNAME, FUNC##_##ELEMENT##_##SCHEME) {                                               \
    CryptoContext<ELEMENT> cc;                                                              \
    try {                                                                                      \
      cc = GenTestCryptoContext<ELEMENT>(#SCHEME, ORD, PTM, FIRST_MOD, BITS);                  \
    } catch (const not_implemented_error&) {                                                   \
      return;                                                                                  \
    } catch (const not_available_error&) {                                                     \
      return;                                                                                  \
    } catch (const std::exception& ex) {                                                       \
      std::cerr << "Exception occurred: " << ex.what() << std::endl;                           \
    } catch (...) {                                                                            \
      std::cerr << "Unknown failure occurred." << std::endl;                                   \
    }                                                                                          \
    FUNC<ELEMENT>(cc, #SCHEME);                                                                \
  }

#define GENERATE_CKKS_TEST_CASE(TOPNAME, FUNC, ELEMENT, SCHEME, ORD, SCALE, FIRST_MOD, NUMPRIME, RELIN, BATCH,     \
                                KEYSWITCH, RESCALEALG)                                                             \
  TEST_F(TOPNAME, FUNC##_##ELEMENT##_##SCHEME##_##KEYSWITCH##_##RESCALEALG##_##ORD) {  \
    CryptoContext<ELEMENT> cc;                                                                                  \
    try {                                                                                                          \
      cc = GenTestCryptoContext<ELEMENT>(#SCHEME, ORD, SCALE, FIRST_MOD, SCALE, NUMPRIME, RELIN, BATCH, KEYSWITCH, \
                                         RESCALEALG);                                                              \
    } catch (const not_implemented_error&) {                                                                       \
      return;                                                                                                      \
    } catch (const not_available_error&) {                                                                         \
      return;                                                                                                      \
    } catch (const std::exception& ex) {                                                                           \
      std::cerr << "Exception occurred: " << ex.what() << std::endl;                                               \
    } catch (...) {                                                                                                \
      std::cerr << "Unknown failure occurred." << std::endl;                                                       \
    }                                                                                                              \
    FUNC<ELEMENT>(cc, #SCHEME);                                                                                    \
  }

#define GENERATE_CKKSNULL_TEST_CASE(TOPNAME, FUNC, ELEMENT, SCHEME, ORD, SCALE, FIRST_MOD, NUMPRIME, RELIN, BATCH, \
                                    KEYSWITCH, RESCALEALG)                                                         \
  TEST_F(TOPNAME, FUNC##_##ELEMENT##_##SCHEME##_##KEYSWITCH##_##RESCALEALG) {                                      \
    CryptoContext<ELEMENT> cc;                                                                                  \
    try {                                                                                                          \
      cc = GenTestCryptoContext<ELEMENT>(#SCHEME, ORD, SCALE, FIRST_MOD, SCALE, NUMPRIME, RELIN, BATCH, KEYSWITCH, \
                                         RESCALEALG);                                                              \
    } catch (...) {                                                                                                \
      std::exception_ptr p = std::current_exception();                                                             \
      std::cerr << (p ? p.__cxa_exception_type()->name() : "null") << std::endl;                                   \
      return;                                                                                                      \
    }                                                                                                              \
    FUNC<ELEMENT>(cc, #SCHEME);                                                                                    \
  }

#define GENERATE_CKKS_PERMUTE_TEST_CASE(TOPNAME, FUNC, ELEMENT, SCHEME, ORD, SCALE, FIRST_MOD, NUMPRIME, RELIN,    \
                                        STRATEGY, BATCH, ITERS, KEYSWITCH, RESCALEALG)                             \
  TEST_F(TOPNAME, FUNC##_##ELEMENT##_##SCHEME##_##BATCH##_##STRATEGY##_##KEYSWITCH##_##RESCALEALG) {               \
    CryptoContext<ELEMENT> cc;                                                                                  \
    try {                                                                                                          \
      cc = GenTestCryptoContext<ELEMENT>(#SCHEME, ORD, SCALE, FIRST_MOD, SCALE, NUMPRIME, RELIN, BATCH, KEYSWITCH, \
                                         RESCALEALG);                                                              \
    } catch (const not_implemented_error&) {                                                                       \
      return;                                                                                                      \
    } catch (const not_available_error&) {                                                                         \
      return;                                                                                                      \
    } catch (const std::exception& ex) {                                                                           \
      std::cerr << "Exception occurred: " << ex.what() << std::endl;                                               \
    } catch (...) {                                                                                                \
      std::cerr << "Unknown failure occurred." << std::endl;                                                       \
    }                                                                                                              \
    FUNC<ELEMENT>(cc, STRATEGY, BATCH, ITERS, #SCHEME);                                                            \
  }

// Somebody should figure out how to do recursive macros. I give up. For now.

//#define _PP_0(_1, ...) _1
//#define _PP_X(_1, ...) (__VA_ARGS__)

//#define ITER_0(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[0])
//#define ITER_1(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_0(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[1])
//#define ITER_2(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_1(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[2])
//#define ITER_3(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_2(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[3])
//#define ITER_4(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_3(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[4])
//#define ITER_5(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_4(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[5])
//#define ITER_6(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_5(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[6])
//#define ITER_7(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_6(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[7])
//#define ITER_8(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_7(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[8])
//#define ITER_9(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_8(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ACTION(TOPNAME, FUNC, ELEMENT, VECTOR[9])
//#define ITER_10(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_9(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT)

//#define ITER(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT) ITER_6(VECTOR, ACTION, TOPNAME, FUNC, ELEMENT)
//
//static vector<string> V( {"Null", "StSt", "BGV", "BFV", "BFVrns"} );
//
//ITER(V, GENERATE_PKE_TEST_CASE, Encrypt_Decrypt, EncryptionScalar, Poly)

#endif /* SRC_CORE_LIB_UTILS_TESTCASEGEN_H_ */
